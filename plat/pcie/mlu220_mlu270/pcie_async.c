/*
 * This file is part of cambricon pcie driver
 *
 * Copyright (c) 2018, Cambricon Technologies Corporation Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/pci.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/vmalloc.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/mm.h>
#endif

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "pcie_dma.h"
#include "cndrv_pci.h"
#include "cndrv_mm.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "cndrv_monitor.h"
#include "cndrv_sbts.h"

static void cn_pci_async_message_work(struct work_struct *work);

static void cn_pci_put_async_mem_release(struct pcie_dma_task *task)
{
	if (task->dma_type == PCIE_DMA_P2P) {
		cn_async_address_kref_put((u64)task->peer->src_minfo,
				task->peer->src_addr, task->peer->size);
		cn_async_address_kref_put((u64)task->peer->dst_minfo,
				task->peer->dst_addr, task->peer->size);
	} else if (task->dma_type == PCIE_DMA_MEMSET) {
		cn_async_address_kref_put((u64)task->memset->pminfo, task->memset->dev_addr,
				task->async_info->total_size);
	} else {
		cn_async_address_kref_put((u64)task->transfer->pminfo, task->transfer->ia,
				task->transfer->size);
	}
}

static void cn_pci_dma_trigger_task_release(struct pcie_dma_task *task)
{
	if (task->kvaddr)
		cn_pinned_mem_put_kv(task->tsk->tgid, task->kvaddr);
	if (task->kvaddr_align)
		cn_pinned_mem_put_kv(task->tsk->tgid, task->kvaddr_align);
	if (!task->abort_flag)
		cn_pci_put_async_mem_release(task);

	if (task->dma_type == PCIE_DMA_USER
		|| task->dma_type == PCIE_DMA_PINNED_MEM) {
		put_task_struct(task->tsk);
		mmdrop(task->tsk_mm);
	}

	kmem_cache_free(task->pcie_set->async_mem, task->async_info);
	cn_kfree(task->transfer);
	cn_kfree(task->memset);
	cn_kfree(task->peer);
	cn_kfree(task);
}

static int cn_pci_set_remain_task_err(struct pcie_dma_task *async_task)
{
	u32 status;
	struct pcie_dma_task *task;
	struct pcie_dma_task *next_task = async_task->next_task;

	status = DMA_TASK_FINISH_ERR;

	while (next_task) {
		task = next_task;
		cn_sbts_dma_finish_set_sta(
				task->pcie_set_stream->bus_set->core,
				task->async_info->ack_host_va,
				status,
				0, 0);
		next_task = task->next_task;
		cn_pci_dma_trigger_task_release(task);
	}

	return 0;
}

static int cn_pci_dma_trigger_task(struct pcie_dma_task *task)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int ret = 0;
	u32 status;
	u64 start_ns, finish_ns;

	cn_dev_pcie_debug(pcie_set, "async dma trigger tags:%llu, index:%llu",
			task->tags, task->index);

	start_ns = get_host_timestamp_by_clockid(task->clockid);
	if (task->dma_type == PCIE_DMA_P2P) {
		ret = cn_pci_dma_p2p(task->peer);
	} else if (task->dma_type == PCIE_DMA_MEMSET) {
		ret = pci_dma_memset((void *)pcie_set, task->memset);
	} else {
		if (cn_pci_dma_transfer(task))
			ret = -1;
	}

	finish_ns = get_host_timestamp_by_clockid(task->clockid);
	if (ret)
		status = DMA_TASK_FINISH_ERR;
	else
		status = DMA_TASK_FINISH;

	cn_sbts_dma_finish_set_sta(
			task->pcie_set_stream->bus_set->core,
			task->async_info->ack_host_va,
			status,
			cpu_to_le64(start_ns),
			cpu_to_le64(finish_ns));

	if (ret)
		cn_pci_set_remain_task_err(task);
	cn_pci_dma_trigger_task_release(task);

	return ret;
}

static int cn_pci_dma_abort(u64 tags, u64 index, void *pcie_priv)
{
	struct pcie_dma_task *task = NULL;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct hlist_node *tmp;

	mutex_lock(&pcie_set->async_task_hash_lock);
	hash_for_each_possible_safe(pcie_set->async_task_htable,
						task, tmp, hlist, tags) {
		if (task->tags != tags)
			continue;
		if (task->index != index)
			continue;

		hash_del(&task->hlist);
		mutex_unlock(&pcie_set->async_task_hash_lock);

		task->abort_flag = 1;
		cn_pci_dma_trigger_task_release(task);
		return 0;
	}
	cn_dev_pcie_err(pcie_set, "no task in hash table for abort tags:%llu index:%llu",
				tags, index);
	mutex_unlock(&pcie_set->async_task_hash_lock);

	return 0;
}

/*
 * task with diffrent dma_tag value link to task_head->row_entry;
 * task with same dma_tag and different dma_index link to \
 * task_head->column
 *
 * task_head[dma_tag1]->task_head[dma_tag2]->task_head[dma_tag3]
 *             |                    |                    |
 *           index1               index1               index1
 *             |
 *           index2
 */
static size_t cn_pci_dma_async(struct transfer_s *t,
		struct dma_async_info_s **pinfo, void *pcie_priv)
{
	struct pcie_dma_task *task;
	struct transfer_s *new;
	struct pinned_mem_va *mem;
	enum CN_PCIE_DMA_TYPE dma_type;
	struct cn_pcie_set *pcie_set_stream = (struct cn_pcie_set *)pcie_priv;
	struct cn_bus_set *bus_set = (struct cn_bus_set *)t->bus_set;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)bus_set->priv;
	struct dma_async_info_s *async_info;

	async_info = kmem_cache_zalloc(pcie_set->async_mem, GFP_KERNEL);
	if (!async_info) {
		cn_dev_pcie_err(pcie_set, "create dma async info failed");
		return -1;
	}

	async_info->index = t->index;
	async_info->tags = t->tags;
	async_info->host_vaddr = t->ca;
	async_info->device_vaddr = t->ia;
	async_info->total_size = t->size;
	async_info->direction = t->direction;
	*pinfo = async_info;

	mem = cn_pinned_mem_check(current, t->ca, t->size);
	dma_type = mem ? PCIE_DMA_PINNED_MEM : PCIE_DMA_USER;

	task = cn_kzalloc(sizeof(*task), GFP_KERNEL);
	if (task == NULL) {
		cn_dev_pcie_err(pcie_set, "kzalloc task error");
		goto exit;
	}

	new = cn_kzalloc(sizeof(*t), GFP_KERNEL);
	if (new == NULL) {
		cn_dev_pcie_err(pcie_set, "kzalloc host error");
		goto task_exit;
	}
	memcpy(new, t, sizeof(*t));

	if (cn_pci_init_dma_task(task, new, dma_type, pcie_set))
		goto device_tb_exit;

	task->pcie_set_stream = pcie_set_stream;
	task->async_info = async_info;
	task->tags = async_info->tags;
	task->index = async_info->index;
	task->dma_async = 1;
	task->user = t->user;
	task->device_vaddr = t->ia;
	task->clockid = get_host_timestamp_clockid(t->user, bus_set->core);
	INIT_WORK(&task->trigger_work, cn_pci_async_message_work);

	if (dma_type ==  PCIE_DMA_PINNED_MEM) {
		task->kvaddr = cn_pinned_mem_get_kv(current->tgid, t->ca, t->size);
		if (!task->kvaddr) {
			goto device_tb_exit;
		}
		task->kvaddr_cur = task->kvaddr;

		if (task->non_align[1].cnt) {
			task->kvaddr_align = cn_pinned_mem_get_kv(current->tgid,
							task->non_align[1].ca,
							task->non_align[1].cnt);
			if (!task->kvaddr_align) {
				cn_pinned_mem_put_kv(task->tsk->tgid, task->kvaddr_align);
				cn_dev_pcie_err(pcie_set,
					"non_align_ca:%#llx non_align_cnt=%#lx\n",
					task->non_align[1].ca, task->non_align[1].cnt);
				goto device_tb_exit;
			}
		}
	}

	atomic_inc(&task->tsk_mm->mm_count);
	get_task_struct(task->tsk);

	mutex_lock(&pcie_set_stream->async_task_hash_lock);
	hash_add(pcie_set_stream->async_task_htable, &task->hlist, async_info->tags);
	mutex_unlock(&pcie_set_stream->async_task_hash_lock);

	cn_dev_pcie_debug(pcie_set,
		"async dma tags:%llu, index:%llu", async_info->tags, async_info->index);
	return 0;

device_tb_exit:
	cn_kfree(new);
task_exit:
	cn_kfree(task);
exit:
	kmem_cache_free(pcie_set->async_mem, async_info);
	return -1;
}

static int cn_pci_get_async_htable(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pcie_dma_task *task = NULL;
	struct hlist_node *tmp;
	int i = 0;
	int hash_size = HASH_SIZE(pcie_set->async_task_htable);
	u32 used_cnt;
	int flag = 0;

	mutex_lock(&pcie_set->async_task_hash_lock);
	for (i = 0; i < hash_size; i++) {
		used_cnt = 0;
		hlist_for_each_entry_safe(task, tmp,
				&pcie_set->async_task_htable[i], hlist) {
			used_cnt++;
		}
		if (used_cnt) {
			cn_dev_pcie_info(pcie_set, "node[%03d]: %d", i, used_cnt);
			flag = 1;
		}
	}
	mutex_unlock(&pcie_set->async_task_hash_lock);

	if (!flag)
		cn_dev_pcie_info(pcie_set, "All not used!");

	return 0;
}

static size_t cn_pci_dma_p2p_async(struct peer_s *t,
		struct dma_async_info_s **pinfo, void *pcie_priv)
{
	struct pcie_dma_task *task = NULL;
	struct cn_pcie_set *pcie_set_stream = (struct cn_pcie_set *)pcie_priv;
	struct cn_bus_set *src_bus_set = (struct cn_bus_set *)t->src_bus_set;
	struct cn_pcie_set *pcie_set_src = (struct cn_pcie_set *)src_bus_set->priv;
	struct cn_bus_set *dst_bus_set = (struct cn_bus_set *)t->dst_bus_set;
	struct cn_pcie_set *pcie_set_dst = (struct cn_pcie_set *)dst_bus_set->priv;
	struct peer_s *new = NULL;
	struct dma_async_info_s *async_info;

	async_info = kmem_cache_zalloc(pcie_set_src->async_mem, GFP_KERNEL);
	if (!async_info) {
		cn_dev_pcie_err(pcie_set_src, "create dma async info failed");
		return -1;
	}

	async_info->index = t->index;
	async_info->tags = t->tags;
	async_info->host_vaddr = t->src_addr;
	async_info->device_vaddr = t->dst_addr;
	async_info->total_size = t->size;
	async_info->direction = DMA_P2P;
	*pinfo = async_info;

	task = cn_kzalloc(sizeof(*task), GFP_KERNEL);
	if (task == NULL) {
		kmem_cache_free(pcie_set_src->async_mem, async_info);
		return -1;
	}

	new = cn_kzalloc(sizeof(*t), GFP_KERNEL);
	if (new == NULL) {
		cn_dev_pcie_err(pcie_set_src, "kzalloc host error");
		cn_kfree(task);
		kmem_cache_free(pcie_set_src->async_mem, async_info);
		return -ENOMEM;
	}
	memcpy(new, t, sizeof(*t));

	task->pcie_set = pcie_set_src;
	task->pcie_set_stream = pcie_set_stream;
	task->peer = new;
	task->dma_type = PCIE_DMA_P2P;
	task->src_addr = t->src_addr;
	task->dst_addr = t->dst_addr;
	task->count = t->size;
	task->pcie_set_dst = pcie_set_dst;

	task->async_info = async_info;
	task->tags = async_info->tags;
	task->index = async_info->index;
	task->user = t->user;
	task->device_vaddr = t->dst_addr;
	task->clockid = get_host_timestamp_clockid(t->user, src_bus_set->core);
	INIT_WORK(&task->trigger_work, cn_pci_async_message_work);

	mutex_lock(&pcie_set_stream->async_task_hash_lock);
	hash_add(pcie_set_stream->async_task_htable, &task->hlist, async_info->tags);
	mutex_unlock(&pcie_set_stream->async_task_hash_lock);

	cn_dev_pcie_debug(pcie_set_src,
		"async p2p dma tags:%llu, index:%llu", async_info->tags, async_info->index);
	return 0;
}

static int pci_dma_memset_async(struct memset_s *t,
		struct dma_async_info_s **pinfo, void *pcie_priv)
{
	struct pcie_dma_task *task = NULL;
	struct memset_s *new = NULL;
	struct cn_pcie_set *pcie_set_stream = (struct cn_pcie_set *)pcie_priv;
	struct cn_bus_set *bus_set = (struct cn_bus_set *)t->bus_set;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)bus_set->priv;
	struct dma_async_info_s *async_info;

	async_info = kmem_cache_zalloc(pcie_set->async_mem, GFP_KERNEL);
	if (!async_info) {
		cn_dev_pcie_err(pcie_set, "create dma async info failed");
		return -1;
	}

	async_info->index = t->index;
	async_info->tags = t->tags;
	async_info->host_vaddr = 0;
	async_info->device_vaddr = t->dev_addr;
	async_info->direction = t->direction;
	if (t->direction == MEMSET_D8) {
		async_info->total_size = t->number * sizeof(unsigned char);
	} else if (t->direction == MEMSET_D16) {
		async_info->total_size = t->number * sizeof(unsigned short);
	} else if (t->direction == MEMSET_D32) {
		async_info->total_size = t->number * sizeof(unsigned int);
	} else {
		cn_dev_pcie_err(pcie_set, "direction is invalid!");
		kmem_cache_free(pcie_set->async_mem, async_info);
		return -1;
	}
	*pinfo = async_info;

	task = cn_kzalloc(sizeof(*task), GFP_KERNEL);
	if (task == NULL) {
		cn_dev_pcie_err(pcie_set, "kzalloc task fialed!");
		kmem_cache_free(pcie_set->async_mem, async_info);
		return -ENOMEM;
	}

	new = cn_kzalloc(sizeof(*t), GFP_KERNEL);
	if (new == NULL) {
		cn_dev_pcie_err(pcie_set, "kzalloc host error");
		cn_kfree(task);
		kmem_cache_free(pcie_set->async_mem, async_info);
		return -ENOMEM;
	}
	memcpy(new, t, sizeof(*t));

	task->pcie_set = pcie_set;
	task->pcie_set_stream = pcie_set_stream;
	task->dma_type = PCIE_DMA_MEMSET;
	task->memset = new;
	task->async_info = async_info;
	task->tags = async_info->tags;
	task->index = async_info->index;
	task->user = t->user;
	task->device_vaddr = t->dev_addr;
	task->clockid = get_host_timestamp_clockid(t->user, bus_set->core);
	INIT_WORK(&task->trigger_work, cn_pci_async_message_work);

	mutex_lock(&pcie_set_stream->async_task_hash_lock);
	hash_add(pcie_set_stream->async_task_htable, &task->hlist, async_info->tags);
	mutex_unlock(&pcie_set_stream->async_task_hash_lock);

	cn_dev_pcie_debug(pcie_set, "async memset tags:%llu, index :%llu", async_info->tags, async_info->index);

	return 0;
}

static void cn_pci_async_message_work(struct work_struct *work)
{
	struct pcie_dma_task *task = (struct pcie_dma_task *)container_of(work,
			struct pcie_dma_task, trigger_work);
	struct cn_pcie_set *pcie_set_stream = task->pcie_set_stream;
	int ret;
	u64 tags;
	u64 index;
	struct pcie_dma_task *next_task;
	int trigger_type = task->trigger_type;

	cn_dev_pcie_debug(pcie_set_stream, "tags:%llu index:%llu trigger_type:%d",
			task->tags, task->index, task->trigger_type);

	do {
		next_task = task->next_task;
		switch (trigger_type) {
		case DMA_RELEASE_TASK:
			cn_pci_dma_trigger_task_release(task);
			break;
		case DMA_HOST_TRIGGER:
			tags = task->tags;
			index = task->index;
			ret = cn_pci_dma_trigger_task(task);
			if (ret) {
				cn_dev_pcie_err(pcie_set_stream, "dma trigger task failed tags:%llu index:%llu",
						tags, index);
				cn_sbts_dma_finish_wakeup(pcie_set_stream->bus_set->core);
				return;
			}
			break;
		default:
			cn_dev_pcie_err(pcie_set_stream, "unknown task trigger type:%d",
					task->trigger_type);
			break;
		}
		task = next_task;
	} while (next_task);

	if (trigger_type == DMA_HOST_TRIGGER)
		cn_sbts_dma_finish_wakeup(pcie_set_stream->bus_set->core);
}

static struct pcie_dma_task *__dma_async_find_task_and_out(
		struct cn_pcie_set *pcie_set,
		u64 tags, u64 index)
{
	struct pcie_dma_task *task = NULL;
	struct hlist_node *tmp;

	mutex_lock(&pcie_set->async_task_hash_lock);
	hash_for_each_possible_safe(pcie_set->async_task_htable,
			task, tmp, hlist, tags) {
		if (task->tags != tags)
			continue;
		if (task->index != index)
			continue;

		hash_del(&task->hlist);
		mutex_unlock(&pcie_set->async_task_hash_lock);

		return task;
	}
	cn_dev_pcie_err(pcie_set, "no task in hash table tags:%llu index:%llu",
			tags, index);
	mutex_unlock(&pcie_set->async_task_hash_lock);
	return NULL;
}

static int cn_pci_dma_async_message_process(void *pcie_priv,
		struct arm_trigger_message *message)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pcie_dma_task *head_task = NULL;
	struct pcie_dma_task *task = NULL;
	struct pcie_dma_task *prev_task = NULL;
	int i;

	cn_dev_pcie_debug(pcie_set, "tags:%llu index:%llu trigger_type:%d task_num:%d",
			message->tags, message->task_info[0].index,
			message->trigger_type, message->task_num);

	for (i = 0; i < message->task_num; i++) {
		task = __dma_async_find_task_and_out(pcie_set,
				message->tags, message->task_info[i].index);
		if (!task) {
			cn_dev_pcie_err(pcie_set, "find task in hash table failed");
			return -1;
		}
		task->trigger_type = message->trigger_type;

		if (!head_task)
			head_task = task;

		if (prev_task) {
			prev_task->next_task = task;
			task->prev_task = prev_task;
		}

		prev_task = task;
	}
	task->next_task = NULL;

	if (!head_task) {
		cn_dev_pcie_err(pcie_set, "no task to trigger");
		return -1;
	}
	/* cn_pci_async_message_work */
	queue_work(system_unbound_wq, &head_task->trigger_work);

	return 0;
}

static int cn_pci_dma_async_init(struct cn_pcie_set *pcie_set)
{
	char slab_name[64];

	sprintf(slab_name, "camb_dma_async_info%d", pcie_set->id);
	pcie_set->async_mem = kmem_cache_create(slab_name,
				sizeof(struct dma_async_info_s), 64,
				SLAB_HWCACHE_ALIGN, NULL);
	if (!pcie_set->async_mem) {
		cn_dev_pcie_err(pcie_set, "alloc task mem cache failed");
		return -ENOMEM;
	}

	hash_init(pcie_set->async_task_htable);

	cn_dev_pcie_debug(pcie_set, "ASYNC DMA INIT");

	return 0;
}

static void cn_pci_dma_async_exit(struct cn_pcie_set *pcie_set)
{
	kmem_cache_destroy(pcie_set->async_mem);

	cn_dev_pcie_debug(pcie_set, "ASYNC DMA EXIT");
}
