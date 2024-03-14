/*
 * This file is part of cambricon edge driver
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

#include <linux/version.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/mm.h>
#endif
#include <linux/delay.h>
#include <linux/slab.h> /*cn_kfree*/
#include <linux/uaccess.h>/*copy_to_user,copy_from_user*/
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "cndrv_edge.h"
#include "./cndrv_edge_dma.h"
#include "cndrv_mm.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "cndrv_monitor.h"
#include "cndrv_sbts.h"

static void cn_edge_async_message_work(struct work_struct *work);

static void cn_edge_put_async_mem_release(struct edge_dma_task *task)
{
	struct cn_core_set *core = task->edge_set->bus_set->core;

	if (unlikely(core->device_id == MLUID_220_EDGE))
		return;

	cn_async_address_kref_put((u64)task->pminfo, task->device_vaddr,
			task->async_info->total_size);
}

static void cn_edge_dma_trigger_task_release(struct edge_dma_task *task)
{
	if (task->dma_type == EDGE_DMA_PINNED_MEM) {
		cn_pinned_mem_put_kv(task->tsk->tgid, task->kvaddr);
	}

	if (!task->abort_flag)
		cn_edge_put_async_mem_release(task);

	if (task->dma_type == EDGE_DMA_USER
		|| task->dma_type == EDGE_DMA_PINNED_MEM) {
		put_task_struct(task->tsk);
		mmdrop(task->tsk_mm);
	}

	kmem_cache_free(task->edge_set->async_mem, task->async_info);

	cn_kfree(task->transfer);
	cn_kfree(task->memset);
	cn_kfree(task);
}

int cn_edge_dma_abort(u64 tags, u64 index, void *edge_priv)
{
	struct edge_dma_task *task = NULL;
	struct cn_edge_set *edge_set = (struct cn_edge_set *)edge_priv;
	struct hlist_node *tmp;

	mutex_lock(&edge_set->async_task_hash_lock);
	hash_for_each_possible_safe(edge_set->async_task_htable,
						task, tmp, hlist, tags) {
		if (task->tags != tags)
			continue;
		if (task->index != index)
			continue;
		hash_del(&task->hlist);
		mutex_unlock(&edge_set->async_task_hash_lock);

		task->abort_flag = 1;
		cn_edge_dma_trigger_task_release(task);
		return 0;
	}
	cn_dev_err("no task in hash table for abort tags:%llu index:%llu",
				tags, index);
	mutex_unlock(&edge_set->async_task_hash_lock);

	return 0;
}

static int cn_edge_set_remain_task_err(struct edge_dma_task *async_task)
{
	u32 status;
	struct edge_dma_task *task;
	struct edge_dma_task *next_task = async_task->next_task;

	status = DMA_TASK_FINISH_ERR;

	while (next_task) {
		task = next_task;
		cn_sbts_dma_finish_set_sta(
				task->edge_set_stream->bus_set->core,
				task->async_info->ack_host_va,
				status, 0, 0);
		next_task = task->next_task;
		cn_edge_dma_trigger_task_release(task);
	}

	return 0;
}

static int cn_edge_dma_trigger_task(struct edge_dma_task *task)
{
	struct cn_edge_set *edge_set = task->edge_set;
	int ret;
	u32 status;
	u64 start_ns, finish_ns;

	cn_dev_edge_debug(edge_set, "async dma trigger tags :%llX, index :%llu",
			task->tags, task->index);

	start_ns = get_host_timestamp_by_clockid(task->clockid);
	if (task->dma_type == EDGE_DMA_MEMSET_ASYNC) {
		ret = cn_edge_dma_memset(task);
	} else {
		ret = cn_edge_dma_transfer(task);
	}
	finish_ns = get_host_timestamp_by_clockid(task->clockid);

	if (ret) {
		status = DMA_TASK_FINISH_ERR;
	} else {
		status = DMA_TASK_FINISH;
	}

	cn_sbts_dma_finish_set_sta(
			task->edge_set_stream->bus_set->core,
			task->async_info->ack_host_va,
			status,
			cpu_to_le64(start_ns),
			cpu_to_le64(finish_ns));

	if (ret)
		cn_edge_set_remain_task_err(task);
	cn_edge_dma_trigger_task_release(task);
	return ret;
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
size_t cn_edge_dma_async(struct transfer_s *t,
		struct dma_async_info_s **pinfo, void *edge_priv)
{
	struct edge_dma_task *task = NULL;
	struct transfer_s *new;
	struct pinned_mem_va *mem;
	enum CN_EDGE_DMA_TYPE dma_type;
	struct cn_edge_set *edge_set_stream = (struct cn_edge_set *)edge_priv;
	struct cn_bus_set *bus_set = (struct cn_bus_set *)t->bus_set;
	struct cn_edge_set *edge_set = (struct cn_edge_set *)bus_set->priv;
	struct dma_async_info_s *async_info;

	async_info = kmem_cache_zalloc(edge_set->async_mem, GFP_KERNEL);
	if (!async_info) {
		cn_dev_err("create dma async info failed");
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
	dma_type = mem ? EDGE_DMA_PINNED_MEM : EDGE_DMA_USER;

	task = cn_kzalloc(sizeof(*task), GFP_KERNEL);
	if (task == NULL) {
		cn_dev_edge_err(edge_set, "kzalloc task error");
		goto exit;
	}

	new = cn_kzalloc(sizeof(*t), GFP_KERNEL);
	if (new == NULL) {
		cn_dev_edge_err(edge_set, "kzalloc host error");
		goto task_exit;
	}
	memcpy(new, t, sizeof(*t));

	if (cn_edge_init_dma_task(task, new, dma_type, edge_priv))
		goto device_tb_exit;

	task->edge_set_stream = edge_set_stream;
	task->async_info = async_info;
	task->tags = async_info->tags;
	task->index = async_info->index;
	task->dma_async = 1;
	task->user = t->user;
	task->device_vaddr = t->ia;
	task->pminfo = t->pminfo;
	task->clockid = get_host_timestamp_clockid(t->user, edge_set->bus_set->core);
	INIT_WORK(&task->trigger_work, cn_edge_async_message_work);

	atomic_inc(&task->tsk_mm->mm_count);
	get_task_struct(task->tsk);

	mutex_lock(&edge_set_stream->async_task_hash_lock);
	hash_add(edge_set_stream->async_task_htable, &task->hlist, async_info->tags);
	mutex_unlock(&edge_set_stream->async_task_hash_lock);

	cn_dev_edge_debug(edge_set, "async dma tags :%llx, index :%llu", async_info->tags, async_info->index);
	return 0;

device_tb_exit:
	cn_kfree(new);
task_exit:
	cn_kfree(task);
exit:
	kmem_cache_free(edge_set->async_mem, async_info);
	return -1;
}

int cn_edge_memset_async(struct memset_s *t, struct dma_async_info_s **pinfo, void *edge_priv)
{
	struct edge_dma_task *task = NULL;
	struct memset_s *new;
	struct ion_device_addr ion_dev_addr;
	struct cn_edge_set *edge_set_stream = (struct cn_edge_set *)edge_priv;
	struct cn_bus_set *bus_set = (struct cn_bus_set *)t->bus_set;
	struct cn_edge_set *edge_set = (struct cn_edge_set *)bus_set->priv;
	struct dma_async_info_s *async_info;

	async_info = kmem_cache_zalloc(edge_set->async_mem, GFP_KERNEL);
	if (!async_info) {
		cn_dev_err("create dma async info failed");
		return -ENOMEM;
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
		cn_dev_err("direction is invalid!");
		return -1;
	}
	*pinfo = async_info;

	task = cn_kzalloc(sizeof(*task), GFP_KERNEL);
	if (task == NULL) {
		cn_dev_err("kzalloc task fialed!");
		kmem_cache_free(edge_set->async_mem, async_info);
		return -ENOMEM;
	}

	new = cn_kzalloc(sizeof(*t), GFP_KERNEL);
	if (new == NULL) {
		cn_dev_err("kzalloc host error");
		cn_kfree(task);
		kmem_cache_free(edge_set->async_mem, async_info);
		return -ENOMEM;
	}
	memcpy(new, t, sizeof(*t));

	if (edge_init_device_addr((void *)t->dev_addr, &ion_dev_addr)) {
		cn_kfree(new);
		cn_kfree(task);
		kmem_cache_free(edge_set->async_mem, async_info);
		return -1;
	}

	if (ion_dev_addr.version != 1) {
		cn_dev_edge_err(edge_set, "version invalid");
		cn_kfree(new);
		cn_kfree(task);
		kmem_cache_free(edge_set->async_mem, async_info);
		return -1;
	}

	task->edge_set = edge_set;
	task->edge_set_stream = edge_set_stream;
	task->dma_type = EDGE_DMA_MEMSET_ASYNC;
	task->memset = new;
	task->async_info = async_info;
	task->tags = async_info->tags;
	task->index = async_info->index;
	task->ion_cntx.iova = ion_dev_addr.iova;
	task->ion_cntx.handle_id = ion_dev_addr.handle_id;
	task->user = t->user;
	task->device_vaddr = t->dev_addr;
	task->pminfo = t->pminfo;
	task->clockid = get_host_timestamp_clockid(t->user, edge_set->bus_set->core);
	INIT_WORK(&task->trigger_work, cn_edge_async_message_work);

	mutex_lock(&edge_set_stream->async_task_hash_lock);
	hash_add(edge_set_stream->async_task_htable, &task->hlist, async_info->tags);
	mutex_unlock(&edge_set_stream->async_task_hash_lock);

	cn_dev_edge_debug(edge_set,
		"memset async tags :%llX, index :%llu", async_info->tags, async_info->index);
	return 0;

}

int cn_edge_get_async_htable(void *edge_priv)
{
	struct cn_edge_set *edge_set = (struct cn_edge_set *)edge_priv;
	struct edge_dma_task *task = NULL;
	struct hlist_node *tmp;
	int i = 0;
	int hash_size = HASH_SIZE(edge_set->async_task_htable);
	u32 used_cnt;
	int flag = 0;

	mutex_lock(&edge_set->async_task_hash_lock);
	for (i = 0; i < hash_size; i++) {
		used_cnt = 0;
		hlist_for_each_entry_safe(task, tmp,
				&edge_set->async_task_htable[i], hlist) {
			used_cnt++;
		}
		if (used_cnt) {
			cn_dev_info("node[%03d]: %d", i, used_cnt);
			flag = 1;
		}
	}
	mutex_unlock(&edge_set->async_task_hash_lock);

	if (!flag)
		cn_dev_info("All not used!");

	return 0;
}

static void cn_edge_async_message_work(struct work_struct *work)
{
	struct edge_dma_task *task = (struct edge_dma_task *)container_of(work,
			struct edge_dma_task, trigger_work);
	struct cn_edge_set *edge_set_stream = task->edge_set_stream;
	int ret;
	u64 tags;
	u64 index;
	struct edge_dma_task *next_task;
	int trigger_type = task->trigger_type;

	cn_dev_edge_debug(edge_set_stream, "tags:%llu index:%llu trigger_type:%d",
			task->tags, task->index, task->trigger_type);

	do {
		next_task = task->next_task;
		switch (trigger_type) {
		case DMA_RELEASE_TASK:
			cn_edge_dma_trigger_task_release(task);
			break;
		case DMA_HOST_TRIGGER:
			tags = task->tags;
			index = task->index;
			ret = cn_edge_dma_trigger_task(task);
			if (ret) {
				cn_dev_edge_err(edge_set_stream, "dma trigger task failed tags:%llu index:%llu",
						tags, index);
				cn_sbts_dma_finish_wakeup(edge_set_stream->bus_set->core);
				return;
			}
			break;
		default:
			cn_dev_edge_err(edge_set_stream, "unknown task trigger type:%d",
					task->trigger_type);
			break;
		}
		task = next_task;
	} while (next_task);

	if (trigger_type == DMA_HOST_TRIGGER)
		cn_sbts_dma_finish_wakeup(edge_set_stream->bus_set->core);
}

static struct edge_dma_task *__dma_async_find_task_and_out(
		struct cn_edge_set *edge_set,
		u64 tags, u64 index)
{
	struct edge_dma_task *task = NULL;
	struct hlist_node *tmp;

	mutex_lock(&edge_set->async_task_hash_lock);
	hash_for_each_possible_safe(edge_set->async_task_htable,
			task, tmp, hlist, tags) {
		if (task->tags != tags)
			continue;
		if (task->index != index)
			continue;

		hash_del(&task->hlist);
		mutex_unlock(&edge_set->async_task_hash_lock);

		return task;
	}
	cn_dev_edge_err(edge_set, "no task in hash table tags:%llu index:%llu",
			tags, index);
	mutex_unlock(&edge_set->async_task_hash_lock);
	return NULL;
}

int cn_edge_dma_async_message_process(void *edge_priv,
		struct arm_trigger_message *message)
{
	struct cn_edge_set *edge_set = (struct cn_edge_set *)edge_priv;
	struct edge_dma_task *head_task = NULL;
	struct edge_dma_task *task = NULL;
	struct edge_dma_task *prev_task = NULL;
	int i;

	cn_dev_edge_debug(edge_set, "tags:%llu index:%llu trigger_type:%d task_num:%d",
			message->tags, message->task_info[0].index,
			message->trigger_type, message->task_num);

	for (i = 0; i < message->task_num; i++) {
		task = __dma_async_find_task_and_out(edge_set,
				message->tags, message->task_info[i].index);
		if (!task) {
			cn_dev_edge_err(edge_set, "find task in hash table failed");
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
		cn_dev_edge_err(edge_set, "no task to trigger");
		return -1;
	}
	/* cn_edge_async_message_work */
	queue_work(system_unbound_wq, &head_task->trigger_work);

	return 0;
}

int cn_edge_dma_async_init(struct cn_edge_set *edge_set)
{
	char slab_name[64];

	sprintf(slab_name, "camb_dma_async_info%d", 0);
	edge_set->async_mem = kmem_cache_create(slab_name,
				sizeof(struct dma_async_info_s), 64,
				SLAB_HWCACHE_ALIGN, NULL);
	if (!edge_set->async_mem) {
		cn_dev_err("alloc task mem cache failed");
		return -ENOMEM;
	}

	hash_init(edge_set->async_task_htable);
	mutex_init(&edge_set->async_task_hash_lock);

	cn_dev_debug("ASYNC DMA INIT");

	return 0;
}

void cn_edge_dma_async_exit(struct cn_edge_set *edge_set)
{
	struct edge_dma_task *task = NULL;
	struct hlist_node *tmp;
	int bkt;

	if (hash_empty(edge_set->async_task_htable)) {
		cn_dev_info("async task hask is null");
		return;
	}
	mutex_lock(&edge_set->async_task_hash_lock);
	hash_for_each_safe(edge_set->async_task_htable,
					bkt, tmp, task, hlist) {
		hash_del(&task->hlist);
		cn_edge_dma_trigger_task_release(task);
	}
	mutex_unlock(&edge_set->async_task_hash_lock);

	kmem_cache_destroy(edge_set->async_mem);
	cn_dev_debug("ASYNC DMA EXIT");
}
