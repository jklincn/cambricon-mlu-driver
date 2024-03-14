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
#include "cndrv_genalloc.h"
#include "cndrv_commu.h"
#include "cndrv_monitor.h"
#include "cndrv_sbts.h"

static void cn_pci_pinned_unmap_sg(struct async_task *task);
static void cn_pci_async_message_work(struct work_struct *work);

static void cn_pci_put_async_mem_release(struct async_task *async_task)
{
	if (async_task->dma_type == PCIE_DMA_P2P) {
		cn_async_address_kref_put((u64)async_task->peer.src_minfo,
				async_task->peer.src_addr, async_task->peer.size);
		cn_async_address_kref_put((u64)async_task->peer.dst_minfo,
				async_task->peer.dst_addr, async_task->peer.size);
	} else if (async_task->dma_type == PCIE_DMA_MEMSET) {
		cn_async_address_kref_put((u64)async_task->memset.pminfo, async_task->memset.dev_addr,
				async_task->async_info->total_size);
	} else {
		cn_async_address_kref_put((u64)async_task->transfer.pminfo, async_task->transfer.ia,
				async_task->transfer.size);
	}
}

static void cn_pci_async_dma_task_release(struct cn_pcie_set *pcie_set)
{
	int i;
	struct async_task *task;
	struct dma_async_info_s *async_info;

	if (pcie_set->async_static_desc_host_kva &&
		pcie_set->async_static_desc_dev_va) {
		cn_device_share_mem_free(0, pcie_set->async_static_desc_host_kva,
				pcie_set->async_static_desc_dev_va,
				pcie_set->bus_set->core);
	}

	if (pcie_set->async_dynamic_desc_host_kva &&
		pcie_set->async_dynamic_desc_dev_va) {
		cn_device_share_mem_free(0, pcie_set->async_dynamic_desc_host_kva,
				pcie_set->async_dynamic_desc_dev_va,
				pcie_set->bus_set->core);
	}

	if (pcie_set->async_task_bitmap)
		cn_kfree(pcie_set->async_task_bitmap);
	if (pcie_set->async_dynamic_desc_bitmap)
		cn_kfree(pcie_set->async_dynamic_desc_bitmap);

	if (!pcie_set->async_info_table)
		return;
	for (i = 0; i < pcie_set->async_static_task_num; i++) {
		async_info = pcie_set->async_info_table[i];
		if (async_info)
			cn_kfree(async_info);
	}
	if (pcie_set->async_info_table)
		cn_kfree(pcie_set->async_info_table);
	pcie_set->async_info_table = NULL;

	if (!pcie_set->async_task_table)
		return;
	for (i = 0; i < pcie_set->async_static_task_num; i++) {
		task = pcie_set->async_task_table[i];
		if (task) {
			if (task->pp_pages)
				cn_vfree(task->pp_pages);
			if (task->desc_buf)
				cn_vfree(task->desc_buf);
			if (task)
				cn_kfree(task);
		}
	}
	if (pcie_set->async_task_table)
		cn_kfree(pcie_set->async_task_table);
	pcie_set->async_task_table = NULL;
}

static int cn_pci_async_dma_task_init(struct cn_pcie_set *pcie_set)
{
	int i, n, ret;
	struct async_task *task;
	struct dma_async_info_s *async_info;
	u32 bitmap_size;

	if (pcie_set->arm_trigger_enable) {
		ret = cn_device_share_mem_alloc(0, &pcie_set->async_static_desc_host_kva,
				&pcie_set->async_static_desc_dev_va,
				pcie_set->async_static_desc_size,
				pcie_set->bus_set->core);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "async static desc alloc fail");
			return -1;
		}

		ret = cn_device_share_mem_alloc(0, &pcie_set->async_dynamic_desc_host_kva,
				&pcie_set->async_dynamic_desc_dev_va,
				pcie_set->async_dynamic_desc_size,
				pcie_set->bus_set->core);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "async dynamic desc alloc fail");
			goto exit;
		}

		bitmap_size = BITS_TO_LONGS(pcie_set->async_dynamic_desc_num) *
					sizeof(long);
		pcie_set->async_dynamic_desc_bitmap = cn_kzalloc(bitmap_size, GFP_KERNEL);
		if (pcie_set->async_dynamic_desc_bitmap == NULL) {
			cn_dev_pcie_err(pcie_set, "async dynamic desc bitmap alloc fail");
			goto exit;
		}
		spin_lock_init(&pcie_set->async_dynamic_desc_lock);
	}

	/* init async task table */
	pcie_set->async_task_table = cn_kzalloc(
			sizeof(task) * pcie_set->async_static_task_num, GFP_KERNEL);
	if (pcie_set->async_task_table == NULL)
		goto exit;
	for (i = 0; i < pcie_set->async_static_task_num; i++) {
		task = cn_kzalloc(sizeof(*task), GFP_KERNEL);
		if (task == NULL)
			goto exit;
		task->id = i;

		if (pcie_set->arm_trigger_enable) {
			task->host_desc_addr = pcie_set->async_static_desc_host_kva +
					pcie_set->async_max_desc_num * pcie_set->per_desc_size * i;
			task->dev_desc_addr = pcie_set->async_static_desc_dev_va +
					pcie_set->async_max_desc_num * pcie_set->per_desc_size * i;
			task->desc_buf = cn_vmalloc(pcie_set->async_max_desc_num *
					pcie_set->per_desc_size);
			if (task->desc_buf == NULL) {
				cn_kfree(task);
				goto exit;
			}

			n = (pcie_set->arm_trigger_max_size / PAGE_SIZE) + 1; /* 4097 */
			task->pp_pages = cn_vzalloc(n * sizeof(struct page *));
			if (task->pp_pages == NULL) {
				cn_vfree(task->desc_buf);
				cn_kfree(task);
				goto exit;
			}
		}
		pcie_set->async_task_table[i] = task;
	}

	/* init async info table */
	pcie_set->async_info_table = cn_kzalloc(
			sizeof(async_info) * pcie_set->async_static_task_num,
			GFP_KERNEL);
	if (pcie_set->async_info_table == NULL)
		goto exit;
	for (i = 0; i < pcie_set->async_static_task_num; i++) {
		async_info = cn_kzalloc(sizeof(*async_info), GFP_KERNEL);
		if (async_info == NULL)
			goto exit;
		pcie_set->async_info_table[i] = async_info;
	}

	/* init async task bitmap */
	bitmap_size = BITS_TO_LONGS(pcie_set->async_static_task_num) *
				sizeof(long);
	pcie_set->async_task_bitmap = cn_kzalloc(bitmap_size, GFP_KERNEL);
	if (pcie_set->async_task_bitmap == NULL) {
		cn_dev_pcie_err(pcie_set, "async task bitmap alloc fail");
		goto exit;
	}
	spin_lock_init(&pcie_set->async_task_lock);

	return 0;

exit:
	cn_dev_pcie_err(pcie_set, "async dma task init fail");
	cn_pci_async_dma_task_release(pcie_set);
	return -1;
}

static int cn_pci_get_async_dma_idle_task(struct cn_pcie_set *pcie_set,
		struct async_task **task, struct dma_async_info_s **info)
{
	struct async_task *async_task;
	struct dma_async_info_s *async_info;
	int index;
	int n;

	spin_lock(&pcie_set->async_task_lock);
	index = find_first_zero_bit(pcie_set->async_task_bitmap,
			pcie_set->async_static_task_num);
	if (index >= pcie_set->async_static_task_num) {
		spin_unlock(&pcie_set->async_task_lock);
		goto dynamic_alloc;
	}
	set_bit(index, pcie_set->async_task_bitmap);
	spin_unlock(&pcie_set->async_task_lock);

	async_task = pcie_set->async_task_table[index];
	async_info = pcie_set->async_info_table[index];
	memset(async_task, 0, ((u64)(&async_task->reserved) - (u64)async_task));
	memset(async_info, 0, sizeof(*async_info));
	*task = async_task;
	*info = async_info;
	return 0;

	/* Dynamic alloc async_task if static alloc failed */
dynamic_alloc:
	async_task = cn_kzalloc(sizeof(*async_task), GFP_KERNEL);
	if (async_task != NULL) {
		async_task->desc_buf = cn_vzalloc(pcie_set->async_max_desc_num *
				pcie_set->per_desc_size);
		if (async_task->desc_buf == NULL) {
			cn_kfree(async_task);
			cn_dev_pcie_err(pcie_set, "alloc task desc buf fail");
			return -1;
		}

		n = (pcie_set->arm_trigger_max_size / PAGE_SIZE) + 1; /* 4097 */
		async_task->pp_pages = cn_vzalloc(n * sizeof(struct page *));
		if (async_task->pp_pages == NULL) {
			cn_vfree(async_task->desc_buf);
			cn_kfree(async_task);
			cn_dev_pcie_err(pcie_set, "alloc task pp_pages buf fail");
			return -1;
		}

		async_task->dynamic_alloc_flag = 1;

		async_info = cn_kzalloc(sizeof(*async_info), GFP_KERNEL);
		if (!async_info) {
			cn_vfree(async_task->pp_pages);
			cn_vfree(async_task->desc_buf);
			cn_kfree(async_task);
			cn_dev_pcie_err(pcie_set, "alloc async info fail");
			return -1;
		}
		*task = async_task;
		*info = async_info;
		return 0;
	}

	cn_dev_pcie_err(pcie_set, "get async idle task fail");
	return -1;
}

static void cn_pci_put_async_dma_idle_task(struct cn_pcie_set *pcie_set,
		struct async_task *task, struct dma_async_info_s *async_info)
{
	if (task->dynamic_alloc_flag) {
		cn_kfree(async_info);
		if (task->dynamic_desc_num) {
			spin_lock(&pcie_set->async_dynamic_desc_lock);
			bitmap_clear(pcie_set->async_dynamic_desc_bitmap,
					task->bit_index, task->dynamic_desc_num);
			spin_unlock(&pcie_set->async_dynamic_desc_lock);
		}
		cn_vfree(task->pp_pages);
		cn_vfree(task->desc_buf);
		cn_kfree(task);
		return;
	} else {
		spin_lock(&pcie_set->async_task_lock);
		clear_bit(task->id, pcie_set->async_task_bitmap);
		spin_unlock(&pcie_set->async_task_lock);
	}
}

static int cn_parse_async_task(struct pcie_dma_task *task,
		struct async_task *async_task)
{
	struct cn_pcie_set *pcie_set = async_task->pcie_set;

	if (cn_pci_init_dma_task(task, &async_task->transfer, async_task->dma_type, pcie_set))
		return -1;

	task->tsk = async_task->tsk;
	task->tsk_mm = async_task->tsk_mm;
	task->dma_async = 1;

	task->kvaddr = async_task->kvaddr;
	task->kvaddr_cur = async_task->kvaddr_cur;
	task->kvaddr_align = async_task->kvaddr_align;

	return 0;
}

static void cn_pci_dma_trigger_task_release(struct async_task *async_task)
{
	if (async_task->async_info->desc_device_va) {
		if (async_task->dma_type == PCIE_DMA_USER
			|| async_task->dma_type == PCIE_DMA_PINNED_MEM) {
			cn_pci_pinned_unmap_sg(async_task);
		}
	}

	if (async_task->kvaddr)
		cn_pinned_mem_put_kv(async_task->tsk->tgid, async_task->kvaddr);
	if (async_task->kvaddr_align)
		cn_pinned_mem_put_kv(async_task->tsk->tgid, async_task->kvaddr_align);
	if (!async_task->abort_flag)
		cn_pci_put_async_mem_release(async_task);

	if (async_task->dma_type == PCIE_DMA_USER
		|| async_task->dma_type == PCIE_DMA_PINNED_MEM) {
		put_task_struct(async_task->tsk);
		mmdrop(async_task->tsk_mm);
	}

	cn_pci_put_async_dma_idle_task(async_task->pcie_set, async_task, async_task->async_info);
}

static int cn_pci_set_remain_task_err(struct async_task *async_task)
{
	u32 status;
	struct async_task *task;
	struct async_task *next_task = async_task->next_task;

	status = DMA_TASK_FINISH_ERR;

	while (next_task) {
		task = next_task;
		cn_sbts_dma_finish_set_sta(
				task->pcie_set_stream->bus_set->core,
				task->async_info->ack_host_va,
				status, 0, 0);
		next_task = task->next_task;
		cn_pci_dma_trigger_task_release(task);
	}

	return 0;
}

static int cn_pci_dma_trigger_task(struct async_task *async_task)
{
	struct cn_pcie_set *pcie_set = async_task->pcie_set;
	int ret = 0;
	struct pcie_dma_task *task = NULL;
	u32 status;
	u64 start_ns, finish_ns;

	cn_dev_pcie_debug(pcie_set, "async dma trigger tags:%llu, index:%llu",
			async_task->tags, async_task->index);

	start_ns = get_host_timestamp_by_clockid(async_task->clockid);
	if (async_task->dma_type == PCIE_DMA_P2P) {
		ret = cn_pci_dma_p2p(&async_task->peer);
	} else if (async_task->dma_type == PCIE_DMA_MEMSET) {
		ret = pci_dma_memset((void *)pcie_set, &async_task->memset);
	} else {
		task = cn_pci_get_dma_idle_task(pcie_set, async_task->transfer.direction);
		if (!task) {
			ret = -1;
			goto exit;
		}

		if (cn_parse_async_task(task, async_task)) {
			ret = -1;
			cn_pci_put_dma_idle_task(pcie_set, task);
			goto exit;
		}

		if (cn_pci_dma_transfer(task))
			ret = -1;
		cn_pci_put_dma_idle_task(pcie_set, task);
	}

exit:
	finish_ns = get_host_timestamp_by_clockid(async_task->clockid);
	if (ret)
		status = DMA_TASK_FINISH_ERR;
	else
		status = DMA_TASK_FINISH;
	cn_sbts_dma_finish_set_sta(
			async_task->pcie_set_stream->bus_set->core,
			async_task->async_info->ack_host_va,
			status,
			cpu_to_le64(start_ns),
			cpu_to_le64(finish_ns));

	if (ret)
		cn_pci_set_remain_task_err(async_task);
	cn_pci_dma_trigger_task_release(async_task);

	return ret;
}

static int cn_pci_dma_abort(u64 tags, u64 index, void *pcie_priv)
{
	struct async_task *async_task = NULL;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct hlist_node *tmp;

	mutex_lock(&pcie_set->async_task_hash_lock);
	hash_for_each_possible_safe(pcie_set->async_task_htable,
						async_task, tmp, hlist, tags) {
		if (async_task->tags != tags)
			continue;
		if (async_task->index != index)
			continue;

		hash_del(&async_task->hlist);
		mutex_unlock(&pcie_set->async_task_hash_lock);

		async_task->abort_flag = 1;
		cn_pci_dma_trigger_task_release(async_task);
		return 0;
	}
	cn_dev_pcie_err(pcie_set, "no task in hash table for abort tags:%llu index:%llu",
				tags, index);
	mutex_unlock(&pcie_set->async_task_hash_lock);
	return 0;
}

static int cn_pci_get_pinned_page(struct async_task *task,
		unsigned long pinned_addr, size_t len, unsigned long nr_pages)
{
	struct pinned_mem_va *mem_uva;
	struct pinned_mem *mem_blk;
	unsigned long page_count = 0;
	unsigned long offset, count;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int nents = 0;
	struct page *pg;

	mem_uva = cn_pinned_mem_check(task->tsk, pinned_addr, len);
	if (!mem_uva || !(mem_uva->pst_blk)) {
		cn_dev_pcie_err(pcie_set,
				"mem 0x%lx not exsit in pinned mem table",
				pinned_addr);
		return -EFAULT;
	}

	mem_blk = mem_uva->pst_blk;

	while (len > 0 && nents < nr_pages) {
		pg = cn_pinned_mem_get_pages(mem_blk, mem_uva->va_start,
				pinned_addr, &page_count);
		if (!pg) {
			cn_dev_pcie_err(pcie_set,
					"mem 0x%lx not exsit in pinned mem table",
					pinned_addr);
			return -EFAULT;
		}

		task->pp_pages[nents] = pg;

		offset = pinned_addr - mem_uva->va_start;
		offset &= ~PAGE_MASK;
		count = min((page_count << PAGE_SHIFT) - offset, len);

		/* save first page offset */
		if (nents == 0)
			task->offset = offset;

		task->chunk[nents] = count;

		pinned_addr += count;
		len -= count;
		nents++;
	}

	if (len > 0)
		return -1;

	task->nents = nents;

	return nents;
}

static void cn_pci_pinned_unmap_sg(struct async_task *task)
{
	struct scatterlist *sg;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	unsigned long dma_addr;
	unsigned long count;
	struct device *dev;
	int i = 0;

	dev = &pcie_set->pdev->dev;

	for_each_sg(task->sg_list, sg, task->sg_list_nents, i) {
		dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);
		dma_unmap_page(dev, dma_addr, count, DMA_BIDIRECTIONAL);
	}
	task->sg_list_nents = 0;
}

static int cn_pci_pinned_map_sg(struct async_task *task)
{
	struct scatterlist *sg_list = task->sg_list;
	struct device *dev;
	unsigned long dma_addr;
	unsigned long offset, count;
	struct page *pg;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int i;

	dev = &pcie_set->pdev->dev;
	task->sg_list_nents = 0;
	offset = task->offset;

	for (i = 0; i < task->nents; i++) {
		pg = task->pp_pages[i];
		count = task->chunk[i];

		dma_addr = (unsigned long)dma_map_page(dev, pg, offset,
				count, DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dev, dma_addr)) {
			cn_dev_pcie_err(pcie_set, "dma_mapping_error error");
			goto exit;
		}

		sg_dma_address(sg_list) = dma_addr;
		sg_dma_len(sg_list) = count;

		sg_list++;
		task->sg_list_nents++;
		offset = 0;
	}

	return 0;
exit:
	cn_pci_pinned_unmap_sg(task);
	return -1;
}

static int cn_pci_async_get_dynamic_task_desc(struct async_task *task, int desc_num)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int bit_index;
	int desc_align_num;

	/* Hardware Limit: desc addr 64 Bytes align */
	desc_align_num = 64 / pcie_set->per_desc_size;
	if (desc_num % desc_align_num)
		desc_num += desc_align_num - (desc_num % desc_align_num);

	spin_lock(&pcie_set->async_dynamic_desc_lock);
	bit_index = bitmap_find_next_zero_area(pcie_set->async_dynamic_desc_bitmap,
			pcie_set->async_dynamic_desc_num, 0,
			desc_num, 0);
	if (bit_index >= pcie_set->async_dynamic_desc_num) {
		spin_unlock(&pcie_set->async_dynamic_desc_lock);
		return -1;
	}
	bitmap_set(pcie_set->async_dynamic_desc_bitmap, bit_index, desc_num);
	spin_unlock(&pcie_set->async_dynamic_desc_lock);

	task->bit_index = bit_index;
	task->dynamic_desc_num = desc_num;
	task->dev_desc_addr = pcie_set->async_dynamic_desc_dev_va +
				bit_index * pcie_set->per_desc_size;
	task->host_desc_addr = pcie_set->async_dynamic_desc_host_kva +
				bit_index * pcie_set->per_desc_size;

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
	struct pinned_mem_va *mem;
	struct async_task *task = NULL;
	struct dma_async_info_s *async_info = NULL;
	enum CN_PCIE_DMA_TYPE dma_type;
	struct cn_pcie_set *pcie_set_stream = (struct cn_pcie_set *)pcie_priv;
	struct cn_bus_set *bus_set = (struct cn_bus_set *)t->bus_set;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)bus_set->priv;
	size_t head_cnt = 0;
	size_t tail_cnt = 0;
	int ret;
	int nents = 0;

	ret = cn_pci_get_async_dma_idle_task(pcie_set, &task, &async_info);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "get idle async task fail");
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

	task->async_info = async_info;
	memcpy(&task->transfer, t, sizeof(*t));
	task->index = async_info->index;
	task->tags = async_info->tags;
	task->dma_type = dma_type;
	task->tsk = current;
	task->tsk_mm = current->mm;
	task->pcie_set = pcie_set;
	task->pcie_set_stream = pcie_set_stream;
	task->user = t->user;
	task->clockid = get_host_timestamp_clockid(t->user, bus_set->core);
	INIT_WORK(&task->trigger_work, cn_pci_async_message_work);

	if (dma_type == PCIE_DMA_PINNED_MEM) {
		task->kvaddr = cn_pinned_mem_get_kv(task->tsk->tgid,
				t->ca, t->size);
		if (!task->kvaddr) {
			cn_dev_pcie_err(pcie_set,
				"t->ca=0x%lx t->size=0x%lx\n", t->ca, t->size);
			goto exit;
		}
		task->kvaddr_cur = task->kvaddr;

		if (pcie_set->ops->dma_align) {
			pcie_set->ops->dma_align(t, &head_cnt, &tail_cnt);

			if (tail_cnt) {
				task->kvaddr_align =
					cn_pinned_mem_get_kv(task->tsk->tgid,
							t->ca + t->size - tail_cnt, tail_cnt);
				if (!task->kvaddr_align) {
					cn_pinned_mem_put_kv(task->tsk->tgid, task->kvaddr);
					cn_dev_pcie_err(pcie_set,
						"t->ca=0x%lx t->size=0x%lx tail_cnt=0x%lx\n",
						t->ca, t->size, tail_cnt);
					goto exit;
				}
			}
		}
	}

	atomic_inc(&current->mm->mm_count);
	get_task_struct(task->tsk);

	if (pcie_set->arm_trigger_enable
			&& pcie_set == pcie_set_stream
			&& dma_type == PCIE_DMA_PINNED_MEM
			&& t->size <= pcie_set->arm_trigger_max_size
			&& (t->direction == DMA_H2D || t->direction == DMA_D2H)
			&& IS_ALIGNED(t->ca, 4) && IS_ALIGNED(t->ia, 4) && IS_ALIGNED(t->size, 4)) {

		nents = cn_pci_get_pinned_page(task, t->ca, t->size, pcie_set->async_max_desc_num - 1);
		if (nents < 0)
			goto host_trigger_task;

		if (task->dynamic_alloc_flag) {
			if (cn_pci_async_get_dynamic_task_desc(task, nents))
				goto host_trigger_task;
		}

		sg_init_table(task->sg_list, pcie_set->async_max_desc_num);

		ret = cn_pci_pinned_map_sg(task);
		if (ret < 0)
			goto host_trigger_task;

		if (pcie_set->ops->async_dma_fill_desc_list(task)) {
			cn_dev_pcie_err(pcie_set, "async dma fill desc fail");
			cn_pci_pinned_unmap_sg(task);
			goto host_trigger_task;
		}

		async_info->desc_len = task->desc_len;
		async_info->desc_device_va = task->dev_desc_addr;

		cn_dev_pcie_debug(pcie_set,
				"arm async dma tags:%llu, index:%llu", async_info->tags, async_info->index);
	}

host_trigger_task:
	mutex_lock(&pcie_set_stream->async_task_hash_lock);
	hash_add(pcie_set_stream->async_task_htable, &task->hlist, async_info->tags);
	mutex_unlock(&pcie_set_stream->async_task_hash_lock);

	if (async_info->desc_device_va) {
		__sync_fetch_and_add(&pcie_set_stream->arm_trigger_dma_cnt, 1);
	} else {
		__sync_fetch_and_add(&pcie_set_stream->host_trigger_dma_cnt, 1);
	}
	cn_dev_pcie_debug(pcie_set,
		"async dma tags:%llu, index:%llu", async_info->tags, async_info->index);

	return 0;

exit:
	cn_pci_put_async_dma_idle_task(pcie_set, task, async_info);
	return -1;
}

static int cn_pci_get_async_htable(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct async_task *async_task = NULL;
	struct hlist_node *tmp;
	int i = 0;
	int hash_size = HASH_SIZE(pcie_set->async_task_htable);
	u32 used_cnt;
	int flag = 0;

	mutex_lock(&pcie_set->async_task_hash_lock);
	for (i = 0; i < hash_size; i++) {
		used_cnt = 0;
		hlist_for_each_entry_safe(async_task, tmp,
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
	struct async_task *async_task = NULL;
	struct dma_async_info_s *async_info = NULL;
	struct cn_pcie_set *pcie_set_stream = (struct cn_pcie_set *)pcie_priv;
	struct cn_bus_set *src_bus_set = (struct cn_bus_set *)t->src_bus_set;
	struct cn_pcie_set *pcie_set_src = (struct cn_pcie_set *)src_bus_set->priv;
	struct cn_bus_set *dst_bus_set = (struct cn_bus_set *)t->dst_bus_set;
	struct cn_pcie_set *pcie_set_dst = (struct cn_pcie_set *)dst_bus_set->priv;
	int ret;

	ret = cn_pci_get_async_dma_idle_task(pcie_set_dst, &async_task, &async_info);
	if (ret) {
		cn_dev_pcie_err(pcie_set_dst, "get idle async task fail");
		return -1;
	}

	async_info->index = t->index;
	async_info->tags = t->tags;
	async_info->host_vaddr = t->src_addr;
	async_info->device_vaddr = t->dst_addr;
	async_info->total_size = t->size;
	async_info->direction = DMA_P2P;
	*pinfo = async_info;

	memcpy(&async_task->peer, t, sizeof(*t));
	async_task->async_info = async_info;
	async_task->dma_type = PCIE_DMA_P2P;
	async_task->pcie_set_src = pcie_set_src;
	async_task->pcie_set = pcie_set_dst;
	async_task->pcie_set_stream = pcie_set_stream;

	async_task->tags = async_info->tags;
	async_task->index = async_info->index;
	async_task->user = t->user;
	async_task->clockid = get_host_timestamp_clockid(t->user, src_bus_set->core);
	INIT_WORK(&async_task->trigger_work, cn_pci_async_message_work);

	mutex_lock(&pcie_set_stream->async_task_hash_lock);
	hash_add(pcie_set_stream->async_task_htable, &async_task->hlist, async_info->tags);
	mutex_unlock(&pcie_set_stream->async_task_hash_lock);

	__sync_fetch_and_add(&pcie_set_src->host_trigger_p2p_cnt, 1);

	cn_dev_pcie_debug(pcie_set_src,
		"async p2p dma tags:%llu, index:%llu", async_info->tags, async_info->index);

	return 0;
}

static int pci_dma_memset_async(struct memset_s *t,
		struct dma_async_info_s **pinfo, void *pcie_priv)
{
	struct async_task *async_task = NULL;
	struct dma_async_info_s *async_info = NULL;
	struct cn_pcie_set *pcie_set_stream = (struct cn_pcie_set *)pcie_priv;
	struct cn_bus_set *bus_set = (struct cn_bus_set *)t->bus_set;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)bus_set->priv;
	int ret;

	ret = cn_pci_get_async_dma_idle_task(pcie_set, &async_task, &async_info);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "get idle async task fail");
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
		cn_pci_put_async_dma_idle_task(pcie_set, async_task, async_info);
		return -1;
	}
	*pinfo = async_info;

	async_task->async_info = async_info;
	memcpy(&async_task->memset, t, sizeof(*t));
	async_task->dma_type = PCIE_DMA_MEMSET;
	async_task->index = async_info->index;
	async_task->tags = async_info->tags;
	async_task->pcie_set = pcie_set;
	async_task->pcie_set_stream = pcie_set_stream;
	async_task->user = t->user;
	async_task->clockid = get_host_timestamp_clockid(t->user, bus_set->core);
	INIT_WORK(&async_task->trigger_work, cn_pci_async_message_work);

	mutex_lock(&pcie_set_stream->async_task_hash_lock);
	hash_add(pcie_set_stream->async_task_htable, &async_task->hlist, async_info->tags);
	mutex_unlock(&pcie_set_stream->async_task_hash_lock);

	cn_dev_pcie_debug(pcie_set, "async memset tags:%llu, index:%llu", async_info->tags, async_info->index);

	return 0;
}

static void cn_pci_async_message_work(struct work_struct *work)
{
	struct async_task *async_task = (struct async_task *)container_of(work,
			struct async_task, trigger_work);
	struct cn_pcie_set *pcie_set_stream = async_task->pcie_set_stream;
	int ret;
	u64 tags;
	u64 index;
	struct async_task *next_task;
	int trigger_type = async_task->trigger_type;

	cn_dev_pcie_debug(pcie_set_stream, "tags:%llu index:%llu trigger_type:%d",
			async_task->tags, async_task->index, async_task->trigger_type);

	do {
		next_task = async_task->next_task;
		switch (trigger_type) {
		case DMA_RELEASE_TASK:
			cn_pci_dma_trigger_task_release(async_task);
			break;
		case DMA_HOST_TRIGGER:
			tags = async_task->tags;
			index = async_task->index;
			ret = cn_pci_dma_trigger_task(async_task);
			if (ret) {
				cn_dev_pcie_err(pcie_set_stream, "dma trigger task failed tags:%llu index:%llu",
						tags, index);
				cn_sbts_dma_finish_wakeup(pcie_set_stream->bus_set->core);
				return;
			}
			break;
		default:
			cn_dev_pcie_err(pcie_set_stream, "unknown async_task trigger type:%d",
					async_task->trigger_type);
			break;
		}
		async_task = next_task;
	} while (next_task);

	if (trigger_type == DMA_HOST_TRIGGER)
		cn_sbts_dma_finish_wakeup(pcie_set_stream->bus_set->core);
}

static struct async_task *__dma_async_find_task_and_out(
		struct cn_pcie_set *pcie_set,
		u64 tags, u64 index)
{
	struct async_task *async_task = NULL;
	struct hlist_node *tmp;

	mutex_lock(&pcie_set->async_task_hash_lock);
	hash_for_each_possible_safe(pcie_set->async_task_htable,
			async_task, tmp, hlist, tags) {
		if (async_task->tags != tags)
			continue;
		if (async_task->index != index)
			continue;

		hash_del(&async_task->hlist);
		mutex_unlock(&pcie_set->async_task_hash_lock);

		return async_task;
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
	struct async_task *head_task = NULL;
	struct async_task *async_task = NULL;
	struct async_task *prev_task = NULL;
	int i;

	cn_dev_pcie_debug(pcie_set, "tags:%llu index:%llu trigger_type:%d task_num:%d",
			message->tags, message->task_info[0].index,
			message->trigger_type, message->task_num);

	for (i = 0; i < message->task_num; i++) {
		async_task = __dma_async_find_task_and_out(pcie_set,
				message->tags, message->task_info[i].index);
		if (!async_task) {
			cn_dev_pcie_err(pcie_set, "find task in hash table failed");
			return -1;
		}
		async_task->trigger_type = message->trigger_type;

		if (!head_task)
			head_task = async_task;

		if (prev_task) {
			prev_task->next_task = async_task;
			async_task->prev_task = prev_task;
		}

		prev_task = async_task;
	}
	async_task->next_task = NULL;

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
	if (cn_pci_async_dma_task_init(pcie_set)) {
		return -1;
	}

	hash_init(pcie_set->async_task_htable);

	cn_dev_pcie_debug(pcie_set, "ASYNC DMA INIT");

	return 0;
}

static void cn_pci_dma_async_exit(struct cn_pcie_set *pcie_set)
{
	cn_pci_async_dma_task_release(pcie_set);

	cn_dev_pcie_debug(pcie_set, "ASYNC DMA EXIT");
}
