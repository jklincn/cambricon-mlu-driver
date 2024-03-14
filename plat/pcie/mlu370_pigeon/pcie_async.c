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

static void cn_pci_async_pinned_mem_sgl_free(struct async_task *task);
static void cn_pci_async_message_work(struct work_struct *work);

static void cn_pci_put_async_mem_release(struct async_task *async_task)
{
	if (async_task->dma_type == PCIE_DMA_P2P) {
		if (async_task->async_info->desc_device_va) {
			cn_mem_linear_unmap(async_task->peer.dst_minfo,
				async_task->sg_tb);
		}

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

	/* async task bitmap */
	cn_kfree(pcie_set->async_task_bitmap);

	/* async info table */
	if (!pcie_set->async_info_table)
		return;
	for (i = 0; i < pcie_set->async_static_task_num; i++) {
		async_info = pcie_set->async_info_table[i];
		cn_kfree(async_info);
	}
	cn_kfree(pcie_set->async_info_table);
	pcie_set->async_info_table = NULL;

	/* async task table */
	if (!pcie_set->async_task_table)
		return;
	for (i = 0; i < pcie_set->async_static_task_num; i++) {
		task = pcie_set->async_task_table[i];
		cn_kfree(task);
	}
	cn_kfree(pcie_set->async_task_table);
	pcie_set->async_task_table = NULL;

	if (pcie_set->arm_trigger_enable) {
		cn_vfree(pcie_set->async_desc_buf);
		cn_vfree(pcie_set->async_chunk);
		cn_vfree(pcie_set->async_sg_list);
		cn_vfree(pcie_set->async_pp_pages);
		if (pcie_set->async_desc_host_kva &&
			pcie_set->async_desc_dev_va) {
			cn_device_share_mem_free(0, pcie_set->async_desc_host_kva,
					pcie_set->async_desc_dev_va,
					pcie_set->bus_set->core);
		}
		cn_kfree(pcie_set->async_desc_bitmap);
	}
}

static int cn_pci_async_dma_task_init(struct cn_pcie_set *pcie_set)
{
	int i, ret;
	struct async_task *task;
	struct dma_async_info_s *async_info;
	u32 bitmap_size;

	/* desc buf */
	if (pcie_set->arm_trigger_enable) {
		bitmap_size = BITS_TO_LONGS(pcie_set->async_desc_num) *
					sizeof(long);
		pcie_set->async_desc_bitmap = cn_kzalloc(bitmap_size, GFP_KERNEL);
		if (pcie_set->async_desc_bitmap == NULL) {
			cn_dev_pcie_err(pcie_set, "async desc bitmap alloc fail");
			goto exit;
		}
		spin_lock_init(&pcie_set->async_desc_lock);

		ret = cn_device_share_mem_alloc(0, &pcie_set->async_desc_host_kva,
				&pcie_set->async_desc_dev_va,
				pcie_set->async_desc_size,
				pcie_set->bus_set->core);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "async desc alloc fail");
			goto exit;
		}

		pcie_set->async_pp_pages = cn_vzalloc(sizeof(struct page *) *
					pcie_set->async_desc_size /
					pcie_set->per_desc_size);
		if (pcie_set->async_pp_pages == NULL)
			goto exit;

		pcie_set->async_sg_list = cn_vzalloc(sizeof(struct scatterlist) *
					pcie_set->async_desc_size /
					pcie_set->per_desc_size);
		if (pcie_set->async_sg_list == NULL)
			goto exit;

		pcie_set->async_chunk = cn_vzalloc(sizeof(int) *
					pcie_set->async_desc_size /
					pcie_set->per_desc_size);
		if (pcie_set->async_chunk == NULL)
			goto exit;

		pcie_set->async_desc_buf = cn_vzalloc(pcie_set->async_desc_size);
		if (pcie_set->async_desc_buf == NULL)
			goto exit;
	}

	/* async task table */
	pcie_set->async_task_table = cn_kzalloc(
			sizeof(task) * pcie_set->async_static_task_num,
			GFP_KERNEL);
	if (pcie_set->async_task_table == NULL)
		goto exit;
	for (i = 0; i < pcie_set->async_static_task_num; i++) {
		task = cn_kzalloc(sizeof(*task), GFP_KERNEL);
		if (task == NULL)
			goto exit;
		task->id = i;
		pcie_set->async_task_table[i] = task;
	}

	/* async info table */
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

	/* async task bitmap */
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

static int cn_pci_async_get_task_desc(struct async_task *task, int desc_num)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int bit_index;
	int desc_align_num;
	u64 prt_start, cur;

	/* Hardware Limit: desc addr 64 Bytes align */
	desc_align_num = 64 / pcie_set->per_desc_size;
	if (desc_num % desc_align_num)
		desc_num += desc_align_num - (desc_num % desc_align_num);

	prt_start = get_jiffies_64();
retry:
	spin_lock(&pcie_set->async_desc_lock);
	bit_index = bitmap_find_next_zero_area(pcie_set->async_desc_bitmap,
			pcie_set->async_desc_num, 0,
			desc_num, 0);
	if (bit_index >= pcie_set->async_desc_num) {
		spin_unlock(&pcie_set->async_desc_lock);

		if (desc_num > pcie_set->async_max_desc_num)
			return -1;

		if (fatal_signal_pending(current)) {
			cn_dev_pcie_err(pcie_set, "killed by fatal signal");
			return -1;
		}

		cur = get_jiffies_64();
		if (time_after64(cur, prt_start + HZ * 10)) {
			cn_dev_pcie_info(pcie_set, "get task desc is busy %dms",
				jiffies_to_msecs(cur - prt_start));
			prt_start = get_jiffies_64();
			schedule();
		} else {
			usleep_range(50, 100);
		}
		goto retry;
	}
	bitmap_set(pcie_set->async_desc_bitmap, bit_index, desc_num);
	spin_unlock(&pcie_set->async_desc_lock);

	task->bit_index = bit_index;
	task->desc_num = desc_num;
	task->dev_desc_addr = pcie_set->async_desc_dev_va +
		bit_index * pcie_set->per_desc_size;
	task->host_desc_addr = pcie_set->async_desc_host_kva +
		bit_index * pcie_set->per_desc_size;
	task->desc_buf = (void *)((u64)pcie_set->async_desc_buf +
			bit_index * pcie_set->per_desc_size);
	task->pp_pages = (struct page **)((u64)pcie_set->async_pp_pages +
			bit_index * sizeof(struct page *));
	task->chunk = (int *)((u64)pcie_set->async_chunk +
			bit_index * sizeof(int));
	task->sg_list = (struct scatterlist *)((u64)pcie_set->async_sg_list +
			bit_index * sizeof(struct scatterlist));

	sg_init_table(task->sg_list, desc_num);

	return 0;
}

static void cn_pci_async_put_task_desc(struct async_task *task)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;

	if (task->desc_num) {
		spin_lock(&pcie_set->async_desc_lock);
		bitmap_clear(pcie_set->async_desc_bitmap,
				task->bit_index, task->desc_num);
		spin_unlock(&pcie_set->async_desc_lock);
		task->desc_num = 0;
	}
}

static int cn_pci_get_async_dma_idle_task(struct cn_pcie_set *pcie_set,
		struct async_task **task, struct dma_async_info_s **info)
{
	struct async_task *async_task;
	struct dma_async_info_s *async_info;
	int index;

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
		async_task->dynamic_alloc_flag = 1;
		async_info = cn_kzalloc(sizeof(*async_info), GFP_KERNEL);
		if (!async_info) {
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
	if (unlikely(pcie_set->state == PCIE_STATE_STOP)) {
		cn_dev_pcie_info(pcie_set, "dma stop");
		return;
	}

	cn_pci_async_put_task_desc(task);

	if (task->dynamic_alloc_flag) {
		cn_kfree(async_info);
		cn_kfree(task);
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

	cn_pci_init_dma_task(task, &async_task->transfer, async_task->dma_type, pcie_set);

	task->tsk = async_task->tsk;
	task->tsk_mm = async_task->tsk_mm;
	task->dma_async = 1;

	task->kvaddr = async_task->kvaddr;

	return 0;
}

static void cn_pci_async_dma_task_end(struct async_task *task)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;

	if (task->nents) {
		if (task->dma_type == PCIE_DMA_PINNED_MEM) {
			cn_pci_async_pinned_mem_sgl_free(task);
		}
		if ((task->dma_type == PCIE_DMA_P2P) &&
			(task->p2p_trans_type == P2P_TRANS_DMA_MAP)) {
			dma_unmap_sg(&pcie_set->pdev->dev, task->sg_list,
				task->nents, DMA_BIDIRECTIONAL);
		}
	}

	task->nents = 0;
}

static void cn_pci_dma_trigger_task_release(struct async_task *task)
{
	cn_pci_async_dma_task_end(task);

	if (task->kvaddr)
		cn_pinned_mem_put_kv(task->tsk->tgid, task->kvaddr);
	if (!task->abort_flag)
		cn_pci_put_async_mem_release(task);

	if (task->dma_type == PCIE_DMA_USER
		|| task->dma_type == PCIE_DMA_PINNED_MEM) {
		put_task_struct(task->tsk);
		mmdrop(task->tsk_mm);
	}

	cn_pci_put_async_dma_idle_task(task->pcie_set, task, task->async_info);
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
				async_task, tmp, hlist, tags + index) {
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

static int cn_pci_get_desc_num(struct async_task *task)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	struct pinned_mem_va *mem_uva;
	struct pinned_mem *mem_blk;
	int desc_num = 0;
	int ret;
	int chunk;
	int start_chunk;
	int end_chunk;
	unsigned long desc_max_len = 0;
	unsigned long count = 0;
	unsigned long trans_count = 0;

	switch (task->dma_type) {
	case PCIE_DMA_PINNED_MEM:
		mem_uva = cn_pinned_mem_check(task->tsk, task->async_info->host_vaddr,
				task->async_info->total_size);
		if (!mem_uva || !(mem_uva->pst_blk)) {
			cn_dev_pcie_err(pcie_set, "mem %#llx not exsit in pinned mem table",
					task->async_info->host_vaddr);
			return -EFAULT;
		}
		mem_blk = mem_uva->pst_blk;

		ret = cn_pinned_mem_get_chunks(mem_blk, mem_uva->va_start,
				task->async_info->host_vaddr, task->async_info->total_size,
				&start_chunk, &end_chunk);
		if (ret) {
			desc_num = -1;
			return desc_num;
		}
		desc_max_len = pcie_set->per_desc_max_size;
		for (chunk = start_chunk; chunk <= end_chunk; chunk++) {
			count = mem_blk->pages_cnt[chunk] * PAGE_SIZE;
			while (count) {
				trans_count = min(count, desc_max_len);
				count -= trans_count;
				desc_num++;
			}
		}
		break;
	case PCIE_DMA_P2P:
		desc_num = task->sg_tb->nents;
		break;
	default:
		cn_dev_pcie_err(pcie_set, "unknown dma type:%d", task->dma_type);
		desc_num = -1;
		break;
	}

	desc_num *= MAX_UNPACK_NUM;
	/* reserve for flush write */
	desc_num += 2;
	return desc_num;
}

static int cn_pci_async_do_pinned_page(struct async_task *task,
		unsigned long pinned_addr, size_t len)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	struct pinned_mem_va *mem_uva;
	struct pinned_mem *mem_blk;
	unsigned long page_count = 0;
	unsigned long offset, count;
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

	while (len > 0) {
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

	task->nents = nents;
	return nents;
}

static int cn_pci_async_get_pages(struct async_task *task)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	unsigned long cpu_addr;
	size_t len;
	int nents;

	switch (task->dma_type) {
	case PCIE_DMA_PINNED_MEM:
		cpu_addr = task->async_info->host_vaddr;
		len = task->async_info->total_size;
		nents = cn_pci_async_do_pinned_page(task, cpu_addr, len);
		break;
	default:
		cn_dev_pcie_err(pcie_set, "unknown dma type:%d", task->dma_type);
		nents = -1;
		break;
	}

	return nents;
}

static void cn_pci_async_pinned_mem_sgl_free(struct async_task *task)
{
	struct scatterlist *sg;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	unsigned long dma_addr;
	unsigned long count;
	struct device *dev;
	int i = 0;

	dev = &pcie_set->pdev->dev;

	for_each_sg(task->sg_list, sg, task->nents, i) {
		dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);
		if (task->transfer.direction == DMA_D2H) {
			dma_unmap_page(dev, dma_addr, count, DMA_BIDIRECTIONAL);
		} else {
			dma_unmap_page(dev, dma_addr, count, DMA_TO_DEVICE);
		}
	}
}

static int cn_pci_async_pinned_mem_sgl(struct async_task *task)
{
	struct scatterlist *sg_list = task->sg_list;
	struct device *dev;
	unsigned long dma_addr;
	unsigned long offset, count;
	struct page *pg;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int i;

	dev = &pcie_set->pdev->dev;
	offset = task->offset;

	for (i = 0; i < task->nents; i++) {
		pg = task->pp_pages[i];
		count = task->chunk[i];

		if (task->transfer.direction == DMA_D2H) {
			dma_addr = (unsigned long)dma_map_page(dev, pg, offset,
					count, DMA_BIDIRECTIONAL);
		} else {
			dma_addr = (unsigned long)dma_map_page(dev, pg, offset,
					count, DMA_TO_DEVICE);
		}
		if (dma_mapping_error(dev, dma_addr)) {
			cn_dev_pcie_err(pcie_set, "dma_mapping_error error");
			goto exit;
		}

		sg_dma_address(sg_list) = dma_addr;
		sg_dma_len(sg_list) = count;

		sg_list++;
		offset = 0;
	}

	return 0;
exit:
	cn_pci_async_pinned_mem_sgl_free(task);
	return -1;
}

static int cn_pci_async_update_sgl(struct async_task *task)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int nents;

	switch (task->dma_type) {
	case PCIE_DMA_PINNED_MEM:
		nents = cn_pci_async_pinned_mem_sgl(task);
		break;
	case PCIE_DMA_P2P:
		nents = dma_map_sg(&pcie_set->pdev->dev, task->sg_list,
				task->nents, DMA_BIDIRECTIONAL);
		if (!nents) {
			cn_dev_pcie_err(pcie_set, "dma map sglist fail nents=%d", nents);
			return -1;
		}
		break;
	default:
		cn_dev_pcie_err(pcie_set, "unknown dma type:%d", task->dma_type);
		nents = -1;
		break;
	}

	return nents;
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
	int ret;
	int desc_num = 0;

	if ((t->direction != DMA_H2D) && (t->direction != DMA_D2H)) {
		cn_dev_pcie_err(pcie_set, "direction is invalid!");
		return -1;
	}

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
	}

	atomic_inc(&current->mm->mm_count);
	get_task_struct(task->tsk);

	if (!pcie_set_stream->arm_trigger_enable) {
		async_info->reason = ASYNC_REASON_DEVICE_DISABLE;
		goto host_trigger_task;
	}
	if (pcie_set != pcie_set_stream) {
		async_info->reason = ASYNC_REASON_STREAM_INVALID;
		goto host_trigger_task;
	}
	if (dma_type != PCIE_DMA_PINNED_MEM) {
		async_info->reason = ASYNC_REASON_H2D_D2H_NOT_PINNED;
		goto host_trigger_task;
	}

	/* device trigger */
	desc_num = cn_pci_get_desc_num(task);
	if (desc_num < 0) {
		async_info->reason = ASYNC_REASON_H2D_D2H_GET_DESC_NUM_ERR;
		goto host_trigger_task;
	}

	if (cn_pci_async_get_task_desc(task, desc_num)) {
		async_info->reason = ASYNC_REASON_DESC_NOT_ENOUGH;
		goto host_trigger_task;
	}

	ret = cn_pci_async_get_pages(task);
	if (ret < 0) {
		cn_pci_async_put_task_desc(task);
		async_info->reason = ASYNC_REASON_H2D_D2H_GET_PAGES_ERR;
		goto host_trigger_task;
	}

	ret = cn_pci_async_update_sgl(task);
	if (ret < 0) {
		cn_pci_async_dma_task_end(task);
		cn_pci_async_put_task_desc(task);
		async_info->reason = ASYNC_REASON_H2D_D2H_UP_SGL_ERR;
		goto host_trigger_task;
	}

	if (pcie_set->ops->async_dma_fill_desc_list(task)) {
		cn_pci_async_dma_task_end(task);
		cn_pci_async_put_task_desc(task);
		async_info->reason = ASYNC_REASON_H2D_D2H_FILL_DESC_ERR;
		goto host_trigger_task;
	}

	async_info->reason = ASYNC_REASON_DEVICE_H2D_D2H;
	async_info->desc_len = task->desc_len;
	async_info->desc_device_va = task->dev_desc_addr;

host_trigger_task:
	mutex_lock(&pcie_set_stream->async_task_hash_lock);
	hash_add(pcie_set_stream->async_task_htable, &task->hlist,
				async_info->tags + async_info->index);
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

static size_t cn_pci_dma_p2p_async(struct peer_s *t,
		struct dma_async_info_s **pinfo, void *pcie_priv)
{
	struct async_task *task = NULL;
	struct dma_async_info_s *async_info = NULL;
	struct cn_pcie_set *pcie_set_stream = (struct cn_pcie_set *)pcie_priv;
	struct cn_bus_set *src_bus_set = (struct cn_bus_set *)t->src_bus_set;
	struct cn_pcie_set *pcie_set_src = (struct cn_pcie_set *)src_bus_set->priv;
	struct cn_bus_set *dst_bus_set = (struct cn_bus_set *)t->dst_bus_set;
	struct cn_pcie_set *pcie_set_dst = (struct cn_pcie_set *)dst_bus_set->priv;
	int able;
	int ret;
	int desc_num = 0;

	ret = cn_pci_get_async_dma_idle_task(pcie_set_src, &task, &async_info);
	if (ret) {
		cn_dev_pcie_err(pcie_set_src, "get idle async task fail");
		return -1;
	}

	async_info->index = t->index;
	async_info->tags = t->tags;
	async_info->host_vaddr = t->src_addr;
	async_info->device_vaddr = t->dst_addr;
	async_info->total_size = t->size;
	async_info->direction = DMA_P2P;
	*pinfo = async_info;

	memcpy(&task->peer, t, sizeof(*t));
	task->async_info = async_info;
	task->dma_type = PCIE_DMA_P2P;
	task->pcie_set_dst = pcie_set_dst;
	task->pcie_set = pcie_set_src;
	task->pcie_set_stream = pcie_set_stream;

	task->tags = async_info->tags;
	task->index = async_info->index;
	task->user = t->user;
	task->clockid = get_host_timestamp_clockid(t->user, src_bus_set->core);
	INIT_WORK(&task->trigger_work, cn_pci_async_message_work);
	able = cn_bus_dma_p2p_able(src_bus_set, dst_bus_set);
	if (able == P2P_FAST_ABLE) {
		task->p2p_trans_type = P2P_TRANS_BUS_ADDRESS;
	} else {
		task->p2p_trans_type = P2P_TRANS_DMA_MAP;
	}

	if (!pcie_set_stream->arm_trigger_enable) {
		async_info->reason = ASYNC_REASON_DEVICE_DISABLE;
		goto host_trigger_task;
	}
	if (pcie_set_stream != pcie_set_src) {
		async_info->reason = ASYNC_REASON_STREAM_INVALID;
		goto host_trigger_task;
	}
	if (able == P2P_HOST_TRANSFER) {
		async_info->reason = ASYNC_REASON_P2P_HOST_TRANSFER;
		goto host_trigger_task;
	}
	if (t->size > pcie_set_stream->per_desc_max_size) {
		async_info->reason = ASYNC_REASON_P2P_EXCEED_SIZE;
		goto host_trigger_task;
	}

	/* device trigger */
	task->sg_tb = cn_mem_linear_remap(t->dst_minfo, t->dst_addr, t->size);
	if (IS_ERR_OR_NULL(task->sg_tb)) {
		async_info->reason = ASYNC_REASON_P2P_LINEAR_REMAP_ERR;
		goto host_trigger_task;
	}

	desc_num = cn_pci_get_desc_num(task);
	if (cn_pci_async_get_task_desc(task, desc_num)) {
		cn_mem_linear_unmap(t->dst_minfo, task->sg_tb);
		async_info->reason = ASYNC_REASON_DESC_NOT_ENOUGH;
		goto host_trigger_task;
	}
	task->nents = task->sg_tb->nents;
	task->sg_list = task->sg_tb->sgl;

	if (task->p2p_trans_type == P2P_TRANS_DMA_MAP) {
		ret = cn_pci_async_update_sgl(task);
		if (ret < 0) {
			cn_mem_linear_unmap(t->dst_minfo, task->sg_tb);
			cn_pci_async_dma_task_end(task);
			cn_pci_async_put_task_desc(task);
			async_info->reason = ASYNC_REASON_P2P_UP_SGL_ERR;
			goto host_trigger_task;
		}
	}

	if (pcie_set_stream->ops->async_dma_fill_desc_list(task)) {
		cn_mem_linear_unmap(t->dst_minfo, task->sg_tb);
		cn_pci_async_dma_task_end(task);
		cn_pci_async_put_task_desc(task);
		cn_dev_pcie_err(pcie_set_stream, "async dma fill desc fail");
		async_info->reason = ASYNC_REASON_P2P_FILL_DESC_ERR;
		goto host_trigger_task;
	}

	async_info->reason = ASYNC_REASON_DEVICE_P2P;
	async_info->desc_len = task->desc_len;
	async_info->desc_device_va = task->dev_desc_addr;

host_trigger_task:
	mutex_lock(&pcie_set_stream->async_task_hash_lock);
	hash_add(pcie_set_stream->async_task_htable, &task->hlist,
				async_info->tags + async_info->index);
	mutex_unlock(&pcie_set_stream->async_task_hash_lock);

	if (async_info->desc_device_va) {
		__sync_fetch_and_add(&pcie_set_stream->arm_trigger_p2p_cnt, 1);
	} else {
		__sync_fetch_and_add(&pcie_set_stream->host_trigger_p2p_cnt, 1);
	}

	cn_dev_pcie_debug(pcie_set_stream,
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
	async_info->host_vaddr = t->val;
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
	async_info->reason = ASYNC_REASON_DEVICE_NOTSUPPORT;
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
	hash_add(pcie_set_stream->async_task_htable, &async_task->hlist,
				async_info->tags + async_info->index);
	mutex_unlock(&pcie_set_stream->async_task_hash_lock);

	cn_dev_pcie_debug(pcie_set, "async memset tags:%llu, index:%llu", async_info->tags, async_info->index);

	return 0;
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
	u64 prt_start, sch_start, cur;

	cn_dev_pcie_debug(pcie_set_stream, "tags:%llu index:%llu trigger_type:%d",
			async_task->tags, async_task->index, async_task->trigger_type);

	prt_start = get_jiffies_64();
	sch_start = get_jiffies_64();
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

		cur = get_jiffies_64();
		if (time_after64(cur, sch_start + HZ * 5)) {
			sch_start = get_jiffies_64();
			usleep_range(50, 100);
		}
		if (time_after64(cur, prt_start + HZ * 15)) {
			cn_dev_pcie_info(pcie_set_stream, "async message work is busy %dms",
				jiffies_to_msecs(cur - prt_start));
			prt_start = get_jiffies_64();
			schedule();
		}
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
			async_task, tmp, hlist, tags + index) {
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

	if (unlikely(pcie_set->state == PCIE_STATE_STOP)) {
		cn_dev_pcie_info(pcie_set, "dma stop");
		return -1;
	}

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
	mutex_init(&pcie_set->async_task_hash_lock);

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
