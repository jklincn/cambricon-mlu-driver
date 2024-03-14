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

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <asm/io.h>
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

static void cn_pci_shared_dma_desc_release(struct cn_pcie_set *pcie_set);
static void cn_pci_shared_dma_channel_soft_release(struct dma_channel_info *channel);
static void cn_pci_priv_dma_desc_release(struct cn_pcie_set *pcie_set);
static void cn_pci_priv_dma_channel_release(struct pcie_dma_task *task, int order);
static void cn_pci_priv_dma_channel_soft_release(struct dma_channel_info *channel);
static void cn_pci_pinned_mem_sgl_free(struct dma_channel_info *channel, struct cn_pcie_set *pcie_set);
static int cn_pci_channel_dma_start(struct cn_pcie_set *pcie_set,
		struct dma_channel_info *channel, int phy);
static int cn_pci_dma_async_init(struct cn_pcie_set *pcie_set);

static struct pcie_dma_task *cn_pci_get_dma_idle_task(struct cn_pcie_set *pcie_set, DMA_DIR_TYPE direction);
static void cn_pci_put_dma_idle_task(struct cn_pcie_set *pcie_set,
		struct pcie_dma_task *task);
static void cn_pci_dma_task_release(struct cn_pcie_set *pcie_set);
static int cn_pci_finish_fifo_complete_out(struct cn_pcie_set *pcie_set, struct pcie_dma_task *task);

static int cn_pci_dma_phy_empty(struct cn_pcie_set *pcie_set, int phy)
{
	int i = 0;
	int ret = 1;

	for (i = 0; i < pcie_set->dma_fetch_buff; i++) {
		if (pcie_set->running_channels[phy][i]) {
			ret = 0;
			break;
		}
	}
	return ret;
}

static int cn_pci_dma_phy_busy_num(struct cn_pcie_set *pcie_set, int phy)
{
	int i = 0;
	int ret = 0;

	for (i = 0; i < pcie_set->dma_fetch_buff; i++) {
		if (pcie_set->running_channels[phy][i]) {
			ret++;
		}
	}
	return ret;
}

static struct dma_channel_info *cn_pci_get_priv_idle_channel(struct cn_pcie_set *pcie_set,
		struct pcie_dma_task *task, int order)
{
	int i, n, cnt;
	struct dma_channel_info *channel;
	struct dma_channel_info **list;

	/* priv_order_table maybe NULL when don't init dma priv channel */
	if (!task->priv_order_table)
		return NULL;

	for (n = order; n <= pcie_set->max_desc_order - 1; n++) {
		cnt = task->priv_order_table[n].number;
		list = task->priv_order_table[n].list;
		for (i = 0; i < cnt; i++) {
			channel = list[i];
			if (__sync_bool_compare_and_swap(
						&channel->status,
						CHANNEL_IDLE, CHANNEL_ASSIGNED)) {
				channel->task = task;
				return channel;
			}
		}
	}

	return NULL;
}

static struct dma_channel_info *cn_pci_get_shared_idle_channel(
	struct cn_pcie_set *pcie_set, struct pcie_dma_task *task, int order)
{
	int i;
	int index;
	struct dma_channel_info *channel;

	if (!pcie_set->shared_channel_list)
		return NULL;

	for (i = 0; i < pcie_set->shared_channel_cnt;  i++) {
		index = (i + pcie_set->shared_channel_search) % pcie_set->shared_channel_cnt;
		channel = pcie_set->shared_channel_list[index];
		if (__sync_bool_compare_and_swap(
					&channel->status,
					CHANNEL_IDLE, CHANNEL_ASSIGNED)) {
			__sync_fetch_and_add(&pcie_set->shared_channel_search, 1);
			channel->task = task;
			return channel;
		}
	}

	return NULL;
}

static struct dma_channel_info *cn_pci_get_idle_channel(struct cn_pcie_set *pcie_set,
		struct pcie_dma_task *task, int nents)
{
	static int cap;
	int order;
	struct dma_channel_info *channel;
	u64 prt_start, sch_start, cur;

	if ((task->dma_type == PCIE_DMA_P2P) &&
		(task->p2p_trans_type == P2P_TRANS_BUS_ADDRESS)) {
		order = 2;
	} else {
		cap = cap ? cap : roundup_pow_of_two(
			(pcie_set->dma_buffer_size / PAGE_SIZE) + 1);
		if (nents <= 0 || nents > cap * MAX_UNPACK_NUM) {
			cn_dev_pcie_err(pcie_set, "before nents=%d\n", nents);
			return NULL;
		}

		nents = roundup_pow_of_two(nents);
		order = order_base_2(nents);
		cn_dev_pcie_debug(pcie_set, "nents=%d, order=%d\n", nents, order);
	}

	prt_start = get_jiffies_64();
	sch_start = get_jiffies_64();
	while (1) {
		if (fatal_signal_pending(current)) {
			cn_dev_pcie_err(pcie_set, "killed by fatal signal");
			return NULL;
		}

		if (!pcie_set->des_set) {
			channel = cn_pci_get_priv_idle_channel(pcie_set, task, order);
			if (channel)
				return channel;
		}
		channel = cn_pci_get_shared_idle_channel(pcie_set, task, order);
		if (channel)
			return channel;

		cur = get_jiffies_64();
		if (time_after64(cur, sch_start + HZ * 5)) {
			sch_start = get_jiffies_64();
			usleep_range(50, 100);
		}
		if (time_after64(cur, prt_start + HZ * 15)) {
			cn_dev_pcie_info(pcie_set, "get idle channel is busy %dms",
				jiffies_to_msecs(cur - prt_start));
			prt_start = get_jiffies_64();
			schedule();
		}

		if (cn_pci_finish_fifo_complete_out(pcie_set, task))
			return NULL;

		/* limit the number of virt channels per task for
		 * fair scheduling when a packet is too large
		 */
		if (kfifo_len(&task->ready_fifo) > 32 * sizeof(channel)) {
			usleep_range(50, 60);
			cn_dev_pcie_debug(pcie_set, "get idle channel fifo is busy");
		}
	}

	return NULL;
}

static void cn_pci_set_idle_channel(struct dma_channel_info *channel)
{
	__sync_lock_test_and_set(&channel->status, CHANNEL_IDLE);
}

static int
cn_pci_channel_dma_ready(struct dma_channel_info *channel, size_t remain)
{
	ulong channel_mask;
	struct pcie_dma_task *task = channel->task;
	struct cn_pcie_set *p = channel->pcie_set;
	int start = 0;
	int ret;
	unsigned long flags;
	int phy;
	int index;
	int i;
	int empty = 1;
	int running_phy_num = 0;

	if (p->ops->fill_desc_list(channel)) {
		cn_dev_pcie_err(p, "fill desc failed");
		return -1;
	}

	channel->status = CHANNEL_READY;

	running_phy_num = cn_pci_dma_phy_busy_num(p, 0);

	if (channel->task->count <= p->dma_bypass_custom_size &&
		p->spkg_channel_id &&
		!channel->task->cfg.phy_mode &&
		running_phy_num <= (p->dma_fetch_buff / 4 + 1)) {
		for (i = 0; i < p->spkg_dma_fetch_buff; i++) {
			if (!__sync_bool_compare_and_swap(&p->spkg_status[i],
					CHANNEL_IDLE, CHANNEL_RUNNING))
				continue;

			channel->fetch_command_id = i;
			channel->task->spkg_polling_flag = 1;
			__sync_lock_test_and_set(&channel->status, CHANNEL_RUNNING);
			p->ops->dma_go_command(channel, p->spkg_channel_id);
			return 0;
		}
	}

	channel_mask = p->dma_phy_channel_mask;
	if (channel->task->cfg.phy_dma_mask) {
		channel_mask &= channel->task->cfg.phy_dma_mask;
	}

retry:
	index = p->phy_channel_search % p->max_phy_channel;
	for (i = 0; i < p->max_phy_channel; i++) {
		phy = (i + index) % p->max_phy_channel;
		if (!test_bit(phy, &channel_mask))
			continue;
		ret = cn_pci_channel_dma_start(p, channel, phy);
		if (ret < 0) {
			return -1;
		} else if (!ret) {
			start = 1;
			goto after_search;
		}
	}

	/*
	 * if all phy channels are running, add the channel to ready_fifo,
	 * wait for schedule by last dma interrupt handle
	 *
	 * note: schedule maybe run over before fifo in,
	 * the last channel will not dma go, then timeout, do a retry here
	 */
after_search:
	if (start == 0) {
		spin_lock_irqsave(&task->ready_fifo_lock, flags);
		ret = kfifo_in(&task->ready_fifo, &channel, sizeof(channel));
		spin_unlock_irqrestore(&task->ready_fifo_lock, flags);
		if (ret != sizeof(channel)) {
			cn_dev_pcie_err(p, "bug on: ready kfifo_in fail\n");
			return -1;
		}

		for (phy = 0; phy < p->max_phy_channel; phy++) {
			if (!cn_pci_dma_phy_empty(p, phy)) {
				empty = 0;
				break;
			}
		}

		/* if all phy channel is empty
		 * recheck last channel(remain == 0 mean last)
		 */
		if (empty && remain == 0) {
			spin_lock_irqsave(&task->ready_fifo_lock, flags);
			if (!kfifo_is_empty(&task->ready_fifo)) {
				cn_dev_pcie_debug(p, "####dma retry go####");
				ret = kfifo_out(&task->ready_fifo, &channel, sizeof(channel));
				if (ret != sizeof(channel)) {
					cn_dev_pcie_err(p, "bug on: ready kfifo_out fail\n");
					spin_unlock_irqrestore(&task->ready_fifo_lock, flags);
					return -1;
				}
				spin_unlock_irqrestore(&task->ready_fifo_lock, flags);
				goto retry;
			}
			spin_unlock_irqrestore(&task->ready_fifo_lock, flags);
		}
	}
	return 0;
}

static void cn_pci_print_channel_info(struct dma_channel_info *channel,
		struct cn_pcie_set *pcie_set)
{
	if (!(pcie_set->ops->show_desc_list)) {
		cn_dev_pcie_err(pcie_set, "show_desc_list is NULL");
		return;
	}

	if (channel)
		pcie_set->ops->show_desc_list(channel);
}

static void cn_pci_dump_reg_info(struct cn_pcie_set *pcie_set)
{
	if (!(pcie_set->ops->dump_reg)) {
		cn_dev_pcie_err(pcie_set, "dump_reg is NULL");
		return;
	}
	pcie_set->ops->dump_reg(pcie_set);
}

/*
 * merge 4k continuous phy pages, reduce dma dec number
 * then increase pcie dma bandwidth
 */
static void cn_pci_pages_merge_sgl(struct dma_channel_info *channel,
		struct pcie_dma_task *task)
{
	int i;
	struct scatterlist *sg  = (struct scatterlist *)channel->sg;
	size_t remain_len = channel->transfer_length;
	size_t chunk_size;
	void **p = channel->pp_pages;
	int offset = task->offset;

	for (i = 0; i < channel->nents; i++) {
		chunk_size = min((size_t)(task->chunk[i] * PAGE_SIZE - offset),
				remain_len);
		sg_set_page(sg, (struct page *)*p, chunk_size, offset);

		remain_len -= chunk_size;
		sg = sg_next(sg);
		p = p + task->chunk[i];
		offset = 0;
	}
}

static int cn_pci_pinned_mem_sgl(struct dma_channel_info *channel,
		struct pcie_dma_task *task)
{
	struct scatterlist *sg = (struct scatterlist *)channel->sg;
	struct device *dev;
	unsigned long dma_addr = 0;
	unsigned long offset, count;
	struct page *pg;
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	int i;

	channel->nents = 0;

	dev = &pcie_set->pdev->dev;
	offset = task->offset;

	for (i = 0; i < task->nents; i++) {
		pg = task->pp_pages[i];
		count = task->chunk[i];

		if (channel->direction == DMA_D2H || channel->direction == DMA_P2P) {
			dma_addr = (unsigned long)dma_map_page(dev, pg, offset,
					count, DMA_FROM_DEVICE);
		} else {
			dma_addr = (unsigned long)dma_map_page(dev, pg, offset,
					count, DMA_TO_DEVICE);
		}
		if (dma_mapping_error(dev, dma_addr)) {
			cn_dev_pcie_err(pcie_set, "dma_mapping_error error");
			goto exit;
		}

		sg_dma_address(sg) = dma_addr;
		sg_dma_len(sg) = count;

		sg++;
		channel->nents++;
		offset = 0;
	}

	return 0;
exit:
	cn_pci_pinned_mem_sgl_free(channel, pcie_set);
	return -1;
}

static void cn_pci_put_page(struct pcie_dma_task *task, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		put_page((struct page *)task->pp_pages[i]);
		task->pp_pages[i] = NULL;
	}
}

/*
 * merge 4k continuous phy pages
 * for example 1MB user memory contain 512KB, 256KB, 256KB
 * nents = 3, chuck[0] = 512KB/4KB, chuck[1] = chuck[2] = 256KB/4KB
 */
static int cn_pci_merge_page_sg(struct pcie_dma_task *task, int cnt)
{
	int i, nents;

	nents = 1;
	task->chunk[0] = 1;

	if (cnt == 1)
		return nents;

	for (i = 1; i < cnt; i++) {
		if (page_to_pfn((struct page *)task->pp_pages[i - 1]) + 1 ==
				page_to_pfn((struct page *)task->pp_pages[i])) {
			task->chunk[nents - 1]++;
		} else {
			task->chunk[nents] = 1;
			nents++;
		}
	}
	return nents;
}

/*
 * @brief Pins user IO pages that have been mapped to the user processes virtual
 *        address space with remap_pfn_range.
 *
 * @param[in]     mm The process address space.
 * @param[in]     start Beginning of the virtual address range of the IO pages.
 * @param[in]     nr_page Number of pages to pin from start.
 * @param[in,out] pages Storage array for pointers to the pinned pages.
 *                           Must be large enough to contain at least page_count
 *                           pointers.
 *
 * @return pinned number if the pages were pinned successfully, error otherwise.
 */
static int cn_get_io_pages(struct mm_struct *mm, unsigned long start, unsigned long nr_pages, struct page **pages)
{
	struct vm_area_struct *vma;
	unsigned long pfn;
	int i, ret = 0, pinned = 0;

	/* find the first VMA which intersects the interval start_addr..end_addr-1 */
	vma = find_vma_intersection(mm, start, start + 1);

	/* Verify that the given address range is contained in a single vma */
	if ((vma == NULL) || ((vma->vm_flags & (VM_IO | VM_PFNMAP)) == 0) ||
			!((vma->vm_start <= start) &&
				((vma->vm_end - start) >> PAGE_SHIFT >= nr_pages))) {
		pr_err("Cannot map memory with base addr 0x%lx and size of 0x%lx pages\n",
				start, nr_pages);
		return -EFAULT;
	}

	for (i = 0; i < nr_pages; i++) {
		if ((follow_pfn(vma, (start + (i * PAGE_SIZE)), &pfn) < 0) ||
				(!pfn_valid(pfn))) {
			ret = -EFAULT;
			break;
		}

		/* Page-backed memory mapped to userspace with remap_pfn_range */
		pages[i] = pfn_to_page(pfn);
		get_page(pages[i]);
		pinned++;
	}

	if (pinned) {
		ret = pinned;
	}

	return ret;
}

static int cn_pci_do_user_page(struct pcie_dma_task *task,
		unsigned long cpu_addr, int cnt)
{
	int nents;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	unsigned int flags = 0;
	struct mm_struct *mm = task->tsk_mm;
	DMA_DIR_TYPE direction = task->transfer->direction;

	if (!atomic_inc_not_zero(&mm->mm_users)) {
		cn_dev_pcie_err(pcie_set, "atomic_inc_not_zero");
		return -1;
	}

	if (direction == DMA_D2H)
		flags |= FOLL_WRITE;

	cn_mmap_read_lock(mm);
	if (mm == current->mm)
		nents = cn_get_user_pages(cpu_addr, cnt, flags,
				(struct page **)(task->pp_pages), NULL);
	else
		nents = cn_get_user_pages_remote(task->tsk,
				mm, cpu_addr, cnt, flags,
				(struct page **)(task->pp_pages), NULL, NULL);

	if (nents == -EFAULT) {
		nents = cn_get_io_pages(mm, cpu_addr, cnt, (struct page **)(task->pp_pages));
	}

	cn_mmap_read_unlock(mm);
	mmput(mm);

	if (nents != cnt) {
		cn_dev_pcie_err(pcie_set,
				"cpu_addr:0x%lx, nents:%d, cnt:%d",
				cpu_addr, nents, cnt);
		cn_pci_put_page(task, nents);
		return -EFAULT;
	}

	/* merge 4k continuous phy pages */
	nents = cn_pci_merge_page_sg(task, cnt);
	return nents;
}

static int cn_pci_do_kernel_page(struct pcie_dma_task *task,
		unsigned long kernel_addr, int cnt)
{
	int i, nents;

	if (is_vmalloc_addr((void *)kernel_addr)) {
		for (i = 0; i < cnt; i++) {
			task->pp_pages[i] =
				vmalloc_to_page((void *)(kernel_addr + i * PAGE_SIZE));
		}
		nents = cn_pci_merge_page_sg(task, cnt);
	} else {
		for (i = 0; i < cnt; i++) {
			task->pp_pages[i] =
				virt_to_page(kernel_addr + i * PAGE_SIZE);
		}
		nents = 1; /* kernel addr phy continuous */
		task->chunk[0] = cnt;
	}

	return nents;
}

static int cn_pci_do_p2p_page(struct pcie_dma_task *task,
		unsigned long bar_addr, int cnt)
{
	int i, nents;

	for (i = 0; i < cnt; i++) {
		task->pp_pages[i] =
			pfn_to_page((bar_addr + i * PAGE_SIZE) >>
					PAGE_SHIFT);
	}

	nents = 1; /* bar addr phy continuous */
	task->chunk[0] = cnt;
	return nents;
}

static int cn_pci_do_pinned_page(struct pcie_dma_task *task,
		unsigned long pinned_addr, size_t len)
{
	struct pinned_mem_va *mem_uva;
	struct pinned_mem *mem_blk;
	unsigned long uva_base;
	unsigned long page_count = 0;
	unsigned long offset, count;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int nents = 0;
	struct page *pg;
	size_t transfer_len;

	if (task->dma_async) {
		mem_blk = cn_async_pinned_mem_check(task->kvaddr);
		if (!mem_blk) {
			cn_dev_pcie_err(pcie_set,
					"mem 0x%lx len=0x%lxnot exsit in pinned mem table",
					task->kvaddr, len);
			return -EFAULT;
		}

		uva_base = pinned_addr - (task->kvaddr - mem_blk->kva_start);
		transfer_len = len;
		while (len > 0) {
			pg = cn_pinned_mem_get_pages(mem_blk, uva_base,
					pinned_addr,
					&page_count);
			task->pp_pages[nents] = pg;

			offset = pinned_addr - uva_base;
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
		task->kvaddr += transfer_len;
	} else {
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
	}

	task->nents = nents;
	return nents;
}

static int cn_pci_get_pages(struct pcie_dma_task *task,
			unsigned long cpu_addr, size_t len)
{
	unsigned long offset;
	int page_cnt, nents;
	struct cn_pcie_set *pcie_set = task->pcie_set;

	if (task->nents) /* set 0, after channel copy task */
		return task->nents;

	if (task->dma_type == PCIE_DMA_PINNED_MEM) {
		nents = cn_pci_do_pinned_page(task, cpu_addr, len);
		return nents;
	}

	offset = cpu_addr & (~PAGE_MASK);
	page_cnt = (offset + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	cpu_addr &= PAGE_MASK;

	switch (task->dma_type) {
	case PCIE_DMA_USER:
	case PCIE_DMA_USER_REMOTE:
		nents = cn_pci_do_user_page(task, cpu_addr, page_cnt);
		break;

	case PCIE_DMA_MEMSET:
	case PCIE_DMA_KERNEL:
		nents = cn_pci_do_kernel_page(task, cpu_addr, page_cnt);
		break;

	case PCIE_DMA_P2P:
		nents = cn_pci_do_p2p_page(task, cpu_addr, page_cnt);
		break;

	default:
		cn_dev_pcie_err(pcie_set, "fail dma type: %d\n", task->dma_type);
		return -1;
	}

	if (nents < 0)
		return nents;

	task->nents = nents;
	task->page_cnt = page_cnt;

	/*
	 * just save first page offset, other pages must 4KB align
	 */
	task->offset = offset;

	return nents;
}

static int cn_pci_fill_channel_sg(struct dma_channel_info *channel,
		struct pcie_dma_task *task)
{
	void **p;

	/* just swap point table for fast copy */
	p = channel->pp_pages;
	channel->pp_pages = task->pp_pages;
	task->pp_pages = p;

	channel->page_cnt = task->page_cnt;
	channel->nents = task->nents;

	cn_pci_pages_merge_sgl(channel, task);

	/* after copy to channel from task, clear task */
	task->nents = 0;
	task->page_cnt = 0;
	return 0;
}

static int cn_pci_channel_update_sgl(struct dma_channel_info *channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	struct pcie_dma_task *task = channel->task;
	int nents;

	if (task->dma_type == PCIE_DMA_PINNED_MEM) {
		cn_pci_pinned_mem_sgl(channel, task);
		task->nents = 0;
		return 0;
	}

	if (cn_pci_fill_channel_sg(channel, task)) {
		cn_dev_pcie_err(pcie_set, "cn_pci_fill_channel_sg fail");
		return -1;
	}

	if (channel->direction == DMA_D2H || channel->direction == DMA_P2P) {
		nents = dma_map_sg(&pcie_set->pdev->dev, channel->sg, channel->nents,
				DMA_FROM_DEVICE);
	} else {
		nents = dma_map_sg(&pcie_set->pdev->dev, channel->sg, channel->nents,
				DMA_TO_DEVICE);
	}
	if (!nents) {
		cn_dev_pcie_err(pcie_set, "dma map sglist fail nents=%d", nents);
		return -1;
	}
	channel->nents = nents;

	return 0;
}

static void cn_pci_pinned_mem_sgl_free(struct dma_channel_info *channel,
	struct cn_pcie_set *pcie_set)
{
	struct scatterlist *sg;
	unsigned long dma_addr;
	unsigned long count;
	struct device *dev = &pcie_set->pdev->dev;
	int i = 0;

	for_each_sg(channel->sg, sg, channel->nents, i) {
		dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);
		if (channel->direction == DMA_D2H || channel->direction == DMA_P2P) {
			dma_unmap_page(dev, dma_addr, count, DMA_FROM_DEVICE);
		} else {
			dma_unmap_page(dev, dma_addr, count, DMA_TO_DEVICE);
		}
	}
	channel->nents = 0;
}

static int cn_pci_channel_dma_end(struct dma_channel_info *channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	int i;

	if (channel->dma_type == PCIE_DMA_PINNED_MEM)
		cn_pci_pinned_mem_sgl_free(channel, pcie_set);
	if (channel->nents && channel->dma_type != PCIE_DMA_PINNED_MEM) {
		if (channel->direction == DMA_D2H || channel->direction == DMA_P2P) {
			dma_unmap_sg(&pcie_set->pdev->dev, channel->sg,
				channel->nents, DMA_FROM_DEVICE);
		} else {
			dma_unmap_sg(&pcie_set->pdev->dev, channel->sg,
				channel->nents, DMA_TO_DEVICE);
		}
	}
	for (i = 0; i < channel->page_cnt; i++) {
		if (channel->pp_pages[i]) {
			if (channel->dma_type != PCIE_DMA_KERNEL &&
				channel->dma_type != PCIE_DMA_MEMSET &&
				channel->dma_type != PCIE_DMA_P2P &&
				channel->dma_type != PCIE_DMA_PINNED_MEM) {
				if (channel->direction == DMA_D2H)
					set_page_dirty_lock((struct page *)
							channel->pp_pages[i]);
				put_page((struct page *)channel->pp_pages[i]);
			}
		}
		channel->pp_pages[i] = NULL;
	}


	channel->page_cnt = 0;
	channel->nents = 0;
	channel->task = NULL;
	channel->fix_count = 0;
	cn_pci_set_idle_channel(channel);

	return 0;
}

static int cn_pci_channel_dma_start(struct cn_pcie_set *pcie_set,
		struct dma_channel_info *channel, int phy)
{
	int fetch_num;
	struct pcie_dma_task *task = channel->task;
	int success = 0;
	int i = 0;

	for (i = 0; i < pcie_set->dma_fetch_buff; i++) {
		if (pcie_set->running_channels[phy][i]) {
			continue;
		}

		fetch_num = i;
		if (__sync_bool_compare_and_swap(&pcie_set->running_channels[phy][fetch_num],
				0, (unsigned long)channel) == 0)
			continue;

		if (!__sync_bool_compare_and_swap(&channel->status, CHANNEL_READY, CHANNEL_RUNNING)) {
			cn_dev_pcie_err(pcie_set, "set CHANNEL_RUNNING error:%d", channel->status);
			__sync_lock_test_and_set(&pcie_set->running_channels[phy][fetch_num], 0);
			return -1;
		}
		__sync_fetch_and_add(&pcie_set->phy_channel_search, 1);
		channel->fetch_command_id = fetch_num;

		if (unlikely(task->cfg.phy_mode)) {
			if (!(pcie_set->ops->dma_bypass_smmu)) {
				cn_dev_pcie_err(pcie_set, "Don't support physical mode dma");
			} else {
				pcie_set->ops->dma_bypass_smmu(phy, 1, pcie_set);
			}
		}

		if (pcie_set->ops->dma_go_command(channel, phy) < 0) {
			__sync_lock_test_and_set(&pcie_set->running_channels[phy][fetch_num], 0);
			break;
		}

		success = 1;
		break;
	}

	if (success == 0) {
		__sync_lock_test_and_set(&channel->status, CHANNEL_READY);
		return 1;
	}

	return 0;
}

static void cn_pci_print_channel_state(struct pcie_dma_task *task,
			struct cn_pcie_set *p_set)
{
	int i;
	int j;
	struct dma_channel_info *channel;

	if (task == NULL)
		return;

	cn_dev_pcie_info(p_set, "time out task:%lx", (unsigned long)task);
	cn_dev_pcie_info(p_set, "direction:%d count:%lx",
		task->transfer->direction, task->count);

	cn_dev_pcie_info(p_set, "task ready fifo len: %d",
			kfifo_len(&task->ready_fifo));

	cn_dev_pcie_info(p_set, "task finish fifo len: %d",
			kfifo_len(&task->finish_fifo));

	for (i = 0; i < p_set->max_phy_channel; i++) {
		for (j = 0; j < p_set->dma_fetch_buff; j++) {
			channel = (struct dma_channel_info *)p_set->running_channels[i][j];
			if (channel && channel->task == task) {
				cn_dev_pcie_info(p_set,
					"phy_channel:[%d][%d] %#lx desc_va:%#llx run_status:%d task:%#lx",
					i, j, (unsigned long)channel,
					channel->desc_device_va, channel->status,
					(unsigned long)channel->task);

				cn_pci_print_channel_info(channel, p_set);
			}
		}
	}
}

static void cn_pci_check_error_wait(struct pcie_dma_task *task)
{
	struct dma_channel_info *channel;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	unsigned int ret;
	int phy, command_id;
	int loop_cnt = 0;
	unsigned long flags;

	/* stop schedule by interrupt handle */
	__sync_lock_test_and_set(&task->status, DMA_TASK_EXIT);
	mdelay(50);

	spin_lock_irqsave(&task->ready_fifo_lock, flags);
	while (!kfifo_is_empty(&task->ready_fifo)) {
		ret = kfifo_out(&task->ready_fifo, &channel, sizeof(channel));
		if (ret != sizeof(channel)) {
			cn_dev_pcie_err(pcie_set, "ready_fifo out fail");
		}

		cn_pci_channel_dma_end(channel);
	}
	spin_unlock_irqrestore(&task->ready_fifo_lock, flags);

loop:
	for (phy = 0; phy < pcie_set->max_phy_channel; phy++) {
		for (command_id = 0; command_id < pcie_set->dma_fetch_buff; command_id++) {
			channel = (struct dma_channel_info *)pcie_set->running_channels[phy][command_id];
			/* channel is set to assigned when getting idle phy channel in interrupt */
			if ((channel == NULL) || ((unsigned long)channel == CHANNEL_ASSIGNED))
				continue;

			if (channel->task != task)
				continue;

			if (channel->status != CHANNEL_COMPLETED && channel->status != CHANNEL_COMPLETED_ERR) {
				mdelay(1);

				if (loop_cnt++ < 1000) {
					goto loop;
				} else {
					cn_dev_pcie_warn(pcie_set,
						"one channel leak channel->status=%d", channel->status);
				}
			}
		}
	}

	mdelay(50);
	while (!kfifo_is_empty(&task->finish_fifo)) {
		ret = kfifo_out(&task->finish_fifo, &channel, sizeof(channel));
		if (ret != sizeof(channel)) {
			cn_dev_pcie_err(pcie_set, "finish_fifo out fail");
		}

		cn_pci_channel_dma_end(channel);
	}
}

static size_t cn_pci_transfer_len(struct pcie_dma_task *task, size_t remain)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
#if 0
	size_t len;
	int div = 4;

	if ((task->count > pcie_set->dma_buffer_size * 2) ||
			(remain <= 64 * 1024))
		return min(remain, (size_t)pcie_set->dma_buffer_size);

	if ((remain < 128 * 1024))
		div = 2;

	len = task->count / div;
	len = min(len, pcie_set->dma_buffer_size);
	len = min(len, remain);

	return len;
#else
	/*
	 * split a big packet to N * dma_buffer_size, default dma_buffer_size equal 1MB
	 */
	return min_t(size_t, remain, (size_t)pcie_set->dma_buffer_size);
#endif
}

static unsigned long cn_pci_small_packet_write(struct pcie_dma_task *task)
{
	DMA_DIR_TYPE direction = task->transfer->direction;

	if (unlikely(task->cfg.phy_mode))
		return 0;

	if ((direction == DMA_H2D) &&
			task->transfer->size <= task->pcie_set->dma_bypass_custom_size &&
			(task->dma_type == PCIE_DMA_USER ||
			task->dma_type == PCIE_DMA_KERNEL)) {
		if (!cn_pci_dma_bar_write(task)) {
			return 1;
		}
	}

	if ((direction == DMA_H2D) &&
			task->transfer->size <= task->pcie_set->dma_bypass_pinned_size &&
			(task->dma_type == PCIE_DMA_PINNED_MEM)) {
		if (!cn_pci_dma_bar_write(task)) {
			return 1;
		}
	}

	return 0;
}

static unsigned long cn_pci_small_packet_read(struct pcie_dma_task *task)
{
	DMA_DIR_TYPE direction = task->transfer->direction;

	if ((direction == DMA_D2H) &&
			task->transfer->size <= task->pcie_set->d2h_bypass_custom_size) {
		if (!cn_pci_dma_bar_read(task)) {
			return 1;
		}
	}

	return 0;
}

static int cn_pci_finish_fifo_complete_out(struct cn_pcie_set *pcie_set, struct pcie_dma_task *task)
{
	struct dma_channel_info *channel = NULL;
	/*
	 * setting the already complelte channel to idle,
	 * if the channel if error, we will retry to transfer it
	 */
	while (!kfifo_is_empty(&task->finish_fifo)) {
		if (!kfifo_out(&task->finish_fifo, &channel, sizeof(channel))) {
			cn_dev_pcie_err(pcie_set, "finish_fifo out fail");
			return -1;
		}

		if (channel->status == CHANNEL_COMPLETED) {
			cn_pci_channel_dma_end(channel);
		} else if (channel->status == CHANNEL_COMPLETED_ERR) {
			task->retry_cnt++;
			__sync_lock_test_and_set(&task->err_flag, 0);
			cn_dev_pcie_info(pcie_set,
					"retry:%d length:%ld",
					task->retry_cnt, channel->transfer_length);
			if (task->retry_cnt >= 3) {
				cn_pci_channel_dma_end(channel);
				cn_dev_pcie_err(pcie_set, "Too much error");
				return -1;
			}
			__sync_fetch_and_add(&pcie_set->soft_retry_cnt, 1);
			cn_pci_channel_dma_ready(channel, 0);
		}
	}

	return 0;
}

static size_t cn_pci_dma_transfer(struct pcie_dma_task *task)
{
	size_t len, remain;
	struct dma_channel_info *channel = NULL;
	u64 ram_addr, cpu_addr;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	DMA_DIR_TYPE direction;
	long ret;
	u64 prt_start, cur;
	int desc_unpack_num;

	if (!task->transfer) {
		cn_dev_pcie_err(pcie_set, "task transfer is NULL");
		return 0;
	}
	direction = task->transfer->direction;

	if (task->transfer->size == 0) {
		cn_dev_pcie_info(pcie_set, "transfer size %ld",
			task->transfer->size);
		return task->count;
	}

	task->transfer_len = 0;
	ram_addr = task->transfer->ia;
	cpu_addr = task->transfer->ca;
	remain = task->count;

	if (!pcie_set->dma_phy_channel_mask) {
		cn_dev_pcie_err(pcie_set, "No dma channel now");
		return -1;
	}

	if (pcie_set->state == PCIE_STATE_SUSPEND) {
		do {
			__sync_fetch_and_add(&pcie_set->task_suspend_num, 1);
			ret = wait_event_interruptible(pcie_set->task_suspend_wq,
				pcie_set->state != PCIE_STATE_SUSPEND);
			__sync_fetch_and_sub(&pcie_set->task_suspend_num, 1);

			if (ret < 0) {
				cn_dev_pcie_err(pcie_set, "Task is breaked by signal");
				return -1;
			}
		} while (pcie_set->state == PCIE_STATE_SUSPEND);
	}

	if (pcie_set->state == PCIE_STATE_STOP) {
		cn_dev_pcie_info(pcie_set, "dma stop");
		return -1;
	}

	/*
	 * h2d use bar2/bar4 write small data to ddr, for x86 writecombine cn_ioremap write
	 * faster than dma
	 */
	if (cn_pci_small_packet_write(task)) {
		return 0;
	}

	/*
	 * d2h small data use bar2/bar4 read instead of PCIe dma for "heavy" start
	 */
	if (cn_pci_small_packet_read(task)) {
		return 0;
	}

	__sync_fetch_and_add(&pcie_set->task_num, 1);

	while (1) {
		int nents = 0;

		if (pcie_set->state == PCIE_STATE_STOP) {
			cn_dev_pcie_err(pcie_set, "in stop state");
			goto ERROR_RETURN;
		}

		if (remain > 0) {
			len = cn_pci_transfer_len(task, remain);
			if ((task->dma_type != PCIE_DMA_P2P) ||
				(task->p2p_trans_type != P2P_TRANS_BUS_ADDRESS)) {
				nents = cn_pci_get_pages(task, cpu_addr, len);
				if (nents < 0) {
					cn_dev_pcie_err(pcie_set, "cn_pci_get_pages fail");
					cn_pci_check_error_wait(task);
					__sync_fetch_and_sub(&pcie_set->task_num, 1);
					return nents;
				}
			} else {
				nents = 1;
			}

			if (((direction == DMA_P2P) || (direction == DMA_D2H)) &&
					pcie_set->ops->get_desc_unpack_num) {
				desc_unpack_num = pcie_set->ops->get_desc_unpack_num(ram_addr, cpu_addr);
				nents = (nents - 1) * desc_unpack_num + MAX_UNPACK_NUM;
			}
			channel = cn_pci_get_idle_channel(pcie_set, task, nents);
			if (channel == NULL) {
				cn_dev_pcie_err(pcie_set, "get idle channel failed");
				goto ERROR_RETURN;
			}

			channel->direction = direction;
			channel->transfer_length = len;
			channel->cpu_addr = cpu_addr;
			channel->ram_addr = ram_addr;
			channel->dma_type = task->dma_type;

			cpu_addr += len;
			ram_addr += len;
			remain -= len;

			if ((task->dma_type != PCIE_DMA_P2P) ||
				(task->p2p_trans_type != P2P_TRANS_BUS_ADDRESS)) {
				if (cn_pci_channel_update_sgl(channel)) {
					cn_pci_set_idle_channel(channel);
					goto ERROR_RETURN;
				}
			}
			if (cn_pci_channel_dma_ready(channel, remain)) {
				cn_pci_set_idle_channel(channel);
				goto ERROR_RETURN;
			}
		} else {
retry:
			if (!task->spkg_polling_flag) {
				ret = wait_event_interruptible_timeout(task->channel_wq,
					(task->transfer_len >= task->count) || task->err_flag, TIME_OUT_VALUE);
				if (ret == -ERESTARTSYS) {
					if (!fatal_signal_pending(current)) {
						cn_dev_pcie_debug(pcie_set, "dequeue now%lx",
							current->pending.signal.sig[0]);
						usleep_range(20, 50);
						goto retry;
					}
				}
				if (ret < 0) {
					cn_dev_pcie_err(pcie_set, "Task is breaked by signal");
					goto ERROR_RETURN;
				} else if (!ret) {
					if (down_killable(&pcie_set->timeout_log_sem)) {
						cn_dev_pcie_err(pcie_set, "get timeout log sem is breaked by signal");
						goto ERROR_RETURN;
					}

					cn_pci_dump_reg_info(pcie_set);
					cn_pci_print_channel_state(task, pcie_set);
					up(&pcie_set->timeout_log_sem);
					goto ERROR_RETURN;
				} else {
					if (jiffies_to_msecs(TIME_OUT_VALUE - ret) > 1000)
						cn_dev_pcie_info(pcie_set, "system busy time:%d",
							jiffies_to_msecs(TIME_OUT_VALUE - ret));
				}
			} else {

				prt_start = get_jiffies_64();
polling_retry:
				if (pcie_set->ops->polling_dma_status(pcie_set, channel)) {
					if (unlikely(pcie_set->state == PCIE_STATE_STOP)) {
						cn_dev_pcie_info(pcie_set, "dma stop");
						goto ERROR_RETURN;
					}

					cur = get_jiffies_64();
					if (time_after64(cur, prt_start + HZ * 10)) {
						cn_dev_pcie_info(pcie_set, "polling dma status is busy %dms",
								jiffies_to_msecs(cur - prt_start));
						prt_start = get_jiffies_64();
						schedule();
					}
					goto polling_retry;
				}
			}
		}

		if (cn_pci_finish_fifo_complete_out(pcie_set, task))
			goto ERROR_RETURN;

		if ((task->transfer_len >= task->count) &&
			(kfifo_is_empty(&task->finish_fifo)))
			break;
	}

	if (task->poison_flag == 1) {
		cn_dev_pcie_err(pcie_set, "task with poison");
		__sync_fetch_and_sub(&pcie_set->task_num, 1);
		return -1;
	}

	__sync_fetch_and_sub(&pcie_set->task_num, 1);
	return 0;

ERROR_RETURN:
	cn_pci_check_error_wait(task);
	__sync_fetch_and_sub(&pcie_set->task_num, 1);
	return task->count;
}

static void cn_pci_init_dma_task(struct pcie_dma_task *task, struct transfer_s *t,
		enum CN_PCIE_DMA_TYPE type, struct cn_pcie_set *pcie_set)
{
	task->pcie_set = pcie_set;
	task->transfer = t;
	task->count = t->size;
	task->dma_type = type;
	task->tsk = current;
	task->tsk_mm = current->mm;
	task->dma_async = 0;
	memset(&task->cfg, 0, sizeof(task->cfg));
	task->nents = 0;
	task->page_cnt = 0;
	task->spkg_polling_flag = 0;
	task->poison_flag = 0;
}

static size_t cn_pci_dma(struct transfer_s *t, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pcie_dma_task *task;
	struct pinned_mem_va *mem;
	enum CN_PCIE_DMA_TYPE type;
	size_t ret = 0;

	mem = cn_pinned_mem_check(current, t->ca, t->size);
	type = mem ? PCIE_DMA_PINNED_MEM : PCIE_DMA_USER;

	task = cn_pci_get_dma_idle_task(pcie_set, t->direction);
	if (!task)
		return -1;

	cn_pci_init_dma_task(task, t, type, pcie_set);

	ret = cn_pci_dma_transfer(task);
	cn_pci_put_dma_idle_task(pcie_set, task);
	return ret;
}

static size_t cn_pci_dma_remote(struct transfer_s *t,
	struct task_struct *tsk, struct mm_struct *tsk_mm, void *pcie_priv)
{
	struct pcie_dma_task *task;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	size_t ret;

	if (!tsk) {
		cn_dev_pcie_err(pcie_set, "tsk point is null");
		return -1;
	}

	task = cn_pci_get_dma_idle_task(pcie_set, t->direction);
	if (!task)
		return -1;

	cn_pci_init_dma_task(task, t, PCIE_DMA_USER_REMOTE, pcie_set);

	task->tsk = tsk;
	task->tsk_mm = tsk_mm;
	atomic_inc(&tsk_mm->mm_count);

	ret = cn_pci_dma_transfer(task);
	cn_pci_put_dma_idle_task(pcie_set, task);
	mmdrop(tsk_mm);
	return ret;
}

static size_t cn_pci_dma_kernel(unsigned long host_addr, u64 device_addr,
		size_t count, DMA_DIR_TYPE dir, void *pcie_priv)
{
	struct pcie_dma_task *task;
	struct transfer_s t;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	size_t ret = 0;

	TRANSFER_INIT(t, host_addr, device_addr, count, dir);

	task = cn_pci_get_dma_idle_task(pcie_set, dir);
	if (!task)
		return -1;

	cn_pci_init_dma_task(task, &t, PCIE_DMA_KERNEL, pcie_set);

	ret = cn_pci_dma_transfer(task);
	cn_pci_put_dma_idle_task(pcie_set, task);
	return ret;
}

static size_t cn_pci_dma_cfg(struct transfer_s *t,
		struct dma_config_t *cfg, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pcie_dma_task *task;
	struct pinned_mem_va *mem;
	enum CN_PCIE_DMA_TYPE type;
	size_t ret = 0;

	mem = cn_pinned_mem_check(current, t->ca, t->size);
	type = mem ? PCIE_DMA_PINNED_MEM : PCIE_DMA_USER;

	task = cn_pci_get_dma_idle_task(pcie_set, t->direction);
	if (!task)
		return -1;

	cn_pci_init_dma_task(task, t, type, pcie_set);

	task->cfg = *cfg;
	ret = cn_pci_dma_transfer(task);
	cn_pci_put_dma_idle_task(pcie_set, task);
	return ret;
}

static size_t cn_pci_dma_kernel_cfg(unsigned long host_addr, u64 device_addr,
		size_t count, DMA_DIR_TYPE direction,
		struct dma_config_t *cfg, void *pcie_priv)
{
	struct pcie_dma_task *task;
	struct transfer_s t;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	size_t ret = 0;

	TRANSFER_INIT(t, host_addr, device_addr, count, direction);

	task = cn_pci_get_dma_idle_task(pcie_set, direction);
	if (!task)
		return -1;

	cn_pci_init_dma_task(task, &t, PCIE_DMA_KERNEL, pcie_set);

	task->cfg = *cfg;
	ret = cn_pci_dma_transfer(task);
	cn_pci_put_dma_idle_task(pcie_set, task);
	return ret;
}

static int cn_pci_dma_bypass_smmu_all(void *pcie_priv, bool en)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (!pcie_set->ops->dma_bypass_smmu_all)
		return 0;

	return pcie_set->ops->dma_bypass_smmu_all(en, pcie_set);
}

static int cn_pci_shared_desc_shm_init(struct cn_pcie_set *pcie_set)
{
	int ret;
	u64 dev_va;
	unsigned long host_kva;

	ret = cn_device_share_mem_alloc(0, &host_kva, &dev_va,
			pcie_set->shared_desc_total_size,
			pcie_set->bus_set->core);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "shared dma desc alloc fail");
		return -1;
	}

	pcie_set->shared_desc_dev_va = dev_va;
	pcie_set->shared_desc_host_kva = host_kva;

	cn_dev_pcie_debug(pcie_set,
		"shared dma desc alloc [%lx] <-> dev[%llx]", host_kva, dev_va);
	return 0;
}

static void cn_pci_shared_desc_shm_release(struct cn_pcie_set *pcie_set)
{
	u64 dev_va;
	unsigned long host_kva;

	host_kva = pcie_set->shared_desc_host_kva;
	dev_va = pcie_set->shared_desc_dev_va;

	if (host_kva && dev_va) {
		cn_device_share_mem_free(0, host_kva, dev_va,
				pcie_set->bus_set->core);
	}
}

static int cn_pci_shared_dma_channel_soft_init(struct cn_pcie_set *pcie_set,
		struct dma_channel_info *channel, int id)
{
	int block = channel->desc_size / pcie_set->per_desc_size;
	int n;

	channel->pcie_set = pcie_set;
	channel->shared_flag = 1;
	__sync_lock_test_and_set(&channel->status, CHANNEL_IDLE);

	n = (pcie_set->dma_buffer_size / PAGE_SIZE) + 1; /* 257 */
	channel->pp_pages = cn_kzalloc(n *
			sizeof(struct page *), GFP_KERNEL);
	if (channel->pp_pages == NULL)
		goto exit;

	channel->sg = cn_vzalloc(block *
			sizeof(struct scatterlist));
	if (channel->sg == NULL)
		goto exit;

	sg_init_table(channel->sg, block);
	return 0;
exit:
	cn_pci_shared_dma_channel_soft_release(channel);
	cn_dev_pcie_err(pcie_set, "shared dma channel soft init fail");
	return -1;
}

static void cn_pci_shared_dma_channel_soft_release(struct dma_channel_info *channel)
{
	if (channel->sg)
		cn_vfree(channel->sg);

	if (channel->pp_pages)
		cn_kfree(channel->pp_pages);
}

static int cn_pci_shared_dma_desc_init(struct cn_pcie_set *pcie_set)
{
	int i;
	u64 dev_va;
	unsigned long host_kva;
	struct dma_channel_info *channel;

	dev_va = pcie_set->shared_desc_dev_va;
	host_kva = pcie_set->shared_desc_host_kva;

	pcie_set->shared_channel_list = cn_kzalloc(
			sizeof(*pcie_set->shared_channel_list) * pcie_set->shared_channel_cnt,
			GFP_KERNEL);
	if (pcie_set->shared_channel_list == NULL)
		return -1;

	for (i = 0; i < pcie_set->shared_channel_cnt;  i++) {
		channel = cn_kzalloc(sizeof(*channel), GFP_KERNEL);
		if (channel == NULL)
			goto exit;

		channel->desc_device_va = dev_va;
		channel->desc_virt_base = (void *)host_kva;
		channel->desc_size = pcie_set->shared_channel_desc_cnt *
					pcie_set->per_desc_size;

		cn_dev_pcie_debug(pcie_set,
			"shared channel[%d] host[%#lx] <-> dev[%#llx]",
				i, host_kva, dev_va);

		if (cn_pci_shared_dma_channel_soft_init(pcie_set, channel, i)) {
			cn_kfree(channel);
			goto exit;
		}

		pcie_set->shared_channel_list[i] = channel;
		dev_va += channel->desc_size;
		host_kva += channel->desc_size;
	}

	return 0;
exit:
	cn_pci_shared_dma_desc_release(pcie_set);
	cn_dev_pcie_err(pcie_set, "shared dma desc init fail");
	return -1;
}

static void cn_pci_shared_dma_desc_release(struct cn_pcie_set *pcie_set)
{
	int i;
	struct dma_channel_info *channel;

	if (!pcie_set->shared_channel_list)
		return;

	for (i = 0; i < pcie_set->shared_channel_cnt; i++) {
		channel = pcie_set->shared_channel_list[i];
		if (channel) {
			cn_pci_shared_dma_channel_soft_release(channel);
			cn_kfree(channel);
			pcie_set->shared_channel_list[i] = NULL;
		}
	}

	cn_kfree(pcie_set->shared_channel_list);
}

static int cn_pci_priv_desc_order_table_init(struct cn_pcie_set *pcie_set)
{
	int index;
	struct pcie_dma_task *task;

	for (index = 0; index < DMA_TASK_MAX; index++) {
		task = pcie_set->task_table[index];
		task->priv_order_table = cn_kzalloc(
			sizeof(*task->priv_order_table) * pcie_set->max_desc_order, GFP_KERNEL);
		if (task->priv_order_table == NULL) {
			cn_dev_pcie_err(pcie_set, "priv_order_table kzalloc error");
			return -1;
		}
	}

	return 0;
}

static void cn_pci_priv_desc_order_table_release(struct cn_pcie_set *pcie_set)
{
	int index;
	struct pcie_dma_task *task;

	if (!pcie_set->task_table)
		return;

	for (index = 0; index < DMA_TASK_MAX; index++) {
		task = pcie_set->task_table[index];
		if (!task)
			continue;
		if (task->priv_order_table) {
			cn_kfree(task->priv_order_table);
			task->priv_order_table = NULL;
		}
	}
}

static int cn_pci_priv_desc_shm_init(struct cn_pcie_set *pcie_set)
{
	int ret;
	u64 dev_va;
	unsigned long host_kva;

	ret = cn_device_share_mem_alloc(0, &host_kva, &dev_va,
			pcie_set->priv_desc_total_size,
			pcie_set->bus_set->core);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "priv dma desc alloc fail");
		return -1;
	}

	pcie_set->priv_desc_dev_va = dev_va;
	pcie_set->priv_desc_host_kva = host_kva;

	cn_dev_pcie_debug(pcie_set,
		"priv dma desc alloc [%#lx] <-> dev[%#llx]", host_kva, dev_va);
	return 0;
}

static void cn_pci_priv_desc_shm_release(struct cn_pcie_set *pcie_set)
{
	u64 dev_va;
	unsigned long host_kva;

	host_kva = pcie_set->priv_desc_host_kva;
	dev_va = pcie_set->priv_desc_dev_va;

	if (host_kva && dev_va) {
		cn_device_share_mem_free(0, host_kva, dev_va, pcie_set->bus_set->core);
	}
}

static int cn_pci_priv_dma_channel_soft_init(struct cn_pcie_set *pcie_set,
		struct dma_channel_info *channel, int id)
{
	int block = channel->desc_size / pcie_set->per_desc_size;
	int n;

	channel->pcie_set = pcie_set;
	__sync_lock_test_and_set(&channel->status, CHANNEL_IDLE);


	n = (pcie_set->dma_buffer_size / PAGE_SIZE) + 1; /* 257 */
	channel->pp_pages = cn_kzalloc(n *
			sizeof(struct page *), GFP_KERNEL);
	if (channel->pp_pages == NULL)
		goto exit;

	channel->sg = cn_vzalloc(block *
			sizeof(struct scatterlist));
	if (channel->sg == NULL)
		goto exit;

	sg_init_table(channel->sg, block);

	return 0;
exit:
	cn_pci_priv_dma_channel_soft_release(channel);
	cn_dev_pcie_err(pcie_set, "priv dma channel soft init fail");
	return -1;
}

static void cn_pci_priv_dma_channel_soft_release(struct dma_channel_info *channel)
{
	if (channel->sg)
		cn_vfree(channel->sg);

	if (channel->pp_pages)
		cn_kfree(channel->pp_pages);
}

static int cn_pci_priv_dma_channel_init(struct pcie_dma_task *task,
		u64 dev_va, unsigned long host_kva, int order)
{
	int i;
	int block = task->priv_order_table[order].block;
	int cnt = task->priv_order_table[order].number;
	struct dma_channel_info *channel;
	struct dma_channel_info **list = task->priv_order_table[order].list;
	int step = block * task->pcie_set->per_desc_size;

	/* Hardware Limit: desc addr 64 Bytes align */
	if (order == 0)
		step = 64;

	for (i = 0; i < cnt; i++, dev_va += step, host_kva += step) {
		channel = cn_kzalloc(sizeof(*channel), GFP_KERNEL);
		if (channel == NULL)
			goto exit;

		channel->desc_device_va = dev_va;
		channel->desc_virt_base = (void *)host_kva;
		channel->desc_size = block * task->pcie_set->per_desc_size;

		cn_dev_pcie_debug(task->pcie_set,
			"priv channel[%d]%d host[%#lx] <-> dev[%#llx]",
				block, i, host_kva, dev_va);

		if (cn_pci_priv_dma_channel_soft_init(task->pcie_set, channel, i)) {
			cn_kfree(channel);
			goto exit;
		}

		list[i] = channel;
	}

	return 0;

exit:
	cn_pci_priv_dma_channel_release(task, order);
	cn_dev_pcie_err(task->pcie_set, "priv dma channel init fail");
	return -1;
}

static void cn_pci_priv_dma_channel_release(struct pcie_dma_task *task, int order)
{
	int i;
	int cnt = task->priv_order_table[order].number;
	struct dma_channel_info **list = task->priv_order_table[order].list;
	struct dma_channel_info *channel;

	for (i = 0; i < cnt; i++) {
		channel = list[i];
		if (channel) {
			cn_pci_priv_dma_channel_soft_release(channel);
			cn_kfree(channel);
			list[i] = NULL;
		}
	}
}

static int cn_pci_priv_dma_channel_table_init(struct pcie_dma_task *task,
					int total, int block, int i)
{
	int cnt = (total / task->pcie_set->per_desc_size) / block;

	/* Hardware Limit: desc addr 64 Bytes align */
	if (i == 0)
		cnt = cnt / 2;

	task->priv_order_table[i].list = cn_kzalloc(
			sizeof(*task->priv_order_table[i].list) * cnt, GFP_KERNEL);
	if (task->priv_order_table[i].list == NULL)
		return -1;

	return cnt;
}

static void cn_pci_priv_dma_channel_table_release(struct pcie_dma_task *task, int i)
{
	if (task->priv_order_table[i].list) {
		cn_kfree(task->priv_order_table[i].list);
		task->priv_order_table[i].list = NULL;
	}
}

/*
 * for example 1MB share memory, each desc is 32Byte, total desc number: 1MB/32=32K
 * task_num : 32 , each task desc number 32K/32 = 1K
 * block  : 256 128 64 32 16 8 4 2 1
 * number : 2   2   2  2  2  2 2 2 4
 *
 * order_table
 * [0] ---> order=0, block=1, number=4, list[0][1][2][3]
 * [1] ---> order=1, block=2, number=2, list[0][1]
 * [2] ---> order=2, block=4, number=2. list[0][1]
 *  .
 * [8] ---> order=8, block=256, number=2, list[0][1]
 *
 */
static int cn_pci_priv_dma_desc_init(struct cn_pcie_set *pcie_set)
{
	int i, index, block, total, cnt;
	u64 dev_va;
	unsigned long host_kva;
	struct pcie_dma_task *task;

	dev_va = pcie_set->priv_desc_dev_va;
	host_kva = pcie_set->priv_desc_host_kva;

	for (index = 0; index < DMA_TASK_MAX; index++) {
		task = pcie_set->task_table[index];
		total = pcie_set->priv_desc_total_size / DMA_TASK_MAX;
		for (i = (pcie_set->max_desc_order - 1); i >= 0; i--) {
			if (i != 0) /* last one dont split */
				total /= 2;
			block = 1 << i; /* 2^i from 256 to 1 */
			cnt = cn_pci_priv_dma_channel_table_init(task,
					total, block, i);
			if (cnt == -1)
				goto exit;

			task->priv_order_table[i].block = block;
			task->priv_order_table[i].number = cnt;
			cn_dev_pcie_debug(pcie_set, "task[%d]:block%d number=%d",
				index, task->priv_order_table[i].block,
				task->priv_order_table[i].number);

			if (cn_pci_priv_dma_channel_init(task, dev_va, host_kva, i))
				goto exit;

			dev_va += total;
			host_kva += total;
		}
	}
	return 0;
exit:
	cn_pci_priv_dma_desc_release(pcie_set);
	cn_dev_pcie_err(pcie_set, "priv dma desc init fail");
	return -1;
}

static void cn_pci_priv_dma_desc_release(struct cn_pcie_set *pcie_set)
{
	int i, index;
	struct pcie_dma_task *task;

	if (!pcie_set->task_table)
		return;

	for (index = 0; index < DMA_TASK_MAX; index++) {
		task = pcie_set->task_table[index];
		if (!task)
			continue;
		if (!task->priv_order_table)
			continue;
		for (i = (pcie_set->max_desc_order - 1); i >= 0; i--) {
			if (task->priv_order_table[i].number == 0)
				continue;

			cn_pci_priv_dma_channel_release(task, i);
			cn_pci_priv_dma_channel_table_release(task, i);
		}
	}
}

static int cn_pci_check_priv_dma_desc(struct cn_pcie_set *pcie_set)
{
	int i, index;
	int order_size = 0;
	int size = 0;
	u64 dev_va;
	struct dma_channel_info **list;
	struct pcie_dma_task *task;

	dev_va = pcie_set->priv_desc_dev_va;

	for (index = 0; index < DMA_TASK_MAX; index++) {
		task = pcie_set->task_table[index];
		for (i = (pcie_set->max_desc_order - 1); i >= 0;  i--) {
			list = task->priv_order_table[i].list;
			if (dev_va != list[0]->desc_device_va) {
				cn_dev_pcie_err(pcie_set,
					"check dev_va error index:%d order:%d", index, i);
			}

			/* Hardware Limit: desc addr 64 Bytes align */
			if (i == 0)
				order_size = task->priv_order_table[i].block *
					task->priv_order_table[i].number * pcie_set->per_desc_size * 2;
			else
				order_size = task->priv_order_table[i].block *
					task->priv_order_table[i].number * pcie_set->per_desc_size;
			dev_va += order_size;
			size += order_size;
		}
		if (size > pcie_set->priv_desc_total_size) {
			cn_dev_pcie_err(pcie_set, "priv dma desc spilt error");
			return -1;
		}
	}

	return 0;
}

static int cn_pci_dma_priv_channel_mem_init(struct cn_pcie_set *pcie_set)
{
	int ret = 0;
	int cnt = 0;

	cnt = pcie_set->priv_desc_total_size / pcie_set->per_desc_size
		/ DMA_TASK_MAX / 2 / (1 << (pcie_set->max_desc_order - 1));
	if (!cnt) {
		cn_dev_pcie_info(pcie_set, "don't init dma priv channel");
		cn_dev_pcie_info(pcie_set, "priv_desc_total_size:%#lx per_desc_size:%d",
			pcie_set->priv_desc_total_size, pcie_set->per_desc_size);
		cn_dev_pcie_info(pcie_set, " DMA_TASK_MAX:%d max_desc_order:%d",
			DMA_TASK_MAX, (pcie_set->max_desc_order - 1));
		return 0;
	}

	ret = cn_pci_priv_desc_order_table_init(pcie_set);
	if (ret)
		goto priv_desc_order_table_init_err;

	ret = cn_pci_priv_desc_shm_init(pcie_set);
	if (ret)
		goto priv_desc_shm_init_err;

	ret = cn_pci_priv_dma_desc_init(pcie_set);
	if (ret)
		goto priv_dma_desc_init_err;

	ret = cn_pci_check_priv_dma_desc(pcie_set);
	if (ret)
		goto check_priv_dma_desc;

	cn_dev_pcie_debug(pcie_set, "dma priv channel mem init successfully");
	return 0;

check_priv_dma_desc:
	cn_pci_priv_dma_desc_release(pcie_set);
priv_dma_desc_init_err:
	cn_pci_priv_desc_shm_release(pcie_set);
priv_desc_shm_init_err:
priv_desc_order_table_init_err:
	cn_pci_priv_desc_order_table_release(pcie_set);
	return -1;
}

static int cn_pci_dma_channel_mem_init(struct cn_pcie_set *pcie_set)
{
	int ret;
	int max_pages, max_order;

	/*
	 * worst case, 1MB start addr not 4k-align and all pages not continuous
	 * contain 1MB/4K + 1 = 257 pages
	 */
	max_pages = roundup_pow_of_two((pcie_set->dma_buffer_size / PAGE_SIZE) + 1);
	max_order = order_base_2(max_pages * MAX_UNPACK_NUM);
	pcie_set->max_desc_order = max_order;

	/* Hardware Limit: desc addr 64 Bytes align */
	pcie_set->shared_channel_desc_cnt = pcie_set->dma_buffer_size / PAGE_SIZE + 2;
	pcie_set->shared_channel_desc_cnt *= MAX_UNPACK_NUM;
	pcie_set->shared_channel_cnt = pcie_set->shared_desc_total_size /
			pcie_set->per_desc_size / pcie_set->shared_channel_desc_cnt;

	ret = cn_pci_shared_desc_shm_init(pcie_set);
	if (ret)
		return -1;

	ret = cn_pci_shared_dma_desc_init(pcie_set);
	if (ret)
		goto shared_dma_desc_init_err;

	return 0;

shared_dma_desc_init_err:
	cn_pci_shared_desc_shm_release(pcie_set);
	return -1;
}

static struct pcie_dma_task *
cn_pci_get_dma_idle_task(struct cn_pcie_set *pcie_set, DMA_DIR_TYPE direction)
{
	int i, ret;
	struct pcie_dma_task *task;
	int index;

	/* get task depends on direction, odd is for d2h, even is for h2d
	 * this is for fair scheduling when testing bidirectional bandwidth
	 */
	if (direction == DMA_H2D) {
		ret = down_killable(&pcie_set->task_sem_h2d);
	} else {
		ret = down_killable(&pcie_set->task_sem_d2h);
	}
	if (ret) {
		cn_dev_pcie_err(pcie_set, "down_killable=%d", ret);
		return NULL;
	}

retry:
	index = pcie_set->task_search_start % DMA_TASK_MAX;
	for (i = 0; i < DMA_TASK_MAX; i++) {
		index = (i + index) % DMA_TASK_MAX;
		task = pcie_set->task_table[index];
		if (direction == DMA_H2D) {
			if (index % 2)
				continue;
		} else {
			if (!(index % 2))
				continue;
		}
		if (__sync_bool_compare_and_swap(&task->status,
					DMA_TASK_IDLE, DMA_TASK_ASSIGNED)) {
			/* [NOTE] Set values to 0 before reserved in struct pcie_dma_task */
			memset(task, 0, ((u64)(&task->reserved) - (u64)task));

			__sync_fetch_and_add(&pcie_set->task_search_start, 1);
			return task;
		}
	}
	goto retry;
}

static void cn_pci_put_dma_idle_task(struct cn_pcie_set *pcie_set,
		struct pcie_dma_task *task)
{
	DMA_DIR_TYPE direction;
	/*
	 * ready_fifo and finish_fifo should be empty, recheck here
	 */
	__sync_lock_test_and_set(&task->status, DMA_TASK_EXIT);
	if (!kfifo_is_empty(&task->ready_fifo)) {
		cn_dev_pcie_err(pcie_set, "bug on: ready fifo is not empty");
		kfifo_reset(&task->ready_fifo);
	}

	if (!kfifo_is_empty(&task->finish_fifo)) {
		cn_dev_pcie_err(pcie_set, "bug on: finish fifo is not empty");
		kfifo_reset(&task->finish_fifo);
	}

	if (task->transfer == NULL) {
		cn_dev_pcie_err(pcie_set, "task transfer is NULL");
		return;
	}
	direction = task->transfer->direction;
	__sync_lock_test_and_set(&task->status, DMA_TASK_IDLE);
	if (direction == DMA_H2D) {
		up(&pcie_set->task_sem_h2d);
	} else {
		up(&pcie_set->task_sem_d2h);
	}
}

static int cn_pci_dma_task_struct_init(struct cn_pcie_set *pcie_set,
		struct pcie_dma_task *task)
{
	int n, max_pages, max_order;
	u64 desc_num;
	u64 share_cnt, priv_cnt;

	/*
	 * note: no-lock kfifo only can be used in single producer and consumer
	 *
	 * ready fifo:
	 *	producer is "thread", consumer is "interrupt"
	 * finish fifo:
	 *	producer is "interrupt", consumer is "interrupt-bottom"
	 *
	 * one channel once transfer 1MB data, we support above-4GB data transfer,
	 * so at least need sizeof(*point) * 4096 buffer(32KB),
	 * but virtual channel less than 4096, so it`s total enough
	 *
	 */

	n = (pcie_set->dma_buffer_size / PAGE_SIZE) + 1; /* 257 */
	max_pages = roundup_pow_of_two((pcie_set->dma_buffer_size / PAGE_SIZE) + 1);
	max_order = order_base_2(max_pages);

	if (max_order == 0) { /* coverity check error */
		cn_dev_pcie_err(pcie_set, "dma_buffer_size need big enough");
		return -1;
	}

	/* num_order[0] maybe equal to 2 * num_order[max_order] */
	share_cnt = ((pcie_set->shared_desc_total_size / 2 / pcie_set->per_desc_size)
			>> max_order) * (max_order + 1);

	priv_cnt = ((pcie_set->priv_desc_total_size / 2 / pcie_set->per_desc_size
			/ DMA_TASK_MAX) >> (max_order - 1)) * max_order;
	cn_dev_pcie_debug(pcie_set,
			"share_cnt[%lld], priv_cnt[%lld]", share_cnt, priv_cnt);

	if (kfifo_alloc(&task->ready_fifo,
			sizeof(void *) * (share_cnt + priv_cnt), GFP_KERNEL)) {
		cn_dev_pcie_err(pcie_set, "ready_fifo alloc error");
		return -1;
	}

	if (kfifo_alloc(&task->finish_fifo,
			sizeof(void *) * (share_cnt + priv_cnt), GFP_KERNEL)) {
		cn_dev_pcie_err(pcie_set, "finish_fifo alloc error");
		goto free_ready_kfifo;
	}
	spin_lock_init(&task->ready_fifo_lock);
	init_waitqueue_head(&task->channel_wq);

	/*
	 * page point table for get_user_pages
	 */
	task->pp_pages = cn_kzalloc(n *
			sizeof(struct page *), GFP_KERNEL);
	if (task->pp_pages == NULL)
		goto free_finish_kfifo;

	/*
	 * a table record continuous phy pages number for malloc/kmalloc,
	 * for pinnend memory save continuous len
	 */
	task->chunk = cn_kzalloc(n *
			sizeof(*task->chunk), GFP_KERNEL);
	if (task->chunk == NULL)
		goto free_pp_pages;

	/*
	 * desc buf for all channels related to this task
	 */
	desc_num = roundup_pow_of_two((pcie_set->dma_buffer_size / PAGE_SIZE) + 1);
	task->desc_buf = cn_vmalloc(desc_num * pcie_set->per_desc_size * MAX_UNPACK_NUM);
	if (task->desc_buf == NULL)
		goto free_chunk;

	task->pcie_set = pcie_set;
	__sync_lock_test_and_set(&task->status, DMA_TASK_IDLE);
	return 0;

free_chunk:
	cn_kfree(task->chunk);
free_pp_pages:
	cn_kfree(task->pp_pages);
free_finish_kfifo:
	kfifo_free(&task->finish_fifo);
free_ready_kfifo:
	kfifo_free(&task->ready_fifo);
	return -1;
}

static int cn_pci_dma_task_init(struct cn_pcie_set *pcie_set)
{
	int i, ret;
	struct pcie_dma_task *task;

	pcie_set->task_table = cn_kzalloc(
			sizeof(task) * DMA_TASK_MAX, GFP_KERNEL);
	if (pcie_set->task_table == NULL)
		goto exit;

	for (i = 0; i < DMA_TASK_MAX; i++) {
		task = cn_kzalloc(sizeof(*task), GFP_KERNEL);
		if (task == NULL)
			goto exit;
		ret = cn_pci_dma_task_struct_init(pcie_set, task);
		if (ret)
			goto exit;
		pcie_set->task_table[i] = task;
	}

	sema_init(&pcie_set->task_sem_h2d, DMA_TASK_MAX / 2);
	sema_init(&pcie_set->task_sem_d2h, DMA_TASK_MAX / 2);

	return 0;
exit:
	cn_dev_pcie_err(pcie_set, "dma task init fail");
	cn_pci_dma_task_release(pcie_set);
	return -1;
}

static void cn_pci_dma_task_release(struct cn_pcie_set *pcie_set)
{
	int i;
	struct pcie_dma_task *task;

	if (!pcie_set->task_table)
		return;

	for (i = 0; i < DMA_TASK_MAX; i++) {
		task = pcie_set->task_table[i];
		if (task) {
			kfifo_free(&task->ready_fifo);
			kfifo_free(&task->finish_fifo);

			cn_kfree(task->chunk);
			cn_kfree(task->pp_pages);
			cn_vfree(task->desc_buf);
			cn_kfree(task);
		}
	}

	cn_kfree(pcie_set->task_table);
	pcie_set->task_table = NULL;
}

static void cn_pci_async_free_handle(struct work_struct *work)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)container_of(work,
			struct cn_pcie_set, async_free_work);
	struct dma_channel_info *channel = NULL;
	unsigned int ret;
	u64 prt_start, sch_start, cur;
	int i = 0;
	/*
	 * channel->status has three situations
	 * CHANNEL_COMPLETED : dma transfer complete but not ready to release
	 * CHANNEL_IDLE : dma transfer error, has been released
	 */
	prt_start = get_jiffies_64();
	sch_start = get_jiffies_64();
	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		while (!kfifo_is_empty(&pcie_set->af_fifo[i])) {
			ret = kfifo_out(&pcie_set->af_fifo[i], &channel, sizeof(channel));
			if (ret != sizeof(channel)) {
				cn_dev_pcie_err(pcie_set, "af_fifo[%d] out fail", i);
			}
			if (channel->status == CHANNEL_COMPLETED) {
				cn_pci_channel_dma_end(channel);
			} else if (channel->status == CHANNEL_IDLE) {
				cn_dev_pcie_debug(pcie_set, "dma transfer err, has been released");
			} else {
				cn_dev_pcie_err(pcie_set, "channel->status:%d", channel->status);
			}

			cur = get_jiffies_64();
			if (time_after64(cur, sch_start + HZ * 1)) {
				sch_start = get_jiffies_64();
				usleep_range(50, 100);
			}

			if (time_after64(cur, prt_start + HZ * 15)) {
				cn_dev_pcie_info(pcie_set, "dma async free is busy %dms",
						jiffies_to_msecs(cur - prt_start));
				prt_start = get_jiffies_64();
				break;
			}
		}
	}
}

static int cn_pci_dma_async_free_init(struct cn_pcie_set *pcie_set)
{
	u64 share_cnt, priv_cnt;
	int i = 0;
	/* num_order[0] maybe equal to 2 * num_order[max_order] */
	share_cnt = ((pcie_set->shared_desc_total_size / 2 / pcie_set->per_desc_size)
			>> pcie_set->max_desc_order) * (pcie_set->max_desc_order + 1);
	priv_cnt = ((pcie_set->priv_desc_total_size / 2 / pcie_set->per_desc_size)
			>> (pcie_set->max_desc_order - 1)) * pcie_set->max_desc_order;
	cn_dev_pcie_debug(pcie_set,
			"share_cnt[%lld], priv_cnt[%lld]", share_cnt, priv_cnt);
	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (kfifo_alloc(&pcie_set->af_fifo[i],
					sizeof(void *) * (share_cnt + priv_cnt), GFP_KERNEL)) {
			cn_dev_pcie_err(pcie_set, "af_fifo[%d] alloc error", i);
			return -1;
		}
	}
	INIT_WORK(&pcie_set->async_free_work, cn_pci_async_free_handle);

	cn_dev_pcie_info(pcie_set, "dma async free init success");
	return 0;
}

static void cn_pci_dma_async_free_exit(struct cn_pcie_set *pcie_set)
{
	int i = 0;
	if (!pcie_set->async_free_work.func)
		return;
	cancel_work_sync(&pcie_set->async_free_work);
	flush_work(&pcie_set->async_free_work);
	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		kfifo_free(&pcie_set->af_fifo[i]);
	}
}

static int cn_pci_dma_af_ctrl(void *pcie_priv, unsigned int enable)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (enable) {
		pcie_set->af_enable = 1;
		cn_dev_pcie_info(pcie_set, "dma async free enable");
	} else {
		pcie_set->af_enable = 0;
		cn_dev_pcie_info(pcie_set, "dma async free disable");
	}

	return 0;
}

static int cn_pci_dma_des_set(void *pcie_priv, unsigned int value)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (value) {
		pcie_set->des_set = value;
		cn_dev_pcie_info(pcie_set, "dma descripter set value = %d", value);
	} else {
		pcie_set->des_set = 0;
		cn_dev_pcie_info(pcie_set, "dma descripter disable");
	}

	return 0;
}

static void cn_pci_dma_phy_channel_release(struct cn_pcie_set *pcie_set)
{
	int i;

	if (!pcie_set->running_channels)
		return;

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->running_channels[i]) {
			cn_kfree(pcie_set->running_channels[i]);
			pcie_set->running_channels[i] = NULL;
		}
	}

	if (pcie_set->running_channels) {
		cn_kfree(pcie_set->running_channels);
		pcie_set->running_channels = NULL;
	}
}

static int cn_pci_dma_phy_channel_init(struct cn_pcie_set *pcie_set)
{
	u32 bitmap_size;
	int i;

	pcie_set->running_channels = cn_kzalloc((pcie_set->max_phy_channel) *
				(sizeof(unsigned long *)), GFP_KERNEL);
	if (!pcie_set->running_channels) {
		cn_dev_pcie_err(pcie_set, "kzalloc running_channels error");
		return -1;
	}

	bitmap_size = BITS_TO_LONGS(pcie_set->dma_fetch_buff) * sizeof(long);
	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		pcie_set->running_channels[i] = cn_kzalloc(pcie_set->dma_fetch_buff *
					(sizeof(unsigned long)), GFP_KERNEL);
		if (!pcie_set->running_channels[i]) {
			cn_dev_pcie_err(pcie_set, "kzalloc running_channels[%d] error", i);
			goto exit;
		}
	}

	return 0;
exit:
	cn_pci_dma_phy_channel_release(pcie_set);
	cn_dev_pcie_err(pcie_set, "dma phy channel init failed");
	return -1;
}

static int cn_pci_dma_sync_init(struct cn_pcie_set *pcie_set)
{
	if (cn_pci_dma_phy_channel_init(pcie_set))
		return -1;

	if (cn_pci_dma_task_init(pcie_set))
		return -1;

	if (cn_pci_dma_channel_mem_init(pcie_set))
		goto release_memory;

	if (cn_pci_dma_priv_channel_mem_init(pcie_set))
		return -1;

	pcie_set->ops->dma_bypass_size(pcie_set);

	if (pcie_set->af_enable) {
		if (cn_pci_dma_async_free_init(pcie_set))
			return -1;
	}
	cn_dev_pcie_debug(pcie_set, "dma channel init successfully");
	return 0;

release_memory:
	cn_dev_pcie_info(pcie_set, "dma channel init failed");
	return -1;
}

static void cn_pci_dma_sync_exit(struct cn_pcie_set *pcie_set)
{
	if (pcie_set->af_enable) {
		cn_pci_dma_async_free_exit(pcie_set);
	}
	cn_pci_priv_dma_desc_release(pcie_set);
	cn_pci_priv_desc_shm_release(pcie_set);
	cn_pci_priv_desc_order_table_release(pcie_set);

	cn_pci_shared_dma_desc_release(pcie_set);
	cn_pci_shared_desc_shm_release(pcie_set);

	cn_pci_dma_task_release(pcie_set);
	cn_pci_dma_phy_channel_release(pcie_set);
}

static int cn_pci_dma_suspend(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = pcie_priv;

	if (pcie_set->state != PCIE_STATE_STOP) {
		__sync_lock_test_and_set(&pcie_set->state, PCIE_STATE_SUSPEND);
	}
	while (pcie_set->task_num != pcie_set->task_suspend_num) {
		schedule();
		udelay(1);
	}

	cn_dev_pcie_info(pcie_set, "task_num:%d task_suspend_num:%d",
		pcie_set->task_num, pcie_set->task_suspend_num);

	return 0;
}

__attribute__((unused))
static size_t cn_pci_boot_image_hsp(unsigned long host_addr, u64 device_addr,
						size_t count, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (cn_pci_dma_kernel(host_addr, device_addr, count, DMA_H2D, pcie_priv)) {
		cn_dev_pcie_err(pcie_set, "hsp boot image failed");
		return -1;
	}

	return 0;
}

__attribute__((unused))
static size_t cn_pci_check_image_hsp(unsigned char *host_data, u64 device_addr,
						size_t count, void *pcie_priv)
{
	int ret = -1;
	unsigned char *check_buf = NULL;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	check_buf = cn_vzalloc(count);
	if (!check_buf) {
		cn_dev_pcie_err(pcie_set, "hsp buff vzalloc failed");
		goto ERR_RET;
	}

	ret = cn_pci_dma_kernel((unsigned long)check_buf, device_addr, count, DMA_D2H, pcie_priv);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "hsp dma D2H error");
		goto ERR_RET;
	}

	ret = strncmp(host_data, check_buf, count);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "hsp data check failed!");
		goto ERR_RET;
	}

ERR_RET:
	if (check_buf)
		cn_vfree(check_buf);

	return ret;
}
