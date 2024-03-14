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
static void cn_pci_shared_dma_channel_release(struct cn_pcie_set *pcie_set, int order);
static void cn_pci_shared_dma_channel_soft_release(struct dma_channel_info *channel);
static void cn_pci_priv_dma_desc_release(struct cn_pcie_set *pcie_set);
static void cn_pci_priv_dma_channel_release(struct pcie_dma_task *task, int order);
static void cn_pci_priv_dma_channel_soft_release(struct dma_channel_info *channel);
static void cn_pci_pinned_mem_sgl_free(struct dma_channel_info *channel);
static int cn_pci_channel_dma_start(struct cn_pcie_set *pcie_set,
		struct dma_channel_info *channel);
static int cn_pci_dma_async_init(struct cn_pcie_set *pcie_set);

static struct pcie_dma_task *cn_pci_get_dma_idle_task(struct cn_pcie_set *pcie_set, DMA_DIR_TYPE direction);
static void cn_pci_put_dma_idle_task(struct cn_pcie_set *pcie_set,
		struct pcie_dma_task *task);
static void cn_pci_dma_task_release(struct cn_pcie_set *pcie_set);


static struct dma_channel_info *cn_pci_get_priv_idle_channel(struct cn_pcie_set *pcie_set,
		struct pcie_dma_task *task, int order)
{
	int i, n, cnt;
	struct dma_channel_info *channel;
	struct dma_channel_info **list;

	/*
	 * just first 16 share channel_256 have secondary copy buffer
	 */
	if (task->dma_copy == 1)
		return NULL;

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

static struct dma_channel_info *cn_pci_get_shared_idle_channel(struct cn_pcie_set *pcie_set,
		struct pcie_dma_task *task, int order)
{
	int i, n, cnt;
	struct dma_channel_info *channel;
	struct dma_channel_info **list;

	if (!pcie_set->order_table)
		return NULL;

	for (n = order; n <= pcie_set->max_desc_order; n++) {
		cnt = pcie_set->order_table[n].number;
		list = pcie_set->order_table[n].list;

		/*
		 * just first 16 channel_512 have secondary copy buffer
		 * TODO: new secondary copy buffer table like share or private table
		 */
		if (task->dma_copy == 1)
			cnt = min(16, cnt);

		for (i = 0; i < cnt; i++) {
			channel = list[i];

			/*
			 * 4 bytes non-align dma data need secondary copy,
			 * but for some platforms (like HI3559) dma coherent buf are not enough.
			 * so we only use init-ok channel for transfer
			 */
			if (task->dma_copy == 1) {
				if (channel->dma_buf_cnt == 0)
					continue;
			}

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

static struct dma_channel_info *cn_pci_get_idle_channel(struct cn_pcie_set *pcie_set,
		struct pcie_dma_task *task, int nents)
{
	int channel_cap;
	int order;
	struct dma_channel_info *channel;

	if (task->dma_type != PCIE_DMA_P2P) {
		channel_cap = roundup_pow_of_two((pcie_set->dma_buffer_size / PAGE_SIZE) + 1);
		if (nents <= 0 || nents > channel_cap) {
			cn_dev_pcie_err(pcie_set, "before nents=%d\n", nents);
			return NULL;
		}

		nents = roundup_pow_of_two(nents);
		order = order_base_2(nents);
		cn_dev_pcie_debug(pcie_set, "nents=%d, order=%d\n", nents, order);
	} else {
		order = 0;
	}
	channel = cn_pci_get_priv_idle_channel(pcie_set, task, order);
	if (channel)
		return channel;

	return cn_pci_get_shared_idle_channel(pcie_set, task, order);
}

static void cn_pci_set_idle_channel(struct dma_channel_info *channel)
{
	__sync_lock_test_and_set(&channel->status, CHANNEL_IDLE);
}

static int
cn_pci_channel_dma_ready(struct dma_channel_info *channel, size_t remain)
{
	u32 channel_mask;
	struct pcie_dma_task *task = channel->task;
	struct cn_pcie_set *p = channel->pcie_set;
	int start = 0;
	int ret;
	unsigned long flags;

	if (p->ops->fill_desc_list(channel)) {
		cn_dev_pcie_err(p, "fill desc failed");
		return -1;
	}

	if (!__sync_bool_compare_and_swap(&channel->status, CHANNEL_ASSIGNED, CHANNEL_READY)) {
		if (!__sync_bool_compare_and_swap(&channel->status, CHANNEL_COMPLETED_ERR, CHANNEL_READY)) {
			cn_dev_pcie_err(p, "set CHANNEL_READY error:%d", channel->status);
			return -1;
		}
	}

	channel_mask = p->dma_phy_channel_mask;
	if (channel->task->cfg.phy_dma_mask) {
		channel_mask &= channel->task->cfg.phy_dma_mask;
	}

retry:
	while ((p->channel_run_flag & channel_mask) ^ channel_mask) {
		ret = cn_pci_channel_dma_start(p, channel);
		if (ret < 0) {
			return -1;
		} else if (!ret) {
			start = 1;
			break;
		}
	}

	/*
	 * if all phy channels are running, add the channel to ready_fifo,
	 * wait for schedule by last dma interrupt handle
	 *
	 * note: schedule maybe run over before fifo in,
	 * the last channel will not dma go, then timeout, do a retry here
	 */
	if (start == 0) {
		spin_lock_irqsave(&task->ready_fifo_lock, flags);
		ret = kfifo_in(&task->ready_fifo, &channel, sizeof(channel));
		spin_unlock_irqrestore(&task->ready_fifo_lock, flags);
		if (ret != sizeof(channel)) {
			cn_dev_pcie_err(p, "bug on: ready kfifo_in fail\n");
			return -1;
		}

		/* recheck last channel(remain == 0 mean last) */
		if (p->channel_run_flag == 0 && remain == 0) {
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

static void cn_pci_dma_copy_update_sgl(struct dma_channel_info *channel)
{
	int i;
	size_t remain;
	struct scatterlist *sg;
	unsigned int per_size = DMA_BUFFER_SIZE / channel->dma_buf_cnt;

	channel->nents = 0;
	sg = (struct scatterlist *)channel->sg;

	for (i = 0; i < channel->transfer_length / per_size; i++) {
		sg_dma_address(sg) = channel->dma_buf[i].dma_addr;
		sg_dma_len(sg) = channel->dma_buf[i].size;
		channel->nents++;
		sg++;
	}

	remain = channel->transfer_length % per_size;
	if (remain) {
		sg_dma_address(sg) = channel->dma_buf[i].dma_addr;
		sg_dma_len(sg) = remain;
		channel->nents++;
	}
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

		dma_addr = (unsigned long)dma_map_page(dev, pg, offset,
				count, DMA_BIDIRECTIONAL);
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
	cn_pci_pinned_mem_sgl_free(channel);
	return -1;
}

/*
 * copy_flag
 * 0: copy data from channel dma buf to user buf
 * 1: copy data from user buf to channel dma buf
 */
static int cn_pci_copy_buf(struct dma_channel_info *channel, int copy_flag)
{
	unsigned long offset = 0;
	unsigned long copy_len;
	unsigned long copy_len_cur;
	unsigned long len;
	unsigned long count;
	unsigned long cpu_addr;
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	struct pcie_dma_task *task = channel->task;
	unsigned char *buf_virt = NULL;
	unsigned int BUFF_SIZE = DMA_BUFFER_SIZE / channel->dma_buf_cnt;
	struct pinned_mem *mem_blk = NULL;
	struct page **pages;
	int page_cnt, i;
	unsigned long page_offset, page_vaddr;
	u64 k_vaddr;
	u64 pinned_kvaddr;

	cpu_addr = channel->cpu_addr;
	pinned_kvaddr = channel->pinned_kvaddr;

	copy_len = channel->transfer_length;
	while (copy_len) {
		copy_len_cur = min(copy_len, BUFF_SIZE -
						(offset % BUFF_SIZE));
		buf_virt = channel->dma_buf[offset / BUFF_SIZE].vir_addr;

		if (task->dma_async) {
			switch (task->dma_type) {
			case PCIE_DMA_USER:
				page_offset = cpu_addr & (~PAGE_MASK);
				pages = cn_pci_dma_get_user_pages(cpu_addr, copy_len_cur,
									&page_cnt, task);
				if (!pages) {
					cn_dev_pcie_err(pcie_set,
							"user addr%#lx is error", cpu_addr);
					return -1;
				}
				len = copy_len_cur;
				for (i = 0; i < page_cnt; i++) {
					page_vaddr = (u64)page_address(pages[i]);
					if (!page_vaddr) {
						cn_pci_dma_put_user_pages(pages, page_cnt);
						return -1;
					}
					if (i == 0) {
						k_vaddr = page_vaddr + page_offset;
						count = PAGE_SIZE - page_offset;
						count = min(len, count);
					} else {
						k_vaddr = page_vaddr;
						count = min(PAGE_SIZE, len);
					}
					if (copy_flag)
						memcpy(buf_virt, (void *)k_vaddr, count);
					else
						memcpy((void *)k_vaddr, buf_virt, count);
					buf_virt += count;
					len -= count;
				}
				cn_pci_dma_put_user_pages(pages, page_cnt);
				break;
			case PCIE_DMA_PINNED_MEM:
				mem_blk = cn_async_pinned_mem_check(pinned_kvaddr);
				if (!mem_blk) {
					cn_dev_pcie_err(pcie_set,
							"mem %#llx not exsit in pinned mem table",
							pinned_kvaddr);
					return -EFAULT;
				}
				if (copy_flag) {
					memcpy(buf_virt, (void *)pinned_kvaddr, copy_len_cur);
				} else {
					memcpy((void *)pinned_kvaddr, buf_virt, copy_len_cur);
				}
				break;
			case PCIE_DMA_MEMSET:
			case PCIE_DMA_KERNEL:
				if (copy_flag)
					memcpy(buf_virt,
						(void *)cpu_addr, copy_len_cur);
				else
					memcpy((void *)cpu_addr,
						buf_virt, copy_len_cur);
				break;
			default:
				cn_dev_pcie_err(pcie_set,
					"fail to cn_pci_copy_to_buf type:%d",
							task->dma_type);
				return -1;
			}
		} else {
			switch (task->dma_type) {
			case PCIE_DMA_USER:
			case PCIE_DMA_PINNED_MEM:
				if (copy_flag) {
					if (copy_from_user(buf_virt,
						(void __user *)cpu_addr, copy_len_cur))
						return -1;
				} else {
					if (copy_to_user((void __user *)cpu_addr,
						buf_virt, copy_len_cur))
						return -1;
				}
				break;
			case PCIE_DMA_MEMSET:
			case PCIE_DMA_KERNEL:
				if (copy_flag)
					memcpy(buf_virt,
						(void *)cpu_addr, copy_len_cur);
				else
					memcpy((void *)cpu_addr,
						buf_virt, copy_len_cur);
				break;
			default:
				cn_dev_pcie_err(pcie_set,
					"fail to cn_pci_copy_to_buf type:%d",
							task->dma_type);
				return -1;
			}
		}
		cpu_addr += copy_len_cur;
		pinned_kvaddr += copy_len_cur;
		offset += copy_len_cur;
		copy_len -= copy_len_cur;
	}

	return 0;
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
		mem_blk = cn_async_pinned_mem_check(task->kvaddr_cur);
		if (!mem_blk) {
			cn_dev_pcie_err(pcie_set,
					"mem 0x%lx len=0x%lxnot exsit in pinned mem table",
					task->kvaddr_cur, len);
			return -EFAULT;
		}

		uva_base = pinned_addr - task->align_offset - (task->kvaddr_cur - mem_blk->kva_start);
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
		task->kvaddr_cur += transfer_len;
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

	/*
	 * just first 16 channel_512 have secondary copy buffer
	 */
	if (task->dma_copy == 1)
		return (1 << pcie_set->max_desc_order); /* 512 */

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
#if 0
	for (i = 0; i < task->page_cnt; i++) {
		channel->pp_pages[i] = task->pp_pages[i];
	}
#else
	/* just swap point table for fast copy */
	p = channel->pp_pages;
	channel->pp_pages = task->pp_pages;
	task->pp_pages = p;
#endif

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

	if (task->dma_copy) {
		cn_pci_dma_copy_update_sgl(channel);
		if (channel->direction == DMA_H2D)
			return cn_pci_copy_buf(channel, 1);
		return 0;
	}

	if (task->dma_type == PCIE_DMA_PINNED_MEM) {
		cn_pci_pinned_mem_sgl(channel, task);
		task->nents = 0;
		return 0;
	}

	if (cn_pci_fill_channel_sg(channel, task)) {
		cn_dev_pcie_err(pcie_set, "cn_pci_fill_channel_sg fail");
		return -1;
	}

	/* TODO: H2D/D2H use differnt direction flag */
	nents = dma_map_sg(&pcie_set->pdev->dev, channel->sg, channel->nents,
			DMA_BIDIRECTIONAL);
	if (!nents) {
		cn_dev_pcie_err(pcie_set, "dma map sglist fail nents=%d", nents);
		return -1;
	}
	channel->nents = nents;

	return 0;
}

static void cn_pci_pinned_mem_sgl_free(struct dma_channel_info *channel)
{
	struct scatterlist *sg;
	struct cn_core_set *core =
		(struct cn_core_set *)channel->pcie_set->bus_set->core;
	unsigned long dma_addr;
	unsigned long count;
	struct device *dev;
	int i = 0;

	dev = cn_bus_get_dev((void *)core->bus_set);
	if (!dev) {
		cn_dev_err("dev is NULL");
		return;
	}

	for_each_sg(channel->sg, sg, channel->nents, i) {
		dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);
		dma_unmap_page(dev, dma_addr, count, DMA_BIDIRECTIONAL);
	}
	channel->nents = 0;
}

static int cn_pci_channel_dma_end(struct dma_channel_info *channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	int i;

	if (channel->dma_copy) {
		if (channel->direction == DMA_D2H)
			cn_pci_copy_buf(channel, 0);
	} else {
		if (channel->dma_type == PCIE_DMA_PINNED_MEM)
			cn_pci_pinned_mem_sgl_free(channel);
		if (channel->nents && channel->dma_type != PCIE_DMA_PINNED_MEM)
			dma_unmap_sg(&pcie_set->pdev->dev, channel->sg,
				channel->nents, DMA_BIDIRECTIONAL);
		for (i = 0; i < channel->page_cnt; i++) {
			if (channel->pp_pages[i]) {
				if (channel->dma_type != PCIE_DMA_KERNEL &&
					channel->dma_type != PCIE_DMA_MEMSET &&
					channel->dma_type != PCIE_DMA_PINNED_MEM) {
					if (channel->direction == DMA_D2H)
						set_page_dirty_lock((struct page *)
								channel->pp_pages[i]);
					put_page((struct page *)channel->pp_pages[i]);
				}
			}
			channel->pp_pages[i] = NULL;
		}
	}
	channel->page_cnt = 0;
	channel->nents = 0;
	channel->dma_copy = 0;
	channel->task = NULL;
	channel->fix_count = 0;

	cn_pci_set_idle_channel(channel);

	return 0;
}

static int cn_pci_channel_dma_start(struct cn_pcie_set *pcie_set,
		struct dma_channel_info *channel)
{
	int phy;
	struct pcie_dma_task *task = channel->task;
	ulong mask;
	int success = 0;

	mask = (ulong)(pcie_set->dma_phy_channel_mask &
		(~pcie_set->channel_run_flag));
	if (task->cfg.phy_dma_mask)
		mask &= (ulong)task->cfg.phy_dma_mask;

	for_each_set_bit(phy, &mask, pcie_set->max_phy_channel) {
		if (__sync_bool_compare_and_swap(&pcie_set->running_channels[phy],
				0, (unsigned long)channel) == 0)
			continue;

		if (!__sync_bool_compare_and_swap(&channel->status, CHANNEL_READY, CHANNEL_RUNNING)) {
			cn_dev_pcie_err(pcie_set, "set CHANNEL_RUNNING error:%d", channel->status);
			__sync_lock_test_and_set(&pcie_set->running_channels[phy], 0);
			return -1;
		}
		__sync_fetch_and_or(&pcie_set->channel_run_flag, (1 << phy));

		if (unlikely(task->cfg.phy_mode)) {
			if (!(pcie_set->ops->dma_bypass_smmu)) {
				cn_dev_pcie_err(pcie_set, "Don't support physical mode dma");
			} else {
				pcie_set->ops->dma_bypass_smmu(phy, 1, pcie_set);
			}
		}

		if (pcie_set->ops->dma_go_command(channel, phy) < 0) {
			__sync_fetch_and_and(&pcie_set->channel_run_flag, ~(1 << phy));
			__sync_lock_test_and_set(&pcie_set->running_channels[phy], 0);
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
	struct dma_channel_info *channel;

	if (task == NULL)
		return;

	cn_dev_pcie_info(p_set, "time out task:%lx", (unsigned long)task);
	cn_dev_pcie_info(p_set, "direction:%d  cpu_addr_cur:%lx count:%lx",
		task->transfer->direction, task->align_offset, task->count);

	cn_dev_pcie_info(p_set, "task ready fifo len: %d",
			kfifo_len(&task->ready_fifo));

	cn_dev_pcie_info(p_set, "task finish fifo len: %d",
			kfifo_len(&task->finish_fifo));

	for (i = 0; i < p_set->max_phy_channel; i++) {
		channel = (struct dma_channel_info *)p_set->running_channels[i];
		if (channel && channel->task == task) {
			cn_dev_pcie_info(p_set,
				"phy_channel:%d %lx desc_va:%#llx run_status:%d task:%lx",
				i, (unsigned long)channel,
				channel->desc_device_va, channel->status,
				(unsigned long)channel->task);

			cn_pci_print_channel_info(channel, p_set);
		}
	}
}

static void cn_pci_check_error_wait(struct pcie_dma_task *task)
{
	struct dma_channel_info *channel;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	unsigned int ret;

	/* stop schedule by interrupt handle */
	__sync_lock_test_and_set(&task->status, DMA_TASK_EXIT);

	/* wait running channel finish */
	mdelay(5);
	while (!kfifo_is_empty(&task->ready_fifo)) {
		ret = kfifo_out(&task->ready_fifo, &channel, sizeof(channel));
		if (ret != sizeof(channel)) {
			cn_dev_pcie_err(pcie_set, "ready_fifo out fail");
		}

		cn_pci_channel_dma_end(channel);
	}

	mdelay(5);
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
#if 1
	struct cn_pcie_set *pcie_set = task->pcie_set;
	size_t len;
	unsigned long offset;
	int div = 4;

	if ((task->count > pcie_set->dma_buffer_size * 2) ||
			(remain <= 64 * 1024))
		return min(remain, (size_t)pcie_set->dma_buffer_size);

	if ((remain < 128 * 1024))
		div = 2;

	if (!task->dma_copy)
		offset = ((task->transfer->ca +
					task->align_offset) & (PAGE_SIZE - 1));
	else
		/* 4-byte algin big packet split to small packets
		 * very small packet need len 64-byte algin
		 */
		offset = 0;

	len = ((task->count / div + PAGE_SIZE) & PAGE_MASK) + PAGE_SIZE - offset;
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

static size_t cn_pci_dma_transfer(struct pcie_dma_task *task)
{
	size_t transfer_len = 0;
	size_t len, remain;
	int retry_cnt = 0;         /* when error occur, we must retry to transfer */
	struct dma_channel_info *channel = NULL;
	u64 ram_addr, cpu_addr;
	u64 pinned_kvaddr;
	u64 dma_wait_cnt = 0;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	u64 start_jiffies = 0;
	DMA_DIR_TYPE direction;
	long ret;
	int flag = 0;

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

	ram_addr = task->transfer->ia + task->align_offset;
	cpu_addr = task->transfer->ca + task->align_offset;
	pinned_kvaddr = task->kvaddr + task->align_offset;
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
	if (cn_pci_small_packet_write(task))
		return 0;

	__sync_fetch_and_add(&pcie_set->task_num, 1);

	while (1) {
		int nents = 0;

		if (pcie_set->state == PCIE_STATE_STOP) {
			cn_dev_pcie_err(pcie_set, "in stop state");
			goto ERROR_RETURN;
		}

		if (remain > 0) {
			len = cn_pci_transfer_len(task, remain);
			if (task->dma_type != PCIE_DMA_P2P) {
				nents = cn_pci_get_pages(task, cpu_addr, len);
				if (nents < 0) {
					cn_dev_pcie_err(pcie_set, "cn_pci_get_pages fail");
					cn_pci_check_error_wait(task);
					__sync_fetch_and_sub(&pcie_set->task_num, 1);
					return nents;
				}
			}

			channel = cn_pci_get_idle_channel(pcie_set, task, nents);
			if (channel != NULL) {
				dma_wait_cnt = 0;

				channel->direction = direction;
				channel->transfer_length = len;
				channel->cpu_addr = cpu_addr;
				channel->ram_addr = ram_addr;
				channel->pinned_kvaddr = pinned_kvaddr;
				channel->dma_type = task->dma_type;
				channel->dma_copy = task->dma_copy;

				cpu_addr += len;
				ram_addr += len;
				pinned_kvaddr += len;
				remain -= len;

				flag++;

				if (task->dma_type != PCIE_DMA_P2P) {
					if (cn_pci_channel_update_sgl(channel)) {
						cn_pci_set_idle_channel(channel);
						goto ERROR_RETURN;
					}
				}

				if (cn_pci_channel_dma_ready(channel, remain)) {
					cn_pci_set_idle_channel(channel);
					goto ERROR_RETURN;
				}
			}
		}

		/*
		 * if no packet need split to transfer, wait for finish
		 * if no idle virtual channel, wait until someone release virtual channel
		 */
		if (remain == 0 || channel == NULL) {
			if (flag) {
				/* waiting a running channel to completed */
retry:
				ret = wait_event_interruptible_timeout(task->channel_wq,
					!kfifo_is_empty(&task->finish_fifo), TIME_OUT_VALUE);
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
				u64 cur = get_jiffies_64();

				if (dma_wait_cnt <= 3) {
					start_jiffies = get_jiffies_64();
				} else if (time_after64(cur, start_jiffies + HZ * 5)) {
					cn_dev_pcie_info(pcie_set, "dma_wait_cnt:%lld %dms",
						dma_wait_cnt, jiffies_to_msecs(cur - start_jiffies));
					start_jiffies = get_jiffies_64();
				}

				dma_wait_cnt++;
				schedule();
			}
		}


		/*
		 * setting the already complelte channel to idle,
		 * if the channel if error, we will retry to transfer it
		 */
		while (!kfifo_is_empty(&task->finish_fifo)) {
			if (!kfifo_out(&task->finish_fifo, &channel, sizeof(channel))) {
				cn_dev_pcie_err(pcie_set, "finish_fifo out fail");
				return -1;
			}
			flag--;

			if (channel != NULL) {
				if (channel->status == CHANNEL_COMPLETED) {
					transfer_len += channel->transfer_length;
					if (!pcie_set->af_enable || task->dma_copy)
						cn_pci_channel_dma_end(channel);
					else
						channel->status = CHANNEL_ASYNC_FREE;
				} else if (channel->status == CHANNEL_COMPLETED_ERR) {
					retry_cnt++;
					cn_dev_pcie_info(pcie_set,
							"retry:%d length:%ld",
							retry_cnt, channel->transfer_length);
					if (retry_cnt >= 3) {
						cn_pci_channel_dma_end(channel);
						cn_dev_pcie_err(pcie_set, "Too much error");
						goto ERROR_RETURN;
					}
					__sync_fetch_and_add(&pcie_set->soft_retry_cnt, 1);
					cn_pci_channel_dma_ready(channel, remain);
				}
			}
		}

		if (transfer_len >= task->count)
			break;
	}

	if (task->non_align_flag) {
		ret = cn_pci_bar_copy_data(task);
		if (ret < 0) {
			cn_dev_pcie_err(pcie_set, "bar copy error");
			goto ERROR_RETURN;
		}
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

static int cn_pci_dma_align(struct pcie_dma_task *task, struct transfer_s *t,
		enum CN_PCIE_DMA_TYPE type, struct cn_pcie_set *pcie_set)
{
	size_t head_cnt = 0;
	size_t tail_cnt = 0;
	struct non_align_s *p;

	if (task->pcie_set->ops->dma_align) {
		task->dma_copy = task->pcie_set->ops->dma_align(t,
				&head_cnt, &tail_cnt);
	}

	if (head_cnt) {
		p = &task->non_align[0];
		p->cnt = head_cnt;
		p->ia = t->ia;
		p->ca = t->ca;
		task->align_offset += head_cnt;
		task->count -= head_cnt;
		task->non_align_flag = 1;
	}

	if (tail_cnt) {
		p = &task->non_align[1];
		p->cnt = tail_cnt;
		p->ia = t->ia + t->size - tail_cnt;
		p->ca = t->ca + t->size - tail_cnt;
		task->count -= tail_cnt;
		task->non_align_flag = 1;
	}

	if (task->non_align_flag)
		__sync_fetch_and_add(&pcie_set->non_align_cnt, 1);

	return 0;
}

static int cn_pci_init_dma_task(struct pcie_dma_task *task, struct transfer_s *t,
		enum CN_PCIE_DMA_TYPE type, struct cn_pcie_set *pcie_set)
{
	task->pcie_set = pcie_set;
	task->transfer = t;
	task->count = t->size;
	task->align_offset = 0;
	task->dma_type = type;
	task->tsk = current;
	task->tsk_mm = current->mm;
	memset(task->non_align, 0, sizeof(task->non_align));
	task->non_align_flag = 0;
	task->dma_copy = 0;
	task->dma_async = 0;
	task->p2p_src_bar = NULL;
	task->p2p_dst_bar = NULL;
	memset(&task->cfg, 0, sizeof(task->cfg));
	task->nents = 0;
	task->page_cnt = 0;
	task->poison_flag = 0;

	return cn_pci_dma_align(task, t, type, pcie_set);
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
	if (cn_pci_init_dma_task(task, t, type, pcie_set)) {
		cn_pci_put_dma_idle_task(pcie_set, task);
		return t->size;
	}

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

	/* The address aligned require */
	if ((t->ca & 0x3F) || (t->size & 0x3f) || (t->ia & 0x03)) {
		cn_dev_pcie_err(pcie_set,
				"hostAddr:0x%lx dev:addr:%llx count:%lx",
				t->ca, t->ia, t->size);
		return -1;
	}

	task = cn_pci_get_dma_idle_task(pcie_set, t->direction);
	if (!task)
		return -1;
	if (cn_pci_init_dma_task(task, t, PCIE_DMA_USER_REMOTE, pcie_set)) {
		cn_pci_put_dma_idle_task(pcie_set, task);
		return t->size;
	}

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
	if (cn_pci_init_dma_task(task, &t, PCIE_DMA_KERNEL, pcie_set)) {
		cn_pci_put_dma_idle_task(pcie_set, task);
		return count;
	}

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
	if (cn_pci_init_dma_task(task, t, type, pcie_set)) {
		cn_pci_put_dma_idle_task(pcie_set, task);
		return t->size;
	}

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
	if (cn_pci_init_dma_task(task, &t,
			PCIE_DMA_KERNEL, pcie_set)) {
		cn_pci_put_dma_idle_task(pcie_set, task);
		return count;
	}

	task->cfg = *cfg;
	ret = cn_pci_dma_transfer(task);
	cn_pci_put_dma_idle_task(pcie_set, task);
	return ret;
}

static int cn_pci_alloc_dma_buffer(struct dma_channel_info *channel)
{
	int i;
	struct dma_buf_info *element;
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	struct pci_dev *pci_dev = pcie_set->pdev;
	int order = 0;
	int buf_cnt, buf_sz;

retry:
	buf_cnt = 1 << order;
	buf_sz = pcie_set->dma_buffer_size / buf_cnt;
	if (buf_sz < PAGE_SIZE) {
		channel->dma_buf_cnt = 0;
		goto exit;
	}

	channel->dma_buf = cn_kzalloc(sizeof(*element) * buf_cnt, GFP_KERNEL);
	if (channel->dma_buf == NULL) {
		cn_dev_pcie_err(pcie_set, "dma_buf kzalloc error");
		return -1;
	}

	for (i = 0; i < buf_cnt; i++) {
		element = &channel->dma_buf[i];
		element->size = buf_sz;
		element->vir_addr = dma_alloc_coherent(&pci_dev->dev,
					buf_sz, &(element->dma_addr),
						GFP_KERNEL | __GFP_NOWARN);
		if (element->vir_addr == NULL) {
			while (i--) {
				element = &channel->dma_buf[i];
				dma_free_coherent(&pci_dev->dev, element->size,
					element->vir_addr, element->dma_addr);
			}
			cn_kfree(channel->dma_buf);
			order++;
			goto retry;
		}
	}
	channel->dma_buf_cnt = buf_cnt;

exit:
	cn_dev_pcie_debug(pcie_set, "buf_sz=%#x, buf_cnt=%d",
		buf_sz, channel->dma_buf_cnt);
	return 0;
}

static void cn_pci_free_dma_buffer(struct dma_channel_info *channel)
{
	struct dma_buf_info *element;
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	struct pci_dev *pci_dev = pcie_set->pdev;
	int buf_cnt = channel->dma_buf_cnt;

	if (buf_cnt) {
		while (buf_cnt--) {
			element = &channel->dma_buf[buf_cnt];
			if (element->vir_addr) {
				pci_free_consistent(pci_dev, element->size,
						element->vir_addr, element->dma_addr);
				element->vir_addr = NULL;
				element->dma_addr = 0;
			}
		}
		cn_kfree(channel->dma_buf);
		channel->dma_buf_cnt = 0;
	}
}

static void cn_pci_dma_channel_mem_release(struct cn_pcie_set *pcie_set)
{
	if (pcie_set->running_channels) {
		cn_kfree(pcie_set->running_channels);
		pcie_set->running_channels = NULL;
	}
}

static int cn_pci_shared_desc_order_table_init(struct cn_pcie_set *pcie_set)
{
	int max_pages, max_order;
	int cnt;

	/*
	 * worst case, 1MB start addr not 4k-align and all pages not continuous
	 * contain 1MB/4K + 1 = 257 pages
	 */
	max_pages = roundup_pow_of_two((pcie_set->dma_buffer_size / PAGE_SIZE) + 1);
	max_order = order_base_2(max_pages);
	pcie_set->max_desc_order = max_order;

	cnt = (pcie_set->shared_desc_total_size / 2 / pcie_set->per_desc_size)
		>> pcie_set->max_desc_order;
	if (!cnt) {
		cn_dev_pcie_err(pcie_set, "not enough space to assign for max order channel");
		cn_dev_pcie_info(pcie_set, "shared_desc_total_size:%#lx per_desc_size:%d",
				pcie_set->shared_desc_total_size, pcie_set->per_desc_size);
		cn_dev_pcie_info(pcie_set, "max_desc_order:%d", pcie_set->max_desc_order);
		return -1;
	}

	pcie_set->order_table = cn_kzalloc(
		sizeof(*pcie_set->order_table) * (max_order + 1), GFP_KERNEL);
	if (pcie_set->order_table == NULL) {
		cn_dev_pcie_err(pcie_set, "order_table kzalloc error");
		return -1;
	}

	return 0;
}

static void cn_pci_shared_desc_order_table_release(struct cn_pcie_set *pcie_set)
{
	if (pcie_set->order_table) {
		cn_kfree(pcie_set->order_table);
		pcie_set->order_table = NULL;
	}
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
		cn_device_share_mem_free(0, host_kva, dev_va, pcie_set->bus_set->core);
	}
}

static int cn_pci_shared_dma_channel_soft_init(struct cn_pcie_set *pcie_set,
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

	if (block == (1 << pcie_set->max_desc_order) && id < 16) {
		if (cn_pci_alloc_dma_buffer(channel)) {
			cn_dev_pcie_err(pcie_set,
					"channel alloc_dma_buffer error");
			return -1;
		}
	}

	return 0;
exit:
	cn_pci_shared_dma_channel_soft_release(channel);
	cn_dev_pcie_err(pcie_set, "shared dma channel soft init fail");
	return -1;
}

static void cn_pci_shared_dma_channel_soft_release(struct dma_channel_info *channel)
{
	if (channel->dma_buf)
		cn_pci_free_dma_buffer(channel);

	if (channel->sg)
		cn_vfree(channel->sg);

	if (channel->pp_pages)
		cn_kfree(channel->pp_pages);
}

static int cn_pci_shared_dma_channel_init(struct cn_pcie_set *pcie_set,
		u64 dev_va, unsigned long host_kva, int order)
{
	int i;
	int block = pcie_set->order_table[order].block;
	int cnt = pcie_set->order_table[order].number;
	struct dma_channel_info *channel;
	struct dma_channel_info **list = pcie_set->order_table[order].list;
	int step = block * pcie_set->per_desc_size;

	/* Hardware Limit: desc addr 64 Bytes align */
	if (order == 0)
		step = 64;

	for (i = 0; i < cnt; i++, dev_va += step, host_kva += step) {
		channel = cn_kzalloc(sizeof(*channel), GFP_KERNEL);
		if (channel == NULL)
			goto exit;

		channel->desc_order = order;
		channel->desc_device_va = dev_va;
		channel->desc_virt_base = (void *)host_kva;
		channel->desc_size = block * pcie_set->per_desc_size;

		cn_dev_pcie_debug(pcie_set,
			"shared channel[%d]%d host[%#lx] <-> dev[%#llx]",
				block, i, host_kva, dev_va);

		if (cn_pci_shared_dma_channel_soft_init(pcie_set, channel, i)) {
			cn_kfree(channel);
			goto exit;
		}


		list[i] = channel;
	}

	return 0;
exit:
	cn_pci_shared_dma_channel_release(pcie_set, order);
	cn_dev_pcie_err(pcie_set, "shared dma channel init fail");
	return -1;
}

static void cn_pci_shared_dma_channel_release(struct cn_pcie_set *pcie_set, int order)
{
	int i;
	int cnt = pcie_set->order_table[order].number;
	struct dma_channel_info **list = pcie_set->order_table[order].list;
	struct dma_channel_info *channel;

	for (i = 0; i < cnt; i++) {
		channel = list[i];
		if (channel) {
			cn_pci_shared_dma_channel_soft_release(channel);
			cn_kfree(channel);
			list[i] = NULL;
		}
	}
}

static int cn_pci_shared_dma_channel_table_init(struct cn_pcie_set *pcie_set,
					int total, int block, int i)
{
	int cnt = (total / pcie_set->per_desc_size) / block;

	/* Hardware Limit: desc addr 64 Bytes align */
	if (i == 0)
		cnt = cnt / 2;

	pcie_set->order_table[i].list = cn_kzalloc(
			sizeof(*pcie_set->order_table[i].list) * cnt, GFP_KERNEL);
	if (pcie_set->order_table[i].list == NULL)
		return -1;

	return cnt;
}

static void cn_pci_shared_dma_channel_table_release(struct cn_pcie_set *pcie_set, int i)
{
	if (pcie_set->order_table[i].list) {
		cn_kfree(pcie_set->order_table[i].list);
		pcie_set->order_table[i].list = NULL;
	}
}

/*
 * for example 1MB share memory, each desc is 32Byte, total desc number: 1MB/32=32K
 * block  : 512 256 128 64 32 16 8  4  2  1
 * number : 32  32  32  32 32 32 32 32 32 64
 *
 * order_table
 * [0] ---> order=0, block=1, number=64, list[0][1][2]....[63]
 * [1] ---> order=1, block=2, number=32, list[0][1][2]....[31]
 * [2] ---> order=2, block=4, number=32. list[0][1][2]....[31]
 *  .
 * [9] ---> order=9, block=512, number=32, list[0][1][2]....[31]
 *
 */
static int cn_pci_shared_dma_desc_init(struct cn_pcie_set *pcie_set)
{
	int i, block, total, cnt;
	u64 dev_va;
	unsigned long host_kva;

	total = pcie_set->shared_desc_total_size;
	dev_va = pcie_set->shared_desc_dev_va;
	host_kva = pcie_set->shared_desc_host_kva;

	for (i = pcie_set->max_desc_order; i >= 0;  i--) {
		if (i != 0) /* last one dont split */
			total /= 2;

		block = 1 << i; /* 2^i from 512 to 1 */
		cnt = cn_pci_shared_dma_channel_table_init(pcie_set,
				total, block, i);
		if (cnt == -1)
			goto exit;

		pcie_set->order_table[i].block = block;
		pcie_set->order_table[i].number = cnt;
		cn_dev_pcie_debug(pcie_set, "block%d number=%d",
			pcie_set->order_table[i].block, pcie_set->order_table[i].number);

		if (cn_pci_shared_dma_channel_init(pcie_set, dev_va, host_kva, i))
			goto exit;

		dev_va += total;
		host_kva += total;
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

	if (!pcie_set->order_table)
		return;

	for (i = 0; i <= pcie_set->max_desc_order; i++) {
		if (pcie_set->order_table[i].number == 0)
			continue;

		cn_pci_shared_dma_channel_release(pcie_set, i);
		cn_pci_shared_dma_channel_table_release(pcie_set, i);
	}
}

static int cn_pci_check_shared_dma_desc(struct cn_pcie_set *pcie_set)
{
	int i;
	int order_size = 0;
	int size = 0;
	u64 dev_va;
	struct dma_channel_info **list;

	dev_va = pcie_set->shared_desc_dev_va;

	for (i = pcie_set->max_desc_order; i >= 0;  i--) {
		list = pcie_set->order_table[i].list;
		if (dev_va != list[0]->desc_device_va) {
			cn_dev_pcie_err(pcie_set, "check dev_va error order:%d", i);
		}

		order_size = pcie_set->order_table[i].block *
			pcie_set->order_table[i].number * pcie_set->per_desc_size;
		dev_va += order_size;
		size += order_size;
	}
	if (size > pcie_set->shared_desc_total_size) {
		cn_dev_pcie_err(pcie_set, "shared dma desc spilt error");
		return -1;
	}

	return 0;
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
	if (channel->dma_buf)
		cn_pci_free_dma_buffer(channel);

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

		channel->desc_order = order;
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

	pcie_set->running_channels = cn_kzalloc(
			(pcie_set->max_phy_channel) *
				(sizeof(unsigned long)), GFP_KERNEL);
	if (!pcie_set->running_channels) {
		cn_dev_pcie_err(pcie_set, "Phy channel kzalloc error");
		return -1;
	}

	ret = cn_pci_shared_desc_order_table_init(pcie_set);
	if (ret)
		goto shared_desc_order_table_init_err;

	ret = cn_pci_shared_desc_shm_init(pcie_set);
	if (ret)
		goto shared_desc_shm_init_err;

	ret = cn_pci_shared_dma_desc_init(pcie_set);
	if (ret)
		goto shared_dma_desc_init_err;

	ret = cn_pci_check_shared_dma_desc(pcie_set);
	if (ret)
		goto check_shared_dma_desc;

	return 0;

check_shared_dma_desc:
	cn_pci_shared_dma_desc_release(pcie_set);
shared_dma_desc_init_err:
	cn_pci_shared_desc_shm_release(pcie_set);
shared_desc_shm_init_err:
	cn_pci_shared_desc_order_table_release(pcie_set);
shared_desc_order_table_init_err:
	cn_pci_dma_channel_mem_release(pcie_set);

	return -1;
}

static struct pcie_dma_task *cn_pci_get_dma_idle_task(struct cn_pcie_set *pcie_set, DMA_DIR_TYPE direction)
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

	return NULL;
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
	task->desc_buf = cn_vmalloc(desc_num * pcie_set->per_desc_size);
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
	u64 start, cur;

	/*
	 * channel->status has three situations
	 * CHANNEL_ASYNC_FREE : ready to release channel resource
	 * CHANNEL_COMPLETED : dma transfer complete but not ready to release
	 * CHANNEL_IDLE : dma transfer error, has been released
	 */
	start = get_jiffies_64();
	while (!kfifo_is_empty(&pcie_set->af_fifo)) {
		ret = kfifo_out_peek(&pcie_set->af_fifo, &channel, sizeof(channel));
		if (ret != sizeof(channel)) {
			cn_dev_pcie_err(pcie_set, "af_fifo out peek fail");
		}
		if (channel->status == CHANNEL_ASYNC_FREE) {
			ret = kfifo_out(&pcie_set->af_fifo, &channel, sizeof(channel));
			if (ret != sizeof(channel)) {
				cn_dev_pcie_err(pcie_set, "af_fifo out fail");
			}
			cn_pci_channel_dma_end(channel);
		} else if (channel->status == CHANNEL_IDLE) {
			ret = kfifo_out(&pcie_set->af_fifo, &channel, sizeof(channel));
			if (ret != sizeof(channel)) {
				cn_dev_pcie_err(pcie_set, "af_fifo out fail");
			}
		}

		cur = get_jiffies_64();
		if (time_after64(cur, start + HZ * 15)) {
			cn_dev_pcie_debug(pcie_set, "dma async free is busy %dms",
					jiffies_to_msecs(cur - start));
			start = get_jiffies_64();
			schedule();
		}
	}
}

static int cn_pci_dma_async_free_init(struct cn_pcie_set *pcie_set)
{
	u64 share_cnt, priv_cnt;

	/* num_order[0] maybe equal to 2 * num_order[max_order] */
	share_cnt = ((pcie_set->shared_desc_total_size / 2 / pcie_set->per_desc_size)
			>> pcie_set->max_desc_order) * (pcie_set->max_desc_order + 1);
	priv_cnt = ((pcie_set->priv_desc_total_size / 2 / pcie_set->per_desc_size)
			>> (pcie_set->max_desc_order - 1)) * pcie_set->max_desc_order;
	cn_dev_pcie_debug(pcie_set,
			"share_cnt[%lld], priv_cnt[%lld]", share_cnt, priv_cnt);

	if (kfifo_alloc(&pcie_set->af_fifo,
			sizeof(void *) * (share_cnt + priv_cnt), GFP_KERNEL)) {
		cn_dev_pcie_err(pcie_set, "af_fifo alloc error");
		return -1;
	}

	INIT_WORK(&pcie_set->async_free_work, cn_pci_async_free_handle);

	cn_dev_pcie_info(pcie_set, "dma async free init success");
	return 0;
}

static void cn_pci_dma_async_free_exit(struct cn_pcie_set *pcie_set)
{
	if (!pcie_set->async_free_work.func)
		return;
	cancel_work_sync(&pcie_set->async_free_work);
	flush_work(&pcie_set->async_free_work);
	kfifo_free(&pcie_set->af_fifo);
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

static int cn_pci_dma_sync_init(struct cn_pcie_set *pcie_set)
{
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
	cn_pci_shared_desc_order_table_release(pcie_set);
	cn_pci_dma_channel_mem_release(pcie_set);

	cn_pci_dma_task_release(pcie_set);
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
