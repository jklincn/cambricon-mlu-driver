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

static void cn_pci_pinned_mem_sgl_free(struct dma_channel_info *channel);
static int cn_pci_channel_dma_start(struct cn_pcie_set *pcie_set);
static int cn_pci_dma_async_init(struct cn_pcie_set *pcie_set);

static int cn_pci_get_idle_channel(struct pcie_dma_task *task)
{
	int i, index;
	struct cn_pcie_set *p_set = task->pcie_set;

	if (((p_set->max_channel / 2) <= task->channel_count) ||
			(p_set->max_channel/p_set->task_active_num <=
			task->channel_count))
		return -1;

	index = p_set->channel_search_start % p_set->max_channel;
	for (i = 0; i < p_set->max_channel; i++, index++) {
		index = index % p_set->max_channel;

		/*
		 * 4 bytes non-align dma data need secondary copy,
		 * but for some platforms (like HI3559) dma coherent buf are not enough.
		 * so we only use ready channel for transfer
		 */
		if (task->dma_copy == 1) {
			if (p_set->dma_channels[index].dma_buf_cnt == 0)
				continue;
		}

		if (__sync_bool_compare_and_swap(
				&p_set->dma_channels[index].status,
				CHANNEL_IDLE, CHANNEL_ASSIGNED)) {
			p_set->dma_channels[index].task = task;
			task->channel_count++;
			return index;
		}
	}

	return -1;
}

static void cn_pci_set_idle_channel(struct dma_channel_info *channel)
{
	if (channel->task)
		channel->task->channel_count--;

	__sync_lock_test_and_set(&channel->status, CHANNEL_IDLE);
}

static int cn_pci_channel_dma_ready(struct dma_channel_info *channel)
{
	u32 channel_mask;
	struct cn_pcie_set *p = channel->pcie_set;

	if (!(p->ops->fill_desc_list)) {
		cn_dev_pcie_err(p, "fill_desc_list is NULL");
		return -EINVAL;
	}
	if (p->ops->fill_desc_list(channel)) {
		cn_dev_pcie_err(p, "fill desc fail channelID:%d", channel->id);
		return -1;
	}

	channel_mask = p->dma_res.channel_mask;
	if (channel->task->cfg.phy_dma_mask) {
		channel_mask &= channel->task->cfg.phy_dma_mask;
	}

	__sync_lock_test_and_set(&channel->status, CHANNEL_READY);
	while ((p->channel_run_flag & channel_mask) ^ channel_mask) {
		cn_pci_channel_dma_start(p);

		if (channel->status != CHANNEL_READY)
			break;
		schedule();
	}

	return 0;
}

static void cn_pci_print_channel_info(int id, struct cn_pcie_set *pcie_set)
{
	if (!(pcie_set->ops->show_desc_list)) {
		cn_dev_pcie_err(pcie_set, "show_desc_list is NULL");
		return;
	}
	if (id >= 0 && id < pcie_set->max_channel)
		pcie_set->ops->show_desc_list(&pcie_set->dma_channels[id]);
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
	struct scatterlist *sg_merge;
	unsigned int per_size = DMA_BUFFER_SIZE / channel->dma_buf_cnt;

	channel->nents_merge = 0;
	sg_merge = (struct scatterlist *)channel->sg_merge;

	for (i = 0; i < channel->transfer_length / per_size; i++) {
		sg_dma_address(sg_merge) = channel->dma_buf[i].dma_addr;
		sg_dma_len(sg_merge) = channel->dma_buf[i].size;
		channel->nents_merge++;
		sg_merge++;
	}

	remain = channel->transfer_length % per_size;
	if (remain) {
		sg_dma_address(sg_merge) = channel->dma_buf[i].dma_addr;
		sg_dma_len(sg_merge) = remain;
		channel->nents_merge++;
	}
}

static void cn_pci_p2p_sg(struct dma_channel_info *channel)
{
	int i;
	unsigned long dma_addr = 0;
	struct scatterlist *sg;
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	u64 p2p_offset = pcie_set->p2p_bus_offset;

	if (p2p_offset == 0)
		return;
	for_each_sg(channel->sg, sg, channel->nents, i) {
		dma_addr = sg_dma_address(sg);
		sg_dma_address(sg) = dma_addr - p2p_offset;
	}
}

/*
 * merge 4k continuous phy pages, reduce dma dec number
 * then increase pcie dma bandwidth
 */
static void cn_pci_pages_merge_sgl(struct dma_channel_info *channel, int offset)
{
	int start_page, i;
	struct scatterlist *sg  = (struct scatterlist *)channel->sg;
	size_t remain_len = channel->transfer_length;
	size_t chunk_size;
	int page_cnt = channel->page_cnt;

	sg_init_table(sg, page_cnt);

	for (start_page = 0, i = 0; i < page_cnt; i++) {
		if (i == page_cnt - 1)
			sg_mark_end(sg);
		else if (page_to_pfn((struct page *)channel->pp_pages[i]) + 1 !=
				page_to_pfn((struct page *)channel->pp_pages[i + 1]))
			sg_unmark_end(sg);
		else
			continue;

		chunk_size = min((size_t)((i - start_page + 1) * PAGE_SIZE - offset),
				remain_len);
		sg_set_page(sg, (struct page *)channel->pp_pages[start_page],
				chunk_size, offset);

		remain_len -= chunk_size;
		sg = sg_next(sg);
		offset = 0;
		channel->nents++;
		start_page = i + 1;
	}
}

/*
 * for enable iommu system, merge can reduce dma dec number
 * then increase pcie dma bandwidth
 */
static void cn_pci_iommu_merge_sgl(struct dma_channel_info *channel)
{
	int i;
	struct scatterlist *sg;
	struct scatterlist *sg_merge;
	unsigned long cpu_addr_cur;
	unsigned long count_cur;
	unsigned long cpu_dma_addr = 0;
	unsigned long count = 0;

	channel->nents_merge = 0;
	sg_merge = (struct scatterlist *)channel->sg_merge;

	for_each_sg(channel->sg, sg, channel->nents, i) {
		cpu_addr_cur = sg_dma_address(sg);
		count_cur = sg_dma_len(sg);

		if (!i)
			cpu_dma_addr = cpu_addr_cur;

		if (cpu_dma_addr + count == cpu_addr_cur)
			count += count_cur;
		else {
			sg_dma_address(sg_merge) = cpu_dma_addr;
			sg_dma_len(sg_merge) = count;
			channel->nents_merge++;
			sg_merge++;
			cpu_dma_addr = cpu_addr_cur;
			count = count_cur;
		}
	}

	sg_dma_address(sg_merge) = cpu_dma_addr;
	sg_dma_len(sg_merge) = count;
	channel->nents_merge++;
	sg_merge++;
}

static int cn_pci_pinned_mem_sgl(struct dma_channel_info *channel)
{
	struct pcie_dma_task *task = channel->task;
	struct scatterlist *sg_merge = (struct scatterlist *)channel->sg_merge;
	struct cn_core_set *core = (struct cn_core_set *)channel->pcie_set->bus_set->core;
	struct device *dev;
	struct pinned_mem_va *mem_uva;
	struct pinned_mem *mem_blk;
	unsigned long uva_base;
	unsigned long page_count = 0;
	unsigned long dma_addr = 0;
	unsigned long offset;
	unsigned long count;
	unsigned long len;
	unsigned long pinned_addr;
	struct page *pg;
	CN_HOSTALLOC_TYPE type;
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	size_t transfer_len;

	channel->nents_merge = 0;
	len = channel->transfer_length;
	pinned_addr = channel->cpu_addr;

	dev = cn_bus_get_dev((void *)core->bus_set);
	if (!dev) {
		cn_dev_pcie_err(pcie_set, "dev is NULL");
		return -1;
	}

	if (task->dma_async) {
		mem_blk = cn_async_pinned_mem_check(task->kvaddr_cur);
		if (!mem_blk) {
			cn_dev_pcie_err(pcie_set,
				"mem 0x%lx len=0x%lxnot exsit in pinned mem table",
				task->kvaddr_cur, len);
			return -EFAULT;
		}

		type = mem_blk->type;
		uva_base = pinned_addr - task->align_offset - (task->kvaddr_cur - mem_blk->kva_start);
		transfer_len = len;
		while (len > 0) {
			pg = cn_pinned_mem_get_pages(mem_blk, uva_base,
					pinned_addr,
					&page_count);
			offset = pinned_addr - uva_base;
			offset &= ~PAGE_MASK;
			count = min((page_count << PAGE_SHIFT) - offset, len);

			switch (type) {
			case CN_HOSTALLOC_TYPE_DEFAULT:
					dma_addr = (unsigned long)dma_map_page(dev, pg, offset,
					count, DMA_BIDIRECTIONAL);
				if (dma_mapping_error(dev, dma_addr)) {
					cn_dev_pcie_err(pcie_set, "dma_mapping_error error");
					goto exit;
				}
				break;
			default:
				cn_dev_pcie_err(pcie_set, "pinned mem type error");
				goto exit;
			}

			sg_dma_address(sg_merge) = dma_addr;
			sg_dma_len(sg_merge) = count;

			sg_merge++;
			channel->nents_merge++;
			pinned_addr += count;
			len -= count;
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
		type = mem_blk->type;

		while (len > 0) {
			offset = pinned_addr - mem_uva->va_start;
			pg = cn_pinned_mem_get_pages(mem_blk, mem_uva->va_start,
					pinned_addr, &page_count);
			if (!pg) {
				cn_dev_pcie_err(pcie_set,
						"mem 0x%lx not exsit in pinned mem table",
						pinned_addr);
				return -EFAULT;
			}
			offset &= ~PAGE_MASK;
			count = min((page_count << PAGE_SHIFT) - offset, len);
			switch (type) {
			case CN_HOSTALLOC_TYPE_DEFAULT:
				dma_addr = (unsigned long)dma_map_page(dev, pg, offset,
				count, DMA_BIDIRECTIONAL);
				if (dma_mapping_error(dev, dma_addr)) {
					cn_dev_pcie_err(pcie_set, "dma_mapping_error error");
					goto exit;
				}
				break;
			default:
				cn_dev_pcie_err(pcie_set, "pinned mem type error");
				goto exit;
			}

			sg_dma_address(sg_merge) = dma_addr;
			sg_dma_len(sg_merge) = count;

			sg_merge++;
			channel->nents_merge++;
			pinned_addr += count;
			len -= count;
		}
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

	if (task->dma_type == PCIE_DMA_P2P)
		cpu_addr = task->dst_addr +
				(channel->cpu_addr - task->transfer->d_bar);
	else
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
			case PCIE_DMA_P2P:
				if (!copy_flag) {
					if (cn_pci_p2p_bar_write(task,
							cpu_addr,
							(unsigned long)buf_virt,
							copy_len_cur)) {
						cn_dev_pcie_err(pcie_set,
							"p2p_dma_write failed");
						return -1;
					}
				}
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
			case PCIE_DMA_P2P:
				if (!copy_flag) {
					if (cn_pci_p2p_bar_write(task,
							cpu_addr,
							(unsigned long)buf_virt,
							copy_len_cur)) {
						cn_dev_pcie_err(pcie_set,
							"p2p_dma_write failed");
						return -1;
					}
				}
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

static void cn_pci_put_page(struct dma_channel_info *channel, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		put_page((struct page *)channel->pp_pages[i]);
		channel->pp_pages[i] = NULL;
	}
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

static int cn_pci_do_user_page(struct dma_channel_info *channel,
		unsigned long cpu_addr, int cnt)
{
	int nents;
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	unsigned int flags = 0;
	struct pcie_dma_task *task = channel->task;
	struct mm_struct *mm = task->tsk_mm;

	if (!atomic_inc_not_zero(&mm->mm_users)) {
		cn_dev_pcie_err(pcie_set, "atomic_inc_not_zero");
		return -1;
	}

	if (channel->direction == DMA_D2H)
		flags |= FOLL_WRITE;

	cn_mmap_read_lock(mm);
	if (mm == current->mm)
		nents = cn_get_user_pages(cpu_addr, cnt, flags,
				(struct page **)(channel->pp_pages), NULL);
	else
		nents = cn_get_user_pages_remote(task->tsk,
				mm, cpu_addr, cnt, flags,
				(struct page **)(channel->pp_pages), NULL, NULL);

	if (nents == -EFAULT) {
		nents = cn_get_io_pages(mm, cpu_addr, cnt, (struct page **)(channel->pp_pages));
	}

	cn_mmap_read_unlock(mm);
	mmput(mm);

	if (nents != cnt) {
		cn_dev_pcie_err(pcie_set,
				"cpu_addr:0x%lx, nents:%d, cnt:%d",
				cpu_addr, nents, cnt);
		cn_pci_put_page(channel, nents);
		return -EFAULT;
	}

	return 0;
}

static int cn_pci_do_kernel_page(struct dma_channel_info *channel,
		unsigned long kernel_addr, int cnt)
{
	int i;

	for (i = 0; i < cnt; i++) {
		channel->pp_pages[i] =
			virt_to_page(kernel_addr + i * PAGE_SIZE);
	}
	return 0;
}

static int cn_pci_do_p2p_page(struct dma_channel_info *channel,
		unsigned long bar_addr, int cnt)
{
	int i;

	for (i = 0; i < cnt; i++) {
		channel->pp_pages[i] =
			pfn_to_page((bar_addr + i * PAGE_SIZE) >>
					PAGE_SHIFT);
	}
	return 0;
}

static int cn_pci_do_sg_page(struct dma_channel_info *channel)
{
	unsigned long cpu_addr, offset;
	int page_cnt;
	int ret = -1;
	int len = channel->transfer_length;
	struct pcie_dma_task *task = channel->task;

	cpu_addr = channel->cpu_addr;
	offset = cpu_addr & (~PAGE_MASK);
	page_cnt = (offset + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	channel->page_cnt = page_cnt;

	cpu_addr &= PAGE_MASK;

	switch (task->dma_type) {
	case PCIE_DMA_USER:
	case PCIE_DMA_USER_REMOTE:
		ret = cn_pci_do_user_page(channel, cpu_addr, page_cnt);
		break;

	case PCIE_DMA_MEMSET:
	case PCIE_DMA_KERNEL:
		ret = cn_pci_do_kernel_page(channel, cpu_addr, page_cnt);
		break;

	case PCIE_DMA_P2P:
		ret = cn_pci_do_p2p_page(channel, cpu_addr, page_cnt);
		break;

	default:
		break;
	}

	if (ret)
		return ret;

	cn_pci_pages_merge_sgl(channel, offset);
	return 0;
}

static int cn_pci_channel_update_sgl(struct dma_channel_info *channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	struct pcie_dma_task *task = channel->task;
	int nents;
	int ret = 0;

	if (task->dma_copy) {
		cn_pci_dma_copy_update_sgl(channel);
		if (channel->direction == DMA_H2D)
			return cn_pci_copy_buf(channel, 1);
		return 0;
	}

	if (task->dma_type == PCIE_DMA_PINNED_MEM)
		return cn_pci_pinned_mem_sgl(channel);

	ret = cn_pci_do_sg_page(channel);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "do dma sg page fail");
		return ret;
	}

	/* TODO: H2D/D2H use differnt direction flag */
	nents = dma_map_sg(&pcie_set->pdev->dev, channel->sg, channel->nents,
			DMA_BIDIRECTIONAL);
	if (!nents) {
		cn_dev_pcie_err(pcie_set, "dma map sglist fail nents=%d", nents);
		return -1;
	}
	channel->nents = nents;

	if ((task->dma_type == PCIE_DMA_P2P) &&
			(channel->pcie_set->p2p_bus_offset != 0)) {
		cn_pci_p2p_sg(channel);
	}
	cn_pci_iommu_merge_sgl(channel);

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

	for_each_sg(channel->sg_merge, sg, channel->nents_merge, i) {
		dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);
		dma_unmap_page(dev, dma_addr, count, DMA_BIDIRECTIONAL);
	}
	channel->nents_merge = 0;
}

static int cn_pci_channel_dma_end(struct dma_channel_info *channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	int i;
	struct pcie_dma_task *task;

	task = channel->task;
	if (task->dma_copy) {
		if (channel->direction == DMA_D2H || channel->direction == DMA_P2P)
			cn_pci_copy_buf(channel, 0);
	} else {
		if (task->dma_type == PCIE_DMA_PINNED_MEM)
			cn_pci_pinned_mem_sgl_free(channel);
		if (channel->nents && task->dma_type != PCIE_DMA_PINNED_MEM)
			dma_unmap_sg(&pcie_set->pdev->dev, channel->sg,
				channel->nents, DMA_BIDIRECTIONAL);
		for (i = 0; i < channel->page_cnt; i++) {
			if (channel->pp_pages[i]) {
				if (channel->direction == DMA_D2H)
					set_page_dirty_lock((struct page *)
							channel->pp_pages[i]);
				if (task->dma_type != PCIE_DMA_KERNEL &&
					task->dma_type != PCIE_DMA_MEMSET &&
					task->dma_type != PCIE_DMA_P2P &&
					task->dma_type != PCIE_DMA_PINNED_MEM) {
					put_page((struct page *)channel->pp_pages[i]);
				}
			}
			channel->pp_pages[i] = NULL;
		}
	}
	channel->page_cnt = 0;
	channel->nents = 0;

	channel->task->channel_wait_flag &= (~(1ul << channel->id));
	__sync_fetch_and_and(&channel->task->channel_done_flag,
		(~(1ul << (channel->id))));
	cn_pci_set_idle_channel(channel);

	return 0;
}

static int cn_pci_channel_dma_start(struct cn_pcie_set *pcie_set)
{
	int i = 0;
	int phy;
	int index;
	struct dma_channel_info *channel;
	struct pcie_dma_task *task;
	ulong mask;
	int success;

	for (i = 0; i < pcie_set->max_channel; i++) {
		mask = (ulong)(pcie_set->dma_res.channel_mask &
			(~pcie_set->channel_run_flag));
		if (!mask) {
			break;
		}

		index = (pcie_set->channel_search_start + i) % pcie_set->max_channel;
		channel = &pcie_set->dma_channels[index];

		if (channel->status != CHANNEL_READY) {
			continue;
		}

		if (!__sync_bool_compare_and_swap(&channel->status, CHANNEL_READY,
			CHANNEL_LOCK)) {
			continue;
		}

		success = 0;
		task = channel->task;
		mask = (ulong)(pcie_set->dma_res.channel_mask &
			(~pcie_set->channel_run_flag));
		if (task->cfg.phy_dma_mask)
			mask &= (ulong)task->cfg.phy_dma_mask;

		for_each_set_bit(phy, &mask, pcie_set->max_phy_channel) {
			if (__sync_bool_compare_and_swap(&pcie_set->running_channels[phy],
					0, (unsigned long)channel) == 0)
				continue;

			__sync_lock_test_and_set(&channel->status, CHANNEL_RUNNING);
			__sync_fetch_and_or(&pcie_set->channel_run_flag, (1 << phy));

			if (!(pcie_set->ops->dma_go_command)) {
				cn_dev_pcie_err(pcie_set, "dma_go is NULL");
				return -EINVAL;
			}

			if (unlikely(task->cfg.phy_mode)) {
				if (!(pcie_set->ops->dma_bypass_smmu)) {
					cn_dev_pcie_err(pcie_set, "Don't support physical mode dma");
					cn_dev_pcie_err(pcie_set, "Channel:%d is physical mode", index);
				} else {
					pcie_set->ops->dma_bypass_smmu(phy, 1, pcie_set);
				}
			}

			if (pcie_set->ops->dma_go_command(channel, phy) < 0) {
				__sync_fetch_and_and(&pcie_set->channel_run_flag, ~(1 << phy));
				__sync_lock_test_and_set(&channel->status, CHANNEL_LOCK);
				__sync_lock_test_and_set(&pcie_set->running_channels[phy], 0);
				break;
			}

			success = 1;
			break;
		}

		if (success) {
			__sync_fetch_and_add(&pcie_set->channel_search_start, 1);
		} else {
			__sync_lock_test_and_set(&channel->status, CHANNEL_READY);
		}
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

	cn_dev_pcie_info(p_set, "task:%lx channel_wait_flag:%lx",
		(unsigned long)task, task->channel_wait_flag);
	cn_dev_pcie_info(p_set,
		"channel_done_flag:%lx cpu_addr_cur:%lx count:%lx",
		task->channel_done_flag, task->align_offset, task->count);
	cn_dev_pcie_info(p_set, "direction:%d channel_count:%d",
		task->transfer->direction, task->channel_count);

	for (i = 0; i < p_set->max_channel; i++) {
		channel = &p_set->dma_channels[i];
		cn_dev_pcie_info(p_set,
			"Channel:%d %d %lx status:%d task:%lx",
			i, channel->id, (unsigned long)channel,
			channel->status,
			(unsigned long)channel->task);
		cn_pci_print_channel_info(i, p_set);
	}

	for (i = 0; i < p_set->max_phy_channel; i++) {
		channel = (struct dma_channel_info *)p_set->running_channels[i];
		if (channel) {
			cn_dev_pcie_info(p_set,
				"phy_channel:%d %d %lx run_status:%d task:%lx",
				i, channel->id, (unsigned long)channel,
				channel->status,
				(unsigned long)channel->task);
		}
	}
}

static void cn_pci_check_error_wait(struct pcie_dma_task *task)
{
	int i, j;
	struct dma_channel_info *channel = NULL;

	for (i = 0; i < 1000000; i++) {
		for (j = 0; j < task->pcie_set->max_channel; j++) {
			if (!(task->channel_wait_flag & (1ul << j)))
				continue;

			channel = &task->pcie_set->dma_channels[j];
			__sync_bool_compare_and_swap(&channel->status,
				CHANNEL_READY, CHANNEL_COMPLETED);
			if (channel->status != CHANNEL_LOCK &&
					channel->status != CHANNEL_RUNNING)
				cn_pci_channel_dma_end(channel);
		}

		if (!task->channel_wait_flag)
			break;
		schedule();
		udelay(10);
	}

	mdelay(5);

	for (j = 0; j < task->pcie_set->max_channel; j++) {
		if (!(task->channel_wait_flag & (1ul << j)))
			continue;

		channel = &task->pcie_set->dma_channels[j];
		cn_dev_pcie_err(task->pcie_set,
			"channel_id:%d channel_wait_flag:%lx",
			j, task->channel_wait_flag);
		cn_pci_channel_dma_end(channel);
	}
}

static size_t cn_pci_transfer_len(struct pcie_dma_task *task, size_t remain)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	size_t len;
	unsigned long offset;
	int div = 4;

	if ((task->count > pcie_set->dma_buffer_size * 2) ||
			(pcie_set->task_active_num > 2) ||
			(remain <= 64 * 1024))
		return min(remain, (size_t)pcie_set->dma_buffer_size);

	if ((remain < 128 * 1024) || (pcie_set->task_active_num >= 2))
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
}

static size_t cn_pci_dma_transfer(struct pcie_dma_task *task)
{
	int channel_id;
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
	int ret;

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

	if (!pcie_set->dma_res.channel_mask) {
		cn_dev_pcie_err(pcie_set, "No dma channel now");
		return -1;
	}

	__sync_fetch_and_add(&pcie_set->task_num, 1);

	if (pcie_set->state == PCIE_STATE_SUSPEND) {
		long ret;

		do {
			__sync_fetch_and_add(&pcie_set->task_suspend_num, 1);
			ret = wait_event_interruptible(pcie_set->task_suspend_wq,
				pcie_set->state != PCIE_STATE_SUSPEND);
			__sync_fetch_and_sub(&pcie_set->task_suspend_num, 1);

			if (ret < 0) {
				cn_dev_pcie_err(pcie_set, "Task is breaked by signal");
				__sync_fetch_and_sub(&pcie_set->task_num, 1);
				return -1;
			}
		} while (pcie_set->state == PCIE_STATE_SUSPEND);
	}

	if (pcie_set->state == PCIE_STATE_STOP) {
		cn_dev_pcie_info(pcie_set, "dma stop");
		__sync_fetch_and_sub(&pcie_set->task_num, 1);
		return -1;
	}

	if ((direction == DMA_H2D) &&
			task->transfer->size <= pcie_set->dma_bypass_custom_size &&
			(task->dma_type == PCIE_DMA_USER ||
			task->dma_type == PCIE_DMA_KERNEL)) {
		if (!cn_pci_dma_bar_write(task)) {
			__sync_fetch_and_sub(&pcie_set->task_num, 1);
			return 0;
		}
	}

	if ((direction == DMA_H2D) &&
			task->transfer->size <= pcie_set->dma_bypass_pinned_size &&
			(task->dma_type == PCIE_DMA_PINNED_MEM)) {
		if (!cn_pci_dma_bar_write(task)) {
			__sync_fetch_and_sub(&pcie_set->task_num, 1);
			return 0;
		}
	}

	if (direction != DMA_P2P) {
		ret = down_killable(&pcie_set->transfer_data_sem);
		if (ret) {
			__sync_fetch_and_sub(&pcie_set->task_num, 1);
			cn_dev_pcie_err(pcie_set, "down_killable=%d", ret);
			return task->count;
		}
	}

	__sync_fetch_and_add(&pcie_set->task_active_num, 1);

	while (1) {
		if (pcie_set->state == PCIE_STATE_STOP) {
			cn_dev_pcie_err(pcie_set, "in stop state");
			goto ERROR_RETURN;
		}

		channel_id = -1;
		if (remain > 0) {
			len = cn_pci_transfer_len(task, remain);
			channel_id = cn_pci_get_idle_channel(task);
		}

		if (channel_id >= 0 && channel_id < pcie_set->max_channel) {
			int ret;
			dma_wait_cnt = 0;

			channel = &pcie_set->dma_channels[channel_id];
			channel->direction = direction;
			channel->transfer_length = len;
			channel->cpu_addr = cpu_addr;
			channel->ram_addr = ram_addr;
			channel->pinned_kvaddr = pinned_kvaddr;

			cpu_addr += len;
			ram_addr += len;
			pinned_kvaddr += len;
			remain -= len;
			task->channel_wait_flag |= (1ul << channel_id);

			ret = cn_pci_channel_update_sgl(channel);
			if (ret) {
				cn_dev_pcie_err(pcie_set, "channel_id:%d",
						channel_id);
				cn_pci_check_error_wait(task);
				__sync_fetch_and_sub(&pcie_set->task_active_num, 1);
				__sync_fetch_and_sub(&pcie_set->task_num, 1);
				if (direction != DMA_P2P) {
					up(&pcie_set->transfer_data_sem);
				}
				return ret;
			}

			if (cn_pci_channel_dma_ready(channel)) {
				cn_dev_pcie_err(pcie_set, "fail channel_id:%d",
						channel_id);
				goto ERROR_RETURN;
			}
		} else {
			if (task->channel_wait_flag) {
				/* waiting a running channel to completed */
				long ret;
retry:
				ret = wait_event_interruptible_timeout(task->channel_wq,
					(task->channel_wait_flag & task->channel_done_flag),
					TIME_OUT_VALUE);
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

					cn_dev_pcie_err(pcie_set, "time out 0x%lx 0x%lx",
						task->channel_wait_flag, task->channel_done_flag);
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

		/* setting the already complelte channel to idle,
		 * if the channel if error, we will retry to transfer it
		 */
		for (channel_id = 0; channel_id < pcie_set->max_channel; channel_id++) {
			if ((task->channel_wait_flag & task->channel_done_flag) &
					(1 << channel_id)) {
				channel = &pcie_set->dma_channels[channel_id];

				if (channel->status == CHANNEL_COMPLETED) {
					transfer_len += channel->transfer_length;
					cn_pci_channel_dma_end(channel);
				} else if (channel->status == CHANNEL_COMPLETED_ERR) {
					retry_cnt++;
					cn_dev_pcie_info(pcie_set,
						"retry:%d channel_id:%d length:%ld",
						retry_cnt, channel_id, channel->transfer_length);
					__sync_fetch_and_and(&task->channel_done_flag, (~(1 << channel_id)));
					if (retry_cnt >= 3) {
						cn_dev_pcie_err(pcie_set, "Too much error");
						goto ERROR_RETURN;
					}
					__sync_fetch_and_add(&pcie_set->soft_retry_cnt, 1);
					cn_pci_channel_dma_ready(channel);
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

	__sync_fetch_and_sub(&pcie_set->task_active_num, 1);
	__sync_fetch_and_sub(&pcie_set->task_num, 1);
	if (direction != DMA_P2P) {
		up(&pcie_set->transfer_data_sem);
	}
	return 0;

ERROR_RETURN:
	cn_pci_check_error_wait(task);
	__sync_fetch_and_sub(&pcie_set->task_active_num, 1);
	__sync_fetch_and_sub(&pcie_set->task_num, 1);
	if (direction != DMA_P2P) {
		up(&pcie_set->transfer_data_sem);
	}
	return task->count;
}


static int cn_pci_dma_align(struct pcie_dma_task *task, struct transfer_s *t,
		enum CN_PCIE_DMA_TYPE type, struct cn_pcie_set *pcie_set)
{
	size_t head_cnt = 0;
	size_t tail_cnt = 0;
	struct non_align_s *p;

	if (task->pcie_set->ops->dma_align)
		task->pcie_set->ops->dma_align(task, &head_cnt, &tail_cnt);

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
	task->dma_type = type;
	task->tsk = current;
	task->tsk_mm = current->mm;
	init_waitqueue_head(&task->channel_wq);

	return cn_pci_dma_align(task, t, type, pcie_set);
}

static size_t cn_pci_dma(struct transfer_s *t, void *pcie_priv)
{
	struct pcie_dma_task task;
	struct pinned_mem_va *mem;
	enum CN_PCIE_DMA_TYPE type;

	mem = cn_pinned_mem_check(current, t->ca, t->size);
	type = mem ? PCIE_DMA_PINNED_MEM : PCIE_DMA_USER;

	memset(&task, 0, sizeof(task));
	if (cn_pci_init_dma_task(&task, t, type,
			(struct cn_pcie_set *)pcie_priv))
		return t->size;

	return cn_pci_dma_transfer(&task);
}

static size_t cn_pci_dma_remote(struct transfer_s *t,
	struct task_struct *tsk, struct mm_struct *tsk_mm, void *pcie_priv)
{
	struct pcie_dma_task task;
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

	memset(&task, 0, sizeof(task));
	if (cn_pci_init_dma_task(&task, t,
			PCIE_DMA_USER_REMOTE, pcie_set))
		return t->size;

	task.tsk = tsk;
	task.tsk_mm = tsk_mm;
	atomic_inc(&tsk_mm->mm_count);

	ret = cn_pci_dma_transfer(&task);
	mmdrop(tsk_mm);
	return ret;
}

static size_t cn_pci_dma_kernel(unsigned long host_addr, u64 device_addr,
		size_t count, DMA_DIR_TYPE dir, void *pcie_priv)
{
	struct pcie_dma_task task;
	struct transfer_s t;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	TRANSFER_INIT(t, host_addr, device_addr, count, dir);

	memset(&task, 0, sizeof(task));
	if (cn_pci_init_dma_task(&task, &t,
			PCIE_DMA_KERNEL, pcie_set))
		return count;

	return cn_pci_dma_transfer(&task);
}

static size_t cn_pci_dma_cfg(struct transfer_s *t,
		struct dma_config_t *cfg, void *pcie_priv)
{
	struct pcie_dma_task task;
	struct pinned_mem_va *mem;
	enum CN_PCIE_DMA_TYPE type;

	mem = cn_pinned_mem_check(current, t->ca, t->size);
	type = mem ? PCIE_DMA_PINNED_MEM : PCIE_DMA_USER;

	memset(&task, 0, sizeof(task));
	if (cn_pci_init_dma_task(&task, t, type,
			(struct cn_pcie_set *)pcie_priv))
		return t->size;

	task.cfg = *cfg;
	return cn_pci_dma_transfer(&task);
}

static size_t cn_pci_dma_kernel_cfg(unsigned long host_addr, u64 device_addr,
		size_t count, DMA_DIR_TYPE direction,
		struct dma_config_t *cfg, void *pcie_priv)
{
	struct pcie_dma_task task;
	struct transfer_s t;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	TRANSFER_INIT(t, host_addr, device_addr, count, direction);

	memset(&task, 0, sizeof(task));
	if (cn_pci_init_dma_task(&task, &t,
			PCIE_DMA_KERNEL, pcie_set))
		return count;

	task.cfg = *cfg;
	return cn_pci_dma_transfer(&task);
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
	cn_dev_pcie_debug(pcie_set, "channel%d buf_sz=0x%x, buf_cnt=%d",
		channel->id, buf_sz, channel->dma_buf_cnt);
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
	int i;
	struct dma_channel_info *channel;

	if (pcie_set->running_channels) {
		cn_kfree(pcie_set->running_channels);
		pcie_set->running_channels = NULL;
	}

	if (!pcie_set->dma_channels)
		return;

	for (i = 0; i < pcie_set->max_channel; i++) {
		channel = &pcie_set->dma_channels[i];
		if (channel->pp_pages) {
			cn_kfree(channel->pp_pages);
			channel->pp_pages = NULL;
		}

		if (channel->sg) {
			cn_kfree(channel->sg);
			channel->sg = NULL;
		}

		if (channel->sg_merge) {
			cn_kfree(channel->sg_merge);
			channel->sg_merge = NULL;
		}

		cn_pci_free_dma_buffer(channel);
	}

	cn_kfree(pcie_set->dma_channels);
	pcie_set->dma_channels = NULL;
}

static int cn_pci_dma_channel_mem_init(struct cn_pcie_set *pcie_set)
{
	int i, pages;
	struct dma_channel_info *channel;

	pcie_set->running_channels = cn_kzalloc(
			(pcie_set->max_phy_channel) *
				(sizeof(unsigned long)), GFP_KERNEL);
	if (!pcie_set->running_channels) {
		cn_dev_pcie_err(pcie_set, "Phy channel kzalloc error");
		return -1;
	}

	pcie_set->dma_channels = cn_kzalloc(
			(pcie_set->max_channel) *
				(sizeof(*channel)), GFP_KERNEL);
	if (!pcie_set->dma_channels) {
		cn_dev_pcie_err(pcie_set, "Channel kzalloc error");
		return -1;
	}

	pages = (pcie_set->dma_buffer_size / PAGE_SIZE) + 1;
	for (i = 0; i < pcie_set->max_channel; i++) {
		channel = &pcie_set->dma_channels[i];
		channel->pcie_set = pcie_set;
		channel->id = i;
		__sync_lock_test_and_set(&channel->status, CHANNEL_IDLE);

		channel->pp_pages = cn_kzalloc(pages * sizeof(struct page *), GFP_KERNEL);
		if (!channel->pp_pages) {
			cn_dev_pcie_err(pcie_set,
				"Channel %d kzalloc pp_pages error", i);
			return -1;
		}

		channel->sg = cn_kzalloc(pages * sizeof(struct scatterlist), GFP_KERNEL);
		if (!channel->sg) {
			cn_dev_pcie_err(pcie_set,
				"Channel %d kzalloc sgl error", i);
			return -1;
		}

		channel->sg_merge = cn_kzalloc(pages * sizeof(struct scatterlist), GFP_KERNEL);
		if (!channel->sg_merge) {
			cn_dev_pcie_err(pcie_set,
				"Channel %d kzalloc sgl error", i);
			return -1;
		}
		sg_init_table(channel->sg_merge, pages);

		if (cn_pci_alloc_dma_buffer(channel)) {
			cn_dev_pcie_err(pcie_set,
				"Channel %d alloc_dma_buffer error", i);
			return -1;
		}
	}

	return 0;
}

static int cn_pci_device_share_mem_init(struct cn_pcie_set *pcie_set)
{
	int i, rc;
	struct dma_channel_info *channel;
	dev_addr_t dev_vaddr;
	host_addr_t host_vaddr;

	if (!pcie_set->max_channel)
		return 0;

	rc = cn_device_share_mem_alloc(0, &host_vaddr, &dev_vaddr,
				pcie_set->dma_desc_total_size,
				pcie_set->bus_set->core);
	if (rc)
		return -1;

	cn_dev_pcie_info(pcie_set,
		"alloc host[%lx] <-> dev[%llx]", host_vaddr, dev_vaddr);

	for (i = 0; i < pcie_set->max_channel; i++) {
		channel = &pcie_set->dma_channels[i];
		channel->desc_size = pcie_set->dma_desc_total_size / pcie_set->max_channel;
		channel->desc_device_va = dev_vaddr + i * channel->desc_size;
		channel->desc_virt_base = (void *)host_vaddr + i * channel->desc_size;
	}

	return 0;
}

static int cn_pci_dma_sync_init(struct cn_pcie_set *pcie_set)
{
	assert(pcie_set != NULL);

	if (cn_pci_dma_channel_mem_init(pcie_set))
		goto release_memory;

	if (cn_pci_device_share_mem_init(pcie_set))
		goto release_memory;

	pcie_set->ops->dma_bypass_size(pcie_set);

	cn_dev_pcie_debug(pcie_set, "dma channel init successfully");
	return 0;

release_memory:
	cn_dev_pcie_info(pcie_set, "dma channel init failed");
	cn_pci_dma_channel_mem_release(pcie_set);

	return -1;
}

static void cn_pci_device_share_mem_release(struct cn_pcie_set *pcie_set)
{
	struct cn_bus_set *bus_set = pcie_set->bus_set;
	host_addr_t host_vaddr;
	dev_addr_t dev_vaddr;

	if (!pcie_set->max_channel)
		return;

	if (!pcie_set->dma_channels)
		return;

	host_vaddr = (host_addr_t)(pcie_set->dma_channels[0].desc_virt_base);
	dev_vaddr = (dev_addr_t)(pcie_set->dma_channels[0].desc_device_va);
	if (host_vaddr && dev_vaddr)
		cn_device_share_mem_free(0, host_vaddr, dev_vaddr, bus_set->core);

	pcie_set->dma_channels[0].desc_virt_base = 0;
	pcie_set->dma_channels[0].desc_device_va = 0;
}

static void cn_pci_dma_sync_exit(struct cn_pcie_set *pcie_set)
{
	cn_pci_device_share_mem_release(pcie_set);
	cn_pci_dma_channel_mem_release(pcie_set);
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
