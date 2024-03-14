#include "cndrv_debug.h"
/*
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
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/of.h>
#include <linux/io.h>
#include <linux/types.h>
#include <linux/kallsyms.h>
#include "cndrv_bus.h"
#include "cndrv_edge.h"
#include "cndrv_core.h"
#include "cndrv_domain.h"
#include "cndrv_mm.h"
#include "cndrv_edge_c20e.h"
#include "cndrv_edge_ce3226.h"
#include "cndrv_edge_pigeon.h"
#include "cndrv_edge_pcie_arm_dev.h"
#include "cndrv_pre_compile.h"

#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/mm.h>
#endif
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif

#define CN_EDGE_DRV_NAME	"cndrv-virtual-dev"

#include "./cndrv_edge_dma.h"
#if defined(__KERNEL__)
#include "cndrv_commu.h"
#include <linux/cache.h>
#else
#error "unsupport user space"
#endif /* __KERNEL__ */

#ifdef CONFIG_CNDRV_ION_EDGE
extern void *cn_mem_map_cached(u64 iova, u64 size);

extern void *cn_mem_map_nocached(u64 iova, u64 size);

extern void cn_mem_unmap(void* kva);
#else
static void *cn_mem_map_nocached(u64 iova, u64 size)
{
	return NULL;
}

static void *cn_mem_map_cached(u64 iova, u64 size)
{
	return NULL;
}

static void cn_mem_unmap(void* kva)
{
	return;
}
#endif

void edge_reg_write32(void *priv, unsigned long offset, unsigned int val)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)priv;
	iowrite32(val, edge_set->reg_virt_base + offset);
}

unsigned int  edge_reg_read32(void *priv, unsigned long offset)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)priv;
	return ioread32(edge_set->reg_virt_base + offset);
}

void edge_reg_write64(void *priv, unsigned long offset, u64 val)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)priv;
	iowrite64(val, edge_set->reg_virt_base + offset);
}

u64 edge_reg_read64(void *priv, unsigned long offset)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)priv;
	return ioread64(edge_set->reg_virt_base + offset);
}

void edge_mem_write32(void *priv, unsigned long offset, unsigned int val)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)priv;
	iowrite32(val, edge_set->share_mem[0].virt_addr + offset);
}

unsigned int edge_mem_read32(void *priv, unsigned long offset)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)priv;
	return ioread32(edge_set->share_mem[0].virt_addr + offset);
}

int cn_edge_enable_irq(int hw_irq, void *edge_priv)
{
	return 0;
}

int cn_edge_disable_irq(int hw_irq, void *edge_priv)
{
	return 0;
}

int cn_edge_register_interrupt(int hw_irq, interrupt_cb_t handler, void *data, void *edge_priv)
{
	return 0;
}

void cn_edge_unregister_interrupt(int hw_irq, void *edge_priv)
{
}

struct device *cn_edge_get_dev(void *edge_priv)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)edge_priv;
	return &edge_set->pdev->dev;
}

int cn_edge_get_mem_cnt(void *edge_priv)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)edge_priv;
	return edge_set->shm_cnt;
}

CN_MEM_TYPE cn_edge_get_mem_type(void *pcie_priv, int index)
{
	return CN_SHARE_MEM_DEV;
}

void *cn_edge_get_mem_base(void *edge_priv, int index)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)edge_priv;
	return edge_set->share_mem[index].virt_addr;
}

unsigned long cn_edge_get_mem_size(void *edge_priv, int index)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)edge_priv;
	return edge_set->share_mem[index].win_length;
}

unsigned long cn_edge_get_mem_phyaddr(void *edge_priv, int index)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)edge_priv;
	return edge_set->share_mem[index].phy_addr;
}

int cn_edge_get_info(void *edge_priv, struct bus_info_s *bus_info)
{
	struct cn_edge_set *edge_set = (struct cn_edge_set *)edge_priv;
	int device_id = edge_set->device_id;

	bus_info->bus_type = BUS_TYPE_EDGE;
	bus_info->info.edge.vendor = device_id & 0xffff;
	bus_info->info.edge.device = (device_id >> 16) & 0xffff;
	bus_info->info.edge.subsystem_vendor = 0;

	return 0;
}
void cn_edge_mb(void *edge_priv)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)edge_priv;

	switch (edge_set->device_id) {
	case MLUID_220_EDGE:
		edge_reg_read64(edge_set, 0xa00000);
		edge_reg_read64(edge_set, 0xa00040);
		smp_mb();
		break;
	case MLUID_CE3226_EDGE:
		/*TODO: only for support this function,no test*/
		smp_mb();
		break;
	default:
		/*TODO: only for support this function,no test*/
		smp_mb();
		break;
	}
}

static struct page **edge_get_user_pages(u64 user_addr,
		u64 size, int *page_cnt,
		struct task_struct *tsk,
		struct mm_struct *tsk_mm)
{
	struct page **user_pages = NULL;
	int offset;
	int total_page;
	struct page *page_put = NULL;
	int i;

	offset = user_addr & (~PAGE_MASK);
	total_page = (offset + size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/*free in edge_put_user_pages or here function.*/
	user_pages = cn_kzalloc(sizeof(struct page *) * total_page, GFP_KERNEL);
	if (!user_pages) {
		pr_err("alloc page fail\n");
		return NULL;
	}

	/**
	 * 1. Must be called with mmap_read_lock held for read or write.
	 * 2. exit_mm of do_exit will set tsk->mm = NULL. So mst use tsk_mm,
	 * Must not use tsk->mm to cn_mmap_read_lock.
	 **/
	cn_mmap_read_lock(tsk_mm);
	*page_cnt = cn_get_user_pages_remote(tsk, tsk_mm, user_addr, total_page,
					FOLL_WRITE, user_pages, NULL, NULL);
	cn_mmap_read_unlock(tsk_mm);

	if ((*page_cnt) <= 0 || *page_cnt != total_page) {
		pr_err("get address(%#llx) user page fail, need:%d but get %d\n",
			user_addr, total_page, *page_cnt);

		for (i = 0; i < *page_cnt; i++) {
			page_put = *(user_pages + i);
			if (page_put) {
				/*dec page ref*/
				put_page(page_put);
			}
		}

		cn_kfree(user_pages);
		user_pages = NULL;
	}

	return user_pages;
}

static void edge_put_user_pages(struct page **pages, int page_cnt)
{
	int i;
	struct page *page_put = NULL;

	if (pages == NULL || page_cnt == 0)
		return;

	for (i = 0; i < page_cnt; i++) {
		page_put = *(pages + i);
		if (page_put) {
			/*dec page ref*/
			put_page(page_put);
		}
	}

	cn_kfree(pages);
}

/**
 * copy data from kernel space to user space in kthread context.
 * @kernel_vaddr: kernel space address.
 * @user_vaddr: user space address, only get offset of first page in @pages.all address information in @pages.
 * @pages: pages detail information of @user_vaddr.
 * @total_size: copy size.
 * return residual size, 0 successful, other error.
 **/
static size_t edge_copy_to_user(u64 user_vaddr, u64 kernel_vaddr, struct page **pages, size_t total_size)
{
	size_t offset;
	int index = 0;
	size_t size;
	/*vaddr: map user space to kernel space.*/
	void *vaddr;

	/*1. copy head data, that not a whole page of user_vaddr begin*/
	offset = user_vaddr & (~PAGE_MASK);
	if (offset) {
		size = PAGE_SIZE - offset;
		if (size > total_size) {
			size = total_size;
		}

		/*only use for a moment,so use kmap_atomic not use kmap*/
		vaddr = (void *)((u64)kmap_atomic(*(pages + index)) + offset);
		memcpy(vaddr, (void *)kernel_vaddr, size);
		kunmap_atomic(vaddr);

		total_size -= size;
		index++;
		kernel_vaddr += size;
	}

	/*2. copy whole page data.*/
	while (total_size >= PAGE_SIZE) {
		vaddr = kmap_atomic(*(pages + index));
		memcpy(vaddr, (void *)kernel_vaddr, PAGE_SIZE);
		kunmap_atomic(vaddr);

		total_size -= PAGE_SIZE;
		index++;
		kernel_vaddr += PAGE_SIZE;
	}

	/*3. copy tail data, that not a whole page of user_vaddr end*/
	if (total_size) {
		size = total_size;
		vaddr = kmap_atomic(*(pages + index));
		memcpy(vaddr, (void *)kernel_vaddr, size);
		kunmap_atomic(vaddr);

		total_size -= size;
		index++;
		kernel_vaddr += size;
	}

	return total_size;
}

struct edge_copy_s {
	struct page **pages;
	/*size of every page*/
	u64 page_size;
	u32 page_cnt;
	u64 total_size;
	/*total size sub toal copy size*/
	u64 remain_size;
	/*current page size valid*/
	u64 page_remain_size;
	/*next to copied page index,current is page_index - 1*/
	int page_index;
	/*page vir address*/
	u64 page_vir;
	u32 page_offset;
};

/**
 * copy data from src to dst, size is src->total_size.
 * this function support copy one time only.not support copy more than one time.
 **/
static size_t __edge_memcpy(struct edge_copy_s *src,
			struct edge_copy_s *dst, int direction)
{
	u32 cp_size = src->total_size;

	if (cp_size == 0)
		return cp_size;

	/*invalid device dcache range.*/
	if (direction == DMA_D2H) {
		cn_edge_cache_invalid((void *)src->page_vir + src->page_offset,
					cp_size);
	}

	/*copy*/
	memcpy((void *)(dst->page_vir + dst->page_offset),
			(void *)(src->page_vir + src->page_offset),
			cp_size);

	/*flush cache to DDR*/
	if (direction == DMA_H2D) {
		cn_edge_cache_clean((void *)dst->page_vir + dst->page_offset,
				cp_size);
	}

	return cp_size;
}

/**
 * copy data from kernel space to user space in kthread contex.
 * @user_tb: user space address information.
 * @kernel_tb: kernel space address information.
 * @direction:
 * tsk: task_struct information bind with @user_tb.
 * tsk_mm: mm_struct bind without $user_tb.
 * pcie_priv:
 **/
size_t edge_dma_remote(
		struct transfer_s             *transfer,
		struct task_struct            *tsk,
		struct mm_struct	      *tsk_mm,
		void                          *pcie_priv
		)
{
	u64 user_vaddr;
	u64 kernel_vaddr;
	size_t total_size;
	struct page **user_page = NULL;
	int page_cnt;

	user_vaddr = transfer->ca;
	kernel_vaddr = transfer->ia;
	total_size = transfer->size;

	/*Inc mm_count to don't release current->mm in other progress*/
	atomic_inc(&tsk_mm->mm_count);

	/* Inc a users to use this user_addr for kthread.
	 * user_addr will not release after this operation.*/
	if (!atomic_inc_not_zero(&tsk_mm->mm_users)) {
		pr_err("can not inc mm_users.\n");
		goto release_mm_count_ref;
	}

	user_page = edge_get_user_pages(user_vaddr, total_size, &page_cnt, tsk, tsk_mm);
	/*Decrement the use count and release all resources for an mm.*/
	/*Dec mm_users*/
	mmput(tsk_mm);
	if (user_page == NULL) {
		goto release_mm_count_ref;
	}

	total_size = edge_copy_to_user(user_vaddr, kernel_vaddr, user_page, total_size);

	edge_put_user_pages(user_page, page_cnt);

release_mm_count_ref:
	/*Dec mm_count*/
	mmdrop(tsk_mm);

	return total_size;
}

unsigned long cn_edge_get_reg_phyaddr(void *edge_priv)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)edge_priv;
	return edge_set->reg_phy_addr;
}

unsigned long cn_edge_get_reg_size(void *edge_priv)
{
	struct cn_edge_set *edge_set;

	edge_set = (struct cn_edge_set *)edge_priv;
	return edge_set->reg_size;
}

int cn_edge_get_lnkcap(void *pcie_priv, struct bus_lnkcap_info *lnk_info)
{
	lnk_info->speed = 0;
	lnk_info->width = 0;

	return 0;
}

int cn_edge_get_curlnk(void *pcie_priv, struct bus_lnkcap_info *lnk_info)
{
	lnk_info->speed = 0;
	lnk_info->width = 0;

	return 0;
}

int cn_edge_get_dma_info(void *pcie_priv, struct dma_info_s *dma_info)
{
	dma_info->dma_data_total[DMA_D2H] = 0;
	dma_info->dma_data_total[DMA_H2D] = 0;

	return 0;
}

int cn_edge_get_bar_info(void *pcie_priv, struct bar_info_s *bar_info)
{
	return 0;
}

static u32 cn_pci_get_bdf(void *pcie_priv)
{
	return 0;
}

static u32 cn_pci_get_current_bdf(void *pcie_priv)
{
	return 0;
}

static bool cn_pci_check_pdev_virtfn(void *pcie_priv)
{
	return 0;
}

int cn_edge_copy_to_usr_fromio(u64 dst, u64 src, size_t size, void *edge_priv)
{
	cn_edge_cache_invalid((void *)src, size);

	if (copy_to_user((void __user *)dst, (void *)src, size)) {
		return -EFAULT;
	}

	return 0;
}

int cn_edge_copy_from_usr_toio(u64 dst, u64 src, size_t size, void *edge_priv)
{
	if (copy_from_user((void *)dst, (void __user *)src, size)) {
		return -EFAULT;
	}

	cn_edge_cache_flush((void *)dst, size);
	return 0;
}

size_t cn_edge_pinned_mem_transfer(struct edge_dma_task *task)
{
	size_t total_size;
	struct edge_copy_s src_cpy = {0};
	struct edge_copy_s dst_cpy = {0};
	int remain_size;
	int ret;
	DMA_DIR_TYPE direction = task->transfer->direction;

	total_size = task->transfer->size;

	src_cpy.total_size = total_size;
	dst_cpy.total_size = total_size;

	remain_size = total_size;

	/*lock device address and get kvaddr, kva match start address of iova*/
	task->ion_cntx.kva =
		(u64)cn_mem_map_cached((u64)task->ion_cntx.iova, total_size);
	if (!task->ion_cntx.kva) {
		pr_err("%s %d mlu dev address %#llx is error\n", __func__, __LINE__,
			(u64)task->ion_cntx.iova);
		return remain_size;
	}

	switch (direction) {
		case DMA_D2H: {
			src_cpy.page_vir = task->ion_cntx.kva;
			src_cpy.page_offset = 0;

			dst_cpy.page_vir = task->kvaddr;
			dst_cpy.page_offset = 0;

			break;
		}
		case DMA_H2D: {
			src_cpy.page_vir = task->kvaddr;
			src_cpy.page_offset = 0;

			dst_cpy.page_vir = task->ion_cntx.kva;
			dst_cpy.page_offset = 0;
			break;
		}
		default: {
			pr_err("direction(%d) is error", direction);
			goto release_map_kernel;
		}
	}

	/*memcpy data*/
	ret = __edge_memcpy(&src_cpy, &dst_cpy, task->transfer->direction);
	if (likely(ret == total_size)) {
		remain_size = 0;
	}

release_map_kernel:
	/*unmap kva and sub ref count*/
	cn_mem_unmap((void *)task->ion_cntx.kva);
	return remain_size;
}

size_t cn_edge_dma_transfer(struct edge_dma_task *task)
{
	u64 src;
	u64 dst;
	size_t total_size;
	struct page **user_pages = NULL;
	int page_cnt;
	struct mm_struct *tsk_mm = task->tsk_mm;
	struct task_struct *tsk = task->tsk;
	struct edge_copy_s src_cpy = {0};
	struct edge_copy_s dst_cpy = {0};
	int ret;
	int remain_size;
	void *free;
	DMA_DIR_TYPE direction = task->transfer->direction;

	if (task->dma_type == EDGE_DMA_PINNED_MEM) {
		return cn_edge_pinned_mem_transfer(task);
	}

	total_size = task->transfer->size;

	src_cpy.total_size = total_size;
	dst_cpy.total_size = total_size;

	remain_size = total_size;

	/*Inc mm_count to don't release current->mm in other progress*/
	atomic_inc(&tsk_mm->mm_count);

	/**
	 * Inc a users to use this user_addr for kthread.
	 * user_addr will not release after this operation.
	 **/
	if (!atomic_inc_not_zero(&tsk_mm->mm_users)) {
		pr_err("can not inc mm_users.\n");
		goto release_mm_count_ref;
	}

	/*lock host address*/
	user_pages = edge_get_user_pages(task->transfer->ca,
			total_size, &page_cnt, tsk, tsk_mm);

	/*Decrement the use count and release all resources for an mm.*/
	/*Dec mm_users*/
	mmput(tsk_mm);

	if (user_pages == NULL) {
		pr_err("user address %#llx is error\n", (u64)task->transfer->ca);
		goto release_mm_count_ref;
	}

	/*lock device address and get kvaddr, kva match start address of iova*/
	task->ion_cntx.kva =
		(u64)cn_mem_map_cached((u64)task->ion_cntx.iova, total_size);
	if (!task->ion_cntx.kva) {
		pr_err("%s %d mlu dev address %#llx is error\n", __func__, __LINE__,
			(u64)task->ion_cntx.iova);
		goto release_user_page;
	}

	switch (direction) {
		case DMA_D2H: {
			src_cpy.page_vir = task->ion_cntx.kva;
			src_cpy.page_offset = 0;

			dst = task->transfer->ca;
			/**
			 * use this function for short-lived objects.
			 **/
			dst_cpy.page_vir = (u64)cn_vm_map_ram(user_pages,
							page_cnt, -1, PAGE_KERNEL);
			if (!dst_cpy.page_vir) {
				goto release_map_kernel;
			}
			/**
			 *dst_cpy.page_vir = (u64)vmap(user_pages,
			 *				page_cnt, -1, PAGE_KERNEL);
			 */
			dst_cpy.page_offset = dst & (~PAGE_MASK);
			free = (void *)dst_cpy.page_vir;

			break;
		}
		case DMA_H2D: {
			src = task->transfer->ca;
			/**
			 *use this function for short-lived objects.
			 **/
			src_cpy.page_vir = (u64)cn_vm_map_ram(user_pages,
							page_cnt, -1, PAGE_KERNEL);
			if (!src_cpy.page_vir) {
				goto release_map_kernel;
			}
			/**
			 *src_cpy.page_vir = (u64)vmap(user_pages,
			 *				page_cnt, -1, PAGE_KERNEL);
			 **/
			src_cpy.page_offset = src & (~PAGE_MASK);
			free = (void *)src_cpy.page_vir;

			dst_cpy.page_vir = task->ion_cntx.kva;
			dst_cpy.page_offset = 0;
			break;
		}
		default: {
			pr_err("direction(%d) is error", direction);
			goto release_map_kernel;
		}
	}

	/*memcpy data*/
	ret = __edge_memcpy(&src_cpy, &dst_cpy, task->transfer->direction);
	if (likely(ret == total_size)) {
		remain_size = 0;
	}

	/*if use kmap,use vunmap(free) to free;*/
	vm_unmap_ram(free, page_cnt);

release_map_kernel:
	/*unmap kva and sub ref count*/
	cn_mem_unmap((void *)task->ion_cntx.kva);
release_user_page:
	edge_put_user_pages(user_pages, page_cnt);
release_mm_count_ref:
	/*Dec mm_count*/
	mmdrop(tsk_mm);

	return remain_size;
}

static void __edge_memset_D8(u64 addr, unsigned char val, u64 number)
{
	u64 start = addr;
	unsigned long len = number;

	while (number--) {
		*(volatile u8 *)start = val;
		start++;
	}
	cn_edge_cache_clean((void *)addr, len);
}

static void __edge_memset_D16(u64 addr, unsigned short val, u64 number)
{
	u64 start = addr;
	unsigned long len = number * 2;

	while (number--) {
		*(volatile u16 *)start = val;
		start += 2;
	}
	cn_edge_cache_clean((void *)addr, len);
}

static void __edge_memset_D32(u64 addr, unsigned int val, u64 number)
{
	u64 start = addr;
	unsigned long len = number * 4;

	while (number--) {
		*(volatile u32 *)start = val;
		start += 4;
	}
	cn_edge_cache_clean((void *)addr, len);
}

int cn_edge_dma_memset(struct edge_dma_task *task)
{
	int ret = 0;
	struct memset_s *t = task->memset;
	unsigned long size = task->async_info->total_size;

	task->ion_cntx.kva = (u64)cn_mem_map_cached((u64)task->ion_cntx.iova, size);
	if (!task->ion_cntx.kva) {
		pr_err("%s %d mlu dev address %#llx is error\n", __func__, __LINE__,
			(u64)task->ion_cntx.iova);
		return -EINVAL;
	}

	if (t->direction == MEMSET_D8) {
		__edge_memset_D8(task->ion_cntx.kva, t->val, t->number);
	} else if (t->direction == MEMSET_D16) {
		__edge_memset_D16(task->ion_cntx.kva, t->val, t->number);
	} else if (t->direction == MEMSET_D32) {
		__edge_memset_D32(task->ion_cntx.kva, t->val, t->number);
	} else {
		pr_err("%s %d direction %d invalid\n", __func__, __LINE__, t->direction);
		ret = -EINVAL;
	}

	cn_mem_unmap((void *)task->ion_cntx.kva);

	return ret;
}

size_t edge_dma(struct transfer_s *t, void *pcie_priv)
{
	void *kva;
	int ret = 0;

	kva = cn_mem_map_nocached(t->ia, (u64)t->size);
	if (!kva) {
		pr_err("%s %d cn_mem_map_nocached failed!", __func__, __LINE__);
		return -ENOMEM;
	}

	if (t->direction == DMA_D2H) {
		if (copy_to_user((void __user *)t->ca, kva, t->size)) {
			pr_err("%s %d copy to usr failed!", __func__, __LINE__);
			ret = -EFAULT;
			goto out;
		}
	} else if (t->direction == DMA_H2D) {
		if (copy_from_user(kva, (void __user *)t->ca, t->size)) {
			pr_err("%s %d copy from usr failed!", __func__, __LINE__);
			ret = -EFAULT;
			goto out;
		}
	} else {
		pr_err("%s %d direction %d invalid\n", __func__, __LINE__, t->direction);
		ret = -EINVAL;
		goto out;
	}

out:
	cn_mem_unmap(kva);

	return ret;
}

static struct bus_ops edge_ops = {
	.dma_remote = edge_dma_remote,
	.dma = edge_dma,
	.mem_write32 = edge_mem_write32,
	.mem_read32 = edge_mem_read32,
	.dma_async = cn_edge_dma_async,
	.dma_async_message_process = cn_edge_dma_async_message_process,
	.dma_abort = cn_edge_dma_abort,
	.reg_write32 = edge_reg_write32,
	.reg_read32 = edge_reg_read32,
	.get_reg_size = cn_edge_get_reg_size,
	.get_reg_phyaddr = cn_edge_get_reg_phyaddr,
	.mem_mb = cn_edge_mb,
	.get_dev = cn_edge_get_dev,
	.enable_irq = cn_edge_enable_irq,
	.disable_irq = cn_edge_disable_irq,
	.get_mem_cnt = cn_edge_get_mem_cnt,
	.get_mem_base = cn_edge_get_mem_base,
	.get_mem_size = cn_edge_get_mem_size,
	.get_mem_phyaddr = cn_edge_get_mem_phyaddr,
	.get_mem_type = cn_edge_get_mem_type,
	.get_bus_info = cn_edge_get_info,
	.get_bar_info = cn_edge_get_bar_info,
	.register_interrupt = cn_edge_register_interrupt,
	.get_bus_lnkcap = cn_edge_get_lnkcap,
	.get_bus_curlnk = cn_edge_get_curlnk,
	.get_dma_info = cn_edge_get_dma_info,
	.unregister_interrupt = cn_edge_unregister_interrupt,
	.copy_to_usr_fromio = cn_edge_copy_to_usr_fromio,
	.copy_from_usr_toio = cn_edge_copy_from_usr_toio,
	.dma_memset_async = cn_edge_memset_async,
	.outbound_able = NULL,
	.core_type_switch = pigeon_edge_switch_core_type,
	.get_bus_bdf = cn_pci_get_bdf,
	.get_current_bdf = cn_pci_get_current_bdf,
	.check_pdev_virtfn = cn_pci_check_pdev_virtfn,
};

int edge_setup(void *priv)
{
	return 0;
}

int edge_pre_init(void *priv)
{
	return 0;
}

int edge_pre_exit(void *priv)
{
	return 0;
}

int edge_domain_get_resource(void *edge, struct domain_resource *resource)
{
	struct cn_edge_set *edge_set = (struct cn_edge_set *)edge;

	memset(resource, 0, sizeof(struct domain_resource));

	resource->id = edge_set->device_id;
	resource->cfg_reg_size = edge_set->reg_size;
	resource->share_mem_size = edge_set->share_mem[0].win_length;

	return 0;
}
/**
 * cn_edge_probe()
 *
 * @pdev: pci device pointer
 * @id: pointer to table of device id/id's.
 *
 * Description: This probing function gets called for all PCI devices which
 * match the ID table and are not "owned" by other driver yet. This function
 * gets passed a "struct pci_dev *" for each device whose entry in the ID table
 * matches the device. The probe functions returns zero when the driver choose
 * to take "ownership" of the device or an error code(-ve no) otherwise.
 */
static int cn_edge_probe(struct platform_device *pdev)
{
	struct cn_bus_set *bus_set;
	int ret = 0;
	struct cn_edge_set *edge_set;
	struct device_node *np = pdev->dev.of_node;
	int device_id, idx;

	if (of_property_read_u32(np, "device-id", &device_id) != 0) {
		device_id = MLUID_220_EDGE;
	}

	edge_set = cn_kzalloc(sizeof(struct cn_edge_set), GFP_KERNEL);
	if (!edge_set) {
		return -ENOMEM;
	}

	edge_set->pdev = pdev;
	edge_set->device_id = device_id;
	platform_set_drvdata(pdev, edge_set);
	idx = cn_get_mlu_idx(0, 0);

	switch (edge_set->device_id) {
	case MLUID_220_EDGE:
		c20e_edge_init(edge_set);
		break;
	case MLUID_PIGEON_EDGE:
		pigeon_edge_init(edge_set);
		break;
	case MLUID_CE3226_EDGE:
		ce3226_edge_init(edge_set);
		break;
	/* isPCIeArmPlatform() not ready yet */
	case MLUID_370_DEV:
	case MLUID_590_DEV:
	case MLUID_580_DEV:
		mlu_pcie_arm_dev_init(edge_set);
		break;
	default:
		cn_kfree(edge_set);
		pr_err("device id is error.\n");
		return -1;
	}

	bus_set = cn_bus_set_init(edge_set, &pdev->dev, &edge_ops, edge_setup,
		edge_pre_init, edge_pre_exit, edge_domain_get_resource);
	edge_set->bus_set = bus_set;

	ret = cn_bus_probe(bus_set, device_id, 0, idx);
	if (ret) {
		cn_bus_set_exit(bus_set, &pdev->dev);
		return -EFAULT;
	}

	ret = cn_edge_dma_async_init(edge_set);
	if (unlikely(ret))
		return -1;

	return ret;
}

static int cn_edge_remove(struct platform_device *pdev)
{
	struct cn_edge_set *edge_set = platform_get_drvdata(pdev);
	void *bus_set = edge_set->bus_set;

	cn_edge_dma_async_exit(edge_set);

	cn_bus_remove(bus_set, edge_set->device_id);

	cn_bus_set_exit(bus_set, &pdev->dev);

	switch (edge_set->device_id) {
	case MLUID_220_EDGE:
		c20e_edge_exit(edge_set);
		break;
	case MLUID_CE3226_EDGE:
		ce3226_edge_exit(edge_set);
		break;
	case MLUID_PIGEON_EDGE:
		pigeon_edge_exit(edge_set);
		break;
	case MLUID_370_DEV:
	case MLUID_590_DEV:
	case MLUID_580_DEV:
		mlu_pcie_arm_dev_exit(edge_set);
		break;
	default:
		break;
	}

	platform_set_drvdata(pdev, NULL);

	cn_kfree(edge_set);
	return 0;
}

static const struct of_device_id cn_edge_cdev_match[] = {
        { .compatible = "cndrv-virdev"},
        {},
};

static struct platform_driver cn_edge_driver = {
	.probe = cn_edge_probe,
	.remove = cn_edge_remove,
	.driver = {
		.name = CN_EDGE_DRV_NAME,
		.of_match_table = cn_edge_cdev_match,
	},
};

int cn_edge_drv_init(void)
{
	return platform_driver_register(&cn_edge_driver);
}

void cn_edge_drv_exit(void)
{
	return platform_driver_unregister(&cn_edge_driver);
}
