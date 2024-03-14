/************************************************************************
 *  @file pcie_bar.c
 *
 *  @brief For pcie support definitions.
 **************************************************************************/

/*************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ***************************************************************************/
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/io.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "pcie_dma.h"
#include "pcie_bar.h"
#include "cndrv_pci.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_debug.h"
#include "cndrv_mm.h"
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/mm.h>
#endif

static int cn_pci_bar_copy_to_usr_fromio(unsigned long host_addr, u64 device_addr,
		size_t count, enum BAR_BLOCK_TYPE block_type,
		void *dma_task, struct cn_pcie_set *pcie_set);
static int cn_pci_bar_copy_from_usr_toio(unsigned long host_addr, u64 device_addr,
		size_t count, enum BAR_BLOCK_TYPE block_type,
		void *dma_task, struct cn_pcie_set *pcie_set);
static int cn_pci_bar_memcpy_fromio(unsigned long host_addr, u64 device_addr,
		size_t count, enum BAR_BLOCK_TYPE block_type,
		void *dma_task, struct cn_pcie_set *pcie_set);
static int cn_pci_bar_memcpy_toio(unsigned long host_addr, u64 device_addr,
		size_t count, enum BAR_BLOCK_TYPE block_type,
		void *dma_task, struct cn_pcie_set *pcie_set);

static struct bar_resource *pcie_get_specific_bar(int index,
						struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar;
	int flag = 0;

	list_for_each_entry(bar, &pcie_set->bar_resource_head, list) {
		if (bar->type == PF_BAR && bar->index == index) {
			flag = 1;
			break;
		}
	}

	if (flag == 0) {
		cn_dev_err("get unregister bar index %d error", index);
		return NULL;
	}

	/*
	 * Try to get bar, if it's unoccupied, set wai_count == INT_MAX, this means
	 * MDR got the specefic bar and others won't get this bar until the MDR release it.
	 *
	 */
	__sync_fetch_and_add(&bar->wait_count, 1);
	if (down_killable(&bar->occupy_lock)) {
		__sync_fetch_and_sub(&bar->wait_count, 1);
		return NULL;
	}

	__sync_lock_test_and_set(&bar->wait_count, INT_MAX);

	return bar;
}

static struct bar_resource *pcie_get_bar(enum BAR_BLOCK_TYPE block_type,
				struct cn_pcie_set *pcie_set)
{
	int bar_flag = 0;
	int wait_min = INT_MAX;
	struct bar_resource *bar, *tmp;
	int ret;

	list_for_each_entry(bar, &pcie_set->bar_resource_head, list) {
		if (!down_trylock(&bar->occupy_lock)) {
			bar_flag = 1;
			break;
		}
	}

	if (bar_flag == 1)
		return bar;

	if (block_type == NOBLOCK)
		return NULL;

/*
 * wait_count == INT_MAX means this bar is allocted to MDR
 * so we need to do retry and then find another available bar in list
 *
 */
retry:
	wait_min = INT_MAX;
	bar = list_first_entry(&pcie_set->bar_resource_head,
			struct bar_resource, list);

	list_for_each_entry(tmp, &pcie_set->bar_resource_head, list) {
		if (tmp->wait_count == INT_MAX)
			continue;
		if (tmp->wait_count < wait_min) {
			wait_min = tmp->wait_count;
			bar = tmp;
		}
	}

	__sync_fetch_and_add(&bar->wait_count, 1);
	ret = down_timeout(&bar->occupy_lock, HZ / 10);
	__sync_fetch_and_sub(&bar->wait_count, 1);

	if (ret == -EINTR) {
		cn_dev_pcie_info(pcie_set, "task is breaked by signal");
		return NULL;
	}

	/* 100ms timeout, retry get bar */
	if (ret)
		goto retry;

	return bar;
}

static void pcie_put_bar(struct bar_resource *bar, struct cn_pcie_set *pcie_set)
{
	__sync_bool_compare_and_swap(&bar->wait_count, INT_MAX, 0);
	up(&bar->occupy_lock);
}

static int cn_pci_get_bar_info(void *pcie_priv, struct bar_info_s *bar_info)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pci_dev *pdev = pcie_set->pdev;
	int i;
	u64 sz, base;

	for (i = 0; i < 6; i++) {
		sz = pci_resource_len(pdev, i);
		if (!sz)
			continue;
		base = pci_resource_start(pdev, i);

		bar_info->bar[i].bar_base = base;
		bar_info->bar[i].bar_sz = sz;
	}

	return 0;
}

static u64 cn_bar_window_avail_size(struct cn_pcie_set *pcie_set,
		struct bar_resource *bar, u64 axi_addr, u64 *bar_base)
{
	u64 axi_base = pcie_set->ops->set_bar_window(
					axi_addr, bar, pcie_set);
	*bar_base = (u64)bar->base + axi_addr - axi_base;

	return (axi_base + bar->size - axi_addr);
}

#define BAR_WRITE_ONCE_START \
{\
	len = cn_bar_window_avail_size(pcie_set, \
		bar, dev_addr, &bar_base); \
	len = min(remain, len); \
}

#define BAR_WRITE_ONCE_END \
{\
	/* barrior */ \
	wmb(); \
	ioread8((void *)bar_base); \
	barrier(); \
	remain -= len; \
	data += len; \
	dev_addr += len; \
}
#define BAR_READ_ONCE_START BAR_WRITE_ONCE_START
#define BAR_READ_ONCE_END \
{\
	remain -= len; \
	data += len; \
	dev_addr += len; \
	bar_base += len; \
}

#define BAR_READ_FROMIO_FUNC(func, type, data) \
do { \
	BAR_READ_ONCE_START; \
	ret = cn_pci_##func((type)data, bar_base, len, pcie_set); \
	if (ret) { \
		cn_dev_pcie_err(pcie_set, "copy func failed"); \
		break; \
	} \
	BAR_READ_ONCE_END; \
} while (remain)

#define BAR_WRITE_TOIO_FUNC(func, type, data) \
do { \
	BAR_WRITE_ONCE_START; \
	ret = cn_pci_##func(bar_base, (type)data, len, pcie_set); \
	if (ret) { \
		cn_dev_pcie_err(pcie_set, "copy func failed"); \
		break; \
	} \
	BAR_WRITE_ONCE_END; \
} while (remain)

static int cn_pci_bar_inbound_restrict_down(enum BAR_BLOCK_TYPE block_type,
						struct bar_resource *bar,
						struct cn_pcie_set *pcie_set)
{
	u64 start;
	u64 end;

	if (block_type == BLOCK) {
		start = get_jiffies_64();
		while (!atomic_add_unless(&pcie_set->inbound_count, 1,
						pcie_set->max_inbound_cnt)) {
			udelay(10);
			end = get_jiffies_64();
			if (jiffies_to_msecs(end - start) > 10000) {
				cn_dev_pcie_err(pcie_set, "get_bar time out!");
				return -1;
			}
		}
	} else {
		if (!atomic_add_unless(&pcie_set->inbound_count, 1,
				pcie_set->max_inbound_cnt)) {
			return -1;
		}
	}

	return 0;
}

static void cn_pci_bar_inbound_restrict_up(struct cn_pcie_set *pcie_set)
{
	atomic_dec(&pcie_set->inbound_count);
}

static int cn_pci_bar_mig_bypass(struct bar_resource *bar, struct pcie_dma_task *task,
				struct cn_pcie_set *pcie_set, bool bypass)
{
	int ret;
	if (task && task->cfg.phy_mode) {
		if (bypass) {
			ret = cn_smmu_cau_bypass(pcie_set->bus_set->core, bar->smmu_in, 1);
			if (ret)
				return ret;
			ret = cn_smmu_cau_bypass(pcie_set->bus_set->core, bar->smmu_out, 1);
			if (ret)
				return ret;
		} else {
			ret = cn_smmu_cau_bypass(pcie_set->bus_set->core, bar->smmu_in, 0);
			if (ret)
				return ret;
			ret = cn_smmu_cau_bypass(pcie_set->bus_set->core, bar->smmu_out, 0);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int cn_get_io_pages(struct mm_struct *mm, unsigned long start, unsigned long nr_pages, struct page **pages);
static struct page **cn_pci_dma_get_user_pages(u64 user_addr, u64 size, int *page_cnt,
						struct pcie_dma_task *task)
{
	struct task_struct *tsk = NULL;
	struct mm_struct *tsk_mm = NULL;
	DMA_DIR_TYPE direction;
	struct page **user_pages = NULL;
	int offset;
	int total_page;
	struct page *page_put = NULL;
	unsigned int flags = 0;
	int i;

	if (!task || !task->transfer) {
		cn_dev_err("task==NULL || transfer==NULL");
		return NULL;
	}
	tsk = task->tsk;
	tsk_mm = task->tsk_mm;
	direction = task->transfer->direction;
	offset = user_addr & (~PAGE_MASK);
	total_page = (offset + size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/*free in dma_async_put_user_pages or here function.*/
	user_pages = cn_kzalloc(sizeof(struct page *) * total_page, GFP_KERNEL);
	if (!user_pages) {
		cn_dev_pcie_err(task->pcie_set, "alloc page fail");
		return NULL;
	}

	if (!atomic_inc_not_zero(&tsk_mm->mm_users)) {
		cn_kfree(user_pages);
		return NULL;
	}

	if (direction == DMA_D2H)
		flags |= FOLL_WRITE;

	/*Must be called with mmap_read_lock held for read or write.*/
	cn_mmap_read_lock(tsk_mm);
	if (tsk_mm == current->mm)
		*page_cnt = cn_get_user_pages(user_addr, total_page, flags,
					user_pages, NULL);
	else
		*page_cnt = cn_get_user_pages_remote(tsk, tsk_mm, user_addr,
					total_page, flags, user_pages, NULL, NULL);

	if (*page_cnt == -EFAULT) {
		*page_cnt = cn_get_io_pages(tsk_mm, user_addr, total_page, user_pages);
	}

	cn_mmap_read_unlock(tsk_mm);
	mmput(tsk_mm);

	if ((*page_cnt) <= 0 || *page_cnt != total_page) {
		cn_dev_pcie_err(task->pcie_set, "get addr(%#llx) page fail, need:%d but get %d\n",
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

static void cn_pci_dma_put_user_pages(struct page **pages, int page_cnt)
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

int mlu290_ce3226_pcie_bar_read(unsigned long host_addr, u64 device_addr, size_t count,
				struct cn_pcie_set *pcie_set)
{
	int ret = -1;

	if (cn_access_ok(VERIFY_WRITE, (void *)host_addr, count))
		ret = cn_pci_bar_copy_to_usr_fromio(host_addr, device_addr, count,
							BLOCK, NULL, pcie_set);
	else
		ret = cn_pci_bar_memcpy_fromio(host_addr, device_addr, count,
							BLOCK, NULL, pcie_set);
	return ret;
}

int mlu290_ce3226_pcie_bar_write(unsigned long host_addr, u64 device_addr, size_t count,
				struct cn_pcie_set *pcie_set)
{
	int ret = -1;

	if (likely(cn_access_ok(VERIFY_READ, (void *)host_addr, count)))
		ret = cn_pci_bar_copy_from_usr_toio(host_addr, device_addr, count,
							BLOCK, NULL, pcie_set);
	else
		ret = cn_pci_bar_memcpy_toio(host_addr, device_addr, count,
							BLOCK, NULL, pcie_set);
	return ret;
}


/*
 * adapt for FT1500(arm64)
 *
 * FT1500(arm64): memcpy and direct structure assignment are implemented
 * by ldp/stp instruction which don't support nocache address,
 * so we need to convert nocache address to cacheable.
 *
 */
static int cn_pci_copy_to_usr_fromio(u64 dst, u64 src, size_t size, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

#if defined(__x86_64__)
	if (copy_to_user((void __user *)dst, (void *)src, size)) {
		cn_dev_pcie_err(pcie_set,
			"user_addr=%#llx,bar_addr=%#llx,size=%#lx", dst, src, size);
		cn_dev_pcie_err(pcie_set, "copy_to_user failed!");
		return -EFAULT;
	}
#else
	unsigned char buff[256];

	while (size) {
		size_t num = size;

		if (num > sizeof(buff))
			num = sizeof(buff);
		memcpy_fromio((void *)buff, (void __iomem *)src, num);
		if (copy_to_user((void __user *)dst, (void *)buff, num)) {
			cn_dev_pcie_err(pcie_set, "copy_to_user failed!");
			return -EFAULT;
		}
		size -= num;
		dst += num;
		src += num;
	}
#endif
	return 0;
}

/*
 * adapt for FT1500(arm64)
 *
 * FT1500(arm64): memcpy and direct structure assignment are implemented
 * by ldp/stp instruction which don't support nocache address,
 * so we need to convert nocache address to cacheable.
 *
 */
static int cn_pci_copy_from_usr_toio(u64 dst, u64 src, size_t size, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

#if defined(__x86_64__)
	if (copy_from_user((void *)dst, (void __user *)src, size)) {
		cn_dev_pcie_err(pcie_set,
				"bar_addr=%#llx,user_addr=%#llx,size=%#lx",
				dst, src, size);
		cn_dev_pcie_err(pcie_set, "copy_from_user failed!");
		return -EFAULT;
	}
#else
	unsigned char buff[256];

	while (size) {
		size_t num = size;

		if (num > sizeof(buff))
			num = sizeof(buff);
		if (copy_from_user((void *)buff, (void __user *)src, num)) {
			cn_dev_pcie_err(pcie_set, "copy_from_user failed!");
			return -EFAULT;
		}
		memcpy_toio((void __iomem *)dst, (void *)buff, num);
		size -= num;
		dst += num;
		src += num;
	}
#endif
	return 0;
}

static int cn_pci_memcpy_fromio(u64 dst, u64 src, size_t size, void *pcie_priv)
{
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	/* NOTE: bar ioremap_wc mode and memcpy_fromio happened RC_aer error
	 * FIX : use ioread8 instead of memcpy_fromio
	 */
	for (i = 0; i < size; i++, src++)
		((unsigned char *)dst)[i] = ioread8((void __iomem *)src);
	cn_dev_pcie_debug(pcie_set, "memcpy_fromio success");

	return 0;
}

static int cn_pci_memcpy_toio(u64 dst, u64 src, size_t size, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	memcpy_toio((void __iomem *)dst, (void *)src, size);
	cn_dev_pcie_debug(pcie_set, "memcpy_toio success");

	return 0;
}

static int cn_pci_memsetD8_copy(u64 dst, u64 val, size_t size, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	unsigned char num = val;

	memset_io((void *)dst, num, size);
	cn_dev_pcie_debug(pcie_set, "memset_io success");

	return 0;
}

static int cn_pci_memsetD16_copy(u64 dst, u64 val, size_t buf_len, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	unsigned int num = val;
	unsigned long size = buf_len/2;

	while (size) {
		iowrite16(num, (void *)dst);
		dst += 2;
		size--;
	}

	cn_dev_pcie_debug(pcie_set, "memset16_io success");

	return 0;
}

static int cn_pci_memsetD32_copy(u64 dst, u64 val, size_t buf_len, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	unsigned int num = val;
	unsigned long size = buf_len/4;

	while (size) {
		iowrite32(num, (void *)dst);
		dst += 4;
		size--;
	}

	cn_dev_pcie_debug(pcie_set, "memset32_io success");

	return 0;
}

static int cn_pci_bar_copy_to_usr_fromio(unsigned long host_addr, u64 device_addr,
				size_t count, enum BAR_BLOCK_TYPE block_type,
				void *dma_task, struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar = NULL;
	u64 len;
	u64 bar_base;
	u64 remain = count;
	u64 dev_addr = device_addr;
	void *data = (void *)host_addr;
	struct pcie_dma_task *task = (struct pcie_dma_task *)dma_task;
	int ret = -1;

	if (remain == 0)
		return 0;

	bar = pcie_get_bar(block_type, pcie_set);
	if (!bar)
		return ret;

	if (cn_pci_bar_mig_bypass(bar, task, pcie_set, 1))
		goto FREE_BAR;

	BAR_READ_FROMIO_FUNC(copy_to_usr_fromio, u64, data);

	ret |= cn_pci_bar_mig_bypass(bar, task, pcie_set, 0);
FREE_BAR:
	pcie_put_bar(bar, pcie_set);

	return ret;
}

static int cn_pci_bar_copy_from_usr_toio(unsigned long host_addr, u64 device_addr,
				size_t count, enum BAR_BLOCK_TYPE block_type,
				void *dma_task, struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar = NULL;
	u64 len;
	u64 bar_base;
	u64 remain = count;
	u64 dev_addr = device_addr;
	void *data = (void *)host_addr;
	struct pcie_dma_task *task = (struct pcie_dma_task *)dma_task;
	int ret = -1;

	if (remain == 0)
		return 0;

	bar = pcie_get_bar(block_type, pcie_set);
	if (!bar)
		return -1;

	if (cn_pci_bar_inbound_restrict_down(block_type, bar, pcie_set))
		goto FREE_BAR;

	if (cn_pci_bar_mig_bypass(bar, task, pcie_set, 1))
		goto FREE_INBOUND;

	BAR_WRITE_TOIO_FUNC(copy_from_usr_toio, u64, data);

	ret |= cn_pci_bar_mig_bypass(bar, task, pcie_set, 0);
FREE_INBOUND:
	cn_pci_bar_inbound_restrict_up(pcie_set);
FREE_BAR:
	pcie_put_bar(bar, pcie_set);

	return ret;
}

static int cn_pci_p2p_memcpy_toio(unsigned long host_addr, u64 device_addr,
			size_t count, void *dma_task, struct cn_pcie_set *pcie_set)
{
	u64 len;
	u64 bar_base;
	u64 remain = count;
	u64 dev_addr = device_addr;
	void *data = (void *)host_addr;
	struct pcie_dma_task *task = (struct pcie_dma_task *)dma_task;
	int ret;
	struct bar_resource *bar = task->p2p_dst_bar;

	if (remain == 0)
		return 0;

	if (cn_pci_bar_inbound_restrict_down(BLOCK, bar, pcie_set))
		return 0;

	BAR_WRITE_TOIO_FUNC(memcpy_toio, u64, data);

	cn_pci_bar_inbound_restrict_up(pcie_set);

	return 0;
}

static int cn_pci_bar_memcpy_fromio(unsigned long host_addr, u64 device_addr,
				size_t count, enum BAR_BLOCK_TYPE block_type,
				void *dma_task, struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar = NULL;
	u64 len;
	u64 bar_base;
	u64 remain = count;
	u64 dev_addr = device_addr;
	void *data = (void *)host_addr;
	struct pcie_dma_task *task = (struct pcie_dma_task *)dma_task;
	int ret = -1;

	if (remain == 0)
		return 0;

	bar = pcie_get_bar(block_type, pcie_set);
	if (!bar)
		return ret;

	if (cn_pci_bar_mig_bypass(bar, task, pcie_set, 1))
		goto FREE_BAR;

	BAR_READ_FROMIO_FUNC(memcpy_fromio, u64, data);

	ret |= cn_pci_bar_mig_bypass(bar, task, pcie_set, 0);
FREE_BAR:
	pcie_put_bar(bar, pcie_set);

	return ret;
}

static int cn_pci_bar_memcpy_toio(unsigned long host_addr, u64 device_addr,
				size_t count, enum BAR_BLOCK_TYPE block_type,
				void *dma_task, struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar = NULL;
	u64 len;
	u64 bar_base;
	u64 remain = count;
	u64 dev_addr = device_addr;
	void *data = (void *)host_addr;
	struct pcie_dma_task *task = (struct pcie_dma_task *)dma_task;
	int ret = -1;

	if (!remain)
		return 0;

	bar = pcie_get_bar(block_type, pcie_set);
	if (!bar)
		return -1;

	if (cn_pci_bar_inbound_restrict_down(block_type, bar, pcie_set))
		goto FREE_BAR;

	if (cn_pci_bar_mig_bypass(bar, task, pcie_set, 1))
		goto FREE_INBOUND;

	BAR_WRITE_TOIO_FUNC(memcpy_toio, u64, data);

	ret |= cn_pci_bar_mig_bypass(bar, task, pcie_set, 0);
FREE_INBOUND:
	cn_pci_bar_inbound_restrict_up(pcie_set);
FREE_BAR:
	pcie_put_bar(bar, pcie_set);

	return ret;
}

#define PCI_MEMSET_KBUF(name, type, per_size) \
static void cn_pci_memset##name##_kbuf(unsigned long kbuf_addr, type val, \
			unsigned int buf_size) \
{ \
	unsigned long addr = kbuf_addr; \
	unsigned int len = buf_size / per_size; \
	while (len) { \
		*((type *)addr) = val; \
		addr += per_size; \
		--len; \
	} \
} \
/* the memset export symbol:
 * cn_pci_memsetD8_kbuf
 * cn_pci_memsetd16_kbuf
 * cn_pci_memsetd32kbuf
 */
PCI_MEMSET_KBUF(D8, unsigned char, 1)
PCI_MEMSET_KBUF(D16, unsigned short, 2)
PCI_MEMSET_KBUF(D32, unsigned int, 4)

static int cn_pci_prepare_kernel_buffer(struct transfer_s *tf, u64 size)
{
	char *buf;
	int buf_len = 0;
	int cnt = 0;
	int order = get_order(min_t(u64, size, 0x100000));

retry:
	if (cnt > 2 || order < 0)
		goto exit;

	buf = (void *)cn_get_free_pages(GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY, order);
	if (!buf) {
		--order;
		++cnt;
		goto retry;
	}

	tf->ca = (unsigned long) buf;
	buf_len = PAGE_SIZE * (1 << order);

	return buf_len;

exit:
	cn_dev_debug("alloc kernel buffer failed, use bar do memset");
	return -1;
}

static int cn_pci_dma_do_memset(struct cn_pcie_set *pcie_set, u64 dev_addr,
		int val, u64 *remain, int per_size)
{
	struct pcie_dma_task *task;
	struct transfer_s tf;
	int buf_len;

	if (!*remain)
		return 0;

	memset(&tf, 0, sizeof(tf));
	tf.direction = DMA_H2D;

	buf_len = cn_pci_prepare_kernel_buffer(&tf, *remain);
	if (buf_len < 0)
		return 0;

	if (per_size == 1) {
		cn_pci_memsetD8_kbuf(tf.ca, val, buf_len);
	} else if (per_size == 2) {
		cn_pci_memsetD16_kbuf(tf.ca, val, buf_len);
	} else {
		cn_pci_memsetD32_kbuf(tf.ca, val, buf_len);
	}

	task = cn_pci_get_dma_idle_task(pcie_set, tf.direction);
	if (!task)
		return -1;
	while (*remain > 0) {
		tf.ia = dev_addr;
		tf.size = min_t(u64, *remain, buf_len);

		if (cn_pci_init_dma_task(task, &tf, PCIE_DMA_MEMSET, pcie_set))
			break;

		if (cn_pci_dma_transfer(task)) {
			cn_dev_pcie_err(pcie_set, "dma transfer err");
			cn_pci_put_dma_idle_task(pcie_set, task);
			cn_free_pages(tf.ca, get_order(buf_len));
			return -1;
		}

		dev_addr += tf.size;
		*remain -= tf.size;
	}
	cn_pci_put_dma_idle_task(pcie_set, task);

	cn_free_pages(tf.ca, get_order(buf_len));

	return 0;
}

static int cn_pci_dma_memsetD8(u64 device_addr, unsigned char number,
		unsigned long size, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct bar_resource *bar = NULL;
	u64 len;
	u64 bar_base;
	u64 remain = size;
	u64 dev_addr = device_addr;
	u64 data = 0ULL; /* only indicate memset count */
	enum BAR_BLOCK_TYPE block_type = BLOCK;
	int ret = -1;

	if (remain >= pcie_set->dma_memsetD8_custom_size) {
		if (cn_pci_dma_do_memset(pcie_set, dev_addr, number, &remain,
					sizeof(number)))
			return -1;
	}

	if (!remain)
		return 0;

	bar = pcie_get_bar(block_type, pcie_set);
	if (!bar)
		return -1;

	if (cn_pci_bar_inbound_restrict_down(block_type, bar, pcie_set))
		goto FREE_BAR;

	BAR_WRITE_TOIO_FUNC(memsetD8_copy, unsigned char, number);

	cn_pci_bar_inbound_restrict_up(pcie_set);
FREE_BAR:
	pcie_put_bar(bar, pcie_set);

	return ret;
}

static int cn_pci_dma_memsetD16(u64 device_addr, unsigned short us,
		unsigned long size, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct bar_resource *bar = NULL;
	u64 len;
	u64 bar_base;
	u64 remain = size*2;
	u64 dev_addr = device_addr;
	u64 data = 0ULL; /* only indicate memset count */
	enum BAR_BLOCK_TYPE block_type = BLOCK;
	int ret = -1;

	if (remain >= pcie_set->dma_memsetD16_custom_size) {
		if (cn_pci_dma_do_memset(pcie_set, dev_addr, us, &remain,
					sizeof(us)))
			return -1;
	}

	if (!remain)
		return 0;

	bar = pcie_get_bar(block_type, pcie_set);
	if (!bar)
		return -1;

	if (cn_pci_bar_inbound_restrict_down(block_type, bar, pcie_set))
		goto FREE_BAR;

	BAR_WRITE_TOIO_FUNC(memsetD16_copy, unsigned short, us);

	cn_pci_bar_inbound_restrict_up(pcie_set);
FREE_BAR:
	pcie_put_bar(bar, pcie_set);

	return ret;
}

static int cn_pci_dma_memsetD32(u64 device_addr, unsigned int ui,
		unsigned long size, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct bar_resource *bar = NULL;
	u64 len;
	u64 bar_base;
	u64 remain = size*4;
	u64 dev_addr = device_addr;
	u64 data = 0ULL; /* only indicate memset count */
	enum BAR_BLOCK_TYPE block_type = BLOCK;
	int ret = -1;

	if (remain >= pcie_set->dma_memsetD32_custom_size) {
		if (cn_pci_dma_do_memset(pcie_set, dev_addr, ui, &remain,
					sizeof(ui)))
			return -1;
	}

	if (!remain)
		return 0;

	bar = pcie_get_bar(block_type, pcie_set);
	if (!bar)
		return -1;

	if (cn_pci_bar_inbound_restrict_down(block_type, bar, pcie_set))
		goto FREE_BAR;

	BAR_WRITE_TOIO_FUNC(memsetD32_copy, unsigned int, ui);

	cn_pci_bar_inbound_restrict_up(pcie_set);
FREE_BAR:
	pcie_put_bar(bar, pcie_set);

	return ret;
}

static int cn_pci_bar_copy_data(struct pcie_dma_task *task)
{
	struct cn_pcie_set *pcie_set;
	int i, ret = 0;
	struct non_align_s *p;
	DMA_DIR_TYPE direction = task->transfer->direction;
	struct page **pages;
	int page_cnt;
	size_t t_len;
	int j;
	unsigned long page_offset, page_vaddr;
	struct pinned_mem_va *mem_uva;
	unsigned long cpu_addr, kaddr, pinned_addr;

	if (!task->non_align_flag)
		return 0;

	pcie_set = task->pcie_set;
	if (!pcie_set) {
		cn_dev_err("pcie_set is NULL");
		return -1;
	}

	for (i = 0; i < 2; i++) {
		p = &task->non_align[i];
		if (!p->cnt)
			continue;

		if (task->dma_type == PCIE_DMA_USER) {
			cpu_addr = p->ca;
			page_offset = cpu_addr & (~PAGE_MASK);

			pages = cn_pci_dma_get_user_pages(cpu_addr, p->cnt,
								&page_cnt, task);
			if (!pages) {
				cn_dev_pcie_err(pcie_set,
					"user addr%#lx is error", cpu_addr);
				return -1;
			}
			for (j = 0; j < page_cnt; j++) {
				page_vaddr = (unsigned long)page_address(pages[j]);
				if (!page_vaddr) {
					cn_pci_dma_put_user_pages(pages, page_cnt);
					return -1;
				}
				if (j == 0) {
					kaddr = page_vaddr + page_offset;
					t_len = PAGE_SIZE - page_offset;
					t_len = min(t_len, p->cnt);
				} else {
					kaddr = page_vaddr;
					t_len = min(PAGE_SIZE, p->cnt);
				}
				if (direction == DMA_H2D) {
					ret |= cn_pci_bar_memcpy_toio((u64)kaddr, p->ia,
						t_len, BLOCK, task, pcie_set);
				} else if (direction == DMA_D2H) {
					ret |= cn_pci_bar_memcpy_fromio((u64)kaddr, p->ia,
						t_len, BLOCK, task, pcie_set);
				}
				p->ia += t_len;
				p->cnt -= t_len;
			}
			cn_pci_dma_put_user_pages(pages, page_cnt);
		} else if (task->dma_type == PCIE_DMA_PINNED_MEM) {
			pinned_addr = p->ca;
			if (task->dma_async) {
				if (i == 0)
					kaddr = task->kvaddr;
				else
					kaddr = task->kvaddr_align;
			} else {
				mem_uva = cn_pinned_mem_check(task->tsk, pinned_addr, p->cnt);
				if (!mem_uva) {
					cn_dev_pcie_err(pcie_set,
						"mem 0x%lx not exsit in pinned mem table",
						pinned_addr);
					return -1;
				}
				kaddr = mem_uva->pst_blk->kva_start;
				page_offset = pinned_addr - mem_uva->va_start;
				kaddr += page_offset;
			}
			if (direction == DMA_H2D) {
				ret |= cn_pci_bar_memcpy_toio((u64)kaddr, p->ia,
						p->cnt, BLOCK, task, pcie_set);
			} else if (direction == DMA_D2H) {
				ret |= cn_pci_bar_memcpy_fromio((u64)kaddr, p->ia,
						p->cnt, BLOCK, task, pcie_set);
			}
		} else if (task->dma_type == PCIE_DMA_P2P) {
			char *buffer = cn_kzalloc(p->cnt, GFP_KERNEL);

			if (buffer == NULL)
				return -1;

			kaddr = (unsigned long)cn_ioremap(p->ca, p->cnt);
			if (!kaddr) {
				cn_kfree(buffer);
				return -1;
			}
			ret = cn_pci_memcpy_toio((u64)buffer, (u64)kaddr, p->cnt, task->pcie_set_dst);
			cn_iounmap((void *)kaddr);
			if (!ret) {
				ret |= cn_pci_p2p_memcpy_toio((u64)buffer, p->ia,
						p->cnt, task, pcie_set);
				cn_kfree(buffer);
			} else {
				cn_kfree(buffer);
				cn_dev_pcie_err(pcie_set, "p2p bar copy failed");
				return -1;
			}
		} else if (task->dma_type == PCIE_DMA_MEMSET) {
			ret |= cn_pci_bar_memcpy_toio(p->ca, p->ia, p->cnt, BLOCK, task, pcie_set);
		} else if (task->dma_type == PCIE_DMA_KERNEL) {
			kaddr = p->ca;
			if (direction == DMA_H2D) {
				ret |= cn_pci_bar_memcpy_toio((u64)kaddr, p->ia,
						p->cnt, BLOCK, task, pcie_set);
			} else if (direction == DMA_D2H) {
				ret |= cn_pci_bar_memcpy_fromio((u64)kaddr, p->ia,
						p->cnt, BLOCK, task, pcie_set);
			}
		}
	}
	task->non_align_flag = 0;

	return ret;
}

static int cn_pci_dma_bar_write(struct pcie_dma_task *task)
{
	struct cn_pcie_set *pcie_set;
	int ret = 0;
	u64 d_addr = task->transfer->ia;
	u64 h_addr = task->transfer->ca;
	size_t len = task->transfer->size;
	int i;
	DMA_DIR_TYPE direction = task->transfer->direction;
	struct page **user_pages = NULL;
	struct pinned_mem *mem_blk;
	unsigned long page_offset;
	size_t count;
	int page_cnt;
	u64 page_vaddr;

	pcie_set = task->pcie_set;

	if ((task->dma_type != PCIE_DMA_USER &&
			task->dma_type != PCIE_DMA_KERNEL &&
			task->dma_type != PCIE_DMA_PINNED_MEM) ||
			(direction != DMA_H2D)) {
		cn_dev_pcie_err(pcie_set, "dma_type:%d, direction:%d",
					task->dma_type, direction);
		return -1;
	}
	if (task->dma_async) {
		if (task->dma_type == PCIE_DMA_USER) {
			page_offset = h_addr & (~PAGE_MASK);
			user_pages = cn_pci_dma_get_user_pages(h_addr, len,
								&page_cnt, task);
			if (!user_pages) {
				cn_dev_pcie_err(pcie_set,
					"user addr %#llx is error", h_addr);
				return -1;
			}
			for (i = 0; i < page_cnt; i++) {
				page_vaddr = (u64)page_address(user_pages[i]);
				if (!page_vaddr) {
					cn_pci_dma_put_user_pages(user_pages, page_cnt);
					return -1;
				}
				if (i == 0) {
					h_addr = page_vaddr + page_offset;
					count = PAGE_SIZE - page_offset;
					count = min(count, len);
				} else {
					h_addr = page_vaddr;
					count = min(PAGE_SIZE, len);
				}
				ret |= cn_pci_bar_memcpy_toio(h_addr, d_addr, count,
							NOBLOCK, task, pcie_set);
				d_addr += count;
				len -= count;
			}
			cn_pci_dma_put_user_pages(user_pages, page_cnt);
		} else {
			mem_blk = cn_async_pinned_mem_check(task->kvaddr);
			if (!mem_blk) {
				cn_dev_pcie_err(pcie_set,
					"mem 0x%lx len=0x%lxnot exsit in pinned mem table",
					task->kvaddr, len);
				return -1;
			}
			ret = cn_pci_bar_memcpy_toio(task->kvaddr, d_addr, len,
						NOBLOCK, task, pcie_set);
		}

		return ret;
	}

	if (task->dma_type == PCIE_DMA_USER ||
				task->dma_type == PCIE_DMA_PINNED_MEM) {
		ret = cn_pci_bar_copy_from_usr_toio(h_addr, d_addr,
						len, NOBLOCK, task, pcie_set);
	} else
		ret = cn_pci_bar_memcpy_toio(h_addr, d_addr, len, NOBLOCK,
						task, pcie_set);

	return ret;
}

static size_t cn_pci_boot_image(unsigned long host_addr, u64 device_addr,
						size_t count, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (cn_pci_bar_memcpy_toio(host_addr, device_addr,
					count, BLOCK, NULL, pcie_set)) {
		cn_dev_pcie_err(pcie_set, "boot image failed");
		return -1;
	}

	return 0;
}

static size_t cn_pci_check_image(unsigned char *host_data, u64 device_addr,
						size_t count, void *pcie_priv)
{
	int ret = -1;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	unsigned char *check_buf = NULL;

	check_buf = cn_vzalloc(count);
	if (!check_buf) {
		cn_dev_pcie_err(pcie_set, "buff vzalloc failed");
		goto ERR_RET;
	}

	ret = cn_pci_bar_memcpy_fromio((unsigned long)check_buf, device_addr,
						count, BLOCK, NULL, pcie_set);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "bar_memcpy_fromio error");
		goto ERR_RET;
	}

	ret = strncmp(host_data, check_buf, count);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "data check failed!");
		goto ERR_RET;
	}

ERR_RET:
	if (check_buf)
		cn_vfree(check_buf);

	return ret;
}

static int pci_dma_memset(void *pcie_priv, struct memset_s *t)
{
	int ret = 0;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (!pcie_set) {
		cn_dev_err("cn pcie set is null!");
		return -EINVAL;
	}
	if (!t) {
		cn_dev_pcie_err(pcie_set, "stransfer is null!");
		return -EINVAL;
	}

	if (t->direction == MEMSET_D8) {
		ret = cn_pci_dma_memsetD8(t->dev_addr, t->val, t->number, pcie_set);
	} else if (t->direction == MEMSET_D16) {
		ret = cn_pci_dma_memsetD16(t->dev_addr, t->val, t->number, pcie_set);
	} else if (t->direction == MEMSET_D32) {
		ret = cn_pci_dma_memsetD32(t->dev_addr, t->val, t->number, pcie_set);
	} else {
		cn_dev_pcie_err(pcie_set, "direction is invalid!");
		ret = -EINVAL;
	}

	return ret;
}
