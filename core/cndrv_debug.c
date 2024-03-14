/*
 * core/cndrv_debug.c
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
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
 */

#include <linux/version.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include "cndrv_os_compat.h"
#include "cndrv_debug.h"

int dma_bypass_custom_size = 0;
module_param(dma_bypass_custom_size, int, S_IRUGO | S_IWUSR | S_IWGRP);

int d2h_bypass_custom_size;
module_param(d2h_bypass_custom_size, int, S_IRUGO | S_IWUSR | S_IWGRP);

int dma_align_size;
module_param(dma_align_size, int, 0444);

int dma_fetch_enable = 1;
module_param(dma_fetch_enable, int, 0444);

int dma_af_enable = 1;
module_param(dma_af_enable, int, 0444);

int arm_trigger_enable = 1;
module_param(arm_trigger_enable, int, 0444);

int dma_hmsc_enable;
module_param(dma_hmsc_enable, int, 0444);

int dma_bypass_pinned_size;
int dma_memsetD8_custom_size;
int dma_memsetD16_custom_size;
int dma_memsetD32_custom_size;

module_param(dma_bypass_pinned_size, int, 0444);
module_param(dma_memsetD8_custom_size, int, 0444);
module_param(dma_memsetD16_custom_size, int, 0444);
module_param(dma_memsetD32_custom_size, int, 0444);

int dma_secondary_copy = -1;
module_param(dma_secondary_copy, int, 0444);
MODULE_PARM_DESC(dma_secondary_copy,
	"Set the dma secondary copy flag, default is not to do secondary copy");

char *inject_error = NULL;
module_param(inject_error, charp, 0444);
MODULE_PARM_DESC(inject_error, "Inject error to specific PCIe device(s), input BDF number(s) separated by commas");

#define MAX_INJECT_DEVICE_COUNT	(8)
int cn_inject_error_init(struct cn_core_set *core)
{
	u32 bdf[MAX_INJECT_DEVICE_COUNT];
	u16 bus, dev, fn;
	int i, idx = 0;
	char *bdf_str, *tmp;

	if (!inject_error)
		return 0;

	bdf_str = kstrdup(inject_error, GFP_KERNEL);
	if (!bdf_str) {
		cn_dev_core_warn(core, "inject error: failed to allocate memory");
		return 0;
	}

	tmp = bdf_str; /* following loop will change addr of bdf_str, record for kfree */
	while (bdf_str) {
		char *comma = strchr(bdf_str, ',');
		if (comma)
			*comma = '\0';

		if (sscanf(bdf_str, "%hx:%hx.%hx", &bus, &dev, &fn) != 3) {
			cn_dev_core_warn(core, "inject error: invalid BDF number %s", bdf_str);
			kfree(tmp);
			return 0;
		}

		// record inject device bdf
		bdf[idx] = bus << 8 | dev << 3 | fn;

		idx++;
		if (idx >= MAX_INJECT_DEVICE_COUNT) {
			cn_dev_core_warn(core, "exceed max inject device count %d",
					MAX_INJECT_DEVICE_COUNT);
			break;
		}

		bdf_str = comma ? comma + 1 : NULL;
	}

	// inject error to specific bdf
	for (i = 0; i < idx; i++) {
		if (cn_bus_get_bdf(core->bus_set) == bdf[i]) {
			cn_dev_core_err(core, "inject error success for Card%d, bdf: %02hx:%02hx.%hx",
				core->idx, (bdf[i] >> 8) & 0xff, (bdf[i] >> 3) & 0x1f, bdf[i] & 0x7);
			kfree(tmp);
			return -1;
		}
	}

	kfree(tmp);
	return 0;
}

void cn_inject_error_exit(struct cn_core_set *core)
{
	return;
}

/***
 * TCDP ignore iommu state and Just use bar2-bus-addr
 * NOTE:
 *	It shall work with ACS CTL OFF.
 */
int tcdp_ignore_iommu = 1;
module_param(tcdp_ignore_iommu, int, 0444);
MODULE_PARM_DESC(tcdp_ignore_iommu,
	"Set the tcdp ignore iommu just use bar2-bus-addr, dft 1");
/***
 * TCDP enable state and the top half of bar2 will be used as
 * win-normal + win-mdr * 7(at most)
 * if this set as 0, means all be used as normal win.
 */
int tcdp_mdr_win_cnt = 0;
module_param(tcdp_mdr_win_cnt, int, 0444);
MODULE_PARM_DESC(tcdp_mdr_win_cnt,
	"Set number of mdr win in bar2 top half, dft 0, spt 0/1/3/7");

int print_debug;
struct print_debug_info_s print_debug_info[] = {
	{"dev_dbg", 0x01},
	{"dev_core_dbg", 0x02},
	{"dev_pcie_dbg", 0x08},
	{"dev_edge_dbg", 0x10},
	{"dev_i2c_dbg", 0x20},
	{"dev_monitor_dbg", 0x40},
	{"dev_proc_dbg", 0x80},
	{"dev_domain_dbg", 0x100},
	{NULL, 0xFFFF},
};
#ifdef CN_KMEM_LEAK_DEBUG
DEFINE_SPINLOCK(kmem_leak_lock);
LIST_HEAD(kmem_list_head);

struct kmem_t {
	struct list_head list;
	const char *func;
	unsigned int line;
	void *addr;
};

#define insert_kmem_info(new, func, line) \
({ \
	struct kmem_t *entry = \
		kzalloc(sizeof(*entry), GFP_ATOMIC); \
\
	entry->func = func; \
	entry->line = line; \
	entry->addr = new; \
\
	spin_lock(&kmem_leak_lock); \
	list_add(&entry->list, &kmem_list_head); \
	spin_unlock(&kmem_leak_lock); \
})

#define delete_kmem_info(addr) \
({ \
	int flag = 0; \
	struct kmem_t *entry, *tmp; \
\
	spin_lock(&kmem_leak_lock); \
	list_for_each_entry_safe(entry, tmp, &kmem_list_head, list) { \
		if (addr == entry->addr) { \
			flag = 1; \
			list_del(&entry->list); \
			break; \
		} \
	} \
	spin_unlock(&kmem_leak_lock); \
	if (flag) { \
		kfree(entry); \
	} else { \
		pr_err("free a illegal kernel addr:%px\n", addr); \
		dump_stack(); \
		entry = NULL; \
	} \
	entry; \
})

/*
 * kmalloc/kzalloc/free
 */
void *__cn_kzalloc(size_t size, gfp_t flags,
		const char *func, const unsigned int line)
{
	void *new = kzalloc(size, flags);

	if (new == NULL)
		return new;

	insert_kmem_info(new, func, line);
	return new;
}

void *__cn_kmalloc(size_t size, gfp_t flags,
		const char *func, const unsigned int line)
{
	void *new = kmalloc(size, flags);

	if (new == NULL)
		return new;
	insert_kmem_info(new, func, line);
	return new;
}

void __cn_kfree(const void *addr)
{
	struct kmem_t *entry;

	if (unlikely(ZERO_OR_NULL_PTR(addr)))
		return;

	entry = delete_kmem_info(addr);
	if (entry)
		kfree(addr);
}

/*
 * __get_free_pages/free_pages
 */
void *__cn_get_free_pages(gfp_t flags, unsigned int order,
		const char *func, const unsigned int line)
{
	void *new = (void *)__get_free_pages(flags, order);

	if (new == NULL)
		return new;
	insert_kmem_info(new, func, line);
	return new;
}

void __cn_free_pages(unsigned long address, unsigned int order)
{
	void *addr = (void *)address;

	struct kmem_t *entry = delete_kmem_info(addr);

	if (entry)
		free_pages(address, order);
}

/*
 * ioremap/ioremap_wc/iounmap
 */
void __iomem *__cn_ioremap(phys_addr_t base, size_t size,
		const char *func, const unsigned int line)
{
#if defined(__x86_64__)
	void *new = ioremap(base, size);
#else
	void *new = ioremap_nocache(base, size);
#endif

	if (new == NULL)
		return new;
	insert_kmem_info(new, func, line);
	return new;
}

void __iomem *__cn_ioremap_wc(phys_addr_t base, size_t size,
		const char *func, const unsigned int line)
{
#if defined(__x86_64__)
	void *new = ioremap_wc(base, size);
#else
	void *new = ioremap_nocache(base, size);
#endif

	if (new == NULL)
		return new;
	insert_kmem_info(new, func, line);
	return new;
}

void __cn_iounmap(void *addr)
{
	struct kmem_t *entry  = delete_kmem_info(addr);

	if (entry)
		iounmap(addr);
}

/*
 * vmalloc/vfree
 */
void *__cn_vmalloc(size_t size, const char *func, const unsigned int line)
{
	void *new = vmalloc(size);

	if (new == NULL)
		return new;
	insert_kmem_info(new, func, line);
	return new;
}

void *__cn_vzalloc(size_t size, const char *func, const unsigned int line)
{
	void *new = vzalloc(size);

	if (new == NULL)
		return new;
	insert_kmem_info(new, func, line);
	return new;
}

void *__cn_kcalloc(size_t num, size_t size, gfp_t flags,
		const char *func, const unsigned int line)
{
	void *new = kcalloc(num, size, flags);

	if (new == NULL)
		return new;
	insert_kmem_info(new, func, line);
	return new;
}

void *__cn_kzalloc_node(size_t size, gfp_t flags, int node,
		const char *func, const unsigned int line)
{
	void *new = kzalloc_node(size, flags, node);

	if (new == NULL)
		return new;
	insert_kmem_info(new, func, line);
	return new;
}

void *__cn_kmalloc_node(size_t size, gfp_t flags, int node,
		const char *func, const unsigned int line)
{
	void *new = kmalloc_node(size, flags, node);

	if (new == NULL)
		return new;
	insert_kmem_info(new, func, line);
	return new;
}

void __cn_vfree(const void *addr)
{
	struct kmem_t *entry = delete_kmem_info(addr);

	if (entry)
		vfree(addr);
}

void cn_show_kmem_leak(void)
{
	struct kmem_t *entry, *tmp;

	if (list_empty(&kmem_list_head)) {
		pr_info("no kmem leak\n");
		return;
	}

	spin_lock(&kmem_leak_lock);
	list_for_each_entry_safe(entry, tmp, &kmem_list_head, list) {
		pr_err("[kmem leak] func:%s, line:%d, addr:%px !!!\n",
			entry->func, entry->line, entry->addr);
	}
	spin_unlock(&kmem_leak_lock);
}


#endif
