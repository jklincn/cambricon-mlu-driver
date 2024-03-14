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
#ifndef __CNDRV_DEBUG_H__
#define __CNDRV_DEBUG_H__

#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include "cndrv_core.h"
#include "cndrv_pre_compile.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif

/* The selection and information about cndrv debug control */
enum print_debug_sel {
	DEV_DBG = 0,
	DEV_CORE_DBG,
	DEV_PCIE_DBG,
	DEV_EDGE_DBG,
	DEV_I2C_DBG,
	DEV_MONITOR_DBG,
	DEV_PROC_DBG,
	DEV_DOMAIN_DBG,
};

struct print_debug_info_s {
	char *name;
	int bit_mask;
};

extern struct print_debug_info_s print_debug_info[];

//#define CN_KMEM_LEAK_DEBUG
#ifdef CN_KMEM_LEAK_DEBUG
extern void *__cn_kzalloc(size_t size, gfp_t flags,
	const char *func, const unsigned int line);
extern void *__cn_kmalloc(size_t size, gfp_t flags,
	const char *func, const unsigned int line);
extern void *__cn_vmalloc(size_t size,
	const char *func, const unsigned int line);
extern void *__cn_vzalloc(size_t size,
	const char *func, const unsigned int line);
extern void *__cn_kcalloc(size_t num, size_t size, gfp_t flags,
	const char *func, const unsigned int line);
extern void *__cn_kzalloc_node(size_t size, gfp_t flags, int node,
	const char *func, const unsigned int line);
extern void *__cn_kmalloc_node(size_t size, gfp_t flags, int node,
	const char *func, const unsigned int line);
extern void *__cn_get_free_pages(gfp_t flags, unsigned int order,
	const char *func, const unsigned int line);

extern void __cn_kfree(const void *addr);
extern void __cn_vfree(const void *addr);
extern void __cn_free_pages(unsigned long address, unsigned int order);

extern void __iomem *__cn_ioremap(phys_addr_t base, size_t size,
		const char *func, const unsigned int line);
extern void __iomem *__cn_ioremap_wc(phys_addr_t base, size_t size,
		const char *func, const unsigned int line);
extern void __cn_iounmap(void *addr);

extern void cn_show_kmem_leak(void);

#define cn_kmalloc(size, flags) \
	__cn_kmalloc(size, flags, __func__, __LINE__)
#define cn_kzalloc(size, flags) \
	__cn_kzalloc(size, flags, __func__, __LINE__)
#define cn_vmalloc(size) \
	__cn_vmalloc(size, __func__, __LINE__)
#define cn_vzalloc(size) \
	__cn_vzalloc(size, __func__, __LINE__)
#define cn_kcalloc(num, size, flags) \
	__cn_kcalloc(num, size, flags, __func__, __LINE__)
#define cn_kzalloc_node(size, flags, node) \
	__cn_kzalloc_node(size, flags, node, __func__, __LINE__)
#define cn_kmalloc_node(size, flags, node) \
	__cn_kmalloc_node(size, flags, node, __func__, __LINE__)
#define cn_get_free_pages(flags, order) \
	__cn_get_free_pages(flags, order, __func__, __LINE__)

#define cn_kfree(objp) \
({ \
	__cn_kfree(objp); \
	objp = NULL; \
})
#define cn_vfree(objp) \
({ \
	__cn_vfree(objp); \
	objp = NULL; \
})
#define cn_free_pages __cn_free_pages
#define cn_ioremap(base, size) \
	__cn_ioremap(base, size, __func__, __LINE__)
#define cn_ioremap_wc(base, size) \
	__cn_ioremap_wc(base, size, __func__, __LINE__)
#define cn_iounmap __cn_iounmap
#else
#define cn_kmalloc kmalloc
#define cn_kzalloc kzalloc
#define cn_vmalloc vmalloc
#define cn_vzalloc vzalloc
#define cn_kcalloc kcalloc
#define cn_kzalloc_node kzalloc_node
#define cn_kmalloc_node kmalloc_node
#define cn_get_free_pages __get_free_pages
#define cn_kfree(objp) \
({ \
	kfree(objp); \
	objp = NULL; \
})
#define cn_vfree(objp) \
({ \
	vfree(objp); \
	objp = NULL; \
})
#define cn_free_pages free_pages
#define cn_ioremap ioremap

#if defined(__x86_64__)
#define cn_ioremap_wc ioremap_wc
#else
#define cn_ioremap_wc ioremap
#endif

#define cn_iounmap iounmap
#endif

static inline void *
cn_numa_aware_kmalloc(struct cn_core_set *core, size_t size, gfp_t flags)
{
	int node = cn_core_get_numa_node_by_core(core);

	if (node == -1) {
		return cn_kmalloc(size, flags);
	}

	return cn_kmalloc_node(size, flags, node);
}

static inline void *
cn_numa_aware_kzalloc(struct cn_core_set *core, size_t size, gfp_t flags)
{
	return cn_numa_aware_kmalloc(core, size, flags | __GFP_ZERO);
}

extern int dma_bypass_custom_size;
extern int d2h_bypass_custom_size;
extern int dma_bypass_pinned_size;
extern int dma_align_size;
extern int dma_fetch_enable;
extern int dma_af_enable;
extern int arm_trigger_enable;
extern int dma_hmsc_enable;
extern int dma_memsetD8_custom_size;
extern int dma_memsetD16_custom_size;
extern int dma_memsetD32_custom_size;
extern int dma_secondary_copy;
extern int data_outbound_enable;
extern int tcdp_ignore_iommu;
extern int tcdp_mdr_win_cnt;

/* used to simulate some cards probe failed */
extern char *inject_error;
int cn_inject_error_init(struct cn_core_set *core);
void cn_inject_error_exit(struct cn_core_set *core);

#define __print(fn, level, str, arg...) \
	fn("%s: [%s][%d][CPU %d]: " str "\n", \
		level, __func__, __LINE__, raw_smp_processor_id(), ##arg)

#define __ce_print(fn, level, str, arg...) \
	fn("%s: [%d][CPU %d]: " str "\n", \
		level, __LINE__, raw_smp_processor_id(), ##arg)

#define __core_print(fn, level, core, str, arg...) \
do { \
	if (core) \
		fn("%s: [%s][%s][%d][CPU %d]: " str "\n", \
			level, core->core_name, __func__, __LINE__, \
			raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, __func__, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define __core_ce_print(fn, level, core, str, arg...) \
do { \
	if (core) \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, core->core_name, __LINE__, \
			raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%d][CPU %d]: " str "\n", \
			level, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define __pcie_print(fn, level, pcie, str, arg...) \
do { \
	if (pcie) \
		fn("%s: [%s][%s][%d][CPU %d]: " str "\n", \
			level, pcie->core_name, __func__, \
			__LINE__, raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, __func__, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define __edge_print(fn, level, edge, str, arg...) \
do { \
	if (edge && edge->bus_set && edge->bus_set->core) \
		fn("%s: [%s][%s][%d][CPU %d]: " str "\n", \
			level, edge->bus_set->core->core_name, __func__, \
			__LINE__, raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, __func__, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define __i2c_print(fn, level, i2c, str, arg...) \
do { \
	if (i2c && i2c->core) \
		fn("%s: [%s][%s][%d][CPU %d]: " str "\n", \
			level, i2c->core->core_name, __func__, \
			__LINE__, raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, __func__, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define __monitor_print(fn, level, monitor, str, arg...) \
do { \
	if (monitor && monitor->core) \
		fn("%s: [%s][%s][%d][CPU %d]: " str "\n", \
			level, monitor->core->core_name, __func__, \
			__LINE__, raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, __func__, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define __monitor_ce_print(fn, level, monitor, str, arg...) \
do { \
	if (monitor && monitor->core) \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, monitor->core->core_name, \
			__LINE__, raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%d][CPU %d]: " str "\n", \
			level, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define __cndev_print(fn, level, cndev, str, arg...) \
do { \
	if (cndev && cndev->core) \
		fn("%s: [%s][%s][%d][CPU %d]: " str "\n", \
			level, cndev->core->core_name, __func__, \
			__LINE__, raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, __func__, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define __cndev_ce_print(fn, level, cndev, str, arg...) \
do { \
	if (cndev && cndev->core) \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, cndev->core->core_name, \
			__LINE__, raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%d][CPU %d]: " str "\n", \
			level, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define __proc_print(fn, level, proc, str, arg...) \
do { \
	if (proc) \
		fn("%s: [BusId%s][%s][%d][CPU %d]: " str "\n", \
			level, proc->dev_name, __func__, \
			__LINE__, raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, __func__, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define cn_dev_info(str, arg...) \
	__print(pr_info, "INFO", str, ##arg)
#define cn_dev_core_info(core, str, arg...) \
	__core_print(pr_info, "INFO", (core), str, ##arg)
#define cn_ce_dev_core_info(core, str, arg...) \
	__core_ce_print(pr_info, "INFO", (core), str, ##arg)
#define cn_dev_pcie_info(pcie, str, arg...) \
	__pcie_print(pr_info, "INFO", (pcie), str, ##arg)
#define cn_dev_i2c_info(i2c, str, arg...) \
	__i2c_print(pr_info, "INFO", (i2c), str, ##arg)
#define cn_dev_cndev_info(cndev, str, arg...) \
	__cndev_print(pr_info, "INFO", (cndev), str, ##arg)
#define cn_ce_dev_cndev_info(cndev, str, arg...) \
	__cndev_ce_print(pr_info, "INFO", (cndev), str, ##arg)
#define cn_dev_monitor_info(monitor, str, arg...) \
	__monitor_print(pr_info, "INFO", (monitor), str, ##arg)

#define cn_dev_warn(str, arg...) \
	__print(pr_warn, "WARNING", str, ##arg)
#define cn_dev_warn_limit(str, arg...) \
	__print(pr_warn_ratelimited, "WARNING", str, ##arg);
#define cn_dev_core_warn(core, str, arg...) \
	__core_print(pr_warn, "WARNING", (core), str, ##arg)
#define cn_dev_pcie_warn(pcie, str, arg...) \
	__pcie_print(pr_warn, "WARNING", (pcie), str, ##arg)
#define cn_dev_edge_warn(edge, str, arg...) \
	__edge_print(pr_warn, "WARNING", (edge), str, ##arg)
#define cn_dev_i2c_warn(i2c, str, arg...) \
	__i2c_print(pr_warn, "WARNING", (i2c), str, ##arg)
#define cn_dev_monitor_warn(monitor, str, arg...) \
	__monitor_print(pr_warn, "WARNING", (monitor), str, ##arg)
#define cn_dev_cndev_warn(cndev, str, arg...) \
	__cndev_print(pr_warn, "WARNING", (cndev), str, ##arg)

#define cn_dev_err(str, arg...) \
	__print(pr_err, "ERROR", str, ##arg)
#define cn_dev_err_limit(str, arg...) \
	__print(pr_err_ratelimited, "ERROR", str, ##arg);
#define cn_ce_dev_err(str, arg...) \
	__ce_print(pr_err, "ERROR", str, ##arg)
#define cn_dev_core_err(core, str, arg...) \
	__core_print(pr_err, "ERROR", (core), str, ##arg)
#define cn_ce_dev_core_err(core, str, arg...) \
	__core_ce_print(pr_err, "ERROR", (core), str, ##arg)
#define cn_dev_core_err_limit(core, str, arg...) \
	__core_print(pr_err_ratelimited, "ERROR", (core), str, ##arg)
#define cn_dev_pcie_err(pcie, str, arg...) \
	__pcie_print(pr_err, "ERROR", (pcie), str, ##arg)
#define cn_dev_edge_err(edge, str, arg...) \
	__edge_print(pr_err, "ERROR", (edge), str, ##arg)
#define cn_dev_i2c_err(i2c, str, arg...) \
	__i2c_print(pr_err, "ERROR", (i2c), str, ##arg)
#define cn_dev_monitor_err(monitor, str, arg...) \
	__monitor_print(pr_err, "ERROR", (monitor), str, ##arg)
#define cn_ce_dev_monitor_err(monitor, str, arg...) \
	__monitor_ce_print(pr_err, "ERROR", (monitor), str, ##arg)
#define cn_dev_cndev_err(cndev, str, arg...) \
	__cndev_print(pr_err, "ERROR", (cndev), str, ##arg)
#define cn_ce_dev_cndev_err(cndev, str, arg...) \
	__cndev_ce_print(pr_err, "ERROR", (cndev), str, ##arg)
#define cn_dev_proc_err(proc, str, arg...) \
	__proc_print(pr_err, "ERROR", (proc), str, ##arg)

#define HIT_PRINT_BDG(sel)  (print_debug & print_debug_info[sel].bit_mask)
#define cn_dev_debug(str, arg...) \
do { \
	if (HIT_PRINT_BDG(DEV_DBG)) \
		__print(pr_info, "DEBUG", str, ##arg); \
} while (0)

#define cn_dev_core_debug(core, str, arg...) \
do { \
	if (unlikely(HIT_PRINT_BDG(DEV_CORE_DBG))) \
		__core_print(pr_info, "DEBUG", (core), str, ##arg); \
} while (0)

#define cn_dev_core_debug_limit(core, str, arg...) \
do { \
	if (unlikely(HIT_PRINT_BDG(DEV_CORE_DBG))) \
		__core_print(pr_info_ratelimited, "DEBUG", (core), str, ##arg); \
} while (0)

#define cn_ce_dev_core_debug(core, str, arg...) \
do { \
	if (unlikely(HIT_PRINT_BDG(DEV_CORE_DBG))) \
		__core_ce_print(pr_info, "DEBUG", (core), str, ##arg); \
} while (0)

#define cn_dev_pcie_debug(pcie, str, arg...) \
do {\
	if (HIT_PRINT_BDG(DEV_PCIE_DBG)) \
		__pcie_print(pr_info, "DEBUG", (pcie), str, ##arg); \
} while (0)

#define cn_dev_edge_debug(pcie, str, arg...) \
do {\
	if (HIT_PRINT_BDG(DEV_EDGE_DBG)) \
		__edge_print(pr_info, "DEBUG", (pcie), str, ##arg); \
} while (0)


#define cn_dev_i2c_debug(i2c, str, arg...) \
do {\
	if (HIT_PRINT_BDG(DEV_I2C_DBG)) \
		__i2c_print(pr_info, "DEBUG", (i2c), str, ##arg); \
} while (0)

#define cn_dev_monitor_debug(monitor, str, arg...) \
do {\
	if (HIT_PRINT_BDG(DEV_MONITOR_DBG)) \
		__monitor_print(pr_info, "DEBUG", (monitor), str, ##arg); \
} while (0)

#define cn_dev_cndev_debug(cndev, str, arg...) \
do {\
	if (cndev->print_debug  == true) \
		__cndev_print(pr_info, "DEBUG", (cndev), str, ##arg); \
} while (0)

#define cn_ce_dev_cndev_debug(cndev, str, arg...) \
do {\
	if (cndev->print_debug  == true) \
		__cndev_ce_print(pr_info, "DEBUG", (cndev), str, ##arg); \
} while (0)

#define USER_RECOMMED "It is recommended to refer to the " \
	"<Cambricon-Driver-User-Guide> for explanations of " \
	"error messages and recommended follow-up actions."

#define cn_recommend(core, str) \
do { \
	if (IS_ERR_OR_NULL(core)) \
		pr_err("[%s]: " str "\n", \
			 __func__); \
	else \
		pr_err("[%s][%s]: " str "\n", \
			core->core_name, __func__); \
} while (0)

static inline int d2d_1d_overlap_check(struct cn_core_set *core, __u64 src,
		__u64 dst, __u64 size)
{
	int ret = 0;

	if ((src < dst && (src + size) > dst) ||
	    (dst < src && (dst + size) > src)) {
		ret = -1;
		cn_dev_core_warn(core, "d2d 1D overlap: src[%llx] and dst[%llx] size[%llx]",
			src, dst, size);
	}

	return ret;
}

#endif /* __CNDRV_DEBUG_H__ */
