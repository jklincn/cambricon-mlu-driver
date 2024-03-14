/*
 * sbts/p2pshm.c
 *
 * NOTICE:
 * Copyright (C) 2021 Cambricon, Inc. All rights reserved.
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

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/bitmap.h>
#include <linux/printk.h>
#include <asm/barrier.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/ptrace.h>
#include <linux/rwsem.h>

#include "cndrv_os_compat.h"
#include "cndrv_core.h"
#include "cndrv_mm.h"
#include "cndrv_sbts.h"
#include "cndrv_bus.h"
#include "sbts.h"
#include "cndrv_debug.h"
#include "cndrv_ioctl.h"
#include "cndrv_hpq.h"
#include "queue.h"

/**
 * common structures and data types
 */
#define P2PSHM_HOST_IDX            (~0UL)
#define BIT16_MASK                 (0xFFFFULL)
#define P2PSHM_ALGO_WIDTH          (4)
#define P2PSHM_ALGO_SHIFT          (60)
#define P2PSHM_ALGO_MASK           ((1ULL << P2PSHM_ALGO_WIDTH) - 1)

#define P2PSHM_TYPE_ONLY_HW(type) ((type) == SBTS_P2PSHM_REG_HW)
#define P2PSHM_TYPE_HAVE_HW(type) ((type) & SBTS_P2PSHM_REG_HW)
#define P2PSHM_TYPE_HAVE_SW(type) ((type) & SBTS_P2PSHM_REG_SW)

enum p2pshm_algo {
	P2PSHM_ALGO_4SC = 1U,
	P2PSHM_ALGO_NUM,
};

/* p2pshm table entry */
struct cd_p2pshm_info {
	__le64 p2pshm_bus_addr;
	__le64 p2pshm_dev_va;
	__le32 p2pshm_sz;
	__le32 card_idx;
} __packed;

/* fixed single copy size for 4sc-algorithm */
#define P2PSHM_SINGLE_COPY_MIN_SZ	(4U)

enum p2pshm_state {
	P2PSHM_INIT = 0,
	P2PSHM_PRE_INIT,
	P2PSHM_INIT_DONE,
	P2PSHM_PRE_EXIT,
	P2PSHM_EXIT_DONE,
	P2PSHM_DISABLE,
};

enum p2pshm_err_code {
	P2PSHM_NONE = 0,
	P2PSHM_SUCCESS = P2PSHM_NONE,
	P2PSHM_CPU_ARCH_UNSUPPORT,
	P2PSHM_MLU_ARCH_UNSUPPORT,
	P2PSHM_MIX_TYPE_UNSUPPORT,
	P2PSHM_P2P_MATRIX_ERR,
	P2PSHM_DMA_ALLOCATOR_NOMEM,
	P2PSHM_INB_SHM_NOMEM,
	P2PSHM_MLU_OUTB_WIN_UNSUPPORT,
	P2PSHM_INIT_FAIL,
	P2PSHM_SINGLE_COPY_ATOMIC_MIN_SZ_UNSUPPORT,
	P2PSHM_PROBE_TIMEOUT,
	P2PSHM_P2PSHM_ALLOC_FAIL,
	P2PSHM_PROBE_FAIL,
	P2PSHM_VIRT_UNSUPPORT,
	P2PSHM_IOVA_MAP_FAIL,
	P2PSHM_ERR_CODE_NUM,
};

static const struct p2pshm_err_str {
	const char *str[P2PSHM_ERR_CODE_NUM];
} p2pshm_err_strs = {
	.str[P2PSHM_NONE] =
			"none",
	.str[P2PSHM_CPU_ARCH_UNSUPPORT] =
			"cpu arch is unsupported",
	.str[P2PSHM_MLU_ARCH_UNSUPPORT] =
			"mlu arch is unsupported",
	.str[P2PSHM_MIX_TYPE_UNSUPPORT] =
			"multi cards with different types is unsupported",
	.str[P2PSHM_P2P_MATRIX_ERR] =
			"p2p matrix test is failed",
	.str[P2PSHM_DMA_ALLOCATOR_NOMEM] =
			"out of host-dma-memory",
	.str[P2PSHM_INB_SHM_NOMEM] =
			"out of pcie-inbound-shared-memory",
	.str[P2PSHM_MLU_OUTB_WIN_UNSUPPORT] =
			"mlu pcie-outbound-window is unsupported",
	.str[P2PSHM_INIT_FAIL] =
			"p2pshm init failed",
	.str[P2PSHM_SINGLE_COPY_ATOMIC_MIN_SZ_UNSUPPORT] =
			"p2pshm single copy min size is unsupported",
	.str[P2PSHM_PROBE_TIMEOUT] =
			"p2pshm probe timeout",
	.str[P2PSHM_P2PSHM_ALLOC_FAIL] =
			"p2pshm reserve buffer alloc failed",
	.str[P2PSHM_PROBE_FAIL] =
			"p2pshm probe failed",
	.str[P2PSHM_VIRT_UNSUPPORT] =
			"virtualization is unsupported",
	.str[P2PSHM_IOVA_MAP_FAIL] =
			"iova map failed"
};

struct outb_win_info {
	enum outb_win_type type;
	__u16 idx;
	__u64 dev_pa;
	__u64 sz;
};

struct p2pshm_mem {
	/* fixed base address of device-shared-memory */
	void *shm_host_kva;
	dev_addr_t shm_dev_va;
	__u64 shm_bus_addr;
	__u64 shm_cpu_phy_addr;
	__u32 shm_sz;

	/* fixed base address of p2pshm reserved buffer */
	void *p2pshm_host_kva;
	dev_addr_t p2pshm_dev_va;
	__u64 p2pshm_bus_addr;
	__u64 p2pshm_cpu_phy_addr;
	__u32 p2pshm_sz;
};

struct p2pshm_info {
	/* probe */
	struct list_head entry;
	struct cn_core_set *core;
	unsigned int card_idx;

	/* outbound window and p2pshm memory */
	int reg_type;
	struct device *dev;
	struct outb_win_info outb_win;
	struct p2pshm_mem mem;
	struct p2pshm_table *p2pshm_tbl;

	bool late_init_en;
	bool avail_en;
};

struct p2pshm_allocator {
	struct mutex lock;
	__u32 bitmap_size;
	__u32 bitmap_nr;
	__u32 grain;
	__u32 grain_shift;
	__u32 grain_mask;
	unsigned long *bitmap;
};

static struct mlu_p2pshm {
	/* avoid false sharing */
	volatile enum p2pshm_state state __aligned(64);

	struct p2pshm_info host_shm;
	struct list_head shms_list;
	enum p2pshm_err_code err;
	int reg_type;
	struct task_struct *post_init_worker;
	volatile bool force_exit;
	struct completion post_init_exited;
	volatile unsigned int probe_cnt;
	volatile unsigned int probe_ar;
	wait_queue_head_t wait_init;

	/* p2pshm attributes and resources */
	__u8 single_copy_max_sz;
	__u8 single_copy_min_sz;

	/* p2pshm allocator */
	struct p2pshm_allocator allocator;
} global_mlu_p2pshm;

/* For dynamic probe&remove of cn_core */
DECLARE_RWSEM(global_rwsem);

enum p2pshm_map_type {
	P2PSHM_UNMAP = 0,
	P2PSHM_MAP_BUS_PA = 1,
	P2PSHM_MAP_IOVA = 2,
};

struct p2pshm_item {
	struct p2pshm_info *shm;
	enum p2pshm_map_type map_type;
	u64 io_addr;
};

struct p2pshm_table {
	unsigned int ncards;
	struct p2pshm_item item[0];
};

#define RECORD_ERR_ONCE(err_code) \
do { \
	smp_mb(); \
	if (!global_mlu_p2pshm.err) { \
		global_mlu_p2pshm.err = (err_code); \
		smp_wmb(); \
		global_mlu_p2pshm.state = P2PSHM_DISABLE; \
	} \
	smp_mb(); \
	wake_up_interruptible(&global_mlu_p2pshm.wait_init); \
} while (0)

static inline struct p2pshm_info *__core2p2pshm_info(struct cn_core_set *core)
{
	return (core ? core->shm_set : NULL);
}

static inline unsigned int
__p2pshm_key2idx(__u64 key, struct p2pshm_allocator *allocator)
{
	return (unsigned int)((key & (~P2PSHM_ALGO_MASK)) >>
			allocator->grain_shift);
}

static inline unsigned int
__p2pshm_key_get_algo(__u64 key)
{
	return (unsigned int)((key >> P2PSHM_ALGO_SHIFT) & P2PSHM_ALGO_MASK);
}

static inline __u64
__p2pshm_key_gen(unsigned int idx, enum p2pshm_algo algo,
		struct p2pshm_allocator *allocator)
{
	return ((((__u64)idx) << allocator->grain_shift) |
			(((__u64)algo & P2PSHM_ALGO_MASK) << P2PSHM_ALGO_SHIFT));
}

static inline __u64
__p2pshm_key_mask_algo(__u64 key)
{
	return (key & (~(P2PSHM_ALGO_MASK << P2PSHM_ALGO_SHIFT)));
}

static inline int __p2pshm_enable(void)
{
	int ret = 0;

	ret = wait_event_interruptible(global_mlu_p2pshm.wait_init,
			(global_mlu_p2pshm.state == P2PSHM_DISABLE ||
			global_mlu_p2pshm.state == P2PSHM_INIT_DONE ||
			global_mlu_p2pshm.state == P2PSHM_PRE_EXIT));
	if (unlikely(ret)) {
		cn_dev_err("wait p2pshm init failed(return %d)", ret);
		return ret;
	}

	if (global_mlu_p2pshm.state == P2PSHM_DISABLE) {
		return -ENODEV;
	}

	if (global_mlu_p2pshm.state == P2PSHM_INIT_DONE) {
		return 0;
	}

	return -EAGAIN;
}

static enum p2pshm_err_code __single_copy_sz_check(void)
{
	if (global_mlu_p2pshm.single_copy_min_sz < P2PSHM_SINGLE_COPY_MIN_SZ) {
		cn_dev_err("p2pshm single copy min sz limit %d(current %d)",
				(int)P2PSHM_SINGLE_COPY_MIN_SZ,
				(int)global_mlu_p2pshm.single_copy_min_sz);
		return P2PSHM_SINGLE_COPY_ATOMIC_MIN_SZ_UNSUPPORT;
	}

	return P2PSHM_SUCCESS;
}

static enum p2pshm_err_code __wait_all_cores_ar(void)
{
	unsigned int req = global_mlu_p2pshm.probe_cnt;
	/* about 15s timeout */
	const unsigned int timeout_ms = 15000;
	unsigned int cnt = 0;
	struct p2pshm_info *shm;

	while (global_mlu_p2pshm.probe_ar != req) {
		if (global_mlu_p2pshm.force_exit == true) {
			return P2PSHM_INIT_FAIL;
		}

		if ((++cnt) == timeout_ms) {
			cn_dev_err("wait all core arrive timeout(req %d ar %d)",
					req,
					global_mlu_p2pshm.probe_ar);
			return P2PSHM_PROBE_TIMEOUT;
		}

		down_read(&global_rwsem);
		list_for_each_entry(shm, &global_mlu_p2pshm.shms_list,
				entry) {
			struct cn_core_set *core = shm->core;
			int state;

			if (!core) {
				break;
			}

			state = READ_ONCE(core->state);
			if (state == CN_BOOTERR || state == CN_RESET_ERR) {
				cn_dev_core_err(core,
						"wait core failed(state %d)",
						state);
				up_read(&global_rwsem);
				return P2PSHM_INIT_FAIL;
			}

		}

		up_read(&global_rwsem);

		msleep(1);
	}

	return P2PSHM_SUCCESS;
}

static void __p2pshm_update(struct cn_core_set *core, struct p2pshm_info *shm)
{
	struct p2pshm_attr attr = {0};
	struct p2pshm_mem *mem = &shm->mem;
	dev_addr_t p2pshm_dev_va;
	struct outb_win_info *outb_win;
	__u64 off = 0;

	if (cn_bus_get_p2pshm_info(core->bus_set, &attr)) {
		RECORD_ERR_ONCE(P2PSHM_MLU_ARCH_UNSUPPORT);
		cn_dev_core_info(core, "p2pshm is unsupported");
		return;
	}

	outb_win = &shm->outb_win;
	outb_win->type = attr.win_type;
	outb_win->idx = attr.outb_win_idx;
	outb_win->dev_pa = attr.outb_win_dev_pa;
	outb_win->sz = (attr.outb_win_sz > SBTS_P2PSHM_SZ ?
			SBTS_P2PSHM_SZ : attr.outb_win_sz);

	mem = &shm->mem;
	mem->shm_host_kva = attr.shm_host_kva;
	mem->shm_dev_va = attr.shm_dev_va;
	mem->shm_bus_addr = attr.shm_pci_bus_addr;
	mem->shm_cpu_phy_addr = attr.shm_cpu_phy_addr;
	mem->shm_sz = attr.shm_sz;

	p2pshm_dev_va = cn_shm_get_dev_addr_by_name(core, SBTS_P2PSHM_NAME);
	if (p2pshm_dev_va == (dev_addr_t)-1) {
		cn_dev_core_info(core, "p2pshm is unsupported");
		return;
	}

	off = (__u64)p2pshm_dev_va - (__u64)mem->shm_dev_va;

	mem->p2pshm_dev_va = p2pshm_dev_va;
	mem->p2pshm_bus_addr = (__u64)mem->shm_bus_addr + off;
	mem->p2pshm_cpu_phy_addr = (__u64)mem->shm_cpu_phy_addr + off;
	mem->p2pshm_host_kva = (void *)((__u64)mem->shm_host_kva + off);
	mem->p2pshm_sz = SBTS_P2PSHM_SZ;
}

static struct p2pshm_info *__attach_p2pshm(struct cn_core_set *core)
{
	struct p2pshm_info *shm;

	if (unlikely(cn_core_is_vf(core) || cn_is_mim_en(core))) {
		RECORD_ERR_ONCE(P2PSHM_VIRT_UNSUPPORT);
		cn_dev_core_warn(core, "reprobe with device status unsupport");
		return NULL;
	}

	down_write(&global_rwsem);
	list_for_each_entry(shm, &global_mlu_p2pshm.shms_list, entry) {
		if (shm->card_idx == core->idx) {
			shm->core = core;
			core->shm_set = shm;
			/* virtual address may be changed */
			__p2pshm_update(core, shm);
			cn_dev_core_info(core, "attach p2pshm success");
			up_write(&global_rwsem);
			return shm;
		}

	}

	cn_dev_core_info(core, "core idx %d does not exist", core->idx);
	up_write(&global_rwsem);
	return NULL;
}

static void __detach_p2pshm(struct cn_core_set *core)
{
	struct p2pshm_info *shm;

	down_write(&global_rwsem);
	list_for_each_entry(shm, &global_mlu_p2pshm.shms_list, entry) {
		if (shm->card_idx == core->idx) {
			shm->core = NULL;
			core->shm_set = NULL;
			cn_dev_core_info(core, "detach p2pshm success");
			up_write(&global_rwsem);
			return;
		}

	}

	cn_dev_core_err(core, "core idx %d does not exist", core->idx);
	up_write(&global_rwsem);
	return;
}

static struct p2pshm_info *
__req_core_once(struct cn_core_set *core)
{
	int ar = 0;
	struct p2pshm_info *shm;

	shm = __attach_p2pshm(core);
	if (!shm) {
		cn_dev_core_err(core, "p2pshm attach failed");
		return NULL;
	}

	if (likely(shm->late_init_en == true)) {
		return shm;
	}

	shm->late_init_en = true;
	/* guarantee p2pshm info updated */
	smp_wmb();
	ar = __sync_fetch_and_add(&global_mlu_p2pshm.probe_ar,
			(!!shm->late_init_en));
	cn_dev_core_debug(core, "p2pshm arrive %d", ar);
	return shm;
}

static enum p2pshm_err_code __p2p_matrix_test(void)
{
	struct p2pshm_info *src_shm, *dst_shm;
	struct list_head *shms_list = &global_mlu_p2pshm.shms_list;
	int ret = 0;

	ret = __wait_all_cores_ar();
	if (unlikely(ret)) {
		return ret;
	}

	down_read(&global_rwsem);
	/* p2p matrix is tested by cn_bus_dma_p2p_able(src_bus, dst_bus) */
	list_for_each_entry(src_shm, shms_list, entry) {
		list_for_each_entry(dst_shm, shms_list, entry) {
			struct cn_core_set *src_core = src_shm->core;
			struct cn_core_set *dst_core = dst_shm->core;
			void *src_bus_set;
			void *dst_bus_set;

			if (!src_core) {
				cn_dev_info("core idx %d is null",
						src_shm->card_idx);
				up_read(&global_rwsem);
				return P2PSHM_P2P_MATRIX_ERR;
			}

			if (!dst_core) {
				cn_dev_info("core idx %d is null",
						dst_shm->card_idx);
				up_read(&global_rwsem);
				return P2PSHM_P2P_MATRIX_ERR;
			}

			src_bus_set = src_core->bus_set;
			dst_bus_set = dst_core->bus_set;
			/* skip if @src_shm == @dst_shm */
			if (src_shm == dst_shm) {
				continue;
			}

			if (cn_bus_dma_p2p_able(src_bus_set, dst_bus_set) < 0) {
				cn_dev_info("p2p (%d->%d) is disable",
						src_core->idx, dst_core->idx);
				up_read(&global_rwsem);
				return P2PSHM_P2P_MATRIX_ERR;
			}

		}

	}

	up_read(&global_rwsem);
	return P2PSHM_SUCCESS;
}

static void __p2pshm_dma_unmap(struct p2pshm_item *item,
		struct p2pshm_info *src_shm)
{
	struct device *src_dev = src_shm->dev;
	struct p2pshm_info *dst_shm = item->shm;
	struct p2pshm_mem *dst_mem = &dst_shm->mem;

	if (item->map_type == P2PSHM_UNMAP) {
		return;
	}

	if (item->map_type == P2PSHM_MAP_BUS_PA) {
		return;
	}

	if (!dst_shm) {
		cn_dev_core_err(src_shm->core, "dst shm is null");
		return;
	}

	dma_unmap_page(src_dev, item->io_addr, dst_mem->p2pshm_sz,
			DMA_BIDIRECTIONAL);
	item->map_type = P2PSHM_UNMAP;
	item->io_addr = 0;
	item->shm = NULL;
}

static int __p2pshm_dma_map(struct p2pshm_item *item,
		struct p2pshm_info *src_shm, struct p2pshm_info *dst_shm)
{
	struct device *src_dev = src_shm->dev;
	struct p2pshm_mem *dst_mem = &dst_shm->mem;
	struct page *page;
	/* default dma_map_page() */
	bool dma_map = true;
	bool is_dev = (dst_shm->card_idx != (unsigned int)P2PSHM_HOST_IDX);

	item->shm = dst_shm;

	/* same device */
	if (src_shm == dst_shm) {
		return 0;
	}

	/* detect ACS */
	if (is_dev == true) {
		struct cn_core_set *src_core = src_shm->core;
		struct cn_core_set *dst_core = dst_shm->core;
		void *src_bus_set;
		void *dst_bus_set;

		if (!src_core) {
			return -ENODEV;
		}

		if (!dst_core) {
			return -ENODEV;
		}

		src_bus_set = src_core->bus_set;
		dst_bus_set = dst_core->bus_set;
		/**
		 * TLP request ignores ACS or ACS disable if
		 * cn_bus_dma_p2p_able() return P2P_FAST_ABLE,
		 * access pci bus address is allowed.
		 * Direct-access pci bus address(without ATC) is better for
		 * performance(but non-security)
		 */
		if (cn_bus_dma_p2p_able(src_bus_set, dst_bus_set) ==
				P2P_FAST_ABLE) {
			dma_map = false;
		}

	}

	if (dma_map == false) {
		item->io_addr = dst_mem->p2pshm_bus_addr;
		item->map_type = P2PSHM_MAP_BUS_PA;
		return 0;
	}

	if (is_dev == true) {
		/**
		 * device p2pshm is contiguous physical 64-bit cpu address
		 */
		page = pfn_to_page(dst_mem->p2pshm_cpu_phy_addr >> PAGE_SHIFT);
	} else {
		/**
		 * dma_alloc_coherent() guarantees contiguous physical 64-bit
		 * cpu address and virtual address.
		 * NOTICE: dma_alloc_coherent() can return memory in the
		 * vmalloc range.
		 */
		if (is_vmalloc_addr(dst_mem->p2pshm_host_kva)) {
			page = vmalloc_to_page(dst_mem->p2pshm_host_kva);
		} else {
			page = virt_to_page(dst_mem->p2pshm_host_kva);
		}

	}

	/**
	 * dma_map_page() return IOVA if IOMMU enable,
	 * otherwise pci bus address is returned
	 */
	item->io_addr = dma_map_page(src_dev, page, 0, dst_mem->p2pshm_sz,
			DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(src_dev, item->io_addr))) {
		cn_dev_core_err(src_shm->core,
				"dma mapping error(dst card[%d])",
				dst_shm->card_idx);
		return -EIO;
	}

	item->map_type = P2PSHM_MAP_IOVA;
	return 0;
}

static void __p2pshm_unmap(void)
{
	struct p2pshm_info *src_shm;
	struct list_head *shms_list = &global_mlu_p2pshm.shms_list;

	list_for_each_entry(src_shm, shms_list, entry) {
		struct p2pshm_table *tbl = src_shm->p2pshm_tbl;
		int cur_idx;

		if (unlikely(!tbl)) {
			continue;
		}

		for (cur_idx = 0; cur_idx < tbl->ncards; ++cur_idx) {
			struct p2pshm_item *item = &tbl->item[cur_idx];

			__p2pshm_dma_unmap(item, src_shm);
		}

		cn_kfree(tbl);
		src_shm->p2pshm_tbl = NULL;
	}

}

static enum p2pshm_err_code __p2pshm_map(void)
{
	int ret = 0;
	struct p2pshm_info *src_shm;
	struct list_head *shms_list = &global_mlu_p2pshm.shms_list;
	unsigned int ncards;
	unsigned int table_size;

	ret = __wait_all_cores_ar();
	if (unlikely(ret)) {
		return ret;
	}

	/* only host, or host + ncards */
	ncards = (P2PSHM_TYPE_ONLY_HW(global_mlu_p2pshm.reg_type)) ?
			1 : global_mlu_p2pshm.probe_cnt + 1;

	table_size = ncards * sizeof(struct p2pshm_item) +
			sizeof(struct p2pshm_table);

	down_read(&global_rwsem);
	list_for_each_entry(src_shm, shms_list, entry) {
		struct cn_core_set *src_core = src_shm->core;
		struct p2pshm_table *tbl;
		struct p2pshm_info *dst_shm;
		struct p2pshm_item *item;
		int cur_idx = -1;

		tbl = cn_kzalloc(table_size, GFP_KERNEL);
		if (unlikely(!tbl)) {
			cn_dev_core_err(src_core, "alloc p2pshm table failed");
			goto exit;
		}

		src_shm->p2pshm_tbl = tbl;
		tbl->ncards = ncards;

		/* host shm iova map */
		cur_idx++;
		item = &tbl->item[cur_idx];
		dst_shm = &global_mlu_p2pshm.host_shm;
		if (unlikely(__p2pshm_dma_map(item, src_shm, dst_shm))) {
			cn_dev_core_err(src_core,
					"item[%d] map host failed",
					cur_idx);
			goto exit;
		}

		cn_dev_core_debug(src_core,
				"item[%d] map host success",
				cur_idx);

		if (P2PSHM_TYPE_ONLY_HW(global_mlu_p2pshm.reg_type))
			continue;

		/* device shm iova map */
		list_for_each_entry(dst_shm, shms_list, entry) {
			cur_idx++;
			item = &tbl->item[cur_idx];

			if (unlikely(__p2pshm_dma_map(item, src_shm,
					dst_shm))) {
				cn_dev_core_err(src_core,
						"item[%d] map card[%d] failed",
						cur_idx, dst_shm->card_idx);
				goto exit;
			}

			cn_dev_core_debug(src_core,
					"item[%d] map card[%d] success",
					cur_idx, dst_shm->card_idx);
		}
	}

	up_read(&global_rwsem);
	cn_dev_info("map %d cards success", ncards);
	return P2PSHM_SUCCESS;

exit:
	__p2pshm_unmap();
	up_read(&global_rwsem);
	return P2PSHM_IOVA_MAP_FAIL;
}

static void __host_p2pshm_exit(void)
{
	struct p2pshm_info *host_shm = &global_mlu_p2pshm.host_shm;
	struct p2pshm_mem *mem = &host_shm->mem;

	if (!mem->p2pshm_host_kva) {
		return;
	}

	dma_free_coherent(host_shm->dev, mem->p2pshm_sz, mem->p2pshm_host_kva,
			mem->p2pshm_bus_addr);
	mem->p2pshm_host_kva = NULL;
	mem->p2pshm_sz = 0;
}

static enum p2pshm_err_code __host_p2pshm_init(__u32 p2pshm_sz)
{
	struct p2pshm_info *host_shm = &global_mlu_p2pshm.host_shm;
	struct p2pshm_mem *mem = &host_shm->mem;
	struct device *dma_dev = cndrv_core_get_dma_device();

	/* try to alloc dma-buffer via @dma_dev if @dma_dev is existed */
	if (dma_dev) {
		mem->p2pshm_host_kva = dma_alloc_coherent(dma_dev, p2pshm_sz,
				&mem->p2pshm_bus_addr, GFP_KERNEL);
	}

	/**
	 * attempt dma_alloc_coherent() via first mlu-device
	 * if dma_alloc_coherent() failed via @dma_device
	 */
	if (!mem->p2pshm_host_kva) {
		struct p2pshm_info *first_shm = list_first_entry(
				&global_mlu_p2pshm.shms_list,
				struct p2pshm_info, entry);

		dma_dev = first_shm->dev;
		mem->p2pshm_host_kva = dma_alloc_coherent(dma_dev, p2pshm_sz,
				&mem->p2pshm_bus_addr, GFP_KERNEL);
	}

	if (!mem->p2pshm_host_kva) {
		cn_dev_err("p2pshm host dma alloc failed(size %#lx)!",
				(unsigned long)p2pshm_sz);
		return P2PSHM_DMA_ALLOCATOR_NOMEM;
	}

	mem->p2pshm_sz = p2pshm_sz;
	mem->p2pshm_dev_va = 0U;
	host_shm->dev = dma_dev;
	host_shm->card_idx = (unsigned int)P2PSHM_HOST_IDX;

	cn_dev_debug("host p2pshm init success(host kva %px bus addr %px size %d)",
			mem->p2pshm_host_kva, (void *)mem->p2pshm_bus_addr,
			mem->p2pshm_sz);
	return P2PSHM_SUCCESS;
}

static void __allocator_exit(void)
{
	struct p2pshm_allocator *allocator = &global_mlu_p2pshm.allocator;

	if (!allocator->bitmap) {
		return;
	}

	if (!bitmap_empty(allocator->bitmap, allocator->bitmap_nr)) {
		cn_dev_err("p2pshm bitmap is not empty");
	}

	cn_kfree(allocator->bitmap);
	allocator->bitmap = NULL;
}

static enum p2pshm_err_code __allocator_init(__u32 num, __u32 grain_shift)
{
	struct p2pshm_allocator *allocator = &global_mlu_p2pshm.allocator;

	allocator->grain_shift = grain_shift;
	allocator->grain = (1U << grain_shift);
	allocator->grain_mask = allocator->grain - 1;
	allocator->bitmap_nr = num;
	allocator->bitmap_size =
			BITS_TO_LONGS(allocator->bitmap_nr) * sizeof(long);
	allocator->bitmap = cn_kzalloc(allocator->bitmap_size, GFP_KERNEL);
	if (!allocator->bitmap) {
		cn_dev_err("alloc bitmap failed");
		return P2PSHM_INIT_FAIL;
	}

	mutex_init(&allocator->lock);
	return P2PSHM_SUCCESS;
}

void cn_p2pshm_register(struct cn_core_set *core)
{
	struct p2pshm_attr attr = {0};
	struct p2pshm_info *shm = (struct p2pshm_info *)core->shm_set;
	u8 single_copy_min_sz = global_mlu_p2pshm.single_copy_min_sz;
	u8 single_copy_max_sz = global_mlu_p2pshm.single_copy_max_sz;

	if (unlikely(!shm)) {
		cn_dev_core_err(core, "internal error: register before probe");
		RECORD_ERR_ONCE(P2PSHM_PROBE_FAIL);
		return;
	}

	if (cn_bus_get_p2pshm_info(core->bus_set, &attr)) {
		RECORD_ERR_ONCE(P2PSHM_MLU_ARCH_UNSUPPORT);
		cn_dev_core_info(core, "p2pshm is unsupported");
		return;
	}

	if (unlikely(attr.single_copy_min_sz > attr.single_copy_max_sz)) {
		cn_dev_core_err(core,
				"single copy size(min %d max %d) is invalid",
				(int)attr.single_copy_min_sz,
				(int)attr.single_copy_max_sz);
		return;
	}

	shm->reg_type = attr.reg_type;
	shm->dev = attr.dev;

	/* update single copy size */
	if (single_copy_min_sz < attr.single_copy_min_sz) {
		single_copy_min_sz = attr.single_copy_min_sz;
	}

	if ((single_copy_max_sz == 0) ||
			(single_copy_max_sz > attr.single_copy_max_sz)) {
		single_copy_max_sz = attr.single_copy_max_sz;
	}

	cn_dev_core_debug(core, "single copy size[%d:%d]",
			(int)single_copy_min_sz,
			(int)single_copy_max_sz);
	global_mlu_p2pshm.single_copy_min_sz = single_copy_min_sz;
	global_mlu_p2pshm.single_copy_max_sz = single_copy_max_sz;
}

int cn_p2pshm_init(struct cn_core_set *core)
{
	struct p2pshm_info *shm;

	if (unlikely(global_mlu_p2pshm.state == P2PSHM_DISABLE)) {
		return 0;
	}

	if (unlikely(cn_core_is_vf(core) || cn_is_mim_en(core))) {
		RECORD_ERR_ONCE(P2PSHM_VIRT_UNSUPPORT);
		return 0;
	}

	if (core->shm_set) {
		cn_dev_core_err(core, "internal error: probe");
		return -1;
	}

	/* re-probe if chip-reset done */
	if (unlikely(global_mlu_p2pshm.state != P2PSHM_PRE_INIT)) {
		return 0;
	}

	shm = cn_kzalloc(sizeof(*shm), GFP_KERNEL);
	if (unlikely(!shm)) {
		cn_dev_core_err(core, "alloc shm failed");
		RECORD_ERR_ONCE(P2PSHM_PROBE_FAIL);
		return -1;
	}

	core->shm_set = shm;
	shm->core = core;
	shm->card_idx = core->idx;
	shm->reg_type = SBTS_P2PSHM_REG_INIT;
	list_add_tail(&shm->entry, &global_mlu_p2pshm.shms_list);
	global_mlu_p2pshm.probe_cnt++;

	cn_p2pshm_register(core);

	return 0;
}

void cn_p2pshm_exit(struct cn_core_set *core)
{
	struct p2pshm_info *shm = (struct p2pshm_info *)core->shm_set;

	if (unlikely(!shm)) {
		return;
	}

	/* remove if chip-reset */
	if (global_mlu_p2pshm.state != P2PSHM_PRE_EXIT) {
		__detach_p2pshm(core);
		return;
	}

	list_del_init(&shm->entry);
	global_mlu_p2pshm.probe_cnt--;
	core->shm_set = NULL;
	cn_kfree(shm);
}

static inline __u64
fill_desc_p2pshm_tbl_info(__u64 version, enum p2pshm_algo algo,
		enum outb_win_type outb_win_type, __u16 outb_win_idx,
		__u64 outb_win_dev_pa, __u32 outb_win_sz,
		__u32 current_idx, unsigned int ncards, __u64 info_iova,
		struct comm_ctrl_desc *ctrl_desc,
		struct sbts_set *sbts)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	/* version relate structure */
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct ctrl_desc_data_v1 *data =
			(struct ctrl_desc_data_v1 *)&ctrl_desc->data;
	struct cd_p2pshm_tbl_info *priv =
			(struct cd_p2pshm_tbl_info *)data->priv;

	switch (version) {
	case SBTS_VERSION:
		ctrl_desc->version = version;

		/* get ctrl desc data */
		data                  = (struct ctrl_desc_data_v1 *)ctrl_desc->data;
		data->type            = P2PSHM_CTRL;
		priv                  = (struct cd_p2pshm_tbl_info *)data->priv;
		priv->p2pshm_algo     = (__u8)algo;
		priv->outb_win_type   = (__u8)outb_win_type;
		priv->outb_win_idx    = cpu_to_le16(outb_win_idx);
		priv->outb_win_dev_pa = cpu_to_le64(outb_win_dev_pa);
		priv->outb_win_sz     = cpu_to_le32(outb_win_sz);
		priv->current_idx     = cpu_to_le32(current_idx);
		priv->ncards          = cpu_to_le32(ncards);
		priv->info_iova       = cpu_to_le64(info_iova);

		/* calculate payload_size: version + ctrl + data + ctrl_priv */
		payload_size = sizeof(struct comm_ctrl_desc);
		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

static int
__p2pshm_table_load(struct cn_core_set *core, struct p2pshm_info *cur_shm)
{
	struct sbts_set *sbts = core->sbts_set;
	struct sched_manager *sched_mgr = sbts->sched_manager;
	/* must init tx_desc & rx_desc */
	struct comm_ctrl_desc tx_desc = {0};
	struct comm_ctrl_desc rx_desc = {0};
	struct cd_p2pshm_info *cd_shms = NULL;
	__u64 payload_size = 0;
	host_addr_t host_va = 0;
	dev_addr_t dev_va = 0;
	unsigned int ncards = 0;
	__u64 tbl_size = 0;
	unsigned int i;
	struct p2pshm_table *tbl = cur_shm->p2pshm_tbl;
	int ret = 0;

	/* read from table */
	ncards = tbl->ncards;
	tbl_size = sizeof(struct cd_p2pshm_info) * ncards;

	ret = cn_device_share_mem_alloc(0, &host_va, &dev_va, tbl_size, core);
	if (ret) {
		cn_dev_core_err(core,
				"alloc shmem info dev buffer(size %#llx) failed",
				(unsigned long long)tbl_size);
		return -ENOMEM;
	}

	cd_shms = cn_kzalloc(tbl_size, GFP_KERNEL);
	if (!cd_shms) {
		cn_dev_core_err(core,
				"alloc shmem info host buffer(size %#llx) failed",
				(unsigned long long)tbl_size);
		ret = -ENOMEM;
		goto exit;
	}

	for (i = 0; i < tbl->ncards; ++i) {
		struct p2pshm_item *item = &tbl->item[i];
		struct p2pshm_info *shm = item->shm;
		struct p2pshm_mem *mem = &shm->mem;

		if (!shm) {
			cn_dev_core_err(core, "item[%d] is null", i);
			ret = -EIO;
			goto exit;
		}

		cd_shms[i].p2pshm_bus_addr =
				cpu_to_le64(item->io_addr);
		cd_shms[i].p2pshm_dev_va =
				cpu_to_le64(mem->p2pshm_dev_va);
		cd_shms[i].p2pshm_sz =
				cpu_to_le32(mem->p2pshm_sz);
		cd_shms[i].card_idx = cpu_to_le32(shm->card_idx);
	}

	memcpy_toio((void *)host_va, (void *)cd_shms, tbl_size);

	/* pass shmem info to device */
	payload_size = fill_desc_p2pshm_tbl_info(SBTS_VERSION,
			P2PSHM_ALGO_4SC,
			cur_shm->outb_win.type,
			cur_shm->outb_win.idx,
			cur_shm->outb_win.dev_pa,
			cur_shm->outb_win.sz,
			cur_shm->card_idx,
			ncards,
			dev_va,
			&tx_desc, sbts);

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
			ANNOY_USER, (__u64)payload_size);
	if (unlikely(ret || rx_desc.sta)) {
		cn_dev_core_err(core, "sbts ioctl failed(return %d)!", ret);
		ret = -EFAULT;
		goto exit;
	}

exit:
	if (cd_shms) {
		cn_kfree(cd_shms);
	}

	if (host_va) {
		cn_device_share_mem_free(0, host_va, dev_va, core);
	}

	return ret;
}

int cn_p2pshm_late_init(struct cn_core_set *core)
{
	struct p2pshm_info *shm;
	int ret = 0;

	shm = __req_core_once(core);
	if (unlikely(!shm)) {
		cn_dev_core_warn(core, "shm is null");
		return -1;
	}

	ret = wait_event_interruptible(global_mlu_p2pshm.wait_init,
			(global_mlu_p2pshm.state == P2PSHM_DISABLE ||
			global_mlu_p2pshm.state == P2PSHM_INIT_DONE ||
			global_mlu_p2pshm.state == P2PSHM_PRE_EXIT));
	if (unlikely(ret)) {
		cn_dev_core_err(core, "wait p2pshm init failed(return %d)",
				ret);
		return -1;
	}

	if (__p2pshm_enable()) {
		cn_dev_core_info(core, "not support p2pshm");
		return -1;
	}

	if (P2PSHM_TYPE_ONLY_HW(global_mlu_p2pshm.reg_type)) {
		cn_dev_core_info(core, "no need message to dev");
		return -1;
	}

	/* load */
	ret = __p2pshm_table_load(core, shm);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "p2pshm table load failed(return %d)",
				ret);
		return -1;
	}

	/* available flag set */
	shm->avail_en = true;
	/* guarantee @avail_en updated */
	smp_mb();
	return 0;
}

void cn_p2pshm_late_exit(struct cn_core_set *core)
{
	struct p2pshm_info *shm = __core2p2pshm_info(core);

	if (unlikely(!shm)) {
		cn_dev_core_err(core, "shm is null");
		return;
	}

	shm->avail_en = false;
	/* guarantee @avail_en updated */
	smp_mb();
}

/* return 0 if available */
int sbts_p2pshm_enable(void)
{
	return __p2pshm_enable();
}

/* return 0 if available */
int sbts_p2pshm_dev_rw(void)
{
	int ret = __p2pshm_enable();

	if (ret)
		return ret;

	if (P2PSHM_TYPE_HAVE_SW(global_mlu_p2pshm.reg_type))
		return 0;

	return -ENODEV;
}

static int __p2pshm_alloc_4sc(__u64 *key)
{
	struct p2pshm_allocator *allocator = &global_mlu_p2pshm.allocator;
	unsigned int idx;
	int ret = 0;

	if (unlikely(mutex_lock_killable(&allocator->lock))) {
		cn_dev_err("killed by fatal signal");
		return -EINTR;
	}

	idx = find_first_zero_bit(allocator->bitmap, allocator->bitmap_nr);
	if (unlikely(idx >= allocator->bitmap_nr)) {
		ret = -ENOMEM;
		goto out;
	}

	set_bit(idx, allocator->bitmap);
	*key = __p2pshm_key_gen(idx, P2PSHM_ALGO_4SC, allocator);

out:
	mutex_unlock(&allocator->lock);
	return ret;
}

static void __p2pshm_free_4sc(__u64 key)
{
	struct p2pshm_allocator *allocator = &global_mlu_p2pshm.allocator;
	unsigned int algo = __p2pshm_key_get_algo(key);
	unsigned int idx = __p2pshm_key2idx(key, allocator);

	if (unlikely(idx >= allocator->bitmap_nr)) {
		cn_dev_err("key %llu is invalid(bitmap nr %u grain size %u)",
				(unsigned long long)key,
				allocator->bitmap_nr,
				allocator->grain);
		return;
	}

	if (unlikely(algo != P2PSHM_ALGO_4SC)) {
		cn_dev_err("key %llu algo(%d) is invalid(bitmap nr %u grain size %u)",
				(unsigned long long)key,
				algo,
				allocator->bitmap_nr,
				allocator->grain);
		return;
	}

	/* guarantee all posted write-requests completed */
	sbts_p2pshm_flush_write();

	mutex_lock(&allocator->lock);
	if (!test_bit(idx, allocator->bitmap)) {
		cn_dev_err("key %llu is invalid(bitmap nr %u grain size %u)",
				(unsigned long long)key,
				allocator->bitmap_nr,
				allocator->grain);
		goto out;
	}

	clear_bit(idx, allocator->bitmap);
out:
	mutex_unlock(&allocator->lock);
}

int
sbts_p2pshm_alloc64(__u64 *key)
{
	int ret = __p2pshm_enable();

	if (unlikely(ret)) {
		return ret;
	}

	if (unlikely(!key)) {
		return -EINVAL;
	}

	return __p2pshm_alloc_4sc(key);
}

void
sbts_p2pshm_free64(__u64 key)
{
	int ret = __p2pshm_enable();

	if (unlikely(ret)) {
		return;
	}

	__p2pshm_free_4sc(key);
}

static inline bool
__p2pshm_addr_is_valid(void *va, void *start, __u32 sz)
{
	__u64 s = (__u64)start;
	__u64 addr = (__u64)va;
	__u64 e = s + sz;

	return (addr >= s && addr < e);
}

static inline void *
__p2pshm_key2va_4sc(struct cn_core_set *core, __u64 key)
{
	struct p2pshm_mem *mem;
	struct p2pshm_info *shm;
	void *va;
	unsigned int algo = __p2pshm_key_get_algo(key);
	__u64 __key = __p2pshm_key_mask_algo(key);

	if (unlikely(algo != P2PSHM_ALGO_4SC)) {
		cn_dev_core_err(core, "key %#llx algo %d is invalid",
				(unsigned long long)key,
				algo);
		return NULL;
	}

	shm = (core ? __core2p2pshm_info(core) : &global_mlu_p2pshm.host_shm);
	if (unlikely(!shm)) {
		cn_dev_core_err(core, "shm is invalid");
		return NULL;
	}

	mem = &shm->mem;
	va = (void *)((__u64)mem->p2pshm_host_kva + __key);
	return (__p2pshm_addr_is_valid(va, mem->p2pshm_host_kva,
			mem->p2pshm_sz) ? va : NULL);
}

static inline int
__p2pshm_write64_4sc_relaxed(volatile __u32 *va, __u64 val, __u16 seq)
{
	union {
		__le16 slice[8];
		volatile __u32 sc[4];
	} packet64;
	int i;

	/* always unroll */
	packet64.slice[0] = cpu_to_le16(seq);
	packet64.slice[1] = cpu_to_le16((u16)(val & BIT16_MASK));
	packet64.slice[2] = cpu_to_le16(seq);
	packet64.slice[3] = cpu_to_le16((u16)((val >> 16) & BIT16_MASK));
	packet64.slice[4] = cpu_to_le16(seq);
	packet64.slice[5] = cpu_to_le16((u16)((val >> 32) & BIT16_MASK));
	packet64.slice[6] = cpu_to_le16(seq);
	packet64.slice[7] = cpu_to_le16((u16)((val >> 48) & BIT16_MASK));

	/* a single-copy is always fixed at 4 bytes */
	for (i = 0; i < (sizeof(packet64) >> 2); ++i) {
		va[i] = packet64.sc[i];
	}

	return 0;
}

static inline int
__p2pshm_read64_4sc_relaxed(volatile __u32 *va, __u64 *val, __u16 *seq)
{
	unsigned long flags;
	union {
		__le16 slice[8];
		volatile __u32 sc[4];
	} packet;
	__le16 dif = 0;

	local_irq_save(flags);
	preempt_disable();
	/* guarantee local_irq_save() and preempt_disable completed */
	smp_mb();
	packet.sc[0] = va[0];
	packet.sc[1] = va[1];
	packet.sc[2] = va[2];
	packet.sc[3] = va[3];
	/* guarantee @packet loads completed */
	smp_mb();
	local_irq_restore(flags);
	preempt_enable();
	dif |= packet.slice[0] ^ packet.slice[2];
	dif |= packet.slice[4] ^ packet.slice[6];
	dif |= packet.slice[0] ^ packet.slice[4];
	if (unlikely(dif)) {
		return -EAGAIN;
	}

	*val = (((__u64)le16_to_cpu(packet.slice[1])) |
			(((__u64)le16_to_cpu(packet.slice[3])) << 16) |
			(((__u64)le16_to_cpu(packet.slice[5])) << 32) |
			(((__u64)le16_to_cpu(packet.slice[7])) << 48));
	*seq = le16_to_cpu(packet.slice[0]);
	return 0;
}

int
sbts_p2pshm_write64(__u64 key, __u64 val, __u16 seq)
{
	int ret = __p2pshm_enable();
	struct p2pshm_info *shm;
	/* avoid compiler optimization */
	volatile __u32 *va;

	if (unlikely(ret)) {
		return ret;
	}

	va = (volatile __u32 *)__p2pshm_key2va_4sc(NULL, key);
	if (unlikely(!va)) {
		cn_dev_err("host p2pshm(key %#llx) is invalid",
				(unsigned long long)key);
		return -EFAULT;
	}

	ret = __p2pshm_write64_4sc_relaxed(va, val, seq);
	if (unlikely(ret)) {
		cn_dev_err("local write(key %#llx) failed",
				(unsigned long long)key);
		return ret;
	}

	/* flush store-buffer */
	smp_wmb();

	down_read(&global_rwsem);
	list_for_each_entry(shm, &global_mlu_p2pshm.shms_list, entry) {
		struct cn_core_set *core = shm->core;

		if (!core) {
			continue;
		}

		va = (volatile __u32 *)__p2pshm_key2va_4sc(core, key);
		if (unlikely(!va)) {
			cn_dev_core_err(core, "p2pshm(key %#llx) is invalid",
					(unsigned long long)key);
			up_read(&global_rwsem);
			return -EFAULT;
		}

		ret = __p2pshm_write64_4sc_relaxed(va, val, seq);
		if (unlikely(ret)) {
			/* TODO */
			cn_dev_err("remote write(key %#llx) failed",
					(unsigned long long)key);
			up_read(&global_rwsem);
			return ret;
		}

	}

	up_read(&global_rwsem);
	/* flush wc-buffer */
	wmb();

	return 0;
}

int
sbts_p2pshm_read64(__u64 key, __u64 *val, __u16 *seq)
{
	int ret = __p2pshm_enable();
	/* avoid compiler optimization */
	volatile __u32 *va;

	if (unlikely(ret)) {
		return ret;
	}

	va = (volatile __u32 *)__p2pshm_key2va_4sc(NULL, key);
	if (unlikely(!va)) {
		cn_dev_err("host p2pshm(key %#llx) is invalid",
				(unsigned long long)key);
		return -EFAULT;
	}

	return __p2pshm_read64_4sc_relaxed(va, val, seq);
}

int
sbts_p2pshm_flush_write(void)
{
	struct p2pshm_info *shm;

	if (unlikely(global_mlu_p2pshm.state != P2PSHM_INIT_DONE)) {
		return -EIO;
	}

	/* flush store buffer and wc-buffer in host */
	wmb();

	down_read(&global_rwsem);
	list_for_each_entry(shm, &global_mlu_p2pshm.shms_list, entry) {
		if (!shm->core) {
			continue;
		}

		cn_bus_mb(shm->core->bus_set);
	}

	up_read(&global_rwsem);
	return 0;
}

static inline int
__p2pshm_key2hostiova_4sc(struct cn_core_set *core,
		__u64 key, __u64 *iova)
{
	struct p2pshm_info *shm;
	struct p2pshm_table *tbl;
	struct p2pshm_item *item;
	unsigned int algo = __p2pshm_key_get_algo(key);
	__u64 __key = __p2pshm_key_mask_algo(key);
	__u64 va;
	int i, find_flag = 0;

	if (unlikely(algo != P2PSHM_ALGO_4SC)) {
		cn_dev_core_err(core, "key %#llx algo %d is invalid",
				(unsigned long long)key,
				algo);
		return -EINVAL;
	}

	shm = __core2p2pshm_info(core);
	if (unlikely(!shm)) {
		cn_dev_core_err(core, "shm is invalid");
		return -ENODEV;
	}
	tbl = shm->p2pshm_tbl;
	for (i = 0; i < tbl->ncards; i++) {
		item = &tbl->item[i];
		if (item->shm == &global_mlu_p2pshm.host_shm) {
			find_flag = 1;
			break;
		}
	}
	if (!find_flag) {
		cn_dev_core_err(core, "cant find shm host item");
		return -ENODEV;
	}

	va = item->io_addr + __key;
	if (__p2pshm_addr_is_valid((void *)va, (void *)item->io_addr,
				item->shm->mem.p2pshm_sz)) {
		*iova = va;
		return 0;
	} else {
		*iova = 0;
		return -EINVAL;
	}
}

int sbts_p2pshm_get_hostiova_by_card(struct cn_core_set *core,
		__u64 key, __u64 *iova)
{
	int ret = __p2pshm_enable();

	if (unlikely(ret)) {
		return ret;
	}

	if (!P2PSHM_TYPE_HAVE_HW(global_mlu_p2pshm.reg_type)) {
		return -ENODEV;
	}

	return __p2pshm_key2hostiova_4sc(core, key, iova);
}

u64 sbts_p2pshm_get_hostkva(__u64 key)
{
	int ret = __p2pshm_enable();

	if (unlikely(ret)) {
		return 0;
	}

	if (!P2PSHM_TYPE_HAVE_HW(global_mlu_p2pshm.reg_type)) {
		return 0;
	}
	/* get host va */
	return (u64)__p2pshm_key2va_4sc(NULL, key);
}

static void __p2pshm_dump_mem(struct seq_file *m, struct p2pshm_info *shm)
{
#define FMT_PRT(str, val) \
	seq_printf(m, "%-30s at %#llx\n", str, (unsigned long long)(val))

	FMT_PRT("shm kernel va", shm->mem.shm_host_kva);
	FMT_PRT("shm device va", shm->mem.shm_dev_va);
	FMT_PRT("shm bus addr", shm->mem.shm_bus_addr);
	FMT_PRT("p2pshm kernel va", shm->mem.p2pshm_host_kva);
	FMT_PRT("p2pshm device va", shm->mem.p2pshm_dev_va);
	FMT_PRT("p2pshm bus addr", shm->mem.p2pshm_bus_addr);
	FMT_PRT("p2pshm cpu physical addr", shm->mem.p2pshm_cpu_phy_addr);
#undef FMT_PRT
}

static void __p2pshm_dump_begin(struct seq_file *m)
{
	seq_printf(m, "p2pshm debug info\n");
	seq_printf(m, "probe count %d\n", global_mlu_p2pshm.probe_cnt);
	seq_printf(m, "single copy max size %d\n",
			(int)global_mlu_p2pshm.single_copy_max_sz);
	seq_printf(m, "single copy min size %d\n",
			(int)global_mlu_p2pshm.single_copy_min_sz);
	seq_printf(m, "register type %#x\n", global_mlu_p2pshm.reg_type);
	seq_printf(m, "\n");
}

static void __p2pshm_dump_end(struct seq_file *m)
{
	seq_printf(m, "\n");
}

static void __p2pshm_dump_out_win(struct seq_file *m, struct p2pshm_info *shm)
{
	seq_printf(m, "%-30s at %#llx (type %d index %d)\n",
			"outbound window",
			(unsigned long long)shm->outb_win.dev_pa,
			(int)shm->outb_win.type,
			(int)shm->outb_win.idx);
}

static void __p2pshm_dump_item(struct seq_file *m, struct p2pshm_item *item,
		struct sbts_set *sbts)
{
	struct p2pshm_info *shm = item->shm;
	bool is_host = (shm->card_idx == (unsigned int)P2PSHM_HOST_IDX);
	const char *prefix_name = (shm->card_idx == sbts->core->idx ?
			"[Current] " : "");

	if (is_host == true) {
		seq_printf(m, "[Host]\np2pshm info(dev %px %s)\n",
				shm->dev,
				shm->avail_en ? "available" : "disable");
	} else {
		seq_printf(m, "%scard[%d]\np2pshm info(dev %px %s)\n",
				prefix_name,
				shm->card_idx,
				shm->dev,
				shm->avail_en ? "available" : "disable");
	}
	seq_printf(m, "%-30s at %#llx (type %d)\n", "io address",
			(unsigned long long)item->io_addr, item->map_type);
	seq_printf(m, "register type %#x ", shm->reg_type);
	__p2pshm_dump_mem(m, shm);
	__p2pshm_dump_out_win(m, shm);
	seq_printf(m, "\n");
}

static void __p2pshm_dump_all_shms(struct seq_file *m, struct sbts_set *sbts)
{
	struct p2pshm_info *shm = __core2p2pshm_info(sbts->core);
	struct p2pshm_table *tbl;
	unsigned int i;

	if (unlikely(!shm)) {
		seq_printf(m, "p2pshm is not ready");
		return;
	}

	tbl = shm->p2pshm_tbl;
	if (unlikely(!tbl)) {
		seq_printf(m, "p2pshm is not ready");
		return;
	}

	for (i = 0; i < tbl->ncards; ++i) {
		struct p2pshm_item *item = &tbl->item[i];

		__p2pshm_dump_item(m, item, sbts);
	}

}

void cn_p2pshm_proc_dump(struct seq_file *m, struct cn_core_set *core)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;

	if (!sbts) {
		seq_printf(m, "sbts is null\n");
		return;
	}

	if (unlikely(global_mlu_p2pshm.state == P2PSHM_DISABLE)) {
		seq_printf(m, "p2pshm is disable(%s)\n",
				p2pshm_err_strs.str[global_mlu_p2pshm.err]);
		return;
	}

	if (unlikely(global_mlu_p2pshm.state != P2PSHM_INIT_DONE)) {
		seq_printf(m, "p2pshm is not ready(state %d)\n",
				global_mlu_p2pshm.state);
		return;
	}

	__p2pshm_dump_begin(m);
	__p2pshm_dump_all_shms(m, sbts);
	__p2pshm_dump_end(m);
}

void cn_p2pshm_global_post_exit(void)
{
	/* flush and wait post_init worker completion */
	if (global_mlu_p2pshm.post_init_worker) {
		/* make post_init worker exit */
		global_mlu_p2pshm.force_exit = true;
		/* guarantee @force_exit updated */
		smp_mb();

		wait_for_completion(&global_mlu_p2pshm.post_init_exited);
		global_mlu_p2pshm.post_init_worker = NULL;
	}

	/* force override */
	global_mlu_p2pshm.state = P2PSHM_PRE_EXIT;
	/* guarantee @state updated */
	smp_mb();

	__p2pshm_unmap();
	__host_p2pshm_exit();
}

static void __p2pshm_shms_leak_check(void)
{
	struct p2pshm_info *shm, *n;

	if (list_empty(&global_mlu_p2pshm.shms_list)) {
		return;
	}

	list_for_each_entry_safe(shm, n, &global_mlu_p2pshm.shms_list, entry) {
		if (shm->card_idx == (unsigned int)P2PSHM_HOST_IDX) {
			cn_dev_err("shm host is possibly lost");
		} else {
			if (shm->core) {
				cn_dev_err("shm core idx %d is possibly lost",
						(unsigned int)shm->card_idx);
			}

		}
		global_mlu_p2pshm.probe_cnt--;
		list_del_init(&shm->entry);
		cn_kfree(shm);
	}

}

static int __p2pshm_post_init_work_raw(void *data)
{
	enum p2pshm_err_code err_code = P2PSHM_SUCCESS;

	if (P2PSHM_TYPE_ONLY_HW(global_mlu_p2pshm.reg_type))
		goto init_host;

	err_code = __single_copy_sz_check();
	if (err_code) {
		goto err;
	}

	err_code = __p2p_matrix_test();
	if (err_code) {
		goto err;
	}

init_host:
	/* host p2pshm init */
	err_code = __host_p2pshm_init(SBTS_P2PSHM_SZ);
	if (err_code) {
		goto err;
	}

	err_code = __p2pshm_map();
	if (err_code) {
		goto host_p2pshm_exit;
	}

	/* allocator init */
	err_code = __allocator_init(P2PSHM_GRAIN_NUM, P2PSHM_GRAIN_SZ_SHIFT);
	if (err_code) {
		goto p2pshm_unmap;
	}

	global_mlu_p2pshm.state = P2PSHM_INIT_DONE;
	smp_mb();
	wake_up_interruptible(&global_mlu_p2pshm.wait_init);
	return 0;

p2pshm_unmap:
	__p2pshm_unmap();
host_p2pshm_exit:
	__host_p2pshm_exit();
err:
	RECORD_ERR_ONCE(err_code);
	return 0;
}

static int cn_p2pshm_post_init_work(void *data)
{
	int ret = __p2pshm_post_init_work_raw(data);

	complete(&global_mlu_p2pshm.post_init_exited);
	return ret;
}

int cn_p2pshm_global_post_init(void)
{
	struct p2pshm_info *shm;

	if (unlikely(global_mlu_p2pshm.state == P2PSHM_DISABLE)) {
		cn_dev_info("CPU arch unsupport, P2PSHM disabled");
		return 0;
	}

	if (unlikely(!global_mlu_p2pshm.probe_cnt)) {
		cn_dev_err("probe cnt is 0");
		RECORD_ERR_ONCE(P2PSHM_INIT_FAIL);
		return 0;
	}

	/* disable p2pshm if exists probe without register
	 * or multi-cards registered diff type */
	list_for_each_entry(shm, &global_mlu_p2pshm.shms_list, entry) {
		if (shm->reg_type == SBTS_P2PSHM_REG_INIT) {
			RECORD_ERR_ONCE(P2PSHM_MLU_ARCH_UNSUPPORT);
			return 0;
		}
		global_mlu_p2pshm.reg_type &= shm->reg_type;
		if (!global_mlu_p2pshm.reg_type) {
			RECORD_ERR_ONCE(P2PSHM_MIX_TYPE_UNSUPPORT);
			return 0;
		}
	}

	cn_dev_debug("p2pshm probe cnt == reg cnt(%d)",
			global_mlu_p2pshm.probe_cnt);
	init_completion(&global_mlu_p2pshm.post_init_exited);
	global_mlu_p2pshm.post_init_worker =
			sbts_kthread_run(cn_p2pshm_post_init_work, NULL,
			"cn_p2pshm_post_init_work");
	if (IS_ERR(global_mlu_p2pshm.post_init_worker)) {
		cn_dev_err("create p2pshm post init worker failed");
		global_mlu_p2pshm.post_init_worker = NULL;
		RECORD_ERR_ONCE(P2PSHM_INIT_FAIL);
	}
	return 0;
}

void cn_p2pshm_global_pre_exit(void)
{
	/* For Debug */
	__p2pshm_shms_leak_check();

	__allocator_exit();

	global_mlu_p2pshm.state = P2PSHM_EXIT_DONE;
	/* guarantee @state updated */
	smp_mb();
}

/* only support x86-64 */
#ifndef CONFIG_X86_64
int cn_p2pshm_global_pre_init(void)
{
	memset(&global_mlu_p2pshm, 0, sizeof(global_mlu_p2pshm));
	global_mlu_p2pshm.reg_type = SBTS_P2PSHM_REG_INIT;
	init_waitqueue_head(&global_mlu_p2pshm.wait_init);
	INIT_LIST_HEAD(&global_mlu_p2pshm.shms_list);
	RECORD_ERR_ONCE(P2PSHM_CPU_ARCH_UNSUPPORT);
	return 0;
}
#else /* CONFIG_X86_64 */
int cn_p2pshm_global_pre_init(void)
{
	memset(&global_mlu_p2pshm, 0, sizeof(global_mlu_p2pshm));
	/* begin from support all */
	global_mlu_p2pshm.reg_type = SBTS_P2PSHM_REG_ALL;
	init_waitqueue_head(&global_mlu_p2pshm.wait_init);
	INIT_LIST_HEAD(&global_mlu_p2pshm.shms_list);
	global_mlu_p2pshm.state = P2PSHM_PRE_INIT;
	/* guarantee @state updated */
	smp_mb();
	return 0;
}
#endif
