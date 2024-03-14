/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/spinlock_types.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/ptrace.h>
#include <linux/kthread.h>
#include <linux/mman.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include "cndrv_genalloc.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_mcc.h"
#include "cndrv_debug.h"
#include "hal/cn_mem_hal.h"
#include "camb_mm.h"
#include "include/camb_mm_priv.h"
#include "cndrv_commu.h"
#include "cndrv_gdma.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_ipcm.h"
#include "cndrv_udvm.h"
#include "camb_mm_rpc.h"
#include "camb_udvm.h"
#include "camb_mm_compat.h"
#include "camb_mm_tools.h"
#include "camb_mm_pgretire.h"
#include "camb_p2p_remap.h"
#include "camb_linear_remap.h"
#include "camb_vmm.h"
#include "cndrv_fa.h"
#include "cndrv_df.h"
#include "cndrv_sbts.h"
#include "cndrv_lpm.h"
#include "cndrv_mcu.h"
#include "cndrv_mem_perf.h"

#define POOL_PAGE_SHIFT			(12)
#define SMMUV2_VIRT_BASE		(0x8000000000)

/*reserved memory is a continuous space start from 0 offset*/
/*all the card has the same info for init process*/
/**
 * |------ 0x0
 * |
 * | rpc_reserved (4KB, arm boot flag)
 * |
 * |------- 0x1000
 * |
 * | commu_reserved (64KB)
 * |
 * |------- 0x11000
 * |
 * | kernel_debug_reserved (1MB record arm dmesg for DFX)
 * |
 * |------- 0x111000
 * |
 * | pgretire_reserved (1MB record retired address info for arm)
 * |
 * |------- 0x211000
 * |
 * | IPCM virtio (288KB)
 * |
 * |------- 0x259100
 **/
static struct shm_rsrv_info shm_rev[] = {
	[SHM_RPC_RESV] = {"rpc_reserved", 0x1000}, /*phys 0x4800,0000*/
	[SHM_COMMU_RESV] = {"commu_reserved", 0x10000}, /*phys 0x4800,1000*/
#ifndef CONFIG_CNDRV_EDGE
	[SHM_KDBG_RESV] = {"kernel_debug_reserved", 0x100000}, /*phys 0x4801,1000*/
	[SHM_PGRE_RESV] = {"pgretire_reserved", PGRETIRE_SHM_REV_SZ}, /*phys 0x4811,1000*/
	/* configs_reserved offset fixed at 0x211000 can't be modified, uboot and resource_arm use it!*/
	[SHM_CFGS_RESV] = {"configs_reserved", 0x1000}, /*phys 0x4821,1000*/
	[SHM_KDUMP_RESV] = {"kdump_reserved", 0x2000}, /*phys 0x4821,2000*/
#endif
};

/*
 * pf's ipcm inbound offset: layout after shm_rev[]
 * vf's ipcm inbound offset: from 0
 */
static struct shm_rsrv_info shm_rev_ipcm[] = {
	/* for IPCM */
	{"vdev0vring0", 0x10000},
	{"vdev0vring1", 0x10000},
	{"vdev0buffer", 0x80000},
	{"rsc_table0", 0x1000},
};

/*
 * mlu370 need reserved mdr memory from inbound share memory range
 */
static struct shm_rsrv_info shm_rev_mdr = {
	"mdr_reserved", C30S_MDR_RESERVE_SZ
};

/*
 * mlu370 need reserved p2pshm memory from inbound share memory range
 */
static struct shm_rsrv_info shm_rev_sbts = {
	SBTS_P2PSHM_NAME, SBTS_P2PSHM_SZ
};

/*
 * mlu590/mlu585 need reserved data_outbound_pageshm memory from inbound share memory range
 */
static struct shm_rsrv_info shm_rev_dob_page[] = {
	{"dob_page_reserved", 0x10000},
};

/*
 * name MUST be diff from inbound cause we use the same list: shm_rsrv_list.
 *
 * ipcm must reserved cause we no need a extra ctrlq to sync,
 * arm need axi_addr to create vq while boot, and at that time vf driver may not loaded.
 *
 * commu must be reserved first cause serv_daemon_server run before commu_post_init(),
 * so commu_lib can't get the right ctrlq offset while outbound enabled
 */
static struct shm_rsrv_info ob_shm_rev[] = {
	{"commu_OB", 0x2000},
};

static struct shm_rsrv_info ob_shm_rev_ipcm[] = {
	{"vdev0vring0_OB", 0x10000},
	{"vdev0vring1_OB", 0x10000},
	{"vdev0buffer_OB", 0x40000},
};

static struct shm_rsrv_info shm_rev_sram = {
	"sram_reserved", 0/*size will get from bus,here is zero.*/
};

static struct shm_rsrv_info sram_rev_sbts = {
	"sram_reserved_AOP", 20 << 10 /*16k for pcie atomic op & sbts.*/
};

struct shm_rsrv_priv *__shm_get_handle_by_name(void *mem_set, unsigned char *name)
{
	struct cn_mm_set *mm_set = mem_set;
	struct shm_rsrv_priv *tmp = NULL;
	struct shm_rsrv_priv *pos = NULL;
	struct shm_rsrv_priv *ret_handle = NULL;

	list_for_each_entry_safe(pos, tmp, &mm_set->shm_rsrv_list, list) {
		if (strncmp(name, pos->name, sizeof(pos->name)) == 0) {
			ret_handle = pos;
			break;
		}
	}

	if (ret_handle == NULL)
		return ERR_PTR(-EINVAL);

	return ret_handle;
}

char *__shm_get_name_by_dev_vaddr(void *mem_set, dev_addr_t dev_vaddr)
{
	struct cn_mm_set *mm_set = mem_set;
	struct shm_rsrv_priv *tmp = NULL;
	struct shm_rsrv_priv *pos = NULL;
	struct shm_rsrv_priv *ret_handle = NULL;

	list_for_each_entry_safe(pos, tmp, &mm_set->shm_rsrv_list, list) {
		if (dev_vaddr == pos->rev_dev_vaddr) {
			ret_handle = pos;
			break;
		}
	}

	if (ret_handle == NULL)
		return NULL;

	return ret_handle->name;
}

int mempool_init(struct mempool_t *pool, host_addr_t virt,
			phys_addr_t phys, unsigned long size, struct cn_mm_set *mm_set)
{
	int ret=0;
	struct cn_core_set *core = NULL;

	if (mm_set)
		core = (struct cn_core_set *)mm_set->core;

	cn_dev_core_info(core, "create pool VA[%lx] -> PA[%llx] : SIZE[%lx]",
					 virt, phys, size);
	pool->virt = virt;
	pool->phys = phys;
	pool->size = size;
	atomic_long_set(&pool->used_size, 0);
	pool->pool = NULL;

	return ret;
}

void mempool_destroy(struct mempool_t *pool)
{
	if (pool->pool) {
		cn_gen_pool_destroy(pool->pool);
		pool->pool = NULL;
	}

}

int mempool_add_pool(struct mempool_t *pool, int min_alloc_order, unsigned long virt,
				phys_addr_t phys, unsigned long size, struct cn_mm_set *mm_set)
{
	int ret = 0;
	struct cn_core_set *core = NULL;

	if (mm_set)
		core = (struct cn_core_set *)mm_set->core;

	cn_dev_core_debug(core, "add pool to hostpool VA[%lx] -> PA[%llx] : SIZE[%lx]",
		   virt, phys, size);

	if (pool->pool) {
		cn_dev_core_err(core, "error: pool already alloc");
	}

	pool->pool = cn_gen_pool_create(min_alloc_order, -1);
	if (pool->pool == NULL) {
		cn_dev_core_err(core, "could not alloc mempool");
		return -1;
	}

	ret = cn_gen_pool_add_virt(pool->pool, virt, phys, size, -1);
	if (ret)
		cn_dev_core_err(core, "error to add mem pool");

	return ret;
}

static int mdr_pool_init(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct shm_rsrv_priv *shm_priv = NULL;
	struct mdr_info_t mdr_info = { 0 };
	int rpc_ret = 0, ret = 0;
	size_t result_len = 0;

	if (!mm_set->mdr_in_shm) {
		cn_dev_core_debug(core, "current board not need init mdr in host");
		return 0;
	}

	shm_priv = __shm_get_handle_by_name(mm_set, "mdr_reserved");
	if (IS_ERR_OR_NULL(shm_priv)) {
		cn_dev_core_err(core, "no found shm_priv for mdr_reserved");
		return -EINVAL;
	}

	cn_dev_core_info(core, "mdr_reserved: dev:%#llx, host:%#lx, size:%#lx",
					 shm_priv->rev_dev_vaddr, shm_priv->rev_host_vaddr,
					 shm_priv->rev_size);

	/* Call rpc init mdr_pool in ARM */
	mdr_info.size = shm_priv->rev_size;
	mdr_info.shm_axi_addr = shm_priv->rev_dev_vaddr;
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mdr_pool_init", &mdr_info,
						 sizeof(struct mdr_info_t), &rpc_ret, &result_len,
						 sizeof(int));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client query mem failed.");
		return ret;
	}

	if (rpc_ret < 0) {
		cn_dev_core_err(core, "mdr_pool init in arm failed");
		return rpc_ret;
	}

	return 0;
}

/*
 *NOTE: Sram va need alloc dynamicly in host, so could not config in the
 * dm_early_init. However the config in vf bar0 base is different with pf,
 * so we need to trans va base to arm for remap win config.
 */
static int sram_remap_peer_config(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct cn_bus_set *bus_set= core->bus_set;
	struct domain_resource resource;
	int rpc_ret = 0, ret = 0;
	struct sram_mem_addr_set sram_info;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	dev_addr_t pa_sz, va_addr, pa_addr;

	if (!cn_bus_pcie_sram_able(bus_set)) {
		cn_dev_core_info(core, "current board not need init sram remap");
		return 0;
	}

	memset(&resource, 0, sizeof(resource));
	if (bus_set->get_resource(bus_set->priv, &resource)) {
		cn_dev_core_err(core, "PCI: can not get pci bar res");
		return -EINVAL;
	}

	va_addr = cn_shm_get_dev_addr_by_name((void*)core, "sram_reserved");
	if (IS_ERR_OR_NULL((void *)va_addr)) {
		cn_dev_core_err(core, "get sram_reserved dev addr error.");
		return -EINVAL;
	}

	pa_addr = resource.sram_pa_base;
	pa_sz = resource.sram_pa_size;
	cn_dev_core_info(core, "get sram reserved: iova:%#llx, dev pa:%#llx, size:%#llx",
					va_addr, pa_addr, pa_sz);

	sram_info.shm_iova = va_addr;
	sram_info.shm_pa = pa_addr;
	sram_info.shm_size = pa_sz;

	/* Call rpc init sram remap in ARM */
	memset(&remsg, 0x00, sizeof(struct ret_msg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_config_sram_win", &sram_info,
						 sizeof(struct sram_mem_addr_set),
						 &remsg, &result_len, sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc call fail, ret:%d", ret);
		return ret;
	}

	if (remsg.ret) {
		cn_dev_core_err(core, "sram remap set in arm failed");
		return rpc_ret;
	}

	return 0;
}

static int __dev_shm_allocate_padded(void *mem_set, size_t aligned,
					host_addr_t *host, dev_addr_t *dev)
{
	struct cn_mm_set *mm_set = mem_set;
	size_t allocated_size = 0, padded_size = 0UL;

	struct shm_rsrv_priv *tmp = NULL;
	struct shm_rsrv_priv *pos = NULL;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	list_for_each_entry_safe(pos, tmp, &mm_set->shm_rsrv_list, list) {
		if (pos->type == CN_SHM_INBD)
			allocated_size += pos->rev_size;
	}

	padded_size = ALIGN(allocated_size, aligned);
	padded_size -= allocated_size;

	return cn_device_share_mem_alloc(0, host, dev, padded_size, core);
}

static int
__dev_shm_free_padded(void *mem_set, host_addr_t host, dev_addr_t dev)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	return cn_device_share_mem_free(0, host, dev, core);
}

/**
 * shm_reserved_init_sram don't create pminfo to insert_mapinfo,
 * because iova maybe equal with cn_sram_alloc's iova.RB tree
 * can't insert same iova.
 **/
static int
shm_reserved_init_sram(void *mem_set, struct shm_rsrv_info *shm_resv,
					   int n, int shm_type)
{
	int i = 0;
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	host_addr_t rev_host_vaddr = (host_addr_t)-1;
	dev_addr_t rev_dev_vaddr = (dev_addr_t)-1;
	phys_addr_t rev_phy_addr;
	struct shm_rsrv_priv *shm_priv = NULL;
	int ret = -1;
	struct domain_resource resource;
	struct cn_bus_set *bus_set = core->bus_set;

	shm_priv = cn_kzalloc(sizeof(struct shm_rsrv_priv), GFP_KERNEL);
	if (!shm_priv) {
		cn_dev_core_err(core, "kzalloc shm_rsrv_priv data space error!");
		return -ENOMEM;
	}

	ret = camb_device_share_mem_alloc(&rev_host_vaddr,
			&rev_dev_vaddr, &rev_phy_addr, shm_resv[i].rev_size, 0x0, mm_set);
	if (ret) {
		cn_dev_core_err(core, "camb_device_share_mem_alloc fail.");
		goto out;
	}

	/**
	 * Avoid dirty shared mem access on some pretty rare occations
	 * such as VM shutting down WITHOUT decent driver exiting
	 **/
	if (core->board_info.platform != MLU_PLAT_VDK &&
			core->board_info.platform != MLU_PLAT_ZEBU) {
		memset_io((void *)rev_host_vaddr, 0x0, shm_resv[i].rev_size);
	}
	/* flush wc-buffer */
	wmb();

	cn_dev_core_info(core, "%s:alloc host[%lx] <-> dev[%llx], size = %#lx",
			shm_resv[i].name, rev_host_vaddr,
			rev_dev_vaddr, shm_resv[i].rev_size);

	if (strlen(shm_resv[i].name) + 1 > sizeof(shm_priv->name)) {
		cn_dev_core_err(core, "size of shm_priv->name is insufficient for %s, please enlarge it\n",
				shm_resv[i].name);
		ret = -EINVAL;
		goto out;
	}

	strcpy(shm_priv->name, shm_resv[i].name);

	shm_priv->rev_size = shm_resv[i].rev_size;
	shm_priv->rev_host_vaddr = rev_host_vaddr;
	shm_priv->rev_dev_vaddr = rev_dev_vaddr;
	shm_priv->type = shm_type;

	memset(&resource, 0, sizeof(resource));
	/*get sram address information form bus.*/
	if (bus_set->get_resource(bus_set->priv, &resource)) {
		cn_dev_core_err(core, "PCI: can not get pci bar res.");
		ret = -EINVAL;
		goto out;
	}

	shm_priv->rev_phy_addr = resource.sram_pa_base;

	list_add_tail(&shm_priv->list, &mm_set->shm_rsrv_list);

	return 0;
out:
	cn_kfree(shm_priv);
	return ret;
}

static int
shm_reserved_init_type(void *mem_set, struct shm_rsrv_info *shm_resv,
					   int n, int shm_type)
{
	int i = 0;
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	host_addr_t rev_host_vaddr = (host_addr_t)-1;
	dev_addr_t rev_dev_vaddr = (dev_addr_t)-1;
	phy_addr_t rev_phy_addr = (phy_addr_t)-1;
	struct shm_rsrv_priv *shm_priv = NULL;
	int ret = -1;

	for (i = 0; i < n; i++) {
		shm_priv = cn_kzalloc(sizeof(struct shm_rsrv_priv), GFP_KERNEL);
		if (!shm_priv) {
			cn_dev_core_err(core, "kzalloc shm_rsrv_priv data space error!");
			return -ENOMEM;
		}

		ret = -1;

		switch (shm_type) {
		case CN_SHM_INBD:
			ret = cn_device_share_mem_alloc(0, &rev_host_vaddr,
					&rev_dev_vaddr, shm_resv[i].rev_size, core);
			break;
		case CN_SHM_SRAM:
			ret = camb_sram_alloc_internal(0, &rev_host_vaddr,
					&rev_dev_vaddr, &rev_phy_addr, shm_resv[i].rev_size, core,
					__builtin_return_address(0));
			break;
		case CN_SHM_OUTBD:
			ret = cn_host_share_mem_alloc(0, &rev_host_vaddr,
					&rev_dev_vaddr, shm_resv[i].rev_size, core);
			break;
		default:
			cn_dev_core_err(core, "Flag should be 0(inbound) or 1(outbound)!!!");
			goto out;
		}

		if (ret) {
			cn_dev_core_err(core, "alloc reserved memory for %d failed", shm_type);
			goto out;
		}

		/* Avoid dirty shared mem access on some pretty rare occations
		 * such as VM shutting down WITHOUT decent driver exiting */
		if (core->board_info.platform != MLU_PLAT_VDK &&
				core->board_info.platform != MLU_PLAT_ZEBU) {
			memset_io((void *)rev_host_vaddr, 0x0, shm_resv[i].rev_size);
		}
		/* flush wc-buffer */
		wmb();

		cn_dev_core_info(core, "%s:alloc host[%lx] <-> dev[%llx], size = %#lx",
					shm_resv[i].name, rev_host_vaddr,
					rev_dev_vaddr, shm_resv[i].rev_size);

		if (strlen(shm_resv[i].name) + 1 > sizeof(shm_priv->name)) {
			cn_dev_core_err(core, "size of shm_priv->name is insufficient for %s, please enlarge it\n",
				shm_resv[i].name);
			ret = -EINVAL;
			goto out;
		}

		strcpy(shm_priv->name, shm_resv[i].name);

		shm_priv->rev_size = shm_resv[i].rev_size;
		shm_priv->rev_host_vaddr = rev_host_vaddr;
		shm_priv->rev_dev_vaddr = rev_dev_vaddr;
		shm_priv->rev_phy_addr = rev_phy_addr;
		shm_priv->type = shm_type;

		list_add_tail(&shm_priv->list, &mm_set->shm_rsrv_list);
	}

	return 0;

out:
	cn_kfree(shm_priv);
	return ret;
}

static int shm_reserved_init_aligned(void *mm_set, struct shm_rsrv_info *shm_resv,
		int n, int shm_type, int (*reserved_init_func)(void *, struct shm_rsrv_info *, int, int))
{
	host_addr_t padded_host_addr = 0UL;
	dev_addr_t  padded_dev_addr = 0UL;
	int ret = 0;

	ret = __dev_shm_allocate_padded(mm_set, shm_resv->rev_size,
			&padded_host_addr, &padded_dev_addr);
	if (ret) {
		cn_dev_err("allocate padded error.");
		return ret;
	}

	ret = reserved_init_func(mm_set, shm_resv, n, shm_type);
	if (ret) {
		cn_dev_err("call reserved func error.");
		return ret;
	}

	ret = __dev_shm_free_padded(mm_set, padded_host_addr, padded_dev_addr);
	if (ret) {
		cn_dev_err("free padded error.");
		return ret;
	}

	return ret;
}

static int sram_share_mem_init(void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct cn_bus_set *bus_set = core->bus_set;
	dev_addr_t iova, pa_addr, pa_size;
	struct domain_resource resource;
	host_addr_t host_addr = 0UL;
	int ret = 0;

	if (!cn_bus_pcie_sram_able(bus_set)) {
		cn_dev_core_debug(core, "skip sram init.");
		return 0;
	}

	memset(&resource, 0, sizeof(resource));

	/*get sram address information form bus.*/
	if (bus_set->get_resource(bus_set->priv, &resource)) {
		cn_dev_core_err(core, "PCI: can not get pci bar res");
		return -EINVAL;
	}
	pa_size = resource.sram_pa_size;
	pa_addr = resource.sram_pa_base;

	/*shm of sram's size get from bus.128kB is pf or sriov, 16kb is vf.*/
	shm_rev_sram.rev_size = pa_size;

	cn_dev_core_info(core, "sram from bus size:%#llx pa:%#llx size:%#llx",
			(u64)resource.sram_pa_size, (u64)resource.sram_pa_base,
			(u64)shm_rev_sram.rev_size);

	/*smmu remap window size and start addr need align*/
	ret = shm_reserved_init_aligned(mem_set, &shm_rev_sram, 1,
			CN_SHM_INBD, shm_reserved_init_sram);
	if (ret) {
		cn_dev_core_err(core, "reserved sram mem which shm_rev_sram error.");
		return ret;
	}

	iova = cn_shm_get_dev_addr_by_name((void *)core, "sram_reserved");
	if (IS_ERR_OR_NULL((void *)iova)) {
		cn_dev_core_err(core, "get sram_reserved dev addr error.");
		return -EINVAL;
	}

	host_addr = cn_shm_get_host_addr_by_name((void *)core, "sram_reserved");
	if (IS_ERR_OR_NULL((void *)host_addr)) {
		cn_dev_core_err(core, "get sram_reserved host addr error.");
		return -EINVAL;
	}

	mempool_init(&(mm_set->sram_pool), host_addr, pa_addr, pa_size, mm_set);
	mempool_add_pool(&(mm_set->sram_pool), POOL_PAGE_SHIFT, host_addr,
			pa_addr, pa_size, mm_set);

	/*sram iova = paddr offset + mm_set->sram_virt_base*/
	mm_set->sram_virt_base = iova;

	/*PF-SRIOV can not send rpc, so PF-SRIOV set remap window here.*/
	if (cn_is_mim_en(core) && !cn_core_is_vf(core)) {
		mm_set->smmu_ops.smmu_add_remap((void *)core, iova, pa_addr,
					pa_size, SMMU_RMPTYPE_SRAM);
	}

	if (!cn_core_is_vf(core)) {
		/*reserved atomicop for pcie*/
		ret = shm_reserved_init_type(mm_set, &sram_rev_sbts, 1, CN_SHM_SRAM);
	}

	return ret;
}

static void shm_reserved_init(void *mem_set)
{
	int n;
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	if (core->device_id == MLUID_370_DEV || core->device_id == MLUID_590_DEV) {
		return;
	}

	if (!cn_core_is_vf(core)) {
		n = ARRAY_SIZE(shm_rev);
		shm_reserved_init_type(mm_set, shm_rev, n, CN_SHM_INBD);
		if (cn_bus_outbound_able(core->bus_set)) {
			n = ARRAY_SIZE(ob_shm_rev);
			shm_reserved_init_type(mm_set, ob_shm_rev, n, CN_SHM_OUTBD);
		}
	}

	if (mm_set->mdr_in_shm) {
		shm_reserved_init_aligned(mem_set, &shm_rev_mdr, 1, CN_SHM_INBD, shm_reserved_init_type);
	}

	if (cn_ipcm_enable(core)) {
		n = ARRAY_SIZE(shm_rev_ipcm);
		shm_reserved_init_type(mm_set, shm_rev_ipcm, n, CN_SHM_INBD);
		if (cn_bus_outbound_able(core->bus_set)) {
			n = ARRAY_SIZE(ob_shm_rev_ipcm);
			shm_reserved_init_type(mm_set, ob_shm_rev_ipcm, n, CN_SHM_OUTBD);
		}
	}

	if (mm_set->devid == MLUID_370) {
		shm_reserved_init_type(mm_set, &shm_rev_sbts, 1, CN_SHM_INBD);
	}

	if (mm_set->devid == MLUID_590 || mm_set->devid == MLUID_580) {
		n = ARRAY_SIZE(shm_rev_dob_page);
		shm_reserved_init_type(mm_set, shm_rev_dob_page, n, CN_SHM_INBD);
	}
}

static void shm_reserved_exit(void *mem_set)
{
	struct shm_rsrv_priv *tmp = NULL;
	struct shm_rsrv_priv *pos = NULL;
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	if (core->device_id == MLUID_370_DEV) {
		return;
	}

	if (core->device_id == MLUID_590_DEV) {
		return;
	}

	if (!list_empty(&mm_set->shm_rsrv_list)) {
		list_for_each_entry_safe(pos, tmp, &mm_set->shm_rsrv_list, list) {
			cn_kfree(pos);
		}
	}
}

static void host_share_mem_exit(void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;

	mempool_destroy(&(mm_set->hostpool));
}

static int host_share_mem_init(void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	dev_addr_t phy = (dev_addr_t)-1;
	unsigned long size = 0;
	host_addr_t virt = (host_addr_t)-1;
	int shm_cnt = 0;
	int i = 0;

	shm_cnt = cn_bus_get_mem_cnt(core->bus_set);

	for (i = 0; i < shm_cnt; i++) {
		if (cn_bus_get_mem_type(core->bus_set, i) == CN_SHARE_MEM_HOST) {
			virt = (host_addr_t)cn_bus_get_mem_base(core->bus_set, i);
			size = cn_bus_get_mem_size(core->bus_set, i);
			phy = cn_bus_get_device_addr(core->bus_set, i);

			mempool_init(&(mm_set->hostpool), virt, phy, size, mm_set);
			mempool_add_pool(&(mm_set->hostpool), POOL_PAGE_SHIFT,
					virt, phy, size, mm_set);
			return 0;
		}
	}

	return -1;
}

static void device_share_mem_exit(void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;

	mempool_destroy(&(mm_set->devpool));
}

static void sram_share_mem_exit(void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	size_t size;
	host_addr_t host_vaddr;

	host_vaddr = cn_shm_get_host_addr_by_name(core, "sram_reserved");
	size = cn_shm_get_size_by_name(core, "sram_reserved");

	/*sram_reserved mem have not pminfo, need free here.*/
	if (!IS_ERR_OR_NULL((void *)host_vaddr)) {
		cn_gen_pool_free(mm_set->devpool.pool, host_vaddr, size);
		atomic_long_sub(size, &mm_set->devpool.used_size);
	}

	mempool_destroy(&(mm_set->sram_pool));
}

/*to init the device share memory pool*/
static int device_share_mem_init(void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	dev_addr_t phy = (dev_addr_t)-1;
	unsigned long size = 0;
	host_addr_t virt = (host_addr_t)-1;
	int shm_cnt = 0;
	int i = 0;

	shm_cnt = cn_bus_get_mem_cnt(core->bus_set);

	for (i = 0; i < shm_cnt; i++) {
		if (cn_bus_get_mem_type(core->bus_set, i) == CN_SHARE_MEM_DEV) {
			/*virt is kva of share mem*/
			virt = (host_addr_t)cn_bus_get_mem_base(core->bus_set, i);
			/*size is share mem size*/
			size = cn_bus_get_mem_size(core->bus_set, i);
			/*phy is phy address of share mem*/
			phy = cn_bus_get_mem_phyaddr(core->bus_set, i);
			/*init device share memory*/
			mempool_init(&(mm_set->devpool), virt, phy, size, mm_set);
			mempool_add_pool(&(mm_set->devpool), POOL_PAGE_SHIFT, virt, phy, size, mm_set);

			return 0;
		}
	}

	return -1;
}

static int krpc_client_init(struct cn_core_set *core)
{
	struct cn_mm_set *mm_set = core->mm_set;

	mm_set->endpoint = __mem_open_channel("commu_cn_mm_krpc", mm_set);
	if (mm_set->endpoint == NULL) {
		cn_dev_core_err(core, "__mem_open_channel(%s) failed\n", "commu_cn_mm_krpc");
		return -ENOMEM;
	}

	mm_set->mem_async_endpoint =
		__mem_open_channel("commu_cn_mm_async_krpc", mm_set);
	if (mm_set->mem_async_endpoint == NULL) {
		cn_dev_core_err(core, "__mem_open_channel(%s) failed\n", "commu_cn_mm_async_krpc");
		return -ENOMEM;
	}

	cn_dev_core_info(core, "cn memory krpc client register success");

	return 0;
}

static void krpc_client_deinit(struct cn_core_set *core)
{
	struct cn_mm_set *mm_set = core->mm_set;

	__mem_destroy_channel(core, &mm_set->endpoint);
	__mem_destroy_channel(core, &mm_set->mem_async_endpoint);
}

static int mm_priv_data_init(struct cn_mm_priv_data *mm_priv_data,
							   struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	mm_priv_data->mmroot = RB_ROOT;
	mm_priv_data->memcheck_magic = 0; /* Close MemCheck Debug as Default */
	rwlock_init(&mm_priv_data->node_lock);	/* lock used by rbtree insert/delete */
	spin_lock_init(&mm_priv_data->minfo_lock); /* lock used for thread concurrency */
	INIT_LIST_HEAD(&mm_priv_data->priv_list);

	mm_priv_data->udvm_priv = NULL;
	mm_priv_data->udvm_index = core->idx;
	INIT_LIST_HEAD(&mm_priv_data->udvm_node);
	INIT_LIST_HEAD(&mm_priv_data->minfo_list);
	spin_lock_init(&mm_priv_data->mmlist_lock);

	atomic_long_set(&mm_priv_data->used_size, 0);
	mutex_init(&mm_priv_data->uva_lock);/*lock fake_malloc address, write pminfo->uva, insert vma_list*/

	atomic64_set(&mm_priv_data->mem_lpm_count, 0);

	return 0;
}

static void mm_common_init(struct cn_mm_set *mm_set, void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	spin_lock_init(&mm_set->ipcm_lock);
	spin_lock_init(&mm_set->ffl_lock);

	INIT_LIST_HEAD(&mm_set->free_failure_list);
	INIT_LIST_HEAD(&mm_set->shm_rsrv_list);
	INIT_LIST_HEAD(&mm_set->ipcm_head);

	mm_set->phy_used_mem = DEFAULT_PHY_USED_MEM;
	mm_set->phy_total_mem = core->board_info.total_memory;
	cn_dev_core_info(core, "phy total:%#lx", mm_set->phy_total_mem);
	/*local memory*/
	mm_set->vir_used_mem = DEFAULT_VIR_USED_MEM;
	mm_set->vir_total_mem = VIRT_TOTAL_SIZE;
	cn_dev_core_info(core, "vir total:%#lx", mm_set->vir_total_mem);
}

static void mm_dev_init(struct cn_mm_set *mm_set, void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	unsigned long reg_size = 0, mem_size = 0;
	unsigned long reg_phyaddr = 0, mem_phyaddr = 0;
	int shm_cnt, i;

	/* the defult status of  page retirement is inactive. */
	mm_set->pgretire_enable = false;
	mm_set->pgretire_server_enable = false;

	/* the defult status of  peer_free is enabled. */
	mm_set->peer_free_enable = false;

	/* the default status of p2p remap is disabled. */
	mm_set->ppool.mode = PPOOL_MODE_DISABLE;

	/* the default status of linear remap is disabled. */
	mm_set->linear.is_support = false;

	/* the defult status of vmm is disable. */
	mm_set->vmm_enable = false;
	INIT_LIST_HEAD(&mm_set->vmm_pid_head);
	spin_lock_init(&mm_set->vmm_pid_lock);

	/* mdr memory default remap in bar2 area range */
	mm_set->mdr_in_shm = false;

	/* disable to notify the task push to do sync the LLC. */
	mm_set->notify_l1c_sync = false;

	/* the status of compress feature support. */
	mm_set->compress_support = false;
	mm_set->enable_compress_alloc = false;

	/* disable support separate memory alloc as default. */
	mm_set->separate_support = false;

	mm_set->obmap_support = false;

	/* the defult status of  delay free is active. */
	core->delay_free_enable = MEM_DELAYFREE_ENABLE;/*delay free enable*/

	shm_cnt = cn_bus_get_mem_cnt(core->bus_set);
	/* get the start address for remap window */
	reg_phyaddr = cn_bus_get_reg_phyaddr(core->bus_set);
	mem_phyaddr = cn_bus_get_mem_phyaddr(core->bus_set, 0);
	/* get the size of the remap windows, such as config or memory window */
	reg_size = cn_bus_get_reg_size(core->bus_set);
	for (i = 0; i < shm_cnt; i++) {
		if (cn_bus_get_mem_type(core->bus_set, i) == CN_SHARE_MEM_DEV) {
			mem_size = cn_bus_get_mem_size(core->bus_set, i);
			break;
		}
	}

	switch (core->device_id) {
	case MLUID_220:
		/*reset the size of remap windows for M.2*/
		reg_size = 0x4000000;
		mem_size = 0x4000000;
		mm_set->dev_virt_base = SMMUV2_VIRT_BASE + reg_size;
		break;
	case MLUID_220_EDGE:
		/*reset the size of remap windows for M.2*/
		reg_size = 0x2000000;
		mm_set->dev_virt_base = SMMUV2_VIRT_BASE + reg_size;
		break;
	case MLUID_270:
	case MLUID_270V:
	case MLUID_270V1:
		mm_set->dev_virt_base = SMMUV2_VIRT_BASE + mem_phyaddr - reg_phyaddr;
		break;
	case MLUID_290:
		mm_set->dev_virt_base = SMMUV2_VIRT_BASE + mem_phyaddr - reg_phyaddr;
		mm_set->pgretire_enable = true;
		break;
	case MLUID_290V1:
		mm_set->dev_virt_base = SMMUV2_VIRT_BASE + mem_phyaddr - reg_phyaddr;
		break;
	case MLUID_370:
		mm_set->ppool.mode = PPOOL_MODE_NORMAL;
		mm_set->pgretire_enable = true;
		mm_set->vmm_enable = true;
		mm_set->mdr_in_shm = true;
		mm_set->separate_support = true;
		mm_set->dev_virt_base = C30S_AXI_SHM_BASE;
		break;
	case MLUID_370V:
		mm_set->dev_virt_base = cn_bus_get_device_addr(core->bus_set, 0);
		break;
	case MLUID_580:
		/* while linear is supported, p2p_remap and mdr will be replaced with linear interface */
		mm_set->linear.is_support = true;
		mm_set->vmm_enable = true;
		mm_set->compress_support = true;
		mm_set->pgretire_enable = true;
		mm_set->dev_virt_base = C50_AXI_SHM_BASE;
		mm_set->obmap_support = cn_bus_outbound_able(core->bus_set);
		mm_set->enable_compress_alloc = true;
		break;
	case MLUID_590:
		/* while linear is supported, p2p_remap and mdr will be replaced with linear interface */
		mm_set->linear.is_support = true;
		mm_set->vmm_enable = true;
		mm_set->pgretire_enable = true;
		mm_set->dev_virt_base = C50_AXI_SHM_BASE;
		mm_set->obmap_support = cn_bus_outbound_able(core->bus_set);
		break;
	case MLUID_590V:
	case MLUID_580V:
		mm_set->obmap_support = cn_bus_outbound_able(core->bus_set);
		mm_set->dev_virt_base =
			cn_bus_get_device_addr(core->bus_set, 0);
		break;
	case MLUID_CE3226:
		mm_set->vmm_enable = true;
		mm_set->dev_virt_base = CE3226_AXI_SHM_BASE;
		break;
	case MLUID_PIGEON:
		mm_set->vmm_enable = true;
		mm_set->dev_virt_base = PIGEON_AXI_SHM_BASE;
		break;
	case MLUID_370_DEV:
		mm_set->dev_virt_base = 0;
		core->delay_free_enable = MEM_DELAYFREE_DISABLE;/*delay free disable*/
		mm_set->pgretire_server_enable = true;
		break;
	case MLUID_590_DEV:
		mm_set->dev_virt_base = 0;
		core->delay_free_enable = MEM_DELAYFREE_DISABLE;/*delay free disable*/
		mm_set->pgretire_server_enable = true;
		break;
	case MLUID_CE3226_EDGE:
		reg_size = 0x800000;
		mm_set->vmm_enable = true;
		mm_set->dev_virt_base = CE3226_AXI_SHM_BASE;
		core->delay_free_enable = MEM_DELAYFREE_DISABLE;/*delay free disable*/
		break;
		break;
	case MLUID_PIGEON_EDGE:
		reg_size = 0x800000;
		mm_set->vmm_enable = true;
		mm_set->compress_support = true;
		mm_set->dev_virt_base = PIGEON_AXI_SHM_BASE;
		core->delay_free_enable = MEM_DELAYFREE_DISABLE;/*defay free disable*/
		break;
	default:
		cn_dev_err("board[%#llx] not support", core->device_id);
		break;
	}

	mm_set->pcie_reg_size = reg_size;
	mm_set->pcie_mem_size = mem_size;
	mm_set->devid = core->device_id;
	/* default open dumpmeminfo */
	mm_set->is_dump_meminfo = true;
}

void cn_mem_get_feats_status(void *pcore, struct mem_feats_t *status)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = (struct cn_mm_set *)core->mm_set;

	status->vmm = mm_set->vmm_enable;
	status->vmm_handle2fd = mm_set->vmm_enable;
	status->compression = mm_set->compress_support;
	status->linear = mm_set->linear.is_support;
	status->linear_granularity = 1UL << 30;
}

/*
 * this function called only in _M_MEM_GET_IPU_RESV_MEM. For resume card when context create.
 */
int camb_mem_lpm_get(void *user, struct cn_core_set *core)
{
	struct file *fp = (struct file *)user;
	struct cn_mm_priv_data *mm_priv_data = __get_mm_priv(fp, core->mm_set);

	atomic64_inc(&mm_priv_data->mem_lpm_count);

	/*
	 * this ioctl means context create and need resume card and exit lowpower.
	 * cn_lpm_put_all_module_cnt will be called at do_exit.
	 */
	if (cn_lpm_get_all_module(core)) {
		cn_dev_core_err(core, "mem get lpm failed!");
		atomic64_dec(&mm_priv_data->mem_lpm_count);
		return -EINVAL;
	}
	return 0;
}

void camb_mem_lpm_put(void *user, struct cn_core_set *core)
{
	struct file *fp = (struct file *)user;
	struct cn_mm_priv_data *mm_priv_data = __get_mm_priv(fp, core->mm_set);

	/* put all count when dev close */
	cn_lpm_put_cnt_all_module(core, atomic64_read(&mm_priv_data->mem_lpm_count));
}

int cn_mem_private_data_init(void *fp_private_data)
{
	struct fp_priv_data *priv_data = fp_private_data;
	struct cn_mm_priv_data *mm_priv_data;
	struct cn_core_set *core = priv_data->core;
	struct cn_mm_set *mm_set = (struct cn_mm_set *)core->mm_set;

	priv_data->mm_priv_data = cn_kzalloc(sizeof(struct cn_mm_priv_data), GFP_KERNEL);
	if (!priv_data->mm_priv_data) {
		cn_dev_core_err(core, "kzalloc priv_data->cn_mm_priv_data failed.");
		return -ENOMEM;
	}

	mm_priv_data = (struct cn_mm_priv_data *)priv_data->mm_priv_data;

	mm_priv_data_init(mm_priv_data, mm_set);

	return 0;
}

int cn_mem_private_data_exit(void *fp_private_data)
{
	struct fp_priv_data *priv_data = fp_private_data;
	struct cn_mm_priv_data *mm_priv_data;

	/**
	 * BUGFIX:(DRIVER-11579)
	 * cn_mem_private_data_exit is called by cn_core_free_priv_data which
	 * couldn't guarantee that memory module handles(cn_mm_set, udvm_set, and
	 * more) is valid to be accessed.
	 *
	 * So be much more cautions to add other release job in this function;
	 **/

	mm_priv_data = priv_data->mm_priv_data;
	cn_kfree(mm_priv_data);
	priv_data->mm_priv_data = NULL;

	return 0;
}

/* @briefly introduce
 * When the thread or the driver is going to close, it is used to recycle
 * the whole allocated memory of one thread which is signed by tag parameter.
 */
int cn_mem_do_exit(u64 tag, void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct file *fp = (struct file *)tag;
	struct cn_mm_priv_data *mm_priv_data;
	int ret = 0, release_fa = 0;

	/* we will delete mm_priv_data from list in cn_mem_private_data_exit */
	mm_priv_data = __get_mm_priv(fp, mm_set);
	if (!mm_priv_data) {
		cn_dev_core_err(core, "get mem priv data failed");
		return -EINVAL;
	}

	camb_mem_lpm_put(fp, core);

	/**
	 * fp && fp->private_data means that current context belongs to process exit;
	 * core->open_count == 1 means that current process is the last process
	 * hold this device, we can do fa_shrink after process memory release.
	 **/
	if (fp && fp->private_data && (core->open_count == 1))
		release_fa = 1;

	if (mm_priv_data->udvm_priv) {
		ret = camb_priv_data_list_release(mm_priv_data);
		udvm_unregister_privdata(mm_priv_data);

	} else {
		camb_priv_data_rbtree_release(mm_priv_data, mm_set, tag);
	}

	if (release_fa)
		camb_fa_shrink(mm_set, mm_set->fa_array, true);

	return ret;
}

/**
 *	@breifly introduce
 *	It is used to release the whole allocated device memory.
 */
void cn_mm_release_res(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	/**
	 * NOTE:
	 * 1. release memory node hanging on mm_set->mem_priv_data rbtree;
	 * 2. release workqueue and hrimter used for delay free
	 * 3. clear msg_list's memory nodes which belong to mm_set->mem_priv_data rbtree;
	 **/
	cn_mem_do_exit(0, pcore);

	flush_work(&mm_set->free_worker);
	cancel_work_sync(&mm_set->free_worker);
	camb_delay_free_exit(mm_set);
	core->delay_free_enable = MEM_DELAYFREE_DISABLE;/*delay free disable*/

	/* peer free exit before commu exit */
	camb_peer_free_exit(pcore);

	/* free fast alloc chunks resource before commu_exit */
	camb_fa_shrink(mm_set, mm_set->fa_array, true);

	/* release free_failure list resource */
	camb_clear_free_failure_list(mm_set);

	/* release p2p pool remap resource */
	camb_p2p_normal_remap_exit(mm_set);

	/* release linear remap resource */
	camb_linear_remap_exit(mm_set);
}

/* @briefly introduce
 * It will be used to allocate the all management resouce, usually in the
 * process of driver probe.
 */
int cn_mm_init(struct cn_core_set *core)
{
	struct cn_mm_set *mm_set;

	mm_set = cn_kzalloc(sizeof(struct cn_mm_set), GFP_KERNEL);
	if (mm_set == NULL) {
	    cn_dev_core_err(core, "alloc mm_set fail");
	    return -ENOMEM;
	}

	core->mm_set = mm_set;
	mm_set->core = core;
	/* public mm_priv_data init */
	mm_priv_data_init(&mm_set->mm_priv_data, mm_set);

	mm_common_init(mm_set, core);

	mm_dev_init(mm_set, core);
	/*to init memory hardware,such as smmu and llc*/
	cn_mem_hal_init(mm_set);
	/*init device share memory*/
	device_share_mem_init(mm_set);
	/*init host share memory*/
	host_share_mem_init(mm_set);

	/*reserved device share memory*/
	shm_reserved_init(mm_set);

	if (sram_share_mem_init(mm_set)) {
		cn_dev_err("sram share mem init error.");
		goto sram_fail;
	}

	if (camb_fa_init(core))
		goto sram_fail;

	if (cn_mem_perf_init(mm_set)) {
		cn_dev_core_err(core, "mem perf init failed.");
		goto sram_fail;
	}

	mm_set->alloc_align.align_enable = MEM_ALLOC_ALIGN_DISABLE;
	mm_set->alloc_align.align_order = 14;

	if (mm_set->pgretire_enable)
		camb_init_page_retirement(mm_set);

	camb_free_ts_init(mm_set);

	mm_set->numa_enable = false;

	return 0;

sram_fail:
	camb_shm_do_exit(0, mm_set);
	sram_share_mem_exit(mm_set);
	shm_reserved_exit(mm_set);
	host_share_mem_exit(mm_set);
	device_share_mem_exit(mm_set);
	cn_mem_hal_exit(mm_set);
	cn_kfree(core->mm_set);

	return -ENOMEM;
}

int cn_mm_bootargs_init(struct cn_core_set *core)
{
	struct cn_mm_set *mm_set = core->mm_set;
	char mm_bootargs[256];

	cn_dev_core_info(core, "Set memory module paramter into cambr_configs!");
	cn_dev_core_info(core, "\t inline_ecc_en: %d", core->ile_en);
	cn_dev_core_info(core, "\t linear_en: %d", mm_set->linear.is_support);

	sprintf(mm_bootargs, "ile_en=%d;linear_en=%d;", core->ile_en,
			mm_set->linear.is_support);

	strncat(core->cambr_configs, mm_bootargs, strlen(mm_bootargs));
	return 0;
}

/* @briefly introduce
 * By contrast with cn_mm_init, it will be used to free the whole management
 * resouces, usually in the process of driver remove. And make sure that the
 * whole device memory has been released by the cn_mm_release_res function.
 */
void cn_mm_exit(struct cn_core_set *core)
{
	struct cn_mm_set *mm_set = core->mm_set;

	if (!mm_set)
		return ;

	camb_fast_alloc_exit(mm_set->fa_array);

	cn_mem_perf_exit(mm_set);

	camb_free_ts_deinit(mm_set);

	camb_shm_do_exit(0, mm_set);

	sram_share_mem_exit(mm_set);

	shm_reserved_exit(mm_set);
	host_share_mem_exit(mm_set);
	device_share_mem_exit(mm_set);
	cn_mem_hal_exit(mm_set);

	cn_kfree(core->mm_set);
}

void cn_mm_reinit(void *pcore)
{
	cn_mem_hal_reinit(pcore);
}

/*For get data otbound mem Axi addr and IOVA base in device*/
int cn_data_ob_init(void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;
	struct cn_core_set *core = mm_set->core;
	unsigned long size = 0;
	dev_addr_t phy;
	host_addr_t virt;
	struct mem_ob_ctrl ctrl_info;
	struct ret_msg remsg;
	int len;
	int ret;
	unsigned int lvl1_pg, lvl2_pg;
	unsigned int lvl1_pg_cnt, lvl2_pg_cnt;
	u64 lvl1_base, lvl2_base;
	int ori_pg_cnt = 2048;
	unsigned long ob_base_addr;
	int order;

	if (cn_bus_get_dob_win_info(core->bus_set, &lvl1_pg, &lvl1_pg_cnt, &lvl1_base,
					&lvl2_pg, &lvl2_pg_cnt, &lvl2_base)) {
		cn_dev_info("This platform don't support get_device_pointer function.");
		return 0;
	}
	ob_base_addr = lvl1_base - (ori_pg_cnt - lvl1_pg_cnt) * (1 << lvl1_pg);

	len = __get_rpc_buf_size(core->support_ipcm);
	if (sizeof(struct ob_data_rpc_t) > len) {
		WARN(1, "please fix MAX_OB_PCI_ADDR_CNT if change rpc buf size.");
		return -EINVAL;
	}

	/*send device_pa/lvl1_pg/lvl2_pgl/total_win_cnt to device*/
	ctrl_info.cmd = OB_CMD_CONFIG_OB;
	ctrl_info.ob_info.device_pa = ob_base_addr;
	ctrl_info.ob_info.lvl1 = 1 << lvl1_pg;
	ctrl_info.ob_info.lvl2 = 1 << lvl2_pg;
	ctrl_info.ob_info.total_win_cnt = ori_pg_cnt * 2;
	ret = camb_call_mem_ob_ctl_rpc(mm_set, &ctrl_info, &remsg);
	if (ret) {
		cn_dev_err("send outbound configuration to device error");
		goto exit;
	}

	memset(&ctrl_info, 0, sizeof(ctrl_info));

	/*get iova from devie*/
	ctrl_info.cmd = OB_CMD_GET_ADDRESS;
	ret = camb_call_mem_ob_ctl_rpc(mm_set, &ctrl_info, &remsg);
	if (ret) {
		cn_dev_err("get outbound iova address error");
		goto exit;
	}
	if (remsg.ob_addr.device_pa != ob_base_addr || remsg.ob_addr.iova_size <
			((unsigned long)((1 << lvl1_pg) + (1 << lvl2_pg)) * ori_pg_cnt)) {
		cn_dev_err("outbound address info error. %#lx %#x %#x %#lx %#x %#lx",
				ob_base_addr, lvl1_pg, lvl2_pg, remsg.ob_addr.device_pa,
				((1 << lvl1_pg) + (1 << lvl2_pg)) * ori_pg_cnt,
				remsg.ob_addr.iova_size);
		ret = -EINVAL;
		goto exit;
	}

	/*init device pa lvl1 pool*/
	phy = lvl1_base;
	virt = remsg.ob_addr.iova_start +
		(ori_pg_cnt - lvl1_pg_cnt) * (1 << lvl1_pg);
	size = (1 << lvl1_pg) * lvl1_pg_cnt;
	/*min order is 16(64KB)*/
	order = lvl1_pg > 16 ? lvl1_pg : 16;
	mempool_init(&(mm_set->hostpool_l), virt, phy, size, mm_set);
	mempool_add_pool(&(mm_set->hostpool_l), order, virt, phy, size, mm_set);

	/*init device pa lvl2 pool*/
	virt += size;
	phy += size;
	size = (1 << lvl2_pg) * lvl2_pg_cnt;
	/*min order is 16(64KB)*/
	order = lvl2_pg > 16 ? lvl2_pg : 16;
	mempool_init(&(mm_set->hostpool_h), virt, phy, size, mm_set);
	mempool_add_pool(&(mm_set->hostpool_h), order, virt, phy, size, mm_set);

	return 0;

exit:
	WARN_ON("data outbound init error\n");
	return ret;
}

void cn_data_ob_exit(void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;

	mempool_destroy(&(mm_set->hostpool_l));
	mempool_destroy(&(mm_set->hostpool_h));
}

int cn_mm_last_init(struct cn_core_set *core)
{
	struct cn_mm_set *mm_set = core->mm_set;

	if (!cn_core_is_vf(core) && cn_is_mim_en(core)) {
		cn_dev_core_debug(core, "not pf-only or vf");
		return 0;
	}

	/*close device FA only if pcore is vf*/
	if (cn_core_is_vf(core)) {
		camb_mem_fa_dev_ctrl(mm_set, MEM_FA_DISABLE);
	}

	if (!cn_core_is_vf(core) && !cn_is_mim_en(core)) {
		/*Note: data ob just init in pf for once, it may not support for virtualization*/
		cn_data_ob_init(mm_set);
	}

	camb_mem_snapshot_ctrl(mm_set);

	return 0;
}

void cn_mm_last_exit(struct cn_core_set *core)
{
	struct cn_mm_set *mm_set = core->mm_set;

	if (!cn_core_is_vf(core) && !cn_is_mim_en(core)) {
		cn_data_ob_exit((void *)mm_set);
	}

	return;
}

int cn_mm_late_init(struct cn_core_set *core)
{
	camb_delay_free_init((struct cn_mm_set *)core->mm_set);

	if (!cn_core_is_vf(core) && cn_is_mim_en(core)) {
		cn_dev_core_debug(core, "not pf-only or vf");
		return 0;
	}

	camb_get_pgretire_init_result((struct cn_mm_set *)core->mm_set);
	camb_peer_free_init((void *)core);
	mdr_pool_init((void *)core);
	camb_p2p_normal_remap_init((struct cn_mm_set *)core->mm_set);
	camb_linear_remap_init((struct cn_mm_set *)core->mm_set);
	camb_vmm_support_check((struct cn_mm_set *)core->mm_set);

	camb_compress_ctrl((struct cn_mm_set *)core->mm_set,
					((struct cn_mm_set *)core->mm_set)->enable_compress_alloc);

	/*For mlu590, nedd config vf and pf sram remap.*/
	sram_remap_peer_config((void *)core);

	return 0;
}

void cn_mm_late_exit(struct cn_core_set *core)
{
	cn_mm_release_res(core);
}

int cn_mm_rpc_late_init(struct cn_core_set *core)
{
	int ret;
	ret = krpc_client_init(core);

	return ret;
}

void cn_mm_rpc_late_exit(struct cn_core_set *core)
{
	krpc_client_deinit(core);
}

