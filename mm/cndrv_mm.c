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
#include <linux/pid.h>
#include <linux/pid_namespace.h>

#include "cndrv_genalloc.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_mcc.h"
#include "cndrv_debug.h"
#include "cndrv_ioctl.h"
#include "hal/cn_mem_hal.h"
#include "hal/hal_llc/llc_common.h"
#include "camb_mm.h"
#include "camb_mm_priv.h"
#include "cndrv_sbts.h"
#include "cndrv_commu.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_fa.h"
#include "cndrv_gdma.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_ipcm.h"
#include "camb_mm_rpc.h"
#include "camb_sg_split.h"
#include "cndrv_udvm.h"
#include "cndrv_udvm_usr.h"
#include "camb_udvm.h"
#include "camb_mm_compat.h"
#include "cndrv_ipcm.h"
#include "camb_pinned_mem.h"
#include "camb_mm_pgretire.h"
#include "camb_mm_tools.h"
#include "camb_ob.h"
#include "camb_p2p_remap.h"
#include "camb_linear_remap.h"
#include "cndrv_df.h"
#include "cndrv_ext.h"
#include "cndrv_smlu.h"
#include "camb_iova_allocator.h"

/* CREATE_TRACE_POINTS only support defined once, only include "camb_trace.h" in other source files */
#define CREATE_TRACE_POINTS
#include "camb_trace.h"

#include "cndrv_mem_perf.h"

/* Only 220 edge platform need ignore params check */
#if defined(CONFIG_CNDRV_C20E_SOC)
static bool ignore_params_check = true;
#else
static bool ignore_params_check = false;
#endif


static int
cn_memcpy_dma_params_kref_get(u64 tag, host_addr_t host_vaddr,
		dev_addr_t dev_vaddr, unsigned long size, struct mapinfo **ppminfo,
		bool is_async);
static int
cn_memset_dma_params_kref_get(u64 tag, dev_addr_t dev_vaddr,
		unsigned long number, unsigned int per_size, struct mapinfo **ppminfo,
		bool is_async);
static int
cn_memcpy_peer_params_kref_get(u64 src_tag, u64 dst_tag,
		dev_addr_t src_vaddr, dev_addr_t dst_vaddr, unsigned long size,
		struct mapinfo **src_ppminfo, struct mapinfo **dst_ppminfo,
		bool is_async);

dev_addr_t cn_shm_get_dev_addr_by_name(void *pcore, unsigned char *name)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct shm_rsrv_priv *pos = __shm_get_handle_by_name(mm_set, name);

	if (IS_ERR_OR_NULL(pos)) {
		return (dev_addr_t)-1;
	}

	return pos->rev_dev_vaddr;
}

host_addr_t cn_shm_get_host_addr_by_name(void *pcore, unsigned char *name)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct shm_rsrv_priv *pos = __shm_get_handle_by_name(mm_set, name);

	if (IS_ERR_OR_NULL(pos)) {
		return (host_addr_t)-1;
	}

	return pos->rev_host_vaddr;
}

phy_addr_t cn_shm_get_phy_addr_by_name(void *pcore, unsigned char *name)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct shm_rsrv_priv *pos = __shm_get_handle_by_name(mm_set, name);

	if (IS_ERR_OR_NULL(pos)) {
		return (phy_addr_t)-1;
	}

	return pos->rev_phy_addr;
}

size_t cn_shm_get_size_by_name(void *pcore, unsigned char *name)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct shm_rsrv_priv *pos = __shm_get_handle_by_name(mm_set, name);

	if (IS_ERR_OR_NULL(pos)) {
		return (size_t)-1;
	}

	return pos->rev_size;
}

int cn_shm_get_sram_dev_info(void *pcore, dev_addr_t *pa_addr, dev_addr_t *pa_sz)
{
	struct cn_core_set *core = pcore;

	/*
	 *FIXME: we need get pcie sram by bus set api.
	 */
	*pa_addr = C50_AXI_SRAM_PA_BASE;
	*pa_sz = C50_AXI_SRAM_TOTAL_SIZE;

	cn_dev_core_info(core, "mem pa addr %llx size %llx", *pa_addr, *pa_sz);
	return 0;
}

dev_addr_t cn_shm_get_dev_va_base(void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	return mm_set->dev_virt_base;
}

/**
 * camb_free_mem_rpc -- direct free device memory will __mem_call_rpc
 *@input
 *	@use_ccache: if true this mem will be cached by ccmalloc,
 *	Fa mem need be cached, and Large mem (>512MB) will not be cached.
 *
 * @return val:
 *     0 --- success;
 *     errorNums --- __mem_call_rpc failed return.
 **/
int camb_free_mem_rpc(struct cn_mm_set *mm_set, unsigned int type,
							 dev_addr_t device_addr, dev_addr_t mdr_addr,
							 size_t size, struct ret_msg *remsg,
							 bool use_ccache)
{
	int ret = 0, pgretire_status = 0;
	size_t dev_ret_len = sizeof(struct ret_msg);
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct free_mem_list free_list;
	int  list_len = sizeof(struct free_mem_list);

	free_list.mem_cnt = 1;

	pgretire_status = camb_set_pgretire_status(mm_set);
	free_list.extra_status = pgretire_status;
	remsg->extra_ret = 0;

	if (use_ccache) {
		free_list.mem_list[0].tag = type;
	} else {
		free_list.mem_list[0].tag = type | SYNC_FREE_TAG;
	}

	cn_dev_core_debug(core, "mem need sync free, set tag %x",
					  free_list.mem_list[0].tag);
	if (((free_list.mem_list[0].tag) & ((1 << CN_MEM_BIT) - 1)) == CN_MDR_MEM) {
		free_list.mem_list[0].device_addr = mdr_addr;
		free_list.mem_list[0].mdr_va.mdr_addr = device_addr;
		free_list.mem_list[0].mdr_va.mdr_size = size;
	} else {
		free_list.mem_list[0].device_addr = device_addr;
	}
	cn_dev_core_debug(core, "Fa Mem free %#llx", free_list.mem_list[0].device_addr);

	memset(remsg, 0x00, sizeof(struct ret_msg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_free",
						 &free_list, list_len, remsg, &dev_ret_len, sizeof(struct ret_msg));

	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client free mem failed.");
		return ret;
	}

	/* ignore remsg->ret return value */
	if (!ret && remsg->ret) {
		cn_dev_core_err(core, "rpc_mem_free error status is %d", remsg->ret);
	}

	camb_get_pgretire_result(mm_set, pgretire_status, remsg->extra_ret);
	return 0;
}

static int __call_mem_ctrl_rpc(struct cn_mm_set *mm_set, int en)
{
	struct cn_core_set *core = mm_set->core;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0, pgretire_status = 0;
	struct mem_ctrl ctrl_info;
	int flag = en;

	ctrl_info.flag = en;
	pgretire_status = camb_set_pgretire_status(mm_set);
	ctrl_info.extra_status = pgretire_status;
	memset(&remsg, 0x00, sizeof(struct ret_msg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_ctrl", &ctrl_info,
						 sizeof(struct mem_ctrl), &remsg, &result_len,
						 sizeof(struct ret_msg));

	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client set mem mode %x is failed.", flag);
		return ret;
	}

	if (remsg.ret) {
		cn_dev_core_err(core, "rpc_mem_ctrl error status is %d",
						remsg.ret);
		return remsg.ret;
	}

	camb_get_pgretire_result(mm_set, pgretire_status, remsg.extra_ret);

	return 0;
}

int camb_call_mem_ob_ctl_rpc(struct cn_mm_set *mm_set, struct mem_ob_ctrl *ctl_info, struct ret_msg *remsg)
{
	struct cn_core_set *core = mm_set->core;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	memset(remsg, 0x00, sizeof(struct ret_msg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_ob_ctl", ctl_info,
						 sizeof(struct mem_ob_ctrl), remsg, &result_len,
						 sizeof(struct ret_msg));

	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client set mem mode %x is failed.", ctl_info->cmd);
		return ret;
	}

	if (remsg->ret) {
		cn_dev_core_err(core, "rpc_mem_ctrl error status is %d",
						remsg->ret);
		return remsg->ret;
	}

	return 0;
}

static int __mem_wait_df_finished(struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	unsigned long flags;
	unsigned int retry_times = 0;
	unsigned int async_wait_times = 0;

	/*
	 * proc func change ccmalloc, must insure delay free mem flow stop.
	 * cancel work could not guarantee all queue work has accomplished.
	 * in order to make its reliable, need check logic states
	 */

wait_clear_df_list:
	spin_lock_irqsave(&mm_set->work_sync_lock, flags);
	if ((!llist_empty(&mm_set->free_list) ||
		 atomic_read(&mm_set->free_worker_state) != WORK_IDLE) &&
		(retry_times < MAX_RETRY_TIMES)) {
		spin_unlock_irqrestore(&mm_set->work_sync_lock, flags);
		retry_times++;
		usleep_range(1000, 1100);
		goto wait_clear_df_list;
	} else {
		spin_unlock_irqrestore(&mm_set->work_sync_lock, flags);
		if (mm_set->vir_used_mem != DEFAULT_VIR_USED_MEM &&
			(async_wait_times < MAX_RETRY_TIMES)) {
			async_wait_times++;
			msleep(200);
			goto wait_clear_df_list;
		}
	}

	if ((retry_times >= MAX_RETRY_TIMES) ||
		(async_wait_times >= MAX_RETRY_TIMES)) {
		cn_dev_core_err(core, "Error: wait for mem free to init status timeout.");
		return -ETIMEDOUT;
	}

	return 0;
}

/*
 * ctrl mem alloc/free accelerate optimization mode enable or disable
 * 1. ctrl host mem delay free mode;
 * 2. ctrl ccmalloc feature in arm mem cache
 */
int camb_mem_ac_ctrl(struct cn_mm_set *mm_set, unsigned int flag)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	if (flag == MEM_DELAYFREE_ENABLE &&
		core->delay_free_enable == MEM_DELAYFREE_DISABLE) {
		cn_dev_core_info(core, "enabled: Delay Free && CCMalloc.");
		camb_fa_shrink(mm_set, mm_set->fa_array, true);

		core->delay_free_enable = MEM_DELAYFREE_ENABLE;
		hrtimer_start(&mm_set->hrtimer, mm_set->time_delay, HRTIMER_MODE_REL);

		__call_mem_ctrl_rpc(mm_set, (((CCMALLOC_MODE & MEM_EXTENSION_MODE_MASK)
			<< MEM_EXTENSION_MODE_BIT) | (flag & MEM_EXTENSION_OPS_MASK)));

	} else if (flag == MEM_DELAYFREE_DISABLE &&
			   core->delay_free_enable == MEM_DELAYFREE_ENABLE) {
		camb_fa_shrink(mm_set, mm_set->fa_array, true);
		if (__mem_wait_df_finished(mm_set)) {
			return -ETIMEDOUT;
		}

		cn_dev_core_info(core, "disable: Delay Free && CCMalloc.");
		core->delay_free_enable = MEM_DELAYFREE_DISABLE;

		if (hrtimer_is_queued(&mm_set->hrtimer))
			hrtimer_cancel(&mm_set->hrtimer);

		__call_mem_ctrl_rpc(mm_set, (((CCMALLOC_MODE & MEM_EXTENSION_MODE_MASK)
			<< MEM_EXTENSION_MODE_BIT) | (flag & MEM_EXTENSION_OPS_MASK)));

	} else if (flag == MEM_CCMALLOC_DEBUG) {
		cn_dev_core_info(core, "CCMalloc cache mem dump in arm.");
		__call_mem_ctrl_rpc(mm_set, (((CCMALLOC_MODE & MEM_EXTENSION_MODE_MASK)
			<< MEM_EXTENSION_MODE_BIT) | (flag & MEM_EXTENSION_OPS_MASK)));
	} else {
		cn_dev_core_info(core, "AC INVALID SET, now DF state %d.",
						 core->delay_free_enable);
	}

	return 0;
}

int camb_mem_df_ctrl(void *mem_set, unsigned int flag)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	if (mm_set->devid == MLUID_CE3226_EDGE || mm_set->devid == MLUID_PIGEON_EDGE ||
	    mm_set->devid == MLUID_370_DEV || mm_set->devid == MLUID_590_DEV) {
		cn_dev_core_info(core,
						 "Platform Mlu EDGE Can't config Delay Free!");
		return 0;
	}

	if (flag == MEM_DELAYFREE_ENABLE &&
		core->delay_free_enable == MEM_DELAYFREE_DISABLE) {
		cn_dev_core_info(core, "enabled: Delay Free.");
		core->delay_free_enable = MEM_DELAYFREE_ENABLE;
		hrtimer_start(&mm_set->hrtimer, mm_set->time_delay, HRTIMER_MODE_REL);

	} else if (flag == MEM_DELAYFREE_DISABLE &&
			   core->delay_free_enable == MEM_DELAYFREE_ENABLE) {
		camb_fa_shrink(mm_set, mm_set->fa_array, true);
		if (__mem_wait_df_finished(mm_set)) {
			return -ETIMEDOUT;
		}
		cn_dev_core_info(core, "disable: Delay Free.");
		core->delay_free_enable = MEM_DELAYFREE_DISABLE;

		if (hrtimer_is_queued(&mm_set->hrtimer))
			hrtimer_cancel(&mm_set->hrtimer);
	} else {
		cn_dev_core_info(core, "DF INVALID SET, now DF state %d.",
						 core->delay_free_enable);
	}

	return 0;
}

int camb_mem_cc_ctrl(void *mem_set, unsigned int flag)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	if (mm_set->devid == MLUID_CE3226_EDGE || mm_set->devid == MLUID_PIGEON_EDGE ||
	    mm_set->devid == MLUID_370_DEV || mm_set->devid == MLUID_590_DEV) {
		cn_dev_core_info(core,
						 "Platform Mlu EDGE Can't config CCmalloc!");
		return 0;
	}

	if (flag == MEM_CCMALLOC_ENABLE) {
		cn_dev_core_info(core, "enabled: CCMalloc.");
		camb_fa_shrink(mm_set, mm_set->fa_array, true);

		__call_mem_ctrl_rpc(mm_set, (((CCMALLOC_MODE & MEM_EXTENSION_MODE_MASK)
			<< MEM_EXTENSION_MODE_BIT) | (flag & MEM_EXTENSION_OPS_MASK)));

	} else if (flag == MEM_CCMALLOC_DISABLE) {
		camb_fa_shrink(mm_set, mm_set->fa_array, true);
		if (__mem_wait_df_finished(mm_set)) {
			return -ETIMEDOUT;
		}

		cn_dev_core_info(core, "disable: CCMalloc.");
		camb_fa_shrink(mm_set, mm_set->fa_array, true);

		__call_mem_ctrl_rpc(mm_set, (((CCMALLOC_MODE & MEM_EXTENSION_MODE_MASK)
			<< MEM_EXTENSION_MODE_BIT) | (flag & MEM_EXTENSION_OPS_MASK)));

	}

	return 0;
}

int camb_mem_fa_dev_ctrl(void *mem_set, unsigned int flag)
{
	struct cn_mm_set *mm_set = mem_set;

	if (mm_set->fa_remote_ctrl != FA_RE_CTRL_CLIENT) {
		return 0;
	}

	if (flag == MEM_FA_ENABLE) {
		__call_mem_ctrl_rpc(mm_set, (FA_REMOTE_MODE << MEM_EXTENSION_MODE_BIT)
							| MEM_FA_ENABLE);
	} else if (flag == MEM_FA_DISABLE) {
		__call_mem_ctrl_rpc(mm_set, (FA_REMOTE_MODE << MEM_EXTENSION_MODE_BIT)
							| MEM_FA_DISABLE);
	}

	return 0;
}

int camb_mem_fa_dev_mask_chunks(void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;

	if (mm_set->fa_remote_ctrl != FA_RE_CTRL_CLIENT)
		return -EPERM;

	__call_mem_ctrl_rpc(mm_set, (FA_MASK_CHUNKS << MEM_EXTENSION_MODE_BIT));

	return 0;
}

int camb_mem_trigger_pgretire_rpc(void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;

	__call_mem_ctrl_rpc(mm_set, (PGRETIRE_TRIGGER << MEM_EXTENSION_MODE_BIT));

	return 0;
}

int camb_mem_switch_linear_mode_rpc(void *mem_set, int mode)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	if (!mm_set->linear.is_support)
		return 0;

	if (mm_set->linear.mode == mode)
		return 0;

	if (!cn_core_is_vf(core) && cn_is_mim_en(core)) {
		return -EACCES;
	}

	/* NOTE: ready to disable linear mapping, need clear fast alloc at first */
	if (mm_set->linear.mode != LINEAR_MODE_DISABLE &&
		mode == LINEAR_MODE_DISABLE) {
		camb_fa_ctrl(mm_set, 3);
	}

	mm_set->linear.mode = mode;

	return __call_mem_ctrl_rpc(mm_set,
		((LINEAR_MODE << MEM_EXTENSION_MODE_BIT) | (mm_set->linear.mode)));
}

int camb_mem_switch_linear_compress_rpc(void *mem_set, int mode)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	if (!mm_set->linear.is_support)
		return 0;

	if (!cn_core_is_vf(core) && cn_is_mim_en(core)) {
		return -EACCES;
	}

	camb_fa_ctrl(mm_set, 3);

	return __call_mem_ctrl_rpc(mm_set,
		((LINEAR_COMPRESS_MODE << MEM_EXTENSION_MODE_BIT) | mode));
}

int camb_mem_snapshot_ctrl(void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	/* fa has been cleared of last_init process. */
	camb_fa_shrink(mm_set, mm_set->fa_array, true);
	/* do snapshot. */
	__call_mem_ctrl_rpc(mm_set, (SNAPSHOT_MODE << MEM_EXTENSION_MODE_BIT));
	return 0;
}

int cn_mem_extension(void *pcore, int en)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	int flag = en;
	int mode, op;

	if (core->open_count) {
		cn_dev_core_info(core,
						 "Can't set memory extension now! (Device not free)");
		return 0;
	}

	if (mm_set->devid == MLUID_CE3226_EDGE || mm_set->devid == MLUID_PIGEON_EDGE ||
	    mm_set->devid == MLUID_370_DEV || mm_set->devid == MLUID_590_DEV) {
		cn_dev_core_info(core,
						 "Platform Mlu EDGE Can't config memory extension!");
		return 0;
	}
	if (atomic_dec_return(&mm_set->proc_set)) {
		cn_dev_core_info(core,
						 "Last set memory extension not finished yet!");
		atomic_inc(&mm_set->proc_set);
		return 0;
	}

	cn_dev_core_debug(core, "flag = %x", flag);
	/*flag[0:3] - memory extension operation value(0: disable; 1: enable)*/
	/*flag[4:7] - memory extension mode(0: Codec Turbo; 1: IPU Turbo)*/
	mode = (flag >> MEM_EXTENSION_MODE_BIT) & MEM_EXTENSION_MODE_MASK;
	op = flag & MEM_EXTENSION_OPS_MASK;

	switch (mode) {
	case CODEC_TURBO_MODE:
		cn_dev_core_info(core,
						 "%s Codec Turbo!",
						 ((op == MEM_TURBO_ENABLE) ? "Enable" : "Disable"));
		__call_mem_ctrl_rpc(mm_set, flag);
		core->mem_extension = op;
		break;
	case ACCLERATE_MODE:
		camb_mem_ac_ctrl(mm_set, op);
		break;
	case HAI_MODE:
		cn_dev_core_info(core,
						 "%s smmu hai!",
						 ((op == MEM_HAI_ENABLE) ? "Enable" : "Disable"));
		__call_mem_ctrl_rpc(mm_set, flag);
		break;
	}

	atomic_inc(&mm_set->proc_set);
	return 0;
}

static int
__fake_minfo_release(struct mapinfo *pminfo, struct cn_mm_set *mm_set,
					 int *free_minfo)
{
	dev_addr_t device_vaddr = udvm_get_iova_from_addr(pminfo->virt_addr);
	struct ret_msg remsg;
	size_t result_len;
	int ret;

	*free_minfo = 0;
	memset(&remsg, 0x00, sizeof(struct ret_msg));

	ret = __mem_call_rpc(mm_set->core, mm_set->endpoint, "rpc_iova_put",
			(void *)&device_vaddr, sizeof(device_vaddr),
			(void *)&remsg, (size_t *)&result_len, sizeof(struct ret_msg));

	if (ret < 0) {
		return (ret == ERROR_RPC_RESET) ? -EINVAL : -EAGAIN;
	}

	*free_minfo = 1;
	return 0;
}

static int
__fa_minfo_release(struct mapinfo *pminfo, struct cn_mm_set *mm_set,
				   int *free_minfo)
{
	int ret = 0;

	*free_minfo = 0;

	camb_free_ts_node_record(pminfo, FREE_TS_READY_CALLRPC);
	ret = camb_fa_free(mm_set->fa_array, (void *)&pminfo->fa_info);
	if (ret < 0)
		return ret;

	*free_minfo = 1;
	return 0;
}

static int
__normal_minfo_release(struct mapinfo *pminfo, struct cn_mm_set *mm_set,
					   int *free_minfo)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct ret_msg remsg;
	unsigned int unit_nums;
	unsigned long flags;
	int ret = 0;

	*free_minfo = 0;
	if (core->delay_free_enable == MEM_DELAYFREE_ENABLE
		&& pminfo->mem_meta.size < DELAY_FREE_SIZE_MAX
		&& pminfo->mem_meta.type != CN_MDR_MEM) {

		if (pminfo->mem_meta.size < DELAY_FREE_UNIT_SIZE) {
			unit_nums = 1;
		} else {
			unit_nums = (pminfo->mem_meta.size / DELAY_FREE_UNIT_SIZE);
		}

		spin_lock_irqsave(&mm_set->work_sync_lock, flags);
		llist_add_batch(&pminfo->free_node, &pminfo->free_node,
						&mm_set->free_list);

		/*NOTE: llist free_mem_cnt can not accurately response mem in free_list!
		  when free worker is idle and mem cnt is large than threshold, call free worker.*/
		if (atomic_add_return(unit_nums, &mm_set->free_mem_cnt) > DELAY_FREE_CNT_THRESHOLD &&
			atomic_read(&mm_set->free_worker_state) == WORK_IDLE) {
			spin_unlock_irqrestore(&mm_set->work_sync_lock, flags);
			queue_work(system_unbound_wq, &mm_set->free_worker);
		} else {
			spin_unlock_irqrestore(&mm_set->work_sync_lock, flags);

			/* if the free_mem_cnt is less than the threshold, to start the
			 * hrtimer to avoid the free_list holding the memory alltime.
			 */
			if (atomic_add_return(1, &mm_set->timer_hot) == 1)
				hrtimer_start(&mm_set->hrtimer, mm_set->time_delay, HRTIMER_MODE_REL);
		}

	} else {
		camb_free_ts_node_record(pminfo, FREE_TS_READY_CALLRPC);

		ret = camb_free_mem_rpc(pminfo->mm_set, pminfo->mem_meta.type,
								udvm_get_iova_from_addr(pminfo->virt_addr),
								pminfo->mdr_peer_addr,
								pminfo->mem_meta.size, &remsg, false);
		if (ret < 0) {
			return (ret == ERROR_RPC_RESET) ? -EINVAL : -EAGAIN;
		}

		*free_minfo = 1;
	}

	return 0;
}

static int
__vmm_minfo_release(struct mapinfo *pminfo, struct cn_mm_set *mm_set,
					   int *free_minfo)
{
	camb_free_ts_node_record(pminfo, FREE_TS_READY_CALLRPC);
	vmm_minfo_release(pminfo);
	*free_minfo = 1;

	return 0;
}

static int
__extn_minfo_release(struct mapinfo *pminfo, struct cn_mm_set *mm_set,
					   int *free_minfo)
{
	extn_minfo_release(pminfo);
	*free_minfo = 1;

	return 0;
}

void __pminfo_sg_table_free(struct mapinfo *pminfo)
{
	if (pminfo->sg_table) {
		sg_free_table(pminfo->sg_table);
		cn_kfree(pminfo->sg_table);
		pminfo->sg_table = NULL;
	}
}

static void camb_peer_obmap_release(struct mapinfo *pminfo);
int camb_mem_release(struct mapinfo *pminfo)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	int free_pminfo = 0, ret;
	__u64 size;

	trace_mapinfo_release(pminfo);
	camb_free_ts_node_record(pminfo, FREE_TS_ZEROREFCNT);

	cn_dev_core_debug(core, "memory release: dev_addr = %llx type:%d",
					  pminfo->virt_addr, pminfo->mem_type);

	/* after ctrl + c, uva should 0. uva bound to iova. */
	if (current->mm && pminfo->uva) {
		size = pminfo->mem_meta.size;
		/*addr head is 4KB align,but pminfo->mem_meta.size maybe not PAGE_SIZE ALIGN.*/
		size = PAGE_ALIGN(size);
		camb_unmap_uva(pminfo->uva, size, pminfo->uva_cached);
	}

	camb_unmap_kva(pminfo);

	camb_peer_obmap_release(pminfo);

	__pminfo_sg_table_free(pminfo);

	camb_p2p_remap_release(pminfo);

	if (pminfo->ipcm_info) {
		if (atomic_sub_and_test(1, pminfo->ipcm_info->ipcm_refcnt)) {
			cn_kfree(pminfo->ipcm_info->ipcm_refcnt);
			pminfo->ipcm_info->ipcm_refcnt = NULL;
			cn_kfree(pminfo->ipcm_info);
			pminfo->ipcm_info = NULL;
		} else {
			cn_kfree(pminfo->ipcm_info);
			pminfo->ipcm_info = NULL;
			camb_free_ts_node_record_and_saved(pminfo, FREE_TS_RPC_RETURNED);
			cn_kfree(pminfo);
			return 0;
		}
	}

	/* DRIVER-11107: ANT LLC cacheLine alias problem workaround */
	if (pminfo->mem_meta.type == CN_SEPARATE_MEM) llc_maintanance(core, 3);

	switch (pminfo->mem_type) {
	case MEM_FAKE:
		ret = __fake_minfo_release(pminfo, mm_set, &free_pminfo);
		break;
	case MEM_FA:
		ret = __fa_minfo_release(pminfo, mm_set, &free_pminfo);
		break;
	case MEM_VMM:
		ret = __vmm_minfo_release(pminfo, mm_set, &free_pminfo);
		break;
	case MEM_IE:
		ret = __extn_minfo_release(pminfo, mm_set, &free_pminfo);
		break;
	case MEM_LG:
	default:
		ret = __normal_minfo_release(pminfo, mm_set, &free_pminfo);
		break;
	}

	/**
	 * ATTENTION: DRIVER-12212, Do not access mapinfo after switch release
	 * without free_pminfo flag value check, mapinfo maybe released in
	 * __normal_minfo_release while queue delay_free work.
	 **/

	if (ret < 0) {
		return ret;
	}

	/* if free_pminfo is set true, means that the mapinfo will not be freed in
	 * __xxx_minfo_release functions. So we can access pminfo safely. */
	if (free_pminfo) {
		/* VMM allocated memory will modify information after physical memory release, skip now */
		if (pminfo->mem_type != MEM_VMM && pminfo->mem_type != MEM_FAKE) {
			__sync_sub_and_fetch(&mm_set->phy_used_mem, pminfo->mem_meta.size);
			__sync_sub_and_fetch(&mm_set->vir_used_mem, pminfo->mem_meta.size);
		}
		camb_free_ts_node_record_and_saved(pminfo, FREE_TS_RPC_RETURNED);
		__sync_lock_test_and_set(&mm_set->smmu_invalid_mask, 0xfffffffff);
		cn_kfree(pminfo);
	}

	return 0;
}

static int camb_host_shm_release(struct mapinfo *pminfo)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	unsigned long host_vaddr = pminfo->shm_info.host_vaddr;
	unsigned long size = pminfo->mem_meta.size;

	cn_dev_core_debug(core, "release host_vaddr = %lx, dev_addr = %llx in mapinfo(%px)",
					  host_vaddr, pminfo->shm_info.device_vaddr, pminfo);

	if (mm_set->hostpool.pool == NULL) {
		cn_dev_core_err(core, "create device pool fisrt!!!");
		return -EAGAIN;
	}

	cn_gen_pool_free(mm_set->hostpool.pool, host_vaddr, size);
	atomic_long_sub(size, &mm_set->hostpool.used_size);

	cn_kfree(pminfo);
	return 0;
}

static int camb_dev_shm_release(struct mapinfo *pminfo)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	unsigned long host_vaddr = pminfo->shm_info.host_vaddr;
	unsigned long size = pminfo->mem_meta.size;

	cn_dev_core_debug(core, "release host_vaddr = %lx, dev_addr = %llx in mapinfo(%px)",
					  host_vaddr, pminfo->shm_info.device_vaddr, pminfo);

	if (mm_set->devpool.pool == NULL) {
		cn_dev_core_err(core, "create device pool fisrt!!!");
		return -EAGAIN;
	}

	camb_peer_obmap_release(pminfo);

	cn_gen_pool_free(mm_set->devpool.pool, host_vaddr, size);
	atomic_long_sub(size, &mm_set->devpool.used_size);

	cn_kfree(pminfo);
	return 0;
}

static int camb_sram_shm_release(struct mapinfo *pminfo)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	unsigned long host_vaddr = pminfo->shm_info.host_vaddr;
	unsigned long size = pminfo->mem_meta.size;

	cn_dev_core_info(core, "release host_vaddr = %lx, dev_addr = %llx in mapinfo(%p)",
					  host_vaddr, pminfo->shm_info.device_vaddr, pminfo);

	if (mm_set->sram_pool.pool == NULL) {
		cn_dev_core_err(core, "no sram pool.");
		return -EAGAIN;
	}

	camb_peer_obmap_release(pminfo);

	cn_gen_pool_free(mm_set->sram_pool.pool, host_vaddr, size);
	atomic_long_sub(size, &mm_set->sram_pool.used_size);

	cn_kfree(pminfo);
	return 0;
}

/* FIXME: tmp modify, fp maybe invalid when p2p!!!
 * delete it after mem release strategy fix!
 */
struct cn_mm_priv_data *
__get_mm_priv(struct file *fp, struct cn_mm_set *mm_set)
{
	struct fp_priv_data *priv_data;

	if (fp && fp->private_data) {
		priv_data = fp->private_data;
		return (struct cn_mm_priv_data *)priv_data->mm_priv_data;
	} else if (mm_set) {
		return &mm_set->mm_priv_data;
	}

	return NULL;
}

#define __update_pid_info_node(mapinfo, ops, size) \
do { \
	struct file *fp = (struct file *)mapinfo->tag; \
	struct fp_priv_data *priv_data; \
	struct pid_info_s *pid_info_node; \
	if ((fp) && (fp)->private_data) { \
		priv_data = (fp)->private_data; \
		pid_info_node = priv_data->pid_info_node; \
		__sync_##ops##_and_fetch(&pid_info_node->phy_usedsize, (size)); \
		__sync_##ops##_and_fetch(&pid_info_node->vir_usedsize, (size)); \
	} \
} while (0)

/* Funciton: camb_kref_get
 * Description: Atomic Increase pminfo->refcnt to forbid
 *              other process free the memory
 */

int __minfo_kref_get(struct mapinfo *pminfo, dev_addr_t addr, size_t size)
{
	if (atomic_read(&pminfo->free_flag) != 0)
		return -ENXIO;

	if (atomic_add_unless(&pminfo->refcnt, 1, 0) == 0)
		return -ENXIO;

	trace_mapinfo_kref_get(pminfo);

	return 0;
}

static int
camb_kref_get_internal(u64 tag, dev_addr_t device_vaddr,
		struct mapinfo **minfo, struct cn_mm_set *mm_set, bool vmm_valid_check)
{
	int ret = 0;
	struct file *fp = (struct file *)tag;
	struct mapinfo *pminfo = NULL;

	*minfo = NULL;

	pminfo = search_mapinfo_with_func(fp, mm_set, device_vaddr, 0,
						__minfo_kref_get);

	if (IS_ERR_OR_NULL(pminfo)) {
		/* NOTE: called uva_get in 300ARM will be failed and do not output error log */
		ret = (pminfo == NULL) ? -ENXIO : PTR_ERR(pminfo);
	} else {
		if (vmm_valid_check && pminfo->mem_type == MEM_VMM &&
			atomic_read(&pminfo->vmm_info.isvalid) != VALID) {
			camb_kref_put(pminfo, camb_mem_release);
			ret = -ENXIO;
		} else {
			*minfo = pminfo;
		}
	}

	return ret;
}

int camb_kref_get(u64 tag, dev_addr_t device_vaddr,
			  struct mapinfo **minfo, struct cn_mm_set *mm_set)
{
	return camb_kref_get_internal(tag, device_vaddr, minfo, mm_set, true);
}

int camb_kref_get_without_vmm_check(u64 tag, dev_addr_t device_vaddr,
			  struct mapinfo **minfo, struct cn_mm_set *mm_set)
{
	return camb_kref_get_internal(tag, device_vaddr, minfo, mm_set, false);
}

#ifdef CONFIG_CNDRV_EDGE
/**
 * NOTE: edge platform use map_kernel to do async copy tasks, which not
 * support cross multi physical memory handles. So it's forbidden to support
 * VMM iova range validate check in EDGE platform.
 **/
static int
camb_kref_get_validate(u64 tag, dev_addr_t device_vaddr, unsigned long size,
			  struct mapinfo **minfo, struct cn_mm_set *mm_set)
{
	int ret = 0;

	ret = camb_kref_get(tag, device_vaddr, minfo, mm_set);
	if (!ret && __params_check_range(*minfo, device_vaddr, size)) {
		camb_kref_put(*minfo, camb_mem_release);
		ret = -ENXIO;
	}

	return ret;
}
#else

static int
__minfo_kref_get_check(struct mapinfo *pminfo, dev_addr_t addr, size_t size)
{
	if (__params_check_range(pminfo, addr, size))
		return -ENXIO;

	return __minfo_kref_get(pminfo, addr, size);
}

static int
camb_kref_get_validate(u64 tag, dev_addr_t device_vaddr, unsigned long size,
			  struct mapinfo **minfo, struct cn_mm_set *mm_set)
{
	int ret = 0;
	struct file *fp = (struct file *)tag;
	struct mapinfo *pminfo = NULL;

	*minfo = NULL;

	if (addr_is_vmm(device_vaddr)) {
		pminfo = camb_vmm_minfo_kref_get_range(tag, device_vaddr, size,
							__minfo_kref_get_check);
	} else {
		pminfo = search_mapinfo_with_func(fp, mm_set, device_vaddr, size,
							__minfo_kref_get_check);
	}

	if (IS_ERR_OR_NULL(pminfo)) {
		cn_dev_debug("mapinfo for addr(%#llx) invalid", device_vaddr);
		ret = (pminfo == NULL) ? -ENXIO : PTR_ERR(pminfo);
	} else {
		*minfo = pminfo;
	}

	return ret;
}
#endif

unsigned int camb_kref_put(struct mapinfo *pminfo, int (*release)(struct mapinfo *pminfo))
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	spinlock_t *minfo_lock = NULL;
	int ret = 0;

	trace_mapinfo_kref_put(pminfo);

	if (atomic_add_unless(&pminfo->refcnt, -1, 1))
		return 1;

	/** fix bug for DRIVER-6308 **/
	minfo_lock = __get_minfo_lock_with_mapinfo(pminfo);
	if (!minfo_lock) {
		WARN(1, "could found minfo_lock with mapinfo input, maybe bug happened");
		return 0;
	}

	spin_lock(minfo_lock);
	if (unlikely(!atomic_dec_and_test(&pminfo->refcnt))) {
		spin_unlock(minfo_lock);
		return 1;
	}

	if (!((mm_set->devid == MLUID_PIGEON_EDGE || mm_set->devid == MLUID_CE3226_EDGE)
				&& pminfo->mem_type == MEM_FAKE)) {
		delete_mapinfo((struct cn_mm_priv_data *)pminfo->mm_priv_data, pminfo);
	}
	spin_unlock(minfo_lock);

	ret = release(pminfo);
	if (ret == -EAGAIN) {
		/* After insert_mapinfo, we can't make sure
		 * new mapinfo's location int rbtree. return 1
		 * to make sure get next p by rb_first
		 */
		spin_lock(minfo_lock);
		atomic_inc(&pminfo->refcnt);
		atomic_set(&pminfo->free_flag, 0);
		if (!((mm_set->devid == MLUID_PIGEON_EDGE || mm_set->devid == MLUID_CE3226_EDGE)
					&& pminfo->mem_type == MEM_FAKE)) {
			insert_mapinfo((struct cn_mm_priv_data *)pminfo->mm_priv_data, pminfo);
		}
		spin_unlock(minfo_lock);
	}

	return 1;
}

#ifdef CONFIG_CNDRV_EDGE
/* See comment in camb_kref_get_validate */
static unsigned int
camb_kref_put_range(struct mapinfo *pminfo, dev_addr_t start, unsigned long size,
			int (*release)(struct mapinfo *pminfo))
{
	return camb_kref_put(pminfo, release);
}
#else
static unsigned int
camb_kref_put_range(struct mapinfo *pminfo, dev_addr_t start, unsigned long size,
			int (*release)(struct mapinfo *pminfo))
{
	if (pminfo->mem_type != MEM_VMM)
		return camb_kref_put(pminfo, release);
	else
		return camb_vmm_minfo_kref_put_range(pminfo, start, size, release);
}
#endif
/* Funciton: camb_free_kref_get
 * Description: Atomic set pminfo->free_flag as true to forbid double free.
 * NOTICE: Only called by mem_free(share_mem_free, cn_mem_free...)
 */
int __minfo_free_kref_get(struct mapinfo *pminfo, dev_addr_t addr, size_t size)
{
	if (pminfo->ipcm_info && pminfo->ipcm_info->parent)
		return -EACCES;

	if (atomic_cmpxchg(&pminfo->free_flag, 0, 1) != 0)
		return -ENXIO;

	return 0;
}

static int
camb_free_kref_get(u64 tag, dev_addr_t device_vaddr,
				   struct mapinfo **minfo, struct cn_mm_set *mm_set)
{
	int ret = 0;
	struct file *fp = (struct file *)tag;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mapinfo *pminfo;

	*minfo = NULL;

	pminfo = search_mapinfo_with_func(fp, mm_set, device_vaddr, 0,
						__minfo_free_kref_get);

	if (IS_ERR_OR_NULL(pminfo)) {
		cn_dev_core_err(core, "mapinfo for addr(%#llx) invalid", device_vaddr);
		ret = PTR_ERR(pminfo);
	} else {
		*minfo = pminfo;
	}

	return ret;
}

static inline void
camb_free_kref_put(struct mapinfo *pminfo)
{
	atomic_set(&pminfo->free_flag, 0);
}

static int __migrate_mapinfo(struct cn_mm_priv_data *src_priv,
						   struct cn_mm_priv_data *dst_priv,
						   struct mapinfo *minfo, u64 tag)
{
	dev_addr_t vaddr;
	spinlock_t *minfo_lock;

	if (!minfo)
		return 0;

	vaddr = minfo->virt_addr;
	minfo_lock = __get_minfo_lock_with_mmpriv(src_priv, vaddr);
	if (!minfo_lock) {
		WARN(1, "could found minfo_lock with mapinfo input, maybe bug happened");
		return 0;
	}

	/**
	 * NOTE:
	 * after migrate, tag input is still old fp. so we don't need change
	 * tag in mapinfo.
	 **/
	spin_lock(minfo_lock);
	if (atomic_read(&minfo->refcnt) != 0) {
		delete_mapinfo(src_priv, minfo);
		/**
		 * forbidden camb_kref_put try to delete_mapinfo again without
		 * mm_priv_data exchange
		 **/
		atomic_inc(&minfo->refcnt);
		spin_unlock(minfo_lock);
	} else {
		spin_unlock(minfo_lock);
		/**
		 * minfo->refcnt == 0 means mapinfo has been deleted from rbtree, do not
		 * need migrate it
		 **/
		return 0;
	}

	/* only do migrate if delete_mapinfo succeed */
	minfo_lock = __get_minfo_lock_with_mmpriv(dst_priv, vaddr);
	if (!minfo_lock) {
		WARN(1, "could found minfo_lock with mapinfo input, maybe bug happened");
		return 0;
	}

	spin_lock(minfo_lock);
	minfo->mm_priv_data = dst_priv;
	minfo->tag = tag;
	insert_mapinfo(dst_priv, minfo);
	spin_unlock(minfo_lock);
	camb_kref_put(minfo, camb_mem_release);
	return 0;
}

int camb_mem_statistics(void *mem_set, struct cn_mem_stat *mem_stat)
{
	int ret = 0;
	struct fa_stat stat;
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = mm_set->core;
	struct cn_fa_array *arr = mm_set->fa_array;
	struct mem_dbg_t dbg;
	struct dbg_meminfo_t remsg;
	size_t result_len = sizeof(struct dbg_meminfo_t);

	if (!mem_stat)
		return -EINVAL;

	/*VIRTUAL-454 Bug fix: forbid get mem to be called in pf when sriov is enabled*/
	if (cn_is_mim_en(core) && !cn_core_is_vf(core)) {
		return 0;
	}

	/* Get Fast Alloc Mem info */
	ret = camb_fa_statistic(arr, &stat);
	if (ret)
		return ret;

	mem_stat->fa_total_mem = stat.total_size / 1024;
	mem_stat->fa_used_mem = stat.used_size / 1024;
	mem_stat->fa_shrink_size = stat.shrink_size / 1024;
	mem_stat->fa_require_mem = stat.require_mem;
	mem_stat->fa_alloc_mem = stat.used_size;

	dbg.cmd = MEM_DBG_ZONEINFO;
	memset(&remsg, 0x0, result_len);
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_debug", &dbg,
		sizeof(struct mem_dbg_t), &remsg, &result_len,
		sizeof(struct dbg_meminfo_t));

	if (ret < 0 || remsg.ret) {
		cn_dev_core_err(core, "Failed, __mem_call_rpc(core, %d), rpc_mem_debug(%d)",
				ret, remsg.ret);
		return -EINVAL;
	}

	mem_stat->ccmalloc_state = remsg.ccmalloc_state;
	mem_stat->phy_total_mem = remsg.base.total_mem >> 10UL;
	mem_stat->phy_used_mem = remsg.base.used_mem >> 10UL;

	/*add dev FA info*/
	cn_dev_core_debug(core, "add fa dev mem total %lx used %lx",
					 remsg.base.fa_dev_mem, remsg.base.fa_dev_used_mem);
	mem_stat->fa_dev_total_mem = remsg.base.fa_dev_mem >> 10UL;
	mem_stat->fa_dev_used_mem = remsg.base.fa_dev_used_mem >> 10UL;

	mem_stat->fa_chunk_size = arr->chunk_size;
	mem_stat->fa_alloc_size = arr->alloc_size;
	mem_stat->alloc_order = 1 << arr->alloc_order;

	return 0;
}

unsigned int
camb_mem_put_release(u64 tag, dev_addr_t device_vaddr, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mapinfo *pminfo = NULL;
	struct file *fp = (struct file *)tag;

	if (ignore_params_check) return 0;

	pminfo = search_mapinfo_with_fp(fp, device_vaddr, mm_set);
	if (unlikely(IS_ERR_OR_NULL(pminfo))) {
		cn_dev_core_err(core, "Can't find the mapinfo for addr %llx",
						device_vaddr);
		return -ENXIO;
	}
	cn_dev_core_debug(core, "Has been find the mapinfo(%px)", pminfo);

	return camb_kref_put(pminfo, camb_mem_release);
}

int cn_get_mdr_addr(u64 tag, dev_addr_t mdr_addr, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mapinfo *pminfo = NULL;

	ret = camb_kref_get(tag, mdr_addr, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal for mdr alloc", mdr_addr);
		return ret;
	}

	return 0;
}

int cn_put_mdr_addr(u64 tag, dev_addr_t mdr_addr, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mapinfo *pminfo = NULL;
	struct file *fp = (struct file *)tag;

	pminfo = search_mapinfo_with_fp(fp, mdr_addr, mm_set);
	if (unlikely(IS_ERR_OR_NULL(pminfo))) {
		cn_dev_core_err(core, "Can't find the mapinfo for addr %llx", mdr_addr);
		return -ENXIO;
	}

	cn_dev_core_debug(core, "Has been find the mapinfo(addr = %px)", pminfo);

	camb_kref_put(pminfo, camb_mem_release);
	return 0;
}

int camb_dob_iova_alloc(dev_addr_t *iova, dev_addr_t *device_pa, size_t size, struct sg_table *table)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct camb_ob_direct_map *obd_map;
	struct cn_gen_pool *pool;
	struct mempool_t *p_hostpool;
	int use_small_win_flag = 0;
	struct scatterlist *sg;
	dev_addr_t dev_phy_addr;
	void *vaddr;
	int cnt, i, ret;

	WARN_ON(!IS_ALIGNED(size, 0x10000));

	if (!udvm_set->obd_map) {
		ret = camb_pinned_obd_map_init();
		if (ret)
			return ret;
	}

	obd_map = udvm_set->obd_map;

	cnt = sg_nents(table->sgl);
	for_each_sg(table->sgl, sg, cnt, i) {
		WARN_ON(!sg->length);
		if (!IS_ALIGNED(sg->length, obd_map->align_size_h)) {
			use_small_win_flag = 1;
			break;
		}
	}

	if (use_small_win_flag) {
		pool = obd_map->hostpool_l.pool;
		p_hostpool = &obd_map->hostpool_l;
	} else {
		pool = obd_map->hostpool_h.pool;
		p_hostpool = &obd_map->hostpool_h;
	}

	vaddr = cn_gen_pool_dma_alloc(pool, size, &dev_phy_addr);
	if (!vaddr) {
		cn_dev_err("no enough outbound mem!");
		return -ENOSPC;
	}

	*device_pa = (dev_addr_t)dev_phy_addr;
	*iova = (dev_addr_t)vaddr;
	atomic_long_add(size, &p_hostpool->used_size);

	return 0;
}

int camb_dob_iova_free(u64 iova, size_t size)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct camb_ob_direct_map *obd_map = udvm_set->obd_map;
	struct mempool_t *p_hostpool;

	if (iova >= obd_map->hostpool_h.virt) {
		p_hostpool = &obd_map->hostpool_h;
	} else {
		p_hostpool = &obd_map->hostpool_l;
	}

	cn_gen_pool_free(p_hostpool->pool, iova, size);
	atomic_long_sub(size, &p_hostpool->used_size);

	return 0;
}

int camb_dob_dev_mem_alloc(dev_addr_t *device_pa, dev_addr_t *iova, size_t size,
		struct sg_table *table, void *mem_set)
{
	return camb_dob_iova_alloc(iova, device_pa, size, table);
}

int camb_dob_dev_mem_free(u64 iova, dev_addr_t dev_phy_addr, size_t size, void *mem_set)
{
	return camb_dob_iova_free(iova, size);
}

int cn_host_share_mem_alloc(u64 tag, host_addr_t *host_vaddr,
	dev_addr_t *device_addr, size_t size, void *pcore)
{
	dev_addr_t dev_phy_addr;
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = pcore;
	struct mapinfo *pminfo = NULL;
	struct file *fp = (struct file *)tag;
	struct cn_mm_priv_data *mm_priv_data;

	mm_set = (struct cn_mm_set *)core->mm_set;
	mm_priv_data = __get_mm_priv(fp, mm_set);
	if (!mm_priv_data) {
		cn_dev_core_err(core, "get mem priv data failed");
		return -EINVAL;
	}

	pminfo = cn_kzalloc(sizeof(struct mapinfo), GFP_KERNEL);
	if (!pminfo) {
		cn_dev_core_err(core, "kzalloc mapInfo failed.");
		return -ENOMEM;
	}
	cn_dev_core_debug(core, "device share mem alloc:pmapinfo = %px", pminfo);

	/*mapinfo init*/
	camb_init_mapinfo_basic(pminfo, mm_set, tag);
	pminfo->mem_meta.size = size;
	pminfo->mem_meta.type = CN_SHARE_MEM;
	pminfo->mem_meta.flag = CN_C_nA;

	if (mm_set->hostpool.pool == NULL) {
		cn_dev_core_err(core, "create device pool fisrt!!!");
		cn_kfree(pminfo);
		return -EINVAL;
	}

	*host_vaddr = (host_addr_t)
		cn_gen_pool_dma_alloc(mm_set->hostpool.pool, size, &dev_phy_addr);
	if (!(*host_vaddr)) {
		cn_dev_core_err(core, "alloc share memory error");
		cn_kfree(pminfo);
		return -ENOMEM;
	}

	*device_addr = dev_phy_addr;
	atomic_long_add(size, &mm_set->hostpool.used_size);

	/*insert the mapinfo into rb tree*/
	pminfo->shm_info.device_vaddr = *device_addr;
	pminfo->shm_info.host_vaddr = *host_vaddr;
	pminfo->shm_info.type = CN_HOST_SHM;
	pminfo->shm_info.caller = __builtin_return_address(0);
	cn_dev_core_debug(core, "malloc host_vaddr = %lx and dev_addr = %llx",
		   pminfo->shm_info.host_vaddr, pminfo->shm_info.device_vaddr);
	insert_mapinfo(mm_priv_data, pminfo);

	return 0;
}

int cn_host_share_mem_free(u64 tag, host_addr_t host_vaddr,
	dev_addr_t device_vaddr, void *pcore)
{
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = pcore;
	struct mapinfo *pminfo = NULL;
	int ret = 0;

	mm_set = (struct cn_mm_set *)core->mm_set;
	ret = camb_free_kref_get(tag, device_vaddr, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal for free", device_vaddr);
		return ret;
	}

	if (pminfo->shm_info.host_vaddr != host_vaddr) {
		camb_free_kref_put(pminfo);
		cn_dev_core_err(core, "host virtual address don't match!");
		return -EFAULT;
	}

	/*If the refcnt == 0, release the mapinfo.If not, only sub the refcnt and
	  reserved the mapinfo in the rb tree.*/
	camb_kref_put(pminfo, camb_host_shm_release);

	return 0;
}

int camb_device_share_mem_alloc(host_addr_t *host_vaddr, dev_addr_t *device_vaddr,
		phys_addr_t *phy_addr, size_t size, size_t alignment, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = NULL;

	if (!mm_set) {
		cn_dev_err("no mem_set alloc!!!");
		return -EINVAL;
	}

	core = (struct cn_core_set *)mm_set->core;

	if (mm_set->devpool.pool == NULL) {
		cn_dev_core_err(core, "create device pool fisrt!!!");
		return -EINVAL;
	}

	if (!alignment) {
		*host_vaddr = (host_addr_t)
			cn_gen_pool_dma_alloc(mm_set->devpool.pool, size, phy_addr);
	} else {
		*host_vaddr = (host_addr_t)
			cn_gen_pool_dma_alloc_aligned(mm_set->devpool.pool, size, alignment, phy_addr);
	}
	if (!(*host_vaddr)) {
		cn_dev_core_warn(core, "no share memory to alloc");
		return -ENOMEM;
	}

	*device_vaddr = *phy_addr - mm_set->devpool.phys + mm_set->dev_virt_base;
	atomic_long_add(size, &mm_set->devpool.used_size);

	cn_dev_core_debug(core, "malloc host_vaddr = %lx and dev_vaddr = %llx szie:%#lx",
			*host_vaddr, *device_vaddr, size);

	return 0;
}

int cn_device_share_mem_alloc_aligned(u64 tag, host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, size_t size, size_t alignment, void *pcore)
{
	phys_addr_t phy_addr = 0;
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = pcore;
	struct mapinfo *pminfo = NULL;
	struct file *fp = (struct file *)tag;
	struct cn_mm_priv_data *mm_priv_data;

	mm_set = (struct cn_mm_set *)core->mm_set;
	mm_priv_data = __get_mm_priv(fp, mm_set);
	if (!mm_priv_data) {
		cn_dev_core_err(core, "get mem priv data failed");
		return -EINVAL;
	}

	pminfo = cn_kzalloc(sizeof(struct mapinfo), GFP_KERNEL);
	if (!pminfo) {
		cn_dev_core_err(core, "Kzalloc mapInfo failed.");
		return -ENOMEM;
	}
	cn_dev_core_debug(core, "device share mem alloc:pmapinfo = %px", pminfo);

	/*mapinfo init*/
	camb_init_mapinfo_basic(pminfo, mm_set, tag);
	pminfo->mem_meta.size = size;
	pminfo->mem_meta.type = CN_SHARE_MEM;
	pminfo->mem_meta.flag = CN_C_nA;

	*host_vaddr = 0;
	camb_device_share_mem_alloc(host_vaddr, device_vaddr, &phy_addr, size, alignment, mm_set);
	if (!(*host_vaddr)) {
		/* FIXME: change to err print later */
		cn_dev_core_warn(core, "no share memory to alloc");
		cn_kfree(pminfo);
		return -ENOMEM;
	}

	/*insert the mapinfo into rb tree*/
	pminfo->shm_info.device_paddr = phy_addr;
	pminfo->shm_info.device_vaddr = *device_vaddr;
	pminfo->shm_info.host_vaddr = *host_vaddr;
	pminfo->shm_info.type = CN_DEV_SHM;
	pminfo->shm_info.caller = __builtin_return_address(0);
	cn_dev_core_debug(core, "malloc host_vaddr = %lx and dev_vaddr = %llx size:%#lx",
			pminfo->shm_info.host_vaddr, pminfo->shm_info.device_vaddr, size);

	insert_mapinfo(mm_priv_data, pminfo);

	return 0;
}

int cn_device_share_mem_alloc(u64 tag, host_addr_t *host_vaddr,
	dev_addr_t *device_vaddr, size_t size, void *pcore)
{
	return cn_device_share_mem_alloc_aligned(tag, host_vaddr, device_vaddr, size, 0, pcore);
}

int cn_device_share_mem_free(u64 tag, host_addr_t host_vaddr,
	dev_addr_t device_vaddr, void *pcore)
{
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = pcore;
	struct mapinfo *pminfo = NULL;
	int ret = 0;

	mm_set = (struct cn_mm_set *)core->mm_set;
	ret = camb_free_kref_get(tag, device_vaddr, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal for free", device_vaddr);
		return ret;
	}

	if (pminfo->shm_info.host_vaddr != host_vaddr) {
		camb_free_kref_put(pminfo);
		cn_dev_core_err(core, "host virtual address don't match!");
		return -EFAULT;
	}

	/*If the refcnt == 0, release the mapinfo.If not, only sub the refcnt and
	  reserved the mapinfo in the rb tree.*/
	camb_kref_put(pminfo, camb_dev_shm_release);

	return 0;
}

int cn_sram_get_paddr(u64 tag, dev_addr_t device_vaddr,
	phys_addr_t *device_paddr, void *pcore)
{
	struct mapinfo *pminfo = NULL;
	struct file *fp = (struct file *)tag;
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = pcore;

	mm_set = (struct cn_mm_set *)core->mm_set;
	pminfo = search_mapinfo_with_fp(fp, device_vaddr, mm_set);
	if (unlikely(IS_ERR_OR_NULL(pminfo))) {
		cn_dev_core_err(core, "Can't find the mapinfo for addr %llx", device_vaddr);
		return -ENXIO;
	}

	cn_dev_core_debug(core, "%p host_va = %lx dev_va = %llx pa:%#llx", pminfo,
			pminfo->shm_info.host_vaddr, pminfo->shm_info.device_vaddr,
			(u64)pminfo->shm_info.device_paddr);

	*device_paddr = pminfo->shm_info.device_paddr + device_vaddr - pminfo->shm_info.device_vaddr;
	return 0;
}

int camb_sram_alloc_internal(u64 tag, host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, phy_addr_t *phy_addr,
		size_t size, void *pcore, void *caller)
{
	phy_addr_t phy_tmp;
	struct mapinfo *pminfo = NULL;
	struct file *fp = (struct file *)tag;
	struct cn_mm_priv_data *mm_priv_data;
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = pcore;

	mm_set = (struct cn_mm_set *)core->mm_set;
	mm_priv_data = __get_mm_priv(fp, mm_set);
	if (!mm_priv_data) {
		cn_dev_core_err(core, "get mem priv data failed");
		return -EINVAL;
	}

	if (mm_set->sram_pool.pool == NULL) {
		cn_dev_core_err(core, "create device pool fisrt!!!");
		return -EINVAL;
	}

	pminfo = cn_kzalloc(sizeof(struct mapinfo), GFP_KERNEL);
	if (!pminfo) {
		cn_dev_core_err(core, "Kzalloc mapInfo failed.");
		return -ENOMEM;
	}

	/*mapinfo init*/
	camb_init_mapinfo_basic(pminfo, mm_set, tag);
	pminfo->mem_meta.size = size;
	pminfo->mem_meta.type = CN_SHARE_MEM;
	pminfo->mem_meta.flag = CN_C_nA;

	*host_vaddr = (host_addr_t)
			cn_gen_pool_dma_alloc(mm_set->sram_pool.pool, size, &phy_tmp);
	if (!(*host_vaddr)) {
		cn_dev_core_warn(core, "no share memory to alloc");
		cn_kfree(pminfo);
		return -ENOMEM;
	}

	*device_vaddr = phy_tmp - mm_set->sram_pool.phys + mm_set->sram_virt_base;

	atomic_long_add(size, &mm_set->sram_pool.used_size);

	/*insert the mapinfo into rb tree*/
	pminfo->shm_info.device_paddr = phy_tmp;
	pminfo->shm_info.device_vaddr = *device_vaddr;
	pminfo->shm_info.host_vaddr = *host_vaddr;
	pminfo->shm_info.type = CN_SRAM_SHM;
	pminfo->shm_info.caller = caller;

	cn_dev_core_debug(core, "host_va = %lx dev_va = %llx pa:%#llx pa:%#llx",
			pminfo->shm_info.host_vaddr, pminfo->shm_info.device_vaddr,
			(u64)phy_tmp, (u64)pminfo->shm_info.device_paddr);

	/*phy_addr is null default. Only sram_rev_sbts invoke this function not NULL.*/
	if (phy_addr)
		*phy_addr = phy_tmp;

	insert_mapinfo(mm_priv_data, pminfo);

	return 0;
}

int cn_sram_get_base_addr(u64 tag, host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, phy_addr_t *phy_addr,
		size_t *size, void *pcore)
{
	*device_vaddr = cn_shm_get_dev_addr_by_name(pcore, "sram_reserved");
	if (*device_vaddr == -1) {
		cn_dev_err("Can not get device_vaddr.");
		return -1;
	}

	*host_vaddr = cn_shm_get_host_addr_by_name(pcore, "sram_reserved");
	if (*host_vaddr == -1) {
		cn_dev_err("Can not get host_vaddr.");
		return -1;
	}

	*phy_addr = cn_shm_get_phy_addr_by_name(pcore, "sram_reserved");
	if (*phy_addr == -1) {
		cn_dev_err("Can not get phy_addr.");
		return -1;
	}

	*size = cn_shm_get_size_by_name(pcore, "sram_reserved");
	if (*size == -1) {
		cn_dev_err("Can not get size.");
		return -1;
	}

	return 0;
}

int cn_sram_alloc(u64 tag, host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, size_t size, void *pcore)
{
	return camb_sram_alloc_internal(tag, host_vaddr, device_vaddr, NULL, size, pcore, __builtin_return_address(0));
}

int cn_sram_free(u64 tag, host_addr_t host_vaddr,
	dev_addr_t device_vaddr, void *pcore)
{
	struct mapinfo *pminfo = NULL;
	int ret = 0;
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = pcore;

	mm_set = (struct cn_mm_set *)core->mm_set;
	ret = camb_free_kref_get(tag, device_vaddr, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal for free", device_vaddr);
		return ret;
	}

	if (pminfo->shm_info.host_vaddr != host_vaddr) {
		camb_free_kref_put(pminfo);
		cn_dev_core_err(core, "host virtual address don't match!");
		return -EFAULT;
	}

	/**
	 * If the refcnt == 0, release the mapinfo.If not, only sub the refcnt and
	 * reserved the mapinfo in the rb tree.
	 **/
	camb_kref_put(pminfo, camb_sram_shm_release);

	return 0;
}

unsigned long cn_share_mem_mmap(u64 tag, host_addr_t host_vaddr,
	unsigned long size, int prot, int shm_type, void *pcore)
{
	struct file *fp = (struct file *)tag;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct vm_area_struct *vma;
	unsigned long va = 0;
	int ret = 0;
	unsigned long paddr, offset;
	unsigned long mapsize = 0;
	struct page *outbd_pages;
	struct cn_bus_set *bus;
	int page_index = 0;
	int i;
	u32 outbd_size;
	unsigned long usr_va = 0;

	mapsize = PAGE_SIZE + ((size + offset_in_page(host_vaddr) - 1) & PAGE_MASK);
	cn_dev_core_debug(core, "host_vaddr = 0x%lx size = 0x%lx mapsize = 0x%lx",
			host_vaddr, size, mapsize);

	va = vm_mmap(fp, 0, mapsize, prot, MAP_SHARED, 0);
	if (IS_ERR_VALUE(va)) {
		cn_dev_err("vm_mmap error va:%lx, size:%ld", va, mapsize);
		return va;
	}

	/*
	 * It is awkward, since find_vma()[R] and remap_pfn_range()[W] both
	 * requires mmap locking, meanwhile vm_mmap() holds the lock inside itself,
	 * so extend the locking scope in spite of minor performance lose
	 * */
	cn_mmap_write_lock(current->mm);

	vma = find_vma(current->mm, va);
	if (!vma) {
		cn_dev_err("mem alloc find vma is NULL");
		ret = -EFAULT;
		goto free_vm_mmap;
	}

#ifndef CONFIG_CNDRV_EDGE
	/*IO memory should be noncached on the ARM platform*/
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#endif
	switch (shm_type) {
	case CN_SHM_INBD:
		paddr = (unsigned long)cn_gen_pool_virt_to_phys(mm_set->devpool.pool,
						host_vaddr);
		cn_dev_core_debug(core, "pa = 0x%lx", paddr);

		ret = remap_pfn_range(vma, va, paddr >> PAGE_SHIFT, mapsize,
						vma->vm_page_prot);
		if (ret) {
			cn_dev_err("remap pfn range error va: 0x%lx mapsize:%ld"
						" ret: %d m->start: 0x%lx vm->end:0x%lx",
						va, mapsize, ret, vma->vm_start, vma->vm_end);
			goto free_vm_mmap;
		}
		cn_dev_core_debug(core, "va = 0x%lx offset_in_page(host_vaddr) = 0x%lx",
						va, offset_in_page(host_vaddr));
		usr_va = va + offset_in_page(host_vaddr);
		break;
	case CN_SHM_OUTBD:
		offset = (unsigned long)cn_gen_pool_virt_offset(mm_set->hostpool.pool,
						host_vaddr);
		page_index = offset >> PAGE_SHIFT;
		cn_dev_core_debug(core, "va offset = 0x%lx page index = %d",
						offset, page_index);
		bus = core->bus_set;
		outbd_size = cn_bus_get_outbound_size(bus);
		if (!outbd_size) {
			cn_dev_err("outbd_size = %#x", outbd_size);
			ret = -EINVAL;
			goto free_vm_mmap;
		} else if (((unsigned long)page_index * PAGE_SIZE + mapsize)
					> outbd_size) {
			cn_dev_err("Mmap size overflow!!! page_index = %d PAGE_SIZE = 0x%lx"
					   "mapsize = 0x%lx outbd_size = %#x",
					   page_index, PAGE_SIZE, mapsize, outbd_size);
			ret = -EINVAL;
			goto free_vm_mmap;
		}
		for (i = 0; i < mapsize / PAGE_SIZE; i++) {
			outbd_pages = cn_bus_get_outbound_pages(bus, page_index);
			remap_pfn_range(vma, va, page_to_pfn(outbd_pages),
					PAGE_SIZE, PAGE_SHARED);
			page_index++;
			va += PAGE_SIZE;
		}
		cn_dev_core_debug(core, "va = 0x%lx offset_in_page(host_vaddr) = 0x%lx",
						vma->vm_start, offset_in_page(host_vaddr));
		usr_va = vma->vm_start + offset_in_page(host_vaddr);
		break;
	default:
		cn_dev_core_err(core, "Flag should be 0(inbound) or 1(outbound)!!!");
		ret = -EINVAL;
		goto free_vm_mmap;
	}

	cn_mmap_write_unlock(current->mm);
	return usr_va;

free_vm_mmap:
	cn_mmap_write_unlock(current->mm);
	vm_munmap(va, mapsize);

	return ret;
}
EXPORT_SYMBOL(cn_share_mem_mmap);

int cn_share_mem_munmap(u64 tag, unsigned long va,
	unsigned long size, int shm_type, void *pcore)
{
	struct cn_core_set *core = pcore;
	int ret = 0;
	unsigned long mapsize = 0;

	mapsize = PAGE_SIZE + ((size + offset_in_page(va) - 1) & PAGE_MASK);

	switch (shm_type) {
	case CN_SHM_INBD:
	case CN_SHM_OUTBD:
		ret = vm_munmap(va & PAGE_MASK, mapsize);
		if (ret) {
			cn_dev_core_err(core, "vm munmap failed!!!");
			return -EINVAL;
		}
		break;
	default:
		cn_dev_core_err(core, "Flag should be 0(inbound) or 1(outbound)!!!");
	}

	return 0;
}
EXPORT_SYMBOL(cn_share_mem_munmap);

/*host mem size check for debugfs. Default close*/
static int camb_mem_dma_hmsc(host_addr_t host_vaddr, size_t size)
{
	struct vm_area_struct *vma;

	cn_mmap_read_lock(current->mm);
	vma = find_vma_intersection(current->mm, (unsigned long)host_vaddr,
			(unsigned long)(host_vaddr + size));
	cn_mmap_read_unlock(current->mm);
	if (!vma) {
		cn_dev_err("host mem alloc find vma is NULL");
		return -ENOMEM;
	}

	if ((host_vaddr + size) > vma->vm_end) {
		cn_dev_err("OutOfBound:host malloc addr is %#lx, malloc size is %#lx, transfer data size is %#lx no match!",
			host_vaddr, vma->vm_end - host_vaddr, size);
		return -EFAULT;
	}

	return 0;
}


static int
__set_prot_check(struct mapinfo *pminfo, dev_addr_t device_vaddr, size_t size)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	int ret = 0;

	ret = __params_check_addr_equal(pminfo, device_vaddr);
	if (ret) {
		return ret;
	}

	/**
	 * NOTE: if we support input zero size means set_prot for
	 * allocated device memroy which will avoid search rbtree
	 * in driverAPI.
	 **/
	ret = (size != 0) ? __params_check_size_equal(pminfo, size) : 0;
	if (ret) {
		return ret;
	}

	if (pminfo->mem_type == MEM_FA || pminfo->mem_type == MEM_FAKE) {
		cn_dev_core_err(core, "Prot of FA Alloc Memory can't be changed");
		return -ENXIO;
	}

	if (pminfo->ipcm_info) {
		cn_dev_core_err(core, "Prot of IPCM Memory can't be changed");
		return -ENXIO;
	}

	if (atomic_cmpxchg(&pminfo->free_flag, 0, 1) != 0) {
		cn_dev_core_err(core, "Addr: %#llx has been freed", pminfo->virt_addr);
		return -ENXIO;
	}

	if (atomic_cmpxchg(&pminfo->refcnt, 1, 0) != 1) {
		atomic_set(&pminfo->free_flag, 0);
		cn_dev_core_err(core, "Addr: %#llx is in use !", pminfo->virt_addr);
		return -EACCES;
	}

	return 0;
}

int cn_mem_set_prot(u64 tag, dev_addr_t device_vaddr, unsigned long size,
					int prot_flag, void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mapinfo *pminfo = NULL;
	unsigned long param[3];
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	struct file *fp = (struct file *)tag;
	int ret = 0;

	cn_dev_core_debug(core, "input prot_flag = %#x", prot_flag);
	pminfo = search_mapinfo_with_func(fp, mm_set, device_vaddr, size,
						__set_prot_check);

	if (IS_ERR_OR_NULL(pminfo)) {
		cn_dev_core_err(core, "mapinfo for addr(%#llx) invalid", device_vaddr);
		return PTR_ERR(pminfo);
	}

	param[0] = (unsigned long)udvm_get_iova_from_addr(pminfo->virt_addr);
	param[1] = (unsigned long)((size == 0) ? pminfo->mem_meta.size : size);
	param[2] = (unsigned long)prot_flag;

	memset(&remsg, 0x0, result_len);
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_set_prot",
						 param, 3 * sizeof(unsigned long),
						 &remsg, &result_len, sizeof(struct ret_msg));
	if (ret < 0) {
		atomic_inc(&pminfo->refcnt);
		atomic_set(&pminfo->free_flag, 0);
		cn_dev_core_err(core, "rpc set memory prot failed.");
		return -EPIPE;
	}

	if (remsg.ret < 0) {
		atomic_inc(&pminfo->refcnt);
		atomic_set(&pminfo->free_flag, 0);
		cn_dev_core_err(core, "flag of memory prot error");
		return remsg.ret;
	}

	pminfo->mem_meta.flag = (unsigned int)remsg.ret;
	atomic_inc(&pminfo->refcnt);
	atomic_set(&pminfo->free_flag, 0);
	pr_debug("%s: new memory flag = 0x%x", __func__, pminfo->mem_meta.flag);

	return 0;
}

int camb_mem_alloc_internal(u64 tag,
			  dev_addr_t *device_vaddr,
			  struct mem_attr *pattr,
			  void *mem_set, struct mapinfo **ppminfo)
{
	struct cn_mm_set *mm_set = mem_set;
	struct mapinfo *pminfo = NULL;
	struct cn_core_set *core = mm_set->core;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0, retry_times = 0;
	struct file *fp = (struct file *)tag;
	struct cn_mm_priv_data *mm_priv_data;
	unsigned int rpc_free_times_last = 0;
	unsigned int rpc_free_times = 0;
	unsigned long flags;
	struct fa_stat stat;
	struct cn_fa_array *arr = mm_set->fa_array;
	unsigned int align_enable = mm_set->alloc_align.align_enable;
	unsigned int align_order = mm_set->alloc_align.align_order;
	bool do_fa = 0;

	mm_priv_data = __get_mm_priv(fp, mm_set);
	if (!mm_priv_data) {
		cn_dev_core_err(core, "get mem priv data failed");
		return -EINVAL;
	}

	cn_dev_core_debug(core, ">>>>>>>>>>>>>>Enter memory allocator<<<<<<<<<<<<<<<<");
	cn_dev_core_debug(core, "type = %d, Total size = %#lx, alignment = 0x%x, affinity = %d"
		, pattr->type, pattr->size, pattr->align, pattr->affinity);

	if (!pattr->size || (int)pattr->affinity >= 4 || (int)pattr->affinity < -2) {
		return -EINVAL;
	}

	if (mm_set->enable_compress_alloc)
		pattr->flag |= 1UL << ATTR_compress;

	if (!mm_set->compress_support)
		pattr->flag &= ~(1UL << ATTR_compress);

	if (pattr->type == CN_SEPARATE_MEM) {
		if (!mm_set->separate_support) {
			cn_dev_core_debug(core, "not support separate alloc for current plat");
			return -EPERM;
		}

		if (!IS_ALIGNED(pattr->size, 1UL << 20)) {
			cn_dev_core_err(core, "alloc separate memory must make sure input size is aligned with 1MB");
			return -EINVAL;
		}
	}

	pminfo = cn_kzalloc(sizeof(struct mapinfo), GFP_KERNEL);
	if (!pminfo) {
		cn_dev_core_err(core, "kzalloc mapInfo failed.");
		return -ENOMEM;
	}

	/*mapinfo init*/
	camb_init_mapinfo_basic(pminfo, mm_set, tag);

	/* The fast alloc will be activated when
	 * 1. the allocated size fits the fa alloc_size, and
	 * 2. the tag is not NULL (That means the allocation is calling from kernel
	 *    space when the tag is zero), and
	 * 3. the fa is enable, and
	 * 4. the allocated mem_type is CN_IPU_MEM/CN_CONST_MEM/CN_COMPRESS_MEM.
	 */
	do_fa = (!!tag) && (pattr->size < arr->alloc_size * 1024) &&
		(mm_set->fa_array->enable == 1) &&
		(pattr->type == CN_IPU_MEM || pattr->type == CN_CONST_MEM || pattr->type == CN_COMPRESS_MEM);
	/* if align enabled, then align alloc size, otherwise, do nothing */
	if ((!!align_enable) && !do_fa) {
		pattr->size = align_up(pattr->size, 1 << align_order);
		cn_dev_core_debug(core, "after size align: type = %d, Total size = %#lx, alignment = 0x%x, affinity = %d",
			pattr->type, pattr->size, pattr->align, pattr->affinity);
	}

	/*init the memory attributes*/
	pminfo->mem_meta.size = (unsigned long)pattr->size;
	pminfo->mem_meta.align = pattr->align;
	pminfo->mem_meta.type = pattr->type;
	pminfo->mem_meta.affinity = pattr->affinity;
	pminfo->mem_meta.flag = pattr->flag;
	pminfo->mem_meta.vmid = pattr->vmid;
	strncpy(pminfo->mem_meta.name, pattr->name, EXT_NAME_SIZE);

	camb_config_redzone_size(fp, mm_set, pminfo, &pattr->size, do_fa);

	memset(&remsg, 0x00, sizeof(struct ret_msg));
	if (do_fa) {
		if (pattr->affinity == -2)
			pattr->affinity = 4;

		ret = camb_fa_alloc(mm_set->fa_array, pattr, pattr->size, &pminfo->fa_info);
		if (ret < 0) {
			camb_dump_error_minfo(tag, pattr, mm_set, ret, NULL);
			cn_kfree(pminfo);
			return ret;
		}

		if (pattr->affinity == 4)
			pattr->affinity = -2;

		pminfo->mem_type = MEM_FA;
		pminfo->is_linear = pminfo->fa_info.is_linear;
		cn_dev_core_debug(core, "FA: get device = %#llx", pminfo->virt_addr);
	} else {
		rpc_free_times_last = atomic_read(&mm_set->rpc_free_times);
call_rpc:
		ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_alloc",
							 pattr, sizeof(struct mem_attr),
							 &remsg, &result_len, sizeof(struct ret_msg));
		/* It's setted as MEM_LG defaultly. And it maybe changes to other value
		 * according the context. */
		pminfo->mem_type = MEM_LG;

		if (ret < 0) {
			cn_dev_core_err(core, "cnrpc client request mem failed.");
			cn_kfree(pminfo);
			return -EPIPE;
		}

		if (remsg.ret) {
			if (remsg.ret == -ENOSPC) {
				/*If either fa free chunk can be recycled or delay free list is not
				  empty, then goto mem alloc retry condition.*/

				/*only free worker is idle && mem list is NULL,
				  can be assumed all mem had call commu for free*/
				spin_lock_irqsave(&mm_set->work_sync_lock, flags);
				rpc_free_times = atomic_read(&mm_set->rpc_free_times);

				if (((rpc_free_times != rpc_free_times_last) ||
					 (!llist_empty(&mm_set->free_list)) ||
					 (atomic_read(&mm_set->free_worker_state) == WORK_RUNNING)) &&
					(retry_times < MAX_RETRY_TIMES)) {
					rpc_free_times_last = rpc_free_times;
					spin_unlock_irqrestore(&mm_set->work_sync_lock, flags);
					goto malloc_retry;
				} else {
					spin_unlock_irqrestore(&mm_set->work_sync_lock, flags);
					ret = camb_fa_statistic(arr, &stat);
					if ((!ret) && (stat.shrink_size)) {
						camb_fa_shrink(mm_set, mm_set->fa_array, true);
					} else {
						goto malloc_error;
					}
				}

malloc_retry:
				/* The timer has been modified form 10us to 10ms, so we
				 * should make sure the retry_time is large than the
				 * frequency of hrtimer. Here do change the minimum value of
				 * schedule timeout from 100us to 210us.
				 */
				schedule_timeout_interruptible(usecs_to_jiffies(210 * (1 + retry_times)));

				if (fatal_signal_pending(current)) {
					cn_dev_core_err(core, "fatal signal received, mem alloc abort.");
					cn_kfree(pminfo);
					return -EINTR;
				}

				retry_times++;
				goto call_rpc;
malloc_error:
				cn_dev_core_err(core,
					"MEM_TIMEOUT: already try retry times %d", retry_times);
				camb_dump_error_minfo(tag, pattr, mm_set, remsg.ret, &remsg.meminfo);
			} else {
				camb_dump_error_minfo(tag, pattr, mm_set, remsg.ret, &remsg.meminfo);
			}

			cn_kfree(pminfo);
			return remsg.ret;
		}

		cn_dev_core_debug(core, "LG: get device = %#llx", remsg.device_addr);
		pminfo->virt_addr = remsg.device_addr;
		pminfo->is_linear = remsg.is_linear;
	}

	/* It means that the memory has been allocated in the kernel context when
	 * the tag is NULL. And sets the mem_type as MEM_KEXT.
	 */
	if (!tag)
		pminfo->mem_type = MEM_KEXT;

	if (pminfo->mem_type == MEM_LG) {
		pminfo->align_size = ALIGN(pminfo->mem_meta.size, camb_get_page_size());
	} else {
		pminfo->align_size = camb_fixsize(mm_set->fa_array, pminfo->mem_meta.size);
	}

	/*insert the mapinfo into rb tree*/
	insert_mapinfo(mm_priv_data, pminfo);

	/* NOTE: we will set unified device_address in insert_mapinfo if udvm is
	 * enabled, so output address need get from pminfo->virt_addr after
	 * insert_mapinfo
	 **/
	*device_vaddr = pminfo->virt_addr;

	/* DRIVER-12456: pattr->size maybe modified while memcheck is enabled,
	 * pminfo->mem_meta.size is real size need be counted. */
	__sync_add_and_fetch(&mm_set->phy_used_mem, (unsigned long)pminfo->mem_meta.size);
	__sync_add_and_fetch(&mm_set->vir_used_mem, (unsigned long)pminfo->mem_meta.size);
	__update_pid_info_node(pminfo, add, (u64)pminfo->mem_meta.size);

	/* Used for flush the pcie vf bar's cau accurately. Bits 0~36 stand for
	 * the stream id to index the cau*/
	__sync_lock_test_and_set(&mm_set->smmu_invalid_mask, 0xfffffffff);

	camb_set_redzone(fp, pminfo, mm_set);

	if (unlikely(ppminfo)) {
		*ppminfo = pminfo;
	}

	trace_alloc(pminfo);

	/* DRIVER-11107: ANT LLC cacheLine alias problem workaround */
	if (pminfo->mem_meta.type == CN_SEPARATE_MEM) llc_maintanance(core, 3);

	return 0;
}

int camb_rst_pst_l2cache(u64 tag, void *mem_set)
{
	int ret = 0;
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = mm_set->core;

	cn_dev_core_info(core, "reset llc persisting for dev %x", mm_set->devid);
	if (mm_set->llc_ops.llc_lock_clr) {
		ret = mm_set->llc_ops.llc_lock_clr(core);
	} else {
		return -EPERM;
	}
	cn_dev_core_info(core,
					 "LLC persisting clear %s.\n", ret == 0 ? "successfully" : "failed");

	return ret;
}

/* NOTE: user must make sure input pminfo is valid pointer, before calling this interface. */
int camb_fill_mapinfo_sgtable(struct mapinfo *pminfo)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct sg_table *table = NULL;
	struct scatterlist *sg = NULL;
	struct sglist_param_t params = {};
	struct sglist_remsg_t *remsg = NULL;
	ssize_t result_len = 0, filled_size = 0, aligned_size = 0;
	int i = 0, ret = 0, max_counts = SGLIST_MAX_COUNTS(core->support_ipcm);
	int retry_times = 0;
	bool first_rpc = true;

	if (pminfo->sg_table) {
		cn_dev_core_debug(core, "pminfo's sg_table is exist");
		return 0;
	}

	result_len = max_counts * sizeof(struct sglist_node_t) +
		sizeof(struct sglist_remsg_t);

	remsg = cn_kzalloc(result_len, GFP_KERNEL);
	if (!remsg) {
		cn_dev_core_err(core, "create remsg buffer failed");
		return -ENOMEM;
	}

	table = cn_kzalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!table) {
		cn_dev_core_err(core, "create sg_table buffer failed");
		cn_kfree(remsg);
		return -ENOMEM;
	}

	if (pminfo->mem_type == MEM_FA) {
		aligned_size = camb_fixsize(mm_set->fa_array, pminfo->mem_meta.size);
	} else {
		aligned_size = ALIGN(pminfo->mem_meta.size, camb_get_page_size());
	}

	if (!IS_ALIGNED(aligned_size, PAGE_SIZE)) {
		cn_dev_core_err(core, "cambricon minimum align size smaller than PAGE SIZE");
		cn_kfree(table);
		cn_kfree(remsg);
		return -EINVAL;
	}

	params.iova = udvm_get_iova_from_addr(pminfo->virt_addr);
	params.size = aligned_size;
	params.host_page_shift = PAGE_SHIFT;

refill:
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_get_sglist",
						 &params, sizeof(struct sglist_param_t), remsg,
						 &result_len, result_len);
	if (ret || remsg->ret) {
		cn_dev_core_err(core, "Failed call rpc_mem_get_sglist(%d, %d)",
				ret, remsg->ret);
		if (!first_rpc) sg_free_table(table);
		cn_kfree(table);
		cn_kfree(remsg);
		return -EPIPE;
	}

	if (first_rpc) {
		retry_times = DIV_ROUND_UP(remsg->total_counts, max_counts) - 1;
		ret = sg_alloc_table(table, remsg->total_counts, GFP_KERNEL);
		if (ret) {
			cn_dev_core_err(core, "failed alloc sg_table");
			cn_kfree(table);
			cn_kfree(remsg);
			return -ENOMEM;
		}

		sg = table->sgl;
	}

	for (i = 0; i < remsg->curr_counts; i++) {
		sg_set_page(sg, pfn_to_page(remsg->nodes[i].pfn), remsg->nodes[i].length, 0);
		sg_dma_len(sg) = sg->length;
		sg = sg_next(sg);
		filled_size += remsg->nodes[i].length;
	}

	if (retry_times--) {
		first_rpc = false;
		params.size -= filled_size;
		params.iova += filled_size;
		filled_size = 0;
		goto refill;
	}

	pminfo->sg_table = table;
	cn_kfree(remsg);
	return 0;
}

int cn_mem_alloc(u64 tag,
		dev_addr_t *device_vaddr, struct mem_attr *pattr, void *pcore)
{
	int ret = 0;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	ret = cn_smlu_try_charge(core, mem_cgrp_id, (void *)tag, NULL, pattr->size);
	if (ret) {
		cn_dev_core_debug(core, "smlu:memory alloc check failed(%d -- %#lx),because of memory limitations",
							pattr->affinity, pattr->size);
		return -ENOSPC;
	}

	ret = camb_mem_alloc_internal(tag, device_vaddr, pattr, mm_set, NULL);

	if (ret) {
		cn_smlu_uncharge(core, mem_cgrp_id, (void *)tag, NULL, pattr->size);
	}

	return ret;
}

int cn_mem_perf_alloc(__u64 tag, dev_addr_t *device_vaddr, struct mem_attr *pmattr,
		struct mem_perf_attr *pattr, void *pcore)
{
	int ret = 0;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mapinfo *pminfo = NULL;

	if (cn_mem_perf_enable(tag) <= 0) {
		/*perf disable or ctrl + c*/
		return cn_mem_alloc(tag, device_vaddr, pmattr, pcore);
	}

	ret = cn_smlu_try_charge(core, mem_cgrp_id, (void *)tag, NULL, pattr->attr.size);
	if (ret) {
		cn_dev_core_debug(core, "smlu:memory alloc check failed(%d -- %#lx),because of memory limitations",
							pattr->attr.affinity, pattr->attr.size);
		return -ENOSPC;
	}

	ret = camb_mem_alloc_internal(tag, device_vaddr, &(pattr->attr), mm_set, &pminfo);
	if (ret) {
		cn_smlu_uncharge(core, mem_cgrp_id, (void *)tag, NULL, pattr->attr.size);
		return ret;
	}

	pminfo->context_id = pattr->context_id;

	return cn_mem_perf_put_details(pattr->correlation_id, pminfo, DEV_MEM_MALLOC);
}

int cn_mdr_alloc_internal(u64 tag,
			  dev_addr_t *device_vaddr,
			  struct mem_attr *pattr,
			  void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct mapinfo *pminfo = NULL;
	struct cn_core_set *core = mm_set->core;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;
	struct file *fp = (struct file *)tag;
	struct cn_mm_priv_data *mm_priv_data;

	mm_priv_data = __get_mm_priv(fp, mm_set);
	if (!mm_priv_data) {
		cn_dev_core_err(core, "get mem priv data failed");
		return -EINVAL;
	}

	cn_dev_core_debug(core, ">>>>>>>>>>>>>>Enter memory allocator<<<<<<<<<<<<<<<<");
	cn_dev_core_debug(core, "type = %d, Total size = %#lx, alignment = 0x%x"
		, pattr->type, pattr->size, pattr->align);

	/* mdr alloc not support -2: multi channel. */
	if (!pattr->size || (int)pattr->affinity >= 4 || (int)pattr->affinity <= -2) {
		return -EINVAL;
	}

	pminfo = cn_kzalloc(sizeof(struct mapinfo), GFP_KERNEL);
	if (!pminfo) {
		cn_dev_core_err(core, "Kzalloc mapInfo failed.");
		return -ENOMEM;
	}

	/*mapinfo init*/
	camb_init_mapinfo_basic(pminfo, mm_set, tag);
	/*init the memory attributes*/
	pminfo->mem_meta.size = (unsigned long)pattr->size;
	pminfo->mem_meta.align = pattr->align;
	pminfo->mem_meta.type = pattr->type;
	pminfo->mem_meta.affinity = pattr->affinity;
	pminfo->mem_meta.flag = pattr->flag;
	pminfo->mem_meta.vmid = pattr->vmid;
	strncpy(pminfo->mem_meta.name, pattr->name, EXT_NAME_SIZE);

	/*it is not a ipc shared memory, so...*/
	pminfo->ipcm_info = NULL;
	memset(&remsg, 0x00, sizeof(struct ret_msg));

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mdr_mem_alloc",
						 pattr, sizeof(struct mem_attr),
						 &remsg, &result_len, sizeof(struct ret_msg));
	pminfo->mem_type = MEM_LG;

	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client request mem failed.");
		cn_kfree(pminfo);
		return -EPIPE;
	}

	if (remsg.ret) {
		camb_dump_error_minfo(tag, pattr, mm_set, remsg.ret, &remsg.meminfo);
		cn_kfree(pminfo);
		return remsg.ret;
	}

	cn_dev_core_debug(core, "get device = %#llx", remsg.device_addr);
	cn_dev_core_debug(core, "mdr device = %#llx", remsg.mdr_va.mdr_addr);
	/*insert the mapinfo into rb tree*/
	pminfo->virt_addr = remsg.mdr_va.mdr_addr;
	pminfo->mdr_peer_addr = remsg.mdr_va.device_addr;

	insert_mapinfo(mm_priv_data, pminfo);

	*device_vaddr = pminfo->virt_addr;

	trace_mdr_alloc(pminfo);

	__sync_add_and_fetch(&mm_set->phy_used_mem, (unsigned long)pattr->size);
	__sync_add_and_fetch(&mm_set->vir_used_mem, (unsigned long)pattr->size);

	/* Used for flush the pcie vf bar's cau accurately. Bits 0~36 stand for
	 * the stream id to index the cau*/
	__sync_lock_test_and_set(&mm_set->smmu_invalid_mask, 0xfffffffff);

	__update_pid_info_node(pminfo, add, (u64)pattr->size);

	return 0;
}

int cn_mdr_alloc(u64 tag,
		dev_addr_t *device_vaddr, struct mem_attr *pattr, void *pcore)
{
	int ret = 0;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	ret = cn_smlu_try_charge(core, mem_cgrp_id, (void *)tag, NULL, pattr->size);
	if (ret) {
		cn_dev_core_debug(core, "smlu:mdr memory alloc check failed(%d -- %#lx),because of memory limitations",
							pattr->affinity, pattr->size);
		return -ENOSPC;
	}

	if ((int)pattr->affinity == -3 || mm_set->linear.is_support) {
		pattr->affinity = -1;
		pattr->type = CN_IPU_MEM;

		ret = camb_mem_alloc_internal(tag, device_vaddr, pattr, mm_set, NULL);
	} else {
		ret = cn_mdr_alloc_internal(tag, device_vaddr, pattr, mm_set);
	}

	if (ret) {
		cn_smlu_uncharge(core, mem_cgrp_id, (void *)tag, NULL, pattr->size);
	}

	return ret;
}

int cn_mem_free(u64 tag, dev_addr_t virt_addr, void *pcore)
{
	struct file *fp = (struct file *)tag;
	int ret = 0;
	struct mapinfo *pminfo = NULL;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	cn_dev_core_debug(core, "free addr = %#llx ", virt_addr);

	ret = camb_free_kref_get(tag, virt_addr, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal for free", virt_addr);
		return ret;
	}

	ret = __params_check_addr_equal(pminfo, virt_addr);
	if (ret) {
		camb_free_kref_put(pminfo);
		return ret;
	}

	if (unlikely(pminfo->mem_type == MEM_FAKE)) {
		camb_free_kref_put(pminfo);
		return ret;
	}

	trace_free(pminfo);
	camb_free_ts_node_init(pminfo);
	camb_free_ts_node_record(pminfo, FREE_TS_CALLFREE);

	if (pminfo->mem_type != MEM_VMM && pminfo->mem_type != MEM_IE) {
		__update_pid_info_node(pminfo, sub, (u64)pminfo->mem_meta.size);
		cn_smlu_uncharge(core, mem_cgrp_id, (void *)pminfo->tag, pminfo->active_ns, (u64)pminfo->mem_meta.size);
	}

	ret = camb_check_redzone(fp, pminfo, mm_set);

	mapinfo_release(pminfo);

	return ret;
}

int cn_mem_perf_free(u64 tag, dev_addr_t virt_addr, __u64 correlation_id, void *pcore)
{
	struct file *fp = (struct file *)tag;
	int ret = 0;
	struct mapinfo tmp;
	struct mapinfo *pminfo = NULL;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	cn_dev_core_debug(core, "free addr = %#llx ", virt_addr);

	ret = camb_free_kref_get(tag, virt_addr, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal for free", virt_addr);
		return ret;
	}

	ret = __params_check_addr_equal(pminfo, virt_addr);
	if (ret) {
		camb_free_kref_put(pminfo);
		return ret;
	}

	if (unlikely(pminfo->mem_type == MEM_FAKE)) {
		camb_free_kref_put(pminfo);
		return ret;
	}

	trace_free(pminfo);
	camb_free_ts_node_init(pminfo);
	camb_free_ts_node_record(pminfo, FREE_TS_CALLFREE);

	if (pminfo->mem_type != MEM_VMM && pminfo->mem_type != MEM_IE) {
		__update_pid_info_node(pminfo, sub, (u64)pminfo->mem_meta.size);
		cn_smlu_uncharge(core, mem_cgrp_id, (void *)pminfo->tag, pminfo->active_ns, (u64)pminfo->mem_meta.size);
	}

	ret = camb_check_redzone(fp, pminfo, mm_set);

	tmp.tag        = pminfo->tag;
	tmp.mm_set     = pminfo->mm_set;
	tmp.mem_meta   = pminfo->mem_meta;
	tmp.align_size = pminfo->align_size;
	tmp.virt_addr  = pminfo->virt_addr;
	tmp.tgid       = pminfo->tgid;
	tmp.mem_type   = pminfo->mem_type;
	tmp.context_id = pminfo->context_id;
	tmp.is_linear  = pminfo->is_linear;

	mapinfo_release(pminfo);

	if (cn_mem_perf_put_details(correlation_id, &tmp, DEV_MEM_FREE)) {
		cn_dev_core_err(core, "add mem perf free data failed!!!");
	}

	return ret;
}

static int __is_support_merge(struct cn_mm_set *mm_set)
{
	switch (mm_set->devid) {
	case MLUID_100:
	case MLUID_220:
	case MLUID_220_EDGE:
	case MLUID_270:
	case MLUID_270V:
	case MLUID_270V1:
	case MLUID_290:
	case MLUID_290V1:
		return 1;
	default:
		return 0;
	}
}

/*NOTE:do not support vpu memory to merged*/
int cn_mem_merge(u64 tag, dev_addr_t *merged_addr, dev_addr_t *virt_addr,
		int cnt, void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mapinfo **minfo_array = NULL;
	struct mapinfo *pminfo = NULL;
	dev_addr_t vaddr = 0;
	int i = 0, j = 0, k = 0;
	int ret = 0;
	__u64 *param;
	__u64 *tmp = NULL;
	unsigned int mm_type = 0;
	__u64 total_size = 0;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	struct file *fp = (struct file *)tag;
	struct cn_mm_priv_data *mm_priv_data;
	struct cn_fa_array *arr = mm_set->fa_array;
	spinlock_t *minfo_lock = NULL;

	mm_priv_data = __get_mm_priv(fp, mm_set);
	if (!mm_priv_data) {
		cn_dev_core_err(core, "get mem priv data failed");
		return -EINVAL;
	}

	if (!__is_support_merge(mm_set)) {
		cn_dev_core_err(core, "this platform don't support merge.");
		return -EPERM;
	}

	/* NOTE: in mlu200 platform, input address to do merge must belong to the same device */
	minfo_lock = __get_minfo_lock_with_mmpriv(mm_priv_data, virt_addr[0]);
	if (!minfo_lock) {
		cn_dev_core_err(core, "get minfo_lock failed");
		return -EINVAL;
	}

	if (unlikely(!(cnt > 0))) {
		return -EINVAL;
	}

	minfo_array =
		(struct mapinfo **)cn_kzalloc(sizeof(struct mapinfo *) * cnt, GFP_KERNEL);
	if (!minfo_array) {
		cn_dev_core_err(core, "kzalloc mapInfo array failed.");
		return -ENOMEM;
	}

	pminfo = (struct mapinfo *)cn_kzalloc(sizeof(struct mapinfo), GFP_KERNEL);
	if (!pminfo) {
		cn_dev_core_err(core, "kzalloc mapInfo failed.");
		ret = -ENOMEM;
		goto err_kmalloc_mapinfo;
	}

	/*| vmid | length | data |*/
	param = (__u64 *)cn_kzalloc(sizeof(__u64) * (cnt + 1) * 2, GFP_KERNEL);
	if (unlikely(!param)) {
		cn_dev_core_err(core, "Kzalloc merge sglist memory failed.");
		ret = -ENOMEM;
		goto err_kmalloc_mgsg;
	}

	if ((sizeof(__u64) * (cnt + 1) * 2) > RPC_TRANS_MAX_LEN(core->support_ipcm)) {
		cn_dev_core_err(core, "Param Data too Large, Out of buffer");
		ret = -EINVAL;
		goto err_large_size;
	}

	param[0] = -1;
	param[1] = cnt * 2;
	tmp = param + 2;
	/*get all the mapinfos to merge*/
	for (i = 0; i < cnt; i++) {
		vaddr = virt_addr[i];
		cn_dev_core_debug(core, "VirtualAddress will be merged = %#lx",
			(unsigned long)vaddr);

		/*NOTE:If the address has been free when searched the mapinfos for
		 * merge, it will be error.*/
		spin_lock(minfo_lock);
		minfo_array[i] = search_mapinfo(mm_priv_data, vaddr);
		if (unlikely(!minfo_array[i])) {
			spin_unlock(minfo_lock);
			cn_dev_core_err(core, "(%#llx)get mapinfo invalid!",
							vaddr);
			ret = -ENXIO;
			k = i;
			goto err_search_mapinfo;
		}

		/* Merge Addr Need 512K Align */
		if ((minfo_array[i]->virt_addr != vaddr) ||
			(minfo_array[i]->mem_meta.size & (arr->alloc_size * 1024 - 1))) {
			spin_unlock(minfo_lock);
			cn_dev_core_err(core, "merged_addr don't match alloc_addr!");
			ret = -ENXIO;
			k = i;
			goto err_search_mapinfo;
		}

		if (minfo_array[i]->ipcm_info ||
			(minfo_array[i]->mem_meta.type == CN_MDR_MEM) ||
			(minfo_array[i]->mem_type == MEM_FAKE)) {
			spin_unlock(minfo_lock);
			cn_dev_core_err(core, "input address %#llx is invalid for merge", vaddr);
			ret = -ENXIO;
			k = i;
			goto err_search_mapinfo;
		}

		if (atomic_cmpxchg(&minfo_array[i]->free_flag, 0, 1) != 0) {
			spin_unlock(minfo_lock);
			cn_dev_core_err(core, "Addr:%#llx has been freed", vaddr);
			k = i;
			ret = -ENXIO;
			goto err_search_mapinfo;
		}

		/* Set the refcount = 0 when the refcount is 1. To make sure that it
		 * doesn't have any copy ops while mem_merge.*/
		if (atomic_cmpxchg(&minfo_array[i]->refcnt, 1, 0) != 1) {
			spin_unlock(minfo_lock);
			cn_dev_core_err(core, "Merge: device address(%#llx) has been used!",
							 minfo_array[i]->virt_addr);
			camb_free_kref_put(minfo_array[i]);
			ret = -EACCES;
			k = i;
			goto err_check_ref_legality;
		}

		spin_unlock(minfo_lock);

		/* delete mapinfo */
		delete_mapinfo(mm_priv_data, minfo_array[i]);

		*tmp = minfo_array[i]->virt_addr;
		tmp++;
		*tmp = minfo_array[i]->mem_meta.size;
		tmp++;
		total_size += minfo_array[i]->mem_meta.size;
	}

	/*All the addrs to merge have the same type*/
	mm_type = minfo_array[0]->mem_meta.type;
	memset(&remsg, 0x00, sizeof(struct ret_msg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_merge",
			param, sizeof(__u64) * (cnt + 1) * 2,
			&remsg, &result_len, sizeof(struct ret_msg));

	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client request mem failed.");
		k = cnt;
		ret = -EPIPE;
		goto err_rpc_mem;
	}

	if (remsg.ret) {
		cn_dev_core_err(core, "rpc_mem_merge error status is %d", remsg.ret);
		ret = remsg.ret;
		k = cnt;
		goto err_rpc_mem;
	}

	*merged_addr = remsg.device_addr;

	/* merge finish, need release all resoucre created at merge start */
	for (i = 0; i < cnt; i++) {
		cn_kfree(minfo_array[i]);
	}
	cn_kfree(minfo_array);
	cn_kfree(param);

	/*init the new mapinfo*/
	camb_init_mapinfo_basic(pminfo, mm_set, tag);

	pminfo->mem_meta.vmid = -1;
	pminfo->mem_meta.type = mm_type;
	pminfo->mem_meta.size = total_size;
	pminfo->virt_addr = *merged_addr;
	insert_mapinfo(mm_priv_data, pminfo);

	return 0;

err_rpc_mem:
err_check_ref_legality:
err_search_mapinfo:
	for (j = 0; j < k; j++) {
		camb_free_kref_put(minfo_array[j]);
		atomic_set(&minfo_array[j]->refcnt, 1);
		insert_mapinfo(mm_priv_data, minfo_array[j]);
	}

err_large_size:
	cn_kfree(param);
err_kmalloc_mgsg:
	cn_kfree(pminfo);
err_kmalloc_mapinfo:
	cn_kfree(minfo_array);

	return ret;
}

#ifdef PEER_FREE_TEST
enum OFFSITE_FREE_TEST_FLAG {
	TEST_FLAG_NORMAL = 0,
	TEST_FLAG_CLEAR_LIST,
	TEST_FLAG_MUL_THREAD,
};

int camb_peer_free_test(u64 tag, dev_addr_t test_flag, dev_addr_t *virt_addr,
		int cnt, void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	dev_addr_t vaddr = 0;
	int i = 0, k = 0;
	int ret = 0;
	__u64 *param;
	__u64 *tmp = NULL;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);

	if (unlikely(!(cnt > 0))) {
		return -EINVAL;
	}

	/*| vmid | length | data |*/
	param = (__u64 *)cn_kzalloc(sizeof(__u64) * (cnt + 2), GFP_KERNEL);
	if (unlikely(!param)) {
		cn_dev_core_err(core, "Kzalloc merge sglist memory failed.");
		ret = -ENOMEM;
		return ret;
	}

	if ((sizeof(__u64) * (cnt + 2)) > 0x1000) {
		cn_dev_core_err(core, "Param Data too Large, Out of buffer");
		ret = -EINVAL;
		goto err_large_size;
	}

	param[0] = test_flag;
	param[1] = cnt;
	tmp = param + 2;
	/*get all the mapinfos to merge*/
	for (i = 0; i < cnt; i++) {
		vaddr = virt_addr[i];
		*tmp = vaddr;
		tmp++;
	}

	/*All the addrs to merge have the same type*/
	memset(&remsg, 0x00, sizeof(struct ret_msg));
	cn_dev_core_info(core, "%s: tag = 0x%llx\n", __func__, tag);
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_peer_free_test",
			param, sizeof(__u64) * (cnt + 2), &remsg, &result_len,
			sizeof(struct ret_msg));

	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client request mem failed.");
		k = cnt;
		ret = -EPIPE;
		goto err_large_size;
	}

	if (remsg.ret) {
		cn_dev_core_err(core, "rpc_peer_free_test error status is %d", remsg.ret);
		ret = remsg.ret;
		goto err_large_size;
	}

	cn_kfree(param);

	return 0;

err_large_size:
	cn_kfree(param);

	return ret;
}
#endif	//#ifdef PEER_FREE_TEST

#if 0
static int __get_const_type(void *mem_set, struct mapinfo *pminfo, int *type)
{
	struct cn_mm_set *mm_set = mem_set;

	if ((mm_set->devid != MLUID_580 && mm_set->devid != MLUID_590) ||
						mm_set->notify_l1c_sync == false)
		return 0;

	if (!strncmp(pminfo->mem_meta.name, "const_inst", 10)) {
		*type = MEM_CI;
		return 1;
	} else if (!strncmp(pminfo->mem_meta.name, "const_data", 10)) {
		*type = MEM_CD;
		return 1;
	} else {
		*type = MEM_INV;
		return 0;
	}
}
#endif

unsigned long cn_mem_copy_h2d(u64 tag, host_addr_t host_vaddr,
		dev_addr_t device_vaddr, size_t size, void *pcore)
{
	int ret = 0, lock_ret = 0;
	unsigned long rcnt = 0;/*residual count*/
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mapinfo *pminfo = NULL;
	struct transfer_s t;

	if (dma_hmsc_enable) {
		ret = camb_mem_dma_hmsc(host_vaddr, size);
		if (ret < 0)
			return ret;
	}

	ret = camb_kref_get_validate(tag, device_vaddr, size, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal for copy", device_vaddr);
		return ret;
	}

	/* NOTES: In the edge platform, such as mlu220_edge and CE3226, the sync H2D
	 * process will be implemented in the user space. */
	/**
	 * FIXME: fix bug: DRIVER-4186
	 *    uva_locked will traverse rbtree for uva, will reduce interface
	 * performance. need optimize in the future
	 **/
	lock_ret = cn_pinned_mem_uva_locked(host_vaddr);
	/*call pcie dma function to transfer*/
	TRANSFER_INIT(t, host_vaddr, device_vaddr, size, DMA_H2D);
	rcnt = cn_bus_dma(core->bus_set, &t);
	if (!lock_ret)
		cn_pinned_mem_uva_unlocked(host_vaddr);

	camb_kref_put_range(pminfo, device_vaddr, size, camb_mem_release);

	return rcnt;
}

unsigned long cn_mem_copy_d2h(u64 tag, host_addr_t host_vaddr,
		dev_addr_t device_vaddr, ssize_t size, void *pcore)
{
	int ret = 0, lock_ret = 0;
	unsigned long rcnt = 0;/*residual count*/
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mapinfo *pminfo = NULL;
	struct transfer_s t;

	if (dma_hmsc_enable) {
		ret = camb_mem_dma_hmsc(host_vaddr, size);
		if (ret < 0)
			return ret;
	}

	ret = camb_kref_get_validate(tag, device_vaddr, size, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal for copy", device_vaddr);
		return ret;
	}

	/**
	 * FIXME: fix bug: DRIVER-4186
	 *    uva_locked will traverse rbtree for uva, will reduce interface
	 * performance. need optimize in the future
	 **/
	lock_ret = cn_pinned_mem_uva_locked(host_vaddr);
	/*call pcie dma function to transfer*/
	TRANSFER_INIT(t, host_vaddr, device_vaddr, size, DMA_D2H);
	rcnt = cn_bus_dma(core->bus_set, &t);
	if (!lock_ret)
		cn_pinned_mem_uva_unlocked(host_vaddr);

	camb_kref_put_range(pminfo, device_vaddr, size, camb_mem_release);
	return rcnt;
}

static bool __check_is_readonly(struct mapinfo *pminfo)
{
	struct cn_core_set *core = ((struct cn_mm_set *)pminfo->mm_set)->core;

	/* DRIVER-13174: to remove the ap checking when do the implementation of gdma
	   copy/memset process in the edge platform. */
	if (isCEPlatform(core))
		return 0;

	return MEM_AP_FROM_PROT(pminfo->mem_meta.flag) == AP_OR;
}

int cn_mem_copy_d2d(u64 tag, dev_addr_t src_vaddr, dev_addr_t dst_vaddr,
		ssize_t size, void *pcore, int compress_type)
{
	int ret = 0;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mapinfo *src_pminfo = NULL;
	struct mapinfo *dst_pminfo = NULL;
	int src_get = 0, dst_get = 0;

	if (src_vaddr == dst_vaddr) {
		cn_dev_core_err(core, "input src(%#llx) and dst(%#llx) is same!",
			src_vaddr, dst_vaddr);
		return -ENXIO;
	}

	if (ignore_params_check || addr_is_export(src_vaddr) || addr_is_export(dst_vaddr))
		goto edge;

	ret = camb_kref_get_validate(tag, src_vaddr, size, &src_pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(core, "Src_Addr(%#llx) is illegal for copy", src_vaddr);
		return ret;
	}

	src_get = 1;
	ret = camb_kref_get_validate(tag, dst_vaddr, size, &dst_pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(core, "Dst_Addr(%#llx) is illegal for copy", dst_vaddr);
		goto out;
	}

	dst_get = 1;
	if (__check_is_readonly(dst_pminfo)) {
		cn_dev_core_err(core, "Dst(%#llx) is read-only, not support write with d2d!",
						dst_pminfo->virt_addr);
		ret = -ENXIO;
		goto out;
	}

edge:
	if (cn_gdma_able(core)) {
		ret = cn_gdma_memcpy_sync(core, src_vaddr, dst_vaddr, size, compress_type);
		if (unlikely(ret)) {
			cn_dev_core_err(core, "cn_gdma_memcpy_sync failed,%d", ret);
		}
		goto out;
	}

	ret = cn_sbts_invoke_d2d_sync(core, (u64)src_vaddr, (u64)dst_vaddr, (u64)size);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "d2d invoke failed");
	}

out:
	if (src_get) {
		camb_kref_put_range(src_pminfo, src_vaddr, size, camb_mem_release);
	}
	if (dst_get) {
		camb_kref_put_range(dst_pminfo, dst_vaddr, size, camb_mem_release);
	}
	return ret;
}

int cn_mem_copy_d2d_2d(u64 tag, dev_addr_t dst_vaddr, ssize_t dpitch,
			dev_addr_t src_vaddr, ssize_t spitch, ssize_t width,
			ssize_t height, void *pcore)
{
	int ret = 0;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mapinfo *src_pminfo = NULL;
	struct mapinfo *dst_pminfo = NULL;
	ssize_t size = width * height;

	int src_get = 0, dst_get = 0;

	if (src_vaddr == dst_vaddr) {
		cn_dev_core_err(core, "input src(%#llx) and dst(%#llx) is same!",
			src_vaddr, dst_vaddr);
		return -ENXIO;
	}

	if (ignore_params_check || addr_is_export(src_vaddr) || addr_is_export(dst_vaddr))
		goto edge;

	ret = camb_kref_get_validate(tag, src_vaddr, size, &src_pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(core, "Src_Addr(%#llx) is illegal for copy", src_vaddr);
		return ret;
	}
	src_get = 1;

	ret = camb_kref_get_validate(tag, dst_vaddr, size, &dst_pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(core, "Dst_Addr(%#llx) is illegal for copy", dst_vaddr);
		goto out;
	}
	dst_get = 1;

	if (__check_is_readonly(dst_pminfo)) {
		cn_dev_core_err(core, "Dst(%#llx) is read-only, not support write with d2d!",
						dst_pminfo->virt_addr);
		ret = -ENXIO;
		goto out;
	}

edge:
	if (cn_gdma_able(core)) {
		ret = cn_gdma_memcpy_2d_sync(core,
								src_vaddr,
								dst_vaddr,
								spitch,
								dpitch,
								width,
								height);
		if (unlikely(ret)) {
			cn_dev_core_err(core, "cn_gdma_memcpy_2d_sync failed!,%d", ret);
			goto out;
		}
	} else {
		ret = -EINVAL;
		cn_dev_core_err(core, "no support!");
		goto out;
	}

out:
	if (src_get) {
		camb_kref_put_range(src_pminfo, src_vaddr, size, camb_mem_release);
	}
	if (dst_get) {
		camb_kref_put_range(dst_pminfo, dst_vaddr, size, camb_mem_release);
	}

	return ret;
}

int cn_mem_copy_d2d_3d(u64 tag, struct memcpy_d2d_3d_compat *p,
		void *pcore)
{
	int ret = 0;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mapinfo *src_pminfo = NULL;
	struct mapinfo *dst_pminfo = NULL;
	dev_addr_t src_vaddr = p->src;
	dev_addr_t dst_vaddr = p->dst;
	ssize_t size = p->extent.width * p->extent.height * p->extent.depth;

	int src_get = 0, dst_get = 0;

	if (src_vaddr == dst_vaddr) {
		cn_dev_core_err(core, "input src(%#llx) and dst(%#llx) is same!",
			src_vaddr, dst_vaddr);
		return -ENXIO;
	}

	if (ignore_params_check || addr_is_export(src_vaddr) || addr_is_export(dst_vaddr))
		goto edge;

	ret = camb_kref_get_validate(tag, src_vaddr, size, &src_pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(core, "Src_Addr(%#llx) is illegal for copy", src_vaddr);
		return ret;
	}
	src_get = 1;

	ret = camb_kref_get_validate(tag, dst_vaddr, size, &dst_pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(core, "Dst_Addr(%#llx) is illegal for copy", dst_vaddr);
		goto out;
	}
	dst_get = 1;

	if (__check_is_readonly(dst_pminfo)) {
		cn_dev_core_err(core, "Dst(%#llx) is read-only, not support write with d2d!",
						dst_pminfo->virt_addr);
		ret = -ENXIO;
		goto out;
	}

edge:
	if (cn_gdma_able(core)) {
		ret = cn_gdma_memcpy_3d_sync(core, p);
		if (unlikely(ret)) {
			cn_dev_core_err(core, "cn_gdma_memcpy_3d_sync failed,%d", ret);
			goto out;
		}
	} else {
		ret = -EINVAL;
		cn_dev_core_err(core, "no support!");
		goto out;
	}

out:
	if (src_get) {
		camb_kref_put_range(src_pminfo, src_vaddr, size, camb_mem_release);
	}
	if (dst_get) {
		camb_kref_put_range(dst_pminfo, dst_vaddr, size, camb_mem_release);
	}

	return ret;
}

int camb_get_mem_range(u64 tag, dev_addr_t vaddr, dev_addr_t *base,
		ssize_t *size, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mapinfo *pminfo = NULL;
	int ret = 0;

	ret = camb_kref_get(tag, vaddr, &pminfo, mm_set);
	if (unlikely(ret < 0)) {
		cn_dev_core_err(core, "device addr map info not found!");
		return ret;
	}

	*base = pminfo->virt_addr;
	*size = pminfo->mem_meta.size;

	cn_dev_core_debug(core, "get_mem_range:input(%#llx)--base(%#llx)--size(%#lx)",
					  vaddr, *base, *size);

	camb_kref_put(pminfo, camb_mem_release);
	return ret;
}

int camb_peer_free_msg_list_clear(u64 tag, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	if (!mm_set->peer_free_enable)
		return 0;

	memset(&remsg, 0x0, result_len);
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_msg_list_clear",
						 &tag, sizeof(u64),
						 &remsg, &result_len, sizeof(struct ret_msg));

	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client request mem failed.");
		return -EPIPE;
	}
	if (remsg.ret) {
		cn_dev_core_err(core, "peer free message list clear failed.");
		return -EINVAL;
	}

	return 0;
}

int camb_shm_do_exit(u64 tag, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mapinfo *post = NULL;
	struct rb_node *p = NULL;
	int ret = 0;
	struct cn_mm_priv_data *mm_priv_data;

	if (tag != 0) {
		cn_dev_core_err(core, "Error Tag Input!");
		return -EINVAL;
	} else {
		mm_priv_data = &mm_set->mm_priv_data;
	}

	read_lock(&mm_priv_data->node_lock);
	p = rb_first(&mm_priv_data->mmroot);
	while (p != NULL) {
		post = rb_entry(p, struct mapinfo, node);
		cn_dev_core_debug(core, "mem_do_exit:pmapinfo = %px", post);

		/* NOTE: post get from mm_priv_data->mmroot. thus, the structure
		 * of mapinfo must belong to current process. don't need check
		 * legality of tag.
		 */
		read_unlock(&mm_priv_data->node_lock);

		if (atomic_cmpxchg(&post->free_flag, 0, 1) != 0) {
			cn_dev_core_warn(core, "%#llx freed by other ops and still saved in"
						" rbtree which should not happened for share memory!",
						post->virt_addr);
			ret = 0;
			goto direct_next;
		}

		/* If the refcnt == 0, release the mapinfo.If not, only sub the refcnt and
		 * reserved the mapinfo in the rb tree.
		 */
		if (post->shm_info.type == CN_DEV_SHM) {
			ret = camb_kref_put(post, camb_dev_shm_release);
		} else if (post->shm_info.type == CN_HOST_SHM) {
			ret = camb_kref_put(post, camb_host_shm_release);
		} else if (post->shm_info.type == CN_SRAM_SHM) {
			ret = camb_kref_put(post, camb_sram_shm_release);
		} else {
			cn_dev_core_err(core, "mem_do_exit: pmapinfo shm type error: %d",
							post->shm_info.type);
		}

direct_next:
		read_lock(&mm_priv_data->node_lock);

		if (ret) {
			p = rb_first(&mm_priv_data->mmroot);
		} else {
			p = rb_next(p);
		}
	}

	read_unlock(&mm_priv_data->node_lock);

	return ret;
}

static void camb_vm_dummy_open(struct vm_area_struct *vma)
{
	struct vma_priv_t *priv_data = vma->vm_private_data;

	if (!priv_data)
		return ;

	atomic_inc(&priv_data->refcnt);
}

static void camb_vm_dummy_close(struct vm_area_struct *vma)
{
	struct vma_priv_t *priv_data = vma->vm_private_data;

	if (!priv_data)
		return ;

	if (atomic_sub_and_test(1, &priv_data->refcnt))
		cn_kfree(priv_data);

	vma->vm_private_data = NULL;
}

const struct vm_operations_struct camb_vma_dummy_ops = {
	.open = camb_vm_dummy_open,
	.close = camb_vm_dummy_close,
};

int camb_vma_is_dummy(struct vm_area_struct *vma)
{
	return vma->vm_ops == &camb_vma_dummy_ops;
}

static void
camb_release_ipc_handle(struct mapinfo *pminfo)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct mapinfo *mtmp = NULL;
	struct mapinfo *mpos = NULL;

	/* Lock list_del with ipcm_refcnt */
	if (pminfo->ipcm_info->mode == IPC_MODE_MEM) {
		spin_lock(&mm_set->ipcm_lock);
		if (!list_empty(&mm_set->ipcm_head)) {
			list_for_each_entry_safe(mpos, mtmp, &mm_set->ipcm_head, ipcm_list) {
				if (pminfo == mpos) {
					list_del_init(&mpos->ipcm_list);
				}
			}
		}
		spin_unlock(&mm_set->ipcm_lock);
	} else {
		udvm_ipc_handle_release((dev_ipc_handle_t)pminfo);
	}
}

int mapinfo_release(struct mapinfo *pminfo)
{
	camb_free_vma_list(pminfo);

	/* If the refcnt == 0, release the mapinfo.If not, only sub the refcnt and
	 * reserved the mapinfo in the rb tree.
	 */
	if (pminfo->ipcm_info)
		camb_release_ipc_handle(pminfo);

	return camb_kref_put(pminfo, camb_mem_release);
}

int camb_priv_data_list_release(struct cn_mm_priv_data *mm_priv_data)
{
	struct mapinfo *mpos = NULL;
	struct udvm_priv_data *udvm_priv = (struct udvm_priv_data *)mm_priv_data->udvm_priv;
	struct mlu_priv_data *mlu_priv = udvm_mlu_priv_must_valid(udvm_priv, mm_priv_data->udvm_index);

	/**
	 * NOTE: DRIVER-6467, why not use list_for_each_entry_safe?
	 *  At first, cn_mem_free and cn_mem_do_exit are called concurrently (this
	 *  situation is possible if UDVM is enabled).
	 *
	 *  If we use list_for_each_entry_safe(mpos, mtmp, head, member), mtmp's
	 *  memory may be freed:
	 *
	 *        Thread A                               Thread B
	 *  cn_mem_free(Address A)              __mem_priv_data_list_release
	 *  camb_kref_put(Address A)               spin_lock(mmlist_lock)
	 *  delete_mapinfo(Address A)       list_for_each_entry_safe(mpos(Address B), mtmp(Address A))
	 *  Waiting mmlist_lock                 list_del_init(mpos(Address B))
	 *                                         spin_unlock(mmlist_lock)
	 *  camb_mem_release(Address A)          camb_mem_release(Address B)
	 *  kfree(mapinfo(Address A))              kfree(mapinfo(Address B))
	 *                               mpos = mtmp; mtmp = list_next_entry(mtmp) (Use After Free)
	 *
	 * And we must do spin_unlock(mmlist_lock) after list_del_init, because
	 * spin_lock(mmlist_lock) is called again in mapinfo_release.
	 **/
	spin_lock(&mlu_priv->minfo_lock);
	spin_lock(&mm_priv_data->mmlist_lock);
	while (!list_empty(&mm_priv_data->minfo_list)) {
		mpos = list_first_entry(&mm_priv_data->minfo_list,
					struct mapinfo, priv_node);

		list_del_init(&mpos->priv_node);
		/* mm_priv_data in mapinfo not used in delete_mapinfo */
		mpos->mm_priv_data = NULL;
		/**
		 * set free_flag as true for mpos, avoid call camb_mem_release in
		 * cn_mem_free or mapinfo_release in close_handle again.
		 **/
		if (atomic_cmpxchg(&mpos->free_flag, 0, 1) != 0)
			continue;

		spin_unlock(&mm_priv_data->mmlist_lock);
		spin_unlock(&mlu_priv->minfo_lock);

		camb_free_ts_node_init(mpos);
		camb_free_ts_node_record(mpos, FREE_TS_CALLFREE);
		trace_mem_priv_release(mpos);

		if (!mpos->ipcm_info || !mpos->ipcm_info->parent) {
			struct cn_mm_set *mm_set = (struct cn_mm_set *)mpos->mm_set;
			struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

			__update_pid_info_node(mpos, sub, (u64)mpos->mem_meta.size);
			cn_smlu_uncharge(core, mem_cgrp_id, (void *)mpos->tag, mpos->active_ns, (u64)mpos->mem_meta.size);
		}

		mapinfo_release(mpos);

		spin_lock(&mlu_priv->minfo_lock);
		spin_lock(&mm_priv_data->mmlist_lock);
	}
	spin_unlock(&mm_priv_data->mmlist_lock);
	spin_unlock(&mlu_priv->minfo_lock);

	return 0;
}

void camb_priv_data_rbtree_release(struct cn_mm_priv_data *mm_priv_data,
								   void *mem_set, u64 tag)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mapinfo *post = NULL;
	struct rb_node *p = NULL;
	int ret = 0;

	read_lock(&mm_priv_data->node_lock);
	p = rb_first(&mm_priv_data->mmroot);
	while (p != NULL) {
		post = rb_entry(p, struct mapinfo, node);
		cn_dev_core_debug(core, "mem_do_exit:pmapinfo = %px", post);

		/* NOTE: post get from mm_priv_data->mmroot. thus, the structure
		 * of mapinfo must belong to current process. don't need check
		 * legality of tag.
		 */
		read_unlock(&mm_priv_data->node_lock);

		if (post->mem_meta.type == CN_SHARE_MEM) {
			cn_dev_core_debug(core, "Share Memory Free in camb_shm_do_exit!");
			ret = 0;
			goto do_migrate;
		}

		if (atomic_cmpxchg(&post->free_flag, 0, 1) != 0) {
			ret = 0;
			goto do_migrate;
		}

		/* Only normal memory and Parent shared Memory need sub minfo */
		if (!post->ipcm_info || !post->ipcm_info->parent) {
			__update_pid_info_node(post, sub, (u64)post->mem_meta.size);
			cn_smlu_uncharge(core, mem_cgrp_id, (void *)post->tag, post->active_ns, (u64)post->mem_meta.size);
		}

		/* If the refcnt == 0, release the mapinfo.If not, only sub the refcnt and
		 * reserved the mapinfo in the rb tree.
		 */
		ret = mapinfo_release(post);

		/**
		 * post used to p2p_async and p2p_async not finish, 0 is tag of
		 * mm_set->mm_priv_data
		 **/
do_migrate:
		if (!ret && atomic_cmpxchg(&post->async_used, 1, 0)) {
			__migrate_mapinfo(mm_priv_data, &mm_set->mm_priv_data, post, 0);
			ret = 1;
		}

		read_lock(&mm_priv_data->node_lock);
		if (ret) {
			p = rb_first(&mm_priv_data->mmroot);
		} else {
			p = rb_next(p);
		}
	}

	read_unlock(&mm_priv_data->node_lock);

	camb_peer_free_msg_list_clear(tag, mem_set);
}

void camb_peer_free_exit(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct peer_free_task_set *peer_free_task = &mm_set->peer_free_task;

	if (!mm_set->peer_free_enable)
		return ;

	if (!cn_core_is_vf(core) && cn_is_mim_en(core)) {
		cn_dev_core_debug(core, "not pf-only or vf");
		return;
	}

	peer_free_task->exit_flag = 1;
	smp_mb();
	if (peer_free_task->wait_msg_thread) {
		send_sig(SIGKILL, peer_free_task->wait_msg_thread, 1);
		kthread_stop(peer_free_task->wait_msg_thread);
		peer_free_task->wait_msg_thread = NULL;
	} else {
		cn_dev_err("wait_msg_thread is null");
	}
	if (mm_set->peer_free_endpoint) {
		cn_dev_core_info(core, "peer_free_endpoint = 0x%lx\n",
				(unsigned long)mm_set->peer_free_endpoint);
		disconnect_endpoint(mm_set->peer_free_endpoint);
	}
}

int cn_mem_debugfs(void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;
	struct mem_dbg_t dbg;
	size_t input_len = sizeof(struct mem_dbg_t);

	cn_dev_core_debug(core, ">>>>>>>>>>>>>>Enter memory debug<<<<<<<<<<<<<<<");

	dbg.pid = ~0x0; /* -1 means special pid, memeinfo dump by debugfs */
	dbg.cmd = MEM_DBG_DUMPINFO;
	memset(&remsg, 0x00, sizeof(struct ret_msg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_debug", &dbg, input_len,
						 &remsg, &result_len, sizeof(struct ret_msg));

	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client query mem failed.");
		return -EPIPE;
	}

	if (remsg.ret) {
		cn_dev_core_err(core, "rpc_mem_debugfs error status is %d", remsg.ret);
		return remsg.ret;
	}

	cn_dev_core_debug(core, ">>>>>>>>>>>>>>Finish memory debug<<<<<<<<<<<<<<<");
	return 0;
}

void camb_peer_free(u64 tag, u64 iova, u64 type, struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	host_addr_t host_vaddr;
	dev_addr_t device_vaddr;
	struct mapinfo *pminfo = NULL;
	int ret;

	device_vaddr = (dev_addr_t)iova;
	switch (type) {
	case CN_SHM_INBD:
		ret = camb_free_kref_get(tag, device_vaddr, &pminfo, mm_set);
		if (ret < 0) {
			cn_dev_core_err(core, "Addr(%#llx) is illegal for free", device_vaddr);
			break;
		}
		host_vaddr = pminfo->shm_info.host_vaddr;
		camb_free_kref_put(pminfo);
		ret = cn_device_share_mem_free(tag, host_vaddr, device_vaddr, core);
		if (ret) {
			cn_dev_core_err(core, "cn_device_share_mem_free err!");
		}
		break;
	case CN_SHM_OUTBD:
		ret = camb_free_kref_get(tag, device_vaddr, &pminfo, mm_set);
		if (ret < 0) {
			cn_dev_core_err(core, "Addr(%#llx) is illegal for free", device_vaddr);
			break;
		}
		host_vaddr = pminfo->shm_info.host_vaddr;
		camb_free_kref_put(pminfo);
		ret = cn_host_share_mem_free(tag, host_vaddr, device_vaddr, core);
		if (ret) {
			cn_dev_core_err(core, "cn_host_share_mem_free err!");
		}
		break;
	case CN_MEM_MALLOC:
		ret = cn_mem_free(tag, device_vaddr, core);
		if (ret) {
			cn_dev_core_err(core, "cn_mem_free err!");
		}
		break;
	default:
		cn_dev_core_err(core, "iova 0x%llx invalid!", iova);
	}
	cn_dev_core_debug(core, "Done");
}

int peer_free_thread(void *data)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)data;
	struct commu_message_buffer commu_msg_buf = {0};
	struct commu_message_data *commu_msg_data = NULL;
	int commu_msg_size = 0;
	u64 commu_msg_cnt = 0, tag = 0, iova = 0, num = 0, type = 0;
	int i = 0;
	struct peer_free_task_set *peer_free_task = &mm_set->peer_free_task;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	/* change delay free thread cpu affinity
	 * if driver run on smp processor, put delay free thread
	 * to cpus other than cpu0 to imporve the performance of
	 * LaunchKernel extra
	 */
	if (current->nr_cpus_allowed > 1)
		CN_CLEAR_CPUMASK(0);

	allow_signal(SIGKILL);
	while (!kthread_should_stop()) {

		/* driver unload */
		if (peer_free_task->exit_flag || core->reset_flag) {
			msleep(20);
			continue;
		}
		if (!commu_wait_for_message(mm_set->peer_free_endpoint,
									&commu_msg_buf, &commu_msg_size)) {
			cn_dev_core_debug(core, "wait message");
			continue;
		}
		/* When user use multithread launch small kernel, there
		 * will be a huge number of param_buf delay free task in
		 * this thread, in this condition, commu_wait_for_message
		 * have no chance call wait_event_interruptible to schedule
		 * the thread out, and the continuous working of peer free
		 * thread will cause kernel soft lockup.
		 * In order to prevent this bug, we add commu_msg_cnt to
		 * allow this thread have chance to schedule out event in
		 * very busy condition.
		 */
		if (__sync_fetch_and_add(&commu_msg_cnt, 1) % COMMU_MSG_CNT_LIMIT == 0) {
			usleep_range(20, 50);
		}
		/********* get param from msg (not done yet) *********/
		commu_msg_data = (struct commu_message_data *)commu_msg_buf.data;
		num = le64_to_cpu(commu_msg_buf.num);
		if (unlikely(num > COMMU_MSG_DATA_NUM)) {
			cn_dev_core_err(core, "msg num err!");
			continue;
		}
		for (i = 0; i < (int)num; i++) {
			tag = le64_to_cpu(commu_msg_data[i].tag);
			iova = le64_to_cpu(commu_msg_data[i].iova);
			type = le64_to_cpu(commu_msg_data[i].type);
			cn_dev_core_debug(core, "tag = 0x%llx iova = 0x%llx type = %llu",
					tag, iova, type);
			camb_peer_free(tag, iova, type, mm_set);
		}
	}

	return 0;
}

int camb_peer_free_init(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct commu_channel *peer_free_commu_chn;

	if (!mm_set->peer_free_enable)
		return 0;

	peer_free_commu_chn = commu_open_a_channel("commu_camb_peer_free_msg", core, 0);
	mm_set->peer_free_endpoint = connect_msg_endpoint(peer_free_commu_chn);

	mm_set->peer_free_task.exit_flag = 0;
	mm_set->peer_free_task.wait_msg_thread = kthread_run(peer_free_thread,
				mm_set, "%s", "peer_free_thread");
	if (IS_ERR(mm_set->peer_free_task.wait_msg_thread)) {
		cn_dev_core_err(core, "create peer_free_thread failed");
		mm_set->peer_free_task.wait_msg_thread = NULL;
		return -EINVAL;
	}

	cn_dev_core_info(core, "cn memory krpc client register success!");
	return 0;
}

static int
cn_mem_dma_memset(void *pcore, u64 device_addr, unsigned long number,
		unsigned int val, u64 tag, int per_size, DMA_DIR_TYPE dir)
{
	int ret = 0;
	struct mapinfo *pminfo = NULL;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	unsigned long real_size = number * per_size;
	struct memset_s t;

	if (!IS_ALIGNED(device_addr, per_size)) {
		cn_dev_core_err(core, "Addr(%#llx) is not %d bytes aligned",
				device_addr, per_size);
		return -EINVAL;
	}

	if (real_size < number) {
		cn_dev_core_err(core, "invalid per_size(%d) input", per_size);
		return -EINVAL;
	}

	ret = camb_kref_get_validate(tag, device_addr, real_size, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(core, "Addr(%#llx) is illegal for memset", device_addr);
		return ret;
	}

	MEMSET_INIT(t, val, device_addr, number, dir);
	if ((__check_is_readonly(pminfo) == false) && cn_gdma_able(core)) {
		ret = cn_gdma_memset_sync(core, &t);
		if (unlikely(ret)) {
			cn_dev_core_err(core, "cn_gdma_memset_sync failed,%d", ret);
		}
	} else {
		ret = cn_bus_dma_memset(core->bus_set, &t);
	}

	camb_kref_put_range(pminfo, device_addr, real_size, camb_mem_release);

	return ret;
}

#define DMA_MEMSET_OPS(name, type, per_size) \
int cn_mem_dma_memset##name(void *mem_set, u64 device_addr, unsigned long number, \
		type val, u64 tag) \
{ \
	return cn_mem_dma_memset(mem_set, device_addr, number, val, tag, per_size, \
			MEMSET_##name); \
} \
/* the memset export symbol:
 * cn_mem_dma_memsetD8
 * cn_mem_dma_memsetD16
 * cn_mem_dma_memsetD32
 */
DMA_MEMSET_OPS(D8, unsigned char, 1)
DMA_MEMSET_OPS(D16, unsigned short, 2)
DMA_MEMSET_OPS(D32, unsigned int, 4)

int camb_mem_get_ipu_resv(u64 tag, struct ipu_mem_addr_get *ipu_mem_addr, void *mem_set)
{
	int ret = 0;
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = mm_set->core;
	unsigned long tmp_param = 0;
	size_t result_len = sizeof(struct ipu_mem_addr_get);

	if (core->device_id == MLUID_370_DEV) {
		return 0;
	}

	if (core->device_id == MLUID_590_DEV) {
		return 0;
	}

	/*VIRTUAL-434 Bug fix: forbid get ipu resv api to be called in pf when sriov is enabled*/
	if (cn_is_mim_en(core) && !cn_core_is_vf(core)) {
		return 0;
	}

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_get_ipu_resv_mem",
								   &tmp_param, sizeof(unsigned long),
								   ipu_mem_addr,
								   &result_len,
								   sizeof(struct ipu_mem_addr_get));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed.");
		return ret;
	}

	return 0;
}

void camb_init_mapinfo_basic(struct mapinfo *minfo,
						struct cn_mm_set *mm_set, u64 tag)
{
	struct file *fp = (struct file *)tag;
	struct cn_mm_priv_data *mm_priv_data = __get_mm_priv(fp, mm_set);

	RB_CLEAR_NODE(&minfo->node);
	minfo->tgid = ((struct task_struct *)current)->tgid;

	INIT_LIST_HEAD(&minfo->ipcm_list);
	INIT_LIST_HEAD(&minfo->p2p_remap_list);
	INIT_LIST_HEAD(&minfo->obmap_list);
	spin_lock_init(&minfo->obmap_lock);
	spin_lock_init(&minfo->vma_lock);
	INIT_LIST_HEAD(&minfo->vma_head);

	atomic_set(&minfo->refcnt, 1);
	atomic_set(&minfo->map_refcnt, 0);
	atomic_set(&minfo->free_flag, 0);

	minfo->ipcm_info = NULL;
	minfo->is_linear = false;
	minfo->tag = tag;
	minfo->active_ns = task_active_pid_ns(current);
	minfo->mm_set = mm_set;
	minfo->mm_priv_data = mm_priv_data;
	minfo->udvm_priv = mm_priv_data->udvm_priv;
}

int cn_mem_get_size_info(void *mem_info, void *pcore)
{
	int ret = 0;
	struct mem_size_info *mm_size_info = mem_info;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct fa_stat stat;

	if (!mem_info) {
		cn_dev_core_err(core, "Init Error!");
		return -1;
	}

	mm_size_info->phy_total_mem = mm_set->phy_total_mem;
	mm_size_info->phy_used_mem = mm_set->phy_used_mem;
	mm_size_info->vir_total_mem = mm_set->vir_total_mem;
	mm_size_info->vir_used_mem = mm_set->vir_used_mem;

	/* Get Fast Alloc Mem info */
	ret = camb_fa_statistic(mm_set->fa_array, &stat);
	if (ret)
		return ret;

	mm_size_info->fa_total_mem = stat.total_size;
	mm_size_info->fa_used_mem = stat.used_size;

	return ret;
}

unsigned long cn_mem_dma_p2p(
	void                   *pcore_src,
	void                   *pcore_dst,
	u64                    src_addr,
	u64                    src_tag,
	u64                    dst_addr,
	u64                    dst_tag,
	unsigned long          count)
{
	int ret = 0;
	struct cn_core_set *src_core = pcore_src;
	struct cn_core_set *dst_core = pcore_dst;
	struct cn_mm_set *src_mm_set = src_core->mm_set;
	struct cn_mm_set *dst_mm_set = dst_core->mm_set;
	struct mapinfo *src_pminfo = NULL;
	struct mapinfo *dst_pminfo = NULL;
	int src_get = 0, dst_get = 0;
	struct peer_s peer;

	/* Address Only Support 48bit, Need to Mask High bit */
	ret = camb_kref_get_validate(src_tag, src_addr, count, &src_pminfo, src_mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(src_core, "Src_Addr(%#llx) is illegal for p2p", src_addr);
		return ret;
	}
	src_get = 1;

	ret = camb_kref_get_validate(dst_tag, dst_addr, count, &dst_pminfo, dst_mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(dst_core, "Dst_Addr(%#llx) is illegal for p2p", dst_addr);
		goto out;
	}
	dst_get = 1;

	/* memory info */
	peer.src_minfo	 = src_pminfo;
	peer.src_bus_set = src_core->bus_set;
	peer.src_addr    = src_addr;
	peer.dst_minfo   = dst_pminfo;
	peer.dst_bus_set = dst_core->bus_set;
	peer.dst_addr    = dst_addr;
	peer.size        = count;

	ret = cn_bus_dma_p2p(src_core->bus_set, &peer);

out:
	if (src_get) {
		camb_kref_put_range(src_pminfo, src_addr, count, camb_mem_release);
	}
	if (dst_get) {
		camb_kref_put_range(dst_pminfo, dst_addr, count, camb_mem_release);
	}
	return ret;
}

int cn_mem_bar_copy_d2h(u64 tag, dev_addr_t device_vaddr,
		host_addr_t host_vaddr, size_t size, void *pcore)
{
	int ret = 0;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mapinfo *pminfo = NULL;

	ret = camb_kref_get_validate(tag, device_vaddr, size, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(core, "Addr(%#llx) is illegal for copy", device_vaddr);
		return ret;
	}

	/*call bus ddr_read function to transfer*/
	ret = cn_bus_bar_copy_d2h(core->bus_set, device_vaddr, host_vaddr, size);
	camb_kref_put_range(pminfo, device_vaddr, size, camb_mem_release);

	return ret;
}

int cn_mem_bar_copy_h2d(u64 tag, dev_addr_t device_vaddr,
		host_addr_t host_vaddr, size_t size, void *pcore)
{
	int ret = 0;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mapinfo *pminfo = NULL;

	ret = camb_kref_get_validate(tag, device_vaddr, size, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err_limit(core, "Addr(%#llx) is illegal for copy", device_vaddr);
		return ret;
	}

	/*call bus ddr_write function to transfer*/
	ret = cn_bus_bar_copy_h2d(core->bus_set, device_vaddr, host_vaddr, size);
	camb_kref_put_range(pminfo, device_vaddr, size, camb_mem_release);

	return ret;
}

/* IPC share memory ops */
static int camb_ipc_handle_kref_put(u64 handle, struct cn_mm_set *mm_set)
{
	struct mapinfo *pminfo = (struct mapinfo *)handle;
	struct mapinfo *mtmp = NULL;
	struct mapinfo *mpos = NULL;
	int do_free = 0;

	spin_lock(&mm_set->ipcm_lock);
	if (atomic_sub_and_test(1, pminfo->ipcm_info->ipcm_refcnt)) {
		if (!list_empty(&mm_set->ipcm_head)) {
			list_for_each_entry_safe(mpos, mtmp, &mm_set->ipcm_head, ipcm_list) {
				if (pminfo == mpos) {
					list_del_init(&mpos->ipcm_list);
				}
			}
		}
		do_free = 1;
	}
	spin_unlock(&mm_set->ipcm_lock);

	/**
	 * mapinfo stored in list must belongs to creator process. And if
	 * ipcm_refcnt decrease into zero, means that the pminfo->refcnt is zero
	 * as well. So we need release pminfo now.
	 **/
	if (do_free) {
		cn_kfree(pminfo->ipcm_info->ipcm_refcnt);
		pminfo->ipcm_info->ipcm_refcnt = NULL;
		cn_kfree(pminfo->ipcm_info);
		pminfo->ipcm_info = NULL;
		cn_kfree(pminfo);
	}

	return 0;
}

static int camb_ipc_handle_kref_get(u64 handle, struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mapinfo *pminfo = NULL;
	int ret = 0;

	spin_lock(&mm_set->ipcm_lock);
	list_for_each_entry(pminfo, &mm_set->ipcm_head, ipcm_list) {
		if (handle == (u64)pminfo) {
			cn_dev_core_debug(core, "open handle:mapinfo  = %#llx", (u64)pminfo);
			ret = atomic_add_unless(pminfo->ipcm_info->ipcm_refcnt, 1, 0);
			if (!ret) {
				cn_dev_core_err(core, "Handle(%#llx) on ipcm_list is invaild",
								handle);

				spin_unlock(&mm_set->ipcm_lock);
				return -ENOSPC;
			}

			spin_unlock(&mm_set->ipcm_lock);
			return 0;
		}
	}
	spin_unlock(&mm_set->ipcm_lock);
	return -EINVAL;
}

int camb_mem_ipc_get_handle(u64 tag, dev_addr_t dev_vaddr, int mode,
				dev_ipc_handle_t *handle)
{
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = NULL;
	struct mapinfo *pminfo = NULL;
	struct ipc_shm_info *ipc_info = NULL;
	struct file *fp = (struct file *)tag;
	int ret = 0;

	pminfo = search_mapinfo_with_fp(fp, dev_vaddr, mm_set);
	if (unlikely(IS_ERR_OR_NULL(pminfo))) {
		cn_dev_err("Can't find the mapinfo for addr %llx", dev_vaddr);
		return -ENXIO;
	}

	mm_set = (struct cn_mm_set *)pminfo->mm_set;
	core = (struct cn_core_set *)mm_set->core;

	ret = __params_check_addr_equal(pminfo, dev_vaddr);
	if (ret)
		return ret;

	cn_dev_core_debug(core, "Has been find the mapinfo(addr = %px)", pminfo);

	if (pminfo->mem_type == MEM_FAKE ||
		pminfo->mem_type == MEM_VMM || pminfo->mem_type == MEM_KEXT) {
		cn_dev_core_err(core, "input address not support ipc share!");
		return -ENXIO;
	}

	if (!pminfo->ipcm_info) {
		ipc_info = cn_kzalloc(sizeof(struct ipc_shm_info), GFP_KERNEL);
		if (!ipc_info) {
			cn_dev_core_err(core, "kzalloc ipc_info failed.");
			return -ENOMEM;
		}

		ipc_info->ipcm_refcnt = cn_kzalloc(sizeof(atomic_t), GFP_KERNEL);
		if (!ipc_info->ipcm_refcnt) {
			cn_kfree(ipc_info);
			cn_dev_core_err(core, "kzalloc mmtag failed.");
			return -ENOMEM;
		}

		ipc_info->mode = mode;

		/*init the ipcm infomation structure*/
		pminfo->ipcm_info = ipc_info;
		pminfo->ipcm_info->parent = NULL;
		atomic_set(pminfo->ipcm_info->ipcm_refcnt, 1);
	} else {
		cn_dev_core_err(core, "Addr(%llx) Has been GetHandle on this device",
						dev_vaddr);
		return -ENXIO;
	}
	/* NOTE:
	 * Don't need to check the memory busy or not.
	 * Because it can be shared the memory even though the parent has been
	 * using this memory. */

	*handle = (u64)pminfo;

	return 0;
}

int camb_ipc_shm_get_handle(u64 tag,
						  dev_ipc_handle_t *handle,
						  dev_addr_t dev_vaddr,
						  void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct mapinfo *pminfo = NULL;
	int ret = 0;

	ret = camb_mem_ipc_get_handle(tag, dev_vaddr, IPC_MODE_MEM, handle);
	if (ret) return ret;

	pminfo = (struct mapinfo *)(*handle);
	/*list the mapinfo to the core->cn_mm_set for handle checking*/
	spin_lock(&mm_set->ipcm_lock);
	list_add_tail(&pminfo->ipcm_list, &mm_set->ipcm_head);
	spin_unlock(&mm_set->ipcm_lock);

	return 0;
}

int camb_mem_ipc_open_handle(u64 tag, struct mapinfo *ppminfo,
				dev_addr_t *dev_vaddr)
{
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = NULL;
	struct mapinfo *cpminfo = NULL;
	struct ipc_shm_info *ipc_info = NULL;
	struct file *fp = (struct file *)tag;
	struct cn_mm_priv_data *mm_priv_data;

	mm_priv_data = __get_mm_priv(fp, NULL);
	if (!mm_priv_data) {
		cn_dev_core_err(core, "get mem priv data failed");
		return -EINVAL;
	}

	mm_set = (struct cn_mm_set *)ppminfo->mm_set;
	core = (struct cn_core_set *)mm_set->core;

	if (ppminfo->mem_type == MEM_FAKE ||
		ppminfo->mem_type == MEM_VMM || ppminfo->mem_type == MEM_KEXT) {
		cn_dev_core_err(core, "input address not support ipc share!");
		return -ENXIO;
	}

	if (!ppminfo->ipcm_info) {
		cn_dev_core_err(core, "ipcm parent invalid.");
		return -EINVAL;
	}

	cpminfo = search_mapinfo_with_fp(fp, ppminfo->virt_addr, mm_set);
	if (!IS_ERR_OR_NULL(cpminfo)) {
		cn_dev_core_err(core, "OpenHandle Twice is forbidden");
		return -ENXIO;
	}

	/*alloc a child mapinfo for ipc shared address*/
	cpminfo = cn_kzalloc(sizeof(struct mapinfo), GFP_KERNEL);
	if (!cpminfo) {
		cn_dev_core_err(core, "Kmalloc mapInfo failed.");
		return -ENOMEM;
	}

	ipc_info = cn_kzalloc(sizeof(struct ipc_shm_info), GFP_KERNEL);
	if (!ipc_info) {
		cn_dev_core_err(core, "Kmalloc ipc_info failed.");
		cn_kfree(cpminfo);
		return -ENOMEM;
	}

	/*mapinfo init*/
	camb_init_mapinfo_basic(cpminfo, mm_set, tag);
	memcpy(&cpminfo->mem_meta, &ppminfo->mem_meta, sizeof(struct mem_attr));

	/* point to the parent refcnt (cn_ipc_get_handle has increase ipcm_refcnt) */
	ipc_info->parent = ppminfo;
	cpminfo->ipcm_info = ipc_info;
	cpminfo->ipcm_info->ipcm_refcnt = ppminfo->ipcm_info->ipcm_refcnt;

	/*allow this fp to access*/
	cpminfo->mdr_peer_addr = ppminfo->mdr_peer_addr;
	cpminfo->mem_type = ppminfo->mem_type;
	cpminfo->is_linear = ppminfo->is_linear;

	if (cpminfo->mem_type == MEM_FA) {
		memcpy(&cpminfo->fa_info, &ppminfo->fa_info, sizeof(struct fa_addr_t));
	} else {
		cpminfo->virt_addr = ppminfo->virt_addr;
	}

	/*insert the mapinfo into rb tree*/
	insert_mapinfo(mm_priv_data, cpminfo);
	*dev_vaddr = cpminfo->virt_addr;

	return 0;
}

int
camb_ipc_shm_open_handle(u64 tag,
					   dev_ipc_handle_t handle,
					   dev_addr_t *dev_vaddr,
					   void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	int ret = 0;

	if (!handle)
		return -EINVAL;

	if (camb_ipc_handle_kref_get(handle, mm_set)) {
		cn_dev_core_err(core, "IPCM From Hanle(%#llx) has been destroyed", handle);
		return -EINVAL;
	}

	ret = camb_mem_ipc_open_handle(tag, (struct mapinfo *)handle, dev_vaddr);
	if (ret) {
		camb_ipc_handle_kref_put(handle, mm_set);
	}

	return ret;
}

static int __close_handle_check(struct mapinfo *pminfo,
		dev_addr_t device_vaddr, size_t size)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	int ret = 0;

	if (pminfo->mem_type == MEM_FAKE ||
		pminfo->mem_type == MEM_VMM || pminfo->mem_type == MEM_KEXT) {
		cn_dev_core_err(core, "input address not support ipc share!");
		return -ENXIO;
	}

	ret = __params_check_addr_equal(pminfo, device_vaddr);
	if (ret)
		return ret;

	/*check that the address is a ipc shared memory or not*/
	if (!pminfo->ipcm_info || !pminfo->ipcm_info->parent) {
		cn_dev_core_err(core, "The address(%llx) is not an IPCM!", device_vaddr);
		return -ENXIO;
	}

	return (atomic_cmpxchg(&pminfo->free_flag, 0, 1) != 0) ? -ENXIO : 0;
}

int camb_mem_ipc_close_handle(u64 tag, dev_addr_t virt_addr)
{
	struct file *fp = (struct file *)tag;
	struct mapinfo *cpminfo = NULL;

	cpminfo = search_mapinfo_with_func(fp, NULL, virt_addr, 0,
						__close_handle_check);
	if (unlikely(IS_ERR_OR_NULL(cpminfo))) {
		cn_dev_err("Can't find the mapinfo for addr %#llx", virt_addr);
		return -ENXIO;
	}

	trace_ipc_close_handle(cpminfo);
	camb_free_ts_node_init(cpminfo);
	camb_free_ts_node_record(cpminfo, FREE_TS_CALLFREE);

	mapinfo_release(cpminfo);

	return 0;
}

int camb_ipc_shm_close_handle(u64 tag, dev_addr_t dev_vaddr, void *mem_set)
{
	return camb_mem_ipc_close_handle(tag, dev_vaddr);
}

int camb_mem_info_adj(void *pcore, unsigned int dir, unsigned long size)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct pid_info_s *pid_info_node;
	int ret = -EINVAL;

	if (!core->open_count) {
		cn_dev_core_err(core, "MemAdj: the core is inactive!");
		goto out;
	}

	/* only support to add and sub */
	if (dir != 1 && dir != 0) {
		goto out;
	}

	cn_dev_core_debug(core, "MemAdj:tgid(%d) %s size(%#lx)!", current->tgid,
					  dir == 0 ? "decrease" : "increase", size);

	spin_lock(&core->pid_info_lock);
	list_for_each_entry(pid_info_node, &core->pid_head, pid_list) {
		if (pid_info_node->tgid == current->tgid) {
			if (dir) { /* add the size */
				pid_info_node->phy_usedsize += size;
				pid_info_node->vir_usedsize += size;
			} else { /* sub the size */
				pid_info_node->phy_usedsize -= size;
				pid_info_node->vir_usedsize -= size;
			}

			ret = 0;
			break;
		}
	}

	/* Current thread is invalid when the value of ret is -EINVAL. It means that
	 * it doesn't to allocate memory in this thread. */
	spin_unlock(&core->pid_info_lock);

out:
	return ret;
}

/**
 * memcpy_async / memset_async params validate check interfaces, support
 * platforms which are not support udvm
 **/
static int
cn_memcpy_dma_params_kref_get(u64 tag, host_addr_t host_vaddr,
		dev_addr_t dev_vaddr, unsigned long size, struct mapinfo **ppminfo,
		bool is_async)
{
	struct mapinfo *pminfo = NULL;
	int ret = 0;

	if (dma_hmsc_enable) {
		ret = camb_mem_dma_hmsc(host_vaddr, size);
		if (ret < 0)
			return ret;
	}

	ret = camb_kref_get_validate(tag, dev_vaddr, size, &pminfo, NULL);
	if (ret < 0) {
		cn_dev_err_limit("(%#llx, %#lx) is illegal for memcpy", dev_vaddr, size);
		return ret;
	}

	if (is_async) {
		atomic_set(&pminfo->async_used, 1);

		if (pminfo->udvm_priv)
			udvm_register_async_tasks(pminfo->udvm_priv);
	}

	*ppminfo = pminfo;
	return 0;
}

static int
cn_memset_dma_params_kref_get(u64 tag, dev_addr_t dev_vaddr,
		unsigned long number, unsigned int per_size, struct mapinfo **ppminfo,
		bool is_async)
{
	unsigned long real_size = number * per_size;
	struct mapinfo *pminfo = NULL;
	int ret = 0;

	if (!IS_ALIGNED(dev_vaddr, per_size)) {
		cn_dev_err("Addr(%#llx) is not aligned to %d", dev_vaddr, per_size);
		return -EINVAL;
	}

	if (real_size < number) {
		cn_dev_err("invalid per_size(%d) input", per_size);
		return -EINVAL;
	}

	ret = camb_kref_get_validate(tag, dev_vaddr, real_size, &pminfo, NULL);
	if (ret < 0) {
		cn_dev_err_limit("Addr(%#llx) is illegal for memset", dev_vaddr);
		return ret;
	}

	if (is_async) {
		atomic_set(&pminfo->async_used, 1);

		if (pminfo->udvm_priv)
			udvm_register_async_tasks(pminfo->udvm_priv);
	}

	*ppminfo = pminfo;
	return 0;
}

static int
cn_memcpy_peer_params_kref_get(u64 src_tag, u64 dst_tag,
		dev_addr_t src_vaddr, dev_addr_t dst_vaddr, unsigned long size,
		struct mapinfo **src_ppminfo, struct mapinfo **dst_ppminfo,
		bool is_async)
{
	struct mapinfo *src_pminfo = NULL;
	struct mapinfo *dst_pminfo = NULL;
	int src_get = 0, dst_get = 0, ret = 0;

	ret = camb_kref_get_validate(src_tag, src_vaddr, size, &src_pminfo, NULL);
	if (ret < 0) {
		cn_dev_err_limit("Src_Addr(%#llx) is illegal for copy", src_vaddr);
		return ret;
	}
	src_get = 1;

	ret = camb_kref_get_validate(dst_tag, dst_vaddr, size, &dst_pminfo, NULL);
	if (ret < 0) {
		cn_dev_err_limit("Dst_Addr(%#llx) is illegal for copy", dst_vaddr);
		goto out;
	}
	dst_get = 1;

	/* Address from same device, need extra validate check */
	if (src_pminfo->mm_set == dst_pminfo->mm_set) {
		if (src_vaddr == dst_vaddr) {
			cn_dev_err("input same src(%#llx) and dst(%#llx) is not valid operation!",
					   src_vaddr, dst_vaddr);
			ret = -ENXIO;
			goto out;
		}

		if (__check_is_readonly(dst_pminfo)) {
			cn_dev_err("Dst(%#llx) is read-only, not support write with d2d!",
					   dst_vaddr);
			ret = -ENXIO;
			goto out;
		}
	}

	if (is_async) {
		atomic_set(&src_pminfo->async_used, 1);
		atomic_set(&dst_pminfo->async_used, 1);

		if (src_pminfo->udvm_priv)
			udvm_register_async_tasks(src_pminfo->udvm_priv);

		if (dst_pminfo->udvm_priv)
			udvm_register_async_tasks(dst_pminfo->udvm_priv);
	}

	*src_ppminfo = src_pminfo;
	*dst_ppminfo = dst_pminfo;

	return 0;
out:
	if (src_get) {
		camb_kref_put_range(src_pminfo, src_vaddr, size, camb_mem_release);
	}
	if (dst_get) {
		camb_kref_put_range(dst_pminfo, dst_vaddr, size, camb_mem_release);
	}

	return ret;
}

static int
__get_memcpy_dir(int params_dir, dev_addr_t src_addr, dev_addr_t dst_addr,
				bool do_valid_check)
{
	int udvm_dir = 0, dir = 0;

	if (!do_valid_check) {
		return params_dir == DMA_RANDOM ? -ENXIO : params_dir;
	}

	switch (params_dir) {
	case DMA_D2H: params_dir = UDVM_MEMCPY_DIR_D2H; break;
	case DMA_H2D: params_dir = UDVM_MEMCPY_DIR_H2D; break;
	case DMA_D2D: params_dir = UDVM_MEMCPY_DIR_D2D; break;
	case DMA_P2P: params_dir = UDVM_MEMCPY_DIR_P2P; break;
	case DMA_RANDOM: params_dir = UDVM_MEMCPY_DIR_RANDOM; break;
	}

	udvm_dir = udvm_get_memcpy_dir(src_addr, dst_addr);
	if (!udvm_memcpy_dir_check(udvm_dir, params_dir))
		return -ENXIO;

	/* udvm address memcpy_dir check only can distinguish D2H/H2D/D2D */
	switch (udvm_dir) {
	case UDVM_MEMCPY_DIR_D2H: dir = DMA_D2H; break;
	case UDVM_MEMCPY_DIR_H2D: dir = DMA_H2D; break;
	case UDVM_MEMCPY_DIR_D2D: dir = DMA_D2D; break;
	}

	return dir;
}

static bool __is_memset_task(int dir)
{
	return ((dir == MEMSET_D8) || (dir == MEMSET_D16) || (dir == MEMSET_D32));
}

static int
__prepare_priv_with_nocheck(struct sbts_dma_async *params,
			struct sbts_dma_priv *priv)
{
	struct file *src_fp = NULL, *dst_fp = NULL;
	struct fp_priv_data *priv_data = NULL;
	struct cn_core_set *src_core = NULL, *dst_core = NULL;
	int card_id = 0;

	priv->dir = params->dir;
	if (__is_memset_task(params->dir)) {
		dst_fp = udvm_fcheck(params->memset.fd);
		if (!dst_fp) {
			cn_dev_err("invalid cambricon device file descriptor input");
			return -EINVAL;
		}

		priv_data = dst_fp->private_data;
		dst_core = priv_data->core;
		if (params->is_udvm_support) {
			card_id = udvm_get_cardid_from_addr(params->memset.dev_addr);
			if (card_id < 0) {
				cn_dev_err("invalid udvm address input");
				return -ENXIO;
			}
			dst_core = cn_core_get_with_idx(card_id);
		}

		priv->memset.bus_set = (u64)dst_core->bus_set;
		priv->memset.pminfo = (u64)NULL;
		return 0;
	}

	if ((priv->dir == DMA_D2H) || (priv->dir == DMA_D2D) ||
		(priv->dir == DMA_P2P)) {
		src_fp = udvm_fcheck(params->memcpy.mem.src_fd);
		if (!src_fp) {
			cn_dev_err("invalid cambricon device file descriptor input");
			return -EINVAL;
		}

		priv_data = src_fp->private_data;
		src_core = priv_data->core;

		if (params->is_udvm_support) {
			card_id = udvm_get_cardid_from_addr(params->memcpy.src_addr);
			if (card_id < 0) {
				cn_dev_err("invalid udvm address input");
				return -ENXIO;
			}
			src_core = cn_core_get_with_idx(card_id);
		}
	}

	if ((priv->dir == DMA_H2D) || (priv->dir == DMA_D2D) ||
		(priv->dir == DMA_P2P)) {
		dst_fp = udvm_fcheck(params->memcpy.mem.dst_fd);
		if (!dst_fp) {
			cn_dev_err("invalid cambricon device file descriptor input");
			return -EINVAL;
		}

		priv_data = dst_fp->private_data;
		dst_core = priv_data->core;

		if (params->is_udvm_support) {
			card_id = udvm_get_cardid_from_addr(params->memcpy.dst_addr);
			if (card_id < 0) {
				cn_dev_err("invalid udvm address input");
				return -ENXIO;
			}
			dst_core = cn_core_get_with_idx(card_id);
		}
	}

	if (src_core) priv->memcpy.src_bus_set = (u64)src_core->bus_set;
	if (dst_core) priv->memcpy.dst_bus_set = (u64)dst_core->bus_set;
	priv->memcpy.src_pminfo = (u64)NULL;
	priv->memcpy.dst_pminfo = (u64)NULL;

	return 0;
}

int cn_async_address_kref_get(struct sbts_dma_async *params,
			struct sbts_dma_priv *priv)
{
	struct file *src_fp = NULL, *dst_fp = NULL, *ctl_fp = NULL;
	struct mapinfo *src_pminfo = NULL, *dst_pminfo = NULL;
	struct cn_core_set *src_core = NULL, *dst_core = NULL;
	int ret = 0, dir = 0;

	if (ignore_params_check)
		return __prepare_priv_with_nocheck(params, priv);

	if (__is_memset_task(params->dir)) {
		dst_fp = udvm_fcheck(params->memset.fd);
		if (!dst_fp) {
			cn_dev_err("invalid cambricon device file descriptor input");
			return -EINVAL;
		}

		if (addr_is_export(params->memset.dev_addr))
			return __prepare_priv_with_nocheck(params, priv);

		ret = cn_memset_dma_params_kref_get((u64)dst_fp,
					params->memset.dev_addr, params->memset.number,
					params->memset.per_size, &dst_pminfo, true);
		if (!ret) {
			dst_core = ((struct cn_mm_set *)dst_pminfo->mm_set)->core;
			priv->memset.pminfo = (u64)dst_pminfo;
			priv->memset.bus_set = (u64)dst_core->bus_set;
			priv->dir = params->dir;
		}

		return ret;
	}

	if (addr_is_export(params->memcpy.dst_addr) || addr_is_export(params->memcpy.src_addr))
			return __prepare_priv_with_nocheck(params, priv);

	dir = __get_memcpy_dir(params->dir, params->memcpy.src_addr,
					params->memcpy.dst_addr, params->is_udvm_support);
	if (dir < 0) {
		cn_dev_err("invalid memcpy_async dir(%lld). (src:%#llx, dst:%#llx)",
				params->dir, params->memcpy.src_addr, params->memcpy.dst_addr);
		return -ENXIO;
	}

	if (params->is_udvm_support) {
		ctl_fp = udvm_fcheck(params->memcpy.udvm_fd);
		if (!ctl_fp) {
			cn_dev_err("invalid cambricon device file descriptor input");
			return -EINVAL;
		}

		src_fp = dst_fp = ctl_fp;
	} else {
		if ((dir == DMA_D2H) || (dir == DMA_D2D) || (dir == DMA_P2P)) {
			src_fp = udvm_fcheck(params->memcpy.mem.src_fd);
			if (!src_fp) {
				cn_dev_err("invalid cambricon device file descriptor input");
				return -EINVAL;
			}
		}

		if ((dir == DMA_H2D) || (dir == DMA_D2D) || (dir == DMA_P2P)) {
			dst_fp = udvm_fcheck(params->memcpy.mem.dst_fd);
			if (!dst_fp) {
				cn_dev_err("invalid cambricon device file descriptor input");
				return -EINVAL;
			}
		}
	}

	switch (dir) {
	case DMA_D2H: {
		ret = cn_memcpy_dma_params_kref_get((u64)src_fp,
						params->memcpy.dst_addr, params->memcpy.src_addr,
						params->memcpy.size, &src_pminfo, true);
		break;
	}
	case DMA_H2D: {
		ret = cn_memcpy_dma_params_kref_get((u64)dst_fp,
						params->memcpy.src_addr, params->memcpy.dst_addr,
						params->memcpy.size, &dst_pminfo, true);
		break;
	}
	case DMA_D2D:
	case DMA_P2P: {
		ret = cn_memcpy_peer_params_kref_get((u64)src_fp, (u64)dst_fp,
						params->memcpy.src_addr, params->memcpy.dst_addr,
						params->memcpy.size, &src_pminfo, &dst_pminfo, true);
		break;
	}

	default:
		cn_dev_err("input dir(%#llx) is not support", params->dir);
		ret = -EINVAL;
		break;
	}

	if (src_pminfo) {
		priv->memcpy.src_pminfo  = (u64)src_pminfo;
		src_core = ((struct cn_mm_set *)src_pminfo->mm_set)->core;
		priv->memcpy.src_bus_set = (u64)src_core->bus_set;
	}

	if (dst_pminfo) {
		dst_core = ((struct cn_mm_set *)dst_pminfo->mm_set)->core;
		priv->memcpy.dst_pminfo  = (u64)dst_pminfo;
		priv->memcpy.dst_bus_set = (u64)dst_core->bus_set;
	}

	priv->dir = dir;
	if (src_core && dst_core) {
		priv->dir = (src_core == dst_core) ? DMA_D2D : DMA_P2P;
	}

	return ret;
}

void cn_async_address_kref_put(__u64 minfo, dev_addr_t dev_vaddr,
			unsigned long size)
{
	struct mapinfo *pminfo = (struct mapinfo *)minfo;
	struct cn_core_set *core = NULL;
	void *udvm_priv = NULL;

	if (ignore_params_check) return ;

	if (!pminfo) {
		return ;
	}

	/**
	 * NOTE: address input from other driver module maybe clear high bits, we
	 * need set high bits again, before call memory internal interfaces.
	 **/
	core = ((struct cn_mm_set *)pminfo->mm_set)->core;
	dev_vaddr = udvm_get_iova_from_addr(dev_vaddr);
	dev_vaddr |= udvm_get_head_from_addr(pminfo->virt_addr);
	if (dev_vaddr < pminfo->virt_addr ||
		dev_vaddr > (pminfo->virt_addr + pminfo->mem_meta.size)) {
		cn_dev_core_err(core, "input area(%#llx, %#lx) isn't match pminfo(%#llx, %#lx) input!",
				dev_vaddr, size, pminfo->virt_addr, pminfo->mem_meta.size);
		return ;
	}

	udvm_priv = pminfo->udvm_priv;
	camb_kref_put_range(pminfo, dev_vaddr, size, camb_mem_release);
	if (udvm_priv)
		udvm_unregister_async_tasks(udvm_priv);

	return ;
}

int camb_host_mem_check(host_addr_t host_vaddr, size_t size)
{
	return camb_mem_dma_hmsc(host_vaddr, size);
}

int camb_mem_check_without_ref(unsigned long tag, unsigned long device_vaddr,
				unsigned long size, void *mem_set)
{
	int ret = 0;
	struct file *fp = (struct file *)tag;
	struct mapinfo *pminfo = NULL;
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	if (addr_is_vmm(device_vaddr)) {
		pminfo = camb_vmm_minfo_kref_get_range(tag, device_vaddr, size,
							__params_check_range);
	} else {
		pminfo = search_mapinfo_with_func(fp, mm_set, device_vaddr, size,
							__params_check_range);
	}

	if (IS_ERR_OR_NULL(pminfo)) {
		/* NOTE: called uva_get in 300ARM will be failed and do not output error log */
		cn_dev_core_debug(core, "mapinfo for addr(%#lx) invalid", device_vaddr);
		ret = PTR_ERR(pminfo);
	}

	return ret;
}

static void camb_peer_obmap_release(struct mapinfo *pminfo)
{
	struct ob_map_t *ob, *tmp;

	list_for_each_entry_safe(ob, tmp, &pminfo->obmap_list, list_node) {
		list_del_init(&ob->list_node);
		camb_release_ob_map(ob);
	}
}

int camb_peer_register(u64 tag, struct cn_mm_set *lmset, dev_addr_t addr, size_t size,
			struct cn_mm_set *rmset, u32 flags)
{
	struct cn_mm_set *mm_set = NULL;
	struct mapinfo *pminfo = NULL;
	struct ob_map_t *obmap = NULL;
	struct sg_table *table = NULL;
	dev_addr_t iova = 0;
	int ret = 0;

	ret = camb_kref_get(tag, addr, &pminfo, lmset);
	if (ret < 0) {
		cn_dev_err_limit("could found addr(%#llx) in this process", addr);
		return ret;
	}

	/* NOTE: input mm_set maybe is NULL */
	mm_set = pminfo->mm_set;
	if (pminfo->mem_type == MEM_VMM) {
		cn_dev_err_limit("vmm memory not support register at now");
		ret = -EINVAL;
		goto kref_put;
	}

	if (pminfo->mm_set == rmset) {
		cn_dev_debug("register device is as the same as allocated device");
		ret = 0;
		goto kref_put;
	}

	if (camb_dob_size_align(size, rmset) != size) {
		cn_dev_err_limit("input size is not alinged with dob config");
		ret = -EINVAL;
		goto kref_put;
	}

	if (!IS_ALIGNED(addr, 0x10000) || !IS_ALIGNED(size, 0x4000)) {
		cn_dev_err_limit("input register params is not alinged as required");
		ret = -EINVAL;
		goto kref_put;
	}

	/* NOTE: current only support register the allocated memory into ob */
	ret = __params_check_equal(pminfo, addr, size);
	if (ret)
		goto kref_put;

	spin_lock(&pminfo->obmap_lock);
	ret = camb_search_ob_map(&pminfo->obmap_list, get_index_with_mmset(rmset), &obmap);
	spin_unlock(&pminfo->obmap_lock);
	if (!ret && obmap) {
		cn_dev_err("address:%#llx has already been registered on Card%d", addr, get_index_with_mmset(rmset));
		ret = -EEXIST;
		goto kref_put;
	}

	table = cn_mem_linear_remap(pminfo, addr, size);
	if (IS_ERR(table)) {
		cn_dev_err("get device memory remap sg_table failed");
		ret = PTR_ERR(table);
		goto kref_put;
	}

	if (mm_set->devid == MLUID_580 || pminfo->mem_meta.type == CN_SHARE_MEM) {
		/* NOTE: mlu580 limit tc access outbound iova range, use iova allocated from genpool */
		iova = 0;
	} else {
		iova = udvm_get_iova_from_addr(addr);
	}

	obmap = camb_init_ob_map(table, pminfo, cn_mem_linear_unmap, size, rmset, iova);
	if (IS_ERR_OR_NULL(obmap)) {
		cn_dev_err("alloc ob_info failed, check platform whether support ob");
		ret = -ENOMEM;
		goto kref_put;
	}

	spin_lock(&pminfo->obmap_lock);
	list_add_tail(&obmap->list_node, &pminfo->obmap_list);
	spin_unlock(&pminfo->obmap_lock);

	ret = camb_map_ob_win(obmap, 1);
	if (ret) {
		cn_dev_err("cfg outbound win failed:%d\n", ret);
		goto free_obmap;
	} else {
		goto kref_put;
	}

free_obmap:
	spin_lock(&pminfo->obmap_lock);
	list_del(&obmap->list_node);
	spin_unlock(&pminfo->obmap_lock);
	camb_release_ob_map(obmap);
kref_put:
	camb_kref_put_range(pminfo, addr, size, camb_mem_release);
	return ret;
}

int cn_mem_peer_register(struct cn_core_set *lcore, dev_addr_t addr, size_t size, struct cn_core_set *rcore, u32 flags)
{
	return camb_peer_register(0, lcore->mm_set, addr, size, rcore->mm_set, flags);
}

int camb_peer_unregister(u64 tag, struct cn_mm_set *lmset, dev_addr_t addr,
			struct cn_mm_set *rmset)
{
	struct mapinfo *pminfo = NULL;
	struct ob_map_t *obmap = NULL;
	int ret = 0;

	ret = camb_kref_get(tag, addr, &pminfo, lmset);
	if (ret < 0) {
		cn_dev_err_limit("could found addr(%#llx) in this process", addr);
		return ret;
	}

	if (pminfo->mem_type == MEM_VMM) {
		cn_dev_err_limit("vmm memory not support register at now");
		ret = -EINVAL;
		goto kref_put;
	}

	if (rmset == pminfo->mm_set) {
		cn_dev_debug("register device is as the same as allocated device");
		ret = 0;
		goto kref_put;
	}

	spin_lock(&pminfo->obmap_lock);
	ret = camb_search_ob_map(&pminfo->obmap_list, get_index_with_mmset(rmset), &obmap);
	if (ret) {
		spin_unlock(&pminfo->obmap_lock);
		cn_dev_err("address:%#llx not be registered", addr);
		goto kref_put;
	}

	list_del_init(&obmap->list_node);
	spin_unlock(&pminfo->obmap_lock);

	camb_release_ob_map(obmap);

kref_put:
	camb_kref_put(pminfo, camb_mem_release);
	return ret;
}

int cn_mem_peer_unregister(struct cn_core_set *core, dev_addr_t addr,
			struct cn_core_set *rcore)
{
	return camb_peer_unregister(0, core->mm_set, addr, rcore->mm_set);
}

int camb_peer_get_pointer(u64 tag, struct cn_mm_set *lmset, dev_addr_t addr, struct cn_mm_set *rmset,
			dev_addr_t *oaddr, u32 flags)
{
	dev_addr_t offset = 0;
	struct mapinfo *pminfo = NULL;
	struct ob_map_t *obmap = NULL;
	int ret = 0;

	ret = camb_kref_get(tag, addr, &pminfo, lmset);
	if (ret < 0) {
		cn_dev_err_limit("could found addr(%#llx) in this process", addr);
		return ret;
	}

	if (rmset == pminfo->mm_set) {
		cn_dev_debug("register device is as the same as allocated device");
		*oaddr = addr;
		ret = 0;
		goto kref_put;
	}

	if (pminfo->mem_type == MEM_VMM) {
		cn_dev_err_limit("vmm memory not support register at now");
		ret = -EINVAL;
		goto kref_put;
	}

	spin_lock(&pminfo->obmap_lock);
	ret = camb_search_ob_map(&pminfo->obmap_list, get_index_with_mmset(rmset), &obmap);
	spin_unlock(&pminfo->obmap_lock);
	if (ret) {
		cn_dev_err("address:%#llx not be registered", addr);
		goto kref_put;
	}

	offset = udvm_get_iova_from_addr(addr) - udvm_get_iova_from_addr(pminfo->virt_addr);
	*oaddr = obmap->iova + offset;

kref_put:
	camb_kref_put(pminfo, camb_mem_release);
	return ret;
}

int cn_mem_peer_get_pointer(struct cn_core_set *lcore,
			dev_addr_t addr, struct cn_core_set *rcore, dev_addr_t *oaddr, u32 flags)
{
	return camb_peer_get_pointer(0, lcore->mm_set, addr, rcore->mm_set, oaddr, flags);
}

/** START: GDR copy used module interfaces, added by PCIE module **/
int cn_pminfo_get(dev_addr_t iova, struct mapinfo **pminfo)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct udvm_priv_data *udvm_priv;
	struct cn_core_set *core;
	struct cn_mm_set *mm_set;
	int ret = 0;
	int card_id = 0;

	card_id = udvm_get_cardid_from_addr(iova);
	if (card_id < 0) {
		cn_dev_err("invalid cardid %d", card_id);
		return -EINVAL;
	}

	core = (struct cn_core_set *)cn_core_get_with_idx(card_id);
	if (core != NULL) {
		mm_set = core->mm_set;
	} else {
		return -EINVAL;
	}

	rcu_read_lock();
	udvm_priv = radix_tree_lookup(&udvm_set->udvm_raroot, current->tgid);
	if (!udvm_priv) {
		rcu_read_unlock();
		cn_dev_core_err(core, "current process hasn't been initialized");
		return -EINVAL;
	}

	ret = camb_kref_get(udvm_priv->tag, iova, pminfo, mm_set);
	rcu_read_unlock();

	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal.", iova);
	}

	return ret;
}

int cn_mem_p2p_pin_mem(dev_addr_t iova, u64 size, struct sg_table **pin_table)
{
	int ret = 0;
	struct mapinfo *pminfo;
	struct sg_table *p2p_sg_table;

	*pin_table = NULL;
	ret = cn_pminfo_get(iova, &pminfo);
	if (ret) {
		cn_dev_err("%s get pminfo failed %d", __func__, ret);
		return ret;
	}

	p2p_sg_table = cn_mem_linear_remap(pminfo, iova, size);
	if (IS_ERR_OR_NULL(p2p_sg_table)) {
		ret = PTR_ERR(p2p_sg_table);
		cn_dev_err("%s failed %d", __func__, ret);
		goto err;
	}

	*pin_table = p2p_sg_table;

err:
	camb_kref_put(pminfo, camb_mem_release);
	return ret;
}
EXPORT_SYMBOL(cn_mem_p2p_pin_mem);

int cn_mem_p2p_unpin_mem(dev_addr_t iova, struct sg_table *pin_table)
{
	int ret = 0;
	struct mapinfo *pminfo;

	ret =  cn_pminfo_get(iova, &pminfo);
	if (ret) {
		cn_dev_err("%s get pminfo failed %d", __func__, ret);
		return ret;
	}
	cn_mem_linear_unmap(pminfo, pin_table);

	camb_kref_put(pminfo, camb_mem_release);
	return ret;
}
EXPORT_SYMBOL(cn_mem_p2p_unpin_mem);

int cn_mem_remap(dev_addr_t iova, u64 size, dev_addr_t *mapped_addr)
{
	int ret = 0;
	struct mapinfo *pminfo;
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = NULL;
	struct cn_bus_set *src_bus_set;
	u64 offset = 0;

	ret = cn_pminfo_get(iova, &pminfo);
	if (ret) {
		cn_dev_err("get pminfo failed %d", ret);
		return ret;
	}

	ret = camb_mem_p2p_remap(pminfo, iova, size, mapped_addr);
	if (ret) {
		cn_dev_err("camb_mem_p2p_remap failed %d", ret);
		goto err;
	}

	mm_set = (struct cn_mm_set *)pminfo->mm_set;
	core = (struct cn_core_set *)mm_set->core;
	src_bus_set = (struct cn_bus_set *)core->bus_set;
	ret = cn_bus_get_linear_bar_offset(src_bus_set, &offset);
	if (ret == -1) {
		cn_dev_err("get p2p offset: maybe board not support gdr");
		goto err;
	}
	*mapped_addr = *mapped_addr - offset;
err:
	camb_kref_put(pminfo, camb_mem_release);
	return ret;
}
EXPORT_SYMBOL(cn_mem_remap);
int cn_mem_gdr_linear_remap(dev_addr_t iova, u64 size, void **page_table)
{
	int ret = 0;
	struct mapinfo *pminfo;
	struct sg_table *sgl;

	ret = cn_pminfo_get(iova, &pminfo);
	if (ret) {
		cn_dev_err("get pminfo failed %d", ret);
		return ret;
	}

	sgl = cn_mem_linear_remap(pminfo, iova, size);
	if (IS_ERR_OR_NULL(sgl)) {
		cn_dev_err("page_table err");
		ret = -1;
		goto err;
	}
	*page_table = sgl;

	if (*page_table == NULL) {
		cn_dev_err("cn_mem_linear_remap failed");
		ret = -1;
		goto err;
	}

err:
	camb_kref_put(pminfo, camb_mem_release);
	return ret;
}
EXPORT_SYMBOL(cn_mem_gdr_linear_remap);
int cn_mem_unremap(dev_addr_t iova, dev_addr_t mapped_addr)
{
	int ret = 0;
	struct mapinfo *pminfo;
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = NULL;
	struct cn_bus_set *src_bus_set;
	u64 offset = 0;

	ret =  cn_pminfo_get(iova, &pminfo);
	if (ret) {
		cn_dev_err("get pminfo failed %d", ret);
		return ret;
	}
	mm_set = (struct cn_mm_set *)pminfo->mm_set;
	core = (struct cn_core_set *)mm_set->core;
	src_bus_set = (struct cn_bus_set *)core->bus_set;
	ret = cn_bus_get_linear_bar_offset(src_bus_set, &offset);
	if (ret == -1) {
		cn_dev_err("get p2p offset: maybe board not support gdr");
		goto err;
	}
	mapped_addr = mapped_addr + offset;

	ret = camb_mem_p2p_unmap(pminfo, mapped_addr);
	if (ret) {
		cn_dev_err("camb_mem_p2p_unmap failed %d", ret);
		goto err;
	}
err:
	camb_kref_put(pminfo, camb_mem_release);
	return ret;
}
EXPORT_SYMBOL(cn_mem_unremap);
int cn_mem_gdr_linear_unremap(dev_addr_t iova, void *page_table)
{
	int ret = 0;
	struct mapinfo *pminfo;

	ret =  cn_pminfo_get(iova, &pminfo);
	if (ret) {
		cn_dev_err("get pminfo failed %d", ret);
		return ret;
	}
	cn_mem_linear_unmap(pminfo, (struct sg_table *)page_table);

	camb_kref_put(pminfo, camb_mem_release);
	return ret;
}
EXPORT_SYMBOL(cn_mem_gdr_linear_unremap);
/** END: GDR copy used module interfaces, added by PCIE module **/
