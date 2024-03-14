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
#include "cndrv_mm.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_commu.h"
#include "llc_common.h"
#include "../../camb_mm.h"
#include "../../include/camb_mm_rpc.h"

#define MLU290_LLC0_BASE_ADDR		(0xf01000)
#define MLU290_LLC_BASE_OFS			(0x4000)
#define MLU290_LLC_CNT				(8)
#define MLU290_DDR_CHAN_NUM			(8)
/*register*/
#define MLU290_LLCx_BASE_ADDR(n)	\
	(MLU290_LLC0_BASE_ADDR + (n) * MLU290_LLC_BASE_OFS)

#define MLU290_LLCx_ADDR_MAP_REG(n)	(MLU290_LLCx_BASE_ADDR(n) + 0x8c)
#define MLU290_LLCx_CDS_CFG_REG(n)	(MLU290_LLCx_BASE_ADDR(n) + 0x90)

static void mlu290_llc_remap_set(void *pcore, unsigned int flag)
{
	int i;
	unsigned int val, remap;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	remap = flag & 0x3;
	/*    MAP0   |    MAP1    |    MAP2    |    MAP3   */
	val = remap << 2 | remap << 4 | remap << 6 | remap << 8;
	for (i = 0; i < MLU290_LLC_CNT; i++ ) {
		reg_write32(core->bus_set, MLU290_LLCx_ADDR_MAP_REG(i), val);
	}
}


int mlu290_llc_maintanance(void *pcore, unsigned int action)
{
	int ret = 0;
	struct llc_ctrl_in llc_in;
	struct llc_ctrl_ret llc_out;
	size_t llc_ret_len = sizeof(struct llc_ctrl_ret);
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (action > 3)
		return -1;

	memset(&llc_out, 0x0, sizeof(struct llc_ctrl_ret));

	llc_in.cmd = LLC_MAINTAIN;
	llc_in.data[0] = action;

	ret = __mem_call_rpc(mem_set->core, mem_set->endpoint, "rpc_llc_ctrl",
			&llc_in, sizeof(struct llc_ctrl_in),
			&llc_out, &llc_ret_len, sizeof(struct llc_ctrl_ret));

	if (ret < 0) {
		cn_dev_core_err(core, "rpc_call failed with %d returnd!", ret);
		return ret;
	}

	if (llc_out.ret) {
		cn_dev_core_err(core, "LLC set timeout.\n");
		return llc_out.ret;
	}

	return 0;
}

void mlu290_llc_ops_register(void *ops)
{
	struct llc_ops *llc_ops = (struct llc_ops *)ops;

	if (llc_ops) {
		llc_ops->llc_cds_enable = NULL;
		llc_ops->llc_remap_set = mlu290_llc_remap_set;
		llc_ops->llc_maintanance = mlu290_llc_maintanance;
	}
}
