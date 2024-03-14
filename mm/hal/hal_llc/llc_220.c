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
#include "llc_common.h"
#include "cndrv_commu.h"
#include "../../camb_mm.h"
#include "../../include/camb_mm_rpc.h"

#define MLU220_LLC_BASE_ADDR		(0x102000)
/*register*/
#define MLU220_LLC_ADDR_MAP_REG		(MLU220_LLC_BASE_ADDR + 0x8c)

static void mlu220_llc_remap_set(void *pcore, unsigned int flag)
{
	unsigned int val, remap;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	/* if total memory is 2G, just return zero as right */
	unsigned int ddr_cap = core->board_info.total_memory / 0x100000000;

	cn_dev_core_debug(core, "read ddr_cap in board_info is %d\n", ddr_cap);
	remap = flag & 0x3;
	/*    MAP0   |    MAP1    |    MAP2    |    DDR_CAP   */
	val = remap << 2 | remap << 4 | remap << 6 | ddr_cap << 10;
	reg_write32(core->bus_set, MLU220_LLC_ADDR_MAP_REG, val);
}


static int mlu220_llc_maintanance(void *pcore, unsigned int action)
{
	int ret = 0;
	struct llc_ctrl_in llc_in;
	struct llc_ctrl_ret llc_out;
	size_t llc_ret_len = sizeof(struct llc_ctrl_ret);
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	/*	action = 0, do nothing;
		action = 1, invalid only;
		action = 2, clean only;
		action = 3, invalid & clean
	*/
	if (action > 3)
		return -1;

	llc_in.cmd = LLC_MAINTAIN;
	llc_in.data[0] = action;

	memset(&llc_out, 0x0, sizeof(struct llc_ctrl_ret));

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


void mlu220_llc_ops_register(void *ops)
{
	struct llc_ops *llc_ops = (struct llc_ops *)ops;

	if (llc_ops) {
		llc_ops->llc_cds_enable = NULL;
		llc_ops->llc_remap_set = mlu220_llc_remap_set;
		llc_ops->llc_maintanance = mlu220_llc_maintanance;
	}
}

