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

#define MLU270_LLC0_BASE_ADDR		(0x208000)
#define MLU270_LLC_BASE_OFS			(0x10000)
#define MLU270_LLC_CNT              (4)
/*register*/
#define MLU270_LLCx_BASE_ADDR(n)	\
	(MLU270_LLC0_BASE_ADDR + (n) * MLU270_LLC_BASE_OFS)
#define MLU270_LLCx_CDS_CFG_REG(n)	(MLU270_LLCx_BASE_ADDR(n) + 0x90)

void mlu270_llc_cds_enable(void *pcore)
{
	int i = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	for (i = 0; i < MLU270_LLC_CNT; i++) {
		reg_write32(core->bus_set, MLU270_LLCx_CDS_CFG_REG(i), 1);
	}
}

static int mlu270_llc_maintanance(void *pcore, unsigned int action)
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

void mlu270_llc_ops_register(void *ops)
{
	struct llc_ops *llc_ops = (struct llc_ops *)ops;

	if (llc_ops) {
		llc_ops->llc_cds_enable = mlu270_llc_cds_enable;
		llc_ops->llc_remap_set = NULL;
		llc_ops->llc_maintanance = mlu270_llc_maintanance;
	}
}
