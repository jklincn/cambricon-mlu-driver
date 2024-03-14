/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2022 Cambricon, Inc. All rights reserved.
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

static int mlu590_llc_maintanance(void *pcore, unsigned int action)
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

static int mlu590_llc_lock_set_ways(void *pcore, unsigned int ways)
{
	int ret = 0;
	struct llc_ctrl_in llc_in;
	struct llc_ctrl_ret llc_out;
	size_t llc_ret_len = sizeof(struct llc_ctrl_ret);
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (ways > 3) {
		cn_dev_core_warn(core,
			"input ways(%d) is out of current platform maximum lock ways(3), use maximum value as default", ways);
		ways = 3;
	}

	memset(&llc_out, 0x0, sizeof(struct llc_ctrl_ret));

	llc_in.cmd = LLC_LOCK_SET_WAYS;
	llc_in.data[0] = ways;

	ret = __mem_call_rpc(mem_set->core, mem_set->endpoint, "rpc_llc_ctrl",
			&llc_in, sizeof(struct llc_ctrl_in),
			&llc_out, &llc_ret_len, sizeof(struct llc_ctrl_ret));

	if (ret < 0) {
		cn_dev_core_err(core, "rpc_call failed with %d returnd!", ret);
		return ret;
	}

	if (llc_out.ret) {
		cn_dev_core_err(core, "LLC set timeout, ret = %d.\n", llc_out.ret);
		return llc_out.ret;
	}

	return 0;
}

static int mlu590_llc_lock_get_ways(void *pcore, unsigned int *ways)
{
	int ret = 0;
	struct llc_ctrl_in llc_in;
	struct llc_ctrl_ret llc_out;
	size_t llc_ret_len = sizeof(struct llc_ctrl_ret);
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (ways == NULL) {
		return -1;
	}

	memset(&llc_out, 0x0, sizeof(struct llc_ctrl_ret));

	llc_in.cmd = LLC_LOCK_GET_WAYS;

	ret = __mem_call_rpc(mem_set->core, mem_set->endpoint, "rpc_llc_ctrl",
			&llc_in, sizeof(struct llc_ctrl_in),
			&llc_out, &llc_ret_len, sizeof(struct llc_ctrl_ret));

	if (ret < 0) {
		cn_dev_core_err(core, "rpc_call failed with %d returnd!", ret);
		return ret;
	}

	if (llc_out.ret) {
		cn_dev_core_err(core, "LLC set timeout, ret = %d.\n", llc_out.ret);
		return llc_out.ret;
	}

	*ways = llc_out.data[0];

	return 0;
}

static int mlu590_llc_lock_en(void *pcore)
{
	int ret = 0;
	struct llc_ctrl_in llc_in;
	struct llc_ctrl_ret llc_out;
	size_t llc_ret_len = sizeof(struct llc_ctrl_ret);
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	memset(&llc_out, 0x0, sizeof(struct llc_ctrl_ret));

	llc_in.cmd = LLC_LOCK_EN;

	ret = __mem_call_rpc(mem_set->core, mem_set->endpoint, "rpc_llc_ctrl",
			&llc_in, sizeof(struct llc_ctrl_in),
			&llc_out, &llc_ret_len, sizeof(struct llc_ctrl_ret));

	if (ret < 0) {
		cn_dev_core_err(core, "rpc_call failed with %d returnd!", ret);
		return ret;
	}

	if (llc_out.ret) {
		cn_dev_core_err(core, "LLC set timeout, ret = %d.\n", llc_out.ret);
		return llc_out.ret;
	}

	return 0;
}

static int mlu590_llc_lock_dis(void *pcore)
{
	int ret = 0;
	struct llc_ctrl_in llc_in;
	struct llc_ctrl_ret llc_out;
	size_t llc_ret_len = sizeof(struct llc_ctrl_ret);
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	memset(&llc_out, 0x0, sizeof(struct llc_ctrl_ret));

	llc_in.cmd = LLC_LOCK_DIS;

	ret = __mem_call_rpc(mem_set->core, mem_set->endpoint, "rpc_llc_ctrl",
			&llc_in, sizeof(struct llc_ctrl_in),
			&llc_out, &llc_ret_len, sizeof(struct llc_ctrl_ret));
	if (ret < 0) {
		cn_dev_core_err(core, "rpc_call failed with %d returnd!", ret);
		return ret;
	}

	if (llc_out.ret) {
		cn_dev_core_err(core, "LLC set timeout, ret = %d.\n", llc_out.ret);
		return llc_out.ret;
	}

	return 0;
}

static int mlu590_llc_lock_clr(void *pcore)
{
	int ret = 0;
	struct llc_ctrl_in llc_in;
	struct llc_ctrl_ret llc_out;
	size_t llc_ret_len = sizeof(struct llc_ctrl_ret);
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	memset(&llc_out, 0x0, sizeof(struct llc_ctrl_ret));

	llc_in.cmd = LLC_LOCK_CLR;

	ret = __mem_call_rpc(mem_set->core, mem_set->endpoint, "rpc_llc_ctrl",
			&llc_in, sizeof(struct llc_ctrl_in),
			&llc_out, &llc_ret_len, sizeof(struct llc_ctrl_ret));

	if (ret < 0) {
		cn_dev_core_err(core, "rpc_call failed with %d returnd!", ret);
		return ret;
	}

	if (llc_out.ret) {
		cn_dev_core_err(core, "LLC set timeout, ret = %d.\n", llc_out.ret);
		return llc_out.ret;
	}

	return 0;
}

static int mlu590_llc_get_irq_info(void *pcore)
{
	int ret = 0;
	struct llc_ctrl_in llc_in;
	struct llc_ctrl_ret llc_out;
	size_t llc_ret_len = sizeof(struct llc_ctrl_ret);
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;
	int i;

	memset(&llc_out, 0x0, sizeof(struct llc_ctrl_ret));

	llc_in.cmd = LLC_LOCK_GET_IRQ_NUMS;

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

	for (i = 0; i < LLC_DATA_LEN; i++) {
		cn_dev_core_info(core, "%d llc irq nums %d.", i, llc_out.data[i]);
	}

	return 0;
}

void mlu590_llc_ops_register(void *ops)
{
	struct llc_ops *llc_ops = (struct llc_ops *)ops;

	if (llc_ops) {
		llc_ops->llc_maintanance = mlu590_llc_maintanance;
		llc_ops->llc_lock_set_ways = mlu590_llc_lock_set_ways;
		llc_ops->llc_lock_get_ways = mlu590_llc_lock_get_ways;
		llc_ops->llc_lock_en = mlu590_llc_lock_en;
		llc_ops->llc_lock_dis = mlu590_llc_lock_dis;
		llc_ops->llc_lock_clr = mlu590_llc_lock_clr;
		llc_ops->llc_get_irq_info = mlu590_llc_get_irq_info;
	}
}
