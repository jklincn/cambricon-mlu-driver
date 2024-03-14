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

void llc_cds_enable(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (mem_set->llc_ops.llc_cds_enable) {
		mem_set->llc_ops.llc_cds_enable(pcore);
	}
}

void llc_remap_set_for_all_channel(void *pcore, unsigned int remap)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (mem_set->llc_ops.llc_remap_set) {
		mem_set->llc_ops.llc_remap_set(pcore, remap);
	}
}


int llc_maintanance(void *pcore, unsigned int action)
{
	int ret = -1;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (mem_set->llc_ops.llc_maintanance) {
		ret = mem_set->llc_ops.llc_maintanance(pcore, action);
	}

	return ret;
}

int llc_lock_en(void *pcore)
{
	int ret = -1;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (mem_set->llc_ops.llc_lock_en) {
		ret = mem_set->llc_ops.llc_lock_en(pcore);
	}

	return ret;
}

int llc_lock_dis(void *pcore)
{
	int ret = -1;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (mem_set->llc_ops.llc_lock_dis) {
		ret = mem_set->llc_ops.llc_lock_dis(pcore);
	}

	return ret;
}

int llc_lock_clr(void *pcore)
{
	int ret = -1;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (mem_set->llc_ops.llc_lock_clr) {
		ret = mem_set->llc_ops.llc_lock_clr(pcore);
	}

	return ret;
}

int llc_lock_set_ways(void *pcore, unsigned int ways)
{
	int ret = -1;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (mem_set->llc_ops.llc_lock_set_ways) {
		ret = mem_set->llc_ops.llc_lock_set_ways(pcore, ways);
	}

	return ret;
}

int llc_lock_get_ways(void *pcore, unsigned int *ways)
{
	int ret = -1;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (mem_set->llc_ops.llc_lock_get_ways) {
		ret = mem_set->llc_ops.llc_lock_get_ways(pcore, ways);
	}

	return ret;
}

int llc_get_irq_info(void *pcore)
{
	int ret = -1;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	if (mem_set->llc_ops.llc_get_irq_info) {
		ret = mem_set->llc_ops.llc_get_irq_info(pcore);
	}

	return ret;
}

void llc_dev_init(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;

	switch(mem_set->devid) {
	case MLUID_220:
	case MLUID_220_EDGE:
		mlu220_llc_ops_register(&mem_set->llc_ops);
		break;
	case MLUID_270:
		mlu270_llc_ops_register(&mem_set->llc_ops);
		break;
	case MLUID_290:
		mlu290_llc_ops_register(&mem_set->llc_ops);
		break;
	case MLUID_370:
		mlu370_llc_ops_register(&mem_set->llc_ops);
		break;
	case MLUID_590:
	case MLUID_580:
	case MLUID_590V:
	case MLUID_580V:
		mlu590_llc_ops_register(&mem_set->llc_ops);
		break;
	case MLUID_PIGEON:
	case MLUID_PIGEON_EDGE:
		pigeon_llc_ops_register(&mem_set->llc_ops);
		break;
	default:
		cn_dev_core_info(core, "LLC is invalid in this device type(%d)!",
						 mem_set->devid);
		break;
	}


	if ((!cn_core_is_vf(core))
		&& mem_set->devid == MLUID_270) {	/* Only mlu270 Support CDS in LLC */
		llc_cds_enable(pcore);
	}

	if (mem_set->llc_ops.llc_remap_set != NULL) {
		llc_remap_set_for_all_channel(pcore, LLC_REMAP3);
	}
}
