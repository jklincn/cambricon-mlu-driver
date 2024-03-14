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
#include "cndrv_debug.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "llc.h"
#include "./hal_smmu/smmu_common.h"
#include "../camb_mm.h"

size_t camb_get_page_size(void)
{
	size_t page_size = 0x1000; /*default as 4K page size*/

	switch (GRANULE_SIZE) {
	case 0:
		page_size = 0x1000;
		break;
	case 1:
		page_size = 0x4000;
		break;
	case 2:
		page_size = 0x10000;
		break;
	default:
		page_size = 0x1000;
		break;
	}

	return page_size;
}

void cn_mem_hal_exit(struct cn_mm_set *mm_set)
{
	smmu_dev_exit(mm_set->core);
}

void cn_mem_hal_init(struct cn_mm_set *mm_set)
{
	/*llc device resource init*/
	llc_dev_init(mm_set->core);
	/*pcie smmu device resource init*/
	smmu_dev_init(mm_set->core);
}

void cn_mem_hal_reinit(struct cn_mm_set *mm_set)
{
	/*only pcie smmu device resource need to reinit*/
	smmu_dev_reinit(mm_set->core);
}

int cn_smmu_cau_bypass(struct cn_core_set *core, int phy_ch, bool en)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)core->mm_set;
	int (*smmu_cau_bypass)(void *, unsigned int, bool);

	smmu_cau_bypass = mm_set->smmu_ops.smmu_cau_bypass;
	if (!smmu_cau_bypass) {
		cn_dev_core_err(core, "Don't support bypass mode");
		return -EPERM;
	}

	smmu_cau_bypass(core, phy_ch, en);

	return 0;
}

int cn_smmu_cau_invalid(struct cn_core_set *core, unsigned int s_id)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)core->mm_set;
	int (*smmu_cau_invalid)(void *, unsigned int);

	smmu_cau_invalid = mm_set->smmu_ops.smmu_cau_invalid;
	if (!smmu_cau_invalid) {
		cn_dev_core_err(core, "Don't support cau invalid");
		return -EINVAL;
	}
	smmu_cau_invalid(core, s_id);
	return 0;
}
