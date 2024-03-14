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
#include "smmu_common.h"
#include "../../camb_mm.h"

void smmu_dev_exit(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	/*smmu init*/
	if (mm_set->smmu_ops.smmu_release)
		(*mm_set->smmu_ops.smmu_release)(pcore);
}

void smmu_dev_init(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	switch(mm_set->devid) {
	case MLUID_220:
		mlu220_smmu_ops_register(&mm_set->smmu_ops);
		break;
	case MLUID_270:
		mlu270_smmu_ops_register(&mm_set->smmu_ops);
		break;
	case MLUID_290:
		mlu290_smmu_ops_register(&mm_set->smmu_ops);
		break;
	case MLUID_370:
		mlu370_smmu_ops_register(&mm_set->smmu_ops);
		break;
	case MLUID_590:
	case MLUID_580:
		mlu590_smmu_ops_register(&mm_set->smmu_ops);
		break;
	case MLUID_CE3226:
		ce3226_smmu_ops_register(&mm_set->smmu_ops);
		break;
	case MLUID_PIGEON:
		pigeon_smmu_ops_register(&mm_set->smmu_ops);
		break;
	case MLUID_220_EDGE:
	case MLUID_270V:
	case MLUID_270V1:
	case MLUID_290V1:
	case MLUID_370V:
	case MLUID_370_DEV:
	case MLUID_590_DEV:
	case MLUID_590V:
	case MLUID_580V:
	case MLUID_CE3226_EDGE:
	case MLUID_PIGEON_EDGE:
		break;
	default:
		cn_dev_core_err(core, "device id invalid");
	}

	/*smmu init*/
	if (mm_set->smmu_ops.smmu_init)
		(*mm_set->smmu_ops.smmu_init)(pcore, mm_set->pcie_reg_size, mm_set->pcie_reg_size);
}

void smmu_dev_reinit(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	unsigned long reg_size = 0, mem_size = 0;

	reg_size = mm_set->pcie_reg_size;
	mem_size = mm_set->pcie_mem_size;
	/*smmu init*/
	if (mm_set->smmu_ops.smmu_init)
		(*mm_set->smmu_ops.smmu_init)(pcore, reg_size, mem_size);

}
