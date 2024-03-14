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
#include "smmu_common.h"
#include "../../camb_mm.h"

#define MLU220_SMMU_VER_REG					(0xB30000)
#define MLU220_SMMU_GCR0_REG				(0xB30004)
#define MLU220_SMMU_GCR1_REG				(0xB30008)
#define MLU220_SMMU_TCR_REG					(0xB3000c)
#define MLU220_SMMU_TTBR_L_REG				(0xB30010)
#define MLU220_SMMU_TTBR_H_REG				(0xB30014)
#define MLU220_SMMU_DFBR_L_REG				(0xB30018)
#define MLU220_SMMU_DFBR_H_REG				(0xB3001c)
#define MLU220_SMMU_MAIR_L_REG				(0xB30020)
#define MLU220_SMMU_MAIR_H_REG				(0xB30024)
#define MLU220_SMMU_BPBR_L_REG				(0xB30028)
#define MLU220_SMMU_BPBR_H_REG				(0xB3002c)
#define MLU220_SMMU_BPRR_L_REG				(0xB30030)
#define MLU220_SMMU_BPRR_H_REG				(0xB30034)
#define MLU220_SMMU_BPMR_L_REG				(0xB30038)
#define MLU220_SMMU_BPMR_H_REG				(0xB3003c)
#define MLU220_SMMU_BPCR_REG				(0xB30040)
#define MLU220_SMMU_INV_REG					(0xB30044)
#define MLU220_SMMU_PTW0MR_L_REG			(0xB30048)
#define MLU220_SMMU_PTW0MR_H_REG			(0xB3004c)
#define MLU220_SMMU_PTW1MR_L_REG			(0xB30050)
#define MLU220_SMMU_PTW1MR_H_REG			(0xB30054)
#define MLU220_SMMU_PTW2MR_L_REG			(0xB30058)
#define MLU220_SMMU_PTW2MR_H_REG			(0xB3005c)
#define MLU220_SMMU_PTW3MR_L_REG			(0xB30060)
#define MLU220_SMMU_PTW3MR_H_REG			(0xB30064)
#define MLU220_SMMU_PTWCR_REG				(0xB30068)
#define MLU220_SMMU_UPDATE_CFG_REG			(0xB3006C)
#define MLU220_SMMU_DBG0_REG				(0xB30100)
#define MLU220_SMMU_DBG1_REG				(0xB30104)
#define MLU220_SMMU_DBG2_REG				(0xB30108)
#define MLU220_SMMU_DBG3_REG				(0xB3010c)
#define MLU220_SMMU_DBG4_REG				(0xB30110)
#define MLU220_SMMU_FCR_REG					(0xB30114)
#define MLU220_SMMU_FSR_REG					(0xB30118)
#define MLU220_SMMU_FRR0_L_REG				(0xB3011c)
#define MLU220_SMMU_FRR0_H_REG				(0xB30120)
#define MLU220_SMMU_FRR1_L_REG				(0xB30124)
#define MLU220_SMMU_FRR1_H_REG				(0xB30128)
#define MLU220_SMMU_FRR2_L_REG				(0xB3012c)
#define MLU220_SMMU_FRR2_H_REG				(0xB30130)
#define MLU220_SMMU_FRR3_L_REG				(0xB30134)
#define MLU220_SMMU_FRR3_H_REG				(0xB30138)
#define MLU220_SMMU_EVENT0_CTL0_REG			(0xB30200)
#define MLU220_SMMU_EVENT0_CTL1_REG			(0xB30204)
#define MLU220_SMMU_EVENT0_COUNT_REG		(0xB30208)
#define MLU220_SMMU_EVENT1_CTL0_REG			(0xB3020c)
#define MLU220_SMMU_EVENT1_CTL1_REG			(0xB30210)
#define MLU220_SMMU_EVENT1_COUNT_REG		(0xB30214)
#define MLU220_SMMU_EVENT2_CTL0_REG			(0xB30218)
#define MLU220_SMMU_EVENT2_CTL1_REG			(0xB3021c)
#define MLU220_SMMU_EVENT2_COUNT_REG		(0xB30220)
#define MLU220_SMMU_EVENT3_CTL0_REG			(0xB30224)
#define MLU220_SMMU_EVENT3_CTL1_REG			(0xB30228)
#define MLU220_SMMU_EVENT3_COUNT_REG		(0xB3022c)
#define MLU220_SMMU_EVENT4_CTL0_REG			(0xB30230)
#define MLU220_SMMU_EVENT4_CTL1_REG			(0xB30234)
#define MLU220_SMMU_EVENT4_COUNT_REG		(0xB30238)
#define MLU220_SMMU_EVENT5_CTL0_REG			(0xB3023c)
#define MLU220_SMMU_EVENT5_CTL1_REG			(0xB30240)
#define MLU220_SMMU_EVENT5_COUNT_REG		(0xB30244)
#define MLU220_SMMU_EVENT6_CTL0_REG			(0xB30248)
#define MLU220_SMMU_EVENT6_CTL1_REG			(0xB3024c)
#define MLU220_SMMU_EVENT6_COUNT_REG		(0xB30250)
#define MLU220_SMMU_EVENT7_CTL0_REG			(0xB30254)
#define MLU220_SMMU_EVENT7_CTL1_REG			(0xB30258)
#define MLU220_SMMU_EVENT7_COUNT_REG		(0xB3025c)
#define MLU220_SMMU_CAU0_CTL0_REG			(0xB30400)
#define MLU220_SMMU_CAU0_CTL1_REG			(0xB30404)
#define MLU220_SMMU_CAU0_INV_REG			(0xB30408)
#define MLU220_SMMU_CAU_CTL0_REG(n)			((MLU220_SMMU_CAU0_CTL0_REG) + ((n) * 0x10))
#define MLU220_SMMU_CAU_CTL1_REG(n)			((MLU220_SMMU_CAU0_CTL1_REG) + ((n) * 0x10))
#define MLU220_SMMU_CAU_INV_REG(n)			((MLU220_SMMU_CAU0_INV_REG) + ((n) * 0x10))


#define MLU220_REMAP_BASE_ADDR_L			(0x18000000UL)
#define MLU220_REMAP_BASE_ADDR_H			(0x10UL)

static int mlu220_smmu_pre_cau_bypass(void *pcore, unsigned int s_id, bool en)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	unsigned int reg_value;

	reg_value = reg_read32(core->bus_set, MLU220_SMMU_CAU_CTL0_REG(s_id));

	/*1 -- enable the bypass module or 0 -- disable the bypass module*/
	reg_value = en ? reg_value | (1 << 2) : reg_value & (~(1 << 2));

	reg_write32(core->bus_set, MLU220_SMMU_CAU_CTL0_REG(s_id), reg_value);

	return 0;
}

static int mlu220_smmu_pre_cau_invalid(void *pcore, unsigned int s_id)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	int i = 0;
	unsigned int reg_value;

	if (test_and_clear_bit(s_id, &mm_set->smmu_invalid_mask)) {
		reg_write32(core->bus_set, MLU220_SMMU_CAU_INV_REG(s_id), 1);
		reg_read32(core->bus_set, MLU220_SMMU_CAU_INV_REG(s_id));
		do {
			reg_value = reg_read32(core->bus_set, MLU220_SMMU_CAU_INV_REG(s_id));
			if (i++ == 50000) {
				cn_dev_core_info(core, "pcie smmu cau%d invalid timeout!", s_id);
				return -1;
			}
		} while (reg_value);
	}
	return 0;
}

static int
mlu220_smmu_init(void *pcore, dev_addr_t reg_size, dev_addr_t mem_size)
{
	unsigned int i = 0;
	unsigned int cau_cnt = 0;
	unsigned int reg_value = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	cau_cnt = reg_read32(core->bus_set, MLU220_SMMU_VER_REG) >> 8;
	cau_cnt &= 0xff;
	cn_dev_core_info(core, "C20L pcie smmu cau cnt = %d", cau_cnt);

	reg_value = (VA_SIZE << 0 | PA_SIZE << 8 | GRANULE_SIZE << 16);
	reg_write32(core->bus_set, MLU220_SMMU_TCR_REG, reg_value);
	/*invalid mode*/
	reg_write32(core->bus_set, MLU220_SMMU_GCR1_REG, 2);
	/*bar0 remapping*/
	reg_write32(core->bus_set, MLU220_SMMU_BPBR_L_REG, reg_size);
	reg_write32(core->bus_set, MLU220_SMMU_BPBR_H_REG, 0x00000080);
	reg_write32(core->bus_set, MLU220_SMMU_BPRR_L_REG, MLU220_REMAP_BASE_ADDR_L);
	reg_write32(core->bus_set, MLU220_SMMU_BPRR_H_REG, MLU220_REMAP_BASE_ADDR_H);
	reg_write32(core->bus_set, MLU220_SMMU_BPMR_L_REG, ~(mem_size - 1));
	reg_write32(core->bus_set, MLU220_SMMU_BPMR_H_REG, 0x1ffff);
	/*all cau bypass*/
	for (i = 0; i < cau_cnt; i++) {
	    reg_write32(core->bus_set, MLU220_SMMU_CAU_CTL0_REG(i), 0x04420005);
	}

	reg_write32(core->bus_set, MLU220_SMMU_PTWCR_REG, 0xf);

	reg_write32(core->bus_set, MLU220_SMMU_PTW0MR_L_REG, 0x30);
	reg_write32(core->bus_set, MLU220_SMMU_PTW1MR_L_REG, 0xc0);
	reg_write32(core->bus_set, MLU220_SMMU_PTW2MR_L_REG, 0x0f);

	reg_write32(core->bus_set, MLU220_SMMU_BPCR_REG, 0x1);
	reg_write32(core->bus_set, MLU220_SMMU_MAIR_L_REG, 0x07072222);
	reg_write32(core->bus_set, MLU220_SMMU_MAIR_H_REG, 0xffffb0b0);

	/*update and enable smmu*/
	reg_write32(core->bus_set, MLU220_SMMU_UPDATE_CFG_REG, 1);
	reg_write32(core->bus_set, MLU220_SMMU_GCR0_REG, 1);

	reg_value = reg_read32(core->bus_set, MLU220_SMMU_GCR0_REG);
	i = 0;
	while (reg_value != 1) {
		reg_value = reg_read32(core->bus_set, MLU220_SMMU_GCR0_REG);
		if (i++ == 50000) {
			cn_dev_core_err(core, "wait for pcie smmu valid timeout");
			return -1;
		}
	}

	return 0;
}

static int mlu220_smmu_release(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg_write32(core->bus_set, MLU220_SMMU_INV_REG, 1);
	reg_write32(core->bus_set, MLU220_SMMU_GCR0_REG, 0x0);

	return 0;
}


void mlu220_smmu_ops_register(void *fops)
{
	struct pcie_smmu_ops *smmu_ops = (struct pcie_smmu_ops *)fops;

	if (smmu_ops) {
		smmu_ops->smmu_init = mlu220_smmu_init;
		smmu_ops->smmu_release = mlu220_smmu_release;
		smmu_ops->smmu_cau_invalid = mlu220_smmu_pre_cau_invalid;
		smmu_ops->smmu_cau_bypass = mlu220_smmu_pre_cau_bypass;
	}
}
