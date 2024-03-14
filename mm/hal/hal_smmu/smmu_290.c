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

#define MLU290_SMMU_VER_REG					(0x1c0000)
#define MLU290_SMMU_GCR0_REG				(0x1c0004)
#define MLU290_SMMU_GCR1_REG				(0x1c0008)
#define MLU290_SMMU_TCR_REG					(0x1c000c)
#define MLU290_SMMU_TTBR_L_REG				(0x1c0010)
#define MLU290_SMMU_TTBR_H_REG				(0x1c0014)
#define MLU290_SMMU_DFBR_L_REG				(0x1c0018)
#define MLU290_SMMU_DFBR_H_REG				(0x1c001c)
#define MLU290_SMMU_MAIR_L_REG				(0x1c0020)
#define MLU290_SMMU_MAIR_H_REG				(0x1c0024)
#define MLU290_SMMU_BPBR_L_REG				(0x1c0028)
#define MLU290_SMMU_BPBR_H_REG				(0x1c002c)
#define MLU290_SMMU_BPRR_L_REG				(0x1c0030)
#define MLU290_SMMU_BPRR_H_REG				(0x1c0034)
#define MLU290_SMMU_BPMR_L_REG				(0x1c0038)
#define MLU290_SMMU_BPMR_H_REG				(0x1c003c)
#define MLU290_SMMU_BPCR_REG				(0x1c0040)
#define MLU290_SMMU_INV_REG					(0x1c0044)
#define MLU290_SMMU_PTW0MR_L_REG			(0x1c0048)
#define MLU290_SMMU_PTW0MR_H_REG			(0x1c004c)
#define MLU290_SMMU_PTW1MR_L_REG			(0x1c0050)
#define MLU290_SMMU_PTW1MR_H_REG			(0x1c0054)
#define MLU290_SMMU_PTW2MR_L_REG			(0x1c0058)
#define MLU290_SMMU_PTW2MR_H_REG			(0x1c005c)
#define MLU290_SMMU_PTW3MR_L_REG			(0x1c0060)
#define MLU290_SMMU_PTW3MR_H_REG			(0x1c0064)
#define MLU290_SMMU_PTWCR_REG				(0x1c0068)
#define MLU290_SMMU_UPDATE_CFG_REG			(0x1c006C)
#define MLU290_SMMU_DBG0_REG				(0x1c0100)
#define MLU290_SMMU_DBG1_REG				(0x1c0104)
#define MLU290_SMMU_DBG2_REG				(0x1c0108)
#define MLU290_SMMU_DBG3_REG				(0x1c010c)
#define MLU290_SMMU_DBG4_REG				(0x1c0110)
#define MLU290_SMMU_FCR_REG					(0x1c0114)
#define MLU290_SMMU_FSR_REG					(0x1c0118)
#define MLU290_SMMU_FRR0_L_REG				(0x1c011c)
#define MLU290_SMMU_FRR0_H_REG				(0x1c0120)
#define MLU290_SMMU_FRR1_L_REG				(0x1c0124)
#define MLU290_SMMU_FRR1_H_REG				(0x1c0128)
#define MLU290_SMMU_FRR2_L_REG				(0x1c012c)
#define MLU290_SMMU_FRR2_H_REG				(0x1c0130)
#define MLU290_SMMU_FRR3_L_REG				(0x1c0134)
#define MLU290_SMMU_FRR3_H_REG				(0x1c0138)
#define MLU290_SMMU_EVENT0_CTL0_REG			(0x1c0200)
#define MLU290_SMMU_EVENT0_CTL1_REG			(0x1c0204)
#define MLU290_SMMU_EVENT0_COUNT_REG		(0x1c0208)
#define MLU290_SMMU_EVENT1_CTL0_REG			(0x1c020c)
#define MLU290_SMMU_EVENT1_CTL1_REG			(0x1c0210)
#define MLU290_SMMU_EVENT1_COUNT_REG		(0x1c0214)
#define MLU290_SMMU_EVENT2_CTL0_REG			(0x1c0218)
#define MLU290_SMMU_EVENT2_CTL1_REG			(0x1c021c)
#define MLU290_SMMU_EVENT2_COUNT_REG		(0x1c0220)
#define MLU290_SMMU_EVENT3_CTL0_REG			(0x1c0224)
#define MLU290_SMMU_EVENT3_CTL1_REG			(0x1c0228)
#define MLU290_SMMU_EVENT3_COUNT_REG		(0x1c022c)
#define MLU290_SMMU_EVENT4_CTL0_REG			(0x1c0230)
#define MLU290_SMMU_EVENT4_CTL1_REG			(0x1c0234)
#define MLU290_SMMU_EVENT4_COUNT_REG		(0x1c0238)
#define MLU290_SMMU_EVENT5_CTL0_REG			(0x1c023c)
#define MLU290_SMMU_EVENT5_CTL1_REG			(0x1c0240)
#define MLU290_SMMU_EVENT5_COUNT_REG		(0x1c0244)
#define MLU290_SMMU_EVENT6_CTL0_REG			(0x1c0248)
#define MLU290_SMMU_EVENT6_CTL1_REG			(0x1c024c)
#define MLU290_SMMU_EVENT6_COUNT_REG		(0x1c0250)
#define MLU290_SMMU_EVENT7_CTL0_REG			(0x1c0254)
#define MLU290_SMMU_EVENT7_CTL1_REG			(0x1c0258)
#define MLU290_SMMU_EVENT7_COUNT_REG		(0x1c025c)
#define MLU290_SMMU_CAU0_CTL0_REG			(0x1c0400)
#define MLU290_SMMU_CAU0_CTL1_REG			(0x1c0404)
#define MLU290_SMMU_CAU0_INV_REG			(0x1c0408)
#define MLU290_SMMU_CAU_CTL0_REG(n)			((MLU290_SMMU_CAU0_CTL0_REG) + ((n) * 0x10))
#define MLU290_SMMU_CAU_CTL1_REG(n)			((MLU290_SMMU_CAU0_CTL1_REG) + ((n) * 0x10))
#define MLU290_SMMU_CAU_INV_REG(n)			((MLU290_SMMU_CAU0_INV_REG) + ((n) * 0x10))


#define MLU290_REMAP_BASE_ADDR_L			(0x08000000)
#define MLU290_REMAP_BASE_ADDR_H			(0x38)

#define VFWIN_REG_INTERVAL	(0x10)

int mlu290_smmu_pre_cau_bypass(void *pcore, unsigned int s_id, bool en)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	unsigned int reg_value;

	reg_value = reg_read32(core->bus_set, MLU290_SMMU_CAU_CTL0_REG(s_id));

	/*1 -- enable the bypass module or 0 -- disable the bypass module*/
	reg_value = en ? reg_value | (1 << 2) : reg_value & (~(1 << 2));

	reg_write32(core->bus_set, MLU290_SMMU_CAU_CTL0_REG(s_id), reg_value);

	return 0;
}

int mlu290_smmu_pre_cau_invalid(void *pcore, unsigned int s_id)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	int i = 0;
	unsigned int reg_value;

	if (test_and_clear_bit(s_id, &mm_set->smmu_invalid_mask)) {
		reg_write32(core->bus_set, MLU290_SMMU_CAU_INV_REG(s_id), 1);
		reg_read32(core->bus_set, MLU290_SMMU_CAU_INV_REG(s_id));
		do {
			reg_value = reg_read32(core->bus_set, MLU290_SMMU_CAU_INV_REG(s_id));
			if (i++ == 50000) {
				cn_dev_core_info(core, "pcie smmu cau%d invalid timeout!", s_id);
				return -1;
			}
		} while (reg_value);
	}
	return 0;
}

int mlu290_smmu_init(void *pcore, dev_addr_t reg_size, dev_addr_t mem_size)
{
	unsigned int i = 0;
	unsigned int cau_cnt = 0;
	unsigned int reg_value = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	cau_cnt = reg_read32(core->bus_set, MLU290_SMMU_VER_REG) >> 8;
	cau_cnt &= 0xff;
	cn_dev_core_info(core, "C20L pcie smmu cau cnt = %d", cau_cnt);

	reg_value = (VA_SIZE << 0 | PA_SIZE << 8 | GRANULE_SIZE << 16);
	reg_write32(core->bus_set, MLU290_SMMU_TCR_REG, reg_value);
	/*invalid mode*/
	reg_write32(core->bus_set, MLU290_SMMU_GCR1_REG, 2);
	/*bar0 remapping*/
	reg_write32(core->bus_set, MLU290_SMMU_BPBR_L_REG, reg_size);
	reg_write32(core->bus_set, MLU290_SMMU_BPBR_H_REG, 0x00000080);
	reg_write32(core->bus_set, MLU290_SMMU_BPRR_L_REG, MLU290_REMAP_BASE_ADDR_L);
	reg_write32(core->bus_set, MLU290_SMMU_BPRR_H_REG, MLU290_REMAP_BASE_ADDR_H);
	reg_write32(core->bus_set, MLU290_SMMU_BPMR_L_REG, ~(mem_size - 1));
	reg_write32(core->bus_set, MLU290_SMMU_BPMR_H_REG, 0x1ffff);
	/*all cau bypass*/
	for (i = 0; i < cau_cnt; i++) {
	    reg_write32(core->bus_set, MLU290_SMMU_CAU_CTL0_REG(i), 0x04420005);
	}

	reg_write32(core->bus_set, MLU290_SMMU_PTWCR_REG, 0xf);

	reg_write32(core->bus_set, MLU290_SMMU_PTW0MR_L_REG, 0x30);
	reg_write32(core->bus_set, MLU290_SMMU_PTW1MR_L_REG, 0xc0);
	reg_write32(core->bus_set, MLU290_SMMU_PTW2MR_L_REG, 0x0f);

	reg_write32(core->bus_set, MLU290_SMMU_BPCR_REG, 0x1);
	reg_write32(core->bus_set, MLU290_SMMU_MAIR_L_REG, 0x07072222);
	reg_write32(core->bus_set, MLU290_SMMU_MAIR_H_REG, 0xffffb0b0);

	/*update and enable smmu*/
	reg_write32(core->bus_set, MLU290_SMMU_UPDATE_CFG_REG, 1);
	reg_write32(core->bus_set, MLU290_SMMU_GCR0_REG, 1);

	reg_value = reg_read32(core->bus_set, MLU290_SMMU_GCR0_REG);
	i = 0;
	while (reg_value != 1) {
		reg_value = reg_read32(core->bus_set, MLU290_SMMU_GCR0_REG);
		if (i++ == 50000) {
			cn_dev_core_err(core, "wait for pcie smmu valid timeout");
			return -1;
		}
	}

	return 0;
}

int mlu290_smmu_release(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg_write32(core->bus_set, MLU290_SMMU_INV_REG, 1);
	reg_write32(core->bus_set, MLU290_SMMU_GCR0_REG, 0x0);

	return 0;
}


void mlu290_smmu_ops_register(void *fops)
{
	struct pcie_smmu_ops *smmu_ops = (struct pcie_smmu_ops *)fops;

	if (smmu_ops) {
		smmu_ops->smmu_init = mlu290_smmu_init;
		smmu_ops->smmu_release = mlu290_smmu_release;
		smmu_ops->smmu_cau_invalid = mlu290_smmu_pre_cau_invalid;
		smmu_ops->smmu_cau_bypass = mlu290_smmu_pre_cau_bypass;
	}
}
