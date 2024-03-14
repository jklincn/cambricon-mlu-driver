/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2021 Cambricon, Inc. All rights reserved.
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

#define CE3226_PCIE_SMMU_BASE_ADDR        (0x3b0000)
#define PCIE_SMMU_WR32(bus_set, offset, val) \
	reg_write32(bus_set, (CE3226_PCIE_SMMU_BASE_ADDR + (offset)), val)

#define PCIE_SMMU_RD32(bus_set, offset) \
	reg_read32(bus_set, (CE3226_PCIE_SMMU_BASE_ADDR + (offset)))

/*[31:16] is width, [15:0] is shift*/
#define RG_FLD(w, s)                    ((((w) & 0xFF) << 16) | ((s) & 0xFF))
#define FLD_WIDTH(fld)                  (((fld) >> 16) & 0xFF)
#define FLD_SHIFT(fld)                  ((fld) & 0xFF)
#define FLD_MASK(fld)                   \
		((__u64)((1ULL << FLD_WIDTH(fld)) - 1) << FLD_SHIFT(fld))
#define FLD_VAL_GET(fld, val)           \
		(((val) & FLD_MASK(fld)) >> (FLD_SHIFT(fld)))
/**
 *fld:[15:0] is shift
 *fld:[31:16] is width
 **/
 #define FLD_VAL_SET(fld, val)           \
		(((val) << FLD_SHIFT(fld)) & FLD_MASK(fld))

#define CE3226_REMAP_ADDR_L					(0x10000000ULL)
#define CE3226_REMAP_ADDR_H					(0x04)

#define SMMU_MODULE_ID_INFO_REG					(0xff0)
#define SMMU_DATA_INFO_REG					(0xff4)

#define CE3226_SMMU_VER_REG				(0x00)
#define CE3226_SMMU_VER_REG_SUB_VER            RG_FLD(4, 4)
#define CE3226_SMMU_VER_REG_CAU_NUM            RG_FLD(8, 8)

#define CE3226_SMMU_GCR0_REG		(0x100)
#define CE3226_SMMU_GCR1_REG		(0x104)
#define CE3226_SMMU_GCR1_REG_ALLINV_EN            RG_FLD(1, 0)
#define CE3226_SMMU_GCR1_REG_INV_MODE            RG_FLD(1, 1)
#define CE3226_SMMU_GCR1_REG_INV_LVL            RG_FLD(1, 4)
#define CE3226_SMMU_GCR1_REG_L3_CACHE_EN            RG_FLD(1, 17)
#define CE3226_SMMU_GCR1_REG_NS_MATCH_EN            RG_FLD(1, 26)

#define CE3226_SMMU_TCR_REG				(0x140)
#define CE3226_SMMU_UPDATE_CFG_REG			(0x144)

#define CE3226_SMMU_MAIR_L_REG			(0x1a8)
#define CE3226_SMMU_MAIR_H_REG			(0x1ac)

#define CE3226_SMMU_PTW0MR_L_REG			(0x1b0)
#define CE3226_SMMU_PTW0MR_H_REG			(0x1b4)
#define CE3226_SMMU_PTW1MR_L_REG			(0x1b8)
#define CE3226_SMMU_PTW1MR_H_REG			(0x1bc)
#define CE3226_SMMU_PTW2MR_L_REG			(0x1c0)
#define CE3226_SMMU_PTW2MR_H_REG			(0x1c4)
#define CE3226_SMMU_PTW3MR_L_REG			(0x1c8)
#define CE3226_SMMU_PTW3MR_H_REG			(0x1cc)
#define CE3226_SMMU_PTWCR_REG				(0x1d0)

#define CE3226_SMMU_INV0_REG			    (0x400)

#define CE3226_SMMU_RMPWIN_CTL_REG			(0x480)
#define CE3226_SMMU_RMPWIN0_BASE_L_REG		(0x484)
#define CE3226_SMMU_RMPWIN0_BASE_H_REG		(0x488)
#define CE3226_SMMU_RMPWIN0_MASK_REG			(0x48c)
#define CE3226_SMMU_RMPWIN0_REMAP_REG		(0x490)
#define CE3226_SMMU_RMPWIN_BASE_L_REG(n)	((CE3226_SMMU_RMPWIN0_BASE_L_REG) + ((n) * 0x10))
#define CE3226_SMMU_RMPWIN_BASE_H_REG(n)	((CE3226_SMMU_RMPWIN0_BASE_H_REG) + ((n) * 0x10))
#define CE3226_SMMU_RMPWIN_MASK_REG(n)		((CE3226_SMMU_RMPWIN0_MASK_REG) + ((n) * 0x10))
#define CE3226_SMMU_RMPWIN_REMAP_REG(n)		((CE3226_SMMU_RMPWIN0_REMAP_REG) + ((n) * 0x10))

#define CE3226_SMMU_CAU0_CTL_REG				(0x600)
#define CE3226_SMMU_CAU_CTL_REG(n)			((CE3226_SMMU_CAU0_CTL_REG) + ((n) * 0x04))
/*PCIE SMMU BASE OFFSET*/
static void ce3226_det_enable(void *pcore)
{
	return;
}

static int ce3226_smmu_pre_cau_bypass(void *pcore, unsigned int s_id, bool en)
{
	return 0;
}

static int ce3226_smmu_pre_cau_invalid(void *pcore, unsigned int s_id)
{
	return 0;
}

static int
ce3226_smmu_init(void *pcore, dev_addr_t reg_size, dev_addr_t mem_size)
{
	unsigned int i = 0;
	unsigned int cau_cnt = 0;
	unsigned int reg_value = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	cau_cnt = PCIE_SMMU_RD32(core->bus_set, CE3226_SMMU_VER_REG) >> 8;
	cau_cnt &= 0xff;
	cn_dev_core_info(core, "pcie smmu cau cnt = %d", cau_cnt);

	reg_value = (VA_SIZE << 0 | PA_SIZE << 8 | GRANULE_SIZE << 16);
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_TCR_REG, reg_value);
	/*invalid mode*/
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_GCR1_REG, 2);/*is correct*/
	/*bar0 remapping*/
	/*VA :[47:44] set base_h, [43:12] set base_l; [11:0] is align by hardware*/
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_RMPWIN_BASE_L_REG(0),
				((CE3226_AXI_SHM_BASE >> 12) & U32_MAX));
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_RMPWIN_BASE_H_REG(0),
				(CE3226_AXI_SHM_BASE >> 44));
	/*PA*/
	reg_value = (CE3226_REMAP_ADDR_L >> 12) | (CE3226_REMAP_ADDR_H << 20);
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_RMPWIN_REMAP_REG(0), reg_value);
	/*size*/
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_RMPWIN_MASK_REG(0),
				~(mem_size - 1) >> 12);

	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_RMPWIN_CTL_REG, 0x1);

	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_CAU_CTL_REG(0), 0x01020319);
	/*enable bypass all cau*/
	for (i = 1; i < cau_cnt; i++) {
		PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_CAU_CTL_REG(i), 0x01020319);
	}

	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_PTWCR_REG, 0xF);
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_PTW0MR_L_REG, 0x03);
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_PTW1MR_L_REG, 0x1c);
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_PTW2MR_L_REG, 0xe0);

	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_MAIR_L_REG, 0x07072222);
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_MAIR_H_REG, 0xffffb0b0);

	/*update and enable smmu*/
	cn_dev_core_info(core, "update and enable smmu...");
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_UPDATE_CFG_REG, 1);
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_GCR0_REG, 1);

	reg_value = PCIE_SMMU_RD32(core->bus_set, CE3226_SMMU_GCR0_REG);
	i = 0;
	while (reg_value != 1) {
		reg_value = PCIE_SMMU_RD32(core->bus_set, CE3226_SMMU_GCR0_REG);
		if (i++ == 50000) {
			cn_dev_core_err(core, "wait for pcie smmu valid timeout");
			return -1;
		}
	}

	ce3226_det_enable(core);

	return 0;
}

static int ce3226_smmu_release(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_INV0_REG, 1);
	PCIE_SMMU_WR32(core->bus_set, CE3226_SMMU_GCR0_REG, 0x0);

	return 0;
}

void ce3226_smmu_ops_register(void *fops)
{
	struct pcie_smmu_ops *smmu_ops = (struct pcie_smmu_ops *)fops;

	if (smmu_ops) {
		smmu_ops->smmu_init = ce3226_smmu_init;
		smmu_ops->smmu_release = ce3226_smmu_release;
		smmu_ops->smmu_cau_invalid = ce3226_smmu_pre_cau_invalid;
		smmu_ops->smmu_cau_bypass = ce3226_smmu_pre_cau_bypass;
	}
}

