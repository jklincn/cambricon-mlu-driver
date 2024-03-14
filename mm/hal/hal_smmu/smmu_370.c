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

/*PCIE SMMU BASE OFFSET*/
#define MLU370_PCIE_SMMU_BASE_ADDR			(0x100000)
/**/
#define MLU370_SMMU_VER_REG					(0x100000)
#define MLU370_SMMU_GCR0_REG				(0x100004)
#define MLU370_SMMU_GCR1_REG				(0x100008)
#define MLU370_SMMU_GCR2_REG				(0x10000c)
#define MLU370_SMMU_GCR3_REG				(0x100010)
#define MLU370_SMMU_GCR4_REG				(0x100014)
#define MLU370_SMMU_GCR5_REG				(0x100018)
#define MLU370_SMMU_GCR6_REG				(0x10001c)
#define MLU370_SMMU_GCR7_REG				(0x100020)
#define MLU370_SMMU_TCR_REG					(0x100024)
#define MLU370_SMMU_TTBR0_ADDR_REG			(0x100028)
#define MLU370_SMMU_TTBR0_CTL_REG			(0x10002c)
#define MLU370_SMMU_TTBR_ADDR_REG(n)		((MLU370_SMMU_TTBR0_ADDR_REG) + ((n)*0x08))
#define MLU370_SMMU_TTBR_CTL_REG(n)			((MLU370_SMMU_TTBR0_CTL_REG) + ((n)*0x08))
#define MLU370_SMMU_DFBR_L_REG				(0x100070)
#define MLU370_SMMU_DFBR_H_REG				(0x100074)
#define MLU370_SMMU_MAIR_L_REG				(0x100078)
#define MLU370_SMMU_MAIR_H_REG				(0x10007c)
#define MLU370_SMMU_PTW0MR_L_REG			(0x100080)
#define MLU370_SMMU_PTW0MR_H_REG			(0x100084)
#define MLU370_SMMU_PTW1MR_L_REG			(0x100088)
#define MLU370_SMMU_PTW1MR_H_REG			(0x10008c)
#define MLU370_SMMU_PTW2MR_L_REG			(0x100090)
#define MLU370_SMMU_PTW2MR_H_REG			(0x100094)
#define MLU370_SMMU_PTW3MR_L_REG			(0x100098)
#define MLU370_SMMU_PTW3MR_H_REG			(0x10009c)
#define MLU370_SMMU_PTWCR_REG				(0x1000a0)
#define MLU370_SMMU_UPDATE_CFG_REG			(0x1000a4)
/**/
#define MLU370_SMMU_STALL_REG				(0x1000c0)
#define MLU370_SMMU_WIDLE_REG				(0x1000d0)
#define MLU370_SMMU_TIMEOUT_THRESH_REG		(0x1000d4)
#define MLU370_SMMU_INV0_REG			    (0x1000e0)
#define MLU370_SMMU_INV1_REG			    (0x1000e4)
#define MLU370_SMMU_INV2_REG			    (0x1000e8)
#define MLU370_SMMU_CLEAN0_REG				(0x1000f0)
#define MLU370_SMMU_CLEAN1_REG				(0x1000f4)
#define MLU370_SMMU_CLEAN2_REG				(0x1000f8)
/*remap windows*/
#define MLU370_SMMU_RMPWIN_CTL_REG			(0x100100)
#define MLU370_SMMU_RMPWIN0_BASE_L_REG		(0x100110)
#define MLU370_SMMU_RMPWIN0_BASE_H_REG		(0x100114)
#define MLU370_SMMU_RMPWIN0_MASK_REG		(0x100118)
#define MLU370_SMMU_RMPWIN0_REMAP_REG		(0x10011c)
#define MLU370_SMMU_RMPWIN_BASE_L_REG(n)	((MLU370_SMMU_RMPWIN0_BASE_L_REG) + ((n) * 0x10))
#define MLU370_SMMU_RMPWIN_BASE_H_REG(n)	((MLU370_SMMU_RMPWIN0_BASE_H_REG) + ((n) * 0x10))
#define MLU370_SMMU_RMPWIN_MASK_REG(n)		((MLU370_SMMU_RMPWIN0_MASK_REG) + ((n) * 0x10))
#define MLU370_SMMU_RMPWIN_REMAP_REG(n)		((MLU370_SMMU_RMPWIN0_REMAP_REG) + ((n) * 0x10))
/*event*/
#define MLU370_SMMU_EVENT_CTL0_REG			(0x100300)
#define MLU370_SMMU_EVENT_CTL1_REG			(0x100304)
#define MLU370_SMMU_EVENT0_CTL_REG			(0x100308)
#define MLU370_SMMU_EVENT0_COUNT_L_REG		(0x10030c)
#define MLU370_SMMU_EVENT0_COUNT_H_REG		(0x100310)
#define MLU370_SMMU_EVENT_CTL_REG(n)		((MLU370_SMMU_EVENT0_CTL_REG) + ((n) * 0x0c))
#define MLU370_SMMU_EVENT_COUNT_L_REG(n)	((MLU370_SMMU_EVENT0_COUNT_L_REG) + ((n) * 0x0c))
#define MLU370_SMMU_EVENT_COUNT_H_REG(n)	((MLU370_SMMU_EVENT0_COUNT_H_REG) + ((n) * 0x0c))
/*smmu irq fault*/
#define MLU370_SMMU_FAULT_MASK_REG			(0x100400)
#define MLU370_SMMU_FAULT_SATUS_REG			(0x100404)
#define MLU370_SMMU_FAULT_MASK_STATUS_REG	(0x100408)
#define MLU370_SMMU_FAULT_CLEAR_REG			(0x10040c)
#define MLU370_SMMU_FAULT_INFO0_L_REG		(0x100410)
#define MLU370_SMMU_FAULT_INFO0_H_REG		(0x100414)
#define MLU370_SMMU_FAULT_INFO_L_REG(n)		((MLU370_SMMU_FAULT_INFO0_L_REG) + ((n) * 0x08))
#define MLU370_SMMU_FAULT_INFO_H_REG(n)		((MLU370_SMMU_FAULT_INFO0_H_REG) + ((n) * 0x08))
/*dbg*/
#define MLU370_SMMU_DBG0_REG				(0x100500)
#define MLU370_SMMU_DBG1_REG				(0x100504)
#define MLU370_SMMU_DBG2_REG				(0x100508)
#define MLU370_SMMU_DBG3_REG				(0x10050c)
#define MLU370_SMMU_DBG4_REG				(0x100510)
/*cau*/
#define MLU370_SMMU_CAU0_CTL_REG			(0x100600)
#define MLU370_SMMU_CAU_CTL_REG(n)			\
	((MLU370_SMMU_CAU0_CTL_REG) + ((n) * 0x04))

#define SMMU_INV_BITS_L (0x20)
#define SMMU_INV_BITS_H (0x10)
#define SMMU_INV_MASK_L (SMMU_INV_BITS_L - 1)
#define SMMU_INV_MASK_H (SMMU_INV_BITS_H - 1)

static void mlu370_det_enable(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	/* The DET register is defaultly disable when it's mlu370.
	 * So it should to be enable in the initialization phase.
	 */
	reg_write32(core->bus_set, 0x8340448, 0x30);
}

static int mlu370_smmu_pre_cau_bypass(void *pcore, unsigned int s_id, bool en)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	unsigned int reg_value;

	reg_value = reg_read32(core->bus_set, MLU370_SMMU_CAU_CTL_REG(s_id));

	/*1 -- enable the bypass module or 0 -- disable the bypass module*/
	reg_value = en ? reg_value | (1 << 0) : reg_value & (~(1 << 0));

	reg_write32(core->bus_set, MLU370_SMMU_CAU_CTL_REG(s_id), reg_value);

	return 0;
}

static int mlu370_smmu_pre_cau_invalid(void *pcore, unsigned int s_id)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	unsigned int reg = 0UL, val = 0UL;
	unsigned int reg_value;
	int i = 0;

	if (s_id & ~(SMMU_INV_MASK_L)) {	/* s_id input is bigger than INV1_NUMS */
		reg = MLU370_SMMU_INV2_REG;
		val = (s_id - SMMU_INV_BITS_L) & SMMU_INV_MASK_H;
	} else {
		reg = MLU370_SMMU_INV1_REG;
		val = s_id & SMMU_INV_MASK_L;
	}

	if (test_and_clear_bit(s_id, &mm_set->smmu_invalid_mask)) {
		reg_write32(core->bus_set, reg, val);
		reg_read32(core->bus_set, reg);
		do {
			reg_value = reg_read32(core->bus_set, reg);
			if (i++ == 50000) {
				cn_dev_core_info(core,
					"wait for pcie smmu valid timeout, id=%d", s_id);
				return -1;
			}
		} while (reg_value & val);
	}

	return 0;
}

/* the effort is same as release function */
static int mlu370_smmu_reset(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg_write32(core->bus_set, MLU370_SMMU_INV0_REG, 1);
	reg_write32(core->bus_set, MLU370_SMMU_GCR0_REG, 0x0);

	return 0;
}

static int
mlu370_smmu_init(void *pcore, dev_addr_t reg_size, dev_addr_t mem_size)
{
	unsigned int i = 0;
	unsigned int cau_cnt = 0;
	unsigned int reg_value = 0;
	dev_addr_t cfg_size = 0;
	dev_addr_t shm_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	cau_cnt = reg_read32(core->bus_set, MLU370_SMMU_VER_REG) >> 8;
	cau_cnt &= 0xff;
	cn_dev_core_info(core, "pcie smmu cau cnt = %d", cau_cnt);

	/* FIX (VIRTUAL-405): to disable pcie smmu to restore to the default status */
	mlu370_smmu_reset(core);

	reg_value = (VA_SIZE << 0 | PA_SIZE << 8 | GRANULE_SIZE << 16);
	reg_write32(core->bus_set, MLU370_SMMU_TCR_REG, reg_value);
	/*invalid mode*/
	reg_write32(core->bus_set, MLU370_SMMU_GCR1_REG, 2);/*is correct*/
	/* bar0 remapping: remap0 is set as config window, and remap1 is set
	 * as share memory window. To make sure that the configurations of remap0/remap1
	 * are same as the arm's. */
	/*VA :[47:44] set base_h, [43:12] set base_l; [11:0] is align by hardware*/
	/* VA of config window */
	reg_write32(core->bus_set, MLU370_SMMU_RMPWIN_BASE_L_REG(0), 0x8000000);
	reg_write32(core->bus_set, MLU370_SMMU_RMPWIN_BASE_H_REG(0), 0x0);
	/* PA of config window */
	reg_write32(core->bus_set, MLU370_SMMU_RMPWIN_REMAP_REG(0), 0x8000000);
	/* size of config window */
	cfg_size = 0x20000000;
	reg_write32(core->bus_set, MLU370_SMMU_RMPWIN_MASK_REG(0),
				~(cfg_size - 1) >> 12);

	/* VA of share memory window */
	reg_write32(core->bus_set, MLU370_SMMU_RMPWIN_BASE_L_REG(1),
				((C30S_AXI_SHM_BASE >> 12) & U32_MAX));
	reg_write32(core->bus_set, MLU370_SMMU_RMPWIN_BASE_H_REG(1),
				(C30S_AXI_SHM_BASE >> 44));
	/*PA of share memory window */
	reg_write32(core->bus_set, MLU370_SMMU_RMPWIN_REMAP_REG(1), C30S_AXI_SHM_PA_BASE >> 12);
	/*size of share memory window */
	shm_size = mem_size;
	reg_write32(core->bus_set, MLU370_SMMU_RMPWIN_MASK_REG(1),
				~(shm_size - 1) >> 12);

	/* enable remap0/1 windows */
	reg_write32(core->bus_set, MLU370_SMMU_RMPWIN_CTL_REG, 0x3);
	/*cau0(bar0) disable bypass*/
	cn_dev_core_info(core, "PCIE SMMU: to set all_cau as bypass mode except bar0");

	reg_write32(core->bus_set, MLU370_SMMU_CAU_CTL_REG(0), 0x04020408);

	/*enable bypass because bar!*/
	for (i = 1; i < cau_cnt; i++) {
	    reg_write32(core->bus_set, MLU370_SMMU_CAU_CTL_REG(i), 0x04020409);
	}

	reg_write32(core->bus_set, MLU370_SMMU_PTWCR_REG, 0x02020227);
	reg_write32(core->bus_set, MLU370_SMMU_PTW0MR_L_REG, 0x30);
	reg_write32(core->bus_set, MLU370_SMMU_PTW1MR_L_REG, 0xc0);
	reg_write32(core->bus_set, MLU370_SMMU_PTW2MR_L_REG, 0x0f);

	reg_write32(core->bus_set, MLU370_SMMU_MAIR_L_REG, 0x07072222);
	reg_write32(core->bus_set, MLU370_SMMU_MAIR_H_REG, 0xffffb0b0);

	/*update and enable smmu*/
	cn_dev_core_info(core, "update and enable smmu...");
	reg_write32(core->bus_set, MLU370_SMMU_UPDATE_CFG_REG, 1);
	reg_write32(core->bus_set, MLU370_SMMU_GCR0_REG, 1);

	reg_value = reg_read32(core->bus_set, MLU370_SMMU_GCR0_REG);
	i = 0;
	while (reg_value != 1) {
		reg_value = reg_read32(core->bus_set, MLU370_SMMU_GCR0_REG);
		if (i++ == 50000) {
			cn_dev_core_err(core, "wait for pcie smmu valid timeout");
			return -1;
		}
	}

	mlu370_det_enable(core);

	return 0;
}

static int mlu370_smmu_release(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg_write32(core->bus_set, MLU370_SMMU_INV0_REG, 1);
	reg_write32(core->bus_set, MLU370_SMMU_GCR0_REG, 0x0);

	return 0;
}

void mlu370_smmu_ops_register(void *fops)
{
	struct pcie_smmu_ops *smmu_ops = (struct pcie_smmu_ops *)fops;

	if (smmu_ops) {
		smmu_ops->smmu_init = mlu370_smmu_init;
		smmu_ops->smmu_release = mlu370_smmu_release;
		smmu_ops->smmu_cau_invalid = mlu370_smmu_pre_cau_invalid;
		smmu_ops->smmu_cau_bypass = mlu370_smmu_pre_cau_bypass;
	}
}

