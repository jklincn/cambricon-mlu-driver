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
#include "cndrv_udvm_usr.h"
#include "smmu_common.h"
#include "../../camb_mm.h"

/*PCIE SMMU BASE OFFSET*/
#define MLU590_PCIE_SMMU_BASE_ADDR          (0x50000)

/*Reg list begin*/
#define MLU590_SMMU_VER_REG					    (0x50000)
#define MLU590_SMMU_TBU_VER0				    (0x50004)
#define MLU590_SMMU_TBU_VER1				    (0x50008)
#define MLU590_SMMU_TBU_VER2				    (0x5000c)
#define MLU590_SMMU_TBU_VER3				    (0x50010)
#define MLU590_SMMU_ATTR0					    (0x50014)
#define MLU590_SMMU_GCR0_REG				    (0x50100)
#define MLU590_SMMU_GCR1_REG				    (0x50104)
#define MLU590_SMMU_GCR2_REG				    (0x50108)
#define MLU590_SMMU_GCR3_REG				    (0x5010c)
#define MLU590_SMMU_GCR4_REG				    (0x50110)
#define MLU590_SMMU_GCR5_REG				    (0x50114)
#define MLU590_SMMU_GCR6_REG				    (0x50118)
#define MLU590_SMMU_GCR7_REG				    (0x5011c)
#define MLU590_SMMU_GCR8_REG				    (0x50120)
#define MLU590_SMMU_GCR9_REG				    (0x50124)
#define MLU590_SMMU_GCR10_REG				    (0x50128)
#define MLU590_SMMU_GCR11_REG				    (0x5012c)
#define MLU590_SMMU_GCR12_REG				    (0x50130)
#define MLU590_SMMU_GCR13_REG				    (0x50134)
#define MLU590_SMMU_GCR14_REG				    (0x50138)
#define MLU590_SMMU_GCR15_REG				    (0x5013c)
#define MLU590_SMMU_TCR_REG					    (0x50140)
#define MLU590_SMMU_UPDATE_CFG_REG			    (0x50144)
#define MLU590_SMMU_TTBR0_ADDR_REG			    (0x50150)
#define MLU590_SMMU_TTBR0_CTL_REG			    (0x50154)
#define MLU590_SMMU_TTBR_ADDR_REG(n)		    ((MLU590_SMMU_TTBR0_ADDR_REG) + ((n) *	0x08))
#define MLU590_SMMU_TTBR_CTL_REG(n)			    ((MLU590_SMMU_TTBR0_CTL_REG) + ((n)  *	0x08))

#define MLU590_SMMU_DFBR_L_REG				    (0x501a0)
#define MLU590_SMMU_DFBR_H_REG				    (0x501a4)
#define MLU590_SMMU_MAIR_L_REG				    (0x501a8)
#define MLU590_SMMU_MAIR_H_REG				    (0x501ac)
#define MLU590_SMMU_PTW0MR_L_REG			    (0x501b0)
#define MLU590_SMMU_PTW0MR_H_REG			    (0x501b4)
#define MLU590_SMMU_PTW1MR_L_REG			    (0x501b8)
#define MLU590_SMMU_PTW1MR_H_REG			    (0x501bc)
#define MLU590_SMMU_PTW2MR_L_REG			    (0x501c0)
#define MLU590_SMMU_PTW2MR_H_REG			    (0x501c4)
#define MLU590_SMMU_PTW3MR_L_REG			    (0x501c8)
#define MLU590_SMMU_PTW3MR_H_REG			    (0x501cc)
#define MLU590_SMMU_PTWCR_REG				    (0x501d0)
#define MLU590_SMMU_PTWSECU_REG				    (0x501d4)
#define MLU590_SMMU_TIMEOUT_THRESH_REG		    (0x501d8)
#define MLU590_SMMU_PTWCR_SUP_REG			    (0x501d8)
#define MLU590_SMMU_SPF_CFG3_L_REG			    (0x501e0)
#define MLU590_SMMU_SPF_CFG3_H_REG			    (0x501e4)

#define MLU590_SMMU_TBU_CTL0_REG			    (0x50200)
#define MLU590_SMMU_TBU_CTL_REG(n)			    ((MLU590_SMMU_TBU_CTL0_REG) + ((n) * 0x04))

#define MLU590_SMMU_STALL_REG					(0x50280)
#define MLU590_SMMU_CLEAN0_REG					(0x50284)
#define MLU590_SMMU_CLEAN1_REG					(0x50288)
#define MLU590_SMMU_CLEAN2_REG					(0x5028c)
#define MLU590_SMMU_L3_TAGRAM_PAR_INJECT_REG	(0x50300)
#define MLU590_SMMU_L3_DATARAM_PAR_INJECT_REG	(0x50304)
#define MLU590_SMMU_TLBSRAM_PAR_INJECT_REG		(0x50310)
#define MLU590_SMMU_PTWSRAM_PAR_INJECT_REG		(0x50314)
#define MLU590_SMMU_SRAM_PAR_INJECT_NUM_REG		(0x50318)
#define MLU590_SMMU_WIDLE_REG					(0x50380)
#define MLU590_SMMU_INV0_REG					(0x50400)
#define MLU590_SMMU_INV1_REG					(0x50404)
#define MLU590_SMMU_INV2_REG					(0x50408)
#define MLU590_SMMU_SPF_CFG0_REG				(0x50410)
#define MLU590_SMMU_SPF_CFG1_REG				(0x50414)
#define MLU590_SMMU_SPF_CFG2_REG				(0x50418)
#define MLU590_SMMU_SPF_TRIG_REG				(0x5041c)
#define MLU590_SMMU_SPF_CFG3_REG				(0x50420)
#define MLU590_SMMU_INV_FLAG0_REG				(0x50430)
#define MLU590_SMMU_INV_FLAG1_REG				(0x50434)
#define MLU590_SMMU_DBG_INV_FLAG0_REG			(0x50438)
#define MLU590_SMMU_DBG_INV_FLAG1_REG			(0x5043c)
#define MLU590_SMMU_RMPWIN_CTL_REG				(0x50480)
#define MLU590_SMMU_RMPWIN0_BASE_L_REG			(0x50484)
#define MLU590_SMMU_RMPWIN0_BASE_H_REG			(0x50488)
#define MLU590_SMMU_RMPWIN0_MASK_REG			(0x5048c)
#define MLU590_SMMU_RMPWIN0_REMAP_REG			(0x50490)
#define MLU590_SMMU_RMPWIN_BASE_L_REG(n)		((MLU590_SMMU_RMPWIN0_BASE_L_REG) + ((n) * 0x10))
#define MLU590_SMMU_RMPWIN_BASE_H_REG(n)		((MLU590_SMMU_RMPWIN0_BASE_H_REG) + ((n) * 0x10))
#define MLU590_SMMU_RMPWIN_MASK_REG(n)			((MLU590_SMMU_RMPWIN0_MASK_REG) + ((n) * 0x10))
#define MLU590_SMMU_RMPWIN_REMAP_REG(n)			((MLU590_SMMU_RMPWIN0_REMAP_REG) + ((n) * 0x10))
/*CAU cfg*/
#define MLU590_SMMU_CAU0_CTL_REG				(0x50700)
#define MLU590_SMMU_CAU_CTL_REG(n)				((MLU590_SMMU_CAU0_CTL_REG) + ((n) * 0x04))
#define MLU590_SMMU_CAU0_CTL_SUP_REG			(0x50800)
#define MLU590_SMMU_CAU_CTL_SUP_REG(n)			((MLU590_SMMU_CAU0_CTL_SUP_REG) + ((n) * 0x04))

#define MLU590_SMMU_AXCACHE_REP_EN_L_REG		(0x50900)
#define MLU590_SMMU_AXCACHE_REP_EN_H_REG		(0x50904)
#define MLU590_SMMU_STREAM0_REP_AXCACHE_REG		(0x50910)
#define MLU590_SMMU_STREAM_REP_AXCACHE_REG(n)	((MLU590_SMMU_STREAM0_REP_AXCACHE_REG) + ((n) * 0x04))

#define MLU590_SMMU_TRAP_FUNC0_REG			(0x50a80)
#define MLU590_SMMU_TRAP_FUNC_REG(n)		((MLU590_SMMU_TRAP_FUNC0_REG) + ((n) * 0x04))

#define MLU590_SMMU_EVENT_CTL0_REG			(0x50b00)
#define MLU590_SMMU_EVENT_CTL1_REG			(0x50b04)

#define MLU590_SMMU_EVENT0_CTL_REG			(0x50b08)
#define MLU590_SMMU_EVENT0_COUNT_L_REG		(0x50b0c)
#define MLU590_SMMU_EVENT0_COUNT_H_REG		(0x50b10)
#define MLU590_SMMU_EVENT_CTL_REG(n)		((MLU590_SMMU_EVENT0_CTL_REG) + ((n) * 0x0c))
#define MLU590_SMMU_EVENT_COUNT_L_REG(n)	((MLU590_SMMU_EVENT0_COUNT_L_REG) + ((n) * 0x0c))
#define MLU590_SMMU_EVENT_COUNT_H_REG(n)	((MLU590_SMMU_EVENT0_COUNT_H_REG) + ((n) * 0x0c))

#define MLU590_SMMU_FAULT_MASK_REG			(0x50c00)
#define MLU590_SMMU_FAULT_SATUS_REG			(0x50c04)
#define MLU590_SMMU_FAULT_MASK_STATUS_REG	(0x50c08)
#define MLU590_SMMU_FAULT_CLEAR_REG			(0x50c0c)
#define MLU590_SMMU_FAULT_INFO0_L_REG		(0x50c10)
#define MLU590_SMMU_FAULT_INFO0_H_REG		(0x50c14)
#define MLU590_SMMU_FAULT_INFO14_L_REG		(0x50c80)
#define MLU590_SMMU_FAULT_INFO14_H_REG		(0x50c84)

#define MLU590_SMMU_FAULT_INFO_L_REG(n)		\
((n) < 14) ? (((MLU590_SMMU_FAULT_INFO0_L_REG) + ((n) * 0x08))) : \
((((MLU590_SMMU_FAULT_INFO14_L_REG) + (((n) - 14) * 0x08))))
#define MLU590_SMMU_FAULT_INFO_H_REG(n)		\
((n) < 14) ? (((MLU590_SMMU_FAULT_INFO0_H_REG) + ((n) * 0x08))) : \
((((MLU590_SMMU_FAULT_INFO14_H_REG) + (((n) - 14) * 0x08))))

#define MLU590_SMMU_DBG0_REG				(0x50e00)
#define MLU590_SMMU_DBG1_REG				(0x50e04)
#define MLU590_SMMU_DBG2_REG				(0x50e08)
#define MLU590_SMMU_DBG3_REG				(0x50e0c)
#define MLU590_SMMU_DBG4_REG				(0x50e10)
#define MLU590_SMMU_SECU_REG				(0x50f00)
#define MLU590_SMMU_MODULE_ID_INFO_REG		(0x50ff0)
#define MLU590_SMMU_DATE_INFO_REG			(0x50ff4)
#define MLU590_SMMU_RESERVED1_REG			(0x50ff8)
#define MLU590_SMMU_RESERVED2_REG			(0x50ffc)
/*Reg list end*/

#define SMMU_INV_BITS_L (0x20)
#define SMMU_INV_BITS_H (0x10)
#define SMMU_INV_MASK_L (SMMU_INV_BITS_L - 1)
#define SMMU_INV_MASK_H (SMMU_INV_BITS_H - 1)

enum {
	MLU590_SMMU_RMPIDX_CONFIG  = 0x0,
	MLU590_SMMU_RMPIDX_SRAM    = 0x1,
	MLU590_SMMU_RMPIDX_INBOUND = 0x2,
	MLU590_SMMU_RMPIDX_DET     = 0x3,
	MLU590_SMMU_RMPIDX_OB_DESC = 0x4,
	MLU590_SMMU_RMPIDX_FORBIDDEN = 0x5,
	MLU590_SMMU_RMPIDX_DRAM    = 0x6,
};

enum {
	RMP_FLAG_RW = 0x0 << 8,
	RMP_FLAG_RO = 0x3 << 8,
	RMP_FLAG_COMPRESS = 0x3 << 24,
};

static void mlu590_det_enable(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	/* The DET register is defaultly disable when it's mlu590.
	 * So it should to be enable in the initialization phase.
	 */
	if (core->device_id == MLUID_590) {
		reg_write32(core->bus_set, 0x959028, 0x3);
		reg_write32(core->bus_set, 0x95902c, 0x3);
		reg_write32(core->bus_set, 0x959030, 0x3);
		reg_write32(core->bus_set, 0x959034, 0x3);
	}
}

static int mlu590_smmu_pre_cau_bypass(void *pcore, unsigned int s_id, bool en)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	unsigned int reg_value;

	reg_value = reg_read32(core->bus_set, MLU590_SMMU_CAU_CTL_REG(s_id));

	/*1 -- enable the bypass module or 0 -- disable the bypass module*/
	reg_value = en ? reg_value | (1 << 0) : reg_value & (~(1 << 0));

	reg_write32(core->bus_set, MLU590_SMMU_CAU_CTL_REG(s_id), reg_value);

	return 0;
}

static int mlu590_smmu_pre_cau_invalid(void *pcore, unsigned int s_id)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	unsigned int reg = 0UL, val = 0UL;
	unsigned int reg_value;
	int i = 0;

	if (s_id & ~(SMMU_INV_MASK_L)) {	/* s_id input is bigger than INV1_NUMS */
		reg = MLU590_SMMU_INV2_REG;
		val = (s_id - SMMU_INV_BITS_L) & SMMU_INV_MASK_H;
	} else {
		reg = MLU590_SMMU_INV1_REG;
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
static int mlu590_smmu_reset(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg_write32(core->bus_set, MLU590_SMMU_INV0_REG, 1);
	reg_write32(core->bus_set, MLU590_SMMU_GCR0_REG, 0x0);

	return 0;
}

static void mlu590_remap_win_set(struct cn_core_set *core, dev_addr_t va_addr,
		dev_addr_t pa_addr, dev_addr_t size, unsigned int attr, unsigned int win_idx)
{
	/*VA :[47:44] set base_h, [43:12] set base_l; [11:0] is align by hardware*/
	reg_write32(core->bus_set,
		MLU590_SMMU_RMPWIN_BASE_L_REG(win_idx), ((va_addr >> 12) & U32_MAX));

	cn_dev_core_info(core, "func %s idx %d write %x val %x", __func__, win_idx,
		MLU590_SMMU_RMPWIN_BASE_L_REG(win_idx),
		reg_read32(core->bus_set, MLU590_SMMU_RMPWIN_BASE_L_REG(win_idx)));

	reg_write32(core->bus_set,
		MLU590_SMMU_RMPWIN_BASE_H_REG(win_idx), (va_addr >> 44) | attr);

	cn_dev_core_info(core, "func %s idx %d write %x val %x", __func__, win_idx,
		MLU590_SMMU_RMPWIN_BASE_H_REG(win_idx),
		reg_read32(core->bus_set, MLU590_SMMU_RMPWIN_BASE_H_REG(win_idx)));
	/*PA*/
	reg_write32(core->bus_set,
		MLU590_SMMU_RMPWIN_REMAP_REG(win_idx), pa_addr >> 12);

	cn_dev_core_info(core, "func %s idx %d write %x val %x", __func__, win_idx,
		MLU590_SMMU_RMPWIN_REMAP_REG(win_idx),
		reg_read32(core->bus_set, MLU590_SMMU_RMPWIN_REMAP_REG(win_idx)));
	/*size*/
	reg_write32(core->bus_set,
		MLU590_SMMU_RMPWIN_MASK_REG(win_idx), ~(size - 1) >> 12);

	cn_dev_core_info(core, "func %s idx %d size %llx", __func__, win_idx, size);
}

static int
mlu590_smmu_init(void *pcore, dev_addr_t reg_size, dev_addr_t mem_size)
{
	unsigned int i = 0;
	unsigned int cau_cnt = 0;
	unsigned int reg_value = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	cau_cnt = reg_read32(core->bus_set, MLU590_SMMU_VER_REG) >> 8;
	cau_cnt &= 0xff;
	cn_dev_core_info(core, "pcie smmu cau cnt = %d", cau_cnt);

	/* FIX (VIRTUAL-405): to disable pcie smmu to restore to the default status */
	mlu590_smmu_reset(core);

	reg_value = (VA_SIZE << 0 | PA_SIZE << 8 | GRANULE_SIZE << 16);
	reg_write32(core->bus_set, MLU590_SMMU_TCR_REG, reg_value);
	/*invalid mode*/
	reg_write32(core->bus_set, MLU590_SMMU_GCR1_REG, 0x2 | (0x1 << 12));/*is correct*/
	reg_write32(core->bus_set, MLU590_SMMU_GCR3_REG, 0x3fe0);
	reg_write32(core->bus_set, MLU590_SMMU_GCR9_REG, 0x3fe0);
	reg_write32(core->bus_set, MLU590_SMMU_INV_FLAG1_REG, 0x3fe0);
	/*
	 *remap win
	 *index 0: config 0x8000000000 to 0x8000000000.
	 *index 1: SRAM alloc dynamic VA addr in sharemem.
	 *index 2: Inbound sharemem 0x800000000000 to share mem PA.
	 *need add SRAM to share mem PA before Inbound sharemem win index.
	 */
	/* set remap0 as config space */
	mlu590_remap_win_set(core, 0x8000000000, 0x8000000000, 0x40000000, RMP_FLAG_RW,
			MLU590_SMMU_RMPIDX_CONFIG);

	/* set remap2 as inbound space */
	mlu590_remap_win_set(core, C50_AXI_SHM_BASE, C50_AXI_SHM_PA_BASE, mem_size, RMP_FLAG_RW,
			MLU590_SMMU_RMPIDX_INBOUND);

	/* set remap3 as det space */
	mlu590_remap_win_set(core, 0x7803030000, 0x7803030000, 0x1000, RMP_FLAG_RW,
			MLU590_SMMU_RMPIDX_DET);

	/* set remap4 as data outbound desc pg space */
	mlu590_remap_win_set(core, 0x7803020000, 0x7803020000, 0x1000, RMP_FLAG_RW,
			MLU590_SMMU_RMPIDX_OB_DESC);

	reg_write32(core->bus_set, MLU590_SMMU_RMPWIN_CTL_REG,
			(1 << MLU590_SMMU_RMPIDX_CONFIG | 1 << MLU590_SMMU_RMPIDX_INBOUND |
			 1 << MLU590_SMMU_RMPIDX_DET | 1 << MLU590_SMMU_RMPIDX_OB_DESC));
	/*cau0(bar0) disable bypass*/
	cn_dev_core_info(core, "set all cau able bypass except bar0");

	reg_write32(core->bus_set, MLU590_SMMU_CAU_CTL_REG(0), 0x04020408);

	/*enable bypass because bar!*/
	for (i = 1; i < cau_cnt; i++) {
		reg_write32(core->bus_set, MLU590_SMMU_CAU_CTL_REG(i), 0x04020409);
	}

	reg_write32(core->bus_set, MLU590_SMMU_PTWCR_REG, 0x02020227);
	reg_write32(core->bus_set, MLU590_SMMU_PTW0MR_L_REG, 0x30);
	reg_write32(core->bus_set, MLU590_SMMU_PTW1MR_L_REG, 0xc0);
	reg_write32(core->bus_set, MLU590_SMMU_PTW2MR_L_REG, 0x0f);

	reg_write32(core->bus_set, MLU590_SMMU_MAIR_L_REG, 0x07072222);
	reg_write32(core->bus_set, MLU590_SMMU_MAIR_H_REG, 0xffffb0b0);

	/*update and enable smmu*/
	cn_dev_core_info(core, "update and enable smmu...");
	reg_write32(core->bus_set, MLU590_SMMU_UPDATE_CFG_REG, 1);
	reg_write32(core->bus_set, MLU590_SMMU_GCR0_REG, 1);

	reg_value = reg_read32(core->bus_set, MLU590_SMMU_GCR0_REG);
	i = 0;
	while (reg_value != 1) {
		reg_value = reg_read32(core->bus_set, MLU590_SMMU_GCR0_REG);
		if (i++ == 50000) {
			cn_dev_core_err(core, "wait for pcie smmu valid timeout");
			return -1;
		}
	}

	mlu590_det_enable(core);

	return 0;
}

static unsigned int
__bitmap2nums(unsigned long bitmap)
{
	int i = 0, counts = 0;

	for_each_set_bit(i, &bitmap, sizeof(bitmap) * BITS_PER_BYTE)
		counts++;

	return counts;
}

/*
 *FIXME: we need move this remap config to mlu590_smmu_init later.
 */
static int
mlu590_smmu_add_remap_internal(void *pcore, dev_addr_t va_addr,
				dev_addr_t pa_addr, unsigned long size, unsigned int ap,
				unsigned int idx)
{
	unsigned int reg_value = 0, remap_nums;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg_value = reg_read32(core->bus_set, MLU590_SMMU_RMPWIN_CTL_REG);
	remap_nums = __bitmap2nums(reg_value);
	cn_dev_core_debug(core, "pcie smmu reg %x remap cnt = %d", reg_value, remap_nums);

	if ((1UL << idx) & reg_value) {
		cn_dev_core_warn(core, "remap windows %d has already been set", idx);
		return 0;
	}

	cn_dev_core_debug(core, "pcie smmu add remap va = %llx pa = %llx size = %lx",
					 va_addr, pa_addr, size);
	mlu590_remap_win_set(core, va_addr, pa_addr, size, ap, idx);
	reg_value |= (0x1 << idx);
	reg_write32(core->bus_set, MLU590_SMMU_RMPWIN_CTL_REG, reg_value);

	cn_dev_core_debug(core, "pcie smmu add remap ctl %x",
					 reg_read32(core->bus_set, MLU590_SMMU_RMPWIN_CTL_REG));

	return 0;
}

static int
mlu590_smmu_reset_remap_internal(void *pcore, dev_addr_t va_addr,
				dev_addr_t pa_addr, unsigned long size, unsigned int ap,
				unsigned int idx)
{
	unsigned int reg_value = 0, remap_nums;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg_value = reg_read32(core->bus_set, MLU590_SMMU_RMPWIN_CTL_REG);
	remap_nums = __bitmap2nums(reg_value);
	cn_dev_core_debug(core, "pcie smmu reg %x remap cnt = %d", reg_value, remap_nums);

	reg_write32(core->bus_set, MLU590_SMMU_RMPWIN_CTL_REG, reg_value & ~(0x1 << idx));

	cn_dev_core_debug(core, "pcie smmu add remap va = %llx pa = %llx size = %lx",
					 va_addr, pa_addr, size);
	mlu590_remap_win_set(core, va_addr, pa_addr, size, ap, idx);
	reg_value |= (0x1 << idx);
	reg_write32(core->bus_set, MLU590_SMMU_RMPWIN_CTL_REG, reg_value);

	cn_dev_core_debug(core, "pcie smmu add remap ctl %x",
					 reg_read32(core->bus_set, MLU590_SMMU_RMPWIN_CTL_REG));

	return 0;
}

int mlu590_smmu_add_remap(void *pcore, dev_addr_t va_addr,  dev_addr_t pa_addr,
					   unsigned long size, int type)
{
	switch (type) {
	case SMMU_RMPTYPE_SRAM:
		return mlu590_smmu_add_remap_internal(pcore, va_addr, pa_addr,
						size, RMP_FLAG_RW, MLU590_SMMU_RMPIDX_SRAM);
	case SMMU_RMPTYPE_DRAM:
		return mlu590_smmu_add_remap_internal(pcore, va_addr, pa_addr,
						size, RMP_FLAG_RW, MLU590_SMMU_RMPIDX_DRAM);
	case SMMU_RMPTYPE_OS_FORBIDDEN:
		return mlu590_smmu_add_remap_internal(pcore, va_addr, pa_addr,
						size, RMP_FLAG_RO, MLU590_SMMU_RMPIDX_FORBIDDEN);
	default:
		return -EINVAL;
	}
}

int mlu590_smmu_reset_remap(void *pcore, dev_addr_t va_addr, dev_addr_t pa_addr, unsigned long size, int type, int flag)
{
	int attr = 0;

#if 0
	if (flag & 1UL << ATTR_compress)
		attr |= RMP_FLAG_COMPRESS;	
#endif

	switch (type) {
	case SMMU_RMPTYPE_DRAM:
		return mlu590_smmu_reset_remap_internal(pcore, va_addr, pa_addr,
						size, attr | RMP_FLAG_RW, MLU590_SMMU_RMPIDX_DRAM);
	default:
		return -EINVAL;
	}
}

static int mlu590_smmu_release(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg_write32(core->bus_set, MLU590_SMMU_INV0_REG, 1);
	reg_write32(core->bus_set, MLU590_SMMU_GCR0_REG, 0x0);

	return 0;
}

void mlu590_smmu_ops_register(void *fops)
{
	struct pcie_smmu_ops *smmu_ops = (struct pcie_smmu_ops *)fops;

	if (smmu_ops) {
		smmu_ops->smmu_init = mlu590_smmu_init;
		smmu_ops->smmu_release = mlu590_smmu_release;
		smmu_ops->smmu_cau_invalid = mlu590_smmu_pre_cau_invalid;
		smmu_ops->smmu_cau_bypass = mlu590_smmu_pre_cau_bypass;
		smmu_ops->smmu_add_remap = mlu590_smmu_add_remap;
		smmu_ops->smmu_reset_remap = mlu590_smmu_reset_remap;
	}
}

