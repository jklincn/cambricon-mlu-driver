/*
 * This file is part of cambricon pcie driver
 *
 * Copyright (c) 2018, Cambricon Technologies Corporation Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ":%s: " fmt, __func__

#include <linux/version.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/delay.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "../../cndrv_pci.h"
#include "ce3226_zebu_ddr_data.h"

#include "cndrv_pci_ce3226.h"

static void cn_pci_reg_write32(struct cn_pcie_set *pcie_set, unsigned long offset, u32 val)
{
	if (pcie_set->ops->reg_write32)
		pcie_set->ops->reg_write32(offset, val, pcie_set);
	else
		iowrite32(val, pcie_set->reg_virt_base + offset);
}

static u32 cn_pci_reg_read32(struct cn_pcie_set *pcie_set, unsigned long offset)
{
	if (pcie_set->ops->reg_write32)
		return pcie_set->ops->reg_read32(offset, pcie_set);
	else
		return ioread32(pcie_set->reg_virt_base + offset);
}

void ddr_reg_wt32(unsigned long offset, u32 value, void *pcie_set)
{
	cn_pci_reg_write32(pcie_set, offset, value);
}

u32 ddr_reg_rd32(unsigned long offset, void *pcie_set)
{
	uint32_t val = 0;

	val = cn_pci_reg_read32(pcie_set, offset);
	return val;
}

void write_lpddr_mr(uint64_t base_addr, uint32_t mr, uint32_t rank,
				uint32_t data, struct cn_pcie_set *pcie_set)
{
	uint64_t addr;
	uint32_t read_result;

	addr = base_addr + csr_eac_reg8;
	ddr_reg_wt32(addr, (mr+(data<<8)), pcie_set);
	addr = base_addr + csr_eac_reg2;
	ddr_reg_wt32(addr, (rank+(0x1<<8)), pcie_set);
	addr = base_addr + csr_eac_reg1;
	ddr_reg_wt32(addr, 0x1, pcie_set);
	do {
		read_result = ddr_reg_rd32(addr, pcie_set);
	} while (read_result != 0);
}



void config_lpddr4(uint64_t base_addr, struct cn_pcie_set *pcie_set)
{
	uint32_t data;
	uint64_t addr;

	//dsc MEM_UMC0_ADDR
	addr = base_addr + csr_dram_reg0;
	//dram_type/dram_rank_type/dram_rank_en/dram_pkg_type/dram_ratio_f0/dram_ratio_f1/dram_ratio_f2
	data = 0 + (1<<3) + (3<<4) + (0<<8) + (0<<12);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_dram_reg1;
	data = 1 + (1<<1) + (1<<2);//wdbi_en/rdbi_en/mwr_en
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_dram_reg2;
	//wr_linkecc_en/rd_linkecc_en/wr_dc_en/rd_dc_en/bg_en_f0/bg_en_f1/bg_en_f2
	//wsync_type/wsync_off_mode/wsync_off_srpde/wcksus_en
	data = 0 + (0<<8) + (0<<16) + (0<<24);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg0;
	data = 1 + (1<<1);//lookahead_pbpre_en/lookahead_act_en
	ddr_reg_wt32(addr, data, pcie_set);

	/* addr = base_addr + csr_emc_reg1; */
	/* data = 12 + (0<<8) + (0<<16) + (0<<24); */
	/* ddr_reg_wt32(addr, data, pcie_set); */

	addr = base_addr + csr_emc_reg2;
	data = 0 + (0<<8) + (0<<16) + (0<<24);//ipd_en/ipd_zq_en
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg3;
	data = 30 + (0<<8) + (0<<16) + (0<<24);//ipd_cnt
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg4;
	data = 1;//pd_dram_clk_disable_en/isr_dram_clk_disable_en
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg5;
	//1to2_force_wr_ccd_delay_sel/1to2_force_rd_ccd_delay_sel
	//1to4_force_wr_ccd_delay_sel/1to4_force_rd_ccd_delay_sel
	data = 0xffffff;
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg6;
	data = 1;//auto_ref_en
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg7;
	//force_abref/force_pbref/force_abref_postpone_num/force_abref_by_mr4_en/tabref_rk_gap/auto_abref_insert
	data = 0 + (1<<1) + (5<<2) + (1<<5) + (10<<8) + (0<<16);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg8;
	data = 0xa91a;//refresh_rate_sel(0xfa5015af-lp5;0xa91a-lp4)
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg9;
	//isr_en/isrpd_en/isrdsm_en/isr_zq_en/isr_pdrg_vld_cnt[15:0]
	data = 0 + (0<<1) + (0<<2) + (0<<4) + (1<<16);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg10;
	data = 3037 + (119<<16);//tREFIab/tREFIpb
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg11;
	data = 4 + (2<<8) + (7<<16) + (11<<24);//tCCD/tCCD_L/tCCD_WR_RK/tCCD_RD_RK
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg12;
	data = 30 + (7<<8) + (7<<16) + (7<<24);//tCCDMW/tRRD/tRRD_L/tPBR2ACT
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg13;
	data = 31;//tFAW
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg14;
	data = 13 + (33<<8) + (26<<16) + (5<<24);//tRCD/tRAS/tATRDA/tATWRA
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg15;
	data = 5 + (25<<8) + (15<<16) + (13<<24);//tRTP/tWTP/tRPab/tRPpb
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg16;
	data = 20 + (40<<8) + (0<<16) + (18<<24);//tRPRDA/tRPWRA/tPPD/tWTRDA
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg17;
	data = 221 + (110<<16);//tRFCab/tRFCpb
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg18;
	data = 20 + (20<<8) + (20<<16);//tWRTRD/tWRTRD_L/tWRTRD_RK
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg19;
	data = 19 + (19<<8) + (19<<16);//tRDTWR/tRDTWR_L/tRDTWR_RK
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg20;
	data = 1 + (4<<8) + (0<<16) + (8<<24);//tCMDCKE/tCKE/tESCKE/tXP
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg21;
	data = 5 + (2<<8) + (0<<16) + (0<<24);//tCKELCK/tCKCKEH/tCSH
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg22;
	data = 10 + (0<<8) + (229<<16) + (0<<24);//tSR/tXSR
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg65;
	data = 0+(0<<16);//pdrg_en/pdrg_isr_en
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg66;
	data = 0;//pdrg_r0_col_addr/pdrg_r0_row_addr/pdrg_r0_bank_addr
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg67;
	data = 1<<28;//pdrg_r1_col_addr/pdrg_r1_row_addr/pdrg_r1_bank_addr
	ddr_reg_wt32(addr, data, pcie_set);

	/* addr = base_addr + csr_emc_reg23; */
	/* data = 0 + (0<<8) + (0<<16) + (0<<24);//tWTWSYNC/tWTWSYNCmin/tRTWSYNC/tRTWSYNCmin */
	/* ddr_reg_wt32(addr, data, pcie_set); */

	/* addr = base_addr + csr_emc_reg24; */
	/* data = 0 + (0<<8) + (0<<16) + (0<<24);//tWSYNC_FS_OFF/tWSYNC_OFF_FS/tWCKSUS_RW */
	/* ddr_reg_wt32(addr, data, pcie_set); */


	/* addr = base_addr + csr_dti_reg0; */
	/* data = 0 + (0<<8) + (0<<16) + (0<<24);//tWCKENL_FS/tWCKENL_WR/tWCKENL_RD/tWCKPRE_STATIC */
	/* ddr_reg_wt32(addr, data, pcie_set); */

	/* addr = base_addr + csr_dti_reg1; */
	/* data = 0 + (0<<8) + (0<<16) + (0<<24);//tWCKPRE_TOGGLE/tWCK_WR_WINDOW/tWCK_RD_WINDOW/tWCK_OFF_DELAY */
	/* ddr_reg_wt32(addr, data, pcie_set); */

	addr = base_addr + csr_dti_reg2;
	data = 14 + (0<<8) + (11<<16) + (0<<24);//tPHY_WRLAT/tPHY_WRDATA/tPHY_WRCSLAT
	ddr_reg_wt32(addr, data, pcie_set);

#ifdef CE3226_PZ1
	addr = base_addr + csr_dti_reg3;
	data = 12 + (13<<8) + (0<<16) + (0<<24);//tRDDATA_EN/tPHY_RDCSLAT/tRTWCKSUS/tWTWCKSUS
	ddr_reg_wt32(addr, data, pcie_set);
#elif defined(CE3226_ZEBU)
	addr = base_addr + csr_dti_reg3;
	data = 11 + (13<<8) + (0<<16) + (0<<24);//tRDDATA_EN/tPHY_RDCSLAT/tRTWCKSUS/tWTWCKSUS
	ddr_reg_wt32(addr, data, pcie_set);
#endif

	/* addr = base_addr + csr_dti_reg12; */
	/* data = 0; */
	/* ddr_reg_wt32(addr, data, pcie_set); */

	// Bank[2:0] CS[0] ROW[15:0] COL[9:4] 1GBx2Rank
#ifdef MEMSYS_BANK_REMAP
	addr = base_addr + csr_rob_reg0;
	data = (0x6 + (0x7<<8) + (0x8<<16) + (0x1f<<24));//b0/b1/b2/b3
	/* data = (0x16 + (0x17<<8) + (0x18<<16) + (0x1f<<24));//b0/b1/b2/b3 */
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg1;
	data = (0x0 + (0x01<<8) + (0x02<<16) + (0x03<<24));//c4/c5/c6/c7
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg2;
	data = (0x04 + (0x05<<8));//c8/c9
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg3;
	data = (0x09 + (0x0a<<8) + (0x0b<<16) + (0x0c<<24));//r0/r1/r2/r3
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg4;
	data = (0xd + (0xe<<8) + (0xf<<16) + (0x10<<24));//r4/r5/r6/r7
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg5;
	data = (0x11 + (0x12<<8) + (0x13<<16) + (0x14<<24));//r8/r9/r10/r11
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg6;
	data = (0x15 + (0x16<<8) + (0x17<<16));//r12/r13/r14
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg7;
	data = (0x18 + (0x1f<<8) + (0x1f<<16));//r15/16/17
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg8;
	data = (0x19 + (0<<8) + (0<<16));//cs0
	ddr_reg_wt32(addr, data, pcie_set);
#else
	addr = base_addr + csr_rob_reg0;
	data = (0x16 + (0x17<<8) + (0x18<<16) + (0x1f<<24));//b0/b1/b2/b3
	/* data = (0x16 + (0x17<<8) + (0x18<<16) + (0x1f<<24));//b0/b1/b2/b3 */
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg1;
	data = (0x0 + (0x01<<8) + (0x02<<16) + (0x03<<24));//c4/c5/c6/c7
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg2;
	data = (0x04 + (0x05<<8));//c8/c9
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg3;
	data = (0x06 + (0x07<<8) + (0x08<<16) + (0x09<<24));//r0/r1/r2/r3
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg4;
	data = (0xa + (0xb<<8) + (0xc<<16) + (0xd<<24));//r4/r5/r6/r7
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg5;
	data = (0xe + (0xf<<8) + (0x10<<16) + (0x11<<24));//r8/r9/r10/r11
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg6;
	data = (0x12 + (0x13<<8) + (0x14<<16));//r12/r13/r14
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg7;
	data = (0x15 + (0x1f<<8) + (0x1f<<16));//r15/16/17
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg8;
	data = (0x19 + (0<<8) + (0<<16));//cs0
	ddr_reg_wt32(addr, data, pcie_set);
#endif

	addr = base_addr + csr_rob_reg10;
	//reorder_coh_en/reorder_en/bg_en_opt/miss_insert_cnt[3:0]/miss_vld_cnt[3:0]
	data = (1<<0) + (1<<1) + (0<<3) + (7<<4) + (10<<8);
	ddr_reg_wt32(addr, data, pcie_set);
	// Statis configure end


	addr = base_addr + csr_eac_reg2;
	data = 0;
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_eac_reg1;
	data = 1;
	ddr_reg_wt32(addr, data, pcie_set);

	// Need wait or polling csr_eac_reg1 to zero
	addr = base_addr + csr_eac_reg1;
	do {
		data = ddr_reg_rd32(addr, pcie_set);
	} while (data != 0);

	/* addr = base_addr + csr_ile_reg0; */
	/* data = (1 + (0<<8) + (0<<16)); */
	/* ddr_reg_wt32(addr, data, pcie_set); */

//MR config
	write_lpddr_mr(base_addr, 0x3, 0x0, 0xf1, pcie_set); //MR3 Rank0
	write_lpddr_mr(base_addr, 0x2, 0x0, 0x35, pcie_set); //MR2 Rank0
	write_lpddr_mr(base_addr, 0x3, 0x1, 0xf1, pcie_set); //MR3 Rank1
	write_lpddr_mr(base_addr, 0x2, 0x1, 0x35, pcie_set); //MR2 Rank1
}

void config_lpddr5(uint64_t base_addr, struct cn_pcie_set *pcie_set)
{
	uint32_t data;
	uint64_t addr;

	addr = base_addr + csr_dram_reg0;
	//dram_type/dram_rank_type/dram_rank_en/dram_pkg_type/dram_ratio_f0/dram_ratio_f2
	data = 2 + (0 << 3) + (1 << 4) + (0 << 8) + (1 << 12);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_dram_reg1;
	data = 0 + (0 << 1) + (1 << 2); //wdbi_en/rdbi_en/mwr_en
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_dram_reg2;
	//wr_linkecc_en/rd_linkecc_en/wr_dc_en/rd_dc_en/bg_en_f0/bg_en_f1/bg_en_f2
	//wsync_type/wsync_off_mode/wsync_off_srpde/wcksus_en
	data = 0 + (1 << 4) + (1 << 7) + (0 << 16) + (0 << 24);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg0;
	data = 1 + (1 << 1); //lookahead_pbpre_en/lookahead_act_en
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg2;
	data = 0 + (0 << 8) + (0 << 16) + (0 << 24); //ipd_en/ipd_zq_en
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg3;
	data = 30 + (0 << 8) + (0 << 16) + (0 << 24); //ipd_cnt
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg4;
	data = 1; //pd_dram_clk_disable_en/isr_dram_clk_disable_en
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg5;
	//1to2_force_wr_ccd_delay_sel/1to2_force_rd_ccd_delay_sel
	//1to4_force_wr_ccd_delay_sel/1to4_force_rd_ccd_delay_sel
	data = 0xffffff;
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg6;
	data = 1;
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg7;
	//force_abref/force_pbref/force_abref_postpone_num/force_abref_by_mr4_en/tabref_rk_gap/auto_abref_insert
	data = 0 + (1 << 1) + (5 << 2) + (1 << 5) + (10 << 8) + (0 << 16);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg8;
	data = 0xfa5015af; //refresh_rate_sel(0xfa5015af-lp5;0xa91a-lp4)
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg9;
	//isr_en/isrpd_en/isrdsm_en/isr_zq_en/isr_pdrg_vld_cnt[15:0]
	data = 0 + (0 << 1) + (0 << 2) + (0 << 4) + (1 << 16);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg10;
	data = 2906 + (148 << 16); //tREFIab/tREFIpb
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg11;
	data = 2 + (2 << 8) + (7 << 16) + (4 << 24); //tCCD/tCCD_L/tCCD_WR_RK/tCCD_RD_RK
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg12;
	data = 14 + (2 << 8) + (4 << 16) + (4 << 24); //tCCDMW/tRRD/tRRD_L/tPBR2ACT
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg13;
	data = 15; //tFAW
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg14;
	data = 13 + (32 << 8) + (26 << 16) + (0 << 24); //tRCD/tRAS/tATRDA/tATWRA
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg15;
	data = 4 + (41<<8) + (17 << 16) + (13 << 24); //tRTP/tWTP/tRPab/tRPpb
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg16;
	data = 19 + (56 << 8) + (0 << 16) + (35 << 24); //tRPRDA/tRPWRA/tPPD/tWTRDA
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg17;
	data = 166 + (94 << 16); //tRFCab/tRFCpb
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg18;
	data = 20 + (54 << 8) + (0 << 16) + (32 << 24);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg19;
	data = 16 + (18 << 8) + (18 << 16) + (0 << 24);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg20;
	data = 0 + (7 << 8) + (0 << 16) + (9 << 24); //tCMDCKE/tCKE/tESCKE/tXP
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg21;
	data = 4 + (2 << 8) + (2 << 16) + (0 << 24); //tCKELCK/tCKCKEH/tCSH
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg22;
	data = 10 + (0 << 8) + (174 << 16) + (0 << 24); //tSR/tXSR
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg65;
	data = 0 + (0 << 16); //pdrg_en/pdrg_isr_en
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg66;
	data = 0; //pdrg_r0_col_addr/pdrg_r0_row_addr/pdrg_r0_bank_addr
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg67;
	data = 1 << 28; //pdrg_r1_col_addr/pdrg_r1_row_addr/pdrg_r1_bank_addr
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg23;
	data = 12 + (12 << 8) + (22 << 16) + (22 << 24); //tWTWSYNC/tWTWSYNCmin/tRTWSYNC/tRTWSYNCmin
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_emc_reg24;
	data = 0 + (0 << 8) + (0 << 16) + (0 << 24); //tWSYNC_FS_OFF/tWSYNC_OFF_FS/tWCKSUS_RW
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_dti_reg0;
	data = 2 + (4 << 8) + (8 << 16) + (4 << 24);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_dti_reg1;
	data = 1 + (14 << 8) + (23 << 16) + (1 << 24);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_dti_reg2;
	data = 16 + (0 << 8) + (0 << 16) + (0 << 24);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_dti_reg3;
	data = 16 + (0 << 8) + (0 << 16) + (0 << 24);
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_dti_reg12;
	data = 0;
	ddr_reg_wt32(addr, data, pcie_set);

	// Bank[3:0] ROW[16:0] COL[9:4] 4GBx1Rank
#ifdef MEMSYS_BANK_REMAP
	//dsc add rbc
	addr = base_addr + csr_rob_reg0;
	data = (0x7 + (0x8<<8) + (0x9<<16) + (0x0<<24));//b0/b1/b2/b3
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg1;
	data = (0x1 + (0x02<<8) + (0x03<<16) + (0x04<<24));//c4/c5/c6/c7
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg2;
	data = (0x05 + (0x06<<8));//c8/c9
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg3;
	data = (0x0a + (0x0b<<8) + (0x0c<<16) + (0x0d<<24));//r0/r1/r2/r3
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg4;
	data = (0xe + (0xf<<8) + (0x10<<16) + (0x11<<24));//r4/r5/r6/r7
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg5;
	data = (0x12 + (0x13<<8) + (0x14<<16) + (0x15<<24));//r8/r9/r10/r11
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg6;
	data = (0x16 + (0x17<<8) + (0x18<<16));//r12/r13/r14
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg7;
	data = (0x19 + (0x1a<<8) + (0x1f<<16));//r15/16/17
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg8;
	data = (0x1f + (0<<8) + (0<<16));//cs0
	ddr_reg_wt32(addr, data, pcie_set);
#else
	//dsc add rbc
	addr = base_addr + csr_rob_reg0;
	data = (0x17 + (0x18<<8) + (0x19<<16) + (0x1a<<24));//b0/b1/b2/b3
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg1;
	data = (0x0 + (0x01<<8) + (0x02<<16) + (0x03<<24));//c4/c5/c6/c7
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg2;
	data = (0x04 + (0x05<<8));//c8/c9
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg3;
	data = (0x06 + (0x07<<8) + (0x08<<16) + (0x09<<24));//r0/r1/r2/r3
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg4;
	data = (0xa + (0xb<<8) + (0xc<<16) + (0xd<<24));//r4/r5/r6/r7
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg5;
	data = (0xe + (0xf<<8) + (0x10<<16) + (0x11<<24));//r8/r9/r10/r11
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg6;
	data = (0x12 + (0x13<<8) + (0x14<<16));//r12/r13/r14
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg7;
	data = (0x15 + (0x16<<8) + (0x1f<<16));//r15/16/17
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_rob_reg8;
	data = (0x1f + (0<<8) + (0<<16));//cs0
	ddr_reg_wt32(addr, data, pcie_set);
#endif
	addr = base_addr + csr_rob_reg10;
	//reorder_coh_en/reorder_en/bg_en_opt/miss_insert_cnt[3:0]/miss_vld_cnt[3:0]
	data = (1<<0) + (1<<1) + (1<<3) + (7<<4) + (10<<8);
	ddr_reg_wt32(addr, data, pcie_set);

	//dsc add rbc
	addr = base_addr + csr_eac_reg1;
	data = 1;
	ddr_reg_wt32(addr, data, pcie_set);

	addr = base_addr + csr_eac_reg1;
	do {
		udelay(100);
		data = ddr_reg_rd32(addr, pcie_set);
	} while (data != 0);
	write_lpddr_mr(base_addr, 0x1, 0x0, 0x60, pcie_set); //MR1 Rank0
	write_lpddr_mr(base_addr, 0x2, 0x0, 0x7, pcie_set); //MR2 Rank0
	//write_lpddr_mr(base_addr, 0x1, 0x0, 0x6, pcie_set); //MR3 Rank0
	//write_lpddr_mr(base_addr, 0x2, 0x0, 0x7, pcie_set); //MR2 Rank0
	//write_lpddr_mr(base_addr, 0x3, 0x1, 0xf1, pcie_set); //MR3 Rank1
	//write_lpddr_mr(base_addr, 0x2, 0x1, 0x35, pcie_set); //MR2 Rank1
}

void ce3226_fpga_memsys_init(struct cn_pcie_set *pcie_set)
{
	uint32_t val;
	ddr_reg_wt32(0xD00100, 0x1, pcie_set);      // mdc_model_sel_reg: 0x0 work on D2D; 0x1 work on Mem

	/* memsys csr setting */
	ddr_reg_wt32(0xE04100, 0xFFFF, pcie_set);	//memsys_csr rstn_sw
	ddr_reg_wt32(0xE04104, 0x1FF01FF, pcie_set);	//memsys_csr clk_en

#if defined(DDR_INTLV_2K)
	ddr_reg_wt32(0xE0200c, 0x32, pcie_set);		//drs_addr_map 2'b10:2048B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_1K)
	ddr_reg_wt32(0xE0200c, 0x31, pcie_set);		//drs_addr_map 2'b01:1024B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_512)
	ddr_reg_wt32(0xE0200c, 0x30, pcie_set);		//drs_addr_map 2'b00:512B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_NONE)
	ddr_reg_wt32(0xE0200c, 0x33, pcie_set);		//disable DDR interleaving, 2GB/per chn
#endif
	val = ddr_reg_rd32(0xE02010, pcie_set);
	val &= (~0x1);
	ddr_reg_wt32(0xE02010, val, pcie_set);      //bypass DS

	/* mdc csr setting */
	ddr_reg_wt32(0xD04100, 0xFFFF, pcie_set);	//mdc_csr rstn_sw
	ddr_reg_wt32(0xD04104, 0x1FF01FF, pcie_set);	//mdc_csr clk_en
	/* mdc drs dram size, interleaving setting */
#if defined(DDR_INTLV_2K)
	ddr_reg_wt32(0xD0200c, 0x32, pcie_set);		//drs_addr_map 2'b10:2048B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_1K)
	ddr_reg_wt32(0xD0200c, 0x31, pcie_set);		//drs_addr_map 2'b01:1024B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_512)
	ddr_reg_wt32(0xD0200c, 0x30, pcie_set);		//drs_addr_map 2'b00:512B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_NONE)
	ddr_reg_wt32(0xD0200c, 0x33, pcie_set);		//disable DDR interleaving, 2GB/per chn
#endif
	val = ddr_reg_rd32(0xD02010, pcie_set);
	val &= (~0x1);
	ddr_reg_wt32(0xD02010, val, pcie_set);      //bypass DS

	/* top_north_sctrl ars dram size*/
	val = ddr_reg_rd32(0x60338, pcie_set);
	val &= (~0x7e);
#if defined(DDR_INTLV_2K)
	ddr_reg_wt32(0x60338, val | (0x4c), pcie_set); //dram_size 4~1'b 0x6 8GB interleaving size 5~6'b10 2048
#elif defined(DDR_INTLV_1K)
	ddr_reg_wt32(0x60338, val | (0x2c), pcie_set); //dram_size 4~1'b 0x6 8GB interleaving size 5~6'b10 1024
#elif defined(DDR_INTLV_512)
	ddr_reg_wt32(0x60338, val | (0x0c), pcie_set); //dram_size 4~1'b 0x6 8GB interleaving size 5~6'b10 512
#elif defined(DDR_INTLV_NONE)
	ddr_reg_wt32(0x60338, val | (0x6c), pcie_set); //dram_size 4~1'b 0x6 8GB non-interleaving mode
#endif
	val = ddr_reg_rd32(0x60338, pcie_set);
	pr_info("master topn ars dram size 0x%x", val);
}

static void ce3226_lpddr4_memsys_init(struct cn_pcie_set *pcie_set)
{
	uint32_t val;

	/* memsys csr setting */
	ddr_reg_wt32(0xE04100, 0xFFFF, pcie_set);	//memsys_csr rstn_sw
	ddr_reg_wt32(0xE04104, 0x1FF01FF, pcie_set);	//memsys_csr clk_en

#if defined(DDR_INTLV_2K)
	ddr_reg_wt32(0xE0200c, 0x32, pcie_set);		//drs_addr_map 2'b10:2048B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_1K)
	ddr_reg_wt32(0xE0200c, 0x31, pcie_set);		//drs_addr_map 2'b01:1024B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_512)
	ddr_reg_wt32(0xE0200c, 0x30, pcie_set);		//drs_addr_map 2'b00:512B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_NONE)
	ddr_reg_wt32(0xE0200c, 0x33, pcie_set);		//disable DDR interleaving, 2GB/per chn
#endif
	val = ddr_reg_rd32(0xE02010, pcie_set);
	val &= (~0x1);
	ddr_reg_wt32(0xE02010, val, pcie_set);      //bypass DS

	/* mdc csr setting */
	ddr_reg_wt32(0xD04100, 0xFFFF, pcie_set);	//mdc_csr rstn_sw
	ddr_reg_wt32(0xD04104, 0x1FF01FF, pcie_set);	//mdc_csr clk_en
	/* mdc drs dram size, interleaving setting */
#if defined(DDR_INTLV_2K)
	ddr_reg_wt32(0xD0200c, 0x32, pcie_set);		//drs_addr_map 2'b10:2048B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_1K)
	ddr_reg_wt32(0xD0200c, 0x31, pcie_set);		//drs_addr_map 2'b01:1024B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_512)
	ddr_reg_wt32(0xD0200c, 0x30, pcie_set);		//drs_addr_map 2'b00:512B 6~3'b 0110 16Gb=2GB/per chn
#elif defined(DDR_INTLV_NONE)
	ddr_reg_wt32(0xD0200c, 0x33, pcie_set);		//disable DDR interleaving, 2GB/per chn
#endif
	val = ddr_reg_rd32(0xD02010, pcie_set);
	val &= (~0x1);
	ddr_reg_wt32(0xD02010, val, pcie_set);      //bypass DS

	/* top_north_sctrl ars dram size*/
	val = ddr_reg_rd32(0x60338, pcie_set);
	val &= (~0x7e);
#if defined(DDR_INTLV_2K)
	ddr_reg_wt32(0x60338, val | (0x4c), pcie_set); //dram_size 4~1'b 0x6 8GB interleaving size 5~6'b10 2048
#elif defined(DDR_INTLV_1K)
	ddr_reg_wt32(0x60338, val | (0x2c), pcie_set); //dram_size 4~1'b 0x6 8GB interleaving size 5~6'b10 1024
#elif defined(DDR_INTLV_512)
	ddr_reg_wt32(0x60338, val | (0x0c), pcie_set); //dram_size 4~1'b 0x6 8GB interleaving size 5~6'b10 512
#elif defined(DDR_INTLV_NONE)
	ddr_reg_wt32(0x60338, val | (0x6c), pcie_set); //dram_size 4~1'b 0x6 8GB non-interleaving mode
#endif
	val = ddr_reg_rd32(0x60338, pcie_set);
	printk("master topn ars dram size 0x%x", val);
}

/* Full LPDDR4 config
 *
				----- umc0/chn0 (DDR4/2GB)
				|
		---- memsys --- |
		|		----- umc1/chn1 (DDR4/2GB)
		|
	NoC ---
		|		----- umc0/chn0 (DDR4/2GB)
		|		|
		---- mdcsys --- |
				----- umc1/chn1 (DDR4/2GB)
 */
void ce3226_only_one_die_init_full_lpddr4x(struct cn_pcie_set *pcie_set)
{
	ddr_reg_wt32(0xD00100, 0x1, pcie_set); //mdc_model_sel_reg: 0x0 work on D2D; 0x1 work on Mem
	ce3226_lpddr4_memsys_init(pcie_set);
	config_lpddr4(0xE10000, pcie_set); //mem umc0
	config_lpddr4(0xE30000, pcie_set); //mem umc1
	config_lpddr4(0xD10000, pcie_set); //mdc umc0
	config_lpddr4(0xD30000, pcie_set); //mdc umc1
}

static void ce3226_lpddr5_memsys_init(struct cn_pcie_set *pcie_set)
{
	uint32_t val;

	/* memsys csr setting */
	ddr_reg_wt32(0xE04100, 0xFFFF, pcie_set);	//memsys_csr rstn_sw
	ddr_reg_wt32(0xE04104, 0x1FF01FF, pcie_set);	//memsys_csr clk_en

#if defined(DDR_INTLV_2K)
	ddr_reg_wt32(0xE0200c, 0x42, pcie_set);		//drs_addr_map 2'b10:2048B 6~3'b 1000 32Gb=4GB/per chn
#elif defined(DDR_INTLV_1K)
	ddr_reg_wt32(0xE0200c, 0x41, pcie_set);		//drs_addr_map 2'b01:1024B 6~3'b 1000 32Gb=4GB/per chn
#elif defined(DDR_INTLV_512)
	ddr_reg_wt32(0xE0200c, 0x40, pcie_set);		//drs_addr_map 2'b00:512B 6~3'b 1000 32Gb=4GB/per chn
#elif defined(DDR_INTLV_NONE)
	ddr_reg_wt32(0xE0200c, 0x43, pcie_set);		//disable DDR interleaving, 4GB/per chn
#endif
	val = ddr_reg_rd32(0xE02010, pcie_set);
	val &= (~0x1);
	ddr_reg_wt32(0xE02010, val, pcie_set);      //bypass DS

	/* mdc csr setting */
	ddr_reg_wt32(0xD04100, 0xFFFF, pcie_set);	//mdc_csr rstn_sw
	ddr_reg_wt32(0xD04104, 0x1FF01FF, pcie_set);	//mdc_csr clk_en
	/* mdc drs dram size, interleaving setting */

#if defined(DDR_INTLV_2K)
	ddr_reg_wt32(0xD0200c, 0x42, pcie_set);		//drs_addr_map 2'b10:2048B 6~3'b 1000 32Gb=4GB/per chn
#elif defined(DDR_INTLV_1K)
	ddr_reg_wt32(0xD0200c, 0x41, pcie_set);		//drs_addr_map 2'b01:1024B 6~3'b 1000 32Gb=4GB/per chn
#elif defined(DDR_INTLV_512)
	ddr_reg_wt32(0xD0200c, 0x40, pcie_set);		//drs_addr_map 2'b00:512B 6~3'b 1000 32Gb=4GB/per chn
#elif defined(DDR_INTLV_NONE)
	ddr_reg_wt32(0xD0200c, 0x43, pcie_set);		//disable DDR interleaving, 4GB/per chn
#endif

	val = ddr_reg_rd32(0xD02010, pcie_set);
	val &= (~0x1);
	ddr_reg_wt32(0xD02010, val, pcie_set);      //bypass DS

	/* top_north_sctrl ars dram size*/
	val = ddr_reg_rd32(0x60338, pcie_set);
	val &= (~0x7e);
#if defined(DDR_INTLV_2K)
	ddr_reg_wt32(0x60338, val | (0x50), pcie_set); //dram_size 4~1'b 0x8 16GB interleaving size 5~6'b10 2048
#elif defined(DDR_INTLV_1K)
	ddr_reg_wt32(0x60338, val | (0x30), pcie_set); //dram_size 4~1'b 0x8 16GB interleaving size 5~6'b01 1024
#elif defined(DDR_INTLV_512)
	ddr_reg_wt32(0x60338, val | (0x10), pcie_set); //dram_size 4~1'b 0x8 16GB interleaving size 5~6'b10 512
#elif defined(DDR_INTLV_NONE)
	ddr_reg_wt32(0x60338, val | (0x70), pcie_set); //dram_size 4~1'b 0x8 16GB non-interleaving 5~6'b11
#endif
	val = ddr_reg_rd32(0x60338, pcie_set);
	printk("master topn ars dram size 0x%x", val);
}

/* Full LPDDR5 config
 *
				----- umc0/chn0 (DDR5/4GB)
				|
		---- memsys --- |
		|		----- umc1/chn1 (DDR5/4GB)
		|
	NoC ---
		|		----- umc0/chn0 (DDR5/4GB)
		|		|
		---- mdcsys --- |
				----- umc1/chn1 (DDR5/4GB)
 */
void ce3226_only_one_die_init_full_lpddr5(struct cn_pcie_set *pcie_set)
{
	ddr_reg_wt32(0xD00100, 0x1, pcie_set); //ddrc_apd_resetn
	ce3226_lpddr5_memsys_init(pcie_set);
	config_lpddr5(0xE10000, pcie_set); //mem umc0
	config_lpddr5(0xE30000, pcie_set); //mem umc1
	config_lpddr5(0xD10000, pcie_set); //mdc umc0
	config_lpddr5(0xD30000, pcie_set); //mdc umc1
}

void ce3226_memory_and_d2d_init(void *pcie)
{
#if defined(CE3226_LPDDR4_1DIE)
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;
	ce3226_only_one_die_init_full_lpddr4x(pcie_set);
#elif defined(CE3226_LPDDR5_1DIE)
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;
	ce3226_only_one_die_init_full_lpddr5(pcie_set);
#elif defined(CE3226_FPGA)
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;
	ce3226_fpga_memsys_init(pcie_set);
#endif
}
