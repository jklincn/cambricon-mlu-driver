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

#include <linux/version.h>
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
#include "cndrv_debug.h"

#ifdef MLU290_HBM_ZEBU
#define PCIE_HBM_RESET_OFFSET		(0xF00000)//C20
#define PCIE_HBM_INIT_OFFSET		(0x1000000)//C20

#define ddr_reg_wt32(offset, value, bus_set)	\
		reg_write32(bus_set, offset, value)

#define ddr_reg_rd32(offset, bus_set)	\
		reg_read32(bus_set, offset)

static void hbm_init(struct cn_core_set *core, unsigned int base_offset)
{
	int i = 0;
	int value = 0;
	static unsigned int offset_val[84][2] = {{0x3c78, 0x3}, {0x3c7c, 0x3},
				{0x3c84, 0x8}, {0x3cc8, 0x1}, {0x3ccc, 0x1},
				{0x3cd0, 0x4}, {0x3e7c, 0x8}, {0x3e80, 0x91},
				{0x3e9c, 0x14}, {0x3ea0, 0x11}, {0x4044, 0x1d},
				{0x4050, 0x14}, {0x4054, 0x2d}, {0x4058, 0x10},
				{0x405c, 0x15e}, {0x4064, 0x15}, {0x4074, 0x8},
				{0x40cc, 0xf0b}, {0x418c, 0x1b8}, {0x4194, 0x168},
				{0x4310, 0xa}, {0x4314, 0xa}, {0x10004, 0x5},
				{0x40d8, 0xe}, {0x40dc, 0x5}, {0x4060, 0x5},
				{0x3c80, 0x6}, {0x3c84, 0x8}, {0x4088, 0x4},
				{0x400c, 0x1}, {0x4008, 0x1}, {0x3e94, 0x1},
				{0x3cb4, 0x0}, {0x4188, 0xf}, {0x3c64, 0x4},
				{0x4228, 0x1b}, {0x4224, 0x7}, {0x4034, 0x1},
				{0x5008, 0x1}, {0x5000, 0x1}, {0x3e78, 0x1},
				{0x5010, 0x3f}, {0x3c40, 0x1}, {0x3c44, 0x1},
				{0x3c48, 0x0}, {0x5400, 0x0}, {0x5404, 0x1},
				{0x3cb0, 0x1}, {0x5800, 0x1}, {0x424c, 0x1},
				{0x4000, 0x1}, {0x3c40, 0x1}, {0x3c44, 0x1},
				{0x3ca0, 0x1}, {0x3ca4, 0x1}, {0x3ca8, 0x1},
				{0x3cb0, 0x1}, {0x5800, 0x1}, {0x4228, 0x1b},
				{0x4020, 0x1}, {0x41f4, 0x0}, {0x41f8, 0x73},
				{0x41f0, 0x1}, {0x41f0, 0x0}, {0x4020, 0x1},
				{0x41f4, 0x1}, {0x41f8, 0x8}, {0x41f0, 0x1},
				{0x41f0, 0x0}, {0x4020, 0x1}, {0x41f4, 0x2},
				{0x41f8, 0xde}, {0x41f0, 0x1}, {0x41f0, 0x0},
				{0x4020, 0x1}, {0x41f4, 0x3}, {0x41f8, 0xc8},
				{0x41f0, 0x1}, {0x41f0, 0x0}, {0x4020, 0x1},
				{0x41f4, 0x4}, {0x41f8, 0x3}, {0x41f0, 0x1},
				{0x41f0, 0x0}
				};

	for (i = 0; i < 84; i++) {
		ddr_reg_wt32(base_offset + offset_val[i][0], offset_val[i][1], core->bus_set);
		if (offset_val[i][0] == 0x41f0 && offset_val[i][1] == 0x1) {
			while (1) {
				value = ddr_reg_rd32(base_offset + 0x4030, core->bus_set);
				if (value == 1) {
					break;
				}
			}
		}
	}
}
static void hbm_boot_prepare(struct cn_core_set *core)
{
	int i = 0;
	int j = 0;
	int value = 0;
	unsigned int base_offset = 0;

	ddr_reg_wt32(0x5008, 0xff00ff, core->bus_set);
	ddr_reg_rd32(0x5008, core->bus_set);
	for (j = 0; j < 2; j++) {
		for (i = 0; i < 0x14; i += 4) {
			ddr_reg_wt32(PCIE_HBM_RESET_OFFSET + j * 0x4000 + i,
								0x1, core->bus_set);
		}
		for (i = 0; i < 0x14; i += 4) {
			value = ddr_reg_rd32(PCIE_HBM_RESET_OFFSET +
						j * 0x4000 + i, core->bus_set);
		}
	}

	for (j = 0; j < 2; j++) {
		for (i = 0; i < 4; i++) {
			base_offset = PCIE_HBM_INIT_OFFSET +
						(j * 0x100000) + (i * 0x40000);
			hbm_init(core, base_offset);
		}
	}
}
#endif

#define MASK_BITS(nEnd, nStart) \
	(((1UL << ((nEnd) - (nStart) + 1)) - 1) << (nStart))

#define GET_BITS_VAL(nVal, nEnd, nStart) \
	(((nVal) & MASK_BITS(nEnd, nStart)) >> (nStart))

#define SET_BITS_VAL(nVal, nEnd, nStart, nNum) \
	do {\
		(nVal) &= (~MASK_BITS(nEnd, nStart));\
		(nVal) |= (((nNum) << (nStart)) & MASK_BITS(nEnd, nStart));\
	} while (0)\

#ifdef MLU290_HBM

#define hbm_reg_wt32(offset, value, bus_set)	\
		reg_write32(bus_set, offset, value)

#define hbm_reg_rd32(offset, bus_set)	\
		reg_read32(bus_set, offset)

#define HBM_PLL0_BASE_ADDR			(0x00031000)
#define HBM_PLL1_BASE_ADDR			(0x00032000)
#define HBM_PLL2_BASE_ADDR			(0x00035000)
#define HBM_PLL3_BASE_ADDR			(0x00036000)
#define HBM_PHY_BASE_ADDR			(0x00040000) //0x20000*4
#define HBM_MC_BASE_ADDR			(0x01000000) //0x40000*4 100000*8
#define HBM_RC_BASE_ADDR			(0x00F00000) //4000*8
#define HBM_LLC_BASE_ADDR			(0x00F01000) //4000*8
#define HBM_MFBC_BASE_ADDR			(0x00F02000) //4000*8
#define HBM_DATA_FREQ				(2400)
#define HBM_RESETN				(0x08)
#define CFG_HBM_RESET_N				(0x00)
#define CFG_HBM_ARESET_N			(0x04)
#define CFG_LLC_ARESET_N			(0x08)
#define CFG_AXIMON_ARESET_N			(0x0C)
#define CFG_HBM_MT_SEL				(0x10)
#define SBUS_CLK_DIVIDER			(0x01) //100M
#define SCTRL_ADDR				(0xfe)
#define SNAP_ADDR				(0xfd)
#define APC_ADDR				(0x01)
#define APC_BIST_EN_REG				(30)
#define APC_INIT_COMPLETE			(41)
#define FW_POWER_ON_FLOW			(5)
#define FW_INTERRUPT_OP_ON_ALL_CHN		(0x30)
#define FW_INTERRUPT_GET_OP_RESULT		(0x32)
#define FW_INTERRUPT_GET_PARAM_VALUE		(0x33)
#define FW_INTERRUPT_SET_PARAM			(0x34)
#define FW_INTERRUPT_SET_PARAM_VALUE		(0x35)

#define WIR_REG					(2)
#define WDR_CONFIG_REG				(15)
#define CONTROL_1500				(16)
#define READ_CHANNEL				(17)
#define BUSY_DONE_1500_REG			(18)
#define WDR_READ_DATA_31_0			(20)
#define WDR_READ_DATA_63_32			(21)
#define WDR_READ_DATA_95_64			(22)
#define WDR_READ_DATA_127_96			(23)
#define WDR_READ_DATA_159_128			(24)
#define WDR_READ_DATA_191_160			(25)
#define WDR_READ_DATA_223_192			(26)
#define WDR_READ_DATA_255_224			(27)
#define WDR_READ_DATA_287_256			(28)
#define WDR_READ_DATA_319_288			(29)
#define START_WIR_WRITE				(1) //0b001
#define START_WDR_WRITE				(2) //0b010
#define START_WDR_READ				(4) //0b100
#define STOP_1500				(0) //0b000
#define HBM_SEL					(1)
#define PHY_SEL					(0)
#define PHY_CONFIG				(0x14)
#define PHY_CONFIG_LENGTH			(104)
#define HBM_MODE_REG_DUMP_SET			(0x10)
#define HBM_MODE_REG_DUMP_SET_LENGTH		(128)
// Firmware HBM Parameters value
#define M_HBM_MAX_TIMEOUT			(0x2000) //0x3e8
#define M_HBM_TINIT1_CYCLES			(0x1000) //0xc35
#define M_HBM_TINIT2_CYCLES			(0x50) //0x1
#define M_HBM_TINIT3_CYCLES			(0x3000) //0x1e85
#define M_HBM_TINIT4_CYCLES			(0x50) //0xa
#define M_HBM_TINIT5_CYCLES			(0x50) //0x4
#define M_HBM_DIV_MODE				(1)
#define M_HBM_STACK_HEIGHT			(1)
#define M_HBM_T_RDLAT_OFFSET			(4)
#define M_HBM_PARITY_LATENCY			(2)
#define M_HBM_REPAIR_MODE			(2)
// HBM MC reg
#define CFG_MANUAL_ADDRESS_MAP			(0x2400)
#define CFG_GENERATE_REFRESH_ON_SRX		(0x2824)
#define STAT_INTERRUPT_0			(0x294C)
#define INIT_INTERRUPT_MASK_0			(0x2950)
//#define STAT_ECC_1BIT_ERROR_ADDR		(0x2958)
#define STAT_ECC_1BIT_POS			(0x295C)
#define STAT_ECC_1BIT_RMW			(0x2960)
//#define STAT_ECC_2BIT_ERROR_ADDR		(0x2964)
#define STAT_ECC_2BIT_RMW			(0x2968)
#define CFG_TEMP_CTRL_REF_MODE			(0x3C34)
#define CFG_READ_DBI				(0x3C40)
#define CFG_WRITE_DBI				(0x3C44)
#define CFG_DATA_MASK				(0x3C48)
#define CFG_CCD_S				(0x3C64)
#define CFG_CCD_L				(0x3C68)
#define CFG_RRD_S				(0x3C78)
#define CFG_RRD_L				(0x3C7C)
#define CFG_WTR_S				(0x3C80)
#define CFG_WTR_L				(0x3C84)
#define CFG_RD_DQ_PARITY_EN			(0x3CA0)
#define CFG_WR_DQ_PARITY_EN			(0x3CA4)
#define CFG_CA_PARITY_EN			(0x3CA8)
#define CFG_BANK_GROUP_EN			(0x3CAC)
#define CFG_HBM_CB_EN				(0x3CB0)
#define CFG_HBM_PARITY_LATENCY			(0x3CB4)
#define CFG_HBM_TCR_ENABLE			(0x3CB8)
#define STAT_WRITE_DATA_PARITY_ERROR		(0x3CBC)
#define STAT_READ_DATA_PARITY_ERROR		(0x3CC0)
#define CFG_EN_RRDP				(0x3CC8)
#define CFG_PS_ONE_FAW				(0x3CCC)
#define CFG_CCD_R				(0x3CD0)
#define CFG_SBREF_EN				(0x3E78)
#define CFG_RREFD				(0x3E7C)
#define CFG_RFCSB				(0x3E80)
#define CFG_LOOKAHEAD_SBREF			(0x3E94)
#define CFG_ADVANCE_ACTIVATE_READY		(0x3E98)
#define CFG_RCD_RD				(0x3E9C)
#define CFG_RCD_WR				(0x3EA0)
#define CTRLR_SOFT_RESET_N			(0x4000)
#define CFG_LOOKAHEAD_PCH			(0x4008)
#define CFG_LOOKAHEAD_ACT			(0x400C)
#define INIT_AUTO_DISABLE			(0x4010)
#define CFG_BL					(0x4034)
#define CFG_AUTO_REF_EN				(0x4040)
#define CFG_RAS					(0x4044)
#define CFG_RP					(0x4050)
#define CFG_RC					(0x4054)
#define CFG_FAW					(0x4058)
#define CFG_RFC					(0x405C)
#define CFG_RTP					(0x4060)
#define CFG_WR					(0x4064)
#define CFG_XP					(0x4074)
#define CFG_READ_TO_WRITE			(0x4088)
#define CFG_REF_PER				(0x40CC)
#define CFG_MEM_ROWBITS				(0x40D8)
#define CFG_MEM_BANKBITS			(0x40DC)
#define CFG_MOD					(0x4188)
#define CFG_XS					(0x418C)
#define CFG_XPR					(0x4194)
#define CFG_WL					(0x4224)
#define CFG_RL					(0x4228)
//#define INIT_SELF_REFRESH			(0x4234)
#define INIT_SELF_REFRESH_STATUS		(0x4238)
#define INIT_POWER_DOWN				(0x423C)
#define INIT_POWER_DOWN_STATUS			(0x4240)
#define CFG_CTRLR_INIT_DISABLE			(0x424C)
#define CFG_PHYUPD_ACK_DELAY			(0x42FC)
#define CFG_CKSRE				(0x4310)
#define CFG_CKSRX				(0x4314)
#define CFG_IDLE_TIME_TO_SELF_REFRESH		(0x4324)
#define CFG_IDLE_TIME_TO_POWER_DOWN		(0x4328)
#define CFG_BURST_RW_REFRESH_HOLDOFF		(0x432C)
#define INIT_REFRESH_COUNT			(0x4330)
#define CFG_BG_INTERLEAVE			(0x4380)
#define CFG_DBI_BYTE_DISABLE_SOURCE		(0x4384)
#define CFG_DBI_BYTE_DISABLE			(0x4388)
#define CFG_REORDER_EN				(0x5000)
#define CFG_REORDER_QUEUE_EN			(0x5004)
#define CFG_INTRAPORT_REORDER_EN		(0x5008)
#define CFG_MAINTAIN_COHERENCE			(0x500C)
#define CFG_Q_AGE_LIMIT				(0x5010)
#define CFG_SBREF_ISSUE_PER			(0x5014)
#define CFG_RO_DELAY_BADPERF_CHOICE		(0x5024)
#define CFG_DM_EN				(0x5400)
#define CFG_RMW_EN				(0x5404)
#define CFG_ECC_CORRECTION_EN			(0x5800)
#define CFG_ECC_BYPASS				(0x5804)
#define INIT_WRITE_DATA_1B_ECC_ERROR_GEN	(0x5844)
#define INIT_WRITE_DATA_2B_ECC_ERROR_GEN	(0x5848)
#define CFG_ECC_1BIT_INT_THRESH			(0x585C)
#define STAT_INT_ERR_1BIT_THRESH		(0x5860)
#define STAT_CA_PARITY_ERROR			(0x8000)
#define CFG_DFI_T_RDDATA_EN			(0x10000)
#define CFG_DFI_T_PHY_RDLAT			(0x10004)
#define CFG_DFI_T_PHY_WRLAT			(0x10008)
#define CFG_DFI_PHYUPD_EN			(0x1000C)
#define STAT_DFI_INIT_COMPLETE			(0x10034)
//#define STAT_DFI_TCR_TEMP			(0x10048)
#define STAT_DFI_CATTRIP			(0x1004C)
#define CFG_AXI_START_ADDRESS_AXI		(0x12C14)
#define CFG_AXI_END_ADDRESS_AXI			(0x12D94)
#define CFG_MEM_START_ADDRESS_AXI		(0x12F14)
#define CFG_AXI_AUTO_PCH			(0x13210)
#define CFG_AXIRD_ID_REORDER_EN			(0x13214)
#define CFG_AXIRD_INTERLEAVE_SEL		(0x13220)
#define STAT_AXI_DECERR				(0x1322C)

//HBM mt reg
#define MT_EN_SINGLE				(0x4404)
#define MT_STOP_ON_ERROR			(0x4408)
#define MT_ERROR_STS				(0x4424)
#define MT_DONE_ACK				(0x4428)
#define AMT_USEQ_IRAM_WADDR			(0x6000)
#define AMT_USEQ_IRAM_WDATA_0			(0x600C)
#define AMT_USEQ_IRAM_WDATA_1			(0x6010)
#define AMT_SEQUENCER_ENABLE			(0x60C4)

//HBM mc value
#define mc_cfg_xpr				(0x168)
#define mc_cfg_data_mask			(0)
#define mc_cfg_mod				(0x13)
#define mc_cfg_mem_rowbits			(0xe)
#define mc_cfg_mem_bankbits			(0x5)
#define mc_cfg_manual_address_map		(0x0)
#define mc_cfg_generate_refresh_on_srx		(0x1)
#define mc_init_interrupt_mask_0		(0x0)
#define mc_cfg_temp_ctrl_ref_mode		(0x1)
#define mc_cfg_hbm_tcr_enable			(0x1)
#define mc_cfg_en_rrdp				(0x0)
#define mc_cfg_ps_one_faw			(0x0)
#define mc_cfg_sbref_en				(0x1)
#define mc_cfg_lookahead_sbref			(0x1)
#define mc_cfg_advance_activate_ready		(0xa)
#define mc_ctrlr_soft_reset_n			(0x1)
#define mc_cfg_lookahead_pch			(0x1)
#define mc_cfg_lookahead_act			(0x1)
#define mc_init_autoinit_disable		(0x0)
#define mc_cfg_bl				(0x1)
#define mc_cfg_auto_ref_en			(0x1)
#define mc_init_self_refresh			(0x0)
#define mc_cfg_ctrlr_init_disable		(0x1)
#define mc_cfg_phyupd_ack_delay			(0x16)
#define mc_cfg_idle_time_to_self_refresh	(0x0)
#define mc_cfg_idle_time_to_power_down		(0x0)
#define mc_cfg_burst_rw_refresh_holdoff		(0x0)
//#define mc_init_refresh_count			(0x0)
#define mc_cfg_bg_interleave			(0x1)
#define mc_cfg_dbi_byte_disable_source		(0x0)
#define mc_cfg_dbi_byte_disable			(0x0)
#define mc_cfg_reorder_en			(0x1)
#define mc_cfg_reorder_queue_en			(0x1)
#define mc_cfg_intraport_reorder_en		(0x1)
#define mc_cfg_maintain_coherency		(0x1)
#define mc_cfg_q_age_limit			(0x3f)
#define mc_cfg_sbref_issue_per			(0x25)
#define mc_cfg_ro_delay_badperf_choice		(0x3)
#define mc_cfg_dm_en				(0x0)
#define mc_cfg_rmw_en				(0x1)
#define mc_cfg_ecc_bypass			(0x0)
#define mc_init_write_data_1b_ecc_error_gen	(0x0)
#define mc_init_write_data_2b_ecc_error_gen	(0x0)
#define mc_cfg_dfi_t_phy_rdlat			(0x8)
#define mc_cfg_dfi_t_phy_wrlat			(0x5)
#define mc_cfg_dfi_phyupd_en			(0x0)
#define mc_cfg_axi_start_address_axi		(0x0)
#define mc_cfg_axi_end_address_axi		(0xFFFFFFFF)
#define mc_cfg_mem_start_address_axi		(0x0)
#define mc_cfg_axi_auto_pch			(0x0)
#define mc_cfg_axird_id_reorder_en		(0x1)
#define mc_cfg_axird_interleave_sel		(0x1)

#if (HBM_DATA_FREQ == 2400)
#define mc_cfg_ccd_s				(0x2)
#define mc_cfg_ccd_l				(0x4)
#define mc_cfg_rrd_s				(0x5)
#define mc_cfg_rrd_l				(0x5)
#define mc_cfg_wtr_s				(0x5)
#define mc_cfg_wtr_l				(0xB)
#define mc_cfg_en_rrdp				(0x0)
#define mc_cfg_ps_one_faw			(0x0)
#define mc_cfg_ccd_r				(0x3)
#define mc_cfg_rrefd				(0xA)
#define mc_cfg_rfcsb				(0xC1)
#define mc_cfg_rcd_rd				(0x11)
#define mc_cfg_rcd_wr				(0xD)
//#define mc_cfg_ras				(0x28)
#define mc_cfg_rp				(0x11)
#define mc_cfg_rc				(0x39)
#define mc_cfg_faw				(0x14)
#define mc_cfg_rfc				(0x1A6)
#define mc_cfg_rtp				(0x5)
#define mc_cfg_xp				(0xA)
#define mc_cfg_read_to_write			(0x4)
#define mc_cfg_ref_per				(0x1248)
#define mc_cfg_xs				(0x1b2)
#define mc_cfg_cksre				(0xD)
#define mc_cfg_cksrx				(0xD)
#define mc_cfg_dfi_t_rddata_en			(0x13)

/*
 *#elif(HBM_DATA_FREQ == 2000) loose
 *#define mc_cfg_ccd_s				(0x2)
 *#define mc_cfg_ccd_l				(0x4)
 *#define mc_cfg_rrd_s				(0x5)
 *#define mc_cfg_rrd_l				(0x5)
 *#define mc_cfg_wtr_s				(0x9)
 *#define mc_cfg_wtr_l				(0xe)
 *#define mc_cfg_en_rrdp				(0x0)
 *#define mc_cfg_ps_one_faw			(0x0)
 *#define mc_cfg_ccd_r				(0x4)
 *#define mc_cfg_rrefd				(0xA)
 *#define mc_cfg_rfcsb				(0xB0)
 *#define mc_cfg_rcd_rd				(0xf)
 *#define mc_cfg_rcd_wr				(0xB)
 *///#define mc_cfg_ras				(0x23)
/*#define mc_cfg_rp				(0xf)
 *#define mc_cfg_rc				(0x35)
 *#define mc_cfg_faw				(0x15)
 *#define mc_cfg_rfc				(0x180)
 *#define mc_cfg_rtp				(0x8)
 *#define mc_cfg_xp				(0xa)
 *#define mc_cfg_read_to_write			(0x9)
 *#define mc_cfg_ref_per				(0xd00)
 *#define mc_cfg_xs				(0x170)
 *#define mc_cfg_cksre				(0xf)
 *#define mc_cfg_cksrx				(0xf)
 *#define mc_cfg_dfi_t_rddata_en			(0x12)
 */

#elif(HBM_DATA_FREQ == 2000) //tight
#define mc_cfg_ccd_s				(0x2)
#define mc_cfg_ccd_l				(0x4)
#define mc_cfg_rrd_s				(0x4)
#define mc_cfg_rrd_l				(0x4)
#define mc_cfg_wtr_s				(0x4)
#define mc_cfg_wtr_l				(0x9)
#define mc_cfg_en_rrdp				(0x0)
#define mc_cfg_ps_one_faw			(0x0)
#define mc_cfg_ccd_r				(0x3)
#define mc_cfg_rrefd				(0x8)
#define mc_cfg_rfcsb				(0xA0)
#define mc_cfg_rcd_rd				(0xe)
#define mc_cfg_rcd_wr				(0xA)
//#define mc_cfg_ras				(0x21)
#define mc_cfg_rp				(0xe)
#define mc_cfg_rc				(0x2f)
#define mc_cfg_faw				(0x10)
#define mc_cfg_rfc				(0x15E)
#define mc_cfg_rtp				(0x5)
#define mc_cfg_xp				(0x8)
#define mc_cfg_read_to_write			(0x4)
#define mc_cfg_ref_per				(0xf30)
#define mc_cfg_xs				(0x168)
#define mc_cfg_cksre				(0xA)
#define mc_cfg_cksrx				(0xA)
#define mc_cfg_dfi_t_rddata_en			(0x12)

#elif(HBM_DATA_FREQ == 1600)
#define mc_cfg_ccd_s				(0x2)
#define mc_cfg_ccd_l				(0x4)
#define mc_cfg_rrd_s				(0x4)
#define mc_cfg_rrd_l				(0x4)
#define mc_cfg_wtr_s				(0x4)
#define mc_cfg_wtr_l				(0x9)
#define mc_cfg_en_rrdp				(0x0)
#define mc_cfg_ps_one_faw			(0x0)
#define mc_cfg_ccd_r				(0x3)
#define mc_cfg_rrefd				(0x8)
#define mc_cfg_rfcsb				(0xA0)
#define mc_cfg_rcd_rd				(0xe)
#define mc_cfg_rcd_wr				(0xA)
//#define mc_cfg_ras				(0x21)
#define mc_cfg_rp				(0xe)
#define mc_cfg_rc				(0x2f)
#define mc_cfg_faw				(0x10)
#define mc_cfg_rfc				(0x15E)
#define mc_cfg_rtp				(0x5)
#define mc_cfg_xp				(0x8)
#define mc_cfg_read_to_write			(0x4)
#define mc_cfg_ref_per				(0xc20)
#define mc_cfg_xs				(0x168)
#define mc_cfg_cksre				(0xA)
#define mc_cfg_cksrx				(0xA)
#endif

#define mc_mt_stop_on_error			(0)
#define mc_mt_alg_auto_pch			(0)
#define mc_mt_addr_bits				(26)
#define mc_mt_start_addr			(0)
#define mc_mt_arb_mem_addr			(0)
#define mc_mt_cycles				(8)


// HBM value
#define  m_hbm_dram_test_mode			(0) //(0b0)
#define  m_hbm_dram_tcsr			(0) //(0b0)
#define  m_hbm_dram_driver_strength		(4) //(0b000) //0b100 max
#define  m_hbm_dram_bank			(1) //(0b1)
#define  m_hbm_dram_bl				(1) //(0b1)
#define  m_hbm_dram_trr				(0) //(0b0)
#define  m_hbm_dram_trr_pss			(0) //(0b0)
#define  m_hbm_dram_trr_mode_ban		(0) //(0b0000)
#define  m_hbm_dram_cattrip			(0) //(0b0)
#define  m_hbm_dram_misr_ctrl			(0) //(0b000)
#define  m_hbm_dram_read_mux_ctrl		(1) //(0b01)
#define  m_hbm_dram_lpbk			(0) //(0b0)
#define  m_hbm_dram_da_lockout			(0) //(0b0)
#define  m_hbm_dram_vref			(0) //(0b000)

#if (HBM_DATA_FREQ == 2400)
#define m_hbm_dram_driver_wr			(0x14) //(0b10100)
#define m_hbm_dram_wl				(0x7)  //(0b111)
#define m_hbm_dram_ras				(0x28) //(0b101000)
#define m_hbm_dram_impre_trp			(0x0)  //(0b000000)
#elif(HBM_DATA_FREQ == 2000 || HBM_DATA_FREQ == 1600)
#define m_hbm_dram_driver_wr			(0x10) //(0b10000)//0b10000 tight 0b10011 loose
#define m_hbm_dram_wl				(0x6)  //(0b110)
#define m_hbm_dram_ras				(0x21) //(0b100001)//0b100001 tight 0b100011 loose
#define m_hbm_dram_impre_trp			(0x0)  //(0b000000)
#endif
#define phy_driver_impedance			(0xf)  //(0b0001) //0b1111 max


// Firmware HBM Parameters offset
#define HBM_MAX_TIMEOUT				(1)
#define HBM_TINIT1_CYCLES			(2)
#define HBM_TINIT2_CYCLES			(3)
#define HBM_TINIT3_CYCLES			(4)
#define HBM_TINIT4_CYCLES			(5)
#define HBM_TINIT5_CYCLES			(6)
#define HBM_MODE_REGISTER0			(10)
#define HBM_MODE_REGISTER1			(11)
#define HBM_MODE_REGISTER2			(12)
#define HBM_MODE_REGISTER3			(13)
#define HBM_MODE_REGISTER4			(14)
#define HBM_MODE_REGISTER5			(15)
#define HBM_MODE_REGISTER6			(16)
#define HBM_MODE_REGISTER7			(17)
#define HBM_MODE_REGISTER8			(18)
#define HBM_MODE_REGISTER15			(58)
#define HBM_PHY_CONFIG0				(19)
#define HBM_PHY_CONFIG1				(20)
#define HBM_PHY_CONFIG2				(21)
#define HBM_PHY_CONFIG3				(22)
#define HBM_PHY_CONFIG4				(23)
#define HBM_PHY_CONFIG5				(24)
#define HBM_PHY_CONFIG6				(25)
#define HBM_T_RDLAT_OFFSET			(30)
#define HBM_POWER_ON_LANE_REPAIR_MODE		(35)
#define HBM_FREQ				(39)
#define HBM_DIV_MODE				(40)
#define HBM_STACK_HEIGHT			(64)
#define HBM_PARITY_LATENCY			(68)

/* HBM_PLLx_BASE_ADDR */
#define CR_PLLCFG0				(0x00)
#define CR_PLLCFG1				(0x04)
#define CR_PLLCFG2				(0x08)
#define CR_PLLCFG3				(0x0C)
#define CR_PLLCFG4				(0x10)
#define CR_PLLCFG5				(0x14)
#define CR_PLLCFG6				(0x18)
#define CR_PLLCFG7				(0x1C)

#define MLU290_PHY_NUM				(4)
#define MLU290_HBMSYS_NUM_PER_PHY		(2)
#define MLU290_MC_NUM_PER_HBMSYS		(4)

#define MAX_PHY_NUM				(10)
#define MAX_HBMSYS_NUM_PER_PHY			(10)
#define MAX_MC_NUM_PER_HBMSYS			(10)
/* SN code */
#define PMU_CR_BASE_ADDR			(0x5000)
#define HBM_RESETN				(0x08)
#define PMU_RSV_BASE				(0x20004)
#define PMU_RSV(n)				(PMU_RSV_BASE + 0x4*(n))
#define SNCODE_H				PMU_RSV(3)
#define SNCODE_L				PMU_RSV(2)


enum board_type {
	MLU290_EVB = 0,
	MLU290_NULL,
};

struct hbmsys {
	unsigned int mc_base_addr[MAX_MC_NUM_PER_HBMSYS];
	unsigned int rc_base_addr;
	unsigned int llc_base_addr;
	unsigned int mfbc_base_addr;
};

struct hbmphy {
	struct hbmsys hbmsys[MAX_HBMSYS_NUM_PER_PHY];
	unsigned int phy_base_addr;
	unsigned int pll_base_addr;
};

struct ddr_board_set {
	struct cn_core_set *core;
	enum board_type type;
	u64 sncode;
	u8 phy_num;
	u8 hbmsys_num_per_phy;
	u8 mc_num_per_hbmsys;
	u8 channel_num;
	u8 bank_num_per_channel;

	unsigned int mc_cfg_ecc_1bit_int_thresh;
	unsigned int m_hbm_dram_ecc;
	unsigned int m_hbm_dram_dm;
	unsigned int m_hbm_dram_dbiac_write;
	unsigned int m_hbm_dram_dbiac_read;
	unsigned int m_hbm_dram_ac_parity;
	unsigned int m_hbm_dram_dq_w_parity;
	unsigned int m_hbm_dram_dq_r_parity;
	unsigned int m_hbm_dram_pl;
	unsigned int m_hbm_dram_rl;

	unsigned int mission_mode_mr0;
	unsigned int mission_mode_mr1;
	unsigned int mission_mode_mr2;
	unsigned int mission_mode_mr3;
	unsigned int mission_mode_mr4;
	unsigned int mission_mode_mr5;
	unsigned int mission_mode_mr6;
	unsigned int mission_mode_mr7;
	unsigned int mission_mode_mr8;
	unsigned int mission_mode_mr15;
	unsigned int phy_config[4];
	struct hbmphy hbmphy[MAX_PHY_NUM];
};

static void hbm_sbus_write(u8 hbm_num, unsigned int device_addr,
	unsigned int local_addr, unsigned int data, struct ddr_board_set *board)
{
	unsigned int device_addr_offset = GET_BITS_VAL(device_addr, 6, 0);
	unsigned int local_addr_offset = GET_BITS_VAL(local_addr, 7, 0);
	unsigned int addr = 0;

	SET_BITS_VAL(addr, 1, 0, 0);
	SET_BITS_VAL(addr, 9, 2, local_addr_offset);
	SET_BITS_VAL(addr, 16, 10, device_addr_offset);
	SET_BITS_VAL(addr, 31, 17, 0);
	hbm_reg_wt32(board->hbmphy[hbm_num].phy_base_addr + addr, data, board->core->bus_set);
}

static unsigned int hbm_sbus_read(u8 hbm_num, unsigned int device_addr,
			unsigned int local_addr, struct ddr_board_set *board)
{
	unsigned int device_addr_offset = GET_BITS_VAL(device_addr, 6, 0);
	unsigned int local_addr_offset = GET_BITS_VAL(local_addr, 7, 0);
	unsigned int addr = 0;

	SET_BITS_VAL(addr, 1, 0, 0);
	SET_BITS_VAL(addr, 9, 2, local_addr_offset);
	SET_BITS_VAL(addr, 16, 10, device_addr_offset);
	SET_BITS_VAL(addr, 31, 17, 0);
	return hbm_reg_rd32(board->hbmphy[hbm_num].phy_base_addr + addr, board->core->bus_set);
}

static void SET_ARRAY_VAL(unsigned int *nval, unsigned int end, unsigned int start,
							unsigned int nNum)
{
	unsigned int index_start = start / 32;
	unsigned int index_end = end / 32;
	unsigned int bit_start = start % 32;
	unsigned int bit_end = end % 32;

	if (index_start == index_end)
		SET_BITS_VAL(nval[index_start], bit_end, bit_start, nNum);
	else if (index_start == index_end - 1) {
		SET_BITS_VAL(nval[index_start], 31, bit_start, nNum);
		SET_BITS_VAL(nval[index_end], bit_end, 0, (nNum >> (32 - bit_start)));
	} else
		cn_dev_err("error SET_BITS_VAL start:%d, end:%d", start, end);
}

static unsigned int GET_ARRAY_VAL(unsigned int *nval, unsigned int end,
							unsigned int start)
{
	unsigned int rd_data = 0;
	unsigned int index_start = start / 32;
	unsigned int index_end = end / 32;
	unsigned int bit_start = start % 32;
	unsigned int bit_end = end % 32;

	if (index_start == index_end)
		rd_data = GET_BITS_VAL(*(nval + index_start), bit_end, bit_start);
	else if (index_start == index_end - 1) {
		rd_data = GET_BITS_VAL(*(nval + index_start), 31, bit_start);
		rd_data |= GET_BITS_VAL(*(nval + index_end), bit_end, 0)
							<< (32 - bit_start);
	} else
		cn_dev_err("error GET_BITS_VAL start:%d, end:%d", start, end);

	return rd_data;
}

static int wait_for_1500_done(u8 hbm_num, unsigned int expected,
						struct ddr_board_set *board)
{
	unsigned int done = 0;
	unsigned int data = 0;
	unsigned int timeout = 0;
	int ret = 0;

	done = expected ^ 1;
	while ((done != expected) && timeout < 100) {
		usleep_range(1, 2);
		data = hbm_sbus_read(hbm_num, APC_ADDR, BUSY_DONE_1500_REG, board);
		done = GET_BITS_VAL(data, 0, 0);
		timeout++;
	}
	if (timeout >= 100) {
		cn_dev_core_err(board->core, "hbm%d wait for 1500 DONE timeout",
								hbm_num);
		ret = 1;
	}

	return ret;
}

static int apc_1500_busy_done_handshake(u8 hbm_num, struct ddr_board_set *board)
{
	int ret = 0;
	int error = 0;

	ret = wait_for_1500_done(hbm_num, 1, board);
	error |= ret;
	hbm_sbus_write(hbm_num, APC_ADDR, CONTROL_1500, STOP_1500, board);
	ret = wait_for_1500_done(hbm_num, 0, board);
	error |= ret;

	return error;
}

static void wir_write_channel(u8 hbm_num, unsigned int device_sel,
	unsigned int channel, unsigned int instruction, unsigned int instr_length,
						struct ddr_board_set *board)
{
	int ret = 0;
	unsigned int current_instr_length = 0;
	unsigned int data = 0;

	SET_BITS_VAL(data, 7, 0, instruction);
	SET_BITS_VAL(data, 11, 8, channel);
	SET_BITS_VAL(data, 12, 12, device_sel);
	SET_BITS_VAL(data, 31, 13, 0);

	current_instr_length = instr_length;
	hbm_sbus_write(hbm_num, APC_ADDR, WIR_REG, data, board);
	hbm_sbus_write(hbm_num, APC_ADDR, CONTROL_1500, START_WIR_WRITE, board);
	ret = apc_1500_busy_done_handshake(hbm_num, board);
}

static void wdr_read(u8 hbm_num, unsigned int length, unsigned int shift_only,
						struct ddr_board_set *board)
{
	int ret = 0;

	if (length > 320) {
		cn_dev_core_err(board->core, "hbm%d can not shift length%d>320",
							hbm_num, length);
	}
	hbm_sbus_write(hbm_num, APC_ADDR, CONTROL_1500, STOP_1500, board);

	if (shift_only == 1) {
		SET_BITS_VAL(length, 9, 9, 1);
		hbm_sbus_write(hbm_num, APC_ADDR, WDR_CONFIG_REG, length, board); // SHIFT_ONLY
	} else
		hbm_sbus_write(hbm_num, APC_ADDR, WDR_CONFIG_REG, length, board);

	hbm_sbus_write(hbm_num, APC_ADDR, CONTROL_1500, START_WDR_READ, board);
	ret = apc_1500_busy_done_handshake(hbm_num, board);
}

static unsigned int WDR_READ_DATA[] = {
		WDR_READ_DATA_31_0,
		WDR_READ_DATA_63_32,
		WDR_READ_DATA_95_64,
		WDR_READ_DATA_127_96,
		WDR_READ_DATA_159_128,
		WDR_READ_DATA_191_160,
		WDR_READ_DATA_223_192,
		WDR_READ_DATA_255_224,
		WDR_READ_DATA_287_256,
		WDR_READ_DATA_319_288
};

static void wdr_read_sbus_data(u8 hbm_num, unsigned int channel,
	unsigned int *result, unsigned int length, struct ddr_board_set *board)
{
	int i = 0;
	unsigned int mask = (length / 32) * 32;
	int wr_bits = 0;
	int MIN_LOOP = ((length / 32) >= 10) ? 10 : ((length % 32 != 0) ?
					(length / 32 + 1) : (length / 32));

	hbm_sbus_write(hbm_num, APC_ADDR, READ_CHANNEL, (1 << channel), board);
	for (wr_bits = 0; wr_bits < MIN_LOOP; wr_bits++) {
		result[wr_bits] = hbm_sbus_read(hbm_num, APC_ADDR,
						WDR_READ_DATA[wr_bits], board);
		cn_dev_core_debug(board->core,
			"INFO: Reading sbus data wr_bits:%d data:%#x",
						wr_bits, result[wr_bits]);
	}

	if (mask < length) {
		for (i = length; i < mask + 32; i++) {
			SET_ARRAY_VAL(result, i, i, 0);
		}
	}

	for (i = 0; i < length / 32; i++) {
		cn_dev_core_debug(board->core,
			"INFO: Reading sbus data wr_bits:%d  final data:%#x",
							i, result[i]);
	}
}

static int sbus_master_spico_interrupt(u8 hbm_num, unsigned int interrupt_code,
			unsigned int interrupt_value, unsigned int *data,
			struct ddr_board_set *board)
{
	int ret = 0;
	unsigned int timeout = 0;
	unsigned int rd_data;
	struct cn_core_set *core = board->core;

	// Set spico interrupt code and value
	hbm_sbus_write(hbm_num, SNAP_ADDR, 2,
			((interrupt_value << 16) | interrupt_code), board);
	// Assert Interrupt
	rd_data = hbm_sbus_read(hbm_num, SNAP_ADDR, 7, board);
	hbm_sbus_write(hbm_num, SNAP_ADDR, 7, rd_data | 1, board);
	// Lower Interrupt
	hbm_sbus_write(hbm_num, SNAP_ADDR, 7, rd_data & 0xFFFFFFFE, board);
	// Wait for interrupt to complete
	while (timeout < 1000) {
		rd_data = hbm_sbus_read(hbm_num, SNAP_ADDR, 8, board);
		if ((rd_data & 0x8000) == 0)
			break;
		timeout++;
		usleep_range(1000, 1500);
	}
	if (timeout >= 1000) {
		cn_dev_core_err(core, "hbm%d interrupt%#x timeout rd_data=%#x",
						hbm_num, interrupt_code, rd_data);
		ret = -1;
	} else {
		rd_data = hbm_sbus_read(hbm_num, SNAP_ADDR, 8, board);
		*data = (rd_data >> 16) & 0xFFFF;
	}

	return ret;
}

static void set_hbm_parameter(u8 hbm_num, unsigned int offset,
				unsigned int value, struct ddr_board_set *board)
{
	int ret = 0;
	unsigned int rd_data;

	ret = sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_SET_PARAM,
						offset, &rd_data, board);
	if (rd_data != 1 || ret) {
		cn_dev_core_err(board->core, "FW_SET_PARAM error:rd_data=%d,ret=%d",
							rd_data, ret);
	}
	ret = sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_SET_PARAM_VALUE,
							value, &rd_data, board);
	if (rd_data != 1 || ret) {
		cn_dev_core_err(board->core, "FW_SET_VALUE error:rd_data=%d,ret=%d",
							rd_data, ret);
	}
	/* check write value*/
	ret = sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_GET_PARAM_VALUE,
							offset, &rd_data, board);
	if (rd_data != value || ret) {
		cn_dev_core_err(board->core, "FW_GET_VALUE error:rd_data=%d,ret=%d",
							rd_data, ret);
	}
}

#if 0
static u64 ddr_get_sncode(struct cn_core_set *core)
{
	u64 sncode;
	u64 sncode_h;
	u64 sncode_l;

	sncode_h = hbm_reg_rd32(SNCODE_H, core->bus_set);
	sncode_l = hbm_reg_rd32(SNCODE_L, core->bus_set);
	sncode = ((sncode_h & 0xffff) << 32) | sncode_l;

	return sncode;
}

static void get_board_type(struct ddr_board_set *board)
{
	u64 sncode;
	u64 card_type;
	enum board_type type;

	sncode = ddr_get_sncode(board->core);
	board->sncode = sncode;
	card_type = (sncode >> 40);
	switch (card_type) {
	case 0x30:
		type = MLU290_EVB;
		break;
	default:
		type = MLU290_NULL;
	}
	board->type = type;
}
#endif
static int ddr_board_info_init(struct ddr_board_set *board)
{
	int i, j, k;
	struct cn_core_set *core = board->core;

	cn_dev_core_debug(core, "enter ddr board info init");
	board->type = MLU290_EVB; //get_board_type(board);//!!!remember to revise
	switch (board->type) {
	case MLU290_EVB:
		board->phy_num = MLU290_PHY_NUM;
		board->hbmsys_num_per_phy = MLU290_HBMSYS_NUM_PER_PHY;
		board->mc_num_per_hbmsys = MLU290_MC_NUM_PER_HBMSYS;
		board->channel_num = 8;
		board->bank_num_per_channel = 16;
		break;
	default:
		cn_dev_core_err(core, "Invalid Card_Type is %#x",
							board->type);
		return -1;
	}

	for (i = 0; i < board->phy_num; i++) {
		board->hbmphy[i].phy_base_addr = HBM_PHY_BASE_ADDR + 0x20000 * i;
		switch (i) {
		case 0:
			board->hbmphy[i].pll_base_addr = HBM_PLL0_BASE_ADDR;
			break;
		case 1:
			board->hbmphy[i].pll_base_addr = HBM_PLL1_BASE_ADDR;
			break;
		case 2:
			board->hbmphy[i].pll_base_addr = HBM_PLL2_BASE_ADDR;
			break;
		case 3:
			board->hbmphy[i].pll_base_addr = HBM_PLL3_BASE_ADDR;
			break;
		default:
			break;
		}
		for (j = 0; j < board->hbmsys_num_per_phy; j++) {
			board->hbmphy[i].hbmsys[j].rc_base_addr =
				HBM_RC_BASE_ADDR +
				0x4000 * (i * (board->hbmsys_num_per_phy) + j);
			board->hbmphy[i].hbmsys[j].llc_base_addr =
				HBM_LLC_BASE_ADDR +
				0x4000 * (i * (board->hbmsys_num_per_phy) + j);
			board->hbmphy[i].hbmsys[j].mfbc_base_addr =
				HBM_MFBC_BASE_ADDR +
				0x4000 * (i * (board->hbmsys_num_per_phy) + j);
			for (k = 0; k < board->mc_num_per_hbmsys; k++) {
				board->hbmphy[i].hbmsys[j].mc_base_addr[k] =
					HBM_MC_BASE_ADDR +
					0x100000 * (i * board->hbmsys_num_per_phy + j)
					+ 0x40000 * k;
			}
		}
	}

	board->mc_cfg_ecc_1bit_int_thresh = 0xff;
	board->m_hbm_dram_ecc = 1;
	board->m_hbm_dram_dm = 1; /* 0:enable 1:disable always disable*/
	board->m_hbm_dram_dbiac_write = 0;
	board->m_hbm_dram_dbiac_read = 0;
	board->m_hbm_dram_ac_parity = 1;
	board->m_hbm_dram_dq_w_parity = 1;
	board->m_hbm_dram_dq_r_parity = 1;
	board->m_hbm_dram_pl = 2;
	board->m_hbm_dram_rl = 21 - 2;
	board->phy_config[0] = 0x0c4ca40c;
	board->phy_config[1] = 0x0c984ca4;
	board->phy_config[2] = 0xa40c4ca4;
	board->phy_config[3] = 0x0000004c;
	cn_dev_core_debug(core, "exit ddr board info init");

	return 0;
}

static int ddr_do_pll_init(struct ddr_board_set *board, u8 hbm_num)
{
	int ret = 0;
	unsigned int time_out = 0;
	unsigned int expect_ndiv_value = (48 << 20);
	unsigned int current_ndiv_value;
	unsigned int hbm_data_freq = HBM_DATA_FREQ;
	unsigned int apb_pll_addr;
	unsigned int rd_data;
	struct cn_core_set *core = board->core;

	cn_dev_core_debug(core, "enter ddr do pll init");
	apb_pll_addr = board->hbmphy[hbm_num].pll_base_addr;
	switch (hbm_data_freq) {
	case 2400:
		expect_ndiv_value = (48 << 20);
		break;
#if 0
	case 2000:
		expect_ndiv_value = (40 << 20);
		break;
	case 1600:
		expect_ndiv_value = (32 << 20);
		break;
	default:
		cn_dev_core_err(core, "NO KNOW hbm_data_freq");
		break;
#endif
	}

	current_ndiv_value = hbm_reg_rd32(apb_pll_addr + CR_PLLCFG0, core->bus_set);
	if (current_ndiv_value == expect_ndiv_value) {
		cn_dev_core_debug(core, "exit ddr do pll init");
		return ret;
	}

	hbm_reg_wt32(apb_pll_addr + CR_PLLCFG0, expect_ndiv_value, core->bus_set);
	hbm_reg_wt32(apb_pll_addr + CR_PLLCFG5, 0x10001, core->bus_set);

	do {
		rd_data = hbm_reg_rd32(apb_pll_addr + CR_PLLCFG5, core->bus_set);
		usleep_range(1, 2);
		time_out++;
	} while ((rd_data & 0x01) && (time_out < 1000));

	if (time_out >= 1000) {
		rd_data = hbm_reg_rd32(apb_pll_addr + CR_PLLCFG6, core->bus_set);
		if ((rd_data & 0x02) == 0) {
			cn_dev_core_err(core, "hbm%d wait pll lock timeout!",
							hbm_num);
			ret = -1;
		}
	}
	cn_dev_core_debug(core, "exit ddr do pll init");

	return ret;
}

static int hbm_dram_init(struct ddr_board_set *board)
{
	unsigned int hbm_data_freq = HBM_DATA_FREQ;

	cn_dev_core_debug(board->core, "enter hbm dram init");
	board->mc_cfg_ecc_1bit_int_thresh = 0xf;
	board->m_hbm_dram_ecc = 1;
	board->m_hbm_dram_dbiac_write = 1;
	board->m_hbm_dram_dbiac_read = 1;
	board->m_hbm_dram_ac_parity = 1;
	board->m_hbm_dram_dq_w_parity = 1;
	board->m_hbm_dram_dq_r_parity = 1;

	switch (hbm_data_freq) {
	case 2400: {
		if (board->m_hbm_dram_dbiac_write) {
			board->m_hbm_dram_pl = 1;
			board->m_hbm_dram_rl = 26 - 2;
		} else {
			board->m_hbm_dram_pl = 2;
			board->m_hbm_dram_rl = 25 - 2;
		}
	}
	break;
#if 0
	case 2000: {
		if (board->m_hbm_dram_dbiac_write) {
			board->m_hbm_dram_pl = 1;
			board->m_hbm_dram_rl = 22 - 2;
		} else {
			board->m_hbm_dram_pl = 2;
			board->m_hbm_dram_rl = 21 - 2;
		}
	}
	break;
	default:
		cn_dev_core_err(board->core, "NO KNOW hbm_data_freq");
		return -1;
#endif
	}
	cn_dev_core_info(board->core, "current freq: %d, DBI Opened, ECC Opened",
								hbm_data_freq);
	cn_dev_core_debug(board->core, "exit hbm dram init");

	return 0;
}

static void phy_disable_mcu_access(struct cn_core_set *core)
{
	unsigned int rd_data;

	rd_data = hbm_reg_rd32(0x78, core->bus_set);
	rd_data &= (~0x08U);
	hbm_reg_wt32(0x78, rd_data, core->bus_set);
	msleep(100);/* must 100ms */
}

static void phy_enable_mcu_access(struct cn_core_set *core)
{
	unsigned int rd_data;

	rd_data = hbm_reg_rd32(0x78, core->bus_set);
	rd_data |= (0x08U);
	hbm_reg_wt32(0x78, rd_data, core->bus_set);
}

static int ddr_do_pmu_reset_assert(struct cn_core_set *core, u8 hbm_num)
{
	int ret = 0;
	unsigned int hbm_reset_mask;
	unsigned int hbm_reset_value;
	unsigned int rd_data;

	hbm_reset_mask = (0x03 << (hbm_num * 2)) | (0x100 << hbm_num);
	hbm_reset_value = (hbm_reset_mask << 16) | 0;
	hbm_reg_wt32(PMU_CR_BASE_ADDR + HBM_RESETN, hbm_reset_value, core->bus_set);

	rd_data = hbm_reg_rd32(PMU_CR_BASE_ADDR + HBM_RESETN, core->bus_set);
	if ((rd_data & hbm_reset_mask) != 0) {
		ret = -1;
	}

	return ret;
}

static int ddr_do_pmu_reset_release(struct cn_core_set *core, u8 hbm_num)
{
	int ret = 0;
	unsigned int hbm_reset_mask;
	unsigned int hbm_reset_value;
	unsigned int rd_data;

	hbm_reset_mask = (0x03 << (hbm_num * 2)) | (0x100 << hbm_num);
	hbm_reset_value = (hbm_reset_mask << 16) | hbm_reset_mask;
	hbm_reg_wt32(PMU_CR_BASE_ADDR + HBM_RESETN, hbm_reset_value, core->bus_set);

	rd_data = hbm_reg_rd32(PMU_CR_BASE_ADDR + HBM_RESETN, core->bus_set);
	if ((rd_data & hbm_reset_mask) != hbm_reset_mask) {
		ret = -1;
	}

	return ret;
}

static int ddr_do_hbm_reset_assert(struct ddr_board_set *board, u8 hbm_num)
{
	int ret = 0;
	int i;
	unsigned int rd_data;
	unsigned int apb_rc_addr;
	struct cn_core_set *core = board->core;

	for (i = 0; i < board->hbmsys_num_per_phy; i++) {
		apb_rc_addr = board->hbmphy[hbm_num].hbmsys[i].rc_base_addr;
		hbm_reg_wt32(apb_rc_addr + CFG_HBM_RESET_N, 0x0, core->bus_set);
		hbm_reg_wt32(apb_rc_addr + CFG_HBM_ARESET_N, 0x0, core->bus_set);
		hbm_reg_wt32(apb_rc_addr + CFG_LLC_ARESET_N, 0x0, core->bus_set);
		hbm_reg_wt32(apb_rc_addr + CFG_AXIMON_ARESET_N, 0x0, core->bus_set);
		hbm_reg_wt32(apb_rc_addr + CFG_HBM_MT_SEL, 0x0, core->bus_set);

		rd_data = hbm_reg_rd32(apb_rc_addr + CFG_HBM_RESET_N, core->bus_set);
		if (rd_data) {
			ret = -1;
			cn_dev_core_err(core, "read reg:%#x=%#x error",
					apb_rc_addr + CFG_HBM_RESET_N, rd_data);
		}
		rd_data = hbm_reg_rd32(apb_rc_addr + CFG_HBM_ARESET_N, core->bus_set);
		if (rd_data) {
			ret = -1;
			cn_dev_core_err(core, "read reg:%#x=%#x error",
					apb_rc_addr + CFG_HBM_ARESET_N, rd_data);
		}
		rd_data = hbm_reg_rd32(apb_rc_addr + CFG_LLC_ARESET_N, core->bus_set);
		if (rd_data) {
			ret = -1;
			cn_dev_core_err(core, "read reg:%#x=%#x error",
					apb_rc_addr + CFG_LLC_ARESET_N, rd_data);
		}
		rd_data = hbm_reg_rd32(apb_rc_addr + CFG_AXIMON_ARESET_N, core->bus_set);
		if (rd_data) {
			ret = -1;
			cn_dev_core_err(core, "read reg:%#x=%#x error",
					apb_rc_addr + CFG_AXIMON_ARESET_N, rd_data);
		}
		rd_data = hbm_reg_rd32(apb_rc_addr + CFG_HBM_MT_SEL, core->bus_set);
		if (rd_data) {
			ret = -1;
			cn_dev_core_err(core, "read reg:%#x=%#x error",
					apb_rc_addr + CFG_HBM_MT_SEL, rd_data);
		}
	}

	return ret;
}

static int ddr_do_hbm_reset_release(struct ddr_board_set *board, u8 hbm_num)
{
	int ret = 0;
	int i;
	unsigned int apb_rc_addr;
	unsigned int rd_data;
	struct cn_core_set *core = board->core;

	for (i = 0; i < board->hbmsys_num_per_phy; i++) {
		apb_rc_addr = board->hbmphy[hbm_num].hbmsys[i].rc_base_addr;
		hbm_reg_wt32(apb_rc_addr + CFG_HBM_RESET_N, 0x1, core->bus_set);
		hbm_reg_wt32(apb_rc_addr + CFG_HBM_ARESET_N, 0x1, core->bus_set);
		hbm_reg_wt32(apb_rc_addr + CFG_LLC_ARESET_N, 0x1, core->bus_set);
		hbm_reg_wt32(apb_rc_addr + CFG_AXIMON_ARESET_N, 0x1, core->bus_set);

		rd_data = hbm_reg_rd32(apb_rc_addr + CFG_HBM_RESET_N, core->bus_set);
		if (rd_data != 0x1) {
			ret = -1;
			cn_dev_core_err(core, "read reg:%#x=%#x error",
					apb_rc_addr + CFG_HBM_RESET_N, rd_data);
		}
		rd_data = hbm_reg_rd32(apb_rc_addr + CFG_HBM_ARESET_N, core->bus_set);
		if (rd_data != 0x1) {
			ret = -1;
			cn_dev_core_err(core, "read reg:%#x=%#x error",
					apb_rc_addr + CFG_HBM_ARESET_N, rd_data);
		}
		rd_data = hbm_reg_rd32(apb_rc_addr + CFG_LLC_ARESET_N, core->bus_set);
		if (rd_data != 0x1) {
			ret = -1;
			cn_dev_core_err(core, "read reg:%#x=%#x error",
					apb_rc_addr + CFG_LLC_ARESET_N, rd_data);
		}
		rd_data = hbm_reg_rd32(apb_rc_addr + CFG_AXIMON_ARESET_N, core->bus_set);
		if (rd_data != 0x1) {
			ret = -1;
			cn_dev_core_err(core, "read reg:%#x=%#x error",
					apb_rc_addr + CFG_AXIMON_ARESET_N, rd_data);
		}
	}

	return ret;
}

static unsigned int hbm_sbus_reg[] = {
	#include "hbm_sbus.h"
};

static int do_sbus_firmware_upload(struct ddr_board_set *board, u8 hbm_num)
{
	int i = 0;
	unsigned int rd_data;
	unsigned int time_out = 0;
	int hbm_reg_index = ARRAY_SIZE(hbm_sbus_reg);
	struct cn_core_set *core = board->core;

	// Halt the Processor
	hbm_sbus_write(hbm_num, SNAP_ADDR, 0x05, 0x01, board);
	// Place SPICO into Reset and Enable off
	hbm_sbus_write(hbm_num, SNAP_ADDR, 0x01, 0xC0, board);
	// Remove Reset, Enable off, IMEM_CNTL_EN on
	hbm_sbus_write(hbm_num, SNAP_ADDR, 0x01, 0x240, board);
	// Remove halt
	hbm_sbus_write(hbm_num, SNAP_ADDR, 0x05, 0x0, board);
	// Set starting IMEM address for burst download
	hbm_sbus_write(hbm_num, SNAP_ADDR, 0x03, 0x80000000, board);

	for (i = 0; i < hbm_reg_index; i++)
		hbm_sbus_write(hbm_num, SNAP_ADDR, 0x14, hbm_sbus_reg[i], board);

	// Set IMEM_CNTL_EN off
	hbm_sbus_write(hbm_num, SNAP_ADDR, 0x01, 0x40, board);
	// Turn ECC on
	hbm_sbus_write(hbm_num, SNAP_ADDR, 0x16, 0xC0000, board);
	// Set SPICO_ENABLE on
	hbm_sbus_write(hbm_num, SNAP_ADDR, 0x01, 0x140, board);

	usleep_range(1000, 1500);//waiting  for spico to initialize
	rd_data = hbm_sbus_read(hbm_num, SNAP_ADDR, 0x0f, board);
	while ((GET_BITS_VAL(rd_data, 4, 0) != 0x12) &&
				(GET_BITS_VAL(rd_data, 4, 0) != 0x1f) && (time_out < 1000)) {
		usleep_range(1, 2);
		rd_data = hbm_sbus_read(hbm_num, SNAP_ADDR, 0x0f, board);
		time_out++;
	}
	if (time_out >= 1000) {
		cn_dev_core_err(core, "read reg:%#x=%#x timeout",
							SNAP_ADDR, rd_data);
		return -1;
	}

	return 0;
}

static int ddr_do_sbus_init(struct ddr_board_set *board, u8 hbm_num)
{
	int ret, i;
	unsigned int idcode = 0;
	unsigned int last_sbus_address = 0;
	unsigned int rd_data;
	char *device_name;
	struct cn_core_set *core = board->core;

	/* set sbus ctrl clk divider*/
	hbm_sbus_write(hbm_num, SCTRL_ADDR, 0x0a, SBUS_CLK_DIVIDER, board);
	rd_data = hbm_sbus_read(hbm_num, SCTRL_ADDR, 0x0a, board);
	if (rd_data != SBUS_CLK_DIVIDER)
		return -1;
	usleep_range(1, 2);
	/* verify_sbus*/
	last_sbus_address = hbm_sbus_read(hbm_num, SCTRL_ADDR, 0x02, board);
	cn_dev_core_debug(core, "Total Sbus devices:%d", last_sbus_address);
	for (i = 1; i < last_sbus_address; i++) {
		idcode = hbm_sbus_read(hbm_num, i, 0xff, board);
		switch (idcode) {
		case 0x2a:
			device_name = "HBM_APC";
			break;
		case 0x10:
			device_name = "STOP";
			break;
		case 0x0f:
			device_name = "CTC";
			break;
		case 0x0a:
			device_name = "PLL";
			break;
		default:
			cn_dev_core_err(core, "UNKNOWN idcode=%d", idcode);
			ret = -1;
			return ret;
		}
		cn_dev_core_info(core, "Sbus Device%d Idcode%#x device%s",
						i, idcode, device_name);
	}

	ret = do_sbus_firmware_upload(board, hbm_num);
	if (ret)
		cn_dev_core_err(core, "do_sbus_firmware_upload error");
	ret = sbus_master_spico_interrupt(hbm_num, 0x0, 0, &rd_data, board);
	if (!ret)
		cn_dev_core_info(core, "Spico Firmware Revision: 0x%04x",
							rd_data);
	ret = sbus_master_spico_interrupt(hbm_num, 0x1, 0, &rd_data, board);
	if (!ret)
		cn_dev_core_info(core, "Spico Firmware Build ID: 0x%04x",
							rd_data);

	return ret;
}

static void set_mode_registers_values(struct ddr_board_set *board)
{
	SET_BITS_VAL(board->mission_mode_mr0, 7, 7, m_hbm_dram_test_mode);
	SET_BITS_VAL(board->mission_mode_mr0, 6, 6, board->m_hbm_dram_ac_parity);
	SET_BITS_VAL(board->mission_mode_mr0, 5, 5, board->m_hbm_dram_dq_w_parity);
	SET_BITS_VAL(board->mission_mode_mr0, 4, 4, board->m_hbm_dram_dq_r_parity);
	SET_BITS_VAL(board->mission_mode_mr0, 3, 3, 0x0); //0b0
	SET_BITS_VAL(board->mission_mode_mr0, 2, 2, m_hbm_dram_tcsr);
	SET_BITS_VAL(board->mission_mode_mr0, 1, 1, board->m_hbm_dram_dbiac_write);
	SET_BITS_VAL(board->mission_mode_mr0, 0, 0, board->m_hbm_dram_dbiac_read);
	SET_BITS_VAL(board->mission_mode_mr1, 7, 5, m_hbm_dram_driver_strength);
	SET_BITS_VAL(board->mission_mode_mr1, 4, 0, m_hbm_dram_driver_wr);
	SET_BITS_VAL(board->mission_mode_mr2, 7, 3, board->m_hbm_dram_rl);
	SET_BITS_VAL(board->mission_mode_mr2, 2, 0, m_hbm_dram_wl);
	SET_BITS_VAL(board->mission_mode_mr3, 7, 7, m_hbm_dram_bl);
	SET_BITS_VAL(board->mission_mode_mr3, 6, 6, m_hbm_dram_bank);
	SET_BITS_VAL(board->mission_mode_mr3, 5, 0, m_hbm_dram_ras);
	SET_BITS_VAL(board->mission_mode_mr4, 7, 4, 0x0); //0b0
	SET_BITS_VAL(board->mission_mode_mr4, 3, 2, board->m_hbm_dram_pl);
	SET_BITS_VAL(board->mission_mode_mr4, 1, 1, board->m_hbm_dram_dm);
	SET_BITS_VAL(board->mission_mode_mr4, 0, 0, board->m_hbm_dram_ecc);
	SET_BITS_VAL(board->mission_mode_mr5, 7, 7, m_hbm_dram_trr);
	SET_BITS_VAL(board->mission_mode_mr5, 6, 6, m_hbm_dram_trr_pss);
	SET_BITS_VAL(board->mission_mode_mr5, 5, 4, 0x0); //0b0
	SET_BITS_VAL(board->mission_mode_mr5, 3, 0, m_hbm_dram_trr_mode_ban);
	SET_BITS_VAL(board->mission_mode_mr6, 7, 3, m_hbm_dram_impre_trp);
	SET_BITS_VAL(board->mission_mode_mr6, 2, 0, 0x0); //0b0
	SET_BITS_VAL(board->mission_mode_mr7, 7, 7, m_hbm_dram_cattrip);
	SET_BITS_VAL(board->mission_mode_mr7, 6, 6, 0x0); //0b0
	SET_BITS_VAL(board->mission_mode_mr7, 5, 3, m_hbm_dram_misr_ctrl);
	SET_BITS_VAL(board->mission_mode_mr7, 2, 1, m_hbm_dram_read_mux_ctrl);
	SET_BITS_VAL(board->mission_mode_mr7, 0, 0, m_hbm_dram_lpbk);
	SET_BITS_VAL(board->mission_mode_mr8, 7, 1, 0x0); //0b0
	SET_BITS_VAL(board->mission_mode_mr8, 0, 0, m_hbm_dram_da_lockout);
	SET_BITS_VAL(board->mission_mode_mr15, 7, 3, 0x0); //0b0
	SET_BITS_VAL(board->mission_mode_mr15, 2, 0, m_hbm_dram_vref);
}

static void set_phy_config_values(struct ddr_board_set *board)
{
	SET_ARRAY_VAL(board->phy_config, 18, 15, phy_driver_impedance);
	SET_ARRAY_VAL(board->phy_config, 24+18, 24+15, phy_driver_impedance);
	SET_ARRAY_VAL(board->phy_config, 55, 52, phy_driver_impedance);
	SET_ARRAY_VAL(board->phy_config, 56+18, 56+15, phy_driver_impedance);
	SET_ARRAY_VAL(board->phy_config, 80+18, 80+15, phy_driver_impedance);
}

static void set_phy_spico_params(struct ddr_board_set *board, u8 hbm_num)
{
	set_hbm_parameter(hbm_num, HBM_MAX_TIMEOUT, M_HBM_MAX_TIMEOUT, board);
	set_hbm_parameter(hbm_num, HBM_TINIT1_CYCLES, M_HBM_TINIT1_CYCLES, board);
	set_hbm_parameter(hbm_num, HBM_TINIT2_CYCLES, M_HBM_TINIT2_CYCLES, board);
	set_hbm_parameter(hbm_num, HBM_TINIT3_CYCLES, M_HBM_TINIT3_CYCLES, board);
	set_hbm_parameter(hbm_num, HBM_TINIT4_CYCLES, M_HBM_TINIT4_CYCLES, board);
	set_hbm_parameter(hbm_num, HBM_TINIT5_CYCLES, M_HBM_TINIT5_CYCLES, board);
	set_hbm_parameter(hbm_num, HBM_DIV_MODE, M_HBM_DIV_MODE, board);
	set_hbm_parameter(hbm_num, HBM_FREQ, HBM_DATA_FREQ, board);
	set_hbm_parameter(hbm_num, HBM_POWER_ON_LANE_REPAIR_MODE,
							M_HBM_REPAIR_MODE, board);
	set_mode_registers_values(board);
	set_hbm_parameter(hbm_num, HBM_MODE_REGISTER0, board->mission_mode_mr0, board);
	set_hbm_parameter(hbm_num, HBM_MODE_REGISTER1, board->mission_mode_mr1, board);
	set_hbm_parameter(hbm_num, HBM_MODE_REGISTER2, board->mission_mode_mr2, board);
	set_hbm_parameter(hbm_num, HBM_MODE_REGISTER3, board->mission_mode_mr3, board);
	set_hbm_parameter(hbm_num, HBM_MODE_REGISTER4, board->mission_mode_mr4, board);
	set_hbm_parameter(hbm_num, HBM_MODE_REGISTER5, board->mission_mode_mr5, board);
	set_hbm_parameter(hbm_num, HBM_MODE_REGISTER6, board->mission_mode_mr6, board);
	set_hbm_parameter(hbm_num, HBM_MODE_REGISTER7, board->mission_mode_mr7, board);
	set_hbm_parameter(hbm_num, HBM_MODE_REGISTER8, board->mission_mode_mr8, board);
	set_hbm_parameter(hbm_num, HBM_MODE_REGISTER15, board->mission_mode_mr15, board);

	set_phy_config_values(board);
	set_hbm_parameter(hbm_num, HBM_PHY_CONFIG0, board->phy_config[0] & 0xffff, board);
	set_hbm_parameter(hbm_num, HBM_PHY_CONFIG1, (board->phy_config[0] >> 16) & 0xffff, board);
	set_hbm_parameter(hbm_num, HBM_PHY_CONFIG2, board->phy_config[1] & 0xffff, board);
	set_hbm_parameter(hbm_num, HBM_PHY_CONFIG3, (board->phy_config[1] >> 16) & 0xffff, board);
	set_hbm_parameter(hbm_num, HBM_PHY_CONFIG4, board->phy_config[2] & 0xffff, board);
	set_hbm_parameter(hbm_num, HBM_PHY_CONFIG5, (board->phy_config[2] >> 16) & 0xffff, board);
	set_hbm_parameter(hbm_num, HBM_PHY_CONFIG6, board->phy_config[3] & 0xffff, board);

	set_hbm_parameter(hbm_num, HBM_STACK_HEIGHT, M_HBM_STACK_HEIGHT, board);
	set_hbm_parameter(hbm_num, HBM_PARITY_LATENCY, board->m_hbm_dram_pl, board);
	set_hbm_parameter(hbm_num, HBM_T_RDLAT_OFFSET, M_HBM_T_RDLAT_OFFSET, board);
}

static int hbm_firmware_operation(struct ddr_board_set *board, u8 hbm_num,
							unsigned int operation)
{
	int ret = 0;
	unsigned int rd_data;
	unsigned int time_out = 0;
	struct cn_core_set *core = board->core;

	// Run a firmware test operation
	ret = sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_OP_ON_ALL_CHN,
						operation, &rd_data, board);
	if (rd_data != 1 || ret) {
		cn_dev_core_err(core, "sbus_master_spico_interrupt error");
		return -1;
	}
	ret = sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_GET_OP_RESULT,
							0, &rd_data, board);
	while (GET_BITS_VAL(rd_data, 1, 0) == 0x2 && (time_out < 1000)) {//0b10
		usleep_range(50, 60);//must wait 50us
		sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_GET_OP_RESULT,
							0, &rd_data, board);
		time_out++;
	}
	if (time_out >= 1000) {
		cn_dev_core_err(core, "read reg:%#x=%#x timeout",
					FW_INTERRUPT_GET_OP_RESULT, rd_data);
		return -1;
	}
	ret = GET_BITS_VAL(rd_data, 2, 2);

	return ret;
}

static int ddr_do_phy_power_on(struct ddr_board_set *board, u8 hbm_num)
{
	int ret = 0;
	struct cn_core_set *core = board->core;

	// Run a firmware test operation
	ret = hbm_firmware_operation(board, hbm_num, FW_POWER_ON_FLOW);
	if (ret)
		cn_dev_core_err(core, "hbm_num=%d, error_code=%d", hbm_num, ret);

	return ret;
}

static int phy_enter_mission_mode(struct ddr_board_set *board, u8 hbm_num)
{
	int ret = 0;
	unsigned int init_cmplt;
	unsigned int bist_en;

	usleep_range(1, 2);
	init_cmplt = hbm_sbus_read(hbm_num, APC_ADDR, APC_INIT_COMPLETE, board);
	bist_en = hbm_sbus_read(hbm_num, APC_ADDR, APC_BIST_EN_REG, board);
	if (init_cmplt == 0xff && bist_en == 0x0) {
		usleep_range(1, 2);
		return ret;
	}
	hbm_sbus_write(hbm_num, APC_ADDR, APC_BIST_EN_REG, 0x0, board);
	hbm_sbus_write(hbm_num, APC_ADDR, APC_INIT_COMPLETE, 0xff, board);
	usleep_range(1, 2);

	return ret;
}

static int ddr_do_mc_init(struct ddr_board_set *board, u8 hbm_num)
{
	int i, j;
	int ret = 0;
	unsigned int time_out = 0;
	unsigned int rd_data;
	unsigned int apb_mc_addr;
	struct cn_core_set *core = board->core;

	for (i = 0; i < board->hbmsys_num_per_phy; i++)
		for (j = 0; j < board->mc_num_per_hbmsys; j++) {
			apb_mc_addr = board->hbmphy[hbm_num].hbmsys[i].mc_base_addr[j];
			//MC Timing
			hbm_reg_wt32(apb_mc_addr + CFG_CCD_S, mc_cfg_ccd_s, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_CCD_L, mc_cfg_ccd_l, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RRD_S, mc_cfg_rrd_s, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RRD_L, mc_cfg_rrd_l, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_WTR_S, mc_cfg_wtr_s, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_WTR_L, mc_cfg_wtr_l, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_HBM_PARITY_LATENCY, board->m_hbm_dram_pl, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_EN_RRDP, mc_cfg_en_rrdp, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_PS_ONE_FAW, mc_cfg_ps_one_faw, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_CCD_R, mc_cfg_ccd_r, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RREFD, mc_cfg_rrefd, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RFCSB, mc_cfg_rfcsb, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RCD_RD, mc_cfg_rcd_rd, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RCD_WR, mc_cfg_rcd_wr, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RAS, m_hbm_dram_ras, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RP, mc_cfg_rp, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RC, mc_cfg_rc, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_FAW, mc_cfg_faw, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RFC, mc_cfg_rfc, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_WR, m_hbm_dram_driver_wr, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RTP, mc_cfg_rtp, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_XP, mc_cfg_xp, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_READ_TO_WRITE, mc_cfg_read_to_write, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_REF_PER, mc_cfg_ref_per, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_XS, mc_cfg_xs, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_WL, m_hbm_dram_wl + 1, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RL, board->m_hbm_dram_rl + 2, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_CKSRE, mc_cfg_cksre, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_CKSRX, mc_cfg_cksrx, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_READ_DBI,
					board->m_hbm_dram_dbiac_read, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_WRITE_DBI,
					board->m_hbm_dram_dbiac_write, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_HBM_CB_EN,
					board->m_hbm_dram_ecc, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_ECC_CORRECTION_EN,
					board->m_hbm_dram_ecc, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_ECC_1BIT_INT_THRESH,
				board->mc_cfg_ecc_1bit_int_thresh, core->bus_set);

			//hbm_reg_wt32(apb_mc_addr + CFG_XPR, mc_cfg_xpr, core->bus_set);
			//hbm_reg_wt32(apb_mc_addr + CFG_DATA_MASK, mc_cfg_data_mask, core->bus_set);
			//hbm_reg_wt32(apb_mc_addr + CFG_MOD, mc_cfg_mod, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_MEM_ROWBITS,
						mc_cfg_mem_rowbits, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_MEM_BANKBITS,
						mc_cfg_mem_bankbits, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_MANUAL_ADDRESS_MAP,
						mc_cfg_manual_address_map, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_GENERATE_REFRESH_ON_SRX,
						mc_cfg_generate_refresh_on_srx, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + INIT_INTERRUPT_MASK_0,
						mc_init_interrupt_mask_0, core->bus_set);
			//hbm_reg_wt32(apb_mc_addr + CFG_TEMP_CTRL_REF_MODE,
			//			mc_cfg_temp_ctrl_ref_mode, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RD_DQ_PARITY_EN,
						board->m_hbm_dram_dq_r_parity, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_WR_DQ_PARITY_EN,
						board->m_hbm_dram_dq_w_parity, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_CA_PARITY_EN,
						board->m_hbm_dram_ac_parity, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_BANK_GROUP_EN,
						m_hbm_dram_bank, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_HBM_TCR_ENABLE,
						mc_cfg_hbm_tcr_enable, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_EN_RRDP,
						mc_cfg_en_rrdp, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_PS_ONE_FAW,
						mc_cfg_ps_one_faw, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_SBREF_EN,
						mc_cfg_sbref_en, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_SBREF_ISSUE_PER,
						mc_cfg_sbref_issue_per, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_LOOKAHEAD_SBREF,
						mc_cfg_lookahead_sbref, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_ADVANCE_ACTIVATE_READY,
						mc_cfg_advance_activate_ready, core->bus_set);
			//hbm_reg_wt32(apb_mc_addr + CTRLR_SOFT_RESET_N,
			//			mc_ctrlr_soft_reset_n, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_LOOKAHEAD_PCH,
						mc_cfg_lookahead_pch, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_LOOKAHEAD_ACT,
						mc_cfg_lookahead_act, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + INIT_AUTO_DISABLE,
						mc_init_autoinit_disable, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_BL, mc_cfg_bl, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_AUTO_REF_EN,
						mc_cfg_auto_ref_en, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + INIT_SELF_REFRESH,
						mc_init_self_refresh, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_CTRLR_INIT_DISABLE,
						mc_cfg_ctrlr_init_disable, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_PHYUPD_ACK_DELAY,
						mc_cfg_phyupd_ack_delay, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_IDLE_TIME_TO_SELF_REFRESH,
						mc_cfg_idle_time_to_self_refresh, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_IDLE_TIME_TO_POWER_DOWN,
						mc_cfg_idle_time_to_power_down, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_BURST_RW_REFRESH_HOLDOFF,
						mc_cfg_burst_rw_refresh_holdoff, core->bus_set);
			//hbm_reg_wt32(apb_mc_addr + INIT_REFRESH_COUNT,
			//			mc_init_refresh_count, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_BG_INTERLEAVE,
						mc_cfg_bg_interleave, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_DBI_BYTE_DISABLE_SOURCE,
						mc_cfg_dbi_byte_disable_source, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_DBI_BYTE_DISABLE,
						mc_cfg_dbi_byte_disable, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_REORDER_EN, mc_cfg_reorder_en, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_REORDER_QUEUE_EN,
						mc_cfg_reorder_queue_en, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_INTRAPORT_REORDER_EN,
						mc_cfg_intraport_reorder_en, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_MAINTAIN_COHERENCE,
						mc_cfg_maintain_coherency, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_Q_AGE_LIMIT,
						mc_cfg_q_age_limit, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RO_DELAY_BADPERF_CHOICE,
						mc_cfg_ro_delay_badperf_choice, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_DM_EN, mc_cfg_dm_en, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_RMW_EN, mc_cfg_rmw_en, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_ECC_BYPASS, mc_cfg_ecc_bypass, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + INIT_WRITE_DATA_1B_ECC_ERROR_GEN,
						mc_init_write_data_1b_ecc_error_gen, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + INIT_WRITE_DATA_2B_ECC_ERROR_GEN,
						mc_init_write_data_2b_ecc_error_gen, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_DFI_T_RDDATA_EN,
						mc_cfg_dfi_t_rddata_en, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_DFI_T_PHY_RDLAT,
						mc_cfg_dfi_t_phy_rdlat, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_DFI_T_PHY_WRLAT,
						mc_cfg_dfi_t_phy_wrlat, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_DFI_PHYUPD_EN,
						mc_cfg_dfi_phyupd_en, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_AXI_START_ADDRESS_AXI,
						mc_cfg_axi_start_address_axi, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_AXI_END_ADDRESS_AXI,
						mc_cfg_axi_end_address_axi, core->bus_set); //!!!后续可能需要改
			hbm_reg_wt32(apb_mc_addr + CFG_MEM_START_ADDRESS_AXI,
						mc_cfg_mem_start_address_axi, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_AXI_AUTO_PCH,
						mc_cfg_axi_auto_pch, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_AXIRD_ID_REORDER_EN,
						mc_cfg_axird_id_reorder_en, core->bus_set); //!!!后续可以开
			hbm_reg_wt32(apb_mc_addr + CFG_AXIRD_INTERLEAVE_SEL,
						mc_cfg_axird_interleave_sel, core->bus_set);

			usleep_range(1, 2); //  # 1us;
			hbm_reg_wt32(apb_mc_addr + CTRLR_SOFT_RESET_N,
						mc_ctrlr_soft_reset_n, core->bus_set);
			usleep_range(1, 2); //  # 1us;

			//DFI
			rd_data = hbm_reg_rd32(apb_mc_addr + STAT_DFI_INIT_COMPLETE, core->bus_set);
			while (rd_data != 0x1 && (time_out < 1000)) {
				usleep_range(1, 2); //    #100ns ;
				rd_data = hbm_reg_rd32(apb_mc_addr + STAT_DFI_INIT_COMPLETE, core->bus_set);
				time_out++;
			}
			if (time_out >= 1000) {
				ret = -1;
				cn_dev_core_err(core, "read reg:%#x=%#x timeout",
							apb_mc_addr + STAT_DFI_INIT_COMPLETE, rd_data);
			}
			//MC_BASE2
			//rd_data = 0 ;
			//rd_data = hbm_reg_rd32(apb_mc_addr + CTRLR_INIT_DONE, core->bus_set);
			//while ( rd_data != 0x1) {
			//	usleep_range(1, 2); //    #100ns ;
			//	rd_data = hbm_reg_rd32(apb_mc_addr + CTRLR_INIT_DONE, core->bus_set);
			//}
	}

	return ret;
}

static void read_mode_registers_and_phy_config_values(struct ddr_board_set *board,
							u8 hbm_num)
{
	int i = 0;
	unsigned int channel = 0;
	unsigned int mr_data[13] = {0};
	unsigned int phycfg_data[4] = {0};
	struct cn_core_set *core = board->core;

	cn_dev_core_debug(core, "enter read_phy_config_values hbm%d", hbm_num);

	for (channel = 0; channel < 8; channel++) {
		cn_dev_core_debug(core, "enter channel%d", channel);

		wir_write_channel(hbm_num, HBM_SEL, channel,
			HBM_MODE_REG_DUMP_SET, HBM_MODE_REG_DUMP_SET_LENGTH, board);
		wdr_read(hbm_num, HBM_MODE_REG_DUMP_SET_LENGTH, 0, board);
		wdr_read_sbus_data(hbm_num, channel, mr_data,
					HBM_MODE_REG_DUMP_SET_LENGTH, board);
		for (i = 0; i <= 8; i++) {
			cn_dev_core_debug(core, "hbm%d mr%d %02x", hbm_num,
				i, GET_ARRAY_VAL(mr_data, 8 * i + 7, 8 * i));
		}
		cn_dev_core_debug(core, "hbm%d mr15 %02x", hbm_num,
					GET_ARRAY_VAL(mr_data, 122, 120));
		wir_write_channel(hbm_num, PHY_SEL, channel, PHY_CONFIG,
						PHY_CONFIG_LENGTH, board);
		wdr_read(hbm_num, PHY_CONFIG_LENGTH, 0, board);
		wdr_read_sbus_data(hbm_num, channel, phycfg_data,
						PHY_CONFIG_LENGTH, board);
		for (i = 0; i < 4; i++) {
			cn_dev_core_debug(core, "hbm%d phyconfig%d %08x",
						hbm_num, i, phycfg_data[i]);
		}

		cn_dev_core_debug(core, "exit channel%d", channel);
	}

	cn_dev_core_debug(core, "exit read_phy_config_values hbm%d", hbm_num);
}

static int ddr_initialization(struct ddr_board_set *board, u8 hbm_num)
{
	int ret = 0;
	struct cn_core_set *core = board->core;

	ret = ddr_do_pmu_reset_assert(core, hbm_num);
	if (ret) {
		cn_dev_core_err(core, "assert pmu reset error");
		return ret;
	}
	usleep_range(5000, 10000);
	ret = ddr_do_pmu_reset_release(core, hbm_num);
	if (ret) {
		cn_dev_core_err(core, "release pmu reset error");
		return ret;
	}
	usleep_range(5000, 10000);
	ret = ddr_do_hbm_reset_assert(board, hbm_num);
	if (ret) {
		cn_dev_core_err(core, "assert hbm reset error");
		return ret;
	}
	usleep_range(5000, 10000);
	ret = ddr_do_hbm_reset_release(board, hbm_num);
	if (ret) {
		cn_dev_core_err(core, "release hbm reset error");
		return ret;
	}
	usleep_range(10000, 15000);
	ret = ddr_do_sbus_init(board, hbm_num);
	if (ret) {
		cn_dev_core_err(core, "sbus master init error");
		return ret;
	}

	set_phy_spico_params(board, hbm_num);

	ret = ddr_do_phy_power_on(board, hbm_num);
	if (ret) {
		cn_dev_core_err(core, "hbm ddr_do_phy_power_on error%d", ret);
		return ret;
	}
	ret = phy_enter_mission_mode(board, hbm_num);
	if (ret) {
		cn_dev_core_err(core, "phy_enter_misson_mode error");
		return ret;
	}
	ret = ddr_do_mc_init(board, hbm_num);
	if (ret) {
		cn_dev_core_err(core, "hbm ddr_do_mc_init error");
		return ret;
	}
	usleep_range(5000, 10000);

	/* print_debug == 1 for debug hbm config resigter*/
	if (print_debug) {
		read_mode_registers_and_phy_config_values(board, hbm_num);
		usleep_range(5000, 10000);
	}

	return ret;
}

static int enter_self_refresh(struct ddr_board_set *board, u8 hbm_num,
						int sys_num, int mc_num)
{
	int ret = 0;
	unsigned int timeout = 0;
	unsigned int rd_data = 0;
	unsigned int apb_mc_addr;
	struct cn_core_set *core = board->core;

	apb_mc_addr = board->hbmphy[hbm_num].hbmsys[sys_num].mc_base_addr[mc_num];
	hbm_reg_wt32(apb_mc_addr + INIT_SELF_REFRESH, 1, core->bus_set);
	rd_data = hbm_reg_rd32(apb_mc_addr + INIT_SELF_REFRESH_STATUS, core->bus_set);
	while (((rd_data & 0x01) != 1) && (timeout < 1000)) {
		usleep_range(1000, 1500);
		rd_data = hbm_reg_rd32(apb_mc_addr +
					INIT_SELF_REFRESH_STATUS, core->bus_set);
		timeout++;
	}

	if (timeout >= 1000) {
		rd_data = hbm_reg_rd32(apb_mc_addr +
					INIT_SELF_REFRESH_STATUS, core->bus_set);
		cn_dev_core_err(core,
				"hbm%d sys%d mc%d INIT_SELF_REFRESH_STATUS:%#x",
				hbm_num, sys_num, mc_num, rd_data);
		rd_data = hbm_reg_rd32(apb_mc_addr + INIT_REFRESH_COUNT, core->bus_set);
		cn_dev_core_err(core,
				"hbm%d sys%d mc%d INIT_REFRESH_COUNT:%#x",
				hbm_num, sys_num, mc_num, rd_data);
		ret = -1;
	}

	return ret;
}

static int exit_self_refresh(struct ddr_board_set *board, u8 hbm_num,
						int sys_num, int mc_num)
{
	int ret = 0;
	unsigned int timeout = 0;
	unsigned int rd_data = 0;
	unsigned int apb_mc_addr;
	struct cn_core_set *core = board->core;

	apb_mc_addr = board->hbmphy[hbm_num].hbmsys[sys_num].mc_base_addr[mc_num];
	hbm_reg_wt32(apb_mc_addr + INIT_SELF_REFRESH, 0, core->bus_set);
	rd_data = hbm_reg_rd32(apb_mc_addr + INIT_SELF_REFRESH_STATUS, core->bus_set);
	while (((rd_data & 0x01) != 0) && (timeout < 1000)) {
		usleep_range(1, 2);
		rd_data = hbm_reg_rd32(apb_mc_addr +
					INIT_SELF_REFRESH_STATUS, core->bus_set);
		timeout++;
	}

	if (timeout >= 1000) {
		rd_data = hbm_reg_rd32(apb_mc_addr +
					INIT_SELF_REFRESH_STATUS, core->bus_set);
		cn_dev_core_err(core,
				"hbm%d sys%d mc%d INIT_SELF_REFRESH_STATUS:%#x",
				hbm_num, sys_num, mc_num, rd_data);
		ret = -1;
	}

	return ret;
}

static int ddr_disable_reorder_sbref(struct ddr_board_set *board, u8 hbm_num,
						int sys_num, int mc_num)
{
	int ret = 0;
	unsigned int apb_mc_addr;
	struct cn_core_set *core = board->core;

	apb_mc_addr = board->hbmphy[hbm_num].hbmsys[sys_num].mc_base_addr[mc_num];
	ret = enter_self_refresh(board, hbm_num, sys_num, mc_num);
	hbm_reg_wt32(apb_mc_addr + CFG_REORDER_EN, 0, core->bus_set);
	hbm_reg_wt32(apb_mc_addr + CFG_SBREF_EN, 0, core->bus_set);
	usleep_range(10, 20);
	hbm_reg_wt32(apb_mc_addr + CFG_SBREF_EN, 1, core->bus_set);
	ret |= exit_self_refresh(board, hbm_num, sys_num, mc_num);

	return ret;
}

static int ddr_restore_reorder_sbref(struct ddr_board_set *board, u8 hbm_num)
{
	int i, j;
	int ret = 0;
	unsigned int apb_mc_addr;
	struct cn_core_set *core = board->core;

	for (i = 0; i < board->hbmsys_num_per_phy; i++)
		for (j = 0; j < board->mc_num_per_hbmsys; j++) {
			apb_mc_addr = board->hbmphy[hbm_num].hbmsys[i].mc_base_addr[j];
			ret |= enter_self_refresh(board, hbm_num, i, j);
			hbm_reg_wt32(apb_mc_addr + CFG_REORDER_EN, 1, core->bus_set);
			hbm_reg_wt32(apb_mc_addr + CFG_SBREF_EN, 1, core->bus_set);
			ret |= exit_self_refresh(board, hbm_num, i, j);
		}

	return ret;
}

static unsigned int hbm_clear_reg[] = {
	#include "hbm_write_all0.h"
};

static void program_dte_advanced_test(struct ddr_board_set *board, u8 hbm_num,
						int sys_num, int mc_num)
{
	int i;
	unsigned int apb_mc_addr;
	struct cn_core_set *core = board->core;
	int hbm_clear_index = ARRAY_SIZE(hbm_clear_reg);

	apb_mc_addr = board->hbmphy[hbm_num].hbmsys[sys_num].mc_base_addr[mc_num];

	/* disable advanced pattern*/
	hbm_reg_wt32(apb_mc_addr + AMT_SEQUENCER_ENABLE, 0, core->bus_set);
	hbm_reg_wt32(apb_mc_addr + AMT_USEQ_IRAM_WADDR, 0, core->bus_set);
	/* read WRITE_ALL0.rom*/
	for (i = 0; i < hbm_clear_index; i += 2) {
		hbm_reg_wt32(apb_mc_addr + AMT_USEQ_IRAM_WDATA_0,
						hbm_clear_reg[i], core->bus_set);
		hbm_reg_wt32(apb_mc_addr + AMT_USEQ_IRAM_WDATA_1,
						hbm_clear_reg[i+1], core->bus_set);
	}
}

static void do_dte_advanced_start(struct ddr_board_set *board, u8 hbm_num,
						int sys_num, int mc_num)
{
	unsigned int apb_mc_addr;
	struct cn_core_set *core = board->core;

	apb_mc_addr = board->hbmphy[hbm_num].hbmsys[sys_num].mc_base_addr[mc_num];
	/* read to clear last error*/
	hbm_reg_rd32(apb_mc_addr + MT_ERROR_STS, core->bus_set);
	/* enable advanced pattern*/
	hbm_reg_wt32(apb_mc_addr + AMT_SEQUENCER_ENABLE, 1, core->bus_set);
	/* if mt error must stop*/
	hbm_reg_wt32(apb_mc_addr + MT_STOP_ON_ERROR, mc_mt_stop_on_error, core->bus_set);
	/* start test*/
	hbm_reg_wt32(apb_mc_addr + MT_EN_SINGLE, 1, core->bus_set);
}

static int ddr_dte_advanced_start(struct ddr_board_set *board, u8 hbm_num)
{
	int i, j;
	int ret = 0;

	for (i = 0; i < board->hbmsys_num_per_phy; i++)
		for (j = 0; j < board->mc_num_per_hbmsys; j++) {
			/* go disable reorder sbref before dte write all 0*/
			ret |= ddr_disable_reorder_sbref(board, hbm_num, i, j);
			program_dte_advanced_test(board, hbm_num, i, j);
			do_dte_advanced_start(board, hbm_num, i, j);
		}

	return ret;
}

static int ddr_dte_advanced_wait(struct ddr_board_set *board)
{
	int i, j, k;
	int ret = 0;
	u8 hbm_num = board->phy_num;
	int sys_num = board->hbmsys_num_per_phy;
	int mc_num = board->mc_num_per_hbmsys;
	int apb_addr_num = hbm_num * sys_num * mc_num;
	unsigned int apb_mc_addr[MLU290_PHY_NUM * MLU290_HBMSYS_NUM_PER_PHY *
						MLU290_MC_NUM_PER_HBMSYS];
	unsigned int rd_data;
	struct cn_core_set *core = board->core;

	for (i = 0; i < board->phy_num; i++)
		for (j = 0; j < board->hbmsys_num_per_phy; j++)
			for (k = 0; k < board->mc_num_per_hbmsys; k++) {
				apb_mc_addr[i * sys_num * mc_num + j * mc_num + k]
					= board->hbmphy[i].hbmsys[j].mc_base_addr[k];
			}
	for (i = 0; i < apb_addr_num; i++) {
		do {
			rd_data = hbm_reg_rd32(apb_mc_addr[i] +
							MT_DONE_ACK, core->bus_set);
		} while (rd_data != 1);

		rd_data = hbm_reg_rd32(apb_mc_addr[i] + MT_ERROR_STS, core->bus_set);
		if (rd_data != 0) {
			ret = -1;
			cn_dev_core_err(core, "hbm*sys*mc=%d error", i);
		}

		/* stop test*/
		hbm_reg_wt32(apb_mc_addr[i] + MT_EN_SINGLE, 0, core->bus_set);
		/* disable advanced pattern*/
		hbm_reg_wt32(apb_mc_addr[i] + AMT_SEQUENCER_ENABLE, 0, core->bus_set);
	}

	return ret;
}

static int hbm_get_fuse_info(struct ddr_board_set *board, unsigned int *fuse_info,
					unsigned int hbm_num)
{
	int ret = 0;
	int chn_num;
	int bnk_num;
	int sid_num;
	int index;
	struct hbm_repair_info_set decode;
	u32 phy_spare_3 = 0;
	u32 phy_spare_4 = 0;
	struct cn_core_set *core = board->core;

	memset(&decode, 0, sizeof(decode));
	for (chn_num = 0; chn_num < HBM_CHN_NUM; chn_num++)
		for (sid_num = 0; sid_num < HBM_SID_NUM; sid_num++)
			for (bnk_num = 0; bnk_num < HBM_BNK_NUM; bnk_num++) {
				decode.info.eeprom_info = chn_num;
				decode.sid = sid_num;
				decode.bank = bnk_num;
				SET_DECODE_FUSE_PHY_SPARE_3(phy_spare_3, decode);
				cn_dev_core_debug(core, "phy_spare_3=%#x", phy_spare_3);
				hbm_sbus_write(hbm_num, APC_ADDR,
						SPARE_3_REG, phy_spare_3, board);
				ret = hbm_firmware_operation(board,
						hbm_num, FW_HBM_RUN_FUSE_SCAN);
				if (ret) {
					cn_dev_core_err(core,
						"chn_num=%d, sid_num=%d, bnk_num=%d, error_code=%d",
						chn_num, sid_num, bnk_num, ret);
					return ret;
				}
				phy_spare_4 = hbm_sbus_read(hbm_num,
						APC_ADDR, SPARE_4_REG, board);
				index = bnk_num + sid_num * HBM_BNK_NUM +
					chn_num * HBM_SID_NUM * HBM_BNK_NUM+
							hbm_num * HBM_FUSE_NUM;
				fuse_info[index] = GET_FUSE_SCAN_INFO(phy_spare_4);
				cn_dev_core_debug(core, "fuse_info[%d]=%d",
							index, fuse_info[index]);
			}

	return ret;
}

__attribute__((unused)) static int hbm_dte_write_all_zero(struct hbm_repair_set *repair_set)
{
	int i;
	int ret = 0;
	struct ddr_board_set *board = NULL;
	struct cn_mcc_set *mcc_set = repair_set->mcc_set;
	struct cn_core_set *core = mcc_set->core;

	if (!core)
		return -1;

	board = cn_kzalloc(sizeof(struct ddr_board_set), GFP_KERNEL);
	if (!board) {
		cn_dev_core_err(core, "kzalloc ddr_board error");
		return -1;
	}
	board->core = core;
	ret = ddr_board_info_init(board);
	if (ret) {
		cn_dev_core_err(core, "ddr_board_info_init fail");
		goto HBMERR;
	}

	ret = hbm_dram_init(board);
	if (ret) {
		cn_dev_core_err(core, "hbm_dram_init fail");
		goto HBMERR;
	}

	/* disable mcu*/
	phy_disable_mcu_access(core);
	for (i = 0; i < board->phy_num; i++) {
		ret = ddr_dte_advanced_start(board, i);
		if (ret) {
			cn_dev_core_err(core, "ddr_dte_advanced_start fail");
			goto HBMERR;
		}
	}
	ret = ddr_dte_advanced_wait(board);
	if (ret) {
		cn_dev_core_err(core, "ddr_dte_advanced_wait fail");
		goto HBMERR;
	}
	/* go restore reorder sbref after dte write all 0*/
	for (i = 0; i < board->phy_num; i++) {
		ret = ddr_restore_reorder_sbref(board, i);
		if (ret) {
			cn_dev_core_err(core, "ddr_restore_reorder_sbref fail");
			goto HBMERR;
		}
	}

	/* enable mcu*/
	phy_enable_mcu_access(core);

HBMERR:
	if (board) {
		cn_kfree(board);
		board = NULL;
	}

	return ret;
}

__attribute__((unused)) static int hbm_boot_prepare(struct hbm_repair_set *repair_set)
{
	int i;
	int ret = 0;
	struct ddr_board_set *board = NULL;
	struct cn_mcc_set *mcc_set = repair_set->mcc_set;
	struct cn_core_set *core = mcc_set->core;

	if (!core)
		return -1;

	board = cn_kzalloc(sizeof(struct ddr_board_set), GFP_KERNEL);
	if (!board) {
		cn_dev_core_err(core, "kzalloc ddr_board error");
		return -1;
	}
	board->core = core;
	ret = ddr_board_info_init(board);
	if (ret) {
		cn_dev_core_err(core, "ddr_board_info_init fail");
		goto HBMERR;
	}

	for (i = 0; i < 4; i++) {
		ret = ddr_do_pll_init(board, i); /* pll init*/
		if (ret) {
			cn_dev_core_err(core, "ddr_do_pll_init%d fail", i);
			goto HBMERR;
		}
	}

	ret = hbm_dram_init(board);
	if (ret) {
		cn_dev_core_err(core, "hbm_dram_init fail");
		goto HBMERR;
	}

	/* disable mcu*/
	phy_disable_mcu_access(core);
	for (i = 0; i < board->phy_num; i++) {
		ret = ddr_initialization(board, i);
		if (ret) {
			cn_dev_core_err(core, "ddr_initialization fail");
			goto HBMERR;
		}

		ret = ddr_dte_advanced_start(board, i);
		if (ret) {
			cn_dev_core_err(core, "ddr_dte_advanced_start fail");
			goto HBMERR;
		}
	}
	ret = ddr_dte_advanced_wait(board);
	if (ret) {
		cn_dev_core_err(core, "ddr_dte_advanced_wait fail");
		goto HBMERR;
	}
	/* go restore reorder sbref after dte write all 0*/
	for (i = 0; i < board->phy_num; i++) {
		ret = ddr_restore_reorder_sbref(board, i);
		if (ret) {
			cn_dev_core_err(core, "ddr_restore_reorder_sbref fail");
			goto HBMERR;
		}
	}

	/*get fuse info*/
	for (i = 0; i < board->phy_num && !repair_set->fuse_flag; i++) {
		ret = hbm_get_fuse_info(board, repair_set->fuse_info, i);
		if (ret)
			goto HBMERR;
		repair_set->fuse_flag = 1;
	}

	/* enable mcu*/
	phy_enable_mcu_access(core);

HBMERR:
	if (board) {
		cn_kfree(board);
		board = NULL;
	}

	return ret;
}
#endif
