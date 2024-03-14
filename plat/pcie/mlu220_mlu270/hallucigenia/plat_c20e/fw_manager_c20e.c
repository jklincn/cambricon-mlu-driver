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
#include "../../cndrv_pci.h"
#include "c20e_zebu_ddr_data.h"

#define ddr_reg_wt32(offset, value, pcie_set)	\
	cn_pci_reg_write32(pcie_set, offset, value)

#define ddr_reg_rd32(offset, pcie_set)	\
	cn_pci_reg_read32(pcie_set, offset)


__attribute__((unused)) static void hw_fw_boot_prepare(struct cn_pcie_set *pcie_set)
{
	unsigned int temp;
	int temp_i;
	unsigned long ddrc_reg_base_addr;


		ddr_reg_wt32(0x100000, 0x1, pcie_set);  //ddrc_apb_resetn
		temp = ddr_reg_rd32(0x100000, pcie_set);

		ddr_reg_wt32(0x100014, 0x1, pcie_set);  //memesys_prot_resetn
		temp = ddr_reg_rd32(0x100014, pcie_set);

		ddr_reg_wt32(0x100010, 0x1, pcie_set);  //aximonitor_resetn
		temp = ddr_reg_rd32(0x100010, pcie_set);


		for (temp_i = 0; temp_i < 4; temp_i++) {
			ddrc_reg_base_addr = 0x110000 + temp_i * 0x4000;

			ddr_reg_wt32(ddrc_reg_base_addr + 0x304, 0x1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x30, 0x1, pcie_set);

			temp = ddr_reg_rd32(ddrc_reg_base_addr + 0x4, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x0, FREQ0_MSTR, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x10, FREQ0_MRCTRL0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x14, FREQ0_MRCTRL1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x20, FREQ0_DERATEEN, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x24, FREQ0_DERATEINT, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x2c, FREQ0_DERATECTL, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x30, FREQ0_PWRCTL, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x34, FREQ0_PWRTMG, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x38, FREQ0_HWLPCTL, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x50, FREQ0_RFSHCTL0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x54, FREQ0_RFSHCTL1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x60, FREQ0_RFSHCTL3, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x64, FREQ0_RFSHTMG, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x68, FREQ0_RFSHTMG1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xc0, FREQ0_CRCPARCTL0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xd0, FREQ0_INIT0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xd4, FREQ0_INIT1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xd8, FREQ0_INIT2, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xdc, FREQ0_INIT3, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xe0, FREQ0_INIT4, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xe4, FREQ0_INIT5, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xe8, FREQ0_INIT6, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xec, FREQ0_INIT7, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xf0, FREQ0_DIMMCTL, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0xf4, FREQ0_RANKCTL, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x100, FREQ0_DRAMTMG0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x104, FREQ0_DRAMTMG1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x108, FREQ0_DRAMTMG2, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x10c, FREQ0_DRAMTMG3, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x110, FREQ0_DRAMTMG4, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x114, FREQ0_DRAMTMG5, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x118, FREQ0_DRAMTMG6, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x11c, FREQ0_DRAMTMG7, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x120, FREQ0_DRAMTMG8, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x130, FREQ0_DRAMTMG12, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x134, FREQ0_DRAMTMG13, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x138, FREQ0_DRAMTMG14, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x180, FREQ0_ZQCTL0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x184, FREQ0_ZQCTL1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x188, FREQ0_ZQCTL2, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x190, FREQ0_DFITMG0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x194, FREQ0_DFITMG1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x198, FREQ0_DFILPCFG0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x1a0, FREQ0_DFIUPD0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x1a4, FREQ0_DFIUPD1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x1a8, FREQ0_DFIUPD2, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x1b0, FREQ0_DFIMISC, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x1b4, FREQ0_DFITMG2, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x1c0, FREQ0_DBICTL, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x1c4, FREQ0_DFIPHYMSTR, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x200, FREQ0_ADDRMAP0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x204, FREQ0_ADDRMAP1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x208, FREQ0_ADDRMAP2, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x20c, FREQ0_ADDRMAP3, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x210, FREQ0_ADDRMAP4, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x214, FREQ0_ADDRMAP5, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x218, FREQ0_ADDRMAP6, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x21c, FREQ0_ADDRMAP7, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x224, FREQ0_ADDRMAP9, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x228, FREQ0_ADDRMAP10, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x22c, FREQ0_ADDRMAP11, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x240, FREQ0_ODTCFG, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x244, FREQ0_ODTMAP, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x250, FREQ0_SCHED, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x254, FREQ0_SCHED1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x25c, FREQ0_PERFHPR1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x264, FREQ0_PERFLPR1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x26c, FREQ0_PERFWR1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x270, FREQ0_SCHED3, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x274, FREQ0_SCHED4, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x300, FREQ0_DBG0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x304, FREQ0_DBG1, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x30c, FREQ0_DBGCMD, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x320, FREQ0_SWCTL, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x328, FREQ0_SWCTLSTATIC, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x36c, FREQ0_POISONCFG, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x400, FREQ0_PCCFG, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x404, FREQ0_PCFGR_0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x408, FREQ0_PCFGW_0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x490, FREQ0_PCTRL_0, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x494, FREQ0_PCFGQOS0_0, pcie_set);

		}


		ddr_reg_wt32(0x100008, 0x1, pcie_set);  //release DDRC reset
		temp = ddr_reg_rd32(0x100008, pcie_set);

		ddr_reg_wt32(0x10000c, 0x3, pcie_set);  //release PHY reset
		temp = ddr_reg_rd32(0x10000c, pcie_set);

		ddr_reg_wt32(0x100004, 0x3, pcie_set);  //release PHY apb reset
		temp = ddr_reg_rd32(0x100004, pcie_set);


		for (temp_i = 0; temp_i < 4; temp_i++) {
			ddrc_reg_base_addr = 0x110000 + temp_i * 0x4000;
			ddr_reg_wt32(ddrc_reg_base_addr + 0x320, 0x0, pcie_set); //sw_done = 0

			ddr_reg_wt32(ddrc_reg_base_addr + 0x1b0, 0x21, pcie_set); //ddr_init_start=1

			ddr_reg_wt32(ddrc_reg_base_addr + 0x320, 0x1, pcie_set); //sw_done = 1

			temp = ddr_reg_rd32(ddrc_reg_base_addr + 0x324, pcie_set); //polling sw_done_ack

			while ((temp%2) == 0) {
				temp = ddr_reg_rd32(ddrc_reg_base_addr + 0x324, pcie_set);
			}

			temp = ddr_reg_rd32(ddrc_reg_base_addr + 0x1bc, pcie_set);

			while ((temp % 2) == 0) {
				temp = ddr_reg_rd32(ddrc_reg_base_addr + 0x1bc, pcie_set);
			}

			temp = ddr_reg_rd32(ddrc_reg_base_addr + 0x60, pcie_set);

			temp = temp & 0xfffffffe; //disable auto refresh

			ddr_reg_wt32(ddrc_reg_base_addr + 0x60, temp, pcie_set);

			ddr_reg_wt32(ddrc_reg_base_addr + 0x320, 0x0, pcie_set);//sw_done=0

			temp = ddr_reg_rd32(ddrc_reg_base_addr + 0x1b0, pcie_set);

			temp = temp & 0xffffffdf;//ddr_init_start=0
			temp = temp | 0x1;//complete_en=1

			ddr_reg_wt32(ddrc_reg_base_addr + 0x1b0, temp, pcie_set);

			//selfref_sw=0
			temp = ddr_reg_rd32(ddrc_reg_base_addr + 0x30, pcie_set);

			temp = temp & 0xffffffdf;
			ddr_reg_wt32(ddrc_reg_base_addr + 0x30, temp, pcie_set);
			ddr_reg_wt32(ddrc_reg_base_addr + 0x320, 0x1, pcie_set);//sw_done=1
		}
}
