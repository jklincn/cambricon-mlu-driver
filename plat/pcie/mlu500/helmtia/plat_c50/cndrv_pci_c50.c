/************************************************************************
 *
 *  @file cndrv_pci_c50.c
 *
 *  @brief This file is designed to support pcie functions.
 * ######################################################################
 *
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 *
 **************************************************************************/

/*************************************************************************
 * Software License Agreement:
 * -----------------------------------------------------------------------
 * Copyright (C) [2018] by Cambricon, Inc.
 * This code is licensed under MIT license (see below for details)
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *************************************************************************/
/************************************************************************
 *  Include files
 ************************************************************************/
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/platform_device.h>
#include <linux/vmalloc.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/io.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "../../pcie_dma.h"
#include "../../pcie_bar.h"
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "cndrv_mcu.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_pci_c50.h"
#include "cndrv_debug.h"
#include "cndrv_ipcm.h"
#include "cndrv_proc.h"
#include "cndrv_pci_c50s_tcdp.h"

#define DMA_SMMU_STREAM_ID      37

#define PCIE_TO_PCIE		(0x0)
#define PCIE_TO_AXI		(0x1)
#define AXI_TO_PCIE		(0x2)
#define AXI_TO_AXI		(0x3)
#define SRC_ID_PCIE		(0x0)
#define SRC_ID_AXI		(0x2)
#define PCIE_SNOOP		(0x2)

#if (GIC_INTERRUPT_NUM != MSIX_COUNT)
const static int irq_msix_gic_end[16] = {
	0, 1, 2, 3, 4, 5, 6, 7, 37, 117,
	145, 185, 189, 200, 510, 511};
#endif

#if (MSI_COUNT == 1)
const static int irq_msi_gic_end[1] = {511};
#elif (MSI_COUNT == 2)
const static int irq_msi_gic_end[2] = {255, 511};
#elif (MSI_COUNT == 4)
const static int irq_msi_gic_end[4] = {127, 255, 383, 511};
#elif (MSI_COUNT == 8)
const static int irq_msi_gic_end[8] = {63, 127, 191, 255, 319, 383, 447, 511};
#elif (MSI_COUNT == 16)
const static int irq_msi_gic_end[16] = {
	31, 63, 95, 127, 159, 191, 223, 255,
	287, 319, 351, 383, 415, 447, 479, 511};
#elif (MSI_COUNT == 32)
const static int irq_msi_gic_end[32] = {
	15,   31,  47,  63,  79,  95, 111,  127,
	143, 159, 175, 191, 207, 223, 239, 255,
	271, 287, 303, 319, 335, 351, 367, 383,
	399, 415, 431, 447, 463, 479, 495, 511};
#endif

static struct cn_pci_irq_str_index irq_str_index[GIC_INTERRUPT_NUM] = {
	{0, "host_dma_cmd_buf0"}, //pf dma cmd buf
	{1, "host_dma_cmd_buf1"}, //vf0 dma cmd buf
	{2, "host_dma_cmd_buf2"}, //vf1 dma cmd buf
	{3, "host_dma_cmd_buf3"}, //vf2 dma cmd buf
	{4, "host_dma_cmd_buf4"}, //vf3 dma cmd buf
	{5, "host_dma_cmd_buf5"}, //vf4 dma cmd buf
	{6, "host_dma_cmd_buf6"}, //vf5 dma cmd buf
	{7, "host_dma_cmd_buf7"}, //vf6 dma cmd buf
	{8, "host_dma_cmd_buf8"}, //vf7 dma cmd buf
	{9, "pcie_pf_arm_dma"},
	{18, "PCIE_IRQ_GIC_ARM2PF"},
	{29, "pcie_atomic"},
};

static struct cn_pci_pll_cfg mlu590_pll_cfg[] = {
	{MLU590_CRG_SOUTH_C2C_MAC,    "CRG_SOUTH_C2C_MAC"},
	{MLU590_CRG_SOUTH_C2C_CORE,   "CRG_SOUTH_C2C_CORE"},
	{MLU590_CRG_SOUTH_CPU_SYS,    "CRG_SOUTH_CPU_SYS"},
	{MLU590_CRG_SOUTH_CPU_CORE,   "CRG_SOUTH_CPU_CORE"},
	{MLU590_CRG_SOUTH_TINY_CORE,  "CRG_SOUTH_TINY_CORE"},
	{MLU590_CRG_SOUTH_PCIE_2G,    "CRG_SOUTH_PCIE_2G"},
	{MLU590_CRG_SOUTH_CACG,       "CRG_SOUTH_CACG"},

	{MLU590_CRG_WEST_C2C_MAC,     "CRG_WEST_C2C_MAC"},
	{MLU590_CRG_WEST_C2C_CORE,    "CRG_WEST_C2C_CORE"},
	{MLU590_CRG_WEST_VPU_SYS,     "CRG_WEST_VPU_SYS"},
	{MLU590_CRG_WEST_VPU_DEC,     "CRG_WEST_VPU_DEC"},
	{MLU590_CRG_WEST_TINY_CORE,   "CRG_WEST_TINY_CORE"},
	{MLU590_CRG_WEST_CACG,        "CRG_WEST_CACG"},

	{MLU590_CRG_EAST_C2C_MAC,     "CRG_EAST_C2C_MAC"},
	{MLU590_CRG_EAST_C2C_CORE,    "CRG_EAST_C2C_CORE"},
	{MLU590_CRG_EAST_VPU_SYS,     "CRG_EAST_VPU_SYS"},
	{MLU590_CRG_EAST_VPU_DEC,     "CRG_EAST_VPU_DEC"},
	{MLU590_CRG_EAST_TINY_CORE,   "CRG_EAST_TINY_CORE"},
	{MLU590_CRG_EAST_CACG,        "CRG_EAST_CACG"},

	{MLU590_CRG_MIDDLE_SYS0_CACG, "CRG_MIDDLE_SYS0_CACG"},
	{MLU590_CRG_MIDDLE_LLC_CACG,  "CRG_MIDDLE_LLC_CACG"},
	{MLU590_CRG_BAR00_CACG,       "CRG_BAR00_CACG"},
	{MLU590_CRG_BAR10_CACG,       "CRG_BAR10_CACG"},
	{MLU590_CRG_BAR21_CACG,       "CRG_BAR21_CACG"},
	{MLU590_CRG_BAR31_CACG,       "CRG_BAR31_CACG"},

	{MLU590_CRG_IPU_SYSTEM0,      "CRG_IPU_SYSTEM0"},
	{MLU590_CRG_IPU_SYSTEM1,      "CRG_IPU_SYSTEM1"},
	{MLU590_CRG_IPU_SYSTEM2,      "CRG_IPU_SYSTEM2"},
	{MLU590_CRG_IPU_SYSTEM3,      "CRG_IPU_SYSTEM3"},
	{MLU590_CRG_IPU_SYSTEM4,      "CRG_IPU_SYSTEM4"},
	{MLU590_CRG_IPU_SYSTEM5,      "CRG_IPU_SYSTEM5"},
};

static struct cn_pci_pll_cfg mlu590e_pll_cfg[] = {
	{MLU590E_CRG_SOUTH_C2C_MAC,    "CRG_SOUTH_C2C_MAC"},
	{MLU590E_CRG_SOUTH_C2C_CORE,   "CRG_SOUTH_C2C_CORE"},
	{MLU590E_CRG_SOUTH_CPU_SYS,    "CRG_SOUTH_CPU_SYS"},
	{MLU590E_CRG_SOUTH_CPU_CORE,   "CRG_SOUTH_CPU_CORE"},
	{MLU590E_CRG_SOUTH_TINY_CORE,  "CRG_SOUTH_TINY_CORE"},
	{MLU590E_CRG_SOUTH_PCIE_2G,    "CRG_SOUTH_PCIE_2G"},
	{MLU590E_CRG_SOUTH_CACG,       "CRG_SOUTH_CACG"},

	{MLU590E_CRG_WEST_C2C_MAC,     "CRG_WEST_C2C_MAC"},
	{MLU590E_CRG_WEST_C2C_CORE,    "CRG_WEST_C2C_CORE"},
	{MLU590E_CRG_WEST_VPU_SYS,     "CRG_WEST_VPU_SYS"},
	{MLU590E_CRG_WEST_VPU_DEC,     "CRG_WEST_VPU_DEC"},
	{MLU590E_CRG_WEST_TINY_CORE,   "CRG_WEST_TINY_CORE"},
	{MLU590E_CRG_WEST_CACG,        "CRG_WEST_CACG"},

	{MLU590E_CRG_EAST_C2C_MAC,     "CRG_EAST_C2C_MAC"},
	{MLU590E_CRG_EAST_C2C_CORE,    "CRG_EAST_C2C_CORE"},
	{MLU590E_CRG_EAST_VPU_SYS,     "CRG_EAST_VPU_SYS"},
	{MLU590E_CRG_EAST_VPU_DEC,     "CRG_EAST_VPU_DEC"},
	{MLU590E_CRG_EAST_TINY_CORE,   "CRG_EAST_TINY_CORE"},
	{MLU590E_CRG_EAST_CACG,        "CRG_EAST_CACG"},

	{MLU590E_CRG_MIDDLE_SYS0_CACG, "CRG_MIDDLE_SYS0_CACG"},
	{MLU590E_CRG_MIDDLE_LLC_CACG,  "CRG_MIDDLE_LLC_CACG"},

	{MLU590E_CRG_IPU_SYSTEM02_2,   "CRG_IPU_SYSTEM02_2"},
	{MLU590E_CRG_IPU_SYSTEM13_2,   "CRG_IPU_SYSTEM13_2"},
	{MLU590E_CRG_IPU_SYSTEM0,      "CRG_IPU_SYSTEM0"},
	{MLU590E_CRG_IPU_SYSTEM1,      "CRG_IPU_SYSTEM1"},
	{MLU590E_CRG_IPU_SYSTEM2,      "CRG_IPU_SYSTEM2"},
	{MLU590E_CRG_IPU_SYSTEM3,      "CRG_IPU_SYSTEM3"},
};

static struct cn_pci_pll_cfg mlu580_pll_cfg[] = {
	{MLU580_CRG_SOUTH_CPU_SYS,    "CRG_SOUTH_CPU_SYS"},
	{MLU580_CRG_SOUTH_CPU_CORE,   "CRG_SOUTH_CPU_CORE"},
	{MLU580_CRG_SOUTH_SYS0,       "CRG_SOUTH_SYS0"},
	{MLU580_CRG_SOUTH_PCIE_2G,    "CRG_SOUTH_PCIE_2G"},

	{MLU580_CRG_WEST_VDEC,        "CRG_WEST_VDEC"},
	{MLU580_CRG_WEST_JPU,         "CRG_WEST_JPU"},
	{MLU580_CRG_WEST_SYS0,        "CRG_WEST_SYS0"},

	{MLU580_CRG_EAST_VDEC,        "CRG_EAST_VDEC"},
	{MLU580_CRG_EAST_JPU,         "CRG_EAST_JPU"},
	{MLU580_CRG_EAST_SYS0,        "CRG_EAST_SYS0"},

	{MLU580_CRG_MIDDLE_SYS0_CACG, "CRG_MIDDLE_SYS0_CACG"},
	{MLU580_CRG_MIDDLE_LLC_CACG,  "CRG_MIDDLE_LLC_CACG"},
	{MLU580_CRG_BAR00_CACG,       "CRG_BAR00_CACG"},
	{MLU580_CRG_BAR10_CACG,       "CRG_BAR10_CACG"},
	{MLU580_CRG_BAR21_CACG,       "CRG_BAR21_CACG"},
	{MLU580_CRG_BAR31_CACG,       "CRG_BAR31_CACG"},

	{MLU580_CRG_IPU_SYSTEM0,      "CRG_IPU_SYSTEM0"},
	{MLU580_CRG_IPU_SYSTEM1,      "CRG_IPU_SYSTEM1"},
	{MLU580_CRG_IPU_SYSTEM2,      "CRG_IPU_SYSTEM2"},
	{MLU580_CRG_IPU_SYSTEM3,      "CRG_IPU_SYSTEM3"},
	{MLU580_CRG_IPU_SYSTEM4,      "CRG_IPU_SYSTEM4"},
	{MLU580_CRG_IPU_SYSTEM5,      "CRG_IPU_SYSTEM5"},
};

static int c50_bug_fix_list(struct cn_pcie_set *pcie_set);
static int c50_pcie_dma_pre_init_hw(struct cn_pcie_set *pcie_set);
/*
 *  include public c code
 *  warnning: do not remove it to the top of file
 *            otherwise will have build errors
 */
#include "../../pcie_common.c"
#include "../../pcie_interrupt.c"
#include "../helmtia.h"
#include "cndrv_pci_c50s_tcdp.c"
#include "cndrv_pci_c50_sriov.c"
#include "cndrv_pci_c50_atomicop.c"
#define OVER_WRITE(f) c50_##f

__attribute__((unused))
static void pcie_async_show_desc_list(struct async_task *async_task)
{
	void __iomem *host_desc_addr = (void __iomem *)async_task->host_desc_addr;
	int i, desc_offset = 0;

	for (i = 0; i < (async_task->desc_len / DESC_SIZE); i++) {
		cn_dev_pcie_err(async_task->pcie_set,
			"[%d]%#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x", i,
				ioread32(host_desc_addr + desc_offset + 0),
				ioread32(host_desc_addr  + desc_offset + 4),
				ioread32(host_desc_addr  + desc_offset + 8),
				ioread32(host_desc_addr  + desc_offset + 12),
				ioread32(host_desc_addr  + desc_offset + 16),
				ioread32(host_desc_addr  + desc_offset + 20),
				ioread32(host_desc_addr  + desc_offset + 24),
				ioread32(host_desc_addr  + desc_offset + 28));
		desc_offset += DESC_SIZE;
	}
}

static void fill_descriptor(struct cn_pcie_set *pcie_set,
		DMA_DIR_TYPE direction, u64 desc_device_va, void *desc_host_buf,
		u64 ipu_ram_dma_addr, unsigned long cpu_dma_addr, unsigned long count,
		int *desc_number, int *desc_offset, int last_desc_flag)
{
	unsigned int ctrl, ndl, ndu;

	ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(count) << 8));
	if (last_desc_flag) {
		ndl = 0x3;
		ndu = 0x0;
	} else {
		ndl = NEXT_DESC_LOWER32(desc_device_va,
				*desc_number) | 0x12;
		ndu = NEXT_DESC_UPPER32(desc_device_va,
				*desc_number);
	}
	switch (direction) {
	case DMA_H2D:
		FILL_DESC(desc_host_buf, ctrl, ndl, ndu,
				cpu_dma_addr, ipu_ram_dma_addr, *desc_offset);
		break;
	case DMA_D2H:
		FILL_DESC(desc_host_buf, ctrl, ndl, ndu,
				ipu_ram_dma_addr, cpu_dma_addr, *desc_offset);
		break;
	case DMA_P2P:
		if (pcie_set->cfg.p2p_mode == P2P_PULL_MODE) {
			FILL_DESC(desc_host_buf, ctrl, ndl, ndu,
					cpu_dma_addr, ipu_ram_dma_addr, *desc_offset);
		} else {
			FILL_DESC(desc_host_buf, ctrl, ndl, ndu,
					ipu_ram_dma_addr, cpu_dma_addr, *desc_offset);
		}
		break;

	default:
		cn_dev_pcie_err(pcie_set,
				"only DMA_H2D or DMA_D2H transfer mode");
	}
	*desc_offset += DESC_SIZE;
	(*desc_number)++;

}

static int OVER_WRITE(pcie_fill_desc_list)(struct dma_channel_info *channel)
{
	int i;
	unsigned long cpu_dma_addr = 0;
	u64 ipu_ram_dma_addr;
	unsigned long count = 0;
	struct scatterlist *sglist;
	struct scatterlist *sg;
	int desc_offset = 0;
	int desc_number = 0;
	unsigned long desc_max_len = 0;
	int des_end_flag = 0;
	unsigned long trans_count = 0;

	if (channel->task->dma_type == PCIE_DMA_MEMSET)
		return 0;

	if (channel->desc_device_va % 64) {
		cn_dev_pcie_err(channel->pcie_set,
				"No 64 Bytes align : desc device vaddr");
		return -1;
	}

	/* enable descripter debug */
	if (channel->pcie_set->dfx.des_set > 0) {
		desc_max_len = channel->pcie_set->dfx.des_set * PAGE_SIZE;
		cn_dev_pcie_debug(channel->pcie_set,
				"descripter scatter size 0x%lx, nents %d", desc_max_len,  channel->nents);
	} else {
		desc_max_len = channel->pcie_set->per_desc_max_size;
	}

	ipu_ram_dma_addr = channel->ram_addr;
	if (channel->p2p_sgl)
		sglist = channel->p2p_sgl;
	else
		sglist = channel->sg;
	for_each_sg(sglist, sg, channel->nents, i) {
		cpu_dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);

		while (count) {
			trans_count = min(count, desc_max_len);
			if ((trans_count == count) && (i == (channel->nents - 1))) {
				des_end_flag = 1;
			} else {
				des_end_flag = 0;
			}
			fill_descriptor(channel->pcie_set, channel->direction,
					channel->desc_device_va, channel->task->desc_buf,
					ipu_ram_dma_addr, cpu_dma_addr, trans_count,
					&desc_number, &desc_offset, des_end_flag);
			cpu_dma_addr += trans_count;
			ipu_ram_dma_addr += trans_count;
			count -= trans_count;
		}
	}

	channel->desc_len = desc_offset;
	memcpy_toio(channel->desc_virt_base, channel->task->desc_buf, desc_offset);

	return 0;
}

static int OVER_WRITE(async_dma_fill_desc_list)(struct async_task *async_task)
{
	int i;
	unsigned long cpu_dma_addr = 0;
	u64 ipu_ram_dma_addr;
	struct scatterlist *sg;
	int desc_offset = 0;
	int desc_number = 0;
	unsigned long desc_max_len = 0;
	int des_end_flag = 0;
	unsigned long count = 0;
	unsigned long trans_count = 0;

	if (async_task->dma_type == PCIE_DMA_MEMSET)
		return 0;

	desc_max_len = async_task->pcie_set->per_desc_max_size;

	if (async_task->dma_type != PCIE_DMA_P2P) {
		ipu_ram_dma_addr = async_task->transfer.ia;
	} else {
		if (async_task->pcie_set->cfg.p2p_mode == P2P_PULL_MODE) {
			ipu_ram_dma_addr = async_task->peer.dst_addr;
		} else {
			ipu_ram_dma_addr = async_task->peer.src_addr;
		}
	}

	for_each_sg(async_task->sg_list, sg, async_task->nents, i) {
		cpu_dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);

		while (count) {
			trans_count = min(count, desc_max_len);
			if ((trans_count == count) && (i == (async_task->nents - 1))) {
				des_end_flag = 1;
			} else {
				des_end_flag = 0;
			}
			fill_descriptor(async_task->pcie_set,
					async_task->async_info->direction,
					async_task->dev_desc_addr, async_task->desc_buf,
					ipu_ram_dma_addr, cpu_dma_addr, trans_count,
					&desc_number, &desc_offset, des_end_flag);
			cpu_dma_addr += trans_count;
			ipu_ram_dma_addr += trans_count;
			count -= trans_count;
		}
	}

	async_task->desc_len = desc_offset;
	memcpy_toio((void __iomem *)async_task->host_desc_addr, async_task->desc_buf, desc_offset);
	//pcie_async_show_desc_list(async_task);

	return 0;
}

static int OVER_WRITE(async_dma_fill_p2p_pull_desc)(struct async_task *async_task)
{
	unsigned long cpu_dma_addr;
	u64 ipu_ram_dma_addr;
	unsigned long count;
	unsigned int ctrl, ndl, ndu;
	unsigned int desc_size;
	unsigned int desc_offset;

	ipu_ram_dma_addr = async_task->peer.src_addr;
	cpu_dma_addr = sg_dma_address(async_task->sg_list);
	count = 0x1;

	ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(count) << 8));
	ndl = 0x3;
	ndu = 0x0;
	desc_size = DESC_SIZE;
	/* Hardware Limit: desc addr 64 Bytes align */
	desc_offset = (async_task->desc_len % 64) ?
		(async_task->desc_len + 64 - (async_task->desc_len % 64)) : async_task->desc_len;
	FILL_DESC(async_task->desc_buf, ctrl, ndl, ndu,
		cpu_dma_addr, ipu_ram_dma_addr, desc_offset);

	memcpy_toio((void __iomem *)(async_task->host_desc_addr + desc_offset),
		async_task->desc_buf + desc_offset, desc_size);

	return 0;
}

/*
 * The table is used for debug regs dump, very important for us
 * WARNING: different platform have different reg base,
 * we need check every regs carefully with hardware enginer, do not just copy
 */
static struct pcie_dump_reg_s c50_reg[] = {
		{"PCIE ENGINE chn8 ctrl", ENGINE(PF_ENG_NUM)},
		{NULL, ENGINE(PF_ENG_NUM) + 0x4},
		{NULL, ENGINE(PF_ENG_NUM) + 0x8},
		{NULL, ENGINE(PF_ENG_NUM) + 0xC},
		{NULL, ENGINE(PF_ENG_NUM) + 0x10},
		{NULL, ENGINE(PF_ENG_NUM) + 0x1C},

		{"PCIE QUEUE 0 ctrl", QUEUE(PF_ENG_NUM, 0)},
		{NULL, QUEUE(PF_ENG_NUM, 0) + 0x4},
		{NULL, QUEUE(PF_ENG_NUM, 0) + 0x8},
		{NULL, QUEUE(PF_ENG_NUM, 0) + 0xC},
		{NULL, QUEUE(PF_ENG_NUM, 0) + 0x20},
		{NULL, QUEUE(PF_ENG_NUM, 0) + 0x24},
		{NULL, QUEUE(PF_ENG_NUM, 0) + 0x28},

		{"PCIE QUEUE 1 ctrl", QUEUE(PF_ENG_NUM, 1)},
		{NULL, QUEUE(PF_ENG_NUM, 1) + 0x4},
		{NULL, QUEUE(PF_ENG_NUM, 1) + 0x8},
		{NULL, QUEUE(PF_ENG_NUM, 1) + 0xC},
		{NULL, QUEUE(PF_ENG_NUM, 1) + 0x20},
		{NULL, QUEUE(PF_ENG_NUM, 1) + 0x24},
		{NULL, QUEUE(PF_ENG_NUM, 1) + 0x28},

		{"PCIE QUEUE 2 ctrl", QUEUE(PF_ENG_NUM, 2)},
		{NULL, QUEUE(PF_ENG_NUM, 2) + 0x4},
		{NULL, QUEUE(PF_ENG_NUM, 2) + 0x8},
		{NULL, QUEUE(PF_ENG_NUM, 2) + 0xC},
		{NULL, QUEUE(PF_ENG_NUM, 2) + 0x20},
		{NULL, QUEUE(PF_ENG_NUM, 2) + 0x24},
		{NULL, QUEUE(PF_ENG_NUM, 2) + 0x28},

		{"PCIE QUEUE 3 ctrl", QUEUE(PF_ENG_NUM, 3)},
		{NULL, QUEUE(PF_ENG_NUM, 3) + 0x4},
		{NULL, QUEUE(PF_ENG_NUM, 3) + 0x8},
		{NULL, QUEUE(PF_ENG_NUM, 3) + 0xC},
		{NULL, QUEUE(PF_ENG_NUM, 3) + 0x20},
		{NULL, QUEUE(PF_ENG_NUM, 3) + 0x24},
		{NULL, QUEUE(PF_ENG_NUM, 3) + 0x28},

		{"PCIE IRQ MASK", PCIE_IRQ_MASK(0)}, {NULL, PCIE_IRQ_MASK(1)},
		{NULL, PCIE_IRQ_MASK(2)}, {NULL, PCIE_IRQ_MASK(3)},
		{NULL, PCIE_IRQ_MASK(4)}, {NULL, PCIE_IRQ_MASK(5)},
		{NULL, PCIE_IRQ_MASK(6)}, {NULL, PCIE_IRQ_MASK(7)},
		{NULL, PCIE_IRQ_MASK(8)}, {NULL, PCIE_IRQ_MASK(9)},
		{NULL, PCIE_IRQ_MASK(10)}, {NULL, PCIE_IRQ_MASK(11)},
		{NULL, PCIE_IRQ_MASK(12)}, {NULL, PCIE_IRQ_MASK(13)},
		{NULL, PCIE_IRQ_MASK(14)}, {NULL, PCIE_IRQ_MASK(15)},
		{NULL, PCIE_IRQ_MASK(16)}, {NULL, PCIE_IRQ_MASK(17)},
		{NULL, PCIE_IRQ_MASK(18)}, {NULL, PCIE_IRQ_MASK(19)},
		{NULL, PCIE_IRQ_MASK(20)}, {NULL, PCIE_IRQ_MASK(21)},
		{NULL, PCIE_IRQ_MASK(22)}, {NULL, PCIE_IRQ_MASK(23)},
		{NULL, PCIE_IRQ_MASK(24)}, {NULL, PCIE_IRQ_MASK(25)},
		{NULL, PCIE_IRQ_MASK(26)}, {NULL, PCIE_IRQ_MASK(27)},
		{NULL, PCIE_IRQ_MASK(28)}, {NULL, PCIE_IRQ_MASK(29)},
		{NULL, PCIE_IRQ_MASK(30)}, {NULL, PCIE_IRQ_MASK(31)},
		{NULL, PCIE_IRQ_MASK(32)}, {NULL, PCIE_IRQ_MASK(32 + 1)},
		{NULL, PCIE_IRQ_MASK(32 + 2)},

		{"PCIE IRQ STATUS", PCIE_IRQ_STATUS(0)}, {NULL, PCIE_IRQ_STATUS(1)},
		{NULL, PCIE_IRQ_STATUS(2)}, {NULL, PCIE_IRQ_STATUS(3)},
		{NULL, PCIE_IRQ_STATUS(4)}, {NULL, PCIE_IRQ_STATUS(5)},
		{NULL, PCIE_IRQ_STATUS(6)}, {NULL, PCIE_IRQ_STATUS(7)},
		{NULL, PCIE_IRQ_STATUS(8)}, {NULL, PCIE_IRQ_STATUS(9)},
		{NULL, PCIE_IRQ_STATUS(10)}, {NULL, PCIE_IRQ_STATUS(11)},
		{NULL, PCIE_IRQ_STATUS(12)}, {NULL, PCIE_IRQ_STATUS(13)},
		{NULL, PCIE_IRQ_STATUS(14)}, {NULL, PCIE_IRQ_STATUS(15)},
		{NULL, PCIE_IRQ_STATUS(16)}, {NULL, PCIE_IRQ_STATUS(17)},
		{NULL, PCIE_IRQ_STATUS(18)}, {NULL, PCIE_IRQ_STATUS(19)},
		{NULL, PCIE_IRQ_STATUS(20)}, {NULL, PCIE_IRQ_STATUS(21)},
		{NULL, PCIE_IRQ_STATUS(22)}, {NULL, PCIE_IRQ_STATUS(23)},
		{NULL, PCIE_IRQ_STATUS(24)}, {NULL, PCIE_IRQ_STATUS(25)},
		{NULL, PCIE_IRQ_STATUS(26)}, {NULL, PCIE_IRQ_STATUS(27)},
		{NULL, PCIE_IRQ_STATUS(28)}, {NULL, PCIE_IRQ_STATUS(29)},
		{NULL, PCIE_IRQ_STATUS(30)}, {NULL, PCIE_IRQ_STATUS(31)},
		{NULL, PCIE_IRQ_STATUS(32)}, {NULL, PCIE_IRQ_STATUS(32 + 1)},
		{NULL, PCIE_IRQ_STATUS(32 + 2)},

		{"PCIE GIC mask", GIC_MASK},
		{NULL, GIC_MASK + 4}, { NULL, GIC_MASK + 8},
		{NULL, GIC_MASK + 12}, {NULL, GIC_MASK + 16},
		{NULL, GIC_MASK + 20}, {NULL, GIC_MASK + 24},
		{NULL, GIC_MASK + 28}, {NULL, GIC_MASK + 32},
		{NULL, GIC_MASK + 36}, {NULL, GIC_MASK + 40},
		{NULL, GIC_MASK + 44}, {NULL, GIC_MASK + 48},
		{NULL, GIC_MASK + 52}, {NULL, GIC_MASK + 56},
		{NULL, GIC_MASK + 60},
		{"PCIE GIC status", GIC_STATUS},
		{NULL, GIC_STATUS + 4}, {NULL, GIC_STATUS + 8},
		{NULL, GIC_STATUS + 12}, {NULL, GIC_STATUS + 16},
		{NULL, GIC_STATUS + 20}, {NULL, GIC_STATUS + 24},
		{NULL, GIC_STATUS + 28}, {NULL, GIC_STATUS + 32},
		{NULL, GIC_STATUS + 36}, {NULL, GIC_STATUS + 40},
		{NULL, GIC_STATUS + 44}, {NULL, GIC_STATUS + 48},
		{NULL, GIC_STATUS + 52}, {NULL, GIC_STATUS + 56},
		{NULL, GIC_STATUS + 60},

		{"PCIE GIC MSIX VECTOR count", GIC_MSIX_VECTOR_COUNT},
		{"PCIE MSIX clear register", GIC_MSIX_PEND_CLR},
		{NULL, GIC_MSIX_PEND_CLR + 4}, {NULL, GIC_MSIX_PEND_CLR + 8},
		{NULL, GIC_MSIX_PEND_CLR + 12}, {NULL, GIC_MSIX_PEND_CLR + 16},
		{NULL, GIC_MSIX_PEND_CLR + 20}, {NULL, GIC_MSIX_PEND_CLR + 24},
		{NULL, GIC_MSIX_PEND_CLR + 28}, {NULL, GIC_MSIX_PEND_CLR + 32},
		{NULL, GIC_MSIX_PEND_CLR + 36}, {NULL, GIC_MSIX_PEND_CLR + 40},
		{NULL, GIC_MSIX_PEND_CLR + 44}, {NULL, GIC_MSIX_PEND_CLR + 48},
		{NULL, GIC_MSIX_PEND_CLR + 52}, {NULL, GIC_MSIX_PEND_CLR  + 56},
		{NULL, GIC_MSIX_PEND_CLR + 60},

		{"PCIE GIC_CTRL", GIC_CTRL},
};

static struct pcie_dump_reg_s mlu580_top_dump_reg[] = {
	{"TOP_Bar00_DATA_Intr",  0x290200},
	{"TOP_Bar00_CFG_Intr",   0x290204},
	{"TOP_Bar01_DATA_Intr",  0x1a30200},
	{"TOP_Bar10_DATA_Intr",  0x1c20100},
	{"TOP_Bar11_DATA_Intr",  0x1e20100},
	{"TOP_Bar20_DATA_Intr",  0x2020100},
	{"TOP_Bar21_DATA_Intr",  0x2220100},
	{"TOP_Bar30_DATA_Intr",  0x2430200},
	{"TOP_Bar31_DATA_Intr",  0x2620200},
	{"TOP_Middle0_Intr",     0xa80120},
	{"TOP_Middle1_Intr",     0xc80120},
	{"TOP_Middle2_Intr",     0xe80120},
	{"TOP_Middle6_Intr",     0x1680120},
	{"TOP_Middle7_Intr",     0x1880120},
	{"TOP_South0_DATA_Intr", 0x400078},
	{"TOP_South0_CFG_Intr",  0x400094},
	{"TOP_South1_DATA_Intr", 0x600064},
	{"TOP_South1_CFG_Intr",  0x600074},
	{"TOP_West2_DATA_Intr",  0x3010050},
	{"TOP_West4_DATA_Intr",  0x2800038},
	{"TOP_Eest2_DATA_Intr",  0x3810050},
	{"TOP_Eest4_DATA_Intr",  0x2a00038},
	{"TOP_Bar00_Data_Idle",  0x290014},
	{"TOP_Bar00_CFG_Idle",   0x290018},
	{"TOP_Bar01_DATA_Idle",  0x1a30014},
	{"TOP_Bar10_DATA_Idle",  0x1c20028},
	{"TOP_Bar11_DATA_Idle",  0x1e2002c},
	{"TOP_Bar20_DATA_Idle",  0x202002c},
	{"TOP_Bar21_DATA_Idle",  0x2220028},
	{"TOP_Bar30_DATA_Idle",  0x2430014},
	{"TOP_Bar31_DATA_Idle",  0x2620014},
	{"TOP_Middle0_Idle",     0xa80010},
	{"TOP_Middle1_Idle",     0xc80010},
	{"TOP_Middle2_Idle",     0xe80010},
	{"TOP_Middle6_Idle",     0x1680010},
	{"TOP_Middle7_Idle",     0x1880010},
	{"TOP_South0_Data_Idle", 0x400018},
	{"TOP_South0_CFG_Idle",  0x40001c},
	{"TOP_South1_Data_Idle", 0x600010},
	{"TOP_South1_CFG_Idle",  0x600014},
	{"TOP_West2_DATA_Idle",  0x3010010},
	{"TOP_West4_DATA_Idle",  0x280000c},
	{"TOP_Eest2_DATA_Idle",  0x3810010},
	{"TOP_Eest4_DATA_Idle",  0x2a0000c}
};

static struct pcie_dump_reg_s mlu590_top_dump_reg[] = {
	{"TOP_Bar00_DATA_Intr",  0x949200},
	{"TOP_Bar00_CFG_Intr",   0x949204},
	{"TOP_Bar01_DATA_Intr",  0x94a200},
	{"TOP_Bar10_DATA_Intr",  0x94b100},
	{"TOP_Bar11_DATA_Intr",  0x94c100},
	{"TOP_Bar20_DATA_Intr",  0x94d100},
	{"TOP_Bar21_DATA_Intr",  0x94e100},
	{"TOP_Bar30_DATA_Intr",  0x94f200},
	{"TOP_Bar31_DATA_Intr",  0x950200},
	{"TOP_Middle00_0_Intr",  0x95104c},
	{"TOP_Middle00_1_Intr",  0x951058},
	{"TOP_Middle10_0_Intr",  0x957028},
	{"TOP_Middle10_1_Intr",  0x957060},
	{"TOP_Middle05_Intr",    0x956038},
	{"TOP_Middle15_0_Intr",  0x95c070},
	{"TOP_Middle15_1_Intr",  0x95c07c},
	{"TOP_South0_DATA_Intr", 0x946100},
	{"TOP_South1_DATA_Intr", 0x947100},
	{"TOP_South1_CFG_Intr",  0x94710c},
	{"TOP_South2_DATA_Intr", 0x948100},
	{"TOP_West0_DATA_Intr",  0x943124},
	{"TOP_West1_DATA_Intr",  0x944124},
	{"TOP_West2_DATA_Intr",  0x945120},
	{"TOP_Eest0_DATA_Intr",  0x940124},
	{"TOP_Eest1_DATA_Intr",  0x941124},
	{"TOP_Eest2_DATA_Intr",  0x942120},
	{"TOP_Bar00_Data_Idle",  0x949014},
	{"TOP_Bar00_CFG_Idle",   0x949018},
	{"TOP_Bar01_DATA_Idle",  0x94a014},
	{"TOP_Bar10_DATA_Idle",  0x94b028},
	{"TOP_Bar11_DATA_Idle",  0x94c02c},
	{"TOP_Bar20_DATA_Idle",  0x94d02c},
	{"TOP_Bar21_DATA_Idle",  0x94e028},
	{"TOP_Bar30_DATA_Idle",  0x94f014},
	{"TOP_Bar31_DATA_Idle",  0x950014},
	{"TOP_Middle00_Idle",    0x951068},
	{"TOP_Middle10_0_Idle",  0x957034},
	{"TOP_Middle10_1_Idle",  0x95706c},
	{"TOP_Middle05_Idle",    0x956044},
	{"TOP_Middle15_0_Idle",  0x95c034},
	{"TOP_Middle15_1_Idle",  0x95c08c},
	{"TOP_South0_Data_Idle", 0x946014},
	{"TOP_South1_Data_Idle", 0x947018},
	{"TOP_South1_CFG_Idle",  0x94701c},
	{"TOP_South2_Data_Idle", 0x948014},
	{"TOP_West0_DATA_Idle",  0x94300c},
	{"TOP_West1_DATA_Idle",  0x944010},
	{"TOP_West2_DATA_Idle",  0x94500c},
	{"TOP_Eest0_DATA_Idle",  0x94000c},
	{"TOP_Eest1_DATA_Idle",  0x941010},
	{"TOP_Eest2_DATA_Idle",  0x94200c}
};

static struct pcie_dump_reg_s c50_dump_reg[] = {
		{"PCIe GIC", GIC_STATUS + 0x0},
		{NULL, GIC_STATUS + 0x4},
		{NULL, GIC_STATUS + 0x8},
		{NULL, GIC_STATUS + 0xc},
		{NULL, GIC_STATUS + 0x10},
		{NULL, GIC_STATUS + 0x14},
		{NULL, GIC_STATUS + 0x18},
		{NULL, GIC_STATUS + 0x1c},
		{NULL, GIC_STATUS + 0x20},
		{NULL, GIC_STATUS + 0x24},
		{NULL, GIC_STATUS + 0x28},
		{NULL, GIC_STATUS + 0x2c},
		{NULL, GIC_STATUS + 0x30},
		{NULL, GIC_STATUS + 0x34},
		{NULL, GIC_STATUS + 0x38},
		{NULL, GIC_STATUS + 0x3c},

		{"PCIe counter", PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x0},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x4},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x8},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xc},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x10},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x14},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x18},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x1c},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x20},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x24},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x28},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x2c},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x30},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x34},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x38},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x3c},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x40},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x44},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x48},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x4c},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x50},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x54},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x58},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x5c},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x60},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x64},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x68},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x6c},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x70},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x74},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x78},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x7c},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x80},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x84},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x88},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x8c},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x90},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x94},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x98},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0x9c},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xa0},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xa4},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xa8},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xac},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xb0},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xb4},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xb8},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xbc},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xc0},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xc4},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xc8},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xcc},
		{NULL, PCIE_APP_LAYER_SIDEBAND + 0xa0 + 0xd0}
};

static void c50_pcie_dump_fetch_reg(struct cn_pcie_set *pcie_set)
{
	int queue;
	int deep;

	for_each_set_bit(queue, (unsigned long *)&pcie_set->dma_set.dma_phy_channel_mask,
		pcie_set->dma_set.max_phy_channel) {
		for (deep = 0; deep < DMA_QUEUE_BUFF; deep++) {
			cn_dev_pcie_info(pcie_set, "DUMP:queue%d_deep%d", queue, deep);
			cn_dev_pcie_info(pcie_set, "DBG=%#x",
						deep | (1 << (queue * 2 + 3)) | (1 << 11));
			cn_dev_pcie_info(pcie_set, "CMD QUEUE%d", queue);
			cn_pci_reg_write32(pcie_set, DBG_SEL_QUEUE(0, 0),
						deep | (1 << (queue * 2 + 3)) | (1 << 11));
			cn_dev_pcie_info(pcie_set, "DATA0=%#x",
					cn_pci_reg_read32(pcie_set, DBG_DATA0_QUEUE(0, 0)));
			cn_dev_pcie_info(pcie_set, "DATA1=%#x",
					cn_pci_reg_read32(pcie_set, DBG_DATA1_QUEUE(0, 0)));
			cn_dev_pcie_info(pcie_set, "DATA2=%#x",
					cn_pci_reg_read32(pcie_set, DBG_DATA2_QUEUE(0, 0)));
			cn_dev_pcie_info(pcie_set, "DATA3=%#x",
					cn_pci_reg_read32(pcie_set, DBG_DATA3_QUEUE(0, 0)));
			cn_dev_pcie_info(pcie_set, "DATA4=%#x",
					cn_pci_reg_read32(pcie_set, DBG_DATA4_QUEUE(0, 0)));
			cn_dev_pcie_info(pcie_set, "DBG=%#x",
					deep | (1 << ((queue * 2 + 1) + 3)) | (1 << 11));
			cn_dev_pcie_info(pcie_set, "STATUS BUF%d", queue);
			cn_pci_reg_write32(pcie_set, DBG_SEL_QUEUE(0, 0),
					deep | (1 << ((queue * 2 + 1) + 3)) | (1 << 11));
			cn_dev_pcie_info(pcie_set, "DATA0=%#x",
					cn_pci_reg_read32(pcie_set, DBG_DATA0_QUEUE(0, 0)));
			cn_dev_pcie_info(pcie_set, "DATA1=%#x",
					cn_pci_reg_read32(pcie_set, DBG_DATA1_QUEUE(0, 0)));
			cn_dev_pcie_info(pcie_set, "DATA2=%#x",
					cn_pci_reg_read32(pcie_set, DBG_DATA2_QUEUE(0, 0)));
			cn_dev_pcie_info(pcie_set, "DATA3=%#x",
					cn_pci_reg_read32(pcie_set, DBG_DATA3_QUEUE(0, 0)));
			cn_dev_pcie_info(pcie_set, "DATA4=%#x",
					cn_pci_reg_read32(pcie_set, DBG_DATA4_QUEUE(0, 0)));
		}
	}
}

static void OVER_WRITE(pcie_dump_reg)(struct cn_pcie_set *pcie_set)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(c50_reg); i++) {
		if (c50_reg[i].desc)
			cn_dev_pcie_err(pcie_set, "%s:", c50_reg[i].desc);

		cn_dev_pcie_info(pcie_set, "[0x%lx]=%#08x", c50_reg[i].reg,
		cn_pci_reg_read32(pcie_set, c50_reg[i].reg));
	}
	c50_pcie_dump_fetch_reg(pcie_set);
}

static void OVER_WRITE(pcie_debug_dump_reg)(struct cn_pcie_set *pcie_set)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(c50_dump_reg); i++) {
		if (c50_dump_reg[i].desc)
			cn_dev_pcie_bug_report(pcie_set, "%s:", c50_dump_reg[i].desc);

		cn_dev_pcie_bug_report(pcie_set, "[0x%lx]=%#08x",
				c50_dump_reg[i].reg, cn_pci_reg_read32(pcie_set, c50_dump_reg[i].reg));
	}

	if (pcie_set->id == MLUID_590) {
		for (i = 0; i < ARRAY_SIZE(mlu590_top_dump_reg); i++) {
			if (mlu590_top_dump_reg[i].desc)
				cn_dev_pcie_bug_report(pcie_set, "%s:", mlu590_top_dump_reg[i].desc);

			cn_dev_pcie_bug_report(pcie_set, "[0x%lx]=%#08x",
					mlu590_top_dump_reg[i].reg, cn_pci_reg_read32(pcie_set, mlu590_top_dump_reg[i].reg));
		}
	} else if (pcie_set->id == MLUID_580) {
		for (i = 0; i < ARRAY_SIZE(mlu580_top_dump_reg); i++) {
			if (mlu580_top_dump_reg[i].desc)
				cn_dev_pcie_bug_report(pcie_set, "%s:", mlu580_top_dump_reg[i].desc);

			cn_dev_pcie_bug_report(pcie_set, "[0x%lx]=%#08x",
					mlu580_top_dump_reg[i].reg, cn_pci_reg_read32(pcie_set, mlu580_top_dump_reg[i].reg));
		}
	} else {
		cn_dev_pcie_err(pcie_set, "device not support dump top reg");
	}
}

static u64 OVER_WRITE(pcie_set_bar_window)(u64 axi_address,
		struct bar_resource *resource, struct cn_pcie_set *pcie_set)
{
	u64 addr;

	addr = resource->window_addr;
	if (axi_address >= addr && axi_address < (addr + resource->size))
		return addr;

	axi_address &= (~((u64)(resource->size - 1)));

	cn_pci_reg_write32(pcie_set, resource->reg,
			(u32)(axi_address >> resource->pre_align_to_reg));
	cn_pci_reg_read32(pcie_set, resource->reg);

	resource->window_addr = axi_address;

	return axi_address;
}

static int pcie_set_bar0_window(u64 axi_addr, unsigned long *offset,
						struct cn_pcie_set *pcie_set)
{
	int quadrant = 3;
	u32 bar0_level_base;
	u32 bar0_level_size;
	u32 bar0_fixed_size;
	u32 win_base;
	struct bar0_set *bar0_set = NULL;

	bar0_set = &pcie_set->bar0_set;
	*offset = axi_addr & BAR0_MASK;
	win_base = *offset;

	/* 0~3win = 4MB * 4 + bar0_set->bar0_window_base * 0x100000 * 3*/
	bar0_level_base = bar0_set->bar0_window_base;
	bar0_level_size = bar0_level_base << ilog2(BAR_BASE_SIZE);
	bar0_fixed_size = C50_BAR0_LEVEL0_4M * 4 + bar0_level_size * 3;
	if (*offset >= bar0_fixed_size) {
		win_base &= (~(bar0_level_size - 1));
		win_base >>= ilog2(BAR_BASE_SIZE);
		win_base |= (QUADRANT_BASE(0));
		if (win_base != bar0_set->bar0_window_tgt[quadrant]) {
			if (!down_interruptible
			    (&bar0_set->bar0_window_sem[quadrant])) {
				cn_pci_reg_write32(pcie_set,
					BAR0_TO_AXI_TGT_WIN(3 + quadrant),
					win_base);
				bar0_set->bar0_window_flag[quadrant] = 1;
				bar0_set->bar0_window_tgt[quadrant] = win_base;
			} else {
				*offset = 0x1000;//deviceid
				cn_dev_pcie_err(pcie_set,
					"bar0 win%d sem err", quadrant);
				return quadrant;
			}
			cn_pci_reg_read32(pcie_set,
				BAR0_TO_AXI_TGT_WIN(3 + quadrant));
		}
		*offset = bar0_fixed_size + *offset % bar0_level_size;
	}

	return quadrant;
}

static u32 OVER_WRITE(pcie_reg_read32)(u64 axi_addr, struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	u32 data;
	int quadrant;
	struct bar0_set *bar0_set = NULL;

	if (axi_addr < 0x2000) {
		cn_dev_pcie_err(pcie_set, "reg_read illegal addr:%#llx", axi_addr);
		dump_stack();
	}

	bar0_set = &pcie_set->bar0_set;
	quadrant = pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag[quadrant]) {
		data = ioread32(pcie_set->bar0_set.reg_virt_base + offset);
		bar0_set->bar0_window_flag[quadrant] = 0;
		up(&bar0_set->bar0_window_sem[quadrant]);
	} else
		data = ioread32(pcie_set->bar0_set.reg_virt_base + offset);

	return data;
}

static void OVER_WRITE(pcie_reg_write32)(u64 axi_addr, u32 data,
						struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	int quadrant;
	struct bar0_set *bar0_set = NULL;

	bar0_set = &pcie_set->bar0_set;
	quadrant = pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag[quadrant]) {
		iowrite32(data, pcie_set->bar0_set.reg_virt_base + offset);
		bar0_set->bar0_window_flag[quadrant] = 0;
		up(&bar0_set->bar0_window_sem[quadrant]);
	} else
		iowrite32(data, pcie_set->bar0_set.reg_virt_base + offset);
}

static u64 OVER_WRITE(pcie_reg_read64)(u64 axi_addr, struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	u64 data;
	int quadrant;
	struct bar0_set *bar0_set = NULL;

	if (axi_addr < 0x2000) {
		cn_dev_pcie_err(pcie_set, "reg_read illegal addr:%#llx", axi_addr);
		dump_stack();
	}

	bar0_set = &pcie_set->bar0_set;
	quadrant = pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag[quadrant]) {

		data = ioread32(pcie_set->bar0_set.reg_virt_base + offset + 4);
		data <<= 32;
		data |= ioread32(pcie_set->bar0_set.reg_virt_base + offset);
		bar0_set->bar0_window_flag[quadrant] = 0;
		up(&bar0_set->bar0_window_sem[quadrant]);
	} else {
		data = ioread32(pcie_set->bar0_set.reg_virt_base + offset + 4);
		data <<= 32;
		data |= ioread32(pcie_set->bar0_set.reg_virt_base + offset);
	}

	return data;
}

static void OVER_WRITE(pcie_reg_write64)(u64 axi_addr, u64 data,
						struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	int quadrant;
	struct bar0_set *bar0_set = NULL;

	bar0_set = &pcie_set->bar0_set;
	quadrant = pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag[quadrant]) {
		iowrite32(LOWER32(data), pcie_set->bar0_set.reg_virt_base + offset);
		iowrite32(UPPER32(data), pcie_set->bar0_set.reg_virt_base + offset + 4);

		bar0_set->bar0_window_flag[quadrant] = 0;
		up(&bar0_set->bar0_window_sem[quadrant]);
	} else {

		iowrite32(LOWER32(data), pcie_set->bar0_set.reg_virt_base + offset);
		iowrite32(UPPER32(data), pcie_set->bar0_set.reg_virt_base + offset + 4);
	}
}

static int OVER_WRITE(pcie_check_available)(struct cn_pcie_set *pcie_set)
{
	u32 reg_data;

	reg_data = cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
	if (reg_data == REG_VALUE_INVALID) {
		cn_dev_pcie_err(pcie_set, "NOC bus abnormal, read value = %#x", reg_data);
		return -1;
	}

	return 0;
}

static void host_pf_queue_status_buf_status(int engine,
			int *queue_status_buf_num, struct cn_pcie_set *pcie_set)
{
	int queue;
	u32 status_buf_status;

	status_buf_status = cn_pci_reg_read32(pcie_set,
				CMD_STATUS_BUF_STATUS_ENGINE(engine));
	for (queue = 0; queue < DMA_MAX_QUEUE_NUM; queue++) {
		queue_status_buf_num[queue] = GET_BITS_VAL(status_buf_status,
						queue * 8 + 3, queue * 8 + 0);
		cn_dev_pcie_debug(pcie_set, "queue%d_status_buf_num=%d",
					queue, queue_status_buf_num[queue]);
	}
}

static irqreturn_t c50_pcie_dma_interrupt_handle(int index, void *data)
{
	unsigned int queue_status;
	int queue_status_buf_num[4];
	int phy_channel;
	int engine = index;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct dma_channel_info *channel;
	int command_id;

	/****
	 * Attention:
	 *	Close 'pcie_set->do_dma_irq_status  0/1 state-machine check'!!!
	 *	It is redundant code for MLU590. Because all the queue use the
	 *	same one MSI-X IRQ, and for host it FIXED to No.0.
	 */

	/*
	 * read dma interrupt register to get which queue generate interrupt
	 * This interrupt may be done or error.not is done and error.
	 */
	host_pf_queue_status_buf_status(engine, queue_status_buf_num, pcie_set);
	for_each_set_bit(phy_channel, (unsigned long *)&pcie_set->dma_set.dma_phy_channel_mask,
		pcie_set->dma_set.max_phy_channel) {
		if (!queue_status_buf_num[phy_channel])
			continue;

		while (queue_status_buf_num[phy_channel]) {
			queue_status = cn_pci_reg_read32(pcie_set,
					DMA_STATUS_QUEUE(engine, phy_channel));
			command_id = GET_BITS_VAL(queue_status, 25, 22);
			cn_dev_pcie_debug(pcie_set, "command_id=%d", command_id);

			channel = (struct dma_channel_info *)
				pcie_set->dma_set.running_channels[phy_channel][command_id];
			if (!channel) {
				cn_dev_pcie_err(pcie_set,
					"phy_channel:%d is NULL", phy_channel);
				break;
			}

			if (DMA_QUEUE_ERR_CHECK(queue_status)) {
				cn_dev_pcie_err(pcie_set, "queue%d irq error:%#x direction:%d",
						phy_channel, queue_status, channel->direction);
				if (pcie_set->ops->dump_reg)
					pcie_set->ops->dump_reg(pcie_set);
				pcie_set->ops->show_desc_list(channel);
				cn_pci_reg_write32(pcie_set,
					DMA_STATUS_UP_QUEUE(engine, phy_channel), 1);
				cn_pci_dma_complete(phy_channel, command_id,
						CHANNEL_COMPLETED_ERR, pcie_set);
			} else {
				cn_pci_reg_write32(pcie_set,
					DMA_STATUS_UP_QUEUE(engine, phy_channel), 1);
				if (pcie_set->dfx.dma_err_inject_flag) {
					pcie_set->dfx.dma_err_inject_flag = 0;
					cn_dev_pcie_err(pcie_set,
						"DMA interrupt status: Fake Manual Error.");
					cn_pci_dma_complete(phy_channel, command_id,
						CHANNEL_COMPLETED_ERR, pcie_set);
				} else {
					cn_pci_dma_complete(phy_channel, command_id,
						CHANNEL_COMPLETED, pcie_set);
				}
			}
			queue_status_buf_num[phy_channel]--;
		}
	}

	cn_pci_task_fair_schedule(pcie_set);
	return IRQ_HANDLED;
}

static int OVER_WRITE(pcie_dma_go)(struct dma_channel_info *channel, int phy_channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	struct pcie_dma_task *task = channel->task;
	unsigned long desc_addr = 0;
	unsigned int desc_num = 0;
	unsigned int memset_type = 0;
	unsigned long flag = 0;

	if (channel->status != CHANNEL_RUNNING)
		cn_dev_pcie_err(pcie_set, "channel is not locked %d", channel->status);

	spin_lock_irqsave(&pcie_set->dma_set.fetch_lock[phy_channel], flag);
	switch (channel->direction) {
	case DMA_H2D:
		cn_pci_reg_write32(pcie_set,
			CTRL_CMD_CTRL1_QUEUE(PF_ENG_NUM, phy_channel),
			(PCIE_TO_AXI << 0) | (SRC_ID_AXI << 2) | (PCIE_SNOOP << 4));
		break;
	case DMA_D2H:
		cn_pci_reg_write32(pcie_set,
			CTRL_CMD_CTRL1_QUEUE(PF_ENG_NUM, phy_channel),
			(AXI_TO_PCIE << 0) | (SRC_ID_AXI << 2) | (PCIE_SNOOP << 20));
		break;
	case DMA_P2P:
		if (pcie_set->cfg.p2p_mode == P2P_PULL_MODE) {
			cn_pci_reg_write32(pcie_set,
				CTRL_CMD_CTRL1_QUEUE(PF_ENG_NUM, phy_channel),
				(PCIE_TO_AXI << 0) | (SRC_ID_AXI << 2) | (PCIE_SNOOP << 4));
		} else {
			cn_pci_reg_write32(pcie_set,
				CTRL_CMD_CTRL1_QUEUE(PF_ENG_NUM, phy_channel),
				(AXI_TO_PCIE << 0) | (SRC_ID_AXI << 2) | (PCIE_SNOOP << 20));
		}
		break;
	case MEMSET_D8:
		memset_type = 1 << 28;
		break;
	case MEMSET_D16:
		memset_type = 2 << 28;
		break;
	case MEMSET_D32:
		memset_type = 4 << 28;
		break;
	default:
		cn_dev_pcie_err(pcie_set, "channel->direction=%d undefined, Just go even may be dma error.",
							channel->direction);
		/***
		 * Note:
		 *	In normal used situation, will never arrive here.
		 *	Even developer mode can match this, we also let it JUST-GO with ERROR log.
		 *	And to wait any result the DMA report.
		 */
	}

	if (task->dma_type == PCIE_DMA_MEMSET) {
		cn_pci_reg_write32(pcie_set,
				CTRL_LOW_QUEUE(PF_ENG_NUM, phy_channel),
				LOWER32(channel->ram_addr));
		cn_pci_reg_write32(pcie_set,
				CTRL_HIGH_QUEUE(PF_ENG_NUM, phy_channel),
				UPPER16(channel->ram_addr) | memset_type |
				(channel->fetch_command_id << 24));
		cn_pci_reg_write64(pcie_set,
				CTRL_DESC_NUM_QUEUE(PF_ENG_NUM, phy_channel),
				channel->cpu_addr);

		cn_pci_reg_read32(pcie_set,
				CTRL_CMD_CTRL1_QUEUE(PF_ENG_NUM, phy_channel));
		cn_pci_reg_write32(pcie_set,
				CTRL_CMD_CTRL2_QUEUE(PF_ENG_NUM, phy_channel),
				(0x1 << 31) | (0x1 << 30) |
				(channel->transfer_length & (~(0xC0000000))));
		spin_unlock_irqrestore(&pcie_set->dma_set.fetch_lock[phy_channel], flag);

		return 0;
	}

	desc_addr = channel->desc_device_va;
	desc_num = channel->desc_len / pcie_set->per_desc_size;

	cn_pci_reg_write32(pcie_set, CTRL_LOW_QUEUE(PF_ENG_NUM, phy_channel),
					LOWER32(desc_addr));
	cn_pci_reg_write32(pcie_set, CTRL_HIGH_QUEUE(PF_ENG_NUM, phy_channel),
					UPPER32(desc_addr));
	cn_pci_reg_write32(pcie_set, CTRL_DESC_NUM_QUEUE(PF_ENG_NUM, phy_channel),
					desc_num | (channel->fetch_command_id << 16));
	cn_pci_reg_read32(pcie_set, CTRL_DESC_NUM_QUEUE(PF_ENG_NUM, phy_channel));
	cn_pci_reg_write32(pcie_set, CTRL_CMD_CTRL2_QUEUE(PF_ENG_NUM, phy_channel),
					(0x1 << 31));

	spin_unlock_irqrestore(&pcie_set->dma_set.fetch_lock[phy_channel], flag);

	return 0;
}

#ifdef CONFIG_PCI_IOV
static int c50_sriov_support(struct cn_pcie_set *pcie_set)
{
	int total_vfs;
	u64 vf_bar0_size;
	int vf;

	vf_bar0_size = pci_resource_len(
		pcie_set->pdev, PCI_IOV_RESOURCES);

	total_vfs = pci_sriov_get_totalvfs(pcie_set->pdev);
	if (total_vfs * pcie_set->bar0_set.size != vf_bar0_size)
		return 0;

	for (vf = 0; vf < 6; vf += 2)
		if (!pci_resource_start(pcie_set->pdev, PCI_IOV_RESOURCES + vf))
			return 0;

	return 1;
}
#endif

static int c50_dma_bypass_smmu(int phy_ch, bool en, struct cn_pcie_set *pcie_set)
{
	int ret;

	phy_ch = phy_ch + DMA_SMMU_STREAM_ID;
	ret = cn_smmu_cau_bypass(pcie_set->bus_set->core, phy_ch, en);

	return ret;
}

static int c50_dma_bypass_smmu_all(bool en, struct cn_pcie_set *pcie_set)
{
	int ret;
	int eng;
	u32 reg_val;

	for (eng = 0; eng < DMA_REG_CHANNEL_NUM; eng++) {
		ret = cn_smmu_cau_bypass(pcie_set->bus_set->core,
				eng + DMA_SMMU_STREAM_ID, en);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "eng[%d] smmu cau bypass error:%d",
					eng, ret);
			return ret;
		}
	}

	reg_val = cn_pci_reg_read32(pcie_set, 0x58080);
	if (en) {
		reg_val |= 0x10;
	} else {
		reg_val &= 0xf;
	}
	cn_pci_reg_write32(pcie_set, 0x58080, reg_val);

	return ret;
}

static void c50_pcie_sync_write_exit(struct cn_pcie_set *pcie_set)
{
	u64 dev_va;
	unsigned long host_kva;

	dev_va = pcie_set->sw_set.sw_dev_va;
	host_kva = pcie_set->sw_set.sw_host_kva;
	if (host_kva && dev_va) {
		cn_device_share_mem_free(0, host_kva, dev_va, pcie_set->bus_set->core);
	}
}

static int c50_pcie_sync_write_alloc(struct cn_pcie_set *pcie_set, u64 flag_dev_pa)
{
	struct sync_write *sw;
	int sw_index;

	if ((flag_dev_pa % 4) != 0) {
		cn_dev_pcie_err(pcie_set,
			"flag_dev_pa=%#llx is not 4Byte align", flag_dev_pa);
		return -1;
	}

	for (sw_index = 0; sw_index < pcie_set->sw_set.sw_num; sw_index++) {
		sw = &pcie_set->sw_set.sw[sw_index];
		if (__sync_bool_compare_and_swap(&sw->status,
					SYNC_WRITE_IDLE, SYNC_WRITE_ASSIGNED)) {
			sw->sw_flag_pa = flag_dev_pa;
			cn_pci_reg_write32(pcie_set, PF_FLAG_QUEUE_ADDR_L(sw_index),
					LOWER32(sw->sw_flag_pa));
			cn_pci_reg_write32(pcie_set, PF_FLAG_QUEUE_ADDR_H(sw_index),
					UPPER32(sw->sw_flag_pa));
			cn_pci_reg_read32(pcie_set, PF_FLAG_QUEUE_ADDR_H(sw_index));
			cn_dev_pcie_debug(pcie_set,
				"id=%d flag_pa=%#llx trigger_pa=%#llx trigger_kva=%#lx",
				sw_index, sw->sw_flag_pa, sw->sw_trigger_pa, sw->sw_trigger_kva);
			return 0;
		}
	}

	return -1;
}

static void c50_pcie_sync_write_free(struct cn_pcie_set *pcie_set, u64 flag_dev_pa)
{
	struct sync_write *sw;
	int sw_index;

	for (sw_index = 0; sw_index < pcie_set->sw_set.sw_num; sw_index++) {
		sw = &pcie_set->sw_set.sw[sw_index];
		if (sw->sw_flag_pa == flag_dev_pa) {
			sw->sw_flag_pa = 0;
			sw->sw_trigger_count = 0;
			__sync_lock_test_and_set(&sw->status, SYNC_WRITE_IDLE);
		}
	}
}

static void c50_pcie_sync_write_trigger(struct cn_pcie_set *pcie_set, u64 dev_pa, u32 val)
{
	struct sync_write *sw;
	int sw_index;
	u32 bit_wide;
	u32 flag_offset;
	u64 data_64;
	u32 data_32;

	/* each entry occupies 4Byte address range */
	if ((dev_pa % 4) != 0) {
		cn_dev_pcie_err(pcie_set,
			"dev_pa=%#llx is not 4Byte align", dev_pa);
		return;
	}

	bit_wide = pcie_set->sw_set.mode ? 32 : 16;
	for (sw_index = 0; sw_index < pcie_set->sw_set.sw_num; sw_index++) {
		sw = &pcie_set->sw_set.sw[sw_index];
		if ((dev_pa >= sw->sw_flag_pa) &&
			(dev_pa < sw->sw_flag_pa +  (1ULL << bit_wide) * 4)) {
			if (pcie_set->sw_set.mode) {
				flag_offset = (dev_pa - sw->sw_flag_pa) / 4;
				data_64 = flag_offset;
				data_64 <<= 32;
				data_64 |= val;
				/* barrier*/
				smp_mb();
				writeq(data_64, (void __iomem *)sw->sw_trigger_kva);
			} else {
				flag_offset = (dev_pa - sw->sw_flag_pa) / 4;
				data_32 = flag_offset;
				data_32 <<= 16;
				data_32 |= GET_BITS_VAL(val, 15, 0);
				/* barrier*/
				smp_mb();
				writel(data_32, (void __iomem *)sw->sw_trigger_kva);
			}
			sw->sw_trigger_count++;
			return;
		}
	}

	cn_dev_pcie_err(pcie_set,
		"dev_pa=%#llx is out of bounds please alloc sync_write", dev_pa);
}

static void c50_pcie_sync_write_info(struct cn_pcie_set *pcie_set,
				struct sync_write_info *sw_info)
{
	struct sync_write *sw;
	int sw_index;

	for (sw_index = 0; sw_index < pcie_set->sw_set.sw_num; sw_index++) {
		sw = &pcie_set->sw_set.sw[sw_index];
		sw_info[sw_index].sw_id = sw_index;
		sw_info[sw_index].status = sw->status;
		sw_info[sw_index].sw_trigger_pa = sw->sw_trigger_pa;
		sw_info[sw_index].sw_trigger_kva = sw->sw_trigger_kva;
		sw_info[sw_index].sw_flag_pa = sw->sw_flag_pa;
		sw_info[sw_index].sw_trigger_count = sw->sw_trigger_count;
	}
}

static int c50_pcie_sync_write_init(struct cn_pcie_set *pcie_set)
{
	struct sync_write *sw;
	int sw_index;
	u64 dev_va;
	unsigned long host_kva;
	size_t size = 0x1000;
	int ret;

	if (!pcie_set->cfg.sync_write_able)
		return 0;

	ret = cn_device_share_mem_alloc(0, &host_kva, &dev_va, size,
				pcie_set->bus_set->core);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "sync write trigger buf alloc fail");
		return -1;
	}

	pcie_set->sw_set.sw_dev_va = dev_va;
	pcie_set->sw_set.sw_host_kva = host_kva;
	pcie_set->sw_set.sw_total_size = size;
	pcie_set->sw_set.sw_num = PF_SW_NUM;
	pcie_set->sw_set.mode = SYNC_WRITE_MODE;
	cn_pci_reg_write32(pcie_set, PF_SYNC_WRITE_MODE, pcie_set->sw_set.mode);

	for (sw_index = 0; sw_index < pcie_set->sw_set.sw_num; sw_index++) {
		sw = &pcie_set->sw_set.sw[sw_index];
		sw->sw_flag_size = (pcie_set->sw_set.sw_total_size / pcie_set->sw_set.sw_num);
		sw->sw_trigger_pa = (pcie_set->sw_set.sw_dev_va +
					sw_index * sw->sw_flag_size) -
					C50_AXI_SHM_BASE + C50_AXI_SHM_PA_BASE;
		sw->sw_trigger_kva = pcie_set->sw_set.sw_host_kva +
					sw_index * sw->sw_flag_size;
		cn_pci_reg_write32(pcie_set, PF_SYNC_WRITE_ADDR_L(sw_index),
						LOWER32(sw->sw_trigger_pa));
		cn_pci_reg_write32(pcie_set, PF_SYNC_WRITE_ADDR_H(sw_index),
						UPPER32(sw->sw_trigger_pa));
		cn_dev_pcie_debug(pcie_set, "[%d]sw_trigger_pa=%#llx, sw_trigger_kva=%#lx",
					sw_index, sw->sw_trigger_pa, sw->sw_trigger_kva);
	}

	return 0;
}

static int c50_pcie_data_outbound_reserve_able(struct cn_pcie_set *pcie_set, u64 device_addr)
{
	if ((device_addr >= pcie_set->dob_set.ob_axi_addr) &&
			(device_addr <=
			(pcie_set->dob_set.ob_axi_addr + pcie_set->dob_set.dob_reserve_size))) {
		return 1;
	}

	return 0;
}

static void c50_data_outbound_node_exit(struct cn_pcie_set *pcie_set,
					struct data_outbound_node_t *dob_node)
{
	int i;
	struct outbound_mem *outbound_mem;
	struct dob_rpc_free_t dob_free;

	if (!dob_node)
		return;
	outbound_mem = dob_node->share_priv;
	if ((!outbound_mem) || (!dob_node->share_mem_pages))
		return;

	/* invaild outbound win*/
	for (i = 0; i < dob_node->win_cnt; i++) {
		if (c50_pcie_data_outbound_reserve_able(pcie_set, dob_node->device_addr)) {
			/* set data outbound page by resource_arm driver */
			pcie_set->dob_set.share_mem_pages = NULL;
		} else {
			dob_free.desc_offset = dob_node->win_base + i * DOB_PRE_PAGE_SIZE;
			data_outbound_rpc_free(pcie_set->bus_set->core, &dob_free);
		}
	}

	if (dob_node->virt_addr) {
		vm_unmap_ram(dob_node->virt_addr, dob_node->total_size / PAGE_SIZE);
		dob_node->virt_addr = NULL;
	}

	for (i = 0; i < (dob_node->total_size / PAGE_SIZE); i++) {
		if (dob_node->share_mem_pages[i]) {
			dob_node->share_mem_pages[i] = NULL;
		}
	}

	for (i = 0; i < dob_node->win_cnt; i++) {
		if (outbound_mem[i].virt_addr) {
			dma_unmap_page(&pcie_set->pdev->dev, outbound_mem[i].pci_addr,
					PAGE_SIZE << outbound_mem[i].order, DMA_BIDIRECTIONAL);
			__free_pages(outbound_mem[i].pages, outbound_mem[i].order);
		}
	}
	cn_kfree(dob_node->share_mem_pages);
	dob_node->share_mem_pages = NULL;
	cn_kfree(dob_node->share_priv);
	dob_node->share_priv = NULL;
}

static int c50_data_outbound_node_init(struct cn_pcie_set *pcie_set,
					struct data_outbound_node_t *dob_node)
{
	int i, j;
	int page_index = 0;
	unsigned int pre_win_order = 0;
	struct outbound_mem *outbound_mem;
	struct dob_rpc_alloc_t dob_alloc;
	u64 desc_buff = 0ULL;

	dob_node->share_mem_pages = cn_kzalloc(
		sizeof(struct page *) * (dob_node->total_size / PAGE_SIZE),
		GFP_KERNEL);
	if (!dob_node->share_mem_pages) {
		cn_dev_pcie_err(pcie_set, "malloc share_mem_pages error");
		return -1;
	}

	outbound_mem = cn_kzalloc(dob_node->win_cnt * sizeof(struct outbound_mem),
							GFP_KERNEL);
	if (!outbound_mem) {
		cn_dev_pcie_err(pcie_set, "malloc outbound_mem error");
		return -1;
	}
	dob_node->share_priv = (void *)outbound_mem;
	pre_win_order = get_order(dob_node->per_win_size);
	dob_node->pre_win_npages = 1 << pre_win_order;

	for (i = 0; i < dob_node->win_cnt; i++) {
		outbound_mem[i].order = pre_win_order;
		outbound_mem[i].pages = alloc_pages(GFP_KERNEL, pre_win_order);
		if (!outbound_mem[i].pages) {
			cn_dev_pcie_err(pcie_set, "alloc_page error:%d", i);
			goto ERROR_RET;
		}
		outbound_mem[i].virt_addr = page_address(outbound_mem[i].pages);
		outbound_mem[i].pci_addr = dma_map_page(&pcie_set->pdev->dev, outbound_mem[i].pages,
				0, PAGE_SIZE << pre_win_order, DMA_BIDIRECTIONAL);
		if (unlikely(dma_mapping_error(&pcie_set->pdev->dev, outbound_mem[i].pci_addr))) {
			cn_dev_pcie_err(pcie_set, "dma_map_page error:%d", i);
			goto ERROR_RET;
		}
	}

	page_index = 0;
	for (i = 0; i < dob_node->win_cnt; i++) {
		for (j = 0; j < dob_node->pre_win_npages; j++) {
			dob_node->share_mem_pages[page_index] = outbound_mem[i].pages + j;
			page_index++;
		}
	}

#if defined(__x86_64__)
	dob_node->virt_addr = cn_vm_map_ram(dob_node->share_mem_pages,
					page_index, -1, PAGE_KERNEL_NOCACHE);
#else
	dob_node->virt_addr = cn_vm_map_ram(dob_node->share_mem_pages,
					page_index, -1, PAGE_KERNEL);
#endif
	if (!dob_node->virt_addr) {
		cn_dev_pcie_err(pcie_set, "vm_map_ram error");
		goto ERROR_RET;
	}
	cn_dev_pcie_debug(pcie_set, "device addr:%#llx virtual addr:0x%lx",
				dob_node->device_addr, (unsigned long)dob_node->virt_addr);
	/* set outbound win*/
	for (i = 0; i < dob_node->win_cnt; i++) {
		desc_buff = (outbound_mem[i].pci_addr & (~(MASK_BITS(11, 0)))) | 0x1UL;
		dob_alloc.desc_buff = desc_buff;
		dob_alloc.desc_offset = dob_node->win_base + i * DOB_PRE_PAGE_SIZE;

		if (c50_pcie_data_outbound_reserve_able(pcie_set, dob_node->device_addr)) {
			dob_node->type = CN_SHARE_MEM_HOST;
			pcie_set->dob_set.share_mem_pages = dob_node->share_mem_pages;
			cn_dev_pcie_debug(pcie_set, "[%d] %#lx %#llx %#llx",
				i, (unsigned long)outbound_mem[i].virt_addr,
				dob_alloc.desc_offset, desc_buff);
		} else {
			if (data_outbound_rpc_alloc(pcie_set->bus_set->core, &dob_alloc)) {
				cn_dev_pcie_err(pcie_set, "desc_base:%#llx, desc_buff=%#llx",
					dob_alloc.desc_offset, dob_alloc.desc_buff);
				goto ERROR_RET;
			}
		}
	}

	return 0;
ERROR_RET:
	c50_data_outbound_node_exit(pcie_set, dob_node);

	return -1;
}

static void c50_pcie_release_data_outbound_iova(struct cn_pcie_set *pcie_set)
{
	struct data_outbound_set *dob_set;
	struct data_outbound_map_t *map_node, *tmp;

	dob_set = &pcie_set->dob_set;
	if (list_empty(&dob_set->dob_iova_head))
		return;

	mutex_lock(&dob_set->dob_lock);
	list_for_each_entry_safe(map_node, tmp, &dob_set->dob_iova_head, list) {
		if (map_node->sgt)
			dma_unmap_sg(&pcie_set->pdev->dev, map_node->sgt->sgl,
					map_node->sgt->nents, DMA_BIDIRECTIONAL);
		cn_dev_pcie_debug(pcie_set, "device_addr=%#llx, size=%#lx, iova_sgt=%p",
				map_node->device_addr, map_node->size, map_node->sgt);
		sg_free_table(map_node->sgt);
		list_del(&map_node->list);
		cn_kfree(map_node->sgt);
		cn_kfree(map_node);
	}

	mutex_unlock(&dob_set->dob_lock);
}

static void c50_pcie_put_data_outbound_iova(struct cn_pcie_set *pcie_set, struct sg_table **iova_sgt)
{
	struct data_outbound_set *dob_set;
	struct data_outbound_map_t *map_node, *tmp;
	struct sg_table *sgt = NULL;

	sgt = *iova_sgt;
	dob_set = &pcie_set->dob_set;

	mutex_lock(&dob_set->dob_lock);
	list_for_each_entry_safe(map_node, tmp, &dob_set->dob_iova_head, list) {
		if (map_node->sgt == sgt) {
			cn_dev_pcie_debug(pcie_set, "device_addr=%#llx, size=%#lx, iova_sgt=%p",
					map_node->device_addr, map_node->size, map_node->sgt);
			list_del(&map_node->list);
			cn_kfree(map_node);
		}
	}
	mutex_unlock(&dob_set->dob_lock);

	dma_unmap_sg(&pcie_set->pdev->dev, sgt->sgl,
			sgt->nents, DMA_BIDIRECTIONAL);
	sg_free_table(sgt);
	cn_kfree(sgt);

	*iova_sgt = NULL;
}

static int c50_pcie_get_data_outbound_iova(struct cn_pcie_set *src,
					struct cn_pcie_set *dst, u64 device_addr,
					size_t size, struct sg_table **iova_sgt)
{
	struct data_outbound_set *dob_src_set;
	struct data_outbound_set *dob_dst_set;
	struct data_outbound_node_t *dob_node, *dob_tmp;
	struct data_outbound_map_t *map_node;
	int dob_flag = 0, page_offset, page_cnt_start, page_cnt_end;
	struct scatterlist *sgl, *iter;
	struct sg_table *sgt = NULL;
	int i, pre_win_npages, win_size, sg_size;


	if (!c50_pcie_data_outbound_reserve_able(src, device_addr)) {
		cn_dev_pcie_err(src,
				"device_addr=%#llx not is data outbound pa ERROR",
				device_addr);
		return -1;
	}

	if (!dst)
		return -1;

	dob_src_set = &src->dob_set;

	dob_dst_set = &dst->dob_set;

	mutex_lock(&dob_src_set->dob_lock);
	list_for_each_entry_safe(dob_node, dob_tmp, &dob_src_set->dob_head, list) {
		if (device_addr >= dob_node->device_addr &&
				device_addr < dob_node->device_addr +
				dob_node->total_size) {
			dob_flag = 1;
			break;
		}
	}
	mutex_unlock(&dob_src_set->dob_lock);
	if (!dob_flag) {
		cn_dev_pcie_err(src, "device_addr=%#llx is ERROR dob_pa",
				device_addr);
		return -1;
	}
	map_node = NULL;
	map_node = cn_kzalloc(sizeof(*map_node), GFP_KERNEL);
	if (!map_node) {
		return -1;
	}

	sgt = cn_kzalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!sgt) {
		cn_dev_pcie_err(src, "sg_table allocation failed");
		cn_kfree(map_node);
		return -ENOMEM;
	}

	*iova_sgt = sgt;
	pre_win_npages = dob_node->pre_win_npages;
	win_size = pre_win_npages * PAGE_SIZE;

	page_offset = device_addr & (~PAGE_MASK);
	page_cnt_start = (device_addr - dob_node->device_addr) / PAGE_SIZE;
	page_cnt_end = (device_addr + size - 1 - dob_node->device_addr) / PAGE_SIZE;

	sgt->orig_nents = (page_cnt_end / pre_win_npages - page_cnt_start / pre_win_npages) + 1;
	if (sg_alloc_table(sgt, sgt->orig_nents, GFP_KERNEL)) {
		cn_dev_pcie_err(src, "SGL allocation failed");
		cn_kfree(map_node);
		cn_kfree(sgt);
		return -ENOMEM;
	}

	sgl = sgt->sgl;

	for_each_sg(sgl, iter, sgt->orig_nents, i) {
		if (sgt->orig_nents == 1)
			sg_size = size;
		else if (i == 0)
			sg_size = win_size - (device_addr % win_size);
		else if (i == (sgt->orig_nents - 1))
			sg_size = (device_addr + size) % win_size;
		else
			sg_size = win_size;

		sg_set_page(iter, dob_node->share_mem_pages[page_cnt_start], sg_size, page_offset);

		page_cnt_start = ((page_cnt_start / pre_win_npages) + 1) * pre_win_npages;
		page_offset = 0;
	}
	cn_dev_pcie_debug(src, "device_addr=%#llx, size=%#lx",
			device_addr, size);
	cn_dev_pcie_debug(src, "device_start=%#llx, size=%#x",
			dob_node->device_addr,
			dob_node->total_size);
	cn_dev_pcie_debug(src, "page_offset=%#x, page_cnt_start=%#x",
			page_offset, page_cnt_start);
	sgt->nents = dma_map_sg(&dst->pdev->dev, sgl, sgt->orig_nents, DMA_BIDIRECTIONAL);
	if (!sgt->nents) {
		cn_dev_pcie_err(dst, "addr=%#llx map error", device_addr);
		sg_free_table(sgt);
		cn_kfree(map_node);
		cn_kfree(sgt);
		return -ENOMEM;
	}

	map_node->src = src;
	map_node->device_addr = device_addr;
	map_node->size = size;
	map_node->sgt = sgt;
	mutex_lock(&dob_dst_set->dob_lock);
	list_add_tail(&map_node->list, &dob_dst_set->dob_iova_head);
	mutex_unlock(&dob_dst_set->dob_lock);

	cn_dev_pcie_debug(src, "device_addr=%#llx, size=%#lx, iova_sgt=%p",
							device_addr, size, sgt);
	return 0;
}

static void c50_pcie_get_data_outbound_page_info(struct cn_pcie_set *pcie_set,
				int *lvl1_page, int *lvl1_pg_cnt, u64 *lvl1_base,
				int *lvl2_page, int *lvl2_pg_cnt, u64 *lvl2_base)
{
	struct data_outbound_set *dob_set;

	dob_set = &pcie_set->dob_set;

	*lvl1_page = ilog2(dob_set->dob_lvl1_pg);
	*lvl1_pg_cnt = dob_set->dob_axi_pg_cnt / 2;
	*lvl1_base = dob_set->dob_lvl1_axi_base;
	*lvl2_page = ilog2(dob_set->dob_lvl2_pg);
	*lvl2_pg_cnt = (dob_set->dob_axi_pg_cnt / 2 -
			dob_set->dob_lvl2_pg_reserve_cnt * DOB_PAGE_RESERVE_FUNC_CNT);
	*lvl2_base = dob_set->dob_lvl2_axi_base;
	cn_dev_pcie_debug(pcie_set, "dob_info:level1 pg=%#x pg_cnt=%#x base=%#llx",
					*lvl1_page, *lvl1_pg_cnt, *lvl1_base);
	cn_dev_pcie_debug(pcie_set, "dob_info:level2 pg=%#x pg_cnt=%#x base=%#llx",
					*lvl2_page, *lvl2_pg_cnt, *lvl2_base);
}

static void *c50_pcie_data_outbound_page_alloc(struct cn_pcie_set *pcie_set,
						u64 device_addr, size_t size)
{
	struct data_outbound_set *dob_set;
	struct data_outbound_node_t *new;

	if (!device_addr)
		return NULL;

	dob_set = &pcie_set->dob_set;
	/* overflow test*/
	if (device_addr < dob_set->dob_lvl1_axi_base ||
		(device_addr + size) > (dob_set->dob_lvl1_axi_base + dob_set->dob_total_size) ||
		device_addr >= (dob_set->dob_lvl1_axi_base + dob_set->dob_total_size)) {
		cn_dev_pcie_err(pcie_set, "device_addr=%#llx error", device_addr);
		return NULL;
	}

	new = cn_kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return NULL;

	if (device_addr >= dob_set->dob_lvl2_axi_base) {
		new->win_base = dob_set->dob_axi_pg_base +
					dob_set->dob_axi_per_pg_size *
					(dob_set->dob_axi_pg_cnt / 2 +
					(device_addr - dob_set->dob_lvl2_axi_base) /
					dob_set->dob_lvl2_pg);
		new->win_cnt = size / dob_set->dob_lvl2_pg +
					((size % dob_set->dob_lvl2_pg) ? 1 : 0);
		new->per_win_size = dob_set->dob_lvl2_pg;
	} else {
		new->win_base = dob_set->dob_axi_pg_base +
					dob_set->dob_axi_per_pg_size *
					((device_addr - dob_set->dob_lvl1_axi_base) /
					dob_set->dob_lvl1_pg);
		new->win_cnt = size / dob_set->dob_lvl1_pg +
					((size % dob_set->dob_lvl1_pg) ? 1 : 0);
		new->per_win_size = dob_set->dob_lvl1_pg;
	}
	new->total_size = new->win_cnt * new->per_win_size;
	new->type = CN_SHARE_MEM_HOST_DATA;
	new->device_addr = device_addr;
	if (c50_data_outbound_node_init(pcie_set, new)) {
		cn_kfree(new);
		return NULL;
	}
	mutex_lock(&dob_set->dob_lock);
	list_add_tail(&new->list, &dob_set->dob_head);
	mutex_unlock(&dob_set->dob_lock);

	return new->virt_addr;
}

static void c50_pcie_data_outbound_page_free(struct cn_pcie_set *pcie_set,
							u64 device_addr)
{
	struct data_outbound_set *dob_set;
	struct data_outbound_node_t *dob_node, *tmp;

	dob_set = &pcie_set->dob_set;

	mutex_lock(&dob_set->dob_lock);
	list_for_each_entry_safe(dob_node, tmp, &dob_set->dob_head, list) {
		if (device_addr == dob_node->device_addr) {
			c50_data_outbound_node_exit(pcie_set, dob_node);
			list_del(&dob_node->list);
			cn_kfree(dob_node);
			break;
		}
	}
	mutex_unlock(&dob_set->dob_lock);
}

static int c50_pcie_data_outbound_reg(struct cn_pcie_set *pcie_set)
{
	struct data_outbound_set *dob_set = NULL;
	u32 dob_param = 0;

	dob_set = &pcie_set->dob_set;
	SET_BITS_VAL(dob_param, 0, 0, 1);
	SET_BITS_VAL(dob_param, 5, 1, ilog2(dob_set->dob_lvl1_pg) - 1);
	SET_BITS_VAL(dob_param, 10, 6, ilog2(dob_set->dob_lvl2_pg) - 1);
	cn_pci_reg_write32(pcie_set, SLV_WIN_ATR_PARAM, dob_param);
	cn_dev_pcie_debug(pcie_set, "dob_param=%#x", dob_param);

	dob_set->dob_ar_cnt = cn_pci_reg_read32(pcie_set, SLV_WIN_AR_CNT);
	cn_dev_pcie_info(pcie_set, "dob ar count:%#x", dob_set->dob_ar_cnt);

	return 0;
}

static void c50_pcie_data_outbound_desc_pg_init(struct cn_pcie_set *pcie_set)
{
	struct outbound_mem *outbound_mem;
	struct data_outbound_set *dob_set;
	struct data_outbound_node_t *dob_node, *tmp;
	int flag = 0, i;
	u64 desc_buff;
	u64 desc_offset;
	host_addr_t dob_pg_shm_hva;
	phy_addr_t dob_pg_shm_dva;
	u64 dob_pg_shm_dpa = 0ULL;

	dob_set = &pcie_set->dob_set;
	if (list_empty(&dob_set->dob_head))
		return;

	mutex_lock(&dob_set->dob_lock);
	list_for_each_entry_safe(dob_node, tmp, &dob_set->dob_head, list) {
		if (dob_set->ob_axi_addr == dob_node->device_addr) {
			outbound_mem = (struct outbound_mem *)dob_node->share_priv;
			flag = 1;
			break;
		}
	}
	mutex_unlock(&dob_set->dob_lock);

	dob_pg_shm_hva = cn_shm_get_host_addr_by_name(pcie_set->bus_set->core,
							"dob_page_reserved");
	dob_pg_shm_dva = cn_shm_get_dev_addr_by_name(pcie_set->bus_set->core,
							"dob_page_reserved");
	dob_pg_shm_dpa = dob_pg_shm_dva - C50_AXI_SHM_BASE + C50_AXI_SHM_PA_BASE;

	cn_pci_reg_write64(pcie_set, PCIE_INFO_DOB_PAGE_BASE, dob_pg_shm_dpa);
	cn_dev_pcie_debug(pcie_set, "dob_pg_shm:hva=%#lx, dva=%#llx, dpa=%#llx",
				dob_pg_shm_hva, dob_pg_shm_dva, dob_pg_shm_dpa);

	for (i = 0; flag && i < dob_node->win_cnt; i++) {
		desc_buff = (outbound_mem[i].pci_addr & (~(MASK_BITS(11, 0)))) | 0x1UL;
		desc_offset = dob_node->win_base + i * DOB_PRE_PAGE_SIZE
						+ C50_AXI_SHM_DOB_VA_PAGE_BASE;

		memcpy_toio((void __iomem *)(dob_pg_shm_hva + i * (sizeof(desc_offset)
			+ sizeof(desc_buff))), &desc_offset, sizeof(desc_offset));
		memcpy_toio((void __iomem *)(dob_pg_shm_hva + i * (sizeof(desc_offset)
			+ sizeof(desc_buff))) + sizeof(desc_offset),
			&desc_buff, sizeof(desc_buff));
		/* set data outbound page by resource_arm driver */
		cn_dev_pcie_debug(pcie_set, "%d %llx %llx", i, desc_offset, desc_buff);
	}
}

/* reserve 16MB data_outbound for commu/ipcm/js */
static int c50_pcie_data_outbound_reserve_init(struct cn_pcie_set *pcie_set)
{
	struct data_outbound_set *dob_set;
	void __iomem *virt_addr = NULL;
	int index = pcie_set->share_mem_cnt;

	dob_set = &pcie_set->dob_set;

	dob_set->dob_reserve_size = dob_set->dob_lvl2_pg_reserve_cnt * dob_set->dob_lvl2_pg;
	dob_set->ob_axi_addr = dob_set->dob_lvl2_axi_base +
					(dob_set->dob_lvl2_pg *
					(dob_set->dob_cnt /  2 - dob_set->dob_lvl2_pg_reserve_cnt
					* DOB_PAGE_RESERVE_FUNC_CNT));
	virt_addr = c50_pcie_data_outbound_page_alloc(pcie_set,
				dob_set->ob_axi_addr, dob_set->dob_reserve_size);
	if (!virt_addr)
		return -1;

	pcie_set->share_mem[index].virt_addr = virt_addr;
	pcie_set->share_mem[index].win_length = dob_set->dob_reserve_size;
	pcie_set->share_mem[index].type = CN_SHARE_MEM_HOST;
	pcie_set->share_mem[index].device_addr = dob_set->ob_axi_addr;
	cn_dev_pcie_debug(pcie_set, "[%d] reserve dob size=%#lx kva=%#lx dpa=%#llx",
				index, pcie_set->share_mem[index].win_length,
				(unsigned long)pcie_set->share_mem[index].virt_addr,
					pcie_set->share_mem[index].device_addr);
	pcie_set->share_mem_cnt++;

	return 0;
}

static int c50_pcie_data_outbound_init(struct cn_pcie_set *pcie_set)
{
	struct data_outbound_set *dob_set = NULL;
	int index;

	dob_set = &pcie_set->dob_set;
	dob_set->dob_cnt = DOB_PAGE_CNT;
	dob_set->dob_lvl2_pg_reserve_cnt = DOB_PAGE_LEVEL2_RESERVE_CNT;
	dob_set->dob_lvl1_pg = DOB_PAGE_LEVEL1;
	dob_set->dob_lvl2_pg = DOB_PAGE_LEVEL2;
	dob_set->dob_total_size = (dob_set->dob_lvl1_pg * (dob_set->dob_cnt / 2)) +
				(dob_set->dob_lvl2_pg * (dob_set->dob_cnt /  2));
	dob_set->dob_lvl1_axi_base = DOB_AXI_BASE;
	dob_set->dob_lvl2_axi_base = DOB_AXI_BASE +
					dob_set->dob_lvl1_pg * (dob_set->dob_cnt / 2);
	dob_set->dob_axi_pg_cnt = DOB_PAGE_CNT;
	dob_set->dob_axi_per_pg_size = DOB_PRE_PAGE_SIZE;
	dob_set->dob_axi_pg_base = 0ULL; // set 0 for arm set
	INIT_LIST_HEAD(&dob_set->dob_head);
	INIT_LIST_HEAD(&dob_set->dob_iova_head);
	mutex_init(&dob_set->dob_lock);

	if (pcie_set->cfg.outbound_able) {
		/* reserve 16MB for config_outbound*/
		if (c50_pcie_data_outbound_reserve_init(pcie_set)) {
			pcie_set->cfg.outbound_able = 0;
			goto ob_disable;
		}
	} else {
ob_disable:
		if (cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn))
			return 0;

		index = pcie_set->share_mem_cnt;
		pcie_set->share_mem[index].virt_addr =
				(void __iomem *)dob_set->dob_lvl1_axi_base;
		pcie_set->share_mem[index].win_length = dob_set->dob_total_size -
								dob_set->dob_reserve_size
								* DOB_PAGE_RESERVE_FUNC_CNT;
		pcie_set->share_mem[index].type = CN_SHARE_MEM_HOST_DATA;
		pcie_set->share_mem[index].device_addr = dob_set->dob_lvl1_axi_base;
		cn_dev_pcie_info(pcie_set, "[%d] dob size=%#lx kva=%#lx dpa=%#llx",
					index, pcie_set->share_mem[index].win_length,
					(unsigned long)pcie_set->share_mem[index].virt_addr,
					pcie_set->share_mem[index].device_addr);
		pcie_set->share_mem_cnt++;
	}

	c50_pcie_data_outbound_reg(pcie_set);

	return 0;
}

static void c50_pcie_data_outbound_exit(struct cn_pcie_set *pcie_set)
{
	struct data_outbound_set *dob_set;
	struct data_outbound_node_t *dob_node, *tmp;

	dob_set = &pcie_set->dob_set;

	c50_pcie_release_data_outbound_iova(pcie_set);

	if (list_empty(&dob_set->dob_head))
		return;

	mutex_lock(&dob_set->dob_lock);
	list_for_each_entry_safe(dob_node, tmp, &dob_set->dob_head, list) {
		c50_data_outbound_node_exit(pcie_set, dob_node);
		list_del(&dob_node->list);
		cn_kfree(dob_node);
	}

	mutex_unlock(&dob_set->dob_lock);
}

static void c50_check_outbound_ar_cnt(struct cn_pcie_set *pcie_set)
{
	struct data_outbound_set *dob_set;
	u32 ar_cnt;

	if (pcie_set->id == MLUID_580)
		return;

	dob_set = &pcie_set->dob_set;

	ar_cnt = cn_pci_reg_read32(pcie_set, SLV_WIN_AR_CNT);
	ar_cnt -= dob_set->dob_ar_cnt;
	if (ar_cnt) {
		cn_dev_pcie_err(pcie_set, "someone used data outbound read, read cnt = %#x", ar_cnt);
		/* driver_test check call trace */
		dump_stack();
	}

	return;
}

static int cn_pci_link_set(struct cn_pcie_set *pcie_set, bool enable)
{
	u16 lnk_ctrl;
	struct pci_dev *pdev = pcie_set->pdev->bus->self;

	pcie_capability_read_word(pdev, PCI_EXP_LNKCTL, &lnk_ctrl);
	if (enable)
		lnk_ctrl &= ~PCI_EXP_LNKCTL_LD;
	else
		lnk_ctrl |= PCI_EXP_LNKCTL_LD;
	pcie_capability_write_word(pdev, PCI_EXP_LNKCTL, lnk_ctrl);

	cn_dev_pcie_info(pcie_set, "lnk_ctrl = %#x", lnk_ctrl);
	return 0;
}

static int OVER_WRITE(pcie_linkdown_reset)(struct cn_pcie_set *pcie_set)
{
	/* enable top linkdown*/
	//cn_pci_reg_write32(pcie_set, 0x915000, 0x1000);
	cn_pci_link_set(pcie_set, false);
	msleep(100);
	cn_pci_link_set(pcie_set, true);

	return 0;
}


#if 0
static int OVER_WRITE(pcie_soft_reset)(struct cn_pcie_set *pcie_set)
{
	int i = 0;
	u32 info;

	/* enable top softreset*/
	//cn_pci_reg_write32(pcie_set, 0x915004, 0x1000);
	cn_pci_reg_write32(pcie_set, SOFT_RESET_PREG, 1);
	msleep(100);

	while (cn_pci_reg_read32(pcie_set, SOFT_RESET_PREG)) {
		info = cn_pci_reg_read32(pcie_set, SOFT_RESET_DEBUG);
		switch (info) {
		case 0x0:
			cn_dev_pcie_info(pcie_set, "soft_reset:running");
			break;
		case 0x1:
			cn_dev_pcie_info(pcie_set, "soft_reset:pending");
			break;
		case 0x2:
			cn_dev_pcie_info(pcie_set, "soft_reset:ack");
			break;
		case 0x3:
			cn_dev_pcie_info(pcie_set, "soft_reset:protect");
			break;
		default:
			break;
		}
		msleep(100);
		i++;
		if (i > 10) {
			cn_dev_pcie_info(pcie_set, "soft_reset timeout > 1s");
			break;
		}
	}

	return 0;
}
#endif

static int c50_check_ddr_status(struct cn_pcie_set *pcie_set)
{
	int ret = 0, cnt = 0;
	u32 reg32 = 0, boot_status = 0, gddr_status = 0;

	if (pcie_set->id == MLUID_590)
		return 0;

	cnt = 200;
	do {
		reg32 = cn_pci_reg_read32(pcie_set, MLU580_IPC_2);
		gddr_status = GET_BITS_VAL(reg32, 17, 16);
		boot_status = GET_BITS_VAL(reg32, 12, 10);

		if ((gddr_status != 0x1) && (boot_status == 0x2)) {
			cn_dev_pcie_info(pcie_set, "GDDR Init successfully");
			ret = 0;
			break;
		} else if ((gddr_status == 0x1) && (boot_status == 0x0)) {
			cn_dev_pcie_info(pcie_set, "GDDR Init failed, IPC_2:0x%x", reg32);
			ret = -EINVAL;
			break;
		}

		msleep(500);
	} while (--cnt);

	if (!cnt) {
		cn_dev_pcie_err(pcie_set, "Wait GDDR Init Finish Timeout!!");
		return -EINVAL;
	}

	return ret;
}


static int c50_ddr_init_retry(struct cn_pcie_set *pcie_set)
{
	u32 reg1_val = 0x0, reg4_val = 0x0, retry_count = 3;
	int timeout = 0, ret = 0;

	if (pcie_set->id == MLUID_590)
		return -1;

	reg1_val = cn_pci_reg_read32(pcie_set, PF_GIC_INFO_REG_1);
	reg4_val = cn_pci_reg_read32(pcie_set, PF_GIC_INFO_REG_4);
	if ((reg1_val & 0x1) != 0x1 || (reg4_val & 0x1) != 0x1)
		return -1;

	do {
		//send a reset request
		//pr_info("The devcie will be reset\n");
		cn_pci_reg_write32(pcie_set, PF_GIC_INFO_REG_0, 0x1);

		timeout = 100;
		while (cn_pci_reg_read32(pcie_set, PF_GIC_INFO_REG_0) && timeout) {
			cn_dev_pcie_debug(pcie_set, "Wait for full chip reset done\n");
			timeout--;
			msleep(100);
		}
		if (timeout <= 0) {
			cn_dev_pcie_err(pcie_set, "Wait full chip reset timeout\n");
			return -1;
		}

		ret = c50_check_ddr_status(pcie_set);
		if (ret == 0)
			break;
	} while(--retry_count);

	if (retry_count == 0) {
		cn_dev_pcie_err(pcie_set, "gddr init fail\n");
		return -1;
	}

	return 0;
}

static const char *mlu590_hbm_init_status[4] = {
	"HBM init successfully",
	"HBM init failed",
	"HBM address repair failed",
	"HBM init timeout"
};

static int c50_pcie_ddr_set_done(struct cn_pcie_set *pcie_set)
{
	int ret = 0, cnt = 0;
	u32 reg32 = 0;

	/* hbm ready */
	cnt = 1200;
	do {
		reg32 = cn_pci_reg_read32(pcie_set, MLU590_IPC_2);
		if (((reg32 >> MLU590_MCU_DDRTRAINED_FLAG_SHIFT) & MLU590_MCU_DDRTRAINED_FLAG_MASK)
			< MLU590_MCU_DDRTRAINED_BOOT_DONE) {
			ret = -EINVAL;
		} else {
			cn_dev_pcie_info(pcie_set, "DDR Training Params set by MCU Finish");
			ret = 0;
			break;
		}

		if (cnt % 10 == 0)
			cn_dev_pcie_info(pcie_set, "Wait DDR Training status:%x!!", reg32);

		msleep(500);
	} while (--cnt);

	if (!cnt) {
		cn_dev_pcie_err(pcie_set, "Wait DDR Training Finish Timeout!!");
		reg32 = (cn_pci_reg_read32(pcie_set, MLU590_IPC_2) >> 16) & 0x3;
		cn_dev_pcie_info(pcie_set, "HBM Init Status 0x%x", reg32);
		goto err;
	}

	/* hbm repair & init */
	reg32 = (cn_pci_reg_read32(pcie_set, MLU590_IPC_2) >> 16) & 0x3;
	if (reg32) {
		cn_dev_pcie_err(pcie_set, "HBM Init Status 0x%x, %s",
			reg32, mlu590_hbm_init_status[reg32 & 0x3]);
		ret = -EINVAL;
		goto err;
	}

	return ret;

err:
	cn_recommend(pcie_set->bus_set->core, USER_RECOMMED);
	return ret;
}

static const struct pci_device_id cn_pci_mlu500_tbl[] = {
	{ PCI_DEVICE(cambricon_dm_VID, CN_C50_DID) },
	{ PCI_DEVICE(cambricon_dm_VID, CN_C50_S_DID) },
	{ PCI_DEVICE(cambricon_dm_VID, CN_C50_M_DID) },
	{ PCI_DEVICE(cambricon_dm_VID, CN_C50_L_DID) },
	{ PCI_DEVICE(cambricon_dm_VID, CN_C50_T_DID) },
	{ 0 }
};

static const struct pci_device_id cn_pci_mlu580_tbl[] = {
	{ PCI_DEVICE(cambricon_dm_VID, CN_C50_M_DID) },
	{ PCI_DEVICE(cambricon_dm_VID, CN_C50_L_DID) },
	{ 0 }
};

static const struct pci_device_id cn_pci_mlu590_tbl[] = {
	{ PCI_DEVICE(cambricon_dm_VID, CN_C50_DID) },
	{ PCI_DEVICE(cambricon_dm_VID, CN_C50_S_DID) },
	{ 0 }
};

static int pci_device_reset(struct pci_dev *pci_dev)
{
	void __iomem *bar0_base;
	unsigned long bar0_phy_base;
	int timeout = 0;
	u32 reg;

	bar0_phy_base = pci_resource_start(pci_dev, 0);
	bar0_base = ioremap(bar0_phy_base, pci_resource_len(pci_dev, 0));
	if (!bar0_base) {
		cn_dev_info("Failed to ioremap PCI memory");
		return -EIO;
	}

	//get soft reset capability
	if ((ioread32(bar0_base + PF_GIC_INFO_REG_1) & 0x1) == 0x1 &&
			(ioread32(bar0_base + PF_GIC_INFO_REG_4) & 0x1) == 0x1) {
		if (pci_match_id(cn_pci_mlu580_tbl, pci_dev)) {
			if ((ioread32(bar0_base + TINYCORE_RESET) & 0x1) == 0x1) {
				/* tiny core protect*/
				/* rob dynamic reset */
				iowrite32(0x1, bar0_base + TNC_ROB_PORT_PROT0);

				/* remote xbar dynamic reset */
				iowrite32(0x1, bar0_base + TNC_REMOTE_XBAR_DYN_RST_REQ);

				/* polling rob dynamic reset */
				while (timeout < 1000) {
					if ((ioread32(bar0_base + TNC_ROB_PORT_PROT1) & 0x1) == 0x1)
						break;
					timeout++;
					udelay(100);
				}

				/* polling remote xbar reset */
				while (timeout < 1000) {
					if ((ioread32(bar0_base + TNC_REMOTE_XBAR_DYN_RST_ACK) & 0x1) == 0x1)
						break;
					timeout++;
					udelay(100);
				}
				if (timeout >= 1000) {
					cn_dev_err("tinycore poll timeout!");
				} else {
					udelay(100);
					cn_dev_info("rob and remote xbar reset success");
				}
			}

			/* JS protect */
			timeout = 0;
			//step1: js data master mhr req
			reg = ioread32(bar0_base + MLU580_JS_DATA_MHR_REG);
			iowrite32(reg | MLU580_JS_DATA_MHR_MASK, bar0_base + MLU580_JS_DATA_MHR_REG);

			reg = ioread32(bar0_base + MLU580_JS_CFG_MHR_REG);
			iowrite32(reg | MLU580_JS_CFG_MHR_MASK, bar0_base + MLU580_JS_CFG_MHR_REG);
			//step2: wait mhr bus idle
			/* polling js data dynamic reset */
			while (timeout < 1000) {
				if ((ioread32(bar0_base + MLU580_JS_DATA_IDLE_REG) & MLU580_JS_DATA_IDLE_MASK) == MLU580_JS_DATA_IDLE_MASK)
					break;
				timeout++;
				udelay(100);
			}
			/* polling js cfg dynamic reset */
			while (timeout < 1000) {
				if ((ioread32(bar0_base + MLU580_JS_CFG_IDLE_REG) & MLU580_JS_CFG_IDLE_MASK) == MLU580_JS_CFG_IDLE_MASK)
					break;
				timeout++;
				udelay(100);
			}

			if (timeout >= 1000) {
				cn_dev_err("JS poll timeout!");
			} else {
				cn_dev_info("JS reset success");
			}
			reg = ioread32(bar0_base + MLU580_JS_CFG_PRO_REG);
			reg &= ~MLU580_JS_CFG_PRO_MASK;
			iowrite32(reg, bar0_base + MLU580_JS_CFG_PRO_REG);

			reg = ioread32(bar0_base + MLU580_JS_DATA_PRO_REG);
			reg &= ~MLU580_JS_DATA_PRO_MASK;
			iowrite32(reg, bar0_base + MLU580_JS_DATA_PRO_REG);
		} else if (pci_match_id(cn_pci_mlu590_tbl, pci_dev)) {
			/* JS protect */
			timeout = 0;
			//step1: js data master mhr req
			reg = ioread32(bar0_base + MLU590_JS_DATA_MHR_REG);
			iowrite32(reg | MLU590_JS_DATA_MHR_MASK, bar0_base + MLU590_JS_DATA_MHR_REG);

			reg = ioread32(bar0_base + MLU590_JS_CFG_MHR_REG);
			iowrite32(reg | MLU590_JS_CFG_MHR_MASK, bar0_base + MLU590_JS_CFG_MHR_REG);
			//step2: wait mhr bus idle
			/* polling js data dynamic reset */
			while (timeout < 1000) {
				if ((ioread32(bar0_base + MLU590_JS_DATA_IDLE_REG) & MLU590_JS_DATA_IDLE_MASK) == MLU590_JS_DATA_IDLE_MASK)
					break;
				timeout++;
				udelay(100);
			}
			/* polling js cfg dynamic reset */
			while (timeout < 1000) {
				if ((ioread32(bar0_base + MLU590_JS_CFG_IDLE_REG) & MLU590_JS_CFG_IDLE_MASK) == MLU590_JS_CFG_IDLE_MASK)
					break;
				timeout++;
				udelay(100);
			}

			if (timeout >= 1000) {
				cn_dev_err("JS poll timeout!");
			} else {
				cn_dev_info("JS reset success");
			}
			reg = ioread32(bar0_base + MLU590_JS_CFG_PRO_REG);
			reg &= ~MLU590_JS_CFG_PRO_MASK;
			iowrite32(reg, bar0_base + MLU590_JS_CFG_PRO_REG);

			reg = ioread32(bar0_base + MLU590_JS_DATA_PRO_REG);
			reg &= ~MLU590_JS_DATA_PRO_MASK;
			iowrite32(reg, bar0_base + MLU590_JS_DATA_PRO_REG);
		}
		//send a reset request
		//pr_info("The devcie will be reset\n");
		iowrite32(0x1, bar0_base + PF_GIC_INFO_REG_0);

	} else {
		cn_dev_info("no support full chip reset");
	}
	iounmap(bar0_base);

	return 0;
}

static int c50_chip_reset(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pci_dev = pcie_set->pdev;
	int ret = 0;

	ret = pci_device_reset(pci_dev);

	if (ret == 0)
		cn_dev_pcie_info(pcie_set, "c50 chip reset success\n");
	else
		cn_dev_pcie_info(pcie_set, "c50 chip reset failed\n");

	return ret;
}

int mlu500_device_reset(void)
{
	struct pci_dev *pci_dev = NULL;
	int ret = 0;

	while ((pci_dev = pci_get_class(PCI_CLASS_PROCESSING_ACCEL << 8, pci_dev)) != NULL) {
		if (!pci_match_id(cn_pci_mlu500_tbl, pci_dev))
			continue;
		//pr_info("find mlu590 device\n");
		if (pci_enable_device(pci_dev))
			return -EIO;

		ret = pci_device_reset(pci_dev);
		if (ret == 0)
			cn_dev_info("mlu500 device reset success");
		else
			cn_dev_info("mlu500 device reset failed");

		pci_disable_device(pci_dev);
	}

	return ret;
}

static int c50_chip_reset_done(struct cn_pcie_set *pcie_set)
{
	int timeout = 0;
	u32 reg1_val = 0x0, reg4_val = 0x0;

	//get soft reset capability
	//#define PF_GIC_INFO_REG_0	(GBO + SUB_GBO + 0x100)
	//#define PF_GIC_INFO_REG_1	(GBO + SUB_GBO + 0x104)
	reg1_val = cn_pci_reg_read32(pcie_set, PF_GIC_INFO_REG_1);
	reg4_val = cn_pci_reg_read32(pcie_set, PF_GIC_INFO_REG_4);

	if ((reg1_val & 0x1) == 0x1 && (reg4_val & 0x1) == 0x1) {
		timeout = 1000;
		while (cn_pci_reg_read32(pcie_set, PF_GIC_INFO_REG_0) && timeout) {
			cn_dev_debug("wait for full chip reset done");
			timeout--;
			msleep(100);
		}
		if (timeout <= 0) {
			cn_dev_err("wait full chip reset timeout");
			return -1;
		}
	} else {
		cn_dev_info("no support full chip reset");
	}

	return 0;
}

static int c50_pll_irq_enable(struct cn_pcie_set *pcie_set)
{
	int i;
	u32 reg_val;

	if (g_platform_type != MLU_PLAT_ASIC)
		return 0;

	/* pll unlock irq enable */
	if (pcie_set->sn_h16 == SUBSYS_MLU590_E) {
		for (i = 0; i < ARRAY_SIZE(mlu590e_pll_cfg); i++) {
			reg_val = ((1 << PLL_INT_EN) | (1 << (PLL_INT_EN + 16)));
			cn_pci_reg_write32(pcie_set, mlu590e_pll_cfg[i].base_addr + PLL_CTRL, reg_val);
		}
	} else if (pcie_set->id == MLUID_590) {
		for (i = 0; i < ARRAY_SIZE(mlu590_pll_cfg); i++) {
			reg_val = ((1 << PLL_INT_EN) | (1 << (PLL_INT_EN + 16)));
			cn_pci_reg_write32(pcie_set, mlu590_pll_cfg[i].base_addr + PLL_CTRL, reg_val);
		}
	} else if (pcie_set->id == MLUID_580) {
		for (i = 0; i < ARRAY_SIZE(mlu580_pll_cfg); i++) {
			reg_val = ((1 << PLL_INT_EN) | (1 << (PLL_INT_EN + 16)));
			cn_pci_reg_write32(pcie_set, mlu580_pll_cfg[i].base_addr + PLL_CTRL, reg_val);
		}
	}

	return 0;
}

static int c50_pll_irq_sts_dump(struct cn_pcie_set *pcie_set)
{
	int i;
	u32 reg_val;

	if (g_platform_type != MLU_PLAT_ASIC)
		return 0;

	/* dump pll irq sts */
	if (pcie_set->sn_h16 == SUBSYS_MLU590_E) {
		for (i = 0; i < ARRAY_SIZE(mlu590e_pll_cfg); i++) {
			reg_val = cn_pci_reg_read32(pcie_set, mlu590e_pll_cfg[i].base_addr + PLL_CTRL);
			if ((reg_val >> PLL_INT_STS) & 0x1) {
				cn_dev_pcie_err(pcie_set, "%s pll unlock", mlu590e_pll_cfg[i].name);
				/* clear pll irq sts */
				reg_val = ((0 << PLL_INT_STS) | (1 << (PLL_INT_STS + 16)));
				cn_pci_reg_write32(pcie_set, mlu590e_pll_cfg[i].base_addr + PLL_CTRL, reg_val);
			}
		}
	} else if (pcie_set->id == MLUID_590) {
		for (i = 0; i < ARRAY_SIZE(mlu590_pll_cfg); i++) {
			reg_val = cn_pci_reg_read32(pcie_set, mlu590_pll_cfg[i].base_addr + PLL_CTRL);
			if ((reg_val >> PLL_INT_STS) & 0x1) {
				cn_dev_pcie_err(pcie_set, "%s pll unlock", mlu590_pll_cfg[i].name);
				/* clear pll irq sts */
				reg_val = ((0 << PLL_INT_STS) | (1 << (PLL_INT_STS + 16)));
				cn_pci_reg_write32(pcie_set, mlu590_pll_cfg[i].base_addr + PLL_CTRL, reg_val);
			}
		}
	} else if (pcie_set->id == MLUID_580) {
		for (i = 0; i < ARRAY_SIZE(mlu580_pll_cfg); i++) {
			reg_val = cn_pci_reg_read32(pcie_set, mlu580_pll_cfg[i].base_addr + PLL_CTRL);
			if ((reg_val >> PLL_INT_STS) & 0x1) {
				cn_dev_pcie_err(pcie_set, "%s pll unlock", mlu580_pll_cfg[i].name);
				/* clear pll irq sts */
				reg_val = ((0 << PLL_INT_STS) | (1 << (PLL_INT_STS + 16)));
				cn_pci_reg_write32(pcie_set, mlu580_pll_cfg[i].base_addr + PLL_CTRL, reg_val);
			}
		}
	}

	return 0;
}

static struct cn_pci_ops c50_private_ops = {
	/* register space */
	.reg_read32 = OVER_WRITE(pcie_reg_read32),
	.reg_write32 = OVER_WRITE(pcie_reg_write32),
	.reg_read64 = OVER_WRITE(pcie_reg_read64),
	.reg_write64 = OVER_WRITE(pcie_reg_write64),
	/* outbound */
	.dob_desc_pg_init = c50_pcie_data_outbound_desc_pg_init,
	.get_dob_win_info = c50_pcie_get_data_outbound_page_info,
	.dob_win_alloc = c50_pcie_data_outbound_page_alloc,
	.dob_win_free = c50_pcie_data_outbound_page_free,
	.get_dob_iova = c50_pcie_get_data_outbound_iova,
	.put_dob_iova = c50_pcie_put_data_outbound_iova,
	/* bar memcpy */
	.set_bar_window = OVER_WRITE(pcie_set_bar_window),
	/* sync memcpy */
	.dma_go_command = OVER_WRITE(pcie_dma_go),
	.dma_bypass_smmu = c50_dma_bypass_smmu,
	.dma_bypass_smmu_all = c50_dma_bypass_smmu_all,
	.fill_desc_list = OVER_WRITE(pcie_fill_desc_list),
	/* async memcopy */
	.async_dma_fill_desc_list = OVER_WRITE(async_dma_fill_desc_list),
	.async_dma_fill_p2p_pull_desc = OVER_WRITE(async_dma_fill_p2p_pull_desc),
	/* sync write */
	.sync_write_init = c50_pcie_sync_write_init,
	.sync_write_exit = c50_pcie_sync_write_exit,
	.sync_write_alloc = c50_pcie_sync_write_alloc,
	.sync_write_trigger = c50_pcie_sync_write_trigger,
	.sync_write_free = c50_pcie_sync_write_free,
	.sync_write_info = c50_pcie_sync_write_info,
	/* atomicop */
	.pcie_atomicop_init = c50_pcie_hw_atomicop_init,
	.pcie_atomicop_exit = c50_pcie_hw_atomicop_exit,
	/* tcdp */
	.tcdp_top_init = c50s_pcie_tcdp_top_init,
	.tcdp_top_exit = c50s_pcie_tcdp_top_exit,
	.get_tcdp_win_base = c50s_pcie_get_tcdp_win_base,
	.get_tcdp_win_size = c50s_pcie_get_tcdp_win_size,
	.get_tcdp_host_buff = c50s_pcie_get_tcdp_host_buff,
	.tcdp_qp0_wrhost_enable = c50s_pcie_qp0_wrhost_enable,
	.tcdp_qp0_wrhost_disable = c50s_pcie_qp0_wrhost_disable,
	.tcdp_tx_dir_linear_bar_cfg = c50s_pcie_tcdp_tx_dir_linear_bar_cfg,
	.tcdp_txrx_indir_cfg = c50s_pcie_tcdp_txrx_indir_cfg,
	.linear_bar_do_iommu_remap = c50s_pcie_linear_bar_iommu_remap,
	.tcdp_win_base_do_iommu_remap = c50s_pcie_tcdp_win_base_iommu_remap,
	.tcdp_change_channel_state = c50s_pcie_tcdp_change_channel_state,
	/* PCI Express basic */
#if 0
	.soft_reset = OVER_WRITE(pcie_soft_reset),
#endif
	.soft_reset = OVER_WRITE(pcie_linkdown_reset),
	.chip_reset = c50_chip_reset,
	.ddr_set_done = c50_pcie_ddr_set_done,
	.check_available = OVER_WRITE(pcie_check_available),
	/* virtual function */
	.sriov_vf_init = c50_sriov_vf_init,
	.sriov_vf_exit = c50_sriov_vf_exit,
	.iov_virtfn_bus = c50_pcie_iov_virtfn_bus,
	.iov_virtfn_devfn = c50_pcie_iov_virtfn_devfn,
	.sriov_pre_init = c50_sriov_pre_init,
	.sriov_later_exit = c50_sriov_later_exit,
#ifdef CONFIG_PCI_IOV
	.sriov_support = c50_sriov_support,
#endif
	/* dfx */
	.pll_irq_sts_dump = c50_pll_irq_sts_dump,
	.pll_irq_enable = c50_pll_irq_enable,
	.dump_reg = OVER_WRITE(pcie_dump_reg),
	.pcie_debug_dump_reg = OVER_WRITE(pcie_debug_dump_reg),
};

static int c50_increase_cpl_timeout(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	u16 cpl_timeout;
	u16 lnk_sta, speed;
	u32 sn;
	u32 ba_sn;

	pcie_capability_read_word(pcie_set->pdev, PCI_EXP_LNKSTA, &lnk_sta);
	speed = lnk_sta & 0xF;
	if ((g_platform_type != MLU_PLAT_ASIC) || (speed >= PCI_EXP_LNKCTL2_TLS_32_0GT)) {
		pcie_capability_read_word(pdev, PCI_EXP_DEVCTL2, &cpl_timeout);
		//disable completion timeout
		pcie_capability_write_word(pdev, PCI_EXP_DEVCTL2, ((cpl_timeout & 0xffef) | 0x10));
		pcie_capability_read_word(pdev, PCI_EXP_DEVCTL2, &cpl_timeout);
		cn_dev_pcie_info(pcie_set, "disable completion timout:%#x", cpl_timeout & 0xff);
		return 0;
	}

	if (pcie_set->id != MLUID_590)
		return 0;

	sn = cn_pci_reg_read32(pcie_set, MLU590_IPC_14);
	sn = (sn >> 8) & 0xffffff;
	ba_sn = cn_pci_reg_read32(pcie_set, MLU590_IPC_16);
	ba_sn = (ba_sn >> 8) & 0xffffff;
	cn_dev_pcie_info(pcie_set, "sn:%#x ba_sn:%#x", sn, ba_sn);

	/* [DRIVER-13512] need change cpl timeout */
	if ((sn == 0x800301) && (ba_sn == 0x0)) {
		pcie_capability_read_word(pdev, PCI_EXP_DEVCTL2, &cpl_timeout);
		cn_dev_pcie_info(pcie_set, "completion timout default:%#x", cpl_timeout & 0xf);
		//set completion timeout 1-3.5s
		pcie_capability_write_word(pdev, PCI_EXP_DEVCTL2, ((cpl_timeout & 0xfff0) | 0xa));
		pcie_capability_read_word(pdev, PCI_EXP_DEVCTL2, &cpl_timeout);
		cn_dev_pcie_info(pcie_set, "completion timout new:%#x", cpl_timeout & 0xf);
	}

	return 0;
}

static int c50_bug_fix_list(struct cn_pcie_set *pcie_set)
{
	int ret = 0;
	u16 ctl;
	u32 reg_val = 0x0;
	struct pci_dev *pdev = pcie_set->pdev;
	u16 lnk_sta, speed;

	c50_increase_cpl_timeout(pcie_set);

	/*[DRIVER-10092] outs threshold reg 0x80_0094_7458 [6:0] set to 7'd93.*/
	if (pcie_set->id == MLUID_580) {
		cn_pci_reg_write32(pcie_set, 0x400008, 0x5d);
	} else {
		reg_val = cn_pci_reg_read32(pcie_set, 0x947458);
		reg_val &= ~(0x7f << 0);
		reg_val |= (0x5D << 0);
		cn_pci_reg_write32(pcie_set, 0x947458, reg_val);
	}

	/* fix poisoned TLP by rresp error to ok*/
	cn_pci_reg_write32(pcie_set, 0x58050, 0x10);

	/*dma 8kb/16kb flow control*/
	//cn_pci_reg_write32(pcie_set, 0x39018, 0x1);//atc
	//cn_pci_reg_write32(pcie_set, 0x3901c, 0x2);//smmu

	if (pcie_set->sn_h16 == SUBSYS_MLU590_E) {
		/* cfg_dma2atc_disable_prefetch */
		cn_pci_reg_write32(pcie_set, 0x58080, 0x1);
	} else {
		/* ats enable*/
		//cn_pci_reg_write32(pcie_set, 0x39030, 0x14040);//ats deadlock bug
		cn_pci_reg_write32(pcie_set, 0x40208, 0x80000000);//ats window set
		//cn_pci_reg_write32(pcie_set, 0x40224, 0x0);//ats stu get page only one
		/* ats bypass*/
		cn_pci_reg_write32(pcie_set, 0x40320, 0x1);//ats bypass
	}

	/* fix DRIVER-11696: set dma cfg timeout */
	if (pcie_set->sn_h16 == SUBSYS_MLU590_E) {
		/* mlu590E disable timeout */
		cn_pci_reg_write32(pcie_set, 0x39038, 0x0);
		cn_pci_reg_write32(pcie_set, 0x3a970, 0x0);
	} else {
		/* mlu580/mlu590 set max timeout 1023ms */
		cn_pci_reg_write32(pcie_set, 0x39038, 0x3ff);
	}

	/* dma double bandwidth control */
	if (pcie_set->sn_h16 == SUBSYS_MLU590_E) {
		/* pcie_atc_cfg and pcie_ctrl_sidband cannot open at the same time */
		cn_pci_reg_write32(pcie_set, 0x40704, 0x1);
	} else {
		/* swift only support pcie_ctrl_sideband bandwidth control */
		pcie_capability_read_word(pcie_set->pdev, PCI_EXP_LNKSTA, &lnk_sta);
		speed = lnk_sta & 0xF;
		if (speed >= PCI_EXP_LNKCTL2_TLS_32_0GT) {
			/* disable bandwidth control on gen5 server */
			cn_pci_reg_write32(pcie_set, 0x51e00, 0x0);
		} else {
			cn_pci_reg_write32(pcie_set, 0x51e00, 0x1);
		}
	}

	if (pcie_set->id == MLUID_580) {
		/* 1.must first write pcie config*/
		/* 2.enable reduce one_empty_bubble*/
		cn_pci_reg_write32(pcie_set, 0x330, 0x1);
	}

	/*
	 * fix: Turn on extended tags in DevCtl
	 */
	ret = pcie_capability_read_word(pdev, PCI_EXP_DEVCTL, &ctl);
	if (ret)
		return 0;

	if (!(ctl & PCI_EXP_DEVCTL_EXT_TAG)) {
		cn_dev_pcie_info(pcie_set, "enabling Extended Tags\n");
		pcie_capability_set_word(pdev, PCI_EXP_DEVCTL,
				PCI_EXP_DEVCTL_EXT_TAG);
	}

	cn_pci_check_plx_bridge(pcie_set);
	return ret;
}

static int c50_pcie_setup(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/*
	 *  publish ops to uper level
	 *  different cambricon ID have different ops
	 *  same cambricon ID with different wafer, change ops here
	 */
	cn_pci_ops_init(&public_ops, &c50_private_ops);
	pcie_set->ops = &c50_private_ops;

	/* default setting depends on snoop:dev_is_dma_coherent */
#if defined(__x86_64__)
	pcie_set->cfg.arm_trigger_enable = arm_trigger_enable;
	pcie_set->cfg.af_enable = dma_af_enable;
#endif

	/*PCIe-TCDP Cap init*/
	if (pcie_set->id == MLUID_580) {
		pcie_set->cfg.tcdp_able = 1;
	}

	/* mlu590 support sync write */
#if (!defined(__arm__) && !defined(__aarch64__))
	pcie_set->cfg.sync_write_able = 1;
#else
	pcie_set->cfg.sync_write_able = 0;
#endif

	if (g_platform_type == MLU_PLAT_VDK) {
		pcie_set->cfg.pcie_sram_able = 0;
		pcie_set->cfg.atomicop_support = 0;
		pcie_set->cfg.outbound_able = 0;
	} else {
		pcie_set->cfg.pcie_sram_able = 1;
		pcie_set->cfg.atomicop_support = 1;
		pcie_set->cfg.outbound_able = 1;
	}

	cn_dev_pcie_info(pcie_set,
		"arm_trigger_able:%d af_enable:%d tcdp_able:%d sync_write_able:%d",
		pcie_set->cfg.arm_trigger_enable,
		pcie_set->cfg.af_enable,
		pcie_set->cfg.tcdp_able,
		pcie_set->cfg.sync_write_able);

	cn_dev_pcie_info(pcie_set, "sram_able:%d atomicop_support:%d outbound_able:%d",
		pcie_set->cfg.pcie_sram_able,
		pcie_set->cfg.atomicop_support,
		pcie_set->cfg.outbound_able);

	/* soft status */
	pcie_set->share_mem_cnt = 0;
	pcie_set->is_virtfn = 0;

	return 0;
}

static int c50_pcie_domain_get_resource(void *pcie, struct domain_resource *resource)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/* for domain manger get hard resource */
	resource->id = pcie_set->id;
	resource->max_phy_channel = DMA_REG_CHANNEL_NUM;//MAX 9
	resource->cfg_reg_size = AXI_CONFIG_SIZE;
	resource->share_mem_base = C50_AXI_SHM_BASE;
	resource->share_mem_size = pci_resource_len(pcie_set->pdev, 0) / 2; // MAX=128MB
	resource->vf_cfg_limit = 32 * 1024;
	resource->ob_set[0].virt_addr = pcie_set->share_mem[1].virt_addr;
	resource->ob_set[0].win_length = pcie_set->share_mem[1].win_length;
	resource->ob_set[0].ob_axi_base = pcie_set->share_mem[1].device_addr;
	resource->sram_pa_base = C50_AXI_SRAM_PA_BASE;
	resource->sram_pa_size = C50_AXI_SRAM_TOTAL_SIZE;
	/* adapte to huge bar for domain*/
	resource->large_bar_base = cn_pci_bus_address(pcie_set->pdev, 4);
	resource->large_bar_size = pci_resource_len(pcie_set->pdev, 4);

	return 0;
}

static int c50_pcie_set_bar0_window(struct cn_pcie_set *pcie_set)
{
	int i = 0;
	int bar0_mode = BAR0_MAX_SIZE / pcie_set->bar0_set.size;
	struct bar0_set *bar0_set = NULL;

	if (!bar0_mode) {
		cn_dev_pcie_err(pcie_set, "win_size is zero");
		return -1;
	}
	bar0_set = &pcie_set->bar0_set;
	for (i = 0; i < 4; i++) {
		//config:
		if (!pcie_set->bar0_set.size) {
			cn_dev_pcie_err(pcie_set, "bar0 size is zero");
			return -1;
		}

		bar0_set->bar0_window_base = 0x10/bar0_mode;
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_SRC_WIN(3 + i), 0x80010 + (i) * (0x10/bar0_mode));
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_MASK_WIN(3 + i), (0xFFFFFF0 | (0x10/bar0_mode)));
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_TGT_WIN(3 + i), 0x80010 + (i) * (0x10/bar0_mode));
		bar0_set->bar0_window_tgt[i] = 0x80010 + (i) * (0x10/bar0_mode);
	}
	for (i = 0; i < 2; i++) {
		//share mem:
		//bar0 64M(change window(7~8) for 128M mem of per a quad
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_SRC_WIN(7 + i), 0x80080 + (i) * (0x40/bar0_mode));
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_MASK_WIN(7 + i), (0xFFFFFC0 | (0x40/bar0_mode)));
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_TGT_WIN(7 + i), (C50_AXI_SHM_BASE >> 20) + (i) * (0x40/bar0_mode));
	}

	cn_pci_reg_write32(pcie_set, PF_SHARE_MEM_MASK, 0xFFFFF80);//share memory 128M
	cn_pci_reg_write32(pcie_set, PF_SHARE_MEM_BASE, (C50_AXI_SHM_BASE >> 20));//share memory 128M
	cn_pci_reg_read32(pcie_set, PF_SHARE_MEM_BASE);//must add read

	return 0;
}

static int c50_set_bar_default_window(struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar;
	int order;
	unsigned long long mask;

	list_for_each_entry(bar, &pcie_set->bar_resource_head, list) {
		bar->window_addr = 0;
		order = ilog2(bar->size / BAR_BASE_SIZE);
		if (bar->index == 2 && pcie_set->cfg.tcdp_able) {
			mask = 0x0ULL;
			cn_pci_reg_write64(pcie_set, PF_BAR_ADDR_MASK(bar->index), mask);
		} else {
			mask = (0xFFFFFFFULL << order) & 0xFFFFFFFULL;
			cn_pci_reg_write64(pcie_set, PF_BAR_ADDR_MASK(bar->index), mask);
		}
		cn_pci_reg_read32(pcie_set, PF_BAR_ADDR_MASK(bar->index));
		cn_dev_pcie_debug(pcie_set, "bar->index:%d bar->size:%#llx addr_mask:%#llx",
			bar->index, bar->size, mask);
	}

	return c50_pcie_set_bar0_window(pcie_set);
}

static void c50_pcie_bar0_exit(struct cn_pcie_set *pcie_set)
{
	int seg;

	for (seg = 0; seg < MAX_BAR_SEGMENTS; seg++) {
		if (pcie_set->bar0_set.seg[seg].virt) {
			cn_iounmap(pcie_set->bar0_set.seg[seg].virt);
			pcie_set->bar0_set.seg[seg].virt = NULL;
		}
	}
}

static int c50_pcie_bar0_seg_init(struct cn_pcie_set *pcie_set,
				u64 bar0_mem_offset, u64 bar0_mem_size)
{
	struct pcibar_seg_s *p_bar_seg;

	/* the register area */
	p_bar_seg = &pcie_set->bar0_set.seg[0];
	p_bar_seg->size = pcie_set->bar0_set.size / 2;
	p_bar_seg->base = pcie_set->bar0_set.base;
	p_bar_seg->virt = cn_ioremap(p_bar_seg->base, p_bar_seg->size);
	if (!p_bar_seg->virt)
		goto ERROR_RET;
	cn_dev_pcie_debug(pcie_set, "bar0 register virt:%p", p_bar_seg->virt);

	pcie_set->bar0_set.reg_virt_base = p_bar_seg->virt;
	pcie_set->bar0_set.reg_phy_addr = p_bar_seg->base;
	pcie_set->bar0_set.reg_win_length = p_bar_seg->size;

	/* the bar share memory */
	p_bar_seg = &pcie_set->bar0_set.seg[1];
	p_bar_seg->base = pcie_set->bar0_set.base + pcie_set->bar0_set.reg_win_length;
	p_bar_seg->size = pcie_set->bar0_set.size - pcie_set->bar0_set.reg_win_length;
	p_bar_seg->virt = cn_ioremap_wc(p_bar_seg->base, p_bar_seg->size);
	if (!p_bar_seg->virt)
		goto ERROR_RET;
	cn_dev_pcie_debug(pcie_set, "bar0 memory virt:%p", p_bar_seg->virt);

	pcie_set->share_mem_cnt = 1;
	pcie_set->share_mem[0].virt_addr =
		pcie_set->bar0_set.seg[1].virt + bar0_mem_offset;
	pcie_set->share_mem[0].phy_addr =
		pcie_set->bar0_set.seg[1].base + bar0_mem_offset;
	pcie_set->share_mem[0].win_length = bar0_mem_size;
	pcie_set->share_mem[0].type = CN_SHARE_MEM_DEV;
	pcie_set->share_mem[0].device_addr = C50_AXI_SHM_BASE + bar0_mem_offset;

	return 0;

ERROR_RET:
	cn_dev_pcie_err(pcie_set, "pcie bar init error");
	c50_pcie_bar0_exit(pcie_set);

	return -1;
}

static int c50_pcie_bar0_init(struct cn_pcie_set *pcie_set)
{
	u8 i;
	u64 offset, size;
	const void *domain = NULL;
	u64 sz;
	u32 func_id;

	sz = pci_resource_len(pcie_set->pdev, 0);
	if (!sz) {
		cn_dev_pcie_err(pcie_set, "no enough MMIO space for PF bar0");
		return -1;
	}
	pcie_set->bar0_set.base = pci_resource_start(pcie_set->pdev, 0);
	pcie_set->bar0_set.size = sz;

	for (i = 0; i < 4; i++)
		sema_init(&pcie_set->bar0_set.bar0_window_sem[i], 1);

	if (cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		domain = cn_dm_get_domain_early(pcie_set->bus_set,
							DM_FUNC_OVERALL);
		if (!domain)
			return -ENODEV;

		func_id = cn_dm_get_func_id(domain);
		cn_dev_pcie_info(pcie_set, "Domain[%d: 0x%px]", func_id, domain);

		offset = cn_dm_pci_get_bars_shm_bs(domain, 0);
		size = cn_dm_pci_get_bars_shm_sz(domain, 0);
	} else {
		offset = 0;
		size = pcie_set->bar0_set.size / 2;
	}
	cn_dev_pcie_debug(pcie_set, "get from domain offset:%#llx size:%#llx",
						offset, size);

	if (c50_pcie_bar0_seg_init(pcie_set, offset, size))
		return -1;

	return 0;
}

static void c50_pcie_bar2_bar4_exit(struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar, *tmp;

	list_for_each_entry_safe(bar, tmp, &pcie_set->bar_resource_head, list) {
		if (bar->base) {
			cn_iounmap((void *)bar->base);
			list_del(&bar->list);
			cn_kfree(bar);
		}
	}
}

static int c50_pcie_bar2_bar4_init(struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar_pr;
	int index;
	u64 base, sz;
	struct bar_resource bar, soft_bar, *new;
	struct pci_dev *pdev = pcie_set->pdev;
	u32 value32;
	u64 value64;
	u64 bar2_win_sz;
	u64 bar2_win_cnt = 1; /*Default as only 1 for normal win*/

	INIT_LIST_HEAD(&pcie_set->bar_resource_head);

	/*
	 * For MLU580 Magpie the BAR2 can work in two mode
	 * A: whole PF BAR2 256M
	 *           /-----------128-------\   /------------------128-------------------\
	 * B: 256M = bar2-normal + bar2-mdr*7 + 8M*8(DIR Win) + 8K*8(INDIR Win) + reserved
	 *
	 * 	If bar2-mdr is used, then please pay attention, the size of bar-2 normal shall
	 *	be changed.
	 */
	for (index = 2; index < 6; index++) {
		sz = pci_resource_len(pdev, index);
		if (!sz)
			continue;
		base = pci_resource_start(pdev, index);

		memset(&bar, 0, sizeof(bar));
		bar.type = PF_BAR;
		bar.index = index;
		bar.phy_base = base;
		bar.bus_base = cn_pci_bus_address(pdev, index);
		bar.rediv_size = sz;
		/***
		 * bar.reg/pre_align_to_reg are not work in VF mode.
		 */
		if (pcie_set->cfg.tcdp_able && index == 2) {
			/*HardWrite : TCDP will hold half of BAR2*/
			bar.rediv_size = sz / 2; /*[normal&mdr win]+[tcdp zone]*/
			bar.reg = TCDP_RX_TGT_BAR;
			bar.pre_align_to_reg = ilog2(TCDP_BAR_BASE_SIZE);
			bar2_win_cnt = tcdp_mdr_win_cnt + 1;
			bar2_win_cnt = 1 << ilog2(bar2_win_cnt);
			bar2_win_sz = bar.rediv_size / bar2_win_cnt;
			bar.size = bar2_win_sz;
		} else {
			bar.size = sz;
			bar.reg = PF_BAR_ADDR_BASE(index);
			bar.pre_align_to_reg = ilog2(BAR_BASE_SIZE);
		}

		new = mlu590_pcie_bar_resource_struct_init(&bar, pcie_set);
		if (new)
			list_add_tail(&new->list, &pcie_set->bar_resource_head);

		/* resize bar window  */
		value32 = ((ilog2(sz) - 1) << 1) | (1 << 0);
		cn_pci_reg_write32(pcie_set, WIN0_SRC_ADDRL(index), value32);

		value64 = ~(u64)((0x1ULL << ilog2(sz)) - 1);
		cn_pci_reg_write64(pcie_set, WIN0_TRSL_MASKL(index), value64);
		cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
	}
	/*
	 * Soft bar from 6 as begin.
	 */
	if (bar2_win_cnt > 1) {
		memcpy(&soft_bar, &bar, sizeof(bar));
		for (index = 0; index < (bar2_win_cnt - 1); index++) {
			soft_bar.index = index + SOFT_BAR_INDEX_START;
			soft_bar.phy_base = bar.phy_base + (bar2_win_sz << index);
			soft_bar.bus_base = bar.bus_base + (bar2_win_sz << index);
			soft_bar.reg = TCDP_RX_TGT_MDR(index);
			new = mlu590_pcie_bar_resource_struct_init(&soft_bar, pcie_set);
			if (new)
				list_add_tail(&new->list, &pcie_set->bar_resource_head);
		}
	}
	/*Set bar2 mdr wins with tcdp enable*/
	if (pcie_set->cfg.tcdp_able) {
		set_bar2_wins_under_tcdp_mode(pcie_set);
	}

	list_for_each_entry(bar_pr, &pcie_set->bar_resource_head, list) {
		cn_dev_pcie_debug(pcie_set, "bar_type=%d, bar_index=%d, bar_base=%p, bar_sz=%llx",
			bar_pr->type, bar_pr->index, bar_pr->base, bar_pr->size);
	}

	return 0;
}

static void c50_pcie_bar_exit(struct cn_pcie_set *pcie_set)
{
	c50_pcie_bar2_bar4_exit(pcie_set);
	c50_pcie_bar0_exit(pcie_set);
}

static int c50_pcie_bar_init(struct cn_pcie_set *pcie_set)
{
	if (c50_pcie_bar0_init(pcie_set))
		return -1;

	if (c50_pcie_bar2_bar4_init(pcie_set))
		return -1;

	c50_set_bar_default_window(pcie_set);

	return 0;
}

static int c50_pcie_dma_pre_init_hw(struct cn_pcie_set *pcie_set)
{
	int irq;
	char src[30];
	int queue;
	u32 irq_mask = 0x55;//4queue irq to arm
	int queue_status_buf_num[4];
	int cmd_buf;
	int eng;
	u32 reg_val;

	if (pcie_set->sn_h16 == SUBSYS_MLU590_E) {
		/* NOTE: clear pf/vf0-7 dma cmd buf interrupt before enable it*/
		for (cmd_buf = 0; cmd_buf < DMA_MAX_CMD_BUF_NUM; cmd_buf++) {
			host_pf_queue_status_buf_status(cmd_buf, queue_status_buf_num, pcie_set);
			for (queue = 0; queue < DMA_MAX_QUEUE_NUM; queue++) {
				if (!queue_status_buf_num[queue])
					continue;

				while (queue_status_buf_num[queue]) {
					cn_pci_reg_write32(pcie_set,
							DMA_STATUS_UP_QUEUE(cmd_buf, queue), 1);
					queue_status_buf_num[queue]--;
				}
			}
		}

		/* TODO domain_phy_channel_mask */
		/* host cmd buffer init */
		/* bind dma engine 0-4 to cmd buffer 0 */
		for (eng = 0; eng < VER2_DEV_ENG_START; eng++) {
			cn_pci_reg_write32(pcie_set, ENG_CMD_SEL_ENGINE(eng), PF_ENG_NUM);
			cn_dev_pcie_debug(pcie_set, "Link eng:%d to cmd_buf:%d", eng, PF_ENG_NUM);
		}
		/* cmd buffer 0 report irq to host */
		cn_pci_reg_write32(pcie_set, CMD_BUF_CTRL_ENGINE(PF_ENG_NUM), 0x0);
		/* enable cmd buffer 0 irq */
		sprintf(src, "host_dma_cmd_buf%d", PF_ENG_NUM);
		irq = pcie_get_irq(src, pcie_set);
		pcie_gic_unmask(irq, pcie_set);
		cn_pci_reg_write32(pcie_set, PCIE_IRQ_MASK(irq), 0x0);

		/* arm cmd buffer init */
		/* overide axfunc 5-8 to PF */
		for (cmd_buf = VER2_DEV_ENG_START; cmd_buf < VER2_DEV_ENG_END; cmd_buf++) {
			reg_val = cn_pci_reg_read32(pcie_set, DMA_OVERIDE_EN_AXFUNX);
			reg_val |= (0x1 << cmd_buf);
			cn_pci_reg_write32(pcie_set, DMA_OVERIDE_EN_AXFUNX, reg_val);
			cn_pci_reg_write32(pcie_set, DMA_OVERIDE_VALUE_AXFUNC(cmd_buf), 0);
		}
		/* bind dma engine 5-8 to cmd buffer 5-8 */
		for (eng = VER2_DEV_ENG_START; eng < VER2_DEV_ENG_END; eng++) {
			cn_pci_reg_write32(pcie_set, ENG_CMD_SEL_ENGINE(eng), eng);
		}
		/* cmd buffer 5-8 report irq to arm */
		for (cmd_buf = VER2_DEV_ENG_START; cmd_buf < VER2_DEV_ENG_END; cmd_buf++) {
			cn_pci_reg_write32(pcie_set, CMD_BUF_CTRL_ENGINE(cmd_buf), 0x55);
		}
		/* enable cmd buffer 5-8 irq */
		for (cmd_buf = VER2_DEV_ENG_START; cmd_buf < VER2_DEV_ENG_END; cmd_buf++) {
			sprintf(src, "host_dma_cmd_buf%d", cmd_buf);
			irq = pcie_get_irq(src, pcie_set);
			pcie_gic_unmask(irq, pcie_set);
		}
	} else {
		/* NOTE: clear pf dma cmd buf interrupt before enable it*/
		host_pf_queue_status_buf_status(PF_ENG_NUM, queue_status_buf_num, pcie_set);
		for (queue = 0; queue < DMA_MAX_QUEUE_NUM; queue++) {
			if (!queue_status_buf_num[queue])
				continue;

			while (queue_status_buf_num[queue]) {
				cn_pci_reg_write32(pcie_set,
					DMA_STATUS_UP_QUEUE(PF_ENG_NUM, queue), 1);
				queue_status_buf_num[queue]--;
			}
		}

		/* bind all dma engine to pf cmd buffer */
		for_each_set_bit(cmd_buf, (unsigned long *)&pcie_set->dma_set.domain_phy_channel_mask,
				DMA_REG_CHANNEL_NUM) {
			cn_pci_reg_write32(pcie_set, ENG_CMD_SEL_ENGINE(cmd_buf), PF_ENG_NUM);
			cn_dev_pcie_debug(pcie_set, "Link dma%d to pf", cmd_buf);
		}

		/* cmd queue0/1 report irq to host; cmd queue2/3 report irq to arm */
		for_each_set_bit(queue, (unsigned long *)&pcie_set->dma_set.dma_phy_channel_mask,
			pcie_set->dma_set.max_phy_channel) {
			SET_BITS_VAL(irq_mask, queue * 2 + 1, queue * 2 + 0, 0x0);
		}
		cn_pci_reg_write32(pcie_set, CMD_BUF_CTRL_ENGINE(PF_ENG_NUM), irq_mask);
		cn_dev_pcie_debug(pcie_set, "irq mask = %#x", irq_mask); //0x50

		/* enable pf dma irq */
		sprintf(src, "host_dma_cmd_buf%d", PF_ENG_NUM);
		irq = pcie_get_irq(src, pcie_set);
		pcie_gic_unmask(irq, pcie_set);
		cn_pci_reg_write32(pcie_set, PCIE_IRQ_MASK(irq), 0x0);
	}

	return 0;
}

static void c50_pcie_dma_pre_exit(struct cn_pcie_set *pcie_set)
{
	char src[30];

	sprintf(src, "host_dma_cmd_buf%d", PF_ENG_NUM);
	cn_pci_unregister_interrupt(pcie_get_irq(src, pcie_set), pcie_set);
}

static int c50_pcie_dma_pre_init(struct cn_pcie_set *pcie_set)
{
	const void *domain = NULL;
	char src[30];

	if (cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		domain = cn_dm_get_domain_early(pcie_set->bus_set,
							DM_FUNC_OVERALL);
		if (!domain)
			return -ENODEV;

		pcie_set->dma_set.domain_phy_channel_mask = cn_dm_pci_get_dma_ch(domain);
	} else {
		pcie_set->dma_set.domain_phy_channel_mask = DMA_REG_CHANNEL_MASK;
	}

	if (pcie_set->id == MLUID_580 || pcie_set->sn_h16 == SUBSYS_MLU590_E)
		pcie_set->cfg.p2p_mode = P2P_PUSH_MODE;
	else
		pcie_set->cfg.p2p_mode = P2P_PULL_MODE;

	if (pcie_set->cfg.arm_trigger_enable) {
		pcie_set->dma_set.max_phy_channel = HOST_QUEUE_CNT;
		pcie_set->dma_set.dma_phy_channel_mask = (u32)((1 << HOST_QUEUE_CNT) - 1);
	} else {
		pcie_set->dma_set.max_phy_channel = DMA_MAX_QUEUE_NUM;
		pcie_set->dma_set.dma_phy_channel_mask = DMA_MAX_QUEUE_MASK;
	}
	pcie_set->dma_set.dma_fetch_buff = DMA_QUEUE_BUFF;
	if (g_platform_type == MLU_PLAT_ASIC)
		pcie_set->dma_set.dma_timeout = TIME_OUT_VALUE;
	else
		pcie_set->dma_set.dma_timeout = TIME_OUT_VALUE * 100;

	pcie_set->dma_set.shared_desc_total_size = SHARED_DMA_DESC_TOTAL_SIZE;
	pcie_set->dma_set.priv_desc_total_size = PRIV_DMA_DESC_TOTAL_SIZE;
	pcie_set->dma_set.dma_buffer_size = DMA_BUFFER_SIZE;
	pcie_set->per_desc_size = DMA_DESC_PER_SIZE;
	pcie_set->per_desc_max_size = PER_DESC_MAX_SIZE;

	pcie_set->async_set.async_static_task_num = ASYNC_STATIC_TASK_NUM;
	pcie_set->async_set.async_max_desc_num = ASYNC_MAX_DESC_NUM;
	pcie_set->async_set.async_desc_size = ASYNC_DMA_DESC_TOTAL_SIZE;
	pcie_set->async_set.async_desc_num = pcie_set->async_set.async_desc_size /
					pcie_set->per_desc_size;

	sprintf(src, "host_dma_cmd_buf%d", PF_ENG_NUM);
	cn_pci_register_interrupt(pcie_get_irq(src, pcie_set),
			c50_pcie_dma_interrupt_handle, pcie_set, pcie_set);

	c50_pcie_dma_pre_init_hw(pcie_set);

	return 0;
}

static int c50_pcie_interrupt_init(struct cn_pcie_set *pcie_set)
{
	static const int interrupt_count[] = {MSI_COUNT, MSIX_COUNT, INTX_COUNT};

	if (isr_type_index == -1) {
		if (isr_default_type == MSI)
			pcie_set->irq_set.irq_type = MSIX;
		else
			pcie_set->irq_set.irq_type = isr_default_type;
	} else {
		pcie_set->irq_set.irq_type = isr_type_index;
	}

	pcie_set->irq_set.irq_num = interrupt_count[pcie_set->irq_set.irq_type];
	/* fix msix ram bug by writing msix ram*/
	if (pcie_set->irq_set.irq_type == MSIX)
		fill_msix_ram(pcie_set);

	do {
		if (isr_enable_func[pcie_set->irq_set.irq_type](pcie_set) == 0)
			break;

		if (pcie_set->irq_set.irq_type == MSIX) {
			pcie_set->irq_set.irq_type = MSI;
			pcie_set->irq_set.irq_num = interrupt_count[pcie_set->irq_set.irq_type];
		} else if (pcie_set->irq_set.irq_type == MSI) {
			pcie_set->irq_set.irq_type = INTX;
			pcie_set->irq_set.irq_num = interrupt_count[pcie_set->irq_set.irq_type];
		} else if (pcie_set->irq_set.irq_type == INTX) {
			cn_dev_pcie_err(pcie_set, "isr init failed!");
			return -1;
		}
	} while (1);

	if (pcie_set->ops->isr_hw_enable)
		pcie_set->ops->isr_hw_enable(pcie_set);
	pcie_gic_mask_all(pcie_set);

	pcie_set->irq_str_index_ptr = irq_str_index;

	return 0;
}

static int c50_pcie_interrupt_exit(struct cn_pcie_set *pcie_set)
{
	int i;

	cn_pci_disable_all_irqs(pcie_set);
	if (isr_disable_func[pcie_set->irq_set.irq_type](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr destroyed failed!");
		return -1;
	}

	if (pcie_set->irq_set.irq_type == MSIX) {
		for (i = 0; i < (GIC_INTERRUPT_NUM * 4); i++)
			pcie_set->irq_set.msix_ram[i] =
				cn_pci_reg_read32(pcie_set, (GBO + i * 4));
	}

	return 0;
}

static int c50_check_noc_bus(struct cn_pcie_set *pcie_set)
{
	u32 reg_data;

	/* check NOC bus status */
	reg_data = cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
	if (reg_data == REG_VALUE_INVALID) {
		cn_dev_pcie_err(pcie_set, "NOC bus abnormal, read value = %#x", reg_data);
		return -1;
	}

	return 0;
}

static int c50_get_sn_h16(struct cn_pcie_set *pcie_set)
{
	u32 reg32 = 0;

	if ((pcie_set->id == MLUID_590) || (pcie_set->id == MLUID_590V)) {
		reg32 = cn_pci_reg_read32(pcie_set, MLU590_IPC_14);
	} else {
		reg32 = cn_pci_reg_read32(pcie_set, MLU580_IPC_14);
	}
	pcie_set->sn_h16 = (reg32 >> 16) & 0xffff;
	cn_dev_pcie_debug(pcie_set, "sn_h16 = %#x", pcie_set->sn_h16);

	return 0;
}

static int c50_pcie_pre_init(void *pcie)
{
	int ret = 0;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	ret = c50_pcie_bar_init(pcie_set);
	if (ret)
		return -1;

	ret = c50_chip_reset_done(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = c50_check_ddr_status(pcie_set);
	if (ret) {
		ret = c50_ddr_init_retry(pcie_set);
		if (ret)
			goto RELEASE_BAR;
	}

	ret = c50_check_noc_bus(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = c50_get_sn_h16(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = c50_bug_fix_list(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = c50_pcie_interrupt_init(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = c50_pcie_dma_pre_init(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = c50_pcie_data_outbound_init(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = c50_sriov_pf_init(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	return ret;

RELEASE_BAR:
	c50_pcie_bar_exit(pcie_set);
	return -1;
}

static int c50_pcie_pre_exit(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	c50_sriov_pf_exit(pcie_set);

	c50_pcie_data_outbound_exit(pcie_set);
	c50_pcie_dma_pre_exit(pcie_set);

	if (c50_pcie_interrupt_exit(pcie_set))
		return -1;

	c50_check_outbound_ar_cnt(pcie_set);
	c50_pcie_bar_exit(pcie_set);

	return 0;
}

struct cn_pci_info c50_pci_info = {
	.setup = c50_pcie_setup,
	.pre_init = c50_pcie_pre_init,
	.pre_exit = c50_pcie_pre_exit,
	.get_resource = c50_pcie_domain_get_resource,
	.dev_name = "c50"
};
