/************************************************************************
 *
 *  @file cndrv_pci_pigeon.c
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
#include <linux/aer.h>
#include <linux/platform_device.h>
#include <linux/vmalloc.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/slab.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "../../pcie_dma.h"
#include "../../pcie_bar.h"
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_pci_pigeon.h"
#include "cndrv_debug.h"
#include "cndrv_ipcm.h"

#define HOT_RST   1
#define LINKD_RST 2
#define FUNC_RST  3
#define RESET_SEL  FUNC_RST

/*
	The Relation-Map of all 512s PCIe-GIC
 */
#if (GIC_INTERRUPT_NUM != MSIX_COUNT)
const static int irq_msix_gic_end[16] = {
	0, 1, 2, 3, 4, 5, 6, 7,
	37, 117, 145, 185, 189, 200, 510, GIC_INTERRUPT_NUM - 1};
#endif

#if (MSI_COUNT == 1)
const static int irq_msi_gic_end[1] = {GIC_INTERRUPT_NUM - 1};
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
	15, 31, 47, 63, 79, 95, 111, 127,
	143, 159, 175, 191, 207, 223, 239, 255,
	271, 287, 303, 319, 335, 351, 367, 383,
	399, 415, 431, 447, 463, 479, 495, 511};
#endif

static struct cn_pci_irq_str_index irq_str_index[GIC_INTERRUPT_NUM] = {
	{324, "pcie_dma0"},
	{325, "pcie_dma1"},
};

const static struct {
	u64 reg;
	u64 mask;
} pf_table[] = {
	{BAR2_TO_AXI_ADDR_REG_L, 0x0}, /* pf bar2 */
	{BAR4_TO_AXI_ADDR_REG_L, 0x0}, /* pf bar4 */
};

/*
 *  include public c code
 *  warnning: do not remove it to the top of file
 *            otherwise will have build errors
 */
#include "../../pcie_common.c"
#include "../haikouichthys.h"
#define OVER_WRITE(f) pigeon_##f

static int pigeon_bug_fix_list(struct cn_pcie_set *pcie_set);
static u32 OVER_WRITE(pcie_reg_read32)(u64 axi_addr, struct cn_pcie_set *pcie_set);
static void OVER_WRITE(pcie_reg_write32)(u64 axi_addr, u32 data,
						struct cn_pcie_set *pcie_set);
static u64 OVER_WRITE(pcie_reg_read64)(u64 axi_addr, struct cn_pcie_set *pcie_set);
static void OVER_WRITE(pcie_reg_write64)(u64 axi_addr, u64 data,
						struct cn_pcie_set *pcie_set);

/*
	Turn whole transfer task into Description
 */
static int OVER_WRITE(pcie_fill_desc_list)(struct dma_channel_info *channel)
{
	int i;
	unsigned long cpu_dma_addr = 0;
	u64 ipu_ram_dma_addr;
	unsigned long count = 0;
	struct scatterlist *sg;
	int desc_offset = 0;
	int desc_number = 0;
	unsigned int ctrl, ndl, ndu;
	unsigned long cpu_addr_cur;
	unsigned long count_cur;

	ipu_ram_dma_addr = channel->ram_addr;

	if (channel->direction != DMA_P2P) {
		for_each_sg(channel->sg, sg, channel->nents, i) {
			cpu_addr_cur = sg_dma_address(sg);
			count_cur = sg_dma_len(sg);

			if (!i)
				cpu_dma_addr = cpu_addr_cur;

			if (cpu_dma_addr + count == cpu_addr_cur)
				count += count_cur;
			else {
				ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(count) << 8));
				ndl = NEXT_DESC_LOWER32(channel->desc_device_va,
								desc_number) | 0x12;
				ndu = NEXT_DESC_UPPER32(channel->desc_device_va,
								desc_number);
				switch (channel->direction) {
				case DMA_H2D:
					FILL_DESC(channel->task->desc_buf, ctrl, ndl, ndu,
							cpu_dma_addr, ipu_ram_dma_addr, desc_offset);
					break;
				case DMA_D2H:
					FILL_DESC(channel->task->desc_buf, ctrl, ndl, ndu,
							ipu_ram_dma_addr, cpu_dma_addr, desc_offset);
					break;

				default:
					cn_dev_pcie_err(channel->pcie_set,
							"only DMA_H2D or DMA_D2H or DMA_P2P transfer mode");
					return -1;
				}
				desc_offset += DESC_SIZE;
				desc_number++;
				ipu_ram_dma_addr += count;
				cpu_dma_addr = cpu_addr_cur;
				count = count_cur;
			}
		}
		/*The TAIL One*/
		ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(count) << 8));
		ndl = 0x3;
		ndu = 0x0;
		switch (channel->direction) {
		case DMA_H2D:
			FILL_DESC(channel->task->desc_buf, ctrl, ndl, ndu,
					cpu_dma_addr, ipu_ram_dma_addr, desc_offset);
			break;
		case DMA_D2H:
			FILL_DESC(channel->task->desc_buf, ctrl, ndl, ndu,
					ipu_ram_dma_addr, cpu_dma_addr, desc_offset);
			break;

		default:
			cn_dev_pcie_err(channel->pcie_set,
					"only DMA_H2D or DMA_D2H or DMA_P2P transfer mode");
			return -1;
		}
		desc_offset += DESC_SIZE;
		desc_number++;
	} else {
		/*P2P all used BAR and is natual phy-continus*/
		cpu_dma_addr = channel->cpu_addr;
		count = channel->transfer_length;

		ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(count) << 8));
		ndl = 0x3;
		ndu = 0x0;
		FILL_DESC(channel->task->desc_buf, ctrl, ndl, ndu,
			ipu_ram_dma_addr, cpu_dma_addr, desc_offset);
		desc_offset += DESC_SIZE;
		desc_number++;
	}

	channel->desc_len = desc_offset;
	memcpy_toio(channel->desc_virt_base, channel->task->desc_buf, desc_offset);
	return 0;
}

/*
	Show these description memory belong to channel.
 */
static void OVER_WRITE(pcie_show_desc_list)(struct dma_channel_info *channel)
{
#if defined(__x86_64__)
	int desc_offset = 0;

	cn_dev_pcie_err(channel->pcie_set, "transfer_len:%ld desc_len:%d",
		channel->transfer_length, channel->desc_len);

	cn_dev_pcie_err(channel->pcie_set, "<Word> DESC_STATUS;DESC_CONTROL;DESC_NEXT_ADDR_d;DESC_SRC_ADDR_d;DESC_DESt_ADDR_d");
	for (; desc_offset < channel->desc_len; desc_offset += DESC_SIZE) {
		cn_dev_pcie_err(channel->pcie_set,
			"%#llx-%#llx [ %#08x, %#08x, %#08x %#08x, %#08x %#08x, %#08x %#08x ]\n",
			(unsigned long long)(channel->desc_virt_base + desc_offset),
			(unsigned long long)(channel->desc_device_va + desc_offset),
			ioread32(channel->desc_virt_base + desc_offset + 0),
			ioread32(channel->desc_virt_base + desc_offset + 4),
			ioread32(channel->desc_virt_base + desc_offset + 8),
			ioread32(channel->desc_virt_base + desc_offset + 12),
			ioread32(channel->desc_virt_base + desc_offset + 16),
			ioread32(channel->desc_virt_base + desc_offset + 20),
			ioread32(channel->desc_virt_base + desc_offset + 24),
			ioread32(channel->desc_virt_base + desc_offset + 28));
	}
#endif
}

/*
 * The table is used for debug regs dump, very important for us
 * WARNING: different platform have different reg base,
 * we need check every regs carefully with hardware enginer, do not just copy
 */
#define CHNL_REG_OFFSET  1
#define CHNL_REG_LENGTH  11
static struct pcie_dump_reg_s pigeon_reg[] = {
		{"PCIE DMA int status", DI_BASE + 0x4},
		{"PCIE DMA chn0 ctrl", DBO},
		{NULL, DBO + 0x4}, {NULL, DBO + 0x8},
		{NULL, DBO + 0xC}, {NULL, DBO + 0x10},
		{NULL, DBO + 0x14}, {NULL, DBO + 0x18},
		{NULL, DBO + 0x1C}, {NULL, DBO + 0x20},
		{NULL, DBO + 0x24}, {NULL, DBO + 0x28},

		{"PCIE DMA chn1 ctrl", DBO + 0x40},
		{NULL, DBO + 0x40 + 0x4}, {NULL, DBO + 0x40 + 0x8},
		{NULL, DBO + 0x40 + 0xC}, {NULL, DBO + 0x40 + 0x10},
		{NULL, DBO + 0x40 + 0x14}, {NULL, DBO + 0x40 + 0x18},
		{NULL, DBO + 0x40 + 0x1C}, {NULL, DBO + 0x40 + 0x20},
		{NULL, DBO + 0x40 + 0x24}, {NULL, DBO + 0x40 + 0x28},

		{"PCIE GIC mask", GIC_MASK},
		{NULL, GIC_MASK + 0x04},
		{NULL, GIC_MASK + 0x08}, {NULL, GIC_MASK + 0x0C},
		{NULL, GIC_MASK + 0x10}, {NULL, GIC_MASK + 0x14},
		{NULL, GIC_MASK + 0x18}, {NULL, GIC_MASK + 0x1C},
		{NULL, GIC_MASK + 0x20}, {NULL, GIC_MASK + 0x24},
		{NULL, GIC_MASK + 0x28}, {NULL, GIC_MASK + 0x2C},
		{NULL, GIC_MASK + 0x30}, {NULL, GIC_MASK + 0x34},
		{NULL, GIC_MASK + 0x38}, {NULL, GIC_MASK + 0x3C},

		{"PCIE GIC status", GIC_STATUS},
		{NULL, GIC_STATUS + 0x04},
		{NULL, GIC_STATUS + 0x08}, {NULL, GIC_STATUS + 0x0C},
		{NULL, GIC_STATUS + 0x10}, {NULL, GIC_STATUS + 0x14},
		{NULL, GIC_STATUS + 0x18}, {NULL, GIC_STATUS + 0x1C},
		{NULL, GIC_STATUS + 0x20}, {NULL, GIC_STATUS + 0x24},
		{NULL, GIC_STATUS + 0x28}, {NULL, GIC_STATUS + 0x2C},
		{NULL, GIC_STATUS + 0x30}, {NULL, GIC_STATUS + 0x34},
		{NULL, GIC_STATUS + 0x38}, {NULL, GIC_STATUS + 0x3C},
};

static void OVER_WRITE(pcie_dump_reg)(struct cn_pcie_set *pcie_set)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pigeon_reg); i++) {
		if (pigeon_reg[i].desc)
			cn_dev_pcie_err(pcie_set, "%s:", pigeon_reg[i].desc);
		cn_dev_pcie_err(pcie_set, "[0x%lx]=%#08x", pigeon_reg[i].reg,
		cn_pci_reg_read32(pcie_set, pigeon_reg[i].reg));
	}
}

/*
 * no bug like c20l, we just do dummy_mb with a readback
 */
static void OVER_WRITE(pcie_dummy_mb)(struct cn_pcie_set *pcie_set)
{
	/* barrir */
	smp_mb();
	cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
}

/*
 * BAR4 have 8MB pcie space for normal use, Exp, P2P and so on.
 * BAR4 have 1 sliding windows
 */
static int OVER_WRITE(pcie_enable_pf_bar)(struct cn_pcie_set *pcie_set)
{
	int index;
	u64 base, sz;
	struct bar_resource bar, *new;
	struct pci_dev *pdev = pcie_set->pdev;
	int begin = 4;

	/***
	 * For pigeon:
	 *	Bar0 is in "pcie_set->pcibar[0]"
	 *	Bar2 is in "pcie_set->pcibar[1]"
	 *	Bar4 is in "pcie_set->bar_resource_head"
	 */
	for (index = begin; index < 6; index++) {
		sz = pci_resource_len(pdev, index);
		if (!sz)
			continue;

		base = pci_resource_start(pdev, index);

		memset(&bar, 0, sizeof(bar));
		bar.type = PF_BAR;
		bar.index = index;
		bar.phy_base = base; /*BAR HOST PA*/
		/*
		 *Bus Base Is BAR's base In PCIe Zone USED in P2P and so on.
		 * 1. BAR PCIe Bus Base-used by module whose view is in pcie zone, EXP, pcieDMA.
		 * 2. BAR HOST PA/VA   -used by module whose view is in host zone, EXP, hostCPU.
		 */
		bar.bus_base = cn_pci_bus_address(pdev, index); /*BAR Bus Addr*/
		bar.size = sz;
		bar.reg_index = pf_table[index / 2 - 1].reg; /*sliding window target register*/
		bar.reg_mask = pf_table[index / 2 - 1].mask; /*sliding window mask size register*/
		bar.smmu_in = index / 2 * 2;
		bar.smmu_out = index / 2 * 2 - 1;

		/*copy bar to new and get BAR HOST VA*/
		new = pcie_bar_resource_struct_init(&bar);
		if (new == NULL)
			return -1;

		cn_dev_pcie_info(pcie_set,
			"Bar %d : PhyBase 0x%llX  VirtBase 0x%lX BusBase 0x%llX RedIndex 0x%llX RegMask 0x%llX",
				new->index, new->phy_base, (unsigned long)new->base,
				new->bus_base, new->reg_index, new->reg_mask);

		list_add_tail(&new->list, &pcie_set->bar_resource_head);

		/*BAR4 default based on 0x0000_0000*/
		cn_pci_reg_write64(pcie_set, bar.reg_index, bar.reg_mask);
		cn_pci_reg_read64(pcie_set, bar.reg_index);
	}
	return 0;
}

/*
	Read/Write32  & Read/Write64 Based on BAR0 and its win0 if needed.
 */
static int pcie_set_bar0_window(u64 axi_addr, unsigned long *offset,
						struct cn_pcie_set *pcie_set)
{
	int need_sliding = 0;
	unsigned long win_base;
	unsigned long taret_axi;
	struct pigeon_bar0_set *bar0_set = NULL;
	int win_index = 0;

	bar0_set = (struct pigeon_bar0_set *)pcie_set->priv_set;
	*offset = axi_addr & (~((unsigned long)BAR0_FIXED_TOP_SIZE_MASK));

	cn_dev_pcie_debug(pcie_set, "axi_addr = %#llx -----> offset = %#lx.", axi_addr, *offset);
	if (*offset) {
		win_base = bar0_set->bar0_window_base;
		cn_dev_pcie_debug(pcie_set,
			"Register access beyond 8M, maybe meed sliding win0. OffBase=%#lx", win_base);
		if (*offset > (win_base + BAR0_WIN0_SIZE_MASK)) {
			win_base = *offset & (~((unsigned long)BAR0_WIN0_SIZE_MASK));
			taret_axi = (0x80 << 24) | win_base;
			cn_dev_pcie_debug(pcie_set, "Sliding to %#lx", win_base);
			need_sliding = 1;
			if (!down_killable(&bar0_set->bar0_window_sem)) {
				cn_pci_reg_write64(pcie_set, BAR0_TO_AXI_TGT_WIN(win_index), win_base);
				cn_pci_reg_read32(pcie_set, BAR0_TO_AXI_TGT_WIN(win_index));
				bar0_set->bar0_window_flag = 1;
				bar0_set->bar0_window_base = win_base;
			} else {
				*offset = RESERVED_REG; /*Safe reserved register*/
				cn_dev_pcie_err(pcie_set, "Bar0 win0 get semaphore error.");
				return need_sliding;
			}
		} else {
			cn_dev_pcie_debug(pcie_set, "No Sliding.");
		}
		*offset = BAR0_FIXED_TOP_SIZE + (axi_addr & BAR0_WIN0_SIZE_MASK);
	} else {
		cn_dev_pcie_debug(pcie_set, "Register belong to fixed 8M.");
		*offset = axi_addr;
	}
	cn_dev_pcie_debug(pcie_set, "offset = %#lx", *offset);

	return need_sliding;
}

static u32 OVER_WRITE(pcie_reg_read32)(u64 axi_addr, struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	u32 data;
	struct pigeon_bar0_set *bar0_set = NULL;

	bar0_set = (struct pigeon_bar0_set *)pcie_set->priv_set;
	pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag) {
		data = ioread32(pcie_set->reg_virt_base + offset);
		bar0_set->bar0_window_flag = 0;
		up(&bar0_set->bar0_window_sem);
	} else {
		data = ioread32(pcie_set->reg_virt_base + offset);
	}

	return data;
}

static void OVER_WRITE(pcie_reg_write32)(u64 axi_addr, u32 data,
						struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	struct pigeon_bar0_set *bar0_set = NULL;

	bar0_set = (struct pigeon_bar0_set *)pcie_set->priv_set;
	pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag) {
		iowrite32(data, pcie_set->reg_virt_base + offset);
		bar0_set->bar0_window_flag = 0;
		up(&bar0_set->bar0_window_sem);
	} else
		iowrite32(data, pcie_set->reg_virt_base + offset);
}

static u64 OVER_WRITE(pcie_reg_read64)(u64 axi_addr, struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	u64 data;
	struct pigeon_bar0_set *bar0_set = NULL;

	bar0_set = (struct pigeon_bar0_set *)pcie_set->priv_set;
	pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag) {
		data = ioread32(pcie_set->reg_virt_base + offset + 4);
		data <<= 32;
		data |= ioread32(pcie_set->reg_virt_base + offset);
		bar0_set->bar0_window_flag = 0;
		up(&bar0_set->bar0_window_sem);
	} else {
		data = ioread32(pcie_set->reg_virt_base + offset + 4);
		data <<= 32;
		data |= ioread32(pcie_set->reg_virt_base + offset);
	}

	return data;
}

static void OVER_WRITE(pcie_reg_write64)(u64 axi_addr, u64 data,
						struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	struct pigeon_bar0_set *bar0_set = NULL;

	bar0_set = (struct pigeon_bar0_set *)pcie_set->priv_set;

	pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag) {
		iowrite32(LOWER32(data), pcie_set->reg_virt_base + offset);
		iowrite32(UPPER32(data), pcie_set->reg_virt_base + offset + 4);
		bar0_set->bar0_window_flag = 0;
		up(&bar0_set->bar0_window_sem);
	} else {
		iowrite32(LOWER32(data), pcie_set->reg_virt_base + offset);
		iowrite32(UPPER32(data), pcie_set->reg_virt_base + offset + 4);
	}
}

#if (RESET_SEL == LINKD_RST)
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
	cn_dev_pcie_info(pcie_set, "linkdonw reset...");
	cn_pci_link_set(pcie_set, false);
	msleep(100);
	cn_pci_link_set(pcie_set, true);

	return 0;
}
#define real_soft_reset  OVER_WRITE(pcie_linkdown_reset)

#elif (RESET_SEL == FUNC_RST)
static int OVER_WRITE(pcie_func_level_reset)(struct cn_pcie_set *pcie_set)
{
	int ret;

	cn_dev_pcie_info(pcie_set, "function level reset...");
	ret = pci_reset_function(pcie_set->pdev);
	if (ret) {
		cn_dev_pcie_info(pcie_set,
			"this device does not support to reset a single func");
		return -1;
	}

	return 0;
}
#define real_soft_reset  OVER_WRITE(pcie_func_level_reset)

#elif (RESET_SEL == HOT_RST)
static int OVER_WRITE(pcie_hot_reset)(struct cn_pcie_set *pcie_set)
{
	cn_dev_pcie_info(pcie_set, "hot reset...");
	pci_reset_bridge_secondary_bus(pcie_set->pdev->bus->self);

	return 0;
}
#define real_soft_reset  OVER_WRITE(pcie_hot_reset)

#endif

/*
 * It will keep polling flag for longlonglong time until break!
 */
static int OVER_WRITE(pcie_ddr_set_done)(struct cn_pcie_set *pcie_set)
{
	u32 val, cnt = 120;

	val = cn_pci_reg_read32(pcie_set, MCU_BASIC_INFO);

	while (!((val >> MCU_DDRTRAINED_FLAG_SHIFT)
				& MCU_DDRTRAINED_FLAG_MASK)) {
		cn_dev_pcie_info(pcie_set, "DDR Training Params set ......");
		mdelay(500);
		val = cn_pci_reg_read32(pcie_set, MCU_BASIC_INFO);
		if (cnt-- == 0) {
			cn_dev_pcie_info(pcie_set, "DDR Training Params set by MCU timeout");
			return -1;
		}
	}
	cn_dev_pcie_info(pcie_set, "DDR Training Params set by MCU Finish");
	return 0;
}


extern int _normal_pcie_bar_read(unsigned long host_addr, u64 device_addr, size_t count,
				struct cn_pcie_set *pcie_set);
static int OVER_WRITE(pcie_bar_read)(unsigned long host_addr, u64 device_addr, size_t count,
				struct cn_pcie_set *pcie_set)
{
	return _normal_pcie_bar_read(host_addr, device_addr, count, pcie_set);
}
/*
 *********************************************
	Private OPS for pcie_set.ops
 *********************************************
 */
static struct cn_pci_ops pigeon_private_ops = {
	.dump_reg = OVER_WRITE(pcie_dump_reg),
	.fill_desc_list = OVER_WRITE(pcie_fill_desc_list),
	.show_desc_list = OVER_WRITE(pcie_show_desc_list),
	.pci_mb = OVER_WRITE(pcie_dummy_mb),
	.enable_pf_bar = OVER_WRITE(pcie_enable_pf_bar),
	.reg_read32 = OVER_WRITE(pcie_reg_read32),
	.reg_write32 = OVER_WRITE(pcie_reg_write32),
	.reg_read64 = OVER_WRITE(pcie_reg_read64),
	.reg_write64 = OVER_WRITE(pcie_reg_write64),
	.ddr_set_done = OVER_WRITE(pcie_ddr_set_done),
	.bar_read = OVER_WRITE(pcie_bar_read),
	.soft_reset = real_soft_reset,

};

static int pcie_dma_interrupt_init(struct cn_pcie_set *pcie_set)
{
	int i;
	char src[30];
	static const int interrupt_count[] = {MSI_COUNT, MSIX_COUNT, INTX_COUNT};

	pcie_set->irq_num = interrupt_count[pcie_set->irq_type];
	pcie_gic_mask_all(pcie_set);

	/* fix msix ram bug by writing msix ram */
	if (pcie_set->irq_type == MSIX)
		fill_msix_ram(pcie_set);

	/*
	 * int Top Handler entrance to system bases on user parametert 'isr_type_index'
	 * And this will alloc some vector from Host IRQ Domain: Top EP INT CONTROL REGISTER
		1. cn_pci_msi_enable
		2. cn_pci_msix_enable
		3. cn_pci_intx_enable
	 */
	if (isr_enable_func[pcie_set->irq_type](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr init failed!");
		return -1;
	}

	/* Disable all Interrupts */
	pcie_gic_mask_all(pcie_set);

	/* irq_str_index is the recording about PCIeDMA Sub Irq Number */
	pcie_set->irq_str_index_ptr = irq_str_index;
	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		cn_dev_pcie_debug(pcie_set, "Try register dma interrupt %d", i);
		if (pcie_set->dma_phy_channel_mask & (1 << i)) {
			sprintf(src, "pcie_dma%d", i);
			cn_pci_register_interrupt(
					pcie_get_irq(src, pcie_set),
					pcie_dma_interrupt_handle, pcie_set, pcie_set);
		}
	}

	return 0;
}

static void pigeon_set_bar_default_window(struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar;

	list_for_each_entry(bar, &pcie_set->bar_resource_head, list) {
		cn_dev_pcie_info(pcie_set,
			"Tranverse [bar_resource_head] set default BAR_%d Window", bar->index);
		bar->window_addr = 0;
		cn_pci_reg_write64(pcie_set, bar->reg_index, bar->reg_mask);
		cn_pci_reg_read32(pcie_set, bar->reg_index);
	}
}

static int pcie_pre_init_hw(struct cn_pcie_set *pcie_set)
{
	int i;

	pcie_outbound_reg(pcie_set);

	pigeon_set_bar_default_window(pcie_set);

	/***
	 * Write the EP GIC Top Register
	 */
	isr_hw_enable[pcie_set->irq_type](pcie_set);

	pcie_gic_mask_all(pcie_set);

	/***
	 * The IRQ is banding in continous order.
	 */
	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_phy_channel_mask & (1 << i)) {
			pcie_gic_unmask(PCIE_IRQ_DMA + i, pcie_set);
		}
	}
	/***
	 *Only DMA0/1 is default setting.
	 *	Golden mask will be the finnal used to init.
	 */
	cn_pci_reg_write32(pcie_set, DIMASK_LOCAL, pcie_set->dma_phy_channel_mask);
	cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);

	return 0;
}

static int pigeon_pcie_setup(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/*
	 *  publish ops to uper level
	 *  different cambricon ID have different ops
	 *  same cambricon ID with different wafer, change ops here
	 */
	cn_pci_ops_init(&public_ops, &pigeon_private_ops);
	pcie_set->ops = &pigeon_private_ops;

	/* for domain manger get hard resource */
	pcie_set->max_phy_channel = HOST_PHY_CHANNEL_NUM;

	/* set fetch depth and for pigeon is 1 means not support fetch */
	pcie_set->dma_fetch_buff = 1;

	/* soft status */
	pcie_set->share_mem_cnt = 0;

	/* Set the irq type */
	if (isr_type_index == -1) {
		pcie_set->irq_type = isr_default_type;
	} else {
		pcie_set->irq_type = isr_type_index;
	}

	return 0;
}

/*
	If narrow_gen = 0, not any real Gen, means to find the narrowest_gen.
	Otherwise, to check wether has Gen that LessEqual than narrow_gen.
	If find out 'narrowest_gen', then return it or 0 when not.
	Otherwise return 'narrow_gen' when find out LessEqual or 0 when not.

				RETRUN
			    /-----  0 : Not Found that Less than devSelf.
	narrow_gen=0 -->   |     GenX : the narrowest Then set dev as 'narrowest'.
			   |       -1 : Meet error.
			   #
			   |       -1 : Meet error.
	narrow_gen!=0-->   |	 GenX : the first found lessEqual than Setting
			   |            Then set dev as Setting.
			    \-----  0 : Not Found which LessEqual than Setting.
*/
__attribute__((unused))
static int walkthrough_rc_for_lower_genX(struct cn_pcie_set *pcie_set, int narrow_gen)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_bus *bus;
	u16 status, speed;
	int ret_gen = 0;
	int dev_self_gen = 0;
	int narrowest_gen = 0;

	if (!narrow_gen) {
		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &status);
		dev_self_gen = status & PCI_EXP_LNKSTA_CLS;
		narrowest_gen = dev_self_gen;
		cn_dev_pcie_debug(pcie_set, "Init dev self gen as 0x%02x : %s\n",
						 dev_self_gen, PCIE_SPEED_STR(dev_self_gen));
	}
	for (bus = pdev->bus; !pci_is_root_bus(bus); bus = bus->parent) {
		pdev = bus->self;
		if (!pdev) {
			cn_dev_pcie_info(pcie_set, "pdev is null\n");
			return -1;
		}

		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &status);
		speed = status & PCI_EXP_LNKSTA_CLS;

		if (!narrow_gen) {
			cn_dev_pcie_debug(pcie_set, "Try find narrowest ...\n");
			if (speed < narrowest_gen) {
				cn_dev_pcie_debug(pcie_set, "Update narrowest_gen\n");
				narrowest_gen = speed;
			}
		} else {
			cn_dev_pcie_debug(pcie_set, "Try find  LessEqual ...\n");
			if (speed <= narrow_gen) {
				cn_dev_pcie_debug(pcie_set, "pcie bus:%x:%x:%x speed is %s. Mark LessEqual.\n",
						pdev->bus->number, pdev->devfn >> 3,
						pdev->devfn & 0x7, PCIE_SPEED_STR(speed));
				ret_gen = speed;
				cn_dev_pcie_debug(pcie_set, "The first LessEqual is 0x%02x :%s.\n",
						 ret_gen, PCIE_SPEED_STR(speed));
				break;
			}
		}
	}
	if (!narrow_gen && (narrowest_gen != dev_self_gen)) {
		ret_gen = narrowest_gen;
		cn_dev_pcie_debug(pcie_set, "The narrowest_gen is 0x%02x :%s.\n",
						 ret_gen, PCIE_SPEED_STR(narrowest_gen));
	}

	cn_dev_pcie_debug(pcie_set, "ret_gen is 0x%02x : %s\n", ret_gen,
						PCIE_SPEED_STR(ret_gen));
	if (!ret_gen) {
		cn_dev_pcie_info(pcie_set, "Unknown means not find any lower gen and will do nothing.\n");
	}

	return ret_gen;
}

static int pigeon_pcie_domain_get_resource(void *pcie, struct domain_resource *resource)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/*For BAR0 for register & BAR2 for shared memory*/
	resource->id = pcie_set->id;
	resource->max_phy_channel = HOST_PHY_CHANNEL_NUM;
	resource->cfg_reg_size = pcie_set->pcibar[0].size;
	resource->share_mem_size = pcie_set->pcibar[2].size;
	resource->vf_cfg_limit = 16 * 1024;

	return 0;
}

static void plx_switch_drop_poisoned_tlp(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_bus *bus = pdev->bus;
	int i;
	u16 status;

#define PLX_UPSTREAM_SLOT (4)
#define PLX_INGRESS_CONTROL (0xf60)
#define PLX_DROP_POISONED_BIT (0x1 << 9)

	for (i = 0; i < PLX_UPSTREAM_SLOT; i++, bus = bus->parent) {
		if (bus == NULL)
			return;

		pdev = bus->self;
		if (!pdev) {
			cn_dev_pcie_info(pcie_set, "pdev is null\n");
			return;
		}
	}

	pci_read_config_word(pdev, PLX_INGRESS_CONTROL, &status);
	cn_dev_pcie_info(pcie_set,
		"plx upstream slot %x:%x:%x, reg[0x%x]:%x",
			pdev->bus->number, pdev->devfn >> 3, pdev->devfn & 0x7,
			PLX_INGRESS_CONTROL, status);

	/* already set 1 */
	if ((status & PLX_DROP_POISONED_BIT) != 0)
		return;

	status |= PLX_DROP_POISONED_BIT;
	pci_write_config_dword(pdev, PLX_INGRESS_CONTROL, status);
}

static int pigeon_bug_fix_list(struct cn_pcie_set *pcie_set)
{
	cn_dev_pcie_info(pcie_set, "Try fix bug via write regiser.");

	/* private bug list
	 * FW : LEOP-4040  LEPU-115
	 * SW : DRIVER-10561
	 * Note:
	 *	The leopard has special function design which can collect slv-error when do D2H.
	 *	and turn it to OK, and then send INT to Host with related information.
	 *	Via this, EP can bypass "send poision TLP" which will affect others master
	 *	who is work well currently, and on other side, it will lead HOST system killed-self.
	 */
	cn_dev_pcie_info(pcie_set,  "pigeon private bug to fix to reject poision TLP.");
	//TODO ADD HERE
	/*
	 * Same with MLU370 X8
	 * PLX switch drop poisoned TLP
	 */
	plx_switch_drop_poisoned_tlp(pcie_set);


	/* public bug list */
	bug_fix_list(pcie_set);

	return 0;
}

/*
 * BAR0 have 16MB pcie space for regiter area
 *			recording into pcie_set->pcibar[0]
 * BAR0 have 5 sliding windows
 * [   #  ]< 0 >< 1 >< 2 >< 3 >< 4 >
 * # : default fixed 8M
 * 0 : 8M ~ 16M Default Setting
 * 1 : Dumy
 * 2 : Dumy
 * 3 : Dumy
 * 4 : Dumy
 */
static int pigeon_pcie_reg_area_init(struct cn_pcie_set *pcie_set)
{
	struct pcibar_seg_s *bar_seg;
	struct pcibar_s *bar = &pcie_set->pcibar[0];
	struct pigeon_priv_set *p_set = NULL;
	struct pigeon_bar0_set *bar0_set = NULL;

	/***
	 *cndrv_pci.c probe will init pcibar0.seg[0]
	 *This "bar0.seg0" is used as 'register access'.
	 *For PIGEON, the seg[0] cover the whole bar0.
	 */
	bar_seg = &bar->seg[0];
	bar_seg->size = bar->size;
	bar_seg->base = bar->base; /*BAR0 HOST PA*/
	bar_seg->virt = cn_ioremap(bar_seg->base, bar_seg->size); /*BAR0 HOST VA*/
	if (!bar_seg->virt)
		return -1;

	pcie_set->reg_virt_base = bar_seg->virt; /*BAR0 HOST VA*/
	pcie_set->reg_phy_addr = bar_seg->base;  /*BAR0 HOST PA*/
	pcie_set->reg_win_length = bar_seg->size;
	cn_dev_pcie_info(pcie_set, "Bar0_seg[0] Use the whole Bar0.");
	cn_dev_pcie_info(pcie_set, "Bar base  0x%llX -> virt 0x%llX : Length=0x%llX",
		bar->base, (long long unsigned)bar_seg->virt, bar_seg->size);

	/*Bar0 winX control*/
	if (pcie_set->priv_set) {
		p_set = (struct pigeon_priv_set *)pcie_set->priv_set;
		bar0_set = &p_set->bar0_set;
		sema_init(&bar0_set->bar0_window_sem, 1); /*The bar0 window only support one caller once time*/
		bar0_set->bar0_window_base = BAR0_FIXED_TOP_SIZE; /*Default setting Base locate 8M*/
	}

	return 0;
}

/*
 * BAR2 have 8MB pcie space for share memory
 *			recording into pcie_set->pcibar[2]
 * BAR2 have 1 sliding windows
 */
static int pigeon_pcie_shm_area_init(struct cn_pcie_set *pcie_set)
{
	struct pcibar_seg_s *bar_seg;
	struct pcibar_s *bar;
	struct pci_dev *pdev = pcie_set->pdev;
	int index = 2;
	u64 sz, axi_address;

	cn_dev_pcie_info(pcie_set, "Share memory use the whole BAR2");
	sz = pci_resource_len(pdev, index);
	if (!sz) {
		cn_dev_pcie_err(pcie_set, "no enough MMIO space for PF bar%d", index);
		return -1;
	}
	pcie_set->pcibar[index].base = pci_resource_start(pdev, index);
	pcie_set->pcibar[index].size = sz;

	bar = &pcie_set->pcibar[index];
	bar_seg = &bar->seg[0];
	bar_seg->base = bar->base; /*BAR2 HOST PA*/
	bar_seg->size = bar->size; /*BAR2 HOST Size*/

	bar_seg->virt = cn_ioremap_wc(bar_seg->base, bar_seg->size);
	if (!bar_seg->virt)
		return -1;

	pcie_set->share_mem_cnt = 1;
	pcie_set->share_mem[0].virt_addr = bar_seg->virt; /*BAR2 HOST VA*/
	pcie_set->share_mem[0].phy_addr = bar_seg->base;  /*BAR2 HOST PA*/
	pcie_set->share_mem[0].win_length = bar_seg->size;
	pcie_set->share_mem[0].type = CN_SHARE_MEM_DEV;
	pcie_set->share_mem[0].device_addr = PIGEON_AXI_SHM_BASE;

	cn_dev_pcie_info(pcie_set, "share memory virt:%#llX, phy:%#llX, size:%#llX",
			(u64)bar_seg->virt, bar_seg->base, bar_seg->size);

	cn_dev_pcie_info(pcie_set, "Init Bar2 Window for shared memory via write register.");
	axi_address = PIGEON_AXI_SHM_BASE;
	axi_address &= (~(u64)(bar_seg->size - 1));

	cn_dev_pcie_info(pcie_set, "Shared Memory Base = %#llx", (unsigned long long)PIGEON_AXI_SHM_BASE);
	cn_dev_pcie_info(pcie_set, "PIGEON_AXI_SHM_BASE %#llX will be write into BAR2 Target register",
			(unsigned long long)PIGEON_AXI_SHM_BASE);
	cn_pci_reg_write64(pcie_set, BAR2_TO_AXI_ADDR_REG_L, axi_address);
	cn_pci_reg_read32(pcie_set, BAR2_TO_AXI_ADDR_REG_L);

	return 0;
}

static int pigeon_pcie_dma_pre_init(struct cn_pcie_set *pcie_set)
{
	pcie_set->dma_phy_channel_mask = HOST_PHY_CHANNEL_MASK;
	pcie_set->shared_desc_total_size = SHARED_DMA_DESC_TOTAL_SIZE;
	pcie_set->priv_desc_total_size = PRIV_DMA_DESC_TOTAL_SIZE;
	pcie_set->dma_buffer_size = DMA_BUFFER_SIZE;
	pcie_set->per_desc_size = DMA_DESC_PER_SIZE;

	return 0;
}

static int pigeon_pcie_priv_set_alloc(struct cn_pcie_set *pcie_set)
{
	struct pigeon_priv_set *p_set = NULL;

	p_set = cn_kzalloc(sizeof(struct pigeon_priv_set), GFP_KERNEL);

	if (!p_set) {
		cn_dev_pcie_err(pcie_set, "kzalloc priv_set error.");
		return -ENOMEM;
	}

	pcie_set->priv_set = p_set;

	return 0;
}

static int pigeon_check_noc_bus(struct cn_pcie_set *pcie_set)
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

static int pigeon_pcie_pre_init(void *pcie)
{
	int ret = 0;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	ret = pigeon_pcie_priv_set_alloc(pcie_set);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "alloc priv_set error.");
		return -1;
	}
	cn_dev_pcie_debug(pcie_set, "SW init and cn_ioremap BAR0 for register handle above BUS.");
	ret = pigeon_pcie_reg_area_init(pcie_set); /*pcie_set->pcibar[0]*/
	if (ret) {
		cn_dev_pcie_err(pcie_set, "Init for Bar0 error.");
		return -1;
	}

	if (pigeon_check_noc_bus(pcie_set))
		goto exit;

	cn_dev_pcie_debug(pcie_set, "HW Init DDR by Host Driver replacing MCU.");
	pigeon_memory_and_d2d_init(pcie);

	cn_dev_pcie_debug(pcie_set, "HW Fix some HW Bug via register.");
	if (pigeon_bug_fix_list(pcie_set))
		goto exit;

	cn_dev_pcie_debug(pcie_set, "SW Init shared memory in devices Based on BAR2 Fixed.");
	ret = pigeon_pcie_shm_area_init(pcie_set); /*pcie_set->pcibar[1]*/
	if (ret)
		goto exit;
	cn_dev_pcie_debug(pcie_set, "SW For these common uses about BAR4: P2P and so on.");
	ret = pcie_register_bar(pcie_set); /*pcie_set->bar_resource_head. Only BAR4.*/
	if (ret)
		goto exit;

	cn_dev_pcie_debug(pcie_set, "SW DMA capability recording.");
	ret = pigeon_pcie_dma_pre_init(pcie_set);
	if (ret)
		goto exit;

	cn_dev_pcie_debug(pcie_set, "SW OB capability recording.");
	outbound_pre_init(pcie_set);

	cn_dev_pcie_debug(pcie_set, "HW to call do_pcie_init for some hard ware function.");
	ret = do_pcie_init(pcie_set);
	if (ret)
		goto exit;

	cn_dev_pcie_debug(pcie_set, "PCIe init self over and ready call other module init via core probe\n.");

	return 0;
exit:
	bar_deinit(pcie_set);
	return -1;
}

static int pigeon_pcie_pre_exit(void *pcie)
{
	return 0;
}

struct cn_pci_info pigeon_pci_info = {
	.setup = pigeon_pcie_setup,
	.pre_init = pigeon_pcie_pre_init,
	.pre_exit = pigeon_pcie_pre_exit,
	.get_resource = pigeon_pcie_domain_get_resource,
	.dev_name = "pigeon"
};
