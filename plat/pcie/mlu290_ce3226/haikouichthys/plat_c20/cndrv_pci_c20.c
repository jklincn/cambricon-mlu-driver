/************************************************************************
 *
 *  @file cndrv_pci_c20.c
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

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/dmi.h>
#include <linux/vmalloc.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "../../pcie_dma.h"
#include "../../pcie_bar.h"
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_pci_c20.h"
#include "cndrv_debug.h"

#define DMA_SMMU_STREAM_ID      37

static int cambr_rc_timeout_max_enable = 0;
module_param_named(rc_timeout_max_en, cambr_rc_timeout_max_enable, int, S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(rc_timeout_max_en, "Set PCIe completion timeout to max value when loading kernel module");

#if (GIC_INTERRUPT_NUM != MSIX_COUNT)
const static int irq_msix_gic_end[16] = {
	0, 1, 2, 3, 4, 5, 6, 7, 37, 117,
	145, 185, 189, 200, 238, 255};
#endif

#if (MSI_COUNT == 1)
const static int irq_msi_gic_end[1] = {255};
#elif (MSI_COUNT == 2)
const static int irq_msi_gic_end[2] = {127, 255};
#elif (MSI_COUNT == 4)
const static int irq_msi_gic_end[4] = {63, 127, 191, 255};
#elif (MSI_COUNT == 8)
const static int irq_msi_gic_end[8] = {31, 63, 95, 127, 159, 191, 223, 255};
#elif (MSI_COUNT == 16)
const static int irq_msi_gic_end[16] = {
	15,   31,  47,  63,  79,  95, 111,  127,
	143, 159, 175, 191, 207, 223, 239, 255};
#elif (MSI_COUNT == 32)
const static int irq_msi_gic_end[32] = {
	7,   15,  23,	31,  39,  47,  55, 63,
	71,  79,  87,	95, 103, 111, 119, 127,
	135, 143, 151, 159, 167, 175, 183, 191,
	199, 207, 215, 223, 231, 239, 247, 255};
#endif

static struct cn_pci_irq_str_index irq_str_index[256] = {
	{0, "pcie_dma0"},
	{1, "pcie_dma1"},
	{2, "pcie_dma2"},
	{3, "pcie_dma3"},
	{4, "pcie_dma4"},
	{5, "pcie_dma5"},
	{6, "pcie_dma6"},
	{7, "pcie_dma7"},
	{8, "pcie_dma_err0"},
	{9, "pcie_dma_err1"},
	{10, "pcie_dma_err2"},
	{11, "pcie_dma_err3"},
	{12, "pcie_dma_err4"},
	{13, "pcie_dma_err5"},
	{14, "pcie_dma_err6"},
	{15, "pcie_dma_err7"},
	{34, "PCIE_IRQ_GIC_ARM2PF"},
	{118, "MAILBOX_INT0"},
};

const static struct {
	u64 reg;
	u64 mask;
} pf_table[] = {
	{BAR2_TO_AXI_ADDR_REG_L, 0x0ULL}, /* pf bar2 */
	{BAR4_TO_AXI_ADDR_REG_L, 0x0ULL}, /* pf bar4 */
};


/*
 *  include public c code
 *  warnning: do not remove it to the top of file
 *            otherwise will have build errors
 */
#include "../../pcie_common.c"
#include "../haikouichthys.h"
#define OVER_WRITE(f) c20_##f

__attribute__((unused))
static void pcie_async_show_desc_list(struct async_task *async_task)
{
	void __iomem *host_desc_addr = (void __iomem *)async_task->host_desc_addr;
	int i, desc_offset = 0;

	for (i = 0; i < async_task->sg_list_nents; i++) {
		pr_err("async dma desc %d: %#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x\n", i,
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

	if (channel->desc_device_va % 64) {
		cn_dev_pcie_err(channel->pcie_set,
				"No 64 Bytes align : desc device vaddr");
		return -1;
	}

	if (channel->direction != DMA_P2P) {
		for_each_sg(channel->sg, sg, channel->nents, i) {
			cpu_addr_cur = sg_dma_address(sg);
			count_cur = sg_dma_len(sg);

			if (!i)
				cpu_dma_addr = cpu_addr_cur;

			if (cpu_dma_addr + count == cpu_addr_cur)
				count += count_cur;
			else {
				if (((cpu_dma_addr & 0x3) != 0) || ((ipu_ram_dma_addr & 0x3) != 0)
						|| ((count & 0x3) != 0)) {
					cn_dev_pcie_err(channel->pcie_set,
							"No 4bit align:cpu_addr:%#lx dev_addr:%#llx count:%lx",
							cpu_dma_addr, ipu_ram_dma_addr, count);
					return -1;
				}

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

		if (((cpu_dma_addr & 0x3) != 0) || ((ipu_ram_dma_addr & 0x3) != 0)
				|| ((count & 0x3) != 0)) {
			cn_dev_pcie_err(channel->pcie_set,
					"No 4bit align:cpu_addr:%#lx dev_addr:%#llx count:%lx",
					cpu_dma_addr, ipu_ram_dma_addr, count);
			return -1;
		}

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
		cpu_dma_addr = channel->cpu_addr;
		count = channel->transfer_length;

		if (((cpu_dma_addr & 0x3) != 0) || ((ipu_ram_dma_addr & 0x3) != 0)
				|| ((count & 0x3) != 0)) {
			cn_dev_pcie_err(channel->pcie_set,
					"No 4bit align:cpu_addr:%#lx dev_addr:%#llx count:%lx",
					cpu_dma_addr, ipu_ram_dma_addr, count);
			return -1;
		}

		ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(count) << 8));
		ndl = 0x3;
		ndu = 0x0;
		FILL_DESC(channel->task->desc_buf, ctrl, ndl, ndu,
			cpu_dma_addr, ipu_ram_dma_addr, desc_offset);
		desc_offset += DESC_SIZE;
		desc_number++;
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
	unsigned long count = 0;
	struct scatterlist *sg;
	int desc_offset = 0;
	int desc_number = 0;
	unsigned int ctrl, ndl, ndu;
	struct transfer_s *t;
	unsigned long cpu_addr_cur;
	unsigned long count_cur;

	t = &async_task->transfer;
	ipu_ram_dma_addr = t->ia;

	for_each_sg(async_task->sg_list, sg, async_task->sg_list_nents, i) {
		cpu_addr_cur = sg_dma_address(sg);
		count_cur = sg_dma_len(sg);

		if (!i)
			cpu_dma_addr = cpu_addr_cur;

		if (cpu_dma_addr + count == cpu_addr_cur)
			count += count_cur;
		else {
			ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(count) << 8));
			ndl = NEXT_DESC_LOWER32(async_task->dev_desc_addr,
							desc_number) | 0x12;
			ndu = NEXT_DESC_UPPER32(async_task->dev_desc_addr,
							desc_number);
			switch (t->direction) {
			case DMA_H2D:
				FILL_DESC(async_task->desc_buf, ctrl, ndl, ndu,
						cpu_dma_addr, ipu_ram_dma_addr, desc_offset);
				break;
			case DMA_D2H:
				FILL_DESC(async_task->desc_buf, ctrl, ndl, ndu,
						ipu_ram_dma_addr, cpu_dma_addr, desc_offset);
				break;
			default:
				cn_dev_pcie_err(async_task->pcie_set,
						"only DMA_H2D or DMA_D2H transfer mode");
				return -1;
			}
			desc_offset += DESC_SIZE;
			desc_number++;
			ipu_ram_dma_addr += count;
			cpu_dma_addr = cpu_addr_cur;
			count = count_cur;
		}
	}

	ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(count) << 8));
	ndl = 0x3;
	ndu = 0x0;
	switch (t->direction) {
	case DMA_H2D:
		FILL_DESC(async_task->desc_buf, ctrl, ndl, ndu,
				cpu_dma_addr, ipu_ram_dma_addr, desc_offset);
		break;
	case DMA_D2H:
		FILL_DESC(async_task->desc_buf, ctrl, ndl, ndu,
				ipu_ram_dma_addr, cpu_dma_addr, desc_offset);
		break;
	default:
		cn_dev_pcie_err(async_task->pcie_set,
				"only DMA_H2D or DMA_D2H transfer mode");
		return -1;
	}
	desc_offset += DESC_SIZE;
	desc_number++;

	async_task->desc_len = desc_offset;
	memcpy_toio((void __iomem *)async_task->host_desc_addr, async_task->desc_buf, desc_offset);
	//pcie_async_show_desc_list(async_task);

	return 0;
}

/*
 * The table is used for debug regs dump, very important for us
 * WARNING: different platform have different reg base,
 * we need check every regs carefully with hardware enginer, do not just copy
 */
static struct pcie_dump_reg_s c20_reg[] = {
		{"PCIE DMA int status", DI_BASE + 0x4},
		{"PCIE status", 0x100004},
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

		{"PCIE DMA chn2 ctrl", DBO + 0x80},
		{NULL, DBO + 0x80 + 0x4}, {NULL, DBO + 0x80 + 0x8},
		{NULL, DBO + 0x80 + 0xC}, {NULL, DBO + 0x80 + 0x10},
		{NULL, DBO + 0x80 + 0x14}, {NULL, DBO + 0x80 + 0x18},
		{NULL, DBO + 0x80 + 0x1C}, {NULL, DBO + 0x80 + 0x20},
		{NULL, DBO + 0x80 + 0x24}, {NULL, DBO + 0x80 + 0x28},

		{"PCIE DMA chn3 ctrl", DBO + 0xC0},
		{NULL, DBO + 0xC0 + 0x4}, {NULL, DBO + 0xC0 + 0x8},
		{NULL, DBO + 0xC0 + 0xC}, {NULL, DBO + 0xC0 + 0x10},
		{NULL, DBO + 0xC0 + 0x14}, {NULL, DBO + 0xC0 + 0x18},
		{NULL, DBO + 0xC0 + 0x1C}, {NULL, DBO + 0xC0 + 0x20},
		{NULL, DBO + 0xC0 + 0x24}, {NULL, DBO + 0xC0 + 0x28},

		{"PCIE DMA chn4 ctrl", DBO + 0x100},
		{NULL, DBO + 0x100 + 0x4}, {NULL, DBO + 0x100 + 0x8},
		{NULL, DBO + 0x100 + 0xC}, {NULL, DBO + 0x100 + 0x10},
		{NULL, DBO + 0x100 + 0x14}, {NULL, DBO + 0x100 + 0x18},
		{NULL, DBO + 0x100 + 0x1C}, {NULL, DBO + 0x100 + 0x20},
		{NULL, DBO + 0x100 + 0x24}, {NULL, DBO + 0x100 + 0x28},

		{"PCIE DMA chn5 ctrl", DBO + 0x140},
		{NULL, DBO + 0x140 + 0x4}, {NULL, DBO + 0x140 + 0x8},
		{NULL, DBO + 0x140 + 0xC}, {NULL, DBO + 0x140 + 0x10},
		{NULL, DBO + 0x140 + 0x14}, {NULL, DBO + 0x140 + 0x18},
		{NULL, DBO + 0x140 + 0x1C}, {NULL, DBO + 0x140 + 0x20},
		{NULL, DBO + 0x140 + 0x24}, {NULL, DBO + 0x140 + 0x28},

		{"PCIE DMA chn6 ctrl", DBO + 0x180},
		{NULL, DBO + 0x180 + 0x4}, {NULL, DBO + 0x180 + 0x8},
		{NULL, DBO + 0x180 + 0xC}, {NULL, DBO + 0x180 + 0x10},
		{NULL, DBO + 0x180 + 0x14}, {NULL, DBO + 0x180 + 0x18},
		{NULL, DBO + 0x180 + 0x1C}, {NULL, DBO + 0x180 + 0x20},
		{NULL, DBO + 0x180 + 0x24}, {NULL, DBO + 0x180 + 0x28},

		{"PCIE DMA chn7 ctrl", DBO + 0x1C0},
		{NULL, DBO + 0x1C0 + 0x4}, {NULL, DBO + 0x1C0 + 0x8},
		{NULL, DBO + 0x1C0 + 0xC}, {NULL, DBO + 0x1C0 + 0x10},
		{NULL, DBO + 0x1C0 + 0x14}, {NULL, DBO + 0x1C0 + 0x18},
		{NULL, DBO + 0x1C0 + 0x1C}, {NULL, DBO + 0x1C0 + 0x20},
		{NULL, DBO + 0x1C0 + 0x24}, {NULL, DBO + 0x1C0 + 0x28},

		{"PCIE GIC mask", GIC_MASK},
		{NULL, GIC_MASK + 4}, { NULL, GIC_MASK + 8},
		{NULL, GIC_MASK + 12}, {NULL, GIC_MASK + 16},
		{NULL, GIC_MASK + 20}, {NULL, GIC_MASK + 24},
		{NULL, GIC_MASK + 28},
		{"PCIE GIC status", GIC_STATUS},
		{NULL, GIC_STATUS + 4}, {NULL, GIC_STATUS + 8},
		{NULL, GIC_STATUS + 12}, {NULL, GIC_STATUS + 16},
		{NULL, GIC_STATUS + 20}, {NULL, GIC_STATUS + 24},
		{NULL, GIC_STATUS + 28},

		{"PCIE GIC MSIX VECTOR count", GIC_MSIX_VECTOR_COUNT},
		{"PCIE MSIX clear register", GIC_MSIX_PEND_CLR},
		{NULL, GIC_MSIX_PEND_CLR + 4}, {NULL, GIC_MSIX_PEND_CLR + 8},
		{NULL, GIC_MSIX_PEND_CLR + 12}, {NULL, GIC_MSIX_PEND_CLR + 16},
		{NULL, GIC_MSIX_PEND_CLR + 20}, {NULL, GIC_MSIX_PEND_CLR + 24},
		{NULL, GIC_MSIX_PEND_CLR + 28},

		{"PCIE GIC_CTRL", GIC_CTRL},
		{"CR_FCR", C20_PCIE_SMMU_BASE_ADDR + 0x114},
		{"CR_FSR", C20_PCIE_SMMU_BASE_ADDR + 0x118},
		{"CR_FRR0_L", C20_PCIE_SMMU_BASE_ADDR + 0x11c},
		{"CR_FRR0_H", C20_PCIE_SMMU_BASE_ADDR + 0x120},
		{"CR_FRR1_L", C20_PCIE_SMMU_BASE_ADDR + 0x124},
		{"CR_FRR1_H", C20_PCIE_SMMU_BASE_ADDR + 0x128},
		{"CR_FRR2_L", C20_PCIE_SMMU_BASE_ADDR + 0x12c},
		{"CR_FRR2_H", C20_PCIE_SMMU_BASE_ADDR + 0x130},
		{"CR_FRR3_L", C20_PCIE_SMMU_BASE_ADDR + 0x134},
		{"CR_FRR3_H", C20_PCIE_SMMU_BASE_ADDR + 0x138},
		{"PCIE bridge status", SIDEBAND(0)}, {NULL, SIDEBAND(1)},
		{NULL, SIDEBAND(2)}, {NULL, SIDEBAND(3)},
		{NULL, SIDEBAND(4)}, {NULL, SIDEBAND(5)},
		{NULL, SIDEBAND(6)}, {NULL, SIDEBAND(7)},
		{NULL, SIDEBAND(8)}, {NULL, SIDEBAND(9)},
		{NULL, SIDEBAND(10)}, {NULL, SIDEBAND(11)},
		{NULL, SIDEBAND(12)}, {NULL, SIDEBAND(13)},
		{NULL, SIDEBAND(14)}, {NULL, SIDEBAND(15)},
		{NULL, SIDEBAND(16)}, {NULL, SIDEBAND(17)},
		{"PCIE aer status", AER_STATUS(0)}, {NULL, AER_STATUS(1)},
		{NULL, AER_STATUS(2)}, {NULL, AER_STATUS(3)},
		{NULL, AER_STATUS(4)}, {NULL, AER_STATUS(5)},
		{NULL, AER_STATUS(6)}, {NULL, AER_STATUS(7)},
		{NULL, AER_STATUS(8)}, {NULL, AER_STATUS(9)},
		{NULL, AER_STATUS(10)}
};

static void OVER_WRITE(pcie_dump_reg)(struct cn_pcie_set *pcie_set)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(c20_reg); i++) {
		if (c20_reg[i].desc)
			cn_dev_pcie_err(pcie_set, "%s:", c20_reg[i].desc);

		cn_dev_pcie_err(pcie_set, "[0x%lx]=%#08x", c20_reg[i].reg,
		cn_pci_reg_read32(pcie_set, c20_reg[i].reg));
	}
}

static int OVER_WRITE(pcie_check_available)(struct cn_pcie_set *pcie_set)
{
	u32 reg_data;

	reg_data = cn_pci_reg_read32(pcie_set, PCI_COMMAND);
	if (reg_data == REG_VALUE_INVALID) {
		cn_dev_pcie_err(pcie_set, "PCIE link status abnormal, value = %#x", reg_data);
		return -1;
	}

	reg_data = cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
	if (reg_data == REG_VALUE_INVALID) {
		cn_dev_pcie_err(pcie_set, "NOC bus abnormal, read value = %#x", reg_data);
		return -1;
	}

	return 0;
}

static int OVER_WRITE(pcie_dma_align)(struct transfer_s *t,
				size_t *head, size_t *tail)
{
	/*
	 * dma engine need 4 Bytes align for both src/dst/size
	 */
	int align = dma_align_size ? dma_align_size : 0x4;
	int mask = align - 1;
	int dma_copy = 0;

	if ((t->ca & mask) != (t->ia & mask)) {
		dma_copy = 1;
		*head = min(t->size, (size_t)(align - (t->ia & mask)));
	} else {
		*head = min(t->size, (size_t)(align - (t->ca & mask)));
	}
	*head = *head % align;
	if (t->size > *head)
		*tail = (t->size - *head) % align;

	if (dma_secondary_copy == 1)
		dma_copy = 1;

	return dma_copy;
}

#ifdef CONFIG_PCI_IOV
static int OVER_WRITE(pcie_enable_vf_bar)(struct cn_pcie_set *pcie_set)
{
	return 0;
}

static void OVER_WRITE(pcie_disable_vf_bar)(struct cn_pcie_set *pcie_set)
{

}

static int c20_sriov_support(struct cn_pcie_set *pcie_set)
{
	int total_vfs;
	u64 vf_bar0_size;
	int vf;

	vf_bar0_size = pci_resource_len(
		pcie_set->pdev, PCI_IOV_RESOURCES);

	total_vfs = pci_sriov_get_totalvfs(pcie_set->pdev);
	if (total_vfs * pcie_set->pcibar[0].size != vf_bar0_size)
		return 0;

	for (vf = 0; vf < 6; vf += 2)
		if (!pci_resource_start(pcie_set->pdev, PCI_IOV_RESOURCES + vf))
			return 0;

	return 1;
}
#endif

static int c20_dma_bypass_smmu(int phy_ch, bool en, struct cn_pcie_set *pcie_set)
{
	int ret;

	phy_ch = phy_ch + DMA_SMMU_STREAM_ID;
	ret = cn_smmu_cau_bypass(pcie_set->bus_set->core, phy_ch, en);

	return ret;
}

#include "cndrv_pci_c20_sriov.c"

static struct cn_pci_ops c20_private_ops = {
	.dump_reg = OVER_WRITE(pcie_dump_reg),
	.async_dma_fill_desc_list = OVER_WRITE(async_dma_fill_desc_list),
	.fill_desc_list = OVER_WRITE(pcie_fill_desc_list),
	.check_available = OVER_WRITE(pcie_check_available),
	.dma_align = OVER_WRITE(pcie_dma_align),
#ifdef CONFIG_PCI_IOV
	.enable_vf_bar = OVER_WRITE(pcie_enable_vf_bar),
	.disable_vf_bar = OVER_WRITE(pcie_disable_vf_bar),
	.sriov_support = c20_sriov_support,
#endif
	.sriov_vf_init = c20_sriov_vf_init,
	.sriov_vf_exit = c20_sriov_vf_exit,
	.iov_virtfn_bus = c20_pcie_iov_virtfn_bus,
	.iov_virtfn_devfn = c20_pcie_iov_virtfn_devfn,
	.sriov_pre_init = c20_sriov_pre_init,
	.sriov_later_exit = c20_sriov_later_exit,
	.dma_bypass_smmu = c20_dma_bypass_smmu,
};

static int c20_pcie_setup(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/*
	 *  publish ops to uper level
	 *  different cambricon ID have different ops
	 *  same cambricon ID with different wafer, change ops here
	 */
	cn_pci_ops_init(&public_ops, &c20_private_ops);
	pcie_set->ops = &c20_private_ops;

	/* only pf will do pcie_setup */
#if defined(__x86_64__)
	if (!cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn))
		pcie_set->arm_trigger_enable = arm_trigger_enable;
#endif
	/* for domain manger get hard resource */
	if (pcie_set->arm_trigger_enable) {
		pcie_set->max_phy_channel = HOST_PHY_CHANNEL_NUM;
		pcie_set->arm_trigger_max_size = ARM_TRIGGER_MAX_SIZE;
	} else {
		pcie_set->max_phy_channel = DMA_REG_CHANNEL_NUM;
	}

	/* soft status */
	pcie_set->share_mem_cnt = 0;
	pcie_set->is_virtfn = 0;

	pcie_set->irq_type = (isr_type_index == -1) ? isr_default_type : isr_type_index;

	return 0;
}

static int c20_pcie_domain_get_resource(void *pcie, struct domain_resource *resource)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/* for domain manger get hard resource */
	resource->id = pcie_set->id;
	resource->max_phy_channel = DMA_REG_CHANNEL_NUM;
	resource->cfg_reg_size = pcie_set->pcibar[0].size / 2;
	resource->share_mem_size = pcie_set->pcibar[0].size / 2;
	resource->share_mem_base = C20_AXI_SHM_BASE;
	resource->vf_cfg_limit = 2 * 1024;
	resource->ob_mask = ((u64)((1ULL << OUTBOUND_CNT) - 1)) << OUTBOUND_FIRST;
	resource->ob_set[0].virt_addr = pcie_set->share_mem[1].virt_addr;
	resource->ob_set[0].win_length = pcie_set->share_mem[1].win_length;
	resource->ob_set[0].ob_axi_base = pcie_set->share_mem[1].device_addr;

	return 0;
}

static int c20_pcie_bar_init(struct cn_pcie_set *pcie_set)
{
	u64 offset, size;
	u32 func_id;
	const void *domain = NULL;

	domain = cn_dm_get_domain_early(pcie_set->bus_set, DM_FUNC_OVERALL);
	if (!domain)
		return -ENODEV;

	func_id = cn_dm_get_func_id(domain);
	cn_dev_pcie_info(pcie_set, "Domain[%d: 0x%px]", func_id, domain);

	offset = cn_dm_pci_get_bars_shm_bs(domain, 0);
	size = cn_dm_pci_get_bars_shm_sz(domain, 0);

	cn_dev_pcie_debug(pcie_set, "get from domain offset:%#llx size:%#llx",
						offset, size);
	if (pcie_bar_init(pcie_set, offset, size))
		return -1;
	pcie_set->share_mem[0].device_addr = C20_AXI_SHM_BASE + offset;

	return 0;
}

/* fix vf set vf2pf dma reg then unload driver, pf load driver will can not
 * get dma resource at once and dma will error.
 */
static int c20_pcie_clear_vf_dma(struct cn_pcie_set *pcie_set)
{
	int pdma_i;

	for (pdma_i = 0; pdma_i < pcie_set->max_phy_channel; pdma_i++) {
		cn_pci_reg_write32(pcie_set, V2PDMA_CTRL(pdma_i), 0);
		cn_pci_reg_read32(pcie_set, V2PDMA_CTRL(pdma_i));
	}

	return 0;
}

static int c20_pcie_dma_pre_init(struct cn_pcie_set *pcie_set)
{
	const void *domain = NULL;

	domain = cn_dm_get_domain_early(pcie_set->bus_set, DM_FUNC_OVERALL);
	if (!domain)
		return -ENODEV;

	if (cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		pcie_set->dma_phy_channel_mask = 0xFF; //cn_dm_pci_get_dma_ch(domain);
	} else {
		if (pcie_set->arm_trigger_enable)
			pcie_set->dma_phy_channel_mask = HOST_PHY_CHANNEL_MASK;
		else
			pcie_set->dma_phy_channel_mask = DMA_REG_CHANNEL_MASK;
	}

	cn_dev_pcie_debug(pcie_set, "get from domain mask:%#x",
					pcie_set->dma_phy_channel_mask);

	pcie_set->shared_desc_total_size = SHARED_DMA_DESC_TOTAL_SIZE;
	pcie_set->priv_desc_total_size = PRIV_DMA_DESC_TOTAL_SIZE;
	pcie_set->async_static_desc_size = ASYNC_STATIC_DESC_SIZE;
	pcie_set->dma_buffer_size = DMA_BUFFER_SIZE;
	pcie_set->per_desc_size = DMA_DESC_PER_SIZE;
	pcie_set->async_max_desc_num = ASYNC_DMA_DESC;
	pcie_set->async_static_task_num = pcie_set->async_static_desc_size /
					pcie_set->per_desc_size /
					pcie_set->async_max_desc_num;
	pcie_set->async_dynamic_desc_size = ASYNC_DYNAMIC_DESC_SIZE;
	pcie_set->async_dynamic_desc_num = pcie_set->async_dynamic_desc_size /
					pcie_set->per_desc_size;
	pcie_set->max_inbound_cnt = 8;

	/* fix vf dma bug*/
	c20_pcie_clear_vf_dma(pcie_set);

	return 0;
}

static int pcie_dma_interrupt_init(struct cn_pcie_set *pcie_set)
{
	int i;
	char src[30];
	static const int interrupt_count[] = {MSI_COUNT, MSIX_COUNT, INTX_COUNT};

	pcie_set->irq_num = interrupt_count[pcie_set->irq_type];
	pcie_gic_mask_all(pcie_set);

	/* fix msix ram bug by writing msix ram*/
	if (pcie_set->irq_type == MSIX)
		fill_msix_ram(pcie_set);

	do {
		if (isr_enable_func[pcie_set->irq_type](pcie_set) == 0)
			break;

		if (pcie_set->irq_type == MSIX) {
			pcie_set->irq_type = MSI;
			pcie_set->irq_num = interrupt_count[pcie_set->irq_type];
		} else if (pcie_set->irq_type == MSI) {
			pcie_set->irq_type = INTX;
			pcie_set->irq_num = interrupt_count[pcie_set->irq_type];
		} else if (pcie_set->irq_type == INTX) {
			cn_dev_pcie_err(pcie_set, "isr init failed!");
			return -1;
		}
	} while (1);

	pcie_set->irq_str_index_ptr = irq_str_index;
	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_phy_channel_mask & (1 << i)) {
			sprintf(src, "pcie_dma%d", i);
			cn_pci_register_interrupt(
				pcie_get_irq(src, pcie_set),
				pcie_dma_interrupt_handle, pcie_set, pcie_set);

			sprintf(src, "pcie_dma_err%d", i);
			cn_pci_register_interrupt(
				pcie_get_irq(src, pcie_set),
				pcie_dma_interrupt_handle, pcie_set, pcie_set);
		}
	}

	return 0;
}

static int pcie_interrupt_exit(struct cn_pcie_set *pcie_set)
{
	int i;
	struct cn_bus_set *bus_set = pcie_set->bus_set;
	char src[30];

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_phy_channel_mask & (1 << i)) {
			sprintf(src, "pcie_dma%d", i);
			cn_pci_unregister_interrupt(
				pcie_get_irq(src, pcie_set), pcie_set);

			sprintf(src, "pcie_dma_err%d", i);
			cn_pci_unregister_interrupt(
				pcie_get_irq(src, pcie_set), pcie_set);
		}
	}

	bus_set->ops->disable_all_irqs(pcie_set);

	if (isr_disable_func[pcie_set->irq_type](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr destroyed failed!");
		return -1;
	}

	if (pcie_set->irq_type == MSIX) {
		for (i = 0; i < (GIC_INTERRUPT_NUM * 4); i++)
			pcie_set->msix_ram[i] =
				cn_pci_reg_read32(pcie_set, (GBO + i * 4));
	}
	return 0;
}

static int c20_arm_trigger_init(struct cn_pcie_set *pcie_set)
{
	/* arm use ARM_TRIGGER_ARM_PHY_CHANNEL to determine
	 * whether to support arm trigger dma
	 */
	if (pcie_set->arm_trigger_enable) {
		cn_pci_reg_write32(pcie_set, ARM_TRIGGER_ARM_PHY_CHANNEL, ARM_PHY_CHANNEL_NUM);
		cn_pci_reg_write32(pcie_set, ARM_TRIGGER_HOST_PHY_CHANNEL, HOST_PHY_CHANNEL_NUM);
	} else {
		cn_pci_reg_write32(pcie_set, ARM_TRIGGER_HOST_PHY_CHANNEL, DMA_REG_CHANNEL_NUM);
		cn_pci_reg_write32(pcie_set, ARM_TRIGGER_ARM_PHY_CHANNEL, 0);
	}
	return 0;
}

static int pcie_pre_init_hw(struct cn_pcie_set *pcie_set)
{
	int i;
	char src[30];
	unsigned long flags;
	unsigned int status;

	if (pcie_set->outbound_able)
		pcie_outbound_reg(pcie_set);

	set_bar_default_window(pcie_set);

	isr_hw_enable[pcie_set->irq_type](pcie_set);

	pcie_gic_mask_all(pcie_set);

	/* NOTE: clear dma interrupt before enable it*/
	status = cn_pci_reg_read32(pcie_set, DISTATUS_LOCAL);
	cn_pci_reg_write32(pcie_set, DISTATUS_LOCAL, status);

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_phy_channel_mask & (1 << i)) {
			sprintf(src, "pcie_dma%d", i);
			spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
			pcie_gic_unmask(pcie_get_irq(src, pcie_set), pcie_set);
			sprintf(src, "pcie_dma_err%d", i);
			pcie_gic_unmask(pcie_get_irq(src, pcie_set), pcie_set);
			spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);
		}
	}
	cn_pci_reg_write32(pcie_set, DIMASK_LOCAL, 0xFF);
	cn_pci_reg_read32(pcie_set, DIMASK_LOCAL);

	c20_arm_trigger_init(pcie_set);

	return 0;
}

static void c20_pcie_get_fw_id(struct cn_pcie_set *pcie_set)
{
	u64 fw_id = 0ULL;
	u32 info = 0U;

	info = cn_pci_reg_read32(pcie_set, PCIE_FW_ADDR_L);
	fw_id |= (info & 0xFFFFFFFF);
	fw_id <<= 12;
	info = cn_pci_reg_read32(pcie_set, PCIE_FW_ADDR_H);
	fw_id |= (info & 0x00000FFF);
	pcie_set->pcie_fw_id = fw_id;

	cn_dev_pcie_info(pcie_set, "PCIE Firmware Version: %llx", fw_id);
}

/*
 * copy from ./fw/plat/c20_fpga_boot.c
 * we should shutdown arm before hbm init, otherwise arm may in bus busy state
 */
#define PMU_SUBSYS_RESETN (0x500c)
#define	CTRL_BASE_ADDR	0x00600000
#define	CPU_SUBSYS_CTRL_CBW_BUS_CLEAR_ADDR	0x000000C0
#define	CPU_SUBSYS_CTRL_BUSIDLE_ADDR	0x000000BC
#define	CPU_SUBSYS_CTRL__BUSIDLE__BW1_BUS_IDLE__MASK	0x00000002
#define	CPU_SUBSYS_CTRL__BUSIDLE__BWMP_BUS_IDLE__MASK	0x00000004
#define	CPU_SUBSYS_CTRL__BUSIDLE__ETR_AXIBUS_IDLE__MASK	0x00000008
#define	CPU_SUBSYS_CTRL__CBW_BUS_CLEAR__CBW0_BUS_CLEAR__MASK	0x00000001
#define	CPU_SUBSYS_CTRL__CBW_BUS_CLEAR__CBW1_BUS_CLEAR__MASK	0x00000002
#define	CPU_SUBSYS_CTRL__CBW_BUS_CLEAR__CBWMP_BUS_CLEAR__MASK	0x00000004
#define	CPU_SUBSYS_CTRL__BUSIDLE__BW0_BUS_IDLE__MASK	0x00000001
static int c20_boot_pre(struct cn_pcie_set *pcie_set)
{
	unsigned int val, idle_val;
	int loop_flag_1 = 1;
	int loop_time = 0;
	int ret = 0;

	val = cn_pci_reg_read32(pcie_set, PMU_SUBSYS_RESETN);

	if (val & 0x4000) {
		/* step-1: bus clear */
		val = (CPU_SUBSYS_CTRL__CBW_BUS_CLEAR__CBW0_BUS_CLEAR__MASK |
			CPU_SUBSYS_CTRL__CBW_BUS_CLEAR__CBW1_BUS_CLEAR__MASK |
			CPU_SUBSYS_CTRL__CBW_BUS_CLEAR__CBWMP_BUS_CLEAR__MASK);

		cn_pci_reg_write32(pcie_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CBW_BUS_CLEAR_ADDR, val);

		/* step-2: wait bus idle */
		idle_val = (CPU_SUBSYS_CTRL__BUSIDLE__BW0_BUS_IDLE__MASK |
			CPU_SUBSYS_CTRL__BUSIDLE__BW1_BUS_IDLE__MASK |
			CPU_SUBSYS_CTRL__BUSIDLE__BWMP_BUS_IDLE__MASK |
			CPU_SUBSYS_CTRL__BUSIDLE__ETR_AXIBUS_IDLE__MASK);

		while (loop_flag_1) {
			udelay(100);
			val = cn_pci_reg_read32(pcie_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_BUSIDLE_ADDR);
			if (val == idle_val) {
				loop_flag_1 = 0;
			}
			loop_time = loop_time + 1;
			if ((loop_time % 1000) == 0) {
				cn_dev_pcie_info(pcie_set,
					"Error, TIMEOUT find bus idle: loop_time = %d\n", loop_time);
				ret = -1;
				break;
			}

		}
		/* pmu reset cpu */
		cn_pci_reg_write32(pcie_set, PMU_SUBSYS_RESETN, 0x7fff0000);
		/* pmu cpu de-assert */
		cn_pci_reg_write32(pcie_set, PMU_SUBSYS_RESETN, 0x7fff7fff);
	} else {
		cn_pci_reg_write32(pcie_set, PMU_SUBSYS_RESETN, 0x7fff0000);
		cn_pci_reg_write32(pcie_set, PMU_SUBSYS_RESETN, 0x7fff7fff);
	}
	return ret;
}

static int cn_pci_set_pdev_cspeed(unsigned int speed, struct pci_dev *pdev)
{
	int ret;
	struct pci_dev *parent = pdev->bus->self;
	u16 link_status, lnkctl, lnkctl2;
	u16 current_speed, target_vector;
	u32 current_width, target_width;
	u32 reset_cnt = 20;

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	target_width = current_width;
	target_vector = speed;

	cn_dev_info("PCIe link speed is %s", PCIE_SPEED_STR(current_speed));
	cn_dev_info("PCIe link width is x%d", current_width);
	cn_dev_info("PCIe target speed is %s", PCIE_SPEED_STR(speed));

	while ((current_speed != target_vector) ||
			(current_width != target_width)) {
retry:
		cn_dev_info("setting parent target link speed");
		ret = pcie_capability_read_word(parent, PCI_EXP_LNKCTL2,
						&lnkctl2);
		if (ret) {
			cn_dev_err("unable to read from PCI config");
			return -1;
		}

		cn_dev_info("old link control2: 0x%x", (u32)lnkctl2);

		/* only write to parent if target is not as high as ours */
		if ((lnkctl2 & PCI_EXP_LNKCTL2_TLS) != target_vector) {
			lnkctl2 &= ~PCI_EXP_LNKCTL2_TLS;
			lnkctl2 |= target_vector;
			cn_dev_info("new link control2: 0x%x", (u32)lnkctl2);
			ret = pcie_capability_write_word(parent,
					PCI_EXP_LNKCTL2, lnkctl2);
			if (ret) {
				cn_dev_err("unable to write to PCI config");
				return -1;
			}
		} else
			cn_dev_info("target speed is OK");

		cn_dev_info("setting target link speed");
		ret = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL2, &lnkctl2);
		if (ret) {
			cn_dev_err("unable to read from PCI config");
			return -1;
		}

		cn_dev_info("old link control2: 0x%x", (u32)lnkctl2);
		lnkctl2 &= ~PCI_EXP_LNKCTL2_TLS;
		lnkctl2 |= target_vector;
		cn_dev_info("new link control2: 0x%x", (u32)lnkctl2);
		ret = pcie_capability_write_word(pdev, PCI_EXP_LNKCTL2, lnkctl2);
		if (ret) {
			cn_dev_err("unable to write to PCI config");
			return -1;
		}

		ret = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL, &lnkctl);
		if (ret) {
			cn_dev_err("unable to read from PCI config PCIE_EXP_LNKCTL");
			return -1;
		}
		lnkctl |= PCI_EXP_LNKCTL_RL;
		ret = pcie_capability_write_word(pdev, PCI_EXP_LNKCTL, lnkctl);
		if (ret) {
			cn_dev_err("unable to write to PCI config LNKCTL RETRAIN");
			return -1;
		}
		msleep(500);
		reset_cnt--;

		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
		current_speed = link_status & PCI_EXP_LNKSTA_CLS;
		current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
		if (current_width > target_width)
			target_width = current_width;

		cn_dev_info("PCIe link change speed to %s\n", PCIE_SPEED_STR(current_speed));
		cn_dev_info("PCIe link change width to x%d\n", current_width);

		if (current_width != target_width && reset_cnt > 7)
			goto retry;

		if (reset_cnt == 0) {
			cn_dev_err("pcie change speed fail");
			return -1;
		}
	}
	return 0;
}

__attribute__((unused))
static int c20_retrain_link_speed(struct cn_pcie_set *pcie_set)
{
	int ret;
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_dev *parent = pdev->bus->self;
	u64 k_gen;
	u16 link_status;
	u16 link_cap;
	u32 current_speed;
	u32 current_width;
	u32 target_speed;
	u32 target_width;

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	cn_dev_pcie_info(pcie_set, "current link speed:%s current link width:x%d",
			PCIE_SPEED_STR(current_speed), current_width);
	if (current_speed > PCI_EXP_LNKCTL2_TLS_2_5GT) {
		cn_dev_pcie_info(pcie_set, "no need to change speed");
		return 0;
	}

	/* change capability to gen4x16 */
	k_gen = cn_pci_reg_read64(pcie_set, K_GEN_REG);
	k_gen = (k_gen & 0xffff80ff) | 0x7f00;
	cn_pci_reg_write64(pcie_set, K_GEN_REG, k_gen);
	cn_pci_reg_read64(pcie_set, K_GEN_REG);
	cn_dev_pcie_info(pcie_set, "change capability to gen4x16 k_gen:%#llx", k_gen);

	/* get target speed and target width */
	pcie_capability_read_word(parent, PCI_EXP_LNKCAP, &link_cap);
	target_speed = link_cap & PCI_EXP_LNKSTA_CLS;
	target_width = (link_cap & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	cn_dev_pcie_info(pcie_set, "target link speed:%s target link width:x%d",
			PCIE_SPEED_STR(target_speed), target_width);
	if (target_speed >= PCI_EXP_LNKCTL2_TLS_8_0GT) {
		ret = cn_pci_change_speed(pcie_set, PCI_EXP_LNKSTA_CLS_8_0GB, target_width);
		if (ret) {
			cn_dev_info("retrain to gen3 failed");
			return -1;
		}
	}

	if (target_speed >= PCI_EXP_LNKCTL2_TLS_16_0GT) {
		ret = cn_pci_change_speed(pcie_set, PCI_EXP_LNKCTL2_TLS_16_0GT, target_width);
		if (ret) {
			cn_dev_info("retrain to gen4 failed");
			return -1;
		}
	}

	return 0;
}

static int walkthrough_rc_for_lower_gen3(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_bus *bus;
	u16 status, speed;

	for (bus = pdev->bus; !pci_is_root_bus(bus); bus = bus->parent) {
		pdev = bus->self;
		if (!pdev) {
			cn_dev_info("pdev is null\n");
			return -1;
		}

		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &status);
		speed = status & PCI_EXP_LNKSTA_CLS;

		if (speed == PCI_EXP_LNKCTL2_TLS_8_0GT ||
			speed == PCI_EXP_LNKCTL2_TLS_5_0GT ||
			speed == PCI_EXP_LNKCTL2_TLS_2_5GT) {
			cn_dev_debug("pcie bus:%x:%x:%x speed is %s\n",
					pdev->bus->number, pdev->devfn >> 3,
					pdev->devfn & 0x7, PCIE_SPEED_STR(speed));
			return 1;
		}
	}

	return 0;
}

static struct pci_dev *walkthrough_to_slot(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_bus *bus = pdev->bus;
	int i;

#define CN_C20_PCIE_SLOT (5)
	for (i = 0; i < CN_C20_PCIE_SLOT; i++, bus = bus->parent) {
		if (bus == NULL)
			return NULL;

		pdev = bus->self;
		if (!pdev) {
			cn_dev_info("pdev is null\n");
			return NULL;
		}
	}

	cn_dev_info("pcie slot bus:%x:%x:%x\n",
		pdev->bus->number, pdev->devfn >> 3, pdev->devfn & 0x7);
	return pdev;
}

#ifndef PCI_EXP_DEVCTL2_COMP_TIMEOUT
/* Completion Timeout Value */
#define  PCI_EXP_DEVCTL2_COMP_TIMEOUT  0x000f
#endif

static int set_rc_timeout_max(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_bus *bus;
	u32 cap;
	u16 range;

	if (pdev == NULL)
		return -1;

	for (bus = pdev->bus; !pci_is_root_bus(bus); bus = bus->parent) {
		pdev = bus->self;
		if (!pdev) {
			cn_dev_info("pdev is null\n");
			return -1;
		}
	}

	pcie_capability_read_dword(pdev, PCI_EXP_DEVCAP2, &cap);
	cap &= 0xf;
	range = (((fls(cap) - 1)) << 2) + 2;

	cn_dev_info("pcie bus:%x:%x:%x comp timeout 0x%x",
			pdev->bus->number, pdev->devfn >> 3,
			pdev->devfn & 0x7, range);

	pcie_capability_clear_and_set_word(pdev, PCI_EXP_DEVCTL2, PCI_EXP_DEVCTL2_COMP_TIMEOUT, range);

	return 0;
}
__attribute__((unused)) static int is_pdev_slot(struct pci_dev *pdev)
{
	int type;

	type = pci_pcie_type(pdev);
	if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_DOWNSTREAM
		|| type == PCI_EXP_TYPE_PCIE_BRIDGE) {
		return (pcie_caps_reg(pdev) & PCI_EXP_FLAGS_SLOT);
	}
	return 0;
}

 __attribute__((unused))
 static int is_fault_link_slot(struct pci_dev *pdev, struct pci_dev *down_pdev,
				u16 speed, u16 current_width)
{
	u16 cap_speed, down_cap_speed;
	u16 cap_width, down_cap_width;
	u16 link_cap;
	pcie_capability_read_word(pdev, PCI_EXP_LNKCAP, &link_cap);
	cap_speed = link_cap & PCI_EXP_LNKCAP_SLS;
	cap_width = link_cap & PCI_EXP_LNKCAP_MLW;
	pcie_capability_read_word(down_pdev, PCI_EXP_LNKCAP, &link_cap);
	down_cap_speed = link_cap & PCI_EXP_LNKCAP_SLS;
	down_cap_width = link_cap & PCI_EXP_LNKCAP_MLW;

	if ((speed < cap_speed && speed < down_cap_speed)
			|| (current_width < cap_width && current_width < down_cap_width)) {
		return 1;
	}
	return 0;
}

__attribute__((unused))
static int less_than_g3X8(u16 speed, u16 current_width)
{
	if (speed == PCI_EXP_LNKCTL2_TLS_5_0GT ||
			speed == PCI_EXP_LNKCTL2_TLS_2_5GT ||
			current_width == PCI_EXP_LNKSTA_NLW_X1 ||
			current_width == PCI_EXP_LNKSTA_NLW_X2 ||
			current_width == PCI_EXP_LNKSTA_NLW_X4) {
			return 1;
	}
	return 0;
}

__attribute__((unused))
static int policy_check(struct pci_dev *pdev, struct cn_pcie_set *pcie_set, int checkbit)
{
	struct pci_bus *bus;
	u16 status, speed, current_width, linkcap;
	struct pci_dev *copy_pdev;
	struct pci_dev *down_pdev = NULL;
	int ret = 0;

	copy_pdev = pdev;
	down_pdev = pdev;
	for (bus = pdev->bus; !pci_is_root_bus(bus); bus = bus->parent) {
		pdev = bus->self;
		if (!pdev) {
			cn_dev_pcie_info(pcie_set, "pdev is null\n");
			return -1;
		}
		if (!is_pdev_slot(pdev)) {
			down_pdev = pdev;
			continue;
		}
		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &status);
		speed = status & PCI_EXP_LNKSTA_CLS;
		current_width = status & PCI_EXP_LNKSTA_NLW;
		linkcap = status & PCI_EXP_LNKCAP_SLS;
		switch (checkbit) {
		case 1:
			if (less_than_g3X8(speed, current_width)) {

				cn_dev_pcie_err(pcie_set,
						"less than g3X8 PCIe Device BDF:%x:%x:%x the PCIe Device speed is %s current_width is %s\n current link capability is %s\n",
						pdev->bus->number, pdev->devfn >> 3,
						pdev->devfn & 0x7, PCIE_SPEED_STR(speed),
						PCIE_WIDTH_STR(current_width), PCIE_LINKCAP_STR(linkcap));
				cn_dev_pcie_err(pcie_set,
						"less than g3X8 MLU Device BDF:%x:%x:%x\n", copy_pdev->bus->number,
						copy_pdev->devfn >> 3, copy_pdev->devfn & 0x7);
				ret = 1;
			}
			break ;
		case 2:
			if (is_fault_link_slot(pdev, down_pdev, speed, current_width)) {
				cn_dev_pcie_warn(pcie_set, "slot BDF:%x:%x:%x is not correct speed %s, width %s\n",
						pdev->bus->number,  pdev->devfn >> 3, pdev->devfn & 0x7,
						PCIE_SPEED_STR(speed), PCIE_WIDTH_STR(current_width));
			}
			break;
		default:
				cn_dev_pcie_info(pcie_set, "not support this policy check %d\n", checkbit);
				break;
		}
		down_pdev = pdev;
	}

	return ret;
}

__attribute__((unused)) static int
cn_pci_link_check(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	int ret;
	int bit = 0;
	int value = 0;
	int error = 0;

	cn_dev_pcie_info(pcie_set, "PCIe link check bits 0x%x\n", link_check);
	if (!link_check) {
		return 0;
	}
	value = link_check;
	do {
		bit++;
		if (value & 0x1) {
			ret = policy_check(pdev, pcie_set, bit);
			if (ret) {
				error++;
			}
		}
		value >>= 1;
	} while (value);

	if (error) {
		cn_dev_pcie_err(pcie_set, "PCIe link check has error\n");
		return -EACCES;
	}

	return 0;
}

static int c20_bug_fix(struct cn_pcie_set *pcie_set)
{
	int ret = 0;
	struct pci_dev *pdev = pcie_set->pdev;
	u32 sn_flag = 0;
	const char *dmi_board_name;

	dmi_board_name = dmi_get_system_info(DMI_BOARD_NAME);
	if (dmi_board_name) {
		cn_dev_pcie_info(pcie_set, "system info dmi_board_name : %s\n", dmi_board_name);
#if (!defined(__arm__) && !defined(__aarch64__))
		if (strstr(dmi_board_name, "NF5498A5")) {
			ret = c20_retrain_link_speed(pcie_set);
			if (ret) {
				cn_dev_pcie_err(pcie_set,
						"retrain link speed fail sn_flag = %d", sn_flag);
				return -1;
			}
		}
#endif
	}

	sn_flag = cn_pci_reg_read32(pcie_set, IPC4);//sn_flag (0 ~ 15)BA
	/*
	 * (sn_flag & 0xffff) = 0: 290-M5 card
	 * fix: retrain gen1 to gen3/gen4
	 */
#if (defined(__i386__) || defined(__x86_64__) || defined(__X86__))
	ret = cn_pci_link_check(pcie_set);
	if (ret) {
		return -EACCES;
	}
#endif

	/*
	 * (sn_flag & 0xffff) != 0: 290-spider card
	 * fix: double bandwidth(GEN3_host match GEN3_card, GEN4_host match GEN4_card
	 */
	if ((sn_flag & 0xffff)) {
		ret = walkthrough_rc_for_lower_gen3(pcie_set);
		if (ret == 1) {
			pdev = walkthrough_to_slot(pcie_set);
			if (pdev == NULL)
				return 0;
			ret = cn_pci_set_pdev_cspeed(PCI_EXP_LNKCTL2_TLS_8_0GT, pdev);
		}
	}

	cn_dev_pcie_info(pcie_set, "cambr_rc_timeout_max_enable : %d\n", cambr_rc_timeout_max_enable);

	if (cambr_rc_timeout_max_enable == 1)
		set_rc_timeout_max(pcie_set);

	return ret;
}

static int c20_check_noc_bus(struct cn_pcie_set *pcie_set)
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

static int c20_pcie_pre_init(void *pcie)
{
	int ret = 0;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	ret = c20_pcie_bar_init(pcie_set);
	if (ret)
		return -1;

	ret = c20_check_noc_bus(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = c20_bug_fix(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	/* get pcie firmware version info*/
	c20_pcie_get_fw_id(pcie_set);

	ret = c20_boot_pre(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = c20_pcie_dma_pre_init(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = pcie_register_bar(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	outbound_pre_init(pcie_set);

	ret = do_pcie_init(pcie_set);
	if (ret)
		goto RELEASE_BAR;
	return 0;

RELEASE_BAR:
	bar_deinit(pcie_set);
	return -1;
}

static int c20_pcie_pre_exit(void *pcie)
{

	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	if (pcie_interrupt_exit(pcie_set))
		return -1;

	pcie_outbound_exit(pcie_set);

	bar_deinit(pcie_set);

	return 0;
}

struct cn_pci_info c20_pci_info = {
	.setup = c20_pcie_setup,
	.pre_init = c20_pcie_pre_init,
	.pre_exit = c20_pcie_pre_exit,
	.get_resource = c20_pcie_domain_get_resource,
	.dev_name = "c20"
};
