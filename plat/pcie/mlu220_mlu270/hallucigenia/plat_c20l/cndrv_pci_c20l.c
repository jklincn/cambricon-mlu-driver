/************************************************************************
 *
 *  @file cndrv_pci_c20l.c
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

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "../../pcie_dma.h"
#include "../../pcie_bar.h"
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_pci_c20l.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"

#define BAR_NUMS_EACH_VF			3
#define MAX_VF_NUMS				4
#define VF_BAR_NUMS				12
#define DMA_SMMU_STREAM_ID      37

#if (GIC_INTERRUPT_NUM != MSIX_COUNT)
const static int irq_msix_gic_end[16] = {
	9,  19,  23,	38,  42,  64,  87, 100,
	116, 125, 138, 145, 157, 163, 254, 255};
#endif

#if (MSI_COUNT == 1)
const static int irq_msi_gic_end[1] = {255};
#elif (MSI_COUNT == 2)
const static int irq_msi_gic_end[2] = {23, 255};
#elif (MSI_COUNT == 4)
const static int irq_msi_gic_end[4] = {19, 64, 125, 255};
#elif (MSI_COUNT == 8)
const static int irq_msi_gic_end[8] = {19, 23, 64, 81, 100, 138, 163, 255};
#elif (MSI_COUNT == 16)
const static int irq_msi_gic_end[16] = {
	4,   9,  14,  19,  23,  38,  42,  64,
	74, 100, 116, 125, 145, 157, 163, 255};
#elif (MSI_COUNT == 32)
const static int irq_msi_gic_end[32] = {
	4,   9,  14,   19,  23,  33,  38,  42,
	46,  54,  64,  69,  74,  81,  87,  95,
	100, 108, 116, 125, 133, 138, 145, 149,
	157, 163, 168, 173, 178, 183, 188, 255};
#endif

static struct cn_pci_irq_str_index irq_str_index[256] = {
	{39, "pcie_dma0"},
	{40, "pcie_dma1"},
	{41, "pcie_dma2"},
	{42, "pcie_dma3"},
	{25, "PCIE_IRQ_GIC_ARM2PF"},
};

/*
 *  include public c code
 *  warnning: do not remove it to the top of file
 *            otherwise will have build errors
 */
#include "../../pcie_common.c"
#include "../hallucigenia.h"
#include "cndrv_pci_c20l_sriov.c"
#define OVER_WRITE(f) c20l_##f

static int c20l_bug_fix_list(struct cn_pcie_set *pcie_set);

static int adjust_dev_param(struct cn_pcie_set *pcie_set)
{
	unsigned int value, t;

	/* in pcie */
	cn_pci_reg_write32(pcie_set, BAR2_TO_AXI_ADDR_REG_LINK_DOWN, 0x0);

	/*
	 * if not check ,four inbound channel may be failed;
	 */
	pci_read_config_dword(pcie_set->pdev, DEV_CONTROL_STATUS_REG, &value);
	t = 2;
	value &= (~(0x7 << 12));
	value |= (t << 12);
	pci_write_config_dword(pcie_set->pdev, DEV_CONTROL_STATUS_REG, value);

	pci_read_config_dword(pcie_set->pdev, DEV_CONTROL_STATUS_REG, &value);
	cn_dev_debug("PCIe DEV_CONTROL_STATUS_REG :%#x", value);

	value = cn_pci_reg_read32(pcie_set, DCV);
	cn_dev_debug("PCIe DMA Capability and Version Register:%d", value);

	/*
	 * set outstanding number to fix occur timeout error
	 * refer jira bug C10-831
	 */
	value = cn_pci_reg_read32(pcie_set, LOCAL_DEBUG_MUX_CTRL2);
	cn_dev_debug("PCIe 0x109234 value:%x t:%x", value, t);
#if 0
	switch (t) {
	case 0:
		value = 0x7ea40;
		break;

	case 1:
		value = 0x3ea40;
		break;

	case 2:
		/*
		 * outstanding value is base on MaxReadReq and 64B align,
		 * our driver set MaxReadReq equal 512B
		 * hardware spec recommd set the value 14, for 20l disable order check
		 * so we can set it bigger
		 */
		value = 0x3ea40;
		break;

	default:
		value = 0x1ea40;
		break;
	}
#else
	value = 0x3ea40;
#endif
	cn_pci_reg_write32(pcie_set, LOCAL_DEBUG_MUX_CTRL2, value);
	cn_pci_reg_read32(pcie_set, LOCAL_DEBUG_MUX_CTRL2);

	return 0;
}

static int OVER_WRITE(pcie_fill_desc_list)(struct dma_channel_info *channel)
{
	int i;
	unsigned long cpu_dma_addr;
	u64 ipu_ram_dma_addr;
	u64 dev_end;
	unsigned long count = 0;
	unsigned long count_tmp;
	struct scatterlist *sg;
	int desc_offset = 0;
	unsigned int len_ctrl;

	ipu_ram_dma_addr = channel->ram_addr;

	for_each_sg(channel->sg_merge, sg, channel->nents_merge, i) {
		cpu_dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);
		dev_end = ipu_ram_dma_addr + count;

		if (channel->direction == DMA_H2D && ((cpu_dma_addr & 0x3F) != 0
							|| (count & 0x3F) != 0)) {
			cn_dev_pcie_err(channel->pcie_set,
				"No 64bit align:cpu_addr:%#lx count:%#lx\n",
							cpu_dma_addr, count);
			return -1;
		}

		if ((ipu_ram_dma_addr & 0x1ffUL) >= 0x1e0 &&
				(dev_end & 0x1FFUL) && (dev_end & 0x1FFUL) <= 0x20 &&
				count > 8 * 1024 && ((channel->direction == DMA_D2H) ||
				(channel->direction == DMA_P2P))) {
			/* fix hardware bug for C20-393 */
			count_tmp = 0x200 - (ipu_ram_dma_addr & 0x1ff);
			len_ctrl = LENGTH_CTRL(count_tmp, 1, 0);
			FILL_DESC(ipu_ram_dma_addr, cpu_dma_addr, len_ctrl,
				desc_offset, channel);
			desc_offset += DESC_SIZE;

			ipu_ram_dma_addr += count_tmp;
			cpu_dma_addr += count_tmp;
			count -= count_tmp;
		}

		if (i != channel->nents_merge - 1)
			len_ctrl = LENGTH_CTRL(count, 1, 0);
		else
			len_ctrl = LENGTH_CTRL(count, 0, 1);

		FILL_DESC(ipu_ram_dma_addr, cpu_dma_addr, len_ctrl,
			desc_offset, channel);
		desc_offset += DESC_SIZE;

		ipu_ram_dma_addr += count;
	}

	channel->desc_len = desc_offset;
	memcpy_toio(channel->desc_virt_base, channel->desc_buf, desc_offset);

#if defined(__aarch64__)
	channel->pcie_set->ops->pci_mb(channel->pcie_set);
#endif
	return 0;
}

/*
 * The table is used for debug regs dump, very important for us
 * WARNING: different platform have different reg base,
 * we need check every regs carefully with hardware enginer, do not just copy
 */
static struct pcie_dump_reg_s c20l_reg[] = {
		{"PCIE DMA int status", DBO + 0xa0},
		{"PCIE status", 0x100004},
		{"PCIE local error", 0x10920c},
		{"PCIE PHY status", 0x109238},
		{"PCIE ltssm FSM", 0x10c020},
		{"PCIE ltssm other", 0x100104},
		{NULL, 0x100110},
		{NULL, 0x109238},
		{NULL, 0x109214},
		{"PCIE DMA chn0 ctrl", DBO},
		{NULL, DBO + 0x4},
		{NULL, DBO + 0x8},
		{"PCIE DMA chn1 ctrl", DBO + 0x14},
		{NULL, DBO + 0x18},
		{NULL, DBO + 0x1c},
		{"PCIE DMA chn2 ctrl", DBO + 0x28},
		{NULL, DBO + 0x2c},
		{NULL, DBO + 0x30},
		{"PCIE DMA chn3 ctrl", DBO + 0x3c},
		{NULL, DBO + 0x40},
		{NULL, DBO + 0x44},
		{"PCIE GIC mask", GIC_MASK},
		{NULL, GIC_MASK + 4},
		{NULL, GIC_MASK + 8},
		{NULL, GIC_MASK + 12},
		{NULL, GIC_MASK + 16},
		{NULL, GIC_MASK + 20},
		{NULL, GIC_MASK + 24},
		{NULL, GIC_MASK + 28},
		{"PCIE GIC status", GIC_STATUS},
		{NULL, GIC_STATUS + 4},
		{NULL, GIC_STATUS + 8},
		{NULL, GIC_STATUS + 12},
		{NULL, GIC_STATUS + 16},
		{NULL, GIC_STATUS + 20},
		{NULL, GIC_STATUS + 24},
		{NULL, GIC_STATUS + 28},

		{"PCIE MSIX vector count", GIC_MSIX_VECTOR_COUNT},
		{"PCIE MSIX clear register", GIC_MSIX_CLR},
		{NULL, GIC_MSIX_CLR + 4},
		{NULL, GIC_MSIX_CLR + 8},
		{NULL, GIC_MSIX_CLR + 12},
		{NULL, GIC_MSIX_CLR + 16},
		{NULL, GIC_MSIX_CLR + 20},
		{NULL, GIC_MSIX_CLR + 24},
		{NULL, GIC_MSIX_CLR + 28},

		{"PCIE others:GIC_CTRL", GIC_CTRL},
		{NULL, GBO + 0x1000},
		{"CR_FCR", C20L_PCIE_SMMU_BASE_ADDR + 0x114},
		{"CR_FSR", C20L_PCIE_SMMU_BASE_ADDR + 0x118},
		{"CR_FRR0_L", C20L_PCIE_SMMU_BASE_ADDR + 0x11c},
		{"CR_FRR0_H", C20L_PCIE_SMMU_BASE_ADDR + 0x120},
		{"CR_FRR1_L", C20L_PCIE_SMMU_BASE_ADDR + 0x124},
		{"CR_FRR1_H", C20L_PCIE_SMMU_BASE_ADDR + 0x128},
		{"CR_FRR2_L", C20L_PCIE_SMMU_BASE_ADDR + 0x12c},
		{"CR_FRR2_H", C20L_PCIE_SMMU_BASE_ADDR + 0x130},
		{"CR_FRR3_L", C20L_PCIE_SMMU_BASE_ADDR + 0x134},
		{"CR_FRR3_H", C20L_PCIE_SMMU_BASE_ADDR + 0x138}
};

static void OVER_WRITE(pcie_dump_reg)(struct cn_pcie_set *pcie_set)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(c20l_reg); i++) {
		if (c20l_reg[i].desc)
			cn_dev_pcie_err(pcie_set, "%s:", c20l_reg[i].desc);

		cn_dev_pcie_err(pcie_set, "[0x%lx]=%#08x", c20l_reg[i].reg,
		cn_pci_reg_read32(pcie_set, c20l_reg[i].reg));
	}
}

const static struct {
	u64 reg;
	u64 mask;
} pf_table[] = {
	{BAR2_TO_AXI_ADDR_REG_L, 0x0}, /* pf bar2 */
	{BAR4_TO_AXI_ADDR_REG_L, 0x0}, /* pf bar4 */
};

static int OVER_WRITE(pcie_enable_pf_bar)(struct cn_pcie_set *pcie_set)
{
	int index;
	u64 base, sz;
	struct bar_resource bar, *new;
	struct pci_dev *pdev = pcie_set->pdev;

	for (index = 2; index < 6; index++) {
		sz = pci_resource_len(pdev, index);
		if (!sz)
			continue;
		base = pci_resource_start(pdev, index);

		memset(&bar, 0, sizeof(bar));
		bar.type = PF_BAR;
		bar.index = index;
		bar.phy_base = base;
		bar.size = sz;
		bar.reg_index = pf_table[index / 2 - 1].reg;
		bar.reg_mask = pf_table[index / 2 - 1].mask;
		bar.smmu_in = index / 2 * 2;
		bar.smmu_out = index / 2 * 2 - 1;

		new = pcie_bar_resource_struct_init(&bar);
		if (new)
			list_add_tail(&new->list, &pcie_set->bar_resource_head);
	}
	return 0;
}

/*
 * 20l pcie bug fix
 * 128 writes with a read back, the read back maybe not success
 * so we write another data with two readback for fix
 */
static void OVER_WRITE(pcie_dummy_mb)(struct cn_pcie_set *pcie_set)
{
	smp_wmb();
	cn_pci_reg_write32(pcie_set, PCIE_DUMMY_WRITE, 0); /* for pcie bug */
	smp_mb();
	cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
	cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE); /* for pre-fetch */
	smp_mb();
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

static void OVER_WRITE(pcie_dma_align)(struct pcie_dma_task *task,
					size_t *head, size_t *tail)
{
	struct transfer_s *t = task->transfer;
	DMA_DIR_TYPE direction = t->direction;

	if (direction == DMA_H2D) {
		*head = min(task->count, (size_t)(0x40 - (t->ca & 0x3F)));
		*head = (*head) % 0x40;
	}

	if (t->size > *head) {
		if (direction == DMA_H2D)
			*tail = (t->size - *head) % 64;
	}

	if (dma_secondary_copy == 1)
		task->dma_copy = 1;
}

static int OVER_WRITE(pcie_dma_bypass_size)(struct cn_pcie_set *pcie_set)
{
#if defined(__x86_64__)
	pcie_set->dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 16 * 1024 * 1024;
	pcie_set->dma_bypass_pinned_size = dma_bypass_pinned_size ?
				dma_bypass_pinned_size : 256 * 1024;
	pcie_set->dma_memsetD8_custom_size = dma_memsetD8_custom_size ?
				dma_memsetD8_custom_size : 128 * 1024 * 1024;
	pcie_set->dma_memsetD16_custom_size = dma_memsetD16_custom_size ?
				dma_memsetD16_custom_size : 1024 * 1024;
	pcie_set->dma_memsetD32_custom_size = dma_memsetD32_custom_size ?
				dma_memsetD32_custom_size : 1024 * 1024;
#else
	pcie_set->dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 256;
	pcie_set->dma_bypass_pinned_size = dma_bypass_pinned_size ?
				dma_bypass_pinned_size : 256;
	pcie_set->dma_memsetD8_custom_size = dma_memsetD8_custom_size ?
				dma_memsetD8_custom_size : 256;
	pcie_set->dma_memsetD16_custom_size = dma_memsetD16_custom_size ?
				dma_memsetD16_custom_size : 256;
	pcie_set->dma_memsetD32_custom_size = dma_memsetD32_custom_size ?
				dma_memsetD32_custom_size : 256;
#endif
	return 0;
}

#ifdef CONFIG_PCI_IOV
static void pcie_iov_set_numvfs(struct pci_dev *dev, int nr_virtfn)
{
	int pos;

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return;

	pci_write_config_word(dev, pos + PCI_SRIOV_NUM_VF, nr_virtfn);
}

static int pcie_verify_sriov_mmio_space(struct cn_pcie_set *pcie_set)
{
	int i;
	int pos = 0;
	int count = 0;
	short ctrl;
	struct pci_dev *dev;
	struct resource *res;

	dev = pcie_set->pdev;
	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos) {
		cn_dev_pcie_err(pcie_set, "not find ext capability");
		return -ENODEV;
	}

	for (i = 0; i < PCI_SRIOV_NUM_BARS; i++) {
		res = &dev->resource[i + PCI_IOV_RESOURCES];
		if (res->parent)
			count++;
	}

	if (count != BAR_NUMS_EACH_VF) {
		cn_dev_debug("not enough MMIO resources for SR-IOV");
		return -ENOMEM;
	}

	pci_read_config_word(dev, pos + PCI_SRIOV_CTRL, &ctrl);
	pcie_iov_set_numvfs(dev, MAX_VF_NUMS);
	ctrl |= PCI_SRIOV_CTRL_VFE | PCI_SRIOV_CTRL_MSE;

	pci_cfg_access_lock(dev);
	pci_write_config_word(dev, pos + PCI_SRIOV_CTRL, ctrl);
	msleep(100);
	pci_cfg_access_unlock(dev);

	return 0;
}

const static struct {
	int smmu_in;
	int smmu_out;
	u64 reg;
	u64 mask;
} vf_table[8] = {
	{ 5,  6, 0x890, 0x0}, /* vf0 bar2 */
	{ 9, 10, 0x8d0, 0x0}, /* vf1 bar2 */
	{13, 14, 0x910, 0x0}, /* vf2 bar2 */
	{17, 18, 0x950, 0x0}, /* vf3 bar2 */
	{ 7,  8, 0x8a0, 0x0}, /* vf0 bar4 */
	{11, 12, 0x8e0, 0x0}, /* vf1 bar4 */
	{15, 16, 0x920, 0x0}, /* vf2 bar4 */
	{19, 20, 0x960, 0x0}, /* vf3 bar4 */
};
#define AXI_CONFIG_REGISTER_BASE_ADDR    (0x10a000)

/*
 * vf0: bar0 bar2 bar4
 * vf1: bar0 bar2 bar4
 * vf2: bar0 bar2 bar4
 * vf3: bar0 bar2 bar4
 * bars have the same bar_number have a contiguous address space
 */
static int OVER_WRITE(pcie_enable_vf_bar)(struct cn_pcie_set *pcie_set)
{
	int i, j;
	int index = 0;
	u64 bar_start, bar_len;
	struct pci_dev *dev = pcie_set->pdev;
	struct bar_resource *new, bar;

	if (pcie_verify_sriov_mmio_space(pcie_set))
		return -1;

	/*
	 * enable PCIe SR-IOV VF capabilities
	 * i = 1 means won't use VF bar0 to set window
	 */

	for (i = 1; i < PCI_SRIOV_NUM_BARS; i++) {
		bar_start = pci_resource_start(dev, PCI_IOV_RESOURCES + i);
		bar_len = pci_resource_len(dev, PCI_IOV_RESOURCES + i);
		if (!bar_len)
			continue;

		for (j = 0; j < MAX_VF_NUMS; j++) {
			memset(&bar, 0, sizeof(bar));
			bar.type = VF_BAR;
			bar.index = index;
			bar.phy_base = bar_start + j * (bar_len / MAX_VF_NUMS);
			bar.size = bar_len / MAX_VF_NUMS;
			bar.smmu_in = vf_table[index].smmu_in;
			bar.smmu_out = vf_table[index].smmu_out;
			bar.reg_index = vf_table[index].reg + AXI_CONFIG_REGISTER_BASE_ADDR;
			bar.reg_mask = vf_table[index].mask;

			new = pcie_bar_resource_struct_init(&bar);
			if (!new)
				return -1;

			index++;
			list_add_tail(&new->list, &pcie_set->bar_resource_head);
		}
	}

	return 0;
}

static void OVER_WRITE(pcie_disable_vf_bar)(struct cn_pcie_set *pcie_set)
{
	int pos = 0;
	short ctrl;
	struct pci_dev *dev = pcie_set->pdev;

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos) {
		cn_dev_pcie_err(pcie_set, "find ext capability failed");
		return;
	}

	pci_read_config_word(dev, pos + PCI_SRIOV_CTRL, &ctrl);
	pcie_iov_set_numvfs(dev, 0);
	ctrl &= ~(PCI_SRIOV_CTRL_VFE | PCI_SRIOV_CTRL_MSE);

	pci_cfg_access_lock(dev);
	pci_write_config_word(dev, pos + PCI_SRIOV_CTRL, ctrl);
	msleep(100);
	pci_cfg_access_unlock(dev);
}

static int c20l_sriov_support(struct cn_pcie_set *pcie_set)
{
	int total_vfs;
	u64 vf_bar0_size;
	int vf;

	vf_bar0_size = pci_resource_len(pcie_set->pdev, PCI_IOV_RESOURCES);

	total_vfs = pci_sriov_get_totalvfs(pcie_set->pdev);
	if (total_vfs * pcie_set->pcibar[0].size != vf_bar0_size)
		return 0;

	for (vf = 0; vf < 6; vf += 2)
		if (!pci_resource_start(pcie_set->pdev, PCI_IOV_RESOURCES + vf))
			return 0;

	return 1;
}
#endif

static u64 OVER_WRITE(pcie_set_bar_window)(u64 axi_address,
		struct bar_resource *bar, struct cn_pcie_set *pcie_set)
{
	struct cn_core_set *core = pcie_set->bus_set->core;
	u64 addr = bar->window_addr;
	u64 reg = bar->reg_index;

	if (bar->type == VF_BAR) {
		cn_smmu_cau_invalid(core, bar->smmu_in);
		cn_smmu_cau_invalid(core, bar->smmu_out);
	}

	if (axi_address >= addr && axi_address < (addr + bar->size))
		return addr;

	axi_address &= (~(u64)(bar->size - 1));
	cn_pci_reg_write64(pcie_set, reg, axi_address);
	cn_pci_reg_read32(pcie_set, reg);

	bar->window_addr = axi_address;
	return axi_address;
}

static int c20l_dma_bypass_smmu(int phy_ch, bool en, struct cn_pcie_set *pcie_set)
{
	int ret;

	phy_ch = phy_ch + DMA_SMMU_STREAM_ID;
	ret = cn_smmu_cau_bypass(pcie_set->bus_set->core, phy_ch, en);

	return ret;
}

static struct cn_pci_ops c20l_private_ops = {
	.dump_reg = OVER_WRITE(pcie_dump_reg),
	.fill_desc_list = OVER_WRITE(pcie_fill_desc_list),
	.pci_mb = OVER_WRITE(pcie_dummy_mb),
	.check_available = OVER_WRITE(pcie_check_available),
	.dma_align = OVER_WRITE(pcie_dma_align),
	.dma_bypass_size = OVER_WRITE(pcie_dma_bypass_size),
	.enable_pf_bar = OVER_WRITE(pcie_enable_pf_bar),
	.set_bar_window = OVER_WRITE(pcie_set_bar_window),
#ifdef CONFIG_PCI_IOV
	.enable_vf_bar = OVER_WRITE(pcie_enable_vf_bar),
	.disable_vf_bar = OVER_WRITE(pcie_disable_vf_bar),
	.sriov_support = c20l_sriov_support,
#endif
	.sriov_vf_init = c20l_sriov_vf_init,
	.sriov_vf_exit = c20l_sriov_vf_exit,
	.iov_virtfn_bus = c20l_pcie_iov_virtfn_bus,
	.iov_virtfn_devfn = c20l_pcie_iov_virtfn_devfn,
	.sriov_pre_init = c20l_sriov_pre_init,
	.sriov_later_exit = c20l_sriov_later_exit,
	.dma_bypass_smmu = c20l_dma_bypass_smmu,
};

static void cn_pci_dev_save(struct pci_dev *pdev)
{
	/*
	 * Wake-up device prior to save.  PM registers default to D0 after
	 * reset and a simple register restore doesn't reliably return
	 * to a non-D0 state anyway.
	 */
	pci_set_power_state(pdev, PCI_D0);

	pci_save_state(pdev);
	/*
	 * Disable the device by clearing the Command register, except for
	 * INTx-disable which is set.  This not only disables MMIO and I/O port
	 * BARs, but also prevents the device from being Bus Master, preventing
	 * DMA from the device including MSI/MSI-X interrupts.  For PCI 2.3
	 * compliant devices, INTx-disable prevents legacy interrupts.
	 */
}

static void cn_pci_dev_restore(struct pci_dev *dev)
{
	pci_restore_state(dev);

	/*
	 * dev->driver->err_handler->reset_done() is protected against
	 * races with ->remove() by the device lock, which must be held by
	 * the caller.
	 */
}

/* Time to wait after a reset for device to become responsive */
#define PCIE_RESET_READY_POLL_MS 60000
static int cn_pci_dev_wait(struct pci_dev *dev, char *reset_type, int timeout)
{
	int delay = 1;
	u32 id;

	/*
	 * After reset, the device should not silently discard config
	 * requests, but it may still indicate that it needs more time by
	 * responding to them with CRS completions.  The Root Port will
	 * generally synthesize ~0 data to complete the read (except when
	 * CRS SV is enabled and the read was for the Vendor ID; in that
	 * case it synthesizes 0x0001 data).
	 *
	 * Wait for the device to return a non-CRS completion.  Read the
	 * Command register instead of Vendor ID so we don't have to
	 * contend with the CRS SV value.
	 */
	pci_read_config_dword(dev, PCI_COMMAND, &id);
	while (id == ~0) {
		if (delay > timeout) {
			cn_dev_warn("not ready %dms after %s; giving up",
				delay - 1, reset_type);
			return -ENOTTY;
		}

		if (delay > 1000)
			cn_dev_info("not ready %dms after %s; waiting",
					delay - 1, reset_type);

		msleep(delay);
		delay *= 2;
		pci_read_config_dword(dev, PCI_COMMAND, &id);
	}

	if (delay > 1000)
		cn_dev_info("ready %dms after %s",
				delay - 1, reset_type);

	return 0;
}

/**
 * pci_wait_for_pending - wait for @mask bit(s) to clear in status word @pos
 * @dev: the PCI device to operate on
 * @pos: config space offset of status word
 * @mask: mask of bit(s) to care about in status word
 *
 * Return 1 when mask bit(s) in status word clear, 0 otherwise.
 */
static int cn_pci_wait_for_pending(struct pci_dev *dev, int pos, u16 mask)
{
	int i;

	/* Wait for Transaction Pending bit clean */
	for (i = 0; i < 4; i++) {
		u16 status;

		if (i)
			msleep((1 << (i - 1)) * 100);

		pci_read_config_word(dev, pos, &status);
		if (!(status & mask))
			return 1;
	}

	return 0;
}

/**
 * pci_wait_for_pending_transaction - waits for pending transaction
 * @dev: the PCI device to operate on
 *
 * Return 0 if transaction is pending 1 otherwise.
 */
static int cn_pci_wait_for_pending_transaction(struct pci_dev *dev)
{
	if (!pci_is_pcie(dev))
		return 1;

	return cn_pci_wait_for_pending(dev, pci_pcie_cap(dev) + PCI_EXP_DEVSTA,
			PCI_EXP_DEVSTA_TRPND);
}

static int cn_pci_link_reset(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set;
	int pos_cap, ret;
	u32 cor_mask, uncor_mask, root_command;
	struct pci_dev *pdev;
	u16 slot_ctrl, slot_ctrl_orig;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	pdev = pcie_set->pdev->bus->self;
	cn_dev_info("pcie link reset");

	pos_cap = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);

	cn_pci_dev_save(pcie_set->pdev);
	if (pos_cap != 0) {
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, &cor_mask);
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, &uncor_mask);
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_ROOT_COMMAND, &root_command);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, 0xffffffff);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, 0xffffffff);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_ROOT_COMMAND, 0x0);
	}

	pcie_capability_read_word(pdev, PCI_EXP_SLTCTL, &slot_ctrl);
	slot_ctrl_orig = slot_ctrl;
	slot_ctrl &= ~(0x20);
	/*fix hotplug bug*/
	smp_mb();
	pcie_capability_write_word(pdev, PCI_EXP_SLTCTL, slot_ctrl);

	if (!cn_pci_wait_for_pending_transaction(pcie_set->pdev))
		cn_dev_err("timed out waiting for pending transaction; performing soft reset anyway");

	cn_pci_link_set(pcie_set, false);
	msleep(100);
	cn_pci_link_set(pcie_set, true);

	/*
	 * Per PCIe r4.0, sec 6.6.2, a device must complete an FLR within
	 * 100ms, but may silently discard requests while the FLR is in
	 * progress.  Wait 100ms before trying to access the device.
	 */
	msleep(500);

	ret = cn_pci_dev_wait(pcie_set->pdev,
			"link reset", PCIE_RESET_READY_POLL_MS);

	/* fix hotplug bug */
	smp_mb();
	pcie_capability_write_word(pdev, PCI_EXP_SLTCTL, slot_ctrl_orig);

	if (pos_cap != 0) {
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, cor_mask);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, uncor_mask);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_ROOT_COMMAND, root_command);
	}

	cn_pci_dev_restore(pcie_set->pdev);

	return 0;
}

__attribute__((unused)) static int c20l_hotreset_gen1_to_gen3(struct cn_pcie_set *pcie_set)
{
	int ret;
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_dev *parent = pdev->bus->self;
	u16 link_status, lnkctl2;
	u16 current_speed, target_vector;
	u32 current_width, target_width;
	u32 reset_cnt = 10, link_reset = 0;

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	target_width = current_width;
	target_vector = PCI_EXP_LNKCTL2_TLS_8_0GT;

	cn_dev_info("PCIe link speed is %s\n", PCIE_SPEED_STR(current_speed));
	cn_dev_info("PCIe link width is x%d\n", current_width);

	while ((current_speed != PCI_EXP_LNKSTA_CLS_8_0GB) ||
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
		if ((lnkctl2 & PCI_EXP_LNKCTL2_TLS) < target_vector) {
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

		link_reset = 1;
		cn_pci_link_reset(pcie_set);
		reset_cnt--;

		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
		current_speed = link_status & PCI_EXP_LNKSTA_CLS;
		current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
		if (current_width > target_width)
			target_width = current_width;

		cn_dev_info("PCIe link change speed to %s\n", PCIE_SPEED_STR(current_speed));
		cn_dev_info("PCIe link change width to x%d\n", current_width);

		if (current_width != 16 && reset_cnt > 7)
			goto retry;

		if (reset_cnt == 0) {
			cn_dev_err("pcie change speed fail");
			return -1;
		}
	}

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


static int c20l_bug_fix_list(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_dev *parent;
	struct pci_dev *grandparent;
	u16 sdevid, device_id;
	u32 lnkcap, port_number, i, val;
	u64 base_addr, bar_len, bar_paddr;
	void __iomem  *bar_vaddr;
	int ret;

	/*
	 * MLU270_X5K subsystem_id 0x16
	 * MLU270_S4 subsystem_id 0x12
	 * PLX PEX 8796 Multi-Root Switch device_id 0x8796
	 *
	 */
	pci_read_config_word(pdev, PCI_SUBSYSTEM_ID, &sdevid);
	if (((sdevid == 0x16) || (sdevid == 0x12)) && pdev->bus && pdev->bus->self) {
		parent = pdev->bus->self;
		pci_read_config_word(parent, PCI_DEVICE_ID, &device_id);
		if (device_id == 0x8796 && parent->bus && parent->bus->self) {
			grandparent = parent->bus->self;
			pcie_capability_read_dword(parent, PCI_EXP_LNKCAP, &lnkcap);
			port_number = (lnkcap & PCI_EXP_LNKCAP_PN) >> 24;
			base_addr = port_number*0x1000;
			bar_paddr = pci_resource_start(grandparent, 0);
			bar_len = pci_resource_len(grandparent, 0);
			bar_vaddr = cn_ioremap(bar_paddr, bar_len);
			iowrite32(0x7f, bar_vaddr + base_addr + 0xbc8);
			pr_info("pcie bridge upstream port dump: ");
			for (i = 0; i < 8; i++) {
				val = ioread32(bar_vaddr + base_addr + 0x118 + i*4);
				pr_info("0x%x ", val);
			}
			pr_info("\n");
			cn_iounmap((void *)bar_vaddr);
		}
	}

	/*
	 *  1. Gen1 -> Gen3
	 *  description:
	 *  fix method: do hot reset
	 */
#if (!defined(__arm__) && !defined(__aarch64__))
	pci_read_config_word(pdev, PCI_SUBSYSTEM_ID, &sdevid);

	if (sdevid != 0x25) {
		if (c20l_hotreset_gen1_to_gen3(pcie_set))
			return -1;
	}
#endif
#if (defined(__i386__) || defined(__x86_64__) || defined(__X86__))
	ret = cn_pci_link_check(pcie_set);
	if (ret) {
		return -EACCES;
	}
#endif


	/*
	 *  2. dma outbound bug
	 *  description
	 *	1. HOST do DMA transfer inbound
	 *	2. ARM do outbound write
	 *	3. HOST do config write
	 *		do 1.2.3 step together
	 * fix method: disable pcie order check
	 */
	cn_pci_reg_write32(pcie_set, LOCAL_MANAGEMENT_REGISTER + 0x208, 0xc0000000);
	cn_pci_reg_read32(pcie_set, LOCAL_MANAGEMENT_REGISTER + 0x208);

	/*
	 *  PCIe ASPM L1 Error
	 *  description:
	 *  1.PCIe device enable aspm
	 *  2.PCIe device Hang
	 *
	 * fix method: disable aspm
	 */
	ret = pcie_capability_clear_word(pdev, PCI_EXP_LNKCTL, PCI_EXP_LNKCTL_ASPMC);
	if (ret) {
		cn_dev_err("disable aspm fail");
		return -1;
	}
	/* public bug list */
	bug_fix_list(pcie_set);
	return 0;
}

static int c20l_pcie_setup(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/*
	 *  publish ops to uper level
	 *  different cambricon ID have different ops
	 *  same cambricon ID with different wafer, change ops here
	 */
	cn_pci_ops_init(&public_ops, &c20l_private_ops);
	pcie_set->ops = &c20l_private_ops;

	/* for domain manger get hard resource */
	pcie_set->max_phy_channel = DMA_MAX_PHY_CHANNEL;

	/* soft status */
	pcie_set->share_mem_cnt = 0;
	pcie_set->is_virtfn = 0;

	pcie_set->irq_type = (isr_type_index == -1) ? isr_default_type : isr_type_index;

	return 0;
}

static int c20l_pcie_domain_get_resource(void *pcie, struct domain_resource *resource)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/* for domain manger get hard resource */
	resource->id = pcie_set->id;
	resource->max_phy_channel = DMA_MAX_PHY_CHANNEL;
	resource->cfg_reg_size = pcie_set->pcibar[0].size / 2;
	resource->share_mem_size = pcie_set->pcibar[0].size / 2;
	resource->share_mem_base = C20L_AXI_SHM_BASE;
	resource->vf_cfg_limit = 16 * 1024;

	return 0;
}

/*
 * BAR0 have 256MB pcie space
 * |-----128MB regiter area------|-----128MB share memory-----|
 */
static int c20l_pcie_reg_area_init(struct cn_pcie_set *pcie_set)
{
	struct pcibar_seg_s *bar_seg;
	struct pcibar_s *bar = &pcie_set->pcibar[0];

	bar_seg = &bar->seg[0];
	bar_seg->base = bar->base;
	bar_seg->size = bar->size / 2;
	bar_seg->virt = cn_ioremap(bar_seg->base, bar_seg->size);
	if (!bar_seg->virt)
		return -1;

	pcie_set->reg_virt_base = bar_seg->virt;
	pcie_set->reg_phy_addr = bar_seg->base;
	pcie_set->reg_win_length = bar_seg->size;

	return 0;
}

static int c20l_pcie_shm_area_init(struct cn_pcie_set *pcie_set)
{
	u64 size;
	const void *domain = NULL;
	struct pcibar_seg_s *bar_seg;
	struct pcibar_s *bar = &pcie_set->pcibar[0];

	domain = cn_dm_get_domain_early(pcie_set->bus_set, DM_FUNC_OVERALL);
	if (!domain)
		return -ENODEV;

	size = cn_dm_pci_get_bars_shm_sz(domain, 0);
	cn_dev_info("get from domain size:%llx", size);

	bar_seg = &bar->seg[1];
	bar_seg->base = bar->base + bar->size / 2;
	bar_seg->size = size;

	bar_seg->virt = cn_ioremap_wc(bar_seg->base, bar_seg->size);
	if (!bar_seg->virt)
		return -1;

	pcie_set->share_mem_cnt = 1;
	pcie_set->share_mem[0].virt_addr = bar_seg->virt;
	pcie_set->share_mem[0].phy_addr = bar_seg->base;
	pcie_set->share_mem[0].win_length = bar_seg->size;
	pcie_set->share_mem[0].type = CN_SHARE_MEM_DEV;
	pcie_set->share_mem[0].device_addr = C20L_AXI_SHM_BASE;

	return 0;
}

/* fix vf set vf2pf dma reg then unload driver, pf load driver will can not
 * get dma resource at once and dma will error.
 */
static int c20l_pcie_clear_vf_dma(struct cn_pcie_set *pcie_set)
{
	int pdma_i;

	for (pdma_i = 0; pdma_i < pcie_set->max_phy_channel; pdma_i++) {
		cn_pci_reg_write32(pcie_set, V2PDMA_CTRL(pdma_i), 0);
		cn_pci_reg_read32(pcie_set, V2PDMA_CTRL(pdma_i));
	}

	return 0;
}

static int c20l_pcie_dma_pre_init(struct cn_pcie_set *pcie_set)
{
	const void *domain = NULL;
	u32 func_id;

	domain = cn_dm_get_domain_early(pcie_set->bus_set, DM_FUNC_OVERALL);
	if (!domain) {
		cn_dev_err("get from domain failed");
		return -EINVAL;
	}

	func_id = cn_dm_get_func_id(domain);
	cn_dev_info("Domain[%d: 0x%px]", func_id, domain);
	pcie_set->dma_res.channel_mask = cn_dm_pci_get_dma_ch(domain);
	pcie_set->max_inbound_cnt = hweight32(pcie_set->dma_res.channel_mask) * 2;

	cn_dev_debug("get from domain mask:0x%x",
			pcie_set->dma_res.channel_mask);

	pcie_set->dma_desc_total_size = DMA_DESC_TOTAL_SIZE;
	pcie_set->dma_buffer_size = DMA_BUFFER_SIZE;
	pcie_set->max_channel = DMA_MAX_CHANNEL;

	/* fix vf dma bug*/
	c20l_pcie_clear_vf_dma(pcie_set);

	return 0;
}

static void c20l_outbound_pre_init(struct cn_pcie_set *pcie_set)
{
	const void *domain = NULL;

	if (cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		domain = cn_dm_get_domain_early(pcie_set->bus_set, DM_FUNC_PF);
		if (!domain) {
			pr_info("Domain API: get PF domain failed. exit\n");
			return;
		}

		if (-1u == cn_dm_pci_get_ob_mask(domain)) {
			domain = cn_dm_get_domain_early(pcie_set->bus_set,
							DM_FUNC_OVERALL);
		}

		pcie_set->ob_mask = cn_dm_pci_get_ob_mask(domain);
	} else
		pcie_set->ob_mask =
			((u64)((1ULL << OUTBOUND_CNT) - 1)) << OUTBOUND_FIRST;

	pcie_set->ob_size = OUTBOUND_SIZE;
	pcie_set->ob_axi_addr = OUTBOUND_AXI_BASE|(ALL_CFG_UPPER_ADDR << 32);
	pcie_set->ob_cnt = hweight64(pcie_set->ob_mask);
	pcie_set->ob_total_size = pcie_set->ob_size * pcie_set->ob_cnt;
	cn_dev_info("ob_mask:0x%llx ob_cnt:%d ob_size:0x%x ob_total_size:%x ob_axi_addr:%llx",
			pcie_set->ob_mask, pcie_set->ob_cnt, pcie_set->ob_size,
			pcie_set->ob_total_size, pcie_set->ob_axi_addr);
}

static int pcie_pre_init_hw(struct cn_pcie_set *pcie_set)
{
	int i;
	unsigned long flags;
	unsigned int status;
#if 0
	pcie_outbound_reg(pcie_set);
#endif
	adjust_dev_param(pcie_set);

	set_bar_default_window(pcie_set);

	isr_hw_enable[pcie_set->irq_type](pcie_set);

	pcie_gic_mask_all(pcie_set);

	/* NOTE: clear dma interrupt before enable it*/
	status = cn_pci_reg_read32(pcie_set, DI);
	cn_pci_reg_write32(pcie_set, DI, status);

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_res.channel_mask & (1 << i)) {
			spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
			pcie_gic_unmask(PCIE_IRQ_DMA + i, pcie_set);
			spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);
		}
	}
	cn_pci_reg_write32(pcie_set, DIE, 0xF0F);
	cn_pci_reg_write32(pcie_set, DID, 0x0F0);

	return 0;
}

static int c201_check_noc_bus(struct cn_pcie_set *pcie_set)
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

static int c20l_pcie_pre_init(void *pcie)
{
	int ret;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	ret = c20l_pcie_reg_area_init(pcie_set);
	if (ret)
		return -1;

	ret = c201_check_noc_bus(pcie_set);
	if (ret)
		goto exit;

	if (c20l_bug_fix_list(pcie_set))
		goto exit;

	ret = c20l_pcie_shm_area_init(pcie_set);
	if (ret)
		goto exit;

	ret = pcie_register_bar(pcie_set);
	if (ret)
		goto exit;

	ret = c20l_pcie_dma_pre_init(pcie_set);
	if (ret)
		goto exit;

	c20l_outbound_pre_init(pcie_set);

	ret = do_pcie_init(pcie_set);
	if (ret)
		goto exit;

	return 0;
exit:
	cn_dev_pcie_err(pcie_set, "bar init error");
	bar_deinit(pcie_set);
	return -1;
}

static int c20l_pcie_pre_exit(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	if (pcie_interrupt_exit(pcie_set))
		return -1;

	bar_deinit(pcie_set);
	return 0;
}

struct cn_pci_info c20l_pci_info = {
	.setup = c20l_pcie_setup,
	.pre_init = c20l_pcie_pre_init,
	.pre_exit = c20l_pcie_pre_exit,
	.get_resource = c20l_pcie_domain_get_resource,
	.dev_name = "c20l"
};
