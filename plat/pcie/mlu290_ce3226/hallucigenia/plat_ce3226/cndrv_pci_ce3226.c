/************************************************************************
 *
 *  @file cndrv_pci_ce3226.c
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

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "../../pcie_dma.h"
#include "../../pcie_bar.h"
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_pci_ce3226.h"
#include "cndrv_debug.h"

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
	{205, "pcie_dma0"},
	{206, "pcie_dma1"},
};

/*
 *  include public c code
 *  warnning: do not remove it to the top of file
 *            otherwise will have build errors
 */
#include "../../pcie_common.c"
#include "../hallucigenia.h"
#define OVER_WRITE(f) ce3226_##f

static int ce3226_bug_fix_list(struct cn_pcie_set *pcie_set);

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
		 * hardware spec recommd set the value 14
		 */
		value = 0x0ea40;
		break;

	default:
		value = 0x1ea40;
		break;
	}
#else
	value = 0x0ea40;
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
	unsigned long count = 0;
	struct scatterlist *sg;
	int desc_offset = 0;
	unsigned int len_ctrl;

	ipu_ram_dma_addr = channel->ram_addr;

	if (channel->direction != DMA_P2P) {
		for_each_sg(channel->sg, sg, channel->nents, i) {
			cpu_dma_addr = sg_dma_address(sg);
			count = sg_dma_len(sg);

			if (((cpu_dma_addr & 0x3) != 0) || ((ipu_ram_dma_addr & 0x3) != 0)
							|| ((count & 0x3) != 0)) {
				cn_dev_pcie_err(channel->pcie_set,
				"No 4bit align:cpu_addr:%#lx dev_addr:%#llx count:%lx",
						cpu_dma_addr, ipu_ram_dma_addr, count);
				return -1;
			}

			if (i != channel->nents - 1)
				len_ctrl = LENGTH_CTRL(count, 1, 0);
			else
				len_ctrl = LENGTH_CTRL(count, 0, 1);

			FILL_DESC(ipu_ram_dma_addr, cpu_dma_addr, len_ctrl,
				desc_offset, channel);

			/* write next desc addr */
			*((u64 *)(channel->task->desc_buf + desc_offset + DE_NDL)) =
				channel->desc_device_va + desc_offset + DESC_SIZE;
			*((u32 *)(channel->task->desc_buf + desc_offset + DE_ADP)) = 0;
			*((u64 *)(channel->task->desc_buf + desc_offset + DE_TLP_HEAD_ATTRL)) = 0;

			desc_offset += DESC_SIZE;

			ipu_ram_dma_addr += count;
		}
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

		len_ctrl = LENGTH_CTRL(count, 0, 1);
		FILL_DESC(ipu_ram_dma_addr, cpu_dma_addr, len_ctrl,
			desc_offset, channel);

		/* write next desc addr */
		*((u64 *)(channel->task->desc_buf + desc_offset + DE_NDL)) =
			channel->desc_device_va + desc_offset + DESC_SIZE;
		*((u32 *)(channel->task->desc_buf + desc_offset + DE_ADP)) = 0;
		*((u64 *)(channel->task->desc_buf + desc_offset + DE_TLP_HEAD_ATTRL)) = 0;

		desc_offset += DESC_SIZE;
	}

	channel->desc_len = desc_offset;
	memcpy_toio(channel->desc_virt_base, channel->task->desc_buf, desc_offset);

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
static struct pcie_dump_reg_s ce3226_reg[] = {
		{"PCIE DMA int status", DBO + 0xa0},
		{"PCIE status", CTL_BASE + 0X4},
		{"PCIE local error", CTL_BASE + 0x620c},
		{"PCIE PHY status", CTL_BASE + 0x6238},
		{"PCIE ltssm FSM", CTL_BASE + 0x8020},
		{"PCIE ltssm other", CTL_BASE + 0x104},
		{NULL, CTL_BASE + 0x110},
		{NULL, CTL_BASE + 0x5238},
		{NULL, CTL_BASE + 0x5214},
		{"PCIE DMA chn0 ctrl", DBO},
		{NULL, DBO + 0x4},
		{NULL, DBO + 0x8},
		{"PCIE DMA chn1 ctrl", DBO + 0x14},
		{NULL, DBO + 0x18},
		{NULL, DBO + 0x1c},

		{"PCIE GIC mask", GIC_MASK},
		{NULL, GIC_MASK + 4},
		{NULL, GIC_MASK + 8},
		{NULL, GIC_MASK + 12},
		{NULL, GIC_MASK + 16},
		{NULL, GIC_MASK + 20},
		{NULL, GIC_MASK + 24},
		{NULL, GIC_MASK + 28},
		{NULL, GIC_MASK + 32},
		{NULL, GIC_MASK + 36},
		{NULL, GIC_MASK + 40},
		{NULL, GIC_MASK + 44},
		{NULL, GIC_MASK + 48},
		{NULL, GIC_MASK + 52},
		{NULL, GIC_MASK + 56},
		{NULL, GIC_MASK + 60},
		{"PCIE GIC status", GIC_STATUS},
		{NULL, GIC_STATUS + 4},
		{NULL, GIC_STATUS + 8},
		{NULL, GIC_STATUS + 12},
		{NULL, GIC_STATUS + 16},
		{NULL, GIC_STATUS + 20},
		{NULL, GIC_STATUS + 24},
		{NULL, GIC_STATUS + 28},
		{NULL, GIC_STATUS + 32},
		{NULL, GIC_STATUS + 36},
		{NULL, GIC_STATUS + 40},
		{NULL, GIC_STATUS + 44},
		{NULL, GIC_STATUS + 48},
		{NULL, GIC_STATUS + 52},
		{NULL, GIC_STATUS + 56},
		{NULL, GIC_STATUS + 60},

		{"PCIE MSIX vector count", GIC_MSIX_VECTOR_COUNT},
		{"PCIE MSIX clear register", GIC_MSIX_CLR},
		{NULL, GIC_MSIX_CLR + 4},
		{NULL, GIC_MSIX_CLR + 8},
		{NULL, GIC_MSIX_CLR + 12},
		{NULL, GIC_MSIX_CLR + 16},
		{NULL, GIC_MSIX_CLR + 20},
		{NULL, GIC_MSIX_CLR + 24},
		{NULL, GIC_MSIX_CLR + 28},

		{"PCIE GIC_CTRL", GIC_CTRL},
		{NULL, GBO + 0x1000},
};

static void OVER_WRITE(pcie_dump_reg)(struct cn_pcie_set *pcie_set)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ce3226_reg); i++) {
		if (ce3226_reg[i].desc)
			cn_dev_pcie_err(pcie_set, "%s:", ce3226_reg[i].desc);
		cn_dev_pcie_err(pcie_set, "[0x%lx]=%#08x", ce3226_reg[i].reg,
		cn_pci_reg_read32(pcie_set, ce3226_reg[i].reg));
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

const static struct {
	u64 reg;
	u64 mask;
} pf_table[] = {
	{BAR2_TO_AXI_ADDR_REG_L, 0x0}, /* pf bar2 */
	{BAR4_TO_AXI_ADDR_REG_L, 0x0}, /* pf bar4 */
};

static int OVER_WRITE(pcie_enable_pf_bar)(struct cn_pcie_set *pcie_set)
{
	int index = 4;
	u64 base, sz;
	struct bar_resource bar, *new;
	struct pci_dev *pdev = pcie_set->pdev;

	sz = pci_resource_len(pdev, index);
	if (!sz)
		return -1;

	base = pci_resource_start(pdev, index);

	memset(&bar, 0, sizeof(bar));
	bar.type = PF_BAR;
	bar.index = index;
	bar.phy_base = base;
	bar.bus_base = cn_pci_bus_address(pdev, index);
	bar.size = sz;
	bar.reg_index = pf_table[index / 2 - 1].reg;
	bar.reg_mask = pf_table[index / 2 - 1].mask;
	bar.smmu_in = index / 2 * 2;
	bar.smmu_out = index / 2 * 2 - 1;

	new = pcie_bar_resource_struct_init(&bar);
	if (new)
		list_add_tail(&new->list, &pcie_set->bar_resource_head);

	return 0;
}

static struct cn_pci_ops ce3226_private_ops = {
	.dump_reg = OVER_WRITE(pcie_dump_reg),
	.fill_desc_list = OVER_WRITE(pcie_fill_desc_list),
	.pci_mb = OVER_WRITE(pcie_dummy_mb),
	.check_available = OVER_WRITE(pcie_check_available),
	.dma_align = OVER_WRITE(pcie_dma_align),
	.enable_pf_bar = OVER_WRITE(pcie_enable_pf_bar),
};

static int ce3226_pcie_setup(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/*
	 *  publish ops to uper level
	 *  different cambricon ID have different ops
	 *  same cambricon ID with different wafer, change ops here
	 */
	cn_pci_ops_init(&public_ops, &ce3226_private_ops);
	pcie_set->ops = &ce3226_private_ops;

	/* for domain manger get hard resource */
	pcie_set->max_phy_channel = DMA_MAX_PHY_CHANNEL;

	/* soft status */
	pcie_set->share_mem_cnt = 0;

	pcie_set->irq_type = (isr_type_index == -1) ? isr_default_type : isr_type_index;

	return 0;
}

static int ce3226_pcie_domain_get_resource(void *pcie, struct domain_resource *resource)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	resource->id = pcie_set->id;
	resource->max_phy_channel = DMA_MAX_PHY_CHANNEL;
	resource->cfg_reg_size = pcie_set->pcibar[0].size / 2;
	resource->share_mem_size = pcie_set->pcibar[0].size / 2;
	resource->vf_cfg_limit = 16 * 1024;

	return 0;
}

static int ce3226_bug_fix_list(struct cn_pcie_set *pcie_set)
{
	unsigned int value;

	value = cn_pci_reg_read32(pcie_set, LOCAL_ASPM_L1_ENTRY_TIMEOUT);
	value |= 0xfffff;
	cn_pci_reg_write32(pcie_set, LOCAL_ASPM_L1_ENTRY_TIMEOUT, value);
	/* public bug list */
	bug_fix_list(pcie_set);
	return 0;
}

/*
 * BAR0 have 16MB pcie space for regiter area
 */
static int ce3226_pcie_reg_area_init(struct cn_pcie_set *pcie_set)
{
	struct pcibar_seg_s *bar_seg;
	struct pcibar_s *bar = &pcie_set->pcibar[0];

	bar_seg = &bar->seg[0];
	bar_seg->size = bar->size;
	bar_seg->base = bar->base;
	bar_seg->virt = cn_ioremap(bar_seg->base, bar_seg->size);
	if (!bar_seg->virt)
		return -1;

	pcie_set->reg_virt_base = bar_seg->virt;
	pcie_set->reg_phy_addr = bar_seg->base;
	pcie_set->reg_win_length = bar_seg->size;

	return 0;
}

/*
 * BAR2 have 32MB pcie space for share memory
 */
static int ce3226_pcie_shm_area_init(struct cn_pcie_set *pcie_set)
{
	struct pcibar_seg_s *bar_seg;
	struct pcibar_s *bar;
	struct pci_dev *pdev = pcie_set->pdev;
	int index = 2;
	u64 sz, axi_address;

	sz = pci_resource_len(pdev, index);
	if (!sz) {
		cn_dev_err("no enough MMIO space for PF bar%d", index);
		return -1;
	}
	pcie_set->pcibar[index].base = pci_resource_start(pdev, index);
	pcie_set->pcibar[index].size = sz;

	bar = &pcie_set->pcibar[index];
	bar_seg = &bar->seg[0];
	bar_seg->base = bar->base;
	bar_seg->size = bar->size;
	bar_seg->virt = cn_ioremap_wc(bar_seg->base, bar_seg->size);
	if (!bar_seg->virt)
		return -1;

	pcie_set->share_mem_cnt = 1;
	pcie_set->share_mem[0].virt_addr = bar_seg->virt;
	pcie_set->share_mem[0].phy_addr = bar_seg->base;
	pcie_set->share_mem[0].win_length = bar_seg->size;
	pcie_set->share_mem[0].type = CN_SHARE_MEM_DEV;
	pcie_set->share_mem[0].device_addr = CE3226_AXI_SHM_BASE;

	cn_dev_info("share memory virt:%#llx, phy:%#llx, size:%#llx",
			(u64)bar_seg->virt, bar_seg->base, bar_seg->size);

	axi_address = CE3226_AXI_SHM_BASE;
	axi_address &= (~(u64)(bar_seg->size - 1));
	cn_pci_reg_write64(pcie_set, BAR2_TO_AXI_ADDR_REG_L, axi_address);
	cn_pci_reg_read32(pcie_set, BAR2_TO_AXI_ADDR_REG_L);

	return 0;
}

static int ce3226_pcie_dma_pre_init(struct cn_pcie_set *pcie_set)
{
	/* get from domain */
	pcie_set->dma_phy_channel_mask = MAX_PHY_CHANNEL_MASK;

	cn_dev_debug("get from domain mask:0x%x",
			pcie_set->dma_phy_channel_mask);

	pcie_set->shared_desc_total_size = SHARED_DMA_DESC_TOTAL_SIZE;
	pcie_set->priv_desc_total_size = PRIV_DMA_DESC_TOTAL_SIZE;
	pcie_set->dma_buffer_size = DMA_BUFFER_SIZE;
	pcie_set->per_desc_size = DMA_DESC_PER_SIZE;
	pcie_set->max_inbound_cnt = 8;

	return 0;
}

static void ce3226_outbound_pre_init(struct cn_pcie_set *pcie_set)
{
	pcie_set->ob_mask = (u64)((1ULL << OUTBOUND_CNT) - 1) << OUTBOUND_FIRST;
	pcie_set->ob_cnt = hweight64(pcie_set->ob_mask);
	pcie_set->ob_size = OUTBOUND_SIZE;
	pcie_set->ob_total_size = pcie_set->ob_size * pcie_set->ob_cnt;
	pcie_set->ob_axi_addr = OUTBOUND_AXI_BASE | (ALL_CFG_UPPER_ADDR << 32);
}

static int ce3226_check_noc_bus(struct cn_pcie_set *pcie_set)
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

static int ce3226_pcie_pre_init(void *pcie)
{
	int ret;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	ret = ce3226_pcie_reg_area_init(pcie_set);
	if (ret)
		return -1;

	ret = ce3226_check_noc_bus(pcie_set);
	if (ret)
		goto exit;

	ce3226_memory_and_d2d_init(pcie);

	if (ce3226_bug_fix_list(pcie_set))
		goto exit;

	ret = ce3226_pcie_shm_area_init(pcie_set);
	if (ret)
		goto exit;

	ret = pcie_register_bar(pcie_set);
	if (ret)
		goto exit;

	ret = ce3226_pcie_dma_pre_init(pcie_set);
	if (ret)
		goto exit;

	ce3226_outbound_pre_init(pcie_set);

	ret = do_pcie_init(pcie_set);
	if (ret)
		goto exit;

	return 0;
exit:
	bar_deinit(pcie_set);
	return -1;
}

static int ce3226_pcie_pre_exit(void *pcie)
{
	return 0;
}

struct cn_pci_info ce3226_pci_info = {
	.setup = ce3226_pcie_setup,
	.pre_init = ce3226_pcie_pre_init,
	.pre_exit = ce3226_pcie_pre_exit,
	.get_resource = ce3226_pcie_domain_get_resource,
	.dev_name = "ce3226"
};
