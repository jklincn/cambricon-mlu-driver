/************************************************************************
 *
 *  @file cndrv_pci_c20l_vf.c
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

#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "../../pcie_dma.h"
#include "../../pcie_bar.h"
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "./cndrv_pci_c20l.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "../../pcie_common.c"

#define C20L_PCIE_SMMU_ENABLE  1
#define PHY_DMA_GO_START           0
#define PHY_INTERRUPT_HANDLE       1
#define PHY_DMA_INTERRUPT_HANDLE   2
#define PHY_DMA_INTERRUPT_FINISH   3

#define C10_ALL_CFG_UPPER_ADDR	(0x80ULL)
#define C10_PCIE_MEM_BASE	(0x6000000)
#define MBX_V2P_CTRL		(0x1000)
#define MBX_V2P_ADDR_L		(0x1004)
#define MBX_V2P_ADDR_U		(0x1008)
#define MBX_P2V_CTRL		(0x100c)
#define MBX_P2V_ADDR_L		(0x1010)
#define MBX_P2V_ADDR_U		(0x1014)

#define MSI_PENDING_STATUS_IN	(0x1800)
#define MSI_INT_CLR		(0x1804)
#define MSIX_SRC_INT_CLR	(0x1808)
#define INT_BIT_MASK		(0x180c)
#define INT_MASK		(0x1810)

#define PCIE_TO_AXI_ADDR_L(bar_i)	(0x2000 + 0x8 * bar_i)
#define PCIE_TO_AXI_ADDR_U(bar_i)	(0x2004 + 0x8 * bar_i)

#define DCTRL(ch_i)		(0x3000 + 0x14 * ch_i)
#define DSPL(ch_i)		(0x3004 + 0x14 * ch_i)
#define DSPU(ch_i)		(0x3008 + 0x14 * ch_i)
#define DMA_INT_REG(ch_i)	(0x3800 + 0x4 * ch_i)

#define DEO	(0UL)	/*dma command descriptor offset*/

	/*AXI Base Address offset Lower offset in descriptor.this is bar0/bar4 address*/
#define DE_ABAL                 (DEO+0)
	/*AXI Base Address offset Upper offset in descriptor.this is bar0/bar4 address*/
#define DE_ABAU	                (DEO+4)
	/*AXI Address Phase(AR or AW) control*/
#define DE_ADP                  (DEO+8)
	/*PCIe Base Address offset Lower offset in descriptor.
	 *this is cpu dma phy address
	 */
#define DE_PBAL	                (DEO+12)
	/*PCIe Base Address offset Upper offset
	 *in descriptor.this is cpu dma phy address
	 */
#define DE_PBAU	                (DEO+16)
	/*PCIe Lower offset in TLP header attributes */
#define DE_TLP_HEAD_ATTRL       (DEO+20)
	/*PCIe Upper offset in TLP header attributes */
#define DE_TLP_HEAD_ATTRU       (DEO+24)
	/* Length of transfer in bytes
	 * (0indicates maximum length transfer 2^24 bytes).
	 */
#define DE_LC        (DEO+28)
	/*bus status in descriptor.*/
#define DE_BS        (DEO+32)
	/*Next Descriptor Lower address*/
#define DE_NDL       (DEO+36)
	/*Next Descriptor Upper address*/
#define DE_NDU       (DEO+40)

#define LENGTH_CTRL(len, is_continue, is_interrupt) \
	((unsigned int)((len & 0xFFFFFF) | ((is_continue << 5 | is_interrupt) \
			<< 24)))

#undef  GIC_INTERRUPT_NUM
#define GIC_INTERRUPT_NUM	(5)
#define GIC_MSI_COUNT		(1)
#define GIC_MSIX_COUNT		(1)

#define C20L_DESC_SIZE                            (64)

#define C20L_VF_DMA_REG_CHANNEL_NUM             (8)

#define C20L_VF_DMA_DESC_TOTAL_SIZE             (0x100000)
#define C20L_VF_DMA_BUFFER_SIZE                 (1*1024*1024UL)
#define C20L_VF_DMA_REG_CHANNEL_NUM             (8)

#define VF_OUTBOUND_FIRST         (16)
#define VF_OUTBOUND_CNT           (2)
#define VF_OUTBOUND_POWER         (21UL)
#define VF_OUTBOUND_SIZE          (1ULL<<VF_OUTBOUND_POWER)
#define VF_OUTBOUND_SIZE_TOTAL    (VF_OUTBOUND_SIZE*VF_OUTBOUND_CNT)
#define VF_OUTBOUND_AXI_BASE      (C10_PCIE_MEM_BASE + (16UL*1024*1024))

#define DEV_CONTROL_STATUS_REG		(0xC8)

#define PCIE_DMA_IRQ		0
#define PCIE_MBX_IRQ		4

static void c20l_vf_pcie_show_desc_list(struct dma_channel_info *channel);
static void c20l_vf_pcie_dump_reg(struct cn_pcie_set *pcie_set);
static int c20l_vf_pcie_pre_exit(struct cn_pcie_set *pcie_set);


struct c20l_outbound_mem {
	void *virt_addr;
	dma_addr_t pci_addr;
};

static int c20l_vf_adjust_dev_param(struct cn_pcie_set *pcie_set)
{
	unsigned int value, t;

	if (pcie_set == NULL) {
		cn_dev_err("interface is null");
		return -EINVAL;
	}

	/*set payload*/
	pci_read_config_dword(pcie_set->pdev, DEV_CONTROL_STATUS_REG, &value);
	cn_dev_pcie_info(pcie_set, "%d PCIe DEV_CONTROL_STATUS_REG :%#x",
		__LINE__, value);
	/*
	 *if not check ,four inbound channel may be failed;
	 */
	pci_read_config_dword(pcie_set->pdev, DEV_CONTROL_STATUS_REG, &value);
	t = min((unsigned int)2, (unsigned int)((value & (0x7<<5)) >> 5));
	value &= (~(0x7 << 12));
	value |= (t << 12);
	pci_write_config_dword(pcie_set->pdev, DEV_CONTROL_STATUS_REG, value);

	pci_read_config_dword(pcie_set->pdev, DEV_CONTROL_STATUS_REG, &value);
	cn_dev_pcie_info(pcie_set, "%d PCIe DEV_CONTROL_STATUS_REG :%#x",
		__LINE__, value);

	return 0;
}

struct c20l_pcie_dump_reg_s {
	char *desc;
	unsigned long reg;
};

static void c20l_vf_pcie_dump_reg(struct cn_pcie_set *pcie_set)
{
	int i;
	struct c20l_pcie_dump_reg_s reg[] = {
		{"PCIE DMA chn0 INT STATU", DMA_INT_REG(0)},
		{"PCIE DMA chn1 INT STATU", DMA_INT_REG(0)},
		{"PCIE DMA chn2 INT STATU", DMA_INT_REG(0)},
		{"PCIE DMA chn3 INT STATU", DMA_INT_REG(0)},
		{"PCIE DMA chn0 ctrl", DCTRL(0)},
		{NULL, DSPL(0)},
		{NULL, DSPU(0)},
		{"PCIE DMA chn1 ctrl", DCTRL(1)},
		{NULL, DSPL(1)},
		{NULL, DSPU(1)},
		{"PCIE DMA chn2 ctrl", DCTRL(2)},
		{NULL, DSPL(2)},
		{NULL, DSPU(2)},
		{"PCIE DMA chn0 ctrl", DCTRL(3)},
		{NULL, DSPL(3)},
		{NULL, DSPU(3)},
		{"PCIE GIC mask", INT_BIT_MASK},
		{"PCIE MSI clear register", MSI_INT_CLR},
		{"PCIE MSIX clear register", MSIX_SRC_INT_CLR},
	};

	if (pcie_set->irq_type == 0)
		cn_dev_pcie_info(pcie_set, "DMA use msi interrpt");
	else if (pcie_set->irq_type == 1)
		cn_dev_pcie_info(pcie_set, "DMA use msix interrpt");
	else
		cn_dev_pcie_err(pcie_set, "VF don't support intx interrpt");

	for (i = 0; i < (sizeof(reg) / sizeof(reg[0])); i++) {
		if (reg[i].desc) {
			cn_dev_pcie_err(pcie_set, "%s:", reg[i].desc);
		}
		cn_dev_pcie_err(pcie_set,
			"[0x%lx]=%#08x", reg[i].reg,
			cn_pci_reg_read32(pcie_set, reg[i].reg));
	}
}

static void c20l_vf_pcie_mb(struct cn_pcie_set *pcie_set)
{
	struct dma_channel_info *channel;
	void __iomem *virt_base;

	channel = &pcie_set->dma_channels[0];

	if (!channel) {
		cn_dev_info("vf_pcie_mb return.\n");
		usleep_range(10, 20);
		return;
	}

	virt_base = channel->desc_virt_base + channel->desc_size - 4;
	iowrite32(0, virt_base);

	smp_wmb();
	iowrite32(0, virt_base); /* for pcie bug */
	smp_mb();
	ioread32(virt_base);
	ioread32(virt_base); /* for pre-fetch */
	smp_mb();
}

static void c20l_vf_dma_align(struct pcie_dma_task *task, size_t *head, size_t *tail)
{
	struct transfer_s *t = task->transfer;
	DMA_DIR_TYPE direction = t->direction;

	if (direction == DMA_H2D) {
		*head = min(task->count, (size_t)(0x40 - (t->ca & 0x3F)));
		*head = (*head) % 0x40;
	}

	if (t->size > *head) {
		if (direction == DMA_H2D) {
			*tail = (t->size - *head) % 64;
		}
	}
}

static irqreturn_t c20l_vf_pcie_dma_interrupt_handle(int index, void *data)
{
	unsigned int interrupt_status, status_i;
	unsigned int channel_bit, max_phy_channel_mask;
	int phy_channel;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct dma_channel_info *channel;

	/*
	 *  do all dma task in one interrupt, set do_dma_irq_status 1
	 *  other interrupt just return, no need to read/write DI
	 */
	if (pcie_set->do_dma_irq_status == 0) {
		pcie_set->do_dma_irq_status = 1;
	} else {
		return IRQ_HANDLED;
	}

	/*
	 * read dma interrupt register to get whitch channel generate interrupt.
	 * This interrupt may be done or error.not is done and error.
	 */

	interrupt_status = 0;
	for(phy_channel = 0; phy_channel < pcie_set->max_phy_channel; phy_channel++) {
		status_i = cn_pci_reg_read32(pcie_set, DMA_INT_REG(phy_channel));
		if ((!status_i) || status_i == -1U) {
			continue;
		}

		interrupt_status |= status_i << phy_channel;
		if (status_i) {
			cn_pci_reg_write32(pcie_set, DMA_INT_REG(phy_channel), status_i);
		}
	}
	if (!interrupt_status) {
		return IRQ_HANDLED;
	}

	channel_bit = (1|(1<<C20L_VF_DMA_REG_CHANNEL_NUM));
	max_phy_channel_mask = (1 << pcie_set->max_phy_channel) - 1;
	for (phy_channel = 0; phy_channel < pcie_set->max_phy_channel;
			phy_channel++, (channel_bit <<= 1)) {
		if (!(interrupt_status&channel_bit)) {
			continue;
		}

		__sync_fetch_and_and(&pcie_set->channel_run_flag, ~(1 << phy_channel));

		channel = (struct dma_channel_info *)
			pcie_set->running_channels[phy_channel];
		if (!channel) {
			cn_dev_pcie_err(pcie_set,
				"phy_channel:%d is NULL", phy_channel);
			continue;
		}

		if ((interrupt_status&channel_bit) &
				(max_phy_channel_mask <<
					C20L_VF_DMA_REG_CHANNEL_NUM)) {
			cn_dev_pcie_err(pcie_set, "interrupt_status:0x%x", interrupt_status);
			c20l_vf_pcie_dump_reg(pcie_set);
			c20l_vf_pcie_show_desc_list(channel);
			cn_pci_dma_complete(phy_channel, CHANNEL_COMPLETED_ERR, pcie_set);
		} else {
			cn_pci_dma_complete(phy_channel, CHANNEL_COMPLETED, pcie_set);
		}

		if (channel->direction == DMA_H2D) {
			atomic_dec(&pcie_set->inbound_count);
		}
	}

	cn_pci_channel_dma_start(pcie_set);
	return IRQ_HANDLED;
}

/* val: in/out, the input value is the old data, and output val is the new data */
static int c20l_vf_wait_pf(struct cn_pcie_set *pcie_set, u32 *val)
{
	int i;
	u32 old_val;
	int timeout = 10000;

	assert(val);
	old_val = *val;

	for (i = 0; i < timeout; i++) {
		*val = cn_pci_reg_read32(pcie_set, MBX_V2P_ADDR_L);
		if (*val != old_val) {
			break;
		}

		schedule();
		msleep(1);
	}

	if (i >= timeout) {
		return -EHOSTUNREACH;
	}

	return 0;
}

static int c20l_vf_notify_init(struct cn_pcie_set *pcie_set)
{
	u32 cmd = CMD_SRIOV_INIT;

	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, cmd);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, MAILBOX_INIT_REG);

	return c20l_vf_wait_pf(pcie_set, &cmd);
}

static int c20l_vf_notify_exit(struct cn_pcie_set *pcie_set)
{
	u32 cmd = CMD_SRIOV_EXIT;

	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, cmd);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	return c20l_vf_wait_pf(pcie_set, &cmd);
}

static int c20l_vf_get_bdf(struct cn_pcie_set *pcie_set, u32 *bdf)
{
	*bdf = CMD_GET_BDF;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *bdf);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	return c20l_vf_wait_pf(pcie_set, bdf);
}

static int c20l_vf_get_inbound_info(struct cn_pcie_set *pcie_set,
	u32 *offset, u32 *size)
{
	int ret;

	*offset = CMD_GET_INBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *offset);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	ret = c20l_vf_wait_pf(pcie_set, offset);
	if (ret) {
		return ret;
	}

	*size = CMD_GET_INBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *size);
	ret = c20l_vf_wait_pf(pcie_set, size);
	if (ret) {
		return ret;
	}

	return 0;
}

static int c20l_vf_get_outbound_info(struct cn_pcie_set *pcie_set, u32 *size,
	u32 *blocks, u64 *iobase)
{
	u32 upper;
	u32 lower;
	int ret;

	*size = CMD_GET_OUTBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *size);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	ret = c20l_vf_wait_pf(pcie_set, size);
	if (ret) {
		return ret;
	}

	*blocks = CMD_GET_OUTBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *blocks);
	ret = c20l_vf_wait_pf(pcie_set, blocks);
	if (ret) {
		return ret;
	}

	upper = CMD_GET_OUTBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, upper);
	ret = c20l_vf_wait_pf(pcie_set, &upper);
	if (ret) {
		return ret;
	}

	lower = CMD_GET_OUTBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, lower);
	ret = c20l_vf_wait_pf(pcie_set, &lower);
	if (ret) {
		return ret;
	}

	*iobase = (((u64)upper) << 32) + (u64)lower;

	pcie_set->ob_axi_addr = *iobase;
	pcie_set->ob_total_size = *size;
	pcie_set->ob_size = *blocks;
	pcie_set->ob_cnt = pcie_set->ob_total_size/pcie_set->ob_size;

	return 0;
}

static int c20l_vf_get_dma_info(struct cn_pcie_set *pcie_set,
	u32 *dma_mask, u32 *dma_phy_mask)
{
	int ret;

	*dma_mask = CMD_GET_DMA_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *dma_mask);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	ret = c20l_vf_wait_pf(pcie_set, dma_mask);
	if (ret) {
		return ret;
	}

	*dma_phy_mask = CMD_GET_DMA_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *dma_phy_mask);
	ret = c20l_vf_wait_pf(pcie_set, dma_phy_mask);
	if (ret) {
		return ret;
	}

	return 0;
}

static irqreturn_t c20l_vf_mbx_interrupt_handle(int index, void *data)
{
	unsigned int interrupt_status;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct cn_bus_set *bus_set = pcie_set->bus_set;

	/*
	 * read dma interrupt register to get whitch channel generate interrupt.
	 * This interrupt may be done or error.not is done and error.
	 */
	interrupt_status = cn_pci_reg_read32(pcie_set, MBX_P2V_CTRL);

	if (interrupt_status) {
		cn_pci_reg_write32(pcie_set, MBX_P2V_CTRL, 0);
	}

	if (bus_set) {
#ifndef COMMU_HOST_POLL
		struct cn_core_set *core = bus_set->core;

		if (core)
			cn_commu_mailbox_handler(core);
#endif
	}
	return IRQ_HANDLED;
}

static void c20l_vf_desc_write64(unsigned long offset, u64 val,
	struct dma_channel_info *channel)
{
	iowrite32(LOWER32(val), channel->desc_virt_base + offset);
	iowrite32(UPPER32(val), channel->desc_virt_base + offset + 4);
}

static void c20l_vf_desc_write32(unsigned long offset, u32 val,
	struct dma_channel_info *channel)
{
	iowrite32(val, channel->desc_virt_base + offset);
}

#if  defined(__x86_64__)
#define C20L_FILL_DESC(ram_addr, cpu_addr, len_ctrl, desc_offset, tlp_attrl,\
		channel) \
	do { \
		*((u64 *)(channel->desc_buf + desc_offset + DE_ABAL)) = ram_addr; \
		*((u64 *)(channel->desc_buf + desc_offset + DE_PBAL)) = cpu_addr; \
		*((u32 *)(channel->desc_buf + desc_offset + DE_LC)) = len_ctrl; \
		*((u32 *)(channel->desc_buf + desc_offset + DE_TLP_HEAD_ATTRL)) = tlp_attrl; \
	} while (0)
#else
#define C20L_FILL_DESC(ram_addr, cpu_addr, len_ctrl, desc_offset, tlp_attrl,\
		channel) \
	do { \
		*((u64 *)(channel->desc_buf + desc_offset + DE_ABAL)) = ram_addr; \
		*((u32 *)(channel->desc_buf + desc_offset + DE_PBAL)) = cpu_addr; \
		*((u32 *)(channel->desc_buf + desc_offset + DE_PBAL + 4)) = \
			(unsigned int)(cpu_addr>>32); \
		*((u32 *)(channel->desc_buf + desc_offset + DE_LC)) = len_ctrl;\
		*((u32 *)(channel->desc_buf + desc_offset + DE_TLP_HEAD_ATTRL)) = tlp_attrl; \
	} while (0)
#endif

static int c20l_vf_pcie_fill_desc_list(struct dma_channel_info *channel)
{
#ifdef C20L_FPGA
	int i;
	unsigned long cpu_dma_addr;
	unsigned long ipu_ram_dma_addr;
	unsigned long count;
	struct scatterlist *sg;
	int j;
	unsigned long desc_count;
	int last_desc_flag;
	int desc_offset;
	unsigned int len_ctrl;
	u32 tlp_attrl;

	desc_offset = 0;
	ipu_ram_dma_addr = channel->ram_addr;
	tlp_attrl = ((channel->pcie_set->vf_priv_data->bdf << 10) | (1 << 9));

	for_each_sg(channel->sg_merge, sg, channel->nents_merge, i) {
		cpu_dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);

		for (j = 0; j < (int)(count + 479)/480; j++) {
			desc_count = min(480ul, (unsigned long)(count - j*480));
			if (i == (channel->nents_merge - 1) && (j == (count + 479)/480 - 1)) {
				last_desc_flag = 1;
				len_ctrl = LENGTH_CTRL(desc_count, 0, 1);
			} else {
				last_desc_flag = 0;
				len_ctrl = LENGTH_CTRL(desc_count, 1, 0);
			}

			C20L_FILL_DESC(ipu_ram_dma_addr, cpu_dma_addr, len_ctrl,
				desc_offset, tlp_attrl, channel);
			desc_offset += C20L_DESC_SIZE;

			ipu_ram_dma_addr += desc_count;
			cpu_dma_addr += desc_count;
		}
	}
	channel->desc_len = desc_offset;

	memcpy_toio(channel->desc_virt_base, channel->desc_buf, desc_offset);
	wmb();
	ioread8(channel->desc_virt_base);
#else
	int i;
	unsigned long cpu_dma_addr;
	u64 ipu_ram_dma_addr;
	u64 dev_end;
	unsigned long count = 0;
	unsigned long count_tmp;
	struct scatterlist *sg;
	int desc_offset;
	unsigned int len_ctrl;
	u32 tlp_attrl;

	desc_offset = 0;
	ipu_ram_dma_addr = channel->ram_addr;
	tlp_attrl = ((channel->pcie_set->vf_priv_data->bdf << 10) | (1 << 9));

	for_each_sg(channel->sg_merge, sg, channel->nents_merge, i) {
		cpu_dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);
		dev_end = ipu_ram_dma_addr + count;

		if ((ipu_ram_dma_addr&0x1ffUL) >= 0x1e0 &&
				(dev_end&0x1FFUL) && (dev_end&0x1FFUL) <= 0x20 &&
				count > 8*1024 && ((channel->direction == DMA_D2H) ||
								(channel->direction == DMA_P2P))) {
			/* fix hardware bug for C20-393 */
			count_tmp = 0x200 - (ipu_ram_dma_addr&0x1ff);
			len_ctrl = LENGTH_CTRL(count_tmp, 1, 0);
			C20L_FILL_DESC(ipu_ram_dma_addr, cpu_dma_addr, len_ctrl,
				desc_offset, tlp_attrl, channel);
			desc_offset += C20L_DESC_SIZE;

			ipu_ram_dma_addr += count_tmp;
			cpu_dma_addr += count_tmp;
			count -= count_tmp;
		}

		if (i != channel->nents_merge - 1) {
			len_ctrl = LENGTH_CTRL(count, 1, 0);
		} else {
			len_ctrl = LENGTH_CTRL(count, 0, 1);
		}
		C20L_FILL_DESC(ipu_ram_dma_addr, cpu_dma_addr, len_ctrl,
			desc_offset, tlp_attrl, channel);
		desc_offset += C20L_DESC_SIZE;

		ipu_ram_dma_addr += count;
	}

	channel->desc_len = desc_offset;
	memcpy_toio(channel->desc_virt_base, channel->desc_buf, desc_offset);
	wmb();
	ioread8(channel->desc_virt_base);
#endif
	return 0;
}

static void c20l_vf_pcie_show_desc_list(struct dma_channel_info *channel)
{
	int desc_offset = 0;
	struct cn_pcie_set *pcie_set = channel->pcie_set;

	cn_dev_pcie_err(pcie_set, "pcie channel:%d len:%ld desc_len:%d",
		channel->id, channel->transfer_length,
		channel->desc_len);

	for (; desc_offset < channel->desc_len; desc_offset += C20L_DESC_SIZE) {
		cn_dev_pcie_err(pcie_set,
			"%#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x",
			ioread32(channel->desc_virt_base + desc_offset + 0),
			ioread32(channel->desc_virt_base + desc_offset + 4),
			ioread32(channel->desc_virt_base + desc_offset + 8),
			ioread32(channel->desc_virt_base + desc_offset + 12),
			ioread32(channel->desc_virt_base + desc_offset + 16),
			ioread32(channel->desc_virt_base + desc_offset + 20),
			ioread32(channel->desc_virt_base + desc_offset + 24),
			ioread32(channel->desc_virt_base + desc_offset + 28),
			ioread32(channel->desc_virt_base + desc_offset + 32),
			ioread32(channel->desc_virt_base + desc_offset + 36),
			ioread32(channel->desc_virt_base + desc_offset + 40));
	}
}

static inline int c20l_vf_do_irq(struct cn_pcie_set *pcie_set, int interrupt_index)
{
	u64 start;
	u64 end;

	if (pcie_set->irq_desc[interrupt_index].handler) {
		start = get_jiffies_64();
		pcie_set->irq_desc[interrupt_index].handler(interrupt_index,
		pcie_set->irq_desc[interrupt_index].data);
		end = get_jiffies_64();
		if (time_after64(end, start + HZ / 2)) {
			cn_dev_pcie_err(pcie_set,
				"do interrupt%d spend too long time(%dms)!!!",
				interrupt_index, jiffies_to_msecs(end - start));
		}
	} else {
		cn_dev_pcie_err(pcie_set, "no interrupt handle!:%x",
			interrupt_index);
	}

	return 1;
}

static irqreturn_t c20l_vf_msix_interrupt(int irq, void *data)
{
	u32 gic_mask;
	int i;
	irqreturn_t ret = IRQ_NONE;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct msix_entry* entry;
	int vector_index;

	entry = (struct msix_entry*)pcie_set->msix_entry_buf;
	spin_lock(&pcie_set->interrupt_lock);

	for (vector_index = 0; vector_index < GIC_MSIX_COUNT; vector_index++) {
		if (entry[vector_index].vector == irq) {
			break;
		}
	}

	if (vector_index >= GIC_MSIX_COUNT) {
		cn_dev_pcie_err(pcie_set, "Recv error interrupt:%d", irq);
		spin_unlock(&pcie_set->interrupt_lock);
		return ret;
	}

	gic_mask = (u32)pcie_set->gic_mask[0];
	/*
	 *  do all dma task in one interrupt, set dma_ire_done 1
	 *  other interrupt just return, no need to read/write DI
	 */
	pcie_set->do_dma_irq_status = 0;

	for (i = 0; i < GIC_INTERRUPT_NUM; i++) {
		if (!(gic_mask & (1 << i))) {
			if (c20l_vf_do_irq(pcie_set, i)) {
				ret = IRQ_HANDLED;
			}
		}
	}

	cn_pci_reg_read32(pcie_set, MSIX_SRC_INT_CLR);
	cn_pci_reg_write32(pcie_set, MSIX_SRC_INT_CLR, 1);
	cn_pci_reg_read32(pcie_set, MSIX_SRC_INT_CLR);
	spin_unlock(&pcie_set->interrupt_lock);
	return ret;
}

static irqreturn_t c20l_vf_msi_interrupt(int irq, void *data)
{
	u32 gic_mask;
	int i;
	irqreturn_t ret = IRQ_NONE;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct msix_entry* entry;
	int vector_index;
	entry = (struct msix_entry*)pcie_set->msix_entry_buf;

	vector_index = irq - pcie_set->irq;
	if (vector_index >= GIC_MSI_COUNT) {
		cn_dev_err("Recv error interrupt:%d", irq);
		return ret;
	}

	spin_lock(&pcie_set->interrupt_lock);

	gic_mask = (u32)pcie_set->gic_mask[0];
	/*
	 *  do all dma task in one interrupt, set dma_ire_done 1
	 *  other interrupt just return, no need to read/write DI
	 */
	pcie_set->do_dma_irq_status = 0;

	for (i = 0; i < GIC_INTERRUPT_NUM; i++) {
		if (!(gic_mask & (1 << i))) {
			if (c20l_vf_do_irq(pcie_set, i)) {
				ret = IRQ_HANDLED;
			}
		}
	}

	/* why to read register?, please see bugzilla id :167 */
	cn_pci_reg_read32(pcie_set, MSI_INT_CLR);
	cn_pci_reg_write32(pcie_set, MSI_INT_CLR, 0x1);
	cn_pci_reg_read32(pcie_set, MSI_INT_CLR);
	spin_unlock(&pcie_set->interrupt_lock);

	return ret;
}

static int c20l_vf_gic_bit(int irq, struct cn_pcie_set *pcie_set)
{
	int bit;
	int count = 0;
	unsigned long dma_phy_mask;

	if (irq < PCIE_MBX_IRQ) {
		dma_phy_mask = pcie_set->vf_priv_data->dma_phy_mask;
		for_each_set_bit(bit, (unsigned long *)&dma_phy_mask,
			sizeof(dma_phy_mask)*8) {
			if (count == irq) {
				return bit;
			}
			count++;
		}
	}

	return irq;
}

static int c20l_vf_pcie_gic_mask(int irq, struct cn_pcie_set *pcie_set)
{
	u64 reg_val;
	u32 bit_index;

	if (irq < GIC_INTERRUPT_NUM) {
		pcie_set->gic_mask[0] |= (1ULL<<irq);
		bit_index = c20l_vf_gic_bit(irq, pcie_set);
		reg_val = cn_pci_reg_read64(pcie_set, INT_BIT_MASK);
		reg_val |= (1ULL << bit_index);
		cn_pci_reg_write64(pcie_set, INT_BIT_MASK, reg_val);
		return 0;
	}

	return -EINVAL;
}

static int c20l_vf_pcie_gic_unmask(int irq, struct cn_pcie_set *pcie_set)
{
	u64 reg_val;
	u32 bit_index;

	if (irq < GIC_INTERRUPT_NUM) {
		pcie_set->gic_mask[0] &= (~(1ULL<<irq));
		bit_index = c20l_vf_gic_bit(irq, pcie_set);
		cn_pci_reg_write64(pcie_set, INT_MASK, 0x0);
		reg_val = cn_pci_reg_read64(pcie_set, INT_BIT_MASK);
		reg_val &= (~(1ULL<<(bit_index)));
		cn_pci_reg_write64(pcie_set, INT_BIT_MASK, reg_val);
		return 0;
	}

	return -EINVAL;
}


static int c20l_vf_pcie_gic_mask_all(struct cn_pcie_set *pcie_set)
{
	u64 reg_val = -1ULL;

	pcie_set->gic_mask[0] = -1ULL;
	cn_pci_reg_write64(pcie_set, INT_BIT_MASK, reg_val);
	return 0;
}

static int c20l_vf_pcie_get_irq(char *irq_desc, struct cn_pcie_set *pcie_set)
{
	return 0;
}

static int c20l_vf_pcie_dma_go(struct dma_channel_info *channel, int phy_channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	unsigned long start_desc_addr = channel->desc_device_va;

	if (channel->status != CHANNEL_RUNNING) {
		cn_dev_pcie_err(pcie_set, "The channel:%d is not locked %d",
			channel->id, channel->status);
	}

	if (channel->direction == DMA_H2D) {
		if (!atomic_add_unless(&pcie_set->inbound_count, 1,
			pcie_set->max_inbound_cnt))
			return -EINVAL;
	}

	cn_pci_reg_write32(pcie_set, DSPL(phy_channel), LOWER32(start_desc_addr));
	cn_pci_reg_write32(pcie_set, DSPU(phy_channel), UPPER32(start_desc_addr));

	/*
	 * make sure start point is writen in.
	 */
	cn_pci_reg_read32(pcie_set, DSPL(phy_channel));

	/*
	 * start transfer
	 */
	switch (channel->direction) {
	case DMA_H2D:
		cn_pci_reg_write32(pcie_set, DCTRL(phy_channel), 0x1);
		break;

	case DMA_D2H:
	case DMA_P2P:
		cn_pci_reg_write32(pcie_set, DCTRL(phy_channel), 0x3);
		break;

	default:
		return -EINVAL;
	}

	cn_pci_reg_read32(pcie_set, DCTRL(phy_channel));

	return 0;
}

static int c20l_vf_pcie_init(struct cn_pcie_set *pcie_set)
{
	int i, j;
	struct dma_channel_info *channel;
	u64 desc_addr;
	u32 bdf, tlp_attrl;

	bdf = pcie_set->vf_priv_data->bdf;
	tlp_attrl = ((bdf << 10) | (1 << 9));

	for (i = 0; i < pcie_set->max_channel; i++) {
		channel = &pcie_set->dma_channels[i];
		desc_addr = channel->desc_device_va;
		cn_dev_pcie_debug(pcie_set, "channel%d: desc_addr=%llx bdf:%x tlp_attrl:%x",
			i, desc_addr, bdf, tlp_attrl);

		for (j = 0; j < channel->desc_size / 8; j++) {
			c20l_vf_desc_write64(j * 8, 0, channel);
		}

		for (j = 0; j < channel->desc_size / C20L_DESC_SIZE; j++) {
			desc_addr += C20L_DESC_SIZE;
			c20l_vf_desc_write32(j * C20L_DESC_SIZE + DE_NDL,
				LOWER32(desc_addr),
				channel);
			c20l_vf_desc_write32(j * C20L_DESC_SIZE + DE_NDU,
				UPPER32(desc_addr),
				channel);
			c20l_vf_desc_write32(j * C20L_DESC_SIZE +
				DE_TLP_HEAD_ATTRL, tlp_attrl,
				channel);
		}

		channel->desc_buf = cn_kzalloc(channel->desc_size, GFP_KERNEL);
		if (!channel->desc_buf) {
			cn_dev_err("Malloc channe:%d DMA desc fail\n", i);
			goto ERR_RET;
		}

		desc_addr = channel->desc_device_va;
		for (j = 0; j < channel->desc_size / C20L_DESC_SIZE; j++) {
			desc_addr += C20L_DESC_SIZE;
			*((u64 *)(channel->desc_buf +
				j * C20L_DESC_SIZE + DE_NDL)) = desc_addr;
			*((u32 *)(channel->desc_buf + j * C20L_DESC_SIZE +
				DE_TLP_HEAD_ATTRL)) = tlp_attrl;
		}
	}

	cn_dev_pcie_info(pcie_set, "init end");
	return 0;

ERR_RET:
	c20l_vf_pcie_pre_exit(pcie_set);
	return -ENOMEM;
}

static int c20l_vf_pcie_outbound_exit(struct cn_pcie_set *pcie_set)
{
	int i;
	struct c20l_outbound_mem *outbound_mem = pcie_set->share_priv;

	if (!outbound_mem && !pcie_set->share_mem_pages)
		return 0;

	if (!outbound_mem && pcie_set->share_mem_pages) {
		cn_kfree(pcie_set->share_mem_pages);
		pcie_set->share_mem_pages = NULL;

		return 0;
	}

	if (outbound_mem && !pcie_set->share_mem_pages) {
		cn_kfree(pcie_set->share_priv);
		pcie_set->share_priv = NULL;

		return 0;
	}

	if (pcie_set->share_mem[1].virt_addr) {
		vm_unmap_ram(pcie_set->share_mem[1].virt_addr,
			pcie_set->ob_total_size / PAGE_SIZE);
		pcie_set->share_mem[1].virt_addr = NULL;
	}

	for (i = 0; i < pcie_set->ob_total_size / PAGE_SIZE; i++) {
		if (pcie_set->share_mem_pages[i]) {
			ClearPageReserved(pcie_set->share_mem_pages[i]);
			pcie_set->share_mem_pages[i] = NULL;
		}
	}

	for (i = 0; i < pcie_set->ob_cnt; i++) {
		if (outbound_mem && outbound_mem[i].virt_addr)
			pci_free_consistent(pcie_set->pdev, pcie_set->ob_size,
				outbound_mem[i].virt_addr, outbound_mem[i].pci_addr);
	}

	cn_kfree(pcie_set->share_mem_pages);
	pcie_set->share_mem_pages = NULL;
	cn_kfree(pcie_set->share_priv);
	pcie_set->share_priv = NULL;

	return 0;
}


static int c20l_vf_pcie_pre_exit(struct cn_pcie_set *pcie_set)
{
	int i;

	for (i = 0; i < pcie_set->max_channel; i++) {
		if (pcie_set->dma_channels[i].desc_buf) {
			cn_kfree(pcie_set->dma_channels[i].desc_buf);
			pcie_set->dma_channels[i].desc_buf = NULL;
		}
	}
	cn_dev_pcie_info(pcie_set, "c20l_vf_pcie_exit end");
	return 0;
}

static void c20l_vf_pcie_unregister_bar(struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar;
	struct bar_resource *tmp;

	list_for_each_entry_safe(bar, tmp, &pcie_set->bar_resource_head, list) {
		if (bar->base) {
			cn_iounmap((void *)bar->base);
			list_del(&bar->list);
			cn_kfree(bar);
		}
	}
}

static void c20l_vf_bar_deinit(struct cn_pcie_set *pcie_set)
{
	int i, seg;

	cn_dev_pcie_info(pcie_set, "cn_iounmap bars");
	c20l_vf_notify_exit(pcie_set);

	for (i = 0; i < 6; i++) {
		if (pcie_set->pcibar[i].size <= 0)
			continue;

		for (seg = 0; seg < MAX_BAR_SEGMENTS; seg++) {
			if (pcie_set->pcibar[i].seg[seg].virt) {
				cn_iounmap(pcie_set->pcibar[i].seg[seg].virt);
				pcie_set->pcibar[i].seg[seg].virt = NULL;
			}
		}
	}
	c20l_vf_pcie_unregister_bar(pcie_set);
}

static int c20l_vf_pcie_exit(struct cn_pcie_set *pcie_set)
{
	c20l_vf_pcie_gic_mask_all(pcie_set);

	if (isr_disable_func[pcie_set->irq_type](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr destroyed failed!");
		return -1;
	}

	c20l_vf_pcie_outbound_exit(pcie_set);
	c20l_vf_bar_deinit(pcie_set);

	if (pcie_set->vf_priv_data) {
		cn_kfree(pcie_set->vf_priv_data);
		pcie_set->vf_priv_data = NULL;
	}

	return 0;
}

static int pcie_dma_bypass_size(struct cn_pcie_set *pcie_set)
{
#if defined(__x86_64__)
	pcie_set->dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 256 * 1024;
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

static u64 pcie_set_bar_window(u64 axi_address, struct bar_resource *bar,
		struct cn_pcie_set *pcie_set)
{
	u64 addr = bar->window_addr;

	if (axi_address >= addr && axi_address < (addr + bar->size))
		return addr;

	axi_address &= (~((u64)(bar->size - 1)));
	cn_pci_reg_write64(pcie_set, bar->reg_index, axi_address);
	cn_pci_reg_read32(pcie_set, bar->reg_index);

	bar->window_addr = axi_address;
	return axi_address;
}

static int c20l_vf_flush_irq(struct cn_pcie_set *pcie_set)
{
	if (pcie_set->irq_type == 0) {
		cn_pci_reg_write32(pcie_set, MSI_INT_CLR, 0x1);
	} else if (pcie_set->irq_type == 1) {
		cn_pci_reg_write32(pcie_set, MSIX_SRC_INT_CLR, 1);
	}

	return 0;
}

static struct cn_pci_ops c20l_vf_ops = {
	.pcie_init = c20l_vf_pcie_init,
	.pcie_pre_exit = c20l_vf_pcie_pre_exit,
	.pcie_exit = c20l_vf_pcie_exit,
	.fill_desc_list = c20l_vf_pcie_fill_desc_list,
	.show_desc_list = c20l_vf_pcie_show_desc_list,
	.dump_reg = c20l_vf_pcie_dump_reg,
	.pci_mb = c20l_vf_pcie_mb,
	.dma_align = c20l_vf_dma_align,
	.dma_bypass_size = pcie_dma_bypass_size,
	.set_bar_window = pcie_set_bar_window,
	.msi_isr = c20l_vf_msi_interrupt,
	.msix_isr = c20l_vf_msix_interrupt,
	.gic_mask = c20l_vf_pcie_gic_mask,
	.gic_unmask = c20l_vf_pcie_gic_unmask,
	.gic_mask_all = c20l_vf_pcie_gic_mask_all,
	.get_irq_by_desc = c20l_vf_pcie_get_irq,
	.dma_go_command = c20l_vf_pcie_dma_go,
	.bar_write = mlu220_mlu270_pcie_bar_write,
	.bar_read = mlu220_mlu270_pcie_bar_read,
	.flush_irq = c20l_vf_flush_irq,
};

static int c20l_vf_outbound_reg(struct cn_pcie_set *pcie_set)
{
	int i;
	u32 cmd;
	u32 size;
	u32 upper;
	u32 lower;
	int ret = 0;
	struct c20l_outbound_mem *outbound_mem;

	outbound_mem = pcie_set->share_priv;

	cmd = CMD_SET_OUTBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, cmd);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	ret = c20l_vf_wait_pf(pcie_set, &cmd);
	if (ret) {
		cn_dev_err("CMD_SET_OUTBOUND_INFO cmd error");
		return ret;
	}

	size = pcie_set->ob_size;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, size);
	ret = c20l_vf_wait_pf(pcie_set, &size);
	if (ret) {
		cn_dev_err("CMD_SET_OUTBOUND_INFO size error");
		return ret;
	}

	for (i = 0; i < pcie_set->ob_cnt; i++) {
		upper = (u32)(outbound_mem[i].pci_addr>>32);
		cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, upper);
		ret = c20l_vf_wait_pf(pcie_set, &upper);
		if (ret) {
			cn_dev_err("CMD_SET_OUTBOUND_INFO:%d upper:%x error", i, upper);
			return ret;
		}

		lower = (u32)(outbound_mem[i].pci_addr&(-1U));
		cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, lower);
		ret = c20l_vf_wait_pf(pcie_set, &lower);
		if (ret) {
			cn_dev_err("CMD_SET_OUTBOUND_INFO:%d lower:%x error", i, lower);
			return ret;
		}
	}

	return 0;
}

static int c20l_vf_pcie_outbound_init(struct cn_pcie_set *pcie_set)
{
	int i;
	int j;
	int page_index = 0;
	struct c20l_outbound_mem *outbound_mem;
	int index = pcie_set->share_mem_cnt;
	int ret;

	ret = c20l_vf_get_outbound_info(pcie_set, &pcie_set->ob_total_size,
		&pcie_set->ob_size, &pcie_set->ob_axi_addr);
	if (ret) {
		return -1;
	}
	pcie_set->ob_cnt = pcie_set->ob_total_size/pcie_set->ob_size;
	cn_dev_pcie_info(pcie_set, "ob_total_size:%x ob_size:%x ob_axi_addr:%llx ob_cnt:%x\n",
		pcie_set->ob_total_size, pcie_set->ob_size, pcie_set->ob_axi_addr,
		pcie_set->ob_cnt);

	pcie_set->share_mem_pages = (struct page **)cn_kzalloc(
		sizeof(struct page *)*(pcie_set->ob_total_size / PAGE_SIZE),
		GFP_KERNEL);
	if (!pcie_set->share_mem_pages) {
		cn_dev_err("Malloc share_mem_pages error");
		return -ENOMEM;
	}

	outbound_mem = (struct c20l_outbound_mem *)cn_kzalloc(
		pcie_set->ob_cnt * sizeof(struct c20l_outbound_mem), GFP_KERNEL);
	if (!outbound_mem) {
		cn_dev_err("Malloc outbound_mem error");
		ret = -ENOMEM;
		goto ERROR_RET;
	}
	pcie_set->share_priv = (void *)outbound_mem;

	for (i = 0; i < pcie_set->ob_cnt; i++) {
		outbound_mem[i].virt_addr = dma_alloc_coherent(&pcie_set->pdev->dev,
			pcie_set->ob_size, &(outbound_mem[i].pci_addr), GFP_KERNEL);

		cn_dev_pcie_info(pcie_set, "outbound:%d alloc pci_addr:%llx ob_size:%x virt_addr:%lx",
			i, outbound_mem[i].pci_addr, pcie_set->ob_size,
			(ulong)outbound_mem[i].virt_addr);

		if (((ulong)outbound_mem[i].virt_addr)&(PAGE_SIZE - 1)) {
			panic("Address not align\n");
		}

		if (!outbound_mem[i].virt_addr) {
			cn_dev_err("dma_alloc_coherent error:%d", i);
			ret = -ENOMEM;
			goto ERROR_RET;
		}

		if (outbound_mem[i].pci_addr&(pcie_set->ob_size - 1)) {
			cn_dev_err("dma_alloc_coherent not align:%llx\n",
				outbound_mem[i].pci_addr);
			ret = -ENOMEM;
			goto ERROR_RET;
		}
	}

	page_index = 0;
	for (i = 0; i < pcie_set->ob_cnt; i++) {
		for (j = 0; j < pcie_set->ob_size / PAGE_SIZE; j++) {
			pcie_set->share_mem_pages[page_index] =
				virt_to_page(outbound_mem[i].virt_addr +
					j * PAGE_SIZE);
			SetPageReserved(pcie_set->share_mem_pages[page_index]);
			page_index++;
		}
	}

#if  defined(__x86_64__)
	pcie_set->share_mem[index].virt_addr = cn_vm_map_ram(
		pcie_set->share_mem_pages, page_index, -1, PAGE_KERNEL_NOCACHE);
#else
	pcie_set->share_mem[index].virt_addr = cn_vm_map_ram(
		pcie_set->share_mem_pages, page_index, -1, PAGE_KERNEL);
#endif
	if (!pcie_set->share_mem[index].virt_addr) {
		cn_dev_err("vm_map_ram error");
		goto ERROR_RET;
	}

	cn_dev_pcie_info(pcie_set, "host share mem virtual addr:%lx\n",
		(unsigned long)pcie_set->share_mem[index].virt_addr);
	pcie_set->share_mem[index].win_length = pcie_set->ob_total_size;
	pcie_set->share_mem[index].type = CN_SHARE_MEM_HOST;
	pcie_set->share_mem[index].device_addr = pcie_set->ob_axi_addr;

	pcie_set->share_mem_cnt++;
	return 0;

ERROR_RET:
	cn_dev_err("init error");
	c20l_vf_pcie_outbound_exit(pcie_set);

	return ret;
}

static struct bar_resource *c20l_vf_set_init_pf(struct cn_pcie_set *pcie_set, int index)
{
	u64 base, sz;
	struct pci_dev *pdev = pcie_set->pdev;
	struct bar_resource *bar;

	sz = pci_resource_len(pdev, index);
	if (!sz)
		return NULL;

	bar = cn_kzalloc(sizeof(*bar), GFP_KERNEL);
	if (!bar) {
		cn_dev_pcie_err(pcie_set, "kzalloc bar struct failed!");
		return NULL;
	}

	base = pci_resource_start(pdev, index);

	bar->phy_base = base;
	bar->base = cn_ioremap_wc(base, sz);
	if (!bar->base) {
		cn_kfree(bar);
		cn_dev_pcie_err(pcie_set, "cn_ioremap failed!");
		return NULL;
	}

	bar->size = sz;
	sema_init(&bar->occupy_lock, 1);
	bar->type = PF_BAR;
	bar->index = index;

	if (index == 2)
		bar->reg_index = PCIE_TO_AXI_ADDR_L(2);
	else
		bar->reg_index = PCIE_TO_AXI_ADDR_L(4);

	return bar;
}

static int c20l_vf_pcie_enable_pf_bar(struct cn_pcie_set *pcie_set)
{
	int index;
	struct bar_resource *bar;

	for (index = 2; index < 6; index++) {
		bar = c20l_vf_set_init_pf(pcie_set, index);
		if (bar)
			list_add_tail(&bar->list, &pcie_set->bar_resource_head);
	}

	return 0;
}

static int c20l_vf_pcie_bar_init(struct cn_pcie_set *pcie_set)
{
	struct pcibar_seg_s *p_bar_seg;
	struct pcibar_s *p_bar;
	u32 vf_share_mem_base, vf_share_mem_size;

	/* Init bar 0 */
	p_bar = &pcie_set->pcibar[0];

	/* the register area */
	p_bar_seg = &p_bar->seg[0];
	p_bar_seg->size = p_bar->size / 2;
	p_bar_seg->base = p_bar->base;
	p_bar_seg->virt = cn_ioremap(p_bar_seg->base, p_bar_seg->size);
	cn_dev_pcie_info(pcie_set, "Bar0 register virt:%lx size:%llx",
		(ulong)p_bar_seg->virt, p_bar_seg->size);

	if (!p_bar_seg->virt)
		goto ERROR_RET;

	pcie_set->reg_virt_base = p_bar_seg->virt;
	pcie_set->reg_phy_addr = p_bar_seg->base;
	pcie_set->reg_win_length = p_bar_seg->size;

	/* the bar share memory */
	p_bar_seg = &p_bar->seg[1];
	p_bar_seg->base = p_bar->base + pcie_set->reg_win_length;
	p_bar_seg->size = p_bar->size - pcie_set->reg_win_length;

	p_bar_seg->virt = cn_ioremap_wc(p_bar_seg->base, p_bar_seg->size);
	cn_dev_pcie_info(pcie_set, "Bar0 memory virt:%lx size:%llx",
		(ulong)p_bar_seg->virt, p_bar_seg->size);

	if (!p_bar_seg->virt)
		goto ERROR_RET;

	if (c20l_vf_pcie_enable_pf_bar(pcie_set))
		goto ERROR_RET;

	if (c20l_vf_notify_init(pcie_set))
		goto ERROR_RET;

	pcie_set->share_mem_cnt = 1;
	if (c20l_vf_get_inbound_info(pcie_set, &vf_share_mem_base,
		&vf_share_mem_size)) {
		cn_dev_err("error");
		goto ERROR_RET;
	}
	cn_dev_pcie_info(pcie_set, "vf_share_mem_base:%x size:%x",
		vf_share_mem_base, vf_share_mem_size);

#ifdef C20L_PCIE_SMMU_ENABLE
	pcie_set->share_mem[0].virt_addr =
		pcie_set->pcibar[0].seg[1].virt + vf_share_mem_base;
	pcie_set->share_mem[0].phy_addr =
		pcie_set->pcibar[0].seg[1].base + vf_share_mem_base;
	pcie_set->share_mem[0].win_length = vf_share_mem_size;
#else
	pcie_set->share_mem[0].virt_addr =
		pcie_set->pcibar[4].seg[0].virt;
	pcie_set->share_mem[0].phy_addr =
		pcie_set->pcibar[4].seg[0].base;
	pcie_set->share_mem[0].win_length = pcie_set->pcibar[4].seg[0].size;
#endif
	pcie_set->share_mem[0].type = CN_SHARE_MEM_DEV;
	pcie_set->share_mem[0].device_addr = -1;

	return 0;

ERROR_RET:
	cn_dev_err("init error");

	return -1;
}

static int c20l_vf_pre_init_hw(struct cn_pcie_set *pcie_set)
{
	int i;
	int ret;
	unsigned long flags;

	cn_pci_reg_write32(pcie_set, PCIE_TO_AXI_ADDR_L(4), 0);
	cn_pci_reg_write32(pcie_set, PCIE_TO_AXI_ADDR_U(4), 0);
	cn_pci_reg_read32(pcie_set, PCIE_TO_AXI_ADDR_U(4));

	ret = c20l_vf_adjust_dev_param(pcie_set);
	if (ret) {
		cn_dev_err("error");
		return ret;
	}

	ret = c20l_vf_outbound_reg(pcie_set);
	if (ret) {
		cn_dev_err("error");
		return ret;
	}

	c20l_vf_pcie_gic_mask_all(pcie_set);
	spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
	c20l_vf_pcie_gic_unmask(PCIE_MBX_IRQ, pcie_set);
	spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_res.channel_mask&(1 << i)) {
			spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
			c20l_vf_pcie_gic_unmask(PCIE_DMA_IRQ + i, pcie_set);
			spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);
		}
	}

	return 0;
}

static int c20l_vf_clear_irq(struct cn_pcie_set *pcie_set)
{
	int i;
	u32 reg_val;

	for (i = 0; i < DMA_MAX_PHY_CHANNEL; i++) {
		reg_val = cn_pci_reg_read32(pcie_set, DMA_INT_REG(i));
		if (reg_val == 1) {
			cn_pci_reg_write32(pcie_set, DMA_INT_REG(i), 1);
		}
	}

	cn_pci_reg_write32(pcie_set, MBX_P2V_CTRL, 0);
	c20l_vf_flush_irq(pcie_set);

	return 0;
}

static int c20l_vf_pcie_setup(void *pcie)
{
	int result = 0;
	int i;
	u32 channel_mask;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;
	int ret;

	pcie_set->ops = &c20l_vf_ops;

	pcie_set->is_virtfn = 1;
	pcie_set->vf_priv_data = cn_kzalloc(sizeof(struct cn_pci_vf_priv_data),
		GFP_KERNEL);
	if(!pcie_set->vf_priv_data) {
		cn_dev_pcie_err(pcie_set, "vf_priv_data alloc failed");
		return -ENOMEM;
	}

	pcie_set->share_mem_cnt = 0;

	pcie_set->irq_type = (isr_type_index == -1) ? isr_default_type : isr_type_index;

	INIT_LIST_HEAD(&pcie_set->bar_resource_head);

	ret = c20l_vf_pcie_bar_init(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	c20l_vf_clear_irq(pcie_set);

	pcie_set->vf_priv_data->bdf = (((pcie_set->pdev->bus->number) << 8) |
		(pcie_set->pdev->devfn));
	ret = c20l_vf_get_bdf(pcie_set, &pcie_set->vf_priv_data->bdf);
	if (ret)
		goto RELEASE_BAR;

	cn_dev_pcie_info(pcie_set, "number:%x devfn:%x bdf:%x\n", pcie_set->pdev->bus->number,
		pcie_set->pdev->devfn, pcie_set->vf_priv_data->bdf);

	ret = c20l_vf_get_dma_info(pcie_set, &channel_mask,
		&pcie_set->vf_priv_data->dma_phy_mask);
	if (ret)
		goto RELEASE_BAR;

	cn_dev_pcie_info(pcie_set, "channel_mask:%x dma_phy_mask:%x\n", channel_mask,
		pcie_set->vf_priv_data->dma_phy_mask);

	pcie_set->max_phy_channel = __fls(channel_mask) + 1;
	pcie_set->max_channel = 4 * pcie_set->max_phy_channel;
	pcie_set->dma_res.channel_mask = channel_mask;
	pcie_set->max_inbound_cnt = hweight32(channel_mask) * 2;
	/* dma desc size */
	pcie_set->dma_buffer_size = C20L_VF_DMA_BUFFER_SIZE;
	pcie_set->dma_desc_total_size = pcie_set->max_channel * 64 * 1024;

	if (pcie_set->irq_type == 0)
		pcie_set->irq_num = GIC_MSI_COUNT;
	else if (pcie_set->irq_type == 1)
		pcie_set->irq_num = GIC_MSIX_COUNT;

	if (isr_enable_func[pcie_set->irq_type](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr enable failed!");
		return -1;
	}

	ret = c20l_vf_pcie_outbound_init(pcie_set);
	if (ret) {
		goto RELEASE_OUTBOUND;
	}

	c20l_vf_pcie_gic_mask_all(pcie_set);

	cn_pci_register_interrupt(PCIE_MBX_IRQ, c20l_vf_mbx_interrupt_handle,
		pcie_set, pcie_set);

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (channel_mask & (1 << i)) {
			cn_pci_register_interrupt(PCIE_DMA_IRQ + i,
				c20l_vf_pcie_dma_interrupt_handle, pcie_set, pcie_set);
		}
	}

	ret = c20l_vf_pre_init_hw(pcie_set);
	if (ret) {
		goto RELEASE_OUTBOUND;
	}

	return result;

RELEASE_OUTBOUND:
	c20l_vf_pcie_outbound_exit(pcie_set);
RELEASE_BAR:
	c20l_vf_bar_deinit(pcie_set);
	if (pcie_set->vf_priv_data) {
		cn_kfree(pcie_set->vf_priv_data);
		pcie_set->vf_priv_data = NULL;
	}
	return ret;
}

static int c20l_vf_bus_pre_init(void *pcie)
{
	return 0;
}

static int c20l_vf_bus_pre_exit(void *pcie)
{
	return 0;
}

static int c20l_vf_pcie_domain_get_resource(void *pcie, struct domain_resource *resource)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	resource->id = pcie_set->id;

	return 0;
}

struct cn_pci_info c20l_vf_pci_info = {
	.setup = c20l_vf_pcie_setup,
	.pre_init = c20l_vf_bus_pre_init,
	.pre_exit = c20l_vf_bus_pre_exit,
	.get_resource = c20l_vf_pcie_domain_get_resource,
	.dev_name = "c20l-vf"
};
