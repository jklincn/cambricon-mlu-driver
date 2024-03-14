/************************************************************************
 *
 *  @file cndrv_pci_c20_vf.c
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
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "./cndrv_pci_c20.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "../../pcie_common.c"

#define C20_PCIE_VF
#define C20_PCIE_SMMU_ENABLE 1

#define MBX_V2P_CTRL	(0x0000)
#define MBX_V2P_ADDR_L	(0x0004)
#define MBX_V2P_ADDR_U  (0x0008)

#define MBX_P2V_CTRL    (0x000C)
#define MBX_P2V_ADDR_L  (0x0010)
#define MBX_P2V_ADDR_U  (0x0014)

#define VF_INBOUND_REGMSK(bar)   (0x700 + bar * 0xC)
#define VF_INBOUND_BASEL(bar)    (0x704 + bar * 0xC)
#define VF_INBOUND_BASE_MASK_H(bar)  (0x708 + bar * 0xC)

#define GIC_MSI_COUNT       (1)
#define GIC_MSIX_COUNT		(1)

#define VF_BAR2_BASE_ADDR_L (0x704)
#define VF_BAR4_BASE_ADDR_L (0x710)

#define VF_BAR2_MASK_L (0x700)
#define VF_BAR4_MASK_L (0x70c)

/*DMA control regs offset*/
#define DMA_BASE_ADDR		 (0x400)
#define VF_DMA_MASK_ADDR     (0x10)

#define DMA_INT_REG(channel_id)   (0x0600 + channel_id*4)

#define C20_VF_DMA_BUFFER_SIZE    	(1*1024*1024UL)
#define DESC_SIZE					(32)
#define DMA_CHANNEL_REG_SIZE		(0x40)
#define DMA_ISTATUS_BASE			(0x600)
#define DEO	(0UL)	/*dma command descriptor offset*/

#define DMA_PCIE_PARAM	(0x0)
#define DMA_AXI_PARAM	(0x4)
#define SG_ID_PCIE	(0x0)
#define SG_ID_AXI	(0x4)
#define DSE_COND	(0xa)
#define DIRQ		(0x3)
#define DIRQ_ID		(0x1)

/*PCIE DMA Descriptor status*/
#define DE_STATUS                 (DEO+0)
/*PCIE DMA Descriptor control*/
#define DE_CTRL	                (DEO+4)
/*Next Descriptor Lower address*/
#define DE_NDL       (DEO + 0x8)
/*Next Descriptor Upper address*/
#define DE_NDU       (DEO + 0xc)
/*Src Address Lower  in descriptor*/
#define DE_SRC_LOWER (DEO + 0x10)
/*Src Address Upper  in descriptor*/
#define DE_SRC_UPPER (DEO + 0x14)
/*Dest Address Lower  in descriptor*/
#define DE_DEST_LOWER (DEO + 0x18)
/*Dest Address Upper  in descriptor*/
#define DE_DEST_UPPER (DEO + 0x1c)

/*PCIe DMA Channel n source parameter Register*/
#define DSRC_PARAM(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x000)

/*PCIe DMA Channel n Dest Parameter Register*/
#define DDEST_PARAM(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x004)

/*PCIe DMA Channel n SrcAddr Lower Register*/
#define DSRCL(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x008)

/*PCIe DMA Channel n SrcAddr Upper Register*/
#define DSRCU(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x00c)

/*PCIe DMA Channel n DestAddr Lower Register*/
#define DDESTL(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x010)

/*PCIe DMA Channel n DestAddr Upper Register*/
#define DDESTU(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x014)

/*PCIe DMA Channel n Data Length Register(up to 4GB)*/
#define DLEN(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x018)

/*PCIe DMA Channel n Control Register(up to 4GB)*/
#define DCTRL(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x01c)

/*PCIe DMA Channel n Status Register(up to 4GB)*/
#define DSTATUS(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x020)

/*PCIe DMA Channel n Data PRC Length Register(more than 4GB)*/
#define DPRC_LEN(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x024)

/*PCIe DMA Channel n Data Length Register(up to 4GB)*/
#define DSHARE_ACCESS(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x028)

#define LENGTH_CTRL(len) \
	((len == 0x1000000) ? 0 : (unsigned int)(len & 0xFFFFFF))

#define NEXT_DESC_LOWER32(addr, current_index) \
	((unsigned int)((unsigned long)(addr + \
				(current_index + 1) * DESC_SIZE) & 0xFFFFFFFFU))
#define NEXT_DESC_UPPER32(addr, current_index) \
	((unsigned int)(((unsigned long)(addr + \
			(current_index + 1) * DESC_SIZE) >> 32) & 0xFFFFFFFFU))


#define FILL_DESC(addr, ctrl, ndl, ndu, src_addr, dest_addr, desc_offset) \
{ \
	*((u32 *)(addr + desc_offset + DE_CTRL)) = ctrl; \
	*((u32 *)(addr + desc_offset + DE_NDL)) = ndl; \
	*((u32 *)(addr + desc_offset + DE_NDU)) = ndu; \
	*((u32 *)(addr + desc_offset + DE_SRC_LOWER)) = src_addr; \
	*((u32 *)(addr + desc_offset + DE_SRC_UPPER)) = \
			(unsigned int)(src_addr >> 32); \
	*((u32 *)(addr + desc_offset + DE_DEST_LOWER)) = dest_addr; \
	*((u32 *)(addr + desc_offset + DE_DEST_UPPER)) = \
			(unsigned int)(dest_addr >> 32); \
}

static void c20_vf_pcie_dump_reg(struct cn_pcie_set *pcie_set);

struct c20_pcie_dump_reg_s {
	char *desc;
	unsigned long reg;
};

static void c20_vf_pcie_dump_reg(struct cn_pcie_set *pcie_set)
{
	cn_dev_info("no dump function, please add in private file.");
	return;
}

static void c20_vf_pcie_mb(struct cn_pcie_set *pcie_set)
{
	cn_dev_info("empty vf_pcie_mb.\n");
	return;
}

static int c20_vf_dma_align(struct transfer_s *t, size_t *head, size_t *tail)
{
	int dma_copy = 0;

	if ((t->ca & 0x3) != (t->ia & 0x3)) {
		dma_copy = 1;
		*head = min(t->size, (size_t)(0x4 - (t->ia & 0x3)));
	} else {
		*head = min(t->size, (size_t)(0x4 - (t->ca & 0x3)));
	}
	*head = *head % 0x4;
	if (t->size > *head)
		*tail = (t->size - *head) % 4;

	return dma_copy;
}

static void pcie_show_desc_list(struct dma_channel_info *channel)
{
	int desc_offset = 0;

	cn_dev_err("transfer_len:%ld desc_len:%d",
			channel->transfer_length, channel->desc_len);

	for(; desc_offset < channel->desc_len; desc_offset += DESC_SIZE) {
		pr_err(
			"%#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x\n",
			ioread32(channel->desc_virt_base + desc_offset + 0),
			ioread32(channel->desc_virt_base + desc_offset + 4),
			ioread32(channel->desc_virt_base + desc_offset + 8),
			ioread32(channel->desc_virt_base + desc_offset + 12),
			ioread32(channel->desc_virt_base + desc_offset + 16),
			ioread32(channel->desc_virt_base + desc_offset + 20),
			ioread32(channel->desc_virt_base + desc_offset + 24),
			ioread32(channel->desc_virt_base + desc_offset + 28));
	}
}

static irqreturn_t c20_vf_pcie_dma_interrupt_handle(void *data)
{
	unsigned int dma_status;
	unsigned int status_i;
	unsigned int channel_bit,max_phy_channel_mask;
	int phy_channel;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct dma_channel_info *channel;

	dma_status = 0;
	for(phy_channel = 0; phy_channel < pcie_set->max_phy_channel; phy_channel++) {
		status_i = cn_pci_reg_read32(pcie_set, DMA_INT_REG(phy_channel));
		if ((!status_i) || status_i == -1U) {
			continue;
		}

		dma_status |= status_i << phy_channel;
		if (status_i) {
			cn_pci_reg_write32(pcie_set, DMA_INT_REG(phy_channel), status_i);
		}
	}
	if (!dma_status) {
		return IRQ_HANDLED;
	}

	channel_bit = (1|(1<<DMA_REG_CHANNEL_NUM));
	max_phy_channel_mask = (1 << pcie_set->max_phy_channel) - 1;
	for (phy_channel = 0; phy_channel < pcie_set->max_phy_channel;
		phy_channel++,(channel_bit <<= 1)) {

		if (!(dma_status & channel_bit))
			continue;
		/* fix change mlu from vf to pf, dma can not used error*/
		cn_pci_reg_write32(pcie_set, DSHARE_ACCESS(phy_channel), 0);

		__sync_fetch_and_and(&pcie_set->channel_run_flag,~(1 << phy_channel));

		channel = (struct dma_channel_info *)pcie_set->running_channels[phy_channel];
		if (!channel) {
			cn_dev_pcie_err(pcie_set,
				"phy_channel:%d is NULL", phy_channel);
			continue;
		}

		if ((dma_status & channel_bit) &
			(max_phy_channel_mask <<DMA_REG_CHANNEL_NUM)) {
			cn_pci_dma_complete(phy_channel, CHANNEL_COMPLETED_ERR, pcie_set);
			cn_dev_pcie_err(pcie_set,
				"DMA  error interrupt_status:0x%x",
								dma_status);
			pcie_show_desc_list(channel);
		} else{

			cn_pci_dma_complete(phy_channel, CHANNEL_COMPLETED, pcie_set);
		}

		if (channel->direction == DMA_H2D) {
			atomic_dec(&pcie_set->inbound_count);
		}

		/*clear DMA transfer ended flag*/
		cn_pci_reg_write32(pcie_set, (DMA_ISTATUS_BASE + phy_channel * 4), 0x0);
		cn_pci_reg_read32(pcie_set, (DMA_ISTATUS_BASE + phy_channel * 4));
	}

	cn_pci_task_fair_schedule(pcie_set);
	return IRQ_HANDLED;
}

/* val: in/out, the input value is the old data, and output val is the new data */
static int c20_vf_wait_pf(struct cn_pcie_set *pcie_set, u32 *val)
{
	int i;
	u32 old_val;
	int timeout = 1000;

	assert(val);
	old_val = *val;

	for (i = 0; i < timeout; i++) {
		*val = cn_pci_reg_read32(pcie_set, MBX_V2P_ADDR_L);

		if (*val != old_val)
			break;

		schedule();
		msleep(1);
	}

	if (i >= timeout) {
		cn_dev_err("c20_vf_wait_pf:timeout");
		return -1;
	}

	return 0;
}

static int c20_vf_notify_init(struct cn_pcie_set *pcie_set)
{
	u32 cmd = CMD_SRIOV_INIT;

	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, cmd);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, MAILBOX_INIT_REG);

	if (c20_vf_wait_pf(pcie_set, &cmd))
		return -1;

	return 0;
}

static int c20_vf_notify_exit(struct cn_pcie_set *pcie_set)
{
	u32 cmd = CMD_SRIOV_EXIT;

	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, cmd);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	if (c20_vf_wait_pf(pcie_set, &cmd))
		return -1;

	return 0;
}

static int c20_vf_get_inbound_info(struct cn_pcie_set *pcie_set,
	u32 *offset, u32 *size)
{
	*offset = CMD_GET_INBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *offset);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	if (c20_vf_wait_pf(pcie_set, offset))
		return -1;

	*size = CMD_GET_INBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *size);

	if (c20_vf_wait_pf(pcie_set, size))
		return -1;

	return 0;
}

static int c20_vf_get_dma_info(struct cn_pcie_set *pcie_set, u32 *dma_mask)
{
	*dma_mask = CMD_GET_DMA_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *dma_mask);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	if (c20_vf_wait_pf(pcie_set, dma_mask))
		return -1;

	return 0;
}

static irqreturn_t c20_vf_mbx_interrupt_handle(void *data)
{
	unsigned int interrupt_status;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct cn_bus_set *bus_set = pcie_set->bus_set;

	cn_dev_info("start c20 mailbox interrupt handle.");

	/*
	 * read dma interrupt register to get whitch channel generate interrupt.
	 * This interrupt may be done or error.not is done and error.
	 */
	interrupt_status = cn_pci_reg_read32(pcie_set, MBX_P2V_CTRL);

	if (interrupt_status)
		cn_pci_reg_write32(pcie_set, MBX_P2V_CTRL, 0);

	if (bus_set) {
#ifndef COMMU_HOST_POLL
		struct cn_core_set *core = bus_set->core;

		if (core)
			cn_commu_mailbox_handler(core);
#endif
	}
	return IRQ_HANDLED;
}

static int c20_vf_pcie_fill_desc_list(struct dma_channel_info *channel)
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
				"No 64 Bytes align : desc device vaddr[%#llx]",
				channel->desc_device_va);
		return -1;
	}

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
				pr_info("C20 only DMA_H2D or DMA_D2H transfer mode\n");
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
		pr_info("C20 only DMA_H2D or DMA_D2H transfer mode\n");
		return -1;
	}
	desc_offset += DESC_SIZE;
	desc_number++;

	channel->desc_len = desc_offset;
	memcpy_toio(channel->desc_virt_base, channel->task->desc_buf, desc_offset);

	return 0;
}

static irqreturn_t c20_vf_msi_interrupt(int irq, void *data)
{
	irqreturn_t ret = IRQ_NONE;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct msix_entry* entry;
	int vector_index;
	int pf2vf_bitmap,arm2vf_bitmap;
	u32 msi_mask = 0;
	entry = (struct msix_entry*)pcie_set->msix_entry_buf;


	vector_index = irq - pcie_set->irq;
	if (vector_index >= GIC_MSI_COUNT) {
		cn_dev_err("Recv error interrupt:%d", irq);
		return ret;
	}

	//mask msi interrupt
	pci_read_config_dword(pcie_set->pdev, pcie_set->msi_pos + 0x10,&msi_mask);

	msi_mask |= (0x1 << vector_index);
	pci_write_config_dword(pcie_set->pdev, pcie_set->msi_pos + 0x10,msi_mask);

	pf2vf_bitmap = cn_pci_reg_read32(pcie_set, 0xc);
	arm2vf_bitmap = cn_pci_reg_read32(pcie_set, 0x14);

	/*read mb regs to decide which interrupt to process*/
	if (pf2vf_bitmap & 0x1) {
		cn_dev_info("recv pf2vf interrupt!!!");
		c20_vf_mbx_interrupt_handle(data);
	} else if (arm2vf_bitmap & 0x1) {
		cn_dev_info("recv arm2vf interrupt!!!");
		cn_pci_reg_write32(pcie_set, 0x14, 0x0);
	} else {
		c20_vf_pcie_dma_interrupt_handle(data);
	}

	//unmask msi interrupt
	pci_read_config_dword(pcie_set->pdev, pcie_set->msi_pos + 0x10,&msi_mask);

	msi_mask &= (~(0x1 << vector_index));
	pci_write_config_dword(pcie_set->pdev, pcie_set->msi_pos + 0x10,msi_mask);

	return IRQ_HANDLED;

}

static int c20_vf_get_outbound_info(struct cn_pcie_set *pcie_set, u32 *size,
	u32 *blocks, u64 *iobase)
{
	u32 upper;
	u32 lower;
	int ret;

	*size = CMD_GET_OUTBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *size);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	ret = c20_vf_wait_pf(pcie_set, size);
	if (ret)
		return ret;

	*blocks = CMD_GET_OUTBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, *blocks);
	ret = c20_vf_wait_pf(pcie_set, blocks);
	if (ret)
		return ret;

	upper = CMD_GET_OUTBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, upper);
	ret = c20_vf_wait_pf(pcie_set, &upper);
	if (ret)
		return ret;

	lower = CMD_GET_OUTBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, lower);
	ret = c20_vf_wait_pf(pcie_set, &lower);
	if (ret)
		return ret;

	*iobase = (((u64)upper) << 32) + (u64)lower;

	pcie_set->ob_axi_addr = *iobase;
	pcie_set->ob_total_size = *size;
	pcie_set->ob_size = *blocks;
	pcie_set->ob_cnt = pcie_set->ob_total_size/pcie_set->ob_size;


	return 0;
}

struct c20_outbound_mem {
	void *virt_addr;
	dma_addr_t pci_addr;
};

static int c20_vf_pcie_outbound_exit(struct cn_pcie_set *pcie_set)
{
	int i;
	struct c20_outbound_mem *outbound_mem;

	outbound_mem = pcie_set->share_priv;
	if ((!outbound_mem) || (!pcie_set->share_mem_pages)) {
		return 0;
	}

	if (pcie_set->share_mem[1].virt_addr) {
		vm_unmap_ram(pcie_set->share_mem[1].virt_addr,
			pcie_set->ob_total_size/PAGE_SIZE);
		pcie_set->share_mem[1].virt_addr = NULL;
	}

	for (i = 0; i < pcie_set->ob_total_size/PAGE_SIZE; i++) {
		if (pcie_set->share_mem_pages[i]) {
			ClearPageReserved(pcie_set->share_mem_pages[i]);
			pcie_set->share_mem_pages[i] = NULL;
		}
	}

	for (i = 0; i < pcie_set->ob_cnt; i++) {
		if (outbound_mem[i].virt_addr)
			pci_free_consistent(pcie_set->pdev, pcie_set->ob_size,
				outbound_mem[i].virt_addr, outbound_mem[i].pci_addr);
	}

	cn_kfree(pcie_set->share_mem_pages);
	pcie_set->share_mem_pages = NULL;
	cn_kfree(pcie_set->share_priv);
	pcie_set->share_priv = NULL;

	return 0;
}

static int c20_vf_pcie_outbound_init(struct cn_pcie_set *pcie_set)
{
	int i;
	int j;
	int page_index = 0;
	struct c20_outbound_mem *outbound_mem;
	int index = pcie_set->share_mem_cnt;
	int ret;

	ret = c20_vf_get_outbound_info(pcie_set, &pcie_set->ob_total_size,
		&pcie_set->ob_size, &pcie_set->ob_axi_addr);
	if (ret)
		return -1;


	pcie_set->ob_cnt = pcie_set->ob_total_size/pcie_set->ob_size;
	cn_dev_info("ob_total_size:%x ob_size:%x ob_axi_addr:%llx ob_cnt:%x",
		pcie_set->ob_total_size, pcie_set->ob_size, pcie_set->ob_axi_addr,
		pcie_set->ob_cnt);

	pcie_set->share_mem_pages = (struct page **)cn_kzalloc(
		sizeof(struct page *)*(pcie_set->ob_total_size / PAGE_SIZE),
		GFP_KERNEL);
	if (!pcie_set->share_mem_pages) {
		cn_dev_err("Malloc share_mem_pages error");
		return -ENOMEM;
	}

	outbound_mem = (struct c20_outbound_mem *)cn_kzalloc(
		pcie_set->ob_cnt * sizeof(struct c20_outbound_mem), GFP_KERNEL);
	if (!outbound_mem) {
		cn_dev_err("Malloc outbound_mem error");
		ret = -ENOMEM;
		goto ERROR_RET;
	}
	pcie_set->share_priv = (void *)outbound_mem;

	for (i = 0; i < pcie_set->ob_cnt; i++) {

		/*alloc outband momery*/
		outbound_mem[i].virt_addr = dma_alloc_coherent(&pcie_set->pdev->dev,
			pcie_set->ob_size, &(outbound_mem[i].pci_addr), GFP_KERNEL);

		cn_dev_info("outbound:%d alloc pci_addr:%llx ob_size:%x virt_addr:%lx",
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

	cn_dev_info("host share mem virtual addr:%lx",
		(unsigned long)pcie_set->share_mem[index].virt_addr);
	pcie_set->share_mem[index].win_length = pcie_set->ob_total_size;
	pcie_set->share_mem[index].type = CN_SHARE_MEM_HOST;
	pcie_set->share_mem[index].device_addr = pcie_set->ob_axi_addr;

	pcie_set->share_mem_cnt++;
	return 0;

ERROR_RET:
	cn_dev_err("init error");
	c20_vf_pcie_outbound_exit(pcie_set);

	return ret;
}
static void c20_vf_pcie_unregister_bar(struct cn_pcie_set *pcie_set)
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

static void c20_vf_bar_deinit(struct cn_pcie_set *pcie_set)
{
	int bar;
	int seg;

	cn_dev_pcie_info(pcie_set, "cn_iounmap bar0-5");
	c20_vf_notify_exit(pcie_set);

	for (bar = 0; bar < 6; bar ++) {
		if (pcie_set->pcibar[bar].size <= 0)
			continue;

		for (seg = 0; seg < MAX_BAR_SEGMENTS; seg++) {
			if (pcie_set->pcibar[bar].seg[seg].virt) {
				cn_iounmap(pcie_set->pcibar[bar].seg[seg].virt);
				pcie_set->pcibar[bar].seg[seg].virt = NULL;
			}
		}
	}
	c20_vf_pcie_unregister_bar(pcie_set);
	pcie_set->reg_virt_base = NULL;
	pcie_set->reg_phy_addr = 0;
	pcie_set->reg_win_length = 0;
}

static int c20_vf_pcie_exit(struct cn_pcie_set *pcie_set)
{
	if (isr_disable_func[0](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr destroyed failed!");
		return -1;
	}

	c20_vf_bar_deinit(pcie_set);

	if (pcie_set->vf_priv_data) {
		cn_kfree(pcie_set->vf_priv_data);
		pcie_set->vf_priv_data = NULL;
	}

	return 0;
}
static int pcie_get_irq(char *irq_desc, struct cn_pcie_set *pcie_set)
{
	int i = 0;

	for(; i < 256; i++) {
		if (!strcmp(pcie_set->irq_str_index_ptr[i].str_index, irq_desc))
			return pcie_set->irq_str_index_ptr[i].hw_irq_num;
	}

	return -1;
}
static int c20_vf_pcie_init(struct cn_pcie_set *pcie_set)
{
	return 0;
}

static int c20_vf_pcie_pre_exit(struct cn_pcie_set *pcie_set)
{
	cn_dev_info("pcie exit end");
	return 0;
}

static int c20_vf_pcie_dma_go(struct dma_channel_info *channel, int phy_channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	int channel_id = phy_channel;
	unsigned long src_desc_addr = 0;
	unsigned long dst_desc_addr = 0;
	int sgl_enable = 0;
	int sgl_mode = 0;
	int sg_id[2] = {0};
	unsigned int value;

	if (channel->status != CHANNEL_RUNNING)
		cn_dev_pcie_err(pcie_set, "channel is not locked:%d", channel->status);

	if (channel->direction == DMA_H2D) {
		if (!atomic_add_unless(&pcie_set->inbound_count, 1,
			pcie_set->max_inbound_cnt))
			return -EINVAL;
	}

	switch (channel->direction) {
	case DMA_H2D:
		cn_pci_reg_write32(pcie_set,
			DSRC_PARAM(channel_id), DMA_PCIE_PARAM);


		cn_pci_reg_write32(pcie_set,
			DDEST_PARAM(channel_id), DMA_AXI_PARAM);
		break;

	case DMA_D2H:
		cn_pci_reg_write32(pcie_set,
			DSRC_PARAM(channel_id), DMA_AXI_PARAM);
		cn_pci_reg_write32(pcie_set,
			DDEST_PARAM(channel_id), DMA_PCIE_PARAM);
		break;

	default:
		return -1;
	}
	src_desc_addr = channel->desc_device_va;
	dst_desc_addr = 0;
	sg_id[0] = SG_ID_AXI;//desc addr is pcie or axi
	sgl_mode = 3;
	sgl_enable = 1;

	cn_pci_reg_write32(pcie_set, DLEN(channel_id), channel->transfer_length);
	cn_pci_reg_write32(pcie_set, DSRCL(channel_id), LOWER32(src_desc_addr));
	cn_pci_reg_write32(pcie_set, DSRCU(channel_id), UPPER32(src_desc_addr));
	cn_pci_reg_write32(pcie_set, DDESTL(channel_id), LOWER32(dst_desc_addr));
	cn_pci_reg_write32(pcie_set, DDESTU(channel_id), UPPER32(dst_desc_addr));

	cn_pci_reg_write32(pcie_set, DCTRL(channel_id), (sgl_enable << 3)
					| (DSE_COND << 4) | (DIRQ << 8)
					| (DIRQ_ID << 12) | (sgl_mode << 24)
					| (sg_id[0] << 26) | (sg_id[1] << 29));
	value = cn_pci_reg_read32(pcie_set, DCTRL(channel_id));
	value |= 0x1;
	cn_pci_reg_write32(pcie_set, DCTRL(channel_id), value);

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

static int c20_vf_flush_irq(struct cn_pcie_set *pcie_set)
{
	u32 msi_mask = 0;

	//unmask msi interrupt
	pci_read_config_dword(pcie_set->pdev, pcie_set->msi_pos + 0x10, &msi_mask);
	msi_mask |= ((0x1 << GIC_MSI_COUNT) - 1);
	pci_write_config_dword(pcie_set->pdev, pcie_set->msi_pos + 0x10, msi_mask);
	msi_mask &= (~((0x1 << GIC_MSI_COUNT) - 1));
	pci_write_config_dword(pcie_set->pdev, pcie_set->msi_pos + 0x10, msi_mask);

	return 0;
}

static struct cn_pci_ops c20_vf_ops = {
	.pcie_init = c20_vf_pcie_init,
	.pcie_pre_exit = c20_vf_pcie_pre_exit,
	.pcie_exit = c20_vf_pcie_exit,
	.fill_desc_list = c20_vf_pcie_fill_desc_list,
	.show_desc_list = pcie_show_desc_list,
	.dump_reg = c20_vf_pcie_dump_reg,
	.get_irq_by_desc = pcie_get_irq,
	.pci_mb = c20_vf_pcie_mb,
	.dma_align = c20_vf_dma_align,
	.dma_bypass_size = pcie_dma_bypass_size,
	.set_bar_window = pcie_set_bar_window,
	.msi_isr = c20_vf_msi_interrupt,
	.dma_go_command =  c20_vf_pcie_dma_go,
	.bar_read = mlu290_ce3226_pcie_bar_read,
	.bar_write = mlu290_ce3226_pcie_bar_write,
	.flush_irq = c20_vf_flush_irq,
};

static struct bar_resource *c20_vf_set_init_pf(struct cn_pcie_set *pcie_set, int index)
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
	bar->bus_base = cn_pci_bus_address(pdev, index);
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

	if (index == 2) {
		bar->reg_index = VF_BAR2_BASE_ADDR_L;
		cn_pci_reg_write32(pcie_set, VF_BAR2_MASK_L, sz-1);
		cn_pci_reg_read32(pcie_set, VF_BAR2_MASK_L);
	} else {
		bar->reg_index = VF_BAR4_BASE_ADDR_L;
		cn_pci_reg_write32(pcie_set, VF_BAR4_MASK_L, sz-1);
		cn_pci_reg_read32(pcie_set, VF_BAR4_MASK_L);
	}


	return bar;
}

static int c20_vf_pcie_enable_pf_bar(struct cn_pcie_set *pcie_set)
{
	int index;
	struct bar_resource *bar;

	for (index = 2; index < 6; index++) {
		bar = c20_vf_set_init_pf(pcie_set, index);
		if (bar)
			list_add_tail(&bar->list, &pcie_set->bar_resource_head);
	}

	return 0;
}

static int c20_vf_pcie_bar_init(struct cn_pcie_set *pcie_set)
{
	//int bar;
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
	cn_dev_info("Bar0 register virt:%lx size:%llx",
		(ulong)p_bar_seg->virt, p_bar_seg->size);
	if (!p_bar_seg->virt) {
		goto ERROR_RET;
	}

	pcie_set->reg_virt_base = p_bar_seg->virt;
	pcie_set->reg_phy_addr = p_bar_seg->base;
	pcie_set->reg_win_length = p_bar_seg->size;

	/* the bar share memory */
	p_bar_seg = &p_bar->seg[1];
	p_bar_seg->base = p_bar->base + pcie_set->reg_win_length;
	p_bar_seg->size = p_bar->size - pcie_set->reg_win_length;
	p_bar_seg->virt = cn_ioremap_wc(p_bar_seg->base, p_bar_seg->size);
	cn_dev_info("Bar0 memory virt:%lx size:%llx",
		(ulong)p_bar_seg->virt, p_bar_seg->size);

	if (c20_vf_pcie_enable_pf_bar(pcie_set))
		goto ERROR_RET;

	if (!p_bar_seg->virt)
		goto ERROR_RET;

	c20_vf_notify_init(pcie_set);

	pcie_set->share_mem_cnt = 1;
	if (c20_vf_get_inbound_info(pcie_set, &vf_share_mem_base,
		&vf_share_mem_size)) {
		cn_dev_err("get inbound info error.");
		goto ERROR_RET;
	}
	cn_dev_info("vf_share_mem_base:%x size:%x",
		vf_share_mem_base, vf_share_mem_size);

#ifdef C20_PCIE_SMMU_ENABLE
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

	c20_vf_bar_deinit(pcie_set);
	return -1;
}

static int c20_vf_outbound_reg(struct cn_pcie_set *pcie_set)
{
	int i;
	u32 cmd;
	u32 size;
	u32 upper;
	u32 lower;
	int ret = 0;
	struct c20_outbound_mem *outbound_mem;

	outbound_mem = pcie_set->share_priv;

	cmd = CMD_SET_OUTBOUND_INFO;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, cmd);
	cn_pci_reg_write32(pcie_set, MBX_V2P_CTRL, 1);

	ret = c20_vf_wait_pf(pcie_set, &cmd);
	if (ret) {
		cn_dev_err("CMD_SET_OUTBOUND_INFO cmd error");
		return ret;
	}

	size = pcie_set->ob_size;
	cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, size);
	ret = c20_vf_wait_pf(pcie_set, &size);
	if (ret) {
		cn_dev_err("CMD_SET_OUTBOUND_INFO size error");
		return ret;
	}

	for (i = 0; i < pcie_set->ob_cnt; i++) {
		upper = (u32)(outbound_mem[i].pci_addr >> 32);
		cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, upper);
		ret = c20_vf_wait_pf(pcie_set, &upper);
		if (ret) {
			cn_dev_err("CMD_SET_OUTBOUND_INFO:%d upper:%x error", i, upper);
			return ret;
		}

		lower = (u32)(outbound_mem[i].pci_addr & (-1U));
		cn_pci_reg_write32(pcie_set, MBX_V2P_ADDR_L, lower);
		ret = c20_vf_wait_pf(pcie_set, &lower);
		if (ret) {
			cn_dev_err("CMD_SET_OUTBOUND_INFO:%d lower:%x error", i, lower);
			return ret;
		}
	}

	return 0;
}


static int c20_vf_pre_init_hw(struct cn_pcie_set *pcie_set)
{
	int ret;

	if (pcie_set->outbound_able) {
		ret = c20_vf_outbound_reg(pcie_set);
		if (ret) {
			cn_dev_err("error");
			return ret;
		}
	}

	return 0;
}

static int c20_vf_clear_irq(struct cn_pcie_set *pcie_set)
{
	int i;
	u32 reg_val;

	for (i = 0; i < DMA_REG_CHANNEL_NUM; i++) {
		reg_val = cn_pci_reg_read32(pcie_set, DMA_INT_REG(i));
		if (reg_val == 1) {
			cn_pci_reg_write32(pcie_set, DMA_INT_REG(i), 1);
		}
	}

	cn_pci_reg_write32(pcie_set, MBX_P2V_CTRL, 0);
	c20_vf_flush_irq(pcie_set);

	return 0;
}

static int c20_vf_pcie_setup(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	int result = 0;
	u32 channel_mask;
	int ret;

	pcie_set->ops = &c20_vf_ops;
	pcie_set->is_virtfn = 1;

	pcie_set->vf_priv_data = cn_kzalloc(sizeof(struct cn_pci_vf_priv_data), GFP_KERNEL);
	if(!pcie_set->vf_priv_data) {
		cn_dev_pcie_err(pcie_set, "vf_priv_data alloc failed");
		return -1;
	}

	pcie_set->share_mem_cnt = 0;
	INIT_LIST_HEAD(&pcie_set->bar_resource_head);
	if (c20_vf_pcie_bar_init(pcie_set))
		return -1;

	c20_vf_clear_irq(pcie_set);

	if (c20_vf_get_dma_info(pcie_set, &channel_mask))
		goto RELEASE_BAR;

	cn_dev_info("channel_mask:%x", channel_mask);

	pcie_set->max_phy_channel = __fls(channel_mask) + 1;
	pcie_set->dma_phy_channel_mask = channel_mask;
	pcie_set->max_inbound_cnt = hweight32(channel_mask) * 2;
	/* dma desc size */
	pcie_set->async_static_desc_size = ASYNC_STATIC_DESC_SIZE;
	pcie_set->dma_buffer_size = C20_VF_DMA_BUFFER_SIZE;
	pcie_set->shared_desc_total_size = SHARED_DMA_DESC_TOTAL_SIZE;
	pcie_set->per_desc_size = DESC_SIZE;
	pcie_set->async_max_desc_num = ASYNC_DMA_DESC;
	pcie_set->async_static_task_num = pcie_set->async_static_desc_size /
					pcie_set->per_desc_size /
					pcie_set->async_max_desc_num;

	cn_dev_info("max_phy_channel:%x\n", (int)pcie_set->max_phy_channel);
	cn_dev_info("shared_desc_total_size:%x\n", (int)pcie_set->shared_desc_total_size);

	pcie_set->irq_num = GIC_MSI_COUNT;

	pcie_set->irq_type = (isr_type_index == -1) ? isr_default_type : isr_type_index;

	/* get outband memory info */
	if (pcie_set->outbound_able) {
		ret = c20_vf_pcie_outbound_init(pcie_set);
		if (ret)
			goto RELEASE_OUTBOUND;
	}

	/* register vf msi ISR */
	if (isr_enable_func[0](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr init failed!");
		return -1;
	}

	/* c20_vf_outbound_reg */
	if (c20_vf_pre_init_hw(pcie_set))
		goto RELEASE_BAR;

	return result;

RELEASE_OUTBOUND:
	c20_vf_pcie_outbound_exit(pcie_set);
RELEASE_BAR:
	c20_vf_bar_deinit(pcie_set);
	if (pcie_set->vf_priv_data) {
		cn_kfree(pcie_set->vf_priv_data);
		pcie_set->vf_priv_data = NULL;
	}
	return -1;
}

static int c20_vf_bus_pre_init(void *pcie)
{
	return 0;
}

static int c20_vf_bus_pre_exit(void *pcie)
{
	return 0;
}

static int c20_vf_pcie_domain_get_resource(void *pcie, struct domain_resource *resource)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	resource->id = pcie_set->id;

	return 0;
}

struct cn_pci_info c20_vf_pci_info = {
	.setup = c20_vf_pcie_setup,
	.pre_init = c20_vf_bus_pre_init,
	.pre_exit = c20_vf_bus_pre_exit,
	.get_resource = c20_vf_pcie_domain_get_resource,
	.dev_name = "c20-vf"
};
