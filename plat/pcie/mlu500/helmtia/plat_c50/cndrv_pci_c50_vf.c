/************************************************************************
 *
 *  @file cndrv_pci_c50_vf.c
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
#include <linux/spinlock.h>
#include <linux/limits.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "../../pcie_dma.h"
#include "../../cndrv_pci.h"
#include "../../pcie_bar.h"
#include "cndrv_mm.h"
#include "cndrv_mcu.h"
#include "./cndrv_pci_c50.h"
#include "./cndrv_pci_c50_vf.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "../../pcie_common.c"
#include "../../pcie_interrupt.c"
#include "cndrv_proc.h"

#define PCIE_TO_PCIE		(0x0)
#define PCIE_TO_AXI		(0x1)
#define AXI_TO_PCIE		(0x2)
#define AXI_TO_AXI		(0x3)
#define SRC_ID_PCIE		(0x0)
#define SRC_ID_AXI		(0x2)
#define PCIE_SNOOP		(0x2)

static struct cn_pci_irq_str_index irq_str_index[GIC_INTERRUPT_NUM] = {
	{0, "pcie_dma_int"},
	{1, "p2v_mbx"},
	{2, "a2v_mbx"},
	{3, "dr2v_mbx"},
	{4, "vf_bar_remap_irq"},
};

enum wait_flag_pos {
	alloc_commu_ctrlq,
	set_outbound_info,
	sriov_init,
	sriov_exit,
	get_inbound_info,
	get_outbound_info,
	get_dma_info,
	set_sw_info,
	sriov_late_init,
	get_sram_info
};


static int pci_hw_msi_enable(struct cn_pcie_set *pcie_set);
static int pci_hw_msix_enable(struct cn_pcie_set *pcie_set);

static int pci_hw_msi_disable(struct cn_pcie_set *pcie_set);
static int pci_hw_msix_disable(struct cn_pcie_set *pcie_set);
static void c50_vf_pcie_put_data_outbound_iova(struct cn_pcie_set *pcie_set, struct sg_table **iova_sgt);
static void c50_vf_pcie_release_data_outbound_iova(struct cn_pcie_set *pcie_set);

static int (*isr_hw_enable[3]) (struct cn_pcie_set *) = {
	pci_hw_msi_enable,
	pci_hw_msix_enable,
	NULL  /* vf don't support intx */
};

static int (*isr_hw_disable[3])(struct cn_pcie_set *) = {
	pci_hw_msi_disable,
	pci_hw_msix_disable,
	NULL
};

static int pcie_get_irq(char *irq_desc, struct cn_pcie_set *pcie_set)
{
	int i = 0;

	for (; i < 256; i++) {
		if (!strcmp(pcie_set->irq_str_index_ptr[i].str_index, irq_desc))
			return pcie_set->irq_str_index_ptr[i].hw_irq_num;
	}

	return -1;
}

static void c50_vf_pcie_dump_reg(struct cn_pcie_set *pcie_set);

struct c50_pcie_dump_reg_s {
	char *desc;
	unsigned long reg;
};

static void c50_vf_pcie_dump_reg(struct cn_pcie_set *pcie_set)
{
	cn_dev_pcie_info(pcie_set, "no dump function, please add in private file.");
	return;
}


static int pci_hw_msix_enable(struct cn_pcie_set *pcie_set)
{
	/* enable msix*/
	cn_pci_reg_write32(pcie_set, VF_GIC_CTRL,
				GIC_ENABLE_MSIX_BIT | GIC_OPEN_GI_BIT);
	cn_pci_reg_read32(pcie_set, VF_GIC_CTRL);

	return 0;
}

static int pci_hw_msix_disable(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, VF_GIC_CTRL, 0);
	cn_pci_reg_read32(pcie_set, VF_GIC_CTRL);

	return 0;
}

static int pci_hw_msi_enable(struct cn_pcie_set *pcie_set)
{
	/* enable msi */
	cn_pci_reg_write32(pcie_set, VF_GIC_CTRL,
				GIC_ENABLE_MSI_BIT | GIC_OPEN_GI_BIT);
	cn_pci_reg_read32(pcie_set, VF_GIC_CTRL);

	return 0;
}

static int pci_hw_msi_disable(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, VF_GIC_CTRL, 0);
	cn_pci_reg_read32(pcie_set, VF_GIC_CTRL);

	return 0;
}

static void pci_isr_hw_enable(struct cn_pcie_set *pcie_set)
{
	if (isr_hw_enable[pcie_set->irq_set.irq_type])
		isr_hw_enable[pcie_set->irq_set.irq_type](pcie_set);
}

static void pci_isr_hw_disable(struct cn_pcie_set *pcie_set)
{
	if (isr_hw_disable[pcie_set->irq_set.irq_type])
		isr_hw_disable[pcie_set->irq_set.irq_type](pcie_set);
}

__attribute__((unused))
static void pcie_async_show_desc_list(struct async_task *async_task)
{
	void __iomem *host_desc_addr = (void __iomem *)async_task->host_desc_addr;
	int i, desc_offset = 0;

	if (async_task->dma_type != PCIE_DMA_P2P) {
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
	} else {
		cn_dev_pcie_err(async_task->pcie_set,
			"%#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x",
			ioread32(host_desc_addr + desc_offset + 0),
			ioread32(host_desc_addr  + desc_offset + 4),
			ioread32(host_desc_addr  + desc_offset + 8),
			ioread32(host_desc_addr  + desc_offset + 12),
			ioread32(host_desc_addr  + desc_offset + 16),
			ioread32(host_desc_addr  + desc_offset + 20),
			ioread32(host_desc_addr  + desc_offset + 24),
			ioread32(host_desc_addr  + desc_offset + 28));
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

static int c50_vf_pcie_fill_desc_list(struct dma_channel_info *channel)
{
	int i;
	unsigned long cpu_dma_addr = 0;
	u64 ipu_ram_dma_addr;
	unsigned long count = 0;
	struct scatterlist *sg;
	int desc_offset = 0;
	int desc_number = 0;
	unsigned long cpu_addr_cur;
	unsigned long count_cur;

	if (channel->task->dma_type == PCIE_DMA_MEMSET)
		return 0;

	ipu_ram_dma_addr = channel->ram_addr;

	if (channel->desc_device_va % 64) {
		cn_dev_pcie_err(channel->pcie_set,
				"No 64 Bytes align : desc device vaddr");
		return -1;
	}

	if ((channel->direction != DMA_P2P) ||
			(channel->task->p2p_trans_type != P2P_TRANS_BUS_ADDRESS)) {
		for_each_sg(channel->sg, sg, channel->nents, i) {
			cpu_addr_cur = sg_dma_address(sg);
			count_cur = sg_dma_len(sg);

			if (!i)
				cpu_dma_addr = cpu_addr_cur;

			if (cpu_dma_addr + count == cpu_addr_cur)
				count += count_cur;
			else {
				fill_descriptor(channel->pcie_set, channel->direction,
						channel->desc_device_va, channel->task->desc_buf,
						ipu_ram_dma_addr, cpu_dma_addr, count,
						&desc_number, &desc_offset, 0);
				ipu_ram_dma_addr += count;
				cpu_dma_addr = cpu_addr_cur;
				count = count_cur;
			}
		}
		fill_descriptor(channel->pcie_set, channel->direction,
				channel->desc_device_va, channel->task->desc_buf,
				ipu_ram_dma_addr, cpu_dma_addr, count,
				&desc_number, &desc_offset, 1);
	} else {
		cpu_dma_addr = channel->cpu_addr;
		count = channel->transfer_length;

		fill_descriptor(channel->pcie_set, channel->direction,
				channel->desc_device_va, channel->task->desc_buf,
				ipu_ram_dma_addr, cpu_dma_addr, count,
				&desc_number, &desc_offset, 1);
	}

	channel->desc_len = desc_offset;
	memcpy_toio(channel->desc_virt_base, channel->task->desc_buf, desc_offset);

	return 0;
}

static int c50_vf_async_dma_fill_desc_list(struct async_task *async_task)
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


static void host_vf_queue_status_buf_status(int *queue_status_buf_num,
						struct cn_pcie_set *pcie_set)
{
	int queue;
	u32 status_buf_status;

	status_buf_status = cn_pci_reg_read32(pcie_set,
				VF_CMD_STATUS_BUF_STATUS_ENGINE);
	for (queue = 0; queue < DMA_MAX_QUEUE_NUM; queue++) {
		queue_status_buf_num[queue] = GET_BITS_VAL(status_buf_status,
						queue * 8 + 3, queue * 8 + 0);
		cn_dev_pcie_debug(pcie_set, "queue%d_status_buf_num=%d",
					queue, queue_status_buf_num[queue]);
	}
}

static void pcie_show_desc_list(struct dma_channel_info *channel)
{
#if defined(__x86_64__)
	int desc_offset = 0;

	cn_dev_pcie_err(channel->pcie_set, "transfer_len:%ld desc_len:%d",
		channel->transfer_length, channel->desc_len);

	for (; desc_offset < channel->desc_len; desc_offset += DESC_SIZE) {
		cn_dev_pcie_err(channel->pcie_set,
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
#endif
}

static irqreturn_t c50_vf_pcie_dma_interrupt_handle(int index, void *data)
{
	unsigned int queue_status;
	int queue_status_buf_num[4];
	int phy_channel;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct dma_channel_info *channel;
	int command_id;

	/*
	 * read dma interrupt register to get which queue generate interrupt
	 * This interrupt may be done or error.not is done and error.
	 */
	host_vf_queue_status_buf_status(queue_status_buf_num, pcie_set);
	for_each_set_bit(phy_channel, (unsigned long *)&pcie_set->dma_set.dma_phy_channel_mask,
		pcie_set->dma_set.max_phy_channel) {
		if (!queue_status_buf_num[phy_channel])
			continue;

		while (queue_status_buf_num[phy_channel]) {
			queue_status = cn_pci_reg_read32(pcie_set,
					VF_DMA_STATUS_QUEUE(phy_channel));
			command_id = GET_BITS_VAL(queue_status, 25, 22);
			cn_dev_pcie_debug(pcie_set, "command_id=%d", command_id);
			cn_pci_reg_write32(pcie_set,
				VF_DMA_STATUS_UP_QUEUE(phy_channel), 1);

			channel = (struct dma_channel_info *)
				pcie_set->dma_set.running_channels[phy_channel][command_id];
			if (!channel) {
				cn_dev_pcie_err(pcie_set,
					"phy_channel:%d is NULL", phy_channel);
				break;
			}
			if (DMA_QUEUE_ERR_CHECK(queue_status)) {
				cn_dev_pcie_err(pcie_set, "queue%d irq error:%#x",
							phy_channel, queue_status);
				if (pcie_set->ops->dump_reg)
					pcie_set->ops->dump_reg(pcie_set);

				pcie_set->ops->show_desc_list(channel);
				cn_pci_dma_complete(phy_channel, command_id,
						CHANNEL_COMPLETED_ERR, pcie_set);
			} else {
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

static int c50_vf_wait_pf_mbx(struct cn_pcie_set *pcie_set)
{
	int i = 0;
	u32 reg_value;

	do {
		reg_value = cn_pci_reg_read32(pcie_set, VF2PF_MBX_STATUS(0));
		if (reg_value & 0x1) {
			schedule();
			msleep(1);
		}

		i++;
		if (i > 1000000) {
			cn_dev_pcie_err(pcie_set, "Wait Mailbox Available time out.");
			return -1;
		}

	} while (reg_value & 0x1u);

	return 0;
}

static int c50_vf_pcie_dma_go(struct dma_channel_info *channel, int phy_channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	struct pcie_dma_task *task = channel->task;
	unsigned long desc_addr = 0;
	unsigned int desc_num = 0;
	unsigned int memset_type = 0;
	unsigned long flag = 0;

	if (channel->status != CHANNEL_RUNNING)
		cn_dev_pcie_err(pcie_set, "channel is not locked %d",
				channel->status);

	spin_lock_irqsave(&pcie_set->dma_set.fetch_lock[phy_channel], flag);
	switch (channel->direction) {
	case DMA_H2D:
		cn_pci_reg_write32(pcie_set,
			VF_CTRL_CMD_CTRL1_QUEUE(phy_channel),
			(PCIE_TO_AXI << 0) | (SRC_ID_AXI << 2) | (PCIE_SNOOP << 4));
		break;
	case DMA_D2H:
		cn_pci_reg_write32(pcie_set,
			VF_CTRL_CMD_CTRL1_QUEUE(phy_channel),
			(AXI_TO_PCIE << 0) | (SRC_ID_AXI << 2) | (PCIE_SNOOP << 20));
		break;
	case DMA_P2P:
		if (pcie_set->cfg.p2p_mode == P2P_PULL_MODE) {
			cn_pci_reg_write32(pcie_set,
				VF_CTRL_CMD_CTRL1_QUEUE(phy_channel),
				(PCIE_TO_AXI << 0) | (SRC_ID_AXI << 2) | (PCIE_SNOOP << 4));
		} else {
			cn_pci_reg_write32(pcie_set,
				VF_CTRL_CMD_CTRL1_QUEUE(phy_channel),
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
		cn_dev_pcie_err(pcie_set, "channel->direction=%d undefined",
							channel->direction);
		spin_unlock_irqrestore(&pcie_set->dma_set.fetch_lock[phy_channel], flag);
		return -1;
	}

	if (task->dma_type == PCIE_DMA_MEMSET) {
		cn_pci_reg_write32(pcie_set,
				VF_CTRL_LOW_QUEUE(phy_channel),
				LOWER32(channel->ram_addr));
		cn_pci_reg_write32(pcie_set,
				VF_CTRL_HIGH_QUEUE(phy_channel),
				UPPER16(channel->ram_addr) | memset_type |
				(channel->fetch_command_id << 24));
		cn_pci_reg_write64(pcie_set,
				VF_CTRL_DESC_NUM_QUEUE(phy_channel),
				channel->cpu_addr);
		cn_pci_reg_read32(pcie_set,
				VF_CTRL_CMD_CTRL1_QUEUE(phy_channel));
		cn_pci_reg_write32(pcie_set,
				VF_CTRL_CMD_CTRL2_QUEUE(phy_channel),
				(0x1 << 31) | (0x1 << 30) |
				(channel->transfer_length & (~(0xC0000000))));
		spin_unlock_irqrestore(&pcie_set->dma_set.fetch_lock[phy_channel], flag);

		return 0;
	}

	desc_addr = channel->desc_device_va;
	desc_num = channel->desc_len / pcie_set->per_desc_size;

	cn_pci_reg_write32(pcie_set, VF_CTRL_LOW_QUEUE(phy_channel),
					LOWER32(desc_addr));
	cn_pci_reg_write32(pcie_set, VF_CTRL_HIGH_QUEUE(phy_channel),
					UPPER32(desc_addr));
	cn_pci_reg_write32(pcie_set, VF_CTRL_DESC_NUM_QUEUE(phy_channel),
					desc_num | (channel->fetch_command_id << 16));
	cn_pci_reg_read32(pcie_set, VF_CTRL_DESC_NUM_QUEUE(phy_channel));
	cn_pci_reg_write32(pcie_set, VF_CTRL_CMD_CTRL2_QUEUE(phy_channel),
					(0x1 << 31));
	spin_unlock_irqrestore(&pcie_set->dma_set.fetch_lock[phy_channel], flag);

	return 0;
}

static int c50_vf_notify_init(struct cn_pcie_set *pcie_set)
{
	int ret;
	u32 reg_value;
	enum wait_flag_pos pos = sriov_init;

	if (c50_vf_wait_pf_mbx(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "Sriov init failed.");
		return -1;
	}

	reg_value = MAILBOX_INIT_REG;
	cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYL(0), reg_value);
	barrier();
	reg_value = CMD_SRIOV_INIT;
	reg_value = (reg_value << 16) | 0x1;
	cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
	ret = wait_event_interruptible_timeout(
				pcie_set->vf_priv_data->p2v_wait_queue,
				pcie_set->vf_priv_data->wait_flag
				& (0x1u << pos), msecs_to_jiffies(50000));
	if (ret < 0) {
		cn_dev_pcie_err(pcie_set, "breaked by signal");
		return -1;
	} else if (ret == 0) {
		cn_dev_pcie_err(pcie_set, "Wait PF sriov init time out.");
		return -1;
	}

	return 0;
}

static void c50_vf_notify_exit(struct cn_pcie_set *pcie_set)
{
	u32 reg_value, i;
	int ret;
	enum wait_flag_pos pos = sriov_exit;

	if (c50_vf_wait_pf_mbx(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "Sriov exit failed.");
		return;
	}

	reg_value = CMD_SRIOV_EXIT;
	reg_value = (reg_value << 16) | 0x1u;
	cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
	reg_value = cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	if (reg_value & (0x1u << 1)) {
		for (i = 0; i < 5000; i++) {
			reg_value = cn_pci_reg_read32(pcie_set, PF2VF_MBX_ENTRYH(1));
			reg_value = (reg_value & 0xFFFF0000u) >> 16;
			if (reg_value == CMD_SRIOV_EXIT)
				break;

			msleep(1);
		}

		if (i == 5000) {
			cn_dev_pcie_err(pcie_set, "Wait PF sriov exit time out.");
		}

		return;
	}

	ret = wait_event_interruptible_timeout(
					pcie_set->vf_priv_data->p2v_wait_queue,
					pcie_set->vf_priv_data->wait_flag
					& (0x1 << pos),
					msecs_to_jiffies(5000));
	if (ret < 0) {
		cn_dev_pcie_err(pcie_set, "breaked by signal");
	} else if (ret == 0) {
		cn_dev_pcie_err(pcie_set, "Wait PF sriov exit time out.");
	}

	return;
}

static int c50_vf_notify_late_init(struct cn_pcie_set *pcie_set)
{
	u32 reg_value;
	int ret;
	enum wait_flag_pos pos = sriov_late_init;

	if (c50_vf_wait_pf_mbx(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "Sriov pre_exit failed.");
		return -1;
	}

	reg_value = CMD_SRIOV_LATE_INIT;
	reg_value = (reg_value << 16) | 0x1u;
	cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
	ret = wait_event_interruptible_timeout(
			pcie_set->vf_priv_data->p2v_wait_queue,
			pcie_set->vf_priv_data->wait_flag & (0x1u << pos),
			msecs_to_jiffies(5000));
	if (ret < 0) {
		cn_dev_pcie_err(pcie_set, "breaked by signal");
		return -1;
	} else if (ret == 0) {
		cn_dev_pcie_err(pcie_set, "Wait PF sriov late init time out.");
		return -1;
	}

	return 0;
}

static int c50_vf_get_inbound_info(struct cn_pcie_set *pcie_set)
{
	u32 reg_value;
	int ret;
	enum wait_flag_pos pos = get_inbound_info;

	if (c50_vf_wait_pf_mbx(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "get inbound info failed.");
		return -1;
	}

	reg_value = CMD_GET_INBOUND_INFO;
	reg_value = (reg_value << 16) | 0x1u;
	cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
	ret = wait_event_interruptible_timeout(
			pcie_set->vf_priv_data->p2v_wait_queue,
			pcie_set->vf_priv_data->wait_flag & (0x1u << pos),
			msecs_to_jiffies(5000));
	if (ret < 0) {
		cn_dev_pcie_err(pcie_set, "breaked by signal");
		return -1;
	} else if (ret == 0) {
		cn_dev_pcie_err(pcie_set, "Get inbound info time out.");
		return -1;
	}

	return 0;
}

static int c50_vf_get_sram_info(struct cn_pcie_set *pcie_set)
{
	u32 reg_value;
	int ret;
	enum wait_flag_pos pos = get_sram_info;

	if (c50_vf_wait_pf_mbx(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "get inbound info failed.");
		return -1;
	}

	reg_value = CMD_GET_SRAM_INFO;
	reg_value = (reg_value << 16) | 0x1u;
	cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
	ret = wait_event_interruptible_timeout(
			pcie_set->vf_priv_data->p2v_wait_queue,
			pcie_set->vf_priv_data->wait_flag & (0x1u << pos),
			msecs_to_jiffies(5000));
	if (ret < 0) {
		cn_dev_pcie_err(pcie_set, "breaked by signal");
		return -1;
	} else if (ret == 0) {
		cn_dev_pcie_err(pcie_set, "Get sram info time out.");
		return -1;
	}

	return 0;
}

static int c50_vf_pcie_dma_pre_init(struct cn_pcie_set *pcie_set)
{
	if (pcie_set->id == MLUID_580V)
		pcie_set->cfg.p2p_mode = P2P_PUSH_MODE;
	else
		pcie_set->cfg.p2p_mode = P2P_PULL_MODE;

	pcie_set->dma_set.dma_phy_channel_mask = (u32)((1 << pcie_set->dma_set.max_phy_channel) - 1);
	cn_dev_pcie_debug(pcie_set, "get host engine mask:%#x",
					pcie_set->dma_set.dma_phy_channel_mask);

	pcie_set->dma_set.shared_desc_total_size = VF_SHARED_DMA_DESC_TOTAL_SIZE;
	pcie_set->dma_set.priv_desc_total_size = VF_PRIV_DMA_DESC_TOTAL_SIZE;
	pcie_set->dma_set.dma_buffer_size = DMA_BUFFER_SIZE;
	pcie_set->per_desc_size = DMA_DESC_PER_SIZE;
	pcie_set->per_desc_max_size = PER_DESC_MAX_SIZE;

	pcie_set->async_set.async_static_task_num = ASYNC_STATIC_TASK_NUM;
	pcie_set->async_set.async_max_desc_num = ASYNC_MAX_DESC_NUM;
	pcie_set->async_set.async_desc_size = VF_ASYNC_DMA_DESC_TOTAL_SIZE;
	pcie_set->async_set.async_desc_num = pcie_set->async_set.async_desc_size /
					pcie_set->per_desc_size;

	cn_pci_register_interrupt(pcie_get_irq("pcie_dma_int", pcie_set),
					c50_vf_pcie_dma_interrupt_handle,
					pcie_set, pcie_set);

	return 0;
}

static int pcie_dma_bypass_size(struct cn_pcie_set *pcie_set)
{
#if defined(__x86_64__)
	pcie_set->dma_set.dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 256 * 1024;
	pcie_set->dma_set.dma_bypass_pinned_size = dma_bypass_pinned_size ?
				dma_bypass_pinned_size : 256 * 1024;
	pcie_set->dma_set.dma_memsetD8_custom_size = dma_memsetD8_custom_size ?
		        dma_memsetD8_custom_size : 128 * 1024 * 1024;
	pcie_set->dma_set.dma_memsetD16_custom_size = dma_memsetD16_custom_size ?
		        dma_memsetD16_custom_size : 1024 * 1024;
	pcie_set->dma_set.dma_memsetD32_custom_size = dma_memsetD32_custom_size ?
				dma_memsetD32_custom_size : 1024 * 1024;
#else
	pcie_set->dma_set.dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 256;
	pcie_set->dma_set.dma_bypass_pinned_size = dma_bypass_pinned_size ?
				dma_bypass_pinned_size : 256;
	pcie_set->dma_set.dma_memsetD8_custom_size = dma_memsetD8_custom_size ?
		        dma_memsetD8_custom_size : 256;
	pcie_set->dma_set.dma_memsetD16_custom_size = dma_memsetD16_custom_size ?
		        dma_memsetD16_custom_size : 256;
	pcie_set->dma_set.dma_memsetD32_custom_size = dma_memsetD32_custom_size ?
				dma_memsetD32_custom_size : 256;
#endif
	pcie_set->dma_set.d2h_bypass_custom_size = d2h_bypass_custom_size ?
				d2h_bypass_custom_size : 64;
	return 0;
}

static void c50_vf_pcie_get_data_outbound_page_info(struct cn_pcie_set *pcie_set,
				int *lvl1_page, int *lvl1_pg_cnt, u64 *lvl1_base,
				int *lvl2_page, int *lvl2_pg_cnt, u64 *lvl2_base)
{
	struct data_outbound_set *dob_set;

	dob_set = &pcie_set->dob_set;

	*lvl1_page = ilog2(dob_set->dob_lvl1_pg);
	*lvl1_pg_cnt = dob_set->dob_axi_pg_cnt / 2;
	*lvl1_base = dob_set->dob_lvl1_axi_base;
	*lvl2_page = ilog2(dob_set->dob_lvl2_pg);
	*lvl2_pg_cnt = dob_set->dob_axi_pg_cnt / 2;
	*lvl2_base = dob_set->dob_lvl2_axi_base;
}

static int c50_vf_set_data_outbound_reserve_page(struct cn_pcie_set *pcie_set, struct pcie_dob_page_set *dob_page)
{
	u32 reg_value;
	int ret, i;
	enum wait_flag_pos pos = set_outbound_info;

	pcie_set->vf_priv_data->wait_flag &= ~(0x1u << pos);
	for (i = 0; dob_page[i].page_addr != 0; i++) {
		if (c50_vf_wait_pf_mbx(pcie_set)) {
			cn_dev_pcie_err(pcie_set, "set outbound info failed.");
			return -1;
		}

		reg_value = (u32)dob_page[i].page_addr;
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYL(0), reg_value);
		wmb();
		reg_value = CMD_SET_OUTBOUND_INFO;
		reg_value = (reg_value << 16) | ((4 * i) << 1);
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
		if (c50_vf_wait_pf_mbx(pcie_set)) {
			cn_dev_pcie_err(pcie_set, "set outbound info failed.");
			return -1;
		}

		reg_value = (u32)(dob_page[i].page_addr >> 32);
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYL(0), reg_value);
		wmb();
		reg_value = CMD_SET_OUTBOUND_INFO;
		reg_value = (reg_value << 16) | ((4 * i + 1) << 1);
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
		if (c50_vf_wait_pf_mbx(pcie_set)) {
			cn_dev_pcie_err(pcie_set, "set outbound info failed.");
			return -1;
		}

		reg_value = (u32)dob_page[i].val;
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYL(0), reg_value);
		wmb();
		reg_value = CMD_SET_OUTBOUND_INFO;
		reg_value = (reg_value << 16) | ((4 * i + 2) << 1);
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
		if (c50_vf_wait_pf_mbx(pcie_set)) {
			cn_dev_pcie_err(pcie_set, "set outbound info failed.");
			return -1;
		}

		reg_value = (u32)(dob_page[i].val >> 32);
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYL(0), reg_value);
		wmb();
		reg_value = CMD_SET_OUTBOUND_INFO;
		reg_value = (reg_value << 16) | ((4 * i + 3) << 1);
		if (dob_page[i + 1].page_addr == 0)
			reg_value |= 0x1u;
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
	}

	reg_value = cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	if (reg_value & (0x1u << 1)) {
		for (i = 0; i < 5000; i++) {
			reg_value = cn_pci_reg_read32(pcie_set, PF2VF_MBX_ENTRYH(1));
			reg_value = (reg_value & 0xFFFF0000u) >> 16;
			if (reg_value == CMD_SET_OUTBOUND_INFO)
				break;

			msleep(1);
		}

		if (i == 5000) {
			cn_dev_pcie_err(pcie_set, "Set outbound info time out.");
			return -1;
		}

		return 0;
	}

	ret = wait_event_interruptible_timeout(
					pcie_set->vf_priv_data->p2v_wait_queue,
					pcie_set->vf_priv_data->wait_flag
					& (0x1 << pos),
					msecs_to_jiffies(5000));
	if (ret < 0) {
		cn_dev_pcie_err(pcie_set, "breaked by signal");
		return -1;
	} else if (ret == 0) {
		cn_dev_pcie_err(pcie_set, "Set outbound info time out.");
		return -1;
	}

	return 0;
}

static void c50_vf_data_outbound_reserve_node_exit(struct cn_pcie_set *pcie_set,
					struct data_outbound_node_t *dob_node)
{
	struct pcie_dob_page_set dob_page[DOB_PAGE_LEVEL2_RESERVE_CNT + 1];
	int i;

	for (i = 0; i < DOB_PAGE_LEVEL2_RESERVE_CNT; i++) {
		dob_page[i].val = 0;
		dob_page[i].page_addr = dob_node->win_base + i * DOB_PRE_PAGE_SIZE;
	}

	dob_page[DOB_PAGE_LEVEL2_RESERVE_CNT].page_addr = 0;
	dob_page[DOB_PAGE_LEVEL2_RESERVE_CNT].val = 0;

	if (c50_vf_set_data_outbound_reserve_page(pcie_set, dob_page))
		cn_dev_pcie_err(pcie_set, "set data outbound reserve page failed");
}

static int c50_vf_data_outbound_reserve_node_init(struct cn_pcie_set *pcie_set,
					struct data_outbound_node_t *dob_node,
					struct outbound_mem *outbound_mem)
{
	struct pcie_dob_page_set dob_page[DOB_PAGE_LEVEL2_RESERVE_CNT + 1];
	int i;

	for (i = 0; i < DOB_PAGE_LEVEL2_RESERVE_CNT; i++) {
		dob_page[i].val = (outbound_mem[i].pci_addr & (~(MASK_BITS(11, 0)))) | 0x1UL;
		dob_page[i].page_addr = dob_node->win_base + i * DOB_PRE_PAGE_SIZE;
	}

	dob_page[DOB_PAGE_LEVEL2_RESERVE_CNT].page_addr = 0;
	dob_page[DOB_PAGE_LEVEL2_RESERVE_CNT].val = 0;

	if (c50_vf_set_data_outbound_reserve_page(pcie_set, dob_page)) {
		cn_dev_pcie_err(pcie_set, "set data outbound reserve page failed");
		return -1;
	}

	return 0;
}

static void c50_vf_data_outbound_node_exit(struct cn_pcie_set *pcie_set,
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
	if (dob_node->device_addr != pcie_set->dob_set.ob_axi_addr) {
		for (i = 0; i < dob_node->win_cnt; i++) {
			dob_free.desc_offset = dob_node->win_base + i * DOB_PRE_PAGE_SIZE;
			data_outbound_rpc_free(pcie_set->bus_set->core, &dob_free);
		}
	} else {
		c50_vf_data_outbound_reserve_node_exit(pcie_set, dob_node);
		pcie_set->dob_set.share_mem_pages = NULL;
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
		if (outbound_mem[i].virt_addr)
			pci_free_consistent(pcie_set->pdev, dob_node->per_win_size,
			outbound_mem[i].virt_addr, outbound_mem[i].pci_addr);
	}

	cn_kfree(dob_node->share_mem_pages);
	dob_node->share_mem_pages = NULL;
	cn_kfree(dob_node->share_priv);
	dob_node->share_priv = NULL;
}

static int c50_vf_data_outbound_node_init(struct cn_pcie_set *pcie_set,
					struct data_outbound_node_t *dob_node)
{
	int i, j;
	int page_index = 0;
	struct outbound_mem *outbound_mem;
	struct dob_rpc_alloc_t dob_alloc;
	u64 desc_buff = 0ULL;
	void *virt_addr;

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

	for (i = 0; i < dob_node->win_cnt; i++) {
		outbound_mem[i].virt_addr = dma_alloc_coherent(&pcie_set->pdev->dev,
				dob_node->per_win_size, &(outbound_mem[i].pci_addr),
				GFP_KERNEL | __GFP_NOWARN);
		if (!outbound_mem[i].virt_addr) {
			cn_dev_pcie_err(pcie_set, "dma_alloc_coherent error:%d", i);
			goto ERROR_RET;
		}
		if (outbound_mem[i].pci_addr & (dob_node->per_win_size - 1)) {
			cn_dev_pcie_err(pcie_set, "dma_alloc_coherent not align:%llx",
						outbound_mem[i].pci_addr);
			goto ERROR_RET;
		}
	}

	page_index = 0;
	for (i = 0; i < dob_node->win_cnt; i++) {
		for (j = 0; j < dob_node->per_win_size / PAGE_SIZE; j++) {
			virt_addr = outbound_mem[i].virt_addr + j * PAGE_SIZE;
			if (is_vmalloc_addr(virt_addr))
				dob_node->share_mem_pages[page_index] =
						vmalloc_to_page(virt_addr);
			else
				dob_node->share_mem_pages[page_index] =
						virt_to_page(virt_addr);

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
	if (dob_node->device_addr == pcie_set->dob_set.ob_axi_addr) {
		if (c50_vf_data_outbound_reserve_node_init(pcie_set, dob_node, outbound_mem))
			goto ERROR_RET;

		dob_node->type = CN_SHARE_MEM_HOST;
		pcie_set->dob_set.share_mem_pages = dob_node->share_mem_pages;
		return 0;
	}

	for (i = 0; i < dob_node->win_cnt; i++) {
		desc_buff = (outbound_mem[i].pci_addr & (~(MASK_BITS(11, 0)))) | 0x1UL;
		dob_alloc.desc_buff = desc_buff;
		dob_alloc.desc_offset = dob_node->win_base + i * DOB_PRE_PAGE_SIZE;
		if (data_outbound_rpc_alloc(pcie_set->bus_set->core, &dob_alloc)) {
			cn_dev_pcie_err(pcie_set, "desc_base:%#llx, desc_buff=%#llx",
				dob_alloc.desc_offset, dob_alloc.desc_buff);
			goto ERROR_RET;
		}
	}

	return 0;
ERROR_RET:
	c50_vf_data_outbound_node_exit(pcie_set, dob_node);
	return -1;
}

static void *c50_vf_pcie_data_outbound_page_alloc(struct cn_pcie_set *pcie_set,
						u64 device_addr, size_t size)
{
	struct data_outbound_set *dob_set;
	struct data_outbound_node_t *new;

	if (!device_addr)
		return NULL;

	dob_set = &pcie_set->dob_set;

	if (device_addr != dob_set->ob_axi_addr) {
		if ((device_addr < dob_set->dob_lvl1_axi_base)
			|| (device_addr < dob_set->dob_lvl2_axi_base
				&& device_addr >= dob_set->dob_lvl1_axi_base
				+ dob_set->dob_lvl1_pg * dob_set->dob_cnt / 2)
			|| (device_addr >= dob_set->dob_lvl2_axi_base
				+ dob_set->dob_lvl2_pg * dob_set->dob_cnt / 2)
			|| (device_addr < dob_set->dob_lvl2_axi_base
				&& (device_addr + size) > (dob_set->dob_lvl1_axi_base
				+ dob_set->dob_lvl1_pg
				* dob_set->dob_cnt / 2))
			|| (device_addr >= dob_set->dob_lvl2_axi_base
				&& (device_addr + size) > (dob_set->dob_lvl2_axi_base
				+ dob_set->dob_lvl2_pg
				* dob_set->dob_cnt / 2))) {
			cn_dev_pcie_err(pcie_set, "device_addr=%#llx error", device_addr);
			return NULL;
		}
	}

	new = cn_kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return NULL;

	if (device_addr >= dob_set->dob_lvl2_axi_base) {
		new->win_base = dob_set->dob_axi_pg_base
				+ DOB_PAGE_CNT / 2 * dob_set->dob_axi_per_pg_size
				+ dob_set->dob_axi_per_pg_size
				* ((device_addr - dob_set->dob_lvl2_axi_base)
				/ dob_set->dob_lvl2_pg);
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
	if (c50_vf_data_outbound_node_init(pcie_set, new)) {
		cn_kfree(new);
		return NULL;
	}

	mutex_lock(&dob_set->dob_lock);
	list_add_tail(&new->list, &dob_set->dob_head);
	mutex_unlock(&dob_set->dob_lock);

	return new->virt_addr;
}

static void c50_vf_pcie_data_outbound_page_free(struct cn_pcie_set *pcie_set,
							u64 device_addr)
{
	struct data_outbound_set *dob_set;
	struct data_outbound_node_t *dob_node, *tmp;

	dob_set = &pcie_set->dob_set;

	mutex_lock(&dob_set->dob_lock);
	list_for_each_entry_safe(dob_node, tmp, &dob_set->dob_head, list) {
		if (device_addr == dob_node->device_addr) {
			c50_vf_data_outbound_node_exit(pcie_set, dob_node);
			list_del(&dob_node->list);
			cn_kfree(dob_node);
			break;
		}
	}
	mutex_unlock(&dob_set->dob_lock);
}

static int c50_vf_get_data_outbound_info(struct cn_pcie_set *pcie_set)
{
	u32 reg_value;
	int ret;
	enum wait_flag_pos pos = get_outbound_info;

	if (c50_vf_wait_pf_mbx(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "Get outbound info failed.");
		return -1;
	}

	reg_value = CMD_GET_OUTBOUND_INFO;
	reg_value = (reg_value << 16) | 0x1u;
	cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
	ret = wait_event_interruptible_timeout(
					pcie_set->vf_priv_data->p2v_wait_queue,
					pcie_set->vf_priv_data->wait_flag
					& (0x1 << pos),
					msecs_to_jiffies(5000));
	if (ret < 0) {
		cn_dev_pcie_err(pcie_set, "breaked by signal");
		return -1;
	} else if (ret == 0) {
		cn_dev_pcie_err(pcie_set, "Get outbound info time out.");
		return -1;
	}

	return 0;
}

/* reserve 8MB data_outbound for commu/ipcm/js */
static int c50_vf_pcie_data_outbound_reserve_init(struct cn_pcie_set *pcie_set)
{
	struct data_outbound_set *dob_set;
	void __iomem *virt_addr = NULL;
	int index = pcie_set->share_mem_cnt;

	dob_set = &pcie_set->dob_set;
	dob_set->dob_reserve_size = dob_set->dob_lvl2_pg_reserve_cnt * dob_set->dob_lvl2_pg;
	virt_addr = c50_vf_pcie_data_outbound_page_alloc(pcie_set,
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

static int c50_vf_pcie_data_outbound_init(struct cn_pcie_set *pcie_set)
{
	struct data_outbound_set *dob_set = NULL;
	int index = pcie_set->share_mem_cnt;
	int ret;

	ret = c50_vf_get_data_outbound_info(pcie_set);
	if (ret)
		return -1;

	dob_set = &pcie_set->dob_set;
	cn_dev_pcie_info(pcie_set, "dob_cnt:0x%x, dob_lvl1_pg:0x%llx, dob_lvl2_pg:0x%llx, dob_lvl1_axi_base:0x%llx, dob_lvl2_axi_base:0x%llx",
				dob_set->dob_cnt, dob_set->dob_lvl1_pg,
				dob_set->dob_lvl2_pg, dob_set->dob_lvl1_axi_base,
				dob_set->dob_lvl2_axi_base);

	dob_set->dob_axi_pg_cnt = dob_set->dob_cnt;
	dob_set->dob_lvl2_pg_reserve_cnt = DOB_PAGE_LEVEL2_RESERVE_CNT;
	dob_set->dob_axi_per_pg_size = DOB_PRE_PAGE_SIZE;
	dob_set->dob_total_size = (dob_set->dob_lvl1_pg * dob_set->dob_cnt / 2)
					+ (dob_set->dob_lvl2_pg * dob_set->dob_cnt / 2);
	dob_set->dob_axi_pg_base = DOB_PAGE_BASE
					+ (dob_set->dob_lvl1_axi_base - DOB_AXI_BASE)
					/ dob_set->dob_lvl1_pg * DOB_PRE_PAGE_SIZE;
	INIT_LIST_HEAD(&dob_set->dob_head);
	INIT_LIST_HEAD(&dob_set->dob_iova_head);
	mutex_init(&dob_set->dob_lock);

	if (pcie_set->cfg.outbound_able) {
		/* reserve 8MB for config_outbound*/
		if (c50_vf_pcie_data_outbound_reserve_init(pcie_set)) {
			pcie_set->cfg.outbound_able = 0;
			goto ob_disable;
		}
	} else {
ob_disable:
		index = pcie_set->share_mem_cnt;
		pcie_set->share_mem[index].virt_addr =
				(void __iomem *)dob_set->dob_lvl1_axi_base;
		pcie_set->share_mem[index].win_length = dob_set->dob_total_size;
		pcie_set->share_mem[index].type = CN_SHARE_MEM_HOST_DATA;
		pcie_set->share_mem[index].device_addr = dob_set->dob_lvl1_axi_base;
		cn_dev_pcie_info(pcie_set, "[%d] dob size=%#lx kva=%#lx dpa=%#llx",
					index, pcie_set->share_mem[index].win_length,
					(unsigned long)pcie_set->share_mem[index].virt_addr,
					pcie_set->share_mem[index].device_addr);
		pcie_set->share_mem_cnt++;
	}

	return 0;
}

static void c50_vf_pcie_data_outbound_exit(struct cn_pcie_set *pcie_set)
{
	struct data_outbound_set *dob_set = NULL;
	struct data_outbound_node_t *dob_node, *tmp;

	dob_set = &pcie_set->dob_set;
	c50_vf_pcie_release_data_outbound_iova(pcie_set);

	if (list_empty(&dob_set->dob_head))
		return;

	mutex_lock(&dob_set->dob_lock);
	list_for_each_entry_safe(dob_node, tmp, &dob_set->dob_head, list) {
		c50_vf_data_outbound_node_exit(pcie_set, dob_node);
		list_del(&dob_node->list);
		cn_kfree(dob_node);
	}
	mutex_unlock(&dob_set->dob_lock);
}

static irqreturn_t c50_p2vmbx_interrupt_handle(int index, void *data)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct cn_bus_set *bus_set = pcie_set->bus_set;
	struct data_outbound_set *dob_set = NULL;
	int mbx_level, end_flag, msg_index;
	u32 cmd, entryh_val;
	u64 msg;
	enum wait_flag_pos pos;

	mbx_level = cn_pci_reg_read32(pcie_set, PF2VF_MBX_STATUS(1));
	mbx_level = (mbx_level >> 8) & 0x7;

	if (!mbx_level) {
		cn_dev_pcie_info(pcie_set, "There is no message in P2V mailbox!");
		return IRQ_NONE;
	}

	while (mbx_level) {
		msg = cn_pci_reg_read32(pcie_set, PF2VF_MBX_ENTRYL(1));
		barrier();
		entryh_val = cn_pci_reg_read32(pcie_set, PF2VF_MBX_ENTRYH(1));
		mbx_level--;
		cmd = (entryh_val & 0xFFFF0000u) >> 16;
		msg_index = (entryh_val & 0xFFFFu) >> 1;
		end_flag = entryh_val & 0x1u;
		switch (cmd) {
		case CMD_ALLOC_COMMU_CTRLQ:
			if (!bus_set)
				return IRQ_HANDLED;
			return commu_ctrlq_alloc_done(bus_set->core);
		case CMD_SET_OUTBOUND_INFO:
			pos = set_outbound_info;
			break;
		case CMD_SRIOV_INIT:
			pos = sriov_init;
			break;
		case CMD_SRIOV_EXIT:
			pos = sriov_exit;
			break;
		case CMD_SRIOV_LATE_INIT:
			pos = sriov_late_init;
			break;
		case CMD_GET_INBOUND_INFO:
			if (msg_index == 0)
				pcie_set->vf_priv_data->share_mem_base = msg;
			else if (msg_index == 1)
				pcie_set->vf_priv_data->share_mem_size = msg;
			else if (msg_index == 2)
				pcie_set->vf_priv_data->inbdmem_dev_va_base =
								msg;
			else if (msg_index == 3)
				pcie_set->vf_priv_data->inbdmem_dev_va_base |=
								(msg << 32);
			else
				cn_dev_pcie_info(pcie_set,
						"CMD_GET_INBOUND_INFO:msg_index%d",
						msg_index);
			pos = get_inbound_info;
			break;
		case CMD_GET_OUTBOUND_INFO:
			pos = get_outbound_info;

			dob_set = &pcie_set->dob_set;
			if (msg_index == 0)
				dob_set->dob_cnt = msg;
			else if (msg_index == 1)
				dob_set->dob_lvl1_pg = msg;
			else if (msg_index == 2)
				dob_set->dob_lvl2_pg = msg;
			else if (msg_index == 3)
				dob_set->dob_lvl1_axi_base = msg;
			else if (msg_index == 4) {
				dob_set->dob_lvl1_axi_base <<= 32;
				dob_set->dob_lvl1_axi_base |= msg;
			} else if (msg_index == 5)
				dob_set->dob_lvl2_axi_base = msg;
			else if (msg_index == 6) {
				dob_set->dob_lvl2_axi_base <<= 32;
				dob_set->dob_lvl2_axi_base |= msg;
			} else if (msg_index == 7)
				dob_set->ob_axi_addr = msg;
			else if (msg_index == 8) {
				dob_set->ob_axi_addr <<=32;
				dob_set->ob_axi_addr |= msg;
			} else
				cn_dev_pcie_info(pcie_set, "CMD_GET_OUTBOUND_INFO:msg_index%d",
						msg_index);
			break;
		case CMD_GET_DMA_INFO:
			pcie_set->dma_set.dma_phy_channel_mask = msg;
			pos = get_dma_info;
			break;
		case CMD_GET_SRAM_INFO:
			if (msg_index == 0)
				pcie_set->vf_priv_data->sram_pa = msg;
			else if (msg_index == 1)
				pcie_set->vf_priv_data->sram_pa |= (msg << 32);
			else if (msg_index == 2)
				pcie_set->vf_priv_data->sram_size = msg;
			else if (msg_index == 3)
				pcie_set->vf_priv_data->sram_size |= (msg << 32);
			else
				cn_dev_pcie_info(pcie_set,
						"CMD_GET_SRAM_INFO:msg_index%d",
						msg_index);
			pos = get_sram_info;
			break;
		default:
			cn_dev_pcie_info(pcie_set, "No command matched!");
			return IRQ_HANDLED;
		}
	}

	if (end_flag) {
		pcie_set->vf_priv_data->wait_flag |= (0x1u << pos);
		wake_up_interruptible(&pcie_set->vf_priv_data->p2v_wait_queue);
	}

	return IRQ_HANDLED;
}

static irqreturn_t __maybe_unused c50_a2vmbx_interrupt_handle(int index, void *data)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct cn_bus_set *bus_set = pcie_set->bus_set;
	int mbx_level;
	u32 msg;

	mbx_level = cn_pci_reg_read32(pcie_set, ARM2VF_MBX_STATUS(1));
	mbx_level = (mbx_level >> 8) & 0x7;

	if (!mbx_level) {
		cn_dev_pcie_info(pcie_set, "No message in arm2vf mailbox.");
		return -1;
	} else {
		//for (level_i = 0; level_i < mbx_level; level_i++)
		//	cn_pci_reg_read32(pcie_set, ARM2VF_MBX_ENTRYH(1));
		msg = cn_pci_reg_read32(pcie_set, ARM2VF_MBX_ENTRYL(1));
		if (msg != 0x1)
			return IRQ_NONE;
		cn_pci_reg_read32(pcie_set, ARM2VF_MBX_ENTRYH(1));
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

static irqreturn_t c50_vf_msi_interrupt(int irq, void *data)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	int vector_index;
	int irq_index, pos;
	int handler_num;
	u32 msi_mask = 0;
	unsigned long irq_status, irq_mask;
	u64 start, end;

	vector_index = irq - pcie_set->irq_set.irq;

	if (vector_index >= VF_MSI_COUNT) {
		cn_dev_pcie_err(pcie_set, "Recv error interrupt:%d", irq);
		return IRQ_NONE;
	}

	//mask msi interrupt
	pci_read_config_dword(pcie_set->pdev, pcie_set->irq_set.msi_pos + 0x10,
				&msi_mask);
	msi_mask |= (0x1 << vector_index);
	pci_write_config_dword(pcie_set->pdev, pcie_set->irq_set.msi_pos + 0x10,
				msi_mask);
	irq_status = cn_pci_reg_read32(pcie_set, VF_INT_STATUS);
	irq_mask = cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	irq_status &= (~irq_mask);

	for_each_set_bit(pos, (unsigned long *)&irq_status, 5) {
		irq_index = pos;

		handler_num = 0;
		do {
			if (pcie_set->irq_set.irq_desc[irq_index].handler[handler_num]
				== NULL) {
				cn_dev_pcie_err(pcie_set, "no interrupt handle!:%#lx %d",
						irq_status, irq_index);
				break;
			}
			start = get_jiffies_64();
			if (pcie_set->irq_set.irq_desc[irq_index].handler[handler_num]
				(irq_index,
				pcie_set->irq_set.irq_desc[irq_index].data[handler_num])
				== IRQ_HANDLED) {
				end = get_jiffies_64();

				if (time_after64(end, start + HZ / 2))
					cn_dev_pcie_warn(pcie_set,
						"do interrupt%d spend too long time(%dms)!!!",
						irq_index,
						jiffies_to_msecs(end - start));
				break;
			}
			handler_num++;
		} while (handler_num < IRQ_SHARED_NUM);

		if (handler_num == IRQ_SHARED_NUM)
			cn_dev_pcie_err(pcie_set, "no interrupt handle!:%#lx %d",
						irq_status, irq_index);
	}

	//unmask msi interrupt
	pci_read_config_dword(pcie_set->pdev, pcie_set->irq_set.msi_pos + 0x10,
				&msi_mask);
	msi_mask &= (~(0x1 << vector_index));
	pci_write_config_dword(pcie_set->pdev, pcie_set->irq_set.msi_pos + 0x10,
				msi_mask);

	return IRQ_HANDLED;

}

static irqreturn_t c50_vf_msix_interrupt(int irq, void *data)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct msix_entry *entry;
	unsigned long irq_status, irq_mask;
	int vector_index, pos, irq_index, handler_num;
	u32 value;
	u64 start, end;

	entry = (struct msix_entry *)pcie_set->irq_set.msix_entry_buf;

	for (vector_index = 0; vector_index < VF_MSIX_COUNT; vector_index++) {
		if (entry[vector_index].vector == irq)
			break;
	}

	if (vector_index >= VF_MSIX_COUNT) {
		cn_dev_pcie_err(pcie_set, "Recv error interrupt:%d", irq);
		return IRQ_HANDLED;
	}

	irq_status = cn_pci_reg_read32(pcie_set, VF_INT_STATUS);
	irq_mask = cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	irq_status &= (~irq_mask);

	for_each_set_bit(pos, (unsigned long *)&irq_status, 5) {
		irq_index = pos;

		handler_num = 0;
		do {
			if (pcie_set->irq_set.irq_desc[irq_index].handler[handler_num]
				== NULL) {
				cn_dev_pcie_err(pcie_set, "no interrupt handle!:%#lx %d",
						irq_status, irq_index);
				break;
			}
			start = get_jiffies_64();
			if (pcie_set->irq_set.irq_desc[irq_index].handler[handler_num]
				(irq_index,
				pcie_set->irq_set.irq_desc[irq_index].data[handler_num])
				== IRQ_HANDLED) {
				end = get_jiffies_64();

				if (time_after64(end, start + HZ / 2))
					cn_dev_pcie_warn(pcie_set,
						"do interrupt%d spend too long time(%dms)!!!",
						irq_index,
						jiffies_to_msecs(end - start));
				break;
			}
			handler_num++;
		} while (handler_num < IRQ_SHARED_NUM);

		if (handler_num == IRQ_SHARED_NUM)
			cn_dev_pcie_err(pcie_set, "no interrupt handle!:%#lx %d",
						irq_status, irq_index);
	}

	value = cn_pci_reg_read32(pcie_set, VF_MSIX_PEND_CLR);
	value |= (1UL << (vector_index % 32));
	cn_pci_reg_write32(pcie_set, VF_MSIX_PEND_CLR, value);
	value &= (~(1Ul << (vector_index % 32)));
	cn_pci_reg_write32(pcie_set, VF_MSIX_PEND_CLR, value);
	cn_pci_reg_read32(pcie_set, VF_MSIX_PEND_CLR);

	return IRQ_HANDLED;
}

static void c50_vf_pcie_unregister_bar(struct cn_pcie_set *pcie_set)
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

static void c50_vf_bar_deinit(struct cn_pcie_set *pcie_set)
{
	int seg;

	for (seg = 0; seg < MAX_BAR_SEGMENTS; seg++) {
		if (pcie_set->bar0_set.seg[seg].virt) {
			cn_iounmap(pcie_set->bar0_set.seg[seg].virt);
			pcie_set->bar0_set.seg[seg].virt = NULL;
		}
	}

	c50_vf_pcie_unregister_bar(pcie_set);
	pcie_set->bar0_set.reg_virt_base = NULL;
	pcie_set->bar0_set.reg_phy_addr = 0;
	pcie_set->bar0_set.reg_win_length = 0;
}

static void c50_vf_pcie_priv_set_free(struct cn_pcie_set *pcie_set)
{
	c50_vf_pcie_data_outbound_exit(pcie_set);
}

static int c50_vf_pcie_sync_write_alloc(struct cn_pcie_set *pcie_set, u64 flag_dev_pa)
{
	int ret, ret_len;
	struct sync_write *sw;
	struct pcie_rpc_sync_write_set rpc_sw_set;
	void *domain_set = pcie_set->bus_set->core->domain_set;
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
			rpc_sw_set.sw_index = sw_index;
			rpc_sw_set.val = sw->sw_trigger_pa;
			ret = dm_compat_rpc(domain_set, "pcie_set_sync_write_addr", &rpc_sw_set,
					sizeof(struct pcie_rpc_sync_write_set), &rpc_sw_set,
					&ret_len, sizeof(struct pcie_rpc_sync_write_set));
			if (unlikely(ret < 0)) {
				cn_dev_pcie_info(pcie_set, "pcie_set_sync_write_addr failed");
				return -1;
			}

			rpc_sw_set.sw_index = sw_index;
			rpc_sw_set.val = sw->sw_flag_pa;
			ret = dm_compat_rpc(domain_set, "pcie_set_flag_queue_addr", &rpc_sw_set,
					sizeof(struct pcie_rpc_sync_write_set), &rpc_sw_set,
					&ret_len, sizeof(struct pcie_rpc_sync_write_set));
			if (unlikely(ret < 0)) {
				cn_dev_pcie_info(pcie_set, "pcie_set_flag_queue_addr failed");
				return -1;
			}

			cn_dev_pcie_debug(pcie_set,
				"id=%d flag_pa=%#llx trigger_pa=%#llx trigger_kva=%#lx",
				sw_index, sw->sw_flag_pa, sw->sw_trigger_pa, sw->sw_trigger_kva);
			return 0;
		}
	}

	return -1;
}

static void c50_vf_pcie_sync_write_free(struct cn_pcie_set *pcie_set, u64 flag_dev_pa)
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

static void c50_vf_pcie_sync_write_trigger(struct cn_pcie_set *pcie_set, u64 dev_pa, u32 val)
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

static void c50_vf_pcie_sync_write_info(struct cn_pcie_set *pcie_set,
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

static void c50_vf_pcie_sync_write_exit(struct cn_pcie_set *pcie_set)
{
	u64 dev_va;
	unsigned long host_kva;

	dev_va = pcie_set->sw_set.sw_dev_va;
	host_kva = pcie_set->sw_set.sw_host_kva;
	if (host_kva && dev_va) {
		cn_device_share_mem_free(0, host_kva, dev_va, pcie_set->bus_set->core);
	}
}

static int c50_vf_pcie_sync_write_init(struct cn_pcie_set *pcie_set)
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

	for (sw_index = 0; sw_index < pcie_set->sw_set.sw_num; sw_index++) {
		sw = &pcie_set->sw_set.sw[sw_index];
		sw->sw_flag_size = (pcie_set->sw_set.sw_total_size / pcie_set->sw_set.sw_num);
		sw->sw_trigger_pa = (pcie_set->sw_set.sw_dev_va +
					sw_index * sw->sw_flag_size) -
					C50_AXI_SHM_BASE + C50_AXI_SHM_PA_BASE;
		sw->sw_trigger_kva = pcie_set->sw_set.sw_host_kva +
					sw_index * sw->sw_flag_size;
		cn_dev_pcie_debug(pcie_set, "[%d]sw_trigger_pa=%#llx, sw_trigger_kva=%#lx",
					sw_index, sw->sw_trigger_pa, sw->sw_trigger_kva);
	}

	return 0;
}

static u64 pcie_set_bar_window(u64 axi_address, struct bar_resource *resource,
		struct cn_pcie_set *pcie_set)
{
	u64 addr;

	addr = resource->window_addr;
	if (axi_address >= addr && axi_address < (addr + resource->size))
		return addr;

	axi_address &= (~((u64)(resource->size - 1)));
	/* bar base 1MB align*/
	cn_pci_reg_write32(pcie_set, VF_BAR_ADDR_BASE(resource->index),
			(u32)(axi_address >> ilog2(BAR_BASE_SIZE)));
	cn_pci_reg_read32(pcie_set, VF_BAR_ADDR_BASE(resource->index));

	resource->window_addr = axi_address;

	return axi_address;
}

static int c50_vf_pcie_gic_mask(int irq, struct cn_pcie_set *pcie_set)
{
	u32 reg_val;

	if (irq > 4 || irq < 0) {
		cn_dev_pcie_err(pcie_set, "invalid irq num:%d", irq);
		return -1;
	}

	reg_val = cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	reg_val |= 1UL << irq;
	cn_pci_reg_write32(pcie_set, VF_INT_MASK, reg_val);
	cn_pci_reg_read32(pcie_set, VF_INT_MASK);

	return 0;
}

static int c50_vf_pcie_gic_unmask(int irq, struct cn_pcie_set *pcie_set)
{
	u32 reg_val;

	if (irq > 4 || irq < 0) {
		cn_dev_pcie_err(pcie_set, "invalid irq num:%d", irq);
		return -1;
	}

	reg_val = cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	reg_val &= ~(1ULL << irq);
	cn_pci_reg_write32(pcie_set, VF_INT_MASK, reg_val);
	cn_pci_reg_read32(pcie_set, VF_INT_MASK);

	return 0;
}

static int c50_vf_pcie_gic_mask_all(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, VF_INT_MASK, 0xFFFFFFFF);
	cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	return 0;
}

static void c50_vf_pci_mb(struct cn_pcie_set *pcie_set)
{
	/* barrier */
	smp_mb();
	cn_pci_reg_read32(pcie_set, 0x5ffc);
}

static void c50_vf_pcie_put_data_outbound_iova(struct cn_pcie_set *pcie_set, struct sg_table **iova_sgt)
{
	struct data_outbound_set *dob_set;
	struct data_outbound_map_t *map_node, *tmp;
	struct sg_table *sgt = NULL;

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

static void c50_vf_pcie_release_data_outbound_iova(struct cn_pcie_set *pcie_set)
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

static int c50_vf_pcie_data_outbound_reserve_able(struct cn_pcie_set *pcie_set, u64 device_addr)
{
	if ((device_addr >= pcie_set->dob_set.ob_axi_addr) &&
			(device_addr <=
			(pcie_set->dob_set.ob_axi_addr + pcie_set->dob_set.dob_reserve_size))) {
		return 1;
	}

	return 0;
}

static int c50_vf_pcie_get_data_outbound_iova(struct cn_pcie_set *src,
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

	if (!c50_vf_pcie_data_outbound_reserve_able(src, device_addr)) {
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
							device_addr, size, iova_sgt);
	return 0;
}

static struct cn_pci_ops c50_vf_private_ops = {
	.fill_desc_list = c50_vf_pcie_fill_desc_list,
	.async_dma_fill_desc_list = c50_vf_async_dma_fill_desc_list,
	.show_desc_list = pcie_show_desc_list,
	.dump_reg = c50_vf_pcie_dump_reg,
	.get_irq_by_desc = pcie_get_irq,
	.dma_bypass_size = pcie_dma_bypass_size,
	.set_bar_window = pcie_set_bar_window,
	.isr_hw_enable = pci_isr_hw_enable,
	.isr_hw_disable = pci_isr_hw_disable,
	.msi_isr = c50_vf_msi_interrupt,
	.msix_isr = c50_vf_msix_interrupt,
	.dma_go_command =  c50_vf_pcie_dma_go,
	.get_dob_win_info = c50_vf_pcie_get_data_outbound_page_info,
	.dob_win_alloc = c50_vf_pcie_data_outbound_page_alloc,
	.dob_win_free = c50_vf_pcie_data_outbound_page_free,
	.pci_mb = c50_vf_pci_mb,
	.sync_write_init = c50_vf_pcie_sync_write_init,
	.sync_write_exit = c50_vf_pcie_sync_write_exit,
	.sync_write_alloc = c50_vf_pcie_sync_write_alloc,
	.sync_write_trigger = c50_vf_pcie_sync_write_trigger,
	.sync_write_free = c50_vf_pcie_sync_write_free,
	.sync_write_info = c50_vf_pcie_sync_write_info,
	.gic_mask_all = c50_vf_pcie_gic_mask_all,
	.gic_mask = c50_vf_pcie_gic_mask,
	.gic_unmask = c50_vf_pcie_gic_unmask,
	.vf_notify_late_init = c50_vf_notify_late_init,
	.get_dob_iova = c50_vf_pcie_get_data_outbound_iova,
	.put_dob_iova = c50_vf_pcie_put_data_outbound_iova,
};

static int c50_vf_pcie_enable_pf_bar(struct cn_pcie_set *pcie_set)
{
	int index;
	struct bar_resource bar, *new;
	struct pci_dev *pdev = pcie_set->pdev;
	u64 base, sz;

	INIT_LIST_HEAD(&pcie_set->bar_resource_head);

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
		new = mlu590_pcie_bar_resource_struct_init(&bar, pcie_set);
		if (new)
			list_add_tail(&new->list, &pcie_set->bar_resource_head);
	}

	return 0;
}

static int c50_vf_pcie_bar_pre_init(struct cn_pcie_set *pcie_set)
{
	//int bar;
	struct pcibar_seg_s *p_bar_seg;

	/* the register area */
	p_bar_seg = &pcie_set->bar0_set.seg[0];
	p_bar_seg->size = pcie_set->bar0_set.size / 2;
	p_bar_seg->base = pcie_set->bar0_set.base;
	p_bar_seg->virt = cn_ioremap(p_bar_seg->base, p_bar_seg->size);
	cn_dev_pcie_info(pcie_set, "Bar0 register virt:%lx phy:%llx size:%llx",
		(ulong)p_bar_seg->virt, p_bar_seg->base, p_bar_seg->size);
	if (!p_bar_seg->virt)
		goto ERROR_RET;

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

	cn_dev_pcie_info(pcie_set, "Bar0 memory virt:%lx size:%llx",
		(ulong)p_bar_seg->virt, p_bar_seg->size);
	return 0;

ERROR_RET:
	cn_dev_pcie_err(pcie_set, "init error");

	c50_vf_bar_deinit(pcie_set);
	return -1;
}

static int c50_vf_pcie_bar_init(struct cn_pcie_set *pcie_set)
{
	u32 vf_share_mem_base, vf_share_mem_size;

	if (c50_vf_pcie_enable_pf_bar(pcie_set))
		goto ERROR_RET;

	if (c50_vf_notify_init(pcie_set))
		goto ERROR_RET;

	pcie_set->share_mem_cnt = 1;
	if (c50_vf_get_inbound_info(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "get inbound info error.");
		goto ERROR_RET;
	}

	if (pcie_set->cfg.pcie_sram_able)
		if (c50_vf_get_sram_info(pcie_set)) {
			cn_dev_pcie_err(pcie_set, "get sram info error.");
			goto ERROR_RET;
		}

	vf_share_mem_base = pcie_set->vf_priv_data->share_mem_base;
	vf_share_mem_size = pcie_set->vf_priv_data->share_mem_size;
	cn_dev_pcie_info(pcie_set, "vf_share_mem_base:%x size:%x dev_vaddr_base:%llx",
		vf_share_mem_base, vf_share_mem_size,
		pcie_set->vf_priv_data->inbdmem_dev_va_base);

	pcie_set->share_mem[0].virt_addr =
		pcie_set->bar0_set.seg[1].virt + vf_share_mem_base;
	pcie_set->share_mem[0].phy_addr =
		pcie_set->bar0_set.seg[1].base + vf_share_mem_base;
	pcie_set->share_mem[0].win_length = vf_share_mem_size;
	pcie_set->share_mem[0].device_addr =
				pcie_set->vf_priv_data->inbdmem_dev_va_base;
	pcie_set->share_mem[0].type = CN_SHARE_MEM_DEV;

	return 0;

ERROR_RET:
	cn_dev_pcie_err(pcie_set, "init error");

	c50_vf_bar_deinit(pcie_set);
	return -1;
}

static void set_bar_default_window(struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar;
	int order;

	list_for_each_entry(bar, &pcie_set->bar_resource_head, list) {
		bar->window_addr = 0;
		order = ilog2(bar->size / VF_BAR_BASE_SIZE);
		cn_pci_reg_write64(pcie_set, VF_BAR_ADDR_MASK(bar->index),
				(0xFFFFFFFULL << order) & 0xFFFFFFFULL);
		cn_pci_reg_read32(pcie_set, VF_BAR_ADDR_MASK(bar->index));
		cn_dev_pcie_debug(pcie_set, "bar->index:%d bar->size:%#llx addr_mask:%#llx",
			bar->index, bar->size, (0xFFFFFFFULL << order) & 0xFFFFFFFULL);
	}
}

static int c50_vf_pre_init_hw(struct cn_pcie_set *pcie_set)
{
	u32 reg_value;

	set_bar_default_window(pcie_set);
	reg_value = cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	reg_value &= ~(0x1u << 0);
	cn_pci_reg_write32(pcie_set, VF_INT_MASK, reg_value);
	cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	return 0;
}

static int c50_vf_pcie_mbx_interrupt_init(struct cn_pcie_set *pcie_set)
{
	char src[30];
	int ret;
	u32 reg_value;
	static const int interrupt_count[] = {VF_MSI_COUNT, VF_MSIX_COUNT};

	if (pcie_set->irq_set.irq_type >= 2) {
		cn_dev_pcie_err(pcie_set, "vf dont't suppot intx, isr init failed!");
		return -1;
	}

	pcie_set->irq_set.irq_num = interrupt_count[pcie_set->irq_set.irq_type];
	pcie_set->irq_str_index_ptr = irq_str_index;
	reg_value = 0xFFFFFFFF;
	cn_pci_reg_write32(pcie_set, VF_INT_MASK, reg_value);
	cn_pci_reg_read32(pcie_set, VF_INT_MASK);

	if (isr_enable_func[pcie_set->irq_set.irq_type](pcie_set))
		return -1;

	sprintf(src, "p2v_mbx");
	ret = cn_pci_register_interrupt(
				pcie_get_irq(src, pcie_set),
				c50_p2vmbx_interrupt_handle,
				pcie_set, pcie_set);
	if (ret)
		return -1;

	#if defined(IPCM_COMMU_SHARED_IRQ) || defined(IPCM_POLLING_MODE)
	sprintf(src, "a2v_mbx");
	ret = cn_pci_register_interrupt(
				pcie_get_irq(src, pcie_set),
				c50_a2vmbx_interrupt_handle,
				pcie_set, pcie_set);
	if (ret)
		return -1;
	#endif

	reg_value = cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	reg_value &= ~(1u << 1);
	#if defined(IPCM_COMMU_SHARED_IRQ) || defined(IPCM_POLLING_MODE)
	reg_value &= ~(1u << 2);
	#endif
	reg_value &= ~(1u << 3);
	cn_pci_reg_write32(pcie_set, VF_INT_MASK, reg_value);
	cn_pci_reg_read32(pcie_set, VF_INT_MASK);
	return 0;
}

static int c50_vf_pcie_setup(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;
	struct pci_dev *pdev = pcie_set->pdev;
	int ret = 0;
	u64 sz;

	pcie_set->ops = &c50_vf_private_ops;

	pcie_set->cfg.arm_trigger_enable = arm_trigger_enable;
	if (pcie_set->cfg.arm_trigger_enable) {
		pcie_set->dma_set.max_phy_channel = HOST_QUEUE_CNT;
		pcie_set->dma_set.dma_phy_channel_mask = (u32)((1 << HOST_QUEUE_CNT) - 1);
	} else {
		pcie_set->dma_set.max_phy_channel = DMA_MAX_QUEUE_NUM;
		pcie_set->dma_set.dma_phy_channel_mask = DMA_MAX_QUEUE_MASK;
	}
	pcie_set->dma_set.dma_fetch_buff = DMA_QUEUE_BUFF;
	pcie_set->is_virtfn = 1;

	if (g_platform_type == MLU_PLAT_VDK) {
		pcie_set->cfg.pcie_sram_able = 0;
		pcie_set->cfg.outbound_able = 0;
	} else {
		pcie_set->cfg.pcie_sram_able = 1;
		pcie_set->cfg.outbound_able = 1;
	}
	if (g_platform_type == MLU_PLAT_ASIC)
		pcie_set->dma_set.dma_timeout = TIME_OUT_VALUE;
	else
		pcie_set->dma_set.dma_timeout = TIME_OUT_VALUE * 100;
#if (!defined(__arm__) && !defined(__aarch64__))
	pcie_set->cfg.sync_write_able = 1;
#else
	pcie_set->cfg.sync_write_able = 0;
#endif
	pcie_set->share_mem_cnt = 0;
	pcie_set->vf_priv_data = cn_kzalloc(sizeof(struct cn_pci_vf_priv_data),
						GFP_KERNEL);
	if (!pcie_set->vf_priv_data) {
		cn_dev_pcie_err(pcie_set, "vf_priv_data alloc failed");
		return -1;
	}

	if (isr_type_index == -1) {
		if (isr_default_type == MSI) /* for performance optimization*/
			pcie_set->irq_set.irq_type = MSIX;
		else
			pcie_set->irq_set.irq_type = isr_default_type;
	} else {
		pcie_set->irq_set.irq_type = isr_type_index;
	}

	init_waitqueue_head(&pcie_set->vf_priv_data->p2v_wait_queue);

	sz = pci_resource_len(pdev, 0);
	if (!sz) {
		cn_dev_pcie_err(pcie_set, "no enough MMIO space for VF bar0");
		return -1;
	}

	pcie_set->bar0_set.base = pci_resource_start(pdev, 0);
	pcie_set->bar0_set.size = sz;

	if (c50_vf_pcie_bar_pre_init(pcie_set))
		return -1;

	/* register vf msi ISR */
	if (c50_vf_pcie_mbx_interrupt_init(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "Mbx interrupt init failed.");
		return -1;
	}

	if (c50_vf_pcie_bar_init(pcie_set))
		return -1;

	c50_vf_pcie_dma_pre_init(pcie_set);

	if (c50_vf_pcie_data_outbound_init(pcie_set))
		return -1;

	if (c50_vf_pre_init_hw(pcie_set))
		goto RELEASE_BAR;

	return ret;

RELEASE_BAR:
	c50_vf_bar_deinit(pcie_set);
	cn_kfree(pcie_set->vf_priv_data);

	return -1;
}

static int c50_vf_bus_pre_init(void *pcie)
{
	return 0;
}

static int c50_vf_bus_pre_exit(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	c50_vf_notify_exit(pcie_set);

	cn_pci_disable_all_irqs(pcie_set);
	if (isr_disable_func[pcie_set->irq_set.irq_type](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr destroyed failed!");
		return -1;
	}

	c50_vf_pcie_priv_set_free(pcie_set);
	c50_vf_bar_deinit(pcie_set);

	cn_kfree(pcie_set->vf_priv_data);

	return 0;
}

static int c50_vf_pcie_domain_get_resource(void *pcie,
					struct domain_resource *resource)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	resource->id = pcie_set->id;

	//resource->max_phy_channel = pcie_set->dma_set.max_phy_channel;
	resource->cfg_reg_size = pcie_set->bar0_set.reg_win_length;
	resource->share_mem_base = pcie_set->share_mem[0].device_addr;
	resource->share_mem_size = pcie_set->share_mem[0].win_length;
	resource->sram_pa_base = pcie_set->vf_priv_data->sram_pa;
	resource->sram_pa_size = pcie_set->vf_priv_data->sram_size;
	resource->ob_set[0].virt_addr = pcie_set->share_mem[1].virt_addr;
	resource->ob_set[0].win_length = pcie_set->share_mem[1].win_length;
	resource->ob_set[0].ob_axi_base = pcie_set->share_mem[1].device_addr;
	/* adapte to huge bar for domain*/
	resource->large_bar_base = cn_pci_bus_address(pcie_set->pdev, 4);
	resource->large_bar_size = pci_resource_len(pcie_set->pdev, 4);

	return 0;
}

struct cn_pci_info c50_vf_pci_info = {
	.setup = c50_vf_pcie_setup,
	.pre_init = c50_vf_bus_pre_init,
	.pre_exit = c50_vf_bus_pre_exit,
	.get_resource = c50_vf_pcie_domain_get_resource,
	.dev_name = "c50-vf"
};
