/************************************************************************
 *
 *  @file cndrv_pci_c30s_vf.c
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

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "../../pcie_dma.h"
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "./cndrv_pci_c30s.h"
#include "./cndrv_pci_c30s_vf.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "../../pcie_common.c"

static struct cn_pci_irq_str_index irq_str_index[GIC_INTERRUPT_NUM] = {
	{0, "pcie_dma0"},
	{1, "pcie_dma1"},
	{2, "pcie_dma2"},
	{3, "pcie_dma3"},
	{4, "pcie_dma4"},
	{5, "pcie_dma5"},
	{6, "pcie_dma6"},
	{7, "pcie_dma7"},
	{8, "p2v_mbx"},
	{9, "a2v_mbx"},
	{10, "dl2v_mbx"},
	{11, "dr2v_mbx"},
	{12, "vf_bar_remap_irq"},
};

const static int dma_workaround_unpack_num[8] = {1, 2, 2, 3, 2, 3, 3, 4};

static int c30s_vf_get_desc_unpack_num(u64 ipu_addr, unsigned long cpu_addr)
{
	int tail_offset;

	tail_offset = (ipu_addr + (PAGE_SIZE - (cpu_addr % PAGE_SIZE))) % 512;

	return dma_workaround_unpack_num[tail_offset / 64];
}

enum wait_flag_pos {
	alloc_commu_ctrlq,
	set_outbound_info,
	sriov_init,
	sriov_exit,
	get_inbound_info,
	get_outbound_info,
	get_dma_info,
	sriov_late_init
};

static int pcie_get_irq(char *irq_desc, struct cn_pcie_set *pcie_set)
{
	int i = 0;

	for (; i < 256; i++) {
		if (!pcie_set->irq_str_index_ptr[i].str_index)
			return -1;
		if (!strcmp(pcie_set->irq_str_index_ptr[i].str_index, irq_desc))
			return pcie_set->irq_str_index_ptr[i].hw_irq_num;
	}

	return -1;
}

static void c30s_vf_pcie_dump_reg(struct cn_pcie_set *pcie_set);

struct c30s_pcie_dump_reg_s {
	char *desc;
	unsigned long reg;
};

static void c30s_vf_pcie_dump_reg(struct cn_pcie_set *pcie_set)
{
	cn_dev_pcie_info(pcie_set, "no dump function, please add in private file.");
	return;
}

static void pcie_show_desc_list(struct dma_channel_info *channel)
{
	int desc_offset = 0;

	cn_dev_err("transfer_len:%ld desc_len:%d",
		channel->transfer_length, channel->desc_len);

	for (; desc_offset < channel->desc_len; desc_offset += DESC_SIZE) {
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

static irqreturn_t c30s_vf_pcie_dma_interrupt_handle(int index, void *data)
{
	unsigned int dma_status;
	unsigned int status_i;
	unsigned int channel_bit, max_phy_channel_mask;
	int phy_channel;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct dma_channel_info *channel;

	dma_status = 0;
	for (phy_channel = 0; phy_channel < pcie_set->max_phy_channel;
		phy_channel++) {
		status_i = cn_pci_reg_read32(pcie_set,
						DMA_INT_REG(phy_channel));
		if ((!status_i) || status_i == -1U)
			continue;

		dma_status |= status_i << phy_channel;
		if (status_i)
			cn_pci_reg_write32(pcie_set, DMA_INT_REG(phy_channel),
						status_i);

	}
	if (!dma_status)
		return IRQ_HANDLED;

	channel_bit = (1|(1<<DMA_REG_CHANNEL_NUM));
	max_phy_channel_mask = (1 << pcie_set->max_phy_channel) - 1;
	for (phy_channel = 0; phy_channel < pcie_set->max_phy_channel;
		phy_channel++, (channel_bit <<= 1)) {

		if (!(dma_status & channel_bit))
			continue;
		/* fix change mlu from vf to pf, dma can not used error*/
		cn_pci_reg_write32(pcie_set, DSHARE_ACCESS(phy_channel), 0);

		channel = (struct dma_channel_info *)pcie_set->
						running_channels[phy_channel][0];
		if (!channel) {
			cn_dev_pcie_err(pcie_set,
				"phy_channel:%d is NULL", phy_channel);
			continue;
		}

		if ((dma_status & channel_bit) &
			(max_phy_channel_mask << DMA_REG_CHANNEL_NUM)) {
			cn_pci_dma_complete(phy_channel, 0, CHANNEL_COMPLETED_ERR, pcie_set);
			cn_dev_pcie_err(pcie_set,
				"DMA  error interrupt_status:0x%x",
								dma_status);
			pcie_show_desc_list(channel);
		} else {
			cn_pci_dma_complete(phy_channel, 0, CHANNEL_COMPLETED, pcie_set);
		}

		/*clear DMA transfer ended flag*/
		cn_pci_reg_write32(pcie_set,
					(DMA_ISTATUS_BASE + phy_channel * 4),
					0x0);
		cn_pci_reg_read32(pcie_set,
					(DMA_ISTATUS_BASE + phy_channel * 4));
	}

	cn_pci_task_fair_schedule(pcie_set);

	return IRQ_HANDLED;
}

#define GET_BIT(data, bit)	((((data) & (0x1 << (bit))) >> (bit)))
static void c30s_vf_fetch_buf_status(int phy_channel, int *fetch_buf_num,
		int *buf_full, int *buf_empty, struct cn_pcie_set *pcie_set)
{
	u32 buf_status;

	buf_status = cn_pci_reg_read32(pcie_set,
				VF_DMA_CMD_BUFF_STATUS_FETCH(phy_channel));
	*fetch_buf_num = buf_status & (~0xFFFFFFE0);
	*buf_full = GET_BIT(buf_status, 16);
	*buf_empty = GET_BIT(buf_status, 17);
	cn_dev_pcie_debug(pcie_set,
			"buf_status=%#x,buf_num=%d,buf_full=%d,buf_empth=%d",
			buf_status, *fetch_buf_num, *buf_full, *buf_empty);
}

static void c30s_vf_fetch_status_buf_status(int phy_channel,
	int *fetch_status_buf_num, int *status_buf_full, int *status_buf_empty,
	struct cn_pcie_set *pcie_set)
{
	u32 status_buf_status;

	status_buf_status = cn_pci_reg_read32(pcie_set,
				VF_DMA_CMD_STATUS_BUFF_STATUS_FETCH(phy_channel));
	*fetch_status_buf_num = status_buf_status & (~0xFFFFFFE0);
	*status_buf_full = GET_BIT(status_buf_status, 16);
	*status_buf_empty = GET_BIT(status_buf_status, 17);
	cn_dev_pcie_debug(pcie_set,
		"status_buf_num=%d,status_buf_full=%d,status_buf_empty=%d",
		*fetch_status_buf_num, *status_buf_full, *status_buf_empty);
}

static irqreturn_t c30s_vf_dma_fetch_int_handle(int index, void *data)
{

	unsigned int fetch_status;
	int phy_channel = index - VF_PCIE_IRQ_DMA;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct dma_channel_info *channel;
	int fetch_status_buf_num;
	int status_buf_full;
	int status_buf_empty;
	int command_id;

	c30s_vf_fetch_status_buf_status(phy_channel, &fetch_status_buf_num,
				&status_buf_full, &status_buf_empty, pcie_set);

	while (fetch_status_buf_num) {
		fetch_status = cn_pci_reg_read32(pcie_set,
			VF_DMA_STATUS_FETCH(phy_channel));
		command_id = (fetch_status >> 20) & 0xf;

		cn_pci_reg_write32(pcie_set,
				VF_DMA_STATUS_UP_FETCH(phy_channel), 1);
		channel = (struct dma_channel_info *)
				pcie_set->running_channels[phy_channel][command_id];
		if (!channel) {
			cn_dev_pcie_err(pcie_set,
				"phy_channel:%d is NULL", phy_channel);
			break;
		}


		if (DMA_FETCH_ERR_CHECK(fetch_status)) {
			cn_pci_dma_complete(phy_channel, command_id, CHANNEL_COMPLETED_ERR, pcie_set);
			cn_dev_pcie_err(pcie_set, "FETCH DMA interrupt error fetch_status:%#x",
								fetch_status);
			if (pcie_set->ops->dump_reg)
				pcie_set->ops->dump_reg(pcie_set);
			pcie_set->ops->show_desc_list(channel);
		} else {
			cn_pci_dma_complete(phy_channel, command_id, CHANNEL_COMPLETED, pcie_set);
		}

		fetch_status_buf_num--;
	}

	cn_pci_task_fair_schedule(pcie_set);
	return IRQ_HANDLED;
}

static int c30s_vf_wait_pf_mbx(struct cn_pcie_set *pcie_set)
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

static int c30s_vf_notify_init(struct cn_pcie_set *pcie_set)
{
	int ret;
	u32 reg_value;
	enum wait_flag_pos pos = sriov_init;

	if (c30s_vf_wait_pf_mbx(pcie_set)) {
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

static int c30s_vf_notify_exit(struct cn_pcie_set *pcie_set)
{
	u32 reg_value;
	int ret;
	enum wait_flag_pos pos = sriov_exit;

	if (c30s_vf_wait_pf_mbx(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "Sriov exit failed.");
		return -1;
	}

	reg_value = CMD_SRIOV_EXIT;
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
		cn_dev_pcie_err(pcie_set, "Wait PF sriov exit time out.");
		return -1;
	}

	return 0;
}

static int c30s_vf_notify_late_init(struct cn_pcie_set *pcie_set)
{
	u32 reg_value;
	int ret;
	enum wait_flag_pos pos = sriov_late_init;

	if (c30s_vf_wait_pf_mbx(pcie_set)) {
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

static int c30s_vf_get_inbound_info(struct cn_pcie_set *pcie_set)
{
	u32 reg_value;
	int ret;
	enum wait_flag_pos pos = get_inbound_info;

	if (c30s_vf_wait_pf_mbx(pcie_set)) {
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

static int c30s_vf_get_dma_info(struct cn_pcie_set *pcie_set)
{
	u32 reg_value, channel_mask;
	int ret, p_dma_i;
	enum wait_flag_pos pos = get_dma_info;
	char src[30];
	u32 data;

	if (c30s_vf_wait_pf_mbx(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "Get DMA info failed");
		return -1;
	}

	reg_value = CMD_GET_DMA_INFO;
	reg_value = (reg_value << 16) | 0x1u;
	cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
	ret = wait_event_interruptible_timeout(
					pcie_set->vf_priv_data->p2v_wait_queue,
					pcie_set->vf_priv_data->wait_flag
					& (0x1u << pos),
					msecs_to_jiffies(5000));
	if (ret < 0) {
		cn_dev_pcie_err(pcie_set, "breaked by signal");
		return -1;
	} else if (ret == 0) {
		cn_dev_pcie_err(pcie_set, "Get DMA info time out.");
		return -1;
	}

	channel_mask = pcie_set->dma_phy_channel_mask;
	cn_dev_pcie_info(pcie_set, "channel_mask:%x", channel_mask);
	pcie_set->max_phy_channel = hweight32(channel_mask);
	/* dma desc size */

	pcie_set->shared_desc_total_size = VF_SHARED_DMA_DESC_TOTAL_SIZE;
	pcie_set->priv_desc_total_size = VF_PRIV_DMA_DESC_TOTAL_SIZE;
	pcie_set->dma_buffer_size = DMA_BUFFER_SIZE;
	pcie_set->per_desc_size = DMA_DESC_PER_SIZE;
	pcie_set->per_desc_max_size = PER_DESC_MAX_SIZE;
	pcie_set->async_static_task_num = ASYNC_STATIC_TASK_NUM;

	for (p_dma_i = 0; p_dma_i < pcie_set->max_phy_channel; p_dma_i++) {
		sprintf(src, "pcie_dma%d", p_dma_i);
		if (pcie_set->dma_fetch_enable) {
			data = cn_pci_reg_read32(pcie_set, VF_DMA_DESC_DBG_SEL_FETCH(p_dma_i));
			cn_pci_reg_write32(pcie_set, VF_DMA_DESC_DBG_SEL_FETCH(p_dma_i),
				data | (0x1 << 8));
			cn_pci_register_interrupt(pcie_get_irq(src, pcie_set),
				c30s_vf_dma_fetch_int_handle, pcie_set, pcie_set);
		} else {
			cn_pci_register_interrupt(pcie_get_irq(src, pcie_set),
				c30s_vf_pcie_dma_interrupt_handle, pcie_set, pcie_set);
		}
	}

	cn_dev_pcie_info(pcie_set, "max_phy_channel:%x\n", (int)pcie_set->max_phy_channel);
	cn_dev_pcie_info(pcie_set, "shared_desc_total_size:%x\n",
		(int)pcie_set->shared_desc_total_size);

	return 0;
}

static irqreturn_t c30s_p2vmbx_interrupt_handle(int index, void *data)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct cn_bus_set *bus_set = pcie_set->bus_set;
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

		cn_dev_pcie_debug(pcie_set, "CMD: 0x%x, entryh_val:0x%x, end_flag:%d", cmd, entryh_val, end_flag);

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
				cn_dev_pcie_info(pcie_set, "CMD_GET_INBOUND_INFO:msg_index%d",
						msg_index);
			pos = get_inbound_info;
			break;
		case CMD_GET_OUTBOUND_INFO:
			if (msg_index == 0)
				pcie_set->ob_total_size = msg;
			else if (msg_index == 1)
				pcie_set->ob_size = msg;
			else if (msg_index == 2)
				pcie_set->ob_axi_addr = msg;
			else if (msg_index == 3) {
				pcie_set->ob_axi_addr <<= 32;
				pcie_set->ob_axi_addr |= msg;
				if (pcie_set->ob_size)
					pcie_set->ob_cnt =
							pcie_set->ob_total_size
							/ pcie_set->ob_size;
				else
					pcie_set->ob_cnt = 0;
			} else
				cn_dev_pcie_info(pcie_set, "CMD_GET_OUTBOUND_INFO:msg_index%d",
						msg_index);
			pos = get_outbound_info;
			break;
		case CMD_GET_DMA_INFO:
			pcie_set->dma_phy_channel_mask = msg;
			pos = get_dma_info;
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

static irqreturn_t __maybe_unused c30s_a2vmbx_interrupt_handle(int index, void *data)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct cn_bus_set *bus_set = pcie_set->bus_set;
	int mbx_level;
	u32 msg;
	//int level_i;

	mbx_level = cn_pci_reg_read32(pcie_set, ARM2VF_MBX_STATUS(1));
	mbx_level = (mbx_level >> 8) & 0x7;

	if (!mbx_level) {
		cn_dev_pcie_info(pcie_set, "No message in arm2vf mailbox.");
		return IRQ_NONE;
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

/*
 * DRIVER-10027 workaround
 * desc_tail = (ipu_addr + count) % 512
 * desc_align = ipu_addr + count - desc_tail
 * case desc_tail range
 * [0B,64B]:no need unpack
 * (64B,128B]:split into 2 package {ipu_addr~desc_align + 64, remain}
 * (128B,192B]:split into 2 package {ipu_addr~desc_align + 128, remain}
 * (192B,256B]:split into 3 package {ipu_addr~desc_align + 128, 64, remain}
 * (256B,320B]:split into 2 package {ipu_addr~desc_align + 256, remain}
 * (320B,384B]:split into 3 package {ipu_addr~desc_align + 256, 64, remain}
 * (384B,448B]:split into 3 package {ipu_addr~desc_align + 256, 128, remain}
 * (448B,512B):split into 4 package {ipu_addr~desc_align + 256, 128, 64, remain}
 */
static int workaround_fill_desc(struct cn_pcie_set *pcie_set,
		DMA_DIR_TYPE direction, u64 desc_device_va, void *desc_host_buf,
		u64 ipu_ram_dma_addr, unsigned long cpu_dma_addr, unsigned long count,
		int *desc_number, int *desc_offset, int last_desc_flag)
{
	unsigned int ctrl, ndl, ndu;
	unsigned long trans_count;
	unsigned long trans_cpu_addr;
	u64 trans_ipu_addr;
	int trans_align = 512;
	int desc_tail;

	switch (direction) {
	case DMA_H2D:
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
		FILL_DESC(desc_host_buf, ctrl, ndl, ndu,
				cpu_dma_addr, ipu_ram_dma_addr, *desc_offset);
		*desc_offset += DESC_SIZE;
		(*desc_number)++;
		break;
	case DMA_P2P:
	case DMA_D2H:
		trans_ipu_addr = ipu_ram_dma_addr;
		trans_cpu_addr = cpu_dma_addr;
		while (count) {
			desc_tail = (trans_ipu_addr + count) % trans_align;
			trans_align = trans_align / 2;
			if (trans_align <= 32) {
				trans_count = count;
			} else {
				if (desc_tail >= trans_align) {
					if (count > desc_tail % trans_align) {
						/* |-----s---------trans_align----------e------| */
						trans_count = count - desc_tail % trans_align;
					} else {
						/* |---------------trans_align------s---e------| */
						continue;
					}
				} else {
					/* |-----s-----e---trans_align-----------------| */
					continue;
				}
			}

			ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(trans_count) << 8));
			if (last_desc_flag && (trans_count == count)) {
				ndl = 0x3;
				ndu = 0x0;
			} else {
				ndl = NEXT_DESC_LOWER32(desc_device_va,
								*desc_number) | 0x12;
				ndu = NEXT_DESC_UPPER32(desc_device_va,
								*desc_number);
			}
			cn_dev_pcie_debug(pcie_set,
					"ipu_addr:%#llx cpu_addr:%#lx trans_count:%#lx tail:%d",
					trans_ipu_addr, trans_cpu_addr, trans_count,
					(int)((trans_ipu_addr + trans_count) % (trans_align * 2)));
			FILL_DESC(desc_host_buf, ctrl, ndl, ndu,
					trans_ipu_addr, trans_cpu_addr, *desc_offset);

			*desc_offset += DESC_SIZE;
			(*desc_number)++;
			count -= trans_count;
			trans_ipu_addr += trans_count;
			trans_cpu_addr += trans_count;
		}
		break;

	default:
		cn_dev_pcie_err(pcie_set,
				"only DMA_H2D or DMA_D2H or DMA_P2P transfer mode");
		return -1;
	}
	return 0;
}

static int c30s_vf_pcie_fill_desc_list(struct dma_channel_info *channel)
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
				workaround_fill_desc(channel->pcie_set, channel->direction,
						channel->desc_device_va, channel->task->desc_buf,
						ipu_ram_dma_addr, cpu_dma_addr, count,
						&desc_number, &desc_offset, 0);
				ipu_ram_dma_addr += count;
				cpu_dma_addr = cpu_addr_cur;
				count = count_cur;
			}
		}

		workaround_fill_desc(channel->pcie_set, channel->direction,
				channel->desc_device_va, channel->task->desc_buf,
				ipu_ram_dma_addr, cpu_dma_addr, count,
				&desc_number, &desc_offset, 1);
	} else {
		cpu_dma_addr = channel->cpu_addr;
		count = channel->transfer_length;
		workaround_fill_desc(channel->pcie_set, channel->direction,
				channel->desc_device_va, channel->task->desc_buf,
				ipu_ram_dma_addr, cpu_dma_addr, count,
				&desc_number, &desc_offset, 1);
	}

	channel->desc_len = desc_offset;
	memcpy_toio(channel->desc_virt_base, channel->task->desc_buf, desc_offset);
	return 0;
}

static irqreturn_t c30s_vf_msi_interrupt(int irq, void *data)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	int vector_index;
	int irq_index, pos;
	int handler_num;
	unsigned long irq_status, irq_mask;
	u64 start, end;

	vector_index = irq - pcie_set->irq;

	if (vector_index >= GIC_MSI_COUNT) {
		cn_dev_pcie_err(pcie_set, "Recv error interrupt:%d", irq);
		return IRQ_NONE;
	}

	irq_status = cn_pci_reg_read32(pcie_set, VF_PCIE_INT_STATUS(0));
	irq_mask = cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));
	irq_status &= (~irq_mask);

	retry:
	for_each_set_bit(pos, (unsigned long *)&irq_status, 29) {
		if (pos < 24) /* dma related interrupt */
			irq_index = pos / 3;
		else
			irq_index = pos - 24 + 8;

		handler_num = 0;
		do {
			if (pcie_set->irq_desc[irq_index].handler[handler_num]
				== NULL) {
				cn_dev_pcie_err(pcie_set, "no interrupt handle!:%#lx %d",
						irq_status, irq_index);
				break;
			}
			start = get_jiffies_64();
			if (pcie_set->irq_desc[irq_index].handler[handler_num]
				(irq_index,
				pcie_set->irq_desc[irq_index].data[handler_num])
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

	pcie_set->do_dma_irq_status = 0;

	irq_status = cn_pci_reg_read32(pcie_set, VF_PCIE_INT_STATUS(0));
	irq_mask = cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));
	irq_status &= (~irq_mask);
	if (irq_status)
		goto retry;

	return IRQ_HANDLED;

}

static int c30s_vf_get_outbound_info(struct cn_pcie_set *pcie_set)
{
	u32 reg_value;
	int ret;
	enum wait_flag_pos pos = get_outbound_info;

	if (c30s_vf_wait_pf_mbx(pcie_set)) {
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

struct outbound_mem {
	void *virt_addr;
	dma_addr_t pci_addr;
};

static int c30s_vf_pcie_outbound_exit(struct cn_pcie_set *pcie_set)
{
	int i;
	struct outbound_mem *outbound_mem;

	outbound_mem = pcie_set->share_priv;
	if ((!outbound_mem) || (!pcie_set->share_mem_pages))
		return 0;

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
				outbound_mem[i].virt_addr,
				outbound_mem[i].pci_addr);
	}

	cn_kfree(pcie_set->share_mem_pages);
	pcie_set->share_mem_pages = NULL;
	cn_kfree(pcie_set->share_priv);
	pcie_set->share_priv = NULL;

	return 0;
}

static int c30s_vf_pcie_outbound_init(struct cn_pcie_set *pcie_set)
{
	int i;
	int j;
	int page_index = 0;
	struct outbound_mem *outbound_mem;
	int index = pcie_set->share_mem_cnt;
	int ret;

	ret = c30s_vf_get_outbound_info(pcie_set);
	if (ret)
		return -1;

	pcie_set->ob_axi_addr += VF_OUTBOUND_AXI_BASE;
	cn_dev_pcie_info(pcie_set, "ob_total_size:%x ob_size:%x ob_axi_addr:%llx ob_cnt:%x",
		pcie_set->ob_total_size, pcie_set->ob_size,
		pcie_set->ob_axi_addr,
		pcie_set->ob_cnt);

	pcie_set->share_mem_pages = (struct page **)kzalloc(
		sizeof(struct page *)*(pcie_set->ob_total_size / PAGE_SIZE),
		GFP_KERNEL);
	if (!pcie_set->share_mem_pages) {
		cn_dev_pcie_err(pcie_set, "Malloc share_mem_pages error");
		return -ENOMEM;
	}

	outbound_mem = (struct outbound_mem *)kzalloc(
		pcie_set->ob_cnt * sizeof(struct outbound_mem), GFP_KERNEL);
	if (!outbound_mem) {
		cn_dev_pcie_err(pcie_set, "Malloc outbound_mem error");
		ret = -ENOMEM;
		goto ERROR_RET;
	}
	pcie_set->share_priv = (void *)outbound_mem;

	for (i = 0; i < pcie_set->ob_cnt; i++) {

		/*alloc outband momery*/
		outbound_mem[i].virt_addr = dma_alloc_coherent(
			&pcie_set->pdev->dev,
			pcie_set->ob_size,
			&(outbound_mem[i].pci_addr),
			GFP_KERNEL);

		cn_dev_pcie_info(pcie_set, "outbound:%d alloc pci_addr:%llx ob_size:%x virt_addr:%lx",
			i, outbound_mem[i].pci_addr, pcie_set->ob_size,
			(ulong)outbound_mem[i].virt_addr);

		if (((ulong)outbound_mem[i].virt_addr)&(PAGE_SIZE - 1))
			panic("Address not align\n");

		if (!outbound_mem[i].virt_addr) {
			cn_dev_pcie_err(pcie_set, "dma_alloc_coherent error:%d", i);
			ret = -ENOMEM;
			goto ERROR_RET;
		}

		if (outbound_mem[i].pci_addr&(pcie_set->ob_size - 1)) {
			cn_dev_pcie_err(pcie_set, "dma_alloc_coherent not align:%llx\n",
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
		cn_dev_pcie_err(pcie_set, "vm_map_ram error");
		goto ERROR_RET;
	}

	cn_dev_pcie_info(pcie_set, "host share mem virtual addr:%lx",
		(unsigned long)pcie_set->share_mem[index].virt_addr);
	pcie_set->share_mem[index].win_length = pcie_set->ob_total_size;
	pcie_set->share_mem[index].type = CN_SHARE_MEM_HOST;
	pcie_set->share_mem[index].device_addr = pcie_set->ob_axi_addr;

	pcie_set->share_mem_cnt++;
	return 0;

ERROR_RET:
	cn_dev_pcie_err(pcie_set, "init error");
	c30s_vf_pcie_outbound_exit(pcie_set);

	return ret;
}

static void c30s_vf_pcie_unregister_bar(struct cn_pcie_set *pcie_set)
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

static void c30s_vf_bar_deinit(struct cn_pcie_set *pcie_set)
{
	int bar;
	int seg;

	cn_dev_pcie_info(pcie_set, "cn_iounmap bar0-5");

	for (bar = 0; bar < 6; bar++) {
		if (pcie_set->pcibar[bar].size <= 0)
			continue;

		for (seg = 0; seg < MAX_BAR_SEGMENTS; seg++) {
			if (pcie_set->pcibar[bar].seg[seg].virt) {
				cn_iounmap(pcie_set->pcibar[bar].seg[seg].virt);
				pcie_set->pcibar[bar].seg[seg].virt = NULL;
			}
		}
	}

	c30s_vf_pcie_unregister_bar(pcie_set);
	pcie_set->reg_virt_base = NULL;
	pcie_set->reg_phy_addr = 0;
	pcie_set->reg_win_length = 0;
}

static int c30s_vf_pcie_exit(struct cn_pcie_set *pcie_set)
{
	c30s_vf_notify_exit(pcie_set);
	c30s_vf_pcie_outbound_exit(pcie_set);

	if (isr_disable_func[0](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr destroyed failed!");
		return -1;
	}

	c30s_vf_bar_deinit(pcie_set);

	if (pcie_set->vf_priv_data) {
		cn_kfree(pcie_set->vf_priv_data);
		pcie_set->vf_priv_data = NULL;
	}

	return 0;
}

static int c30s_vf_pcie_init(struct cn_pcie_set *pcie_set)
{
	c30s_vf_notify_late_init(pcie_set);
	cn_dev_pcie_info(pcie_set, "pcie init end");
	return 0;
}

static int c30s_vf_pcie_pre_exit(struct cn_pcie_set *pcie_set)
{
	cn_dev_pcie_info(pcie_set, "pcie pre exit end");
	return 0;
}

static int pcie_dma_go(struct dma_channel_info *channel, int phy_channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	int channel_id = phy_channel;
	unsigned long src_desc_addr = 0;
	unsigned long dst_desc_addr = 0;
	int sgl_enable = 0;
	int sgl_mode = 0;
	int sg_id[2] = {0};

	if (channel->status != CHANNEL_RUNNING)
		cn_dev_pcie_err(pcie_set, "channel is not locked:%d", channel->status);

	switch (channel->direction) {
	case DMA_H2D:
		cn_pci_reg_write32(pcie_set,
			DSRC_PARAM(channel_id), DMA_PCIE_PARAM);
		cn_pci_reg_write32(pcie_set,
			DDEST_PARAM(channel_id), DMA_AXI_PARAM);
		break;
	case DMA_P2P:
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

	cn_pci_reg_read32(pcie_set, DDESTU(channel_id));

	cn_pci_reg_write32(pcie_set, DCTRL(channel_id), (sgl_enable << 3)
					| (DSE_COND << 4) | (DIRQ << 8)
					| (DIRQ_ID << 12) | (sgl_mode << 24)
					| (sg_id[0] << 26) | (sg_id[1] << 29)
					| 0x1);

	return 0;
}


static int c30s_vf_pcie_dma_go(struct dma_channel_info *channel, int phy_channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	unsigned long desc_addr = 0;
	unsigned int desc_num = 0;
	int fetch_buf_num;
	int buf_full;
	int buf_empty;
	unsigned long flag = 0;

	if (!pcie_set->dma_fetch_enable)
		return pcie_dma_go(channel, phy_channel);

	if (channel->status != CHANNEL_RUNNING)
		cn_dev_pcie_err(pcie_set, "channel is not locked:%d", channel->status);

	spin_lock_irqsave(&pcie_set->fetch_lock[phy_channel], flag);
	switch (channel->direction) {
	case DMA_H2D:
		cn_pci_reg_write32(pcie_set, VF_DMA_DESC_CTRL_FETCH(phy_channel),
				(DMA_PCIE_PARAM << 0) | (DMA_AXI_PARAM << 16));
		break;

	case DMA_D2H:
		cn_pci_reg_write32(pcie_set, VF_DMA_DESC_CTRL_FETCH(phy_channel),
				(DMA_AXI_PARAM << 0) | (DMA_PCIE_PARAM << 16));
		break;
	default:
		spin_unlock_irqrestore(&pcie_set->fetch_lock[phy_channel], flag);
		return -1;
	}
	desc_addr = channel->desc_device_va;
	desc_num = channel->desc_len / DESC_SIZE;

	cn_pci_reg_write32(pcie_set,
		VF_DMA_DESC_ADDR_L_FETCH(phy_channel), LOWER32(desc_addr));
	cn_pci_reg_write32(pcie_set,
		VF_DMA_DESC_ADDR_H_FETCH(phy_channel), UPPER32(desc_addr));
	cn_pci_reg_write32(pcie_set,
		VF_DMA_DESC_NUM_FETCH(phy_channel), desc_num);
retry:
	/* FETCH TODO: buf_full is for debug, will be remove later */
	c30s_vf_fetch_buf_status(phy_channel, &fetch_buf_num, &buf_full,
						&buf_empty, pcie_set);
	if (!buf_full) {
		cn_pci_reg_write32(pcie_set, VF_DMA_DESC_CTRL2_FETCH(phy_channel),
				((channel->fetch_command_id << 24) | (0x1 << 31)));
	} else {
		cn_dev_pcie_err(pcie_set, "phy_channel[%d] buf is full", phy_channel);
		goto retry;
	}
	spin_unlock_irqrestore(&pcie_set->fetch_lock[phy_channel], flag);

	return 0;
}

static int pcie_dma_bypass_size(struct cn_pcie_set *pcie_set)
{
#if defined(__x86_64__)
	pcie_set->dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 32 * 1024;
	pcie_set->dma_bypass_pinned_size = dma_bypass_pinned_size ?
				dma_bypass_pinned_size : 32 * 1024;
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
	pcie_set->d2h_bypass_custom_size = d2h_bypass_custom_size ?
				d2h_bypass_custom_size : 64;
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


static int c30s_vf_pcie_gic_mask_all(struct cn_pcie_set *pcie_set)
{
	return 0;
}

static void c30s_vf_pci_mb(struct cn_pcie_set *pcie_set)
{
	/* barrier */
	smp_mb();
	cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(1));
}

static int c30s_vf_pcie_gic_mask(int irq, struct cn_pcie_set *pcie_set)
{
	u32 reg_val, irq_i;

	if (irq > 12 || irq < 0) {
		cn_dev_pcie_err(pcie_set, "invalid irq num:%d", irq);
		return -1;
	}

	if (irq < 8)
		irq_i = 3 * irq;
	else
		irq_i = 24 + irq - 8;

	reg_val = cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));
	reg_val |= 1UL << irq_i;
	cn_pci_reg_write32(pcie_set, VF_PCIE_INT_MASK(0), reg_val);
	cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));

	return 0;
}

static int c30s_vf_pcie_gic_unmask(int irq, struct cn_pcie_set *pcie_set)
{
	u32 reg_val, irq_i;

	if (irq > 12 || irq < 0) {
		cn_dev_pcie_err(pcie_set, "invalid irq num:%d", irq);
		return -1;
	}

	if (irq < 8)
		irq_i = 3 * irq;
	else
		irq_i = 24 + irq - 8;

	reg_val = cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));
	reg_val &= ~(1ULL << irq_i);
	cn_pci_reg_write32(pcie_set, VF_PCIE_INT_MASK(0), reg_val);
	cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));

	return 0;
}

static struct cn_pci_ops c30s_vf_private_ops = {
	.pcie_init = c30s_vf_pcie_init,
	.pcie_pre_exit = c30s_vf_pcie_pre_exit,
	.pcie_exit = c30s_vf_pcie_exit,
	.fill_desc_list = c30s_vf_pcie_fill_desc_list,
	.get_desc_unpack_num = c30s_vf_get_desc_unpack_num,
	.show_desc_list = pcie_show_desc_list,
	.dump_reg = c30s_vf_pcie_dump_reg,
	.get_irq_by_desc = pcie_get_irq,
	.pci_mb = c30s_vf_pci_mb,
	.dma_bypass_size = pcie_dma_bypass_size,
	.set_bar_window = pcie_set_bar_window,
	.msi_isr = c30s_vf_msi_interrupt,
	.dma_go_command =  c30s_vf_pcie_dma_go,
	.bar_read = mlu370_pigeon_pcie_bar_read,
	.bar_write = mlu370_pigeon_pcie_bar_write,
	.gic_mask_all = c30s_vf_pcie_gic_mask_all,
	.gic_mask = c30s_vf_pcie_gic_mask,
	.gic_unmask = c30s_vf_pcie_gic_unmask,
};

static int c30s_vf_pcie_enable_pf_bar(struct cn_pcie_set *pcie_set)
{
	int index;
	struct bar_resource bar, *new;
	struct pci_dev *pdev = pcie_set->pdev;
	u64 base, sz;

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
		bar.size = sz;
		new = pcie_bar_resource_struct_init(&bar);
		if (new)
			list_add_tail(&new->list, &pcie_set->bar_resource_head);
	}

	return 0;
}

static int c30s_vf_pcie_bar_pre_init(struct cn_pcie_set *pcie_set)
{
	//int bar;
	struct pcibar_seg_s *p_bar_seg;
	struct pcibar_s *p_bar;

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

	if (!p_bar_seg->virt)
		goto ERROR_RET;

	cn_dev_pcie_info(pcie_set, "Bar0 memory virt:%lx size:%llx",
		(ulong)p_bar_seg->virt, p_bar_seg->size);
	return 0;

ERROR_RET:
	cn_dev_pcie_err(pcie_set, "init error");

	c30s_vf_bar_deinit(pcie_set);
	return -1;
}

static int c30s_vf_pcie_bar_init(struct cn_pcie_set *pcie_set)
{
	u32 vf_share_mem_base, vf_share_mem_size;

	if (c30s_vf_pcie_enable_pf_bar(pcie_set))
		goto ERROR_RET;

	if (c30s_vf_notify_init(pcie_set))
		goto ERROR_RET;

	pcie_set->share_mem_cnt = 1;
	if (c30s_vf_get_inbound_info(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "get inbound info error.");
		goto ERROR_RET;
	}

	vf_share_mem_base = pcie_set->vf_priv_data->share_mem_base;
	vf_share_mem_size = pcie_set->vf_priv_data->share_mem_size;
	cn_dev_pcie_info(pcie_set, "vf_share_mem_base:%x size:%x dev_vaddr_base:%llx",
		vf_share_mem_base, vf_share_mem_size,
		pcie_set->vf_priv_data->inbdmem_dev_va_base);

	pcie_set->share_mem[0].virt_addr =
		pcie_set->pcibar[0].seg[1].virt + vf_share_mem_base;
	pcie_set->share_mem[0].phy_addr =
		pcie_set->pcibar[0].seg[1].base + vf_share_mem_base;
	pcie_set->share_mem[0].win_length = vf_share_mem_size;
	pcie_set->share_mem[0].device_addr =
				pcie_set->vf_priv_data->inbdmem_dev_va_base;

	pcie_set->share_mem[0].type = CN_SHARE_MEM_DEV;

	return 0;

ERROR_RET:
	cn_dev_pcie_err(pcie_set, "init error");

	c30s_vf_bar_deinit(pcie_set);
	return -1;
}

static int c30s_vf_set_outbound_reg(struct cn_pcie_set *pcie_set)
{
	u32 reg_value;
	int i;
	int ret = 0;
	enum wait_flag_pos pos = set_outbound_info;
	struct outbound_mem *outbound_mem;

	outbound_mem = pcie_set->share_priv;

	for (i = 0; i < pcie_set->ob_cnt; i++) {
		if (c30s_vf_wait_pf_mbx(pcie_set)) {
			cn_dev_pcie_err(pcie_set, "Set outbound register failed.");
			return -1;
		}

		reg_value = (u32)(outbound_mem[i].pci_addr & (-1u));
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYL(0), reg_value);
		barrier();
		reg_value = CMD_SET_OUTBOUND_INFO;
		reg_value = (reg_value << 16) | ((i * 2) << 1);
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);

		if (c30s_vf_wait_pf_mbx(pcie_set)) {
			cn_dev_pcie_err(pcie_set, "Set outbound register failed.");
			return -1;
		}

		reg_value = (u32)(outbound_mem[i].pci_addr >> 32);
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYL(0), reg_value);
		barrier();
		reg_value = CMD_SET_OUTBOUND_INFO;
		reg_value = (reg_value << 16) | ((i * 2 + 1) << 1);
		if (i == pcie_set->ob_cnt - 1)
			reg_value |= 0x1u;
		cn_pci_reg_write32(pcie_set, VF2PF_MBX_ENTRYH(0), reg_value);
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
		cn_dev_pcie_err(pcie_set, "Set outbound reg time out.");
		return -1;
	}

	return 0;
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

static int c30s_vf_pre_init_hw(struct cn_pcie_set *pcie_set)
{
	int ret, p_dma_i;
	u32 reg_value;

	set_bar_default_window(pcie_set);
	if (pcie_set->outbound_able) {
		ret = c30s_vf_set_outbound_reg(pcie_set);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "Set outbound reg error");
			return ret;
		}
	}

	reg_value = cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));
	if (pcie_set->dma_fetch_enable) {
		for (p_dma_i = 0; p_dma_i < pcie_set->max_phy_channel; p_dma_i++)
			reg_value &= ~(0x4u << (p_dma_i * 3));
	} else {
		for (p_dma_i = 0; p_dma_i < pcie_set->max_phy_channel; p_dma_i++)
			reg_value &= ~(0x1u << (p_dma_i * 3));
	}

	cn_pci_reg_write32(pcie_set, VF_PCIE_INT_MASK(0), reg_value);
	cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));

	return 0;
}

static int c30s_vf_pcie_mbx_interrupt_init(struct cn_pcie_set *pcie_set)
{
	char src[30];
	int ret;
	u32 reg_value;

	pcie_set->irq_num = GIC_MSI_COUNT;
	pcie_set->irq_str_index_ptr = irq_str_index;
	reg_value = 0xFFFFFFFF;
	cn_pci_reg_write32(pcie_set, VF_PCIE_INT_MASK(0), reg_value);
	cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));

	if (isr_enable_func[0](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr init failed!");
		return -1;
	}

	sprintf(src, "p2v_mbx");
	ret = cn_pci_register_interrupt(
				pcie_get_irq(src, pcie_set),
				c30s_p2vmbx_interrupt_handle,
				pcie_set, pcie_set);
	if (ret)
		return -1;

	#if defined(IPCM_COMMU_SHARED_IRQ) || defined(IPCM_POLLING_MODE)
	sprintf(src, "a2v_mbx");
	ret = cn_pci_register_interrupt(
				pcie_get_irq(src, pcie_set),
				c30s_a2vmbx_interrupt_handle,
				pcie_set, pcie_set);
	if (ret)
		return -1;
	#endif

	reg_value = cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));
	reg_value &= ~(1u << 24);
	#if defined(IPCM_COMMU_SHARED_IRQ) || defined(IPCM_POLLING_MODE)
	reg_value &= ~(1u << 25);
	#endif
	cn_pci_reg_write32(pcie_set, VF_PCIE_INT_MASK(0), reg_value);
	cn_pci_reg_read32(pcie_set, VF_PCIE_INT_MASK(0));
	return 0;
}

static int c30s_vf_pcie_setup(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;
	int result = 0;
	int ret;

	if (pcie_set->dma_fetch_enable)
		pcie_set->dma_fetch_buff = DMA_FETCH_BUFF;
	else
		pcie_set->dma_fetch_buff = 1;

	pcie_set->ops = &c30s_vf_private_ops;
	pcie_set->is_virtfn = 1;
	pcie_set->vf_priv_data = cn_kzalloc(sizeof(struct cn_pci_vf_priv_data),
						GFP_KERNEL);
	if (!pcie_set->vf_priv_data) {
		cn_dev_pcie_err(pcie_set, "vf_priv_data alloc failed");
		return -1;
	}

	pcie_set->irq_type = (isr_type_index == -1) ? isr_default_type : isr_type_index;

	pcie_set->outbound_able = 1;
	init_waitqueue_head(&pcie_set->vf_priv_data->p2v_wait_queue);
	pcie_set->share_mem_cnt = 0;
	INIT_LIST_HEAD(&pcie_set->bar_resource_head);

	if (c30s_vf_pcie_bar_pre_init(pcie_set))
		return -1;

	/* register vf msi ISR */
	if (c30s_vf_pcie_mbx_interrupt_init(pcie_set)) {
		cn_dev_pcie_err(pcie_set, "Mbx interrupt init failed.");
		return -1;
	}

	if (c30s_vf_pcie_bar_init(pcie_set))
		return -1;

	if (c30s_vf_get_dma_info(pcie_set))
		goto RELEASE_BAR;

	/* get outband memory info */
	if (pcie_set->outbound_able) {
		ret = c30s_vf_pcie_outbound_init(pcie_set);
		if (ret)
			goto RELEASE_OUTBOUND;
	}

	/* c30s_vf_set_outbound_reg */
	if (c30s_vf_pre_init_hw(pcie_set))
		goto RELEASE_BAR;

	return result;

RELEASE_OUTBOUND:
	c30s_vf_pcie_outbound_exit(pcie_set);
RELEASE_BAR:
	c30s_vf_bar_deinit(pcie_set);
	if (pcie_set->vf_priv_data) {
		cn_kfree(pcie_set->vf_priv_data);
		pcie_set->vf_priv_data = NULL;
	}
	return -1;
}

static int c30s_vf_bus_pre_init(void *pcie)
{
	return 0;
}

static int c30s_vf_bus_pre_exit(void *pcie)
{
	return 0;
}

static int c30s_vf_pcie_domain_get_resource(void *pcie,
					struct domain_resource *resource)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	resource->id = pcie_set->id;
	resource->max_phy_channel = pcie_set->max_phy_channel;
	resource->cfg_reg_size = pcie_set->reg_win_length;
	resource->share_mem_base = pcie_set->share_mem[0].device_addr;
	resource->share_mem_size = pcie_set->share_mem[0].win_length;
	resource->ob_set[0].virt_addr = pcie_set->share_mem[1].virt_addr;
	resource->ob_set[0].win_length = pcie_set->share_mem[1].win_length;
	resource->ob_set[0].ob_axi_base = pcie_set->share_mem[1].device_addr;

	return 0;
}

struct cn_pci_info c30s_vf_pci_info = {
	.setup = c30s_vf_pcie_setup,
	.pre_init = c30s_vf_bus_pre_init,
	.pre_exit = c30s_vf_bus_pre_exit,
	.get_resource = c30s_vf_pcie_domain_get_resource,
	.dev_name = "c30s-vf"
};
