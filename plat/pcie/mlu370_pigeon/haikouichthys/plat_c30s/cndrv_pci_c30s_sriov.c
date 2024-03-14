/************************************************************************
 *
 *  @file cndrv_pci_c30s_sriov.c
 *
 *  @brief This file is designed to support sriov functions.
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

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "../../pcie_dma.h"
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "./cndrv_pci_c30s.h"
#include "cndrv_domain.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "cndrv_ipcm.h"
#include "cndrv_kwork.h"

#define MAX_VF_COUNT		(8)
#define MAX_VDMA_CHANNEL	(8)

/* MAILBOX REG, W:write, R:read */
#define MBX_BASE		(0x60000)
#define VF2PF_MBXW_STATUS(vf_i)	(MBX_BASE + 0x20 + 0x100 * vf_i)
#define VF2PF_MBXW_ENTRYL(vf_i) (MBX_BASE + 0x24 + 0x100 * vf_i)
#define VF2PF_MBXW_ENTRYH(vf_i)	(MBX_BASE + 0x28 + 0x100 * vf_i)
#define VF2PF_MBXR_STATUS(vf_i)	(MBX_BASE + 0x30 + 0x100 * vf_i)
#define VF2PF_MBXR_ENTRYL(vf_i)	(MBX_BASE + 0x34 + 0x100 * vf_i)
#define VF2PF_MBXR_ENTRYH(vf_i)	(MBX_BASE + 0x38 + 0x100 * vf_i)

#define PF2VF_MBXW_STATUS(vf_i)	(MBX_BASE + 0xa0 + 0x100 * vf_i)
#define PF2VF_MBXW_ENTRYL(vf_i) (MBX_BASE + 0xa4 + 0x100 * vf_i)
#define PF2VF_MBXW_ENTRYH(vf_i)	(MBX_BASE + 0xa8 + 0x100 * vf_i)
#define PF2VF_MBXR_STATUS(vf_i)	(MBX_BASE + 0xb0 + 0x100 * vf_i)
#define PF2VF_MBXR_ENTRYL(vf_i)	(MBX_BASE + 0xb4 + 0x100 * vf_i)
#define PF2VF_MBXR_ENTRYH(vf_i)	(MBX_BASE + 0xb8 + 0x100 * vf_i)

/* ATR_AXI4_SLV1 Registers */
#define ATR_AXI4_SLV1		(0x900)
#define SLV1_TABLE_BASE		(0x20)
#define SLV1_SRC_ADDRL(i)	(ATR_AXI4_SLV1 + (i) * SLV0_TABLE_BASE + 0x0)
#define SLV1_SRC_ADDRU(i)	(ATR_AXI4_SLV1 + (i) * SLV0_TABLE_BASE + 0x4)
#define SLV1_TRSL_ADDRL(i)	(ATR_AXI4_SLV1 + (i) * SLV0_TABLE_BASE + 0x8)
#define SLV1_TRSL_ADDRU(i)	(ATR_AXI4_SLV1 + (i) * SLV0_TABLE_BASE + 0xC)
#define SLV1_TRSL_PARAM(i)	(ATR_AXI4_SLV1 + (i) * SLV0_TABLE_BASE + 0x10)
#define SLV1_TRSL_MASKL(i)	(ATR_AXI4_SLV1 + (i) * SLV0_TABLE_BASE + 0x18)
#define SLV1_TRSL_MASKU(i)	(ATR_AXI4_SLV1 + (i) * SLV0_TABLE_BASE + 0x1C)

#define BAR_REMAP		(0x102000)
#define V2P_TABLE(vf_i, ch_i)	(BAR_REMAP + ch_i * 0x4 + vf_i * 0x100)
#define P2V_TABLE(ch_i)		(BAR_REMAP + 0x1000 + ch_i * 0x4)

#define PCIE_SLV1_ADDR			(0x5000000)
#define VF_OBWIN_SIZE			(0x200000)
#define VF_OB_AXI_ADDR(vf_i)		(PCIE_SLV1_ADDR + VF_OBWIN_SIZE * vf_i)

#define PCIE_PF_MBX_IRQ		(11)
#define PCIE_VF_MBX_IRQ(vf_i)	(13 + vf_i)

static int c30s_pcie_wait_mbx_available(struct cn_pcie_set *pcie_set,
					int vf_id)
{
	int mbx_full;
	int timeout = 1000, i = 0;

	while (1) {
		mbx_full = cn_pci_reg_read32(pcie_set,
						PF2VF_MBXW_STATUS(vf_id));
		mbx_full &= 0x1;
		if (!mbx_full)
			break;
		schedule();
		msleep(1);
		i++;
		if (i > timeout) {
			cn_dev_pcie_info(pcie_set,
					"Wait P2V Mailbox Available Time Out.");
			return -1;
		}
	}
	return 0;
}

static u64 c30s_pcie_ob_mask(struct cn_pcie_set *pcie_set, unsigned int vf_i)
{
	const void *domain;

	if (vf_i >= pcie_set->nums_vf) {
		cn_dev_pcie_err(pcie_set, "vf_i:%d error", vf_i);
		return 0;
	}

	domain = cn_dm_get_domain(pcie_set->bus_set->core, DM_FUNC_VF0 + vf_i);

	return (u64)cn_dm_pci_get_ob_mask(domain);
}

static void c30s_pcie_vf_work(struct work_struct *work)
{
	struct cn_pci_sriov *sriov = (struct cn_pci_sriov *)container_of(
		work, struct cn_pci_sriov, vf2pf_work);
	struct cn_pcie_set *pcie_set = sriov->pcie_set;
	int vf_id = sriov->vf_id;
	struct cn_core_set *core = pcie_set->bus_set->core;
	u64 cmd;
	u32 entryh_value;

	cmd = (sriov->mbx_msg[0] & 0xFFFF0000ul) >> 16;
	if (unlikely(cmd == CMD_SRIOV_LATE_INIT) && sriov->msg_index == 1) {
		/*
		 * set vf start to ipcm, indicated outbound can/can't be accessed
		 */
		sriov->msg_index = 0;
		ipcm_announce_vf_status(core, true, vf_id + 1);
		if (!c30s_pcie_wait_mbx_available(pcie_set, vf_id)) {
			entryh_value = (cmd << 16) | (0x0 << 1) | 0x1;
			cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
								entryh_value);
			cn_dev_pcie_info(pcie_set, "VF:%d Start", vf_id);
		}
	}
	if (likely(commu_get_vf_init_flag(core, vf_id))) {
		commu_vf2pf_handler(core, vf_id);
		return;
	}
	cn_dev_pcie_info(pcie_set, "VF %d CMD:%llx", vf_id, cmd);

	switch (cmd) {
	case CMD_GET_INBOUND_INFO: {
		u32 base;
		u32 size;
		u32 dev_vaddr_l;
		u32 dev_vaddr_h;
		u64 dev_vaddr;

		const void *domain = cn_dm_get_domain(core, DM_FUNC_VF0 + vf_id);

		sriov->msg_index = 0;
		base = cn_dm_pci_get_bars_shm_bs(domain, 0);
		size = cn_dm_pci_get_bars_shm_sz(domain, 0);
		dev_vaddr = cn_bus_get_device_addr(pcie_set->bus_set, 0);
		dev_vaddr += base;
		dev_vaddr_l = (u32)dev_vaddr;
		dev_vaddr_h = (u32)(dev_vaddr >> 32);

		cn_dev_pcie_info(pcie_set, "base %x  --size %x", base, size);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (0 << 1);
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYL(vf_id), base);
		/* Need to make sure write mailbox entry low frist,then entry
		 * high.
		 */
		wmb();
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (1 << 1);
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYL(vf_id), size);
		wmb(); /* confirm the writing order */
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (2 << 1);
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYL(vf_id),
					dev_vaddr_l);
		wmb(); /* confirm the writing order */
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (3 << 1) | 1;
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYL(vf_id),
					dev_vaddr_h);
		wmb(); /* confirm the writing order */
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);
		break;
	}

	case CMD_GET_OUTBOUND_INFO: {
		u64 mask;
		u32 size;
		u32 upper;
		u32 lower;
		u64 iobase;

		sriov->msg_index = 0;
		mask = c30s_pcie_ob_mask(pcie_set, vf_id);
		size = hweight64(mask) * VF_OBWIN_SIZE;
		iobase = VF_OB_AXI_ADDR(vf_id);
		upper = iobase >> 32;
		lower = (u32)iobase;

		cn_dev_pcie_info(pcie_set, "outbound_mask:%x  --size %x %llx %x %x",
			(int)mask, (int)size, iobase, lower, upper);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (0x0 << 1);
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYL(vf_id), size);
		wmb(); /* confirm the writing order */
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (0x1 << 1);
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYL(vf_id),
					VF_OBWIN_SIZE);
		wmb(); /* confirm the writing order */
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (0x2 << 1);
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYL(vf_id), upper);
		wmb(); /* confirm the writing order */
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (0x3 << 1) | 0x1;
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYL(vf_id), lower);
		wmb(); /* confirm the writing order */
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);

		break;
	}

	case CMD_SET_OUTBOUND_INFO: {
		u32 upper;
		u32 lower;
		u32 size;
		u64 iobase;
		u64 value;

		if (sriov->msg_index != 2)
			break;

		sriov->msg_index = 0;
		size = VF_OBWIN_SIZE;
		iobase = VF_OB_AXI_ADDR(vf_id);
		lower = (u32)(sriov->mbx_msg[0] >> 32);
		upper = (u32)(sriov->mbx_msg[1] >> 32);
		value = upper;
		value = (value << 32) | lower;
		cn_dev_pcie_info(pcie_set, "VF %d Outbound AXI Base:%llx, Size:%x, Host Addr:%llx",
				vf_id, iobase, size, value);
		/* outbound pci address */
		cn_pci_reg_write64(pcie_set, SLV1_TRSL_ADDRL(vf_id), value);
		/* axi address */
		value = (VF_OBWIN_SIZE * vf_id) | ((OUTBOUND_POWER - 1) << 1)
			| (1 << 0);
		cn_pci_reg_write64(pcie_set, SLV1_SRC_ADDRL(vf_id), value);
		/* param*/
		value = 0;
		cn_pci_reg_write32(pcie_set, SLV1_TRSL_PARAM(vf_id),
					(u32)value);
		/* mask*/
		value = ~(u64)((0x1ULL << OUTBOUND_POWER) - 1);
		cn_pci_reg_write64(pcie_set, SLV1_TRSL_MASKL(vf_id), value);
		cn_pci_reg_read64(pcie_set, SLV1_TRSL_MASKL(vf_id));

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (0x0 << 1) | 0x1;
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);
		break;
	}

	case CMD_GET_DMA_INFO: {
		int i;
		u32 channel_mask = 0;

		sriov->msg_index = 0;
		/* the vf dma channel is from 0 to N-1 */
		for (i = 0; i < pcie_set->max_phy_channel; i++) {
			if (pcie_set->sriov[vf_id].vf_dma_phy_channel_mask
			    & (1 << i))
				channel_mask = ((channel_mask << 1) | 1);

		}

		cn_dev_pcie_info(pcie_set, "VF %d Physical Channel Mask:%x, Virtual Channel Mask:%x",
			vf_id, pcie_set->sriov[vf_id].vf_dma_phy_channel_mask,
			channel_mask);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (0x0 << 1) | 0x1;
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYL(vf_id),
					channel_mask);
		wmb(); /* confirm the writing order */
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);
		break;
	}

	case CMD_ALLOC_COMMU_CTRLQ: {
		u64 dev_vaddr;
		u32 offset;

		if (sriov->msg_index != 2)
			break;

		sriov->msg_index = 0;
		dev_vaddr = sriov->mbx_msg[1] >> 32;
		dev_vaddr <<= 32;
		dev_vaddr |= (sriov->mbx_msg[0] >> 32);
		offset = dev_vaddr - cn_bus_get_device_addr(pcie_set->bus_set,
									0);
		commu_ctrlq_alloc(core, vf_id, pcie_set->pcibar[0].seg[1].virt + offset, 32);
		cn_dev_pcie_info(pcie_set, "CMD_ALLOC_COMMU_CTRLQ virt:%px offset:%x",
			pcie_set->pcibar[0].seg[1].virt, (int)offset);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (0x0 << 1) | 0x1;
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);
		commu_set_vf_init_flag(core, vf_id, 1);
		break;
	}

	case CMD_SRIOV_INIT: {
		sriov->msg_index = 0;
		cn_dm_init_domain_sriov_smart(core, vf_id + 1);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (0x0 << 1) | 0x1;
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);
		cn_dev_pcie_info(pcie_set, "VF:%d Sriov Init", vf_id);
		break;
	}

	case CMD_SRIOV_EXIT: {
		sriov->msg_index = 0;
		cn_dm_exit_domain_sriov_with_rpc(core, vf_id + 1);

		if (c30s_pcie_wait_mbx_available(pcie_set, vf_id))
			return;

		entryh_value = (cmd << 16) | (0x0 << 1) | 0x1;
		cn_pci_reg_write32(pcie_set, PF2VF_MBXW_ENTRYH(vf_id),
					entryh_value);
		cn_dev_pcie_info(pcie_set, "VF:%d Sriov Exit", vf_id);
		break;
	}

	default:
		break;
	}

	return;
}

irqreturn_t c30s_pcie_v2p_mailbox_handle(void *data, int vf_id)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct cn_core_set *core;
	int level_i, msg_i = 0;
	u32 entry_value;
	u32 mbx_level;
	u64 mbx_msg;

	if (!pcie_set) {
		cn_dev_info("pcie_set is null");
		return IRQ_HANDLED;
	}
	core = pcie_set->bus_set->core;

	if (!core) {
		cn_dev_pcie_info(pcie_set, "core set is null");
		return IRQ_HANDLED;
	}

	entry_value = cn_pci_reg_read32(pcie_set,
					VF2PF_MBXR_ENTRYL(vf_id));

	if (entry_value == MAILBOX_INIT_REG)
		commu_set_vf_init_flag(core, vf_id, 0);

	mbx_level = cn_pci_reg_read32(pcie_set,
					VF2PF_MBXR_STATUS(vf_id));
	cn_dev_pcie_debug(pcie_set, "mbx_level:0x%x", mbx_level);
	/* Mailbox Status Register [0] bit present mailbox_empty */
	if (unlikely(mbx_level & 0x1))
		return IRQ_HANDLED;
	/* Mailbox Status Register [10:8] bit present mailbox_level */
	mbx_level = (mbx_level & 0x700u) >> 8;
	if (unlikely(!mbx_level))
		return IRQ_HANDLED;

	/* TODO need protect msg_index*/
	msg_i = pcie_set->sriov[vf_id].msg_index;
	cn_dev_pcie_debug(pcie_set, "msg_index:%d", msg_i);

	for (level_i = 0; level_i < mbx_level; level_i++) {
		entry_value = cn_pci_reg_read32(pcie_set,
						VF2PF_MBXR_ENTRYL(vf_id));
		mbx_msg = entry_value;
		cn_dev_pcie_debug(pcie_set, "entry L:0x%x", entry_value);
		barrier();
		entry_value = cn_pci_reg_read32(pcie_set,
						VF2PF_MBXR_ENTRYH(vf_id));
		mbx_msg = (mbx_msg << 32) | entry_value;

		cn_dev_pcie_debug(pcie_set, "entry H:0x%x", entry_value);

		if (unlikely(!commu_get_vf_init_flag(core, vf_id) ||
		 ((entry_value & 0xFFFF0000ul) >> 16) == CMD_SRIOV_LATE_INIT)) {
			pcie_set->sriov[vf_id].mbx_msg[msg_i] = mbx_msg;
			msg_i++;
		}
	}

	if (pcie_set->sriov[vf_id].msg_index != msg_i)
		pcie_set->sriov[vf_id].msg_index = msg_i;

	cn_schedule_work(core, &pcie_set->sriov[vf_id].vf2pf_work);

	return IRQ_HANDLED;
}

static irqreturn_t c30s_pcie_pf_mailbox_handle(int index, void *data)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	int i, vf_id;
	unsigned long mbx_status, irq_mask;

	mbx_status = cn_pci_reg_read32(pcie_set,
					PCIE_IRQ_STATUS(PCIE_PF_MBX_IRQ));
	irq_mask = cn_pci_reg_read32(pcie_set, PCIE_IRQ_MASK(PCIE_PF_MBX_IRQ));
	mbx_status = mbx_status & (~irq_mask);

	if (mbx_status & 0x1fe) {
		for_each_set_bit(i, (unsigned long *)&mbx_status, 11)
			if (i > 0 && i < 9) {
				vf_id = i - 1;
				c30s_pcie_v2p_mailbox_handle((void *)pcie_set,
				vf_id);
			}

		return IRQ_HANDLED;
	} else
		return IRQ_NONE;

}

static int c30s_pcie_iov_virtfn_bus(struct cn_pcie_set *pcie_set,
					unsigned int vf_i)
{
	unsigned int vf_totalnums;
	int pos;
	u16 stride;
	u16 offset;

	vf_totalnums = pci_sriov_get_totalvfs(pcie_set->pdev);
	if (!pcie_set->pdev->is_physfn) {
		cn_dev_pcie_err(pcie_set, "dev is not a physical function");
		return -1;
	}

	if (vf_i >= vf_totalnums) {
		cn_dev_pcie_err(pcie_set,
			"vf_id %u is out of range of total vf nums %u",
			vf_i, vf_totalnums);
		return -1;
	}

	pos = pci_find_ext_capability(pcie_set->pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return -1;

	pci_read_config_word(pcie_set->pdev,
			pos + PCI_SRIOV_VF_OFFSET, &offset);
	pci_read_config_word(pcie_set->pdev,
			pos + PCI_SRIOV_VF_STRIDE, &stride);

	return pcie_set->pdev->bus->number +
		((pcie_set->pdev->devfn + offset + vf_i * stride) >> 8);
}

static int c30s_pcie_iov_virtfn_devfn(struct cn_pcie_set *pcie_set,
					unsigned int vf_i)
{
	unsigned int vf_totalnums;
	int pos;
	u16 stride;
	u16 offset;

	vf_totalnums = pci_sriov_get_totalvfs(pcie_set->pdev);
	if (!pcie_set->pdev->is_physfn) {
		cn_dev_pcie_err(pcie_set, "dev is not a physical function");
		return -1;
	}

	if (vf_i >= vf_totalnums) {
		cn_dev_pcie_err(pcie_set,
			"vf_id %u is out of range of total vf nums %u",
			vf_i, vf_totalnums);
		return -1;
	}

	pos = pci_find_ext_capability(pcie_set->pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return -1;

	pci_read_config_word(pcie_set->pdev,
			pos + PCI_SRIOV_VF_OFFSET, &offset);
	pci_read_config_word(pcie_set->pdev,
			pos + PCI_SRIOV_VF_STRIDE, &stride);
	return (pcie_set->pdev->devfn + offset + vf_i * stride) & 0xff;
}

static int c30s_pcie_assign_dmach(struct cn_pcie_set *pcie_set,
	unsigned int vf_id, unsigned int phy_channel, unsigned int virt_channel)
{
	int vf_num;

	vf_num = pcie_set->nums_vf;
	if (vf_id >= vf_num) {
		cn_dev_pcie_err(pcie_set, "vf_id out range of vf available");
		return -1;
	}

	if (phy_channel >= pcie_set->max_phy_channel) {
		cn_dev_pcie_err(pcie_set,
			"dma channel id out range of max dma channel num");
		return -1;
	}

	cn_pci_reg_write32(pcie_set, P2V_TABLE(phy_channel),
			((1 << 31) | vf_id));
	cn_pci_reg_write32(pcie_set, V2P_TABLE(vf_id, virt_channel),
		((1 << 31) | phy_channel));

	cn_pci_reg_read32(pcie_set, P2V_TABLE(phy_channel));
	cn_dev_pcie_info(pcie_set,
		"pdma channel %u assigned to vdma channel %u of vf%u",
			phy_channel, virt_channel, vf_id);

	return 0;
}

static int c30s_pcie_free_dmach(
		struct cn_pcie_set *pcie_set, unsigned int pdma_i)
{
	int vdma_i, vf_i;

	if (pdma_i >= DMA_REG_CHANNEL_NUM) {
		cn_dev_pcie_err(pcie_set,
			"dma channel id out range of max dma channel num");
		return -1;
	}

	cn_pci_reg_write32(pcie_set, P2V_TABLE(pdma_i), 0);

	for (vf_i = 0; vf_i < MAX_VF_COUNT; vf_i++)
		for (vdma_i = 0; vdma_i < MAX_VDMA_CHANNEL; vdma_i++)
			if ((cn_pci_reg_read32(pcie_set, V2P_TABLE(vf_i, vdma_i))
				& 0x7u) == pdma_i)
				cn_pci_reg_write32(pcie_set,
					V2P_TABLE(vf_i, vdma_i), 0);

	cn_pci_reg_read32(pcie_set, P2V_TABLE(pdma_i));
	return 0;
}

/* the dma channel release from vf and will pf get it */
static int c30s_pcie_ch_pf2vf(struct cn_pci_sriov *sriov)
{
	struct cn_pcie_set *pcie_set = sriov->pcie_set;
	int vf = sriov->vf_id;
	int vdma_i;
	int pdma_i;
	char src[20];
	int irq_num;

	sprintf(src, "pcie_dma0");
	irq_num = pcie_get_irq(src, pcie_set);

	cn_dev_pcie_info(pcie_set, "DMA channel from PF to VF mask:%x",
		sriov->vf_dma_phy_channel_mask);

	vdma_i = 0;
	for (pdma_i = 0; pdma_i < pcie_set->max_phy_channel; pdma_i++) {
		if (!(sriov->vf_dma_phy_channel_mask & (1<<pdma_i)))
			continue;

		if (c30s_pcie_assign_dmach(pcie_set, vf, pdma_i, vdma_i))
			return -1;

		pcie_gic_mask(irq_num + pdma_i, pcie_set);
		vdma_i++;
	}

	cn_dev_pcie_info(pcie_set, "VF%d DMA channel:%x", vf, sriov->vf_dma_phy_channel_mask);
	cn_dev_pcie_info(pcie_set, "PF DMA channel:%x", pcie_set->dma_phy_channel_mask);

	return 0;
}

/* the dma channel release from vf and will pf get it */
static int c30s_pcie_ch_vf2pf(struct cn_pcie_set *pcie_set, u32 channel_mask)
{
	int i;
	int vf;
	char src[20];
	int irq_num;

	sprintf(src, "pcie_dma0");
	irq_num = pcie_get_irq(src, pcie_set);

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (!(channel_mask & (1 << i)))
			continue;

		/* put_dma_channel */
		c30s_pcie_free_dmach(pcie_set, i);
		pcie_gic_unmask(irq_num + i, pcie_set);

		for (vf = 0; vf < pcie_set->nums_vf; vf++) {
			if (pcie_set->sriov[vf].vf_dma_phy_channel_mask
								& (1 << i)) {
				pcie_set->sriov[vf].vf_dma_phy_channel_mask
								&= (~(1 << i));
				cn_dev_pcie_err(pcie_set,
					"vf%d DMA channel:%d to PF\n", vf, i);
			}
		}
	}

	cn_dev_pcie_info(pcie_set, "PF DMA channel mask:%x", pcie_set->dma_phy_channel_mask);
	for (vf = 0; vf < pcie_set->nums_vf; vf++) {
		cn_dev_pcie_info(pcie_set, "VF%d DMA channel mask:%x", vf,
			pcie_set->sriov[vf].vf_dma_phy_channel_mask);
	}

	return 0;
}

#ifdef CONFIG_PCI_IOV
static void c30s_set_vf_bar0_win(struct cn_pci_sriov *sriov, int vf_id)
{
	struct cn_pcie_set *pcie_set;
	const void *domain;
	u64 vfs_total_bar0_sz, per_vf_bar0_sz, dev_va, offset, size;
	int total_vfs;
	u32 mask;

	pcie_set = sriov->pcie_set;
	domain = sriov->domain;
	total_vfs = pci_sriov_get_totalvfs(pcie_set->pdev);
	vfs_total_bar0_sz = pci_resource_len(pcie_set->pdev, PCI_IOV_RESOURCES);

	if (total_vfs)
		per_vf_bar0_sz = vfs_total_bar0_sz / total_vfs;
	else {
		cn_dev_pcie_info(pcie_set, "total vf num is zero");
		return;
	}

	dev_va = cn_bus_get_device_addr(pcie_set->bus_set, 0);
	offset = cn_dm_pci_get_bars_shm_bs(domain, 0);
	dev_va += offset;
	size = cn_dm_pci_get_bars_shm_sz(domain, 0);
	mask = (~(size - 1)) >> 20 & 0xFFFFFFFu;
	cn_dev_pcie_info(pcie_set, "vf%d inbound dev_va:%llx, size:%llx.", vf_id, dev_va, size);

	cn_pci_reg_write32(pcie_set,
		VF_BAR0_WIN0_SRC(vf_id), 0x80000u);
	cn_pci_reg_write32(pcie_set,
		VF_BAR0_WIN0_MASK(vf_id), 0xFFFFFFF);
	cn_pci_reg_write32(pcie_set,
		VF_BAR0_WIN0_TGT(vf_id), 0x80000u);

	cn_pci_reg_write32(pcie_set,
		VF_BAR0_WIN1_SRC(vf_id), 0x80000u + ((per_vf_bar0_sz / 2) >> 20)
						+ (offset >> 20));
	cn_pci_reg_write32(pcie_set,
		VF_BAR0_WIN1_MASK(vf_id), mask);
	/*TODO: from domain get this value */
	cn_pci_reg_write32(pcie_set,
		VF_BAR0_WIN1_TGT(vf_id), dev_va >> 20);
	/* config domain id of vf */
	cn_pci_reg_write32(pcie_set,
		VF_DOMAIN_ID(vf_id), vf_id + 1);
	cn_pci_reg_read32(pcie_set,
		VF_BAR0_WIN1_TGT(vf_id));
}
#endif

static int c30s_sriov_vf_init_hw(struct cn_pci_sriov *sriov)
{
	const void *domain;
	int vf;
	unsigned int reg_value;

	domain = sriov->domain;
	if (!domain) {
		cn_dev_pcie_err(sriov->pcie_set, "domain NULL");
		return -1;
	}

	vf = cn_dm_get_vf_func_id(domain);
	if (vf < 0 || vf >= sriov->pcie_set->nums_vf) {
		cn_dev_pcie_err(sriov->pcie_set, "vf index error vf:%d nums_vf:%d",
			vf, sriov->pcie_set->nums_vf);
	}

	/* enable vf interrupt */
	pcie_gic_unmask(PCIE_PF_MBX_IRQ, sriov->pcie_set);
	pcie_gic_unmask(PCIE_VF_MBX_IRQ(vf), sriov->pcie_set);
	reg_value = cn_pci_reg_read32(sriov->pcie_set, PCIE_IRQ_MASK(11));
	reg_value &= ~(1 << (vf + 1));
	cn_pci_reg_write32(sriov->pcie_set, PCIE_IRQ_MASK(11), reg_value);
	reg_value = cn_pci_reg_read32(sriov->pcie_set, PCIE_IRQ_MASK(11));
	#ifdef CONFIG_PCI_IOV
	c30s_set_vf_bar0_win(sriov, vf);
	#endif

	cn_dev_pcie_info(sriov->pcie_set, "PCIE_IRQ_MASK:0x%x,vf%d pre init success", reg_value, vf);

	return 0;
}

static int c30s_sriov_pre_init(struct cn_pci_sriov *sriov)
{
	INIT_WORK(&sriov->vf2pf_work, c30s_pcie_vf_work);

	if (c30s_sriov_vf_init_hw(sriov))
		return -1;

	return 0;
}

static int c30s_sriov_later_exit(struct cn_pci_sriov *sriov)
{
	//unsigned long flags;
	unsigned int reg_value;
/*
	cn_pci_unregister_interrupt(PCIE_PF_MBX_IRQ, sriov->pcie_set);
	pcie_gic_mask(PCIE_PF_MBX_IRQ, sriov->pcie_set);
*/
	reg_value = cn_pci_reg_read32(sriov->pcie_set, PCIE_IRQ_MASK(11));
	reg_value |= (1 << (sriov->vf_id + 1));
	cn_pci_reg_write32(sriov->pcie_set, PCIE_IRQ_MASK(11), reg_value);
	return 0;
}

static int c30s_sriov_vf_init(struct cn_pci_sriov *sriov)
{
	const void *domain = sriov->domain;
	struct cn_pcie_set *pcie_set = sriov->pcie_set;
	int vf;

	vf = cn_dm_get_vf_func_id(domain);
	sriov->vf_dma_phy_channel_mask = cn_dm_pci_get_dma_ch(domain);
	pcie_set->dma_phy_channel_mask &= (~sriov->vf_dma_phy_channel_mask);

	if (c30s_pcie_ch_pf2vf(sriov)) {
		cn_dev_pcie_err(pcie_set, "vf%d fail", vf);
		return -1;
	}

	cn_dev_pcie_info(pcie_set, "vf:%d channel_mask:%x success",
		vf, sriov->vf_dma_phy_channel_mask);

	return 0;
}

static int c30s_sriov_vf_exit(struct cn_pci_sriov *sriov)
{
	struct cn_pcie_set *pcie_set = sriov->pcie_set;

	pcie_set->dma_phy_channel_mask |= sriov->vf_dma_phy_channel_mask;
	sriov->vf_dma_phy_channel_mask = 0;
	c30s_pcie_ch_vf2pf(pcie_set, pcie_set->dma_phy_channel_mask);

	cn_dev_pcie_info(pcie_set, "vf_mask:%x pf_mask:%x", sriov->vf_dma_phy_channel_mask,
			pcie_set->dma_phy_channel_mask);

	return 0;
}
