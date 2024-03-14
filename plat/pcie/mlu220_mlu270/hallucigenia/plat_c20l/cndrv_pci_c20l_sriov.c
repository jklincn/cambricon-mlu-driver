/************************************************************************
 *
 *  @file cndrv_pci_c20l_sriov.c
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
#include <linux/sched.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "../../pcie_dma.h"
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "./cndrv_pci_c20l.h"
#include "cndrv_domain.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "cndrv_mig.h"
#include "binn.h"
#include "cndrv_kwork.h"

#define VF_MSIX_VECTOR_ADDR_L(vf_i)	(GBO + 0x2000 + 0x2000 * vf_i)
#define VF_MSIX_VECTOR_ADDR_U(vf_i)	(GBO + 0x2004 + 0x2000 * vf_i)
#define VF_MSIX_VECTOR_DATA(vf_i)	(GBO + 0x2008 + 0x2000 * vf_i)
#define VF_MSIX_VECTOR_MASK(vf_i)	(GBO + 0x200c + 0x2000 * vf_i)

#define GIC_VF_MSI_ADDR_U(vf_i)		(GBO + 0x13000 + 0x14 * vf_i + 0x4)
#define GIC_VF_MSI_STATUS		(GBO + 0x120b4)

#define GIC_VF_MSIX_ADDR_U(vf_i)	(GBO + 0x1300c + 0x14 * vf_i)
#define GIC_VF_MSIX_ADDR_SIZE(vf_i)	(GBO + 0x13010 + 0x14 * vf_i)
#define GIC_VF_MSIX_STATUS		(GBO + 0x120d8)

#define VF_MSIX_VECTOR_TABLE(i)		(0x1010b4 + 0x1000 * i)
#define VF_MSIX_PENDING_TABLE(i)	(0x1010b8 + 0x1000 * i)

#define PDMA_CTRL(ch_i)			(SIDEBAND_BASE_ADDR + 0x100 + 0x4 * ch_i)
#define PCIE_VF_REMAP_REG(vf_i, ch_i)	(0x10d000 + 0x10 * vf_i + 0x4 * ch_i)

static u64 c20l_sriov_mig_get_size(void *priv, int vf);
static u64 c20l_sriov_mig_get_data(void *priv, int vf, void *buf, u64 size);
static u64 c20l_sriov_mig_put_data(void *priv, int vf, void *buf, u64 size);


static int get_vfid_by_irq_helper(int index)
{
	int ret;

	switch (index) {
		case PCIE_IRQ_VF0_2_PF:
			ret = 0;
			break;

		case PCIE_IRQ_VF1_2_PF:
			ret = 1;
			break;

		case PCIE_IRQ_VF2_2_PF:
			ret = 2;
			break;

		case PCIE_IRQ_VF3_2_PF:
			ret = 3;
			break;

		default:
			ret = 0;
			break;
	}

	return ret;
}

static u32 get_vf_mailbox_base_helper(int index) {
	u32 ret;

	switch (index) {
		case 0:
			ret = (GBO + 0x3000);
			break;

		case 1:
			ret = (GBO + 0x5000);
			break;

		case 2:
			ret = (GBO + 0x7000);
			break;

		case 3:
			ret = (GBO + 0x9000);
			break;

		default:
			ret = (GBO + 0x3000);
			break;
	}
	return ret;
}

static int c20l_pcie_iov_virtfn_bus(struct cn_pcie_set *pcie_set, unsigned int vf_i);
static int c20l_pcie_iov_virtfn_devfn(struct cn_pcie_set *pcie_set, unsigned int vf_i);

static int c20l_pcie_wait_vf(struct cn_pcie_set *pcie_set,
	unsigned long offset, u32 val)
{
	int i;
	int timeout = 1000;

	cn_pci_reg_write32(pcie_set, offset, val);

	for (i = 0; i < timeout; i++) {
		if (val != cn_pci_reg_read32(pcie_set, offset)) {
			break;
		}

		schedule();
		msleep(1);
	}

	if (i >= timeout) {
		return -1;
	}

	return 0;
}

static u64 c20l_pcie_ob_mask(struct cn_pcie_set *pcie_set, unsigned int vf_i)
{
	const void *domain;

	if (vf_i >= pcie_set->nums_vf) {
		cn_dev_pcie_err(pcie_set, "vf_i:%d error", vf_i);
		return 0;
	}

	domain = cn_dm_get_domain(pcie_set->bus_set->core, DM_FUNC_VF0 + vf_i);

	return (u64)cn_dm_pci_get_ob_mask(domain);
}

static u64 c20l_pcie_ob_axi(struct cn_pcie_set *pcie_set, unsigned int vf_i)
{
	int i;
	u64 iobase;
	u64 ob_mask;

	if (vf_i >= pcie_set->nums_vf) {
		cn_dev_pcie_err(pcie_set, "vf_i:%d error", vf_i);
		return 0;
	}

	iobase = pcie_set->ob_axi_addr + pcie_set->ob_total_size;
	for (i = 0; i < vf_i; i++) {
		ob_mask = c20l_pcie_ob_mask(pcie_set, i);
		iobase += (OUTBOUND_SIZE * hweight64(ob_mask));
	}

	return iobase;
}

static void c20l_pcie_vf_work(struct work_struct *work)
{
	struct cn_pci_sriov *sriov = (struct cn_pci_sriov *)container_of(
		work, struct cn_pci_sriov, vf2pf_work);
	struct cn_pcie_set *pcie_set = sriov->pcie_set;
	int vf_id = sriov->vf_id;
	u32 mailbox_base = get_vf_mailbox_base_helper(vf_id);
	u32 cmd;
	struct cn_core_set *core = pcie_set->bus_set->core;

	if (likely(commu_get_vf_init_flag(core, vf_id))) {
		commu_vf2pf_handler(core, vf_id);
		return;
	}

	cmd = cn_pci_reg_read32(pcie_set, mailbox_base + 4);
	cn_dev_pcie_info(pcie_set, "cmd %x %d", cmd, vf_id);

	switch (cmd) {
	case CMD_GET_INBOUND_INFO: {
		u32 base;
		u32 size;
		const void *domain = cn_dm_get_domain(core, DM_FUNC_VF0 + vf_id);

		base = cn_dm_pci_get_bars_shm_bs(domain, 0);
		size = cn_dm_pci_get_bars_shm_sz(domain, 0);

		cn_dev_pcie_info(pcie_set, "base %x  --size %x", base, size);

		if (c20l_pcie_wait_vf(pcie_set, mailbox_base + 4, base)) {
			return;
		}

		cn_pci_reg_write32(pcie_set, mailbox_base + 4, size);
		break;
		}

	case CMD_GET_OUTBOUND_INFO: {
		u64 mask;
		u32 size;
		u32 upper;
		u32 lower;
		u64 iobase;

		mask = c20l_pcie_ob_mask(pcie_set, vf_id);
		sriov->ob_mask = mask;
		size = hweight64(mask) * OUTBOUND_SIZE;
		iobase = c20l_pcie_ob_axi(pcie_set, vf_id);
		upper = iobase >> 32;
		lower = (u32)iobase;

		cn_dev_pcie_info(pcie_set, "outbound_mask:%x  --size %x %llx %x %x",
			(int)mask, (int)size, iobase, lower, upper);

		if (c20l_pcie_wait_vf(pcie_set, mailbox_base + 4, size)) {
			return;
		}

		if (c20l_pcie_wait_vf(pcie_set, mailbox_base + 4,
					OUTBOUND_SIZE)) {
			return;
		}

		if (c20l_pcie_wait_vf(pcie_set, mailbox_base + 4,
				upper)) {
			return;
		}
		cn_pci_reg_write32(pcie_set, mailbox_base + 4, lower);
		break;
		}

	case CMD_SET_OUTBOUND_INFO: {
		int i = 0;
		u64 mask;
		u32 size;
		u32 upper;
		u32 lower;
		u64 iobase;
		u64 pci_addr;
		u32 bus_num;
		u32 devfn;

		mask = c20l_pcie_ob_mask(pcie_set, vf_id);

		devfn = c20l_pcie_iov_virtfn_devfn(pcie_set, vf_id);
		bus_num = c20l_pcie_iov_virtfn_bus(pcie_set, vf_id);

		size = 0xa5a5a5a5;
		if (c20l_pcie_wait_vf(pcie_set, mailbox_base + 4, size)) {
			return;
		}
		size = cn_pci_reg_read32(pcie_set, mailbox_base + 4);

		iobase = c20l_pcie_ob_axi(pcie_set, vf_id);

		for_each_set_bit(i, (unsigned long *)&mask, sizeof(mask)*8) {
			upper = 0xa5a5a5a5;
			if (c20l_pcie_wait_vf(pcie_set, mailbox_base + 4, upper)) {
				return;
			}
			upper = cn_pci_reg_read32(pcie_set, mailbox_base + 4);

			lower = 0xa5a5a5a5;
			if (c20l_pcie_wait_vf(pcie_set, mailbox_base + 4, lower)) {
				return;
			}
			lower = cn_pci_reg_read32(pcie_set, mailbox_base + 4);

			pci_addr = (((u64)upper)<<32)|lower;

			/* outbound pci address */
			cn_pci_reg_write64(pcie_set, A2P_ADDR_REG_0(i),
				(pci_addr&(~0xffULL))|(__fls(size) - 1));

			/* mem region */
			cn_pci_reg_write32(pcie_set, OB_PCIE_DESC_REG_1(i),
				((devfn << 24) | (1 << 23) | 0x2));
			cn_pci_reg_write32(pcie_set, OB_PCIE_DESC_REG_2(i), bus_num);

			/* axi address */
			cn_pci_reg_write64(pcie_set, AXI_REGION_BASE_REG_0(i),
				iobase | (__fls(size) - 1));

			/* make sure the above registers have been writen */
			cn_dev_pcie_info(
				pcie_set,
				"vf:%d outbound:%d reg:0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x",
				vf_id, i,
				cn_pci_reg_read32(pcie_set, A2P_ADDR_REG_0(i)),
				cn_pci_reg_read32(pcie_set, A2P_ADDR_REG_1(i)),
				cn_pci_reg_read32(pcie_set, OB_PCIE_DESC_REG_1(i)),
				cn_pci_reg_read32(pcie_set, OB_PCIE_DESC_REG_2(i)),
				cn_pci_reg_read32(pcie_set, OB_PCIE_DESC_REG_3(i)),
				cn_pci_reg_read32(pcie_set, AXI_REGION_BASE_REG_0(i)),
				cn_pci_reg_read32(pcie_set, AXI_REGION_BASE_REG_1(i)));

			iobase += size;
		}
		cn_pci_reg_write32(pcie_set, mailbox_base + 4, 0xa5a5a5a5);
		break;
		}

	case CMD_GET_DMA_INFO: {
		int i;
		u32 channel_mask = 0;

		/* the vf dma channel is from 0 to N-1 */
		for (i = 0; i < pcie_set->max_phy_channel; i++) {
			if (pcie_set->sriov[vf_id].vf_dma_res.channel_mask&(1<<i)) {
				channel_mask = ((channel_mask << 1) | 1);
			}
		}

		cn_dev_pcie_info(pcie_set, "vf:%d channel_mask:%x %x",
			vf_id, pcie_set->sriov[vf_id].vf_dma_res.channel_mask, channel_mask);

		if (c20l_pcie_wait_vf(pcie_set, mailbox_base + 4, channel_mask)) {
			return;
		}

		cn_pci_reg_write32(pcie_set, mailbox_base + 4,
			pcie_set->sriov[vf_id].vf_dma_res.channel_mask);
		break;
		}

	case CMD_GET_BDF: {
		u32 devfn, bus_num;

		devfn = c20l_pcie_iov_virtfn_devfn(pcie_set, vf_id);
		bus_num = c20l_pcie_iov_virtfn_bus(pcie_set, vf_id);

		cn_pci_reg_write32(pcie_set, mailbox_base + 4, ((bus_num<<8)|devfn));
		cn_dev_pcie_info(pcie_set, "vf:%d CMD_GET_BDF bus_num:%x devfn:%x bdf:%x",
			vf_id, bus_num, devfn, ((bus_num<<8)|devfn));
		break;
		}

	case CMD_ALLOC_COMMU_CTRLQ: {
		u32 offset;

		if (c20l_pcie_wait_vf(pcie_set, mailbox_base + 4, 0x0)) {
			return;
		}
		offset = cn_pci_reg_read32(pcie_set,  mailbox_base + 4);

		commu_ctrlq_alloc(core, vf_id, pcie_set->pcibar[0].seg[1].virt + offset, 32);

		cn_pci_reg_write32(pcie_set, mailbox_base + 4, 0x0);

		cn_dev_pcie_info(pcie_set, "CMD_ALLOC_COMMU_CTRLQ virt:%px offset:%x",
			pcie_set->pcibar[0].seg[1].virt, (int)offset);

		commu_set_vf_init_flag(core, vf_id, 1);
		break;
		}

	case CMD_SRIOV_INIT: {
		cn_dm_init_domain_sriov_smart(core, vf_id + 1);
		cn_pci_reg_write32(pcie_set, mailbox_base + 4, 0x0);
		cn_dev_pcie_info(pcie_set, "VF:%d sriov init", vf_id);
		break;
		}

	case CMD_SRIOV_EXIT: {
		cn_dm_exit_domain_sriov_with_rpc(core, vf_id + 1);
		cn_pci_reg_write32(pcie_set, mailbox_base + 4, 0x0);
		cn_dev_pcie_info(pcie_set, "VF:%d sriov exit", vf_id);
		break;
		}

	default: {
		break;
		}
	}

	return;
}

static irqreturn_t c20l_pcie_vf_mailbox_handle(int index, void *data)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	int vf_id;
	u32 mailbox_base;
	u32 reg_val;
	struct cn_core_set *core = pcie_set->bus_set->core;

	vf_id = get_vfid_by_irq_helper(index);
	mailbox_base = get_vf_mailbox_base_helper(vf_id);

	/* FIXME use heartbeat to insteand it */
	reg_val = cn_pci_reg_read32(pcie_set, mailbox_base);
	if (reg_val == MAILBOX_INIT_REG) {
		commu_set_vf_init_flag(core, vf_id, 0);
	}

	cn_pci_reg_write32(pcie_set, mailbox_base , 0x0);
	cn_dev_pcie_info(pcie_set,
		"here we receive a mailbox message from vf %d", vf_id);

	cn_schedule_work(core, &pcie_set->sriov[vf_id].vf2pf_work);

	return IRQ_HANDLED;
}

static int c20l_pcie_iov_virtfn_bus(struct cn_pcie_set *pcie_set, unsigned int vf_i)
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
	if (!pos) {
		return -1;
	}

	pci_read_config_word(pcie_set->pdev,
			pos + PCI_SRIOV_VF_OFFSET, &offset);
	pci_read_config_word(pcie_set->pdev,
			pos + PCI_SRIOV_VF_STRIDE, &stride);

	return pcie_set->pdev->bus->number +
		((pcie_set->pdev->devfn + offset + vf_i * stride) >> 8);
}

static int c20l_pcie_iov_virtfn_devfn(struct cn_pcie_set *pcie_set, unsigned int vf_i)
{
	unsigned int vf_totalnums;
	int pos;
	u16 stride;
	u16 offset;

	vf_totalnums = pci_sriov_get_totalvfs(pcie_set->pdev);
	if (!pcie_set->pdev->is_physfn) {
		cn_dev_pcie_err(pcie_set, "dev is not a physical function");
		return -EINVAL;
	}

	if (vf_i >= vf_totalnums) {
		cn_dev_pcie_err(pcie_set,
			"vf_id %u is out of range of total vf nums %u",
			vf_i, vf_totalnums);
		return -EINVAL;
	}

	pos = pci_find_ext_capability(pcie_set->pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos) {
		return -EINVAL;
	}

	pci_read_config_word(pcie_set->pdev,
			pos + PCI_SRIOV_VF_OFFSET, &offset);
	pci_read_config_word(pcie_set->pdev,
			pos + PCI_SRIOV_VF_STRIDE, &stride);
	return (pcie_set->pdev->devfn + offset + vf_i * stride) & 0xff;
}

static void c20l_fill_vf_msix_ram(
		struct cn_pcie_set *pcie_set,
		unsigned int vf_i)
{
	cn_pci_reg_write32(pcie_set, VF_MSIX_VECTOR_ADDR_L(vf_i), 0xffffffff);
	cn_pci_reg_write32(pcie_set, VF_MSIX_VECTOR_ADDR_U(vf_i), 0xffffffff);
	cn_pci_reg_write32(pcie_set, VF_MSIX_VECTOR_DATA(vf_i), 0xffffffff);
	cn_pci_reg_write32(pcie_set, VF_MSIX_VECTOR_MASK(vf_i), 0xffffffff);
}

static int c20l_pcie_init_vf_interrupt(
		struct cn_pcie_set *pcie_set, unsigned int vf_i)
{
	unsigned int ob_win_i;
	int bus_num, devfn;
	u32 reg_val = 0;

	if (!pcie_set->sriov) {
		cn_dev_pcie_err(pcie_set, "pcie_set->sriov is null");
		return -EINVAL;
	}

	if (vf_i >= pcie_set->nums_vf) {
		cn_dev_pcie_err(pcie_set, "vf id %u is out of range of max vf nums %u",
			vf_i, pcie_set->nums_vf);
		return -EINVAL;
	}

	c20l_fill_vf_msix_ram(pcie_set, vf_i);

	/* config VF MSIx vector table and pending table base addr */
	cn_pci_reg_write32(pcie_set, VF_MSIX_VECTOR_TABLE(vf_i), 0);
	cn_pci_reg_write32(pcie_set, VF_MSIX_PENDING_TABLE(vf_i), 0x800);

	/* config msi/msix outbound region */

	devfn = c20l_pcie_iov_virtfn_devfn(pcie_set, vf_i);
	bus_num = c20l_pcie_iov_virtfn_bus(pcie_set, vf_i);

	if (devfn < 0 || bus_num < 0) {
		cn_dev_pcie_err(pcie_set,
				"get bus_num or devfn of VF failed");
		return -EINVAL;
	}

	ob_win_i = vf_i + 1;
	/*outbound address*/
	cn_pci_reg_write32(pcie_set, A2P_ADDR_REG_0(ob_win_i), 0x1f);
	cn_pci_reg_write32(pcie_set, A2P_ADDR_REG_1(ob_win_i), 0);
	/*mem region*/
	cn_pci_reg_write32(pcie_set, OB_PCIE_DESC_REG_1(ob_win_i),
		((devfn << 24) | (1 << 23) | 0x2));
	cn_pci_reg_write32(pcie_set, OB_PCIE_DESC_REG_2(ob_win_i), bus_num);
	cn_pci_reg_write32(pcie_set, AXI_REGION_BASE_REG_0(ob_win_i), 0x1f);
	cn_pci_reg_write32(pcie_set, AXI_REGION_BASE_REG_1(ob_win_i),
			(0x90 + vf_i));

	/* make sure the above registers have been writen */
	cn_dev_pcie_info(pcie_set,
		"vf%d msi win_%d reg:0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x",
		vf_i, ob_win_i,
		cn_pci_reg_read32(pcie_set, A2P_ADDR_REG_0(ob_win_i)),
		cn_pci_reg_read32(pcie_set, A2P_ADDR_REG_1(ob_win_i)),
		cn_pci_reg_read32(pcie_set, OB_PCIE_DESC_REG_1(ob_win_i)),
		cn_pci_reg_read32(pcie_set, OB_PCIE_DESC_REG_2(ob_win_i)),
		cn_pci_reg_read32(pcie_set, OB_PCIE_DESC_REG_3(ob_win_i)),
		cn_pci_reg_read32(pcie_set, AXI_REGION_BASE_REG_0(ob_win_i)),
		cn_pci_reg_read32(pcie_set, AXI_REGION_BASE_REG_1(ob_win_i)));

	if (pcie_set->irq_type == 0) {
		cn_pci_reg_write32(pcie_set, GIC_VF_MSI_ADDR_U(vf_i), 0x90 + vf_i);
		reg_val = cn_pci_reg_read32(pcie_set, GIC_VF_MSIX_STATUS);
		reg_val |= (1 << (vf_i + 24));
		cn_pci_reg_write32(pcie_set, GIC_VF_MSIX_STATUS, reg_val);
		cn_pci_reg_read32(pcie_set, GIC_VF_MSIX_STATUS);
	} else if (pcie_set->irq_type == 1) {
		cn_pci_reg_write32(pcie_set, GIC_VF_MSIX_ADDR_U(vf_i), 0x90 + vf_i);
		cn_pci_reg_write32(pcie_set, GIC_VF_MSIX_ADDR_SIZE(vf_i), (~0x0));
		reg_val = cn_pci_reg_read32(pcie_set, GIC_VF_MSIX_STATUS);
		reg_val |= (1 << (vf_i + 8));
		cn_pci_reg_write32(pcie_set, GIC_VF_MSIX_STATUS, reg_val);
		cn_pci_reg_read32(pcie_set, GIC_VF_MSIX_STATUS);
	}

	/* solve intx build error */
	reg_val = reg_val;

	return 0;
}

static int c20l_pcie_assign_dmach(struct cn_pcie_set *pcie_set,
	unsigned int vf_id, unsigned phy_channel, unsigned int virt_channel)
{
	int vf_num;
	int i;

	vf_num = pcie_set->nums_vf;
	if (vf_id >= vf_num) {
		cn_dev_pcie_err(pcie_set, "vf_id out range of vf available");
		return -EINVAL;
	}

	if (phy_channel >= pcie_set->max_phy_channel) {
		cn_dev_pcie_err(pcie_set,
			"dma channel id out range of max dma channel num");
		return -EINVAL;
	}

	cn_pci_reg_write32(pcie_set, PDMA_CTRL(phy_channel),
			((1 << 31) | vf_id));
	cn_pci_reg_write32(pcie_set, PCIE_VF_REMAP_REG(vf_id, virt_channel),
		((1 << 31) | phy_channel));

	for (i = virt_channel + 1; i < pcie_set->max_phy_channel; i++) {
		cn_pci_reg_write32(pcie_set, PCIE_VF_REMAP_REG(vf_id, i),
					phy_channel);
	}

	cn_pci_reg_read32(pcie_set, PDMA_CTRL(phy_channel));
	cn_dev_pcie_info(pcie_set,
		"pdma channel %u assigned to vdma channel %u of vf%u",
			phy_channel, virt_channel, vf_id);

	return 0;
}

static int c20l_pcie_free_dmach(
		struct cn_pcie_set *pcie_set, unsigned int pdma_i)
{
	if (pdma_i >= pcie_set->max_phy_channel) {
		cn_dev_pcie_err(pcie_set,
			"dma channel id out range of max dma channel num");
		return -1;
	}

	cn_pci_reg_write32(pcie_set, PDMA_CTRL(pdma_i), 0);
	cn_pci_reg_read32(pcie_set, PDMA_CTRL(pdma_i));

	return 0;
}

/* the dma channel release from vf and will pf get it */
static int c20l_pcie_ch_pf2vf(struct cn_pci_sriov *sriov)
{
	struct cn_pcie_set *pcie_set = sriov->pcie_set;
	const void *domain = sriov->domain;
	int vf;
	int vdma_i;
	int pdma_i;
	int ret;
	unsigned long flags;

	vf = cn_dm_get_vf_func_id(domain);
	cn_dev_pcie_info(pcie_set, "DMA channel from PF to VF mask:%x",
		sriov->vf_dma_res.channel_mask);

	vdma_i = 0;
	for (pdma_i = 0; pdma_i < pcie_set->max_phy_channel; pdma_i++) {
		if (!(sriov->vf_dma_res.channel_mask & (1<<pdma_i))) {
			continue;
		}

		ret = c20l_pcie_assign_dmach(pcie_set, vf, pdma_i, vdma_i);
		if (ret) {
			return ret;
		}

		spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
		pcie_gic_mask(PCIE_IRQ_DMA + pdma_i, pcie_set);
		spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);
		vdma_i++;
	}

	cn_dev_pcie_info(pcie_set, "VF%d DMA channel:%x", vf, sriov->vf_dma_res.channel_mask);
	cn_dev_pcie_info(pcie_set, "PF DMA channel:%x", pcie_set->dma_res.channel_mask);

	return 0;
}

/* the dma channel release from vf and will pf get it */
static int c20l_pcie_ch_vf2pf(struct cn_pcie_set *pcie_set, u32 channel_mask)
{
	int i;
	int vf;
	unsigned long flags;

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (!(channel_mask&(1<<i))) {
			continue;
		}

		/* put_dma_channel */
		c20l_pcie_free_dmach(pcie_set, i);
		spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
		pcie_gic_unmask(PCIE_IRQ_DMA + i, pcie_set);
		spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);

		for (vf = 0; vf < pcie_set->nums_vf; vf++) {
			if (pcie_set->sriov[vf].vf_dma_res.channel_mask&(1<<i)) {
				pcie_set->sriov[vf].vf_dma_res.channel_mask &= (~(1<<i));
				cn_dev_pcie_info(pcie_set, "vf%d DMA channel:%d to PF", vf, i);
			}
		}
	}

	cn_dev_pcie_info(pcie_set, "PF DMA channel mask:%x", pcie_set->dma_res.channel_mask);
	for (vf = 0; vf < pcie_set->nums_vf; vf++) {
		cn_dev_pcie_info(pcie_set, "VF%d DMA channel mask:%x", vf,
			pcie_set->sriov[vf].vf_dma_res.channel_mask);
	}

	return 0;
}

static int c20l_sriov_vf_init_hw(struct cn_pci_sriov *sriov)
{
	const void *domain;
	int vf;
	int ret;
	unsigned long flags;

	if (!sriov) {
		cn_dev_err("sriov NULL");
		return -EINVAL;
	}

	domain = sriov->domain;
	if (!domain) {
		cn_dev_err("domain NULL");
		return -EINVAL;
	}

	vf = cn_dm_get_vf_func_id(domain);
	if (vf < 0 || vf >= sriov->pcie_set->nums_vf) {
		cn_dev_err("vf index error vf:%d nums_vf:%d",
			vf, sriov->pcie_set->nums_vf);
	}

	ret = c20l_pcie_init_vf_interrupt(sriov->pcie_set, vf);
	if (ret) {
		cn_dev_err("init vf%u interrupt failed", vf);
		return ret;
	}

	/* enable vf interrupt */
	spin_lock_irqsave(&sriov->pcie_set->interrupt_lock, flags);
	pcie_gic_unmask(PCIE_IRQ_VF0_2_PF + vf, sriov->pcie_set);
	spin_unlock_irqrestore(&sriov->pcie_set->interrupt_lock, flags);

	cn_dev_pcie_info(sriov->pcie_set, "vf%d pre init success", vf);

	return 0;
}

static int c20l_sriov_pre_init(struct cn_pci_sriov *sriov)
{
	const void *domain = sriov->domain;
	int vf;

	vf = cn_dm_get_vf_func_id(domain);
	mig_reg_host_cb(sriov->pcie_set->bus_set->core,
		MIG_HOST_PCIE, sriov,
		c20l_sriov_mig_get_size, c20l_sriov_mig_get_data,
		c20l_sriov_mig_put_data);

	cn_pci_register_interrupt(PCIE_IRQ_VF0_2_PF + vf,
		c20l_pcie_vf_mailbox_handle, sriov->pcie_set, sriov->pcie_set);

	INIT_WORK(&sriov->vf2pf_work, c20l_pcie_vf_work);

	return c20l_sriov_vf_init_hw(sriov);
}

static int c20l_sriov_later_exit(struct cn_pci_sriov *sriov)
{
	const void *domain = sriov->domain;
	unsigned long flags;
	int vf;

	if (!domain)
	       return 0;

	vf = cn_dm_get_vf_func_id(domain);
	cn_pci_unregister_interrupt(PCIE_IRQ_VF0_2_PF + vf, sriov->pcie_set);
	spin_lock_irqsave(&sriov->pcie_set->interrupt_lock, flags);
	pcie_gic_mask(PCIE_IRQ_VF0_2_PF + vf, sriov->pcie_set);
	spin_unlock_irqrestore(&sriov->pcie_set->interrupt_lock, flags);

	return 0;
}

static int c20l_sriov_vf_init(struct cn_pci_sriov *sriov)
{
	const void *domain = sriov->domain;
	struct cn_pcie_set *pcie_set = sriov->pcie_set;
	int ret, vf;

	vf = cn_dm_get_vf_func_id(domain);
	sriov->vf_dma_res.channel_mask = cn_dm_pci_get_dma_ch(domain);
	pcie_set->dma_res.channel_mask &= (~sriov->vf_dma_res.channel_mask);
	pcie_set->max_inbound_cnt = hweight32(pcie_set->dma_res.channel_mask) * 2;

	ret = c20l_pcie_ch_pf2vf(sriov);
	if (ret) {
		cn_dev_err("vf%d fail", vf);
		return ret;
	}

	cn_dev_pcie_info(pcie_set, "vf:%d vf_mask:%x pf_mask:%x success",
		vf, sriov->vf_dma_res.channel_mask, pcie_set->dma_res.channel_mask);

	return 0;
}

static int c20l_sriov_vf_exit(struct cn_pci_sriov *sriov)
{
	struct cn_pcie_set *pcie_set = sriov->pcie_set;

	pcie_set->dma_res.channel_mask |= sriov->vf_dma_res.channel_mask;
	pcie_set->max_inbound_cnt = hweight32(pcie_set->dma_res.channel_mask) * 2;
	sriov->vf_dma_res.channel_mask = 0;
	c20l_pcie_ch_vf2pf(pcie_set, pcie_set->dma_res.channel_mask);

	cn_dev_pcie_info(pcie_set, "vf_mask:%x pf_mask:%x", sriov->vf_dma_res.channel_mask,
		pcie_set->dma_res.channel_mask);

	return 0;
}

struct c20l_mig_reg_s {
	u32 addr;
	u32 val;
};

static u64 c20l_sriov_mig_get_size(void *priv, int vf)
{
	struct cn_pci_sriov *sriov = (struct cn_pci_sriov *)priv;
	u64 ob_mask = sriov->ob_mask;
	struct c20l_mig_reg_s *reg;
	int reg_cnt;
	int reg_index = 0;
	int i;
	int j;
	struct binn *mig_binn;
	struct cn_pcie_set *pcie_set = sriov->pcie_set;
	struct cn_core_set *core = pcie_set->bus_set->core;

	/* payload_config:1 gic:2 bar2/bar4:4 outbound */
	reg_cnt = 1 + 2 + 4 + hweight64(ob_mask) * REGION_REGISTER_SIZE / 4;
	reg = cn_kcalloc(reg_cnt, sizeof(struct c20l_mig_reg_s), GFP_KERNEL);

	/* PCIe max payload config */
	reg[reg_index++].addr = 0x101000 + 0x1000 * vf + 0xc8;

	/* gic mask */
	reg[reg_index++].addr = GBO + 0x2000 * (vf + 1) + 0x180c;
	reg[reg_index++].addr = GBO + 0x2000 * (vf + 1) + 0x1810;

	/* bar2/bar4 base */
	for (i = 0 ; i < 2; i++) {
		reg[reg_index].addr = 0x10a000 + 0x890 + vf * 0x40 + i * 0x10;
		reg_index++;
		reg[reg_index].addr = reg[reg_index - 1].addr + 4;
		reg_index++;
	}

	/* outbound */
	cn_dev_pcie_info(sriov->pcie_set, "ob_mask:%llx", ob_mask);
	for_each_set_bit(i, (unsigned long *)&ob_mask, sizeof(ob_mask)*8) {
		for (j = 0; j < REGION_REGISTER_SIZE / 4; j++) {
			reg[reg_index].addr = A2P_ADDR_REG_0(i) + j * 4;
			reg_index++;
		}
	}

	for (i = 0; i < reg_cnt; i++) {
		reg[i].val = cn_pci_reg_read32(sriov->pcie_set, reg[i].addr);
	}

	mig_binn = binn_object();

	binn_object_set_uint64(mig_binn, "ob_mask", ob_mask);
	binn_object_set_int32(mig_binn, "PCIeRegCnt", reg_cnt);
	binn_object_set_blob(mig_binn, "Regs", (void *)reg,
		reg_cnt * sizeof(struct c20l_mig_reg_s));
	/* commu ctrlq */
	binn_object_set_uint64(mig_binn, "ctrlq_offset",
			commu_get_vf_ctrlq_base(core, vf) -
			(u64)pcie_set->pcibar[0].seg[1].virt);
	binn_object_set_uint32(mig_binn, "head",
			commu_get_vf_ctrlq_head(core, vf));
	binn_object_set_uint32(mig_binn, "tail",
			commu_get_vf_ctrlq_tail(core, vf));
	sriov->mig_bin = (void *)mig_binn;

	cn_kfree(reg);

	return binn_size(mig_binn);
}

static u64 c20l_sriov_mig_get_data(void *priv, int vf, void *buf, u64 size)
{
	struct cn_pci_sriov *sriov = (struct cn_pci_sriov *)priv;
	struct binn *mig_binn = sriov->mig_bin;

	size = min_t(u64, size, binn_size(mig_binn));

	memcpy(buf, binn_ptr(mig_binn), size);
	binn_free(mig_binn);
	sriov->mig_bin = NULL;

	return size;
}

static int c20l_sriov_mig_ob_reg(void *priv, int vf, struct c20l_mig_reg_s reg)
{
	struct cn_pci_sriov *sriov = (struct cn_pci_sriov *)priv;
	u32 bus_num;
	u32 devfn;
	int ret = 0;

	if (reg.addr < A2P_ADDR_REG_0(0) || reg.addr >= A2P_ADDR_REG_0(32)) {
		return -1;
	}

	devfn = c20l_pcie_iov_virtfn_devfn(sriov->pcie_set, vf);
	bus_num = c20l_pcie_iov_virtfn_bus(sriov->pcie_set, vf);

	switch ((reg.addr - A2P_ADDR_REG_0(0)) % REGION_REGISTER_SIZE) {
	case 0x08:
		cn_pci_reg_write32(sriov->pcie_set, (ulong)reg.addr,
			((devfn << 24) | (1 << 23) | 0x2));
		break;

	case 0x0c:
		cn_pci_reg_write32(sriov->pcie_set, (ulong)reg.addr, bus_num);
		break;

	default:
		cn_pci_reg_write32(sriov->pcie_set, (ulong)reg.addr, reg.val);
		break;
	}

	return ret;
}

static u64 c20l_sriov_mig_put_data(void *priv, int vf, void *buf, u64 size)
{
	struct cn_pci_sriov *sriov = (struct cn_pci_sriov *)priv;
	int reg_cnt;
	int reg_size;
	struct c20l_mig_reg_s *reg;
	struct binn *mig_bin = buf;
	int i;
	u64 ctrlq_base;
	struct cn_pcie_set *pcie_set = sriov->pcie_set;
	struct cn_core_set *core = pcie_set->bus_set->core;

	cn_dev_pcie_info(sriov->pcie_set, "size:0x%llx", size);

	if (!binn_object_get_uint64(mig_bin, "ob_mask", &sriov->ob_mask)) {
		cn_dev_pcie_err(sriov->pcie_set, "Error");
	}

	if (!binn_object_get_int32(mig_bin, "PCIeRegCnt", &reg_cnt)) {
		cn_dev_pcie_err(sriov->pcie_set, "Error");
	}
	cn_dev_pcie_info(sriov->pcie_set, "PCIeRegCnt:%d", reg_cnt);

	if (!binn_object_get_blob(mig_bin, "Regs", (void **)&reg, &reg_size)) {
		cn_dev_pcie_err(sriov->pcie_set, "Error");
	}
	cn_dev_pcie_info(sriov->pcie_set, "reg_size:%d", reg_size);

	for (i = 0; i < reg_cnt; i++) {
		if (c20l_sriov_mig_ob_reg(sriov, vf, reg[i])) {
			cn_pci_reg_write32(sriov->pcie_set, (ulong)reg[i].addr, reg[i].val);
		}
	}
	ctrlq_base = binn_object_uint64(mig_bin, "ctrlq_offset") +
			(u64)pcie_set->pcibar[0].seg[1].virt;

	cn_dev_pcie_info(sriov->pcie_set, "rebuild ctrlq ring addr %llx %d\n",
			binn_object_uint64(mig_bin, "ctrlq_offset"),
			vf);
	commu_restore_vf_ctrlq(core, vf, ctrlq_base,
		binn_object_uint32(mig_bin, "head"),
		binn_object_uint32(mig_bin, "tail"),
		32);

	return size;
}
