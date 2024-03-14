/************************************************************************
 *
 *  @file cndrv_pci_c50_atomicop.c
 *
 *  @brief This file is designed to support sriov functions.
 * ######################################################################
 *
 * Copyright (c) 2022 Cambricon, Inc. All rights reserved.
 *
 **************************************************************************/

/*************************************************************************
 * Software License Agreement:
 * -----------------------------------------------------------------------
 * Copyright (C) [2022] by Cambricon, Inc.
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
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "./cndrv_pci_c50.h"
#include "cndrv_debug.h"

/* set this cnt if need */
#define PCIE_ATOMICOP_DESC_CNT          64
#define PCIE_ATOMICOP_DESC_CMD_SIZE	64

#define SBTS_ATOMICOP_CFG_LEN_OFFSET  16
#define SBTS_ATOMICOP_LEN_MASK        ((1 << SBTS_ATOMICOP_CFG_LEN_OFFSET) - 1)
#define SBTS_ATOMICOP_USE_SRAM_BIT    (1 << SBTS_ATOMICOP_CFG_LEN_OFFSET)

#ifndef PCI_EXP_DEVCTL2_ATOMIC_REQ
#define PCI_EXP_DEVCTL2_ATOMIC_REQ              (0x40)
#endif

#ifndef PCI_EXP_DEVCAP2_ATOMIC_COMP32
#define PCI_EXP_DEVCAP2_ATOMIC_COMP32           (0x80)
#endif
#ifndef PCI_EXP_DEVCAP2_ATOMIC_COMP64
#define PCI_EXP_DEVCAP2_ATOMIC_COMP64           (0x100)
#endif
#ifndef PCI_EXP_DEVCAP2_ATOMIC_COMP128
#define PCI_EXP_DEVCAP2_ATOMIC_COMP128          (0x200)
#endif
#ifndef PCI_EXP_DEVCAP2_ATOMIC_ROUTE
#define PCI_EXP_DEVCAP2_ATOMIC_ROUTE            (0x40)
#endif
#ifndef PCI_EXP_DEVCTL2_ATOMIC_EGRESS_BLOCK
#define PCI_EXP_DEVCTL2_ATOMIC_EGRESS_BLOCK     (0x80)
#endif

static inline void __pcie_hw_atomicop_set_info(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, ATOMIC_PAGE_BASE_ADDR_L,
			LOWER32(pcie_set->atom_set.atomicop_dev_va));
	cn_pci_reg_write32(pcie_set, ATOMIC_PAGE_BASE_ADDR_H,
			UPPER32(pcie_set->atom_set.atomicop_dev_va));
	cn_pci_reg_write32(pcie_set, ATOMIC_QUEUE_DEPTH_PREG,
			pcie_set->atom_set.atomicop_desc_cnt);
	cn_pci_reg_write32(pcie_set, ATOMIC_AXI_PARAM_PREG, 0);
}

/* check hw head and tail value not bigger than CMD_SIZE
 * if so, we cant use the hw module.
 * */
static int __pcie_hw_len_check(struct cn_pcie_set *pcie_set)
{
	u32 tail, head;

	head = cn_pci_reg_read32(pcie_set, ATOMIC_QUEUE_HEAD_PREG);
	tail = cn_pci_reg_read32(pcie_set, ATOMIC_QUEUE_TAIL_PREG);

	if ((head >= PCIE_ATOMICOP_DESC_CNT) ||
			(tail >= PCIE_ATOMICOP_DESC_CNT)) {
		cn_dev_pcie_err(pcie_set, "hw current head %u tail %u is too big",
				head, tail);
		return -EFAULT;
	}

	return 0;
}

/* in 20ms */
#define PCIE_ATOMICOP_HW_IDLE_TIMEOUT  50
static void __pcie_hw_atomicop_idle_check(struct cn_pcie_set *pcie_set)
{
	u32 sta, head, tail;
	int timeout = PCIE_ATOMICOP_HW_IDLE_TIMEOUT;

	do {
		head = cn_pci_reg_read32(pcie_set, ATOMIC_QUEUE_HEAD_PREG);
		tail = cn_pci_reg_read32(pcie_set, ATOMIC_QUEUE_TAIL_PREG);
		sta = cn_pci_reg_read32(pcie_set, ATOMIC_STATE_DEBUG_PREG);
		if ((head == tail) && (sta == 0)) {
			cn_dev_pcie_debug(pcie_set, "wait hw idle success");
			return;
		}
		timeout--;
		msleep(20);
	} while (timeout);

	cn_dev_pcie_err(pcie_set, "wait pcie hw atomicop idle timeout %u %u %u",
			head, tail, sta);
}

__attribute__((unused))
static int cn_pci_enable_atomic_ops_to_root(
		struct pci_dev *dev, u32 cap_mask)
{
	struct pci_bus *bus = dev->bus;
	struct pci_dev *bridge;
	u32 cap, ctl2;

	if (!pci_is_pcie(dev))
		return -EINVAL;

	/*
	 * Per PCIe r4.0, sec 6.15, endpoints and root ports may be
	 * AtomicOp requesters.  For now, we only support endpoints as
	 * requesters and root ports as completers.  No endpoints as
	 * completers, and no peer-to-peer.
	 */

	switch (pci_pcie_type(dev)) {
	case PCI_EXP_TYPE_ENDPOINT:
	case PCI_EXP_TYPE_LEG_END:
	case PCI_EXP_TYPE_RC_END:
		break;
	default:
		return -EINVAL;
	}

	while (bus->parent) {
		bridge = bus->self;

		pcie_capability_read_dword(bridge, PCI_EXP_DEVCAP2, &cap);

		switch (pci_pcie_type(bridge)) {
		/* Ensure switch ports support AtomicOp routing */
		case PCI_EXP_TYPE_UPSTREAM:
		case PCI_EXP_TYPE_DOWNSTREAM:
			if (!(cap & PCI_EXP_DEVCAP2_ATOMIC_ROUTE))
				return -EINVAL;
			break;

		/* Ensure root port supports all the sizes we care about */
		case PCI_EXP_TYPE_ROOT_PORT:
			if ((cap & cap_mask) != cap_mask)
				return -EINVAL;
			break;
		}

		/* Ensure upstream ports don't block AtomicOps on egress */
		if (pci_pcie_type(bridge) == PCI_EXP_TYPE_UPSTREAM) {
			pcie_capability_read_dword(bridge, PCI_EXP_DEVCTL2,
						   &ctl2);
			if (ctl2 & PCI_EXP_DEVCTL2_ATOMIC_EGRESS_BLOCK)
				return -EINVAL;
		}

		bus = bus->parent;
	}

	return 0;
}

static void c50_pci_check_atomicop(struct cn_pcie_set *pcie_set)
{
	int ret;

	if (!pcie_set->cfg.atomicop_support) {
		cn_dev_pcie_info(pcie_set, "Pcie AtomicOp Not support");
		return;
	}

	/* only need support 64bit op */
	ret = cn_pci_enable_atomic_ops_to_root(pcie_set->pdev,
			PCI_EXP_DEVCAP2_ATOMIC_COMP64);
	if (ret) {
		pcie_set->cfg.atomicop_support = 0;
		cn_dev_pcie_info(pcie_set, "Pcie AtomicOp Not support");
	} else {
		pcie_set->cfg.atomicop_support = 1;
		cn_dev_pcie_info(pcie_set, "Pcie AtomicOp support");
	}
}

static void c50_pcie_hw_atomicop_init(struct cn_pcie_set *pcie_set)
{
	struct cn_core_set *core = pcie_set->bus_set->core;
	u32 desc_cnt = PCIE_ATOMICOP_DESC_CNT;
	u32 alloc_size = desc_cnt * PCIE_ATOMICOP_DESC_CMD_SIZE;
	u64 sram_size = 0;

	/* clear first */
	pcie_set->atom_set.atomicop_host_va = 0;
	pcie_set->atom_set.atomicop_dev_va  = 0;
	pcie_set->atom_set.atomicop_desc_cnt = 0;

	c50_pci_check_atomicop(pcie_set);

	/* not support in vf mode */
	if (cn_core_is_vf(core)) {
		pcie_set->cfg.atomicop_support = 0;
		return;
	}

	if (!pcie_set->cfg.pcie_sram_able) {
		pcie_set->cfg.atomicop_support = 0;
		goto fill_reg;
	}

	/* if hw not support clear the reg info */
	if (!pcie_set->cfg.atomicop_support)
		goto fill_reg;

	/* if len check fail, clear support and reg info */
	if (__pcie_hw_len_check(pcie_set)) {
		pcie_set->cfg.atomicop_support = 0;
		goto fill_reg;
	}

	sram_size = cn_shm_get_size_by_name(core, "sram_reserved_AOP");
	if (sram_size < alloc_size) {
		cn_dev_pcie_err(pcie_set, "reserved sram size %#llx too small!", sram_size);
		pcie_set->cfg.atomicop_support = 0;
		goto fill_reg;
	}

	pcie_set->atom_set.atomicop_host_va =
			cn_shm_get_host_addr_by_name(core, "sram_reserved_AOP");
	pcie_set->atom_set.atomicop_dev_va =
			cn_shm_get_dev_addr_by_name(core, "sram_reserved_AOP");
	if (!pcie_set->atom_set.atomicop_host_va || !pcie_set->atom_set.atomicop_dev_va) {
		cn_dev_pcie_err(pcie_set, "reserved sram addr %#llx %#llx invalid!",
				pcie_set->atom_set.atomicop_host_va, pcie_set->atom_set.atomicop_dev_va);
		pcie_set->atom_set.atomicop_host_va = 0;
		pcie_set->atom_set.atomicop_dev_va = 0;
		pcie_set->atom_set.atomicop_desc_cnt = 0;
		goto fill_reg;
	}
	pcie_set->atom_set.atomicop_desc_cnt = desc_cnt;
	memset_io((void *)pcie_set->atom_set.atomicop_host_va, 0, alloc_size);

fill_reg:
	__pcie_hw_atomicop_idle_check(pcie_set);

	__pcie_hw_atomicop_set_info(pcie_set);

	cn_dev_pcie_debug(pcie_set, "set hw desc with %#llx %#llx %x",
			pcie_set->atom_set.atomicop_host_va, pcie_set->atom_set.atomicop_dev_va,
			pcie_set->atom_set.atomicop_desc_cnt);

	pcie_capability_set_word(pcie_set->pdev, PCI_EXP_DEVCTL2,
			PCI_EXP_DEVCTL2_ATOMIC_REQ);
}

static void c50_pcie_hw_atomicop_exit(struct cn_pcie_set *pcie_set)
{

	if (!pcie_set->atom_set.atomicop_host_va)
		return;

	__pcie_hw_atomicop_idle_check(pcie_set);

	cn_pci_reg_write32(pcie_set, ATOMIC_QUEUE_DEPTH_PREG, 0);
	cn_pci_reg_write32(pcie_set, ATOMIC_PAGE_BASE_ADDR_L, 0);
	cn_pci_reg_write32(pcie_set, ATOMIC_PAGE_BASE_ADDR_H, 0);

	pcie_set->atom_set.atomicop_host_va = 0;
	pcie_set->atom_set.atomicop_dev_va = 0;
	pcie_set->atom_set.atomicop_desc_cnt = 0;
}
