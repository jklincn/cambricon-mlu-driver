// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cambricon's Remote Processor Control Driver
 *
 * Copyright (C) 2020 Cambricon - All Rights Reserved
 *
 */

#include <linux/clk.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include "../include/remoteproc/remoteproc.h"
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/printk.h>
#include <linux/kthread.h>
#include <linux/utsname.h>
#if (KERNEL_VERSION(4, 11, 0) > LINUX_VERSION_CODE)
#include <linux/signal.h>
#else
#include <linux/sched/signal.h>
#endif

#include "remoteproc_internal.h"

#define MAX_VF_NUM                      (8)
#define COMMU_MBOX_MSG                  (0x1)

/*
 * notes:
 * IN_CNDRV_HOST && RPMSG_MASTER_PCIE_RC  --> M.2 rpmsg master
 * IN_CNDRV_HOST && !RPMSG_MASTER_PCIE_RC --> EDGE/D2D rpmsg master
 * !IN_CNDRV_HOST                         --> rpmsg slave
 *
 * simply
 *
 * #if defined(RPMSG_MASTER_PCIE_RC)  --> M.2 rpmsg master
 *
 * #elif defined(IN_CNDRV_HOST)       --> EDGE/D2D rpmsg master

 * #else                              --> rpmsg slave
 *
 * #endif
 */

#ifdef IN_CNDRV_HOST
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_ipcm.h"
#include "cndrv_mm.h"
#ifndef IPCM_COMMU_SHARED_IRQ
#include "cndrv_commu.h"
#endif
#include "cndrv_kwork.h"
#else
#include "../cambr_ipcm.h"
#endif

#ifndef RPMSG_MASTER_PCIE_RC
#include <linux/iopoll.h>
#include <linux/of_reserved_mem.h>
#include <linux/soc/cambricon/irqs.h>

/*
 * vf_id = 0 pf
 * vf_id > 0 vf
 */

/* pf's global rproc can be get by core, so we only extrally maintenance vf's rproc */
static struct rproc *cn_rproc[MAX_VF_NUM + 1] __maybe_unused = {0};
#endif

#if defined(RPMSG_MASTER_PCIE_RC)
struct cambr_rproc_mem {
	/*const */char *name;
	/* host view va */
	host_addr_t cpu_addr;
	/* device addr, inbound ? iova : ob_axi_addr */
	u64 da;
	size_t size;
};
#endif

struct cambr_board_info {
	unsigned long long pci_gic_base;
	/* pf offset */
	unsigned long pci_gic_mbox_offset;
	/* for interrupt info */
	unsigned long long pci_mbox_status_base;
	unsigned long pci_mbox_status_offset;
	unsigned long pci_vf_mbox_offset;
	/* arm only */
	int xxx2arm_irq;
	/* host only */
	int xxx2host_irq;//both xxx2pf & xxx2vf
	/* inbound */
	unsigned long inbound_vf_offset;
	unsigned long inbound_vf_quota;
	/* outbound */
	unsigned long outbound_base;
	unsigned long outbound_pf_offset;
	unsigned long outbound_vf_offset;
	unsigned long outbound_vf_quota;
	unsigned long data_outbound_base;
	/* will be update by cn_bus_outbound_able() */
	bool enable_outbound;
	/* currently, just pf only support data OB */
	bool enable_data_outbound;
	int quirks;
	int max_vf_num;
};

struct cambr_interrupt {
	#if defined(RPMSG_MASTER_PCIE_RC)
	unsigned long trigger_irq;
	unsigned long clear_irq;
	unsigned long irq_status;
	unsigned long unmask_irq;
	#elif defined(IN_CNDRV_HOST) /* edge/d2d master*/
	//TODO
	#else/* slave */
	unsigned int __iomem *trigger_irq;
	unsigned int __iomem *clear_irq;
	unsigned int __iomem *irq_status;
	unsigned int __iomem *unmask_irq;
	#endif
};

#define HW_MAILBOX_QUEUE_SIZE (4)

struct cambr_rproc {
	struct platform_device *pdev;
	/* 0 master; 1 slave; 2 MCU; 3 Die1*/
	int role;
	struct delayed_work work;
	struct workqueue_struct *wq;
	struct rproc *rproc;
	spinlock_t mailbox_lock;
	#ifdef IN_CNDRV_HOST
	void *core_set;
	#ifdef RPMSG_MASTER_PCIE_RC
	struct cambr_rproc_mem *meminfo;
	#endif
	#else
	int vf_id;
	#endif
	#ifdef IPCM_POLLING_MODE
	struct task_struct *poll_worker0;
	struct task_struct *poll_worker1;
	int exit_flag;
	#endif
	struct cambr_board_info *boardinfo;
	struct cambr_interrupt intr;
	volatile unsigned int mbx_idx;
	volatile int in_que_mbx[HW_MAILBOX_QUEUE_SIZE];
};

struct cambr_board_info cambr_board_c30s = {
	.pci_gic_base = 0x8000060000,
	.pci_gic_mbox_offset = 0x800,
	.pci_mbox_status_base = 0x8000020000,
	.pci_mbox_status_offset = 0x222c,
	.pci_vf_mbox_offset = 0x1000,//pcie_vf sheet
	/* vf from 64M  +16M per vf */
	.inbound_vf_offset = 0x4000000UL,
	.inbound_vf_quota = 0x1000000UL,
	.outbound_base = 0x8004000000UL,
	/* pf 0-16M */
	.outbound_pf_offset = 0UL,
	/* vf from 16M  +2M per vf */
	.outbound_vf_offset = 0x1000000UL,
	.outbound_vf_quota = 0x200000UL,
	.enable_data_outbound = false,
	.data_outbound_base = 0xb00000000UL,
	.quirks = QUIRK_AVOID_VF_READ_INBOUND | QUIRK_SRIOV_NO_SUPPORT_DATA_OUTBOUND
				| QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND,
	.max_vf_num = 4,
};

struct cambr_board_info cambr_board_c50 = {
	.pci_gic_base = 0x8000002000,
	.pci_gic_mbox_offset = 0x800,
	.pci_mbox_status_base = 0x8000028000,
	.pci_mbox_status_offset = 0x2248,
	.pci_vf_mbox_offset = 0x1000,//pcie_vf sheet
	/* vf from 64M  +16M per vf */
	.inbound_vf_offset = 0x2000000UL,
	.inbound_vf_quota = 0x1000000UL,
	.outbound_base = 0xc078800000UL,
	/* pf 0-16M */
	.outbound_pf_offset = 0UL,
	/* vf from 16M  +16M per vf */
	.outbound_vf_offset = 0x1000000UL,
	.outbound_vf_quota = 0x1000000UL,
	.enable_data_outbound = false,
	.data_outbound_base = 0xc080062000UL,
	.quirks = QUIRK_SRIOV_NO_SUPPORT_DATA_OUTBOUND
				| QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND,
	.max_vf_num = 6,
};

struct cambr_board_info cambr_board_c20 = {
	.pci_gic_base = 0x8000140000,
	.pci_gic_mbox_offset = 0x406c,
	.pci_mbox_status_base = 0x8000120000,
	.pci_mbox_status_offset = 0x30,
	/* vf from 64M  +16M per vf */
	.inbound_vf_offset = 0x4000000UL,
	.inbound_vf_quota = 0x1000000UL,
	.outbound_base = 0x8006000000UL,
	/* pf 2-16M */
	.outbound_pf_offset = 0x200000UL,
	/* vf from 16M  +2M per vf */
	.outbound_vf_offset = 0x1000000UL,
	.outbound_vf_quota = 0x200000UL,
	.enable_data_outbound = false,
};

struct cambr_board_info cambr_board_c20l = {
	.pci_gic_base = 0x8000140000,
	.pci_gic_mbox_offset = 0x120a4,
	.pci_mbox_status_base = 0,
	.pci_mbox_status_offset = 0,
	.enable_data_outbound = false,
};

struct cambr_board_info cambr_board_c20e = {
	.pci_gic_base = 0x8000b10000,
	.pci_gic_mbox_offset = 0xa0a4,
	.pci_mbox_status_base = 0,
	.pci_mbox_status_offset = 0,
	.enable_data_outbound = false,
};

#define NO_RESOURCE_ENTRIES         1

/* Resource table for the given remote */
struct remote_resource_table {
	unsigned int version;
	unsigned int num;
	unsigned int reserved[2];
	unsigned int offset[NO_RESOURCE_ENTRIES];
	/*
	 * in openAMP header is in struct fw_rsc_vdev,
	 * but the total size/layout of struct remote_resource_table is the same
	 */
	struct fw_rsc_hdr rpmsg_hdr;
	/* rpmsg vdev entry */
	struct fw_rsc_vdev rpmsg_vdev;
	struct fw_rsc_vdev_vring rpmsg_vring0;
	struct fw_rsc_vdev_vring rpmsg_vring1;
} __attribute__((__packed__));
//}__attribute__((packed, aligned(0x100000)));

#define VDEV_RING_SIZE             0x10000
#define VDEV_BUFF_SIZE             0x80000
#define RSC_TABLE_SIZE             0x100

#define IPCM_OUTBOUND_ABLE_MAGIC   0xccaabbcc
#define IPCM_DATA_OUTBOUND_ABLE_MAGIC   0xccaabbdd

/* VirtIO rpmsg device id */
#define VIRTIO_ID_RPMSG_             7

/* Remote supports Name Service announcement */
#define VIRTIO_RPMSG_F_NS           0
#define VIRTIO_RPMSG_F_AS           1

/* VIRTIO_RPMSG_F_NS | VIRTIO_RPMSG_F_AS */
#define RPMSG_IPU_C0_FEATURES        0x3

/* Resource table entries */
#define NUM_VRINGS                  0x02
#define VRING_ALIGN                 0x1000
#define RING_TX                     FW_RSC_ADDR_ANY
#define RING_RX                     FW_RSC_ADDR_ANY
#define VRING_SIZE                  256

#define VDEV_SINGLE_BUFF_SIZE (MAX_RPMSG_BUF_SIZE * VRING_SIZE)

#define NUM_TABLE_ENTRIES           1

struct remote_resource_table resources = {
	/* Version */
	1,

	/* NUmber of table entries */
	NUM_TABLE_ENTRIES,
	/* reserved fields */
	{0, 0,},

	/* Offsets of rsc entries */
	{
	 offsetof(struct remote_resource_table, rpmsg_hdr),//rpmsg_vdev
	},

	/* hdr */
	{RSC_VDEV,},

	/* Virtio device entry */
	{
	 VIRTIO_ID_RPMSG_, 0, RPMSG_IPU_C0_FEATURES, 0, 0, 0,
	 NUM_VRINGS, {0, 0},
	},

	/* Vring rsc entry - part of vdev rsc entry */
	{RING_TX, VRING_ALIGN, VRING_SIZE, 1, 0},
	{RING_RX, VRING_ALIGN, VRING_SIZE, 2, 0},
};

static bool cambr_rproc_is_vf(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;
	#ifdef IN_CNDRV_HOST
	struct cn_core_set *core = ddata->core_set;

	return cn_core_is_vf(core);
	#else
	return (ddata->vf_id != 0);
	#endif
}

static int cambr_rproc_init_board_info(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;
	struct device *dev = rproc->dev.parent;
	#ifdef IN_CNDRV_HOST
	struct cn_core_set *core = ddata->core_set;

	switch (core->device_id) {
	case MLUID_370:
	case MLUID_370V:
	case MLUID_365:
		ddata->boardinfo = &cambr_board_c30s;
		ddata->boardinfo->xxx2arm_irq = 12;//unuse
		if (!cambr_rproc_is_vf(rproc))
			ddata->boardinfo->xxx2host_irq = 11;
		else {
			/* update for vf, foreach vf's view both are 9, pf's view 13/14/15/16 */
			ddata->boardinfo->xxx2host_irq = cn_bus_get_irq_by_desc(core->bus_set, "a2v_mbx");
		}
		break;
	case MLUID_580:
	case MLUID_580V:
	case MLUID_590:
	case MLUID_590V:
		ddata->boardinfo = &cambr_board_c50;
		ddata->boardinfo->xxx2arm_irq = 19;//unuse
		if (!cambr_rproc_is_vf(rproc))
			ddata->boardinfo->xxx2host_irq = 18;
		else {
			/* update for vf, foreach vf's view both are 2, pf's view 20/21/22/23 */
			ddata->boardinfo->xxx2host_irq = cn_bus_get_irq_by_desc(core->bus_set, "a2v_mbx");
		}
		break;
	case MLUID_290:
		ddata->boardinfo = &cambr_board_c20;
		ddata->boardinfo->xxx2arm_irq = 36;//unuse
		ddata->boardinfo->xxx2host_irq = 34;
		break;
	case MLUID_220_EDGE:
	case MLUID_220:
		ddata->boardinfo = &cambr_board_c20e;
		ddata->boardinfo->xxx2arm_irq = 158;//unuse
		ddata->boardinfo->xxx2host_irq = 163;
		break;
	case MLUID_270:
		ddata->boardinfo = &cambr_board_c20l;
		ddata->boardinfo->xxx2arm_irq = 24;//unuse
		ddata->boardinfo->xxx2host_irq = 25;
		break;
	default:
		dev_warn(dev, "%s, ipcm_arm driver: unknown platform:0x%llx\n", __func__, core->device_id);
		/* FIXME */
		ddata->boardinfo = &cambr_board_c30s;
		break;
	}
	/* sync to arm by rsc_table */
	ddata->boardinfo->enable_outbound = (cn_bus_outbound_able(core->bus_set) != 0);

	if (!ddata->boardinfo->enable_outbound)
		ddata->boardinfo->enable_data_outbound = false;
	//else
	//	ddata->boardinfo->enable_data_outbound = false;//(cn_bus_data_outbound_able(core->bus_set) != 0);//phase out data_outbound_able

	dev_info(dev, "%s, enable_outbound:%d data_outbound:%d\n",
		__func__, ddata->boardinfo->enable_outbound, ddata->boardinfo->enable_data_outbound);
	#else
	#if defined(CONFIG_CAMBR_SOC_C30S)
	ddata->boardinfo = &cambr_board_c30s;
	ddata->boardinfo->xxx2arm_irq = CPUGIC__PCIE_XX_TO_ARM_IRQ;
	ddata->boardinfo->xxx2host_irq = CPUGIC__PCIE_XX_TO_PF_IRQ;//unuse
	#elif defined(CONFIG_CAMBR_SOC_C50) || defined(CONFIG_CAMBR_SOC_C50S)
	ddata->boardinfo = &cambr_board_c50;
	ddata->boardinfo->xxx2arm_irq = CPUGIC__PCIE_XX_TO_ARM_IRQ;
	ddata->boardinfo->xxx2host_irq = CPUGIC__PCIE_XX_TO_PF_IRQ;//unuse
	#elif defined(CONFIG_CAMBR_SOC_C20)
	ddata->boardinfo = &cambr_board_c20;
	ddata->boardinfo->xxx2arm_irq = CPUGIC__PCIE_HOST_TO_ARM_IRQ;
	ddata->boardinfo->xxx2host_irq = CPUGIC__PCIE_ARM_TO_HOST_IRQ;//unuse
	#elif defined(CONFIG_CAMBR_SOC_C20E)
	ddata->boardinfo = &cambr_board_c20e;
	ddata->boardinfo->xxx2arm_irq = CPUGIC__PCIE_HOST_TO_ARM_IRQ;
	//ddata->boardinfo->xxx2host_irq = CPUGIC__PCIE_ARM_TO_HOST_IRQ;//unuse
	#elif defined(CONFIG_CAMBR_SOC_C20L)
	ddata->boardinfo = &cambr_board_c20l;
	ddata->boardinfo->xxx2arm_irq = CPUGIC__PCIE_HOST_TO_ARM_IRQ;
	ddata->boardinfo->xxx2host_irq = CPUGIC__PCIE_ARM_TO_HOST_IRQ;//unuse
	#else
	dev_warn(dev, "%s, ipcm_arm driver: unknown platform\n", __func__);
	/* FIXME */
	//ddata->boardinfo = &cambr_board_c20l;
	//ddata->boardinfo->xxx2arm_irq = CPUGIC__PCIE_HOST_TO_ARM_IRQ;
	//ddata->boardinfo->xxx2host_irq = CPUGIC__PCIE_ARM_TO_HOST_IRQ;//unuse
	#endif

	dev_info(dev, "%s, ipcm_arm driver: xxx2arm_irq(%d) xxx2host_irq(%d)\n",
		__func__, ddata->boardinfo->xxx2arm_irq, ddata->boardinfo->xxx2host_irq);
	#endif

	return 0;
}

static int cambr_rproc_get_role(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;

	return ddata->role;
}

static bool cambr_rproc_get_outbound(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;

	return ddata->boardinfo->enable_outbound;
}

static bool cambr_rproc_get_data_outbound(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;

	return ddata->boardinfo->enable_data_outbound;
}

static int cambr_rproc_get_rvdev_index(struct rproc *rproc)
{
	#ifndef IN_CNDRV_HOST
	struct cambr_rproc *ddata = rproc->priv;

	return ddata->vf_id;
	#else
	return  0;
	#endif
}

static int cambr_rproc_check_msg(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;
	struct device *dev = rproc->dev.parent;
	unsigned int msg = 0;
	#if defined(RPMSG_MASTER_PCIE_RC)
	struct cn_core_set *core = ddata->core_set;

	switch (core->device_id) {
	case MLUID_370:
	case MLUID_370V:
	case MLUID_365:
	case MLUID_580:
	case MLUID_580V:
	case MLUID_590:
	case MLUID_590V:
		msg = reg_read32(core->bus_set, ddata->intr.clear_irq + 0x4);
		break;
	case MLUID_270:
	case MLUID_290:
		msg = reg_read32(core->bus_set, ddata->intr.clear_irq);
		break;
	default:
		return -EINVAL;
	}

	dev_dbg(dev, "msg:0x%x\n", msg);
	if ((msg & 0xcabd) != 0xcabd)
		return -EINVAL;
	#elif defined(IN_CNDRV_HOST)
	(void)rproc;
	(void)ddata;
	(void)dev;
	(void)msg;
	#else /* arm */
	#if defined(CONFIG_CAMBR_SOC_C30S) || defined(CONFIG_CAMBR_SOC_C50) || defined(CONFIG_CAMBR_SOC_C50S)
	msg = readl(ddata->intr.clear_irq + 0x1);
	#else
	msg = readl(ddata->intr.clear_irq);
	#endif
	dev_dbg(dev, "msg:0x%x\n", msg);
	if ((msg & 0xcabd) != 0xcabd)
		return -EINVAL;
	#endif /* RPMSG_MASTER_PCIE_RC */
	return (msg >> 16);
}

static int cambr_rproc_check_irq_src(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;
	struct device *dev = rproc->dev.parent;
	unsigned int reg_val = 0, irq_mask;
	#if defined(RPMSG_MASTER_PCIE_RC)
	struct cn_core_set *core = ddata->core_set;

	/* some platforms do not need check interrupt source */
	switch (core->device_id) {
	case MLUID_370:
	case MLUID_370V:
	case MLUID_365:
	case MLUID_580:
	case MLUID_580V:
	case MLUID_590:
	case MLUID_590V:
		if (!cambr_rproc_is_vf(rproc)) {
			reg_val = reg_read32(core->bus_set, ddata->intr.irq_status);
			irq_mask = reg_read32(core->bus_set, ddata->intr.unmask_irq);
			reg_val &= (~irq_mask);
			dev_dbg(dev, "xxx_to_host irq reg: 0x%x, irq_mask:0x%x\n", reg_val, irq_mask);
			/* arm2pf */
			if (!(reg_val & BIT(0)))
				return -EINVAL;
		} else {
			reg_val = reg_read32(core->bus_set, ddata->intr.irq_status);
			dev_dbg(dev, "xxx_to_host irq reg: 0x%x\n", reg_val);
			/* arm2vf */
			if (!(reg_val & BIT(1)))
				return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
	#elif defined(IN_CNDRV_HOST)
	(void)rproc;
	(void)ddata;
	(void)dev;
	(void)reg_val;
	(void)irq_mask;
	#else /* arm */
	/* some platforms do not need check interrupt source */
	#if defined(CONFIG_CAMBR_SOC_C30S) || defined(CONFIG_CAMBR_SOC_C50) || defined(CONFIG_CAMBR_SOC_C50S)
	reg_val = readl(ddata->intr.irq_status);
	irq_mask = readl(ddata->intr.unmask_irq);
	reg_val &= (~irq_mask);
	dev_dbg(dev, "xxx_to_arm irq reg: 0x%x, irq_mask:0x%x\n", reg_val, irq_mask);
	if (!(reg_val & BIT(ddata->vf_id)))
		return -EINVAL;
	#else
	if (ddata->intr.irq_status) {
		(void)irq_mask;
		/* read sideband reg12 pcie_to_arm_mailbox_status reg */
		reg_val = readl(ddata->intr.irq_status);
		dev_dbg(dev, "pcie_to_arm_mailbox_status reg: %x\n", reg_val);
		if (!(reg_val & BIT(8))) {
			return -EINVAL;
		}
	}
	#endif /* CONFIG_CAMBR_SOC_C30S || CONFIG_CAMBR_SOC_C50 || CONFIG_CAMBR_SOC_C50S*/
	#endif /* RPMSG_MASTER_PCIE_RC */
	return 0;
}

/* check without lock is ok */
static int __maybe_unused cambr_rproc_check_irq(struct rproc *rproc)
{
	int ret = 0;

	ret = cambr_rproc_check_irq_src(rproc);
	if (ret < 0)
		return -EINVAL;
	return cambr_rproc_check_msg(rproc);
}

static void __maybe_unused c30s_interrupt_clear(struct rproc *rproc, bool clear_all, bool remote)
{
	struct cambr_rproc *ddata = rproc->priv;
	struct device *dev = rproc->dev.parent;
	int intr_cnt;
	unsigned int reg_val = 0;
	#if defined(RPMSG_MASTER_PCIE_RC)
	struct cn_core_set *core = ddata->core_set;
	unsigned long clear_irq = ddata->intr.clear_irq;

	if (remote)
		clear_irq = ddata->intr.trigger_irq + 0x10;//0x60810
	intr_cnt = reg_read32(core->bus_set, clear_irq);
	dev_dbg(dev, "intr_cnt:%#x\n", intr_cnt);
	/*[0] must is 0,1 indicate empty*/
	if (unlikely(intr_cnt & 0x1))
		return;

	intr_cnt = (intr_cnt >> 8) & 0xf;
	/*intr count should not equal 0*/
	WARN_ON(!intr_cnt);
	if (unlikely(!intr_cnt))
		return;

	do {
		/*mailbox spec ask developer to read low ,then read high.*/
		reg_val = reg_read32(core->bus_set,
								clear_irq + 0x4);
		dev_dbg(dev, "entry l reg:%lx val:%#x\n",
								clear_irq + 0x4,
								reg_val);
		rmb();/* make sure read order */
		reg_val = reg_read32(core->bus_set,
								clear_irq + 0x8);
		dev_dbg(dev, "entry h reg:%lx val:%#x\n",
								clear_irq + 0x8,
							reg_val);
		intr_cnt -= 1;
	} while (clear_all && intr_cnt > 0);
	#elif defined(IN_CNDRV_HOST)
	//TODO
	(void)rproc;
	(void)ddata;
	(void)dev;
	(void)intr_cnt;
	(void)reg_val;
	#else
	unsigned int __iomem *clear_irq = ddata->intr.clear_irq;

	if (remote)
		clear_irq = ddata->intr.trigger_irq + 4;
	intr_cnt = readl(clear_irq);
	dev_dbg(dev, "intr_cnt:%#x", intr_cnt);
	/*[0] must is 0,1 indicate empty*/
	if (unlikely(intr_cnt & 0x1))
		return;

	intr_cnt = (intr_cnt >> 8) & 0xf;
	/*intr count should not equal 0*/
	WARN_ON(!intr_cnt);
	if (unlikely(!intr_cnt))
		return;

	do {
		/*mailbox spec ask developer to read low ,then read high.*/
		reg_val = readl(clear_irq + 0x1);
		dev_dbg(dev, "entry l addr:%px val:%#x\n",
						clear_irq + 0x1,
						reg_val);
		rmb();/* make sure read order */
		reg_val = readl(clear_irq + 0x2);
		dev_dbg(dev, "entry h reg:%px val:%#x\n",
						clear_irq + 0x2,
					reg_val);
		intr_cnt -= 1;
	} while (clear_all && intr_cnt > 0);
	#endif
}

static void __maybe_unused c200s_interrupt_clear(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;
	#if defined(RPMSG_MASTER_PCIE_RC)
	struct cn_core_set *core = ddata->core_set;

	reg_write32(core->bus_set, ddata->intr.clear_irq, 0x0);
	#elif defined(IN_CNDRV_HOST)
	//TODO
	(void)rproc;
	(void)ddata;
	#else
	writel(0x0, ddata->intr.clear_irq);
	#endif
}

/* clear without lock is ok */
static void cambr_rproc_clear_irq(struct rproc *rproc, bool clear_all, bool remote)
{
	#if defined(RPMSG_MASTER_PCIE_RC)
	struct cambr_rproc *ddata = rproc->priv;
	struct cn_core_set *core = ddata->core_set;

	switch (core->device_id) {
	case MLUID_370:
	case MLUID_370V:
	case MLUID_365:
	case MLUID_580:
	case MLUID_580V:
	case MLUID_590:
	case MLUID_590V:
		c30s_interrupt_clear(rproc, clear_all, remote);
		break;
	case MLUID_270:
	case MLUID_290:
		c200s_interrupt_clear(rproc);
		break;
	default:
		break;
	}
	#elif defined(IN_CNDRV_HOST)
	//TODO
	#else
	#if defined(CONFIG_CAMBR_SOC_C30S) || defined(CONFIG_CAMBR_SOC_C50) || defined(CONFIG_CAMBR_SOC_C50S)
	c30s_interrupt_clear(rproc, clear_all, remote);
	#else
	c200s_interrupt_clear(rproc);
	#endif
	#endif
}

#ifdef IN_CNDRV_HOST
void *cambr_rproc_get_virtio_device(void *core)
{
	struct cn_core_set *_core = core;
	struct rproc *rproc;

	if (!_core)
		return NULL;

	rproc = _core->reset_flag ? NULL : _core->ipcm_set;

	return rproc ? rproc->vdev : NULL;
}

struct cn_core_set *cambr_dev_to_core(struct device *dev)
{
	struct rproc *rproc = rproc_get_by_child(dev);
	struct cambr_rproc *ddata;

	if (!rproc) {
		dev_err(dev, "%s not child of rproc\n", __func__);
		return NULL;
	}
	ddata = rproc->priv;

	return ddata->core_set;
}

void cambr_rproc_dev_bus_mb(struct device *dev)
{
	struct cn_core_set *core = cambr_dev_to_core(dev);

	if (unlikely(!core)) {
		dev_err(dev, "%s core is NULL\n", __func__);
		return;
	}
	cn_bus_mb(core->bus_set);
}

#ifndef IPCM_COMMU_SHARED_IRQ
static irqreturn_t cn_commu_host_mbox_handler(struct cn_core_set *core)
{
	#ifndef COMMU_HOST_POLL
	cn_commu_mailbox_handler(core);
	#endif
	return IRQ_HANDLED;
}
#endif

static irqreturn_t __maybe_unused cambr_rproc_isr(int irq, void *p)
{
	struct rproc *rproc = (struct rproc *)p;
	struct device *dev = rproc->dev.parent;
	int vq_id;
	struct cambr_rproc *ddata = rproc->priv;
	unsigned long flags;

	dev_dbg(dev, "%s irq[%d]", __func__, irq);

	#ifdef IPCM_COMMU_SHARED_IRQ
	spin_lock_irqsave(&ddata->mailbox_lock, flags);
	/* check if we got the right irq cause we use SHARED_IRQ with VF2arm VF2PF*/
	vq_id = cambr_rproc_check_irq(rproc);
	if (vq_id < 0) {
		spin_unlock_irqrestore(&ddata->mailbox_lock, flags);
		return IRQ_NONE;
	}

	/* clear irq */
	cambr_rproc_clear_irq(rproc, false, false);
	spin_unlock_irqrestore(&ddata->mailbox_lock, flags);

	#ifdef CALLBACK_IN_INTR_CONTEXT
	rproc_vq_interrupt(rproc, vq_id);
	#else
	if (vq_id == 0)
		mod_delayed_work(ddata->wq, &ddata->work, 0);
	else
		rproc_vq_interrupt(rproc, vq_id);
	#endif /* CALLBACK_IN_INTR_CONTEXT */

	return IRQ_HANDLED;
	#else /* !IPCM_COMMU_SHARED_IRQ */
	spin_lock_irqsave(&ddata->mailbox_lock, flags);
	/* check if we got the right irq cause we use SHARED_IRQ with arm2PF VF2PF*/
	vq_id = cambr_rproc_check_irq_src(rproc);
	if (vq_id < 0) {
		spin_unlock_irqrestore(&ddata->mailbox_lock, flags);
		return IRQ_NONE;
	}
	/* clear irq */
	cambr_rproc_clear_irq(rproc, false, false);
	spin_unlock_irqrestore(&ddata->mailbox_lock, flags);
	#ifdef CALLBACK_IN_INTR_CONTEXT
	rproc_vq_interrupt(rproc, 1);
	rproc_vq_interrupt(rproc, 0);
	#else /* !CALLBACK_IN_INTR_CONTEXT */
	rproc_vq_interrupt(rproc, 1);
	mod_delayed_work(ddata->wq, &ddata->work, 0);
	#endif /* CALLBACK_IN_INTR_CONTEXT */
	/* always call commu isr */
	return cn_commu_host_mbox_handler(ddata->core_set);
	#endif /* IPCM_COMMU_SHARED_IRQ */
}
#else
void *cambr_rproc_get_vhost_device(int vf_id)
{
	struct rproc *rproc;

	rproc = vf_id <= MAX_VF_NUM ? cn_rproc[vf_id] : NULL;

	return rproc ? rproc->vdev : NULL;
}

static irqreturn_t __maybe_unused cambr_rproc_isr(int irq, void *p)
{
	int vf_id;
	unsigned int irq_handle_cnt = 0;
	struct rproc *rproc = NULL;
	struct device *dev;
	int vq_id;
	struct cambr_rproc *ddata;
	unsigned long flags;

	for (vf_id = 0; vf_id < ARRAY_SIZE(cn_rproc); vf_id++) {
		rproc = cn_rproc[vf_id];

		/* avoid access vring in outbound while vf not start */
		if (!rproc || !rproc->vdev || !rproc->vdev->vf_start)
			continue;

		dev = rproc->dev.parent;
		ddata = rproc->priv;

		dev_dbg(dev, "%s irq[%d]", __func__, irq);

		#ifdef IPCM_COMMU_SHARED_IRQ
		spin_lock_irqsave(&ddata->mailbox_lock, flags);
		/* check if we got the right irq cause we use SHARED_IRQ with VF2arm VF2PF*/
		vq_id = cambr_rproc_check_irq(rproc);
		if (vq_id < 0) {
			spin_unlock_irqrestore(&ddata->mailbox_lock, flags);
			continue;
		}

		/* clear irq */
		cambr_rproc_clear_irq(rproc, false, false);
		spin_unlock_irqrestore(&ddata->mailbox_lock, flags);

		/* Process incoming buffers on all our vrings */
		#ifdef CALLBACK_IN_INTR_CONTEXT
		rproc_vq_interrupt(rproc, vq_id);
		#else /* !CALLBACK_IN_INTR_CONTEXT */
		if (vq_id == 1)
			mod_delayed_work(ddata->wq, &ddata->work, 0);
		else
			rproc_vq_interrupt(rproc, vq_id);
		#endif /* CALLBACK_IN_INTR_CONTEXT */

		irq_handle_cnt++;
		#else /* !IPCM_COMMU_SHARED_IRQ */
		spin_lock_irqsave(&ddata->mailbox_lock, flags);
		/* check if we got the right irq cause we use SHARED_IRQ with VF2arm PF2arm*/
		vq_id = cambr_rproc_check_irq_src(rproc);
		if (vq_id < 0) {
			spin_unlock_irqrestore(&ddata->mailbox_lock, flags);
			continue;
		}
		/* clear irq */
		cambr_rproc_clear_irq(rproc, false, false);
		spin_unlock_irqrestore(&ddata->mailbox_lock, flags);

		#ifdef CALLBACK_IN_INTR_CONTEXT
		rproc_vq_interrupt(rproc, 0);
		rproc_vq_interrupt(rproc, 1);
		#else /* !CALLBACK_IN_INTR_CONTEXT */
		rproc_vq_interrupt(rproc, 0);
		mod_delayed_work(ddata->wq, &ddata->work, 0);
		#endif /* CALLBACK_IN_INTR_CONTEXT */

		irq_handle_cnt++;
		#endif /* IPCM_COMMU_SHARED_IRQ */
	}

	if (unlikely(!irq_handle_cnt)) {
		for (vf_id = 0; vf_id < ARRAY_SIZE(cn_rproc); vf_id++) {
			rproc = cn_rproc[vf_id];

			if (!rproc)
				continue;

			dev = rproc->dev.parent;
			ddata = rproc->priv;

			spin_lock_irqsave(&ddata->mailbox_lock, flags);
			vq_id = cambr_rproc_check_irq_src(rproc);
			if (!vq_id) {
				dev_warn_ratelimited(dev, "%s suspicious irq(%d)\n", __func__, irq);
				/* clear irq */
				cambr_rproc_clear_irq(rproc, false, false);
			}
			spin_unlock_irqrestore(&ddata->mailbox_lock, flags);
		}
	}

	return IRQ_HANDLED;
}
#endif

#ifndef CALLBACK_IN_INTR_CONTEXT
/*
 * There is no payload message indicating the virtqueue index as is the
 * case with mailbox-based implementations on OMAP family. As such, this
 * handler processes both the Tx and Rx virtqueue indices on every invocation.
 * The rproc_vq_interrupt function can detect if there are new unprocessed
 * messages or not (returns IRQ_NONE vs IRQ_HANDLED), but there is no need
 * to check for these return values. The index 0 triggering will process all
 * pending Rx buffers, and the index 1 triggering will process all newly
 * available Tx buffers and will wakeup any potentially blocked senders.
 *
 * NOTE:
 * 1. A payload could be added by using some of the source bits in the
 *    IPC interrupt generation registers, but this would need additional
 *    changes to the overall IPC stack, and currently there are no benefits
 *    of adapting that approach.
 * 2. The current logic is based on an inherent design assumption of supporting
 *    only 2 vrings, but this can be changed if needed.
 */
static void cambr_rproc_vring_interrupt(struct work_struct *work)
{
	struct cambr_rproc *ddata =
		container_of(work, struct cambr_rproc, work.work);
	struct rproc *rproc = ddata->rproc;
#ifdef IN_CNDRV_HOST
	rproc_vq_interrupt(rproc, 0);
	//rproc_vq_interrupt(rproc, 1);
#else
	rproc_vq_interrupt(rproc, 1);
	//rproc_vq_interrupt(rproc, 0);
#endif

	/* to avoid mailbox loss */
	queue_delayed_work(ddata->wq, &ddata->work, msecs_to_jiffies(500));
}
#endif

#ifdef IPCM_POLLING_MODE
static int cambr_rproc_poll_worker0(void *data)
{
	struct rproc *rproc = (struct rproc *)data;
	struct cambr_rproc *ddata = rproc->priv;

	allow_signal(SIGKILL);
	for (;;) {
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}
		if (ddata->exit_flag) {
			msleep(20);
			continue;
		}
		rproc_vq_interrupt(rproc, 0);

		usleep_range(20, 50);
	}
	return 0;
}

static int cambr_rproc_poll_worker1(void *data)
{
	struct rproc *rproc = (struct rproc *)data;
	struct cambr_rproc *ddata = rproc->priv;

	allow_signal(SIGKILL);
	for (;;) {
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}
		if (ddata->exit_flag) {
			msleep(20);
			continue;
		}
		rproc_vq_interrupt(rproc, 1);

		usleep_range(20, 50);
	}
	return 0;
}
#endif
void cambr_rproc_register_mailbox(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;
	#if defined(RPMSG_MASTER_PCIE_RC)
	struct cn_core_set *core = ddata->core_set;

	if (core->device_id == MLUID_370 || core->device_id == MLUID_365) {
		ddata->intr.clear_irq = ddata->boardinfo->pci_gic_base
			- 0x8000000000 + ddata->boardinfo->pci_gic_mbox_offset + 0x110;//0x60910
		ddata->intr.trigger_irq = ddata->boardinfo->pci_gic_base
			- 0x8000000000 + ddata->boardinfo->pci_gic_mbox_offset;//0x60800
		ddata->intr.irq_status = ddata->boardinfo->pci_mbox_status_base
			- 0x8000000000 + ddata->boardinfo->pci_mbox_status_offset;//x02222c
		ddata->intr.unmask_irq = ddata->boardinfo->pci_mbox_status_base
			- 0x8000000000 + ddata->boardinfo->pci_mbox_status_offset + 0x100;//x02232c
	} else if (core->device_id == MLUID_370V) {
		ddata->intr.trigger_irq = ddata->boardinfo->pci_vf_mbox_offset;//0x1000
		ddata->intr.clear_irq = ddata->boardinfo->pci_vf_mbox_offset + 0x90;//0x1090
		ddata->intr.irq_status = 0x0;//0x0
		ddata->intr.unmask_irq = 0x100;
	} else if (core->device_id == MLUID_590 || core->device_id == MLUID_580) {
		ddata->intr.clear_irq = ddata->boardinfo->pci_mbox_status_base
			- 0x8000000000 + ddata->boardinfo->pci_gic_mbox_offset + 0x110;//0x28910
		ddata->intr.trigger_irq = ddata->boardinfo->pci_mbox_status_base
			- 0x8000000000 + ddata->boardinfo->pci_gic_mbox_offset;//0x28800
		ddata->intr.irq_status = ddata->boardinfo->pci_gic_base
			- 0x8000000000 + ddata->boardinfo->pci_mbox_status_offset;//0x4248
		ddata->intr.unmask_irq = ddata->boardinfo->pci_gic_base
			- 0x8000000000 + ddata->boardinfo->pci_mbox_status_offset + 0x100;//0x4348
	} else if (core->device_id == MLUID_590V || core->device_id == MLUID_580V) {
		ddata->intr.trigger_irq = ddata->boardinfo->pci_vf_mbox_offset;//0x1000
		ddata->intr.clear_irq = ddata->boardinfo->pci_vf_mbox_offset + 0x30;//0x1030
		ddata->intr.irq_status = 0x2000 + 0x2200;//pcie_vf sheet
		ddata->intr.unmask_irq = 0x2000 + 0x3000;//pcie_vf sheet
	} else {
		/* 200s only support pf */
		ddata->intr.clear_irq = ddata->boardinfo->pci_gic_base
			- 0x8000000000 + ddata->boardinfo->pci_gic_mbox_offset;
		ddata->intr.trigger_irq = ddata->boardinfo->pci_gic_base
			- 0x8000000000 + ddata->boardinfo->pci_gic_mbox_offset + 0x4;
		if (ddata->boardinfo->pci_mbox_status_base)
			ddata->intr.irq_status = ddata->boardinfo->pci_mbox_status_base
				- 0x8000000000 + ddata->boardinfo->pci_mbox_status_offset + 0x4;//reg13 vfx2pf  x=[0..7]
		else
			ddata->intr.irq_status = 0;
	}

	#ifndef IPCM_POLLING_MODE
	/* clear host previous hw mbox status */
	cambr_rproc_clear_irq(rproc, true, false);
	if (!cambr_rproc_is_vf(rproc)) {
		/*
		 * clear arm previous hw mbox status too,
		 * cause rpmsg_probe() -> virtqueue_notify() before arm boot
		 */
		cambr_rproc_clear_irq(rproc, true, true);
	}

	cn_bus_register_interrupt(core->bus_set, ddata->boardinfo->xxx2host_irq,
				cambr_rproc_isr, rproc);

	if (core->device_id == MLUID_370 || core->device_id == MLUID_365) {
		unsigned int reg_val;

		/* unmask arm2pf intr */
		reg_val = reg_read32(core->bus_set, ddata->intr.unmask_irq);
		reg_val &= ~BIT(0);
		reg_val &= 0x7FF;
		reg_write32(core->bus_set, ddata->intr.unmask_irq, reg_val);
	} else if (core->device_id == MLUID_370V) {
		unsigned int reg_val;

		/* unmask arm2vf intr */
		reg_val = reg_read32(core->bus_set, ddata->intr.unmask_irq);
		reg_val &= ~BIT(25);
		reg_write32(core->bus_set, ddata->intr.unmask_irq, reg_val);
	} else if (core->device_id == MLUID_590 || core->device_id == MLUID_580) {
		unsigned int reg_val;

		/* unmask arm2pf intr */
		reg_val = reg_read32(core->bus_set, ddata->intr.unmask_irq);
		reg_val &= ~BIT(0);
		reg_val &= 0x1FF;
		reg_write32(core->bus_set, ddata->intr.unmask_irq, reg_val);
	} else if (core->device_id == MLUID_590V || core->device_id == MLUID_580V) {
		unsigned int reg_val;

		/* unmask arm2vf intr */
		reg_val = reg_read32(core->bus_set, ddata->intr.unmask_irq);
		reg_val &= ~BIT(2);//FIXME?
		reg_write32(core->bus_set, ddata->intr.unmask_irq, reg_val);
	}

	/*
	 * only pf can access gic registers, so enable all vf
	 * see more in c30s_sriov_vf_init_hw()
	 */
	if (!cambr_rproc_is_vf(rproc)) {
		int i = 0;
		/* pf */
		cn_bus_enable_irq(core->bus_set, ddata->boardinfo->xxx2host_irq);
		/* vf */
		for (i = 0; i < ddata->boardinfo->max_vf_num; i++)
			cn_bus_enable_irq(core->bus_set, ddata->boardinfo->xxx2host_irq + 2 + i);
	}
	#endif
	#elif defined(IN_CNDRV_HOST)//EDGE/D2D master
	//TODO
	(void)ddata;
	#else
	#if defined(CONFIG_CAMBR_SOC_C30S)
	unsigned int reg_val;

	if (!cambr_rproc_is_vf(rproc)) {
		ddata->intr.clear_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_gic_base
			+ ddata->boardinfo->pci_gic_mbox_offset + 0x10, sizeof(unsigned int) * 3);//0x60810
		ddata->intr.trigger_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_gic_base
			+ ddata->boardinfo->pci_gic_mbox_offset + 0x100, sizeof(unsigned int) * 8);//0x60900
		ddata->intr.irq_status = (unsigned int *)ioremap(ddata->boardinfo->pci_mbox_status_base
			+ ddata->boardinfo->pci_mbox_status_offset + 0x4, sizeof(unsigned int));//x022230
		ddata->intr.unmask_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_mbox_status_base
			+ ddata->boardinfo->pci_mbox_status_offset + 0x104, sizeof(unsigned int));//x022330
		/* unmask pf2arm intr */
		reg_val = readl(ddata->intr.unmask_irq);
		reg_val &= ~BIT(0);
		reg_val &= 0x7FF;
		writel(reg_val, ddata->intr.unmask_irq);
	} else {
		ddata->intr.clear_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_gic_base
			+ (0x100 * (ddata->vf_id - 1)) + 0x10, sizeof(unsigned int) * 3);//0x60010
		ddata->intr.trigger_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_gic_base
			+ (0x100 * (ddata->vf_id - 1)) + 0x80, sizeof(unsigned int) * 8);//0x60080
		ddata->intr.irq_status = (unsigned int *)ioremap(ddata->boardinfo->pci_mbox_status_base
			+ ddata->boardinfo->pci_mbox_status_offset + 0x4, sizeof(unsigned int));//x022230
		ddata->intr.unmask_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_mbox_status_base
			+ ddata->boardinfo->pci_mbox_status_offset + 0x104, sizeof(unsigned int));//x022330
		/* unmask vf2arm intr */
		reg_val = readl(ddata->intr.unmask_irq);
		reg_val &= ~BIT(ddata->vf_id);
		reg_val &= 0x7FF;
		writel(reg_val, ddata->intr.unmask_irq);
	}
	#elif defined(CONFIG_CAMBR_SOC_C50) || defined(CONFIG_CAMBR_SOC_C50S)
	unsigned int reg_val;

	if (!cambr_rproc_is_vf(rproc)) {
		ddata->intr.clear_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_mbox_status_base
			+ ddata->boardinfo->pci_gic_mbox_offset + 0x10, sizeof(unsigned int) * 3);//0x28810
		ddata->intr.trigger_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_mbox_status_base
			+ ddata->boardinfo->pci_gic_mbox_offset + 0x100, sizeof(unsigned int) * 8);//0x28900
		ddata->intr.irq_status = (unsigned int *)ioremap(ddata->boardinfo->pci_gic_base
			+ ddata->boardinfo->pci_mbox_status_offset + 0x4, sizeof(unsigned int));//0x424c
		ddata->intr.unmask_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_gic_base
			+ ddata->boardinfo->pci_mbox_status_offset + 0x104, sizeof(unsigned int));//0x434c
		/* unmask pf2arm intr */
		reg_val = readl(ddata->intr.unmask_irq);
		reg_val &= ~BIT(0);
		reg_val &= 0x1FF;
		writel(reg_val, ddata->intr.unmask_irq);
	} else {
		ddata->intr.clear_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_mbox_status_base
			+ (0x100 * (ddata->vf_id - 1)) + 0x10, sizeof(unsigned int) * 3);//0x28010
		ddata->intr.trigger_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_mbox_status_base
			+ (0x100 * (ddata->vf_id - 1)) + 0x20, sizeof(unsigned int) * 8);//0x28020
		ddata->intr.irq_status = (unsigned int *)ioremap(ddata->boardinfo->pci_gic_base
			+ ddata->boardinfo->pci_mbox_status_offset + 0x4, sizeof(unsigned int));//0x424c
		ddata->intr.unmask_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_gic_base
			+ ddata->boardinfo->pci_mbox_status_offset + 0x104, sizeof(unsigned int));//0x434c
		/* unmask vf2arm intr */
		reg_val = readl(ddata->intr.unmask_irq);
		reg_val &= ~BIT(ddata->vf_id);
		reg_val &= 0x1FF;
		writel(reg_val, ddata->intr.unmask_irq);
	}
	#else
	/* 200s only support pf */
	ddata->intr.clear_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_gic_base
		+ ddata->boardinfo->pci_gic_mbox_offset + 0x4, sizeof(unsigned int));
	ddata->intr.trigger_irq = (unsigned int *)ioremap(ddata->boardinfo->pci_gic_base
		+ ddata->boardinfo->pci_gic_mbox_offset, sizeof(unsigned int));
	if (ddata->boardinfo->pci_mbox_status_base)
		ddata->intr.irq_status = (unsigned int *)ioremap(ddata->boardinfo->pci_mbox_status_base
			+ ddata->boardinfo->pci_mbox_status_offset, sizeof(unsigned int));
	else
		ddata->intr.irq_status = NULL;
	#endif

	#ifndef IPCM_POLLING_MODE
	cambr_rproc_clear_irq(rproc, true, false);
	if (!cambr_rproc_is_vf(rproc)) {
		if (request_threaded_irq(ddata->boardinfo->xxx2arm_irq, 0,
				cambr_rproc_isr, IRQF_SHARED | IRQF_ONESHOT | IRQF_NO_SUSPEND,
				"ipcm_dev_isr", rproc)) {
			pr_err("[IPCM]failed to request IRQ[%d]\n", ddata->boardinfo->xxx2arm_irq);
		}
	}
	#endif
	#endif
}

void cambr_rproc_unregister_mailbox(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;
	#if defined(RPMSG_MASTER_PCIE_RC)
	#ifndef IPCM_POLLING_MODE
	struct cn_core_set *core = ddata->core_set;
	struct cn_bus_set *bus = core->bus_set;

	cn_bus_disable_irq(bus, ddata->boardinfo->xxx2host_irq);
	cn_bus_unregister_interrupt(bus, ddata->boardinfo->xxx2host_irq);
	#endif
	ddata->intr.clear_irq = 0x0;
	ddata->intr.trigger_irq = 0x0;
	#elif defined(IN_CNDRV_HOST)//EDGE/D2D master
	//TODO
	(void)ddata;
	#else
	#ifndef IPCM_POLLING_MODE
	if (!cambr_rproc_is_vf(rproc)) {
		free_irq(ddata->boardinfo->xxx2arm_irq, rproc);
	}
	#endif
	iounmap(ddata->intr.trigger_irq);
	ddata->intr.trigger_irq = NULL;
	iounmap(ddata->intr.clear_irq);
	ddata->intr.clear_irq = NULL;
	#endif
}

/*
 * MUST be call with lock
 *
 * return false if need to trigger a new mailbox irq
 */
static bool __maybe_unused cambr_rproc_mailbox_pending(struct rproc *rproc, unsigned int pending, unsigned int value)
{
	struct cambr_rproc *ddata = rproc->priv;
	int i;

	if (pending < HW_MAILBOX_QUEUE_SIZE)
		return false;

	for (i = 0; i < pending; i++) {
		if (ddata->in_que_mbx[(ddata->mbx_idx + HW_MAILBOX_QUEUE_SIZE - i) % HW_MAILBOX_QUEUE_SIZE] == value)
			return true;
	}

	return false;
}

/* MUST be call with lock */
static void __maybe_unused cambr_rproc_update_mailbox_info(struct rproc *rproc, unsigned int value)
{
	struct cambr_rproc *ddata = rproc->priv;
	unsigned int i = (ddata->mbx_idx++) % HW_MAILBOX_QUEUE_SIZE;

	ddata->in_que_mbx[i] = value;
}

#define MAILBOX_WAIT_TIMEOUT_US (500)
/* lock & wait prev clear for all mailbox client to avoid interrupt loss */
static void cambr_rproc_send_mailbox(struct rproc *rproc, unsigned int value)
{
	struct cambr_rproc *ddata = rproc->priv;
	unsigned int full;
	unsigned long flags;
	#if defined(RPMSG_MASTER_PCIE_RC)
	struct cn_core_set *core = ddata->core_set;
	struct cn_bus_set *bus = core->bus_set;
	#ifdef IPCM_COMMU_SHARED_IRQ
	unsigned long long start, end;
	#endif

	full = 0;
	spin_lock_irqsave(&ddata->mailbox_lock, flags);
	#ifdef IPCM_COMMU_SHARED_IRQ
	start = get_jiffies_64();
	full = reg_read32(bus, ddata->intr.trigger_irq);
	if (cambr_rproc_mailbox_pending(rproc, (full >> 8) & 0xf, value)) {
		spin_unlock_irqrestore(&ddata->mailbox_lock, flags);
		return;
	}
	do {
		struct device *dev = rproc->dev.parent;

		full = reg_read32(bus, ddata->intr.trigger_irq);
		//cpu_relax();
		if (full & 0x1) {
			udelay(2);
		}
		end = get_jiffies_64();
		if (time_after64(end, start + usecs_to_jiffies(MAILBOX_WAIT_TIMEOUT_US))) {
			dev_warn_ratelimited(dev, "previous interrupt took too long(%dus)!!!",
				jiffies_to_usecs(end - start));
			start = end;
			/* remote do not clear intr, mailbox is full */
			cambr_rproc_clear_irq(rproc, false, true);
		}
	} while (full & 0x1);
	cambr_rproc_update_mailbox_info(rproc, value);
	#endif
	switch (core->device_id) {
	case MLUID_370:
	case MLUID_370V:
	case MLUID_365:
	case MLUID_580:
	case MLUID_580V:
	case MLUID_590:
	case MLUID_590V:
		reg_write32(bus, ddata->intr.trigger_irq + 0x4, value);
		wmb();/* make sure write order */
		reg_write32(bus, ddata->intr.trigger_irq + 0x8, value);
		break;
	case MLUID_270:
	case MLUID_290:
		wmb();/* make sure write order */
		reg_write32(bus, ddata->intr.trigger_irq, value);
		break;
	default:
		break;
	}
	spin_unlock_irqrestore(&ddata->mailbox_lock, flags);
	#elif defined(IN_CNDRV_HOST)
	//use peri_mailbox for EDGE and Die2Die
	//#if defined(CONFIG_CAMBR_SOC_C20E)
	(void)ddata;
	(void)full;
	(void)flags;
	#else

	full = 0;
	spin_lock_irqsave(&ddata->mailbox_lock, flags);
	#ifdef IPCM_COMMU_SHARED_IRQ
	full = readl(ddata->intr.trigger_irq);
	if (cambr_rproc_mailbox_pending(rproc, (full >> 8) & 0xf, value)) {
		spin_unlock_irqrestore(&ddata->mailbox_lock, flags);
		return;
	}
	do {
		int timeout;
		struct device *dev = rproc->dev.parent;

		timeout = readl_poll_timeout_atomic(ddata->intr.trigger_irq,
		full, !(full & 0x1), 2, MAILBOX_WAIT_TIMEOUT_US);
		if (timeout) {
			dev_warn_ratelimited(dev, "previous interrupt took too long(%dus)!!!",
				MAILBOX_WAIT_TIMEOUT_US);
			/* remote do not clear intr, mailbox is full */
			cambr_rproc_clear_irq(rproc, false, true);
		}
	} while (timeout);
	cambr_rproc_update_mailbox_info(rproc, value);
	#endif
	#if defined(CONFIG_CAMBR_SOC_C30S) || defined(CONFIG_CAMBR_SOC_C50) || defined(CONFIG_CAMBR_SOC_C50S)
	writel(value, ddata->intr.trigger_irq + 0x1);
	wmb();/* make sure write order */
	writel(value, ddata->intr.trigger_irq + 0x2);
	#else
	wmb();/* make sure write order */
	writel(value, ddata->intr.trigger_irq);
	#endif
	spin_unlock_irqrestore(&ddata->mailbox_lock, flags);
	#endif
}

static void cambr_rproc_kick(struct rproc *rproc, int vqid)
{
	struct device *dev = rproc->dev.parent;

	cambr_rproc_send_mailbox(rproc, (vqid << 16) | 0xcabd);
	dev_dbg(dev, "%s kicked vq[%d]", __func__, vqid);
}

static int cambr_rproc_get_quirks(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;

	return ddata->boardinfo->quirks;
}

/*
 * we need a rsc table with type RSC_VDEV, when
 * rproc_handle_resources--->rproc_handle_vdev--->rproc_add_subdev to the list
 * to make rproc_start_subdevices-->rproc_vdev_do_start-->rproc_add_virtio_dev,
 * or we MUST manully call rproc_add_subdev() like mtk or qcom.
 *
 * but rproc_alloc_vring() will still use carveout first instead of rsc table. so rsc table is dummy,
 * but the status bit is used for virtio get_status/set_status.
 *
 * cause we do not really load fw here, so we fill a local rsc_table instead of parse from fw header.
 */
int cambr_rproc_fill_rsc_table(struct rproc *rproc, const struct firmware *fw)
{
	struct resource_table *table = NULL;
	size_t tablesz;

	table = (struct resource_table *)&resources;
	tablesz = sizeof(resources);

	/*
	 * Create a copy of the resource table. When a virtio device starts
	 * and calls vring_new_virtqueue() the address of the allocated vring
	 * will be stored in the cached_table. Before the device is started,
	 * cached_table will be copied into device memory by rproc_start()->rproc_find_loaded_rsc_table().
	 */
	rproc->cached_table = kmemdup(table, tablesz, GFP_KERNEL);
	if (!rproc->cached_table)
		return -ENOMEM;

	rproc->table_ptr = rproc->cached_table;
	rproc->table_sz = tablesz;

	dev_dbg(rproc->dev.parent, "%s, %d, table size: %zu\n", __func__, __LINE__, rproc->table_sz);

	return 0;
}

#if defined(RPMSG_MASTER_PCIE_RC)
/*
 * see virtio_rpmsg_bus.c
 * #define MAX_RPMSG_NUM_BUFS	(512)
 * #define MAX_RPMSG_BUF_SIZE	(1024)
 *
 * !!!!must same as cndrv_mm.c shm_rsrv_info shm_rev[]
 */
static struct cambr_rproc_mem cambr_vdev_mem[] = {
		{ .name = "vdev0vring0", .size = VDEV_RING_SIZE,},//64k for taishan, real_size 10246, 4K
		{ .name = "vdev0vring1", .size = VDEV_RING_SIZE,},//64k for taishan, real_size 10246, 4K
		{ .name = "vdev0buffer", .size = VDEV_BUFF_SIZE,},//512K real_size 512K
		{ .name = "rsc_table0", .size = RSC_TABLE_SIZE,},//256 bytes real_size 0x68
		/* outbound */
		{ .name = "vdev0vring0_OB", .size = VDEV_RING_SIZE,},//64k for taishan, real_size 10246, 4K
		{ .name = "vdev0vring1_OB", .size = VDEV_RING_SIZE,},//64k for taishan, real_size 10246, 4K
		{ .name = "vdev0buffer_OB", .size = VDEV_SINGLE_BUFF_SIZE,},//256K 0x40000

		//{ },
};

/* fix rproc_va_to_pa() */
static phys_addr_t cambr_rproc_va_to_pa(struct rproc *rproc, u64 va)
{
	struct cambr_rproc *ddata = rproc->priv;
	struct cambr_rproc_mem *meminfo = ddata->meminfo;
	unsigned int i;
	u32 offset;

	for (i = 0; i < ARRAY_SIZE(cambr_vdev_mem); i++) {
		if (va >= meminfo[i].cpu_addr && va <=
		    meminfo[i].cpu_addr + meminfo[i].size) {
			offset = va - meminfo[i].cpu_addr;
			return meminfo[i].da + offset;
		}
	}

	return 0;
}

#else /* !RPMSG_MASTER_PCIE_RC */
static int cambr_rproc_mem_alloc(struct rproc *rproc,
			      struct rproc_mem_entry *mem)
{
	struct device *dev = rproc->dev.parent;
	void *va;

	if (rproc_get_outbound(rproc) && strstr(mem->name, "_OB")) {
		va = ioremap_nocache(mem->dma, mem->len);
	} else {
		va = ioremap_wc(mem->dma, mem->len);
	}
	if (!va) {
		dev_err(dev, "Unable to map memory region %s: %zx@%llx\n",
			mem->name, mem->len, mem->dma);
		return -ENOMEM;
	}

	/* Update memory entry va */
	mem->va = va;

	dev_info(dev, "alloc memory region name: %s, %zx@%llx  va:%px\n",
			mem->name, mem->len, mem->dma, va);

	return 0;
}

static int cambr_rproc_mem_release(struct rproc *rproc,
				struct rproc_mem_entry *mem)
{
	struct device *dev = rproc->dev.parent;

	iounmap(mem->va);

	dev_info(dev, "release memory region: %zx@%llx\n",
			mem->len, mem->dma);

	return 0;
}
#endif

#ifndef IN_CNDRV_HOST
/* inbound shm pf:64M  +16M per vf*/
static phys_addr_t __maybe_unused cambr_rproc_calc_inbound(struct rproc *rproc, struct reserved_mem *rmem)
{
	struct cambr_rproc *ddata = rproc->priv;

	if (!cambr_rproc_is_vf(rproc))
		return rmem->base;
	return rmem->base + ddata->boardinfo->inbound_vf_offset
			+ (ddata->boardinfo->inbound_vf_quota * (ddata->vf_id - 1));
}

/* outbound shm pf:16M  +2M per vf*/
static u64 cambr_rproc_calc_outbound(struct rproc *rproc)
{
	struct cambr_rproc *ddata = rproc->priv;

	/* TODO after VF support data outbound */
	if (ddata->boardinfo->enable_data_outbound)
		return ddata->boardinfo->data_outbound_base + ddata->boardinfo->outbound_pf_offset;
	/* 0x2000 is commu_OB in cndrv_mm.c */
	if (!cambr_rproc_is_vf(rproc))
		return ddata->boardinfo->outbound_base + ddata->boardinfo->outbound_pf_offset + 0x2000;
	return ddata->boardinfo->outbound_base + ddata->boardinfo->outbound_vf_offset
			+ (ddata->boardinfo->outbound_vf_quota * (ddata->vf_id - 1));
}
#endif

#define LOGBUF_SHM_SIZE (0x80000)

static int cambr_rproc_parse_fw(struct rproc *rproc, const struct firmware *fw)
{
	struct device *dev = rproc->dev.parent;
	struct rproc_mem_entry *mem;

	#if defined(RPMSG_MASTER_PCIE_RC)
	struct cambr_rproc *ddata = rproc->priv;
	struct cn_core_set *core = ddata->core_set;
	int i;

	ddata->meminfo = kmemdup(&cambr_vdev_mem[0],
						sizeof(struct cambr_rproc_mem) * ARRAY_SIZE(cambr_vdev_mem),
						GFP_KERNEL);
	if (!ddata->meminfo)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(cambr_vdev_mem); i++) {
		/*
		 * vdev0buffer for rproc_add_virtio_dev()
		 * cause we had no device tree
		 * and to avoid dma alloc cause we are pcie sharedmemory
		 * (rproc_fw_boot--->rproc_handle_resources--->
		 * rproc_handle_vdev--->rproc_alloc_vring--->rproc_alloc_carveout,
		 * 1. named carveout mem first
		 * 2. then rsc_table
		 *   2.1 da is valid, iommu-based DMA API will iommu_map() a dma_alloc_coherent()
		 *		 dma_addr_t(got dma and va) to da.
		 *   2.2 da is FW_RSC_ADDR_ANY, will set da to the same as dma
		 *       in this scenario, da is dynamic).
		 * vdev0vring0 vdev0vring1 from resource_table.
		 */
		if (!strstr(ddata->meminfo[i].name, "_OB")) {
			/* from cndrv_mm.c shm_rsrv_info reserved */
			ddata->meminfo[i].cpu_addr = cn_shm_get_host_addr_by_name(core, ddata->meminfo[i].name);
			ddata->meminfo[i].da = cn_shm_get_dev_addr_by_name(core, ddata->meminfo[i].name);
		} else if (rproc_get_outbound(rproc)) {
			ddata->meminfo[i].cpu_addr = cn_shm_get_host_addr_by_name(core, ddata->meminfo[i].name);
			ddata->meminfo[i].da = cn_shm_get_dev_addr_by_name(core, ddata->meminfo[i].name);

			/* change pf to data outbound if need */
			if (ddata->boardinfo->enable_data_outbound) {
				char name[40] = {0};

				if (strlen(ddata->meminfo[i].name) > 32) {
					dev_err(dev, "meminfo[%d].name %s too long\n", i, ddata->meminfo[i].name);
					return -EINVAL;
				}

				strcpy(name, ddata->meminfo[i].name);
				strcat(name, "_DATA");

				ddata->meminfo[i].cpu_addr = cn_shm_get_host_addr_by_name(core, name);
				ddata->meminfo[i].da = cn_shm_get_dev_addr_by_name(core, name);
				if (IS_ERR_OR_NULL((void *)ddata->meminfo[i].cpu_addr)) {
					dev_err(dev, "Failed to get cpu addr for %s\n", name);
					return -ENOMEM;
				}
			}
		}
		dev_info(dev, "memory %s:size 0x%zx (host view) cpu_addr 0x%lx; (device view) da 0x%llx\n",
				ddata->meminfo[i].name, ddata->meminfo[i].size,
				ddata->meminfo[i].cpu_addr, ddata->meminfo[i].da);

		/* da(ddata->meminfo[i].dev_addr), but we set host pa here,
		 * see rproc_add_virtio_dev()'s inner comments for vdev0buffer,
		 * dma_declare_coherent_memory()
		 */
		mem = rproc_mem_entry_init(dev, (void *)ddata->meminfo[i].cpu_addr,
				0,
				ddata->meminfo[i].size, ddata->meminfo[i].da,
				NULL,//cambr_rproc_mem_alloc,//already map
				NULL,//cambr_rproc_mem_release,
				ddata->meminfo[i].name);

		if (!mem)
			return -ENOMEM;

		rproc_add_carveout(rproc, mem);
	}
	/* update outbound info to arm in pf, cause vf may not start while arm bootup */
	if (!cambr_rproc_is_vf(rproc)) {
		if (rproc_get_outbound(rproc)) {
			if (ddata->boardinfo->enable_data_outbound)
				resources.rpmsg_vring0.pa = IPCM_DATA_OUTBOUND_ABLE_MAGIC;
			else
				resources.rpmsg_vring0.pa = IPCM_OUTBOUND_ABLE_MAGIC;
		} else {
			resources.rpmsg_vring0.pa = 0;
		}
	}
	#else /*!RPMSG_MASTER_PCIE_RC*/
	struct reserved_mem *rmem;
	struct device_node *np = dev->of_node;
	struct of_phandle_iterator it;
	int index = 0;

	of_phandle_iterator_init(&it, np, "memory-region", NULL, 0);
	while (of_phandle_iterator_next(&it) == 0) {
		rmem = of_reserved_mem_lookup(it.node);
		if (!rmem) {
			dev_err(dev, "unable to acquire memory-region\n");
			return -EINVAL;
		}

		/* No need to map vdev buffer, see more in rproc_add_virtio_dev(),
		 * vdev0buffer is associate to this dev's dma-pool
		 */
		if (!strstr(it.node->name, "buffer")) {
			/* Register memory region */
			mem = rproc_mem_entry_init(dev, NULL,
						(dma_addr_t)rmem->base,
						rmem->size, rmem->base,
						cambr_rproc_mem_alloc,
						cambr_rproc_mem_release,
						it.node->name);
		} else {
			/* Register reserved memory for vdev buffer allocation */
			mem = rproc_of_resm_mem_entry_init(dev, index,
							rmem->size,
							rmem->base,
							it.node->name);
		}

		dev_dbg(dev, "memory %s: size %llx, pa 0x%llx\n",
			it.node->name, rmem->size, rmem->base);

		if (!mem)
			return -ENOMEM;

		rproc_add_carveout(rproc, mem);
		index++;
	}

	#ifndef IN_CNDRV_HOST
	if (cambr_rproc_get_role(rproc)) {
		struct cambr_rproc *ddata = rproc->priv;
		static u64 outbound_magic;

		/* update outbound_able in pf(using rsc_table0) to all */
		if (!cambr_rproc_is_vf(rproc)) {
			struct rproc_mem_entry *rsc_mem;
			struct remote_resource_table *table = NULL;

			rsc_mem = rproc_find_carveout_by_name(rproc, "rsc_table%d", rproc_get_rvdev_index(rproc));
			if (rsc_mem) {
				cambr_rproc_mem_alloc(rproc, rsc_mem);
				table = rsc_mem->va;
				if (!table)
					return -ENOMEM;
				outbound_magic = table->rpmsg_vring0.pa;

				dev_info(dev, "outbound MAGIC: 0x%llx\n", outbound_magic);
				cambr_rproc_mem_release(rproc, rsc_mem);
			}
		}

		if (outbound_magic == IPCM_OUTBOUND_ABLE_MAGIC) {
			ddata->boardinfo->enable_outbound = true;
			ddata->boardinfo->enable_data_outbound = false;
		} else if (outbound_magic == IPCM_DATA_OUTBOUND_ABLE_MAGIC) {
			ddata->boardinfo->enable_outbound = true;
			if (!cambr_rproc_is_vf(rproc))
				ddata->boardinfo->enable_data_outbound = true;
			else
				ddata->boardinfo->enable_data_outbound = false;
		} else {
			ddata->boardinfo->enable_outbound = false;
			ddata->boardinfo->enable_data_outbound = false;
		}

		dev_info(dev, "enable_outbound:%d data_outbound:%d\n",
				ddata->boardinfo->enable_outbound, ddata->boardinfo->enable_data_outbound);

		if (rproc_get_outbound(rproc)) {
			u64 axi_addr = cambr_rproc_calc_outbound(rproc);

			mem = rproc_mem_entry_init(dev, NULL,
					axi_addr, VDEV_RING_SIZE, axi_addr,
					cambr_rproc_mem_alloc,
					cambr_rproc_mem_release,
					"vdev%dvring0_OB", rproc_get_rvdev_index(rproc));
			if (!mem)
				return -ENOMEM;

			rproc_add_carveout(rproc, mem);

			mem = rproc_mem_entry_init(dev, NULL,
					axi_addr + VDEV_RING_SIZE, VDEV_RING_SIZE,
					axi_addr + VDEV_RING_SIZE,
					cambr_rproc_mem_alloc,
					cambr_rproc_mem_release,
					"vdev%dvring1_OB", rproc_get_rvdev_index(rproc));
			if (!mem)
				return -ENOMEM;

			rproc_add_carveout(rproc, mem);

			mem = rproc_mem_entry_init(dev, NULL,
					axi_addr + VDEV_RING_SIZE * 2, VDEV_SINGLE_BUFF_SIZE,
					axi_addr + VDEV_RING_SIZE * 2,
					cambr_rproc_mem_alloc,
					cambr_rproc_mem_release,
					"vdev%dbuffer_OB", rproc_get_rvdev_index(rproc));
			if (!mem)
				return -ENOMEM;

			rproc_add_carveout(rproc, mem);
		}

		if (rproc_get_data_outbound(rproc) && !cambr_rproc_is_vf(rproc)) {
			u64 axi_addr = cambr_rproc_calc_outbound(rproc);

			/* Mapping host-side printk buffer */
			log_buf_addr_set((char *)(axi_addr + VDEV_RING_SIZE * 2 + VDEV_SINGLE_BUFF_SIZE));
		}
	}
	#endif /* !IN_CNDRV_HOST */
	#endif /*!RPMSG_MASTER_PCIE_RC */
	return cambr_rproc_fill_rsc_table(rproc, fw);
}

static int cambr_rproc_start(struct rproc *rproc)
{
	//struct cambr_rproc *ddata = rproc->priv;

	dev_dbg(rproc->dev.parent, "dummy start, mlu core real start at cn_core_bootm() for now\n");
	//enable_irq(rproc->xxx2arm_irq);

	return 0;
}

static int cambr_rproc_stop(struct rproc *rproc)
{
	//struct cambr_rproc *ddata = rproc->priv;

	dev_dbg(rproc->dev.parent, "dummy Stop\n");
	//disable_irq(rproc->xxx2arm_irq);

	return 0;
}

static int cambr_rproc_load(struct rproc *rproc, const struct firmware *fw)
{
	//struct cambr_rproc *ddata = rproc->priv;

	dev_dbg(rproc->dev.parent, "dummy load\n");

	return 0;
}

static struct resource_table *cambr_rproc_find_loaded_rsc_table(struct rproc *rproc,
						       const struct firmware *fw)
{
	struct rproc_mem_entry *mem = NULL;

	dev_dbg(rproc->dev.parent, "%s, %d\n", __func__, __LINE__);

	/* Search for pre-registered carveout */
	mem = rproc_find_carveout_by_name(rproc, "rsc_table%d", rproc_get_rvdev_index(rproc));
	if (mem) {
		#if defined(RPMSG_MASTER_PCIE_RC)
		if (mem->va)//must inited
			return mem->va;
		#else
		if (!mem->va)
			cambr_rproc_mem_alloc(rproc, mem);
		return mem->va;
		#endif
	}

	dev_err(rproc->dev.parent, "%s, %d  NULL\n", __func__, __LINE__);

	return NULL;
}

static const struct rproc_ops cambr_rproc_ops = {
	.kick			= cambr_rproc_kick,//virtio need kick, see rproc_add_virtio_dev() and remoteproce.txt
	.start			= cambr_rproc_start,
	.stop			= cambr_rproc_stop,
	.parse_fw		= cambr_rproc_parse_fw,
	.load			= cambr_rproc_load,//can't be null, rproc_alloc_ops() will get defaults
	.find_loaded_rsc_table = cambr_rproc_find_loaded_rsc_table,
	.get_role       = cambr_rproc_get_role,
	.get_outbound   = cambr_rproc_get_outbound,
	.get_data_outbound   = cambr_rproc_get_data_outbound,
	.get_rvdev_index      = cambr_rproc_get_rvdev_index,
	.is_vf          = cambr_rproc_is_vf,
	.get_quirks     = cambr_rproc_get_quirks,
	#if defined(RPMSG_MASTER_PCIE_RC)
	.va_to_pa       = cambr_rproc_va_to_pa,//cause from shm mem_pool, fixed rproc_va_to_pa()
	#endif
	//.da_to_va     = rproc_da_to_va;//default
};

int cambr_rproc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct cambr_rproc *ddata;
	struct rproc *rproc;
	int ret = 0;
	#ifdef IN_CNDRV_HOST
	struct cn_core_set *core = NULL;
	#else
	const struct device_node *np = pdev->dev.of_node;
	#endif

	rproc = rproc_alloc(dev, "cambr_rproc", &cambr_rproc_ops, NULL, sizeof(*ddata));
	if (!rproc)
		return -ENOMEM;

	rproc->has_iommu = false;
	/* error recovery is not supported at present */
	rproc->recovery_disabled = true;
	ddata = rproc->priv;
	ddata->rproc = rproc;
	spin_lock_init(&ddata->mailbox_lock);
	#ifdef IN_CNDRV_HOST
	core = platform_get_drvdata(pdev);
	core->ipcm_set = rproc;
	ddata->core_set = core;
	ddata->role = 0;//master
	dev_info(dev, "%s, vf_id: %d\n", __func__, core->vf_idx);
	#else
	ddata->role = 1;//slave
	if (of_property_read_u32(np, "vf_id", &ddata->vf_id)) {
		dev_err(dev, "%s, can't get vf_id from dts\n", __func__);
		return -EINVAL;
	}

	cn_rproc[ddata->vf_id] = rproc;
	#endif
	cambr_rproc_init_board_info(rproc);
	platform_set_drvdata(pdev, rproc);

	ddata->pdev = pdev;

	#ifndef CALLBACK_IN_INTR_CONTEXT
	ddata->wq = create_singlethread_workqueue(dev_name(dev));
	if (!ddata->wq) {
		dev_err(dev, "%s, create ipcm_wq failed.\n", __func__);
		platform_set_drvdata(pdev, NULL);
		rproc_free(rproc);
		return -ENOMEM;
	}
	INIT_DELAYED_WORK(&ddata->work, cambr_rproc_vring_interrupt);
	#endif

	cambr_rproc_register_mailbox(rproc);//co-exit with commu, pcie mailbox is not enough

	ret = rproc_add(rproc);
	if (ret)
		goto free_mbox;

	#ifdef IN_CNDRV_HOST
	cn_bus_mb(core->bus_set);
	#endif

	#ifdef IPCM_POLLING_MODE
	ddata->poll_worker0 = kthread_run(cambr_rproc_poll_worker0,
			rproc, "ipcm_poll_0");
	if (IS_ERR_OR_NULL(ddata->poll_worker0)) {
		dev_err(dev, "%s, create poll_worker0 failed.\n", __func__);
		goto free_mbox;
	}
	ddata->poll_worker1 = kthread_run(cambr_rproc_poll_worker1,
			rproc, "ipcm_poll_1");
	if (IS_ERR_OR_NULL(ddata->poll_worker0)) {
		dev_err(dev, "%s, create poll_worker1 failed.\n", __func__);
		goto free_mbox;
	}
	#endif

	return 0;

free_mbox:
	cambr_rproc_unregister_mailbox(rproc);
	#ifndef CALLBACK_IN_INTR_CONTEXT
	destroy_workqueue(ddata->wq);
	#endif
	rproc_free(rproc);
	return ret;
}

int cambr_rproc_remove(struct platform_device *pdev)
{
	struct rproc *rproc = platform_get_drvdata(pdev);
	struct cambr_rproc *ddata = rproc->priv;

	dev_info(&pdev->dev, "%s, role %d\n", __func__, ddata->role);

	#ifdef IPCM_POLLING_MODE
	ddata->exit_flag = 1;
	if (ddata->poll_worker0) {
		smp_mb();/* barrier() */

		send_sig(SIGKILL, ddata->poll_worker0, 1);
		kthread_stop(ddata->poll_worker0);
		ddata->poll_worker0 = NULL;
	}
	if (ddata->poll_worker1) {
		smp_mb();/* barrier() */

		send_sig(SIGKILL, ddata->poll_worker1, 1);
		kthread_stop(ddata->poll_worker1);
		ddata->poll_worker1 = NULL;
	}
	#endif
	cambr_rproc_unregister_mailbox(rproc);

	#ifndef CALLBACK_IN_INTR_CONTEXT
	cancel_delayed_work_sync(&ddata->work);
	flush_delayed_work(&ddata->work);
	flush_workqueue(ddata->wq);
	destroy_workqueue(ddata->wq);
	#endif

	#if defined(RPMSG_MASTER_PCIE_RC)
	kfree(ddata->meminfo);
	ddata->meminfo = NULL;
	#endif

	/* automatic do in rproc_del() */
	//rproc_shutdown(rproc);

	rproc_del(rproc);

	rproc_free(rproc);

	pr_info("%s: %d\n", __func__, __LINE__);

	return 0;
}

#ifdef IN_CNDRV_HOST
int cambr_rproc_dev_init(void *core)
{
	struct platform_device *pdev = NULL;
	struct cn_core_set *_core = (struct cn_core_set *)core;
	int ret;

	pr_debug("%s: %d\n", __func__, __LINE__);

	pdev = platform_device_alloc("cambr-rproc", _core->idx);
	if (!IS_ERR(pdev)) {
		platform_set_drvdata(pdev, core);
		ret = platform_device_add(pdev);
		if (ret) {
			pr_err("[remoteproc]Can't add platform device");
			platform_device_put(pdev);
			return ret;
		}
	} else {
		pr_err("[remoteproc]Can't alloc platform device for %s", _core->core_name);
		return PTR_ERR(pdev);
	}

	pr_debug("%s: %d\n", __func__, __LINE__);
	return 0;
}

void cambr_rproc_dev_exit(void *core)
{
	struct cn_core_set *_core = (struct cn_core_set *)core;
	struct rproc *rproc = _core->ipcm_set;
	struct cambr_rproc *ddata = rproc->priv;

	platform_device_unregister(ddata->pdev);
	pr_info("%s: %d\n", __func__, __LINE__);
}

void cambr_rproc_commu_send_mailbox(void *core)
{
	struct cn_core_set *_core = (struct cn_core_set *)core;
	struct rproc *rproc = _core->ipcm_set;

	if (rproc)
		cambr_rproc_send_mailbox(rproc, COMMU_MBOX_MSG);
	else
		pr_err_ratelimited("%s failed!\n", __func__);
}
#else
static int cambr_rproc_commu_vfid_remap(int vf_id)
{
	return vf_id;
}

void cambr_rproc_commu_send_mailbox(int vf_id)
{
	int idx = cambr_rproc_commu_vfid_remap(vf_id);
	struct rproc *rproc = cn_rproc[idx];

	if (rproc)
		cambr_rproc_send_mailbox(rproc, COMMU_MBOX_MSG);
	else
		pr_err_ratelimited("%s failed!\n", __func__);
}
EXPORT_SYMBOL(cambr_rproc_commu_send_mailbox);
#endif
static const struct of_device_id cambr_rproc_of_match[] __maybe_unused = {
	{ .compatible = "cambr,ipcm", },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, cambr_rproc_of_match);

static struct platform_driver cambr_rproc_driver = {
	.probe = cambr_rproc_probe,
	.remove = cambr_rproc_remove,
	.driver = {
		.name = "cambr-rproc",
		.of_match_table = of_match_ptr(cambr_rproc_of_match),
	},
};
int cambr_rproc_init(void)
{
	return platform_driver_register(&cambr_rproc_driver);
}

void cambr_rproc_exit(void)
{
	platform_driver_unregister(&cambr_rproc_driver);
}

MODULE_DESCRIPTION("Cambrion IPCM Driver");
