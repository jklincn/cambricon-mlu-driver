/*
 * This file is part of cambricon pcie driver
 *
 * Copyright (c) 2018, Cambricon Technologies Corporation Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/types.h>
#if (KERNEL_VERSION(4, 18, 0) > LINUX_VERSION_CODE)
#include <linux/pcieport_if.h>
#endif
#include <linux/pci_hotplug.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>
#include <linux/dma-mapping.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/errno.h>
#include <linux/aer.h>
#include <linux/platform_device.h>
#include <linux/semaphore.h>
#include <linux/iommu.h>

#include "cndrv_core.h"
#include "cndrv_affinity.h"
#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "pcie_dma.h"
#include "cndrv_pci.h"
#include "cndrv_mm.h"
#include "cndrv_domain.h"
#include "cndrv_debug.h"

static int cn_pci_pre_exit(void *pcie_priv);
static size_t cn_pci_dma_transfer(struct pcie_dma_task *task);
static int cn_pci_init_dma_task(struct pcie_dma_task *task, struct transfer_s *t,
		enum CN_PCIE_DMA_TYPE type, struct cn_pcie_set *pcie_set);
#include "pcie_interrupt.c"
#include "pcie_bar.c"
#include "pcie_dma.c"
#include "pcie_p2p.c"
#include "pcie_async.c"

static int cn_pci_sriov_cfg_init(struct cn_pcie_set *pcie_set, int numvfs);
static int cn_pci_sriov_cfg_deinit(struct cn_pcie_set *pcie_set);
static int cn_pci_sriov_configure(struct pci_dev *pdev, int numvfs);
static void *cn_pci_domain_init(const void *cfg, void *pcie_priv);
static int cn_pci_domain_exit(void *pcie_priv);
static int cn_pci_guest_save_prepare(void *pcie_priv);
static int cn_pci_guest_restore_complete(void *pcie_priv);
static void *cn_pci_sriov_init(const void *cfg, void *pcie_priv);
static void *cn_pci_sriov_reinit(const void *cfg, void *pcie_priv);
static int cn_pci_sriov_exit(void *sriov);
static int cn_pci_check_plx_bridge(struct cn_pcie_set *pcie_set);

#define CAMBR_DEVICE(vendor_id, dev_id, info)  {	\
	PCI_DEVICE(vendor_id, dev_id),			\
	.driver_data = (kernel_ulong_t)&info		\
	}

extern struct cn_pci_info c20l_pci_info;
extern struct cn_pci_info c20e_pci_info;
extern struct cn_pci_info c20l_vf_pci_info;

static const struct pci_device_id cn_pci_ids_mlu220_mlu270[] = {
	CAMBR_DEVICE(cambricon_dm_VID, CN_C20L_DID, c20l_pci_info),
	CAMBR_DEVICE(cambricon_dm_VID, CN_C20E_DID, c20e_pci_info),
	CAMBR_DEVICE(cambricon_dm_VID, CN_C20L_VF_DID, c20l_vf_pci_info),
	CAMBR_DEVICE(cambricon_dm_VID, CN_C20L_VF_DID1, c20l_vf_pci_info),
	{}
};

static const struct pci_device_id cn_pci_sriov_ids_mlu220_mlu270[] = {
	CAMBR_DEVICE(cambricon_dm_VID, CN_C20L_DID, c20l_pci_info),
	CAMBR_DEVICE(cambricon_dm_VID, CN_C20E_DID, c20e_pci_info),
	{}
};

static int pcie_speed[] = {0, 5, 10, 16, 32, 64};


MODULE_DEVICE_TABLE(pci_cn_pci_ids_mlu220_mlu270, cn_pci_ids_mlu220_mlu270);
MODULE_DEVICE_TABLE(pci_cn_pci_sriov_ids_mlu220_mlu270, cn_pci_sriov_ids_mlu220_mlu270);

#define DRV_MODULE_NAME		"cambricon-pci-drv_mlu220_mlu270"

static void cn_pci_reg_write32(void *pcie_priv, unsigned long offset, u32 val)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	if (pcie_set->ops->reg_write32) /* c30 rewrite reg_write32 */
		pcie_set->ops->reg_write32(offset, val, pcie_set);
	else
		iowrite32(val, pcie_set->reg_virt_base + offset);
}

static u32 cn_pci_reg_read32(void *pcie_priv, unsigned long offset)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	if (pcie_set->ops->reg_read32)
		return pcie_set->ops->reg_read32(offset, pcie_set);
	else
		return ioread32(pcie_set->reg_virt_base + offset);
}

static void cn_pci_mem_write32(void *pcie_priv, unsigned long offset, u32 val)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	iowrite32(val, pcie_set->share_mem[0].virt_addr + offset);
}

static u32 cn_pci_mem_read32(void *pcie_priv, unsigned long offset)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return ioread32(pcie_set->share_mem[0].virt_addr + offset);
}

static int cn_pci_bar_write(void *pcie_priv, u64 d_addr, unsigned long h_addr, size_t len)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	if (!pcie_set->ops->bar_write) {
		cn_dev_pcie_err(pcie_set, "bar_write is NULL");
		return -1;
	}

	return pcie_set->ops->bar_write(h_addr, d_addr, len, pcie_set);
}

static int cn_pci_bar_read(void *pcie_priv, u64 d_addr, unsigned long h_addr, size_t len)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	if (!pcie_set->ops->bar_read) {
		cn_dev_pcie_err(pcie_set, "bar_read is NULL");
		return -1;
	}

	return pcie_set->ops->bar_read(h_addr, d_addr, len, pcie_set);
}

static void cn_pci_mb(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (!(pcie_set->ops->pci_mb)) {
		cn_dev_pcie_err(pcie_set, "pci_mb function is NULL");
		return;
	}
	pcie_set->ops->pci_mb(pcie_set);
}

static int cn_pci_check_available(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	if (!(pcie_set->ops->check_available)) {
		return 0;
	}
	return pcie_set->ops->check_available(pcie_set);
}

static int cn_pci_get_mem_cnt(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return pcie_set->share_mem_cnt;
}

static CN_MEM_TYPE cn_pci_get_mem_type(void *pcie_priv, int index)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return pcie_set->share_mem[index].type;
}

static unsigned long cn_pci_get_mem_size(void *pcie_priv, int index)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return pcie_set->share_mem[index].win_length;
}

static void *cn_pci_get_mem_base(void *pcie_priv, int index)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return pcie_set->share_mem[index].virt_addr;
}

static unsigned long cn_pci_get_mem_phyaddr(void *pcie_priv, int index)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return pcie_set->share_mem[index].phy_addr;
}

static u64 cn_pci_get_device_addr(void *pcie_priv, int index)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return pcie_set->share_mem[index].device_addr;
}

static unsigned long cn_pci_get_reg_size(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return pcie_set->reg_win_length;
}

static void *cn_pci_get_reg_base(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return pcie_set->reg_virt_base;
}

static unsigned long cn_pci_get_reg_phyaddr(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return pcie_set->reg_phy_addr;
}

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

static int cn_pci_soft_reset(void *pcie_priv, bool reset)
{
	struct cn_pcie_set *pcie_set;
	int rc;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	cn_dev_pcie_info(pcie_set, "pcie soft reset");

	cn_pci_dev_save(pcie_set->pdev);

	if (!cn_pci_wait_for_pending_transaction(pcie_set->pdev))
		cn_dev_pcie_err(pcie_set,
			"timed out waiting for pending transaction");

	if (!(pcie_set->ops->soft_reset)) {
		cn_dev_pcie_err(pcie_set, "soft_reset function is NULL");
		return -EINVAL;
	}

	if (reset)
		pcie_set->ops->soft_reset(pcie_set);

	/*
	 * Per PCIe r4.0, sec 6.6.2, a device must complete an FLR within
	 * 100ms, but may silently discard requests while the FLR is in
	 * progress.  Wait 100ms before trying to access the device.
	 */
	msleep(100);

	rc = cn_pci_dev_wait(pcie_set->pdev, "soft reset", PCIE_RESET_READY_POLL_MS);

	cn_pci_dev_restore(pcie_set->pdev);

	__sync_fetch_and_add(&pcie_set->heartbeat_cnt, 1);

	return rc;
}

static u64 cn_pci_bus_address(struct pci_dev *pdev, int bar)
{
	struct pci_bus_region region;

#if KERNEL_VERSION(3, 10, 107) != LINUX_VERSION_CODE
	pcibios_resource_to_bus(pdev->bus, &region, &pdev->resource[bar]);
#else
	pcibios_resource_to_bus(pdev, &region, &pdev->resource[bar]);
#endif
	return region.start;
}

static int cn_pci_set_dma_mask(struct pci_dev *pdev)
{
	static int mask[] = {64, 32};
	int i;

	for (i = 0; i < ARRAY_SIZE(mask); i++) {
		if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(mask[i]))) {
			pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(mask[i]));
			cn_dev_debug("set pcie dma mask%d ok", mask[i]);
			return 0;
		}
	}

	cn_dev_err("set pcie dma mask err");
	return -EINVAL;
}

static int cn_pci_in_position_check(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	u32 reg_data;

	/* Determine the card's in-position state */
	pci_read_config_dword(pdev, PCI_COMMAND, &reg_data);
	if (reg_data == REG_VALUE_INVALID) {
		cn_dev_pcie_err(pcie_set, "PCIE link status abnormal, value = %#x", reg_data);
		return -1;
	}

	return 0;
}

static int cn_pci_pre_init(struct cn_pcie_set *pcie_set)
{
	u64 sz;
	struct pci_dev *pdev = pcie_set->pdev;

	if (cn_pci_in_position_check(pcie_set))
		goto exit;

	if (unlikely(pci_enable_device(pcie_set->pdev)))
		goto exit;

	pci_set_master(pcie_set->pdev);

	if (pci_request_regions(pcie_set->pdev, pcie_set->dev_name))
		goto exit;

	sz = pci_resource_len(pdev, 0);
	if (!sz) {
		cn_dev_err("no enough MMIO space for PF bar0");
		goto exit;
	}

	INIT_LIST_HEAD(&pcie_set->bar_resource_head);

	pcie_set->pcibar[0].base = pci_resource_start(pdev, 0);
	pcie_set->pcibar[0].size = sz;

	pcie_set->p2p_bus_offset = pci_resource_start(pdev, 0) -
			cn_pci_bus_address(pdev, 0);

	if (cn_pci_set_dma_mask(pdev))
		goto exit;

	if (pdev->bus && pdev->bus->self && pdev->bus->self->bus &&
			pdev->bus->self->bus->self && pdev->bus->self->bus->self->bus)
		pcie_set->hid = (pdev->bus->self->bus->self->bus->number << 16) |
			((pdev->bus->self->bus->self->devfn >> 3) & 0xff) |
			(pdev->bus->self->bus->self->devfn & 0x7);
	else
		pcie_set->hid = 0xffffffff;

	return 0;
exit:
	pci_release_regions(pcie_set->pdev);
	pci_disable_device(pcie_set->pdev);
	return -1;
}

static int cn_pci_set_bus(void *pcie_priv, void *bus_set)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	pcie_set->state = PCIE_STATE_SET_BUS;
	pcie_set->bus_set = bus_set;

	return 0;
}

static int cn_pci_init(void *pcie_priv, void *bus_set)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	int rc;
	struct cn_core_set *core;

	pcie_set->state = PCIE_STATE_INIT;
	pcie_set->bus_set = bus_set;
	core = pcie_set->bus_set->core;

	sema_init(&pcie_set->transfer_data_sem,
		min(MAX_PCI_DMA_TASK, pcie_set->max_channel));

	sema_init(&pcie_set->timeout_log_sem, 1);
	sema_init(&pcie_set->vf_smmu_flush_sem, 1);

	rc = cn_pci_dma_sync_init(pcie_set);
	if (unlikely(rc))
		return -1;

	if (!(pcie_set->ops->pcie_init)) {
		cn_dev_pcie_err(pcie_set, "pcie_init function is NULL");
		return -EINVAL;
	}
	rc = pcie_set->ops->pcie_init(pcie_set);/*c20l_pcie_init*/
	if (unlikely(rc))
		return -1;

	rc = cn_pci_dma_async_init(pcie_set);
	if (unlikely(rc))
		return -1;

	pcie_set->state = PCIE_STATE_NORMAL;

	if (core->domain_set) {
		pcie_set->dm_ops.init = cn_pci_domain_init;
		pcie_set->dm_ops.exit = cn_pci_domain_exit;
		pcie_set->dm_ops.stop = NULL;
		pcie_set->dm_ops.reinit = NULL;
		if (pcie_set->is_virtfn) {
			pcie_set->dm_ops.save_prepare = cn_pci_guest_save_prepare;
			pcie_set->dm_ops.restore_complete = cn_pci_guest_restore_complete;
			dm_register_ops_kernel(core->domain_set, DM_FUNC_VF, PCI,
						&pcie_set->dm_ops, pcie_set);
		} else
			dm_register_ops_kernel(core->domain_set, DM_FUNC_PF, PCI,
						&pcie_set->dm_ops, pcie_set);
	}

	cn_dev_pcie_info(pcie_set, "init end");

	return rc;
}

static int cn_pci_late_exit_cb(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = pcie_priv;
    struct pcie_dma_task *task = NULL;
    struct hlist_node *tmp;
    int bkt;

	__sync_lock_test_and_set(&pcie_set->state, PCIE_STATE_STOP);
	while (pcie_set->task_num) {
		cn_dev_pcie_info(pcie_set,
			"pcie_set->task_num = %d", pcie_set->task_num);
		usleep_range(1000, 1100);
	}

	mutex_lock(&pcie_set->async_task_hash_lock);
	hash_for_each_safe(pcie_set->async_task_htable,
					bkt, tmp, task, hlist) {
		hash_del(&task->hlist);
		cn_pci_dma_trigger_task_release(task);
	}
	mutex_unlock(&pcie_set->async_task_hash_lock);

	return 0;
}

static void cn_pci_exit_cb(void *pcie_priv)
{
	cn_pci_pre_exit(pcie_priv);
}

int cn_pci_pre_exit(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = pcie_priv;
	struct pci_dev  *pci_dev;
	unsigned int i;

	pci_dev = pcie_set->pdev;

	cn_pci_dma_async_exit(pcie_set);

	pci_disable_pcie_error_reporting(pci_dev);

	if (!(pcie_set->ops->pcie_pre_exit)) {
		cn_dev_pcie_err(pcie_set, "pcie_pre_exit function is NULL");
		return -EINVAL;
	}
	pcie_set->ops->pcie_pre_exit(pcie_set); /*c20l_pcie_exit*/
	cn_pci_dma_sync_exit(pcie_set);

	for (i = 0; i < INTERRUPT_IRQ_NUM; i++)
		pcie_set->irq_desc[i].occur_count = 0;

	cn_dev_pcie_info(pcie_set, "cn_pci_exit end");

	return 0;
}

static int client_remove_devices_fn(struct device *dev, void *unused)
{
	struct platform_device *pdev = to_platform_device(dev);

	platform_device_unregister(pdev);

	return 0;
}

static void client_devices_unregister(struct device *dev)
{
	device_for_each_child(dev, NULL, client_remove_devices_fn);
}

static int cn_pci_exit(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = pcie_priv;
	struct pci_dev  *pci_dev;

	//cn_pci_disable_all_irqs(pcie_set);
	pci_dev = pcie_set->pdev;
	if (!(pcie_set->ops->pcie_exit)) {
		cn_dev_pcie_err(pcie_set, "pcie_exit function is NULL");
		return -EINVAL;
	}
	pcie_set->ops->pcie_exit(pcie_set);

	cn_dev_pcie_info(pcie_set, "pci_release_regions");
	pci_release_regions(pci_dev);
	pci_disable_device(pci_dev);

	devm_kfree(&pci_dev->dev, pcie_priv);

	return 0;
}

static void cn_pci_show_info(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pcie_dma_task test_task;
	struct transfer_s t;

	memset(&t, 0, sizeof(t));
	memset(&test_task, 0, sizeof(test_task));
	test_task.transfer = &t;
	cn_pci_print_channel_state(&test_task, pcie_set);
	cn_pci_dump_reg_info(pcie_set);
}

static int cn_pci_interrupt_info(void *pcie_priv, struct int_occur_info_s *int_occur_info)
{
	unsigned int index = 0;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	for (index = 0; index < INTERRUPT_IRQ_NUM; index++) {
		int_occur_info->int_occur_count[index] = pcie_set->irq_desc[index].occur_count;
	}

	return 0;
}

static int cn_pci_get_irq_by_desc(void *pcie_priv, char *irq_desc)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (!pcie_set->ops->get_irq_by_desc) {
		cn_dev_pcie_err(pcie_set, "ops get_irq_by_desc is NULL");
		return -1;
	}

	return pcie_set->ops->get_irq_by_desc(irq_desc, pcie_set);
}

static int cn_pci_get_inbound_cnt(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	return atomic_read(&pcie_set->inbound_count);
}

static u32 cn_pci_get_outbound_size(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	return pcie_set->ob_size * pcie_set->ob_cnt;
}

static struct page *cn_pci_get_outbound_pages(void *pcie_priv, int index)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	return pcie_set->share_mem_pages[index];
}

static int cn_pci_get_outbound_able(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	return pcie_set->outbound_able;
}

static u32 cn_pci_get_non_align_cnt(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	return pcie_set->non_align_cnt;
}

static u32 cn_pci_get_heartbeat_cnt(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	return pcie_set->heartbeat_cnt;
}

static u32 cn_pci_get_soft_retry_cnt(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	return pcie_set->soft_retry_cnt;
}

static u32 cn_pci_get_p2p_exchg_cnt(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	return pcie_set->p2p_exchg_cnt;
}

static struct device *cn_pci_get_dev(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	return &pcie_set->pdev->dev;
}

static int cn_pci_get_dma_info(void *pcie_priv, struct dma_info_s *dma_info)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	dma_info->dma_data_total[DMA_D2H] = pcie_set->total_data[DMA_D2H] +
					pcie_set->total_data[DMA_P2P];
	dma_info->dma_data_total[DMA_H2D] = pcie_set->total_data[DMA_H2D];

	return 0;
}

static int cn_pci_get_info(void *pcie_priv, struct bus_info_s *bus_info)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	bus_info->bus_type = BUS_TYPE_PCIE;
	bus_info->info.pcie.device_id = pcie_set->pdev->devfn;
	bus_info->info.pcie.vendor = pcie_set->pdev->vendor;
	bus_info->info.pcie.subsystem_vendor = pcie_set->pdev->subsystem_vendor;
	bus_info->info.pcie.bus_num = pcie_set->pdev->bus->number;
	bus_info->info.pcie.device = pcie_set->pdev->device;
	bus_info->info.pcie.domain_id = pci_domain_nr(pcie_set->pdev->bus);

	return 0;
}

static int cn_pci_get_isr_type(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	return pcie_set->irq_type;
}

static int cn_pci_get_lnkcap(void *pcie_priv, struct bus_lnkcap_info *lnk_info)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	u32 rdata = 0;

	pcie_capability_read_dword(pcie_set->pdev, PCI_EXP_LNKCAP, &rdata);
	lnk_info->speed = rdata & 0x000F;
	lnk_info->width = (rdata & 0x03F0) >> 4;

	return 0;
}

static int cn_pci_get_curlnk(void *pcie_priv, struct bus_lnkcap_info *lnk_info)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	u16 speed, width;
	struct pci_dev *dev = pcie_set->pdev;
	u16 rdata = 0;

	pcie_capability_read_word(pcie_set->pdev, PCI_EXP_LNKSTA, &rdata);
	lnk_info->speed = rdata & 0x000F;
	lnk_info->width = (rdata & 0x03F0) >> 4;

	lnk_info->min_speed = lnk_info->speed;
	lnk_info->min_width = lnk_info->width;
	dev = cn_pci_upstream_bridge(dev);
	while (dev) {
		pcie_capability_read_word(dev, PCI_EXP_LNKSTA, &rdata);
		speed = rdata & 0x000F;
		width = (rdata & 0x03F0) >> 4;
		if (pcie_speed[lnk_info->min_speed] * lnk_info->min_width >
				pcie_speed[speed] * width) {
			lnk_info->min_speed = speed;
			lnk_info->min_width = width;
		}
		dev = cn_pci_upstream_bridge(dev);
	}

	return 0;
}

static int cn_pci_get_vf_idx(void *pf_pcie_priv, void *vf_pcie_priv)
{
	int vf_totalnums;
	int vf_i;
	int vf_bus;
	int vf_func;
	struct cn_pcie_set *pf_pcie_set = (struct cn_pcie_set *)pf_pcie_priv;
	struct cn_pcie_set *vf_pcie_set = (struct cn_pcie_set *)vf_pcie_priv;

	if ((!pf_pcie_set) || (!vf_pcie_set)) {
		return -1;
	}

	if (!pf_pcie_set->pdev->is_physfn) {
		cn_dev_pcie_err(pf_pcie_set, "dev is not a physical function");
		return -1;
	}

	vf_totalnums = pci_sriov_get_totalvfs(pf_pcie_set->pdev);
	if (vf_totalnums < 0) {
		return -1;
	}

	if (!(pf_pcie_set->ops->iov_virtfn_bus &&
		pf_pcie_set->ops->iov_virtfn_devfn)) {
		return -1;
	}

	for (vf_i = 0; vf_i < vf_totalnums; vf_i++) {
		vf_bus = pf_pcie_set->ops->iov_virtfn_bus(pf_pcie_set, vf_i);
		vf_func = pf_pcie_set->ops->iov_virtfn_devfn(pf_pcie_set, vf_i);

		if (vf_bus == vf_pcie_set->pdev->bus->number &&
			vf_func == vf_pcie_set->pdev->devfn) {
			cn_dev_pcie_info(pf_pcie_set, "vf_i:%d number:(%d %d) devfn:(%d %d)",
				vf_i, pf_pcie_set->pdev->bus->number,
				vf_pcie_set->pdev->bus->number,
				pf_pcie_set->pdev->devfn, vf_pcie_set->pdev->devfn);
			return vf_i;
		}
	}

	return -1;
}

static u32 cn_pci_get_bdf(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (pcie_set->vf_priv_data) {
		return pcie_set->vf_priv_data->bdf;
	} else {
		return pcie_set->bdf;
	}
}

static u32 cn_pci_get_current_bdf(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	return pcie_set->bdf;
}

static bool cn_pci_check_pdev_virtfn(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	return pcie_set->pdev->is_virtfn;
}

static int cn_pci_set_bdf(void *pcie_priv, u32 bdf)
{
	int ret = 0;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (pcie_set->vf_priv_data) {
		pcie_set->vf_priv_data->bdf = bdf;
	} else {
		ret = -EINVAL;
	}

	if (pcie_set->ops->flush_irq) {
		pcie_set->ops->flush_irq(pcie_set);
	}

	return ret;
}

static inline void cn_pci_iov_set_numvfs(struct pci_dev *dev, int nr_virtfn)
{
	int pos;

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return;

	pci_write_config_word(dev, pos + PCI_SRIOV_NUM_VF, nr_virtfn);
}

static void cn_pci_save_and_disable(struct pci_dev *pdev)
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
	pci_write_config_word(pdev, PCI_COMMAND, PCI_COMMAND_INTX_DISABLE);
}

static int cn_pci_check_uncorrectable_status(struct pci_dev *pdev)
{
	unsigned int pos, i;
	unsigned int err_status = 0;

	static const struct {
		unsigned int err;
		char *info;
	} table[] = {
		{PCI_ERR_UNC_POISON_TLP, "Data link protocol"},
		{PCI_ERR_UNC_SURPDN, "Surprise Down"},
		{PCI_ERR_UNC_POISON_TLP, "Poisoned TLP"},
		{PCI_ERR_UNC_FCP, "Flow control protocol"},
		{PCI_ERR_UNC_COMP_TIME, "Completion Timeout"},
		{PCI_ERR_UNC_COMP_ABORT, "Completer Abort"},
		{PCI_ERR_UNC_UNX_COMP, "Unexpected Completion"},
		{PCI_ERR_UNC_RX_OVER, "Receiver Overflow"},
		{PCI_ERR_UNC_MALF_TLP, "Malformed TLP"},
		{PCI_ERR_UNC_ECRC, "ECRC Error status"},
		{PCI_ERR_UNC_UNSUP, "Unsupported request"},
		{PCI_ERR_UNC_ACSV, "ACS Violation"},
		{PCI_ERR_UNC_INTN, "internal error"},
		{PCI_ERR_UNC_MCBTLP, "mc blocked TLP"},
		{PCI_ERR_UNC_ATOMEG, "Atomic egress blocked"},
		{PCI_ERR_UNC_TLPPRE, "TLP prefix blocked"},
	};

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);
	if (pos) {
		pci_read_config_dword(pdev, pos + PCI_ERR_UNCOR_STATUS, &err_status);
		pr_info("pci uncorrectable error status register is :%#x\n",
			err_status);

		for (i = 0; i < ARRAY_SIZE(table); i++) {
			if (err_status & table[i].err)
				pr_err("%s\n", table[i].info);
		}
	} else
		pr_info("%s NO AER capability\n", pci_name(pdev));

	return err_status;
}

/*
 * cn_pci_error_detected - called when PCI error is detected
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 *
 * when this function is invoked , rc will invok link reset if AER error is fatal,that is
 * the @state is pci_channel_io_frozen.
 */
static pci_ers_result_t cn_pci_error_detected(struct pci_dev *pdev,
					pci_channel_state_t state)
{
	pci_ers_result_t ers_ret = PCI_ERS_RESULT_DISCONNECT;

	/*other device may be return need reset ,that cause slot reset is invoked.*/
	if (!cn_pci_check_uncorrectable_status(pdev))
		return PCI_ERS_RESULT_CAN_RECOVER;

	switch (state) {
	/*I/O channel is in normal state when AER severity is no fatal*/
	/*rc will not invoke hot reset*/
	case pci_channel_io_normal:
		/* do something before invoke mmio_enable */
		cn_pci_save_and_disable(pdev);
		ers_ret = PCI_ERS_RESULT_NEED_RESET;
		break;
	/*I/0 to channel is blocked when AER severity is fatal,and thend rc will invoke hot reset,
	 *but rc do not save.
	 */
	case pci_channel_io_frozen:
		pr_err("dev 0x%px, frozen state error, reset controller\n", pdev);
		cn_pci_save_and_disable(pdev);
		ers_ret = PCI_ERS_RESULT_NEED_RESET;
		break;
		/*pci card is dead,state never is this case through see hikey 4.1.8 kernel source code.*/
	case pci_channel_io_perm_failure:
		pr_err("dev 0x%px, frozen state error, req. disconnect\n", pdev);
		/*reset cannot deal with this error*/
		ers_ret = PCI_ERS_RESULT_DISCONNECT;
	}

	return ers_ret;
}

static pci_ers_result_t cn_pci_err_slot_reset(struct pci_dev *pdev)
{
	pr_err("restart after slot reset\n");

	if (pci_enable_device_mem(pdev))
		return PCI_ERS_RESULT_DISCONNECT;

	pci_set_master(pdev);
	pci_restore_state(pdev);
	pci_save_state(pdev);

	return PCI_ERS_RESULT_RECOVERED;
}

static void cn_pci_err_resume(struct pci_dev *pdev)
{
	pr_info("resume\n");

	pci_restore_state(pdev);

	cn_pci_cleanup_aer_uncorrect_error_status(pdev);
}

static const struct pci_error_handlers cn_pci_err_handler = {
	.error_detected = cn_pci_error_detected,
	.slot_reset = cn_pci_err_slot_reset,
	.resume = cn_pci_err_resume,
};

/* type = PCI_CAP_ID_MSI or PCI_CAP_ID_MSI */
static inline int is_msi_msix_capable(struct pci_dev *dev, int type)
{
	struct pci_bus *bus;

	if (!dev || dev->no_msi)
		return 0;

	for (bus = dev->bus; bus; bus = bus->parent)
		if (bus->bus_flags & PCI_BUS_FLAGS_NO_MSI)
			return 0;

	if (!pci_find_capability(dev, type))
		return 0;

	return 1;
}

#include "mlu_peer_mem.c"

static int cn_pci_mlu_mem_client_init(void *pcie_priv)
{
	int ret = 0;
	struct cn_pcie_set *pcie_set = pcie_priv;

	if (pcie_set->id != MLUID_220)
		ret = mlu_mem_client_init();

	return ret;
}

static inline u32 mlu_pci_dev_id(struct pci_dev *pdev)
{
	return ((pdev->bus->number << 8) | pdev->devfn);
}

static struct bus_ops pci_bus_ops = {
	.dma = cn_pci_dma,
	.dma_remote = cn_pci_dma_remote,
	.dma_async = cn_pci_dma_async,
	.dma_kernel = cn_pci_dma_kernel,
	.dma_cfg = cn_pci_dma_cfg,
	.dma_kernel_cfg = cn_pci_dma_kernel_cfg,
	.boot_image = cn_pci_boot_image,
	.check_image = cn_pci_check_image,
	.dma_p2p = cn_pci_dma_p2p,
	.dma_p2p_async = cn_pci_dma_p2p_async,
	.force_p2p_xchg = cn_pci_force_p2p_xchg,
	.dma_abort = cn_pci_dma_abort,
	.dma_async_message_process = cn_pci_dma_async_message_process,
	.dma_p2p_able = cn_pci_dma_p2p_able,
	.get_p2p_able_info = cn_pci_get_p2p_able_info,
	.get_dma_info = cn_pci_get_dma_info,
	.get_bar_info = cn_pci_get_bar_info,
	.copy_to_usr_fromio = cn_pci_copy_to_usr_fromio,
	.copy_from_usr_toio = cn_pci_copy_from_usr_toio,
	.get_async_htable = cn_pci_get_async_htable,
	.mem_read32 = cn_pci_mem_read32,
	.mem_write32 = cn_pci_mem_write32,
	.reg_write32 = cn_pci_reg_write32,
	.reg_read32 = cn_pci_reg_read32,
	.bar_copy_h2d = cn_pci_bar_write,
	.bar_copy_d2h = cn_pci_bar_read,
	.mem_mb = cn_pci_mb,
	.check_available = cn_pci_check_available,
	.get_mem_cnt = cn_pci_get_mem_cnt,
	.get_mem_base = cn_pci_get_mem_base,
	.get_mem_size = cn_pci_get_mem_size,
	.get_mem_phyaddr = cn_pci_get_mem_phyaddr,
	.get_mem_type = cn_pci_get_mem_type,
	.get_device_addr = cn_pci_get_device_addr,
	.get_reg_size = cn_pci_get_reg_size,
	.get_reg_base = cn_pci_get_reg_base,
	.get_reg_phyaddr = cn_pci_get_reg_phyaddr,
	.soft_reset = cn_pci_soft_reset,
	.enable_irq = cn_pci_enable_irq,
	.disable_irq = cn_pci_disable_irq,
	.disable_all_irqs = cn_pci_disable_all_irqs,
	.register_interrupt = cn_pci_register_interrupt,
	.unregister_interrupt = cn_pci_unregister_interrupt,
	.interrupt_info = cn_pci_interrupt_info,
	.get_irq_by_desc = cn_pci_get_irq_by_desc,
	.show_info = cn_pci_show_info,
	.get_dev = cn_pci_get_dev,
	.get_bus_info = cn_pci_get_info,
	.get_isr_type = cn_pci_get_isr_type,
	.get_bus_lnkcap = cn_pci_get_lnkcap,
	.get_bus_curlnk = cn_pci_get_curlnk,
	.get_vf_idx = cn_pci_get_vf_idx,
	.get_bus_bdf = cn_pci_get_bdf,
	.get_current_bdf = cn_pci_get_current_bdf,
	.check_pdev_virtfn = cn_pci_check_pdev_virtfn,
	.set_bus_bdf = cn_pci_set_bdf,
	.post_init = cn_pci_init,
	.post_exit = cn_pci_exit_cb,
	.late_exit = cn_pci_late_exit_cb,
	.set_bus = cn_pci_set_bus,
	.dma_memset = pci_dma_memset,
	.dma_memset_async = pci_dma_memset_async,
	.inbound_cnt = cn_pci_get_inbound_cnt,
	.outbound_size = cn_pci_get_outbound_size,
	.get_outbound_pages = cn_pci_get_outbound_pages,
	.outbound_able = cn_pci_get_outbound_able,
	.non_align_cnt = cn_pci_get_non_align_cnt,
	.heartbeat_cnt = cn_pci_get_heartbeat_cnt,
	.soft_retry_cnt = cn_pci_get_soft_retry_cnt,
	.get_p2p_exchg_cnt = cn_pci_get_p2p_exchg_cnt,
	.mlu_mem_client_init = cn_pci_mlu_mem_client_init,
};

/*
 *  if private func point not NULL
 *  use private func point overwrite public func point
 */

static struct cn_pcie_set *pcie_set_init(struct pci_dev *pdev,
					const struct pci_device_id *id)
{
	struct cn_pcie_set *new;
	struct cn_pci_info *info = (struct cn_pci_info *)id->driver_data;
	u64 mlu_id;

	new = devm_kzalloc(&pdev->dev, sizeof(*new), GFP_KERNEL);
	if (!new)
		return NULL;

	new->pdev = pdev;
	new->bdf = mlu_pci_dev_id(pdev);
	new->idx = cn_get_mlu_idx(new->bdf, pdev->is_virtfn);
	cn_mim_notify_mim_status(new->bdf, 0);
	sprintf(new->core_name, "Card%d", new->idx);

	dev_set_drvdata(&pdev->dev, new);

	mlu_id = (((u64)id->vendor)|(((u64)id->device) << 16));
	new->id = mlu_id;
	sprintf(&new->dev_name[0], info->dev_name);

	new->node = pcibus_to_node(pdev->bus);
	cn_dev_affinity_init(&new->node);

	new->state = PCIE_STATE_PRE_INIT;
	spin_lock_init(&new->interrupt_lock);
	mutex_init(&new->async_task_hash_lock);
	init_waitqueue_head(&new->task_suspend_wq);

	return new;
}

/**
 * cn_pci_probe()
 *
 * @pdev: pci device pointer
 * @id: pointer to table of device id/id's.
 *
 * Description: This probing function gets called for all PCI devices which
 * match the ID table and are not "owned" by other driver yet. This function
 * gets passed a "struct pci_dev *" for each device whose entry in the ID table
 * matches the device. The probe functions returns zero when the driver choose
 * to take "ownership" of the device or an error code(-ve no) otherwise.
 */
static int cn_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct cn_pci_info *info = (struct cn_pci_info *)id->driver_data;
	struct cn_pcie_set *pcie_set;
	struct cn_bus_set *bus_set;
	int ret = 0;
	u8 type = 0x0;
	u64 mlu_id = (((u64)id->vendor)|(((u64)id->device) << 16));
	pcie_set = pcie_set_init(pdev, id);
	if (!pcie_set)
		return -ENOMEM;

	cn_pci_check_plx_bridge(pcie_set);

	ret = cn_pci_pre_init(pcie_set);
	if (ret)
		return -EFAULT;

	bus_set = cn_bus_set_init((void *)pcie_set, &pdev->dev, &pci_bus_ops, info->setup,
			info->pre_init, info->pre_exit, info->get_resource);
	if (!bus_set) {
		cn_dev_err("cn_bus_set_init failed\n");
		goto exit;
	}

	pcie_set->bus_set = bus_set;
	ret = cn_bus_probe(bus_set, mlu_id, type, pcie_set->idx);
	if (ret) {
		cn_dev_err("cn_bus_probe failed\n");
		goto bus_set_exit;
	}

	return 0;
bus_set_exit:
	pcie_set->bus_set = NULL;
	cn_bus_set_exit(bus_set, &pdev->dev);
exit:
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	return ret;
}

/**
 * cn_pci_remove()
 *
 * @pdev: platform device pointer
 * Description: this function calls the main to free the pci resources
 * and releases the PCI resources.
 */
static void cn_pci_remove(struct pci_dev *pdev)
{
	struct cn_pcie_set *pcie_set;

	pcie_set = dev_get_drvdata(&pdev->dev);
	if (pcie_set == NULL)
		return;

	mlu_mem_client_exit();
	client_devices_unregister(&pdev->dev);

	if (pcie_set->bus_set) {
		if (cn_is_mim_en(pcie_set->bus_set->core) && pcie_set->nums_vf > 0) {
			cn_pci_sriov_cfg_deinit(pcie_set);
		}

		cn_bus_remove(pcie_set->bus_set, pcie_set->id);
		cn_bus_set_exit(pcie_set->bus_set, &pdev->dev);
	}

	cn_pci_exit(pcie_set);
	dev_set_drvdata(&pdev->dev, NULL);
}

static int cn_pci_suspend(struct pci_dev *pdev, pm_message_t state)
{
	return 0;
}

static int cn_pci_resume(struct pci_dev *pdev)
{
	return 0;
}

#if KERNEL_VERSION(3, 0, 0) < LINUX_VERSION_CODE
static int cn_pci_sriov_mem_deinit(struct cn_pcie_set *pcie_set);


static int cn_pci_sriov_mem_init(struct cn_pcie_set *pcie_set, int num_vf)
{
	int i;
	void *domain;
	struct cn_core_set *core = pcie_set->bus_set->core;

	pcie_set->nums_vf = num_vf;

	pcie_set->sriov = cn_kcalloc(num_vf, sizeof(struct cn_pci_sriov), GFP_KERNEL);
	if (!pcie_set->sriov) {
		cn_dev_err("Malloc cn_pci_sriov failed\n");
		return -1;
	}

	for (i = 0; i < num_vf; i++) {
		domain = cn_dm_get_domain(core, DM_FUNC_VF0 + i);
		if (!domain) {
			cn_dev_err("VF:%d get domain fail\n", i);
			goto err_free;
		}

		pcie_set->sriov[i].sriov_dm_ops.init = cn_pci_sriov_init;
		pcie_set->sriov[i].sriov_dm_ops.exit = cn_pci_sriov_exit;
		pcie_set->sriov[i].sriov_dm_ops.reinit = cn_pci_sriov_reinit;
		pcie_set->sriov[i].sriov_dm_ops.stop = cn_pci_sriov_exit;
		pcie_set->sriov[i].domain = domain;
		pcie_set->sriov[i].pcie_set = pcie_set;
		pcie_set->sriov[i].vf_id = i;
		if (pcie_set->ops->sriov_pre_init)
			pcie_set->ops->sriov_pre_init(&pcie_set->sriov[i]);
	}

	dm_register_ops_kernel(core->domain_set, DM_FUNC_VF, PCI,
				&pcie_set->sriov[0].sriov_dm_ops, pcie_set);

	return 0;
err_free:
	if (pcie_set->sriov) {
		cn_kfree(pcie_set->sriov);
		pcie_set->sriov = NULL;
	}
	return -1;
}

static int cn_pci_sriov_mem_deinit(struct cn_pcie_set *pcie_set)
{
	struct cn_core_set *core;
	int i;

	for (i = 0; i < pcie_set->nums_vf; i++) {
		if (!(pcie_set->ops->sriov_later_exit)) {
			cn_dev_pcie_err(pcie_set,
					"sriov_later_exit function is NULL");
			return -EINVAL;
		}
		pcie_set->ops->sriov_later_exit(&pcie_set->sriov[i]);
	}

	if (pcie_set->sriov)
		cn_kfree(pcie_set->sriov);

	pcie_set->sriov = NULL;
	pcie_set->nums_vf = 0;
	if (!pcie_set->bus_set || !pcie_set->bus_set->core) {
		cn_dev_err("Core or bus_set is empty\n");
		return -EINVAL;
	}
	core = pcie_set->bus_set->core;
	dm_unregister_ops_kernel(core->domain_set, DM_FUNC_VF, PCI);

	return 0;
}

static int cn_pci_sriov_cfg_init(struct cn_pcie_set *pcie_set, int numvfs)
{
	int ret = 0;

	if (!(pcie_set && numvfs)) {
		return 0;
	}

	ret = cn_dm_sync_vfs_cfg(pcie_set->bus_set->core, numvfs);
	if (ret < 0)
		return 0;

	if (cn_pci_sriov_mem_init(pcie_set, numvfs)) {
		cn_dev_err("Failed to configure sriov");
		return 0;
	}
	pci_enable_sriov(pcie_set->pdev, numvfs);

	return numvfs;
}

static int cn_pci_sriov_cfg_deinit(struct cn_pcie_set *pcie_set)
{
	if (pcie_set) {
		cn_dm_cancel_vfs_cfg(pcie_set->bus_set->core);
		pci_disable_sriov(pcie_set->pdev);
		cn_pci_sriov_mem_deinit(pcie_set);
	}

	return 0;
}

static int cn_pci_sriov_configure(struct pci_dev *pdev, int numvfs)
{
	struct cn_pcie_set *pcie_set = dev_get_drvdata(&pdev->dev);

	if (!(pcie_set->ops->sriov_support &&
		pcie_set->ops->sriov_support(pcie_set))) {
		cn_dev_pcie_err(pcie_set, "This card don't support sriov");
		return 0;
	}

	if (numvfs > 0) {
		return cn_pci_sriov_cfg_init(pcie_set, numvfs);
	}

	if (cn_host_vf_enable()) {
		if (cn_core_vf_unload(pcie_set->bus_set->core)) {
			return -1;
		}
	}

	return cn_pci_sriov_cfg_deinit(pcie_set);
}
#endif

int shutdown(struct cn_core_set *core);
static void cn_pci_shutdown(struct pci_dev *pdev)
{
	struct cn_pcie_set *pcie_set;
	struct cn_core_set *core;

	pcie_set = dev_get_drvdata(&pdev->dev);
	if (!pcie_set)
		return;

	core = pcie_set->bus_set->core;

	if (!cn_core_is_vf(core)) {
		shutdown(core);
		cn_dev_pcie_info(pcie_set, "set arm shutdown");
	} else {
		cn_pci_remove(pdev);
	}
}

static struct pci_driver cn_pci_driver = {
	.name = DRV_MODULE_NAME,
	.id_table = cn_pci_ids_mlu220_mlu270,
	.probe = cn_pci_probe,
	.remove = cn_pci_remove,
	.suspend = cn_pci_suspend,
	.resume = cn_pci_resume,
	.err_handler = &cn_pci_err_handler,
	.shutdown = cn_pci_shutdown,
};

__attribute__((unused)) static struct pci_driver cn_pci_sriov_driver = {
	.name = DRV_MODULE_NAME,
	.id_table = cn_pci_sriov_ids_mlu220_mlu270,
	.probe = cn_pci_probe,
	.remove = cn_pci_remove,
	.suspend = cn_pci_suspend,
	.resume = cn_pci_resume,
	.err_handler = &cn_pci_err_handler,
#if KERNEL_VERSION(3, 0, 0) < LINUX_VERSION_CODE
	.sriov_configure = cn_pci_sriov_configure,
#endif
};

int cn_pci_drv_init_mlu220_mlu270(void)
{
	return pci_register_driver(&cn_pci_driver);
}

void cn_pci_drv_exit_mlu220_mlu270(void)
{
	pci_unregister_driver(&cn_pci_driver);
}

static void *cn_pci_domain_init(const void *cfg, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = pcie_priv;

	if (pcie_set->state == PCIE_STATE_NORMAL)
		return pcie_priv;

	if (pcie_set->state != PCIE_STATE_SUSPEND) {
		cn_dev_err("state:%d", pcie_set->state);
		return pcie_priv;
	}

	__sync_lock_test_and_set(&pcie_set->state, PCIE_STATE_NORMAL);
	wake_up(&pcie_set->task_suspend_wq);

	return pcie_priv;
}

static int cn_pci_domain_exit(void *pcie_priv)
{
	if (!pcie_priv)
		return 0;

	cn_pci_dma_suspend(pcie_priv);

	return 0;
}

static int cn_pci_guest_save_prepare(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = pcie_priv;

	if (!pcie_priv) {
		cn_dev_pcie_err(pcie_set, "pcie_priv is NULL");
		return -EINVAL;
	}

	cn_pci_dma_suspend(pcie_priv);

	return 0;
}

static int cn_pci_guest_restore_complete(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = pcie_priv;

	if (!pcie_priv) {
		cn_dev_pcie_err(pcie_set, "pcie_priv is NULL");
		return -EINVAL;
	}

	if (pcie_set->state == PCIE_STATE_NORMAL)
		return 0;

	__sync_lock_test_and_set(&pcie_set->state, PCIE_STATE_NORMAL);
	wake_up(&pcie_set->task_suspend_wq);

	return 0;
}

static void *cn_pci_sriov_init(const void *cfg, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = pcie_priv;
	int vf;

	vf = cn_dm_get_vf_func_id(cfg);
	if ((!pcie_set) || (vf < 0) || (vf >= pcie_set->nums_vf))
		return NULL;

	cn_pci_dma_suspend(pcie_priv);

	if (!(pcie_set->ops->sriov_vf_init)) {
		cn_dev_pcie_err(pcie_set, "sriov_vf_init is NULL");
		return NULL;
	}
	pcie_set->ops->sriov_vf_init(&pcie_set->sriov[vf]);

	if (pcie_set->dma_res.channel_mask) {
		__sync_lock_test_and_set(&pcie_set->state, PCIE_STATE_NORMAL);
		wake_up(&pcie_set->task_suspend_wq);
	}

	return (void *)(&pcie_set->sriov[vf]);
}

static void *cn_pci_sriov_reinit(const void *cfg, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = pcie_priv;
	void *ret;
	int vf;

	vf = cn_dm_get_vf_func_id(cfg);
	ret = cn_pci_sriov_init(cfg, pcie_priv);

	cn_dev_pcie_info(pcie_set, "vf:%d PF channel_mask:%x",
		vf, pcie_set->dma_res.channel_mask);

	return ret;
}

static int cn_pci_sriov_exit(void *sriov)
{
	struct cn_pcie_set *pcie_set;

	if (!sriov)
		return 0;

	pcie_set = ((struct cn_pci_sriov *)sriov)->pcie_set;

	cn_pci_dma_suspend((void *)pcie_set);

	if (!(pcie_set->ops->sriov_vf_exit)) {
		cn_dev_pcie_err(pcie_set, "sriov_vf_exit is NULL");
		return -EINVAL;
	}
	pcie_set->ops->sriov_vf_exit((struct cn_pci_sriov *)sriov);

	if (pcie_set->dma_res.channel_mask) {
		__sync_lock_test_and_set(&pcie_set->state, PCIE_STATE_NORMAL);
		wake_up(&pcie_set->task_suspend_wq);
	}

	cn_dev_pcie_info(pcie_set, "vf:%d PF channel_mask:%x",
		((struct cn_pci_sriov *)sriov)->vf_id, pcie_set->dma_res.channel_mask);

	return 0;
}

/*
 * Fix PLX bridge bug, if PLX bridge bar0 overlayed with iova, the bridge
 * will return UC error.
 * PLX 9797's upstrean port bar0 F60[26] = 1 and downstream 760[21] = 1,
 * otherwise upstrean port bar0 F60[26] = 1
 */
static int cn_pci_check_plx_bridge(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_bus *pbus;
	int type;
	int i;
	u32 offset;
	unsigned int value;

	if (!iommu_present(pdev->dev.bus)) {
		return 0;
	}

	while (pdev->bus && pdev->bus->self) {
		pbus = pdev->bus;
		pdev = pbus->self;
		type = pci_pcie_type(pdev);

		/* Not plx bridge or not support old version */
		if ((pdev->vendor != 0x10B5) || (type != PCI_EXP_TYPE_UPSTREAM) ||
			(pdev->device < 0x8700)) {
			continue;
		}

		pci_read_config_dword(pdev, 0xf60, &value);
		if (value & (1 << 26)) {
			continue;
		}

		if (pdev->device == 0x9797) {
			/* set 9797 all downstream 760[21] = 1 */
			u32 *pbar0 = (u32 *)pci_ioremap_bar(pdev, 0);

			if (pbar0) {
				for (i = 0; i < 6; i++) {
					offset = (0x760 + i*0x4000);
					pbar0[offset/4] |= (1 << 21);
					cn_dev_pcie_info(pcie_set, "PLX %x offset:%x value:%x",
						pdev->device, offset, pbar0[offset/4]);
				}

				cn_iounmap((void *)pbar0);
			}
		}

		/* Set upstearm F60[26] = 1 */
		value |= (1 << 26);
		pci_write_config_dword(pdev, 0xf60, value);
		cn_dev_pcie_info(pcie_set, "PLX %x value:%x", pdev->device, value);
	}

	return 0;
}
