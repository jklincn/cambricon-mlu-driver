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

#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/topology.h>
#include <linux/cpumask.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_pci.h"
#include "cndrv_debug.h"

__attribute__((unused)) static void cn_pci_ops_init(struct cn_pci_ops *public, struct cn_pci_ops *private)
{
	int i;
	unsigned int *pub_func = (int *)public;
	unsigned int *pri_func = (int *)private;

	for (i = 0; i < sizeof(*private) / sizeof(*pri_func); i++) {
		if (!pri_func[i])
			pri_func[i] = pub_func[i];
	}
}

static int cn_pci_get_idle_phy_channel(struct pcie_dma_task *task, int *phy, int *fetch_num)
{
	ulong mask;
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int i;
	int j = 0;
	int phy_start, phy_end;

	mask = (ulong)pcie_set->dma_set.dma_phy_channel_mask;
	if (task->cfg.phy_dma_mask)
		mask &= (ulong)task->cfg.phy_dma_mask;

	if (task->transfer->direction == DMA_D2H) {
		phy_start = 0;
		phy_end = pcie_set->dma_set.max_phy_channel / 2;
	} else {
		phy_start = pcie_set->dma_set.max_phy_channel / 2;
		phy_end = pcie_set->dma_set.max_phy_channel;
	}
	for (i = phy_start; i < phy_end; i++) {
		if (!test_bit(i, &mask))
			continue;
		for (j = 0; j < pcie_set->dma_set.dma_fetch_buff; j++) {
			if (pcie_set->dma_set.running_channels[i][j]) {
				continue;
			}

			if (__sync_bool_compare_and_swap(&pcie_set->dma_set.running_channels[i][j],
						0, CHANNEL_ASSIGNED) == 0)
				continue;

			*phy = i;
			*fetch_num = j;
			return 0;
		}
	}

	return -1;
}

static int cn_pci_task_dma_start(struct pcie_dma_task *task)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	struct dma_channel_info *channel;
	int phy;
	int ret;
	int fetch_num;

	if (cn_pci_get_idle_phy_channel(task, &phy, &fetch_num))
		return 0;

	/***
	 * Note:
	 *	Before arrive here, the 'task->ready_fifo' has been checked and
	 *	it's sure is not empty.
	 */
	spin_lock(&task->ready_fifo_lock);
	ret = kfifo_out(&task->ready_fifo, &channel, sizeof(channel));
	if (ret != sizeof(channel)) {
		cn_dev_pcie_err(pcie_set, "bug on: ready kfifo_out fail\n");
		spin_unlock(&task->ready_fifo_lock);
		__sync_lock_test_and_set(&pcie_set->dma_set.running_channels[phy][fetch_num], 0);
		return 0;
	}
	spin_unlock(&task->ready_fifo_lock);

	channel->fetch_command_id = fetch_num;
	__sync_lock_test_and_set(&pcie_set->dma_set.running_channels[phy][fetch_num], (unsigned long)channel);
	if (!__sync_bool_compare_and_swap(&channel->status, CHANNEL_READY, CHANNEL_RUNNING)) {
		cn_dev_pcie_err(pcie_set, "set CHANNEL_RUNNING error:%d", channel->status);
		__sync_lock_test_and_set(&channel->status, CHANNEL_RUNNING);
	}

	if (unlikely(task->cfg.phy_mode)) {
		if (!(pcie_set->ops->dma_bypass_smmu)) {
			cn_dev_pcie_err(pcie_set, "Don't support physical mode dma");
			cn_dev_pcie_err(pcie_set, "Channel:%d is physical mode", phy);
		} else {
			pcie_set->ops->dma_bypass_smmu(phy, 1, pcie_set);
		}
	}

	if (pcie_set->ops->dma_go_command(channel, phy) < 0) {
		__sync_lock_test_and_set(&channel->status, CHANNEL_READY);
		__sync_lock_test_and_set(&pcie_set->dma_set.running_channels[phy][fetch_num], 0);
		spin_lock(&task->ready_fifo_lock);
		ret = kfifo_in(&task->ready_fifo, &channel, sizeof(channel));
		spin_unlock(&task->ready_fifo_lock);
		if (ret != sizeof(channel)) {
			cn_dev_pcie_err(pcie_set, "bug on: ready kfifo_in fail\n");
		}
	} else {
		__sync_fetch_and_add(&pcie_set->dma_set.channel_search_start, 1);
		return 1;
	}

	return 0;
}

__attribute__((unused))
static int cn_pci_task_fair_schedule(struct cn_pcie_set *pcie_set)
{
	struct pcie_dma_task *task;
	int i, index;
	ulong mask;

	mask = (ulong)pcie_set->dma_set.dma_phy_channel_mask;

	while (1) {
		int idle = 0;

		index = pcie_set->dma_set.channel_search_start % DMA_TASK_MAX;
		for (i = 0; i < DMA_TASK_MAX; i++) {
			int ret;

			index = (i + index) % DMA_TASK_MAX;
			task = pcie_set->dma_set.task_table[index];

			/* idle or ctrl+c exit */
			if (task->status == DMA_TASK_IDLE || task->status == DMA_TASK_EXIT)
				continue;

			if (kfifo_is_empty(&task->ready_fifo)) {
				continue;
			}

			ret = cn_pci_task_dma_start(task);
			if (ret) /* at least one task go */
				idle = 1;
		}

		/* all tasks no ready channel need to go or all phy channel is running, break */
		if (idle == 0)
			break;
	}

	return 0;
}

static void cn_pci_total_dma_data(struct dma_channel_info *channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	DMA_DIR_TYPE dir = channel->direction;

	switch (dir) {
	case MEMSET_D8:
	case MEMSET_D16:
	case MEMSET_D32:
	case DMA_D2H:
	case DMA_H2D:
	case DMA_P2P:
		pcie_set->dfx.total_data[dir] += channel->transfer_length;
	break;
	default:
		cn_dev_pcie_err(pcie_set, "Direction error:%d", dir);
	break;
	}
}

__attribute__((unused)) static void cn_pci_dma_complete(int phy_channel, int command_id,
			int status, struct cn_pcie_set *pcie_set)
{
	struct dma_channel_info *channel;
	struct pcie_dma_task *task;
	unsigned int ret;
	size_t local_transfer_len;

	channel = (struct dma_channel_info *)pcie_set->dma_set.running_channels[phy_channel][command_id];
	task = channel->task;

	if (task && task->cfg.phy_mode && pcie_set->ops->dma_bypass_smmu) {
		pcie_set->ops->dma_bypass_smmu(phy_channel, 0, pcie_set);
	}

	if ((channel->status != CHANNEL_RUNNING) || (!task)) {
		cn_dev_pcie_err(pcie_set, "status:%d phy_channel:%d command_id:%d",
			channel->status, phy_channel, command_id);
		__sync_lock_test_and_set(&pcie_set->dma_set.running_channels[phy_channel][command_id], 0);
		return;
	}

	__sync_lock_test_and_set(&channel->status, status);
	if (status == CHANNEL_COMPLETED) {
		cn_pci_total_dma_data(channel);

		/*
		 * save transfer_length to prevent async_free_work from
		 * releasing channel early
		 */
		local_transfer_len = channel->transfer_length;
		if (pcie_set->cfg.af_enable && !channel->shared_flag && (!channel->p2p_sgl)) {
			ret = kfifo_in(&pcie_set->af_fifo, &channel, sizeof(channel));
			if (ret != sizeof(channel))
				cn_dev_pcie_err(pcie_set, "af_fifo kfifo_in fail");
			queue_work(system_unbound_wq, &pcie_set->async_free_work);
		} else {
			ret = kfifo_in(&task->finish_fifo, &channel, sizeof(channel));
			if (ret != sizeof(channel))
				cn_dev_pcie_err(pcie_set, "finish_fifo kfifo_in fail");
		}
		/*
		 * add transfer_len is after kfifo_in because to fix finish_fifo is not empty
		 */
		__sync_fetch_and_add(&task->transfer_len, local_transfer_len);
	} else {
		ret = kfifo_in(&task->finish_fifo, &channel, sizeof(channel));
		if (ret != sizeof(channel))
			cn_dev_pcie_err(pcie_set, "finish_fifo kfifo_in fail");
		__sync_lock_test_and_set(&task->err_flag, 1);
	}

	__sync_lock_test_and_set(&pcie_set->dma_set.running_channels[phy_channel][command_id], 0);
	if ((task->transfer_len >= task->count || task->err_flag) &&
		(!task->spkg_polling_flag)) {
		wake_up_interruptible(&task->channel_wq);
	}
}

__attribute__((unused)) static void cn_pci_reg_write32(void *pcie_priv, unsigned long offset, u32 val)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	if (pcie_set->ops->reg_write32)
		pcie_set->ops->reg_write32(offset, val, pcie_set);
	else
		iowrite32(val, pcie_set->bar0_set.reg_virt_base + offset);
}

__attribute__((unused)) static u32 cn_pci_reg_read32(void *pcie_priv, unsigned long offset)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	if (pcie_set->ops->reg_read32)
		return pcie_set->ops->reg_read32(offset, pcie_set);
	else
		return ioread32(pcie_set->bar0_set.reg_virt_base + offset);
}

__attribute__((unused)) static void cn_pci_reg_write64(struct cn_pcie_set *pcie_set, unsigned long offset, u64 val)
{
	if (pcie_set->ops->reg_write64)
		pcie_set->ops->reg_write64(offset, val, pcie_set);
	else {
		iowrite32(LOWER32(val), pcie_set->bar0_set.reg_virt_base + offset);
		iowrite32(UPPER32(val), pcie_set->bar0_set.reg_virt_base + offset + 4);
	}
}

__attribute__((unused)) static u64 cn_pci_reg_read64(struct cn_pcie_set *pcie_set, unsigned long offset)
{
	if (pcie_set->ops->reg_read64)
		return pcie_set->ops->reg_read64(offset, pcie_set);
	else {
		u64 data;

		data = ioread32(pcie_set->bar0_set.reg_virt_base + offset + 4);
		data <<= 32;
		data |= ioread32(pcie_set->bar0_set.reg_virt_base + offset);
		return data;
	}
}

__attribute__((unused)) static u64 cn_pci_bus_address(struct pci_dev *pdev, int bar)
{
	struct pci_bus_region region;

#if KERNEL_VERSION(3, 10, 107) != LINUX_VERSION_CODE
	pcibios_resource_to_bus(pdev->bus, &region, &pdev->resource[bar]);
#else
	pcibios_resource_to_bus(pdev, &region, &pdev->resource[bar]);
#endif
	return region.start;
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
#define PCIE_RESET_READY_POLL_MS            60000
#define PCIE_LINK_TRAINING_POLL_MS          100
#define PCI_SEC_LNKCTL3                     4
#define PCI_SEC_LNKCTL3_PERFORM_LINK_EQU    0x01

static int cn_pci_dev_wait(struct cn_pcie_set *pcie_set, char *reset_type, int timeout)
{
	int delay = 1;
	u32 id;
	struct pci_dev *dev = pcie_set->pdev;

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
			cn_dev_pcie_warn(pcie_set, "not ready %dms after %s; giving up",
				delay - 1, reset_type);
			return -ENOTTY;
		}

		if (delay > 1000)
			cn_dev_pcie_info(pcie_set, "not ready %dms after %s; waiting",
					delay - 1, reset_type);

		msleep(delay);
		delay *= 2;
		pci_read_config_dword(dev, PCI_COMMAND, &id);
	}

	if (delay > 1000)
		cn_dev_pcie_info(pcie_set, "ready %dms after %s",
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

static int cn_pci_wait_for_polling_link_training(struct cn_pcie_set *pcie_set, int timeout)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_dev *parent = pdev->bus->self;
	int delay = 0;
	u16 link_status;

	pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_status);
	while (link_status & PCI_EXP_LNKSTA_LT) {
		if (delay > timeout) {
			cn_dev_pcie_warn(pcie_set,
				"polling link training timeout %dms", delay);
			return -ENOTTY;
		}

		msleep(delay);
		delay++;
		pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_status);
	}

	cn_dev_pcie_debug(pcie_set, "polling link training ready %dms", delay);

	return 0;
}

static int cn_pci_link_eq_set(void *pcie_priv)
{
	u32 lnk_eq;
	int pos_cap;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pci_dev *parent = pcie_set->pdev->bus->self;

	/* Link Equalization Request Interrupt Enable */
	pos_cap = pci_find_ext_capability(parent, PCI_EXT_CAP_ID_SECPCI);
	pci_read_config_dword(parent, pos_cap + PCI_SEC_LNKCTL3, &lnk_eq);
	lnk_eq |= PCI_SEC_LNKCTL3_PERFORM_LINK_EQU;
	pci_write_config_dword(parent, pos_cap + PCI_SEC_LNKCTL3, lnk_eq);

	cn_dev_pcie_info(pcie_set, "set parent link eq PCI_SEC_LNKCTL3 %#x", lnk_eq);
	return 0;
}

static int cn_pci_retrain_set(void *pcie_priv)
{
	u16 lnk_ctrl;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pci_dev *parent = pcie_set->pdev->bus->self;

	pcie_capability_read_word(parent, PCI_EXP_LNKCTL, &lnk_ctrl);
	lnk_ctrl |=  PCI_EXP_LNKCTL_RL;
	pcie_capability_write_word(parent, PCI_EXP_LNKCTL, lnk_ctrl);

	cn_dev_pcie_info(pcie_set, "set parent PCI_EXP_LNKCTL %#x", lnk_ctrl);
	return 0;
}

__attribute__((unused))
static int cn_pci_change_speed(struct cn_pcie_set *pcie_set, u32 target_speed, u32 target_width)
{
	int ret;
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_dev *parent = pdev->bus->self;
	u16 link_status, lnkctl2;
	u32 current_speed;
	u32 current_width;
	u32 retrain_cnt = 0;
	int pos_cap;
	u32 cor_mask, uncor_mask;
	u32 cor_status, uncor_status;
	int parent_pos_cap;
	u32 parent_cor_mask, parent_uncor_mask;
	u32 parent_cor_status, parent_uncor_status;

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

	cn_dev_pcie_info(pcie_set, "current link speed:%s target link speed:%s",
			PCIE_SPEED_STR(current_speed), PCIE_SPEED_STR(target_speed));
	cn_dev_pcie_info(pcie_set, "current link width:x%d target link width:x%d",
			current_width, target_width);

	if ((current_speed != target_speed) ||
			(current_width != target_width)) {
retry:
		cn_pci_dev_save(pdev);

		/* mask pdev aer */
		pos_cap = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);
		if (pos_cap != 0) {
			pci_read_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, &cor_mask);
			pci_read_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, &uncor_mask);
			pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, 0xffffffff);
			pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, 0xffffffff);
		}
		/* mask parent aer */
		parent_pos_cap = pci_find_ext_capability(parent, PCI_EXT_CAP_ID_ERR);
		if (parent_pos_cap != 0) {
			pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_COR_MASK, &parent_cor_mask);
			pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_MASK, &parent_uncor_mask);
			pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_COR_MASK, 0xffffffff);
			pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_MASK, 0xffffffff);
		}

		/* set pdev target speed */
		ret = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL2,
						&lnkctl2);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "unable to read from PCI config");
			return -1;
		}
		lnkctl2 &= ~PCI_EXP_LNKCTL2_TLS;
		lnkctl2 |= target_speed;
		ret = pcie_capability_write_word(pdev,
				PCI_EXP_LNKCTL2, lnkctl2);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "unable to write to PCI config");
			return -1;
		}
		cn_dev_pcie_info(pcie_set, "setting pdev target link speed PCI_EXP_LNKCTL2 %#x", lnkctl2);
		if (!cn_pci_wait_for_pending_transaction(pdev))
			cn_dev_pcie_err(pcie_set, "timed out waiting for pending transaction");

		/* set eq */
		if (target_speed >= 3) {
			cn_pci_link_eq_set(pcie_set);
		}

		/* set parent target speed */
		ret = pcie_capability_read_word(parent, PCI_EXP_LNKCTL2, &lnkctl2);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "unable to read from PCI config");
			return -1;
		}
		lnkctl2 &= ~PCI_EXP_LNKCTL2_TLS;
		lnkctl2 |= target_speed;
		ret = pcie_capability_write_word(parent, PCI_EXP_LNKCTL2, lnkctl2);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "unable to write to PCI config");
			return -1;
		}
		cn_dev_pcie_info(pcie_set, "setting parent target link speed PCI_EXP_LNKCTL2 %#x", lnkctl2);
		if (!cn_pci_wait_for_pending_transaction(parent))
			cn_dev_pcie_err(pcie_set, "timed out waiting for pending transaction");

		cn_pci_wait_for_polling_link_training(pcie_set, PCIE_LINK_TRAINING_POLL_MS);

		/* inquire parent link status*/
		pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_status);
		current_speed = link_status & PCI_EXP_LNKSTA_CLS;
		current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
		if ((current_speed == target_speed) && (current_width == target_width))
			goto aer_restore;

		/* set retrain */
		cn_pci_retrain_set(pcie_set);
		retrain_cnt++;
		cn_pci_wait_for_polling_link_training(pcie_set, PCIE_LINK_TRAINING_POLL_MS);

aer_restore:
		/* pdev aer mask restore */
		if (pos_cap != 0) {
			pci_read_config_dword(pdev, pos_cap + PCI_ERR_COR_STATUS, &cor_status);
			pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_STATUS, cor_status);
			pci_read_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_STATUS, &uncor_status);
			pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_STATUS, uncor_status);
			pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, cor_mask);
			pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, uncor_mask);
		}
		/* parent aer mask restore */
		if (parent_pos_cap != 0) {
			pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_COR_STATUS, &parent_cor_status);
			pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_COR_STATUS, parent_cor_status);
			pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_STATUS, &parent_uncor_status);
			pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_STATUS, parent_uncor_status);
			pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_COR_MASK, parent_cor_mask);
			pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_MASK, parent_uncor_mask);
		}

		cn_pci_dev_restore(pcie_set->pdev);

		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
		current_speed = link_status & PCI_EXP_LNKSTA_CLS;
		current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

		cn_dev_pcie_info(pcie_set, "PCIe link change speed to %s", PCIE_SPEED_STR(current_speed));
		cn_dev_pcie_info(pcie_set, "PCIe link change width to x%d", current_width);

		if (retrain_cnt >= 20) {
			cn_dev_pcie_err(pcie_set, "pcie change speed fail");
			return -1;
		}

		if ((current_speed != target_speed) ||
				(current_width != target_width))
			goto retry;
	}

	return 0;
}

__attribute__((unused))
static int cn_pci_set_cspeed(unsigned int cspeed, void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pci_dev *pdev = pcie_set->pdev;
	u16 link_status;
	u32 current_speed;
	u32 current_width;
	u32 target_speed;

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	target_speed = cspeed;

	cn_dev_pcie_info(pcie_set, "PCIe link speed is %s", PCIE_SPEED_STR(current_speed));
	cn_dev_pcie_info(pcie_set, "PCIe link width is x%d", current_width);
	cn_dev_pcie_info(pcie_set, "PCIe target speed is %s", PCIE_SPEED_STR(cspeed));

	return cn_pci_change_speed(pcie_set, target_speed, current_width);
}

__attribute__((unused))
static int cn_pci_chip_reset(void *pcie_priv, bool reset)
{
	struct cn_pcie_set *pcie_set;
	int ret = 0;

	pcie_set = (struct cn_pcie_set *)pcie_priv;

	cn_dev_pcie_info(pcie_set, "pcie chip reset");

	if (reset) {
		if (pcie_set->ops->chip_reset) {
			ret = pcie_set->ops->chip_reset(pcie_set);
		} else {
			cn_dev_pcie_err(pcie_set, "chip_reset function is NULL");
			return -EINVAL;
		}
	}

	__sync_fetch_and_add(&pcie_set->dfx.heartbeat_cnt, 1);

	return ret;
}

__attribute__((unused))
static int cn_pci_soft_reset(void *pcie_priv, bool reset)
{
	struct cn_pcie_set *pcie_set;
	struct pci_dev *pdev;
	u16 slot_ctrl, slot_ctrl_orig, slot_sta;
	int rc;

	pcie_set = (struct cn_pcie_set *)pcie_priv;
	pdev = pcie_set->pdev->bus->self;
	cn_dev_pcie_info(pcie_set, "pcie soft reset");

	cn_pci_dev_save(pcie_set->pdev);

	if (!cn_pci_wait_for_pending_transaction(pcie_set->pdev))
		cn_dev_pcie_err(pcie_set,
			"timed out waiting for pending transaction");

	if (!(pcie_set->ops->soft_reset)) {
		cn_dev_pcie_err(pcie_set, "soft_reset function is NULL");
		return -EINVAL;
	}

	if (reset) {
		pcie_capability_read_word(pdev, PCI_EXP_SLTCTL, &slot_ctrl_orig);
		slot_ctrl = slot_ctrl_orig & ~(PCI_EXP_SLTCTL_HPIE);
		/*fix hotplug bug*/
		pcie_capability_write_word(pdev, PCI_EXP_SLTCTL, slot_ctrl);
		smp_mb();

		pcie_set->ops->soft_reset(pcie_set);
	}


	/*
	 * Per PCIe r4.0, sec 6.6.2, a device must complete an FLR within
	 * 100ms, but may silently discard requests while the FLR is in
	 * progress.  Wait 100ms before trying to access the device.
	 */
	msleep(100);

	rc = cn_pci_dev_wait(pcie_set, "soft reset", PCIE_RESET_READY_POLL_MS);

	cn_pci_dev_restore(pcie_set->pdev);

	if (reset) {
		pcie_capability_read_word(pdev, PCI_EXP_SLTSTA, &slot_sta);
		cn_dev_pcie_info(pcie_set, "pcie slot sta 0x%x\n", slot_sta);
		pcie_capability_write_word(pdev, PCI_EXP_SLTSTA, slot_sta);
		/* fix hotplug bug */
		smp_mb();
		pcie_capability_write_word(pdev, PCI_EXP_SLTCTL, slot_ctrl_orig);
	}

	if (!(pcie_set->ops->ddr_set_done)) {
		cn_dev_pcie_err(pcie_set, "ddr_set_done is NULL");
		return -EINVAL;
	}

	if (reset)
		rc = pcie_set->ops->ddr_set_done(pcie_set);

	__sync_fetch_and_add(&pcie_set->dfx.heartbeat_cnt, 1);

	return rc;
}

__attribute__((unused))
static int cn_pci_bug_report_pre_check(struct cn_pcie_set *pcie_set)
{
	if (pcie_set->dfx.fp == NULL)
		return 1;
	else
		return 0;
}

#define PCIE_FILE_WRITE_BLOCK (4UL * 1024)
__attribute__((unused))
static int cn_pci_print_to_file(struct cn_pcie_set *pcie_set, const char *pstr, ...)
{
	ssize_t nwrite, w_size;
	ssize_t left;
	char *buf = NULL;
	va_list args;
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	mm_segment_t fs;
#endif

	if (pcie_set->dfx.fp == NULL)
		return -EINVAL;

	va_start(args, pstr);
	buf = kvasprintf(GFP_ATOMIC, pstr, args);
	va_end(args);
	if (!buf) {
		return 0;
	}

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	fs = get_fs();
	set_fs(KERNEL_DS);
#endif

	left = strlen(buf);
	while (left > 0) {
		w_size = min_t(ssize_t, left, PCIE_FILE_WRITE_BLOCK);
		nwrite = cn_fs_write(pcie_set->dfx.fp, buf,
				w_size, &pcie_set->dfx.log_file_pos);
		if ((nwrite <= 0) || (nwrite != w_size))
			goto out;
		left -= w_size;
	}
out:
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	set_fs(fs);
#endif
	kfree(buf);

	return 0;
}

#define cn_dev_pcie_bug_report(pcie, str, arg...) \
({ \
	if (!cn_pci_bug_report_pre_check(pcie)) { \
		cn_pci_print_to_file(pcie_set, str " \n", ##arg); \
	} else { \
		cn_dev_pcie_info(pcie, str, ##arg); \
	} \
})

static int cn_pci_dump_dma_info(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pcie_dma_task *task;
	unsigned int index = 0;
	struct dma_channel_info **list;
	struct dma_channel_info *channel;
	int cnt, order, i;

	cn_dev_pcie_bug_report(pcie_set, "***** start dump task info *****");
	for (index = 0; index < DMA_TASK_MAX; index++) {
		task = pcie_set->dma_set.task_table[index];
		if (task->status != DMA_TASK_IDLE) {
			cn_dev_pcie_bug_report(pcie_set, "***** task_pointer %p *****", task);
			cn_dev_pcie_bug_report(pcie_set, "transfer host_addr     %#llx", (u64)task->transfer->ca);
			cn_dev_pcie_bug_report(pcie_set, "transfer device_addr   %#llx", task->transfer->ia);
			cn_dev_pcie_bug_report(pcie_set, "transfer direction     %d", task->transfer->direction);
			cn_dev_pcie_bug_report(pcie_set, "transfer size          %#lx", task->transfer->size);
			cn_dev_pcie_bug_report(pcie_set, "status                 %ld", task->status);
			cn_dev_pcie_bug_report(pcie_set, "dma_type               %d", task->dma_type);
			cn_dev_pcie_bug_report(pcie_set, "dma_async              %d", task->dma_async);
			cn_dev_pcie_bug_report(pcie_set, "transfer_len           %#lx", task->transfer_len);
			cn_dev_pcie_bug_report(pcie_set, "err_flag               %d", task->err_flag);
			cn_dev_pcie_bug_report(pcie_set, "spkg_polling_flag      %d", task->spkg_polling_flag);
			cn_dev_pcie_bug_report(pcie_set, "p2p_linear_remap       %d", task->p2p_linear_remap);
			cn_dev_pcie_bug_report(pcie_set, "p2p_trans_type         %d", task->p2p_trans_type);
		}
	}

	cn_dev_pcie_bug_report(pcie_set, "***** start dump priv channel info *****");
	for (index = 0; index < DMA_TASK_MAX; index++) {
		task = pcie_set->dma_set.task_table[index];
		for (order = pcie_set->dma_set.max_desc_order - 1; order >= 0; order--) {
			list = task->priv_order_table[order].list;
			cnt = task->priv_order_table[order].number;

			for (i = 0; i < cnt; i++) {
				channel = list[i];
				if (channel->status != CHANNEL_IDLE) {
					cn_dev_pcie_bug_report(pcie_set, "***** channel_pointer %p *****", channel);
					cn_dev_pcie_bug_report(pcie_set, "task_pointer           %p", channel->task);
					cn_dev_pcie_bug_report(pcie_set, "host_addr              %#lx", channel->cpu_addr);
					cn_dev_pcie_bug_report(pcie_set, "device_addr            %#llx", channel->ram_addr);
					cn_dev_pcie_bug_report(pcie_set, "direction              %d", channel->direction);
					cn_dev_pcie_bug_report(pcie_set, "size                   %#lx", channel->transfer_length);
					cn_dev_pcie_bug_report(pcie_set, "status                 %d", channel->status);
					cn_dev_pcie_bug_report(pcie_set, "dma_type               %d", channel->dma_type);
					cn_dev_pcie_bug_report(pcie_set, "desc_device_va         %#llx", channel->desc_device_va);
					cn_dev_pcie_bug_report(pcie_set, "desc_size              %#lx", channel->desc_size);
					cn_dev_pcie_bug_report(pcie_set, "desc_len               %d", channel->desc_len);
					cn_dev_pcie_bug_report(pcie_set, "fetch_command_id       %d", channel->fetch_command_id);
				}
			}
		}
	}

	cn_dev_pcie_bug_report(pcie_set, "***** start dump share channel info *****");
	for (i = 0; i < pcie_set->dma_set.shared_channel_cnt;  i++) {
		channel = pcie_set->dma_set.shared_channel_list[i];
		if (channel->status != CHANNEL_IDLE) {
			cn_dev_pcie_bug_report(pcie_set, "***** channel_pointer %p *****", channel);
			cn_dev_pcie_bug_report(pcie_set, "task_pointer           %p", channel->task);
			cn_dev_pcie_bug_report(pcie_set, "host_addr              %#lx", channel->cpu_addr);
			cn_dev_pcie_bug_report(pcie_set, "device_addr            %#llx", channel->ram_addr);
			cn_dev_pcie_bug_report(pcie_set, "direction              %d", channel->direction);
			cn_dev_pcie_bug_report(pcie_set, "size                   %#lx", channel->transfer_length);
			cn_dev_pcie_bug_report(pcie_set, "status                 %d", channel->status);
			cn_dev_pcie_bug_report(pcie_set, "dma_type               %d", channel->dma_type);
			cn_dev_pcie_bug_report(pcie_set, "desc_device_va         %#llx", channel->desc_device_va);
			cn_dev_pcie_bug_report(pcie_set, "desc_size              %#lx", channel->desc_size);
			cn_dev_pcie_bug_report(pcie_set, "desc_len               %d", channel->desc_len);
			cn_dev_pcie_bug_report(pcie_set, "fetch_command_id       %d", channel->fetch_command_id);
		}
	}

	cn_dev_pcie_bug_report(pcie_set, "***** start dump phy channel info *****");
	for (index = 0; index < pcie_set->dma_set.max_phy_channel; index++) {
		for (i = 0; i < pcie_set->dma_set.dma_fetch_buff; i++) {
			if (pcie_set->dma_set.running_channels[index][i]) {
				channel = (struct dma_channel_info *)pcie_set->dma_set.running_channels[index][i];
				cn_dev_pcie_bug_report(pcie_set, "[%d][%d] channel_pointer %p", index, i, channel);
			}
		}
	}

	return 0;
}

__attribute__((unused))
static int cn_pci_get_bug_report(void *pcie_priv, unsigned long action, void *fp)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	pcie_set->dfx.fp = (struct file *)fp;
	pcie_set->dfx.log_file_pos = 0;

	if (pcie_set->ops->pcie_debug_dump_reg)
		pcie_set->ops->pcie_debug_dump_reg(pcie_set);

	cn_pci_dump_dma_info(pcie_set);

	pcie_set->dfx.fp = NULL;
	pcie_set->dfx.log_file_pos = 0;

	return 0;
}
