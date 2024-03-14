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

#include <linux/pci.h>
#include <linux/topology.h>
#include <linux/cpumask.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_pci.h"
#include "cndrv_debug.h"
#include "cndrv_affinity.h"

static int cn_pci_msi_enable(struct cn_pcie_set *pcie_set)
{
	int ret, pos, i;
	u32 value;

#if KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE
	ret = pci_alloc_irq_vectors(pcie_set->pdev, pcie_set->irq_num,
		pcie_set->irq_num, PCI_IRQ_MSI);
#elif KERNEL_VERSION(3, 10, 107) == LINUX_VERSION_CODE
	ret = pci_enable_msi_block(pcie_set->pdev, pcie_set->irq_num);
#else
	ret = pci_enable_msi_range(pcie_set->pdev, pcie_set->irq_num,
		pcie_set->irq_num);
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)*/
	if (ret < 0) {
		cn_dev_pcie_err(pcie_set,
				"alloc %d msi Failed\n", pcie_set->irq_num);
		return -1;
	}

	pos = pci_find_capability(pcie_set->pdev, PCI_CAP_ID_MSI);
	pcie_set->msi_pos = pos;
	for (i = 0; i < 24; i += 4)
		pci_read_config_dword(pcie_set->pdev, pos + i, &value);

	pcie_set->irq = pcie_set->pdev->irq;

	ret = cn_get_cpu_affinity(pcie_set->node, &pcie_set->cpu_mask);
	if (ret) {
		cn_dev_pcie_info(pcie_set,
				"get cpu affinity failed, can't set cpu affinity\n");
		pcie_set->affinity = 0;
	} else
		pcie_set->affinity = 1;

	for (i = 0; i < pcie_set->irq_num; i++) {
		if (request_irq(pcie_set->irq + i, pcie_set->ops->msi_isr, IRQF_SHARED,
				"cndrv-msi", pcie_set))
			return -1;

		if (pcie_set->affinity == 1) {
			cn_irq_set_affinity(pcie_set->irq + i, &pcie_set->cpu_mask);
		}
	}

	if (pcie_set->ops->isr_hw_enable)
		pcie_set->ops->isr_hw_enable(pcie_set);

	return 0;
}

static int cn_pci_msi_disable(struct cn_pcie_set *pcie_set)
{
	int i;

	if (pcie_set->ops->isr_hw_disable)
		pcie_set->ops->isr_hw_disable(pcie_set);

	for (i = 0; i < pcie_set->irq_num; i++) {
		if (pcie_set->affinity == 1)
			cn_irq_set_affinity(pcie_set->irq + i, NULL);
		free_irq(pcie_set->irq + i, (void *)pcie_set);
		cn_dev_info("free_irq:%d", pcie_set->irq + i);
	}

	if (pcie_set->affinity == 1)
		cn_put_cpu_affinity(pcie_set->node, &pcie_set->cpu_mask);
	pci_disable_msi(pcie_set->pdev);

	return 0;
}

static int cn_pci_msix_enable(struct cn_pcie_set *pcie_set)
{
	int ret;
	unsigned int i, pos;
	unsigned int value;

	for (i = 0; i < pcie_set->irq_num; i++)
		pcie_set->msix_entry_buf[i].entry = i;

#if KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE
	ret = pci_alloc_irq_vectors(pcie_set->pdev, pcie_set->irq_num,
		pcie_set->irq_num, PCI_IRQ_MSIX);

	for (i = 0; i < pcie_set->irq_num; i++)
		pcie_set->msix_entry_buf[i].vector = pci_irq_vector(pcie_set->pdev, i);
#elif KERNEL_VERSION(3, 10, 107) == LINUX_VERSION_CODE
	ret = pci_enable_msix(pcie_set->pdev, pcie_set->msix_entry_buf, pcie_set->irq_num);
#else
	ret = pci_enable_msix_range(pcie_set->pdev, pcie_set->msix_entry_buf,
		pcie_set->irq_num, pcie_set->irq_num);
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)*/

	if (ret < 0) {
		cn_dev_pcie_err(pcie_set, "pci_enable_msix_range error");
		return -1;
	}

	pos = pci_find_capability(pcie_set->pdev, PCI_CAP_ID_MSIX);

	for (i = 0; i < 24; i += 4) {
		pci_read_config_dword(pcie_set->pdev, pos + i, &value);
		cn_dev_pcie_debug(pcie_set,
			"after pci enable msi block:offset:%#x value:%#x",
			pos + i, value);
	}

	pcie_set->irq = pcie_set->pdev->irq;

	ret = cn_get_cpu_affinity(pcie_set->node, &pcie_set->cpu_mask);
	if (ret) {
		cn_dev_pcie_info(pcie_set,
				"get cpu affinity failed, can't set cpu affinity\n");
		pcie_set->affinity = 0;
	} else
		pcie_set->affinity = 1;

	for (i = 0; i < pcie_set->irq_num; i++) {
		if (request_irq(pcie_set->msix_entry_buf[i].vector,
				pcie_set->ops->msix_isr, 0, "cndrv-msix", pcie_set)) {
			cn_dev_pcie_info(pcie_set,
				"request index %d irq is: %d failed.",
				i, pcie_set->msix_entry_buf[i].vector);
			return -1;
		}

		if (pcie_set->affinity == 1) {
			cn_irq_set_affinity(pcie_set->msix_entry_buf[i].vector, &pcie_set->cpu_mask);
		}
		cn_dev_pcie_debug(pcie_set, "request_irq vector:%x success",
			pcie_set->msix_entry_buf[i].vector);
	}

	if (pcie_set->ops->isr_hw_enable)
		pcie_set->ops->isr_hw_enable(pcie_set);

	return 0;
}

static int cn_pci_msix_disable(struct cn_pcie_set *pcie_set)
{
	int i;

	if (pcie_set->ops->isr_hw_disable)
		pcie_set->ops->isr_hw_disable(pcie_set);

	for (i = 0; i < pcie_set->irq_num; i++) {
		if (pcie_set->affinity == 1)
			cn_irq_set_affinity(pcie_set->msix_entry_buf[i].vector, NULL);
		free_irq(pcie_set->msix_entry_buf[i].vector, pcie_set);
		cn_dev_info("free_irq:%x", pcie_set->msix_entry_buf[i].vector);
	}

	if (pcie_set->affinity == 1)
		cn_put_cpu_affinity(pcie_set->node, &pcie_set->cpu_mask);
	pci_disable_msix(pcie_set->pdev);

	return 0;
}

static int cn_pci_intx_enable(struct cn_pcie_set *pcie_set)
{
	int ret;

	pcie_set->irq = pcie_set->pdev->irq;

	ret = cn_get_cpu_affinity(pcie_set->node, &pcie_set->cpu_mask);
	if (ret) {
		cn_dev_pcie_info(pcie_set,
				"get cpu affinity failed, can't set cpu affinity\n");
		pcie_set->affinity = 0;
	} else
		pcie_set->affinity = 1;

	if (pcie_set->affinity == 1) {
		cn_irq_set_affinity(pcie_set->irq, &pcie_set->cpu_mask);
	}

	if (request_irq(pcie_set->irq, pcie_set->ops->intx_isr, IRQF_SHARED,
		"cndrv-intx", pcie_set)) {
		cn_dev_pcie_err(pcie_set, "request intx irq is: %d failed.",
			pcie_set->irq);
		return -1;
	}

	if (pcie_set->ops->isr_hw_enable)
		pcie_set->ops->isr_hw_enable(pcie_set);

	return 0;
}

static int cn_pci_intx_disable(struct cn_pcie_set *pcie_set)
{
	if (pcie_set->ops->isr_hw_disable)
		pcie_set->ops->isr_hw_disable(pcie_set);

	if (pcie_set->affinity == 1)
		cn_irq_set_affinity(pcie_set->irq, NULL);
	free_irq(pcie_set->irq, (void *)pcie_set);

	if (pcie_set->affinity == 1)
		cn_put_cpu_affinity(pcie_set->node, &pcie_set->cpu_mask);
	cn_dev_info("free_irq:%d", pcie_set->irq);
	return 0;
}

static int (*isr_enable_func[3])(struct cn_pcie_set *) = {
	cn_pci_msi_enable,
	cn_pci_msix_enable,
	cn_pci_intx_enable
};

static int (*isr_disable_func[3])(struct cn_pcie_set *) = {
	cn_pci_msi_disable,
	cn_pci_msix_disable,
	cn_pci_intx_disable
};

__attribute__((unused)) static void cn_pci_unregister_interrupt(int hw_irq, struct cn_pcie_set *pcie_set)
{
	unsigned long flags;

	if (hw_irq < 0) {
		cn_dev_pcie_err(pcie_set,
			"pcie_gic hw_irq %d can not less than zero", hw_irq);
		return;
	}

	spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
	pcie_set->irq_desc[hw_irq].handler = NULL;
	if (!(pcie_set->ops->gic_mask)) {
		spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);
		cn_dev_pcie_err(pcie_set, "gic_mask is NULL");
		return;
	}
	pcie_set->ops->gic_mask(hw_irq, pcie_set);
	spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);
}

__attribute__((unused)) static int cn_pci_register_interrupt(int hw_irq,
		interrupt_cb_t handler, void *data, struct cn_pcie_set *pcie_set)
{
	unsigned long flags;

	if (hw_irq < 0) {
		cn_dev_pcie_err(pcie_set,
			"pcie_gic hw_irq %d can not less than zero", hw_irq);
		return -1;
	}

	spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
	if (pcie_set->irq_desc[hw_irq].handler != NULL) {
		cn_dev_pcie_err(pcie_set,
			"pcie_gic %d is already registered", hw_irq);
		spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);
		return -EINVAL;
	}
	pcie_set->irq_desc[hw_irq].handler = handler;
	pcie_set->irq_desc[hw_irq].data = data;
	pcie_set->irq_desc[hw_irq].occur_count = 0;

	spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);

	return 0;
}

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

__attribute__((unused)) static int pcie_register_bar(struct cn_pcie_set *pcie_set)
{
	int ret;
	struct bar_resource *bar;

	if (!(pcie_set->ops->enable_pf_bar)) {
		cn_dev_pcie_err(pcie_set, "enable_pf_bar is NULL");
		return -EINVAL;
	}

	ret = pcie_set->ops->enable_pf_bar(pcie_set);
	if (ret) {
		cn_dev_err("enable pf bar failed!");
		return ret;
	}

	if (!cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		if (pcie_set->ops->enable_vf_bar) {
			ret = pcie_set->ops->enable_vf_bar(pcie_set);
			if (ret)
				cn_dev_debug("enable Above 4G decoding in BIOS");
		}
	}

	list_for_each_entry(bar, &pcie_set->bar_resource_head, list) {
		cn_dev_debug("bar_type=%d, bar_index=%d, bar.base=%px, bar.sz=%llx",
			bar->type, bar->index, bar->base, bar->size);
	}

	return 0;
}

__attribute__((unused)) static void pcie_unregister_bar(struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar, *tmp;

	list_for_each_entry_safe(bar, tmp, &pcie_set->bar_resource_head, list) {
		if (bar->base) {
			cn_iounmap((void *)bar->base);
			list_del(&bar->list);
			cn_kfree(bar);
		}
	}

	if (pcie_set->ops->disable_vf_bar)
		pcie_set->ops->disable_vf_bar(pcie_set);
}

__attribute__((unused)) static int cn_pci_channel_dma_start(struct cn_pcie_set *pcie_set)
{
	int i = 0;
	int phy;
	int index;
	struct dma_channel_info *channel;
	struct pcie_dma_task *task;
	ulong mask;
	int success;

	for (i = 0; i < pcie_set->max_channel; i++) {
		mask = (ulong)(pcie_set->dma_res.channel_mask &
			(~pcie_set->channel_run_flag));
		if (!mask) {
			break;
		}

		index = (pcie_set->channel_search_start + i) % pcie_set->max_channel;
		channel = &pcie_set->dma_channels[index];

		if (channel->status != CHANNEL_READY) {
			continue;
		}

		if (!__sync_bool_compare_and_swap(&channel->status, CHANNEL_READY,
			CHANNEL_LOCK)) {
			continue;
		}

		success = 0;
		task = channel->task;
		mask = (ulong)(pcie_set->dma_res.channel_mask &
			(~pcie_set->channel_run_flag));
		if (task->cfg.phy_dma_mask)
			mask &= (ulong)task->cfg.phy_dma_mask;

		for_each_set_bit(phy, &mask, pcie_set->max_phy_channel) {
			if (__sync_bool_compare_and_swap(&pcie_set->running_channels[phy],
					0, (unsigned long)channel) == 0)
				continue;

			__sync_lock_test_and_set(&channel->status, CHANNEL_RUNNING);
			__sync_fetch_and_or(&pcie_set->channel_run_flag, (1 << phy));

			if (!(pcie_set->ops->dma_go_command)) {
				cn_dev_pcie_err(pcie_set, "dma_go is NULL");
				return -EINVAL;
			}

			if (unlikely(task->cfg.phy_mode)) {
				if (!(pcie_set->ops->dma_bypass_smmu)) {
					cn_dev_pcie_err(pcie_set, "Don't support physical mode dma");
					cn_dev_pcie_err(pcie_set, "Channel:%d is physical mode", index);
				} else {
					pcie_set->ops->dma_bypass_smmu(phy, 1, pcie_set);
				}
			}

			if (pcie_set->ops->dma_go_command(channel, phy) < 0) {
				__sync_fetch_and_and(&pcie_set->channel_run_flag, ~(1 << phy));
				__sync_lock_test_and_set(&channel->status, CHANNEL_LOCK);
				__sync_lock_test_and_set(&pcie_set->running_channels[phy], 0);
				break;
			}

			success = 1;
			break;
		}

		if (success) {
			__sync_fetch_and_add(&pcie_set->channel_search_start, 1);
		} else {
			__sync_lock_test_and_set(&channel->status, CHANNEL_READY);
		}
	}

	return 0;
}

static void cn_pci_total_dma_data(struct dma_channel_info *channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	DMA_DIR_TYPE dir = channel->direction;

	switch (dir) {
	case DMA_D2H:
	case DMA_H2D:
	case DMA_P2P:
		pcie_set->total_data[dir] += channel->transfer_length;
	break;
	default:
		cn_dev_pcie_err(pcie_set, "Direction error:%d", dir);
	break;
	}
}

__attribute__((unused)) static void cn_pci_dma_complete(int phy_channel,
			int status, struct cn_pcie_set *p_set)
{
	struct dma_channel_info *channel;
	struct pcie_dma_task *task;

	channel = (struct dma_channel_info *)p_set->running_channels[phy_channel];
	task = channel->task;

	if (task && task->cfg.phy_mode && p_set->ops->dma_bypass_smmu) {
		p_set->ops->dma_bypass_smmu(phy_channel, 0, p_set);
	}

	__sync_lock_test_and_set(&p_set->running_channels[phy_channel], 0);
	if ((channel->status != CHANNEL_RUNNING) || (!task)) {
		cn_dev_pcie_err(p_set, "channel:%d status:%d phy_c:%d",
			channel->id, channel->status, phy_channel);
		return;
	}

	__sync_fetch_and_or(&task->channel_done_flag, (1ul << channel->id));
	if (status == CHANNEL_COMPLETED)
		cn_pci_total_dma_data(channel);

	wake_up_interruptible(&task->channel_wq);
	__sync_lock_test_and_set(&channel->status, status);
}

__attribute__((unused)) static void cn_pci_reg_write32(struct cn_pcie_set *pcie_set, unsigned long offset, u32 val)
{
	if (pcie_set->ops->reg_write32) /* c30 rewrite reg_write32 */
		pcie_set->ops->reg_write32(offset, val, pcie_set);
	else
		iowrite32(val, pcie_set->reg_virt_base + offset);
}

__attribute__((unused)) static u32 cn_pci_reg_read32(struct cn_pcie_set *pcie_set, unsigned long offset)
{
	if (pcie_set->ops->reg_read32)
		return pcie_set->ops->reg_read32(offset, pcie_set);
	else
		return ioread32(pcie_set->reg_virt_base + offset);
}

__attribute__((unused)) static void cn_pci_reg_write64(struct cn_pcie_set *pcie_set, unsigned long offset, u64 val)
{
	if (pcie_set->ops->reg_write64)
		pcie_set->ops->reg_write64(offset, val, pcie_set);
	else {
		iowrite32(LOWER32(val), pcie_set->reg_virt_base + offset);
		iowrite32(UPPER32(val), pcie_set->reg_virt_base + offset + 4);
	}
}

__attribute__((unused)) static u64 cn_pci_reg_read64(struct cn_pcie_set *pcie_set, unsigned long offset)
{
	if (pcie_set->ops->reg_read64)
		return pcie_set->ops->reg_read64(offset, pcie_set);
	else {
		u64 data;

		data = ioread32(pcie_set->reg_virt_base + offset + 4);
		data <<= 32;
		data |= ioread32(pcie_set->reg_virt_base + offset);
		return data;
	}
}
