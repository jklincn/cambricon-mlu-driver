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

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "pcie_dma.h"
#include "cndrv_pci.h"
#include "cndrv_debug.h"
#include "cndrv_affinity.h"

__attribute__((unused))
static void cn_pci_disable_all_irqs(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	int i;

	for (i = 0; i < INTERRUPT_IRQ_NUM; i++)
		pcie_set->irq_set.irq_desc[i].occur_count = 0;

	if (pcie_set->ops->save_msix_ram)
		pcie_set->ops->save_msix_ram(pcie_set);

	if (!(pcie_set->ops->gic_mask_all)) {
		cn_dev_pcie_err(pcie_set, "gic_mask_all is NULL");
		return;
	}
	pcie_set->ops->gic_mask_all(pcie_set);
}

__attribute__((unused))
static int cn_pci_enable_irq(int hw_irq, void *pcie_priv)
{
	int ret;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (!(pcie_set->ops->gic_unmask)) {
		cn_dev_pcie_err(pcie_set, "gic_unmask is NULL");
		return -EINVAL;
	}
	ret = pcie_set->ops->gic_unmask(hw_irq, pcie_set);

	return ret;
}

__attribute__((unused))
static int cn_pci_disable_irq(int hw_irq, void *pcie_priv)
{
	int ret;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (!(pcie_set->ops->gic_mask)) {
		cn_dev_pcie_err(pcie_set, "gic_mask is NULL");
		return -EINVAL;
	}
	ret = pcie_set->ops->gic_mask(hw_irq, pcie_set);

	return ret;
}

static int cn_pci_msi_enable(struct cn_pcie_set *pcie_set)
{
	int ret, pos, i;
	u32 value;

#if KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE
	ret = pci_alloc_irq_vectors(pcie_set->pdev, pcie_set->irq_set.irq_num,
		pcie_set->irq_set.irq_num, PCI_IRQ_MSI);
#elif KERNEL_VERSION(3, 10, 107) == LINUX_VERSION_CODE
	ret = pci_enable_msi_block(pcie_set->pdev, pcie_set->irq_set.irq_num);
#else
	ret = pci_enable_msi_range(pcie_set->pdev, pcie_set->irq_set.irq_num,
		pcie_set->irq_set.irq_num);
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)*/
	if (ret < 0) {
		cn_dev_pcie_err(pcie_set,
				"alloc %d msi Failed\n", pcie_set->irq_set.irq_num);
		return -1;
	}

	pos = pci_find_capability(pcie_set->pdev, PCI_CAP_ID_MSI);
	pcie_set->irq_set.msi_pos = pos;
	for (i = 0; i < 24; i += 4)
		pci_read_config_dword(pcie_set->pdev, pos + i, &value);

	pcie_set->irq_set.irq = pcie_set->pdev->irq;

	for (i = 0; i < pcie_set->irq_set.irq_num; i++) {
		ret = cn_get_cpu_affinity(pcie_set->node, &pcie_set->irq_set.cpu_mask[i]);
		if (ret) {
			cn_dev_pcie_info(pcie_set,
					"irq %d get cpu affinity failed, can't set cpu affinity\n", (pcie_set->irq_set.irq + i));
			pcie_set->irq_set.affinity[i] = 0;
		} else
			pcie_set->irq_set.affinity[i] = 1;
	}

	for (i = 0; i < pcie_set->irq_set.irq_num; i++) {
		if (request_irq(pcie_set->irq_set.irq + i, pcie_set->ops->msi_isr, IRQF_SHARED,
				"cndrv-msi", pcie_set))
			return -1;

		if (pcie_set->irq_set.affinity[i] == 1) {
			cn_irq_set_affinity(pcie_set->irq_set.irq + i, &pcie_set->irq_set.cpu_mask[i]);
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

	for (i = 0; i < pcie_set->irq_set.irq_num; i++) {
		if (pcie_set->irq_set.affinity[i] == 1)
			cn_irq_set_affinity(pcie_set->irq_set.irq + i, NULL);
		free_irq(pcie_set->irq_set.irq + i, (void *)pcie_set);
		cn_dev_pcie_info(pcie_set, "free_irq:%d", pcie_set->irq_set.irq + i);
	}

	for (i = 0; i < pcie_set->irq_set.irq_num; i++) {
		if (pcie_set->irq_set.affinity[i] == 1)
			cn_put_cpu_affinity(pcie_set->node, &pcie_set->irq_set.cpu_mask[i]);
	}
	pci_disable_msi(pcie_set->pdev);

	return 0;
}

static int cn_pci_msix_enable(struct cn_pcie_set *pcie_set)
{
	int ret;
	unsigned int i, pos;
	unsigned int value;

	for (i = 0; i < pcie_set->irq_set.irq_num; i++)
		pcie_set->irq_set.msix_entry_buf[i].entry = i;

#if KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE
	ret = pci_alloc_irq_vectors(pcie_set->pdev, pcie_set->irq_set.irq_num,
		pcie_set->irq_set.irq_num, PCI_IRQ_MSIX);

	for (i = 0; i < pcie_set->irq_set.irq_num; i++)
		pcie_set->irq_set.msix_entry_buf[i].vector = pci_irq_vector(pcie_set->pdev, i);
#elif KERNEL_VERSION(3, 10, 107) == LINUX_VERSION_CODE
	ret = pci_enable_msix(pcie_set->pdev, pcie_set->irq_set.msix_entry_buf, pcie_set->irq_set.irq_num);
#else
	ret = pci_enable_msix_range(pcie_set->pdev, pcie_set->irq_set.msix_entry_buf,
		pcie_set->irq_set.irq_num, pcie_set->irq_set.irq_num);
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

	pcie_set->irq_set.irq = pcie_set->pdev->irq;

	for (i = 0; i < pcie_set->irq_set.irq_num; i++) {
		ret = cn_get_cpu_affinity(pcie_set->node, &pcie_set->irq_set.cpu_mask[i]);
		if (ret) {
			cn_dev_pcie_info(pcie_set,
					"irq %d get cpu affinity failed, can't set cpu affinity",
					(pcie_set->irq_set.irq + i));
			pcie_set->irq_set.affinity[i] = 0;
		} else
			pcie_set->irq_set.affinity[i] = 1;
	}

	for (i = 0; i < pcie_set->irq_set.irq_num; i++) {
		if (request_irq(pcie_set->irq_set.msix_entry_buf[i].vector,
				pcie_set->ops->msix_isr, 0, "cndrv-msix", pcie_set)) {
			cn_dev_pcie_info(pcie_set,
				"request index %d irq is: %d failed.",
				i, pcie_set->irq_set.msix_entry_buf[i].vector);
			return -1;
		}

		if (pcie_set->irq_set.affinity[i] == 1) {
			cn_irq_set_affinity(pcie_set->irq_set.msix_entry_buf[i].vector,
				&pcie_set->irq_set.cpu_mask[i]);
		}
		cn_dev_pcie_debug(pcie_set, "request_irq vector:%x success",
			pcie_set->irq_set.msix_entry_buf[i].vector);
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

	for (i = 0; i < pcie_set->irq_set.irq_num; i++) {
		if (pcie_set->irq_set.affinity[i] == 1)
			cn_irq_set_affinity(pcie_set->irq_set.msix_entry_buf[i].vector, NULL);
		free_irq(pcie_set->irq_set.msix_entry_buf[i].vector, pcie_set);
		cn_dev_pcie_debug(pcie_set, "free_irq:%x", pcie_set->irq_set.msix_entry_buf[i].vector);
	}

	for (i = 0; i < pcie_set->irq_set.irq_num; i++) {
		if (pcie_set->irq_set.affinity[i] == 1)
			cn_put_cpu_affinity(pcie_set->node, &pcie_set->irq_set.cpu_mask[i]);
	}
	pci_disable_msix(pcie_set->pdev);

	return 0;
}

static int cn_pci_intx_enable(struct cn_pcie_set *pcie_set)
{
	int ret;

	pcie_set->irq_set.irq = pcie_set->pdev->irq;

	ret = cn_get_cpu_affinity(pcie_set->node, &pcie_set->irq_set.cpu_mask[0]);
	if (ret) {
		cn_dev_pcie_info(pcie_set,
				"get cpu affinity failed, can't set cpu affinity\n");
		pcie_set->irq_set.affinity[0] = 0;
	} else
		pcie_set->irq_set.affinity[0] = 1;

	if (pcie_set->irq_set.affinity[0] == 1) {
		cn_irq_set_affinity(pcie_set->irq_set.irq, &pcie_set->irq_set.cpu_mask[0]);
	}

	if (request_irq(pcie_set->irq_set.irq, pcie_set->ops->intx_isr, IRQF_SHARED,
		"cndrv-intx", pcie_set)) {
		cn_dev_pcie_err(pcie_set, "request intx irq is: %d failed.",
			pcie_set->irq_set.irq);
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

	if (pcie_set->irq_set.affinity[0] == 1)
		cn_irq_set_affinity(pcie_set->irq_set.irq, NULL);
	free_irq(pcie_set->irq_set.irq, (void *)pcie_set);

	if (pcie_set->irq_set.affinity[0] == 1)
		cn_put_cpu_affinity(pcie_set->node, &pcie_set->irq_set.cpu_mask[0]);
	cn_dev_pcie_info(pcie_set, "free_irq:%d", pcie_set->irq_set.irq);
	return 0;
}

__attribute__((unused))
static int (*isr_enable_func[3])(struct cn_pcie_set *) = {
	cn_pci_msi_enable,
	cn_pci_msix_enable,
	cn_pci_intx_enable
};

__attribute__((unused))
static int (*isr_disable_func[3])(struct cn_pcie_set *) = {
	cn_pci_msi_disable,
	cn_pci_msix_disable,
	cn_pci_intx_disable
};

__attribute__((unused)) static void cn_pci_unregister_interrupt(int hw_irq, void *pcie_priv)
{
	int handler_num = 0;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (hw_irq < 0) {
		cn_dev_pcie_err(pcie_set,
			"pcie_gic hw_irq %d can not less than zero", hw_irq);
		return;
	}

	for (handler_num = 0; handler_num < IRQ_SHARED_NUM; handler_num++)
		pcie_set->irq_set.irq_desc[hw_irq].handler[handler_num] = NULL;
	if (!(pcie_set->ops->gic_mask)) {
		cn_dev_pcie_err(pcie_set, "gic_mask is NULL");
		return;
	}
	pcie_set->ops->gic_mask(hw_irq, pcie_set);
}

__attribute__((unused)) static int cn_pci_register_interrupt(int hw_irq,
		interrupt_cb_t handler, void *data, void *pcie_priv)
{
	int handler_num = 0;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (hw_irq < 0) {
		cn_dev_pcie_err(pcie_set,
			"pcie_gic hw_irq %d can not less than zero", hw_irq);
		return -1;
	}

	for (handler_num = 0; handler_num < IRQ_SHARED_NUM; handler_num++) {
		if (pcie_set->irq_set.irq_desc[hw_irq].handler[handler_num] == NULL)
			break;
		if (pcie_set->irq_set.irq_desc[hw_irq].handler[handler_num] == handler) {
			cn_dev_pcie_err(pcie_set,
				"hw_irq[%d] handler[%d] is already registered", hw_irq, handler_num);
			return -EINVAL;
		}
	}
	if (handler_num == IRQ_SHARED_NUM) {
		cn_dev_pcie_err(pcie_set,
			"overflow: max support %d handler on same irq", IRQ_SHARED_NUM);
		return -EINVAL;
	}

	pcie_set->irq_set.irq_desc[hw_irq].handler[handler_num] = handler;
	pcie_set->irq_set.irq_desc[hw_irq].data[handler_num] = data;

	return 0;
}
