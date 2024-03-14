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

static void cn_pci_disable_all_irqs(void *pcie_priv)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (!(pcie_set->ops->gic_mask_all)) {
		cn_dev_pcie_err(pcie_set, "gic_mask_all is NULL");
		return;
	}
	pcie_set->ops->gic_mask_all(pcie_set);
}

static int cn_pci_enable_irq(int hw_irq, void *pcie_priv)
{
	unsigned long flags;
	int ret;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
	if (!(pcie_set->ops->gic_unmask)) {
		cn_dev_pcie_err(pcie_set, "gic_unmask is NULL");
		return -EINVAL;
	}
	ret = pcie_set->ops->gic_unmask(hw_irq, pcie_set);
	spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);

	return ret;
}

static int cn_pci_disable_irq(int hw_irq, void *pcie_priv)
{
	unsigned long flags;
	int ret;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
	if (!(pcie_set->ops->gic_mask)) {
		cn_dev_pcie_err(pcie_set, "gic_mask is NULL");
		return -EINVAL;
	}
	ret = pcie_set->ops->gic_mask(hw_irq, pcie_set);
	spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);

	return ret;
}

static int cn_pci_register_interrupt(int hw_irq,
		interrupt_cb_t handler, void *data, void *pcie_priv)
{
	unsigned long flags;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

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

static void cn_pci_unregister_interrupt(int hw_irq, void *pcie_priv)
{
	unsigned long flags;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	if (hw_irq < 0) {
		cn_dev_pcie_err(pcie_set,
			"pcie_gic hw_irq %d can not less than zero", hw_irq);
		return;
	}

	spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
	pcie_set->irq_desc[hw_irq].handler = NULL;
	if (!(pcie_set->ops->gic_mask)) {
		cn_dev_pcie_err(pcie_set, "gic_mask is NULL");
		return;
	}
	pcie_set->ops->gic_mask(hw_irq, pcie_set);
	spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);
}
