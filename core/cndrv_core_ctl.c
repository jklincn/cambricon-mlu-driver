/*
 * core/cndrv_core.c
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/pid_namespace.h>
#include <linux/ftrace.h>
#include <linux/proc_fs.h>
#include <linux/of_device.h>

#include "cndrv_core.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"

static struct cnhost_device *cambricon_ctl;

static struct cndev_dma_device {
	struct device *device;
	void *udvm_set;
	u64 dma_mask;
} cndev_dma_device = {
	.device = NULL,
	.udvm_set = NULL,
	.dma_mask = ~0ULL,
};

struct device *cndrv_core_get_dma_device(void)
{
	return cndev_dma_device.device;
}

void *cndrv_core_get_udvm(void)
{
	return cndev_dma_device.udvm_set;
}

static void cn_core_dma_config(struct cndev_dma_device *cndev_dma_dev)
{
	struct device *dev = cndev_dma_dev->device;

	if (!dev) {
		return;
	}

	/* default value */
	dev->coherent_dma_mask = cndev_dma_dev->dma_mask;
	dev->dma_mask = &cndev_dma_dev->dma_mask;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	(void)of_dma_configure(dev, dev->of_node, true);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	(void)of_dma_configure(dev, dev->of_node);
#else
	dev = NULL;
#endif

	cndev_dma_dev->device = dev;
}

extern const struct file_operations cndev_fops;

static const struct cnhost_driver cndrv_core_ctl_drv = {
	.fops = &cndev_fops,
	.name = "cambricon-ctl",
};

int cn_core_setup_dev_ctl(void)
{
	int ret = 0;

	cambricon_ctl = cnhost_dev_alloc(&cndrv_core_ctl_drv, NULL, CNHOST_DEV_MINOR_CONTROL, 0, 0);
	if (IS_ERR(cambricon_ctl))
		return PTR_ERR(cambricon_ctl);

	ret = cnhost_dev_register(cambricon_ctl, 0);
	if (ret)
		goto err_put;

	cndev_dma_device.device = cambricon_ctl->primary->kdev;
	cn_core_dma_config(&cndev_dma_device);

	ret = cn_udvm_init(&cndev_dma_device.udvm_set);
	if (ret)
		goto err_put;

	return 0;
err_put:
	cnhost_dev_put(cambricon_ctl);
	return ret;
}

void cn_core_remove_dev_ctl(void)
{
	cn_udvm_exit(cndev_dma_device.udvm_set);
	cndev_dma_device.udvm_set = NULL;

	cndev_dma_device.device = NULL;
	if (cambricon_ctl) {
		cnhost_dev_unregister(cambricon_ctl);
		cnhost_dev_put(cambricon_ctl);
	}
	cambricon_ctl = NULL;
}
