/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/file.h>

#include "cndrv_ioctl.h"

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_domain.h"
#include "./platform/cndrv_edge.h"

typedef long (*bus_ioctl_func)(struct cn_core_set *core,
				unsigned int cmd,
				unsigned long arg);

static long bus_show_pcie_info(struct cn_core_set *core,
				unsigned int cmd,
				unsigned long arg)
{
	cn_dev_core_info(core, "SHOW PCIE INFORMATION BEGIN");
	cn_bus_show_info(core->bus_set);
	cn_bus_shutdown(core->bus_set);
	cn_bus_suspend(core->bus_set, 0);
	cn_bus_resume(core->bus_set);
	cn_dev_core_info(core, "SHOW PCIE INFORMATION END");

	return 0;
}

static long bus_get_pcie_bar_info(struct cn_core_set *core,
				unsigned int cmd,
				unsigned long arg)
{
	struct bar_info_s bar_info;

	memset(&bar_info, 0, sizeof(struct bar_info_s));
	cn_bus_get_bar_info(core->bus_set, &bar_info);
	if (copy_to_user((void *)arg, (void *)&bar_info,
			sizeof(struct bar_info_s))) {
		cn_dev_core_err(core, "copy_to_user failed.");
		return -EFAULT;
	}

	return 0;
}

static long bus_get_pcie_info(struct cn_core_set *core,
				unsigned int cmd,
				unsigned long arg)
{
	struct bus_info_s bus_info;

	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);
	if (copy_to_user((void *)arg, (void *)&bus_info,
			sizeof(struct bus_info_s))) {
		cn_dev_core_err(core, "copy_to_user failed.");
		return -EFAULT;
	}

	return 0;
}

static long bus_pcie_cspeed(struct cn_core_set *core,
				unsigned int cmd,
				unsigned long arg)
{
#if 0
	unsigned int cspeed;

	if (cn_is_mim_en(core) || cn_core_is_vf(core))
		return 0;
	cn_dev_core_info(core, "PCIE CHANGE SPEED BEGIN");
	if (copy_from_user((void *)&cspeed, (void *)arg,
			sizeof(unsigned int))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		return -EFAULT;
	} else
		cn_bus_set_cspeed(cspeed, core->bus_set);

	cn_dev_core_info(core, "PCIE CHANGE SPEED END");
#else
	cn_dev_core_info(core, "CANCEL PCIE SPEED CHANGE");
#endif

	return 0;
}

static const struct bus_funcs_s {
	bus_ioctl_func func;
	enum core_work_mode mode;
} bus_funcs[BUS_MAX_NR_COUNT] = {
	[_B_SHOW_PCIE_INFO]	= {bus_show_pcie_info, FULL|MIM_EN|MI|SMLU},
	[_B_GET_PCIE_BAR_INFO]	= {bus_get_pcie_bar_info, FULL|MIM_EN|MI|SMLU},
	[_B_GET_PCIE_INFO]	= {bus_get_pcie_info, FULL|MIM_EN|MI|SMLU},
	[_B_PCIE_CSPEED]	= {bus_pcie_cspeed, FULL|MIM_EN|MI|SMLU},
};

static long cn_bus_ioctl_exec(struct cn_core_set *core,
			unsigned int cmd,
			unsigned long arg,
			unsigned int ioc_nr,
			enum core_work_mode mode)
{
	long ret;

	if (bus_funcs[ioc_nr].func) {
		if (mode & bus_funcs[ioc_nr].mode) {
			ret = bus_funcs[ioc_nr].func(core, cmd, arg);
		} else {
			cn_dev_core_err(core, "IOCTRL command# %d permission denied", ioc_nr);
			ret = -EACCES;
		}
	} else {
		cn_dev_core_err(core, "IOCTRL command# %d is invalid!", ioc_nr);
		ret = -EINVAL;
	}

	return ret;
}

long cn_bus_ioctl(struct cn_core_set *core, unsigned int cmd, unsigned long arg)
{
	unsigned int ioc_nr = _IOC_NR(cmd);
	enum core_work_mode mode = cn_core_get_work_mode(core);

	return cn_bus_ioctl_exec(core, cmd, arg, ioc_nr, mode);
}
