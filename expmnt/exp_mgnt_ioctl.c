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

#include "cndrv_core.h"
#include "exp_mgnt_private.h"
#include "cndrv_debug.h"

#include "cndrv_ioctl.h"

int hb_pick_all(unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	unsigned long bitmap = 0;
	struct DistributeMap dismap;

	if (cn_device_status_query(core, &bitmap) < 0) {
		cn_dev_core_err(core, "query failure.");
		return -EFAULT;
	}
	collect_distribute_map(mnt_set->heartbeat_pkg, bitmap, &dismap);
	if (copy_to_user((void *)arg, (void *)&dismap,
				sizeof(struct DistributeMap))) {
		cn_dev_core_err(core,
				"_HB_PICK_ALL copy_to_user failed.");
		ret = -EFAULT;
	}
	
	return ret;
}

int hb_get_one(unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct ErrState err_state;

	if (copy_from_user((void *)&err_state, (void *)arg,
				sizeof(struct ErrState))) {
		cn_dev_core_err(core,
				"_HB_GET_ONE copy_from_user failed.");
		ret = -EFAULT;
	} else {
		if (get_one_msg(mnt_set->heartbeat_pkg,
					err_state.ModuleID, &err_state)) {
			ret = -EFAULT;
		} else if (copy_to_user((void *)arg, (void *)&err_state,
					sizeof(struct ErrState))) {
			cn_dev_core_err(core,
					"__HB_GET_ONE copy_to_user failed.");
			ret = -EFAULT;
		}
	}
	
	return ret;
}

typedef int (*expmnt_ioctl_func)(unsigned long arg,
	unsigned int cmd, struct cn_core_set *core);

static const struct {
	expmnt_ioctl_func funcs;
	u64 flags;
} expmnt_funcs[EXPMNT_MAX_NR_COUNT] = {
	[_HB_PICK_ALL] = {hb_pick_all, 0},
	[_HB_GET_ONE] = {hb_get_one, 0},
};

long cn_expmnt_ioctl(
		struct cn_core_set *core,
		unsigned int cmd,
		unsigned long arg)
{
	long ret = 0;
	unsigned int ioc_nr = _IOC_NR(cmd);

	if (expmnt_funcs[ioc_nr].funcs) {
		ret = expmnt_funcs[ioc_nr].funcs(arg, cmd, core);
	} else {
		cn_dev_core_err(core, "IOCTRL command# %d is invalid!", _IOC_NR(cmd));
		ret = -EINVAL;
	}

	return ret;
}
