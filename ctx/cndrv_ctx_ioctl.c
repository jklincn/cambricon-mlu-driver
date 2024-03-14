/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2023 Cambricon, Inc. All rights reserved.
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

#include "cndrv_debug.h"
#include "cndrv_ioctl.h"
#include "cndrv_lpm.h"

typedef int (*CTX_IOCTL_FUNC)(struct cn_core_set *, void *, cn_user);

enum ctx_ioctl_type {
	CTX_TYPE_CREATE = 0,
	CTX_TYPE_DESTROY = 1,
	CTX_TYPE_NUM,
};

static int cn_ctx_create(struct cn_core_set *core, void *args, cn_user user)
{
	/* lpm resume */
	if (cn_lpm_get_all_module(core)) {
		cn_dev_core_err(core, "ctx create get lpm failed!");
		return -EINVAL;
	}
	return 0;
}

static int cn_ctx_destroy(struct cn_core_set *core, void *args, cn_user user)
{
	/* lpm suspend */
	cn_lpm_put_all_module(core);
	return 0;
}

static const struct ctx_ioctl_cmd { CTX_IOCTL_FUNC func[CTX_TYPE_NUM];}
__ctx_ioctl = {
	.func[CTX_TYPE_CREATE]             = cn_ctx_create,
	.func[CTX_TYPE_DESTROY]            = cn_ctx_destroy,
};

long cn_ctx_ioctl(struct cn_core_set *core, unsigned int cmd,
			unsigned long arg, struct file *fp)
{
	unsigned int ioc_nr = _IOC_NR(cmd);

	if (unlikely(ioc_nr >= CTX_TYPE_NUM)) {
		cn_dev_core_err(core, "ioctl command number %d is invalid!",
			ioc_nr);
		return -EINVAL;
	}

	if (unlikely(!__ctx_ioctl.func[ioc_nr])) {
		cn_dev_core_err(core, "ioctl command function %d is null!",
				ioc_nr);
		return -ENODEV;
	}

	return __ctx_ioctl.func[ioc_nr](core, (void *)arg, (cn_user)fp);
}
