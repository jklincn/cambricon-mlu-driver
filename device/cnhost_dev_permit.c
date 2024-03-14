/*
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
#include <linux/device.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/capability.h>

#include "cndrv_debug.h"
#include "cnhost_dev_internal.h"


static int dev_permit_ioctl(u32 flags, struct cnhost_file_priv *file_priv)
{
	/* ROOT_ONLY is only for CAP_SYS_ADMIN */
	if (unlikely((flags & CNHOST_DEV_ROOT_ONLY) && !capable(CAP_SYS_ADMIN))) {
		cn_dev_warn("please check the run permission, need root\n");
		return -EACCES;
	}

	return 0;
}

int cnhost_dev_permit_check(struct file *fp, unsigned int cmd, unsigned long arg, struct cnhost_dev_ioctl_desc *ioctl_desc, int size)
{
	unsigned int flags = 0;
	int ret = 0;

	WARN_ON(ioctl_desc == NULL);

	if (unlikely(_IOC_NR(cmd) >= size)) {
		cn_dev_err("invalid input parameter: %d %d\n", _IOC_NR(cmd), size);
		return -EINVAL;
	}

	if (unlikely(ioctl_desc == NULL)) {
		cn_dev_err("invalid input parameter: permit array  is null\n");
		return -EFAULT;
	}

	flags = ioctl_desc[_IOC_NR(cmd)].flags;

	cn_dev_debug("check permit: ioctl %s flags 0x%x\n", ioctl_desc[_IOC_NR(cmd)].name, flags);

	ret = dev_permit_ioctl(flags, NULL);
	if (ret)
		return ret;

	return 0;
}
