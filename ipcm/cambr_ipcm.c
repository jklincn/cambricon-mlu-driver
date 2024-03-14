
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
//#include <linux/rpmsg.h>
#ifdef IN_CNDRV_HOST
#include "../include/cndrv_debug.h"
#include "../include/cndrv_core.h"
#endif
#include "include/remoteproc/remoteproc.h"
#include "include/rpmsg/rpmsg.h"

extern int cambr_rproc_dev_init(void *core);
extern void cambr_rproc_dev_exit(void *core);

extern int cambr_rproc_init(void);
extern void cambr_rproc_exit(void);

extern int rpmsg_init(void);
extern void rpmsg_fini(void);

extern int rpmsg_char_init(void);
extern void rpmsg_chrdev_exit(void);

extern int ipcm_init(void);
extern void ipcm_fini(void);

#ifdef IN_CNDRV_HOST
extern int virtio_rpmsg_init(void);
extern void virtio_rpmsg_fini(void);

int cn_ipcm_driver_init(void)
{
	int ret = 0;

	ret = virtio_init();
	ret |= rpmsg_init();
	ret |= rpmsg_char_init();
	ret |= ipcm_init();
	ret |= remoteproc_init();
	ret |= virtio_rpmsg_init();
	ret |= cambr_rproc_init();

	return ret;
}

void cn_ipcm_driver_exit(void)
{
	cambr_rproc_exit();
	rpmsg_chrdev_exit();
	ipcm_fini();
	virtio_rpmsg_fini();
	remoteproc_exit();
	rpmsg_fini();
	virtio_exit();
}

int cn_ipcm_dev_init(struct cn_core_set *core)
{
	char name[64];

	sprintf(name, "cambricon_ipcm%d", core->idx);
	core->support_ipcm = cn_ipcm_enable(core);
	if (core->support_ipcm) {
		if (cn_pre_check_dev_node(name)) {
			return -1;
		}
		return cambr_rproc_dev_init(core);
	}
	return 0;
}

void cn_ipcm_dev_exit(struct cn_core_set *core)
{
	if (cn_ipcm_enable(core))
		cambr_rproc_dev_exit(core);
}

extern void ipcm_rpc_log_init(void *_core);
extern void ipcm_query_port_service_init(void *core);

int cn_ipcm_late_init(struct cn_core_set *core)
{
	if (cn_ipcm_enable(core)) {
		ipcm_rpc_log_init(core);
		ipcm_query_port_service_init(core);
	}

	return 0;
}

void cn_ipcm_late_exit(struct cn_core_set *core)
{
	return;
}
#else /* !IN_CNDRV_HOST */
extern int vhost_rpmsg_init(void);
extern void vhost_rpmsg_fini(void);

int cn_ipcm_driver_init(void)
{
	int ret = 0;

	ret = vhost_init();
	ret |= rpmsg_init();
	ret |= rpmsg_char_init();
	ret |= ipcm_init();
	ret |= remoteproc_init();
	ret |= vhost_rpmsg_init();
	ret |= cambr_rproc_init();

	return ret;
}

void cn_ipcm_driver_exit(void)
{
	cambr_rproc_exit();
	rpmsg_chrdev_exit();
	ipcm_fini();
	vhost_rpmsg_fini();
	remoteproc_exit();
	rpmsg_fini();
	vhost_exit();
}

static int __init cn_ipcm_init(void)
{
	int ret = 0;

	if (cn_ipcm_enable())
		ret = cn_ipcm_driver_init();
	return ret;
}
module_init(cn_ipcm_init);

static void __exit cn_ipcm_exit(void)
{
	if (cn_ipcm_enable())
		cn_ipcm_driver_exit();
}
module_exit(cn_ipcm_exit);
#endif

MODULE_DESCRIPTION("Cambricon IPCM Module");
MODULE_LICENSE("GPL v2");
