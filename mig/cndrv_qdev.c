/* This file used in virtual machine when live migration */
/*
 * mig/cndrv_qdev.c
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
#include <linux/types.h>
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
#include <linux/vmalloc.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "cndrv_mm.h"
#include "cndrv_domain.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "cndrv_kwork.h"

#define DRV_QDEV_NAME		"cambricon-qdev-drv"
#define QDEV_BAR_OFFSET              0
#define QDEV_VENDER_ID               (0xcabc)
#define QDEV_DEVICE_ID               (0xfae)

enum vf_mig_state {
	MIG_DRV_UNINIT = 0xff,
	QDEV_INITED = 1,
	MIG_DRV_RESERVE0,      /* guest notify the qemu receivd message */
	NOTIFY_SRC_START,      /* qemu write this flag */
	MIG_DRV_SRC_READY,     /* guest notify the qemu ready */
	NOTIFY_DST_VF_RESTORE, /* qemu write this flag */
	MIG_DRV_DST_DONE,      /* guest notify the qemu ready */
	VMLU_FAIL,             /* qemu notify guest fail */
	VF_SRC_FAIL,           /* guest notify qemu fail */
	VF_DST_FAIL,
	PF_SRC_FAIL,
	PF_DST_FAIL,
	MIG_DRV_RESERVE1       /* VF_ROLLBACK_FAIL */
};

struct vf_mig_info_t {
	u32 version;             /* 0.1.0.0 */
	u32 bdf;
	u32 ordinal;             /* dev0/1/2 in Host */
	u32 domain_id;
	u32 vf_id;               /*vf id 0/1/2/3 */
	u32 logical_ordinal;     /* oridinal index in Guest */
	enum vf_mig_state vf_state;
	u32 pf_state;
	u32 qom_state;
	u32 reserve2;            /* block load */
	int vf_errno;            /* vf error number */
	int pf_errno;            /* pf error number, qemu write */
	int qemu_errno;          /* qemu error number */
	u32 reserved[32];
};

enum qdev_run_state {
	QDEV_RUN_NORMAL = 0,
	QDEV_RUN_NOTIFY_STOP,
	QDEV_RUN_STOP,
};

struct qdev_vf_set {
	struct work_struct scan_work;
	enum vf_mig_state state;
	enum qdev_run_state run_state;  /* 0:not stop   1:notify stop    2:stop */
	struct cn_core_set *core;
	int logical_ordinal;
};

struct qdev_set_stru {
	struct pci_dev *pdev;
	void *bar_base;
	ulong bar_size;
};

static struct qdev_set_stru *qdev_set;
static volatile int qdev_connect_cnt;

static u32 qdev_get_bdf(u32 bar_bdf)
{
	return ((bar_bdf >> 8) | (bar_bdf & 0xff));
}

/* find the logical_ordinal in qemu virtual bar */
static int qdev_get_vf_ordinal(u32 bdf)
{
	struct vf_mig_info_t *pbar_info;
	int offset = QDEV_BAR_OFFSET;

	if (!qdev_set) {
		return -1;
	}

	while (offset + sizeof(struct vf_mig_info_t) <= qdev_set->bar_size) {
		pbar_info = (qdev_set->bar_base + offset);
		if (qdev_get_bdf(pbar_info->bdf) == bdf) {
			return pbar_info->logical_ordinal;
		}

		offset += sizeof(struct vf_mig_info_t);
	}

	return -1;
}

/* find the virtual bar offset in global qemu virtual bar */
static struct vf_mig_info_t *qdev_find_bar(struct qdev_vf_set *vf_set)
{
	struct vf_mig_info_t *pbar_info;
	int offset = QDEV_BAR_OFFSET;

	if (!qdev_set) {
		return NULL;
	}

	while (offset + sizeof(struct vf_mig_info_t) <= qdev_set->bar_size) {
		pbar_info = (qdev_set->bar_base + offset);
		if (pbar_info->logical_ordinal == vf_set->logical_ordinal) {
			return pbar_info;
		}

		offset += sizeof(struct vf_mig_info_t);
	}

	return NULL;
}

/* a work for guest virtual machine communication with qemu */
void qdev_scan_work(struct work_struct *work)
{
	struct vf_mig_info_t *bar_info;
	struct qdev_vf_set *vf_set = (struct qdev_vf_set *)container_of(
		work, struct qdev_vf_set, scan_work);

	while (1) {
		usleep_range(100, 200);
		if (vf_set->run_state == QDEV_RUN_NOTIFY_STOP) {
			vf_set->run_state = QDEV_RUN_STOP;
			return;
		}

		bar_info = qdev_find_bar(vf_set);

		if (vf_set->state != bar_info->vf_state) {
			switch (bar_info->vf_state) {
			case NOTIFY_SRC_START:
				bar_info->vf_state = MIG_DRV_RESERVE0;
				cn_core_mig_suspend(vf_set->core);

				vf_set->state = MIG_DRV_SRC_READY;
				bar_info->vf_state = vf_set->state;
				break;

			case NOTIFY_DST_VF_RESTORE:
			case VMLU_FAIL:
			case PF_SRC_FAIL:
				bar_info->vf_state = MIG_DRV_RESERVE0;
				cn_core_mig_resume(vf_set->core, qdev_get_bdf(bar_info->bdf));

				vf_set->state = QDEV_INITED;
				bar_info->vf_state = vf_set->state;
				break;

			default:
				break;
			}

			vf_set->state = bar_info->vf_state;
		}
	}
}

/* The qemu make a virtual bar for guest, this probe the virtual bar */
static int qdev_probe(void)
{
	int result = 0;
	struct pci_dev *pdev;

	pdev = pci_get_subsys(QDEV_VENDER_ID, QDEV_DEVICE_ID, PCI_ANY_ID,
		PCI_ANY_ID, NULL);
	if (!pdev) {
		return -1;
	}

	qdev_set = cn_kzalloc(sizeof(struct qdev_set_stru), GFP_KERNEL);
	if (!qdev_set) {
		return -1;
	}

	qdev_set->pdev = pdev;
	if (unlikely(pci_enable_device(pdev)))
		goto exit;

	pci_set_master(pdev);

	if (pci_request_regions(pdev, "qemu dev"))
		goto exit;

	qdev_set->bar_size = pci_resource_len(pdev, 0);
	qdev_set->bar_base = ioremap(pci_resource_start(pdev, 0),
		qdev_set->bar_size);

	dev_set_drvdata(&pdev->dev, qdev_set);

	return result;

exit:
	result = -EIO;
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	return result;
}

/* The qemu make a virtual bar for guest, this remove the virtual bar */
static void qdev_remove(void)
{
	if (!qdev_set) {
		return;
	}

	dev_set_drvdata(&qdev_set->pdev->dev, NULL);
	if (qdev_set->bar_base) {
		iounmap(qdev_set->bar_base);
	}
	pci_release_regions(qdev_set->pdev);
	pci_clear_master(qdev_set->pdev);
	pci_disable_device(qdev_set->pdev);

	cn_kfree(qdev_set);
	qdev_set = NULL;
}

/*
 * when core probe call this function, this function used for live migration
 * for virtual machine
 * return: -1:error     0:success
 */
int cn_qdev_late_init(struct cn_core_set *core)
{
	int logical_ordinal;
	struct qdev_vf_set *vf_set;
	struct vf_mig_info_t *bar_info;

	__sync_fetch_and_add(&qdev_connect_cnt, 1);
	if (qdev_connect_cnt == 1) {
		if (qdev_probe() < 0) {
			return 0;
		}
	}

	if (!qdev_set) {
		return 0;
	}

	logical_ordinal = qdev_get_vf_ordinal(cn_bus_get_bdf(core->bus_set));
	if (logical_ordinal < 0) {
		return -1;
	}

	core->qdev_vf_set = cn_kzalloc(sizeof(struct qdev_vf_set), GFP_KERNEL);
	if (!core->qdev_vf_set) {
		cn_dev_core_err(core, "kzalloc qdev_vf_set data space error!");
		return -ENOMEM;
	}

	vf_set = core->qdev_vf_set;
	vf_set->logical_ordinal = logical_ordinal;
	vf_set->core = core;
	bar_info = qdev_find_bar(vf_set);
	if (!bar_info) {
		cn_kfree(core->qdev_vf_set);
		return -1;
	}

	bar_info->vf_state = QDEV_INITED;
	INIT_WORK(&vf_set->scan_work, qdev_scan_work);
	/* Not support live migration now, scan_work is too long, so delete it */
	/* schedule_work(&vf_set->scan_work); */

	return 0;
}

/*
 * when core remove call this function, this function used for live migration
 * for virtual machine
 */
void cn_qdev_late_exit(struct cn_core_set *core)
{
	struct vf_mig_info_t *bar_info;
	struct qdev_vf_set *vf_set = core->qdev_vf_set;

	if (vf_set) {
		/* Not support live migration now, so not wait */
		vf_set->run_state = QDEV_RUN_STOP;
		while (vf_set->run_state != QDEV_RUN_STOP) {
			usleep_range(100, 200);
		}

		bar_info = qdev_find_bar(vf_set);
		bar_info->vf_state = MIG_DRV_UNINIT;

		cn_kfree(vf_set);
		core->qdev_vf_set = NULL;
	}

	__sync_fetch_and_sub(&qdev_connect_cnt, 1);
	if (qdev_connect_cnt == 0) {
		qdev_remove();
	}
}
