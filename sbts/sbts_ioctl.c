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
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_sbts.h"
#include "cndrv_smlu.h"

#include "cndrv_ioctl.h"
#include "queue.h"
#include "sbts_ioctl.h"

typedef int (*SBTS_IOCTL_FUNC)(struct sbts_set *, void *, cn_user);

static int
(*sbts_invoke_task_func[SBTS_QUEUE_TASK_TYPE_NUM])(struct sbts_set *sbts,
		struct queue *queue, cn_user user,
		struct sbts_queue_invoke_task *user_param) = {
	sbts_invoke_kernel,
	sbts_place_notifier,
	sbts_wait_notifier,
	sbts_place_idc,
	sbts_hostfn_invoke,
	sbts_invoke_ncs_kernel,
	sbts_dma_async_invoke,
	sbts_dbg_kernel_invoke,
	sbts_dbg_task,
	sbts_queue_sync,
	sbts_invoke_tcdp,
	sbts_invoke_tcdp_debug,
	sbts_wait_notifier_extra,
	sbts_invoke_jpu,
	sbts_invoke_task_topo,
};

static const char *sbts_invoke_task_name[SBTS_QUEUE_TASK_TYPE_NUM] = {
	"invoke kernel",
	"place notifer",
	"wait notifier",
	"place idc",
	"invoke host function",
	"invoke ncs kernel",
	"invoke dma async task",
	"invoke gdb kernel",
	"invoke gdb task",
	"queue sync",
	"invoke tcdp kernel",
	"invoke tcdp debug kernel",
	"wait notifier extra",
	"invoke jpu async task",
	"invoke task topo",
};

static int
cn_sbts_queue_invoke_task(struct sbts_set *sbts, void *args, cn_user user)
{
	int ret;
	struct queue *queue;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct sbts_queue_invoke_task user_param;

	if (copy_from_user((void *)&user_param, args, sizeof(struct sbts_queue_invoke_task))) {
		cn_dev_core_err(core, "copy invoke task params form user failed!");
		return -EFAULT;
	}

	if (unlikely(user_param.task_type >= SBTS_QUEUE_TASK_TYPE_NUM)) {
		cn_dev_core_err(core, "task type %d not support!", user_param.task_type);
		return -EINVAL;
	}

	queue = queue_get(sbts->queue_manager, user_param.hqueue, user, 1);
	if (!queue) {
		cn_dev_core_err_limit(core, "queue_dsid(%#llx) is invalid!", user_param.hqueue);
		return -CN_QUEUE_ERROR_QUEUE_INVALID;
	}

	/* smlu only restricts KERNEL task type */
	if (cn_is_smlu_en(core) && user_param.task_type == SBTS_QUEUE_KERNEL) {
		/* cn_smlu_try_charge can have the following behaviors:
		 * 1. return a negative value represents no cgroup binded
		      or ctrl-c signal arrived during block;
		 * 2. return 0 represents task can be invoked;
		 * 3. block if current ipu_util exceed expected value. */
		ret = cn_smlu_try_charge(core, ipu_cgrp_id, (void *)user, NULL, 0);
		if (ret) {
			queue_put(sbts->queue_manager, queue);
			return -EINTR;
		}
	}

	ret = sbts_invoke_task_func[user_param.task_type](sbts, queue,
					user, &user_param);
	if (ret) {
		cn_dev_core_err(core, "%s failed!", sbts_invoke_task_name[user_param.task_type]);
	}

	queue_put(sbts->queue_manager, queue);

	return ret;
}

static const struct sbts_ioctl_cmd { SBTS_IOCTL_FUNC func[_SBTS_CMD_NUM];}
__sbts_ioctl = {
	.func[_SBTS_CREATE_QUEUE]             = cn_queue_create,
	.func[_SBTS_DESTROY_QUEUE]            = cn_queue_destroy,
	.func[_SBTS_CORE_DUMP]                = cn_core_dump,
	.func[_SBTS_NOTIFIER_CREATE]          = cn_create_notifier,
	.func[_SBTS_NOTIFIER_DESTROY]         = cn_destroy_notifier,
	.func[_SBTS_NOTIFIER_WAIT]            = cn_wait_notifier,
	.func[_SBTS_NOTIFIER_QUERY]           = cn_query_notifier,
	.func[_SBTS_NOTIFIER_ELAPSED_TIME]    = cn_notifier_elapsed_exec_time,
	.func[_SBTS_QUEUE_QUERY]              = cn_query_queue,
	.func[_SBTS_INVOKE_CNGDB_TASK]        = cn_invoke_cngdb_task,
	.func[_SBTS_NCS_COMM_CMD]             = cn_ncs_cmd_func,
	.func[_SBTS_TCDP_COMM_CMD]            = cn_tcdp_cmd_func,
	.func[_SBTS_GET_HW_INFO]              = cn_user_get_hw_info,
	.func[_SBTS_NOTIFIER_ELAPSED_SW_TIME] = cn_notifier_elapsed_sw_time,
	.func[_SBTS_GET_UNOTIFY_INFO]         = cn_sbts_get_unotify_info,
	.func[_SBTS_SET_UNOTIFY_FD]           = cn_sbts_set_unotify_fd,
	.func[_SBTS_DEBUG_CTRL]               = cn_debug_ctrl,
	.func[_SBTS_HW_CFG_HDL]               = cn_hw_cfg_handle,
	.func[_SBTS_CORE_DUMP_ACK]            = cn_core_dump_ack,
	.func[_SBTS_QUEUE_INVOKE_TASK]        = cn_sbts_queue_invoke_task,
	.func[_SBTS_NOTIFIER_IPC_GETHANDLE]   = cn_notifier_ipc_gethandle,
	.func[_SBTS_NOTIFIER_IPC_OPENHANDLE]  = cn_notifier_ipc_openhandle,
	.func[_SBTS_MULTI_QUEUE_SYNC]         = cn_multi_queue_sync,
	.func[_SBTS_TASK_TOPO_CTRL]           = cn_sbts_topo_task_cmd,
};

long cn_sbts_dev_ioctl(struct cn_core_set *core, unsigned int cmd,
			unsigned long arg, struct file *fp)
{
	unsigned int ioc_nr = _IOC_NR(cmd);

	/*for 370 ARM platform*/
	if (unlikely(core->device_id == MLUID_370_DEV)) {
		return 0;
	}

	if (unlikely(core->device_id == MLUID_590_DEV)) {
		return 0;
	}

	if (unlikely(ioc_nr >= _SBTS_CMD_NUM)) {
		cn_dev_core_err(core, "ioctl command number %d is invalid!",
			ioc_nr);
		return -EINVAL;
	}

	if (unlikely(!__sbts_ioctl.func[ioc_nr])) {
		cn_dev_core_err(core, "ioctl command function %d is null!",
				ioc_nr);
		return -ENODEV;
	}

	return core->sbts_set ? __sbts_ioctl.func[ioc_nr](core->sbts_set,
			(void *)arg, (cn_user)fp) : -EINVAL;
}
