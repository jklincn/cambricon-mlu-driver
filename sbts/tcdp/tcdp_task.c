/*
 * sbts/tcdp_task.c
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

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/io.h>

#include "cndrv_core.h"
#include "../core/cndrv_ioctl.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"
#include "../sbts.h"
#include "../sbts_set.h"
#include "../queue.h"
#include "tcdp_task.h"
#include "cndrv_commu.h"
#include "cndrv_monitor.h"

enum tcdp_cmd_type {
	TCDP_CMD_GET_CAPACITY = 0,
	TCDP_CMD_CREATE_TCDP_HANDLE,
	TCDP_CMD_DESTROY_TCDP_HANDLE,
	TCDP_CMD_DESTROY_RESOURCE,
	TCDP_CMD_GET_TNC_NUM,
	TCDP_CMD_GET_TNC_CAP,
	TCDP_CMD_CNT,
};

static char *tcdp_cmd_name[TCDP_CMD_CNT] = {
	"TCDP_CMD_GET_CAPACITY",
	"TCDP_CMD_CREATE_TCDP_HANDLE",
	"TCDP_CMD_DESTROY_TCDP_HANDLE",
	"TCDP_CMD_DESTROY_RESOURCE",
	"TCDP_CMD_GET_TINYCORE_NUMBER",
	"TCDP_CMD_GET_TINYCORE_CAPABILITY",
};


static inline __u64
fill_tcdp_cmd_desc(__u64 version, __u64 user,
		struct comm_ctrl_desc *ctrl_desc,
		struct tcdp_comm_ctrl *tcdp_ctrl,
		struct cn_core_set *core)
{
	__u64 payload_size = 0;
	struct ctrl_desc_data_v1 *data =
		(struct ctrl_desc_data_v1 *)ctrl_desc->data;

	switch (version) {
	case SBTS_VERSION:
		ctrl_desc->version	= version;
		data->type          = TCDP_COMM_CMD;
		data->user          = cpu_to_le64(user);

		memcpy(data->priv, tcdp_ctrl, sizeof(struct tcdp_comm_ctrl));

		payload_size = sizeof(struct comm_ctrl_desc);
		break;
	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

int cn_tcdp_cmd_func(struct sbts_set *sbts_set,
		void *arg,
		cn_user user)
{
	int ret = 0;
	__u64 payload_size = 0;
	struct tcdp_comm_ctrl tcdp_ctrl, *tcdp_ret_ctrl;
	struct comm_ctrl_desc tx_desc;
	struct comm_ctrl_desc rx_desc;
	struct cn_core_set *core = sbts_set->core;
	struct sched_manager *sched_mgr = sbts_set->sched_manager;
	struct ctrl_desc_data_v1 *data;
	host_addr_t host_param_va = 0;
	dev_addr_t dev_param_va = 0;

	if (copy_from_user((void *)&tcdp_ctrl, (void *)arg, sizeof(
					struct tcdp_comm_ctrl))) {
		cn_dev_core_err(core, "copy from user parameters failed!");
		return -EFAULT;
	}

	if (unlikely(tcdp_ctrl.type >= TCDP_CMD_CNT)) {
		cn_dev_core_err(core, "tcdp cmd <%d> is not supported",
				tcdp_ctrl.type);
		return -EINVAL;
	}

	cn_dev_core_debug(core, "tcdp cmd <%s>",
			tcdp_cmd_name[tcdp_ctrl.type]);

	if (tcdp_ctrl.size) {
		ret = alloc_param_buf(sbts_set->queue_manager, tcdp_ctrl.size,
				&host_param_va, &dev_param_va,
				SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
		if (unlikely(ret)) {
			cn_dev_core_err(core, "alloc param buffer failed!");
			return -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		}

		if (cn_bus_copy_from_usr_toio((u64)host_param_va,
				(u64)tcdp_ctrl.extern_data, tcdp_ctrl.size, core->bus_set)) {
			cn_dev_core_err(core, "copy kernel parameters failed!");
			ret = -EINVAL;
			goto copy_param_err;
		}

		tcdp_ctrl.extern_data = dev_param_va;
	}

	payload_size = fill_tcdp_cmd_desc(tcdp_ctrl.version, (__u64)user,
			&tx_desc, &tcdp_ctrl, core);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill tx descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto fill_desc_err;
	}

	print_time_detail("berfore ioctl");
	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
			(__u64)user, (__u64)payload_size);
	print_time_detail("after ioctl");

	if (ret || rx_desc.sta) {
		if (rx_desc.sta == 2) {
			ret = -CN_TCDP_UNSUPPORT;
		} else {
			cn_dev_core_err(core, "tcdp cmd <%s> failed ",
					tcdp_cmd_name[tcdp_ctrl.type]);
			cn_dev_core_err(core, "ret = %d, rx_sta = %llu",
					ret, rx_desc.sta);
			ret = -CN_SBTS_ERROR_IOCTL_FAILED;
		}

		goto ioctl_err;
	}

	data = (struct ctrl_desc_data_v1 *)rx_desc.data;
	tcdp_ret_ctrl = (struct tcdp_comm_ctrl *)data->priv;

	if (unlikely(tcdp_ret_ctrl->ret_code)) {
		ret = -(tcdp_ret_ctrl->ret_code + CN_TCDP_OP_SUCCESS);
		goto tcdp_ret_err;
	}

	if (copy_to_user((void *)arg, (void *)tcdp_ret_ctrl,
				sizeof(struct tcdp_comm_ctrl))) {
		cn_dev_core_err(core, "tcdp cmd <%s> copy to user parameters failed!",
				tcdp_cmd_name[tcdp_ctrl.type]);
		ret = -EFAULT;
		goto copy_err;
	}

	if (tcdp_ctrl.size) {
		free_param_buf(core, dev_param_va);
	}

	return 0;

copy_err:
tcdp_ret_err:
ioctl_err:
fill_desc_err:
copy_param_err:
	if (tcdp_ctrl.size) {
		free_param_buf(core, dev_param_va);
	}
	return ret;
}

int destroy_tcdp_resource(struct sbts_set *sbts_set, cn_user user)
{
	int ret;
	struct comm_ctrl_desc tx_desc;
	struct comm_ctrl_desc rx_desc;
	struct tcdp_comm_ctrl tcdp_ctrl = {0};
	struct cn_core_set *core = sbts_set->core;
	struct sched_manager *sched_mgr = sbts_set->sched_manager;
	__u64 payload_size = 0;

	if (!sbts_set->is_support_tcdp)
		return 0;

	tcdp_ctrl.version = SBTS_VERSION;
	tcdp_ctrl.type = TCDP_CMD_DESTROY_RESOURCE;
	payload_size = fill_tcdp_cmd_desc(SBTS_VERSION, (__u64)user,
			&tx_desc, &tcdp_ctrl, core);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed");
		return -CN_SBTS_ERROR_FILL_TASK_DESC;
	}

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
			(__u64)user, (__u64)payload_size);

	if (ret || rx_desc.sta) {
		if (rx_desc.sta == 2) {
			return -CN_TCDP_UNSUPPORT;
		} else {
			cn_dev_core_err(core, "destroy tcdp resource failed, ret[%d]", ret);
			return -CN_SBTS_ERROR_IOCTL_FAILED;
		}
	}

	return 0;
}

static int __sbts_tcdp_check_support(struct sbts_set *sbts_set)
{
	int ret;
	struct comm_ctrl_desc tx_desc;
	struct comm_ctrl_desc rx_desc;
	struct tcdp_comm_ctrl tcdp_ctrl = {0};
	struct cn_core_set *core = sbts_set->core;
	struct sched_manager *sched_mgr = sbts_set->sched_manager;
	__u64 payload_size = 0;
	__u64 user = 0;

	tcdp_ctrl.version = SBTS_VERSION;
	tcdp_ctrl.type = TCDP_CMD_GET_CAPACITY;
	payload_size = fill_tcdp_cmd_desc(SBTS_VERSION, (__u64)user,
			&tx_desc, &tcdp_ctrl, core);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed");
		return -ENOTSUPP;
	}

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
			(__u64)user, (__u64)payload_size);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "sbts ioctl failed!");
		return -EFAULT;
	}

	if (rx_desc.sta) {
		cn_dev_core_debug(core, "current platform do not support tcdp");
		sbts_set->is_support_tcdp = 0;
	} else {
		sbts_set->is_support_tcdp = 1;
	}

	return 0;

}

int sbts_tcdp_init(struct sbts_set *sbts_set)
{
	struct cn_core_set *core = sbts_set->core;
	int ret;

	ret = __sbts_tcdp_check_support(sbts_set);
	if (ret) {
		cn_dev_core_err(core, "tcdp support check failed");
		return ret;
	}

	return 0;
}

void sbts_tcdp_exit(struct sbts_set *sbts_set)
{
	/* do nothing */
}
