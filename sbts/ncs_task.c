/*
 * sbts/ncs_task.c
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
#include "cndrv_hpq.h"
#include "sbts.h"
#include "queue.h"
#include "notifier.h"
#include "cndrv_debug.h"
#include "ncs_task.h"
#include "cndrv_commu.h"
#include "cndrv_monitor.h"
#include "cndrv_xid.h"

#define NCS_QP_CARD_ID(qp)	(((qp) >> 60) & 0xf)

static int tcdp_enc_remap_remote_tcdp_win_base(struct cn_core_set *core,
			struct cn_core_set *rcore, struct cd_modify_qp *modify_qp_param);
static int tcdp_common_cfg(struct cn_core_set *core, struct cn_core_set *rcore,
			struct cd_modify_qp *modify_qp_param);
static int set_tcdp_cfg_flag(int tx_card, int rx_card);
static int clear_tcdp_cfg_flag(int tx_card, int rx_card);
static int clear_history_relation(struct cn_core_set *core);
struct ncs_linear_bar_info {
	struct cn_core_set *core;
	u64 bus_base;
	u64 phy_base;
	u64 axi_base;
	u64 size;
	int inited;
};
struct ncs_linear_bar_info linear_bar_info_tbl[MAX_FUNCTION_NUM];
int linear_bar_dir_tx_cfg_flag[MAX_FUNCTION_NUM][MAX_FUNCTION_NUM];


static inline __u64
fill_ncs_cmd_desc(__u64 version, __u64 user,
		struct comm_ctrl_desc *ctrl_desc,
		struct ncs_comm_ctrl *ncs_ctrl,
		struct cn_core_set *core)
{
	__u64 payload_size = 0;
	struct ctrl_desc_data_v1 *data =
		(struct ctrl_desc_data_v1 *)ctrl_desc->data;

	switch (version) {
		case SBTS_VERSION:
			ctrl_desc->version	= version;
			data->type          = NCS_COMM_CMD;
			data->user          = cpu_to_le64(user);

			memcpy(data->priv, ncs_ctrl, sizeof(struct ncs_comm_ctrl));

			payload_size = sizeof(struct comm_ctrl_desc);
			break;
		default:
			cn_dev_core_err(core, "version not match!");
			break;
	}

	return payload_size;
}

static void ncs_err(struct cn_core_set *core, int ncs_ret)
{
	switch (ncs_ret) {
	case CN_NCS_QP_MODIFY_PAIRING:
	case CN_NCS_QP_DESTROY_BUSY:
	case CN_NCS_TEMPLATE_CREATE_NO_RESOURCE:
	case CN_NCS_TEMPLATE_DESTROY_BUSY:
	case NCS_QP_IS_INJECTING_ERR:
		break;
	default:
		cn_xid_err(core, XID_MLULINK_ERR, "MLULINK Err %d", ncs_ret);
		break;
	}
}

int cn_ncs_cmd_func(struct sbts_set *sbts_set,
		void *arg,
		cn_user user)
{
	int ret = 0;
	__u64 payload_size = 0;
	struct ncs_comm_ctrl ncs_ctrl, *ncs_ret_ctrl;
	struct comm_ctrl_desc tx_desc;
	struct comm_ctrl_desc rx_desc;
	host_addr_t host_param_va = 0;
	dev_addr_t dev_param_va = 0;
	struct cn_core_set *core = sbts_set->core;
	struct cn_core_set *rcore = NULL;
	struct sched_manager *sched_mgr = sbts_set->sched_manager;
	struct ctrl_desc_data_v1 *data;
	struct cd_create_qp *create_qp_param = NULL;
	struct cd_modify_qp *modify_qp_param = NULL;
	__u64 param_addr = 0;

	if (copy_from_user((void *)&ncs_ctrl, (void *)arg, sizeof(
					struct ncs_comm_ctrl))) {
		cn_dev_core_err(core, "copy from user parameters failed!\n");
		return -EFAULT;
	}

	param_addr = ncs_ctrl.params;

	if (ncs_ctrl.param_size) {
		ret = alloc_param_buf(sbts_set->queue_manager, ncs_ctrl.param_size,
				&host_param_va, &dev_param_va,
				SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
		if (unlikely(ret)) {
			cn_dev_core_err(core, "alloc param buffer failed!\n");
			ret = -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
			goto alloc_param_err;
		}

		if (copy_from_user((void *)host_param_va,
				(void *)ncs_ctrl.params, ncs_ctrl.param_size)) {
			cn_dev_core_err(core, "copy kernel parameters failed!\n");
			ret = -EINVAL;
			goto copy_param_err;
		}

		ncs_ctrl.params = dev_param_va;
	}

	if (ncs_ctrl.type == NCS_CREATE_QP) {
		create_qp_param = (struct cd_create_qp *)ncs_ctrl.data;
		create_qp_param->key[5] = core->idx;
	} else if (ncs_ctrl.type == NCS_MODIFY_QP) {
		modify_qp_param = (struct cd_modify_qp *)ncs_ctrl.data;
	}

	/*
	 * Check ability and prepare input-parameters
	 */
	if (ncs_ctrl.type == NCS_CREATE_QP) {
		/* get pcie_tcdp win_base and win_size
		 *	key[7] : inplace_buffer
		 *	   [6] : inplace_buffer_size
		 *	   [5] : card_id
		 *	   [4] : qp_win_base
		 *	   [3] : qp_win_size
		 * Attetion, then [4][3] is only work with MLU580 who is PCIe-TCDP.
		 */
		if (core->device_id == MLUID_580 || core->device_id == MLUID_570) {
			if (cn_bus_get_tcdp_able(core->bus_set)) {
				create_qp_param->key[4] = cn_bus_get_tcdp_win_base(core->bus_set);
				if (!create_qp_param->key[4]) {
					cn_dev_core_err(core, "get tcdp_win_base error");
					ret = -EINVAL;
					goto ioctl_err;
				}
				create_qp_param->key[3] = cn_bus_get_tcdp_win_size(core->bus_set);
				if (!create_qp_param->key[3]) {
					cn_dev_core_err(core, "get tcdp_win_size error");
					ret = -EINVAL;
					goto ioctl_err;
				}
			} else {
				cn_dev_core_err(core, "do not support tcdp capablity");
				ret = -EINVAL;
				goto ioctl_err;
			}
		}
	} else if (ncs_ctrl.type == NCS_MODIFY_QP) {
		/*
		 * For TCDP-PCIe
		 * check link on ability bwtween remote_card and local_card
		 */
		if (core->device_id == MLUID_580 || core->device_id == MLUID_570) {
			rcore = cn_bus_get_core_set_via_card_id((int)NCS_QP_CARD_ID(modify_qp_param->rqp));
			if (cn_bus_tcdp_link_on_able(core->bus_set, rcore->bus_set) <= 0) {
				cn_dev_core_err(core, "local card-%lld and remote card-%lld can not link on via TCDP-PCIe",
					NCS_QP_CARD_ID(modify_qp_param->qp),
					NCS_QP_CARD_ID(modify_qp_param->rqp));
				ret = -EINVAL;
				goto ioctl_err;
			}
			if (tcdp_enc_remap_remote_tcdp_win_base(core, rcore, modify_qp_param)) {
				ret = -EINVAL;
				cn_dev_core_err(core, "local card-%lld to update tcdp win base for remote card-%lld failed",
					NCS_QP_CARD_ID(modify_qp_param->qp),
					NCS_QP_CARD_ID(modify_qp_param->rqp));
				goto ioctl_err;
			}
			/*This must do after remote tcdp win base remapped*/
			if (tcdp_common_cfg(core, rcore, modify_qp_param)) {
				ret = -EINVAL;
				cn_dev_core_err(core, "local card-%lld DIRenc_INDIR Config remote card-%lld failed",
					NCS_QP_CARD_ID(modify_qp_param->qp),
					NCS_QP_CARD_ID(modify_qp_param->rqp));
				goto ioctl_err;
			}
		}
	}

	payload_size = fill_ncs_cmd_desc(SBTS_VERSION, (__u64)user,
			&tx_desc, &ncs_ctrl, core);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill tx descriptor failed\n");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto fill_desc_err;
	}

	print_time_detail("berfore ioctl");
	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
			(__u64)user, (__u64)payload_size);
	print_time_detail("after ioctl");

	if (ret || rx_desc.sta) {
		if (rx_desc.sta == 2) {
			ret = -CN_NCS_UNSUPPORT;
		} else {
			if (ncs_ctrl.type < NCS_CMD_CNT)
				cn_xid_err(core, XID_MLULINK_ERR,
					"ncs cmd <%s> failed. ret = %d, rx_sta = %llu",
					ncs_cmd_name[ncs_ctrl.type], ret, rx_desc.sta);
			else
				cn_xid_err(core, XID_MLULINK_ERR,
					"ncs cmd type <%u> failed. ret = %d, rx_sta = %llu",
					ncs_ctrl.type, ret, rx_desc.sta);
			ret = -CN_SBTS_ERROR_IOCTL_FAILED;
		}

		goto ioctl_err;
	}

	data = (struct ctrl_desc_data_v1 *)rx_desc.data;
	ncs_ret_ctrl = (struct ncs_comm_ctrl *)data->priv;
	ncs_ret_ctrl->params = param_addr;

	if (unlikely(ncs_ret_ctrl->ret_code)) {
		ret = -(ncs_ret_ctrl->ret_code + CN_NCS_RET_CODE_BASE);
		ncs_err(core, -ret);
		goto ncs_ret_err;
	}

	if (copy_to_user((void *)arg, (void *)ncs_ret_ctrl,
				sizeof(struct ncs_comm_ctrl))) {
		cn_dev_core_err(core, "ncs cmd <%s> copy to user parameters failed!\n",
				ncs_cmd_name[ncs_ctrl.type]);
		ret = -EFAULT;
		goto copy_err;
	}

	return 0;

copy_err:
ncs_ret_err:
ioctl_err:
fill_desc_err:
copy_param_err:
	if (ncs_ctrl.param_size) {
		free_param_buf(core, dev_param_va);
	}
alloc_param_err:
	return ret;
}

int destroy_ncs_resource(struct sbts_set *sbts_set, cn_user user)
{
	int ret;
	struct comm_ctrl_desc tx_desc;
	struct comm_ctrl_desc rx_desc;
	struct ncs_comm_ctrl ncs_ctrl = {0};
	struct cn_core_set *core = sbts_set->core;
	struct sched_manager *sched_mgr = sbts_set->sched_manager;
	__u64 payload_size = 0;


	ncs_ctrl.version = SBTS_VERSION;
	ncs_ctrl.type = NCS_DESTROY_RESOURCE;
	payload_size = fill_ncs_cmd_desc(ncs_ctrl.version, (__u64)user,
			&tx_desc, &ncs_ctrl, core);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed\n");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto fill_desc_err;
	}

	print_time_detail("berfore ioctl");
	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
			(__u64)user, (__u64)payload_size);
	print_time_detail("after ioctl");

	if (ret || rx_desc.sta) {
		if (rx_desc.sta == 2) {
			ret = -CN_NCS_UNSUPPORT;
		} else {
			cn_dev_core_err(core, "destroy ncs resource failed\n");
			ret = -CN_SBTS_ERROR_IOCTL_FAILED;
		}
		goto ioctl_err;
	}

	return 0;
ioctl_err:
fill_desc_err:
	return ret;
}

static inline __u64
fill_desc_ncs_invoke_task(__u64 version, __u64 user,
		struct sbts_queue_invoke_task *user_param, host_addr_t host_param_va,
		dev_addr_t dev_param_va, struct sbts_kernel *kernel_param,
		struct comm_task_desc *task_desc, struct queue *queue, struct sbts_set *sbts)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	__u32 offset;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;
	int ret;
	u32 priv_size = kernel_param->priv_size;

	switch (version) {
	case SBTS_VERSION: {
		task_desc->version = version;

		/* get task desc data */
		data                 = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type           = INVOKE_NCS_TASK;
		data->user           = cpu_to_le64(user);
		data->dev_sid        = cpu_to_le64(queue->dev_sid);

		/* fill perf info */
		offset = sbts_task_get_perf_info(sbts, queue, NCS_TS_TASK,
				user_param, data, &priv_size);

		if (unlikely(priv_size > TASK_DESC_PRIV_MAX_SIZE)) {
			cn_dev_core_err(core, "copy size %u exceed maximum",
					priv_size);
			return payload_size;
		}
		data->priv_size      = priv_size;

		/* copy private data */
		if (copy_from_user((void *)data->priv, (void *)kernel_param->priv,
				kernel_param->priv_size)) {
			cn_dev_core_err(core, "copy priv failed!\n");
			return payload_size;
		}

		/* continue to fill task desc */
		data->param_data = cpu_to_le64(dev_param_va);

		/* copy ncs param from user */
		ret = copy_from_user((void *)host_param_va,
			(void *)kernel_param->params, kernel_param->param_size);
		if (ret) {
			cn_dev_core_err(core, "copy ncs_task parameters failed!\n");
			return payload_size;
		}

		/* calculate payload size: version + task + data + priv_size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) +
				priv_size + offset;
		break;
	}

	default: {
		cn_dev_core_err(core, "version not match!");
		break;
	}

	}

	return payload_size;
}

int sbts_invoke_ncs_kernel(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret = 0;
	__u64 payload_size = 0;
	host_addr_t host_param_va = 0;
	dev_addr_t dev_param_va = 0;
	struct comm_task_desc task_desc;
	struct sbts_kernel *kernel_param = &user_param->priv_data.kernel;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	u64 param_asize = 0;

	if (core->device_id != MLUID_290 &&
			core->device_id != MLUID_370 &&
			core->device_id != MLUID_365)
		return -CN_NCS_UNSUPPORT;

	param_asize = ALIGN(kernel_param->param_size, 8);
	/* alloc param shared memory */
	ret = alloc_param_buf(sbts->queue_manager, param_asize,
			&host_param_va, &dev_param_va,
			SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "alloc param buffer failed!\n");
		return -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
	}

	payload_size = fill_desc_ncs_invoke_task(kernel_param->version, (__u64)user,
			user_param, host_param_va, dev_param_va, kernel_param,
			&task_desc, queue, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed\n");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto err;
	}

	/* push task to device */
	print_time_detail("push task >>");
	ret = queue_push_task(sbts->queue_manager, queue, &task_desc,
			(__u64)user, payload_size);
	print_time_detail("push task <<");

	if (unlikely(ret)) {
		cn_xid_err(core, XID_MLULINK_ERR,
			"queue(%px) sid %#llx, invoke ncs_task failed!",
			queue, queue->dev_sid);
		goto err;
	}

	cn_dev_core_debug(core, "invoke ncs kernel finished!");
	return ret;

err:
	free_param_buf(core, dev_param_va);
	return ret;
}

/*
 * For MLU580's TCDP-PCIe huge bar who will be used as TX DIR route.
 */
static int tcdp_common_cfg(struct cn_core_set *core, struct cn_core_set *rcore,
		struct cd_modify_qp *modify_qp_param)
{
	int ret = 0;
	int tx_card;
	int rx_card;
	u64 rx_liner_bar_bus_base;
	u64 rx_liner_bar_bus_base_map;
	u64 rx_liner_bar_axi_base;
	u64 rx_liner_bar_size;
	u64 rx_tcdp_win_bus_base;
	int p2p_state;

	tx_card = core->idx;
	rx_card = rcore->idx;
	/***
	 * Prevent second config
	 */
	if (set_tcdp_cfg_flag(tx_card, rx_card)) {
		goto exit;
	}

	/*DIR ENC to remote HugeBar*/
	rx_liner_bar_bus_base = linear_bar_info_tbl[rx_card].bus_base;
	rx_liner_bar_axi_base = linear_bar_info_tbl[rx_card].axi_base;
	rx_liner_bar_size = linear_bar_info_tbl[rx_card].size;

	rx_liner_bar_bus_base_map = rx_liner_bar_bus_base;
	p2p_state = cn_bus_dma_p2p_able(core->bus_set, rcore->bus_set);
	if (p2p_state == P2P_ACS_OPEN || p2p_state == P2P_NO_COMMON_UPSTREAM_BRIDGE) {
		rx_liner_bar_bus_base_map = cn_bus_linear_bar_do_iommu_remap(core->bus_set,
				rcore->bus_set, core->idx, rcore->idx);
		if (!rx_liner_bar_bus_base_map) {
			ret = -1;
			cn_dev_core_err(core, "For access rcard-%d linear bar do iommu remap failed", rcore->idx);
			goto exit;
		}
		cn_dev_core_debug(core, "For access rcard-%d linear bar do iommu remap to [%llx]",
			rcore->idx, rx_liner_bar_bus_base_map);
	}
	cn_bus_tcdp_tx_dir_linear_bar_cfg(core->bus_set,
					tx_card, rx_card,
					rx_liner_bar_bus_base_map,
					rx_liner_bar_axi_base,
					rx_liner_bar_size);

	/*INDIR ENC-DEC with remote tcdp win bar*/
	rx_tcdp_win_bus_base = modify_qp_param->rkey[0];
	cn_bus_tcdp_txrx_indir_cfg(core->bus_set,
				tx_card, rx_card,
				rx_tcdp_win_bus_base);

	cn_dev_core_debug(core, "tx_card = %d", tx_card);
	cn_dev_core_debug(core, "rx_card = %d", rx_card);
	cn_dev_core_debug(core, "rx_liner_bar_bus_base = %llx", rx_liner_bar_bus_base);
	cn_dev_core_debug(core, "rx_liner_bar_bus_base_map = %llx", rx_liner_bar_bus_base_map);
	cn_dev_core_debug(core, "rx_liner_bar_axi_base = %llx", rx_liner_bar_axi_base);
	cn_dev_core_debug(core, "rx_liner_bar_size = %llx", rx_liner_bar_size);
	cn_dev_core_debug(core, "rx_tcdp_win_bus_base = %llx", rx_tcdp_win_bus_base);

exit:
	return ret;
}

int linear_bar_info_init(struct cn_core_set *core)
{
	u64 bus_base;
	u64 phy_base;
	u64 axi_base;
	u64 size;
	int ret = 0;

	bus_base = cn_bus_get_linear_bar_bus_base(core->bus_set);
	phy_base = cn_bus_get_linear_bar_bus_base(core->bus_set);
	axi_base = cn_bus_get_linear_bar_axi_base(core->bus_set);
	size = cn_bus_get_linear_bar_size(core->bus_set);

	if (bus_base && axi_base && size) {
		linear_bar_info_tbl[core->idx].core = core;
		linear_bar_info_tbl[core->idx].bus_base = bus_base;
		linear_bar_info_tbl[core->idx].phy_base = phy_base;
		linear_bar_info_tbl[core->idx].axi_base = axi_base;
		linear_bar_info_tbl[core->idx].size = size;
		linear_bar_info_tbl[core->idx].inited = 1; /*Init Done Flag*/
	} else {
		ret = -1;
	}

	cn_dev_core_debug(core, "linear bar bus_base = %llx", bus_base);
	cn_dev_core_debug(core, "linear bar phy_base = %llx", phy_base);
	cn_dev_core_debug(core, "linear bar axi_base = %llx", axi_base);
	cn_dev_core_debug(core, "linear bar size = %llx", size);

	return ret;
}

int linear_bar_info_exit(struct cn_core_set *core)
{
	clear_history_relation(core);
	linear_bar_info_tbl[core->idx].inited = 0;

	return 0;
}

static int clear_history_relation(struct cn_core_set *core)
{
	int i;
	int topo_member_cnt = MAX_FUNCTION_NUM;
	int idx = core->idx; //The core who is offline

	/*clear self*/
	for (i = 0; i < topo_member_cnt; i++) {
		clear_tcdp_cfg_flag(idx, i);
	}
	/*clear neighbours*/
	for (i = 0; i < topo_member_cnt; i++) {
		clear_tcdp_cfg_flag(i, idx);
	}

	return 0;
}

static int set_tcdp_cfg_flag(int tx_card, int rx_card)
{
	int flag_state = 0;
	struct cn_core_set *core = NULL;

	flag_state = __sync_val_compare_and_swap(&linear_bar_dir_tx_cfg_flag[tx_card][rx_card], 0, 1);

	/***
	 * Do not do set state on
	 *	1. ARM Do it only when get physical channel
	 */

	if (!flag_state && (tx_card != rx_card)) {
		core = cn_bus_get_core_set_via_card_id(tx_card);
		cn_dev_core_debug(core, "tcdp pcie turn on about rcard-%d", rx_card);
		cn_bus_tcdp_change_channel_state(core->bus_set, rx_card,
			TCDP_DIR_RX | TCDP_DIR_TX,
			TCDP_CHAN_ON);
	}
	return flag_state;
}

static int clear_tcdp_cfg_flag(int tx_card, int rx_card)
{
	struct cn_core_set *core = NULL;
	int flag_state = 0;

	flag_state = __sync_val_compare_and_swap(&linear_bar_dir_tx_cfg_flag[tx_card][rx_card], 1, 0);

	if (flag_state && (tx_card != rx_card)) {
		/***
		 * Attention, the core is accessable but cn_core table is invaid.
		 * when do remove, the cn_core will pre-clear before destroy core at last.
		 */
		core = linear_bar_info_tbl[tx_card].core;
		cn_dev_core_info(core, "tcdp pcie turn off about rcard-%d", rx_card);
		cn_bus_tcdp_change_channel_state(core->bus_set, rx_card,
			TCDP_DIR_RX | TCDP_DIR_TX,
			TCDP_CHAN_OFF);
	}

	return 0;
}

/*
 * In MLU580 TCDP-PCIe mode when the TLP pass RC then the TCDP win Base need
 * also do iommu remap and send it to ARM, and ARM will do second config for
 * the remote qp key.
 */
static int tcdp_enc_remap_remote_tcdp_win_base(struct cn_core_set *core,
		struct cn_core_set *rcore, struct cd_modify_qp *modify_qp_param)
{
	int p2p_state;
	int ret = 0;
	u64 new_tgt;
	u64 org_tgt;

	p2p_state = cn_bus_dma_p2p_able(core->bus_set, rcore->bus_set);
	if (p2p_state == P2P_ACS_OPEN || p2p_state == P2P_NO_COMMON_UPSTREAM_BRIDGE) {
		cn_dev_core_debug(core, "For access rcard-%d tcdp win base bar do iommu remap", rcore->idx);
		new_tgt = cn_bus_tcdp_win_base_do_iommu_remap(core->bus_set,
				rcore->bus_set, core->idx, rcore->idx);
		if (!new_tgt) {
			ret = -1;
			cn_dev_core_err(core, "For access rcard-%d tcdp win base bar do iommu remap failed", rcore->idx);
		} else {
			/*Keep same with arm driver*/
			org_tgt = modify_qp_param->rkey[0];
			modify_qp_param->rkey[0] = new_tgt;
			cn_dev_core_debug(core, "For access rcard-%d remap tcdp win base [%llx] to [%llx]",
				rcore->idx, org_tgt, new_tgt);
		}
	}
	return ret;
}
