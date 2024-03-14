/*
 * sbts/sbts_task.c
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
#if (KERNEL_VERSION(3, 17, 0) > LINUX_VERSION_CODE)
#include <linux/time.h>
#else
#include <linux/timekeeping.h>
#endif

#include "cndrv_core.h"
#include "../core/cndrv_ioctl.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_hpq.h"
#include "sbts.h"
#include "queue.h"
#include "notifier.h"
#include "hostfunc.h"
#include "dbg.h"
#include "./task_topo/sbts_topo.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "cndrv_monitor.h"
#include "core_dump.h"
#include "cndrv_lpm.h"
#include "cndrv_mcc.h"
#include "cndrv_os_compat.h"

static inline __u64
fill_desc_invoke_kernel(__u64 version, __u64 user,
		struct sbts_queue_invoke_task *user_param,
		host_addr_t host_param_va, dev_addr_t dev_param_va,
		struct sbts_kernel *param, struct comm_task_desc *task_desc,
		struct queue *queue, struct sbts_set *sbts, struct sbts_dev_topo_struct *dtopo)
{
	/* append priv data maybe perf or topo */
	__u32 append_size = 0;
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;
	u32 priv_size = param->priv_size;

	switch (version) {
	case SBTS_VERSION_C20_PARAM_SIZE:
	case SBTS_VERSION_C30_PARAM_SIZE:
		task_desc->version = version;

		/* get task desc data */
		data                 = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type           = INVOKE_KERNEL;
		data->user           = cpu_to_le64(user);
		data->dev_sid        = cpu_to_le64(queue->dev_sid);
		data->dev_topo_cmd   = sbts_queue_task_topo_cmd(user_param);
		data->has_kprintf    = param->params & 1ULL;

		/* topo data and perf data should not both exist */
		if (likely(!dtopo)) {
			/* fill perf info */
			append_size = sbts_task_get_perf_info(sbts, queue, NORMAL_TS_TASK,
					user_param, data, &priv_size);
		} else {
			sbts_task_disable_perf_info(data);
			if (sbts_task_fill_topo_info(sbts, user_param, dtopo,
					data, &priv_size, &append_size)) {
				cn_dev_core_err(core, "kernel task fill topo fail!");
				return 0;
			}
		}

		if (unlikely(priv_size > TASK_DESC_PRIV_MAX_SIZE)) {
			cn_dev_core_err(core, "copy size %u exceed maximum", priv_size);
			return payload_size;
		}

		data->priv_size      = priv_size;
		/* copy private data */
		if (copy_from_user((void *)data->priv, (void *)param->priv,
					param->priv_size)) {
			cn_dev_core_err(core, "copy payload failed!");
			return payload_size;
		}

		/* continue to fill task desc */
		data->param_data = cpu_to_le64(dev_param_va);

		/* copy kernel param from user */
		if (cn_bus_copy_from_usr_toio((u64)host_param_va,
				    (u64)(param->params & (~1ULL)),
				    param->param_size, core->bus_set)) {
			cn_dev_core_err(core, "copy kernel parameters from user failed!");
			return payload_size;
		}

		/* calculate payload size: version + task + data + priv_size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) +
				priv_size + append_size;
		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

int sbts_invoke_kernel(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret;
	__u64 payload_size = 0;
	host_addr_t host_param_va = 0;
	dev_addr_t dev_param_va = 0;
	struct comm_task_desc task_desc;
	struct sbts_kernel *kernel_param = &user_param->priv_data.kernel;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	u64 param_asize = 0;
	struct sbts_dev_topo_struct *dtopo = NULL;
	__u16 dev_topo_cmd = sbts_queue_task_topo_cmd(user_param);

	cn_dev_core_debug(core, "invoke kernel(%px) queue %#016llx", queue,
			queue->dev_sid);

	if (unlikely(sbts_topo_check_is_topo_task(dev_topo_cmd))) {
		dtopo = sbts_topo_get(user_param->dev_topo_id, (u64)user);
		if (!dtopo) {
			cn_dev_core_err(core, "cant find dtopo id %llu", user_param->dev_topo_id);
			return -EINVAL;
		}
	}

	/* alloc param shared memory */
	param_asize = ALIGN(kernel_param->param_size, 8);
	ret = alloc_param_buf(sbts->queue_manager, param_asize,
			&host_param_va, &dev_param_va,
			SBTS_ALLOC_PARAM_WAIT | (likely(!dtopo) ? SBTS_ALLOC_PARAM_MAX : SBTS_ALLOC_PARAM_HALF));
	if (unlikely(ret)) {
		cn_dev_core_err(core, "alloc param buffer failed!");
		ret = -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		goto put_topo;
	}

	payload_size = fill_desc_invoke_kernel(kernel_param->version, (__u64)user,
			user_param, host_param_va, dev_param_va, kernel_param,
			&task_desc, queue, sbts, dtopo);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto free_param;
	}

	/* push task to device */
	print_time_detail("push task >>");
	ret = queue_push_task_ctrl_ticket(sbts->queue_manager, queue, &task_desc,
				(__u64)user, payload_size, !sbts_topo_check_is_topo_param_task(dev_topo_cmd));
	print_time_detail("push task <<");
	if (likely(!ret)) {
		sbts_topo_update_push_num(dtopo, queue, dev_topo_cmd);
		goto put_topo;
	}

	cn_dev_core_err(core,
			"queue(%px) sid %#016llx invoke kernel failed!",
			queue, queue->dev_sid);
free_param:
	free_param_buf(core, dev_param_va);
put_topo:
	if (dtopo) sbts_topo_put(dtopo);
	return ret;
}

static inline __u64
fill_desc_invoke_kernel_debug(__u64 version, __u64 user,
		__u64 dev_ack_addr, host_addr_t host_param_va, dev_addr_t dev_param_va,
		struct sbts_dbg_kernel *param, struct comm_task_desc *task_desc,
		struct queue *queue, struct sbts_set *sbts)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;

	switch (version) {
	case SBTS_VERSION:
	case SBTS_VERSION_AF:
	case SBTS_VERSION_FETCH:
	case SBTS_VERSION_C20_PARAM_SIZE:
		task_desc->version = version;

		/* get task desc data */
		data               = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type         = INVOKE_KERNEL_DEBUG;
		data->user         = cpu_to_le64(user);
		data->dev_sid      = cpu_to_le64(queue->dev_sid);
		data->dev_shm_addr = cpu_to_le64(dev_ack_addr);
		data->has_kprintf  = param->params & 1UL;
		data->priv_size    = param->priv_size;
		/* fill clk id */
		sbts_task_disable_perf_info(data);

		if (unlikely(param->priv_size > TASK_DESC_PRIV_MAX_SIZE)) {
			cn_dev_core_err(core, "copy size %llu exceed maximum", param->priv_size);
			return payload_size;
		}

		/* copy private data */
		if (copy_from_user((void *)data->priv, (void *)param->priv,
					param->priv_size)) {
			cn_dev_core_err(core, "copy payload failed!");
			return payload_size;
		}

		/* continue to fill task desc */
		data->param_data = cpu_to_le64(dev_param_va);

		/* copy kernel param from user */
		if (cn_bus_copy_from_usr_toio((u64)host_param_va,
				    (u64)(param->params & (~1UL)),
				    param->param_size, core->bus_set)) {
			cn_dev_core_err(core, "copy kernel parameters from user failed!");
			return payload_size;
		}

		/* calculate payload size: version + task + data + priv_size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) + param->priv_size;
		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

static int
sbts_kernel_debug_v1(struct sbts_set *sbts,
		struct queue *queue,
		union sbts_task_priv_data *priv_data, cn_user user)
{
	int ret = 0;
	__u64 payload_size = 0;
	host_addr_t host_param_va = 0;
	dev_addr_t dev_param_va = 0;
	struct comm_task_desc task_desc;
	struct sbts_dbg_kernel *dbg_kernel = &priv_data->dbg_kernel;
	struct data_ack_desc *ack_data = NULL;
	/* data transfer will use shared memory */
	struct cn_core_set *core =
			(struct cn_core_set *)sbts->queue_manager->core;
	host_addr_t host_ack_va;
	dev_addr_t dev_ack_va;

	/* alloc device shared memory for data transfer
	 * size = ack_size + __u64 (polling status)
	 */
	ret = cn_device_share_mem_alloc(0, &host_ack_va, &dev_ack_va,
				dbg_kernel->ack_buffer_size + sizeof(__u64), core);
	if (ret) {
		cn_dev_core_err(core, "alloc data transfer share memory failed");
		ret = -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		goto out;
	}
	cn_dev_core_debug(core, "shared memory dev addr:%lld.", dev_ack_va);

	/* get data ack desc */
	ack_data = (struct data_ack_desc *)host_ack_va;
	ack_data->status = DATA_ACK_WAITING;

	/* alloc param shared memory */
	ret = alloc_param_buf(sbts->queue_manager, dbg_kernel->param_size,
			&host_param_va, &dev_param_va,
			SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "alloc param buffer failed!");
		ret =  -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		goto out;
	}

	payload_size = fill_desc_invoke_kernel_debug(dbg_kernel->version, (__u64)user,
			(__u64)dev_ack_va, host_param_va, dev_param_va, dbg_kernel,
			&task_desc, queue, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		free_param_buf(core, dev_param_va);
		ret =  -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto out;
	}

	/* push task to device */
	print_time_detail("push task >>");
	ret = queue_push_task(sbts->queue_manager, queue, &task_desc,
				(__u64)user, payload_size);
	print_time_detail("push task <<");

	if (unlikely(ret)) {
		cn_dev_core_err(core, "queue(%px) sid %#016llx", queue, queue->dev_sid);
		cn_dev_core_err(core, "invoke kernel failed!");
		free_param_buf(core, dev_param_va);
		goto out;
	}

	/* polling ack data status */
	ret = check_ack_data(core, ack_data);
	if (!ret) {
		/* success copy to user */
		if (copy_to_user((void *)dbg_kernel->ack_buffer,
				(void *)ack_data, dbg_kernel->ack_buffer_size)) {
			cn_dev_core_err(core, "kernel debug get task id copy to user failed!");
			ret = -EINVAL;
		}
	} else {
		/* failed return error */
		cn_dev_core_err(core, "invoke kernel debug get task id failed!");
	}

out:
	if (host_ack_va)
		cn_device_share_mem_free(0, host_ack_va, dev_ack_va, core);

	return ret;
}

int
sbts_dbg_kernel_invoke(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	__u64 generation;

	sbts_get_board_generation(sbts, &generation);

	if (generation >= SBTS_BOARD_GENERATION_3) {
		return sbts_kernel_debug_v2(sbts, queue, &user_param->priv_data, user);
	} else {
		return sbts_kernel_debug_v1(sbts, queue, &user_param->priv_data, user);
	}
}


static inline __u64
fill_desc_cngdb_task(__u64 version, __u64 user, __u64 dev_ack_iova,
		struct sbts_ctrl_task *param, struct comm_ctrl_desc *ctrl_desc,
		struct sbts_set *sbts)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct cd_cngdb_task *priv = NULL;
	/* version relate structure */
	struct ctrl_desc_data_v1 *data = NULL;

	switch (version) {
	case SBTS_VERSION:
		ctrl_desc->version = version;
		/* get ctrl desc data */
		data                = (struct ctrl_desc_data_v1 *)ctrl_desc->data;
		data->type          = CNGDB_TASK;
		data->user          = cpu_to_le64(user);
		/* get cd_cngdb_task structure */
		priv                = (struct cd_cngdb_task *)data->priv;
		priv->dev_ack_iova  = cpu_to_le64(dev_ack_iova);

		if (unlikely(param->priv_size >
				(CTRL_DESC_PRIV_MAX_SIZE -
				sizeof(struct cd_cngdb_task)))) {
			cn_dev_core_err(core, "copy size %lld exceed maximum", param->priv_size);
			return payload_size;
		}

		/* copy payload to task desc priv */
		if (copy_from_user((void *)priv->priv, (void *)param->priv,
					param->priv_size)) {
			cn_dev_core_err(core, "copy payload failed!");
			return payload_size;
		}

		/* calculate payload_size: version + data + ctrl + priv_head + priv_data */
		payload_size = sizeof(struct comm_ctrl_desc);

		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

int
cn_invoke_cngdb_task(struct sbts_set *sbts,
				 void *args,
				 cn_user user)
{
	int ret = 0;
	__u64 payload_size = 0;
	struct comm_ctrl_desc tx_cd;
	struct comm_ctrl_desc rx_cd;
	host_addr_t host_vaddr = 0;
	dev_addr_t dev_vaddr = 0;
	struct data_ack_desc *ack_data = NULL;

	struct cn_core_set *core =
			(struct cn_core_set *)sbts->queue_manager->core;
	struct sched_manager *sched_mgr = sbts->sched_manager;
	struct sbts_ctrl_task param = {0};

	if (copy_from_user((void *)&param, (void *)args, sizeof(
			struct sbts_ctrl_task))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	/* alloc device shared memory for data transfer */
	ret = cn_device_share_mem_alloc(0, &host_vaddr, &dev_vaddr,
				param.rx_size + sizeof(__u64), core);
	if (ret) {
		cn_dev_core_err(core, "alloc data transfer share memory failed");
		return -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
	}
	cn_dev_core_debug(core, "shared memory dev addr:%lld.", dev_vaddr);

	/* waiting data transfer */
	ack_data = (struct data_ack_desc *)host_vaddr;
	ack_data->status = DATA_ACK_WAITING;

	payload_size = fill_desc_cngdb_task(param.version, (__u64)user,
			(__u64)dev_vaddr, &param, &tx_cd, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed");
		ret =  -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto out;
	}

	ret = sched_mgr->ioctl(sched_mgr, &tx_cd, &rx_cd,
				(__u64)user, (__u64)payload_size);
	/* Cngdb task ioctl return 1 indicate there is no kernel debug
	 * task match this task id, cngdb also use this error to test
	 * whether a debug kernel is finish. Use info level log.
	 */
	if (unlikely(ret || rx_cd.sta)) {
		cn_dev_core_info(core, "invoke cngdb task failed!");
		ret = -CN_SBTS_ERROR_IOCTL_FAILED;
		goto out;
	}

	/* polling ack data status */
	ret = check_ack_data(core, ack_data);
	if (!ret) {
		/* success copy to user */
		if (copy_to_user((void *)param.rx,
				(void *)ack_data, param.rx_size)) {
			cn_dev_core_err(core, "cngdb task copy to user failed!");
			ret = -EINVAL;
		}
	} else {
		/* failed return error */
		cn_dev_core_err(core, "cngdb task failed!");
	}

out:
	if (host_vaddr)
		cn_device_share_mem_free(0, host_vaddr, dev_vaddr, core);

	return ret;
}

static int queue_sync_option(struct sbts_set *sbts,
				struct queue *queue, int option)
{
	int ret = 0;
	u64 sync_ticket;
	struct hpq_task_ack_desc ack_desc = {0};
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	bool should_yield = (option == CN_CTX_SCHED_SYNC_YIELD);
	int delay_cnt = 0;

	sync_ticket = READ_ONCE(queue->task_ticket);

	if (sync_ticket <= queue->sync_ticket) {
		return 0;
	}

	while (1) {
		ret = queue_get_ack_sta(queue, &ack_desc);
		if (ret) {
			cn_dev_core_err(core, "queue(%px) dsid %llu get ack status fail!", queue, queue->dev_sid);
			ret = -CN_QUEUE_ERROR_QUEUE_INVALID;
			break;
		}

		if (ack_desc.sta) {
			/* queue sta already set in queue_get_ack_sta */
			ret = queue_ack_sta_parse(core, queue, ack_desc);
			break;
		}

		if (sync_ticket <= ack_desc.seq_num) {
			queue->sync_ticket = ack_desc.seq_num;
			cn_dev_core_debug(core, "queue sync done sync ticket %llu seq done %llu",
						sync_ticket,
						ack_desc.seq_num);
			break;
		}

		if (READ_ONCE(queue->sta) == QUEUE_WAITING_DESTROY) {
			cn_dev_core_err(core, "queue did %llu host status %d exception!",
						queue->dev_sid, queue->sta);
			ret = -CN_QUEUE_ERROR_QUEUE_INVALID;
			break;
		}

		if (should_yield) {
			cond_resched();
		}

		if (core->reset_flag) {
			cn_dev_core_err(core, "the reset flag has been set!");
			ret = -EFAULT;
			break;
		}

#define SYNC_PAUSE_DELAY_CNT (50)
		/* need decrease pause time to enhance latency performance */
		if (++delay_cnt == SYNC_PAUSE_DELAY_CNT) {
			delay_cnt = 0;
			ret = sbts_pause_stopable(core, 3, 5);
		}

		if (ret) {
			if (ret == -ERESTARTNOINTR) {
				cn_dev_core_err(core,
						"queue(%px) dsid %llu, sync stop by signal(ret %d) cur_seq_num %llu ticket %llu",
						queue, queue->dev_sid, ret, ack_desc.seq_num, sync_ticket);
			} else {
				if (__sync_bool_compare_and_swap(&queue->sta,
							QUEUE_NORMAL, QUEUE_EXCEPTION)) {
					cn_dev_core_err(core, "queue(%px) sid %#016llx excep",
							queue, queue->dev_sid);
				}
				cn_dev_core_err(core,
					"queue(%px) dsid %llu, sync killed by signal cur_seq_num %llu ticket %llu",
					queue, queue->dev_sid, ack_desc.seq_num, sync_ticket);
			}
			break;
		}
	}

	return ret;
}

static inline int cn_queue_sync_spin(struct sbts_set *sbts,
				struct queue *queue)
{
	return queue_sync_option(sbts, queue, CN_CTX_SCHED_SYNC_SPIN);
}

static inline int cn_queue_sync_yield(struct sbts_set *sbts,
				struct queue *queue)
{
	return queue_sync_option(sbts, queue, CN_CTX_SCHED_SYNC_YIELD);
}

struct sync_queue_data {
	__le64 queue;
	__le64 sync_ticket;
	__le64 ack;
};

static inline void
queue_sync_wakeup(struct sync_queue_data *data, int status)
{
	data->ack = status;
}

static int queue_sync_handler(struct sbts_set *sbts, void *data)
{
	struct sync_queue_data *sync_desc = (struct sync_queue_data *)data;
	struct cn_core_set *core = sbts->core;
	struct hpq_task_ack_desc ack_desc = {0};
	struct queue *queue = NULL;
	__u64 sync_ticket = 0;

	queue = (struct queue *)sync_desc->queue;
	sync_ticket = sync_desc->sync_ticket;

	if (queue_get_ack_sta(queue, &ack_desc)) {
		cn_dev_core_err(core,
				"queue(%px) sid %#016llx get ack status fail!",
				queue, queue->dev_sid);
		queue_sync_wakeup(sync_desc, -CN_QUEUE_ERROR_QUEUE_INVALID);
		return 0;
	}

	if (ack_desc.sta) {
		queue_sync_wakeup(sync_desc, queue_ack_sta_parse(core, queue, ack_desc));
		return 0;
	}

	if (sync_ticket <= ack_desc.seq_num) {
		queue->sync_ticket = ack_desc.seq_num;
		cn_dev_core_debug(core, "queue sync done sync ticket %lld seq done %lld",
				(unsigned long long)sync_ticket,
				(unsigned long long)ack_desc.seq_num);
		queue_sync_wakeup(sync_desc, 0);
		return 0;
	}

	if (READ_ONCE(queue->sta) == QUEUE_WAITING_DESTROY) {
		cn_dev_core_err(core, "queue did %llu host status %d exception!",
					queue->dev_sid, queue->sta);
		queue_sync_wakeup(sync_desc, -CN_QUEUE_ERROR_QUEUE_INVALID);
		return 0;
	}

	return -EAGAIN;
}

static int cn_queue_sync_wait(struct sbts_set *sbts, struct queue *queue)
{
	int ret = 0;
	struct sbts_sync_desc sync_desc;
	struct sync_queue_data data;

	/* prepare sync queue data */
	data.queue       = (__le64)queue;
	data.ack         = 0;
	data.sync_ticket = READ_ONCE(queue->task_ticket);

	init_sbts_sync_desc(&sync_desc, queue_sync_handler, &data);
	ret = sbts_wait_sync_desc_interruptible(sbts, &sync_desc);
	ret = (ret ? ret : data.ack);
	return ret;
}

int cn_queue_sync_sched(struct sbts_set *sbts,
				struct queue *queue)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	cn_dev_core_debug(core, "queue sync sched flag is %d!", queue->sync_flags);

	/* wait sync result. default equal spin */
	switch (queue->sync_flags) {
		case CN_CTX_SCHED_SYNC_SPIN: {
			ret = cn_queue_sync_spin(sbts, queue);
			break;
		}

		case CN_CTX_SCHED_SYNC_WAIT: {
			ret = cn_queue_sync_wait(sbts, queue);
			break;
		}

		case CN_CTX_SCHED_SYNC_YIELD: {
			ret = cn_queue_sync_yield(sbts, queue);
			break;
		}

		default: {
			ret = cn_queue_sync_spin(sbts, queue);
			break;
		}
	}

	return ret;
}

int
sbts_queue_sync(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	return cn_queue_sync_sched(sbts, queue);
}

static int cn_queue_sync_inter(struct cn_core_set *core,
		cn_user user, u64 hqueue)
{
	struct sbts_set *sbts = core->sbts_set;
	struct queue *queue = NULL;
	int ret = 0;

	if (unlikely(!sbts)) {
		cn_dev_core_err(core, "sbts is null!");
		return -EINVAL;
	}

	queue = queue_get(sbts->queue_manager, hqueue, user, 1);
	if (!queue) {
		cn_dev_core_err(core, "queue_dsid(%#llx) is invalid!", hqueue);
		return -CN_QUEUE_ERROR_QUEUE_INVALID;
	}

	ret = cn_queue_sync_sched(sbts, queue);
	if (ret) {
		cn_dev_core_err(core, "queue_dsid(%#llx) sync failed!", hqueue);
	}

	queue_put(sbts->queue_manager, queue);
	return ret;
}

int
cn_queue_sync_for_func(struct sbts_set *sbts, u32 index)
{
	struct queue_for_func_mgr *func_mgr;
	struct cn_core_set *core;

	if (unlikely(!sbts)) {
		return -EINVAL;
	}

	core = sbts->core;
	func_mgr = sbts->que_func_mgr;

	if (index >= MAX_QUEUE_NUM_FOR_FUNC) {
		cn_dev_core_err(core, "index:%d is invalid!", index);
		return -EINVAL;
	}

	return cn_queue_sync_inter(core, 0, func_mgr->array[index]);
}

static inline u64 __wait_notifier_td_fill(
		struct sbts_set *sbts, __u64 user, struct queue *queue,
		struct sbts_queue_invoke_task *user_param,
		struct task_desc_data_v1 *data, u64 free_ticket,
		struct notifier *notifier, struct notifier_active_info *notifier_ainfo,
		struct sbts_dev_topo_struct *dtopo)
{
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct sbts_topo_notifier *notifier_param = &user_param->priv_data.topo_notifier;
	struct notifier_device_info *dev_info =
			sbts_notifier_dev_info(core, notifier);
	struct td_notifier_task *priv = NULL;
	u64 dev_addr = 0;
	/* append size is topo or perf priv size */
	u32 append_size = 0;
	u32 priv_size = 0;
	int ret = 0;

	priv = (struct td_notifier_task *)data->priv;

	if (free_ticket) {
		ret = queue_ack_get_seq_host_iova(core,
				notifier_ainfo->place_q_ack, &dev_addr);
		if (ret) {
			cn_dev_core_err(core, "get host iova failed");
			return 0;
		}
		/* wait the prev task which above place task */
		priv->unique_val   = cpu_to_le64(notifier_ainfo->place_q_seq);
		priv->ack_addr     = cpu_to_le64(dev_addr);
		priv->free_seq     = cpu_to_le64(free_ticket);
		priv->q_idx        = cpu_to_le64(notifier_ainfo->place_q_idx);
		priv->dev_idx      = cpu_to_le32(notifier_ainfo->place_c_idx);
		priv->excep_infect = cpu_to_le32(notifier->exception_infect);
		priv_size = sizeof(struct td_notifier_task);
	} else {
		/* basic wait task */
		priv->unique_val   = cpu_to_le64(dev_info->last_val);
		priv_size = sizeof(__u64);
	}
	/* TOPO task info */
	if (likely(!dtopo)) {
		/* fill perf info */
		append_size = sbts_task_get_perf_info(sbts, queue, NOTIFIER_TS_TASK,
				user_param, data, &priv_size);
	} else {
		if (free_ticket) {
			priv->q_total  = cpu_to_le64(notifier_param->qtask_total);
		} else {
			priv->ack_addr = cpu_to_le64(notifier_param->place_total);
			/* change size */
			priv_size = sizeof(__u64) * 2;
		}

		sbts_task_disable_perf_info(data);
		if (sbts_task_fill_topo_info(sbts, user_param, dtopo,
				data, &priv_size, &append_size)) {
			cn_dev_core_err(core, "wait task fill topo fail!");
			return 0;
		}
	}
	data->priv_size = priv_size;

	cn_dev_core_debug(core, "notifier %llu wait %llu q[%llu] total %llu tik %llu",
			notifier->dev_info->dev_eid, priv->unique_val, priv->q_idx, priv->q_total, free_ticket);

	return priv_size + append_size;
}

/*
 * we need use sbts_notifier_dev_info to get the right dev_info to use.
 *
 * If notifier without IPChandle, the function will return dev_info from notifier,
 * just use it as normal.
 *
 * If notifier with IPChandle, the Place before may used another notifier on it device.
 * And if this wait call use queue one the same device, we need to use the dev_info on that device.
 *
 * example:
 *
 *        notifier0 and notifier1 with same ipchandle.
 *
 * 1. placenotifier with queue0_dev0 notifier0_dev0;
 *	here will save dev0 and queue0 info on notifier0->ipchandle.
 *
 * 2. waitnotifier with  queue0_dev0 notifier1_dev1;
 *      here we need find the dev_info0 from notifier1_dev1->ipchandle->dev_info[0]
 *
 * */
static inline __u64
fill_desc_wait_notifier(__u64 version, __u64 user, u64 free_ticket,
		struct sbts_queue_invoke_task *user_param,
		struct comm_task_desc *task_desc, struct sbts_dev_topo_struct *dtopo,
		struct queue *queue, struct notifier *notifier, struct notifier_active_info *notifier_ainfo,
		struct sbts_set *sbts)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;
	struct notifier_device_info *dev_info =
			sbts_notifier_dev_info(core, notifier);
	u32 append_size = 0;

	sbts_td_priv_size_check(sizeof(struct td_notifier_task));

	switch (version) {
	case SBTS_VERSION:
		task_desc->version = version;

		/* get task desc data */
		data                 = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type           = free_ticket ? QUEUE_WAIT_NOTIFIER_EXTRA : QUEUE_WAIT_NOTIFIER;
		data->user           = cpu_to_le64(user);
		data->dev_sid        = cpu_to_le64(queue->dev_sid);
		data->dev_eid        = cpu_to_le64(dev_info->dev_eid);
		data->dev_topo_cmd   = sbts_queue_task_topo_cmd(user_param);

		append_size = __wait_notifier_td_fill(sbts, user, queue, user_param,
				data, free_ticket, notifier, notifier_ainfo, dtopo);
		if (append_size == 0) {
			cn_dev_core_err(core, "fill td fail");
			return 0;
		}

		/* calculate payload size: version + task + data + priv_size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) +
				append_size;
		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

static int __sbts_wait_notifier_common(
		struct sbts_set *sbts, struct queue *queue,
		struct notifier *notifier,
		struct sbts_queue_invoke_task *user_param,
		__u64 version, cn_user user)
{
	int ret = 0;
	__u64 payload_size = 0;
	struct comm_task_desc task_desc;
	struct notifier_active_info *notifier_ainfo = notifier->active_info;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct sbts_dev_topo_struct *dtopo = NULL;
	u64 free_ticket = 0;
	bool use_q_ack = false;
	__u16 dev_topo_cmd = sbts_queue_task_topo_cmd(user_param);

	if (notifier_task_param_check(user_param)) {
		cn_dev_core_err(core, "notifier task param check fail");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}

	if (unlikely(sbts_topo_check_is_topo_task(dev_topo_cmd))) {
		dtopo = sbts_topo_get(user_param->dev_topo_id, (u64)user);
		if (!dtopo) {
			cn_dev_core_err(core, "cant find dtopo id %llu", user_param->dev_topo_id);
			return -EINVAL;
		}
	}

	//lock necessary
	mutex_lock(&notifier_ainfo->mutex);
	if (!notifier_ainfo->place_q_ack) {
		cn_dev_core_debug(core, "notifier is unused");
		ret = 0;
		goto exit;
	}
	use_q_ack = (queue->core == notifier_ainfo->place_core) ? false : true;
	if (use_q_ack == true) {
		/* create free info on queue dev */
		ret = notifier_dev_free_create(sbts, notifier_ainfo, &free_ticket);
		if (ret) {
			cn_dev_core_err(core, "create dev free res failed");
			goto exit;
		}
	}

	payload_size = fill_desc_wait_notifier(version, (__u64)user, free_ticket,
			user_param, &task_desc, dtopo,
			queue, notifier, notifier_ainfo, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto payload_err;
	}

	ret = queue_push_task(sbts->queue_manager, queue, &task_desc,
				(__u64)user, payload_size);
	if (ret) {
		cn_dev_core_err(core, "queue(%px) sid %#016llx", queue, queue->dev_sid);
		cn_dev_core_err(core, "push task fail");
	} else {
		if (use_q_ack == false)
			notifier->dev_info->waiter_nr++;
		sbts_topo_update_push_num(dtopo, queue, dev_topo_cmd);
		goto exit;
	}

payload_err:
	if (free_ticket)
		notifier_dev_free_release(sbts, free_ticket);
exit:
	mutex_unlock(&notifier_ainfo->mutex);
	if (dtopo) sbts_topo_put(dtopo);

	return ret;
}

int sbts_wait_notifier(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret = 0;
	struct notifier *notifier = NULL;
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct sbts_notifier *notifier_param = &user_param->priv_data.notifier;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	notifier = notifier_get(notifier_mgr, notifier_param->hnotifier, user);
	if (!notifier) {
		cn_dev_core_err(core, "notifier %#llx is invalid", notifier_param->hnotifier);
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}

	ret = __sbts_wait_notifier_common(sbts, queue, notifier, user_param,
			notifier_param->version, user);

	notifier_put(notifier_mgr, notifier);
	return ret;
}

extern int sbts_wait_notifier_extra(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct sbts_notifier_extra *notifier_param = &user_param->priv_data.notifier_extra;
	struct notifier *notifier = NULL;
	cn_user n_user;
	struct sbts_set *n_sbts;
	struct notifier_mgr *n_notifier_mgr;

	if (!sbts_notifier_feature_available(core))
		return -EPERM;

	/* first check&get notifier from input fd */
	n_sbts = sbts_get_sbtsset_by_fd(notifier_param->fd, &n_user);
	if (!n_sbts)
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	n_notifier_mgr = n_sbts->notifier_mgr;

	notifier = notifier_get(n_notifier_mgr, notifier_param->hnotifier, n_user);
	if (!notifier) {
		cn_dev_core_err(n_sbts->core, "notifier %#llx is invalid", notifier_param->hnotifier);
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}

	ret = __sbts_wait_notifier_common(sbts, queue, notifier, user_param,
			notifier_param->version, user);

	notifier_put(n_notifier_mgr, notifier);
	return ret;
}

static inline __u64
fill_desc_place_notifier(__u64 version, __u64 user,
		struct sbts_queue_invoke_task *user_param,
		struct comm_task_desc *task_desc,
		struct queue *queue, struct notifier *notifier, struct sbts_set *sbts,
		struct sbts_dev_topo_struct *dtopo)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;
	struct td_notifier_task *priv = NULL;
	struct sbts_topo_notifier *notifier_param = &user_param->priv_data.topo_notifier;
	u32 priv_size = 0;
	u32 append_size = 0;

	switch (version) {
	case SBTS_VERSION:
		task_desc->version = version;

		/* get task desc data */
		data                 = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type           = PLACE_NOTIFIER;
		data->user           = cpu_to_le64(user);
		data->dev_sid        = cpu_to_le64(queue->dev_sid);
		data->dev_eid        = cpu_to_le64(notifier->dev_info->dev_eid);
		data->dev_topo_cmd   = sbts_queue_task_topo_cmd(user_param);

		priv      = (struct td_notifier_task *)data->priv;
		priv_size = sizeof(__le64);

		if (likely(!dtopo)) {
			append_size = sbts_task_get_perf_info(sbts, queue, NOTIFIER_TS_TASK,
					user_param, data, &priv_size);
		} else {
			priv->ack_addr = cpu_to_le64(notifier_param->place_total);
			priv_size += sizeof(__le64);

			sbts_task_disable_perf_info(data);
			if (sbts_task_fill_topo_info(sbts, user_param, dtopo,
					data, &priv_size, &append_size)) {
				cn_dev_core_err(core, "place notifier fill topo fail!");
				return 0;
			}
		}
		data->priv_size      = priv_size;
		/* add last_val before dtopo to avoid fail and sub back */
		priv->unique_val     = cpu_to_le64(__sync_add_and_fetch(&notifier->dev_info->last_val, 1));

		/* calculate payload size: version + task + data + priv_size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) +
				priv_size + append_size;
		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

int sbts_place_notifier(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret = 0;
	u64 q_seq = 0;
	__u64 payload_size = 0;
	struct notifier *notifier = NULL;
	struct sbts_dev_topo_struct *dtopo = NULL;
	struct notifier_active_info *notifier_ainfo = NULL;
	struct comm_task_desc task_desc;
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct sbts_notifier *notifier_param = &user_param->priv_data.notifier;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	__u16 dev_topo_cmd = sbts_queue_task_topo_cmd(user_param);

	if (notifier_task_param_check(user_param)) {
		cn_dev_core_err(core, "notifier task param check fail");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}

	if (unlikely(sbts_topo_check_is_topo_task(dev_topo_cmd))) {
		dtopo = sbts_topo_get(user_param->dev_topo_id, (u64)user);
		if (!dtopo) {
			cn_dev_core_err(core, "cant find dtopo id %llu", user_param->dev_topo_id);
			return -EINVAL;
		}
	}

	notifier = notifier_get(notifier_mgr, notifier_param->hnotifier, user);
	if (!notifier) {
		cn_dev_core_err(core, "notifier %#llx is invalid", notifier_param->hnotifier);
		ret = -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
		goto put_topo;
	}
	notifier_ainfo = notifier->active_info;

	/* lock necessary */
	mutex_lock(&notifier_ainfo->mutex);

	payload_size = fill_desc_place_notifier(notifier_param->version, (__u64)user,
			user_param, &task_desc, queue, notifier, sbts, dtopo);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		ret =  -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto payload_err;
	}

	ret = queue_push_task_ticket(sbts->queue_manager, queue, &task_desc,
				(__u64)user, payload_size, &q_seq);
	if (ret) {
		cn_dev_core_err(core, "queue(%px) sid %#016llx push task fail", queue, queue->dev_sid);
		__sync_sub_and_fetch(&notifier->dev_info->last_val, 1);
	} else {
		__sync_add_and_fetch(&notifier->dev_info->capturer_nr, 1);
		notifier_place_save_q_ack(queue, notifier,
				notifier_ainfo, q_seq);
		/* save host hw time */
		notifier->host_place_time = sbts_queue_get_host_time(queue);
		sbts_topo_update_push_num(dtopo, queue, dev_topo_cmd);
	}

	cn_dev_core_debug(core, "place notifier %px-%#llx finished", notifier, notifier->dev_info->dev_eid);

payload_err:
	mutex_unlock(&notifier_ainfo->mutex);
	notifier_put(notifier_mgr, notifier);
put_topo:
	if (dtopo) sbts_topo_put(dtopo);
	return ret;
}

/* restore some flag or value when last user exit */
void cn_sbts_restore_resource(struct cn_core_set *core)
{
	struct sbts_set *sbts = core->sbts_set;

	if (!sbts)
		return;

	if (!sbts->queue_manager)
		return;
	WRITE_ONCE(sbts->queue_manager->nomem_flag, 0);
	WRITE_ONCE(sbts->queue_manager->halfmem_flag, 0);
}

static __u64
fill_desc_get_hw_info(__u64 version, __u64 dev_iova,
		struct comm_ctrl_desc *ctrl_desc,
		struct sbts_set *sbts)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	/* version relate structure */
	struct ctrl_desc_data_v1 *data = NULL;
	struct cd_get_hw_info *priv = NULL;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	switch (version) {
	case SBTS_VERSION:
		ctrl_desc->version = version;
		/* get ctrl desc data */
		data             = (struct ctrl_desc_data_v1 *)ctrl_desc->data;
		data->type       = GET_HW_INFO;
		priv             = (struct cd_get_hw_info *)data->priv;
		priv->dev_iova   = cpu_to_le64(dev_iova);

		/* calculate payload_size: version + ctrl + data + ctrl_priv */
		payload_size = sizeof(struct comm_ctrl_desc);
		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

int
cn_get_hw_info(struct sbts_set *sbts)
{
	/* must init tx_desc & rx_desc */
	struct comm_ctrl_desc tx_desc = {0};
	struct comm_ctrl_desc rx_desc = {0};
	struct sched_manager *sched_mgr = sbts->sched_manager;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct sbts_hw_info *hw_info = NULL;
	struct ctrl_desc_data_v1 *data =
			(struct ctrl_desc_data_v1 *)&rx_desc.data;
	struct cd_get_hw_info *priv =
			(struct cd_get_hw_info *)data->priv;

	__u64 payload_size = 0;
	host_addr_t host_va = 0;
	dev_addr_t dev_iova = 0;
	int ret = 0;

	/* send an empty message to get shm size */
	payload_size = fill_desc_get_hw_info(SBTS_VERSION,
					0, &tx_desc, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed");
		ret = -ENOTSUPP;
		goto out;
	}

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
				ANNOY_USER, (__u64)payload_size);
	if (unlikely(ret || rx_desc.sta)) {
		cn_dev_core_err(core, "sbts ioctl failed!");
		ret = -EFAULT;
		goto out;
	}

	cn_dev_core_info(core, "malloc shm size is %lld",
				le64_to_cpu(priv->shm_size));

	ret = cn_device_share_mem_alloc(0, &host_va,
				&dev_iova, le64_to_cpu(priv->shm_size), core);
	if (ret) {
		cn_dev_core_err(core, "alloc data transfer share memory failed");
		ret = -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		goto out;
	}

	payload_size = fill_desc_get_hw_info(SBTS_VERSION,
					dev_iova, &tx_desc, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed");
		ret = -ENOTSUPP;
		goto free_shm;
	}

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
				ANNOY_USER, (__u64)payload_size);
	if (unlikely(ret || rx_desc.sta)) {
		cn_dev_core_err(core, "sbts ioctl failed!");
		ret = -EFAULT;
		goto free_shm;
	}

	hw_info = (struct sbts_hw_info *)host_va;

	sbts->hw_info = cn_numa_aware_kzalloc(core, hw_info->size, GFP_KERNEL);
	if (unlikely(!sbts->hw_info)) {
		cn_dev_core_err(core, "alloc core hw info struct failed!");
		ret = -ENOMEM;
		goto free_shm;
	}

	memcpy_fromio(sbts->hw_info, hw_info, hw_info->size);

free_shm:
	if (host_va)
		cn_device_share_mem_free(0, host_va, dev_iova, core);
out:
	return ret;
}


static int
__raw_set_schedule_policy(struct sbts_set *sbts, int policy)
{
	struct cn_core_set *core = sbts->core;
	struct comm_ctrl_desc tx = {0}, rx = {0};
	struct sched_manager *sched_mgr = sbts->sched_manager;
	struct ctrl_desc_data_v1 *data;
	struct cd_schedule_policy *priv;
	int ret;

	/* fill desc */
	tx.version   = SBTS_VERSION;
	data         = (struct ctrl_desc_data_v1 *)tx.data;
	data->type   = TASK_ACCELERATE;
	priv         = (struct cd_schedule_policy *)data->priv;
	priv->policy = cpu_to_le64(policy);

	ret = sched_mgr->ioctl(sched_mgr, &tx, &rx, ANNOY_USER, sizeof(tx));
	if (unlikely(ret || rx.sta)) {
		cn_dev_core_err(core, "can not set accelerate model now!");
		return -EFAULT;
	}

	return 0;
}

static char *schedule_policy[SCH_POLICY_NUM] = {
	"auto", "acc", "normal",
};

int cn_sbts_set_schedule_policy(struct cn_core_set *core, char *str)
{
	int policy = 0;
	int ret = 0;
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;

	if (!sbts) {
		cn_dev_err("[fatal error] sbts set is null");
		return -EINVAL;
	}

	for (policy = 0; policy < SCH_POLICY_NUM; policy++) {
		if (!strcmp(str, schedule_policy[policy]))
			break;
	}

	if (policy == SCH_POLICY_NUM)
		return -EINVAL;

	if (mutex_lock_killable(&sbts->policy_lock))
		return -EINTR;

	if (sbts->schedule_policy == policy) {
		mutex_unlock(&sbts->policy_lock);
		return 0;
	}

	ret = __raw_set_schedule_policy(sbts, policy);
	if (!ret)
		sbts->schedule_policy = policy;

	mutex_unlock(&sbts->policy_lock);

	return ret;
}

int cn_sbts_get_schedule_policy(struct cn_core_set *core, char *str)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;

	if (!sbts) {
		cn_dev_err("[fatal error] sbts set is null");
		return -EINVAL;
	}

	strcpy(str, schedule_policy[sbts->schedule_policy]);

	return 0;
}

static char *queue_sch_policy[QUEUE_SCH_POLICY_NUM] = {
	"qfs", "noop",
};

int cn_sbts_set_queue_sch_policy(	struct cn_core_set *core, char *str)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct comm_ctrl_desc tx = {0}, rx = {0};
	struct sched_manager *sched_mgr;
	struct ctrl_desc_data_v1 *data;
	struct cd_queue_sch_policy *priv;
	int policy = 0;
	int ret = 0;

	if (!sbts) {
		cn_dev_err("[fatal error] sbts set is null");
		return -EINVAL;
	}

	for (policy = 0; policy < QUEUE_SCH_POLICY_NUM; policy++) {
		if (!strcmp(str, queue_sch_policy[policy]))
			break;
	}

	if (policy == QUEUE_SCH_POLICY_NUM)
		return -EINVAL;

	if (mutex_lock_killable(&sbts->policy_lock))
		return -EINTR;

	if (sbts->queue_sch_policy == policy) {
		mutex_unlock(&sbts->policy_lock);
		return 0;
	}

	sched_mgr = sbts->sched_manager;

	/* fill desc */
	tx.version   = SBTS_VERSION;
	data         = (struct ctrl_desc_data_v1 *)tx.data;
	data->type   = QUEUE_SCH_POLICY;
	priv         = (struct cd_queue_sch_policy *)data->priv;
	priv->policy = cpu_to_le64(policy);

	ret = sched_mgr->ioctl(sched_mgr, &tx, &rx, ANNOY_USER, sizeof(tx));
	if (unlikely(ret || rx.sta)) {
		cn_dev_core_err(core, "can not change queue schedule policy!");
		ret = -EINVAL;
	} else {
		sbts->queue_sch_policy = policy;
	}

	mutex_unlock(&sbts->policy_lock);

	return ret;
}

int cn_sbts_get_queue_sch_policy(struct cn_core_set *core, char *str)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;

	if (!sbts) {
		cn_dev_err("[fatal error] sbts set is null");
		return -EINVAL;
	}

	strcpy(str, queue_sch_policy[sbts->queue_sch_policy]);

	return 0;
}

int cn_sbts_get_old_aiisp_policy(struct cn_core_set *core, __u32 *policy)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;

	if (!sbts) {
		cn_dev_err("[fatal error] sbts set is null");
		return -EINVAL;
	}

	*policy =  sbts->aiisp_policy;
	return 0;
}

int cn_sbts_set_aiisp_policy(struct cn_core_set *core, __u32 policy)
{
	struct sbts_set *sbts = core->sbts_set;
	struct comm_ctrl_desc tx = {0}, rx = {0};
	struct sched_manager *sched_mgr;
	struct ctrl_desc_data_v1 *data;
	struct cd_aiisp_core_policy *priv;

	int ret = 0;

	if (!sbts) {
		cn_dev_err("[fatal error] sbts set is null");
		return -EINVAL;
	}

	if (policy >= CORE_TYPE_POLICY_NUM) {
		return -EINVAL;
	}

	if (mutex_lock_killable(&sbts->policy_lock)) {
		return -EINTR;
	}

	if (sbts->aiisp_policy == policy) {
		mutex_unlock(&sbts->policy_lock);
		return 0;
	}

	sched_mgr = sbts->sched_manager;

	/* fill desc */
	tx.version   = SBTS_VERSION;
	data         = (struct ctrl_desc_data_v1 *)tx.data;
	data->type   = CORE_TYPE_POLICY;
	priv         = (struct cd_aiisp_core_policy *)data->priv;
	priv->policy = cpu_to_le64(policy);

	ret = sched_mgr->ioctl(sched_mgr, &tx, &rx, ANNOY_USER, sizeof(tx));
	if (unlikely(ret || rx.sta)) {
		cn_dev_core_err(core, "can not change aiisp policy!");
		ret = -EINVAL;
	} else {
		sbts->aiisp_policy = policy;
	}

	mutex_unlock(&sbts->policy_lock);

	return ret;
}

static char *aiisp_policy[CORE_TYPE_POLICY_NUM] = {
	"aiisp_disable",
	"aiisp_enable",
};

int  cn_sbts_get_aiisp_policy(struct cn_core_set *core, char *str, int n)
{
	struct sbts_set *sbts = core->sbts_set;

	if (!sbts) {
		cn_dev_err("[fatal error] sbts set is null");
		return -EINVAL;
	}

	if (!sbts->aiisp_policy) {
		strncpy(str, aiisp_policy[0], n);
	} else {
		strncpy(str, aiisp_policy[1], n);
	}

	return 0;
}

static void
__fill_usr_sbts_info_v0(struct user_sbts_info_v0 *usr,
		struct sbts_basic_info *basic)
{
	/* cluster basic info */
	usr->cluster_num = basic->cluster_num;
	usr->ipu_core_num_per_clu = basic->ipu_core_num_per_clu;
	usr->mem_core_num_per_clu = basic->mem_core_num_per_clu;
	/* core dump info */
	usr->dump_header_size = DUMP_HEADER_SIZE_V4;
	usr->ipu_dump_buf_size =
		basic->ipu_core_dump_size;
	usr->mem_dump_buf_size =
		basic->mem_core_dump_size;
	/* ipu arch info */
	usr->ldram_base_addr = basic->ldram_base_addr;
	usr->ldram_stride = basic->ldram_stride;
	usr->ct_ram_size = basic->ct_ram_size;
	usr->lt_ram_size = basic->lt_ram_size;
	usr->shared_mem_size = basic->shared_mem_size;
	/* c2c info */
	usr->c2c_port_num = basic->c2c_port_num;
}

static void
__fill_usr_sbts_info(user_sbts_info_t *usr,
		     struct sbts_basic_info *basic)
{
	/* cluster basic info */
	usr->cluster_num = basic->cluster_num;
	usr->ipu_core_num_per_clu = basic->ipu_core_num_per_clu;
	usr->mem_core_num_per_clu = basic->mem_core_num_per_clu;
	/* core dump info */
	usr->dump_header_size = DUMP_HEADER_SIZE_V4;
	usr->ipu_dump_buf_size =
		basic->ipu_core_dump_size;
	usr->mem_dump_buf_size =
		basic->mem_core_dump_size;
	usr->ncs_dump_buf_size =
		basic->ncs_core_dump_size;
	/* ipu arch info */
	usr->ldram_base_addr = basic->ldram_base_addr;
	usr->ldram_stride = basic->ldram_stride;
	usr->ct_ram_size = basic->ct_ram_size;
	usr->lt_ram_size = basic->lt_ram_size;
	usr->shared_mem_size = basic->shared_mem_size;
	/* c2c info */
	usr->c2c_port_num = basic->c2c_port_num;

	/* v2 add */
	usr->tiny_core_num = basic->tiny_core_num;
	usr->tnc_dump_buf_size =
		basic->tiny_core_dump_size;
	usr->queue_dump_buf_size = usr->dump_header_size +
		(usr->ipu_core_num_per_clu * usr->ipu_dump_buf_size +
		usr->mem_core_num_per_clu * usr->mem_dump_buf_size) * usr->cluster_num +
		usr->tnc_dump_buf_size * usr->tiny_core_num;
	/* ... */

	/* v3 add */
	usr->tcdp_proxy_driver_version = basic->tcdp_proxy_driver_version;
	usr->tcdp_proxy_rpc_buffer = basic->tcdp_proxy_rpc_buffer;
}

int
cn_user_get_hw_info(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct sbts_get_hw_info param = {0};
	struct sbts_hw_info *info = sbts->hw_info;
	struct sbts_basic_info *basic = (struct sbts_basic_info *)info->data;
	__u64 host_version = 0;
	int ret = 0;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
		   struct sbts_get_hw_info))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	/* use different version to get different structure */
	host_version = GET_HOST_VERSION(param.version);

	switch (host_version) {
	case 0: {
		struct user_sbts_info_v0 usr_info_0 = {0};
		/* construct user sbts hw info */
		__fill_usr_sbts_info_v0(&usr_info_0, basic);

		/* copy all hw_info to user */
		if (copy_to_user((void *)param.addr, (void *)&usr_info_0,
					sizeof(usr_info_0))) {
			cn_dev_core_err(core, "copy hw info failed!");
			ret = -EINVAL;
		}

		break;
	}
	case 1:
	case 2:
	case 3: {
		user_sbts_info_t user_info = {0};
		const uint32_t copy_size_table[] = {
			USER_SBTS_INFO_V1_SIZE,
			USER_SBTS_INFO_V2_SIZE,
			USER_SBTS_INFO_V3_SIZE,
		};

		__fill_usr_sbts_info(&user_info, basic);
		if (copy_to_user((void *)param.addr, &user_info,
				 copy_size_table[host_version - 1])) {
			cn_dev_core_err(core, "copy hw info failed (%llu)", host_version);
			return -EINVAL;
		}
		break;
	}
	default:
		cn_dev_core_err(core, "unknown hw info struct version!");
		return -EFAULT;
	}

	return ret;
}

void
cn_release_hw_info(struct sbts_set *sbts)
{
	if (!sbts->hw_info)
		return;

	cn_kfree(sbts->hw_info);
	sbts->hw_info = NULL;
}

int
sbts_commu_detach(struct sbts_set *sbts)
{
	int ret = 0;
	__u64 payload_size = 0;
	struct comm_ctrl_desc tx_desc;
	struct comm_ctrl_desc rx_desc;
	struct sched_manager *sched_mgr = sbts->sched_manager;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct ctrl_desc_data_v1 *data = NULL;

	tx_desc.version = SBTS_VERSION;
	data = (struct ctrl_desc_data_v1 *)tx_desc.data;
	data->type = COMMU_DETACH;
	payload_size = sizeof(struct comm_ctrl_desc);

	cn_dev_core_debug(core, "commu detach begin!");
	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
			0/* no need user */, (__u64)payload_size);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "sbts ioctl failed!");
		return -EFAULT;
	}

	ret = rx_desc.sta;
	if (unlikely(ret)) {
		cn_dev_core_err(core, "commu detach failed!");
		return -EIO;
	}

	cn_dev_core_debug(core, "commu detach finish!");
	return 0;
}

static u64
fill_desc_hw_cfg_hdl(u64 version, struct sbts_set *sbts,
		struct comm_ctrl_desc *ctrl_desc, struct sbts_hw_cfg_hdl *param)
{
	u64 payload_size = 0;
	struct ctrl_desc_data_v1 *data = NULL;
	struct cd_hw_cfg_hdl *priv = NULL;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	switch (version) {
	case SBTS_VERSION:
		ctrl_desc->version = version;
		data               = (struct ctrl_desc_data_v1 *)ctrl_desc->data;
		data->type         = HW_CFG_HDL;
		priv               = (struct cd_hw_cfg_hdl *)data->priv;
		priv->type         = cpu_to_le64(param->type);
		priv->val          = cpu_to_le64(param->val);

		payload_size = sizeof(struct comm_ctrl_desc);
		break;
	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

static int sbts_hw_cfg_hdl(cn_user user, struct sbts_set *sbts,
		struct sbts_hw_cfg_hdl *param)
{
	struct cn_core_set *core = sbts->core;
	struct sched_manager *sched_mgr = sbts->sched_manager;
	struct comm_ctrl_desc tx_desc = {0};
	struct comm_ctrl_desc rx_desc = {0};
	struct ctrl_desc_data_v1 *data =
			(struct ctrl_desc_data_v1 *)&rx_desc.data;
	struct cd_hw_cfg_hdl *priv =
			(struct cd_hw_cfg_hdl *)data->priv;
	u64 payload_size = 0;
	int ret = 0;

	payload_size = fill_desc_hw_cfg_hdl(param->version, sbts, &tx_desc, param);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed");
		return -ENOTSUPP;
	}

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc, (__u64)user, payload_size);
	if (unlikely(ret || rx_desc.sta)) {
		cn_dev_core_err(core, "sbts ioctl failed!");
		return -EFAULT;
	}
	switch (param->type) {
	case CACC_GET_ENABLE:
	case CACC_GET_BYPASS:
		param->val = priv->val;
		break;
	default:
		break;
	}

	return 0;
}

int cn_hw_cfg_handle(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	struct cn_core_set *core = sbts->core;
	struct sbts_hw_cfg_hdl param = {0};
	struct sbts_basic_info *info =
		(struct sbts_basic_info *)sbts->hw_info->data;
	int ret = 0;

	if (copy_from_user((void *)&param, (void *)args,
			sizeof(struct sbts_hw_cfg_hdl))) {
		cn_dev_core_err(core, "copy param from user failed!");
		return -EFAULT;
	}

	if (param.type >= HW_CFG_HDL_TYPE_NUM) {
		cn_dev_core_err(core, "hw cfg handle type invalid!");
		return -EINVAL;
	}

	switch (param.type) {
	case ICACHE_MISS_FETCH_INSTNUM_GET:
		param.val = info->icache_miss_fetch_instnum;
		if (copy_to_user((void *)args, (void *)&param,
				sizeof(struct sbts_hw_cfg_hdl))) {
			cn_dev_core_err(core, "copy param to user failed!");
			ret = -EFAULT;
		}
		break;
	case ICACHE_MISS_FETCH_INSTNUM_SET:
		if (sbts_hw_cfg_hdl(user, sbts, &param)) {
			cn_dev_core_err(core, "sbts hw cfg set failed!");
			ret = -EFAULT;
			break;
		}

		info->icache_miss_fetch_instnum = param.val;
		cn_dev_core_debug(core, "icache miss fetch instnum set to %lld",
			info->icache_miss_fetch_instnum);
		break;
	case TNC_WATCHDOG_TIMER_GET:
		param.val = info->tnc_watchdog_timer;
		if (copy_to_user((void *)args, (void *)&param,
				sizeof(struct sbts_hw_cfg_hdl))) {
			cn_dev_core_err(core, "copy param to user failed!");
			ret = -EFAULT;
		}
		break;
	case TNC_WATCHDOG_TIMER_SET:
		if (sbts_hw_cfg_hdl(user, sbts, &param)) {
			cn_dev_core_err(core, "sbts hw cfg set failed!");
			ret = -EFAULT;
			break;
		}

		info->tnc_watchdog_timer = param.val;
		cn_dev_core_debug(core, "tinycore watchdog timer set to %llds",
			info->tnc_watchdog_timer);
		break;
	default:
		cn_dev_core_err(core, "unsupport hw cfg type:%d", param.type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

int cn_hw_cfg_cacc_handle(struct cn_core_set *core,
		void *_param,
		cn_user user)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct sbts_hw_cfg_hdl *param = (struct sbts_hw_cfg_hdl *)_param;
	int ret = 0;

	if (!sbts)
		return -ENODEV;

	switch (param->type) {
	case CACC_SET_ENABLE:
	case CACC_SET_BYPASS:
	case CACC_GET_ENABLE:
	case CACC_GET_BYPASS:
		if (sbts_hw_cfg_hdl(user, sbts, param)) {
			cn_dev_core_err(core, "sbts hw cfg set failed!");
			ret = -EFAULT;
			break;
		}
		break;
	default:
		cn_dev_core_err(core, "unsupport hw cfg type:%d", param->type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

int cn_hw_cfg_compress_handle(struct cn_core_set *core)
{
	struct sbts_set *sbts = core->sbts_set;
	struct sbts_hw_cfg_hdl param = {0};
	cn_user user = 0;
	unsigned int compress_en;
	unsigned int compress_mode;
	unsigned int compress_high_mode;
	int ret = 0;

	if (!sbts)
		return -ENODEV;

	if (core->device_id != MLUID_590) {
		cn_dev_core_debug(core, "device id %lld not support cfg compress mode",
			core->device_id);
		return 0;
	}

	cn_mcc_get_compress_info(core, &compress_en, &compress_mode,
		 &compress_high_mode);

	param.version = SBTS_VERSION;

	if (COMPRESS_CONFIG_ENABLE == compress_en) {
		param.type = IPC_CFG_COMPRESS_ENABLE;
		param.val = 1;
	} else if (COMPRESS_CONFIG_DISABLE == compress_en) {
		param.type = IPC_CFG_COMPRESS_DISABLE;
		param.val = 0;
	} else {
		cn_dev_core_err(core, "unsupport hw cfg type:%d", param.type);
		return -EINVAL;
	}

	if (sbts_hw_cfg_hdl(user, sbts, &param)) {
		cn_dev_core_err(core, "sbts hw cfg set failed!");
		ret = -EFAULT;
	}

	return ret;
}

static inline __u64 fill_desc_host_function(__u64 version, __u64 user,
		struct sbts_queue_invoke_task *user_param,
		host_addr_t host_finish_sig_va,
		dev_addr_t dev_finish_sig_va, struct sbts_hostfn *hostfn_param,
		struct comm_task_desc *task_desc, struct queue *queue,
		struct sbts_set *sbts)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	__u32 offset;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;
	struct cd_hf_priv_data *priv = NULL;
	u32 priv_size = sizeof(struct cd_hf_priv_data);

	sbts_td_priv_size_check(priv_size);

	if (version == 0) {
		task_desc->version = version;

		/* get task desc data */
		data = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type           = INVOKE_HOST_FUNCTION;
		data->user           = cpu_to_le64(user);
		data->dev_sid        = cpu_to_le64(queue->dev_sid);
		data->param_data     = cpu_to_le64(dev_finish_sig_va);

		/* fill perf info */
		offset = sbts_task_get_perf_info(sbts, queue, HOSTFN_TS_TASK,
				user_param, data, &priv_size);
		data->priv_size      = priv_size;

		priv = (struct cd_hf_priv_data *)data->priv;
		priv->host_finish_sig_va = cpu_to_le64(host_finish_sig_va);
		priv->hqueue = cpu_to_le64(hostfn_param->hqueue);

		/* calculate payload size: version + data */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) +
			       priv_size + offset;
	} else {
		cn_dev_core_err(core, "version not match!");
	}

	return payload_size;
}

int sbts_hostfn_invoke(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret = 0;
	struct comm_task_desc task_desc = { 0 };
	struct cn_core_set *core = NULL;
	struct sbts_hostfunc_set *hostfunc_set = NULL;
	struct hostfn_task_node *task_node = NULL;
	struct sbts_hostfn *hostfn_param = &user_param->priv_data.hostfn;
	host_addr_t host_finish_sig_va = 0;
	dev_addr_t dev_finish_sig_va = 0;
	__u64 payload_size = 0;
	__u8 host_execute_sta = 0;
	struct hostfn_shm_sig sig = { 0 };

	core = (struct cn_core_set *)sbts->core;
	hostfunc_set = sbts->hostfunc_set;

	if (hostfn_param->hf_status == HOSTFN_FINISH) {
		__sync_add_and_fetch(&hostfunc_set->send_finish_req, 1);
	}

	/* send host function finish signal to dev */
	if (hostfn_param->hf_status == HOSTFN_FINISH) {
		host_execute_sta = _HF_EXECUTE_FINISH;

		task_node = sbts_hostfn_node_deregister(sbts, queue, hostfn_param->seq);
		if (!task_node) {
			cn_dev_core_debug(core, "host function task_node "
						"deregister failed");
			return -CN_HOST_FUNC_TASK_FAILED;
		}
		if (task_node->seq != hostfn_param->seq) {
			cn_dev_core_err(core,
					"task node seq %lu que sid %#lx is "
					"unexpected(%lu)",
					(unsigned long)task_node->seq,
					(unsigned long)task_node->queue->dev_sid,
					(unsigned long)hostfn_param->seq);
		}

		sbts_hostfn_fill_shm_sig(&sig, host_execute_sta,
				task_node->hk_pass_trigger_ns,
				hostfn_param->host_get_trigger_ns,
				hostfn_param->hostfn_start_ns, hostfn_param->hostfn_end_ns);
		sbts_hostfn_shm_sig_to_dev(hostfunc_set,
				task_node->host_finish_sig_va, &sig);
		cn_kfree(task_node);
		return ret;
	}

	if (hostfn_param->hf_status != HOSTFN_LAUNCH) {
		return -CN_HOST_FUNC_TASK_FAILED;
	}

	/* push host function task to dev */
	cn_dev_core_debug(core, "invoke host function queue %#016llx",
			queue->dev_sid);
	host_execute_sta = _HF_EXECUTE_INIT_STATE;

	/* add a rbtree node when first time invoking hostfn in this context */
	ret = sbts_hostfn_create_user_node_once(hostfunc_set, queue->user_id);
	if (ret == -ENOMEM) {
		cn_dev_core_err(core, "malloc hostfn_head_rbtree mem "
				      "failed");
		return ret;
	}

	/* alloc param shared memory, dev_finish_sig_va->|hostfn_shm_sig|perf| */
	ret = alloc_param_buf(sbts->queue_manager,
			ALIGN(sizeof(struct hostfn_shm_sig), 8),
			&host_finish_sig_va, &dev_finish_sig_va,
			SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "alloc param buffer failed!");
		ret = -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		return ret;
	}

	sbts_hostfn_fill_shm_sig(&sig, host_execute_sta, 0, 0, 0, 0);

	/* make sure when device receive host_execute_sta, perf info has been ready */
	memcpy_toio((void *)host_finish_sig_va, (void *)&sig,
			_HF_SHM_SIG_PERF_SIZE);
	cn_bus_mb(core->bus_set);
	memcpy_toio((void *)host_finish_sig_va + _HF_SHM_SIG_PERF_SIZE,
			(void *)&sig.host_execute_sta,
			sizeof(sig) - _HF_SHM_SIG_PERF_SIZE);

	payload_size = fill_desc_host_function(hostfn_param->version, (__u64)user,
			user_param, host_finish_sig_va, dev_finish_sig_va,
			hostfn_param, &task_desc, queue, sbts);

	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto err;
	}

	/* push task to device */
	print_time_detail("push task >>");
	ret = queue_push_task(sbts->queue_manager, queue, &task_desc,
			(__u64)user, payload_size);
	print_time_detail("push task <<");

	if (unlikely(ret)) {
		cn_dev_core_err(core,
				"queue(%px) sid %#016llx invoke host function "
				"failed!",
				queue, queue->dev_sid);
		goto err;
	}

	cn_dev_core_debug(core, "invoke host function finished!");
	return ret;

err:
	free_param_buf(core, dev_finish_sig_va);
	return ret;
}

static inline __u64
fill_desc_invoke_tcdp(__u64 version, __u64 user,
		struct sbts_queue_invoke_task *user_param,
		host_addr_t host_param_va, dev_addr_t dev_param_va,
		struct sbts_kernel *param, struct comm_task_desc *task_desc,
		struct queue *queue, struct sbts_set *sbts)
{
	__u32 offset;
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;
	u32 priv_size = param->priv_size;

	if (version == SBTS_VERSION_TCDP) {
		task_desc->version = version;

		/* get task desc data */
		data          = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type    = TCDP_TASK;
		data->user    = cpu_to_le64(user);
		data->dev_sid = cpu_to_le64(queue->dev_sid);
		data->has_kprintf = param->params & 1ULL;

		/* fill perf info */
		offset = sbts_task_get_perf_info(sbts, queue, TCDP_TS_TASK,
				user_param, data, &priv_size);

		if (unlikely(priv_size > TASK_DESC_PRIV_MAX_SIZE)) {
			cn_dev_core_err(core, "copy size %u exceed maximum", priv_size);
			return payload_size;
		}
		data->priv_size      = priv_size;

		/* copy private data */
		if (copy_from_user((void *)data->priv, (void *)param->priv,
					param->priv_size)) {
			cn_dev_core_err(core, "copy payload failed!");
			return payload_size;
		}

		/* continue to fill task desc */
		data->param_data = cpu_to_le64(dev_param_va);

		/* copy kernel param from user */
		if (cn_bus_copy_from_usr_toio((u64)host_param_va,
				    (u64)(param->params & (~1ULL)),
				    param->param_size, core->bus_set)) {
			cn_dev_core_err(core, "copy kernel parameters from user failed!");
			return payload_size;
		}

		/* calculate payload size: version + task + data + priv_size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) + offset +
				priv_size;

	} else {
		cn_dev_core_err(core, "version not match!");
		payload_size = 0;
	}

	return payload_size;
}


int sbts_invoke_tcdp(struct sbts_set *sbts, struct queue *queue,
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

	cn_dev_core_debug(core, "invoke tcdp queue(%px) dev_sid %#016llx", queue,
			queue->dev_sid);

	/* alloc param shared memory */
	param_asize = ALIGN(kernel_param->param_size, 8);
	ret = alloc_param_buf(sbts->queue_manager, param_asize,
			&host_param_va, &dev_param_va,
			SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "alloc param buffer failed!");
		return -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
	}

	payload_size = fill_desc_invoke_tcdp(kernel_param->version, (__u64)user,
			user_param, host_param_va, dev_param_va, kernel_param,
			&task_desc, queue, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto err;
	}

	/* push task to device */
	ret = queue_push_task(sbts->queue_manager, queue, &task_desc,
				(__u64)user, payload_size);

	if (unlikely(ret)) {
		cn_dev_core_err(core,
				"queue(%px) sid %#016llx invoke tcdp failed!",
				queue, queue->dev_sid);
		goto err;
	}

	cn_dev_core_debug(core, "invoke tcdp finished!");
	return ret;

err:
	free_param_buf(core, dev_param_va);
	return ret;
}

static inline __u64
fill_desc_invoke_tcdp_debug(__u64 version, __u64 user,
		host_addr_t host_param_va, dev_addr_t dev_param_va,
		struct sbts_dbg_kernel *param, struct comm_task_desc *task_desc,
		struct queue *queue, struct sbts_set *sbts)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;

	if (version == SBTS_VERSION_TCDP) {
		task_desc->version = version;

		/* get task desc data */
		data          = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type    = TCDP_DEBUG_TASK;
		data->user    = cpu_to_le64(user);
		data->dev_sid = cpu_to_le64(queue->dev_sid);
		/* this parameter is unique taskid  for gdb task */
		data->dev_shm_addr = cpu_to_le64(param->ack_buffer);
		/* params last bit description has_kprintf*/
		data->has_kprintf = cpu_to_le16(param->params & 1ULL);
		data->priv_size   = param->priv_size;

		/* fill clk id */
		sbts_task_disable_perf_info(data);

		if (unlikely(param->priv_size > TASK_DESC_PRIV_MAX_SIZE)) {
			cn_dev_core_err(core, "copy size %llu exceed maximum", param->priv_size);
			return payload_size;
		}

		/* copy private data */
		if (copy_from_user((void *)data->priv, (void *)param->priv,
					param->priv_size)) {
			cn_dev_core_err(core, "copy payload failed!");
			return payload_size;
		}

		/* continue to fill task desc */
		data->param_data = cpu_to_le64(dev_param_va);

		/* copy kernel param from user */
		if (cn_bus_copy_from_usr_toio((u64)host_param_va,
				    (u64)(param->params & (~1ULL)),
				    param->param_size, core->bus_set)) {
			cn_dev_core_err(core, "copy kernel parameters from user failed!");
			return payload_size;
		}

		/* calculate payload size: version + task + data + priv_size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) + param->priv_size;

	} else {
		cn_dev_core_err(core, "version not match!");
		payload_size = 0;
	}

	return payload_size;
}


int sbts_invoke_tcdp_debug(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret = 0;
	__u64 payload_size = 0;
	host_addr_t host_param_va = 0;
	dev_addr_t dev_param_va = 0;
	struct sbts_dbg_kernel *dbg_kernel = &user_param->priv_data.dbg_kernel;
	struct comm_task_desc task_desc;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	u64 perf_size = 0;
	u64 param_asize = 0;

	cn_dev_core_debug(core, "invoke tcdp queue(%px) dev_sid %#016llx", queue,
			queue->dev_sid);

	/* alloc param shared memory */
	param_asize = ALIGN(dbg_kernel->param_size, 8);
	ret = alloc_param_buf(sbts->queue_manager, param_asize + perf_size,
			&host_param_va, &dev_param_va,
			SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "alloc param buffer failed!");
		return -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
	}

	payload_size = fill_desc_invoke_tcdp_debug(dbg_kernel->version, (__u64)user,
			host_param_va, dev_param_va, dbg_kernel,
			&task_desc, queue, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto err;
	}

	/* push task to device */
	ret = queue_push_task(sbts->queue_manager, queue, &task_desc,
				(__u64)user, payload_size);

	if (unlikely(ret)) {
		cn_dev_core_err(core,
				"queue(%px) sid %#016llx invoke tcdp failed!",
				queue, queue->dev_sid);
		goto err;
	}

	cn_dev_core_debug(core, "invoke tcdp finished!");
	return ret;

err:
	free_param_buf(core, dev_param_va);
	return ret;
}

static inline __u64 fill_desc_invoke_jpu(__u64 version, __u64 user,
		struct sbts_queue_invoke_task *user_param,
		host_addr_t host_dataq_va, dev_addr_t dev_dataq_va,
		struct sbts_jpu_async *param, struct comm_task_desc *task_desc,
		struct queue *queue, struct sbts_set *sbts)
{
	__u32 offset;
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;
	struct td_place_jpu_task *priv = NULL;
	u32 priv_size = sizeof(struct td_place_jpu_task);

	sbts_td_priv_size_check(priv_size);

	task_desc->version = version;

	/* get task desc data */
	data = (struct task_desc_data_v1 *)task_desc->data;
	memset(data, 0, sizeof(struct task_desc_data_v1));
	data->type = JPU_TASK;
	data->user = cpu_to_le64(user);
	data->dev_sid = cpu_to_le64(queue->dev_sid);

	/* continue to fill task desc */
	data->param_data = cpu_to_le64(dev_dataq_va);

	/* copy kernel param from user */
	if (cn_bus_copy_from_usr_toio((u64)host_dataq_va,
			    (u64)(param->dataq_addr & (~1ULL)),
			    param->dataq_size, core->bus_set)) {
		cn_dev_core_err(core, "copy dataq from user failed!");
		return payload_size;
	}
	/* fill perf info */
	offset = sbts_task_get_perf_info(sbts, queue, JPU_TASK,
			user_param, data, &priv_size);
	data->priv_size      = priv_size;

	priv = (struct td_place_jpu_task *)data->priv;
	priv->type = cpu_to_le32(param->type);
	priv->batch_head = cpu_to_le32(param->is_batch_head);
	priv->dataq_addr = cpu_to_le64(dev_dataq_va);
	priv->dataq_size = cpu_to_le32(param->dataq_size);
	priv->dataq_seg_size[0] = cpu_to_le32(param->dataq_seg_size[0]);
	priv->dataq_seg_size[1] = cpu_to_le32(param->dataq_seg_size[1]);
	priv->dataq_seg_size[2] = cpu_to_le32(param->dataq_seg_size[2]);
	priv->dataq_seg_size[3] = cpu_to_le32(param->dataq_seg_size[3]);
	priv->cb_func = cpu_to_le64(param->cb_func);
	priv->buf_hdl = cpu_to_le64(param->buf_hdl);
	priv->block_id = cpu_to_le32(param->block_id);
	priv->efd_queue_sid = cpu_to_le64(param->efd_queue_sid);

	/* calculate payload size: version + task + data */
	payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) +
		       priv_size + offset;

	return payload_size;
}

int sbts_invoke_jpu(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret = 0;
	__u64 payload_size = 0;
	host_addr_t host_dataq_va = 0;
	dev_addr_t dev_dataq_va = 0;
	struct sbts_jpu_async *jpu_async = &user_param->priv_data.jpu_async;
	struct comm_task_desc task_desc;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	cn_dev_core_debug(core, "invoke tcdp queue(%p) dev_sid %#016llx", queue,
			queue->dev_sid);

	/* alloc param shared memory */
	ret = alloc_param_buf(sbts->queue_manager, jpu_async->dataq_size,
			&host_dataq_va, &dev_dataq_va,
			SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "alloc param buffer failed!");
		return -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
	}

	payload_size = fill_desc_invoke_jpu(0, (__u64)user,
			user_param,
			host_dataq_va, dev_dataq_va,
			jpu_async, &task_desc, queue, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto err;
	}

	/* push task to device */
	ret = queue_push_task(sbts->queue_manager, queue, &task_desc,
			(__u64)user, payload_size);

	if (unlikely(ret)) {
		cn_dev_core_err(core,
				"queue(%p) sid %#016llx invoke jpu failed!",
				queue, queue->dev_sid);
		goto err;
	}

	cn_dev_core_debug(core, "invoke jpu finished!");
	return ret;

err:
	free_param_buf(core, dev_dataq_va);
	return ret;
}

static inline __u64
fill_desc_invoke_topo(__u64 user, struct sbts_queue_invoke_task *user_param,
		struct comm_task_desc *task_desc,
		struct queue *queue, struct sbts_set *sbts,
		struct sbts_dev_topo_struct *dtopo,
		bool invoke_user_queue)
{
	struct task_desc_data_v1 *data = NULL;
	struct td_invoke_topo_task *priv = NULL;
	u64 perf_task = 0;
	int clock_id = 0;
	/* currently only 1 bit */
	u64 topo_extra_bit = invoke_user_queue ? 1 : 0;

	/* read perf task type and get current host time if perf enable */
	// TODO read user_param->perf_disable to check enable?
	perf_task = cn_monitor_perf_get_sbts_task_type(queue->tgid_entry, &clock_id);

	task_desc->version   = 0;
	data                 = (struct task_desc_data_v1 *)task_desc->data;
	memset(data, 0, sizeof(struct task_desc_data_v1));
	data->type           = QUEUE_TASK_TOPO_INVOKE;
	data->user           = cpu_to_le64(user);
	data->dev_sid        = cpu_to_le64(queue->dev_sid);
	data->dev_topo_cmd   = DEV_TOPO_TASK_TYPE_INVOKE;
	data->is_perf_task   = !!perf_task;
	data->clk_id         = clock_id;
	/* topo invoke is special which we can set priv_size to 0
	 * and device will assume there is struct task_desc_topo_priv behind data.
	 * device will use dev_topo_id to find device topo info.
	 * the dev_topo_id is the first param both in struct task_desc_topo_priv and struct td_invoke_topo_task
	 * after find device topo info, device will check topo_cmd type and do topo trigger,
	 * and in trigger function, it will use struct td_invoke_topo_task to get other param info.
	 * */
	data->priv_size      = 0;

	priv = (struct td_invoke_topo_task *)data->priv;
	priv->dev_topo_id       = cpu_to_le64(dtopo->dev_topo_id);
	priv->invoke_extra_info = cpu_to_le64(topo_extra_bit);
	priv->perf_task         = cpu_to_le64(perf_task);

	if (perf_task) {
		priv->host_invoke_ns      = cpu_to_le64(get_host_timestamp_by_clockid(clock_id));
		priv->correlation_id      = cpu_to_le64(user_param->correlation_id);
		priv->topo_id             = cpu_to_le64(user_param->topo_info);
	}

	return VERSION_SIZE + sizeof(struct task_desc_data_v1) + sizeof(struct td_invoke_topo_task);
}

int sbts_invoke_task_topo(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret = 0;
	struct sbts_dev_topo_struct *dtopo;
	struct comm_task_desc task_desc;
	struct sbts_topo_invoke *invoke_param = &user_param->priv_data.topo_invoke;
	__u64 payload_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	bool invoke_user_queue = (invoke_param->invoke_queue_type == SBTS_TOPO_INVOKE_IN_USER_QUEUE) ? true : false;

	dtopo = sbts_topo_get(user_param->dev_topo_id, (u64)user);
	if (!dtopo) {
		cn_dev_core_err(sbts->core, "cant find dtopo id %llu", user_param->dev_topo_id);
		return -EINVAL;
	}

	TOPO_DEBUG_LOG_CORE(core, "topod %llu invoke, user queue %u", dtopo->dev_topo_id, invoke_user_queue);
	payload_size = fill_desc_invoke_topo((__u64)user, user_param,
			&task_desc, queue, sbts, dtopo, invoke_user_queue);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto topo_put;
	}

	ret = __sbts_queue_push_lock(queue);
	if (ret) {
		goto topo_put;
	}

	/* push task to device */
	ret = queue_push_task_without_lock_and_ticket(sbts->queue_manager, queue, &task_desc,
				(__u64)user, payload_size);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "topo %llu invoke failed!", dtopo->dev_topo_id);
		goto queue_unlock;
	}

	ret = sbts_topo_invoke_ticket_update(sbts, (__u64)user, dtopo,
			invoke_user_queue ? queue : NULL);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "topo %llu invoke ticket update failed!",
				dtopo->dev_topo_id);
	}

	sbts_topo_update_push_num(dtopo, queue, DEV_TOPO_TASK_TYPE_INVOKE);

	cn_dev_core_debug(core, "invoke topo finished!");

queue_unlock:
	__sbts_queue_push_unlock(queue);
topo_put:
	sbts_topo_put(dtopo);
	return ret;
}
