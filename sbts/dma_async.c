/*
 * sbts/dma_async.c
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
#include <linux/kref.h>
#include <linux/ptrace.h>
#include <linux/ktime.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/bitops.h>
#include <linux/bitmap.h>
#include <linux/kthread.h>
#include <asm/io.h>
#include "../core/cndrv_ioctl.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_hpq.h"
#include "sbts.h"
#include "dbg.h"
#include "queue.h"
#include "dma_async.h"
#include "sbts_ioctl.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "cndrv_monitor.h"
#include "cndrv_udvm.h"
#include "cndrv_lpm.h"
#include "sbts_sram.h"
#include "cndrv_mcu.h"
#include "cndrv_pinned_mm.h"

/* debug use */
//#define SBTS_ASYNC_DMA_ALLOC_SHM

static inline __u64
fill_desc_place_dma_async_task(
		struct sbts_set *sbts, struct cn_core_set *core, __u64 version,
		__u64 user, struct sbts_queue_invoke_task *user_param,
		__u64 param_dev_va, struct comm_task_desc *task_desc,
		struct queue *queue, struct dma_async_info_s *dma_task)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct task_desc_data_v1 *data = NULL;
	struct td_place_dma_task *priv = NULL;
	__u32 offset = 0;
	u32 priv_size = sizeof(struct td_place_dma_task);

	sbts_td_priv_size_check(priv_size);

	switch (version) {
	case SBTS_VERSION:
	case SBTS_VERSION_DMA_PAGEABLE:
		task_desc->version = version;
		/* get task desc data */
		data                 = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type           = PLACE_DMA_ASYNC_TASK;
		data->is_idle        = 0;
		data->user           = cpu_to_le64(user);
		data->param_data     = cpu_to_le64(param_dev_va);
		data->dev_sid        = cpu_to_le64(queue->dev_sid);
		data->dev_eid        = 0;

		/* fill perf info */
		if (likely(user_param)) {
			offset = sbts_task_get_perf_info(sbts, queue, DMA_TS_TASK,
					user_param, data, &priv_size);
		} else {
			sbts_task_disable_perf_info(data);
		}
		data->priv_size      = priv_size;

		priv                 = (struct td_place_dma_task *)data->priv;
		priv->queue_sid      = cpu_to_le64(queue->sid);
		priv->index          = cpu_to_le64(dma_task->index);
		priv->host_vaddr     = cpu_to_le64(dma_task->host_vaddr);
		priv->device_vaddr   = cpu_to_le64(dma_task->device_vaddr);
		priv->total_size     = cpu_to_le64(dma_task->total_size);
		priv->direction      = cpu_to_le32(dma_task->direction);
		priv->trg_type       = cpu_to_le32(dma_task->reason);
		priv->desc_len       = cpu_to_le64(dma_task->desc_len);
		priv->desc_device_va = cpu_to_le64(dma_task->desc_device_va);

		/* calculate payload size: version + task + data + priv_size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) +
				priv_size + offset;
		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

void cn_sbts_dma_finish_wakeup(struct cn_core_set *core)
{
	struct sbts_set *sbts;
	struct sched_manager *sched_mgr;
	struct dma_async_manager *manager;
	struct comm_ctrl_desc tx_ctl_desc;
	u64 payload_size = 8;
#define DMA_SEND_CNT   9999999
	int cnt = DMA_SEND_CNT;

	sbts = core->sbts_set;
	if (unlikely(!sbts)) {
		cn_dev_core_err(core, "sbts set is null!");
		return;
	}
	manager = sbts->dma_async_manager;
	if (unlikely(!manager)) {
		cn_dev_core_err(core, "manager set is null!");
		return;
	}
	/* if send en is off, just flush write */
	if (!manager->msg_send_en) {
		cn_bus_mb(core->bus_set);
		return;
	}

	sched_mgr = sbts->sched_manager;
	while (cnt--) {
		/* send message to interrupt device */
		if (commu_send_message_once(sched_mgr->dma_ep,
					&tx_ctl_desc, payload_size))
			return;

		if (sbts_pause(core, 5, 20)) {
			cn_dev_core_err(core, "the reset flag has been set!");
			return;
		}

	}
	cn_dev_core_err(core, "Send data to device timeout, Please check mlu device status\n");
}

void cn_sbts_dma_finish_set_sta(
		struct cn_core_set *core,
		u64 addr_key, u32 sta,
		__le64 start_ns, __le64 end_ns)
{
	struct sbts_set *sbts;
	struct dma_async_manager *manager;
	struct dma_async_ack_desc *ack_desc;
	__le64 status;

	sbts = core->sbts_set;
	if (unlikely(!sbts)) {
		cn_dev_core_err(core, "sbts set is null!");
		return;
	}
	manager = sbts->dma_async_manager;
	if (unlikely(!manager)) {
		cn_dev_core_err(core, "manager set is null!");
		return;
	}

	ack_desc = (struct dma_async_ack_desc *)addr_key;
	status = cpu_to_le64(sta);

	memcpy_toio((void *)&ack_desc->dma_start_ns,
			(void *)&start_ns, sizeof(__le64));
	memcpy_toio((void *)&ack_desc->dma_finish_ns,
			(void *)&end_ns, sizeof(__le64));
	cn_bus_mb(core->bus_set);
	memcpy_toio((void *)&ack_desc->status,
			(void *)&status, sizeof(__le64));
}

void cn_sbts_dma_async_work(
		struct cn_core_set *core,
		void *data,
		void *rx_msg,
		int rx_size)
{
	struct comm_ctrl_desc *msg_desc = (struct comm_ctrl_desc *)rx_msg;
	struct cd_dma_free_msg *rx_data =
			(struct cd_dma_free_msg *)msg_desc->data;

	cn_bus_dma_async_message_process(core->bus_set,
				(void *)rx_data->buf);
}

int dma_async_manager_init(
		struct dma_async_manager **ppdma_mgr,
		struct cn_core_set *core)
{
	struct dma_async_manager *manager = NULL;
	struct sbts_set *sbts_set = NULL;
	struct sbts_hw_info *info = NULL;
	struct sbts_basic_info *b_info = NULL;

	cn_dev_core_debug(core, "dma async manager init");
	sbts_set = core->sbts_set;
	manager = cn_numa_aware_kzalloc(core, sizeof(struct dma_async_manager), GFP_KERNEL);
	if (!manager) {
		cn_dev_core_err(core, "malloc dma manager failed");
		return -ENOMEM;
	}

	manager->core = core;
	manager->sched_mgr = sbts_set->sched_manager;
	manager->sbts = sbts_set;

	if (sbts_d2d_async_info_init(&manager->d2d_info, core)) {
		cn_kfree(manager);
		return -ENOMEM;
	}

	manager->worker = commu_wait_work_run(core, "async_dma",
			sbts_set->sched_manager->dma_ep, manager,
			cn_sbts_dma_async_work);
	if (!manager->worker) {
		cn_dev_core_err(core, "create dma async thread fail");
		sbts_d2d_async_info_exit(&manager->d2d_info, core);
		cn_kfree(manager);
		return -EINVAL;
	}

	manager->msg_send_en = 1;
	info = sbts_set->hw_info;
	if (info) {
		b_info = (struct sbts_basic_info *)info->data;
		/* if high prio dev work always run, no need send msg to wake up */
		manager->msg_send_en = (b_info->work_policy == POLICY_DEFAULT) ? 1 : 0;
	}
	cn_dev_core_info(core, "msg send en is %d", manager->msg_send_en);

	*ppdma_mgr = manager;

	return 0;
}

void dma_async_manager_exit(struct dma_async_manager *dma_async_manager)
{
	struct sbts_set *sbts_set = NULL;

	if (!dma_async_manager) {
		cn_dev_err("dma manager is null");
		return;
	}
	sbts_set = dma_async_manager->sbts;

	commu_wait_work_stop(sbts_set->core, dma_async_manager->worker);
	dma_async_manager->worker = NULL;
	sbts_d2d_async_info_exit(&dma_async_manager->d2d_info,
			sbts_set->core);

	cn_kfree(dma_async_manager);
	sbts_set->dma_async_manager = NULL;
}

static int
dma_task_register(struct cn_core_set *core, struct sbts_dma_async *dma_async_param,
		struct sbts_dma_priv *dma_priv, struct queue *queue, __u64 user,
		struct dma_async_info_s **dma_task)
{
	int ret = 0;

	/* register pcie desc */
	switch (dma_priv->dir) {
	case DMA_H2D: {
		struct transfer_s transfer;

		/* memory info */
		transfer.ca          = dma_async_param->memcpy.src_addr;
		transfer.ia          = dma_async_param->memcpy.dst_addr;
		transfer.size        = dma_async_param->memcpy.size;
		transfer.direction   = DMA_H2D;
		transfer.bus_set     = (void *)dma_priv->memcpy.dst_bus_set;
		transfer.user        = user;
		transfer.pminfo      = (void *)dma_priv->memcpy.dst_pminfo;

		/* sbts info */
		transfer.index       = __sync_add_and_fetch(&queue->dma_ticket, 1);
		transfer.tags        = queue->sid;

		ret = cn_bus_dma_async(core->bus_set, &transfer, dma_task);
		if (ret) {
			cn_dev_core_err(core, "call bus dma async failed");
			ret = -CN_DMA_ASYNC_REG_TASK_FAILED;
		}

		break;
	}

	case DMA_D2H: {
		struct transfer_s transfer;

		/* memory info */
		transfer.ca          = dma_async_param->memcpy.dst_addr;
		transfer.ia          = dma_async_param->memcpy.src_addr;
		transfer.size        = dma_async_param->memcpy.size;
		transfer.direction   = DMA_D2H;
		transfer.bus_set     = (void *)dma_priv->memcpy.src_bus_set;
		transfer.user        = (__u64)user;
		transfer.pminfo      = (void *)dma_priv->memcpy.src_pminfo;

		/* sbts info */
		transfer.index       = __sync_add_and_fetch(&queue->dma_ticket, 1);
		transfer.tags        = queue->sid;

		ret = cn_bus_dma_async(core->bus_set, &transfer, dma_task);
		if (ret) {
			cn_dev_core_err(core, "call bus dma async failed");
			ret = -CN_DMA_ASYNC_REG_TASK_FAILED;
		}

		break;
	}

	case DMA_P2P: {
		struct peer_s peer;

		/* memory info */
		peer.src_minfo	 = (void *)dma_priv->memcpy.src_pminfo;
		peer.src_bus_set = (void *)dma_priv->memcpy.src_bus_set;
		peer.src_addr    = udvm_get_iova_from_addr(dma_async_param->memcpy.src_addr);
		peer.dst_minfo   = (void *)dma_priv->memcpy.dst_pminfo;
		peer.dst_bus_set = (void *)dma_priv->memcpy.dst_bus_set;
		peer.dst_addr    = udvm_get_iova_from_addr(dma_async_param->memcpy.dst_addr);
		peer.size        = dma_async_param->memcpy.size;
		peer.user        = user;

		/* sbts info */
		peer.index       = __sync_add_and_fetch(&queue->dma_ticket, 1);
		peer.tags        = queue->sid;

		ret = cn_bus_dma_p2p_async(core->bus_set, &peer, dma_task);
		if (ret) {
			cn_dev_core_err(core, "p2p async register failed");
			ret = -CN_DMA_ASYNC_REG_TASK_FAILED;
		}
		break;
	}

	case MEMSET_D8:
	case MEMSET_D16:
	case MEMSET_D32: {
		struct memset_s memset;

		/* memcpy info */
		memset.val         = (unsigned int)dma_async_param->memset.val;
		memset.dev_addr    = dma_async_param->memset.dev_addr;
		memset.number      = (size_t)dma_async_param->memset.number;
		memset.direction   = dma_priv->dir;
		memset.bus_set     = (void *)dma_priv->memset.bus_set;
		memset.user        = (__u64)user;
		memset.pminfo      = (void *)dma_priv->memset.pminfo;

		/* sbts info */
		memset.index       = __sync_add_and_fetch(&queue->dma_ticket, 1);
		memset.tags        = queue->sid;

		ret = cn_bus_dma_memset_async(core->bus_set, &memset, dma_task);
		if (ret) {
			cn_dev_core_err(core, "memset register async failed");
			ret = -CN_DMA_ASYNC_REG_TASK_FAILED;
		}

		break;
	}

	default:
		cn_dev_core_err(core, "[FATAL ERROR] sbts dma async invalid dir %lld",
				dma_priv->dir);
		ret = -EINVAL;
	}

	return ret;
}

static void
__sbts_address_release(struct cn_core_set *core,
		struct sbts_dma_async *dma_async_param,
		struct sbts_dma_priv *dma_priv)
{
	switch (dma_priv->dir) {
	case DMA_H2D: {
		cn_async_address_kref_put(dma_priv->memcpy.dst_pminfo,
				dma_async_param->memcpy.dst_addr, dma_async_param->memcpy.size);
		break;
	}

	case DMA_D2H: {
		cn_async_address_kref_put(dma_priv->memcpy.src_pminfo,
				dma_async_param->memcpy.src_addr, dma_async_param->memcpy.size);
		break;
	}

	case DMA_D2D:
	case DMA_P2P: {
		cn_async_address_kref_put(dma_priv->memcpy.src_pminfo,
				dma_async_param->memcpy.src_addr, dma_async_param->memcpy.size);
		cn_async_address_kref_put(dma_priv->memcpy.dst_pminfo,
				dma_async_param->memcpy.dst_addr, dma_async_param->memcpy.size);
		break;
	}

	case MEMSET_D8:
	case MEMSET_D16:
	case MEMSET_D32: {
		cn_async_address_kref_put(dma_priv->memset.pminfo,
				dma_async_param->memset.dev_addr,
				dma_async_param->memset.number * dma_async_param->memset.per_size);
		break;
	}

	default:
		cn_dev_core_err(core, "[FATAL ERROR] sbts dma async invalid dir %lld",
				dma_priv->dir);
	}
}

static inline int __async_alloc_param(struct sbts_set *sbts,
		struct dma_async_info_s *dma_task,
		dev_addr_t *param_dev_va)
{
	host_addr_t param_host_va = 0;
	u64 param_asize = 0;
	int ret = 0;

#ifndef SBTS_ASYNC_DMA_ALLOC_SHM
	if (dma_task->desc_device_va && sbts->dev_sram_en) {
		dma_task->ack_host_va = 0;
		*param_dev_va = 0;
		return 0;
	}
#endif

	param_asize = ALIGN(sizeof(struct dma_async_ack_desc), 8);
	ret = alloc_param_buf(sbts->queue_manager, param_asize,
			&param_host_va, param_dev_va,
			SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
	if (unlikely(ret)) {
		return -ENOMEM;
	}
	dma_task->ack_host_va = param_host_va;

	memset_io((void *)(param_host_va), 0, sizeof(struct dma_async_ack_desc));

	return 0;
}

static int sbts_push_dma_async_task(struct sbts_set *sbts,
		struct queue *queue, struct sbts_dma_async *dma_async_param,
		struct sbts_dma_priv *dma_priv, cn_user user,
		struct sbts_queue_invoke_task *user_param)
{
	int ret;
	__u64 payload_size = 0;
	dev_addr_t param_dev_va = 0;
	struct dma_async_info_s *dma_task = NULL;
	struct comm_task_desc task_desc;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	ret = dma_task_register(core, dma_async_param, dma_priv,
			queue, (__u64)user, &dma_task);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "register to dma err!");
		return ret;
	}

	ret = __async_alloc_param(sbts, dma_task, &param_dev_va);
	if (ret) {
		cn_dev_core_err(core, "alloc param buffer failed");
		ret = -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		goto abort_dma;
	}

	payload_size = fill_desc_place_dma_async_task(sbts, core, dma_async_param->version,
			(__u64)user, user_param, param_dev_va,
			&task_desc, queue, dma_task);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task desc failed");
		ret =  -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto err_destroy;
	}

	/* push task to arm */
	ret = queue_push_task(sbts->queue_manager, queue,
			&task_desc, (__u64)user, payload_size);
	if (ret) {
		cn_dev_core_err(core, "queue(%#llx) sid %#016llx", (u64)queue, queue->sid);
		cn_dev_core_err(core, "push dma async task fail tags:%llu index:%llu",
					dma_task->tags, dma_task->index);
		goto err_destroy;
	}

	return ret;

err_destroy:
	if (param_dev_va)
		free_param_buf(core, param_dev_va);
abort_dma:
	cn_bus_dma_abort(core->bus_set, queue->sid, dma_task->index);
	return ret;
}

#define SBTS_DMA_ASYNC_TYPE_NORMAL  0
#define SBTS_DMA_ASYNC_TYPE_SYNC    1
/* check device & memory type and version
 *
 * */
static int __sbts_async_copy_type_check(struct cn_core_set *core,
		struct sbts_dma_async *dma_async_param,
		struct sbts_dma_priv *dma_priv)
{
	u64 host_addr = 0;

	if (dma_async_param->version < SBTS_VERSION_DMA_PAGEABLE)
		return SBTS_DMA_ASYNC_TYPE_NORMAL;

	switch (dma_priv->dir) {
	case DMA_H2D:
		host_addr = dma_async_param->memcpy.src_addr;
		break;
	case DMA_D2H:
		host_addr = dma_async_param->memcpy.dst_addr;
		break;
	default:
		return SBTS_DMA_ASYNC_TYPE_NORMAL;
	}
	if (cn_pinned_mem_check(current, host_addr,
				dma_async_param->memcpy.size)) {
		return SBTS_DMA_ASYNC_TYPE_NORMAL;
	}

	return SBTS_DMA_ASYNC_TYPE_SYNC;
}

/* desc data has already set by pre_check */
static int __sbts_dma_sync_task_info_dev(struct sbts_set *sbts,
		struct queue *queue, u64 user,
		struct sbts_queue_invoke_task *user_param,
		struct comm_task_desc *task_desc,
		u32 desc_size, u64 start, u64 finish, u64 total_size, u32 direction)
{
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	int ret = 0;
	struct task_desc_data_v1 *data = (struct task_desc_data_v1 *)task_desc->data;
	struct td_place_dma_task *priv = NULL;
	__u64 payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) +
				 + desc_size;

	priv                 = (struct td_place_dma_task *)data->priv;
	priv->queue_sid      = cpu_to_le64(queue->sid);
	priv->index          = cpu_to_le64(__sync_add_and_fetch(&queue->dma_ticket, 1));
	priv->host_vaddr     = cpu_to_le64(start);
	priv->device_vaddr   = cpu_to_le64(finish);
	priv->total_size     = cpu_to_le64(total_size);
	priv->direction      = cpu_to_le32(direction);
	priv->trg_type       = cpu_to_le32(ASYNC_REASON_SYNC_PAGEABLE_MEM);
	priv->desc_len       = 0;
	priv->desc_device_va = 0;

	ret = queue_push_task_without_lock(sbts->queue_manager, queue,
			task_desc, user, payload_size);
	if (ret) {
		cn_dev_core_err(core, "queue sid %#016llx push failed", queue->sid);
	}

	return ret;
}

/* check perf is enable and set task desc data */
static inline bool __sbts_dma_sync_pre_check(struct sbts_set *sbts,
		struct queue *queue, u64 user,
		struct comm_task_desc *task_desc,
		struct sbts_queue_invoke_task *user_param,
		u32 *desc_size, u32 *clock_id)
{
	struct task_desc_data_v1 *data = (struct task_desc_data_v1 *)task_desc->data;
	u32 priv_size = sizeof(struct td_place_dma_task);
	u32 perf_offset = 0;

	memset(data, 0, sizeof(struct task_desc_data_v1));
	perf_offset = sbts_task_get_perf_info(sbts, queue, DMA_TS_TASK,
			user_param, data, &priv_size);
	/* save clock id for time record */
	*clock_id = data->clk_id;

	*desc_size = priv_size + perf_offset;
	/* perf is disabled */
	if (false == data->is_perf_task) {
		return false;
	}

	task_desc->version = SBTS_VERSION;
	data->type           = PLACE_DMA_ASYNC_TASK;
	data->is_idle        = 0;
	data->user           = cpu_to_le64(user);
	data->param_data     = 0;
	data->dev_sid        = cpu_to_le64(queue->dev_sid);
	data->dev_eid        = 0;
	data->dev_shm_addr   = 0;
	data->priv_size      = priv_size;

	return true;
}

static int sbts_dma_async_task_sync(struct sbts_set *sbts,
		struct queue *queue, struct sbts_dma_async *dma_async_param,
		struct sbts_dma_priv *dma_priv, cn_user user,
		struct sbts_queue_invoke_task *user_param)
{
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct cn_bus_set *cpy_bus;
	struct transfer_s t;
	int ret = 0;
	bool perf_en = false;
	u32 clock_id = 0;
	/* save hw time */
	u64 start_ns, finish_ns;
	u64 dir, cpy_size;
	struct comm_task_desc task_desc;
	/* save task priv_size and perf offset size in task desc */
	u32 desc_size = 0;

	ret = __sbts_queue_push_lock(queue);
	if (ret) {
		cn_dev_core_err(core, "unavailable queue lock");
		return ret;
	}

	/* check perf is enable init task_desc and save clock id */
	perf_en = __sbts_dma_sync_pre_check(sbts, queue,
			(u64)user, &task_desc, user_param, &desc_size, &clock_id);

	/* user and param could be NULL */
	ret = sbts_queue_sync(sbts, queue, 0, NULL);
	if (ret)
		goto out;

	cpy_size = dma_async_param->memcpy.size;
	dir = dma_priv->dir;
	if (dir == DMA_H2D) {
		cpy_bus = (struct cn_bus_set *)(dma_priv->memcpy.dst_bus_set);

		TRANSFER_INIT(t, dma_async_param->memcpy.src_addr,
				dma_async_param->memcpy.dst_addr,
				cpy_size, dir);
	} else {
		/* DMA_D2H */
		cpy_bus = (struct cn_bus_set *)(dma_priv->memcpy.src_bus_set);

		TRANSFER_INIT(t, dma_async_param->memcpy.dst_addr,
				dma_async_param->memcpy.src_addr,
				cpy_size, dir);
	}

	start_ns = get_host_timestamp_by_clockid(clock_id);
	ret = cn_bus_dma(cpy_bus, &t);
	finish_ns = get_host_timestamp_by_clockid(clock_id);
	if (ret) {
		cn_dev_core_err(core, "copy fail %d h[%#lx] d[%#llx] size[%#llx] dir[%llu]",
				ret, t.ca, t.ia, cpy_size, dir);
		goto out;
	}

	/* perf disabled save time on host only */
	if (false == perf_en) {
		sbts_queue_add_host_time(queue, (s64)(finish_ns - start_ns));
		ret = 0;
		goto out;
	}
	/* send time with task to dev for perf result */
	ret = __sbts_dma_sync_task_info_dev(sbts, queue, (u64)user, user_param, &task_desc, desc_size,
			start_ns, finish_ns, cpy_size, dir);

out:
	__sbts_queue_push_unlock(queue);
	return ret;
}

int sbts_dma_async_invoke(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret;
	struct sbts_dma_async *dma_async_param = &user_param->priv_data.dma_async;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct sbts_dma_priv dma_priv = {0};
	int cpy_type;

	/* param check */
	ret = cn_async_address_kref_get(dma_async_param, &dma_priv);
	if (ret) {
		cn_dev_core_err(core, "sbts dma async param check failed!");
		return -ENXIO;
	}

	if (dma_priv.dir == DMA_D2D) {
		if ((dma_priv.memcpy.src_bus_set != (__u64)core->bus_set) ||
				(dma_priv.memcpy.dst_bus_set != (__u64)core->bus_set)) {
			ret = -CN_DMA_D2D_INVALID_CONTEXT;
			goto addr_release;
		}

		ret = sbts_d2d_async_invoke(sbts,
				queue, (__u64)user, user_param,
				dma_async_param, &dma_priv);
		if (ret) {
			cn_dev_core_err(core, "sbts d2d async invoke failed! %d", ret);
			goto addr_release;
		}
		return 0;
	}

	cpy_type = __sbts_async_copy_type_check(core, dma_async_param, &dma_priv);

	if (cpy_type == SBTS_DMA_ASYNC_TYPE_NORMAL) {
		ret = sbts_push_dma_async_task(sbts, queue, dma_async_param,
				&dma_priv, user, user_param);
		if (ret)
			goto addr_release;
		return 0;
	} else {
		ret = sbts_dma_async_task_sync(sbts, queue, dma_async_param, &dma_priv,
				user, user_param);
	}

addr_release:
	__sbts_address_release(core, dma_async_param, &dma_priv);
	return ret;
}
