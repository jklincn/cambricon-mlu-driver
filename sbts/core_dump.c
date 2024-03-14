/*
 * sbts/core_dump.c
 *
 * NOTICE:
 * Copyright (C) 2021 Cambricon, Inc. All rights reserved.
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
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/ptrace.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/bitops.h>
#include <linux/kthread.h>
#include <linux/bitmap.h>
#include <asm/io.h>

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 11, 0))
#include <linux/sched.h>
#else
#include <linux/sched/mm.h>
#endif

#include "../core/cndrv_ioctl.h"
#include "cndrv_core.h"
#include "cndrv_os_compat.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_hpq.h"
#include "sbts.h"
#include "dbg.h"
#include "queue.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "unotify.h"
#include "core_dump.h"

/* core dump comm func */
static inline int
__core_dump_send(struct core_dump_manager *dump_mgr, struct comm_ctrl_desc *tx_desc)
{
	struct sched_manager *sched_mgr;
	struct cn_core_set *core;
	struct sbts_set *sbts;
	u64 seq = 0;
	u64 payload_size = sizeof(struct comm_ctrl_desc);
#define COREDUMP_TIMEOUT (10000000)
	int loop_count = COREDUMP_TIMEOUT;

	core = dump_mgr->core;
	sbts = (struct sbts_set *)core->sbts_set;
	sched_mgr = sbts->sched_manager;

	/* send message to interrupt device */
	do {
		seq = commu_send_message_once(sched_mgr->core_dump_ep, tx_desc, payload_size);
		if (likely(seq)) {
			return 0;
		}

		if (sbts_pause(core, 5, 20)) {
			cn_dev_core_err(core, "the reset flag has been set!");
			return -EFAULT;
		}
	} while (loop_count--);

	return -ETIMEDOUT;
}

/* the core dump func of mlu */
static inline void
__downward_dump_info_init(struct core_dump_info *dump_info,
		struct sbts_create_queue *pparam)
{
	dump_info->enable = DUMP_DEFAULT;
	dump_info->version = DUMP_VERSION_V5;
	dump_info->downward_flag = 1;
	dump_info->dumped_done = 0;
	dump_info->dump_record = 0;
	dump_info->dump_uvaddr = pparam->dump_uvaddr;
	dump_info->header_size = DUMP_HEADER_SIZE_V4;
	dump_info->reserved_offset = dump_info->header_size;

	/* get current and current->mm */
	dump_info->task = current;
	dump_info->mm = current->mm;
	atomic_inc(&dump_info->mm->mm_count);
	get_task_struct(dump_info->task);
}

static struct core_dump_info *
mlu_dump_info_init(struct core_dump_manager *dump_mgr,
		struct sbts_create_queue *pparam)
{
	struct core_dump_info *dump_info = NULL;
	__u64 version = GET_HOST_VERSION(pparam->version);

	dump_info = cn_kzalloc(sizeof(struct core_dump_info), GFP_KERNEL);
	if (!dump_info) {
		return NULL;
	}

	switch (version) {
	case HOST_VERSION(4):
		__downward_dump_info_init(dump_info, pparam);
		break;

	case HOST_VERSION(5):
		dump_info->enable = DUMP_DEFAULT;
		dump_info->dumped_done = 0;
		dump_info->downward_flag = 0;
		dump_info->version = 0;
		atomic_set(&dump_info->wait_ack, 0);
		break;

	case HOST_VERSION(6): {
		struct drv_dump_set *drv_set = (struct drv_dump_set *)&pparam->dump_uvaddr;

		dump_info->dumped_done = 0;
		dump_info->downward_flag = 0;
		dump_info->enable = drv_set->core_dump_level;
		dump_info->version = drv_set->layout_version;
		atomic_set(&dump_info->wait_ack, 0);
		break;
	}

	default:
		cn_kfree(dump_info);
		cn_dev_err("unsupport HOST VERSION %lld for core dump!", version);
		return NULL;
	}

	return dump_info;
}

static void
mlu_dump_info_exit(struct core_dump_manager *dump_mgr,
		struct core_dump_info *dump_info)
{
	struct cn_core_set *core = dump_mgr->core;

	if (!dump_info)
		return;

	if (dump_info->downward_flag) {
		if (dump_info->enable) {
			put_task_struct(dump_info->task);
			mmdrop(dump_info->mm);
		}
		cn_kfree(dump_info);
		return;
	}

	if (atomic_read(&dump_info->wait_ack)) {
		int ret;
		struct comm_ctrl_desc tx_desc;

		cn_dev_core_err(core, "there %d dump msgs not ack yet!",
				atomic_read(&dump_info->wait_ack));
		tx_desc.version		= 0;
		tx_desc.sta			= DUMP_COMM_ERROR;
		memcpy(tx_desc.data, &dump_info->last_msg,
				sizeof(struct mlu_core_dump_msg));
		ret = __core_dump_send(dump_mgr, &tx_desc);
		if (ret) {
			cn_dev_core_err(core, "core dump send msg failed!");
		}
	}

	cn_kfree(dump_info);
}

static int
__downward_do_core_dump(struct core_dump_manager *dump_mgr,
		struct core_dump_info *dump_info, struct mlu_core_dump_msg *priv)
{
	u64 block_addr;
	u64 block_size;
	u64 uvaddr = 0;
	struct transfer_s transfer;
	struct cn_core_set *core = dump_mgr->core;
	struct sbts_basic_info *info =
			(struct sbts_basic_info *)dump_mgr->sbts->hw_info->data;

	switch (priv->block_type) {
	case IPU_BLK:
	case MEMCORE_BLK:
	case TNC_BLK:
		uvaddr = dump_info->dump_uvaddr + dump_info->reserved_offset;
		set_bit(priv->block_info, (unsigned long *)dump_info->dumped_bp);
		break;
	case C2C_BLK:
		dump_info->dumped_bp[2] = 1ULL;
		uvaddr = dump_info->dump_uvaddr + dump_info->header_size +
			(info->ipu_core_num_per_clu * info->ipu_core_dump_size +
			info->mem_core_num_per_clu * info->mem_core_dump_size) *
			info->cluster_num + info->tiny_core_num *
			info->tiny_core_dump_size;
		break;
	default:
		cn_dev_core_err(core, "unexpected block type %lld", priv->block_type);
		return 0;
	}

	dump_info->dumped_bp[1] = (info->tiny_core_num == 2) ? (0ULL) : (1ULL);
	/* this bit means core dump file include 4M shared mem */
	dump_info->dumped_bp[1] |= 2ULL;

	block_addr = priv->block_addr + sizeof(struct block_hdr);
	block_size = priv->block_size - sizeof(struct block_hdr);
	transfer.ca = uvaddr;
	transfer.ia = block_addr;
	transfer.size = block_size;
	transfer.direction = DMA_D2H;
	if (cn_bus_dma_remote(dump_mgr->core->bus_set, &transfer,
				dump_info->task, dump_info->mm)) {
		cn_dev_core_err(core, "remote dma failed!");
		return -EFAULT;
	}
	dump_info->reserved_offset += block_size;

	return 0;
}

static void
mlu_core_dump_cbk(struct core_dump_manager *dump_mgr,
		struct comm_ctrl_desc *rx_info)
{
	struct queue *queue;
	struct core_dump_info *dump_info;
	struct cn_core_set *core = dump_mgr->core;
	struct mlu_core_dump_msg *priv;
	struct sbts_set *sbts = core->sbts_set;

	priv = (struct mlu_core_dump_msg *)rx_info->data;

	if (rx_info->sta != DUMP_COMM_INIT) {
		cn_dev_core_err(core, "Recv dump info with invalid status %llu",
					rx_info->sta);
		rx_info->sta = DUMP_COMM_ERROR;
		goto dump_finish;
	}

	/* __queue_get called in this func if queue valid */
	queue = queue_get(sbts->queue_manager, priv->queue_dsid, ANNOY_USER, 0);
	if (!queue) {
		cn_dev_core_err(core, "could not find queue with dsid %llu",
						priv->queue_dsid);
		rx_info->sta = DUMP_COMM_ERROR;
		goto dump_finish;
	}
	dump_info = queue->dump_info;

	if (__sync_bool_compare_and_swap(&queue->sta, QUEUE_NORMAL,
				QUEUE_EXCEPTION)) {
		cn_dev_core_err(core, "queue(%px) dsid %llu start dump %lld!",
				queue, queue->dev_sid, priv->dump_id);
	}

	if (dump_info->downward_flag) {
		if (__downward_do_core_dump(dump_mgr, dump_info, priv)) {
			rx_info->sta = DUMP_COMM_ERROR;
		} else {
			rx_info->sta = DUMP_COMM_FINISH;
		}
		goto dump_queue_put;
	}

	if (sbts_unotify_send(sbts, queue, EFD_CORE_DUMP_DMA, (u64 *)priv,
				sizeof(struct mlu_core_dump_msg))) {
		cn_dev_core_err(core, "send queue(%#llx) msg to usr failed!", (u64)queue);
		rx_info->sta = DUMP_COMM_ERROR;
		goto dump_queue_put;
	}

	atomic_inc(&dump_info->wait_ack);
	/* save the latest dump msg */
	memcpy(&dump_info->last_msg, priv, sizeof(struct mlu_core_dump_msg));

	queue_put(sbts->queue_manager, queue);
	/* return and wait driver-api call cn_core_dump_ack send msg */
	return;

dump_queue_put:
	queue_put(sbts->queue_manager, queue);
dump_finish:
	__core_dump_send(dump_mgr, rx_info);
}

static int
mlu_dump_finish_cbk(struct core_dump_manager *dump_mgr,
		struct comm_dbg_desc *rx_desc)
{
	struct sbts_set *sbts = dump_mgr->sbts;
	struct cn_core_set *core = sbts->core;
	struct queue_manager *queue_mgr = sbts->queue_manager;
	struct dbg_queue_msg *priv =
			(struct dbg_queue_msg *)rx_desc->priv;
	struct queue *queue;
	struct efd_core_dump_msg dump_msg;
	struct core_dump_info *dump_info;
	struct hpq_task_ack_desc ack_desc;

	if (!queue_mgr) {
		cn_dev_core_err(core, "queue mgr is null");
		return -EINVAL;
	}

	queue = queue_get(queue_mgr, priv->queue_dsid, ANNOY_USER, 0);
	if (!queue) {
		cn_dev_core_err_limit(core, "could not find queue with dsid %llu",
						priv->queue_dsid);
		return -CN_QUEUE_ERROR_QUEUE_INVALID;
	}
	queue_get_ack_sta(queue, &ack_desc);
	cn_dev_core_err(core, "queue(%llx) dsid %llu core dump finish!",
			(u64)queue, priv->queue_dsid);

	dump_info = queue->dump_info;

	/* only queue dump finish use this function */
	dump_info->dumped_done = 1;

	/* only dump version used */
	dump_msg.dump_version = dump_info->version;
	memcpy((void *)dump_msg.dumped_bp, (void *)dump_info->dumped_bp,
			sizeof(u64) * 3);

	sbts_unotify_send(sbts, queue,
			CORE_DUMP_COMPLETE,
			(u64 *)&dump_msg, sizeof(struct efd_core_dump_msg));
	queue_put(queue_mgr, queue);

	return 0;
}

static int mlu_copy_dump_header(struct core_dump_info *dump_info)
{
	char *header = cn_kzalloc(dump_info->header_size, GFP_KERNEL);

	if (!header) {
		return -ENOMEM;
	}

	snprintf(header, dump_info->header_size, DUMP_HEARD_FMT_V5,
			dump_info->version, dump_info->dumped_bp[0],
			dump_info->dumped_bp[1], dump_info->dumped_bp[2]);

	if (copy_to_user((void *)dump_info->dump_uvaddr, header,
				dump_info->header_size)) {
		cn_kfree(header);
		return -EFAULT;
	}

	cn_kfree(header);
	return 0;
}

/* the core dump func of former */
static int
former_do_core_dump(struct core_dump_manager *dump_mgr,
		struct core_dump_info *dump_info, u64 *core_dump_msg)
{
	int i = 0;
	int ret = 0;
	u64 cbp = 0;
	u64 uvaddr = 0;
	u64 ncs_uvaddr = 0;
	u64 dump_size;
	u64 dump_addr;
	u64 ncs_core_dump_offset;
	struct transfer_s transfer;
	struct cn_core_set *core = dump_mgr->core;
	struct sbts_basic_info *info =
			(struct sbts_basic_info *)dump_mgr->sbts->hw_info->data;
	struct sbts_core_info *core_info =
			(struct sbts_core_info *)info->core_info;

	/* core dump is disable or already done */
	if (!dump_info->enable || dump_info->dump_record) {
		return 0;
	}

	dump_info->dump_record = 1;

	if (!(core_dump_msg[0] | core_dump_msg[1])) {
		cn_dev_core_err(core, "core dump msg is invalid!");
		return -EINVAL;
	}

	dump_info->dumped_bp[0] = core_dump_msg[0] & dump_info->dumped_bp_mask[0];
	dump_info->dumped_bp[1] = core_dump_msg[1] & dump_info->dumped_bp_mask[1];
	dump_info->dumped_bp[2] = ((core_dump_msg[1] & 0x30000) >> 16) &
		dump_info->dumped_bp_mask[1];

	/* get the uvaddr */
	uvaddr = dump_info->dump_uvaddr + dump_info->header_size;

	ncs_core_dump_offset = (info->ipu_core_num_per_clu * info->ipu_core_dump_size +
		info->mem_core_num_per_clu * info->mem_core_dump_size) * info->cluster_num +
		info->tiny_core_num * info->tiny_core_dump_size;
	ncs_uvaddr = uvaddr + ncs_core_dump_offset;

	/* DMA ENGINE NOT SUPPORT DEV SG_NUM > 1 */
	cn_dev_core_err(core, "core bp: [0]%#llx, [1]%#llx, [2]%#llx",
		dump_info->dumped_bp[0], dump_info->dumped_bp[1], dump_info->dumped_bp[2]);

	/* ipu + memcore + tinycore */
	if (dump_info->dumped_bp[0] || dump_info->dumped_bp[1]) {
		for (i = 0; i < info->core_max_num; i++) {
			/*	reserved_offset fill when dump_info init
			 *	core dump data filled by arm:
			 *	----------
			 *	|  data  | -> dump_size - reserved_buf_size
			 *	---------- -> dump_addr
			 *	|  data  | -> reserved_offset (invalid if dump version == 2)
			 *	---------- -> reserver_buf_addr
			 */
			dump_size = core_info[i].dump_size - dump_info->reserved_offset;
			dump_addr = core_info[i].reserved_buf_addr + dump_info->reserved_offset;

			cbp = (i < 64) ? dump_info->dumped_bp[0] : dump_info->dumped_bp[1];
			if (cbp & (1ULL << (i % 64))) {
				cn_dev_core_err(core, "dump_size:0x%llx, dump_addr:0x%llx",
						dump_size, dump_addr);
				transfer.ca = uvaddr;
				transfer.ia = dump_addr;
				transfer.size = dump_size;
				transfer.direction = DMA_D2H;

				ret = cn_bus_dma_remote(dump_mgr->core->bus_set,
						&transfer, dump_info->task, dump_info->mm);
				if (ret) {
					cn_dev_core_err(core, "core dump dma err");
					break;
				}

				uvaddr += dump_size;
			}
		}
	}

	if (dump_info->dumped_bp[2]) {
		dump_size = info->ncs_core_dump_size;
		dump_addr = info->ncs_core_dump_addr;
		cn_dev_core_err(core, "ncs dump_size:0x%llx, ncs dump_addr:0x%llx",
				dump_size, dump_addr);
		transfer.ca = ncs_uvaddr;
		transfer.ia = dump_addr;
		transfer.size = dump_size;
		transfer.direction = DMA_D2H;
		ret = cn_bus_dma_remote(dump_mgr->core->bus_set,
				&transfer, dump_info->task, dump_info->mm);
		if (ret) {
			cn_dev_core_err(core, "ncs core dump dma err");
		}
	}

	return ret;
}

struct core_dump_info *
former_dump_info_init(struct core_dump_manager *dump_mgr,
		struct sbts_create_queue *pparam)
{
	struct core_dump_info *dump_info = NULL;
	__u64 version = GET_HOST_VERSION(pparam->version);
	struct sbts_basic_info *info =
			(struct sbts_basic_info *)dump_mgr->sbts->hw_info->data;

	dump_info = cn_kzalloc(sizeof(struct core_dump_info), GFP_KERNEL);
	if (!dump_info) {
		return NULL;
	}

	if (!pparam->dump_uvaddr) {
		dump_info->enable = 0U;
		return dump_info;
	}

	dump_info->enable = 1U;
	dump_info->dumped_done = 0;
	dump_info->dump_uvaddr = pparam->dump_uvaddr;

	/* get current and current->mm */
	dump_info->task = current;
	dump_info->mm = current->mm;
	atomic_inc(&dump_info->mm->mm_count);
	get_task_struct(dump_info->task);

	/* init the mask of dumped bp */
	dump_info->dumped_bp_mask[0] = ~(0ULL);
	dump_info->dumped_bp_mask[1] = 0xffffULL;

	/* set queue dump version */
	if (version < HOST_VERSION(1)) {
		dump_info->version = DUMP_VERSION_V2;
		dump_info->reserved_offset = info->reserved_buf_size;
		dump_info->header_size = DUMP_HEADER_SIZE;
		dump_info->dumped_bp_mask[2] = 0;
	} else if ((version >= HOST_VERSION(1)) && (version < HOST_VERSION(2))) {
		dump_info->version = DUMP_VERSION_V3;
		dump_info->reserved_offset = 0ULL;
		dump_info->header_size = DUMP_HEADER_SIZE;
		dump_info->dumped_bp_mask[2] = 0;
	} else if ((version >= HOST_VERSION(2)) && (version < HOST_VERSION(4))) {
		dump_info->version = DUMP_VERSION_V4;
		dump_info->reserved_offset = 0ULL;
		dump_info->header_size = DUMP_HEADER_SIZE_V4;
		dump_info->dumped_bp_mask[2] = 0;
	} else if (version >= HOST_VERSION(4)) {
		dump_info->version = DUMP_VERSION_V5;
		dump_info->reserved_offset = 0ULL;
		dump_info->header_size = DUMP_HEADER_SIZE_V4;
		/* dumped_bp[2] is invalid before version 5 */
		dump_info->dumped_bp_mask[2] = 0x3;
	}

	return dump_info;
}

static void
former_dump_info_exit(struct core_dump_manager *dump_mgr,
		struct core_dump_info *dump_info)
{
	if (dump_info) {
		if (dump_info->enable) {
			put_task_struct(dump_info->task);
			mmdrop(dump_info->mm);
		}
		cn_kfree(dump_info);
	}
}

static void
former_core_dump_cbk(struct core_dump_manager *dump_mgr,
		struct comm_ctrl_desc *rx_info)
{
	struct queue *queue;
	struct core_dump_info *dump_info;
	struct cn_core_set *core = dump_mgr->core;
	struct former_core_dump_msg *priv;
	struct sbts_set *sbts = core->sbts_set;

	priv = (struct former_core_dump_msg *)rx_info->data;

	if (rx_info->sta != DUMP_COMM_INIT) {
		cn_dev_core_err(core, "Recv dump info with invalid status %llu",
					rx_info->sta);
		rx_info->sta = DUMP_COMM_ERROR;
		goto dump_finish;
	}

	queue = queue_get(sbts->queue_manager, priv->queue_dsid, ANNOY_USER, 0);
	if (!queue) {
		cn_dev_core_err(core, "could not find queue with dsid %llu",
						priv->queue_dsid);
		rx_info->sta = DUMP_COMM_ERROR;
		goto dump_finish;
	}
	dump_info = queue->dump_info;

	/* set status ready to send back */
	rx_info->sta = DUMP_COMM_FINISH;

	if (__sync_bool_compare_and_swap(&queue->sta, QUEUE_NORMAL, QUEUE_EXCEPTION))
		cn_dev_core_err(core, "set queue(%#llx) dsid %llu excep",
				(u64)queue, queue->dev_sid);

	if (former_do_core_dump(dump_mgr, dump_info, priv->msg)) {
		cn_dev_core_err(core, "queue(%#llx) sid%llu dsid%llu dump error",
				(u64)queue, queue->sid, queue->dev_sid);
	}

	queue_put(sbts->queue_manager, queue);

dump_finish:
	__core_dump_send(dump_mgr, rx_info);
}


static int
former_dump_finish_cbk(struct core_dump_manager *dump_mgr,
			struct comm_dbg_desc *rx_desc)
{
	struct sbts_set *sbts = dump_mgr->sbts;
	struct cn_core_set *core = dump_mgr->core;
	struct queue_manager *queue_mgr = sbts->queue_manager;
	struct dbg_queue_msg *priv = (struct dbg_queue_msg *)rx_desc->priv;
	struct queue *queue;
	struct efd_core_dump_msg dump_msg;
	struct core_dump_info *dump_info;
	u32 cpy_size;

	if (!queue_mgr) {
		cn_dev_core_err(core, "queue mgr is null");
		return -EINVAL;
	}

	queue = queue_get(queue_mgr, priv->queue_dsid, ANNOY_USER, 0);
	if (!queue) {
		cn_dev_core_err(core, "could not find queue with dsid %llu",
				priv->queue_dsid);
		return -CN_QUEUE_ERROR_QUEUE_INVALID;
	}
	dump_info = queue->dump_info;

	/* only queue dump finish use this function */
	dump_info->dumped_done = 1;

	if (!dump_info->dumped_bp[0] &&
			!dump_info->dumped_bp[1] &&
			!dump_info->dumped_bp[2]) {
		queue_put(queue_mgr, queue);
		return 0;
	}

	cpy_size = sizeof(struct efd_core_dump_msg);
	dump_msg.dump_version = DUMP_VERSION_V5;
	memcpy((void *)dump_msg.dumped_bp, (void *)dump_info->dumped_bp,
			sizeof(u64) * 3);
	sbts_unotify_send(sbts, queue,
			CORE_DUMP_COMPLETE,
			(u64 *)&dump_msg, cpy_size);
	cn_dev_core_info(core, "queue dsid %llu unotify finish",
			priv->queue_dsid);

	queue_put(queue_mgr, queue);

	return 0;
}

static int former_copy_dump_header(struct core_dump_info *dump_info)
{
	char *header = cn_kzalloc(dump_info->header_size, GFP_KERNEL);

	if (!header) {
		return -ENOMEM;
	}

	if (dump_info->version == DUMP_VERSION_V5) {
		snprintf(header, dump_info->header_size, DUMP_HEARD_FMT_V5,
				dump_info->version, dump_info->dumped_bp[0],
				dump_info->dumped_bp[1], dump_info->dumped_bp[2]);

		if (copy_to_user((void *)dump_info->dump_uvaddr, header,
					dump_info->header_size)) {
			cn_kfree(header);
			return -EFAULT;
		}
	} else if (dump_info->version == DUMP_VERSION_V4) {
		snprintf(header, dump_info->header_size, DUMP_HEARD_FMT_V4,
				dump_info->version, dump_info->dumped_bp[0],
				dump_info->dumped_bp[1]);

		if (copy_to_user((void *)dump_info->dump_uvaddr, header,
					dump_info->header_size)) {
			cn_kfree(header);
			return -EFAULT;
		}
	} else {
		snprintf(header, dump_info->header_size, DUMP_HEARD_FMT,
				dump_info->version, dump_info->dumped_bp[0]);

		if (copy_to_user((void *)dump_info->dump_uvaddr, header,
					dump_info->header_size)) {
			cn_kfree(header);
			return -EFAULT;
		}
	}

	cn_kfree(header);
	return 0;
}

/* core dump ioctl func */
static int
__wait_queue_dump_finish(struct cn_core_set *core, struct queue *queue,
		struct core_dump_info *dump_info)
{
	int ret;
	int cnt = CORE_DUMP_TIMEOUT;
	struct hpq_task_ack_desc ack_desc = {0};

	ret = queue_get_ack_sta(queue, &ack_desc);
	if (queue->sta != QUEUE_EXCEPTION
			|| !dump_info->enable
			|| ret) {
		cn_dev_core_err(core, "queue(%px) sid %llu", queue, queue->dev_sid);
		cn_dev_core_err(core, "queue status %d ret:%d", queue->sta, ret);
		cn_dev_core_err(core, "dump enable 0x%x", dump_info->enable);
		return -EINVAL;
	}

	cn_dev_core_debug(core, "queue(%px) sid %llu", queue, queue->dev_sid);
	cn_dev_core_debug(core, "start wait core dump!");
	do {
		if (dump_info->dumped_done) {
			cn_dev_core_err(core, "queue(%px) sid %llu core dump done",
					queue, queue->dev_sid);
			return 0;
		}

		ret = sbts_pause_stopable(core, 20000, 20000);
		if (ret) {
			if (ret == -ERESTARTNOINTR) {
				cn_dev_core_err(core, "queue(%px) sid %llu, wait dump stop by pending signal(ret %d)",
					queue, queue->dev_sid, ret);
			} else {
				cn_dev_core_err(core, "queue(%px) sid %llu, wait dump killed by fatal signal",
					queue, queue->dev_sid);
			}
			return ret;
		}
	} while (--cnt);

	return -ETIMEDOUT;
}

int
cn_core_dump(struct sbts_set *sbts, void *arg, cn_user user)
{
	int ret = 0;
	struct queue *queue = NULL;
	struct sbts_queue_dump param;
	struct cn_core_set *core = sbts->core;
	struct core_dump_info *dump_info;

	if (copy_from_user((void *)&param, (void *)arg, sizeof(struct sbts_queue_dump))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	queue = queue_get(sbts->queue_manager, param.hqueue, user, 0);
	if (!queue) {
		cn_dev_core_err(core, "queue_disd(%#llx) is invalid", param.hqueue);
		return -CN_QUEUE_ERROR_QUEUE_INVALID;
	}
	dump_info = queue->dump_info;

	ret = __wait_queue_dump_finish(core, queue, dump_info);
	if (ret) {
		cn_dev_core_err(core, "wait queue(%px) sid %llu dump finish failed!",
				queue, queue->dev_sid);
		queue_put(sbts->queue_manager, queue);
		return ret;
	}

	ret = sbts->dump_mgr->ops->copy_dump_header(dump_info);
	if (ret) {
		cn_dev_core_err(core, "copy core dump header falied!");
	}

	queue_put(sbts->queue_manager, queue);

	return ret;
}

static int
__queue_dump_dma(struct sbts_set *sbts, struct queue *queue,
		struct core_dump_info *dump_info, struct sbts_queue_dump_ack param,
		cn_user user)
{
	int ret;
	struct cn_core_set *core = sbts->core;
	struct transfer_s t;
	enum core_dump_sta status = DUMP_COMM_FINISH;
	struct mlu_core_dump_msg *priv;
	struct comm_ctrl_desc tx_desc;

	/* check if driver-api alloc dump buffer success */
	if (param.type == CORE_DUMP_ERROR) {
		cn_dev_core_err(core, "the usr alloc dump buffer failed!");
		ret = -EFAULT;
		status = DUMP_COMM_ERROR;
		goto send_msg_to_arm;
	}

	/* memcpy D2H */
	TRANSFER_INIT(t, param.host_addr, param.device_addr, param.size, DMA_D2H);
	ret = cn_bus_dma(core->bus_set, &t);
	if (ret) {
		cn_dev_core_err(core, "host %#llx, device %#llx, size %#llx D2H failed!",
				param.host_addr, param.device_addr, param.size);
		ret = -EFAULT;
		status = DUMP_COMM_ERROR;
	}

send_msg_to_arm:
	if (atomic_read(&dump_info->wait_ack)) {
		atomic_dec(&dump_info->wait_ack);
	} else {
		cn_dev_core_err(core, "dump_id %lld, block id %lld, wait ack num is 0!",
				param.dump_id, param.seq_id);
		status = DUMP_COMM_ERROR;
	}
	priv = (struct mlu_core_dump_msg *)tx_desc.data;
	tx_desc.version		= 0;
	tx_desc.sta			= status;
	priv->user			= (__u64)user;
	priv->queue_dsid	= param.hqueue;
	priv->dump_id		= param.dump_id;
	priv->seq_id		= param.seq_id;
	priv->block_addr	= param.device_addr;
	priv->block_size	= param.size;

	if (__core_dump_send(sbts->dump_mgr, &tx_desc)) {
		cn_dev_core_err(core, "core dump send msg failed!");
		ret = -EFAULT;
	}

	return ret;
}

int
cn_core_dump_ack(struct sbts_set *sbts, void *arg, cn_user user)
{
	int ret = 0;
	struct queue *queue = NULL;
	struct sbts_queue_dump_ack param;
	struct cn_core_set *core = sbts->core;
	struct core_dump_info *dump_info = NULL;

	ret = copy_from_user((void *)&param, (void *)arg,
			sizeof(struct sbts_queue_dump_ack));
	if (ret) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	/* get queue */
	queue = queue_get(sbts->queue_manager, param.hqueue, user, 0);
	if (!queue) {
		cn_dev_core_err(core, "queue_disd(%#llx) is invalid", param.hqueue);
		return -CN_QUEUE_ERROR_QUEUE_INVALID;
	}
	dump_info = queue->dump_info;

	/* wait core dump finish */
	if (param.type == CORE_DUMP_WAIT_FINISH) {
		ret = __wait_queue_dump_finish(core, queue, dump_info);
	} else {
		ret = __queue_dump_dma(sbts, queue, dump_info, param, user);
	}

	if (ret) {
		cn_dev_core_err(core, "queue(%px) sid %llu do %lld failed!",
				queue, queue->dev_sid, param.type);
	}

	queue_put(sbts->queue_manager, queue);
	return ret;
}

struct core_dump_info *
core_dump_info_init(struct sbts_set *sbts, struct sbts_create_queue *pparam)
{
	struct core_dump_manager *dump_mgr = sbts->dump_mgr;

	return dump_mgr->ops->dump_info_init(dump_mgr, pparam);
}

void core_dump_info_exit(struct sbts_set *sbts, struct core_dump_info *dump_info)
{
	struct core_dump_manager *dump_mgr = sbts->dump_mgr;

	dump_mgr->ops->dump_info_exit(dump_mgr, dump_info);
}

int queue_ack_sta_parse(struct cn_core_set *core, struct queue *queue,
		struct hpq_task_ack_desc ack_desc)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct core_dump_manager *dump_mgr = sbts->dump_mgr;

	return dump_mgr->ops->ack_sta_parse(core, queue, ack_desc);
}

/* core dump manager init and exit */
static int
dump_dbg_cbk(struct sbts_set *sbts, struct comm_dbg_desc *rx_desc)
{
	struct core_dump_manager *dump_mgr = sbts->dump_mgr;

	dump_mgr->ops->dump_finish_cbk(dump_mgr, rx_desc);

	return 0;
}

static const struct sbts_dbg_ops dump_dbg_ops = {
	.msg_cbk = dump_dbg_cbk,
};

void sbts_core_dump_thread(
		struct cn_core_set *core,
		void *data,
		void *rx_msg,
		int rx_size)
{
	struct core_dump_manager *dump_mgr = (struct core_dump_manager *)data;

	if (rx_size != sizeof(struct comm_ctrl_desc)) {
		cn_dev_core_err(core, "recv msg size(%d) not match %lu",
			rx_size, sizeof(struct comm_ctrl_desc));
		return;
	}

	dump_mgr->ops->do_core_dump_cbk(dump_mgr, (struct comm_ctrl_desc *)rx_msg);
}

static int
mlu_sbts_error_map(__u64 ack_sta)
{
	int ret = 0;

	switch (lower_32_bits(ack_sta)) {
	case SBTST_ACK_INIT_FAILED:
		ret = CN_SBTS_TASK_DEVICE_INIT_FAILED;
		break;
	case SBTST_ACK_PUSH_FAILED:
		ret = CN_SBTS_TASK_DEVICE_PUSH_FAILED;
		break;
	case SBTST_ACK_CFG_TASK_FAILED:
		ret = CN_SBTS_TASK_DEVICE_CFGTASK_FAILED;
		break;
	case SBTST_ACK_SWTASK_RUN_TIMEOUT:
		ret = CN_SBTS_TASK_SW_RUN_TIMEOUT;
		break;
	case SBTST_ACK_LMEM_RESIZE_FAIL:
		ret = CN_SBTS_LMEM_RESIZE_FAIL;
		break;
	case SBTST_ACK_DMA_ASYNC_ERROR:
		ret = CN_DMA_ASYNC_ERR;
		break;
	case SBTST_ACK_IDC_ERROR:
		ret = CN_IDC_ERR;
		break;
	case SBTST_ACK_NO_TINYCORE:
		ret = CN_TNC_NOT_EXIST;
		break;
	case SBTST_ACK_NOTIFIER_ERROR:
		ret = CN_DEVICE_NOTIFIER_ERR;
		break;
	case SBTST_ACK_C2C_TASK_TIMEOUT ... SBTST_ACK_TCDP_END:
		ret = SBTS_NCS_ACK_ERRNO_BASE + lower_32_bits(ack_sta);
		break;
	case SBTST_ACK_OTHER_ERR:
	default:
		ret = CN_SBTS_TASK_OTHER_ERROR;
		break;
	}

	return -ret;
}

static int
mlu_ack_sta_parse(struct cn_core_set *core, struct queue *queue,
		struct hpq_task_ack_desc ack_desc)
{
	const char *upper_desc = "";
	const char *lower_desc = "";

	switch (upper_32_bits(ack_desc.sta)) {
	case SBTST_ACK_IFU_ERR:
		upper_desc = " instruction fetch error!";
		break;
	case SBTST_ACK_IDU_ERR:
		upper_desc = " instruction decoder error!";
		break;
	case SBTST_ACK_MAU_ERR:
		upper_desc = " memory access error!";
		break;
	case SBTST_ACK_SDU_ERR:
		upper_desc = " stream decode error!";
		break;
	case SBTST_ACK_SMMU_ERR:
		upper_desc = " smmu error!";
		break;
	case SBTST_ACK_WATCH_DOG_ERR:
		upper_desc = " watch dog timeout!";
		break;
	case SBTST_ACK_INIT_RAM_ERR:
		upper_desc = " init ram timeout!";
		break;
	case SBTST_ACK_DUMP_FINISH:
		queue->dump_info->dumped_done = 1;
		break;
	default:
		/* nothing to do */
		break;
	}

	switch (lower_32_bits(ack_desc.sta)) {
	case SBTST_ACK_OTHER_ERR:
		lower_desc = " device task run error!";
		break;
	case SBTST_ACK_INIT_FAILED:
		lower_desc = " init task failed!";
		break;
	case SBTST_ACK_PUSH_FAILED:
		lower_desc = " push task failed!";
		break;
	case SBTST_ACK_CFG_TASK_FAILED:
		lower_desc = " device sw task run error!";
		break;
	case SBTST_ACK_SWTASK_RUN_TIMEOUT:
		lower_desc = " device sw task timeout!";
		break;
	case SBTST_ACK_LMEM_RESIZE_FAIL:
		lower_desc = " local memory resize failed!";
		break;
	case SBTST_ACK_DMA_ASYNC_ERROR:
		lower_desc = " dma async task error!";
		break;
	case SBTST_ACK_IDC_ERROR:
		lower_desc = " idc task error!";
		break;
	case SBTST_ACK_NO_TINYCORE:
		lower_desc = " tinycore not exist!";
		break;
	case SBTST_ACK_NOTIFIER_ERROR:
		lower_desc = " devcie notifier run error!";
		break;
	case SBTST_ACK_C2C_TASK_TIMEOUT ... SBTST_ACK_C2C_TASK_TYPE_INVALID:
		lower_desc = " ncs error!";
		break;
	case SBTST_ACK_TCDP_INTERNEL_ERR ... SBTST_ACK_TCDP_RESEND_EXCEED_MAX_NUM:
		lower_desc = " tcdp error!";
		break;
	default:
		/* nothing to do */
		break;
	}

	cn_dev_core_err(core,
		"queue(%px) sid %llu, curr ticket:%lld, ack ticket:%lld, ack:%#08x_%#08x%s%s",
			queue, queue->dev_sid, queue->task_ticket, ack_desc.seq_num,
			upper_32_bits(ack_desc.sta), lower_32_bits(ack_desc.sta),
			upper_desc, lower_desc);

	return mlu_sbts_error_map(ack_desc.sta);
}

static int former_sbts_error_map(__u64 ack_sta)
{
	int ret = 0;
	__u32 core_id;
	__u32 sbts_ack;

	/* not ipu error */
	if (ack_sta == SBTST_ACK_OTHER_ERR) {
		return -EIO;
	}

	/*
	 * get ipu error code from @sta
	 * the definition of @sta bits:
	 * 0  -  7  bits: ipu error code get from hpq
	 * 8  -  15 bits: error core id from hpq
	 * 16 -  63 bits: reserved
	 */
	sbts_ack = ack_sta & SBTS_IPU_ERRNO_ACK_MASK;
	/* get core id from @sta */
	core_id = (ack_sta >> SBTS_IPU_ERRNO_ACK_OFFSET) & SBTS_IPU_ERRNO_ACK_MASK;
	/*
	 * change error code from hpq to driver api
	 * error code 1 is SBTST_ACK_OTHER_ERR
	 * error code 2 ~ 51 are ipu error
	 * error code 52 is CN_IPU_UNKNOWN_ERR
	 * error code 53 is CN_SBTS_LMEM_RESIZE_FAIL
	 * error code 54 is CN_DMA_ASYNC_ERR
	 * error code 110 ~ 149 is NCS_STREAM_SYNC_ERR
	 * error code 150 ~ 200 is TCDP_STREAM_SYNC_ERR
	 */
	if (sbts_ack > 1 && sbts_ack < 52) {
		sbts_ack = SBTS_IPU_ERRNO_BASE + sbts_ack;
	} else if (sbts_ack == 52) {
		sbts_ack = CN_IPU_UNKNOWN_ERR;
	} else if (sbts_ack == SBTST_ACK_LMEM_RESIZE_FAIL) {
		sbts_ack = CN_SBTS_LMEM_RESIZE_FAIL;
	} else if (sbts_ack == SBTST_ACK_DMA_ASYNC_ERROR) {
		sbts_ack = CN_DMA_ASYNC_ERR;
	} else if (sbts_ack == SBTST_ACK_IDC_ERROR) {
		sbts_ack = CN_IDC_ERR;
	} else if (sbts_ack >= SBTST_ACK_C2C_TASK_TIMEOUT &&
			sbts_ack <= SBTST_ACK_C2C_END) {
		sbts_ack = SBTS_NCS_ACK_ERRNO_BASE + sbts_ack;
	} else {
		cn_dev_debug("unexpected sbts_ack");
		return -EIO;
	}
	/*
	 * the definition of @ret bits:
	 * 0  - 19 bits: error code send to driver api
	 * 20 - 27 bits: error core send to driver api
	 * 28 - 31 bits: reserved
	 */
	ret = (core_id << SBTS_IPU_ERRNO_RET_OFFSET) | sbts_ack;

	return -ret;
}

static int
former_ack_sta_parse(struct cn_core_set *core, struct queue *queue,
		struct hpq_task_ack_desc ack_desc)
{
	const char *lower_desc = "";

	switch (lower_32_bits(ack_desc.sta)) {
	case SBTST_ACK_LMEM_RESIZE_FAIL:
		lower_desc = " local memory resize failed!";
		break;
	case SBTST_ACK_DMA_ASYNC_ERROR:
		lower_desc = " dma async error!";
		break;
	case SBTST_ACK_IDC_ERROR:
		lower_desc = " idc error!";
		break;
	case SBTST_ACK_C2C_TASK_TIMEOUT ... SBTST_ACK_C2C_TASK_TYPE_INVALID:
		lower_desc = " ncs error!";
	default:
		/* nothing to do */
		break;
	}

	cn_dev_core_err(core,
		"queue(%px) sid %llu, curr ticket:%lld, ack ticket:%lld, ack:%#08x_%#08x%s",
			queue, queue->dev_sid, queue->task_ticket, ack_desc.seq_num,
			upper_32_bits(ack_desc.sta), lower_32_bits(ack_desc.sta),
			lower_desc);

	return former_sbts_error_map(ack_desc.sta);
}

static const struct core_dump_ops mlu_dump_ops = {
	.do_core_dump_cbk	= mlu_core_dump_cbk,
	.dump_finish_cbk	= mlu_dump_finish_cbk,
	.dump_info_init		= mlu_dump_info_init,
	.dump_info_exit		= mlu_dump_info_exit,
	.copy_dump_header	= mlu_copy_dump_header,
	.ack_sta_parse		= mlu_ack_sta_parse,
};

static const struct core_dump_ops former_dump_ops = {
	.do_core_dump_cbk	= former_core_dump_cbk,
	.dump_finish_cbk	= former_dump_finish_cbk,
	.dump_info_init		= former_dump_info_init,
	.dump_info_exit		= former_dump_info_exit,
	.copy_dump_header	= former_copy_dump_header,
	.ack_sta_parse		= former_ack_sta_parse,
};

int
sbts_dump_manager_init(struct core_dump_manager **ppdump_mgr, struct cn_core_set *core)
{
	int ret = 0;
	struct core_dump_manager *manager = NULL;
	struct sbts_set *sbts = core->sbts_set;

	manager = cn_kzalloc(sizeof(struct core_dump_manager), GFP_KERNEL);
	if (!manager) {
		cn_dev_core_err(core, "malloc core dump manager failed!");
		return -ENOMEM;
	}

	/* create worker */
	manager->worker = commu_wait_work_run(core, "sbts_dump",
			sbts->sched_manager->core_dump_ep, manager,
			sbts_core_dump_thread);
	if (!manager->worker) {
		cn_dev_core_err(core, "create core dump thread failed!");
		ret = -EINVAL;
		goto thread_init_fail;
	}

	ret = sbts_dbg_register_cbk(sbts, DBG_TASK_DUMP, &dump_dbg_ops);
	if (ret) {
		cn_dev_core_err(core, "register for dbg callback fail");
		goto reg_dbg_fail;
	}

	switch (core->device_id) {
	case MLUID_290:
	case MLUID_290V1:
	case MLUID_270:
	case MLUID_220:
	case MLUID_220_EDGE:
	case MLUID_270V:
	case MLUID_270V1:
		manager->ops = &former_dump_ops;
		break;

	default:
		manager->ops = &mlu_dump_ops;
	}

	manager->core = core;
	manager->sbts = sbts;

	*ppdump_mgr = manager;

	return 0;

reg_dbg_fail:
	commu_wait_work_stop(core, manager->worker);
thread_init_fail:
	cn_kfree(manager);

	return ret;
}

void
sbts_dump_manager_exit(struct core_dump_manager *dump_manager)
{
	if (!dump_manager) {
		cn_dev_err("dump manager is null");
		return;
	}

	commu_wait_work_stop(dump_manager->core, dump_manager->worker);
	dump_manager->sbts->dump_mgr = NULL;

	cn_kfree(dump_manager);
}

