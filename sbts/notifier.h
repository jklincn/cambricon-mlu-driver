/*
 * sbts/notifier.h
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

#ifndef __SBTS_NOTIFIER_H
#define __SBTS_NOTIFIER_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/kref.h>

#include "cndrv_ioctl.h"
#include "sbts_set.h"
#include "cndrv_hpq.h"
#include "cndrv_mm.h"
#include "sbts.h"
#include "cndrv_sbts.h"

struct cn_core_set;
struct sched_manager;
struct sbts_shm_manager;

/*
 * Notifier Management
 */
#define MAX_NOTIFIER_NUM    (1024)
#define STAGE_NOTIFIER_NUM  (128)

#define NOTIFIER_NUM_SPECIAL  (6000)
#define NOTIFIER_NUM_NORMAL   (24000)
#define NOTIFIER_NUM_SRIOV    NOTIFIER_NUM_NORMAL

struct notifier_mgr {
	u64 count;
	u64 stage;
	rwlock_t rwlock;
	struct sbts_set_container_st container;
	struct kref ref_cnt;
	struct sched_manager *sched_mgr;
	struct cn_core_set *core;
	struct sbts_shm_manager *shm_mgr;

	/* for dev free info */
	u64 df_ticket;
	struct mutex df_mutex;
	struct sbts_set_container_st df_container;
	struct kmem_cache *df_mem;
};

struct notifier_dev_free_s {
	u64 ticket;

	struct queue_ack_s *ack_info;

	struct sbts_set_iter_st iter;
};

/* save place and wait info,
 * share one info if INTERPROCESS */
struct notifier_active_info {
	struct mutex mutex;

	struct cn_core_set *place_core;
	int place_c_idx;
	struct queue_ack_s *place_q_ack;
	u64 place_q_seq;
	/* for debug */
	u64 place_q_idx;
};

/* save device info and notifier ack addr info
 * share each device one info if INTERPROCESS in ipchandle */
struct notifier_device_info {
	u64 dev_eid;

	/* the number of place and wait on self-device */
	u64 waiter_nr;
	/* place send to device */
	u64 capturer_nr;
	/* the last place value */
	u64 last_val;

	struct notifier_mgr *notifier_mgr;
};

/* alloc when create notifier with INTERPROCESS
 * each new openhandle will create new notifier and add refcnt
 * insert global handle rbtree will add refcnt once
 * the original notifier will not add refcnt which will init with 1
 * original and child notifier destroy will dec refcnt
 *
 * ** the ipchandle will be destroy when refcnt is 0.
 *
 * ** the rbtree will insert when create handle and erase when ctx(user) exit.
 *
 * */
struct notifier_ipchandle {
	/* create by which user */
	u64 user;
	u64 user_id;
	/* create by which device */
	struct cn_core_set *core;
	/* global seq */
	u64 seq;
	/* handle for global rb tree node */
	struct sbts_set_iter_st iter;
	/* handle ref_cnt add with each notifier */
	struct kref ref_cnt;
	/* save the original notifier's flags */
	u32 flags;

	/* inherit from original notifier */
	struct notifier_active_info *active_info;
	/* only one device info for each devices if use */
	struct notifier_device_info *dev_info[MAX_FUNCTION_NUM];
};

struct notifier {
	u64 eid;
	u64 user;
	u32 flags;
	int destroy;
	bool dis_timing_sw;
	bool dis_timing_all;
	bool exception_infect;

	/* save ipchandle if active */
	struct notifier_ipchandle *ipchandle;
	/* save place queue info */
	struct notifier_active_info *active_info;
	/* save device info */
	struct notifier_device_info *dev_info;

	struct sbts_set_iter_st iter;
	struct kref  ref_cnt;
	struct cn_core_set *core;

	/* get host hw time from queue when place notifier */
	u64 host_place_time;

	/* save placed queue global index, use when user get timestamp */
	u64 place_queue;
	/* notifier ack buffer, only use when record time */
	dev_addr_t dev_vaddr;
	STRUCT_HPAS(hpq_notifier_ack, struct hpq_notifier_ack_desc) ack;
};

enum elapsed_time_type {
	ELAPSED_HW_EXEC_TIME = 0,
	ELAPSED_SW_TIME,
};

#define CN_NOTIFIER_FLAGS_SHIFT (0x8)
#define CN_NOTIFIER_FLAGS_MASK  (0xFFFF << CN_NOTIFIER_FLAGS_SHIFT)

enum notifier_create_flags {
	CN_NOTIFIER_DEFAULT = 0,
	CN_NOTIFIER_DISABLE_TIMING_SW = 0x2,
	CN_NOTIFIER_DISABLE_TIMING_ALL = 0x4,
	CN_NOTIFIER_INTERPROCESS = 0x8,

	/* internal use with CNDrv, not for user
	 * the queue wait notifier task will exception if the
	 * notifier place task's queue exception.
	 * */
	CN_NOTIFIER_INFECT_QUEUE_EXCEPTION = 0x8000,
	/* internal use with CNDrv, not for user
	 * notifier created by topo use.
	 * */
	CN_NOTIFIER_TOPO_INTERNAL = 0x4000,
};

#define CN_NOTIFIER_DISTIM_SW(flag) (((flag) >> CN_NOTIFIER_FLAGS_SHIFT) & CN_NOTIFIER_DISABLE_TIMING_SW)
#define CN_NOTIFIER_DISTIM_ALL(flag) (((flag) >> CN_NOTIFIER_FLAGS_SHIFT) & CN_NOTIFIER_DISABLE_TIMING_ALL)
#define CN_NOTIFIER_INFECT_QUEUE(flag) (((flag) >> CN_NOTIFIER_FLAGS_SHIFT) & CN_NOTIFIER_INFECT_QUEUE_EXCEPTION)

enum notifier_topo_task_type {
	TOPO_NOTIFIER_NORMAL = 0,
	TOPO_NOTIFIER_INTERNAL = 1,
	TOPO_NOTIFIER_USER = 2,
};

/* get notifier's dev_info by core->idx
 *
 * This function is use for whom doesnt known which is the right dev_info.
 *
 * If notifier is not a ipc valid, just return dev_info in itself,
 * no matter core->idx value.
 *
 * If notifier is ipc valid which have ipchandle,
 * we need to check handle dev_info by core->idx.
 * If handle->dev_info[core->idx] is NULL, return notifier->dev_info.
 *
 *
 * */
static inline struct notifier_device_info *
sbts_notifier_dev_info(struct cn_core_set *core, struct notifier *notifier)
{
	if (!notifier->ipchandle)
		return notifier->dev_info;

	return notifier->ipchandle->dev_info[core->idx] ?
			notifier->ipchandle->dev_info[core->idx] :
			notifier->dev_info;
}


int sbts_notifier_feature_available(struct cn_core_set *core);

int notifier_dev_free_create(struct sbts_set *sbts,
		struct notifier_active_info *active_info, u64 *seq);
void notifier_dev_free_release(struct sbts_set *sbts, u64 seq);

int notifier_do_exit(u64 user, struct notifier_mgr *notifier_mgr);
struct notifier *notifier_get(struct notifier_mgr *notifier_mgr,
		u64 eid, cn_user user);
int notifier_put(struct notifier_mgr *notifier_mgr, struct notifier *notifier);
int notifier_manager_init(struct notifier_mgr **ppnotifier_mgr, struct cn_core_set *core);
void notifier_manager_exit(struct notifier_mgr *pnotifier_mgr);

int notifier_capturer_update(
		struct notifier_mgr *notifier_mgr,
		u64 eid, u64 user, u64 update_val);
int notifier_capturer_reset(
		struct notifier_mgr *notifier_mgr,
		u64 eid, u64 user);
static inline int __notifier_capturer_update(struct notifier *notifier,
		u64 update_val)
{
	struct notifier_device_info *dev_info = notifier->dev_info;

	__sync_add_and_fetch(&dev_info->capturer_nr, update_val);
	__sync_add_and_fetch(&dev_info->last_val, update_val);

	return 0;
}

static inline int notifier_task_param_check(
		struct sbts_queue_invoke_task *user_param)
{
	struct sbts_topo_notifier *topo_notifier =
		&user_param->priv_data.topo_notifier;

	if (user_param->dev_topo_cmd == DEV_TOPO_TASK_TYPE_PARAM)
		return -EINVAL;

	if (topo_notifier->type == TOPO_NOTIFIER_USER)
		return -EINVAL;

	return 0;
}

static inline void notifier_place_save_q_ack(
		struct queue *queue,
		struct notifier *notifier,
		struct notifier_active_info *notifier_ainfo,
		u64 seq)
{
	int ret;

	cn_dev_core_debug(queue->core, "save q[%llu] info %llx seq %llu in notifier[%llu]",
			queue->dev_sid, (u64)queue->ack_info, seq, notifier->dev_info->dev_eid);

	if (notifier_ainfo->place_q_ack) {
		if (notifier_ainfo->place_q_ack == queue->ack_info) {
			/* same queue with last just update seq */
			notifier_ainfo->place_q_seq = seq;
			return;
		}
		queue_ack_put(notifier_ainfo->place_q_ack);
		notifier_ainfo->place_q_ack = NULL;
	}
	/* it shouldnt fail when in place notifier we just get queue */
	ret = queue_ack_get(queue->ack_info);
	if (ret) {
		cn_dev_err("call q ack get failed %d", ret);
		BUG_ON(1);
	}
	notifier->place_queue = queue->sid;

	notifier_ainfo->place_core  = queue->core;
	notifier_ainfo->place_c_idx = queue->core->idx;
	notifier_ainfo->place_q_ack = queue->ack_info;
	notifier_ainfo->place_q_seq = seq;
	notifier_ainfo->place_q_idx = queue->dev_sid;
}

#endif
