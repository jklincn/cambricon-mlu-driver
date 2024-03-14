/*
 * sbts/notifier.c
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
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include "../core/cndrv_ioctl.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_sbts.h"
#include "cndrv_hpq.h"
#include "sbts.h"
#include "queue.h"
#include "notifier.h"
#include "sbts_sram.h"
#include "cndrv_debug.h"

static u64 g_notifier_ticket = 1;

DECLARE_RWSEM(g_ipchandle_rwsem);
DEFINE_SBTS_SET_CONTAINER(notifier_ipchandle_container);
static u64 g_ipchandle_seq = 1;

/*
 * For WaitNotifier on another device and IPCNotifier feature.
 * we need check device is MLU590 and check device atomicop available.
 * */
int sbts_notifier_feature_available(struct cn_core_set *core)
{
	struct sbts_set *sbts = core->sbts_set;

	/* no need support multi-dev notifier on edge platform
	 * which have only one mlu device.
	 * */
#ifdef CONFIG_CNDRV_EDGE
	if (core->device_id == MLUID_PIGEON_EDGE)
		return 1;

	return 0;
#endif

	if ((core->device_id != MLUID_590) &&
			(core->device_id != MLUID_590V) &&
			(core->device_id != MLUID_580) &&
			(core->device_id != MLUID_580V))
		return 0;

	if (!sbts->outbd_able)
		return 0;

	if (!sbts_global_atomicop_support())
		return 0;

	return 1;
}

static int __notifier_compare(struct notifier *r, struct notifier *l)
{
	u64 rkey = r->eid;
	u64 lkey = l->eid;

	if (rkey < lkey) {
		return -1;
	}

	if (rkey > lkey) {
		return 1;
	}

	return 0;
}

static struct notifier *__notifier_validate(struct notifier_mgr *notifier_mgr, u64 eid)
{
	struct notifier obj = { .eid = eid };
	struct notifier *notifier = NULL;
	struct cn_core_set *core = (struct cn_core_set *)notifier_mgr->core;

	notifier = sbts_set_find(&notifier_mgr->container, &obj,
			__notifier_compare, iter);

	cn_dev_core_debug(core, "find notifier by id: %#llx", eid);
	return notifier;
}

static void notifier_add(struct notifier_mgr *notifier_mgr, struct notifier *notifier)
{
	struct notifier *n;

	write_lock(&notifier_mgr->rwlock);
	n = sbts_set_insert(&notifier_mgr->container, notifier,
			__notifier_compare, iter);
	if (unlikely(!n)) {
		cn_dev_core_err(notifier_mgr->core,
				"add notifier eid %#lx failed!",
				(unsigned long)notifier->eid);
	}
	write_unlock(&notifier_mgr->rwlock);
}

static void notifier_del(struct notifier_mgr *notifier_mgr, struct notifier *notifier)
{
	sbts_set_erase(&notifier_mgr->container, notifier, iter);
}

/* ret 0  user hasnt place ret, just success
 * ret 1  queue_ack get success, read seq
 * ret <0 some error occur, return fail to user
 * */
static int __notifier_active_info_ack_get(
		struct notifier_active_info *active_info,
		struct queue_ack_s **place_q_ack, u64 *seq
		)
{
	int ret = 0;

	mutex_lock(&active_info->mutex);
	if (!active_info->place_q_ack) {
		mutex_unlock(&active_info->mutex);
		return 0;
	}
	ret = queue_ack_get(active_info->place_q_ack);
	if (ret) {
		mutex_unlock(&active_info->mutex);
		cn_dev_err("queue ack get fail %d", ret);
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}
	*place_q_ack = active_info->place_q_ack;
	*seq = active_info->place_q_seq;
	mutex_unlock(&active_info->mutex);

	return 1;
}

/* check the queue ack seq is equal or bigger than seq.
 * return CN_SBTS_RESOURCE_NOT_READY which is 1 as queue_seq < seq
 * return 0 if queue_seq >= seq or ack sta is exception which means queue is invalid.
 * return <0 if read ack fail
 * */
static int __notifier_active_info_ack_seq_comp(
		struct notifier *notifier,
		struct queue_ack_s *place_q_ack, u64 seq)
{
	int ret = 0;
	struct hpq_task_ack_desc ack;

	/* if timing enable, must wait place finish to wait time value write back */
	seq = notifier->dis_timing_all ? (seq-1) : seq;

	ret = queue_ack_read_ack_data(place_q_ack, &ack);
	/* ret == 0, read ack fail */
	if (!ret)
		return -ETIMEDOUT;
	/* queue_ack >= seq, task finish */
	if (__le64_to_cpu(ack.seq_num) >= seq)
		return 0;
	/* sta is non-zero, queue exception */
	if (ack.sta) {
		cn_dev_warn_limit("return ack queue exception");
		return 0;
	}

	return CN_SBTS_RESOURCE_NOT_READY;
}

/* ipc handle info functions */
static int __notifier_ipchandle_compare(
		struct notifier_ipchandle *r,
		struct notifier_ipchandle *l)
{
	u64 rkey = r->seq;
	u64 lkey = l->seq;

	if (rkey < lkey) {
		return -1;
	}

	if (rkey > lkey) {
		return 1;
	}

	return 0;

}

static inline void __notifier_ipchandle_get(struct notifier_ipchandle *ipchandle)
{
	if (!kref_get_unless_zero(&ipchandle->ref_cnt)) {
		cn_dev_warn("handle(%#llx) seq %llu ref cnt is invalid",
				(u64)ipchandle, ipchandle->seq);
		WARN_ON(1);
	}
}

struct notifier_ipchandle *
notifier_ipchandle_get(u64 seq, struct notifier_ipchandle *phandle)
{
	struct notifier_ipchandle obj = { .seq = seq };
	struct notifier_ipchandle *ipchandle;

	down_read(&g_ipchandle_rwsem);
	ipchandle = sbts_set_find(&notifier_ipchandle_container, &obj,
			__notifier_ipchandle_compare, iter);

	if (!ipchandle) {
		goto get_err;
	}
	if (ipchandle != phandle) {
		cn_dev_warn("find handle by seq %llu with diff addr %#llx %#llx",
				seq, (u64)ipchandle, (u64)phandle);
		ipchandle = NULL;
		goto get_err;
	}
	__notifier_ipchandle_get(ipchandle);
get_err:
	up_read(&g_ipchandle_rwsem);
	return ipchandle;
}

/* create ipchandle when origin notifier create */
/* after create the ref_cnt will be 1 which indicate one original notifier available
 * if remain create flow failed or user destroy notifier without gethandle,
 * the ipchandle will free when destroy the notifier.
 *
 * if user gethandle, the ref_cnt will add once, and handle in rbtree.
 * if other user openhandle, it also add ref_cnt.
 *
 * if the original notifier user(ctx) exit, the rbtree will be erase and dec ref_cnt once.
 * if other notifiers which create by openhandle is being free, the handle ref_cnt will also dec.
 *
 * */
static int notifier_ipchandle_create(
		struct cn_core_set *core,
		struct notifier_mgr *notifier_mgr,
		struct notifier *notifier)
{
	struct notifier_ipchandle *ipchandle, *n;
	bool enable = (notifier->flags >> CN_NOTIFIER_FLAGS_SHIFT) & CN_NOTIFIER_INTERPROCESS;

	if (false == enable) {
		return 0;
	}

	ipchandle = cn_numa_aware_kzalloc(core, sizeof(struct notifier_ipchandle),
			GFP_KERNEL);
	if (!ipchandle) {
		cn_dev_core_err(core, "create notifier ipc handle failed");
		return -ENOMEM;
	}
	/* save current user as create user */
	ipchandle->user = notifier->user;
	ipchandle->user_id = cn_core_get_fp_id((struct file *)notifier->user);
	ipchandle->core = core;
	ipchandle->seq = __sync_add_and_fetch(&g_ipchandle_seq, 1);
	ipchandle->flags = notifier->flags;
	kref_init(&ipchandle->ref_cnt);

	ipchandle->active_info = notifier->active_info;
	ipchandle->dev_info[core->idx] = notifier->dev_info;

	/* insert to handle rbtree */
	down_write(&g_ipchandle_rwsem);
	n = sbts_set_insert(&notifier_ipchandle_container, ipchandle,
			__notifier_ipchandle_compare, iter);
	up_write(&g_ipchandle_rwsem);
	if (!n) {
		cn_dev_core_err(core, "insert ipchandle tree failed!");
		cn_kfree(ipchandle);
		return -EFAULT;
	}
	/* insert rbtree need get once which will put in user(ctx) exit */
	__notifier_ipchandle_get(ipchandle);

	notifier->ipchandle = ipchandle;

	return 0;
}

int destroy_notifier_device_env(
		struct notifier_mgr *notifier_mgr,
		struct notifier_device_info *dev_info,
		struct hpq_notifier_ack *notifier_ack,
		u64 user);

static void notifier_ipchandle_destroy(
		struct notifier_ipchandle *ipchandle)
{
	struct notifier_active_info *active_info = ipchandle->active_info;
	int i;

	if (active_info->place_q_ack) {
		queue_ack_put(active_info->place_q_ack);
	}
	for (i = 0; i < MAX_FUNCTION_NUM; i++) {
		if (NULL == ipchandle->dev_info[i])
			continue;

		destroy_notifier_device_env(ipchandle->dev_info[i]->notifier_mgr,
				ipchandle->dev_info[i], NULL, 0);
		ipchandle->dev_info[i] = NULL;
	}

	cn_kfree(active_info);
	cn_kfree(ipchandle);
}

static void notifier_ipchandle_release(struct kref *kref)
{

}
void notifier_ipchandle_put(struct notifier_ipchandle *ipchandle)
{
	if (kref_put(&ipchandle->ref_cnt, notifier_ipchandle_release)) {
		notifier_ipchandle_destroy(ipchandle);
	}
}


static int
__wait_notifier_polling(struct sbts_set *sbts, struct notifier_mgr *notifier_mgr,
		struct notifier *notifier)
{
	struct cn_core_set *core = sbts->core;
	int ret = 0;
	struct queue_ack_s *place_q_ack;
	u64 seq;
	bool should_yield = ((notifier->flags & CN_CTX_SCHED_SYNC_MASK) ==
			CN_CTX_SCHED_SYNC_YIELD);

	ret = __notifier_active_info_ack_get(
			notifier->active_info,
			&place_q_ack, &seq);
	if (ret <= 0)
		return ret;
	while (1) {
		/* ret > 0 is not finish */
		ret = __notifier_active_info_ack_seq_comp(notifier, place_q_ack, seq);
		if (0 == ret) {
			cn_dev_core_debug(core, "notifier %#llx-%llu wait done",
					(u64)notifier, notifier->dev_info->dev_eid);
			break;
		}

		if (ret < 0) {
			cn_dev_core_err(core, "notifier %#llxx-%llu ack read fail %d",
					(u64)notifier, notifier->dev_info->dev_eid, ret);
			break;
		}

		if (should_yield) {
			cond_resched();
		}

		ret = sbts_pause_stopable(core, 3, 5);
		if (ret) {
			if (ret == -ERESTARTNOINTR) {
				cn_dev_core_err(core, "wait notifier %#llx(dev:%llu) stop by pending signal(ret %d)",
						(u64)notifier, notifier->dev_info->dev_eid, ret);
			} else {
				cn_dev_core_err(core, "wait notifier %#llx(dev:%llu) killed by fatal signal",
						(u64)notifier, notifier->dev_info->dev_eid);
			}
			break;
		}
	}
	queue_ack_put(place_q_ack);

	return ret;
}

struct wait_notifier_data {
	struct notifier *notifier;
	struct queue_ack_s *place_q_ack;
	u64 seq;
	int sta;
};

static int wait_notifier_handler(struct sbts_set *sbts, void *data)
{
	struct wait_notifier_data *wait_data =
			(struct wait_notifier_data *)data;
	struct notifier *notifier = wait_data->notifier;
	int ret = 0;

	ret = __notifier_active_info_ack_seq_comp(notifier,
			wait_data->place_q_ack, wait_data->seq);
	if (ret < 0) {

		cn_dev_core_err(sbts->core, "notifier %#llxx-%llu ack read fail %d",
				(u64)notifier, notifier->dev_info->dev_eid, ret);
		wait_data->sta = ret;
		goto finish;
	}

	if (0 == ret) {
		cn_dev_core_debug(sbts->core, "notifier %#llx-%llu wait done",
				(u64)notifier, notifier->dev_info->dev_eid);
		wait_data->sta = 0;
		goto finish;
	}

	return -EAGAIN;
finish:
	queue_ack_put(wait_data->place_q_ack);
	return 0;
}

static int
__wait_notifier_schedule(struct sbts_set *sbts,
		struct notifier_mgr *notifier_mgr, struct notifier *notifier)
{
	int ret = 0;
	struct sbts_sync_desc sync_desc;
	struct wait_notifier_data data;

	ret = __notifier_active_info_ack_get(
			notifier->active_info,
			&data.place_q_ack, &data.seq);
	if (ret <= 0)
		return ret;
	data.notifier = notifier;
	data.sta = 0;

	init_sbts_sync_desc(&sync_desc, wait_notifier_handler, &data);
	ret = sbts_wait_sync_desc_interruptible(sbts, &sync_desc);
	ret = (ret ? ret : data.sta);
	return ret;
}

int
cn_wait_notifier(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	int ret = 0;
	struct sbts_wait_notifier param;
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct cn_core_set *core = sbts->core;
	struct notifier *notifier = NULL;
	unsigned int sched_flag = 0;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
					struct sbts_wait_notifier))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	notifier = notifier_get(notifier_mgr, param.hnotifier, user);
	if (!notifier) {
		cn_dev_core_err(core, "notifier %#llx is invalid", param.hnotifier);
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}

	sched_flag = (notifier->flags & CN_CTX_SCHED_SYNC_MASK);
	switch (sched_flag) {
		case CN_CTX_SCHED_SYNC_SPIN:
		case CN_CTX_SCHED_SYNC_YIELD:
			ret = __wait_notifier_polling(sbts, notifier_mgr,
					notifier);
			break;
		case CN_CTX_SCHED_SYNC_WAIT:
			ret = __wait_notifier_schedule(sbts, notifier_mgr,
					notifier);
			break;
		default:
			ret = __wait_notifier_polling(sbts, notifier_mgr,
					notifier);
			break;
	}

	notifier_put(notifier_mgr, notifier);
	cn_dev_core_debug(core, "wait notifier finished!");

	return ret;
}

int
cn_query_notifier(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	int ret = 0;
	struct notifier *notifier = NULL;
	struct queue_ack_s *place_q_ack;
	u64 seq;
	struct sbts_query_notifier param;
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
					struct sbts_query_notifier))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	notifier = notifier_get(notifier_mgr, param.hnotifier, user);
	if (!notifier) {
		cn_dev_core_err(core, "query notifier %#llx is invalid", param.hnotifier);
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}
	ret = __notifier_active_info_ack_get(
			notifier->active_info,
			&place_q_ack, &seq);
	if (ret <= 0)
		goto get_ack_err;

	ret = __notifier_active_info_ack_seq_comp(notifier, place_q_ack, seq);
	if (ret < 0) {
		cn_dev_core_err(core, "notifier %px-%#llx ack read fail", notifier, notifier->dev_info->dev_eid);
	}

	queue_ack_put(place_q_ack);
get_ack_err:
	notifier_put(notifier_mgr, notifier);
	cn_dev_core_debug(core, "wait notifier finished!");

	return ret;
}

static int get_notifier_time(struct notifier_mgr *notifier_mgr,
		u64 eid, u64 *hw_time, u64 *host_hw, u64 *sw_time, cn_user user, u64 *qid,
		enum elapsed_time_type type)
{
	int ret = -EFAULT;
	struct hpq_notifier_ack_desc ack = {0};
	struct cn_core_set *core = (struct cn_core_set *)notifier_mgr->core;
	struct notifier *notifier = NULL;

	notifier = notifier_get(notifier_mgr, eid, user);
	if (!notifier) {
		cn_dev_core_err(core, "notifier %#llx invalid", eid);
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}
	if (notifier->dis_timing_all) {
		ret = -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
		goto get_finish;
	}

	if (notifier->dis_timing_sw && (type == ELAPSED_SW_TIME)) {
		ret = -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
		goto get_finish;
	}

	ret = hpas_read(&notifier->ack, &ack);
	if (!ret) {
		cn_dev_core_err(core, "notifier %px-%#llx hpas timeout", notifier, notifier->dev_info->dev_eid);
		ret = -ETIMEDOUT;
	} else if (ack.last_val == notifier->dev_info->last_val) {
		cn_dev_core_debug(core, "notifier %px-%#llx wait done hw time(%lldns), sw time(%lldns)",
				notifier, notifier->dev_info->dev_eid,
				(unsigned long long)ack.hw_time_ns, (unsigned long long)ack.sw_time_ns);
		*hw_time = ack.hw_time_ns;
		*host_hw = notifier->host_place_time;
		*sw_time = ack.sw_time_ns;
		*qid = notifier->place_queue;
		ret = 0;
	} else {
		cn_dev_core_debug(core, "notifier %px-%#llx(ack %lld last %lld) unfinish",
				notifier, notifier->dev_info->dev_eid, ack.last_val, notifier->dev_info->last_val);
		/* cndrv need this ret val as positive number*/
		ret = CN_SBTS_RESOURCE_NOT_READY;
	}
get_finish:
	notifier_put(notifier_mgr, notifier);

	return ret;
}

void ns_to_sec_and_usec(const s64 nsec, __u64 *sec, __u64 *usec)
{
	s32 rem = 0;
	s64 _sec = 0;
	long _nsec = 0;

	if (likely(nsec > 0)) {
		_sec = div_u64_rem(nsec, NSEC_PER_SEC, &rem);
		_nsec = rem;
	} else if (nsec < 0) {
		_sec = -div_u64_rem(-nsec - 1, NSEC_PER_SEC, &rem) - 1;
		_nsec = NSEC_PER_SEC - rem - 1;
	}

	*sec  = (__u64)_sec;
	*usec = (__u64)(_nsec / 1000);
}


static int
__notifier_elapsed_time(struct sbts_set *sbts,
		void *args,
		cn_user user,
		enum elapsed_time_type type)
{
	int ret = 0;
	u64 hw_start_ns = 0;
	u64 hw_end_ns = 0;
	u64 host_hw_s = 0;
	u64 host_hw_e = 0;
	u64 sw_start_ns = 0;
	u64 sw_end_ns = 0;
	u64 hw_elapsed_ns = 0, sw_elapsed_ns = 0, host_elapsed = 0;
	u64 qid_start = 0, qid_end = 0;
	struct sbts_notifier_elapsed_time param;
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
					struct sbts_notifier_elapsed_time))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	ret = get_notifier_time(notifier_mgr, param.hstart, &hw_start_ns, &host_hw_s, &sw_start_ns, user, &qid_start, type);
	if (ret) {
		return ret;
	}

	ret = get_notifier_time(notifier_mgr, param.hend, &hw_end_ns, &host_hw_e, &sw_end_ns, user, &qid_end, type);
	if (ret) {
		return ret;
	}

	host_elapsed = (host_hw_e > host_hw_s) ? (host_hw_e - host_hw_s) : 0;

	switch (type) {
	case ELAPSED_HW_EXEC_TIME:
		/* hw time must place on same queue */
		if (qid_start != qid_end) {
			cn_dev_core_err(core, "invalid place id");
			return -EINVAL;
		}
		hw_elapsed_ns = hw_end_ns - hw_start_ns + host_elapsed;
		cn_dev_core_debug(core, "hw execution elapse time: %#llxns", hw_elapsed_ns);
		ns_to_sec_and_usec(hw_elapsed_ns, &param.tv_sec, &param.tv_usec);
		break;
	case ELAPSED_SW_TIME:
		hw_elapsed_ns = hw_end_ns - hw_start_ns;
		sw_elapsed_ns = sw_end_ns - sw_start_ns;
		/* find max only when place on same queue */
		if (qid_start == qid_end)
		/* [DRVIER-11641] sw_elapsed_ns no less than hw_elapsed_ns */
			sw_elapsed_ns = max(hw_elapsed_ns + host_elapsed, sw_elapsed_ns);
		ns_to_sec_and_usec(sw_elapsed_ns, &param.tv_sec, &param.tv_usec);
		cn_dev_core_debug(core, "software elapse time: %#llxns", sw_elapsed_ns);
		break;
	default:
		cn_dev_core_err(core, "invalid elapsed time type!");
		return -EINVAL;
	}

	if (copy_to_user((void *)args, (void *)&param, sizeof(
					struct sbts_notifier_elapsed_time))) {
		cn_dev_core_err(core, "<NOTIFIER_ELAPSED_TIME> copy parameters to user failed!");
		return -EFAULT;
	}

	cn_dev_core_debug(core, "Se-%#llx, ee-%#llx  elapsed time finished!",
			param.hstart, param.hend);

	return ret;
}

int cn_notifier_elapsed_exec_time(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	return __notifier_elapsed_time(sbts, args, user, ELAPSED_HW_EXEC_TIME);
}

int cn_notifier_elapsed_sw_time(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	return __notifier_elapsed_time(sbts, args, user, ELAPSED_SW_TIME);
}

static int __notifier_active_info_create(
		struct notifier *notifier)
{
	struct notifier_active_info *active_info;

	active_info = cn_kzalloc(sizeof(struct notifier_active_info), GFP_KERNEL);
	if (!active_info) {
		return -ENOMEM;
	}
	mutex_init(&active_info->mutex);
	active_info->place_core  = NULL;
	active_info->place_c_idx = 0;
	active_info->place_q_ack = NULL;
	active_info->place_q_seq = 0;
	active_info->place_q_idx = 0;

	notifier->active_info = active_info;

	return 0;
}

static void __notifier_active_info_destroy(struct notifier *notifier)
{
	if (!notifier->active_info)
		return;
	/* if ipc enabled, activeinfo will free by ipchandle*/
	if (notifier->ipchandle)
		return;

	if (notifier->active_info->place_q_ack) {
		queue_ack_put(notifier->active_info->place_q_ack);
	}

	cn_kfree(notifier->active_info);
	notifier->active_info = NULL;
}

static inline int __notifier_create_flag_check(
		struct cn_core_set *core,
		int flags)
{
	int dis_time_and_ipc;

	flags = flags >> CN_NOTIFIER_FLAGS_SHIFT;

	/* check DISABLETIMING and INTERPROCESS both active */
	dis_time_and_ipc = flags & (CN_NOTIFIER_INTERPROCESS | CN_NOTIFIER_DISABLE_TIMING_ALL);
	if (dis_time_and_ipc == CN_NOTIFIER_INTERPROCESS)
		return -EINVAL;
	/* if INTERPROCESS active, check device feature available */
	if (flags & CN_NOTIFIER_INTERPROCESS) {
		/* not support */
		if (!sbts_notifier_feature_available(core))
			return -EPERM;
	}

	return 0;
}
static int create_notifier_host_env(
		struct notifier_mgr *notifier_mgr,
		struct notifier **ppnotifier,
		int flags, u64 user)
{
	int ret = 0;
	u64 __count;
	host_addr_t host_vaddr;
	dev_addr_t dev_vaddr;
	struct notifier *notifier = NULL;
	struct cn_core_set *core = (struct cn_core_set *)notifier_mgr->core;
	struct sbts_set *sbts = core->sbts_set;

	ret = __notifier_create_flag_check(core, flags);
	if (ret)
		return ret;

	__count = __sync_add_and_fetch(&notifier_mgr->count, 1);
	if (__count > sbts->max_notifier) {
		cn_dev_core_err(core, "the number of notifier arrives the maximum(%u)",
				sbts->max_notifier);
		ret = -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		goto err;
	}

	/*stage warning*/
	if ((__count + STAGE_NOTIFIER_NUM) % MAX_NOTIFIER_NUM == 0) {
		notifier_mgr->stage = (__count + STAGE_NOTIFIER_NUM) / MAX_NOTIFIER_NUM;
	}
	if (__count == notifier_mgr->stage * MAX_NOTIFIER_NUM) {
		cn_dev_core_warn(core, "notifier count %lld reach stage %lld upper limit, raise stage num.",
			__count, notifier_mgr->stage);
		notifier_mgr->stage++;
	}

	notifier = cn_numa_aware_kzalloc(core, sizeof(struct notifier), GFP_KERNEL);
	if (!notifier) {
		cn_dev_core_err(core, "malloc notifier mem failed");
		ret = -ENOMEM;
		goto err;
	}

	notifier->user  = user;
	notifier->flags = flags;
	notifier->dis_timing_sw = CN_NOTIFIER_DISTIM_SW(flags);
	notifier->dis_timing_all = CN_NOTIFIER_DISTIM_ALL(flags);
	notifier->exception_infect = CN_NOTIFIER_INFECT_QUEUE(flags);
	/* ipc enable flag will check in ipchandle create */
	notifier->ipchandle = NULL;
	notifier->active_info = NULL;
	notifier->core = core;
	notifier->eid = __sync_fetch_and_add(&g_notifier_ticket, 1);
	notifier->place_queue = ~(0ULL);
	notifier->host_place_time = 0;
	kref_init(&notifier->ref_cnt);

	if (notifier->dis_timing_all) {
		goto finish;
	}
	/* may not alloc shm if disable timing */
	ret = sbts_shm_alloc(notifier_mgr->shm_mgr, core,
			&host_vaddr, &dev_vaddr);
	if (ret) {
		cn_dev_core_err(core, "alloc notifier ret share memory failed");
		ret = -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		goto alloc_share_err;
	}
	notifier->dev_vaddr = dev_vaddr;
	hpas_init(&notifier->ack, (struct hpq_notifier_ack_as *) host_vaddr);

finish:
	*ppnotifier = notifier;

	return ret;

alloc_share_err:
	cn_kfree(notifier);
err:
	__sync_fetch_and_sub(&notifier_mgr->count, 1);
	return ret;
}

static void destroy_notifier_host_env(
		struct notifier_mgr *notifier_mgr,
		struct notifier *notifier)
{
	if (false == notifier->dis_timing_all)
		sbts_shm_free(notifier_mgr->shm_mgr, notifier->dev_vaddr);

	__sync_fetch_and_sub(&notifier_mgr->count, 1);

	if (notifier->ipchandle)
		notifier_ipchandle_put(notifier->ipchandle);

	cn_kfree(notifier);
}

/* check ipchandle in rbtree with same user
 * erase from rbtree and put refcnt
 * */
static void notifier_ipchandle_release_do_exit(
		u64 user, struct notifier_mgr *notifier_mgr,
		struct cn_core_set *core)
{
	struct notifier_ipchandle *ipchandle, *n;
	struct sbts_set_container_st destroy_container;

	sbts_set_container_init(&destroy_container);

	down_write(&g_ipchandle_rwsem);
	sbts_set_for_each_entry_safe(ipchandle, n, &notifier_ipchandle_container, iter) {
		if (ipchandle->user == user) {
			if (ipchandle->user_id != cn_core_get_fp_id((struct file *)user)) {
				cn_dev_core_err(core, "ipc %#llx[%llu] user[%#llx] id %llu not equal %llu",
						(u64)ipchandle, ipchandle->seq, user, ipchandle->user_id,
						cn_core_get_fp_id((struct file *)user));
				continue;
			}
			sbts_set_erase(&notifier_ipchandle_container, ipchandle, iter);
			(void)sbts_set_insert(&destroy_container, ipchandle,
					__notifier_ipchandle_compare, iter);
		}
	}
	up_write(&g_ipchandle_rwsem);

	sbts_set_for_each_entry_safe(ipchandle, n, &destroy_container, iter) {
		sbts_set_erase(&destroy_container, ipchandle, iter);
		notifier_ipchandle_put(ipchandle);
	}
}

#if 0
TODO do this release resource check later.
/* check ipchandle in rbtree with same core
 * erase from rbtree and put refcnt
 *
 * the rbtree notifier_ipchandle_container should nothing on it
 * when device remove normally because we call ** before do device remove.
 *
 * this function only use for device is in heartbeat.
 * if current device in heartbeat
 *
 *
 * */
static void notifier_ipchandle_release_exit(
		u64 user, struct notifier_mgr *notifier_mgr,
		struct cn_core_set *core)
{
	struct notifier_ipchandle *ipchandle, *n;
	struct sbts_set_container_st destroy_container;

	sbts_set_container_init(&destroy_container);

	down_write(&g_ipchandle_rwsem);
	sbts_set_for_each_entry_safe(ipchandle, n, &notifier_ipchandle_container, iter) {
		if (ipchandle->core == core) {
				cn_dev_core_err("ipc %#llx[%llu] user[%#llx] id %llu not equal %llu",
						(u64)ipchandle, ipchandle->seq, user, ipchandle->user_id,
						cn_core_get_fp_id((struct file *)user));
			sbts_set_erase(&notifier_ipchandle_container, ipchandle, iter);
			(void)sbts_set_insert(&destroy_container, ipchandle,
					__notifier_ipchandle_compare, iter);
		}
	}
	up_write(&g_ipchandle_rwsem);

	sbts_set_for_each_entry_safe(ipchandle, n, &destroy_container, iter) {
		sbts_set_erase(&destroy_container, ipchandle, iter);
		notifier_ipchandle_put(ipchandle);
	}
}
#endif

int notifier_do_exit(u64 user, struct notifier_mgr *notifier_mgr)
{
	struct notifier *notifier = NULL;
	struct notifier *tmp = NULL;
	struct cn_core_set *core = notifier_mgr->core;
	struct sbts_set_container_st *ncontainer = &notifier_mgr->container;
	struct sbts_set_container_st destroy_container;

	sbts_set_container_init(&destroy_container);
	write_lock(&notifier_mgr->rwlock);
	sbts_set_for_each_entry_safe(notifier, tmp, ncontainer, iter) {
		if (notifier->user == user) {
			notifier->destroy = 1;
			sbts_set_erase(ncontainer, notifier, iter);
			(void)sbts_set_insert(&destroy_container, notifier,
					__notifier_compare, iter);
		}
	}
	write_unlock(&notifier_mgr->rwlock);

	sbts_set_for_each_entry_safe(notifier, tmp, &destroy_container, iter) {
		cn_dev_core_debug(core, "notifier :%px resource start to free",
				notifier);
		sbts_set_erase(&destroy_container, notifier, iter);
		notifier_put(notifier_mgr, notifier);
	}

	notifier_ipchandle_release_do_exit(user, notifier_mgr, core);

	return 0;
}

static inline __u64
fill_desc_create_notifier(__u64 version, __u64 user, int flags,
		struct comm_ctrl_desc *ctrl_desc, struct notifier *notifier,
		struct cn_core_set *core)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cd_create_notifier *priv = NULL;
	/* version relate structure */
	struct ctrl_desc_data_v1 *data = NULL;

	switch (version) {
	case SBTS_VERSION:
		ctrl_desc->version = version;
		/* get ctrl desc data */
		data                = (struct ctrl_desc_data_v1 *)ctrl_desc->data;
		data->type          = CREATE_NOTIFIER;
		data->user          = cpu_to_le64(user);
		/* get cd_create_notifier structure */
		priv                = (struct cd_create_notifier *)data->priv;
		priv->flag          = cpu_to_le64(flags);
		priv->dev_ret_iova  = cpu_to_le64(notifier->dev_vaddr);

		/* calculate payload_size: version + sta + ctrl + data + priv */
		payload_size = sizeof(struct comm_ctrl_desc);
		break;

	default:
		cn_dev_core_err(core, "version not match!");
	}

	return payload_size;
}

static int create_notifier_device_env(
		struct notifier_mgr *notifier_mgr,
		struct notifier *notifier,
		int flags, __u64 version,
		u64 user)
{
	int ret = 0;
	struct ctrl_desc_data_v1 *data = NULL;
	struct cd_create_notifier *priv = NULL;
	__u64 payload_size = 0;
	struct notifier_device_info *dev_info = NULL;
	struct sched_manager *sched_mgr = notifier_mgr->sched_mgr;
	struct cn_core_set *core = (struct cn_core_set *)notifier_mgr->core;
	struct comm_ctrl_desc tx_desc;
	struct comm_ctrl_desc rx_desc;

	dev_info = cn_numa_aware_kzalloc(core, sizeof(struct notifier_device_info), GFP_KERNEL);
	if (!dev_info) {
		cn_dev_core_err(core, "alloc mem fail");
		return -ENOMEM;
	}
	payload_size = fill_desc_create_notifier(version, (__u64)user, flags,
			&tx_desc, notifier, core);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto out;
	}

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
				(__u64)user, (__u64)payload_size);
	if (ret || rx_desc.sta) {
		cn_dev_core_err(core, "create notifier fail");
		ret = -CN_SBTS_ERROR_IOCTL_FAILED;
		goto out;
	}

	/* recv notifier eid from device */
	data = (struct ctrl_desc_data_v1 *)rx_desc.data;
	priv = (struct cd_create_notifier *)data->priv;
	dev_info->dev_eid = priv->dev_eid;
	dev_info->notifier_mgr = notifier_mgr;

	notifier->dev_info = dev_info;

	return 0;
out:
	cn_kfree(dev_info);

	return ret;
}

static inline __u64
fill_desc_destroy_notifier(__u64 version, __u64 user,
		struct comm_ctrl_desc *ctrl_desc,
		struct notifier_device_info *dev_info,
		struct cn_core_set *core)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cd_destroy_notifier *priv = NULL;
	/* version relate structure */
	struct ctrl_desc_data_v1 *data = NULL;

	switch (version) {
	case SBTS_VERSION:
		ctrl_desc->version = version;
		/* get ctrl desc data */
		data              = (struct ctrl_desc_data_v1 *)ctrl_desc->data;
		data->type        = DESTROY_NOTIFIER;
		data->user        = cpu_to_le64(user);
		/* get cd_destroy_notifier structure */
		priv              = (struct cd_destroy_notifier *)data->priv;
		priv->dev_eid     = cpu_to_le64(dev_info->dev_eid);
		priv->waiter_nr   = cpu_to_le64(dev_info->waiter_nr);
		priv->capturer_nr = cpu_to_le64(dev_info->capturer_nr);

		/* calculate payload_size: version + sta + ctrl + data + priv */
		payload_size = sizeof(struct comm_ctrl_desc);

		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

int destroy_notifier_device_env(
		struct notifier_mgr *notifier_mgr,
		struct notifier_device_info *dev_info,
		struct hpq_notifier_ack *notifier_ack,
		u64 user)
{
	int ret = 0;
	int cnt = DESTROY_TIMEOUT;
	__u64 payload_size = 0;
	struct sched_manager *sched_mgr = notifier_mgr->sched_mgr;
	struct cn_core_set *core = (struct cn_core_set *)notifier_mgr->core;
	struct comm_ctrl_desc tx_desc;
	struct comm_ctrl_desc rx_desc;

	/* no need to judge the validation of payload_size,
	 * because version is always right
	 */
	payload_size = fill_desc_destroy_notifier(SBTS_VERSION, user,
			&tx_desc, dev_info, core);

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
				user, (__u64)payload_size);
	if (ret || rx_desc.sta) {
		cn_dev_core_err(core, "destroy notifier dev %llu failed", dev_info->dev_eid);
		ret = -CN_SBTS_ERROR_IOCTL_FAILED;
		goto out;
	}
	if (!notifier_ack) {
		ret = 0;
		goto out;
	}

	while (--cnt) {
		struct hpq_notifier_ack_desc ack = {0};

		hpas_read(notifier_ack, &ack);
		if (ack.last_val == ~0ULL) {
			ret = 0;
			cn_dev_core_debug(core, "destroy notifier dev %llu done",
					dev_info->dev_eid);
			break;
		}

		ret = sbts_pause(core, 20000, 20000);
		if (ret) {
			cn_dev_core_err(core, "destroy notifier dev %llx kill by reset",
					dev_info->dev_eid);
			break;
		}
	}

	if (!cnt) {
		cn_dev_core_err(core, "destroy notifier dev %llu timeout",
				dev_info->dev_eid);
		ret = -ETIMEDOUT;
	}
out:
	cn_kfree(dev_info);

	return ret;
}

static int destroy_notifier(
		struct notifier_mgr *notifier_mgr,
		struct notifier *notifier,
		u64 user)
{
	if (NULL == notifier->ipchandle)
		destroy_notifier_device_env(notifier_mgr, notifier->dev_info,
				notifier->dis_timing_all ? NULL : &notifier->ack, user);

	__notifier_active_info_destroy(notifier);

	destroy_notifier_host_env(notifier_mgr, notifier);

	return 0;
}

static inline void __notifier_get(struct notifier *notifier)
{
	if (!kref_get_unless_zero(&notifier->ref_cnt)) {
		cn_dev_warn("notifier(0x%px) dev_eid %#016llx", notifier, notifier->dev_info->dev_eid);
		cn_dev_warn("notifier ref cnt is invalid");
		WARN_ON(1);
	}
}

struct notifier *notifier_get(struct notifier_mgr *notifier_mgr,
		u64 eid, cn_user user)
{
	struct notifier *notifier = NULL;

	if (unlikely(!notifier_mgr)) {
		cn_dev_err("param is invalid");
		return NULL;
	}

	read_lock(&notifier_mgr->rwlock);
	notifier = __notifier_validate(notifier_mgr, eid);
	if (!notifier) {
		goto notifier_err;
	}

	if (notifier->destroy) {
		notifier = NULL;
		goto notifier_err;
	}

	if (user && (notifier->user != (u64)user)) {
		notifier = NULL;
		goto notifier_err;
	}

	__notifier_get(notifier);

notifier_err:
	read_unlock(&notifier_mgr->rwlock);

	return notifier;
}

void notifier_release(struct kref *kref)
{
	struct notifier *notifier = container_of(kref, struct notifier, ref_cnt);

	cn_dev_debug("notifier(%px) eid %#016llx", notifier, notifier->dev_info->dev_eid);
	cn_dev_debug("notifier release");
}

int notifier_put(struct notifier_mgr *notifier_mgr, struct notifier *notifier)
{
	int ret = 0;

	if (kref_put(&notifier->ref_cnt, notifier_release)) {
		ret = destroy_notifier(notifier_mgr, notifier, notifier->user);
	}

	return ret;
}

int notifier_capturer_update(
		struct notifier_mgr *notifier_mgr,
		u64 eid, u64 user, u64 update_val)
{
	struct cn_core_set *core = (struct cn_core_set *)notifier_mgr->core;
	struct notifier *notifier = NULL;
	int ret = 0;

	notifier = notifier_get(notifier_mgr, eid, (cn_user)user);
	if (!notifier) {
		cn_dev_core_err(core, "notifier %#llx is invalid", eid);
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}

	ret = __notifier_capturer_update(notifier, update_val);
	notifier_put(notifier_mgr, notifier);

	return ret;
}

int notifier_capturer_reset(
		struct notifier_mgr *notifier_mgr,
		u64 eid, u64 user)
{
	struct cn_core_set *core = (struct cn_core_set *)notifier_mgr->core;
	struct notifier *notifier = NULL;
	struct notifier_active_info *notifier_ainfo = NULL;

	notifier = notifier_get(notifier_mgr, eid, (cn_user)user);
	if (!notifier) {
		cn_dev_core_err(core, "notifier %#llx is invalid", eid);
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}

	notifier_ainfo = notifier->active_info;
	mutex_lock(&notifier_ainfo->mutex);
	notifier->dev_info->capturer_nr = 0;
	notifier->dev_info->last_val = 0;
	mutex_unlock(&notifier_ainfo->mutex);

	notifier_put(notifier_mgr, notifier);

	return 0;
}

/* create a notifier handle for user
 * 1. create host handle info and alloc memory.
 * 2. send param and create device handle.
 * 3. create ipchandle if need.
 * 4. insert notifier to rbtree
 * */
int
cn_create_notifier(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	int ret = 0;
	struct sbts_create_notifier param;
	struct notifier *notifier = NULL;
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
					struct sbts_create_notifier))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}
	/* 1. create host notifier */
	ret = create_notifier_host_env(notifier_mgr, &notifier,
			param.flags, (u64)user);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "create host notifier failed!");
		return ret;
	}
	/* 2. create active info */
	ret = __notifier_active_info_create(notifier);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "create notifier active info failed");
		/* if fail, only destroy host info */
		goto active_info_fail;
	}
	/* 3. create device notifier */
	ret = create_notifier_device_env(notifier_mgr, notifier,
			param.flags, param.version, (u64)user);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "create device notifier failed");
		goto dev_create_fail;
	}
	/* 4. create ipc handle if need */
	ret = notifier_ipchandle_create(core, notifier_mgr, notifier);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "create ipchandle fail");
		goto ipchandle_fail;
	}

	param.hnotifier = notifier->eid;
	if (copy_to_user((void *)args, (void *)&param, sizeof(
					struct sbts_create_notifier))) {
		cn_dev_core_err(core, "<CREATE_NOTIFIER> copy parameters to user failed!");
		ret = -EFAULT;
		goto cpy_user_fail;
	}
	/* add to rbtree, lock inside */
	notifier_add(notifier_mgr, notifier);

	cn_dev_core_debug(core, "create notifier finished!");
	return 0;

cpy_user_fail:
ipchandle_fail:
	if (NULL == notifier->ipchandle)
		destroy_notifier_device_env(notifier_mgr, notifier->dev_info,
				notifier->dis_timing_all ? NULL : &notifier->ack, (u64)user);
dev_create_fail:
	__notifier_active_info_destroy(notifier);
active_info_fail:
	destroy_notifier_host_env(notifier_mgr, notifier);
	return ret;
}

int
cn_destroy_notifier(struct sbts_set *sbts,
		void *args,
		cn_user user)

{
	int ret = 0;
	struct sbts_destroy_notifier param;
	struct notifier *notifier = NULL;
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
					struct sbts_destroy_notifier))) {
		cn_dev_core_err(core, "copy parameters failed!");
		ret = -EFAULT;
		return ret;
	}

	write_lock(&notifier_mgr->rwlock);
	notifier = __notifier_validate(notifier_mgr, param.hnotifier);
	if (notifier && (notifier->user == (u64)user)) {
		cn_dev_core_debug(core, "destroy notifier %px, eid %#016llx", notifier, notifier->eid);
		notifier->destroy = 1;
		notifier_del(notifier_mgr, notifier);
	} else {
		cn_dev_core_err(core, "destroy notifier %px failed", notifier);
		ret = -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}
	write_unlock(&notifier_mgr->rwlock);

	if (!ret) {
		ret = notifier_put(notifier_mgr, notifier);
	}

	cn_dev_core_debug(core, "destroy notifier finished!");
	return ret;
}

#define CN_NOTIFIER_IPC_HANDLE_SEQ 0
#define CN_NOTIFIER_IPC_HANDLE_PTR 1
#define CN_NOTIFIER_IPC_CORE_IDX   2
#define CN_NOTIFIER_IPC_USER_IDX   3

int
cn_notifier_ipc_gethandle(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	int ret = 0;
	struct sbts_ipc_notifier param;
	struct notifier *notifier = NULL;
	struct notifier_ipchandle *ipchandle;
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
					struct sbts_ipc_notifier))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	notifier = notifier_get(notifier_mgr, param.hnotifier, user);
	if (!notifier) {
		cn_dev_core_err(core, "notifier %#llx is invalid", param.hnotifier);
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}
	ipchandle = notifier->ipchandle;
	if (!ipchandle) {
		cn_dev_core_err(core, "notifier %#llx is not support ipc", param.hnotifier);
		ret = -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
		goto check_fail;
	}

	if (ipchandle->user_id != cn_core_get_fp_id((struct file *)user)) {
		cn_dev_core_warn(core, "notifier create by handle can not get new handle");
		ret = -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
		goto check_fail;
	}

	param.ipchandle[CN_NOTIFIER_IPC_HANDLE_SEQ] = ipchandle->seq;
	param.ipchandle[CN_NOTIFIER_IPC_HANDLE_PTR] = (__u64)ipchandle;
	param.ipchandle[CN_NOTIFIER_IPC_CORE_IDX] = (__u64)core->idx;
	param.ipchandle[CN_NOTIFIER_IPC_USER_IDX] = ipchandle->user_id;

	if (copy_to_user((void *)args, (void *)&param, sizeof(
					struct sbts_ipc_notifier))) {
		cn_dev_core_err(core, "copy parameters to user failed!");
		ret = -EFAULT;
	}
check_fail:
	notifier_put(notifier_mgr, notifier);
	cn_dev_core_debug(core, "get notifier ipc finished!");

	return ret;
}

static struct notifier_ipchandle *__check_ipchandle_valid_and_get(
		struct cn_core_set *core,
		struct sbts_ipc_notifier param,
		u64 user)
{
	struct notifier_ipchandle *ipchandle;

	if (param.ipchandle[CN_NOTIFIER_IPC_USER_IDX] == cn_core_get_fp_id((struct file *)user)) {
		cn_dev_core_warn(core, "can not openhandle from original process ");
		return NULL;
	}

	ipchandle = notifier_ipchandle_get(param.ipchandle[CN_NOTIFIER_IPC_HANDLE_SEQ],
			(struct notifier_ipchandle *)param.ipchandle[CN_NOTIFIER_IPC_HANDLE_PTR]);
	if (!ipchandle) {
		cn_dev_core_err_limit(core, "cant find ipchandle by %#llx %llu",
				param.ipchandle[CN_NOTIFIER_IPC_HANDLE_PTR],
				param.ipchandle[CN_NOTIFIER_IPC_HANDLE_SEQ]);
		return NULL;
	}
	if (ipchandle->user_id == cn_core_get_fp_id((struct file *)user)) {
		cn_dev_core_warn(core, "can not openhandle from original process ");
		notifier_ipchandle_put(ipchandle);
		return NULL;
	}
	return ipchandle;
}

static int __alloc_device_info_ipc_openhandle(
		struct cn_core_set *core,
		struct notifier_mgr *notifier_mgr,
		struct notifier *notifier,
		struct notifier_ipchandle *ipchandle,
		u64 user)
{
	int ret = 0;
	struct notifier_active_info *active_info = ipchandle->active_info;

	mutex_lock(&active_info->mutex);
	if (ipchandle->dev_info[core->idx]) {
		notifier->dev_info = ipchandle->dev_info[core->idx];
		goto out;
	}

	ret = create_notifier_device_env(notifier_mgr, notifier,
			ipchandle->flags, SBTS_VERSION, user);
	if (unlikely(ret)) {
		goto out;
	}
	/* save the new dev info from notifier */
	ipchandle->dev_info[core->idx] = notifier->dev_info;
out:
	mutex_unlock(&active_info->mutex);
	return ret;
}

int
cn_notifier_ipc_openhandle(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	int ret = 0;
	struct sbts_ipc_notifier param;
	struct notifier *notifier = NULL;
	struct notifier_ipchandle *ipchandle = NULL;
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
					struct sbts_ipc_notifier))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}
	/* after get handle success if create new notifier fail need put it */
	ipchandle = __check_ipchandle_valid_and_get(core, param, (u64)user);
	if (!ipchandle) {
		cn_dev_core_debug(core, "input ipchandle is invalid");
		return -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
	}

	/* create a new notifier and save current info in it */
	/* 1. create host notifier */
	ret = create_notifier_host_env(notifier_mgr, &notifier,
			ipchandle->flags, (u64)user);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "create new notifier env failed!");
		goto create_new_fail;
	}
	notifier->ipchandle = ipchandle;
	notifier->active_info = ipchandle->active_info;

	/* 2. create device env if not exist */
	ret = __alloc_device_info_ipc_openhandle(core, notifier_mgr,
			notifier, ipchandle, (u64)user);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "create new device notifier failed");
		goto create_dev_fail;
	}

	param.hnotifier = notifier->eid;
	if (copy_to_user((void *)args, (void *)&param, sizeof(
					struct sbts_ipc_notifier))) {
		cn_dev_core_err(core, "copy parameters to user failed!");
		ret = -EFAULT;
		goto cpy_user_fail;
	}
	/* add to rbtree, lock inside */
	notifier_add(notifier_mgr, notifier);

	cn_dev_core_debug(core, "open notifier ipc finished!");
	return 0;
cpy_user_fail:
	/* we will not free the device env which will destroy when ipchandle free */
create_dev_fail:
	destroy_notifier_host_env(notifier_mgr, notifier);
create_new_fail:
	notifier_ipchandle_put(ipchandle);
	return ret;
}

static int __dev_free_compare(
		struct notifier_dev_free_s *r,
		struct notifier_dev_free_s *l)
{
	u64 rkey = r->ticket;
	u64 lkey = l->ticket;

	if (rkey < lkey) {
		return -1;
	}

	if (rkey > lkey) {
		return 1;
	}

	return 0;
}

int notifier_dev_free_create(struct sbts_set *sbts,
		struct notifier_active_info *active_info, u64 *seq)
{
	struct cn_core_set *core = sbts->core;
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct notifier_dev_free_s *df_info = NULL, *n;
	int ret;

	df_info = kmem_cache_zalloc(notifier_mgr->df_mem, GFP_KERNEL);
	if (!df_info) {
		cn_dev_core_err(core, "alloc for df info");
		return -ENOMEM;
	}
	ret = queue_ack_get(active_info->place_q_ack);
	if (ret) {
		cn_dev_core_err(core, "get queue ack failed");
		goto get_fail;
	}

	df_info->ticket = __sync_add_and_fetch(&notifier_mgr->df_ticket, 1);
	df_info->ack_info = active_info->place_q_ack;

	mutex_lock(&notifier_mgr->df_mutex);
	n = sbts_set_insert(&notifier_mgr->df_container, df_info,
			__dev_free_compare, iter);
	mutex_unlock(&notifier_mgr->df_mutex);
	if (!n) {
		cn_dev_core_err(core, "insert to df failed");
		ret = -ENOMEM;
		goto insert_fail;
	}

	*seq = df_info->ticket;

	cn_dev_core_debug(core, "create df[%llu] q[%llu] info %llx ",
			df_info->ticket, active_info->place_q_idx, (u64)active_info->place_q_ack);

	return 0;
insert_fail:
	queue_ack_put(active_info->place_q_ack);
get_fail:
	kmem_cache_free(notifier_mgr->df_mem, df_info);
	return ret;
}

void notifier_dev_free_release(struct sbts_set *sbts, u64 seq)
{
	struct notifier_mgr *notifier_mgr = sbts->notifier_mgr;
	struct notifier_dev_free_s *df_info = NULL;
	struct notifier_dev_free_s obj = { .ticket = seq };

	mutex_lock(&notifier_mgr->df_mutex);
	df_info = sbts_set_find(&notifier_mgr->df_container, &obj,
			__dev_free_compare, iter);
	if (!df_info) {
		mutex_unlock(&notifier_mgr->df_mutex);
		return;
	}
	sbts_set_erase(&notifier_mgr->df_container, df_info, iter);
	mutex_unlock(&notifier_mgr->df_mutex);

	cn_dev_core_debug(sbts->core, "free df[%llu] info %llx ",
			df_info->ticket, (u64)df_info->ack_info);

	queue_ack_put(df_info->ack_info);

	kmem_cache_free(notifier_mgr->df_mem, df_info);
}

static int notifier_manager_df_init(struct cn_core_set *core,
		struct notifier_mgr *notifier_mgr)
{
	char kmem_name[64];

	if (!sbts_notifier_feature_available(core))
		return 0;

	sprintf(kmem_name, "cn_notifier_df%d", core->idx);
	notifier_mgr->df_mem = kmem_cache_create(
			kmem_name,
			sizeof(struct notifier_dev_free_s),
			64,
			SLAB_HWCACHE_ALIGN, NULL);
	if (!notifier_mgr->df_mem) {
		cn_dev_core_err(core, "alloc cache memory failed");
		return -ENOMEM;
	}
	notifier_mgr->df_ticket = 0;
	sbts_set_container_init(&notifier_mgr->df_container);
	mutex_init(&notifier_mgr->df_mutex);

	return 0;
}

static void notifier_manager_df_exit(struct notifier_mgr *notifier_mgr)
{
	struct cn_core_set *core = notifier_mgr->core;
	struct notifier_dev_free_s *df_info, *n;
	struct sbts_set_container_st *container = &notifier_mgr->df_container;

	if (!notifier_mgr->df_mem)
		return;

	sbts_set_for_each_entry_safe(df_info, n, container, iter) {
		cn_dev_core_warn(core, "some df_info[%llu] need free", df_info->ticket);
		queue_ack_put(df_info->ack_info);
		sbts_set_erase(container, df_info, iter);
		kmem_cache_free(notifier_mgr->df_mem, df_info);
	}

	kmem_cache_destroy(notifier_mgr->df_mem);
}

int notifier_manager_init(struct notifier_mgr **ppnotifier_mgr, struct cn_core_set *core)
{
	struct notifier_mgr *pnotifier_mgr = NULL;
	struct sbts_set *sbts_set = NULL;
	struct notifier *notifier = NULL;
	int ack_buf_size = ALIGN(sizeof(*(notifier->ack.d_as)), 64);
	int ret;

	sbts_set = core->sbts_set;
	pnotifier_mgr = cn_numa_aware_kzalloc(core, sizeof(struct notifier_mgr), GFP_KERNEL);
	if (!pnotifier_mgr) {
		cn_dev_core_err(core, "malloc notifier manager failed");
		return -ENOMEM;
	}

	sbts_set_container_init(&pnotifier_mgr->container);
	rwlock_init(&pnotifier_mgr->rwlock);
	pnotifier_mgr->core = core;
	pnotifier_mgr->sched_mgr = sbts_set->sched_manager;
	pnotifier_mgr->count = 0;
	pnotifier_mgr->stage = 1;

	ret = sbts_shm_init(&pnotifier_mgr->shm_mgr, core,
			sbts_set->max_notifier, ack_buf_size);
	if (ret) {
		cn_dev_core_err(core, "notifier share mem init failed");
		goto shm_init_fail;
	}
	ret = notifier_manager_df_init(core, pnotifier_mgr);
	if (ret) {
		cn_dev_core_err(core, "notifier dev free init failed");
		goto df_init_fail;
	}

	*ppnotifier_mgr = pnotifier_mgr;
	return 0;
df_init_fail:
	sbts_shm_exit(pnotifier_mgr->shm_mgr, core);
shm_init_fail:
	cn_kfree(pnotifier_mgr);
	return ret;
}


void notifier_manager_exit(struct notifier_mgr *notifier_mgr)
{
	struct cn_core_set *core = NULL;
	struct sbts_set *sbts_set = NULL;

	if (!notifier_mgr) {
		cn_dev_err("notifier manager is null");
		return;
	}
	core = notifier_mgr->core;
	sbts_set = core->sbts_set;

	if (notifier_mgr->count != 0) {
		cn_dev_core_err(core, "some notifiers are working, could not be destroyed");
		return;
	}

	notifier_manager_df_exit(notifier_mgr);

	sbts_shm_exit(notifier_mgr->shm_mgr, core);

	cn_kfree(notifier_mgr);
	sbts_set->notifier_mgr = NULL;
}
