/*
 * sbts/topo/sbts_topo.h
 *
 * NOTICE:
 * Copyright (C) 2023 Cambricon, Inc. All rights reserved.
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

#ifndef __SBTS_TOPO_SBTS_TOPO_H
#define __SBTS_TOPO_SBTS_TOPO_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "../sbts_set.h"
#include "../sbts.h"
#include "cndrv_sbts.h"
#include "core/cndrv_ioctl.h"
#include "sbts/queue.h"

//#define TOPO_DEBUG

#ifdef TOPO_DEBUG
#define TOPO_DEBUG_LOG_CORE(core, string, arg...)			\
	cn_dev_core_info(core, string, ##arg)
#define TOPO_DEBUG_LOG(string, arg...)			\
	cn_dev_info(string, ##arg)
#else
#define TOPO_DEBUG_LOG_CORE(core, string, arg...) do {} while (0)
#define TOPO_DEBUG_LOG(core, string, arg...) do {} while (0)

#endif


struct cn_core_set;
struct sched_manager;
struct queue;
struct notifier;

struct dev_topo_inner_queue {
	struct queue *queue;
	struct notifier *notifier;
	/* total task in current queue with current dev topo */
	u64 queue_total_task;
	u64 notifier_place;
};
/* dev topo struct
 * */
struct sbts_dev_topo_struct {
	struct sbts_set *sbts;

	u64 user;
	u64 dev_topo_id;

	int dev_id;
	int tgid;

	u32 node_nums;

	u32 queue_nums;
	struct dev_topo_inner_queue *queues;
	struct queue *leader_queue;

	/* iter for rbtree in sbts topo priv */
	struct sbts_set_iter_st iter;

	struct kref ref_cnt;

	bool is_destroy;

	u64 trigger_send;
	u64 param_send;
	u64 node_send;
};

/* save in sbts_priv which in user fp_priv */
struct sbts_topo_fp_priv {
	struct sbts_fp_priv *sbts_priv;

	/* save each dev topo for current user fp */
	struct sbts_set_container_st container;
	/* lock for container */
	rwlock_t rwlock;
	u64 topo_nums;

	/* list with topo manager for debug */
	struct list_head entry;
};

/*
 * manager priv_head list use to save all current device topo_priv to dump debug info.
 *
 * mutex lock:
 *      priv_head  -->  topo_fp_priv->entry  -->  topo_fp_priv->entry -->  priv_head
 *             priv_rwlock:  |           priv_rwlock:  |
 *                       container                 container
 *                       /       \                 /       \
 *                 dev_topo     dev_topo       dev_topo     dev_topo
 *
 * */
struct sbts_topo_manager {
	struct sched_manager *sched_mgr;
	struct cn_core_set *core;
	struct sbts_set *sbts;

	struct mutex lock;
	struct list_head priv_head;
};

struct sbts_dev_topo_struct *sbts_topo_get(
		u64 dev_topo_id, u64 user);

void sbts_topo_put(struct sbts_dev_topo_struct *dtopo);

int sbts_task_fill_topo_info(struct sbts_set *sbts,
		struct sbts_queue_invoke_task *user_param,
		struct sbts_dev_topo_struct *dtopo,
		struct task_desc_data_v1 *task_desc,
		u32 *priv_offset, u32 *topo_offset);

int sbts_topo_invoke_ticket_update(struct sbts_set *sbts,
		u64 user, struct sbts_dev_topo_struct *dtopo,
		struct queue *user_queue);

int sbts_topo_do_exit(u64 user, struct sbts_topo_manager *topo_manager);

int sbts_topo_priv_init(struct sbts_set *sbts,
		struct sbts_fp_priv *sbts_priv);

void sbts_topo_priv_exit(struct sbts_fp_priv *sbts_priv);

int sbts_topo_manager_init(
		struct sbts_topo_manager **ppmanager,
		struct cn_core_set *core);
void sbts_topo_manager_exit(struct sbts_topo_manager *topo_manager);

static inline int sbts_queue_task_topo_cmd(struct sbts_queue_invoke_task *param)
{
	return param->dev_topo_cmd;
}

static inline int sbts_topo_check_is_topo_task(u16 dev_topo_cmd)
{
	if (dev_topo_cmd == DEV_TOPO_TASK_TYPE_NORMAL)
		return 0;

	return 1;
}

static inline bool sbts_topo_check_is_topo_param_task(u16 dev_topo_cmd)
{
	if (dev_topo_cmd == DEV_TOPO_TASK_TYPE_PARAM)
		return true;

	return false;
}

static inline void sbts_topo_update_push_num(
		struct sbts_dev_topo_struct *dtopo,
		struct queue *queue, u16 dev_topo_cmd)
{
	if (likely(!dtopo))
		return;

	if (dev_topo_cmd == DEV_TOPO_TASK_TYPE_INVOKE) {
		__sync_fetch_and_add(&dtopo->trigger_send, 1);
		return;
	}

	if (dev_topo_cmd == DEV_TOPO_TASK_TYPE_PARAM) {
		__sync_fetch_and_add(&dtopo->param_send, 1);
		__sync_fetch_and_add(&queue->topo_param_cnt, 1);
		return;
	}

	if (dev_topo_cmd == DEV_TOPO_TASK_TYPE_CREATE) {
		__sync_fetch_and_add(&dtopo->node_send, 1);
		/* created task also need free param */
		__sync_fetch_and_add(&queue->topo_param_cnt, 1);
		__queue_topo_updating(queue);
		return;
	}
}

#endif /* __SBTS_TOPO_SBTS_TOPO_H */
