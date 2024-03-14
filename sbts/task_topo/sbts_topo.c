/*
 * sbts/topo/sbts_topo.c
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

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/fs.h>


#include "cndrv_core.h"
#include "cndrv_ioctl.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "../sbts.h"
#include "../sbts_set.h"
#include "../queue.h"
#include "../notifier.h"
#include "cndrv_debug.h"
#include "sbts_topo.h"


/* ticket for each Topo */
static u64 g_dev_topo_seq;

/* struct cd_dev_topo_ctrl cmd_type */
enum task_topo_cd_type {
	TASK_TOPO_CTRL_CREATE = 0,
	TASK_TOPO_CTRL_DESTROY,
};

/* struct sbts_task_topo_cmd -> cmd_type */
enum task_topo_cmd_type {
	SBTS_TOPO_CMD_DEV_CREATE,
	SBTS_TOPO_CMD_DEV_DESTROY,
	SBTS_TOPO_CMD_QUEUE_TICKET_UPDATE,
	SBTS_TOPO_CMD_QUEUE_TICKET_RESET,
	SBTS_TOPO_CMD_DEV_TOPO_DEBUG,
	SBTS_TOPO_CMD_NUM,
};

/* struct sbts_task_topo_cmd -> param_addr */
struct topo_user_queue_info {
	__u64 hqueue;
	__u64 hnotifier;
	__u64 queue_task;
	__u64 notifier_num;
};

#define TOPO_DUMP_INFO_ALL    (~0ULL)
static void __dev_topo_queue_dump(struct dev_topo_inner_queue *queues, u32 nums)
{
	int i;

	SBTS_DBG_OUT("  Q INFO:");
	for (i = 0; i < nums; i++) {
		SBTS_DBG_OUT("    [%d] Qid:%llu Nid:%llu task:%llu place:%llu",
				i, queues[i].queue->dev_sid, queues[i].notifier->dev_info->dev_eid,
				queues[i].queue_total_task, queues[i].notifier_place);
	}
}

static void __dev_topo_info_dump(struct sbts_dev_topo_struct *dtopo)
{

	SBTS_DBG_OUT(" DevTopo[%llu]dev[%d] user[%#llx]tgid[%d] nodes:%u isd:%d qnums:%u",
			dtopo->dev_topo_id, dtopo->dev_id, dtopo->user,
			dtopo->tgid, dtopo->node_nums,
			dtopo->is_destroy, dtopo->queue_nums);
	__dev_topo_queue_dump(dtopo->queues, dtopo->queue_nums);
}

static void topo_find_dev_topo_info_dump(
		struct sbts_topo_manager *manager,
		struct sbts_topo_fp_priv *topo_priv,
		u64 dev_topo_id)
{
	struct sbts_dev_topo_struct *dtopo;
	int dev_all = 0;

	dev_all = (dev_topo_id == TOPO_DUMP_INFO_ALL) ? 1 : 0;

	read_lock(&topo_priv->rwlock);
	sbts_set_for_each_entry(dtopo, &topo_priv->container, iter) {
		if ((dtopo->dev_topo_id != dev_topo_id) && !dev_all)
			continue;

		__dev_topo_info_dump(dtopo);
	}

	read_unlock(&topo_priv->rwlock);
}

/* debug dump function */
static void topo_find_fp_priv_info_dump(
		struct sbts_topo_manager *manager,
		u64 fp_id_tgid, u64 dev_topo_id)
{
	struct sbts_topo_fp_priv *topo_priv = NULL;
	int fp_all = 0;

	fp_all = (fp_id_tgid == TOPO_DUMP_INFO_ALL) ? 1 : 0;

	mutex_lock(&manager->lock);
	list_for_each_entry(topo_priv,
			&manager->priv_head, entry) {
		if ((topo_priv->sbts_priv->fp_id != fp_id_tgid) &&
				(topo_priv->sbts_priv->tgid != fp_id_tgid) &&
				!fp_all)
			continue;

		SBTS_DBG_OUT(">>>>TOPO_PRIV[%llu] tgid[%d] topo nums: %llu",
				topo_priv->sbts_priv->fp_id,
				topo_priv->sbts_priv->tgid,
				topo_priv->topo_nums);
		topo_find_dev_topo_info_dump(manager, topo_priv, dev_topo_id);

	}
	mutex_unlock(&manager->lock);

}

static inline struct sbts_topo_fp_priv *
__find_topo_priv_data(u64 user)
{
	struct cn_core_set *core;
	struct file *fp = (struct file *)user;
	struct fp_priv_data *priv_data =
			(struct fp_priv_data *)fp->private_data;
	struct sbts_fp_priv *sbts_priv = NULL;
	struct sbts_topo_fp_priv *topo_priv = NULL;

	if (unlikely(!priv_data)) {
		cn_dev_err("fp priv is null");
		return NULL;
	}

	core = priv_data->core;
	sbts_priv = (struct sbts_fp_priv *)priv_data->sbts_priv_data;
	if (unlikely(!sbts_priv)) {
		cn_dev_core_err(core, "sbts priv is null");
		return NULL;
	}

	topo_priv = sbts_priv->topo_priv;
	if (unlikely(!topo_priv)) {
		cn_dev_core_err(core, "topo priv is null");
		return NULL;
	}

	return topo_priv;
}

static inline struct topo_user_queue_info *
__copy_topo_user_info(u64 usr_addr, u32 info_nums)
{
	struct topo_user_queue_info *usr_info = NULL;
	u64 usr_data_size = info_nums * sizeof(struct topo_user_queue_info);

	usr_info = cn_kzalloc(usr_data_size, GFP_KERNEL);
	if (!usr_info) {
		cn_dev_err("alloc memory failed");
		return NULL;
	}

	if (copy_from_user((void *)usr_info, (void *)usr_addr, usr_data_size)) {
		cn_dev_err("copy user info failed!");
		cn_kfree(usr_info);
		return NULL;
	}

	return usr_info;
}

static int __dev_topo_compare(
		struct sbts_dev_topo_struct *r,
		struct sbts_dev_topo_struct *l)
{
	u64 rkey = r->dev_topo_id;
	u64 lkey = l->dev_topo_id;

	if (rkey < lkey) {
		return -1;
	}

	if (rkey > lkey) {
		return 1;
	}

	return 0;

}

//should lock outside
static struct sbts_dev_topo_struct *__dtopo_validate(
		struct sbts_topo_fp_priv *topo_priv,
		u64 dev_topo_id)
{
	struct sbts_dev_topo_struct obj = { .dev_topo_id = dev_topo_id };
	struct sbts_dev_topo_struct *dtopo;

	dtopo = sbts_set_find(&topo_priv->container, &obj,
			__dev_topo_compare, iter);

	return dtopo;
}

static inline void __dev_topo_inner_queue_exit(
		struct sbts_set *sbts,
		struct dev_topo_inner_queue *queues,
		u32 nums)
{
	int i;

	for (i = 0; i < nums; i++) {
		if (queues[i].notifier)
			notifier_put(sbts->notifier_mgr, queues[i].notifier);

		if (queues[i].queue)
			queue_put(sbts->queue_manager, queues[i].queue);
	}

	cn_kfree(queues);
}

static inline int __dev_topo_inner_queue_init(
		struct sbts_set *sbts,
		struct dev_topo_inner_queue **ppqueues,
		struct topo_user_queue_info *usr_info,
		u32 nums, u64 user)
{
	struct cn_core_set *core = sbts->core;
	struct dev_topo_inner_queue *queues;
	int i;
	int ret = 0;

	queues = cn_kzalloc(sizeof(struct dev_topo_inner_queue) * nums, GFP_KERNEL);
	if (!queues) {
		cn_dev_core_err(core, "alloc queues info failed!");
		return -ENOMEM;
	}

	for (i = 0; i < nums; i++) {
		queues[i].queue = queue_get(sbts->queue_manager, usr_info[i].hqueue, (cn_user)user, 1);
		if (!queues[i].queue) {
			cn_dev_core_err(core, "queue_dsid(%#llx) is invalid", usr_info[i].hqueue);
			ret = -CN_QUEUE_ERROR_QUEUE_INVALID;
			break;
		}
		queues[i].notifier = notifier_get(sbts->notifier_mgr, usr_info[i].hnotifier, (cn_user)user);
		if (!queues[i].notifier) {
			cn_dev_core_err(core, "notifier %#llx is invalid", usr_info[i].hnotifier);
			ret = -CN_NOTIFIER_ERROR_NOTIFIER_INVALID;
			break;
		}
		queues[i].queue_total_task = usr_info[i].queue_task;
		queues[i].notifier_place = usr_info[i].notifier_num;
	}

	if (nums == i) {
		*ppqueues = queues;
		return 0;
	}

	__dev_topo_inner_queue_exit(sbts, queues, nums);
	return ret;
}

static int __dev_topo_init_queue(
		struct sbts_set *sbts,
		struct sbts_topo_manager *manager,
		struct sbts_dev_topo_struct *dtopo,
		u64 usr_addr)
{
	struct cn_core_set *core = manager->core;
	struct topo_user_queue_info *usr_info = NULL;
	int ret = 0;

	usr_info = __copy_topo_user_info(usr_addr, dtopo->queue_nums);
	if (!usr_info) {
		cn_dev_core_err(core, "copy user info failed");
		return -ENOMEM;
	}

	ret = __dev_topo_inner_queue_init(sbts, &dtopo->queues,
			usr_info, dtopo->queue_nums, dtopo->user);

	cn_kfree(usr_info);

	return ret;
}

static inline void
__dev_topo_find_leader_queue(
		struct sbts_dev_topo_struct *dtopo,
		u64 leader_id)
{
	struct dev_topo_inner_queue *queues = dtopo->queues;
	u32 i;

	for (i = 0; i < dtopo->queue_nums; i++) {
		if (queues->queue->dev_sid != leader_id)
			continue;

		dtopo->leader_queue = queues->queue;
		break;
	}
}

static int __dev_topo_create_device_env(
		struct sbts_set *sbts,
		struct sbts_topo_manager *manager,
		struct sbts_dev_topo_struct *dtopo)
{
	struct sched_manager *sched_mgr = sbts->sched_manager;
	struct comm_ctrl_desc tx_desc = {0};
	struct comm_ctrl_desc rx_desc = {0};
	struct ctrl_desc_data_v1 *data = NULL;
	struct cd_dev_topo_ctrl *priv = NULL;
	int ret;

	tx_desc.version      = cpu_to_le64(SBTS_VERSION);
	data                 = (struct ctrl_desc_data_v1 *)tx_desc.data;
	data->type           = cpu_to_le64(TASK_TOPO_CTRL);
	priv                 = (struct cd_dev_topo_ctrl *)data->priv;
	priv->cmd_type       = cpu_to_le32(TASK_TOPO_CTRL_CREATE);
	priv->dev_topo_id    = cpu_to_le64(dtopo->dev_topo_id);
	priv->node_nums      = cpu_to_le32(dtopo->node_nums);
	priv->queue_nums     = cpu_to_le32(dtopo->queue_nums);
	if (dtopo->leader_queue)
		priv->leader_queue   = cpu_to_le64(dtopo->leader_queue->dev_sid);
	else
		priv->leader_queue   = 0;

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
				0, sizeof(struct comm_ctrl_desc));
	if (ret || rx_desc.sta) {
		cn_dev_core_err(sbts->core, "create dev env failed");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}

	return 0;
}

static int __dev_topo_destroy_device_env(
		struct sbts_dev_topo_struct *dtopo)
{
	struct sbts_set *sbts = dtopo->sbts;
	struct sched_manager *sched_mgr = sbts->sched_manager;
	struct comm_ctrl_desc tx_desc = {0};
	struct comm_ctrl_desc rx_desc = {0};
	struct ctrl_desc_data_v1 *data = NULL;
	struct cd_dev_topo_ctrl *priv = NULL;
	int ret;

	tx_desc.version      = cpu_to_le64(SBTS_VERSION);
	data                 = (struct ctrl_desc_data_v1 *)tx_desc.data;
	data->type           = cpu_to_le64(TASK_TOPO_CTRL);
	priv                 = (struct cd_dev_topo_ctrl *)data->priv;
	priv->cmd_type       = cpu_to_le32(TASK_TOPO_CTRL_DESTROY);
	priv->dev_topo_id    = cpu_to_le64(dtopo->dev_topo_id);

	priv->trigger_send   = cpu_to_le64(READ_ONCE(dtopo->trigger_send));
	priv->param_send     = cpu_to_le64(READ_ONCE(dtopo->param_send));
	priv->node_send      = cpu_to_le64(READ_ONCE(dtopo->node_send));

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
				0, sizeof(struct comm_ctrl_desc));
	if (ret || rx_desc.sta) {
		cn_dev_core_warn(sbts->core, "destroy dev env failed");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}
	return 0;
}

static int __dev_topo_insert_privdata(
		struct sbts_topo_manager *manager,
		struct sbts_dev_topo_struct *dtopo,
		u64 user)
{
	struct cn_core_set *core = manager->core;
	struct sbts_topo_fp_priv *topo_priv = NULL;
	struct sbts_dev_topo_struct *n;

	topo_priv = __find_topo_priv_data(user);
	if (unlikely(!topo_priv)) {
		cn_dev_core_err(core, "get topo priv fail");
		return -EINVAL;
	}

	write_lock(&topo_priv->rwlock);
	n = sbts_set_insert(&topo_priv->container, dtopo,
			__dev_topo_compare, iter);
	if (unlikely(!n)) {
		write_unlock(&topo_priv->rwlock);
		cn_dev_core_err(core, "insert failed!");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}
	topo_priv->topo_nums++;
	write_unlock(&topo_priv->rwlock);

	return 0;
}

static inline void __dev_topo_erase_privdata(
		struct sbts_topo_fp_priv *topo_priv,
		struct sbts_dev_topo_struct *dtopo)
{
	sbts_set_erase(&topo_priv->container, dtopo, iter);
	topo_priv->topo_nums--;
}

static inline void __dtopo_get(struct sbts_dev_topo_struct *dtopo)
{
	if (!kref_get_unless_zero(&dtopo->ref_cnt)) {
		cn_dev_warn("dev topo(%#llx) seq %llu ref cnt invalid",
				(u64)dtopo, dtopo->dev_topo_id);
		WARN_ON(1);
	}
}

/* may use when invoke dev topo */
__attribute__((unused))
struct sbts_dev_topo_struct *sbts_topo_get(
		u64 dev_topo_id, u64 user)
{
	struct sbts_topo_fp_priv *topo_priv = NULL;
	struct sbts_dev_topo_struct *dtopo = NULL;

	topo_priv = __find_topo_priv_data(user);
	if (unlikely(!topo_priv)) {
		return NULL;
	}

	read_lock(&topo_priv->rwlock);
	dtopo = __dtopo_validate(topo_priv, dev_topo_id);
	if (!dtopo) {
		goto get_err;
	}

	__dtopo_get(dtopo);

get_err:
	read_unlock(&topo_priv->rwlock);
	return dtopo;
}

static void dtopo_release(struct kref *kref)
{
	struct sbts_dev_topo_struct *dtopo;
	dtopo = container_of(kref, struct sbts_dev_topo_struct, ref_cnt);
	TOPO_DEBUG_LOG("dev topo release, dev_topo_id is %llu.", dtopo->dev_topo_id);
}

void sbts_topo_put(struct sbts_dev_topo_struct *dtopo)
{
	if (kref_put(&dtopo->ref_cnt, dtopo_release)) {
		__dev_topo_destroy_device_env(dtopo);
		__dev_topo_inner_queue_exit(dtopo->sbts, dtopo->queues, dtopo->queue_nums);

		TOPO_DEBUG_LOG("dtopo %llu destroy finish", dtopo->dev_topo_id);
		cn_kfree(dtopo);
	}
}

static int sbts_create_dev_topo(struct sbts_set *sbts,
		u64 user, struct sbts_task_topo_cmd *param)
{
	struct cn_core_set *core =
			(struct cn_core_set *)sbts->core;
	struct sbts_topo_manager *manager = sbts->topo_manager;
	struct sbts_dev_topo_struct *dtopo = NULL;
	int ret;

	dtopo = cn_kzalloc(sizeof(struct sbts_dev_topo_struct), GFP_KERNEL);
	if (!dtopo) {
		cn_dev_core_err(core, "alloc memory failed");
		return -ENOMEM;
	}
	dtopo->sbts        = sbts;
	dtopo->user        = user;
	dtopo->dev_id      = core->idx;
	dtopo->dev_topo_id = __sync_add_and_fetch(&g_dev_topo_seq, 1);
	dtopo->tgid        = current->tgid;
	dtopo->node_nums   = param->node_nums;
	dtopo->queue_nums  = param->param_nums;
	dtopo->leader_queue = NULL;
	dtopo->is_destroy  = false;
	kref_init(&dtopo->ref_cnt);

	ret = __dev_topo_init_queue(sbts, manager, dtopo, param->param_addr);
	if (ret) {
		goto init_queue_fail;
	}
	__dev_topo_find_leader_queue(dtopo, param->leader_hqueue);

	ret = __dev_topo_create_device_env(sbts, manager, dtopo);
	if (ret) {
		goto create_device_fail;
	}

	ret = __dev_topo_insert_privdata(manager, dtopo, user);
	if (ret) {
		goto insert_fail;
	}
	TOPO_DEBUG_LOG_CORE(core, "dtopo %llu created", dtopo->dev_topo_id);
#ifdef TOPO_DEBUG
	__dev_topo_info_dump(dtopo);
#endif

	param->dev_topo_id = dtopo->dev_topo_id;

	return 0;

insert_fail:
	__dev_topo_destroy_device_env(dtopo);
create_device_fail:
	__dev_topo_inner_queue_exit(sbts, dtopo->queues, dtopo->queue_nums);
init_queue_fail:
	cn_kfree(dtopo);
	return ret;
}

static int sbts_destroy_dev_topo(struct sbts_set *sbts,
		u64 user, struct sbts_task_topo_cmd *param)
{
	struct cn_core_set *core =
			(struct cn_core_set *)sbts->core;
	struct sbts_topo_fp_priv *topo_priv = NULL;
	struct sbts_dev_topo_struct *dtopo = NULL;
	int ret = 0;

	topo_priv = __find_topo_priv_data(user);
	if (unlikely(!topo_priv)) {
		cn_dev_core_err(core, "find topo priv failed");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}

	write_lock(&topo_priv->rwlock);
	dtopo = __dtopo_validate(topo_priv, param->dev_topo_id);
	if (likely(dtopo)) {
		dtopo->is_destroy = true;
		__dev_topo_erase_privdata(topo_priv, dtopo);
		TOPO_DEBUG_LOG_CORE(core, "dtopo %llu destroy", dtopo->dev_topo_id);
	} else {
		cn_dev_core_err(core, "cant find dev topo %llu id", param->dev_topo_id);
		ret = -EINVAL;
	}
	write_unlock(&topo_priv->rwlock);
	if (!ret) {
		sbts_topo_put(dtopo);
	}

	return ret;
}

/*
 * after invoke dev topo to device
 * update inner queues ticket in this topo.
 * */
int sbts_topo_invoke_ticket_update(struct sbts_set *sbts,
		u64 user, struct sbts_dev_topo_struct *dtopo,
		struct queue *user_queue)
{
	struct cn_core_set *core =
			(struct cn_core_set *)sbts->core;
	struct queue *update_queue = NULL;
	u32 i = 0;
	struct dev_topo_inner_queue *queues = dtopo->queues;
	int ret = 0;

	TOPO_DEBUG_LOG_CORE(core, "update ticket after invoke");
	for (i = 0; i < dtopo->queue_nums; i++) {
		update_queue = NULL;
		if(!queues[i].queue) {
			cn_dev_core_warn(core, "topo %llu invoke update %d queue invalid",
						dtopo->dev_topo_id, i);
		} else {
			if (user_queue && (queues[i].queue == dtopo->leader_queue)) {
				update_queue = user_queue;
			} else {
				update_queue = queues[i].queue;
			}
			ret = __queue_ticket_update(update_queue, queues[i].queue_total_task);
			if (ret) {
				cn_dev_core_err(core, "queue %llu update ticket failed",
						update_queue->dev_sid);
			}
		}
		if (update_queue && queues[i].notifier && queues[i].notifier_place) {
			__notifier_capturer_update(queues[i].notifier, queues[i].notifier_place);
			notifier_place_save_q_ack(update_queue, queues[i].notifier, queues[i].notifier->active_info,
						update_queue->task_ticket);
		}
	}
	return ret;
}

static int sbts_topo_ticket_reset(struct sbts_set *sbts,
		u64 user, struct sbts_task_topo_cmd *param)
{
	struct cn_core_set *core =
			(struct cn_core_set *)sbts->core;
	struct topo_user_queue_info *usr_info = NULL;
	int ret = 0;
	int i;

	usr_info = __copy_topo_user_info(param->param_addr, param->param_nums);
	if (!usr_info) {
		cn_dev_core_err(core, "copy user info failed");
		return -ENOMEM;
	}

	TOPO_DEBUG_LOG_CORE(core, "reset some ticket");
	for (i = 0; i < param->param_nums; i++) {
		if (usr_info[i].hqueue) {
			TOPO_DEBUG_LOG_CORE(core, "reset q[%llu]", usr_info[i].hqueue);
			ret = queue_ticket_reset(sbts->queue_manager,
					usr_info[i].hqueue, user);
			if (ret) {
				cn_dev_core_err(core, "queue %llu reset failed",
						usr_info[i].hqueue);
				break;
			}
		}
		if (usr_info[i].hnotifier) {
			TOPO_DEBUG_LOG_CORE(core, "reset n[%llu]", usr_info[i].hnotifier);
			ret = notifier_capturer_reset(sbts->notifier_mgr,
					usr_info[i].hnotifier, user);
			if (ret) {
				cn_dev_core_err(core, "notifier %llu reset failed",
						usr_info[i].hnotifier);
				break;
			}
		}
	}

	cn_kfree(usr_info);

	return ret;
}

/* api call this function to update queue ticket for tasks un-resident
 * when create topo nodes
 *
 * */
static int sbts_topo_ticket_update(struct sbts_set *sbts,
		u64 user, struct sbts_task_topo_cmd *param)
{
	struct cn_core_set *core =
			(struct cn_core_set *)sbts->core;
	struct queue *queue = NULL;
	struct notifier *notifier = NULL;
	struct topo_user_queue_info *usr_info = NULL;
	int ret = 0;
	int i;

	usr_info = __copy_topo_user_info(param->param_addr, param->param_nums);
	if (!usr_info) {
		cn_dev_core_err(core, "copy user info failed");
		return -ENOMEM;
	}

	TOPO_DEBUG_LOG_CORE(core, "update some ticket");
	for (i = 0; i < param->param_nums; i++) {
		if (usr_info[i].hqueue) {
			queue = queue_get(sbts->queue_manager, usr_info[i].hqueue,
					(cn_user)user, 1);
			if (!queue) {
				cn_dev_core_err(core, "invalid queue %llu update %llu failed",
						usr_info[i].hqueue,
						usr_info[i].queue_task);
				ret = -EINVAL;
				break;
			}
			TOPO_DEBUG_LOG_CORE(core, "update q[%llu] %llu", queue->dev_sid, usr_info[i].queue_task);
			__queue_ticket_update(queue, usr_info[i].queue_task);
			__queue_topo_updating(queue);
		}
		if (usr_info[i].hnotifier && usr_info[i].notifier_num) {
			notifier = notifier_get(sbts->notifier_mgr, usr_info[i].hnotifier, (cn_user)user);
			if (!notifier) {
				cn_dev_core_err(core, "invalid notifier %llu update %llu failed",
						usr_info[i].hnotifier,
						usr_info[i].notifier_num);
				ret = -EINVAL;
			} else {
				TOPO_DEBUG_LOG_CORE(core, "update n[%llu] %llu",
						notifier->dev_info->dev_eid, usr_info[i].notifier_num);
				__notifier_capturer_update(notifier, usr_info[i].notifier_num);
				notifier_place_save_q_ack(queue, notifier, notifier->active_info,
						queue->task_ticket);
				notifier_put(sbts->notifier_mgr, notifier);
			}
		}
		if (queue) {
			queue_put(sbts->queue_manager, queue);
			queue = NULL;
		}
		if (ret)
			break;
	}

	cn_kfree(usr_info);

	return ret;
}

int cn_sbts_topo_task_cmd(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	int ret = 0;
	struct sbts_task_topo_cmd param;
	struct cn_core_set *core = sbts->core;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
					struct sbts_task_topo_cmd))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	if (param.version != SBTS_VERSION) {
		cn_dev_core_err_limit(core, "input version invalid");
		return -EINVAL;
	}

	switch (param.cmd_type) {
	case SBTS_TOPO_CMD_DEV_CREATE:
		ret = sbts_create_dev_topo(sbts, (u64)user, &param);
		break;
	case SBTS_TOPO_CMD_DEV_DESTROY:
		ret = sbts_destroy_dev_topo(sbts, (u64)user, &param);
		break;
	case SBTS_TOPO_CMD_QUEUE_TICKET_RESET:
		ret = sbts_topo_ticket_reset(sbts, (u64)user, &param);
		break;
	case SBTS_TOPO_CMD_QUEUE_TICKET_UPDATE:
		ret = sbts_topo_ticket_update(sbts, (u64)user, &param);
		break;
	case SBTS_TOPO_CMD_DEV_TOPO_DEBUG:
	default:
		cn_dev_core_debug(core, "input type invalid %llu", param.cmd_type);
		ret = -EINVAL;
		break;
	}

	if (copy_to_user((void *)args, (void *)&param, sizeof(
					struct sbts_task_topo_cmd))) {
		cn_dev_core_err(core, "copy parameters to user failed!");
		ret = -EFAULT;
	}

	return 0;
}

/* call this function when task fill all priv data in struct task_desc_data_v1
 * return value is topo task priv data size
 * */
int sbts_task_fill_topo_info(struct sbts_set *sbts,
		struct sbts_queue_invoke_task *user_param,
		struct sbts_dev_topo_struct *dtopo,
		struct task_desc_data_v1 *task_desc,
		u32 *priv_offset, u32 *topo_offset)
{
	struct task_desc_topo_priv *topo_priv;

	TOPO_DEBUG_LOG("dev_topo_id %llu fill node %u, offset %llu",
			dtopo->dev_topo_id, user_param->dev_topo_node_index, priv_offset);

	*priv_offset = ALIGN(*priv_offset, 8);
	topo_priv = (struct task_desc_topo_priv *)((u64)task_desc->priv + *priv_offset);

	topo_priv->dev_topo_id = cpu_to_le64(user_param->dev_topo_id);
	topo_priv->dev_topo_node_index = cpu_to_le64(user_param->dev_topo_node_index);
	topo_priv->topo_info = cpu_to_le64(user_param->topo_info);

	*topo_offset = sizeof(struct task_desc_topo_priv);

	return 0;
}

static void sbts_topo_priv_erase_all(
		struct sbts_topo_fp_priv *topo_priv)
{
	struct sbts_dev_topo_struct *dtopo, *tmp;
	struct sbts_set_container_st destroy_container;

	sbts_set_container_init(&destroy_container);

	write_lock(&topo_priv->rwlock);
	sbts_set_for_each_entry_safe(dtopo, tmp, &topo_priv->container, iter) {
		dtopo->is_destroy = true;
		__dev_topo_erase_privdata(topo_priv, dtopo);
		(void)sbts_set_insert(&destroy_container, dtopo,
				__dev_topo_compare, iter);
	}
	write_unlock(&topo_priv->rwlock);

	sbts_set_for_each_entry_safe(dtopo, tmp, &destroy_container, iter) {
		sbts_set_erase(&destroy_container, dtopo, iter);
		sbts_topo_put(dtopo);
	}
}

int sbts_topo_do_exit(u64 user, struct sbts_topo_manager *manager)
{
	struct cn_core_set *core = manager->core;
	struct sbts_topo_fp_priv *topo_priv = NULL;

	topo_priv = __find_topo_priv_data(user);
	if (unlikely(!topo_priv)) {
		cn_dev_core_err(core, "get topo priv fail");
		return -EINVAL;
	}

	sbts_topo_priv_erase_all(topo_priv);

	return 0;
}

int sbts_topo_priv_init(struct sbts_set *sbts,
		struct sbts_fp_priv *sbts_priv)
{
	struct cn_core_set *core = sbts->core;
	struct sbts_topo_manager *manager = sbts->topo_manager;
	struct sbts_topo_fp_priv *topo_priv = NULL;

	if (unlikely(!manager)) {
		cn_dev_core_err(core, "manager is null");
		return -EINVAL;
	}

	topo_priv = cn_numa_aware_kzalloc(core, sizeof(struct sbts_topo_fp_priv), GFP_KERNEL);
	if (!topo_priv) {
		cn_dev_core_err(core, "malloc priv failed");
		return -ENOMEM;
	}

	topo_priv->sbts_priv = sbts_priv;
	topo_priv->topo_nums = 0;

	sbts_set_container_init(&topo_priv->container);
	rwlock_init(&topo_priv->rwlock);

	mutex_lock(&manager->lock);
	list_add_tail(&topo_priv->entry, &manager->priv_head);
	mutex_unlock(&manager->lock);

	sbts_priv->topo_priv = topo_priv;

	return 0;
}

void sbts_topo_priv_exit(struct sbts_fp_priv *sbts_priv)
{
	struct sbts_set *sbts_set = sbts_priv->sbts_set;
	struct cn_core_set *core = sbts_set->core;
	struct sbts_topo_manager *manager = sbts_set->topo_manager;
	struct sbts_topo_fp_priv *topo_priv = sbts_priv->topo_priv;

	if (!topo_priv)
		return;

	if (topo_priv->topo_nums) {
		cn_dev_core_warn(core, "priv topo num is %llu", topo_priv->topo_nums);
		WARN_ON(1);
	}

	sbts_topo_priv_erase_all(topo_priv);

	mutex_lock(&manager->lock);
	list_del(&topo_priv->entry);
	mutex_unlock(&manager->lock);

	cn_kfree(sbts_priv->topo_priv);
}

int sbts_topo_manager_init(
		struct sbts_topo_manager **ppmanager,
		struct cn_core_set *core)
{
	struct sbts_topo_manager *manager;
	struct sbts_set *sbts_set = core->sbts_set;

	manager = cn_numa_aware_kzalloc(core, sizeof(struct sbts_topo_manager), GFP_KERNEL);
	if (!manager) {
		cn_dev_core_err(core, "malloc topo manager failed");
		return -ENOMEM;
	}
	manager->core = core;
	manager->sched_mgr = sbts_set->sched_manager;
	manager->sbts = sbts_set;
	INIT_LIST_HEAD(&manager->priv_head);
	mutex_init(&manager->lock);

	*ppmanager = manager;

	return 0;
}

void sbts_topo_manager_exit(struct sbts_topo_manager *topo_manager)
{
	struct sbts_set *sbts_set = topo_manager->sbts;

	if (!topo_manager) {
		cn_dev_err("topo manager is null");
		return;
	}

	cn_kfree(topo_manager);
	sbts_set->topo_manager = NULL;
}


/************** for proc debug code ****************/


int cn_sbts_topo_debug_show(struct cn_core_set *core, struct seq_file *m)
{
	struct sbts_set *sbts_set = NULL;
	struct sbts_topo_manager *manager = NULL;
	struct param_buf_manager *param_mgr = NULL;

	//int ret = 0;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_info("core is null");
		return -EINVAL;
	}
	sbts_set = core->sbts_set;
	if (IS_ERR_OR_NULL(sbts_set)) {
		cn_dev_core_info(core, "sbts set is null");
		return -EINVAL;
	}
	manager = sbts_set->topo_manager;
	if (IS_ERR_OR_NULL(manager)) {
		cn_dev_core_info(core, "manager is null");
		return -EINVAL;
	}
	cn_dev_core_info(core, "task topo debug show");

	param_mgr = sbts_set->queue_manager->param_mgr;
	/* dump global info */
	seq_printf(m, "global seq:   %llu\n", g_dev_topo_seq);
	/* dump some manager info */
	seq_printf(m, "priv list is %s\n", list_empty(&manager->priv_head) ?
			"empty" : "not empty");
	seq_printf(m, "param alloced %#x pages\n", param_mgr->alloced_pages);

	seq_puts(m, ">>>>TOPO DEBUG Commands<<<<\n");
	seq_puts(m, "echo read#topo_priv#'fp_id'(all)\n");
	seq_puts(m, "echo read#dev_topo#'fp_id'(all)#'topo_seq'(all)\n");

	return 0;
}

/* show topo_fp_priv in current core_set by fp_id or tgid */
static void topo_proc_debug_topo_priv_out(
		struct cn_core_set *core,
		char *ops_val)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct sbts_topo_manager *manager = sbts->topo_manager;
	u64 target_id = 0;

	if (!ops_val) {
		cn_dev_info("Input Ops val is null");
		return;
	}

	if (!strncmp(ops_val, "all", 3)) {
		target_id = TOPO_DUMP_INFO_ALL;
		goto start_prt;
	}

	if (kstrtou64(ops_val, 0, &target_id)) {
		cn_dev_info("input val invalid %s", ops_val);
		return;
	}

start_prt:
	topo_find_fp_priv_info_dump(manager, target_id, TOPO_DUMP_INFO_ALL);
}

/* show topo_fp_priv's dev_topo in current core_set by fp_id or tgid */
static void topo_proc_debug_dev_topo_out(
		struct cn_core_set *core,
		char *ops_val)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct sbts_topo_manager *manager = sbts->topo_manager;
	char *sep;
	u64 fp_id = 0, topo_id = 0;

	if (!ops_val) {
		fp_id = TOPO_DUMP_INFO_ALL;
		topo_id = TOPO_DUMP_INFO_ALL;
		goto start_prt;
	}
	sep = strsep(&ops_val, "#");

	if (!strncmp(sep, "all", 3)) {
		fp_id = TOPO_DUMP_INFO_ALL;
	} else if (kstrtou64(sep, 0, &fp_id)) {
		fp_id = TOPO_DUMP_INFO_ALL;
	}

	if (!ops_val || !strncmp(ops_val, "all", 3)) {
		topo_id = TOPO_DUMP_INFO_ALL;
		goto start_prt;
	}

	if (kstrtou64(ops_val, 0, &topo_id)) {
		topo_id = TOPO_DUMP_INFO_ALL;
	}

start_prt:
	topo_find_fp_priv_info_dump(manager, fp_id, topo_id);
}

void topo_proc_debug_set(
		struct cn_core_set *core,
		char *ops_type, char *ops_val)
{
//TODO
}

void topo_proc_debug_read(
		struct cn_core_set *core,
		char *ops_type, char *ops_val)
{
	if (!ops_type) {
		cn_dev_info("Input Ops type is null");
		return;
	}

	if (!strncmp(ops_type, "topo_priv", 9)) {
		topo_proc_debug_topo_priv_out(core, ops_val);
	} else if (!strncmp(ops_type, "dev_topo", 8)) {
		topo_proc_debug_dev_topo_out(core, ops_val);
	} else {
		cn_dev_info("ops type:<<%s>> not support", ops_type);
	}
}

#define TOPO_DBG_STR_LEN 200
void cn_sbts_topo_debug_write(
		struct cn_core_set *core,
		const char __user *user_buf,
		size_t count)
{
	struct sbts_set *sbts_set = NULL;
	struct sbts_topo_manager *manager = NULL;
	char cmd[TOPO_DBG_STR_LEN];
	size_t cmd_size = min_t(size_t, count, TOPO_DBG_STR_LEN);
	char *sep = cmd;
	char *ops_name, *ops_type, *ops_val;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_info("core is null");
		return;
	}
	sbts_set = core->sbts_set;
	if (IS_ERR_OR_NULL(sbts_set)) {
		cn_dev_core_info(core, "sbts set is null");
		return;
	}
	manager = sbts_set->topo_manager;
	if (IS_ERR_OR_NULL(manager)) {
		cn_dev_core_info(core, "manager is null");
		return;
	}
	cn_dev_core_info(core, "task topo debug write");

	memset(cmd, 0, TOPO_DBG_STR_LEN);
	if (copy_from_user(cmd, user_buf, cmd_size))
		return;

	if (count < 4) {
		cn_dev_info("User input str Too short : [%s]", cmd);
		return;
	}
	cmd[cmd_size - 1] = 0;

	ops_name = strsep(&sep, "#");
	ops_type = strsep(&sep, "#");
	ops_val = sep;

	if (!strncmp(ops_name, "set", 3)) {
		topo_proc_debug_set(core, ops_type, ops_val);
	} else if (!strncmp(ops_name, "read", 4)) {
		topo_proc_debug_read(core, ops_type, ops_val);
	} else {
		cn_dev_err("ops name:<<%s>> not support", ops_name);
	}
}

u64 sbts_topo_get_arm_topo_node_bitmap(struct cn_core_set *core)
{
	struct sbts_hw_info *info;
	struct sbts_basic_info *basic;
	struct sbts_set *sbts = core->sbts_set;

	if(!sbts) {
		return 0;
	}

	info = sbts->hw_info;
	if(!info) {
		return 0;
	}

	basic = (struct sbts_basic_info *)info->data;
	return basic->topo_node_bitmap;
}
