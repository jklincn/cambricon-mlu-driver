#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/rbtree.h>
#include <linux/seq_file.h>
#include <linux/kref.h>
#include "cndrv_mm.h"
#include "cndrv_bus.h"
#include "cndrv_commu.h"
#include "unotify.h"
#include "cndrv_sbts.h"
#include "sbts.h"
#include "cndrv_hpq.h"
#include "queue.h"
#include "../core/cndrv_ioctl.h"
#include "cndrv_core.h"
#include "hostfunc.h"
#include "../core/cndrv_driver_capability.h"
#include "cndrv_monitor.h"

#define HF_SEND_USR_TRY 5

struct hostfn_to_user_msg {
	u64 version;
	u64 hqueue;
	u64 seq;
	u32 clock_id;
	u32 perf_enable;
};

struct hostfn_head_rbtree {
	struct rb_node node;
	u64 fp_id;
	struct list_head triggered_task_list;
	struct mutex mutex;
	struct kref ref_cnt;
	unsigned long seq;
};

static void __hf_send_to_usr(
		struct sbts_set *sbts, struct queue *queue, u64 *ptr)
{
	int loop = HF_SEND_USR_TRY;
	struct cn_core_set *core = sbts->core;

	while (loop--) {
		if (!sbts_unotify_send(sbts, queue, HOST_FUNCTION_PROCESS, ptr,
				    sizeof(struct hostfn_to_user_msg)))
			return;

		if (sbts_pause(core, 10, 100))
			break;
	}

	cn_dev_warn_limit("[%s] host function signal user space fail %#llx",
			core->core_name, (u64)queue);
}

void sbts_hostfn_fill_shm_sig(struct hostfn_shm_sig *sig, __u8 host_execute_sta,
		__u64 hk_pass_trigger_ns, __u64 host_get_trigger_ns,
		__u64 hostfn_start_ns, __u64 hostfn_end_ns)
{
	sig->host_execute_sta = host_execute_sta;
	sig->hk_pass_trigger_ns = hk_pass_trigger_ns;
	sig->host_get_trigger_ns = host_get_trigger_ns;
	sig->hostfn_start_ns = hostfn_start_ns;
	sig->hostfn_end_ns = hostfn_end_ns;
	return;
}

void sbts_hostfn_shm_sig_to_dev(struct sbts_hostfunc_set *hostfunc_set,
		host_addr_t host_sig_va, struct hostfn_shm_sig *sig)
{
#define HOSTFN_SEND_CNT 9999999
	struct sched_manager *sched_mgr = NULL;
	struct comm_ctrl_desc tx_ctl_desc = { 0 };
	u64 payload_size = 8;
	int cnt = HOSTFN_SEND_CNT;
	struct cn_core_set *core = hostfunc_set->sbts->core;

	/* make sure when device receive host_execute_sta, perf info has been ready */
	memcpy_toio((void *)host_sig_va, (void *)sig, _HF_SHM_SIG_PERF_SIZE);
	cn_bus_mb(core->bus_set);
	memcpy_toio((void *)host_sig_va + _HF_SHM_SIG_PERF_SIZE,
			(void *)&sig->host_execute_sta,
			sizeof(*sig) - _HF_SHM_SIG_PERF_SIZE);

	__sync_fetch_and_add(&hostfunc_set->sig_num, 1);

	/* if wakeup device enable is off, just flush write */
	if (!hostfunc_set->wakeup_dev_en) {
		/* memcpy_toio only write 1 byte here,  wmb() flush out wc-buffer */
		wmb();
		return;
	}

	sched_mgr = hostfunc_set->sched_mgr;
	while (cnt--) {
		/* send message to interrupt and wake up device */
		if (commu_send_message(sched_mgr->hostfn_ep, &tx_ctl_desc,
				    payload_size)) {
			return;
		}
		if (sbts_pause(core, 5, 20)) {
			cn_dev_core_err(core, "the reset flag has been set!");
			return;
		}
	}
	cn_dev_core_err(core, "send data to device timeout, Please check mlu "
			      "device status\n");
}

static struct hostfn_head_rbtree *hostfn_rbtree_search(
		struct rb_root *root, u64 fp_id)
{
	struct rb_node *node;
	struct hostfn_head_rbtree *item;
	node = root->rb_node;

	while (node) {
		item = container_of(node, struct hostfn_head_rbtree, node);
		if (item->fp_id > fp_id) {
			node = node->rb_left;
		} else if (item->fp_id < fp_id) {
			node = node->rb_right;
		} else {
			return item;
		}
	}
	return NULL;
}

static int hostfn_rbtree_insert(
		struct rb_root *root, struct hostfn_head_rbtree *item)
{
	struct rb_node **new = NULL, *parent = NULL;
	struct hostfn_head_rbtree *this;
	new = &(root->rb_node);

	/* Figureout where to put new node */
	while (*new) {
		this = container_of(*new, struct hostfn_head_rbtree, node);
		parent = *new;

		if (item->fp_id < this->fp_id) {
			new = &((*new)->rb_left);
		} else if (item->fp_id > this->fp_id) {
			new = &((*new)->rb_right);
		} else {
			return -EFAULT;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&item->node, parent, new);
	rb_insert_color(&item->node, root);
	return 0;
}

static inline struct hostfn_head_rbtree *__hostfn_rbtree_node_get(
		struct sbts_hostfunc_set *hostfunc_set, __u64 fp_id)
{
	struct rb_root *root = NULL;
	struct hostfn_head_rbtree *head = NULL;

	root = &hostfunc_set->triggered_rbtree_root;
	mutex_lock(&hostfunc_set->mutex);
	head = hostfn_rbtree_search(root, fp_id);
	if (head) {
		kref_get(&head->ref_cnt);
	}
	mutex_unlock(&hostfunc_set->mutex);
	return head;
}

static void _release(struct kref *kref)
{
}

static inline int __hostfn_rbtree_node_put(
		struct sbts_hostfunc_set *hostfunc_set,
		struct hostfn_head_rbtree *head)
{
	struct rb_root *root = NULL;
	struct hostfn_task_node *hf_task = NULL, *tmp = NULL;
	__u8 host_execute_sta = _HF_EXECUTE_FINISH;
	struct hostfn_shm_sig sig = { 0 };

	root = &hostfunc_set->triggered_rbtree_root;
	if (kref_put(&head->ref_cnt, _release)) {
		list_for_each_entry_safe (hf_task, tmp,
				&head->triggered_task_list, head) {
			__sync_fetch_and_add(
					&hostfunc_set->do_exit_delete_num, 1);
			sbts_hostfn_fill_shm_sig(&sig, host_execute_sta,
					hf_task->hk_pass_trigger_ns, 0, 0, 0);
			sbts_hostfn_shm_sig_to_dev(hostfunc_set,
					hf_task->host_finish_sig_va, &sig);
			cn_kfree(hf_task);
		}
		cn_kfree(head);
		return 1;
	}
	return 0;
}

static inline int __hostfn_rbtree_node_create(
		struct sbts_hostfunc_set *hostfunc_set, __u64 fp_id)
{
	int ret = 0;
	struct rb_root *root = NULL;
	struct hostfn_head_rbtree *head = NULL, *tmp = NULL;
	struct cn_core_set *core = hostfunc_set->core;

	root = &hostfunc_set->triggered_rbtree_root;

	mutex_lock(&hostfunc_set->mutex);
	head = hostfn_rbtree_search(root, fp_id);
	mutex_unlock(&hostfunc_set->mutex);

	if (!head) {
		tmp = cn_numa_aware_kzalloc(core, sizeof(struct hostfn_head_rbtree), GFP_KERNEL);
		if (!tmp) {
			return -ENOMEM;
		}
		tmp->fp_id = fp_id;
		INIT_LIST_HEAD(&tmp->triggered_task_list);
		mutex_init(&tmp->mutex);
		kref_init(&tmp->ref_cnt);
		head = tmp;

		mutex_lock(&hostfunc_set->mutex);
		ret = hostfn_rbtree_insert(root, head);
		if (ret) {
			/* rbtree node exist */
			cn_kfree(head);
			mutex_unlock(&hostfunc_set->mutex);
			return 0;
		}
		mutex_unlock(&hostfunc_set->mutex);
	}
	return 0;
}

static inline void __hostfn_rbtree_node_destroy(
		struct sbts_hostfunc_set *hostfunc_set, __u64 fp_id)
{
	struct hostfn_head_rbtree *head = NULL;
	struct rb_root *root = NULL;

	root = &hostfunc_set->triggered_rbtree_root;

	mutex_lock(&hostfunc_set->mutex);
	head = hostfn_rbtree_search(root, fp_id);
	if (!head) {
		mutex_unlock(&hostfunc_set->mutex);
		return;
	}

	rb_erase(&head->node, root);
	mutex_unlock(&hostfunc_set->mutex);
	/*put out of lock*/

	/* delay context free */
	while (SBTS_KREF_READ(&head->ref_cnt) > 1) {
		usleep_range(2, 5);
	}

	__hostfn_rbtree_node_put(hostfunc_set, head);

	return;
}

static void signal_user_hostfn(struct sbts_set *sbts, struct queue *queue,
		__u64 seq, u32 clock_id, u32 perf_enable)
{
	struct hostfn_to_user_msg user_priv = { 0 };

	user_priv.version = 0;
	user_priv.hqueue = queue->dev_sid;
	user_priv.seq = seq;
	user_priv.clock_id = clock_id;
	user_priv.perf_enable = perf_enable;

	__hf_send_to_usr(sbts, queue, (u64 *)&user_priv);
}

static u32 get_hostfn_task_perf_info(struct cn_core_set *core,
		struct queue *queue, u32 *clock_id)
{
	bool perf_en;

	perf_en = cn_monitor_perf_type_check_clockid(queue->tgid_entry, core,
			HOSTFN_TS_TASK, clock_id);

	return perf_en ? 1 : 0;
}

static int create_hostfn_node(struct sbts_hostfunc_set *hostfunc_set,
		u64 host_finish_sig_va, struct queue *queue, u32 clock_id,
		u32 perf_enable, struct hostfn_task_node **task)
{
	struct hostfn_task_node *node = NULL;
	struct sbts_set *sbts = hostfunc_set->sbts;
	struct cn_core_set *core = sbts->core;

	node = cn_numa_aware_kzalloc(core, sizeof(struct hostfn_task_node), GFP_KERNEL);
	if (unlikely(!node)) {
		cn_dev_core_err(core, "create host function task node failed");
		return -ENOMEM;
	}

	node->host_finish_sig_va = host_finish_sig_va;
	node->queue = queue;
	node->seq = 0;

	if (perf_enable) {
		node->hk_pass_trigger_ns =
				get_host_timestamp_by_clockid(clock_id);
	} else {
		node->hk_pass_trigger_ns = 0;
	}

	INIT_LIST_HEAD(&node->head);

	*task = node;
	return 0;
}

static int hostfn_node_register(struct sbts_hostfunc_set *hostfunc_set,
		struct hostfn_task_node *task_node)
{
	struct hostfn_head_rbtree *head = NULL;
	__u64 fp_id = task_node->queue->user_id;
	struct cn_core_set *core = hostfunc_set->sbts->core;

	head = __hostfn_rbtree_node_get(hostfunc_set, fp_id);
	if (!head) {
		cn_dev_core_err(core, "cannot find host function rbtree node "
				      "by fp_id");
		return -EFAULT;
	}

	mutex_lock(&head->mutex);
	head->seq++;
	task_node->seq = head->seq;
	cn_dev_debug("add queue sid %#llx seq %lu", task_node->queue->dev_sid,
			task_node->seq);
	list_add_tail(&task_node->head, &head->triggered_task_list);
	mutex_unlock(&head->mutex);

	if (__hostfn_rbtree_node_put(hostfunc_set, head)) {
		return -EFAULT;
	}

	return 0;
}

int sbts_hostfn_create_user_node_once(
		struct sbts_hostfunc_set *hostfunc_set, __u64 fp_id)
{
	__sync_add_and_fetch(&hostfunc_set->invoke_task_num, 1);
	return __hostfn_rbtree_node_create(hostfunc_set, fp_id);
}

struct hostfn_task_node *sbts_hostfn_node_deregister(
		struct sbts_set *sbts, struct queue *queue, __u64 seq)
{
	struct cn_core_set *core = NULL;
	struct hostfn_task_node *task = NULL;
	struct sbts_hostfunc_set *hostfunc_set = NULL;
	struct hostfn_head_rbtree *head = NULL;
	u64 fp_id = 0;

	if (!sbts) {
		return NULL;
	}

	if (!queue) {
		return NULL;
	}

	hostfunc_set = sbts->hostfunc_set;
	fp_id = queue->user_id;
	core = sbts->core;

	head = __hostfn_rbtree_node_get(hostfunc_set, fp_id);
	if (!head) {
		cn_dev_core_err(core, "get hostfunc rbtree node failed");
		return NULL;
	}

	mutex_lock(&head->mutex);
	list_for_each_entry (task, &head->triggered_task_list, head) {
		if (task->seq == seq) {
			list_del(&task->head);
			mutex_unlock(&head->mutex);
			__hostfn_rbtree_node_put(hostfunc_set, head);
			__sync_fetch_and_add(
					&hostfunc_set->delete_from_trigger_list_num,
					1);
			return task;
		}
	}

	mutex_unlock(&head->mutex);
	__hostfn_rbtree_node_put(hostfunc_set, head);
	cn_dev_core_err(core, "cannot find head host function task in rbtree "
			      "user node");
	return NULL;
}

void sbts_hostfunc_wait_work(struct cn_core_set *core,
		void *priv_data,
		void *rx_msg, int rx_size)
{
	struct sbts_hostfunc_set *hostfunc_set =
			(struct sbts_hostfunc_set *)priv_data;
	struct hostfn_task_node *task_node = NULL;
	struct sbts_set *sbts = hostfunc_set->sbts;
	struct queue *queue = NULL;
	struct comm_hostfn_desc *rx_desc = (struct comm_hostfn_desc *)rx_msg;
	struct hostfn_shm_sig sig = { 0 };
	u32 perf_enable;
	u32 clock_id;
	__u8 host_execute_sta = _HF_EXECUTE_FINISH;
	int ret = 0;

	if (rx_desc->trigger_type != _HF_TRIGGER_NORMAL) {
		cn_dev_core_err(core, "receive wrong host function "
				      "message from dev");
		return;
	}

	task_node = NULL;
	hostfunc_set->receive_trigger_num++;

	queue = queue_get(sbts->queue_manager, rx_desc->hqueue,
			ANNOY_USER, 0);
	if (!queue) {
		/* queue has been destroyed, send execute finish to release resource of device */
		hostfunc_set->queue_invalid_trigger_num++;
		sbts_hostfn_fill_shm_sig(
				&sig, host_execute_sta, 0, 0, 0, 0);
		sbts_hostfn_shm_sig_to_dev(hostfunc_set,
				rx_desc->host_finish_sig_addr, &sig);
	} else {
		perf_enable = get_hostfn_task_perf_info(
				core, queue, &clock_id);
		ret = create_hostfn_node(hostfunc_set,
				rx_desc->host_finish_sig_addr, queue,
				clock_id, perf_enable, &task_node);
		if (ret == -ENOMEM) {
			hostfunc_set->queue_invalid_trigger_num++;
			sbts_hostfn_fill_shm_sig(&sig, host_execute_sta,
					0, 0, 0, 0);
			sbts_hostfn_shm_sig_to_dev(hostfunc_set,
					rx_desc->host_finish_sig_addr,
					&sig);
			queue_put(sbts->queue_manager, queue);
			return;
		}
		ret = hostfn_node_register(hostfunc_set, task_node);
		if (ret == -EFAULT) {
			/* current user has been destroyed, send execute finish to release resource of device */
			hostfunc_set->queue_invalid_trigger_num++;
			sbts_hostfn_fill_shm_sig(&sig, host_execute_sta,
					task_node->hk_pass_trigger_ns,
					0, 0, 0);
			sbts_hostfn_shm_sig_to_dev(hostfunc_set,
					task_node->host_finish_sig_va,
					&sig);
			cn_kfree(task_node);
			task_node = NULL;
		} else {
			/* trigger host user executing host function */
			signal_user_hostfn(sbts, task_node->queue,
					task_node->seq, clock_id,
					perf_enable);
			hostfunc_set->add_to_trigger_list_num++;
		}
		queue_put(sbts->queue_manager, queue);
	}
}

void sbts_hostfn_task_free(
		struct sbts_hostfunc_set *hostfunc_set, struct queue *queue)
{
	/* get the rbtree node by the user id in queue*/
	u64 sid = 0;
	u64 fp_id = 0;
	struct rb_root *root = NULL;
	struct hostfn_head_rbtree *head = NULL;
	struct hostfn_task_node *hf_task = NULL, *tmp = NULL;
	__u8 host_execute_sta = _HF_EXECUTE_FINISH;
	struct hostfn_shm_sig sig = { 0 };
	LIST_HEAD(destroy_head);

	if (unlikely(!hostfunc_set)) {
		cn_dev_debug("host function set is null");
		return;
	}

	fp_id = queue->user_id;
	root = &hostfunc_set->triggered_rbtree_root;

	head = __hostfn_rbtree_node_get(hostfunc_set, fp_id);
	if (!head) {
		return;
	}

	/* deregister all of the host function node of this queue */
	sid = queue->sid;
	mutex_lock(&head->mutex);
	list_for_each_entry_safe (
			hf_task, tmp, &head->triggered_task_list, head) {
		if (hf_task->queue->sid == sid) {
			list_move(&hf_task->head, &destroy_head);
		}
	}
	mutex_unlock(&head->mutex);
	__hostfn_rbtree_node_put(hostfunc_set, head);

	list_for_each_entry_safe (hf_task, tmp, &destroy_head, head) {
		cn_dev_debug("exit queue sid %#llx seq %lu",
				hf_task->queue->dev_sid, hf_task->seq);
		sbts_hostfn_fill_shm_sig(&sig, host_execute_sta,
				hf_task->hk_pass_trigger_ns, 0, 0, 0);
		sbts_hostfn_shm_sig_to_dev(hostfunc_set,
				hf_task->host_finish_sig_va, &sig);
		cn_kfree(hf_task);
		__sync_fetch_and_add(
				&hostfunc_set->queue_do_exit_delete_num, 1);
	}

	return;
}

int sbts_hostfunc_do_exit(u64 user, struct sbts_hostfunc_set *hostfunc_set)
{
	u64 fp_id = 0;
	struct file *fp = NULL;

	if (unlikely(!hostfunc_set)) {
		cn_dev_debug("host function set is null");
		return 0;
	}

	fp = (struct file *)user;
	fp_id = ((struct fp_priv_data *)fp->private_data)->fp_id;

	__hostfn_rbtree_node_destroy(hostfunc_set, fp_id);

	return 0;
}

int sbts_hostfunc_init(struct sbts_set *sbts_set)
{
	int ret = 0;
	struct sbts_hostfunc_set *hostfunc_set = NULL;
	struct sbts_hw_info *info = NULL;
	struct sbts_basic_info *b_info = NULL;
	struct cn_core_set *core = sbts_set->core;
	const driver_capability_list_t *cap = NULL;

	cap = get_capability(core);
	if (cap->hostfunc_version < CAPABILITY_HOSTFUNC_VERSION_1) {
		cn_dev_info("device_id:%lld do not support host function",
				core->device_id);
		return 0;
	}

	cn_dev_core_debug(core, "host function manager init");

	hostfunc_set = cn_numa_aware_kzalloc(core, sizeof(struct sbts_hostfunc_set), GFP_KERNEL);
	if (!hostfunc_set) {
		cn_dev_core_err(core, "malloc hostfunc set mem failed");
		return -ENOMEM;
	}

	hostfunc_set->core = core;
	hostfunc_set->sbts = sbts_set;
	hostfunc_set->sched_mgr = sbts_set->sched_manager;
	hostfunc_set->triggered_rbtree_root = RB_ROOT;
	hostfunc_set->add_to_trigger_list_num = 0;
	hostfunc_set->invoke_task_num = 0;
	hostfunc_set->receive_trigger_num = 0;

	mutex_init(&hostfunc_set->mutex);

	hostfunc_set->worker = commu_wait_work_run(core, "sbts_hf",
			sbts_set->sched_manager->hostfn_ep,
			hostfunc_set, sbts_hostfunc_wait_work);
	if (!hostfunc_set->worker) {
		cn_dev_core_err(core, "create host function thread "
				      "failed");
		ret = -EINVAL;
		goto worker_err;
	}

	hostfunc_set->wakeup_dev_en = 1;
	info = sbts_set->hw_info;
	if (info) {
		b_info = (struct sbts_basic_info *)info->data;
		/* if high prio dev work always run, do not need to wake up by sending msg */
		hostfunc_set->wakeup_dev_en =
				(b_info->work_policy == POLICY_DEFAULT) ? 1 : 0;
	}
	cn_dev_core_info(core, " hostfunc  wakeup_dev_en is %d",
			hostfunc_set->wakeup_dev_en);

	sbts_set->hostfunc_set = hostfunc_set;
	return 0;

worker_err:
	cn_kfree(hostfunc_set);
	return ret;
}

void sbts_hostfunc_exit(struct sbts_hostfunc_set *hostfunc_set)
{
	struct sbts_set *sbts_set = NULL;

	if (unlikely(!hostfunc_set)) {
		cn_dev_debug("host function set is null");
		return;
	}

	sbts_set = hostfunc_set->sbts;

	commu_wait_work_stop(sbts_set->core, hostfunc_set->worker);
	cn_kfree(hostfunc_set);
}

int cn_hostfn_record_show(struct cn_core_set *core, struct seq_file *m)
{
	struct sbts_set *sbts_set = NULL;
	struct sbts_hostfunc_set *hostfunc_set;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_info("core is null");
		return -EINVAL;
	}
	sbts_set = core->sbts_set;
	if (IS_ERR_OR_NULL(sbts_set)) {
		cn_dev_core_info(core, "sbts set is null");
		return -EINVAL;
	}
	hostfunc_set = sbts_set->hostfunc_set;
	if (IS_ERR_OR_NULL(hostfunc_set)) {
		cn_dev_core_info(core, "hostfunc manager is null");
		return -EINVAL;
	}
	cn_dev_core_info(core, "hostfunc record show");
	seq_printf(m, "invoke_task_num:   %llu:\n",
			hostfunc_set->invoke_task_num);
	seq_printf(m, "receive_trigger_num:   %llu:\n",
			hostfunc_set->receive_trigger_num);
	seq_printf(m, "add_to_trigger_list_num:   %llu:\n",
			hostfunc_set->add_to_trigger_list_num);
	seq_printf(m, "delete_from_trigger_list_num:   %llu:\n",
			hostfunc_set->delete_from_trigger_list_num);
	seq_printf(m, "do exit delete num:   %llu:\n",
			hostfunc_set->do_exit_delete_num);
	seq_printf(m, "queue do exit delete num:   %llu:\n",
			hostfunc_set->queue_do_exit_delete_num);
	seq_printf(m, "send finish req:   %llu:\n",
			hostfunc_set->send_finish_req);
	seq_printf(m, "sig num:   %llu:\n", hostfunc_set->sig_num);
	seq_printf(m, "queue invalid trigger num:   %llu:\n",
			hostfunc_set->queue_invalid_trigger_num);
	seq_printf(m, "post sig num:   %llu:\n",
			hostfunc_set->sig_num -
					hostfunc_set->queue_invalid_trigger_num);

	return 0;
}
