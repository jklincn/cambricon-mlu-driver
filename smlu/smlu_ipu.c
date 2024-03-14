#include <linux/list.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/rbtree.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>

#include "smlu_internal.h"

#define	IPU_UTIL_UPDATE_PERIOD	(1)//ms
#define	IPU_UTIL_RETRY_TIME	(10000)

/* insert_smlucg_rb_node */
//INSERT_RB_NODE_OPS(smlu_cgroup, active_ns, smlucg);
/* delete_smlucg_rb_node */
//DELETE_RB_NODE_OPS(smlu_cgroup, smlucg);
/* search_smlucg_rb_node */
SEARCH_RB_NODE_OPS(smlu_cgroup, active_ns, smlucg);

static void smlu_ipu_average_util(struct smlu_cap *smlu_cap)
{
	struct smlu_cgroup_res *res = &(smlu_cap->resources[ipu_cgrp_id]);
	unsigned long old = res->average_t[res->head];

	res->average_t[res->head] = res->raw_usage;
	res->total = (res->total + res->average_t[res->head]) - old;

	res->head++;
	if (res->head == SMLU_AVERAGE_TOTAL)
		res->head = 0;

	res->average = res->total / SMLU_AVERAGE_TOTAL;
}

static void smlu_ipuutil_update_work(struct work_struct *work)
{
	struct smlu_set *smlu_set = container_of(work, struct smlu_set, util_worker.work);
	struct cn_core_set *core = smlu_set->core;
	struct smlu_cap *smlu_cap;
	struct pid_info_s *pid_info_node = NULL;
	int ret;

	/* update all tgid_entry */
	ret = cn_perf_process_ipu_util_update_from_shm(core, IPU_UTIL_RETRY_TIME);
	if (unlikely(ret)) {
		cn_dev_core_info(core, "update process util return -EAGAIN retry");
		goto out;
	}

	mutex_lock(&smlu_set->caps_lock);
	down_write(&smlu_set->ns_rwsem);
	list_for_each_entry(smlu_cap, &smlu_set->caps_head, cap_node) {
		smlu_cap->resources[ipu_cgrp_id].raw_usage = 0;
		smlu_cap->resources[ipu_cgrp_id].usage = 0;
	}

	/* update ipu_chip_util */
	smlu_set->total_util = cn_perf_ipu_chip_util_get(core);
	/* update namespace's pid_list util & total usage */
	tree_traverse_and_operate(smlu_set->ns_tree, smlu_cgroup, {
		smlu_cap = post->smlu_cap;
		post->ns_util = 0;

		/* multi-thread inner process use the same tgid_entry, see cn_perf_private_data_init() */
		cn_perf_namespace_ipu_util_get(core, post->active_ns, &post->ns_util);
		smlu_cap->resources[ipu_cgrp_id].raw_usage += post->ns_util;
		smlu_cap->resources[ipu_cgrp_id].usage += post->ns_util / 1000;

		spin_lock(&post->pid_lock);
		list_for_each_entry(pid_info_node, &post->pid_head, pid_list) {
			cn_perf_process_ipu_util_fill_pid_info(pid_info_node);
		}
		smlu_ipu_average_util(smlu_cap);
		spin_unlock(&post->pid_lock);

		smlu_util_data_raw_update(smlu_cap, IPU_UTIL);
	});
	up_write(&smlu_set->ns_rwsem);
	mutex_unlock(&smlu_set->caps_lock);

out:
	schedule_delayed_work(&smlu_set->util_worker, msecs_to_jiffies(IPU_UTIL_UPDATE_PERIOD));
}

static int ipucg_init(struct cn_core_set *core)
{
	struct smlu_set *smlu_set = core->smlu_set;

	INIT_DELAYED_WORK(&smlu_set->util_worker, smlu_ipuutil_update_work);

	return 0;
}

static int ipucg_exit(struct cn_core_set *core)
{
	struct smlu_set *smlu_set = core->smlu_set;

	cancel_delayed_work_sync(&smlu_set->util_worker);
	return 0;
}

static int ipucg_online(struct cn_core_set *core)
{
	struct smlu_set *smlu_set = core->smlu_set;

	schedule_delayed_work(&smlu_set->util_worker, msecs_to_jiffies(IPU_UTIL_UPDATE_PERIOD));
	return 0;
}

static int ipucg_offline(struct cn_core_set *core)
{
	struct smlu_set *smlu_set = core->smlu_set;

	cancel_delayed_work_sync(&smlu_set->util_worker);
	return 0;
}

static int ipucg_try_charge(struct cn_core_set *core, void *fp, void *active_ns, __u64 usage)
{
	struct smlu_set *smlu_set = core->smlu_set;
	struct smlu_cgroup *smlu_cgroup;
	struct smlu_cap *smlu_cap;
	int ret = 0;

	down_read(&smlu_set->ns_rwsem);
	smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, active_ns ? : task_active_pid_ns(current));
	if (!smlu_cgroup) {
		cn_dev_core_err_limit(core, "need create smlu instances and open /dev/cambricon-caps/cap_dev%d_miX first",
			core->pf_idx);
		up_read(&smlu_set->ns_rwsem);
		return -ESRCH;
	}

	smlu_cap = smlu_cgroup->smlu_cap;
	up_read(&smlu_set->ns_rwsem);

	ret = cn_smlu_util_adjust_output(core, smlu_cap, IPU_UTIL);
	if (!ret || ret == -ENODEV) {
		/* charge success or no util_adjust module, permit task invoke */
		return 0;
	} else {
		/* ctrl-c return */
		return ret;
	}
}

struct smlu_cgroup_subsys ipu_cgrp_subsys = {
	.css_init = ipucg_init,
	.css_exit = ipucg_exit,
	.css_online = ipucg_online,
	.css_offline = ipucg_offline,
	.css_try_charge	= ipucg_try_charge,
};

