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

/* insert_smlucg_rb_node */
//INSERT_RB_NODE_OPS(smlu_cgroup, active_ns, smlucg);
/* delete_smlucg_rb_node */
//DELETE_RB_NODE_OPS(smlu_cgroup, smlucg);
/* search_smlucg_rb_node */
SEARCH_RB_NODE_OPS(smlu_cgroup, active_ns, smlucg);

#define __update_pid_info_node(pid_info_node, ops, size) \
do { \
	__sync_##ops##_and_fetch(&pid_info_node->phy_usedsize, (size)); \
	__sync_##ops##_and_fetch(&pid_info_node->vir_usedsize, (size)); \
} while (0)

/* APIs for mem to charge/uncharge specific resources */
static int memcg_try_charge(struct cn_core_set *core, void *fp, void *active_ns, __u64 usage)
{
	struct file *filp = (struct file *)fp;
	struct smlu_set *smlu_set = core->smlu_set;
	struct smlu_cgroup *smlu_cgroup;
	struct smlu_cap *smlu_cap;
	struct smlu_priv_data *smlu_priv;
	struct pid_info_s *pid_info_node = NULL;
	__u64 new, quota;
	int ret = 0;

	down_write(&smlu_set->ns_rwsem);
	smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, active_ns ? : task_active_pid_ns(current));
	if (!smlu_cgroup) {
		cn_dev_core_err(core, "need create smlu instances and open /dev/cambricon-caps/cap_dev%d_miX first",
			core->pf_idx);
		ret = -ESRCH;
		goto out;
	}
	smlu_cap = smlu_cgroup->smlu_cap;

	new = smlu_cap->resources[mem_cgrp_id].usage + usage;
	quota = smlu_cap->resources[mem_cgrp_id].max * (100 + smlu_cap->resources[mem_cgrp_id].factor) / 100;
	if (new > quota) {
		/* TODO device memory cgroup oom dump */
		cn_dev_core_err_limit(core, "%s: current usage 0x%llx, req 0x%llx, quota 0x%llx:0x%llx",
			dev_name(smlu_cap->minor->kdev), smlu_cap->resources[mem_cgrp_id].usage, usage,
			smlu_cap->resources[mem_cgrp_id].max, quota);
		ret = -ENOSPC;
		goto out;
	} else {
		smlu_cap->resources[mem_cgrp_id].usage = new;
	}

	if (unlikely(!fp)) {
		cn_dev_core_debug(core, "need fp to update pid_info");
		goto out;
	} else if (file_is_cndev(filp)) {
		struct cndev_priv_data *priv_data = (struct cndev_priv_data *)filp->private_data;

		smlu_priv = (struct smlu_priv_data *)priv_data->smlu_priv_data;

		if (!smlu_priv->smlu_cgroup)
			smlu_priv->smlu_cgroup = smlu_cgroup;

		if (!smlu_priv->pid_info_node[core->idx]) {
			pid_info_node = cn_kzalloc(sizeof(struct pid_info_s), GFP_KERNEL);
			if (!pid_info_node) {
				cn_dev_core_err(core, "malloc pid_info_node failed");
				ret = -ENOMEM;
				goto out;
			}

			pid_info_node->fp = fp;
			pid_info_node->tgid = current->tgid;
			pid_info_node->active_ns = task_active_pid_ns(current);
			pid_info_node->active_pid = task_tgid_nr_ns(current, pid_info_node->active_ns);
			pid_info_node->pgid = task_pgrp_nr_ns(current, pid_info_node->active_ns);
			pid_info_node->taskpid = find_get_pid(current->pid);

			spin_lock(&smlu_cgroup->pid_lock);
			list_add_tail(&pid_info_node->pid_list, &smlu_cgroup->vmm_pid_head);
			spin_unlock(&smlu_cgroup->pid_lock);

			smlu_priv->pid_info_node[core->idx] = pid_info_node;
		} else {
			pid_info_node = smlu_priv->pid_info_node[core->idx];
		}
		__update_pid_info_node(pid_info_node, add, usage);
	} else {
		struct fp_priv_data *priv_data = (struct fp_priv_data *)filp->private_data;

		smlu_priv = (struct smlu_priv_data *)priv_data->smlu_priv_data;
		pid_info_node = smlu_priv->pid_info_node[0];
		__update_pid_info_node(pid_info_node, add, usage);
	}

out:
	up_write(&smlu_set->ns_rwsem);
	return ret;
}

static void memcg_uncharge(struct cn_core_set *core, void *fp, void *active_ns, __u64 usage)
{
	struct file *filp = (struct file *)fp;
	struct smlu_set *smlu_set = core->smlu_set;
	struct smlu_cgroup *smlu_cgroup;
	struct smlu_cap *smlu_cap;
	struct smlu_priv_data *smlu_priv;
	struct pid_info_s *pid_info_node;
	int ret;

	down_write(&smlu_set->ns_rwsem);
	smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, active_ns ? : task_active_pid_ns(current));
	if (!smlu_cgroup) {
		cn_dev_core_err(core, "need create smlu instances and open /dev/cambricon-caps/cap_dev%d_miX first",
			core->pf_idx);
		/* do we really need to repair it with smlu_priv->smlu_cgroup? */
		goto out;
	}

	smlu_cap = smlu_cgroup->smlu_cap;
	smlu_cap->resources[mem_cgrp_id].usage -= usage;

	/* fp may released in delay free, or 0 for kernelspace alloc */
	spin_lock(&smlu_cgroup->pid_lock);
	ret = smlu_cgroup_is_fp_valid(smlu_cgroup, filp);
	if (ret == 2) {
		struct cndev_priv_data *priv_data = (struct cndev_priv_data *)filp->private_data;

		smlu_priv = (struct smlu_priv_data *)priv_data->smlu_priv_data;
		pid_info_node = smlu_priv->pid_info_node[core->idx];
		__update_pid_info_node(pid_info_node, sub, usage);
	} else if (ret == 1) {
		struct fp_priv_data *priv_data = (struct fp_priv_data *)filp->private_data;

		smlu_priv = (struct smlu_priv_data *)priv_data->smlu_priv_data;
		pid_info_node = smlu_priv->pid_info_node[0];
		__update_pid_info_node(pid_info_node, sub, usage);
	}
	spin_unlock(&smlu_cgroup->pid_lock);

out:
	up_write(&smlu_set->ns_rwsem);
}

/**
 * memcg_offline - cgroup css_offline callback
 *
 * This function is called when @css is about to go away and responsible
 * for shooting down all memcg associated with @css. As part of that it
 * marks all the resource pool entries to max value, so that when resources are
 * uncharged, associated resource pool can be freed as well.
 */
static int memcg_offline(struct cn_core_set *core)
{
	//set_all_resource_max_limit(core);

	return 0;
}

struct smlu_cgroup_subsys mem_cgrp_subsys = {
	.css_offline	= memcg_offline,
	.css_try_charge	= memcg_try_charge,
	.css_uncharge	= memcg_uncharge,
};

