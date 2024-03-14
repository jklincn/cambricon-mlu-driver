#include <linux/version.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/signal.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/module.h>
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/task.h>
#endif
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/rbtree.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/seq_file.h>

#include "cndrv_domain.h"	/* cn_dm_attr_cluster_num() */
#include "smlu_internal.h"

static struct mutex smlu_util_module_lock;
/* export data for cambricon-util_drv.ko */
struct smlu_util_adjust_module_s ex_smlu_util_adjust_module = {0};
EXPORT_SYMBOL(ex_smlu_util_adjust_module);
struct smlu_util_data_raw ex_util_data[MAX_PHYS_CARD][MAX_SMLU_INSTANCE_COUNT + 1][UTIL_TYPE_MAX];
EXPORT_SYMBOL(ex_util_data);

/* generate an array of cgroup subsystem pointers */
#define SUBSYS(_x) [_x ## _cgrp_id] = &_x ## _cgrp_subsys,
struct smlu_cgroup_subsys *smlu_cgroup_subsys[] = {
	SMLU_CGROUP_LIST
};
#undef SUBSYS

/* array of cgroup subsystem names */
#define SUBSYS(_x) [_x ## _cgrp_id] = #_x,
static const char *smlu_cgroup_subsys_name[] = {
	SMLU_CGROUP_LIST
};
#undef SUBSYS

/* insert_smlucg_rb_node */
//INSERT_RB_NODE_OPS(smlu_cgroup, active_ns, smlucg);
/* delete_smlucg_rb_node */
DELETE_RB_NODE_OPS(smlu_cgroup, smlucg);
/* search_smlucg_rb_node */
SEARCH_RB_NODE_OPS(smlu_cgroup, active_ns, smlucg);

/* MONITOR_CNDEV_SET_FEATURE, CNHOST_DEV_ROOT_ONLY */
int cn_core_set_smlu_mode(struct cn_core_set *core, int enable)
{
	struct smlu_cgroup_subsys *ss;
	int i;
	int ret;

	if (!cn_is_smlu_support(core))
		return -EINVAL;

	if (core->smlu_enable == enable) {
		return 0;
	}

	if (core->open_count) {
		cn_dev_core_err(core, "This card is busy");
		return -EBUSY;
	}

	if (enable) {
		smlu_for_each_subsys(ss, i) {
			if (ss->css_online) {
				ret = ss->css_online(core);
				if (ret) {
					cn_dev_core_err(core, "[%s] css_online fail", smlu_cgroup_subsys_name[i]);
					return ret;
				}
			}
		}
	} else {
		struct smlu_set *smlu_set = core->smlu_set;

		mutex_lock(&smlu_set->caps_lock);
		if (!list_empty(&smlu_set->caps_head)) {
			cn_dev_core_err(core, "Must destroy all instances before sMLU OFF");
			mutex_unlock(&smlu_set->caps_lock);
			return -EBUSY;
		}
		mutex_unlock(&smlu_set->caps_lock);

		smlu_for_each_subsys(ss, i) {
			if (ss->css_offline) {
				ret = ss->css_offline(core);
				if (ret) {
					cn_dev_core_err(core, "[%s] css_offline fail", smlu_cgroup_subsys_name[i]);
					return ret;
				}
			}
		}
	}

	core->smlu_enable = enable;
	return 0;
}

int cn_is_smlu_en(struct cn_core_set *core)
{
	return core->smlu_enable;
}

int cn_is_smlu_support(struct cn_core_set *core)
{
	if (IS_ERR_OR_NULL(core))
		return 0;

	if (cn_core_is_vf(core)) {
		return 0;
	}

	if (isEdgePlatform(core)) {
		return 0;
	}

	/*
	 * cn_core_get_work_mode()?
	 * core->mim_enable coundn't be change during devnode open,
	 * so it's safe while others call cn_is_smlu_support().
	 */
	if (cn_is_mim_en(core)) {
		return 0;
	}

	if (MLUID_MAJOR_ID(core->device_id) >= 3)
		return 1;

	return 0;
}

int smlu_default_profile_init(struct cn_core_set *core)
{
	int i, j;
	__u64 total_quota[SMLU_CGROUP_SUBSYS_COUNT];
	__u64 profile_quota[SMLU_CGROUP_SUBSYS_COUNT];
	struct smlu_set *smlu_set;

	if (!core || !core->smlu_set) {
		cn_dev_core_err(core, "invalid core_set");
		return -EINVAL;
	}

	smlu_set = core->smlu_set;

	for (j = 0; j < SMLU_CGROUP_SUBSYS_COUNT; j++) {
		total_quota[j] = smlu_set->total[j].max;
	}

	/* default profile: 1, 1/2, 1/4 (ipu/mem) */
	for (i = 0; i < DEFAULT_SMLU_PROFILE_COUNT; i++) {
		smlu_set->profile_desc_info[i].profile_id = i;
		for (j = 0; j < SMLU_CGROUP_SUBSYS_COUNT; j++) {
			/* default profile's factor is 0 */
			smlu_set->profile_desc_info[i].profile_res[j].factor = 0;

			profile_quota[j] = total_quota[j] / default_profile_spec[i];
			smlu_set->profile_desc_info[i].profile_res[j].max = profile_quota[j];
		}

		smlu_set->profile_desc_info[i].total_capacity = default_profile_spec[i];

		/* smlu profile_name: Xp.Ymb. X is ipu quota by percentage, Y is mem quota by MB */
		sprintf(smlu_set->profile_desc_info[i].profile_name,
			"%llup.%llumb", profile_quota[ipu_cgrp_id], profile_quota[mem_cgrp_id] >> 20);
	}

	return 0;
}

struct PID_parameter cn_pid_parameter[MAX_PHYS_CARD] = {{{0}}};
EXPORT_SYMBOL(cn_pid_parameter);

void cn_pid_parameter_init(struct cn_core_set *core)
{
	if (!core)
		return;

	strcpy(cn_pid_parameter[core->idx].board_model_name,
		core->board_info.board_model_name);
}

void cn_pid_parameter_exit(struct cn_core_set *core)
{
	memset(&cn_pid_parameter[core->idx], 0,
			sizeof(cn_pid_parameter[core->idx]));
}

int cn_smlu_late_init(struct cn_core_set *core)
{
	struct smlu_set *smlu_set;
	struct smlu_cgroup_subsys *ss;
	int i;
	int ret;

	/* to save EDGE os mem */
	if (!cn_is_smlu_support(core))
		return 0;

	cn_dev_core_info(core, "namespace:(%pK:%pK)", task_active_pid_ns(current), &init_pid_ns);

	smlu_set = cn_kzalloc(sizeof(struct smlu_set), GFP_KERNEL);
	if (smlu_set == NULL) {
		cn_dev_core_err(core, "alloc smlu_set fail");
		return -ENOMEM;
	}

	core->smlu_set = smlu_set;
	smlu_set->core = core;
	init_rwsem(&smlu_set->ns_rwsem);/* lock used for rbtree insert/delete */
	rwlock_init(&smlu_set->quota_lock);/* lock used for update total */
	mutex_init(&smlu_set->profile_lock);/* lock used for update profile */
	mutex_init(&smlu_set->caps_lock);/* lock used for caps ops */
	mutex_init(&smlu_util_module_lock);
	INIT_LIST_HEAD(&smlu_set->caps_head);
	ida_init(&smlu_set->instance_ida);

	smlu_for_each_subsys(ss, i) {
		if (ss->css_init) {
			ret = ss->css_init(core);
			if (ret) {
				cn_dev_core_err(core, "[%s] css_init fail", smlu_cgroup_subsys_name[i]);
				return ret;
			}
		}

		switch (i) {
		case mem_cgrp_id: {
			struct cndev_memory_info info;

			memset(&info, 0x0, sizeof(struct cndev_memory_info));
			ret = cndev_card_memory_info(core, &info);
			if (ret) {
				cn_dev_core_err(core, "smlu: cndev_card_memory_info error:%d", ret);
				return ret;
			}
			smlu_set->total[i].max = info.phy_total << 20;//core->board_info.total_memory;
			smlu_set->total[i].usage = 0;
			smlu_set->total[i].factor = SMLU_MAX_OVERCOMMIT_FACTOR;
			break;
		}
		case ipu_cgrp_id:
			smlu_set->total[i].max = 100;//ipu util
			smlu_set->total[i].usage = 0;
			smlu_set->total[i].factor = SMLU_MAX_OVERCOMMIT_FACTOR;
			break;
		}
	}

	ret = smlu_default_profile_init(core);
	if (ret) {
		cn_dev_core_err(core, "smlu_default_profile_init failed");
		return ret;
	}

	cn_pid_parameter_init(core);
	return 0;
}

void cn_smlu_late_exit(struct cn_core_set *core)
{
	struct smlu_set *smlu_set;
	struct smlu_cap *smlu_cap, *tmp;
	struct smlu_cgroup_subsys *ss;
	int i;
	int ret;

	if (!cn_is_smlu_support(core))
		return;

	cn_pid_parameter_exit(core);

	/* if smlu mode is enabled, this call will disable it, meanwhile
	 * decrease the ref count of cambricon_util_drv module, otherwise
	 * cambricon_util_drv module can't be removed */
	cn_core_set_smlu_mode(core, 0);

	smlu_for_each_subsys(ss, i) {
		if (ss->css_exit) {
			ret = ss->css_exit(core);
			if (ret) {
				cn_dev_core_err(core, "[%s] css_exit fail", smlu_cgroup_subsys_name[i]);
				return;
			}
		}
	}

	smlu_set = core->smlu_set;

	/* maintanence rbtree */
	down_write(&smlu_set->ns_rwsem);
	tree_traverse_and_operate(smlu_set->ns_tree, smlu_cgroup, {
		delete_smlucg_rb_node(&smlu_set->ns_tree, post);
		cn_kfree(post);
		ret = 1;
	});
	up_write(&smlu_set->ns_rwsem);

	/* if cnmon do not destroy smlu instances, cleanup here. */
	mutex_lock(&smlu_set->caps_lock);
	list_for_each_entry_safe(smlu_cap, tmp, &smlu_set->caps_head, cap_node) {
		list_del(&smlu_cap->cap_node);

		if (likely(smlu_cap->minor)) {
			cn_dev_core_info(core, "cdev %u:%u, %s, deleted",
				smlu_cap->minor->major,
				smlu_cap->minor->index,
				dev_name(smlu_cap->minor->kdev));
			cnhost_dev_unregister(smlu_cap->minor->dev);
			cnhost_dev_put(smlu_cap->minor->dev);

			//smlu_cap->instance_id == smlu_cap->minor->dev->vf_index
			ida_simple_remove(&smlu_set->instance_ida, smlu_cap->instance_id);
		}
		cn_kfree(smlu_cap);
	}
	mutex_unlock(&smlu_set->caps_lock);

	ida_destroy(&smlu_set->instance_ida);

	cn_kfree(core->smlu_set);
}

/* smlu couldn't be enable/disable during devnode open */
int cn_smlu_private_data_init(struct file *fp, void *fp_private_data)
{
	struct smlu_priv_data *smlu_priv;
	struct pid_info_s *pid_info_node = NULL;
	int ret = 0;

	if (file_is_cndev(fp)) {
		struct cndev_priv_data *priv_data = (struct cndev_priv_data *)fp_private_data;

		smlu_priv = cn_kzalloc(sizeof(struct smlu_priv_data) + sizeof(struct pid_info_s *) * MAX_FUNCTION_NUM, GFP_KERNEL);
		if (!smlu_priv) {
			cn_dev_err("malloc smlu_priv_data fail");
			return -ENOMEM;
		}
		smlu_priv->num = MAX_FUNCTION_NUM;
		smlu_priv->ns = task_active_pid_ns(current);
		/*
		 * in case scenes: user open ctl node before cap_node bind a namespace, smlu_cgroup not in rbtree;
		 * BTW all cards could have diff smlu enable status and namespace, but for fp->priv_data, smlu_cgroup is same.
		 * so update smlu_priv->smlu_cgroup and add to smlu_cgroup->vmm_pid_head later while vmm try_charge
		 */

		priv_data->smlu_priv_data = smlu_priv;
	} else {
		struct fp_priv_data *priv_data = (struct fp_priv_data *)fp_private_data;
		struct cn_core_set *core = priv_data->core;
		struct smlu_set *smlu_set = core->smlu_set;
		struct smlu_cgroup *smlu_cgroup;

		if (!cn_is_smlu_en(core))
			return 0;

		smlu_priv = cn_kzalloc(sizeof(struct smlu_priv_data) + sizeof(struct pid_info_s *), GFP_KERNEL);
		if (!smlu_priv) {
			cn_dev_core_err(core, "malloc smlu_priv_data failed");
			return -ENOMEM;
		}

		pid_info_node = cn_kzalloc(sizeof(struct pid_info_s), GFP_KERNEL);
		if (!pid_info_node) {
			cn_dev_core_err(core, "malloc pid_info_node failed");
			ret = -ENOMEM;
			goto err_pid_info;
		}

		smlu_priv->num = 1;
		smlu_priv->ns = task_active_pid_ns(current);
		/* add to smlu_cgroup->pid_head now */
		smlu_priv->pid_info_node[0] = pid_info_node;

		pid_info_node->fp = fp;
		pid_info_node->phy_usedsize = 0;
		pid_info_node->vir_usedsize = 0;
		pid_info_node->tgid = current->tgid;
		pid_info_node->active_ns = task_active_pid_ns(current);
		pid_info_node->active_pid =
			task_tgid_nr_ns(current, pid_info_node->active_ns);
		pid_info_node->pgid =
			task_pgrp_nr_ns(current, pid_info_node->active_ns);
		pid_info_node->taskpid = find_get_pid(current->pid);

		if (smlu_find_tid_cap_node(core)) {
			down_read(&smlu_set->ns_rwsem);
			smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, task_active_pid_ns(current));
			if (!smlu_cgroup) {
				cn_dev_core_err(core, "need create smlu instances and open /dev/cambricon-caps/cap_dev%d_miX first",
					core->pf_idx);
				ret = -ESRCH;
				goto err_find_ns;
			}
			smlu_priv->smlu_cgroup = smlu_cgroup;

			spin_lock(&smlu_cgroup->pid_lock);
			list_add_tail(&pid_info_node->pid_list, &smlu_cgroup->pid_head);
			spin_unlock(&smlu_cgroup->pid_lock);

			up_read(&smlu_set->ns_rwsem);
		} else {
			/* try it in case delay unbind */
			down_read(&smlu_set->ns_rwsem);
			smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, task_active_pid_ns(current));
			if (smlu_cgroup) {
				smlu_priv->smlu_cgroup = smlu_cgroup;

				spin_lock(&smlu_cgroup->pid_lock);
				list_add_tail(&pid_info_node->pid_list, &smlu_cgroup->pid_head);
				spin_unlock(&smlu_cgroup->pid_lock);
			}
			up_read(&smlu_set->ns_rwsem);
		}

		priv_data->smlu_priv_data = smlu_priv;

		return 0;

err_find_ns:
		up_read(&smlu_set->ns_rwsem);
		put_pid(pid_info_node->taskpid);
		cn_kfree(pid_info_node);
err_pid_info:
		cn_kfree(smlu_priv);
		return ret;
	}

	return 0;
}

/* smlu couldn't be enable/disable during devnode open */
int cn_smlu_private_data_exit(struct file *fp, void *fp_private_data)
{
	struct smlu_cgroup *smlu_cgroup;
	struct pid_info_s *pid_info_node;
	int i;

	if (file_is_cndev(fp)) {
		struct cndev_priv_data *priv_data = (struct cndev_priv_data *)fp_private_data;
		struct smlu_priv_data *smlu_priv = (struct smlu_priv_data *)priv_data->smlu_priv_data;

		smlu_cgroup = smlu_priv->smlu_cgroup;
		/* no vmm alloc at any cards */
		if (!smlu_cgroup)
			goto out;

		for (i = 0; i < smlu_priv->num; i++) {
			pid_info_node = smlu_priv->pid_info_node[i];

			if (pid_info_node) {
				put_pid(pid_info_node->taskpid);

				spin_lock(&smlu_cgroup->pid_lock);
				list_del(&pid_info_node->pid_list);
				spin_unlock(&smlu_cgroup->pid_lock);

				cn_kfree(smlu_priv->pid_info_node[i]);
				smlu_priv->pid_info_node[i] = NULL;
			}
		}
out:
		cn_kfree(smlu_priv);
		priv_data->smlu_priv_data = NULL;
	} else {
		struct fp_priv_data *priv_data = (struct fp_priv_data *)fp_private_data;
		struct cn_core_set *core = priv_data->core;
		struct smlu_priv_data *smlu_priv = (struct smlu_priv_data *)priv_data->smlu_priv_data;

		/* smlu_priv is null */
		if (!cn_is_smlu_en(core))
			return 0;

		smlu_cgroup = smlu_priv->smlu_cgroup;

		for (i = 0; i < smlu_priv->num; i++) {
			pid_info_node = smlu_priv->pid_info_node[i];

			if (likely(pid_info_node)) {
				put_pid(pid_info_node->taskpid);

				/* no bind namespace, it's ok while driver-api enumerates all nodes */
				if (smlu_cgroup) {
					spin_lock(&smlu_cgroup->pid_lock);
					list_del(&pid_info_node->pid_list);
					spin_unlock(&smlu_cgroup->pid_lock);
				}

				cn_kfree(smlu_priv->pid_info_node[i]);
				smlu_priv->pid_info_node[i] = NULL;
			}
		}

		cn_kfree(smlu_priv);
		priv_data->smlu_priv_data = NULL;
	}

	return 0;
}


int cn_smlu_try_charge(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			void *fp, void *active_ns, __u64 usage)
{
	struct smlu_cgroup_subsys *ss = smlu_cgroup_subsys[subsys];
	int ret = 0;

	if (!cn_is_smlu_en(core))
		return 0;

	if (ss->css_try_charge) {
		ret = ss->css_try_charge(core, fp, active_ns, usage);
		if (ret) {
			cn_dev_core_debug(core, "[%s] css_try_charge fail", smlu_cgroup_subsys_name[subsys]);
		}
	}
	return ret;
}

void cn_smlu_uncharge(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			void *fp, void *active_ns, __u64 usage)
{
	struct smlu_cgroup_subsys *ss = smlu_cgroup_subsys[subsys];

	if (!cn_is_smlu_en(core))
		return;

	if (ss->css_uncharge) {
		ss->css_uncharge(core, fp, active_ns, usage);
	}
}

/* query subsys's quota and usage info of a namespace */
int cn_smlu_query_namespace_quota(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			void *active_ns, struct smlu_cgroup_res *res)
{
	struct smlu_set *smlu_set;
	struct smlu_cgroup *smlu_cgroup;
	struct smlu_cap *smlu_cap;
	int ret = 0;

	if (!cn_is_smlu_en(core))
		return -EINVAL;

	smlu_set = core->smlu_set;

	down_read(&smlu_set->ns_rwsem);
	smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, active_ns ? active_ns : task_active_pid_ns(current));
	if (!smlu_cgroup) {
		cn_dev_core_debug(core, "can't find smlu_cgroup of active_ns:%pK", active_ns);
		ret = -ESRCH;
		goto out;
	}
	smlu_cap = smlu_cgroup->smlu_cap;
	memcpy(res, &smlu_cap->resources[subsys], sizeof(struct smlu_cgroup_res));
out:
	up_read(&smlu_set->ns_rwsem);
	return ret;
}

extern void cndev_proc_info_combine(struct proc_mem_info *mem_info, u32 *num);

/*
 * query subsys's pid info of current namespace
 * @param [in,out] mem_info with pid, out filled with it's usedsize.
 */
int cn_smlu_query_namespace_pid_info(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			struct smlu_proc_info *proc_info)
{
	struct smlu_set *smlu_set;
	struct pid_info_s *pid_info_node;
	struct proc_mem_info *mem_info = (struct proc_mem_info *)proc_info;
	struct cndev_process_ipuutil *ipuutil = (struct cndev_process_ipuutil *)proc_info;
	int pid;
	int ret = 0;

	if (!cn_is_smlu_en(core))
		return -EINVAL;

	smlu_set = core->smlu_set;

	down_read(&smlu_set->ns_rwsem);
	if (!cn_is_host_ns()) {
		struct smlu_cgroup *smlu_cgroup;

		smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, task_active_pid_ns(current));
		if (!smlu_cgroup) {
			cn_dev_core_err(core, "can't find smlu_cgroup of active_ns:%pK", task_active_pid_ns(current));
			ret = -ESRCH;
			goto out;
		}
		ret = -ESRCH;// not found
		switch (subsys) {
		case mem_cgrp_id:
			mem_info->phy_memused = 0;
			mem_info->virt_memused = 0;
			break;
		case ipu_cgrp_id:
			ipuutil->util = 0;
			break;
		default:
			cn_dev_core_err(core, "unknown smlu cgroup subsystem");
			break;
		}
		spin_lock(&smlu_cgroup->pid_lock);
		list_for_each_entry(pid_info_node, &smlu_cgroup->pid_head, pid_list) {
			pid = pid_info_node->active_pid;

			switch (subsys) {
			case mem_cgrp_id:
				if (pid == mem_info->pid) {
					mem_info->phy_memused += pid_info_node->phy_usedsize;
					mem_info->virt_memused += pid_info_node->vir_usedsize;
					ret = 0;
					/* no break; different context inner a process could have more records in pid_info list */
				}
				break;
			case ipu_cgrp_id:
				if (pid == ipuutil->tgid) {
					ipuutil->util += pid_info_node->ipu_util;
					ret = 0;
					break; /* multi-thread inner process use the same tgid_entry, see cn_perf_private_data_init() */
				}
				break;
			default:
				cn_dev_core_err(core, "unknown smlu cgroup subsystem");
				break;
			}
		}
		/* found */
		if (ret == 0) {
			if (subsys == mem_cgrp_id) {
				/* amend vmm pid info */
				list_for_each_entry(pid_info_node, &smlu_cgroup->vmm_pid_head, pid_list) {
					pid = pid_info_node->active_pid;

					if (pid == mem_info->pid) {
						mem_info->phy_memused += pid_info_node->phy_usedsize;
						mem_info->virt_memused += pid_info_node->vir_usedsize;
						//break;/* FIXME each process only have single vmm pid_info_node? */
					}
				}
			}
		}
		spin_unlock(&smlu_cgroup->pid_lock);
	} else {
		ret = -ESRCH;// not found
		tree_traverse_and_operate(smlu_set->ns_tree, smlu_cgroup, {
			spin_lock(&post->pid_lock);
			list_for_each_entry(pid_info_node, &post->pid_head, pid_list) {
				pid = pid_info_node->tgid;

				switch (subsys) {
				case mem_cgrp_id:
					if (pid == mem_info->pid) {
						mem_info->phy_memused += pid_info_node->phy_usedsize;
						mem_info->virt_memused += pid_info_node->vir_usedsize;
						ret = 0;// found
						/* no break; different context inner a process could have more records in pid_info list */
					}
					break;
				case ipu_cgrp_id:
					if (pid == ipuutil->tgid) {
						ipuutil->util += pid_info_node->ipu_util;
						ret = 0;
						break;/* multi-thread inner process use the same tgid_entry, see cn_perf_private_data_init() */
					}
					break;
				default:
					cn_dev_core_err(core, "unknown smlu cgroup subsystem");
					break;
				}
			}

			/* found */
			if (ret == 0) {
				if (subsys == mem_cgrp_id) {
					/* amend vmm pid info */
					list_for_each_entry(pid_info_node, &post->vmm_pid_head, pid_list) {
						pid = pid_info_node->tgid;

						if (pid == mem_info->pid) {
							mem_info->phy_memused += pid_info_node->phy_usedsize;
							mem_info->virt_memused += pid_info_node->vir_usedsize;
							//break;/* FIXME each process only have single vmm pid_info_node? */
						}
					}
				}
				spin_unlock(&post->pid_lock);
				goto out;/* pid only match one namespace */
			}
			spin_unlock(&post->pid_lock);
		});
	}
out:
	up_read(&smlu_set->ns_rwsem);
	return ret;
}

/* num will be update to the real get item number */
int cn_smlu_query_namespace_pid_infos(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			u16 instance_id, int *num, struct smlu_proc_info *proc_info)
{
	struct smlu_set *smlu_set;
	struct pid_info_s *pid_info_node;
	struct proc_mem_info *mem_info = (struct proc_mem_info *)proc_info;
	struct cndev_process_ipuutil *ipuutil = (struct cndev_process_ipuutil *)proc_info;
	int i = 0;
	int ret = 0;

	if (!cn_is_smlu_en(core))
		return -EINVAL;

	if (!num || *num <= 0)
		return -EINVAL;

	smlu_set = core->smlu_set;

	down_read(&smlu_set->ns_rwsem);
	if (!cn_is_host_ns()) {
		struct smlu_cgroup *smlu_cgroup;

		smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, task_active_pid_ns(current));
		if (!smlu_cgroup) {
			cn_dev_core_err(core, "can't find smlu_cgroup of current_ns:%pK, maybe no process",
					task_active_pid_ns(current));
			ret = -ESRCH;
			goto out;
		}
		if (instance_id != 0 && smlu_cgroup->smlu_cap->instance_id != (int)instance_id) {
			cn_dev_core_debug(core, "input instance_id<%d> not match with current instance_id<%d>",
					(int)instance_id, smlu_cgroup->smlu_cap->instance_id);
			ret = -ESRCH;
			goto out;
		}
		spin_lock(&smlu_cgroup->pid_lock);
		if (list_empty(&smlu_cgroup->pid_head)) {
			spin_unlock(&smlu_cgroup->pid_lock);
			cn_dev_core_debug(core, "smlu_cgroup pid list is empty, rollback to the old way");
			ret = -ESRCH;
			goto out;
		}
		list_for_each_entry(pid_info_node, &smlu_cgroup->pid_head, pid_list) {
			switch (subsys) {
			case mem_cgrp_id:
				mem_info[i].pid = pid_info_node->active_pid;
				mem_info[i].phy_memused = pid_info_node->phy_usedsize;
				mem_info[i].virt_memused = pid_info_node->vir_usedsize;
				break;
			case ipu_cgrp_id:
				ipuutil[i].tgid = pid_info_node->active_pid;
				ipuutil[i].util = pid_info_node->ipu_util;
				break;
			default:
				cn_dev_core_err(core, "unknown smlu cgroup subsystem");
				break;
			}
			i++;
			if (i >= *num)
				break;
		}
		spin_unlock(&smlu_cgroup->pid_lock);
		*num = i;

		switch (subsys) {
		case mem_cgrp_id:
			/* different context inner a process could have more records in pid_info list */
			cndev_proc_info_combine(mem_info, num);

			/* amend vmm pid info, must after combine, otherwise it will count more than real */
			spin_lock(&smlu_cgroup->pid_lock);
			for (i = 0; i < (*num); i++) {
				int pid;

				list_for_each_entry(pid_info_node, &smlu_cgroup->vmm_pid_head, pid_list) {
					pid = pid_info_node->active_pid;
					if (mem_info[i].pid == pid) {
						mem_info[i].phy_memused += pid_info_node->phy_usedsize;
						mem_info[i].virt_memused += pid_info_node->vir_usedsize;
					}
				}
			}
			spin_unlock(&smlu_cgroup->pid_lock);
			break;
		case ipu_cgrp_id: {
			/* ipu remove duplicated pid outside */
			struct smlu_cap *smlu_cap = smlu_cgroup->smlu_cap;

			*((u32 *)(&ipuutil[*num])) = smlu_cap->resources[ipu_cgrp_id].usage * 100 / smlu_cap->resources[ipu_cgrp_id].max;
			break;
		}
		default:
			cn_dev_core_err(core, "unknown smlu cgroup subsystem");
			break;
		}
	} else {
		/* pf can see all pids, or just return fail which will rollback to the old way */
		tree_traverse_and_operate(smlu_set->ns_tree, smlu_cgroup, {
			if ((instance_id != 0 && post->smlu_cap->instance_id == (int)instance_id) || instance_id ==0) {
				spin_lock(&post->pid_lock);
				list_for_each_entry(pid_info_node, &post->pid_head, pid_list) {
					switch (subsys) {
					case mem_cgrp_id:
						mem_info[i].pid = pid_info_node->tgid;
						mem_info[i].phy_memused = pid_info_node->phy_usedsize;
						mem_info[i].virt_memused = pid_info_node->vir_usedsize;
						break;
					case ipu_cgrp_id:
						ipuutil[i].tgid = pid_info_node->tgid;
						ipuutil[i].util = pid_info_node->ipu_util;
						break;
					default:
						cn_dev_core_err(core, "unknown smlu cgroup subsystem");
						break;
					}
					i++;
					if (i >= *num) {
						spin_unlock(&post->pid_lock);
						goto enough;
					}
				}
				spin_unlock(&post->pid_lock);
			}
		});
enough:
		*num = i;

		switch (subsys) {
		case mem_cgrp_id:
			/* different context inner a process could have more records in pid_info list */
			cndev_proc_info_combine(mem_info, num);

			/* amend vmm pid info, must after combine, otherwise it will count more than real */
			for (i = 0; i < (*num); i++) {
				int pid;

				tree_traverse_and_operate(smlu_set->ns_tree, smlu_cgroup, {
					spin_lock(&post->pid_lock);
					list_for_each_entry(pid_info_node, &post->vmm_pid_head, pid_list) {
						pid = pid_info_node->tgid;
						if (mem_info[i].pid == pid) {
							mem_info[i].phy_memused += pid_info_node->phy_usedsize;
							mem_info[i].virt_memused += pid_info_node->vir_usedsize;
						}
					}
					spin_unlock(&post->pid_lock);
				});
			}
			break;
		case ipu_cgrp_id:
			/* ipu remove duplicated pid outside */
			*((u32 *)(&ipuutil[*num])) = smlu_set->total_util;
			break;
		default:
			cn_dev_core_err(core, "unknown smlu cgroup subsystem");
			break;
		}
	}

out:
	up_read(&smlu_set->ns_rwsem);
	return ret;
}

/* query the supported profile_id */
int cn_smlu_query_available_profile_id(struct cn_core_set *core,
					__u32 *profile_id,
					int *num)
{
	int i, profile_idx = 0;
	int max_profile_count;
	struct smlu_set *smlu_set;

	if (!core || !core->smlu_set) {
		cn_dev_core_err(core, "invalid core_set");
		return -EINVAL;
	}

	if (!cn_is_smlu_en(core)) {
		cn_dev_core_err(core, "operation not supported");
		return -EINVAL;
	}

	memset(profile_id, 0, sizeof(__u32) * (*num));
	smlu_set = core->smlu_set;
	max_profile_count = min((*num), (int)MAX_SMLU_PROFILE_COUNT);

	mutex_lock(&smlu_set->profile_lock);
	for (i = 0; i < max_profile_count; i++) {
		if (smlu_set->profile_desc_info[i].total_capacity) {
			profile_id[profile_idx] = smlu_set->profile_desc_info[i].profile_id;
			profile_idx++;
		}
	}
	mutex_unlock(&smlu_set->profile_lock);

	*num = profile_idx;

	return 0;
}

/* need use profile_lock to protect by called function */
int smlu_query_profile_remain_capacity(struct cn_core_set *core, __u32 profile_id)
{
	int i;
	struct smlu_set *smlu_set;
	struct smlu_cap *tmp;
	__u32 factor;
	__u64 total_quota, tmp_quota = 0;
	__u64 remain[SMLU_CGROUP_SUBSYS_COUNT];
	__u64 remain_quota[SMLU_CGROUP_SUBSYS_COUNT];
	__u64 req[SMLU_CGROUP_SUBSYS_COUNT];
	__u64 req_quota[SMLU_CGROUP_SUBSYS_COUNT];
	__u64 remain_capacity = MAX_SMLU_INSTANCE_COUNT;

	if (!core || !core->smlu_set) {
		cn_dev_core_err(core, "invalid core_set");
		return -EINVAL;
	}

	smlu_set = core->smlu_set;

	for (i = 0; i < SMLU_CGROUP_SUBSYS_COUNT; i++) {
		req[i] = smlu_set->profile_desc_info[profile_id].profile_res[i].max;
		factor = smlu_set->profile_desc_info[profile_id].profile_res[i].factor;
		req_quota[i] = req[i] * (100 + factor) / 100;

		read_lock(&smlu_set->quota_lock);
		remain[i] = smlu_set->total[i].max - smlu_set->total[i].usage;
		total_quota = smlu_set->total[i].max * (100 + SMLU_MAX_OVERCOMMIT_FACTOR) / 100;
		read_unlock(&smlu_set->quota_lock);

		mutex_lock(&smlu_set->caps_lock);
		list_for_each_entry(tmp, &smlu_set->caps_head, cap_node) {
			tmp_quota += tmp->resources[i].max * (100 + tmp->resources[i].factor) / 100;
		}
		mutex_unlock(&smlu_set->caps_lock);

		remain_quota[i] = total_quota - tmp_quota;
	}

	for (i = 0; i < SMLU_CGROUP_SUBSYS_COUNT; i++) {
		remain_capacity = min(remain_capacity, remain[i] / req[i]);
		remain_capacity = min(remain_capacity, remain_quota[i] / req_quota[i]);
	}

	return remain_capacity;;
}

int cn_smlu_query_profile_info(struct cn_core_set *core,
				__u32 profile_id,
				struct smlu_profile_info *info)
{
	int i;
	struct smlu_set *smlu_set;
	__u32 factor;
	__u64 max;

	if (!core || !core->smlu_set) {
		cn_dev_core_err(core, "invalid core_set");
		return -EINVAL;
	}

	if (!cn_is_smlu_en(core)) {
		cn_dev_core_debug(core, "operation not supported");
		return -EINVAL;
	}

	smlu_set = core->smlu_set;

	mutex_lock(&smlu_set->profile_lock);
	if (profile_id >= MAX_SMLU_PROFILE_COUNT ||
			!smlu_set->profile_desc_info[profile_id].total_capacity) {
		cn_dev_core_err(core, "invalid profile_id:%u", profile_id);
		mutex_unlock(&smlu_set->profile_lock);
		return -EINVAL;
	}

	info->profile_id = smlu_set->profile_desc_info[profile_id].profile_id;

	for (i = 0; i < SMLU_CGROUP_SUBSYS_COUNT; i++) {
		factor = smlu_set->profile_desc_info[profile_id].profile_res[i].factor;
		max = smlu_set->profile_desc_info[profile_id].profile_res[i].max;
		info->profile_res[i][SMLU_FACTOR] = factor;
		info->profile_res[i][SMLU_MAX] = max;
	}

	info->total_capacity = smlu_set->profile_desc_info[profile_id].total_capacity;
	info->remain_capacity = smlu_query_profile_remain_capacity(core, profile_id);
	memcpy(info->profile_name, smlu_set->profile_desc_info[profile_id].profile_name,
			CNDEV_MAX_PROFILE_NAME_SIZE);
	mutex_unlock(&smlu_set->profile_lock);

	return 0;
}

int cn_smlu_new_profile(struct cn_core_set *core,
			struct cndev_smlu_cgroup_info *res,
			struct smlu_profile_info *profile_info)
{
	int i, ret;
	__u32 total_capacity;
	struct smlu_set *smlu_set;

	if (!core || !core->smlu_set) {
		cn_dev_core_err(core, "invalid core_set");
		return -EINVAL;
	}

	if (!cn_is_smlu_en(core)) {
		cn_dev_core_err(core, "operation not supported");
		return -EINVAL;
	}

	smlu_set = core->smlu_set;

	// input quota validity check
	read_lock(&smlu_set->quota_lock);
	if (res->cgroup_item[SMLU_MEM][SMLU_MAX] > smlu_set->total[mem_cgrp_id].max ||
			res->cgroup_item[SMLU_MEM][SMLU_FACTOR] > SMLU_MAX_OVERCOMMIT_FACTOR ||
			res->cgroup_item[SMLU_IPU][SMLU_MAX] > smlu_set->total[ipu_cgrp_id].max ||
			res->cgroup_item[SMLU_IPU][SMLU_FACTOR] > SMLU_MAX_OVERCOMMIT_FACTOR) {
		cn_dev_core_err(core, "invalid profile quota, input quota exceed total res");
		read_unlock(&smlu_set->quota_lock);
		return -EINVAL;
	}
	read_unlock(&smlu_set->quota_lock);

	for (i = SMLU_CGROUP_SUBSYS_COUNT; i < SMLU_RES_COUNT; i++) {
		if (res->cgroup_item[i][SMLU_MAX] != 0 || res->cgroup_item[i][SMLU_FACTOR] != 0) {
			cn_dev_core_err(core, "invalid profile quota, exist not supported res type");
			return -EINVAL;
		}
	}

	// calculate total_capacity of the new profile
	read_lock(&smlu_set->quota_lock);
	total_capacity = smlu_set->total[mem_cgrp_id].max / res->cgroup_item[SMLU_MEM][SMLU_MAX];
	total_capacity = min((__u32)total_capacity, (__u32)(smlu_set->total[ipu_cgrp_id].max / res->cgroup_item[SMLU_IPU][SMLU_MAX]));
	read_unlock(&smlu_set->quota_lock);

	// new a profile by input quota info
	mutex_lock(&smlu_set->profile_lock);
	for (i = 0; i < MAX_SMLU_PROFILE_COUNT; i++) {
		if (smlu_set->profile_desc_info[i].total_capacity != 0)
			continue;

		memset(&smlu_set->profile_desc_info[i], 0, sizeof(struct smlu_profile_desc));

		smlu_set->profile_desc_info[i].profile_id = i;

		smlu_set->profile_desc_info[i].profile_res[mem_cgrp_id].max = res->cgroup_item[SMLU_MEM][SMLU_MAX];
		smlu_set->profile_desc_info[i].profile_res[mem_cgrp_id].factor = res->cgroup_item[SMLU_MEM][SMLU_FACTOR];

		smlu_set->profile_desc_info[i].profile_res[ipu_cgrp_id].max = res->cgroup_item[SMLU_IPU][SMLU_MAX];
		smlu_set->profile_desc_info[i].profile_res[ipu_cgrp_id].factor = res->cgroup_item[SMLU_IPU][SMLU_FACTOR];

		smlu_set->profile_desc_info[i].total_capacity = total_capacity;

		sprintf(smlu_set->profile_desc_info[i].profile_name,
			"%llup.%llumb", res->cgroup_item[SMLU_IPU][SMLU_MAX],
			res->cgroup_item[SMLU_MEM][SMLU_MAX] >> 20);
		break;
	}
	mutex_unlock(&smlu_set->profile_lock);

	if (i >= MAX_SMLU_PROFILE_COUNT) {
		cn_dev_core_err(core, "profile count exceeds the max supported:%d",
					MAX_SMLU_PROFILE_COUNT);
		return -ENOSPC;
	}

	ret = cn_smlu_query_profile_info(core, i, profile_info);
	if (ret) {
		cn_dev_core_err(core, "cn_smlu_query_profile_info failed");
		return -EFAULT;
	}

	return 0;
}

int cn_smlu_delete_profile(struct cn_core_set *core, __u32 profile_id)
{
	struct smlu_set *smlu_set;

	if (!core || !core->smlu_set) {
		cn_dev_core_err(core, "invalid core_set");
		return -EINVAL;
	}

	if (!cn_is_smlu_en(core)) {
		cn_dev_core_err(core, "operation not supported");
		return -EINVAL;
	}

	if (profile_id >= MAX_SMLU_PROFILE_COUNT) {
		cn_dev_core_err(core, "error profile_id, delete failed");
		return -EINVAL;
	}

	smlu_set = core->smlu_set;

	// delete profile by input profile_id
	mutex_lock(&smlu_set->profile_lock);
	if (smlu_set->profile_desc_info[profile_id].total_capacity == 0){
		cn_dev_core_err(core, "profile_id %u do not exist, delete failed", profile_id);
		mutex_unlock(&smlu_set->profile_lock);
		return -EINVAL;
	} else {
		smlu_set->profile_desc_info[profile_id].total_capacity = 0;
		cn_dev_core_info(core, "delete profile_id %u success", profile_id);
	}
	mutex_unlock(&smlu_set->profile_lock);

	return 0;
}

/* query one smlu cap's quota and usage info by instance id */
int cn_smlu_query_instance(struct cn_core_set *core, struct cndev_smlu_cgroup_info *cgroup_info)
{
	struct smlu_set *smlu_set;
	struct smlu_cap *smlu_cap;
	struct smlu_cgroup_subsys *ss;
	int cgrp_id = cgroup_info->cgrp_id;
	int subsys;
	int ret = -ENXIO;

	if (!cn_is_smlu_en(core))
		return -EINVAL;

	smlu_set = core->smlu_set;

	mutex_lock(&smlu_set->caps_lock);
	list_for_each_entry(smlu_cap, &smlu_set->caps_head, cap_node) {
		cn_dev_core_debug(core, "iter smlu cap node %u:%u, %s",
				smlu_cap->minor->major,
				smlu_cap->minor->index,
				dev_name(smlu_cap->minor->kdev));
		if (smlu_cap->instance_id == cgrp_id) {
			struct bus_info_s bus_info = {0};

			cn_bus_get_bus_info(core->bus_set, &bus_info);

			cgroup_info->profile_id = smlu_cap->profile_id;
			cgroup_info->bus = bus_info.info.pcie.bus_num;
			cgroup_info->device = (bus_info.info.pcie.device_id >> 3) & 0x1f;
			cgroup_info->function = bus_info.info.pcie.device_id & 0x07;
			cgroup_info->domain = bus_info.info.pcie.domain_id;
			memcpy(cgroup_info->uuid, core->board_info.uuid, DRIVER_PMU_UUID_SIZE);
			cgroup_info->uuid[9] = smlu_cap->instance_id;

			snprintf(cgroup_info->device_name, CNDEV_DEVICE_NAME_LEN, "/dev/cambricon-caps/cap_dev%d_mi%d",
				core->pf_idx, smlu_cap->instance_id);

			smlu_for_each_subsys(ss, subsys) {
				cn_dev_core_debug(core, "found cgrp_id[%d] subsys[%d]:%s quota = 0x%llx, usage = 0x%llx,"
					"overcommit factor = %d",
					cgrp_id, subsys, smlu_cgroup_subsys_name[subsys],
					smlu_cap->resources[subsys].max, smlu_cap->resources[subsys].usage,
					smlu_cap->resources[subsys].factor);

				cgroup_info->cgroup_item[subsys][SMLU_FACTOR]  = smlu_cap->resources[subsys].factor;
				cgroup_info->cgroup_item[subsys][SMLU_MAX] = smlu_cap->resources[subsys].max;
				if (subsys == ipu_cgrp_id) {
					cgroup_info->cgroup_item[subsys][SMLU_USAGE] = smlu_cap->resources[subsys].average; /* average for cnmon show */
				} else {
					cgroup_info->cgroup_item[subsys][SMLU_USAGE] = smlu_cap->resources[subsys].usage;
				}
			}
			ret = 0;
			break;
		}
	}
	mutex_unlock(&smlu_set->caps_lock);
	return ret;
}

/* query numbers of smlu caps' quota and usage info, num will be update to real get number if > total caps */
int cn_smlu_query_all_instances(struct cn_core_set *core, int *num, struct cndev_smlu_cgroup_info *cgroup_info)
{
	struct smlu_set *smlu_set;
	struct smlu_cap *smlu_cap;
	struct cndev_smlu_cgroup_info *iter;
	int i = 0;
	struct smlu_cgroup_subsys *ss;
	int subsys;
	struct bus_info_s bus_info = {0};
	int ret = -1;

	if (!cn_is_smlu_en(core))
		return -EINVAL;

	if (!num || *num <= 0)
		return -EINVAL;

	cn_bus_get_bus_info(core->bus_set, &bus_info);

	smlu_set = core->smlu_set;

	mutex_lock(&smlu_set->caps_lock);
	list_for_each_entry(smlu_cap, &smlu_set->caps_head, cap_node) {
		cn_dev_core_debug(core, "iter smlu cap node %u:%u, %s",
				smlu_cap->minor->major,
				smlu_cap->minor->index,
				dev_name(smlu_cap->minor->kdev));

		iter = &cgroup_info[i];
		iter->profile_id = smlu_cap->profile_id;
		iter->cgrp_id = smlu_cap->instance_id;
		iter->bus = bus_info.info.pcie.bus_num;
		iter->device = (bus_info.info.pcie.device_id >> 3) & 0x1f;
		iter->function = bus_info.info.pcie.device_id & 0x07;
		iter->domain = bus_info.info.pcie.domain_id;
		memcpy(iter->uuid, core->board_info.uuid, DRIVER_PMU_UUID_SIZE);
		iter->uuid[9] = smlu_cap->instance_id;

		snprintf(iter->device_name, CNDEV_DEVICE_NAME_LEN, "/dev/cambricon-caps/cap_dev%d_mi%d",
				core->pf_idx, smlu_cap->instance_id);

		smlu_for_each_subsys(ss, subsys) {
			cn_dev_core_debug(core, "subsys[%d]:%s quota = 0x%llx, usage = 0x%llx,"
				"overcommit factor = %d",
				subsys, smlu_cgroup_subsys_name[subsys],
				smlu_cap->resources[subsys].max, smlu_cap->resources[subsys].usage,
				smlu_cap->resources[subsys].factor);

			iter->cgroup_item[subsys][SMLU_FACTOR] = smlu_cap->resources[subsys].factor;
			iter->cgroup_item[subsys][SMLU_MAX] = smlu_cap->resources[subsys].max;
			if (subsys == ipu_cgrp_id) {
				iter->cgroup_item[subsys][SMLU_USAGE] = smlu_cap->resources[subsys].average; /* average for cnmon show */
			} else {
				iter->cgroup_item[subsys][SMLU_USAGE] = smlu_cap->resources[subsys].usage;
			}

		}
		i++;
		if (i >= *num)
			break;
	}
	*num = i;//update the real item number
	ret = 0;
	mutex_unlock(&smlu_set->caps_lock);

	return ret;
}

int cn_smlu_cap_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct smlu_set *smlu_set = core->smlu_set;
	struct smlu_cap *smlu_cap;
	struct pid_info_s *pid_info_node;
	struct task_struct *task = NULL;
	char buf[TASK_COMM_LEN];
	struct smlu_cgroup_subsys *ss;
	int i;

	if (!cn_is_smlu_support(core))
		return -EINVAL;

	smlu_set = core->smlu_set;

	seq_printf(m, "smlu_support:%d smlu_enable:%d\n", cn_is_smlu_support(core), cn_is_smlu_en(core));
	read_lock(&smlu_set->quota_lock);
	smlu_for_each_subsys(ss, i) {
		seq_printf(m, "subsys[%d]:%s total = %lld, usage = %lld, overcommit factor = %d\n",
			i, smlu_cgroup_subsys_name[i],
			smlu_set->total[i].max, smlu_set->total[i].usage, smlu_set->total[i].factor);
	}
	read_unlock(&smlu_set->quota_lock);

	seq_puts(m, "\n");

	if (!cn_is_host_ns()) {
		struct smlu_cgroup *smlu_cgroup;

		down_read(&smlu_set->ns_rwsem);
		smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, task_active_pid_ns(current));
		if (!smlu_cgroup) {
			seq_printf(m, "current_ns:%pK not bind any smlu_cgroup.\n", task_active_pid_ns(current));
			up_read(&smlu_set->ns_rwsem);
			return 0;
		}
		seq_printf(m, "smlu_cgroup:%pK, namespace:%pK, ", smlu_cgroup, smlu_cgroup->active_ns);

		smlu_cap = smlu_cgroup->smlu_cap;
		if (likely(smlu_cap->minor)) {
			seq_printf(m, "binded cap node %u:%u, %s, ",
						smlu_cap->minor->major,
						smlu_cap->minor->index,
						dev_name(smlu_cap->minor->kdev));
			seq_printf(m, "profile_id:%d, instance_id:%d", smlu_cap->profile_id, smlu_cap->instance_id);
		}
		seq_puts(m, "\n");

		smlu_for_each_subsys(ss, i) {
			seq_printf(m, "----subsys[%d]:%s quota = %lld, usage = %lld, overcommit factor = %d\n",
				i, smlu_cgroup_subsys_name[i],
				smlu_cap->resources[i].max, smlu_cap->resources[i].usage,
				smlu_cap->resources[i].factor);
		}

		spin_lock(&smlu_cgroup->pid_lock);
		seq_puts(m, "mm:\n");
		list_for_each_entry(pid_info_node, &smlu_cgroup->pid_head, pid_list) {
			task = get_pid_task(find_vpid(pid_info_node->active_pid), PIDTYPE_PID);
			if (task) {
				get_task_comm(buf, task);
				put_task_struct(task);
			}
			seq_printf(m, "\tpid:%d comm:%s, mem used:%lld\n",
				pid_info_node->active_pid, task ? buf : "unknown", pid_info_node->phy_usedsize);
		}
		seq_puts(m, "vmm:\n");
		list_for_each_entry(pid_info_node, &smlu_cgroup->vmm_pid_head, pid_list) {
			task = get_pid_task(find_vpid(pid_info_node->active_pid), PIDTYPE_PID);
			if (task) {
				get_task_comm(buf, task);
				put_task_struct(task);
			}
			seq_printf(m, "\tpid:%d comm:%s, vmm mem used:%lld\n",
				pid_info_node->active_pid, task ? buf : "unknown", pid_info_node->phy_usedsize);
		}
		seq_puts(m, "mlu:\n");
		list_for_each_entry(pid_info_node, &smlu_cgroup->pid_head, pid_list) {
			task = get_pid_task(find_vpid(pid_info_node->active_pid), PIDTYPE_PID);
			if (task) {
				get_task_comm(buf, task);
				put_task_struct(task);
			}
			seq_printf(m, "\tpid:%d comm:%s, mlu used:%lld\n",
				pid_info_node->active_pid, task ? buf : "unknown", pid_info_node->ipu_util / 1000);
		}
		spin_unlock(&smlu_cgroup->pid_lock);
		seq_printf(m, "namespace ipu_util:%lld\n", smlu_cgroup->ns_util / 1000);
		up_read(&smlu_set->ns_rwsem);
	} else {
		seq_puts(m, "------------instance info------------\n");
		mutex_lock(&smlu_set->caps_lock);
		list_for_each_entry(smlu_cap, &smlu_set->caps_head, cap_node) {
			if (likely(smlu_cap->minor)) {
				seq_printf(m, "--smlu cap node %u:%u, %s, ",
					smlu_cap->minor->major,
					smlu_cap->minor->index,
					dev_name(smlu_cap->minor->kdev));
				seq_printf(m, "profile_id:%d, instance_id:%d\n", smlu_cap->profile_id, smlu_cap->instance_id);
			}
			smlu_for_each_subsys(ss, i) {
				seq_printf(m, "----subsys[%d]:%s quota = %lld, usage = %lld, overcommit factor = %d\n",
					i, smlu_cgroup_subsys_name[i],
					smlu_cap->resources[i].max, smlu_cap->resources[i].usage,
					smlu_cap->resources[i].factor);
			}
			seq_puts(m, "\n");
		}
		mutex_unlock(&smlu_set->caps_lock);

		seq_puts(m, "\n");

		seq_puts(m, "------------namespace info------------\n");
		down_read(&smlu_set->ns_rwsem);
		tree_traverse_and_operate(smlu_set->ns_tree, smlu_cgroup, {
			seq_printf(m, "--smlu_cgroup:%pK, namespace:%pK, ", post, post->active_ns);

			smlu_cap = post->smlu_cap;
			if (likely(smlu_cap->minor)) {
				seq_printf(m, "binded cap node %u:%u, %s ",
					smlu_cap->minor->major,
					smlu_cap->minor->index,
					dev_name(smlu_cap->minor->kdev));
			}
			seq_puts(m, "\n");

			spin_lock(&post->pid_lock);
			seq_puts(m, "mm:\n");
			list_for_each_entry(pid_info_node, &post->pid_head, pid_list) {
				task = get_pid_task(find_vpid(pid_info_node->tgid), PIDTYPE_PID);
				if (task) {
					get_task_comm(buf, task);
					put_task_struct(task);
				}
				seq_printf(m, "\ttgid:%d active_pid:%d comm:%s, mem used:%lld\n",
					pid_info_node->tgid, pid_info_node->active_pid,
					task ? buf : "unknown", pid_info_node->phy_usedsize);
			}
			seq_puts(m, "vmm:\n");
			list_for_each_entry(pid_info_node, &post->vmm_pid_head, pid_list) {
				task = get_pid_task(find_vpid(pid_info_node->tgid), PIDTYPE_PID);
				if (task) {
					get_task_comm(buf, task);
					put_task_struct(task);
				}
				seq_printf(m, "\ttgid:%d active_pid:%d comm:%s, vmm mem used:%lld\n",
					pid_info_node->tgid, pid_info_node->active_pid,
					task ? buf : "unknown", pid_info_node->phy_usedsize);
			}
			seq_puts(m, "mlu:\n");
			list_for_each_entry(pid_info_node, &post->pid_head, pid_list) {
				task = get_pid_task(find_vpid(pid_info_node->tgid), PIDTYPE_PID);
				if (task) {
					get_task_comm(buf, task);
					put_task_struct(task);
				}
				seq_printf(m, "\ttgid:%d active_pid:%d comm:%s, mlu used:%lld\n",
					pid_info_node->tgid, pid_info_node->active_pid,
					task ? buf : "unknown", pid_info_node->ipu_util / 1000);
			}
			spin_unlock(&post->pid_lock);
			seq_printf(m, "namespace ipu_util:%lld\n", post->ns_util / 1000);
			seq_puts(m, "\n");
		});

		seq_printf(m, "ipu_chip_util:%d\n", smlu_set->total_util);
		up_read(&smlu_set->ns_rwsem);
	}
	return 0;
}

void cn_smlu_get_sub_dev_info(struct cn_core_set *core, struct dev_info_s *sub_dev_info)
{
	struct smlu_set *smlu_set = core->smlu_set;
	struct smlu_cap *smlu_cap;
	struct cnhost_minor *minor;
	dev_t devt;
	int idx = 0;

	if (!cn_is_smlu_en(core))
		return;

	mutex_lock(&smlu_set->caps_lock);
	list_for_each_entry(smlu_cap, &smlu_set->caps_head, cap_node) {
		minor = smlu_cap->minor;
		devt = cnhost_dev_get_devt(minor->dev);
		sub_dev_info->unique_id[idx] = (uint64_t)devt;
		idx++;
	}
	mutex_unlock(&smlu_set->caps_lock);
	sub_dev_info->dev_num = idx;
}

struct cn_core_set *cn_smlu_get_core(struct cnhost_minor *minor)
{
	struct smlu_cap *smlu_cap;

	smlu_cap = (struct smlu_cap *)(minor->dev->dev_private);
	return smlu_cap->core;
}

/* called with smlu_cgroup->pid_lock */
int smlu_cgroup_is_fp_valid(struct smlu_cgroup *smlu_cgroup, struct file *filp)
{
	struct pid_info_s *pid_info_node;

	if (unlikely(!filp))
		return 0;

	list_for_each_entry(pid_info_node, &smlu_cgroup->pid_head, pid_list) {
		if (pid_info_node->fp == filp) {
			return 1;
		}
	}

	list_for_each_entry(pid_info_node, &smlu_cgroup->vmm_pid_head, pid_list) {
		if (pid_info_node->fp == filp) {
			WARN_ON(!file_is_cndev(filp));
			return 2;
		}
	}
	return 0;
}

int smlu_util_data_raw_update(struct smlu_cap *smlu_cap, enum util_type type)
{
	struct cn_core_set *core = NULL;
	int card_id, instance_id;

	if (!smlu_cap || !smlu_cap->core) {
		cn_dev_core_err(core, "invalid smlu_cap");
		return -1;
	}

	core = smlu_cap->core;
	card_id = core->idx;
	instance_id = smlu_cap->instance_id;

	switch (type) {
	case IPU_UTIL:
		ex_util_data[card_id][instance_id][type].util_target = smlu_cap->resources[ipu_cgrp_id].max;
		ex_util_data[card_id][instance_id][type].util_usage = smlu_cap->resources[ipu_cgrp_id].usage;
		break;
	// vpu_cgrp_id is to be adapted
	// case VPU_UTIL:
	// 	ex_util_data[card_id][instance_id][type].util_target = smlu_cap->resources[vpu_cgrp_id].max;
	// 	ex_util_data[card_id][instance_id][type].util_usage = smlu_cap->resources[vpu_cgrp_id].usage;
	// 	break;
	default:
		cn_dev_core_err(core, "invalid type: %d", type);
		return -1;
	}

	return 0;
}

void cn_smlu_get_util_adjust_fn(struct cn_core_set *core)
{
	struct smlu_set *smlu_set = core->smlu_set;
	void *output = NULL;

	if (!ex_smlu_util_adjust_module.smlu_util_adjust_module) {
		cn_dev_core_warn(core,
			"smlu need insmod cambricon-util_drv.ko to adjust utilization rate");
		goto no_smlu_util_module;
	}

	mutex_lock(&smlu_util_module_lock);
	switch (module_refcount((struct module *)ex_smlu_util_adjust_module.smlu_util_adjust_module)) {
	case -1: /* module is in process of unloading */
		cn_dev_core_warn(core, "smlu util adjust module is unloading, not support util adjust now");
		goto smlu_util_module_unlock;
	case 0: /* first open, increase refcnt of cambricon-util_drv.ko */
	default: /* not first open */
		break;
	}

	if (try_module_get((struct module *)ex_smlu_util_adjust_module.smlu_util_adjust_module)) {
		output = (void *)ex_smlu_util_adjust_module.smlu_util_adjust_output;
		cn_dev_core_debug(core, "output=%p", output);
	} else {
		cn_dev_core_warn(core, "get smlu util adjust module failed");
	}

smlu_util_module_unlock:
	mutex_unlock(&smlu_util_module_lock);

no_smlu_util_module:
	smlu_set->util_output_fn = output;
}

void cn_smlu_put_util_adjust_fn(struct cn_core_set *core)
{
	struct smlu_set *smlu_set = core->smlu_set;

	if (smlu_set->util_output_fn == NULL)
		return;

	mutex_lock(&smlu_util_module_lock);
	if (module_refcount((struct module *)ex_smlu_util_adjust_module.smlu_util_adjust_module) == 1) {
		smlu_set->util_output_fn = NULL;
	}

	module_put((struct module *)ex_smlu_util_adjust_module.smlu_util_adjust_module);
	mutex_unlock(&smlu_util_module_lock);
}

long cn_smlu_util_adjust_output(struct cn_core_set *core,
	void *smlu_cap, enum util_type type)
{
	struct smlu_set *smlu_set = core->smlu_set;
	struct smlu_cap *cap = (struct smlu_cap *)smlu_cap;
	ex_output_fn fn;
	long ret;

	if (smlu_set->util_output_fn == NULL) {
		/*
		 * if cambricon-util_drv.ko not insmod, return -ENODEV,
		 * make sure invoke kernel not block. The result is that
		 * it has no ipu util adjust function.
		 */
		return -ENODEV;
	}

	fn = (ex_output_fn)(smlu_set->util_output_fn);
	ret = fn(core->idx, cap->instance_id, type);

	return ret;
}
