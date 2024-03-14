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
#include <linux/bitops.h>
#include <linux/rbtree.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include "cndrv_cap.h"
#include "smlu_internal.h"

/* insert_smlucg_rb_node */
INSERT_RB_NODE_OPS(smlu_cgroup, active_ns, smlucg);
/* delete_smlucg_rb_node */
DELETE_RB_NODE_OPS(smlu_cgroup, smlucg);
/* search_smlucg_rb_node */
SEARCH_RB_NODE_OPS(smlu_cgroup, active_ns, smlucg);


struct tid_cap_node *smlu_find_tid_cap_node(struct cn_core_set *core)
{
	struct list_head *tid_cap_list_head = &core->tid_cap_list_head;
	struct mutex *tid_cap_lock = &core->tid_cap_lock;
	struct tid_cap_node *tid_cap_node = NULL;
	int found = 0;

	mutex_lock(tid_cap_lock);
	list_for_each_entry(tid_cap_node, tid_cap_list_head, list) {
		if (tid_cap_node->pid == current->pid) {
			found = 1;
			break;
		}
	}
	mutex_unlock(tid_cap_lock);
	return found ? tid_cap_node : NULL;
}

static struct smlu_cgroup *smlu_cgroup_alloc_and_bind_locked(struct smlu_cap *smlu_cap)
{
	struct cn_core_set *core = smlu_cap->core;
	struct smlu_set *smlu_set = core->smlu_set;
	struct cnhost_minor *minor = smlu_cap->minor;
	struct smlu_cgroup *smlu_cgroup;
	struct pid_namespace *active_ns = task_active_pid_ns(current);

	smlu_cgroup = cn_kzalloc(sizeof(struct smlu_cgroup), GFP_KERNEL);
	if (!smlu_cgroup) {
		cn_dev_core_err(core, "smlu_cgroup alloc failed when bind new namespace:%pK", active_ns);
		return ERR_PTR(-ENOMEM);
	}
	smlu_cgroup->active_ns = active_ns;
	smlu_cgroup->smlu_cap = smlu_cap;
	INIT_LIST_HEAD(&smlu_cgroup->pid_head);
	INIT_LIST_HEAD(&smlu_cgroup->vmm_pid_head);
	spin_lock_init(&smlu_cgroup->pid_lock);
	/* insert smlu_cgroup to rbtree */
	insert_smlucg_rb_node(&smlu_set->ns_tree, smlu_cgroup);
	cn_dev_core_info(core, "cap_node: %s binded a new namespace:%pK", dev_name(minor->kdev), active_ns);

	return smlu_cgroup;
}

/*
 * called by cn_core_open()
 */
int smlu_cap_bind_namespace(struct cn_core_set *core)
{
	struct tid_cap_node *tid_cap_node;
	struct inode *smlu_cap_inode;
	struct cnhost_minor *minor;
	struct smlu_set *smlu_set = core->smlu_set;
	struct smlu_cap *smlu_cap;
	struct smlu_cgroup *smlu_cgroup;
	struct pid_namespace *active_ns = task_active_pid_ns(current);
	int ret = 0;

	cn_dev_core_debug(core, ">>>>>>>>>>");

	/* sanity check again */
	if (!cn_is_smlu_en(core))
		return 0;

	tid_cap_node = smlu_find_tid_cap_node(core);
	if (tid_cap_node) {
		smlu_cap_inode = tid_cap_node->inode;
		minor = cnhost_dev_minor_acquire(imajor(smlu_cap_inode),
						iminor(smlu_cap_inode));
		if (IS_ERR(minor)) {
			return PTR_ERR(minor);
		}

		smlu_cap = (struct smlu_cap *)(minor->dev->dev_private);
		down_write(&smlu_set->ns_rwsem);
		smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, active_ns);
		if (!smlu_cgroup) {
			smlu_cgroup = smlu_cgroup_alloc_and_bind_locked(smlu_cap);
			if (IS_ERR_OR_NULL(smlu_cgroup)) {
				goto err_unlock;
			}
		} else {
			struct smlu_cap *tmp = smlu_cgroup->smlu_cap;

			if (tmp->minor == minor) {
				cn_dev_core_debug(core, "cap_node: %s already binded this namespace", dev_name(minor->kdev));
			} else {
				/* current namespace no process use the old smlu_cap */
				spin_lock(&smlu_cgroup->pid_lock);
				if (list_empty(&smlu_cgroup->pid_head)) {
					cn_dev_core_info(core, "namespace:%pK cap_node changing: %s -> %s",
						active_ns, dev_name(tmp->minor->kdev), dev_name(minor->kdev));

					smlu_cgroup->smlu_cap = smlu_cap;
				} else {
					cn_dev_core_err(core, "this namespace:%pK already binded a cap_node: %s, can't bind this cap_node:%s",
						active_ns, dev_name(tmp->minor->kdev), dev_name(minor->kdev));
					ret = -EEXIST;
					spin_unlock(&smlu_cgroup->pid_lock);
					goto err_unlock;
				}
				spin_unlock(&smlu_cgroup->pid_lock);
			}
		}
		up_write(&smlu_set->ns_rwsem);
		cnhost_dev_minor_release(minor);
	} else {
		/* closed cap node before open /dev/cambricon_dev, maybe driver-api enumerates all nodes */
		/* try it in case delay unbind */
		smlu_cgroup = search_smlucg_rb_node(&smlu_set->ns_tree, active_ns);
		if (smlu_cgroup) {
			struct smlu_cap *last = smlu_cgroup->smlu_cap;

			cn_dev_core_debug(core, "still bind the last cap_node: %s", dev_name(last->minor->kdev));
		}
	}

	cn_dev_core_debug(core, "<<<<<<<<<<");
	return 0;

err_unlock:
	up_write(&smlu_set->ns_rwsem);
	cnhost_dev_minor_release(minor);
	return ret;
}

/*
 * When bind sMLU instance, need open smlu_cap node first, and then open
 * cambricon_dev OR cambricon_ipcm node. Error will be reported if
 * open smlu_cap node of a same device twice continuously.
 */
int smlu_cap_open(struct inode *inode, struct file *fp)
{
	struct cn_core_set *core;
	struct tid_cap_node *tid_cap_node;
	struct cnhost_minor *minor;
	struct smlu_cap *smlu_cap;
	struct mi_cap_fp_priv_data *priv_data;
	struct list_head *tid_cap_list_head;
	struct mutex *tid_cap_lock;
	int ret = 0;

	minor = cnhost_dev_minor_acquire(imajor(inode), iminor(inode));
	if (IS_ERR(minor))
		return PTR_ERR(minor);

	smlu_cap = (struct smlu_cap *)(minor->dev->dev_private);
	core = smlu_cap->core;
	if (core->state == CN_RESET) {
		cn_dev_err("core is under reset");
		ret = -ENODEV;
		goto release_minor;
	}

	/* smlu could be turn off without destroy cap node. (only if nobody open devnode) */
	if (!cn_is_smlu_en(core)) {
		ret = -EPERM;
		goto release_minor;
	}

	tid_cap_list_head = &core->tid_cap_list_head;
	tid_cap_lock = &core->tid_cap_lock;

	/* sanity check */
	if (smlu_find_tid_cap_node(core)) {
		cn_dev_core_err(core, "open smlu_cap node twice or not closed last time");
		ret = -EEXIST;
		goto release_minor;
	}

	tid_cap_node = cn_kzalloc(sizeof(*tid_cap_node), GFP_KERNEL);
	if (!tid_cap_node) {
		cn_dev_core_err(core, "malloc tid_cap_node failed");
		ret = -ENOMEM;
		goto release_minor;
	}

	tid_cap_node->inode = inode;
	tid_cap_node->pid = current->pid;

	priv_data = cn_kzalloc(sizeof(struct mi_cap_fp_priv_data), GFP_KERNEL);
	if (!priv_data) {
		cn_dev_core_err(core, "malloc priv_data fail");
		ret = -ENOMEM;
		goto err;
	}

	mutex_lock(tid_cap_lock);
	list_add_tail(&tid_cap_node->list, tid_cap_list_head);
	mutex_unlock(tid_cap_lock);

	priv_data->core = core;
	priv_data->minor = minor;/* use to find smlu_cap when bind */
	priv_data->tid_cap_node = tid_cap_node;
	fp->private_data = (void *)priv_data;

	return 0;

err:
	cn_kfree(tid_cap_node);
release_minor:
	cnhost_dev_minor_release(minor);
	return ret;
}

int smlu_cap_close(struct inode *inode, struct file *fp)
{
	struct mi_cap_fp_priv_data *priv_data = fp->private_data;
	struct tid_cap_node *tid_cap_node;
	struct cnhost_minor *minor;
	struct cn_core_set *core;
	struct mutex *tid_cap_lock;

	tid_cap_node = priv_data->tid_cap_node;
	core = priv_data->core;

	tid_cap_lock = &core->tid_cap_lock;
	mutex_lock(tid_cap_lock);
	list_del(&tid_cap_node->list);
	mutex_unlock(tid_cap_lock);
	cn_kfree(tid_cap_node);

	minor = priv_data->minor;
	cnhost_dev_minor_release(minor);

	cn_kfree(priv_data);
	fp->private_data = NULL;

	return 0;
}

static int smlu_cap_get_instance_pcie_info(struct file *fp,
			struct cn_core_set *core,
			unsigned int cmd,
			unsigned long arg)
{
	struct bus_info_s bus_info = {0};

	cn_bus_get_bus_info(core->bus_set, &bus_info);
	if (copy_to_user((void *)arg, (void *)&bus_info,
			sizeof(struct bus_info_s))) {
		cn_dev_core_err(core, "copy_to_user failed.");
		return -EFAULT;
	}

	return 0;
}

static int smlu_cap_get_instance_unique_id(struct file *fp,
				struct cn_core_set *core,
				unsigned int cmd,
				unsigned long arg)
{
	struct inode *inode = fp->f_inode;
	uint64_t unique_id = inode->i_rdev;

	if (copy_to_user((void *)arg, (void *)&unique_id, sizeof(unique_id))) {
		cn_dev_core_err(core, "copy_to_user failed.");
		return -EFAULT;
	}

	return 0;
}

static long smlu_cap_ioctl(struct file *fp, unsigned int cmd,
			unsigned long arg)
{
	struct mi_cap_fp_priv_data *priv_data = fp->private_data;
	struct cnhost_minor *minor = priv_data->minor;
	struct smlu_cap *smlu_cap = (struct smlu_cap *)(minor->dev->dev_private);
	struct cn_core_set *core = smlu_cap->core;
	struct smlu_set *smlu_set;
	int ret = 0;

	/* smlu could be turn off without destroy cap node. (only if nobody open devnode) */
	if (!cn_is_smlu_en(core))
		return -EPERM;

	smlu_set = core->smlu_set;

	switch(cmd) {
	case SMLU_CAP_GET_INSTANCE_PCIE_INFO: {
		ret = smlu_cap_get_instance_pcie_info(fp, core, cmd, arg);
		break;
	}
	case SMLU_CAP_GET_INSTANCE_UNIQUE_ID: {
		ret = smlu_cap_get_instance_unique_id(fp, core, cmd, arg);
		break;
	}
	default:
		cn_dev_core_err(core,
			"IOCTRL command# %d is invalid!", _IOC_NR(cmd));
		ret = -EINVAL;
	}

	return ret;
}

/* query from cndev_card_get_smlu_info_common(), so not provide ioctl here */
static const struct file_operations smlu_cap_fops = {
	.owner = THIS_MODULE,
	.open = smlu_cap_open,
	.release = smlu_cap_close,
	.unlocked_ioctl = smlu_cap_ioctl,
	.compat_ioctl = smlu_cap_ioctl,
};

static const struct cnhost_driver cndrv_smlu_cap_drv = {
	.fops = &smlu_cap_fops,
	.name = "cambricon-cap",
};

static int smlu_cap_get_cap_num(struct cn_core_set *core)
{
	struct smlu_set *smlu_set;
	struct smlu_cap *smlu_cap;
	int idx = 0;

	if (!cn_is_smlu_en(core))
		return 0;

	smlu_set = core->smlu_set;
	mutex_lock(&smlu_set->caps_lock);
	list_for_each_entry(smlu_cap, &smlu_set->caps_head, cap_node) {
		idx++;
	}
	mutex_unlock(&smlu_set->caps_lock);
	return idx;
}

/*
 * 1.new a smlu_cap to stashed quota data, add to the total.usage, all partitions must < total.max resource.
 * 2.add a device node.
 * [in] resource quota data.
 * [out] minor as smlu instance id.
 */
int cn_smlu_cap_node_init(struct cn_core_set *core, struct cndev_smlu_cgroup_info *res)
{
	struct smlu_cap *smlu_cap, *tmp;
	struct cnhost_device *ddev;
	struct smlu_set *smlu_set;
	int instance_id;
	int ret = 0;

	if (unlikely(!core) || !cn_is_smlu_en(core)) {
		cn_dev_err("core invalid or not support/enable smlu");
		return -EINVAL;
	}

	if (!cn_is_host_ns()) {
		cn_dev_core_err(core, "Denied create mlu_cap node in docker");
		return -EACCES;
	}

	if (smlu_cap_get_cap_num(core) > MAX_SMLU_INSTANCE_COUNT) {
		cn_dev_core_err(core, "too many smlu_cap");
		return -EFAULT; /* -EFAULT represents exceed, be consistent with cnmon */
	}

	smlu_set = core->smlu_set;

	smlu_cap = cn_kzalloc(sizeof(struct smlu_cap), GFP_KERNEL);
	if (!smlu_cap) {
		cn_dev_core_err(core, "smlu_cap alloc failed");
		return -ENOMEM;
	}

	instance_id = ida_simple_get(&smlu_set->instance_ida, 1, 0, GFP_KERNEL);
	if (instance_id < 0) {
		cn_dev_core_err(core, "instance_id alloc failed");
		goto free_smlu_cap;
	}

	mutex_lock(&smlu_set->caps_lock);
	write_lock(&smlu_set->quota_lock);
	if (res->cgroup_item[SMLU_IPU][SMLU_MAX]) {
		/* ipu_util percentage */
		__u64 remain = smlu_set->total[ipu_cgrp_id].max - smlu_set->total[ipu_cgrp_id].usage;
		__u64 total_quota = smlu_set->total[ipu_cgrp_id].max * (100 + SMLU_MAX_OVERCOMMIT_FACTOR) / 100;
		__u64 req_quota = 0;
		__u64 remain_quota = 0;

		list_for_each_entry(tmp, &smlu_set->caps_head, cap_node) {
			remain_quota += tmp->resources[ipu_cgrp_id].max * (100 + tmp->resources[ipu_cgrp_id].factor) / 100;
		}

		remain_quota = total_quota - remain_quota;
		req_quota = res->cgroup_item[SMLU_IPU][SMLU_MAX] * (100 + res->cgroup_item[SMLU_IPU][SMLU_FACTOR]) / 100;

		if (res->cgroup_item[SMLU_IPU][SMLU_MAX] <= remain && req_quota <= remain_quota) {
			smlu_set->total[ipu_cgrp_id].usage += res->cgroup_item[SMLU_IPU][SMLU_MAX];
			smlu_cap->resources[ipu_cgrp_id].max = res->cgroup_item[SMLU_IPU][SMLU_MAX];
			smlu_cap->resources[ipu_cgrp_id].factor = res->cgroup_item[SMLU_IPU][SMLU_FACTOR];
			cn_dev_core_info(core, "smlu add cap:ipu %lld, remain:%lld",
					res->cgroup_item[SMLU_IPU][SMLU_MAX], remain - res->cgroup_item[SMLU_IPU][SMLU_MAX]);
		} else {
			cn_dev_core_err(core, "smlu_cap ipu exceed! req=%lld:%lld, total=%lld:%lld, avail=%lld:%lld",
					res->cgroup_item[SMLU_IPU][SMLU_MAX], req_quota,
					smlu_set->total[ipu_cgrp_id].max, total_quota,
					remain, remain_quota);
			ret = -EFAULT;
			goto err_update;
		}
	} else {
		smlu_cap->resources[ipu_cgrp_id].max = smlu_set->total[ipu_cgrp_id].max;
		smlu_cap->resources[ipu_cgrp_id].factor = 0;
	}

	if (res->cgroup_item[SMLU_MEM][SMLU_MAX]) {
		__u64 remain = smlu_set->total[mem_cgrp_id].max - smlu_set->total[mem_cgrp_id].usage;
		__u64 total_quota = smlu_set->total[mem_cgrp_id].max * (100 + SMLU_MAX_OVERCOMMIT_FACTOR) / 100;
		__u64 req_quota = 0;
		__u64 remain_quota = 0;

		list_for_each_entry(tmp, &smlu_set->caps_head, cap_node) {
			remain_quota += tmp->resources[mem_cgrp_id].max * (100 + tmp->resources[mem_cgrp_id].factor) / 100;
		}

		remain_quota = total_quota - remain_quota;
		req_quota = res->cgroup_item[SMLU_MEM][SMLU_MAX] * (100 + res->cgroup_item[SMLU_MEM][SMLU_FACTOR]) / 100;

		if (res->cgroup_item[SMLU_MEM][SMLU_MAX] <= remain && req_quota <= remain_quota) {
			smlu_set->total[mem_cgrp_id].usage += res->cgroup_item[SMLU_MEM][SMLU_MAX];
			smlu_cap->resources[mem_cgrp_id].max = res->cgroup_item[SMLU_MEM][SMLU_MAX];
			smlu_cap->resources[mem_cgrp_id].factor = res->cgroup_item[SMLU_MEM][SMLU_FACTOR];
			cn_dev_core_info(core, "smlu add cap:mem %lld, remain:%lld",
					res->cgroup_item[SMLU_MEM][SMLU_MAX], remain - res->cgroup_item[SMLU_MEM][SMLU_MAX]);
		} else {
			cn_dev_core_err(core, "smlu_cap mem exceed! req=%lld:%lld, total=%lld:%lld, avail=%lld:%lld",
					res->cgroup_item[SMLU_MEM][SMLU_MAX], req_quota,
					smlu_set->total[mem_cgrp_id].max, total_quota,
					remain, remain_quota);
			ret = -EFAULT;
			/* restore */
			smlu_set->total[ipu_cgrp_id].usage -= res->cgroup_item[SMLU_IPU][SMLU_MAX];
			goto err_update;
		}
	} else {
		smlu_cap->resources[mem_cgrp_id].max = smlu_set->total[mem_cgrp_id].max;
		smlu_cap->resources[mem_cgrp_id].factor = 0;
	}
	write_unlock(&smlu_set->quota_lock);
	mutex_unlock(&smlu_set->caps_lock);

	/* add device node */
	ddev = cnhost_dev_alloc(&cndrv_smlu_cap_drv, smlu_cap, CNHOST_DEV_MINOR_SMLU_CAP, core->pf_idx, instance_id);
	if (IS_ERR(ddev)) {
		ret = PTR_ERR(ddev);
		goto free_ida;
	}
	ret = cnhost_dev_register(ddev, 0);
	if (ret) {
		cnhost_dev_put(ddev);
		goto free_ida;
	}

	mutex_lock(&smlu_set->caps_lock);
	list_add_tail(&smlu_cap->cap_node, &smlu_set->caps_head);
	mutex_unlock(&smlu_set->caps_lock);

	smlu_cap->core = core;
	smlu_cap->minor = ddev->primary;
	smlu_cap->instance_id = instance_id;
	smlu_cap->profile_id = res->profile_id;
	mutex_init(&smlu_cap->open_lock);

	cn_dev_core_info(core, "cdev %u:%u, %s, added",
				smlu_cap->minor->major,
				smlu_cap->minor->index,
				dev_name(smlu_cap->minor->kdev));

	return instance_id;

err_update:
	write_unlock(&smlu_set->quota_lock);
	mutex_unlock(&smlu_set->caps_lock);
free_ida:
	ida_simple_remove(&smlu_set->instance_ida, instance_id);
free_smlu_cap:
	cn_kfree(smlu_cap);
	return ret;
}

/*
 * 1.delete the device node.
 * 2.free the smlu_cap, release the quota from total
 * 3.dec the refcount of smlu_cap
 */
int cn_smlu_cap_node_exit(struct cn_core_set *core, int instance_id)
{
	struct cnhost_minor *pminor;
	struct smlu_cap *smlu_cap;
	struct smlu_set *smlu_set;
	struct smlu_cgroup_subsys *ss;
	int i;
	int ret = -ENODEV;

	if (unlikely(!core) || !cn_is_smlu_en(core)) {
		cn_dev_err("core invalid or not support/enable smlu");
		return -EINVAL;
	}

	if (!cn_is_host_ns()) {
		cn_dev_core_err(core, "Denied destory mlu_cap node in docker");
		return -EACCES;
	}

	/*
	 * Notice
	 * we need to check whether smlu_cap node is still in use, driver-api close smlu_cap after open immediately,
	 * thus we don't hold the open count.
	 * but it can be check by smlu_cgroup->pid_head, or just check core->open_count simply.
	 *
	 * if driver-api change, we should move step 2 to cndrv_smlu_cgroup_drv.release() or just keep here is ok,
	 * cause cnhost_dev_unregister with open count protected.
	 */

	/* step 1. unregister the managed device */
	smlu_set = core->smlu_set;

	mutex_lock(&smlu_set->caps_lock);
	list_for_each_entry(smlu_cap, &smlu_set->caps_head, cap_node) {
		if (smlu_cap->instance_id == instance_id) {
			pminor = smlu_cap->minor;
			//smlu_cap->instance_id == pminor->dev->vf_index

			down_write(&smlu_set->ns_rwsem);
			tree_traverse_and_operate(smlu_set->ns_tree, smlu_cgroup, {
				if (post->smlu_cap == smlu_cap) {
					spin_lock(&post->pid_lock);
					if (!list_empty(&post->pid_head)) {
						struct pid_info_s *pid_info_node;

						cn_dev_core_info(core, "Can't destory mlu_cap:%s, still in use, pid info:",
								dev_name(pminor->kdev));
						list_for_each_entry(pid_info_node, &post->pid_head, pid_list) {
							cn_dev_core_info(core, "tgid:%d active_pid:%d", pid_info_node->tgid,  pid_info_node->active_pid);
						}
						spin_unlock(&post->pid_lock);
						up_write(&smlu_set->ns_rwsem);
						mutex_unlock(&smlu_set->caps_lock);
						return -EBUSY;
					}
					spin_unlock(&post->pid_lock);
				}
			});
			/* now we can delete smlu_cgroup */
			tree_traverse_and_operate(smlu_set->ns_tree, smlu_cgroup, {
				if (post->smlu_cap == smlu_cap) {
					delete_smlucg_rb_node(&smlu_set->ns_tree, post);
					cn_kfree(post);
					ret = 1;
				}
			});
			up_write(&smlu_set->ns_rwsem);

			write_lock(&smlu_set->quota_lock);
			/* update quota usage info */
			smlu_for_each_subsys(ss, i) {
				smlu_set->total[i].usage -= smlu_cap->resources[i].max;
			}
			write_unlock(&smlu_set->quota_lock);

			cn_dev_core_info(core, "cdev %u:%u, %s, deleted",
						pminor->major,
						pminor->index,
						dev_name(pminor->kdev));
			cnhost_dev_unregister(pminor->dev);/* with open count protected, but driver-api had closed */
			cnhost_dev_put(pminor->dev);

			list_del(&smlu_cap->cap_node);
			ida_simple_remove(&smlu_set->instance_ida, instance_id);
			cn_kfree(smlu_cap);
			ret = 0;
			break;
		}
	}

	mutex_unlock(&smlu_set->caps_lock);

	return ret;
}
