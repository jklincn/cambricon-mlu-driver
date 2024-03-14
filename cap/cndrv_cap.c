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
#include <linux/ptrace.h>
#include "cndrv_cap.h"
#include "mi_cap_internal.h"

/**
 * If want to bind MI, need open mi_cap node first, and then open
 * cambricon_dev OR cambricon_ipcm node. Error will be reported if
 * open mi_cap node of a same device twice continuously.
 */
int mi_cap_open(struct inode *inode, struct file *fp)
{
	struct cn_core_set *mi_core, *core;
	struct tid_cap_node *tid_cap_node;
	struct cnhost_minor *minor;
	struct mi_cap_fp_priv_data *priv_data;
	struct list_head *tid_cap_list_head;
	struct mutex *tid_cap_lock;

	minor = cnhost_dev_minor_acquire(imajor(inode), iminor(inode));
	if (IS_ERR(minor))
		return PTR_ERR(minor);

	mi_core = (struct cn_core_set *)(minor->dev->dev_private);
	if (!mi_core || mi_core->state == CN_RESET) {
		cn_dev_err("get mi_core failed");
		cnhost_dev_minor_release(minor);
		return -ENODEV;
	}

	core = cn_core_get_with_idx(mi_core->pf_idx);
	tid_cap_list_head = &core->tid_cap_list_head;
	tid_cap_lock = &core->tid_cap_lock;

	mutex_lock(tid_cap_lock);
	list_for_each_entry(tid_cap_node, tid_cap_list_head, list) {
		if (tid_cap_node->pid == current->pid) {
			cn_dev_core_err(mi_core, "open mi_cap node twice or not closed last time, "
					"last tid:%d, current tid:%d", tid_cap_node->pid, current->pid);
			mutex_unlock(tid_cap_lock);
			cnhost_dev_minor_release(minor);
			return -EEXIST;
		}
	}
	mutex_unlock(tid_cap_lock);

	tid_cap_node = cn_kzalloc(sizeof(*tid_cap_node), GFP_KERNEL);
	if (!tid_cap_node) {
		cn_dev_core_err(mi_core, "malloc tid_cap_node failed");
		cnhost_dev_minor_release(minor);
		return -ENOMEM;
	}

	tid_cap_node->inode = inode;
	tid_cap_node->core = mi_core;
	tid_cap_node->pid = current->pid;

	priv_data = cn_kzalloc(sizeof(struct mi_cap_fp_priv_data), GFP_KERNEL);
	if (!priv_data) {
		cn_dev_core_err(mi_core, "malloc priv_data fail");
		cn_kfree(tid_cap_node);
		cnhost_dev_minor_release(minor);
		return -ENOMEM;
	}
	mutex_lock(tid_cap_lock);
	list_add_tail(&tid_cap_node->list, tid_cap_list_head);
	mutex_unlock(tid_cap_lock);

	priv_data->core = mi_core;
	priv_data->minor = minor;
	priv_data->tid_cap_node = tid_cap_node;
	fp->private_data = (void *)priv_data;

	return 0;
}

int mi_cap_close(struct inode *inode, struct file *fp)
{
	struct tid_cap_node *tid_cap_node;
	struct mi_cap_fp_priv_data *priv_data;
	struct cnhost_minor *minor;
	struct cn_core_set *mi_core, *core;
	struct mutex *tid_cap_lock;

	priv_data = fp->private_data;
	if (!priv_data) {
		cn_dev_info("priv_data is NULL");
		return 0;
	}

	tid_cap_node = priv_data->tid_cap_node;
	if (!tid_cap_node) {
		cn_dev_info("tid_cap_node is NULL");
		return 0;
	}

	mi_core = tid_cap_node->core;
	if (mi_core)
		cn_dev_core_debug(mi_core, "no fp bind to this MI");

	core = cn_core_get_with_idx(priv_data->core->pf_idx);
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

static long mi_cap_ioctl(struct file *fp, unsigned int cmd,
			unsigned long arg)
{
	struct mi_cap_fp_priv_data *priv_data;
	struct cn_core_set *mi_core;
	int ret = 0;

	priv_data = fp->private_data;
	if (!priv_data || !priv_data->core)
		return -EFAULT;

	mi_core = priv_data->core;

	switch(cmd) {
	case MI_CAP_GET_INSTANCE_PCIE_INFO: {
		ret = mi_cap_get_instance_pcie_info(fp, mi_core, cmd, arg);
		break;
	}
	case MI_CAP_GET_INSTANCE_UNIQUE_ID: {
		ret = mi_cap_get_instance_unique_id(fp, mi_core, cmd, arg);
		break;
	}
	default:
		cn_dev_core_err(mi_core,
			"IOCTRL command# %d is invalid!", _IOC_NR(cmd));
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations cndrv_mi_cap_fops = {
	.owner = THIS_MODULE,
	.open = mi_cap_open,
	.release = mi_cap_close,
	.unlocked_ioctl = mi_cap_ioctl,
	.compat_ioctl = mi_cap_ioctl,
};

static const struct cnhost_driver cndrv_mi_cap_drv = {
	.fops = &cndrv_mi_cap_fops,
	.name = "cambricon-cap",
};

int cn_mi_cap_node_init(struct cn_core_set *mi_core)
{
	struct cnhost_device *ddev;

	if (!mi_core) {
		cn_dev_err("mi_core is NULL");
		return -1;
	}

	if (!cn_core_is_vf(mi_core))
		return 0;

	/* Do not init in VM */
	if (cn_core_is_vf(mi_core) && !cn_is_mim_en(mi_core))
		return 0;

	ddev = cnhost_dev_alloc(&cndrv_mi_cap_drv, mi_core, CNHOST_DEV_MINOR_MI_CAP,
		mi_core->pf_idx, mi_core->vf_idx);
	if (IS_ERR(ddev)) {
		return PTR_ERR(ddev);
	}

	mi_core->device = ddev;

	return 0;
}

void cn_mi_cap_node_exit(struct cn_core_set *mi_core)
{
}

int cn_mi_cap_node_late_init(struct cn_core_set *mi_core)
{
	int ret = 0;
	struct cnhost_device *ddev;

	if (!mi_core) {
		cn_dev_err("mi_core is NULL");
		return -1;
	}

	if (!cn_core_is_vf(mi_core))
		return 0;

	/* Do not init in VM */
	if (cn_core_is_vf(mi_core) && !cn_is_mim_en(mi_core))
		return 0;

	ddev = mi_core->device;
	ret = cnhost_dev_register(ddev, 0);
	if (ret)
		goto err_put;

	return 0;

err_put:
	cnhost_dev_put(ddev);
	return ret;
}

void cn_mi_cap_node_late_exit(struct cn_core_set *mi_core)
{
	if (!mi_core) {
		cn_dev_err("mi_core is NULL");
		return;
	}

	if (!cn_core_is_vf(mi_core))
		return;

	/* Not be inited in VM */
	if (cn_core_is_vf(mi_core) && !cn_is_mim_en(mi_core))
		return;

	if (mi_core->device) {
		cnhost_dev_unregister(mi_core->device);
		cnhost_dev_put(mi_core->device);
	}

	mi_core->device = NULL;
}
