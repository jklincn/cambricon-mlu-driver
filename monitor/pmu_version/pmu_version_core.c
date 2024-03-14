#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/platform_device.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/time.h>
#if (KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE)
#include <linux/time64.h>
#include <linux/timekeeping.h>
#else
#include <linux/timex.h>
#endif
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "../monitor.h"
#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"


int cn_monitor_axi_open_common(void *mset, void *mon_conf)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor_set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops)) {
		cn_dev_err("monitor_set monitor_ops is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops->open_monitor)) {
		cn_dev_err("monitor_ops, open_monitor is null");
		return -EINVAL;
	}

	return monitor_set->monitor_ops->open_monitor(mset, mon_conf);
}

int cn_monitor_axi_openall_common(void *mset, u8 hub_id)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor_set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops)) {
		cn_dev_err("monitor_set monitor_ops is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops->openall_monitor)) {
		cn_dev_err("monitor_ops, openall_monitor is null");
		return -EINVAL;
	}

	return monitor_set->monitor_ops->openall_monitor(mset, hub_id);
}

long cn_monitor_hub_ctrl_common(void *mset, unsigned long arg)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor_set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops)) {
		cn_dev_err("monitor_set monitor_ops is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops->hub_ctrl)) {
		cn_dev_err("monitor_ops, hub_ctrl is null");
		return -EINVAL;
	}

	return monitor_set->monitor_ops->hub_ctrl(mset, arg);
}

long cn_monitor_read_ringbuf_pos_common(void *mset, unsigned long arg)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor_set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops)) {
		cn_dev_err("monitor_set monitor_ops is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops->read_ringbuf_pos)) {
		cn_dev_err("monitor_ops, read_ringbuf_pos is null");
		return -EINVAL;
	}

	return monitor_set->monitor_ops->read_ringbuf_pos(mset, arg);
}

long cn_monitor_highrate_param_common(void *mset, unsigned long arg)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor_set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops)) {
		cn_dev_err("monitor_set monitor_ops is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops->highrate_param)) {
		cn_dev_err("monitor_ops, highrate_param is null");
		return -EINVAL;
	}

	return monitor_set->monitor_ops->highrate_param(mset, arg);
}

int cn_monitor_get_axistruct_size(void *mset, u32 *size)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor_set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops)) {
		cn_dev_err("monitor_set monitor_ops is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops->get_axistruct_size)) {
		cn_dev_err("monitor_ops, get_axistruct_size is null");
		return -EINVAL;
	}

	return monitor_set->monitor_ops->get_axistruct_size(mset, size);
}

int cn_monitor_get_basic_param_size(void *mset, u32 *size)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)mset;

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor_set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops)) {
		cn_dev_err("monitor_set monitor_ops is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops->get_basic_param_size)) {
		cn_dev_err("monitor_ops, get_basic_param_size is null");
		return -EINVAL;
	}

	return monitor_set->monitor_ops->get_basic_param_size(size);
}

int cn_monitor_get_basic_param(void *mset, void *pdata)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)mset;

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor_set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops)) {
		cn_dev_err("monitor_set monitor_ops is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(monitor_set->monitor_ops->get_basic_param_data)) {
		cn_dev_err("monitor_ops, get_basic_param_data is null");
		return -EINVAL;
	}

	return monitor_set->monitor_ops->get_basic_param_data(mset, pdata);
}
