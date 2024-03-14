#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/atomic.h>
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_debug.h"
#include "xid_internal.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

int cn_xid_init(struct cn_core_set *core)
{
	struct cn_xid_set *xid_set;

	xid_set = cn_kzalloc(sizeof(struct cn_xid_set), GFP_KERNEL);
	if (!xid_set) {
		cn_dev_err("alloc for xid set error");
		return -ENOMEM;
	}
	atomic64_set(&xid_set->xids, 0);
	bitmap_zero(xid_set->xids_ctrl, XID_MAX_ERR);
	bitmap_zero(xid_set->xids_bitmap, XID_MAX_ERR);

	xid_set->xid_print = true;
	xid_set->core = core;
	core->xid_set = xid_set;

	return 0;
}

void cn_xid_exit(struct cn_core_set *core)
{
	struct cn_xid_set *xid_set = core->xid_set;

	if (xid_set) {
		xid_set->core = NULL;
		cn_kfree(xid_set);
	}
}

int cn_xid_err_record(const struct cn_core_set *core,
	const u32 xid)
{
	struct cn_xid_set *xid_set = (struct cn_xid_set *)core->xid_set;

	if (IS_ERR_OR_NULL(xid_set)) {
		return -EINVAL;
	}

	if (!xid) {
		atomic64_set(&xid_set->xids, xid);
		return 0;
	}

	if (!test_bit(xid, xid_set->xids_ctrl)) {
		atomic64_set(&xid_set->xids, xid);
		if (xid && xid < XID_MAX_ERR) {
			set_bit(xid, xid_set->xids_bitmap);
		}
		return 0;
	}

	return -EACCES;
}

static int xid_enable(const struct cn_core_set *core, u64 xid, u8 select)
{
	struct cn_xid_set *xid_set = (struct cn_xid_set *)core->xid_set;

	if (select) {
		bitmap_zero(xid_set->xids_ctrl, XID_MAX_ERR);
	} else {
		if (xid && xid < XID_MAX_ERR) {
			/* enable xid */
			clear_bit(xid, xid_set->xids_ctrl);
		} else {
			return -EINVAL;
		}
	}

	return 0;
}

static int xid_disable(const struct cn_core_set *core, u64 xid, u8 select)
{
	struct cn_xid_set *xid_set = (struct cn_xid_set *)core->xid_set;
	if (select) {
		bitmap_fill(xid_set->xids_ctrl, XID_MAX_ERR);
		clear_bit(XID_NO_ERR, xid_set->xids_ctrl);
	} else {
		if (xid > XID_NO_ERR && xid < XID_MAX_ERR) {
			/* enable xid */
			set_bit(xid, xid_set->xids_ctrl);
		} else {
			return -EINVAL;
		}
	}

	return 0;
}

int cn_disable_xid_common(const struct cn_core_set *core,
	struct cndev_feature_set_xid *xid_info)
{
	int ret = 0;

	ret = xid_disable(core, xid_info->xid, xid_info->select);

	return ret;
}

int cn_clear_xid_common(const struct cn_core_set *core,
	struct cndev_feature_set_xid *xid_info)
{
	struct cn_xid_set *xid_set = (struct cn_xid_set *)core->xid_set;

	atomic64_set(&xid_set->xids, 0);

	if (xid_info->select)
		bitmap_zero(xid_set->xids_bitmap, XID_MAX_ERR);

	return 0;
}

int cn_enable_xid_common(const struct cn_core_set *core,
	struct cndev_feature_set_xid *xid_info)
{
	int ret = 0;

	ret = xid_enable(core, xid_info->xid, xid_info->select);

	return ret;
}

void cn_get_xid_err(const struct cn_core_set *core,
	u64 *xid_err)
{
	struct cn_xid_set *xid_set = (struct cn_xid_set *)core->xid_set;

	if (!IS_ERR_OR_NULL(xid_err))
		*xid_err = atomic64_read(&xid_set->xids);
}

int cn_get_xid_status(const struct cn_core_set *core,
	struct cndev_feature_get_xid *xid_info)
{
	u32 pos = 0;
	int ret = 0;
	u32 xid_cnt = 0;
	struct cn_xid_set *xid_set = (struct cn_xid_set *)core->xid_set;
	void *data = NULL;
	u64 *xid_datas = NULL;

	data = (xid_info->select == XID_SELECT_XIDS_SWITCH) ?
		xid_set->xids_ctrl : xid_set->xids_bitmap;

	if (IS_ERR_OR_NULL(xid_set))
		return -EINVAL;

	xid_datas = (u64 *)cn_kzalloc(sizeof(u64) * XID_MAX_ERR, GFP_KERNEL);
	if (!xid_datas)
		return -ENOMEM;

	pos = 1;
	for_each_set_bit_from(pos, data, XID_MAX_ERR) {
		xid_datas[xid_cnt++] = pos;
	}

	ret = xid_cp_less_val(&xid_info->data.cn_xids.xid_num, xid_cnt,
		xid_info->data.cn_xids.xids, xid_datas, sizeof(u64));

	xid_info->data.cn_xids.xid_num = xid_cnt;

	cn_kfree(xid_datas);

	return ret;
}

int cn_xid_debug(const struct cn_core_set *core,
	u64 *xid_err, u64 *xid_status, u64 *xid_switch)
{
	u32 pos = 0;
	u32 xid_cnt = 0;
	struct cn_xid_set *xid_set = (struct cn_xid_set *)core->xid_set;

	*xid_err = atomic64_read(&xid_set->xids);

	if (IS_ERR_OR_NULL(xid_set))
		return -EINVAL;

	pos = 1;
	for_each_set_bit_from(pos, xid_set->xids_bitmap, XID_MAX_ERR) {
		xid_status[xid_cnt++] = pos;
	}

	xid_cnt = 0;
	pos = 1;
	for_each_set_bit_from(pos, xid_set->xids_ctrl, XID_MAX_ERR) {
		xid_switch[xid_cnt++] = pos;
	}

	return 0;
}

int xid_show_info(struct seq_file *m, void *v)
{
	int ret = 0;
	u64 xid_err = 0;
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	u64 *xid_status = NULL;
	u64 *xid_switch = NULL;
	u64 i = 0;

	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	xid_status = (u64 *)cn_kzalloc(sizeof(u64) * XID_MAX_ERR, GFP_KERNEL);
	if (!xid_status) {
		return -ENOMEM;
	}

	xid_switch = (u64 *)cn_kzalloc(sizeof(u64) * XID_MAX_ERR, GFP_KERNEL);
	if (!xid_switch) {
		cn_kfree(xid_status);
		return -ENOMEM;
	}

	ret = cn_xid_debug(core, &xid_err, xid_status, xid_switch);
	if (!ret) {
		seq_printf(m, "XID: %llu\n", xid_err);
		seq_printf(m, "\nTotal XIDs:\n");
		for (i = 0; i < XID_MAX_ERR; i++) {
			if (xid_status[i])
				seq_printf(m, "Err: %llu\n", xid_status[i]);
		}
		seq_printf(m, "\nXIDs Switch status:\n");
		for (i = 0; i < XID_MAX_ERR; i++) {
			if (xid_switch[i])
				seq_printf(m, "XID %llu OFF\n", xid_switch[i]);
		}
	}

	if (xid_switch)
		cn_kfree(xid_switch);

	if (xid_status)
		cn_kfree(xid_status);

	return ret;
}
