/*************************************************************************
* NOTICE:
* Copyright (c) 2022 Cambricon, Inc. All rights reserved.
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
***************************************************************************/
#ifndef __CNDRV_XID_H__
#define __CNDRV_XID_H__

#include <linux/kernel.h>
#include <linux/atomic.h>
#include "cndrv_core.h"
#include "cndrv_pre_compile.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif

struct cn_xid_set {
	/* debug switch */
	bool xid_print;
	/* core set */
	void *core;
	/* lastest xid */
	atomic64_t xids;
	/* xids bitmaps */
	DECLARE_BITMAP(xids_bitmap, XID_MAX_ERR);
	/* xid switch */
	DECLARE_BITMAP(xids_ctrl, XID_MAX_ERR);
};

int cn_xid_init(struct cn_core_set *core);
void cn_xid_exit(struct cn_core_set *core);

int cn_disable_xid_common(const struct cn_core_set *core,
	struct cndev_feature_set_xid *xid_info);
int cn_clear_xid_common(const struct cn_core_set *core,
	struct cndev_feature_set_xid *xid_info);
int cn_enable_xid_common(const struct cn_core_set *core,
	struct cndev_feature_set_xid *xid_info);
int cn_get_xid_status(const struct cn_core_set *core,
	struct cndev_feature_get_xid *xid_info);
int cn_xid_err_record(const struct cn_core_set *core,
	const u32 xid);
void cn_get_xid_err(const struct cn_core_set *core,
	u64 *xid_err);
int cn_xid_debug(const struct cn_core_set *core,
	u64 *xid_err, u64 *xid_status, u64 *xid_switch);
int xid_show_info(struct seq_file *m, void *v);

#define cn_xid_err(core, xid, fmt, arg...) \
do { \
	if (core) \
		cn_xid_err_record(core, xid); \
	if (xid) { \
		if (core) { \
			if ((core->xid_set) && ((struct cn_xid_set *)(core->xid_set))->xid_print == true) { \
				pr_err("CNRM: Xid [%s]: %u, " fmt "\n", core->core_name, xid, ##arg); \
			} else { \
			} \
		} else { \
			pr_err("CNRM: Xid [N/A]: %u, " fmt "\n", xid, ##arg); \
		} \
	} \
} while (0)

#endif /* __CNDRV_XID_H__ */
