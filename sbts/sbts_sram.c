/*
 * sbts/sbts_sram.c
 *
 * NOTICE:
 * Copyright (C) 2022 Cambricon, Inc. All rights reserved.
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

#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/printk.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/io.h>


#include "cndrv_core.h"
#include "cndrv_os_compat.h"
#include "cndrv_ioctl.h"
#include "cndrv_sbts.h"
#include "sbts.h"
#include "cndrv_debug.h"

int g_sbts_atomicop_enable = 1;

enum sbts_atomicop_ctrl_e {
	ATOMICOP_CTRL_CHECK = 0,
};

struct cd_atomicop_ctrl_msg {
	__le64 type;
	__le64 val;
};

/* return 1 if support */
int sbts_global_atomicop_support(void)
{
	return g_sbts_atomicop_enable;
}

#if 0
// reserved code
/* return 0 if support */
static int sbts_check_dev_atomicop(struct cn_core_set *core)
{
	struct sbts_set *sbts = core->sbts_set;
	struct sched_manager *sched_mgr = sbts->sched_manager;
	struct comm_ctrl_desc tx = {0}, rx = {0};
	struct ctrl_desc_data_v1 *data;
	struct cd_atomicop_ctrl_msg *priv;
	int ret;

	/* fill desc */
	tx.version         = SBTS_VERSION;
	data               = (struct ctrl_desc_data_v1 *)tx.data;
	data->type         = ATOMICOP_CTRL;
	priv               = (struct cd_atomicop_ctrl_msg *)data->priv;
	priv->type         = cpu_to_le64(ATOMICOP_CTRL_CHECK);

	ret = sched_mgr->ioctl(sched_mgr, &tx, &rx,
			ANNOY_USER, sizeof(struct comm_ctrl_desc));
	if (unlikely(ret || rx.sta)) {
		cn_dev_core_err(core, "dev check op ctrl msg send fail!");
		return -EFAULT;
	}
	data = (struct ctrl_desc_data_v1 *)rx.data;
	priv = (struct cd_atomicop_ctrl_msg *)data->priv;

	return le64_to_cpu(priv->val);
}
#endif

static inline int __sbts_atomicop_check_dev(struct cn_core_set *core)
{
	if ((core->device_id == MLUID_590) ||
			(core->device_id == MLUID_590V) ||
			(core->device_id == MLUID_580) ||
			(core->device_id == MLUID_580V)) {
		return 1;
	}
	return 0;
}

static void __hwinfo_cap_check(struct cn_core_set *core)
{
	struct sbts_set *sbts_set = core->sbts_set;
	struct sbts_hw_info *info = sbts_set->hw_info;
	struct sbts_basic_info *b_info = NULL;

	sbts_set->dev_sram_en = false;
	sbts_set->dev_atomicop_en = false;

	if (!info) {
		cn_dev_core_info(core, "device hwinfo invalid");
		return;
	}

	b_info = (struct sbts_basic_info *)info->data;
	cn_dev_core_info(core, "hw cap bitmap %#llx", b_info->hw_cap_bitmap);

	sbts_set->dev_atomicop_en = !!(b_info->hw_cap_bitmap & SBTS_HW_CAP_ATOMICOP_ENABLE);
	sbts_set->dev_sram_en = !!(b_info->hw_cap_bitmap & SBTS_HW_CAP_SRAM_ENABLE);
}

static void sbts_atomicop_init(struct cn_core_set *core)
{
	struct sbts_set *sbts_set = core->sbts_set;

	/* some device not support before */
	if (!g_sbts_atomicop_enable)
		return;

	if (!__sbts_atomicop_check_dev(core)) {
		cn_dev_core_info(core, "platform not support");
		g_sbts_atomicop_enable = 0;
		return;
	}

	if (!sbts_set->dev_atomicop_en){
		cn_dev_core_info(core, "hw cap atomicop disable");
		g_sbts_atomicop_enable = 0;
		return;
	}
}

int sbts_sram_manager_init(struct cn_core_set *core)
{

	__hwinfo_cap_check(core);
	sbts_atomicop_init(core);

	return 0;
}

