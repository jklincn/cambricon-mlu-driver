/*
 * gdma/gdma_hal.c
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
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

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "gdma_hal.h"
#include "gdma_debug.h"
#include "gdma_common.h"
#include "plat/mlu370/gdma_c30s.h"
#include "plat/mlu500/gdma_c50.h"
#include "plat/pigeon/gdma_pigeon.h"
#include "gdma_common_api.h"

const struct cn_gdma_plat_driver gdma_plat_drvs[] = {
	{
		.device_id = MLUID_365,
		.info_probe = cn_gdma_plat_c30s_info_probe,
		.init_ctrl_res = cn_gdma_plat_c30s_init,
	},
	{
		.device_id = MLUID_370,
		.info_probe = cn_gdma_plat_c30s_info_probe,
		.init_ctrl_res = cn_gdma_plat_c30s_init,
	},
	{
		.device_id = MLUID_590,
		.info_probe = cn_gdma_plat_c50_info_probe,
		.init_ctrl_res = cn_gdma_plat_c50_init,
	},
	{
		.device_id = MLUID_580,
		.info_probe = cn_gdma_plat_c50_info_probe,
		.init_ctrl_res = cn_gdma_plat_c50_init,
	},
	{
		.device_id = MLUID_PIGEON_EDGE,
		.info_probe = cn_gdma_plat_pigeon_info_probe,
		.init_ctrl_res = cn_gdma_plat_pigeon_init,
	},
};

int cn_gdma_plat_probe(struct cn_gdma_set *gdma_set)
{
	int ret = -EINVAL;
	int i;
	struct cn_core_set *core = gdma_set->core;
	const struct cn_gdma_plat_driver *drv;

	for (i = 0; i < ARRAY_SIZE(gdma_plat_drvs); i++) {
		drv = gdma_plat_drvs + i;
		if (core->device_id == drv->device_id) {
			gdma_set->plat_drv = (struct cn_gdma_plat_driver *)drv;
			break;
		}
	}

	if (gdma_set->plat_drv && gdma_set->plat_drv->info_probe) {
		ret = gdma_set->plat_drv->info_probe(gdma_set);
		if (ret) {
			cn_dev_gdma_err(gdma_set, "gdma info probe failed\n");
			return ret;
		}
	}

	if (!gdma_set->info) {
		cn_dev_gdma_err(gdma_set,
			"can't support device,name %s,id 0x%llx",
			gdma_set->core->board_info.board_model_name,
			gdma_set->core->device_id);
		return -EINVAL;
	}

	if (!gdma_set->info->ctrl_num) {
		cn_dev_gdma_info(gdma_set,
			"there is no gdma controller on %s",
			gdma_set->core->board_info.board_model_name);
		return -EINVAL;
	}

	cn_dev_gdma_info(gdma_set, "ctrl_num=%d ctrl_chan_num=%d",
			gdma_set->info->ctrl_num, gdma_set->info->ctrl_chan_num);

	return ret;
}

int cn_gdma_get_ctrl_num(struct cn_gdma_set *gdma_set)
{
	if (unlikely(!gdma_set->info)) {
		return 0;
	} else {
		return gdma_set->info->ctrl_num;
	}
}

int cn_gdma_get_ctrl_chan_num(struct cn_gdma_set *gdma_set)
{
	if (unlikely(!gdma_set->info)) {
		return 0;
	} else {
		return gdma_set->info->ctrl_chan_num;
	}
}

int cn_gdma_get_task_num(struct cn_gdma_set *gdma_set)
{
	if (unlikely(!gdma_set->info)) {
		return 0;
	} else {
		return gdma_set->info->task_num;
	}
}

int cn_gdma_get_memset_buf_size(struct cn_gdma_set *gdma_set)
{
	if (unlikely(!gdma_set->info)) {
		return 0;
	} else {
		return gdma_set->info->memset_buf_size;
	}
}

int cn_gdma_get_irq_type(struct cn_gdma_set *gdma_set)
{
	if (unlikely(!gdma_set->info)) {
		return -GDMA_UNSUPPORT;
	} else {
		return gdma_set->info->irq_type;
	}
}

int cn_gdma_get_vchan_num(struct cn_gdma_set *gdma_set)
{
	if (unlikely(!gdma_set->info)) {
		return 0;
	} else {
		return gdma_set->info->vchan_num;
	}
}

int cn_gdma_get_priv_vchan_num(struct cn_gdma_set *gdma_set)
{
	if (unlikely(!gdma_set->info)) {
		return 0;
	} else {
		return gdma_set->info->priv_vchan_num;
	}
}

int cn_gdma_init_ctrl_resource(struct cn_gdma_set *gdma_set,
		struct cn_gdma_controller *ctrl, int idx)
{
	int ret = -EINVAL;

	if (gdma_set->plat_drv && gdma_set->plat_drv->init_ctrl_res) {
		ret = gdma_set->plat_drv->init_ctrl_res(ctrl, idx);
	}

	return ret;
}

int cn_gdma_get_pchan_resource(struct cn_gdma_controller *ctrl,
		struct cn_gdma_phy_chan *channel, int chnnl_idx)
{
	if (chnnl_idx < 0 || chnnl_idx >= ctrl->pchan_num) {
		return -EINVAL;
	}

	if (!ctrl->pchans[chnnl_idx]) {
		ctrl->pchans[chnnl_idx] = channel;
		channel->idx = chnnl_idx;
		channel->irq = ctrl->irq + chnnl_idx;
		channel->base = CHANNEL_BASE(ctrl->main_csr_base, chnnl_idx);
	}

	return GDMA_SUCCESS;
}
