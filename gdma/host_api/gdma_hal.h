/*
 * gdma/gdma_hal.h
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

#ifndef __CNDRV_GDMA_HAL_H__
#define __CNDRV_GDMA_HAL_H__

#include "gdma_common.h"

int cn_gdma_plat_probe(struct cn_gdma_set *gdma_set);
int cn_gdma_plat_probe(struct cn_gdma_set *gdma_set);
int cn_gdma_get_ctrl_num(struct cn_gdma_set *gdma_set);
int cn_gdma_get_ctrl_chan_num(struct cn_gdma_set *gdma_set);
int cn_gdma_get_task_num(struct cn_gdma_set *gdma_set);
int cn_gdma_get_memset_buf_size(struct cn_gdma_set *gdma_set);
int cn_gdma_get_irq_type(struct cn_gdma_set *gdma_set);
int cn_gdma_get_vchan_num(struct cn_gdma_set *gdma_set);
int cn_gdma_get_priv_vchan_num(struct cn_gdma_set *gdma_set);
int cn_gdma_init_ctrl_resource(struct cn_gdma_set *gdma_set,
		struct cn_gdma_controller *ctrl, int idx);
int cn_gdma_get_pchan_resource(struct cn_gdma_controller *ctrl,
		struct cn_gdma_phy_chan *channel, int chnnl_idx);

#endif
