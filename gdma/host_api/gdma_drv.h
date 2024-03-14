/*
 * gdma/gdma_drv.h
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

#ifndef __CNDRV_GDMA_DRV_H__
#define __CNDRV_GDMA_DRV_H__

#include "gdma_common.h"

#define HOST_GDMA_CLOSE_CTRL_CONFIG   (1)

int cn_gdma_drv_init(struct cn_gdma_set *gdma_set);
int cn_gdma_drv_deinit(struct cn_gdma_set *gdma_set);
int cn_gdma_chan_start(struct cn_gdma_virt_chan *vchan);
struct cn_gdma_phy_chan *cn_gdma_get_idle_phy_chan(struct cn_gdma_set *gdma_set);
int cn_gdma_put_idle_phy_chan(struct cn_gdma_phy_chan *pchan);
int cn_gdma_tx_go(struct cn_gdma_phy_chan *pchan,
		struct cn_gdma_virt_chan *vchan);

#endif
