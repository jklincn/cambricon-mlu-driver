/*
 * gdma/gdma_debug.h
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

#ifndef __CNDRV_GDMA_DEBUG_H__
#define __CNDRV_GDMA_DEBUG_H__

#include "cndrv_debug.h"
#include "gdma_common.h"
#include "gdma_desc.h"

#define SHOW_RUN_STATUS_MASK (4)

#define __gdma_print(fn, level, gdma, str, arg...) \
do { \
	if (gdma && gdma->core) \
		fn("%s: [%s][%s][%d][CPU %d] " str "\n", \
			level, gdma->core_name, __func__, \
			__LINE__, raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%s][%d][CPU %d][GDMA] " str "\n", \
			level, __func__, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define cn_dev_gdma_info(gdma, str, arg...) \
	__gdma_print(pr_info, "INFO", (gdma), str, ##arg)

#define cn_dev_gdma_warn(gdma, str, arg...) \
	__gdma_print(pr_warn, "WARNING", (gdma), str, ##arg)

#define cn_dev_gdma_err(gdma, str, arg...) \
	__gdma_print(pr_err, "ERROR", (gdma), str, ##arg)

#define cn_dev_gdma_debug(gdma, str, arg...) \
do { \
	if (unlikely(gdma->debug_print)) \
		__gdma_print(pr_info, "DEBUG", (gdma), str, ##arg); \
} while (0)

void cn_gdma_dbg_show_run_status(struct cn_gdma_set *gdma_set);
void cn_gdma_dbg_show_ctrl_info(struct cn_gdma_set *gdma_set,
							struct cn_gdma_controller *ctrl);
void cn_gdma_dbg_ctrl_reg_dump(struct cn_gdma_set *gdma_set,
							struct cn_gdma_controller *ctrl);
void cn_gdma_dbg_show_chan_info(struct cn_gdma_set *gdma_set,
						struct cn_gdma_phy_chan *chan);
void cn_gdma_dbg_chan_reg_dump(struct cn_gdma_set *gdma_set,
							struct cn_gdma_phy_chan *chan);
void cn_gdma_dbg_show_package(struct cn_gdma_set *gdma_set,
						struct cn_gdma_package *package);
void cn_gdma_dbg_show_contex_0_desc(struct cn_gdma_set *gdma_set,
						struct gdma_contex_type_0_desc *desc);

void cn_gdma_dbg_show_contex_0_pigeon_desc(struct cn_gdma_set *gdma_set,
					struct gdma_contex_type_0_pigeon_desc *desc);
void cn_gdma_dbg_show_contex_1_desc(struct cn_gdma_set *gdma_set,
						struct gdma_contex_type_1_desc *desc);
void cn_gdma_dbg_show_normal_desc(struct cn_gdma_set *gdma_set,
						struct gdma_normal_desc *desc);
void cn_gdma_dbg_dump_desc(struct cn_gdma_set *gdma_set,
							struct cn_shm *desc);
#endif
