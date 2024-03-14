/*
 * include/cndrv_kwork.h
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

#ifndef __CNDRV_WORK_H__
#define __CNDRV_WORK_H__

#include <linux/list.h>
#include <linux/workqueue.h>

#include "cndrv_core.h"

#define CN_WQ_NAME_LEN     32

struct cn_kworkqueue_inner_t {
	struct list_head list;
	struct cn_core_set *core;
	struct workqueue_struct *wq;
	char name[CN_WQ_NAME_LEN];
};

extern struct list_head* cn_get_core_workqueue_head(struct cn_core_set *core);

extern struct workqueue_struct *cn_create_singlethread_workqueue(
	struct cn_core_set *core, const char *name);

extern struct workqueue_struct *cn_alloc_workqueue(
	struct cn_core_set *core, const char *name, unsigned int flags,
	int max_active);

extern void cn_destroy_workqueue(struct cn_core_set *core,
	struct workqueue_struct *wq);

extern bool cn_schedule_work(struct cn_core_set *core,
	struct work_struct *work);

extern int cn_kwork_init(void);
extern void cn_kwork_exit(void);
extern int cn_kwork_mlu_init(struct cn_core_set *core);
extern void cn_kwork_mlu_exit(struct cn_core_set *core);

#endif
