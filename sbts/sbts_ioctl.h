/*
 * sbts/sbts_ioctl.h
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
#ifndef __SBTS_SBTS_IOCTL_H
#define __SBTS_SBTS_IOCTL_H

#include <linux/types.h>

#include "cndrv_sbts.h"
#include "cndrv_debug.h"
#include "cndrv_pre_compile.h"

extern int
cn_queue_create(struct sbts_set *,
		void *,
		cn_user);

extern int
cn_queue_destroy(struct sbts_set *,
		void *,
		cn_user);

extern int
cn_core_dump(struct sbts_set *sbts,
		void *arg,
		cn_user user);

/*
 * Notifier Management
 */
extern int
cn_create_notifier(struct sbts_set *,
		void *,
		cn_user);

extern int
cn_destroy_notifier(struct sbts_set *,
		void *,
		cn_user);

extern int
cn_wait_notifier(struct sbts_set *,
		void *,
		cn_user);

extern int
cn_query_notifier(struct sbts_set *,
		void *,
		cn_user);

extern int
cn_notifier_elapsed_exec_time(struct sbts_set *sbts,
		void *args,
		cn_user user);

extern int
cn_notifier_elapsed_sw_time(struct sbts_set *sbts,
		void *args,
		cn_user user);

extern int
cn_notifier_ipc_gethandle(struct sbts_set *sbts,
		void *args,
		cn_user user);

extern int
cn_notifier_ipc_openhandle(struct sbts_set *sbts,
		void *args,
		cn_user user);

extern int sbts_place_notifier(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int sbts_wait_notifier(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int sbts_wait_notifier_extra(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

int cn_sbts_topo_task_cmd(struct sbts_set *sbts,
		void *args,
		cn_user user);

extern int
cn_query_queue(struct sbts_set *,
		void *,
		cn_user);

extern int
cn_multi_queue_sync(struct sbts_set *,
		void *,
		cn_user);

extern int
cn_invoke_cngdb_task(struct sbts_set *,
		 void *param,
		 cn_user);

extern int
cn_ncs_cmd_func(struct sbts_set *sbts_set,
		 void *arg,
		 cn_user user);

extern int
cn_tcdp_cmd_func(struct sbts_set *sbts_set,
		void *arg,
		cn_user user);

extern int
cn_user_get_hw_info(struct sbts_set *,
		void *,
		cn_user);

extern int
cn_sbts_get_unotify_info(struct sbts_set *sbts,
		void *args,
		cn_user user);

extern int
cn_sbts_set_unotify_fd(struct sbts_set *sbts,
		void *args,
		cn_user user);

extern int
cn_debug_ctrl(struct sbts_set *sbts,
		void *args,
		cn_user user);

/* hw cfg handle function */
extern int
cn_hw_cfg_handle(struct sbts_set *sbts,
		void *args,
		cn_user user);

extern int
cn_core_dump_ack(struct sbts_set *sbts,
		void *arg,
		cn_user user);

extern int
sbts_invoke_kernel(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int
sbts_place_idc(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int
sbts_hostfn_invoke(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int
sbts_invoke_ncs_kernel(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int sbts_dma_async_invoke(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int
sbts_dbg_kernel_invoke(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

/* debug function */
extern int sbts_dbg_task(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int
sbts_queue_sync(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int
sbts_invoke_tcdp(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int
sbts_invoke_tcdp_debug(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int
sbts_invoke_jpu(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);

extern int
sbts_invoke_task_topo(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param);
#endif /* __SBTS_SBTS_IOCTL_H */
