/*
 * sbts/dbg.h
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

#ifndef __SBTS_DBG_H
#define __SBTS_DBG_H

#include <linux/types.h>
#include "cndrv_sbts.h"

#define DEBUG_DESC_SIZE 16

struct sbts_set;
struct queue;
struct sched_manager;
struct cn_core_set;
struct task_struct;

enum dbg_task_type {
	DBG_TASK_DEBUG = 0,
	DBG_TASK_DUMP = 1,
	DBG_TASK_NUM,
};

struct comm_dbg_desc {
	__le64 version;		/* version */
	__le64 sta;
	__le64 type;
	__le64 user;
	__le64 user_id;
	/* data */
	__le64 priv[DEBUG_DESC_SIZE];
};

struct dbg_queue_msg {
	__le64 queue_dsid;
};

struct sbts_dbg_ops {
	int (*msg_cbk)(struct sbts_set *sbts, struct comm_dbg_desc *rx_desc);
};

struct sbts_dbg_mod {
	u64 inited;
	const struct sbts_dbg_ops *ops;
};

struct sbts_dbg_set {
	struct sched_manager *sched_mgr;
	struct cn_core_set *core;
	struct sbts_set *sbts;

	struct sbts_dbg_mod mod[DBG_TASK_NUM];

	void *worker;
	struct debug_manager *mgr;
};

extern int sbts_dbg_init(struct sbts_set *sbts_set);
extern void sbts_dbg_exit(struct sbts_dbg_set *dbg_set);

extern int sbts_dbg_register_cbk(struct sbts_set *sbts_set, enum dbg_task_type, const struct sbts_dbg_ops *ops);

extern int dbg_do_exit(u64 user, struct sbts_dbg_set *dbg_set);
extern int sbts_kernel_debug_v2(struct sbts_set *sbts,
		struct queue *queue,
		union sbts_task_priv_data *priv_data, cn_user user);
#endif /* __SBTS_DBG_H */
