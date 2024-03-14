/*
 * sbts/hostfunc.h
 *
 * NOTICE:
 * Copyright (C) 2021 Cambricon, Inc. All rights reserved.
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
#ifndef _HOSTFUNC_H
#define _HOSTFUNC_H

#include <linux/list.h>

#include "sbts.h"
#include "queue.h"
#include "cndrv_mm.h"

#define _HF_TRIGGER_NORMAL 1
/* perf sig size in struct hostfn_shm_sig */
#define _HF_SHM_SIG_PERF_SIZE 4 * 8

struct sbts_hostfunc_set {
	struct sched_manager *sched_mgr;
	struct cn_core_set *core;
	struct sbts_set *sbts;
	void *worker;
	struct rb_root triggered_rbtree_root;
	struct mutex mutex;
	int wakeup_dev_en;
	/* just for debug */
	__u64 add_to_trigger_list_num;
	__u64 invoke_task_num;
	__u64 receive_trigger_num;
	__u64 delete_from_trigger_list_num;
	__u64 do_exit_delete_num;
	__u64 queue_do_exit_delete_num;
	__u64 sig_num;
	__u64 send_finish_req;
	__u64 queue_invalid_trigger_num;
};

struct hostfn_task_node {
	struct list_head head;
	u64 host_finish_sig_va;
	struct queue *queue;
	unsigned long seq;
	u64 hk_pass_trigger_ns;
};

struct hostfn_shm_sig {
	__u64 hk_pass_trigger_ns;
	__u64 host_get_trigger_ns;
	__u64 hostfn_start_ns;
	__u64 hostfn_end_ns;
	__u8 host_execute_sta;
} __attribute__((aligned(8)));

enum hostfn_execute_status {
	_HF_EXECUTE_INIT_STATE = 0,
	_HF_EXECUTE_FINISH = 1,
	_HF_EXECUTE_EXCEPTION = 2,
};

int sbts_hostfn_create_user_node_once(
		struct sbts_hostfunc_set *hostfunc_set, __u64 fp_id);
void sbts_hostfn_fill_shm_sig(struct hostfn_shm_sig *sig, __u8 host_execute_sta,
		__u64 hk_pass_trigger_ns, __u64 host_get_trigger_ns,
		__u64 hostfn_start_ns, __u64 hostfn_end_ns);
void sbts_hostfn_shm_sig_to_dev(struct sbts_hostfunc_set *hostfunc_set,
		host_addr_t host_sig_va, struct hostfn_shm_sig *sig);
struct hostfn_task_node *sbts_hostfn_node_deregister(
		struct sbts_set *sbts, struct queue *queue, __u64 seq);
void sbts_hostfn_task_free(
		struct sbts_hostfunc_set *hostfunc_set, struct queue *queue);
int sbts_hostfunc_init(struct sbts_set *sbts_set);
int sbts_hostfunc_do_exit(u64 user, struct sbts_hostfunc_set *hostfunc_set);
void sbts_hostfunc_exit(struct sbts_hostfunc_set *hostfunc_set);

#endif
