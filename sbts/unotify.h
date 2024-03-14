/*
 * sbts/unotify.h
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

#ifndef __SBTS_UNOTIFY_H
#define __SBTS_UNOTIFY_H

#include <linux/eventfd.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>


/* user efd_data buf num */
#define MAX_USER_BUF 8
/* size of efd_data priv dize */
#define EFD_DESC_SIZE 24
/* task buffer for signal task */
#define EFD_BUF_NUM 32

struct cn_core_set;
struct queue;

enum efd_task_type {
	CORE_DUMP_COMPLETE = 0,
	HOST_FUNCTION_PROCESS,
	PRINTF_PROCESS,
	GDB_PROCESS,
	EFD_CORE_DUMP_DMA,
	EFD_JPU_PROCESS,
	EFD_TASK_TYPE_NUM,
};

/* ioctl to user */
struct sbts_efd_head {
	__u64 version;
	/* user set val input as efd_data buffer count */
	/* kernel set val output as valid efd_data count */
	__u32 data_count;
	/* user ptr to save sbts_efd_data */
	__u64 efd_data;
};

struct sbts_efd_data {
	__u32 type;
	__u32 reserved;
	__u64 hqueue;
	/* do not access this val */
	__u64 res[6];
	/* 24 */
	__u64 priv[EFD_DESC_SIZE];
};

struct sbts_efd_task {
	struct list_head entry;
	struct sbts_efd_data msg;
};

struct efd_core_dump_msg {
	__u64 dump_version;
	__u64 dumped_bp[3];
};

/* for each efd from user set */
struct sbts_efd {
	unsigned long out_n;
	/* user struct file* */
	u64 user;
	/* efd info ticket */
	u64 idx;
	/* eventfd from user */
	int user_efd;
	/* user tgid when create */
	int tgid;

	/* kernel eventfd context info */
	struct eventfd_ctx *ctx;
	struct file *efd_file;

	/* list save task wait user to get */
	struct list_head task_list;
	struct mutex list_lock;

	struct kref  ref_cnt;
	/* list to efd manager */
	struct list_head list;

	/* task count control */
	u64 task_cnt[EFD_TASK_TYPE_NUM];
	u64 lmt_ctl_cnt[EFD_TASK_TYPE_NUM];
	/* debug cnt */
	u64 total_cnt[EFD_TASK_TYPE_NUM];
	u64 read_cnt[EFD_TASK_TYPE_NUM];

	/* save user name for debug */
	char proc_name[TASK_COMM_LEN];
};

struct sbts_efd_manager {
	struct cn_core_set *core;
	struct sbts_set *sbts;

	/* mem cache for efd task data */
	struct kmem_cache *task_mem;

	rwlock_t rwlock;
	u64 ticket;
	struct list_head efd_head;
};



extern int efd_put(struct sbts_efd_manager *manager,
			struct sbts_efd *efd);

extern struct sbts_efd *sbts_get_efd_by_user(
		struct sbts_efd_manager *manager, u64 user);

extern int sbts_unotify_send(struct sbts_set *sbts,
		struct queue *queue,
		enum efd_task_type ptype,
		u64 *priv_data,
		u32 priv_size);

int sbts_efd_do_exit(u64 user, struct sbts_efd_manager *manager);

int sbts_efd_manager_init(struct sbts_efd_manager **ppmanager,
			struct cn_core_set *core);
void sbts_efd_manager_exit(struct sbts_efd_manager *manager);
#endif /*__SBTS_UNOTIFY_H*/
