/*
 * sbts/queue.h
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

#ifndef __SBTS_QUEUE_H
#define __SBTS_QUEUE_H

#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/spinlock.h>

#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_hpq.h"
#include "sbts.h"
#include "sbts_set.h"
#include "cndrv_os_compat.h"

/* param buff */
#define PARAM_BUF_SIZE_MAX                  (32ULL * 1024 * 1024)
#define PARAM_BUF_SIZE_MIN                  (4ULL * 1024 * 1024)
/* special type */
#define PARAM_BUF_SIZE_SPECIAL              (2ULL * 1024 * 1024)
#define PARAM_BUF_SIZE_370                  (16ULL * 1024 * 1024)

#define PARAM_WAIT_TIMEOUT_512MS_MASK       ((1ULL << 19) - 1)

#define PARAM_BUF_PAGE_SIZE                 (0x40)

enum sbts_param_alloc_type {
	SBTS_ALLOC_PARAM_ONCE = 0x01U,
	SBTS_ALLOC_PARAM_WAIT = 0x02U,
	SBTS_ALLOC_PARAM_HALF = 0x04U,
	SBTS_ALLOC_PARAM_MAX  = 0x08U,

};

#define MAX_QUEUE_NUM_FOR_FUNC              (16)
#define QUEUE_NUM_SPECIAL                   (1024)
#define QUEUE_NUM_NORMAL                    (4096)
#define QUEUE_NUM_SRIOV                     QUEUE_NUM_NORMAL
#define QUEUE_Q_LEN_ORDER                   (3)
#define QUEUE_Q_LEN                         (1 << (QUEUE_Q_LEN_ORDER))

/* Forward declaration */
struct cn_core_set;
struct task_struct;
struct mm_struct;
struct sbts_efd;
struct core_dump_info;
struct sched_manager;
struct sbts_shm_manager;
struct sbts_set;

enum queue_status {
	QUEUE_NORMAL = 0,
	QUEUE_EXCEPTION,
	QUEUE_WAITING_DESTROY,
	QUEUE_DESTROY,
};

struct sbts_bucket {
	volatile u64 bucket;
/* avoid false sharing */
} __aligned(64);

#define QUEUE_RECORD_LIST(op) \
	op(param_delay, 3, 4) \
	op(queue_backward, 3, 10) \
	op(task_backward, 3, 4)

/* struct will create when create queue resource.
 * if other module first get ackinfo, must get queue before,
 * then the module can get ackinfo anywhere.
 * when queue destroy, if other module still get ackinfo, the info will not be free.
 * the last put will free ackinfo and free the shm addr.
 *
 * The important exception situation is some device in an abnormal state,
 * and will do heartbeat function.
 *
 * (Any device will do heartbeat function only when no user is using)
 *
 * if the ackinfo device is in heartbeat,
 * we need free shm resource in `__queue_ack_free` to avoid memory leak.
 * before we free resource, all users should be exited,
 * so other devices will not access this addr.
 *
 * if other devices which will access this addr in heartbeat.
 * the module which is using ackinfo should handle the put sequence by themself.
 *
 * */
struct queue_ack_s {
	struct queue_manager *queue_manager;

	volatile bool addr_valid;
	struct kref ref_cnt;

	u64 seq;

	unsigned long ret_dev_iova;
	unsigned long ret_host_vaddr;

	/* for dev read host iova addr */
	u64 ret_host_iova[MAX_FUNCTION_NUM];

	STRUCT_HPAS(hpq_queue_ack, struct hpq_task_ack_desc) ack;
};

struct queue {
	struct mutex mutex;
	struct list_head head;
	struct list_head sync_entry;
	struct kref ref_cnt;
	volatile int sta;  /* queue status*/

	struct sbts_efd *efd;
	struct core_dump_info *dump_info;
	struct cn_core_set *core;
	struct queue_ack_s *ack_info;
	struct perf_tgid_entry *tgid_entry;

	u32 sync_flags;
	u64 user;
	/* task count of worked task which equals seq_num in ack when queue idle */
	u64 task_ticket;
	/* saved seq_num in task push to short next push time */
	u64 remote_ticket;
	/* saved seq_num after queue_sync success, send dev when destroy */
	u64 sync_ticket;
	u64 priority;
	/*add this if init new async dma task*/
	u64 dma_ticket;
	/* record topo param modify num on this queue */
	u64 topo_param_cnt;

	u64 sid;
	u64 dev_sid;
	u64 user_id;
	u64 map_ret_vaddr;
	u64 unique_id;

	/* save task hw time which run in host with sync */
	u64 host_hw_time;

	/* set when current queue update ticket as dev topo's inner queue
	 * if CNDrv exit after update queue's ticket without reset,
	 * queue task_ticket will not equal device's ticket.
	 * destroy queue need check this flag to clear task_ticket before destroy.
	 * */
	bool topo_updating;
};

struct queue_manager {
	rwlock_t rwlock;
	struct mutex mqsync_mutex;
	u64      total_task;
	u64	 count;
	int nomem_flag;
	int halfmem_flag;
	struct list_head head;
	struct sched_manager *sched_mgr;
	struct param_buf_manager *param_mgr;
	struct cn_core_set *core;
	struct sbts_shm_manager *shm_mgr;
	int driver_unload_flag;

	/* histogram of congestion and delay count */
	volatile unsigned int record_en;
#define RECORD_STRUCT(name, bucket_order, width_order) \
	struct sbts_bucket name##_bucket[1 << (bucket_order)]; \
	volatile u64 name##_total_cnt __aligned(64);
	QUEUE_RECORD_LIST(RECORD_STRUCT);
#undef RECORD_STRUCT
};

struct queue_for_func_mgr {
	struct semaphore sema;
	spinlock_t lock;
	u64 array[MAX_QUEUE_NUM_FOR_FUNC];
	unsigned long used_bitmap;
};

/* param buffer manager in queue_manager */
struct param_buf_manager {
	struct mutex lock;
	u64 dev_addr_base;
	u64 host_addr_base;
	/* total param size */
	u32 param_buf_size;
	u32 page_size;
	/* bitmap size in byte */
	u32 bitmap_size;
	u32 bitmap_nr;
	u32 half_pages;
	u32 alloced_pages;
	/* record alloc buf size */
	u32 *size_buf;
	unsigned long *bitmap;
};


extern int
queue_ack_read_ack_data(struct queue_ack_s *ack_info,
		struct hpq_task_ack_desc *ack);
extern int
queue_ack_get_seq_host_iova(
		struct cn_core_set *req_core,
		struct queue_ack_s *ack_info, u64 *addr);
extern int
queue_ack_get(struct queue_ack_s *ack_info);
extern void
queue_ack_put(struct queue_ack_s *ack_info);

/* The helper functions to ref/unref the queue object */
extern struct queue *queue_get(struct queue_manager *queue_mgr, u64 devsid,
		cn_user user, int check_excep);
extern int queue_put(struct queue_manager *queue_mgr, struct queue *queue);

/* The function to get ack-desc of specified queue */
extern int queue_get_ack_sta(struct queue *queue,
		struct hpq_task_ack_desc *ack);

/* The helper functions to push task in queue */
extern int queue_push_task_ctrl_ticket(struct queue_manager *queue_manager,
			struct queue *queue, struct comm_task_desc *task,
			__u64 user, __u64 payload_size, bool update_ticket);

extern int queue_push_task_check_idle(struct queue_manager *queue_manager,
		struct queue *queue, struct comm_task_desc *task,
		u64 user, __u64 payload_size, u64 *is_idle);
extern int queue_push_task_ticket(struct queue_manager *queue_manager,
		struct queue *queue, struct comm_task_desc *task,
		u64 user, __u64 payload_size, u64 *ticket);
extern int queue_push_task_without_lock(struct queue_manager *queue_manager,
		struct queue *queue, struct comm_task_desc *task,
		u64 user, __u64 payload_size);
extern int queue_push_task_without_lock_and_ticket(struct queue_manager *queue_manager,
			struct queue *queue, struct comm_task_desc *task,
			__u64 user, __u64 payload_size);
extern int queue_push_task(struct queue_manager *pqueue_mgr,
		struct queue *queue, struct comm_task_desc *task, u64 user,
		__u64 payload_size);

extern int queue_ticket_reset(struct queue_manager *queue_manager,
		u64 queue_did, u64 user);

/* queue_do_exit() is called if @user oopsed or exited */
extern int queue_do_exit(u64 user, struct queue_manager *queue_mgr);

/* allocate/free parameter-buffer of task */
extern int
alloc_param_buf(struct queue_manager *pqueue_mgr, u32 size,
		host_addr_t *host_vaddr, dev_addr_t *dev_vaddr, u32 flags);
extern void free_param_buf(struct cn_core_set *core, dev_addr_t dev_addr);
extern void free_param_buf_array(struct cn_core_set *core,
		dev_addr_t *dev_vaddrs, int nmemb);

extern int queue_ack_sta_parse(struct cn_core_set *core, struct queue *queue,
		struct hpq_task_ack_desc ack_desc);

extern int cn_queue_init_for_func(struct sbts_set *sbts_set);
extern int cn_queue_exit_for_func(struct sbts_set *sbts_set);

extern int
cn_queue_create_for_func(struct sbts_set *sbts, u32 index);
extern int
cn_queue_destroy_for_func(struct sbts_set *sbts, u32 index);
extern int
cn_queue_sync_for_func(struct sbts_set *sbts, u32 index);
extern int
cn_queue_get_for_func(struct sbts_set *sbts, u32 *index, u64 *que_dsid);
extern void
cn_queue_put_for_func(struct sbts_set *sbts, u32 index);
extern int cn_queue_sync_sched(struct sbts_set *sbts, struct queue *queue);

extern int queue_manager_init(struct queue_manager **queue_manager,
		struct cn_core_set *core);
extern void queue_manager_exit(struct queue_manager *queue_manager);
extern int param_buf_manager_init(struct cn_core_set *);
extern void param_buf_manager_exit(struct cn_core_set *);

static inline int __sbts_queue_push_lock(
		struct queue *queue)
{
	if (mutex_lock_killable(&queue->mutex)) {
		__sync_bool_compare_and_swap(&queue->sta,
					QUEUE_NORMAL, QUEUE_EXCEPTION);
		cn_dev_core_err(queue->core, "queue dsid %#016llx push task killed by signal, sta:%d",
				queue->dev_sid, queue->sta);
		return -EINTR;
	}
	return 0;
}

static inline void __sbts_queue_push_unlock(struct queue *queue)
{
	mutex_unlock(&queue->mutex);
}

static inline void sbts_queue_add_host_time(struct queue *queue, s64 t)
{
	if (likely(t > 0))
		__sync_fetch_and_add(&queue->host_hw_time, (u64)t);
}

static inline u64 sbts_queue_get_host_time(struct queue *queue)
{
	return READ_ONCE(queue->host_hw_time);

}

static inline int __queue_ticket_update(
		struct queue *queue, u64 update_val)
{
	__sync_add_and_fetch(&queue->task_ticket, update_val);

	return 0;
}

static inline void __queue_topo_updating(
		struct queue *queue)
{
	queue->topo_updating = true;
}
#endif /* __SBTS_QUEUE_H */
