/*
 * sbts/sbts.c
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
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/ktime.h>
#include <linux/pid_namespace.h>
#include <linux/llist.h>
#include <linux/fdtable.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_os_compat.h"
#include "dbg.h"
#include "cndrv_hpq.h"
#include "sbts.h"
#include "queue.h"
#include "notifier.h"
#include "dma_async.h"
#include "./idc/idc.h"
#include "./tcdp/tcdp_task.h"
#include "./task_topo/sbts_topo.h"
#include "to_cndrv.h"
#include "cndrv_debug.h"
#include "cndrv_domain.h"
#include "cndrv_ioctl.h"
#include "cndrv_commu.h"
#include "cndrv_monitor.h"
#include "unotify.h"
#include "kprintf.h"
#include "hostfunc.h"
#include "cndrv_lpm.h"
#include "core_dump.h"
#include "cndrv_driver_capability.h"
#include "cndrv_xid.h"
#include "sbts_sram.h"
#include "jpu_async.h"


/* The definition of sync-thread manager */
struct sync_manager {
	struct cn_core_set *core;
	int exit_flag;
	struct task_struct *worker;
	wait_queue_head_t wait_head;
	struct llist_head pending_lhead;
	struct list_head sync_list;
};

#define BOARD_GENERATION_SHIFT	(24ULL)
#define BOARD_GENERATION_WIDTH	(4ULL)
#define BOARD_GENERATION_MASK	\
	((~((~0ULL) << BOARD_GENERATION_WIDTH)) << BOARD_GENERATION_SHIFT)
void sbts_get_board_generation(struct sbts_set *sbts, __u64 *type)
{
	struct cn_core_set *core = sbts->core;

	*type = (core->device_id & BOARD_GENERATION_MASK) >> BOARD_GENERATION_SHIFT;
}

int sbts_udelay_killable(struct cn_core_set *core,
		unsigned long time)
{
	udelay(time);

	if (core->reset_flag)
		return -EFAULT;

	if (fatal_signal_pending(current))
		return -EINTR;

	return 0;
}

int sbts_pause_killable(struct cn_core_set *core,
			unsigned long min, unsigned long max)
{
	usleep_range(min, max);

	if (core->reset_flag)
		return -EFAULT;

	if (fatal_signal_pending(current))
		return -EINTR;

	return 0;
}

int sbts_pause_stopable(struct cn_core_set *core,
			unsigned long min, unsigned long max)
{
	usleep_range(min, max);

	if (core->reset_flag)
		return -EFAULT;

	/* For resolve CTR-4337 issue, here need restart nointr:
	 * ERESTARTSYS maybe return INTR when user register sigaction
	 * User sigaction will change system default action for signal.
	 * So ERESTARTSYS will return user with  EINTR.
	 * For avoid such issue, here change to return ERESTARTNOINTR.
	 */
	if (signal_pending(current)) {
		if (fatal_signal_pending(current)) {
			return -EINTR;
		} else {
			return -ERESTARTNOINTR;
		}
	}

	return 0;
}

int sbts_pause(struct cn_core_set *core,
			unsigned long min, unsigned long max)
{
	usleep_range(min, max);

	if (core->reset_flag)
		return -EFAULT;

	return 0;
}

struct sbts_set *sbts_get_sbtsset_by_fd(int fd, cn_user *user)
{
	struct file *fp;
	struct fp_priv_data *priv_data;
	struct cn_core_set *core;

	rcu_read_lock();
	fp = cn_fcheck(fd);
	rcu_read_unlock();

	if (!fp || !fp->private_data)
		return NULL;

	priv_data = fp->private_data;
	core = priv_data->core;
	if (!core)
		return NULL;

	*user = (cn_user)fp;

	return core->sbts_set;
}

static int do_sched_ioctl(struct sched_manager *sched_mgr,
	struct comm_ctrl_desc *tx_ctl_desc, struct comm_ctrl_desc *rx_ctl_desc,
	__u64 user, __u64 payload_size)
{
	struct cn_core_set *core = sched_mgr->sbts->core;
	int rx_size = 0;
	u64 seq = 0;
	int time = SCHED_IOCTL_TIMEOUT;

	do {
		seq = commu_send_message_until_reset(sched_mgr->ctrl_ep, tx_ctl_desc,
				payload_size);

		/* send message success */
		if (seq) {
			break;
		}

		if (!time) {
			cn_dev_core_err(core, "send ctrl data timeout!");
			return -ETIMEDOUT;
		}

		time--;

		if (sbts_pause(core, 2, 5)) {
			cn_dev_core_err(core, "the reset flag has been set!");
			return -EFAULT;
		}
	} while (1);

	/* get */
	if (seq != commu_wait_for_message_seq_until_reset(sched_mgr->ctrl_ep, rx_ctl_desc,
			&rx_size, seq)) {
		cn_dev_core_err(core, "recv ctrl data fail");
		__sync_fetch_and_add(&sched_mgr->ctrl_fail_cnt, 1);
		return -EFAULT;
	}

	return 0;
}

int check_ack_data(struct cn_core_set *core, struct data_ack_desc *host_addr)
{
	int time = CHECK_ACK_DATA_TIMEOUT;
	struct data_ack_desc *ack = host_addr;

	if (!ack) {
		cn_dev_core_err(core, "host addr is null!");
		return -EINVAL;
	}

	while (--time) {
		if (ack->status == DATA_ACK_FINISH)
			return 0;
		else if (ack->status == DATA_ACK_ERROR) {
			cn_dev_core_err(core, "data ack error!");
			return -CN_KERNEL_DEBUG_ERROR_ACK;
		}
		/* TODO data validation check */

		/* TODO arm heart beats check */
		if (sbts_pause_killable(core, 2, 5)) {
			cn_dev_core_err(core, "user abort task!");
			return -EINTR;
		}
	}

	/* timeout */
	cn_dev_core_err(core, "get device data timeout!");
	return -CN_KERNEL_DEBUG_ERROR_TIMEOUT;
}

static int sched_ioctl(struct sched_manager *sched_mgr,
	struct comm_ctrl_desc *tx_ctl_desc,
	struct comm_ctrl_desc *rx_ctl_desc,
	__u64 user, __u64 payload_size)
{
	int ret = 0;

	ret = do_sched_ioctl(sched_mgr, tx_ctl_desc, rx_ctl_desc,
				user, payload_size);

	return ret;
}

static void sbts_board_info_init(struct cn_core_set *core)
{
	struct cn_board_info *info = &core->board_info;
	struct sbts_set *sbts = core->sbts_set;

	info->max_queue = sbts->max_queue - MAX_QUEUE_NUM_FOR_FUNC;
	info->max_notifier = sbts->max_notifier;
	info->max_dimx = MAX_DIM_NUM;
	info->max_dimy = MAX_DIM_NUM;
	info->max_dimz = MAX_DIM_NUM;
	/* support queue priority */
	info->queue_prio_support = 1;
}

static int sbts_hw_cfg_init(struct cn_core_set *core)
{
	int rc = 0;

	rc = cn_hw_cfg_compress_handle(core);
	if (rc) {
		cn_dev_core_err(core, "sbts hw cfg set failed!");
		return -EFAULT;
	}

	return rc;
}

__attribute__((unused))
static void sbts_hw_cfg_exit(struct cn_core_set *core)
{
	if (unlikely(!core)) {
		cn_dev_debug("host hw cfg core is null");
		return;
	}
}

void cn_sbts_get_sbts_info(struct cn_core_set *core,
		struct sbts_info_s *sbts_info)
{
	struct sbts_set *sbts = core->sbts_set;
	struct sbts_hw_info *info = NULL;
	struct sbts_basic_info *b_info = NULL;

	if (!sbts) {
		memset(sbts_info, 0, sizeof(struct sbts_info_s));
		return;
	}

	info = sbts->hw_info;
	if (info) {
		b_info = (struct sbts_basic_info *)info->data;

		if (b_info) {
			sbts_info->ct_ram_size = b_info->ct_ram_size;
			sbts_info->lt_ram_size = b_info->lt_ram_size;
			sbts_info->shared_mem_size = b_info->shared_mem_size;
			sbts_info->ldram_size = b_info->local_mem_size;
			sbts_info->ldram_max_size = b_info->ldram_max_size;
		}
	}

	sbts_info->multi_dev_notifier = sbts_notifier_feature_available(core);
	sbts_info->ipc_notifier = sbts_notifier_feature_available(core);
}

int cn_sbts_get_lmem_size(struct cn_core_set *core,
		__u64 *lmem_size)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct sbts_basic_info *info;

	if (!sbts) {
		cn_dev_core_err(core, "sbts is null!");
		return -EINVAL;
	}

	info = (struct sbts_basic_info *)sbts->hw_info->data;
	*lmem_size = info->local_mem_size;
	return 0;
}

#ifdef CONFIG_CNDRV_EDGE
static volatile unsigned int has_event;

void sbts_wake_up_sync_manager(struct sync_manager *sync_manager)
{
	__sync_fetch_and_or(&has_event, 1);
	if (waitqueue_active(&sync_manager->wait_head)) {
		wake_up_interruptible(&sync_manager->wait_head);
	}
}
#else
void sbts_wake_up_sync_manager(struct sync_manager *sync_manager)
{
}
#endif

int
sbts_wait_sync_desc_interruptible(struct sbts_set *sbts,
		struct sbts_sync_desc *desc)
{
	struct sync_manager *sync_mgr = sbts->sync_manager;
	int rc = 0;

	llist_add(&desc->l_entry, &sync_mgr->pending_lhead);

	/* wake up sync thread and sleep current thread */
	wake_up_interruptible(&sync_mgr->wait_head);

	/* wait for @completion_sync, it can be interrupted by a signal */
	rc = wait_for_completion_interruptible(&desc->completion_sync);
	if (unlikely(rc)) {
		WRITE_ONCE(desc->should_detach, true);
#ifdef CONFIG_CNDRV_EDGE
		/**
		 * guarantee to @should_detach is set before
		 * waking sync_thread up
		 */
		smp_wmb();
		sbts_wake_up_sync_manager(sync_mgr);
#endif
		wait_for_completion(&desc->completion_sync);
	}

	/* override @rc if @exit_code is set */
	rc = (desc->exit_code ? desc->exit_code : rc);

	return rc;
}

static void __sync_desc_handle(struct sbts_set *sbts_set,
		struct sbts_sync_desc *sync_desc,
		unsigned int *total_cnt, unsigned int *wait_cnt)
{
	int rc = 0;

	if (unlikely((READ_ONCE(sync_desc->should_detach) == true) ||
			(!sync_desc->sync_handler))) {
		list_del_init(&sync_desc->entry);
		complete(&sync_desc->completion_sync);
		return;
	}

	(*total_cnt)++;
	rc = sync_desc->sync_handler(sbts_set, sync_desc->data);
	if (rc == -EAGAIN) {
		(*wait_cnt)++;
		return;
	}

	sync_desc->exit_code = rc;
	list_del_init(&sync_desc->entry);
	complete(&sync_desc->completion_sync);
}

int sync_manager_thread(void *data)
{
#define SYNC_THREAD_MAX_SLEEP_TIME             (100)//us
#define SYNC_THREAD_MIN_SLEEP_TIME             (3)//us
	struct sbts_set *sbts_set = (struct sbts_set *)data;
	struct cn_core_set *core = sbts_set->core;
	struct sync_manager *sync_manager = sbts_set->sync_manager;
	struct sbts_sync_desc *sync_desc, *temp;
	struct llist_head *pending_lhead;
	struct list_head *sync_list;
	struct llist_node *new_batch;
	struct list_head new_list;
#ifndef CONFIG_CNDRV_EDGE
	ktime_t start, stop;
	unsigned long long usec;
#endif
	unsigned int total_cnt;
	unsigned int wait_cnt;

	if (!sync_manager) {
		cn_dev_core_err(core, "sync manager is null!");
		return 0;
	}

	pending_lhead = &sync_manager->pending_lhead;
	sync_list = &sync_manager->sync_list;

	if (current->nr_cpus_allowed > 1)
		CN_CLEAR_CPUMASK(0);

	allow_signal(SIGKILL);
	while (!kthread_should_stop()) {
		if (sync_manager->exit_flag || core->reset_flag) {
			msleep(20);
			continue;
		}

#ifdef CONFIG_CNDRV_EDGE
		wait_event_interruptible(sync_manager->wait_head, has_event || !llist_empty(pending_lhead));
		__sync_lock_release(&has_event);
#else
		if (list_empty(sync_list)) {
			/* sleep current thread when list is empty */
			if (wait_event_interruptible(sync_manager->wait_head,
					!llist_empty(pending_lhead))) {
				continue;
			}
		}

		start = ktime_get();
#endif
		total_cnt = wait_cnt = 0;
		new_batch = llist_del_all(pending_lhead);

		/* traverse @sync_list */
		list_for_each_entry_safe(sync_desc, temp, sync_list, entry) {
			__sync_desc_handle(sbts_set, sync_desc, &total_cnt,
					&wait_cnt);
		}

		/**
		 * move @sync_desc to @new_list in reverse order of
		 * @new_batch llist chain
		 */
		if (new_batch) {
			INIT_LIST_HEAD(&new_list);
			llist_for_each_entry_safe(sync_desc, temp, new_batch,
					l_entry) {
				list_add(&sync_desc->entry, &new_list);
				__sync_desc_handle(sbts_set, sync_desc,
						&total_cnt, &wait_cnt);
			}

			/* join @sync_list with @new_list */
			list_splice_tail(&new_list, sync_list);
		}

#ifndef CONFIG_CNDRV_EDGE
		stop = ktime_get();

		/* Sleep is for decrease cpu utilization. But the time of
		 * sleep will affect cpu utilization.
		 *
		 * So the time of sleep will dynamic adjusting.
		 * The sleep time is the same as last running time to keep
		 * cpu utilization between 50% and 100%.
		 *
		 * For avoid sleep time is too long and sync latency become
		 * too large, here set the max sleep time.
		 *
		 * For avoid sleep too long when sync_desc num descrease a lot.
		 * Here define descrease num is half of the wait sync_desc num.
		 * Then sleep time for next loop also be half of last time.
		 */
		usec = ktime_to_us(ktime_sub(stop, start));

		if (wait_cnt < (total_cnt >> 1)) {
			usec = usec >> 1;
		}

		usec = min_t(unsigned long long, usec, SYNC_THREAD_MAX_SLEEP_TIME);
		usec = max_t(unsigned long long, usec, SYNC_THREAD_MIN_SLEEP_TIME);

		usleep_range(SYNC_THREAD_MIN_SLEEP_TIME, usec);
#endif
	}

	return 0;
#undef SYNC_THREAD_MAX_SLEEP_TIME
#undef SYNC_THREAD_MIN_SLEEP_TIME
}

static int
sbts_sync_manager_init(struct sbts_set *sbts_set)
{
	int ret = 0;
	struct sync_manager *sync_manager;
	struct cn_core_set *core = sbts_set->core;

	sync_manager = cn_numa_aware_kzalloc(core, sizeof(struct sync_manager), GFP_KERNEL);
	if (!sync_manager) {
		cn_dev_core_err(core, "malloc queue sync manager failed");
		return -ENOMEM;
	}

	sbts_set->sync_manager = sync_manager;

	/* init sync Manager */
	sync_manager->exit_flag = 0;
	sync_manager->core = core;
	INIT_LIST_HEAD(&sync_manager->sync_list);
	init_llist_head(&sync_manager->pending_lhead);
	init_waitqueue_head(&sync_manager->wait_head);

	/* create worker thread */
	sync_manager->worker = sbts_kthread_run_on_node(sync_manager_thread,
			sbts_set, cn_core_get_numa_node_by_core(core),
			"%s", "sync_manager_thread");
	if (IS_ERR(sync_manager->worker)) {
		cn_dev_core_err(core, "create sync manager thread failed");
		ret = PTR_ERR(sync_manager->worker);
		goto worker_err;
	}

	return ret;

worker_err:
	cn_kfree(sync_manager);
	sbts_set->sync_manager = NULL;
	return ret;
}

static void
sbts_sync_manager_exit(struct sbts_set *sbts_set)
{
	struct sync_manager *sync_manager = NULL;

	if (unlikely(!sbts_set)) {
		cn_dev_err("sbts set is null!");
		return;
	}

	sync_manager = sbts_set->sync_manager;

	if (unlikely(!sync_manager)) {
		cn_dev_err("queue sync manager is null!");
		return;
	}

	/* exit sync manager */
	sync_manager->exit_flag = 1;
	smp_mb();
	send_sig(SIGKILL, sync_manager->worker, 1);
	if (sync_manager->worker) {
		kthread_stop(sync_manager->worker);
		sync_manager->worker = NULL;
	} else {
		cn_dev_err("queue sync worker is null");
	}

	if (!list_empty(&sync_manager->sync_list)) {
		struct sbts_sync_desc *sync_desc, *temp;

		/* something is wrong if list is not empty when exit */
		cn_dev_core_err(sync_manager->core,
				"sync list is not empty!");
		list_for_each_entry_safe(sync_desc, temp,
				&sync_manager->sync_list, entry) {
			sync_desc->exit_code = -EIO;
			list_del_init(&sync_desc->entry);
			complete(&sync_desc->completion_sync);
		}

	}

	if (!llist_empty(&sync_manager->pending_lhead)) {
		struct llist_node *l_first;
		struct sbts_sync_desc *sync_desc, *temp;

		/* something is wrong if llist is not empty when exit */
		cn_dev_core_err(sync_manager->core,
				"sync pending list is not empty!");
		l_first = llist_del_all(&sync_manager->pending_lhead);
		llist_for_each_entry_safe(sync_desc, temp, l_first, l_entry) {
			sync_desc->exit_code = -EIO;
			complete(&sync_desc->completion_sync);
		}

	}

	cn_kfree(sync_manager);
	sbts_set->sync_manager = NULL;
}

/**
 * check sbts task perf enable and fill perf desc
 * priv_size will be alined up to 8 if perf enabled
 * return the size of perf-data via specified task type.
 */
__u32 sbts_task_get_perf_info(struct sbts_set *sbts, struct queue *queue,
		__u64 task_type, struct sbts_queue_invoke_task *user_param,
		struct task_desc_data_v1 *task_desc, u32 *priv_size)
{
	struct sbts_perf_info perf_info = {0};
	struct cn_core_set *core = sbts->core;
	struct task_perf_desc *perf_desc;

	/* the task not user task */
	if (user_param->perf_disable & 0x1) {
		task_desc->is_perf_task = false;
		task_desc->clk_id       = CN_DEFAULT_CLOCKID;
		return 0;
	}

	/* cur task type not enable task */
	if (!(cn_monitor_perf_info_enable_task_type(queue->tgid_entry, core, task_type, &perf_info))) {
		task_desc->is_perf_task = false;
		task_desc->clk_id       = CN_DEFAULT_CLOCKID;
		return 0;
	}

	*priv_size = ALIGN(*priv_size, 8);

	task_desc->is_perf_task   = true;
	task_desc->clk_id         = perf_info.clk_id;

	perf_desc = (struct task_perf_desc *)((u64)task_desc->priv + (u64)*priv_size);
	perf_desc->correlation_id = cpu_to_le64(user_param->correlation_id);
	perf_desc->topo_id        = cpu_to_le64(user_param->topo_info);

	if ((!(perf_info.host_invoke))	&&
			((perf_info.collection_mode == DEFAULT_COLLECTION_MODE) ||
			(perf_info.performance_mode == CNTRACE_PERFORMANCE_MODE))) {
		perf_desc->host_invoke_ns = 0;
	} else {
		perf_desc->host_invoke_ns =
			cpu_to_le64(get_host_timestamp_by_clockid(perf_info.clk_id));
	}

	return sizeof(struct task_perf_desc);
}

int sbts_perf_task_tsinfo_size_get(struct cn_core_set *core, __u64 task_type,
		__u64 unique_seq_id, __u32 *normal_size, __u32 *append_size)
{
	int ret;
	struct comm_ctrl_desc tx_desc = {0};
	struct comm_ctrl_desc rx_desc = {0};
	struct sbts_set *sbts;
	struct sched_manager *sched_mgr;
	struct ctrl_desc_data_v1 *data = NULL;
	struct cd_perf_tsinfo_size_get *priv = NULL;

	if (!core) {
		cn_dev_err("core is NULL!");
		return -EINVAL;
	}
	sbts = (struct sbts_set *)core->sbts_set;
	if (!sbts)
		return -ENODEV;
	sched_mgr = sbts->sched_manager;

	tx_desc.version        = SBTS_VERSION;
	/* get ctrl desc data */
	data                   = (struct ctrl_desc_data_v1 *)tx_desc.data;
	data->type             = TSINFO_SIZE_GET;
	priv                   = (struct cd_perf_tsinfo_size_get *)data->priv;
	priv->task_type        = task_type;
	priv->unique_seq_id    = unique_seq_id;

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc,
			ANNOY_USER, sizeof(struct comm_ctrl_desc));
	if (unlikely(ret || rx_desc.sta)) {
		cn_dev_core_err(core, "sbts ioctl failed!");
		return -EFAULT;
	}

	data         = (struct ctrl_desc_data_v1 *)rx_desc.data;
	priv         = (struct cd_perf_tsinfo_size_get *)data->priv;
	*normal_size = priv->normal_size;
	*append_size = priv->append_size;

	return 0;
}

static inline void __dfree_d2d_async(struct cn_core_set *core,
		struct ctrl_desc_data_v1 *data)
{
	struct cd_dfree_d2d_async_desc *priv =
		(struct cd_dfree_d2d_async_desc *)data->priv;
	struct d2d_async_free_addr *slot;
	int i;

	for (i = 0; i < le64_to_cpu(priv->buf_num); ++i) {
		slot = &priv->buf_addr[i];
		sbts_d2d_async_free(core, le64_to_cpu(slot->ticket));
	}
}

static inline void __dfree_param_buf(struct cn_core_set *core,
		struct ctrl_desc_data_v1 *data)
{
#define ADDR_ARRAY_SIZE (16U)
	struct cd_dfree_host_buf_desc *priv =
			(struct cd_dfree_host_buf_desc *)data->priv;
	int i;
	int nmemb = 0;
	dev_addr_t dev_vaddrs[ADDR_ARRAY_SIZE];

	for (i = 0; i < le64_to_cpu(priv->buf_num); ++i) {
		dev_vaddrs[nmemb] = le64_to_cpu(priv->buf_addr[i].param_buf);
		nmemb += (!!priv->buf_addr[i].param_buf);
		if (nmemb == ADDR_ARRAY_SIZE) {
			free_param_buf_array(core, dev_vaddrs, nmemb);
			nmemb = 0;
		}


	}

	if (nmemb) {
		free_param_buf_array(core, dev_vaddrs, nmemb);
	}

#undef ADDR_ARRAY_SIZE
}

static inline void __dfree_notifier_free(struct cn_core_set *core,
		struct ctrl_desc_data_v1 *data)
{
	struct cd_dfree_notifier_desc *priv =
		(struct cd_dfree_notifier_desc *)data->priv;
	struct notifier_delay_free_addr *slot;
	int i;

	for (i = 0; i < le64_to_cpu(priv->buf_num); ++i) {
		slot = &priv->buf_addr[i];
		notifier_dev_free_release(core->sbts_set, le64_to_cpu(slot->ticket));
	}

}

void sbts_delay_free_thread(struct cn_core_set *core,
		void *data, void *rx_msg, int rx_size)
{
	struct comm_ctrl_desc *rx_cd;
	struct ctrl_desc_data_v1 *cd_data;

	rx_cd = (struct comm_ctrl_desc *)rx_msg;
	cd_data = (struct ctrl_desc_data_v1 *)rx_cd->data;
	switch (cd_data->type) {
	case DFREE_D2D_ASYNC:
		__dfree_d2d_async(core, cd_data);
		break;
	case DFREE_PARAM_BUF:
		__dfree_param_buf(core, cd_data);
		break;
	case DFREE_NOTIFIER_FREE:
		__dfree_notifier_free(core, cd_data);
		break;
	default:
		cn_dev_core_err(core, "receive ctrl type[%lld] wrong",
			cd_data->type);
		break;
	}
}

static u64
fill_desc_lpm_set(__u64 version, struct comm_ctrl_desc *ctrl_desc,
		struct sbts_set *sbts, u64 ops)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	/* version relate structure */
	struct ctrl_desc_data_v1 *data = NULL;
	struct cd_lpm_set *priv = NULL;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;

	switch (version) {
	case SBTS_VERSION:
		ctrl_desc->version = version;
		/* get ctrl desc data */
		data             = (struct ctrl_desc_data_v1 *)ctrl_desc->data;
		data->type       = LPM_SET;
		priv             = (struct cd_lpm_set *)data->priv;
		priv->ops        = cpu_to_le64(ops);

		/* calculate payload_size: version + ctrl + data + ctrl_priv */
		payload_size = sizeof(struct comm_ctrl_desc);
		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

static int sbts_lpm_set(struct cn_core_set *core, enum sbts_lpm_ops ops)
{
	int ret;
	u64 payload_size;
	struct comm_ctrl_desc tx_desc = {0};
	struct comm_ctrl_desc rx_desc = {0};
	struct sbts_set *sbts;
	struct sched_manager *sched_mgr;

	if (!core) {
		cn_dev_err("core is NULL!");
		return -EINVAL;
	}
	sbts = (struct sbts_set *)core->sbts_set;
	sched_mgr = sbts->sched_manager;

	payload_size = fill_desc_lpm_set(SBTS_VERSION, &tx_desc, sbts, ops);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed");
		return -ENOTSUPP;
	}

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc, ANNOY_USER, payload_size);
	if (unlikely(ret || rx_desc.sta)) {
		cn_dev_core_err(core, "sbts ioctl failed!");
		return -EFAULT;
	}

	return 0;
}

static int sbts_lpm_get_gate_count(struct cn_core_set *core, __u64 *gate_count,
		__u64 *ref_count)
{
	int ret;
	u64 payload_size;
	struct comm_ctrl_desc tx_desc = {0};
	struct comm_ctrl_desc rx_desc = {0};
	struct sbts_set *sbts;
	struct sched_manager *sched_mgr;
	struct ctrl_desc_data_v1 *data = (struct ctrl_desc_data_v1 *)rx_desc.data;
	struct cd_lpm_set *priv = (struct cd_lpm_set *)data->priv;

	if (!core) {
		cn_dev_err("core is NULL!");
		return -EINVAL;
	}
	sbts = (struct sbts_set *)core->sbts_set;
	sched_mgr = sbts->sched_manager;

	payload_size = fill_desc_lpm_set(SBTS_VERSION, &tx_desc, sbts,
			SBTS_LPM_GATE_COUNT);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed");
		return -ENOTSUPP;
	}

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc, ANNOY_USER, payload_size);
	if (unlikely(ret || rx_desc.sta)) {
		cn_dev_core_err(core, "sbts ioctl failed!");
		return -EFAULT;
	}

	*gate_count = priv->gate_count;
	*ref_count = priv->ref_count;


	return 0;
}

static inline int
sbts_support_task_runtime_lpm(struct cn_core_set *core)
{
	if (!isCEPlatform(core)) {
		cn_dev_core_err(core, "device id %lld not support task runtime low power!",
				core->device_id);
		return 0;
	}
	return 1;
}

static inline bool
sbts_enable_lpm(struct cn_core_set *core)
{
	switch (core->device_id) {
	case MLUID_270:
	case MLUID_270V1:
	case MLUID_270V:
	case MLUID_370:
	case MLUID_370V:
	case MLUID_CE3226:
	case MLUID_CE3226_EDGE:
	case MLUID_PIGEON:
	case MLUID_PIGEON_EDGE:
	case MLUID_590:
	case MLUID_590V:
		return true;
	default:
		return false;
	}
}

static int sbts_lpm_suspend(struct cn_core_set *core)
{
	return sbts_lpm_set(core, SBTS_LPM_SUSPEND);
}

static int sbts_lpm_resume(struct cn_core_set *core)
{
	struct sbts_set *sbts_set = core->sbts_set;

	/* here for wait mode switch done. */
	while (READ_ONCE(sbts_set->low_power_mode) == CN_SBTS_LP_BUSY_RUNTIME) {
		usleep_range(20, 30);
	}

	return sbts_lpm_set(core, SBTS_LPM_RESUME);
}

static int
sbts_lpm_mode_switch(struct cn_core_set *core, enum cn_sbts_lpm_mode mode)
{
	int ret;
	enum cn_sbts_lpm_mode old;
	enum sbts_lpm_ops ops;
	struct sbts_set *sbts_set = NULL;

	if (!core) {
		cn_dev_err("core is NULL!");
		return -EINVAL;
	}

	sbts_set = core->sbts_set;
	if (!sbts_set) {
		cn_dev_core_err(core, "sbts set is NULL");
		return -EINVAL;
	}

	if (sbts_set->low_power_mode == mode)
		return 0;

	if (!sbts_support_task_runtime_lpm(core))
		return -EINVAL;

	if (mode == CN_SBTS_LP_TASK_RUNTIME) {
		ops = SBTS_LPM_TASK_MODE;
	} else if (mode == CN_SBTS_LP_USER_RUNTIME) {
		ops = SBTS_LPM_USER_MODE;
	} else {
		cn_dev_core_err(core, "invalid mode %d", mode);
		return -EINVAL;
	}

	if (mutex_lock_killable(&sbts_set->lp_mode_lock))
		return -EINTR;

	old = sbts_set->low_power_mode;
	sbts_set->low_power_mode = CN_SBTS_LP_BUSY_RUNTIME;
	/* memory order of count and lpm mode */
	wmb();
	if (cn_lpm_is_resumed(core)) {
		cn_dev_core_err(core, "card busy now low power mode switch to %d failed!", mode);
		sbts_set->low_power_mode = old;
		mutex_unlock(&sbts_set->lp_mode_lock);
		return -EBUSY;
	}

	ret = sbts_lpm_set(core, ops);
	if (ret) {
		cn_dev_core_err(core, "low power mode switch to %d failed!", mode);
		sbts_set->low_power_mode = old;
		mutex_unlock(&sbts_set->lp_mode_lock);
		return -EINVAL;
	}

	sbts_set->low_power_mode = mode;
	mutex_unlock(&sbts_set->lp_mode_lock);

	return 0;
}

int cn_sbts_lpm_mode_switch_to_user(struct cn_core_set *core)
{
	return sbts_lpm_mode_switch(core, CN_SBTS_LP_USER_RUNTIME);
}

int cn_sbts_lpm_mode_switch_to_task(struct cn_core_set *core)
{
	return sbts_lpm_mode_switch(core, CN_SBTS_LP_TASK_RUNTIME);
}

bool cn_sbts_lpm_mode_check(struct cn_core_set *core, enum cn_sbts_lpm_mode mode)
{
	struct sbts_set *sbts_set = NULL;
	if (!core) {
		cn_dev_err("core is NULL!");
		return false;
	}

	sbts_set = core->sbts_set;
	if (!sbts_set) {
		return false;
	}

	return (READ_ONCE(sbts_set->low_power_mode) == mode);
}

static void sbts_lpm_show(struct cn_core_set *core, struct seq_file *m)
{
	int ret;
	__u64 gate_count, ref_count;
	struct sbts_set *sbts_set = core->sbts_set;

	if (!sbts_set)
		return;

	if (sbts_set->low_power_mode == CN_SBTS_LP_USER_RUNTIME)
		return;

	ret = sbts_lpm_get_gate_count(core, &gate_count, &ref_count);
	if (ret) {
		seq_printf(m, "get gate count failed! ret = %d\n", ret);
		return;
	}
	seq_printf(m, "sbts low power info: ref_count %lld, gate_count %lld\n",
			ref_count, gate_count);
}

const static struct lpm_module_ops lpm_ops = {
	.suspend        = sbts_lpm_suspend,
	.resume         = sbts_lpm_resume,
	.show			= sbts_lpm_show,
};

static int
sbts_low_power_init(struct sbts_set *sbts_set)
{
	struct cn_core_set *core = sbts_set->core;

	if (!sbts_enable_lpm(core))
		return 0;

	if (cn_lpm_register(core, LPM_MODULE_TYPE_IPU, &lpm_ops)) {
		cn_dev_core_err(core, "register lpm handle failed!");
		return -EINVAL;
	}
	sbts_set->low_power_mode = CN_SBTS_LP_USER_RUNTIME;
	mutex_init(&sbts_set->lp_mode_lock);

	return 0;
}

static int
sbts_low_power_exit(struct sbts_set *sbts_set)
{
	struct cn_core_set *core = sbts_set->core;

	if (!sbts_enable_lpm(core))
		return 0;

	if (cn_lpm_unregister(core, LPM_MODULE_TYPE_IPU)) {
		cn_dev_core_err(core, "unregister lpm handle failed!");
		return -EINVAL;
	}

	return 0;
}

static int
sbts_delay_free_init(struct sbts_set *sbts_set)
{
	int ret = 0;
	struct delay_free_set *dfree_set = NULL;
	struct cn_core_set *core = sbts_set->core;

	dfree_set = cn_numa_aware_kzalloc(core, sizeof(struct delay_free_set), GFP_KERNEL);
	if (!dfree_set) {
		cn_dev_core_err(core, "malloc delay free set mem failed");
		return -ENOMEM;
	}

	sbts_set->delay_free_set = dfree_set;
	/* create worker thread */
	dfree_set->worker = commu_wait_work_run(core, "sbts_df",
			sbts_set->sched_manager->dfree_ep, dfree_set,
			sbts_delay_free_thread);
	if (!dfree_set->worker) {
		cn_dev_core_err(core, "create delay free thread failed");
		ret = -EINVAL;
		goto worker_err;
	}

	return ret;

worker_err:
	cn_kfree(dfree_set);
	return ret;
}

static void
sbts_delay_free_exit(struct sbts_set *sbts_set)
{
	struct delay_free_set *dfree = NULL;

	if (unlikely(!sbts_set)) {
		cn_dev_err("sbts set is null!");
		return;
	}
	dfree = sbts_set->delay_free_set;

	if (unlikely(!dfree)) {
		cn_dev_err("delay free set is null!");
		return;
	}

	commu_wait_work_stop(sbts_set->core, dfree->worker);

	cn_kfree(dfree);
	sbts_set->delay_free_set = NULL;
}

#define SBTS_CONNECT_MSG_ENDPOINT(name, en_sram) \
({ \
	if (en_sram) { \
		sched->name##_ep = connect_sram_msg_endpoint(sched->name##_chnl); \
	} else { \
		sched->name##_ep = connect_msg_endpoint(sched->name##_chnl); \
	} \
})

static int sbts_commu_init(struct sbts_set *sbts)
{
	int ret = 0;
	struct cn_core_set *core = sbts->core;
	struct sched_manager *sched = NULL;
	const driver_capability_list_t *cap = NULL;
	int en_pcie_sram = cn_bus_pcie_sram_able(core->bus_set);
	__u64 generation = 0;

	sched = cn_numa_aware_kzalloc(core, sizeof(struct sched_manager), GFP_KERNEL);
	if (unlikely(!sched)) {
		cn_dev_core_err(core, "alloc schedule manager failed!");
		return -ENOMEM;
	}

	sched->ctrl_chnl = commu_open_a_channel("sbts_ctrl_channel", core, 0);
	if (!sched->ctrl_chnl) {
		cn_xid_err(core, XID_RPC_ERR, "ctrl_channel open failed");
		ret = -EFAULT;
		goto err;
	}

	sched->ctrl_fail_cnt = 0;

	SBTS_CONNECT_MSG_ENDPOINT(ctrl, 0);
	if (!sched->ctrl_ep) {
		cn_dev_core_err(core, "ctrl_channel ep connect failed");
		ret = -EFAULT;
		goto err_close_ctrl;
	}

	sched->task_chnl = commu_open_a_channel("sbts_task_channel", core, 0);
	if (!sched->task_chnl) {
		cn_xid_err(core, XID_RPC_ERR, "task_channel open failed");
		ret = -EFAULT;
		goto err_disconnect_ctrl;
	}

	SBTS_CONNECT_MSG_ENDPOINT(task, en_pcie_sram);
	if (!sched->task_ep) {
		cn_dev_core_err(core, "task_channel ep connect failed");
		ret = -EFAULT;
		goto err_close_task;
	}

	sched->dma_chnl = commu_open_a_channel("sbts_dma_trigger_channel", core, 0);
	if (!sched->dma_chnl) {
		cn_xid_err(core, XID_RPC_ERR, "dma_channel open failed");
		ret = -EFAULT;
		goto err_disconnect_task;
	}

	SBTS_CONNECT_MSG_ENDPOINT(dma, 0);
	if (!sched->dma_ep) {
		cn_dev_core_err(core, "dma_channel ep connect failed");
		ret = -EFAULT;
		goto err_close_dma;
	}

	sched->dfree_chnl = commu_open_a_channel("sbts_delay_free_channel", core, 0);
	if (!sched->dfree_chnl) {
		cn_xid_err(core, XID_RPC_ERR, "delay free channel open failed");
		ret = -EFAULT;
		goto err_disconnect_dma;
	}

	SBTS_CONNECT_MSG_ENDPOINT(dfree, 0);
	if (!sched->dfree_ep) {
		cn_dev_core_err(core, "delay free channel ep connect failed");
		ret = -EFAULT;
		goto err_close_dfree;
	}

	sched->idc_chnl = commu_open_a_channel("sbts_idc_channel", core, 0);
	if (!sched->idc_chnl) {
		cn_xid_err(core, XID_RPC_ERR, "idc_channel open failed");
		ret = -EFAULT;
		goto err_disconnect_dfree;
	}

	SBTS_CONNECT_MSG_ENDPOINT(idc, 0);
	if (!sched->idc_ep) {
		cn_dev_core_err(core, "idc_channel ep connect failed");
		ret = -EFAULT;
		goto err_close_idc;
	}

	sched->core_dump_chnl = commu_open_a_channel("sbts_core_dump_channel", core, 0);
	if (!sched->core_dump_chnl) {
		cn_xid_err(core, XID_RPC_ERR, "core_dump_channel open failed");
		ret = -EFAULT;
		goto err_disconnect_idc;
	}

	SBTS_CONNECT_MSG_ENDPOINT(core_dump, 0);
	if (!sched->core_dump_ep) {
		cn_dev_core_err(core, "core_dump_channel ep connect failed");
		ret = -EFAULT;
		goto err_close_core_dump;
	}

	sched->dbg_chnl = commu_open_a_channel("sbts_dbg_channel", core, 0);
	if (!sched->dbg_chnl) {
		cn_xid_err(core, XID_RPC_ERR, "dbg_channel open failed");
		ret = -EFAULT;
		goto err_disconnect_core_dump;
	}

	SBTS_CONNECT_MSG_ENDPOINT(dbg, 0);
	if (!sched->dbg_ep) {
		cn_dev_core_err(core, "dbg_channel ep connect failed");
		ret = -EFAULT;
		goto err_close_dbg;
	}

	sched->kprintf_chnl =
			commu_open_a_channel("sbts_kprintf_channel", core, 0);
	if (!sched->kprintf_chnl) {
		cn_dev_core_err(core, "kernel printf channel open failed");
		ret = -EFAULT;
		goto err_disconnect_dbg;
	}

	SBTS_CONNECT_MSG_ENDPOINT(kprintf, 0);
	if (!sched->kprintf_ep) {
		cn_dev_core_err(core, "kernel printf channel ep connect failed");
		ret = -EFAULT;
		goto err_close_kprintf;
	}

	cap = get_capability(core);
	if (cap->hostfunc_version >= CAPABILITY_HOSTFUNC_VERSION_1) {
		sched->hostfn_chnl = commu_open_a_channel(
				"sbts_hostfn_channel", core, 0);
		if (!sched->hostfn_chnl) {
			cn_xid_err(core, XID_RPC_ERR, "host function channel open "
					      "failed");
			ret = -EFAULT;
			goto err_disconnect_kprintf;
		}

		SBTS_CONNECT_MSG_ENDPOINT(hostfn, 0);
		if (!sched->hostfn_ep) {
			cn_dev_core_err(core, "host function channel ep "
					      "connect "
					      "failed");
			ret = -EFAULT;
			goto err_close_hostfn;
		}
	} else {
		cn_dev_core_warn(core, "device do not support host function "
				       "channel and endpoint");
	}

	sbts_get_board_generation(sbts, &generation);
	if (generation >= SBTS_BOARD_GENERATION_5) {
		sched->jpu_chnl = commu_open_a_channel("sbts_jpu_channel", core, 0);
		if (!sched->jpu_chnl) {
			cn_xid_err(core, XID_RPC_ERR, "jpu channel open failed");
			ret = -EFAULT;
			goto err_disconnect_hostfn;
		}

		SBTS_CONNECT_MSG_ENDPOINT(jpu, 0);
		if (!sched->jpu_ep) {
			cn_dev_core_err(core, "jpu channel ep connect failed");
			ret = -EFAULT;
			goto err_close_jpu;
		}
	}

	sched->ctl_ticket = 0;
	sched->fail_cnt = 0;
	sched->sbts = sbts;
	sched->ioctl = sched_ioctl;
	sbts->sched_manager = sched;

	return ret;
err_close_jpu:
	if (generation >= SBTS_BOARD_GENERATION_5) {
		close_a_channel(sched->jpu_chnl);
	}
err_disconnect_hostfn:
	if (cap->hostfunc_version >= CAPABILITY_HOSTFUNC_VERSION_1) {
		disconnect_endpoint(sched->hostfn_ep);
	}
err_close_hostfn:
	close_a_channel(sched->hostfn_chnl);
err_disconnect_kprintf:
	disconnect_endpoint(sched->kprintf_ep);
err_close_kprintf:
	close_a_channel(sched->kprintf_chnl);
err_disconnect_dbg:
	disconnect_endpoint(sched->dbg_ep);
err_close_dbg:
	close_a_channel(sched->dbg_chnl);
err_disconnect_core_dump:
	disconnect_endpoint(sched->core_dump_ep);
err_close_core_dump:
	close_a_channel(sched->core_dump_chnl);
err_disconnect_idc:
	disconnect_endpoint(sched->idc_ep);
err_close_idc:
	close_a_channel(sched->idc_chnl);
err_disconnect_dfree:
	disconnect_endpoint(sched->dfree_ep);
err_close_dfree:
	close_a_channel(sched->dfree_chnl);
err_disconnect_dma:
	disconnect_endpoint(sched->dma_ep);
err_close_dma:
	close_a_channel(sched->dma_chnl);
err_disconnect_task:
	disconnect_endpoint(sched->task_ep);
err_close_task:
	close_a_channel(sched->task_chnl);
err_disconnect_ctrl:
	disconnect_endpoint(sched->ctrl_ep);
err_close_ctrl:
	close_a_channel(sched->ctrl_chnl);
err:
	cn_kfree(sched);
	return ret;
}

static void sbts_commu_exit(struct sbts_set *sbts)
{
	struct cn_core_set *core;
	struct sched_manager *sched;

	if (unlikely(!sbts)) {
		cn_dev_err("sbts is null!");
		return;
	}

	core = sbts->core;
	sched = sbts->sched_manager;
	if (unlikely(!sched)) {
		cn_dev_core_err(core, "sched manager is null!");
		return;
	}

	if (unlikely(sched->ctrl_fail_cnt)) {
		cn_dev_core_err(core, "ctrl channel fail recv cnt %ld",
				sched->ctrl_fail_cnt);
	}

	if (unlikely(sbts_commu_detach(sbts))) {
		cn_dev_core_err(core, "sbts commu detach failed!");
	}

	if (likely(sched->hostfn_ep)) {
		disconnect_endpoint(sched->hostfn_ep);
	}

	if (likely(sched->kprintf_ep)) {
		disconnect_endpoint(sched->kprintf_ep);
	}

	if (likely(sched->dbg_ep)) {
		disconnect_endpoint(sched->dbg_ep);
	}

	if (likely(sched->core_dump_ep)) {
		disconnect_endpoint(sched->core_dump_ep);
	}

	if (likely(sched->idc_ep)) {
		disconnect_endpoint(sched->idc_ep);
	}

	if (likely(sched->dma_ep)) {
		disconnect_endpoint(sched->dma_ep);
	}

	if (likely(sched->task_ep)) {
		disconnect_endpoint(sched->task_ep);
	}

	if (likely(sched->ctrl_ep)) {
		disconnect_endpoint(sched->ctrl_ep);
	}

	if (likely(sched->dfree_ep)) {
		disconnect_endpoint(sched->dfree_ep);
	}

	if (likely(sched->jpu_ep)) {
		disconnect_endpoint(sched->jpu_ep);
	}

	if (likely(sched->kprintf_chnl)) {
		close_a_channel(sched->kprintf_chnl);
	}

	if (likely(sched->hostfn_chnl)) {
		close_a_channel(sched->hostfn_chnl);
	}

	if (likely(sched->dbg_chnl)) {
		close_a_channel(sched->dbg_chnl);
	}

	if (likely(sched->core_dump_chnl)) {
		close_a_channel(sched->core_dump_chnl);
	}

	if (likely(sched->idc_chnl)) {
		close_a_channel(sched->idc_chnl);
	}

	if (likely(sched->dma_chnl)) {
		close_a_channel(sched->dma_chnl);
	}

	if (likely(sched->task_chnl)) {
		close_a_channel(sched->task_chnl);
	}

	if (likely(sched->ctrl_chnl)) {
		close_a_channel(sched->ctrl_chnl);
	}

	if (likely(sched->dfree_chnl)) {
		close_a_channel(sched->dfree_chnl);
	}

	if (likely(sched->jpu_chnl)) {
		close_a_channel(sched->jpu_chnl);
	}

	cn_kfree(sched);
	sbts->sched_manager = NULL;
}

static int ncs_do_exit(__u64 user, struct sbts_set *sbts_set)
{
	return destroy_ncs_resource(sbts_set, (cn_user)user);
}

static int tcdp_do_exit(__u64 user, struct sbts_set *sbts_set)
{
	return destroy_tcdp_resource(sbts_set, (cn_user)user);
}

/**
 * resource release when close dev
 */
int cn_sbts_do_exit(cn_user user, struct cn_core_set *core)
{
	struct sbts_set *sbts_set = core->sbts_set;

	if (!sbts_set)
		return 0;

	sbts_topo_do_exit((u64)user, sbts_set->topo_manager);
	queue_do_exit((u64) user, sbts_set->queue_manager);
	sbts_hostfunc_do_exit((u64)user, sbts_set->hostfunc_set);
	notifier_do_exit((u64) user, sbts_set->notifier_mgr);
	tcdp_do_exit((u64) user, sbts_set);
	ncs_do_exit((u64) user, sbts_set);
	sbts_idc_do_exit((u64) user, sbts_set->idc_manager);
	sbts_efd_do_exit((u64)user, sbts_set->efd_manager);
	dbg_do_exit((u64) user, sbts_set->dbg_set);

	return 0;
}

int cn_sbts_priv_data_init(struct fp_priv_data *priv_data)
{
	struct cn_core_set *core = priv_data->core;
	struct sbts_set *sbts = core->sbts_set;
	struct sbts_fp_priv *sbts_priv = NULL;
	int ret = 0;

	priv_data->sbts_priv_data = NULL;

	if (!sbts) {
		return 0;
	}

	sbts_priv = cn_kzalloc(sizeof(struct sbts_fp_priv), GFP_KERNEL);
	if (!sbts_priv) {
		cn_dev_core_err(core, "malloc priv failed!");
		return -ENOMEM;
	}
	sbts_priv->sbts_set = sbts;
	sbts_priv->fp_id = priv_data->fp_id;
	sbts_priv->tgid = current->tgid;

	ret = sbts_topo_priv_init(sbts, sbts_priv);
	if (ret) {
		cn_dev_core_err(core, "init topo priv failed!");
		cn_kfree(sbts_priv);
		return ret;
	}

	priv_data->sbts_priv_data = sbts_priv;
	return 0;
}

void cn_sbts_priv_data_exit(struct fp_priv_data *priv_data)
{
	struct sbts_fp_priv *sbts_priv;

	if (!priv_data->sbts_priv_data)
		return;

	sbts_priv = (struct sbts_fp_priv *)priv_data->sbts_priv_data;

	sbts_topo_priv_exit(sbts_priv);

	cn_kfree(priv_data->sbts_priv_data);
}

int cn_sbts_init(struct cn_core_set *core)
{
	struct sbts_set *sbts = NULL;

	if (!core) {
		cn_dev_err("core is null");
		return -EINVAL;
	}
	if ((core->device_id == MLUID_370_DEV) ||
			(core->device_id == MLUID_590_DEV)) {
		cn_dev_core_debug(core, "not support dev mode.\n");
		return 0;
	}

	/* do init if pf-only or vf */
	if (!cn_core_is_vf(core) && cn_is_mim_en(core)) {
		cn_dev_core_debug(core, "not pf-only or vf");
		return 0;
	}

	cn_dev_core_debug(core, "%s init start", __func__);

	sbts = (struct sbts_set *) cn_numa_aware_kzalloc(core, sizeof(struct sbts_set),
				GFP_KERNEL);
	if (!sbts) {
		cn_dev_core_err(core, "malloc sbts_set fail");
		return -ENOMEM;
	}

	core->sbts_set = sbts;
	sbts->core = core;

	sbts_drv_to_cndrv_init(sbts);

	return 0;
}

static void sbts_set_param_init(struct sbts_set *sbts)
{
	struct cn_core_set *core = sbts->core;

	sbts->outbd_able = cn_bus_outbound_able(core->bus_set);

	if (cn_core_is_vf(core)) {
		sbts->max_queue = QUEUE_NUM_SRIOV;
		sbts->max_notifier = NOTIFIER_NUM_SRIOV;
	} else if (core->device_id == MLUID_220 ||
			core->device_id == MLUID_220_EDGE ||
			core->device_id == MLUID_CE3226 ||
			core->device_id == MLUID_CE3226_EDGE ||
			core->device_id == MLUID_PIGEON ||
			core->device_id == MLUID_PIGEON_EDGE) {
		sbts->max_queue = QUEUE_NUM_SPECIAL;
		sbts->max_notifier = NOTIFIER_NUM_SPECIAL;
	} else {
		sbts->max_queue = QUEUE_NUM_NORMAL;
		sbts->max_notifier = NOTIFIER_NUM_NORMAL;
	}
}

int cn_sbts_late_init(struct cn_core_set *core)
{
	struct sbts_set *sbts = core->sbts_set;
	int ret = 0;

	if (!sbts) {
		cn_dev_core_debug(core, "sbts not inited");
		return 0;
	}

	sbts_set_param_init(sbts);

	ret = sbts_commu_init(sbts);
	if (ret) {
		cn_dev_core_err(core, "sbts commu init failed");
		return -EFAULT;
	}

	ret = cn_get_hw_info(sbts);
	if (ret) {
		cn_dev_core_err(core, "get mlu hw info failed!");
		goto err_commu_exit;
	}

	ret = sbts_dbg_init(sbts);
	if (ret) {
		cn_dev_core_err(core, "sbts dbg init failed!");
		goto err_release_hw_info;
	}

	ret = sbts_sram_manager_init(core);
	if (ret) {
		cn_dev_core_err(core, "sbts sram init failed!");
		goto err_release_dbg;
	}

	ret = sbts_kprintf_init(sbts);
	if (ret) {
		cn_dev_core_err(core, "sbts kprintf init failed");
		goto err_sram_exit;
	}

	ret = sbts_dump_manager_init(&sbts->dump_mgr, core);
	if (ret) {
		cn_dev_core_err(core, "core dump manager init failed!");
		goto err_kprintf_exit;
	}

	if (queue_manager_init(&sbts->queue_manager,
				core)) {
		cn_dev_core_err(core, "queue manager init failed!");
		ret = -EPIPE;
		goto err_dump_manager_exit;
	}

	ret = notifier_manager_init(&sbts->notifier_mgr, core);
	if (ret) {
		cn_dev_core_err(core, "notifier manager init failed!");
		goto err_queue_mgr_exit;
	}

	ret = param_buf_manager_init(core);
	if (ret) {
		cn_dev_core_err(core, "param buf init failed");
		goto err_notifier_mgr_exit;
	}

	ret = cn_queue_init_for_func(core->sbts_set);
	if (ret) {
		cn_dev_core_err(core, "queue init for func failed");
		goto err_param_buf_exit;
	}

	ret = dma_async_manager_init(&sbts->dma_async_manager, core);
	if (ret) {
		cn_dev_core_err(core, "dma async manager init failed!");
		goto err_queue_init_for_func;
	}

	ret = sbts_idc_manager_init(&sbts->idc_manager, core);
	if (ret) {
		cn_dev_core_err(core, "idc manager init failed!");
		goto err_dma_mgr_exit;
	}

	ret = sbts_delay_free_init(sbts);
	if (ret) {
		cn_dev_core_err(core, "sbts delay free init failed!");
		goto err_idc_mgr_exit;
	}

	ret = sbts_sync_manager_init(sbts);
	if (ret) {
		cn_dev_core_err(core, "sbts queue sync init failed!");
		goto err_delay_free;
	}

	ret = sbts_efd_manager_init(&sbts->efd_manager, core);
	if (ret) {
		cn_dev_core_err(core, "efd manager init failed!");
		goto err_sync_manager_exit;
	}

	ret = sbts_hostfunc_init(sbts);
	if (ret) {
		cn_dev_core_err(core, "sbts host function init failed");
		goto err_efd_manager_exit;
	}

	ret = sbts_tcdp_init(sbts);
	if (ret) {
		cn_dev_core_err(core, "sbts tcdp init failed!");
		goto err_hostfunc_exit;
	}

	ret = sbts_low_power_init(sbts);
	if (ret) {
		cn_dev_core_err(core, "sbts low power init failed!");
		goto err_tcdp_exit;
	}

	ret = sbts_hw_cfg_init(core);
	if (ret) {
		cn_dev_core_err(core, "sbts hw cfg init failed");
		goto err_low_power_exit;
	}

	ret = sbts_topo_manager_init(&sbts->topo_manager, core);
	if (ret) {
		cn_dev_core_err(core, "sbts task topo init failed");
		goto err_hw_cfg_exit;
	}

	ret = sbts_jpu_manager_init(&sbts->jpu_mgr, core);
	if (ret) {
		cn_dev_core_err(core, "jpu manager init failed!");
		goto err_topo_manager_exit;
	}

	mutex_init(&sbts->policy_lock);
	sbts_board_info_init(core);

	return 0;

err_topo_manager_exit:
	sbts_topo_manager_exit(sbts->topo_manager);
err_hw_cfg_exit:
	sbts_hw_cfg_exit(core);
err_low_power_exit:
	sbts_low_power_exit(sbts);
err_tcdp_exit:
	sbts_tcdp_exit(sbts);
err_hostfunc_exit:
	sbts_hostfunc_exit(sbts->hostfunc_set);
err_efd_manager_exit:
	sbts_efd_manager_exit(sbts->efd_manager);
err_sync_manager_exit:
	sbts_sync_manager_exit(sbts);
err_delay_free:
	sbts_delay_free_exit(sbts);
err_idc_mgr_exit:
	sbts_idc_manager_exit(sbts->idc_manager);
err_dma_mgr_exit:
	dma_async_manager_exit(sbts->dma_async_manager);
err_queue_init_for_func:
	cn_queue_exit_for_func(sbts);
err_param_buf_exit:
	param_buf_manager_exit(core);
err_notifier_mgr_exit:
	notifier_manager_exit(sbts->notifier_mgr);
err_queue_mgr_exit:
	queue_manager_exit(sbts->queue_manager);
err_dump_manager_exit:
	sbts_dump_manager_exit(sbts->dump_mgr);
err_kprintf_exit:
	sbts_kprintf_exit(sbts->kprintf_set);
err_sram_exit:
err_release_dbg:
	sbts_dbg_exit(sbts->dbg_set);
err_release_hw_info:
	cn_release_hw_info(sbts);
err_commu_exit:
	sbts_commu_exit(sbts);
	return ret;
}

void cn_sbts_exit(struct cn_core_set *core)
{
	struct sbts_set *sbts = core->sbts_set;

	cn_kfree(sbts);
	core->sbts_set = NULL;
}

void cn_sbts_late_exit(struct cn_core_set *core)
{
	struct sbts_set *sbts = core->sbts_set;
	struct queue_manager *queue_manager = NULL;

	if (!sbts) {
		cn_dev_core_err(core, "sbts set is null!");
		return;
	}

	sbts_drv_to_cndrv_exit(sbts);

	queue_manager = sbts->queue_manager;

	if (!queue_manager) {
		cn_dev_core_err(core, "queue manager is null!");
	} else {
		queue_manager->driver_unload_flag = 1;
	}

	sbts_jpu_manager_exit(sbts->jpu_mgr);
	sbts_topo_manager_exit(sbts->topo_manager);
	sbts_hw_cfg_exit(core);
	sbts_low_power_exit(sbts);
	sbts_tcdp_exit(sbts);
	sbts_efd_manager_exit(sbts->efd_manager);
	sbts_sync_manager_exit(sbts);
	sbts_delay_free_exit(sbts);
	sbts_idc_manager_exit(sbts->idc_manager);
	dma_async_manager_exit(sbts->dma_async_manager);
	cn_queue_exit_for_func(sbts);
	param_buf_manager_exit(core);
	notifier_manager_exit(sbts->notifier_mgr);
	sbts_hostfunc_exit(sbts->hostfunc_set);
	queue_manager_exit(sbts->queue_manager);
	sbts_dump_manager_exit(sbts->dump_mgr);
	sbts_kprintf_exit(sbts->kprintf_set);
	sbts_dbg_exit(sbts->dbg_set);
	sbts_shm_global_dev_exit(sbts);
	cn_release_hw_info(sbts);
	sbts_commu_exit(sbts);
}

int cn_sbts_global_init(void)
{
	int ret;

	ret = sbts_shm_global_init();
	if (ret)
		return ret;

	ret = cn_sbts_idc_global_init();
	if (ret)
		return ret;

	return 0;
}

void cn_sbts_global_exit(void)
{

	cn_sbts_idc_global_exit();
	sbts_shm_global_exit();
}
