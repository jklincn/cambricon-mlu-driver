/*
 * sbts/dbg.c
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

#include <linux/slab.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/kref.h>
#include <linux/delay.h>
#include <linux/semaphore.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/mman.h>

#include "../core/cndrv_ioctl.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_hpq.h"
#include "sbts.h"
#include "dbg.h"
#include "queue.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"

/****************************************************************/
/* data structure define */
struct debug_controller_st {
	__u32 pid;
	__u64 user;
	__u64 core_map_uaddr;
	__u64 task_map_uaddr;
	host_addr_t task_shm_host;
	dev_addr_t task_shm_dev;
	struct list_head entry;
};

struct debug_core_info {
	__u64 core_ver;
	__u64 core_num;
	__u64 each_size;
	__u64 core_shm_size;
	host_addr_t core_shm_host;
	dev_addr_t core_shm_dev;
};

struct debug_task_info {
	__u64 task_ver;
	__u64 task_size;
};

struct debug_manager {
	__u32 ref_count;
	__u32 initialized;
	struct mutex init_lock;

	struct debug_core_info core;
	struct debug_task_info task;

	__u32 controller_num;
	struct list_head list;
	struct mutex lock;

	struct sbts_dbg_set *dbg;
};
/****************************************************************/
/* utility function */
static int
__util_shm_alloc(struct debug_manager *mgr, __u64 size,
			host_addr_t *haddr, dev_addr_t *daddr)
{
	struct sbts_set *sbts = mgr->dbg->sbts;
	struct cn_core_set *core = sbts->core;
	int ret;

	if (sbts->outbd_able) {
		ret = cn_host_share_mem_alloc(0, haddr, daddr, size, core);
	} else {
		ret = cn_device_share_mem_alloc(0, haddr, daddr, size, core);
	}

	if (unlikely(ret)) {
		cn_dev_core_err(core, "share mem alloc failed");
		return -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
	}

	return ret;
}

static void
__util_shm_free(struct debug_manager *mgr,
		host_addr_t haddr, dev_addr_t daddr)
{
	struct sbts_set *sbts = mgr->dbg->sbts;
	struct cn_core_set *core = sbts->core;

	if (sbts->outbd_able) {
		cn_host_share_mem_free(0, haddr, daddr, core);
	} else {
		cn_device_share_mem_free(0, haddr, daddr, core);
	}
}

static int
__util_memory_map(struct debug_manager *mgr, __u64 user,
		host_addr_t haddr, __u64 mapped_size, __u64 *vaddr)
{
	struct sbts_set *sbts = mgr->dbg->sbts;
	struct cn_core_set *core = sbts->core;
	unsigned long va_start = 0;

	va_start = cn_share_mem_mmap(
				user,
				haddr,
				mapped_size,
				PROT_READ,
				sbts->outbd_able,
				core);
	if (IS_ERR_VALUE(va_start)) {
		cn_dev_core_err(core, "debug manager map failed");
		return va_start;
	}

	*vaddr = va_start;
	return 0;
}

static void
__util_memory_unmap(struct debug_manager *mgr, __u64 user,
		__u64 mapped_addr, __u64 mapped_size)
{
	struct sbts_set *sbts = mgr->dbg->sbts;
	struct cn_core_set *core = sbts->core;
	int ret;

	ret = cn_share_mem_munmap(
				user,
				mapped_addr,
				mapped_size,
				sbts->outbd_able,
				core);
	if (unlikely(ret))
		cn_dev_core_err(core, "unmap debug core sta failed");

}

static struct debug_controller_st *
__util_controller_get(struct debug_manager *mgr, __u64 user)
{
	struct debug_controller_st *st;

	list_for_each_entry(st, &mgr->list, entry) {
		if (user == st->user)
			return st;
	}
	return NULL;
}

static inline struct sched_manager *
__util_get_sch_mgr(struct sbts_set *sbts)
{
	return sbts->sched_manager;
}

static inline struct debug_manager *
__util_get_debug_mgr(struct sbts_set *sbts)
{
	return sbts->dbg_set->mgr;
}
/****************************************************************/
/* sbts ioctl to device */
/* TODO attribute check argc */
static int
__raw_debug_ioctl(struct debug_manager *mgr,
		struct comm_ctrl_desc *tx, struct comm_ctrl_desc *rx,
		__u64 user, __u32 type, int argc, ...)
{
	struct sbts_set *sbts = mgr->dbg->sbts;
	struct cn_core_set *core = sbts->core;
	struct sched_manager *sch = __util_get_sch_mgr(sbts);
	struct ctrl_desc_data_v1 *data;
	struct cd_debug_ctrl *priv;
	int ret;
	int i;
	va_list argv;

	tx->version      = 0;
	data             = (struct ctrl_desc_data_v1 *)&tx->data;
	data->type       = DEBUG_CTRL;
	data->user       = user;
	priv             = (struct cd_debug_ctrl *)data->priv;
	priv->type       = type;

	va_start(argv, argc);
	for (i = 0; i < argc; i++) {
		priv->priv[i] = va_arg(argv, __u64);
	}
	va_end(argv);

	ret = sch->ioctl(sch, tx, rx, user, sizeof(struct comm_ctrl_desc));
	if (unlikely(ret || rx->sta)) {
		cn_dev_core_err(core, "debug manager ioctl failed");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}

	return 0;
}

static int
__ioctl_get_core_info(struct debug_manager *mgr, __u64 user,
		struct debug_core_info *info)
{
	struct comm_ctrl_desc tx = {0}, rx = {0};
	struct ctrl_desc_data_v1 *rxdata;
	struct cd_debug_ctrl *rxpriv;
	int ret;

	ret = __raw_debug_ioctl(mgr, &tx, &rx, user,
			DEBUG_GET_CORE_INFO, 0);
	if (ret)
		return ret;

	rxdata = (struct ctrl_desc_data_v1 *)&rx.data;
	rxpriv = (struct cd_debug_ctrl *)rxdata->priv;

	info->core_ver      = rxpriv->priv[0];
	info->core_num      = rxpriv->priv[1];
	info->each_size     = rxpriv->priv[2];
	info->core_shm_size = info->core_num * info->each_size;

	return 0;
}

static int
__ioctl_get_task_info(struct debug_manager *mgr, __u64 user,
		struct debug_task_info *info)
{
	struct comm_ctrl_desc tx = {0}, rx = {0};
	struct ctrl_desc_data_v1 *rxdata;
	struct cd_debug_ctrl *rxpriv;
	int ret;

	ret = __raw_debug_ioctl(mgr, &tx, &rx, user,
			DEBUG_GET_TASK_INFO, 0);
	if (ret)
		return ret;

	rxdata = (struct ctrl_desc_data_v1 *)&rx.data;
	rxpriv = (struct cd_debug_ctrl *)rxdata->priv;

	info->task_ver   = rxpriv->priv[0];
	info->task_size  = rxpriv->priv[1];

	return 0;
}

static int
__ioctl_init_core(struct debug_manager *mgr, __u64 user,
		__u64 shm_iova, __u64 shm_size)
{
	struct comm_ctrl_desc tx = {0}, rx = {0};

	return __raw_debug_ioctl(mgr, &tx, &rx, user,
				DEBUG_INIT_CORE_INFO, 2, shm_iova, shm_size);
}

static int
__ioctl_init_task(struct debug_manager *mgr, __u64 user, __u32 pid,
		__u64 shm_iova, __u64 shm_size)
{
	struct comm_ctrl_desc tx = {0}, rx = {0};

	return __raw_debug_ioctl(mgr, &tx, &rx, user,
				DEBUG_INIT_TASK_INFO, 3, shm_iova, shm_size, pid);
}

static int
__ioctl_exit_core(struct debug_manager *mgr, __u64 user)
{
	struct comm_ctrl_desc tx = {0}, rx = {0};

	return __raw_debug_ioctl(mgr, &tx, &rx, user,
				DEBUG_EXIT_CORE_INFO, 0);
}

static int
__ioctl_exit_task(struct debug_manager *mgr, __u64 user, __u64 pid)
{
	struct comm_ctrl_desc tx = {0}, rx = {0};

	return __raw_debug_ioctl(mgr, &tx, &rx, user,
				DEBUG_EXIT_TASK_INFO, 1, pid);
}

static int
__ioctl_register_user(struct debug_manager *mgr, __u64 user, __u64 pid)
{
	struct comm_ctrl_desc tx = {0}, rx = {0};

	return __raw_debug_ioctl(mgr, &tx, &rx, user,
				DEBUG_REGISTER_USER, 1, pid);
}

static int
__ioctl_unreigster_user(struct debug_manager *mgr, __u64 user, __u64 pid)
{
	struct comm_ctrl_desc tx = {0}, rx = {0};

	return __raw_debug_ioctl(mgr, &tx, &rx, user,
				DEBUG_UNREGISTER_USER, 1, pid);
}

static int
__ioctl_update_head(struct debug_manager *mgr, __u64 user,
		__u64 pid, __u64 head)
{
	struct comm_ctrl_desc tx = {0}, rx = {0};

	return __raw_debug_ioctl(mgr, &tx, &rx, user,
					DEBUG_UPDATE_HEAD, 2, pid, head);
}

/****************************************************************/
/* data structure management */
static int __debug_try_init(struct debug_manager *mgr)
{
	struct debug_core_info *core = &mgr->core;
	int ret = 0;

	if (mutex_lock_killable(&mgr->init_lock)) {
		cn_dev_err("mutex killed");
		return 1;
	}

	mgr->ref_count++;

	if (mgr->initialized) {
		mutex_unlock(&mgr->init_lock);
		return ret;
	}

	ret = __util_shm_alloc(mgr,
				core->core_shm_size,
				&core->core_shm_host,
				&core->core_shm_dev);
	if (unlikely(ret)) {
		cn_dev_err("debug manager shm alloc failed");
		ret = 1;
		goto out;
	}

	ret = __ioctl_init_core(mgr,
				ANNOY_USER,
				core->core_shm_dev,
				core->core_shm_size);
	if (unlikely(ret)) {
		cn_dev_err("debug manager init core info failed");
		ret = 1;
		goto free_shm;
	}

	mgr->initialized = 1;
	mutex_unlock(&mgr->init_lock);
	return ret;

free_shm:
	__util_shm_free(mgr, core->core_shm_host, core->core_shm_dev);
out:
	mgr->ref_count--;
	mutex_unlock(&mgr->init_lock);
	return ret;
}

static void __debug_try_exit(struct debug_manager *mgr)
{
	struct debug_core_info *core;
	int ret;

	mutex_lock(&mgr->init_lock);

	mgr->ref_count--;
	if (mgr->ref_count) {
		mutex_unlock(&mgr->init_lock);
		return;
	}

	core = &mgr->core;

	ret = __ioctl_exit_core(mgr, ANNOY_USER);
	if (unlikely(ret)) {
		cn_dev_err("fatal error debug manager exit core info failed");
		return;
	}

	__util_shm_free(mgr, core->core_shm_host, core->core_shm_dev);
	mgr->initialized = 0;
	mutex_unlock(&mgr->init_lock);
}

static int
__debug_controller_init(struct debug_manager *mgr, __u32 pid, __u64 user,
			struct debug_controller_st **pst)
{
	struct debug_controller_st *st;
	struct debug_task_info *task;
	struct debug_core_info *core;
	int ret;

	if (mutex_lock_killable(&mgr->lock)) {
		cn_dev_err("mutex killed");
		return 1;
	}

	if (unlikely(__util_controller_get(mgr, user)))
		goto err;

	st = cn_kzalloc(sizeof(struct debug_controller_st), GFP_KERNEL);
	if (unlikely(!st))
		goto err;

	st->pid = pid;
	st->user = user;

	core = &mgr->core;
	ret = __util_memory_map(mgr, user, core->core_shm_host,
				core->core_shm_size, &st->core_map_uaddr);
	if (ret)
		goto free_st;

	task = &mgr->task;
	ret = __util_shm_alloc(mgr, task->task_size,
				&st->task_shm_host, &st->task_shm_dev);
	if (ret)
		goto core_unmap;

	ret = __util_memory_map(mgr, user, st->task_shm_host,
				task->task_size, &st->task_map_uaddr);
	if (ret)
		goto free_shm;

	ret = __ioctl_init_task(mgr, user, pid,
				st->task_shm_dev, task->task_size);
	if (ret)
		goto task_unmap;

	mgr->controller_num++;
	list_add_tail(&st->entry, &mgr->list);
	mutex_unlock(&mgr->lock);

	*pst = st;
	return 0;

task_unmap:
	__util_memory_unmap(mgr, user, st->task_map_uaddr,
			task->task_size);
free_shm:
	__util_shm_free(mgr, st->task_shm_host,
			st->task_shm_dev);
core_unmap:
	__util_memory_unmap(mgr, user, st->core_map_uaddr,
			core->core_shm_size);
free_st:
	cn_kfree(st);
err:
	mutex_unlock(&mgr->lock);
	cn_dev_err("debug controller create failed");
	return 1;
}

static int
__debug_controller_exit(struct debug_manager *mgr,
		__u64 user, int at_exit)
{
	struct debug_controller_st *st;
	struct debug_task_info *task = &mgr->task;
	struct debug_core_info *core = &mgr->core;
	int ret = 0;

	if (mutex_lock_killable(&mgr->lock)) {
		cn_dev_err("mutex killed");
		return 1;
	}

	st = __util_controller_get(mgr, user);
	if (!st) {
		ret = 1;
		goto out;
	}

	ret = __ioctl_exit_task(mgr, user, st->pid);
	if (unlikely(ret)) {
		cn_dev_err("[fatal error] debug manager exit task failed");
		ret = 1;
		goto out;
	}

	if (!at_exit) {
		__util_memory_unmap(mgr, user, st->task_map_uaddr, task->task_size);
		__util_memory_unmap(mgr, user, st->core_map_uaddr, core->core_shm_size);
	}

	__util_shm_free(mgr, st->task_shm_host, st->task_shm_dev);

	mgr->controller_num--;
	list_del_init(&st->entry);
	cn_kfree(st);

out:
	mutex_unlock(&mgr->lock);
	return ret;
}

static int __debug_manager_init(struct sbts_dbg_set *dbg)
{
	struct cn_core_set *core = dbg->sbts->core;
	struct debug_manager *mgr;
	__u64 generation;

	mgr = cn_kzalloc(sizeof(struct debug_manager), GFP_KERNEL);
	if (unlikely(!mgr)) {
		cn_dev_core_err(core, "debug manager init failed");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&mgr->list);
	mutex_init(&mgr->init_lock);
	mutex_init(&mgr->lock);
	mgr->dbg = dbg;

	sbts_get_board_generation(dbg->sbts, &generation);

	if (generation < SBTS_BOARD_GENERATION_3)
		goto out;

	if (unlikely(__ioctl_get_core_info(mgr, ANNOY_USER, &mgr->core)))
		goto err;

	if (unlikely(__ioctl_get_task_info(mgr, ANNOY_USER, &mgr->task)))
		goto err;

out:
	dbg->mgr = mgr;
	return 0;

err:
	cn_kfree(mgr);
	return 1;
}

static void __debug_manager_exit(struct sbts_dbg_set *dbg)
{
	struct sbts_set *sbts = dbg->sbts;
	struct cn_core_set *core = sbts->core;
	struct debug_manager *mgr = dbg->mgr;
	struct debug_controller_st *st, *temp;

	if (!mgr->initialized)
		goto free;

	cn_dev_core_err(core, "[fatal error] some controller not exit");

	list_for_each_entry_safe(st, temp, &mgr->list, entry) {
		__debug_controller_exit(mgr, st->user, 1);
		__debug_try_exit(mgr);
	}

free:
	cn_kfree(mgr);
	dbg->mgr = NULL;
}

/****************************************************************/
/* user ioctl handle */
static inline __u64
fill_desc_debug_task(__u64 version, __u64 user,
		struct sbts_kernel *kernel_param, struct comm_task_desc *task_desc,
		struct queue *queue, struct sbts_set *sbts)
{
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct task_desc_data_v1 *data;
	__u32 desc_size = sizeof(struct task_desc_data_v1);
	__u64 payload_size = 0;

	switch (version) {
	case SBTS_VERSION:
		data =        (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, desc_size);
		data->type    = DEBUG_TASK;
		data->user    = cpu_to_le64(user);
		data->dev_sid = cpu_to_le64(queue->dev_sid);
		data->priv_size = kernel_param->priv_size;

		/* fill clk id */
		sbts_task_disable_perf_info(data);

		if (unlikely(kernel_param->priv_size > TASK_DESC_PRIV_MAX_SIZE)) {
			cn_dev_core_err(core, "copy size %llu exceed maximum",
					kernel_param->priv_size);
			return payload_size;
		}

		if (copy_from_user((void *)data->priv,
				(void *)kernel_param->priv, kernel_param->priv_size)) {
			cn_dev_core_err(core, "copy payload failed!\n");
			return payload_size;
		}
		payload_size = VERSION_SIZE + desc_size + kernel_param->priv_size;
		break;

	default:
		cn_dev_core_err(core, "version not match!");
	}
	return payload_size;
}


int sbts_dbg_task(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct sbts_kernel *kernel_param = &user_param->priv_data.kernel;
	struct comm_task_desc task_desc = {0};
	__u64 payload_size = 0;
	int ret = 0;
	__u64 generation;

	sbts_get_board_generation(sbts, &generation);
	if (generation < SBTS_BOARD_GENERATION_3)
		return -EINVAL;

	payload_size = fill_desc_debug_task(kernel_param->version,
				(__u64)user, kernel_param, &task_desc, queue, sbts);
	if (unlikely(!payload_size)) {
		return -CN_SBTS_ERROR_FILL_TASK_DESC;
	}

	ret = queue_push_task(sbts->queue_manager,
			queue, &task_desc, (__u64)user, payload_size);
	if (unlikely(ret))
		cn_dev_core_err(core, "queue(%px) sid %#016llx debug task failed!",
				queue, queue->dev_sid);

	return ret;
}

static inline __u64
fill_desc_kernel_debug_v2(__u64 version, __u64 user,
		host_addr_t host_param_va, dev_addr_t dev_param_va,
		struct sbts_dbg_kernel *param, struct comm_task_desc *task_desc,
		struct queue *queue, struct sbts_set *sbts)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data;

	switch (version) {
	case SBTS_VERSION_C30_PARAM_SIZE:
		task_desc->version = version;

		/* get task desc data */
		data               = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type         = INVOKE_KERNEL_DEBUG;
		data->user         = cpu_to_le64(user);
		data->dev_sid      = cpu_to_le64(queue->dev_sid);
		data->has_kprintf  = cpu_to_le16(param->params & 1UL);
		data->priv_size    = param->priv_size;
		/* fill clk id */
		sbts_task_disable_perf_info(data);

		if (unlikely(param->priv_size > TASK_DESC_PRIV_MAX_SIZE)) {
			cn_dev_core_err(core, "copy size %llu exceed maximum", param->priv_size);
			return payload_size;
		}

		/* copy private data */
		if (copy_from_user((void *)data->priv, (void *)param->priv,
					param->priv_size)) {
			cn_dev_core_err(core, "copy payload failed!");
			return payload_size;
		}

		/* continue to fill task desc */
		data->param_data = cpu_to_le64(dev_param_va);
		/* this parameter is unique taskid */
		data->dev_shm_addr = cpu_to_le64(param->ack_buffer);

		/* copy kernel param from user */
		if (cn_bus_copy_from_usr_toio((u64)host_param_va, (u64)(param->params & (~1UL)),
				param->param_size, core->bus_set)) {
			cn_dev_core_err(core, "copy kernel parameters from user failed!");
			return payload_size;
		}

		/* calculate payload size: version + task + data + priv_size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) + param->priv_size;
		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

int
sbts_kernel_debug_v2(struct sbts_set *sbts,
		struct queue *queue,
		union sbts_task_priv_data *priv_data, cn_user user)
{
	struct cn_core_set *core = sbts->core;
	int ret = 0;
	__u64 payload_size = 0;
	host_addr_t host_param_va = 0;
	dev_addr_t dev_param_va = 0;
	struct comm_task_desc task_desc;
	struct sbts_dbg_kernel *dbg_kernel = &priv_data->dbg_kernel;

	/* alloc param shared memory */
	ret = alloc_param_buf(sbts->queue_manager, dbg_kernel->param_size,
			&host_param_va, &dev_param_va,
			SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "alloc param buffer failed!");
		return -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
	}

	payload_size = fill_desc_kernel_debug_v2(dbg_kernel->version, (__u64)user,
			host_param_va, dev_param_va, dbg_kernel,
			&task_desc, queue, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		free_param_buf(core, dev_param_va);
		return -CN_SBTS_ERROR_FILL_TASK_DESC;
	}

	/* push task to device */
	print_time_detail("push task >>");
	ret = queue_push_task(sbts->queue_manager, queue, &task_desc,
				(__u64)user, payload_size);
	print_time_detail("push task <<");

	if (unlikely(ret)) {
		cn_dev_core_err(core, "queue(%px) sid %#016llx", queue, queue->dev_sid);
		cn_dev_core_err(core, "invoke kernel failed!");
		free_param_buf(core, dev_param_va);
	}

	return ret;
}

static int
__debug_ctrl_get(struct sbts_set *sbts_set, void *arg,
		struct sbts_debug_ctrl *param, cn_user user)
{
	struct cn_core_set *cn_core = sbts_set->core;
	struct debug_manager *mgr = __util_get_debug_mgr(sbts_set);
	struct debug_core_info *core = &mgr->core;
	struct debug_task_info *task = &mgr->task;
	struct debug_controller_st *st;
	int ret = 0;

	if (__debug_try_init(mgr)) {
		cn_dev_core_err(cn_core, "init debug manager failed");
		return -EFAULT;
	}

	if (__debug_controller_init(mgr, param->pid, (__u64)user, &st)) {
		cn_dev_core_err(cn_core, "debug manager create controller failed");
		ret = -EFAULT;
		goto exit;
	}

	param->get.version        = 0;

	param->get.core_ver       = core->core_ver;
	param->get.core_num       = core->core_num;
	param->get.each_size      = core->each_size;
	param->get.core_map_addr  = st->core_map_uaddr;

	param->get.task_ver       = task->task_ver;
	param->get.task_size      = task->task_size;
	param->get.task_map_addr  = st->task_map_uaddr;

	if (copy_to_user((void *)arg, (void *)param,
					sizeof(struct sbts_debug_ctrl))) {
		cn_dev_core_err(cn_core, "copy param to user failed");
		ret = -EFAULT;
		goto controller_exit;
	}

	cn_dev_core_debug(cn_core, "get debug manager ret %d", ret);
	return ret;

controller_exit:
	__debug_controller_exit(mgr, (__u64)user, 0);
exit:
	__debug_try_exit(mgr);
	return ret;
}

static int
__debug_ctrl_put(struct sbts_set *sbts_set, void *arg,
		struct sbts_debug_ctrl *param, cn_user user)
{
	struct debug_manager *mgr = __util_get_debug_mgr(sbts_set);

	if (!__debug_controller_exit(mgr, (__u64)user, 0))
		__debug_try_exit(mgr);

	return 0;
}

static int
__debug_ctrl_register(struct sbts_set *sbts, void *arg,
			struct sbts_debug_ctrl *param, cn_user user)
{
	struct cn_core_set *core = sbts->core;
	struct debug_manager *mgr = __util_get_debug_mgr(sbts);
	int ret;

	if (!mgr->initialized)
		return 1;

	ret = __ioctl_register_user(mgr, (__u64)user, param->pid);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "debug register user 0x%llx pid %d failed",
				(__u64)user, param->pid);
	}

	return ret;
}

static int
__debug_ctrl_unregister(struct sbts_set *sbts, void *arg,
			struct sbts_debug_ctrl *param, cn_user user)
{
	struct cn_core_set *core = sbts->core;
	struct debug_manager *mgr = __util_get_debug_mgr(sbts);
	int ret;

	if (!mgr->initialized)
		return 1;

	ret = __ioctl_unreigster_user(mgr, (__u64)user, param->pid);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "debug unregister user 0x%llx pid %d failed",
				(__u64)user, param->pid);
	}
	return ret;
}

static int
__debug_ctrl_update(struct sbts_set *sbts, void *arg,
			struct sbts_debug_ctrl *param, cn_user user)
{
	struct cn_core_set *core = sbts->core;
	struct debug_manager *mgr = __util_get_debug_mgr(sbts);
	int ret;

	if (!mgr->initialized)
		return 1;

	ret = __ioctl_update_head(mgr, (__u64)user,
					param->pid, param->update.head);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "debug update head user 0x%llx pid %d head %d failed",
				(__u64)user, param->pid, param->update.head);
	}

	return ret;
}

typedef int (*DEBUG_CTRL_FUNC)(struct sbts_set *sbts, void *arg,
			struct sbts_debug_ctrl *param, cn_user user);
static DEBUG_CTRL_FUNC ctrl_func[DEBUG_CTRL_CMD_NUM] = {
	__debug_ctrl_get,
	__debug_ctrl_put,
	__debug_ctrl_register,
	__debug_ctrl_unregister,
	__debug_ctrl_update,
};

int cn_debug_ctrl(struct sbts_set *sbts_set,
			void *arg, cn_user user)
{
	struct cn_core_set *core = sbts_set->core;
	struct sbts_debug_ctrl param;
	__u64 generation;

	sbts_get_board_generation(sbts_set, &generation);
	if (generation < SBTS_BOARD_GENERATION_3)
		return -EINVAL;

	if (copy_from_user((void *)&param, (void *)arg,
				sizeof(struct sbts_debug_ctrl))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	if (param.type >= DEBUG_CTRL_CMD_NUM)
		return -EINVAL;

	return ctrl_func[param.type](sbts_set, arg, &param, user);
}

void sbts_dbg_wait_work(struct cn_core_set *core,
			void *priv_data,
			void *rx_msg, int rx_size)
{
	struct comm_dbg_desc *rx_desc = (struct comm_dbg_desc *)rx_msg;
	struct sbts_dbg_set *dbg_set = (struct sbts_dbg_set *)priv_data;
	const struct sbts_dbg_ops *ops;

	if (rx_desc->type >= DBG_TASK_NUM) {
		cn_dev_core_err(core, "Unknown msg type %llu for dbg",
					rx_desc->type);
		return;
	}

	ops = dbg_set->mod[rx_desc->type].ops;
	if (!ops || !ops->msg_cbk) {
		cn_dev_core_err(core,
			"dbg type %llu ops or cbk is null",
					rx_desc->type);
		return;
	}
	ops->msg_cbk(dbg_set->sbts, rx_desc);
}


int sbts_dbg_register_cbk(struct sbts_set *sbts_set,
		enum dbg_task_type type,
		const struct sbts_dbg_ops *ops)
{
	struct sbts_dbg_set *dbg_set = NULL;
	struct cn_core_set *core = NULL;

	if (!sbts_set || !sbts_set->dbg_set) {
		cn_dev_core_err(core, "sbts mod needs to init first");
		return -EINVAL;
	}

	dbg_set = sbts_set->dbg_set;
	core = sbts_set->core;

	if (type >= DBG_TASK_NUM) {
		cn_dev_core_err(core,
				"register dbg info with invalid type %d", type);
		return -EINVAL;
	}

	if (__sync_bool_compare_and_swap(&dbg_set->mod[type].inited,
			0, 1)) {
		dbg_set->mod[type].ops = ops;
	} else {
		cn_dev_core_err(core, "registered ops for debug type %d already", type);
		return -EEXIST;
	}

	return 0;
}


int sbts_dbg_init(struct sbts_set *sbts_set)
{
	int ret = 0;
	struct sbts_dbg_set *dbg_set = NULL;
	struct cn_core_set *core = sbts_set->core;

	dbg_set = cn_kzalloc(sizeof(struct sbts_dbg_set), GFP_KERNEL);
	if (!dbg_set) {
		cn_dev_core_err(core, "malloc dbg set mem failed");
		return -ENOMEM;
	}
	dbg_set->core = core;
	dbg_set->sbts = sbts_set;
	dbg_set->sched_mgr = sbts_set->sched_manager;

	dbg_set->sbts = sbts_set;

	ret = __debug_manager_init(dbg_set);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "init debug manager failed");
		goto free_dbg;
	}

	/* create worker */
	dbg_set->worker = commu_wait_work_run(core, "sbts_dbg",
			sbts_set->sched_manager->dbg_ep,
			dbg_set, sbts_dbg_wait_work);
	if (!dbg_set->worker) {
		cn_dev_core_err(core, "create thread failed");
		ret = -EINVAL;
		goto worker_err;
	}

	sbts_set->dbg_set = dbg_set;

	return 0;

worker_err:
	__debug_manager_exit(dbg_set);
free_dbg:
	cn_kfree(dbg_set);
	return ret;
}

int dbg_do_exit(u64 user, struct sbts_dbg_set *dbg_set)
{
	struct debug_manager *mgr = dbg_set->mgr;

	if (!mgr->initialized)
		return 0;

	if (!__debug_controller_exit(mgr, (__u64)user, 1))
		__debug_try_exit(mgr);

	return 0;
}

void sbts_dbg_exit(struct sbts_dbg_set *dbg_set)
{
	struct sbts_set *sbts_set = NULL;

	if (unlikely(!dbg_set)) {
		cn_dev_err("dbg set is null!");
		return;
	}
	sbts_set = dbg_set->sbts;

	__debug_manager_exit(dbg_set);

	commu_wait_work_stop(sbts_set->core, dbg_set->worker);

	cn_kfree(dbg_set);
	sbts_set->dbg_set = NULL;
}
