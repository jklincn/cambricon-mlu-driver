/*
 * sbts/sbts_d2d.c
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

#include <linux/spinlock.h>
#include <linux/slab.h>

#include "cndrv_ioctl.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_lpm.h"
#include "sbts.h"
#include "queue.h"
#include "dma_async.h"
#include "cndrv_perf_usr.h"

static u64 g_sbts_d2d_seq = 1;

static inline __u64
fill_desc_invoke_d2d_kernel(enum func_kernel_type type,
		__u64 version, __u64 user,
		struct sbts_queue_invoke_task *user_param,
		__u64 param_num, void *param, u64 cp_size,
		host_addr_t host_param_va, dev_addr_t dev_param_va,
		struct comm_task_desc *task_desc,
		struct queue *queue, struct sbts_set *sbts)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	__u32 offset = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;
	struct td_launch_func_kernel *priv = NULL;
	u32 priv_size = sizeof(struct td_launch_func_kernel);

	sbts_td_priv_size_check(priv_size);

	switch (version) {
	case SBTS_VERSION:
		/* SBTS_VERSION map to SBTS_VERSION_FUNC_TASK */
		task_desc->version = SBTS_VERSION_FUNC_TASK;

		/* get task desc data */
		data                 = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type           = INVOKE_FUNC_KERNEL;
		data->user           = cpu_to_le64(user);
		data->dev_sid        = cpu_to_le64(queue->dev_sid);
		/* continue to fill task desc */
		data->param_data     = cpu_to_le64(dev_param_va);

		/* fill perf info */
		if (user_param) {
			offset = sbts_task_get_perf_info(sbts, queue, DMA_TS_TASK,
					user_param, data, &priv_size);
		} else {
			sbts_task_disable_perf_info(data);
		}

		data->priv_size      = priv_size;

		/* copy kernel param from kernel space */
		memcpy_toio((void *)host_param_va, param,
				sizeof(__le64) * param_num);

#ifdef CONFIG_CNDRV_EDGE
		cn_edge_cache_flush((void *)host_param_va, sizeof(__le64) * param_num);
#endif

		priv = (struct td_launch_func_kernel *)data->priv;
		priv->kernel_type = cpu_to_le64(type);
		priv->size        = cpu_to_le64(cp_size);

		priv->src         = ((__le64 *)param)[0];
		priv->dst         = ((__le64 *)param)[1];

		/* calculate payload size: version + task + data + priv->size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) +
				priv_size + offset;
		break;

	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}

	return payload_size;
}

static int
__sbts_invoke_d2d_kernel(struct sbts_set *sbts, enum func_kernel_type type,
		u64 version, struct queue *queue, cn_user user,
		struct sbts_queue_invoke_task *user_param,
		u32 param_num, __le64 *param_array,
		u64 cp_size)
{
	int ret = 0;
	u64 payload_size = 0;
	host_addr_t host_param_va = 0;
	dev_addr_t dev_param_va = 0;
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct comm_task_desc task_desc;
	u64 param_asize = 0;

	param_asize = sizeof(u64) * param_num;
	/* alloc param shared memory */
	ret = alloc_param_buf(sbts->queue_manager, param_asize,
			&host_param_va, &dev_param_va,
			SBTS_ALLOC_PARAM_WAIT | SBTS_ALLOC_PARAM_MAX);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "alloc param buffer failed!");
		return -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
	}

	payload_size = fill_desc_invoke_d2d_kernel(type, version,
			(u64)user, user_param, (u64)param_num,
			(void *)param_array, cp_size, host_param_va, dev_param_va,
			&task_desc, queue, sbts);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill task descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto err;
	}

	print_time_detail("push task >>");
	ret = queue_push_task(sbts->queue_manager, queue, &task_desc,
				(u64)user, payload_size);
	print_time_detail("push task <<");
	if (unlikely(ret)) {
		cn_dev_core_err(core, "queue(%px) sid %#016llx push failed",
				queue, queue->dev_sid);
		goto err;
	}

	return ret;

err:
	free_param_buf(core, dev_param_va);
	return ret;
}

#define SBTS_INVOKE_D2D_SYNC_PARAM_NUM   3
#define SBTS_INVOKE_D2D_ASYNC_PARAM_NUM  4
/* function for mm call
 * the input addr is already check by mm
 * */
int cn_sbts_invoke_d2d_sync(
		struct cn_core_set *core,
		u64 src_addr, u64 dst_addr, u64 size)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct queue *queue;
	u32 que_index = -1;
	u64 queue_dsid = 0;
	__le64 param_arr[SBTS_INVOKE_D2D_SYNC_PARAM_NUM];
	int ret = 0;

	if (!sbts)
		return -ENODEV;

	ret = cn_lpm_get_with_cond(core, LPM_MODULE_TYPE_IPU,
						(!cn_sbts_lpm_mode_check(core, CN_SBTS_LP_TASK_RUNTIME)));
	if (unlikely(ret)) {
		cn_dev_core_err(core, "d2d sync lpm get failed");
		goto out;
	}

	ret = cn_queue_get_for_func(sbts, &que_index,
			&queue_dsid);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "get queue for d2d failed!");
		goto lpm_put;
	}

	queue = queue_get(sbts->queue_manager, queue_dsid, (cn_user)ANNOY_USER, 1);
	if (!queue) {
		cn_dev_core_err(core, "queue_dsid(%#llx) is invalid", queue_dsid);
		 ret = -CN_QUEUE_ERROR_QUEUE_INVALID;
		 goto reset_queue;
	}

	param_arr[0] = cpu_to_le64(src_addr);
	param_arr[1] = cpu_to_le64(dst_addr);
	param_arr[2] = cpu_to_le64(size);
	ret = __sbts_invoke_d2d_kernel(sbts,
			D2D_KERNEL_NORMAL, SBTS_VERSION,
			queue, (cn_user)ANNOY_USER, NULL,
			SBTS_INVOKE_D2D_SYNC_PARAM_NUM,
			param_arr, size);
	if (ret) {
		cn_dev_core_err(core, "invoke d2d kernel failed");
		goto reset_queue;
	}

	ret = cn_queue_sync_for_func(sbts, que_index);
	if (ret) {
		cn_dev_core_err(core, "d2d sync failed");
		goto reset_queue;
	}

	goto queue_put;

reset_queue:
	cn_queue_destroy_for_func(sbts, que_index);
	cn_queue_create_for_func(sbts, que_index);
queue_put:
	queue_put(sbts->queue_manager, queue);
	cn_queue_put_for_func(sbts, que_index);
lpm_put:
	if (unlikely(cn_lpm_put_with_cond(core, LPM_MODULE_TYPE_IPU,
						(!cn_sbts_lpm_mode_check(core, CN_SBTS_LP_TASK_RUNTIME))))) {
		cn_dev_core_err(core, "FATAL ERROR, lpm put failed");
	}
out:
	return ret;
}

static int __d2d_async_task_compare(struct sbts_d2d_task *r,
		struct sbts_d2d_task *l)
{
	u64 rkey = r->ticket;
	u64 lkey = l->ticket;

	if (rkey < lkey) {
		return -1;
	}

	if (rkey > lkey) {
		return 1;
	}

	return 0;
}


/* return the alloced task seq id which will need in free */
static u64 __alloc_d2d_info_save(struct sbts_set *sbts,
		struct sbts_dma_async *dma_async_param,
		struct sbts_dma_priv *dma_priv)
{
	struct cn_core_set *core = (struct cn_core_set *)sbts->core;
	struct dma_async_manager *dma_async_manager =
			(struct dma_async_manager *)sbts->dma_async_manager;
	struct sbts_d2d_async_info *d2d_info = &dma_async_manager->d2d_info;
	struct sbts_d2d_task *task = NULL, *tmp = NULL;
	u64 ticket;

	task = kmem_cache_zalloc(d2d_info->task_mem, GFP_KERNEL);
	if (!task) {
		cn_dev_core_err(core, "alloc task mem failed");
		return 0;
	}

	task->src_addr = dma_async_param->memcpy.src_addr;
	task->dst_addr = dma_async_param->memcpy.dst_addr;
	task->src_pminfo = dma_priv->memcpy.src_pminfo;
	task->dst_pminfo = dma_priv->memcpy.dst_pminfo;
	task->size = dma_async_param->memcpy.size;

	mutex_lock(&d2d_info->mutex);
	ticket = __sync_add_and_fetch(&g_sbts_d2d_seq, 1);
	task->ticket = ticket;
	tmp = sbts_set_insert(&d2d_info->container, task,
			__d2d_async_task_compare, iter);
	mutex_unlock(&d2d_info->mutex);
	if (!tmp) {
		cn_dev_core_err(core, "add task to set failed");
		kmem_cache_free(d2d_info->task_mem, task);
		return 0;
	}

	return ticket;
}

static inline void
__free_d2d_info(struct cn_core_set *core,
		struct sbts_d2d_task *task)
{
	cn_async_address_kref_put(task->src_pminfo, task->src_addr, task->size);
	cn_async_address_kref_put(task->dst_pminfo, task->dst_addr, task->size);
}

static inline struct sbts_d2d_task *
__find_and_erase_d2d_task(struct sbts_set *sbts, u64 ticket)
{
	struct dma_async_manager *dma_async_manager =
			(struct dma_async_manager *)sbts->dma_async_manager;
	struct sbts_d2d_async_info *d2d_info = &dma_async_manager->d2d_info;
	struct sbts_d2d_task obj = {.ticket = ticket};
	struct sbts_d2d_task *task = NULL;

	mutex_lock(&d2d_info->mutex);
	task = sbts_set_find(&d2d_info->container, &obj,
			__d2d_async_task_compare, iter);
	if (!task) {
		mutex_unlock(&d2d_info->mutex);
		return NULL;
	}
	sbts_set_erase(&d2d_info->container, task, iter);
	mutex_unlock(&d2d_info->mutex);

	return task;
}

void sbts_d2d_async_free(struct cn_core_set *core, u64 ticket)
{
	struct sbts_set *sbts = core->sbts_set;
	struct dma_async_manager *dma_async_manager =
			(struct dma_async_manager *)sbts->dma_async_manager;
	struct sbts_d2d_async_info *d2d_info = &dma_async_manager->d2d_info;
	struct sbts_d2d_task *task = NULL;

	task = __find_and_erase_d2d_task(sbts, ticket);
	if (!task) {
		cn_dev_core_err(core, "cant find task by ticket %llu", ticket);
		return;
	}

	__free_d2d_info(core, task);
	kmem_cache_free(d2d_info->task_mem, task);
}

static inline void __push_fail_del_d2d_task(
		struct cn_core_set *core, u64 ticket)
{
	struct sbts_set *sbts = core->sbts_set;
	struct dma_async_manager *dma_async_manager =
			(struct dma_async_manager *)sbts->dma_async_manager;
	struct sbts_d2d_async_info *d2d_info = &dma_async_manager->d2d_info;
	struct sbts_d2d_task *task = NULL;

	task = __find_and_erase_d2d_task(sbts, ticket);
	if (!task) {
		cn_dev_core_err(core, "cant find task by ticket %llu", ticket);
		return;
	}

	kmem_cache_free(d2d_info->task_mem, task);
}

int sbts_d2d_async_info_init(
		struct sbts_d2d_async_info *info,
		struct cn_core_set *core)
{
	char kmem_name[64];

	sprintf(kmem_name, "cn_d2d_task%d", core->idx);

	info->task_mem = kmem_cache_create(
			kmem_name,
			sizeof(struct sbts_d2d_task),
			64,
			SLAB_HWCACHE_ALIGN, NULL);
	if (!info->task_mem) {
		cn_dev_core_err(core, "alloc mem cache failed");
		return -ENOMEM;
	}

	sbts_set_container_init(&info->container);
	mutex_init(&info->mutex);

	return 0;
}

void sbts_d2d_async_info_exit(
		struct sbts_d2d_async_info *info,
		struct cn_core_set *core)
{
	struct sbts_d2d_task *task, *tmp;
	u32 i = 0;

	sbts_set_for_each_entry_safe(task, tmp, &info->container, iter) {
		sbts_set_erase(&info->container, task, iter);
		__free_d2d_info(core, task);
		kmem_cache_free(info->task_mem, task);
		i++;
	}
	cn_dev_core_info(core, "free %u d2d task", i);

	kmem_cache_destroy(info->task_mem);
}

int sbts_d2d_async_invoke(struct sbts_set *sbts,
		struct queue *queue, u64 user,
		struct sbts_queue_invoke_task *user_param,
		struct sbts_dma_async *dma_async_param,
		struct sbts_dma_priv *dma_priv)
{
	struct cn_core_set *core;
	__le64 param_arr[SBTS_INVOKE_D2D_ASYNC_PARAM_NUM];
	u64 task_ticket;
	int ret = 0;

	if (!sbts)
		return -ENODEV;

	core = (struct cn_core_set *)sbts->core;

	task_ticket = __alloc_d2d_info_save(sbts,
			dma_async_param, dma_priv);
	if (!task_ticket)
		return -ENOMEM;

	/***
	 * Just show warning without handle about result.
	 */
	d2d_1d_overlap_check(core, dma_async_param->memcpy.src_addr,
				dma_async_param->memcpy.dst_addr,
				dma_async_param->memcpy.size);

	param_arr[0] = cpu_to_le64(dma_async_param->memcpy.src_addr);
	param_arr[1] = cpu_to_le64(dma_async_param->memcpy.dst_addr);
	param_arr[2] = cpu_to_le64(dma_async_param->memcpy.size);
	param_arr[3] = cpu_to_le64(task_ticket);
	ret = __sbts_invoke_d2d_kernel(sbts,
			D2D_KERNEL_ASYNC, dma_async_param->version,
			queue, (cn_user)user, user_param,
			SBTS_INVOKE_D2D_ASYNC_PARAM_NUM,
			param_arr, dma_async_param->memcpy.size);
	if (ret) {
		cn_dev_core_err(core, "invoke d2d kernel failed");
		__push_fail_del_d2d_task(core, task_ticket);
	}

	return ret;
}
