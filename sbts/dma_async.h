/*
 * sbts/dma_async.h
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

#ifndef __SBTS_DMA_ASYNC_H
#define __SBTS_DMA_ASYNC_H

#include <linux/types.h>

#include <linux/spinlock.h>
#include <linux/slab.h>

#include "sbts_set.h"

#define SBTS_VERSION_DMA_PAGEABLE  (2U)

struct cn_core_set;
struct sbts_set;
struct sched_manager;
struct task_struct;

struct cd_dma_free_data {
	__le64 tags;
	__le64 index;
	__le64 type;
};

#define DMA_MSG_BUF_MAX_SIZE (30)
/* ctrl_desc_data_v1->priv  [sbts.h]*/
struct cd_dma_free_msg {
	__le64 buf_size;
	__le64 buf[DMA_MSG_BUF_MAX_SIZE];
};

struct sbts_d2d_task {
	u64 src_addr;
	u64 dst_addr;
	u64 src_pminfo;
	u64 dst_pminfo;
	u64 size;
	u64 ticket;
	struct sbts_set_iter_st iter;
};

struct sbts_d2d_async_info {
	struct kmem_cache *task_mem;
	struct sbts_set_container_st container;
	struct mutex mutex;
};

struct dma_async_manager {
	struct sched_manager *sched_mgr;
	struct cn_core_set *core;
	struct sbts_set *sbts;

	void *worker;

	int msg_send_en;
	volatile int exit_flag;

	struct sbts_d2d_async_info d2d_info;
};

int dma_async_manager_init(
		struct dma_async_manager **ppdma_mgr,
		struct cn_core_set *core);

void dma_async_manager_exit(struct dma_async_manager *dma_async_manager);

void sbts_d2d_async_free(struct cn_core_set *core, u64 ticket);

int sbts_d2d_async_info_init(
		struct sbts_d2d_async_info *info,
		struct cn_core_set *core);

void sbts_d2d_async_info_exit(
		struct sbts_d2d_async_info *info,
		struct cn_core_set *core);

int sbts_d2d_async_invoke(struct sbts_set *sbts,
		struct queue *queue, u64 user,
		struct sbts_queue_invoke_task *user_param,
		struct sbts_dma_async *dma_async_param,
		struct sbts_dma_priv *dma_priv);

#endif /* __SBTS_DMA_ASYNC_H */
