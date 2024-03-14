/*
 * gdma/gdma_sched.c
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

#include <linux/version.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <asm/atomic.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/wait.h>
#if (KERNEL_VERSION(4, 11, 0) > LINUX_VERSION_CODE)
#include <linux/signal.h>
#else
#include <linux/sched/signal.h>
#endif

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_mm.h"
#include "gdma_sched.h"
#include "gdma_drv.h"
#include "gdma_common.h"
#include "gdma_hal.h"
#include "gdma_debug.h"
#include "gdma_common_api.h"

#define GDMA_TMP_BUFFER_SIZE (64)

static int gdma_memset_d8(struct cn_gdma_task *task)
{
	unsigned char tmp_buffer[GDMA_TMP_BUFFER_SIZE] = {0};
	int i;
	int total_count;
	unsigned long host_kva = 0;

	cn_dev_gdma_debug(task->gdma_set, "task %d memset d8 begin", task->idx);

	memset((void *)tmp_buffer,
			task->transfer.memset_value & 0xff,
			sizeof(tmp_buffer));

	host_kva = task->memset_shm.host_kva;
	total_count = task->memset_shm.size / sizeof(tmp_buffer);
	for (i = 0; i < total_count; i++) {
		memcpy_toio((void *)host_kva,
					(void *)tmp_buffer,
					sizeof(tmp_buffer));
		host_kva += sizeof(tmp_buffer);
	}

	cn_bus_mb(task->gdma_set->core->bus_set);

	task->memset_value = task->transfer.memset_value & 0xff;
	task->remain_src = task->memset_shm.dev_va;

	cn_dev_gdma_debug(task->gdma_set, "task %d memset d8 end", task->idx);

	return GDMA_SUCCESS;
}

static int gdma_memset_d16(struct cn_gdma_task *task)
{
	unsigned short tmp_buffer[GDMA_TMP_BUFFER_SIZE] = {0};
	int i;
	int total_count;
	unsigned long host_kva = 0;

	cn_dev_gdma_debug(task->gdma_set, "task %d memset d16 begin", task->idx);

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	for (i = 0; i < GDMA_TMP_BUFFER_SIZE; i++) {
		tmp_buffer[i] = task->transfer.memset_value & 0xffff;
	}
#else
	memset16((void *)tmp_buffer,
			task->transfer.memset_value & 0xffff,
			GDMA_TMP_BUFFER_SIZE);
#endif

	host_kva = task->memset_shm.host_kva;
	total_count = task->memset_shm.size / sizeof(tmp_buffer);
	for (i = 0; i < total_count; i++) {
		memcpy_toio((void *)host_kva,
						(void *)tmp_buffer,
						sizeof(tmp_buffer));
		host_kva += sizeof(tmp_buffer);
	}

	cn_bus_mb(task->gdma_set->core->bus_set);

	task->memset_value = task->transfer.memset_value & 0xffff;
	task->remain_src = task->memset_shm.dev_va;

	cn_dev_gdma_debug(task->gdma_set, "task %d memset d16 end", task->idx);

	return GDMA_SUCCESS;
}

static int gdma_memset_d32(struct cn_gdma_task *task)
{
	u32 tmp_buffer[GDMA_TMP_BUFFER_SIZE] = {0};
	int i;
	int total_count;
	unsigned long host_kva = 0;

	cn_dev_gdma_debug(task->gdma_set, "task %d memset d32 begin", task->idx);

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	for (i = 0; i < GDMA_TMP_BUFFER_SIZE; i++) {
		tmp_buffer[i] = task->transfer.memset_value & 0xffffffff;
	}
#else
	memset32((void *)tmp_buffer,
			task->transfer.memset_value & 0xffffffff,
			GDMA_TMP_BUFFER_SIZE);
#endif

	host_kva = task->memset_shm.host_kva;
	total_count = task->memset_shm.size / sizeof(tmp_buffer);
	for (i = 0; i < total_count; i++) {
		memcpy_toio((void *)host_kva,
						(void *)tmp_buffer,
						sizeof(tmp_buffer));
		host_kva += sizeof(tmp_buffer);
	}

	cn_bus_mb(task->gdma_set->core->bus_set);

	task->memset_value = task->transfer.memset_value & 0xffffffff;
	task->remain_src = task->memset_shm.dev_va;

	cn_dev_gdma_debug(task->gdma_set, "task %d memset d32 end", task->idx);

	return GDMA_SUCCESS;
}

static int gdma_memset_d64(struct cn_gdma_task *task)
{
	u64 tmp_buffer[GDMA_TMP_BUFFER_SIZE] = {0};
	int i;
	int total_count;
	unsigned long host_kva = 0;

	cn_dev_gdma_debug(task->gdma_set, "task %d memset d64 begin", task->idx);

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	for (i = 0; i < GDMA_TMP_BUFFER_SIZE; i++) {
		tmp_buffer[i] = task->transfer.memset_value;
	}
#else
	memset64((void *)tmp_buffer,
			task->transfer.memset_value,
			GDMA_TMP_BUFFER_SIZE);
#endif

	host_kva = task->memset_shm.host_kva;
	total_count = task->memset_shm.size / sizeof(tmp_buffer);
	for (i = 0; i < total_count; i++) {
		memcpy_toio((void *)host_kva,
						(void *)tmp_buffer,
						sizeof(tmp_buffer));
		host_kva += sizeof(tmp_buffer);
	}

	cn_bus_mb(task->gdma_set->core->bus_set);

	task->memset_value = task->transfer.memset_value;
	task->remain_src = task->memset_shm.dev_va;

	cn_dev_gdma_debug(task->gdma_set, "task %d memset d64 end", task->idx);

	return GDMA_SUCCESS;
}

static int gdma_init_memset_buffer(struct cn_gdma_task *task)
{
	int ret = 0;

	switch (task->transfer.type) {
	case GDMA_MEMSET_D8:
		ret = gdma_memset_d8(task);
		break;
	case GDMA_MEMSET_D16:
		ret = gdma_memset_d16(task);
		break;
	case GDMA_MEMSET_D32:
		ret = gdma_memset_d32(task);
		break;
	case GDMA_MEMSET_D64:
		ret = gdma_memset_d64(task);
		break;
	default:
		cn_dev_gdma_err(task->gdma_set, "task %d invalid memset type %d",
						task->idx, task->transfer.type);
		return -EINVAL;
	}

#ifdef CONFIG_CNDRV_EDGE
	cn_edge_cache_flush((void *)task->memset_shm.host_kva, task->memset_shm.size);
#endif
	return ret;
}

struct cn_gdma_virt_chan *gdma_get_priv_idle_vchan(struct cn_gdma_set *gdma_set,
		struct cn_gdma_task *task)
{
	int i;
	struct cn_gdma_virt_chan *vchan;

	for (i = 0; i < task->priv_vchan_num; i++) {
		vchan = task->priv_vchan[i];
		if (__sync_bool_compare_and_swap(&vchan->status,
					GDMA_CHANNEL_IDLE,
					GDMA_CHANNEL_ASSIGNED)) {
			return vchan;
		}
	}

	return NULL;
}

struct cn_gdma_virt_chan *gdma_get_shared_idle_vchan(struct cn_gdma_set *gdma_set,
		struct cn_gdma_task *task)
{
	int i;
	int index;
	struct cn_gdma_virt_chan *vchan;

	for (i = 0; i < gdma_set->vchan_num; i++) {
		index = (i + gdma_set->vchan_search_start) % gdma_set->vchan_num;
		vchan = gdma_set->vchan_pool[index];
		if (__sync_bool_compare_and_swap(&vchan->status,
						GDMA_CHANNEL_IDLE,
						GDMA_CHANNEL_ASSIGNED)) {
			__sync_fetch_and_add(&gdma_set->vchan_search_start, 1);
			return vchan;
		}
	}

	return NULL;
}

static struct cn_gdma_virt_chan *cn_gdma_get_idle_virt_chan(struct cn_gdma_set *gdma_set,
		struct cn_gdma_task *task)
{
	struct cn_gdma_virt_chan *vchan = NULL;

	vchan = gdma_get_priv_idle_vchan(gdma_set, task);
	if (vchan)
		return vchan;

	vchan = gdma_get_shared_idle_vchan(gdma_set, task);
	if (vchan)
		return vchan;

	usleep_range(10, 20);
	cn_dev_gdma_debug(gdma_set, "No enough vchan return NULL");

	return NULL;
}

int cn_gdma_put_idle_virt_chan(struct cn_gdma_virt_chan *vchan)
{
	__sync_lock_test_and_set(&vchan->status, GDMA_CHANNEL_IDLE);

	return GDMA_SUCCESS;
}

static int cn_gdma_setup_virt_chan_transfer(struct cn_gdma_virt_chan *vchan,
		struct cn_gdma_task *task)
{
	int ret = -EINVAL;
	struct cn_gdma_package *pkg = &vchan->pkg;

	cn_dev_gdma_debug(vchan->gdma_set, "vchan %d setup task %d package",
			vchan->idx, task->idx);

	vchan->dma_tx_mode = task->dma_tx_mode;
	vchan->task = task;
	switch (pkg->type) {
	case GDMA_MEMCPY:
		ret = cn_gdma_fill_memcpy_desc(vchan->gdma_set, vchan, pkg);
		break;
	case GDMA_MEMSET_D8:
	case GDMA_MEMSET_D16:
	case GDMA_MEMSET_D32:
	case GDMA_MEMSET_D64:
		ret = cn_gdma_fill_memset_desc(vchan->gdma_set, vchan, pkg);
		break;
	case GDMA_MEMCPY_2D:
		ret = cn_gdma_fill_memcpy_2d_desc(vchan->gdma_set, vchan, pkg);
		break;
	case GDMA_MEMCPY_3D:
		ret = cn_gdma_fill_memcpy_3d_desc(vchan->gdma_set, vchan, pkg);
		break;
	default:
		cn_dev_gdma_err(vchan->gdma_set, "task %d package type %d invalid",
						task->idx,
						pkg->type);
		return -EINVAL;
	}

#ifdef CONFIG_CNDRV_EDGE
	cn_edge_cache_flush((void *)vchan->desc_shm.host_kva, vchan->desc_shm.size);
#endif

	return ret;
}

static inline int gdma_task_tx_max_load(struct cn_gdma_task *task)
{
	if (task->transfer.len <= GDMA_LOW_TRANSFER_SIZE) {
		return GDMA_LOW_TX_LOAD;
	} else if (task->transfer.len <= GDMA_MEDIUM_TRANSFER_SIZE) {
		return GDMA_MEDIUM_TX_LOAD;
	} else {
		return GDMA_HIGH_TX_LOAD;
	}
}

static int gdma_task_build_memcpy_package(struct cn_gdma_task *task,
		struct cn_gdma_package *pkg)
{
	u32 len;

	pkg->type = task->transfer.type;
	len = min_t(u64, task->remain_size, task->tx_max_load);
	pkg->src = task->remain_src;
	pkg->dst = task->remain_dst;
	pkg->len = len;
	task->remain_src += len;
	task->remain_dst += len;
	task->remain_size -= len;

	cn_dev_gdma_debug(task->gdma_set,
			"package src:%#llx dst:%#llx len:%#llx",
			pkg->src, pkg->dst, pkg->len);

	return GDMA_SUCCESS;
}

static int gdma_task_build_memset_package(struct cn_gdma_task *task,
		struct cn_gdma_package *pkg)
{
	u32 len;

	pkg->type = task->transfer.type;
	len = min_t(u64, task->remain_size, task->tx_max_load);
	pkg->src = task->remain_src;
	pkg->dst = task->remain_dst;
	pkg->len = len;
	task->remain_dst += len;
	task->remain_size -= len;

	cn_dev_gdma_debug(task->gdma_set,
			"package src:%#llx dst:%#llx len:%#llx",
			pkg->src, pkg->dst, pkg->len);

	return GDMA_SUCCESS;
}

static int gdma_task_build_memcpy_2d_package(struct cn_gdma_task *task,
		struct cn_gdma_package *pkg)
{
	pkg->type = task->transfer.type;
	pkg->src = task->transfer.src;
	pkg->dst = task->transfer.dst;
	pkg->len = task->transfer.len;
	task->remain_size -= pkg->len;

	return GDMA_SUCCESS;
}

static int gdma_task_build_memcpy_3d_package(struct cn_gdma_task *task,
		struct cn_gdma_package *pkg)
{
	pkg->type = task->transfer.type;
	pkg->src = task->transfer.src;
	pkg->dst = task->transfer.dst;
	pkg->len = task->transfer.len;
	task->remain_size -= pkg->len;

	return GDMA_SUCCESS;
}

static int gdma_task_split_package(struct cn_gdma_task *task,
		struct cn_gdma_package *pkg)
{
	int ret = -EINVAL;

	cn_dev_gdma_debug(task->gdma_set,
				"task %d total tx %lld, remain size %#llx",
				task->idx,
				task->total_tx_num,
				task->remain_size);

	switch (task->transfer.type) {
	case GDMA_MEMCPY:
		ret = gdma_task_build_memcpy_package(task, pkg);
		break;
	case GDMA_MEMSET_D8:
	case GDMA_MEMSET_D16:
	case GDMA_MEMSET_D32:
	case GDMA_MEMSET_D64:
		ret = gdma_task_build_memset_package(task, pkg);
		break;
	case GDMA_MEMCPY_2D:
		ret = gdma_task_build_memcpy_2d_package(task, pkg);
		break;
	case GDMA_MEMCPY_3D:
		ret = gdma_task_build_memcpy_3d_package(task, pkg);
		break;
	default:
		cn_dev_gdma_err(task->gdma_set, "task %d invalid tx type %d",
						task->idx, task->transfer.type);
		return -EINVAL;
	}

	return ret;
}

static u64 gdma_calc_total_tx_num(struct cn_gdma_task *task)
{
	u64 total_tx_num = 0;

	total_tx_num =
		(task->transfer.len + task->tx_max_load - 1) / task->tx_max_load;
	return total_tx_num;
}

static int gdma_task_transfer_package(struct cn_gdma_set *gdma_set,
		struct cn_gdma_task *task)
{
	struct cn_gdma_virt_chan *vchan = NULL;
	struct cn_gdma_phy_chan *pchan = NULL;
	struct cn_gdma_package *pkg = NULL;
	int ret;

	if (!task->remain_size) {
		cn_dev_gdma_debug(gdma_set, "task %d remain tx num is empty",
						task->idx);
		return GDMA_SUCCESS;
	}

	vchan = cn_gdma_get_idle_virt_chan(gdma_set, task);
	if (!vchan) {
		cn_dev_gdma_debug(gdma_set, "task %d request vchan is null",
						task->idx);
		return GDMA_NORESOURCE;
	}
	cn_dev_gdma_debug(gdma_set, "task %d get vchan %d to transfer",
								task->idx,
								vchan->idx);

	pkg = &vchan->pkg;
	ret = gdma_task_split_package(task, pkg);
	if (ret) {
		cn_dev_gdma_err(gdma_set,
					"Bug! task %d split package invalid", task->idx);
		return -GDMA_ERROR;
	}

	ret = cn_gdma_setup_virt_chan_transfer(vchan, task);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "task %d setup vchan %d package failed",
						task->idx,
						vchan->idx);
		return -GDMA_ERROR;
	}

	__sync_fetch_and_add(&task->channel_tx_count, 1);

	pchan = cn_gdma_get_idle_phy_chan(gdma_set);
	if (pchan) {
		cn_dev_gdma_debug(gdma_set, "task %d get pchan %d.%d tx go",
				task->idx, pchan->ctrl->idx, pchan->idx);
		task->trigger_tx = 1;
		return cn_gdma_tx_go(pchan, vchan);
	} else {
		cn_dev_gdma_debug(gdma_set,
				"task %d not get phy chan, put vchan %d in ready fifo",
				task->idx, vchan->idx);

		ret = kfifo_in(&task->ready_vchan_fifo,
				(void *)&vchan,
				sizeof(vchan));
		if (unlikely(ret != sizeof(vchan))) {
			cn_dev_gdma_err(gdma_set,
					"task %d vchan ready fifo in failed", task->idx);
			return -GDMA_ERROR;
		}
	}

	return GDMA_SUCCESS;
}

static int gdma_task_transfer_ready_vchan(struct cn_gdma_set *gdma_set,
		struct cn_gdma_task *task)
{
	struct cn_gdma_virt_chan *vchan = NULL;
	struct cn_gdma_phy_chan *pchan = NULL;
	unsigned long flags = 0;
	int out_len = 0;

	if (kfifo_is_empty(&task->ready_vchan_fifo)) {
		cn_dev_gdma_debug(gdma_set, "task %d ready vchan fifo is empty",
						task->idx);
		return GDMA_SUCCESS;
	}

	pchan = cn_gdma_get_idle_phy_chan(gdma_set);
	if (!pchan) {
		return GDMA_NORESOURCE;
	}
	task->pchan = pchan;

	cn_dev_gdma_debug(gdma_set, "task %d get pchan %d.%d tx go",
			task->idx, pchan->ctrl->idx, pchan->idx);

	spin_lock_irqsave(&task->ready_vchan_lock, flags);
	if (!kfifo_is_empty(&task->ready_vchan_fifo)) {
		out_len = kfifo_out(&task->ready_vchan_fifo,
					(void *)&vchan, sizeof(vchan));
		if (unlikely(out_len != sizeof(vchan))) {
			cn_dev_gdma_err(gdma_set, "task %d ready fifo out failed",
							task->idx);
			spin_unlock_irqrestore(&task->ready_vchan_lock, flags);
			cn_gdma_put_idle_phy_chan(pchan);
			return -GDMA_ERROR;
		}
	} else {
		spin_unlock_irqrestore(&task->ready_vchan_lock, flags);
		cn_gdma_put_idle_phy_chan(pchan);
		return GDMA_SUCCESS;
	}
	spin_unlock_irqrestore(&task->ready_vchan_lock, flags);

	task->trigger_tx = 1;
	return cn_gdma_tx_go(pchan, vchan);
}

static int gdma_task_clear_vchan_fifo(struct cn_gdma_set *gdma_set,
		struct cn_gdma_task *task)
{
	struct cn_gdma_virt_chan *vchan = NULL;
	int ret = 0;
	unsigned long flags;
	int out_len = 0;

	do {
		spin_lock_irqsave(&task->ready_vchan_lock, flags);
		if (!kfifo_is_empty(&task->ready_vchan_fifo)) {
			out_len = kfifo_out(&task->ready_vchan_fifo,
					(void *)&vchan, sizeof(vchan));
			if (unlikely(out_len != sizeof(vchan))) {
				cn_dev_gdma_err(gdma_set, "task %d ready vchan fifo out failed",
						task->idx);
				spin_unlock_irqrestore(&task->ready_vchan_lock, flags);
				ret = -GDMA_ERROR;
				break;
			}
		} else {
			spin_unlock_irqrestore(&task->ready_vchan_lock, flags);
			ret = GDMA_SUCCESS;
			break;
		}
		spin_unlock_irqrestore(&task->ready_vchan_lock, flags);

		cn_dev_gdma_debug(gdma_set, "task %d release ready vchan %d",
					task->idx, vchan->idx);

		__sync_fetch_and_sub(&task->channel_tx_count, 1);
		cn_gdma_put_idle_virt_chan(vchan);
	} while (1);

	cn_dev_gdma_debug(gdma_set, "task %d last check channel tx count %d",
					task->idx, task->channel_tx_count);

	return ret;
}

int cn_gdma_request_task(struct cn_gdma_set *gdma_set,
		struct cn_gdma_task **task)
{
	struct cn_gdma_task *find_task = NULL;
	int i;
	u32 index = 0;
	int ret = -1;

	ret = down_killable(&gdma_set->task_sem);
	if (ret == -EINTR) {
		cn_dev_gdma_err(gdma_set, "request task cancel by signal!");
		return ret;
	}

	index = gdma_set->task_search_start % gdma_set->task_num;
	do {
		for (i = 0; i < gdma_set->task_num; i++) {
			find_task = *(gdma_set->task_pool + index);
			if (__sync_bool_compare_and_swap(&find_task->status,
						GDMA_TASK_IDLE, GDMA_TASK_ASSIGNED)) {
				__sync_fetch_and_add(&gdma_set->task_search_start, i + 1);
				*task = find_task;
				ret = GDMA_SUCCESS;
				goto out;
			}
			index++;
			index %= gdma_set->task_num;
		}

		usleep_range(1, 10);

		if (fatal_signal_pending(current) ||
			current->flags & PF_EXITING) {
			cn_dev_gdma_err(gdma_set, "request task cancel by signal!");
			up(&gdma_set->task_sem);
			*task = NULL;
			ret = -EINTR;
			break;
		}
	} while (1);

out:
	return ret;
}

int cn_gdma_release_task(struct cn_gdma_set *gdma_set,
						struct cn_gdma_task *task)
{
	task->pchan = NULL;
	kfifo_reset(&task->ready_vchan_fifo);
	__sync_lock_test_and_set(&task->status, GDMA_TASK_IDLE);
	up(&gdma_set->task_sem);

	return GDMA_SUCCESS;
}

int cn_gdma_init_task_transfer(struct cn_gdma_set *gdma_set,
		struct cn_gdma_task *task, struct cn_gdma_transfer *transfer)
{
	int ret = 0;

	memcpy((void *)&task->transfer, (void *)transfer,
			sizeof(struct cn_gdma_transfer));

	task->tx_max_load = gdma_task_tx_max_load(task);
	task->total_tx_num = gdma_calc_total_tx_num(task);
	if (unlikely(!task->total_tx_num)) {
		cn_dev_gdma_err(gdma_set, "task %d total_tx_num can't be zero",
						task->idx);
		return -EINVAL;
	}

	if (task->transfer.len <= gdma_set->poll_size) {
		task->dma_tx_mode = GDMA_TX_POLL_MODE;
	} else {
		task->dma_tx_mode = GDMA_TX_INTR_MODE;
	}

	task->finish_tx_num = 0;
	task->channel_done = 0;
	task->channel_tx_count = 0;
	task->trigger_tx = 0;
	task->remain_dst = transfer->dst;
	task->remain_size = transfer->len;
	task->error_flag = 0;

	switch (transfer->type) {
	case GDMA_MEMCPY:
		task->remain_src = transfer->src;
		break;
	case GDMA_MEMSET_D8:
	case GDMA_MEMSET_D16:
	case GDMA_MEMSET_D32:
	case GDMA_MEMSET_D64:
		ret = gdma_init_memset_buffer(task);
		break;
	case GDMA_MEMCPY_2D:
	case GDMA_MEMCPY_3D:
		//memcpy needn't split package
		task->total_tx_num = 1;
		task->remain_src = transfer->src;
		break;
	default:
		cn_dev_gdma_err(gdma_set, "task %d invalid transfer type %d",
				task->idx, transfer->type);
		return -EINVAL;
	}

	if (ret) {
		cn_dev_gdma_err(gdma_set, "gdma init failed, ret=%d", ret);
		return ret;
	}

	cn_dev_gdma_debug(gdma_set, "task %d total_tx_num %lld",
				task->idx,
				task->total_tx_num);

	__sync_lock_test_and_set(&task->status, GDMA_TASK_READY);

	return ret;
}

int cn_gdma_task_run(struct cn_gdma_set *gdma_set, struct cn_gdma_task *task)
{
	int ret = -1;
	struct cn_gdma_phy_chan *pchan;
	u32 main_chan_status = 0;
	u32 channel_status = 0;

	__sync_lock_test_and_set(&task->status, GDMA_TASK_SCHED);

	while (1) {
		ret = gdma_task_transfer_package(gdma_set, task);
		/* get vchan return GDMA_NORESOURCE should continue */
		if (unlikely(ret < 0)) {
			cn_dev_gdma_err(gdma_set, "task %d transfer package failed",
							task->idx);
			__sync_lock_test_and_set(&task->status, GDMA_TASK_ERROR);
			break;
		}

		ret = gdma_task_transfer_ready_vchan(gdma_set, task);
		/* get pchan return GDMA_NORESOURCE should continue */
		if (unlikely(ret < 0)) {
			cn_dev_gdma_err(gdma_set, "task %d transfer ready vchan failed",
							task->idx);
			__sync_lock_test_and_set(&task->status, GDMA_TASK_ERROR);
			break;
		}

		if (task->remain_size) {
			continue;
		}

		if (!task->trigger_tx &&
			!kfifo_is_empty(&task->ready_vchan_fifo)) {
			continue;
		}

		if (task->dma_tx_mode == GDMA_TX_POLL_MODE) {
			task->trigger_tx = 0;
			if (task->error_flag) {
				cn_dev_gdma_err(gdma_set, "task %d error!", task->idx);
				__sync_lock_test_and_set(&task->status, GDMA_TASK_ERROR);
				ret = -GDMA_ERROR;
				break;
			}

			if (task->total_tx_num == task->finish_tx_num) {
				__sync_lock_test_and_set(&task->status, GDMA_TASK_DONE);
				ret = GDMA_SUCCESS;
				break;
			}
			continue;
		}

		ret = wait_event_timeout(task->channel_wq,
				task->channel_done || !task->channel_tx_count || task->error_flag,
				60 * HZ);
		if (!ret) {
			cn_dev_gdma_err(gdma_set,
				"task %d wait timeout,tx count %d,trigger tx %d,chan done %d",
				task->idx, task->channel_tx_count, task->trigger_tx,
				task->channel_done);

			pchan = task->pchan;//FIXME
			if (pchan) {
				main_chan_status = reg_read32(pchan->gdma_set->core->bus_set,
										pchan->ctrl->main_csr_base + 0x20);
				channel_status = (main_chan_status >> (pchan->idx * 4)) & 0xf;
				cn_dev_gdma_err(pchan->gdma_set,
					"gdmac%d channel%d main status:0x%x channel status:0x%x",
					pchan->ctrl->idx, pchan->idx,
					main_chan_status, channel_status);
			}

			cn_dev_gdma_info(gdma_set,
				"task %d gdma transfer info:\n"
				"type:%d src:0x%llx dst:0x%llx size:0x%llx value 0x%llx",
				task->idx,
				task->transfer.type,
				task->transfer.src,
				task->transfer.dst,
				task->transfer.len,
				task->transfer.memset_value);
			ret = -GDMA_ERROR;
			__sync_lock_test_and_set(&task->status, GDMA_TASK_EXIT);
			break;
		}

		__sync_bool_compare_and_swap(&task->channel_done, 1, 0);

		if (task->error_flag) {
			cn_dev_gdma_err(gdma_set, "task %d error!", task->idx);
			__sync_lock_test_and_set(&task->status, GDMA_TASK_ERROR);
			ret = -GDMA_ERROR;
			break;
		}

		if (task->total_tx_num == task->finish_tx_num) {
			__sync_lock_test_and_set(&task->status, GDMA_TASK_DONE);
			ret = GDMA_SUCCESS;
			break;
		}

		task->trigger_tx = 0;
	}

	gdma_task_clear_vchan_fifo(gdma_set, task);
	if (unlikely(print_debug & SHOW_RUN_STATUS_MASK)) {
		cn_gdma_dbg_show_run_status(gdma_set);
	}
	cn_dev_gdma_debug(gdma_set, "task %d quit from run loop", task->idx);
	return ret;
}

static void gdma_memset_shm_exit(struct cn_gdma_set *gdma_set)
{
	if (gdma_set->memset_shm.host_kva &&
			gdma_set->memset_shm.dev_va) {
		cn_device_share_mem_free(0,
			gdma_set->memset_shm.host_kva,
			gdma_set->memset_shm.dev_va,
			gdma_set->core);
	}
}

static int gdma_memset_shm_init(struct cn_gdma_set *gdma_set)
{
	int ret = 0;
	u32 memset_buf_size;
	unsigned long host_kva;
	u64 dev_va;
	u32 task_num;

	task_num = cn_gdma_get_task_num(gdma_set);
	memset_buf_size = cn_gdma_get_memset_buf_size(gdma_set);
	if (!task_num || !memset_buf_size) {
		return -EINVAL;
	}

	if (memset_buf_size % GDMA_MEMSET_BUFFER_SIZE) {
		cn_dev_gdma_err(gdma_set, "Bug! memset_buf_size %d should be align with 1024",
				memset_buf_size);
		return -EINVAL;
	}

	gdma_set->memset_shm.size = task_num * memset_buf_size;
	ret = cn_device_share_mem_alloc(0,
			&host_kva, &dev_va,
			gdma_set->memset_shm.size, gdma_set->core);
	if (ret) {
		cn_dev_gdma_err(gdma_set,
			"alloc share memory for task memset failed.");
		return ret;
	}
	gdma_set->memset_shm.host_kva = host_kva;
	gdma_set->memset_shm.dev_va = dev_va;

	cn_dev_gdma_info(gdma_set,
		"gdma memset shm size:%#llx dev_va:%#llx host_kva:%#lx buf_size:%#x",
		gdma_set->memset_shm.size, dev_va, host_kva, memset_buf_size);

	return ret;
}

static void gdma_task_exit(struct cn_gdma_set *gdma_set)
{
	int i;
	struct cn_gdma_task *task = NULL;

	if (!gdma_set->task_pool)
		return;

	for (i = 0; i < gdma_set->task_num; i++) {
		task = gdma_set->task_pool[i];
		kfifo_free(&task->ready_vchan_fifo);
		cn_kfree(task);
	}
	cn_kfree(gdma_set->task_pool);
}

static int gdma_task_init(struct cn_gdma_set *gdma_set)
{
	int i;
	struct cn_gdma_task *task = NULL;
	unsigned long host_kva;
	u64 dev_va;
	u32 memset_buf_size;
	u32 priv_vchan_num;

	gdma_set->task_num = cn_gdma_get_task_num(gdma_set);
	gdma_set->vchan_num = cn_gdma_get_vchan_num(gdma_set);
	priv_vchan_num = cn_gdma_get_priv_vchan_num(gdma_set);
	memset_buf_size = cn_gdma_get_memset_buf_size(gdma_set);
	if (!gdma_set->task_num || !gdma_set->vchan_num ||
		!priv_vchan_num || !memset_buf_size) {
		return -EINVAL;
	}

	sema_init(&gdma_set->task_sem, gdma_set->task_num);
	host_kva = gdma_set->memset_shm.host_kva;
	dev_va = gdma_set->memset_shm.dev_va;

	gdma_set->task_pool = cn_kzalloc(gdma_set->task_num *
				sizeof(struct cn_gdma_task *), GFP_KERNEL);
	if (!gdma_set->task_pool) {
		cn_dev_gdma_err(gdma_set, "alloc task pool failed!");
		return -ENOMEM;
	}

	for (i = 0; i < gdma_set->task_num; i++) {
		task = cn_kzalloc(sizeof(struct cn_gdma_task), GFP_KERNEL);
		if (!task) {
			cn_dev_gdma_err(gdma_set, "alloc task %d object failed", i);
			return -ENOMEM;
		}
		if (kfifo_alloc(&task->ready_vchan_fifo,
					(gdma_set->vchan_num + priv_vchan_num) *
					sizeof(struct cn_gdma_virt_chan *), GFP_KERNEL)) {
			cn_dev_gdma_err(gdma_set, "task %d kfifo alloc ready vchan failed", i);
			return -ENOMEM;
		}
		task->idx = i;
		task->status = GDMA_TASK_IDLE;
		task->gdma_set = gdma_set;
		task->priv_vchan_num = priv_vchan_num;
		spin_lock_init(&task->ready_vchan_lock);
		init_waitqueue_head(&task->channel_wq);

		task->memset_shm.host_kva = host_kva;
		task->memset_shm.dev_va = dev_va;
		task->memset_shm.size = memset_buf_size;

		gdma_set->task_pool[i] = task;
		host_kva += task->memset_shm.size;
		dev_va += task->memset_shm.size;
	}

	return 0;
}

void gdma_priv_virt_chan_exit(struct cn_gdma_set *gdma_set)
{
	int i, j;
	struct cn_gdma_task *task;

	if (gdma_set->priv_desc_shm.host_kva &&
			gdma_set->priv_desc_shm.dev_va) {
		cn_device_share_mem_free(0,
				gdma_set->priv_desc_shm.host_kva,
				gdma_set->priv_desc_shm.dev_va,
				gdma_set->core);
	}

	if (!gdma_set->task_pool)
		return;
	for (i = 0; i < gdma_set->task_num; i++) {
		task = gdma_set->task_pool[i];
		if (!task->priv_vchan)
			return;
		for (j = 0; j < task->priv_vchan_num; j++) {
			cn_kfree(task->priv_vchan[j]);
		}
		cn_kfree(task->priv_vchan);
	}
}

int gdma_priv_virt_chan_init(struct cn_gdma_set *gdma_set)
{
	struct cn_gdma_task *task = NULL;
	unsigned long host_kva;
	u64 dev_va;
	int i, j;
	struct cn_gdma_virt_chan *vchan;
	int ret;
	u32 priv_vchan_num;

	priv_vchan_num = cn_gdma_get_priv_vchan_num(gdma_set);
	if (!priv_vchan_num) {
		cn_dev_gdma_err(gdma_set, "gdma priv vchan num invalid");
		return -EINVAL;
	}
	for (i = 0; i < gdma_set->task_num; i++) {
		task = gdma_set->task_pool[i];
		task->priv_vchan = cn_kzalloc(sizeof(struct cn_gdma_virt_chan *) *
				priv_vchan_num, GFP_KERNEL);
		if (!task->priv_vchan) {
			cn_dev_gdma_err(gdma_set, "alloc task priv vchan failed!");
			return -ENOMEM;
		}
	}

	gdma_set->priv_desc_shm.size = gdma_set->task_num *
		priv_vchan_num * GDMA_VCHAN_DESC_BUFFER_SIZE;
	ret = cn_device_share_mem_alloc(0,
			&host_kva, &dev_va,
			gdma_set->priv_desc_shm.size, gdma_set->core);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "alloc priv desc share memory failed!");
		return -ENOMEM;
	}
	gdma_set->priv_desc_shm.host_kva = host_kva;
	gdma_set->priv_desc_shm.dev_va = dev_va;
	cn_dev_gdma_info(gdma_set,
		"gdma priv vchan shm size:%#llx dev_va:%#llx host_kva:%#lx",
		gdma_set->priv_desc_shm.size, dev_va, host_kva);

	for (i = 0; i < gdma_set->task_num; i++) {
		task = gdma_set->task_pool[i];
		for (j = 0; j < priv_vchan_num; j++) {
			vchan = cn_kzalloc(sizeof(struct cn_gdma_virt_chan), GFP_KERNEL);
			if (!vchan) {
				cn_dev_gdma_err(gdma_set, "alloc priv vchan failed!");
				return -ENOMEM;
			}

			//vchan->idx = 1000 + i * 10 + j;
			vchan->gdma_set = gdma_set;
			vchan->status = GDMA_CHANNEL_IDLE;
			vchan->desc_shm.host_kva = host_kva;
			vchan->desc_shm.dev_va = dev_va;
			vchan->desc_shm.size = GDMA_VCHAN_DESC_BUFFER_SIZE;

			task->priv_vchan[j] = vchan;
			host_kva += vchan->desc_shm.size;
			dev_va += vchan->desc_shm.size;
		}
	}

	return GDMA_SUCCESS;
}

static void gdma_shared_virt_chan_exit(struct cn_gdma_set *gdma_set)
{
	struct cn_gdma_virt_chan *vchan = NULL;
	int i;

	if (gdma_set->shared_desc_shm.host_kva &&
			gdma_set->shared_desc_shm.dev_va) {
		cn_device_share_mem_free(0,
				gdma_set->shared_desc_shm.host_kva,
				gdma_set->shared_desc_shm.dev_va,
				gdma_set->core);
	}

	if (!gdma_set->vchan_pool)
		return;
	for (i = 0; i < gdma_set->vchan_num; i++) {
		vchan = gdma_set->vchan_pool[i];
		cn_kfree(vchan);
	}
	cn_kfree(gdma_set->vchan_pool);
}

static int gdma_shared_virt_chan_init(struct cn_gdma_set *gdma_set)
{
	int i;
	struct cn_gdma_virt_chan *vchan = NULL;
	unsigned long host_kva;
	u64 dev_va;
	int ret;

	gdma_set->shared_desc_shm.size = gdma_set->vchan_num * GDMA_VCHAN_DESC_BUFFER_SIZE;
	ret = cn_device_share_mem_alloc(0,
			&host_kva, &dev_va,
			gdma_set->shared_desc_shm.size, gdma_set->core);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "alloc desc share memory failed!");
		return -ENOMEM;
	}
	gdma_set->shared_desc_shm.host_kva = host_kva;
	gdma_set->shared_desc_shm.dev_va = dev_va;
	cn_dev_gdma_info(gdma_set,
		"gdma shared vchan shm size:%#llx dev_va:%#llx host_kva:%#lx vchan_num:%d",
		gdma_set->shared_desc_shm.size, dev_va, host_kva, gdma_set->vchan_num);

	gdma_set->vchan_pool = cn_kzalloc(sizeof(struct cn_gdma_virt_chan *) *
					gdma_set->vchan_num, GFP_KERNEL);
	if (!gdma_set->vchan_pool) {
		cn_dev_gdma_err(gdma_set, "alloc virt channel pool failed!");
		return -ENOMEM;
	}
	for (i = 0; i < gdma_set->vchan_num; i++) {
		vchan = cn_kzalloc(sizeof(struct cn_gdma_virt_chan), GFP_KERNEL);
		if (!vchan) {
			cn_dev_gdma_err(gdma_set, "alloc vchan %d object failed", i);
			return -ENOMEM;
		}

		vchan->idx = i;
		vchan->gdma_set = gdma_set;
		vchan->status = GDMA_CHANNEL_IDLE;
		vchan->desc_shm.host_kva = host_kva;
		vchan->desc_shm.dev_va = dev_va;
		vchan->desc_shm.size = GDMA_VCHAN_DESC_BUFFER_SIZE;

		gdma_set->vchan_pool[i] = vchan;
		host_kva += vchan->desc_shm.size;
		dev_va += vchan->desc_shm.size;
	}

	return GDMA_SUCCESS;
}

int cn_gdma_sched_init(struct cn_gdma_set *gdma_set)
{
	int ret = 0;

	if (!gdma_set->available_pchan_num) {
		cn_dev_gdma_info(gdma_set, "host gdma no pchan not need init sched");
		return ret;
	}

	gdma_set->poll_size = GDMA_POLL_MODE_TX_SIZE;

	ret = gdma_memset_shm_init(gdma_set);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "gdma memset shm init failed");
		goto memset_shm_exit;
	}

	ret = gdma_task_init(gdma_set);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "gdma task init failed");
		goto task_exit;
	}

	ret = gdma_priv_virt_chan_init(gdma_set);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "priv virt vchan init failed");
		goto priv_virt_chan_exit;
	}

	ret = gdma_shared_virt_chan_init(gdma_set);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "gdma virt chan init failed");
		goto shared_virt_chan_exit;
	}

	return ret;

shared_virt_chan_exit:
	gdma_shared_virt_chan_exit(gdma_set);
priv_virt_chan_exit:
	gdma_priv_virt_chan_exit(gdma_set);
task_exit:
	gdma_task_exit(gdma_set);
memset_shm_exit:
	gdma_memset_shm_exit(gdma_set);
	cn_dev_gdma_err(gdma_set, "gdma sched init failed");
	return ret;
}

int cn_gdma_sched_deinit(struct cn_gdma_set *gdma_set)
{
	if (!gdma_set->available_pchan_num) {
		cn_dev_gdma_info(gdma_set, "host gdma no pchan not need deinit sched");
		return GDMA_SUCCESS;
	}
	gdma_shared_virt_chan_exit(gdma_set);
	gdma_priv_virt_chan_exit(gdma_set);
	gdma_task_exit(gdma_set);
	gdma_memset_shm_exit(gdma_set);

	return GDMA_SUCCESS;
}
