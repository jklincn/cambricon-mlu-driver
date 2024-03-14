/*
 * gdma/gdma_api.c
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
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/delay.h>

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_gdma.h"
#include "gdma_api.h"
#include "gdma_drv.h"
#include "gdma_rpc.h"
#include "gdma_sched.h"
#include "gdma_debug.h"
#include "gdma_common.h"
#include "gdma_common_api.h"


int cn_host_gdma_init(struct cn_gdma_super_set *gdma_set)
{
	int ret = 0;
	struct cn_core_set *core = gdma_set->core;
	struct cn_gdma_set *host_gdma = NULL;

	host_gdma = cn_kzalloc(sizeof(struct cn_gdma_set), GFP_KERNEL);
	if (!host_gdma) {
		cn_dev_core_err(core, "alloc host gdma set failed");
		return -ENOMEM;
	}

	gdma_set->host_gdma = (void *)host_gdma;
	host_gdma->core = core;
	strcpy(host_gdma->core_name, core->core_name);

	ret = cn_gdma_drv_init(host_gdma);
	if (ret) {
		cn_dev_core_err(core, "gdma drv init failed");
		goto drv_exit;
	}

	ret = cn_gdma_sched_init(host_gdma);
	if (ret) {
		cn_dev_core_err(core, "gdma sched init failed");
		goto sched_exit;
	}

	return 0;

sched_exit:
	cn_gdma_drv_deinit(host_gdma);
drv_exit:
	cn_kfree(gdma_set->host_gdma);
	return ret;
}

int cn_host_gdma_exit(struct cn_gdma_super_set *gdma_set)
{
	struct cn_core_set *core;
	struct cn_gdma_set *host_gdma;

	if (!gdma_set || !gdma_set->core || !gdma_set->host_gdma) {
		cn_dev_err("host gdma exit invalid param");
		return -EINVAL;
	}

	core = gdma_set->core;
	host_gdma = gdma_set->host_gdma;
	cn_gdma_sched_deinit(host_gdma);
	cn_gdma_drv_deinit(host_gdma);
	cn_kfree(gdma_set->host_gdma);

	return 0;
}

int cn_host_gdma_rpc_init(struct cn_gdma_super_set *gdma_set)
{
	struct cn_core_set *core = gdma_set->core;
	struct cn_gdma_set *host_gdma = NULL;
	struct cn_gdma_load_param load_param = {0};
	int in_len = 0;
	size_t out_len = 0;
	struct memcpy_d2d_out out = {0};
	int ret;

#if HOST_GDMA_CLOSE_CTRL_CONFIG
	/***
	 * Only work on MLU580 and the CE must do rpc init-exit process.
	 */
	if (core->device_id == MLUID_580) {
		return 0;
	}
#endif
	host_gdma = gdma_set->host_gdma;
	host_gdma->load_endpoint = __gdma_open_channel(core, "copy_engine_load_krpc");
	if (!host_gdma->load_endpoint) {
		cn_dev_core_err(core, "copy_engine_load_krpc open failed!\n");
		return -GDMA_ERROR;
	}

	//param invalid check
	if (host_gdma->ctrl_num > GDMA_MAX_CTRL_NUM) {
		cn_dev_core_err(core, "gdma ctrl %d is too big to support!",
						host_gdma->ctrl_num);
		return -EINVAL;
	}

	/***
	 * rpc arm to config gdma smmu
	 */
	load_param.mode = GDMA_HOST_MODE;
	load_param.ctrl_num = host_gdma->ctrl_num;

	memcpy((void *)load_param.smmu_info,
			(void *)host_gdma->info->smmu_info,
			sizeof(struct cn_gdma_smmu_info) * load_param.ctrl_num);
	in_len = sizeof(load_param);
	out_len = sizeof(out);

	//call rpc_gdma_load to initialize smmu for host mode
	cn_dev_core_debug(core, "call gdma rpc gdma load to init smmu!");
	ret = __gdma_call_rpc(core, host_gdma->load_endpoint,
				"rpc_gdma_load",
				(void *)&load_param,
				in_len,
				(void *)&out,
				&out_len,
				sizeof(out));
	if (ret) {
		cn_dev_core_err(core, "rpc_gdma_load failed,ret %d,out %d", ret, out.ret);
		return ret;
	}

	return ret;
}

void cn_host_gdma_rpc_exit(struct cn_gdma_super_set *gdma_set)
{
	struct cn_core_set *core = gdma_set->core;
	struct cn_gdma_set *host_gdma = gdma_set->host_gdma;

#if HOST_GDMA_CLOSE_CTRL_CONFIG
	/***
	 * Only work on MLU580 and the CE must do rpc init-exit process.
	 */
	if (core->device_id == MLUID_580) {
		return;
	}
#endif
	if (host_gdma->load_endpoint) {
		__gdma_close_channel(core, host_gdma->load_endpoint);
		host_gdma->load_endpoint = NULL;
	}

	return;
}

static int cn_gdma_transfer_sync(struct cn_gdma_super_set *gdma_set,
							struct cn_gdma_transfer *transfer)
{
	struct cn_core_set *core = gdma_set->core;
	struct cn_gdma_set *host_gdma = gdma_set->host_gdma;
	struct cn_gdma_task *task = NULL;
	int ret = -1;


	if (!host_gdma->available_pchan_num) {
		cn_dev_core_err(core, "host gdma has no pchan to use. failed");
		return ret;
	}

	if (!transfer->len) {
		cn_dev_core_debug(core, "gdma transfer size 0, do nothing");
		return 0;
	}
	cn_dev_core_debug(core,
			"process pid %d tpid %d gdma transfer info:\n"
			"type:%d src:0x%llx dst:0x%llx size:0x%llx value 0x%llx",
			current->pid, current->tgid,
			transfer->type, transfer->src, transfer->dst,
			transfer->len, transfer->memset_value);

	ret = cn_gdma_request_task(host_gdma, &task);
	if (ret) {
		cn_dev_core_err(core,
				"process pid %d tpid %d request task failed!\n"
				"gdma transfer info:\n"
				"type:%d src:0x%llx dst:0x%llx size:0x%llx value 0x%llx",
				current->pid, current->tgid,
				transfer->type, transfer->src, transfer->dst,
				transfer->len, transfer->memset_value);
		return -GDMA_ERROR;
	}

	ret = cn_gdma_init_task_transfer(host_gdma, task, transfer);
	if (ret) {
		cn_dev_core_err(core, "init task %d transfer failed", task->idx);
		goto error;
	}

	ret = cn_gdma_task_run(host_gdma, task);
	if (ret) {
		cn_dev_core_err(core, "start gdma task %d failed", task->idx);
		goto error;
	}

error:
	cn_gdma_release_task(host_gdma, task);
	if (ret) {
		cn_dev_core_err(core,
			"process pid %d tpid %d release task failed!gdma task info:\n"
			"type:%d src:0x%llx dst:0x%llx size:0x%llx value 0x%llx",
			current->pid, current->tgid,
			transfer->type, transfer->src, transfer->dst,
			transfer->len, transfer->memset_value);
	}

	return ret;
}

int cn_host_gdma_memcpy(struct cn_gdma_super_set *gdma_set, u64 src_vaddr,
			u64 dst_vaddr, ssize_t size, int compress_type)
{
	struct cn_core_set *core = gdma_set->core;
	struct cn_gdma_set *host_gdma = gdma_set->host_gdma;
	struct cn_gdma_transfer gdma_trans = {0};
	int ret = 0;

	if (unlikely(host_gdma->inject_error_src)) {
		cn_dev_core_err(core, "Use error address 0x%llx to memcpy",
			host_gdma->inject_error_src);
		gdma_trans.src = host_gdma->inject_error_src;
	} else {
		gdma_trans.src = src_vaddr;
	}

	gdma_trans.dst = dst_vaddr;
	gdma_trans.len = size;
	gdma_trans.type = GDMA_MEMCPY;
	gdma_trans.compress_type = compress_type;
	ret = cn_gdma_transfer_sync(gdma_set, &gdma_trans);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "gdma host memcpy sync failed,ret %d", ret);
	}

	return ret;
}

int cn_host_gdma_memset(struct cn_gdma_super_set *gdma_set, struct memset_s *t)
{
	struct cn_core_set *core = gdma_set->core;
	struct cn_gdma_transfer gdma_trans = {0};
	int ret = 0;

	if (!t) {
		cn_dev_core_err(core, "host gdma memset invalid param");
		return -EINVAL;
	}

	gdma_trans.dst = t->dev_addr;
	gdma_trans.memset_value = t->val;
	switch (t->direction) {
	case MEMSET_D8:
		gdma_trans.type = GDMA_MEMSET_D8;
		gdma_trans.len = t->number;
		break;
	case MEMSET_D16:
		gdma_trans.type = GDMA_MEMSET_D16;
		gdma_trans.len = t->number * sizeof(u16);
		break;
	case MEMSET_D32:
		gdma_trans.type = GDMA_MEMSET_D32;
		gdma_trans.len = t->number * sizeof(u32);
		break;
	default:
		cn_dev_core_err(core, "invalid dir type %d", t->direction);
		return -EINVAL;
	}

	ret = cn_gdma_transfer_sync(gdma_set, &gdma_trans);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "gdma host memset sync failed,ret %d", ret);
	}

	return ret;
}

int cn_host_gdma_memcpy_2d(struct cn_gdma_super_set *gdma_set,
					u64 src_vaddr,
					u64 dst_vaddr,
					ssize_t spitch,
					ssize_t dpitch,
					ssize_t width,
					ssize_t height)
{
	struct cn_core_set *core = gdma_set->core;
	struct cn_gdma_transfer gdma_trans = {0};
	int ret = 0;

	gdma_trans.src = src_vaddr;
	gdma_trans.dst = dst_vaddr;
	gdma_trans.d2d_2d.spitch = spitch;
	gdma_trans.d2d_2d.dpitch = dpitch;
	gdma_trans.d2d_2d.width = width;
	gdma_trans.d2d_2d.height = height;
	gdma_trans.len = width * height;
	gdma_trans.type = GDMA_MEMCPY_2D;

	ret = cn_gdma_transfer_sync(gdma_set, &gdma_trans);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "gdma host memcpy 2d sync failed,%d", ret);
	}

	return ret;
}

int cn_host_gdma_memcpy_3d(struct cn_gdma_super_set *gdma_set,
					struct memcpy_d2d_3d_compat *p)
{
	struct cn_core_set *core = gdma_set->core;
	struct cn_gdma_transfer gdma_trans = {0};
	int ret = 0;

	memcpy((void *)&gdma_trans.d2d_3d,
			(void *)p,
			sizeof(*p));

	gdma_trans.src = p->src;
	gdma_trans.dst = p->dst;
	gdma_trans.len = p->extent.width * p->extent.height * p->extent.depth;
	gdma_trans.type = GDMA_MEMCPY_3D;

	ret = cn_gdma_transfer_sync(gdma_set, &gdma_trans);
	if (unlikely(ret)) {
		cn_dev_core_err(core, "gdma host memcpy 3d sync failed,%d", ret);
	}

	return ret;
}
