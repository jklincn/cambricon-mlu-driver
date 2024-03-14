/*
 * ce_api/ce_gdma_api.c
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
#include "cndrv_gdma.h"
#include "cndrv_debug.h"
#include "ce_gdma_api.h"
#include "gdma_rpc.h"
#include "gdma_common_api.h"

int cn_ce_gdma_memcpy(struct cn_gdma_super_set *gdma_set,
							u64 src_vaddr,
							u64 dst_vaddr,
							ssize_t size,
							int compress_type)
{
	struct cn_core_set *core = gdma_set->core;
	struct ce_gdma_set *ce_gdma = gdma_set->ce_gdma;
	struct memcpy_d2d_in in = {0};
	struct memcpy_d2d_out out = {0};
	size_t in_len = 0;
	size_t out_len = 0;
	int ret = 0;

	in.src = src_vaddr;
	in.dst = dst_vaddr;
	in.size = size;
	in.compress_type = compress_type;
	in.memd2d_type = CE_MEMCPY_1D;
	in_len = sizeof(struct memcpy_d2d_in);
	out_len = sizeof(struct memcpy_d2d_out);

	if (compress_type != MEMCPY_D2D_NO_COMPRESS) {
		if (MLUID_PIGEON != core->device_id && MLUID_PIGEON_EDGE != core->device_id) {
			cn_dev_core_err(core, "devive %lld not support compress api.\n",
				core->device_id);
			return -EPERM;
		}
	}

	if (down_killable(&ce_gdma->ce_gdma_sema)) {
		cn_dev_core_err(core, "Aborted by signal waile waiting for semaphore.\n");
		return -EINTR;
	}

	ret = __gdma_call_rpc(core, ce_gdma->gdma_submit_endpoint,
			"rpc_memcpyd2d_submit", &in, in_len,
			&out, &out_len, out_len);
	if (ret < 0) {
		cn_dev_core_err(core, "memcpy d2d submit rpc call failed,%d", ret);
		goto out;
	}

	if (out.ret) {
		cn_dev_core_err(core, "memcpy d2d submit failed:%d.", out.ret);
		ret = out.ret;
		goto out;
	}

	in.task_addr = out.task_addr;
	ret = __gdma_call_rpc(core, ce_gdma->gdma_sync_endpoint,
			"rpc_memcpyd2d_sync", &in, in_len,
			&out, &out_len, out_len);
	if (ret < 0) {
		cn_dev_core_err(core, "memcpy d2d sync rpc call failed,%d", ret);
		goto out;
	}
	ret = out.ret;

out:
	up(&ce_gdma->ce_gdma_sema);
	return ret;
}

int cn_ce_gdma_memcpy_2d(struct cn_gdma_super_set *gdma_set,
						u64 src_vaddr,
						u64 dst_vaddr,
						ssize_t spitch,
						ssize_t dpitch,
						ssize_t width,
						ssize_t height)
{
	struct cn_core_set *core = gdma_set->core;
	struct ce_gdma_set *ce_gdma = gdma_set->ce_gdma;
	struct memcpy_d2d_in in = {0};
	struct memcpy_d2d_out out = {0};
	size_t in_len = 0;
	size_t out_len = 0;
	int ret = 0;

	in.src = src_vaddr;
	in.dst = dst_vaddr;
	in.d2d_2d.spitch = spitch;
	in.d2d_2d.dpitch = dpitch;
	in.d2d_2d.width = width;
	in.d2d_2d.height = height;
	in.size = spitch * dpitch;
	in.memd2d_type = CE_MEMCPY_2D;
	in_len = sizeof(struct memcpy_d2d_in);
	out_len = sizeof(struct memcpy_d2d_out);

	if (down_killable(&ce_gdma->ce_gdma_sema)) {
		cn_dev_core_err(core, "Aborted by signal waile waiting for semaphore.\n");
		return -EINTR;
	}

	ret = __gdma_call_rpc(core, ce_gdma->gdma_submit_endpoint,
			"rpc_memcpyd2d_submit", &in, in_len,
			&out, &out_len, out_len);
	if (ret < 0) {
		cn_dev_core_err(core, "memcpy d2d submit rpc call failed,%d", ret);
		goto out;
	}

	if (out.ret) {
		cn_dev_core_err(core, "memcpy d2d submit failed:%d.", out.ret);
		ret = out.ret;
		goto out;
	}

	in.task_addr = out.task_addr;
	ret = __gdma_call_rpc(core, ce_gdma->gdma_sync_endpoint,
			"rpc_memcpyd2d_sync", &in, in_len,
			&out, &out_len, out_len);
	if (ret < 0) {
		cn_dev_core_err(core, "memcpy d2d sync rpc call failed,%d", ret);
		goto out;
	}
	ret = out.ret;

out:
	up(&ce_gdma->ce_gdma_sema);
	return ret;
}

int cn_ce_gdma_memcpy_3d(struct cn_gdma_super_set *gdma_set,
						struct memcpy_d2d_3d_compat *p)
{
	struct cn_core_set *core = gdma_set->core;
	struct ce_gdma_set *ce_gdma = gdma_set->ce_gdma;
	struct memcpy_d2d_in in = {0};
	struct memcpy_d2d_out out = {0};
	size_t in_len = 0;
	size_t out_len = 0;
	int ret = 0;

	in.d2d_3d = *p;
	in.size = p->dst_ptr.pitch * p->extent.height * p->extent.depth;
	in.memd2d_type = CE_MEMCPY_3D;
	in_len = sizeof(struct memcpy_d2d_in);
	out_len = sizeof(struct memcpy_d2d_out);

	if (down_killable(&ce_gdma->ce_gdma_sema)) {
		cn_dev_core_err(core, "Aborted by signal waile waiting for semaphore.\n");
		return -EINTR;
	}

	ret = __gdma_call_rpc(core, ce_gdma->gdma_submit_endpoint,
			"rpc_memcpyd2d_submit", &in, in_len,
			&out, &out_len, out_len);
	if (ret < 0) {
		cn_dev_core_err(core, "memcpy d2d submit rpc call failed,%d", ret);
		goto out;
	}

	if (out.ret) {
		cn_dev_core_err(core, "memcpy d2d submit failed:%d.", out.ret);
		ret = out.ret;
		goto out;
	}

	in.task_addr = out.task_addr;
	ret = __gdma_call_rpc(core, ce_gdma->gdma_sync_endpoint,
			"rpc_memcpyd2d_sync", &in, in_len,
			&out, &out_len, out_len);
	if (ret < 0) {
		cn_dev_core_err(core, "memcpy d2d sync rpc call failed,%d", ret);
		goto out;
	}
	ret = out.ret;

out:
	up(&ce_gdma->ce_gdma_sema);
	return ret;
}

int cn_ce_gdma_memset(struct cn_gdma_super_set *gdma_set,
							struct memset_s *t)
{
	struct cn_core_set *core = gdma_set->core;
	struct ce_gdma_set *ce_gdma = gdma_set->ce_gdma;
	struct memcpy_d2d_in in = {0};
	struct memcpy_d2d_out out = {0};
	int in_len = 0;
	size_t out_len = 0;
	int ret = 0;

	in.memset_val = t->val;
	in.dst = t->dev_addr;
	in.size = t->number;
	switch (t->direction) {
	case MEMSET_D8:
		in.memd2d_type = CE_MEMSET_D8;
		break;
	case MEMSET_D16:
		in.memd2d_type = CE_MEMSET_D16;
		break;
	case MEMSET_D32:
		in.memd2d_type = CE_MEMSET_D32;
		break;
	default:
		cn_dev_core_err(core, "Error param:%d\n", t->direction);
		ret = -EINVAL;
		goto out;
	}
	in_len = sizeof(struct memcpy_d2d_in);
	out_len = sizeof(struct memcpy_d2d_out);

	if (down_killable(&ce_gdma->ce_gdma_sema)) {
		cn_dev_core_err(core, "Aborted by signal waile waiting for semaphore.\n");
		return -EINTR;
	}

	ret = __gdma_call_rpc(core, ce_gdma->gdma_submit_endpoint,
			"rpc_memcpyd2d_submit", &in, in_len,
			&out, &out_len, sizeof(out));
	if (ret < 0) {
		cn_dev_core_err(core, "memset d2d submit rpc call failed,%d", ret);
		goto out;
	}

	if (out.ret) {
		cn_dev_core_err(core, "memset d2d submit failed:%d.", out.ret);
		ret = out.ret;
		goto out;
	}

	in.task_addr = out.task_addr;
	ret = __gdma_call_rpc(core, ce_gdma->gdma_sync_endpoint,
			"rpc_memcpyd2d_sync", &in, in_len,
			&out, &out_len, sizeof(out));
	if (ret < 0) {
		cn_dev_core_err(core, "memset d2d sync rpc call failed,%d", ret);
		goto out;
	}
	ret = out.ret;

out:
	up(&ce_gdma->ce_gdma_sema);
	return ret;
}
