/*
 * gdma/gdma_api.h
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

#ifndef __CNDRV_GDMA_API_H__
#define __CNDRV_GDMA_API_H__

#include <linux/types.h>

#include "cndrv_bus.h"
#include "cndrv_gdma.h"
#include "gdma_common_api.h"

enum cn_gmda_request_type {
	GDMA_MEMCPY = 0,
	GDMA_MEMSET_D8,
	GDMA_MEMSET_D16,
	GDMA_MEMSET_D32,
	GDMA_MEMSET_D64,
	GDMA_MEMCPY_2D,
	GDMA_MEMCPY_3D,
	GDMA_MAX_TRANSFER,
};

struct cn_gdma_transfer {
	u64 src;
	u64 dst;
	u64 len;
	u64 memset_value;
	u32 type;
	int compress_type;

	//d2d 2d params
	struct memcpy_d2d_2d d2d_2d;
	//d2d 3d params
	struct memcpy_d2d_3d_compat d2d_3d;
};

enum cn_gdma_result {
	GDMA_SUCCESS = 0,
	GDMA_ERROR,
	GDMA_UNSUPPORT,
	GDMA_CONTINUE,
	GDMA_NORESOURCE,
};

#ifdef CONFIG_CNDRV_HOST_GDMA
int cn_host_gdma_init(struct cn_gdma_super_set *gdma_set);
int cn_host_gdma_exit(struct cn_gdma_super_set *gdma_set);
int cn_host_gdma_rpc_init(struct cn_gdma_super_set *gdma_set);
void cn_host_gdma_rpc_exit(struct cn_gdma_super_set *gdma_set);
int cn_host_gdma_memcpy(struct cn_gdma_super_set *gdma_set, u64 src_vaddr,
					u64 dst_vaddr, ssize_t size, int comnpress_type);
int cn_host_gdma_memset(struct cn_gdma_super_set *gdma_set,
					struct memset_s *t);
int cn_host_gdma_memcpy_2d(struct cn_gdma_super_set *gdma_set,
					u64 src_vaddr,
					u64 dst_vaddr,
					ssize_t spitch,
					ssize_t dpitch,
					ssize_t width,
					ssize_t height);
int cn_host_gdma_memcpy_3d(struct cn_gdma_super_set *gdma_set,
					struct memcpy_d2d_3d_compat *p);

#else
static inline int cn_host_gdma_init(struct cn_gdma_super_set *gdma_set)
{
	return 0;
}

static inline int cn_host_gdma_exit(struct cn_gdma_super_set *gdma_set)
{
	return 0;
}

static inline int cn_host_gdma_rpc_init(struct cn_gdma_super_set *gdma_set)
{
	return 0;
}

static inline void cn_host_gdma_rpc_exit(struct cn_gdma_super_set *gdma_set)
{
	return;
}

static inline int cn_host_gdma_memcpy(struct cn_gdma_super_set *gdma_set, u64 src_vaddr,
			u64 dst_vaddr, ssize_t size, int compress_type)
{
	return -EINVAL;
}

static inline int cn_host_gdma_memset(struct cn_gdma_super_set *gdma_set, struct memset_s *t)
{
	return -EINVAL;
}

static inline int cn_host_gdma_memcpy_2d(struct cn_gdma_super_set *gdma_set,
					u64 src_vaddr,
					u64 dst_vaddr,
					ssize_t spitch,
					ssize_t dpitch,
					ssize_t width,
					ssize_t height)
{
	return -EINVAL;
}

static inline int cn_host_gdma_memcpy_3d(struct cn_gdma_super_set *gdma_set,
					struct memcpy_d2d_3d_compat *p)
{
	return -EINVAL;
}
#endif

#endif
