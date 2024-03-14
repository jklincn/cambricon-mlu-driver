/*
 * ce_api/ce_gdma_api.h
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

#ifndef __CNDRV_CE_GDMA_API_H__
#define __CNDRV_CE_GDMA_API_H__

#include <linux/types.h>

#include "cndrv_bus.h"
#include "cndrv_gdma.h"
#include "gdma_common_api.h"

int cn_ce_gdma_memcpy(struct cn_gdma_super_set *gdma_set,
							u64 src_vaddr,
							u64 dst_vaddr,
							ssize_t size,
							int compress_type);

int cn_ce_gdma_memcpy(struct cn_gdma_super_set *gdma_set,
							u64 src_vaddr,
							u64 dst_vaddr,
							ssize_t size,
							int compress_type);

int cn_ce_gdma_memcpy_2d(struct cn_gdma_super_set *gdma_set,
						u64 src_vaddr,
						u64 dst_vaddr,
						ssize_t spitch,
						ssize_t dpitch,
						ssize_t width,
						ssize_t height);

int cn_ce_gdma_memcpy_3d(struct cn_gdma_super_set *gdma_set,
						struct memcpy_d2d_3d_compat *p);

int cn_ce_gdma_memset(struct cn_gdma_super_set *gdma_set,
							struct memset_s *t);

#endif
