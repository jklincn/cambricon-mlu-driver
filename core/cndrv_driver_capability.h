/*
 * core/cndrv_driver_capability.h
 *
 * NOTICE:
 * Copyright (C) 2021 Cambricon, Inc. All rights reserved.
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
#ifndef _CNDRV_DRIVER_CAPABILITY_H
#define _CNDRV_DRIVER_CAPABILITY_H

#include <linux/types.h>

struct cn_core_set;

/* version of capability api */
#define CAPABILITY_VERSION_1 1

/* capability list of all function of driver */
#define CAPABILITY_DEFAULT 0

#define CAPABILITY_HOSTFUNC_NOTSUPPORT CAPABILITY_DEFAULT
#define CAPABILITY_HOSTFUNC_VERSION_1 1
/* support hostfn perf */
#define CAPABILITY_HOSTFUNC_VERSION_2 2

#define CAPABILITY_QE_NOTIFIER_NOTSUPPORT CAPABILITY_DEFAULT
#define CAPABILITY_QE_NOTIFIER_SUPPORT_V1 1

#define CAPABILITY_QE_IDC_NOTSUPPORT CAPABILITY_DEFAULT
#define CAPABILITY_QE_IDC_SUPPORT_V1 1

/* reserve */
#define CAPABILITY_TASK_TOPO_VERSION_0 CAPABILITY_DEFAULT

#define CAPABILITY_SBTS_INFO_VERSION_V1 1
#define CAPABILITY_SBTS_INFO_VERSION_V2 2
#define CAPABILITY_SBTS_INFO_VERSION_V3 3

/* WARN: never change the order of struct members! 
You can only add a member at the end of struct! */
typedef struct driver_capability_st {
	u8 hostfunc_version;
	u8 queue_exception_infect_notifier_version;
	u8 queue_exception_infect_idc_version;
	u8 task_topo_version;
	u8 sbts_info_version;
	u8 reserved[3];
	u64 topo_node_bitmap_cap;
} __attribute__((__packed__)) driver_capability_list_t;

int cn_get_driver_capability(struct cn_core_set *core, void *args);
const driver_capability_list_t *get_capability(struct cn_core_set *core);

#endif
