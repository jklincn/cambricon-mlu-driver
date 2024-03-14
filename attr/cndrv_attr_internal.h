/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2019 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_CNDRV_ATTR_INTERNAL_H__
#define __CAMBRICON_CNDRV_ATTR_INTERNAL_H__

#include "cndrv_core.h"

int cn_attr_init(struct cn_core_set *core);
void cn_attr_exit(struct cn_core_set *core);
void cn_attr_update_aiisp(struct cn_core_set *core, __u32 nn_num, __u32 isp_num);
void cn_attr_fill_attr(struct cn_core_set *core);
int cn_attr_init_attr_vf(struct cn_core_set *core);
void cn_attr_exit_attr_vf(struct cn_core_set *core);
long cn_attr_ioctl(struct file *fp, struct cn_core_set *core, __u32 cmd, unsigned long arg);
long cn_attr_ctl_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);
int cn_attr_get_resource(struct cn_core_set *core, u32 res_index, u64 *value);
int cn_attr_fill_resource(struct cn_core_set *core, void *resource, u32 res_len);

#endif
