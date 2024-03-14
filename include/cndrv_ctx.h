/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2023 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CNDRV_CTX_H__
#define __CNDRV_CTX_H__

#include "cndrv_core.h"

/* 
 * Interface for ioctl:
 *      cn_ctx_ioctl: context ioctl entry.
 */
extern long cn_ctx_ioctl(struct cn_core_set *core, unsigned int cmd,
			unsigned long arg, struct file *fp);

#endif

