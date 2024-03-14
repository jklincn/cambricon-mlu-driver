/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#ifndef _CN_MEM_HAL_H_
#define _CN_MEM_HAL_H_

struct cn_mm_set;
void cn_mem_hal_exit(struct cn_mm_set *mm_set);
void cn_mem_hal_init(struct cn_mm_set *mm_set);
void cn_mem_hal_reinit(struct cn_mm_set *mm_set);

#endif
