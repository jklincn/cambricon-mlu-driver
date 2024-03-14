/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_MMLIB_BITMAP_H_
#define __CAMBRICON_MMLIB_BITMAP_H_

int bitmap_set_ll(unsigned long *map, int start, int nr);
int bitmap_clear_ll(unsigned long *map, int start, int nr);

#endif /* __CAMBRICON_MMLIB_BITMAP_H_ */
