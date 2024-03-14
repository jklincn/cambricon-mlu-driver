/*
 * gdma/plat/mlu590/gdma_c50.h
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

#ifndef __CNDRV_GDMA_C50_H__
#define __CNDRV_GDMA_C50_H__

#include "gdma_reg.h"

#define C50_MAIN_CSR_INDEX (0)
#define C50_TOP_CSR_INDEX (1)
#define C50_SMMU_INDEX (2)
#define C50_IRQ_INDEX (3)
#define GDMA_COMMON_RETRY_COUNT (128)
#define GDMA_COMMON_DELAY (5)
#define GDMA_MIN_DELAY (5)
#define GDMA_MAX_DELAY (100)

/***controller special reg defines***/
#define GDMA_COMMON_INTER (0x70)

int cn_gdma_plat_c50_init(void *dev, int dev_num);
int cn_gdma_plat_c50_info_probe(void *gdma_set);

#endif
