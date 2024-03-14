/*
 * gdma/plat/mlu370/gdma_smmu.h
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

#ifndef __CNDRV_GDMA_SMMU_H__
#define __CNDRV_GDMA_SMMU_H__

#include "../../gdma_common.h"

/*smmu register*/
#define SMMU_CR_FAULT_SATUS_REG (0x404)
#define SMMU_CR_FAULT_INFO0_L_REG (0x410)
#define SMMU_CR_FAULT_INFO0_H_REG (0x414)
#define SMMU_CR_FAULT_INFO_L_REG(n) ((SMMU_CR_FAULT_INFO0_L_REG) + ((n) * 0x08))
#define SMMU_CR_FAULT_INFO_H_REG(n) ((SMMU_CR_FAULT_INFO0_H_REG) + ((n) * 0x08))
#define SMMU_CR_FAULT_MASK_REG (0x400)
#define SMMU_CR_FAULT_SATUS_REG (0x404)
#define SMMU_CR_FAULT_MASK_STATUS_REG (0x408)
#define SMMU_CR_FAULT_CLEAR_REG (0x40c)

#define SMMU_INV_BITS_L (0x20)
#define SMMU_INV_BITS_H (0x10)
#define SMMU_INV_MASK_L (SMMU_INV_BITS_L - 1)
#define SMMU_INV_MASK_H (SMMU_INV_BITS_H - 1)
#define FAULT_INFO_MAX (25)

int smmu370_get_fault(struct cn_gdma_controller *ctrl, unsigned int *fsr);
void smmu370_dumpreg(struct cn_gdma_controller *ctrl);
int smmu370_clear_fault(struct cn_gdma_controller *ctrl, unsigned int fsr);

#endif
