/*
 * gdma/plat/mlu370/gdma_smmu.c
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

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "gdma_smmu.h"
#include "../../gdma_debug.h"

static const char *smmu_fault_info_message[FAULT_INFO_MAX] = {
	[0] = "write access hit remap win ap ro",
	[1] = "find no ttbr for this domain",
	[2] = "va bit is overflow",
	[3] = "streamtag invalid",
	[4] = "pagetable lvl 0 descriptor is valid",
	[5] = "pagetable lvl 0 is block",
	[6] = "pagetable lvl 1 descriptor is valid",
	[7] = "pagetable lvl 1 is block",
	[8] = "pagetable lvl 2 descriptor is valid",
	[9] = "pagetable lvl 3 descriptor is valid",
	[9] = "pagetable lvl 3 descriptor is not page",
	[11] = "write trans hit tlb ap is ro",
	[12] = "TLB RAM parity error",
	[13] = "PTW data cache RAM parity error",
	[14] = "PTW rresp error",
	[15] = "PTW rresp timeout",
	[16] = "PTW bresp error",
	[17] = "PTW bresp error",
	[18] = "performance count over",
	[19] = "security access forbidden",
	[20] = "PCIE 1 bit ecc error",
	[21] = "PCIE 2 bit ecc error",
};

static inline u32 smmu_read32(struct cn_gdma_controller *ctrl,
								unsigned long reg)
{
	return reg_read32(ctrl->gdma_set->core->bus_set, ctrl->smmu_base + reg);
}

static inline void smmu_write32(struct cn_gdma_controller *ctrl,
								unsigned long reg,
								u32 value)
{
	reg_write32(ctrl->gdma_set->core->bus_set, ctrl->smmu_base + reg, value);
}


static int get_error_info_index(int fault_idx)
{
	int info_index = -1;

	switch (fault_idx) {
	case 0:
		info_index = 0;
		break;
	case 1:
		info_index = 1;
		break;
	case 2:
		info_index = 2;
		break;
	case 3:
		info_index = 3;
		break;
	case 4:
	case 5:
		info_index = 4;
		break;
	case 6:
	case 7:
		info_index = 5;
		break;
	case 8:
		info_index = 6;
		break;
	case 9:
	case 10:
		info_index = 7;
		break;
	case 11:
		info_index = 8;
		break;
	case 12:
		info_index = 9;
		break;
	case 13:
		info_index = 10;
		break;
	case 14:
	case 15:
		info_index = 11;
		break;
	case 16:
	case 17:
		info_index = 12;
		break;
	case 18:
		info_index = 13;
		break;
	case 19:
		info_index = 14;
		break;
	}

	return info_index;
}

int smmu370_get_fault(struct cn_gdma_controller *ctrl, unsigned int *fsr)
{
	/* NOTE: It will be called in irq cntext. */
	*fsr = smmu_read32(ctrl, SMMU_CR_FAULT_SATUS_REG);
	return GDMA_SUCCESS;
}

void smmu370_dumpreg(struct cn_gdma_controller *ctrl)
{
	/* NOTE: It will be called in irq cntext. */
	u32 regval = 0, regval_mask = 0, fault_val;
	int i = 0, index;

	regval = smmu_read32(ctrl, SMMU_CR_FAULT_SATUS_REG);
	regval_mask = smmu_read32(ctrl, SMMU_CR_FAULT_MASK_STATUS_REG);
	if (regval & regval_mask) {
		cn_dev_gdma_info(ctrl->gdma_set, "smmu_fault status_reg = %x\n",
				regval & regval_mask);
#define bitmap_for_next(pos, bit_list)	\
	for (pos = __ffs(bit_list); (bit_list) > 0; \
		(bit_list) &= ~(1 << pos), pos = __ffs(bit_list))
		fault_val = regval & regval_mask;
		bitmap_for_next(i, fault_val) {
			index = get_error_info_index(i);
			cn_dev_gdma_debug(ctrl->gdma_set,
					"smmu fault index %x info reg [%d] message [%s]\n",
					i, index,
					(smmu_fault_info_message[i] == NULL) ?
						"undefined" : smmu_fault_info_message[i]);
			regval = smmu_read32(ctrl, SMMU_CR_FAULT_INFO_L_REG(index));
			cn_dev_gdma_debug(ctrl->gdma_set,
				"smmu_fault reg num %d INFO_L_REG = %x\n", index, regval);
			regval = smmu_read32(ctrl, SMMU_CR_FAULT_INFO_H_REG(index));
			cn_dev_gdma_debug(ctrl->gdma_set,
				"smmu_fault reg num %d INFO_H_REG = %x\n", index, regval);
		}
	}
}

int smmu370_clear_fault(struct cn_gdma_controller *ctrl, unsigned int fsr)
{
	/* NOTE: It will be called in irq cntext. */
	cn_dev_gdma_debug(ctrl->gdma_set,
			"func %s ctrl %d smmu\n", __func__, ctrl->idx);
	smmu_write32(ctrl, SMMU_CR_FAULT_CLEAR_REG, fsr);

	return GDMA_SUCCESS;
}
