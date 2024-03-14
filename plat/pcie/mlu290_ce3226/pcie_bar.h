/************************************************************************
 *  @file pcie_bar.h
 *
 *  @brief For pcie support definitions.
 **************************************************************************/

/*************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
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
 ***************************************************************************/

#ifndef _PCIE_BAR_H_
#define _PCIE_BAR_H_

#include <linux/semaphore.h>
#include <linux/hashtable.h>
#include "cndrv_debug.h"

enum BAR_TYPE {
	PF_BAR = 0,
	VF_BAR,
};

struct bar_resource {
	u64 phy_base;
	u64 bus_base;
	void *base;
	u64 size;
	u64 window_addr;
	u64 reg_index;
	u64 reg_mask;

	volatile int wait_count;
	int smmu_in;
	int smmu_out;
	enum BAR_TYPE type; /* 0: PF, 1: VF */
	int index; /* real bar index in PF or VF */

	struct semaphore occupy_lock;
	struct list_head list;
};

enum BAR_BLOCK_TYPE {
	BLOCK = 0,
	NOBLOCK,
};

__attribute__((unused)) static struct bar_resource *pcie_bar_resource_struct_init(struct bar_resource *bar)
{
	struct bar_resource *new;

	new = cn_kzalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL)
		return NULL;

	memcpy(new, bar, sizeof(*new));
	new->base = cn_ioremap_wc(new->phy_base, new->size);
	if (!new->base) {
		cn_kfree(new);
		cn_dev_err("cn_ioremap failed!");
		return NULL;
	}
	sema_init(&new->occupy_lock, 1);

	return new;
}

extern int mlu290_ce3226_pcie_bar_read(unsigned long host_addr, u64 device_addr, size_t count,
				struct cn_pcie_set *pcie_set);
extern int mlu290_ce3226_pcie_bar_write(unsigned long host_addr, u64 device_addr, size_t count,
				struct cn_pcie_set *pcie_set);
#endif
