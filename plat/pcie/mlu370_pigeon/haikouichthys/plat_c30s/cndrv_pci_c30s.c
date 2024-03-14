/************************************************************************
 *
 *  @file cndrv_pci_c30s.c
 *
 *  @brief This file is designed to support pcie functions.
 * ######################################################################
 *
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 *
 **************************************************************************/

/*************************************************************************
 * Software License Agreement:
 * -----------------------------------------------------------------------
 * Copyright (C) [2018] by Cambricon, Inc.
 * This code is licensed under MIT license (see below for details)
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *************************************************************************/
/************************************************************************
 *  Include files
 ************************************************************************/
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/dmi.h>
#include <linux/aer.h>
#include <linux/platform_device.h>
#include <linux/vmalloc.h>
#include <linux/jiffies.h>
#include <linux/delay.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "../../pcie_dma.h"
#include "../../pcie_bar.h"
#include "../../cndrv_pci.h"
#include "cndrv_mm.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_pci_c30s.h"
#include "cndrv_debug.h"

#define DMA_SMMU_STREAM_ID      37

#if (GIC_INTERRUPT_NUM != MSIX_COUNT)
const static int irq_msix_gic_end[16] = {
	0, 1, 2, 3, 4, 5, 6, 7, 37, 117,
	145, 185, 189, 200, 510, 511};
#endif

#if (MSI_COUNT == 1)
const static int irq_msi_gic_end[1] = {511};
#elif (MSI_COUNT == 2)
const static int irq_msi_gic_end[2] = {255, 511};
#elif (MSI_COUNT == 4)
const static int irq_msi_gic_end[4] = {127, 255, 383, 511};
#elif (MSI_COUNT == 8)
const static int irq_msi_gic_end[8] = {63, 127, 191, 255, 319, 383, 447, 511};
#elif (MSI_COUNT == 16)
const static int irq_msi_gic_end[16] = {
	32, 63, 95, 127, 159, 191, 223, 239, 255,
	287, 319, 351, 383, 415, 447, 479, 511};
#elif (MSI_COUNT == 32)
const static int irq_msi_gic_end[32] = {
	15,   31,  47,  63,  79,  95, 111,  127,
	143, 159, 175, 191, 207, 223, 239, 255,
	271, 287, 303, 319, 335, 351, 367, 383,
	399, 415, 431, 447, 463, 479, 495, 511};
#endif

static struct cn_pci_irq_str_index irq_str_index[GIC_INTERRUPT_NUM] = {
	{0, "pcie_dma0"},
	{1, "pcie_dma1"},
	{2, "pcie_dma2"},
	{3, "pcie_dma3"},
	{4, "pcie_dma4"},
	{5, "pcie_dma5"},
	{6, "pcie_dma6"},
	{7, "pcie_dma7"},
	{135, "gdma0"},
	{133, "gdma1"},
	{330, "gdma2"},
	{328, "gdma3"},
};

const static int dma_workaround_unpack_num[8] = {1, 2, 2, 3, 2, 3, 3, 4};

static int c30s_bug_fix_list(struct cn_pcie_set *pcie_set);
/*
 *  include public c code
 *  warnning: do not remove it to the top of file
 *            otherwise will have build errors
 */
#include "../../pcie_common.c"
#include "../haikouichthys.h"
#define OVER_WRITE(f) c30s_##f

__attribute__((unused))
static void pcie_async_show_desc_list(struct async_task *async_task)
{
	void __iomem *host_desc_addr = (void __iomem *)async_task->host_desc_addr;
	int i, desc_offset = 0;

	for (i = 0; i < (async_task->desc_len / DESC_SIZE); i++) {
		cn_dev_pcie_err(async_task->pcie_set,
			"[%d]%#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x", i,
				ioread32(host_desc_addr + desc_offset + 0),
				ioread32(host_desc_addr + desc_offset + 4),
				ioread32(host_desc_addr + desc_offset + 8),
				ioread32(host_desc_addr + desc_offset + 12),
				ioread32(host_desc_addr + desc_offset + 16),
				ioread32(host_desc_addr + desc_offset + 20),
				ioread32(host_desc_addr + desc_offset + 24),
				ioread32(host_desc_addr + desc_offset + 28));
		desc_offset += DESC_SIZE;
	}

	if ((async_task->async_info->direction == DMA_D2H) ||
			(async_task->async_info->direction == DMA_P2P)) {
		desc_offset = (async_task->desc_len % 64) ?
			(async_task->desc_len + 64 - (async_task->desc_len % 64)) :
			async_task->desc_len;
		cn_dev_pcie_err(async_task->pcie_set,
				"[flush]%#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x",
				ioread32(host_desc_addr + desc_offset + 0),
				ioread32(host_desc_addr + desc_offset + 4),
				ioread32(host_desc_addr + desc_offset + 8),
				ioread32(host_desc_addr + desc_offset + 12),
				ioread32(host_desc_addr + desc_offset + 16),
				ioread32(host_desc_addr + desc_offset + 20),
				ioread32(host_desc_addr + desc_offset + 24),
				ioread32(host_desc_addr + desc_offset + 28));
	}
}

static int OVER_WRITE(get_desc_unpack_num)(u64 ipu_addr, unsigned long cpu_addr)
{
	int tail_offset;
	tail_offset = (ipu_addr + (PAGE_SIZE - (cpu_addr % PAGE_SIZE))) % 512;

	return dma_workaround_unpack_num[tail_offset / 64];
}

/*
 * DRIVER-10027 workaround
 * desc_tail = (ipu_addr + count) % 512
 * desc_align = ipu_addr + count - desc_tail
 * case desc_tail range
 * [0B,64B]:no need unpack
 * (64B,128B]:split into 2 package {ipu_addr~desc_align + 64, remain}
 * (128B,192B]:split into 2 package {ipu_addr~desc_align + 128, remain}
 * (192B,256B]:split into 3 package {ipu_addr~desc_align + 128, 64, remain}
 * (256B,320B]:split into 2 package {ipu_addr~desc_align + 256, remain}
 * (320B,384B]:split into 3 package {ipu_addr~desc_align + 256, 64, remain}
 * (384B,448B]:split into 3 package {ipu_addr~desc_align + 256, 128, remain}
 * (448B,512B):split into 4 package {ipu_addr~desc_align + 256, 128, 64, remain}
 */
static int workaround_fill_desc(struct cn_pcie_set *pcie_set,
		DMA_DIR_TYPE direction, u64 desc_device_va, void *desc_host_buf,
		u64 ipu_ram_dma_addr, unsigned long cpu_dma_addr, unsigned long count,
		int *desc_number, int *desc_offset, int last_desc_flag)
{
	unsigned int ctrl, ndl, ndu;
	unsigned long trans_count;
	unsigned long trans_cpu_addr;
	u64 trans_ipu_addr;
	int trans_align = 512;
	int desc_tail;

	switch (direction) {
	case DMA_H2D:
		ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(count) << 8));
		if (last_desc_flag) {
			ndl = 0x3;
			ndu = 0x0;
		} else {
			ndl = NEXT_DESC_LOWER32(desc_device_va,
							*desc_number) | 0x12;
			ndu = NEXT_DESC_UPPER32(desc_device_va,
							*desc_number);
		}
		FILL_DESC(desc_host_buf, ctrl, ndl, ndu,
				cpu_dma_addr, ipu_ram_dma_addr, *desc_offset);
		*desc_offset += DESC_SIZE;
		(*desc_number)++;
		break;
	case DMA_P2P:
	case DMA_D2H:
		trans_ipu_addr = ipu_ram_dma_addr;
		trans_cpu_addr = cpu_dma_addr;
		while (count) {
			desc_tail = (trans_ipu_addr + count) % trans_align;
			trans_align = trans_align / 2;
			if (trans_align <= 32) {
				trans_count = count;
			} else {
				if (desc_tail >= trans_align) {
					if (count > desc_tail % trans_align) {
						/* |-----s---------trans_align----------e------| */
						trans_count = count - desc_tail % trans_align;
					} else {
						/* |---------------trans_align------s---e------| */
						continue;
					}
				} else {
					/* |-----s-----e---trans_align-----------------| */
					continue;
				}
			}

			ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(trans_count) << 8));
			if (last_desc_flag && (trans_count == count)) {
				ndl = 0x3;
				ndu = 0x0;
			} else {
				ndl = NEXT_DESC_LOWER32(desc_device_va,
								*desc_number) | 0x12;
				ndu = NEXT_DESC_UPPER32(desc_device_va,
								*desc_number);
			}
			cn_dev_pcie_debug(pcie_set,
					"ipu_addr:%#llx cpu_addr:%#lx trans_count:%#lx tail:%d",
					trans_ipu_addr, trans_cpu_addr, trans_count,
					(int)((trans_ipu_addr + trans_count) % (trans_align * 2)));
			FILL_DESC(desc_host_buf, ctrl, ndl, ndu,
					trans_ipu_addr, trans_cpu_addr, *desc_offset);

			*desc_offset += DESC_SIZE;
			(*desc_number)++;
			count -= trans_count;
			trans_ipu_addr += trans_count;
			trans_cpu_addr += trans_count;
		}
		break;

	default:
		cn_dev_pcie_err(pcie_set,
				"only DMA_H2D or DMA_D2H or DMA_P2P transfer mode");
		return -1;
	}
	return 0;
}

static int OVER_WRITE(pcie_fill_desc_list)(struct dma_channel_info *channel)
{
	int i;
	unsigned long cpu_dma_addr = 0;
	u64 ipu_ram_dma_addr;
	unsigned long count = 0;
	struct scatterlist *sg;
	int desc_offset = 0;
	int desc_number = 0;
	unsigned long cpu_addr_cur;
	unsigned long count_cur;
	unsigned long des_page_len = 0;
	int scatter_num = 0;
	int des_end_flag = 0;
	unsigned long trans_count = 0;
	ipu_ram_dma_addr = channel->ram_addr;

	/* enable descripter debug */
	if (channel->pcie_set->des_set > 0) {
		des_page_len = channel->pcie_set->des_set * PAGE_SIZE;
		cn_dev_pcie_debug(channel->pcie_set,
				"descripter scatter size 0x%lx, nents %d", des_page_len,  channel->nents);
	}
	if (channel->desc_device_va % 64) {
		cn_dev_pcie_err(channel->pcie_set,
				"No 64 Bytes align : desc device vaddr");
		return -1;
	}

	if ((channel->direction != DMA_P2P) ||
			(channel->task->p2p_trans_type != P2P_TRANS_BUS_ADDRESS)) {
		if (des_page_len) {
			for_each_sg(channel->sg, sg, channel->nents, i) {
				cpu_dma_addr = sg_dma_address(sg);
				count = sg_dma_len(sg);

				while (count) {
					trans_count = min(count, des_page_len);
					if ((trans_count == count) && (i == (channel->nents - 1))) {
						des_end_flag = 1;
					} else {
						des_end_flag = 0;
					}
					workaround_fill_desc(channel->pcie_set, channel->direction,
							channel->desc_device_va, channel->task->desc_buf,
							ipu_ram_dma_addr, cpu_dma_addr, trans_count,
							&desc_number, &desc_offset, des_end_flag);
					cpu_dma_addr += trans_count;
					ipu_ram_dma_addr += trans_count;
					count -= trans_count;
					scatter_num++;
				}

				cn_dev_pcie_debug(channel->pcie_set,
					"descripter scatter num %d", scatter_num);
			}
		} else {
			for_each_sg(channel->sg, sg, channel->nents, i) {
				cpu_addr_cur = sg_dma_address(sg);
				count_cur = sg_dma_len(sg);

				if (!i)
					cpu_dma_addr = cpu_addr_cur;

				if (cpu_dma_addr + count == cpu_addr_cur)
					count += count_cur;
				else {

					workaround_fill_desc(channel->pcie_set, channel->direction,
							channel->desc_device_va, channel->task->desc_buf,
							ipu_ram_dma_addr, cpu_dma_addr, count,
							&desc_number, &desc_offset, 0);
					ipu_ram_dma_addr += count;
					cpu_dma_addr = cpu_addr_cur;
					count = count_cur;
				}
			}
			workaround_fill_desc(channel->pcie_set, channel->direction,
					channel->desc_device_va, channel->task->desc_buf,
					ipu_ram_dma_addr, cpu_dma_addr, count,
					&desc_number, &desc_offset, 1);
		}
	} else {
		cpu_dma_addr = channel->cpu_addr;
		count = channel->transfer_length;
		workaround_fill_desc(channel->pcie_set, channel->direction,
				channel->desc_device_va, channel->task->desc_buf,
				ipu_ram_dma_addr, cpu_dma_addr, count,
				&desc_number, &desc_offset, 1);
	}

	channel->desc_len = desc_offset;
	memcpy_toio(channel->desc_virt_base, channel->task->desc_buf, desc_offset);
	//pcie_show_desc_list(channel);
	return 0;
}

static int c30s_async_dma_fill_flush_desc_list(struct async_task *async_task)
{
	unsigned long cpu_dma_addr;
	u64 ipu_ram_dma_addr;
	unsigned long count;
	unsigned int ctrl, ndl, ndu;
	unsigned int desc_size;
	unsigned int desc_offset;

	switch (async_task->async_info->direction) {
	case DMA_H2D:
		return 0;
	case DMA_D2H:
		ipu_ram_dma_addr = async_task->transfer.ia;
		break;
	case DMA_P2P:
		ipu_ram_dma_addr = async_task->peer.src_addr;
		break;
	default:
		cn_dev_pcie_err(async_task->pcie_set,
				"only DMA_H2D or DMA_D2H or DMA_P2P transfer mode");
		return -1;
	}
	cpu_dma_addr = sg_dma_address(async_task->sg_list);
	count = 0x1;

	ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(count) << 8));
	ndl = 0x3;
	ndu = 0x0;
	desc_size = DESC_SIZE;
	/* Hardware Limit: desc addr 64 Bytes align */
	desc_offset = (async_task->desc_len % 64) ?
		(async_task->desc_len + 64 - (async_task->desc_len % 64)) : async_task->desc_len;
	FILL_DESC(async_task->desc_buf, ctrl, ndl, ndu,
		cpu_dma_addr, ipu_ram_dma_addr, desc_offset);

	memcpy_toio((void __iomem *)(async_task->host_desc_addr + desc_offset),
		async_task->desc_buf + desc_offset, desc_size);

	return 0;
}

static int OVER_WRITE(async_dma_fill_desc_list)(struct async_task *async_task)
{
	int i;
	unsigned long cpu_dma_addr = 0;
	u64 ipu_ram_dma_addr;
	struct scatterlist *sg;
	int desc_offset = 0;
	int desc_number = 0;
	unsigned long desc_max_len = 0;
	int des_end_flag = 0;
	unsigned long count = 0;
	unsigned long trans_count = 0;

	desc_max_len = async_task->pcie_set->per_desc_max_size;

	if (async_task->dma_type != PCIE_DMA_P2P) {
		ipu_ram_dma_addr = async_task->transfer.ia;
	} else {
		/* push mode */
		ipu_ram_dma_addr = async_task->peer.src_addr;
	}

	for_each_sg(async_task->sg_list, sg, async_task->nents, i) {
		cpu_dma_addr = sg_dma_address(sg);
		count = sg_dma_len(sg);

		while (count) {
			trans_count = min(count, desc_max_len);
			if ((trans_count == count) && (i == (async_task->nents - 1))) {
				des_end_flag = 1;
			} else {
				des_end_flag = 0;
			}
			workaround_fill_desc(async_task->pcie_set,
					async_task->async_info->direction,
					async_task->dev_desc_addr, async_task->desc_buf,
					ipu_ram_dma_addr, cpu_dma_addr, trans_count,
					&desc_number, &desc_offset, des_end_flag);
			cpu_dma_addr += trans_count;
			ipu_ram_dma_addr += trans_count;
			count -= trans_count;
		}
	}

	async_task->desc_len = desc_offset;
	memcpy_toio((void __iomem *)async_task->host_desc_addr, async_task->desc_buf, desc_offset);

	c30s_async_dma_fill_flush_desc_list(async_task);
	//pcie_async_show_desc_list(async_task);

	return 0;
}

/*
 * The table is used for debug regs dump, very important for us
 * WARNING: different platform have different reg base,
 * we need check every regs carefully with hardware enginer, do not just copy
 */
static struct pcie_dump_reg_s c30s_reg[] = {
		{"PCIE DMA int status", DI_BASE + 0x4},
		{"PCIE ltssm status", LTSSM},
		{"PCIE DMA chn0 ctrl", DBO},
		{NULL, DBO + 0x4}, {NULL, DBO + 0x8},
		{NULL, DBO + 0xC}, {NULL, DBO + 0x10},
		{NULL, DBO + 0x14}, {NULL, DBO + 0x18},
		{NULL, DBO + 0x1C}, {NULL, DBO + 0x20},
		{NULL, DBO + 0x24}, {NULL, DBO + 0x28},

		{"PCIE DMA chn1 ctrl", DBO + 0x40},
		{NULL, DBO + 0x40 + 0x4}, {NULL, DBO + 0x40 + 0x8},
		{NULL, DBO + 0x40 + 0xC}, {NULL, DBO + 0x40 + 0x10},
		{NULL, DBO + 0x40 + 0x14}, {NULL, DBO + 0x40 + 0x18},
		{NULL, DBO + 0x40 + 0x1C}, {NULL, DBO + 0x40 + 0x20},
		{NULL, DBO + 0x40 + 0x24}, {NULL, DBO + 0x40 + 0x28},

		{"PCIE DMA chn2 ctrl", DBO + 0x80},
		{NULL, DBO + 0x80 + 0x4}, {NULL, DBO + 0x80 + 0x8},
		{NULL, DBO + 0x80 + 0xC}, {NULL, DBO + 0x80 + 0x10},
		{NULL, DBO + 0x80 + 0x14}, {NULL, DBO + 0x80 + 0x18},
		{NULL, DBO + 0x80 + 0x1C}, {NULL, DBO + 0x80 + 0x20},
		{NULL, DBO + 0x80 + 0x24}, {NULL, DBO + 0x80 + 0x28},

		{"PCIE DMA chn3 ctrl", DBO + 0xC0},
		{NULL, DBO + 0xC0 + 0x4}, {NULL, DBO + 0xC0 + 0x8},
		{NULL, DBO + 0xC0 + 0xC}, {NULL, DBO + 0xC0 + 0x10},
		{NULL, DBO + 0xC0 + 0x14}, {NULL, DBO + 0xC0 + 0x18},
		{NULL, DBO + 0xC0 + 0x1C}, {NULL, DBO + 0xC0 + 0x20},
		{NULL, DBO + 0xC0 + 0x24}, {NULL, DBO + 0xC0 + 0x28},

		{"PCIE DMA chn4 ctrl", DBO + 0x100},
		{NULL, DBO + 0x100 + 0x4}, {NULL, DBO + 0x100 + 0x8},
		{NULL, DBO + 0x100 + 0xC}, {NULL, DBO + 0x100 + 0x10},
		{NULL, DBO + 0x100 + 0x14}, {NULL, DBO + 0x100 + 0x18},
		{NULL, DBO + 0x100 + 0x1C}, {NULL, DBO + 0x100 + 0x20},
		{NULL, DBO + 0x100 + 0x24}, {NULL, DBO + 0x100 + 0x28},

		{"PCIE DMA chn5 ctrl", DBO + 0x140},
		{NULL, DBO + 0x140 + 0x4}, {NULL, DBO + 0x140 + 0x8},
		{NULL, DBO + 0x140 + 0xC}, {NULL, DBO + 0x140 + 0x10},
		{NULL, DBO + 0x140 + 0x14}, {NULL, DBO + 0x140 + 0x18},
		{NULL, DBO + 0x140 + 0x1C}, {NULL, DBO + 0x140 + 0x20},
		{NULL, DBO + 0x140 + 0x24}, {NULL, DBO + 0x140 + 0x28},

		{"PCIE DMA chn6 ctrl", DBO + 0x180},
		{NULL, DBO + 0x180 + 0x4}, {NULL, DBO + 0x180 + 0x8},
		{NULL, DBO + 0x180 + 0xC}, {NULL, DBO + 0x180 + 0x10},
		{NULL, DBO + 0x180 + 0x14}, {NULL, DBO + 0x180 + 0x18},
		{NULL, DBO + 0x180 + 0x1C}, {NULL, DBO + 0x180 + 0x20},
		{NULL, DBO + 0x180 + 0x24}, {NULL, DBO + 0x180 + 0x28},

		{"PCIE DMA chn7 ctrl", DBO + 0x1C0},
		{NULL, DBO + 0x1C0 + 0x4}, {NULL, DBO + 0x1C0 + 0x8},
		{NULL, DBO + 0x1C0 + 0xC}, {NULL, DBO + 0x1C0 + 0x10},
		{NULL, DBO + 0x1C0 + 0x14}, {NULL, DBO + 0x1C0 + 0x18},
		{NULL, DBO + 0x1C0 + 0x1C}, {NULL, DBO + 0x1C0 + 0x20},
		{NULL, DBO + 0x1C0 + 0x24}, {NULL, DBO + 0x1C0 + 0x28},

		{"PCIE IRQ MASK", PCIE_IRQ_MASK(0)}, {NULL, PCIE_IRQ_MASK(1)},
		{NULL, PCIE_IRQ_MASK(2)}, {NULL, PCIE_IRQ_MASK(3)},
		{NULL, PCIE_IRQ_MASK(4)}, {NULL, PCIE_IRQ_MASK(5)},
		{NULL, PCIE_IRQ_MASK(6)}, {NULL, PCIE_IRQ_MASK(7)},
		{NULL, PCIE_IRQ_MASK(8)}, {NULL, PCIE_IRQ_MASK(9)},
		{NULL, PCIE_IRQ_MASK(10)}, {NULL, PCIE_IRQ_MASK(11)},
		{NULL, PCIE_IRQ_MASK(12)}, {NULL, PCIE_IRQ_MASK(13)},
		{NULL, PCIE_IRQ_MASK(14)}, {NULL, PCIE_IRQ_MASK(15)},
		{NULL, PCIE_IRQ_MASK(16)}, {NULL, PCIE_IRQ_MASK(17)},
		{NULL, PCIE_IRQ_MASK(18)}, {NULL, PCIE_IRQ_MASK(19)},
		{NULL, PCIE_IRQ_MASK(20)}, {NULL, PCIE_IRQ_MASK(21)},
		{NULL, PCIE_IRQ_MASK(22)}, {NULL, PCIE_IRQ_MASK(23)},

		{"PCIE IRQ STATUS", PCIE_IRQ_STATUS(0)}, {NULL, PCIE_IRQ_STATUS(1)},
		{NULL, PCIE_IRQ_STATUS(2)}, {NULL, PCIE_IRQ_STATUS(3)},
		{NULL, PCIE_IRQ_STATUS(4)}, {NULL, PCIE_IRQ_STATUS(5)},
		{NULL, PCIE_IRQ_STATUS(6)}, {NULL, PCIE_IRQ_STATUS(7)},
		{NULL, PCIE_IRQ_STATUS(8)}, {NULL, PCIE_IRQ_STATUS(9)},
		{NULL, PCIE_IRQ_STATUS(10)}, {NULL, PCIE_IRQ_STATUS(11)},
		{NULL, PCIE_IRQ_STATUS(12)}, {NULL, PCIE_IRQ_STATUS(13)},
		{NULL, PCIE_IRQ_STATUS(14)}, {NULL, PCIE_IRQ_STATUS(15)},
		{NULL, PCIE_IRQ_STATUS(16)}, {NULL, PCIE_IRQ_STATUS(17)},
		{NULL, PCIE_IRQ_STATUS(18)}, {NULL, PCIE_IRQ_STATUS(19)},
		{NULL, PCIE_IRQ_STATUS(20)}, {NULL, PCIE_IRQ_STATUS(21)},
		{NULL, PCIE_IRQ_STATUS(22)}, {NULL, PCIE_IRQ_STATUS(23)},

		{"PCIE GIC mask", GIC_MASK},
		{NULL, GIC_MASK + 4}, { NULL, GIC_MASK + 8},
		{NULL, GIC_MASK + 12}, {NULL, GIC_MASK + 16},
		{NULL, GIC_MASK + 20}, {NULL, GIC_MASK + 24},
		{NULL, GIC_MASK + 28}, {NULL, GIC_MASK + 32},
		{NULL, GIC_MASK + 36}, {NULL, GIC_MASK + 40},
		{NULL, GIC_MASK + 44}, {NULL, GIC_MASK + 48},
		{NULL, GIC_MASK + 52}, {NULL, GIC_MASK + 56},
		{NULL, GIC_MASK + 60},

		{"PCIE GIC status", GIC_STATUS},
		{NULL, GIC_STATUS + 4}, {NULL, GIC_STATUS + 8},
		{NULL, GIC_STATUS + 12}, {NULL, GIC_STATUS + 16},
		{NULL, GIC_STATUS + 20}, {NULL, GIC_STATUS + 24},
		{NULL, GIC_STATUS + 28}, {NULL, GIC_STATUS + 32},
		{NULL, GIC_STATUS + 36}, {NULL, GIC_STATUS + 40},
		{NULL, GIC_STATUS + 44}, {NULL, GIC_STATUS + 48},
		{NULL, GIC_STATUS + 52}, {NULL, GIC_STATUS + 56},
		{NULL, GIC_STATUS + 60},

		{"PCIE GIC MSIX VECTOR count", GIC_MSIX_VECTOR_COUNT},
		{"PCIE MSIX clear register", GIC_MSIX_PEND_CLR},
		{NULL, GIC_MSIX_PEND_CLR + 4}, {NULL, GIC_MSIX_PEND_CLR + 8},
		{NULL, GIC_MSIX_PEND_CLR + 12}, {NULL, GIC_MSIX_PEND_CLR + 16},
		{NULL, GIC_MSIX_PEND_CLR + 20}, {NULL, GIC_MSIX_PEND_CLR + 24},
		{NULL, GIC_MSIX_PEND_CLR + 28}, {NULL, GIC_MSIX_PEND_CLR + 32},
		{NULL, GIC_MSIX_PEND_CLR + 36}, {NULL, GIC_MSIX_PEND_CLR + 40},
		{NULL, GIC_MSIX_PEND_CLR + 44}, {NULL, GIC_MSIX_PEND_CLR + 48},
		{NULL, GIC_MSIX_PEND_CLR + 52}, {NULL, GIC_MSIX_PEND_CLR + 56},
		{NULL, GIC_MSIX_PEND_CLR + 60},

		{"PCIE GIC_CTRL", GIC_CTRL},

		{"PCIE FETCH STATUS", DMA_STATUS_FETCH(0)},
		{NULL, DMA_STATUS_FETCH(1)},
		{NULL, DMA_STATUS_FETCH(2)},
		{NULL, DMA_STATUS_FETCH(3)},
		{NULL, DMA_STATUS_FETCH(4)},
		{NULL, DMA_STATUS_FETCH(5)},
		{NULL, DMA_STATUS_FETCH(6)},
		{NULL, DMA_STATUS_FETCH(7)},
		{"PCIE DESC FETCH SM DBG", DMA_DESC_DBG_SM_FETCH(0)},
		{"NULL", DMA_DESC_DBG_SM_FETCH(1)},
		{"NULL", DMA_DESC_DBG_SM_FETCH(2)},
		{"NULL", DMA_DESC_DBG_SM_FETCH(3)},
		{"NULL", DMA_DESC_DBG_SM_FETCH(4)},
		{"NULL", DMA_DESC_DBG_SM_FETCH(5)},
		{"NULL", DMA_DESC_DBG_SM_FETCH(6)},
		{"NULL", DMA_DESC_DBG_SM_FETCH(7)},
};

static void OVER_WRITE(pcie_dump_reg)(struct cn_pcie_set *pcie_set)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(c30s_reg); i++) {
		if (c30s_reg[i].desc)
			cn_dev_pcie_err(pcie_set, "%s:", c30s_reg[i].desc);

		cn_dev_pcie_info(pcie_set, "[0x%lx]=%#08x", c30s_reg[i].reg,
		cn_pci_reg_read32(pcie_set, c30s_reg[i].reg));
	}
}

static int OVER_WRITE(pcie_enable_vf_bar)(struct cn_pcie_set *pcie_set)
{
	return 0;
}

static void OVER_WRITE(pcie_disable_vf_bar)(struct cn_pcie_set *pcie_set)
{

}

static u64 OVER_WRITE(pcie_set_bar_window)(u64 axi_address,
		struct bar_resource *resource, struct cn_pcie_set *pcie_set)
{
	u64 addr;

	addr = resource->window_addr;
	if (axi_address >= addr && axi_address < (addr + resource->size))
		return addr;

	axi_address &= (~((u64)(resource->size - 1)));
	/* bar base 1MB align*/
	cn_pci_reg_write32(pcie_set, PF_BAR_ADDR_BASE(resource->index),
			(u32)(axi_address >> ilog2(BAR_BASE_SIZE)));
	cn_pci_reg_read32(pcie_set, PF_BAR_ADDR_BASE(resource->index));

	resource->window_addr = axi_address;

	return axi_address;
}

static int pcie_set_bar0_window(u64 axi_addr, unsigned long *offset,
						struct cn_pcie_set *pcie_set)
{
	int quadrant;
	int level0;
	int level1;
	u32 bar0_level1_base;
	u32 bar0_level1_size;
	int win_base;
	struct c30s_bar0_set *bar0_set = NULL;

	bar0_set = (struct c30s_bar0_set *)pcie_set->priv_set;
	*offset = axi_addr & BAR0_MASK;
	quadrant = *offset / QUADRANT_SIZE;
	/*
	 * Here a 4 quadrant at most.
	 */
	quadrant %= 4;

	level0 = (*offset & (QUADRANT_MASK)) / C30S_BAR0_LEVEL0_4M;

	if (level0) {
		/* 4win 0x80010 + (0x10)/bar0_mode - 3win 0x80010 base=1MB*/
		bar0_level1_base = bar0_set->bar0_window_base;
		bar0_level1_size = bar0_level1_base << ilog2(BAR_BASE_SIZE);
		level1 = (*offset & QUADRANT_MASK) / bar0_level1_size;
		win_base = cn_pci_reg_read32(pcie_set,
				BAR0_TO_AXI_TGT_WIN(3 + quadrant));
		win_base = (win_base & (~QUADRANT_BASE(quadrant))) /
							(bar0_level1_base);
		if (win_base != level1) {
			if (!down_killable(&bar0_set->bar0_window_sem[quadrant])) {
				cn_pci_reg_write32(pcie_set,
						BAR0_TO_AXI_TGT_WIN(3 + quadrant),
						QUADRANT_BASE(quadrant) +
						level1 * (bar0_level1_base));
				bar0_set->bar0_window_flag[quadrant] = 1;
			} else {
				*offset = 0x1000;//deviceid
				cn_dev_pcie_err(pcie_set,
						"bar0 win%d sem err", quadrant);
				return quadrant;
			}
			cn_pci_reg_read32(pcie_set,
					BAR0_TO_AXI_TGT_WIN(3 + quadrant));
		}
		*offset = 4 * C30S_BAR0_LEVEL0_4M + quadrant * bar0_level1_size +
				((*offset & QUADRANT_MASK) % bar0_level1_size);
	} else
		*offset = quadrant * C30S_BAR0_LEVEL0_4M +
						(*offset & QUADRANT_MASK);
	return quadrant;
}

static u32 OVER_WRITE(pcie_reg_read32)(u64 axi_addr, struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	u32 data;
	int quadrant;
	struct c30s_bar0_set *bar0_set = NULL;

	if (axi_addr < 0x2000) {
		cn_dev_pcie_info(pcie_set, "reg_read illegal addr:%#llx", axi_addr);
	}

	bar0_set = (struct c30s_bar0_set *)pcie_set->priv_set;
	quadrant = pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag[quadrant]) {
		data = ioread32(pcie_set->reg_virt_base + offset);
		bar0_set->bar0_window_flag[quadrant] = 0;
		up(&bar0_set->bar0_window_sem[quadrant]);
	} else
		data = ioread32(pcie_set->reg_virt_base + offset);

	return data;
}

static void OVER_WRITE(pcie_reg_write32)(u64 axi_addr, u32 data,
						struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	int quadrant;
	struct c30s_bar0_set *bar0_set = NULL;

	bar0_set = (struct c30s_bar0_set *)pcie_set->priv_set;
	quadrant = pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag[quadrant]) {
		iowrite32(data, pcie_set->reg_virt_base + offset);
		bar0_set->bar0_window_flag[quadrant] = 0;
		up(&bar0_set->bar0_window_sem[quadrant]);
	} else
		iowrite32(data, pcie_set->reg_virt_base + offset);
}

static u64 OVER_WRITE(pcie_reg_read64)(u64 axi_addr, struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	u64 data;
	int quadrant;
	struct c30s_bar0_set *bar0_set = NULL;

	if (axi_addr < 0x2000) {
		cn_dev_pcie_info(pcie_set, "reg_read illegal addr:%#llx", axi_addr);
	}

	bar0_set = (struct c30s_bar0_set *)pcie_set->priv_set;
	quadrant = pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag[quadrant]) {

		data = ioread32(pcie_set->reg_virt_base + offset + 4);
		data <<= 32;
		data |= ioread32(pcie_set->reg_virt_base + offset);

		bar0_set->bar0_window_flag[quadrant] = 0;
		up(&bar0_set->bar0_window_sem[quadrant]);
	} else {
		data = ioread32(pcie_set->reg_virt_base + offset + 4);
		data <<= 32;
		data |= ioread32(pcie_set->reg_virt_base + offset);
	}

	return data;
}

static void OVER_WRITE(pcie_reg_write64)(u64 axi_addr, u64 data,
						struct cn_pcie_set *pcie_set)
{
	unsigned long offset;
	int quadrant;
	struct c30s_bar0_set *bar0_set = NULL;

	bar0_set = (struct c30s_bar0_set *)pcie_set->priv_set;

	quadrant = pcie_set_bar0_window(axi_addr, &offset, pcie_set);
	if (bar0_set->bar0_window_flag[quadrant]) {

		iowrite32(LOWER32(data), pcie_set->reg_virt_base + offset);
		iowrite32(UPPER32(data), pcie_set->reg_virt_base + offset + 4);
		bar0_set->bar0_window_flag[quadrant] = 0;
		up(&bar0_set->bar0_window_sem[quadrant]);
	} else {

		iowrite32(LOWER32(data), pcie_set->reg_virt_base + offset);
		iowrite32(UPPER32(data), pcie_set->reg_virt_base + offset + 4);
	}
}

static int OVER_WRITE(pcie_check_available)(struct cn_pcie_set *pcie_set)
{
	u32 reg_data;

	reg_data = cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
	if (reg_data == REG_VALUE_INVALID) {
		cn_dev_pcie_err(pcie_set, "NOC bus abnormal, read value = %#x", reg_data);
		return -1;
	}

	return 0;
}

#define GET_BIT(data, bit)	((((data) & (0x1 << (bit))) >> (bit)))
static void fetch_buf_status(int phy_channel, int *fetch_buf_num,
		int *buf_full, int *buf_empty, struct cn_pcie_set *pcie_set)
{
	u32 buf_status;

	buf_status = cn_pci_reg_read32(pcie_set,
				DMA_CMD_BUFF_STATUS_FETCH(phy_channel));
	*fetch_buf_num = buf_status & (~0xFFFFFFE0);
	*buf_full = GET_BIT(buf_status, 16);
	*buf_empty = GET_BIT(buf_status, 17);
	cn_dev_debug("buf_status=%#x, buf_num=%d, buf_full=%d, buf_empth=%d",
			buf_status, *fetch_buf_num, *buf_full, *buf_empty);
}

static void fetch_status_buf_status(int phy_channel, int *fetch_status_buf_num,
				int *status_buf_full, int *status_buf_empty,
						struct cn_pcie_set *pcie_set)
{
	u32 status_buf_status;

	status_buf_status = cn_pci_reg_read32(pcie_set,
				DMA_CMD_STATUS_BUFF_STATUS_FETCH(phy_channel));
	*fetch_status_buf_num = status_buf_status & (~0xFFFFFFE0);
	*status_buf_full = GET_BIT(status_buf_status, 16);
	*status_buf_empty = GET_BIT(status_buf_status, 17);
	cn_dev_debug("status_buf_num=%d, status_buf_full=%d, status_buf_empty=%d",
		*fetch_status_buf_num, *status_buf_full, *status_buf_empty);
}

__attribute__((unused))
static void fetch_dbg_dump_reg(struct cn_pcie_set *pcie_set, int phy_channel)
{
	int buffer_entry;
	int buffer_id;

	for (buffer_entry = 0; buffer_entry < 16; buffer_entry++) {
		for (buffer_id = 1; buffer_id <= 8; buffer_id *= 2) {
			cn_pci_reg_write32(pcie_set, DMA_DESC_DBG_SEL_FETCH(phy_channel),
				buffer_entry | (buffer_id << 4) | (1 << 8));
			cn_dev_pcie_err(pcie_set, "buffer_entry[%d] buffer_id[%#x] DESC_FETCH_DBG_DATA0[%#08x]",
				buffer_entry, buffer_id,
				cn_pci_reg_read32(pcie_set, DMA_DESC_DBG_DATA0_FETCH(phy_channel)));
			cn_dev_pcie_err(pcie_set, "buffer_entry[%d] buffer_id[%#x] DESC_FETCH_DBG_DATA1[%#08x]",
				buffer_entry, buffer_id,
				cn_pci_reg_read32(pcie_set, DMA_DESC_DBG_DATA1_FETCH(phy_channel)));
			cn_dev_pcie_err(pcie_set, "buffer_entry[%d] buffer_id[%#x] DESC_FETCH_DBG_DATA2[%#08x]",
				buffer_entry, buffer_id,
				cn_pci_reg_read32(pcie_set, DMA_DESC_DBG_DATA2_FETCH(phy_channel)));
			cn_dev_pcie_err(pcie_set, "buffer_entry[%d] buffer_id[%#x] DESC_FETCH_DBG_DATA3[%#08x]",
				buffer_entry, buffer_id,
				cn_pci_reg_read32(pcie_set, DMA_DESC_DBG_DATA3_FETCH(phy_channel)));
			cn_dev_pcie_err(pcie_set, "buffer_entry[%d] buffer_id[%#x] DESC_FETCH_DBG_DATA4[%#08x]",
				buffer_entry, buffer_id,
				cn_pci_reg_read32(pcie_set, DMA_DESC_DBG_DATA4_FETCH(phy_channel)));
			cn_dev_pcie_err(pcie_set, "buffer_entry[%d] buffer_id[%#x] DESC_FETCH_DBG_DATA5[%#08x]",
				buffer_entry, buffer_id,
				cn_pci_reg_read32(pcie_set, DMA_DESC_DBG_DATA5_FETCH(phy_channel)));
			cn_dev_pcie_err(pcie_set, "buffer_entry[%d] buffer_id[%#x] DESC_FETCH_DBG_DATA6[%#08x]",
				buffer_entry, buffer_id,
				cn_pci_reg_read32(pcie_set, DMA_DESC_DBG_DATA6_FETCH(phy_channel)));
			cn_dev_pcie_err(pcie_set, "buffer_entry[%d] buffer_id[%#x] DESC_FETCH_DBG_DATA7[%#08x]",
				buffer_entry, buffer_id,
				cn_pci_reg_read32(pcie_set, DMA_DESC_DBG_DATA7_FETCH(phy_channel)));
		}
	}
	cn_pci_reg_write32(pcie_set, DMA_DESC_DBG_SEL_FETCH(phy_channel), 0);
}

static int workaround_for_d2h_with_poison_TLP(struct dma_channel_info *channel,
	struct cn_pcie_set *pcie_set, int phy)
{
	int i;
	struct pcie_dma_task *task = channel->task;

	if (channel->fix_count == 1) {
		cn_dev_pcie_info(channel->pcie_set, "try fix error");
		pcie_set->ops->dump_reg(pcie_set);
		return 1;
	}

	for (i = 0; i < channel->desc_len; i += DESC_SIZE) {
		unsigned long len, dst;
		unsigned int ctrl;

		dst = ioread32(channel->desc_virt_base + i + DE_DEST_LOWER);
		ctrl = ioread32(channel->desc_virt_base + i + DE_CTRL);
		len = (ctrl >> 8) & (0x1000000 - 1);

		/* head align-down to 64-Bytes, tail align-up to 64 Bytes */
		len = ((dst + len + 0x3f) & (~0x3f)) - (dst & (~0x3f));
		ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(len) << 8));
		iowrite32(ctrl, channel->desc_virt_base + i + DE_CTRL);

		dst &= (~0x3f);
		iowrite32(dst, channel->desc_virt_base + i + DE_DEST_LOWER);

#define MDR_IOVA_START_L 0x04000000
#define MDR_IOVA_START_H 0x8000
		/* change dst as available mdr addr */
		iowrite32(MDR_IOVA_START_L + phy * 0x100000, channel->desc_virt_base + i + DE_SRC_LOWER);
		iowrite32(MDR_IOVA_START_H, channel->desc_virt_base + i + DE_SRC_UPPER);
	}
	task->poison_flag = 1;
	channel->fix_count = 1;

	/* use same phy and command_id go dma again */
	channel->status = CHANNEL_RUNNING;
	pcie_set->ops->dma_go_command(channel, phy);

	return 0;
}
static int OVER_WRITE(pcie_polling_dma_status)(struct cn_pcie_set *pcie_set,
			struct dma_channel_info *channel)
{
	unsigned int fetch_status;
	int phy_channel = pcie_set->spkg_channel_id;
	int fetch_status_buf_num;
	int status_buf_full;
	int status_buf_empty;
	int command_id;
	int ret;

	if (!pcie_set->dma_fetch_enable)
		return pcie_polling_dma_status(pcie_set, channel);

	if (spin_trylock(&pcie_set->spkg_lock)) {
		fetch_status_buf_status(phy_channel, &fetch_status_buf_num,
					&status_buf_full, &status_buf_empty, pcie_set);
		while (fetch_status_buf_num) {
			fetch_status = cn_pci_reg_read32(pcie_set,
							DMA_STATUS_FETCH(phy_channel));
			command_id = (fetch_status >> 20) & 0xf;
			cn_pci_reg_write32(pcie_set,
					DMA_STATUS_UP_FETCH(phy_channel), 1);

			if (!__sync_bool_compare_and_swap(&pcie_set->spkg_status[command_id],
					CHANNEL_RUNNING, CHANNEL_COMPLETED)) {
				cn_dev_pcie_err(pcie_set, "set CHANNEL_COMPLETED error:%d command_id:%d",
						pcie_set->spkg_status[command_id], command_id);
			}
			pcie_set->spkg_fetch_status[command_id] = fetch_status;
			if (channel->fetch_command_id == command_id)
				break;

			fetch_status_buf_num--;
		}
		spin_unlock(&pcie_set->spkg_lock);
	}

	if (pcie_set->spkg_status[channel->fetch_command_id] == CHANNEL_COMPLETED) {
		if (DMA_FETCH_ERR_CHECK(pcie_set->spkg_fetch_status[channel->fetch_command_id])) {
			cn_dev_pcie_err(pcie_set, "FETCH DMA interrupt error fetch_status:%#x",
					pcie_set->spkg_fetch_status[channel->fetch_command_id]);
			if (pcie_set->ops->dump_reg)
				pcie_set->ops->dump_reg(pcie_set);
			pcie_set->ops->show_desc_list(channel);
#ifdef DMA_FETCH_DUG
			fetch_dbg_dump_reg(pcie_set, phy_channel);
#endif
			/*
			 * fix bug: d2h-dma error interrupt with poison TLP make MCE Error
			 * use MDR memory do D2H copy, to rewrite Host memory
			 *
			 * Bit [8]: Data reading failed due to Completion Timeout
			 * Bit [9]: Data reading failed due to UR received if on PCIe
			 * domain, or DECERR received if on AXI domain.
			 * Bit [10]: Data reading failed due to UR or EP received if on
			 * PCIe domain, or SLVERR response received if on AXI
			 * domain.
			 * Bit [11]: Data reading failed due to ECRC received if on PCIe
			 * domain, PCIe Controller or Bridge Memory Error; or Data
			 * error reported by the AXI Application if on AXI domain.
			 */
			ret = 1;
			if ((channel->direction == DMA_D2H) &&
				(pcie_set->spkg_fetch_status[channel->fetch_command_id] & 0xf00)) {
				pcie_set->spkg_status[channel->fetch_command_id] = CHANNEL_RUNNING;
				ret = workaround_for_d2h_with_poison_TLP(channel, pcie_set, phy_channel);
			}

			if (ret) {
				cn_pci_dma_spkg_complete(channel, CHANNEL_COMPLETED_ERR, pcie_set);
			}
		} else {
			cn_pci_dma_spkg_complete(channel, CHANNEL_COMPLETED, pcie_set);
		}

		return 0;
	} else {
		return -EAGAIN;
	}
}

static irqreturn_t pcie_dma_fetch_interrupt_handle(int index, void *data)
{
	unsigned int fetch_status;
	int phy_channel = index - PCIE_IRQ_DMA;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct dma_channel_info *channel;
	int fetch_status_buf_num;
	int status_buf_full;
	int status_buf_empty;
	int command_id;
	int ret;

	fetch_status_buf_status(phy_channel, &fetch_status_buf_num,
				&status_buf_full, &status_buf_empty, pcie_set);

	while (fetch_status_buf_num) {
		fetch_status = cn_pci_reg_read32(pcie_set,
						DMA_STATUS_FETCH(phy_channel));
		command_id = (fetch_status >> 20) & 0xf;
		cn_pci_reg_write32(pcie_set,
				DMA_STATUS_UP_FETCH(phy_channel), 1);

		channel = (struct dma_channel_info *)
				pcie_set->running_channels[phy_channel][command_id];
		if (!channel) {
			cn_dev_pcie_err(pcie_set,
				"phy_channel:%d is NULL", phy_channel);
			break;
		}

		if (DMA_FETCH_ERR_CHECK(fetch_status)) {
			cn_dev_pcie_err(pcie_set, "FETCH%d DMA interrupt error fetch_status:%#x",
								phy_channel, fetch_status);
			if (pcie_set->ops->dump_reg)
				pcie_set->ops->dump_reg(pcie_set);
			pcie_set->ops->show_desc_list(channel);
#ifdef DMA_FETCH_DUG
			fetch_dbg_dump_reg(pcie_set, phy_channel);
#endif
			/*
			 * fix bug: d2h-dma error interrupt with poison TLP make MCE Error
			 * use MDR memory do D2H copy, to rewrite Host memory
			 *
			 * Bit [8]: Data reading failed due to Completion Timeout
			 * Bit [9]: Data reading failed due to UR received if on PCIe
			 * domain, or DECERR received if on AXI domain.
			 * Bit [10]: Data reading failed due to UR or EP received if on
			 * PCIe domain, or SLVERR response received if on AXI
			 * domain.
			 * Bit [11]: Data reading failed due to ECRC received if on PCIe
			 * domain, PCIe Controller or Bridge Memory Error; or Data
			 * error reported by the AXI Application if on AXI domain.
			 */
			ret = 1;
			if ((channel->direction == DMA_D2H) && (fetch_status & 0xf00)) {
				ret = workaround_for_d2h_with_poison_TLP(channel, pcie_set, phy_channel);
			}

			if (ret) {
				cn_pci_dma_complete(phy_channel, command_id, CHANNEL_COMPLETED_ERR, pcie_set);
			}
		} else {
			cn_pci_dma_complete(phy_channel, command_id, CHANNEL_COMPLETED, pcie_set);
		}

		fetch_status_buf_num--;
	}

	cn_pci_task_fair_schedule(pcie_set);
	return IRQ_HANDLED;
}

static int OVER_WRITE(pcie_dma_go)(struct dma_channel_info *channel,
							int phy_channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	unsigned long desc_addr = 0;
	unsigned int desc_num = 0;
	int fetch_buf_num;
	int buf_full;
	int buf_empty;
	unsigned long flag = 0;

	if (!pcie_set->dma_fetch_enable)
		return pcie_dma_go(channel, phy_channel);

	if (channel->status != CHANNEL_RUNNING)
		cn_dev_pcie_err(pcie_set, "channel is not locked:%d", channel->status);

	spin_lock_irqsave(&pcie_set->fetch_lock[phy_channel], flag);
	switch (channel->direction) {
	case DMA_H2D:
		cn_pci_reg_write32(pcie_set, DMA_DESC_CTRL_FETCH(phy_channel),
				(DMA_PCIE_PARAM << 0) | (DMA_AXI_PARAM << 16));
		break;

	case DMA_P2P:
	case DMA_D2H:
		cn_pci_reg_write32(pcie_set, DMA_DESC_CTRL_FETCH(phy_channel),
				(DMA_AXI_PARAM << 0) | (DMA_PCIE_PARAM << 16));
		break;
	default:
		cn_dev_pcie_err(pcie_set, "unknown dma direction:%d", channel->direction);
		spin_unlock_irqrestore(&pcie_set->fetch_lock[phy_channel], flag);
		return -1;
	}
	desc_addr = channel->desc_device_va;
	desc_num = channel->desc_len / DESC_SIZE;

	cn_pci_reg_write32(pcie_set,
		DMA_DESC_ADDR_L_FETCH(phy_channel), LOWER32(desc_addr));
	cn_pci_reg_write32(pcie_set,
		DMA_DESC_ADDR_H_FETCH(phy_channel), UPPER32(desc_addr));
	cn_pci_reg_write32(pcie_set,
		DMA_DESC_NUM_FETCH(phy_channel), desc_num);
retry:
	/* FETCH TODO: buf_full is for debug, will be remove later */
	fetch_buf_status(phy_channel, &fetch_buf_num, &buf_full,
						&buf_empty, pcie_set);
	if (!buf_full) {
		cn_pci_reg_write32(pcie_set, DMA_DESC_CTRL2_FETCH(phy_channel),
				((channel->fetch_command_id << 24) | (0x1 << 31)));
		cn_pci_reg_read32(pcie_set,
				DMA_DESC_CTRL2_FETCH(phy_channel));
	} else {
		cn_dev_pcie_err(pcie_set, "phy_channel[%d] is full fetch_buf_num:%#x buf_full:%d buf_empty:%d",
				phy_channel, fetch_buf_num, buf_full, buf_empty);
		goto retry;
	}
	spin_unlock_irqrestore(&pcie_set->fetch_lock[phy_channel], flag);

	return 0;
}

static int OVER_WRITE(pcie_enable_pf_bar)(struct cn_pcie_set *pcie_set)
{
	int index;
	u64 base, sz;
	struct bar_resource bar, *new;
	struct pci_dev *pdev = pcie_set->pdev;

	for (index = 2; index < 6; index++) {
		sz = pci_resource_len(pdev, index);
		if (!sz)
			continue;
		base = pci_resource_start(pdev, index);

		memset(&bar, 0, sizeof(bar));
		bar.type = PF_BAR;
		bar.index = index;
		bar.phy_base = base;
		bar.bus_base = cn_pci_bus_address(pdev, index);
		bar.size = sz;
		bar.smmu_in = index / 2 * 2;
		bar.smmu_out = index / 2 * 2 - 1;

		new = pcie_bar_resource_struct_init(&bar);
		if (new)
			list_add_tail(&new->list, &pcie_set->bar_resource_head);
	}

	return 0;
}
#include "cndrv_pci_c30s_sriov.c"

#ifdef CONFIG_PCI_IOV
static int c30s_sriov_support(struct cn_pcie_set *pcie_set)
{
	int total_vfs;
	u64 vf_bar0_size;
	int vf;

	vf_bar0_size = pci_resource_len(
		pcie_set->pdev, PCI_IOV_RESOURCES);

	total_vfs = pci_sriov_get_totalvfs(pcie_set->pdev);
	if (total_vfs * pcie_set->pcibar[0].size != vf_bar0_size)
		return 0;

	for (vf = 0; vf < 6; vf += 2)
		if (!pci_resource_start(pcie_set->pdev, PCI_IOV_RESOURCES + vf))
			return 0;

	return 1;
}
#endif

static int c30s_dma_bypass_smmu(int phy_ch, bool en, struct cn_pcie_set *pcie_set)
{
	int ret;

	phy_ch = phy_ch + DMA_SMMU_STREAM_ID;
	ret = cn_smmu_cau_bypass(pcie_set->bus_set->core, phy_ch, en);

	return ret;
}

static int c30s_dma_bypass_smmu_all(bool en, struct cn_pcie_set *pcie_set)
{
	int ret;
	int eng;

	for (eng = 0; eng < DMA_REG_CHANNEL_NUM; eng++) {
		ret = cn_smmu_cau_bypass(pcie_set->bus_set->core,
				eng + DMA_SMMU_STREAM_ID, en);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "eng[%d] smmu cau bypass error:%d",
					eng, ret);
			return ret;
		}
	}

	return ret;
}

static struct cn_pci_ops c30s_private_ops = {
	.dump_reg = OVER_WRITE(pcie_dump_reg),
	.async_dma_fill_desc_list = OVER_WRITE(async_dma_fill_desc_list),
	.fill_desc_list = OVER_WRITE(pcie_fill_desc_list),
	.get_desc_unpack_num = OVER_WRITE(get_desc_unpack_num),
	.set_bar_window = OVER_WRITE(pcie_set_bar_window),
	.reg_read32 = OVER_WRITE(pcie_reg_read32),
	.reg_write32 = OVER_WRITE(pcie_reg_write32),
	.reg_read64 = OVER_WRITE(pcie_reg_read64),
	.reg_write64 = OVER_WRITE(pcie_reg_write64),
	.check_available = OVER_WRITE(pcie_check_available),
	.dma_go_command = OVER_WRITE(pcie_dma_go),
	.enable_vf_bar = OVER_WRITE(pcie_enable_vf_bar),
	.disable_vf_bar = OVER_WRITE(pcie_disable_vf_bar),
	.enable_pf_bar = OVER_WRITE(pcie_enable_pf_bar),

	.sriov_vf_init = c30s_sriov_vf_init,
	.sriov_vf_exit = c30s_sriov_vf_exit,
	.iov_virtfn_bus = c30s_pcie_iov_virtfn_bus,
	.iov_virtfn_devfn = c30s_pcie_iov_virtfn_devfn,
	.sriov_pre_init = c30s_sriov_pre_init,
	.sriov_later_exit = c30s_sriov_later_exit,
	.dma_bypass_smmu = c30s_dma_bypass_smmu,
	.dma_bypass_smmu_all = c30s_dma_bypass_smmu_all,
#ifdef CONFIG_PCI_IOV
	.sriov_support = c30s_sriov_support,
#endif
	.polling_dma_status = OVER_WRITE(pcie_polling_dma_status),
};


/* Time to wait after a reset for device to become responsive */
#define PCIE_DL_ACT_POLL_MS          1000
#define PCI_EXP_LNKCAP_DLLA      0x100000
#define PCI_EXP_LNKSTA_DL_ACT    0x2000

static int cn_pci_wait_dllact(struct cn_pcie_set *pcie_set, int timeout)
{
	int delay = 1;
	u32 lnkcap;
	u16 link_status;
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_dev *parent = pdev->bus->self;

	pcie_capability_read_dword(parent, PCI_EXP_LNKCAP, &lnkcap);
	if (lnkcap & PCI_EXP_LNKCAP_DLLA) {
		pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_status);
		while (!(link_status & PCI_EXP_LNKSTA_DL_ACT)) {
			if (delay > timeout) {
				cn_dev_pcie_warn(pcie_set,
						"not ready %dms ; giving up",
				delay - 1);
				return -ENOTTY;
			}

			if (delay > 1000)
				cn_dev_pcie_info(pcie_set,
						"not ready %dms; waiting",
						delay - 1);

			msleep(delay);
			delay *= 2;
			pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_status);
		}

		if (delay > 1000)
			cn_dev_pcie_info(pcie_set, "ready %dms",
					delay - 1);

	} else {
		cn_dev_pcie_info(pcie_set,
			"do not support Data Link Layer Link Active Reporting Capable");
		msleep(500);
	}

	return 0;
}

static int M83U_change_speed(struct cn_pcie_set *pcie_set, u32 target_speed, u32 target_width)
{
	int ret;
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_dev *parent = pdev->bus->self;
	u16 link_status, lnkctl2;
	u64 k_gen;
	u32 current_speed;
	u32 current_width;
	u32 gen3_retrain_cnt = 0;
	u32 gen4_retrain_cnt = 0;
	int pos_cap;
	u32 cor_mask, uncor_mask;
	u32 cor_status, uncor_status;
	int parent_pos_cap;
	u32 parent_cor_mask, parent_uncor_mask;
	u32 parent_cor_status, parent_uncor_status;
	int delay;

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

	cn_dev_pcie_info(pcie_set, "current link speed:%s target link speed:%s",
			PCIE_SPEED_STR(current_speed), PCIE_SPEED_STR(target_speed));
	cn_dev_pcie_info(pcie_set, "current link width:x%d target link width:x%d",
			current_width, target_width);

	if ((current_speed == target_speed) &&
			(current_width == target_width))
		return 0;

	cn_pci_dev_save(pdev);

gen3_retry:
	cn_dev_pcie_info(pcie_set, "gen3_retrain_cnt :%d, gen4_retrain_cnt:%d",
			gen3_retrain_cnt, gen4_retrain_cnt);

	target_speed = PCI_EXP_LNKCTL2_TLS_8_0GT;

	/* change capability to gen4x16 */
	k_gen = cn_pci_reg_read64(pcie_set, K_GEN_REG);
	k_gen = (k_gen & 0xffef0fff) | 0x7000;
	cn_pci_reg_write64(pcie_set, K_GEN_REG, k_gen);
	cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
	cn_dev_pcie_info(pcie_set, "change capability to gen4x16 k_gen:%#llx", k_gen);

	/* mask pdev aer */
	pos_cap = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);
	if (pos_cap != 0) {
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, &cor_mask);
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, &uncor_mask);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, 0xffffffff);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, 0xffffffff);
	}
	/* mask parent aer */
	parent_pos_cap = pci_find_ext_capability(parent, PCI_EXT_CAP_ID_ERR);
	if (parent_pos_cap != 0) {
		pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_COR_MASK, &parent_cor_mask);
		pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_MASK, &parent_uncor_mask);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_COR_MASK, 0xffffffff);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_MASK, 0xffffffff);
	}

	/* set pdev target speed */
	ret = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL2,
			&lnkctl2);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "unable to read from PCI config");
		return -1;
	}
	lnkctl2 &= ~PCI_EXP_LNKCTL2_TLS;
	lnkctl2 |= target_speed;
	ret = pcie_capability_write_word(pdev,
			PCI_EXP_LNKCTL2, lnkctl2);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "unable to write to PCI config");
		return -1;
	}
	cn_dev_pcie_info(pcie_set, "setting pdev target link speed PCI_EXP_LNKCTL2 %#x", lnkctl2);
	if (!cn_pci_wait_for_pending_transaction(pdev))
		cn_dev_pcie_err(pcie_set, "timed out waiting for pending transaction");

	/* set eq */
	if (target_speed >= 3) {
		cn_pci_link_eq_set(pcie_set);
	}

	/* set parent target speed */
	ret = pcie_capability_read_word(parent, PCI_EXP_LNKCTL2, &lnkctl2);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "unable to read from PCI config");
		return -1;
	}
	lnkctl2 &= ~PCI_EXP_LNKCTL2_TLS;
	lnkctl2 |= target_speed;
	ret = pcie_capability_write_word(parent, PCI_EXP_LNKCTL2, lnkctl2);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "unable to write to PCI config");
		return -1;
	}
	cn_dev_pcie_info(pcie_set, "setting parent target link speed PCI_EXP_LNKCTL2 %#x", lnkctl2);
	if (!cn_pci_wait_for_pending_transaction(parent))
		cn_dev_pcie_err(pcie_set, "timed out waiting for pending transaction");

	cn_pci_wait_for_polling_link_training(pcie_set, PCIE_LINK_TRAINING_POLL_MS);

	msleep(100);

	/* inquire parent link status*/
	pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	if ((current_speed == target_speed) && (current_width == target_width))
		goto gen3_aer_restore;

	/* set retrain */
	cn_pci_retrain_set(pcie_set);
	gen3_retrain_cnt++;
	cn_pci_wait_for_polling_link_training(pcie_set, PCIE_LINK_TRAINING_POLL_MS);

gen3_aer_restore:
	ret = cn_pci_wait_dllact(pcie_set, PCIE_DL_ACT_POLL_MS);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "dllact timeout");
		return -1;
	}

	delay = 0;
	/* inquire parent link status*/
	do {
		msleep(100);
		delay++;
		pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_status);
		current_speed = link_status & PCI_EXP_LNKSTA_CLS;
		current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
		if (delay > 20) {
			cn_dev_pcie_info(pcie_set, "wait link status timeout");
			break;
		}
	} while ((current_speed != target_speed) || (current_width != target_width));

	msleep(1000);

	/* pdev aer mask restore */
	if (pos_cap != 0) {
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_COR_STATUS, &cor_status);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_STATUS, cor_status);
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_STATUS, &uncor_status);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_STATUS, uncor_status);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, cor_mask);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, uncor_mask);
	}
	/* parent aer mask restore */
	if (parent_pos_cap != 0) {
		pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_COR_STATUS, &parent_cor_status);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_COR_STATUS, parent_cor_status);
		pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_STATUS, &parent_uncor_status);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_STATUS, parent_uncor_status);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_COR_MASK, parent_cor_mask);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_MASK, parent_uncor_mask);
	}

	cn_pci_dev_restore(pcie_set->pdev);

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

	cn_dev_pcie_info(pcie_set, "PCIe link change speed to %s", PCIE_SPEED_STR(current_speed));
	cn_dev_pcie_info(pcie_set, "PCIe link change width to x%d", current_width);

	if (gen3_retrain_cnt >= 20) {
		cn_dev_pcie_err(pcie_set, "pcie change speed fail");
		return -1;
	}

	if ((current_speed != target_speed) ||
			(current_width != target_width))
		goto gen3_retry;

	target_speed = PCI_EXP_LNKCTL2_TLS_16_0GT;

	/* mask pdev aer */
	pos_cap = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);
	if (pos_cap != 0) {
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, &cor_mask);
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, &uncor_mask);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, 0xffffffff);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, 0xffffffff);
	}
	/* mask parent aer */
	parent_pos_cap = pci_find_ext_capability(parent, PCI_EXT_CAP_ID_ERR);
	if (parent_pos_cap != 0) {
		pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_COR_MASK, &parent_cor_mask);
		pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_MASK, &parent_uncor_mask);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_COR_MASK, 0xffffffff);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_MASK, 0xffffffff);
	}

	/* set pdev target speed */
	ret = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL2,
			&lnkctl2);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "unable to read from PCI config");
		return -1;
	}
	lnkctl2 &= ~PCI_EXP_LNKCTL2_TLS;
	lnkctl2 |= target_speed;
	ret = pcie_capability_write_word(pdev,
			PCI_EXP_LNKCTL2, lnkctl2);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "unable to write to PCI config");
		return -1;
	}
	cn_dev_pcie_info(pcie_set, "setting pdev target link speed PCI_EXP_LNKCTL2 %#x", lnkctl2);
	if (!cn_pci_wait_for_pending_transaction(pdev))
		cn_dev_pcie_err(pcie_set, "timed out waiting for pending transaction");

	/* set eq */
	if (target_speed >= 3) {
		cn_pci_link_eq_set(pcie_set);
	}

	/* set parent target speed */
	ret = pcie_capability_read_word(parent, PCI_EXP_LNKCTL2, &lnkctl2);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "unable to read from PCI config");
		return -1;
	}
	lnkctl2 &= ~PCI_EXP_LNKCTL2_TLS;
	lnkctl2 |= target_speed;
	ret = pcie_capability_write_word(parent, PCI_EXP_LNKCTL2, lnkctl2);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "unable to write to PCI config");
		return -1;
	}
	cn_dev_pcie_info(pcie_set, "setting parent target link speed PCI_EXP_LNKCTL2 %#x", lnkctl2);
	if (!cn_pci_wait_for_pending_transaction(parent))
		cn_dev_pcie_err(pcie_set, "timed out waiting for pending transaction");

	cn_pci_wait_for_polling_link_training(pcie_set, PCIE_LINK_TRAINING_POLL_MS);

	msleep(100);

	/* inquire parent link status*/
	pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	if ((current_speed == target_speed) && (current_width == target_width))
		goto gen4_aer_restore;

	/* set retrain */
	cn_pci_retrain_set(pcie_set);
	gen4_retrain_cnt++;
	cn_pci_wait_for_polling_link_training(pcie_set, PCIE_LINK_TRAINING_POLL_MS);

gen4_aer_restore:
	ret = cn_pci_wait_dllact(pcie_set, PCIE_DL_ACT_POLL_MS);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "dllact timeout");
		return -1;
	}

	delay = 0;
	/* inquire parent link status*/
	do {
		msleep(100);
		delay++;
		pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_status);
		current_speed = link_status & PCI_EXP_LNKSTA_CLS;
		current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
		if (delay > 20) {
			cn_dev_pcie_info(pcie_set, "wait link status timeout");
			break;
		}
	} while ((current_speed != target_speed) || (current_width != target_width));

	msleep(1000);

	/* pdev aer mask restore */
	if (pos_cap != 0) {
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_COR_STATUS, &cor_status);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_STATUS, cor_status);
		pci_read_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_STATUS, &uncor_status);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_STATUS, uncor_status);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_COR_MASK, cor_mask);
		pci_write_config_dword(pdev, pos_cap + PCI_ERR_UNCOR_MASK, uncor_mask);
	}
	/* parent aer mask restore */
	if (parent_pos_cap != 0) {
		pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_COR_STATUS, &parent_cor_status);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_COR_STATUS, parent_cor_status);
		pci_read_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_STATUS, &parent_uncor_status);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_STATUS, parent_uncor_status);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_COR_MASK, parent_cor_mask);
		pci_write_config_dword(parent, parent_pos_cap + PCI_ERR_UNCOR_MASK, parent_uncor_mask);
	}

	cn_pci_dev_restore(pcie_set->pdev);

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

	cn_dev_pcie_info(pcie_set, "PCIe link change speed to %s", PCIE_SPEED_STR(current_speed));
	cn_dev_pcie_info(pcie_set, "PCIe link change width to x%d", current_width);

	if (gen4_retrain_cnt >= 20) {
		cn_dev_pcie_err(pcie_set, "pcie change speed fail");
		return -1;
	}

	if ((current_speed != target_speed) ||
			(current_width != target_width))
		goto gen3_retry;

	return 0;
}

__attribute__((unused))
static int M83U_retrain_link_speed(struct cn_pcie_set *pcie_set)
{
	int ret;
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_dev *parent = pdev->bus->self;
	struct pci_dev *rc_pdev = NULL;
	u16 link_status;
	u16 link_cap;
	u32 current_speed;
	u32 current_width;
	u32 target_speed;
	u32 target_width;
	struct pci_bus *bus;
	u32 cor_mask, uncor_mask;
	u32 cor_status, uncor_status;
	int pos_cap;

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	cn_dev_pcie_info(pcie_set, "current link speed:%s current link width:x%d",
			PCIE_SPEED_STR(current_speed), current_width);
	if (current_speed >= PCI_EXP_LNKCTL2_TLS_2_5GT) {
		cn_dev_pcie_info(pcie_set, "no need to change speed");
		return 0;
	}

	for (bus = pdev->bus; !pci_is_root_bus(bus); bus = bus->parent) {
		rc_pdev = bus->self;
		if (!rc_pdev) {
			cn_dev_pcie_info(pcie_set, "rc_pdev is null\n");
			return -1;
		}
	}

	if (rc_pdev == NULL)
		return 0;

	/* mask rc aer */
	pos_cap = pci_find_ext_capability(rc_pdev, PCI_EXT_CAP_ID_ERR);
	if (pos_cap != 0) {
		pci_read_config_dword(rc_pdev, pos_cap + PCI_ERR_COR_MASK, &cor_mask);
		pci_read_config_dword(rc_pdev, pos_cap + PCI_ERR_UNCOR_MASK, &uncor_mask);
		pci_write_config_dword(rc_pdev, pos_cap + PCI_ERR_COR_MASK, 0xffffffff);
		pci_write_config_dword(rc_pdev, pos_cap + PCI_ERR_UNCOR_MASK, 0xffffffff);
	}

	/* get target speed and target width */
	pcie_capability_read_word(parent, PCI_EXP_LNKCAP, &link_cap);
	target_speed = link_cap & PCI_EXP_LNKSTA_CLS;
	target_width = (link_cap & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	cn_dev_pcie_info(pcie_set, "target link speed:%s target link width:x%d",
			PCIE_SPEED_STR(target_speed), target_width);

	ret = M83U_change_speed(pcie_set, PCI_EXP_LNKCTL2_TLS_16_0GT, target_width);
	if (ret) {
		cn_dev_pcie_info(pcie_set, "retrain to gen4 failed");
		return -1;
	}

	/* pdev aer mask restore */
	if (pos_cap != 0) {
		pci_read_config_dword(rc_pdev, pos_cap + PCI_ERR_COR_STATUS, &cor_status);
		pci_write_config_dword(rc_pdev, pos_cap + PCI_ERR_COR_STATUS, cor_status);
		pci_read_config_dword(rc_pdev, pos_cap + PCI_ERR_UNCOR_STATUS, &uncor_status);
		pci_write_config_dword(rc_pdev, pos_cap + PCI_ERR_UNCOR_STATUS, uncor_status);
		pci_write_config_dword(rc_pdev, pos_cap + PCI_ERR_COR_MASK, cor_mask);
		pci_write_config_dword(rc_pdev, pos_cap + PCI_ERR_UNCOR_MASK, uncor_mask);
	}

	return 0;
}

__attribute__((unused))
static int c30s_retrain_link_speed(struct cn_pcie_set *pcie_set)
{
	int ret;
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_dev *parent = pdev->bus->self;
	u64 k_gen;
	u16 link_status;
	u16 link_cap;
	u32 current_speed;
	u32 current_width;
	u32 target_speed;
	u32 target_width;

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	cn_dev_pcie_info(pcie_set, "current link speed:%s current link width:x%d",
			PCIE_SPEED_STR(current_speed), current_width);
	if (current_speed > PCI_EXP_LNKCTL2_TLS_2_5GT) {
		cn_dev_pcie_info(pcie_set, "no need to change speed");
		return 0;
	}

	/* change capability to gen4x16 */
	k_gen = cn_pci_reg_read64(pcie_set, K_GEN_REG);
	k_gen = (k_gen & 0xffff80ff) | 0x7f00;
	cn_pci_reg_write64(pcie_set, K_GEN_REG, k_gen);
	cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
	cn_dev_pcie_info(pcie_set, "change capability to gen4x16 k_gen:%#llx", k_gen);

	/* get target speed and target width */
	pcie_capability_read_word(parent, PCI_EXP_LNKCAP, &link_cap);
	target_speed = link_cap & PCI_EXP_LNKSTA_CLS;
	target_width = (link_cap & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	cn_dev_pcie_info(pcie_set, "target link speed:%s target link width:x%d",
			PCIE_SPEED_STR(target_speed), target_width);

	if (target_speed >= PCI_EXP_LNKCTL2_TLS_8_0GT) {
		ret = cn_pci_change_speed(pcie_set, PCI_EXP_LNKSTA_CLS_8_0GB, target_width);
		if (ret) {
			cn_dev_pcie_info(pcie_set, "retrain to gen3 failed");
			return -1;
		}
	}

	if (target_speed >= PCI_EXP_LNKCTL2_TLS_16_0GT) {
		ret = cn_pci_change_speed(pcie_set, PCI_EXP_LNKCTL2_TLS_16_0GT, target_width);
		if (ret) {
			cn_dev_pcie_info(pcie_set, "retrain to gen4 failed");
			return -1;
		}
	}

	return 0;
}

__attribute__((unused))
static int c30s_increase_cpl_timeout(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	u16 cpl_timeout;

	pcie_capability_read_word(pdev, PCI_EXP_DEVCTL2, &cpl_timeout);
	cn_dev_pcie_info(pcie_set, "completion timout default:%d", cpl_timeout & 0xf);
	//set completion timeout 1-3.5s
	pcie_capability_write_word(pdev, PCI_EXP_DEVCTL2, ((cpl_timeout & 0xfff0) | 0xa));
	pcie_capability_read_word(pdev, PCI_EXP_DEVCTL2, &cpl_timeout);
	cn_dev_pcie_info(pcie_set, "completion timout new:%d", cpl_timeout & 0xf);
	return 0;
}

static void c30s_pcie_data_outbound_reg(struct cn_pcie_set *pcie_set)
{
	int i = 0;
	int outbound_index;
	struct outbound_mem *outbound_mem;
	u64 value;
	struct c30s_priv_set *p_set = NULL;
	struct data_outbound_set *dob_set = NULL;

	p_set = (struct c30s_priv_set *)pcie_set->priv_set;
	dob_set = &p_set->dob_set;
	outbound_mem = dob_set->share_priv;
	if ((!outbound_mem) || (!dob_set->share_mem_pages))
		return;

	for_each_set_bit(outbound_index, (unsigned long *)&dob_set->ob_mask,
		sizeof(dob_set->ob_mask) * 8) {
		/* slv3 outbound pci address */
		cn_pci_reg_write64(pcie_set, SLV3_TRSL_ADDRL(outbound_index),
					(outbound_mem[i].pci_addr));
		/* slv3 axi address */
		value = SLV3_OUTBOUND_AXI_BASE |
				(dob_set->ob_size * outbound_index) |
				(((SLV3_OUTBOUND_POWER - 1) << 1) | (1 << 0));
		cn_pci_reg_write64(pcie_set,
					SLV3_SRC_ADDRL(outbound_index), value);
		cn_dev_pcie_info(pcie_set,
			"data outbound:%d virtual_addr:%px pci_addr:%#llx\n",
				outbound_index, outbound_mem[i].virt_addr,
						outbound_mem[i].pci_addr);
		i++;
		cn_dev_pcie_info(pcie_set, "SLV3_TRSL_ADDRL=%#llx\n",
		cn_pci_reg_read64(pcie_set, SLV3_TRSL_ADDRL(outbound_index)));
		cn_dev_pcie_info(pcie_set, "SLV3_SRC_ADDRL=%#llx\n",
		cn_pci_reg_read64(pcie_set, SLV3_SRC_ADDRL(outbound_index)));
	}
}

static int c30s_pcie_data_outbound_exit(struct cn_pcie_set *pcie_set)
{
	int i;
	int outbound_index;
	struct outbound_mem *outbound_mem;
	struct c30s_priv_set *p_set = NULL;
	struct data_outbound_set *dob_set = NULL;

	if (!pcie_set->priv_set)
		return 0;
	p_set = (struct c30s_priv_set *)pcie_set->priv_set;
	dob_set = &p_set->dob_set;
	outbound_mem = dob_set->share_priv;
	if ((!outbound_mem) || (!dob_set->share_mem_pages))
		return 0;

	if (pcie_set->share_mem[2].virt_addr) {
		vm_unmap_ram(pcie_set->share_mem[2].virt_addr,
			(dob_set->ob_cnt * dob_set->ob_size) / PAGE_SIZE);
		pcie_set->share_mem[2].virt_addr = NULL;
	}

	for (i = 0; i < (dob_set->ob_cnt * dob_set->ob_size) / PAGE_SIZE; i++) {
		if (dob_set->share_mem_pages[i]) {
			dob_set->share_mem_pages[i] = NULL;
		}
	}

	for (i = 0; i < dob_set->ob_cnt; i++) {
		if (outbound_mem[i].virt_addr)
			pci_free_consistent(pcie_set->pdev, dob_set->ob_size,
			outbound_mem[i].virt_addr, outbound_mem[i].pci_addr);
	}

	for_each_set_bit(outbound_index, (unsigned long *)&dob_set->ob_mask,
		sizeof(dob_set->ob_mask) * 8) {
		cn_pci_reg_write64(pcie_set,
					SLV3_SRC_ADDRL(outbound_index), 0ULL);
		cn_pci_reg_write64(pcie_set,
					SLV3_TRSL_ADDRL(outbound_index), 0ULL);
	}
	cn_kfree(dob_set->share_mem_pages);
	dob_set->share_mem_pages = NULL;
	cn_kfree(dob_set->share_priv);
	dob_set->share_priv = NULL;

	return 0;
}

static int c30s_pcie_data_outbound_init(struct cn_pcie_set *pcie_set)
{
	int i;
	int j;
	int page_index = 0;
	struct outbound_mem *outbound_mem;
	int index = pcie_set->share_mem_cnt;
	struct c30s_priv_set *p_set = NULL;
	struct data_outbound_set *dob_set = NULL;
	void *virt_addr;

	p_set = (struct c30s_priv_set *)pcie_set->priv_set;
	dob_set = &p_set->dob_set;

	dob_set->dob_ar_cnt = cn_pci_reg_read32(pcie_set, SLV_WIN_AR_CNT);
	dob_set->dob_ar_cnt &= 0xff;
	cn_dev_pcie_info(pcie_set, "dob ar count:%#x", dob_set->dob_ar_cnt);

	dob_set->share_mem_pages = cn_kzalloc(
		sizeof(struct page *) * (dob_set->ob_total_size / PAGE_SIZE),
		GFP_KERNEL);
	if (!dob_set->share_mem_pages) {
		pr_err("Malloc share_mem_pages error\n");
		return -1;
	}

	outbound_mem = cn_kzalloc(dob_set->ob_cnt * sizeof(struct outbound_mem),
								GFP_KERNEL);
	if (!outbound_mem) {
		pr_err("Malloc outbound_mem error\n");
		goto ERROR_RET;
	}
	dob_set->share_priv = (void *)outbound_mem;

	for (i = 0; i < dob_set->ob_cnt; i++) {
		outbound_mem[i].virt_addr = dma_alloc_coherent(&pcie_set->pdev->dev,
			dob_set->ob_size, &(outbound_mem[i].pci_addr), GFP_KERNEL);
		if (!outbound_mem[i].virt_addr) {
			pr_err("dma_alloc_coherent error:%d\n", i);
			goto ERROR_RET;
		}

		if (outbound_mem[i].pci_addr&(dob_set->ob_size - 1)) {
			pr_err("dma_alloc_coherent not align:%llx\n",
					outbound_mem[i].pci_addr);
			goto ERROR_RET;
		}
	}

	page_index = 0;
	for (i = 0; i < dob_set->ob_cnt; i++) {
		for (j = 0; j < dob_set->ob_size / PAGE_SIZE; j++) {
			virt_addr = outbound_mem[i].virt_addr + j * PAGE_SIZE;
			if (is_vmalloc_addr(virt_addr))
				dob_set->share_mem_pages[page_index] =
						vmalloc_to_page(virt_addr);
			else
				dob_set->share_mem_pages[page_index] =
						virt_to_page(virt_addr);
			page_index++;
		}
	}

#if  defined(__x86_64__)
	pcie_set->share_mem[index].virt_addr = cn_vm_map_ram(
		dob_set->share_mem_pages, page_index, -1, PAGE_KERNEL_NOCACHE);
#else
	pcie_set->share_mem[index].virt_addr = cn_vm_map_ram(
		dob_set->share_mem_pages, page_index, -1, PAGE_KERNEL);
#endif
	if (!pcie_set->share_mem[index].virt_addr) {
		pr_err("vm_map_ram error\n");
		goto ERROR_RET;
	}

	pr_info("host share mem virtual addr:%px\n",
		pcie_set->share_mem[index].virt_addr);
	pcie_set->share_mem[index].win_length = dob_set->ob_total_size;
	pcie_set->share_mem[index].type = CN_SHARE_MEM_HOST_DATA;
	pcie_set->share_mem[index].device_addr = dob_set->ob_axi_addr;

	pcie_set->share_mem_cnt++;

	return 0;

ERROR_RET:
	c30s_pcie_data_outbound_exit(pcie_set);

	return -1;
}

static void c30s_pcie_data_outbound_pre_init(struct cn_pcie_set *pcie_set)
{
	struct c30s_priv_set *p_set = NULL;
	struct data_outbound_set *dob_set = NULL;

	p_set = (struct c30s_priv_set *)pcie_set->priv_set;
	dob_set = &p_set->dob_set;
	dob_set->ob_size = SLV3_OUTBOUND_SIZE;
	dob_set->ob_axi_addr = SLV3_OUTBOUND_AXI_BASE;
	dob_set->ob_mask = ((u64)((1ULL << SLV3_OUTBOUND_CNT) - 1))
							<< SLV3_OUTBOUND_FIRST;
	dob_set->ob_cnt = hweight64(dob_set->ob_mask);
	dob_set->ob_total_size = dob_set->ob_size * dob_set->ob_cnt;

	cn_dev_pcie_info(pcie_set,
			"data ob_cnt:%d ob_size:0x%x ob_total_size:%x ob_axi_addr:%llx",
				dob_set->ob_cnt, dob_set->ob_size,
				dob_set->ob_total_size, dob_set->ob_axi_addr);
}

/*
	If narrow_gen = 0, not any real Gen, means to find the narrowest_gen.
	Otherwise, to check wether has Gen that LessEqual than narrow_gen.
	If find out 'narrowest_gen', then return it or 0 when not.
	Otherwise return 'narrow_gen' when find out LessEqual or 0 when not.

				RETRUN
			    /-----  0 : Not Found that Less than devSelf.
	narrowest_gen=0 -->|     GenX : the narrowest Then set dev as 'narrowest'.
			   |       -1 : Meet error.
			   #
			   |       -1 : Meet error.
	narrowest_gen!=0-->|	 GenX : the first found lessEqual than Setting
			   |            Then set dev as Setting.
			    \-----  0 : Not Found which LessEqual than Setting.
*/
static int walkthrough_rc_for_lower_genX(struct cn_pcie_set *pcie_set, int narrow_gen)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_bus *bus;
	u16 status, speed;
	int ret_gen = 0;
	int dev_self_gen = 0;
	int narrowest_gen = 0;

	if (!narrow_gen) {
		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &status);
		dev_self_gen = status & PCI_EXP_LNKSTA_CLS;
		narrowest_gen = dev_self_gen;
		cn_dev_pcie_info(pcie_set, "Init dev self gen as 0x%02x : %s\n",
						 dev_self_gen, PCIE_SPEED_STR(dev_self_gen));
	}
	for (bus = pdev->bus; !pci_is_root_bus(bus); bus = bus->parent) {
		pdev = bus->self;
		if (!pdev) {
			cn_dev_pcie_info(pcie_set, "pdev is null\n");
			return -1;
		}

		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &status);
		speed = status & PCI_EXP_LNKSTA_CLS;

		if (!narrow_gen) {
			cn_dev_pcie_info(pcie_set, "Try find narrowest ...\n");
			if (speed < narrowest_gen) {
				cn_dev_pcie_info(pcie_set, "Update narrowest_gen\n");
				narrowest_gen = speed;
			}
		} else {
			cn_dev_pcie_info(pcie_set, "Try find  LessEqual ...\n");
			if (speed <= narrow_gen) {
				cn_dev_pcie_info(pcie_set, "pcie bus:%x:%x:%x speed is %s. Mark LessEqual.\n",
						pdev->bus->number, pdev->devfn >> 3,
						pdev->devfn & 0x7, PCIE_SPEED_STR(speed));
				ret_gen = speed;
				cn_dev_pcie_info(pcie_set, "The first LessEqual is 0x%02x :%s.\n",
						 ret_gen, PCIE_SPEED_STR(speed));
				break;
			}
		}
	}
	if (!narrow_gen && (narrowest_gen != dev_self_gen)) {
		ret_gen = narrowest_gen;
		cn_dev_pcie_info(pcie_set, "The narrowest_gen is 0x%02x :%s.\n",
						 ret_gen, PCIE_SPEED_STR(narrowest_gen));
	}

	cn_dev_pcie_info(pcie_set, "ret_gen is 0x%02x : %s\n", ret_gen,
						PCIE_SPEED_STR(ret_gen));
	if (!ret_gen) {
		cn_dev_pcie_info(pcie_set, "Unknown means not find any will do nothing.\n");
	}

	return ret_gen;
}

static struct pci_dev *walkthrough_to_slot(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_bus *bus = pdev->bus;
	int i;

#define CN_C30_PCIE_SLOT (5)
	for (i = 0; i < CN_C30_PCIE_SLOT; i++, bus = bus->parent) {
		if (bus == NULL)
			return NULL;

		pdev = bus->self;
		if (!pdev) {
			cn_dev_info("pdev is null\n");
			return NULL;
		}
	}

	cn_dev_info("pcie slot bus:%x:%x:%x\n",
		pdev->bus->number, pdev->devfn >> 3, pdev->devfn & 0x7);
	return pdev;
}

static int cn_pci_set_pdev_cspeed(unsigned int speed, struct pci_dev *pdev)
{
	int ret;
	struct pci_dev *parent = pdev->bus->self;
	u16 link_status, lnkctl, lnkctl2;
	u16 current_speed, target_vector;
	u32 current_width, target_width;
	u32 reset_cnt = 20;

	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	target_width = current_width;
	target_vector = speed;

	cn_dev_info("PCIe link speed is %s", PCIE_SPEED_STR(current_speed));
	cn_dev_info("PCIe link width is x%d", current_width);
	cn_dev_info("PCIe target speed is %s", PCIE_SPEED_STR(speed));

	while ((current_speed != target_vector) ||
			(current_width != target_width)) {
retry:
		cn_dev_info("setting parent target link speed");
		ret = pcie_capability_read_word(parent, PCI_EXP_LNKCTL2,
						&lnkctl2);
		if (ret) {
			cn_dev_err("unable to read from PCI config");
			return -1;
		}

		cn_dev_info("old link control2: 0x%x", (u32)lnkctl2);

		/* only write to parent if target is not as high as ours */
		if ((lnkctl2 & PCI_EXP_LNKCTL2_TLS) != target_vector) {
			lnkctl2 &= ~PCI_EXP_LNKCTL2_TLS;
			lnkctl2 |= target_vector;
			cn_dev_info("new link control2: 0x%x", (u32)lnkctl2);
			ret = pcie_capability_write_word(parent,
					PCI_EXP_LNKCTL2, lnkctl2);
			if (ret) {
				cn_dev_err("unable to write to PCI config");
				return -1;
			}
		} else
			cn_dev_info("target speed is OK");

		cn_dev_info("setting target link speed");
		ret = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL2, &lnkctl2);
		if (ret) {
			cn_dev_err("unable to read from PCI config");
			return -1;
		}

		cn_dev_info("old link control2: 0x%x", (u32)lnkctl2);
		lnkctl2 &= ~PCI_EXP_LNKCTL2_TLS;
		lnkctl2 |= target_vector;
		cn_dev_info("new link control2: 0x%x", (u32)lnkctl2);
		ret = pcie_capability_write_word(pdev, PCI_EXP_LNKCTL2, lnkctl2);
		if (ret) {
			cn_dev_err("unable to write to PCI config");
			return -1;
		}

		ret = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL, &lnkctl);
		if (ret) {
			cn_dev_err("unable to read from PCI config PCIE_EXP_LNKCTL");
			return -1;
		}
		lnkctl |= PCI_EXP_LNKCTL_RL;
		ret = pcie_capability_write_word(pdev, PCI_EXP_LNKCTL, lnkctl);
		if (ret) {
			cn_dev_err("unable to write to PCI config LNKCTL RETRAIN");
			return -1;
		}
		msleep(500);
		reset_cnt--;

		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
		current_speed = link_status & PCI_EXP_LNKSTA_CLS;
		current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
		if (current_width > target_width)
			target_width = current_width;

		cn_dev_info("PCIe link change speed to %s\n", PCIE_SPEED_STR(current_speed));
		cn_dev_info("PCIe link change width to x%d\n", current_width);

		if (current_width != target_width && reset_cnt > 7)
			goto retry;

		if (reset_cnt == 0) {
			cn_dev_err("pcie change speed fail");
			return -1;
		}
	}
	return 0;
}

static int workaround_x8_m8_adapt_to_narrowest_path(struct cn_pcie_set *pcie_set)
{
	int ret = 0;
	int narrowest_gen = 0;
	u32 sn_flag = 0;
	struct pci_dev *pdev = NULL;
	u16 link_status;
	u32 current_speed;
	u32 current_width;

	pdev = pcie_set->pdev;
	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);
	current_speed = link_status & PCI_EXP_LNKSTA_CLS;
	current_width = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	/*
		check sn, Just for X4/X8 which have twins_chip in one card.
	*/
	sn_flag = cn_pci_reg_read32(pcie_set, IPC_5) & 0xFFFF;
	sn_flag = (sn_flag >> 8) & 0xFF;
	cn_dev_pcie_info(pcie_set, "sn_flag : %x\n", sn_flag);
	/*
		find the narrowest GenX from devSelf until RC(not including).
		and Set devSelf to the GenX.
		X8 0x54
		M8 0x55  0x58
	*/
	if (sn_flag == 0x54 || sn_flag == 0x58) {
		cn_dev_pcie_info(pcie_set, "Try find narrowest gen in the road...\n");
		narrowest_gen = walkthrough_rc_for_lower_genX(pcie_set, 0);
		if (narrowest_gen > 0) {
			cn_dev_pcie_info(pcie_set, "Found and set narrowest gen 0x%02x : %s\n",
				narrowest_gen, PCIE_SPEED_STR(narrowest_gen));
			cn_dev_pcie_info(pcie_set, "change [Gen%s x%d] to [Gen%s x%d]...\n",
						PCIE_SPEED_STR(current_speed), current_width,
						PCIE_SPEED_STR(narrowest_gen), current_width);
			ret = cn_pci_change_speed(pcie_set, narrowest_gen, current_width);
			if (ret) {
				cn_dev_pcie_err(pcie_set, "Set %s failed for narrowest_gen adapt.\n",
					PCIE_SPEED_STR(narrowest_gen));
			} else {
				cn_dev_pcie_info(pcie_set, "Set %s success for narrowest_gen adapt.\n",
					PCIE_SPEED_STR(narrowest_gen));
			}
		}
	}

	if (sn_flag == 0x55) {
		cn_dev_pcie_info(pcie_set, "Try find narrowest gen in the road...\n");
		narrowest_gen = walkthrough_rc_for_lower_genX(pcie_set, 0);
		if (narrowest_gen > 0) {
			cn_dev_pcie_info(pcie_set, "Found and set downlink to gen 0x%02x : %s\n",
				current_speed, PCIE_SPEED_STR(current_speed));

			pdev = walkthrough_to_slot(pcie_set);
			if (pdev) {
				ret = cn_pci_set_pdev_cspeed(PCI_EXP_LNKCTL2_TLS_8_0GT, pdev);

				if (ret) {
					cn_dev_pcie_err(pcie_set, "Set %s failed for narrowest_gen adapt.\n",
						PCIE_SPEED_STR(current_speed));
				} else {
					cn_dev_pcie_info(pcie_set, "Set %s success for narrowest_gen adapt.\n",
						PCIE_SPEED_STR(current_speed));
				}
			}
		}
	}

	return ret;
}

static void plx_switch_drop_poisoned_tlp(struct cn_pcie_set *pcie_set)
{
	u32 sn;
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_bus *bus = pdev->bus;
	int i;
	u16 status;

	sn = cn_pci_reg_read32(pcie_set, IPC_5) & 0xFFFF;
	sn = (sn >> 8) & 0xFF;

	/* X8 0x54 */
	if (sn != 0x54)
		return;

#define PLX_UPSTREAM_SLOT (4)
#define PLX_INGRESS_CONTROL (0xf60)
#define PLX_DROP_POISONED_BIT (0x1 << 9)

	for (i = 0; i < PLX_UPSTREAM_SLOT; i++, bus = bus->parent) {
		if (bus == NULL)
			return;

		pdev = bus->self;
		if (!pdev) {
			cn_dev_pcie_info(pcie_set, "pdev is null\n");
			return;
		}
	}

	pci_read_config_word(pdev, PLX_INGRESS_CONTROL, &status);
	cn_dev_pcie_info(pcie_set,
		"plx upstream slot %x:%x:%x, reg[0x%x]:%x",
			pdev->bus->number, pdev->devfn >> 3, pdev->devfn & 0x7,
			PLX_INGRESS_CONTROL, status);

	/* already set 1 */
	if ((status & PLX_DROP_POISONED_BIT) != 0)
		return;

	status |= PLX_DROP_POISONED_BIT;
	pci_write_config_dword(pdev, PLX_INGRESS_CONTROL, status);
}

__attribute__((unused)) static int is_pdev_slot(struct pci_dev *pdev)
{
	int type;

	type = pci_pcie_type(pdev);
	if (type == PCI_EXP_TYPE_ROOT_PORT || type == PCI_EXP_TYPE_DOWNSTREAM
		|| type == PCI_EXP_TYPE_PCIE_BRIDGE) {
		return (pcie_caps_reg(pdev) & PCI_EXP_FLAGS_SLOT);
	}
	return 0;
}

 __attribute__((unused))
 static int is_fault_link_slot(struct pci_dev *pdev, struct pci_dev *down_pdev,
				u16 speed, u16 current_width)
{
	u16 cap_speed, down_cap_speed;
	u16 cap_width, down_cap_width;
	u16 link_cap;
	pcie_capability_read_word(pdev, PCI_EXP_LNKCAP, &link_cap);
	cap_speed = link_cap & PCI_EXP_LNKCAP_SLS;
	cap_width = link_cap & PCI_EXP_LNKCAP_MLW;
	pcie_capability_read_word(down_pdev, PCI_EXP_LNKCAP, &link_cap);
	down_cap_speed = link_cap & PCI_EXP_LNKCAP_SLS;
	down_cap_width = link_cap & PCI_EXP_LNKCAP_MLW;

	if ((speed < cap_speed && speed < down_cap_speed)
			|| (current_width < cap_width && current_width < down_cap_width)) {
		return 1;
	}
	return 0;
}

__attribute__((unused))
static int less_than_g3X8(u16 speed, u16 current_width)
{
	if (speed == PCI_EXP_LNKCTL2_TLS_5_0GT ||
			speed == PCI_EXP_LNKCTL2_TLS_2_5GT ||
			current_width == PCI_EXP_LNKSTA_NLW_X1 ||
			current_width == PCI_EXP_LNKSTA_NLW_X2 ||
			current_width == PCI_EXP_LNKSTA_NLW_X4) {
			return 1;
	}
	return 0;
}

__attribute__((unused))
static int policy_check(struct pci_dev *pdev, struct cn_pcie_set *pcie_set, int checkbit)
{
	struct pci_bus *bus;
	u16 status, speed, current_width, linkcap;
	struct pci_dev *copy_pdev;
	struct pci_dev *down_pdev = NULL;
	int ret = 0;

	copy_pdev = pdev;
	down_pdev = pdev;
	for (bus = pdev->bus; !pci_is_root_bus(bus); bus = bus->parent) {
		pdev = bus->self;
		if (!pdev) {
			cn_dev_pcie_info(pcie_set, "pdev is null\n");
			return -1;
		}
		if (!is_pdev_slot(pdev)) {
			down_pdev = pdev;
			continue;
		}
		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &status);
		speed = status & PCI_EXP_LNKSTA_CLS;
		current_width = status & PCI_EXP_LNKSTA_NLW;
		linkcap = status & PCI_EXP_LNKCAP_SLS;
		switch (checkbit) {
		case 1:
			if (less_than_g3X8(speed, current_width)) {

				cn_dev_pcie_err(pcie_set,
						"less than g3X8 PCIe Device BDF:%x:%x:%x the PCIe Device speed is %s current_width is %s\n current link capability is %s\n",
						pdev->bus->number, pdev->devfn >> 3,
						pdev->devfn & 0x7, PCIE_SPEED_STR(speed),
						PCIE_WIDTH_STR(current_width), PCIE_LINKCAP_STR(linkcap));
				cn_dev_pcie_err(pcie_set,
						"less than g3X8 MLU Device BDF:%x:%x:%x\n", copy_pdev->bus->number,
						copy_pdev->devfn >> 3, copy_pdev->devfn & 0x7);
				ret = 1;
			}
			break ;
		case 2:
			if (is_fault_link_slot(pdev, down_pdev, speed, current_width)) {
				cn_dev_pcie_warn(pcie_set, "slot BDF:%x:%x:%x is not correct speed %s, width %s\n",
						pdev->bus->number,  pdev->devfn >> 3, pdev->devfn & 0x7,
						PCIE_SPEED_STR(speed), PCIE_WIDTH_STR(current_width));
			}
			break;
		default:
				cn_dev_pcie_info(pcie_set, "not support this policy check %d\n", checkbit);
				break;
		}
		down_pdev = pdev;
	}

	return ret;
}

__attribute__((unused)) static int
cn_pci_link_check(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	int ret;
	int bit = 0;
	int value = 0;
	int error = 0;

	cn_dev_pcie_info(pcie_set, "PCIe link check bits 0x%x\n", link_check);
	if (!link_check) {
		return 0;
	}
	value = link_check;
	do {
		bit++;
		if (value & 0x1) {
			ret = policy_check(pdev, pcie_set, bit);
			if (ret) {
				error++;
			}
		}
		value >>= 1;
	} while (value);

	if (error) {
		cn_dev_pcie_err(pcie_set, "PCIe link check has error\n");
		return -EACCES;
	}

	return 0;
}

static int c30s_bug_fix_list(struct cn_pcie_set *pcie_set)
{
	int ret = 0;
	u16 ctl;
	const char *dmi_board_name;
	struct pci_dev *pdev = pcie_set->pdev;

	dmi_board_name = dmi_get_system_info(DMI_BOARD_NAME);
	if (dmi_board_name)
		cn_dev_pcie_info(pcie_set, "system info dmi_board_name : %s\n", dmi_board_name);

	/*
	 * fix: retrain gen1 to gen3/gen4
	 */
#if (!defined(__arm__) && !defined(__aarch64__))
	if (dmi_board_name && strstr(dmi_board_name, "NF5498A5")) {
		ret = M83U_retrain_link_speed(pcie_set);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "retrain link speed fail");
			return -1;
		}
	} else {
		ret = c30s_retrain_link_speed(pcie_set);
		if (ret) {
			cn_dev_pcie_err(pcie_set, "retrain link speed fail");
			return -1;
		}
	}
#if (defined(__i386__) || defined(__x86_64__) || defined(__X86__))
	ret = cn_pci_link_check(pcie_set);
	if (ret) {
		return -EACCES;
	}
#endif
#else
	c30s_increase_cpl_timeout(pcie_set);
#endif

	/*
	 * Disable: PCIe ASPM L0s L1
	 */
	ret = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL, &ctl);
	if (!ret) {
		ctl &= ~(PCI_EXP_LNKCTL_ASPM_L1 | PCI_EXP_LNKCTL_ASPM_L0S);
		ret = pcie_capability_write_word(pdev, PCI_EXP_LNKCTL, ctl);
	}
	if (ret) {
		cn_dev_pcie_err(pcie_set, "disable aspm fail");
	}

	/*
	 * fix: change outbound slv from no-snoop to snoop
	 */
	cn_pci_reg_write32(pcie_set, SLV0_SNOOP_SET_REG, 0x30);

	/*
	 * Add workaroud for X8/M8 to adapt to narrowest_gen.
	 */
	ret = workaround_x8_m8_adapt_to_narrowest_path(pcie_set);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "X8/M8 adapt to narrowest_gen fail");
	}

	/*
	 * fix: Turn on extended tags in DevCtl
	 */
	ret = pcie_capability_read_word(pdev, PCI_EXP_DEVCTL, &ctl);
	if (ret)
		return 0;

	if (!(ctl & PCI_EXP_DEVCTL_EXT_TAG)) {
		cn_dev_pcie_info(pcie_set, "enabling Extended Tags\n");
		pcie_capability_set_word(pdev, PCI_EXP_DEVCTL,
				PCI_EXP_DEVCTL_EXT_TAG);
	}

	/*
	 * X8 PLX switch drop poisoned TLP
	 */
	plx_switch_drop_poisoned_tlp(pcie_set);

	return ret;
}

static int c30s_pcie_setup(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/*
	 *  publish ops to uper level
	 *  different cambricon ID have different ops
	 *  same cambricon ID with different wafer, change ops here
	 */
	cn_pci_ops_init(&public_ops, &c30s_private_ops);
	pcie_set->ops = &c30s_private_ops;

	/* only pf will do pcie_setup */
#if defined(__x86_64__)
	if (!cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn))
		pcie_set->arm_trigger_enable = arm_trigger_enable;
#endif
	/* for domain manger get hard resource */
	if (pcie_set->arm_trigger_enable) {
		pcie_set->max_phy_channel = HOST_PHY_CHANNEL_NUM;
	} else {
		pcie_set->max_phy_channel = INTR_DMA_CHANNEL_NUM;
	}
	pcie_set->spkg_channel_id = SMALL_PACKET_CHANNEL_ID;

	if (pcie_set->dma_fetch_enable) {
		pcie_set->dma_fetch_buff = DMA_FETCH_BUFF;
		pcie_set->spkg_dma_fetch_buff = SPKG_DMA_FETCH_BUFF;
	} else {
		pcie_set->dma_fetch_buff = 1;
		pcie_set->spkg_dma_fetch_buff = 1;
	}

	/* soft status */
	pcie_set->share_mem_cnt = 0;
	pcie_set->is_virtfn = 0;

	if (isr_type_index == -1) {
		if (isr_default_type == MSI) /* workaround for deadlock */
			pcie_set->irq_type = MSIX;
		else
			pcie_set->irq_type = isr_default_type;
	} else {
		pcie_set->irq_type = isr_type_index;
	}
	return 0;
}

static int c30s_pcie_domain_get_resource(void *pcie, struct domain_resource *resource)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	/* for domain manger get hard resource */
	resource->id = pcie_set->id;
	resource->max_phy_channel = DMA_REG_CHANNEL_NUM;
	resource->cfg_reg_size = AXI_CONFIG_SIZE;
	resource->share_mem_base = C30S_AXI_SHM_BASE;
	resource->share_mem_size = pcie_set->pcibar[0].size / 2; // MAX=128MB
	resource->vf_cfg_limit = 8 * 1024;
	resource->ob_mask = ((u64)((1ULL << OUTBOUND_CNT) - 1)) << OUTBOUND_FIRST;
	resource->ob_set[0].virt_addr = pcie_set->share_mem[1].virt_addr;
	resource->ob_set[0].win_length = pcie_set->share_mem[1].win_length;
	resource->ob_set[0].ob_axi_base = pcie_set->share_mem[1].device_addr;

	return 0;
}

static int pcie_reg_shm_bar_init(struct cn_pcie_set *pcie_set,
				u64 bar0_mem_offset, u64 bar0_mem_size)
{
	struct pcibar_seg_s *p_bar_seg;
	struct pcibar_s *p_bar;

	/* Init bar 0 */
	p_bar = &pcie_set->pcibar[0];

	/* the register area */
	p_bar_seg = &p_bar->seg[0];
	p_bar_seg->size = p_bar->size / 2;
	p_bar_seg->base = p_bar->base;
	p_bar_seg->virt = cn_ioremap(p_bar_seg->base, p_bar_seg->size);
	if (!p_bar_seg->virt)
		goto ERROR_RET;
	cn_dev_pcie_debug(pcie_set, "bar0 register virt:%p", p_bar_seg->virt);

	pcie_set->reg_virt_base = p_bar_seg->virt;
	pcie_set->reg_phy_addr = p_bar_seg->base;
	pcie_set->reg_win_length = p_bar_seg->size;

	/* the bar share memory */
	p_bar_seg = &p_bar->seg[1];
	p_bar_seg->base = p_bar->base + pcie_set->reg_win_length;
	p_bar_seg->size = p_bar->size - pcie_set->reg_win_length;
	p_bar_seg->virt = cn_ioremap_wc(p_bar_seg->base, p_bar_seg->size);
	if (!p_bar_seg->virt)
		goto ERROR_RET;
	cn_dev_pcie_debug(pcie_set, "bar0 memory virt:%p", p_bar_seg->virt);

	pcie_set->share_mem_cnt = 1;
	pcie_set->share_mem[0].virt_addr =
		pcie_set->pcibar[0].seg[1].virt + bar0_mem_offset;
	pcie_set->share_mem[0].phy_addr =
		pcie_set->pcibar[0].seg[1].base + bar0_mem_offset;
	pcie_set->share_mem[0].win_length = bar0_mem_size;
	pcie_set->share_mem[0].type = CN_SHARE_MEM_DEV;
	pcie_set->share_mem[0].device_addr = -1;

	return 0;

ERROR_RET:
	cn_dev_pcie_err(pcie_set, "pcie bar init error");
	bar_deinit(pcie_set);

	return -1;
}

static int c30s_pcie_bar_init(struct cn_pcie_set *pcie_set)
{
	u8 i;
	u32 func_id;
	u64 offset, size;
	const void *domain = NULL;
	struct c30s_priv_set *p_set = NULL;
	struct c30s_bar0_set *bar0_set = NULL;

	if (cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		domain = cn_dm_get_domain_early(pcie_set->bus_set,
							DM_FUNC_OVERALL);
		if (!domain)
			return -ENODEV;

		func_id = cn_dm_get_func_id(domain);
		cn_dev_pcie_info(pcie_set, "Domain[%d: 0x%px]", func_id, domain);

		offset = cn_dm_pci_get_bars_shm_bs(domain, 0);
		size = cn_dm_pci_get_bars_shm_sz(domain, 0);
	} else {
		offset = 0;
		size = pcie_set->pcibar[0].size / 2;
	}

	cn_dev_pcie_debug(pcie_set, "get from domain offset:%#llx size:%#llx",
						offset, size);

	if (pcie_reg_shm_bar_init(pcie_set, offset, size))
		return -1;
	pcie_set->share_mem[0].device_addr = C30S_AXI_SHM_BASE + offset;

	/* c30s priv_set bar0 window set*/
	if (pcie_set->priv_set) {
		p_set = (struct c30s_priv_set *)pcie_set->priv_set;
		bar0_set = &p_set->bar0_set;
		if (!bar0_set) {
			cn_dev_pcie_info(pcie_set, "kzalloc bar0_set error");
			goto RELEASE_BAR;
		}
		for (i = 0; i < 4; i++)
			sema_init(&bar0_set->bar0_window_sem[i], 1);
	}

	return 0;

RELEASE_BAR:
	bar_deinit(pcie_set);

	return -1;
}

static int c30s_pcie_set_bar0_window(struct cn_pcie_set *pcie_set)
{
	int i = 0;
	int bar0_mode = 0;
	struct c30s_bar0_set *bar0_set = NULL;

	bar0_set = (struct c30s_bar0_set *)pcie_set->priv_set;
	for (i = 0; i < 4; i++) {
		//config:
		if (!pcie_set->pcibar[0].size) {
			cn_dev_pcie_err(pcie_set, "bar0 size is zero");
			return -1;
		}
		bar0_mode = BAR0_MAX_SIZE / pcie_set->pcibar[0].size;
		if (!bar0_mode) {
			cn_dev_pcie_err(pcie_set, "win_size is zero");
			return -1;
		}
		//bar0 16M(no change) + 32M(change window(3~6)) for 128M config of per a quad
		bar0_set->bar0_window_base = 0x10/bar0_mode;
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_SRC_WIN(3 + i), 0x80010 + (i) * (0x10/bar0_mode));
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_MASK_WIN(3 + i), (0xFFFFFF0 | (0x10/bar0_mode)));
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_TGT_WIN(3 + i), 0x80000 + (i) * 0x80);//bar0 128M * 4 quad
		//share mem:
		//bar0 32M(change window(7~10) for 128M mem of per a quad
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_SRC_WIN(7 + i), 0x80000 + (4 + i) * (0x20/bar0_mode));
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_MASK_WIN(7 + i), (0xFFFFFE0 | (0x20/bar0_mode)));
		cn_pci_reg_write32(pcie_set,
			BAR0_TO_AXI_TGT_WIN(7 + i), (C30S_AXI_SHM_BASE >> 20) + (i) * (0x20/bar0_mode));
	}
	cn_pci_reg_write32(pcie_set, PF_SHARE_MEM_MASK, 0xFFFFF80);//share memory 128M
	cn_pci_reg_write32(pcie_set, PF_SHARE_MEM_BASE, (C30S_AXI_SHM_BASE >> 20));//share memory 128M
	cn_pci_reg_read32(pcie_set, PF_SHARE_MEM_MASK);//must add read

	return 0;
}

static int c30s_set_bar_default_window(struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar;
	int order;

	list_for_each_entry(bar, &pcie_set->bar_resource_head, list) {
		bar->window_addr = 0;
		order = ilog2(bar->size / BAR_BASE_SIZE);
		cn_pci_reg_write64(pcie_set, PF_BAR_ADDR_MASK(bar->index),
				(0xFFFFFFFULL << order) & 0xFFFFFFFULL);
		cn_pci_reg_read32(pcie_set, PF_BAR_ADDR_MASK(bar->index));
		cn_dev_pcie_debug(pcie_set, "bar->index:%d bar->size:%#llx addr_mask:%#llx",
			bar->index, bar->size, (0xFFFFFFFULL << order) & 0xFFFFFFFULL);
	}

	return c30s_pcie_set_bar0_window(pcie_set);
}

static int c30s_pcie_dma_pre_init(struct cn_pcie_set *pcie_set)
{
	const void *domain = NULL;

	if (cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		domain = cn_dm_get_domain_early(pcie_set->bus_set,
							DM_FUNC_OVERALL);
		if (!domain)
			return -ENODEV;

		pcie_set->dma_phy_channel_mask = cn_dm_pci_get_dma_ch(domain);
	} else {
		if (pcie_set->arm_trigger_enable)
			pcie_set->dma_phy_channel_mask = HOST_PHY_CHANNEL_MASK;
		else
			pcie_set->dma_phy_channel_mask = INTR_DMA_CHANNEL_MASK;
	}

	cn_dev_pcie_debug(pcie_set, "get from domain mask:%#x",
					pcie_set->dma_phy_channel_mask);

	pcie_set->shared_desc_total_size = SHARED_DMA_DESC_TOTAL_SIZE;
	pcie_set->priv_desc_total_size = PRIV_DMA_DESC_TOTAL_SIZE;
	pcie_set->dma_buffer_size = DMA_BUFFER_SIZE;
	pcie_set->per_desc_size = DMA_DESC_PER_SIZE;
	pcie_set->per_desc_max_size = PER_DESC_MAX_SIZE;

	pcie_set->async_static_task_num = ASYNC_STATIC_TASK_NUM;
	pcie_set->async_max_desc_num = ASYNC_MAX_DESC_NUM;
	pcie_set->async_desc_size = ASYNC_DMA_DESC_TOTAL_SIZE;
	pcie_set->async_desc_num = pcie_set->async_desc_size /
					pcie_set->per_desc_size;

	return 0;
}

static int pcie_dma_interrupt_init(struct cn_pcie_set *pcie_set)
{
	int i;
	char src[30];
	static const int interrupt_count[] = {MSI_COUNT, MSIX_COUNT, INTX_COUNT};

	pcie_set->irq_num = interrupt_count[pcie_set->irq_type];

	/* fix msix ram bug by writing msix ram*/
	if (pcie_set->irq_type == MSIX)
		fill_msix_ram(pcie_set);

	do {
		if (isr_enable_func[pcie_set->irq_type](pcie_set) == 0)
			break;

		if (pcie_set->irq_type == MSIX) {
			pcie_set->irq_type = MSI;
			pcie_set->irq_num = interrupt_count[pcie_set->irq_type];
		} else if (pcie_set->irq_type == MSI) {
			pcie_set->irq_type = INTX;
			pcie_set->irq_num = interrupt_count[pcie_set->irq_type];
		} else if (pcie_set->irq_type == INTX) {
			cn_dev_pcie_err(pcie_set, "isr init failed!");
			return -1;
		}
	} while (1);

	pcie_gic_mask_all(pcie_set);

	pcie_set->irq_str_index_ptr = irq_str_index;
	if (pcie_set->dma_fetch_enable) {
		cn_pci_reg_write32(pcie_set,
				PCIE_DMA_CTRL_TYPE, DMA_REG_CHANNEL_MASK);
		cn_pci_reg_read32(pcie_set, PCIE_DMA_CTRL_TYPE);
	} else {
		cn_pci_reg_write32(pcie_set,
				PCIE_DMA_CTRL_TYPE, 0);
		cn_pci_reg_read32(pcie_set, PCIE_DMA_CTRL_TYPE);
	}
	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_phy_channel_mask & (1 << i)) {
			sprintf(src, "pcie_dma%d", i);
			if (pcie_set->dma_fetch_enable) {
				cn_pci_register_interrupt(
					pcie_get_irq(src, pcie_set),
					pcie_dma_fetch_interrupt_handle, pcie_set, pcie_set);
			} else {
				cn_pci_register_interrupt(
					pcie_get_irq(src, pcie_set),
					pcie_dma_interrupt_handle, pcie_set, pcie_set);
			}
		}
	}

	return 0;
}

static int pcie_interrupt_exit(struct cn_pcie_set *pcie_set)
{
	int i;
	struct cn_bus_set *bus_set = pcie_set->bus_set;
	char src[30];

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_phy_channel_mask & (1 << i)) {
			sprintf(src, "pcie_dma%d", i);
			cn_pci_unregister_interrupt(
					pcie_get_irq(src, pcie_set), pcie_set);
		}
	}

	bus_set->ops->disable_all_irqs(pcie_set);
	if (isr_disable_func[pcie_set->irq_type](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr destroyed failed!");
		return -1;
	}

	if (pcie_set->irq_type == MSIX) {
		for (i = 0; i < (GIC_INTERRUPT_NUM * 4); i++)
			pcie_set->msix_ram[i] =
				cn_pci_reg_read32(pcie_set, (GBO + i * 4));
	}

	return 0;
}

static int c30s_arm_trigger_init(struct cn_pcie_set *pcie_set)
{
	/* arm use ARM_TRIGGER_ARM_PHY_CHANNEL to determine
	 * whether to support arm trigger dma
	 */
	if (pcie_set->arm_trigger_enable) {
		cn_pci_reg_write32(pcie_set, ARM_TRIGGER_ARM_PHY_CHANNEL, ARM_PHY_CHANNEL_NUM);
		cn_pci_reg_write32(pcie_set, ARM_TRIGGER_HOST_PHY_CHANNEL, HOST_PHY_CHANNEL_NUM);
	} else {
		cn_pci_reg_write32(pcie_set, ARM_TRIGGER_HOST_PHY_CHANNEL, INTR_DMA_CHANNEL_NUM);
		cn_pci_reg_write32(pcie_set, ARM_TRIGGER_ARM_PHY_CHANNEL, 0);
	}
	if (pcie_set->dma_fetch_enable)
		cn_pci_reg_write32(pcie_set, ARM_TRIGGER_DMA_FETCH_ENABLE, 1);
	else
		cn_pci_reg_write32(pcie_set, ARM_TRIGGER_DMA_FETCH_ENABLE, 0);

	return 0;
}

static int pcie_pre_init_hw(struct cn_pcie_set *pcie_set)
{
	int i;
	char src[30];
	unsigned int status;
	int fetch_status_buf_num;
	int status_buf_full;
	int status_buf_empty;

	c30s_set_bar_default_window(pcie_set);

	if (pcie_set->outbound_able)
		pcie_outbound_reg(pcie_set);

	if (pcie_set->data_outbound_able)
		c30s_pcie_data_outbound_reg(pcie_set);

	if (pcie_set->ops->isr_hw_enable)
		pcie_set->ops->isr_hw_enable(pcie_set);

	pcie_gic_mask_all(pcie_set);

	/* NOTE: clear dma interrupt before enable it(nomal mode and fetch mode)*/
	/* nomal mode*/
	if (!pcie_set->dma_fetch_enable) {
		status = cn_pci_reg_read32(pcie_set, DISTATUS_LOCAL);
		cn_pci_reg_write32(pcie_set, DISTATUS_LOCAL, status);
	}
	/* fetch mode*/
	for (i = 0; i < DMA_REG_CHANNEL_NUM; i++) {
		fetch_status_buf_status(i, &fetch_status_buf_num, &status_buf_full,
						&status_buf_empty, pcie_set);

		while (fetch_status_buf_num) {
			cn_pci_reg_write32(pcie_set, DMA_STATUS_UP_FETCH(i), 1);
			fetch_status_buf_num--;
		}
	}

	/* reset the binding relationship between vf and dma engine */
	for (i = 0; i < DMA_REG_CHANNEL_NUM; i++)
		c30s_pcie_free_dmach(pcie_set, i);

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_phy_channel_mask & (1 << i)) {
			sprintf(src, "pcie_dma%d", i);
			pcie_gic_unmask(pcie_get_irq(src, pcie_set), pcie_set);
		}
		if (pcie_set->dma_fetch_enable)
			cn_pci_reg_write32(pcie_set, PCIE_IRQ_MASK(i), 0x3);
		else
			cn_pci_reg_write32(pcie_set, PCIE_IRQ_MASK(i), 0x4);
	}
	cn_pci_reg_write32(pcie_set, PCIE_IRQ_MASK(pcie_set->spkg_channel_id), 0x7);
	cn_pci_reg_write32(pcie_set, DIMASK_LOCAL, 0xFFFF);
	cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);

	c30s_arm_trigger_init(pcie_set);

	return 0;
}

static int c30s_pcie_priv_set_alloc(struct cn_pcie_set *pcie_set)
{
	struct c30s_priv_set *p_set;

	p_set = cn_kzalloc(sizeof(struct c30s_priv_set), GFP_KERNEL);
	if (!p_set) {
		cn_dev_pcie_info(pcie_set, "kzalloc priv_set error");
		return -ENOMEM;
	}

	pcie_set->priv_set = p_set;

	return 0;
}

static void pcie_priv_set_free(struct cn_pcie_set *pcie_set)
{
	c30s_pcie_data_outbound_exit(pcie_set);
}

static int c30s_check_noc_bus(struct cn_pcie_set *pcie_set)
{
	u32 reg_data;

	/* check NOC bus status */
	reg_data = cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
	if (reg_data == REG_VALUE_INVALID) {
		cn_dev_pcie_err(pcie_set, "NOC bus abnormal, read value = %#x", reg_data);
		return -1;
	}

	return 0;
}

static void c30s_check_outbound_ar_cnt(struct cn_pcie_set *pcie_set)
{
	struct c30s_priv_set *p_set;
	struct data_outbound_set *dob_set;
	u32 ar_cnt;

	if (!pcie_set->priv_set)
		return;
	p_set = (struct c30s_priv_set *)pcie_set->priv_set;
	dob_set = &p_set->dob_set;

	ar_cnt = cn_pci_reg_read32(pcie_set, SLV_WIN_AR_CNT);
	ar_cnt &= 0xff;
	ar_cnt -= dob_set->dob_ar_cnt;
	if (ar_cnt) {
		cn_dev_pcie_err(pcie_set, "someone used data outbound read, read cnt = %#x", ar_cnt);
		/* driver_test check call trace */
		dump_stack();
	}

	return;
}

static int c30s_pcie_pre_init(void *pcie)
{
	int ret = 0;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	ret = c30s_pcie_priv_set_alloc(pcie_set);
	if (ret)
		return -1;

	ret = c30s_pcie_bar_init(pcie_set);
	if (ret)
		return -1;

	ret = c30s_check_noc_bus(pcie_set);
	if (ret)
		return -1;

	ret = c30s_bug_fix_list(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = c30s_pcie_dma_pre_init(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	ret = pcie_register_bar(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	outbound_pre_init(pcie_set);

	/* TODO: where should I put this? here or plat/pcie/mlu370/haikouichthys/haikouichthys.h */
	if (cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		ret = cn_pci_register_interrupt(PCIE_PF_MBX_IRQ,
				c30s_pcie_pf_mailbox_handle,
				pcie_set,
				pcie_set);
		if (ret)
			goto RELEASE_BAR;
	}

	ret = do_pcie_init(pcie_set);
	if (ret)
		goto RELEASE_BAR;

	return 0;
RELEASE_BAR:
	bar_deinit(pcie_set);
	return -1;
}

static int c30s_pcie_pre_exit(void *pcie)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie;

	if (pcie_interrupt_exit(pcie_set))
		return -1;

#ifdef USE_DATA_OUTBOUND
	pcie_priv_set_free(pcie_set);
#endif
	pcie_outbound_exit(pcie_set);
	c30s_check_outbound_ar_cnt(pcie_set);
	bar_deinit(pcie_set);

	return 0;
}

struct cn_pci_info c30s_pci_info = {
	.setup = c30s_pcie_setup,
	.pre_init = c30s_pcie_pre_init,
	.pre_exit = c30s_pcie_pre_exit,
	.get_resource = c30s_pcie_domain_get_resource,
	.dev_name = "c30s"
};
