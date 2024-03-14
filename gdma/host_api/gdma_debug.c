/*
 * gdma/gdma_debug.h
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

#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "gdma_desc.h"
#include "gdma_debug.h"
#include "gdma_common_api.h"

void cn_gdma_dbg_show_run_status(struct cn_gdma_set *gdma_set)
{
	int i;
	struct cn_gdma_virt_chan *vchan = NULL;
	struct cn_gdma_phy_chan *pchan = NULL;

	if (likely(!(gdma_set->debug_print & SHOW_RUN_STATUS_MASK))) {
		return;
	}

	for (i = 0; i < gdma_set->vchan_num; i++) {
		vchan = gdma_set->vchan_pool[i];
		cn_dev_gdma_info(gdma_set, "vchan %d status %d",
					vchan->idx, vchan->status);
	}

	for (i = 0; i < gdma_set->total_pchan_num; i++) {
		pchan = gdma_set->pchan_pool[i];
		cn_dev_gdma_info(gdma_set,
			"pchan %d.%d status %d",
			pchan->ctrl->idx, pchan->idx,
			pchan->status);
	}
}

void cn_gdma_dbg_show_ctrl_info(struct cn_gdma_set *gdma_set,
		struct cn_gdma_controller *ctrl)
{
	cn_dev_gdma_debug(gdma_set, "Controller %d:", ctrl->idx);
	cn_dev_gdma_debug(gdma_set, "main_csr_base 0x%lx", ctrl->main_csr_base);
	cn_dev_gdma_debug(gdma_set, "top_csr_base 0x%lx", ctrl->top_csr_base);
	cn_dev_gdma_debug(gdma_set, "smmu_base 0x%lx", ctrl->smmu_base);
	cn_dev_gdma_debug(gdma_set, "ctrl pchan_num %d", ctrl->pchan_num);
	cn_dev_gdma_debug(gdma_set, "ctrl irq %d", ctrl->irq);
}

void cn_gdma_dbg_ctrl_reg_dump(struct cn_gdma_set *gdma_set,
		struct cn_gdma_controller *ctrl)
{
	ctrl->ops->ctrl_reg_dump(ctrl);
}

void cn_gdma_dbg_show_chan_info(struct cn_gdma_set *gdma_set,
		struct cn_gdma_phy_chan *channel)
{
	cn_dev_gdma_debug(gdma_set, "Channel %d.%d:", channel->ctrl->idx, channel->idx);
	cn_dev_gdma_debug(gdma_set, "base 0x%lx", channel->base);
	cn_dev_gdma_debug(gdma_set, "irq %d", channel->irq);
}

void cn_gdma_dbg_chan_reg_dump(struct cn_gdma_set *gdma_set,
		struct cn_gdma_phy_chan *channel)
{
	channel->ctrl->ops->channel_reg_dump(channel);
}

void cn_gdma_dbg_show_package(struct cn_gdma_set *gdma_set,
		struct cn_gdma_package *package)
{
	if (likely(!gdma_set->debug_print)) {
		return;
	}

	cn_dev_gdma_debug(gdma_set, "type %d", package->type);
	cn_dev_gdma_debug(gdma_set, "src:%#llx", package->src);
	cn_dev_gdma_debug(gdma_set, "dst:%#llx", package->dst);
	cn_dev_gdma_debug(gdma_set, "len:%#llx", package->len);
}

void cn_gdma_dbg_show_contex_0_desc(struct cn_gdma_set *gdma_set,
		struct gdma_contex_type_0_desc *desc)
{
	if (likely(!gdma_set->debug_print)) {
		return;
	}

	cn_dev_gdma_debug(gdma_set, "fixpattern 0x%x", desc->fixed_pattern);
	cn_dev_gdma_debug(gdma_set, "type 0x%x", desc->type);
	cn_dev_gdma_debug(gdma_set, "OWN %d", desc->OWN);
	cn_dev_gdma_debug(gdma_set, "HALT %d", desc->HALT);
	cn_dev_gdma_debug(gdma_set, "FC %d", desc->FC);
	cn_dev_gdma_debug(gdma_set, "prog_rblen_7_0 %d", desc->prog_rblen_7_0);
	cn_dev_gdma_debug(gdma_set, "prog_wblen_7_0 %d", desc->prog_wblen_7_0);
	cn_dev_gdma_debug(gdma_set, "read_ostd_4_0 %d", desc->read_ostd_4_0);
	cn_dev_gdma_debug(gdma_set, "write_ostd_4_0 %d", desc->write_ostd_4_0);
	cn_dev_gdma_debug(gdma_set, "src_addr_47_40 0x%x", desc->src_addr_47_40);
	cn_dev_gdma_debug(gdma_set, "dst_addr_47_40 0x%x", desc->dst_addr_47_40);
	cn_dev_gdma_debug(gdma_set, "nxt_dscrpt_addr_47_32 0x%x",
					desc->nxt_dscrpt_addr_47_32);
	cn_dev_gdma_debug(gdma_set, "nxt_dscrpt_addr_31_0 0x%x",
					desc->nxt_dscrpt_addr_31_0);
}

void cn_gdma_dbg_show_contex_0_pigeon_desc(struct cn_gdma_set *gdma_set,
		struct gdma_contex_type_0_pigeon_desc *desc)
{
	if (likely(!gdma_set->debug_print)) {
		return;
	}

	cn_dev_gdma_debug(gdma_set, "fixpattern 0x%x", desc->fixed_pattern);
	cn_dev_gdma_debug(gdma_set, "type 0x%x", desc->type);
	cn_dev_gdma_debug(gdma_set, "OWN %d", desc->OWN);
	cn_dev_gdma_debug(gdma_set, "HALT %d", desc->HALT);
	cn_dev_gdma_debug(gdma_set, "FC %d", desc->FC);
	cn_dev_gdma_debug(gdma_set, "prog_rblen_7_0 %d", desc->prog_rblen_7_0);
	cn_dev_gdma_debug(gdma_set, "prog_wblen_7_0 %d", desc->prog_wblen_7_0);
	cn_dev_gdma_debug(gdma_set, "read_ostd_4_0 %d", desc->read_ostd_4_0);
	cn_dev_gdma_debug(gdma_set, "write_ostd_4_0 %d", desc->write_ostd_4_0);
	cn_dev_gdma_debug(gdma_set, "compress_type_3_0 %d", desc->aw_compress_type_3_0);
	cn_dev_gdma_debug(gdma_set, "compress_en %d", desc->aw_compress_en);
	cn_dev_gdma_debug(gdma_set, "compress_overwrite %d", desc->aw_compress_overwrite);
	cn_dev_gdma_debug(gdma_set, "src_addr_47_40 0x%x", desc->src_addr_47_40);
	cn_dev_gdma_debug(gdma_set, "dst_addr_47_40 0x%x", desc->dst_addr_47_40);
	cn_dev_gdma_debug(gdma_set, "nxt_dscrpt_addr_47_32 0x%x",
					desc->nxt_dscrpt_addr_47_32);
	cn_dev_gdma_debug(gdma_set, "nxt_dscrpt_addr_31_0 0x%x",
					desc->nxt_dscrpt_addr_31_0);
}


void cn_gdma_dbg_show_contex_1_desc(struct cn_gdma_set *gdma_set,
		struct gdma_contex_type_1_desc *desc)
{
	if (likely(!gdma_set->debug_print)) {
		return;
	}

	cn_dev_gdma_debug(gdma_set, "fixpattern 0x%x", desc->fixed_pattern);
	cn_dev_gdma_debug(gdma_set, "type 0x%x", desc->type);
	cn_dev_gdma_debug(gdma_set, "OWN %d", desc->OWN);
	cn_dev_gdma_debug(gdma_set, "HALT %d", desc->HALT);
	cn_dev_gdma_debug(gdma_set, "SOD %d", desc->SOD);
	cn_dev_gdma_debug(gdma_set, "dim1_len_19_5 0x%x", desc->dim1_len_19_5);
	cn_dev_gdma_debug(gdma_set, "dim1_len_4_0 0x%x", desc->dim1_len_4_0);
	cn_dev_gdma_debug(gdma_set, "dim2_en %d", desc->dim2_en);
	cn_dev_gdma_debug(gdma_set, "dim2_len_19_15 0x%x", desc->dim2_len_19_15);
	cn_dev_gdma_debug(gdma_set, "dim2_len_14_0 0x%x", desc->dim2_len_14_0);
	cn_dev_gdma_debug(gdma_set, "dim2_stride_21_0 %d", desc->dim2_stride_21_0);
	cn_dev_gdma_debug(gdma_set, "dim3_en %d", desc->dim3_en);
	cn_dev_gdma_debug(gdma_set, "dim3_stride_47_32 0x%x",
					desc->dim3_stride_47_32);
	cn_dev_gdma_debug(gdma_set, "dim3_stride_31_0 0x%x",
								desc->dim3_stride_31_0);
	cn_dev_gdma_debug(gdma_set, "dim3_stride_sign %d", desc->dim3_stride_sign);
	cn_dev_gdma_debug(gdma_set, "nxt_dscrpt_addr_47_32 0x%x",
					desc->nxt_dscrpt_addr_47_32);
	cn_dev_gdma_debug(gdma_set, "nxt_dscrpt_addr_31_0 0x%x",
					desc->nxt_dscrpt_addr_31_0);
}

void cn_gdma_dbg_show_normal_desc(struct cn_gdma_set *gdma_set,
		struct gdma_normal_desc *desc)
{
	if (likely(!gdma_set->debug_print)) {
		return;
	}

	cn_dev_gdma_debug(gdma_set, "fixpattern 0x%x", desc->fixed_pattern);
	cn_dev_gdma_debug(gdma_set, "type 0x%x", desc->type);
	cn_dev_gdma_debug(gdma_set, "OWN %d", desc->OWN);
	cn_dev_gdma_debug(gdma_set, "HALT %d", desc->HALT);
	cn_dev_gdma_debug(gdma_set, "IOBC %d", desc->IOBC);
	cn_dev_gdma_debug(gdma_set, "FD %d", desc->FD);
	cn_dev_gdma_debug(gdma_set, "LD %d", desc->LD);
	cn_dev_gdma_debug(gdma_set, "SNS %d", desc->SNS);
	cn_dev_gdma_debug(gdma_set, "DNS %d", desc->DNS);
	cn_dev_gdma_debug(gdma_set, "src_addr_39_24 0x%x", desc->src_addr_39_24);
	cn_dev_gdma_debug(gdma_set, "src_addr_23_0 0x%x", desc->src_addr_23_0);
	cn_dev_gdma_debug(gdma_set, "dst_addr_39_32 0x%x", desc->dst_addr_39_32);
	cn_dev_gdma_debug(gdma_set, "dst_addr_31_0 0x%x", desc->dst_addr_31_0);
	cn_dev_gdma_debug(gdma_set, "data_len_23_16 0x%x", desc->data_len_23_16);
	cn_dev_gdma_debug(gdma_set, "data_len_15_0 0x%x", desc->data_len_15_0);
	cn_dev_gdma_debug(gdma_set, "nxt_dscrpt_addr_47_32 0x%x",
					desc->nxt_dscrpt_addr_47_32);
	cn_dev_gdma_debug(gdma_set, "nxt_dscrpt_addr_31_0 0x%x",
					desc->nxt_dscrpt_addr_31_0);
}

void cn_gdma_dbg_dump_desc(struct cn_gdma_set *gdma_set,
		struct cn_shm *desc)
{
	u32 rd_value;
	int i;

	if (likely(!gdma_set->debug_print)) {
		return;
	}

	for (i = 0; i < 8; i++) {
		rd_value = ioread32((void *)(desc->host_kva + i * 4));
		cn_dev_gdma_debug(gdma_set, "DESC %d: 0x%x", i, rd_value);
	}
}
