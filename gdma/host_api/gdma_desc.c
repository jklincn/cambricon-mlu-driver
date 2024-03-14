/*
 * gdma/gdma_desc.c
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
#include <linux/delay.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "gdma_desc.h"
#include "gdma_debug.h"
#include "gdma_hal.h"
#include "gdma_common_api.h"

static void gdma_build_context_1_desc_param(struct cn_gdma_set *gdma_set,
		int type, struct context_1_desc_param *context1_param)
{
	switch (type) {
	case GDMA_MEMCPY:
		break;
	case GDMA_MEMSET_D8:
	case GDMA_MEMSET_D16:
	case GDMA_MEMSET_D32:
	case GDMA_MEMSET_D64:
		context1_param->dim2_en = 0x1;
		context1_param->dim1_len = cn_gdma_get_memset_buf_size(gdma_set);
		break;
	case GDMA_MEMCPY_2D:
	case GDMA_MEMCPY_3D:
	default:
		cn_dev_gdma_err(gdma_set, "build contex 1 desc param type invalid");
		break;
	}
}

static void gdma_fill_contex_type_0_desc(struct cn_gdma_set *gdma_set,
		struct cn_gdma_package *pkg,
		struct cn_shm *cur_desc,
		struct cn_shm *next_desc)
{
	struct gdma_contex_type_0_desc contex_type_0_desc = {0};
	struct gdma_contex_type_0_desc *pdesc = &contex_type_0_desc;

	pdesc->fixed_pattern = GDMA_FIXED_PATTERN;
	pdesc->OWN = DESC_OWN_DMA;
	pdesc->type = DESC_DT_CONTEX_0;

	pdesc->dst_addr_47_40 = ((pkg->dst >> 40) & 0xFF);
	pdesc->awburst_1_0 = 0x1;
	pdesc->src_addr_47_40 = ((pkg->src >> 40) & 0xFF);
	pdesc->arburst_1_0 = 0x1;
	if (gdma_set->core->device_id == MLUID_590
		|| gdma_set->core->device_id == MLUID_590V
		|| gdma_set->core->device_id == MLUID_580
		|| gdma_set->core->device_id == MLUID_580V) {
		pdesc->prog_wblen_7_0 = 0x3f;
		pdesc->prog_rblen_7_0 = 0x3f;

	} else {
		pdesc->prog_wblen_7_0 = 0x7;
		pdesc->prog_rblen_7_0 = 0x7;
	}
	pdesc->read_ostd_4_0 = 0x7;
	pdesc->write_ostd_4_0 = 0x7;
	pdesc->nxt_dscrpt_addr_31_0 = (next_desc->dev_va & 0xFFFFFFFF);
	pdesc->nxt_dscrpt_addr_47_32 = (u32)((next_desc->dev_va >> 32) & 0xFFFF);

	memcpy_toio((void *)cur_desc->host_kva,
				(void *)pdesc,
				sizeof(struct gdma_contex_type_0_desc));

	if (unlikely(gdma_set->debug_print)) {
		cn_gdma_dbg_show_contex_0_desc(gdma_set, pdesc);
		cn_gdma_dbg_dump_desc(gdma_set, cur_desc);
	}
}

static void gdma_fill_contex_type_0_pigeon_desc(struct cn_gdma_set *gdma_set,
		struct cn_gdma_package *pkg,
		struct cn_shm *cur_desc,
		struct cn_shm *next_desc,
		int compress_type)
{
	struct gdma_contex_type_0_pigeon_desc contex_type_0_desc = {0};
	struct gdma_contex_type_0_pigeon_desc *pdesc = &contex_type_0_desc;

	pdesc->fixed_pattern = GDMA_FIXED_PATTERN;
	pdesc->OWN = DESC_OWN_DMA;
	pdesc->type = DESC_DT_CONTEX_0;

	pdesc->dst_addr_47_40 = ((pkg->dst >> 40) & 0xFF);
	pdesc->awburst_1_0 = 0x1;
	pdesc->src_addr_47_40 = ((pkg->src >> 40) & 0xFF);
	pdesc->arburst_1_0 = 0x1;

	pdesc->prog_wblen_7_0 = 0x1f;
	pdesc->prog_rblen_7_0 = 0x1f;

	pdesc->read_ostd_4_0 = 0x7;
	pdesc->write_ostd_4_0 = 0x7;
	pdesc->aw_compress_en = ((compress_type >> 5) & 0x1);
	pdesc->aw_compress_overwrite = ((compress_type >> 4) & 0x1);
	pdesc->aw_compress_type_3_0 = (compress_type & 0xf);
	pdesc->nxt_dscrpt_addr_31_0 = (next_desc->dev_va & 0xFFFFFFFF);
	pdesc->nxt_dscrpt_addr_47_32 = (u32)((next_desc->dev_va >> 32) & 0xFFFF);

	memcpy_toio((void *)cur_desc->host_kva,
				(void *)pdesc,
				sizeof(struct gdma_contex_type_0_desc));

	if (unlikely(gdma_set->debug_print)) {
		cn_gdma_dbg_show_contex_0_pigeon_desc(gdma_set, pdesc);
		cn_gdma_dbg_dump_desc(gdma_set, cur_desc);
	}
}

static void gdma_fill_contex_type_1_desc(struct cn_gdma_set *gdma_set,
		struct context_1_desc_param *param,
		struct cn_shm *cur_desc,
		struct cn_shm *next_desc)
{
	struct gdma_contex_type_1_desc contex_type_1_desc = {0};
	struct gdma_contex_type_1_desc *pdesc = &contex_type_1_desc;

	pdesc->fixed_pattern = GDMA_FIXED_PATTERN;
	pdesc->OWN = DESC_OWN_DMA;
	pdesc->type = DESC_DT_CONTEX_1;

	pdesc->dim3_stride_31_0 = param->dim3_stride;

	/*dim1_len should be actual len -1*/
	pdesc->dim2_len_14_0 = (param->dim2_len - 1) & 0x7fff;
	pdesc->dim3_stride_sign = param->dim3_stride_sign;
	pdesc->dim3_stride_47_32 = (param->dim3_stride >> 32) & 0xffff;

	/*dim1_len should be actual len - 1*/
	pdesc->dim1_len_4_0 = (param->dim1_len - 1) & 0x1f;
	pdesc->dim2_stride_21_0 = param->dim2_stride & 0x3fffff;
	pdesc->dim2_len_19_15 = ((param->dim2_len - 1) >> 15) & 0x1f;

	pdesc->HALT = param->halt;
	pdesc->SOD = param->sod;
	pdesc->dim2_en = param->dim2_en;
	pdesc->dim3_en = param->dim3_en;
	pdesc->dim1_len_19_5 = ((param->dim1_len - 1) >> 5) & 0x7fff;

	pdesc->nxt_dscrpt_addr_31_0 = next_desc->dev_va & 0xffffffff;
	pdesc->nxt_dscrpt_addr_47_32 = (next_desc->dev_va >> 32) & 0xffff;

	memcpy_toio((void *)cur_desc->host_kva,
				(void *)pdesc,
				sizeof(struct gdma_contex_type_1_desc));

	if (unlikely(gdma_set->debug_print)) {
		cn_gdma_dbg_show_contex_1_desc(gdma_set, pdesc);
		cn_gdma_dbg_dump_desc(gdma_set, cur_desc);
	}
}

static void gdma_fill_normal_desc(struct cn_gdma_set *gdma_set,
		struct cn_gdma_package *pkg,
		struct cn_shm *cur_desc,
		struct cn_shm *next_desc,
		int fisrt_desc,
		int last_desc,
		int iobc,
		int halt)
{
	struct gdma_normal_desc normal_desc = {0};
	struct gdma_normal_desc *pdesc = &normal_desc;

	pdesc->fixed_pattern = GDMA_FIXED_PATTERN;
	pdesc->type = DESC_DT_NORMAL;
	pdesc->OWN = DESC_OWN_DMA;

	pdesc->dst_addr_31_0 = pkg->dst & 0xffffffff;
	pdesc->dst_addr_39_32 = (pkg->dst >> 32) & 0xff;
	pdesc->src_addr_23_0 = pkg->src & 0xffffff;
	pdesc->src_addr_39_24 = (pkg->src >> 24) & 0xffff;
	pdesc->data_len_15_0 = (pkg->len - 1) & 0xffff;
	pdesc->data_len_23_16 = ((pkg->len - 1) >> 16) & 0xff;
	pdesc->FD = fisrt_desc;
	pdesc->LD = last_desc;
	pdesc->IOBC = iobc;
	pdesc->HALT = halt;

	if (!last_desc) {
		pdesc->nxt_dscrpt_addr_31_0 = next_desc->dev_va & 0xffffffff;
		pdesc->nxt_dscrpt_addr_47_32 = (next_desc->dev_va >> 32) & 0xffff;
	}

	memcpy_toio((void *)cur_desc->host_kva,
				(void *)pdesc,
				sizeof(struct gdma_normal_desc));

	if (unlikely(gdma_set->debug_print)) {
		cn_gdma_dbg_show_normal_desc(gdma_set, pdesc);
		cn_gdma_dbg_dump_desc(gdma_set, cur_desc);
	}
}

int cn_gdma_fill_memcpy_desc(struct cn_gdma_set *gdma_set,
		struct cn_gdma_virt_chan *chan,
		struct cn_gdma_package *pkg)
{
	struct cn_shm cur_desc = {0};
	struct cn_shm next_desc = {0};
	int first_desc = 1;
	int last_desc = 1;
	int iobc = 0;
	int halt = 1;
	int compress_type;

	if (unlikely(!chan->task)) {
		return -GDMA_ERROR;
	}

	cur_desc.host_kva = chan->desc_shm.host_kva;
	cur_desc.dev_va = chan->desc_shm.dev_va;
	next_desc.host_kva = chan->desc_shm.host_kva + GDMA_DESC_SIZE;
	next_desc.dev_va = chan->desc_shm.dev_va + GDMA_DESC_SIZE;
	compress_type = chan->task->transfer.compress_type;

	if (gdma_set->core->device_id == MLUID_PIGEON_EDGE ||
		gdma_set->core->device_id == MLUID_PIGEON) {
		gdma_fill_contex_type_0_pigeon_desc(gdma_set, pkg,
				&cur_desc, &next_desc,
				compress_type);

	} else {
		gdma_fill_contex_type_0_desc(gdma_set, pkg,
				&cur_desc, &next_desc);
	}
	cur_desc.host_kva += GDMA_DESC_SIZE;
	cur_desc.dev_va += GDMA_DESC_SIZE;
	next_desc.host_kva += GDMA_DESC_SIZE;
	next_desc.dev_va += GDMA_DESC_SIZE;

	gdma_fill_normal_desc(gdma_set, pkg,
				&cur_desc, &next_desc,
				first_desc, last_desc,
				iobc, halt);

	return GDMA_SUCCESS;
}

int cn_gdma_fill_memset_desc(struct cn_gdma_set *gdma_set,
		struct cn_gdma_virt_chan *chan,
		struct cn_gdma_package *pkg)
{
	struct cn_shm cur_desc = {0};
	struct cn_shm next_desc = {0};
	struct context_1_desc_param context1_param = {0};
	int first_desc = 1;
	int last_desc = 1;
	int iobc = 0;
	int halt = 1;

	if (unlikely(!chan->task)) {
		return -GDMA_ERROR;
	}

	cur_desc.host_kva = chan->desc_shm.host_kva;
	cur_desc.dev_va = chan->desc_shm.dev_va;
	next_desc.host_kva = chan->desc_shm.host_kva + GDMA_DESC_SIZE;
	next_desc.dev_va = chan->desc_shm.dev_va + GDMA_DESC_SIZE;

	gdma_build_context_1_desc_param(gdma_set, pkg->type, &context1_param);

	gdma_fill_contex_type_0_desc(gdma_set, pkg,
				&cur_desc, &next_desc);
	cur_desc.host_kva += GDMA_DESC_SIZE;
	cur_desc.dev_va += GDMA_DESC_SIZE;
	next_desc.host_kva += GDMA_DESC_SIZE;
	next_desc.dev_va += GDMA_DESC_SIZE;
	gdma_fill_contex_type_1_desc(gdma_set, &context1_param,
				&cur_desc, &next_desc);
	cur_desc.host_kva += GDMA_DESC_SIZE;
	cur_desc.dev_va += GDMA_DESC_SIZE;
	next_desc.host_kva += GDMA_DESC_SIZE;
	next_desc.dev_va += GDMA_DESC_SIZE;

	gdma_fill_normal_desc(gdma_set, pkg,
				&cur_desc, &next_desc,
				first_desc, last_desc,
				iobc, halt);

	return GDMA_SUCCESS;
}

int cn_gdma_fill_memcpy_2d_desc(struct cn_gdma_set *gdma_set,
		struct cn_gdma_virt_chan *chan,
		struct cn_gdma_package *pkg)
{
	struct cn_shm cur_desc = {0};
	struct cn_shm next_desc = {0};
	struct memcpy_d2d_2d *d2d_2d = &chan->task->transfer.d2d_2d;
	struct context_1_desc_param context1_param = {0};
	int first_desc = 1;
	int last_desc = 1;
	int iobc = 0;
	int halt = 1;

	if (unlikely(!chan->task)) {
		return -GDMA_ERROR;
	}

	cur_desc.host_kva = chan->desc_shm.host_kva;
	cur_desc.dev_va = chan->desc_shm.dev_va;
	next_desc.host_kva = chan->desc_shm.host_kva + GDMA_DESC_SIZE;
	next_desc.dev_va = chan->desc_shm.dev_va + GDMA_DESC_SIZE;

	//fill memcpy 2D contex 0 desc
	gdma_fill_contex_type_0_desc(gdma_set, pkg,
					&cur_desc, &next_desc);
	cur_desc.host_kva += GDMA_DESC_SIZE;
	cur_desc.dev_va += GDMA_DESC_SIZE;
	next_desc.host_kva += GDMA_DESC_SIZE;
	next_desc.dev_va += GDMA_DESC_SIZE;

	//fill memcpy 2D contex 1 desc for src
	context1_param.sod = 0;
	context1_param.dim2_en = 1;
	context1_param.dim3_en = 0;
	context1_param.dim1_len = d2d_2d->width;
	context1_param.dim2_len = d2d_2d->height;
	context1_param.dim2_stride = d2d_2d->spitch;
	context1_param.halt = 0;
	gdma_fill_contex_type_1_desc(gdma_set, &context1_param,
					&cur_desc, &next_desc);
	cur_desc.host_kva += GDMA_DESC_SIZE;
	cur_desc.dev_va += GDMA_DESC_SIZE;
	next_desc.host_kva += GDMA_DESC_SIZE;
	next_desc.dev_va += GDMA_DESC_SIZE;

	//fill memcpy 2D contex 1 desc for dst
	context1_param.sod = 1;
	context1_param.dim2_stride = d2d_2d->dpitch;
	gdma_fill_contex_type_1_desc(gdma_set, &context1_param,
					&cur_desc, &next_desc);
	cur_desc.host_kva += GDMA_DESC_SIZE;
	cur_desc.dev_va += GDMA_DESC_SIZE;
	next_desc.host_kva += GDMA_DESC_SIZE;
	next_desc.dev_va += GDMA_DESC_SIZE;

	//fill memcpy 2D normal desc
	gdma_fill_normal_desc(gdma_set, pkg,
				&cur_desc, &next_desc,
				first_desc, last_desc,
				iobc, halt);

	return GDMA_SUCCESS;
}

int cn_gdma_fill_memcpy_3d_desc(struct cn_gdma_set *gdma_set,
		struct cn_gdma_virt_chan *chan,
		struct cn_gdma_package *pkg)
{
	struct cn_shm cur_desc = {0};
	struct cn_shm next_desc = {0};
	struct memcpy_d2d_3d_compat *d2d_3d = &chan->task->transfer.d2d_3d;
	struct context_1_desc_param context1_param = {0};
	int first_desc = 1;
	int last_desc = 1;
	int iobc = 0;
	int halt = 1;

	if (unlikely(!chan->task)) {
		return -GDMA_ERROR;
	}

	//fill memcpy 3D contex 0 desc
	cur_desc.host_kva = chan->desc_shm.host_kva;
	cur_desc.dev_va = chan->desc_shm.dev_va;
	next_desc.host_kva = chan->desc_shm.host_kva + GDMA_DESC_SIZE;
	next_desc.dev_va = chan->desc_shm.dev_va + GDMA_DESC_SIZE;

	gdma_fill_contex_type_0_desc(gdma_set, pkg,
					&cur_desc, &next_desc);
	cur_desc.host_kva += GDMA_DESC_SIZE;
	cur_desc.dev_va += GDMA_DESC_SIZE;
	next_desc.host_kva += GDMA_DESC_SIZE;
	next_desc.dev_va += GDMA_DESC_SIZE;

	//fill memcpy 3D contex 1 desc for src
	context1_param.sod = 0;
	context1_param.dim2_en = 1;
	context1_param.dim3_en = 1;
	context1_param.dim1_len = d2d_3d->extent.width;
	context1_param.dim2_len = d2d_3d->extent.height;
	context1_param.dim2_stride = d2d_3d->src_ptr.pitch;
	context1_param.dim3_stride = d2d_3d->src_ptr.ysize * d2d_3d->src_ptr.pitch;
	gdma_fill_contex_type_1_desc(gdma_set, &context1_param,
					&cur_desc, &next_desc);
	cur_desc.host_kva += GDMA_DESC_SIZE;
	cur_desc.dev_va += GDMA_DESC_SIZE;
	next_desc.host_kva += GDMA_DESC_SIZE;
	next_desc.dev_va += GDMA_DESC_SIZE;

	//fill memcpy 3D contex 1 desc for dst
	context1_param.sod = 1;
	context1_param.dim2_stride = d2d_3d->dst_ptr.pitch;
	context1_param.dim3_stride = d2d_3d->dst_ptr.ysize * d2d_3d->dst_ptr.pitch;

	gdma_fill_contex_type_1_desc(gdma_set, &context1_param,
					&cur_desc, &next_desc);
	cur_desc.host_kva += GDMA_DESC_SIZE;
	cur_desc.dev_va += GDMA_DESC_SIZE;
	next_desc.host_kva += GDMA_DESC_SIZE;
	next_desc.dev_va += GDMA_DESC_SIZE;

	//fill memcpy 3D normal desc
	gdma_fill_normal_desc(gdma_set, pkg,
				&cur_desc, &next_desc,
				first_desc, last_desc,
				iobc, halt);

	return GDMA_SUCCESS;
}
