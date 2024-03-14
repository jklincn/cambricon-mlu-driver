/*
 * gdma/gdma_desc.h
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

#ifndef __CNDRV_GDMA_DESC_H__
#define __CNDRV_GDMA_DESC_H__

/*fixed pattern*/
#define GDMA_FIXED_PATTERN (0x94)
#define DESC_OWN_CPU (0)
#define DESC_OWN_DMA (1)
#define DESC_DT_CONTEX_0 (0x00)
#define DESC_DT_CONTEX_1 (0x01)
#define DESC_DT_CONTEX_2 (0x02)
#define DESC_DT_NORMAL (0x03)
#define GDMA_DESC_SIZE (32)

struct gdma_normal_desc {
	 /*DESC0*/
	u32 dst_addr_31_0:32;

	/*DESC1*/
	u32 dst_addr_39_32:8;
	u32 src_addr_23_0:24;

	/*DESC2*/
	u32 src_addr_39_24:16;
	u32 data_len_15_0:16;

	/*DESC3*/
	u32 data_len_23_16:8;
	u32 unused_9_8:2;
	u32 IOBC:1;
	u32 DNS:1;
	u32 SNS:1;
	u32 DR:1;
	u32 SR:1;
	u32 WDSE:1;
	u32 WSSE:1;
	u32 WSE:1;
	u32 HALT:1;
	u32 LD:1;
	u32 FD:1;
	u32 type:2;
	u32 OWN:1;
	u32 fixed_pattern:8;

	/*DESC4*/
	u32 nxt_dscrpt_addr_31_0:32;

	/*DESC5*/
	u32 nxt_dscrpt_addr_47_32:16;
	u32 reserved:16;

	/*for 128bit align,total size 256bit*/
	u32 align_packed_0:32;
	u32 align_packed_1:32;
};

struct gdma_contex_type_0_desc {
	/*DESC0*/
	u32 prog_wblen_7_0:8;
	u32 awburst_1_0:2;
	u32 awcache_3_0:4;
	u32 awprot_2_0:3;
	u32 awqos_3_0:4;
	u32 unpack_size_2_0:3;
	u32 dst_addr_47_40:8;

	/*DESC1*/
	u32 prog_rblen_7_0:8;
	u32 arburst_1_0:2;
	u32 arcache_3_0:4;
	u32 arprot_2_0:3;
	u32 arqos_3_0:4;
	u32 pack_size_2_0:3;
	u32 src_addr_47_40:8;

	/*DESC2*/
	u32 TRT_1_0:2;
	u32 PERM:1;
	u32 FC:1;
	u32 OSFE:1;
	u32 write_ostd_4_0:5;
	u32 read_ostd_4_0:5;
	u32 awdomain_id_3_0:4;
	u32 awpasid_8_0:9;
	u32 ardomain_id_3_0:4;

	/*DESC3*/
	u32 arpasid_8_0:9;
	u32 unused_17_9:9;
	u32 HALT:1;
	u32 type:4;
	u32 OWN:1;
	u32 fixed_pattern:8;

	/*DESC4*/
	u32 nxt_dscrpt_addr_31_0:32;

	/*DESC5*/
	u32 nxt_dscrpt_addr_47_32:16;
	u32 reserved:16;

	/*for 128bit align,total size 256bit*/
	u32 align_packed_0:32;
	u32 align_packed_1:32;
};
struct gdma_contex_type_0_pigeon_desc {
	/*DESC0*/
	u32 prog_wblen_7_0:8;
	u32 awburst_1_0:2;
	u32 awcache_3_0:4;
	u32 awprot_2_0:3;
	u32 awqos_3_0:4;
	u32 unpack_size_2_0:3;
	u32 dst_addr_47_40:8;

	/*DESC1*/
	u32 prog_rblen_7_0:8;
	u32 arburst_1_0:2;
	u32 arcache_3_0:4;
	u32 arprot_2_0:3;
	u32 arqos_3_0:4;
	u32 pack_size_2_0:3;
	u32 src_addr_47_40:8;

	/*DESC2*/
	u32 TRT_1_0:2;
	u32 PERM:1;
	u32 FC:1;
	u32 OSFE:1;
	u32 write_ostd_4_0:5;
	u32 read_ostd_4_0:5;
	u32 awdomain_id_2_0:3;
	u32 aw_compress_overwrite:1;
	u32 aw_cachemode_3_0:4;
	u32 aw_compress_type_3_0:4;
	u32 aw_compress_en:1;
	u32 ardomain_id_3_0:4;

	/*DESC3*/
	u32 ar_cachemode_3_0:4;
	u32 arpasid_8_4:5;
	u32 unused_17_9:9;
	u32 HALT:1;
	u32 type:4;
	u32 OWN:1;
	u32 fixed_pattern:8;

	/*DESC4*/
	u32 nxt_dscrpt_addr_31_0:32;

	/*DESC5*/
	u32 nxt_dscrpt_addr_47_32:16;
	u32 reserved:16;

	/*for 128bit align,total size 256bit*/
	u32 align_packed_0:32;
	u32 align_packed_1:32;
};


struct gdma_contex_type_1_desc {
	/*DESC0*/
	u32 dim3_stride_31_0:32;

	/*DESC1*/
	u32 dim3_stride_47_32:16;
	u32 dim3_stride_sign:1;
	u32 dim2_len_14_0:15;

	/*DESC2*/
	u32 dim2_len_19_15:5;
	u32 dim2_stride_21_0:22;
	u32 dim1_len_4_0:5;

	/*DESC3*/
	u32 dim1_len_19_5:15;
	u32 dim3_en:1;
	u32 dim2_en:1;
	u32 SOD:1;
	u32 HALT:1;
	u32 type:4;
	u32 OWN:1;
	u32 fixed_pattern:8;

	/*DESC4*/
	u32 nxt_dscrpt_addr_31_0:32;

	/*DESC5*/
	u32 nxt_dscrpt_addr_47_32:16;
	u32 reserved:16;

	 /*for 128bit align,total size 256bit*/
	u32 align_packed_0:32;
	u32 align_packed_1:32;
};

#include "gdma_common.h"

int cn_gdma_fill_memcpy_desc(struct cn_gdma_set *gdma_set,
						struct cn_gdma_virt_chan *chan,
						struct cn_gdma_package *pkg);

int cn_gdma_fill_memset_desc(struct cn_gdma_set *gdma_set,
						struct cn_gdma_virt_chan *chan,
						struct cn_gdma_package *pkg);

int cn_gdma_fill_memcpy_2d_desc(struct cn_gdma_set *gdma_set,
						struct cn_gdma_virt_chan *chan,
						struct cn_gdma_package *pkg);

int cn_gdma_fill_memcpy_3d_desc(struct cn_gdma_set *gdma_set,
						struct cn_gdma_virt_chan *chan,
						struct cn_gdma_package *pkg);

#endif
