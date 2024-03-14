/*
 * mgr/mgr_packet_stru.h
 *
 * NOTICE:
 * Copyright (C) 2019 Cambricon, Inc. All rights reserved.
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

#ifndef __MGR_PACKET_STRU_H
#define __MGR_PACKET_STRU_H

enum mig_dir_e {
	MIG_H2D_SAVE_CTX = 0, /*!< indicating it's a request to save ctx */
	MIG_H2D_RESTORE_CTX
};

enum mig_header_type {
	MIG_HEADER_PREPARE = 0,
	MIG_HEADER_QUERY_STATE,
	MIG_HEADER_DATA,
	MIG_HEADER_DATA_DONE,
	MIG_HEADER_COMPLETE,
	MIG_HEADER_CANCEL,
	MIG_HEADER_CANCEL_COMPLETE,
	MIG_HEADER_DEBUG_INFO,
};

#pragma pack(1)
struct mig_h2d_msg_t {
	__u32                       vf; /* vf id */
	enum mig_dir_e              dir;
	enum mig_header_type        header_type;
	unsigned char               pay_load[52];
};

struct mig_d2h_res_t {
	__u32                       state;
	unsigned char               pay_load[28];
};

struct mig_save_payload_res_t {
	u8                          mem_type;
	u8                          dev_done;
	/* Software Component identifier, for example, MIG_PROT_CPNT_PCIE. */
	u8                          cpnt;
	u8                          sub_cpnt;
	/* 1 indicate the last data in this software component */
	u32                         cpnt_done;
	u64                         size;
	u32                         offset;  /* start cache offset */
};

struct mig_restore_payload_t {
	u8                          mem_type;
	u8                          dev_done;
	/* Software Component identifier, for example, MIG_PROT_CPNT_PCIE. */
	u8                          cpnt;
	u8                          sub_cpnt;
	/* 1 indicate the last data in this software component */
	u32                         cpnt_done;
	u64                         size;
	u32                         offset;  /* start cache offset */
};

struct mig_debug_payload_t {
	u32                         set_flag;
	u32                         type;
	u32                         enable;
};

#pragma pack()

#endif
