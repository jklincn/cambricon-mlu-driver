/*
 * sbts/core_dump.h
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

#ifndef __SBTS_CORE_DUMP_H
#define __SBTS_CORE_DUMP_H

#include <linux/types.h>

#define DUMP_HEADER_SIZE	(64UL)
#define DUMP_HEADER_SIZE_V4	(256UL)

#define DUMP_VERSION_V2    (2)
#define DUMP_VERSION_V3    (3)
#define DUMP_VERSION_V4    (4)
#define DUMP_VERSION_V5    (5)
#define DUMP_VERSION_V6    (6)

#define DUMP_HEARD_FMT     "VERSION:%d,core bp:0x%0llx:end"
#define DUMP_HEARD_FMT_V4  "VERSION:%d,core bp:0x%0llx 0x%0llx:end"
#define DUMP_HEARD_FMT_V5  "VERSION:%d,core bp:0x%0llx 0x%0llx 0x%0llx:end"

#define DUMP_DISCARD  (0)
#define DUMP_LIGHT    (1)
#define DUMP_DEFAULT  (2)

struct comm_dbg_desc;
struct comm_ctrl_desc;
struct core_dump_manager;
struct sbts_create_queue;
struct cn_core_set;
struct sbts_set;
struct task_struct;

/* former struct */
struct former_core_dump_msg {
	__le64 user;
	__le64 user_id;
	__le64 queue_dsid;
	__le64 dump_id;
	__le64 seq_num;
	__le64 msg[2];
};

/* mlu struct */
struct mlu_core_dump_msg {
	__le64 user;
	__le64 user_id;
	__le64 queue_dsid;
	__le64 dump_id;
	__le64 seq_id;
	__le64 block_addr;
	__le64 block_size;
	__le64 block_type;
	__le64 block_info;
};

enum block_type {
	IPU_BLK = 0,
	MEMCORE_BLK,
	TNC_BLK,
	C2C_BLK,
	TOPO_BLK,
	CORE_INFO,
	BLOCK_TYPE_NUM,
};

#define BLOCK_HDR_RESERVED_SIZE		(12U)
struct block_hdr {
	__u64 version;
	__u64 type;			/* for example, ipu\topo node */
	__u64 info;			/* for example, error ipu id */
	__u64 size;			/* current block size */
	__u64 reserved[BLOCK_HDR_RESERVED_SIZE];
};

struct drv_dump_set {
	__u32 core_dump_level;
	__u32 layout_version;
} __attribute__((__packed__));

/* comm core dump struct */
enum core_dump_sta {
	DUMP_COMM_INIT = 1,
	DUMP_COMM_ERROR,
	DUMP_COMM_FINISH,
	DUMP_COMM_END,
};

struct core_dump_info {
	u32 enable;
	int version;
	int downward_flag;

	volatile int dumped_done;
	int dump_record;
	__u64 dump_uvaddr;
	__u64 header_size;
	__u64 reserved_offset;
	struct task_struct *task;
	struct mm_struct *mm;
	volatile u64 dumped_bp[3];
	u64 dumped_bp_mask[3];
	atomic_t wait_ack;
	struct mlu_core_dump_msg last_msg;
};

struct core_dump_ops {
	void (*do_core_dump_cbk)(struct core_dump_manager *mgr,
			struct comm_ctrl_desc *rx_info);
	int (*dump_finish_cbk)(struct core_dump_manager *mgr,
			struct comm_dbg_desc *rx_desc);
	struct core_dump_info *(*dump_info_init)(struct core_dump_manager *mgr,
			struct sbts_create_queue *pparam);
	void (*dump_info_exit)(struct core_dump_manager *mgr,
			struct core_dump_info *dump_info);
	int (*copy_dump_header)(struct core_dump_info *dump_info);
	int (*ack_sta_parse)(struct cn_core_set *core, struct queue *queue,
		struct hpq_task_ack_desc ack_desc);
};

struct core_dump_manager {
	struct cn_core_set *core;
	struct sbts_set *sbts;
	void *worker;
	const struct core_dump_ops *ops;
};

extern struct core_dump_info *
core_dump_info_init(struct sbts_set *sbts, struct sbts_create_queue *pparam);

extern void
core_dump_info_exit(struct sbts_set *sbts, struct core_dump_info *dump_info);

extern int
sbts_dump_manager_init(struct core_dump_manager **ppdump_mgr, struct cn_core_set *core);

extern void
sbts_dump_manager_exit(struct core_dump_manager *dump_manager);

#endif /* __SBTS_CORE_DUMP_H */
