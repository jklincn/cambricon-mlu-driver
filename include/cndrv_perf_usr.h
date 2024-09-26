/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_CAMBR_PERF_H__
#define __LINUX_CAMBR_PERF_H__

enum drv_async_reason {
	/* 0 - 10 is device trigger */
	DRV_ASYNC_REASON_INIT = 0,
	DRV_ASYNC_REASON_DEVICE_H2D_D2H,
	DRV_ASYNC_REASON_DEVICE_P2P,
	DRV_ASYNC_REASON_DEVICE_MEMSET,
	/* 20 - 39 is host trigger common reason */
	DRV_ASYNC_REASON_HOST_COMMON_START = 20,
	DRV_ASYNC_REASON_DEVICE_DISABLE = DRV_ASYNC_REASON_HOST_COMMON_START,
	DRV_ASYNC_REASON_DEVICE_NOTSUPPORT,
	DRV_ASYNC_REASON_STREAM_INVALID,
	DRV_ASYNC_REASON_DESC_NOT_ENOUGH,
	DRV_ASYNC_REASON_SYNC_PAGEABLE_MEM = 24,
	/* 40 - 59 is host trigger h2d d2h reason */
	DRV_ASYNC_REASON_HOST_H2D_D2H_START = 40,
	DRV_ASYNC_REASON_H2D_D2H_NOT_PINNED = DRV_ASYNC_REASON_HOST_H2D_D2H_START,
	DRV_ASYNC_REASON_H2D_D2H_GET_DESC_NUM_ERR,
	DRV_ASYNC_REASON_H2D_D2H_GET_PAGES_ERR,
	DRV_ASYNC_REASON_H2D_D2H_UP_SGL_ERR,
	DRV_ASYNC_REASON_H2D_D2H_FILL_DESC_ERR,
	/* 60 - ... is host trigger p2p reason*/
	DRV_ASYNC_REASON_HOST_P2P_START = 60,
	DRV_ASYNC_REASON_P2P_HOST_TRANSFER = DRV_ASYNC_REASON_HOST_P2P_START,
	DRV_ASYNC_REASON_P2P_EXCEED_SIZE,
	DRV_ASYNC_REASON_P2P_LINEAR_REMAP_ERR,
	DRV_ASYNC_REASON_P2P_UP_SGL_ERR,
	DRV_ASYNC_REASON_P2P_FILL_DESC_ERR,
	DRV_ASYNC_REASON_P2P_FILL_PULL_DESC_ERR,
};

enum dev_mem_free_append_index {
	MEM_PERF_DEV_FREE_REQUEST_SIZE = 1,
	MEM_PERF_DEV_FREE_ALIGNED_SIZE,
	MEM_PERF_DEV_FREE_FA_TOTAL,
	MEM_PERF_DEV_FREE_FA_FREE,
	MEM_PERF_DEV_FREE_DEV_FA_TOTAL,
	MEM_PERF_DEV_FREE_DEV_FA_FREE,
	MEM_PERF_DEV_FREE_TOTAL,
	MEM_PERF_DEV_FREE_FREE,
	MEM_PERF_DEV_FREE_PROCESS_USED,
	MEM_PERF_DEV_FREE_ADDRESS,
	MEM_PERF_DEV_FREE_DEVICE_ID,
	MEM_PERF_DEV_FREE_CONTEXT_ID,
	MEM_PERF_DEV_FREE_IS_LINEAR,
	MEM_PERF_DEV_FREE_MAPINFO,
	MEM_PERF_DEV_FREE_INDEX_NUM = MEM_PERF_DEV_FREE_MAPINFO,
};

/*device mem malloc*/
enum dev_mem_malloc_append_index {
	MEM_PERF_DEV_MALLOC_REQUEST_SIZE = 1,
	MEM_PERF_DEV_MALLOC_ALIGNED_SIZE,
	MEM_PERF_DEV_MALLOC_FA_TOTAL,
	MEM_PERF_DEV_MALLOC_FA_FREE,
	MEM_PERF_DEV_MALLOC_DEV_FA_TOTAL,
	MEM_PERF_DEV_MALLOC_DEV_FA_FREE,
	MEM_PERF_DEV_MALLOC_TOTAL,
	MEM_PERF_DEV_MALLOC_FREE,
	MEM_PERF_DEV_MALLOC_PROCESS_USED,
	MEM_PERF_DEV_MALLOC_ADDRESS,
	MEM_PERF_DEV_MALLOC_DEVICE_ID,
	MEM_PERF_DEV_MALLOC_CONTEXT_ID,
	MEM_PERF_DEV_MALLOC_IS_LINEAR,
	MEM_PERF_DEV_MALLOC_MAPINFO,
	MEM_PERF_DEV_MALLOC_INDEX_NUM = MEM_PERF_DEV_MALLOC_MAPINFO,
};

enum perf_record_mode {
	LOSS_RECORD_MODE = 1,
	LOSSLESS_RECORD_MODE,
};

enum perf_work_mode {
	NORMAL_WORK_MODE = 1,
	DEBUG_WORK_MODE,
};

enum perf_collection_mode {
	DEFAULT_COLLECTION_MODE = 1,
	ALL_COLLECTION_MODE,
};

enum perf_performance_mode {
	DEFAULT_PERFORMANCE_MODE = 1,
	CNTRACE_PERFORMANCE_MODE,
};

enum ncs_ts_type {
	NCS_TS_TYPE_CTASK = 0,
	NCS_TS_TYPE_TX_QTASK,
	NCS_TS_TYPE_RX_QTASK,
	NCS_TS_TYPE_ACK,
};

enum dma_ts_sub_task_type {
	TS_DMA_ASYNC_H2D,
	TS_DMA_ASYNC_D2H,
	TS_DMA_ASYNC_P2P,
	TS_MEMSET_D8,
	TS_MEMSET_D16,
	TS_MEMSET_D32,
	TS_DMA_ASYNC_D2D = 20,
	TS_DMA_SUB_TYPE_MAX,
};

#define MAX_BITMAP			(128)
#define TS_PERF 			(0x1ULL << 56)
#define MEM_PERF 			(0x2ULL << 56)
#define TASK_TYPE_MODULE_MASK			(0xffULL << 56)
#define TASK_TYPE_VALUE_MASK			(~TASK_TYPE_MODULE_MASK)
/* task type layout
 *------------------------------
 *|63      56|55               0|
 *------------------------------
 *|task mask |  task type       |
 *------------------------------
 * in TS_PERF task_mask[63:47] is all zero of compat previously version drvier and papi api.
 * task mask : TS TASK, MEM TASK
 * task type : NORMAL_TS_TASK, ...
 * */
#define NORMAL_TS_TASK      (0X1ULL)
#define NOTIFIER_TS_TASK    (0X1ULL << (2 - 1))
#define DMA_TS_TASK         (0X1ULL << (3 - 1))
#define NCS_TS_TASK         (0X1ULL << (8 - 1))
#define IDC_TS_TASK         (0X1ULL << (9 - 1))
#define HOSTFN_TS_TASK      (0X1ULL << (11 - 1))
#define TCDP_TS_TASK        (0X1ULL << (12 - 1))

#define TS_PERF_TASK (NORMAL_TS_TASK | NOTIFIER_TS_TASK | DMA_TS_TASK | NCS_TS_TASK | \
					 IDC_TS_TASK | HOSTFN_TS_TASK | TCDP_TS_TASK)
#define MAX_TS_TASK_NUM     (7)

#define DEV_MEM_MALLOC       ((MEM_PERF) | (0X1ULL))
#define DEV_MEM_FREE         ((MEM_PERF) | (0X1ULL << (2 - 1)))
#define HOST_MEM_MALLOC      ((MEM_PERF) | (0X1ULL << (3 - 1)))
#define HOST_MEM_FREE        ((MEM_PERF) | (0X1ULL << (4 - 1)))
#define MEM_PERF_TASK        (DEV_MEM_MALLOC | DEV_MEM_FREE | HOST_MEM_MALLOC | HOST_MEM_FREE)

#define MAX_MEM_TASK_NUM     (4)
#define TS_PERF_MASK 	(TS_PERF_TASK)
#define MEM_PERF_MASK 	(MEM_PERF_TASK)

#define __sbts_task_list(op) \
	op(NORMAL, 	normal)	\
	op(NOTIFIER,    notifier) \
	op(DMA, 	dma)	\
	op(NCS, 	ncs)	\
	op(IDC, 	idc)	\
	op(HOSTFN, 	hostfn)	\
	op(TCDP, 	tcdp)

/* normal task */
enum normal_task_append_index {
	NORMAL_TASK_HOST_INVOKE_NS = 1,
	NORMAL_TASK_ARM_RECEIVE_NS,
	NORMAL_TASK_PUSH_NS,
	NORMAL_TASK_TASK_FREE_NS,
	NORMAL_TASK_TOPO_ID,
	NORMAL_TASK_QUEUE_ID,
	NORMAL_TASK_KERNEL_TYPE,
	NORMAL_TASK_KERNEL_DEPRECATED_1,
	NORMAL_TASK_KERNEL_ADDR,
	NORMAL_TASK_UNIQUE_QUEUE_ID,
	NORMAL_TASK_INDEX_NUM = NORMAL_TASK_UNIQUE_QUEUE_ID,
};

/* dma async task */
enum dma_task_append_index {
	DMA_TASK_SUB_TYPE = 1,
	DMA_TASK_HOST_INVOKE_NS,
	DMA_TASK_ARM_RECEIVE_NS,
	DMA_TASK_PUSH_NS,
	DMA_TASK_FREE_NS,
	DMA_TASK_TOPO_ID,
	DMA_TASK_QUEUE_ID,
	DMA_TASK_COPY_SIZE,
	DMA_TASK_TRIGGER_TYPE,
	DMA_TASK_UNIQUE_QUEUE_ID,
	DMA_TASK_INDEX_NUM = DMA_TASK_UNIQUE_QUEUE_ID,
};

enum idc_task_info_bitmap_e {
	IDC_TASK_COMMU_WITH_HOST = 0,
};

/* idc task */
enum idc_task_append_index {
	IDC_TASK_SUB_TYPE = 1,
	IDC_TASK_HOST_INVOKE_NS,
	IDC_TASK_ARM_RECEIVE_NS,
	IDC_TASK_FREE_NS,
	IDC_TASK_USER_ADDR,
	IDC_TASK_FLAG,
	IDC_TASK_USER_VAL,
	IDC_TASK_KERNEL_ADDR,
	IDC_TASK_TOPO_ID,
	IDC_TASK_QUEUE_ID,
	IDC_TASK_INFO_BITMAP, /* enum idc_task_info_bitmap_e */
	IDC_TASK_UNIQUE_QUEUE_ID,
	IDC_TASK_INDEX_NUM = IDC_TASK_UNIQUE_QUEUE_ID
};

/* notifier task */
enum notifier_task_append_index {
	NOTIFIER_TASK_SUB_TYPE = 1,
	NOTIFIER_TASK_HOST_INVOKE_NS,
	NOTIFIER_TASK_ARM_RECEIVE_NS,
	NOTIFIER_TASK_FREE_NS,
	NOTIFIER_TASK_ID,
	NOTIFIER_UNIQUE_VAL,
	NOTIFIER_TASK_TOPO_ID,
	NOTIFIER_TASK_QUEUE_ID,
	NOTIFIER_TASK_UNIQUE_QUEUE_ID,
	NOTIFIER_TASK_INDEX_NUM = NOTIFIER_TASK_UNIQUE_QUEUE_ID,
};

/* host function task */
enum hostfn_task_append_index {
	HOSTFN_TASK_HOST_INVOKE_NS = 1,
	HOSTFN_TASK_ARM_RECEIVE_START_NS,
	HOSTFN_TASK_PUSH_NS,
	HOSTFN_TASK_HK_PASS_NS,
	HOSTFN_TASK_USER_RECEVICE_NS,
	HOSTFN_TASK_ARM_RECEVICE_FINISH_NS,
	HOSTFN_TASK_FREE_NS,
	HOSTFN_TASK_TOPO_ID,
	HOSTFN_TASK_QUEUE_ID,
	HOSTFN_TASK_UNIQUE_QUEUE_ID,
	HOSTFN_TASK_INDEX_NUM = HOSTFN_TASK_UNIQUE_QUEUE_ID,
};

/* tcdp task */
enum tcdp_task_append_index {
	TCDP_TASK_HOST_INVOKE_NS = 1,
	TCDP_TASK_ARM_RECEIVE_NS,
	TCDP_TASK_PUSH_NS,
	TCDP_TASK_FREE_NS,
	TCDP_TASK_TOPO_ID,
	TCDP_TASK_QUEUE_ID,
	TCDP_TASK_KERNEL_ADDR,
	TCDP_TASK_UNIQUE_QUEUE_ID,
	TCDP_TASK_INDEX_NUM = TCDP_TASK_UNIQUE_QUEUE_ID,
};

/* ncs task */
enum ncs_task_append_index {
	NCS_TASK_SUB_TYPE = 1,
	NCS_TASK_ID,
	NCS_TASK_HOST_INVOKE_NS,
	NCS_TASK_INIT_START_NS,
	NCS_TASK_INIT_END_NS,
	NCS_TASK_PRE_PUSHED_START_NS,
	NCS_TASK_PRE_PUSHED_END_NS,
	NCS_TASK_PUSHED_END_NS,
	NCS_TASK_FREE_NS,
	NCS_TX_TASK_READY_NS,
	NCS_TX_TASK_FINISH_NS,
	NCS_RX_TASK_READY_NS,
	NCS_RX_TASK_LAST_TSF_LAUNCH_NS,
	NCS_RX_TASK_LAST_TSF_FINISH_NS,
	NCS_RX_TASK_FINISH_NS,
	NCS_TASK_QUEUE_ID,
	NCS_TASK_UNIQUE_QUEUE_ID,
	NCS_TASK_INDEX_NUM = NCS_TASK_UNIQUE_QUEUE_ID,
};

/* ts info comm data */
struct ts_append_data {
	__le32 debug;
	__le32 index;
	__le64 data;
} __attribute__((__packed__));

#define COMM_DATA_SIZE (sizeof(__le64) * 4)
#define DEBUG_NUM	20
#define NON_DEBUG_NUM NCS_TASK_INDEX_NUM
#define MAX_APPEND_NUM (NON_DEBUG_NUM + DEBUG_NUM)
struct task_ts_info {
	__le64 entry_type;
	__le64 correlation_id;
	__le64 task_start_ns;
	__le64 task_finish_ns;
	struct ts_append_data append_data_table[MAX_APPEND_NUM];
} __attribute__((__packed__));

struct perf_ts_info_header {
	__le64 version;
	__le64 record_mode;
	__le64 work_mode;
	__le64 collection_mode;
	__le64 performance_mode;
	__le64 valid_buffer_size;
	__le64 valid_entry_num;
	__le64 last_entry_index;
	__le64 cur_entry_index;
	__le64 start_time;
	__le64 finish_time;
};

#endif
