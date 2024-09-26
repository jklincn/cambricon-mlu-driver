/*
 * sbts/sbts.h
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
#ifndef __SBTS_SBTS_H
#define __SBTS_SBTS_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/cpumask.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/llist.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/bug.h>

#include "sbts_errno.h"
#include "cndrv_debug.h"
#include "cndrv_monitor.h"
#include "cndrv_mm.h"
#include "cndrv_pre_compile.h"
#include "cndrv_perf_usr.h"
#include "core/cndrv_ioctl.h"

#define SCHED_PARAMS_SIZE  (0x20000)
#define SCHED_PARAMS_STEP  (0x6000)  /* 3 */

#ifdef SCHED_PROFILE
#include <linux/ktime.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
#include <linux/hrtimer.h>
#else
#include <linux/timekeeping.h>
#endif
#define print_time(str) \
do { \
	u64 ns = get_host_timestamp_by_clockid(CLOCK_MONOTONIC_RAW); \
	cn_dev_debug("===>%10s time: %llu ns\n", str, \
			(unsigned long long)ns); \
} while (0)
#else
#define print_time(str)  ({})
#endif

#define print_time_detail(str)  print_time(str)

#define VERSION_SIZE		(sizeof(__u64))
#define KPRINTF_DESC_SIZE	(20U)
#define TASK_DESC_SIZE		(28U)
#define CTRL_DESC_SIZE		(32U)
#define CTRL_DESC_STA_SIZE	(sizeof(__u64))

#define ANNOY_USER		(0)
#define MAX_DIM_NUM		(65535UL)

#define DESTROY_TIMEOUT           (10000)
#define PUSH_TASK_TIMEOUT         (999999999UL)
#define CORE_DUMP_TIMEOUT         (159999999UL)
#define SCHED_IOCTL_TIMEOUT       (20UL << 20)
#define CHECK_ACK_DATA_TIMEOUT	  (19999999UL)

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#include <linux/atomic.h>
#define SBTS_KREF_READ(a) atomic_read(&((a)->refcount))
#else
#include <linux/kref.h>
#define SBTS_KREF_READ(a) kref_read(a)
#endif

/* The wrapper macros to create or run a kthread on specified node */
#define sbts_kthread_create_on_node(threadfn, data, node, namefmt, ...) \
	kthread_create_on_node(threadfn, data, node, namefmt, ## __VA_ARGS__)

#define sbts_kthread_create(threadfn, data, namefmt, ...)		\
	sbts_kthread_create_on_node(threadfn, data, NUMA_NO_NODE,	\
			namefmt, ## __VA_ARGS__)

#define sbts_kthread_run_on_node(threadfn, data, node, namefmt, ...)	\
({									\
	struct task_struct *__k =					\
			sbts_kthread_create_on_node(threadfn, data,	\
			node, namefmt, ## __VA_ARGS__);			\
	if (!IS_ERR(__k)) {						\
		wake_up_process(__k);					\
	}								\
	__k;								\
})

#define sbts_kthread_run(threadfn, data, namefmt, ...)		\
	sbts_kthread_run_on_node(threadfn, data, NUMA_NO_NODE,	\
			namefmt, ## __VA_ARGS__)

#define sbts_compile_check(cond) BUILD_BUG_ON_MSG(cond, "check failed : " #cond)

#define SBTS_DBG_OUT(string, arg...)	\
	pr_info("[%d]SBTS_DBG_INFO: " string "\n", __LINE__, ##arg)	\

/* Forward declaration */
struct sched_manager;
struct queue_manager;
struct sbts_dbg_set;
struct sbts_kprintf_set;
struct notifier_mgr;
struct dma_async_manager;
struct idc_manager;
struct sbts_efd_manager;
struct cn_core_set;
struct sbts_hw_info;
struct sync_manager;
struct queue_for_func_mgr;
struct core_dump_manager;
struct commu_channel;
struct commu_endpoint;
struct queue;
struct jpu_manageer;
struct sbts_topo_manager;

/* task descriptor */
enum data_type {
	QUEUE_SYNC = 0,
	INVOKE_KERNEL,
	INVOKE_KERNEL_DEBUG,
	PLACE_NOTIFIER,
	QUEUE_WAIT_NOTIFIER,
	INVOKE_FUNC_KERNEL,
	PLACE_DMA_ASYNC_TASK,
	INVOKE_NCS_TASK,
	PLACE_IDC_TASK,
	DEBUG_TASK,
	INVOKE_HOST_FUNCTION,
	TCDP_TASK,
	TCDP_DEBUG_TASK,
	QUEUE_WAIT_NOTIFIER_EXTRA,
	JPU_TASK,
	QUEUE_TASK_TOPO_INVOKE,
	SBTS_DATA_TYPE_NUM,
};

/* hpq_task_desc->td */
struct comm_task_desc {
	__le64 version;		/* version */
	/* data:
	 *  desc data       struct task_desc_data_v1
	 *  task priv data (align to u64)
	 *  perf priv data  struct task_perf_desc
	 *  or
	 *  topo data       struct task_desc_topo_priv
	 * */
	__le64 data[TASK_DESC_SIZE];
};

struct hpq_task_ack_desc {
	__le64 seq_num;
	__le64 sta;
	__le64 kernel_printf_num;
} __attribute__((__packed__));

struct hpq_notifier_ack_desc {
	__le64 last_val;
	__le64 seq_val;    /* deprecated */
	__le64 hw_time_ns; /* hardware execution time */
	__le64 sw_time_ns; /* software timestamp */
} __attribute__((__packed__));

/* comm_task_desc->data */
struct task_desc_data_v1 {
	__le32 type;
	struct {
		__le32 is_idle:1;
		__le32 has_kprintf:1;
		__le32 is_perf_task:1;
		__le32 clk_id:4;
		__le32 priv_size:8;
		__le32 dev_topo_cmd:4;
		__le32 res:13;
	};
	__le64 user;
	__le64 param_data;
	__le64 dev_sid;
	__le64 dev_eid;
	__le64 dev_shm_addr;
	__le64 priv[0];
} __attribute__((__packed__));

struct task_perf_desc {
	__le64 topo_id;
	__le64 host_invoke_ns;
	__le64 correlation_id;
} __attribute__((__packed__));

struct task_desc_topo_priv {
	__le64 dev_topo_id;
	__le64 dev_topo_node_index;
	__le64 topo_info;
} __attribute__((__packed__));

#define TASK_DESC_PRIV_MAX_SIZE		\
	(sizeof(__le64) * TASK_DESC_SIZE -	\
		sizeof(struct task_desc_data_v1) -	\
		sizeof(struct task_perf_desc) -		\
		sizeof(struct task_desc_topo_priv))

#define sbts_td_priv_size_check(size) sbts_compile_check((long)ALIGN(size, 8) > (long)TASK_DESC_PRIV_MAX_SIZE);

/* task_desc_data_v1->priv */
struct td_place_dma_task {
	__le64 queue_sid;
	__le64 index;
	__le64 host_vaddr;
	__le64 device_vaddr;
	__le64 total_size;
	__le32 direction;
	__le32 trg_type;
	/* arm trigger flag */
	__le64 desc_device_va;
	__le64 desc_len;
};

/* task_desc_data_v1->priv */
struct td_launch_func_kernel {
	__le64 kernel_type;
	__le64 size;
	__le64 src;
	__le64 dst;
};

struct td_notifier_task {
	__le64 unique_val;
	__le64 ack_addr;
	__le64 free_seq;
	/* debug info */
	__le64 q_idx;
	__le32 dev_idx;
	/* this can be bool */
	__le32 excep_infect;
	/* for topo */
	__le64 q_total;
};

struct td_place_jpu_task {
	__le32 type;
	__le32 batch_head;
	__le32 dataq_size;
	__le32 block_id;
	__le32 dataq_seg_size[4];
	__le64 dataq_addr;
	__le64 cb_func;
	__le64 buf_hdl;
	__le64 efd_queue_sid;
};

struct td_invoke_topo_task {
	__le64 dev_topo_id;
	/* bit map for some info */
	__le64 invoke_extra_info;
	/* for perf info */
	__le64 perf_task;
	__le64 correlation_id;
	__le64 host_invoke_ns;
	__le64 topo_id;
};

/* ctrl descriptor */
enum ctrl_type {
	CREATE_QUEUE = 0,
	DESTROY_QUEUE,
	CREATE_NOTIFIER,
	DESTROY_NOTIFIER,
	CORE_DUMP_DONE,
	CNGDB_TASK,
	GET_HW_INFO,
	COMMU_DETACH,
	NCS_COMM_CMD,
	LPM_SET,
	DEBUG_CTRL,
	HW_CFG_HDL,
	KPRINTF_SET,
	TASK_ACCELERATE,
	IDC_CTRL,
	P2PSHM_CTRL,
	QUEUE_SCH_POLICY,
	TCDP_COMM_CMD,
	TSINFO_SIZE_GET,
	ATOMICOP_CTRL,
	CORE_TYPE_POLICY,
	TASK_TOPO_CTRL,
};

struct comm_ctrl_desc {
	__le64 version;		/* version */
	__le64 sta;
	/* data */
	__le64 data[CTRL_DESC_SIZE];
};

/* comm_ctrl_desc->data */
struct ctrl_desc_data_v1 {
	__le64 type;
	__le64 user;
	__le64 priv[0];
};

#define CTRL_DESC_PRIV_MAX_SIZE		\
	(sizeof(__le64) * CTRL_DESC_SIZE - sizeof(struct ctrl_desc_data_v1))

#define sbts_cd_priv_size_check(size) sbts_compile_check((long)ALIGN(size, 8) > (long)CTRL_DESC_PRIV_MAX_SIZE);

/* kernel printf comm desc */
struct comm_kprintf_desc {
	__le64 version;
	__le64 kfdata_cnt;
	__le64 data[KPRINTF_DESC_SIZE];
};

/* host function comm desc */
struct comm_hostfn_desc {
	__le64 trigger_type;
	__le64 version;
	__le64 hqueue;
	__le64 host_finish_sig_addr;
};

/* buffer to transmit param_buf and free_queue_buf */
struct cd_param_buf_trans_msg {
	dev_addr_t param_buf_dev_addr;
	dev_addr_t free_queue_dev_addr;
	u64 queue_size;
};

/* ctrl_desc_data_v1->priv */
struct cd_create_queue {
	__le64 core_dump_en;
	__le64 dump_version;
	__le64 dev_ret_iova;
	__le64 host_sid;
	__le64 priority;
	__le64 dev_sid; /* dtoh return value */
	__le64 tgid_entry_id;
	__le64 unique_id;
} __attribute__((__packed__));
/* ctrl_desc_data_v1->priv */
struct cd_destroy_queue {
	__le64 dev_sid;
	__le64 queue_ticket;
	__le64 sync_ticket;
	__le64 topo_param_cnt;
};
/* ctrl_desc_data_v1->priv */
struct cd_create_notifier {
	__le64 flag;
	__le64 dev_ret_iova;
	__le64 dev_eid; /* dtoh return value */
};
/* ctrl_desc_data_v1->priv */
struct cd_destroy_notifier {
	__le64 dev_eid;
	__le64 waiter_nr;
	__le64 capturer_nr;
};
/* ctrl_desc_data_v1->priv */
struct cd_set_localmem {
	__le64 mem_size;
};
/* ctrl_desc_data_v1->priv */
struct cd_cngdb_task {
	__le64 dev_ack_iova;
	__le64 priv[0];
};
/* ctrl_desc_data_v1->priv */
struct cd_core_dump {
	__le64 dev_sid;
};

struct cd_get_hw_info {
	__le64 dev_iova;
	__le64 shm_size;
};

struct cd_lpm_set {
	__le64 ops;
	__le64 gate_count;
	__le64 ref_count;
};

struct cd_hw_cfg_hdl {
	__le64 type;
	__le64 val;
};

struct cd_hf_priv_data {
	__le64 host_finish_sig_va;
	__le64 hqueue;
};

/* used for TSINFO_SIZE_GET */
struct cd_perf_tsinfo_size_get {
	__u64 task_type;
	__u64 unique_seq_id;
	__u32 normal_size;
	__u32 append_size;
} __attribute__((__packed__));

enum queue_schedule_policy {
	QUEUE_SCH_POLICY_QFS = 0,
	QUEUE_SCH_POLICY_NOOP,
	QUEUE_SCH_POLICY_NUM,
};

struct cd_queue_sch_policy {
	__le64 policy;
};

enum user_schedule_policy {
	SCH_POLICY_AUTO = 0,
	SCH_POLICY_ACC,
	SCH_POLICY_NORMAL,
	SCH_POLICY_NUM,
};

struct cd_schedule_policy {
	__le64 policy;
};

enum aiisp_core_policy {
	CORE_TYPE_NN_NN = 0,
	CORE_TYPE_NN_ISP,
	CORE_TYPE_POLICY_NUM,
};

struct cd_aiisp_core_policy {
	__le64 policy;
};

enum debug_ctrl_type {
	DEBUG_GET_CORE_INFO = 0,/* [0]:version, [1]:number, [2]:each_size */
	DEBUG_GET_TASK_INFO,	/* [0]:version, [1]:size */
	DEBUG_INIT_CORE_INFO,	/* [0]:shm_iova, [1]:total_size */
	DEBUG_INIT_TASK_INFO,	/* [0]:shm_iova, [1]:total_size, [2]:pid */
	DEBUG_EXIT_CORE_INFO,	/* none */
	DEBUG_EXIT_TASK_INFO,	/* [0]:pid */
	DEBUG_REGISTER_USER,	/* [0]:pid */
	DEBUG_UNREGISTER_USER,	/* [0]:pid */
	DEBUG_UPDATE_HEAD,		/* [0]:pid, [1]:head */
	DEBUG_CTRL_NUM,
};

struct cd_debug_ctrl {
	__le64 type;
	__le64 priv[4];
};

struct param_buf_trans_msg {
	__le64 param_buf_dev_addr;
	__le64 free_queue_dev_addr;
	__le64 queue_size;
};

enum delay_free_type {
	DFREE_PARAM_BUF = 0,
	DFREE_D2D_ASYNC,
	DFREE_NOTIFIER_FREE,
};

#define NOTIFIER_DELAY_FREE_ORDER   (4)
#define NOTIFIER_DELAY_FREE_NUM     (1U << NOTIFIER_DELAY_FREE_ORDER)
struct notifier_delay_free_addr {
        __le64 ticket;
};
struct cd_dfree_notifier_desc {
        __le64 buf_num;
        struct notifier_delay_free_addr buf_addr[NOTIFIER_DELAY_FREE_NUM];
};

#define ASYNC_D2D_FREE_ORDER   (3)
#define ASYNC_D2D_FREE_NUM     (1U << ASYNC_D2D_FREE_ORDER)
struct d2d_async_free_addr {
	__le64 ticket;
};
struct cd_dfree_d2d_async_desc {
	__le64 buf_num;
	struct d2d_async_free_addr buf_addr[ASYNC_D2D_FREE_NUM];
};

struct free_buf_addr {
	/* param buffer addr need to be freed */
	__le64 param_buf;
};

#define MAX_FREE_BUF_ORDER (4)
#define MAX_FREE_BUF_NUM   (1U << MAX_FREE_BUF_ORDER)
struct cd_dfree_host_buf_desc {
	__le64 buf_num;
	struct free_buf_addr buf_addr[MAX_FREE_BUF_NUM];
};

/* p2pshm communication structure */
struct cd_p2pshm_tbl_info {
	__u8 p2pshm_algo;
	__u8 outb_win_type;
	__le16 outb_win_idx;
	__le64 outb_win_dev_pa;
	__le32 outb_win_sz;
	__le32 current_idx;
	__le32 ncards;
	__le64 info_iova;
} __attribute__((__packed__));

struct cd_dev_topo_ctrl {
	__le32 cmd_type;
	__le32 node_nums;
	__le64 dev_topo_id;
	__le64 leader_queue;
	__le32 queue_nums;
	__le32 reserve;
	__le64 trigger_send;
	__le64 param_send;
	__le64 node_send;
} __attribute__((__packed__));

/* cngdb function type */
enum cngdb_task_type {
	CNGDB_KERNEL_INSIDE = 0,
	CNGDB_TASK_ASYNC,
	CNGDB_GET_CORE_PC,
	CNGDB_RESUME_FROM_PC,
	CNGDB_CORE_DUMP,
	CNGDB_TASK_NUM,
};

enum data_ack_status {
	DATA_ACK_WAITING = 0,
	DATA_ACK_ERROR,
	DATA_ACK_FINISH,
};

#define CN_SBTS_RESOURCE_NOT_READY     1

struct sbts_fp_priv {
	struct sbts_set *sbts_set;
	/* user fp global seq */
	u64 fp_id;

	int tgid;

	void *topo_priv;
};


struct sbts_shm_iova_info {
	/* start addr */
	u64 addr;
	/* addr len in byte*/
	u32 addr_len;
	/* start idx num from total shm */
	u32 idx_start;
	/* index num by addr_len / shm page_size */
	u32 idx_num;
	/* index num of add each iova_info before and current */
	u32 max_idx;
};

enum sbts_shm_iova_sta {
	SBTS_SHM_IOVA_INIT = 0,
	SBTS_SHM_IOVA_READY,
	SBTS_SHM_IOVA_ERROR,
};
struct sbts_shm_iova_top {
	int sta;
	/* save origin shm host va */
	host_addr_t host_vaddr;
	/* iova num from sg list */
	unsigned int nents;
	/* save sgt for put */
	struct sg_table *iova_sgt;
	/* used dev bus set */
	struct cn_bus_set *req_bus;
	/* alloc memory iova num by nents */
	struct sbts_shm_iova_info *info;
};

/* queue and notifier share mem manager */
struct sbts_shm_manager {
	struct mutex shm_lock;

	host_addr_t host_vaddr;
	dev_addr_t dev_vaddr;

	u32 page_size;
	u32 nbits;
	u32 bitmap_size;
	unsigned long *bitmap;
};

int sbts_shm_init(struct sbts_shm_manager **shm_mgr, struct cn_core_set *core,
		u32 nbits, u32 page_size);
void sbts_shm_exit(struct sbts_shm_manager *shm_mgr, struct cn_core_set *core);
int sbts_shm_alloc(struct sbts_shm_manager *shm_mgr, struct cn_core_set *core,
		host_addr_t *host_vaddr, dev_addr_t *dev_vaddr);

int sbts_shm_get_host_iova(struct cn_core_set *core, struct cn_core_set *req_core,
		struct sbts_shm_manager *shm_mgr, dev_addr_t dev_vaddr, u64 *iova);

void sbts_shm_free(struct sbts_shm_manager *shm_mgr, dev_addr_t dev_vaddr);

void sbts_shm_global_dev_exit(struct sbts_set *sbts);
int sbts_shm_global_init(void);
void sbts_shm_global_exit(void);

struct delay_free_set {
	void *worker;
};

/* cngdb relate data structure */
struct data_ack_desc {
	__le64 status;
	__le64 data[0];	/* variable length */
} __attribute__((__packed__));

extern int
check_ack_data(struct cn_core_set *core, struct data_ack_desc *host_addr);

/* dirver-api param version decide the
 * structure of sbts hw info message.
 */
/* used before driver 4.8 */
struct user_sbts_info_v0 {
	__u64 cluster_num;
	__u64 ipu_core_num_per_clu;
	__u64 mem_core_num_per_clu;
	__u64 dump_header_size;
	__u64 ipu_dump_buf_size;
	__u64 mem_dump_buf_size;
	__u64 ldram_base_addr;
	__u64 ldram_stride;
	__u64 ct_ram_size;
	__u64 lt_ram_size;
	__u64 shared_mem_size;
	__u64 c2c_port_num;
};


/* dirver-api param version decide the
 * structure of sbts hw info message.
 */
/* used after driver 4.8 */
struct user_sbts_info_v3 {
	__u64 cluster_num;
	__u64 ipu_core_num_per_clu;
	__u64 mem_core_num_per_clu;
	__u64 dump_header_size;
	__u64 ipu_dump_buf_size;
	__u64 mem_dump_buf_size;
	__u64 ncs_dump_buf_size;
	__u64 ldram_base_addr;
	__u64 ldram_stride;
	__u64 ct_ram_size;
	__u64 lt_ram_size;
	__u64 shared_mem_size;
	__u64 c2c_port_num;
	/* v2: add support for TNC coredump */
	__u64 tiny_core_num;
	__u64 tnc_dump_buf_size;
	__u64 queue_dump_buf_size;
	/* v3: add tcdp proxy support */
	__u64 tcdp_proxy_driver_version;
	__u64 tcdp_proxy_rpc_buffer;
	/* ... */
};

typedef struct user_sbts_info_v3 user_sbts_info_t;

#define USER_SBTS_INFO_V1_SIZE (offsetof(user_sbts_info_t, tiny_core_num))
#define USER_SBTS_INFO_V2_SIZE (offsetof(user_sbts_info_t, tcdp_proxy_driver_version))
#define USER_SBTS_INFO_V3_SIZE (sizeof(struct user_sbts_info_v3))

struct sbts_core_info {
	__u64 dump_size;
	__u64 dump_addr;
	__u64 reserved_buf_addr;
	/* ... */
} __attribute__((__packed__));

enum sbts_work_thread_policy {
	POLICY_DEFAULT = 0,
	POLICY_HIGH_PRIO,
};

enum sbts_hw_cap_name {
	SBTS_HW_CAP_ATOMICOP_ENABLE = (0x1ULL),
	SBTS_HW_CAP_SRAM_ENABLE     = (0x1ULL << 1),
};

struct sbts_basic_info {
	__u64 cluster_num;
	__u64 ipu_core_num_per_clu;
	__u64 mem_core_num_per_clu;
	__u64 tiny_core_num;
	__u64 core_max_num;
	__u64 host_queue_depth;
	__u64 ipu_core_dump_size;
	__u64 mem_core_dump_size;
	__u64 tiny_core_dump_size;
	__u64 ncs_core_dump_size;
	__u64 ncs_core_dump_addr;
	__u64 reserved_buf_size;
	/* default local memory size in MB */
	__u64 local_mem_size;
	__u64 ldram_max_size;
	__u64 ldram_min_size;
	__u64 ldram_base_addr;
	__u64 ldram_stride;
	__u64 ct_ram_size;
	__u64 lt_ram_size;
	__u64 shared_mem_size;
	__u64 c2c_port_num;
	__u64 icache_miss_fetch_instnum;
	__u64 tnc_watchdog_timer;
	/* enum sbts_work_thread_policy */
	__u64 work_policy;
	__u64 hw_cap_bitmap;

	/* tcdp proxy driver info, default set 0 */
	__u64 tcdp_proxy_driver_version;
	__u64 tcdp_proxy_rpc_buffer;
	__u64 topo_node_bitmap;
	__u64 core_info[0];
} __attribute__((__packed__));

/* no need to add version in this struct,
 * cause device and host will update at the same time.
 */
struct sbts_hw_info {
	__u64 size;
	__u64 data[0];
} __attribute__((__packed__));

struct sbts_set {
	struct sched_manager *sched_manager;
	struct queue_manager *queue_manager;
	struct sbts_dbg_set *dbg_set;
	struct sbts_kprintf_set *kprintf_set;
	struct sbts_hostfunc_set *hostfunc_set;
	struct delay_free_set *delay_free_set;
	struct notifier_mgr *notifier_mgr;
	struct dma_async_manager *dma_async_manager;
	struct idc_manager *idc_manager;
	struct sbts_efd_manager *efd_manager;
	struct cn_core_set *core;
	struct sbts_hw_info *hw_info;
	struct sync_manager *sync_manager;
	struct queue_for_func_mgr *que_func_mgr;
	struct core_dump_manager *dump_mgr;
	struct jpu_manager *jpu_mgr;
	struct sbts_topo_manager *topo_manager;
	int schedule_policy;
	int queue_sch_policy;
	int aiisp_policy;
	struct mutex policy_lock;
	int low_power_mode;
	struct mutex lp_mode_lock;
	int is_support_tcdp;
	int outbd_able;

	struct {
		bool dev_sram_en;
		bool dev_atomicop_en;
	} __aligned(8);

	u32 max_queue;
	u32 max_notifier;
};

struct sched_manager {
	struct commu_channel *ctrl_chnl;
	struct commu_channel *task_chnl;
	struct commu_channel *dma_chnl;
	struct commu_channel *dfree_chnl;
	struct commu_channel *idc_chnl;
	struct commu_channel *dbg_chnl;
	struct commu_channel *core_dump_chnl;
	struct commu_channel *kprintf_chnl;
	struct commu_channel *hostfn_chnl;
	struct commu_channel *jpu_chnl;
	struct commu_endpoint *ctrl_ep;
	struct commu_endpoint *task_ep;
	struct commu_endpoint *dma_ep;
	struct commu_endpoint *dfree_ep;
	struct commu_endpoint *idc_ep;
	struct commu_endpoint *dbg_ep;
	struct commu_endpoint *core_dump_ep;
	struct commu_endpoint *kprintf_ep;
	struct commu_endpoint *hostfn_ep;
	struct commu_endpoint *jpu_ep;
	volatile unsigned long ctrl_fail_cnt;

	u64 ctl_ticket;
	u64 fail_cnt;
	struct sbts_set *sbts;
	/* __u64 user and payload_size */
	int (*ioctl)(struct sched_manager *,
				 struct comm_ctrl_desc *,
				 struct comm_ctrl_desc *,
				 __u64, __u64);
};

enum sbts_board_generation {
	SBTS_BOARD_GENERATION_1 = 1,
	SBTS_BOARD_GENERATION_2,
	SBTS_BOARD_GENERATION_3,
	SBTS_BOARD_GENERATION_5 = 5,
};
/* used for sbts low power */
enum sbts_lpm_ops {
	SBTS_LPM_RESUME = 1,
	SBTS_LPM_SUSPEND,
	SBTS_LPM_USER_MODE,
	SBTS_LPM_TASK_MODE,
	SBTS_LPM_GATE_COUNT,
};

/* func kernel management */
enum func_kernel_type {
	/*
	 * notice: need agree with device
	 */
	D2D_KERNEL_NORMAL = 1,
	D2D_KERNEL_ASYNC,
};

#ifdef CONFIG_CNDRV_SBTS
extern int cn_hw_cfg_compress_handle(struct cn_core_set *core);
#else
static inline int cn_hw_cfg_compress_handle(struct cn_core_set *core)
{
	return 0;
}
#endif
extern void sbts_get_board_generation(struct sbts_set *sbts, __u64 *type);

/* mlu hw info */
extern int cn_get_hw_info(struct sbts_set *);
extern void cn_release_hw_info(struct sbts_set *);

/* commu detach */
extern int sbts_commu_detach(struct sbts_set *);

__u32 sbts_task_get_perf_info(struct sbts_set *sbts, struct queue *queue,
		__u64 task_type, struct sbts_queue_invoke_task *user_param,
		struct task_desc_data_v1 *task_desc, u32 *priv_size);

static inline void sbts_task_disable_perf_info(struct task_desc_data_v1 *task_desc)
{
	task_desc->is_perf_task = false;
	task_desc->clk_id       = CN_DEFAULT_CLOCKID;
}

extern int
sbts_udelay_killable(struct cn_core_set *core, unsigned long time);

extern int
sbts_pause_killable(struct cn_core_set *core,
			unsigned long min, unsigned long max);

extern int
sbts_pause_stopable(struct cn_core_set *core,
			unsigned long min, unsigned long max);

extern int
sbts_pause(struct cn_core_set *core,
			unsigned long min, unsigned long max);

struct sbts_set *sbts_get_sbtsset_by_fd(int fd, cn_user *user);
/**
 * SBTS synchronization primitive related types and methods
 */
struct sbts_sync_desc {
	int (*sync_handler)(struct sbts_set *, void *);
	void *data;
	int exit_code;
	bool should_detach;
	struct completion completion_sync;
	union {
		struct llist_node l_entry;
		struct list_head entry;
	};
};

static inline void
init_sbts_sync_desc(struct sbts_sync_desc *desc,
		int (*h)(struct sbts_set *, void *),
		void *data)
{
	desc->sync_handler = h;
	desc->data = data;
	desc->exit_code = 0;
	desc->should_detach = false;
	init_completion(&desc->completion_sync);
}

extern int
sbts_wait_sync_desc_interruptible(struct sbts_set *sbts_set,
		struct sbts_sync_desc *desc);
extern void sbts_wake_up_sync_manager(struct sync_manager *sync_manager);

/* p2pshm API */
extern int sbts_p2pshm_alloc64(u64 *key);
extern void sbts_p2pshm_free64(u64 key);
extern int sbts_p2pshm_write64(u64 key, u64 val, u16 seq);
extern int sbts_p2pshm_read64(u64 key, u64 *val, u16 *seq);
extern int sbts_p2pshm_flush_write(void);
extern int sbts_p2pshm_enable(void);
extern int sbts_p2pshm_dev_rw(void);
extern u64 sbts_p2pshm_get_hostkva(__u64 key);
extern int sbts_p2pshm_get_hostiova_by_card(struct cn_core_set *core,
		__u64 key, __u64 *iova);

/* ncs internal API */
extern int destroy_ncs_resource(struct sbts_set *, cn_user);

#endif /* __SBTS_SBTS_H */
