#ifndef __CAMBRICON_MONITOR_PERF_H__
#define __CAMBRICON_MONITOR_PERF_H__

#include <linux/atomic.h>
#include <linux/mutex.h>
#include "cndrv_hpq.h"
#include "cndrv_mm.h"
#include "cndrv_perf_usr.h"
#include "monitor/monitor.h"


struct ts_offset_sample_data {
	u64 host_timestamp_ns;
	u64 device_timestamp_ns;
};

struct tk_base {
	__le32 clk_id;
	__le64 last_tsg_ns;
	__le64 offset_ns;
	__le64 offset_ns_err_per_second;
} __packed;

enum slave_tkb_id {
	SLAVE_TKB_MONO = 0,
	SLAVE_TKB_RAW,
	SLAVE_TKB_NUM,
};

#define MAX_SAMPLE_NUM  (3)
#define TK_BASE_BAK_NUM (10)
struct ts_sync_data {
	u64 last;
	u64 prev;
	u64 max_err_ns[TK_BASE_BAK_NUM];
	struct ts_offset_sample_data data[MAX_SAMPLE_NUM];
	struct tk_base dev_tk_base;
	struct tk_base tk_base_bak[TK_BASE_BAK_NUM];
};

struct time_sync_timestamp {
	__le64 dev_timestamp;
} __packed;

#define op(task_type, task_name) DECLARE_BITMAP(task_name##_bitmap, MAX_BITMAP);
struct perf_rpc_ctrl_msg {
	u32 version;
	u32 record_mode;
	u32 collection_mode;
	u32 performance_mode;
	u64 ctrl_ops;
	u64 unique_seq_id;
	u64 task_type;
	u64 buffer_size;
	s64 cur_clockid;
	u64 tgid;
	u64 tgid_iova;
	u64 perf_iova;
	__sbts_task_list(op)
} __packed;
#undef op

struct perf_rpc_cfg_info {
	u32 unique_seq_id;
	u64 data_size;
	u64 host_shm_addr;
	u64 dev_shm_addr;
}__packed;

struct perf_rpc_info_get {
	u64 dev_buf_addr;
	u64 buffer_size;
} __packed;

struct tgid_shm_data {
	u64 util;
};

struct tgid_process_util {
	u64 host_va;
	u64 dev_iova;
	u64 real_util;
	struct tgid_shm_data *shm;
};

#define op(task_type, task_name) DECLARE_BITMAP(task_name##_bitmap, MAX_BITMAP);
struct perf_tgid_entry {
	bool enable;
	int cur_clockid;
	u32 record_mode;
	u32 collection_mode;
	u32 performance_mode;
	pid_t cur_tgid;
	struct mutex enable_lock;
	struct list_head entry;
	u64 unique_seq_id;
	u64 task_type;
	u64 task_type_size_get;
	u64 buffer_size;
	u64 version;
	u64 feature;
	u64 enable_user;
	atomic_t ref_cnt;
	struct tgid_process_util util;
	struct pid_namespace *active_ns;
	/* host private */
	atomic_t usr_ref_cnt;
	atomic_t dev_ref_cnt;
	struct cn_monitor_set *monitor_set;
	u64 host_invoke;
	__sbts_task_list(op)
};
#undef op

struct perf_shm_data {
	u32 rd_seq;
	u32 wr_seq;
	u32 chip_util;
	u32 period_ns;
} __packed;

struct perf_process_util {
	u64 dev_iova;
	u64 host_va;
	u32 chip_util;
	u32 period_ns;
	struct perf_shm_data *shm;
};

struct monitor_perf_set {
	struct cn_core_set *core;
	struct cn_monitor_set *monitor_set;

	/* use when get host and device offset */
	spinlock_t ts_offset_lock;
	struct mutex ts_offset_mutex;

	host_addr_t tx_host_vaddr;
	dev_addr_t tx_dev_vaddr;
	host_addr_t rx_host_vaddr;
	dev_addr_t rx_dev_vaddr;
	STRUCT_HPAS_32(time_sync_ack, struct time_sync_timestamp) ack;

	struct ts_sync_data ts_sync_data[SLAVE_TKB_NUM];

	/* use when __time_sync_and_calculate() concurrency call */
	struct mutex time_sync_mutex;
	struct delayed_work time_sync_work;
	u64 delay_us;
	bool time_sync_work_active;

	u64 tgid_count;
	atomic64_t seq_id;
	struct rw_semaphore rwsem;
	struct list_head head;
	struct perf_process_util util;

	void *perf_ep;
	/* [DRVIER-3722] only use for commu_call_rpc_timeout */
	void *time_ep;
};

#define DEVICE_THREAD_CREATE (0x1)
#define DEVICE_THREAD_DESTROY (0x2)
struct ts_offset_rpc_set_s {
	u64 cmd;
	/* shm that host write and device read(polling) */
	u64 tx_vaddr;
	/* shm that device write and host read(polling) */
	u64 rx_vaddr;
};

/* perf buffer size validation check, max 16MB */
#define TS_INFO_BUF_SIZE_MAX (0x10 << 20)
#define TS_INFO_BUF_SIZE_MIN (0x100)

#define TIME_SYNC_TIMEOUT (10000UL)

/* shared memory management */
int cn_perf_shm_alloc(struct monitor_perf_set *perf_set,
					 host_addr_t *host_va,
					 dev_addr_t *dev_iova,
					 u64 size);
void cn_perf_shm_free(struct monitor_perf_set *perf_set,
					  host_addr_t host_va,
					  dev_addr_t dev_iova);

int monitor_perf_init(struct cn_monitor_set *monitor_set);
void monitor_perf_free(struct cn_monitor_set *monitor_set);

int monitor_perf_restart(struct cn_monitor_set *monitor_set);
void monitor_perf_stop(struct cn_monitor_set *monitor_set);

void cn_perf_time_sync_show(struct seq_file *m, struct cn_core_set *core);
int __task_type_is_sbts(u64 task_type);

#endif
