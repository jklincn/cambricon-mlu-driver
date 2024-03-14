#ifndef __CAMBRICON_MEM_PERF_H__
#define __CAMBRICON_MEM_PERF_H__

#define MEM_PERF_BUF_SIZE_MIN		(0x100)
#define MEM_PERF_BUF_SIZE_MAX		(0x10 << 20)

struct mem_perf_data {
	u32 append_num;
	u64 event_type_bitmap;/*Which data can be appended.*/
	struct task_ts_info mem_info;/*the actual mem perf data.*/
};

/**
 * The mem_perf_buf format as follow:
 *
 *   address     data_address
 *     ||           ||
 *     \/           \/
 * ------------------------
 * |  buf_head  | data ...
 * ------------------------
 *
 **/
struct mem_perf_buf {
	/*same as struct mem_perf_tgid_entry.buf_size*/
	u64 buf_size;

	u64 seq;
	/*struct mem_task_info count in data_address*/
	u64 valid_entry_num;

	/*address is the begin of buffuer.*/
	u64 address;
	struct perf_ts_info_header buf_head;

	/*data_address = address + sizeof(struct perf_ts_info_header)*/
	u64 data_address;
	u64 total_data_size;/*The data_address total size when malloc*/
	u64 valid_data_size;/*valid size of data_address*/
};

struct mem_perf_tgid_entry {
	bool enable;
	bool version_check;
	pid_t cur_tgid;
	pid_t active_pid;
	struct mutex enable_lock;
	struct list_head entry;
	u64 unique_seq_id;
	u64 version;/*The driver_papi_version_check*/
	__u64 feature;
	u64 enable_user;/*save tag*/
	atomic_t ref_cnt;
	struct mem_perf_buf perf_buf;

	u64 task_type; /*which task will actual be perf. This is some task.*/
	u64 task_type_size_get;/*which task can be perf.This is all task.*/

	/*User will configuration which task type to this perf.All task type in the cfg_tasks. */
	struct perf_cfg_tasks *cfg_tasks;
	u64 cfg_tasks_cnt;
};

struct cn_mem_perf_priv_data {
	struct mem_perf_tgid_entry *tgid_entry;
};

#endif
