/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_CNDRV_MONCOMMON_H__
#define __CAMBRICON_CNDRV_MONCOMMON_H__

struct device;
struct cn_core_set;
struct perf_tgid_entry;

struct monitor_version_check_v1 {
	__u32 papi_version;
	__u32 drv_version;
} __packed;

#define CN_DEFAULT_CLOCKID CLOCK_MONOTONIC_RAW
struct sbts_perf_info {
	int clk_id;
	__u32 work_mode;
	__u32 collection_mode;
	__u32 performance_mode;
	bool host_invoke;
};

long cn_monitor_ioctl(void *fp,
				void *pcore,
				unsigned int cmd,
				unsigned long arg);

int cn_monitor_late_init(struct cn_core_set *pcore);
void cn_monitor_late_exit(struct cn_core_set *pcore);
void cn_monitor_earlyexit(void *pcore);

int cn_monitor_private_data_init(struct fp_priv_data *priv_data);
void cn_monitor_private_data_exit(struct fp_priv_data *priv_data);

void cn_monitor_do_exit(u64 fp, void *pcore);

int cn_monitor_restart(void *pcore);
void cn_monitor_stop(void *pcore);

int cn_monitor_init(struct cn_core_set *core);
void cn_monitor_exit(struct cn_core_set *core);

void cndev_print_debug_set(struct cn_core_set *core, unsigned long usr_set);
bool cndev_print_debug_get(struct cn_core_set *core);
bool file_is_cndev(struct file *fp);

#define DEFINE_GET_PRIVDATA(name) \
	void *cndev_get_##name##_priv(struct file *fp);

DEFINE_GET_PRIVDATA(udvm);
DEFINE_GET_PRIVDATA(hostmem);

int cn_monitor_ts_offset_calculate(struct cn_core_set *core);
int cn_monitor_ts_offset_calculate_in_late_init(struct cn_core_set *core);
void cn_monitor_ts_offset_calculate_in_late_exit(struct cn_core_set *core);
bool cn_monitor_perf_info_enable_task_type(struct perf_tgid_entry *tgid_entry, struct cn_core_set *core,
		u64 task_type, struct sbts_perf_info *perf_info);
u64 cn_monitor_perf_get_sbts_task_type(struct perf_tgid_entry *tgid_entry, int *clock_id);
bool
cn_monitor_perf_type_check_clockid(struct perf_tgid_entry *tgid_entry,
		struct cn_core_set *core, __u64 task_type, int *clock_id);
int get_host_timestamp_clockid(u64 user, struct cn_core_set *core);
u64 get_host_timestamp_by_clockid(int clockid);
long cn_monitor_axi_driver_ver(void *mset, unsigned long arg);
void cn_monitor_init_drv_ver(void *mset);
long cn_monitor_hub_ctrl_common(void *mset, unsigned long arg);
long cn_monitor_read_ringbuf_pos_common(void *mset, unsigned long arg);
long cn_monitor_highrate_param_common(void *mset, unsigned long arg);
void cn_perf_private_data_exit(struct fp_priv_data *priv_data);
int cn_perf_private_data_init(struct fp_priv_data *priv_data);
/* smlu helper */
int cn_perf_process_ipu_util_update_from_shm(struct cn_core_set *core, int retry);
int cn_perf_process_ipu_util_fill_pid_info(struct pid_info_s *pid_info);
int cn_perf_ipu_chip_util_get(struct cn_core_set *core);
int cn_perf_namespace_ipu_util_get(struct cn_core_set *core, struct pid_namespace *active_ns, u64 *ns_util);

void cn_perf_tgid_entry_show(struct seq_file *m, struct cn_core_set *core);
void tgid_entry_put(struct perf_tgid_entry *tgid_entry);
struct perf_tgid_entry * tgid_entry_get(u64 user);
u64 get_tgid_entry_id(struct perf_tgid_entry *tgid_entry);
bool __cn_perf_by_pass(struct cn_core_set *core);
#endif /*__CAMBRICON_CNDRV_MONCOMMON_H__*/
