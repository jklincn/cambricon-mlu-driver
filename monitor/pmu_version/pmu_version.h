#ifndef __CAMBRICON_PMU_VERSION_H__
#define __CAMBRICON_PMU_VERSION_H__

int cn_monitor_axi_open_common(void *mset, void *mon_conf);
int cn_monitor_axi_openall_common(void *mset, u8 hub_id);
long cn_monitor_read_data_common(void *mset, void *arg);
long cn_monitor_hub_ctrl_common(void *mset, unsigned long arg);
long cn_monitor_read_ringbuf_pos_common(void *mset, unsigned long arg);
long cn_monitor_highrate_param_common(void *mset, unsigned long arg);
int cn_monitor_get_param_common(void *mset, void *data);
int cn_monitor_get_axistruct_size(void *mset, u32 *size);
int cn_monitor_get_basic_param_size(void *mset, u32 *size);
int cn_pmu_version_check(void *mset, u32 papi_version, u64 *feature_data, u64 len, u64 *pmu_version);
int cn_pmu_reinit_version(void *mset);

#endif
