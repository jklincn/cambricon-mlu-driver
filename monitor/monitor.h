#ifndef __CAMBRICON_CNDRV_MONITOR_H__
#define __CAMBRICON_CNDRV_MONITOR_H__
#include <linux/seq_file.h>
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "./axi_monitor/cndrv_axi_monitor.h"
#include "./highrate/cndrv_monitor_highrate.h"
#include "include/cndrv_monitor_usr.h"
#include "include/cndrv_perf_usr.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif

#define MON_GET_PARAM                "monitor_rpc_get_param"
#define MON_GET_PMU_LATEINIT         "monitor_rpc_lateinit"
#define MON_GET_PMU_EARLYEXIT        "monitor_rpc_earlyexit"
#define MON_OPEN_AXIM                "monitor_rpc_axi_open"
#define MON_CLOSE_AXIM               "monitor_rpc_axi_close"
#define MON_SET_TS                   "monitor_rpc_axi_hub_set_ts"
#define MON_READ_AXIM_IRQ_STA        "monitor_rpc_axi_read_irqstatus"
#define MON_READ_AXIM_ERR_INF        "monitor_rpc_axi_read_errorinfo"
#define MON_SET_AXIH_DIRECT_MODE     "monitor_rpc_axi_direct_mode"
#define MON_SET_IPU_PROF             "monitor_rpc_set_ipu_prof"
#define MON_SET_IPU_PERF             "monitor_rpc_set_ipu_perf"
#define MON_SET_SMMU_PERF            "monitor_rpc_set_smmu_perf"
#define MON_SET_LLC_PERF             "monitor_rpc_set_llc_perf"
#define MON_SET_l1C_PERF             "monitor_rpc_set_l1c_perf"
#define MON_CTRL_l1C_PERF            "monitor_rpc_ctrl_l1c_perf"
#define MON_SET_PMU_HIGHRATE_MODE    "monitor_rpc_set_highratemode"
#define MON_CLEAR_PMU_DATA           "monitor_rpc_request_clear_data"
#define MON_EXIT_HOST                "monitor_host_do_exit"
#define MON_START_HOST               "monitor_host_start"
#define MON_START_HUB_TRACE          "monitor_rpc_request_hub_trace"
#define MON_GET_PFMU_CNTR_NUM        "monitor_rpc_pfmu_get_counter_num"
#define MON_SET_PFMU_CNTRS           "monitor_rpc_pfmu_set_counter_type"
#define MON_GET_PFMU_CNTR            "monitor_rpc_pfmu_get_counter_type"
#define MON_CTRL_PFMU_PERF           "monitor_rpc_ipu_cluster_pfmu_start_stop"
#define MON_CONFIG_PFMU_SNAPHOST_PC  "monitor_rpc_ipu_cluster_pfmu_set_snapshot_pc"
#define MON_SET_AXIM_SAMPLING        "monitor_rpc_set_sampling"
#define MON_INIT_PMU_HIGHRATE_MODE   "monitor_rpc_axi_highrate_mode"
#define MON_STOP_HUB_TRACE           "monitor_rpc_stop_hub_trace"
#define MON_UPADATE_PERF_DATA        "monitor_rpc_start_update_perf_data"
#define MON_GET_PFMU_CONFIG          "monitor_rpc_pfmu_get_counter_setting"
#define MON_SET_PFMU_CNTR            "monitor_rpc_pfmu_set_counter_type_alone"
#define MON_CTRL_PFMU                "monitor_rpc_ipu_pfmu_ctrl"
#define MON_GET_IPU_L2P_MAP          "monitor_rpc_hubtrace_l2p"
#define MON_CONFIG_HUB_TRACE         "monitor_rpc_set_hub_trace"

#define monitor_cp_less_val(user_len, kern_len, user, kern, len)	\
({	\
	int __ret = 0;	\
	int n = *(user_len) < kern_len ? *(user_len) : kern_len;	\
	*(user_len) = kern_len;	\
	if (user)	\
		__ret = cndev_cp_to_usr(user, kern, n * len);	\
	__ret;	\
})

#define monitor_cp_from_usr(user_len, kern_len, user, kern, len)	\
({	\
	int __ret = 0;	\
	int n = *(user_len) < kern_len ? *(user_len) : kern_len;	\
	*(user_len) = n;	\
	if (user) {	\
		__ret = copy_from_user((void *)kern, (void *)user, n * len);	\
		if (__ret) {	\
			pr_err("[%s] [%d] copy_from_user failed\n", __func__, __LINE__);	\
			__ret = -EFAULT;	\
		}	\
	}	\
	__ret;	\
})

struct monitor_perf_set;

#define CN_MONITOR_SUPPORT 0
#define CN_MONITOR_NOT_SUPPORT 1

/*use for late init*/
enum SM_INFO {
	PMU_INFO = 0,
	PMU_PERF_INFO = PMU_INFO,
	PMU_AXIM_INFO = 1,
	TOTAL_PMU_SM_INFO,
};

enum cn_pmu_drv_feature_status {
	CN_PMU_FEAT_NOT_SUPPORT,
	CN_PMU_FEAT_SUPPORT,
	CN_PMU_FEAT_BYPASS,
};

struct sharemem_info {
	u64 sharememory_va;
	size_t sharememory_size;
};

struct cn_monitor_lateset {

	u8 sm_info_cnt;
	u32 sm_info_mask;
	struct sharemem_info sm_info[TOTAL_PMU_SM_INFO];

	/*board type*/
	u8 board_type;
};

struct cn_monitor_ops {
	int (*pmu_monitor_lateinit)(void *pcore);
	void (*pmu_monitor_earlyexit)(void *pcore);
};

struct pmu_data_layout {
	unsigned long host_va;
	size_t buffer_size;
};

struct cn_monitor_set {
	struct cn_core_set *core;
	void *bus_set;
	void *axi_set;
	void *cndev_set;
	struct monitor_perf_set *perf_set;

	/*bug report dfx*/
	struct cn_report_block *pmu_report;

	void *endpoint;

	u8 board_type;
	/*for monitor buffer*/
	unsigned long sharememory_host_va[TOTAL_PMU_SM_INFO];
	u64 sharememory_device_va[TOTAL_PMU_SM_INFO];
	size_t sharememory_size[TOTAL_PMU_SM_INFO];

	/*use to save user fp*/
	u64 lock_fp;

	u32 hub_num;

	struct cn_axi_monitor_config *config;

	struct cn_aximhub_ops ops;

	struct task_struct *profiling_worker;

	u64 device_va_addr;

	struct cn_monitor_highrate_set *monitor_highrate_set;

	u32 highrate_start[16];

#define AXI_MONITOR_NORMAL_MODE        (0)
#define AXI_MONITOR_MATCH_ALL_MODE     (2)
	u8 highrate_mode;

	u8 amh_type_perf;
	u8 amh_type_time;

	u8 die_cnt;

	struct cn_aximhub_data_parse_ops *parse_ops;

	u32 monitor_version;

	struct cn_monitor_ops *mon_ops;

	struct pmu_data_layout *shmem_layout;

	struct cn_aximonitor_ops *monitor_ops;

	struct cn_aximon_zone_info *zone_info;

	struct axi_hubtrace_map_ipu_info *mlu_hubtrace_table;

	u64 support_data_mode;

	void *res_param;
	u64 pmu_version;
	u64 rec_version;
	u64 support_l1c;
	struct mutex pmu_ver_mutex;

	u64 support_monitor;
};

struct axi_param_s {
	u8 hub_num;
	u8 monitor[10];
	u64 phy_ipu_cluster_mask;
	u16 logic_ipu_cluster_cnt;
	u16 ipu_core_pre_cluster;
	u8 llc_group;
	u8 jpu_num;
	u8 smmu_group_num;
	u8 ipu_core_num;
	u8 ipu_cluster_num;
	u8 llc_num;
	u64 phy_tnc_cluster_mask;
	u8 tnc_core_num;
	u8 tnc_cluster_num;
};

struct counter_info_s {
	int ret;
	__u32 cluster_id;
	__u32 core_id;
	__u32 cnt_num;
	__u32 cnt_type[16];
};

struct pfmu_id_info_s {
	__u32 cluster_id;
	__u32 core_id;
};

struct counter_num_s {
	int ret;
	__u32 cnt_num;
};

struct pfmu_event_info_s {
	int ret;
	__u32 cluster_id;
	__u32 core_id;
	__u32 cnt_num;
	__u64 event_mask;
	__u32 event_type[16];
};

struct perf_update_rpc_info {
	int ret;
	__u32 update_status;
	__u16 ipu_perf_entry_count;
	__u16 smmu_perf_entry_count;
	__u16 llc_perf_entry_count;
	__u16 smmu_exp_entry_count;
	__u16 l1c_entry_count;
};

enum pfmu_hubtrace_type {
	PFMU_IPU = 0,
	PFMU_TINYCORE,
};

struct pfmu_hubtrace_l2p {
	int ret;
	__u32 type;
	__u32 cluster_num;
	__u32 full_cluster_num;
	__u8 l2p[64];
};

struct cn_monitor_priv_data {
	atomic64_t monitor_lpm_count;
};

/* ts perf private data and funcs */
#define DRIVER_FEAT_MASK (DRIVER_FEAT_TS_PERF_START | DRIVER_FEAT_MONITOR_START | DRIVER_FEAT_MEM_PERF_START | DRIVER_FEAT_MEM_CP_START)
#define DRIVER_FEAT_MONITOR_MAX_SUPPORT DRIVER_FEAT_MONITOR_L1C_PERF
#define DRIVER_FEAT_TS_PERF_MAX_SUPPORT DRIVER_FEAT_TS_PERF_UNIQUE_ID
#define DRIVER_FEAT_MEM_PERF_MAX_SUPPORT DRIVER_FEAT_MEM_PERF_BASE_V1
#define DRIVER_FEAT_MEM_CP_MAX_SUPPORT DRIVER_FEAT_MEM_CP_BASE

struct perf_cfg_data {
	struct perf_cfg_tasks *ts_perf;
	__u64 ts_num;
	__u64 ts_size;
	struct perf_cfg_tasks *mem_perf;
	__u64 mem_num;
	__u64 mem_size;
}__attribute__((__packed__));

struct __perf_mode_cfg {
	__u32 perf_ctrl;
	__u32 record_mode;
	union {
		struct {
			__u32 work_mode;
			__u32 collection_mode;
			__u32 performance_mode;
			__u64 buffer_size;
		}__attribute__((__packed__));
		struct {
			__u32 data_size;
			__u32 debug_data_size;
			struct perf_cfg_tasks *data_ptr;
			struct perf_cfg_tasks *debug_ptr;
			__u64 ts_buffer_size;
			__u64 mem_buffer_size;
		}__attribute__((__packed__));
	}__attribute__((__packed__));
}__attribute__((__packed__));

void monitor_PrintLog(const char *fmt, ...);

/*monitor top function*/
int cn_monitor_get_param_len(void);
int cn_monitor_get_axiperf_len(void);
int cn_monitor_get_pmustruct_len(void);

int cn_monitor_get_param(void *mset, void *pdata);
int cn_monitor_axi_highrate_open(void *mset, void *mon_conf);
int cn_monitor_axi_highrate_close(void *mset, u16 monitor_id);
int cn_monitor_axi_highrate_openall(void *mset, u8 hub_id);
int cn_monitor_axi_highrate_closeall(void *mset, u8 monitor_id);

void cn_monitor_axi_struct_default(void *mon_conf);
void cn_monitor_pmu_struct_default(void *mon_conf);
int cn_monitor_axi_open(void *mset, void *mon_conf);
int cn_monitor_axi_close(void *mset, u16 monitor_id);
int cn_monitor_axi_openall(void *mset, u8 hub_id);
int cn_monitor_axi_closeall(void *mset, u8 monitor_id);
int cn_monitor_set_ts_mode(void *mset, u16 mode_para);
int cn_monitor_axi_read_irqstatus(void *mset, void *irq_status);
int cn_monitor_axi_read_errorinfo(void *mset, void *err_info);
int cn_monitor_axi_read_posinfo(void *mset, void *err_info);
int cn_monitor_get_pmu_struct_size(void *mset, u32 *size);
int cn_monitor_get_axi_struct_size(void *mset, u32 *size);

int cn_monitor_axi_finish(void *mset, u8 hub_id);
int cn_monitor_axi_direct_mode(void *mset, void *mode_info);
int cn_monitor_axi_highrate_mode(void *mset, void *mode_info);
size_t cn_monitor_dma(void *bus_set, u64 host_addr, u64 dev_addr,
		size_t size, DMA_DIR_TYPE direction);
int cn_monitor_read_ring_buffer(void *mset, struct monitor_read_buffer *ring_info);
int cn_monitor_read_data(void *mset, void *arg);
int cn_pmu_read_data(struct cn_monitor_set *mset, struct pmu_data_s *arg);
int cn_pmu_update_perf_data_async(struct cn_monitor_set *mset, void *info);
int cn_monitor_highrate_read_data(void *mset, void *arg);
int cn_monitor_set_ipu_profiling(void *mset, void *prof);
int cn_monitor_set_ipu_perf(void *mset, void *perf);
int cn_monitor_set_smmu_perf(void *mset, void *perf);
int cn_monitor_set_llc_perf(void *mset, void *perf);
int cn_monitor_set_l1c_perf(void *mset, void *perf);
int cn_monitor_ctrl_l1c_perf(void *mset, void *perf);
int cn_monitor_clr_pmu_data(void *mset, void *data);
int cn_monitor_request_hub_trace(void *mset, void *data);
int cn_monitor_get_counter_num(void *mset, void *cnt_num);
int cn_monitor_get_counter_type(void *mset, void *cnt_type);
int cn_monitor_set_counter_type(void *mset, struct pfmu_counter_type *cnt_type);
int cn_monitor_set_snapshot_pc(void *mset, struct pfmu_snapshot_pc *snapshot);
int cn_monitor_pfmu_start(void *mset, void *perf);
int cn_monitor_pfmu_get_event(void *mset, void *event);
int cn_monitor_pfmu_set_event(void *mset, void *event);
int cn_monitor_pfmu_ctrl(void *mset, void *ctrl);
int cn_monitor_set_highratemode(void *mset, int state);
int cn_monitor_host_start(void *mset);
int cn_monitor_host_exit(void *mset);
int cn_monitor_stop_hub_trace(void *mset, void *data);
int cn_monitor_set_hub_trace(void *mset, void *hub_trace);

int cn_monitor_rpc_register(void *pcore);

/* process util relate fucntion */
struct perf_tgid_entry;
struct perf_tgid_entry *pid_info2tgid_entry(struct pid_info_s *pid_info);
/* MUST call after update success */
u64 perf_process_util_get(struct perf_tgid_entry *entry);
/* MUST call after update success */
u32 perf_chip_util_get(struct monitor_perf_set *perf_set);
/* retval: 0 success; -EAGAIN need retry */
int perf_process_util_update(struct monitor_perf_set *perf_set, int retry);

/* perf timestamp related api */
void cn_monitor_perf_tgid_exit(u64 fp, struct cn_monitor_set *monitor_set);
/* int cn_monitor_ts_info_set(void *fp, struct cn_monitor_set *monitor_set, */
/* 							unsigned long arg); */
/* int cn_monitor_ts_info_get(void *fp, struct cn_monitor_set *monitor_set, */
/* 							struct monitor_ts_info_get *usr_ts_info_get); */
int cn_monitor_ts_offset_get(struct cn_monitor_set *monitor_set,
							struct monitor_ts_offset *ts_offset);

int cn_monitor_axi_wake_monitor_hub_thread(void *mset, void *mode_info);

int cn_monitor_reset_kfifo_mem(struct cn_monitor_set *monitor_set);

void cn_monitor_reset_highrate_context(struct highrate_thread_context *thread_context);

int cn_monitor_axi_start_openall(void *mset, u8 hub_id);
int cn_monitor_get_highrate_param_ver(void *mset, unsigned long arg);
long cn_monitor_card_info(void *mset, unsigned long arg);
int cn_monitor_read_data_ver(void *mset, void *arg);
int cn_monitor_update_perf_data_async(void *mset, unsigned long arg);
int cn_monitor_get_basic_param(void *mset, void *pdata);
int cn_monitor_compatible_read_data(void *mset, void *arg);
int cn_monitor_pfmu_get_hubtrace_l2p(void *mset, void *map_info);
int cn_monitor_axi_open_with_bw_mode(void *mset, void *mon_conf);
int cn_monitor_get_baisc_param_size(u32 *size);
long cn_monitor_read_ringbuf_pos(void *mset, unsigned long arg);
int cn_monitor_get_basic_param_data(void *mset, void *pdata);
long cn_monitor_get_highrate_param(void *mset, unsigned long arg);
long cn_monitor_hub_ctrl(void *mset, unsigned long arg);
int cn_monitor_get_resource_param(void *mset, void *pdata);

/* monitor perf export ops */
extern u64 __tsperf_get_feature(void *fp, struct cn_monitor_set *mset);
extern int __perf_version_check(void *fp, struct cn_monitor_set *monitor_set,
		u64 papi_version, u64 *sub_feature, u64 fdata_len, u64 *perf_version);
extern int cn_monitor_perf_mode_config(void *fp, struct cn_monitor_set *monitor_set,
		struct __perf_mode_cfg *mode_config, struct perf_cfg_data __perf_cfg_data,
		struct perf_cfg_data __dbg_perf_cfg_data);
extern int cn_monitor_perf_clkid_config(void *fp, struct cn_monitor_set *monitor_set,
		struct perf_clkid_config *clkid_config);
extern int cn_monitor_perf_task_type_config(void *fp, struct cn_monitor_set *monitor_set,
		struct perf_task_type_config *task_type_config);
extern int cn_monitor_perf_task_type_config_v2(void *fp, struct cn_monitor_set *monitor_set,
		u64 *cfg_data, u32 len, struct perf_task_type_config_v2 *task_type_config);
extern int cn_monitor_perf_tsinfo_size_get(void *fp, struct cn_monitor_set *monitor_set,
		struct perf_info_size_get *size_get);
extern int cn_monitor_perf_tsinfo_get(void *fp, struct cn_monitor_set *monitor_set,
		struct perf_task_info_get *tsinfo_get);

int cndrv_monitor_lpm_get(void *user, struct cn_core_set *core);
void cndrv_monitor_lpm_put(void *user, struct cn_core_set *core);

#endif
