#ifndef __CAMBRICON_CNDEV_SERVER_H__
#define __CAMBRICON_CNDEV_SERVER_H__

#include "cndrv_monitor_usr.h"
#include "cndrv_core.h"
#include "cndrv_qos.h"
#include "../camb_pmu_rpc.h"
#include "cndrv_attr.h"
#include "cndrv_cndev.h"

enum cndev_version {
	CNDEV_VERSION0,
	CNDEV_VERSION1,
	CNDEV_VERSION2,
	CNDEV_VERSION5 = 5,
	CNDEV_VERSION6,
};

#define CNDEV_CURRENT_VER CNDEV_VERSION6

#define VM_PF            0
#define VM_VF            1
/* reserve: cndev api use 2 to indicate host_vf */
#define VM_HOST_VF       3

#define ATTR_DISABLE     0
#define ATTR_ENABLE      1

/*codec support max process*/
#define CN_CNDEV_MAX_CODEC_PROCESS_NUM 65535

#define CHASSIS_PART_NAME_BYTES_MAX            (12)
#define MLU500_CHASSIS_PART_NAME_BYTES_MAX     (16)
#define CNDEV_IPU_FREQ_CAPPING_RETRY           (1)

#define CHECK_CNDEV_EP_NULL(cndev_set, core) \
do { \
	if (IS_ERR_OR_NULL(cndev_set)) \
		return -EINVAL; \
	if (IS_ERR_OR_NULL(cndev_set->endpoint)) { \
		cn_dev_cndev_err(cndev_set, "Invalid cndev commu endpoint"); \
		return -EINVAL; \
	} \
	core = (struct cn_core_set *)cndev_set->core; \
	if (IS_ERR_OR_NULL(core)) { \
		cn_dev_cndev_err(cndev_set, "Invalid core"); \
		return -EINVAL; \
	} \
} while (0)

enum cndev_quirks {
	/*
	 * Device only support physical Function Only
	 */
	CNDEV_QUIRK_PF_ONLY                 = (1ULL << 0),
	/*
	 * Device support scaler
	 */
	CNDEV_QUIRK_SUPPORT_SCALER          = (1ULL << 1),
};

struct chassis_info {
	u8 info_ready;

	u8 chassis_sn[CHASSIS_SN_BYTES];

	u8 chassis_product_date[CHASSIS_PRODUCT_DATE_BYTES];

	u8 chassis_part_num[MLU500_CHASSIS_PART_NAME_BYTES_MAX];

	u8 chassis_vendor_name[CHASSIS_VENDOR_NAME_BYTES];
};

enum cndev_health_sta {
	CNDEV_CARD_ERROR = 0,
	CNDEV_CARD_RUNNING,
	CNDEV_CARD_OTHER_STATE,
};

struct bus_throughput_s {
	/*save the last value in *_last*/
	u64 read_last;
	u64 write_last;
	/*save each 20ms value in above var*/
	u64 read_data;
	u64 write_data;
};

struct board_info_s {
	struct cn_mcu_info mcu_info;
	u8 chip_id;
	u8 uuid[CNDRV_UUID_SIZE];
	u64 sn;
	u8 secure_mode;
	u8 soc_id[SOC_ID_SIZE];
	u32 board_type;
	u64 chip_type;
	u32 ddr_bus_width;
	u32 ddr_bandwidth;
	u32 ddr_bandwidth_decimal;
	u32 ipu_cluster;
	u32 ipu_core;
};

struct ipufreq_info_s {
	/*MHz*/
	u32 ipu_freq;
};

struct power_info_s {
	/**< board max power unit:W*/
	u16 max_power;
	/**< current power unit:W*/
	u16 power_usage;
	/**< MLU fan speed,the percentage of the max fan speed*/
	u16 fan_speed;
	u16 tdp;
	u8 temperature_num;
	/**< temperature variable, (type: s8) */
	s8 temp[20];

	u8 ic_num;
	/* domain logic ic bitmap */
	u64 logic_ic_bitmap;
	/* hw phyical ic bitmap */
	u64 phy_ic_bitmap;
	/**< ipucluster freq variable, (type: u16) */
	u16 ic_freq[20];

	u32 edpp_count;
	u32 tdp_freq_capping_count;
};

struct chassis_runtime_info_s {
	u16 machine_power;
	u16 machine_in_fan;
	u16 machine_out_fan;

	u16 fan_num;
	u16 fan[0];
};

struct memory_info_s {
	/**< MLU physical total memory, unit:MB*/
	u64 phy_total;
	/**< MLU physical used memory, unit:MB*/
	u64 phy_used;
	/**< MLU virtual total memory, unit:MB*/
	u64 virt_total;
	/**< MLU virtual used memory, unit:MB*/
	u64 virt_used;
	u64 ipu_used;
	u64 vpu_used;
	/**< ARM OS Total memory, unit:Bytes*/
	u64 sys_totalram;
	/**< ARM OS Free memory, unit:Bytes*/
	u64 sys_freeram;
	u32 chl_num;
	u64 each_chl[0];
};

struct ipuutil_info_s {
	u16 chip_util;
	u8 core_num;
	u8 tinycore_num;
	u8 core_util[0];
};

struct acpuutil_info_s {
	u16 chip_util;
	u8 core_num;
	u8 core_util[0];
};

struct codecutil_info_s {
	u8 vpu_num;
	u8 jpu_num;
	u8 scaler_num;
	u8 codec_util[0];
};

struct cndev_vf_info_s {
	u16 vm_num;
	u16 vm_mask;
};

struct cndev_ipufreq_set_s {
	u32 ipu_freq;
	u32 ctrl_mode;
};

struct NCS_basic_info_s {

	u64 mc_sn;
	u64 ba_sn;

	u32 slot_id;
	u32 port_id;

	u8 dev_ip[ADDRESS_LEN];
	u8 uuid[CNDRV_UUID_SIZE];

	u32 dev_ip_version;
	u32 is_ip_valid;

	enum cclink_connect_type type;

	u8 major_version;
	u8 minor_version;
	u8 build_version;

	u64 ncs_uuid64;

	int ret;
};

struct NCS_speed_info_s {

	u32 speed;
	u32 speed_fmt;

	int ret;
};

struct NCS_capability_info_s {

	u8 cap_p2p_tsf;
	u8 cap_ilkn_fec;

	int ret;
};

struct ncs_state_data {
	int is_active;
	int serdes_state;
	int cable_state;
	int ret;
};

struct NCS_reset_counter_s {
	u32 link;
	enum cclink_counter cntr;
};

struct NCS_port_config_s {

	u32 ops;
	u32 port_idx;
	u32 support_mode_flags;
	u32 current_mode_flags;
	int ret;
};

struct ncs_cnt_info_s {

	int ret;

	u64 ncs_cnt[CCLINK_ERR_NUM];
};

struct mlulink_switch_ctrl_s {

	u32 ops;
	s32 port_idx;
	s32 field;
	u32 value;
	int ret;
};

struct ncs_info_s {

	struct cndev_ncs_basic_info basic_info[8];
	u32 mlulink_port;
	u64 ncs_uuid64;
	int is_support_mlulink;
	int ret;
};

struct cn_cndev_lateset {
	u8 bus;
	u8 device;
	u8 func;
	u16 domain;
	u16 driver_major_ver;
	u16 driver_minor_ver;
	u16 driver_build_ver;
};

struct cn_cndev_resource {
	int ret;
	/*host require count*/
	u32 count;

	u64 resource[0];
};

struct board_info_ext_s {
	struct card_mac_info_s mac_info;
	struct card_pre_setting_info_s pre_setting_info;

	int ret;
};

/* RPC (1024 - sizeof(int)) / sizeof(struct codecutil) */
#define MAX_PROCESS_CODEC_CNT 80
#pragma pack(1)
struct codec_pid_info {
	u32 process_num;
	u32 tgid[MAX_PROCESS_CODEC_CNT];
};

struct codec_process_util {
	int ret;
	u32 vpu_dec[MAX_PROCESS_CODEC_CNT];
	u32 vpu_enc[MAX_PROCESS_CODEC_CNT];
	u32 jpu[MAX_PROCESS_CODEC_CNT];
};
#pragma pack()

typedef int (*ioctls)(int);
struct cn_cndev_ioctl {
	void (*card_info_fill)(void *cset);
	int (*card_power_info)(void *cset,
		struct cndev_power_info *cndev_info);
	int (*card_memory_info)(void *cset,
		struct cndev_memory_info *mem_info);
	int (*user_proc_info)(void *cset,
		struct cndev_proc_info *proc_info);
	int (*card_health_state)(void *cset,
		struct cndev_health_state *hstate);
	int (*card_ecc_info)(void *cset,
		struct cndev_ecc_info *einfo);
	int (*card_vm_info)(void *cset,
		struct cndev_vm_info *vinfo);
	int (*card_ipuutil_info)(void *cset,
		struct cndev_ipuutil_info *uinfo);
	int (*card_codecutil_info)(void *cset,
		struct cndev_codecutil_info *uinfo);
	int (*card_freq_info)(void *cset,
		struct cndev_freq_info *finfo);
	int (*card_curbuslnk)(void *cset,
		struct cndev_curbuslnk_info *linfo);
	int (*card_pciethroughput)(void *cset,
		struct cndev_pcie_throughput *tpinfo);
	int (*card_power_capping)(void *cset,
		struct cndev_powercapping_s *pcinfo);
	int (*card_ipufreq_set)(void *cndev_set,
		struct cndev_ipufreq_set *setinfo);
	int (*card_ncs_version)(void *cndev_set,
		struct cndev_NCS_version *verinfo);
	int (*card_ncs_state)(void *cndev_set,
		struct cndev_NCS_state_info *stinfo);
	int (*card_ncs_speed)(void *cndev_set,
		struct cndev_NCS_speed_info *stinfo);
	int (*card_ncs_capability)(void *cndev_set,
		struct cndev_NCS_capability *capinfo);
	int (*card_ncs_counter)(void *cndev_set,
		struct cndev_NCS_counter *cntrinfo);
	int (*card_ncs_remote)(void *cndev_set,
		struct cndev_NCS_remote_info *rmtinfo);
	int (*card_reset_ncs_counter)(void *cndev_set,
		struct cndev_NCS_reset_counter *rstinfo);
	int (*card_chassis_info)(void *cndev_set,
		struct cndev_chassis_info *rstinfo);
	int (*card_qos_reset)(void *cndev_set);
	int (*card_qos_info)(void *cndev_set,
		struct cndev_qos_info *qos_info);
	int (*card_qos_desc)(void *cndev_set,
		struct cndev_qos_detail *qos_info);
	int (*card_set_qos)(void *cndev_set,
		struct cndev_qos_param *qos_info);
	int (*card_set_qos_group)(void *cndev_set,
		struct cndev_qos_group_param *qos_info);
	int (*card_acpuutil_info)(void *cset,
		struct cndev_acpuutil_info *uinfo);
	int (*card_acpuutil_timer)(void *cset,
		struct cndev_acpuutil_timer *timer);
	int (*card_get_retire_pages)(void *cset,
		struct cndev_retire_page *retire_pages);
	int (*card_get_retire_status)(void *cset,
		struct cndev_retire_status *retire_status);
	int (*card_get_retire_remapped_rows)(void *cset,
		struct cndev_retire_remapped_rows *retire_remapped_rows);
	int (*card_retire_switch)(void *cset,
		struct cndev_retire_op *retire_op);
	int (*card_ncs_port_config)(void *cset,
		struct cndev_NCS_config *port_config);
	int (*card_mlulink_switch_ctrl)(void *cset,
		struct cndev_mlulink_switch_ctrl *ctrl);
	int (*card_ipufreq_ctrl)(void *cset,
		struct cndev_ipufreq_ctrl *ctrl);
	int (*card_get_ncs_info)(void *cset,
		struct cndev_ncs_info *info);
	int (*card_get_card_info_ext)(void *cset,
		struct cndev_card_info_ext *info);
	int (*card_get_process_iputil)(void *cset,
		struct cndev_process_ipuutil_info *info);
	int (*card_get_process_codecutil)(void *cset,
		struct cndev_process_codecutil_info *info);
	int (*card_get_feature)(void *cset,
		struct cndev_feature *info);
	int (*card_set_feature)(void *cset,
		struct cndev_feature *info);
	int (*card_get_mim_profile_info)(void *cset,
		struct cndev_mim_profile_info *info);
	int (*card_get_mim_possible_place_info)(void *cset,
		struct cndev_mim_possible_place_info *info);
	int (*card_get_mim_vmlu_capacity_info)(void *cset,
		struct cndev_mim_vmlu_capacity_info *info);
	int (*card_get_mim_device_info)(void *cset,
		struct cndev_mim_device_info *info);
	int (*card_get_desc_info)(void *cset,
		struct cndev_mi_card *info);
	int (*card_get_cntr_info)(void *cset,
		struct cndev_cntr_info *info);
	int (*chassis_power_info)(void *cset,
		struct cndev_chassis_power_info *info);
	int (*card_get_smlu_profile_id)(void *cset,
		struct cndev_smlu_profile_id *info);
	int (*card_get_smlu_profile_info)(void *cset,
		struct cndev_smlu_profile_info *info);
	int (*card_new_smlu_profile)(void *cset,
		struct cndev_smlu_profile_info *info);
	int (*card_delete_smlu_profile)(void *cset,
		struct cndev_smlu_profile_info *info);
};

struct cn_cndev_ops {
	int (*cndev_start)(void *cset);
	int (*cndev_do_exit)(void *cset);
	int (*cndev_lateinit)(void *pcore);
	int (*cndev_restart)(void *cset);
	void (*cndev_stop)(void *cset);
	void (*cndev_exit)(void *cset);
};

struct cndev_ctrl_s {
	int tgid;
	struct list_head list;
};

struct cn_cndev_process_info {
	u32 process_num;
	struct mutex codec_mutex;
	struct codec_process_util util_info;
	struct cndev_process_codecutil *codec;
	u64 *active_pid;
};

struct cndev_config {

	u64 ipu_cfg_recovery;
	u64 power_cfg_recovery;

	struct cndev_powercapping_s power_capping_cfg;
	struct cndev_ipufreq_set_s ipu_freq_cfg;
};

struct cn_cndev_set {
	struct cn_core_set *core;
	struct cnrpc_client *rpc_client;
	void *endpoint;

	u64 device_id;

	/*card number*/
	int idx;
	char core_name[32];

	struct cndev_card_info card_static_info;

	struct hrtimer hrtimer;
	ktime_t time_delay;

	const struct cn_cndev_ops *ops;
	const struct cn_cndev_ioctl *ioctl;

	struct list_head list;

	struct bus_throughput_s bus_throughput;

	bool print_debug;

	struct hrtimer mcuinfo_hrtimer;
	ktime_t mcuinfo_time_delay;

	struct bus_throughput_s pcie_throughput_to_mcu;
	u8 host_info_flush_done;
	struct cndev_qos_conf_s qos_conf;

	struct cn_cndev_process_info process_info;

	atomic64_t ipu_freq_set_ref;

	struct cndev_config cndev_cfg;
	u64 quirks;
};

struct xpll_reg {
	u32 xpll_cfg0;
	u32 xpll_cfg1;
	u32 xpll_ctrl;
	u32 xpll_frac_adj_en;
	u32 xpll_frac_step0_up_cfg0;
	u32 xpll_frac_step0_up_cfg1;
	u32 xpll_frac_step1_up_cfg0;
	u32 xpll_frac_step1_up_cfg1;
	u32 xpll_frac_step0_down_cfg0;
	u32 xpll_frac_step0_down_cfg1;
	u32 xpll_frac_step1_down_cfg0;
	u32 xpll_frac_step1_down_cfg1;
	u32 xpll_frac_cur_fbdiv;
	u32 xpll_frac_cur_fracdiv;
};

struct xpll_freq_frac {
	u32 freq;
	u32 fbdiv;
	u32 fracdiv;
	u32 refdiv;
	u32 postdiv1;
	u32 postdiv2;
};

#if !defined(CONFIG_CNDRV_EDGE)
static inline int cndev_init_ce3226(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_pigeon(struct cn_cndev_set *cndev_set)
{
	return 0;
}
int cndev_init_mlu270(struct cn_cndev_set *cndev_set);
int cndev_init_mlu220(struct cn_cndev_set *cndev_set);
int cndev_init_mlu290(struct cn_cndev_set *cndev_set);
int cndev_init_mlu370(struct cn_cndev_set *cndev_set);
int cndev_init_mlu590(struct cn_cndev_set *cndev_set);
int cndev_init_mlu580(struct cn_cndev_set *cndev_set);
#elif defined(CONFIG_CNDRV_PCIE_ARM_PLATFORM)
static inline int cndev_init_mlu270(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu220(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu290(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_ce3226(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_pigeon(struct cn_cndev_set *cndev_set)
{
	return 0;
}
int cndev_init_mlu370(struct cn_cndev_set *cndev_set);
int cndev_init_mlu580(struct cn_cndev_set *cndev_set);
int cndev_init_mlu590(struct cn_cndev_set *cndev_set);
#elif defined(CONFIG_CNDRV_C20E_SOC)
static inline int cndev_init_mlu270(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu290(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu370(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu590(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu580(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_ce3226(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_pigeon(struct cn_cndev_set *cndev_set)
{
	return 0;
}
int cndev_init_mlu220(struct cn_cndev_set *cndev_set);
#elif defined(CONFIG_CNDRV_CE3226_SOC)
static inline int cndev_init_mlu220(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu270(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu290(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu370(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu590(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu580(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_pigeon(struct cn_cndev_set *cndev_set)
{
	return 0;
}
int cndev_init_ce3226(struct cn_cndev_set *cndev_set);
#elif defined(CONFIG_CNDRV_PIGEON_SOC)
static inline int cndev_init_mlu220(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu270(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu290(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu370(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu590(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_ce3226(struct cn_cndev_set *cndev_set)
{
	return 0;
}
static inline int cndev_init_mlu580(struct cn_cndev_set *cndev_set)
{
	return 0;
}
int cndev_init_pigeon(struct cn_cndev_set *cndev_set);
#endif

/* place common function here */
int cndev_common_init(struct cn_cndev_set *cndev_set);
int cndev_start_common(void *cset);
int cndev_do_exit_common(void *cset);
void cndev_check_bus_throughput(struct cn_cndev_set *cndev_set);

void card_info_fill_common(void *cset);
void card_info_fill_vf_common(void *cset);

int cndev_get_valid_vf_num(void *cset, u16 *num, u16 *mask);
int cndev_vcard_trans(struct cn_cndev_set *cndev_set, u16 *vcard);

int cndev_card_health_status_common(void *cset,
		struct cndev_health_state *hstate);

void cndev_proc_info_combine(struct proc_mem_info *mem_info, u32 *num);
int cndev_user_proc_info_common(void *cset,
		struct cndev_proc_info *proc_info);

int cndev_user_proc_info_mlu500_vf(void *cset,
	struct cndev_proc_info *proc_info);

int card_power_info_vf_common(void *cset,
			struct cndev_power_info *power_info);

int card_ecc_info_common(void *cset,
		struct cndev_ecc_info *einfo);

int card_ecc_info_vf_common(void *cset,
	struct cndev_ecc_info *einfo);

int cndev_card_memory_info_common(void *cset,
		struct cndev_memory_info *mem_info);

int cndev_card_ipuutil_info_common(void *cset,
	struct cndev_ipuutil_info *util_info);

int cndev_card_acpuutil_info_common(void *cset,
	struct cndev_acpuutil_info *util_info);

int cndev_card_acpuutil_timer_common(void *cset,
	struct cndev_acpuutil_timer *timer);

int cndev_card_codecutil_info_common(void *cset,
	struct cndev_codecutil_info *util_info);

int cndev_card_curbuslnk_common(void *cset,
	struct cndev_curbuslnk_info *linfo);

int cndev_card_pciethroughput_common(void *cset,
	struct cndev_pcie_throughput *tpinfo);

int cndev_card_powercapping_common(void *cset,
	struct cndev_powercapping_s *pcinfo);

int cndev_card_get_feature_common(void *cset,
	struct cndev_feature *info);

int cndev_card_set_feature_common(void *cset,
	struct cndev_feature *info);

int cndev_card_get_computing_power_common(void *cset,
	struct cndev_feature *info);

int cndev_card_get_xid_common(void *cset,
	struct cndev_feature *info);

int cndev_card_exclusive_mode_common(void *cset,
	int ops, struct cndev_feature *info);

int cndev_card_set_xid_common(void *cset,
	struct cndev_feature *info);

int cndev_card_sriov_mode_common(void *cset,
	int ops, struct cndev_feature *info);

int cndev_card_set_mim_vmlu_common(void *cset,
	struct cndev_feature *info);

int cndev_card_get_mim_vmlu_info_common(void *cset,
	struct cndev_feature *info);

int cndev_card_set_smlu_common(void *cset,
	struct cndev_feature *info);

int cndev_card_get_smlu_info_common(void *cset,
	struct cndev_feature *info);

int cndev_qos_reset_common(void *cndev_set);
int cndev_qos_policy_common(void *cndev_set,
				struct cndev_qos_info *qos_info);
int cndev_qos_desc_common(void *cset,
				struct cndev_qos_detail *qos_info);
int cndev_set_qos_policy(void *cset, struct cndev_qos_param *qos_info);
int cndev_set_qos_group_policy(void *cset, struct cndev_qos_group_param *qos_info);
int cndev_card_get_retire_pages(void *cset,
	struct cndev_retire_page *retire_pages);
int cndev_card_get_retire_status(void *cset,
	struct cndev_retire_status *retire_status);
int cndev_card_get_retire_remapped_rows(void *cset,
	struct cndev_retire_remapped_rows *retire_remapped_rows);
int cndev_card_retire_switch(void *cset,
	struct cndev_retire_op *retire_op);
int card_ncs_version_common(void *cset,
			struct cndev_NCS_version *verinfo);
int card_ncs_state_common(void *cset,
	struct cndev_NCS_state_info *stinfo);
int card_ncs_speed_common(void *cset,
	struct cndev_NCS_speed_info *stinfo);
int card_ncs_capability_common(void *cset,
	struct cndev_NCS_capability *capinfo);
int card_ncs_counter_common(void *cset,
	struct cndev_NCS_counter *cntrinfo);
int card_ncs_remote_common(void *cset,
	struct cndev_NCS_remote_info *rmtinfo);
int card_ncs_reset_cntr_common(void *cset,
	struct cndev_NCS_reset_counter *rstinfo);
int card_get_ncs_info_common(void *cset,
			struct cndev_ncs_info *ncs_info);
int card_ncs_port_config_common(void *cset,
	struct cndev_NCS_config *port_config);
int card_mlulink_switch_ctrl_common(void *cset,
	struct cndev_mlulink_switch_ctrl *mlulink_switch_ctrl);
int cndev_get_process_codecutil_common(void *cset,
	struct cndev_process_codecutil_info *info);
int cndev_card_get_desc_common(void *cset,
	struct cndev_mi_card *info);
int cndev_card_get_mim_device_info_common(void *cset,
	struct cndev_mim_device_info *info);
int cndev_card_get_mim_vmlu_capacity_info_common(void *cset,
	struct cndev_mim_vmlu_capacity_info *info);
int cndev_card_get_mim_possible_place_info_common(void *cset,
	struct cndev_mim_possible_place_info *info);
int cndev_card_get_mim_profile_info_common(void *cset,
	struct cndev_mim_profile_info *info);
int cndev_card_get_cntr_info_common(void *cset,
	struct cndev_cntr_info *info);
int cndev_card_get_smlu_profile_id_common(void *cset,
	struct cndev_smlu_profile_id *info);
int cndev_card_get_smlu_profile_info_common(void *cset,
	struct cndev_smlu_profile_info *info);
int cndev_card_new_smlu_profile_common(void *cset,
	struct cndev_smlu_profile_info *info);
int cndev_card_delete_smlu_profile_common(void *cset,
	struct cndev_smlu_profile_info *info);

void cndev_exit_common(void *cset);
int cndev_rpc_lateinit(void *cset);
int cndev_rpc_resource(void *cset);
int cndev_rpc_dev_info(void *cset,
	struct board_info_s *brdinfo_rmt, u16 vcard);
int cndev_lateinit_common(void *pcore);
int cndev_lateinit_mlu370(void *pcore);
int cndev_restart_common(void *cset);
void cndev_stop_common(void *cset);
int cndev_rpc_client_register(void *pcore);
int cndev_checkstate_common(void *core_set);

/* place server function here */
int cndev_card_info(struct cn_cndev_set *cndev_set,
	unsigned long arg, struct cndev_head *arg_head);
void cndev_card_info_fill(struct cn_cndev_set *cndev_set);
int cndev_card_power_info(struct cn_cndev_set *cndev_set,
				struct cndev_power_info *cndev_info);
int cndev_user_proc_info(struct cn_cndev_set *cndev_set,
				struct cndev_proc_info *proc_info);
int cndev_card_health_state(struct cn_cndev_set *cndev_set,
				struct cndev_health_state *hstate);
int cndev_card_ecc_info(struct cn_cndev_set *cndev_set,
				struct cndev_ecc_info *einfo);
int cndev_card_vm_info(struct cn_cndev_set *cndev_set,
				struct cndev_vm_info *vinfo);
int cndev_card_ipuutil_info(struct cn_cndev_set *cndev_set,
				struct cndev_ipuutil_info *uinfo);
int cndev_card_codecutil_info(struct cn_cndev_set *cndev_set,
				struct cndev_codecutil_info *uinfo);
int cndev_card_freq_info(struct cn_cndev_set *cndev_set,
				struct cndev_freq_info *finfo);
int cndev_card_curbuslnk(struct cn_cndev_set *cndev_set,
				struct cndev_curbuslnk_info *linfo);
int cndev_card_pciethroughput(struct cn_cndev_set *cndev_set,
				struct cndev_pcie_throughput *tpinfo);
int cndev_power_capping(struct cn_cndev_set *cndev_set,
				struct cndev_powercapping_s *pcinfo);
int cndev_ipufreq_set(struct cn_cndev_set *cndev_set,
				struct cndev_ipufreq_set *setinfo);
int cndev_get_ncs_version(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_version *verinfo);
int cndev_get_ncs_state(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_state_info *stinfo);
int cndev_get_ncs_speed(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_speed_info *stinfo);
int cndev_get_ncs_capability(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_capability *capinfo);
int cndev_get_ncs_counter(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_counter *cntrinfo);
int cndev_get_ncs_remote(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_remote_info *rmtinfo);
int cndev_reset_ncs_counter(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_reset_counter *rstinfo);
int cndev_ioctl_attribute(struct cn_cndev_set *cndev_set,
				struct cndev_ioctl_attr *attrinfo);
int cndev_chassis_info_fill(struct cn_cndev_set *cndev_set,
				struct cndev_chassis_info *chassis_info);
int cndev_reset_qos(struct cn_cndev_set *cndev_set);
int cndev_qos_operation(struct cn_cndev_set *cndev_set,
				struct cndev_qos_info *qos_info);
int cndev_qos_desc(struct cn_cndev_set *cndev_set,
				struct cndev_qos_detail *qos_desc);
int cndev_set_qos_param(struct cn_cndev_set *cndev_set,
	struct cndev_qos_param *qos_info);
int cndev_set_qos_group_param(struct cn_cndev_set *cndev_set,
	struct cndev_qos_group_param *qos_info);
int cndev_card_acpuutil_info(struct cn_cndev_set *cndev_set,
				struct cndev_acpuutil_info *uinfo);
int cndev_card_acpuutil_timer(struct cn_cndev_set *cndev_set,
	struct cndev_acpuutil_timer *timer);

int cndev_get_retire_pages(struct cn_cndev_set *cndev_set,
	struct cndev_retire_page *retire_pages);
int cndev_get_retire_status(struct cn_cndev_set *cndev_set,
	struct cndev_retire_status *retire_status);
int cndev_get_retire_remapped_rows(struct cn_cndev_set *cndev_set,
	struct cndev_retire_remapped_rows *retire_remapped_rows);
int cndev_retire_switch(struct cn_cndev_set *cndev_set,
	struct cndev_retire_op *retire_op);
int cndev_ncs_port_config(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_config *port_config);
int cndev_ncs_mlulink_switch_ctrl(struct cn_cndev_set *cndev_set,
				struct cndev_mlulink_switch_ctrl *mlulink_switch_ctrl);
int cndev_ipu_freq_ctrl(struct cn_cndev_set *cndev_set,
				struct cndev_ipufreq_ctrl *ipufreq_ctrl);
int cndev_get_ncs_info(struct cn_cndev_set *cndev_set,
				struct cndev_ncs_info *ncs_info);
int cndev_get_card_info_ext(struct cn_cndev_set *cndev_set,
				struct cndev_card_info_ext *card_info_ext);
int cndev_get_process_codecutil(struct cn_cndev_set *cndev_set,
				struct cndev_process_codecutil_info *info);
int cndev_get_feature(struct cn_cndev_set *cndev_set,
	struct cndev_feature *info);
int cndev_set_feature(struct cn_cndev_set *cndev_set,
	struct cndev_feature *info);
int cndev_exclusive_mod_ctrl(struct cn_cndev_set *cndev_set,
	struct cndev_feature_exclusive_mode *exclusive_mode_ctrl);

int cndrv_cndev_lateinit(void *pcore);
int cndrv_cndev_restart(void *pcore);
void cndrv_cndev_stop(void *pcore);
int cndrv_cndev_init(void *pcore);
void cndrv_cndev_free(void *pcore);


int cndev_get_process_util(struct cn_cndev_set *cndev_set,
			struct cndev_process_ipuutil_info *process_info);
int cndev_get_process_ipuutil_common(void *cset,
			struct cndev_process_ipuutil_info *process_info);
void cndev_init_codec_process_util(struct cn_cndev_set *cndev_set);
int cndev_card_card_info_ext(void *cset,
	struct cndev_card_info_ext *ext_info);

int cndev_get_mim_profile_info(struct cn_cndev_set *cndev_set,
	struct cndev_mim_profile_info *info);
int cndev_get_mim_possible_place_info(struct cn_cndev_set *cndev_set,
	struct cndev_mim_possible_place_info *info);
int cndev_card_get_mim_vmlu_capacity_info(struct cn_cndev_set *cndev_set,
	struct cndev_mim_vmlu_capacity_info *info);
int cndev_card_get_mim_device_info(struct cn_cndev_set *cndev_set,
	struct cndev_mim_device_info *info);
int cndev_card_get_desc_info(struct cn_cndev_set *cndev_set,
	struct cndev_mi_card *info);
int cndev_card_get_cntr_info(struct cn_cndev_set *cndev_set,
	struct cndev_cntr_info *info);
int cndev_chassis_power_info_fill(struct cn_cndev_set *cndev_set,
		struct cndev_chassis_power_info *info);
/* smlu cap */
int cndev_get_smlu_profile_id(struct cn_cndev_set *cndev_set,
	struct cndev_smlu_profile_id *info);
int cndev_get_smlu_profile_info(struct cn_cndev_set *cndev_set,
	struct cndev_smlu_profile_info *info);
int cndev_new_smlu_profile(struct cn_cndev_set *cndev_set,
	struct cndev_smlu_profile_info *info);
int cndev_delete_smlu_profile(struct cn_cndev_set *cndev_set,
	struct cndev_smlu_profile_info *info);
#endif
