#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/hrtimer.h>
#include <linux/random.h>
#include <linux/pid_namespace.h>

#include "cndrv_core.h"
#include "cndrv_domain.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"
#include "cndrv_mcu.h"
#include "cndrv_mcc.h"
#include "../../core/version.h"
#include "cndrv_commu.h"

#include "cndev_server.h"
#include "../monitor.h"

#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"

void card_info_fill_mlu220_edge(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;
	struct cn_board_info *pbrdinfo = &core->board_info;
	struct cndev_card_info *info = &cndev_set->card_static_info;

	info->head.card = core->idx;
	info->head.version = CNDEV_CURRENT_VER;
	info->head.buf_size = sizeof(struct cndev_card_info);
	info->head.real_size = sizeof(struct cndev_card_info);

	info->mcu_major_ver = pbrdinfo->mcu_info.mcu_major;
	info->mcu_minor_ver = pbrdinfo->mcu_info.mcu_minor;
	info->mcu_build_ver = pbrdinfo->mcu_info.mcu_build;
	info->driver_major_ver = DRV_MAJOR;
	info->driver_minor_ver = DRV_MINOR;
	info->driver_build_ver = DRV_BUILD;

	info->subsystem_id = pbrdinfo->board_type;

	info->ipu_cluster = pbrdinfo->cluster_num;
	info->ipu_core = pbrdinfo->ipu_core_num;

	info->card_name = core->board_model;
	info->card_sn = pbrdinfo->serial_num;

	strcpy(info->board_model, pbrdinfo->board_model_name);

	info->mother_board_sn = 0;
	info->qdd_status = 0;
	info->mother_board_mcu_fw_ver = 0;

	info->pcie_fw_info = 0;

	/*220 uuid, get uuid after bl3 init */
	cndrv_mcu_read_uuid(core, info->uuid);

	/* mem data width */
	info->data_width = pbrdinfo->bus_width;
	info->bandwidth = pbrdinfo->bandwidth;
	info->bandwidth_decimal = pbrdinfo->bandwidth_decimal;
}

void card_info_fill_mlu220_m2(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;
	struct cn_board_info *pbrdinfo = &core->board_info;
	struct cndev_card_info *info = &cndev_set->card_static_info;
	struct bus_info_s bus_info;
	struct bus_lnkcap_info lnk_info;

	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);

	memset(&lnk_info, 0, sizeof(struct bus_lnkcap_info));
	cn_bus_get_lnkcap(core->bus_set, &lnk_info);

	info->head.card = core->idx;
	info->head.version = CNDEV_CURRENT_VER;
	info->head.buf_size = sizeof(struct cndev_card_info);
	info->head.real_size = sizeof(struct cndev_card_info);

	info->mcu_major_ver = pbrdinfo->mcu_info.mcu_major;
	info->mcu_minor_ver = pbrdinfo->mcu_info.mcu_minor;
	info->mcu_build_ver = pbrdinfo->mcu_info.mcu_build;
	info->driver_major_ver = DRV_MAJOR;
	info->driver_minor_ver = DRV_MINOR;
	info->driver_build_ver = DRV_BUILD;

	info->subsystem_id = pbrdinfo->board_type;

	/*get from pci_dev*/
	info->bus_type = bus_info.bus_type;
	info->device_id = bus_info.info.pcie.device;
	info->vendor_id = bus_info.info.pcie.vendor;
	info->subsystem_vendor = bus_info.info.pcie.subsystem_vendor;
	info->domain = bus_info.info.pcie.domain_id;
	info->bus = bus_info.info.pcie.bus_num;
	info->device = (bus_info.info.pcie.device_id >> 3) & 0x1f;
	info->func = bus_info.info.pcie.device_id & 0x07;

	info->ipu_cluster = pbrdinfo->cluster_num;
	info->ipu_core = pbrdinfo->ipu_core_num;

	info->max_speed = lnk_info.speed;
	info->max_width = lnk_info.width;

	info->card_name = core->board_model;
	info->card_sn = pbrdinfo->serial_num;

	strcpy(info->board_model, pbrdinfo->board_model_name);

	info->mother_board_sn = pbrdinfo->BA_serial_num;
	info->mother_board_mcu_fw_ver = pbrdinfo->BA_mcu_fw_ver;
	info->slot_id = pbrdinfo->slot_id;
	info->chip_id = pbrdinfo->chip_id;

	info->qdd_status = pbrdinfo->qdd_status;

	/*220 uuid, get uuid after bl3 init */
	cndrv_mcu_read_uuid(core, info->uuid);

	cn_bus_get_pcie_fw_info(core->bus_set, &info->pcie_fw_info);
	/* SOC ID*/
	info->secure_mode = pbrdinfo->secure_mode;
	memcpy(info->soc_id, pbrdinfo->soc_id.soc_id_data, SOC_ID_SIZE);

	/* ddr hbm data width */
	info->data_width = pbrdinfo->bus_width;
	info->bandwidth = pbrdinfo->bandwidth;
	info->bandwidth_decimal = pbrdinfo->bandwidth_decimal;
}

int card_power_info_mlu220(void *cset,
			struct cndev_power_info *power_info)
{
	int ret = 0;
	struct board_power_info pinfo;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core;
	struct cn_board_info *pbrdinfo;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	pbrdinfo = &core->board_info;

	power_info->head.version = CNDEV_CURRENT_VER;
	power_info->head.real_size = sizeof(struct cndev_power_info);

	ret = cndrv_mcu_read_power_info(core, &pinfo);
	if (ret) {
		return ret;
	}

	power_info->max_power = pinfo.peak_power ?
			pinfo.peak_power : pbrdinfo->peak_power;
	power_info->power_usage = pinfo.board_power;
	power_info->power_usage_decimal = pinfo.board_power_decimal;
	power_info->max_power_decimal = pinfo.max_power_decimal;
	power_info->fan_speed = pinfo.fan_speed;
	power_info->machine_power = 0;
	power_info->min_power_cap = pbrdinfo->min_power_cap;
	power_info->min_power_cap_decimal = pbrdinfo->min_power_cap_dec;
	power_info->max_power_cap_decimal = pbrdinfo->max_power_cap_dec;
	power_info->perf_limit_num = 0;
	power_info->edpp_count = 0;
	power_info->tdp_freq_capping_count = 0;

	/* mlu220 set tdp equal peak power */
	power_info->tdp = pbrdinfo->peak_power;
	power_info->ipu_cluster_freq_num = 0;
	power_info->instantaneous_power = power_info->power_usage;
	power_info->instantaneous_power_decimal = power_info->power_usage_decimal;
	power_info->ipu_cluster_mask = 0;

	ret = cndev_cp_less_val(
			&power_info->temperature_num, pinfo.temperature_num,
			power_info->temp, pinfo.temp, sizeof(s8));

	power_info->ignore_chassis_power_info = 1;

	/*free temp buf in power_info struct which alloced in mcu function.*/
	cn_kfree(pinfo.temp);
	return ret;
}

#ifdef CONFIG_CNDRV_EDGE
extern int ion_debug_client_info_get(unsigned int heap_id_mask,
			u32 *proc_num, struct proc_mem_info *mem_info);
int user_proc_info_mlu220edge(void *cset,
	struct cndev_proc_info *proc_info)
{
	int ret = 0;
	u32 proc_num = 512;
	int copy_length;
	struct proc_mem_info *mem_info;
	struct cn_core_set *core;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	proc_info->head.version = CNDEV_CURRENT_VER;
	proc_info->head.real_size = sizeof(struct cndev_proc_info);

	mem_info = cn_kzalloc(proc_num * sizeof(struct proc_mem_info), GFP_KERNEL);
	if (!mem_info) {
		cn_dev_cndev_err(cndev_set, "malloc for buffer fail");
		proc_info->proc_num = 0;
		return -ENOMEM;
	}

	ret = ion_debug_client_info_get(1 << 19, &proc_num, mem_info);
	if (ret) {
		cn_dev_cndev_err(cndev_set, "get proc info fail");
		proc_info->proc_num = 0;
		goto END;
	}
	cn_dev_cndev_debug(cndev_set, "get proc: %u", proc_num);
	cndev_proc_info_combine(mem_info, &proc_num);
	cn_dev_cndev_debug(cndev_set, "final proc: %u", proc_num);
	copy_length = (proc_num < proc_info->proc_num)
		? proc_num : proc_info->proc_num;
	proc_info->proc_num = proc_num;
	if (proc_info->proc_info_node && proc_num) {
		ret = cndev_cp_to_usr(
			proc_info->proc_info_node,
			mem_info,
			copy_length * sizeof(struct proc_mem_info));
	}
END:
	cn_kfree(mem_info);
	return ret;
}
#else
int user_proc_info_mlu220edge(void *cset,
	struct cndev_proc_info *proc_info)
{
	return -1;
}
#endif

int card_health_status_mlu220edge(void *cset,
			struct cndev_health_state *hstate)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	hstate->head.version = CNDEV_CURRENT_VER;
	hstate->head.real_size = sizeof(struct cndev_health_state);

	hstate->host_state = core->state;
	hstate->card_state = CNDEV_CARD_RUNNING;

	return 0;
}

int card_vm_info_mlu220(void *cset,
	struct cndev_vm_info *vinfo)
{

	vinfo->head.version = CNDEV_CURRENT_VER;
	vinfo->head.real_size = sizeof(struct cndev_vm_info);

	vinfo->vm_check = VM_PF;
	vinfo->vm_num = 0;

	return 0;
}

int card_ipufreq_set_mlu220(void *cset,
				struct cndev_ipufreq_set *setinfo)
{
	int ret = 0;
	int result = -1, result_len = 0;
	struct cndev_ipufreq_set_s freqset;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	freqset.ipu_freq = setinfo->ipu_freq;
	freqset.ctrl_mode = setinfo->ctrl_mode;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_ipufreq_set",
			(void *)&freqset, sizeof(struct cndev_ipufreq_set_s),
			(void *)&result, &result_len, sizeof(int));
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}
	if (result < 0) {
		cn_dev_cndev_err(cndev_set, "set freq failed");
	}

	return result;
}

int cndev_card_freq_info_mlu220(void *cset,
	struct cndev_freq_info *finfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret = 0;
	struct cn_core_set *core = NULL;
	struct cn_board_info *pbrdinfo = NULL;
	u16 vcard;
	struct ipu_freq_info info = {0};

	vcard = (finfo->head.card >> 8) & 0x0f;
	if (vcard)
		return -ENODEV;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	pbrdinfo = &core->board_info;
	if (IS_ERR_OR_NULL(pbrdinfo))
		return -EINVAL;

	finfo->head.version = CNDEV_CURRENT_VER;
	finfo->head.real_size = sizeof(struct cndev_freq_info);

	finfo->ddr_freq = pbrdinfo->ddr_speed;
	ret = cndrv_mcu_read_ipu_freq(cndev_set->core, &info);
	finfo->rated_ipu_freq = info.rated_ipu_freq;
	finfo->ipu_freq = info.ipu_freq;
	finfo->ipu_fast_dfs_flag = info.ipu_fast_dfs_flag;
	finfo->ipu_overtemp_dfs_flag = info.ipu_overtemp_dfs_flag;

	finfo->range[0] = pbrdinfo->min_ipu_freq_cap;
	finfo->range[1] = pbrdinfo->max_ipu_freq_cap;
	finfo->freq_num = 0;

	finfo->die_ipu_cnt = 0;
	return ret;
}

int cndev_start_mlu220edge(void *cset)
{
	int in_len = 0;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int ret = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_host_start",
			NULL, 0,
			NULL, &in_len, 0);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
	}

	return ret;
}

int cndev_do_exit_mlu220edge(void *cset)
{
	int in_len = 0;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int ret = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	ret = __pmu_call_rpc(core, cndev_set->endpoint,
			"rpc_cndev_do_exit",
			NULL, 0,
			NULL, &in_len, 0);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
	}

	return 0;
}

static const struct cn_cndev_ioctl cndev_mlu220_ioctl = {
	.card_info_fill = card_info_fill_mlu220_m2,
	.card_power_info = card_power_info_mlu220,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = NULL,
	.card_vm_info = card_vm_info_mlu220,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = cndev_card_codecutil_info_common,
	.card_freq_info = cndev_card_freq_info_mlu220,
	.card_curbuslnk = cndev_card_curbuslnk_common,
	.card_pciethroughput = cndev_card_pciethroughput_common,
	.card_power_capping = cndev_card_powercapping_common,
	.card_ipufreq_set = card_ipufreq_set_mlu220,
	.card_ncs_version = NULL,
	.card_ncs_state = NULL,
	.card_ncs_speed = NULL,
	.card_ncs_capability = NULL,
	.card_ncs_counter = NULL,
	.card_ncs_remote = NULL,
	.card_reset_ncs_counter = NULL,
	.card_chassis_info = NULL,
	.card_qos_reset = cndev_qos_reset_common,
	.card_qos_info = cndev_qos_policy_common,
	.card_qos_desc = cndev_qos_desc_common,
	.card_set_qos = cndev_set_qos_policy,
	.card_set_qos_group = cndev_set_qos_group_policy,
	.card_acpuutil_info = cndev_card_acpuutil_info_common,
	.card_acpuutil_timer = cndev_card_acpuutil_timer_common,
	.card_get_retire_pages = NULL,
	.card_get_retire_status = NULL,
	.card_get_retire_remapped_rows = NULL,
	.card_retire_switch = NULL,
	.card_ncs_port_config = NULL,
	.card_mlulink_switch_ctrl = NULL,
	.card_ipufreq_ctrl = NULL,
	.card_get_ncs_info = card_get_ncs_info_common,
	.card_get_card_info_ext = NULL,
	.card_get_process_iputil = NULL,
	.card_get_process_codecutil = NULL,
	.card_get_feature = cndev_card_get_feature_common,
	.card_set_feature = cndev_card_set_feature_common,
	.card_get_mim_profile_info = NULL,
	.card_get_mim_possible_place_info = NULL,
	.card_get_mim_vmlu_capacity_info = NULL,
	.card_get_mim_device_info = NULL,
	.card_get_desc_info = NULL,
	.card_get_cntr_info = NULL,
	.chassis_power_info = NULL,
	.card_get_smlu_profile_id = NULL,
	.card_get_smlu_profile_info = NULL,
	.card_new_smlu_profile = NULL,
	.card_delete_smlu_profile = NULL,
};

static const struct cn_cndev_ops cndev_mlu220_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_common,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_common,
	.cndev_exit = cndev_exit_common,
};

static const struct cn_cndev_ioctl cndev_mlu220_edge_ioctl = {
	.card_info_fill = card_info_fill_mlu220_edge,
	.card_power_info = card_power_info_mlu220,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = user_proc_info_mlu220edge,
	.card_health_state = card_health_status_mlu220edge,
	.card_ecc_info = NULL,
	.card_vm_info = card_vm_info_mlu220,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = cndev_card_codecutil_info_common,
	.card_freq_info = cndev_card_freq_info_mlu220,
	.card_curbuslnk = NULL,
	.card_pciethroughput = NULL,
	.card_power_capping = cndev_card_powercapping_common,
	.card_ipufreq_set = card_ipufreq_set_mlu220,
	.card_ncs_version = NULL,
	.card_ncs_state = NULL,
	.card_ncs_speed = NULL,
	.card_ncs_capability = NULL,
	.card_ncs_counter = NULL,
	.card_ncs_remote = NULL,
	.card_reset_ncs_counter = NULL,
	.card_chassis_info = NULL,
	.card_qos_reset = cndev_qos_reset_common,
	.card_qos_info = cndev_qos_policy_common,
	.card_qos_desc = cndev_qos_desc_common,
	.card_set_qos = cndev_set_qos_policy,
	.card_set_qos_group = cndev_set_qos_group_policy,
	.card_acpuutil_info = cndev_card_acpuutil_info_common,
	.card_acpuutil_timer = cndev_card_acpuutil_timer_common,
	.card_get_retire_pages = NULL,
	.card_get_retire_status = NULL,
	.card_get_retire_remapped_rows = NULL,
	.card_retire_switch = NULL,
	.card_ncs_port_config = NULL,
	.card_mlulink_switch_ctrl = NULL,
	.card_ipufreq_ctrl = NULL,
	.card_get_ncs_info = card_get_ncs_info_common,
	.card_get_card_info_ext = NULL,
	.card_get_process_iputil = NULL,
	.card_get_process_codecutil = NULL,
	.card_get_feature = cndev_card_get_feature_common,
	.card_set_feature = cndev_card_set_feature_common,
	.card_get_mim_profile_info = NULL,
	.card_get_mim_possible_place_info = NULL,
	.card_get_mim_vmlu_capacity_info = NULL,
	.card_get_mim_device_info = NULL,
	.card_get_desc_info = NULL,
	.card_get_cntr_info = NULL,
	.chassis_power_info = NULL,
	.card_get_smlu_profile_id = NULL,
	.card_get_smlu_profile_info = NULL,
	.card_new_smlu_profile = NULL,
	.card_delete_smlu_profile = NULL,
};

static const struct cn_cndev_ops cndev_mlu220_edge_ops = {

	.cndev_start = cndev_start_mlu220edge,
	.cndev_do_exit = cndev_do_exit_mlu220edge,
	.cndev_lateinit = cndev_lateinit_common,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_common,
	.cndev_exit = cndev_exit_common,
};

int cndev_init_mlu220(struct cn_cndev_set *cndev_set)
{
	cn_dev_cndev_info(cndev_set, "cndev init in MLU220 platform");

	switch (cndev_set->device_id) {
	case MLUID_220:
		cndev_set->ops = &cndev_mlu220_ops;
		cndev_set->ioctl = &cndev_mlu220_ioctl;
		break;
	case MLUID_220_EDGE:
		cndev_set->ops = &cndev_mlu220_edge_ops;
		cndev_set->ioctl = &cndev_mlu220_edge_ioctl;
		break;
	default:
		break;
	}

	cndev_common_init(cndev_set);

	return 0;
}
