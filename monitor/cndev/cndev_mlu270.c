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


int card_power_info_mlu270(void *cset,
			struct cndev_power_info *power_info)
{
	int ret = 0, i;
	struct board_power_info pinfo;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core;
	void *domain_set;
	struct cn_board_info *pbrdinfo;
	unsigned long domain_mask, domain_div = 0;
	u16 vcard;
	struct power_info_s *vf_pinfo = NULL;
	int result_len = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

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
	power_info->power_usage_decimal = 0;
	power_info->max_power_decimal = 0;
	power_info->fan_speed = pinfo.fan_speed;
	power_info->machine_power = 0;
	power_info->min_power_cap = pbrdinfo->min_power_cap;
	power_info->min_power_cap_decimal = pbrdinfo->min_power_cap_dec;
	power_info->max_power_cap_decimal = pbrdinfo->max_power_cap_dec;
	power_info->perf_limit_num = 0;
	power_info->edpp_count = 0;
	power_info->tdp_freq_capping_count = 0;

	/* mlu270 set tdp equal peak power */
	power_info->tdp = pbrdinfo->peak_power;
	power_info->ipu_cluster_freq_num = 0;
	power_info->instantaneous_power = power_info->power_usage;
	power_info->instantaneous_power_decimal = power_info->power_usage_decimal;
	power_info->ipu_cluster_mask = 0;

	/*check status*/
	domain_set = core->domain_set;

	domain_mask = cn_dm_get_domain_mask(domain_set);
	for_each_set_bit(i, &domain_mask, sizeof(domain_mask) * BITS_PER_U8)
		domain_div++;
	/*divide pf domain*/
	if (domain_div > 1)
		domain_div--;

	vcard = (power_info->head.card >> 8) & 0x0f;
	ret = cndev_vcard_trans(cndev_set, &vcard);
	if (ret)
		goto PIERR;

	if (vcard && vcard != 0xff) {
		pinfo.temperature_num = 4 / domain_div + 1;

		vf_pinfo = cn_kzalloc(sizeof(struct power_info_s), GFP_KERNEL);
		if (!vf_pinfo) {
			cn_dev_cndev_err(cndev_set, "alloc memory fail");
			ret = -ENOMEM;
			goto PIERR;
		}

		ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_power_info",
			(void *)&vcard, sizeof(u16),
			(void *)vf_pinfo, &result_len, sizeof(struct power_info_s));

		if (ret < 0) {
			cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
			goto PIERR;
		}

		power_info->power_usage = vf_pinfo->power_usage;
		power_info->max_power = vf_pinfo->max_power;
		power_info->fan_speed = vf_pinfo->fan_speed;
		cn_kfree(vf_pinfo);
	}

	/*send user how many temperature we can send*/
	/*copy shorter length of temp to user*/
	ret = cndev_cp_less_val(
			&power_info->temperature_num, pinfo.temperature_num,
			power_info->temp, pinfo.temp, sizeof(s8));

	power_info->ignore_chassis_power_info = 1;

PIERR:
	/*free temp buf in power_info struct which alloced in mcu function.*/
	cn_kfree(pinfo.temp);
	return ret;
}

int card_ecc_info_mlu270(void *cset,
	struct cndev_ecc_info *einfo)
{
	int mcc_channel_num = 0, i = 0;
	struct ecc_info_t *card_ecc_info = NULL;
	struct cn_core_set *core;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u16 vcard;
	int ret = 0;

	vcard = (einfo->head.card >> 8) & 0x0f;
	if (vcard)
		return -ENODEV;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	if (cndev_checkstate_common(core)) {
		return -EINVAL;
	}

	einfo->head.version = CNDEV_CURRENT_VER;
	einfo->head.real_size = sizeof(struct cndev_ecc_info);
	einfo->single_biterr = 0;
	einfo->multi_biterr = 0;
	einfo->single_multierr = 0;
	einfo->multi_multierr = 0;
	einfo->corrected_err = 0;
	einfo->uncorrect_err = 0;
	einfo->total_err = 0;
	einfo->die2die_crc_err = 0;
	einfo->die2die_crc_err_overflow = 0;

	down_read(&core->mcc_state_sem);

	mcc_channel_num = cn_mcc_get_channel_num(core);
	if (mcc_channel_num < 0) {
		ret = -EINVAL;
		goto out;
	}

	card_ecc_info =
		(struct ecc_info_t *)cn_mcc_get_ecc_status(core);
	if (IS_ERR_OR_NULL(card_ecc_info)) {
		ret = -EINVAL;
		goto out;
	}
	up_read(&core->mcc_state_sem);

	for (i = 0; i < mcc_channel_num; i++) {
		einfo->single_biterr +=
			card_ecc_info[i].one_bit_ecc_error;
		einfo->multi_biterr +=
			card_ecc_info[i].multiple_one_bit_ecc_error;
		einfo->single_multierr +=
			card_ecc_info[i].multiple_bit_ecc_error;
		einfo->multi_multierr +=
			card_ecc_info[i].multiple_multiple_bit_ecc_error;
	}

	einfo->corrected_err = einfo->single_biterr + einfo->multi_biterr;
	einfo->uncorrect_err = einfo->single_multierr + einfo->multi_multierr;
	einfo->total_err = einfo->corrected_err + einfo->uncorrect_err;

	return 0;

out:
	up_read(&core->mcc_state_sem);
	return ret;
}

int card_vm_info_mlu270(void *cset,
	struct cndev_vm_info *vinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret = 0;
	u16 vf_num = 0, vf_mask = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	vinfo->head.version = CNDEV_CURRENT_VER;
	vinfo->head.real_size = sizeof(struct cndev_vm_info);

	if (cndev_set->device_id == MLUID_270) {
		vinfo->vm_check = VM_PF;
		ret = cndev_get_valid_vf_num(cndev_set, &vf_num, &vf_mask);
		if (ret) {
			vf_mask = 0;
		}
		vinfo->vm_num = vf_mask;
	} else {
		vinfo->vm_check = cn_host_vf_enable() ? VM_HOST_VF : VM_VF;
		vinfo->vm_num = 0;
	}

	return 0;
}

int cndev_card_freq_info_mlu270(void *cset,
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

static const struct cn_cndev_ioctl cndev_mlu270_ioctl = {
	.card_info_fill = card_info_fill_common,
	.card_power_info = card_power_info_mlu270,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = card_ecc_info_mlu270,
	.card_vm_info = card_vm_info_mlu270,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = cndev_card_codecutil_info_common,
	.card_freq_info = cndev_card_freq_info_mlu270,
	.card_curbuslnk = cndev_card_curbuslnk_common,
	.card_pciethroughput = cndev_card_pciethroughput_common,
	.card_power_capping = cndev_card_powercapping_common,
	.card_ipufreq_set = NULL,
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

static const struct cn_cndev_ops cndev_mlu270_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_common,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_common,
	.cndev_exit = cndev_exit_common,
};

static const struct cn_cndev_ioctl cndev_mlu270_vf_ioctl = {
	.card_info_fill = card_info_fill_vf_common,
	.card_power_info = card_power_info_vf_common,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = NULL,
	.card_vm_info = card_vm_info_mlu270,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = NULL,
	/*not support in vf*/
	.card_freq_info = NULL,
	.card_curbuslnk = NULL,
	.card_pciethroughput = cndev_card_pciethroughput_common,
	.card_power_capping = NULL,
	.card_ipufreq_set = NULL,
	.card_ncs_version = NULL,
	.card_ncs_state = NULL,
	.card_ncs_speed = NULL,
	.card_ncs_capability = NULL,
	.card_ncs_counter = NULL,
	.card_ncs_remote = NULL,
	.card_reset_ncs_counter = NULL,
	.card_chassis_info = NULL,
	.card_qos_reset = NULL,
	.card_qos_info = NULL,
	.card_qos_desc = NULL,
	.card_set_qos = NULL,
	.card_set_qos_group = NULL,
	.card_acpuutil_info = NULL,
	.card_acpuutil_timer = NULL,
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

static const struct cn_cndev_ops cndev_mlu270_vf_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_common,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_common,
	.cndev_exit = cndev_exit_common,
};

int cndev_init_mlu270(struct cn_cndev_set *cndev_set)
{

	switch (cndev_set->device_id) {
	case MLUID_270:
		cndev_set->ops = &cndev_mlu270_ops;
		cndev_set->ioctl = &cndev_mlu270_ioctl;
		break;
	case MLUID_270V:
	case MLUID_270V1:
		cndev_set->ops = &cndev_mlu270_vf_ops;
		cndev_set->ioctl = &cndev_mlu270_vf_ioctl;
		break;
	}

	cndev_common_init(cndev_set);


	return 0;
}
