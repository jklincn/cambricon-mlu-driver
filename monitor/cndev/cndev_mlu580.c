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
#include "../camb_pmu_rpc.h"
#include "cndrv_xid.h"
#include "cndrv_smlu.h"
#include "cndev_rpc_info.h"

int cndev_print_overtemp_freq_warning_mlu580(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	int ret = -EINVAL;
	struct mlu_overtemp_value overtemp;
	struct mlu_overtemp_warning *freq_warning = NULL;
	struct mlu_overtemp_warning *poweroff_warning = NULL;

	if (IS_ERR_OR_NULL(pcore)) {
		cn_dev_err("pcore set is null");
		return ret;
	}

	memset(&overtemp, 0, sizeof(struct mlu_overtemp_value));

	freq_warning = &(core->freq_warning);
	poweroff_warning = &(core->poweroff_warning);

	ret = cndrv_mcu_read_overtemp_freq(core, &overtemp);
	if (!ret) {
		if (overtemp.freq_value != freq_warning->value) {
			freq_warning->value = overtemp.freq_value;
			freq_warning->cycle = freq_warning->refresh_cycle;
		}
		if (freq_warning->cycle > 0 && freq_warning->mode == OVERTEMP_WARNING_AUTO) {
			freq_warning->cycle--;
			cn_dev_core_warn(core, "Overtemperature and Frequency is reducating");
		}

		if (overtemp.poweroff_value != poweroff_warning->value) {
			poweroff_warning->value = overtemp.poweroff_value;
			poweroff_warning->cycle = poweroff_warning->refresh_cycle;
		}
		if (poweroff_warning->cycle > 0 && poweroff_warning->mode == OVERTEMP_WARNING_AUTO) {
			poweroff_warning->cycle--;
			cn_dev_core_warn(core, "Overtemperature and Poweroff has occurred");
		}
	}

	return ret;
}

static enum hrtimer_restart mlu580_cndev_mcuinfo_work_hrtimer(struct hrtimer *timer)
{
	struct cn_cndev_set *cndev_set = NULL;
	struct cn_core_set *core = NULL;

	cndev_set = container_of(timer, struct cn_cndev_set, mcuinfo_hrtimer);

	if (IS_ERR_OR_NULL(cndev_set))
		goto timer_err;
	if (IS_ERR_OR_NULL(cndev_set->core))
		goto out;

	core = cndev_set->core;

	cndev_print_overtemp_freq_warning_mlu580(core);

out:
	hrtimer_forward_now(timer, cndev_set->mcuinfo_time_delay);
	return HRTIMER_RESTART;
timer_err:
	return HRTIMER_NORESTART;
}

int cndev_lateinit_mlu580(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;
	int ret = 0;

	if (cndev_set->device_id != MLUID_580V) {
		hrtimer_start(&cndev_set->mcuinfo_hrtimer, cndev_set->mcuinfo_time_delay,
				HRTIMER_MODE_REL);
	}

	ret = cndev_rpc_client_register(pcore);
	if (ret) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call commu register failed");
		goto out;
	}

	ret = cndev_rpc_resource(cndev_set);
	if (ret) {
		cn_dev_cndev_err(cndev_set, "cndev get resource failed");
		goto out;
	}

	ret = cndev_rpc_lateinit(cndev_set);
	if (ret) {
		cn_dev_cndev_err(cndev_set, "cndev rpc lateinit failed");
		goto out;
	}

	ret = cndev_start_common(cndev_set);
	if (ret) {
		cn_dev_cndev_err(cndev_set, "cndev rpc start cndev failed");
	}

out:
	return ret;
}

void cndev_stop_mlu580(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *pcore = NULL;

	if (!cndev_set) {
		return;
	}

	pcore = cndev_set->core;

	if (cndev_set->endpoint) {
		__pmu_disconnect(cndev_set->endpoint, pcore);
		cndev_set->endpoint = NULL;
	}

	hrtimer_cancel(&cndev_set->hrtimer);
	if (cndev_set->device_id != MLUID_580V) {
		hrtimer_cancel(&cndev_set->mcuinfo_hrtimer);
	}
}

void cndev_exit_mlu580(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *pcore = NULL;

	if (!cndev_set) {
		return;
	}

	pcore = cndev_set->core;

	hrtimer_cancel(&cndev_set->hrtimer);

	if (cndev_set && cndev_set->device_id != MLUID_580V) {
		hrtimer_cancel(&cndev_set->mcuinfo_hrtimer);
	}

	if (cndev_set->endpoint) {
		__pmu_disconnect(cndev_set->endpoint, pcore);
		cndev_set->endpoint = NULL;
	}

	cndev_set->ops = NULL;
}

void card_info_fill_mlu580(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;
	struct cn_board_info *pbrdinfo = &core->board_info;
	struct cndev_card_info *info = &cndev_set->card_static_info;
	struct bus_info_s bus_info;
	struct bus_lnkcap_info lnk_info;
	struct board_info_s brdinfo_rmt;

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

	/* pcie fw version, get from ipc reg */
	info->pcie_fw_info = pbrdinfo->pcie_fw_info;

	/* SOC ID*/
	info->secure_mode = pbrdinfo->secure_mode;
	memcpy(info->soc_id, pbrdinfo->soc_id.soc_id_data, SOC_ID_SIZE);

	/* get info from dev */
	memset(&brdinfo_rmt, 0x0, sizeof(struct board_info_s));
	cndev_rpc_dev_info(cndev_set, &brdinfo_rmt, 0);
	/* mem data width */
	info->data_width = brdinfo_rmt.ddr_bus_width;
	info->bandwidth = brdinfo_rmt.ddr_bandwidth;
	info->bandwidth_decimal = brdinfo_rmt.ddr_bandwidth_decimal;
	memcpy(info->uuid, brdinfo_rmt.uuid, CNDRV_UUID_SIZE);
	memcpy(pbrdinfo->uuid, brdinfo_rmt.uuid, CNDRV_UUID_SIZE);
}

int card_power_info_mlu580(void *cset,
			struct cndev_power_info *power_info)
{
	int ret = 0, i;
	struct board_power_info pinfo;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	void *domain_set;
	struct cn_board_info *pbrdinfo;
	unsigned long domain_mask, domain_div = 0;
	u16 vcard;
	struct power_info_s *vf_pinfo = NULL;
	uint32_t result_len = sizeof(struct power_info_s) + 20 * sizeof(u8);

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
	power_info->max_power_decimal = pinfo.max_power_decimal;
	power_info->fan_speed = pinfo.fan_speed;
	power_info->machine_power = pinfo.machine_power;
	power_info->min_power_cap = pbrdinfo->min_power_cap;
	power_info->min_power_cap_decimal = pbrdinfo->min_power_cap_dec;
	power_info->max_power_cap_decimal = pbrdinfo->max_power_cap_dec;

	power_info->over_temp_poweroff_times = pinfo.over_temp_poweroff_times;
	power_info->over_temp_underclock_times = pinfo.over_temp_underclock_times;
	power_info->over_temp_poweroff_temp = pinfo.over_temp_poweroff_temp;
	power_info->over_temp_underclock_temp = pinfo.over_temp_underclock_temp;

	/* mlu580 set tdp */
	power_info->tdp = pbrdinfo->peak_power;
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
			cn_dev_monitor_err(cndev_set, "pmu rpc call failed, ret = %d", ret);
			cn_kfree(vf_pinfo);
			goto PIERR;
		}

		power_info->power_usage = vf_pinfo->power_usage;
		power_info->power_usage_decimal = 0;
		power_info->max_power = vf_pinfo->max_power;
		power_info->fan_speed = vf_pinfo->fan_speed;

		ret = cndev_cp_less_val(
			&power_info->ipu_cluster_freq_num, vf_pinfo->ic_num,
			power_info->ipu_cluster_freq, vf_pinfo->ic_freq, sizeof(u16));

		power_info->instantaneous_power = vf_pinfo->power_usage;
		power_info->instantaneous_power_decimal = 0;
		power_info->ipu_cluster_mask = vf_pinfo->logic_ic_bitmap;
		power_info->ipu_cluster_freq_num = vf_pinfo->ic_num;
		power_info->edpp_count = vf_pinfo->edpp_count;
		power_info->tdp_freq_capping_count = vf_pinfo->tdp_freq_capping_count;
		cn_kfree(vf_pinfo);
	} else {
		ret = cndev_cp_less_val(
			&power_info->ipu_cluster_freq_num, pinfo.ipu_cluster_freq_num,
			power_info->ipu_cluster_freq, pinfo.ic_freq, sizeof(u16));
		if (ret) {
			goto PIERR;
		}
		power_info->ipu_cluster_freq_num = pinfo.ipu_cluster_freq_num;
		power_info->instantaneous_power = pinfo.instantaneous_power;
		power_info->instantaneous_power_decimal = pinfo.instantaneous_power_decimal;
		power_info->ipu_cluster_mask = pinfo.ipu_cluster_mask;

		power_info->edpp_count = pinfo.edpp_count;
		power_info->tdp_freq_capping_count = pinfo.tdp_freq_capping_count;
	}

	if (power_info->perf_limit_num) {
		/*copy shorter length of power limit reason to user*/
		ret = cndev_cp_less_val(
			&power_info->perf_limit_num, pinfo.perf_limit_num,
			power_info->perf_limit, pinfo.perf_limit, sizeof(u8));
	}

	/*send user how many temperature we can send*/
	/*copy shorter length of temp to user*/
	ret = cndev_cp_less_val(
			&power_info->temperature_num, pinfo.temperature_num,
			power_info->temp, pinfo.temp, sizeof(s8));
	if (ret) {
		goto PIERR;
	}

PIERR:
	/*free temp buf in power_info struct which alloced in mcu function.*/
	cn_kfree(pinfo.ic_freq);
	cn_kfree(pinfo.temp);
	cn_kfree(pinfo.perf_limit);
	return ret;
}

int card_vm_info_mlu580(void *cset,
	struct cndev_vm_info *vinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret = 0;
	u16 vf_num = 0, vf_mask = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	vinfo->head.version = CNDEV_CURRENT_VER;
	vinfo->head.real_size = sizeof(struct cndev_vm_info);

	if (cndev_set->device_id == MLUID_580) {
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

int cndev_card_freq_info_mlu580(void *cset,
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

	/*send user how many die ipu freq we can send*/
	/*copy shorter length of die to ipu freq user*/
	ret = cndev_cp_less_val(
			&finfo->die_ipu_cnt, info.die_ipu_freq.die_ipu_cnt,
			finfo->die_ipu_freq, info.die_ipu_freq.ipu_freq, sizeof(u32));
	finfo->die_ipu_cnt = info.die_ipu_freq.die_ipu_cnt;
	return ret;
}

int cndev_card_powercapping_mlu580(void *cset,
	struct cndev_powercapping_s *pcinfo)
{
	struct power_capping_info *mcu_param;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u16 vcard;

	vcard = (pcinfo->head.card >> 8) & 0x0f;
	if (vcard)
		return -ENODEV;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	pcinfo->head.version = CNDEV_CURRENT_VER;
	pcinfo->head.real_size = sizeof(struct cndev_powercapping_s);

	mcu_param = (struct power_capping_info *)&pcinfo->ops_type;

	return cndrv_mcu_power_capping(cndev_set->core, mcu_param);
}

int card_ipufreq_ctrl_mlu580(void *cset, struct cndev_ipufreq_ctrl *ipufreq_ctrl)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	core = cndev_set->core;

	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	if (IS_ERR_OR_NULL(ipufreq_ctrl))
		return -EINVAL;

	ipufreq_ctrl->head.version = CNDEV_CURRENT_VER;
	ipufreq_ctrl->head.real_size = sizeof(struct cndev_ipufreq_ctrl);

	return 0;
}

int card_ipufreq_set_mlu580(void *cset,
	struct cndev_ipufreq_set *setinfo)
{
	int ret = 0;
	int result = -1;
	uint32_t result_len = sizeof(result);
	struct cndev_ipufreq_set_s freqset;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	freqset.ipu_freq = setinfo->ipu_freq;
	freqset.ctrl_mode = setinfo->ctrl_mode;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_ipufreq_set",
			(void *)&freqset, sizeof(struct cndev_ipufreq_set_s),
			(void *)&result, &result_len, sizeof(result));
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}
	if (result < 0) {
		cn_dev_cndev_err(cndev_set, "set freq failed");
	}

	return result;
}

int cndev_card_get_retire_pages_mlu580(void *cset,
	struct cndev_retire_page *retire_pages)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int result = 0;
	u64 *page_addr = NULL;
	u32 page_count = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	retire_pages->head.version = CNDEV_CURRENT_VER;
	retire_pages->head.real_size = sizeof(struct cndev_retire_page);

	if (cn_core_is_vf(core) || cn_is_mim_en(core) || !core->ile_en) {
		retire_pages->page_count = 0;
		result = 0;
		goto out;
	} else {
		result = cn_mcc_get_retire_pages(core, retire_pages->cause,
			&page_count, &page_addr);
	}

	if (result) {
		cn_dev_cndev_err(cndev_set, "get retire pages info failed");
		goto out;
	}

	if (page_count)
		result = cndev_cp_less_val(
				&retire_pages->page_count, page_count,
				retire_pages->page_addr, page_addr, sizeof(u64));

	retire_pages->page_count = page_count;

out:
	return result;

}

int cndev_card_get_retire_status_mlu580(void *cset,
	struct cndev_retire_status *retire_status)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int result = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	retire_status->head.version = CNDEV_CURRENT_VER;
	retire_status->head.real_size = sizeof(struct cndev_retire_status);

	if (cn_core_is_vf(core) || cn_is_mim_en(core) || !core->ile_en) {
		retire_status->is_pending = 0;
		retire_status->is_failure = 0;
		return 0;
	} else {
		result = cn_mcc_get_retire_pages_pending_status(core,
			&retire_status->is_pending, &retire_status->is_failure);
	}

	return result;
}

int cndev_card_get_retire_remapped_rows_mlu580(void *cset,
	struct cndev_retire_remapped_rows *retire_remapped_rows)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int result = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	retire_remapped_rows->head.version = CNDEV_CURRENT_VER;
	retire_remapped_rows->head.real_size = sizeof(struct cndev_retire_remapped_rows);

	if (!core->ile_en) {
		retire_remapped_rows->unc_rows = 0;
		retire_remapped_rows->corr_rows = 0;
		retire_remapped_rows->pending_rows = 0;
		retire_remapped_rows->fail_rows = 0;
		return 0;
	}

	result = cn_mcc_get_remapped_rows(core, &retire_remapped_rows->corr_rows,
		&retire_remapped_rows->unc_rows, &retire_remapped_rows->pending_rows,
		&retire_remapped_rows->fail_rows);

	return result;
}

int cndev_card_retire_switch_mlu580(void *cset,
	struct cndev_retire_op *retire_op)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int result = 0;
	int ret = 0;
	u32 retire_switch = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	retire_op->head.version = CNDEV_CURRENT_VER;
	retire_op->head.real_size = sizeof(struct cndev_retire_op);

	if (!core->ile_en) {
		retire_op->retire_switch = 0;
		return 0;
	}

	if (retire_op->op) {
		if (retire_op->retire_switch)
			retire_switch = 1;
		else
			retire_switch = 0;

		result = cn_mcc_retire_switch(core, retire_switch);
		/*set switch(on-1), return 1*/
		/*set switch(off-0), return 0*/
		/*set switch(others), query*/
		if (retire_switch == result)
			return 0;
		else
			return -EINVAL;
	} else {
		/*set switch 0xff means query switch*/
		ret = cn_mcc_retire_switch(core, 0xff);
		if (ret < 0) {
			retire_op->retire_switch = 0;
			result = -EINVAL;
		} else {
			retire_op->retire_switch = ret;
			result = 0;
		}
	}
	return result;
}

int cndev_card_ile_ctrl_mlu580(void *cset, struct cndev_feature *info)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct cndev_feature_ile_ctrl ile_op;
	u32 cpsize = sizeof(struct cndev_feature_ile_ctrl);
	u32 reg32 = 0;

	cpsize = (cpsize < info->head.buf_size) ? cpsize : info->head.buf_size;
	if (IS_ERR_OR_NULL(info->DPTR))
		return -EINVAL;

	if (cndev_cp_from_usr(info->DPTR, &ile_op, cpsize))
		return -EINVAL;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	reg32 = cn_mcu_read32(core, MLU580_IPC_33);
	reg32 &= ~0x3;
	if (ile_op.op)
		reg32 |= 0x2;
	else
		reg32 |= 0x1;
	cn_mcu_write32(core, MLU580_IPC_33, reg32);
	return 0;
}

int cndev_card_set_feature_mlu580(void *cset, struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	info->head.version = CNDEV_CURRENT_VER;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	switch (info->FID)
	{
	case CN_FEAT_XID:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_set_xid);
		ret = cndev_card_set_xid_common(cset, info);
		break;
	case CN_FEAT_CMP_PW:
		info->SUP = 0;
		break;
	case CN_FEAT_EXCLUSIVE_MOD:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_exclusive_mode);
		ret = cndev_card_exclusive_mode_common(cset, CNDEV_SET_EXCLUSIVE_MODE, info);
		break;
	case CN_FEAT_SRIOV_MOD:
		info->SUP = cn_dm_is_mim_support(core);
		info->head.real_size = sizeof(struct cndev_feature_sriov_mode);
		if (info->SUP) {
			ret = cndev_card_sriov_mode_common(cset, CNDEV_SET_SRIOV_MODE, info);
		} else {
			ret = 0;
		}
		break;
	case CN_FEAT_MIM_VMLU:
		info->SUP = cn_dm_is_mim_support(core);
		info->head.real_size = sizeof(struct cndev_feature_mim_vmlu);
		if (info->SUP) {
			ret = cndev_card_set_mim_vmlu_common(cset, info);
		} else {
			ret = 0;
		}
		break;
	case CN_FEAT_INLINE_ECC_CTRL:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_ile_ctrl);
		info->head.version = CNDEV_CURRENT_VER;
		ret = cndev_card_ile_ctrl_mlu580(cset, info);
		break;
	case CN_FEAT_SMLU:
		info->SUP = cn_is_smlu_support(core);
		info->head.real_size = sizeof(struct cndev_feature_smlu);
		if (info->SUP) {
			ret = cndev_card_set_smlu_common(cset, info);
		} else {
			ret = 0;
		}
		break;
	default:
		ret = 0;
		info->SUP = 0;
		break;
	}

	return ret;
}

int cndev_card_get_feature_mlu580(void *cset, struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	info->head.version = CNDEV_CURRENT_VER;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	switch (info->FID)
	{
	case CN_FEAT_XID:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_get_xid);
		ret = cndev_card_get_xid_common(cset, info);
		break;
	case CN_FEAT_CMP_PW:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_get_computing_power);
		ret = cndev_card_get_computing_power_common(cset, info);
		break;
	case CN_FEAT_EXCLUSIVE_MOD:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_exclusive_mode);
		ret = cndev_card_exclusive_mode_common(cset, CNDEV_GET_EXCLUSIVE_MODE, info);
		break;
	case CN_FEAT_SRIOV_MOD:
		info->SUP = cn_dm_is_mim_support(core);
		info->head.real_size = sizeof(struct cndev_feature_sriov_mode);
		if (info->SUP) {
			ret = cndev_card_sriov_mode_common(cset, CNDEV_GET_SRIOV_MODE, info);
		} else {
			ret = 0;
		}
		break;
	case CN_FEAT_MIM_VMLU:
		info->SUP = cn_dm_is_mim_support(core);
		info->head.real_size = sizeof(struct cndev_feature_mim_vmlu_info);
		if (info->SUP) {
			ret = cndev_card_get_mim_vmlu_info_common(cset, info);
		} else {
			ret = 0;
		}
		break;
	case CN_FEAT_SMLU:
		info->SUP = cn_is_smlu_support(core);
		info->head.real_size = sizeof(struct cndev_feature_smlu_info);
		if (info->SUP) {
			ret = cndev_card_get_smlu_info_common(cset, info);
		} else {
			ret = 0;
		}
		break;
	default:
		ret = 0;
		info->SUP = 0;
		break;
	}

	return ret;
}

static const struct cn_cndev_ioctl cndev_mlu580_ioctl = {
	.card_info_fill = card_info_fill_mlu580,
	.card_power_info = card_power_info_mlu580,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = card_ecc_info_common,
	.card_vm_info = card_vm_info_mlu580,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = cndev_card_codecutil_info_common,
	.card_freq_info = cndev_card_freq_info_mlu580,
	.card_curbuslnk = cndev_card_curbuslnk_common,
	.card_pciethroughput = cndev_card_pciethroughput_common,
	.card_power_capping = cndev_card_powercapping_mlu580,
	.card_ipufreq_set = card_ipufreq_set_mlu580,
	.card_ncs_version = card_ncs_version_common,
	.card_ncs_state = card_ncs_state_common,
	.card_ncs_speed = card_ncs_speed_common,
	.card_ncs_capability = card_ncs_capability_common,
	.card_ncs_counter = card_ncs_counter_common,
	.card_ncs_remote = card_ncs_remote_common,
	.card_reset_ncs_counter = card_ncs_reset_cntr_common,
	.card_chassis_info = NULL,
	.card_qos_reset = NULL,
	.card_qos_info = NULL,
	.card_qos_desc = NULL,
	.card_set_qos = NULL,
	.card_set_qos_group = NULL,
	.card_acpuutil_info = cndev_card_acpuutil_info_common,
	.card_acpuutil_timer = cndev_card_acpuutil_timer_common,
	.card_get_retire_pages = cndev_card_get_retire_pages_mlu580,
	.card_get_retire_status = cndev_card_get_retire_status_mlu580,
	.card_get_retire_remapped_rows = cndev_card_get_retire_remapped_rows_mlu580,
	.card_retire_switch = cndev_card_retire_switch_mlu580,
	.card_ncs_port_config = card_ncs_port_config_common,
	.card_mlulink_switch_ctrl = card_mlulink_switch_ctrl_common,
	.card_ipufreq_ctrl = card_ipufreq_ctrl_mlu580,
	.card_get_ncs_info = card_get_ncs_info_common,
	.card_get_card_info_ext = NULL,
	.card_get_process_iputil = cndev_get_process_ipuutil_common,
	.card_get_process_codecutil = cndev_get_process_codecutil_common,
	.card_get_feature = cndev_card_get_feature_mlu580,
	.card_set_feature = cndev_card_set_feature_mlu580,
	.card_get_mim_profile_info = cndev_card_get_mim_profile_info_common,
	.card_get_mim_possible_place_info = cndev_card_get_mim_possible_place_info_common,
	.card_get_mim_vmlu_capacity_info = cndev_card_get_mim_vmlu_capacity_info_common,
	.card_get_mim_device_info = cndev_card_get_mim_device_info_common,
	.card_get_desc_info = cndev_card_get_desc_common,
	.card_get_cntr_info = cndev_card_get_cntr_info_common,
	.chassis_power_info = NULL,
	.card_get_smlu_profile_id = cndev_card_get_smlu_profile_id_common,
	.card_get_smlu_profile_info = cndev_card_get_smlu_profile_info_common,
	.card_new_smlu_profile = cndev_card_new_smlu_profile_common,
	.card_delete_smlu_profile = cndev_card_delete_smlu_profile_common,
};

static const struct cn_cndev_ops cndev_mlu580_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_mlu580,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_mlu580,
	.cndev_exit = cndev_exit_mlu580,
};

static const struct cn_cndev_ioctl cndev_mlu580_vf_ioctl = {
	.card_info_fill = card_info_fill_vf_common,
	.card_power_info = card_power_info_vf_common,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_mlu500_vf,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = card_ecc_info_vf_common,
	.card_vm_info = card_vm_info_mlu580,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = NULL,
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
	.card_get_mim_profile_info = cndev_card_get_mim_profile_info_common,
	.card_get_mim_possible_place_info = cndev_card_get_mim_possible_place_info_common,
	.card_get_mim_vmlu_capacity_info = cndev_card_get_mim_vmlu_capacity_info_common,
	.card_get_mim_device_info = cndev_card_get_mim_device_info_common,
	.card_get_desc_info = NULL,
	.card_get_cntr_info = NULL,
	.chassis_power_info = NULL,
	.card_get_smlu_profile_id = cndev_card_get_smlu_profile_id_common,
	.card_get_smlu_profile_info = cndev_card_get_smlu_profile_info_common,
	.card_new_smlu_profile = cndev_card_new_smlu_profile_common,
};

static const struct cn_cndev_ops cndev_mlu580_vf_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_mlu580,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_mlu580,
	.cndev_exit = cndev_exit_mlu580,
};

int cndev_init_mlu580(struct cn_cndev_set *cndev_set)
{

	switch (cndev_set->device_id) {
	case MLUID_580:
		cndev_set->ops = &cndev_mlu580_ops;
		cndev_set->ioctl = &cndev_mlu580_ioctl;
		/* Timer 500ms */
		cndev_set->mcuinfo_time_delay = ktime_set(0, 500 * 1000 * 1000);
		hrtimer_init(&cndev_set->mcuinfo_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		cndev_set->mcuinfo_hrtimer.function = mlu580_cndev_mcuinfo_work_hrtimer;
		cndev_init_codec_process_util(cndev_set);
		break;
	case MLUID_580V:
	case MLUID_580_DEV:
		cndev_set->ops = &cndev_mlu580_vf_ops;
		cndev_set->ioctl = &cndev_mlu580_vf_ioctl;
		break;
	}

	cndev_common_init(cndev_set);

	return 0;
}
