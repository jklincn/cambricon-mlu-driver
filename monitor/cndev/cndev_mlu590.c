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
#include "cndrv_domain.h"
#include "cndrv_smlu.h"


static struct cndev_config mlu590_card_cfg[MAX_FUNCTION_NUM];

int cndev_card_powercapping_mlu590(void *cset,
	struct cndev_powercapping_s *pcinfo);
int card_ipufreq_ctrl_mlu590(void *cset,
	struct cndev_ipufreq_ctrl *ipufreq_ctrl);

int cndev_print_overtemp_freq_warning_mlu590(void *pcore)
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

static enum hrtimer_restart mlu590_cndev_mcuinfo_work_hrtimer(struct hrtimer *timer)
{
	struct cn_cndev_set *cndev_set = NULL;
	struct cn_core_set *core = NULL;
	struct dma_info_s dma_info;
	u32 reg32 = 0;

	cndev_set = container_of(timer, struct cn_cndev_set, mcuinfo_hrtimer);

	if (IS_ERR_OR_NULL(cndev_set))
		goto timer_err;
	if (IS_ERR_OR_NULL(cndev_set->core))
		goto out;

	core = cndev_set->core;

	cndev_print_overtemp_freq_warning_mlu590(core);

	cn_bus_get_dma_info(core->bus_set, &dma_info);

	cndev_set->pcie_throughput_to_mcu.read_data =
		dma_info.dma_data_total[DMA_D2H] -
		cndev_set->pcie_throughput_to_mcu.read_last;
	cndev_set->pcie_throughput_to_mcu.write_data =
		dma_info.dma_data_total[DMA_H2D] -
		cndev_set->pcie_throughput_to_mcu.write_last;
	cndev_set->pcie_throughput_to_mcu.read_last =
		dma_info.dma_data_total[DMA_D2H];
	cndev_set->pcie_throughput_to_mcu.write_last =
		dma_info.dma_data_total[DMA_H2D];

	reg32 = cndev_set->pcie_throughput_to_mcu.write_data / 1024 / 1024;
	reg32 |= (cndev_set->pcie_throughput_to_mcu.read_data  / 1024 / 1024) << 16;

	cn_mcu_write32(core, MLU590_IPC_45, reg32);

out:
	hrtimer_forward_now(timer, cndev_set->mcuinfo_time_delay);
	return HRTIMER_RESTART;
timer_err:
	return HRTIMER_NORESTART;
}

int cndev_lateinit_mlu590(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;
	int ret = 0;

	if (cndev_set->device_id != MLUID_590V) {
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

int cndev_lateinit_mlu590_pf(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;
	int ret = 0;
	struct cndev_powercapping_s power_capping_setting = {};
	struct cndev_ipufreq_ctrl ipufreq_ctrl = {};

	ret = cndev_lateinit_mlu590(pcore);
	if (ret)
		goto out;

	if (mlu590_card_cfg[core->idx].ipu_cfg_recovery) {
		memcpy(&ipufreq_ctrl, &mlu590_card_cfg[core->idx].ipu_freq_cfg,
			sizeof(struct cndev_ipufreq_set_s));

		ipufreq_ctrl.head.card = 0;
		if (card_ipufreq_ctrl_mlu590(cndev_set, &ipufreq_ctrl)) {
			cn_dev_cndev_warn(cndev_set, "Recover IPU freq control configuration failed");
		}
	}

	if (mlu590_card_cfg[core->idx].power_cfg_recovery) {
		memcpy(&power_capping_setting, &mlu590_card_cfg[core->idx].power_capping_cfg,
			sizeof(struct cndev_ipufreq_set_s));

		power_capping_setting.head.card = 0;
		ret = cndev_card_powercapping_mlu590(cndev_set, &power_capping_setting);
		if (ret) {
			cn_dev_cndev_warn(cndev_set, "Recover power cap configuration failed");
		}
	}

out:
	return ret;
}

void cndev_stop_mlu590(void *cset)
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
	if (cndev_set->device_id != MLUID_590V) {
		hrtimer_cancel(&cndev_set->mcuinfo_hrtimer);
	}
}

void cndev_exit_mlu590(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *pcore = NULL;

	if (!cndev_set) {
		return;
	}

	pcore = cndev_set->core;

	hrtimer_cancel(&cndev_set->hrtimer);

	if (cndev_set && cndev_set->device_id != MLUID_590V) {
		hrtimer_cancel(&cndev_set->mcuinfo_hrtimer);
	}

	if (cndev_set->endpoint) {
		__pmu_disconnect(cndev_set->endpoint, pcore);
		cndev_set->endpoint = NULL;
	}

	cndev_set->ops = NULL;
}

int cndev_restart_mlu590(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	if (!cndev_set) {
		return 0;
	}

	hrtimer_start(&cndev_set->hrtimer,
		cndev_set->time_delay,
		HRTIMER_MODE_REL);

	return 0;
}

void card_info_fill_mlu590(void *cset)
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

int card_power_info_mlu590(void *cset,
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
	int copy_length = 0;
	struct chassis_runtime_info_s *chassis_rt_info = NULL;

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

	/* mlu590 set tdp */
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

	if (power_info->ignore_chassis_power_info) {
		cn_dev_cndev_debug(cndev_set, "ingore chassis info");
		power_info->fan_num = 0;
		power_info->machine_power = 0;
		pinfo.temp[3] = 0;
		pinfo.temp[4] = 0;
		pinfo.temperature_num += 2;
		ret = cndev_cp_less_val(
			&power_info->temperature_num, pinfo.temperature_num,
			power_info->temp, pinfo.temp, sizeof(s8));

		goto PIERR;
	}

	copy_length = sizeof(struct chassis_runtime_info_s) +
		sizeof(u16) * MLU590_FAN_COUNT;
	chassis_rt_info = cn_kzalloc(copy_length, GFP_KERNEL);
	if (!chassis_rt_info) {
		cn_dev_core_err(core, "alloc buf fail");
		ret = -ENOMEM;
		goto PIERR;
	}
	chassis_rt_info->fan_num = MLU590_FAN_COUNT;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_fan_info",
			NULL, 0, (void *)chassis_rt_info, &result_len, copy_length);
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
		goto RT_ERR;
	}

	power_info->machine_power = chassis_rt_info->machine_power;
	pinfo.temp[3] = chassis_rt_info->machine_in_fan;
	pinfo.temp[4] = chassis_rt_info->machine_out_fan;
	pinfo.temperature_num += 2;

	copy_length =
		(power_info->fan_num < chassis_rt_info->fan_num)
		? power_info->fan_num : chassis_rt_info->fan_num;
	/*send user how many MLU590 FAN we can send*/
	power_info->fan_num = chassis_rt_info->fan_num;

	/*send user how many temperature we can send*/
	/*copy shorter length of temp to user*/
	ret = cndev_cp_less_val(
			&power_info->temperature_num, pinfo.temperature_num,
			power_info->temp, pinfo.temp, sizeof(s8));
	if (ret) {
		goto RT_ERR;
	}

	/*copy shorter length of FAN to user*/
	if (power_info->fan) {
		ret = cndev_cp_to_usr(power_info->fan, chassis_rt_info->fan,
			copy_length * sizeof(u16));
	}

RT_ERR:
	/*free FAN buf in power_info struct which alloced in mcu function.*/
	if (chassis_rt_info)
		cn_kfree(chassis_rt_info);

PIERR:
	/*free temp buf in power_info struct which alloced in mcu function.*/
	cn_kfree(pinfo.ic_freq);
	cn_kfree(pinfo.temp);
	cn_kfree(pinfo.perf_limit);

	return ret;
}

int card_vm_info_mlu590(void *cset,
	struct cndev_vm_info *vinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret = 0;
	u16 vf_num = 0, vf_mask = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	vinfo->head.version = CNDEV_CURRENT_VER;
	vinfo->head.real_size = sizeof(struct cndev_vm_info);

	if (cndev_set->device_id == MLUID_590) {
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

int cndev_card_freq_info_mlu590(void *cset,
	struct cndev_freq_info *finfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret = 0;
	struct cn_core_set *core = NULL;
	struct cn_board_info *pbrdinfo = NULL;
	u16 vcard = 0;
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

int cndev_card_powercapping_mlu590(void *cset,
	struct cndev_powercapping_s *pcinfo)
{
	struct power_capping_info *mcu_param = NULL;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	u16 vcard = 0;
	int ret = 0;

	vcard = (pcinfo->head.card >> 8) & 0x0f;
	if (vcard)
		return -ENODEV;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	pcinfo->head.version = CNDEV_CURRENT_VER;
	pcinfo->head.real_size = sizeof(struct cndev_powercapping_s);

	mcu_param = (struct power_capping_info *)&pcinfo->ops_type;

	ret = cndrv_mcu_power_capping(cndev_set->core, mcu_param);
	if (!ret) {
		if (mcu_param->ops_type) {
			switch (mcu_param->mode) {
				case TEMPORARY:
					memcpy(&mlu590_card_cfg[core->idx].power_capping_cfg, &pcinfo,
						sizeof(struct cndev_ipufreq_set_s));
					mlu590_card_cfg[core->idx].power_cfg_recovery = 1;
				break;
				case DISABLE_PERMANENT:
					mlu590_card_cfg[core->idx].power_cfg_recovery = 0;
				break;
				default:
				break;
			}
		}
	}

	return ret;
}

int __card_ipufreq_set_ctrl(void *cset, struct cndev_ipufreq_set_s *freqset)
{
	int ret = 0;
	int result = -1;
	uint32_t result_len = sizeof(result);
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	u32 cnt = 200;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	while (cnt-- > 0) {
		ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_ipufreq_set",
				(void *)freqset, sizeof(struct cndev_ipufreq_set_s),
				(void *)&result, &result_len, sizeof(result));
		if (ret < 0) {
			cn_dev_cndev_err(cndev_set, "call commu failed");
			return ret;
		}

		if (result == CNDEV_IPU_FREQ_CAPPING_RETRY) {
			msleep(50);
			continue;
		} else {
			return result;
		}
	}

	return 0;
}

int card_ipufreq_ctrl_mlu590(void *cset, struct cndev_ipufreq_ctrl *ipufreq_ctrl)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u32 reg32 = 0;
	struct cn_core_set *core = NULL;
	int ret = 0;
	struct cndev_ipufreq_set_s freqset;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	core = cndev_set->core;

	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	if (IS_ERR_OR_NULL(ipufreq_ctrl))
		return -EINVAL;

	ipufreq_ctrl->head.version = CNDEV_CURRENT_VER;
	ipufreq_ctrl->head.real_size = sizeof(struct cndev_ipufreq_ctrl);

	switch (ipufreq_ctrl->ops_type) {
	case CNDEV_IPU_FREQ_LOCK_STATUS:
		reg32 = cn_mcu_read32(core, MLU590_IPC_42);
		ipufreq_ctrl->ipufreq_lock_status = (reg32 >> 5) & 0x1;
		break;
	case CNDEV_IPU_FREQ_LOCK_CLEAR:
		freqset.ctrl_mode = 2;
		freqset.ipu_freq = 0;
		ret = __card_ipufreq_set_ctrl(cndev_set, &freqset);
		if (ret < 0) {
			cn_dev_cndev_err(cndev_set, "unlock IPU freq failed");
			return ret;
		}

		if (mlu590_card_cfg[core->idx].ipu_cfg_recovery &&
			mlu590_card_cfg[core->idx].ipu_freq_cfg.ctrl_mode) {
			mlu590_card_cfg[core->idx].ipu_cfg_recovery = 0;
		}
		break;
	default:
		cn_xid_err(core, XID_SW_NOTIFY_ERR,
			"cndev ipufreq ctrl not support %u", ipufreq_ctrl->ops_type);
		return -EPERM;
	}

	return 0;
}

int card_ipufreq_set_mlu590(void *cset,
	struct cndev_ipufreq_set *setinfo)
{
	int ret = 0;
	struct cndev_ipufreq_set_s freqset;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	freqset.ipu_freq = setinfo->ipu_freq;
	freqset.ctrl_mode = setinfo->ctrl_mode;
	ret = __card_ipufreq_set_ctrl(cndev_set, &freqset);
	if (!ret) {
		mlu590_card_cfg[core->idx].ipu_cfg_recovery = 1;
		memcpy(&mlu590_card_cfg[core->idx].ipu_freq_cfg, setinfo,
			sizeof(struct cndev_ipufreq_set_s));
	} else {
		cn_dev_cndev_err(cndev_set, "Set IPU freq failed");
		freqset.ipu_freq = 0;
		freqset.ctrl_mode = 3;
		__card_ipufreq_set_ctrl(cndev_set, &freqset);
		return ret;
	}

	return 0;
}

int cndev_card_get_retire_pages_mlu590(void *cset,
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

	if (cn_core_is_vf(core) || cn_is_mim_en(core)) {
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

int cndev_card_get_retire_status_mlu590(void *cset,
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

	if (cn_core_is_vf(core) || cn_is_mim_en(core)) {
		retire_status->is_pending = 0;
		retire_status->is_failure = 0;
		return 0;
	} else {
		result = cn_mcc_get_retire_pages_pending_status(core,
			&retire_status->is_pending, &retire_status->is_failure);
	}

	return result;
}

int cndev_card_get_retire_remapped_rows_mlu590(void *cset,
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

	result = cn_mcc_get_remapped_rows(core, &retire_remapped_rows->corr_rows,
		&retire_remapped_rows->unc_rows, &retire_remapped_rows->pending_rows,
		&retire_remapped_rows->fail_rows);

	return result;
}

int cndev_card_retire_switch_mlu590(void *cset,
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

int cndev_card_set_feature_mlu590(void *cset, struct cndev_feature *info)
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

int cndev_card_get_feature_mlu590(void *cset, struct cndev_feature *info)
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

int cndev_chassis_info_mlu590(void *cset, struct cndev_chassis_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	struct cndev_head head = {0};
	struct chassis_info *chassis_info = NULL;
	void *rpc_buf = NULL;
	struct cn_core_set *core = NULL;
	u32 size = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	memcpy(&head, &info->head, sizeof(struct cndev_head));

	info->head.version = CNDEV_CURRENT_VER;
	info->head.real_size = sizeof(struct cndev_chassis_info);
	info->head.buf_size = head.buf_size;
	info->head.card = head.card;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	rpc_buf = cn_kzalloc(1024 * sizeof(u8), GFP_KERNEL);
	if (!rpc_buf) {
		return -ENOMEM;
	}

	chassis_info = cn_kzalloc(sizeof(struct chassis_info), GFP_KERNEL);
	if (!chassis_info) {
		ret = -ENOMEM;
		goto no_mem_chassis;
	}

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_chassis_info",
			NULL, 0, (void *)chassis_info, &result_len, sizeof(struct chassis_info));
	if (ret < 0) {
		cn_dev_core_info(core, "call rpc_cndev_chassis_info failed");
		goto out;
	}

	if (chassis_info->info_ready & CHASSIS_SN_READY) {
		memcpy((void *)&info->chassis_sn,
			chassis_info->chassis_sn, CHASSIS_SN_BYTES);
		info->info_ready |= CHASSIS_SN_READY;
	}

	if (chassis_info->info_ready & CHASSIS_PRODUCT_DATE_READY) {
		memcpy((void *)&info->chassis_product_date,
			chassis_info->chassis_product_date, CHASSIS_PRODUCT_DATE_BYTES);
		info->info_ready |= CHASSIS_PRODUCT_DATE_READY;
	}

	if (chassis_info->info_ready & CHASSIS_PART_NUM_READY) {
		memset(info->chassis_part_num, 0x0, CHASSIS_PART_NUMBER_BYTES);
		size = info->chassis_part_name_size > MLU500_CHASSIS_PART_NAME_BYTES_MAX ?
			MLU500_CHASSIS_PART_NAME_BYTES_MAX : info->chassis_part_name_size;
		if (copy_to_user(info->chassis_part_name,
				chassis_info->chassis_part_num, size)) {
			cn_dev_core_info(core, "copy to usr failed!, ret = %d", ret);
			ret =  -EFAULT;
			goto out;
		}
		info->info_ready |= CHASSIS_PART_NUM_READY;
		info->chassis_part_name_size = size;
	}

	if (chassis_info->info_ready & CHASSIS_VENDOR_NAME_READY) {
		memcpy(info->chassis_vendor_name,
			chassis_info->chassis_vendor_name, CHASSIS_VENDOR_NAME_BYTES);
		info->info_ready |= CHASSIS_VENDOR_NAME_READY;
	}

	memset(info->nvme_info, 0x0,
		sizeof(struct cndev_nvme_ssd_info) * NVME_SSD_COUNT);

	size = sizeof(struct cndev_nvme_ssd_info) * MLU590_NVME_SSD_COUNT;
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_nvme_info",
		NULL, 0, (void *)rpc_buf, &result_len, size);
	if (ret < 0) {
		cn_dev_core_info(core, "call rpc_cndev_nvme_info failed");
		goto out;
	}
	ret = cndev_cp_less_val(
		&info->nvme_ssd_num, MLU590_NVME_SSD_COUNT,
		info->p_nvme_info, rpc_buf, sizeof(struct cndev_nvme_ssd_info));
	info->nvme_ssd_num = MLU590_NVME_SSD_COUNT;
	if (ret < 0) {
		cn_dev_core_err_limit(core, "nvme info cndev copy to usr failed");
		goto out;
	}

	memset(info->psu_info, 0x0,
		sizeof(struct cndev_psu_info) * PSU_COUNT);

	size = sizeof(struct cndev_psu_info) * MLU590_PSU_COUNT;
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_psu_info",
		NULL, 0, (void *)rpc_buf, &result_len, size);
	if (ret < 0) {
		cn_dev_core_info(core, "call rpc_cndev_psu_info failed");
		goto out;
	}

	if (info->p_psu_info) {
		ret = cndev_cp_less_val(
			&info->psu_num, MLU590_PSU_COUNT,
			info->p_psu_info, rpc_buf, sizeof(struct cndev_psu_info));
		info->psu_num = MLU590_PSU_COUNT;
		if (ret < 0) {
			cn_dev_core_err_limit(core, "psu info cndev copy to usr failed");
			goto out;
		}
	}

	memset(info->ib_info, 0x0,
		sizeof(struct cndev_ib_info) * IB_BOARD_COUNT);

	size = sizeof(struct cndev_ib_info_v5) * MLU590_IB_BOARD_COUNT;
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_ib_info",
		NULL, 0, (void *)rpc_buf, &result_len, size);
	if (ret < 0) {
		cn_dev_core_info(core, "call rpc_cndev_ib_info failed");
		goto out;
	}
	if (info->p_ib_info) {
		ret = cndev_cp_less_val(
			&info->ib_board_num, MLU590_IB_BOARD_COUNT,
			info->p_ib_info, rpc_buf, sizeof(struct cndev_ib_info_v5));
		info->ib_board_num = MLU590_IB_BOARD_COUNT;
		if (ret < 0) {
			cn_dev_core_err_limit(core, "ib info cndev copy to usr failed");
			goto out;
		}
	}

out:
	if (chassis_info)
		cn_kfree(chassis_info);

	if (rpc_buf)
		cn_kfree(rpc_buf);

	return ret;

no_mem_chassis:
	if (rpc_buf)
		cn_kfree(rpc_buf);

	return ret;
}

int cndev_chassis_power_info_mlu590(void *cset, struct cndev_chassis_power_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	struct cndev_head head = {0};
	struct cn_core_set *core = NULL;
	int copy_length = 0;
	struct chassis_runtime_info_s *chassis_rt_info = NULL;
	char chassis_temp[MLU590_CHASSIS_TEMP_COUNT] = {0};

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	memcpy(&head, &info->head, sizeof(struct cndev_head));

	info->head.version = CNDEV_CURRENT_VER;
	info->head.real_size = sizeof(struct cndev_chassis_power_info);
	info->head.buf_size = head.buf_size;
	info->head.card = head.card;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	copy_length = sizeof(struct chassis_runtime_info_s) +
		sizeof(u16) * MLU590_FAN_COUNT;
	chassis_rt_info = cn_kzalloc(copy_length, GFP_KERNEL);
	if (!chassis_rt_info) {
		cn_dev_core_err(core, "alloc buf fail");
		ret = -ENOMEM;
		goto PIERR;
	}
	chassis_rt_info->fan_num = MLU590_FAN_COUNT;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_fan_info",
			NULL, 0, (void *)chassis_rt_info, &result_len, copy_length);
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
		goto RT_ERR;
	}

	info->chassis_power = chassis_rt_info->machine_power;

	copy_length =
		(info->chassis_fan_num < chassis_rt_info->fan_num)
		? info->chassis_fan_num : chassis_rt_info->fan_num;
	/*send user how many MLU590 FAN we can send*/
	info->chassis_fan_num = chassis_rt_info->fan_num;

	/*copy shorter length of FAN to user*/
	if (info->chassis_fan) {
		ret = cndev_cp_to_usr(info->chassis_fan, chassis_rt_info->fan,
			copy_length * sizeof(u16));
		if (ret) {
			goto RT_ERR;
		}
	}

	chassis_temp[0] = chassis_rt_info->machine_in_fan;
	chassis_temp[1] = chassis_rt_info->machine_out_fan;
	info->chassis_temperature_num = MLU590_CHASSIS_TEMP_COUNT;

	/*send user how many temperature we can send*/
	/*copy shorter length of temp to user*/
	ret = cndev_cp_less_val(
			&info->chassis_temperature_num, MLU590_CHASSIS_TEMP_COUNT,
			info->chassis_temp, chassis_temp, sizeof(s8));

RT_ERR:
	cn_kfree(chassis_rt_info);

PIERR:
	return ret;
}

static const struct cn_cndev_ioctl cndev_mlu590_ioctl = {
	.card_info_fill = card_info_fill_mlu590,
	.card_power_info = card_power_info_mlu590,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = card_ecc_info_common,
	.card_vm_info = card_vm_info_mlu590,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = cndev_card_codecutil_info_common,
	.card_freq_info = cndev_card_freq_info_mlu590,
	.card_curbuslnk = cndev_card_curbuslnk_common,
	.card_pciethroughput = cndev_card_pciethroughput_common,
	.card_power_capping = cndev_card_powercapping_mlu590,
	.card_ipufreq_set = card_ipufreq_set_mlu590,
	.card_ncs_version = card_ncs_version_common,
	.card_ncs_state = card_ncs_state_common,
	.card_ncs_speed = card_ncs_speed_common,
	.card_ncs_capability = card_ncs_capability_common,
	.card_ncs_counter = card_ncs_counter_common,
	.card_ncs_remote = card_ncs_remote_common,
	.card_reset_ncs_counter = card_ncs_reset_cntr_common,
	.card_chassis_info = cndev_chassis_info_mlu590,
	.card_qos_reset = NULL,
	.card_qos_info = NULL,
	.card_qos_desc = NULL,
	.card_set_qos = NULL,
	.card_set_qos_group = NULL,
	.card_acpuutil_info = cndev_card_acpuutil_info_common,
	.card_acpuutil_timer = cndev_card_acpuutil_timer_common,
	.card_get_retire_pages = cndev_card_get_retire_pages_mlu590,
	.card_get_retire_status = cndev_card_get_retire_status_mlu590,
	.card_get_retire_remapped_rows = cndev_card_get_retire_remapped_rows_mlu590,
	.card_retire_switch = cndev_card_retire_switch_mlu590,
	.card_ncs_port_config = card_ncs_port_config_common,
	.card_mlulink_switch_ctrl = card_mlulink_switch_ctrl_common,
	.card_ipufreq_ctrl = card_ipufreq_ctrl_mlu590,
	.card_get_ncs_info = card_get_ncs_info_common,
	.card_get_card_info_ext = cndev_card_card_info_ext,
	.card_get_process_iputil = cndev_get_process_ipuutil_common,
	.card_get_process_codecutil = cndev_get_process_codecutil_common,
	.card_get_feature = cndev_card_get_feature_mlu590,
	.card_set_feature = cndev_card_set_feature_mlu590,
	.card_get_mim_profile_info = cndev_card_get_mim_profile_info_common,
	.card_get_mim_possible_place_info = cndev_card_get_mim_possible_place_info_common,
	.card_get_mim_vmlu_capacity_info = cndev_card_get_mim_vmlu_capacity_info_common,
	.card_get_mim_device_info = cndev_card_get_mim_device_info_common,
	.card_get_desc_info = cndev_card_get_desc_common,
	.card_get_cntr_info = cndev_card_get_cntr_info_common,
	.chassis_power_info = cndev_chassis_power_info_mlu590,
	.card_get_smlu_profile_id = cndev_card_get_smlu_profile_id_common,
	.card_get_smlu_profile_info = cndev_card_get_smlu_profile_info_common,
	.card_new_smlu_profile = cndev_card_new_smlu_profile_common,
	.card_delete_smlu_profile = cndev_card_delete_smlu_profile_common,
};

static const struct cn_cndev_ops cndev_mlu590_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_mlu590_pf,
	.cndev_restart = cndev_restart_mlu590,
	.cndev_stop = cndev_stop_mlu590,
	.cndev_exit = cndev_exit_mlu590,
};

static const struct cn_cndev_ioctl cndev_mlu590_vf_ioctl = {
	.card_info_fill = card_info_fill_vf_common,
	.card_power_info = card_power_info_vf_common,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_mlu500_vf,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = card_ecc_info_vf_common,
	.card_vm_info = card_vm_info_mlu590,
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
	.card_delete_smlu_profile = cndev_card_delete_smlu_profile_common,
};

static const struct cn_cndev_ops cndev_mlu590_vf_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_mlu590,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_mlu590,
	.cndev_exit = cndev_exit_mlu590,
};

int cndev_init_mlu590(struct cn_cndev_set *cndev_set)
{

	switch (cndev_set->device_id) {
	case MLUID_590:
		cndev_set->ops = &cndev_mlu590_ops;
		cndev_set->ioctl = &cndev_mlu590_ioctl;
		/* Timer 500ms */
		cndev_set->mcuinfo_time_delay = ktime_set(0, 500 * 1000 * 1000);
		hrtimer_init(&cndev_set->mcuinfo_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		cndev_set->mcuinfo_hrtimer.function = mlu590_cndev_mcuinfo_work_hrtimer;
		cndev_init_codec_process_util(cndev_set);
		break;
	case MLUID_590V:
	case MLUID_590_DEV:
		cndev_set->ops = &cndev_mlu590_vf_ops;
		cndev_set->ioctl = &cndev_mlu590_vf_ioctl;
		break;
	}

	cndev_common_init(cndev_set);

	return 0;
}
