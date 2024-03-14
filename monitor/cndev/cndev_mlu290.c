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

int cndev_chassis_info_mlu290(void *cset, struct cndev_chassis_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	struct cndev_head head = {0};
	struct chassis_info remote_chassis_infos = {0};
	struct cndev_nvme_ssd_info nvme_info[NVME_SSD_COUNT];
	struct cndev_psu_info psu_info[PSU_COUNT];
	struct cndev_ib_info ib_info[IB_BOARD_COUNT];
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	memcpy(&head, &info->head, sizeof(struct cndev_head));
	memset(info, 0x00, sizeof(struct cndev_chassis_info));

	info->head.version = CNDEV_CURRENT_VER;
	info->head.real_size = sizeof(struct cndev_chassis_info);
	info->head.buf_size = head.buf_size;
	info->head.card = head.card;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_chassis_info",
			NULL, 0, (void *)&remote_chassis_infos, &result_len, sizeof(struct chassis_info));
	if (ret < 0) {
		pr_err("call rpc_cndev_chassis_info failed");
		return ret;
	}

	if (remote_chassis_infos.info_ready & CHASSIS_SN_READY) {
		memcpy((void *)&info->chassis_sn,
			remote_chassis_infos.chassis_sn, CHASSIS_SN_BYTES);
		info->info_ready |= CHASSIS_SN_READY;
	}

	if (remote_chassis_infos.info_ready & CHASSIS_PRODUCT_DATE_READY) {
		memcpy((void *)&info->chassis_product_date,
			remote_chassis_infos.chassis_product_date, CHASSIS_PRODUCT_DATE_BYTES);
		info->info_ready |= CHASSIS_PRODUCT_DATE_READY;
	}

	if (remote_chassis_infos.info_ready & CHASSIS_PART_NUM_READY) {
		memcpy(info->chassis_part_num,
			remote_chassis_infos.chassis_part_num, CHASSIS_PART_NUMBER_BYTES);
		info->info_ready |= CHASSIS_PART_NUM_READY;
	}

	if (remote_chassis_infos.info_ready & CHASSIS_VENDOR_NAME_READY) {
		memcpy(info->chassis_vendor_name,
			remote_chassis_infos.chassis_vendor_name, CHASSIS_VENDOR_NAME_BYTES);
		info->info_ready |= CHASSIS_VENDOR_NAME_READY;
	}

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_nvme_info",
		NULL, 0, (void *)&nvme_info, &result_len, sizeof(struct cndev_nvme_ssd_info));
	if (ret < 0) {
		pr_err("call rpc_cndev_nvme_info failed");
		return ret;
	}
	info->nvme_ssd_num = NVME_SSD_COUNT;
	memcpy(info->nvme_info, nvme_info,
		sizeof(struct cndev_nvme_ssd_info) * NVME_SSD_COUNT);

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_psu_info",
		NULL, 0, (void *)&psu_info, &result_len, sizeof(struct cndev_psu_info));
	if (ret < 0) {
		pr_err("call rpc_cndev_psu_info failed");
		return ret;
	}
	info->psu_num = PSU_COUNT;
	memcpy(info->psu_info, psu_info,
		sizeof(struct cndev_psu_info) * PSU_COUNT);

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_ib_info",
		NULL, 0, (void *)&ib_info, &result_len, sizeof(struct cndev_ib_info));
	if (ret < 0) {
		pr_err("call rpc_cndev_ib_info failed");
		return ret;
	}
	info->ib_board_num = IB_BOARD_COUNT;
	memcpy(info->ib_info, ib_info,
		sizeof(struct cndev_ib_info) * IB_BOARD_COUNT);

	return 0;
}

int card_power_info_mlu290(void *cset,
			struct cndev_power_info *power_info)
{
	int ret = 0;
	struct board_power_info pinfo;
	int copy_length;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core;
	struct cn_board_info *pbrdinfo;
	int result_len = 0;
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
	power_info->power_usage_decimal = pinfo.board_power_decimal;
	power_info->max_power_decimal = 0;
	power_info->fan_speed = pinfo.fan_speed;
	power_info->machine_power = pinfo.machine_power;
	power_info->min_power_cap = pbrdinfo->min_power_cap;
	power_info->min_power_cap_decimal = pbrdinfo->min_power_cap_dec;
	power_info->max_power_cap_decimal = pbrdinfo->max_power_cap_dec;
	power_info->perf_limit_num = 0;
	power_info->edpp_count = 0;
	power_info->tdp_freq_capping_count = 0;

	/* mlu290 set tdp equal peak powerf */
	power_info->tdp = pbrdinfo->peak_power;
	power_info->ipu_cluster_freq_num = 0;
	power_info->instantaneous_power = power_info->power_usage;
	power_info->instantaneous_power_decimal = power_info->power_usage_decimal;
	power_info->ipu_cluster_mask = 0;

	copy_length =
		(power_info->temperature_num < pinfo.temperature_num)
		? power_info->temperature_num : pinfo.temperature_num;
	/*send user how many temperature we can send*/
	power_info->temperature_num = pinfo.temperature_num;
	/*copy shorter length of temp to user*/
	if (power_info->temp) {
		ret = cndev_cp_to_usr(power_info->temp, pinfo.temp,
			copy_length * sizeof(s8));
	}
	/*free temp buf in power_info struct which alloced in mcu function.*/
	cn_kfree(pinfo.temp);

	if (power_info->ignore_chassis_power_info) {
		cn_dev_cndev_debug(cndev_set, "ingore chassis info");
		power_info->fan_num = 0;
		goto PIERR;
	}

	copy_length = sizeof(struct chassis_runtime_info_s) +
		sizeof(u16) * FAN_SPEED;
	chassis_rt_info = cn_kzalloc(copy_length, GFP_KERNEL);
	if (!chassis_rt_info) {
		cn_dev_core_err(core, "alloc buf fail");
		ret = -ENOMEM;
		goto PIERR;
	}
	chassis_rt_info->fan_num = FAN_SPEED;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_fan_info",
				NULL, 0, (void *)chassis_rt_info, &result_len, copy_length);
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
		goto RT_ERR;
	}

	copy_length =
		(power_info->fan_num < chassis_rt_info->fan_num)
		? power_info->fan_num : chassis_rt_info->fan_num;
	/*send user how many MLU290 FAN we can send*/
	power_info->fan_num = chassis_rt_info->fan_num;

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
	return ret;
}

int chassis_power_info_mlu290(void *cset,
	struct cndev_chassis_power_info *info)
{
	int ret = 0;
	struct board_power_info pinfo;
	int copy_length = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct cn_board_info *pbrdinfo = NULL;
	int result_len = 0;
	struct chassis_runtime_info_s *chassis_rt_info = NULL;
	char chassis_temp[MLU290_CHASSIS_TEMP_COUNT] = {0};

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	pbrdinfo = &core->board_info;

	info->head.version = CNDEV_CURRENT_VER;
	info->head.real_size = sizeof(struct cndev_chassis_power_info);

	ret = cndrv_mcu_read_power_info(core, &pinfo);
	if (ret) {
		return ret;
	}

	info->chassis_power = pinfo.machine_power;

	copy_length =
		(info->chassis_temperature_num < pinfo.temperature_num)
		? info->chassis_temperature_num : pinfo.temperature_num;
	/*send user how many temperature we can send*/
	info->chassis_temperature_num = pinfo.temperature_num;
	/*copy shorter length of temp to user*/
	if (info->chassis_temp) {
		ret = cndev_cp_to_usr(info->chassis_temp, pinfo.temp,
			copy_length * sizeof(s8));
		if (ret) {
			cn_kfree(pinfo.temp);
			cn_dev_core_err(core, "copy to user failed");
			goto PIERR;
		}
	}

	chassis_temp[0] = pinfo.temp[6];
	chassis_temp[1] = pinfo.temp[7];
	info->chassis_temperature_num = MLU590_CHASSIS_TEMP_COUNT;

	/*free temp buf in info struct which alloced in mcu function.*/
	cn_kfree(pinfo.temp);

	copy_length = sizeof(struct chassis_runtime_info_s) +
		sizeof(u16) * FAN_SPEED;
	chassis_rt_info = cn_kzalloc(copy_length, GFP_KERNEL);
	if (!chassis_rt_info) {
		cn_dev_core_err(core, "alloc buf fail");
		ret = -ENOMEM;
		goto PIERR;
	}
	chassis_rt_info->fan_num = FAN_SPEED;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_fan_info",
		NULL, 0, (void *)chassis_rt_info, &result_len, copy_length);
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
		goto RT_ERR;
	}

	info->chassis_power = pinfo.machine_power;

	copy_length =
		(info->chassis_fan_num < chassis_rt_info->fan_num)
		? info->chassis_fan_num : chassis_rt_info->fan_num;
	/*send user how many MLU290 FAN we can send*/
	info->chassis_fan_num = chassis_rt_info->fan_num;

	/*copy shorter length of FAN to user*/
	if (info->chassis_fan) {
		ret = cndev_cp_to_usr(info->chassis_fan, chassis_rt_info->fan,
			copy_length * sizeof(u16));
		if (ret) {
			goto RT_ERR;
		}
	}

	/*send user how many temperature we can send*/
	/*copy shorter length of temp to user*/
	ret = cndev_cp_less_val(
			&info->chassis_temperature_num, MLU290_CHASSIS_TEMP_COUNT,
			info->chassis_temp, chassis_temp, sizeof(s8));

RT_ERR:
	cn_kfree(chassis_rt_info);

PIERR:
	return ret;
}

int card_ecc_info_mlu290(void *cset,
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
		cn_dev_cndev_err(cndev_set, "get ecc ptr err");
		ret = -EINVAL;
		goto out;
	}
	up_read(&core->mcc_state_sem);

	for (i = 0; i < mcc_channel_num; i++) {
		einfo->single_biterr +=
			card_ecc_info[i].one_bit_ecc_error;
		einfo->multi_biterr +=
			card_ecc_info[i].multiple_one_bit_ecc_error;
	}

	einfo->total_err = einfo->single_biterr + einfo->multi_biterr;

	return 0;

out:
	up_read(&core->mcc_state_sem);
	return ret;
}

int card_vm_info_mlu290(void *cset,
	struct cndev_vm_info *vinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret = 0;
	u16 vf_num = 0, vf_mask = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	vinfo->head.version = CNDEV_CURRENT_VER;
	vinfo->head.real_size = sizeof(struct cndev_vm_info);

	if (cndev_set->device_id == MLUID_290) {
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


int card_ncs_version_mlu290(void *cset,
			struct cndev_NCS_version *verinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	u32 link = 0;
	struct NCS_basic_info_s rpc_info = {0};
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(verinfo))
		return -EINVAL;

	verinfo->head.version = CNDEV_CURRENT_VER;
	verinfo->head.real_size = sizeof(struct cndev_NCS_version);

	link = verinfo->link;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_get_cclink_basic_info",
			(void *)&link, sizeof(u32),
			(void *)&rpc_info, &result_len, sizeof(struct NCS_basic_info_s));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_get_cclink_basic_info ret:%d result_len:%d"
			, ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	verinfo->build_version = rpc_info.build_version;
	verinfo->minor_version = rpc_info.minor_version;
	verinfo->major_version = rpc_info.major_version;

	return 0;
}

int card_ncs_state_mlu290(void *cset,
						struct cndev_NCS_state_info *stinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	u32 link = 0;
	__s32 link_state = 0;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(stinfo))
		return -EINVAL;

	stinfo->head.version = CNDEV_CURRENT_VER;
	stinfo->head.real_size = sizeof(struct cndev_NCS_state_info);

	link = stinfo->link;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_get_cclink_state_info",
					(void *)&link, sizeof(u32),
					(void *)&link_state, &result_len, sizeof(__s32));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_get_cclink_state_info ret:%d result_len:%d"
					, ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	stinfo->state = link_state;

	return 0;
}

int card_ncs_speed_mlu290(void *cset,
			struct cndev_NCS_speed_info *stinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	u32 link = 0;
	struct NCS_speed_info_s rpc_info = {0};
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(stinfo))
		return -EINVAL;

	stinfo->head.version = CNDEV_CURRENT_VER;
	stinfo->head.real_size = sizeof(struct cndev_NCS_speed_info);

	link = stinfo->link;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_get_cclink_speed_info",
			(void *)&link, sizeof(u32),
			(void *)&rpc_info, &result_len, sizeof(struct NCS_speed_info_s));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_get_cclink_speed_info ret:%d result_len:%d"
			, ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	stinfo->speed = rpc_info.speed;
	stinfo->speed_fmt = rpc_info.speed_fmt;
	ret = rpc_info.ret;

	return ret;
}

int card_ncs_capability_mlu290(void *cset,
			struct cndev_NCS_capability *capinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	u32 link = 0;
	struct NCS_capability_info_s rpc_info = {0};
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(capinfo))
		return -EINVAL;

	capinfo->head.version = CNDEV_CURRENT_VER;
	capinfo->head.real_size = sizeof(struct cndev_NCS_capability);

	link = capinfo->link;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_get_cclink_capability_info",
			(void *)&link, sizeof(u32),
			(void *)&rpc_info, &result_len, sizeof(struct NCS_capability_info_s));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_get_cclink_capability_info ret:%d result_len:%d"
			, ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	capinfo->cap_ilkn_fec = rpc_info.cap_ilkn_fec;
	capinfo->cap_p2p_tsf = rpc_info.cap_p2p_tsf;
	return 0;
}

int cndev_card_freq_info_mlu290(void *cset,
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

	ret = cndrv_mcu_read_ddr_freq(cndev_set->core, &finfo->ddr_freq);
	pbrdinfo->ddr_speed = finfo->ddr_freq;
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

int card_ncs_reset_cntr_mlu290(void *cset,
			struct cndev_NCS_reset_counter *rstinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	int res = 0;
	struct NCS_reset_counter_s rpc_info = {0};
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(rstinfo))
		return -EINVAL;

	rstinfo->head.version = CNDEV_CURRENT_VER;
	rstinfo->head.real_size = sizeof(struct cndev_NCS_reset_counter);

	rpc_info.link = rstinfo->link;
	rpc_info.cntr = rstinfo->cntr;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_reset_cclink_counter",
			(void *)&rpc_info, sizeof(struct NCS_reset_counter_s),
			&res, &result_len, sizeof(int));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_reset_cclink_counter ret:%d result_len:%d"
			, ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	return res;
}


static enum hrtimer_restart cndev_mcuinfo_work_hrtimer(struct hrtimer *timer)
{
	struct cn_cndev_set *cndev_set = NULL;
	struct cn_core_set *core = NULL;
	struct dma_info_s dma_info;
	struct ecc_info_t *card_ecc_info = NULL;
	u32 reg32 = 0;
	int i = 0;
	u64 single_biterr = 0;
	u64 multi_biterr = 0;
	int channel = 0;
	int ret = 0;

	cndev_set = container_of(timer, struct cn_cndev_set, mcuinfo_hrtimer);

	if (IS_ERR_OR_NULL(cndev_set))
		goto timer_err;
	if (IS_ERR_OR_NULL(cndev_set->core))
		goto out;

	core = cndev_set->core;

	ret = cndrv_print_overtemp_freq_warning(core);
	if (ret) {
		goto out;
	}

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

	if (!cndev_set->host_info_flush_done) {
		reg32 = cndev_set->card_static_info.func & 0xffff;
		reg32 |= cndev_set->card_static_info.domain << 16;
		cn_mcu_write32(core, IPC20, reg32);

		reg32 = cndev_set->card_static_info.bus & 0xffff;
		reg32 |= (cndev_set->card_static_info.device  & 0xffff) << 16;
		cn_mcu_write32(core, IPC21, reg32);

		reg32 = DRV_MINOR;
		reg32 |= DRV_MAJOR << 16;
		cn_mcu_write32(core, IPC28, reg32);

		cndev_set->host_info_flush_done = 1;
	}

	reg32 = cndev_set->pcie_throughput_to_mcu.write_data / 1024 / 1024;
	reg32 |= (cndev_set->pcie_throughput_to_mcu.read_data  / 1024 / 1024) << 16;
	cn_mcu_write32(core, IPC22, reg32);

	channel = cn_mcc_get_channel_num(core);
	if (channel < 0) {
		cn_dev_cndev_err(cndev_set, "get channel err");
		goto out;
	}

	card_ecc_info =	(struct ecc_info_t *)cn_mcc_get_ecc_status(core);
	if (IS_ERR_OR_NULL(card_ecc_info)) {
		cn_dev_cndev_err(cndev_set, "get ecc ptr err");
		goto out;
	}

	for (i = 0; i < channel; i++) {
		single_biterr += card_ecc_info[i].one_bit_ecc_error;
		multi_biterr += card_ecc_info[i].multiple_one_bit_ecc_error;
	}

	reg32 = (u16)(multi_biterr & 0xffff);
	reg32 |= (u16)(single_biterr & 0xffff) << 16;
	cn_mcu_write32(core, IPC16, reg32);

out:
	hrtimer_forward_now(timer, cndev_set->mcuinfo_time_delay);
	return HRTIMER_RESTART;
timer_err:
	return HRTIMER_NORESTART;
}

void cndev_exit_mlu290(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *pcore = NULL;

	if (!cndev_set) {
		return;
	}

	pcore = cndev_set->core;

	hrtimer_cancel(&cndev_set->hrtimer);

	if (cndev_set && cndev_set->device_id != MLUID_290V1) {
		hrtimer_cancel(&cndev_set->mcuinfo_hrtimer);
	}

	if (cndev_set->endpoint) {
		__pmu_disconnect(cndev_set->endpoint, pcore);
		cndev_set->endpoint = NULL;
	}

	cndev_set->ops = NULL;
}

int cndev_lateinit_mlu290_vf(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;
	int ret = 0;

	if (cndev_set->device_id != MLUID_290V1) {
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

	ret = cndev_start_common(cndev_set);
	if (ret) {
		cn_dev_cndev_err(cndev_set, "cndev rpc start cndev failed");
	}

out:
	return ret;
}

int cndev_lateinit_mlu290(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;
	int ret = 0;

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

	if (cndev_set->device_id != MLUID_290V1) {

		hrtimer_start(&cndev_set->mcuinfo_hrtimer, cndev_set->mcuinfo_time_delay,
				HRTIMER_MODE_REL);

		ret = cndev_rpc_lateinit(cndev_set);
		if (ret) {
			cn_dev_cndev_err(cndev_set, "cndev rpc lateinit failed");
			goto out;
		}

		ret = cndev_start_common(cndev_set);
		if (ret) {
			cn_dev_cndev_err(cndev_set, "cndev rpc start cndev failed");
		}
	}

out:
	return ret;
}

void cndev_stop_mlu290(void *cset)
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
	if (cndev_set->device_id != MLUID_290V1) {
		hrtimer_cancel(&cndev_set->mcuinfo_hrtimer);
	}
}

static const struct cn_cndev_ioctl cndev_mlu290_ioctl = {
	.card_info_fill = card_info_fill_common,
	.card_power_info = card_power_info_mlu290,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = card_ecc_info_mlu290,
	.card_vm_info = card_vm_info_mlu290,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = cndev_card_codecutil_info_common,
	.card_freq_info = cndev_card_freq_info_mlu290,
	.card_curbuslnk = cndev_card_curbuslnk_common,
	.card_pciethroughput = cndev_card_pciethroughput_common,
	.card_power_capping = cndev_card_powercapping_common,
	.card_ipufreq_set = NULL,
	.card_ncs_version = card_ncs_version_common,
	.card_ncs_state = card_ncs_state_common,
	.card_ncs_speed = card_ncs_speed_common,
	.card_ncs_capability = card_ncs_capability_common,
	.card_ncs_counter = card_ncs_counter_common,
	.card_ncs_remote = card_ncs_remote_common,
	.card_reset_ncs_counter = card_ncs_reset_cntr_common,
	.card_chassis_info = cndev_chassis_info_mlu290,
	.card_qos_reset = cndev_qos_reset_common,
	.card_qos_info = cndev_qos_policy_common,
	.card_qos_desc = cndev_qos_desc_common,
	.card_set_qos = cndev_set_qos_policy,
	.card_set_qos_group = cndev_set_qos_group_policy,
	.card_acpuutil_info = cndev_card_acpuutil_info_common,
	.card_acpuutil_timer = cndev_card_acpuutil_timer_common,
	.card_get_retire_pages = cndev_card_get_retire_pages,
	.card_get_retire_status = cndev_card_get_retire_status,
	.card_get_retire_remapped_rows = cndev_card_get_retire_remapped_rows,
	.card_retire_switch = cndev_card_retire_switch,
	.card_ncs_port_config = card_ncs_port_config_common,
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
	.chassis_power_info = chassis_power_info_mlu290,
	.card_get_smlu_profile_id = NULL,
	.card_get_smlu_profile_info = NULL,
	.card_new_smlu_profile = NULL,
	.card_delete_smlu_profile = NULL,
};

static const struct cn_cndev_ops cndev_mlu290_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_mlu290,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_mlu290,
	.cndev_exit = cndev_exit_mlu290,
};

static const struct cn_cndev_ioctl cndev_mlu290_vf_ioctl = {
	.card_info_fill = card_info_fill_vf_common,
	.card_power_info = card_power_info_vf_common,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = NULL,
	.card_vm_info = card_vm_info_mlu290,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = NULL,
	/*not support in vf*/
	.card_freq_info = NULL,
	.card_curbuslnk = NULL,
	.card_pciethroughput = cndev_card_pciethroughput_common,
	.card_power_capping = NULL,
	.card_ipufreq_set = NULL,
	.card_ncs_version = card_ncs_version_common,
	.card_ncs_state = card_ncs_state_common,
	.card_ncs_speed = card_ncs_speed_common,
	.card_ncs_capability = card_ncs_capability_common,
	.card_ncs_counter = card_ncs_counter_common,
	.card_ncs_remote = card_ncs_remote_common,
	.card_reset_ncs_counter = card_ncs_reset_cntr_common,
	.card_chassis_info = cndev_chassis_info_mlu290,
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
	.card_ncs_port_config = card_ncs_port_config_common,
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

static const struct cn_cndev_ops cndev_mlu290_vf_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_mlu290_vf,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_mlu290,
	.cndev_exit = cndev_exit_mlu290,
};

int cndev_init_mlu290(struct cn_cndev_set *cndev_set)
{

	switch (cndev_set->device_id) {
	case MLUID_290:
		cndev_set->ops = &cndev_mlu290_ops;
		cndev_set->ioctl = &cndev_mlu290_ioctl;
		//500 * 1000 * 1000
		cndev_set->mcuinfo_time_delay = ktime_set(0, 500 * 1000 * 1000);
		hrtimer_init(&cndev_set->mcuinfo_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		cndev_set->mcuinfo_hrtimer.function = cndev_mcuinfo_work_hrtimer;
		break;
	case MLUID_290V1:
		cndev_set->ops = &cndev_mlu290_vf_ops;
		cndev_set->ioctl = &cndev_mlu290_vf_ioctl;
		break;
	}

	cndev_common_init(cndev_set);


	return 0;
}
