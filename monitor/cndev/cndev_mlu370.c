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

int card_power_info_mlu370(void *cset,
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

	if (cndev_set->card_static_info.chip_id) {
		power_info->max_power = pbrdinfo->peak_power;
	} else {
		power_info->max_power = pinfo.peak_power ?
			pinfo.peak_power : pbrdinfo->peak_power;
	}
	power_info->power_usage = pinfo.board_power;
	power_info->power_usage_decimal = 0;
	power_info->max_power_decimal = pinfo.max_power_decimal;
	power_info->fan_speed = pinfo.fan_speed;
	power_info->machine_power = pinfo.machine_power;
	power_info->min_power_cap = pbrdinfo->min_power_cap;
	power_info->min_power_cap_decimal = pbrdinfo->min_power_cap_dec;
	power_info->max_power_cap_decimal = pbrdinfo->max_power_cap_dec;
	power_info->perf_limit_num = 0;
	power_info->edpp_count = 0;
	power_info->tdp_freq_capping_count = 0;

	/* mlu370 set tdp */
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
			cn_dev_monitor_err(cndev_set, "pmu rpc call failed, ret = %d", ret);
			goto PIERR;
		}

		power_info->power_usage = vf_pinfo->power_usage;
		power_info->max_power = vf_pinfo->max_power;
		power_info->fan_speed = vf_pinfo->fan_speed;
		cn_kfree(vf_pinfo);
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

	power_info->machine_power = chassis_rt_info->machine_power;
	pinfo.temp[3] = chassis_rt_info->machine_in_fan;
	pinfo.temp[4] = chassis_rt_info->machine_out_fan;
	pinfo.temperature_num += 2;

	copy_length =
		(power_info->fan_num < chassis_rt_info->fan_num)
		? power_info->fan_num : chassis_rt_info->fan_num;
	/*send user how many ML370 FAN we can send*/
	power_info->fan_num = chassis_rt_info->fan_num;

	/*send user how many temperature we can send*/
	/*copy shorter length of temp to user*/
	ret = cndev_cp_less_val(
			&power_info->temperature_num, pinfo.temperature_num,
			power_info->temp, pinfo.temp, sizeof(s8));
	if (ret) {
		goto PIERR;
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
	cn_kfree(pinfo.temp);
	return ret;
}

int cndev_card_freq_info_mlu370(void *cset,
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

int card_ipufreq_set_mlu370(void *cset,
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

int card_vm_info_mlu370(void *cset,
	struct cndev_vm_info *vinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core;
	int ret;
	u16 vf_num, vf_mask;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	core = (struct cn_core_set *)cndev_set->core;

	vinfo->head.version = CNDEV_CURRENT_VER;
	vinfo->head.real_size = sizeof(struct cndev_vm_info);

	if (cndev_set->device_id == MLUID_370) {
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

static enum hrtimer_restart mlu370_cndev_mcuinfo_work_hrtimer(struct hrtimer *timer)
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

	cn_mcu_write32(core, IPC_21, reg32);

out:
	hrtimer_forward_now(timer, cndev_set->mcuinfo_time_delay);
	return HRTIMER_RESTART;
timer_err:
	return HRTIMER_NORESTART;
}

int card_ipufreq_ctrl_mlu370(void *cset, struct cndev_ipufreq_ctrl *ipufreq_ctrl)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u32 reg32 = 0;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	core = cndev_set->core;

	if (IS_ERR_OR_NULL(ipufreq_ctrl))
		return -EINVAL;

	ipufreq_ctrl->head.version = CNDEV_CURRENT_VER;
	ipufreq_ctrl->head.real_size = sizeof(struct cndev_ipufreq_ctrl);

	switch (ipufreq_ctrl->ops_type) {
	case 0:
		reg32 = cn_mcu_read32(core, IPC_23);
		ipufreq_ctrl->ipufreq_lock_status = (reg32 >> 31) & 0x1;
		break;
	case 1:
		reg32 = cn_mcu_read32(core, IPC_23);
		reg32 &= ~(1 << 31);
		cn_mcu_write32(core, IPC_23, reg32);
		break;
	default:
		cn_xid_err(core, XID_SW_NOTIFY_ERR,
			"cndev ipufreq ctrl not support %u", ipufreq_ctrl->ops_type);
		return -EPERM;
	}

	return 0;
}

int cndev_card_powercapping_mlu370(void *cset,
	struct cndev_powercapping_s *pcinfo)
{
	struct power_capping_info *mcu_param;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u16 vcard;
	struct cn_core_set *core = NULL;

	vcard = (pcinfo->head.card >> 8) & 0x0f;
	if (vcard)
		return -ENODEV;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	pcinfo->head.version = CNDEV_CURRENT_VER;
	pcinfo->head.real_size = sizeof(struct cndev_powercapping_s);

	if (cndev_set->card_static_info.chip_id) {
		core = cndev_set->core;
		cn_xid_err(core, XID_SW_NOTIFY_ERR,
			"Chip 1 not support setting the power capping");
		return -EPERM;
	}
	mcu_param = (struct power_capping_info *)&pcinfo->ops_type;

	return cndrv_mcu_power_capping(cndev_set->core, mcu_param);
}

int card_ecc_info_mlu370(void *cset,
	struct cndev_ecc_info *einfo)
{
	int mcc_channel_num = 0;
	int d2dc_num = 0, i = 0;
	struct die2die_crc_info_t  *card_d2dc_info = NULL;
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
	einfo->addr_forbidden_err = 0;
	einfo->inline_ecc_support = core->ile_en;

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

	for (i = 0; i < mcc_channel_num; i++) {
		einfo->single_biterr +=
			card_ecc_info[i].one_bit_ecc_error;
		einfo->multi_biterr +=
			card_ecc_info[i].multiple_one_bit_ecc_error;
		einfo->addr_forbidden_err += card_ecc_info[i].addr_forbidden_error;
	}

	einfo->corrected_err = einfo->single_biterr;
	einfo->uncorrect_err = einfo->multi_biterr;

	einfo->total_err = einfo->corrected_err + einfo->uncorrect_err;

	d2dc_num = cn_mcc_get_d2dc_num(core);
	if (d2dc_num < 0) {
		ret = -EINVAL;
		goto out;
	}

	card_d2dc_info =
		(struct die2die_crc_info_t  *)cn_mcc_get_d2dc_status(core);
	if (IS_ERR_OR_NULL(card_d2dc_info)) {
		cn_dev_cndev_err(cndev_set, "get crc ptr err");
		ret = -EINVAL;
		goto out;
	}
	up_read(&core->mcc_state_sem);

	for (i = 0; i < d2dc_num; i++) {
		einfo->die2die_crc_err +=
			card_d2dc_info[i].rx_crc_err;
		einfo->die2die_crc_err +=
			card_d2dc_info[i].rx_arq_crc_err;
		einfo->die2die_crc_err_overflow +=
			card_d2dc_info[i].rx_crc_err_overflow;
		einfo->die2die_crc_err_overflow +=
			card_d2dc_info[i].rx_arq_crc_err_overflow;

		einfo->die2die_crc_err_overflow +=
			card_d2dc_info[i].rx_crc_of;
		einfo->die2die_crc_err_overflow +=
			card_d2dc_info[i].arq_rx_crc_of;
	}

	return 0;

out:
	up_read(&core->mcc_state_sem);
	return ret;
}

int cndev_chassis_info_mlu370(void *cset, struct cndev_chassis_info *info)
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
	u32 size = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	memcpy(&head, &info->head, sizeof(struct cndev_head));

	info->head.version = CNDEV_CURRENT_VER;
	info->head.real_size = sizeof(struct cndev_chassis_info);
	info->head.buf_size = head.buf_size;
	info->head.card = head.card;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_chassis_info",
			NULL, 0, (void *)&remote_chassis_infos, &result_len, sizeof(struct chassis_info));
	if (ret < 0) {
		cn_dev_core_info(core, "call rpc_cndev_chassis_info failed");
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
		size = info->chassis_part_name_size > CHASSIS_PART_NAME_BYTES_MAX ?
			CHASSIS_PART_NAME_BYTES_MAX : info->chassis_part_name_size;
		if (copy_to_user(info->chassis_part_name,
				remote_chassis_infos.chassis_part_num, size)) {
			cn_dev_core_info(core, "copy to usr failed!, ret = %d", ret);
			return -EFAULT;
		}
		info->info_ready |= CHASSIS_PART_NUM_READY;
		info->chassis_part_name_size = size;
	}

	if (remote_chassis_infos.info_ready & CHASSIS_VENDOR_NAME_READY) {
		memcpy(info->chassis_vendor_name,
			remote_chassis_infos.chassis_vendor_name, CHASSIS_VENDOR_NAME_BYTES);
		info->info_ready |= CHASSIS_VENDOR_NAME_READY;
	}

	size = sizeof(struct cndev_nvme_ssd_info) * NVME_SSD_COUNT;
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_nvme_info",
		NULL, 0, (void *)&nvme_info, &result_len, size);
	if (ret < 0) {
		cn_dev_core_info(core, "call rpc_cndev_nvme_info failed");
		return ret;
	}
	info->nvme_ssd_num = NVME_SSD_COUNT;
	memcpy(info->nvme_info, nvme_info, size);

	size = sizeof(struct cndev_psu_info) * PSU_COUNT;
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_psu_info",
		NULL, 0, (void *)&psu_info, &result_len, size);
	if (ret < 0) {
		cn_dev_core_info(core, "call rpc_cndev_psu_info failed");
		return ret;
	}
	info->psu_num = PSU_COUNT;
	memcpy(info->psu_info, psu_info, size);

	size = sizeof(struct cndev_ib_info) * IB_BOARD_COUNT;
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_ib_info",
		NULL, 0, (void *)&ib_info, &result_len, size);
	if (ret < 0) {
		cn_dev_core_info(core, "call rpc_cndev_ib_info failed");
		return ret;
	}
	info->ib_board_num = IB_BOARD_COUNT;
	memcpy(info->ib_info, ib_info, size);

	return 0;
}

int cndev_chassis_power_info_mlu370(void *cset, struct cndev_chassis_power_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	struct cndev_head head = {0};
	struct cn_core_set *core = NULL;
	int copy_length = 0;
	struct chassis_runtime_info_s *chassis_rt_info = NULL;
	char chassis_temp[MLU590_CHASSIS_TEMP_COUNT] = {0};

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	memcpy(&head, &info->head, sizeof(struct cndev_head));

	info->head.version = CNDEV_CURRENT_VER;
	info->head.real_size = sizeof(struct cndev_chassis_power_info);
	info->head.buf_size = head.buf_size;
	info->head.card = head.card;

	copy_length = sizeof(struct chassis_runtime_info_s) +
		sizeof(u16) * FAN_SPEED;
	chassis_rt_info = cn_kzalloc(copy_length, GFP_KERNEL);
	if (!chassis_rt_info) {
		cn_dev_core_err(core, "alloc buf fail");
		ret = -ENOMEM;
		goto out;
	}
	chassis_rt_info->fan_num = FAN_SPEED;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_fan_info",
			NULL, 0, (void *)chassis_rt_info, &result_len, copy_length);
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
		goto out;
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
			goto out;
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

out:
	if (chassis_rt_info)
		cn_kfree(chassis_rt_info);

	return 0;
}

int cndev_card_get_retire_pages_mlu370(void *cset,
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

int cndev_card_get_retire_status_mlu370(void *cset,
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

int cndev_card_get_retire_remapped_rows_mlu370(void *cset,
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

	/* temp: return value */
	result = 0;
	retire_remapped_rows->unc_rows = 0;
	retire_remapped_rows->corr_rows = 0;
	retire_remapped_rows->pending_rows = 0;
	retire_remapped_rows->fail_rows = 0;

	return result;
}

int cndev_card_retire_switch_mlu370(void *cset,
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

int cndev_lateinit_mlu370(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;
	int ret = 0;

	if (cndev_set->device_id != MLUID_370V) {
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

void cndev_stop_mlu370(void *cset)
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
	if (cndev_set->device_id != MLUID_370V) {
		hrtimer_cancel(&cndev_set->mcuinfo_hrtimer);
	}
}

void cndev_exit_mlu370(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *pcore = NULL;

	if (!cndev_set) {
		return;
	}

	pcore = cndev_set->core;

	hrtimer_cancel(&cndev_set->hrtimer);

	if (cndev_set && cndev_set->device_id != MLUID_370V) {
		hrtimer_cancel(&cndev_set->mcuinfo_hrtimer);
	}

	if (cndev_set->endpoint) {
		__pmu_disconnect(cndev_set->endpoint, pcore);
		cndev_set->endpoint = NULL;
	}

	cndev_set->ops = NULL;
}

void cndev_init_codec_process_util(struct cn_cndev_set *cndev_set)
{
	cndev_set->process_info.codec = cn_vzalloc(sizeof(struct cndev_process_codecutil) * CN_CNDEV_MAX_CODEC_PROCESS_NUM);
	if (!cndev_set->process_info.codec) {
		cn_dev_err("cndev malloc process codec failed!");
		return;
	}

	cndev_set->process_info.active_pid = cn_vzalloc(sizeof(u64) * CN_CNDEV_MAX_CODEC_PROCESS_NUM);
	if (!cndev_set->process_info.active_pid) {
		cn_dev_err("cndev malloc process active_pid failed!");
		cn_vfree(cndev_set->process_info.codec);
		cndev_set->process_info.codec = NULL;
		return;
	}
	mutex_init(&cndev_set->process_info.codec_mutex);
}

static const struct cn_cndev_ioctl cndev_mlu370_ioctl = {
	.card_info_fill = card_info_fill_common,
	.card_power_info = card_power_info_mlu370,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = card_ecc_info_mlu370,
	.card_vm_info = card_vm_info_mlu370,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = cndev_card_codecutil_info_common,
	.card_freq_info = cndev_card_freq_info_mlu370,
	.card_curbuslnk = cndev_card_curbuslnk_common,
	.card_pciethroughput = cndev_card_pciethroughput_common,
	.card_power_capping = cndev_card_powercapping_mlu370,
	.card_ipufreq_set = card_ipufreq_set_mlu370,
	.card_ncs_version = card_ncs_version_common,
	.card_ncs_state = card_ncs_state_common,
	.card_ncs_speed = card_ncs_speed_common,
	.card_ncs_capability = card_ncs_capability_common,
	.card_ncs_counter = card_ncs_counter_common,
	.card_ncs_remote = card_ncs_remote_common,
	.card_reset_ncs_counter = card_ncs_reset_cntr_common,
	.card_chassis_info = cndev_chassis_info_mlu370,
	.card_qos_reset = cndev_qos_reset_common,
	.card_qos_info = cndev_qos_policy_common,
	.card_qos_desc = cndev_qos_desc_common,
	.card_set_qos = cndev_set_qos_policy,
	.card_set_qos_group = cndev_set_qos_group_policy,
	.card_acpuutil_info = cndev_card_acpuutil_info_common,
	.card_acpuutil_timer = cndev_card_acpuutil_timer_common,
	.card_get_retire_pages = cndev_card_get_retire_pages_mlu370,
	.card_get_retire_status = cndev_card_get_retire_status_mlu370,
	.card_get_retire_remapped_rows = cndev_card_get_retire_remapped_rows_mlu370,
	.card_retire_switch = cndev_card_retire_switch_mlu370,
	.card_ncs_port_config = card_ncs_port_config_common,
	.card_mlulink_switch_ctrl = card_mlulink_switch_ctrl_common,
	.card_ipufreq_ctrl = card_ipufreq_ctrl_mlu370,
	.card_get_ncs_info = card_get_ncs_info_common,
	.card_get_card_info_ext = cndev_card_card_info_ext,
	.card_get_process_iputil = cndev_get_process_ipuutil_common,
	.card_get_process_codecutil = cndev_get_process_codecutil_common,
	.card_get_feature = cndev_card_get_feature_common,
	.card_set_feature = cndev_card_set_feature_common,
	.card_get_mim_profile_info = NULL,
	.card_get_mim_possible_place_info = NULL,
	.card_get_mim_vmlu_capacity_info = NULL,
	.card_get_mim_device_info = NULL,
	.card_get_desc_info = NULL,
	.card_get_cntr_info = NULL,
	.chassis_power_info = cndev_chassis_power_info_mlu370,
	.card_get_smlu_profile_id = cndev_card_get_smlu_profile_id_common,
	.card_get_smlu_profile_info = cndev_card_get_smlu_profile_info_common,
	.card_new_smlu_profile = cndev_card_new_smlu_profile_common,
	.card_delete_smlu_profile = cndev_card_delete_smlu_profile_common,
};

static const struct cn_cndev_ops cndev_mlu370_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_mlu370,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_mlu370,
	.cndev_exit = cndev_exit_mlu370,
};

static const struct cn_cndev_ioctl cndev_mlu370_vf_ioctl = {
	.card_info_fill = card_info_fill_vf_common,
	.card_power_info = card_power_info_vf_common,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = NULL,
	.card_vm_info = card_vm_info_mlu370,
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
	.card_chassis_info = cndev_chassis_info_mlu370,
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
	.card_mlulink_switch_ctrl = card_mlulink_switch_ctrl_common,
	.card_ipufreq_ctrl = NULL,
	.card_get_ncs_info = card_get_ncs_info_common,
	.card_get_card_info_ext = cndev_card_card_info_ext,
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
	.chassis_power_info = cndev_chassis_power_info_mlu370,
	.card_get_smlu_profile_id = cndev_card_get_smlu_profile_id_common,
	.card_get_smlu_profile_info = cndev_card_get_smlu_profile_info_common,
	.card_new_smlu_profile = cndev_card_new_smlu_profile_common,
	.card_delete_smlu_profile = cndev_card_delete_smlu_profile_common,
};

static const struct cn_cndev_ops cndev_mlu370_vf_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_mlu370,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_mlu370,
	.cndev_exit = cndev_exit_mlu370,
};

int cndev_init_mlu370(struct cn_cndev_set *cndev_set)
{

	switch (cndev_set->device_id) {
	case MLUID_370:
		cndev_set->ops = &cndev_mlu370_ops;
		cndev_set->ioctl = &cndev_mlu370_ioctl;
		/* Timer 500ms */
		cndev_set->mcuinfo_time_delay = ktime_set(0, 500 * 1000 * 1000);
		hrtimer_init(&cndev_set->mcuinfo_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		cndev_set->mcuinfo_hrtimer.function = mlu370_cndev_mcuinfo_work_hrtimer;
		cndev_init_codec_process_util(cndev_set);
		break;
	case MLUID_370V:
	case MLUID_370_DEV:
		cndev_set->ops = &cndev_mlu370_vf_ops;
		cndev_set->ioctl = &cndev_mlu370_vf_ioctl;
		break;
	}

	cndev_common_init(cndev_set);

	return 0;
}
