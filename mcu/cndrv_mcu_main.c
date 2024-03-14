#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_mcu.h"
#include "cndrv_debug.h"
#include "cndrv_trans.h"
#include "mcu.h"
#include "../attr/cndrv_attr_res.h"

const u32 pigeon_platform_id[4] = {
	CN_CHIP_TYPE_LEOPARD,
	CN_CHIP_TYPE_PIGEON,
	CN_CHIP_TYPE_PIGEONC,
	CN_CHIP_TYPE_LEOPARD
};

int switch_core_type_check(struct cn_core_set *pcore)
{
	struct cn_board_info *pboardi = &pcore->board_info;
	switch (pcore->device_id) {
	case MLUID_PIGEON_EDGE:
	case MLUID_PIGEON:
		if (pboardi->chip_type == CN_CHIP_ID_LEOPARD) {
			return 0;
		} else {
			cn_dev_err("unknown chip_type, device id is [%llu] chip type is [%d]", pcore->device_id, pboardi->chip_type);
			return 1;
		}
		break;
	default:
		cn_dev_err("unknown device_id");
		return 1;
	}

	return 1;
}

void cn_mcu_write32(void *pcore, unsigned long offset, u32 val)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg_write32(core->bus_set, offset, val);
}

u32 cn_mcu_read32(void *pcore, unsigned long offset)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	return reg_read32(core->bus_set, offset);
}

int cndrv_mcu_read_basic_info(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->read_basic_info)) {
		cn_dev_err("read basic func null");
		return -EINVAL;
	}
	return mcu_set->mcu_ops->read_basic_info(pcore);
}

/**
* @brief read 270 mcu power info
* @param pcore core layer handle
* @param *info power info struct
*
* based on variable temp buffer length,
* this function will alloc a buffer to save then.
* user must free the *temp buffer itself.
*
* @return
*/
int cndrv_mcu_read_power_info(void *pcore, struct board_power_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->read_power_info)) {
		cn_dev_err("read func null");
		return -EINVAL;
	}
	return mcu_set->mcu_ops->read_power_info(pcore, info);
}

/**
* @brief read 270 freq info
* @param pcore core layer handle
* @param *freq freq info struct
*
* @return
*/
int cndrv_mcu_read_ipu_freq(void *pcore, struct ipu_freq_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->read_ipu_freq)) {
		cn_dev_err("read func null");
		return -EINVAL;
	}
	return mcu_set->mcu_ops->read_ipu_freq(pcore, info);
}

int cndrv_mcu_read_ddr_freq(void *pcore, u32 *freq)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->read_ddr_freq)) {
		cn_dev_err("read func null");
		return -EINVAL;
	}
	return mcu_set->mcu_ops->read_ddr_freq(pcore, freq);
}

/**
* @brief read 290 current max temperature
* @param pcore core layer handle
* @param *temp_value temperature value
*
* @return
*/
int cndrv_mcu_read_max_temp(void *pcore, int *max_temp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->read_max_temp)) {
		cn_dev_debug("read func null");
		return -EINVAL;
	}
	return mcu_set->mcu_ops->read_max_temp(pcore, max_temp);
}

int cndrv_mcu_read_uuid(void *pcore, unsigned char *uuid)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->read_uuid)) {
		cn_dev_debug("read func null");
		return -EINVAL;
	}
	return mcu_set->mcu_ops->read_uuid(pcore, uuid);
}

/**
* @brief read 290 current over temperature and freq reduce flag
* @param pcore core layer handle
* @param *flag over temperature and frequency reducation flag
*
* @return
*/
int cndrv_mcu_read_overtemp_freq(void *pcore, struct mlu_overtemp_value *overtemp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("overtemp mcu set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->read_overtemp_freq)) {
		cn_dev_debug("overtemp read overtemp freq null");
		return -EINVAL;
	}

	return mcu_set->mcu_ops->read_overtemp_freq(pcore, overtemp);
}

int cndrv_check_overtemp_warning_recallflag(struct cn_core_set *core)
{
	struct mlu_overtemp_warning *freq_warning = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("mcu_set is null");
		return -EINVAL;
	}
	freq_warning = &(core->freq_warning);

	freq_warning->recall_count++;

	if (freq_warning->recall_count % 2 == 0) {

		freq_warning->recall_count = 0;

		return 0;
	}

	return 1;
}

/**
 * @brief print overtemperature warning info
 * @param pcore core layer handle
 * @return 0
 */
int cndrv_print_overtemp_freq_warning(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	int ret = -EINVAL;
	struct mlu_overtemp_value overtemp;
	struct mlu_overtemp_warning *freq_warning = NULL;

	if (IS_ERR_OR_NULL(pcore)) {
		cn_dev_err("pcore set is null");
		return ret;
	}

	freq_warning = &(core->freq_warning);

	memset(&overtemp, 0, sizeof(struct mlu_overtemp_value));
	cndrv_mcu_read_overtemp_freq(pcore, &overtemp);

	if (overtemp.freq_value > freq_warning->value) {
		freq_warning->value = overtemp.freq_value;
		freq_warning->cycle = freq_warning->refresh_cycle;
	}

	if (freq_warning->cycle > 0 && freq_warning->mode == OVERTEMP_WARNING_AUTO) {
		freq_warning->cycle--;
		cn_dev_warn("Overtemperature and Frequency is reducating 0x%x\n", freq_warning->value);
	}

	ret = cndrv_check_overtemp_warning_recallflag(core);

	return ret;
}

/**
* @brief read 290 over temperature flag
* @param pcore core layer handle
* @param *flag over temperature flag
*
* @return flag
*/
int cndrv_mcu_read_over_temp_flag(void *pcore, int *poweroff_flag)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->read_over_temp_flag)) {
		cn_dev_err("read func null");
		return -EINVAL;
	}
	return mcu_set->mcu_ops->read_over_temp_flag(pcore, poweroff_flag);
}

int cndrv_mcu_read_halt_reason(void *pcore, struct exception_info *info, u8 klog)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->read_exception_info)) {
		cn_dev_err("read func null");
		return -EINVAL;
	}
	return mcu_set->mcu_ops->read_exception_info(pcore, info, klog);
}

/**
* @brief read or write power capping
* @param pcore core layer handle
* @param *pcinfo power cap info struct
*
* @return
*/
int cndrv_mcu_power_capping(void *pcore, struct power_capping_info *pcinfo)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->power_capping)) {
		cn_dev_err("power cap func null");
		return -EINVAL;
	}
	return mcu_set->mcu_ops->power_capping(pcore, pcinfo);
}

int cndrv_mcu_set_host_driver_status(void *pcore, int status)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(core)) {
		return -EINVAL;
	}

	if (cn_core_is_vf(core)) {
		return 0;
	}

	if (IS_ERR_OR_NULL(mcu_set)) {
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->set_host_drv_status)) {
		return -EINVAL;
	}

	return mcu_set->mcu_ops->set_host_drv_status(pcore, status);
}

int mcu_get_platform_id_common(void *pcore, u32 *chip_type)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;

	if (IS_ERR_OR_NULL(chip_type)) {
		cn_dev_core_err(core, "chip_type is null");
		return -EINVAL;
	}
	if (pboardi->platform_id == CN_CHIP_TYPE_UNKNOWN) {
		cn_dev_core_err(core, "chip_type is unknown");
		return -EINVAL;
	}
	*chip_type = pboardi->platform_id;
	return 0;
}

int mcu_get_platform_info_common(void *pcore, struct monitor_platform_info *monitor_platform)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	u32 buf_size = 0;

	if (IS_ERR_OR_NULL(monitor_platform)) {
		cn_dev_core_err(core, "monitor platform is null");
		return -EINVAL;
	}
	buf_size = sizeof(struct monitor_chip_info) * pboardi->platform_num;
	if (monitor_platform->buf_size < buf_size) {
		goto next;
	}
	if (monitor_platform->info) {
		if (copy_to_user((void*)monitor_platform->info, pboardi->platform_info, buf_size)) {
			cn_dev_core_err(core, "copy_to_user failed");
			ret = -EFAULT;
		}
	}

next:

	monitor_platform->total_chip = pboardi->platform_num;
	monitor_platform->buf_size = buf_size;
	return ret;
}

int cndrv_mcu_get_platform_info(void *pcore, void *info)
{
	if (IS_ERR_OR_NULL(pcore) || IS_ERR_OR_NULL(info)) {
		cn_dev_debug("core_set or info is null");
		return -EINVAL;
	}
	return mcu_get_platform_info_common(pcore, info);
}

int cndrv_mcu_get_platform_id(void *pcore, u32 *chip_type)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	int ret = 0;
	struct cn_board_info *pbrdinfo = &core->board_info;

	if (IS_ERR_OR_NULL(pcore) || IS_ERR_OR_NULL(chip_type)) {
		cn_dev_err("pcore set or chip_type is null");
		return -EINVAL;
	}
	switch (core->device_id) {
	case MLUID_PIGEON:
	case MLUID_PIGEON_EDGE:
		*chip_type = pigeon_platform_id[pbrdinfo->chip_type & 0x3];
		break;
	default:
		ret = mcu_get_platform_id_common(pcore, chip_type);
		break;
	}
	return ret;
}

void __mcu_set_basic_for_vf(struct cn_core_set *core)
{
	struct cn_board_info *pboardi = &core->board_info;

	switch (core->board_model) {
	case MLU270_VF:
		core->board_info.board_idx = CN_MLU270_VF;
		pboardi->ecc_support = mlu270_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
		strcpy(pboardi->board_model_name,
			mlu270_basic_info_table[core->board_info.board_idx].board_model_name);
		pboardi->peak_power = mlu270_basic_info_table[core->board_info.board_idx].peak_power;
		pboardi->bandwidth = mlu270_basic_info_table[core->board_info.board_idx].bandwidth;
		pboardi->bandwidth_decimal = mlu270_basic_info_table[core->board_info.board_idx].bandwidth_decimal;
		pboardi->platform_id = mlu270_basic_info_table[core->board_info.board_idx].platform_id;
		break;
	case MLU290_VF:
		core->board_info.board_idx = CN_MLU290_VF;
		pboardi->ecc_support = mlu290_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
		strcpy(pboardi->board_model_name,
			mlu290_basic_info_table[core->board_info.board_idx].board_model_name);
		pboardi->peak_power = mlu290_basic_info_table[core->board_info.board_idx].peak_power;
		pboardi->bandwidth = mlu290_basic_info_table[core->board_info.board_idx].bandwidth;
		pboardi->bandwidth_decimal = mlu290_basic_info_table[core->board_info.board_idx].bandwidth_decimal;
		pboardi->platform_id = mlu290_basic_info_table[core->board_info.board_idx].platform_id;
		break;
	case MLU370_VF:
		core->board_info.board_idx = CN_MLU370_VF;
		pboardi->ecc_support = mlu370_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
		strcpy(pboardi->board_model_name,
			mlu370_basic_info_table[core->board_info.board_idx].board_model_name);
		pboardi->peak_power = mlu370_basic_info_table[core->board_info.board_idx].peak_power;
		pboardi->bandwidth = mlu370_basic_info_table[core->board_info.board_idx].bandwidth;
		pboardi->bandwidth_decimal = mlu370_basic_info_table[core->board_info.board_idx].bandwidth_decimal;
		pboardi->platform_id = mlu370_basic_info_table[core->board_info.board_idx].platform_id;
		break;
	case MLU580_VF:
		core->board_info.board_idx = CN_MLU580_VF;
		pboardi->ecc_support = mlu580_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
		strcpy(pboardi->board_model_name,
			mlu580_basic_info_table[core->board_info.board_idx].board_model_name);
		pboardi->peak_power = mlu580_basic_info_table[core->board_info.board_idx].peak_power;
		pboardi->bandwidth = mlu580_basic_info_table[core->board_info.board_idx].bandwidth;
		pboardi->bandwidth_decimal = mlu580_basic_info_table[core->board_info.board_idx].bandwidth_decimal;
		pboardi->platform_id = mlu580_basic_info_table[core->board_info.board_idx].platform_id;
		break;
	case MLU590_VF:
		core->board_info.board_idx = CN_MLU590_VF;
		pboardi->ecc_support = mlu590_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
		strcpy(pboardi->board_model_name,
			mlu590_basic_info_table[core->board_info.board_idx].board_model_name);
		pboardi->peak_power = mlu590_basic_info_table[core->board_info.board_idx].peak_power;
		pboardi->bandwidth = mlu590_basic_info_table[core->board_info.board_idx].bandwidth;
		pboardi->bandwidth_decimal = mlu590_basic_info_table[core->board_info.board_idx].bandwidth_decimal;
		pboardi->platform_id = mlu590_basic_info_table[core->board_info.board_idx].platform_id;
		break;
	default:
		break;
	}

	/* min power cap, vf not support */
	pboardi->min_power_cap = 0;
	pboardi->min_power_cap_dec = 0;

	/* per cluster */
	pboardi->ipu_core_num = 4;
	/* FIXME */
	pboardi->mem_channel = 1;
}

int __mcu_board_init(struct cn_core_set *core)
{
	int ret = 0;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	atomic64_set(&mcu_set->enable_power_cap_ref, 0);
	atomic64_set(&mcu_set->disable_power_cap_ref, 0);

	switch (core->device_id) {
	case MLUID_220:
	case MLUID_220_EDGE:
		ret = mcu_init_mlu220(mcu_set);
		break;
	case MLUID_270:
		ret = mcu_init_mlu270(mcu_set);
		break;
	case MLUID_270V:
	case MLUID_270V1:
		core->board_model = MLU270_VF;
		__mcu_set_basic_for_vf(core);
		ret = -ENODEV;
		break;
	case MLUID_290:
		ret = mcu_init_mlu290(mcu_set);
		break;
	case MLUID_290V1:
		core->board_model = MLU290_VF;
		__mcu_set_basic_for_vf(core);
		ret = -ENODEV;
		break;
	case MLUID_370:
		ret = mcu_init_mlu370(mcu_set);
		break;
	case MLUID_370V:
		core->board_model = MLU370_VF;
		__mcu_set_basic_for_vf(core);
		ret = -ENODEV;
		break;
	case MLUID_CE3226:
	case MLUID_CE3226_EDGE:
		ret = mcu_init_ce3226(mcu_set);
		break;
	case MLUID_590:
		ret = mcu_init_mlu590(mcu_set);
		break;
	case MLUID_580:
		ret = mcu_init_mlu580(mcu_set);
		break;
	case MLUID_580V:
		core->board_model = MLU580_VF;
		__mcu_set_basic_for_vf(core);
		ret = -ENODEV;
		break;
	case MLUID_590V:
		core->board_model = MLU590_VF;
		__mcu_set_basic_for_vf(core);
		ret = -ENODEV;
		break;
	case MLUID_PIGEON:
	case MLUID_PIGEON_EDGE:
		ret = mcu_init_pigeon(mcu_set);
		break;
	default:
		cn_dev_err("device [%#llx] not support", core->device_id);
		ret = -ENODEV;
		break;
	}
	return ret;
}

int cn_mcu_init(struct cn_core_set *core)
{
	struct cn_mcu_set *mcu_set;
	int ret;
	int poweroff_flag = 0;
	struct exception_info exp_info;

	cn_dev_core_info(core, "mcu init");
	mcu_set = cn_kzalloc(sizeof(struct cn_mcu_set), GFP_KERNEL);
	if (!mcu_set) {
		cn_dev_err("alloc mcu set error.");
		return -ENOMEM;
	}
	core->mcu_set = mcu_set;
	mcu_set->core = core;

	cn_mcu_fill_platform_info(core);

	ret = __mcu_board_init(core);
	if (ret) {
		core->mcu_set = NULL;
		cn_kfree(mcu_set);
		if (ret == -ENODEV)
			return 0;
		return ret;
	}

	ret = cndrv_mcu_read_basic_info((void *)core);
	if (!ret)
		cn_dev_core_info(core, "MCU Version: v%u.%u.%u",
			core->board_info.mcu_info.mcu_major,
			core->board_info.mcu_info.mcu_minor,
			core->board_info.mcu_info.mcu_build);
	else {
		cn_kfree(core->mcu_set);
		core->mcu_set = NULL;
		goto out;
	}

	if ((core->device_id == MLUID_290) || (core->device_id == MLUID_270)
		|| (core->device_id == MLUID_590) || (core->device_id == MLUID_580)) {
		cndrv_mcu_read_over_temp_flag(core, &poweroff_flag);
		if (poweroff_flag)
			cn_dev_core_warn(core, "Over temperature poweroff at last time");
		else
			cn_dev_core_info(core, "NOT over temperature poweroff at last time");
	}

	cndrv_mcu_read_halt_reason(core, &exp_info, EXCEPTION_REASON_PRINT);

	ret = cn_host_mcu_trans_init(core);
	if (ret) {
		cn_dev_core_warn(core, "trans init failed");
	}

out:

	return ret;
}

void cn_mcu_exit(struct cn_core_set *core)
{
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	cn_host_mcu_free(core);

	cn_dev_core_info(core, "mcu free");
	if (mcu_set) {
		if (mcu_set->mcu_ops->mcu_exit) {
			mcu_set->mcu_ops->mcu_exit(mcu_set);
		}
		cn_kfree(mcu_set);
		core->mcu_set = NULL;
	}
}

int cndrv_mcu_set_overtemp_param(void *pcore,
				struct cndev_overtemp_param *overtemp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(overtemp)) {
		cn_dev_core_err(core, "cndev overtemp null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->set_overtemp_policy)) {
		return -EPERM;
	}
	if (!cn_is_mim_en(core) && !cn_core_is_vf(core))
		return mcu_set->mcu_ops->set_overtemp_policy(core, overtemp);
	return -EINVAL;
}

int cndrv_mcu_get_overtemp_param(void *pcore,
				struct cndev_overtemp_param *overtemp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(overtemp)) {
		cn_dev_core_err(core, "cndev overtemp null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->get_overtemp_policy)) {
		return -EPERM;
	}
	if (!cn_is_mim_en(core) && !cn_core_is_vf(core))
		return mcu_set->mcu_ops->get_overtemp_policy(core, overtemp);
	return -EINVAL;
}

int cndrv_set_d2d_crc_err(void *pcore,
	u32 status)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set)) {
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(mcu_set->mcu_ops->set_d2d_crc_err)) {
		return -EPERM;
	}

	return mcu_set->mcu_ops->set_d2d_crc_err(core, status);
}

int mcu_show_info(struct seq_file *m, void *v)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_mcu_set *mcu_set = NULL;

	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	mcu_set = (struct cn_mcu_set *)core->mcu_set;

	if (IS_ERR_OR_NULL(mcu_set))
		return -EINVAL;

	seq_printf(m, "Enable Power Capping Reference Count: %llu\n", (u64)atomic64_read(&mcu_set->enable_power_cap_ref));
	seq_printf(m, "Disable Power Capping Reference Count: %llu\n", (u64)atomic64_read(&mcu_set->disable_power_cap_ref));

	return ret;
}
