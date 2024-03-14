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
#include "cndrv_xid.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_mcu.h"
#include "cndrv_debug.h"

#include "mcu.h"
#include "cndrv_trans.h"

#define DDR_TOTAL_mlu290(a) ((a) * 32ULL * 0x100000 * 1024)

int __mcu_read_power_cap_mlu290(void *pcore, u32 *cap_value, u16 *dec_cap_value)
{
	u32 reg32 = 0;

	reg32 = cn_mcu_read32(pcore, IPC13);

	if (reg32 & MCU_POWER_CAP_ENABLE_MLU290) {
		*cap_value = reg32 & MCU_POWER_CAP_MASK_MLU290;
	} else {
		*cap_value = 0;
	}

	/* mlu290 power cap decimal */
	if (dec_cap_value)
		*dec_cap_value = 0;

	return 0;
}

int __mcu_set_power_cap_mlu290(void *pcore, u32 cap_value, u16 dec_cap_value)
{
	u32 reg32 = 0;
	u32 half_power = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	half_power = pboardi->peak_power / 2;

	if (!cap_value) {
		reg32 = 0;
		atomic64_inc(&mcu_set->disable_power_cap_ref);
	} else if ((cap_value < half_power)
			|| (cap_value > pboardi->peak_power)) {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "User input cap value %u out of range!",
			cap_value);
		return -EINVAL;
	} else {
		reg32 = (cap_value & MCU_POWER_CAP_MASK_MLU290)
				| MCU_POWER_CAP_ENABLE_MLU290;
		atomic64_inc(&mcu_set->enable_power_cap_ref);
	}

	cn_mcu_write32(pcore, IPC13, reg32);

	return 0;
}

int mcu_read_basic_info_mlu290(void *pcore)
{
	int ret = 0;
	u32 reg32 = 0;
	u64 serial_num = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	u8 subsystem_id = 0;
	u16 dec_power_cap = 0;

	reg32 = cn_mcu_read32(core, IPC26);
	pboardi->ddr_speed = reg32 & 0xffff;
	pboardi->ddr_freq = 1000;

	/*TODO: only one version of mlu290 with 32GB HBM now*/
	pboardi->ddr_cap = 1;
	pboardi->ddr_type = 1;
	pboardi->total_memory =
			DDR_TOTAL_mlu290(pboardi->ddr_type * pboardi->ddr_cap);

	/* read chip version */
	pboardi->chip_version = 0;
	cn_dev_core_debug(core, "chip ver: %d", pboardi->chip_version);

	/*chip type subsystem_id and mcu version*/
	reg32 = cn_mcu_read32(core, IPC7);
	cn_dev_core_debug(core, "IPC7, val: 0x%08X\n", reg32);

	pboardi->chip_type = (reg32 >> MCU_MAIN_VERSION_SHIFT)
			& MCU_VERSION_MASK;
	subsystem_id = (reg32 >> MCU_BOARD_TYPE_SHIFT)
			& MCU_VERSION_MASK;
	pboardi->board_type = subsystem_id;
	pboardi->mcu_info.mcu_major = (reg32 >> MCU_SW_MAJOR_VER_SHIFT)
			& MCU_VERSION_MASK;
	pboardi->mcu_info.mcu_minor = (reg32 >> MCU_SW_MINOR_VER_SHIFT)
			& MCU_VERSION_MASK;
	/*split minor and build version from uint8*/
	pboardi->mcu_info.mcu_build = pboardi->mcu_info.mcu_minor & 0xF;
	pboardi->mcu_info.mcu_minor = (pboardi->mcu_info.mcu_minor & 0xF0) >> 4;
	pboardi->mcu_info.mcu_rc = 0;

	pboardi->cluster_num = 16;
	pboardi->ipu_core_num = 4;
	pboardi->mem_channel = 4;

	core->board_model = MLU290;

	/*board serial number*/
	reg32 = cn_mcu_read32(core, IPC1);
	serial_num = reg32;
	reg32 = cn_mcu_read32(core, IPC2);
	pboardi->slot_id = (reg32 & (0xff0000)) >> 16;
	serial_num |= ((u64)(reg32 & 0xFFFF) << 32);
	cn_dev_core_info(core, "board serial: %016llX", serial_num);
	pboardi->serial_num = serial_num;

	memcpy(pboardi->uuid, &serial_num, CNDRV_UUID_SIZE >> 1);
	serial_num = ~serial_num;
	memcpy((void *)pboardi->uuid + (CNDRV_UUID_SIZE >> 1), &serial_num, CNDRV_UUID_SIZE >> 1);

	/*BA serial number*/
	reg32 = cn_mcu_read32(core, IPC3);
	serial_num = reg32;
	reg32 = cn_mcu_read32(core, IPC4);

	/*MLU290 BA mcu firmware version */
	pboardi->BA_mcu_fw_ver = (reg32 >> 16) & 0xFFFF;

	serial_num |= ((u64)(reg32 & 0xFFFF) << 32);
	cn_dev_core_info(core, "BA serial: %016llX", serial_num);
	pboardi->BA_serial_num = serial_num;

	pboardi->gdma_mask = 0x0;
	pboardi->platform = MLU_PLAT_ASIC;

	pboardi->peak_power = 350;
	core->board_info.board_idx = CN_MLU290;
	pboardi->min_power_cap_ctrl = mlu290_basic_info_table[core->board_info.board_idx].min_power_cap_ctrl;
	if (pboardi->min_power_cap_ctrl) {
		pboardi->min_power_cap = pboardi->min_power_cap_ctrl;
	} else {
		pboardi->min_power_cap = pboardi->peak_power / 2;
	}
	pboardi->min_power_cap_dec = 0;
	pboardi->max_power_cap_dec = 0;

	reg32 = cn_mcu_read32(core, IPC11) >> MCU_QDD_STATUS_SHIFT & 0xFF;
	pboardi->qdd_status = reg32;

	core->die_cnt = 1;
	pboardi->chip_id = 0;
	pboardi->secure_mode = NORMAL_BOOT;
	memset(pboardi->soc_id.soc_id_data, 0, SOC_ID_SIZE);
	strcpy(pboardi->board_model_name, mlu290_basic_info_table[core->board_info.board_idx].board_model_name);

	pboardi->bandwidth = mlu290_basic_info_table[core->board_info.board_idx].bandwidth;
	pboardi->bandwidth_decimal = mlu290_basic_info_table[core->board_info.board_idx].bandwidth_decimal;
	pboardi->platform_id = mlu290_basic_info_table[core->board_info.board_idx].platform_id;

	/* get board info */
	pboardi->bus_width = mlu290_board_info[core->board_info.board_idx][INFO_BUS_WIDTH];
	pboardi->ecc_support = mlu290_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
	pboardi->stack_size = mlu290_board_info[core->board_info.board_idx][INFO_STACK_SIZE];
	pboardi->sram_size = mlu290_board_info[core->board_info.board_idx][INFO_SRAM_SIZE];
	pboardi->cache_size = mlu290_board_info[core->board_info.board_idx][INFO_CACHE_SIZE];
	pboardi->kc_limit = mlu290_board_info[core->board_info.board_idx][INFO_KC_LIMIT];
	pboardi->o_kc_limit = mlu290_board_info[core->board_info.board_idx][INFO_O_KC_LIMIT];
	pboardi->rated_ipu_freq = mlu290_board_info[core->board_info.board_idx][INFO_MAX_IPU_FREQ];

	/* get ipu freq capping range */
	pboardi->min_ipu_freq_cap = mlu290_basic_info_table[core->board_info.board_idx].min_ipu_freq_cap;
	pboardi->max_ipu_freq_cap = mlu290_basic_info_table[core->board_info.board_idx].max_ipu_freq_cap;

	cn_dev_core_info(core, "board_model_name %s, board_model %#x, peak_power %#x",
		pboardi->board_model_name,  core->board_model, pboardi->peak_power);

	__mcu_read_power_cap_mlu290(core, &reg32, &dec_power_cap);
	if (reg32)
		cn_dev_core_info(core, "Board Power Cap to %u.%02uW", reg32, dec_power_cap);

	ret = mcu_version_contorl(core,
							&pboardi->mcu_info,
							core->board_info.board_idx,
							cn_mlu290_mcu_ver_control);

	return ret;
}


/**
 * @brief read mlu290 mcu power info
 * @param pcore core layer handle
 * @param *info power info struct
 *
 * based on variable temp buffer length,
 * this function will alloc a buffer to save then.
 * user must free the *temp buffer itself.
 *
 * @return
 */
int mcu_read_power_info_mlu290(void *pcore, struct board_power_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	s8 *temp_buf = NULL;
	u32 reg32 = 0;

	temp_buf = cn_kzalloc(sizeof(s8) * MLU290_TEMPERTURE_INFO_CONUT, GFP_KERNEL);
	if (!temp_buf) {
		cn_dev_core_err(core, "alloc buf fail");
		return -ENOMEM;
	}

	reg_data.data = cn_mcu_read32(core, IPC10);
	cn_dev_core_debug(core, "IPC10: 0x%04X", reg_data.data);

	/* HBM temperature */
	temp_buf[1] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	temp_buf[2] = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	temp_buf[3] = reg_data.bit.data2 - MCU_TEMP_CORRECTION_FACTOR;
	temp_buf[4] = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;

	reg_data.data = cn_mcu_read32(core, IPC5);
	cn_dev_core_debug(core, "IPC5: 0x%04X", reg_data.data);

	/* board temperature */
	temp_buf[0] = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	/* ic temperature */
	temp_buf[5] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	/* spider in temperature */
	temp_buf[6] = reg_data.bit.data2 - MCU_TEMP_CORRECTION_FACTOR;
	/* spider out temperature */
	temp_buf[7] = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;

	__mcu_read_power_cap_mlu290(core, &info->peak_power, &info->max_power_decimal);
	info->fan_speed = 0;

	reg32 = cn_mcu_read32(core, IPC14);
	info->board_power = reg32 & 0xffff;
	info->board_power_decimal = 0;

	info->machine_power = (reg32 >> MCU_MACHINE_TEMP_SHIFT) & 0xffff;

	info->temperature_num = MLU290_TEMPERTURE_INFO_CONUT;
	info->temp = temp_buf;

	/* not support */
	info->edpp_count = 0;
	info->tdp_freq_capping_count = 0;

	return 0;
}

/**
 * @brief read mlu290 ipu freq
 * @param pcore core layer handle
 * @param *freq ipu freq info return
 *
 * @return
 */
int mcu_read_ipu_freq_mlu290(void *pcore, struct ipu_freq_info *info)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;

	reg32 = cn_mcu_read32(pcore, IPC24);
	info->ipu_freq = reg32 & 0xffff;

	info->ipu_overtemp_dfs_flag = 0;
	info->ipu_fast_dfs_flag = 0;
	info->rated_ipu_freq = pboardi->rated_ipu_freq;

	return 0;
}

int mcu_read_max_temp_mlu290(void *pcore, int *max_temp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	int temp_value = 0;

	*max_temp = -MCU_TEMP_CORRECTION_FACTOR;
	/* chip temperature */
	reg_data.data = cn_mcu_read32(core, IPC5);
	temp_value = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* board temperature */
	temp_value = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* hbm0 temperature */
	reg_data.data = cn_mcu_read32(core, IPC10);
	temp_value = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* hbm1 temperature */
	temp_value = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* hbm2 temperature */
	temp_value = reg_data.bit.data2 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* hbm3 temperature */
	temp_value = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	return 0;
}

int mcu_read_over_temp_flag_mlu290(void *pcore, int *poweroff_flag)
{
	u32 reg32 = 0;

	reg32 = cn_mcu_read32(pcore, IPC0);
	*poweroff_flag = (reg32 & 0x80) >> 7;

	return 0;
}

int mcu_read_ddr_freq_mlu290(void *pcore, u32 *freq)
{
	u32 reg32 = 0;

	reg32 = cn_mcu_read32(pcore, IPC26);
	*freq = reg32 & 0xffff;

	return 0;
}

/**
 * brief set or read power capping status
 * @param pcore core layer handle
 * @param *pcinfo powercapping info struct
 *
 * @return
 */
int mcu_power_capping_mlu290(void *pcore, struct power_capping_info *pcinfo)
{
	int ret = 0;

	/* mlu290 not support set high precision power cap */
	pcinfo->high_precision_support = HIGH_PRECISION_POWER_CAP_SUPPORT;

	if (pcinfo->ops_type) {
		ret = __mcu_set_power_cap_mlu290(pcore, pcinfo->cap_value, pcinfo->dec_cap_value);
	} else {
		ret = __mcu_read_power_cap_mlu290(pcore, &pcinfo->cap_value, &pcinfo->dec_cap_value);
	}

	return ret;
}

/**
 * brief set host driver load status to mcu
 * @param pcore core layer handle
 *
 * @return
 */
int mcu_set_host_driver_status_mlu290(void *pcore, int status)
{
	int ret = 0;
	u32 reg32 = 0;

	reg32 = cn_mcu_read32(pcore, IPC29);

	if (status)
		reg32 |= (status & 0x01) << 4;
	else
		reg32 &= ~(0x01 << 4);

	cn_mcu_write32(pcore, IPC29, reg32);

	return ret;
}

int mcu_read_overtemp_freq_mlu290(void *pcore, struct mlu_overtemp_value *overtemp)
{
	u32 reg32 = 0;

	reg32 = cn_mcu_read32(pcore, IPC0);

	overtemp->freq_value = (reg32 >> 4) & 0x7;

	return 0;
}

void mcu_exit_mlu290(void *mset)
{
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)mset;

	if (mcu_set) {
		mcu_set->core = NULL;
		mcu_set->mcu_ops = NULL;
	}
}

int mcu_set_overtemp_policy_mlu290(void *pcore, struct cndev_overtemp_param *overtemp)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct mlu_overtemp_warning *freq_warning = NULL;

	if (IS_ERR_OR_NULL(core) || IS_ERR_OR_NULL(overtemp))
		return -EINVAL;
	if (overtemp->mode > 1) {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "Invalid mode %d. [0, 1]", overtemp->mode);
		return -EINVAL;
	}
	if (overtemp->cycle < 1 || overtemp->cycle > 65535) {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "Invalid refresh cycle %u. [1, 65535]", overtemp->cycle);
		return -EINVAL;
	}

	freq_warning = &core->freq_warning;
	freq_warning->mode = overtemp->mode;
	freq_warning->refresh_cycle = overtemp->cycle * 2;

	return ret;
}

int mcu_get_overtemp_policy_mlu290(void *pcore, struct cndev_overtemp_param *overtemp)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct mlu_overtemp_warning *freq_warning = NULL;

	if (IS_ERR_OR_NULL(core) || IS_ERR_OR_NULL(overtemp))
		return -EINVAL;

	freq_warning = &core->freq_warning;
	overtemp->mode = freq_warning->mode;
	overtemp->cycle = freq_warning->refresh_cycle / 2;

	return ret;
}

int mcu_read_exception_info_mlu290(void *pcore, struct exception_info *info, u8 klog)
{
	return 0;
}

static const struct cn_mcu_ops mcu_mlu290_ops = {
	.read_basic_info = mcu_read_basic_info_mlu290,
	.read_power_info = mcu_read_power_info_mlu290,
	.read_ipu_freq = mcu_read_ipu_freq_mlu290,
	.read_max_temp = mcu_read_max_temp_mlu290,
	.read_over_temp_flag = mcu_read_over_temp_flag_mlu290,
	.power_capping = mcu_power_capping_mlu290,
	.read_ddr_freq = mcu_read_ddr_freq_mlu290,
	.set_host_drv_status = mcu_set_host_driver_status_mlu290,
	.read_overtemp_freq = mcu_read_overtemp_freq_mlu290,
	.mcu_exit = mcu_exit_mlu290,
	.get_overtemp_policy = mcu_get_overtemp_policy_mlu290,
	.set_overtemp_policy = mcu_set_overtemp_policy_mlu290,
	.read_uuid = NULL,
	.set_d2d_crc_err = NULL,
	.read_exception_info = mcu_read_exception_info_mlu290,
};

int mcu_init_mlu290(struct cn_mcu_set *mcu_set)
{
	struct cn_core_set *core = NULL;
	u32 reg32 = 0;

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	mcu_set->mcu_ops = &mcu_mlu290_ops;

	core = (struct cn_core_set *)(mcu_set->core);
	/*Frequency Refresh Cycle*/
	core->freq_warning.refresh_cycle = 30 * 2;
	core->freq_warning.cycle = 0;
	core->freq_warning.mode = 0;
	core->freq_warning.recall_count = 0;

	/*For details, see DRIVER-11122*/
	reg32 = cn_mcu_read32(core, IPC30);
	if ((reg32 & 0xFFF) != 0x31e) {
		reg32 = (reg32 & 0xFFFF0000) | 0x831e;
		cn_mcu_write32(core, IPC30, reg32);
	}

	return 0;
}
