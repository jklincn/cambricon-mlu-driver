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

#define DDR_TOTAL_MLU270(a) ((a) * 4ULL * 0x100000)
#define TABLE_BASE 0x10

const u32 ddr_freq_mlu270[4] = {1600, 2400, 2666, 3200};
const u32 ddr_type_mlu270[4] = {16, 8, 4, 2};
const u32 ddr_cap_mlu270[4]  = {512, 1024, 2048, 4096};

struct mlu_board_model mlu270_board_model_table[] = {
	{MLU270_EVB, CN_MLU270_EVB},
	{MLU270_D4, CN_MLU270_D4},
	{MLU270_S4, CN_MLU270_S4},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{MLU270_V4, CN_MLU270_V4},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{MLU270_X5K, CN_MLU270_X5K},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{MLU270_F4, CN_MLU270_F4},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{MLU270_FD4, CN_MLU270_FD4},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{-1, CN_MLU270_UNKNOWN_TYPE},
	{MLU270_V4K, CN_MLU270_V4K},
	{MLU270_A4K, CN_MLU270_A4K},
};

int __mcu_read_power_cap_mlu270(void *pcore, u32 *cap_value, u16 *dec_cap_value)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;

	reg32 = cn_mcu_read32(pcore, MCU_MSG_INFO3);

	if (reg32 & MCU_POWER_CAP_ENABLE) {
		*cap_value = reg32 & MCU_POWER_CAP_MASK;
		*cap_value = clamp(*cap_value,
				(u32)(pboardi->peak_power / 2),
				pboardi->peak_power);
	} else {
		*cap_value = 0;
	}

	/* mlu270 power cap decimal */
	if (dec_cap_value)
		*dec_cap_value = 0;

	return 0;
}

int __mcu_set_power_cap_mlu270(void *pcore, u32 cap_value, u16 dec_vap_value)
{
	u32 reg32 = 0;
	u32 half_power;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	half_power = pboardi->peak_power / 2;

	if (!cap_value) {
		atomic64_inc(&mcu_set->disable_power_cap_ref);
	} else if ((cap_value < half_power)
			|| (cap_value > pboardi->peak_power)) {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "User input cap value %u out of range!",
			cap_value);
		return -EINVAL;
	} else {
		cap_value = (cap_value & MCU_POWER_CAP_MASK)
				| MCU_POWER_CAP_ENABLE;
		atomic64_inc(&mcu_set->enable_power_cap_ref);
	}
	reg32 = cn_mcu_read32(pcore, MCU_MSG_INFO3)
			& ~(MCU_POWER_CAP_MASK | MCU_POWER_CAP_ENABLE);
	reg32 |= cap_value;

	cn_mcu_write32(pcore, MCU_MSG_INFO3, reg32);

	return 0;
}

int mcu_read_basic_info_mlu270(void *pcore)
{
	int ret = 0;
	int cnt;
	u32 ddr_freq;
	u32 reg32 = 0;
	u64 serial_num;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	u8 subsystem_id;
	u8 a_type_board_symbol;
	int index = 0;
	int model = 0;
	int board_idx = 0;
	int board_model_table_size = ARRAY_SIZE(mlu270_board_model_table);
	u16 dec_cap_value = 0;

	cnt = 300;
	do {
		reg32 = cn_mcu_read32(core, MCU_BASIC_INFO);
		if (!((reg32 >> MCU_DDRTRAINED_FLAG_SHIFT)
					& MCU_DDRTRAINED_FLAG_MASK)) {
			ret = -EINVAL;
		} else {
			cn_dev_core_info(core, "DDR Training Params set by MCU Finish");
			break;
		}
		msleep(20);
	} while (--cnt);
	if (!cnt) {
		cn_xid_err(core, XID_MCU_ERR, "Wait DDR Training Finish Timeout!!");
		cn_recommend(core, USER_RECOMMED);
		return ret;
	}

	/*chip hardware version and ddr info*/
	/* this version is not what we want.
	pboardi->chip_version = (reg32 >> MCU_CHIP_VERSION_SHIFT)
			& MCU_CHIP_VERSION_MASK;
 */
	ddr_freq = (reg32 >> MCU_DDR_FREQ_SHIFT)
			& MCU_DDR_FREQ_MASK;
	pboardi->ddr_type = ddr_type_mlu270[(reg32 >> MCU_DDR_TYPE_SHIFT)
			& MCU_DDR_TYPE_MASK];
	pboardi->ddr_cap =  ddr_cap_mlu270[(reg32 >> MCU_DDR_CAPACITY_SHIFT)
			& MCU_DDR_CAPACITY_MASK];

	pboardi->total_memory =
			DDR_TOTAL_MLU270(pboardi->ddr_type * pboardi->ddr_cap);

	pboardi->ddr_speed = ddr_freq_mlu270[ddr_freq&0x03];
	pboardi->ddr_freq = 1600;

	/* read chip version */
	reg32 = cn_mcu_read32(core, CHIP_VERSION_INFO);
	pboardi->chip_version = (reg32 >> 15) & 0x01;
	cn_dev_core_debug(core, "chip ver: %d", pboardi->chip_version);

	/*chip type subsystem_id and mcu version*/
	reg32 = cn_mcu_read32(core, MCU_VERSION_INFO);
	cn_dev_core_debug(core, "7494: 0x%08X", reg32);

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

	pboardi->cluster_num = 4;
	pboardi->ipu_core_num = 4;
	pboardi->mem_channel = 4;

	/*board serial number*/
	reg32 = cn_mcu_read32(core, MCU_SN_INFO_LOW);
	a_type_board_symbol = (reg32 >> A_TYPE_BOARD_SHIFT)
		& A_TYPE_BOARD_MASK;
	serial_num = reg32;
	reg32 = cn_mcu_read32(core, MCU_SN_INFO_HIGH) & 0xFFFF;
	serial_num |= ((u64)reg32 << 32);
	cn_dev_core_info(core, "board serial: %016llX", serial_num);
	pboardi->serial_num = serial_num;

	pboardi->gdma_mask = 0x0;
	pboardi->platform = MLU_PLAT_ASIC;

	/*uuid*/
	memset(pboardi->uuid, 0, CNDRV_UUID_SIZE);
	memcpy(pboardi->uuid, &serial_num, CNDRV_UUID_SIZE >> 1);

	pboardi->BA_serial_num = 0;
	pboardi->BA_mcu_fw_ver = 0;
	pboardi->slot_id = 0;
	pboardi->qdd_status = 0;
	pboardi->chip_id = 0;
	pboardi->secure_mode = NORMAL_BOOT;
	memset(pboardi->soc_id.soc_id_data, 0, SOC_ID_SIZE);

	core->die_cnt = 1;
	index = subsystem_id - TABLE_BASE;
	if (index >= board_model_table_size || index < 0) {
		cn_xid_err(core, XID_MCU_ERR, "mcu subsystem_id %#x error", subsystem_id);
		core->board_model = MLU270_EVB;
		core->board_info.board_idx = CN_MLU270_UNKNOWN_TYPE;
		goto out;
	}

	model = mlu270_board_model_table[index].board_model_val;
	board_idx = mlu270_board_model_table[index].board_info_idx;
	if (model < 0 || board_idx == CN_MLU270_UNKNOWN_TYPE) {
		cn_xid_err(core, XID_MCU_ERR,
			"mcu subsystem_id %#x model %#x error", subsystem_id, model);
		core->board_model = MLU270_EVB;
		core->board_info.board_idx = CN_MLU270_UNKNOWN_TYPE;
		goto out;
	}

	if (model == MLU270_S4) {
		if (a_type_board_symbol == 0x2) {
			core->board_model = MLU270_S4a;
			core->board_info.board_idx = CN_MLU270_S4a;
		} else {
			core->board_model = MLU270_S4;
			core->board_info.board_idx = CN_MLU270_S4;
		}
	} else {
		core->board_model = model;
		core->board_info.board_idx = board_idx;
	}

out:

	strcpy(pboardi->board_model_name,
		mlu270_basic_info_table[core->board_info.board_idx].board_model_name);
	pboardi->peak_power = mlu270_basic_info_table[core->board_info.board_idx].peak_power;
	pboardi->min_power_cap_ctrl = mlu270_basic_info_table[core->board_info.board_idx].min_power_cap_ctrl;
	if (pboardi->min_power_cap_ctrl) {
		pboardi->min_power_cap = pboardi->min_power_cap_ctrl;
	} else {
		pboardi->min_power_cap = pboardi->peak_power / 2;
	}
	pboardi->min_power_cap_dec = 0;
	pboardi->max_power_cap_dec = 0;

	cn_dev_core_info(core, "board_model_name %s subsystem_id %#x, board_model %#x, peak_power %#x",
		pboardi->board_model_name, subsystem_id, core->board_model, pboardi->peak_power);
	cn_dev_core_info(core, "board_idx %d", core->board_info.board_idx);

	pboardi->bandwidth = mlu270_basic_info_table[core->board_info.board_idx].bandwidth;
	pboardi->bandwidth_decimal = mlu270_basic_info_table[core->board_info.board_idx].bandwidth_decimal;
	pboardi->platform_id = mlu270_basic_info_table[core->board_info.board_idx].platform_id;

	__mcu_read_power_cap_mlu270(core, &reg32, &dec_cap_value);
	if (reg32)
		cn_dev_core_info(core, "Board Power Cap to %u.%02uW", reg32, dec_cap_value);

	/* get board info */
	pboardi->bus_width = mlu270_board_info[core->board_info.board_idx][INFO_BUS_WIDTH];
	pboardi->ecc_support = mlu270_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
	pboardi->stack_size = mlu270_board_info[core->board_info.board_idx][INFO_STACK_SIZE];
	pboardi->sram_size = mlu270_board_info[core->board_info.board_idx][INFO_SRAM_SIZE];
	pboardi->cache_size = mlu270_board_info[core->board_info.board_idx][INFO_CACHE_SIZE];
	pboardi->kc_limit = mlu270_board_info[core->board_info.board_idx][INFO_KC_LIMIT];
	pboardi->o_kc_limit = mlu270_board_info[core->board_info.board_idx][INFO_O_KC_LIMIT];
	pboardi->rated_ipu_freq = mlu270_board_info[core->board_info.board_idx][INFO_MAX_IPU_FREQ];

	/* get ipu freq capping range */
	pboardi->min_ipu_freq_cap = mlu270_basic_info_table[core->board_info.board_idx].min_ipu_freq_cap;
	pboardi->max_ipu_freq_cap = mlu270_basic_info_table[core->board_info.board_idx].max_ipu_freq_cap;

	cn_dev_core_info(core, "bus_width %u ecc_support %u, stack_size %llu",
		pboardi->bus_width,	pboardi->ecc_support, pboardi->stack_size);

	cn_dev_core_info(core, "sram_size %llu, cache_size %llu, kc_limit %u, rated_ipu_freq %u,",
		pboardi->sram_size, pboardi->cache_size, pboardi->kc_limit, pboardi->rated_ipu_freq);

	ret = mcu_version_contorl(core,
							&pboardi->mcu_info,
							core->board_info.board_idx,
							cn_mlu270_mcu_ver_control);

	return ret;
}

/**
* @brief read mlu270 mcu power info
* @param pcore core layer handle
* @param *info power info struct
*
* based on variable temp buffer length,
* this function will alloc a buffer to save then.
* user must free the *temp buffer itself.
*
* @return
*/
int mcu_read_power_info_mlu270(void *pcore, struct board_power_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	s8 *temp_buf = NULL;
	s8 max_temp;

	temp_buf = cn_kzalloc(5 * sizeof(s8), GFP_KERNEL);
	if (!temp_buf) {
		cn_dev_core_err(core, "alloc buf fail");
		return -ENOMEM;
	}

	reg_data.data = cn_mcu_read32(core, 0x74a0);
	cn_dev_core_debug(core, "74a0: 0x%04X", reg_data.data);

	temp_buf[1] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	temp_buf[2] = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	temp_buf[3] = reg_data.bit.data2 - MCU_TEMP_CORRECTION_FACTOR;
	temp_buf[4] = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;

	max_temp = max3((s8)max(temp_buf[1], temp_buf[2]), temp_buf[3], temp_buf[4]);
	temp_buf[1] = temp_buf[2] = temp_buf[3] = temp_buf[4] = max_temp;

	reg_data.data = cn_mcu_read32(core, 0x74a4);
	cn_dev_core_debug(core, "74a4: 0x%04X", reg_data.data);

	/*top temperature*/
	temp_buf[0] = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;
	/*mul 25 to get rpm*/
	info->fan_speed = reg_data.bit.data2 * 100 / 0xff;
	info->board_power = reg_data.bit.data1;

	__mcu_read_power_cap_mlu270(core, &info->peak_power, &info->max_power_decimal);

	info->temperature_num = 5;
	info->temp = temp_buf;

	/* not support */
	info->edpp_count = 0;
	info->tdp_freq_capping_count = 0;

	return 0;
}

/**
* @brief read mlu270 ipu freq
* @param pcore core layer handle
* @param *freq ipu freq info return
*
* @return
*/
int mcu_read_ipu_freq_mlu270(void *pcore, struct ipu_freq_info *info)
{
	u32 cur_fbdiv, cur_fracdiv, post_div;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;

	post_div = (cn_mcu_read32(pcore, PMU_IPU_PLLCFG0) >> 27) & 0x03;
	if (post_div == 0) {
		post_div = 3;
	}

	cur_fbdiv = cn_mcu_read32(pcore, PMU_IPU_FRAC_CUR_FBDIV)
			& 0xfff;
	cur_fracdiv = cn_mcu_read32(pcore, PMU_IPU_FRAC_CUR_FRACDIV)
			& 0xffffff;

	info->ipu_freq = DIV_ROUND_CLOSEST((cur_fracdiv * 25), 0xffffff * post_div) +
			DIV_ROUND_CLOSEST(cur_fbdiv * 25, post_div);

	info->ipu_overtemp_dfs_flag = 0;
	info->ipu_fast_dfs_flag = 0;
	info->rated_ipu_freq = pboardi->rated_ipu_freq;

	return 0;
}

int mcu_read_max_temp_mlu270(void *pcore, int *max_temp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	int temp_value;

	*max_temp = -MCU_TEMP_CORRECTION_FACTOR;
	/* memsys0 temperature */
	reg_data.data = cn_mcu_read32(core, MCU_MSG_INFO0);
	temp_value = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* memsys1 temperature */
	temp_value = reg_data.bit.data2 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* memsys2 temperature */
	temp_value = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* memsys3 temperature */
	temp_value = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* top temperature */
	reg_data.data = cn_mcu_read32(core, MCU_MSG_INFO1);
	temp_value = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	return 0;
}

int mcu_read_over_temp_flag_mlu270(void *pcore, int *poweroff_flag)
{
	u32 reg32 = 0;

	reg32 = cn_mcu_read32(pcore, MCU_MSG_INFO1);
	*poweroff_flag = (reg32 & 0x40) >> 6;

	return 0;
}

/**
* brief set or read power capping status
* @param pcore core layer handle
* @param *pcinfo powercapping info struct
*
* @return
*/
int mcu_power_capping_mlu270(void *pcore, struct power_capping_info *pcinfo)
{
	int ret = 0;

	/* mlu270 not support set high precision power cap */
	pcinfo->high_precision_support = HIGH_PRECISION_POWER_CAP_SUPPORT;

	if (pcinfo->ops_type) {
		ret = __mcu_set_power_cap_mlu270(pcore, pcinfo->cap_value, pcinfo->dec_cap_value);
	} else {
		pcinfo->dec_cap_value = 0;
		ret = __mcu_read_power_cap_mlu270(pcore, &pcinfo->cap_value, &pcinfo->dec_cap_value);
	}

	return ret;
}

void mcu_exit_mlu270(void *mset)
{
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)mset;
	if (mcu_set) {
		mcu_set->core = NULL;
		mcu_set->mcu_ops = NULL;
	}
}

int mcu_read_exception_info_mlu270(void *pcore, struct exception_info *info, u8 klog)
{
	return 0;
}

static const struct cn_mcu_ops mcu_mlu270_ops = {
	.read_basic_info = mcu_read_basic_info_mlu270,
	.read_power_info = mcu_read_power_info_mlu270,
	.read_ipu_freq = mcu_read_ipu_freq_mlu270,
	.read_max_temp = mcu_read_max_temp_mlu270,
	.read_over_temp_flag = mcu_read_over_temp_flag_mlu270,
	.power_capping = mcu_power_capping_mlu270,
	.read_ddr_freq = NULL,
	.set_host_drv_status = NULL,
	.read_overtemp_freq = NULL,
	.mcu_exit = mcu_exit_mlu270,
	.get_overtemp_policy = NULL,
	.set_overtemp_policy = NULL,
	.read_uuid = NULL,
	.set_d2d_crc_err = NULL,
	.read_exception_info = mcu_read_exception_info_mlu270,
};

int mcu_init_mlu270(struct cn_mcu_set *mcu_set)
{
	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	mcu_set->mcu_ops = &mcu_mlu270_ops;
	return 0;
}



