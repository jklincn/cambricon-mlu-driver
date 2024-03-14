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

#define MCU_UUID_2_INFO_MLU220 (0x20020)
#define MCU_UUID_1_INFO_MLU220 (0x20024)
#define MCU_UUID_0_INFO_MLU220 (0x20028)

const u32 ddr_mem_cap[] = {4, 8, 1, 2};
#define DDR_TOTAL_MLU220(a) (ddr_mem_cap[a] * 1024ULL * 0x100000)

const u32 ddr_freq_mlu220[2] = {1866, 3733};

int __mcu_read_power_cap_mlu220(void *pcore, u32 *cap_value, u16 *dec_cap_value)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	reg32 = cn_mcu_read32(pcore, MCU_MSG_INFO3_MLU220);

	if (reg32 & MCU_POWER_CAP_ENABLE) {
		*cap_value = reg32 & MCU_POWER_CAP_MASK;
		*cap_value = clamp(*cap_value,
			(u32)(mlu220_basic_info_table[pboardi->board_idx].max_power_cap / 2),
			mlu220_basic_info_table[pboardi->board_idx].max_power_cap);
		atomic64_inc(&mcu_set->enable_power_cap_ref);
	} else {
		*cap_value = 0;
		atomic64_inc(&mcu_set->disable_power_cap_ref);
	}

	/* mlu220 power cap decimal */
	if (dec_cap_value) {
		reg32 = cn_mcu_read32(pcore, MCU_MSG_INFO3_MLU220);

		if (reg32 & MCU_POWER_CAP_ENABLE) {
			*dec_cap_value = 0;
		} else {
			*dec_cap_value =
				mlu220_basic_info_table[pboardi->board_idx].max_power_decimal;
		}
	}

	return 0;
}

int __mcu_set_power_cap_mlu220(void *pcore, u32 cap_value, u16 dec_cap_value)
{
	u32 reg32 = 0;
	u32 half_power;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;

	half_power = pboardi->peak_power / 2;

	if (!cap_value) {

	} else if ((cap_value < half_power)
			|| (cap_value > mlu220_basic_info_table[pboardi->board_idx].max_power_cap)) {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "User input cap value %u out of range!",
			cap_value);
		return -EINVAL;
	} else {
		cap_value = (cap_value & MCU_POWER_CAP_MASK)
				| MCU_POWER_CAP_ENABLE;
	}
	reg32 = cn_mcu_read32(pcore, MCU_MSG_INFO3_MLU220)
			& ~(MCU_POWER_CAP_MASK | MCU_POWER_CAP_ENABLE);
	reg32 |= cap_value;

	cn_mcu_write32(pcore, MCU_MSG_INFO3_MLU220, reg32);

	return 0;
}

int mcu_read_basic_info_mlu220(void *pcore)
{
	int ret = 0;
	int cnt;
	u32 ddr_freq;
	u32 reg32 = 0;
	u64 serial_num;
	u8 sn_high_8bit;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	u16 dec_cap_value = 0;

	cnt = 300;
	do {
		reg32 = cn_mcu_read32(core, MCU_BASIC_INFO_MLU220);
		if (!((reg32 >> MCU_DDRTRAINED_FLAG_SHIFT)
					& MCU_DDRTRAINED_FLAG_MASK)) {
			ret = -EINVAL;
		} else {
			cn_dev_core_info(core, "DDR Training Params set by MCU Finish\n");
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
	pboardi->chip_version = 0;
	ddr_freq =  (reg32 >> MCU_DDR_FREQ_SHIFT)
			& MCU_DDR_FREQ_MASK;
	pboardi->ddr_cap =  (reg32 >> MCU_DDR_CAPACITY_SHIFT)
			& MCU_DDR_CAPACITY_MASK;

	pboardi->total_memory = DDR_TOTAL_MLU220(pboardi->ddr_cap);

	pboardi->ddr_freq = ddr_freq_mlu220[ddr_freq&0x01];
	pboardi->ddr_speed = pboardi->ddr_freq;

	/*mcu version*/
	reg32 = cn_mcu_read32(core, MCU_VERSION_INFO_MLU220);
	cn_dev_core_debug(core, "version reg: 0x20008, val: 0x%08X\n", reg32);

	pboardi->chip_type = (reg32 >> MCU_MAIN_VERSION_SHIFT)
			& MCU_VERSION_MASK;
	pboardi->mcu_info.mcu_major = (reg32 >> MCU_SW_MAJOR_VER_SHIFT)
			& MCU_VERSION_MASK;
	pboardi->mcu_info.mcu_minor = (reg32 >> MCU_SW_MINOR_VER_SHIFT)
			& MCU_VERSION_MASK;
	/*split minor and build version from uint8*/
	pboardi->mcu_info.mcu_build = pboardi->mcu_info.mcu_minor & 0xF;
	pboardi->mcu_info.mcu_minor = (pboardi->mcu_info.mcu_minor & 0xF0) >> 4;
	pboardi->mcu_info.mcu_rc = 0;

	pboardi->cluster_num = 1;
	pboardi->ipu_core_num = 4;
	pboardi->mem_channel = 1;

	/*board serial number*/
	reg32 = cn_mcu_read32(core, MCU_SN_INFO_LOW_MLU220);
	serial_num = reg32;
	reg32 = cn_mcu_read32(core, MCU_SN_INFO_HIGH_MLU220) & 0xFFFF;
	serial_num |= ((u64)reg32 << 32);
	sn_high_8bit = (reg32 >> 8) & 0xFF;
	pboardi->board_type = sn_high_8bit;
	cn_dev_core_info(core, "board serial: %016llX\n", serial_num);
	pboardi->serial_num = serial_num;

	pboardi->BA_serial_num = 0;
	pboardi->BA_mcu_fw_ver = 0;
	pboardi->slot_id = 0;
	pboardi->qdd_status = 0;
	pboardi->chip_id = 0;

	pboardi->gdma_mask = 0x0;
	pboardi->platform = MLU_PLAT_ASIC;

	memset(pboardi->uuid, 0, CNDRV_UUID_SIZE);

	pboardi->secure_mode = NORMAL_BOOT;
	memset(pboardi->soc_id.soc_id_data, 0, SOC_ID_SIZE);

	core->die_cnt = 1;
	switch (sn_high_8bit) {
	case 0x30:
	case 0x31:
	case 0x32:
		core->board_model = MLU220_EVB;
		core->board_info.board_idx = CN_MLU220_EDGE;
		break;
	case 0x33:
	case 0x34:
		core->board_model = MLU220_M2;
		core->board_info.board_idx = CN_MLU220_M2;
		break;
	case 0x35:
	case 0x36:
		core->board_model = MLU220_EDGE;
		core->board_info.board_idx = CN_MLU220_SOM;
		break;
	case 0x37:
		core->board_model = MLU220_M2;
		core->board_info.board_idx = CN_MLU220_M2t;
		break;
	case 0x38:
		core->board_model = MLU220_M2i;
		core->board_info.board_idx = CN_MLU220_M2i;
		break;
	case 0x3A:
		core->board_model = MLU220_M2;
		core->board_info.board_idx = CN_MLU220_M2RA;
		break;
	case 0xC1:
		core->board_model = MLU220_EVB;
		core->board_info.board_idx = CN_MLU220_MXM;
		break;
	case 0xC3:
		core->board_model = MLU220_EVB;
		core->board_info.board_idx = CN_MLU220_MXMT;
		break;
	case 0xED:
		/* Only for U.2 */
		pboardi->serial_num = pboardi->serial_num >> 8;
		core->board_model = MLU220_M2;
		core->board_info.board_idx = CN_MLU220_U2;
		break;
	default:
		cn_xid_err(core, XID_MCU_ERR, "unknown board type : %#x", sn_high_8bit);
		if (core->device_id == MLUID_220_EDGE) {
			core->board_model = MLU220_EDGE;
			core->board_info.board_idx = CN_MLU220_EDGE;
		} else {
			core->board_model = MLU220_M2;
			core->board_info.board_idx = CN_MLU220_UNKNOWN_TYPE;
		}
		break;
	}

	/* update running mode */
	if (core->device_id == MLUID_220_EDGE) {
		core->board_model = MLU220_EDGE;
	}

	pboardi->peak_power = mlu220_basic_info_table[core->board_info.board_idx].peak_power;
	strcpy(pboardi->board_model_name, mlu220_basic_info_table[core->board_info.board_idx].board_model_name);
	pboardi->min_power_cap_ctrl = mlu220_basic_info_table[core->board_info.board_idx].min_power_cap_ctrl;
	if (pboardi->min_power_cap_ctrl) {
		pboardi->min_power_cap = pboardi->min_power_cap_ctrl;
	} else {
		pboardi->min_power_cap = pboardi->peak_power / 2;
	}
	pboardi->min_power_cap_dec = 0;
	pboardi->max_power_cap_dec = 0;

	pboardi->bandwidth = mlu220_basic_info_table[core->board_info.board_idx].bandwidth;
	pboardi->bandwidth_decimal = mlu220_basic_info_table[core->board_info.board_idx].bandwidth_decimal;
	pboardi->platform_id = mlu220_basic_info_table[core->board_info.board_idx].platform_id;

	cn_dev_core_info(core, "board_model_name %s, board_model %#x, peak_power %#x",
		pboardi->board_model_name,  core->board_model, pboardi->peak_power);

	__mcu_read_power_cap_mlu220(core, &reg32, &dec_cap_value);
	if (reg32)
		cn_dev_core_info(core, "Board Power Cap to %u.%02uW", reg32, dec_cap_value);

	/* get board info */
	pboardi->bus_width = mlu220_board_info[core->board_info.board_idx][INFO_BUS_WIDTH];
	pboardi->ecc_support = mlu220_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
	pboardi->stack_size = mlu220_board_info[core->board_info.board_idx][INFO_STACK_SIZE];
	pboardi->sram_size = mlu220_board_info[core->board_info.board_idx][INFO_SRAM_SIZE];
	pboardi->cache_size = mlu220_board_info[core->board_info.board_idx][INFO_CACHE_SIZE];
	pboardi->kc_limit = mlu220_board_info[core->board_info.board_idx][INFO_KC_LIMIT];
	pboardi->o_kc_limit = mlu220_board_info[core->board_info.board_idx][INFO_O_KC_LIMIT];
	pboardi->rated_ipu_freq = mlu220_board_info[core->board_info.board_idx][INFO_MAX_IPU_FREQ];

	/* get ipu freq capping range */
	pboardi->min_ipu_freq_cap = mlu220_basic_info_table[core->board_info.board_idx].min_ipu_freq_cap;
	pboardi->max_ipu_freq_cap = mlu220_basic_info_table[core->board_info.board_idx].max_ipu_freq_cap;

	cn_dev_core_info(core, "bus_width %u ecc_support %u, stack_size %llu",
		pboardi->bus_width,	pboardi->ecc_support, pboardi->stack_size);

	cn_dev_core_info(core, "sram_size %llu, cache_size %llu, kc_limit %u, rated_ipu_freq %u",
		pboardi->sram_size, pboardi->cache_size, pboardi->kc_limit, pboardi->rated_ipu_freq);

	ret = mcu_version_contorl(core,
							&pboardi->mcu_info,
							core->board_info.board_idx,
							cn_mlu220_mcu_ver_control);

	return ret;
}

/**
* @brief read mlu220 mcu power info
* @param pcore core layer handle
* @param *info power info struct
*
* based on variable temp buffer length,
* this function will alloc a buffer to save then.
* user must free the *temp buffer itself.
*
* @return
*/
int mcu_read_power_info_mlu220(void *pcore, struct board_power_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	s8 *temp_buf = NULL;

	temp_buf = cn_kzalloc(2 * sizeof(s8), GFP_KERNEL);
	if (!temp_buf) {
		cn_dev_core_err(core, "alloc buf fail\n");
		return -ENOMEM;
	}

	reg_data.data = cn_mcu_read32(core, MCU_MSG_INFO0_MLU220);
	cn_dev_core_debug(core, "MCU_MSG_INFO0, reg: 0x20014,val: 0x%04X\n", reg_data.data);
	/* memsys0 temp */
	temp_buf[1] = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;

	reg_data.data = cn_mcu_read32(core, MCU_MSG_INFO1_MLU220);
	cn_dev_core_debug(core, "MCU_MSG_INFO1, reg: 0x20018,val: 0x%04X\n", reg_data.data);
	/* board temp */
	temp_buf[0] = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;
	/*mul 25 to get rpm*/
	info->fan_speed = reg_data.bit.data2 * 100 / 0xff;
	info->board_power = reg_data.bit.data1;

	reg_data.data = cn_mcu_read32(core, MCU_MSG_INFO2_MLU220);
	cn_dev_core_debug(core, "MCU_MSG_INFO2, reg: 0x2001c,val: 0x%04X\n", reg_data.data);
	info->board_power_decimal = ((reg_data.bit.data3 & 0xf0) >> 4)*10 +
								(reg_data.bit.data3 & 0x0f);
	if (info->board_power_decimal > 99) {
		cn_dev_core_err(core, "board power decimal %d illegal",
				info->board_power_decimal);
	}

	__mcu_read_power_cap_mlu220(core, &info->peak_power, &info->max_power_decimal);

	info->temperature_num = 2;
	info->temp = temp_buf;

	/* not support */
	info->edpp_count = 0;
	info->tdp_freq_capping_count = 0;

	return 0;
}

/**
* @brief read mlu220 ipu freq
* @param pcore core layer handle
* @param *freq ipu freq info return
*
* @return
*/
int mcu_read_ipu_freq_mlu220(void *pcore, struct ipu_freq_info *info)
{
	u32 cur_fbdiv, cur_fracdiv, post_div;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data = {0};
	struct cn_board_info *pboardi = &core->board_info;

	post_div = (cn_mcu_read32(pcore, PMU_IPU_PLLCFG0_MLU220) >> 27) & 0x03;
	if (post_div == 0) {
		post_div = 4;
	}

	cur_fbdiv = cn_mcu_read32(pcore, PMU_IPU_FRAC_CUR_FBDIV_MLU220)
			& 0xfff;
	cur_fracdiv = cn_mcu_read32(pcore, PMU_IPU_FRAC_CUR_FRACDIV_MLU220)
			& 0xffffff;

	info->ipu_freq = DIV_ROUND_CLOSEST((cur_fracdiv * 25), 0xffffff * post_div) +
			DIV_ROUND_CLOSEST(cur_fbdiv * 25, post_div);

	reg_data.data = cn_mcu_read32(core, MCU_MSG_INFO2_MLU220);
	cn_dev_core_debug(core, "MCU_MSG_INFO2, reg: 0x2001c,val: 0x%04X\n", reg_data.data);

	info->ipu_overtemp_dfs_flag = reg_data.data >> MCU_IPUDFS_TEMP_DFS_SHIFT & 0x01;
	info->ipu_fast_dfs_flag = reg_data.data >> MCU_IPUDFS_FAST_DFS_SHIFT & 0x01;
	info->rated_ipu_freq = pboardi->rated_ipu_freq;

	return 0;
}

int mcu_read_max_temp_mlu220(void *pcore, int *max_temp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	int temp_value;

	*max_temp = -MCU_TEMP_CORRECTION_FACTOR;
	/* memsys0 temperature */
	reg_data.data = cn_mcu_read32(core, MCU_MSG_INFO0_MLU220);
	temp_value = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* board temperature */
	reg_data.data = cn_mcu_read32(core, MCU_MSG_INFO1_MLU220);
	temp_value = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	return 0;
}

/**
* brief set or read power capping status
* @param pcore core layer handle
* @param *pcinfo powercapping info struct
*
* @return
*/
int mcu_power_capping_mlu220(void *pcore, struct power_capping_info *pcinfo)
{
	int ret = 0;

	/* mlu220 not support set high precision power cap */
	pcinfo->high_precision_support = HIGH_PRECISION_POWER_CAP_SUPPORT;

	if (pcinfo->ops_type) {
		ret = __mcu_set_power_cap_mlu220(pcore, pcinfo->cap_value, pcinfo->dec_cap_value);
	} else {
		pcinfo->dec_cap_value = 0;
		ret = __mcu_read_power_cap_mlu220(pcore, &pcinfo->cap_value, &pcinfo->dec_cap_value);
	}

	return ret;
}

void mcu_exit_mlu220(void *mset)
{
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)mset;
	if (mcu_set) {
		mcu_set->core = NULL;
		mcu_set->mcu_ops = NULL;
	}
}

int mcu_read_uuid_mlu220(void *pcore, unsigned char *uuid)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pbrdinfo = &core->board_info;
	u32 reg32 = 0;

	if (IS_ERR_OR_NULL(uuid)) {
		cn_dev_core_err(core, "invalid uuid buffer");
		return -EINVAL;
	}

	/*220 uuid*/
	if (!pbrdinfo->uuid_ready) {
		reg32 = cn_mcu_read32(core, MCU_UUID_0_INFO_MLU220);
		memcpy(&pbrdinfo->uuid[0], &reg32, 4);

		reg32 = cn_mcu_read32(core, MCU_UUID_1_INFO_MLU220);
		memcpy(&pbrdinfo->uuid[4], &reg32, 4);

		reg32 = (cn_mcu_read32(core, MCU_UUID_2_INFO_MLU220) >> UUID_2_SHIFT) & UUID_2_MASK;
		pbrdinfo->uuid[8] = reg32;
		pbrdinfo->uuid_ready = 1;
	}

	memcpy(uuid, pbrdinfo->uuid, CNDRV_UUID_SIZE);

	return 0;
}

int mcu_read_exception_info_mlu220(void *pcore, struct exception_info *info, u8 klog)
{
	return 0;
}

static const struct cn_mcu_ops mcu_mlu220_ops = {
	.read_basic_info = mcu_read_basic_info_mlu220,
	.read_power_info = mcu_read_power_info_mlu220,
	.read_ipu_freq = mcu_read_ipu_freq_mlu220,
	.read_max_temp = mcu_read_max_temp_mlu220,
	.read_over_temp_flag = NULL,
	.power_capping = mcu_power_capping_mlu220,
	.read_ddr_freq = NULL,
	.set_host_drv_status = NULL,
	.read_overtemp_freq = NULL,
	.mcu_exit = mcu_exit_mlu220,
	.get_overtemp_policy = NULL,
	.set_overtemp_policy = NULL,
	.read_uuid = mcu_read_uuid_mlu220,
	.set_d2d_crc_err = NULL,
	.read_exception_info = mcu_read_exception_info_mlu220,
};

int mcu_init_mlu220(struct cn_mcu_set *mcu_set)
{
	cn_dev_debug("[%s] MLU220 platform\n", __func__);

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null\n");
		return -EINVAL;
	}
	mcu_set->mcu_ops = &mcu_mlu220_ops;
	return 0;
}



