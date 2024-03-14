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

#define MLU370_DDR_CNT                    (6)
#define MLU370_IPU_FREQ_SHIFT             (10)
#define MLU370_IPU_OVERTEMP_FREQ_SHIFT    (20)
#define MLU370_DDR_CAP_SHIFT              (4)
#define MLU370_DDR_TYPE_SHIFT             (28)
/* SECURE BOOT MODE */
#define MLU370_UNKNOWN_BOOT    0X0
#define MLU370_SECURE_BOOT     0X1
#define MLU370_NORMAL_BOOT     0X2
#define MLU370_SEC_BYPASS_BOOT 0X3
/* SOC ID INFO */
#define MLU370_SOC_ID_BASE_ADDR           (0x367008)
#define MLU370_SOC_ID_REG_CNT             (8)
#define MLU370_X8_IPU_VOLTAGE             (75U)
#define MLU370_VOLTAGE_REG_OFFSET         (0x83d45a8)

int __mcu_read_power_cap_mlu370(void *pcore, u32 *cap_value, u16 *dec_cap_value)
{
	u32 reg32 = 0;
	u32 mode;
	u32 power_cap = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;

	reg32 = cn_mcu_read32(pcore, IPC_23);

	power_cap = (reg32 & MLU370_MCU_POWER_CAP_MASK);
	mode = reg32 & MLU370_MCU_POWER_CAP_ENABLE;
	cn_dev_core_debug(core, "IPC_23: 0x%08X", reg32);

	if (power_cap > pboardi->peak_power) {
		*cap_value = pboardi->peak_power;
	} else {
		*cap_value = power_cap;
	}

	/* mlu370 power cap decimal */
	if (dec_cap_value)
		*dec_cap_value = 0;

	return 0;
}

int __mcu_set_power_cap_mlu370(void *pcore, u32 cap_value, u32 mode, u16 dec_cap_value)
{
	u32 reg32 = 0;
	u32 min_power_cap_ctrl = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	min_power_cap_ctrl =
		pboardi->min_power_cap_ctrl ? pboardi->min_power_cap_ctrl : pboardi->peak_power / 2;

	if (!cap_value) {

	} else if ((cap_value < min_power_cap_ctrl)
			|| (cap_value > pboardi->peak_power)) {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "User input cap value %u out of range!",
			cap_value);
		return -EINVAL;
	} else {
		if (mode != PERMANENT && mode != TEMPORARY && mode != DISABLE_PERMANENT) {
			cn_xid_err(core, XID_SW_NOTIFY_ERR, "Invalid user input mode %u !",
				mode);
			return -EINVAL;
		}

		switch (mode) {
		case TEMPORARY:
		case PERMANENT:
			cap_value = (cap_value & MLU370_MCU_POWER_CAP_MASK) |
				((mode & 0x1) << MLU370_MCU_POWER_CAP_ENABLE_SHIFT);
			atomic64_inc(&mcu_set->enable_power_cap_ref);
			break;
		case DISABLE_PERMANENT:
			cap_value =	(0x1 << MLU370_MCU_POWER_CAP_ENABLE_SHIFT);
			atomic64_inc(&mcu_set->disable_power_cap_ref);
			break;
		}
	}

	reg32 = cn_mcu_read32(pcore, IPC_23)
			& ~(MLU370_MCU_POWER_CAP_MASK | MLU370_MCU_POWER_CAP_ENABLE_MASK);
	reg32 = reg32 & ~(MLU370_MCU_POWER_CAP_MASK | MLU370_MCU_POWER_CAP_ENABLE_MASK);
	reg32 |= cap_value;

	cn_mcu_write32(pcore, IPC_23, reg32);

	reg32 = cn_mcu_read32(pcore, IPC_23) & 0xffff;
	if (reg32 != cap_value) {
		return -EINVAL;
	}
	return 0;
}

static int __mcu_set_ipu_voltage(struct cn_core_set *core,
	const u8 voltage)
{
	u32 reg32 = 0;
	u32 cnt = 20;

	/* Read ipu voltage */
	reg32 = reg_read32(core->bus_set, MLU370_VOLTAGE_REG_OFFSET);
	if (((reg32 >> 8) & 0xff) == voltage) {
		cn_dev_core_info(core, "IPU voltage is 0.%2uv", voltage);
		return 0;
	}

	/* set ipu voltage */
	reg32 = (0xa0 << 24) | voltage;
	cn_mcu_write32(core, IPC_25, reg32);

	/* readback */
	do {
		reg32 = reg_read32(core->bus_set, MLU370_VOLTAGE_REG_OFFSET);
		if (((reg32 >> 8) & 0xff) == voltage)
			return 0;
		msleep(500);
	} while (--cnt);

	return -EINVAL;
}

int mcu_read_basic_info_mlu370(void *pcore)
{
	int ret = 0;
	u32 reg32 = 0;
	u64 serial_num = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	u8 subsystem_id = 0;
	u8 sn_high_8bit;
	u8 chip_idx = 0;
	u8 die_cnt = 0;
	int cnt;
	u64 total_mem_size = 0;
	u8 rank = 0;
	int i = 0;

	cnt = 600;
	do {
		reg32 = cn_mcu_read32(core, IPC_1);
		if (((reg32 >> MLU370_MCU_DDRTRAINED_FLAG_SHIFT) & MLU370_MCU_DDRTRAINED_FLAG_MASK)
			< MLU370_MCU_DDRTRAINED_BOOT_DONE) {
			ret = -EINVAL;
		} else {
			cn_dev_core_info(core, "DDR Training Params set by MCU Finish");
			ret = 0;
			break;
		}

		if (cnt % 10 == 0)
			cn_dev_core_info(core, "Wait DDR Training status:%x!!", reg32);

		msleep(1000);
	} while (--cnt);
	if (!cnt) {
		cn_xid_err(core, XID_MCU_ERR, "Wait DDR Training Finish Timeout!!");
		cn_recommend(core, USER_RECOMMED);
		return ret;
	}

	reg32 = cn_mcu_read32(core, IPC_7);
	pboardi->chip_die_info[0].die_0 = reg32 & 0x3;
	pboardi->chip_die_info[0].die_1 = reg32 >> 3 & 0x3;
	pboardi->chip_die_info[1].die_0 = reg32 >> 6 & 0x3;
	pboardi->chip_die_info[1].die_1 = reg32 >> 9 & 0x3;
	memcpy(core->chip_die_info, pboardi->chip_die_info, sizeof(struct cn_die_info) * 2);

	die_cnt += pboardi->chip_die_info[chip_idx].die_0 ? 1:0;
	die_cnt += pboardi->chip_die_info[chip_idx].die_1 ? 1:0;

	core->die_cnt = die_cnt;

	reg32 = cn_mcu_read32(core, IPC_7);
	cn_dev_core_info(core, "IPC_7: 0x%08X", reg32);

	/*TODO According to the mcu reg*/
	pboardi->ddr_freq = 3200;
	/* ddr speed Mbps*/
	pboardi->ddr_speed = 6400;

	reg32 = cn_mcu_read32(core, IPC_8);
	/* rank cnt */
	rank = reg32 & 0x1 ? 2:1;

	/* IPC_8 4-15 bit*/
	pboardi->ddr_cap = ((reg32 >> MLU370_DDR_CAP_SHIFT) & 0xfff) * rank;
	/* IPC_8 28-31 bit*/
	pboardi->ddr_type = (reg32 >> MLU370_DDR_TYPE_SHIFT) & 0xf;

	/* read chip version */
	pboardi->chip_version = 0;
	cn_dev_core_info(core, "chip ver: %d", pboardi->chip_version);

	/*chip type subsystem_id and mcu version*/
	reg32 = cn_mcu_read32(core, IPC_6);
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
	pboardi->mem_channel = 1;

	/*board serial number*/
	reg32 = cn_mcu_read32(core, IPC_4);

	serial_num = reg32;
	reg32 = cn_mcu_read32(core, IPC_5) & 0xFFFF;
	serial_num |= ((u64)reg32 << 32);
	sn_high_8bit = (reg32 >> 8) & 0xFF;
	cn_dev_core_info(core, "board serial: %016llX", serial_num);
	pboardi->serial_num = serial_num;

	pboardi->gdma_mask = core->die_cnt > 1 ? 0x3 : 0xf;
	pboardi->platform = MLU_PLAT_ASIC;

	reg32 = cn_mcu_read32(core, IPC_0);
	pboardi->chip_id = (reg32 >> 9) & 0x1;
	/*uuid*/
	memset(pboardi->uuid, 0, CNDRV_UUID_SIZE);
	pboardi->uuid[15] = pboardi->chip_id;
	memcpy(pboardi->uuid, &serial_num, CNDRV_UUID_SIZE >> 1);

	/*BA serial number*/
	reg32 = cn_mcu_read32(core, IPC_11);
	serial_num = reg32;
	reg32 = cn_mcu_read32(core, IPC_12);

	/*MLU290 BA mcu firmware version */
	pboardi->BA_mcu_fw_ver = (reg32 >> 16) & 0xFFFF;

	serial_num |= ((u64)(reg32 & 0xFFFF) << 32);
	cn_dev_core_debug(core, "BA serial: %016llX", serial_num);
	pboardi->BA_serial_num = serial_num;

	reg32 = cn_mcu_read32(core, IPC_5);
	cn_dev_core_debug(core, "IPC_5: %016X", reg32);
	pboardi->slot_id = (reg32 & (0xff0000)) >> 16;

	reg32 = cn_mcu_read32(core, IPC_17);
	cn_dev_core_debug(core, "IPC_17: %016X", reg32);
	pboardi->qdd_status = reg32;

	switch (sn_high_8bit) {
	case 0x50:
		core->board_info.board_idx = CN_MLU370_EVB_D;
		total_mem_size = 0x600000000;
		break;
	case 0x51:
		core->board_info.board_idx = CN_MLU370_EVB_S;
		total_mem_size = 0x300000000;
		break;
	case 0x52:
		core->board_info.board_idx = CN_MLU370_X4L;
		total_mem_size = 0x600000000;
		break;
	case 0x53:
		core->board_info.board_idx = CN_MLU370_S4;
		total_mem_size = 0x600000000;
		break;
	case 0x54:
		core->board_info.board_idx = CN_MLU370_X8;
		total_mem_size = 0x600000000;
		if (__mcu_set_ipu_voltage(core, MLU370_X8_IPU_VOLTAGE)) {
			cn_xid_err(core, XID_MCU_ERR,
				"Change IPU voltage to 0.%02uv failed", MLU370_X8_IPU_VOLTAGE);
		} else {
			cn_dev_core_info(core,
				"Change IPU voltage to 0.%02uv successfully", MLU370_X8_IPU_VOLTAGE);
		}
		break;
	case 0x55:
	case 0x58:
		core->board_info.board_idx = CN_MLU370_M8;
		total_mem_size = 0xC00000000;
		break;
	case 0x56:
		core->board_info.board_idx = CN_MLU365_D2;
		total_mem_size = 0x300000000;
		break;
	case 0x57:
		core->board_info.board_idx = CN_MLU370_X4;
		total_mem_size = 0x600000000;
		break;
	case 0x59:
		core->board_info.board_idx = CN_MLU370_X4K;
		total_mem_size = 0x600000000;
		break;
	default:
		cn_xid_err(core, XID_MCU_ERR, "unknown board type : %#x", sn_high_8bit);
		core->board_model = CN_MLU370_EVB_S;
		core->board_info.board_idx = CN_MLU370_UNKNOWN_TYPE;
		total_mem_size = 0x300000000;
		break;
	}

	pboardi->total_memory =	total_mem_size;
	core->board_model = MLU370;

	strcpy(pboardi->board_model_name,
		mlu370_basic_info_table[core->board_info.board_idx].board_model_name);

	/*read TDP from mcu reg*/
	reg32 = cn_mcu_read32(core, IPC_9);
	pboardi->peak_power = reg32 & 0x3FF;
	pboardi->min_power_cap_ctrl = mlu370_basic_info_table[core->board_info.board_idx].min_power_cap_ctrl;
	if (pboardi->min_power_cap_ctrl) {
		pboardi->min_power_cap = pboardi->min_power_cap_ctrl;
	} else {
		pboardi->min_power_cap = pboardi->peak_power / 2;

	}
	pboardi->min_power_cap_dec = 0;
	pboardi->max_power_cap_dec = 0;

	pboardi->bandwidth = mlu370_basic_info_table[core->board_info.board_idx].bandwidth;
	pboardi->bandwidth_decimal = mlu370_basic_info_table[core->board_info.board_idx].bandwidth_decimal;
	pboardi->platform_id = core->die_cnt > 1 ? CN_CHIP_TYPE_C30S_DUAL_DIE : CN_CHIP_TYPE_C30S;

	/* get board info */
	pboardi->bus_width = mlu370_board_info[core->board_info.board_idx][INFO_BUS_WIDTH];
	pboardi->ecc_support = mlu370_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
	pboardi->stack_size = mlu370_board_info[core->board_info.board_idx][INFO_STACK_SIZE];
	pboardi->sram_size = mlu370_board_info[core->board_info.board_idx][INFO_SRAM_SIZE];
	pboardi->cache_size = mlu370_board_info[core->board_info.board_idx][INFO_CACHE_SIZE];
	pboardi->kc_limit = mlu370_board_info[core->board_info.board_idx][INFO_KC_LIMIT];
	pboardi->o_kc_limit = mlu370_board_info[core->board_info.board_idx][INFO_O_KC_LIMIT];
	pboardi->rated_ipu_freq = mlu370_board_info[core->board_info.board_idx][INFO_MAX_IPU_FREQ];

	/* get ipu freq capping range */
	pboardi->min_ipu_freq_cap = mlu370_basic_info_table[core->board_info.board_idx].min_ipu_freq_cap;
	pboardi->max_ipu_freq_cap = mlu370_basic_info_table[core->board_info.board_idx].max_ipu_freq_cap;

	cn_dev_core_info(core, "board_model_name %s, board_model %#x, tdp %#x",
		pboardi->board_model_name,  core->board_model, pboardi->peak_power);

	/* BIT 8-10 INDICATE BOOT MODE */
	pboardi->secure_mode = (cn_mcu_read32(core, IPC_1) >> 8) & 0x7;
	if (pboardi->secure_mode == MLU370_SECURE_BOOT) {
		for (i = 0; i < MLU370_SOC_ID_REG_CNT; i++) {
			reg32 = cn_mcu_read32(core, MLU370_SOC_ID_BASE_ADDR + sizeof(u32) * i);
			pboardi->soc_id.soc_id_reg[i] = reg32;
		}
	}

	ret = mcu_version_contorl(core,
			&pboardi->mcu_info,
			core->board_info.board_idx,
			cn_mlu370_mcu_ver_control);

	return ret;
}

int mcu_read_power_info_mlu370(void *pcore, struct board_power_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	s8 *temp_buf = NULL;

	temp_buf = cn_kzalloc(8 * sizeof(s8), GFP_KERNEL);
	if (!temp_buf) {
		cn_dev_core_err(core, "alloc buf fail");
		return -ENOMEM;
	}

	reg_data.data = cn_mcu_read32(core, IPC_13);
	cn_dev_core_debug(core, "IPC_13: 0x%04X", reg_data.data);

	/*chip temperature*/
	temp_buf[0] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	/*board temperature*/
	temp_buf[1] = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	/*mem temperature*/
	temp_buf[2] = reg_data.bit.data2 - MCU_TEMP_CORRECTION_FACTOR;

	reg_data.data = cn_mcu_read32(core, IPC_7);
	if (reg_data.data & (1 << 14)) {
		/*TODO MLU370 get fan speed*/
		info->fan_speed = 0;
	} else {
		info->fan_speed = 0;
	}

	reg_data.data = cn_mcu_read32(core, IPC_15);

	info->board_power = reg_data.data & 0xffff;
	info->board_power_decimal = 0;
	info->machine_power = (reg_data.data >> MCU_MACHINE_TEMP_SHIFT) & 0xffff;

	__mcu_read_power_cap_mlu370(core, &info->peak_power, &info->max_power_decimal);

	info->temperature_num = 3;
	info->temp = temp_buf;

	/* not support */
	info->edpp_count = 0;
	info->tdp_freq_capping_count = 0;

	return 0;
}

int mcu_read_ipu_freq_mlu370(void *pcore, struct ipu_freq_info *info)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	// struct cn_board_info *pboardi = &core->board_info;

	reg32 = cn_mcu_read32(pcore, IPC_22);
	info->ipu_freq = reg32 & 0xffff;
	info->die_ipu_freq.ipu_freq[0] = reg32 & 0xffff;
	info->die_ipu_freq.ipu_freq[1] = (reg32 >> 16) & 0xffff;
	info->die_ipu_freq.die_ipu_cnt = core->die_cnt;

	info->ipu_overtemp_dfs_flag = 0;

	info->ipu_fast_dfs_flag = 0;

	reg32 = cn_mcu_read32(pcore, IPC_9);
	/*IPC_9 OFFSET:10, SIZE:12*/
	info->rated_ipu_freq = reg32 >> MLU370_IPU_FREQ_SHIFT & 0xfff;

	return 0;
}

int mcu_read_max_temp_mlu370(void *pcore, int *max_temp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	int temp_value;

	*max_temp = -MCU_TEMP_CORRECTION_FACTOR;
	/* memsys temperature */
	reg_data.data = cn_mcu_read32(core, IPC_13);
	temp_value = reg_data.bit.data2 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* board temperature */
	temp_value = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* top temperature */
	temp_value = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	return 0;
}

int mcu_read_over_temp_flag_mlu370(void *pcore, int *poweroff_flag)
{
	u32 reg32 = 0;

	reg32 = cn_mcu_read32(pcore, IPC_0);
	*poweroff_flag = (reg32 & 0x2) >> 1;

	return 0;
}

int mcu_power_capping_mlu370(void *pcore, struct power_capping_info *pcinfo)
{
	int ret = 0;

	/* mlu370 not support set high precision power cap */
	pcinfo->high_precision_support = HIGH_PRECISION_POWER_CAP_SUPPORT;

	if (pcinfo->ops_type) {
		ret = __mcu_set_power_cap_mlu370(pcore, pcinfo->cap_value, pcinfo->mode, pcinfo->dec_cap_value);
	} else {
		ret = __mcu_read_power_cap_mlu370(pcore, &pcinfo->cap_value, &pcinfo->dec_cap_value);
	}

	return ret;
}

int mcu_set_host_driver_status_mlu370(void *pcore, int status)
{
	int ret = 0;
	u32 reg32 = 0;

	reg32 = cn_mcu_read32(pcore, IPC_2);

	if (status)
		reg32 |= (status & 0x01) << 10;
	else
		reg32 &= ~(0x01 << 10);

	cn_mcu_write32(pcore, IPC_2, reg32);

	return ret;
}

int mcu_set_d2d_crc_err_mlu370(void *pcore, u32 status)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	reg32 = cn_mcu_read32(pcore, IPC_2);
	if (status) {
		reg32 |= (1 << 16);
	}

	cn_mcu_write32(pcore, IPC_2, reg32);

	return 0;
}

int mcu_read_exception_info_mlu370(void *pcore, struct exception_info *info, u8 klog)
{
	return 0;
}

void mcu_exit_mlu370(void *mset)
{
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)mset;

	if (mcu_set) {
		mcu_set->core = NULL;
		mcu_set->mcu_ops = NULL;
	}
}

static const struct cn_mcu_ops mcu_mlu370_ops = {
	.read_basic_info = mcu_read_basic_info_mlu370,
	.read_power_info = mcu_read_power_info_mlu370,
	.read_ipu_freq = mcu_read_ipu_freq_mlu370,
	.read_max_temp = mcu_read_max_temp_mlu370,
	.read_over_temp_flag = mcu_read_over_temp_flag_mlu370,
	.power_capping = mcu_power_capping_mlu370,
	.read_ddr_freq = NULL,
	.set_host_drv_status = mcu_set_host_driver_status_mlu370,
	.mcu_exit = mcu_exit_mlu370,
	.get_overtemp_policy = NULL,
	.set_overtemp_policy = NULL,
	.read_uuid = NULL,
	.set_d2d_crc_err = mcu_set_d2d_crc_err_mlu370,
	.read_exception_info = mcu_read_exception_info_mlu370,
};

int mcu_init_mlu370(struct cn_mcu_set *mcu_set)
{
	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	mcu_set->mcu_ops = &mcu_mlu370_ops;

	return 0;
}
