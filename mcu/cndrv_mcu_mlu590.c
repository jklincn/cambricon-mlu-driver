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
#include "cndrv_mcc.h"
#include "cndrv_debug.h"
#include "../core/version.h"
#include "mcu.h"
#include "cndrv_trans.h"

#define MLU590_MCU_POWER_CAP_MASK	0x3FF
#define MLU590_MCU_POWER_CAP_ENABLE	0x8000
#define MLU590_MCU_POWER_CAP_ENABLE_SHIFT	(15)
#define MLU590_MCU_POWER_CAP_ENABLE_MASK	(0X1 << MLU590_MCU_POWER_CAP_ENABLE_SHIFT)

/* SECURE BOOT MODE */
#define MLU590_UNKNOWN_BOOT    0X0
#define MLU590_SECURE_BOOT     0X1
#define MLU590_NORMAL_BOOT     0X2
#define MLU590_SEC_BYPASS_BOOT 0X3
/* SOC ID INFO */
#define MLU590_SOC_ID_BASE_ADDR           (0x929008)
#define MLU590_SOC_ID_REG_CNT             (8)

#define MLU590_A6_HBM_COUNT               (6)
#define MLU590_A5_HBM_COUNT               (5)
#define MLU590_A3_HBM_COUNT               (3)

/*
    Top hbm id      0    1    2    3    4    5
    Addrdec hbm id  0    2    1    4    3    5
*/
const u32 hbm_topid_to_decid[MLU590_HBM_CHANNEL_COUNT] = {0, 2, 1, 4, 3, 5};
const char* chip_type[] = {"A6", "A5", "A3", "UNKNOW"};

int __mcu_read_power_cap_mlu590(void *pcore, u32 *cap_value, u16 *dec_cap_value)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg32 = cn_mcu_read32(core, MLU590_IPC_38);
	cn_dev_core_debug(core, "MLU590_IPC_38: 0x%08X", reg32);
	*cap_value = reg32 & 0x3FF;

	/* MLU590 power cap decimal */
	if (dec_cap_value)
		*dec_cap_value = 0;

	return 0;
}

int __mcu_set_power_cap_mlu590(void *pcore, u32 cap_value, u32 mode, u16 dec_cap_value)
{
	u32 reg32 = 0;
	u32 min_power_cap_ctrl = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	min_power_cap_ctrl =
		pboardi->min_power_cap_ctrl ? pboardi->min_power_cap_ctrl : pboardi->peak_power / 2;

	if (mode == DISABLE_PERMANENT) {
		cap_value =	(0x1 << MLU590_MCU_POWER_CAP_ENABLE_SHIFT);
		atomic64_inc(&mcu_set->disable_power_cap_ref);
	} else if (mode == PERMANENT) {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "No support mode %u !",
			mode);
		return -EPERM;
	} else if (mode == TEMPORARY) {
		if ((cap_value < min_power_cap_ctrl)
			|| (cap_value > pboardi->peak_power)) {
			cn_xid_err(core, XID_SW_NOTIFY_ERR, "User input cap value %u out of range!",
				cap_value);
			return -EINVAL;
		} else {
			cap_value = (cap_value & MLU590_MCU_POWER_CAP_MASK) |
				((0x1) << MLU590_MCU_POWER_CAP_ENABLE_SHIFT);
		}
		atomic64_inc(&mcu_set->enable_power_cap_ref);
	} else {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "Invalid user input mode %u !",
			mode);
		return -EINVAL;
	}

	reg32 = cn_mcu_read32(pcore, MLU590_IPC_37)
			& ~(MLU590_MCU_POWER_CAP_MASK | MLU590_MCU_POWER_CAP_ENABLE_MASK);
	reg32 = reg32 & ~(MLU590_MCU_POWER_CAP_MASK | MLU590_MCU_POWER_CAP_ENABLE_MASK);
	reg32 |= cap_value;
	reg32 &= 0x83FF;
	cn_mcu_write32(pcore, MLU590_IPC_37, reg32);

	reg32 = cn_mcu_read32(pcore, MLU590_IPC_37) & 0x83FF;
	if (reg32 != cap_value) {
		return -EINVAL;
	}

	return 0;
}

static const char *mlu590_hbm_init_status[4] = {
	"HBM init successfully",
	"HBM init failed",
	"HBM address repair failed",
	"HBM init timeout"
};

int mcu_read_basic_info_mlu590(void *pcore)
{
	int ret = 0;
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	u64 serial_num = 0;
	u32 sn_high_16bit = 0;
	u8 special_info = 0;
	u64 total_mem_size = 0;
	u64 hbm_capacity = 0;
	u16 max_power_decimal = 0;
	int i = 0;
	u64 mem_mask = 0;
	u32 hbm_topid = 0;
	u32 mem_mask_dec = 0;

	/* hbm ready */
	int cnt = 0;

	cnt = 1200;
	do {
		reg32 = cn_mcu_read32(core, MLU590_IPC_2);
		if (((reg32 >> MLU590_MCU_DDRTRAINED_FLAG_SHIFT) & MLU590_MCU_DDRTRAINED_FLAG_MASK)
			< MLU590_MCU_DDRTRAINED_BOOT_DONE) {
			ret = -EINVAL;
		} else {
			cn_dev_core_info(core, "DDR Training Params set by MCU Finish");
			ret = 0;
			break;
		}

		if (cnt % 10 == 0)
			cn_dev_core_info(core, "Wait DDR Training status:%x!!", reg32);

		msleep(500);
	} while (--cnt);
	if (!cnt) {
		cn_xid_err(core, XID_HBM_ERR, "Wait DDR Training Finish Timeout!!");
		goto err;
	}

	reg32 = (cn_mcu_read32(core, MLU590_IPC_2) >> 16) & 0x3;
	if (reg32) {
		cn_xid_err(core, XID_HBM_ERR, "HBM Init Status 0x%x, %s", reg32, mlu590_hbm_init_status[reg32 & 0x3]);
		ret = -EPERM;
		goto err;
	}

	/* board info */
	core->board_model = MLU590;
	/* set default */
	reg32 = cn_mcu_read32(core, MLU590_IPC_8);
	core->fw_support_lt_freq_cap = reg32 >> 26 & 0x1;
	core->drv_support_lt_freq_cap = cn_core_lt_cap_enable();
	cn_dev_core_info(core, "FW Support LT Freq Capping  : [%s]", core->fw_support_lt_freq_cap ? "Yes" : "No");
	cn_dev_core_info(core, "DRV Support LT Freq Capping : [%s]", core->drv_support_lt_freq_cap ? "Yes" : "No");

	/* chip type subsystem_id and mcu version */
	pboardi->chip_version = 0;
	reg32 = cn_mcu_read32(core, MLU590_IPC_7);

	/* slot id */
	pboardi->slot_id = (reg32 >> 16) & 0xFF;

	pboardi->chip_type = (reg32 >> 24) & 0xFF;
	pboardi->mcu_info.mcu_major = (reg32 >> 12)
		& 0xF;
	pboardi->mcu_info.mcu_minor = (reg32 >> 8)
		& 0xF;

	/* MUC Version, build version */
	pboardi->mcu_info.mcu_build = (reg32 >> 4)
		& 0xF;
	reg32 = cn_mcu_read32(core, MLU590_IPC_19);
	pboardi->mcu_info.mcu_build |= ((reg32 >> 28) & 0xF) << 4;

	/* rc version duplicate */
	pboardi->mcu_info.mcu_rc = 0;

	/* chip info */
	core->die_cnt = 1;
	pboardi->chip_id = 0;

	/* Boot Mode */
	reg32 = cn_mcu_read32(core, MLU590_IPC_2);
	pboardi->secure_mode = (reg32 >> 7) & 0x7;
	memset(pboardi->soc_id.soc_id_data, 0, SOC_ID_SIZE);

	/* ipu info */
	pboardi->cluster_num = 12;
	pboardi->ipu_core_num = 4;

	/* mem info */
	pboardi->mem_channel = 1;

	/* dev sn */
	reg32 = cn_mcu_read32(core, MLU590_IPC_13);
	serial_num = reg32;
	reg32 = cn_mcu_read32(core, MLU590_IPC_14);
	serial_num |= (u64)reg32 << 32;
	pboardi->serial_num = serial_num;

	/* ba sn */
	reg32 = cn_mcu_read32(core, MLU590_IPC_15);
	serial_num = reg32;
	reg32 = cn_mcu_read32(core, MLU590_IPC_16);
	serial_num |= (u64)reg32 << 32;
	pboardi->BA_serial_num = serial_num;

	/*resouce*/
	reg32 = cn_mcu_read32(core, MLU590_IPC_5);
	cn_dev_core_info(core, "Resource Info: 0x%x", reg32);
	pboardi->ipusys_mask = reg32 & 0x3f;

	/*resouce ext*/
	reg32 = cn_mcu_read32(core, MLU590_IPC_59);
	cn_dev_core_info(core, "Resource Ext Info: 0x%x", reg32);
	if ((reg32 >> 31) & 0x1) {
		pboardi->platform = (reg32 >> 24) & 0x7;
		cn_dev_core_info(core, "Platform: 0x%x", pboardi->platform);
		if (pboardi->platform >= MLU_PLAT_UNKNOW) {
			pboardi->platform = MLU_PLAT_UNKNOW;
		}
		pboardi->gdma_mask = (reg32 >> 16) & 0xff;
	} else {
		pboardi->platform = MLU_PLAT_ASIC;
		pboardi->gdma_mask = 0x3f;
	}

	reg32 = cn_mcu_read32(core, MLU590_CFG);
	hbm_capacity = (((reg32 >> 4) & 0x1) ? 16:8);
	cn_dev_core_info(core, "HBM Capacity: %llu GB", hbm_capacity);
	hbm_topid = (reg32 >> 12) & 0x7;
	cn_dev_core_info(core, "HBM Top ID: %u", hbm_topid);

	reg32 = cn_mcu_read32(core, MLU590_IPC_5);
	mem_mask = (reg32 >> 6) & 0x3f;
	reg32 = bitmap_weight((unsigned long *)&mem_mask, 32);
	pboardi->hbm_cnt = reg32;
	pboardi->noc_mode = NOC_MODE1;

	reg32 = cn_mcu_read32(core, MLU590_CFG);
	cn_dev_core_info(core, "CHIP Type: %s", chip_type[reg32 & 0x3]);

	if (pboardi->hbm_cnt != MLU590_A6_HBM_COUNT) {
		if (pboardi->hbm_cnt == MLU590_A5_HBM_COUNT) {
			pboardi->bad_hbm_mask = 1 << hbm_topid_to_decid[hbm_topid];
			pboardi->hbm_mask = 0x3f;
			pboardi->hbm_mask &= ~(1 << hbm_topid_to_decid[hbm_topid]);
		} else if (pboardi->hbm_cnt == MLU590_A3_HBM_COUNT) {
			pboardi->bad_hbm_mask = 1 << hbm_topid_to_decid[hbm_topid];
			pboardi->hbm_mask = 0x3f;
			pboardi->hbm_mask &= ~(1 << hbm_topid_to_decid[hbm_topid]);
			pboardi->hbm_mask &= ~((1U << 2) | (1U << 3));
		} else {
			pboardi->bad_hbm_mask = 1 << hbm_topid_to_decid[hbm_topid];
			cn_dev_core_warn(core, "Configed top HBM Mask 0x%llx", mem_mask);
			mem_mask_dec = 0;
			for (i = 0; i < MLU590_A6_HBM_COUNT; i++) {
				if ((mem_mask >> i) & 0x1) {
					mem_mask_dec |= (u32)1 << hbm_topid_to_decid[i];
				}
			}
			mem_mask_dec &= ~((u32)1 << hbm_topid_to_decid[hbm_topid]);
			pboardi->hbm_mask = mem_mask_dec;
		}
		cn_dev_core_info(core, "HBM Slot: 0x%x", pboardi->bad_hbm_mask);
	} else {
		pboardi->hbm_mask = 0x3f;
		pboardi->bad_hbm_mask = 0;
	}

	cn_dev_core_info(core, "HBM Mask : 0x%x", pboardi->hbm_mask);
	total_mem_size = (u64)0x40000000 * hbm_capacity * pboardi->hbm_cnt;
	cn_dev_core_info(core, "Total HBM Capacity: 0x%llx B", total_mem_size);

	sn_high_16bit = (pboardi->serial_num >> 48) & 0xffff;
	pboardi->board_type = sn_high_16bit;

	special_info = (pboardi->serial_num >> 40) & 0xff;
	pboardi->special_info = special_info;

	switch (sn_high_16bit) {
	case SUBSYS_MLU585: /*MLU585*/
		/* HBM freq */
		pboardi->ddr_freq = 1600;
		switch (special_info)
		{
		case 0:
			core->board_info.board_idx = CN_MLU585;
			break;
		case 1:
			core->board_info.board_idx = CN_MLU585_V1;
			break;
		default:
			core->board_info.board_idx = CN_MLU585;
			break;
		}
		break;
	case SUBSYS_MLU590_H8: /*MLU590-H8*/
		/* HBM freq */
		pboardi->ddr_freq = 1600;
		core->board_info.board_idx = CN_MLU590_H8;
		break;
	case SUBSYS_MLU590_M9U: /*MLU590-M9U*/
		if (core->drv_support_lt_freq_cap && !core->fw_support_lt_freq_cap) {
			cn_xid_err(core, XID_MCU_ERR, "Firmware NOT Support LT Freq Capping");
			return -EPERM;
		}
		/* HBM freq */
		pboardi->ddr_freq = 1800;
		switch (special_info)
		{
		case SPECIAL_M9:
			core->board_info.board_idx = CN_MLU590_M9;
			break;
		case SPECIAL_M9U:
			core->board_info.board_idx = CN_MLU590_M9U;
			break;
		case SPECIAL_M9L:
			core->board_info.board_idx = CN_MLU590_M9L;
			break;
		case SPECIAL_M9B:
			pboardi->ddr_freq = 1600;
			core->board_info.board_idx = CN_MLU590_M9B;
			break;
		case SPECIAL_M9C:
			pboardi->ddr_freq = 1600;
			core->board_info.board_idx = CN_MLU590_M9C;
			break;
		default:
			core->board_info.board_idx = CN_MLU590_UNKNOWN_TYPE;
			break;
		}
		break;
	case SUBSYS_MLU590_E:
		/* HBM freq */
		pboardi->ddr_freq = 1600;
		core->board_info.board_idx = CN_MLU590_E;
		pboardi->noc_mode = NOC_MODE2;
		break;
	default:
		core->board_info.board_idx = CN_MLU590_UNKNOWN_TYPE;
		total_mem_size = 0x1400000000;/*80GB*/
		/* HBM freq */
		pboardi->ddr_freq = 1600;
		cn_xid_err(core, XID_MCU_ERR, "unknown board type : %#x", sn_high_16bit);
		break;
	}

	pboardi->total_memory =	total_mem_size;
	strcpy(pboardi->board_model_name, mlu590_basic_info_table[core->board_info.board_idx].board_model_name);
	/* hbm speed */
	reg32 = cn_mcu_read32(core, MLU590_IPC_3);
	pboardi->ddr_speed = ((reg32 >> 16) & 0xff) * 100;
	pboardi->ddr_cap = hbm_capacity;
	pboardi->ddr_type = 0;

	/* tdp */
	reg32 = cn_mcu_read32(core, MLU590_IPC_11);
	pboardi->peak_power = reg32 & 0x3FF;
	if (!pboardi->peak_power)
		cn_xid_err(core, XID_MCU_ERR, "Invalid Thermal Design Power. IPC-38 %x", reg32);
	pboardi->min_power_cap_ctrl = mlu590_basic_info_table[core->board_info.board_idx].min_power_cap_ctrl;
	if (pboardi->min_power_cap_ctrl) {
		pboardi->min_power_cap = pboardi->min_power_cap_ctrl;
	} else {
		pboardi->min_power_cap = pboardi->peak_power / 2;
	}
	pboardi->min_power_cap_dec = 0;
	pboardi->max_power_cap_dec = 0;

	/* qdd status not support */
	pboardi->qdd_status = 0;

	/* uuid */
	memset(pboardi->uuid, 0, CNDRV_UUID_SIZE);

	pboardi->platform_id = mlu590_basic_info_table[core->board_info.board_idx].platform_id;

	/* pcie fw version */
	reg32 = cn_mcu_read32(core, MLU590_IPC_17);
	pboardi->pcie_fw_info = reg32 & 0xffff;

	/* mem bandwidth */
	pboardi->bandwidth =
		mlu590_basic_info_table[core->board_info.board_idx].bandwidth;
	pboardi->bandwidth_decimal =
		mlu590_basic_info_table[core->board_info.board_idx].bandwidth_decimal;

	/* get board info */
	pboardi->bus_width = mlu590_board_info[core->board_info.board_idx][INFO_BUS_WIDTH];
	pboardi->ecc_support = mlu590_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
	pboardi->stack_size = mlu590_board_info[core->board_info.board_idx][INFO_STACK_SIZE];
	pboardi->sram_size = mlu590_board_info[core->board_info.board_idx][INFO_SRAM_SIZE];
	pboardi->cache_size = mlu590_board_info[core->board_info.board_idx][INFO_CACHE_SIZE];
	pboardi->kc_limit = mlu590_board_info[core->board_info.board_idx][INFO_KC_LIMIT];
	pboardi->o_kc_limit = mlu590_board_info[core->board_info.board_idx][INFO_O_KC_LIMIT];
	pboardi->rated_ipu_freq = mlu590_board_info[core->board_info.board_idx][INFO_MAX_IPU_FREQ];

	/* get ipu freq capping range */
	pboardi->min_ipu_freq_cap = mlu590_basic_info_table[core->board_info.board_idx].min_ipu_freq_cap;
	pboardi->max_ipu_freq_cap = mlu590_basic_info_table[core->board_info.board_idx].max_ipu_freq_cap;

	cn_dev_core_info(core, "board_model_name %s, board_model %#x, tdp %#x",
		pboardi->board_model_name, core->board_model, pboardi->peak_power);

	/* BIT 7-9 INDICATE BOOT MODE */
	if (pboardi->secure_mode == MLU590_SECURE_BOOT) {
		for (i = 0; i < MLU590_SOC_ID_REG_CNT; i++) {
			reg32 = cn_mcu_read32(core, MLU590_SOC_ID_BASE_ADDR + sizeof(u32) * i);
			pboardi->soc_id.soc_id_reg[i] = reg32;
		}
	}

	__mcu_read_power_cap_mlu590(core, &reg32, &max_power_decimal);
	if (reg32)
		cn_dev_core_info(core, "Board Power Cap to %u.%02uW", reg32, max_power_decimal);

	return ret;

err:
	cn_recommend(core, USER_RECOMMED);
	return ret;
}


/**
 * @brief read mlu590 mcu power info
 * @param pcore core layer handle
 * @param *info power info struct
 *
 * based on variable temp buffer length,
 * this function will alloc a buffer to save then.
 * user must free the *temp buffer itself.
 *
 * @return
 */
int mcu_read_power_info_mlu590(void *pcore, struct board_power_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	s8 *temp_buf = NULL;
	u8 *perf_limit_buf = NULL;
	int ret = 0;
	u32 reg32 = 0;
	u16 *ic_freq = NULL;
	struct cn_board_info *pboardi = &core->board_info;
	u16 ipufreq_avg = 0;
	u32 i = 0;

	temp_buf = cn_kzalloc(8 * sizeof(s8), GFP_KERNEL);
	if (!temp_buf) {
		cn_dev_core_err(core, "alloc buf fail");
		return -ENOMEM;
	}

	perf_limit_buf = cn_kzalloc(CNDEV_PERF_LIMIT_MAX_COUNT * sizeof(u8), GFP_KERNEL);
	if (!perf_limit_buf) {
		cn_dev_core_err(core, "alloc buf fail");
		ret = -ENOMEM;
		goto PERF_LIMIT_MEM_ERR;
	}

	ic_freq = cn_kzalloc(MLU590_MAX_IPUCLUSTER_COUNT * sizeof(u16), GFP_KERNEL);
	if (!ic_freq) {
		cn_dev_core_err(core, "alloc freq buf fail");
		ret = -ENOMEM;
		goto IPUSYS_FREQ_MEM_ERR;
	}

	reg_data.data = cn_mcu_read32(core, MLU590_IPC_42);
	perf_limit_buf[CNDEV_PERF_LIMIT_TDP] =
		reg_data.data & 0x1;
	perf_limit_buf[CNDEV_PERF_LIMIT_POWER_CAPPING] =
		(reg_data.data >> 1) & 0x3;
	perf_limit_buf[CNDEV_PERF_LIMIT_FREQ_LIMIT] =
		(reg_data.data >> 3) & 0x3;
	perf_limit_buf[CNDEV_PERF_LIMIT_FREQ_LOCK] =
		(reg_data.data >> 5) & 0x1;
	perf_limit_buf[CNDEV_PERF_LIMIT_POWER_BRAKE] =
		(reg_data.data >> 6) & 0x3;
	perf_limit_buf[CNDEV_PERF_LIMIT_OVERTEMP_UNDERCLOCKING] =
		(reg_data.data >> 8) & 0x1;

	info->perf_limit = perf_limit_buf;
	info->perf_limit_num = CNDEV_PERF_LIMIT_MAX_COUNT;

	reg_data.data = cn_mcu_read32(core, MLU590_IPC_22);
	/*chip temperature*/
	temp_buf[0] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	/*mem temperature*/
	temp_buf[2] = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;

	reg_data.data = cn_mcu_read32(core, MLU590_IPC_25);
	/*board temperature*/
	temp_buf[1] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;

	/*fan*/
	info->fan_speed = 0;

	/*power*/
	reg_data.data = cn_mcu_read32(core, MLU590_IPC_28);
	info->board_power = (reg_data.data >> 16) & 0xffff;
	if (!info->board_power)
		cn_xid_err(core, XID_MCU_ERR, "Invalid Power Usage. IPC-28 %x", reg_data.data);

	info->board_power_decimal = 0;
	reg_data.data = cn_mcu_read32(core, MLU590_IPC_27);
	info->machine_power = reg_data.data & 0xffff;

	__mcu_read_power_cap_mlu590(core, &info->peak_power, &info->max_power_decimal);

	/* over temperature info */
	reg_data.data = cn_mcu_read32(core, MLU590_IPC_32);
	info->over_temp_underclock_times = (reg_data.data >> 24) & 0xff;
	info->over_temp_underclock_temp = ((reg_data.data >> 16) & 0xff) - MCU_TEMP_CORRECTION_FACTOR;
	info->over_temp_poweroff_times = (reg_data.data >> 8) & 0xff;
	info->over_temp_poweroff_temp = (reg_data.data & 0xff) - MCU_TEMP_CORRECTION_FACTOR;

	info->temperature_num = 3;
	info->temp = temp_buf;

	reg32 = cn_mcu_read32(core, MLU590_IPC_28);
	info->instantaneous_power = reg32 & 0xffff;
	info->instantaneous_power_decimal = 0;

	reg32 = cn_mcu_read32(core, MLU590_IPC_54);
	ic_freq[0] = reg32 & 0xffff;
	ic_freq[1] = reg32 & 0xffff;
	ic_freq[2] = (reg32 >> 16) & 0xffff;
	ic_freq[3] = (reg32 >> 16) & 0xffff;
	reg32 = cn_mcu_read32(core, MLU590_IPC_53);
	ic_freq[4] = reg32 & 0xffff;
	ic_freq[5] = reg32 & 0xffff;
	ic_freq[6] = (reg32 >> 16) & 0xffff;
	ic_freq[7] = (reg32 >> 16) & 0xffff;
	reg32 = cn_mcu_read32(core, MLU590_IPC_52);
	ic_freq[8] = reg32 & 0xffff;
	ic_freq[9] = reg32 & 0xffff;
	ic_freq[10] = (reg32 >> 16) & 0xffff;
	ic_freq[11] = (reg32 >> 16) & 0xffff;
	info->ipu_cluster_freq_num = MLU590_MAX_IPUCLUSTER_COUNT;
	info->ic_freq = ic_freq;

	reg32 = cn_mcu_read32(core, MLU590_IPC_38);
	ipufreq_avg = (reg32 >> 12) & 0xFFF;

	info->ipu_cluster_mask = 0;
	for (i = 0; i < MLU590_MAX_IPUSYS_COUNT; i++) {
		info->ipu_cluster_mask |= (pboardi->ipusys_mask & (0x1 << i)) ? (0x3 << (i * 2)) : 0x0;
	}

	for (i = 0; i < MLU590_MAX_IPUCLUSTER_COUNT; i++) {
		if (test_bit(i, (const volatile unsigned long *)&info->ipu_cluster_mask)) {
			if (!ic_freq[i])
				ic_freq[i] = ipufreq_avg;
		}
	}

	/* freq capping count */
	reg32 = cn_mcu_read32(core, MLU590_IPC_26);
	info->edpp_count = reg32 >> 16;
	info->tdp_freq_capping_count = reg32 & 0xffff;

	return 0;

IPUSYS_FREQ_MEM_ERR:
	if (perf_limit_buf)
		cn_kfree(perf_limit_buf);

PERF_LIMIT_MEM_ERR:
	if (temp_buf)
		cn_kfree(temp_buf);

	return ret;
}

/**
 * @brief read mlu590 ipu freq
 * @param pcore core layer handle
 * @param *freq ipu freq info return
 *
 * @return
 */
int mcu_read_ipu_freq_mlu590(void *pcore, struct ipu_freq_info *info)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;

	info->ipu_freq = 0;
	info->ipu_overtemp_dfs_flag = 0;
	info->ipu_fast_dfs_flag = 0;

	reg32 = cn_mcu_read32(core, MLU590_IPC_38);
	info->ipu_freq = (reg32 >> 12) & 0xFFF;
	if (!info->ipu_freq)
		cn_xid_err(core, XID_MCU_ERR, "Read IPU Freq Error. IPC-38 %x", reg32);

	info->die_ipu_freq.ipu_freq[0] = info->ipu_freq;
	info->die_ipu_freq.ipu_freq[1] = 0;
	info->die_ipu_freq.die_ipu_cnt = 1;
	info->rated_ipu_freq = pboardi->rated_ipu_freq;

	return 0;
}

int mcu_read_max_temp_mlu590(void *pcore, int *max_temp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	int temp_value;

	*max_temp = -MCU_TEMP_CORRECTION_FACTOR;

	reg_data.data = cn_mcu_read32(core, MLU590_IPC_22);
	/* top temperature */
	temp_value = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/*mem temperature*/
	temp_value = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	reg_data.data = cn_mcu_read32(core, MLU590_IPC_25);
	/* board temperature */
	temp_value = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	return 0;
}

int mcu_read_over_temp_flag_mlu590(void *pcore, int *poweroff_flag)
{
	u32 reg32 = 0;
	s16 over_temp = 0;
	u8 poweroff_times = 0;
	u8 dfs_time = 0;
	s16 underclock_temp = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg32 = cn_mcu_read32(core, MLU590_IPC_32);

	over_temp = (reg32 & 0xff) - MCU_TEMP_CORRECTION_FACTOR;
	poweroff_times = (reg32 >> 8) & 0xff;
	dfs_time = (reg32 >> 24) & 0xff;
	underclock_temp = (reg32 >> 16) & 0xff;

	*poweroff_flag = poweroff_times;
	cn_mcu_write32(core, MLU590_IPC_41, ((0x3 << 16) | 0x3));

	if (poweroff_times) {
		cn_xid_err(core, XID_OVER_TEMP_ERR, "Over temperature power-off times: %u", poweroff_times);
		cn_xid_err(core, XID_OVER_TEMP_ERR, "Over temperature power-off: IPU %d degrees celsius", over_temp);

		reg32 = cn_mcu_read32(core, MLU590_IPC_25);
		over_temp = ((reg32 >> 16) & 0xff) - MCU_TEMP_CORRECTION_FACTOR;
		cn_xid_err(core, XID_OVER_TEMP_ERR, "Over temperature power-off: Board %d degrees celsius", over_temp);
		over_temp = ((reg32 >> 24) & 0xff) - MCU_TEMP_CORRECTION_FACTOR;
		cn_xid_err(core, XID_OVER_TEMP_ERR, "Over temperature power-off: HBM %d degrees celsius", over_temp);
		/* clear Excess temperature counter, bit 0/1, mask 15/16 */
	}

	if (dfs_time) {
		cn_xid_err(core, XID_OVER_TEMP_ERR, "Over temperature underclock times: %u", dfs_time);
		cn_xid_err(core, XID_OVER_TEMP_ERR, "Over temperature underclock: %d degrees celsius", underclock_temp);
		/* clear Excess temperature counter, bit 0/1, mask 15/16 */
	}

	return 0;
}

int mcu_read_ddr_freq_mlu590(void *pcore, u32 *freq)
{
	return 0;
}

/**
 * brief set or read power capping status
 * @param pcore core layer handle
 * @param *pcinfo powercapping info struct
 *
 * @return
 */
int mcu_power_capping_mlu590(void *pcore, struct power_capping_info *pcinfo)
{
	int ret = 0;

	/* mlu590 not support set high precision power cap */
	pcinfo->high_precision_support = HIGH_PRECISION_POWER_CAP_SUPPORT;

	if (pcinfo->ops_type) {
		ret = __mcu_set_power_cap_mlu590(pcore, pcinfo->cap_value, pcinfo->mode, pcinfo->dec_cap_value);
	} else {
		ret = __mcu_read_power_cap_mlu590(pcore, &pcinfo->cap_value, &pcinfo->dec_cap_value);
	}

	return ret;
}

/**
 * brief set host driver load status to mcu
 * @param pcore core layer handle
 *
 * @return
 */
int mcu_set_host_driver_status_mlu590(void *pcore, int status)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg32 = cn_mcu_read32(pcore, MLU590_IPC_46);
	if (status) {
		/* set drv status */
		reg32 |= (status & 0x01) << 31;

		/* set drv lt freq capping attr */
		reg32 |= core->drv_support_lt_freq_cap ? (0x1 << 30) : 0;

		/* set drv version */
		reg32 &= ~(0xffffff);
		reg32 |= ((u32)DRV_MAJOR << 16) | (DRV_MINOR << 8) | (DRV_BUILD);
	} else {
		reg32 &= (~0xC0FFFFFF);
	}

	cn_mcu_write32(pcore, MLU590_IPC_46, reg32);

	cn_dev_core_info(core, "Set DRV Status %d, 0x%08X, 0x%08X",
		status, reg32, cn_mcu_read32(pcore, MLU590_IPC_38));

	return 0;
}

int mcu_read_overtemp_freq_mlu590(void *pcore, struct mlu_overtemp_value *overtemp)
{
	u32 reg32 = 0;
	u8 poweroff_times = 0;
	u8 dfs_time = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg32 = cn_mcu_read32(core, MLU590_IPC_32);
	if (reg32 == 0xffffffff) {
		return -EINVAL;
	} else {
		poweroff_times = (reg32 >> 8) & 0xff;
		dfs_time =  (reg32 >> 24) & 0xff;

		overtemp->poweroff_value = poweroff_times;
		overtemp->freq_value = dfs_time;
	}

	return 0;
}

int mcu_set_overtemp_policy_mlu590(void *pcore, struct cndev_overtemp_param *overtemp)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct mlu_overtemp_warning *freq_warning = NULL;
	struct mlu_overtemp_warning *poweroff_warning = NULL;

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

	poweroff_warning = &core->poweroff_warning;
	poweroff_warning->mode = overtemp->mode;

	return ret;
}

int mcu_get_overtemp_policy_mlu590(void *pcore, struct cndev_overtemp_param *overtemp)
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

int mcu_read_exception_info_mlu590(void *pcore, struct exception_info *info, u8 klog)
{
	return 0;
}

void mcu_exit_mlu590(void *mset)
{
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)mset;

	if (mcu_set) {
		mcu_set->core = NULL;
		mcu_set->mcu_ops = NULL;
	}
}

static const struct cn_mcu_ops mcu_mlu590_ops = {
	.read_basic_info = mcu_read_basic_info_mlu590,
	.read_power_info = mcu_read_power_info_mlu590,
	.read_ipu_freq = mcu_read_ipu_freq_mlu590,
	.read_max_temp = mcu_read_max_temp_mlu590,
	.read_over_temp_flag = mcu_read_over_temp_flag_mlu590,
	.power_capping = mcu_power_capping_mlu590,
	.read_ddr_freq = mcu_read_ddr_freq_mlu590,
	.set_host_drv_status = mcu_set_host_driver_status_mlu590,
	.read_overtemp_freq = mcu_read_overtemp_freq_mlu590,
	.mcu_exit = mcu_exit_mlu590,
	.get_overtemp_policy = mcu_get_overtemp_policy_mlu590,
	.set_overtemp_policy = mcu_set_overtemp_policy_mlu590,
	.read_uuid = NULL,
	.set_d2d_crc_err = NULL,
	.read_exception_info = mcu_read_exception_info_mlu590,
};

int mcu_init_mlu590(struct cn_mcu_set *mcu_set)
{
	struct cn_core_set *core = NULL;
	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	mcu_set->mcu_ops = &mcu_mlu590_ops;

	core = (struct cn_core_set *)(mcu_set->core);
	/*Frequency Refresh Cycle*/
	core->freq_warning.refresh_cycle = 1;
	core->poweroff_warning.refresh_cycle = 1;

	return 0;
}
