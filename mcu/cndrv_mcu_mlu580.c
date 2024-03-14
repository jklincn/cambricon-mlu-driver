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

#define MLU580_MCU_POWER_CAP_MASK	0x7FFF
#define MLU580_MCU_POWER_CAP_ENABLE	0x8000
#define MLU580_MCU_POWER_CAP_ENABLE_SHIFT	(15)
#define MLU580_MCU_POWER_CAP_ENABLE_MASK	(0X1 << MLU580_MCU_POWER_CAP_ENABLE_SHIFT)

#define MLU580_MCU_DDRTRAINED_FLAG_SHIFT  (10)
#define MLU580_MCU_DDRTRAINED_FLAG_MASK   (0x7)
#define MLU580_MCU_DDRTRAINED_MEM_DONE    (0x1)
#define MLU580_MCU_DDRTRAINED_BOOT_DONE   (0x2)

/* SECURE BOOT MODE */
#define MLU580_UNKNOWN_BOOT    0X0
#define MLU580_SECURE_BOOT     0X1
#define MLU580_NORMAL_BOOT     0X2
#define MLU580_SEC_BYPASS_BOOT 0X3
/* SOC ID INFO */
#define MLU580_SOC_ID_REG_CNT             (8)

enum {
	MCU_MLU580_EXPT_OVERTEMP = 1,
	MCU_MLU580_EXPT_PI = 2,
	MCU_MLU580_EXPT_PCIE = 3,
	MCU_MLU580_EXPT_MAX = 8,
};

#define PCIE_SPEED_2_5_GT  0x0001
#define PCIE_SPEED_5_0_GT  0x0002
#define PCIE_SPEED_8_0_GT  0x0003
#define PCIE_SPEED_16_0_GT 0x0004
#define PCIE_SPEED_32_0_GT 0x0005

#define PCIE_WIDTH_X1  0x0001
#define PCIE_WIDTH_X2  0x0002
#define PCIE_WIDTH_X4  0x0004
#define PCIE_WIDTH_X8  0x0008
#define PCIE_WIDTH_X16 0x0010

const u32 mlu580_ddr_topid_to_decid[MLU580_DDR_CHANNEL_COUNT] = {0, 2, 1, 4, 3, 5};
const char* mlu580_chip_type[] = {"A6", "A5", "A3", "UNKNOW"};
const u8 mlu580_mem_group_capacity[] = {2, 4, 8, 16};
const char* mlu580_halt_reason_desc[MCU_MLU580_EXPT_MAX] = {
	"",
	"Over temperature power-off",
	"PI (Power Intergrity)",
	"PCIe exception",
	"Unkonw",
	"Unkonw",
	"Unkonw",
	"Unkonw",
};

#define IPU_BAR_NUM        8
#define IPU_CLUSTER_NUM    12
#define ZONE_BLOCK_MAP_NUM 24
#define IPU_SP_RANG_CFG(high, low) (((high) << 16) | (low))
#define IPU_SP_SIZE_CFG(high, low) (((high) << 16) | (low))
#define ZOME_MAP_CFG(val3, val2, val1, val0)	\
	(((val3) << 24) | ((val2) << 16) | ((val1) << 8) | (val0))

static unsigned long ipu_bar_base[IPU_BAR_NUM] = {
	0x290000,  /* ipu_bar_00 */
	0x1a30000, /* ipu_bar_01 */
	0x1c20000, /* ipu_bar_10 */
	0x1e20000, /* ipu_bar_11 */
	0x2020000, /* ipu_bar_20 */
	0x2220000, /* ipu_bar_21 */
	0x2430000, /* ipu_bar_30 */
	0x2620000, /* ipu_bar_31 */
};

static unsigned long ipu_sp_cfg_base[IPU_BAR_NUM] = {
/*  bar00  bar01  bar10  bar11  bar20  bar21  bar30  bar31 */
	0x350, 0x300, 0x200, 0x200, 0x200, 0x200, 0x300, 0x300
};

static unsigned long ipu_sp_range_cfg_offset[] = {
	0x0,  /* IPU_SYS0_SP_RANGE_START */
	0x4,  /* IPU_SYS1_SP_RANGE_START */
	0x8,  /* IPU_SYS2_SP_RANGE_START */
	0xc,  /* IPU_SYS3_SP_RANGE_START */
	0x10, /* IPU_SYS4_SP_RANGE_START */
	0x14  /* IPU_SYS5_SP_RANGE_START */
};

static unsigned long ipu_sp_size_cfg_offset[] = {
	0x18, /* IPU_SYS0_SP_RANGE_SIZE */
	0x1c, /* IPU_SYS1_SP_RANGE_SIZE */
	0x20, /* IPU_SYS2_SP_RANGE_SIZE */
	0x24, /* IPU_SYS3_SP_RANGE_SIZE */
	0x28, /* IPU_SYS4_SP_RANGE_SIZE */
	0x2c  /* IPU_SYS5_SP_RANGE_SIZE */
};

static unsigned long zone_block_map_cfg_offset[] = {
	0x30, /* SP_ZONE_BLOCK_0_3_MAP */
	0x34, /* SP_ZONE_BLOCK_4_7_MAP */
	0x38, /* SP_ZONE_BLOCK_8_11_MAP */
	0x3c, /* SP_ZONE_BLOCK_12_15_MAP */
	0x40, /* SP_ZONE_BLOCK_16_19_MAP */
	0x44  /* SP_ZONE_BLOCK_20_23_MAP */
};

static void
__mcu_spm_cfg_raw_mlu580(void *pcore, u32 *sp_range, u32 *sp_size, u32 *zone_map)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	unsigned long reg_addr;
	int i, j;

	for (i = 0; i < IPU_BAR_NUM; i++) {
		reg_addr = ipu_bar_base[i] + ipu_sp_cfg_base[i];

		for (j = 0; j < MLU580_DDR_CHANNEL_COUNT; j++) {
			/* 1.cfg ipu bar sp range start */
			cn_mcu_write32(core, reg_addr + ipu_sp_range_cfg_offset[j],
				IPU_SP_RANG_CFG(sp_range[j * 2 + 1], sp_range[j * 2]));
			/* 2.cfg ipu bar sp size */
			cn_mcu_write32(core, reg_addr + ipu_sp_size_cfg_offset[j],
				IPU_SP_RANG_CFG(sp_size[j * 2 + 1], sp_size[j * 2]));
			/* 3.cfg zone block map */
			cn_mcu_write32(core, reg_addr + zone_block_map_cfg_offset[j],
				ZOME_MAP_CFG(zone_map[j * 4 + 3], zone_map[j * 4 + 2],
							 zone_map[j * 4 + 1], zone_map[j * 4]));
		}
	}
}

static u32 sp_range_cfg_invalid = 0x1ff;
static u32 sp_range_cfg_1[IPU_CLUSTER_NUM] = {
	0x0, 0x15, 0x2a, 0x3f, 0x54, 0x69, 0x7e, 0x93, 0xa8, 0xbd, 0xd2, 0xe7
};
static u32 sp_range_cfg_2[IPU_CLUSTER_NUM] = {
	0x0, 0x1c, 0x38, 0x54, 0x70, 0x8c, 0xa8, 0xc4, 0xe0, 0xfc, 0x118, 0x134
};
static u32 sp_range_cfg_3[IPU_CLUSTER_NUM] = {
	0x0, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x100, 0x120, 0x1ff, 0x1ff
};

static u32 sp_size_cfg_invalid = 0x0;
static u32 sp_size_cfg_1[IPU_CLUSTER_NUM] = {
	0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15
};
static u32 sp_size_cfg_2[IPU_CLUSTER_NUM] = {
	0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c
};
static u32 sp_size_cfg_3[IPU_CLUSTER_NUM] = {
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
};

static u32 sp_zone_block_map_cfg_invalid = 0x1f;
static u32 sp_zone_block_map_cfg_1[ZONE_BLOCK_MAP_NUM] = {
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc,
	0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
};

static void
__mcu_spm_cfg_array_gen_mlu580(u32 ipu_mask, u32 llc_mask,
					   u32 *range_cfg, u32 *size_cfg, u32 *map_cfg,
					   u32 *range_array, u32 *size_array, u32 *map_array)
{
	int i, j = 0;
	int range_index = 0, size_index = 0, map_index = 0;

	for (i = 0; i < MLU580_DDR_CHANNEL_COUNT; i++) {
		if (ipu_mask & ((0x1) << i)) {
			/* ipu system enable */
			range_array[i * 2] = range_cfg[range_index++];
			range_array[i * 2 + 1] = range_cfg[range_index++];
			size_array[i * 2] = size_cfg[size_index++];
			size_array[i * 2 + 1] = size_cfg[size_index++];
		} else {
			/* ipu system disable */
			range_array[i * 2] = sp_range_cfg_invalid;
			range_array[i * 2 + 1] = sp_range_cfg_invalid;
			size_array[i * 2] = sp_size_cfg_invalid;
			size_array[i * 2 + 1] = sp_size_cfg_invalid;
		}

		if (llc_mask & ((0x1) << i)) {
			/* llc system enable */
			map_array[j * 4] = map_cfg[map_index];
			map_array[j * 4 + 1] = map_cfg[map_index + 1];
			map_array[j * 4 + 2] = map_cfg[map_index + 2];
			map_array[j * 4 + 3] = map_cfg[map_index + 3];
			j++;
		}
		map_index += 4;
	}

	for (; j < MLU580_DDR_CHANNEL_COUNT; j++) {
		map_array[j * 4] = sp_zone_block_map_cfg_invalid;
		map_array[j * 4 + 1] = sp_zone_block_map_cfg_invalid;
		map_array[j * 4 + 2] = sp_zone_block_map_cfg_invalid;
		map_array[j * 4 + 3] = sp_zone_block_map_cfg_invalid;
	}
}

static int __mcu_spm_cfg_set_mlu580(void *pcore)
{
	/* generate sp_rang_array, sp_size_array, zone_block_map_array */
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	u32 sp_range[IPU_CLUSTER_NUM]; /* generate by ipu system bitmap */
	u32 sp_size[IPU_CLUSTER_NUM]; /* generate by ipu system bitmap */
	u32 zone_map[ZONE_BLOCK_MAP_NUM]; /* generate by llc system bitmap */

	unsigned long ipu_mask, ddr_mask, llc_mask = 0;
	u32 ipu_num, ddr_num;
	int i;

	ipu_mask = cn_mcu_read32(core, MLU580_IPC_5);
	ipu_mask &= 0x3f;
	ipu_num = bitmap_weight((unsigned long *)&ipu_mask, MLU580_DDR_CHANNEL_COUNT);

	ddr_mask = cn_mcu_read32(core, MLU580_IPC_5);
	ddr_mask >>= 6;
	ddr_mask &= 0x3f;
	ddr_num = bitmap_weight((unsigned long *)&ddr_mask, MLU580_DDR_CHANNEL_COUNT);

	for (i = 0; i < MLU580_DDR_CHANNEL_COUNT; i++) {
		if (ddr_mask & ((0x1) << i)) {
			llc_mask |= (0x1 << mlu580_ddr_topid_to_decid[i]);
		}
	}

	switch (ipu_num) {
	case 6:
		if (ddr_num == 6) {
			__mcu_spm_cfg_array_gen_mlu580(ipu_mask, llc_mask,
							sp_range_cfg_2, sp_size_cfg_2, sp_zone_block_map_cfg_1,
							sp_range, sp_size, zone_map);
		} else if (ddr_num == 5) {
			__mcu_spm_cfg_array_gen_mlu580(ipu_mask, llc_mask,
							sp_range_cfg_1, sp_size_cfg_1, sp_zone_block_map_cfg_1,
							sp_range, sp_size, zone_map);
		} else {
			goto error;
		}
		break;
	case 5:
		if (ddr_num == 6) {
			__mcu_spm_cfg_array_gen_mlu580(ipu_mask, llc_mask,
							sp_range_cfg_3, sp_size_cfg_3, sp_zone_block_map_cfg_1,
							sp_range, sp_size, zone_map);
		} else if (ddr_num == 5) {
			__mcu_spm_cfg_array_gen_mlu580(ipu_mask, llc_mask,
							sp_range_cfg_2, sp_size_cfg_2, sp_zone_block_map_cfg_1,
							sp_range, sp_size, zone_map);
		} else {
			goto error;
		}
		break;
	case 4:
		if (ddr_num == 3) {
			__mcu_spm_cfg_array_gen_mlu580(ipu_mask, llc_mask,
							sp_range_cfg_1, sp_size_cfg_1, sp_zone_block_map_cfg_1,
							sp_range, sp_size, zone_map);
		} else {
			goto error;
		}
		break;
	case 3:
		if (ddr_num == 3) {
			__mcu_spm_cfg_array_gen_mlu580(ipu_mask, llc_mask,
							sp_range_cfg_2, sp_size_cfg_2, sp_zone_block_map_cfg_1,
							sp_range, sp_size, zone_map);
		} else {
			goto error;
		}
		break;
	default:
		goto error;
	}

	__mcu_spm_cfg_raw_mlu580(core, sp_range, sp_size, zone_map);
	return 0;

error:
	cn_dev_core_err(core, "[Fatal Error] system number wrong!"
					" ipu %#lx ddr %#lx", ipu_mask, ddr_mask);
	return -EINVAL;
}

int __mcu_read_power_cap_mlu580(void *pcore, u32 *cap_value, u16 *dec_cap_value)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg32 = cn_mcu_read32(core, MLU580_IPC_38);
	cn_dev_core_debug(core, "MLU580_IPC_38: 0x%08X", reg32);
	*cap_value = reg32 & 0xFFF;

	/* MLU580 power cap decimal */
	if (dec_cap_value)
		*dec_cap_value = 0;

	return 0;
}

int __mcu_set_power_cap_mlu580(void *pcore, u32 cap_value, u32 mode, u16 dec_cap_value)
{
	u32 reg32 = 0;
	u32 min_power_cap_ctrl = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)core->mcu_set;

	min_power_cap_ctrl =
		pboardi->min_power_cap_ctrl ? pboardi->min_power_cap_ctrl : pboardi->peak_power / 2;

	if (mode == DISABLE_PERMANENT) {
		cap_value =	(0x1 << MLU580_MCU_POWER_CAP_ENABLE_SHIFT);
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
			cap_value = (cap_value & MLU580_MCU_POWER_CAP_MASK) |
				((0x1) << MLU580_MCU_POWER_CAP_ENABLE_SHIFT);
		}
		atomic64_inc(&mcu_set->enable_power_cap_ref);
	} else {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "Invalid user input mode %u !",
			mode);
		return -EINVAL;
	}

	reg32 = cn_mcu_read32(pcore, MLU580_IPC_37)
			& ~(MLU580_MCU_POWER_CAP_MASK | MLU580_MCU_POWER_CAP_ENABLE_MASK);
	reg32 = reg32 & ~(MLU580_MCU_POWER_CAP_MASK | MLU580_MCU_POWER_CAP_ENABLE_MASK);
	reg32 |= cap_value;
	reg32 &= 0xFFFF;
	cn_mcu_write32(pcore, MLU580_IPC_37, reg32);

	reg32 = cn_mcu_read32(pcore, MLU580_IPC_37) & 0xFFFF;
	if (reg32 != cap_value) {
		return -EINVAL;
	}

	return 0;
}

const char *mlu580_hbm_init_statu[4] = {
	"DDR init successfully",
	"DDR init failed",
	"DDR address repair failed",
	"DDR init timeout"
};

int mcu_read_basic_info_mlu580(void *pcore)
{
	int ret = 0;
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	u64 serial_num = 0;
	u32 sn_high_16bit = 0;
	u8 special_info = 0;
	u64 total_mem_size = 0;
	u64 ddr_capacity = 0;
	u16 max_power_decimal = 0;
	int i = 0;
	u64 mem_mask = 0;
	u32 ddr_topid = 0;
	/* ddr ready */
	int cnt = 0;

	cnt = 1200;
	do {
		reg32 = cn_mcu_read32(core, MLU580_IPC_2);
		if (((reg32 >> MLU580_MCU_DDRTRAINED_FLAG_SHIFT) & MLU580_MCU_DDRTRAINED_FLAG_MASK)
			< MLU580_MCU_DDRTRAINED_BOOT_DONE) {
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
		cn_xid_err(core, XID_MCU_ERR, "Wait DDR Training Finish Timeout!!");
		goto err;
	}

	reg32 = (cn_mcu_read32(core, MLU580_IPC_2) >> 16) & 0x3;
	if (reg32) {
		cn_xid_err(core, XID_HBM_ERR, "DDR Init Status 0x%x, %s", reg32, mlu580_hbm_init_statu[reg32 & 0x3]);
		ret = -EPERM;
		goto err;
	}

	/* board info */
	core->board_model = MLU580;

	/* chip type subsystem_id and mcu version */
	pboardi->chip_version = 0;
	reg32 = cn_mcu_read32(core, MLU580_IPC_7);
	cn_dev_core_info(core, "IPC_7: 0x%x", reg32);
	pboardi->chip_type = (reg32 >> 24) & 0xFF;
	pboardi->mcu_info.mcu_major = (reg32 >> 12)
		& 0xF;
	pboardi->mcu_info.mcu_minor = (reg32 >> 8)
		& 0xF;
	pboardi->mcu_info.mcu_build = reg32 & 0xff;
	pboardi->mcu_info.mcu_rc = 0;

	cn_dev_core_info(core, "MCU FW Version: %u.%u.%u",
		pboardi->mcu_info.mcu_major,
		pboardi->mcu_info.mcu_minor,
		pboardi->mcu_info.mcu_build);

	/* slot id */
	pboardi->slot_id = 0;

	/* chip info */
	core->die_cnt = 1;
	pboardi->chip_id = 0;

	/* Boot Mode */
	reg32 = cn_mcu_read32(core, MLU580_IPC_2);
	cn_dev_core_info(core, "IPC_2: 0x%x", reg32);
	pboardi->secure_mode = (reg32 >> 8) & 0x3;
	memset(pboardi->soc_id.soc_id_data, 0, SOC_ID_SIZE);

	/* ipu info */
	pboardi->cluster_num = 12;
	pboardi->ipu_core_num = 4;

	/* mem info */
	pboardi->mem_channel = 1;

	/* dev sn */
	reg32 = cn_mcu_read32(core, MLU580_IPC_13);
	cn_dev_core_info(core, "IPC_13: 0x%x", reg32);
	serial_num = reg32;
	reg32 = cn_mcu_read32(core, MLU580_IPC_14);
	cn_dev_core_info(core, "IPC_14: 0x%x", reg32);
	serial_num |= (u64)reg32 << 32;
	pboardi->serial_num = serial_num;

	/* ba sn */
	pboardi->BA_serial_num = 0x0;

	cn_dev_core_info(core, "IPU Flag = 0x%x", (cn_mcu_read32(core, MLU580_IPC_5) >> 0) & 0x3F);
	cn_dev_core_info(core, "DDR Flag = 0x%x", (cn_mcu_read32(core, MLU580_IPC_5) >> 6) & 0x3f);
	cn_dev_core_info(core, "C2C Flag = 0x%x", (cn_mcu_read32(core, MLU580_IPC_5) >> 12) & 0xff);
	cn_dev_core_info(core, "TNC Flag = 0x%x", (cn_mcu_read32(core, MLU580_IPC_5) >> 20) & 0xff);
	cn_dev_core_info(core, "BAD DDR ID = %x", (cn_mcu_read32(core, MLU580_CFG) >> 12) & 7);

	pboardi->gdma_mask = 0x3f;
	pboardi->platform = MLU_PLAT_ASIC;

	reg32 = cn_mcu_read32(core, MLU580_IPC_5);
	cn_dev_core_info(core, "Resource Info: 0x%x", reg32);
	pboardi->ipusys_mask = reg32 & 0x3f;

	reg32 = cn_mcu_read32(core, MLU580_CFG);
	cn_dev_core_info(core, "IPC_CFG: 0x%x", reg32);
	ddr_topid = (reg32 >> 12) & 0x7;
	cn_dev_core_info(core, "DDR Top ID = %u", ddr_topid);

	reg32 = cn_mcu_read32(core, MLU580_IPC_5);
	mem_mask = (reg32 >> 6) & 0x3f;
	reg32 = bitmap_weight((unsigned long *)&mem_mask, 32);
	pboardi->hbm_cnt = reg32;

	reg32 = cn_mcu_read32(core, MLU580_CFG);
	cn_dev_core_info(core, "CHIP Type = %s", mlu580_chip_type[reg32 & 0x3]);

	if (pboardi->hbm_cnt != MLU580_DDR_CHANNEL_COUNT) {
		if (ddr_topid < MLU580_DDR_CHANNEL_COUNT) {
			pboardi->bad_hbm_mask = 1 << mlu580_ddr_topid_to_decid[ddr_topid];
			cn_dev_core_info(core, "DDR MASK = 0x%x", pboardi->bad_hbm_mask);
		} else {
			cn_xid_err(core, XID_MCU_ERR, "Invalid TOP DDR ID %u", ddr_topid);
			pboardi->bad_hbm_mask = 0;
		}
	}

	sn_high_16bit = (pboardi->serial_num >> 48) & 0xffff;
	pboardi->board_type = sn_high_16bit;

	special_info = (pboardi->serial_num >> 40) & 0xff;
	pboardi->special_info = special_info;

	switch (sn_high_16bit) {
	case SUBSYS_MLU580_EVB:
		core->board_info.board_idx = CN_MLU580_EVB;
		break;
	case SUBSYS_MLU560:
		core->board_info.board_idx = CN_MLU560;
		break;
	case SUBSYS_MLU560F:
		core->board_info.board_idx = CN_MLU560F;
		break;
	case SUBSYS_MLU580:
		core->board_info.board_idx = CN_MLU580;
		break;
	case SUBSYS_MLU570:
		core->board_info.board_idx = CN_MLU570;
		break;
	case SUBSYS_MLU570F:
		core->board_info.board_idx = CN_MLU570F;
		break;
	default:
		core->board_info.board_idx = CN_MLU580_UNKNOWN_TYPE;
		break;
	}

	pboardi->ddr_freq = 8000;
	reg32 = cn_mcu_read32(core, MLU580_CAPACITY);
	cn_dev_core_info(core, "cfg_ddr_capacity: 0x%x", reg32);
	ddr_capacity = mlu580_mem_group_capacity[reg32 & 0x3];
	cn_dev_core_info(core, "MEM Group Capacity = %llu GB", ddr_capacity);

	cn_dev_core_info(core, "DDR Cnt = %u", pboardi->hbm_cnt);
	total_mem_size = (u64)0x40000000 * ddr_capacity * pboardi->hbm_cnt;
	cn_dev_core_info(core, "DDR Total Capacity = 0x%llx B", total_mem_size);

	pboardi->total_memory =	total_mem_size;
	strcpy(pboardi->board_model_name, mlu580_basic_info_table[core->board_info.board_idx].board_model_name);
	/* ddr speed, unit 100Mbps */
	reg32 = cn_mcu_read32(core, MLU580_IPC_3);
	pboardi->ddr_speed = ((reg32 >> 16) & 0xff) * 100;
	pboardi->ddr_cap = ddr_capacity;
	pboardi->ddr_type = 0;

	/* tdp */
	reg32 = cn_mcu_read32(core, MLU580_IPC_11);
	pboardi->peak_power = reg32 & 0x3FF;
	if (!pboardi->peak_power)
		cn_xid_err(core, XID_MCU_ERR, "Invalid Thermal Design Power. IPC-38 %x", reg32);
	pboardi->min_power_cap_ctrl = mlu580_basic_info_table[core->board_info.board_idx].min_power_cap_ctrl;
	if (pboardi->min_power_cap_ctrl) {
		pboardi->min_power_cap = pboardi->min_power_cap_ctrl;
	} else {
		pboardi->min_power_cap = pboardi->peak_power / 2;
	}
	pboardi->min_power_cap_dec = 0;
	pboardi->max_power_cap_dec = 0;

	/* qdd status */
	pboardi->qdd_status = 0;

	/* uuid */
	memset(pboardi->uuid, 0, CNDRV_UUID_SIZE);

	pboardi->platform_id = mlu580_basic_info_table[core->board_info.board_idx].platform_id;

	/* pcie fw version */
	reg32 = cn_mcu_read32(core, MLU580_IPC_17);
	pboardi->pcie_fw_info = reg32 & 0xffff;

	/* mem bandwidth */
	pboardi->bandwidth =
		mlu580_basic_info_table[core->board_info.board_idx].bandwidth;
	pboardi->bandwidth_decimal =
		mlu580_basic_info_table[core->board_info.board_idx].bandwidth_decimal;

	/* get board info */
	pboardi->bus_width = mlu580_board_info[core->board_info.board_idx][INFO_BUS_WIDTH];
	pboardi->ecc_support = mlu580_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
	pboardi->stack_size = mlu580_board_info[core->board_info.board_idx][INFO_STACK_SIZE];
	pboardi->sram_size = mlu580_board_info[core->board_info.board_idx][INFO_SRAM_SIZE];
	pboardi->cache_size = mlu580_board_info[core->board_info.board_idx][INFO_CACHE_SIZE];
	pboardi->kc_limit = mlu580_board_info[core->board_info.board_idx][INFO_KC_LIMIT];
	pboardi->o_kc_limit = mlu580_board_info[core->board_info.board_idx][INFO_O_KC_LIMIT];
	pboardi->rated_ipu_freq = mlu580_board_info[core->board_info.board_idx][INFO_MAX_IPU_FREQ];

	/* get ipu freq capping range */
	pboardi->min_ipu_freq_cap = mlu580_basic_info_table[core->board_info.board_idx].min_ipu_freq_cap;
	pboardi->max_ipu_freq_cap = mlu580_basic_info_table[core->board_info.board_idx].max_ipu_freq_cap;

	cn_dev_core_info(core, "board_model_name %s, board_model %#x, tdp %#x",
		pboardi->board_model_name, core->board_model, pboardi->peak_power);

	/* BIT 7-9 INDICATE BOOT MODE */
	if (pboardi->secure_mode == MLU580_SECURE_BOOT) {
		for (i = 0; i < MLU580_SOC_ID_REG_CNT; i++) {
			pboardi->soc_id.soc_id_reg[i] = 0;
		}
	}

	__mcu_read_power_cap_mlu580(core, &reg32, &max_power_decimal);
	if (reg32)
		cn_dev_core_info(core, "Board Power Cap to %u.%02uW", reg32, max_power_decimal);

	ret = __mcu_spm_cfg_set_mlu580(core);

	return ret;

err:
	cn_recommend(core, USER_RECOMMED);
	return ret;
}


/**
 * @brief read mlu580 mcu power info
 * @param pcore core layer handle
 * @param *info power info struct
 *
 * based on variable temp buffer length,
 * this function will alloc a buffer to save then.
 * user must free the *temp buffer itself.
 *
 * @return
 */
int mcu_read_power_info_mlu580(void *pcore, struct board_power_info *info)
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

	ic_freq = cn_kzalloc(MLU580_MAX_IPUCLUSTER_COUNT * sizeof(u16), GFP_KERNEL);
	if (!ic_freq) {
		cn_dev_core_err(core, "alloc freq buf fail");
		ret = -ENOMEM;
		goto IPUSYS_FREQ_MEM_ERR;
	}

	reg_data.data = cn_mcu_read32(core, MLU580_IPC_40);
	reg_data.data = reg_data.data & 0xffff;

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

	reg_data.data = cn_mcu_read32(core, MLU580_IPC_22);
	cn_dev_core_debug(core, "IPC_22: 0x%04X", reg_data.data);
	/*chip temperature*/
	temp_buf[0] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	/*mem temperature*/
	temp_buf[2] = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;

	reg_data.data = cn_mcu_read32(core, MLU580_IPC_25);
	cn_dev_core_debug(core, "IPC_25: 0x%04X", reg_data.data);
	/*board temperature*/
	temp_buf[1] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;

	/*fan*/
	info->fan_speed = 0;

	/*power*/
	reg_data.data = cn_mcu_read32(core, MLU580_IPC_28);
	info->board_power = (reg_data.data >> 16) & 0xffff;
	if (!info->board_power)
		cn_xid_err(core, XID_MCU_ERR, "Invalid Power Usage. IPC-28 %x", reg_data.data);

	info->board_power_decimal = 0;
	info->machine_power = 0;

	__mcu_read_power_cap_mlu580(core, &info->peak_power, &info->max_power_decimal);

	/* over temperature info */
	reg_data.data = cn_mcu_read32(core, MLU580_IPC_32);
	info->over_temp_underclock_times = (reg_data.data >> 24) & 0xff;
	info->over_temp_underclock_temp = ((reg_data.data >> 16) & 0xff) - MCU_TEMP_CORRECTION_FACTOR;
	info->over_temp_poweroff_times = (reg_data.data >> 8) & 0xff;
	info->over_temp_poweroff_temp = (reg_data.data & 0xff) - MCU_TEMP_CORRECTION_FACTOR;

	info->temperature_num = 3;
	info->temp = temp_buf;

	reg32 = cn_mcu_read32(core, MLU580_IPC_28);
	info->instantaneous_power = reg32 & 0xffff;
	info->instantaneous_power_decimal = 0;

	reg32 = cn_mcu_read32(core, MLU580_IPC_54);
	ic_freq[0] = reg32 & 0xffff;
	ic_freq[1] = reg32 & 0xffff;
	ic_freq[2] = (reg32 >> 16) & 0xffff;
	ic_freq[3] = (reg32 >> 16) & 0xffff;
	reg32 = cn_mcu_read32(core, MLU580_IPC_53);
	ic_freq[4] = reg32 & 0xffff;
	ic_freq[5] = reg32 & 0xffff;
	ic_freq[6] = (reg32 >> 16) & 0xffff;
	ic_freq[7] = (reg32 >> 16) & 0xffff;
	reg32 = cn_mcu_read32(core, MLU580_IPC_52);
	ic_freq[8] = reg32 & 0xffff;
	ic_freq[9] = reg32 & 0xffff;
	ic_freq[10] = (reg32 >> 16) & 0xffff;
	ic_freq[11] = (reg32 >> 16) & 0xffff;
	info->ipu_cluster_freq_num = MLU580_MAX_IPUCLUSTER_COUNT;
	info->ic_freq = ic_freq;

	reg32 = cn_mcu_read32(core, MLU580_IPC_38);
	ipufreq_avg = (reg32 >> 12) & 0xFFF;

	info->ipu_cluster_mask = 0;
	for (i = 0; i < MLU580_MAX_IPUSYS_COUNT; i++) {
		info->ipu_cluster_mask |= (pboardi->ipusys_mask & (0x1 << i)) ? (0x3 << (i * 2)) : 0x0;
	}

	for (i = 0; i < MLU580_MAX_IPUCLUSTER_COUNT; i++) {
		if (test_bit(i, (const volatile unsigned long *)&info->ipu_cluster_mask)) {
			if (!ic_freq[i])
				ic_freq[i] = ipufreq_avg;
		}
	}

	/* freq capping count */
	reg32 = cn_mcu_read32(core, MLU580_IPC_50);
	info->edpp_count = reg32;
	/* not support */
	info->tdp_freq_capping_count = 0;

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
 * @brief read mlu580 ipu freq
 * @param pcore core layer handle
 * @param *freq ipu freq info return
 *
 * @return
 */
int mcu_read_ipu_freq_mlu580(void *pcore, struct ipu_freq_info *info)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;

	info->ipu_freq = 0;
	info->ipu_overtemp_dfs_flag = 0;
	info->ipu_fast_dfs_flag = 0;

	reg32 = cn_mcu_read32(core, MLU580_IPC_38);
	info->ipu_freq = (reg32 >> 12) & 0xFFF;
	if (!info->ipu_freq)
		cn_xid_err(core, XID_MCU_ERR, "Read IPU Freq Error. IPC-38 %x", reg32);

	info->die_ipu_freq.ipu_freq[0] = info->ipu_freq;
	info->die_ipu_freq.ipu_freq[1] = 0;
	info->die_ipu_freq.die_ipu_cnt = 1;
	info->rated_ipu_freq = pboardi->rated_ipu_freq;

	return 0;
}

int mcu_read_max_temp_mlu580(void *pcore, int *max_temp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	int temp_value;

	*max_temp = -MCU_TEMP_CORRECTION_FACTOR;

	reg_data.data = cn_mcu_read32(core, MLU580_IPC_22);
	/* top temperature */
	temp_value = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/*mem temperature*/
	temp_value = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	reg_data.data = cn_mcu_read32(core, MLU580_IPC_25);
	/* board temperature */
	temp_value = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	return 0;
}

int mcu_read_over_temp_flag_mlu580(void *pcore, int *poweroff_flag)
{
	u32 reg32 = 0;
	u8 over_temp = 0;
	u8 poweroff_times = 0;
	u8 dfs_time = 0;
	u8 underclock_temp = 0;
	u16 temp = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg32 = cn_mcu_read32(core, MLU580_IPC_32);

	over_temp = (reg32 & 0xff) - MCU_TEMP_CORRECTION_FACTOR;
	poweroff_times = (reg32 >> 8) & 0xff;
	dfs_time = (reg32 >> 24) & 0xff;
	underclock_temp = (reg32 >> 16) & 0xff;

	*poweroff_flag = poweroff_times;

	reg32 = cn_mcu_read32(core, MLU580_IPC_41);
	reg32 |= (0x3 << 16) | 0x3;
	cn_mcu_write32(core, MLU580_IPC_41, reg32);

	if (poweroff_times) {
		cn_xid_err(core, XID_OVER_TEMP_ERR, "Over temperature power-off times: %u", poweroff_times);
		cn_xid_err(core, XID_OVER_TEMP_ERR, "Over temperature power-off: %u degrees celsius", over_temp);

		reg32 = cn_mcu_read32(core, MLU580_IPC_27);
		temp = ((reg32 >> 8) & 0xff);
		if (temp)
			cn_dev_core_warn(core, "Board temperature: %u degree celsius", temp - 100);
		temp = reg32 & 0xff;
		if (temp)
			cn_dev_core_warn(core, "GDDR temperature: %u degree celsius", temp - 100);
	}

	if (dfs_time) {
		cn_xid_err(core, XID_OVER_TEMP_ERR, "Over temperature underclock times: %u ", dfs_time);
		cn_xid_err(core, XID_OVER_TEMP_ERR, "Over temperature underclock: %u degrees celsius", underclock_temp);
	}

	return 0;
}

int mcu_read_exception_info_mlu580(void *pcore,
	struct exception_info *info, u8 klog)
{
	u32 reg32 = 0;
	u32 halt_reason = 0;
	u32 pi_detail = 0;
	u32 pcie_detail = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct bus_lnkcap_info lnk_info;

	reg32 = cn_mcu_read32(core, MLU580_IPC_47);
	halt_reason = reg32 & 0xff;
	pi_detail = (reg32 >> 8) & 0x3ff;
	pcie_detail = reg32 >> 18;

	if (halt_reason && klog) {
		switch (halt_reason) {
			case MCU_MLU580_EXPT_OVERTEMP:
				cn_xid_err(core, XID_PREV_HALT_ERR,
					"Halt Reason: %s",
					mlu580_halt_reason_desc[halt_reason]);
			break;
			case MCU_MLU580_EXPT_PI:
				cn_xid_err(core, XID_PREV_HALT_ERR,
					"Halt Reason: %s, Detail Status: 0x%x",
					mlu580_halt_reason_desc[halt_reason], pi_detail);
			break;
			case MCU_MLU580_EXPT_PCIE:
				memset(&lnk_info, 0, sizeof(struct bus_lnkcap_info));
				cn_bus_get_curlnk(core->bus_set, &lnk_info);
				if ((lnk_info.speed >= PCIE_SPEED_32_0_GT) && (lnk_info.width >= PCIE_WIDTH_X16)) {
					cn_xid_err(core, XID_PREV_HALT_ERR,
						"Halt Reason: %s, Detail Status Code: 0x%x",
						mlu580_halt_reason_desc[halt_reason], pcie_detail);
				}
			break;
			default:
			break;
		}
	}

	reg32 = cn_mcu_read32(core, MLU580_IPC_41);
	reg32 |= (0x8 << 16) | 0x8;
	/* bit 8 clear halt reason */
	cn_mcu_write32(core, MLU580_IPC_41, reg32);

	return 0;
}

int mcu_read_ddr_freq_mlu580(void *pcore, u32 *freq)
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
int mcu_power_capping_mlu580(void *pcore, struct power_capping_info *pcinfo)
{
	int ret = 0;

	/* mlu580 not support set high precision power cap */
	pcinfo->high_precision_support = HIGH_PRECISION_POWER_CAP_SUPPORT;

	if (pcinfo->ops_type) {
		ret = __mcu_set_power_cap_mlu580(pcore, pcinfo->cap_value, pcinfo->mode, pcinfo->dec_cap_value);
	} else {
		ret = __mcu_read_power_cap_mlu580(pcore, &pcinfo->cap_value, &pcinfo->dec_cap_value);
	}

	return ret;
}

/**
 * brief set host driver load status to mcu
 * @param pcore core layer handle
 *
 * @return
 */
int mcu_set_host_driver_status_mlu580(void *pcore, int status)
{
	u32 reg32 = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg32 = cn_mcu_read32(pcore, MLU580_IPC_46);
	if (status) {
		/* set drv status */
		reg32 |= (status & 0x01) << 31;

		/* set drv version */
		reg32 &= ~(0xffffff);
		reg32 |= ((u32)DRV_MAJOR << 16) | (DRV_MINOR << 8) | (DRV_BUILD);
	} else {

		reg32 &= (~0x80FFFFFF);
	}

	cn_mcu_write32(pcore, MLU580_IPC_46, reg32);

	cn_dev_core_info(core, "Set DRV Status %d, 0x%08X, 0x%08X",
		status, reg32, cn_mcu_read32(pcore, MLU580_IPC_38));

	return 0;
}

int mcu_read_overtemp_freq_mlu580(void *pcore, struct mlu_overtemp_value *overtemp)
{
	u32 reg32 = 0;
	u8 poweroff_times = 0;
	u8 dfs_time = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg32 = cn_mcu_read32(core, MLU580_IPC_32);
	if (reg32 == 0xffffffff) {
		return -EINVAL;
	} else {
		poweroff_times = (reg32 >> 8) & 0xff;
		dfs_time = (reg32 >> 24) & 0xff;

		overtemp->poweroff_value = poweroff_times;
		overtemp->freq_value = dfs_time;
	}

	return 0;
}

int mcu_set_overtemp_policy_mlu580(void *pcore, struct cndev_overtemp_param *overtemp)
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

int mcu_get_overtemp_policy_mlu580(void *pcore, struct cndev_overtemp_param *overtemp)
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

void mcu_exit_mlu580(void *mset)
{
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)mset;

	if (mcu_set) {
		mcu_set->core = NULL;
		mcu_set->mcu_ops = NULL;
	}
}

static const struct cn_mcu_ops mcu_mlu580_ops = {
	.read_basic_info = mcu_read_basic_info_mlu580,
	.read_power_info = mcu_read_power_info_mlu580,
	.read_ipu_freq = mcu_read_ipu_freq_mlu580,
	.read_max_temp = mcu_read_max_temp_mlu580,
	.read_over_temp_flag = mcu_read_over_temp_flag_mlu580,
	.power_capping = mcu_power_capping_mlu580,
	.read_ddr_freq = mcu_read_ddr_freq_mlu580,
	.set_host_drv_status = mcu_set_host_driver_status_mlu580,
	.read_overtemp_freq = mcu_read_overtemp_freq_mlu580,
	.mcu_exit = mcu_exit_mlu580,
	.get_overtemp_policy = mcu_get_overtemp_policy_mlu580,
	.set_overtemp_policy = mcu_set_overtemp_policy_mlu580,
	.read_uuid = NULL,
	.set_d2d_crc_err = NULL,
	.read_exception_info = mcu_read_exception_info_mlu580,
};

int mcu_init_mlu580(struct cn_mcu_set *mcu_set)
{
	struct cn_core_set *core = NULL;
	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null");
		return -EINVAL;
	}
	mcu_set->mcu_ops = &mcu_mlu580_ops;

	core = (struct cn_core_set *)(mcu_set->core);
	/*Frequency Refresh Cycle*/
	core->freq_warning.refresh_cycle = 1;
	core->poweroff_warning.refresh_cycle = 1;

	return 0;
}
