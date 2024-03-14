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
#include "cndrv_attr.h"

#define PIGEON_TEMPERTURE_INFO_CONUT	5
#define PIGEON_RSV_BASE  0x80000
#define PIGEON_IPC1     (PIGEON_RSV_BASE + 0xD04)
#define PIGEON_IPC5     (PIGEON_RSV_BASE + 0xD14)
#define PIGEON_IPC6     (PIGEON_RSV_BASE + 0xD18)
#define PIGEON_IPC7     (PIGEON_RSV_BASE + 0xD1C)
#define PIGEON_IPC9     (PIGEON_RSV_BASE + 0xD24)
#define PIGEON_IPC11    (PIGEON_RSV_BASE + 0xD2C)
#define PIGEON_IPC12    (PIGEON_RSV_BASE + 0xD30)
#define PIGEON_IPC13    (PIGEON_RSV_BASE + 0xD34)
#define PIGEON_IPC14    (PIGEON_RSV_BASE + 0xD38)
#define PIGEON_IPC15    (PIGEON_RSV_BASE + 0xD3C)

#define PIGEON_TOP_SCTRL_BASE 0x0
#define PIGEON_CHIP_ID         (PIGEON_TOP_SCTRL_BASE + 0x0) /* CHIP ID */
#define PIGEON_EFUSEC_PRELOAD  (PIGEON_TOP_SCTRL_BASE + 0x8) /* Main/sub id */

#define CHIP_ID_SOC_1V_2301                        (0xef230000)
#define CHIP_ID_SOC_PIGEON                         (0x32250000)

#define DDR_TOTAL_PIGEON(a) ((a) * 1024ULL * 1024ULL * 1024ULL)

enum {
	LEOPARD_LP4X = 0x20,
	LEOPARD_LP5 = 0x21,
	PIGEON_LP4X = 0x30,
	PIGEON_LP5 = 0x31,
	PIGEON_LP5_EVB = 0x32,
};

const u32 ddr_freq_pigeon[4] = {2133, 0, 0, 3200};
const u32 ddr_speed_pigeon[4] = {1600, 4266, 1600, 6400};
const u32 ddr_bandwidth_pigeon[4] = {17, 17, 25, 25};
const u32 ddr_bandwidth_decimal_pigeon[4] = {6, 6, 6, 6};
const u8 ddr_capacity[16] =
  /* 0  1  2  3  4  5  6   7   8  9  a  b  c  d  e   f  : unit GB */
	{0, 2, 3, 4, 6, 8, 12, 16, 0, 2, 3, 4, 6, 8, 12, 16};

int __mcu_read_power_cap_pigeon(void *pcore, u32 *cap_value)
{
	*cap_value = 0;

	return 0;
}

int __mcu_set_power_cap_pigeon(void *pcore, u32 cap_value)
{
	return 0;
}
static void unknown_soc(struct cn_core_set *core,
	struct cn_board_info *pboardi)
{
	core->board_model = SOC_1V_2301;
	core->board_info.board_idx = CN_PIGEON_UNKNOWN_TYPE;
	pboardi->platform_id = CN_CHIP_TYPE_UNKNOWN;
	pboardi->chip_type = CN_CHIP_ID_UNKNOWN;
	pboardi->rated_ipu_freq = 0;
}

static void pigeon_soc(struct cn_core_set *core,
	struct cn_board_info *pboardi)
{
	u32 reg32 = 0;
	u32 main_id = 0;
	u32 sub_id0 = 0;

	reg32 = cn_mcu_read32(core, PIGEON_EFUSEC_PRELOAD);
	main_id = reg32 >> 23 & 0x1;
	sub_id0 = MCU_BITS(reg32, 19, 16) & 0xf;
	if (!main_id) {
		pboardi->chip_type = CN_CHIP_ID_LEOPARD;

		core->board_model = LEOPARD_EDGE;
		core->board_info.board_idx = CN_LEOPARD;
		pboardi->platform_id = CN_CHIP_TYPE_LEOPARD;
		pboardi->rated_ipu_freq = 1200;
	} else {
		if (sub_id0) {
			pboardi->chip_type = CN_CHIP_ID_PIGEONC;
			pboardi->rated_ipu_freq = 1000;
		} else {
			pboardi->chip_type = CN_CHIP_ID_PIGEON;
			pboardi->rated_ipu_freq = 1200;
		}

		core->board_model = PIGEON;
		core->board_info.board_idx = CN_PIGEON;
		pboardi->platform_id = CN_CHIP_TYPE_PIGEON;
	}
}

static void ef2301_soc(struct cn_core_set *core,
	struct cn_board_info *pboardi)
{
	u32 reg32 = 0;
	u32 main_id = 0;

	reg32 = cn_mcu_read32(core, PIGEON_CHIP_ID);
	main_id = MCU_BITS(reg32, 12, 4) & 0xff;
	switch (main_id)
	{
	case 0x20:
		pboardi->platform_id = CN_CHIP_TYPE_1V_2301;
		pboardi->chip_type = CN_CHIP_ID_1V_2301;
		pboardi->rated_ipu_freq = 1200;
		break;
	case 0x2c:
		pboardi->platform_id = CN_CHIP_TYPE_1V_2302;
		pboardi->chip_type = CN_CHIP_ID_1V_2302;
		pboardi->rated_ipu_freq = 1000;
		break;
	default:
		unknown_soc(core, pboardi);
		break;
	}

	core->board_model = SOC_1V_2301;
	core->board_info.board_idx = CN_1V_2301;
}

int mcu_read_basic_info_pigeon(void *pcore)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	u8 ddr_info = 0;
	u32 reg32 = 0;
	u64 serial_num = 0;

	/*chip hardware version and ddr info*/
	reg32 = cn_mcu_read32(core, PIGEON_CHIP_ID);
	switch (reg32 & 0xffff0000) {
	case CHIP_ID_SOC_1V_2301:
		ef2301_soc(core, pboardi);
	break;
	case CHIP_ID_SOC_PIGEON:
		pigeon_soc(core, pboardi);
	break;
	default:
		unknown_soc(core, pboardi);
	break;
	}

	pboardi->chip_version = 0;
	core->die_cnt = 1;

	/*mcu version*/
	reg32 = cn_mcu_read32(core, PIGEON_IPC5);
	cn_ce_dev_core_debug(core, "version reg: %X, val: 0x%08X", PIGEON_IPC5, reg32);
	reg32 = reg32 & 0xffff;
	pboardi->mcu_info.mcu_major = (reg32 >> MCU_SW_MAJOR_VER_SHIFT)
		& MCU_VERSION_MASK;
	pboardi->mcu_info.mcu_minor = (reg32 >> MCU_SW_MINOR_VER_SHIFT)
		& MCU_VERSION_MASK;
	/*split minor and build version from uint8*/
	pboardi->mcu_info.mcu_build = pboardi->mcu_info.mcu_minor & 0xF;
	pboardi->mcu_info.mcu_minor = (pboardi->mcu_info.mcu_minor & 0xF0) >> 4;
	pboardi->mcu_info.mcu_rc = 0;

	reg32 = cn_mcu_read32(core, PIGEON_IPC1);
	pboardi->bsp_major = (reg32 >> 16) & 0xFF;
	pboardi->bsp_minor = (reg32 >> 12) & 0xF;

	/* ipu info */
	pboardi->cluster_num = 1;
	pboardi->ipu_core_num = 1;
	pboardi->mem_channel = 1;

	/* sn info */
	reg32 = cn_mcu_read32(core, PIGEON_IPC6);
	serial_num = reg32;
	reg32 = cn_mcu_read32(core, PIGEON_IPC7);
	serial_num |= ((u64)reg32 << 32);
	pboardi->board_type = (reg32 >> 16) & 0xffff;
	pboardi->serial_num = serial_num;

	pboardi->gdma_mask = 0x1;
	pboardi->platform = MLU_PLAT_ASIC;

	/* uuid */
	memset(pboardi->uuid, 0, CNDRV_UUID_SIZE);

	/* unused item */
	pboardi->BA_serial_num = 0;
	pboardi->BA_mcu_fw_ver = 0;
	pboardi->slot_id = 0;
	pboardi->qdd_status = 0;
	pboardi->chip_id = 0;
	pboardi->peak_power = 0;

	/* sec info */
	pboardi->secure_mode = NORMAL_BOOT;
	memset(pboardi->soc_id.soc_id_data, 0x0, SOC_ID_SIZE);

	cn_ce_dev_core_info(core, "DDR Vendor %x", ddr_info & 0xf);

	reg32 = cn_mcu_read32(core, PIGEON_IPC9);
	cn_ce_dev_core_info(core, "DDR Info %x", reg32);
	cn_ce_dev_core_info(core, "DDR Type 0x%x", (reg32 >> 28) & 0xf);
	cn_ce_dev_core_info(core, "DDR Freq %u", (reg32 >> 18) & 0x3);
	cn_ce_dev_core_info(core, "DDR Capacity %u", (reg32 >> 4) & 0xfff);
	cn_ce_dev_core_info(core, "DDR Vendor id %u", (reg32 >> 1) & 0x7);
	cn_ce_dev_core_info(core, "DDR rank id %u", reg32 & 0x1);

	pboardi->ddr_type = (reg32 >> 28) & 0x3;
	pboardi->ddr_speed = ddr_speed_pigeon[(reg32 >> 18) & 0x3];
	pboardi->ddr_freq = ddr_freq_pigeon[pboardi->ddr_type];
	pboardi->bandwidth = ddr_bandwidth_pigeon[pboardi->ddr_type];
	pboardi->bandwidth_decimal = ddr_bandwidth_decimal_pigeon[pboardi->ddr_type];
	pboardi->ddr_cap = (reg32 >> 4) & 0xfff;
	if (!pboardi->ddr_cap)
		cn_xid_err(core, XID_MCU_ERR, "invalid ddr capacity : 0x%x", pboardi->ddr_cap);
	pboardi->total_memory = DDR_TOTAL_PIGEON(pboardi->ddr_cap);

	pboardi->marking_id = 0;

	/* get board info */
	pboardi->bus_width = pigeon_board_info[core->board_info.board_idx][INFO_BUS_WIDTH];
	pboardi->ecc_support = pigeon_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
	pboardi->stack_size = pigeon_board_info[core->board_info.board_idx][INFO_STACK_SIZE];
	pboardi->sram_size = pigeon_board_info[core->board_info.board_idx][INFO_SRAM_SIZE];
	pboardi->cache_size = pigeon_board_info[core->board_info.board_idx][INFO_CACHE_SIZE];
	pboardi->kc_limit = pigeon_board_info[core->board_info.board_idx][INFO_KC_LIMIT];
	pboardi->o_kc_limit = pigeon_board_info[core->board_info.board_idx][INFO_O_KC_LIMIT];

	cn_ce_dev_core_info(core, "board_model %#x ", core->board_model);

	return ret;
}

int mcu_read_power_info_pigeon(void *pcore, struct board_power_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	s8 *temp_buf = NULL;

	temp_buf = cn_kzalloc(PIGEON_TEMPERTURE_INFO_CONUT * sizeof(s8), GFP_KERNEL);
	if (!temp_buf) {
		cn_ce_dev_core_err(core, "alloc buf fail\n");
		return -ENOMEM;
	}

	reg_data.data = cn_mcu_read32(core, PIGEON_IPC11);
	cn_ce_dev_core_debug(core, "PIGEON_IPC11: %X, val: 0x%04X\n",
		PIGEON_IPC11, reg_data.data);
	/* IPU temp */
	temp_buf[0] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;

	/* VI temp */
	temp_buf[1] = reg_data.bit.data3 - MCU_TEMP_CORRECTION_FACTOR;

	/* CPU temp */
	temp_buf[2] = reg_data.bit.data2 - MCU_TEMP_CORRECTION_FACTOR;

	/* ISP temp */
	temp_buf[3] = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;

	reg_data.data = cn_mcu_read32(core, PIGEON_IPC12);
	cn_ce_dev_core_debug(core, "PIGEON_IPC12: %X, val: 0x%04X\n",
		PIGEON_IPC12, reg_data.data);

	/* TOPN temp */
	temp_buf[4] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;

	/* TBD */
	info->fan_speed = 0;
	info->board_power = 0;
	info->board_power_decimal = 0;
	info->max_power_decimal = 0;
	info->peak_power = 0;
	/* TBD */
	__mcu_read_power_cap_pigeon(core, &info->peak_power);

	info->temperature_num = PIGEON_TEMPERTURE_INFO_CONUT;
	info->temp = temp_buf;

	/* not support */
	info->edpp_count = 0;
	info->tdp_freq_capping_count = 0;

	return 0;
}

#define IPUFREQ_TIMEOUT 500
int mcu_read_ipu_freq_pigeon(void *pcore, struct ipu_freq_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	int i  = 0, j = 0;
	u64 fbdiv = 0;
	u64 frac = 0;
	u64 refdiv = 0;
	u64 postdiv1 = 0;
	u64 postdiv2 = 0;
	u64 val = 0;
	u64 div = 0;
	u64 dec = 0;

	info->ipu_overtemp_dfs_flag = 0;
	info->ipu_fast_dfs_flag = 0;
	/* in pigeon, die_ipu_cnt means count of CT/LT freq*/
	info->die_ipu_freq.die_ipu_cnt = 2;
	info->rated_ipu_freq = pboardi->rated_ipu_freq;

	while (++j <= IPUFREQ_TIMEOUT)
	{
		for (i = 0; i < 2; i++) {
			fbdiv = (cn_mcu_read32(core, 0x1240 + 0x00 + i * 0x40) >> 8) & 0xfff;
			frac = cn_mcu_read32(core, 0x1240 + 0x04 + i * 0x40) & 0xffffff;
			refdiv = cn_mcu_read32(core, 0x1240 + 0x00 + i * 0x40) & 0x3f;
			postdiv1 = (cn_mcu_read32(core, 0x1240 + 0x00 + i * 0x40) >> 27) & 0x7;
			postdiv2 = (cn_mcu_read32(core, 0x1240 + 0x00 + i * 0x40) >> 24) & 0x7;
			val = (((u64)24 * ((fbdiv << 24) + frac)) >> 24);
			div = (refdiv * postdiv1 * postdiv2);
			dec = do_div(val, div);
			if (dec >= 2) {
				val += 1;
			}

			info->die_ipu_freq.ipu_freq[i] = val;
		}

		info->ipu_freq = info->die_ipu_freq.ipu_freq[1];

		/* freq check */
		if (info->die_ipu_freq.ipu_freq[0] && info->die_ipu_freq.ipu_freq[1]) {
			goto out;
		}
		mdelay(1);
	}

	if (!info->die_ipu_freq.ipu_freq[0] || !info->die_ipu_freq.ipu_freq[1])
		return -EAGAIN;

	return 0;
out:
	return 0;
}
int mcu_read_max_temp_pigeon(void *pcore, int *max_temp)
{
	return 0;
}

int mcu_power_capping_pigeon(void *pcore, struct power_capping_info *pcinfo)
{
	int ret = 0;

	return ret;
}

int mcu_read_uuid_pigeon(void *pcore, unsigned char *uuid)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pbrdinfo = &core->board_info;
	u32 reg32 = 0;

	if (IS_ERR_OR_NULL(uuid)) {
		cn_ce_dev_core_err(core, "invalid uuid buffer");
		return -EINVAL;
	}

	/*CE uuid*/
	if (!pbrdinfo->uuid_ready) {
		reg32 = cn_mcu_read32(core, PIGEON_IPC15);
		memcpy(&pbrdinfo->uuid[0], &reg32, 4);

		reg32 = cn_mcu_read32(core, PIGEON_IPC14);
		memcpy(&pbrdinfo->uuid[4], &reg32, 4);

		reg32 = (cn_mcu_read32(core, PIGEON_IPC13)) & UUID_2_MASK;
		pbrdinfo->uuid[8] = reg32;
		pbrdinfo->uuid_ready = 1;
	}

	memcpy(uuid, pbrdinfo->uuid, CNDRV_UUID_SIZE);

	return 0;
}

int mcu_read_exception_info_pigeon(void *pcore, struct exception_info *info, u8 klog)
{
	return 0;
}

void mcu_exit_pigeon(void *mset)
{
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)mset;

	if (mcu_set) {
		mcu_set->core = NULL;
		mcu_set->mcu_ops = NULL;
	}
}

static const struct cn_mcu_ops mcu_pigeon_ops = {
	.read_basic_info = mcu_read_basic_info_pigeon,
	.read_power_info = mcu_read_power_info_pigeon,
	.read_ipu_freq = mcu_read_ipu_freq_pigeon,
	.read_max_temp = mcu_read_max_temp_pigeon,
	.read_over_temp_flag = NULL,
	.power_capping = mcu_power_capping_pigeon,
	.read_ddr_freq = NULL,
	.set_host_drv_status = NULL,
	.read_overtemp_freq = NULL,
	.mcu_exit = mcu_exit_pigeon,
	.get_overtemp_policy = NULL,
	.set_overtemp_policy = NULL,
	.read_uuid = mcu_read_uuid_pigeon,
	.set_d2d_crc_err = NULL,
	.read_exception_info = mcu_read_exception_info_pigeon,
};

int mcu_init_pigeon(struct cn_mcu_set *mcu_set)
{
	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_ce_dev_err("mcu set is null");
		return -EINVAL;
	}
	mcu_set->mcu_ops = &mcu_pigeon_ops;

	return 0;
}
