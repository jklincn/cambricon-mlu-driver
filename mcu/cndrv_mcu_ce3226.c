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

#define CE3226_TEMPERTURE_INFO_CONUT	3
#define CE3226_MCU_DDR_CAPACITY_MASK 0XFF
#define CE3226_MCU_DDR_TYPE_SHIFT 28
#define CE3226_MCU_DDR_TYPE_MASK 0XF
#define CE3226_MCU_DDR_CAPACITY_SHIFT 4

#define CE3226_IPC1     (0x214)
#define CE3226_IPC5     (0x224)
#define CE3226_IPC6     (0x228)
#define CE3226_IPC7     (0x22C)
#define CE3226_IPC9     (0x234)
#define CE3226_IPC11    (0x23c)
#define CE3226_IPC12    (0x240)
#define CE3226_IPC13    (0x244)

#define CE3226_RSV8    (0x1830)
#define CE3226_RSV9    (0x1834)
#define CE3226_RSV10   (0x1838)

#define DDR_TOTAL_CE3226(a) ((a) * 1024ULL * 1024ULL * 1024ULL)
#define CE3226_DDR_LP4 (0)
#define CE3226_DDR_LP5 (3)
#define CE3226_CHIP_TYPE 4

const char *ce3226_name[4] = {
	"CE3226ES",
	"CE3226V100",
	"CE3226V101",
	"CE3226V101",/* CE3226V100 Downgrade */
};
const u32 ce3226_ipufreq[4] = {
	1000, /* CE3226_ES */
	1200, /* CE3226V100 */
	1000, /* CE3226V101 */
	1000, /* CE3226V100 Downgrade */
};
const u32 rated_ddr_freq_ce3226[4] = {2133, 2133, 3200, 3200};
const u32 ddr_freq_ce3226[4] = {1600, 4266, 1600, 6400};
const u32 ddr_bandwidth[4] = {34, 34, 51, 51};
const u32 ddr_bandwidth_decimal[4] = {12, 12, 2, 2};

const u8 ce3226_platform[CE3226_CHIP_TYPE] = {
	CN_CHIP_TYPE_CE3226_ES,
	CN_CHIP_TYPE_CE3226_V100,
	CN_CHIP_TYPE_CE3226_V101,
	CN_CHIP_TYPE_CE3226_V101
};

int __mcu_read_power_cap_ce3226(void *pcore, u32 *cap_value)
{
	*cap_value = 0;

	return 0;
}

int __mcu_set_power_cap_ce3226(void *pcore, u32 cap_value)
{
	return 0;
}

#if defined(CONFIG_CNDRV_CE3226_SOC)
#include <linux/soc/cambricon/cambr-soc-info.h>

int mcu_read_basic_info_ce3226(void *pcore)
{
	int ret = 0;
	u32 ddr_freq;
	u32 reg32 = 0;
	u64 serial_num;
	u8 sn_high_8bit;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	int cnt;
	u32 die_mask = 0;
	u8 ddr_speed = 0;
	struct cambr_soc_info soc_info;

	/* DIE COUNT & DDR TRAINNING FLAG */
	reg32 = cn_mcu_read32(core, CE3226_IPC9);
	die_mask = ((reg32 >> 23) & 0x01) ? 3:1;
	reg32 = (reg32 >> 21) & 0x3;

	cnt = 300;
	do {
		if (reg32 != die_mask) {
			ret = -EBUSY;
		} else {
			cn_dev_core_info(core, "DDR Training Params set by MCU Finish");
			break;
		}
		reg32 = (cn_mcu_read32(core, CE3226_IPC9) >> 21) & 0x3;
		msleep(20);
	} while (--cnt);
	if (!cnt) {
		cn_xid_err(core, XID_MCU_ERR, "Wait DDR Training Finish Timeout!!");
		cn_recommend(core, USER_RECOMMED);
		return ret;
	}

	/*chip hardware version and ddr info*/
	pboardi->chip_type = 0;
	pboardi->chip_version = 0;

	reg32 = cn_mcu_read32(core, CE3226_IPC9);
	cn_dev_core_debug(core, "MEM&D2D reg: %X, val: 0x%08X\n", CE3226_IPC9, reg32);
	ddr_freq = 0;
	pboardi->ddr_cap = (reg32 >> CE3226_MCU_DDR_CAPACITY_SHIFT)
			& CE3226_MCU_DDR_CAPACITY_MASK;
	pboardi->total_memory = DDR_TOTAL_CE3226(pboardi->ddr_cap);
	pboardi->ddr_type = (reg32 >> CE3226_MCU_DDR_TYPE_SHIFT)
			& CE3226_MCU_DDR_TYPE_MASK;
	/* DIE COUNT */
	core->die_cnt = ((reg32 >> 23) & 0x01) ? 2:1;
	/* DDR FREQ, IPC_9 18-19 BIT */
	ddr_speed = (reg32 >> 28) & 0x3;
	pboardi->ddr_speed = ddr_freq_ce3226[(reg32 >> 18) & 0x3];
	pboardi->ddr_freq = rated_ddr_freq_ce3226[pboardi->ddr_type & 0x3];

	/* get bandwidth with ddr type */
	if ((pboardi->ddr_type & 0x3) == CE3226_DDR_LP4 ||
		(pboardi->ddr_type & 0x3) == CE3226_DDR_LP5) {
		pboardi->bandwidth = ddr_bandwidth[(pboardi->ddr_type & 0x3)];
		pboardi->bandwidth_decimal = ddr_bandwidth_decimal[(pboardi->ddr_type & 0x3)];
	} else {
		/* get bandwidth with ddr speed */
		pboardi->bandwidth = ddr_bandwidth[ddr_speed];
		pboardi->bandwidth_decimal = ddr_bandwidth_decimal[ddr_speed];
	}

	/*mcu version*/
	reg32 = cn_mcu_read32(core, CE3226_IPC5);
	cn_dev_core_debug(core, "version reg: %X, val: 0x%08X", CE3226_IPC5, reg32);
	reg32 = (reg32 >> 16) & 0xffff;
	pboardi->mcu_info.mcu_major = (reg32 >> MCU_SW_MAJOR_VER_SHIFT)
			& MCU_VERSION_MASK;
	pboardi->mcu_info.mcu_minor = (reg32 >> MCU_SW_MINOR_VER_SHIFT)
			& MCU_VERSION_MASK;
	/*split minor and build version from uint8*/
	pboardi->mcu_info.mcu_build = pboardi->mcu_info.mcu_minor & 0xF;
	pboardi->mcu_info.mcu_minor = (pboardi->mcu_info.mcu_minor & 0xF0) >> 4;
	pboardi->mcu_info.mcu_rc = 0;

	pboardi->cluster_num = 1;
	pboardi->ipu_core_num = 1;
	pboardi->mem_channel = 1;

	/*board serial number*/
	reg32 = cn_mcu_read32(core, CE3226_IPC6);
	serial_num = reg32;
	reg32 = cn_mcu_read32(core, CE3226_IPC7) & 0xFFFF;
	serial_num |= ((u64)reg32 << 32);

	/* SN HIGH 8BIT */
	sn_high_8bit = (reg32 >> 8) & 0xFF;
	pboardi->board_type = sn_high_8bit;
	cn_dev_core_info(core, "board serial: %016llX\n", serial_num);
	pboardi->serial_num = serial_num;

	pboardi->gdma_mask = core->die_cnt > 1 ? 0x1 : 0x3;
	pboardi->platform = MLU_PLAT_ASIC;

	pboardi->BA_serial_num = 0;
	pboardi->BA_mcu_fw_ver = 0;
	pboardi->slot_id = 0;
	pboardi->qdd_status = 0;
	pboardi->chip_id = 0;
	pboardi->secure_mode = NORMAL_BOOT;
	memset(pboardi->soc_id.soc_id_data, 0x0, SOC_ID_SIZE);

	memset(pboardi->uuid, 0, CNDRV_UUID_SIZE);

	if (core->device_id == MLUID_CE3226_EDGE) {
		core->board_model = CE3226_EDGE;
		switch (core->die_cnt) {
		case 1:
			core->board_info.board_idx = CN_CE3226_S;
			break;
		case 2:
			core->board_info.board_idx = CN_CE3226_D;
			break;
		default:
			cn_xid_err(core, XID_MCU_ERR, "unknown board type : %#x", sn_high_8bit);
			core->board_info.board_idx = CN_CE3226_UNKNOWN_TYPE;
			break;
		}
	}

	pboardi->peak_power = ce3226_basic_info_table[core->board_info.board_idx].peak_power;

	cambr_soc_get_family_id(&soc_info);
	pboardi->marking_id = soc_info.marking_id;
	strcpy(pboardi->board_model_name, ce3226_name[pboardi->marking_id & 0x3]);
	pboardi->platform_id = ce3226_platform[pboardi->marking_id & 0x3];

	cn_dev_core_info(core, "board_model_name %s, board_model %#x, marking_id %x",
		pboardi->board_model_name, core->board_model, soc_info.marking_id);

	/* get board info */
	pboardi->bus_width = ce3226_board_info[core->board_info.board_idx][INFO_BUS_WIDTH];
	pboardi->ecc_support = ce3226_board_info[core->board_info.board_idx][INFO_ECC_SUPPORT];
	pboardi->stack_size = ce3226_board_info[core->board_info.board_idx][INFO_STACK_SIZE];
	pboardi->sram_size = ce3226_board_info[core->board_info.board_idx][INFO_SRAM_SIZE];
	pboardi->cache_size = ce3226_board_info[core->board_info.board_idx][INFO_CACHE_SIZE];
	pboardi->kc_limit = ce3226_board_info[core->board_info.board_idx][INFO_KC_LIMIT];
	pboardi->o_kc_limit = ce3226_board_info[core->board_info.board_idx][INFO_O_KC_LIMIT];
	pboardi->rated_ipu_freq = ce3226_ipufreq[pboardi->marking_id & 0x3];
	cn_dev_core_info(core, "bus_width %u ecc_support %u, stack_size %llu",
		pboardi->bus_width,	pboardi->ecc_support, pboardi->stack_size);

	cn_dev_core_info(core, "sram_size %llu, cache_size %llu, kc_limit %u, rated_ipu_freq %u",
		pboardi->sram_size, pboardi->cache_size, pboardi->kc_limit, pboardi->rated_ipu_freq);

	return ret;
}
#else
int mcu_read_basic_info_ce3226(void *pcore)
{
	return 0;
}
#endif

int mcu_read_power_info_ce3226(void *pcore, struct board_power_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	s8 *temp_buf = NULL;
	struct cn_board_info *pboardi = &core->board_info;

	temp_buf = cn_kzalloc(CE3226_TEMPERTURE_INFO_CONUT * sizeof(s8), GFP_KERNEL);
	if (!temp_buf) {
		cn_dev_core_err(core, "alloc buf fail\n");
		return -ENOMEM;
	}

	reg_data.data = cn_mcu_read32(core, CE3226_IPC11);
	cn_dev_core_debug(core, "CE3226_IPC11: %X, reg: 0x20014,val: 0x%04X\n",
		CE3226_IPC11, reg_data.data);
	/* IPU temp */
	temp_buf[0] = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;

	/* VI temp */
	temp_buf[1] = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;

	/* CPU temp */
	temp_buf[2] = reg_data.bit.data2 - MCU_TEMP_CORRECTION_FACTOR;

	/* TBD */
	info->fan_speed = 0;

	reg_data.data = cn_mcu_read32(core, CE3226_IPC12);
	cn_dev_core_debug(core, "CE3226_IPC12: %X, reg: 0x20018,val: 0x%04X\n", CE3226_IPC12, reg_data.data);
	info->board_power = reg_data.data & 0xFFFF;

	/* TBD */
	info->board_power_decimal = 0;
	/* TBD */
	info->max_power_decimal =
		ce3226_basic_info_table[pboardi->board_idx].max_power_decimal;
	/* TBD */
	__mcu_read_power_cap_ce3226(core, &info->peak_power);

	info->temperature_num = CE3226_TEMPERTURE_INFO_CONUT;
	info->temp = temp_buf;

	/* not support */
	info->edpp_count = 0;
	info->tdp_freq_capping_count = 0;

	return 0;
}

#define IPUFREQ_TIMEOUT 500
int mcu_read_ipu_freq_ce3226(void *pcore, struct ipu_freq_info *info)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	int i  = 0, j = 0;
	u64 fbdiv = 0;
	u64 frac = 0;
	u64 refdiv = 0;
	u64 postdiv1 = 0;
	u64 postdiv2 = 0;
	u64 val = 0;
	u64 div = 0;
	u64 dec = 0;
	struct cn_board_info *pboardi = &core->board_info;

	info->ipu_overtemp_dfs_flag = 0;
	info->ipu_fast_dfs_flag = 0;
	/* in ce3226, die_ipu_cnt means count of CT/LT freq*/
	info->die_ipu_freq.die_ipu_cnt = 2;
	info->rated_ipu_freq = pboardi->rated_ipu_freq;

	while (++j <= IPUFREQ_TIMEOUT)
	{
		for (i = 0; i < 2; i++) {
			fbdiv = (cn_mcu_read32(core, 0x6b000 + 0x00 + i * 0x10) >> 8) & 0xfff;
			frac = cn_mcu_read32(core, 0x6b000 + 0x04 + i * 0x10) & 0xffffff;
			refdiv = cn_mcu_read32(core, 0x6b000 + 0x00 + i * 0x10) & 0x3f;
			postdiv1 = (cn_mcu_read32(core, 0x6b000 + 0x00 + i * 0x10) >> 27) & 0x7;
			postdiv2 = (cn_mcu_read32(core, 0x6b000 + 0x00 + i * 0x10) >> 24) & 0x7;
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

int mcu_read_max_temp_ce3226(void *pcore, int *max_temp)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	mcu_split_reg_byte_t reg_data;
	int temp_value;

	*max_temp = -MCU_TEMP_CORRECTION_FACTOR;

	reg_data.data = cn_mcu_read32(core, CE3226_IPC11);
	cn_dev_core_debug(core, "CE3226_IPC11: %X, reg: 0x20014,val: 0x%04X\n",
		CE3226_IPC11, reg_data.data);
	/* IPU temp */
	temp_value = reg_data.bit.data0 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* VI temp */
	temp_value = reg_data.bit.data1 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	/* CPU temp */
	temp_value = reg_data.bit.data2 - MCU_TEMP_CORRECTION_FACTOR;
	if (temp_value > *max_temp)
		*max_temp = temp_value;

	return 0;
}

int mcu_power_capping_ce3226(void *pcore, struct power_capping_info *pcinfo)
{
	int ret = 0;

	return ret;
}

int mcu_read_uuid_ce3226(void *pcore, unsigned char *uuid)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pbrdinfo = &core->board_info;
	u32 reg32 = 0;

	if (IS_ERR_OR_NULL(uuid)) {
		cn_dev_core_err(core, "invalid uuid buffer");
		return -EINVAL;
	}

	/*CE uuid*/
	if (!pbrdinfo->uuid_ready) {
		reg32 = cn_mcu_read32(core, CE3226_RSV10);
		memcpy(&pbrdinfo->uuid[0], &reg32, 4);

		reg32 = cn_mcu_read32(core, CE3226_RSV9);
		memcpy(&pbrdinfo->uuid[4], &reg32, 4);

		reg32 = (cn_mcu_read32(core, CE3226_RSV8)) & UUID_2_MASK;
		pbrdinfo->uuid[8] = reg32;
		pbrdinfo->uuid_ready = 1;
	}

	memcpy(uuid, pbrdinfo->uuid, CNDRV_UUID_SIZE);

	return 0;
}

int mcu_read_exception_info_ce3226(void *pcore, struct exception_info *info, u8 klog)
{
	return 0;
}

void mcu_exit_ce3226(void *mset)
{
	struct cn_mcu_set *mcu_set = (struct cn_mcu_set *)mset;

	if (mcu_set) {
		mcu_set->core = NULL;
		mcu_set->mcu_ops = NULL;
	}
}

static const struct cn_mcu_ops mcu_ce3226_ops = {
	.read_basic_info = mcu_read_basic_info_ce3226,
	.read_power_info = mcu_read_power_info_ce3226,
	.read_ipu_freq = mcu_read_ipu_freq_ce3226,
	.read_max_temp = mcu_read_max_temp_ce3226,
	.read_over_temp_flag = NULL,
	.power_capping = mcu_power_capping_ce3226,
	.read_ddr_freq = NULL,
	.set_host_drv_status = NULL,
	.read_overtemp_freq = NULL,
	.mcu_exit = mcu_exit_ce3226,
	.get_overtemp_policy = NULL,
	.set_overtemp_policy = NULL,
	.read_uuid = mcu_read_uuid_ce3226,
	.set_d2d_crc_err = NULL,
	.read_exception_info = mcu_read_exception_info_ce3226,
};

int mcu_init_ce3226(struct cn_mcu_set *mcu_set)
{
	cn_dev_debug("[%s] CE3226 platform\n", __func__);

	if (IS_ERR_OR_NULL(mcu_set)) {
		cn_dev_err("mcu set is null\n");
		return -EINVAL;
	}
	mcu_set->mcu_ops = &mcu_ce3226_ops;

	return 0;
}
