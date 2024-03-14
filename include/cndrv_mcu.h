/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_CNDRV_MCU_H__
#define __CAMBRICON_CNDRV_MCU_H__

#define IPU_FREQ_MHZ(x) (x)
#define KERNEL_CLASS_LIMIT(x) (x)
#define OBSOLETE_KERNEL_CLASS_LIMIT(x) (x)
#define DDR_BUS_WIDTH(x) (x)
/* LLC_NUM * width */
#define BUS_WIDTH(x, y)       ((x) * (y))

/* ecc support */
enum ECC_SUPPORT {
	ECC_NOT_SUPPORT = 0,
	ECC_SUPPORT = 1,
};

/* maximum stack memory per mlu in MB, 512MB */
#define STACK_SIZE	((8ULL << 30) / 20 / 0x100000)
#define OBSOLETE_STACK_SIZE 0
/* maximum sram memory in Bytes, 2MB */
#define SRAM_SIZE	(1024 * 1024 + 1024 * 1024)

/* maximum sram memory in Bytes, 4MB */
#define SRAM_SIZE_370 (1024 * 1024 * 4)

/* system cache size in Bytes, 1K */
#define CACHE_SIZE	(256 * 1024 * 4)

#define DYNAMIC_VALUE	(0)

#define MB_2_B(x) ((x) << 20)
#define KB_2_B(x) ((x) << 10)

/* system cache size in Bytes */
enum SYSTEM_CACHE_SIZE {
	CACHE_SIZE_256KB = KB_2_B(256U),
	CACHE_SIZE_1MB   = MB_2_B(1U),
	CACHE_SIZE_2MB   = MB_2_B(2U),
	CACHE_SIZE_24MB  = MB_2_B(24U),
	CACHE_SIZE_40MB  = MB_2_B(40U),
	CACHE_SIZE_48MB  = MB_2_B(48U),
	CACHE_SIZE_80MB  = MB_2_B(80U),
	CACHE_SIZE_96MB  = MB_2_B(96U),
};

/* mcu version check */
#define MCU_VER_CHECK   (1)
#define MCU_VER_UNCHECK (0)

#define MIN_POWER_CAP_CTRL (0)

#define HIGH_PRECISION_POWER_CAP_SUPPORT     0

/**************** mlu290 ****************/
#define CHIP_VERSION_INFO_MLU290	(0x0000)

#define IPC_BASE 0x00000004
#define IPC0     (IPC_BASE + 0x0)
#define IPC1     (IPC_BASE + 0x4) /* card SN low 32 bit */
#define IPC2     (IPC_BASE + 0x8) /* card SN high 16 bit */
#define IPC3     (IPC_BASE + 0xc) /* mother board SN low 32 bit */
#define IPC4     (IPC_BASE + 0x10) /* mother board SN high 16 bit */
#define IPC5     (IPC_BASE + 0x14) /* temperature */
#define IPC6     (IPC_BASE + 0x18)
#define IPC7     (IPC_BASE + 0x1c) /* mcu version */
#define IPC8     (IPC_BASE + 0x20)
#define IPC9     (IPC_BASE + 0x24)
#define IPC10    (IPC_BASE + 0x28) /* every HBM temp */
#define IPC11    (IPC_BASE + 0x2c)
#define IPC12    (IPC_BASE + 0x30)
#define IPC13    (IPC_BASE + 0x34) /* POWER CAP */
#define IPC14    (IPC_BASE + 0x38) /* board power */
#define IPC15    (IPC_BASE + 0x3c)
#define IPC16    (IPC_BASE + 0x40)
#define IPC17    (IPC_BASE + 0x44)
#define IPC18    (IPC_BASE + 0x48)
#define IPC19    (IPC_BASE + 0x4c)
#define IPC20    (IPC_BASE + 0x50)
#define IPC21    (IPC_BASE + 0x54)
#define IPC22    (IPC_BASE + 0x58)
#define IPC23    (IPC_BASE + 0x5c)
#define IPC24    (IPC_BASE + 0x60) /* IPU freq */
#define IPC25    (IPC_BASE + 0x64)
#define IPC26    (IPC_BASE + 0x68) /* HBM freq */
#define IPC27    (IPC_BASE + 0x6c)
#define IPC28    (IPC_BASE + 0x70)
#define IPC29    (IPC_BASE + 0x74)
#define IPC30    (IPC_BASE + 0x78)
#define IPC31    (IPC_BASE + 0x7c)

#define MCU_POWER_CAP_MASK_MLU290	0x7FFF
#define MCU_POWER_CAP_ENABLE_MLU290	0x8000

#define MLU290_TEMPERTURE_INFO_CONUT	8
/********************************/

/**************** mlu370 ****************/
#define MLU370_MCU_POWER_CAP_MASK	0x7FFF
#define MLU370_MCU_POWER_CAP_ENABLE	0x8000
#define MLU370_MCU_POWER_CAP_ENABLE_SHIFT	(15)
#define MLU370_MCU_POWER_CAP_ENABLE_MASK	(0X1 << MLU370_MCU_POWER_CAP_ENABLE_SHIFT)
#define MLU370_MCU_DDRTRAINED_FLAG_SHIFT  (11)
#define MLU370_MCU_DDRTRAINED_FLAG_MASK   (0x7)
#define MLU370_MCU_DDRTRAINED_MEM_DONE    (3)
#define MLU370_MCU_DDRTRAINED_BOOT_DONE   (4)
#define RSV_BASE  0x368000
#define IPC_0     (RSV_BASE + 0x8) /* MCU Status */
#define IPC_1     (RSV_BASE + 0xC) /* Status */
#define IPC_2     (RSV_BASE + 0x10) /* Set host driver status */
#define IPC_4     (RSV_BASE + 0x18) /* card SN low 32 bit */
#define IPC_5     (RSV_BASE + 0x1C) /* card SN high 16 bit */
#define IPC_6     (RSV_BASE + 0x20) /* FW Version */
#define IPC_7     (RSV_BASE + 0x24) /* MCU INFO, bit 14 has_fan */
#define IPC_8     (RSV_BASE + 0x28) /* 4-15 ddr cap */
#define IPC_9     (RSV_BASE + 0x2C) /* 0-9 bit TDP, 10-21 IPU FREQ*/
#define IPC_11    (RSV_BASE + 0x34) /* BA SN */
#define IPC_12    (RSV_BASE + 0x38) /* BA SN/FW */
#define IPC_13    (RSV_BASE + 0x3C) /* temperature */
#define IPC_15    (RSV_BASE + 0x44) /* power */
#define IPC_17    (RSV_BASE + 0x4C) /* QDD */
#define IPC_21    (RSV_BASE + 0x5C) /* IPU overtemp freq bit 20 */
#define IPC_22    (RSV_BASE + 0x60) /* IPU freq (ro) */
#define IPC_23    (RSV_BASE + 0x64) /* POWER CAP */
#define IPC_25    (RSV_BASE + 0x6C) /* VOLTAGE */

/********************************/
#define MLU590_MCU_DDRTRAINED_FLAG_SHIFT  (10)
#define MLU590_MCU_DDRTRAINED_FLAG_MASK   (0x7)
#define MLU590_MCU_DDRTRAINED_MEM_DONE    (0x1)
#define MLU590_MCU_DDRTRAINED_BOOT_DONE   (0x2)
#define MLU590_RSV_BASE  0x95E000
#define MLU590_CFG       (MLU590_RSV_BASE + 0xC) /* MCU Status */
#define MLU590_IPC_2     (MLU590_RSV_BASE + 0x24) /* Boot Status */
#define MLU590_IPC_3     (MLU590_RSV_BASE + 0x28) /* HBM Freq */
#define MLU590_IPC_4     (MLU590_RSV_BASE + 0x2c) /* HBM ECC */
#define MLU590_IPC_5     (MLU590_RSV_BASE + 0x30) /* HBM MASK */
#define MLU590_IPC_6     (MLU590_RSV_BASE + 0x34) /* HBM ECC */
#define MLU590_IPC_7     (MLU590_RSV_BASE + 0x38) /* MCU Version  */
#define MLU590_IPC_8     (MLU590_RSV_BASE + 0x3C) /* lt freq cap  */
#define MLU590_IPC_11    (MLU590_RSV_BASE + 0x48) /* static tdp */
#define MLU590_IPC_13    (MLU590_RSV_BASE + 0x50) /* dev sn low */
#define MLU590_IPC_14    (MLU590_RSV_BASE + 0x54) /* dev sn high */
#define MLU590_IPC_15    (MLU590_RSV_BASE + 0x58) /* ba SN low */
#define MLU590_IPC_16    (MLU590_RSV_BASE + 0x5C) /* ba SN high */
#define MLU590_IPC_17    (MLU590_RSV_BASE + 0x60) /* pcie fw version */
#define MLU590_IPC_19    (MLU590_RSV_BASE + 0x68) /* MCU Version */
#define MLU590_IPC_22    (MLU590_RSV_BASE + 0x74) /* chip/mem temp*/
#define MLU590_IPC_25    (MLU590_RSV_BASE + 0x80) /* Board temp */
#define MLU590_IPC_26    (MLU590_RSV_BASE + 0x84) /* chassis power */
#define MLU590_IPC_27    (MLU590_RSV_BASE + 0x88) /* chassis power */
#define MLU590_IPC_28    (MLU590_RSV_BASE + 0x8c) /* power */
#define MLU590_IPC_32    (MLU590_RSV_BASE + 0x9c) /* over temp */
#define MLU590_IPC_37    (MLU590_RSV_BASE + 0x110) /* power cap */
#define MLU590_IPC_36    (MLU590_RSV_BASE + 0x10c) /* ipu freq & cap */
#define MLU590_IPC_38    (MLU590_RSV_BASE + 0x114) /* ipu freq */
#define MLU590_IPC_41    (MLU590_RSV_BASE + 0x120) /* over temp ctrl */
#define MLU590_IPC_42    (MLU590_RSV_BASE + 0x124) /* freq capping */
#define MLU590_IPC_45    (MLU590_RSV_BASE + 0x130) /* pcie thoughput */
#define MLU590_IPC_46    (MLU590_RSV_BASE + 0x134) /* drv status & version */
#define MLU590_IPC_52    (MLU590_RSV_BASE + 0x14c) /* IPUSYS 4/5 freq */
#define MLU590_IPC_53    (MLU590_RSV_BASE + 0x150) /* IPUSYS 2/3 freq */
#define MLU590_IPC_54    (MLU590_RSV_BASE + 0x154) /* IPUSYS 0/1 freq */
#define MLU590_IPC_59    (MLU590_RSV_BASE + 0x168) /* resource ext */

/********************************/
#define MLU580_RSV_BASE  0x280000
#define MLU580_IPC_BASE  0x280100
#define MLU580_CFG       (MLU580_RSV_BASE + 0xC) /* MCU Status */
#define MLU580_CAPACITY  (MLU580_RSV_BASE + 0x10) /* DDR CAPACITY */
#define MLU580_IPC_2     (MLU580_IPC_BASE + 0x24) /* Boot Status */
#define MLU580_IPC_3     (MLU580_IPC_BASE + 0x28) /* DDR Freq */
#define MLU580_IPC_4     (MLU580_IPC_BASE + 0x2c) /* DDR ECC */
#define MLU580_IPC_5     (MLU580_IPC_BASE + 0x30) /* DDR MASK */
#define MLU580_IPC_6     (MLU580_IPC_BASE + 0x34) /* DDR ECC */
#define MLU580_IPC_7     (MLU580_IPC_BASE + 0x38) /* MCU Version  */
#define MLU580_IPC_11    (MLU580_IPC_BASE + 0x48) /* static tdp */
#define MLU580_IPC_13    (MLU580_IPC_BASE + 0x50) /* dev sn low */
#define MLU580_IPC_14    (MLU580_IPC_BASE + 0x54) /* dev sn high */
#define MLU580_IPC_15    (MLU580_IPC_BASE + 0x58) /* ba SN low */
#define MLU580_IPC_16    (MLU580_IPC_BASE + 0x5C) /* ba SN high */
#define MLU580_IPC_17    (MLU580_IPC_BASE + 0x60) /* pcie fw version */
#define MLU580_IPC_22    (MLU580_IPC_BASE + 0x74) /* chip/mem temp*/
#define MLU580_IPC_25    (MLU580_IPC_BASE + 0x80) /* Board temp */
#define MLU580_IPC_27    (MLU580_IPC_BASE + 0x88) /* over temp power off */
#define MLU580_IPC_28    (MLU580_IPC_BASE + 0x8c) /* power */
#define MLU580_IPC_32    (MLU580_IPC_BASE + 0x9c) /* over temp under clock */
#define MLU580_IPC_33    (MLU580_IPC_BASE + 0x100) /* ecc ctrl */
#define MLU580_IPC_37    (MLU580_IPC_BASE + 0x110) /* power cap */
#define MLU580_IPC_36    (MLU580_IPC_BASE + 0x10c) /* ipu freq & cap */
#define MLU580_IPC_38    (MLU580_IPC_BASE + 0x114) /* ipu freq */
#define MLU580_IPC_40    (MLU580_IPC_BASE + 0x11c) /* perf limit */
#define MLU580_IPC_41    (MLU580_IPC_BASE + 0x120) /* over temp ctrl */
#define MLU580_IPC_45    (MLU580_IPC_BASE + 0x130) /* pcie thoughput */
#define MLU580_IPC_46    (MLU580_IPC_BASE + 0x134) /* drv status & version */
#define MLU580_IPC_47    (MLU580_IPC_BASE + 0x138) /* board last time exception */
#define MLU580_IPC_50    (MLU580_IPC_BASE + 0x144) /* freq capping count */
#define MLU580_IPC_52    (MLU580_IPC_BASE + 0x14c) /* IPUSYS 4/5 freq */
#define MLU580_IPC_53    (MLU580_IPC_BASE + 0x150) /* IPUSYS 2/3 freq */
#define MLU580_IPC_54    (MLU580_IPC_BASE + 0x154) /* IPUSYS 0/1 freq */
/********************************/

enum board_info_type {
	INFO_KC_LIMIT = 0,
	INFO_MAX_IPU_FREQ,
	INFO_ECC_SUPPORT,
	INFO_BUS_WIDTH,
	INFO_STACK_SIZE,
	INFO_SRAM_SIZE,
	INFO_CACHE_SIZE,
	INFO_O_KC_LIMIT,
	INFO_TYPE_NUM,
};

enum cn_board_mlu270_info_idx {
	CN_MLU270_EVB = 0,
	CN_MLU270_D4,
	CN_MLU270_S4,
	CN_MLU270_S4a,
	CN_MLU270_V4,
	CN_MLU270_X5K,
	CN_MLU270_F4,
	CN_MLU270_FD4,
	CN_MLU270_V4K,
	CN_MLU270_VF,
	CN_MLU270_A4K,
	CN_MLU270_UNKNOWN_TYPE,
	CN_MLU270_MAX,
};

enum cn_board_mlu220_info_idx {
	CN_MLU220_M2 = 0,
	CN_MLU220_EDGE,
	CN_MLU220_EVB,
	CN_MLU220_M2i,
	CN_MLU220_M2RA,
	CN_MLU220_U2,
	CN_MLU220_M2t,
	CN_MLU220_SOM,
	CN_MLU220_MXM,
	CN_MLU220_MXMT,
	CN_MLU220_UNKNOWN_TYPE,
	CN_MLU220_MAX,
};

enum cn_board_mlu290_info_idx {
	CN_MLU290 = 0,
	CN_MLU290_VF,
	CN_MLU290_UNKNOWN_TYPE,
	CN_MLU290_MAX,
};

enum cn_board_mlu370_info_idx {
	CN_MLU370_EVB_D = 0,
	CN_MLU370_EVB_S,
	CN_MLU370_X4L,
	CN_MLU370_S4,
	CN_MLU370_X8,
	CN_MLU370_M8,
	CN_MLU365_D2,
	CN_MLU370_X4,
	CN_MLU370_M83U,
	CN_MLU370_X4K,
	CN_MLU370_VF,
	CN_MLU370_UNKNOWN_TYPE,
	CN_MLU370_MAX,
};

enum cn_board_ce3226_info_idx {
	CN_CE3226_S,
	CN_CE3226_D,
	CN_CE3226_UNKNOWN_TYPE,
	CN_CE3226_MAX,
};

enum cn_board_pigeon_info_idx {
	CN_LEOPARD,
	CN_PIGEON,
	CN_1V_2301,
	CN_PIGEON_UNKNOWN_TYPE,
	CN_PIGEON_MAX,
};

enum cn_board_mlu590_info_idx {
	CN_MLU585 = 0,
	CN_MLU590_H8,
	CN_MLU590_M9,
	CN_MLU590_M9U,
	CN_MLU590_M9L,
	CN_MLU585_V1,
	CN_MLU590_M9B,
	CN_MLU590_M9C,
	CN_MLU590_E,
	CN_MLU590_VF,
	CN_MLU590_UNKNOWN_TYPE,
	CN_MLU590_MAX,
};

enum cn_board_mlu580_info_idx {
	CN_MLU580_EVB = 0,
	CN_MLU560,
	CN_MLU560F,
	CN_MLU580,
	CN_MLU570,
	CN_MLU570F,
	CN_MLU580_VF,
	CN_MLU580_UNKNOWN_TYPE,
	CN_MLU580_MAX,
};

enum cn_pigeon_chipid_type {
	CN_CHIP_ID_LEOPARD = 0,
	CN_CHIP_ID_PIGEON = 1,
	CN_CHIP_ID_PIGEONC = 2,
	CN_CHIP_ID_1V_2301 = 3,
	CN_CHIP_ID_1V_2302 = 4,
	CN_CHIP_ID_UNKNOWN = 5,
	CN_CHIP_ID_MAX,
};

enum cndev_ipu_type {
	CT = 0,
	LT = 1,
	ALL = 2,
	IPU_TYPE_MAX,
};

enum mlu_subsys_id {
	SUBSYS_MLU370_EVBD = 0x50,
	SUBSYS_MLU370_EVBS = 0x51,
	SUBSYS_MLU370_X4L  = 0x52,
	SUBSYS_MLU370_S4   = 0x53,
	SUBSYS_MLU370_X8   = 0x54,
	SUBSYS_MLU370_M8   = 0x55,
	SUBSYS_MLU365_D2   = 0x56,
	SUBSYS_MLU370_X4   = 0x57,
	SUBSYS_MLU370_M83U = 0x58,
	SUBSYS_MLU370_X4K  = 0x59,
	SUBSYS_MLU585      = 0x8000,
	SUBSYS_MLU590_H8   = 0x8001,
	SUBSYS_MLU590_M9   = 0x8003,
	SUBSYS_MLU590_M9U  = 0x8003,
	SUBSYS_MLU590_M9L  = 0x8003,
	SUBSYS_MLU590_E    = 0x8010,
	SUBSYS_LEOPARD     = 0x8200,
	SUBSYS_PIGEON      = 0x8300,
	SUBSYS_MLU580_EVB  = 0x8100,
	SUBSYS_MLU560      = 0x8101,
	SUBSYS_MLU560F     = 0x8102,
	SUBSYS_MLU580      = 0x8103,
	SUBSYS_MLU570      = 0x8109,
	SUBSYS_MLU570F     = 0x8105,
};

enum mlu_noc_mode {
	NOC_MODE1 = 1,
	NOC_MODE2 = 2,
};

enum mlu_platform {
	MLU_PLAT_ASIC = 0,
	MLU_PLAT_ZEBU = 1,
	MLU_PLAT_PZ1 = 2,
	MLU_PLAT_FPGA = 3,
	MLU_PLAT_VDK = 4,
	MLU_PLAT_UNKNOW = 5,
};

struct board_power_info {
	/* current peak power may changed by power capping */
	u32 peak_power;
	u32 min_power_cap;
	/* current max power decimal*/
	u16 max_power_decimal;
	u32 min_power_cap_decimal;
	u32 max_power_cap_decimal;
	/* current fan speed */
	u16 fan_speed;
	/*current board power*/
	u16 board_power;
	u16 board_power_decimal;
	/*current machine power*/
	u16 machine_power;
	/*numbers of temp point*/
	u8 temperature_num;
	/*temperature array*/
	/*on mlu270 we have 5 temp point (top) and (ipu0-3) (-100-156)*/
	/*free this pointer before function finish*/
	s8 *temp;

	u8 fan_num;
	s16 *fan;
	/* over temperature power-off timers. */
	u32 over_temp_poweroff_times;
	/* over temperature under clocking timers. */
	u32 over_temp_underclock_times;
	/* over temperature power-off tmeperature. unit: degree */
	s8 over_temp_poweroff_temp;
	/* over temperature under clocking tmeperature. unit: degree */
	s8 over_temp_underclock_temp;
	/* total limit count */
	u8 perf_limit_num;
	/* power limit reason detail */
	u8 *perf_limit;

	u16 instantaneous_power;
	u16 instantaneous_power_decimal;

	u64 ipu_cluster_mask;
	u16 ipu_cluster_freq_num;
	u16 *ic_freq;
	u32 edpp_count;
	u32 tdp_freq_capping_count;
};

struct exception_info {
	/* halt reason */
	u32 exception_reason;

	/* detaile reason */
	u32 detail;
};

struct power_capping_info {
	/* input type read - 0 or write - 1 */
	u32 ops_type;
	/* power capping value read or write */
	u32 cap_value;
	/* mlu370 support temporary and permanent mode */
	u32 mode;
	/* card support high precision power cap */
	u16 high_precision_support;
	/* decimal power cap */
	u16 dec_cap_value;
};

struct multi_die_ipu_freq {
	__u8 die_ipu_cnt;
	__u32 ipu_freq[8];
};

struct ipu_freq_info {
	/*MHz*/
	__u32 ipu_freq;

	/*IPU over temperature freq adjust*/
	__u8 ipu_overtemp_dfs_flag;

	/*IPU fast dynamic freq*/
	__u8 ipu_fast_dfs_flag;

	/*reated ipu freq*/
	__u32 rated_ipu_freq;

	struct multi_die_ipu_freq die_ipu_freq;
};

struct cndev_overtemp_param {
	/* auto clear warning */
	__u8 mode;
	/* warning cycle */
	__u32 cycle;
};

extern const u64
mlu270_board_info[CN_MLU270_MAX][INFO_TYPE_NUM];
extern const u64
mlu220_board_info[CN_MLU220_MAX][INFO_TYPE_NUM];
extern const u64
mlu290_board_info[CN_MLU290_MAX][INFO_TYPE_NUM];
extern const u64
mlu370_board_info[CN_MLU370_MAX][INFO_TYPE_NUM];
extern const u64
ce3226_board_info[CN_CE3226_MAX][INFO_TYPE_NUM];
extern const u64
mlu590_board_info[CN_MLU590_MAX][INFO_TYPE_NUM];
extern const u64
pigeon_board_info[CN_PIGEON_MAX][INFO_TYPE_NUM];
extern const u64
mlu580_board_info[CN_MLU580_MAX][INFO_TYPE_NUM];

void cn_mcu_write32(void *pcore, unsigned long offset, u32 val);
u32 cn_mcu_read32(void *pcore, unsigned long offset);

int switch_core_type_check(struct cn_core_set *pcore);
int cndrv_mcu_read_power_info(void *pcore, struct board_power_info *info);
int cndrv_mcu_read_ipu_freq(void *pcore, struct ipu_freq_info *info);
int cndrv_mcu_read_max_temp(void *pcore, int *max_temp);
int cndrv_mcu_read_over_temp_flag(void *pcore, int *poweroff_flag);
int cndrv_mcu_power_capping(void *pcore, struct power_capping_info *pcinfo);
int cndrv_mcu_read_ddr_freq(void *pcore, u32 *freq);
int cndrv_mcu_set_host_driver_status(void *pcore, int status);
int cndrv_print_overtemp_freq_warning(void *pcore);
int cndrv_mcu_set_overtemp_param(void *pcore,
	struct cndev_overtemp_param *overtemp);
int cndrv_mcu_get_overtemp_param(void *pcore,
	struct cndev_overtemp_param *overtemp);
int cndrv_mcu_read_uuid(void *pcore, unsigned char *uuid);
int cndrv_set_d2d_crc_err(void *pcore,
	u32 status);
int cndrv_mcu_get_platform_info(void *pcore, void *info);
int cndrv_mcu_get_platform_id(void *pcore, u32 *chip_type);
int cndrv_mcu_read_overtemp_freq(void *pcore, struct mlu_overtemp_value *overtemp);
int cn_mcu_init(struct cn_core_set *core);
void cn_mcu_exit(struct cn_core_set *core);
int mcu_show_info(struct seq_file *m, void *v);

#endif
