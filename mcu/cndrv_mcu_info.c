/* this file aim to define hardware information */
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_mcu.h"
#include "cndrv_debug.h"

#include "mcu.h"

const struct mlu_board_basic_info mlu270_basic_info_table[CN_MLU270_MAX] = {
	{150, "MLU270-EVB", 150, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_EVB */
	{70, "MLU270-D4", 70, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_D4 */
	{70, "MLU270-S4", 70, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_S4 */
	{70, "MLU270-S4a", 70, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_S4a */
	{70, "MLU270-V4", 70, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_V4 */
	{150, "MLU270-X5K", 150, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_X5K */
	{150, "MLU270-F4", 150, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_F4 */
	{150, "MLU270-FD4", 150, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_FD4 */
	{70, "MLU270-V4K", 70, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_V4K */
	{70, "MLU270-VF", 70, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_VF */
	{70, "MLU270-A4K", 70, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* MLU270_A4K */
	{70, "MLU270-UNKNOWN", 70, 0, 102, 4, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20L, 0, 0},/* UNKNOWN */
};

const struct mlu_board_basic_info mlu220_basic_info_table[CN_MLU220_MAX] = {
	{8, "MLU220-M2", 8, 25, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* CN_MLU220_M2 */
	{25, "MLU220-EDGE", 25, 0, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* CN_MLU220_EDGE */
	{8, "MLU220-EVB", 8, 25, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* CN_MLU220_EVB */
	{8, "MLU220-M2i", 12, 25, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* CN_MLU220_M2i */
	{8, "MLU220-M.2RA", 8, 25, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* CN_MLU220_M2RA */
	{16, "MLU220-U.2", 16, 0, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* CN_MLU220_U.2 */
	{8, "MLU220-M2t", 8, 25, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* CN_MLU220_M2t */
	{15, "MLU220-SOM", 15, 0, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* CN_MLU220_SOM 0x35 0x36 */
	{16, "MLU220-MXM", 16, 0, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* CN_MLU220_MXM */
	{16, "MLU220-MXMT", 16, 0, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* CN_MLU220_MXMT */
	{8, "MLU220-UNKNOWN", 8, 25, 29, 86, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20E, 200, 800},/* UNKNOWN */
};

const struct mlu_board_basic_info mlu290_basic_info_table[CN_MLU290_MAX] = {
	{350, "MLU290-M5", 350, 0, 1228, 8, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20, 0, 0},/* MLU290-M5 */
	{350, "MLU290-VF", 350, 0, 1228, 8, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20, 0, 0},/* MLU290_VF */
	{350, "MLU290-UNKNOWN", 350, 0, 1228, 8, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C20, 0, 0},/* UNKNOWN */
};

/* MLU370 max_power_cap & peak_power(tdp) read form mcu */
const struct mlu_board_basic_info mlu370_basic_info_table[CN_MLU370_MAX] = {
	{0, "MLU370-EVBD", 0, 0, 307, 2, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* MLU370_EVB_D */
	{0, "MLU370-EVBS", 0, 0, 153, 6, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S, 200, 1300},/* MLU370_EVB_S */
	{0, "MLU370-X4L", 0, 0, 307, 2, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* MLU370_X4L */
	{0, "MLU370-S4", 0, 0, 307, 2, 40, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* MLU370_S4 */
	{0, "MLU370-X8", 0, 0, 307, 2, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* MLU370_X8 */
	{0, "MLU370-M8", 0, 0, 307, 2, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* MLU370_M8 */
	{0, "MLU365-D2", 0, 0, 153, 6, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* MLU365_D2 */
	{0, "MLU370-X4", 0, 0, 307, 2, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* MLU370_X4 */
	{0, "MLU370-M8", 0, 0, 307, 2, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* MLU370_M83U */
	{0, "MLU370-X4K", 0, 0, 307, 2, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* MLU370_X4K */
	{0, "MLU370-VF", 0, 0, 307, 2, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* MLU370_VF */
	{0, "MLU370-UNKNOWN", 0, 0, 307, 2, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C30S_DUAL_DIE, 200, 1300},/* UNKNOWN */
};

const struct mlu_board_basic_info ce3226_basic_info_table[CN_CE3226_MAX] = {
	{25, "", 25, 0,
		DYNAMIC_VALUE, DYNAMIC_VALUE, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_CE3226_V101, 0, 0},/* CN_CE3226 */
	{25, "", 25, 0,
		DYNAMIC_VALUE, DYNAMIC_VALUE, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_CE3226_V100, 0, 0},/* CN_CE3226 D2D */
	{8, "", 8, 25,
		DYNAMIC_VALUE, DYNAMIC_VALUE, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_CE3226_ES, 0, 0},/* UNKNOWN */
};

const struct mlu_board_basic_info mlu590_basic_info_table[CN_MLU590_MAX] = {
	{0, "MLU580-H5",  0, 0, 1228, 8, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1500},/* MLU580-H5 */
	{0, "MLU590-H8",  0, 0, 2048, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1500},/* MLU590_M5 */
	{0, "MLU590-M9", 0, 0, 2764, 8, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1600},/* MLU590_M9 */
	{0, "MLU590-M9U",  0, 0, 2764, 8, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1600},/* MLU590_M9U*/
	{0, "MLU590-M9L", 0, 0, 2764, 8, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1600},/* MLU590_M9L */
	{0, "MLU585",  0, 0, 2048, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1500},/* MLU585 */
	{0, "MLU590-M9B", 0, 0, 2048, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1600},/* MLU590_M9B */
	{0, "MLU590-M9C", 0, 0, 2048, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1600},/* MLU590_M9C */
	{0, "MLU590-E", 0, 0, 2048, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1600},/* MLU590_E */
	/* TODO: Modify MI name */
	{0, "MLU590",  0, 0, 2764, 8, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1500},/* MLU590_VF */
	{0, "MLU590-UNKNOWN", 0, 0, 2048, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50, 600, 1500},/* UNKNOWN */
};

const struct mlu_board_basic_info mlu580_basic_info_table[CN_MLU580_MAX] = {
	{0, "MLU580-EVB",  0, 0, 768, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50S, 600, 1500},/* MLU580_EVB */
	{0, "MLU560",  0, 0, 384, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50S, 600, 1500},/* MLU560 */
	{0, "MLU560F", 0, 0, 384, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50S, 600, 1500},/* MLU560 */
	{0, "MLU580",  0, 0, 768, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50S, 600, 1500},/* MLU580 */
	{0, "MLU570", 0, 0, 640, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50S, 600, 1600},/* MLU570 */
	{0, "MLU570F", 0, 0, 640, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50S, 600, 1600},/* MLU570 */
	/* TODO: Modify MI name */
	{0, "MLU580",  0, 0, 768, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50S, 600, 1500},/* MLU580_VF */
	{0, "MLU580-UNKNOWN", 0, 0, 768, 0, MIN_POWER_CAP_CTRL, CN_CHIP_TYPE_C50S, 600, 1500},/* UNKNOWN */
};

/* array to record each board model's information */
const u64 mlu270_board_info[CN_MLU270_MAX][INFO_TYPE_NUM] = {
	/* MLU270_EVB */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU270_D4 */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* MLU270_S4 */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU270_S4a */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU270_V4 */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU270_X5K */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1100U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU270_F4 */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU270_FD4 */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU270_V4K */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU270_VF */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU270_A4K */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* UNKNOWN */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(256U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
};

/* array to record each board model's information */
const u64 mlu220_board_info[CN_MLU220_MAX][INFO_TYPE_NUM] = {
	/* MLU220_M2 */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(500U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* MLU220_EDGE */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(800U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* MLU220_EVB */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(500U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_256KB, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* CN_MLU220_M2i */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(500U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_256KB, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* CN_MLU220_M2RA */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(500U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_256KB, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* CN_MLU220_U.2 */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(500U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_256KB, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* CN_MLU220_M2t */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(500U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_256KB, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* CN_MLU220_SOM */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(800U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_256KB, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* CN_MLU220_MXM */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(500U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_256KB, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* CN_MLU220_MXMT */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(500U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_256KB, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* UNKNOWN */
	{KERNEL_CLASS_LIMIT(1), IPU_FREQ_MHZ(500U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
};

/* array to record each board model's information */
const u64 mlu290_board_info[CN_MLU290_MAX][INFO_TYPE_NUM] = {
	/* MLU290 */
	{KERNEL_CLASS_LIMIT(16), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(4096U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(64)},
	/* MLU290_VF */
	{KERNEL_CLASS_LIMIT(16), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(4096U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(64)},
	/* UNKNOWN */
	{KERNEL_CLASS_LIMIT(16), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(4096U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(64)},
};

/* array to record each board model's information */
const u64 mlu370_board_info[CN_MLU370_MAX][INFO_TYPE_NUM] = {
	/* MLU370_EVB_D */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1000U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU370_EVB_S */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(192U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU370_X4L */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1000U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU370_S4 */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU370_X8 */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1000U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU370_M8 */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1300U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU365_D2 */
	{KERNEL_CLASS_LIMIT(2), IPU_FREQ_MHZ(1000U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(192U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE_1MB, OBSOLETE_KERNEL_CLASS_LIMIT(8)},
	/* MLU370_X4 */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1000U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU370_M83U */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1300U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU370_X4K */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1000U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE_2MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU370-VF */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1300U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
	/* MLU370-UNKNOWN */
	{KERNEL_CLASS_LIMIT(4), IPU_FREQ_MHZ(1300U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE_370, CACHE_SIZE, OBSOLETE_KERNEL_CLASS_LIMIT(16)},
};

/* array to record each board model's information */
const u64 ce3226_board_info[CN_CE3226_MAX][INFO_TYPE_NUM] = {
	/* CE3226 */
	{KERNEL_CLASS_LIMIT(0), IPU_FREQ_MHZ(1000U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, 0, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* CE3226 D2D */
	{KERNEL_CLASS_LIMIT(0), IPU_FREQ_MHZ(1200U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, 0, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
	/* UNKNOWN */
	{KERNEL_CLASS_LIMIT(0), IPU_FREQ_MHZ(1000U), ECC_NOT_SUPPORT,
		DDR_BUS_WIDTH(64U), STACK_SIZE, SRAM_SIZE, 0, OBSOLETE_KERNEL_CLASS_LIMIT(4)},
};

/* array to record each board model's information */
const u64 pigeon_board_info[CN_PIGEON_MAX][INFO_TYPE_NUM] = {
	/* LEOPARD */
	{KERNEL_CLASS_LIMIT(0), IPU_FREQ_MHZ(1200U), ECC_SUPPORT,
		DDR_BUS_WIDTH(32U), OBSOLETE_STACK_SIZE, 0, CACHE_SIZE_1MB, OBSOLETE_KERNEL_CLASS_LIMIT(1)},
	/* PIGEON */
	{KERNEL_CLASS_LIMIT(0), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(32U), OBSOLETE_STACK_SIZE, 0, CACHE_SIZE_1MB, OBSOLETE_KERNEL_CLASS_LIMIT(1)},
	/* SOC_1V_2301 */
	{KERNEL_CLASS_LIMIT(0), IPU_FREQ_MHZ(1200), ECC_SUPPORT,
		DDR_BUS_WIDTH(32U), OBSOLETE_STACK_SIZE, 0, CACHE_SIZE_1MB, OBSOLETE_KERNEL_CLASS_LIMIT(1)},
	/* UNKNOWN */
	{KERNEL_CLASS_LIMIT(0), IPU_FREQ_MHZ(1000U), ECC_SUPPORT,
		DDR_BUS_WIDTH(32U), OBSOLETE_STACK_SIZE, 0, CACHE_SIZE_1MB, OBSOLETE_KERNEL_CLASS_LIMIT(1)},
};

/* array to record each board model's information */
const u64 mlu590_board_info[CN_MLU590_MAX][INFO_TYPE_NUM] = {
	/* MLU585 */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		BUS_WIDTH(3, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_24MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU590-H8 */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		BUS_WIDTH(5, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_40MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU590-M9 */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1600U), ECC_SUPPORT,
		BUS_WIDTH(6, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_48MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU590-M9U */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1600U), ECC_SUPPORT,
		BUS_WIDTH(6, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_48MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU590-M9L */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1600U), ECC_SUPPORT,
		BUS_WIDTH(6, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_48MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU585 */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		BUS_WIDTH(5, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_40MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU590-M9B */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1600U), ECC_SUPPORT,
		BUS_WIDTH(5, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_40MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU590-M9C */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1600U), ECC_SUPPORT,
		BUS_WIDTH(5, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_40MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU590-E */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1600U), ECC_SUPPORT,
		BUS_WIDTH(6, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_48MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU590_VF */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		BUS_WIDTH(6, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_48MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* UNKNOWN */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		BUS_WIDTH(5, 1024), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_40MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
};

const u64 mlu580_board_info[CN_MLU580_MAX][INFO_TYPE_NUM] = {
	/* MLU580-EVB */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_96MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU560 */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		DDR_BUS_WIDTH(192U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_48MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU560F */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		DDR_BUS_WIDTH(192U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_48MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU580 */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_96MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU570 */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1600U), ECC_SUPPORT,
		DDR_BUS_WIDTH(320U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_80MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU570F */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1600U), ECC_SUPPORT,
		DDR_BUS_WIDTH(320U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_80MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* MLU580_VF */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_48MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
	/* UNKNOWN */
	{KERNEL_CLASS_LIMIT(8), IPU_FREQ_MHZ(1500U), ECC_SUPPORT,
		DDR_BUS_WIDTH(384U), STACK_SIZE, SRAM_SIZE, CACHE_SIZE_40MB, OBSOLETE_KERNEL_CLASS_LIMIT(32)},
};

#define PEAK_K(x) ((x) * 1024)
#define PEAK_V(x) (x)

enum PEAK_PER_CYCLE_PER_CORE {
	/*0.375K*/
	PEAK_0_P_375K = 384,
	/*0.5K*/
	PEAK_0_P_5K = 512,
	/*1.5K*/
	PEAK_1_P_5K = 1536,
};

const u64 device_computing_power[BOARD_MAX][CNDEV_MAX_COMPUTING_POWER_TYPE] = {
	/*MLU100*/
	{
		PEAK_K(0), PEAK_K(0), PEAK_K(0), PEAK_K(0), PEAK_K(0), PEAK_K(0),
		PEAK_V(0), PEAK_V(0), PEAK_V(0), PEAK_V(0), PEAK_V(0)
	},
	/*MLU220*/
	{
		PEAK_K(4), PEAK_K(2), PEAK_K(1), PEAK_K(0), PEAK_K(0), PEAK_K(0),
		PEAK_V(64), PEAK_V(0), PEAK_V(32), PEAK_V(0), PEAK_V(0)
	},
	/*MLU270*/
	{
		PEAK_K(8), PEAK_K(4), PEAK_K(2), PEAK_K(0), PEAK_K(0), PEAK_K(0),
		PEAK_V(64), PEAK_V(0), PEAK_V(32), PEAK_V(0), PEAK_V(0)
	},
	/*MLU290*/
	{
		PEAK_K(8), PEAK_K(4), PEAK_K(2), PEAK_K(0), PEAK_K(0), PEAK_K(0),
		PEAK_V(64), PEAK_V(0), PEAK_V(32), PEAK_V(0), PEAK_V(0)
	},
	/*MLU370*/
	{
		PEAK_K(4), PEAK_K(4), PEAK_K(2), PEAK_1_P_5K, PEAK_1_P_5K, PEAK_0_P_375K,
		PEAK_V(128), PEAK_V(0), PEAK_V(64), PEAK_V(0), PEAK_V(0)
	},
	/*CE3226*/
	{
		PEAK_K(4), PEAK_K(2), PEAK_K(1), PEAK_K(0), PEAK_K(0), PEAK_K(0),
		PEAK_V(128), PEAK_V(0), PEAK_V(64), PEAK_V(0), PEAK_V(0)
	},
	/*MLU590*/
	{
		PEAK_K(8), PEAK_K(4), PEAK_K(1), PEAK_K(2), PEAK_K(2), PEAK_0_P_5K,
		PEAK_V(128), PEAK_V(0), PEAK_V(64), PEAK_V(0), PEAK_V(0)
	},
	/*PIGEON*/
	{
		PEAK_K(4), PEAK_K(2), PEAK_0_P_5K, PEAK_K(0), PEAK_K(0), PEAK_K(0),
		PEAK_V(64), PEAK_V(32), PEAK_V(32), PEAK_V(0), PEAK_V(0)
	},
	/*MLU580*/
	{
		PEAK_K(8), PEAK_K(4), PEAK_K(1), PEAK_K(2), PEAK_K(2), PEAK_0_P_5K,
		PEAK_V(128), PEAK_V(0), PEAK_V(64), PEAK_V(0), PEAK_V(0)
	},
	/*MLU270_VF*/
	{
		PEAK_K(8), PEAK_K(4), PEAK_K(2), PEAK_K(0), PEAK_K(0), PEAK_K(0),
		PEAK_V(64), PEAK_V(0), PEAK_V(32), PEAK_V(0), PEAK_V(0)
	},
	/*MLU290_VF*/
	{
		PEAK_K(8), PEAK_K(4), PEAK_K(2), PEAK_K(0), PEAK_K(0), PEAK_K(0),
		PEAK_V(64), PEAK_V(0), PEAK_V(32), PEAK_V(0), PEAK_V(0)
	},
	/*MLU370_VF*/
	{
		PEAK_K(4), PEAK_K(4), PEAK_K(2), PEAK_1_P_5K, PEAK_1_P_5K, PEAK_0_P_375K,
		PEAK_V(128), PEAK_V(0), PEAK_V(64), PEAK_V(0), PEAK_V(0)
	},
	/*MLU590_VF*/
	{
		PEAK_K(8), PEAK_K(4), PEAK_K(1), PEAK_K(2), PEAK_K(2), PEAK_0_P_5K,
		PEAK_V(128), PEAK_V(0), PEAK_V(64), PEAK_V(0), PEAK_V(0)
	},
	/*MLU580_VF*/
	{
		PEAK_K(8), PEAK_K(4), PEAK_K(1), PEAK_K(2), PEAK_K(2), PEAK_0_P_5K,
		PEAK_V(128), PEAK_V(0), PEAK_V(64), PEAK_V(0), PEAK_V(0)
	},
	/*BOARD_UNKNOWN_VF*/
	{},
	/*BOARD_UNKNOWN*/
	{},
};

const struct monitor_chip_info platform_info[CN_CHIP_TYPE_MAX - 1] = {
	{CN_CHIP_TYPE_C20E, "C20E"},
	{CN_CHIP_TYPE_C20L, "C20L"},
	{CN_CHIP_TYPE_C20, "C20"},
	{CN_CHIP_TYPE_C30S, "C30S"},
	{CN_CHIP_TYPE_C30S_DUAL_DIE, "C30D"},
	{CN_CHIP_TYPE_CE3226_V101, "CE3226V101"},
	{CN_CHIP_TYPE_CE3226_V100, "CE3226V100"},
	{CN_CHIP_TYPE_CE3226_ES, "CE3226_RESERVED"},
	{CN_CHIP_TYPE_C50, "C50"},
	{CN_CHIP_TYPE_LEOPARD, "LEOPARD"},
	{CN_CHIP_TYPE_PIGEON, "1V-2201"},
	{CN_CHIP_TYPE_PIGEONC, "1V-2202"},
	{CN_CHIP_TYPE_C50S, "C50S"},
	{CN_CHIP_TYPE_1V_2301, "1V-2301"},
	{CN_CHIP_TYPE_1V_2302, "1V-2302"},
};

struct cn_mcu_info cn_mlu270_mcu_ver_control[CN_MLU270_MAX] = {
	{1, 1, 3, MCU_VER_CHECK}, //EVB
	{1, 1, 3, MCU_VER_CHECK}, //D4
	{1, 1, 3, MCU_VER_CHECK}, //S4
	{1, 1, 3, MCU_VER_CHECK}, //S4a
	{1, 1, 3, MCU_VER_CHECK}, //V4
	{1, 1, 3, MCU_VER_CHECK}, //X5K
	{1, 1, 4, MCU_VER_CHECK}, //F4
	{1, 1, 3, MCU_VER_CHECK}, //FD4
	{1, 1, 3, MCU_VER_CHECK}, //V4K
	{1, 1, 3, MCU_VER_CHECK}, //VF
	{1, 1, 4, MCU_VER_CHECK}, //A4K
	{1, 1, 3, MCU_VER_CHECK}, //UNKNOWN_TYPE
};

struct cn_mcu_info cn_mlu220_mcu_ver_control[CN_MLU220_MAX] = {
	{1, 1, 0, MCU_VER_CHECK}, //M2
	{1, 0, 0, MCU_VER_UNCHECK}, //EDGE
	{1, 1, 0, MCU_VER_UNCHECK}, //EVB
	{1, 1, 0, MCU_VER_UNCHECK}, //M2i
	{1, 1, 0, MCU_VER_UNCHECK}, //M2RA
	{1, 1, 0, MCU_VER_UNCHECK}, //U.2
	{1, 1, 0, MCU_VER_UNCHECK}, //M2T
	{1, 1, 0, MCU_VER_UNCHECK}, //SOM
	{1, 1, 0, MCU_VER_UNCHECK}, //MXM
	{1, 1, 0, MCU_VER_UNCHECK}, //MXMT
	{1, 1, 0, MCU_VER_UNCHECK}, //UNKNOWN_TYPE
};

struct cn_mcu_info cn_mlu290_mcu_ver_control[CN_MLU290_MAX] = {
	{1, 0, 0, MCU_VER_UNCHECK}, //CN_MLU290
	{1, 0, 0, MCU_VER_UNCHECK}, //CN_MLU290_VF
	{1, 0, 0, MCU_VER_UNCHECK}, //CN_MLU290_UNKNOWN_TYPE
};

struct cn_mcu_info cn_mlu370_mcu_ver_control[CN_MLU370_MAX] = {
	{1, 1, 3, MCU_VER_UNCHECK}, //MLU370_EVB_D
	{1, 0, 0, MCU_VER_UNCHECK}, //MLU370_EVB_S
	{1, 0, 0, MCU_VER_UNCHECK}, //MLU370_X4L
	{1, 1, 3, MCU_VER_CHECK}, //MLU370_S4
	{1, 1, 3, MCU_VER_CHECK}, //MLU370_X8
	{1, 1, 3, MCU_VER_CHECK}, //MLU370_M8
	{1, 1, 3, MCU_VER_CHECK}, //MLU365_D2
	{1, 1, 3, MCU_VER_CHECK}, //MLU370_X4
	{1, 1, 3, MCU_VER_CHECK}, //MLU370_M83U
	{1, 0, 0, MCU_VER_UNCHECK}, //MLU370_X4K
	{1, 0, 0, MCU_VER_UNCHECK}, //MLU370-VF
	{1, 0, 0, MCU_VER_UNCHECK}, //MLU370-UNKNOWN
};

int mcu_version_contorl(struct cn_core_set *core,
						struct cn_mcu_info *ver,
						int board_idx,
						struct cn_mcu_info version_control[])
{
	int ret = 0;
	int compatible_major = 0, compatible_minor = 0, compatible_build = 0;

	compatible_major = ver->mcu_major - version_control[board_idx].mcu_major;
	compatible_minor = ver->mcu_minor - version_control[board_idx].mcu_minor;
	compatible_build = ver->mcu_build - version_control[board_idx].mcu_build;

	cn_dev_core_info(core,
		"MCU Ver: v%u.%u.%u, Standard Ver: v%u.%u.%u",
		ver->mcu_major, ver->mcu_minor, ver->mcu_build,
		version_control[board_idx].mcu_major,
		version_control[board_idx].mcu_minor,
		version_control[board_idx].mcu_build);

	if (version_control[board_idx].skip_check == MCU_VER_UNCHECK) {
		cn_dev_core_info(core, "Skip mcu version check.");
		return ret;
	}

	if (compatible_major != 0) {
		/*MCU Major Version Check Error*/
		cn_dev_core_err(core,
			"MCU Major Version Check Failed. Standard MCU Ver: v%u.%u.%u",
			version_control[board_idx].mcu_major,
			version_control[board_idx].mcu_minor,
			version_control[board_idx].mcu_build);

		if (core->cambr_mcu_version_check)
			ret = -EINVAL;
	} else if (compatible_minor != 0) {
		/*MCU Minor Version Check*/
		cn_dev_core_info(core,
			"MCU Minor Version Not Match. Standard MCU Ver: v%u.%u.%u",
			version_control[board_idx].mcu_major,
			version_control[board_idx].mcu_minor,
			version_control[board_idx].mcu_build);

	} else if (compatible_build != 0) {
		/*MCU Build Version Check*/
		cn_dev_core_info(core,
			"MCU Build Version Not Match. Standard MCU Ver: v%u.%u.%u",
			version_control[board_idx].mcu_major,
			version_control[board_idx].mcu_minor,
			version_control[board_idx].mcu_build);

	} else {
		cn_dev_core_info(core, "MCU Version Check successfully.");
	}

	return ret;
}

void cn_mcu_fill_platform_info(struct cn_core_set *core)
{
	struct cn_board_info *pboardi = &core->board_info;
	u32 len = ARRAY_SIZE(platform_info);

	pboardi->platform_num = len > CN_PALATFORM_TYPE_MAX_NUM ? CN_PALATFORM_TYPE_MAX_NUM : len;
	memcpy(pboardi->platform_info, platform_info, sizeof(struct monitor_chip_info) * pboardi->platform_num);
}
