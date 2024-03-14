/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_CNDRV_MCC_H__
#define __CAMBRICON_CNDRV_MCC_H__

#include "cndrv_core.h"

#define EEPROM_MAX_NUM			(512)
#define ECC_BIT_1			(0)
#define ECC_BIT_2			(1)
#define ECC_BIT_1_2			(2)

#define MLU370_D2DC_RX_CRC_ERR_DURATION   (3)

#define MLU590_HBM_CHANNEL_COUNT 6
#define MLU580_DDR_CHANNEL_COUNT 6

struct ecc_info_t {
	u64 one_bit_ecc_error;
	/* when 290/370 it means two bit err */
	u64 multiple_one_bit_ecc_error;
	u64 multiple_bit_ecc_error;
	u64 multiple_multiple_bit_ecc_error;
	u64 addr_forbidden_error;
};

struct die2die_crc_info_t  {
	u64 rx_crc_err;
	u64 rx_arq_crc_err;
	u64 rx_crc_err_overflow;
	u64 rx_arq_crc_err_overflow;
	/* for policy warning */
	u64 prev_rx_crc_err;
	u64 prev_rx_arq_crc_err;
	u64 prev_crc_err_inc;
	u64 prev_arq_crc_err_inc;
	u32 rx_crc_err_duration;
	u32 rx_arq_crc_err_duration;
	u64 rx_crc_of;
	u64 arq_rx_crc_of;
};

/**
 * addr_info_t used to translate, different platform have different meanings:
 *
 * MLU290:
 *     hbm_num == > HBM Index
 *     sys_num == > LLC Index
 *     pmc_num == > physical MemoryChannel Index
 *     chn_num == > MemoryChannel Index
 *     ecc_type == > ECC error type
 *     llc_addr == > LLC address
 *
 * MLU370:
 *     hbm_num == > Module Index
 *     sys_num == > LLC Index
 *     pmc_num == > LLC Config (bit[0]: shuffle & bit[2:1] interleaving_size)
 *     chn_num == > no used
 *     ecc_type == > ECC error type
 *     llc_addr == > LLC address (25bit llc_addr, need left shift 9 bits to get full address)
 **/
struct hbm_retire_info_t {
	union {
		u64 info;
		struct {
			u8 hbm_num;
			u8 sys_num;
			u8 pmc_num; /*phy_mc_num*/
			u8 chn_num;
			u32 ecc_addr;
		};
	};
	u32 ecc_type;
};

enum COMPRESS_CONFIG_EN {
	COMPRESS_CONFIG_ENABLE = 0,
	COMPRESS_CONFIG_DISABLE,
};

__attribute__((unused))
static const char *comp_mode_en[2] = {
	[COMPRESS_CONFIG_ENABLE] = "COMPRESS ENABLE",
	[COMPRESS_CONFIG_DISABLE] = "COMPRESS DISABLE",
};

enum LLC_COMPRESS_MODE {
	LLC_LOW_INTERLEAVE_COMPRESS = 0,
	LLC_HIGH_INTERLEAVE_COMPRESS,
	LLC_ND_INTERLEAVE_COMPRESS,
};

__attribute__((unused))
static const char *comp_mode_mode[3] = {
	[LLC_LOW_INTERLEAVE_COMPRESS] = "LOW INTERLEAVE",
	[LLC_HIGH_INTERLEAVE_COMPRESS] = "HIGH INTERLEAVE",
};

enum LLC_COMPRESS_HIGH_MODE {
	/* High interleave, and the low 40G memory can be compressed */
	LLC_COMPRESS_HIGH_MODE_LOW = 0,
	/* High interleave, and the high 40G memory can be compressed */
	LLC_COMPRESS_HIGH_MODE_HIGH,
	/* High interleave, and all the memory can be compressed */
	LLC_COMPRESS_HIGH_MODE_ALL,
};

enum MM_SIZE_LIMIT_COEF {
	MM_SIZE_ALL = 0, /*capacity 16GB--16GB,capacity 8GB--8GB*/
	MM_SIZE_LIMIT1,  /*capacity 16GB--8GB, capacity 8GB--4GB*/
	MM_SIZE_LIMIT2,  /*capacity 16GB--4GB, capacity 8GB--2GB*/
	MM_SIZE_LIMIT3,  /*capacity 16GB--2GB, capacity 8GB--1GB*/
	MM_SIZE_LIMIT4,  /*capacity 16GB--1GB, capacity 8GB--1GB*/
};

__attribute__((unused))
static const char *comp_high_mode[3] = {
	[LLC_COMPRESS_HIGH_MODE_LOW] = "LOW COMPRESS",
	[LLC_COMPRESS_HIGH_MODE_HIGH] = "HIGH COMPRESS",
};

#ifdef CONFIG_CNDRV_MCC
int cn_mcc_get_d2dc_num(void *pcore);
int cn_mcc_get_channel_num(void *pcore);
void *cn_mcc_get_ecc_status(void *pcore);
void *cn_mcc_get_d2dc_status(void *pcore);
void cn_mcc_get_map_mode(void *pcore, unsigned int *map_mode,
						  unsigned int *hbm_idx);
void cn_mcc_get_compress_info(void *pcore, unsigned int *compress_en,
				unsigned int *compress_mode, unsigned int *compress_high_mode);
void cn_mcc_get_mem_limit_coef(void *pcore, unsigned int *limit_coef);

void cn_mcc_dump_llc_state(void *pcore);

void cn_mcc_get_retire_info(void *pcore, struct hbm_retire_info_t **retire_info,
					unsigned int *retire_num, int irq_flag);
int cn_mcc_get_retire_pages(void *pcore, int cause, unsigned int *pagecount,
						u64 **page_addr);
int cn_mcc_get_retire_pages_pending_status(void *pcore, int *ispending,
						int *isfailure);
int cn_mcc_get_remapped_rows(void *pcore, unsigned int *corr_rows,
			unsigned int *unc_rows, unsigned int *pending_rows,
			unsigned int *fail_rows);
int cn_mcc_retire_switch(void *pcore, int status);
int cn_mcc_ecc_irq_inject(void *pcore, u32 sys_mc_num,
						u32 mc_state, u32 ecc_addr);
int cn_mcc_get_eeprom_switch(void *pcore, int status);
int cn_mcc_get_eeprom_info(void *pcore, unsigned int **rom_info, unsigned int *eeprom_num);
int cn_mcc_get_sys_mc_nums(void *pcore, unsigned int *sys_mc_nums);

int cn_mcc_init(struct cn_core_set *core);
void cn_mcc_exit(struct cn_core_set *core);
void cn_mcc_release_after_shutdown(struct cn_core_set *core);
#else
static inline int cn_mcc_get_d2dc_num(void *pcore)
{
	return -EINVAL;
}
static inline int cn_mcc_get_channel_num(void *pcore)
{
	return -EINVAL;
}
static inline void *cn_mcc_get_ecc_status(void *pcore)
{
	return NULL;
}
static inline void *cn_mcc_get_d2dc_status(void *pcore)
{
	return NULL;
}
static inline void cn_mcc_get_map_mode(void *pcore, unsigned int *map_mode,
						  unsigned int *hbm_idx)
{
	return;
}
static inline void cn_mcc_get_compress_info(void *pcore, unsigned int *compress_en,
				unsigned int *compress_mode, unsigned int *compress_high_mode)
{
	return;
}
static inline void cn_mcc_get_mem_limit_coef(void *pcore, unsigned int *limit_coef)
{
	return;
}

static inline void cn_mcc_dump_llc_state(void *pcore)
{
	return;
}

static inline void cn_mcc_get_retire_info(void *pcore, struct hbm_retire_info_t **retire_info,
					unsigned int *retire_num, int irq_flag)
{
}
static inline int cn_mcc_get_retire_pages(void *pcore, int cause, unsigned int *pagecount,
						u64 **page_addr)
{
	return -EINVAL;
}
static inline int cn_mcc_get_retire_pages_pending_status(void *pcore, int *ispending,
						int *isfailure)
{
	return -EINVAL;
}
static inline int cn_mcc_get_remapped_rows(void *pcore, unsigned int *corr_rows,
			unsigned int *unc_rows, unsigned int *pending_rows,
			unsigned int *fail_rows)
{
	return -EINVAL;
}
static inline int cn_mcc_retire_switch(void *pcore, int status)
{
	return -EINVAL;
}
static inline int cn_mcc_ecc_irq_inject(void *pcore, u32 sys_mc_num,
						u32 mc_state, u32 ecc_addr)
{
	return -EINVAL;
}
static inline int cn_mcc_get_eeprom_switch(void *pcore, int status)
{
	return -EINVAL;
}
static inline int cn_mcc_get_eeprom_info(void *pcore, unsigned int **rom_info, unsigned int *eeprom_num)
{
	return -EINVAL;
}
static inline int cn_mcc_get_sys_mc_nums(void *pcore, unsigned int *sys_mc_nums)
{
	return -EINVAL;
}

static inline int cn_mcc_init(struct cn_core_set *core)
{
	return 0;
}
static inline void cn_mcc_exit(struct cn_core_set *core)
{
}
static inline void cn_mcc_release_after_shutdown(struct cn_core_set *core)
{
}
#endif

#endif
