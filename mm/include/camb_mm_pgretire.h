/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_MM_PGRETIRE_H_
#define __CAMBRICON_MM_PGRETIRE_H_

/* MARCO only used in pageretire */
#define PGRETIRE_SHM_REV_SZ		(0x100000)
#define PGRETIRE_DBG_OFS		(0x80000)
#define PGRETIRE_MAGIC	((0x1211) + 'P')
#define PGRETIRE_INIT_MODE	(0)
#define PGRETIRE_IRQ_MODE	(1)
enum pgretire_status {
	PGRETIRE_IDLE = 0x0,
	PGRETIRE_PENDING = 0x1,
	PGRETIRE_RUNNING = 0x2,
};

enum pgretire_flags {
	PGRETIRE_ENABLE  = PGRETIRE_MAGIC + 1,
	PGRETIRE_DISABLE = PGRETIRE_MAGIC + 2,
};

/* FIXME: add max_cnt to get max cnt from mcc, without create definition in arm */

/* addr_info_t used to translate  */
struct addr_info_t {
	uint8_t hbm_id;		/* HBM ID */
	uint8_t sys_id;		/* LLC ID */
	uint8_t chl_id;		/* MC  ID */
	uint8_t ecc_type;	/* DBE or SBE */
	uint32_t llc_addr; /* 30bit LLC Address */
};

struct pgretire_info_t {
	uint16_t magic;
	uint16_t mode;
	uint16_t length;
	uint16_t counts;
	struct addr_info_t addrs[0];
};

#define PGRETIRE_MAX_CNT	(512)
#define PGRETIRE_BUF_LENS(count) \
	(sizeof(struct pgretire_info_t) + sizeof(struct addr_info_t) * (count))

struct pgretire_dbg_t {
	uint16_t magic;
	uint16_t ecc_type;
	uint16_t length;
	uint16_t counts;
	uint64_t pages[PGRETIRE_MAX_CNT];
};


int camb_init_page_retirement(struct cn_mm_set *mm_set);
unsigned int camb_set_pgretire_status(struct cn_mm_set *mm_set);
void camb_get_pgretire_result(struct cn_mm_set *mm_set,
				unsigned int flag, int retval);
int camb_get_pgretire_init_result(struct cn_mm_set *mm_set);
void camb_parse_pgretire_status(struct cn_mm_set *mm_set, void *seqfile);
int camb_do_page_retirement(struct cn_mm_set *mm_set, int pgretire_mode);
#endif /* __CAMBRICON_MM_PGRETIRE_H_ */
