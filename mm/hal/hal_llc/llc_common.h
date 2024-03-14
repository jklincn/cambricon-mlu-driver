/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef _LLC_COMMON_H
#define _LLC_COMMON_H

#define LLC_ENABLE              0
#define LLC_DISABLE             1
#define LLC_MAINTAIN            2
#define LLC_SET_EVENT           3
#define LLC_GET_EVENT           4
#define LLC_CLR_EVENT           5
#define LLC_ADB_RST             6
#define LLC_ADDR_MAP            7
#define LLC_RST                 8
#define LLC_LOCK_EN             9
#define LLC_LOCK_DIS            10
#define LLC_LOCK_CLR            11
#define LLC_LOCK_SET_WAYS       12
#define LLC_LOCK_GET_WAYS       13
#define LLC_LOCK_GET_IRQ_NUMS	14

enum {
	LLC_REMAP0 = 0x0,
	LLC_REMAP1 = 0x1,
	LLC_REMAP2 = 0x2,
	LLC_REMAP3 = 0x3,
};
#define LLC_DATA_LEN		(48)
struct llc_ctrl_in {
	unsigned int cmd;
	unsigned int data[LLC_DATA_LEN];
};

struct llc_ctrl_ret {
	int ret;
	unsigned int data[LLC_DATA_LEN];
};

void llc_dev_init(void *pcore);
void llc_cds_enable(void *pcore);
void llc_remap_set_for_all_channel(void *pcore, unsigned int remap);
int llc_maintanance(void *pcore, unsigned int action);
int llc_lock_en(void *pcore);
int llc_lock_dis(void *pcore);
int llc_lock_clr(void *pcore);
int llc_lock_set_ways(void *pcore, unsigned int ways);
int llc_lock_get_ways(void *pcore, unsigned int *ways);
int llc_get_irq_info(void *pcore);

#ifndef CONFIG_CNDRV_EDGE
void mlu220_llc_ops_register(void *);
void mlu270_llc_ops_register(void *);
void mlu290_llc_ops_register(void *);
void mlu370_llc_ops_register(void *);
void mlu590_llc_ops_register(void *);
static inline void pigeon_llc_ops_register(void *ops) {}
#else
static inline void mlu270_llc_ops_register(void *ops) {}
static inline void mlu290_llc_ops_register(void *ops) {}
static inline void mlu370_llc_ops_register(void *ops) {}
static inline void mlu590_llc_ops_register(void *ops) {}
#if defined(CONFIG_CNDRV_C20E_SOC)
void mlu220_llc_ops_register(void *);
#elif defined(CONFIG_CNDRV_CE3226_SOC)
static inline void mlu220_llc_ops_register(void *ops) {}
#elif defined(CONFIG_CNDRV_PIGEON_SOC)
static inline void mlu220_llc_ops_register(void *ops) {}
#else
static inline void mlu220_llc_ops_register(void *ops) {}
#endif

#if defined(CONFIG_CNDRV_PIGEON_SOC)
void pigeon_llc_ops_register(void *);
#else
static inline void pigeon_llc_ops_register(void *ops) {}
#endif
#endif

#endif	/* _LLC_COMMON_H */
