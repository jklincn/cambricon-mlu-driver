/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#ifndef __CNDRV_TRANS_H__
#define __CNDRV_TRANS_H__

#ifndef CONFIG_CNDRV_EDGE
int cn_host_mcu_trans_init(void *pcore);
void cn_host_mcu_free(void *pcore);

int cn_bus_is_support_soft_repair_info(void *bus_set);

#else
static inline int cn_host_mcu_trans_init(void *pcore)
{
	return 0;
}
static inline void cn_host_mcu_free(void *pcore)
{
}
static inline int cn_bus_is_support_soft_repair_info(void *bus_set)
{
	return -1;
}

#endif

#endif
