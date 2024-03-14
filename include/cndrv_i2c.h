/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CNDRV_I2C_H__
#define __CNDRV_I2C_H__

#ifdef CONFIG_CNDRV_I2C
long cn_i2c_ioctl(void *pcore, unsigned int cmd, unsigned long arg);

int cn_i2c_init(struct cn_core_set *core);
void cn_i2c_exit(struct cn_core_set *core);
#else
long cn_i2c_ioctl(void *pcore, unsigned int cmd, unsigned long arg){
	return -1;
}

int cn_i2c_init(struct cn_core_set *core){
	return 0;
}
void cn_i2c_exit(struct cn_core_set *core){}
#endif

#endif
