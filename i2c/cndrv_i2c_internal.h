/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CNDRV_I2C_INTERNAL_H__
#define __CNDRV_I2C_INTERNAL_H__

#include <linux/semaphore.h>

#define I2C_R_SLAVE_LEN	0x0001 /*read length according to slave*/

enum i2c_speed {
	STD_SPEED = 1,	/* 0 to 100 Kb/s*/
	FAST_SPEED,	/* <= 400 Kb/s or <= 1000 Kb/s */
	HIGH_SPPED,	/* < 3.4 Mb/s */
};

struct cn_i2c_msg {
	u16 addr;
	u16 flag;
	size_t len;
	u8 *buff;
};

struct cn_i2c_ops {
	void (*i2c_free)(void *iset);
	int (*config_i2c_speed)(void *iset, enum i2c_speed speed);
	int (*i2c_read)(void *iset, struct cn_i2c_msg *i2c_msg);
	int (*i2c_write)(void *iset, struct cn_i2c_msg *i2c_msg);
};

struct cn_i2c_set {
	struct cn_core_set *core;
	struct semaphore dw_i2c_sem;
	const struct cn_i2c_ops *i2c_ops;
};

#endif
