/*
 * core/cndrv_devnode.h
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _CNDRV_DEV_MANAGER_H
#define _CNDRV_DEV_MANAGER_H
#include <linux/major.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/device.h>

struct device;
struct attribute_group;

#define DEV_DYNAMIC_MINOR	-1

#define DEVICE_MINORS           1024  
#define DEV_SPECIAL_CTL_MINOR	1023
#define DEV_SPECIAL_CAP_CONFIG_MINOR	0
#define DEV_SPECIAL_CAP_MONITOR_MINOR	1
/*
 * 0: cambricon-devX cambricon_ctl
 * 1: cambricon-caps/cambricon-capX
 */
typedef enum __drv_camb_dev_type_t {
	E_DEV_NODE_TYPE_DEV = 0,
	E_DEV_NODE_TYPE_CAP = 1,
	E_DEV_NODE_TYPE_BUTT = 2,
	}drv_camb_dev_type_t;

typedef struct __drv_camb_device_t {
	int major;
	int minor;
	char *name;
	struct file_operations *fops;

	struct list_head list;
	struct device *parent;
	struct device *this_device;

	const struct attribute_group **groups;
	umode_t mode;

	drv_camb_dev_type_t en_dev_type;
}drv_camb_device_t;

extern 
int camb_dev_register(drv_camb_dev_type_t en_dev_type, drv_camb_device_t * pst_camb_dev, struct file_operations *fops, int minor);

extern 
void camb_dev_deregister(drv_camb_device_t *pst_camb_dev);

#endif
