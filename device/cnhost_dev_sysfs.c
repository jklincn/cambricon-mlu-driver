/*
 *
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
#include <linux/device.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/cdev.h>

#include "cnhost_dev_internal.h"
#include "cnhost_dev_common.h"

#define DEVICE_NAME "cambricon"

static struct device_type sysfs_device_minor = {
	.name = DEVICE_NAME,
};

struct class *cnhost_dev_class;

static char *sysfs_devnode(struct device *dev, umode_t *mode)
{
	char *name_fmt = NULL;

	if (mode)
		*mode |= 0666;

	if (MAJOR(cnhost_dev_get_major(CNHOST_DEV_MINOR_MI_CAP)) == MAJOR(dev->devt)
		|| MAJOR(cnhost_dev_get_major(CNHOST_DEV_MINOR_SMLU_CAP)) == MAJOR(dev->devt))
		name_fmt = "cambricon-caps/%s";
	else
		name_fmt = "%s";

	return kasprintf(GFP_KERNEL, name_fmt, dev_name(dev));
}

int cnhost_dev_sysfs_init(void)
{
	cnhost_dev_class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR(cnhost_dev_class))
		return PTR_ERR(cnhost_dev_class);

	cnhost_dev_class->devnode = sysfs_devnode;

	return 0;
}

void cnhost_dev_sysfs_destory(void)
{
	if (IS_ERR_OR_NULL(cnhost_dev_class))
		return;
	class_destroy(cnhost_dev_class);
	cnhost_dev_class = NULL;
}

static void sysfs_release(struct device *dev)
{
	kfree(dev);
}

struct device *cnhost_dev_sysfs_minor_alloc(struct cnhost_minor *minor)
{
	const char *minor_str = NULL;
	struct device *kdev;
	int r = -1;

	switch (minor->type) {
	case  CNHOST_DEV_MINOR_PHYSICAL:
		minor_str = "cambricon_dev%d";
		break;
	case CNHOST_DEV_MINOR_CONTROL:
		minor_str = "cambricon_ctl";
		break;
	case CNHOST_DEV_MINOR_MI_CAP:
		minor_str = "cap_dev%d_mi%d";
		break;
	case CNHOST_DEV_MINOR_SMLU_CAP:
		minor_str = "cap_dev%d_mi%d";
		break;
	}

	kdev = kzalloc(sizeof(*kdev), GFP_KERNEL);
	if (!kdev)
		return ERR_PTR(-ENOMEM);

	device_initialize(kdev);
	kdev->devt = MKDEV(minor->major, minor->index);
	kdev->class = cnhost_dev_class;
	kdev->type = &sysfs_device_minor;
	kdev->parent = minor->dev->dev;
	kdev->release = sysfs_release;
	dev_set_drvdata(kdev, minor);

	if (minor->type == CNHOST_DEV_MINOR_CONTROL)
		r = dev_set_name(kdev, minor_str);
	else if (minor->type == CNHOST_DEV_MINOR_PHYSICAL)
		r = dev_set_name(kdev, minor_str, minor->dev->card_index);
	else if (minor->type == CNHOST_DEV_MINOR_MI_CAP)
		r = dev_set_name(kdev, minor_str, minor->dev->card_index, minor->dev->vf_index);
	else if (minor->type == CNHOST_DEV_MINOR_SMLU_CAP)
		r = dev_set_name(kdev, minor_str, minor->dev->card_index, minor->dev->vf_index);
	else
		r = dev_set_name(kdev, minor_str, minor->index);

	if (r < 0)
		goto err_free;

	return kdev;

err_free:
	put_device(kdev);
	return ERR_PTR(r);
}
