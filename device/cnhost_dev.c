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

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/delay.h>

#include "cndrv_debug.h"
#include "cndrv_core.h"

#include "device/cnhost_dev_sysfs.h"
#include "device/cnhost_dev_managed.h"

DEFINE_MUTEX(dev_global_mutex);
static DEFINE_SPINLOCK(dev_minor_lock);
static struct idr dev_minors_idr[CNHOST_DEV_MINOR_BUTT];
static dev_t dev_major_minor[CNHOST_DEV_MINOR_BUTT];

static char *dev_minor_name[CNHOST_DEV_MINOR_BUTT] = {
	"cambricon_ctl",
	"cambricon_dev",
	"cambricon_mi_cap",
	"cambricon_smlu_cap"
};
static int  dev_minor_size[CNHOST_DEV_MINOR_BUTT] = {1, 128, 1024, 1024};

struct cdev device_cdev[CNHOST_DEV_MINOR_BUTT];

static bool dev_core_init_complete;

#define FUNC_IN() do{printk("%s %d\n", __func__, __LINE__);}while(0)


#define replace_fops_my(f, fops) \
		do {	\
					struct file *__file = (f); \
					fops_put(__file->f_op); \
					BUG_ON(!(__file->f_op = (fops))); \
				} while(0)

static void dev_release(struct kref *ref)
{
	struct cnhost_device *dev = container_of(ref, struct cnhost_device, ref);

	if (dev->driver->release)
		dev->driver->release(dev);

	cnhost_devm_release(dev);

	kfree(dev->managed.final_kfree);
}

void cnhost_dev_get(struct cnhost_device *dev)
{
	if (dev)
		kref_get(&dev->ref);
}

void cnhost_dev_put(struct cnhost_device *dev)
{
	if (dev)
		kref_put(&dev->ref, dev_release);
}

unsigned int cnhost_dev_read(struct cnhost_device *dev)
{
    if (dev)
        return CN_KREF_READ(&dev->ref);
    return 0;
}


static struct cnhost_minor **dev_minor_get_slot(struct cnhost_device *dev,
					     unsigned int type)
{
	type = type;

	return &dev->primary;
}

int dev_minor_get_type(unsigned int major_id, unsigned int *type)
{
	int i = 0;

	for ( i = 0; i <  CNHOST_DEV_MINOR_BUTT; i++) {
		if (MAJOR(dev_major_minor[i]) == major_id) {
			*type  = i;
			return 0;
		}
	}

	return -EINVAL;
}

unsigned int cnhost_dev_get_major(int type)
{
	WARN_ON(CNHOST_DEV_MINOR_BUTT <= type);

	if (type >= CNHOST_DEV_MINOR_BUTT)
		return -EINVAL;

	return dev_major_minor[type];
}

static void dev_minor_alloc_release(struct cnhost_device *dev, void *data)
{
	struct cnhost_minor *minor = data;
	unsigned long flags;

	WARN_ON(dev != minor->dev);
	WARN_ON(CNHOST_DEV_MINOR_BUTT <= minor->type);

	put_device(minor->kdev);

	spin_lock_irqsave(&dev_minor_lock, flags);
	idr_remove(&dev_minors_idr[minor->type], minor->index);
	spin_unlock_irqrestore(&dev_minor_lock, flags);
}

dev_t cnhost_dev_get_devt(struct cnhost_device *dev)
{
	struct cnhost_minor *minor;
	dev_t devt;

	if (!dev || !dev->primary) {
		WARN_ON(1);
		return 0;
	}

	minor = *dev_minor_get_slot(dev, 0);
	devt = MKDEV(minor->major, minor->index);

	return devt;
}

static int dev_minor_alloc(struct cnhost_device *dev, unsigned int type)
{
	struct cnhost_minor *minor;
	unsigned long flags;
	int r;

	minor = cnhost_devm_kzalloc(dev, sizeof(*minor), GFP_KERNEL);
	if (!minor)
		return -ENOMEM;

	minor->type = type;
	minor->dev = dev;

	idr_preload(GFP_KERNEL);
	spin_lock_irqsave(&dev_minor_lock, flags);
	r = idr_alloc(&dev_minors_idr[type],
		      NULL,
		      0,
		      dev_minor_size[type],
		      GFP_NOWAIT);
	spin_unlock_irqrestore(&dev_minor_lock, flags);
	idr_preload_end();

	if (r < 0)
		return r;

	minor->major = MAJOR(dev_major_minor[type]);
	minor->index = r;

	r = cnhost_devm_add_action_or_reset(dev, dev_minor_alloc_release, minor);
	if (r)
		return r;

	minor->kdev = cnhost_dev_sysfs_minor_alloc(minor);
	if (IS_ERR(minor->kdev))
		return PTR_ERR(minor->kdev);

	*dev_minor_get_slot(dev, type) = minor;
	return 0;
}

static int dev_minor_register(struct cnhost_device *dev)
{
	struct cnhost_minor *minor;
	unsigned long flags;
	int ret;

	cn_dev_debug("\n");

	minor = *dev_minor_get_slot(dev, 0);
	if (!minor)
		return -EINVAL;
	if (cn_pre_check_dev_node(dev_name(minor->kdev))) {
		return -1;
	}
	ret = device_add(minor->kdev);
	if (ret)
		goto err_debugfs;

	spin_lock_irqsave(&dev_minor_lock, flags);
	idr_replace(&dev_minors_idr[minor->type], minor, minor->index);
	spin_unlock_irqrestore(&dev_minor_lock, flags);

	cn_dev_debug("new minor registered %d\n", minor->index);
	return 0;

err_debugfs:
	return ret;
}

static void dev_minor_unregister(struct cnhost_device *dev)
{
	struct cnhost_minor *minor;
	unsigned long flags;
	unsigned int dev_ref = 0;

	minor = *dev_minor_get_slot(dev, 0);
	if (!minor || !device_is_registered(minor->kdev))
		return;

	spin_lock_irqsave(&dev_minor_lock, flags);
	while ((dev_ref = cnhost_dev_read(dev)) > 1) {
		spin_unlock_irqrestore(&dev_minor_lock, flags);
		cn_dev_err_limit("%s(minor %d ref:%d pf_idx:%d vf_idx:%d) is opened, Please close cambricon device first",
				dev_name(minor->kdev), minor->index, dev_ref, dev->card_index, dev->vf_index);
		msleep(1000);
		spin_lock_irqsave(&dev_minor_lock, flags);
	}
	idr_replace(&dev_minors_idr[minor->type], NULL, minor->index);
	spin_unlock_irqrestore(&dev_minor_lock, flags);

	device_del(minor->kdev);
	dev_set_drvdata(minor->kdev, NULL);
}

struct cnhost_minor *find_cnhost_minor(unsigned int type, unsigned int minor_id)
{
	struct cnhost_minor *minor;
	unsigned long flags;

	spin_lock_irqsave(&dev_minor_lock, flags);
	minor = idr_find(&dev_minors_idr[type], minor_id);
	spin_unlock_irqrestore(&dev_minor_lock, flags);

	if (!minor) {
		return ERR_PTR(-ENODEV);
	}

	return minor;
}

struct cnhost_minor *cnhost_dev_minor_acquire(unsigned int major_id, unsigned int minor_id)
{
	struct cnhost_minor *minor;
	unsigned long flags;
	int ret = 0;
	unsigned int type;

	ret = dev_minor_get_type(major_id, &type);
	if (ret) {
		return ERR_PTR(-ENODEV);
	}

	spin_lock_irqsave(&dev_minor_lock, flags);
	minor = idr_find(&dev_minors_idr[type], minor_id);
	if (minor)
		cnhost_dev_get(minor->dev);
	spin_unlock_irqrestore(&dev_minor_lock, flags);

	if (!minor) {
		return ERR_PTR(-ENODEV);
	}

	return minor;
}

void cnhost_dev_minor_release(struct cnhost_minor *minor)
{
	cnhost_dev_put(minor->dev);
}

void cnhost_dev_unregister(struct cnhost_device *dev)
{
	dev->registered = false;

	dev_minor_unregister(dev);
}

static void dev_init_release(struct cnhost_device *dev, void *res)
{
	put_device(dev->dev);

	dev->dev = NULL;
	mutex_destroy(&dev->struct_mutex);
}

static int dev_init(struct cnhost_device *dev,
			const struct cnhost_driver *driver,
			struct device *parent, unsigned int type)
{
	int ret;

	if (!dev_core_init_complete) {
		cn_dev_err("device core is not initialized\n");
		return -ENODEV;
	}

	kref_init(&dev->ref);
	dev->dev = get_device(parent);
	dev->driver = driver;

	INIT_LIST_HEAD(&dev->managed.resources);
	spin_lock_init(&dev->managed.lock);

	mutex_init(&dev->struct_mutex);

	ret = cnhost_devm_add_action(dev, dev_init_release, NULL);
	if (ret)
		return ret;

	ret = dev_minor_alloc(dev, type);
	if (ret)
		goto err;

	return 0;

err:
	cnhost_devm_release(dev);

	return ret;
}

struct cnhost_device *cnhost_dev_alloc(const struct cnhost_driver *driver,
				 void *private, unsigned int type, int card_index, int vf_index)
{
	struct cnhost_device *dev;
	int ret;

	if (type >= CNHOST_DEV_MINOR_BUTT)
		return ERR_PTR(-EINVAL);

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	dev->card_index = card_index;
	dev->vf_index = vf_index;

	dev->dev_private = private;

	ret = dev_init(dev, driver, NULL, type);
	if (ret) {
		kfree(dev);
		return ERR_PTR(ret);
	}

	cnhost_devm_add_final_kfree(dev, dev);

	return dev;
}

int cnhost_dev_register(struct cnhost_device *dev, unsigned long flags)
{
	const struct cnhost_driver *driver = dev->driver;
	int ret;

	WARN_ON(!dev->managed.final_kfree);
	WARN_ON(!dev->primary);

	mutex_lock(&dev_global_mutex);

	ret = dev_minor_register(dev);
	if (ret)
		goto err_minors;

	dev->registered = true;

	cn_dev_info("Initialized %s for %s on minor %d",
		 driver->name, dev_name(dev->primary->kdev),
		 dev->primary->index);

	goto out_unlock;

err_minors:
	dev_minor_unregister(dev);
out_unlock:
	mutex_unlock(&dev_global_mutex);
	return ret;
}

static int dev_stub_open(struct inode *inode, struct file *filp)
{
	const struct file_operations *new_fops;
	struct cnhost_minor *minor;
	int err;

	cn_dev_debug("\n");

	minor = cnhost_dev_minor_acquire(imajor(inode), iminor(inode));
	if (IS_ERR(minor))
		return PTR_ERR(minor);

	new_fops = fops_get(minor->dev->driver->fops);
	if (!new_fops) {
		err = -ENODEV;
		goto out;
	}

	replace_fops_my(filp, new_fops);
	if (filp->f_op->open)
		err = filp->f_op->open(inode, filp);
	else
		err = 0;

out:
	cnhost_dev_minor_release(minor);

	return err;
}

static const struct file_operations dev_stub_fops = {
	.owner = THIS_MODULE,
	.open = dev_stub_open,
	.llseek = noop_llseek,
};

void cnhost_dev_core_exit(void)
{
	int i = 0;

	if (!dev_core_init_complete)
		return;

	for (i = 0; i < CNHOST_DEV_MINOR_BUTT; i++) {
		cdev_del(&device_cdev[i]);
		unregister_chrdev_region(dev_major_minor[i], dev_minor_size[i]);
	}

	cnhost_dev_sysfs_destory();

	for (i = 0; i < CNHOST_DEV_MINOR_BUTT; i++) {
		idr_destroy(&dev_minors_idr[i]);
	}

}

int cnhost_dev_core_init(void)
{
	int ret;
	int i = 0;

	for (i = 0; i < CNHOST_DEV_MINOR_BUTT; i++) {
		idr_init(&dev_minors_idr[i]);
	}

	ret = cnhost_dev_sysfs_init();
	if (ret < 0) {
		cn_dev_err("Cannot create class: %d\n", ret);
		goto error_sysfs;
	}

	for (i = 0; i < CNHOST_DEV_MINOR_BUTT; i++) {
		ret = alloc_chrdev_region(&dev_major_minor[i], 0, dev_minor_size[i], dev_minor_name[i]);
		if (ret < 0)
			goto error_chr;

		cdev_init(&device_cdev[i], &dev_stub_fops);
		cdev_add(&device_cdev[i], dev_major_minor[i], dev_minor_size[i]);
	}

	dev_core_init_complete = true;

	cn_dev_debug("Initialized\n");
	return 0;

error_chr:
	for ( i--; i >= 0; i--) {
		cdev_del(&device_cdev[i]);
		unregister_chrdev_region(dev_major_minor[i], dev_minor_size[i]);
	}

	cnhost_dev_sysfs_destory();

error_sysfs:
	for (i = 0; i < CNHOST_DEV_MINOR_BUTT; i++) {
		idr_destroy(&dev_minors_idr[i]);
	}
	return ret;
}

