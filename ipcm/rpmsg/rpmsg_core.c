// SPDX-License-Identifier: GPL-2.0
/*
 * remote processor messaging bus
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 * Copyright (C) 2011 Google, Inc.
 *
 * Ohad Ben-Cohen <ohad@wizery.com>
 * Brian Swetland <swetland@google.com>
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include "../include/rpmsg/rpmsg.h"
#include <linux/of_device.h>
#include <linux/pm_domain.h>
#include <linux/slab.h>

#include "rpmsg_internal.h"

/**
 * cn_rpmsg_create_ept() - create a new rpmsg_endpoint
 * @rpdev: rpmsg channel device
 * @cb: rx callback handler
 * @priv: private data for the driver's use(optional, will be pass to ept->cb())
 * @chinfo: channel_info with the local rpmsg address to bind with @cb (use chinfo.src only)
 *
 * Every rpmsg address in the system is bound to an rx callback (so when
 * inbound messages arrive, they are dispatched by the rpmsg bus using the
 * appropriate callback handler) by means of an rpmsg_endpoint struct.
 *
 * This function allows drivers to create such an endpoint, and by that,
 * bind a callback, and possibly some private data too, to an rpmsg address
 * (either one that is known in advance, or one that will be dynamically
 * assigned for them).
 *
 * Simple rpmsg drivers need not call cn_rpmsg_create_ept, because an endpoint
 * is already created for them when they are probed by the rpmsg bus
 * (using the rx callback provided when they registered to the rpmsg bus).
 *
 * So things should just work for simple drivers: they already have an
 * endpoint, their rx callback is bound to their rpmsg address, and when
 * relevant inbound messages arrive (i.e. messages which their dst address
 * equals to the src address of their rpmsg channel), the driver's handler
 * is invoked to process it.
 *
 * That said, more complicated drivers might need to allocate
 * additional rpmsg addresses, and bind them to different rx callbacks.
 * To accomplish that, those drivers need to call this function.
 *
 * Drivers should provide their @rpdev channel (so the new endpoint would belong
 * to the same remote processor their channel belongs to), an rx callback
 * function, an optional private data (which is provided back when the
 * rx callback is invoked), and an address they want to bind with the
 * callback. If @addr is RPMSG_ADDR_ANY, then cn_rpmsg_create_ept will
 * dynamically assign them an available rpmsg address (drivers should have
 * a very good reason why not to always use RPMSG_ADDR_ANY here).
 *
 * Returns a pointer to the endpoint on success, or NULL on error.
 */
struct rpmsg_endpoint *cn_rpmsg_create_ept(struct rpmsg_device *rpdev,
					rpmsg_rx_cb_t cb, void *priv,
					struct rpmsg_channel_info chinfo)
{
	if (WARN_ON(!rpdev))
		return NULL;

	return rpdev->ops->create_ept(rpdev, cb, priv, chinfo);
}

/**
 * cn_rpmsg_destroy_ept() - destroy an existing rpmsg endpoint
 * @ept: endpoing to destroy
 *
 * Should be used by drivers to destroy an rpmsg endpoint previously
 * created with cn_rpmsg_create_ept(). As with other types of "free" NULL
 * is a valid parameter.
 */
void cn_rpmsg_destroy_ept(struct rpmsg_endpoint *ept)
{
	if (ept && ept->ops)
		ept->ops->destroy_ept(ept);
}

/**
 * cn_rpmsg_send() - send a message across to the remote processor
 * @ept: the rpmsg endpoint
 * @data: payload of message
 * @len: length of payload
 *
 * This function sends @data of length @len on the @ept endpoint.
 * The message will be sent to the remote processor which the @ept
 * endpoint belongs to, using @ept's address and its associated rpmsg
 * device destination addresses.
 * In case there are no TX buffers available, the function will block until
 * one becomes available, or a timeout of 15 seconds elapses. When the latter
 * happens, -ERESTARTSYS is returned.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
int cn_rpmsg_send(struct rpmsg_endpoint *ept, void *data, int len)
{
	if (WARN_ON(!ept))
		return -EINVAL;
	if (!ept->ops->send)
		return -ENXIO;

	return ept->ops->send(ept, data, len);
}

/**
 * cn_rpmsg_sendto() - send a message across to the remote processor, specify dst
 * @ept: the rpmsg endpoint
 * @data: payload of message
 * @len: length of payload
 * @dst: destination address
 *
 * This function sends @data of length @len to the remote @dst address.
 * The message will be sent to the remote processor which the @ept
 * endpoint belongs to, using @ept's address as source.
 * In case there are no TX buffers available, the function will block until
 * one becomes available, or a timeout of 15 seconds elapses. When the latter
 * happens, -ERESTARTSYS is returned.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
int cn_rpmsg_sendto(struct rpmsg_endpoint *ept, void *data, int len, u32 dst)
{
	if (WARN_ON(!ept))
		return -EINVAL;
	if (!ept->ops->sendto)
		return -ENXIO;

	return ept->ops->sendto(ept, data, len, dst);
}

/**
 * cn_rpmsg_send_offchannel() - send a message using explicit src/dst addresses
 * @ept: the rpmsg endpoint
 * @src: source address
 * @dst: destination address
 * @data: payload of message
 * @len: length of payload
 *
 * This function sends @data of length @len to the remote @dst address,
 * and uses @src as the source address.
 * The message will be sent to the remote processor which the @ept
 * endpoint belongs to.
 * In case there are no TX buffers available, the function will block until
 * one becomes available, or a timeout of 15 seconds elapses. When the latter
 * happens, -ERESTARTSYS is returned.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
int cn_rpmsg_send_offchannel(struct rpmsg_endpoint *ept, u32 src, u32 dst,
			  void *data, int len)
{
	if (WARN_ON(!ept))
		return -EINVAL;
	if (!ept->ops->send_offchannel)
		return -ENXIO;

	return ept->ops->send_offchannel(ept, src, dst, data, len);
}

/**
 * cn_rpmsg_trysend() - send a message across to the remote processor
 * @ept: the rpmsg endpoint
 * @data: payload of message
 * @len: length of payload
 *
 * This function sends @data of length @len on the @ept endpoint.
 * The message will be sent to the remote processor which the @ept
 * endpoint belongs to, using @ept's address as source and its associated
 * rpdev's address as destination.
 * In case there are no TX buffers available, the function will immediately
 * return -ENOMEM without waiting until one becomes available.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
int cn_rpmsg_trysend(struct rpmsg_endpoint *ept, void *data, int len)
{
	if (WARN_ON(!ept))
		return -EINVAL;
	if (!ept->ops->trysend)
		return -ENXIO;

	return ept->ops->trysend(ept, data, len);
}

/**
 * cn_rpmsg_trysendto() - send a message across to the remote processor, specify dst
 * @ept: the rpmsg endpoint
 * @data: payload of message
 * @len: length of payload
 * @dst: destination address
 *
 * This function sends @data of length @len to the remote @dst address.
 * The message will be sent to the remote processor which the @ept
 * endpoint belongs to, using @ept's address as source.
 * In case there are no TX buffers available, the function will immediately
 * return -ENOMEM without waiting until one becomes available.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
int cn_rpmsg_trysendto(struct rpmsg_endpoint *ept, void *data, int len, u32 dst)
{
	if (WARN_ON(!ept))
		return -EINVAL;
	if (!ept->ops->trysendto)
		return -ENXIO;

	return ept->ops->trysendto(ept, data, len, dst);
}

/**
 * cn_rpmsg_poll() - poll the endpoint's send buffers
 * @ept:	the rpmsg endpoint
 * @filp:	file for poll_wait()
 * @wait:	poll_table for poll_wait()
 *
 * Returns mask representing the current state of the endpoint's send buffers
 */
__poll_t cn_rpmsg_poll(struct rpmsg_endpoint *ept, struct file *filp,
			poll_table *wait)
{
	if (WARN_ON(!ept))
		return 0;
	if (!ept->ops->poll)
		return 0;

	return ept->ops->poll(ept, filp, wait);
}

/**
 * cn_rpmsg_trysend_offchannel() - send a message using explicit src/dst addresses
 * @ept: the rpmsg endpoint
 * @src: source address
 * @dst: destination address
 * @data: payload of message
 * @len: length of payload
 *
 * This function sends @data of length @len to the remote @dst address,
 * and uses @src as the source address.
 * The message will be sent to the remote processor which the @ept
 * endpoint belongs to.
 * In case there are no TX buffers available, the function will immediately
 * return -ENOMEM without waiting until one becomes available.
 *
 * Can only be called from process context (for now).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
int cn_rpmsg_trysend_offchannel(struct rpmsg_endpoint *ept, u32 src, u32 dst,
			     void *data, int len)
{
	if (WARN_ON(!ept))
		return -EINVAL;
	if (!ept->ops->trysend_offchannel)
		return -ENXIO;

	return ept->ops->trysend_offchannel(ept, src, dst, data, len);
}

/*
 * match a rpmsg channel with a channel info struct.
 * this is used to make sure we're not creating rpmsg devices for channels
 * that already exist.
 */
static int rpmsg_device_match(struct device *dev, void *data)
{
	struct rpmsg_channel_info *chinfo = data;
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);

	if (chinfo->src != RPMSG_ADDR_ANY && chinfo->src != rpdev->src)
		return 0;

	if (chinfo->dst != RPMSG_ADDR_ANY && chinfo->dst != rpdev->dst)
		return 0;

	if (strncmp(chinfo->name, rpdev->id.name, RPMSG_NAME_SIZE))
		return 0;

	/* found a match ! */
	return 1;
}

struct device *cn_rpmsg_find_device(struct device *parent,
				 struct rpmsg_channel_info *chinfo)
{
	return device_find_child(parent, chinfo, rpmsg_device_match);

}

#if (KERNEL_VERSION(3, 12, 0) <= LINUX_VERSION_CODE)
/* sysfs show configuration fields */
#define rpmsg_show_attr(field, path, format_string)			\
static ssize_t								\
field##_show(struct device *dev,					\
			struct device_attribute *attr, char *buf)	\
{									\
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);		\
									\
	return snprintf(buf, PAGE_SIZE, format_string, rpdev->path);		\
}									\
static DEVICE_ATTR_RO(field)

#define rpmsg_string_attr(field, member)				\
static ssize_t								\
field##_store(struct device *dev, struct device_attribute *attr,	\
	      const char *buf, size_t sz)				\
{									\
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);		\
	char *new, *old;						\
									\
	new = kstrndup(buf, sz, GFP_KERNEL);				\
	if (!new)							\
		return -ENOMEM;						\
	new[strcspn(new, "\n")] = '\0';					\
									\
	device_lock(dev);						\
	old = rpdev->member;						\
	if (strlen(new)) {						\
		rpdev->member = new;					\
	} else {							\
		kfree(new);						\
		rpdev->member = NULL;					\
	}								\
	device_unlock(dev);						\
									\
	kfree(old);							\
									\
	return sz;							\
}									\
static ssize_t								\
field##_show(struct device *dev,					\
	     struct device_attribute *attr, char *buf)			\
{									\
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);		\
									\
	return snprintf(buf, PAGE_SIZE, "%s\n", rpdev->member);			\
}									\
static DEVICE_ATTR_RW(field)

/* for more info, see Documentation/ABI/testing/sysfs-bus-rpmsg */
rpmsg_show_attr(name, id.name, "%s\n");
rpmsg_show_attr(desc, desc, "%s\n");
rpmsg_show_attr(src, src, "0x%x\n");
rpmsg_show_attr(dst, dst, "0x%x\n");
rpmsg_show_attr(announce, announce ? "true" : "false", "%s\n");
rpmsg_string_attr(driver_override, driver_override);

static ssize_t modalias_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);
	#if (KERNEL_VERSION(4, 13, 0) <= LINUX_VERSION_CODE)
	ssize_t len;

	len = of_device_modalias(dev, buf, PAGE_SIZE);
	if (len != -ENODEV)
		return len;
	#endif

	return snprintf(buf, PAGE_SIZE, RPMSG_DEVICE_MODALIAS_FMT "\n", rpdev->id.name);
}
static DEVICE_ATTR_RO(modalias);

static struct attribute *rpmsg_dev_attrs[] = {
	&dev_attr_name.attr,
	&dev_attr_desc.attr,
	&dev_attr_modalias.attr,
	&dev_attr_dst.attr,
	&dev_attr_src.attr,
	&dev_attr_announce.attr,
	&dev_attr_driver_override.attr,
	NULL,
};
ATTRIBUTE_GROUPS(rpmsg_dev);
#endif

/* rpmsg devices and drivers are matched using the service name */
static inline int rpmsg_id_match(const struct rpmsg_device *rpdev,
				  const struct rpmsg_device_id *id)
{
	return strncmp(id->name, rpdev->id.name, RPMSG_NAME_SIZE) == 0;
}

/* match rpmsg channel and rpmsg driver */
static int rpmsg_dev_match(struct device *dev, struct device_driver *drv)
{
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);
	struct rpmsg_driver *rpdrv = to_rpmsg_driver(drv);
	const struct rpmsg_device_id *ids = rpdrv->id_table;
	unsigned int i;

	if (rpdev->driver_override)
		return !strcmp(rpdev->driver_override, drv->name);

	/* cambricon */
	if (!strncmp(rpdev->desc, drv->name, RPMSG_NAME_SIZE))
		return 1;

	if (ids)
		for (i = 0; ids[i].name[0]; i++)
			if (rpmsg_id_match(rpdev, &ids[i]))
				return 1;

	return of_driver_match_device(dev, drv);
}

static int rpmsg_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);
	#if (KERNEL_VERSION(4, 13, 0) <= LINUX_VERSION_CODE)
	int ret;

	ret = of_device_uevent_modalias(dev, env);
	if (ret != -ENODEV)
		return ret;
	#endif

	return add_uevent_var(env, "MODALIAS=" RPMSG_DEVICE_MODALIAS_FMT,
					rpdev->id.name);
}

/*
 * when an rpmsg driver is probed with a channel, we seamlessly create
 * it an endpoint, binding its rx callback to a unique local rpmsg
 * address.
 *
 * if we need to, we also announce about this channel to the remote
 * processor (needed in case the driver is exposing an rpmsg service).
 */
static int rpmsg_dev_probe(struct device *dev)
{
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);
	struct rpmsg_driver *rpdrv = to_rpmsg_driver(rpdev->dev.driver);
	struct rpmsg_channel_info chinfo = {};
	struct rpmsg_endpoint *ept = NULL;
	int err;

	#if (KERNEL_VERSION(3, 18, 0) <= LINUX_VERSION_CODE)
	err = dev_pm_domain_attach(dev, true);
	if (err) {
		dev_dbg(dev, "%s: %d, dev_pm_domain_attach failed. ignore it\n", __func__, __LINE__);
		//goto out;//cambricon hack
	}
	#endif

	if (rpdrv->callback) {
		strncpy(chinfo.name, rpdev->id.name, RPMSG_NAME_SIZE);
		chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
		chinfo.src = rpdev->src;
		chinfo.dst = RPMSG_ADDR_ANY;

		ept = cn_rpmsg_create_ept(rpdev, rpdrv->callback, NULL, chinfo);
		if (!ept) {
			dev_err(dev, "failed to create endpoint\n");
			err = -ENOMEM;
			goto out;
		}

		rpdev->ept = ept;
		rpdev->src = ept->addr;
	}

	err = rpdrv->probe(rpdev);
	if (err) {
		dev_err(dev, "%s: failed: %d\n", __func__, err);
		if (ept)
			cn_rpmsg_destroy_ept(ept);
		goto out;
	}

	if (ept && rpdev->ops->announce_create)
		err = rpdev->ops->announce_create(rpdev);
out:
	return err;
}

/* adapt for RHEL OS */
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a,b) (((a) << 8) + (b))
#endif

#if ((KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE) || \
	(defined (RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,1) && \
	KERNEL_VERSION(5, 14, 0) <= LINUX_VERSION_CODE))
static void rpmsg_dev_remove(struct device *dev)
#else
static int rpmsg_dev_remove(struct device *dev)
#endif
{
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);
	struct rpmsg_driver *rpdrv = to_rpmsg_driver(rpdev->dev.driver);
	int err = 0;

	dev_dbg(dev, "%s: %d\n", __func__, __LINE__);

	if (rpdev->ops->announce_destroy)
		err = rpdev->ops->announce_destroy(rpdev);

	if (rpdrv->remove)
		rpdrv->remove(rpdev);

	#if (KERNEL_VERSION(3, 18, 0) <= LINUX_VERSION_CODE)
	dev_pm_domain_detach(dev, true);
	#endif

	if (rpdev->ept)
		cn_rpmsg_destroy_ept(rpdev->ept);

#if ((KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE) || \
	(defined (RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,1) && \
	KERNEL_VERSION(5, 14, 0) <= LINUX_VERSION_CODE))
	(void)err;
#else
	return err;
#endif
}

static struct bus_type rpmsg_bus = {
	.name		= "cn_rpmsg",
	.match		= rpmsg_dev_match,
	#if (KERNEL_VERSION(3, 12, 0) <= LINUX_VERSION_CODE)
	.dev_groups	= rpmsg_dev_groups,
	#endif
	.uevent		= rpmsg_uevent,
	.probe		= rpmsg_dev_probe,
	.remove		= rpmsg_dev_remove,
};

int cn_rpmsg_register_device(struct rpmsg_device *rpdev)
{
	struct device *dev = &rpdev->dev;
	int ret;

	dev_set_name(&rpdev->dev, "%s.%s.%d.%d", dev_name(dev->parent),
		     rpdev->id.name, rpdev->src, rpdev->dst);

	rpdev->dev.bus = &rpmsg_bus;

	ret = device_register(&rpdev->dev);
	if (ret) {
		dev_err(dev, "device_register failed: %d\n", ret);
		put_device(&rpdev->dev);
	}

	return ret;
}

/*
 * find an existing channel using its name + address properties,
 * and destroy it
 */
int cn_rpmsg_unregister_device(struct device *parent,
			    struct rpmsg_channel_info *chinfo)
{
	struct device *dev;

	dev = cn_rpmsg_find_device(parent, chinfo);
	if (!dev)
		return -EINVAL;

	device_unregister(dev);

	put_device(dev);

	return 0;
}

/**
 * __cn_register_rpmsg_driver() - register an rpmsg driver with the rpmsg bus
 * @rpdrv: pointer to a struct rpmsg_driver
 * @owner: owning module/driver
 *
 * Returns 0 on success, and an appropriate error value on failure.
 */
int __cn_register_rpmsg_driver(struct rpmsg_driver *rpdrv, struct module *owner)
{
	rpdrv->drv.bus = &rpmsg_bus;
	rpdrv->drv.owner = owner;
	return driver_register(&rpdrv->drv);
}

/**
 * cn_unregister_rpmsg_driver() - unregister an rpmsg driver from the rpmsg bus
 * @rpdrv: pointer to a struct rpmsg_driver
 *
 * Returns 0 on success, and an appropriate error value on failure.
 */
void cn_unregister_rpmsg_driver(struct rpmsg_driver *rpdrv)
{
	driver_unregister(&rpdrv->drv);
}


int rpmsg_init(void)
{
	int ret;

	ret = bus_register(&rpmsg_bus);
	if (ret)
		pr_err("failed to register rpmsg bus: %d\n", ret);
	pr_info("%s, %d\n", __func__, __LINE__);
	return ret;
}

void rpmsg_fini(void)
{
	bus_unregister(&rpmsg_bus);
}

//MODULE_DESCRIPTION("remote processor messaging bus");
//MODULE_LICENSE("GPL v2");
