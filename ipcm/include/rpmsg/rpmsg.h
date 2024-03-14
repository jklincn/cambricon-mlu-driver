/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Remote processor messaging
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 * Copyright (C) 2011 Google, Inc.
 * All rights reserved.
 */

#ifndef _LINUX_RPMSG_H
#define _LINUX_RPMSG_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/mod_devicetable.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/printk.h>
#ifdef IN_CNDRV_HOST
#include "cndrv_ipcm.h"
#else
#include "../../cambr_ipcm.h"
#endif

#if (KERNEL_VERSION(4, 16, 0) > LINUX_VERSION_CODE)
typedef unsigned __bitwise __poll_t;
#endif

#define RPMSG_ADDR_ANY		0xFFFFFFFF


struct rpmsg_device;
struct rpmsg_endpoint;
struct rpmsg_device_ops;
struct rpmsg_endpoint_ops;
struct cn_core_set;

/* lockdep subclasses for use with ept cb_lock mutex nested calls */
#define RPMSG_LOCKDEP_SUBCLASS_NORMAL   0 /* regular ept cb_lock */
#define RPMSG_LOCKDEP_SUBCLASS_NS       1 /* name service ept cb_lock */

/**
 * struct rpmsg_channel_info - channel info representation
 * @name: name of service
 * @desc: description of service
 * @src: local address
 * @dst: destination address
 */
struct rpmsg_channel_info {
	char name[RPMSG_NAME_SIZE];
	char desc[RPMSG_NAME_SIZE];
	u32 src;
	u32 dst;
};


/* may run in irq_context(in_irq() || irq_disable()), check remoterproc driver's kick() */
typedef int (*rpmsg_rx_cb_t)(struct rpmsg_device *, void *, int, void *, u32);

/**
 * rpmsg_device - device that belong to the rpmsg bus
 * @dev: the device struct
 * @id: device id (used to match between rpmsg drivers and devices)
 * @driver_override: driver name to force a match
 * @src: local address
 * @dst: destination address
 * @ept: the rpmsg endpoint of this channel(if rpdrv->callback is present)
 * @announce: if set, rpmsg will announce the creation/removal of this channel
 * @desc: desc for driver_overide for match the expected
 * @list: for vf, create vf channel and add pf resource to vf rpmsg_device while vf driver ok
 * @rx_callback: pf rx_cb for ipcm_priv while vf driver ok
 * @services: pf rpc func_set for ipcm_priv while vf driver ok
 * @vf_id: vf_id for rx_cb's param to indicate where msg from
 */
struct rpmsg_device {
	struct device dev;
	struct rpmsg_device_id id;
	char *driver_override;
	u32 src;
	u32 dst;
	struct rpmsg_endpoint *ept;
	bool announce;
	const struct rpmsg_device_ops *ops;
	/* cambricon */
	struct list_head list;
	ipcm_rx_cb_t rx_callback;
	bool rx_cb_async;
	struct rpmsg_rpc_service_set *services;
	char desc[RPMSG_NAME_SIZE];
	int vf_id;
	bool reset_flag;
	atomic_t rpc_flag;
};

/**
 * struct rpmsg_endpoint - binds a local rpmsg address to its user
 * @rpdev: rpmsg channel device
 * @refcount: when this drops to zero, the ept is deallocated
 * @cb: rx callback handler
 * @cb_lock: must be taken before accessing/changing @cb
 * @cb_lockdep_class: mutex lockdep class to be used with @cb_lock
 * @addr: local rpmsg address
 * @priv: private data for the driver's use
 * @ns_unbind_cb: end point service unbind callback, called when remote
 *                ept is destroyed.
 *
 * In essence, an rpmsg endpoint represents a listener on the rpmsg bus, as
 * it binds an rpmsg address with an rx callback handler.
 *
 * Simple rpmsg drivers shouldn't use this struct directly, because
 * things just work: every rpmsg driver provides an rx callback upon
 * registering to the bus, and that callback is then bound to its rpmsg
 * address when the driver is probed. When relevant inbound messages arrive
 * (i.e. messages which their dst address equals to the src address of
 * the rpmsg channel), the driver's handler is invoked to process it.
 *
 * More complicated drivers though, that do need to allocate additional rpmsg
 * addresses, and bind them to different rx callbacks, must explicitly
 * create additional endpoints by themselves (see cn_rpmsg_create_ept()).
 */
struct rpmsg_endpoint {
	struct rpmsg_device *rpdev;
	struct kref refcount;
	rpmsg_rx_cb_t cb;
	struct mutex cb_lock;
	int cb_lockdep_class;
	u32 addr;
	void *priv;

	const struct rpmsg_endpoint_ops *ops;
	pid_t tgid;
	int cb_max_time;
};

/**
 * struct rpmsg_driver - rpmsg driver struct
 * @drv: underlying device driver
 * @id_table: rpmsg ids serviced by this driver
 * @probe: invoked when a matching rpmsg channel (i.e. device) is found
 * @remove: invoked when the rpmsg channel is removed
 * @callback: invoked when an inbound message is received on the channel
 */
struct rpmsg_driver {
	struct device_driver drv;
	const struct rpmsg_device_id *id_table;
	int (*probe)(struct rpmsg_device *dev);
	void (*remove)(struct rpmsg_device *dev);
	int (*callback)(struct rpmsg_device *, void *, int, void *, u32);
};

#ifndef IN_CNDRV_HOST
struct rpmsg_device *cn_rpmsg_create_channel(int vf_id, struct rpmsg_channel_info *chinfo);
#else
struct rpmsg_device *cn_rpmsg_create_channel(void *core, struct rpmsg_channel_info *chinfo);
#endif

int __cn_register_rpmsg_driver(struct rpmsg_driver *drv, struct module *owner);
void cn_unregister_rpmsg_driver(struct rpmsg_driver *drv);
void cn_rpmsg_destroy_ept(struct rpmsg_endpoint *ept);
struct rpmsg_endpoint *cn_rpmsg_create_ept(struct rpmsg_device *rpdev,
					rpmsg_rx_cb_t cb, void *priv,
					struct rpmsg_channel_info chinfo);

int cn_rpmsg_send(struct rpmsg_endpoint *ept, void *data, int len);
int cn_rpmsg_sendto(struct rpmsg_endpoint *ept, void *data, int len, u32 dst);
int cn_rpmsg_send_offchannel(struct rpmsg_endpoint *ept, u32 src, u32 dst,
			  void *data, int len);

int cn_rpmsg_trysend(struct rpmsg_endpoint *ept, void *data, int len);
int cn_rpmsg_trysendto(struct rpmsg_endpoint *ept, void *data, int len, u32 dst);
int cn_rpmsg_trysend_offchannel(struct rpmsg_endpoint *ept, u32 src, u32 dst,
			     void *data, int len);

__poll_t cn_rpmsg_poll(struct rpmsg_endpoint *ept, struct file *filp,
			poll_table *wait);

/* use a macro to avoid include chaining to get THIS_MODULE */
#define cn_register_rpmsg_driver(drv) \
	__cn_register_rpmsg_driver(drv, THIS_MODULE)

/**
 * module_rpmsg_driver() - Helper macro for registering an rpmsg driver
 * @__rpmsg_driver: rpmsg_driver struct
 *
 * Helper macro for rpmsg drivers which do not do anything special in module
 * init/exit. This eliminates a lot of boilerplate.  Each module may only
 * use this macro once, and calling it replaces module_init() and module_exit()
 */
#define module_rpmsg_driver(__rpmsg_driver) \
	module_driver(__rpmsg_driver, cn_register_rpmsg_driver, \
			cn_unregister_rpmsg_driver)
#endif /* _LINUX_RPMSG_H */
