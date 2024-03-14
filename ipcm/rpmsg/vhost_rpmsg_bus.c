// SPDX-License-Identifier: GPL-2.0
/*
 * Vhost-based remote processor messaging bus
 *
 * Based on virtio_rpmsg_bus.c
 *
 * Copyright (C) 2020 Cambricon - All Rights Reserved
 *
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/dma-mapping.h>
#include "../include/rpmsg/rpmsg.h"
#include "../include/vhost/vhost.h"
#include "../include/uapi/linux/virtio_ids.h"
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/io.h>
//#include <linux/kallsyms.h>
#include <linux/soc/cambricon/cnosal/cnosal_module.h>

#include "rpmsg_internal.h"
#include "../cambr_ipcm.h"

#ifndef mmiowb
#define mmiowb() do {} while (0)
#endif

static u64 vapa_pa_base, vapa_va_base;
static u32 vapa_size;

int pf_vf_num;

/* ipcm loaded before monitor & domain */
static u64 (*monitor_get_host_ns_func)(int dm_func_id, s32 clk_id);

static struct ipcm_timestamp_info *perf_dev_kva;

/**
 * struct virtproc_info - virtual remote processor state
 * @vdev:	the virtio device
 * @rvq:	rx vhost_virtqueue
 * @svq:	tx vhost_virtqueue
 * @buf_size:   size of one rx or tx buffer
 * @tx_lock:	protects svq, sbufs and sleepers, to allow concurrent senders.
 *		sending a message might require waking up a dozing remote
 *		processor, which involves sleeping, hence the mutex.
 * @endpoints:	idr of local endpoints, allows fast retrieval
 * @endpoints_lock: lock of the endpoints set
 * @sendq:	wait queue of sending contexts waiting for a tx buffers
 * @sleepers:	number of senders that are waiting for a tx buffer
 * @as_ept:	the bus's address service endpoint
 * @nb:		notifier block for receiving notifications from vhost device
 *              driver
 * @list:	maintain list of client drivers bound to rpmsg vhost device
 * @list_lock:  mutex to protect updating the list
 *
 * This structure stores the rpmsg state of a given vhost remote processor
 * device (there might be several virtio proc devices for each physical
 * remote processor).
 */
struct virtproc_info {
	struct vhost_dev *vdev;
	struct vhost_virtqueue *rvq, *svq;
	unsigned int buf_size;
	/* mutex to protect sending messages */
	spinlock_t tx_lock;
	/* mutex to protect receiving messages */
	struct mutex rx_lock;
	struct idr endpoints;
	/* mutex to protect receiving accessing idr */
	struct mutex endpoints_lock;
	wait_queue_head_t sendq;
	atomic_t sleepers;
	struct rpmsg_endpoint *as_ept;
	struct notifier_block nb;
	struct list_head list;
	/* mutex to protect updating pending rpdev in vrp */
	struct mutex list_lock;
	void *rbufs_ob;
};

/**
 * @vrp: the remote processor this channel belongs to
 */
struct vhost_rpmsg_channel {
	struct rpmsg_device rpdev;

	struct virtproc_info *vrp;
};

#define to_vhost_rpmsg_channel(_rpdev) \
	container_of(_rpdev, struct vhost_rpmsg_channel, rpdev)

static void vhost_rpmsg_destroy_ept(struct rpmsg_endpoint *ept);
static int vhost_rpmsg_send(struct rpmsg_endpoint *ept, void *data, int len);
static int vhost_rpmsg_sendto(struct rpmsg_endpoint *ept, void *data, int len,
			      u32 dst);
static int vhost_rpmsg_send_offchannel(struct rpmsg_endpoint *ept, u32 src,
				       u32 dst, void *data, int len);
static int vhost_rpmsg_trysend(struct rpmsg_endpoint *ept, void *data, int len);
static int vhost_rpmsg_trysendto(struct rpmsg_endpoint *ept, void *data,
				 int len, u32 dst);
static int vhost_rpmsg_trysend_offchannel(struct rpmsg_endpoint *ept, u32 src,
					  u32 dst, void *data, int len);

static const struct rpmsg_endpoint_ops vhost_endpoint_ops = {
	.destroy_ept = vhost_rpmsg_destroy_ept,
	.send = vhost_rpmsg_send,
	.sendto = vhost_rpmsg_sendto,
	.send_offchannel = vhost_rpmsg_send_offchannel,
	.trysend = vhost_rpmsg_trysend,
	.trysendto = vhost_rpmsg_trysendto,
	.trysend_offchannel = vhost_rpmsg_trysend_offchannel,
};

/**
 * __ept_release() - deallocate an rpmsg endpoint
 * @kref: the ept's reference count
 *
 * This function deallocates an ept, and is invoked when its @kref refcount
 * drops to zero.
 *
 * Never invoke this function directly!
 */
static void __ept_release(struct kref *kref)
{
	struct rpmsg_endpoint *ept = container_of(kref, struct rpmsg_endpoint,
						  refcount);
	/*
	 * At this point no one holds a reference to ept anymore,
	 * so we can directly free it
	 */
	kfree(ept);
}

/**
 * __rpmsg_create_ept() - Create rpmsg endpoint
 * @vrp: virtual remote processor of the vhost device where endpoint has to be
 *       created
 * @rpdev: rpmsg device on which endpoint has to be created
 * @cb: callback associated with the endpoint
 * @priv: private data for the driver's use
 * @addr: channel_info with the local rpmsg address to bind with @cb
 *
 * Allows drivers to create an endpoint, and bind a callback with some
 * private data, to an rpmsg address.
 */
static struct rpmsg_endpoint *__rpmsg_create_ept(struct virtproc_info *vrp,
						 struct rpmsg_device *rpdev,
						 rpmsg_rx_cb_t cb,
						 void *priv, u32 addr)
{
	int id_min, id_max, id;
	struct rpmsg_endpoint *ept;
	struct device *dev = rpdev ? &rpdev->dev : &vrp->vdev->dev;

	ept = kzalloc(sizeof(*ept), GFP_KERNEL);
	if (!ept)
		return NULL;

	kref_init(&ept->refcount);
	mutex_init(&ept->cb_lock);

	ept->rpdev = rpdev;
	ept->cb = cb;
	ept->priv = priv;
	ept->ops = &vhost_endpoint_ops;

	/* do we need to allocate a local address ? */
	if (addr == RPMSG_ADDR_ANY) {
		id_min = RPMSG_RESERVED_ADDRESSES;
		id_max = RPMSG_RESERVED_ADDRESSES_END;
	} else {
		id_min = addr;
		id_max = addr + 1;
	}

	mutex_lock(&vrp->endpoints_lock);

	/* bind the endpoint to an rpmsg address (and allocate one if needed) */
	if (addr == RPMSG_ADDR_ANY) {
		id = idr_alloc_cyclic(&vrp->endpoints, ept, id_min, id_max, GFP_KERNEL);
	} else {
		id = idr_alloc(&vrp->endpoints, ept, id_min, id_max, GFP_KERNEL);
	}
	if (id < 0) {
		struct rpmsg_endpoint *tmp;
		struct task_struct *task;
		char buf[TASK_COMM_LEN];

		dev_err(dev, "idr_alloc failed: %d\n", id);
		get_task_comm(buf, current);
		dev_err(dev, "tgid:%d comm:%s create_ept with addr(%d) failed, start dump endpoints\n",
					task_tgid_nr(current), buf, addr);
		idr_for_each_entry(&vrp->endpoints, tmp, id) {
			task = get_pid_task(find_vpid(tmp->tgid), PIDTYPE_PID);
			if (task)
				get_task_comm(buf, task);

			dev_info(&vrp->vdev->dev, "ept[%d]: addr(%d), tgid: %d, comm: %s.\n",
					id, tmp->addr, tmp->tgid, task ? buf : "unknown(none exist)");
			if (task)
				put_task_struct(task);
			/* NS AS ept have no rpdev */
			if (tmp->rpdev) {
				dev_info(&vrp->vdev->dev, "    belongs to rpdev %px: %s.%d.%d\n",
					tmp->rpdev, tmp->rpdev->id.name, tmp->rpdev->src, tmp->rpdev->dst);
			}
		}
		goto free_ept;
	}
	ept->addr = id;
	ept->tgid = task_tgid_nr(current);

	mutex_unlock(&vrp->endpoints_lock);

	return ept;

free_ept:
	mutex_unlock(&vrp->endpoints_lock);
	kref_put(&ept->refcount, __ept_release);
	return NULL;
}

/**
 * vhost_rpmsg_create_ept() - Create rpmsg endpoint
 * @rpdev: rpmsg device on which endpoint has to be created
 * @cb: callback associated with the endpoint
 * @priv: private data for the driver's use
 * @chinfo: channel_info with the local rpmsg address to bind with @cb
 *
 * Wrapper to __rpmsg_create_ept() to create rpmsg endpoint
 */
static struct rpmsg_endpoint
*vhost_rpmsg_create_ept(struct rpmsg_device *rpdev, rpmsg_rx_cb_t cb, void *priv,
			struct rpmsg_channel_info chinfo)
{
	struct vhost_rpmsg_channel *vch = to_vhost_rpmsg_channel(rpdev);

	return __rpmsg_create_ept(vch->vrp, rpdev, cb, priv, chinfo.src);
}

/**
 * __rpmsg_destroy_ept() - destroy an existing rpmsg endpoint
 * @vrp: virtproc which owns this ept
 * @ept: endpoing to destroy
 *
 * An internal function which destroy an ept without assuming it is
 * bound to an rpmsg channel. This is needed for handling the internal
 * name service endpoint, which isn't bound to an rpmsg channel.
 * See also __rpmsg_create_ept().
 */
static void
__rpmsg_destroy_ept(struct virtproc_info *vrp, struct rpmsg_endpoint *ept)
{
	/* make sure new inbound messages can't find this ept anymore */
	mutex_lock(&vrp->endpoints_lock);
	idr_remove(&vrp->endpoints, ept->addr);
	mutex_unlock(&vrp->endpoints_lock);

	/* make sure in-flight inbound messages won't invoke cb anymore */
	mutex_lock(&ept->cb_lock);
	ept->cb = NULL;
	mutex_unlock(&ept->cb_lock);

	kref_put(&ept->refcount, __ept_release);
}

/**
 * vhost_rpmsg_destroy_ept() - destroy an existing rpmsg endpoint
 * @ept: endpoing to destroy
 *
 * Wrapper to __rpmsg_destroy_ept() to destroy rpmsg endpoint
 */
static void vhost_rpmsg_destroy_ept(struct rpmsg_endpoint *ept)
{
	struct vhost_rpmsg_channel *vch = to_vhost_rpmsg_channel(ept->rpdev);

	__rpmsg_destroy_ept(vch->vrp, ept);
}

/**
 * vhost_rpmsg_announce_create() - Announce creation of new channel
 * @rpdev: rpmsg device on which new endpoint channel is created
 *
 * Send a message to the remote processor's name service about the
 * creation of this channel.
 */
static int vhost_rpmsg_announce_create(struct rpmsg_device *rpdev)
{
	struct vhost_rpmsg_channel *vch = to_vhost_rpmsg_channel(rpdev);
	struct virtproc_info *vrp = vch->vrp;
	struct device *dev = &rpdev->dev;
	int err = 0;

	if (!rpdev->ept || !rpdev->announce)
		return err;

	dev_info(dev, "%s, %s\n", __func__, rpdev->id.name);

	/* need to tell remote processor's name service about this channel ? */
	if (vhost_has_feature(vrp->vdev, VIRTIO_RPMSG_F_NS)) {
		struct rpmsg_ns_msg_ext nsm;

		strncpy(nsm.name, rpdev->id.name, RPMSG_NAME_SIZE);
		nsm.name[RPMSG_NAME_SIZE - 1] = '\0';
		nsm.addr = rpdev->ept->addr;
		nsm.flags = RPMSG_NS_CREATE | RPMSG_AS_ANNOUNCE;
		strncpy(nsm.desc, rpdev->desc, RPMSG_NAME_SIZE);
		nsm.desc[RPMSG_NAME_SIZE - 1] = '\0';

		err = cn_rpmsg_sendto(rpdev->ept, &nsm, sizeof(nsm), RPMSG_NS_ADDR);
		if (err)
			dev_err(dev, "failed to announce service %d\n", err);
	}

	return err;
}

/**
 * vhost_rpmsg_announce_destroy() - Announce deletion of channel
 * @rpdev: rpmsg device on which this endpoint channel is created
 *
 * Send a message to the remote processor's name service about the
 * deletion of this channel.
 */
static int vhost_rpmsg_announce_destroy(struct rpmsg_device *rpdev)
{
	struct vhost_rpmsg_channel *vch = to_vhost_rpmsg_channel(rpdev);
	struct virtproc_info *vrp = vch->vrp;
	struct device *dev = &rpdev->dev;
	int err = 0;

	if (!rpdev->ept || !rpdev->announce)
		return err;

	dev_info(dev, "%s, %s\n", __func__, rpdev->id.name);

	/* tell remote processor's name service we're removing this channel */
	if (vhost_has_feature(vrp->vdev, VIRTIO_RPMSG_F_NS)) {
		struct rpmsg_ns_msg nsm;

		strncpy(nsm.name, rpdev->id.name, RPMSG_NAME_SIZE);
		nsm.name[RPMSG_NAME_SIZE - 1] = '\0';
		nsm.addr = rpdev->ept->addr;
		nsm.flags = RPMSG_NS_DESTROY;

		err = cn_rpmsg_sendto(rpdev->ept, &nsm, sizeof(nsm), RPMSG_NS_ADDR);
		if (err)
			dev_err(dev, "failed to announce service %d\n", err);
	}

	return err;
}

static const struct rpmsg_device_ops vhost_rpmsg_ops = {
	.create_ept = vhost_rpmsg_create_ept,
	.announce_create = vhost_rpmsg_announce_create,
	.announce_destroy = vhost_rpmsg_announce_destroy,
};

/**
 * vhost_rpmsg_release_device() - Callback to free vhost_rpmsg_channel
 * @dev: struct device of rpmsg_device
 *
 * Invoked from device core after all references to "dev" is removed
 * to free the wrapper vhost_rpmsg_channel.
 */
static void vhost_rpmsg_release_device(struct device *dev)
{
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);
	struct vhost_rpmsg_channel *vch = to_vhost_rpmsg_channel(rpdev);

	kfree(vch);
}

static bool vhost_rpmsg_remote_ready(struct vhost_dev *vdev)
{
	dev_dbg(&vdev->dev, "%s, status:0x%x, vf_start:%d\n", __func__, vhost_get_status(vdev), vdev->vf_start);
	return vdev->vf_start;
}

/**
 * vhost_rpmsg_create_channel - Create an rpmsg channel
 * @dev: struct device of vhost_dev
 * @name: name of the rpmsg channel to be created
 *
 * Create an rpmsg channel using its name. Invokes rpmsg_register_device()
 * only if status is VIRTIO_CONFIG_S_DRIVER_OK or else just adds it to
 * list of pending rpmsg devices. This is because if the rpmsg client
 * driver is already loaded when rpmsg is being registered, it'll try
 * to start accessing virtqueue which will be ready only after VIRTIO
 * sets status as VIRTIO_CONFIG_S_DRIVER_OK.
 */
static struct rpmsg_device *vhost_rpmsg_create_channel(struct virtproc_info *vrp,
						 struct rpmsg_channel_info *chinfo,
						 bool announce)
{
	struct vhost_rpmsg_channel *vch;
	struct rpmsg_device *rpdev;
	struct device *tmp, *dev = &vrp->vdev->dev;
	int ret;

	/* make sure a similar channel doesn't already exist */
	tmp = cn_rpmsg_find_device(dev, chinfo);
	if (tmp) {
		/* decrement the matched device's refcount back */
		put_device(tmp);
		dev_err(dev, "channel %s:%x:%x already exist\n",
				chinfo->name, chinfo->src, chinfo->dst);
		return NULL;
	}

	vch = kzalloc(sizeof(*vch), GFP_KERNEL);
	if (!vch)
		return NULL;

	/* Link the channel to our vrp */
	vch->vrp = vrp;

	/* Assign public information to the rpmsg_device */
	rpdev = &vch->rpdev;
	rpdev->src = chinfo->src;
	rpdev->dst = chinfo->dst;
	rpdev->ops = &vhost_rpmsg_ops;

	/*
	 * rpmsg server channels has predefined local address (for now),
	 * and their existence needs to be announced remotely
	 */
	if (/*rpdev->src != RPMSG_ADDR_ANY || */announce)
		rpdev->announce = true;

	strncpy(rpdev->id.name, chinfo->name, RPMSG_NAME_SIZE);
	rpdev->id.name[RPMSG_NAME_SIZE - 1] = '\0';
	strncpy(rpdev->desc, chinfo->desc, RPMSG_NAME_SIZE);
	rpdev->desc[RPMSG_NAME_SIZE - 1] = '\0';

	rpdev->dev.parent = &vrp->vdev->dev;
	rpdev->dev.release = vhost_rpmsg_release_device;
	if (!vhost_rpmsg_remote_ready(vrp->vdev)) {
		mutex_lock(&vrp->list_lock);
		list_add_tail(&rpdev->list, &vrp->list);
		mutex_unlock(&vrp->list_lock);
	} else {
		dev_info(dev, "%s, channel %s, src(%d), dst(%d)\n",
			__func__, chinfo->name, chinfo->src, chinfo->dst);
		ret = cn_rpmsg_register_device(rpdev);
		if (ret)
			return NULL;
	}

	return rpdev;
}

/**
 * cn_rpmsg_destroy_channel - Delete an rpmsg channel
 * @dev: struct device of rpmsg_device
 *
 * Delete channel created using vhost_rpmsg_create_channel()
 */
int cn_rpmsg_destroy_channel(struct rpmsg_device *rpdev)
{
	struct vhost_rpmsg_channel *vch;
	struct virtproc_info *vrp;
	struct vhost_dev *vdev;
	struct rpmsg_channel_info chinfo = {};
	int ret = 0;

	strncpy(chinfo.name, rpdev->id.name, RPMSG_NAME_SIZE);
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = rpdev->src;
	chinfo.dst = rpdev->dst;

	vch = to_vhost_rpmsg_channel(rpdev);
	vrp = vch->vrp;
	vdev = vrp->vdev;

	if (!vhost_rpmsg_remote_ready(vdev)) {
		mutex_lock(&vrp->list_lock);
		list_del(&rpdev->list);
		mutex_unlock(&vrp->list_lock);
		kfree(vch);
	} else {
		ret = cn_rpmsg_unregister_device(&vrp->vdev->dev, &chinfo);
		if (ret)
			dev_err(&vrp->vdev->dev, "rpmsg_destroy_channel:%s failed: %d\n", chinfo.name, ret);
	}
	return ret;
}

/* cambricon */
extern void *cambr_rproc_get_vhost_device(int vf_id);

struct rpmsg_device *cn_rpmsg_create_channel(int vf_id, struct rpmsg_channel_info *chinfo)
{
	struct vhost_dev *vdev = cambr_rproc_get_vhost_device(vf_id);
	struct virtproc_info *vrp = vdev ? vhost_get_drvdata(vdev) : NULL;

	if (!vrp)
		return NULL;

	return vhost_rpmsg_create_channel(vrp, chinfo, false);
}

static struct rpmsg_device *__ipcm_create_channel(int vf_id, char *channel_name)
{
	struct rpmsg_channel_info chinfo = {};
	struct vhost_dev *vdev = cambr_rproc_get_vhost_device(vf_id);
	struct virtproc_info *vrp = vdev ? vhost_get_drvdata(vdev) : NULL;

	if (!vrp)
		return NULL;

	strncpy(chinfo.name, channel_name, sizeof(chinfo.name));
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = RPMSG_ADDR_ANY;
	chinfo.dst = RPMSG_ADDR_ANY;
	strncpy(chinfo.desc, "rpmsg-ipcm", sizeof(chinfo.desc));

	return vhost_rpmsg_create_channel(vrp, &chinfo, true);
}

struct rpmsg_device_proxy *ipcm_create_channel(char *channel_name)
{
	int vf_id;
	struct rpmsg_device_proxy *proxy;
	struct rpmsg_device *rpdev;

	proxy = kzalloc(sizeof(struct rpmsg_device_proxy) + sizeof(struct rpmsg_device *) * pf_vf_num, GFP_KERNEL);
	if (!proxy)
		return ERR_PTR(-ENOMEM);
	proxy->pf_vf_num = pf_vf_num;
	for (vf_id = 0; vf_id < pf_vf_num; vf_id++) {
		rpdev = __ipcm_create_channel(vf_id, channel_name);
		if (rpdev) {
			proxy->rpdev[vf_id] = rpdev;
			proxy->rpdev[vf_id]->vf_id = vf_id;
		} else
			proxy->rpdev[vf_id] = NULL;
	}
	return proxy;
}
EXPORT_SYMBOL(ipcm_create_channel);

static struct rpmsg_device *_ipcm_create_user_channel(struct virtproc_info *vrp, char *channel_name, u32 addr)
{
	struct rpmsg_channel_info chinfo = {};

	strncpy(chinfo.name, channel_name, sizeof(chinfo.name));
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = addr;
	chinfo.dst = RPMSG_ADDR_ANY;
	strncpy(chinfo.desc, "rpmsg-ipcm", sizeof(chinfo.desc));

	return vhost_rpmsg_create_channel(vrp, &chinfo, true);
}

static struct rpmsg_device *__ipcm_create_user_channel(int vf_id, char *channel_name, u32 addr)
{
	struct rpmsg_channel_info chinfo = {};

	strncpy(chinfo.name, channel_name, sizeof(chinfo.name));
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = addr;
	chinfo.dst = RPMSG_ADDR_ANY;
	strncpy(chinfo.desc, "rpmsg-ipcm", sizeof(chinfo.desc));

	return cn_rpmsg_create_channel(vf_id, &chinfo);
}

struct rpmsg_device_proxy *ipcm_create_user_channel(char *channel_name, u32 addr)
{
	int vf_id;
	struct rpmsg_device_proxy *proxy;
	struct rpmsg_device *rpdev;

	proxy = kzalloc(sizeof(struct rpmsg_device_proxy) + sizeof(struct rpmsg_device *) * pf_vf_num, GFP_KERNEL);
	if (!proxy)
		return ERR_PTR(-ENOMEM);
	proxy->pf_vf_num = pf_vf_num;
	for (vf_id = 0; vf_id < pf_vf_num; vf_id++) {
		rpdev = __ipcm_create_user_channel(vf_id, channel_name, addr);
		if (rpdev) {
			proxy->rpdev[vf_id] = rpdev;
			proxy->rpdev[vf_id]->vf_id = vf_id;
		} else
			proxy->rpdev[vf_id] = NULL;
	}
	return proxy;
}
EXPORT_SYMBOL(ipcm_create_user_channel);

int ipcm_destroy_channel(struct rpmsg_device_proxy *proxy)
{
	int ret = 0;
	int vf_id;
	struct rpmsg_device *rpdev;

	for (vf_id = 0; vf_id < proxy->pf_vf_num; vf_id++) {
		rpdev = proxy->rpdev[vf_id];
		if (rpdev)
			ret += cn_rpmsg_destroy_channel(rpdev);
	}
	kfree(proxy);
	proxy = NULL;
	return ret;
}
EXPORT_SYMBOL(ipcm_destroy_channel);

/*
 * server announce_create, client will setup the channel local,
 * then client announce ack with his addr,
 * server receive ack to update his dst as client's addr
 */
bool ipcm_channel_ready(struct rpmsg_device *rpdev)
{
	return rpdev->dst != RPMSG_ADDR_ANY;
}
EXPORT_SYMBOL(ipcm_channel_ready);

static int rpmsg_create_chrdev(struct virtproc_info *vrp)
{
	struct vhost_rpmsg_channel *vch;
	struct rpmsg_device *rpdev;
	struct device *dev = &vrp->vdev->dev;
	int ret = 0;

	dev_dbg(dev, "%s\n", __func__);

	vch = kzalloc(sizeof(*vch), GFP_KERNEL);
	if (!vch)
		return -ENOMEM;

	/* Link the channel to our vrp */
	vch->vrp = vrp;

	/* Assign public information to the rpmsg_device */
	rpdev = &vch->rpdev;
	rpdev->ops = &vhost_rpmsg_ops;
	//rpdev->src = RPMSG_ADDR_ANY;
	//rpdev->dst = RPMSG_ADDR_ANY;

	rpdev->dev.parent = &vrp->vdev->dev;
	rpdev->dev.release = vhost_rpmsg_release_device;
	/* rpmsg_char will not announce, so will not access outbound while vf not start */
	#if 0
	if (!vhost_rpmsg_remote_ready(vrp->vdev)) {
		strncpy(rpdev->id.name, "rpmsg_chrdev", RPMSG_NAME_SIZE);
		rpdev->driver_override = "rpmsg_chrdev";
		mutex_lock(&vrp->list_lock);
		list_add_tail(&rpdev->list, &vrp->list);
		mutex_unlock(&vrp->list_lock);
	} else {
		ret = rpmsg_chrdev_register_device(rpdev);
	}
	return ret;
	#else
	ret = rpmsg_chrdev_register_device(rpdev);
	return ret;
	#endif
}

static void *get_a_tx_buf(struct virtproc_info *vrp, u16 *head, int *len)
{
	struct vhost_virtqueue *svq = vrp->svq;
	void *ret;

	/* support multiple concurrent senders */
	spin_lock(&vrp->tx_lock);
	/* grab a buffer */
	ret = vhost_virtqueue_get_outbuf(svq, head, len);
	mmiowb();
	spin_unlock(&vrp->tx_lock);
	return ret;
}

/**
 * rpmsg_upref_sleepers() - enable "tx-complete" interrupts, if needed
 * @vrp: virtual remote processor state
 *
 * This function is called before a sender is blocked, waiting for
 * a tx buffer to become available.
 *
 * If we already have blocking senders, this function merely increases
 * the "sleepers" reference count, and exits.
 *
 * Otherwise, if this is the first sender to block, we also enable
 * virtio's tx callbacks, so we'd be immediately notified when a tx
 * buffer is consumed (we rely on virtio's tx callback in order
 * to wake up sleeping senders as soon as a tx buffer is used by the
 * remote processor).
 */
static void rpmsg_upref_sleepers(struct virtproc_info *vrp)
{
	/* support multiple concurrent senders */
	spin_lock(&vrp->tx_lock);

	/* are we the first sleeping context waiting for tx buffers ? */
	if (atomic_inc_return(&vrp->sleepers) == 1)
		/* enable "tx-complete" interrupts before dozing off */
		vhost_virtqueue_enable_cb(vrp->svq);

	spin_unlock(&vrp->tx_lock);
}

/**
 * rpmsg_downref_sleepers() - disable "tx-complete" interrupts, if needed
 * @vrp: virtual remote processor state
 *
 * This function is called after a sender, that waited for a tx buffer
 * to become available, is unblocked.
 *
 * If we still have blocking senders, this function merely decreases
 * the "sleepers" reference count, and exits.
 *
 * Otherwise, if there are no more blocking senders, we also disable
 * virtio's tx callbacks, to avoid the overhead incurred with handling
 * those (now redundant) interrupts.
 */
static void rpmsg_downref_sleepers(struct virtproc_info *vrp)
{
	/* support multiple concurrent senders */
	spin_lock(&vrp->tx_lock);

	/* are we the last sleeping context waiting for tx buffers ? */
	if (atomic_dec_and_test(&vrp->sleepers))
		/* disable "tx-complete" interrupts */
		vhost_virtqueue_disable_cb(vrp->svq);

	spin_unlock(&vrp->tx_lock);
}

static int rpmsg_dump_dfx(struct virtproc_info *vrp)
{
	struct vhost_virtqueue *vq;
	struct device *dev;
	struct vring *vring;
	struct rpmsg_endpoint *ept;
	int id;
	int i;

	if (!vrp || !vrp->vdev)
		return -EINVAL;

	dev = &vrp->vdev->dev;

	for (i = 0; i < 2; i++) {
		if (i == 0) {
			vq = vrp->svq;
			dev_info(dev, "===================== svq =====================\n");
		} else {
			vq = vrp->rvq;
			dev_info(dev, "===================== rvq =====================\n");
		}
		vring = &vq->vringh.vring;

		dev_info(dev, "interrupts: %ld\n", vq->intr_cnt);
		dev_info(dev, "messages: %ld\n", vq->msg_cnt);
		dev_info(dev, "last_avail_idx: %d\n", vq->vringh.last_avail_idx);
		dev_info(dev, "last_used_idx: %d\n", vq->vringh.last_used_idx);

		if (0) {//avoid read outbound
			dev_info(dev, "vring_used_event: %d\n",	vring_used_event(vring));
			dev_info(dev, "used: flags %d,  idx %d\n",
						vring->used->flags, vring->used->idx);
		}

		dev_info(dev, "vring_avail_event: %d\n", vring_avail_event(vring));
		dev_info(dev, "avail: flags %d,  idx %d\n",
						vring->avail->flags, vring->avail->idx);
	}

	dev_info(dev, "==================== endpoints ====================\n");
	mutex_lock(&vrp->endpoints_lock);
	idr_for_each_entry(&vrp->endpoints, ept, id) {
		struct rpmsg_device *rpdev = ept->rpdev;

		dev_info(dev, "ept[%d]: addr(%d).\n", id, ept->addr);
		/* NS AS ept have no rpdev */
		if (rpdev) {
			dev_info(dev, "    belongs to rpdev %px: %s.%d.%d, rpc status: %d, cb_max_time: %d us\n",
				rpdev, rpdev->id.name,
				rpdev->src, rpdev->dst, atomic_read(&rpdev->rpc_flag), ept->cb_max_time);
		}
	}
	mutex_unlock(&vrp->endpoints_lock);

	return 0;
}

int ipcm_dump_dfx(struct vhost_dev *vdev)
{
	struct virtproc_info *vrp;

	if (!vdev)
		return -EINVAL;

	vrp = vhost_get_drvdata(vdev);

	return rpmsg_dump_dfx(vrp);
}

#define RPMSG_DUMP_ONCE(vrp) ({ \
	static bool __section(".data.once") __warned; \
				\
	if (unlikely(!__warned)) { \
		__warned = true; \
		rpmsg_dump_dfx(vrp); \
	} \
})

/**
 * rpmsg_send_offchannel_raw() - send a message across to the remote processor
 * @rpdev: the rpmsg channel
 * @src: source address
 * @dst: destination address
 * @data: payload of message
 * @len: length of payload
 * @wait: indicates whether caller should block in case no TX buffers available
 *
 * This function is the base implementation for all of the rpmsg sending API.
 *
 * It will send @data of length @len to @dst, and say it's from @src. The
 * message will be sent to the remote processor which the @rpdev channel
 * belongs to.
 *
 * The message is sent using one of the TX buffers that are available for
 * communication with this remote processor.
 *
 * If @wait is true, the caller will be blocked until either a TX buffer is
 * available, or 15 seconds elapses (we don't want callers to
 * sleep indefinitely due to misbehaving remote processors), and in that
 * case -ERESTARTSYS is returned. The number '15' itself was picked
 * arbitrarily; there's little point in asking drivers to provide a timeout
 * value themselves.
 *
 * Otherwise, if @wait is false, and there are no TX buffers available,
 * the function will immediately fail, and -ENOMEM will be returned.
 *
 * Normally drivers shouldn't use this function directly; instead, drivers
 * should use the appropriate rpmsg_{try}send{to, _offchannel} API
 * (see include/linux/rpmsg.h).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
static int rpmsg_send_offchannel_raw(struct rpmsg_device *rpdev,
				     u32 src, u32 dst,
				     void *data, int len, bool wait)
{
	struct vhost_rpmsg_channel *vch = to_vhost_rpmsg_channel(rpdev);
	struct virtproc_info *vrp = vch->vrp;
	struct vhost_virtqueue *svq = vrp->svq;
	struct device *dev = &rpdev->dev;
	struct rpmsg_hdr *msg;
	int length;
	u16 head;
	int err = 0;

	if (!vrp->vdev->vf_start) {
		return -ENODEV;
	}

	if (unlikely(ipcm_record)) {
		perf_dev_kva[ipcm_record_index].remote_real_cb_end_ns
			= monitor_get_host_ns_func(rpdev->vf_id, CLOCK_MONOTONIC_RAW);
	}

	/*
	 * We currently use fixed-sized buffers, and therefore the payload
	 * length is limited.
	 *
	 * One of the possible improvements here is either to support
	 * user-provided buffers (and then we can also support zero-copy
	 * messaging), or to improve the buffer allocator, to support
	 * variable-length buffer sizes.
	 */
	if (len > vrp->buf_size - sizeof(struct rpmsg_hdr)) {
		dev_err(dev, "message is too big (%d)\n", len);
		return -EMSGSIZE;
	}

	/* grab a buffer */
	msg = get_a_tx_buf(vrp, &head, &length);
	if (!msg && !wait) {
		dev_err(dev, "Failed to get buffer for OUT transfers\n");
		return -ENOMEM;
	}

#define RPMSG_TX_TIMEOUT_MS     (15000)
#define RPMSG_TX_INTERVAL_MS    (500)

	/* no free buffer ? wait for one (but bail after 15 seconds) */
	while (!msg) {
		int i = 0;

		/* enable "tx-complete" interrupts, if not already enabled */
		rpmsg_upref_sleepers(vrp);

		/*
		 * sleep until a free buffer is available or 15 secs elapse.
		 * the timeout period is not configurable because there's
		 * little point in asking drivers to specify that.
		 * if later this happens to be required, it'd be easy to add.
		 */
		/* check every RPMSG_TX_INTERVAL_MS */
		do {
			err = wait_event_interruptible_timeout(vrp->sendq,
						(msg = get_a_tx_buf(vrp, &head, &length)),
						msecs_to_jiffies(RPMSG_TX_INTERVAL_MS));
			i += RPMSG_TX_INTERVAL_MS;
		} while (!err && i < RPMSG_TX_TIMEOUT_MS);

		/* disable "tx-complete" interrupts if we're the last sleeper */
		rpmsg_downref_sleepers(vrp);

		/* timeout ? */
		if (!err) {
			dev_err(dev, "timeout waiting for a tx buffer\n");
			//RPMSG_DUMP_ONCE(vrp);
			rpmsg_dump_dfx(vrp);
			return -ETIMEDOUT;
		} else if (err == -ERESTARTSYS) {
			dev_info_ratelimited(dev, "fatal signal received when wait tx buffer.\n");
			return err;
		}
	}

	if (unlikely(ipcm_record)) {
		perf_dev_kva[ipcm_record_index].remote_get_tx_buf_ns
			= monitor_get_host_ns_func(rpdev->vf_id, CLOCK_MONOTONIC_RAW);
	}

	msg->len = len;
	msg->flags = 0;
	msg->src = src;
	msg->dst = dst;
	msg->reserved = 0;
	memcpy_toio(msg->data, data, len);
	dma_wmb();/* make sure data before mailbox */

	dev_dbg(dev, "TX From 0x%x, To 0x%x, Len %d, Flags %d, Reserved %d\n",
		msg->src, msg->dst, msg->len, msg->flags, msg->reserved);
#if defined(CONFIG_DYNAMIC_DEBUG)
	dynamic_hex_dump("rpmsg_virtio TX: ", DUMP_PREFIX_NONE, 16, 1,
			 msg, sizeof(*msg) + msg->len, true);
#endif

	spin_lock(&vrp->tx_lock);

	err = vhost_virtqueue_put_buf(svq, head, len + sizeof(struct rpmsg_hdr));
	if (err) {
		/*
		 * need to reclaim the buffer here, otherwise it's lost
		 * (memory won't leak, but rpmsg won't use it again for TX).
		 * this will wait for a buffer management overhaul.
		 */
		dev_err(dev, "vhost_virtqueue_put_buf failed: %d\n", err);
		goto out;
	}

	mmiowb();

	vrp->svq->msg_cnt++;

	/* tell the remote processor it has a pending message to read */
	vhost_virtqueue_kick(vrp->svq);

out:
	spin_unlock(&vrp->tx_lock);

	if (unlikely(ipcm_record)) {
		perf_dev_kva[ipcm_record_index++].remote_kick_mbox_ns
			= monitor_get_host_ns_func(rpdev->vf_id, CLOCK_MONOTONIC_RAW);
		if (ipcm_record_index == ipcm_record) {
			ipcm_record = 0;
			iounmap((void *)perf_dev_kva);
			perf_dev_kva = NULL;
		}
	}

	return err;
}

static int vhost_rpmsg_send(struct rpmsg_endpoint *ept, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr, dst = rpdev->dst;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int vhost_rpmsg_sendto(struct rpmsg_endpoint *ept, void *data, int len,
			      u32 dst)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int vhost_rpmsg_send_offchannel(struct rpmsg_endpoint *ept, u32 src,
				       u32 dst, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int vhost_rpmsg_trysend(struct rpmsg_endpoint *ept, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr, dst = rpdev->dst;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

static int vhost_rpmsg_trysendto(struct rpmsg_endpoint *ept, void *data,
				 int len, u32 dst)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

static int vhost_rpmsg_trysend_offchannel(struct rpmsg_endpoint *ept, u32 src,
					  u32 dst, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

/**
 * rpmsg_recv_single - Invoked when a buffer is received from remote VIRTIO dev
 * @vrp: virtual remote processor of the vhost device which has received a msg
 * @dev: struct device of vhost_dev
 * @msg: pointer to the rpmsg_hdr
 * @len: length of the received buffer
 *
 * Invoked when a buffer is received from remote VIRTIO device. It gets the
 * destination address from rpmsg_hdr and invokes the callback of the endpoint
 * corresponding to the address
 */
static int rpmsg_recv_single(struct virtproc_info *vrp, struct device *dev,
			     struct rpmsg_hdr *msg, unsigned int len)
{
	struct rpmsg_endpoint *ept;

	if (unlikely(ipcm_record)) {
		if (ipcm_record_index == 1 && perf_dev_kva[0].remote_recv_buf_ns == 0)
			ipcm_record_index = 0;
		perf_dev_kva[ipcm_record_index].remote_recv_buf_ns
			= monitor_get_host_ns_func(vrp->vdev->index, CLOCK_MONOTONIC_RAW);
	}

	dev_dbg(dev, "From: 0x%x, To: 0x%x, Len: %d, Flags: %d, Reserved: %d\n",
		msg->src, msg->dst, msg->len, msg->flags, msg->reserved);
#if defined(CONFIG_DYNAMIC_DEBUG)
	dynamic_hex_dump("rpmsg_virtio RX: ", DUMP_PREFIX_NONE, 16, 1,
			 msg, sizeof(*msg) + msg->len, true);
#endif

	/*
	 * We currently use fixed-sized buffers, so trivially sanitize
	 * the reported payload length.
	 */
	if (len > vrp->buf_size ||
	    msg->len > (len - sizeof(struct rpmsg_hdr))) {
		dev_warn(dev, "inbound msg too big: (%d, %d)\n", len, msg->len);
		return -EINVAL;
	}

	/* use the dst addr to fetch the callback of the appropriate user */
	mutex_lock(&vrp->endpoints_lock);

	ept = idr_find(&vrp->endpoints, msg->dst);

	/* let's make sure no one deallocates ept while we use it */
	if (ept)
		kref_get(&ept->refcount);

	mutex_unlock(&vrp->endpoints_lock);

	if (ept) {
		ktime_t start, end, delta;
		int duration;

		start = ktime_get();

		/* make sure ept->cb doesn't go away while we use it */
		mutex_lock(&ept->cb_lock);

		if (ept->cb)
			ept->cb(ept->rpdev, msg->data, msg->len, ept->priv,
				msg->src);

		mutex_unlock(&ept->cb_lock);

		end = ktime_get();
		delta = ktime_sub(end, start);
		duration = ktime_to_us(delta);
		if (unlikely(duration > 500))
			dev_dbg(&ept->rpdev->dev, "ept(%d) cb took too long: %d us", ept->addr, duration);
		if (duration > ept->cb_max_time)
			ept->cb_max_time = duration;

		/* farewell, ept, we don't need you anymore */
		kref_put(&ept->refcount, __ept_release);
	} else {
		dev_warn(dev, "msg received with no recipient(%d -> %d)\n", msg->src, msg->dst);
	}

	vrp->rvq->msg_cnt++;

	return 0;
}

/**
 * vhost_rpmsg_recv_done - Callback of the receive virtqueue
 * @rvq: Receive virtqueue
 *
 * Invoked when the remote VIRTIO device sends a notification on the receive
 * virtqueue. It gets base address of the input buffer and repeatedly calls
 * rpmsg_recv_single() until no more buffers are left to be read.
 */
static void vhost_rpmsg_recv_done(struct vhost_virtqueue *rvq)
{
	struct vhost_dev *vdev = rvq->dev;
	struct virtproc_info *vrp = vhost_get_drvdata(vdev);
	unsigned int len, msgs_received = 0;
	struct device *dev = &vdev->dev;
	struct rpmsg_hdr *msg;
	u16 head;
	int err;

	msg = vhost_virtqueue_get_inbuf(rvq, &head, &len);
	if (!msg) {
		dev_dbg(dev, "uhm, incoming signal, but no used buffer ?\n");
		return;
	}

	vhost_virtqueue_disable_cb(rvq);
	while (msg) {
		err = rpmsg_recv_single(vrp, dev, msg, len);
		if (err)
			break;

		vhost_virtqueue_put_buf(rvq, head, len);
		msgs_received++;

		msg = vhost_virtqueue_get_inbuf(rvq, &head, &len);
	}
	vhost_virtqueue_enable_cb(rvq);

	/*
	 * Try to read message one more time in case a new message is submitted
	 * after vhost_virtqueue_get_inbuf() inside the while loop but before enabling
	 * callbacks
	 */
	msg = vhost_virtqueue_get_inbuf(rvq, &head, &len);
	if (msg) {
		err = rpmsg_recv_single(vrp, dev, msg, len);
		if (!err)
			msgs_received++;
		vhost_virtqueue_put_buf(rvq, head, len);
	}

	dev_dbg(dev, "Received %u messages\n", msgs_received);

	/* tell the remote processor we added another available rx buffer */
	if (msgs_received)
		vhost_virtqueue_kick(vrp->rvq);
}

/**
 * vhost_rpmsg_xmit_done - Callback of the receive virtqueue
 * @svq: Send virtqueue
 *
 * This is invoked whenever the remote processor completed processing
 * a TX msg we just sent it, and the buffer is put back to the used ring.
 *
 * Normally, though, we suppress this "tx complete" interrupt in order to
 * avoid the incurred overhead.
 */
static void vhost_rpmsg_xmit_done(struct vhost_virtqueue *svq)
{
	struct vhost_dev *vdev = svq->dev;
	struct virtproc_info *vrp = vhost_get_drvdata(vdev);
	struct device *dev = &vdev->dev;

	dev_dbg(dev, "%s\n", __func__);

	/* wake up potential senders that are waiting for a tx buffer */
	wake_up_interruptible(&vrp->sendq);
}

/**
 * vhost_rpmsg_as_cb - Callback of address service announcement
 * @data: rpmsg_as_msg sent by remote VIRTIO device
 * @len: length of the received message
 * @priv: private data for the driver's use
 * @src: source address of the remote VIRTIO device that sent the AS
 *       announcement
 *
 * Invoked when a address service announcement arrives to assign the
 * destination address of the rpmsg device.
 */
static int vhost_rpmsg_as_cb(struct rpmsg_device *rpdev, void *data, int len,
			     void *priv, u32 hdr_src)
{
	struct virtproc_info *vrp = priv;
	struct device *dev = &vrp->vdev->dev;
	struct rpmsg_channel_info chinfo;
	struct rpmsg_as_msg *msg = data;
	struct rpmsg_device *rpmsg_dev;
	struct device *rdev;
	int ret = 0;
	u32 flags;
	u32 src;
	u32 dst;

#if defined(CONFIG_DYNAMIC_DEBUG)
	dynamic_hex_dump("AS announcement: ", DUMP_PREFIX_NONE, 16, 1,
			 data, len, true);
#endif

	if (len == sizeof(*msg)) {
		src = msg->src;
		dst = msg->dst;
		flags = msg->flags;
	} else {
		dev_err(dev, "malformed AS msg (%d)\n", len);
		return -EINVAL;
	}

	/*
	 * the name service ept does _not_ belong to a real rpmsg channel,
	 * and is handled by the rpmsg bus itself.
	 * for sanity reasons, make sure a valid rpdev has _not_ sneaked
	 * in somehow.
	 */
	if (rpdev) {
		dev_err(dev, "anomaly: ns ept has an rpdev handle\n");
		return -EINVAL;
	}

	/* don't trust the remote processor for null terminating the name */
	msg->name[RPMSG_NAME_SIZE - 1] = '\0';

	dev_info(dev, "%sing dst addr 0x%x to channel %s src 0x%x\n",
		 flags & RPMSG_AS_ASSIGN ? "Assign" : "Free",
		 dst, msg->name, src);

	strncpy(chinfo.name, msg->name, sizeof(chinfo.name));
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = src;
	chinfo.dst = RPMSG_ADDR_ANY;

	/* Find a similar channel */
	rdev = cn_rpmsg_find_device(dev, &chinfo);
	if (!rdev) {
		ret = -ENODEV;
		goto err_find_device;
	}

	rpmsg_dev = to_rpmsg_device(rdev);
	if (flags & RPMSG_AS_ASSIGN) {
		if (rpmsg_dev->dst != RPMSG_ADDR_ANY) {
			dev_err(dev, "Address bound to channel %s src 0x%x\n",
				msg->name, src);
			ret = -EBUSY;
			goto err_find_device;
		}
		rpmsg_dev->dst = dst;
	} else {
		rpmsg_dev->dst = RPMSG_ADDR_ANY;
	}

err_find_device:
	put_device(rdev);

	return ret;
}

static unsigned int vhost_rpmsg_features[] = {
	VIRTIO_RPMSG_F_AS,
	VIRTIO_RPMSG_F_NS,
};

/**
 * vhost_rpmsg_set_features - Sets supported features on the VHOST device
 *
 * Build supported features from the feature table and invoke
 * vhost_set_features() to set the supported features on the VHOST device
 */
static int vhost_rpmsg_set_features(struct vhost_dev *vdev)
{
	unsigned int feature_table_size;
	unsigned int feature;
	u64 device_features = 0;
	int ret, i;

	feature_table_size =  ARRAY_SIZE(vhost_rpmsg_features);
	for (i = 0; i < feature_table_size; i++) {
		feature = vhost_rpmsg_features[i];
		WARN_ON(feature >= 64);
		device_features |= (1ULL << feature);
	}

	ret = vhost_set_features(vdev, device_features);
	if (ret)
		return ret;

	return 0;
}

static ssize_t endpoints_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct vhost_dev *vdev = to_vhost_dev(dev);
	struct virtproc_info *vrp = vhost_get_drvdata(vdev);
	char *p = buf;
	struct rpmsg_endpoint *ept;
	int id;

	mutex_lock(&vrp->endpoints_lock);
	idr_for_each_entry(&vrp->endpoints, ept, id) {
		struct rpmsg_device *rpdev = ept->rpdev;

		p += snprintf(p, PAGE_SIZE - (p - buf), "ept[%d]: addr(%d) tgid(%d).\n", id, ept->addr, ept->tgid);
		/* NS AS ept have no rpdev */
		if (rpdev) {
			p += snprintf(p, PAGE_SIZE - (p - buf),
				"\tbelongs to rpdev %px: %s.%d.%d, rpc status: %d, cb_max_time: %d us\n",
				rpdev, rpdev->id.name,
				rpdev->src, rpdev->dst, atomic_read(&rpdev->rpc_flag), ept->cb_max_time);
		}
	}
	mutex_unlock(&vrp->endpoints_lock);
	return p - buf;
}
static DEVICE_ATTR_RO(endpoints);

static int vhost_rpmsg_remove_device(struct device *dev, void *data)
{
	device_unregister(dev);

	return 0;
}

IPCM_DECLARE_CALLBACK_FUNC(rpc_vf_start);
IPCM_DECLARE_CALLBACK_FUNC(rpc_vf_exit);

static struct rpmsg_rpc_service_set vf_state_service_table[] = {
		DEF_CALLBACK_PAIR(rpc_vf_start),
		DEF_CALLBACK_PAIR(rpc_vf_exit),
		DEF_CALLBACK_PAIR_END,
};
#define VF_STATE_SERVICE_TABLE vf_state_service_table

static int32_t
rpc_vf_start(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	int _vf_id = *(int *)in_msg;
	struct vhost_dev *vdev = cambr_rproc_get_vhost_device(_vf_id);
	struct virtproc_info *vrp = vdev ? vhost_get_drvdata(vdev) : NULL;
	struct rpmsg_device *rpdev;

	*out_len = sizeof(int);

	if (unlikely(!vrp)) {
		*((int *)out_msg) = -ENODEV;
		return -ENODEV;
	}

	if (!vdev->vf_start) {
		dev_info(&vdev->dev, "VF %d Start\n", _vf_id);
		vdev->vf_start = true;
	} else {
		dev_info(&vdev->dev, "VF %d Start with driver has not rmmod when last run in vm\n", _vf_id);
	}

	/* suppress "tx-complete" interrupts */
	vhost_virtqueue_disable_cb(vrp->svq);
	mutex_lock(&vrp->list_lock);
	list_for_each_entry(rpdev, &vrp->list, list) {
		struct rpmsg_channel_info chinfo = {};
		struct device *tmp;

		strncpy(chinfo.name, rpdev->id.name, sizeof(chinfo.name));
		chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
		chinfo.src = rpdev->src;
		chinfo.dst = rpdev->dst;
		tmp = cn_rpmsg_find_device(&vdev->dev, &chinfo);
		if (tmp) {
			/* decrement the matched device's refcount back */
			put_device(tmp);
			/* VF restart, not first time, just anounce remote */
			vhost_rpmsg_announce_create(rpdev);
		} else {
			int ret = 0;

			dev_info(&vdev->dev, "%s create chanel, %s.%d.%d\n", __func__,
				rpdev->id.name, rpdev->src, rpdev->dst);
			ret = cn_rpmsg_register_device(rpdev);
			if (ret) {
				mutex_unlock(&vrp->list_lock);
				*((int *)out_msg) = ret;
				return ret;
			}
		}
	}
	//list_del(&vrp->list);
	mutex_unlock(&vrp->list_lock);

	*((int *)out_msg) = 0;
	return 0;
}

static int32_t
rpc_vf_exit(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	int _vf_id = *(int *)in_msg;
	struct vhost_dev *vdev = cambr_rproc_get_vhost_device(_vf_id);

	*out_len = sizeof(int);

	if (unlikely(!vdev)) {
		*((int *)out_msg) = -ENODEV;
		return -ENODEV;
	}

	if (vdev->vf_start) {
		dev_info(&vdev->dev, "VF %d Exit\n", _vf_id);
		vhost_reset_vqs(vdev);
		/* do not remove for vf restart */
		//ret = device_for_each_child(&vdev->dev, NULL, vhost_rpmsg_remove_device);
		//if (ret)
		//	dev_warn(&vdev->dev, "can't remove rpmsg device: %d\n", ret);
		vdev->vf_start = false;
	} else {
		dev_info(&vdev->dev, "VF %d already Exit\n", _vf_id);
	}
	*((int *)out_msg) = 0;
	return 0;
}

IPCM_DECLARE_CALLBACK_FUNC(rpc_enable_perf_record);
IPCM_DECLARE_CALLBACK_FUNC(rpc_perf_test);

static struct rpmsg_rpc_service_set perf_record_service_table[] = {
		DEF_CALLBACK_PAIR(rpc_enable_perf_record),
		DEF_CALLBACK_PAIR(rpc_perf_test),
		DEF_CALLBACK_PAIR_END,
};
#define PERF_REC_SERVICE_TABLE perf_record_service_table

static int32_t
rpc_enable_perf_record(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct ipcm_perf_test_info *test_info = (struct ipcm_perf_test_info *)in_msg;
	int ret = 0;

	pr_info("%s, shm iova:0x%llx, test_cnt:%d, record_en:%d vf_id:%d\n",
		__func__, test_info->perf_dev_iova, test_info->test_cnt, test_info->record_en, vf_id);

	if (unlikely(!monitor_get_host_ns_func)) {
		monitor_get_host_ns_func = (void *)cnosal_kallsyms_lookup_name("monitor_get_host_ns");
		if (!monitor_get_host_ns_func) {
			pr_err("get monitor_get_host_ns failed!");
			ret = -ENODEV;
			goto out;
		}
	}

	if (test_info->test_cnt <= 0) {
		ret = -EINVAL;
		goto out;
	}

	ipcm_record_index = 0;
	ipcm_record = 0;

	if (test_info->perf_dev_iova && test_info->record_en) {
		/* cvms_get_shm_arm_addr() */
		u64 dev_pa = vapa_pa_base + (test_info->perf_dev_iova - vapa_va_base);

		perf_dev_kva = (struct ipcm_timestamp_info *)ioremap(dev_pa,
			sizeof(struct ipcm_timestamp_info) * test_info->test_cnt);
		if (!perf_dev_kva) {
			pr_err("%s, cvms_share_kmap error\n", __func__);
			ret = -EIO;
			goto out;
		}
		ipcm_record = test_info->test_cnt;
	}

out:
	*out_len = sizeof(int);
	*((int *)out_msg) = ret;
	return 0;
}

static int32_t
rpc_perf_test(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	*out_len = in_len;
	memcpy(out_msg, in_msg, in_len);
	return 0x88;
}

static struct rpmsg_device* ipcm_rpc_log_dev;

/**
 * @brief Arm prints it's logging on host's printk
 *
 * On current implementation, host can view ARM's log only on some severe
 * scenarios such as ARM crashing, that's insufficient cause maybe ARM want
 * to inform host about its exception status, not as fatal as crashing. In
 * that case, ARM'S subsystems can invoke this API to do that.
 *
 * @param  fmt[in] formatting string
 * @param  ...[in] optional arguments to format
 *
 * Example: ipcm_rpc_log("%s %d", __func__, cnt);
 *
 * @return 0 if success, otherwise with the Error code.
 *
 */
int ipcm_rpc_log(char *fmt, ...)
{
	int ret = 0;
	va_list args;
	char buf[MAX_BUF_LEN];
	int sz = 0;
	struct rpmsg_device *dev = NULL;

	might_sleep();

	if (fmt == NULL) {
		pr_err("%s: fmt = NULL\n", __func__);
		return -EINVAL;
	}

	va_start(args, fmt);
	sz = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	dev = ipcm_rpc_log_dev;
	if (dev == NULL) {
		pr_err("%s: ipcm_log_dev = NULL\n", __func__);
		return -EINVAL;
	}

	/* Printing are synchronized on both sides */
	printk(buf);

	ret = ipcm_send_message(dev, buf, strlen(buf) + 1);
	if (ret) {
		pr_err("%s: ipcm_send_message() failed\n", __func__);
	}

	return ret;
}
EXPORT_SYMBOL(ipcm_rpc_log);

/**
 * vhost_rpmsg_probe - Create virtual remote processor for the VHOST device
 * @vdev - VHOST device with vendor ID and device ID supported by this driver
 *
 * Invoked when VHOST device is registered with vendor ID and device ID
 * supported by this driver. Creates and initializes the virtual remote
 * processor for the VHOST device
 */
static int vhost_rpmsg_probe(struct vhost_dev *vdev)
{
	vhost_vq_callback_t *vq_cbs[] = { vhost_rpmsg_xmit_done, vhost_rpmsg_recv_done };
	static const char * const names[] = { "output", "input" };
	struct device *dev = &vdev->dev;
	struct vhost_virtqueue *vqs[2];
	struct virtproc_info *vrp;
	size_t total_buf_space;
	phys_addr_t tx_pa, rx_pa;
	unsigned long tx_va, rx_va;
	dma_addr_t bufs_dma, bufs_dma_ob = 0;
	void *bufs_va, *bufs_va_ob = NULL;
	struct device_node *rsz = NULL;
	struct device_node *shm = NULL;
	int err;
	struct rpmsg_device *rpdev;

	if (!vapa_pa_base) {
		rsz = of_find_node_by_name(NULL, "reserved-memory");
		if (!rsz) {
			dev_err(dev, "get reserved-memory failed\n");
			return -EINVAL;
		}
		shm = of_find_node_by_name(rsz, "share_memory");
		if (!shm) {
			dev_err(dev, "get share_memory failed\n");
			return -EINVAL;
		}
		err = of_property_read_u64(shm, "phys-base", &vapa_pa_base);
		if (err < 0) {
			dev_err(dev, "share_memory phys-base failed<%d>\n", err);
			return -EINVAL;
		}
		err = of_property_read_u64(shm, "virt-base", &vapa_va_base);
		if (err < 0) {
			dev_err(dev, "share_memory virt-base failed<%d>\n", err);
			return -EINVAL;
		}
		err = of_property_read_u32(shm, "size", &vapa_size);
		if (err < 0) {
			err = of_property_read_u32(shm, "shm-size", &vapa_size);
			if (err < 0) {
				dev_err(dev, "share_memory size failed<%d>\n", err);
				return -EINVAL;
			}
		}
		dev_info(dev, "%s, 0x%llx<--->0x%llx, size:0x%x!\n",
				__func__, vapa_pa_base, vapa_va_base, vapa_size);
	}

	/*
	 * outbound shm can't access while core driver not load,
	 * and nobody add_in_buf to fill shm which will lead to NS announce crash.
	 * so while vhost_rpmsg_create_channel() we not actually register rpdev to avoid probe.
	 */
	if (vdev->index == 0) {
		vdev->vf_start = true;
	} else {
		vdev->vf_start = false;
	}

	vrp = kzalloc(sizeof(*vrp), GFP_KERNEL);
	if (!vrp) {
		err = -ENOMEM;
		goto failed;
	}

	vrp->vdev = vdev;

	idr_init(&vrp->endpoints);
	mutex_init(&vrp->endpoints_lock);
	spin_lock_init(&vrp->tx_lock);
	mutex_init(&vrp->rx_lock);
	mutex_init(&vrp->list_lock);
	init_waitqueue_head(&vrp->sendq);

	err = vhost_rpmsg_set_features(vdev);
	if (err) {
		dev_err(dev, "Failed to set features\n");
		goto free_vrp;
	}

	/* We expect two vhost_virtqueues, tx and rx (and in this order) */
	err = vhost_create_vqs(vdev, 2, MAX_RPMSG_NUM_BUFS / 2, vqs, vq_cbs,
			       names);
	if (err) {
		dev_err(dev, "Failed to create virtqueues\n");
		goto free_vrp;
	}

	vrp->svq = vqs[0];
	vrp->rvq = vqs[1];

	vrp->buf_size = MAX_RPMSG_BUF_SIZE;

	total_buf_space = MAX_RPMSG_NUM_BUFS * MAX_RPMSG_BUF_SIZE;

	/* allocate coherent memory for the buffers */
	bufs_va = dma_alloc_coherent(vdev->dev.parent,
				     total_buf_space, &bufs_dma,
				     GFP_KERNEL);
	if (!bufs_va) {
		err = -ENOMEM;
		goto del_vqs;
	}

	dev_info(&vdev->dev, "using dma_alloc_coherent(): va %px, dma %pad\n",
		bufs_va, &bufs_dma);

	if (vhost_get_outbound(vdev)) {
		bufs_va_ob = cambr_gen_pool_dma_alloc(vdev->OB_pool, total_buf_space/2, &bufs_dma_ob);
		dev_info(&vdev->dev, "using cambricon genpool: va %px, dma %pad\n",
			bufs_va_ob, &bufs_dma_ob);
		if (!bufs_va_ob) {
			err = -ENOMEM;
			goto free_coherent;
		}
	}

	/* to iova */
	//rx_pa = (phys_addr_t)bufs_dma + total_buf_space / 2;
	//tx_pa = (phys_addr_t)bufs_dma;
	rx_pa = (phys_addr_t)vapa_va_base + (bufs_dma - vapa_pa_base) + total_buf_space / 2;
	tx_pa = (phys_addr_t)vapa_va_base + (bufs_dma - vapa_pa_base);
	rx_va = (unsigned long)bufs_va + total_buf_space / 2;
	tx_va = (unsigned long)bufs_va;
	if (vhost_get_outbound(vdev)) {
		vrp->rbufs_ob = bufs_va_ob;
		tx_pa = (phys_addr_t)bufs_dma_ob;
		tx_va = (unsigned long)bufs_va_ob;
	}

	vhost_init_mem_region(vrp->rvq, rx_pa,
			rx_va, total_buf_space / 2);
	vhost_init_mem_region(vrp->svq, tx_pa,
			tx_va, total_buf_space / 2);
	vrp->rvq->intr_cnt = 0;
	vrp->svq->intr_cnt = 0;
	vrp->rvq->msg_cnt = 0;
	vrp->svq->msg_cnt = 0;

	vhost_set_drvdata(vdev, vrp);

	INIT_LIST_HEAD(&vrp->list);

	/* avoid access outbound while not ready yet */
	if (vhost_rpmsg_remote_ready(vdev)) {
		/* suppress "tx-complete" interrupts */
		vhost_virtqueue_disable_cb(vrp->svq);
	}

	/* if supported by the remote processor, enable the address service */
	if (vhost_has_feature(vdev, VIRTIO_RPMSG_F_AS)) {
		/* a dedicated endpoint handles the name service msgs */
		vrp->as_ept = __rpmsg_create_ept(vrp, NULL, vhost_rpmsg_as_cb,
						 vrp, RPMSG_AS_ADDR);
		if (!vrp->as_ept) {
			dev_err(&vdev->dev, "failed to create the as ept\n");
			err = -ENOMEM;
			goto free_genpool;
		}
	} else {
		dev_err(&vdev->dev, "Address Service not supported\n");
		err = -ENOMEM;
		goto free_genpool;
	}

	err = sysfs_create_file(&vdev->dev.kobj, &dev_attr_endpoints.attr);
	if (err) {
		dev_err(&vdev->dev, "%s, failed to sysfs_create_file.\n", __func__);
		goto free_genpool;
	}
	err = rpmsg_create_chrdev(vrp);
	if (err) {
		dev_err(&vdev->dev, "%s, failed to register chrdev.\n", __func__);
		goto remove_sysfs;
	}

	/* create vf state service on pf */
	if (vdev->index == 0) {
		rpdev = _ipcm_create_user_channel(vrp, VS_CHANNEL_NAME, RPMSG_VS_ADDR);
		if (likely(rpdev))
			rpdev->services = VF_STATE_SERVICE_TABLE;
	}

	/* Create ep for rpc log on pf */
	if (vdev->index == 0) {
		ipcm_rpc_log_dev = _ipcm_create_user_channel(vrp, RPSMG_LOG_CHANNEL_NAME, RPSMG_LOG_ADDR);
		if (IS_ERR_OR_NULL(ipcm_rpc_log_dev)) {
			dev_err(&vdev->dev, "__ipcm_create_log_channel() failed\n");
		}
	}

	/* Create ep for perf record */
	rpdev = _ipcm_create_user_channel(vrp, RPSMG_REC_CHANNEL_NAME, RPMSG_REC_ADDR);
	if (IS_ERR_OR_NULL(rpdev)) {
		dev_err(&vdev->dev, "__ipcm_create_perf_rec_channel() failed\n");
	} else {
		rpdev->services = PERF_REC_SERVICE_TABLE;
	}

	/* Create ep for codec get tgid */
	rpdev = _ipcm_create_user_channel(vrp, RPSMG_QUERY_PORT_NAME, RPMSG_QUERY_PORT_ADDR);
	if (IS_ERR_OR_NULL(rpdev)) {
		dev_err(&vdev->dev, "__ipcm_create_tgid_channel() failed\n");
	}

	pf_vf_num++;

	dev_info(&vdev->dev, "vhost rpmsg is online\n");

	return 0;

remove_sysfs:
	sysfs_remove_file(&vdev->dev.kobj, &dev_attr_endpoints.attr);
free_genpool:
	if (vhost_get_outbound(vdev))
		cambr_gen_pool_dma_free(vdev->OB_pool, total_buf_space/2,
			(unsigned long)bufs_va_ob);
free_coherent:
	dma_free_coherent(vdev->dev.parent, total_buf_space,
			  bufs_va, bufs_dma);
del_vqs:
	vhost_del_vqs(vdev);
free_vrp:
	kfree(vrp);
failed:
	dev_info(&vdev->dev, "vhost rpmsg failed with err:%d\n", err);
	return err;
}

static int vhost_rpmsg_remove(struct vhost_dev *vdev)
{
	struct virtproc_info *vrp = vhost_get_drvdata(vdev);
	size_t total_buf_space = MAX_RPMSG_NUM_BUFS * MAX_RPMSG_BUF_SIZE;
	int ret;

	ret = device_for_each_child(&vdev->dev, NULL, vhost_rpmsg_remove_device);
	if (ret)
		dev_warn(&vdev->dev, "can't remove rpmsg device: %d\n", ret);

	sysfs_remove_file(&vdev->dev.kobj, &dev_attr_endpoints.attr);
	if (vrp->as_ept)
		__rpmsg_destroy_ept(vrp, vrp->as_ept);

	idr_destroy(&vrp->endpoints);

	vhost_del_vqs(vdev);

	if (vhost_get_outbound(vdev))
		cambr_gen_pool_dma_free(vdev->OB_pool, total_buf_space/2,
			(unsigned long)vrp->rbufs_ob);

	kfree(vrp);
	vhost_set_drvdata(vdev, NULL);
	return 0;
}

static struct virtio_device_id vhost_rpmsg_id_table[] = {
	{ VIRTIO_ID_RPMSG, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct vhost_driver vhost_rpmsg_driver = {
	.driver.name	= "cn_vhost_ipc",
	.driver.owner	= THIS_MODULE,
	.id_table	= vhost_rpmsg_id_table,
	.probe		= vhost_rpmsg_probe,
	.remove		= vhost_rpmsg_remove,
};

int vhost_rpmsg_init(void)
{
	int ret;

	pr_info("%s, %d\n", __func__, __LINE__);
	ret = vhost_register_driver(&vhost_rpmsg_driver);
	if (ret)
		pr_err("Failed to register vhost rpmsg driver: %d\n", ret);

	return ret;
}

void vhost_rpmsg_fini(void)
{
	vhost_unregister_driver(&vhost_rpmsg_driver);
}

MODULE_DEVICE_TABLE(vhost, vhost_rpmsg_id_table);
MODULE_DESCRIPTION("Vhost-based remote processor messaging bus");
MODULE_LICENSE("GPL v2");
