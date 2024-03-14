// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio-based remote processor messaging bus
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 * Copyright (C) 2011 Google, Inc.
 *
 * Ohad Ben-Cohen <ohad@wizery.com>
 * Brian Swetland <swetland@google.com>
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/dma-mapping.h>
#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_device.h>
#include "../include/rpmsg/rpmsg.h"
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched.h>
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/task.h>
#endif
#include <linux/delay.h>
#include "../include/virtio/virtio.h"
#include "../include/uapi/linux/virtio_ids.h"
#include "../include/virtio/virtio_config.h"
#include <linux/wait.h>
#include <linux/pid_namespace.h>

#include "../include/remoteproc/remoteproc.h"
#include "../include/virtio/virtio_ring.h"

#include "rpmsg_internal.h"

#include "cndrv_ipcm.h"

#ifndef PHYS_PFN
#define PHYS_PFN(x) ((unsigned long)((x) >> PAGE_SHIFT))
#endif

static inline void virtio_mmiowb(struct virtio_device *vdev)
{
	smp_mb(); /*barrier*/
}

#ifdef IN_CNDRV_HOST
#include "cndrv_core.h"
#include "cndrv_bus.h"

extern struct cn_core_set *cambr_dev_to_core(struct device *dev);

/* a readback as a barrier, for vf */
static void virtio_barrier(struct virtio_device *vdev)
{
	struct cn_core_set *core = cambr_dev_to_core(&vdev->dev);

	if (unlikely(!core)) {
		dev_err_ratelimited(&vdev->dev, "%s core is NULL\n", __func__);
		return;
	}

	/*
	 * only vf's with QUIRK_AVOID_VF_READ_INBOUND:
	 * vring0/vring1 vdevbuffer rx in outbound, vdevbuffer tx in inbound shm, need a readback as barrier.
	 * see rproc_get_quirks().
	 *
	 * otherwise a smp_wmb() is enough.
	 * 1. all vring0/vring1/vdevbuferr in inbound, while not support outbound;
	 * 2. all vring0/vring1/vdevbuferr in outbound, while not support inbound, N/A for now;
	 * 3. vring0/vdevbuffer rx in outbound, vring1/vdevbuffer tx in inbound,
	 *    while !QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND, N/A for now;
	 * 4. vring0 in inbound but vring0->used and vdevbuffer rx in outbound,
	 *    vring1/vdevbuffer tx in inbound, while QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND, a workaround for #3;
	 */
	if (cn_core_is_vf(core) && virtio_get_outbound(vdev)/* && QUIRK_AVOID_VF_READ_INBOUND*/) {
		cn_bus_mb(core->bus_set);
	} else {
		wmb();/* make sure data before idx, smp_wmb in x86 is a compiler barrier, not cpu barrier */
	}
}
#else
static inline void virtio_barrier(struct virtio_device *vdev)
{
	smp_wmb();/* make sure data before mailbox */
}
#endif

/*
 * TODO
 * endpoints SHOULD in struct rpmsg_device, but now rpmsg_device has only one default ept.
 * and rpmsg_devices/virtio_rpmsg_channels SHOULD in struct virtproc_info.
 * rpmsg_ns_cb
 */

/**
 * struct virtproc_info - virtual remote processor state
 * @vdev:	the virtio device
 * @rvq:	rx virtqueue
 * @svq:	tx virtqueue
 * @rbufs:	kernel address of rx buffers
 * @sbufs:	kernel address of tx buffers
 * @num_bufs:	total number of buffers for rx and tx
 * @buf_size:   size of one rx or tx buffer
 * @last_sbuf:	index of last tx buffer used
 * @bufs_dma:	dma base addr of the buffers
 * @tx_lock:	protects svq, sbufs and sleepers, to allow concurrent senders.
 *		sending a message might require waking up a dozing remote
 *		processor, which involves sleeping, hence the mutex.
 * @endpoints:	idr of local endpoints, allows fast retrieval
 * @endpoints_lock: lock of the endpoints set
 * @sendq:	wait queue of sending contexts waiting for a tx buffers
 * @sleepers:	number of senders that are waiting for a tx buffer
 * @ns_ept:	the bus's name service endpoint
 *
 * This structure stores the rpmsg state of a given virtio remote processor
 * device (there might be several virtio proc devices for each physical
 * remote processor).
 */
struct virtproc_info {
	struct virtio_device *vdev;
	struct virtqueue *rvq, *svq;
	void *rbufs, *sbufs;
	unsigned int num_bufs;
	unsigned int buf_size;
	int last_sbuf;
	dma_addr_t bufs_dma;
	spinlock_t tx_lock;
	struct idr endpoints;
	struct mutex endpoints_lock;
	wait_queue_head_t sendq;
	atomic_t sleepers;
	struct rpmsg_endpoint *ns_ept;
	/* cambricon */
	dma_addr_t bufs_dma_ob;
	void *rbufs_ob, *sbufs_ob;
	#ifdef CALLBACK_IN_INTR_CONTEXT
	struct work_struct ns_work;
	struct list_head ns_msgs;
	spinlock_t ns_lock;
	#endif
};

/**
 * struct virtio_rpmsg_channel - rpmsg channel descriptor
 * @rpdev: the rpmsg channel device
 * @vrp: the remote processor this channel belongs to
 *
 * This structure stores the channel that links the rpmsg device to the virtio
 * remote processor device.
 */
struct virtio_rpmsg_channel {
	struct rpmsg_device rpdev;

	struct virtproc_info *vrp;
};

#define to_virtio_rpmsg_channel(_rpdev) \
	container_of(_rpdev, struct virtio_rpmsg_channel, rpdev)

static void virtio_rpmsg_destroy_ept(struct rpmsg_endpoint *ept);
static int virtio_rpmsg_send(struct rpmsg_endpoint *ept, void *data, int len);
static int virtio_rpmsg_sendto(struct rpmsg_endpoint *ept, void *data, int len,
			       u32 dst);
static int virtio_rpmsg_send_offchannel(struct rpmsg_endpoint *ept, u32 src,
					u32 dst, void *data, int len);
static int virtio_rpmsg_trysend(struct rpmsg_endpoint *ept, void *data, int len);
static int virtio_rpmsg_trysendto(struct rpmsg_endpoint *ept, void *data,
				  int len, u32 dst);
static int virtio_rpmsg_trysend_offchannel(struct rpmsg_endpoint *ept, u32 src,
					   u32 dst, void *data, int len);

static const struct rpmsg_endpoint_ops virtio_endpoint_ops = {
	.destroy_ept = virtio_rpmsg_destroy_ept,
	.send = virtio_rpmsg_send,
	.sendto = virtio_rpmsg_sendto,
	.send_offchannel = virtio_rpmsg_send_offchannel,
	.trysend = virtio_rpmsg_trysend,
	.trysendto = virtio_rpmsg_trysendto,
	.trysend_offchannel = virtio_rpmsg_trysend_offchannel,
};

/**
 * rpmsg_sg_init - initialize scatterlist according to cpu address location
 * @vrp: virtual remoteproc structure used with this buffer
 * @sg: scatterlist to fill
 * @cpu_addr: virtual address of the buffer
 * @len: buffer length
 *
 * An internal function filling scatterlist according to virtual address
 * location (in vmalloc or in kernel).
 */
#define DATA_DIR_IN  (0)
#define DATA_DIR_OUT (1)

static void
rpmsg_sg_init(struct virtproc_info *vrp, struct scatterlist *sg, void *cpu_addr, unsigned int len, int dir)
{
	/* cambricon hack for PCIe inbound shared mem are none of below */
	#if defined(RPMSG_MASTER_PCIE_RC)
	unsigned long offset;
	dma_addr_t dma_addr;

	if (virtio_get_outbound(vrp->vdev) && dir == DATA_DIR_IN) {
		offset = cpu_addr - vrp->rbufs_ob;
		dma_addr = vrp->bufs_dma_ob + offset;
	} else {
		offset = cpu_addr - vrp->rbufs;
		dma_addr = vrp->bufs_dma + offset;
	}

	sg_init_table(sg, 1);
	sg_set_page(sg, pfn_to_page(PHYS_PFN(dma_addr)), len,
			    offset_in_page(cpu_addr));
	#else
	if (is_vmalloc_addr(cpu_addr)) {
		sg_init_table(sg, 1);
		sg_set_page(sg, vmalloc_to_page(cpu_addr), len,
			    offset_in_page(cpu_addr));
	} else {
		WARN_ON(!virt_addr_valid(cpu_addr));
		sg_init_one(sg, cpu_addr, len);
	}
	#endif
}

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

/* for more info, see below documentation of cn_rpmsg_create_ept() */
static struct rpmsg_endpoint *__rpmsg_create_ept(struct virtproc_info *vrp,
						 struct rpmsg_device *rpdev,
						 rpmsg_rx_cb_t cb,
						 void *priv, u32 addr)
{
	int id_min, id_max, id;
	struct rpmsg_endpoint *ept;
	struct device *dev = rpdev ? &rpdev->dev : &vrp->vdev->dev;
	struct pid_namespace *active_ns;

	dev_dbg(dev, "%s, addr(%d)", __func__, addr);

	ept = kzalloc(sizeof(*ept), GFP_KERNEL);
	if (!ept)
		return NULL;

	kref_init(&ept->refcount);
	mutex_init(&ept->cb_lock);

	ept->rpdev = rpdev;
	ept->cb = cb;
	ept->priv = priv;
	ept->ops = &virtio_endpoint_ops;

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
		active_ns = task_active_pid_ns(current);
		dev_err(dev, "tgid:%d active_tgid:%d comm:%s create_ept with addr(%d) failed, start dump endpoints\n",
					task_tgid_nr(current), task_tgid_nr_ns(current, active_ns), buf, addr);
		idr_for_each_entry(&vrp->endpoints, tmp, id) {
			task = get_pid_task(find_vpid(tmp->tgid), PIDTYPE_PID);
			if (task)
				get_task_comm(buf, task);

			dev_info(&vrp->vdev->dev, "ept[%d]: addr(%d), active_tgid: %d, comm: %s.\n",
					id, tmp->addr, tmp->tgid, task ? buf : "unknown(none exist/not the same ns)");
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
	active_ns = task_active_pid_ns(current);
	ept->tgid = task_tgid_nr_ns(current, active_ns);
	ept->cb_lockdep_class = ((ept->addr == RPMSG_NS_ADDR) ?
				 RPMSG_LOCKDEP_SUBCLASS_NS :
				 RPMSG_LOCKDEP_SUBCLASS_NORMAL);

	dev_dbg(dev, "%s ept.addr: %d\n", __func__, ept->addr);
	mutex_unlock(&vrp->endpoints_lock);

	return ept;

free_ept:
	mutex_unlock(&vrp->endpoints_lock);
	kref_put(&ept->refcount, __ept_release);
	return NULL;
}

static struct rpmsg_endpoint *virtio_rpmsg_create_ept(struct rpmsg_device *rpdev,
						      rpmsg_rx_cb_t cb,
						      void *priv,
						      struct rpmsg_channel_info chinfo)
{
	struct virtio_rpmsg_channel *vch = to_virtio_rpmsg_channel(rpdev);

	dev_dbg(&rpdev->dev, "%s, channel %s, src(%d), dst(%d)\n", __func__, chinfo.name, chinfo.src, chinfo.dst);

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
	mutex_lock_nested(&ept->cb_lock, ept->cb_lockdep_class);
	ept->cb = NULL;
	mutex_unlock(&ept->cb_lock);

	kref_put(&ept->refcount, __ept_release);
}

static void virtio_rpmsg_destroy_ept(struct rpmsg_endpoint *ept)
{
	struct virtio_rpmsg_channel *vch = to_virtio_rpmsg_channel(ept->rpdev);

	__rpmsg_destroy_ept(vch->vrp, ept);
}

static int virtio_rpmsg_announce_create(struct rpmsg_device *rpdev)
{
	struct virtio_rpmsg_channel *vch = to_virtio_rpmsg_channel(rpdev);
	struct virtproc_info *vrp = vch->vrp;
	struct device *dev = &rpdev->dev;
	int err = 0;

	if (!rpdev->ept || !rpdev->announce)
		return err;

	dev_dbg(dev, "%s, %s\n", __func__, rpdev->id.name);

	/* need to tell remote processor's name service about this channel ? */
	if (virtio_has_feature(vrp->vdev, VIRTIO_RPMSG_F_NS)) {
		struct rpmsg_ns_msg nsm;

		strncpy(nsm.name, rpdev->id.name, RPMSG_NAME_SIZE);
		nsm.name[RPMSG_NAME_SIZE - 1] = '\0';
		nsm.addr = rpdev->ept->addr;
		nsm.flags = RPMSG_NS_CREATE;

		err = cn_rpmsg_sendto(rpdev->ept, &nsm, sizeof(nsm), RPMSG_NS_ADDR);
		if (err)
			dev_err(dev, "failed to announce ns service %d\n", err);
	}

	/*
	 * need to tell remote processor's address service about the address allocated
	 * to this channel
	 */
	if (virtio_has_feature(vrp->vdev, VIRTIO_RPMSG_F_AS)) {
		struct rpmsg_as_msg asmsg;

		strncpy(asmsg.name, rpdev->id.name, RPMSG_NAME_SIZE);
		asmsg.name[RPMSG_NAME_SIZE - 1] = '\0';
		asmsg.dst = rpdev->src;
		asmsg.src = rpdev->dst;
		asmsg.flags = RPMSG_AS_ASSIGN;

		err = cn_rpmsg_sendto(rpdev->ept, &asmsg, sizeof(asmsg), RPMSG_AS_ADDR);
		if (err)
			dev_err(dev, "failed to announce as service %d\n", err);
	}

	return err;
}

static int virtio_rpmsg_announce_destroy(struct rpmsg_device *rpdev)
{
	struct virtio_rpmsg_channel *vch = to_virtio_rpmsg_channel(rpdev);
	struct virtproc_info *vrp = vch->vrp;
	struct device *dev = &rpdev->dev;
	int err = 0;

	if (!rpdev->ept || !rpdev->announce)
		return err;

	dev_info(dev, "%s, %s\n", __func__, rpdev->id.name);

	/*
	 * need to tell remote processor's address service that we're freeing
	 * the address allocated to this channel
	 */
	if (virtio_has_feature(vrp->vdev, VIRTIO_RPMSG_F_AS)) {
		struct rpmsg_as_msg asmsg;

		strncpy(asmsg.name, rpdev->id.name, RPMSG_NAME_SIZE);
		asmsg.name[RPMSG_NAME_SIZE - 1] = '\0';
		asmsg.dst = rpdev->src;
		asmsg.src = rpdev->dst;
		asmsg.flags = RPMSG_AS_FREE;

		err = cn_rpmsg_sendto(rpdev->ept, &asmsg, sizeof(asmsg), RPMSG_AS_ADDR);
		if (err)
			dev_err(dev, "failed to announce service %d\n", err);
	}

	/* tell remote processor's name service we're removing this channel */
	if (virtio_has_feature(vrp->vdev, VIRTIO_RPMSG_F_NS)) {
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

static const struct rpmsg_device_ops virtio_rpmsg_ops = {
	.create_ept = virtio_rpmsg_create_ept,
	.announce_create = virtio_rpmsg_announce_create,
	.announce_destroy = virtio_rpmsg_announce_destroy,
};

static void virtio_rpmsg_release_device(struct device *dev)
{
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);
	struct virtio_rpmsg_channel *vch = to_virtio_rpmsg_channel(rpdev);

	dev_info(dev, "%s: %s.%d.%d\n", __func__, rpdev->id.name, rpdev->src, rpdev->dst);

	kfree(vch);
}

/*
 * create an rpmsg channel using its name and address info.
 * this function will be used to create both static and dynamic
 * channels.
 */
static struct rpmsg_device *rpmsg_create_channel(struct virtproc_info *vrp,
						 struct rpmsg_channel_info *chinfo,
						 bool announce)
{
	struct virtio_rpmsg_channel *vch;
	struct rpmsg_device *rpdev;
	struct device *tmp, *dev = &vrp->vdev->dev;
	int ret;

	dev_info(dev, "%s, channel %s, src(%d), dst(%d), announce(%d), desc:%s\n",
		__func__, chinfo->name, chinfo->src, chinfo->dst, announce, chinfo->desc);

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
	rpdev->ops = &virtio_rpmsg_ops;

	/*
	 * rpmsg server channels has predefined local address (for now),
	 * and their existence needs to be announced remotely
	 */
	if (rpdev->src != RPMSG_ADDR_ANY || announce)
		rpdev->announce = true;

	strncpy(rpdev->id.name, chinfo->name, RPMSG_NAME_SIZE);
	rpdev->id.name[RPMSG_NAME_SIZE - 1] = '\0';
	strncpy(rpdev->desc, chinfo->desc, RPMSG_NAME_SIZE);
	rpdev->desc[RPMSG_NAME_SIZE - 1] = '\0';

	rpdev->dev.parent = &vrp->vdev->dev;
	rpdev->dev.release = virtio_rpmsg_release_device;
	ret = cn_rpmsg_register_device(rpdev);
	if (ret)
		return NULL;

	return rpdev;
}

/* cambricon add */
static struct virtproc_info *g_vrp;
int cn_rpmsg_destroy_channel(struct rpmsg_device *rpdev)
{
	int ret;
	struct virtio_rpmsg_channel *vch = to_virtio_rpmsg_channel(rpdev);
	struct virtproc_info *vrp = vch->vrp;
	struct rpmsg_channel_info chinfo = {};

	strncpy(chinfo.name, rpdev->id.name, RPMSG_NAME_SIZE);
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = rpdev->src;
	chinfo.dst = rpdev->dst;
	chinfo.desc[0] = '\0';

	ret = cn_rpmsg_unregister_device(&vrp->vdev->dev, &chinfo);
	if (ret)
		dev_err(&vrp->vdev->dev, "rpmsg_destroy_channel:%s failed: %d\n", chinfo.name, ret);
	return ret;
}
extern void *cambr_rproc_get_virtio_device(void *core);

struct rpmsg_device *cn_rpmsg_create_channel(void *core, struct rpmsg_channel_info *chinfo)
{
	struct virtio_device *vdev = cambr_rproc_get_virtio_device(core);
	struct virtproc_info *vrp = vdev ? vdev->priv : NULL;

	if (!vrp) {
		pr_err("virtproc_info NULL in %s, channel %s, src(%d), dst(%d)\n",
				__func__, chinfo->name, chinfo->src, chinfo->dst);
		return NULL;
	}

	return rpmsg_create_channel(vrp, chinfo, false);
}

struct rpmsg_device *ipcm_open_channel(void *core, char *channel_name)
{
	struct rpmsg_device *rpdev = NULL;
	struct virtio_device *vdev = cambr_rproc_get_virtio_device(core);
	struct device *tmp, *dev;
	struct rpmsg_channel_info chinfo = {};
	struct virtproc_info *vrp = vdev ? vdev->priv : NULL;
	int retry = 10;//need large while in ZEBU

	if (!vrp) {
		pr_err("virtproc_info NULL in %s, channel %s\n", __func__, channel_name);
		return NULL;
	}

	strncpy(chinfo.name, channel_name, sizeof(chinfo.name));
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = RPMSG_ADDR_ANY;
	chinfo.dst = RPMSG_ADDR_ANY;
	chinfo.desc[0] = '\0';

	dev = &vrp->vdev->dev;
	do {
		tmp = cn_rpmsg_find_device(dev, &chinfo);
		if (tmp) {
			/* decrement the matched device's refcount back */
			put_device(tmp);
			rpdev = to_rpmsg_device(tmp);
			break;
		}

		/* wait vhost announce create */
		usleep_range(100000, 200000);
	} while (retry--);

	if (!rpdev)
		dev_err(dev, "%s, channel %s fail!\n", __func__, chinfo.name);

	return rpdev;
}

/*
 * create a kernel channel (with default ept)
 * to communicate to a ept create in userspace.
 */
struct rpmsg_device *ipcm_open_user_channel(void *core, char *channel_name, u32 dst)
{
	struct rpmsg_channel_info chinfo = {};

	strncpy(chinfo.name, channel_name, sizeof(chinfo.name));
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = RPMSG_ADDR_ANY;
	chinfo.dst = dst;
	strncpy(chinfo.desc, "rpmsg-ipcm", sizeof(chinfo.desc));

	return cn_rpmsg_create_channel(core, &chinfo);
}

int ipcm_destroy_channel(struct rpmsg_device *rpdev)
{
	return cn_rpmsg_destroy_channel(rpdev);
}

/* for test only, use the latest vrp */
struct rpmsg_device *__ipcm_open_channel(char *channel_name)
{
	struct rpmsg_device *rpdev = NULL;
	struct device *tmp, *dev;
	struct rpmsg_channel_info chinfo = {};
	struct virtproc_info *vrp = g_vrp;

	if (!vrp) {
		pr_err("virtproc_info NULL in %s, channel %s\n", __func__, channel_name);
		return NULL;
	}

	strncpy(chinfo.name, channel_name, sizeof(chinfo.name));
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = RPMSG_ADDR_ANY;
	chinfo.dst = RPMSG_ADDR_ANY;
	chinfo.desc[0] = '\0';

	dev = &vrp->vdev->dev;
	tmp = cn_rpmsg_find_device(dev, &chinfo);
	if (tmp) {
		/* decrement the matched device's refcount back */
		put_device(tmp);
		rpdev = to_rpmsg_device(tmp);
	} else {
		dev_err(dev, "%s, channel %s fail!\n", __func__, chinfo.name);
	}

	return rpdev;
}

/* ipcm internal helper */
static struct rpmsg_device *_ipcm_open_user_channel(struct virtproc_info *vrp, char *channel_name, u32 dst)
{
	struct rpmsg_channel_info chinfo = {};

	if (!vrp) {
		pr_err("virtproc_info NULL in %s, channel %s, dst %d\n", __func__, channel_name, dst);
		return NULL;
	}

	strncpy(chinfo.name, channel_name, sizeof(chinfo.name));
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = RPMSG_ADDR_ANY;
	chinfo.dst = dst;
	strncpy(chinfo.desc, "rpmsg-ipcm", sizeof(chinfo.desc));

	return rpmsg_create_channel(vrp, &chinfo, false);
}

/* for test only, use the latest vrp */
struct rpmsg_device *__ipcm_open_user_channel(char *channel_name, u32 dst)
{
	return _ipcm_open_user_channel(g_vrp, channel_name, dst);
}

/*
 * server announce_create, client will setup the channel local,
 * then client announce ack with his addr,
 * server receive ack to update his dst as client's addr
 */
bool ipcm_channel_ready(struct rpmsg_device *rpdev)
{
	return rpdev->dst != RPMSG_ADDR_ANY;
}

static int rpmsg_create_chrdev(struct virtproc_info *vrp)
{
	struct virtio_rpmsg_channel *vch;
	struct rpmsg_device *rpdev;
	struct device *dev = &vrp->vdev->dev;

	dev_dbg(dev, "%s\n", __func__);

	vch = kzalloc(sizeof(*vch), GFP_KERNEL);
	if (!vch)
		return -ENOMEM;

	/* Link the channel to our vrp */
	vch->vrp = vrp;

	/* Assign public information to the rpmsg_device */
	rpdev = &vch->rpdev;
	rpdev->ops = &virtio_rpmsg_ops;
	//rpdev->src = RPMSG_ADDR_ANY;
	//rpdev->dst = RPMSG_ADDR_ANY;

	rpdev->dev.parent = &vrp->vdev->dev;
	rpdev->dev.release = virtio_rpmsg_release_device;
	return rpmsg_chrdev_register_device(rpdev);
}
/* cambricon end */

/* super simple buffer "allocator" that is just enough for now */
static void *get_a_tx_buf(struct virtproc_info *vrp)
{
	unsigned int len;
	void *ret;

	/* support multiple concurrent senders */
	spin_lock(&vrp->tx_lock);

	/*
	 * either pick the next unused tx buffer
	 * (half of our buffers are used for sending messages)
	 */
	if (vrp->last_sbuf < vrp->num_bufs / 2)
		ret = vrp->sbufs + vrp->buf_size * vrp->last_sbuf++;
	/* or recycle a used one */
	else
		ret = virtqueue_get_buf(vrp->svq, &len);

	virtio_mmiowb(vrp->vdev);
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
		virtqueue_enable_cb(vrp->svq);

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
		virtqueue_disable_cb(vrp->svq);

	spin_unlock(&vrp->tx_lock);
}

static int rpmsg_dump_dfx(struct virtproc_info *vrp)
{
	struct vring_virtqueue *vvq;
	struct virtqueue *vq;
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
			vq = vrp->rvq;
			dev_info(dev, "===================== rvq =====================\n");
		} else {
			vq = vrp->svq;
			dev_info(dev, "===================== svq =====================\n");
		}
		vvq = to_vvq(vq);
		if (!vvq->packed_ring) {
			vring = &vvq->split.vring;

			dev_info(dev, "interrupts: %ld\n", vq->intr_cnt);
			dev_info(dev, "messages: %ld\n", vq->msg_cnt);
			//dev_info(dev, "use_dma_api: %d\n", vvq->use_dma_api);
			//dev_info(dev, "weak_barriers: %d\n", vvq->weak_barriers);
			dev_info(dev, "broken: %d\n", vvq->broken);
			//dev_info(dev, "indirect: %d\n", vvq->indirect);
			dev_info(dev, "event: %d\n", vvq->event);
			dev_info(dev, "free_head: %d\n", vvq->free_head);
			dev_info(dev, "num_added: %d\n", vvq->num_added);
			dev_info(dev, "last_used_idx: %d\n", vvq->last_used_idx);

			dev_info(dev, "avail_flags_shadow: %d\n", vvq->split.avail_flags_shadow);
			dev_info(dev, "avail_idx_shadow: %d\n", vvq->split.avail_idx_shadow);
			//dev_info(dev, "queue_dma_addr: 0x%pad\n", &vvq->split.queue_dma_addr);
			//dev_info(dev, "queue_size_in_bytes: %zu\n", vvq->split.queue_size_in_bytes);

			dev_info(dev, "vring_used_event: %d\n",	vring_used_event(vring));
			dev_info(dev, "vring_avail_event: %d\n", vring_avail_event(vring));

			dev_info(dev, "used: flags %d,  idx %d\n",
							vring->used->flags, vring->used->idx);
			dev_info(dev, "avail: flags %d,  idx %d\n",
							vring->avail->flags, vring->avail->idx);
		}
	}

	dev_info(dev, "==================== endpoints ====================\n");
	mutex_lock(&vrp->endpoints_lock);
	idr_for_each_entry(&vrp->endpoints, ept, id) {
		struct rpmsg_device *rpdev = ept->rpdev;

		dev_info(&vrp->vdev->dev, "ept[%d]: addr(%d).\n", id, ept->addr);
		/* NS AS ept have no rpdev */
		if (rpdev) {
			dev_info(&vrp->vdev->dev, "    belongs to rpdev %px: %s.%d.%d, rpc status: %d, cb_max_time: %d us\n",
				rpdev, rpdev->id.name,
				rpdev->src, rpdev->dst, atomic_read(&rpdev->rpc_flag), ept->cb_max_time);
		}
	}
	mutex_unlock(&vrp->endpoints_lock);
	return 0;
}

int ipcm_dump_dfx(struct virtio_device *vdev)
{
	struct virtproc_info *vrp;

	if (!vdev)
		return -EINVAL;

	vrp = vdev->priv;
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
	struct virtio_rpmsg_channel *vch = to_virtio_rpmsg_channel(rpdev);
	struct virtproc_info *vrp = vch->vrp;
	struct device *dev = &rpdev->dev;
	struct scatterlist sg;
	struct rpmsg_hdr *msg;
	int err;

	if (unlikely(rpdev->reset_flag)) {
		dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
		/* compat commu */
		return -2;
	}
	if (unlikely(!vrp->vdev->vf_start)) {
		dev_err_ratelimited(dev, "!vf_start\n");
		return -ENODEV;
	}

	/* bcasting isn't allowed */
	if (src == RPMSG_ADDR_ANY || dst == RPMSG_ADDR_ANY) {
		dev_err(dev, "invalid addr (src 0x%x, dst 0x%x)\n", src, dst);
		return -EINVAL;
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
	msg = get_a_tx_buf(vrp);
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
						(msg = get_a_tx_buf(vrp)),
						msecs_to_jiffies(RPMSG_TX_INTERVAL_MS));
			i += RPMSG_TX_INTERVAL_MS;
		} while (!err && i < RPMSG_TX_TIMEOUT_MS && !rpdev->reset_flag);

		if (unlikely(rpdev->reset_flag)) {
			dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
			/* compat commu */
			return -2;
		}

		/* disable "tx-complete" interrupts if we're the last sleeper */
		rpmsg_downref_sleepers(vrp);

		/* timeout ? */
		if (!err) {
			dev_err(dev, "timeout waiting for a tx buffer\n");
			RPMSG_DUMP_ONCE(vrp);
			return -ETIMEDOUT;
		} else if (err == -ERESTARTSYS) {
			dev_info_ratelimited(dev, "fatal signal received when wait tx buffer.\n");
			return err;
		}
	}

	if (unlikely(ipcm_record)) {
		perf_host_kva[ipcm_record_index].get_tx_buf_ns
			= get_host_timestamp_by_clockid(CLOCK_MONOTONIC_RAW);
	}

	msg->len = len;
	msg->flags = 0;
	msg->src = src;
	msg->dst = dst;
	msg->reserved = 0;
	memcpy_toio(msg->data, data, len);
	virtio_barrier(vrp->vdev);

	dev_dbg(dev, "TX From 0x%x, To 0x%x, Len %d, Flags %d, Reserved %d\n",
		msg->src, msg->dst, msg->len, msg->flags, msg->reserved);
#if defined(CONFIG_DYNAMIC_DEBUG)
	dynamic_hex_dump("rpmsg_virtio TX: ", DUMP_PREFIX_NONE, 16, 1,
			 msg, sizeof(*msg) + msg->len, true);
#endif

	rpmsg_sg_init(vrp, &sg, msg, sizeof(*msg) + len, DATA_DIR_OUT);

	spin_lock(&vrp->tx_lock);

	/* add message to the remote processor's virtqueue */
	err = virtqueue_add_outbuf(vrp->svq, &sg, 1, msg, GFP_ATOMIC);
	if (err) {
		/*
		 * need to reclaim the buffer here, otherwise it's lost
		 * (memory won't leak, but rpmsg won't use it again for TX).
		 * this will wait for a buffer management overhaul.
		 */
		dev_err(dev, "virtqueue_add_outbuf failed: %d\n", err);
		goto out;
	}

	vrp->svq->msg_cnt++;

	/* tell the remote processor it has a pending message to read */
	virtqueue_kick(vrp->svq);
	virtio_mmiowb(vrp->vdev);

out:
	spin_unlock(&vrp->tx_lock);

	if (unlikely(ipcm_record)) {
		perf_host_kva[ipcm_record_index].kick_mbox_ns
			= get_host_timestamp_by_clockid(CLOCK_MONOTONIC_RAW);
	}

	return err;
}

static int virtio_rpmsg_send(struct rpmsg_endpoint *ept, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr, dst = rpdev->dst;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int virtio_rpmsg_sendto(struct rpmsg_endpoint *ept, void *data, int len,
			       u32 dst)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int virtio_rpmsg_send_offchannel(struct rpmsg_endpoint *ept, u32 src,
					u32 dst, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int virtio_rpmsg_trysend(struct rpmsg_endpoint *ept, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr, dst = rpdev->dst;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

static int virtio_rpmsg_trysendto(struct rpmsg_endpoint *ept, void *data,
				  int len, u32 dst)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

static int virtio_rpmsg_trysend_offchannel(struct rpmsg_endpoint *ept, u32 src,
					   u32 dst, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

static int rpmsg_recv_single(struct virtproc_info *vrp, struct device *dev,
			     struct rpmsg_hdr *msg, unsigned int len)
{
	struct rpmsg_endpoint *ept;
	struct scatterlist sg;
	int err;

	if (unlikely(ipcm_record)) {
		perf_host_kva[ipcm_record_index].recv_buf_ns
			= get_host_timestamp_by_clockid(CLOCK_MONOTONIC_RAW);
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
		mutex_lock_nested(&ept->cb_lock, ept->cb_lockdep_class);

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

		if (unlikely(ipcm_record)) {
			perf_host_kva[ipcm_record_index].ept_cb_end_ns
				= get_host_timestamp_by_clockid(CLOCK_MONOTONIC_RAW);
		}

		/* farewell, ept, we don't need you anymore */
		kref_put(&ept->refcount, __ept_release);
	} else
		dev_warn(dev, "msg received with no recipient(%d -> %d)\n", msg->src, msg->dst);

	/* publish the real size of the buffer */
	rpmsg_sg_init(vrp, &sg, msg, vrp->buf_size, DATA_DIR_IN);

	/* add the buffer back to the remote processor's virtqueue */
	err = virtqueue_add_inbuf(vrp->rvq, &sg, 1, msg, GFP_ATOMIC);
	if (err < 0) {
		dev_err(dev, "failed to add a virtqueue buffer: %d\n", err);
		return err;
	}

	vrp->rvq->msg_cnt++;

	return 0;
}

/* called when an rx buffer is used, and it's time to digest a message */
static void rpmsg_recv_done(struct virtqueue *rvq)
{
	struct virtproc_info *vrp = rvq->vdev->priv;
	struct device *dev = &rvq->vdev->dev;
	struct rpmsg_hdr *msg;
	unsigned int len, msgs_received = 0;
	int err;

	msg = virtqueue_get_buf(rvq, &len);
	if (!msg) {
		dev_dbg(dev, "uhm, incoming signal, but no used buffer ?\n");
		return;
	}

	virtqueue_disable_cb(rvq);
	while (msg) {
		err = rpmsg_recv_single(vrp, dev, msg, len);
		if (err)
			break;

		msgs_received++;

		msg = virtqueue_get_buf(rvq, &len);
	}
	virtqueue_enable_cb(rvq);

	/*
	 * Try to read message one more time in case a new message is submitted
	 * after virtqueue_get_buf() inside the while loop but before enabling
	 * callbacks
	 */
	msg = virtqueue_get_buf(rvq, &len);
	if (msg) {
		err = rpmsg_recv_single(vrp, dev, msg, len);
		if (!err)
			msgs_received++;
	}

	dev_dbg(dev, "Received %u messages\n", msgs_received);

	/* tell the remote processor we added another available rx buffer */
	if (msgs_received)
		virtqueue_kick(vrp->rvq);
}

/*
 * This is invoked whenever the remote processor completed processing
 * a TX msg we just sent it, and the buffer is put back to the used ring.
 *
 * Normally, though, we suppress this "tx complete" interrupt in order to
 * avoid the incurred overhead.
 */
static void rpmsg_xmit_done(struct virtqueue *svq)
{
	struct virtproc_info *vrp = svq->vdev->priv;

	dev_dbg(&svq->vdev->dev, "%s\n", __func__);

	/* wake up potential senders that are waiting for a tx buffer */
	wake_up_interruptible(&vrp->sendq);
}

/* invoked when a name service announcement arrives */
static int rpmsg_ns_cb(struct rpmsg_device *rpdev, void *data, int len,
		       void *priv, u32 src)
{
	struct rpmsg_ns_msg *msg = data;
	struct rpmsg_ns_msg_ext *msg_ext = data;
	struct rpmsg_device *newch;
	struct rpmsg_channel_info chinfo;
	struct virtproc_info *vrp = priv;
	struct device *dev = &vrp->vdev->dev;
	int ret;

#if defined(CONFIG_DYNAMIC_DEBUG)
	dynamic_hex_dump("NS announcement: ", DUMP_PREFIX_NONE, 16, 1,
			 data, len, true);
#endif

	if (len == sizeof(*msg)) {
		chinfo.desc[0] = '\0';
	} else if (len == sizeof(*msg_ext)) {
		strncpy(chinfo.desc, msg_ext->desc, sizeof(chinfo.desc));
		chinfo.desc[RPMSG_NAME_SIZE -1] = '\0';
	} else {
		dev_err(dev, "malformed ns msg (%d)\n", len);
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

	dev_dbg(dev, "%sing channel %s addr 0x%x\n",
		 msg->flags & RPMSG_NS_DESTROY ? "destroy" : "creat",
		 msg->name, msg->addr);

	strncpy(chinfo.name, msg->name, sizeof(chinfo.name));
	chinfo.name[RPMSG_NAME_SIZE - 1] = '\0';
	chinfo.src = RPMSG_ADDR_ANY;
	chinfo.dst = msg->addr;

	if (msg->flags & RPMSG_NS_DESTROY) {
		ret = cn_rpmsg_unregister_device(&vrp->vdev->dev, &chinfo);
		if (ret)
			dev_err(dev, "rpmsg_destroy_channel failed: %d\n", ret);
	} else {
		if (msg->addr < RPMSG_RESERVED_ADDRESSES)
			chinfo.src = msg->addr;//make src = dst
		newch = rpmsg_create_channel(vrp, &chinfo, msg->flags & RPMSG_AS_ANNOUNCE);
		if (!newch)
			dev_err(dev, "rpmsg_create_channel failed\n");
	}

	return 0;
}

/* cambricon */
#ifdef IN_CNDRV_HOST
int virtio_rpmsg_query_endpoint(struct rpmsg_device *rpdev, int addr)
{
	struct virtio_rpmsg_channel *vch = to_virtio_rpmsg_channel(rpdev);
	struct virtproc_info *vrp = vch->vrp;
	struct rpmsg_endpoint *ept = NULL;

	mutex_lock(&vrp->endpoints_lock);
	ept = idr_find(&vrp->endpoints, addr);
	mutex_unlock(&vrp->endpoints_lock);

	if (ept)
		return ept->tgid;
	return -ENXIO;
}
#endif

#ifdef CALLBACK_IN_INTR_CONTEXT
struct ns_msg_data {
	struct rpmsg_device *rpdev;
	void *data;
	int len;
	void *priv;
	u32 src;
	struct list_head list;
};

static int rpmsg_ns_cb_pre(struct rpmsg_device *rpdev, void *data, int len,
		       void *priv, u32 src)
{
	struct ns_msg_data *msg_data;
	struct virtproc_info *vrp = priv;
	struct device *dev = &vrp->vdev->dev;

	msg_data = kzalloc(sizeof(struct ns_msg_data), GFP_NOWAIT);
	if (!msg_data) {
		dev_err(dev, "%s NOMEM\n", __func__);
		return -ENOMEM;
	}

	msg_data->data = kmemdup(data, len, GFP_NOWAIT);
	if (!msg_data->data) {
		dev_err(dev, "%s NOMEM\n", __func__);
		kfree(msg_data);
		return -ENOMEM;
	}

	msg_data->priv = priv;
	msg_data->rpdev = rpdev;
	msg_data->len = len;
	msg_data->src = src;

	spin_lock(&vrp->ns_lock);
	list_add(&msg_data->list, &vrp->ns_msgs);
	spin_unlock(&vrp->ns_lock);

	schedule_work(&vrp->ns_work);
	return 0;
}
static void rpmsg_ns_cb_work(struct work_struct *work)
{
	struct virtproc_info *vrp =	container_of(work, struct virtproc_info, ns_work);
	struct ns_msg_data *msg_data, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&vrp->ns_lock, flags);
	list_for_each_entry_safe(msg_data, tmp, &vrp->ns_msgs, list) {
		spin_unlock_irqrestore(&vrp->ns_lock, flags);
		rpmsg_ns_cb(msg_data->rpdev, msg_data->data, msg_data->len, msg_data->priv, msg_data->src);
		spin_lock_irqsave(&vrp->ns_lock, flags);
		list_del(&msg_data->list);
		kfree(msg_data->data);
		kfree(msg_data);
	}
	spin_unlock_irqrestore(&vrp->ns_lock, flags);

}
#endif

static ssize_t endpoints_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct virtio_device *vdev = dev_to_virtio(dev);
	struct virtproc_info *vrp = vdev->priv;
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

/* cambricon end */
static int rpmsg_probe(struct virtio_device *vdev)
{
	vq_callback_t *vq_cbs[] = { rpmsg_recv_done, rpmsg_xmit_done };
	static const char * const names[] = { "input", "output" };
	struct virtqueue *vqs[2];
	struct virtproc_info *vrp;
	void *bufs_va;
	int err = 0, i;
	size_t total_buf_space;
	bool notify;
	/*cambricon*/
	phys_addr_t tx_pa, rx_pa;
	unsigned long tx_va, rx_va;
	void *bufs_va_ob = NULL;

	dev_info(&vdev->dev, "%s, %d\n", __func__, __LINE__);
	vrp = kzalloc(sizeof(*vrp), GFP_KERNEL);
	if (!vrp)
		return -ENOMEM;

	vrp->vdev = vdev;

	idr_init(&vrp->endpoints);
	mutex_init(&vrp->endpoints_lock);
	spin_lock_init(&vrp->tx_lock);
	init_waitqueue_head(&vrp->sendq);

	/* We expect two virtqueues, rx and tx (and in this order) */
	err = virtio_find_vqs(vdev, 2, vqs, vq_cbs, names, NULL);
	if (err)
		goto free_vrp;

	vrp->rvq = vqs[0];
	vrp->svq = vqs[1];

	/* we expect symmetric tx/rx vrings */
	WARN_ON(virtqueue_get_vring_size(vrp->rvq) !=
		virtqueue_get_vring_size(vrp->svq));

	/* we need less buffers if vrings are small */
	if (virtqueue_get_vring_size(vrp->rvq) < MAX_RPMSG_NUM_BUFS / 2)
		vrp->num_bufs = virtqueue_get_vring_size(vrp->rvq) * 2;
	else
		vrp->num_bufs = MAX_RPMSG_NUM_BUFS;

	vrp->buf_size = MAX_RPMSG_BUF_SIZE;

	total_buf_space = vrp->num_bufs * vrp->buf_size;

	dev_info(&vdev->dev, "num_bufs:%u buf_size:%u total_buf_space:%zu\n",
				vrp->num_bufs, vrp->buf_size, total_buf_space);

	/* see more in rproc_add_virtio_dev() Associate reserved memory to vdev device */
	#if !defined(RPMSG_MASTER_PCIE_RC)
	/* allocate coherent memory for the buffers */
	bufs_va = dma_alloc_coherent(vdev->dev.parent,
				     total_buf_space, &vrp->bufs_dma,
				     GFP_KERNEL);
	if (!bufs_va) {
		err = -ENOMEM;
		goto vqs_del;
	}

	dev_info(&vdev->dev, "using dma_alloc_coherent(): va %px, dma %pad\n",
		bufs_va, &vrp->bufs_dma);
	#else
	bufs_va = cambr_gen_pool_dma_alloc(vdev->buffer_pool, total_buf_space, &vrp->bufs_dma);
	dev_info(&vdev->dev, "using cambricon genpool: va %px, dma %pad\n",
		bufs_va, &vrp->bufs_dma);
	if (!bufs_va) {
		err = -ENOMEM;
		goto vqs_del;
	}
	#endif
	if (virtio_get_outbound(vdev)) {
		bufs_va_ob = cambr_gen_pool_dma_alloc(vdev->OB_pool, total_buf_space/2, &vrp->bufs_dma_ob);
		dev_info(&vdev->dev, "using cambricon genpool: va %px, dma %pad\n",
			bufs_va_ob, &vrp->bufs_dma_ob);
		if (!bufs_va_ob) {
			err = -ENOMEM;
			goto free_coherent;
		}
	}

	/* half of the buffers is dedicated for RX */
	vrp->rbufs = bufs_va;

	/* and half is dedicated for TX */
	vrp->sbufs = bufs_va + total_buf_space / 2;

	/* cambricon */
	rx_pa = (phys_addr_t)vrp->bufs_dma;
	tx_pa = (phys_addr_t)vrp->bufs_dma + total_buf_space / 2;
	rx_va = (unsigned long)vrp->rbufs;
	tx_va = (unsigned long)vrp->sbufs;
	if (virtio_get_outbound(vdev)) {
		vrp->rbufs_ob = bufs_va_ob;
		rx_pa = (phys_addr_t)vrp->bufs_dma_ob;
		rx_va = (unsigned long)vrp->rbufs_ob;
	}

	/* set up the receive buffers */
	for (i = 0; i < vrp->num_bufs / 2; i++) {
		struct scatterlist sg;
		void *cpu_addr;

		if (virtio_get_outbound(vdev))
			cpu_addr = vrp->rbufs_ob + i * vrp->buf_size;
		else
			cpu_addr = vrp->rbufs + i * vrp->buf_size;

		rpmsg_sg_init(vrp, &sg, cpu_addr, vrp->buf_size, DATA_DIR_IN);

		err = virtqueue_add_inbuf(vrp->rvq, &sg, 1, cpu_addr,
					  GFP_KERNEL);
		WARN_ON(err); /* sanity check; this can't really happen */
	}

	/* cambricon */
	vrp->rvq->intr_cnt = 0;
	vrp->svq->intr_cnt = 0;
	vrp->rvq->msg_cnt = 0;
	vrp->svq->msg_cnt = 0;
	/* both pf_vf default is true */
	vdev->vf_start = true;


	/* suppress "tx-complete" interrupts */
	virtqueue_disable_cb(vrp->svq);

	vdev->priv = vrp;

	/* if supported by the remote processor, enable the name service */
	if (virtio_has_feature(vdev, VIRTIO_RPMSG_F_NS)) {
		/* a dedicated endpoint handles the name service msgs */
		#ifdef CALLBACK_IN_INTR_CONTEXT
		INIT_LIST_HEAD(&vrp->ns_msgs);
		spin_lock_init(&vrp->ns_lock);
		INIT_WORK(&vrp->ns_work, rpmsg_ns_cb_work);
		vrp->ns_ept = __rpmsg_create_ept(vrp, NULL, rpmsg_ns_cb_pre,
						vrp, RPMSG_NS_ADDR);
		#else
		vrp->ns_ept = __rpmsg_create_ept(vrp, NULL, rpmsg_ns_cb,
						vrp, RPMSG_NS_ADDR);
		#endif
		if (!vrp->ns_ept) {
			dev_err(&vdev->dev, "failed to create the ns ept\n");
			err = -ENOMEM;
			goto free_genpool;
		}
	}

	/*
	 * Prepare to kick but don't notify yet - we can't do this before
	 * device is ready.
	 */
	notify = virtqueue_kick_prepare(vrp->rvq);

	/* From this point on, we can notify and get callbacks. */
	virtio_device_ready(vdev);

	/* tell the remote processor it can start sending messages */
	/*
	 * this might be concurrent with callbacks, but we are only
	 * doing notify, not a full kick here, so that's ok.
	 */
	if (notify)
		virtqueue_notify(vrp->rvq);

	/* cambricon */
	g_vrp = vrp;

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

	_ipcm_open_user_channel(vrp, "ipcm_file", IPCM_DAEMON_PORT);
	_ipcm_open_user_channel(vrp, "ipcm_cmd", IPCM_DAEMON_PORT);

	dev_info(&vdev->dev, "rpmsg is online\n");

	return 0;

remove_sysfs:
	sysfs_remove_file(&vdev->dev.kobj, &dev_attr_endpoints.attr);

free_genpool:
	if (virtio_get_outbound(vdev))
		cambr_gen_pool_dma_free(vdev->OB_pool, total_buf_space/2,
				(unsigned long)bufs_va_ob);
free_coherent:
#if !defined(RPMSG_MASTER_PCIE_RC)
	dma_free_coherent(vdev->dev.parent, total_buf_space,
			  bufs_va, vrp->bufs_dma);
#else
	cambr_gen_pool_dma_free(vdev->buffer_pool, total_buf_space,
			(unsigned long)bufs_va);
#endif

vqs_del:
	vdev->config->del_vqs(vrp->vdev);
free_vrp:
	kfree(vrp);
	return err;
}

static int rpmsg_remove_device(struct device *dev, void *data)
{
	dev_info(dev, "%s, %d\n", __func__, __LINE__);

	device_unregister(dev);

	return 0;
}

static void rpmsg_remove(struct virtio_device *vdev)
{
	struct virtproc_info *vrp = vdev->priv;
	size_t total_buf_space = vrp->num_bufs * vrp->buf_size;
	int ret;

	dev_info(&vdev->dev, "%s, %d\n", __func__, __LINE__);

	vdev->config->reset(vdev);

	ret = device_for_each_child(&vdev->dev, NULL, rpmsg_remove_device);
	if (ret)
		dev_warn(&vdev->dev, "can't remove rpmsg device: %d\n", ret);

	/* cambricon */
	sysfs_remove_file(&vdev->dev.kobj, &dev_attr_endpoints.attr);

	if (vrp->ns_ept)
		__rpmsg_destroy_ept(vrp, vrp->ns_ept);

	idr_destroy(&vrp->endpoints);

	vdev->config->del_vqs(vrp->vdev);
#if !defined(RPMSG_MASTER_PCIE_RC)
	dma_free_coherent(vdev->dev.parent, total_buf_space,
			  vrp->rbufs, vrp->bufs_dma);
#else
	cambr_gen_pool_dma_free(vdev->buffer_pool, total_buf_space,
			(unsigned long)vrp->rbufs);
#endif
	if (virtio_get_outbound(vdev)) {
		cambr_gen_pool_dma_free(vdev->OB_pool, total_buf_space/2,
				(unsigned long)vrp->rbufs_ob);
	}
	kfree(vrp);
	g_vrp = NULL;
	vdev->priv = NULL;
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_RPMSG, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_RPMSG_F_NS,
	VIRTIO_RPMSG_F_AS,
};

static struct virtio_driver virtio_ipc_driver = {
	.feature_table	= features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name	= "cn_virtio_ipc",
	.driver.owner	= THIS_MODULE,
	.id_table	= id_table,
	.probe		= rpmsg_probe,
	.remove		= rpmsg_remove,
};

int virtio_rpmsg_init(void)
{
	int ret;

	pr_info("%s, %d\n", __func__, __LINE__);
	ret = register_virtio_driver(&virtio_ipc_driver);
	if (ret)
		pr_err("failed to register virtio driver: %d\n", ret);

	return ret;
}

void virtio_rpmsg_fini(void)
{
	unregister_virtio_driver(&virtio_ipc_driver);
}

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio-based remote processor messaging bus");
MODULE_LICENSE("GPL v2");
