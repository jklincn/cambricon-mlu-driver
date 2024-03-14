// SPDX-License-Identifier: GPL-2.0-only
/*
 * Remote processor messaging transport (OMAP platform-specific bits)
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 * Copyright (C) 2011 Google, Inc.
 *
 * Ohad Ben-Cohen <ohad@wizery.com>
 * Brian Swetland <swetland@google.com>
 */

#include <linux/version.h>
#include <linux/dma-mapping.h>
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
#include <linux/dma-map-ops.h>
#endif
#include <linux/export.h>
#include "../include/uapi/linux/virtio_ring.h"
#include "../include/remoteproc/remoteproc.h"
#include "../include/vhost/vhost.h"
#include "../include/uapi/linux/virtio_ids.h"
#include <linux/err.h>
#include <linux/kref.h>
#include <linux/slab.h>

#include "remoteproc_internal.h"

#include <linux/of_reserved_mem.h>

/* rproc_vhost_write - Write data to buffer provided by remote virtio driver
 * @vdev: Vhost device that communicates with remove virtio device
 * @dst: Buffer address present in the memory of the remote system to which
 *   data should be written
 * @src: Buffer address in the local device provided by the vhost client driver
 * @len: Length of the data to be copied from @src to @dst
 *
 * Write data to buffer provided by remote virtio driver from buffer provided
 * by vhost client driver.
 */
static int rproc_vhost_write(struct vhost_dev *vdev, u64 dst, void *src, int len)
{
	int ret = 0;

	memcpy_toio((void *)dst, src, len);

	return ret;
}

/* rproc_vhost_read - Read data from buffer provided by remote virtio driver
 * @vdev: Vhost device that communicates with remove virtio device
 * @dst: Buffer address in the local device provided by the vhost client driver
 * @src: Buffer address in the remote device provided by the remote virtio
 *   driver
 * @len: Length of the data to be copied from @src to @dst
 *
 * Read data from buffer provided by remote virtio driver to address provided
 * by vhost client driver.
 */
static int rproc_vhost_read(struct vhost_dev *vdev, void *dst, u64 src, int len)
{
	int ret = 0;

	memcpy_fromio(dst, (void *)src, len);

	return ret;
}

/* rproc_vhost_notify - Send notification to the remote virtqueue
 * @vq: The local vhost virtqueue corresponding to the remote virtio virtqueue
 *
 * Use endpoint core framework to raise MSI-X interrupt to notify the remote
 * virtqueue.
 */
static void  rproc_vhost_notify(struct vhost_virtqueue *vq)
{
	struct rproc_vring *rvring = vhost_vq_get_backend(vq);
	struct rproc *rproc = rvring->rvdev->rproc;
	int notifyid = rvring->notifyid;

	dev_dbg(&rproc->dev, "kicking vq index: %d\n", notifyid);

	rproc->ops->kick(rproc, notifyid);
}

/**
 * rproc_vq_interrupt() - tell remoteproc that a virtqueue is interrupted
 * @rproc: handle to the remote processor
 * @notifyid: index of the signalled virtqueue (unique per this @rproc)
 *
 * This function should be called by the platform-specific rproc driver,
 * when the remote processor signals that a specific virtqueue has pending
 * messages available.
 *
 * Returns IRQ_NONE if no message was found in the @notifyid virtqueue,
 * and otherwise returns IRQ_HANDLED.
 */
irqreturn_t rproc_vq_interrupt(struct rproc *rproc, int notifyid)
{
	struct rproc_vring *rvring;

	dev_dbg(&rproc->dev, "vq index %d is interrupted\n", notifyid);

	rvring = idr_find(&rproc->notifyids, notifyid);
	if (!rvring || !rvring->vq)
		return IRQ_NONE;

	rvring->vq->intr_cnt++;
	vhost_virtqueue_callback(rvring->vq);
	return IRQ_HANDLED;
}

/* rproc_vhost_reset_vqs - reset all the vqs associated with the vhost device
 * @vdev: Vhost device that communicates with remove virtio device
 *
 * reset all the vqs associated with the vhost device.
 * It may use while VF restart
 */
void rproc_vhost_reset_vqs(struct vhost_dev *vdev)
{
	struct vhost_virtqueue *vq;
	struct vringh *vrh;
	int i;

	for (i = 0; i < vdev->nvqs; i++) {
		vq = vdev->vqs[i];
		if (IS_ERR_OR_NULL(vq))
			continue;
		vrh = &vq->vringh;
		vrh->completed = 0;
		vrh->last_avail_idx = 0;
		vrh->last_used_idx = 0;
	}
}

/* rproc_vhost_del_vqs - Delete all the vqs associated with the vhost device
 * @vdev: Vhost device that communicates with remove virtio device
 *
 * Delete all the vqs associated with the vhost device and free the memory
 * address reserved for accessing the remote virtqueue.
 */
static void rproc_vhost_del_vqs(struct vhost_dev *vdev)
{
	struct vhost_virtqueue *vq;
	struct rproc_vring *rvring;
	int i;

	for (i = 0; i < vdev->nvqs; i++) {
		vq = vdev->vqs[i];
		if (IS_ERR_OR_NULL(vq))
			continue;
		rvring = vhost_vq_get_backend(vq);
		rvring->vq = NULL;
		kfree(vq);
	}
	kfree(vdev->vqs);
	vdev->vqs = NULL;
	vdev->nvqs = 0;
}

/* rproc_vhost_create_vq - Create a new vhost virtqueue
 * @vdev: Vhost device that communicates with remove virtio device
 * @index: Index of the vhost virtqueue
 * @num_bufs: The number of buffers that should be supported by the vhost
 *   virtqueue (number of descriptors in the vhost virtqueue)
 * @callback: Callback function associated with the virtqueue
 *
 * Create a new vhost virtqueue which can be used by the vhost client driver
 * to access the remote virtio. This sets up the local address of the vhost
 * virtqueue but shouldn't be accessed until the virtio sets the status to
 * VIRTIO_CONFIG_S_DRIVER_OK.
 */
static struct vhost_virtqueue *
rproc_vhost_create_vq(struct vhost_dev *vdev, int index,
			unsigned int num_bufs,
			void (*callback)(struct vhost_virtqueue *))
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct rproc *rproc = vdev_to_rproc(vdev);
	struct device *dev = &rproc->dev;
	struct rproc_mem_entry *mem;
	struct rproc_vring *rvring;
	struct vhost_virtqueue *vq;
	struct vringh *vringh;
	void __iomem *vq_addr;
	struct vring *vring;
	int ret;

	/* we're temporarily limited to two virtqueues per rvdev */
	if (index >= ARRAY_SIZE(rvdev->vring))
		return ERR_PTR(-EINVAL);

	vq = kzalloc(sizeof(*vq), GFP_KERNEL);
	if (!vq)
		return ERR_PTR(-ENOMEM);

	vq->dev = vdev;
	vq->callback = callback;
	vq->num = num_bufs;
	vq->notify = rproc_vhost_notify;
	vq->type = VHOST_TYPE_MMIO;

	vringh = &vq->vringh;
	vring = &vringh->vring;

	/* Search allocated memory region by name */
	/* put all vrings to outbound if QUIRK_AVOID_VF_READ_INBOUND */
	if (rproc_get_outbound(rproc) && rproc_is_vf(rproc)
			&& (rproc_get_quirks(rproc) & QUIRK_AVOID_VF_READ_INBOUND)) {
		mem = rproc_find_carveout_by_name(rproc, "vdev%dvring%d_OB", rproc_get_rvdev_index(rproc),
					  index);
	} else {
		/* put vring0 to outbound if !QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND */
		if (rproc_get_outbound(rproc)
				&& !(rproc_get_quirks(rproc) & QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND)
				&& (index == 0))
			mem = rproc_find_carveout_by_name(rproc, "vdev%dvring%d_OB", rproc_get_rvdev_index(rproc),
					  index);
		else
			mem = rproc_find_carveout_by_name(rproc, "vdev%dvring%d", rproc_get_rvdev_index(rproc),
					  index);
	}
	if (!mem || !mem->va) {
		ret = -ENOMEM;
		goto out;
	}

	rvring = &rvdev->vring[index];
	vq_addr = mem->va;

	dev_dbg(dev, "vring%d: va %px qsz %d notifyid %d\n",
		index, vq_addr, num_bufs, rvring->notifyid);

	vring_init(vring, num_bufs, vq_addr, rvring->align);

	if (rproc_get_outbound(rproc)
			&& !(rproc_is_vf(rproc)	&& (rproc_get_quirks(rproc) & QUIRK_AVOID_VF_READ_INBOUND))
			&& (rproc_get_quirks(rproc) & QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND)
			&& (index == 0)) {
		/* vring0 still in inbound, but put vring->used in outbound like vdev0buffer_OB, to keep order */
		mem = rproc_find_carveout_by_name(rproc, "vdev%dvring%d_OB", rproc_get_rvdev_index(rproc),
					index);
		if (!mem || !mem->va) {
			ret = -ENOMEM;
			goto out;
		}

		vring_update_used_addr(vring, mem->va);
	}

	ret = vringh_init_mmio(vringh, 0, num_bufs, false, vring->desc,
			       vring->avail, vring->used);
	if (ret) {
		dev_err(dev, "Failed to init vringh\n");
		goto out;
	}

	rvring->vq = vq;
	vhost_vq_set_backend(vq, rvring);

	return vq;

out:
	kfree(vq);

	return ERR_PTR(ret);
}

/* rproc_vhost_create_vqs - Create vhost virtqueues for vhost device
 * @vdev: Vhost device that communicates with the remote virtio device
 * @nvqs: Number of vhost virtqueues to be created
 * @num_bufs: The number of buffers that should be supported by the vhost
 *   virtqueue (number of descriptors in the vhost virtqueue)
 * @vqs: Pointers to all the created vhost virtqueues
 * @callback: Callback function associated with the virtqueue
 * @names: Names associated with each virtqueue
 *
 * Create vhost virtqueues for vhost device. This acts as a wrapper to
 * rproc_vhost_create_vq() which creates individual vhost virtqueue.
 */
static int rproc_vhost_create_vqs(struct vhost_dev *vdev, unsigned int nvqs,
				    unsigned int num_bufs,
				    struct vhost_virtqueue *vqs[],
				    vhost_vq_callback_t *callbacks[],
				    const char * const names[])
{
	struct rproc *rproc = vdev_to_rproc(vdev);
	struct device *dev = &rproc->dev;
	int ret, i;

	for (i = 0; i < nvqs; i++) {
		vqs[i] = rproc_vhost_create_vq(vdev, i, num_bufs,
						 callbacks[i]);
		if (IS_ERR_OR_NULL(vqs[i])) {
			ret = PTR_ERR(vqs[i]);
			dev_err(dev, "Failed to create virtqueue\n");
			goto err;
		}
	}

	vdev->nvqs = nvqs;
	vdev->vqs = kmemdup(&vqs[0], sizeof(struct vhost_virtqueue *) * nvqs, GFP_KERNEL);

	return 0;

err:
	rproc_vhost_del_vqs(vdev);
	return ret;
}

/* rproc_vhost_set_features - vhost_config_ops to set vhost device features
 * @vdev: Vhost device that communicates with the remote virtio device
 * @features: Features supported by the vhost client driver
 *
 * vhost_config_ops invoked by the vhost client driver to set vhost device
 * features.
 */
static int rproc_vhost_set_features(struct vhost_dev *vdev, u64 features)
{
	vdev->features = features;

	return 0;
}

/* rproc_vhost_set_status - vhost_config_ops to set vhost device status
 * @vdev: Vhost device that communicates with the remote virtio device
 * @status: Vhost device status configured by vhost client driver
 *
 * vhost_config_ops invoked by the vhost client driver to set vhost device
 * status.
 */
static int rproc_vhost_set_status(struct vhost_dev *vdev, u8 status)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct fw_rsc_vdev *rsc;

	rsc = (void *)rvdev->rproc->table_ptr + rvdev->rsc_offset;

	rsc->status = status;
	dev_info(&vdev->dev, "status: %d\n", status);

	return 0;
}

/* rproc_vhost_get_status - vhost_config_ops to get vhost device status
 * @vdev: Vhost device that communicates with the remote virtio device
 *
 * vhost_config_ops invoked by the vhost client driver to get vhost device
 * status set by the remote virtio driver.
 */
static u8 rproc_vhost_get_status(struct vhost_dev *vdev)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct fw_rsc_vdev *rsc;

	rsc = (void *)rvdev->rproc->table_ptr + rvdev->rsc_offset;

	return rsc->status;
}

static const struct vhost_config_ops rproc_vhost_config_ops = {
	.create_vqs	= rproc_vhost_create_vqs,
	.del_vqs	= rproc_vhost_del_vqs,
	.reset_vqs  = rproc_vhost_reset_vqs,
	.write		= rproc_vhost_write,
	.read		= rproc_vhost_read,
	.set_features	= rproc_vhost_set_features,
	.set_status	= rproc_vhost_set_status,
	.get_status	= rproc_vhost_get_status,
};

/* rproc_vhost_release_dev - Callback function to free device
 * @dev: Device in vhost_dev that has to be freed
 *
 * Callback function from device core invoked to free the device after
 * all references have been removed. This frees the allocated memory for
 * struct ntb_vhost.
 */
static void rproc_vhost_release_dev(struct device *dev)
{
	struct vhost_dev *vdev = to_vhost_dev(dev);
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct rproc *rproc = vdev_to_rproc(vdev);

	dev_info(dev, "%s: %s\n", __func__, rproc->name);

	kfree(vdev);

	kref_put(&rvdev->refcount, rproc_vdev_release);

	put_device(&rproc->dev);
}

/* rproc_add_vhost_dev - Register a vhost device
 * @rvdev: the remote vdev
 * @id: the device type identification (used to match it with a driver).
 *
 * Invoked vhost_register_device() to register a vhost device after populating
 * the deviceID and vendorID of the vhost device.
 */
int rproc_add_vhost_dev(struct rproc_vdev *rvdev, int id)
{
	struct rproc *rproc = rvdev->rproc;
	struct vhost_dev *vdev;
	struct device *dev = &rvdev->dev;
	struct rproc_mem_entry *mem;
	int ret;

	if (rproc->ops->kick == NULL) {
		ret = -EINVAL;
		dev_err(dev, ".kick method not defined for %s\n", rproc->name);
		goto out;
	}

	/* Try to find dedicated vdev buffer carveout */
	mem = rproc_find_carveout_by_name(rproc, "vdev%dbuffer", rproc_get_rvdev_index(rproc));
	if (mem) {
		phys_addr_t pa;

		if (mem->of_resm_idx != -1) {
			struct device_node *np = rproc->dev.parent->of_node;

			/* Associate reserved memory to vdev device */
			ret = of_reserved_mem_device_init_by_idx(dev, np,
								 mem->of_resm_idx);
			if (ret) {
				dev_err(dev, "Can't associate reserved memory\n");
				goto out;
			}
		} else {
			if (mem->va) {
				dev_dbg(dev, "vdev %d buffer already mapped\n",
					 rvdev->index);
				pa = rproc_va_to_pa(rproc, mem->va);
				dev_dbg(dev, "vdev %d pa:0x%llx  va:0x%lx\n",
					 rvdev->index, pa, (unsigned long)mem->va);
			} else {
				/* Use dma address as carveout no memmapped yet */
				pa = (phys_addr_t)mem->dma;
			}

			/* Associate vdev buffer memory pool to vdev subdev */
			#if (KERNEL_VERSION(5, 1, 0) <= LINUX_VERSION_CODE)
			ret = dma_declare_coherent_memory(dev, pa,
							   mem->da,
							   mem->len);
			#else
			ret = dma_declare_coherent_memory(dev, pa,
							   mem->da,
							   mem->len, DMA_MEMORY_EXCLUSIVE);
			#endif
			if (ret < 0) {
				dev_err(dev, "Failed to associate buffer\n");
				goto out;
			}
		}
	} else {
		struct device_node *np = rproc->dev.parent->of_node;

		/*
		 * If we don't have dedicated buffer, just attempt to re-assign
		 * the reserved memory from our parent. A default memory-region
		 * at index 0 from the parent's memory-regions is assigned for
		 * the rvdev dev to allocate from. Failure is non-critical and
		 * the allocations will fall back to global pools, so don't
		 * check return value either.
		 */
		of_reserved_mem_device_init_by_idx(dev, np, 0);
		dev_warn(dev, "Failed to find vdev%dbuffer\n", rproc_get_rvdev_index(rproc));
	}

	/* Allocate virtio device */
	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev) {
		ret = -ENOMEM;
		goto out;
	}

	vdev->dev.parent = dev;
	vdev->dev.release = rproc_vhost_release_dev;
	vdev->id.device = id;
	vdev->ops = &rproc_vhost_config_ops;

	mutex_init(&vdev->mutex);

	/* cambricon */
	rproc->vdev = vdev;
	vdev->outbound = rproc_get_outbound(rproc);

	if (rproc_get_outbound(rproc)) {
		struct rproc_mem_entry *ob_mem;

		ob_mem = rproc_find_carveout_by_name(rproc, "vdev%dbuffer_OB", rproc_get_rvdev_index(rproc));
		if (ob_mem) {
			vdev->OB_pool = cambr_gen_pool_create((unsigned long)ob_mem->va,
										ob_mem->da, ob_mem->len);
		} else {
			dev_err(dev, "%s, can't find vdev%dbuffer_OB!\n", __func__, rproc_get_rvdev_index(rproc));
			ret = -EINVAL;
			goto out;
		}
	}

	/*
	 * We're indirectly making a non-temporary copy of the rproc pointer
	 * here, because drivers probed with this vdev will indirectly
	 * access the wrapping rproc.
	 *
	 * Therefore we must increment the rproc refcount here, and decrement
	 * it _only_ when the vdev is released.
	 */
	get_device(&rproc->dev);

	/* Reference the vdev and vring allocations */
	kref_get(&rvdev->refcount);

	ret = vhost_register_device(vdev);
	if (ret) {
		dev_err(dev, "Failed to register vhost device\n");
		return ret;
	}

	return 0;

out:
	return ret;
}

/* rproc_remove_vhost_dev - Inbind callback to cleanup the PCIe EP controller
 * @dev: the vhost device
 * @data: must be null
 *
 * This will unregister vhost device
 */
int rproc_remove_vhost_dev(struct device *dev, void *data)
{
	struct vhost_dev *vdev = to_vhost_dev(dev);

	dev_info(dev, "%s\n", __func__);

	if (device_is_registered(&vdev->dev))
		vhost_unregister_device(vdev);

	/* cambricon */
	if (vdev->outbound) {
		if (vdev->OB_pool)
			cambr_gen_pool_destroy(vdev->OB_pool);
		vdev->OB_pool = NULL;
	}

	return 0;
}
