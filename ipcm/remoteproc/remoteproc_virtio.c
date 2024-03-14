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
#include <linux/export.h>
#include <linux/err.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include "../include/remoteproc/remoteproc.h"
#include "../include/virtio/virtio.h"
#include "../include/virtio/virtio_config.h"
#include "../include/uapi/linux/virtio_ids.h"
#include "../include/virtio/virtio_ring.h"


#include "remoteproc_internal.h"

#if !defined(RPMSG_MASTER_PCIE_RC)
#include <linux/of_reserved_mem.h>
#endif

/* kick the remote processor, and let it know which virtqueue to poke at */
static bool rproc_virtio_notify(struct virtqueue *vq)
{
	struct rproc_vring *rvring = vq->priv;
	struct rproc *rproc = rvring->rvdev->rproc;
	int notifyid = rvring->notifyid;

	dev_dbg(&rproc->dev, "kicking vq index: %d\n", notifyid);

	rproc->ops->kick(rproc, notifyid);
	return true;
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
	return vring_interrupt(0, rvring->vq);
}

static struct virtqueue *rp_find_vq(struct virtio_device *vdev,
				    unsigned int id,
				    void (*callback)(struct virtqueue *vq),
				    const char *name, bool ctx)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct rproc *rproc = vdev_to_rproc(vdev);
	struct device *dev = &rproc->dev;
	struct rproc_mem_entry *mem;
	struct rproc_vring *rvring;
	struct fw_rsc_vdev *rsc;
	struct virtqueue *vq;
	void *addr;
	int len, size;

	/* we're temporarily limited to two virtqueues per rvdev */
	if (id >= ARRAY_SIZE(rvdev->vring))
		return ERR_PTR(-EINVAL);

	if (!name)
		return NULL;

	/* Search allocated memory region by name */
	/* put all vrings to outbound if QUIRK_AVOID_VF_READ_INBOUND */
	if (rproc_get_outbound(rproc) && rproc_is_vf(rproc)
			&& (rproc_get_quirks(rproc) & QUIRK_AVOID_VF_READ_INBOUND)) {
		mem = rproc_find_carveout_by_name(rproc, "vdev%dvring%d_OB", rproc_get_rvdev_index(rproc),
						id);
	} else {
		/* put vring0 to outbound if !QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND */
		if (rproc_get_outbound(rproc)
				&& !(rproc_get_quirks(rproc) & QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND)
				&& (id == 0))
			mem = rproc_find_carveout_by_name(rproc, "vdev%dvring%d_OB", rproc_get_rvdev_index(rproc),
						id);
		else
			mem = rproc_find_carveout_by_name(rproc, "vdev%dvring%d", rproc_get_rvdev_index(rproc),
						id);
	}

	if (!mem || !mem->va)
		return ERR_PTR(-ENOMEM);

	rvring = &rvdev->vring[id];
	addr = mem->va;
	len = rvring->len;

	/* zero vring */
	size = vring_size(len, rvring->align);
	memset_io(addr, 0, size);

	dev_dbg(dev, "%s, vring%d: va %px qsz %d notifyid %d\n", __func__,
		id, addr, len, rvring->notifyid);

	/*
	 * Create the new vq, and tell virtio we're not interested in
	 * the 'weak' smp barriers, since we're talking with a real device.
	 */
	vq = vring_new_virtqueue(id, len, rvring->align, vdev, false, ctx,
				 addr, rproc_virtio_notify, callback, name);
	if (!vq) {
		dev_err(dev, "vring_new_virtqueue %s failed\n", name);
		rproc_free_vring(rvring);
		return ERR_PTR(-ENOMEM);
	}

	if (rproc_get_outbound(rproc)
			&& !(rproc_is_vf(rproc)	&& (rproc_get_quirks(rproc) & QUIRK_AVOID_VF_READ_INBOUND))
			&& (rproc_get_quirks(rproc) & QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND)
			&& (id == 0)) {
		/* vring0 still in inbound, but put vring->used in outbound like vdev0buffer_OB, to keep order */
		mem = rproc_find_carveout_by_name(rproc, "vdev%dvring%d_OB", rproc_get_rvdev_index(rproc),
					id);
		if (!mem || !mem->va) {
			rproc_free_vring(rvring);
			return ERR_PTR(-ENOMEM);
		}

		memset_io(mem->va, 0, size);

		vring_update_used_addr(virtqueue_get_vring(vq), mem->va);
	}

	rvring->vq = vq;
	vq->priv = rvring;

	/* Update vring in resource table */
	rsc = (void *)rproc->table_ptr + rvdev->rsc_offset;
	*((int *)&rsc->vring[id].da) = *((int *)&mem->da);
	*((int *)&rsc->vring[id].da + 1) = *((int *)&mem->da + 1);

	return vq;
}

static void __rproc_virtio_del_vqs(struct virtio_device *vdev)
{
	struct virtqueue *vq, *n;
	struct rproc_vring *rvring;

	list_for_each_entry_safe(vq, n, &vdev->vqs, list) {
		rvring = vq->priv;
		rvring->vq = NULL;
		vring_del_virtqueue(vq);
	}
}

static void rproc_virtio_del_vqs(struct virtio_device *vdev)
{
	__rproc_virtio_del_vqs(vdev);
}

static int rproc_virtio_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
				 struct virtqueue *vqs[],
				 vq_callback_t *callbacks[],
				 const char *const names[],
				 const bool *ctx,
				 struct irq_affinity *desc)
{
	int i, ret, queue_idx = 0;

	for (i = 0; i < nvqs; ++i) {
		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}

		vqs[i] = rp_find_vq(vdev, queue_idx++, callbacks[i], names[i],
				    ctx ? ctx[i] : false);
		if (IS_ERR(vqs[i])) {
			ret = PTR_ERR(vqs[i]);
			goto error;
		}
	}

	return 0;

error:
	__rproc_virtio_del_vqs(vdev);
	return ret;
}

static u8 rproc_virtio_get_status(struct virtio_device *vdev)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct fw_rsc_vdev *rsc;

	rsc = (void *)rvdev->rproc->table_ptr + rvdev->rsc_offset;

	return rsc->status;
}

static void rproc_virtio_set_status(struct virtio_device *vdev, u8 status)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct fw_rsc_vdev *rsc;

	rsc = (void *)rvdev->rproc->table_ptr + rvdev->rsc_offset;

	rsc->status = status;
	dev_info(&vdev->dev, "status: %d\n", status);
}

static void rproc_virtio_reset(struct virtio_device *vdev)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct fw_rsc_vdev *rsc;

	rsc = (void *)rvdev->rproc->table_ptr + rvdev->rsc_offset;

	rsc->status = 0;
	dev_info(&vdev->dev, "reset !\n");
}

/* provide the vdev features as retrieved from the firmware */
static u64 rproc_virtio_get_features(struct virtio_device *vdev)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct fw_rsc_vdev *rsc;

	rsc = (void *)rvdev->rproc->table_ptr + rvdev->rsc_offset;

	return rsc->dfeatures;
}

static void rproc_transport_features(struct virtio_device *vdev)
{
	/*
	 * Packed ring isn't enabled on remoteproc for now,
	 * because remoteproc uses vring_new_virtqueue() which
	 * creates virtio rings on preallocated memory.
	 */
	__virtio_clear_bit(vdev, VIRTIO_F_RING_PACKED);
}

static int rproc_virtio_finalize_features(struct virtio_device *vdev)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct fw_rsc_vdev *rsc;

	rsc = (void *)rvdev->rproc->table_ptr + rvdev->rsc_offset;

	/* Give virtio_ring a chance to accept features */
	vring_transport_features(vdev);

	/* Give virtio_rproc a chance to accept features. */
	rproc_transport_features(vdev);

	/* Make sure we don't have any features > 32 bits! */
	WARN_ON((u32)vdev->features != vdev->features);

	/*
	 * Remember the finalized features of our vdev, and provide it
	 * to the remote processor once it is powered on.
	 */
	rsc->gfeatures = vdev->features;

	return 0;
}

static void rproc_virtio_get(struct virtio_device *vdev, unsigned int offset,
			     void *buf, unsigned int len)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct fw_rsc_vdev *rsc;
	void *cfg;

	rsc = (void *)rvdev->rproc->table_ptr + rvdev->rsc_offset;
	cfg = &rsc->vring[rsc->num_of_vrings];

	if (offset + len > rsc->config_len || offset + len < len) {
		dev_err(&vdev->dev, "%s: access out of bounds\n", __func__);
		return;
	}

	memcpy(buf, cfg + offset, len);
}

static void rproc_virtio_set(struct virtio_device *vdev, unsigned int offset,
			     const void *buf, unsigned int len)
{
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct fw_rsc_vdev *rsc;
	void *cfg;

	rsc = (void *)rvdev->rproc->table_ptr + rvdev->rsc_offset;
	cfg = &rsc->vring[rsc->num_of_vrings];

	if (offset + len > rsc->config_len || offset + len < len) {
		dev_err(&vdev->dev, "%s: access out of bounds\n", __func__);
		return;
	}

	memcpy(cfg + offset, buf, len);
}

static const struct virtio_config_ops rproc_virtio_config_ops = {
	.get_features	= rproc_virtio_get_features,
	.finalize_features = rproc_virtio_finalize_features,
	.find_vqs	= rproc_virtio_find_vqs,
	.del_vqs	= rproc_virtio_del_vqs,
	.reset		= rproc_virtio_reset,
	.set_status	= rproc_virtio_set_status,
	.get_status	= rproc_virtio_get_status,
	.get		= rproc_virtio_get,
	.set		= rproc_virtio_set,
};

/*
 * This function is called whenever vdev is released, and is responsible
 * to decrement the remote processor's refcount which was taken when vdev was
 * added.
 *
 * Never call this function directly; it will be called by the driver
 * core when needed.
 */
static void rproc_virtio_dev_release(struct device *dev)
{
	struct virtio_device *vdev = dev_to_virtio(dev);
	struct rproc_vdev *rvdev = vdev_to_rvdev(vdev);
	struct rproc *rproc = vdev_to_rproc(vdev);

	dev_info(dev, "%s: %s\n", __func__, rproc->name);

	kfree(vdev);

	kref_put(&rvdev->refcount, rproc_vdev_release);

	put_device(&rproc->dev);
}

/**
 * rproc_add_virtio_dev() - register an rproc-induced virtio device
 * @rvdev: the remote vdev
 * @id: the device type identification (used to match it with a driver).
 *
 * This function registers a virtio device. This vdev's partent is
 * the rproc device.
 *
 * Returns 0 on success or an appropriate error value otherwise.
 */
int rproc_add_virtio_dev(struct rproc_vdev *rvdev, int id)
{
	struct rproc *rproc = rvdev->rproc;
	struct device *dev = &rvdev->dev;
	struct virtio_device *vdev;
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
			#if defined(RPMSG_MASTER_PCIE_RC)
			ret = -EINVAL;
			dev_err(dev, "Can't associate reserved memory, host SHOULD rproc_mem_entry_init() instead of rproc_of_resm_mem_entry_init()\n");
			goto out;
			#else
			struct device_node *np = rproc->dev.parent->of_node;

			/* Associate reserved memory to vdev device */
			ret = of_reserved_mem_device_init_by_idx(dev, np,
								 mem->of_resm_idx);
			if (ret) {
				dev_err(dev, "Can't associate reserved memory\n");
				goto out;
			}
			#endif
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
			/*
			 * while RPMSG_MASTER_PCIE_RC we are pcie shm, cross OS/DDR,
			 * can't associate host pa to device side's address(da/dpa),
			 * because host pa can't mapping to right host va.
			 * dma_declare_coherent_memory() like
			 * of_reserved_mem_device_init_by_idx()-->reserved_mem_ops->device_init->rmem_dma_device_init
			 * -->dma_init_coherent_memory()
			 * -->dma_assigned_coherent_memory()
			 * will make rpmsg_probe()-->dma_alloc_coherent() alloc from this vdev0buffer,
			 * if not present, we will use genpool
			 */
			#if !defined(RPMSG_MASTER_PCIE_RC)
			#if (KERNEL_VERSION(5, 1, 0) <= LINUX_VERSION_CODE)
			/* Associate vdev buffer memory pool to vdev subdev */
			ret = dma_declare_coherent_memory(dev, pa,
							   mem->da,
							   mem->len);
			#else
			ret = dma_declare_coherent_memory(dev, pa,
							   mem->da,
							   mem->len, DMA_MEMORY_EXCLUSIVE);
			#endif
			if (ret < 0) {
				dev_err(dev, "Failed to associate buffer\n");//occur -38
				goto out;
			}
			#else
			//use genpool, see below
			#endif
		}
	} else {
		#if !defined(RPMSG_MASTER_PCIE_RC)
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
		#endif
		dev_warn(dev, "Failed to find vdev%dbuffer\n", rproc_get_rvdev_index(rproc));
	}

	/* Allocate virtio device */
	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev) {
		ret = -ENOMEM;
		goto out;
	}
	vdev->id.device	= id,
	vdev->config = &rproc_virtio_config_ops,
	vdev->dev.parent = dev;
	vdev->dev.release = rproc_virtio_dev_release;

	/* cambricon hack */
	rproc->vdev = vdev;
	vdev->outbound = rproc_get_outbound(rproc);
	#if defined(RPMSG_MASTER_PCIE_RC)
	if (mem) {
		vdev->buffer_pool = cambr_gen_pool_create((unsigned long)mem->va,
									mem->da, mem->len);
	} else {
		dev_err(dev, "%s, %d, can't find vdev0buffer!\n", __func__, __LINE__);
		ret = -EINVAL;
		goto out;
	}
	#endif

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

	ret = register_virtio_device(vdev);
	if (ret) {
		put_device(&vdev->dev);
		dev_err(dev, "failed to register vdev: %d\n", ret);
		goto out;
	}

	dev_dbg(dev, "registered %s (type %d)\n", dev_name(&vdev->dev), id);

out:
	return ret;
}

/**
 * rproc_remove_virtio_dev() - remove an rproc-induced virtio device
 * @dev: the virtio device
 * @data: must be null
 *
 * This function unregisters an existing virtio device.
 */
int rproc_remove_virtio_dev(struct device *dev, void *data)
{
	struct virtio_device *vdev = dev_to_virtio(dev);

	dev_info(dev, "%s\n", __func__);

	unregister_virtio_device(vdev);

	/* cambricon */
	#if defined(RPMSG_MASTER_PCIE_RC)
	dev_dbg(dev, "%s, %d [genpool] destroy.\n", __func__, __LINE__);
	if (vdev->buffer_pool)
		cambr_gen_pool_destroy(vdev->buffer_pool);
	vdev->buffer_pool = NULL;
	if (vdev->outbound) {
		if (vdev->OB_pool)
			cambr_gen_pool_destroy(vdev->OB_pool);
		vdev->OB_pool = NULL;
	}
	#endif

	return 0;
}
