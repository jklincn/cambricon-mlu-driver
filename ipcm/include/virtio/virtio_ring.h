/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_RING_H
#define _LINUX_VIRTIO_RING_H

#include <asm/barrier.h>
#include <linux/irqreturn.h>
#include "../uapi/linux/virtio_ring.h"
#include "virtio.h"

//#define DEBUG

struct vring_desc_state_split {
	void *data;			/* Data for callback. */
	struct vring_desc *indir_desc;	/* Indirect descriptor, if any. */
};

struct vring_desc_state_packed {
	void *data;			/* Data for callback. */
	struct vring_packed_desc *indir_desc; /* Indirect descriptor, if any. */
	u16 num;			/* Descriptor list length. */
	u16 next;			/* The next desc state in a list. */
	u16 last;			/* The last desc state in a list. */
};

struct vring_desc_extra_packed {
	dma_addr_t addr;		/* Buffer DMA addr. */
	u32 len;			/* Buffer length. */
	u16 flags;			/* Descriptor flags. */
};

struct vring_virtqueue {
	struct virtqueue vq;

	/* Is this a packed ring? */
	bool packed_ring;

	/* Is DMA API used? */
	bool use_dma_api;

	/* Can we use weak barriers? */
	bool weak_barriers;

	/* Other side has made a mess, don't try any more. */
	bool broken;

	/* Host supports indirect buffers */
	bool indirect;

	/* Host publishes avail event idx */
	bool event;

	/* Head of free buffer list. */
	unsigned int free_head;
	/* Number we've added since last sync. */
	unsigned int num_added;

	/* Last used index we've seen. */
	u16 last_used_idx;

	union {
		/* Available for split ring */
		struct {
			/* Actual memory layout for this queue. */
			struct vring vring;

			/* Last written value to avail->flags */
			u16 avail_flags_shadow;

			/*
			 * Last written value to avail->idx in
			 * guest byte order.
			 */
			u16 avail_idx_shadow;

			/* Per-descriptor state. */
			struct vring_desc_state_split *desc_state;

			/* DMA address and size information */
			dma_addr_t queue_dma_addr;
			size_t queue_size_in_bytes;
		} split;

		/* Available for packed ring */
		struct {
			/* Actual memory layout for this queue. */
			struct {
				unsigned int num;
				struct vring_packed_desc *desc;
				struct vring_packed_desc_event *driver;
				struct vring_packed_desc_event *device;
			} vring;

			/* Driver ring wrap counter. */
			bool avail_wrap_counter;

			/* Device ring wrap counter. */
			bool used_wrap_counter;

			/* Avail used flags. */
			u16 avail_used_flags;

			/* Index of the next avail descriptor. */
			u16 next_avail_idx;

			/*
			 * Last written value to driver->flags in
			 * guest byte order.
			 */
			u16 event_flags_shadow;

			/* Per-descriptor state. */
			struct vring_desc_state_packed *desc_state;
			struct vring_desc_extra_packed *desc_extra;

			/* DMA address and size information */
			dma_addr_t ring_dma_addr;
			dma_addr_t driver_event_dma_addr;
			dma_addr_t device_event_dma_addr;
			size_t ring_size_in_bytes;
			size_t event_size_in_bytes;
		} packed;
	};

	/* How to notify other side. FIXME: commonalize hcalls! */
	bool (*notify)(struct virtqueue *vq);

	/* DMA, allocation, and size information */
	bool we_own_ring;

#ifdef DEBUG
	/* They're supposed to lock for us. */
	unsigned int in_use;

	/* Figure out if their kicks are too delayed. */
	bool last_add_time_valid;
	ktime_t last_add_time;
#endif
};

/* cambricon */
static inline bool vring_get_outbound(const struct vring_virtqueue *vq)
{
	return vq->vq.vdev->outbound;
}

/*
 * Helpers.
 */

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

/*
 * Barriers in virtio are tricky.  Non-SMP virtio guests can't assume
 * they're not on an SMP host system, so they need to assume real
 * barriers.  Non-SMP virtio hosts could skip the barriers, but does
 * anyone care?
 *
 * For virtio_pci on SMP, we don't need to order with respect to MMIO
 * accesses through relaxed memory I/O windows, so virt_mb() et al are
 * sufficient.
 *
 * For using virtio to talk to real devices (eg. other heterogeneous
 * CPUs) we do need real barriers.  In theory, we could be using both
 * kinds of virtio, so it's a runtime decision, and the branch is
 * actually quite cheap.
 */

static inline void virtio_mb(bool weak_barriers)
{
	if (weak_barriers)
		virt_mb();/* barrier */
	else
		mb();/* barrier */
}

static inline void virtio_rmb(bool weak_barriers)
{
	if (weak_barriers)
		virt_rmb();/* barrier */
	else
		rmb();/* barrier */
}

static inline void virtio_wmb(bool weak_barriers)
{
	if (weak_barriers)
		virt_wmb();/* barrier */
	else
		wmb();/* barrier */
}

static inline void virtio_store_mb(bool weak_barriers,
				   __virtio16 *p, __virtio16 v)
{
	if (weak_barriers) {
		virt_store_mb(*p, v);/* barrier */
	} else {
		WRITE_ONCE(*p, v);
		mb();/* barrier */
	}
}

struct virtio_device;
struct virtqueue;

/*
 * Creates a virtqueue and allocates the descriptor ring.  If
 * may_reduce_num is set, then this may allocate a smaller ring than
 * expected.  The caller should query virtqueue_get_vring_size to learn
 * the actual size of the ring.
 */
struct virtqueue *vring_create_virtqueue(unsigned int index,
					 unsigned int num,
					 unsigned int vring_align,
					 struct virtio_device *vdev,
					 bool weak_barriers,
					 bool may_reduce_num,
					 bool ctx,
					 bool (*notify)(struct virtqueue *vq),
					 void (*callback)(struct virtqueue *vq),
					 const char *name);

/* Creates a virtqueue with a custom layout. */
struct virtqueue *__vring_new_virtqueue(unsigned int index,
					struct vring vring,
					struct virtio_device *vdev,
					bool weak_barriers,
					bool ctx,
					bool (*notify)(struct virtqueue *),
					void (*callback)(struct virtqueue *),
					const char *name);

/*
 * Creates a virtqueue with a standard layout but a caller-allocated
 * ring.
 */
struct virtqueue *vring_new_virtqueue(unsigned int index,
				      unsigned int num,
				      unsigned int vring_align,
				      struct virtio_device *vdev,
				      bool weak_barriers,
				      bool ctx,
				      void *pages,
				      bool (*notify)(struct virtqueue *vq),
				      void (*callback)(struct virtqueue *vq),
				      const char *name);

/*
 * Destroys a virtqueue.  If created with vring_create_virtqueue, this
 * also frees the ring.
 */
void vring_del_virtqueue(struct virtqueue *vq);

/* Filter out transport-specific feature bits. */
void vring_transport_features(struct virtio_device *vdev);

irqreturn_t vring_interrupt(int irq, void *_vq);

#endif /* _LINUX_VIRTIO_RING_H */
