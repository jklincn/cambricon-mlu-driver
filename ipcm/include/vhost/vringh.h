#ifndef _CAMBR_VRINGH_H
#define _CAMBR_VRINGH_H
#include <linux/compiler.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/vringh.h>
#include <linux/virtio_ring.h>

struct mmiovec {
	u64 iov_base;
	size_t iov_len;
};

/**
 * struct vringh_mmiov - mmiovec mangler.
 *
 * Mangles mmiovec in place, and restores it.
 * Remaining data is iov + i, of used - i elements.
 */
struct vringh_mmiov {
	struct mmiovec *iov;
	size_t consumed; /* Within iov[i] */
	unsigned int i, used, max_num;
};

/* Helpers for kernelspace vrings. */
int vringh_init_mmio(struct vringh *vrh, u64 features,
		     unsigned int num, bool weak_barriers,
		     struct vring_desc *desc,
		     struct vring_avail *avail,
		     struct vring_used *used);

static inline void vringh_mmiov_init(struct vringh_mmiov *mmiov,
				     struct mmiovec *mmiovec, unsigned int num)
{
	mmiov->used = 0;
	mmiov->i = 0;
	mmiov->consumed = 0;
	mmiov->max_num = num;
	mmiov->iov = mmiovec;
}

int vringh_getdesc_mmio(struct vringh *vrh,
			struct vringh_mmiov *riov,
			struct vringh_mmiov *wiov,
			u16 *head,
			gfp_t gfp);

int vringh_complete_mmio(struct vringh *vrh, u16 head, u32 len);

bool vringh_notify_enable_mmio(struct vringh *vrh);
void vringh_notify_disable_mmio(struct vringh *vrh);
int vringh_need_notify_mmio(struct vringh *vrh);

#endif /* _CAMBR_VRINGH_H */
