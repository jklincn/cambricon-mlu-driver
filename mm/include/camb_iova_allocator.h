#ifndef __CAMBRICON_VMM_IOVA_ALLOCATOR_H_
#define __CAMBRICON_VMM_IOVA_ALLOCATOR_H_
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/rbtree.h>
#include "cndrv_mm.h"

#define GENERIC_IOVA_BASE (VMM_IOVA_BASE + VMM_IOVA_SIZE)
#define GENERIC_IOVA_SIZE (0x1UL << 40)
#define GENERIC_MINIMUM_SHIFT (16)
#define EXTN_MINIMUM_SHIFT (16)
#define OB_MINIMUM_SHIFT (16)

struct camb_iova_pool {
	dev_addr_t base;
	size_t total_size;
	unsigned int shift;
	void *allocator;
};

/* TODO: add iova process rcache node */
struct camb_iova_node {
	struct rb_node node;
	unsigned long pfn_hi;
	unsigned long pfn_lo;
};

struct camb_iova_domain {
	spinlock_t  iova_rbtree_lock;
	struct rb_root rbroot;

	struct rb_node *cached_node;
	struct camb_iova_node anchor;
	unsigned long granule;
	unsigned long start_pfn;
	unsigned long end_pfn;
};

static inline unsigned long camb_iova_size(struct camb_iova_node *iova)
{
	return iova->pfn_hi - iova->pfn_lo + 1;
}

static inline unsigned long camb_iova_align(struct camb_iova_domain *iovad, unsigned long size)
{
	return ALIGN(size, iovad->granule);
}

static inline unsigned long camb_iova_shift(struct camb_iova_domain *iovad)
{
	return __ffs(iovad->granule);
}

static inline dev_addr_t
camb_iova_addr(struct camb_iova_domain *iovad, struct camb_iova_node *iova)
{
	return (dev_addr_t)iova->pfn_lo << camb_iova_shift(iovad);
}

static inline unsigned long
camb_iova_pfn(struct camb_iova_domain *iovad, dev_addr_t iova)
{
	return iova >> camb_iova_shift(iovad);
}

void camb_create_iova_allocator(struct camb_iova_domain *iovad,
		unsigned long start_pfn, unsigned long end_pfn, unsigned long granule);
dev_addr_t
camb_alloc_iova(struct camb_iova_domain *iovad, dev_addr_t start,
		unsigned long size, unsigned long align);
void camb_free_iova(struct camb_iova_domain *iovad, dev_addr_t vaddr);
void camb_destroy_iova_allocator(struct camb_iova_domain *iovad);
int camb_generic_iova_init(struct camb_iova_pool *pool);
void camb_generic_iova_exit(struct camb_iova_pool *iova_pool);
#endif /* __CAMBRICON_VMM_IOVA_ALLOCATOR_H_ */
