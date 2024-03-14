/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_MM_COMPAT_H__
#define __CAMBRICON_MM_COMPAT_H__
#include <linux/radix-tree.h>

/** compatible interfaces for mapinfo rbtree ops  **/
void insert_mapinfo(struct cn_mm_priv_data *mm_priv_data,
					struct mapinfo *minfo);
void delete_mapinfo(struct cn_mm_priv_data *mm_priv_data,
					struct mapinfo *minfo);
struct mapinfo *search_mapinfo(struct cn_mm_priv_data *mm_priv_data,
							dev_addr_t virt_addr);
struct mapinfo *search_mapinfo_with_func(struct file *fp,
				struct cn_mm_set *mm_set, dev_addr_t vaddr, size_t size,
				int (func)(struct mapinfo *, dev_addr_t, size_t));
struct mapinfo *search_mapinfo_with_fp(struct file *fp, dev_addr_t vaddr,
					   struct cn_mm_set *mm_set);

/** compatible interfaces for mm_priv_data lock ops  **/
#define DEFINE_UDVM_LOCK(name, type) \
	type *__get_##name##_lock_with_mmpriv(struct cn_mm_priv_data *mm_priv_data, dev_addr_t vaddr); \
	type *__get_##name##_lock_with_mapinfo(struct mapinfo *minfo); \
	type *__get_##name##_lock_with_fp(struct file *fp, dev_addr_t vaddr, struct cn_mm_set *mm_set);


/* NOTE: use lock_with_mapinfo as better, lock_with_mmpriv need make sure
 * mm_priv_data is valid. in some situation, we will get lock with mm_priv_data
 * has already been freed. */
DEFINE_UDVM_LOCK(minfo, spinlock_t)
/* FIXME: uva_lock not need store in mm_priv_data, need optimize in the future */
DEFINE_UDVM_LOCK(uva, struct mutex)

/* NOTE: fix 3.10.693 compile error, not found radix_tree_empty function */
static inline bool cn_radix_tree_empty(struct radix_tree_root *root)
{
#if (KERNEL_VERSION(4, 7, 0) <= LINUX_VERSION_CODE)
	return radix_tree_empty(root);
#else
	return root->rnode == NULL;
#endif
}

#endif /* __CAMBRICON_MM_COMPAT_H__ */
