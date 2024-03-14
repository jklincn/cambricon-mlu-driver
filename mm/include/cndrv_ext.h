#ifndef __CAMBRICON_EXT_H_
#define __CAMBRICON_EXT_H_
#include "camb_iova_allocator.h"

struct extn_phys_priv {
	/* radix_tree used to managed physical handle, index with handle ID */
	struct radix_tree_root ra_root;
	struct list_head list;
	spinlock_t lock;
};

struct extn_priv_data {
	struct extn_phys_priv phys;
};

#ifdef CONFIG_CNDRV_EDGE
int camb_free_vma_list(struct mapinfo *pminfo);
int camb_unmap_uva(user_addr_t uva, __u64 size, int cached);
int camb_vma_is_uva(struct vm_area_struct *vma);
int camb_copy_sg_table(struct sg_table *dst_table, struct sg_table *src_table);
int camb_pminfo_sg_table_set(struct mapinfo *pminfo, void *mem_set);
void camb_unmap_kva(struct mapinfo *pminfo);

int extn_minfo_release(struct mapinfo *pminfo);
void camb_mem_extn_priv_release(struct extn_priv_data *extn_priv);
int camb_mem_extn_priv_init(struct extn_priv_data **pextn_priv);
int camb_import_extn_mem(u64 tag, unsigned int fd, u64 size, unsigned long *handle, struct cn_mm_set *mm_set);
int camb_map_extn_mem(u64 tag, unsigned long handle, unsigned long size,
		unsigned long offset, unsigned int flag, dev_addr_t *iova);
int camb_destroy_extn_mem(u64 tag, unsigned long handle);
#else
static inline int camb_free_vma_list(struct mapinfo *pminfo)
{
	return 0;
}
static inline int camb_unmap_uva(user_addr_t uva, __u64 size, int cached)
{
	return 0;
}
static inline int camb_vma_is_uva(struct vm_area_struct *vma)
{
	return 0;
}
static inline int camb_copy_sg_table(struct sg_table *dst_table, struct sg_table *src_table)
{
	return 0;
}
static inline int camb_pminfo_sg_table_set(struct mapinfo *pminfo, void *mem_set)
{
	return 0;
}

static inline void camb_unmap_kva(struct mapinfo *pminfo)
{
}
static inline int extn_minfo_release(struct mapinfo *pminfo)
{
	return 0;
}
static inline void camb_mem_extn_priv_release(struct extn_priv_data *extn_priv)
{
}
static inline int camb_mem_extn_priv_init(struct extn_priv_data **pextn_priv)
{
	return 0;
}
static inline int camb_import_extn_mem(u64 tag, unsigned int fd, u64 size, unsigned long *handle, struct cn_mm_set *mm_set)
{
	return 0;
}
static inline int camb_map_extn_mem(u64 tag, unsigned long handle, unsigned long size,
		unsigned long offset, unsigned int flag, dev_addr_t *iova)
{
	return 0;
}
static inline int camb_destroy_extn_mem(u64 tag, unsigned long handle)
{
	return 0;
}
#endif
#endif
