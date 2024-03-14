/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_VMM_H_
#define __CAMBRICON_VMM_H_
#include "camb_range_tree.h"

#define VMM_IOVA_BASE (0x3UL << 46)
#define VMM_IOVA_SIZE (0x1UL << 40)
#define VMM_IOVA_POOL_SHIFT    (29)
#define VMM_MINIMUM_SHIFT (25)
#define IS_VMM_ALIGNED(sz)  \
	(((sz) & ((typeof(sz))(1UL << VMM_MINIMUM_SHIFT) - 1)) == 0)

#define GET_FLAGS(addr, msb, lsb) \
	(((addr) >> (lsb)) & ((1UL << ((msb) - (lsb) + 1)) - 1))

#define SET_FLAGS(type, flags, msb, lsb, val) \
	do { \
		flags &= ~(((1UL << ((msb) - (lsb) + 1)) - 1) << (lsb)); \
		flags |= (type)((val) & ((1UL << ((msb) - (lsb) + 1)) - 1)) << (lsb); \
	} while(0)

enum vmm_struct_valid {
	INVALID = 0x0,
	VALID = 0x1,
};

struct camb_vmm_set {
	/* vmm address reserved genpool */
	dev_addr_t base;
	size_t total_size;
	unsigned int shift;
	void *allocator;
};

struct vmm_phys_priv {
	/* radix_tree used to managed physical handle, index with handle ID */
	struct radix_tree_root ra_root;
	struct list_head list;
	spinlock_t lock;
	struct pid_info_s *pid_infos[MAX_FUNCTION_NUM]; /* used to collect handle process*/
};

struct vmm_iova_priv {
	struct range_tree_t range_tree;
	spinlock_t lock;
};

struct vmm_minfo_priv {
	struct range_tree_t range_tree;
	rwlock_t   node_lock;
	spinlock_t minfo_lock;
	struct mutex uva_lock;
};

struct vmm_priv_data {
	struct vmm_phys_priv phys;
	struct vmm_iova_priv iova;
	struct vmm_minfo_priv minfo;
};

enum handle_flags {
	HANDLE_compress = 0x0,
	HANDLE_shared   = 0x1,
	HANDLE_security = 0x2,
};

struct camb_vmm_handle {
	struct list_head node;
	unsigned long handle;   /* handle id after udvm encode */
	unsigned long size;     /* must aligned with VMM_MINIMUM_SHIFT */
	unsigned int flags;     /* special allcoated flags: bit[0] -- compress type */
	atomic_t     refcnt;    /* refcnt used to protect physical handle validate */
	atomic_t     release_refcnt; /* refcnt for handle validate call cn_mem_release times */
	struct cn_mm_set *mm_set;
	struct vmm_priv_data *vmm_priv;
	u64 tag;
	void *active_ns;
};

#define HANDLE_FLAG(handle, name) \
	GET_FLAGS(((struct camb_vmm_handle *)(handle))->flags, HANDLE_##name, HANDLE_##name)
#define SET_HANDLE_FLAG(handle, name, val) \
	SET_FLAGS(unsigned int, ((struct camb_vmm_handle *)(handle))->flags, HANDLE_##name, HANDLE_##name, val)

struct camb_vmm_iova {
	struct range_tree_node_t node;
	unsigned long align;
	unsigned int counts;
	unsigned long bitmap[0];
};

/* RPC command and its structure */
enum vmm_ctl_cmd {
	VMM_MEM_SUPPORT = 0x0,
	VMM_MEM_CREATE  = 0x1,
	VMM_MEM_RELEASE = 0x2,
	VMM_MEM_MAP     = 0x3,
	VMM_MEM_UNMAP   = 0x4,
	VMM_MEM_HANDLE_GET = 0x5,
};

struct vmm_ctl_t {
	unsigned int cmd;
	union {
		/* used for MemCreate */
		struct mem_attr attr;
		/* used for MemRelease, MemMap, MemUnmap */
		struct {
			unsigned long handle;
			unsigned long iova;
			unsigned long size;
			unsigned int  prot;
		};
	};
};

int cn_vmm_mem_create(u64 tag, unsigned long size, unsigned int flags,
			unsigned long *handle, struct cn_mm_set *mm_set);
int cn_vmm_mem_release(u64 tag, unsigned long handle);
int cn_vmm_mem_address_reserve(u64 tag, unsigned long size, unsigned long align,
			dev_addr_t start, unsigned long flags, dev_addr_t *iova);
int cn_vmm_mem_address_free(u64 tag, dev_addr_t addr, unsigned long size);
int cn_vmm_mem_map(u64 tag, dev_addr_t vaddr, unsigned long size,
			unsigned long offset, unsigned long handle);
int cn_vmm_set_access(u64 tag, dev_addr_t vaddr, unsigned long size,
			unsigned int prot, unsigned int dev_id);
int cn_vmm_mem_unmap(u64 tag, dev_addr_t vaddr, unsigned long size);
int cn_vmm_get_attribute(u64 tag, unsigned long *args, unsigned int nums,
			unsigned int type, unsigned long *data);
int cn_vmm_export_share_handle(u64 tag, unsigned long handle, unsigned int type,
			unsigned int *share_handle);
int cn_vmm_import_share_handle(u64 tag, unsigned int share_handle,
			unsigned int type, unsigned long *handle);

int vmm_minfo_release(struct mapinfo *pminfo);
int camb_mem_vmm_priv_init(struct vmm_priv_data **pvmm_priv);
void camb_mem_vmm_priv_release(struct vmm_priv_data *vmm_priv);
int camb_vmm_support_check(struct cn_mm_set *mm_set);
int camb_vmm_init(struct camb_vmm_set *vmm_set);
void camb_vmm_exit(struct camb_vmm_set *vmm_set);

void insert_vmm_mapinfo(struct vmm_priv_data *vmm_priv, struct mapinfo *minfo);
void delete_vmm_mapinfo(struct vmm_priv_data *vmm_priv, struct mapinfo *minfo);
struct mapinfo *search_vmm_mapinfo(struct vmm_priv_data *vmm_priv, dev_addr_t addr);

int camb_vmm_get_reserved_range(struct mapinfo *pminfo, dev_addr_t *base,
					unsigned long *size);

struct mapinfo *
camb_vmm_minfo_kref_get_range(u64 tag, dev_addr_t vaddr, unsigned long size,
			int (kref_get)(struct mapinfo *, dev_addr_t, size_t ));

unsigned int
camb_vmm_minfo_kref_put_range(struct mapinfo *first, dev_addr_t vaddr,
			unsigned long size, int (release)(struct mapinfo *));
#endif /* __CAMBRICON_VMM_H_ */
