/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#ifndef __CAMBRICON_MM_UDVM_H__
#define __CAMBRICON_MM_UDVM_H__

#include <linux/fdtable.h>
#include <linux/threads.h>
#include "cndrv_pre_compile.h"
#include "cndrv_mm.h"
#include "cndrv_core.h"
#include "camb_vmm.h"
#include "camb_iova_allocator.h"
#include "cndrv_pinned_mm.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif

#define udvm_fget(fd) fget(fd)
#define udvm_fput(file) fput(file)

static inline struct file *udvm_fcheck(unsigned int fd)
{
	struct file *fp = NULL;

	/** NOTE:
	 * fcheck_files will check rcu_read_lock or files->file_lock is held
	 * before call __fcheck_files. so we hold rcu_read_lock before call
	 * fcheck is better!!!
	 **/
	rcu_read_lock();
	fp = cn_fcheck(fd);
	rcu_read_unlock();

	return fp;
}

#define udvm_copy_from_user(user, kernel, len) \
({\
	int __ret = 0;  \
	if (sizeof(typeof(*kernel)) != len) { \
		pr_err("%s[%d] input data size(%#lx) is invalid!\n", __func__, __LINE__, len); \
		__ret = -EINVAL; \
	} else { \
		__ret = copy_from_user((void *)kernel, (void *)user, len); \
		if (__ret) { \
			pr_err("%s[%d] copy_from_user failed!\n", __func__, __LINE__); \
			__ret = -EFAULT; \
		} \
	} \
	__ret; \
})

#define udvm_copy_to_user(user, kernel, len) \
({\
	int __ret = 0;  \
	__ret = copy_to_user((void *)user, (void *)kernel, len); \
	if (__ret) { \
		pr_err("%s[%d] copy_to_user failed!\n", __func__, __LINE__); \
		__ret = -EFAULT; \
	} \
	__ret; \
})

/* defination used for unified device virtual address */
#define UDVM_VIRT_ADDRESS_BITS (64)
#define MLU_VIRT_ADDRESS_BITS  (48)
#define MLU_VIRT_ADDRESS_MASK  ((1ULL << MLU_VIRT_ADDRESS_BITS) - 1)
#define UDVM_TYPE_BITS         (UDVM_VIRT_ADDRESS_BITS - MLU_VIRT_ADDRESS_BITS)
#define UDVM_TYPE_MASK  ((1ULL << UDVM_TYPE_BITS) - 1) << MLU_VIRT_ADDRESS_BITS

#define MLU_VIRT_TYPE_BITS    \
	(UDVM_VIRT_ADDRESS_BITS - MLU_VIRT_ADDRESS_BITS)
#define MLU_VIRT_TYPE_MASK \
	(((1ULL << MLU_VIRT_TYPE_BITS) - 1) << MLU_VIRT_ADDRESS_BITS)

/* MLU DeviceID in virtual address */
#define MLU_CARD_IDX_SHIFT   (MLU_VIRT_ADDRESS_BITS)
#define MLU_CARD_IDX_BITS    (8)
#define MLU_CARD_IDX_MASK    ((1ULL << MLU_CARD_IDX_BITS) - 1)

/* MLU device address magic bits */
#define MLU_ADDRESS_MAGIC_SHIFT (MLU_CARD_IDX_SHIFT + MLU_CARD_IDX_BITS)
#define MLU_ADDRESS_MAGIC_BITS  (8)
#define MLU_ADDRESS_MAGIC_MASK  ((1ULL << MLU_ADDRESS_MAGIC_BITS) - 1)

enum udvm_address_magic {
	UDVM_ADDR_VMM     = 0x1,
	UDVM_ADDR_PUBLIC  = 0x2,
	UDVM_ADDR_DEFAULT = 0x3, /* this is the last enumeration */
};

struct camb_ob_direct_map {
	struct mempool_t	hostpool_l;
	unsigned int align_size_l;
	struct mempool_t	hostpool_h;
	unsigned int align_size_h;
};

struct cn_udvm_set {
	struct list_head udvm_head;
	struct radix_tree_root udvm_raroot;
	spinlock_t udvm_lock;

	struct radix_tree_root udvm_ipc_raroot;
	spinlock_t udvm_ipc_lock;

	struct camb_vmm_set vmm_set;
	struct camb_iova_pool iova_pool;
	struct camb_ob_direct_map *obd_map;
	struct pinned_mem_rb_task *pm_task_root;
	struct pinned_mem_rb_blk *pm_blk_root;
};

struct udvm_ipc_handle {
	union {
		dev_ipc_handle_t udvm_handle;
		struct mapinfo *pminfo;
		unsigned long kva;
	};

	unsigned int flags;
	int memory_type;
	int tgid;
	void *mm_set;
};

struct mlu_priv_data {
	spinlock_t mm_priv_lock;
	struct list_head mm_priv_list;

	struct mutex uva_lock;

	struct rb_root mmroot;
	rwlock_t   node_lock;
	spinlock_t minfo_lock;
	atomic_t isvalid;
};

struct udvm_peer_st {
	int local_card;
	/* which need be increase open_count, if not register in current process */
	int remote_card;
	struct pid_info_s pid_info;
};

struct udvm_priv_data {
	int tgid;
	u64 tag;
	struct list_head unode;

	unsigned int memcheck_magic;
	atomic_long_t udvm_counts;
	atomic_long_t udvm_async_tasks;

	struct mlu_priv_data *mlu_priv[MAX_FUNCTION_NUM];
	struct vmm_priv_data *vmm_priv;
	struct extn_priv_data *extn_priv;
	struct idr peer_idr;
	spinlock_t peer_lock;
	struct mutex mlu_lock;
};

#define udvm_kref_get(x) (atomic_long_inc_not_zero(&(x)->udvm_counts))
#define udvm_empty(x)    (atomic_long_read(&(x)->udvm_counts) == 1)

#define udvm_mlu_priv_must_valid(udvm, index) \
({ \
	BUG_ON(!(udvm)->mlu_priv[index]);\
	(udvm)->mlu_priv[index]; \
})

struct udvm_priv_data *get_udvm_priv_data(struct file *fp);
int udvm_unregister_privdata(void *mm_priv_data);
int udvm_register_async_tasks(void *udvm_priv);
void udvm_unregister_async_tasks(void *udvm_priv);
bool fp_is_udvm(struct file *fp);
int get_index_with_mmset(void *mm_set);
dev_addr_t set_udvm_address(int index, dev_addr_t addr, int type);
int udvm_get_address_magic(dev_addr_t udvm_addr);
bool addr_is_public(dev_addr_t address);
bool addr_is_vmm(dev_addr_t address);
bool addr_is_export(dev_addr_t address);
int udvm_camb_kref_get(struct mapinfo **ppminfo, u64 *ptag, dev_addr_t udvm_addrs, struct cn_mm_set *mm_set,
		int (*camb_kref_get_func)(u64 tag, dev_addr_t device_vaddr, struct mapinfo **ppminfo,
			struct cn_mm_set *mm_set));
int udvm_ipc_handle_release(dev_ipc_handle_t handle);

static int inline __parse_address2index(dev_addr_t udvm_address)
{
#ifdef CONFIG_CNDRV_EDGE
	return 0;
#else
	int index = (udvm_address >> MLU_CARD_IDX_SHIFT) & MLU_CARD_IDX_MASK;
	return index >= MAX_FUNCTION_NUM ? -ENXIO : index;
#endif
}

int udvm_get_memcpy_dir(dev_addr_t src_addr, dev_addr_t dst_addr);
bool udvm_memcpy_dir_check(int dir, int params_dir);

unsigned long udvm_copy_cp_node(void *buf, int idx,
		int *skip, unsigned long size,
		int (*do_copy)(void *, unsigned long, unsigned long, unsigned long));
#endif /* __CAMBRICON_MM_UDVM_H__ */
