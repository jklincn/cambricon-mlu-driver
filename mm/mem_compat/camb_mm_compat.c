/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#include "camb_mm_priv.h"
#include "camb_mm.h"
#include "camb_udvm.h"
#include "camb_vmm.h"
#include "camb_mm_compat.h"
#include "cndrv_udvm.h"

/**
 * NOTE: this file is used to compat old version driverAPI which is not
 * support Cambricon UDVM. all resource and variables are managed by
 * mm_priv_data!!!
 **/
static bool
__is_udvm_enabled(struct mapinfo *minfo)
{
	if (minfo->udvm_priv == NULL)
		return false;
	return true;
}

static int
__get_index_minfo(struct mapinfo *minfo)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)minfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	return core->idx;
}

#define REGISTER_UDVM_LOCK(name, type, member) \
type *__get_##name##_lock_with_mmpriv(struct cn_mm_priv_data *mm_priv_data, dev_addr_t vaddr) \
{ \
	WARN(!mm_priv_data, "must make sure input parameters is valid"); \
	if (mm_priv_data->udvm_priv) { \
		struct udvm_priv_data *udvm_priv = NULL; \
		int index = mm_priv_data->udvm_index; \
		udvm_priv = (struct udvm_priv_data *)mm_priv_data->udvm_priv; \
		if (addr_is_vmm(vaddr)) \
			return &udvm_priv->vmm_priv->minfo.member; \
		else  \
			return &udvm_mlu_priv_must_valid(udvm_priv, index)->member; \
	} else { \
		return &mm_priv_data->member; \
	} \
} \
type *__get_##name##_lock_with_fp(struct file *fp, dev_addr_t vaddr, struct cn_mm_set *mm_set) \
{\
	if (fp_is_udvm(fp) && addr_is_udvm(vaddr)) { \
		struct udvm_priv_data *__udvm = get_udvm_priv_data(fp); \
		int index = udvm_get_cardid_from_addr(vaddr); \
		if (!__udvm) return NULL; \
		if (addr_is_vmm(vaddr)) \
			return &__udvm->vmm_priv->minfo.member; \
		else  \
			return index < 0 ? NULL : &udvm_mlu_priv_must_valid(__udvm, index)->member; \
	} else { \
		struct cn_mm_priv_data *__mmpriv = __get_mm_priv(fp, mm_set); \
		if (!__mmpriv) return NULL; \
		return __get_##name##_lock_with_mmpriv(__mmpriv, vaddr); \
	} \
} \
type *__get_##name##_lock_with_mapinfo(struct mapinfo *minfo) \
{ \
	WARN(!minfo, "must make sure input parameters is valid"); \
	if (minfo->udvm_priv) { \
		struct udvm_priv_data *udvm_priv = NULL; \
		int index = 0; \
		udvm_priv = (struct udvm_priv_data *)minfo->udvm_priv; \
		index = __get_index_minfo(minfo); \
		if (minfo->mem_type == MEM_VMM) \
			return &udvm_priv->vmm_priv->minfo.member; \
		else  \
			return &udvm_mlu_priv_must_valid(udvm_priv, index)->member; \
	} else { \
		struct cn_mm_priv_data *mm_priv_data = \
			(struct cn_mm_priv_data *)minfo->mm_priv_data; \
		WARN(!mm_priv_data, "input minfo's mm_priv_data is NULL"); \
		return &mm_priv_data->member; \
	} \
}

REGISTER_UDVM_LOCK(minfo, spinlock_t, minfo_lock)
REGISTER_UDVM_LOCK(uva, struct mutex, uva_lock)

/* insert_minfo_rb_node */
INSERT_RB_NODE_OPS(mapinfo, virt_addr, minfo);
/* delete_minfo_rb_node */
DELETE_RB_NODE_OPS(mapinfo, minfo);
/* search_minfo_rb_node */
SEARCH_RB_NODE_OPS(mapinfo, virt_addr, mem_meta.size, minfo);

/* old version mapinfo rbtree interfaces */
static void
__insert_mapinfo(struct cn_mm_priv_data *mm_priv_data, struct mapinfo *minfo)
{
	write_lock(&mm_priv_data->node_lock);
	insert_minfo_rb_node(&mm_priv_data->mmroot, minfo);
	if (minfo->mem_meta.type != CN_SHARE_MEM)
		atomic_long_add(minfo->mem_meta.size, &mm_priv_data->used_size);
	write_unlock(&mm_priv_data->node_lock);
}

static void
__delete_mapinfo(struct cn_mm_priv_data *mm_priv_data, struct mapinfo *minfo)
{
	write_lock(&mm_priv_data->node_lock);
	delete_minfo_rb_node(&mm_priv_data->mmroot, minfo);
	if (minfo->mem_meta.type != CN_SHARE_MEM)
		atomic_long_sub(minfo->mem_meta.size, &mm_priv_data->used_size);
	write_unlock(&mm_priv_data->node_lock);
}

/* NOTE: just called by cn_mem_merge */
struct mapinfo *
search_mapinfo(struct cn_mm_priv_data *mm_priv_data, dev_addr_t virt_addr)
{
	struct mapinfo *minfo = NULL;

	read_lock(&mm_priv_data->node_lock);
	minfo = search_minfo_rb_node(&mm_priv_data->mmroot, virt_addr);
	read_unlock(&mm_priv_data->node_lock);

	return minfo;
}

/* Cambricon UDVM version mapinfo rbtree interfaces */
static void
__insert_udvm_mapinfo(struct udvm_priv_data *udvm_priv, int index,
					  struct mapinfo *minfo)
{
	struct mlu_priv_data *mlu_priv = udvm_mlu_priv_must_valid(udvm_priv, index);
	write_lock(&mlu_priv->node_lock);
	insert_minfo_rb_node(&mlu_priv->mmroot, minfo);
	write_unlock(&mlu_priv->node_lock);
}

static void
__insert_priv_list(struct cn_mm_priv_data *mm_priv_data, struct mapinfo *minfo)
{
	/**
	 * NOTE: insert_mapinfo while camb_kref_put do release failed
	 * maybe input NULL pointer mm_priv_data
	 **/
	if (!mm_priv_data)
		return;

	spin_lock(&mm_priv_data->mmlist_lock);
	atomic_long_add(minfo->mem_meta.size, &mm_priv_data->used_size);
	list_add(&minfo->priv_node, &mm_priv_data->minfo_list);
	spin_unlock(&mm_priv_data->mmlist_lock);
}

static void
__delete_udvm_mapinfo(struct udvm_priv_data *udvm_priv, int index,
					  struct mapinfo *minfo)
{
	struct mlu_priv_data *mlu_priv = udvm_mlu_priv_must_valid(udvm_priv, index);
	write_lock(&mlu_priv->node_lock);
	delete_minfo_rb_node(&mlu_priv->mmroot, minfo);
	write_unlock(&mlu_priv->node_lock);
}

static void
__delete_priv_list(struct cn_mm_priv_data *mm_priv_data, struct mapinfo *minfo)
{
	/**
	 * NOTE: delete_mapinfo while camb_kref_put do release failed
	 * maybe input NULL pointer mm_priv_data
	 **/
	if (!mm_priv_data)
		return;

	spin_lock(&mm_priv_data->mmlist_lock);
	atomic_long_sub(minfo->mem_meta.size, &mm_priv_data->used_size);
	/**
	 * NOTE: different between list_del_init and list_del
	 * list_del_init will INIT_LIST_HEAD after __list_del_entry, which avoid
	 * kernel crash if we do list_del twice accidentally.
	 **/
	if (!list_empty(&minfo->priv_node)) {
		list_del_init(&minfo->priv_node);
		minfo->mm_priv_data = NULL;
	}

	spin_unlock(&mm_priv_data->mmlist_lock);
}

static struct mapinfo *
___search_udvm_mapinfo(struct mlu_priv_data *mlu_priv, dev_addr_t vaddr)
{
	struct mapinfo *minfo = NULL;

	read_lock(&mlu_priv->node_lock);
	minfo = search_minfo_rb_node(&mlu_priv->mmroot, vaddr);
	read_unlock(&mlu_priv->node_lock);

	return minfo;
}

static struct mapinfo *
__search_udvm_mapinfo(struct udvm_priv_data *udvm_priv, dev_addr_t vaddr)
{
	int index = __parse_address2index(vaddr);
	struct mlu_priv_data *mlu_priv = NULL;

	if (addr_is_vmm(vaddr))
		return search_vmm_mapinfo(udvm_priv->vmm_priv, vaddr);

	if (index < 0)
		return ERR_PTR(index);

	mlu_priv = udvm_priv->mlu_priv[index];
	if (!mlu_priv) {
		return ERR_PTR(-ENXIO);
	}

	return ___search_udvm_mapinfo(mlu_priv, vaddr);
}

/* public mapinfo rbtree interfaces */
/* NOTE: use inline attr to avoid compile warning: defined but not used */
void
insert_mapinfo(struct cn_mm_priv_data *mm_priv_data, struct mapinfo *minfo)
{
	int index = 0;

	index = __get_index_minfo(minfo);
	if (__is_udvm_enabled(minfo)) {
		struct udvm_priv_data *udvm_priv = NULL;

		udvm_priv = (struct udvm_priv_data *)minfo->udvm_priv;
		if (minfo->mem_type == MEM_VMM) {
			/* vmm mapinfo saved address is udvm address, not need set again */
			insert_vmm_mapinfo(udvm_priv->vmm_priv, minfo);
			return ;
		}

		if (minfo->mem_type == MEM_KEXT) {
			minfo->virt_addr = set_udvm_address(index, minfo->virt_addr, UDVM_ADDR_PUBLIC);
		}

		if (minfo->mem_type != MEM_FAKE) {
			minfo->virt_addr = set_udvm_address(index, minfo->virt_addr, UDVM_ADDR_DEFAULT);
		}

		__insert_udvm_mapinfo(udvm_priv, index, minfo);
		__insert_priv_list(mm_priv_data, minfo);
	} else {
		WARN(!mm_priv_data, "mm_priv_data is invalid while UDVM Disable");
		if (minfo->mem_type == MEM_KEXT) {
			minfo->virt_addr = set_udvm_address(index, minfo->virt_addr, UDVM_ADDR_PUBLIC);
		}

		__insert_mapinfo(mm_priv_data, minfo);
	}
}

void
delete_mapinfo(struct cn_mm_priv_data *mm_priv_data, struct mapinfo *minfo)
{
	if (__is_udvm_enabled(minfo)) {
		struct udvm_priv_data *udvm_priv = NULL;
		int index = 0;

		udvm_priv = (struct udvm_priv_data *)minfo->udvm_priv;

		if (minfo->mem_type == MEM_VMM) {
			delete_vmm_mapinfo(udvm_priv->vmm_priv, minfo);
			return ;
		}

		index = __get_index_minfo(minfo);
		__delete_udvm_mapinfo(udvm_priv, index, minfo);
		__delete_priv_list(mm_priv_data, minfo);
	} else {
		WARN(!mm_priv_data, "mm_priv_data is invalid while UDVM Disable");
		__delete_mapinfo(mm_priv_data, minfo);
	}
}

/**
 *  search_mapinfo_with_fp  -  find device memory handle from file pointer.
 *  @fp:     input file pointer which pointer to cambricon_devX or cambricon_ctl
 *  @vaddr:  48bit device virtual address which need find its handle
 *  @mm_set: specific MLU card memory handle which is used to get card Index
 *
 *  Search for the device memory handle for @vaddr, input fp support pointer to
 *  cambricon_ctl and cambricon_devX. NOTICE: we only find the device index which
 *  get from @mm_set, so must make sure @mm_set is correct.
 */
struct mapinfo *
search_mapinfo_with_fp(struct file *fp, dev_addr_t vaddr,
		struct cn_mm_set *mm_set)
{
	struct udvm_priv_data *udvm_priv = NULL;

	if (fp_is_udvm(fp)) {
		struct udvm_priv_data *udvm_priv = get_udvm_priv_data(fp);

		if (!udvm_priv)
			return ERR_PTR(-EINVAL);

		return __search_udvm_mapinfo(udvm_priv, vaddr);
	} else {
		struct cn_mm_priv_data *mm_priv_data = __get_mm_priv(fp, mm_set);

		if (!mm_priv_data)
			return ERR_PTR(-EINVAL);

		if (mm_priv_data->udvm_priv) {
			udvm_priv = (struct udvm_priv_data *)mm_priv_data->udvm_priv;

			return __search_udvm_mapinfo(udvm_priv, vaddr);
		}

		return search_mapinfo(mm_priv_data, vaddr);
	}
}

static struct mapinfo *
__search_mapinfo_vmm_func(struct vmm_priv_data *vmm_priv, dev_addr_t vaddr,
			size_t size, int (func)(struct mapinfo *, dev_addr_t, size_t))
{
	struct mapinfo *pminfo = NULL;
	int ret = -ENXIO;

	spin_lock(&vmm_priv->minfo.minfo_lock);
	pminfo = search_vmm_mapinfo(vmm_priv, vaddr);
	ret = (pminfo != NULL) ? func(pminfo, vaddr, size) : -ENXIO;
	spin_unlock(&vmm_priv->minfo.minfo_lock);

	pminfo = (ret == 0) ? pminfo : ERR_PTR(ret);
	return pminfo;
}

static struct mapinfo *
__search_mapinfo_udvm_func(struct udvm_priv_data *udvm_priv, dev_addr_t vaddr,
			size_t size, int (func)(struct mapinfo *, dev_addr_t, size_t))
{
	struct mapinfo *pminfo = NULL;
	struct mlu_priv_data *mlu_priv = NULL;
	int ret = -ENXIO, index = __parse_address2index(vaddr);

	if (addr_is_vmm(vaddr))
		return __search_mapinfo_vmm_func(udvm_priv->vmm_priv, vaddr, size, func);

	if (index < 0)
		return ERR_PTR(index);

	mlu_priv = udvm_priv->mlu_priv[index];
	if (!mlu_priv)
		return ERR_PTR(-ENXIO);

	spin_lock(&mlu_priv->minfo_lock);
	pminfo = ___search_udvm_mapinfo(mlu_priv, vaddr);
	ret = (pminfo != NULL) ? func(pminfo, vaddr, size) : -ENXIO;
	spin_unlock(&mlu_priv->minfo_lock);

	pminfo = (ret == 0) ? pminfo : ERR_PTR(ret);
	return pminfo;
}

static struct mapinfo *
__search_mapinfo_func(struct cn_mm_priv_data *mm_priv_data, dev_addr_t vaddr,
			size_t size, int (func)(struct mapinfo *, dev_addr_t, size_t))
{
	struct mapinfo *pminfo = NULL;
	spinlock_t *minfo_lock = __get_minfo_lock_with_mmpriv(mm_priv_data, vaddr);
	int ret = -ENXIO;

	if (!minfo_lock) return ERR_PTR(-ENXIO);

	spin_lock(minfo_lock);
	pminfo = search_mapinfo(mm_priv_data, vaddr);
	ret = (pminfo != NULL) ? func(pminfo, vaddr, size) : -ENXIO;
	spin_unlock(minfo_lock);

	pminfo = (ret == 0) ? pminfo : ERR_PTR(ret);
	return pminfo;
}

/**
 *  search_mapinfo_with_func  -  find memory handle and do something need atomic with file pointer.
 *  @fp:     input file pointer which pointer to cambricon_devX or cambricon_ctl
 *  @mm_set: specific MLU card memory handle which is used to get card Index
 *  @vaddr:  48bit device virtual address which need find its handle
 *  @size:   device memory size.
 *
 *  Search for the device memory handle for @vaddr, input fp support pointer to
 *  cambricon_ctl and cambricon_devX. NOTICE: we only find the device index which
 *  get from @mm_set, so must make sure @mm_set is correct.
 */
struct mapinfo *
search_mapinfo_with_func(struct file *fp, struct cn_mm_set *mm_set,
		dev_addr_t vaddr, size_t size,
		int (func)(struct mapinfo *, dev_addr_t, size_t))
{
	struct udvm_priv_data *udvm_priv = NULL;

	if (addr_is_public(vaddr))
		fp = NULL;

	if (fp_is_udvm(fp)) {
		udvm_priv = get_udvm_priv_data(fp);

		if (!udvm_priv)
			return ERR_PTR(-EINVAL);

		return __search_mapinfo_udvm_func(udvm_priv, vaddr, size, func);
	} else {
		struct cn_mm_priv_data *mm_priv_data = __get_mm_priv(fp, mm_set);

		if (!mm_priv_data)
			return ERR_PTR(-EINVAL);

		if (mm_priv_data->udvm_priv) {
			udvm_priv = (struct udvm_priv_data *)mm_priv_data->udvm_priv;
			return __search_mapinfo_udvm_func(udvm_priv, vaddr, size, func);
		}

		return __search_mapinfo_func(mm_priv_data, vaddr, size, func);
	}
}
