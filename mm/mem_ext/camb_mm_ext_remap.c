/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2023 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/spinlock_types.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/ptrace.h>
#include <linux/kthread.h>
#include <linux/mman.h>
#include <linux/workqueue.h>
#include <linux/timer.h>

#include "cndrv_genalloc.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_mcc.h"
#include "cndrv_debug.h"
#include "hal/cn_mem_hal.h"
#include "camb_mm.h"
#include "camb_mm_priv.h"
#include "cndrv_sbts.h"
#include "cndrv_commu.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_fa.h"
#include "cndrv_gdma.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_ipcm.h"
#include "camb_mm_rpc.h"
#include "camb_sg_split.h"
#include "cndrv_udvm.h"
#include "camb_udvm.h"
#include "camb_mm_compat.h"
#include "cndrv_ipcm.h"
#include "camb_mm_pgretire.h"
#include "camb_mm_tools.h"
#include "cndrv_df.h"
#include "cndrv_ext.h"
#include "camb_mm_ext_remap.h"
#include "cndrv_udvm_usr.h" /* ioctl command and structure */
#ifdef CONFIG_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif
#include "camb_iova_allocator.h"

static struct udvm_priv_data *__get_udvm_priv_from_devfp(u64 dev_tag)
{
	struct cn_mm_priv_data *mm_priv_data;

	mm_priv_data = __get_mm_priv((struct file *)dev_tag, NULL);
	if (!mm_priv_data) {
		cn_dev_err("get mem priv data failed");
		return NULL;
	}

	return mm_priv_data->udvm_priv;
}

/*this tag is ctrl fp, so need get_udvm_priv_data get udvm*/
static struct extn_priv_data *__get_extn_priv_from_ctlfp(u64 ctrl_tag)
{
	struct udvm_priv_data *udvm = get_udvm_priv_data((struct file *)ctrl_tag);

	return (udvm != NULL) ? udvm->extn_priv : NULL;
}

/*this tag is dev fp, so need __get_udvm_priv_from_devfp get udvm*/
static struct extn_priv_data *__get_extn_priv_from_devfp(u64 dev_fp_tag)
{
	struct udvm_priv_data *udvm = __get_udvm_priv_from_devfp(dev_fp_tag);

	return (udvm != NULL) ? udvm->extn_priv : NULL;
}

static int __handle_ref_kref_get(struct extn_priv_data *extn_priv, unsigned long handle,
			struct camb_handle_ref **pphandle)
{
	struct camb_handle_ref *phandle = NULL;

	rcu_read_lock();
	phandle = radix_tree_lookup(&extn_priv->phys.ra_root, handle);

	if (!phandle) {
		rcu_read_unlock();
		cn_dev_debug("invalid handle(%#lx) input", handle);
		return -EINVAL;
	}

	if (!atomic_add_unless(&phandle->refcnt, 1, 0)) {
		rcu_read_unlock();
		cn_dev_err("input handle maybe in free");
		return -EINVAL;
	}

	*pphandle = phandle;

	rcu_read_unlock();

	return 0;
}

static int __handle_ref_kref_put(struct camb_handle_ref *phandle,
			void (*release)(struct camb_handle_ref *))
{
	struct extn_priv_data *extn_priv = phandle->extn_priv;
	struct camb_handle_ref *tmp = NULL;

	WARN_ON(release == NULL);

	if (!atomic_add_unless(&phandle->refcnt, -1, 1)) {
		spin_lock(&extn_priv->phys.lock);
		if (unlikely(!atomic_dec_and_test(&phandle->refcnt))) {
			spin_unlock(&extn_priv->phys.lock);
			return 0;
		}

		tmp = radix_tree_delete(&extn_priv->phys.ra_root, phandle->handle);
		list_del_init(&phandle->node);
		spin_unlock(&extn_priv->phys.lock);

		WARN_ON(tmp != phandle);
		synchronize_rcu();
		release(phandle);

		return 1;
	}

	return 0;
}

static void rpc_put_extn_mem_handle(struct cn_mm_set *mm_set, unsigned int handle)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct extn_ctl_t params;
	struct ret_msg remsg = {0};
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	params.cmd = EXTN_MEM_HANDLE_PUT;
	params.handle = handle;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_extn_mem_ctl", &params,
					sizeof(struct extn_ctl_t), &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
	}

	if (remsg.ret < 0) {
		cn_dev_core_err(core, "put external memory handle fail. %d", remsg.ret);
	}
}

static int rpc_get_extn_mem_handle(struct cn_mm_set *mm_set, unsigned int fd, u64 size, unsigned long *ion_handle_id)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct extn_ctl_t params;
	struct ret_msg remsg = {0};
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	params.cmd = EXTN_MEM_HANDLE_GET_BY_FD;
	params.fd = fd;
	params.size = size;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_extn_mem_ctl", &params,
					sizeof(struct extn_ctl_t), &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
		return -EPIPE;
	}

	if (remsg.ret < 0) {
		cn_dev_core_err(core, "get memory handle fail %d", remsg.ret);
		return remsg.ret;
	}

	*ion_handle_id = remsg.handle_id;

	return 0;
}

static void camb_extn_mem_release(struct camb_handle_ref *phandle)
{
	struct cn_mm_set *mm_set = phandle->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	cn_dev_core_debug(core, "extn phys handle release %#lx ref:%d", phandle->handle,
			atomic_read(&phandle->refcnt));

	rpc_put_extn_mem_handle(mm_set, udvm_get_iova_from_addr(phandle->handle));

	cn_kfree(phandle);
}

int camb_import_extn_mem(u64 ctl_tag, unsigned int fd, u64 size, unsigned long *handle, struct cn_mm_set *mm_set)
{
	struct extn_priv_data *extn_priv = __get_extn_priv_from_ctlfp(ctl_tag);
	struct camb_handle_ref *handle_ref = NULL;
	int ret = 0;
	unsigned long handle_id = 0;
	unsigned long ion_handle_id = 0;

	if (!extn_priv) {
		cn_dev_err("invalid process tags(%#llx) input", ctl_tag);
		return -EINVAL;
	}

	ret = rpc_get_extn_mem_handle(mm_set, fd, size, &ion_handle_id);
	if (ret) {
		cn_dev_err("get external mem handle id failed. fd is %d", fd);
		return ret;
	}

	handle_id = set_udvm_address(get_index_with_mmset(mm_set),
			ion_handle_id, UDVM_ADDR_DEFAULT);

	ret = __handle_ref_kref_get(extn_priv, handle_id, &handle_ref);
	if (!ret) {
		*handle = handle_id;
		/*put ion handle if handle_ref already exit.*/
		rpc_put_extn_mem_handle(mm_set, ion_handle_id);
		return 0;
	}

	handle_ref = cn_kzalloc(sizeof(struct camb_handle_ref), GFP_KERNEL);
	if (!handle_ref) {
		cn_dev_err("alloc physical handle buffer failed");
		rpc_put_extn_mem_handle(mm_set, ion_handle_id);
		return -ENOMEM;
	}

	handle_ref->handle = handle_id;
	handle_ref->size = size;
	handle_ref->mm_set = mm_set;
	handle_ref->extn_priv = extn_priv;
	atomic_set(&handle_ref->refcnt, 1);

	spin_lock(&extn_priv->phys.lock);
	ret = radix_tree_insert(&extn_priv->phys.ra_root, handle_ref->handle,
			(void *)handle_ref);
	if (likely(!ret)) {
		/*add list when insert successful.*/
		list_add(&handle_ref->node, &extn_priv->phys.list);
	} else {
		spin_unlock(&extn_priv->phys.lock);
		cn_dev_err("insert %#lx to rdxt error. Mabybe have been inserted.",
				handle_ref->handle);
		cn_kfree(handle_ref);
		rpc_put_extn_mem_handle(mm_set, ion_handle_id);
		return ret;
	}
	spin_unlock(&extn_priv->phys.lock);

	*handle = handle_ref->handle;

	return 0;
}

static struct camb_iova_domain *__get_iovad(void)
{
	return ((struct cn_udvm_set *)cndrv_core_get_udvm())->iova_pool.allocator;
}

static int rpc_extn_mem_map(struct cn_mm_set *mm_set, unsigned long iova,
		unsigned long size, unsigned int handle, unsigned int prot)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct extn_ctl_t params;
	struct ret_msg remsg = {0};
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	params.cmd = EXTN_MEM_MAP;
	params.iova = iova;
	params.handle = handle;
	params.size = size;
	params.prot = prot;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_extn_mem_ctl", &params,
					sizeof(struct extn_ctl_t), &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
		return -EPIPE;
	}

	if (remsg.ret < 0) {
		cn_dev_core_err(core, "external memory map fail. %d", remsg.ret);
		return remsg.ret;
	}

	return remsg.ret;
}

static void rpc_extn_mem_unmap(struct cn_mm_set *mm_set, unsigned long iova,
		unsigned long size)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct extn_ctl_t params;
	struct ret_msg remsg = {0};
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	params.cmd = EXTN_MEM_UNMAP;
	params.iova = iova;
	params.size = size;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_extn_mem_ctl", &params,
					sizeof(struct extn_ctl_t), &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
	}

	if (remsg.ret < 0) {
		cn_dev_core_err(core, "external memory unmap fail. %d", remsg.ret);
	}
}

int camb_destroy_extn_mem(u64 ctl_tag, unsigned long handle)
{
	struct extn_priv_data *extn_priv = __get_extn_priv_from_ctlfp(ctl_tag);
	struct camb_handle_ref *phandle = NULL;

	if (!extn_priv) {
		cn_dev_err("invalid process tags(%#llx) input",ctl_tag);
		return -EINVAL;
	}

	rcu_read_lock();
	phandle = radix_tree_lookup(&extn_priv->phys.ra_root, handle);

	if (!phandle) {
		rcu_read_unlock();
		cn_dev_err("invalid handle(%#lx) input", handle);
		return -EINVAL;
	}

	rcu_read_unlock();

	return __handle_ref_kref_put(phandle, camb_extn_mem_release);
}

static int __create_extn_minfo(u64 dev_tag, struct camb_handle_ref *phandle, dev_addr_t vaddr,
		unsigned long size, struct mapinfo **ppminfo)
{
	struct mapinfo *minfo = NULL;
	struct cn_mm_priv_data *mm_priv_data = __get_mm_priv((struct file *)dev_tag, NULL);

	minfo = cn_kzalloc(sizeof(struct mapinfo), GFP_KERNEL);
	if (!minfo) {
		cn_dev_err("alloc mapinfo buffer failed");
		return -ENOMEM;
	}

	camb_init_mapinfo_basic(minfo, phandle->mm_set, 0);
	minfo->tag = dev_tag;
	minfo->active_ns = task_active_pid_ns(current);
	minfo->mm_priv_data = mm_priv_data;
	minfo->udvm_priv = mm_priv_data->udvm_priv;
	minfo->mem_type = MEM_IE;
	minfo->is_linear = false;
	minfo->mem_meta.size = size;
	minfo->mem_meta.type = CN_IPU_MEM;

	minfo->extn_info.vaddr = vaddr;
	minfo->extn_info.phandle = phandle;

	*ppminfo = minfo;

	return 0;
}

int camb_map_extn_mem(u64 dev_tag, unsigned long handle, unsigned long size, unsigned long offset,
		unsigned int flag, dev_addr_t *iova)
{
	int ret = 0;
	dev_addr_t dev_vaddr = 0;
	unsigned int dev_handle_id = 0;
	struct mapinfo *minfo;
	struct camb_handle_ref *phandle = NULL;
	struct extn_priv_data *extn_priv = __get_extn_priv_from_devfp(dev_tag);

	if (!extn_priv) {
		cn_dev_err("invalid process tags(%#llx) input", dev_tag);
		return -EINVAL;
	}

	/*add handle ref cnt, which for mapinfo*/
	ret = __handle_ref_kref_get(extn_priv, handle, &phandle);
	if (ret) {
		cn_dev_err("handle(%#lx)  error", handle);
		return ret;
	}

	if (offset + size > phandle->size) {
		__handle_ref_kref_put(phandle, camb_extn_mem_release);
		cn_dev_err("[handle:%#lx size:%#lx] but size:%#lx offset:%#lx", handle,
				phandle->size, size, offset);
		return -EINVAL;
	}

	/*alloc iova from allocator.the phandle->size is unlimit.*/
	dev_vaddr = camb_alloc_iova(__get_iovad(), 0, phandle->size, 1 << EXTN_MINIMUM_SHIFT);
	if (!dev_vaddr) {
		__handle_ref_kref_put(phandle, camb_extn_mem_release);
		cn_dev_err("[handle %#lx] Device have no enough iova.", handle);
		return -ENOSPC;
	}

	/*create pminfo*/
	ret = __create_extn_minfo(dev_tag, phandle, dev_vaddr, phandle->size, &minfo);
	if (ret) {
		camb_free_iova(__get_iovad(), dev_vaddr);
		__handle_ref_kref_put(phandle, camb_extn_mem_release);
		cn_dev_err("create iova(%#llx) mapinfo error", dev_vaddr);
		return ret;
	}

	dev_vaddr = udvm_get_iova_from_addr(minfo->extn_info.vaddr);
	dev_handle_id = udvm_get_iova_from_addr(handle);

	/*map iova*/
	ret = rpc_extn_mem_map(minfo->mm_set, dev_vaddr, minfo->mem_meta.size,
			dev_handle_id, minfo->mem_meta.flag);
	if (ret) {
		cn_dev_err("set access for (addr: %#llx, size: %#lx) failed",
				minfo->virt_addr, minfo->mem_meta.size);
		camb_free_iova(__get_iovad(), minfo->extn_info.vaddr);
		kfree(minfo);
		__handle_ref_kref_put(phandle, camb_extn_mem_release);
		return ret;
	}

	minfo->extn_info.offset = offset;

	insert_mapinfo(minfo->mm_priv_data, minfo);

	*iova = minfo->extn_info.vaddr + offset;

	return 0;
}

int camb_mem_extn_priv_init(struct extn_priv_data **pextn_priv)
{
	struct extn_priv_data *extn_priv;

	extn_priv = cn_kzalloc(sizeof(struct extn_priv_data), GFP_KERNEL);
	if (!extn_priv) {
		cn_dev_err("create extn_priv_data failed");
		return -ENOMEM;
	}

	/* init physical handle management structure */
	INIT_RADIX_TREE(&extn_priv->phys.ra_root, GFP_ATOMIC);
	INIT_LIST_HEAD(&extn_priv->phys.list);
	spin_lock_init(&extn_priv->phys.lock);

	if (pextn_priv)
		*pextn_priv = extn_priv;

	return 0;
}

static void __extn_priv_handle_release(struct extn_priv_data *extn_priv)
{
	struct camb_handle_ref *tmp, *pos, *val;
	struct list_head handle_rm_list;
	int bug_on = 0;

	INIT_LIST_HEAD(&handle_rm_list);
	/* physical handle resource release*/
	if (!cn_radix_tree_empty(&extn_priv->phys.ra_root)) {
		spin_lock(&extn_priv->phys.lock);
		list_for_each_entry_safe(pos, tmp, &extn_priv->phys.list, node) {
			val = radix_tree_delete(&extn_priv->phys.ra_root, pos->handle);
			if (val != pos) {
				bug_on = 1;
				break;
			}

			list_move(&pos->node, &handle_rm_list);
		}
		spin_unlock(&extn_priv->phys.lock);

		WARN_ON(bug_on);

		list_for_each_entry_safe(pos, tmp, &handle_rm_list, node) {
			list_del_init(&pos->node);
			camb_extn_mem_release(pos);
		}
	}
}

void camb_mem_extn_priv_release(struct extn_priv_data *extn_priv)
{
	if (!extn_priv)
		return;

	__extn_priv_handle_release(extn_priv);

	cn_kfree(extn_priv);
}


int extn_minfo_release(struct mapinfo *pminfo)
{
	struct camb_handle_ref *phandle = pminfo->extn_info.phandle;
	unsigned long addr = udvm_get_iova_from_addr(pminfo->virt_addr);

	camb_free_iova(__get_iovad(), addr);

	rpc_extn_mem_unmap(pminfo->mm_set, addr, pminfo->mem_meta.size);

	__handle_ref_kref_put(phandle, camb_extn_mem_release);

	return 0;
}

