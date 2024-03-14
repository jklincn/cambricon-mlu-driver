#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/pid_namespace.h>
#include <linux/radix-tree.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_udvm_usr.h"
#include "cndrv_genalloc.h"
#include "hal/cn_mem_hal.h"
#include "camb_mm.h"
#include "camb_udvm.h"
#include "camb_mm_compat.h"
#include "camb_range_tree.h"
#include "camb_vmm.h"
#include "camb_vmm_internal.h"
#include "camb_iova_allocator.h"
#include "cndrv_smlu.h"


static struct camb_vmm_set *__get_vmm_set(void)
{
	return &(((struct cn_udvm_set *)cndrv_core_get_udvm())->vmm_set);
}

static struct camb_iova_domain *__get_iovad(void)
{
	return (struct camb_iova_domain *)(__get_vmm_set()->allocator);
}

static struct vmm_priv_data *__get_vmm_priv(u64 tag)
{
	struct udvm_priv_data *udvm = get_udvm_priv_data((struct file *)tag);

	return (udvm != NULL) ? udvm->vmm_priv : NULL;
}

#define VMM_ADD (0)
#define VMM_SUB (1)

static void
__update_vmm_pid_info(struct camb_vmm_handle *phandle, int ops,
				unsigned long size)
{
	struct vmm_priv_data *vmm = phandle->vmm_priv;
	struct cn_mm_set *mm_set = phandle->mm_set;
	struct pid_info_s *pid_info = NULL;
	unsigned int index = get_index_with_mmset(phandle->mm_set);

	if (!vmm->phys.pid_infos[index]) {
		pid_info = cn_kzalloc(sizeof(struct pid_info_s), GFP_KERNEL);
		if (!pid_info) return ;

		pid_info->tgid = current->tgid;
		pid_info->active_ns = task_active_pid_ns(current);
		pid_info->active_pid = task_tgid_nr_ns(current, pid_info->active_ns);
		pid_info->pgid = task_pgrp_nr_ns(current, pid_info->active_ns);
		pid_info->taskpid = find_get_pid(current->pid);

		spin_lock(&mm_set->vmm_pid_lock);
		list_add_tail(&pid_info->pid_list, &mm_set->vmm_pid_head);
		spin_unlock(&mm_set->vmm_pid_lock);

		vmm->phys.pid_infos[index] = pid_info;
	}

	if (ops == VMM_ADD) {
		__sync_add_and_fetch(&vmm->phys.pid_infos[index]->phy_usedsize, size);
		__sync_add_and_fetch(&vmm->phys.pid_infos[index]->vir_usedsize, size);
	} else if (ops == VMM_SUB) {
		__sync_sub_and_fetch(&vmm->phys.pid_infos[index]->phy_usedsize, size);
		__sync_sub_and_fetch(&vmm->phys.pid_infos[index]->vir_usedsize, size);
	}
}

static bool
rpc_vmm_mem_check_support(struct cn_mm_set *mm_set, unsigned long iova,
				unsigned long size)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct vmm_ctl_t params;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	memset(&remsg, 0x0, result_len);

	params.cmd = VMM_MEM_SUPPORT;
	params.iova = iova;
	params.size = size;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_vmm_mem_ctl", &params,
					sizeof(struct vmm_ctl_t), &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
		return 0;
	}

	return (remsg.ret < 0) ? 0 : !!remsg.ret;
}

static int
rpc_vmm_mem_create(struct cn_mm_set *mm_set, unsigned long size,
			unsigned int *flags, unsigned int *handle)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct vmm_ctl_t params;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	if (!flags || !handle)
		return -EINVAL;

	params.cmd = VMM_MEM_CREATE;
	params.attr.size = size;
	params.attr.type = CN_IPU_MEM;
	params.attr.affinity = -1;
	params.attr.flag = *flags;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_vmm_mem_ctl", &params,
					sizeof(struct vmm_ctl_t), &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
		return -EPIPE;
	}

	if (remsg.ret < 0) {
		cn_dev_core_err(core, "alloc memory handle failed %d", remsg.ret);
		return remsg.ret;
	}

	*flags = remsg.flag;
	*handle = remsg.handle_id;

	return 0;
}

static int
rpc_vmm_mem_handle_get(struct cn_mm_set *mm_set, unsigned int handle)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct vmm_ctl_t params;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	params.cmd = VMM_MEM_HANDLE_GET;
	params.handle = handle;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_vmm_mem_ctl", &params,
					sizeof(struct vmm_ctl_t), &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
		return -EPIPE;
	}

	if (remsg.ret < 0) {
		cn_dev_core_err(core, "handle kref get failed %d", remsg.ret);
		return remsg.ret;
	}

	return 0;
}

static void
rpc_vmm_mem_release(struct cn_mm_set *mm_set, unsigned int handle)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct vmm_ctl_t params;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	params.cmd = VMM_MEM_RELEASE;
	params.handle = handle;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_vmm_mem_ctl", &params,
					sizeof(struct vmm_ctl_t), &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
		/* FIXME: add release failed handle into ffl list */
	}
}

static int
rpc_vmm_mem_map(struct cn_mm_set *mm_set, unsigned long iova,
		unsigned long size, unsigned int handle, unsigned int prot)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct vmm_ctl_t params;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	params.cmd = VMM_MEM_MAP;
	params.iova = iova;
	params.handle = handle;
	params.size = size;
	params.prot = prot;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_vmm_mem_ctl", &params,
					sizeof(struct vmm_ctl_t), &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
		return -EPIPE;
	}

	return remsg.ret;
}

static unsigned int __get_modify_flag(unsigned int old, unsigned int new)
{
	unsigned int flags = 0;

	if ((new ^ old) & (0x3 << ATTR_mair))
		SET_MODIFY_FLAGS(flags, mair, (new >> ATTR_mair) & 0x3);

	if ((new ^ old) & (0x1 << ATTR_ap))
		SET_MODIFY_FLAGS(flags, ap, (new >> ATTR_ap) & 0x1);

	if ((new ^ old) & (0x1 << ATTR_cachelocked))
		SET_MODIFY_FLAGS(flags, cachelocked, (new >> ATTR_cachelocked) & 0x1);

	return flags;
}

static int
rpc_vmm_mem_modify_prot(struct cn_mm_set *mm_set, unsigned long iova,
			unsigned long size, unsigned int old_prot, unsigned int new_prot)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	unsigned long params[3];
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	unsigned int flags = __get_modify_flag(old_prot, new_prot);
	int ret = 0;

	if (!flags) {
		cn_dev_core_debug(core, "input new_prot is as same as old, not need change");
		return 0;
	}

	params[0] = iova;
	params[1] = size;
	params[2] = flags;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_set_prot", &params,
					sizeof(unsigned long) * 3, &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
		return -EPIPE;
	}

	if (remsg.ret != new_prot) {
		cn_dev_core_err(core, "try to modify flags failed (input:%#x, return:%#x)",
				new_prot, remsg.ret);
		return -EINVAL;
	}

	return 0;
}

static void
rpc_vmm_mem_unmap(struct cn_mm_set *mm_set, unsigned long iova,
		unsigned long size)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct vmm_ctl_t params;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	params.cmd = VMM_MEM_UNMAP;
	params.iova = iova;
	params.size = size;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_vmm_mem_ctl", &params,
					sizeof(struct vmm_ctl_t), &remsg, &result_len,
					sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client failed %d", ret);
		/* FIXME: add release failed handle into ffl list */
	}
}

static int
camb_vmm_handle_kref_get(struct vmm_priv_data *vmm_priv, unsigned long handle,
			struct camb_vmm_handle **pphandle)
{
	struct camb_vmm_handle *phandle = NULL;

	rcu_read_lock();
	phandle = radix_tree_lookup(&vmm_priv->phys.ra_root, handle);

	if (!phandle) {
		rcu_read_unlock();
		/* error log too much while running multi_thread test in driver_test, close it. */
		cn_dev_debug("invalid handle(%#lx) input", handle);
		return -EINVAL;
	}

	if (!atomic_add_unless(&phandle->refcnt, 1, 0)) {
		rcu_read_unlock();
		cn_dev_err("input handle maybe in free");
		return -EINVAL;
	}

	if (pphandle) *pphandle = phandle;
	rcu_read_unlock();

	return 0;
}

static int
camb_vmm_handle_kref_put(struct camb_vmm_handle *phandle,
			void (*release)(struct camb_vmm_handle *))
{
	struct vmm_priv_data *vmm_priv = phandle->vmm_priv;
	struct camb_vmm_handle *tmp = NULL;

	WARN_ON(release == NULL);

	if (!atomic_add_unless(&phandle->refcnt, -1, 1)) {
		spin_lock(&vmm_priv->phys.lock);
		if (unlikely(!atomic_dec_and_test(&phandle->refcnt))) {
			spin_unlock(&vmm_priv->phys.lock);
			return 0;
		}

		tmp = radix_tree_delete(&vmm_priv->phys.ra_root, phandle->handle);
		list_del_init(&phandle->node);
		spin_unlock(&vmm_priv->phys.lock);

		BUG_ON(tmp != phandle);
		synchronize_rcu();
		release(phandle);

		return 1;
	}

	return 0;
}

static void camb_vmm_mem_release(struct camb_vmm_handle *phandle)
{
	struct cn_mm_set *mm_set = phandle->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	cn_dev_core_debug(core, "vmm phys handle release %#lx", phandle->handle);

	rpc_vmm_mem_release(mm_set, udvm_get_iova_from_addr(phandle->handle));

	cn_smlu_uncharge(core, mem_cgrp_id, (void *)phandle->tag, phandle->active_ns, phandle->size);

	__update_vmm_pid_info(phandle, VMM_SUB, phandle->size);
	__sync_sub_and_fetch(&mm_set->phy_used_mem, phandle->size);
	__sync_sub_and_fetch(&mm_set->vir_used_mem, phandle->size);
	cn_kfree(phandle);
}

static int
camb_vmm_mem_create_internal(u64 tag, unsigned long size,
			unsigned char flags, unsigned long *handle,
			struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct camb_vmm_handle *phandle = NULL;
	unsigned int handle_id = 0;
	int ret = 0;

	if (!vmm_priv) {
		cn_dev_core_err(core, "invalid process tags(%#llx) input", tag);
		return -EINVAL;
	}

	if (!IS_VMM_ALIGNED(size)) {
		cn_dev_core_err(core, "input size(%#lx) is not aligned with %#lx", size,
					1UL << VMM_MINIMUM_SHIFT);
		return -EINVAL;
	}

	if (!mm_set->vmm_enable) {
		cn_dev_core_err(core, "current device not support VMM interfaces");
		return -ERROR_UDVM_NOT_SUPPORTED;
	}

	phandle = cn_kzalloc(sizeof(struct camb_vmm_handle), GFP_KERNEL);
	if (!phandle) {
		cn_dev_core_err(core, "alloc physical handle buffer failed");
		return -ENOMEM;
	}

	phandle->size = size;
	phandle->flags = flags;
	phandle->mm_set = mm_set;
	phandle->vmm_priv = vmm_priv;
	atomic_set(&phandle->refcnt, 1);
	atomic_set(&phandle->release_refcnt, 1);
	phandle->tag = tag;
	phandle->active_ns = task_active_pid_ns(current);

	ret = rpc_vmm_mem_create(mm_set, phandle->size, &phandle->flags, &handle_id);
	if (ret || !handle_id) {
		cn_dev_core_err(core, "call rpc alloc physical handle failed %d", ret);
		cn_kfree(phandle);
		return ret;
	}

	phandle->handle =
		set_udvm_address(get_index_with_mmset(mm_set), handle_id, UDVM_ADDR_VMM);

	spin_lock(&vmm_priv->phys.lock);
	ret = radix_tree_insert(&vmm_priv->phys.ra_root, phandle->handle,
				(void *)phandle);
	if (likely(!ret)) list_add(&phandle->node, &vmm_priv->phys.list);
	spin_unlock(&vmm_priv->phys.lock);

	if (ret) {
		rpc_vmm_mem_release(mm_set, handle_id);
		cn_kfree(phandle);
		return ret;
	}

	if (handle)
		*handle = phandle->handle;

	__sync_add_and_fetch(&mm_set->phy_used_mem, (unsigned long)phandle->size);
	__sync_add_and_fetch(&mm_set->vir_used_mem, (unsigned long)phandle->size);
	__update_vmm_pid_info(phandle, VMM_ADD, phandle->size);
	return 0;
}

int cn_vmm_mem_create(u64 tag, unsigned long size, unsigned int flags,
			unsigned long *handle, struct cn_mm_set *mm_set)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	ret = cn_smlu_try_charge(core, mem_cgrp_id, (void *)tag, NULL, size);
	if (ret) {
		cn_dev_core_debug(core, "smlu:memory alloc check failed(%#lx),because of memory limitations", size);
		return -ENOSPC;
	}

	ret = camb_vmm_mem_create_internal(tag, size, flags, handle, mm_set);

	if (ret) {
		cn_smlu_uncharge(core, mem_cgrp_id, (void *)tag, NULL, size);
	}


	return ret;
}

int cn_vmm_mem_release(u64 tag, unsigned long handle)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct camb_vmm_handle *phandle = NULL;

	if (!vmm_priv) {
		cn_dev_err("invalid process tags(%#llx) input", tag);
		return -EINVAL;
	}

	rcu_read_lock();
	phandle = radix_tree_lookup(&vmm_priv->phys.ra_root, handle);

	if (!phandle) {
		rcu_read_unlock();
		cn_dev_err("invalid handle(%#lx) input", handle);
		return -EINVAL;
	}

	if (!atomic_add_unless(&phandle->release_refcnt, -1, 0)) {
		rcu_read_unlock();
		cn_dev_err("handle in free, don't need free again");
		return -ENXIO;
	}

	rcu_read_unlock();

	return camb_vmm_handle_kref_put(phandle, camb_vmm_mem_release);
}

static void
camb_vmm_iova_bitmap_clear(struct vmm_priv_data *vmm_priv, dev_addr_t vaddr,
				unsigned long size, struct camb_vmm_iova *first)
{
	struct camb_vmm_iova *iova = NULL;
	unsigned long remain_size = size, cur_size = 0;
	dev_addr_t cur_addr = 0;

	spin_lock(&vmm_priv->iova.lock);
	cur_addr = vaddr;
	vmm_iova_for_each_in_first(iova, first, vmm_priv, vaddr + size - 1) {
		cur_size = min_t(unsigned long, remain_size, iova->node.end - cur_addr + 1);

		clear_vmm_iova_bitmap(iova, cur_addr, cur_size);

		remain_size -= cur_size;
		if (!remain_size)
			break;

		cur_addr += cur_size;
	}

	spin_unlock(&vmm_priv->iova.lock);
}

static int
camb_vmm_iova_bitmap_set(struct vmm_priv_data *vmm_priv, dev_addr_t vaddr,
				unsigned long size, struct camb_vmm_iova **pfirst)
{
	struct camb_vmm_iova *iova = NULL, *first = NULL;
	unsigned long remain_size = size, cur_size = 0;
	dev_addr_t cur_addr = 0;
	int ret = 0;

	spin_lock(&vmm_priv->iova.lock);
	cur_addr = vaddr;
	vmm_iova_for_each_in(iova, first, vmm_priv, vaddr, vaddr + size - 1) {
		cur_size = min_t(unsigned long, remain_size, iova->node.end - cur_addr + 1);

		ret = set_vmm_iova_bitmap(iova, cur_addr, cur_size);
		if (ret) {
			spin_unlock(&vmm_priv->iova.lock);
			cn_dev_err("range(%#llx, %#lx) is in use.", cur_addr, cur_size);
			ret = -ENXIO;
			goto failed;
		}

		remain_size -= cur_size;
		if (!remain_size)
			break;

		cur_addr += cur_size;
	}
	spin_unlock(&vmm_priv->iova.lock);

	if (remain_size) {
		cn_dev_err("invalid virtual address(%#llx, %#lx) input", vaddr, size);
		ret = -ENXIO;
		goto failed;
	}

	if (pfirst) *pfirst = first;
	return 0;

failed:
	if (size - remain_size)
		camb_vmm_iova_bitmap_clear(vmm_priv, vaddr, size - remain_size, first);
	return ret;
}

int cn_vmm_mem_address_reserve(u64 tag, unsigned long size, unsigned long align,
				dev_addr_t start, unsigned long flags, dev_addr_t *iova)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct camb_vmm_iova *piova = NULL;
	unsigned long bytes = 0, counts = 0;

	if (!vmm_priv) {
		cn_dev_err("invalid process tags(%#llx) input", tag);
		return -EINVAL;
	}

	if (!IS_VMM_ALIGNED(size)) {
		cn_dev_err("input size(%#lx) is not aligned with %#lx", size,
				   1UL << VMM_MINIMUM_SHIFT);
		return -EINVAL;
	}

	if (align && !(IS_VMM_ALIGNED(align) && is_power_of_2(size2bits(align)))) {
		cn_dev_err("input align(%#lx) is not power of 2 for default alignment:%#lx",
				   align, 1UL << VMM_MINIMUM_SHIFT);
		return -EINVAL;
	}

	if (!align) align = (1UL << VMM_MINIMUM_SHIFT);

	if (!IS_ALIGNED(start, align)) {
		cn_dev_err("input start(%#llx) must be aligned with align(%#lx) input",
				   start, align);
		return -EINVAL;
	}

	counts = size2bits(size);
	bytes = sizeof(struct camb_vmm_iova) + BITS_TO_LONGS(counts) * sizeof(unsigned long);
	piova = cn_kzalloc(bytes, GFP_KERNEL);
	if (!piova) {
		cn_dev_err("alloc virtual address buffer failed");
		return -ENOMEM;
	}

	piova->align = align;
	piova->counts = counts;

	piova->node.start = camb_alloc_iova(__get_iovad(), start, size, align);
	if (!piova->node.start) {
		cn_dev_err("alloc iova start at %#llx failed!", start);
		cn_kfree(piova);
		return -ENOSPC;
	}

	piova->node.end = piova->node.start + size - 1;
	spin_lock(&vmm_priv->iova.lock);
	insert_vmm_iova(vmm_priv, piova);
	spin_unlock(&vmm_priv->iova.lock);

	if (iova)
		*iova = piova->node.start;

	return 0;
}

int cn_vmm_mem_address_free(u64 tag, dev_addr_t addr, unsigned long size)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct camb_vmm_iova *piova = NULL;

	if (!vmm_priv) {
		cn_dev_err("invalid process tags(%#llx) input", tag);
		return -EINVAL;
	}

	if (!IS_VMM_ALIGNED(size) || !IS_VMM_ALIGNED(addr)) {
		cn_dev_err("input size(%#lx) is not aligned with %#lx", size,
				   1UL << VMM_MINIMUM_SHIFT);
		return -EINVAL;
	}

	spin_lock(&vmm_priv->iova.lock);
	piova = search_vmm_iova_compare(vmm_priv, addr, size);
	if (!piova) {
		spin_unlock(&vmm_priv->iova.lock);
		cn_dev_err("params(%#llx, %#lx) is invalid", addr, size);
		return -EINVAL;
	}

	if (!bitmap_empty(piova->bitmap, piova->counts)) {
		spin_unlock(&vmm_priv->iova.lock);
		cn_dev_err("reserved range(%#llx, %#lx) still in use",
				   piova->node.start, vmm_iova_size(piova));
		return -EINVAL;
	}

	delete_vmm_iova(vmm_priv, piova);
	spin_unlock(&vmm_priv->iova.lock);

	camb_free_iova(__get_iovad(), piova->node.start);
	cn_kfree(piova);
	return 0;
}

static int
camb_vmm_create_minfo(u64 tag, struct camb_vmm_iova *piova,
			struct camb_vmm_handle *phandle, dev_addr_t vaddr,
			unsigned long size)
{
	struct mapinfo *minfo = NULL;

	minfo = cn_kzalloc(sizeof(struct mapinfo), GFP_KERNEL);
	if (!minfo) {
		cn_dev_err("alloc mapinfo buffer failed");
		return -ENOMEM;
	}

	camb_init_mapinfo_basic(minfo, phandle->mm_set, 0);
	minfo->tag = tag;
	minfo->mm_priv_data = NULL;
	minfo->udvm_priv = get_udvm_priv_data((struct file *)tag);
	minfo->mem_type = MEM_VMM;
	minfo->is_linear = false;
	minfo->mem_meta.size = size;
	minfo->mem_meta.type = CN_IPU_MEM;
	/* minfo->mem_meta.flag will be set during cu_vmm_set_access called */

	minfo->vmm_info.vaddr = vaddr;
	minfo->vmm_info.piova = piova;
	minfo->vmm_info.phandle = phandle;
	atomic_set(&minfo->vmm_info.isvalid, INVALID);

	insert_mapinfo(NULL, minfo);
	return 0;
}

int cn_vmm_mem_map(u64 tag, dev_addr_t vaddr, unsigned long size,
			unsigned long offset, unsigned long handle)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct camb_vmm_handle *phandle = NULL;
	struct camb_vmm_iova *piova = NULL;
	int ret = 0;

	if (!vmm_priv) {
		cn_dev_err("invalid process tags(%#llx) input", tag);
		return -EINVAL;
	}

	if (!IS_VMM_ALIGNED(size) || !IS_VMM_ALIGNED(vaddr) ||
		!IS_VMM_ALIGNED(offset)) {
		cn_dev_err("input params(%#llx %#lx, %#lx) is not aligned with %#lx",
				   vaddr, size, offset, 1UL << VMM_MINIMUM_SHIFT);
		return -EINVAL;
	}

	ret = camb_vmm_handle_kref_get(vmm_priv, handle, &phandle);
	if (ret)
		return ret;

	if (size != phandle->size) {
		cn_dev_err("input size(%#lx) is not match physical handle size(%#lx)",
				   size, phandle->size);
		ret = -EINVAL;
		goto release_handle;
	}

	ret = camb_vmm_iova_bitmap_set(vmm_priv, vaddr, size, &piova);
	if (ret)
		goto release_handle;

	ret = camb_vmm_create_minfo(tag, piova, phandle, vaddr, size);
	if (ret)
		goto release_bitmap;

	return 0;
release_bitmap:
	camb_vmm_iova_bitmap_clear(vmm_priv, vaddr, size, piova);
release_handle:
	camb_vmm_handle_kref_put(phandle, camb_vmm_mem_release);
	return ret;
}

static int
__vmm_set_access_check(struct mapinfo *pminfo, dev_addr_t vaddr, size_t size)
{
	if (pminfo->virt_addr != vaddr) {
		cn_dev_err("not support input vaddr with offset (%#llx, %#llx)",
				pminfo->virt_addr, vaddr);
		return -ENXIO;
	}

	if (atomic_cmpxchg(&pminfo->free_flag, 0, 1) != 0) {
		cn_dev_err("Addr: %#llx has been freed", pminfo->virt_addr);
		return -ENXIO;
	}

	if (atomic_cmpxchg(&pminfo->refcnt, 1, 0) != 1) {
		atomic_set(&pminfo->free_flag, 0);
		cn_dev_err("Addr: %#llx is in use !", pminfo->virt_addr);
		return -ENXIO;
	}

	return 0;
}

enum {
	SET_ACCESS_DEFAULT = 0x0,
	SET_ACCESS_MAPPED  = 0x1,
	SET_ACCESS_CHANGED = 0x2,
};

struct mapinfo_extra_t {
	struct list_head lnode;
	struct mapinfo *minfo;
	int status;
	unsigned int old_flags;
};

#define list_for_each_minfo_extra(head, _extra, do_release, func) { \
	struct list_head *_pos = NULL, *_tmp = NULL; \
	list_for_each_safe(_pos, _tmp, head) { \
		_extra = list_entry(_pos, struct mapinfo_extra_t, lnode); \
		func; \
		if (do_release) { \
			list_del_init(&_extra->lnode); \
			cn_kfree(_extra); \
		} \
	} \
}

static int
__search_multi_minfos(u64 tag, struct vmm_priv_data *vmm_priv, dev_addr_t vaddr,
		unsigned long size, struct list_head *head, unsigned int *counts,
		int (func)(struct mapinfo *, dev_addr_t, size_t))
{
	struct mapinfo_extra_t *extra = NULL;
	struct mapinfo *minfo = NULL, *first = NULL;
	unsigned long find_vaddr = 0, mapped_size = 0, cur_sz = 0;
	unsigned int find_counts = 0;
	int ret = 0;

	find_vaddr = vaddr;

	spin_lock(&vmm_priv->minfo.minfo_lock);
	read_lock(&vmm_priv->minfo.node_lock);
	vmm_minfo_for_each_in(minfo, first, vmm_priv, vaddr, vaddr + size - 1) {
		ret = func(minfo, find_vaddr, 0);
		if (ret || mapped_size == size)
			goto exit;

		cur_sz = minfo->mem_meta.size;
		extra = cn_kzalloc(sizeof(struct mapinfo_extra_t), GFP_ATOMIC);
		if (!extra) {
			ret = -ENOMEM;
			goto exit;
		}

		extra->minfo = minfo;
		extra->status = SET_ACCESS_DEFAULT;
		extra->old_flags = minfo->mem_meta.flag;
		list_add_tail(&extra->lnode, head);

		mapped_size += cur_sz;
		find_vaddr  += cur_sz;
		find_counts++;
	}
exit:
	read_unlock(&vmm_priv->minfo.node_lock);
	spin_unlock(&vmm_priv->minfo.minfo_lock);

	if (mapped_size != size) {
		cn_dev_err("input set access virtual address range invalid");
		return -ENXIO;
	}

	if (counts) *counts = find_counts;
	return 0;
}

static int
__do_multi_minfos_map_rpc(struct list_head *minfo_extra_list,
			struct cn_mm_set *mm_set, unsigned int prot)
{
	struct camb_vmm_handle *phandle = NULL;
	struct mapinfo_extra_t *extra = NULL;
	unsigned long dev_vaddr = 0;
	unsigned int dev_handle_id = 0;
	int ret = 0;

	list_for_each_minfo_extra(minfo_extra_list, extra, false, {
		struct mapinfo *minfo = extra->minfo;
		phandle = (struct camb_vmm_handle *)minfo->vmm_info.phandle;

		if (atomic_read(&minfo->vmm_info.isvalid) == VALID) {
			/* ignore security and compress bit, which decided by physical handle */
			if ((minfo->mem_meta.flag ^ prot) &
				~((1UL << ATTR_security) | (1UL << ATTR_compress))) {

				dev_vaddr = udvm_get_iova_from_addr(minfo->virt_addr);

				ret = rpc_vmm_mem_modify_prot(minfo->mm_set, dev_vaddr, minfo->mem_meta.size,
									  minfo->mem_meta.flag, prot);
				if (ret) {
					cn_dev_err("modify access for (addr: %#llx, handle: %#lx, size: %#lx) failed",
							   minfo->virt_addr, phandle->handle,
							   minfo->mem_meta.size);
					return ret;
				}

				minfo->mem_meta.flag = prot;
				extra->status = SET_ACCESS_CHANGED;
			}

			continue;
		}

		minfo->mem_meta.flag = prot;

		if (mm_set != minfo->mm_set) {
			cn_dev_err("input set access device is not match memory allocation device");
			return -ERROR_UDVM_INVALID_DEVICE;
		}

		if (HANDLE_FLAG(minfo->vmm_info.phandle, compress) && mm_set->compress_support)
			SET_FLAGS(unsigned int, minfo->mem_meta.flag, ATTR_compress,
					ATTR_compress, 1);

		if (HANDLE_FLAG(minfo->vmm_info.phandle, security))
			SET_FLAGS(unsigned int,minfo->mem_meta.flag, ATTR_security,
					ATTR_security, 1);

		dev_vaddr = udvm_get_iova_from_addr(minfo->virt_addr);
		dev_handle_id = udvm_get_iova_from_addr(phandle->handle);
		ret = rpc_vmm_mem_map(minfo->mm_set, dev_vaddr, minfo->mem_meta.size,
					dev_handle_id, minfo->mem_meta.flag);
		if (ret) {
			cn_dev_err("set access for (addr: %#llx, handle: %#lx, size: %#lx) failed",
					minfo->virt_addr, phandle->handle, minfo->mem_meta.size);
			return ret;
		}

		atomic_set(&minfo->vmm_info.isvalid, VALID);
		extra->status = SET_ACCESS_MAPPED;
	})

	return 0;
}

int cn_vmm_set_access(u64 tag, dev_addr_t vaddr, unsigned long size,
				unsigned int prot, unsigned int dev_id)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct list_head minfo_extra_list;
	struct mapinfo_extra_t *extra = NULL;
	struct cn_mm_set *mm_set = NULL;
	int ret = 0;

	if (!vmm_priv) {
		cn_dev_err("invalid process tags(%#llx) input", tag);
		return -EINVAL;
	}

	if (!IS_VMM_ALIGNED(size) || !IS_VMM_ALIGNED(vaddr)) {
		cn_dev_err("input size(%#lx) is not aligned with %#lx", size,
				   1UL << VMM_MINIMUM_SHIFT);
		return -EINVAL;
	}

	mm_set = __get_mmset_with_index(dev_id);
	if (IS_ERR_OR_NULL(mm_set)) {
		cn_dev_err("input invalid device id %d", dev_id);
		return -EINVAL;
	}

	/* 1. find mapinfo for set_access */
	INIT_LIST_HEAD(&minfo_extra_list);
	ret = __search_multi_minfos(tag, vmm_priv, vaddr, size, &minfo_extra_list,
					NULL, __vmm_set_access_check);
	if (ret)
		goto release_minfos;

	/* set each mapinfo's access */
	ret = __do_multi_minfos_map_rpc(&minfo_extra_list, mm_set, prot);
	if (ret)
		goto release_minfos;

	list_for_each_minfo_extra(&minfo_extra_list, extra, true, {
		atomic_inc(&extra->minfo->refcnt);
		atomic_set(&extra->minfo->free_flag, 0);
	})

	return 0;

release_minfos:
	list_for_each_minfo_extra(&minfo_extra_list, extra, true, {
		struct mapinfo *pminfo = extra->minfo;
		if (extra->status == SET_ACCESS_MAPPED) {
			rpc_vmm_mem_unmap(pminfo->mm_set, udvm_get_iova_from_addr(pminfo->virt_addr),
							pminfo->mem_meta.size);
			pminfo->mem_meta.flag = 0;
			atomic_set(&pminfo->vmm_info.isvalid, INVALID);
		} else if (extra->status == SET_ACCESS_CHANGED) {
			/* FIXME: reset access as old flags */
		}

		atomic_inc(&pminfo->refcnt);
		atomic_set(&pminfo->free_flag, 0);
	})

	return ret;
}

static int
__vmm_mem_unmap_check(struct mapinfo *pminfo, dev_addr_t vaddr, size_t size)
{
	if (pminfo->virt_addr != vaddr) {
		cn_dev_err("not support input vaddr with offset (%#llx, %#llx)",
				pminfo->virt_addr, vaddr);
		return -ENXIO;
	}

	if (atomic_cmpxchg(&pminfo->free_flag, 0, 1) != 0) {
		cn_dev_err("Addr: %#llx has been unmapped", pminfo->virt_addr);
		return -ENXIO;
	}

	return 0;
}

int vmm_minfo_release(struct mapinfo *pminfo)
{
	struct camb_vmm_handle *phandle = pminfo->vmm_info.phandle;
	struct camb_vmm_iova *piova = pminfo->vmm_info.piova;
	struct vmm_priv_data *vmm_priv =
		((struct udvm_priv_data *)(pminfo->udvm_priv))->vmm_priv;

	unsigned long addr = udvm_get_iova_from_addr(pminfo->virt_addr);

	if (atomic_read(&pminfo->vmm_info.isvalid) == VALID)
		rpc_vmm_mem_unmap(pminfo->mm_set, addr, pminfo->mem_meta.size);

	camb_vmm_handle_kref_put(phandle, camb_vmm_mem_release);
	camb_vmm_iova_bitmap_clear(vmm_priv, pminfo->virt_addr,
					pminfo->mem_meta.size, piova);

	return 0;
}

int cn_vmm_mem_unmap(u64 tag, dev_addr_t vaddr, unsigned long size)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct list_head minfo_extra_list;
	struct mapinfo_extra_t *extra = NULL;
	int ret = 0;

	if (!vmm_priv) {
		cn_dev_err("invalid process tags(%#llx) input", tag);
		return -EINVAL;
	}

	if (!IS_VMM_ALIGNED(size) || !IS_VMM_ALIGNED(vaddr)) {
		cn_dev_err("input size(%#lx) is not aligned with %#lx", size,
				   1UL << VMM_MINIMUM_SHIFT);
		return -EINVAL;
	}

	INIT_LIST_HEAD(&minfo_extra_list);
	ret = __search_multi_minfos(tag, vmm_priv, vaddr, size, &minfo_extra_list,
					NULL, __vmm_mem_unmap_check);
	if (ret)
		goto release_minfos;

	list_for_each_minfo_extra(&minfo_extra_list, extra, true, {
		camb_kref_put(extra->minfo, camb_mem_release);
	})

	return 0;

release_minfos:
	list_for_each_minfo_extra(&minfo_extra_list, extra, true, {
		atomic_set(&extra->minfo->free_flag, 0);
	})

	return ret;
}

static int
vmm_attribute_get_access(u64 tag, dev_addr_t iova, unsigned int dev_id,
				unsigned long *flags)
{
	struct mapinfo *pminfo = NULL;
	int ret = 0;

	if (!flags)
		return -EINVAL;

	ret = camb_kref_get(tag, iova, &pminfo, NULL);
	if (ret < 0) {
		cn_dev_err("invalid iova(%#llx) input", iova);
		return -ENXIO;
	}

	if (pminfo->mem_type != MEM_VMM) {
		camb_kref_put(pminfo, camb_mem_release);
		cn_dev_err("input iova (%#llx) not from vmm interfaces", iova);
		return -ENXIO;
	}

	if (dev_id != get_index_with_mmset(pminfo->mm_set)) {
		camb_kref_put(pminfo, camb_mem_release);
		return -ERROR_UDVM_INVALID_DEVICE;
	}

	*flags = pminfo->mem_meta.flag &
		~((1UL << ATTR_security) | (1UL << ATTR_compress));

	camb_kref_put(pminfo, camb_mem_release);
	return 0;
}

/**
 * NOTE: retain_handle will increase handle's refcnt, and returned handle
 * support to be released by calling cn_vmm_mem_release.
 **/
static int
vmm_attribute_retain_handle(u64 tag, dev_addr_t iova, unsigned long *handle)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct mapinfo *pminfo = NULL;
	struct camb_vmm_handle *phandle = NULL, *tmp = NULL;
	int ret = 0;

	if (!vmm_priv) {
		cn_dev_err("invalid process tags(%#llx) input", tag);
		return -EINVAL;
	}

	if (!handle)
		return -EINVAL;

	ret = camb_kref_get_without_vmm_check(tag, iova, &pminfo, NULL);
	if (ret < 0) {
		cn_dev_err("invalid iova(%#llx) input", iova);
		return -ENXIO;
	}

	if (pminfo->mem_type != MEM_VMM) {
		camb_kref_put(pminfo, camb_mem_release);
		cn_dev_err("input iova (%#llx) not from vmm interfaces", iova);
		return -ENXIO;
	}

	phandle = pminfo->vmm_info.phandle;
	ret = camb_vmm_handle_kref_get(vmm_priv, phandle->handle, &tmp);
	if (ret) {
		camb_kref_put(pminfo, camb_mem_release);
		cn_dev_err("increase handle's reference counts failed(%d)", ret);
		return ret;
	}

	BUG_ON(tmp != phandle);

	atomic_inc(&phandle->release_refcnt);
	*handle = phandle->handle;
	camb_kref_put(pminfo, camb_mem_release);

	return 0;
}

static int
vmm_attribute_get_prop(u64 tag, unsigned long handle, unsigned long *flags)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct camb_vmm_handle *phandle = NULL;

	if (!flags) {
		cn_dev_err("invalid flags buffer input");
		return -EINVAL;
	}

	*flags = 0;

	if (!vmm_priv) {
		cn_dev_err("invalid process tags(%#llx) input", tag);
		return -EINVAL;
	}

	rcu_read_lock();
	phandle = radix_tree_lookup(&vmm_priv->phys.ra_root, handle);
	rcu_read_unlock();

	if (!phandle) {
		cn_dev_err("invalid handle(%#lx) input", handle);
		return -EINVAL;
	}

	VMM_SET_HANDLE_PROP_DATA(*flags, FLAGS, phandle->flags);
	VMM_SET_HANDLE_PROP_DATA(*flags, LOCATION_ID, get_index_with_mmset(phandle->mm_set));
	VMM_SET_HANDLE_PROP_DATA(*flags, LOCATION_TYPE, 0);

	return 0;
}

static int
vmm_attribute_get_granularity(u64 tag, unsigned long type, unsigned long *granu)
{
	int ret = 0;

	if (!granu) return -EINVAL;

	*granu = 0;

	switch (type) {
	case UDVM_VMM_GRANULARITY_MINIMUM:
	case UDVM_VMM_GRANULARITY_RECOMMENDED:
		*granu = (1UL << VMM_MINIMUM_SHIFT);
		break;
	default: ret = -EINVAL;
	}

	return ret;
}

int cn_vmm_get_attribute(u64 tag, unsigned long *args, unsigned int nums,
				unsigned int type, unsigned long *data)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	int ret = -EINVAL;

	if (!vmm_priv) {
		cn_dev_err("invalid process tags(%#llx) input", tag);
		return -EINVAL;
	}

	switch (type) {
	case UDVM_VMM_ATTRIBUTE_GRANULARITY:
		if (nums == 1)
			ret = vmm_attribute_get_granularity(tag, args[0], data);
		break;
	case UDVM_VMM_ATTRIBUTE_HANDLE_PROP:
		if (nums == 1)
			ret = vmm_attribute_get_prop(tag, args[0], data);
		break;
	case UDVM_VMM_ATTRIBUTE_POINTER_ACCESS:
		if (nums == 2)
			ret = vmm_attribute_get_access(tag, args[0], args[1], data);
		break;
	case UDVM_VMM_ATTRIBUTE_POINTER_HANDLE:
		if (nums == 1)
			ret = vmm_attribute_retain_handle(tag, args[0], data);
		break;
	default :
		cn_dev_err("invalid attribute type(%d) input", type);
		return -EINVAL;
	}

	return ret;
}

/**
 * Check if vmm reserved iova range is useable for input device!
 **/
int camb_vmm_get_reserved_range(struct mapinfo *pminfo, dev_addr_t *base,
					unsigned long *size)
{
	struct camb_vmm_iova *iova = NULL;

	if (!pminfo || pminfo->mem_type != MEM_VMM)
		return 0;

	iova = pminfo->vmm_info.piova;

	if (base)
		*base = iova->node.start;

	if (size)
		*size = vmm_iova_size(iova);

	return 0;
}

/* vmm process share interface */
struct vmm_anon_priv {
	struct cn_mm_set *mm_set;
	unsigned long handle;
	unsigned int flags;
	unsigned long size;
};

static int camb_vmm_anon_share_release(struct inode *inode, struct file *fp)
{
	struct vmm_anon_priv *priv = fp->private_data;

	rpc_vmm_mem_release(priv->mm_set, udvm_get_iova_from_addr(priv->handle));

	cn_kfree(priv);

	return 0;
}

static const struct file_operations cn_vmm_anon_share_fops = {
	.owner = THIS_MODULE,
	.release = camb_vmm_anon_share_release,
};

static int
__vmm_share_create_and_bind(struct camb_vmm_handle *phandle, unsigned int *share_handle)
{
	struct vmm_anon_priv *priv = NULL;
	int fd = -1;
	struct file *file = NULL;

	priv = cn_kzalloc(sizeof(struct vmm_anon_priv), GFP_KERNEL);
	if (!priv) {
		cn_dev_err("create vmm_anon_priv buffer failed!");
		return -ENOMEM;
	}

	priv->mm_set = phandle->mm_set;
	priv->handle = phandle->handle;
	priv->size   = phandle->size;
	priv->flags  = phandle->flags;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		cn_dev_err("try to get unused file descriptor failed");
		cn_kfree(priv);
		return fd;
	}

	file = anon_inode_getfile("[cambricon_vmm_share]", &cn_vmm_anon_share_fops, priv, O_CLOEXEC);
	if (IS_ERR(file)) {
		cn_dev_err("try to create anon file failed");
		put_unused_fd(fd);
		cn_kfree(priv);
		return PTR_ERR(file);
	}

	fd_install(fd, file);

	*share_handle = fd;

	return 0;
}

int cn_vmm_export_share_handle(u64 tag, unsigned long handle, unsigned int type,
					unsigned int *share_handle)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct cn_mm_set *mm_set = NULL;
	struct camb_vmm_handle *phandle = NULL;
	int ret = 0;

	if (type != VMM_HANDLE_TYPE_FILE_DESCRIPTOR) {
		cn_dev_err("invalid shareable handle type intput");
		return -EINVAL;
	}

	/* handle validate check */
	ret = camb_vmm_handle_kref_get(vmm_priv, handle, &phandle);
	if (ret)
		return ret;

	if (!HANDLE_FLAG(phandle, shared)) {
		camb_vmm_handle_kref_put(phandle, camb_vmm_mem_release);
		return -EINVAL;
	}

	/* rpc handle refcnt increase */
	mm_set = phandle->mm_set;
	ret = rpc_vmm_mem_handle_get(mm_set, udvm_get_iova_from_addr(phandle->handle));
	if (ret) {
		camb_vmm_handle_kref_put(phandle, camb_vmm_mem_release);
		return ret;
	}

	/* create shareable handle */
	ret = __vmm_share_create_and_bind(phandle, share_handle);
	if (ret) {
		rpc_vmm_mem_release(mm_set, udvm_get_iova_from_addr(phandle->handle));
		camb_vmm_handle_kref_put(phandle, camb_vmm_mem_release);
		return ret;
	}

	camb_vmm_handle_kref_put(phandle, camb_vmm_mem_release);
	return 0;
}

int cn_vmm_import_share_handle(u64 tag, unsigned int share_handle,
			unsigned int type, unsigned long *handle)
{
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	struct file *fp = udvm_fcheck(share_handle);
	struct vmm_anon_priv *priv = NULL;
	struct camb_vmm_handle *phandle = NULL;
	int ret = 0;

	if (type != VMM_HANDLE_TYPE_FILE_DESCRIPTOR) {
		cn_dev_err("invalid shareable handle type intput");
		return -EINVAL;
	}

	if (!fp || (fp->f_op != &cn_vmm_anon_share_fops)) {
		cn_dev_err("invalid vmm share file descriptor intput");
		return -EINVAL;
	}

	priv = (struct vmm_anon_priv *)fp->private_data;

	phandle = cn_kzalloc(sizeof(struct camb_vmm_handle), GFP_KERNEL);
	if (!phandle) {
		cn_dev_err("alloc physical handle buffer failed");
		return -ENOMEM;
	}

	phandle->size = priv->size;
	phandle->flags = priv->flags;
	phandle->mm_set = priv->mm_set;
	phandle->handle = priv->handle;
	phandle->vmm_priv = vmm_priv;
	atomic_set(&phandle->refcnt, 1);
	atomic_set(&phandle->release_refcnt, 1);
	phandle->tag = tag;
	phandle->active_ns = task_active_pid_ns(current);

	ret = rpc_vmm_mem_handle_get(priv->mm_set, udvm_get_iova_from_addr(priv->handle));
	if (ret) {
		cn_kfree(phandle);
		return ret;
	}

	spin_lock(&vmm_priv->phys.lock);
	ret = radix_tree_insert(&vmm_priv->phys.ra_root, phandle->handle,
				(void *)phandle);
	if (likely(!ret)) list_add(&phandle->node, &vmm_priv->phys.list);
	spin_unlock(&vmm_priv->phys.lock);

	if (ret) {
		rpc_vmm_mem_release(phandle->mm_set, phandle->handle);
		cn_kfree(phandle);
		return ret;
	}

	if (handle)
		*handle = phandle->handle;

	return 0;
}
/* vmm process share interface */

static int
__vmm_minfo_kref_get_check(int card_id, int base_flag,
		struct mapinfo *minfo, dev_addr_t addr, unsigned long size,
		int (kref_get)(struct mapinfo *, dev_addr_t, size_t))
{
	struct cn_core_set *core = cn_core_get_with_idx(card_id);
	/* NOTE: make sure input range belongs to the same device */
	if (get_index_with_mmset(minfo->mm_set) != card_id) {
		cn_dev_core_err(core, "not support access cross different devices(first:%d, cur:%d)",
				   card_id, get_index_with_mmset(minfo->mm_set));
		return -ENXIO;
	}

	if (atomic_read(&minfo->vmm_info.isvalid) != VALID) {
		cn_dev_core_err(core, "(%#llx, %#lx) is still not ready for access.",
					addr, size);
		return -ENXIO;
	}

	if (base_flag != minfo->mem_meta.flag) {
		cn_dev_core_err(core, "not support access cross different prot(base:%#x, cur:%#x)",
					base_flag, minfo->mem_meta.flag);
		return -ENXIO;
	}

	if (kref_get && kref_get(minfo, addr, size)) {
		cn_dev_core_err(core, "(%#llx, %#lx) failed to adjust reference count.",
					addr, size);
		return -ENXIO;
	}

	return 0;
}

struct mapinfo *
camb_vmm_minfo_kref_get_range(u64 tag, dev_addr_t vaddr, unsigned long size,
			int (kref_get)(struct mapinfo *, dev_addr_t, size_t ))
{
	int first_card_id = -1, base_flag = -1, ret = 0;
	struct vmm_priv_data *vmm_priv = __get_vmm_priv(tag);
	unsigned long remain_size = size, cur_size = 0;
	struct mapinfo *first = NULL, *minfo = NULL;
	dev_addr_t cur_addr = vaddr;

	if (!vmm_priv) {
		cn_dev_err("invalid process tags(%#llx) input", tag);
		return ERR_PTR(-EINVAL);
	}

	spin_lock(&vmm_priv->minfo.minfo_lock);
	read_lock(&vmm_priv->minfo.node_lock);
	vmm_minfo_for_each_in(minfo, first, vmm_priv, vaddr, vaddr + size - 1) {
		cur_size = min_t(unsigned long, remain_size, minfo->rnode.end - cur_addr + 1);

		if (first_card_id == -1)
			first_card_id = get_index_with_mmset(minfo->mm_set);

		if (base_flag == -1)
			base_flag = minfo->mem_meta.flag;

		ret = __vmm_minfo_kref_get_check(first_card_id, base_flag, minfo,
					cur_addr, cur_size, kref_get);
		if (ret) {
			read_unlock(&vmm_priv->minfo.node_lock);
			spin_unlock(&vmm_priv->minfo.minfo_lock);
			goto failed;
		}

		remain_size -= cur_size;
		if (!remain_size)
			break;

		cur_addr += cur_size;
	}
	read_unlock(&vmm_priv->minfo.node_lock);
	spin_unlock(&vmm_priv->minfo.minfo_lock);

	if (remain_size) {
		cn_dev_err("OutOfBound: input area(%#llx, %#lx) is not match valid area(%#llx, %#lx)",
				vaddr, size, vaddr, size - remain_size);
		ret = -ENXIO;
		goto failed;
	}

	return first;

failed:
	/* NOTE: if first is invalid, remain_size is equal to size */
	if (size - remain_size) {
		camb_vmm_minfo_kref_put_range(first, vaddr, size - remain_size,
				camb_mem_release);
	}

	return ERR_PTR(ret);
}

unsigned int
camb_vmm_minfo_kref_put_range(struct mapinfo *first, dev_addr_t vaddr,
			unsigned long size, int (release)(struct mapinfo *))
{
	struct vmm_priv_data *vmm_priv = NULL;
	struct udvm_priv_data *udvm_priv =
		(struct udvm_priv_data *)(first->udvm_priv);

	struct mapinfo *minfo = NULL, *next = NULL;
	unsigned long remain_size = size, cur_size = 0;
	dev_addr_t cur_addr = vaddr;
	int ret = 0;
	struct list_head remove_list;

	if (!udvm_priv) {
		cn_dev_err("invalid mapinfo (%#llx) for vmm release", first->virt_addr);
		return 0;
	}

	vmm_priv = udvm_priv->vmm_priv;
	INIT_LIST_HEAD(&remove_list);

	spin_lock(&vmm_priv->minfo.minfo_lock);
	write_lock(&vmm_priv->minfo.node_lock);
	vmm_minfo_for_each_in_first_safe(minfo, next, first, vmm_priv, vaddr + size - 1) {
		cur_size = min_t(unsigned long, remain_size, minfo->rnode.end - cur_addr + 1);

		/* Already locked in node_lock. Do not need call delete_vmm_mapinfo which will get node_lock again. */
		if (atomic_sub_and_test(1, &minfo->refcnt)) {
			camb_range_tree_delete(&vmm_priv->minfo.range_tree, &minfo->rnode);
			list_add(&minfo->rnode.lnode, &remove_list);
		}

		remain_size -= cur_size;
		if (!remain_size)
			break;

		cur_addr += cur_size;
	}
	write_unlock(&vmm_priv->minfo.node_lock);
	spin_unlock(&vmm_priv->minfo.minfo_lock);

	list_for_each_entry_safe(minfo, next, &remove_list, rnode.lnode) {
		list_del(&minfo->rnode.lnode);
		ret = release(minfo);
		if (ret == -EAGAIN) {
			spin_lock(&vmm_priv->minfo.minfo_lock);
			atomic_inc(&minfo->refcnt);
			atomic_set(&minfo->free_flag, 0);
			insert_vmm_mapinfo(vmm_priv, minfo);
			spin_unlock(&vmm_priv->minfo.minfo_lock);
		}
	}

	return 0;
}

int camb_vmm_support_check(struct cn_mm_set *mm_set)
{
	struct camb_vmm_set *vmm_set = __get_vmm_set();
	unsigned long addr = udvm_get_iova_from_addr(vmm_set->base);
	int ret = 0;

	ret = rpc_vmm_mem_check_support(mm_set, addr, vmm_set->total_size);

	mm_set->vmm_enable &= ret;

	cn_dev_core_info((struct cn_core_set *)mm_set->core, "VMM Support status: %s",
				mm_set->vmm_enable ? "ENABLE" : "DISABLE");
	return 0;
}

int camb_mem_vmm_priv_init(struct vmm_priv_data **pvmm_priv)
{
	struct vmm_priv_data *vmm_priv;

	vmm_priv = cn_kzalloc(sizeof(struct vmm_priv_data), GFP_KERNEL);
	if (!vmm_priv) {
		cn_dev_err("create vmm_priv_data failed");
		return -ENOMEM;
	}

	/* 1. init device virtual address management structure */
	camb_range_tree_init(&vmm_priv->iova.range_tree);
	spin_lock_init(&vmm_priv->iova.lock);

	/* 2. init physical handle management structure */
	INIT_RADIX_TREE(&vmm_priv->phys.ra_root, GFP_ATOMIC);
	INIT_LIST_HEAD(&vmm_priv->phys.list);
	spin_lock_init(&vmm_priv->phys.lock);
	/* pid_info_node do lazy init */

	/* 3. init mapinfo management structure */
	camb_range_tree_init(&vmm_priv->minfo.range_tree);
	rwlock_init(&vmm_priv->minfo.node_lock);
	spin_lock_init(&vmm_priv->minfo.minfo_lock);
	mutex_init(&vmm_priv->minfo.uva_lock);

	if (pvmm_priv) *pvmm_priv = vmm_priv;
	return 0;
}

static void __vmm_priv_handle_release(struct vmm_priv_data *vmm_priv)
{
	struct camb_vmm_handle *tmp, *pos, *val;
	struct list_head handle_rm_list;
	int bug_on = 0, i = 0;

	INIT_LIST_HEAD(&handle_rm_list);
	/* physical handle resource release*/
	if (!cn_radix_tree_empty(&vmm_priv->phys.ra_root)) {
		spin_lock(&vmm_priv->phys.lock);
		list_for_each_entry_safe(pos, tmp, &vmm_priv->phys.list, node) {
			val = radix_tree_delete(&vmm_priv->phys.ra_root, pos->handle);
			if (val != pos) {
				bug_on = 1;
				break;
			}

			list_move(&pos->node, &handle_rm_list);
		}
		spin_unlock(&vmm_priv->phys.lock);

		BUG_ON(bug_on);

		list_for_each_entry_safe(pos, tmp, &handle_rm_list, node) {
			list_del_init(&pos->node);
			camb_vmm_mem_release(pos);
		}
	}

	for (i = 0; i < MAX_FUNCTION_NUM; i++) {
		if (vmm_priv->phys.pid_infos[i]) {
			struct pid_info_s *pid_info = vmm_priv->phys.pid_infos[i];
			struct cn_mm_set *mm_set =
				(struct cn_mm_set *)__get_mmset_with_index(i);

			put_pid(pid_info->taskpid);
			spin_lock(&mm_set->vmm_pid_lock);
			list_del_init(&pid_info->pid_list);
			spin_unlock(&mm_set->vmm_pid_lock);

			cn_kfree(pid_info);
			vmm_priv->phys.pid_infos[i] = NULL;
		}
	}
}

static void __vmm_priv_iova_release(struct vmm_priv_data *vmm_priv)
{
	struct range_tree_node_t *node = NULL, *next = NULL;
	struct camb_vmm_iova *iova;
	int bug_on = 0;

	spin_lock(&vmm_priv->iova.lock);
	camb_range_tree_for_each_safe(node, next, &vmm_priv->iova.range_tree) {
		iova = get_vmm_iova(node);
		if (!bitmap_empty(iova->bitmap, iova->counts)) {
			bug_on = 1;
			break;
		}

		camb_range_tree_delete(&vmm_priv->iova.range_tree, node);
		spin_unlock(&vmm_priv->iova.lock);

		camb_free_iova(__get_iovad(), node->start);
		cn_kfree(iova);

		spin_lock(&vmm_priv->iova.lock);
	}
	spin_unlock(&vmm_priv->iova.lock);

	BUG_ON(bug_on);

	/* TODO: Other release task */
}

static void __vmm_priv_minfo_release(struct vmm_priv_data *vmm_priv)
{
	struct mapinfo *pminfo = NULL;

	read_lock(&vmm_priv->minfo.node_lock);
	while (!camb_range_tree_empty(&vmm_priv->minfo.range_tree)) {
		pminfo =
			get_mapinfo(camb_range_tree_first(&vmm_priv->minfo.range_tree));
		read_unlock(&vmm_priv->minfo.node_lock);

		mapinfo_release(pminfo);

		read_lock(&vmm_priv->minfo.node_lock);
	}
	read_unlock(&vmm_priv->minfo.node_lock);
}

/* called vmm_priv_exit must make sure async task is finished */
void camb_mem_vmm_priv_release(struct vmm_priv_data *vmm_priv)
{

	if (!vmm_priv) return;

	__vmm_priv_minfo_release(vmm_priv);
	__vmm_priv_handle_release(vmm_priv);
	__vmm_priv_iova_release(vmm_priv);
	cn_kfree(vmm_priv);
}

int cn_mem_vmm_process_release(struct cn_core_set *core)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)core->mm_set;
	struct pid_info_s *pid_info_node;
	struct task_struct *task = NULL;

	spin_lock(&mm_set->vmm_pid_lock);
	list_for_each_entry(pid_info_node, &mm_set->vmm_pid_head, pid_list) {
		task = get_pid_task(pid_info_node->taskpid, PIDTYPE_PID);
		if (task) {
			cn_dev_core_info(core,
					"Killing user processes, open count : %d", core->open_count);
			send_sig(SIGKILL, task, 1);
			put_task_struct(task);
		}
	}
	spin_unlock(&mm_set->vmm_pid_lock);
	return 0;
}

int cn_mem_get_vmm_pid_info(void *pcore, int pid, u64 *vir_usedsize, u64 *phy_usedsize)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = (struct cn_mm_set *)core->mm_set;
	struct pid_info_s *pid_info_node;
	struct pid_info_s tmp;
	int current_pid = 0;

	tmp.tgid = current->tgid;
	tmp.active_ns = task_active_pid_ns(current);
	tmp.active_pid = task_tgid_nr_ns(current, tmp.active_ns);

	spin_lock(&mm_set->vmm_pid_lock);
	list_for_each_entry(pid_info_node, &mm_set->vmm_pid_head, pid_list) {
		/* to avoid diff dockers has same pid, check active_ns first */
		if (cn_check_curproc_is_docker(&tmp) && tmp.active_ns != pid_info_node->active_ns)
			continue;
		if (cn_check_curproc_is_docker(&tmp)) {
			current_pid = pid_info_node->active_pid;
		} else {
			current_pid = pid_info_node->tgid;
		}

		if (current_pid == pid) { /* each process only have single vmm pid_info_node */
			if (vir_usedsize)
				*vir_usedsize += (pid_info_node->vir_usedsize >> 10);

			if (phy_usedsize)
				*phy_usedsize += (pid_info_node->phy_usedsize >> 10);

			break;
		}
	}
	spin_unlock(&mm_set->vmm_pid_lock);
	return 0;
}

int camb_vmm_init(struct camb_vmm_set *vmm_set)
{
	struct camb_iova_domain *iovad;

	vmm_set->base       = set_udvm_address(MLU_CARD_IDX_MASK, VMM_IOVA_BASE, UDVM_ADDR_VMM);
	vmm_set->total_size = VMM_IOVA_SIZE;
	vmm_set->shift      = VMM_MINIMUM_SHIFT;

	iovad = cn_kzalloc(sizeof(struct camb_iova_domain), GFP_KERNEL);
	if (!iovad) {
		cn_dev_err("alloc buffer for iova allocator failed");
		return -ENOMEM;
	}

	camb_create_iova_allocator(iovad, vmm_set->base >> vmm_set->shift,
					(vmm_set->base + vmm_set->total_size) >> vmm_set->shift,
					1UL << vmm_set->shift);

	cn_dev_info("VMM pool Init:(%px) start:%#llx, size:%#lx, shift:%d", vmm_set,
				vmm_set->base, vmm_set->total_size, vmm_set->shift);
	vmm_set->allocator = (void *)iovad;
	return 0;
}

void camb_vmm_exit(struct camb_vmm_set *vmm_set)
{
	if (vmm_set->allocator) {
		camb_destroy_iova_allocator((struct camb_iova_domain *)vmm_set->allocator);
		cn_kfree(vmm_set->allocator);
		vmm_set->allocator = NULL;
	}
}
