/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2021 Cambricon, Inc. All rights reserved.
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
#include "cndrv_udvm_usr.h" /* ioctl command and structure */
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif

#define CN_UVA_MAP_MODE_SHIFT (16)
#define CN_UVA_MAP_MODE_WIDTH (1)
#define CN_UVA_MAP_MODE_MASK (((1 << CN_UVA_MAP_MODE_WIDTH) - 1) << CN_UVA_MAP_MODE_SHIFT)
#define CN_UVA_MAP_MODE_BY_SIZE (0)
#define CN_UVA_MAP_MODE_ALL_IOVA (1)

#define CN_UVA_MAP_CACHE_SHIFT (0)
#define CN_UVA_MAP_CACHE_WIDTH (1)
#define CN_UVA_MAP_CACHE_MASK (((1 << CN_UVA_MAP_CACHE_WIDTH) - 1) << CN_UVA_MAP_CACHE_SHIFT)
#define CN_UVA_MAP_CACHE_NO_CACHE (0)
#define CN_UVA_MAP_CACHE_CACHE (1)

#ifdef CONFIG_CNDRV_EDGE
int map_va_vma(struct file *fp, __u64 size, __u64 *uva,
		struct vm_area_struct **uvma)
{
	__u64 va = 0;
	struct vm_area_struct *vma = NULL;

	if (fp == NULL || uva == NULL || uvma == NULL) {
		return -EINVAL;
	}

	if (size % PAGE_SIZE) {
		cn_dev_err("size 0x%llx not aligned with PAGE_SIZE: 0x%lx.",
			size, PAGE_SIZE);
		return -EINVAL;
	}

	va = vm_mmap(fp, 0, size, PROT_READ | PROT_WRITE, MAP_SHARED, 0);
	if (IS_ERR_VALUE(va)) {
		cn_dev_err("vm_mmap error.%lld",va);
		return va;
	}

	cn_mmap_write_lock(current->mm);
	vma = find_vma(current->mm, va);
	if (!vma) {
		cn_dev_err("mem alloc find vma is NULL.");
		cn_mmap_write_unlock(current->mm);
		vm_munmap(va, size);
		return -EINVAL;
	}
	/* zap_vma_ptes only support VM_PFNMAP */
	vma->vm_flags |= VM_SPECIAL;
	cn_mmap_write_unlock(current->mm);

	*uva = va;
	*uvma = vma;

	return 0;
}

int unmap_va_vma(__u64 *uva, __u64 *size, int len)
{
	int i = 0;

	if (uva == NULL || size == NULL) {
		return -EINVAL;
	}

	/* It's possible meta is void */
	for (i = 0; i < len; i++) {
		if (uva[i]) {
			vm_munmap(uva[i], size[i]);
		}
	}

	return 0;
}

int phy_map_user(struct sg_table *table, struct vm_area_struct *vma)
{
	int i;
	int ret;
	struct scatterlist *sg;
	unsigned long addr = 0;
	unsigned long offset = 0;

	if (table == NULL || vma == NULL) {
		return -EINVAL;
	}

	addr = vma->vm_start;
	offset = vma->vm_pgoff * PAGE_SIZE;

	for_each_sg(table->sgl, sg, table->nents, i) {
		struct page *page = sg_page(sg);
		unsigned long remainder = vma->vm_end - addr;
		unsigned long len = sg->length;

		if (offset >= sg->length) {
			offset -= sg->length;
			continue;
		} else if (offset) {
			page += offset / PAGE_SIZE;
			len = sg->length - offset;
			offset = 0;
		}
		len = min(len, remainder);
		/* DRIVER-4507 BUG fix: clear ptes before remap_pfn_range */
		//zap_vma_ptes(vma, addr, len);
		cn_mmap_write_lock(vma->vm_mm);
		ret = remap_pfn_range(vma, addr, page_to_pfn(page), len,
				vma->vm_page_prot);
		cn_mmap_write_unlock(vma->vm_mm);
		if (ret)
			return ret;
		addr += len;
		if (addr >= vma->vm_end) {
			return 0;
		}
	}

	return 0;
}
#endif

unsigned long get_size_from_table(struct sg_table *table)
{
	unsigned long size = 0;
	struct scatterlist *sg = NULL;
	int i = 0;

	if (table == NULL) {
		return 0;
	}

	for_each_sg(table->sgl, sg, table->nents, i) {
		size += sg->length;
	}

	return size;
}

#if (KERNEL_VERSION(5, 8, 0) > LINUX_VERSION_CODE)
static void *camb_mem_vmap(struct sg_table *table, pgprot_t prot)
{
	struct scatterlist *sg;
	int i, j;
	int npages = 0;
	struct page **pages = NULL;
	struct page **tmp = NULL;

	struct vm_struct *area;
	unsigned long size;

	npages = PAGE_ALIGN(get_size_from_table(table)) / PAGE_SIZE;
	pages = vmalloc(sizeof(struct page *) * npages);
	tmp = pages;

	if (!pages)
		return ERR_PTR(-ENOMEM);

	for_each_sg(table->sgl, sg, table->nents, i) {
		int npages_this_entry = PAGE_ALIGN(sg->length) / PAGE_SIZE;
		struct page *page = sg_page(sg);

		BUG_ON(i >= npages);
		for (j = 0; j < npages_this_entry; j++)
			*(tmp++) = page++;
	}

	might_sleep();
	size = (unsigned long)npages << PAGE_SHIFT;
	area = __get_vm_area(size, VM_MAP, VMALLOC_START, VMALLOC_END);
	if (!area) {
		vfree(pages);
		return NULL;
	}

	if (map_vm_area(area, prot, pages)) {
		vunmap(area->addr);
		vfree(pages);
		return NULL;
	}

	vfree(pages);

	return area->addr;
}
#else
static void *camb_mem_vmap(struct sg_table *table, pgprot_t prot)
{
	struct scatterlist *sg;
	unsigned long stack[32], *pfns = stack, i = 0, j = 0;
	unsigned long *tmp;
	unsigned long n_pfn;
	unsigned long phy;
	void *vaddr = NULL;

	n_pfn = PAGE_ALIGN(get_size_from_table(table)) / PAGE_SIZE;
	if (n_pfn > ARRAY_SIZE(stack)) {
		/* Too big for stack -- allocate temporary array instead */
		pfns = kvmalloc_array(n_pfn, sizeof(*pfns), GFP_KERNEL);
		if (!pfns)
			return NULL;
	}

	tmp = pfns;

	for_each_sg(table->sgl, sg, table->nents, i) {
		int npages_this_entry = PAGE_ALIGN(sg->length) / PAGE_SIZE;
		phy = sg_phys(sg);

		for (j = 0; j < npages_this_entry; j++) {
			*(tmp++) = phy >> PAGE_SHIFT;
			phy += PAGE_SIZE;
		}
	}

	vaddr = vmap_pfn(pfns, n_pfn, prot);
	if (pfns != stack)
		kvfree(pfns);

	return vaddr;
}
#endif

void *camb_mem_map_kernel(struct sg_table *table, int cached)
{
	void *vaddr;
	pgprot_t pgprot;

	if (table == NULL) {
		return ERR_PTR(-EINVAL);
	}

	if (cached == 0x1)
		pgprot = PAGE_KERNEL;
	else
		pgprot = pgprot_writecombine(PAGE_KERNEL);

	vaddr = camb_mem_vmap(table, pgprot);
	if (!vaddr)
		return ERR_PTR(-ENOMEM);

	return vaddr;
}

/*This function cann't invoked after ctrl + c.*/
int camb_unmap_uva(user_addr_t uva, __u64 size, int cached)
{
	int ret = 0;

	/*Must check current->mm. Maybe cn_mmap_read_lock is null after ctrl + c*/
	if (current->mm && cached) {
		cn_mem_cache_op(0, 0, uva, size,
				UDVM_CACHE_OP_INVALID, NULL);
	}

	ret = unmap_va_vma(&uva, &size, 1);

	return ret;
}

int camb_free_vma_list(struct mapinfo *pminfo)
{
	struct mm_vma_list *vma_list, *tmp;
	user_addr_t uva = 0;
	unsigned long size = 0;
	struct vma_priv_t *priv_data = NULL;
	int cached;

	spin_lock(&pminfo->vma_lock);

	list_for_each_entry_safe(vma_list, tmp, &pminfo->vma_head, list_node) {
		if (vma_list->vma->vm_mm != current->mm)
			continue;

		uva = vma_list->vma->vm_start;
		size = vma_list->vma->vm_end - vma_list->vma->vm_start;
		if (pminfo->uva_cached || pminfo->kva_info.kva_cached) {
			/**
			 * Only flush cache once because A55 is PIPT.
			 * Here no need flush cache again if uva_cached or kva_cached is set.
			 **/
			cached = 0;
		} else {
			priv_data = vma_list->vma->vm_private_data;
			cached = priv_data->cached;
		}

		/*the reason of mutex_unlock is __unmap_uva whill mutex_lock uva_lock,to avoid dead lock*/
		spin_unlock(&pminfo->vma_lock);

		/*Maybe uva is other process which parent or child process, so no need to check return value,*/
		camb_unmap_uva(uva, size, cached);

		spin_lock(&pminfo->vma_lock);
	}

	spin_unlock(&pminfo->vma_lock);

	return 0;
}

static void uva_vm_open(struct vm_area_struct *vma)
{
	struct vma_priv_t *priv_data = vma->vm_private_data;
	struct mapinfo *pminfo = NULL;
	struct cn_core_set *core;
	struct cn_mm_priv_data *mm_priv_data;
	struct cn_mm_set *mm_set;
	struct mm_vma_list *vma_list;

	if (unlikely(!priv_data)) {
		cn_dev_err("private_data is null.");
		return;
	}

	pminfo = priv_data->minfo;

	mm_set = (struct cn_mm_set *)pminfo->mm_set;
	core = (struct cn_core_set *)mm_set->core;
	mm_priv_data = pminfo->mm_priv_data;

	cn_dev_debug("tgid:%#llx pid:%#llx %#llx %#llx", (u64)current->pid,
			(u64)current->tgid, (u64)vma, (u64)vma->vm_private_data);

	/*TODO: need fix in fork scene, refer to DRIVER-5938*/
	if (pminfo->uva == vma->vm_start) {
		return;
	}

	vma_list = cn_kzalloc(sizeof(struct mm_vma_list), GFP_KERNEL);
	if (!vma_list) {
		cn_dev_core_err(core, "no system mem");
		return;
	}

	/*TODO: need to optimize in fork scene, refer to DRIVER-5938*/
	vma_list->vma = vma;
	INIT_LIST_HEAD(&vma_list->list_node);

	spin_lock(&pminfo->vma_lock);
	list_add_tail(&vma_list->list_node, &pminfo->vma_head);
	/*map_refcnt is use for fork(), to protect pminfo not free.*/
	if (atomic_add_return(1, &pminfo->map_refcnt) == 1) {
		atomic_inc(&pminfo->refcnt);
	}

	spin_unlock(&pminfo->vma_lock);

	atomic_inc(&priv_data->refcnt);
}

static int __del_vma_list(struct mm_vma_list *vma_list, struct vm_area_struct *vma, struct cn_core_set *core)
{
	if (vma_list->vma == vma) {
		cn_dev_core_debug(core, "free vma:%#llx uva: %#lx", (u64)vma, vma->vm_start);
		list_del(&vma_list->list_node);
		cn_kfree(vma_list);
		return 1;
	}

	return 0;
}

static void uva_vm_close(struct vm_area_struct *vma)
{
	struct vma_priv_t *priv_data = vma->vm_private_data;
	struct mapinfo *pminfo = NULL;
	int kref_put_flag = 0;
	struct mm_vma_list *vma_list, *tmp;
	struct cn_mm_priv_data *mm_priv_data;
	struct cn_mm_set *mm_set;
	struct cn_core_set *core;

	if (unlikely(!priv_data)) {
		cn_dev_err("private_data is null.");
		return;
	}

	pminfo = priv_data->minfo;

	if (atomic_sub_and_test(1, &priv_data->refcnt))
		cn_kfree(priv_data);

	mm_set = (struct cn_mm_set *)pminfo->mm_set;
	core = (struct cn_core_set *)mm_set->core;
	mm_priv_data = pminfo->mm_priv_data;

	/*lock vma_head*/
	spin_lock(&pminfo->vma_lock);
	list_for_each_entry_safe(vma_list, tmp, &pminfo->vma_head, list_node) {
		/*free uva list*/
		if (__del_vma_list(vma_list, vma, core)) {
			if (atomic_sub_and_test(1, &pminfo->map_refcnt)) {
				kref_put_flag = 1;
			}

			vma->vm_private_data = NULL;
			break;
		}
	}
	spin_unlock(&pminfo->vma_lock);

	if (kref_put_flag) {
		if (!atomic_read(&pminfo->refcnt))
			camb_mem_release(pminfo);
		else
			camb_kref_put(pminfo, camb_mem_release);
	}
}

const struct vm_operations_struct uva_vma_ops = {
	.open = uva_vm_open,
	.close = uva_vm_close,
};

int camb_init_vma_priv_data(struct vm_area_struct *vma,
					struct mapinfo *minfo, unsigned long offset, int cached)
{
	struct vma_priv_t *priv_data = NULL;

	vma->vm_private_data = NULL;

	priv_data = cn_kzalloc(sizeof(struct vma_priv_t), GFP_KERNEL);
	if (!priv_data)
		return -ENOMEM;

	priv_data->minfo = minfo;
	priv_data->offset = offset;
	priv_data->cached = cached;
	atomic_set(&priv_data->refcnt, 0);

	vma->vm_private_data = priv_data;
	return 0;
}

const struct vm_operations_struct vma_ops_null = {
};

static inline int need_fake_malloc(struct cn_mm_set *mm_set)
{
	if ((mm_set->devid == MLUID_370_DEV) ||
		(mm_set->devid == MLUID_590_DEV) ||
		(mm_set->devid == MLUID_PIGEON_EDGE) ||
		(mm_set->devid == MLUID_CE3226_EDGE)) {
		return 1;
	}

	return 0;
}

static int __fake_malloc(u64 tag, dev_addr_t device_vaddr,
						 struct cn_mm_set *mm_set, struct mapinfo **out_pminfo)
{
	struct mapinfo *pminfo = NULL;
	struct cn_core_set *core = mm_set->core;
	size_t result_len;
	int ret = 0;
	struct file *fp = (struct file *)tag;
	struct cn_mm_priv_data *mm_priv_data = NULL;
	struct udvm_priv_data *udvm_priv_data = NULL;
	struct mem_attr_get attr = {0};
	dev_addr_t rpc_dev_addr;

	/* NOTE: DRIVER-11186
	 * After udvm is enabled as default, input tag points to udvm_priv_data.
	 * __fake_malloc create mapinfo just used for cnMemMmap, which not need consider
	 * resource released during ContextDestroy.
	 **/
	if (fp_is_udvm(fp)) {
		udvm_priv_data = get_udvm_priv_data(fp);
	} else {
		mm_priv_data = __get_mm_priv(fp, mm_set);
	}

	if (!mm_priv_data && !udvm_priv_data) {
		cn_dev_core_err(core, "get mem priv data failed");
		return -EINVAL;
	}

	pminfo = cn_kzalloc(sizeof(struct mapinfo), GFP_KERNEL);
	if (!pminfo) {
		cn_dev_core_err(core, "kzalloc mapInfo failed.");
		return -ENOMEM;
	}

	/*mapinfo init*/
	if (!mm_priv_data) {
		camb_init_mapinfo_basic(pminfo, mm_set, 0);
		pminfo->mm_priv_data = NULL;
		pminfo->udvm_priv = udvm_priv_data;
	} else {
		camb_init_mapinfo_basic(pminfo, mm_set, tag);
	}

	pminfo->mem_type = MEM_FAKE;

	rpc_dev_addr = udvm_get_iova_from_addr(device_vaddr);
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_iova_get",
			(void *)&rpc_dev_addr, sizeof(rpc_dev_addr),
			(void *)&attr, (size_t *)&result_len, sizeof(struct mem_attr_get));

	if (ret < 0 || attr.ret) {
		cn_dev_core_err(core, "cnrpc client request mem failed.");
		cn_kfree(pminfo);
		return attr.ret;
	}

	/*init the memory attributes*/
	pminfo->mem_meta.align = 512;
	pminfo->mem_meta.type = CN_IPU_MEM;
	pminfo->mem_meta.affinity = -2;
	pminfo->mem_meta.flag = 0;
	pminfo->mem_meta.vmid = 0;
	pminfo->mdr_peer_addr = 0;

	pminfo->virt_addr = attr.iova | udvm_get_head_from_addr(device_vaddr);
	pminfo->mem_meta.size = (unsigned long)attr.size;

	if (mm_set->devid != MLUID_PIGEON_EDGE && mm_set->devid != MLUID_CE3226_EDGE) {
		/* To insert the mapinfo into the rb_tree for next copy_process in
		 * device context. It is that the device address was allocated in the
		 * host and accesssed in the device context.
		 * But the pmapinfo needs a real handle size. And when the fake_malloc
		 * is evolved with the media memory accessed in the ai context in the
		 * ce3226v100 platform, it does not use the handle size for pmapinfo
		 * size. As it will have the size overlap scene when the media memory
		 * was accessed multiple times. So it does not be inserted into the
		 * rb_tree.
		 */
		insert_mapinfo(mm_priv_data, pminfo);
	}

	/*why did it need to update the used_mem info? */
//	__sync_add_and_fetch(&mm_set->phy_used_mem, pminfo->mem_meta.size);
//	__sync_add_and_fetch(&mm_set->vir_used_mem, pminfo->mem_meta.size);

	/** Used for flush the pcie vf bar's cau accurately. Bits 0~36 stand for
	 * the stream id to index the cau
	 **/
	__sync_lock_test_and_set(&mm_set->smmu_invalid_mask, 0xfffffffff);

	*out_pminfo = pminfo;

	return 0;
}

int __dump_table(struct sg_table *table)
{
	int i;
	size_t size = 0;
	int cnt;

	cn_dev_info("table:%#llx", (u64)table);
	cn_dev_info("table sgl:%#llx", (u64)table->sgl);
	cn_dev_info("table nents:%#llx", (u64)table->nents);
	cn_dev_info("table orig_nents:%#llx", (u64)table->orig_nents);

	cnt = sg_nents(table->sgl);
	/*This debug function maybe error,if sg is chain*/
	for (i = 0; i < cnt; i++) {
		cn_dev_info("sgl[%d] page link:%#llx", i, (u64)table->sgl[i].page_link);
		cn_dev_info("sgl[%d] offset:%#llx", i, (u64)table->sgl[i].offset);
		cn_dev_info("sgl[%d] length:%#llx", i, (u64)table->sgl[i].length);
		cn_dev_info("sgl[%d] dma_address:%#llx", i, (u64)table->sgl[i].dma_address);
		cn_dev_info("sgl[%d] pfn:%lld", i, (u64)page_to_pfn(sg_page(&table->sgl[i])));
		size += table->sgl[i].length;
	}

	cn_dev_info("table total size:%#llx", (u64)size);

	return 0;
}

/**
 * split one sg_table from pminfo according to @map_addr and @map_size.
 * cn_sg_split will change table->sgl,so @table copy from pminfo->sg_table.
 * Note: map_addr and pminfo->virt_addr must PAGE_ALIGN.
 **/
int camb_split_sg_table(struct mapinfo *pminfo, dev_addr_t map_addr, __u64 map_size,
		struct sg_table *table, struct sg_table *out_table, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = mm_set->core;
	/*offset in ion_handle*/
	size_t offset;
	size_t split_sizes[1];
	struct scatterlist *sgl_out[1];
	int ret = 0;
	int in_mapped_nents;
	int out_mapped_nents[1];
	struct cn_fa_array *arr = mm_set->fa_array;

	if (unlikely(map_addr < pminfo->virt_addr
		|| !PAGE_ALIGNED(map_addr)
		|| !PAGE_ALIGNED(pminfo->virt_addr))) {
		cn_dev_core_err(core, "map_addr error:%#llx %#llx", (u64)map_addr, (u64)pminfo->virt_addr);
		return -EINVAL;
	}

	/*1. offset in pminfo, nb_splits of sg_split is 1*/
	offset = map_addr - pminfo->virt_addr;
	if (unlikely(offset > pminfo->mem_meta.size)) {
		cn_dev_core_err(core, "offset is error:%#llx", (u64)offset);
		return -EINVAL;
	}

	/*2. offset in chunk size of fast alloc*/
	if (pminfo->mem_type == MEM_FA) {
		offset += pminfo->virt_addr & ((arr->chunk_size * 1024) - 1);
	}

	split_sizes[0] = map_size;

	in_mapped_nents = sg_nents(table->sgl);

	ret = cn_sg_split(table->sgl, in_mapped_nents,
		offset, 1, split_sizes, sgl_out, out_mapped_nents, GFP_ATOMIC);
	if (ret) {
		cn_dev_core_err(core, "sg_split error:%#llx", (u64)ret);
		return -EINVAL;
	}

	out_table->sgl = sgl_out[0];
	out_table->nents = out_mapped_nents[0];
	out_table->orig_nents = out_mapped_nents[0];

	ret = cn_sg_clear_offset(out_table->sgl);
	if (ret) {
		cn_dev_core_err(core, "sg clear offset error:%#llx", (u64)ret);
		return -EINVAL;
	}

	cn_dev_core_debug(core, "map iova:%#llx map size:%#llx nents:%#llx",
				(u64)map_addr, (u64)map_size, (u64)in_mapped_nents);

	return 0;
}

int camb_copy_sg_table(struct sg_table *dst_table, struct sg_table *src_table)
{
	int ret = 0, i, cnt;
	struct scatterlist *new_sg;
	struct scatterlist *sg;

	cnt = sg_nents(src_table->sgl);

	ret = sg_alloc_table(dst_table, cnt, GFP_ATOMIC);
	if (ret) {
		cn_dev_err("fail malloc scatterlist.");
		return -ENOMEM;
	}
	dst_table->orig_nents = src_table->orig_nents;

	new_sg = dst_table->sgl;
	for_each_sg(src_table->sgl, sg, cnt, i) {
		sg_set_page(new_sg, sg_page(sg), sg->length, 0);
		sg_dma_address(new_sg) = sg_phys(sg);
		sg_dma_len(new_sg) = sg->length;

		new_sg = sg_next(new_sg);
	}

	return 0;
}

static int __pminfo_map_uva(u64 tag, struct mapinfo *pminfo, dev_addr_t map_dev_addr,
		__u64 map_size, user_addr_t *uva, __u32 cached, struct vm_area_struct **out_vma, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = mm_set->core;
	int ret = 0;
	struct vm_area_struct *vma = NULL;
	struct sg_table table = {0};

	/*2.split sgl list of phy addrss*/
	ret = camb_split_sg_table(pminfo, map_dev_addr, map_size, pminfo->sg_table, &table, mem_set);
	if (ret) {
		cn_dev_core_info(core, "split sgl to get phy addrss sgl error");
		return ret;
	}

	/*3. get vma*/
	ret = map_va_vma((struct file *)tag, map_size, uva, &vma);
	if (ret) {
		cn_dev_core_err(core, "get uva fail.");
		kfree(table.sgl);
		return ret;
	}

	/* Do not copy this vma on fork */
	vma->vm_flags |= VM_DONTCOPY;

	/*set page cache prot*/
	if (!cached) {
		/*map no cahce*/
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	}

	vma->vm_pgoff = 0;

	/*4. map sg_table to vma*/
	ret = phy_map_user(&table, vma);
	if (ret) {
		cn_dev_core_info(core, "map user error");
		unmap_va_vma(uva, &map_size, 1);
		kfree(table.sgl);
		return ret;
	}

	ret = camb_init_vma_priv_data(vma, pminfo, map_dev_addr - pminfo->virt_addr, cached);
	if (ret) {
		cn_dev_core_info(core, "set vm_private_data failed!");
		unmap_va_vma(uva, &map_size, 1);
		kfree(table.sgl);
		return ret;
	}

	*out_vma = vma;

	/**
	  * NOTICE:
	  * malloc by cn_sg_split need use kfree.
	  * malloc by sg_alloc_table need use sg_free_table.
	 */
	kfree(table.sgl);

	return ret;
}

int camb_pminfo_sg_table_set(struct mapinfo *pminfo, void *mem_set)
{
	struct mutex *uva_lock = __get_uva_lock_with_mapinfo(pminfo);
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = mm_set->core;
	dev_addr_t rpc_dev_addr;
	struct sg_table *origin_table;
	struct sg_table *sg_table;
	size_t result_len;
	int ret = 0;

	if (pminfo->sg_table) {
		return 0;
	}

	if (!uva_lock) {
		cn_dev_core_err(core, "could not found uva_lock from mapinfo");
		return -EINVAL;
	}
	/*lock sg_table, to avoid multi thread write pminfo->sg_table*/
	mutex_lock(uva_lock);

	/*check again in lock.*/
	if (pminfo->sg_table) {
		mutex_unlock(uva_lock);
		return 0;
	}

	rpc_dev_addr = udvm_get_iova_from_addr(pminfo->virt_addr);
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_map_host",
			&rpc_dev_addr, sizeof(__u64),
			(void *)&origin_table, (size_t *)&result_len, sizeof(origin_table));
	if (ret < 0 || origin_table == NULL) {
		cn_dev_core_err(core, "cnrpc client request mem sgl table failed.");
		mutex_unlock(uva_lock);
		return -EINVAL;
	}

	sg_table = cn_kzalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!sg_table) {
		cn_dev_core_err(core, "no mem alloc sg table.");
		mutex_unlock(uva_lock);
		return -ENOMEM;
	}

	ret = camb_copy_sg_table(sg_table, origin_table);
	if (ret) {
		cn_kfree(sg_table);
		cn_dev_core_err(core, "copy sg_table failed.");
		mutex_unlock(uva_lock);
		return ret;
	}

	/*no need to wb*/
	pminfo->sg_table = sg_table;

	mutex_unlock(uva_lock);

	return 0;
}

int __mem_map_segment_uva(u64 tag, struct mapinfo *pminfo,
			dev_addr_t device_vaddr, __u64 size, user_addr_t *uva, __u32 cached,
			void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = mm_set->core;
	int ret = 0;
	struct vm_area_struct *vma = NULL;
	__u64 map_size = size;
	dev_addr_t map_dev_addr = device_vaddr;

	/*head align*/
	map_size += device_vaddr & (~PAGE_MASK);
	/*tail align*/
	map_size = PAGE_ALIGN(map_size);

	map_dev_addr &= PAGE_MASK;

	ret = camb_pminfo_sg_table_set(pminfo, mem_set);
	if (ret) {
		cn_dev_core_err(core, "sg table set error.");
		return ret;
	}

	ret = __pminfo_map_uva(tag, pminfo, map_dev_addr, map_size, uva, cached, &vma, mem_set);
	if (ret) {
		cn_dev_core_err(core, "__pminfo_map_uva error.");
		return ret;
	}
	vma->vm_ops = &uva_vma_ops;
	vma->vm_ops->open(vma);

	/*uva need add offset to user*/
	*uva += device_vaddr & (~PAGE_MASK);

	return ret;
}

/**
 * NOTE: map_all_iova will increase mapinfo's refcnt. If userspace don't call
 * uva_put due to receive ctrlC signal, memory cannot be released until process
 * exit.
 *
 * Maybe we need make function much more safe in the future. avoid recycling
 * memory by decrease mapinfo refcnt to zero during process exit.
 **/
static int __mem_map_all_iova(u64 tag, struct mapinfo *pminfo, dev_addr_t device_vaddr,
		__u64 size, user_addr_t *uva, __u32 cached, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = mm_set->core;
	int ret = 0;
	struct vm_area_struct *vma = NULL;
	__u64 map_size = size;
	dev_addr_t map_dev_addr;

	struct mutex *uva_lock =
		__get_uva_lock_with_fp((struct file *)tag, device_vaddr, mm_set);
	if (!uva_lock) {
		cn_dev_core_err(core, "could not get uva_lock from input fp");
		return -EINVAL;
	}

	map_size = pminfo->mem_meta.size;
	/*tail align.pminfo->mem_meta.size maybe not PAGE_SIZE ALIGN.*/
	map_size = PAGE_ALIGN(map_size);

	map_dev_addr = pminfo->virt_addr;

	if (!PAGE_ALIGNED(map_dev_addr)) {
		cn_dev_core_err(core, "pminfo->virt_addr need PAGE_ALIGN.");
		return -EINVAL;
	}

	ret = camb_pminfo_sg_table_set(pminfo, mem_set);
	if (ret) {
		cn_dev_core_err(core, "sg table set error.");
		return ret;
	}

	/*lock uva, to avoid multi thread write pminfo->uva*/
	mutex_lock(uva_lock);

	if (pminfo->uva) {
		*uva = pminfo->uva + (device_vaddr - pminfo->virt_addr);
		/*only add refcnt if had been mapped.*/
		atomic_inc(&pminfo->refcnt);
		mutex_unlock(uva_lock);
		return 0;
	}

	ret = __pminfo_map_uva(tag, pminfo, map_dev_addr, map_size, uva, cached, &vma, mem_set);
	if (ret) {
		cn_dev_core_err(core, "__pminfo_map_uva error.");
		mutex_unlock(uva_lock);
		return ret;
	}
	vma->vm_ops = &camb_vma_dummy_ops;
	vma->vm_ops->open(vma);

	atomic_inc(&pminfo->refcnt);
	pminfo->uva = *uva;
	pminfo->uva_cached = cached;

	mutex_unlock(uva_lock);

	*uva += device_vaddr - pminfo->virt_addr;

	return ret;
}

static int __do_mem_uva_get(u64 tag, struct mapinfo *pminfo, dev_addr_t device_vaddr,
		__u64 size, user_addr_t *uva, __u32 prot, void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;
	int flag = (prot & CN_UVA_MAP_MODE_MASK) >> CN_UVA_MAP_MODE_SHIFT;
	int cached;

	if (CN_UVA_MAP_CACHE_NO_CACHE ==
			(prot & CN_UVA_MAP_CACHE_MASK) >> CN_UVA_MAP_CACHE_SHIFT) {
		cached = 0;
	} else {
		cached = 1;
	}

	/* It does not have the map all mode for media memory in CE3226 platform.
	 * So the functions, such as getAttributes, will not be supported.
	 * And it plays an explicit effect (to decline the performance) of the
	 * apis of H2D/D2H/Memset.*/
	if ((mm_set->devid == MLUID_PIGEON_EDGE || mm_set->devid == MLUID_CE3226_EDGE)
		&& pminfo->mem_type == MEM_FAKE) {
		return __mem_map_segment_uva(tag, pminfo, device_vaddr,
				size, uva, cached, mem_set);
	}

	/*Attention: Must check MEM_FAKE->CN_KEXT_MEM->CN_UVA_MAP_MODE_ALL_IOVA in order*/

	/* It only does segment map when the memory has been allocated in fake_alloc
	 * or kernel scene. Don't care the CN_UVA_MAP_MODE_ALL_IOVA flag.
	 */
	if (pminfo->mem_type == MEM_FAKE || pminfo->mem_type == MEM_KEXT) {
		return __mem_map_segment_uva(tag, pminfo, device_vaddr,
				size, uva, cached, mem_set);
	}

	if (flag == CN_UVA_MAP_MODE_ALL_IOVA) {
		/*map uva of iova, and will atomic_inc refcnt*/
		return __mem_map_all_iova(tag, pminfo, device_vaddr,
				size, uva, cached, mem_set);
	}

	if (flag == CN_UVA_MAP_MODE_BY_SIZE) {
		return __mem_map_segment_uva(tag, pminfo, device_vaddr,
				size, uva, cached, mem_set);
	}

	cn_dev_err("flag:%#x is error.", flag);
	return -EINVAL;
}

int cn_mem_uva_get(u64 tag, dev_addr_t device_vaddr, __u64 size,
		user_addr_t *uva, __u32 prot, void *pcore)
{
	int ret = 0;
	struct mapinfo *pminfo = NULL;
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	struct mutex *uva_lock =
		__get_uva_lock_with_fp((struct file *)tag, device_vaddr, mm_set);
	if (!uva_lock) {
		cn_dev_core_err(core, "could not get uva_lock from input fp");
		return -EINVAL;
	}

	cn_dev_core_debug(core, "iova:%#llx -- size:%#llx -- prot:%#llx",
			(u64)device_vaddr, (u64)size, (u64)prot);

	/*lock to avoid multi thread fake alloc same address.*/
	mutex_lock(uva_lock);

	ret = camb_kref_get(tag, device_vaddr, &pminfo, mm_set);
	/*mlu370 arm need fake malloc if camb_kref_get fail. other platform need return if camb_kref_get fail.*/
	if (ret < 0 && !need_fake_malloc(mm_set)) {
		cn_dev_err("Addr(%#llx) is illegal for uva get.", device_vaddr);
		mutex_unlock(uva_lock);
		return ret;
	}

	if (ret < 0 && isCEPlatform(core) && !addr_is_export(device_vaddr)) {
		cn_dev_err("The addr(%#llx) does not get permission to do fake_malloc", device_vaddr);
		mutex_unlock(uva_lock);
		return ret;
	}

	if (ret < 0) {
		/*fake malloc.*/
		if (__fake_malloc(tag, device_vaddr, mm_set, &pminfo)) {
			cn_dev_err("Addr(%#llx) is illegal for fake malloc", device_vaddr);
			mutex_unlock(uva_lock);
			return -ENXIO;
		}
	}

	mutex_unlock(uva_lock);

	ret = __params_check_range(pminfo, device_vaddr, size);
	if (ret) {
		/*put refcnt of __fake_malloc*/
		camb_kref_put(pminfo, camb_mem_release);
		return ret;
	}

	ret = __do_mem_uva_get(tag, pminfo, device_vaddr, size, uva, prot, mm_set);

	cn_dev_core_debug(core, "iova:%#llx uva:%#llx(%#llx) size:%#llx prot:%#llx",
			(u64)device_vaddr, (u64)*uva, (u64)pminfo->uva, (u64)size, (u64)prot);

	camb_kref_put(pminfo, camb_mem_release);

	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is map fail.", device_vaddr);
	}

	return ret;
}

int camb_vma_is_uva(struct vm_area_struct *vma)
{
	return vma->vm_ops == &uva_vma_ops;
}

static inline int __cache_op_param_check(dev_addr_t iova, user_addr_t uva, __u64 size)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma = NULL;
	__u64 end = uva + size;
	struct vma_priv_t *priv = NULL;
	int ret = -EINVAL;

	#if (KERNEL_VERSION(5, 8, 0) > LINUX_VERSION_CODE)
	WARN_ON(!rwsem_is_locked(&mm->mmap_sem));
	#else
	mmap_assert_locked(mm);
	#endif

	/**
	 * Maybe vma is error, find_vma only Look up the first VMA
	 * which satisfies addr < vm_end, NULL if none.
	 * So check uva and uva + len of vma.
	 **/
	vma = find_vma(mm, uva);
	if (vma && uva >= vma->vm_start && end <= vma->vm_end) {
		if (addr_is_export(iova))
			return 0;

		if (camb_vma_is_uva(vma) || camb_vma_is_dummy(vma)) {
			priv = vma->vm_private_data;
			ret = 0;
		}
	}

	if (ret != 0) {
		cn_dev_err("uva:%#llx iova:%#llx or len:%#llx is illegal.",
				(u64)uva, (u64)iova, (u64)size);
		return ret;
	}

	/*uva and size is valid if run here,Check iova valid here.*/
	if (iova && (iova - priv->minfo->virt_addr - priv->offset) != (uva - vma->vm_start)) {
		cn_dev_err("iova:%#llx is illegal.", (u64)iova);
		return -EINVAL;
	}

	return 0;
}

/**
 * uva and len need PAGE_ALIGN;
 **/
int __uva_addr_check(user_addr_t uva, __u64 len, int *mem_type,
				int *mem_meta_type, dev_addr_t *iova, int *cached)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma = NULL;
	__u64 end = uva + len;
	int ret = -EINVAL;
	struct vma_priv_t *priv = NULL;
	struct mapinfo *pminfo;

	if ((offset_in_page(uva)) || (uva > TASK_SIZE) || \
		(len > TASK_SIZE - uva) || (offset_in_page(len))) {
		cn_dev_err("uva:%#llx or len:%#llx is illegal.", (u64)uva, (u64)len);
		return ret;
	}

	cn_mmap_read_lock(mm);

	/**
	 * Maybe vma is error, find_vma only Look up the first VMA
	 * which satisfies addr < vm_end, NULL if none.
	 * So check uva and uva + len of vma.
	 **/
	vma = find_vma(mm, uva);
	if (vma && uva >= vma->vm_start && end <= vma->vm_end) {
		if (camb_vma_is_uva(vma)) {
			ret = 0;
			priv = vma->vm_private_data;
			pminfo = priv->minfo;
			*mem_type = pminfo->mem_type;
			*mem_meta_type = pminfo->mem_meta.type;
			*iova = pminfo->virt_addr;
			*cached = priv->cached;
		} else if (camb_vma_is_dummy(vma)) {
			ret = 0;
		} else {
			cn_dev_info("uva is error");
		}
	} else {
		cn_dev_err("uva:%#llx len:%#llx to find vma is failed.", (u64)uva, (u64)len);
	}

	cn_mmap_read_unlock(mm);
	return ret;
}

int cn_mem_uva_put(u64 tag, user_addr_t uva, __u64 size, dev_addr_t iova,
			__u32 prot, void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	int flag = (prot & CN_UVA_MAP_MODE_MASK) >> CN_UVA_MAP_MODE_SHIFT;
	unsigned int offset;
	unsigned int mem_meta_type = CN_MAX_MEM;
	unsigned int mem_type = 0;
	dev_addr_t iova_get = iova;
	int cached;

	offset = uva & (~PAGE_MASK);
	size += offset;/*head align*/
	size = PAGE_ALIGN(size);/*tail align*/

	uva &= PAGE_MASK;

	/* param of __uva_addr_check need PAGE_ALIGN;*/
	if (__uva_addr_check(uva, size, &mem_type, &mem_meta_type, &iova_get, &cached)) {
		cn_dev_core_err(core, "uva:%#llx size:%#llx is illegal for put.", (u64)uva, (u64)size);
		return -EINVAL;
	}

	/* It only has the segment map mode for media memory in CE3226 platform. */
	if ((mm_set->devid == MLUID_PIGEON_EDGE || mm_set->devid == MLUID_CE3226_EDGE)
		&& mem_type == MEM_FAKE) {
		return camb_unmap_uva(uva, size, cached);
	}

	/*see __do_mem_uva_get annotation*/
	if (mem_type == MEM_FAKE || mem_type == MEM_KEXT) {
		return camb_unmap_uva(uva, size, cached);
	}

	/*see __do_mem_uva_get annotation*/
	if (flag == CN_UVA_MAP_MODE_ALL_IOVA) {
		return camb_mem_put_release(tag, iova_get, mm_set);
	}

	if (flag == CN_UVA_MAP_MODE_BY_SIZE) {
		return camb_unmap_uva(uva, size, cached);
	}

	cn_dev_core_err(core, "uva:%#llx size:%#llx flag:%#x is illegal for put.",
			(u64)uva, (u64)size, flag);
	return -EINVAL;
}

/**
 * @tag and @mem_set no use,can be set 0 or NULL. if @iova == 0, no check whether it valid.
 **/
int cn_mem_cache_op(u64 tag, dev_addr_t iova, user_addr_t uva, __u64 size,
		__u32 op, void *pcore)
{
	struct mm_struct *mm = current->mm;
	int ret = 0;

	/*this lock protect vma_priv_t & pminfo & cache operarion*/
	cn_mmap_read_lock(mm);

	if (__cache_op_param_check(iova, uva, size)) {
		cn_dev_err("iova(%#llx),uva:%#llx or len:%#llx is illegal.",
				(u64)iova, (u64)uva, (u64)size);
		ret = -EINVAL;
		goto unlock_mmap;
	}

	switch (op) {
		case UDVM_CACHE_OP_FLUSH:
			/*This function will align by cache_line_size() */
			cn_edge_cache_flush((void *)uva, size);
			break;
		case UDVM_CACHE_OP_INVALID:
			/*This function will align by cache_line_size() */
			cn_edge_cache_invalid((void *)uva, size);
			break;
		case UDVM_CACHE_OP_CLEAN:
			/*This function will align by cache_line_size() */
			cn_edge_cache_clean((void *)uva, size);
			break;
		default:
			cn_dev_err("cache op is invalid.");
			ret = -EINVAL;
			goto unlock_mmap;
	}

unlock_mmap:
	cn_mmap_read_unlock(mm);

	return ret;
}
