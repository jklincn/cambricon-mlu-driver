#include <linux/kernel.h>
#include <linux/hash.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/sched.h>
#include <linux/ftrace.h>
#include <linux/delay.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/mm.h>
#endif
#include <linux/seq_file.h>
#include <asm/page.h>

#include "cndrv_debug.h"
#include "cndrv_genalloc.h"/*cn_gen_pool*/
#include "cndrv_monitor.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_monitor_usr.h"
#include "camb_mm_priv.h"
#include "cndrv_sbts.h"
#include "camb_mm.h"
#include "camb_udvm.h"
#include "camb_pinned_mem.h"
#include "camb_sg_split.h"
#include "cndrv_bus.h"/*dob*/
#include "cndrv_ob_pinned_mm.h"
#include "camb_ob.h"
#include "camb_cp.h"

/*
 * common macro
 */
#define MIN_FREERAM_SIZE_BYTE		(1UL << 20) /*define the min freeram size as 10MB*/

#define write_lock_my(x) do {\
	write_lock(x);\
} while (0)

#define write_unlock_my(x) do {\
	write_unlock(x);\
} while (0)

#define read_lock_my(x) do {\
	read_lock(x);\
} while (0)

#define read_unlock_my(x) do {\
	read_unlock(x);\
} while (0)

#define SEARCH_RB_NODE_OPS_EQ(info_struct, addr_member, size_member, name) \
	static struct info_struct *search_##name##_rb_node_eq(struct rb_root *root,\
									dev_addr_t addr) \
{	\
	struct rb_node *__this_node = root->rb_node;	\
	struct info_struct *__this_info = NULL;			\
	while (__this_node) {							\
		__this_info = rb_entry(__this_node, struct info_struct, node);		\
		if (__this_info->addr_member > addr)		\
			__this_node = __this_node->rb_left;		\
		else if (__this_info->addr_member < addr) \
			__this_node = __this_node->rb_right;	\
		else										\
			return __this_info;						\
	}								\
	return NULL;					\
}

#define SEARCH_INFO_OPS_EQ(parent_struct, member_lock, member_root, info_struct, name) \
	static struct info_struct *search_##name##_eq(struct parent_struct *data,	\
											dev_addr_t vaddr) \
{		\
	struct info_struct *info = NULL;	\
	info = search_##name##_rb_node_eq(&data->member_root, vaddr);	\
	return info;	\
}
/*
 * pinned mem tree macro
 */
INSERT_RB_NODE_OPS(pinned_mem, kva_start, pinned_mem)
/* insert_pinned_mem */
INSERT_INFO_OPS(pinned_mem_rb_blk, rb_lock, root, pinned_mem, pinned_mem)

DELETE_RB_NODE_OPS(pinned_mem, pinned_mem)
/* delete_pinned_mem */
DELETE_INFO_OPS(pinned_mem_rb_blk, rb_lock, root, pinned_mem, pinned_mem)

SEARCH_RB_NODE_OPS(pinned_mem, kva_start, vm_size, pinned_mem)
/* search_pinned_mem */
SEARCH_INFO_OPS(pinned_mem_rb_blk, rb_lock, root, pinned_mem, pinned_mem)

/*
 * pinned mem pid tree macro
 */
INSERT_RB_NODE_OPS(pinned_mem_task, task, pinned_mem_task)
/* insert_pinned_mem_task */
INSERT_INFO_OPS(pinned_mem_rb_task, rb_lock, root, pinned_mem_task, pinned_mem_task)

DELETE_RB_NODE_OPS(pinned_mem_task, pinned_mem_task)
/* delete_pinned_mem_task */
DELETE_INFO_OPS(pinned_mem_rb_task, rb_lock, root, pinned_mem_task, pinned_mem_task)

SEARCH_RB_NODE_OPS(pinned_mem_task, task, size, pinned_mem_task)
/* search_pinned_mem_task */
SEARCH_INFO_OPS(pinned_mem_rb_task, rb_lock, root, pinned_mem_task, pinned_mem_task)

/*
 * pinned mem va tree macro
 */
INSERT_RB_NODE_OPS(pinned_mem_va, va_start, pinned_mem_va)
/* insert_pinned_mem_va */
INSERT_INFO_OPS(pinned_mem_task, rb_lock, rb_uva, pinned_mem_va, pinned_mem_va)

DELETE_RB_NODE_OPS(pinned_mem_va, pinned_mem_va)
/* delete_pinned_mem_va */
DELETE_INFO_OPS(pinned_mem_task, rb_lock, rb_uva, pinned_mem_va, pinned_mem_va)

SEARCH_RB_NODE_OPS(pinned_mem_va, va_start, vm_size, pinned_mem_va)
/* search_pinned_mem_va */
SEARCH_INFO_OPS(pinned_mem_task, rb_lock, rb_uva, pinned_mem_va, pinned_mem_va)

SEARCH_RB_NODE_OPS_EQ(pinned_mem_va, va_start, vm_size, pinned_mem_va)
/* search_pinned_mem_va_eq */
SEARCH_INFO_OPS_EQ(pinned_mem_task, rb_lock, rb_uva, pinned_mem_va, pinned_mem_va)

#define __FIND_TREE_NODE_BY_TASK(pinned_mem_rb_task, tgid) \
		search_pinned_mem_task(pinned_mem_rb_task, (dev_addr_t)(tgid))
#define __FIND_TREE_NODE_BY_KVA(pinned_mem_rb_task, kva)    search_pinned_mem(pinned_mem_rb_task, kva)
#define __FIND_TREE_NODE_BY_UVA(pst_task, uva)    search_pinned_mem_va(pst_task, uva)
#define __FIND_TREE_NODE_BY_UVA_EQ(pst_task, uva) search_pinned_mem_va_eq(pst_task, uva)

/*tlinux not found PAGE_ALIGNED*/
#ifndef PAGE_ALIGNED
#define PAGE_ALIGNED(addr)      IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
#endif

struct hostmem_priv_data {
	spinlock_t task_lock;
	struct list_head task_list;
};

int camb_release_udvm_ob_map(struct udvm_ob_map_t *ob_map);
static int __map_ob_win_internal(struct udvm_ob_map_t *ob, int card_id, bool is_map_iova);

static struct hostmem_priv_data *get_hostmem_priv(struct file *fp)
{
	return (struct hostmem_priv_data *)cndev_get_hostmem_priv(fp);
}

int check_si_meminfo(size_t size)
{
	struct sysinfo val;
	unsigned long freeram = 0;

	si_meminfo(&val);
	freeram = val.freeram * val.mem_unit;

	cn_dev_debug("allocate size:%#lx, freeram:%#lx, unit:%#x", size, freeram,
				 val.mem_unit);

	if ((long)(freeram - size) >= MIN_FREERAM_SIZE_BYTE)
		return 1;
	else
		return 0;
}

static void *__pinned_mem_vmap(struct page **pages, unsigned int count,
							   unsigned long flags, pgprot_t prot)
{
#if (KERNEL_VERSION(4, 7, 0) <= LINUX_VERSION_CODE)
	return vmap(pages, count, flags, prot);
#else
	struct vm_struct *area;
	unsigned long size;		/* In bytes */

	if (count > totalram_pages)
		return NULL;

	size = (unsigned long)count << PAGE_SHIFT;
	area = __get_vm_area(size, flags, VMALLOC_START, VMALLOC_END);
	if (!area)
		return NULL;

	if (cn_map_vm_area(area, prot, pages)) {
		vunmap(area->addr);
		return NULL;
	}

	return area->addr;
#endif
}

static unsigned int __get_page_count(struct pinned_mem *pst_blk)
{
	int i = 0;
	int page_count = 0;

	if (!pst_blk)
		return 0;

	for (i = 0; i < pst_blk->chunks; i++) {
		page_count += pst_blk->pages_cnt[i];
	}

	return page_count;
}

static int pinnde_mem_vmap(struct pinned_mem *pst_blk)
{
	unsigned int page_count = 0;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	if (!pst_blk)
		return -EINVAL;

	/* map to kernel space */
	page_count = __get_page_count(pst_blk);
	pst_blk->kva_start = (unsigned long)__pinned_mem_vmap(pst_blk->pages,
			page_count, VM_MAP, PAGE_KERNEL);

	if (!pst_blk->kva_start) {
		cn_dev_err("vmap failed page_count %d.", page_count);
		return -ENOMEM;
	}

	write_lock_my(&udvm_set->pm_blk_root->rb_lock);
	insert_pinned_mem(udvm_set->pm_blk_root, pst_blk);
	write_unlock_my(&udvm_set->pm_blk_root->rb_lock);

	return 0;
}

static struct vm_area_struct *
pinned_mem_find_vma(struct mm_struct *mm, unsigned long va, unsigned long size)
{
	struct vm_area_struct *vma = NULL;

	cn_mmap_write_lock(mm);
	vma = find_vma(mm, va);
	if (vma && vma->vm_start >= va && va + size <= vma->vm_end) {
		vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
		vma->vm_private_data = NULL;
		vma->vm_ops = &camb_vma_dummy_ops;
	} else if (vma) {
		cn_dev_err("va:%#lx %#lx %#lx size:%#lx is invalid.",
				va, vma->vm_start, vma->vm_end, size);
		vma = NULL;
	}
	cn_mmap_write_unlock(mm);

	return vma;
}

static int
pinned_vm_insert_pages(struct vm_area_struct *vma, unsigned long addr,
					   struct page **pages, unsigned long pgcount)
{
	unsigned int idx = 0;
	int err = -EINVAL;

	for (idx = 0; idx < pgcount; ++idx) {
		err = vm_insert_page(vma, addr + (PAGE_SIZE * idx), pages[idx]);
		if (err)
			break;
	}

	return err;
}

static int bad_address(void *p)
{
	unsigned long dummy = 0;

#if (KERNEL_VERSION(5, 8, 0) <= LINUX_VERSION_CODE)
	return get_kernel_nofault(dummy, p);
#else
	return probe_kernel_address((unsigned long *)p, dummy);
#endif
}

struct pinned_mem_va *__find_pinned_mem_va(struct pinned_mem_rb_task *pm_task_root, pid_t tgid,
		unsigned long va, bool is_equal)
{
	struct pinned_mem_va *pst_uva = NULL;
	struct pinned_mem_task *pst_task = NULL;

	pst_task = __FIND_TREE_NODE_BY_TASK(pm_task_root, tgid);
	if (!pst_task) {
		goto out;
	}

	if (is_equal) {
		pst_uva = __FIND_TREE_NODE_BY_UVA_EQ(pst_task, va);
	} else {
		pst_uva = __FIND_TREE_NODE_BY_UVA(pst_task, va);
	}

out:
	return pst_uva;
}

struct pinned_mem_va *find_pinned_mem_va(pid_t tgid, unsigned long va, bool is_equal)
{
	struct pinned_mem_va *pst_uva = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	read_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __find_pinned_mem_va(udvm_set->pm_task_root, tgid, va, is_equal);
	read_unlock_my(&udvm_set->pm_task_root->rb_lock);

	return pst_uva;
}

#define PINNED_ORDER_MAX (10)
static int do_alloc_pinned_mem_pages(struct pinned_mem *pst_blk,
				unsigned long all_size, int nid)
{
	unsigned int last_page = 0;
	unsigned long pages_needed = 0;
	struct page **tmp_pages;
	int *tmp_index;
	int *tmp_index1;
	int chunks = 0;
	unsigned long tmp_size = 0;
	unsigned long minus_size = 0;

	if (!pst_blk)
		return -EINVAL;

	all_size = ALIGN(all_size, PAGE_SIZE);
	pages_needed = all_size >> PAGE_SHIFT;
	tmp_pages = cn_vmalloc(sizeof(struct page *) * pages_needed);
	if (!tmp_pages) {
		return -ENOMEM;
	}

	tmp_index = cn_vmalloc(sizeof(int) * pages_needed);
	if (!tmp_index) {
		cn_vfree(tmp_pages);
		return -ENOMEM;
	}

	while (tmp_size < all_size) {
		struct page *pages;
		int order;
		int i;

		minus_size = all_size - tmp_size;
		order = get_order(minus_size);
		/* Dont over allocate*/
		if ((PAGE_SIZE << order) > minus_size)
			order--;

		order = min(order, PINNED_ORDER_MAX);
		pages = NULL;
		while (!pages) {
			pages = alloc_pages_node(nid, GFP_KERNEL | __GFP_NOWARN |
						__GFP_NORETRY, order);
			if (pages)
				break;

			if (order == 0)
				goto failed_nomem;

			order--;
		}

		split_page(pages, order);

		for (i = 0; i < (1 << order); i++) {
			tmp_pages[last_page++] = &pages[i];
		}
		tmp_size += PAGE_SIZE << order;
		tmp_index[chunks++] = 1 << order;
	}

	tmp_index1 = cn_vmalloc(sizeof(int) * chunks);
	if (!tmp_index1)
		goto failed_nomem;

	memcpy(tmp_index1, tmp_index, sizeof(int) * chunks);
	cn_vfree(tmp_index);

	pst_blk->pages_cnt = tmp_index1;
	pst_blk->pages = tmp_pages;
	pst_blk->chunks = chunks;

	return 0;

failed_nomem:
	while (last_page--)
		__free_page(tmp_pages[last_page]);
	cn_vfree(tmp_pages);
	cn_vfree(tmp_index);
	return -ENOMEM;
}

static int alloc_pinned_mem_pages_node(struct pinned_mem *pst_blk,
								unsigned long all_size, int node)
{
	return do_alloc_pinned_mem_pages(pst_blk, all_size, node);
}

static int
alloc_pinned_mem_pages(struct pinned_mem *pst_blk, unsigned long all_size)
{
	/* input NUMA_NO_NODE means to alloc_pages */
	return do_alloc_pinned_mem_pages(pst_blk, all_size, NUMA_NO_NODE);
}

static void free_pinned_mem_pages(struct pinned_mem *pst_blk)
{
	int page_cnt = 0;
	int i;

	if (!pst_blk)
		goto out;

	page_cnt = __get_page_count(pst_blk);

	if (pst_blk->type == CN_HOSTALLOC_TYPE_REGISTER) {
		for (i = 0; i < page_cnt; i++) {
			/*for __register_uva_to_pinned_mem of cn_get_user_pages*/
			put_page(pst_blk->pages[i]);
		}

		/*CN_MEMHOSTALLOC_REGISTER of pst_blk no need to __free_page*/
		page_cnt = 0;
	}

	while (page_cnt--) {
		__free_page(pst_blk->pages[page_cnt]);
	}

	cn_vfree(pst_blk->pages);
	cn_vfree(pst_blk->pages_cnt);

out:
	return;
}

static struct pinned_mem *
alloc_pinned_mem_node(CN_HOSTALLOC_TYPE type, unsigned long va_start,
					  unsigned long total_size, int node)
{
	struct pinned_mem *pst_blk = NULL;
	struct udvm_ob_map_t *ob_map = NULL;
	int ret = 0;

	pst_blk = cn_kzalloc(sizeof(struct pinned_mem), GFP_KERNEL);
	if (!pst_blk) {
		cn_dev_err("Kmalloc pinned_mem failed.");
		goto out;
	}

	ob_map = cn_kzalloc(sizeof(struct udvm_ob_map_t), GFP_KERNEL);
	if (!ob_map) {
		cn_dev_err("malloc ob_map_t fail.");
		goto free_blk;
	}

	pst_blk->type = type;
	atomic_set(&pst_blk->ref_cnt, 0);
	atomic_set(&pst_blk->k_rcnt, 0);
	pst_blk->vm_size = total_size;

	pst_blk->ob_map = ob_map;
	mutex_init(&ob_map->map_lock);

	ret = alloc_pinned_mem_pages_node(pst_blk, total_size, node);
	if (ret) {
		/* Allocate host pinned memory without numa node when it's failed to
		 * allocate with numa node.
		 */
		ret = alloc_pinned_mem_pages(pst_blk, total_size);
	}

	if (ret) {
		cn_dev_err("alloc_pinned_mem_pages failed.");
		goto free_ob_map;
	}

	return pst_blk;

free_ob_map:
	cn_kfree(ob_map);
free_blk:
	cn_kfree(pst_blk);
out:
	return NULL;
}

static struct pinned_mem *alloc_pinned_mem(CN_HOSTALLOC_TYPE type,
				 unsigned long va_start, unsigned long total_size)
{
	struct pinned_mem *pst_blk = NULL;
	struct udvm_ob_map_t *ob_map = NULL;
	int ret = 0;

	pst_blk = cn_kzalloc(sizeof(struct pinned_mem), GFP_KERNEL);
	if (!pst_blk) {
		cn_dev_err("Kmalloc pinned_mem failed.");
		goto out;
	}

	ob_map = cn_kzalloc(sizeof(struct udvm_ob_map_t), GFP_KERNEL);
	if (!ob_map) {
		cn_dev_err("malloc ob_map_t fail.");
		goto free_blk;
	}

	pst_blk->type = type;
	atomic_set(&pst_blk->ref_cnt, 0);
	atomic_set(&pst_blk->k_rcnt, 0);
	pst_blk->vm_size = total_size;

	mutex_init(&ob_map->map_lock);
	pst_blk->ob_map = ob_map;

	ret = alloc_pinned_mem_pages(pst_blk, total_size);
	if (ret) {
		cn_dev_err("alloc_pinned_mem_pages failed.");
		goto free_ob_map;
	}

	return pst_blk;

free_ob_map:
	cn_kfree(ob_map);
free_blk:
	cn_kfree(pst_blk);
out:
	return NULL;
}

int __send_ob_data_to_device(int card_id, struct ob_data_rpc_t *ob_data)
{
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core;
	struct ret_msg remsg;
	size_t result_len;
	int ret;
	int send_len;

	/*send valid data.*/
	send_len = sizeof(struct ob_data_rpc_t) - sizeof(ob_data->data)
		+ ob_data->cnt * sizeof(struct ob_data_payload);

	mm_set = __get_mmset_with_index(card_id);
	if (!mm_set)
		return -ENODEV;

	core = (struct cn_core_set *)mm_set->core;

	memset(&remsg, 0, sizeof(remsg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_cfg_outbound_win",
			ob_data, send_len,
			&remsg, &result_len,
			sizeof(struct ret_msg));
	if (ret || remsg.ret) {
		cn_dev_core_err(core, "cnrpc call failed.%#llx %#llx",
				(u64)ret, (u64)remsg.ret);
		ret = -EPIPE;
	}

	return ret;
}

static inline bool payload_not_full(int count)
{
	if (count % MAX_OB_PCI_ADDR_CNT != 0) {
		return true;
	}

	return false;
}

int camb_map_ob_win(struct ob_map_t *ob, int is_map_iova)
{
	struct sg_table *sg_table = ob->table;
	struct scatterlist *sg;
	int i, ret, err, cnt;
	unsigned long offset = 0;
	struct ob_data_rpc_t *ob_data = NULL;
	int index = 0, seg = 0;
	struct device *dev;
	int ob_data_size = RPC_TRANS_MAX_LEN(1);

	ob_data = (struct ob_data_rpc_t *)cn_kzalloc(ob_data_size, GFP_KERNEL);
	if (!ob_data) {
		cn_dev_err("ob_data_rpc_t alloc failed");
		return -ENOMEM;
	}

	cnt = sg_nents(sg_table->sgl);
	if (is_map_iova) {
		dev = cn_core_get_dev(ob->card_id);
		/*
		 * dma_maps_sg_attrs returns 0 on error and > 0 on success.
		 * It should never return a value < 0.
		 */
		ret = dma_map_sg(dev, sg_table->sgl, cnt, DMA_BIDIRECTIONAL);
		if (!ret) {
			ob->status = OB_MAP_ERROR;
			cn_kfree(ob_data);
			cn_dev_err("cfg outbound win failed.%#llx", (u64)ret);
			return -ENOMEM;
		}

		ob_data->tag = OB_DATA_MAP_SMMU_SOF;
	} else {
		ob_data->tag = OB_DATA_UNMAP_SMMU_SOF;
	}

	/* The arm will check whether the rpc trans is in the same context through
	 * the dpa, iova and size infomations. */
	ob_data->device_pa = ob->device_pa;
	ob_data->iova = ob->iova;
	ob_data->size = ob->iova_size;
	/* When mapping the ob wins, it will use the offset to get the device pa. */
	ob_data->offset = offset;
	/* the total nents count */
	ob_data->t_cnt = cnt;
	ob_data->s_cnt = 0;

	for_each_sg(sg_table->sgl, sg, cnt, i) {
		ob_data->data[index].pci_addr = sg_dma_address(sg);
		ob_data->data[index].size = sg_dma_len(sg);
		offset += sg_dma_len(sg);
		/* the ob_data count in the current rpc trans */
		index++;

		/**
		 * fill ob_data->data by cnt and MAX_OB_PCI_ADDR_CNT
		 * Max cnt is MAX_OB_PCI_ADDR_CNT that one rpc transfer..
		 **/
		if (payload_not_full(index) && !sg_is_last(sg)) {
			continue;
		}

		/* we have three scenes: 1. payload is full and 2.sg_is_last and
		 * 3.payload_is_full && sg_is_last. */
		if (sg_is_last(sg)) {
			if (is_map_iova) {
				ob_data->tag = OB_DATA_MAP_SMMU_EOF;
			} else {
				ob_data->tag = OB_DATA_UNMAP_SMMU_EOF;
			}
		} else if (seg) {
			/* to deal with the scene 1. */
			if (is_map_iova) {
				ob_data->tag = OB_DATA_MAP_SMMU_MOF;
			} else {
				ob_data->tag = OB_DATA_UNMAP_SMMU_MOF;
			}
		}

		ob_data->cnt = index;
		seg++;
		ret = __send_ob_data_to_device(ob->card_id, ob_data);
		if (ret) {
			err = ret;
			cn_dev_err("cfg ob win fail");
			goto send_error;
		}

		index = 0;
		/* reset the ob_data status for the next rpc trans */
		ob_data->tag = 0;
		ob_data->s_cnt += ob_data->cnt;
		ob_data->cnt = 0;
		/* update dpa info for the next ob_data frame */
		ob_data->offset = offset;
	}

	if (!is_map_iova) {
		dev = cn_core_get_dev(ob->card_id);
		dma_unmap_sg(dev, sg_table->sgl, cnt, DMA_BIDIRECTIONAL);
	}

	ob->status = OB_MAP_COMPLETE;
	cn_kfree(ob_data);
	return 0;

send_error:
	ob->status = OB_MAP_ERROR;
	cn_kfree(ob_data);
	return err;
}

int camb_release_ob_map(struct ob_map_t *ob_map)
{
	int ret = 0;

	if (camb_map_ob_win(ob_map, 0)) {
		/* NOTE: donot direct return, we need free dob iova resource as usual */
		cn_dev_err("invalid cfg win error");
		ret = -EINVAL;
	}

	camb_dob_dev_mem_free(ob_map->device_va, ob_map->device_pa,
			ob_map->iova_size, ob_map->mm_set);

	if (ob_map->sgt_release)
		ob_map->sgt_release(ob_map->priv, ob_map->table);

	cn_kfree(ob_map);

	return ret;
}

/* Direct call this function is dangerous
 * This function is internal use by mem and sbts only */
void cn_pinned_mem_free_pstblk(struct pinned_mem *pst_blk)
{
	if (!pst_blk) {
		cn_dev_err("input handle is null");
		dump_stack();
		return;
	}

	if (pst_blk->kva_start) {
		udvm_ipc_handle_release((dev_ipc_handle_t)pst_blk->kva_start);
		vunmap((void *)(pst_blk->kva_start));
	}

	if (pst_blk->ob_map) {
		/*release all dma and outbound reousrce*/
		camb_release_udvm_ob_map(pst_blk->ob_map);
	}

	free_pinned_mem_pages(pst_blk);
	cn_kfree(pst_blk);
}

static void __free_pinned_mem(struct pinned_mem **ppst_blk)
/*acquire lock*/
{
	struct pinned_mem *pst_blk = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	if (!ppst_blk) {
		return;
	}

	pst_blk = *ppst_blk;
	if (!pst_blk) {
		return;
	}

	/*WARN_ON(atomic_read(&pst_blk->ref_cnt) != 0);*/

	delete_pinned_mem(udvm_set->pm_blk_root, pst_blk);

	write_unlock_my(&udvm_set->pm_blk_root->rb_lock);

	/* sbts return 1 if mm can release pst_blk */
	if (cn_sbts_idc_kaddr_rm(pst_blk))
		cn_pinned_mem_free_pstblk(pst_blk);

	*ppst_blk = NULL;

	write_lock_my(&udvm_set->pm_blk_root->rb_lock);
}

static void free_pinned_mem(struct pinned_mem **ppst_blk)
{
	struct pinned_mem *pst_blk = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	if (!ppst_blk) {
		return;
	}

	pst_blk = *ppst_blk;
	if (!pst_blk) {
		return;
	}

	write_lock_my(&udvm_set->pm_blk_root->rb_lock);
	if (atomic_read(&pst_blk->ref_cnt) == 0) {
		__free_pinned_mem(ppst_blk);
	}
	write_unlock_my(&udvm_set->pm_blk_root->rb_lock);
}

static unsigned long insert_uva_to_tree(struct file *fp, struct vm_area_struct *vma,
		pid_t tgid, struct pinned_mem *pst_blk,
		unsigned long uaddr, unsigned long va_size)
{
	struct pinned_mem_va *pst_uva = NULL;
	struct pinned_mem_task *pst_task = NULL;
	unsigned long size = 0;
	unsigned long  usize = 0;
	int chunks = 0;
	int page_index = 0;
	int i = 0, insert_flag = 0;
	unsigned long va_start = uaddr;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct hostmem_priv_data *hostmem_priv = get_hostmem_priv(fp);

	if (!pst_blk) {
		cn_dev_err("NULL ptr.");
		return 0;
	}

	if (va_size > pst_blk->vm_size) {
		cn_dev_err("NULL ptr.");
		return 0;
	}

	read_lock_my(&udvm_set->pm_task_root->rb_lock);

	pst_task = __FIND_TREE_NODE_BY_TASK(udvm_set->pm_task_root, tgid);
	if (pst_task) {
		if (pst_task->hostmem_priv != hostmem_priv) {
			read_unlock_my(&udvm_set->pm_task_root->rb_lock);
			cn_dev_err("current pst_task(%d) not belongs to input priv(%px)",
				tgid, hostmem_priv);
			return 0;
		}

		pst_uva = __FIND_TREE_NODE_BY_UVA(pst_task, uaddr);
		if (pst_uva) {
			read_unlock_my(&udvm_set->pm_task_root->rb_lock);
			return 0;
		}
	}
	read_unlock_my(&udvm_set->pm_task_root->rb_lock);

	chunks = pst_blk->chunks;
	page_index = 0;

	for (i = 0; vma && i < chunks && usize < va_size; i++) {
		int ret = 0;

		size = pst_blk->pages_cnt[i] << PAGE_SHIFT;

		cn_mmap_write_lock(current->mm);
		ret = pinned_vm_insert_pages(vma, va_start, &pst_blk->pages[page_index],
									 pst_blk->pages_cnt[i]);
		cn_mmap_write_unlock(current->mm);
		if (ret) {
			cn_dev_err("remap_pfn_range failed.");
			return 0;
		}

		page_index += pst_blk->pages_cnt[i];
		va_start += size;
		usize += size;
	}

	pst_uva = cn_kzalloc(sizeof(struct pinned_mem_va), GFP_KERNEL);
	if (!pst_uva) {
		cn_dev_err("Kmalloc pinned_mem_va failed.");
		return 0;
	}

	pst_uva->task = (unsigned long)(tgid);
	pst_uva->va_start = uaddr;
	pst_uva->vm_size = va_size;
	pst_uva->pst_blk = pst_blk;
	atomic_set(&pst_uva->refcnt, 1);

	write_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_task = __FIND_TREE_NODE_BY_TASK(udvm_set->pm_task_root, tgid);
	if (!pst_task) {
		pst_task = cn_kzalloc(sizeof(struct pinned_mem_task), GFP_ATOMIC);
		if (!pst_task) {
			cn_dev_err("Kmalloc pinned_mem_task failed.");
			write_unlock_my(&udvm_set->pm_task_root->rb_lock);
			cn_kfree(pst_uva);
			return 0;
		}

		pst_task->task = (unsigned long)(tgid);
		pst_task->size = 1;
		pst_task->rb_uva = RB_ROOT;
		pst_task->hostmem_priv = hostmem_priv;
		atomic_set(&pst_task->uva_cnt, 0);
		atomic_set(&pst_task->refcnt, 1);

		insert_pinned_mem_task(udvm_set->pm_task_root, pst_task);
		insert_flag = 1;
	} else {
		WARN(pst_task->hostmem_priv != hostmem_priv,
			 "ATTENTION: alloc pinned memory with multi different fp, it's not allowed");
	}

	atomic_inc(&pst_task->uva_cnt);
	insert_pinned_mem_va(pst_task, pst_uva);
	write_unlock_my(&udvm_set->pm_task_root->rb_lock);

	if (insert_flag) {
		spin_lock(&hostmem_priv->task_lock);
		list_add(&pst_task->lnode, &hostmem_priv->task_list);
		spin_unlock(&hostmem_priv->task_lock);
	}

	return va_size;
}

static unsigned long
__remove_uva_from_tree(pid_t tgid, unsigned long va, bool is_equal)
{
	struct pinned_mem_va *pst_uva = NULL;
	struct pinned_mem_task *pst_task = NULL;
	struct pinned_mem *pst_blk = NULL;
	unsigned long size = 0;
	int need_free = 0;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	write_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_task = __FIND_TREE_NODE_BY_TASK(udvm_set->pm_task_root, tgid);
	if (!pst_task) {
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		goto out;
	}

	if (is_equal) {
		pst_uva = __FIND_TREE_NODE_BY_UVA_EQ(pst_task, va);
	} else {
		pst_uva = __FIND_TREE_NODE_BY_UVA(pst_task, va);
	}

	if (!pst_uva) {
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		cn_dev_err("not find pst_uva for uva %lx tgid %ld.", va, (unsigned long)tgid);
		goto out;
	}

	pst_blk = pst_uva->pst_blk;
	if (!pst_blk) {
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		cn_dev_err("not find pst_blk for uva %lx tgid %ld.", va, (unsigned long)tgid);
		goto out;
	}

	if (!atomic_sub_and_test(1, &pst_uva->refcnt)) {
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		goto out;
	}

	size = pst_uva->vm_size;
	delete_pinned_mem_va(pst_task, pst_uva);

	cn_kfree(pst_uva);

	atomic_dec(&pst_task->uva_cnt);

	/* check pinned mem tree */
	if (atomic_sub_and_test(1, &pst_blk->ref_cnt))
		need_free = 1;

	write_unlock_my(&udvm_set->pm_task_root->rb_lock);

	if (need_free) {
		free_pinned_mem(&pst_blk);
	}

out:
	return size;
}

static unsigned long remove_uva_from_tree(pid_t tgid, unsigned long va)
{
	return __remove_uva_from_tree(tgid, va, true);
}

int pinned_mem_open(void **hostmem_priv)
{
	struct hostmem_priv_data *priv = NULL;

	priv = cn_kzalloc(sizeof(struct hostmem_priv_data), GFP_KERNEL);
	if (!priv) {
		cn_dev_err("alloc memory for privdata failed!");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&priv->task_list);
	spin_lock_init(&priv->task_lock);

	*hostmem_priv = (void *)priv;
	return 0;
}

/*
 * free pinned mem when process close all fds
 */
int pinned_mem_close(void *hostmem_priv)
{
	int reg_cnt = 0;
	int release_task = 0;
	struct pinned_mem_va  *pst_uva = NULL;
	struct pinned_mem_task *tmp = NULL, *pos = NULL;
	struct pinned_mem     *pst_blk = NULL;
	struct hostmem_priv_data *priv = (struct hostmem_priv_data *)hostmem_priv;
	struct list_head free_list;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	if (!priv)
		return -EINVAL;

	INIT_LIST_HEAD(&free_list);

	spin_lock(&priv->task_lock);
	list_for_each_entry_safe(pos, tmp, &priv->task_list, lnode)
		list_move(&pos->lnode, &free_list);
	spin_unlock(&priv->task_lock);

	list_for_each_entry_safe(pos, tmp, &free_list, lnode) {
		list_del_init(&pos->lnode);

		write_lock_my(&udvm_set->pm_task_root->rb_lock);

		if (atomic_sub_and_test(1, &pos->refcnt)) {
			delete_pinned_mem_task(udvm_set->pm_task_root, pos);
			release_task = 1;
		}
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);

		if (!release_task) {
			continue;
		}

		tree_traverse_and_operate(pos->rb_uva, pinned_mem_va, {
			pst_uva = post;
			pst_blk = pst_uva->pst_blk;
			reg_cnt = atomic_sub_and_test(1, &pst_blk->ref_cnt);
			if (reg_cnt) {
				free_pinned_mem(&pst_blk);
			}

			delete_pinned_mem_va(pos, pst_uva);
			cn_kfree(pst_uva);
			ret = 1;
		});

		release_task = 0;
		cn_kfree(pos);
	}

	cn_kfree(priv);
	return 0;
}

unsigned long pinned_mem_info(struct seq_file *m)
{
	unsigned long size = 0;
	unsigned long all_size = 0;
	struct pinned_mem_task *pst_tmp = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	int len;
	char buf[512];

	if (!m)
		return 0;

	read_lock_my(&udvm_set->pm_task_root->rb_lock);
	tree_traverse_and_operate(udvm_set->pm_task_root->root, pinned_mem_task, {
		pst_tmp = post;
		seq_printf(m, "TGID %ld:\n", post->task);
		size = 0;
		tree_traverse_and_operate(pst_tmp->rb_uva, pinned_mem_va, {
			size += post->vm_size;
			all_size += post->vm_size;
			if (!post->pst_blk->ob_map) {
				seq_printf(m, "  |->UVA: 0x%lx-0x%lx   KVA: 0x%lx   IOVA: 0x0  IOVA_REF: 0  BLK_REF: %d\n",
					post->va_start, post->va_start + post->vm_size,
					post->pst_blk->kva_start,
					atomic_read(&(post->pst_blk->ref_cnt)));
			} else {
				len = sprintf(buf, "  |->UVA: 0x%lx-0x%lx   KVA: 0x%lx   IOVA: %#lx  ",
					post->va_start, post->va_start + post->vm_size,
					post->pst_blk->kva_start,
					post->pst_blk->ob_map->iova);

				len += sprintf(buf + len, "IOVA_REF: %d  BLK_REF: %d ",
					post->pst_blk->ob_map->iova_ref,
					atomic_read(&(post->pst_blk->ref_cnt)));

				len += sprintf(buf + len, "DMA|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d ",
					post->pst_blk->ob_map->dev_map[0].dma_refcnt,
					post->pst_blk->ob_map->dev_map[1].dma_refcnt,
					post->pst_blk->ob_map->dev_map[2].dma_refcnt,
					post->pst_blk->ob_map->dev_map[3].dma_refcnt,
					post->pst_blk->ob_map->dev_map[4].dma_refcnt,
					post->pst_blk->ob_map->dev_map[5].dma_refcnt,
					post->pst_blk->ob_map->dev_map[6].dma_refcnt,
					post->pst_blk->ob_map->dev_map[7].dma_refcnt,
					post->pst_blk->ob_map->dev_map[8].dma_refcnt,
					post->pst_blk->ob_map->dev_map[9].dma_refcnt,
					post->pst_blk->ob_map->dev_map[10].dma_refcnt,
					post->pst_blk->ob_map->dev_map[11].dma_refcnt,
					post->pst_blk->ob_map->dev_map[12].dma_refcnt,
					post->pst_blk->ob_map->dev_map[13].dma_refcnt,
					post->pst_blk->ob_map->dev_map[14].dma_refcnt,
					post->pst_blk->ob_map->dev_map[15].dma_refcnt);

				len += sprintf(buf + len, "DEV|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d",
					post->pst_blk->ob_map->dev_map[0].dev_refcnt,
					post->pst_blk->ob_map->dev_map[1].dev_refcnt,
					post->pst_blk->ob_map->dev_map[2].dev_refcnt,
					post->pst_blk->ob_map->dev_map[3].dev_refcnt,
					post->pst_blk->ob_map->dev_map[4].dev_refcnt,
					post->pst_blk->ob_map->dev_map[5].dev_refcnt,
					post->pst_blk->ob_map->dev_map[6].dev_refcnt,
					post->pst_blk->ob_map->dev_map[7].dev_refcnt,
					post->pst_blk->ob_map->dev_map[8].dev_refcnt,
					post->pst_blk->ob_map->dev_map[9].dev_refcnt,
					post->pst_blk->ob_map->dev_map[10].dev_refcnt,
					post->pst_blk->ob_map->dev_map[11].dev_refcnt,
					post->pst_blk->ob_map->dev_map[12].dev_refcnt,
					post->pst_blk->ob_map->dev_map[13].dev_refcnt,
					post->pst_blk->ob_map->dev_map[14].dev_refcnt,
					post->pst_blk->ob_map->dev_map[15].dev_refcnt);

				seq_printf(m, "%s\n", buf);
			}
		});
		seq_printf(m, "  |->MemTotal 0x%lx\n", size);
	});
	read_unlock_my(&udvm_set->pm_task_root->rb_lock);

	if (udvm_set->obd_map) {
		seq_printf(m, "|->outbound low window used:%#lx outbound high window used:%#lx\n",
				atomic_long_read(&udvm_set->obd_map->hostpool_l.used_size),
				atomic_long_read(&udvm_set->obd_map->hostpool_h.used_size));
	}

	seq_printf(m, "|->MemTotal 0x%lx\n", all_size);
	return 0;
}

int camb_pinned_mem_init(struct cn_udvm_set *udvm_set)
{
	udvm_set->pm_blk_root = cn_kzalloc(sizeof(struct pinned_mem_rb_blk), GFP_KERNEL);
	if (!udvm_set->pm_blk_root) {
		cn_dev_err("create pm_blk_root failed");
		return -ENOMEM;
	}

	udvm_set->pm_task_root = cn_kzalloc(sizeof(struct pinned_mem_rb_task), GFP_KERNEL);
	if (!udvm_set->pm_task_root) {
		cn_dev_err("create pm_task_root failed");
		cn_kfree(udvm_set->pm_blk_root);
		return -ENOMEM;
	}

	udvm_set->pm_blk_root->root = RB_ROOT;
	udvm_set->pm_task_root->root = RB_ROOT;

	rwlock_init(&udvm_set->pm_blk_root->rb_lock);
	rwlock_init(&udvm_set->pm_task_root->rb_lock);

	return 0;
}

void camb_pinned_mem_exit(void)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct pinned_mem_task *pst_tmp = NULL;

	write_lock_my(&udvm_set->pm_task_root->rb_lock);
	tree_traverse_and_operate(udvm_set->pm_task_root->root, pinned_mem_task, {
		pst_tmp = post;
		tree_traverse_and_operate(pst_tmp->rb_uva, pinned_mem_va, {
			delete_pinned_mem_va(pst_tmp, post);
			cn_kfree(post);
			ret = 1;
		});

		delete_pinned_mem_task(udvm_set->pm_task_root, pst_tmp);
		cn_kfree(pst_tmp);
		ret = 1;
	});
	write_unlock_my(&udvm_set->pm_task_root->rb_lock);

	write_lock_my(&udvm_set->pm_blk_root->rb_lock);
	tree_traverse_and_operate(udvm_set->pm_blk_root->root, pinned_mem, {
		__free_pinned_mem(&post);
		ret = 1;
	});
	write_unlock_my(&udvm_set->pm_blk_root->rb_lock);

	cn_kfree(udvm_set->pm_blk_root);
	cn_kfree(udvm_set->pm_task_root);

	if (udvm_set->obd_map) {
		mempool_destroy(&udvm_set->obd_map->hostpool_l);
		mempool_destroy(&udvm_set->obd_map->hostpool_h);
		cn_kfree(udvm_set->obd_map);
	}
}

struct page *cn_pinned_mem_get_pages(struct pinned_mem *pst_blk, unsigned long uva_start,
	unsigned long cur_va, unsigned long *pcount)
{
	int chunks = 0;
	int pg_index = 0;
	int i = 0;
	int pg_offset = 0;
	int pg_cnt = 0;
	struct page *ppage = NULL;

	if (!pst_blk || !pcount) {
		return NULL;
	}

	if (uva_start > cur_va) {
		cn_dev_err("can not find uva start(0x%lx) cur_va(0x%lx).", uva_start, cur_va);
		return NULL;
	}

	*pcount = 0;

	chunks = pst_blk->chunks;

	pg_offset = (cur_va - uva_start) >> PAGE_SHIFT;

	for (i = 0; i < chunks; i++) {
		pg_cnt = pst_blk->pages_cnt[i];
		if (pg_offset < pg_cnt) {
			*pcount = pg_cnt - pg_offset;
			ppage = pst_blk->pages[pg_index + pg_offset];
			break;
		}

		pg_offset -= pg_cnt;
		pg_index += pg_cnt;
	}

	return ppage;
}

int cn_pinned_mem_get_chunks(struct pinned_mem *pst_blk, unsigned long uva_start,
	unsigned long cur_va, size_t len, int *start, int *end)
{
	unsigned long cur_va_end = cur_va + len;
	int pg_offset;
	int pg_cnt;
	int start_chunk;
	int end_chunk;

	if (!pst_blk) {
		cn_dev_err("psk blk is null");
		return -1;
	}

	if (uva_start > cur_va) {
		cn_dev_err("can not find uva start(0x%lx) cur_va(0x%lx).", uva_start, cur_va);
		return -1;
	}

	pg_cnt = 0;
	pg_offset = (cur_va - uva_start) >> PAGE_SHIFT;
	for (start_chunk = 0; start_chunk < pst_blk->chunks; start_chunk++) {
		pg_cnt += pst_blk->pages_cnt[start_chunk];
		if (pg_cnt >= pg_offset)
			break;
	}

	pg_cnt = 0;
	pg_offset = (cur_va_end - uva_start) >> PAGE_SHIFT;
	if ((cur_va_end - uva_start) % PAGE_SIZE)
		pg_offset++;
	for (end_chunk = 0; end_chunk < pst_blk->chunks; end_chunk++) {
		pg_cnt += pst_blk->pages_cnt[end_chunk];
		if (pg_cnt >= pg_offset)
			break;
	}

	if (start_chunk > end_chunk) {
		cn_dev_err("get chunk error start_chunk:%d end_chunk:%d", start_chunk, end_chunk);
		return -1;
	}

	*start = start_chunk;
	*end = end_chunk;

	return 0;
}

/*
 * check va in which hash entry
 *
 * cn_pinned_mem_check must running in userspace process context.
 * heap mem space maybe not PAGE_ALIGN which align with 0x10, So add size to check.
 */
struct pinned_mem_va *cn_pinned_mem_check(struct task_struct *task,
		unsigned long va, unsigned long size)
{
	struct pinned_mem_va *pst_uva = NULL;
	pid_t tgid = task->tgid;

	pst_uva = find_pinned_mem_va(tgid, va, false);
	if (pst_uva && (va + size) > (pst_uva->va_start + pst_uva->vm_size)) {
		return NULL;
	}

	return pst_uva;
}

int cn_pinned_mem_uva_locked(unsigned long va)
{
	struct pinned_mem_va *pst_uva = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	int ret = -EINVAL;

	write_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __find_pinned_mem_va(udvm_set->pm_task_root, current->tgid, va, false);

	if (pst_uva) {
		atomic_inc(&pst_uva->refcnt);
		ret = 0;
	}

	write_unlock_my(&udvm_set->pm_task_root->rb_lock);

	return ret;
}

void cn_pinned_mem_uva_unlocked(unsigned long va)
{
	unsigned long size = 0;

	size = __remove_uva_from_tree(current->tgid, va, false);
	if (size > 0) { /* size > 0 means remove success */
		vm_munmap(va, size);
	}
}

/*
 * check kva in which hash entry
 */
struct pinned_mem *
cn_async_pinned_mem_check(unsigned long kva)
{
	struct pinned_mem  *pst_kva = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	read_lock_my(&udvm_set->pm_blk_root->rb_lock);
	pst_kva = __FIND_TREE_NODE_BY_KVA(udvm_set->pm_blk_root, kva);
	read_unlock_my(&udvm_set->pm_blk_root->rb_lock);

	return pst_kva;
}

/*
 * Alloc the host pinned memory with numa node.
 * And same as the cn_pinned_mem_alloc function, it only be used in current task
 * context.
 */
int cn_pinned_mem_alloc_node(struct file *fp, unsigned long arg, unsigned int cond)
{
	struct pinned_mem_node_param *pm_param = NULL;
	struct vm_area_struct *vma;
	struct pinned_mem *pst_blk = NULL;
	int ret;
	unsigned long va = 0;
	unsigned long size;
	unsigned long valid_size = 0;
	unsigned int id = -1; /* core id */
	unsigned int node = -1; /* memory numa node */
	CN_HOSTALLOC_TYPE type = CN_HOSTALLOC_TYPE_DEFAULT;
	struct cn_mm_set *mm_set = NULL;

	pm_param = (struct pinned_mem_node_param *)cn_kzalloc(cond, GFP_KERNEL);
	if (!pm_param) {
		cn_dev_err("pm_param alloc failed.");
		return -ENOMEM;
	}

	ret = copy_from_user((void *)pm_param, (void *)arg, cond);
	if (ret) {
		cn_dev_err("copy_from_user failed.");
		ret = -EINVAL;
		goto free_pm_param;
	}

	size = pm_param->size;
	if ((long)size <= 0) {
		cn_dev_err("pinned mem size : %ld invalid", (long)size);
		ret = -EINVAL;
		goto free_pm_param;
	}

	if (!check_si_meminfo(size)) {
		cn_dev_err("The host memory free size is less than allocated size!");
		ret = -ENOMEM;
		goto free_pm_param;
	}

	va = vm_mmap(fp, 0, size, PROT_READ | PROT_WRITE, MAP_SHARED, 0);
	if (IS_ERR_VALUE(va) || (va + size < va)) {
		cn_dev_err("vm_mmap error va:%lx, size:%ld", va, size);
		ret = -ENOMEM;
		goto free_pm_param;
	}

	vma = pinned_mem_find_vma(current->mm, va, size);
	if (!vma) {
		cn_dev_err("mem alloc find vma is NULL");
		ret = -ENOMEM;
		goto free_vm_mmap;
	}

	id = pm_param->id;
	if ((int)id < 0) {
		pst_blk = alloc_pinned_mem(type, va, size);
		goto pst_chk;
	}

	mm_set = __get_mmset_with_index(id);
	if (mm_set->numa_enable == true) {
		/* Get host memory numa node with device id */
		node = cn_core_get_numa_node(id);
		if (unlikely((int)node < 0)) {
			pst_blk = alloc_pinned_mem(type, va, size);
		} else {
			pst_blk = alloc_pinned_mem_node(type, va, size, node);
		}
	} else {
		pst_blk = alloc_pinned_mem(type, va, size);
	}

pst_chk:
	if (!pst_blk) {
		cn_dev_err("alloc pinned mem failed. size(0x%lx)", size);
		ret = -ENOMEM;
		goto free_vm_mmap;
	}

	atomic_inc(&pst_blk->ref_cnt);
	/*default value is CN_MEMHOSTALLOC_DEVICEMAP*/
	pst_blk->flags = CN_MEMHOSTALLOC_DEVICEMAP;

	/* map to kernel space */
	ret = pinnde_mem_vmap(pst_blk);
	if (ret) {
		atomic_dec(&pst_blk->ref_cnt);
		goto free_pinned_mems;
	}

	valid_size = insert_uva_to_tree(fp, vma, current->tgid, pst_blk, va, size);
	if (valid_size != size) {
		cn_dev_err("insert_uva_to_tree size not match. %#llx %#llx\n",
				(u64)valid_size, (u64)size);
		ret = -ENOMEM;
		atomic_dec(&pst_blk->ref_cnt);
		goto free_pinned_mems;
	}

	pm_param->uaddr = (unsigned long)va;
	if (copy_to_user((void *)arg, (void *)pm_param, cond)) {
		cn_dev_err("copy_to_user failed.");
		ret = -EINVAL;
		goto free_remove;
	}

	cn_kfree(pm_param);
	return 0;

free_remove:
	valid_size = remove_uva_from_tree(current->tgid, va);
	if (valid_size != size) {
		cn_dev_err("remove_uva_from_tree error.");
	}
	pst_blk = NULL;
free_pinned_mems:
	free_pinned_mem(&pst_blk);
free_vm_mmap:
	vm_munmap(va, size);
free_pm_param:
	cn_kfree(pm_param);
	return ret;
}

int cn_pinned_mem_alloc_internal(struct file *fp, unsigned long *p_va,
								 unsigned long size, int flags)
{
	struct vm_area_struct *vma;
	struct pinned_mem *pst_blk = NULL;
	int ret;
	unsigned long va = 0;
	unsigned long valid_size = 0;
	CN_HOSTALLOC_TYPE type = CN_HOSTALLOC_TYPE_DEFAULT;

	if (!check_si_meminfo(size)) {
		cn_dev_err("remain host memory is not support use!");
		return -ENOMEM;
	}

	va = vm_mmap(fp, 0, size, PROT_READ | PROT_WRITE, MAP_SHARED, 0);
	if (IS_ERR_VALUE(va)) {
		cn_dev_err("vm_mmap error va:%ld, size:%#lx", va, size);
		return va;
	}

	vma = pinned_mem_find_vma(current->mm, va, size);
	if (!vma) {
		cn_dev_err("mem alloc find vma is NULL");
		ret = -ENOMEM;
		goto free_vm_mmap;
	}

	pst_blk = alloc_pinned_mem(type, va, size);
	if (!pst_blk) {
		cn_dev_err("alloc pinned mem failed. size(0x%lx)", size);
		ret = -ENOMEM;
		goto free_vm_mmap;
	}
	atomic_inc(&pst_blk->ref_cnt);
	pst_blk->flags = flags;

	/* map to kernel space */
	ret = pinnde_mem_vmap(pst_blk);
	if (ret) {
		atomic_dec(&pst_blk->ref_cnt);
		cn_dev_err("map to kernel space failed, ret(0x%x).", ret);
		goto free_pinned_mems;
	}

	valid_size = insert_uva_to_tree(fp, vma, current->tgid, pst_blk, va, size);
	if (valid_size != size) {
		cn_dev_err("insert_uva_to_tree size not match.%#lx %#lx", size, valid_size);
		ret = -ENOMEM;
		atomic_dec(&pst_blk->ref_cnt);
		goto free_pinned_mems;
	}

	*p_va = va;

	return 0;

free_pinned_mems:
	free_pinned_mem(&pst_blk);
free_vm_mmap:
	vm_munmap(va, size);
	return ret;
}

int cn_pinned_mem_free_internal(unsigned long va)
{
	int ret;
	unsigned long size;

	/*return the actual size of va*/
	size = remove_uva_from_tree(current->tgid, va);
	if (!size) {
		cn_dev_err("remove_uva_from_tree error: %ld.", va);
		return -EFAULT;
	}

	ret = vm_munmap(va, size);
	if (ret) {
		cn_dev_err("vm_munmap error va %lx size %lx ret: %d",
				va, size, ret);
		return ret;
	}

	return 0;
}

/*
 * Alloc the host pinned memory with numa node and type.
 * And same as the cn_pinned_mem_alloc function, it only be used in current task
 * context.
 */
int cn_pinned_mem_flag_alloc(struct file *fp, unsigned long arg, unsigned int cond)
{
	struct pinned_mem_flag_param pm_flag_param;
	int ret;
	unsigned long size;
	unsigned long uva;
	struct cn_mm_set *mm_set = NULL;

	ret = copy_from_user((void *)&pm_flag_param, (void *)arg, cond);
	if (ret) {
		cn_dev_err("copy_from_user failed.");
		return -EINVAL;
	}

	mm_set = __get_mmset_with_index(pm_flag_param.card_id);
	if (!mm_set) {
		cn_dev_err("card id error.");
		return -EINVAL;
	}

	if (!mm_set->obmap_support) {
		cn_dev_err("No support outbound.");
		return -EPERM;
	}

	if (pm_flag_param.flags != CN_MEMHOSTALLOC_DEVICEMAP) {
		cn_dev_err("only support CN_MEMHOSTALLOC_DEVICEMAP current");
		return -EINVAL;
	}

	size = camb_dob_size_align(pm_flag_param.size, mm_set);
	if (!size) {
		cn_dev_err("size align fail");
		return -EINVAL;
	}

	ret = cn_pinned_mem_alloc_internal(fp, &uva, size, pm_flag_param.flags);
	if (ret) {
		cn_dev_err("pinned mem alloc internal fail.");
		return ret;
	}
	pm_flag_param.uaddr = uva;

	if (copy_to_user((void *)arg, (void *)&pm_flag_param, cond)) {
		cn_dev_err("copy_to_user failed.");
		cn_pinned_mem_free_internal(pm_flag_param.uaddr);
		return -EINVAL;
	}

	return 0;
}

bool __wait_ob_map_complete(struct ob_map_t *ob_map)
{
	int time_out = 10000;

	while (time_out--) {
		if (ob_map->status == OB_MAP_COMPLETE)
			return true;

		udelay(100);
	}

	cn_dev_err("status:%d error", ob_map->status);

	return false;
}

/*return 0 if mapped && mapped successful, other value mapped error or not mapped*/
int camb_search_ob_map(struct list_head *head, int card_id, struct ob_map_t **obmap)
{
	struct ob_map_t *ob, *tmp;
	int find_flag = 0;

	list_for_each_entry_safe(ob, tmp, head, list_node) {
		if (card_id == ob->card_id) {
			*obmap = ob;
			find_flag = 1;
			break;
		}
	}

	/*not found ob map*/
	if (!find_flag)
		return -ENXIO;

	/**
	 * ob_map has been found here,but maybe not use,
	 * because other thread maybe mapping iova.
	 * We must use spin_lock, but map iova might_sleep,
	 * so map iova after spin_unlock. Here check whether
	 * map successful.
	 **/
	if (__wait_ob_map_complete(ob)) {
		return 0;
	}

	return -EINVAL;
}

int __register_uva_to_pinned_mem(struct file *fp, unsigned long va, unsigned long size, int flags)
{
	struct pinned_mem *pst_blk = NULL;
	int ret = 0, pages_needed, cnt;
	struct mm_struct *mm = current->mm;
	u64 valid_size;
	u64 va_start;
	struct page **tmp_pages;
	int *tmp_index;
	int i;
	int chunks;
	pid_t tgid = current->tgid;
	struct vm_area_struct *vma;
	struct udvm_ob_map_t *ob_map = NULL;

	cn_mmap_write_lock(mm);
	/*Maybe vma is stack space.*/
	vma = find_vma(mm, va);
	if (!vma || va < vma->vm_start || (va + size) > vma->vm_end) {
		cn_dev_err("uva:%#lx size:%#lx is invalid", va, size);
		if (vma) {
			cn_dev_err("vma :va:%#llx size:%#llx", (u64)vma->vm_start,
					(u64)vma->vm_end - (u64)vma->vm_start);
		}
		cn_mmap_write_unlock(mm);
		return -EINVAL;
	}

	cn_mmap_write_unlock(mm);

	/*va and size have been PAGE_ALIGNED.*/
	pages_needed = size / PAGE_SIZE;
	va_start = va;

	tmp_pages = cn_vmalloc(sizeof(struct page *) * pages_needed);
	if (!tmp_pages) {
		cn_dev_err("vmalloc fail.");
		return -ENOMEM;
	}
	memset(tmp_pages, 0, sizeof(struct pages *) * pages_needed);

	tmp_index = cn_vmalloc(sizeof(int) * pages_needed);
	if (!tmp_index) {
		cn_dev_err("no os mem");
		ret = -ENOMEM;
		goto free_pages;
	}
	memset(tmp_index, 0, sizeof(int) * pages_needed);

	cn_mmap_write_lock(mm);
	cnt = cn_get_user_pages(va_start, pages_needed, FOLL_WRITE, tmp_pages, NULL);
	cn_mmap_write_unlock(mm);

	if (cnt != pages_needed) {
		cn_dev_err("get user pages fail cnt:%d,%d", cnt, pages_needed);
		ret = -ENXIO;
		goto put_pages;
	}

	chunks = 1;
	for (i = 1; i < cnt; ++i) {
		tmp_index[chunks - 1]++;
		if (page_to_pfn(tmp_pages[i]) != page_to_pfn(tmp_pages[i - 1]) + 1) {
			chunks++;
		}
	}
	tmp_index[chunks - 1]++;

	pst_blk = cn_kzalloc(sizeof(struct pinned_mem), GFP_KERNEL);
	if (!pst_blk) {
		ret = -ENOMEM;
		cn_dev_err("Kmalloc pinned_mem failed.");
		goto put_pages;
	}

	ob_map = cn_kzalloc(sizeof(struct udvm_ob_map_t), GFP_KERNEL);
	if (!ob_map) {
		cn_dev_err("malloc ob_map_t fail.");
		goto free_blk;
	}

	pst_blk->pages_cnt = tmp_index;
	pst_blk->pages = tmp_pages;
	pst_blk->chunks = chunks;
	pst_blk->flags = flags;

	mutex_init(&ob_map->map_lock);
	pst_blk->ob_map = ob_map;

	pst_blk->type = CN_HOSTALLOC_TYPE_REGISTER;
	atomic_set(&pst_blk->ref_cnt, 0);
	atomic_set(&pst_blk->k_rcnt, 0);
	pst_blk->vm_size = size;

	atomic_inc(&pst_blk->ref_cnt);

	valid_size = insert_uva_to_tree(fp, NULL, tgid, pst_blk, va_start, size);
	if (valid_size != size) {
		cn_dev_err("insert_uva_to_tree size not match.\n");
		ret = -ENOMEM;
		goto free_ob_map;
	}

	return 0;

free_ob_map:
	cn_kfree(ob_map);
free_blk:
	cn_kfree(pst_blk);
put_pages:
	for (i = 0; i < cnt; i++) {
		put_page(tmp_pages[i]);
	}
	cn_vfree(tmp_index);
free_pages:
	cn_vfree(tmp_pages);
	return ret;
}

struct pinned_mem_va *__search_pst_uva(struct pinned_mem_rb_task *pm_task_root, u64 va, u64 size)
{
	struct pinned_mem_task *pst_task = NULL;
	struct pinned_mem_va *pst_uva = NULL;

	pst_task = __FIND_TREE_NODE_BY_TASK(pm_task_root, current->tgid);
	if (!pst_task) {
		return NULL;
	}

	pst_uva = __FIND_TREE_NODE_BY_UVA(pst_task, va);
	if (!pst_uva) {
		return NULL;
	}

	if ((pst_uva->va_start + pst_uva->vm_size) < (va + size)) {
		return NULL;
	}

	return pst_uva;
}

static int register_uva_to_pinned_mem(struct file *fp, u64 uva, u64 size,
									  int flags)
{
	struct pinned_mem_va *pst_uva = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	int ret;

	write_lock_my(&udvm_set->pm_task_root->rb_lock);

	pst_uva = __search_pst_uva(udvm_set->pm_task_root, uva, size);
	if (pst_uva) {
		if (pst_uva->pst_blk->type == CN_HOSTALLOC_TYPE_REGISTER) {
			/*TODO: need return already value*/
			cn_dev_err("%#llx already register.", uva);
		} else {
			cn_dev_err("This type no support register.");
		}

		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		return -EINVAL;
	}

	write_unlock_my(&udvm_set->pm_task_root->rb_lock);

	/*uva is stack or heap space, here maybe sleep.*/
	ret = __register_uva_to_pinned_mem(fp, uva, size, flags);
	if (ret) {
		cn_dev_err("register uva to pinned mem error");
	}

	return ret;
}

struct ob_map_t *camb_init_ob_map(struct sg_table *table, void *priv,
	void (*sgt_release)(void *, struct sg_table *), unsigned long size, struct cn_mm_set *mm_set, dev_addr_t iova)
{
	unsigned long aligned_size = ALIGN(size, camb_get_page_size());
	struct ob_map_t *ob = NULL;
	phys_addr_t dev_paddr = 0;
	dev_addr_t dev_vaddr = 0;
	int ret = 0;

	if (!sgt_release) {
		cn_dev_err("need init sgt_release at first");
		return ERR_PTR(-EINVAL);
	}

	ob = cn_kzalloc(sizeof(struct ob_map_t), GFP_KERNEL);
	if (!ob) {
		cn_dev_err("os mem alloc fail.");
		sgt_release(priv, table);
		return ERR_PTR(-ENOMEM);
	}

	ob->card_id = get_index_with_mmset(mm_set);
	ob->mm_set = mm_set;
	ob->status = OB_RPC_CONFIG;
	ob->table = table;
	ob->priv = priv;
	ob->sgt_release = sgt_release;

	ret = camb_dob_dev_mem_alloc(&dev_paddr, &dev_vaddr, aligned_size, ob->table, mm_set);
	if (ret) {
		cn_dev_err("dob mem alloc fail.");
		sgt_release(priv, table);
		cn_kfree(ob);
		return ERR_PTR(ret);
	}

	ob->device_pa = dev_paddr;
	ob->device_va = dev_vaddr;
	ob->iova = !iova ? dev_vaddr : iova;
	ob->iova_size = aligned_size;
	INIT_LIST_HEAD(&ob->list_node);

	return ob;
}

int cn_pinned_mem_host_register(struct file *fp, unsigned long arg,
		unsigned int cond)
{
	struct pinned_mem_host_reg_param pm_param = {0};
	int ret;
	CN_MEMHOSTREGISTER_FLAG flag;

	if (cond != sizeof(pm_param)) {
		cn_dev_err("param error.");
		return -EINVAL;
	}

	ret = copy_from_user((void *)&pm_param, (void *)arg, cond);
	if (ret) {
		cn_dev_err("copy_from_user failed.");
		return -EINVAL;
	}

	flag = pm_param.flags;
	if (flag != CN_MEMHOSTREGISTER_DEVICEMAP) {
		cn_dev_err("only support CN_MEMHOSTREGISTER_DEVICEMAP current");
		return -EINVAL;
	}

	flag = CN_MEMHOSTALLOC_DEVICEMAP;

	return cn_pinned_mem_host_register_internal(fp, pm_param.uaddr, pm_param.size,
										flag, pm_param.card_id);
}

struct pinned_mem_va *__search_register_pst_uva(struct pinned_mem_rb_task *pm_task_root, u64 uva)
{
	struct pinned_mem_va *pst_uva = NULL;
	struct pinned_mem *pst_blk = NULL;

	pst_uva = __search_pst_uva(pm_task_root, uva, 0);
	if (!pst_uva) {
		cn_dev_err("uva:%#llx is invalid\n", uva);
		return NULL;
	}

	if (uva != pst_uva->va_start) {
		cn_dev_err("uva is error. %#llx need:%#llx", uva,
				(u64)pst_uva->va_start);
		return NULL;
	}

	pst_blk = pst_uva->pst_blk;
	if (!pst_blk) {
		cn_dev_err("pst_blk is NULL\n");
		return NULL;
	}

	if (pst_blk->type != CN_HOSTALLOC_TYPE_REGISTER) {
		cn_dev_err("pst_blk or type(%d) is invalid\n", pst_blk->type);
		return NULL;
	}

	return pst_uva;
}

/*old version*/
int cn_pinned_mem_host_unregister(struct file *fp, unsigned long arg,
		unsigned int cond)
{
	struct pinned_mem_host_unreg_param pm_param = {0};
	struct pinned_mem_va *pst_uva = NULL;
	u64 va;
	int ret;
	struct cn_mm_set *mm_set = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	if (cond != sizeof(pm_param)) {
		cn_dev_err("pinned mem param error.");
		return -EINVAL;
	}

	ret = copy_from_user((void *)&pm_param, (void *)arg, cond);
	if (ret) {
		cn_dev_err("copy_from_user failed.");
		return -EINVAL;
	}

	mm_set = __get_mmset_with_index(pm_param.card_id);
	if (!mm_set) {
		cn_dev_err("card id error.");
		return -EINVAL;
	}

	if (!mm_set->obmap_support) {
		cn_dev_err("No support outbound.");
		return -EPERM;
	}

	if (addr_is_udvm(pm_param.uaddr)) {
		return camb_peer_unregister((u64)fp, NULL, pm_param.uaddr, mm_set);
	}

	write_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __search_register_pst_uva(udvm_set->pm_task_root, pm_param.uaddr);
	if (!pst_uva) {
		cn_dev_err("Not find pst_uva that type is register.");
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		return -EINVAL;
	}

	va = pst_uva->va_start;

	write_unlock_my(&udvm_set->pm_task_root->rb_lock);

	if (!remove_uva_from_tree(current->tgid, va)) {
		cn_dev_err("remove_uva_from_tree error.");
		return -EFAULT;
	}

	return ret;
}

int cn_pinned_mem_get_flags(struct file *fp, unsigned long arg,
		unsigned int cond)
{
	struct pinned_mem_get_flags_param pm_param = {0};
	struct pinned_mem_va *pst_uva = NULL;
	struct pinned_mem *pst_blk = NULL;
	struct cn_mm_set *mm_set = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	if (cond != sizeof(pm_param)) {
		cn_dev_err("pinned mem param error.");
		return -EINVAL;
	}

	if (copy_from_user((void *)&pm_param, (void *)arg, cond)) {
		cn_dev_err("copy_from_user failed.");
		return -EINVAL;
	}

	mm_set = __get_mmset_with_index(pm_param.card_id);
	if (!mm_set) {
		cn_dev_err("card id error.");
		return -EINVAL;
	}

	if (!mm_set->obmap_support) {
		cn_dev_err("No support outbound.");
		return -EPERM;
	}

	write_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __search_pst_uva(udvm_set->pm_task_root, pm_param.uaddr, 0);
	if (!pst_uva) {
		cn_dev_err("uva:%#llx is invalid\n", pm_param.uaddr);
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		return -EINVAL;
	}

	pst_blk = pst_uva->pst_blk;
	if (!pst_blk) {
		cn_dev_err("pst_blk is invalid\n");
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		return -EINVAL;
	}

	pm_param.flags = pst_blk->flags;
	write_unlock_my(&udvm_set->pm_task_root->rb_lock);

	if (copy_to_user((void *)arg, (void *)&pm_param, cond)) {
		cn_dev_err("copy_to_user failed.");
		return -EINVAL;
	}

	return 0;
}

void camb_pst_blk_kref_put(struct pinned_mem *pst_blk)
{
	if (atomic_sub_and_test(1, &pst_blk->ref_cnt)) {
		free_pinned_mem(&pst_blk);
	}
}

static int __ob_map_alloc_sg_table(struct pinned_mem *pst_blk, struct udvm_ob_map_t *ob,
								unsigned int card_id)
{
	struct sg_table *table = NULL;
	unsigned long total_size = PAGE_ALIGN(pst_blk->vm_size);
	int ret = 0, cnt = 0, i = 0;

	table = cn_kzalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!table) {
		cn_dev_err("alloc sg_table failed.");
		return -ENOMEM;
	}

	for (i = 0; i < pst_blk->chunks; i++) {
		cnt += pst_blk->pages_cnt[i];
	}

	ret = cn_sg_alloc_table_from_pages(table, pst_blk->pages, cnt, 0,
									  total_size, GFP_KERNEL);
	if (ret) {
		cn_kfree(table);
		cn_dev_err("set sg table fail.");
		return -ENOMEM;
	}

	ob->dev_map[card_id].table = table;
	cn_sg_clear_offset(ob->dev_map[card_id].table->sgl);

	return 0;
}

static int map_dma(struct pinned_mem *pst_blk, struct udvm_ob_map_t *ob_map, int card_id)
{
	struct sg_table *sg_table;
	struct device *dev;
	int ret = 0;
	int cnt;

	/*alloc sg table for ob_map->dev_map[card_id]*/
	ret = __ob_map_alloc_sg_table(pst_blk, ob_map, card_id);
	if (ret) {
		cn_dev_err("sg table init error for card %d\n",  card_id);
		return ret;
	}

	sg_table = ob_map->dev_map[card_id].table;
	cnt = sg_nents(sg_table->sgl);
	dev = cn_core_get_dev(card_id);
	ret = dma_map_sg(dev, sg_table->sgl, cnt, DMA_BIDIRECTIONAL);
	if (!ret) {
		cn_dev_err("map dma for card %d failed.%#llx\n", card_id, (u64)ret);
		sg_free_table(sg_table);
		cn_kfree(sg_table);
		ob_map->dev_map[card_id].table = NULL;
		return -ENOMEM;
	}

	return 0;
}

static int unmap_dma(struct udvm_ob_map_t *ob_map, int card_id)
{
	struct device *dev;
	int cnt;
	struct sg_table *sg_table;

	sg_table = ob_map->dev_map[card_id].table;
	cnt = sg_nents(sg_table->sgl);
	dev = cn_core_get_dev(card_id);
	dma_unmap_sg(dev, sg_table->sgl, cnt, DMA_BIDIRECTIONAL);

	sg_free_table(sg_table);
	cn_kfree(sg_table);
	ob_map->dev_map[card_id].table = NULL;

	return 0;
}

static int unmap_ob_win(struct udvm_ob_map_t *ob, int card_id)
{
	return __map_ob_win_internal(ob, card_id, false);
}

static int map_ob_win(struct udvm_ob_map_t *ob, int card_id)
{
	return __map_ob_win_internal(ob, card_id, true);
}

static int comppatible_init_udvm_ob_map(struct udvm_ob_map_t *ob_map, struct pinned_mem *pst_blk,
		int card_id, unsigned long iova_size)
{
	dev_addr_t iova, device_pa;
	int ret;

	ret = map_dma(pst_blk, ob_map, card_id);
	if (ret) {
		cn_dev_err("map dma error.");
		return ret;
	}

	if (!ob_map->iova) {
		if (camb_dob_iova_alloc(&iova, &device_pa, iova_size,
					ob_map->dev_map[card_id].table)) {
			cn_dev_err("dob mem alloc fail.");
			ret = -ENOSPC;
			goto free_dma;
		}

		ob_map->device_pa = device_pa;
		ob_map->iova_size = iova_size;
		ob_map->iova = iova;
		ob_map->iova_ref = 1;
	}

	ret = map_ob_win(ob_map, card_id);
	if (ret) {
		cn_dev_err("map outbound win failed.%d", ret);
		goto free_iova;
	}

	ob_map->dev_map[card_id].dev_refcnt = 1;
	ob_map->dev_map[card_id].dma_refcnt = 1;

	return 0;

free_iova:
	if (!ob_map->iova) {
		camb_dob_iova_free(iova, iova_size);
		ob_map->device_pa = 0;
		ob_map->iova_size = 0;
		ob_map->iova = 0;
		ob_map->iova_ref = 0;
	}
free_dma:
	unmap_dma(ob_map, card_id);
	return ret;
}

/*old version*/
int cn_pinned_mem_get_device_pointer(struct file *fp, unsigned long arg,
		unsigned int cond)
{
	struct pinned_mem_get_device_pointer_param pm_param = {0};
	struct pinned_mem *pst_blk = NULL;
	struct pinned_mem_va *pst_uva = NULL;
	struct udvm_ob_map_t *ob_map = NULL;
	unsigned long size = 0;
	int card_id;
	int ret;
	struct cn_mm_set *mm_set = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	u64 iova_size = 0;

	if (cond != sizeof(pm_param)) {
		cn_dev_err("param error.");
		return -EINVAL;
	}

	ret = copy_from_user((void *)&pm_param, (void *)arg, cond);
	if (ret) {
		cn_dev_err("copy_from_user failed.");
		return -EINVAL;
	}

	mm_set = __get_mmset_with_index(pm_param.card_id);
	if (!mm_set) {
		cn_dev_err("card id error.");
		return -EINVAL;
	}

	if (!mm_set->obmap_support) {
		cn_dev_err("No support outbound.");
		return -EPERM;
	}

	/*only support flags is 0*/
	if (pm_param.flags != 0) {
		cn_dev_err("only support flags = 0 current");
		return -EINVAL;
	}

	if (addr_is_udvm(pm_param.uaddr)) {
		ret = camb_peer_get_pointer((u64)fp, NULL, pm_param.uaddr, mm_set,
					&pm_param.iova, pm_param.flags);
		if (ret) {
			cn_dev_err("get peer memory device pointer failed:%d", ret);
			return ret;
		}

		return copy_to_user((void *)arg, (void *)&pm_param, cond);
	}

	write_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __search_pst_uva(udvm_set->pm_task_root, pm_param.uaddr, 0);
	if (!pst_uva) {
		cn_dev_err("uva:%#llx is invalid\n", pm_param.uaddr);
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		return -EINVAL;
	}

	iova_size = ALIGN(PAGE_ALIGN(pst_uva->vm_size), 0x10000);

	pst_blk = pst_uva->pst_blk;
	if (!pst_blk) {
		cn_dev_err("pst_blk is invalid\n");
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		return -EINVAL;
	}

	size = pst_blk->vm_size;
	card_id = pm_param.card_id;

	ob_map = pst_blk->ob_map;

	/*protect pst_blk don't free after write_unlock_my*/
	atomic_inc(&pst_blk->ref_cnt);
	write_unlock_my(&udvm_set->pm_task_root->rb_lock);

	mutex_lock(&ob_map->map_lock);

	if (ob_map->dev_map[card_id].table) {
		pm_param.iova = ob_map->iova + pm_param.uaddr - pst_uva->va_start;
		mutex_unlock(&ob_map->map_lock);
		camb_pst_blk_kref_put(pst_blk);
		return copy_to_user((void *)arg, (void *)&pm_param, cond);
	}

	ret = comppatible_init_udvm_ob_map(ob_map, pst_blk, card_id, iova_size);
	if (ret) {
		mutex_unlock(&ob_map->map_lock);
		camb_pst_blk_kref_put(pst_blk);
		return ret;
	}

	pm_param.iova = ob_map->iova + pm_param.uaddr - pst_uva->va_start;

	mutex_unlock(&ob_map->map_lock);

	camb_pst_blk_kref_put(pst_blk);

	return copy_to_user((void *)arg, (void *)&pm_param, cond);
}

/*
 * the function only can be use for current task text
 * for example: ioctl
 */

int cn_pinned_mem_alloc(struct file *fp, unsigned long arg, unsigned int cond)
{
	void *pm_param = cn_kzalloc(cond, GFP_KERNEL);
	int ret;
	unsigned long va = 0;
	unsigned long size;

	if (!pm_param) {
		cn_dev_err("pm_param alloc failed.");
		return -ENOMEM;
	}

	ret = copy_from_user((void *)pm_param, (void *)arg, cond);
	if (ret) {
		cn_dev_err("copy_from_user failed.");
		ret = -EINVAL;
		goto free_pm_param;
	}

	size = GET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, size);
	if ((long)size <= 0) {
		cn_dev_err("pinned mem size : %ld invalid", (long)size);
		ret = -EINVAL;
		goto free_pm_param;
	}

	ret = cn_pinned_mem_alloc_internal(fp, &va, size, CN_MEMHOSTALLOC_DEVICEMAP);
	if (ret) {
		cn_dev_err("alloc pinned mem failed.");
		ret = -EINVAL;
		goto free_pm_param;
	}

	SET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, uaddr, (unsigned long)va);
	if (copy_to_user((void *)arg, (void *)pm_param, cond)) {
		cn_dev_err("copy_to_user failed.");
		ret = -EINVAL;
		goto free_pinned_mem;
	}

	cn_kfree(pm_param);
	return 0;

free_pinned_mem:
	cn_pinned_mem_free_internal(va);
free_pm_param:
	cn_kfree(pm_param);
	return ret;
}

/*
 * the function only can be use for current task text
 * for example: ioctl
 */
int cn_pinned_mem_free(struct file *fp, unsigned long arg, unsigned int cond)
{
	unsigned long va;
	unsigned long size = 0;
	int ret = -1;

	if (copy_from_user((void *)&va, (void *)arg, sizeof(va))) {
		cn_dev_err("copy_from_user failed");
		ret = -EINVAL;
		goto out;
	}

	size = remove_uva_from_tree(current->tgid, va);
	if (!size) {
		cn_dev_err("remove_uva_from_tree error: %ld.", size);
		ret = -EFAULT;
		goto out;
	}

	ret = vm_munmap(va, size);
	if (ret) {
		cn_dev_err("vm_munmap error va %lx size %lx ret: %d", va, size, ret);
		goto out;
	}
	ret = 0;
out:
	return ret;
}

int camb_pinned_mem_ipc_get_handle(struct file *fp, host_addr_t host_vaddr,
					dev_ipc_handle_t *handle, unsigned int *flags)
{
	struct pinned_mem_va *pst_uva = NULL;
	unsigned long kva_handle = 0UL;
	pid_t tgid = current->tgid;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	read_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __find_pinned_mem_va(udvm_set->pm_task_root, tgid, host_vaddr, true);
	if (pst_uva)
		kva_handle = pst_uva->pst_blk->kva_start;
	read_unlock_my(&udvm_set->pm_task_root->rb_lock);

	if (!kva_handle) {
		cn_dev_err("Get handle search va list failed.");
		return -EFAULT;
	}

	*handle = (dev_ipc_handle_t)kva_handle;

	if (flags)
		*flags = pst_uva->pst_blk->flags;

	return 0;
}

int cn_pinned_mem_get_handle(struct file *fp, unsigned long arg, unsigned int cond)
{
	int ret;
	unsigned long va;
	unsigned long handle;
	void *pm_param = cn_kzalloc(cond, GFP_KERNEL);

	if (!pm_param) {
		cn_dev_err("pm_param alloc failed.");
		return -ENOMEM;
	}

	ret = copy_from_user((void *)pm_param, (void *)arg, cond);
	if (ret) {
		cn_dev_err("copy_from_user failed.");
		ret = -EINVAL;
		goto free_pm_param;
	}

	va = GET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, uaddr);

	ret = camb_pinned_mem_ipc_get_handle(fp, va, (dev_ipc_handle_t *)&handle, NULL);
	if (ret)
		goto free_pm_param;

	SET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, handle, handle);

	if (copy_to_user((void *)arg, (void *)pm_param, cond)) {
		cn_dev_err("copy_to_user failed.");
		ret = -EINVAL;
		goto free_pm_param;
	}

	cn_kfree(pm_param);
	return 0;

free_pm_param:
	cn_kfree(pm_param);
	return ret;
}

int camb_pinned_mem_ipc_close_handle(struct file *fp, host_addr_t host_vaddr)
{
	unsigned long size = 0;

	size = remove_uva_from_tree(current->tgid, host_vaddr);
	if (!size) {
		cn_dev_err("remove_uva_from_tree error: %ld.", size);
		return -EFAULT;
	}

	return vm_munmap(host_vaddr, size);
}

int cn_pinned_mem_close_handle(struct file *fp, unsigned long arg, unsigned int cond)
{
	int ret;
	unsigned long handle;
	void *pm_param = cn_kzalloc(cond, GFP_KERNEL);
	unsigned long va;

	if (!pm_param) {
		cn_dev_err("pm_param alloc failed.");
		return -ENOMEM;
	}

	ret = copy_from_user((void *)pm_param, (void *)arg, cond);
	if (ret) {
		cn_dev_err("copy_from_user failed.");
		ret = -EINVAL;
		goto free_pm_param;
	}

	handle = GET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, handle);
	if (bad_address((void *)handle)) {
		cn_dev_err("Open handle failed, handle invalid.\n");
		ret = -EINVAL;
		goto free_pm_param;
	}

	va = GET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, uaddr);

	ret = camb_pinned_mem_ipc_close_handle(fp, va);
	if (ret) goto free_pm_param;

	if (copy_to_user((void *)arg, (void *)pm_param, cond)) {
		cn_dev_err("copy_to_user failed.");
		ret = -EINVAL;
		goto free_pm_param;
	}

	cn_kfree(pm_param);
	return 0;

free_pm_param:
	cn_kfree(pm_param);
	return ret;
}

int camb_pinned_mem_ipc_open_handle(struct file *fp, unsigned long kva, int tgid,
			host_addr_t *host_vaddr, unsigned long *size, unsigned int *flags)
{
	struct pinned_mem *pst_blk = NULL;
	struct vm_area_struct *vma = NULL;
	unsigned long va_size = 0, valid_size = 0;
	unsigned long va = 0;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

/*DRIVER-16710 temporary modification*/
#if 0
	/*ipc get and ipc open must be executed between different process, but old version no restrict.*/
	if (tgid && tgid == current->tgid) {
		cn_dev_err("get handle can't be same tgid as open handle.");
		return -EINVAL;
	}
#endif

	read_lock_my(&udvm_set->pm_blk_root->rb_lock);
	pst_blk = __FIND_TREE_NODE_BY_KVA(udvm_set->pm_blk_root, kva);
	if (pst_blk && pst_blk->kva_start == kva) {
		atomic_inc(&pst_blk->ref_cnt);
	} else {
		pst_blk = NULL;
	}
	read_unlock_my(&udvm_set->pm_blk_root->rb_lock);

	if (!pst_blk) {
		cn_dev_err("find_pinned_mem for %#lx failed", kva);
		/**
		 * OpenHandle don't input host address, find_pinned_mem_va failed
		 * because of handle input is invalid
		 **/
		return -EINVAL;
	}

	va_size = pst_blk->vm_size;

	va = vm_mmap(fp, 0, va_size, PROT_READ | PROT_WRITE, MAP_SHARED, 0);
	if (IS_ERR_VALUE(va)) {
		cn_dev_err("Open handle vm_mmap error va:%lx, size:%ld", va,
				   pst_blk->vm_size);
		return -ENOMEM;
	}

	vma = pinned_mem_find_vma(current->mm, va, va_size);
	if (!vma) {
		vm_munmap(va, va_size);
		cn_dev_err("Open handle mem alloc find vma is NULL");
		return -ENOMEM;
	}

	valid_size = insert_uva_to_tree(fp, vma, current->tgid, pst_blk, va, va_size);
	if (valid_size != va_size) {
		vm_munmap(va, va_size);
		cn_dev_err("insert_uva_to_tree size not match.\n");
		return -ENOMEM;
	}

	if (host_vaddr) *host_vaddr = va;
	if (size) *size = va_size;
	if (flags) {
		*flags = pst_blk->flags;
	}

	return 0;
}

int cn_pinned_mem_open_handle(struct file *fp, unsigned long arg, unsigned int cond)
{
	int ret = 0;
	unsigned long va;
	unsigned long handle;
	unsigned long va_size;
	void *pm_param = cn_kzalloc(cond, GFP_KERNEL);

	if (!pm_param) {
		cn_dev_err("pm_param alloc failed.");
		return -ENOMEM;
	}

	ret = copy_from_user((void *)pm_param, (void *)arg, cond);
	if (ret) {
		cn_dev_err("copy_from_user failed.");
		ret = -EINVAL;
		goto free_pm_param;
	}

	handle = GET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, handle);

	ret = camb_pinned_mem_ipc_open_handle(fp, handle, 0, &va, &va_size, NULL);
	if (ret)
		goto free_pm_param;

	SET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, uaddr, va);
	SET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, size, va_size);

	if (copy_to_user((void *)arg, (void *)pm_param, cond)) {
		cn_dev_err("Open handle copy_to_user failed.");
		ret = -EFAULT;
		goto free_remove;
	}

	cn_kfree(pm_param);
	return 0;

free_remove:
	camb_pinned_mem_ipc_close_handle(fp, va);
free_pm_param:
	cn_kfree(pm_param);
	return ret;
}

int camb_pinned_get_mem_range(struct file *fp, host_addr_t host_vaddr,
			host_addr_t *base, unsigned long *size)
{
	struct pinned_mem_va *entry = NULL;
	pid_t tgid = current->tgid;

	entry = find_pinned_mem_va(tgid, host_vaddr, false);
	if (!entry) {
		cn_dev_err("Get range search va(0x%lx) list range failed.", host_vaddr);
		return -EFAULT;
	}

	if (base) *base = entry->va_start;
	if (size) *size = entry->vm_size;

	return 0;
}

int cn_pinned_mem_get_range(struct file *fp, unsigned long arg, unsigned int cond)
{
	int ret = 0;
	unsigned long va, base = 0, size = 0;
	void *pm_param = cn_kzalloc(cond, GFP_KERNEL);

	if (!pm_param) {
		cn_dev_err("pm_param alloc failed.");
		return -ENOMEM;
	}

	ret = copy_from_user((void *)pm_param, (void *)arg, cond);
	if (ret) {
		cn_dev_err("Get range copy_from_user failed.");
		ret = -EINVAL;
		goto free_pm_param;
	}

	va = GET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, uaddr);

	ret = camb_pinned_get_mem_range(fp, va, &base, &size);
	if (ret)
		goto free_pm_param;

	SET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, uaddr, base);
	SET_COMPAT_PARAM_MON(pm_param, pinned_mem, cond, size, size);

	if (copy_to_user((void *)arg, (void *)pm_param, cond)) {
		cn_dev_err("Get range copy_to_user failed.");
		ret = -EINVAL;
		goto free_pm_param;
	}

	cn_kfree(pm_param);
	return 0;

free_pm_param:
	cn_kfree(pm_param);
	return -EFAULT;
}

int cn_pinned_mem_pst_kref_get(struct pinned_mem *pst_blk)
{
	if (!pst_blk) {
		cn_dev_err("input handle is null");
		dump_stack();
		return -EINVAL;
	}

	atomic_inc(&pst_blk->k_rcnt);

	return 0;
}

int cn_pinned_mem_pst_kref_put_test(struct pinned_mem *pst_blk)
{
	if (!pst_blk) {
		cn_dev_err("input handle is null");
		dump_stack();
		return -EINVAL;
	}

	return atomic_sub_and_test(1, &pst_blk->k_rcnt);
}

/* cn_pinned_mem_get_kv_pst must running in userspace process context. */
struct pinned_mem *cn_pinned_mem_get_kv_pst(pid_t tgid,
		unsigned long uva, u64 size, unsigned long *kva)
{
	unsigned long kvaddr = 0;
	struct pinned_mem *pst_blk = NULL;
	struct pinned_mem_va *pst_uva = NULL;
	u64 uva_end = uva + size;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	if (uva_end < uva) {
		cn_dev_err("overflow: uva 0x%lx, size 0x%llx.", uva, size);
		return NULL;
	}

	read_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __find_pinned_mem_va(udvm_set->pm_task_root, tgid, uva, false);
	if (!pst_uva) {
		cn_dev_err("can not find uva(0x%lx) in the pid (%ld) tree.", uva, (unsigned long)tgid);
		goto out;
	}

	if (uva_end > pst_uva->va_start + pst_uva->vm_size) {
		cn_dev_err("OutOfBound: input uva range(%#lx-%#llx), search uva range(%#lx-%#lx) no match.",
			uva, uva_end, pst_uva->va_start, pst_uva->va_start + pst_uva->vm_size);
		goto out;
	}

	pst_blk = pst_uva->pst_blk;

	atomic_inc(&pst_blk->ref_cnt);

	kvaddr = pst_blk->kva_start;
	kvaddr += uva - pst_uva->va_start;
out:
	read_unlock_my(&udvm_set->pm_task_root->rb_lock);
	*kva = kvaddr;
	return pst_blk;
}

unsigned long cn_pinned_mem_get_kv(pid_t tgid,
		unsigned long uva, u64 size)
{
	unsigned long kvaddr = 0;
	struct pinned_mem *pst_blk;

	pst_blk = cn_pinned_mem_get_kv_pst(tgid, uva, size, &kvaddr);

	return kvaddr;
}

int cn_pinned_mem_put_kv(pid_t tgid, unsigned long kvaddr)
{
	struct pinned_mem *pst_blk = NULL;
	int need_free = 0;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	read_lock_my(&udvm_set->pm_blk_root->rb_lock);
	pst_blk = __FIND_TREE_NODE_BY_KVA(udvm_set->pm_blk_root, kvaddr);
	if (pst_blk) {
		if (atomic_sub_and_test(1, &pst_blk->ref_cnt)) {
			need_free = 1;
		}
	}
	read_unlock_my(&udvm_set->pm_blk_root->rb_lock);

	if (need_free) {
		free_pinned_mem(&pst_blk);
	}

	return 0;
}

unsigned long
cn_pinned_mem_copy_cp_node(void *tmp_buf, int *skip, unsigned long size,
		int (*do_copy)(void *, unsigned long, unsigned long, unsigned long))
{
	struct pinned_mem_task *pst_task = NULL;
	struct pinned_mem_va *post = NULL;
	struct rb_node *p = NULL;
	pid_t tgid = current->tgid;
	unsigned long real_size = 0;
	unsigned long per_cp_node_size = camb_per_cp_node_size();
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	read_lock_my(&udvm_set->pm_task_root->rb_lock);

	pst_task = __FIND_TREE_NODE_BY_TASK(udvm_set->pm_task_root, tgid);
	if (pst_task) {
		p = rb_first(&pst_task->rb_uva);
		while (p != NULL) {
			post = rb_entry(p, struct pinned_mem_va, node);
			real_size += per_cp_node_size;
			/* When the real size is larger than the input size, it skips to
			 * fill in the input buffer.
			 * And we need to get the total real size, so to do it continue.
			 */
			if (*skip)
				goto do_skip;

			if (real_size > size) {
				*skip = 1;
				goto do_skip;
			}

			do_copy(tmp_buf, post->va_start, post->vm_size, CHECKPOINT_MEMORY_TYPE_HOST);
			tmp_buf += per_cp_node_size;
do_skip:
			p = rb_next(p);
		}
	}
	read_unlock_my(&udvm_set->pm_task_root->rb_lock);

	return real_size;
}

struct udvm_ob_map_t *__find_ob_map(unsigned long uaddr)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct pinned_mem_va *pst_uva = NULL;
	struct pinned_mem *pst_blk;
	struct udvm_ob_map_t *ob_map = NULL;

	read_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __search_pst_uva(udvm_set->pm_task_root, uaddr, 0);
	if (!pst_uva) {
		cn_dev_err("uva:%#lx is invalid\n", uaddr);
		goto out;
	}

	pst_blk = pst_uva->pst_blk;
	if (!pst_blk) {
		cn_dev_err("pst_blk is invalid\n");
		goto out;
	}

	ob_map = pst_blk->ob_map;
out:
	read_unlock_my(&udvm_set->pm_task_root->rb_lock);
	return ob_map;
}

int cn_pinned_mem_host_unregister_internal(struct file *fp, u64 uaddr, int card_id)
{
	struct cn_mm_set *mm_set = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct pinned_mem_va *pst_uva = NULL;
	u64 va;

	mm_set = __get_mmset_with_index(card_id);
	if (!mm_set) {
		cn_dev_err("card id error.");
		return -EINVAL;
	}

	if (!mm_set->obmap_support) {
		cn_dev_err("This card don't support outbound.");
		return -EPERM;
	}

	if (addr_is_udvm(uaddr)) {
		return camb_peer_unregister((u64)fp, NULL, uaddr, mm_set);
	}

	write_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __search_register_pst_uva(udvm_set->pm_task_root, uaddr);
	if (!pst_uva) {
		cn_dev_err("Not find pst_uva that type is register.");
		write_unlock_my(&udvm_set->pm_task_root->rb_lock);
		return -EINVAL;
	}

	va = pst_uva->va_start;
	write_unlock_my(&udvm_set->pm_task_root->rb_lock);

	if (!remove_uva_from_tree(current->tgid, va)) {
		cn_dev_err("remove_uva_from_tree error.");
		return -EFAULT;
	}

	return 0;
}

int cn_pinned_mem_host_register_internal(struct file *fp, u64 va, u64 size,
		int flags, int card_id)
{
	struct cn_mm_set *mm_set = NULL;
	int ret;

	mm_set = __get_mmset_with_index(card_id);
	if (!mm_set) {
		cn_dev_err("card id error.");
		return -EINVAL;
	}

	if (!mm_set->obmap_support) {
		cn_dev_err("No support outbound.");
		return -EPERM;
	}

	if (!PAGE_ALIGNED(size) || !PAGE_ALIGNED(va)) {
		cn_dev_err("%#llx %#llx is error, need PAGE_ALIGNED.",
				size, va);
		return -EINVAL;
	}

	if (flags == CN_MEMHOSTREGISTER_IOMEMORY) {
		ret = camb_peer_register((u64)fp, NULL, va, size, mm_set, flags);
	} else {
		ret = register_uva_to_pinned_mem(fp, va, size, flags);
	}

	if (ret) {
		cn_dev_err("register uva:%#llx fail.", va);
		return -EINVAL;
	}

	return 0;
}

/*camb_map_ob_win need map dma and unmap dma, but __map_ob_win_internal don't do it.*/
static int __map_ob_win_internal(struct udvm_ob_map_t *ob, int card_id, bool is_map_iova)
{
	struct sg_table *sg_table = ob->dev_map[card_id].table;
	struct scatterlist *sg;
	int i, ret = 0, cnt;
	unsigned long offset = 0;
	struct ob_data_rpc_t *ob_data = NULL;
	int index = 0, seg = 0;
	int ob_data_size = RPC_TRANS_MAX_LEN(1);
	int j;

	ob_data = (struct ob_data_rpc_t *)cn_kzalloc(ob_data_size, GFP_KERNEL);
	if (!ob_data) {
		cn_dev_err("ob_data_rpc_t alloc failed");
		return -ENOMEM;
	}

	if (is_map_iova) {
		ob_data->tag = OB_DATA_MAP_SMMU_SOF;
	} else {
		ob_data->tag = OB_DATA_UNMAP_SMMU_SOF;
	}


	cnt = sg_nents(sg_table->sgl);

	/**
	 * The arm will check whether the rpc trans is in the same context through
	 * the dpa, iova and size infomations.
	 **/
	ob_data->device_pa = ob->device_pa;
	ob_data->iova = ob->iova;
	ob_data->size = ob->iova_size;
	/* When mapping the ob wins, it will use the offset to get the device pa. */
	ob_data->offset = offset;
	/* the total nents count */
	ob_data->t_cnt = cnt;
	ob_data->s_cnt = 0;

	cn_dev_debug("pa:%#lx iova:%#lx size:%#lx", ob_data->device_pa, ob_data->iova, ob_data->size);

	for_each_sg(sg_table->sgl, sg, cnt, i) {
		ob_data->data[index].pci_addr = sg_dma_address(sg);
		ob_data->data[index].size = sg_dma_len(sg);
		offset += sg_dma_len(sg);
		/* the ob_data count in the current rpc trans */
		index++;

		/**
		 * fill ob_data->data by cnt and MAX_OB_PCI_ADDR_CNT
		 * Max cnt is MAX_OB_PCI_ADDR_CNT that one rpc transfer..
		 **/
		if (payload_not_full(index) && !sg_is_last(sg)) {
			continue;
		}

		/**
		 * we have three scenes: 1. payload is full and 2.sg_is_last and
		 * 3.payload_is_full && sg_is_last.
		 **/
		if (sg_is_last(sg)) {
			if (is_map_iova) {
				ob_data->tag = OB_DATA_MAP_SMMU_EOF;
			} else {
				ob_data->tag = OB_DATA_UNMAP_SMMU_EOF;
			}
		} else if (seg) {
			/* to deal with the scene 1. */
			if (is_map_iova) {
				ob_data->tag = OB_DATA_MAP_SMMU_MOF;
			} else {
				ob_data->tag = OB_DATA_UNMAP_SMMU_MOF;
			}
		}

		ob_data->cnt = index;
		seg++;

		for (j = 0; j < ob_data->cnt; j++) {
			cn_dev_debug("ob data pci_addr %llx size %x.",
						ob_data->data[j].pci_addr, ob_data->data[j].size);
		}

		ret = __send_ob_data_to_device(card_id, ob_data);
		if (ret) {
			cn_dev_err("cfg ob win fail");
			goto send_error;
		}

		index = 0;
		/* reset the ob_data status for the next rpc trans */
		ob_data->tag = 0;
		ob_data->s_cnt += ob_data->cnt;
		ob_data->cnt = 0;
		/* update dpa info for the next ob_data frame */
		ob_data->offset = offset;
	}

	cn_kfree(ob_data);
	return ret;

send_error:
	cn_kfree(ob_data);
	return ret;
}

int cn_pinned_mem_unmap_ob(u64 uaddr, int card_id)
{
	struct udvm_ob_map_t *ob_map = NULL;
	int ret;

	ob_map = __find_ob_map(uaddr);
	if (!ob_map) {
		cn_dev_err("uaddr %llx card %d find ob_map error.", uaddr, card_id);
		return -EINVAL;
	}

	mutex_lock(&ob_map->map_lock);
	if (ob_map->dev_map[card_id].dev_refcnt == 1) {
		/*unmap pcie axi addr and outbound windows*/
		ret = unmap_ob_win(ob_map, card_id);
		if (ret) {
			cn_dev_err("cfg unmap outbound win failed.%#llx", (u64)ret);
			mutex_unlock(&ob_map->map_lock);
			return ret;
		}
	}
	ob_map->dev_map[card_id].dev_refcnt--;
	mutex_unlock(&ob_map->map_lock);

	return 0;
}

int cn_pinned_mem_map_dma(__u64 uaddr, int card_id)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct pinned_mem_va *pst_uva = NULL;
	struct pinned_mem *pst_blk;
	struct udvm_ob_map_t *ob_map = NULL;
	int ret = 0;

	read_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __search_pst_uva(udvm_set->pm_task_root, uaddr, 0);
	if (!pst_uva) {
		cn_dev_err("uva:%#llx is invalid\n", uaddr);
		ret = -EINVAL;
		goto out;
	}

	pst_blk = pst_uva->pst_blk;

	if (!pst_blk) {
		cn_dev_err("pst_blk is invalid\n");
		ret = -EINVAL;
		goto out;
	}

	ob_map = pst_blk->ob_map;
	if (!ob_map) {
		cn_dev_err("ob map is NULL\n");
		ret = -EINVAL;
		goto out;
	}

	read_unlock_my(&udvm_set->pm_task_root->rb_lock);

	mutex_lock(&ob_map->map_lock);
	if (!ob_map->dev_map[card_id].dma_refcnt) {
		ret = map_dma(pst_blk, ob_map, card_id);
		if (ret) {
			cn_dev_err("%#llx map dma error.", uaddr);
			mutex_unlock(&ob_map->map_lock);
			return ret;
		}
	}

	ob_map->dev_map[card_id].dma_refcnt++;
	mutex_unlock(&ob_map->map_lock);

	return 0;
out:
	read_unlock_my(&udvm_set->pm_task_root->rb_lock);
	return ret;
}

static void __release_udvm_map_ob(struct udvm_ob_map_t *ob)
{
	int i;

	/*force release ob*/
	for (i = 0; i < MAX_OB_PHYS_CARD; i++) {
		if (ob->dev_map[i].dev_refcnt) {
			unmap_ob_win(ob, i);
		}
	}
}

static void __release_udvm_map_dma(struct udvm_ob_map_t *ob)
{
	int i;

	/*force release dma*/
	for (i = 0; i < MAX_OB_PHYS_CARD; i++) {
		if (ob->dev_map[i].dma_refcnt) {
			unmap_dma(ob, i);
		}
	}
}

int camb_release_udvm_ob_map(struct udvm_ob_map_t *ob_map)
{
	__release_udvm_map_ob(ob_map);

	__release_udvm_map_dma(ob_map);

	/*free iova*/
	if (ob_map->iova_ref) {
		camb_dob_iova_free(ob_map->iova, ob_map->iova_size);
	}

	/*free ob struct*/
	cn_kfree(ob_map);

	return 0;
}

int cn_pinned_mem_iova_alloc(u64 uva, unsigned long *iova_alloc)
{
	struct pinned_mem_va *pst_uva = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct pinned_mem *pst_blk;
	struct sg_table *tmp_table = NULL;
	struct udvm_ob_map_t *ob = NULL;
	dev_addr_t iova, device_pa;
	int i;
	u64 iova_size = 0;

	read_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __search_pst_uva(udvm_set->pm_task_root, uva, 0);
	if (!pst_uva) {
		cn_dev_err("Not find pst_uva that type is register.");
		read_unlock_my(&udvm_set->pm_task_root->rb_lock);
		return -EINVAL;
	}
	read_unlock_my(&udvm_set->pm_task_root->rb_lock);

	pst_blk = pst_uva->pst_blk;
	ob = pst_blk->ob_map;

	/*iova need page align 0x10000(64KB) of mlu590*/
	iova_size = ALIGN(PAGE_ALIGN(pst_uva->vm_size), 0x10000);

	mutex_lock(&ob->map_lock);
	/*ob->iova = iova when iova_ref is 1 and *iova_alloc = ob->iova when iova_ref bigger than 1 need mutex*/
	if (!ob->iova_ref) {
		for (i = 0; i < MAX_OB_PHYS_CARD; i++) {
			if (ob->dev_map[i].table) {
				tmp_table = ob->dev_map[i].table;
				break;
			}
		}
		if (camb_dob_iova_alloc(&iova, &device_pa, iova_size, tmp_table)) {
			cn_dev_err("dob mem alloc fail.");
			mutex_unlock(&ob->map_lock);
			return -ENOSPC;
		}
		ob->iova = iova;
		ob->device_pa = device_pa;
		ob->iova_size = iova_size;
	}
		*iova_alloc = ob->iova;
	ob->iova_ref++;
	mutex_unlock(&ob->map_lock);

	return 0;
}

int cn_pinned_mem_iova_free(u64 uva)
{
	struct pinned_mem_va *pst_uva = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct udvm_ob_map_t *ob_map = NULL;

	read_lock_my(&udvm_set->pm_task_root->rb_lock);
	pst_uva = __search_pst_uva(udvm_set->pm_task_root, uva, 0);
	if (!pst_uva) {
		cn_dev_err("Not find pst_uva that type is register.");
		read_unlock_my(&udvm_set->pm_task_root->rb_lock);
		return -EINVAL;
	}
	read_unlock_my(&udvm_set->pm_task_root->rb_lock);

	ob_map = pst_uva->pst_blk->ob_map;

	mutex_lock(&ob_map->map_lock);
	if (--ob_map->iova_ref == 0) {
		camb_dob_iova_free(ob_map->iova, ob_map->iova_size);
		ob_map->iova = 0;
	}
	mutex_unlock(&ob_map->map_lock);

	return 0;
}

int cn_pinned_mem_unmap_dma(u64 uaddr, int card_id)
{
	struct udvm_ob_map_t *ob_map = NULL;

	ob_map = __find_ob_map(uaddr);
	if (!ob_map) {
		cn_dev_err("uaddr %llx card %d find ob_map error.", uaddr, card_id);
		return -EINVAL;
	}

	mutex_lock(&ob_map->map_lock);
	if (--ob_map->dev_map[card_id].dma_refcnt == 0) {
		unmap_dma(ob_map, card_id);
	}
	mutex_unlock(&ob_map->map_lock);

	return 0;
}

int cn_pinned_mem_map_ob(u64 uaddr, int card_id)
{
	struct udvm_ob_map_t *ob_map = NULL;
	int ret;

	ob_map = __find_ob_map(uaddr);
	if (!ob_map) {
		cn_dev_err("uaddr %llx card %d find ob_map error.", uaddr, card_id);
		return -EINVAL;
	}

	mutex_lock(&ob_map->map_lock);
	if (ob_map->dev_map[card_id].dev_status) {
		/*map error before. we won't map again. */
		mutex_unlock(&ob_map->map_lock);
		return -EINVAL;
	}

	if (!ob_map->dev_map[card_id].dev_refcnt) {
		/*map pcie axi addr and outbound windows*/
		ret = map_ob_win(ob_map, card_id);
		if (ret) {
			cn_dev_err("cfg map outbound win failed.%#llx", (u64)ret);
			ob_map->dev_map[card_id].dev_status = 1;
			mutex_unlock(&ob_map->map_lock);
			return ret;
		}
	}

	ob_map->dev_map[card_id].dev_refcnt++;
	mutex_unlock(&ob_map->map_lock);

	return 0;
}

int camb_pinned_obd_map_init(void)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct cn_mm_set *mm_set;
	struct camb_ob_direct_map *obd_map;
	unsigned long size = 0;
	dev_addr_t phy;
	host_addr_t virt;
	int i, order;

	obd_map = cn_kzalloc(sizeof(struct camb_ob_direct_map), GFP_KERNEL);
	if (!obd_map) {
		cn_dev_err("no mem to init obd map.");
		return -ENOMEM;
	}

	for (i = 0; i < MAX_OB_PHYS_CARD; i++) {
		mm_set = __get_mmset_with_index(i);
		if (mm_set && mm_set->hostpool_h.pool) {
			break;
		}
	}

	if (!mm_set) {
		cn_dev_err("no card support outbound.");
		cn_kfree(obd_map);
		return -EINVAL;
	}

	phy = mm_set->hostpool_l.phys;
	virt = mm_set->hostpool_l.virt;
	size = mm_set->hostpool_l.size;
	order = mm_set->hostpool_l.pool->min_alloc_order;

	mempool_init(&(obd_map->hostpool_l), virt, phy, size, NULL);
	mempool_add_pool(&(obd_map->hostpool_l), order, virt, phy, size, NULL);
	obd_map->align_size_l = 1 << order;
	cn_dev_info("data outbound l: [%#lx-%#lx] <=> [%#llx %#llx] align_size:%#x",
			virt, virt + size, phy, phy + size, obd_map->align_size_l);

	phy = mm_set->hostpool_h.phys;
	virt = mm_set->hostpool_h.virt;
	size = mm_set->hostpool_h.size;
	order = mm_set->hostpool_h.pool->min_alloc_order;
	mempool_init(&(obd_map->hostpool_h), virt, phy, size, NULL);
	mempool_add_pool(&(obd_map->hostpool_h), order, virt, phy, size, NULL);
	obd_map->align_size_h = 1 << order;
	cn_dev_info("data outbound h: [%#lx-%#lx] <=> [%#llx %#llx] align_size:%#x",
			virt, virt + size, phy, phy + size, obd_map->align_size_h);

	if (!__sync_bool_compare_and_swap(&udvm_set->obd_map, 0, obd_map)) {
		mempool_destroy(&obd_map->hostpool_l);
		mempool_destroy(&obd_map->hostpool_h);
		cn_kfree(obd_map);
	}

	return 0;
}


