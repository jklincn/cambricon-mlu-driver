#include <linux/scatterlist.h>
#include <linux/module.h>
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_genalloc.h"
#include "hal/cn_mem_hal.h"
#include "camb_mm.h"
#include "camb_p2p_remap.h"
#include "camb_sg_split.h"
#include "camb_linear_remap.h"

#include "camb_trace.h"

static int cambr_linear_mode = LINEAR_MODE_ENABLE;
module_param_named(linear_mode, cambr_linear_mode,
				   int, S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(linear_mode, "Set linear mapping effective level when loading kernel module");

enum {
	LINEAR_REMAP_DIRECT_RETURN = 0x0,
	LINEAR_REMAP_P2P_REMAP     = 0x1,
	LINEAR_REMAP_SGLIST_REMAP  = 0x2,
	LINEAR_REMAP_INVALID,
};

static inline bool __is_linear_in_range(struct mapinfo *pminfo)
{
	struct cn_mm_set *mm_set = pminfo->mm_set;
	unsigned long start = pminfo->virt_addr;
	unsigned long end = start + pminfo->mem_meta.size;

	if (!pminfo->is_linear)
		return false;

	return (start >= mm_set->linear.vaddr) && (end <= (mm_set->linear.vaddr + mm_set->linear.size));
}

static inline int
__get_linear_remap_mode(struct cn_mm_set *mm_set, struct mapinfo *pminfo)
{
	if (mm_set->ppool.mode == PPOOL_MODE_NORMAL)
		return LINEAR_REMAP_P2P_REMAP;

	if (!mm_set->linear.is_support)
		return LINEAR_REMAP_INVALID;

	if (__is_linear_in_range(pminfo) || pminfo->mem_meta.type == CN_SHARE_MEM) {
		return LINEAR_REMAP_DIRECT_RETURN;
	} else {
		return (mm_set->ppool.mode == PPOOL_MODE_LINEAR) ?
			LINEAR_REMAP_P2P_REMAP : LINEAR_REMAP_SGLIST_REMAP;
	}
}

static inline int
__get_linear_unmap_mode(struct cn_mm_set *mm_set, struct mapinfo *pminfo,
			struct sg_table *table, u64 offset)
{
	struct scatterlist *sg = table->sgl;

	if (mm_set->ppool.mode == PPOOL_MODE_NORMAL)
		return LINEAR_REMAP_P2P_REMAP;

	if (!mm_set->linear.is_support)
		return LINEAR_REMAP_INVALID;

	if (__is_linear_in_range(pminfo) || pminfo->mem_meta.type == CN_SHARE_MEM) {
		return LINEAR_REMAP_DIRECT_RETURN;
	} else {
		return camb_p2p_range_in_pool(mm_set, sg_phys(sg) + offset, sg->length) ?
			LINEAR_REMAP_P2P_REMAP : LINEAR_REMAP_SGLIST_REMAP;
	}
}

static struct sg_table *
camb_linear_create_sgtable(dev_addr_t *addrs, unsigned long *size, int counts, u64 offset)
{
#define SINGLE_SG_MAXIMUM_SIZE (1UL << 30)
	struct sg_table *table = cn_kzalloc(sizeof(struct sg_table), GFP_KERNEL);
	struct scatterlist *sg;
	int ret = 0, i = 0, j = 0;
	unsigned int nents = 0, *sub_counts = 0;
	unsigned long isize = 0;

	if (!table)
		return ERR_PTR(-ENOMEM);

	sub_counts = cn_kzalloc(sizeof(unsigned int) * counts, GFP_KERNEL);
	if (!sub_counts) {
		cn_kfree(table);
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < counts; i++) {
		sub_counts[i] = (size[i] / SINGLE_SG_MAXIMUM_SIZE) + !!(size[i] % SINGLE_SG_MAXIMUM_SIZE);
		nents += sub_counts[i];
	}

	ret = sg_alloc_table(table, nents, GFP_KERNEL);
	if (ret) {
		cn_kfree(table);
		cn_kfree(sub_counts);
		return ERR_PTR(ret);
	}

	sg = table->sgl;
	for (i = 0; i < counts; i++) {
		dev_addr_t addr = addrs[i];
		unsigned long sz = size[i];

		addr -= offset;

		for (j = 0; j < sub_counts[i]; j++) {
			dev_addr_t pg_offset = offset_in_page(addr);

			isize = sz > SINGLE_SG_MAXIMUM_SIZE ? SINGLE_SG_MAXIMUM_SIZE : sz;
			sg_set_page(sg, pfn_to_page(PFN_DOWN(addr)), isize, pg_offset);
			sg_dma_len(sg) = isize;
			sg_dma_address(sg) = addr;
			sg = sg_next(sg);

			sz -= isize;
			addr += isize;
		}
	}

	cn_kfree(sub_counts);
	return table;
#undef SINGLE_SG_MAXIMUM_SIZE
}

struct sg_table *
camb_linear_sglist_translate(struct mapinfo *pminfo, dev_addr_t start, unsigned long size, u64 offset)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct sg_table *orig_table = NULL, *otable = NULL;
	struct scatterlist *sg = NULL, *osg = NULL, *tmpsg = NULL;
	unsigned long sg_offset = 0, linear_ofs = 0;
	int ret = 0, counts = 0, i = 0;

	sg_offset = udvm_get_iova_from_addr(start) - udvm_get_iova_from_addr(pminfo->virt_addr);
	ret = camb_fill_mapinfo_sgtable(pminfo);
	if (ret)
		return ERR_PTR(ret);

	orig_table = pminfo->sg_table;
	if (!orig_table)
		return ERR_PTR(-EINVAL);

	otable = cn_kzalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!otable) {
		cn_dev_core_err(core, "alloc otable buffer failed");
		return ERR_PTR(-ENOMEM);
	}

	ret = cn_sg_get_sub(orig_table->sgl, orig_table->nents, sg_offset, size,
					  &tmpsg, &counts, GFP_KERNEL);
	if (ret) {
		cn_dev_core_err(core, "sg_splist error with ret:%d", ret);
		cn_kfree(otable);
		return ERR_PTR(ret);
	}

	ret = sg_alloc_table(otable, counts, GFP_KERNEL);
	if (ret) {
		kfree(tmpsg); /* return from cn_sg_split, not malloc with cn_kzalloc */
		cn_dev_core_err(core, "alloc sg_table for otable failed");
		cn_kfree(otable);
		return ERR_PTR(ret);
	}

	osg = otable->sgl;
	linear_ofs = (mm_set->linear.vaddr - mm_set->linear.paddr);

	for_each_sg(tmpsg, sg, counts, i) {
		dev_addr_t addrs = sg_phys(sg) + linear_ofs;
		dev_addr_t pg_offset = offset_in_page(addrs);

		addrs -= offset;
		sg_set_page(osg, pfn_to_page(PFN_DOWN(addrs)), sg->length, pg_offset);
		sg_dma_len(osg) = osg->length;
		sg_dma_address(osg) = addrs;
		cn_dev_core_debug(core, "%d phys:%#llx, length:%#x", i, sg_phys(osg), osg->length);
		osg = sg_next(osg);
	}

	kfree(tmpsg);
	return otable;
}

struct sg_table *
cn_mem_linear_remap(void *minfo, dev_addr_t start, unsigned long size)
{
	struct mapinfo *pminfo = (struct mapinfo *)minfo;
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = NULL;
	struct sg_table *otable = NULL;
	int type = LINEAR_REMAP_INVALID, ret = 0;
	dev_addr_t oaddr = 0;
	u64 offset;

	if (!minfo)
		return ERR_PTR(-EINVAL);

	mm_set = (struct cn_mm_set *)pminfo->mm_set;
	core = (struct cn_core_set *)mm_set->core;
	ret = cn_bus_get_linear_bar_offset(core->bus_set, &offset);
	if (ret < 0)
		return ERR_PTR(-EINVAL);

	start = udvm_get_iova_from_addr(start);

	type = __get_linear_remap_mode(mm_set, pminfo);

	switch (type) {
	case LINEAR_REMAP_DIRECT_RETURN:
		if (pminfo->mem_meta.type == CN_SHARE_MEM) {
			/**
			 * NOTE:
			 * calculate physical start from devpool physical base, due to support
			 * SRAM which do not save its phys address in its mapinfo.
			 **/
			start = (start - mm_set->dev_virt_base) + mm_set->devpool.phys;
			offset = 0;
		}
		otable = camb_linear_create_sgtable(&start, &size, 1, offset);
		break;
	case LINEAR_REMAP_P2P_REMAP:
		ret = camb_mem_p2p_remap(minfo, start, size, &oaddr);
		otable = !ret ? camb_linear_create_sgtable(&oaddr, &size, 1, offset) : ERR_PTR(ret);
		break;
	case LINEAR_REMAP_SGLIST_REMAP:
		otable = camb_linear_sglist_translate(pminfo, start, size, offset);
		break;
	default:
		otable = ERR_PTR(-EINVAL);
	}

	trace_linear_remap(pminfo, start, size, type);

	return otable;
}

void cn_mem_linear_unmap(void *minfo, struct sg_table *table)
{
	struct mapinfo *pminfo = (struct mapinfo *)minfo;
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = NULL;
	int type = LINEAR_REMAP_INVALID;
	int ret;
	u64 offset;

	if (!minfo || !table)
		return ;

	mm_set = (struct cn_mm_set *)pminfo->mm_set;
	core = (struct cn_core_set *)mm_set->core;
	ret = cn_bus_get_linear_bar_offset(core->bus_set, &offset);
	if (ret < 0)
		return;

	type = __get_linear_unmap_mode(mm_set, pminfo, table, offset);
	switch (type) {
	case LINEAR_REMAP_DIRECT_RETURN:
	case LINEAR_REMAP_SGLIST_REMAP:
		break;
	case LINEAR_REMAP_P2P_REMAP:
		camb_mem_p2p_unmap(minfo, sg_phys(table->sgl) + offset);
		break;
	default:
		return;
	}

	trace_linear_unmap(minfo, type);

	sg_free_table(table);
	cn_kfree(table);
}

static int __init_largebar_remap(struct cn_mm_set *mm_set, unsigned long lsize)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct ret_msg remsg;
	struct bar_info_s info;
	ssize_t result_len = sizeof(struct ret_msg), size = 0;
	int ret = 0;

	memset(&info, 0x0, sizeof(struct bar_info_s));
	ret = cn_bus_get_bar_info(core->bus_set, &info);
	if (ret) {
		cn_dev_core_err(core, "error get bar_info!");
		return ret;
	}

	/* NOTE: p2p use bar4 do data transfer */
	size = info.bar[4].bar_sz;

	if (size >= lsize) {
		mm_set->ppool.mode = PPOOL_MODE_DISABLE;
		return 0;
	}

	memset(&remsg, 0x0, sizeof(struct ret_msg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_p2p_pool_init", &size,
						 sizeof(uint64_t), &remsg, &result_len,
						 sizeof(struct ret_msg));
	if (ret || remsg.ret) {
		cn_dev_core_err(core, "p2p_pool_init failed! (%d,%d)", ret, remsg.ret);
		return -EINVAL;
	}

	mm_set->ppool.mode = PPOOL_MODE_NORMAL;
	return camb_p2p_pool_init(mm_set, remsg.device_addr, size);
}

int camb_linear_remap_init(struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct linear_remsg_t remsg;
	ssize_t result_len = sizeof(struct linear_remsg_t);
	int ret = 0;

	if (!mm_set->linear.is_support)
		return 0;

	if (!mm_set->smmu_ops.smmu_add_remap) {
		cn_dev_core_err(core, "current platform not support linear remap");
		return -EPERM;
	}

	memset(&remsg, 0x0, result_len);
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_linear_remap_init", NULL,
						 0, &remsg, &result_len,
						 sizeof(struct linear_remsg_t));
	if (ret || remsg.ret) {
		cn_dev_core_err(core, "linear_remap_init failed! (%d,%d)",
				ret, remsg.ret);
		return ret;
	}

	/* Only PF only mode enable PCIE SMMU remap windows */
	if (!cn_core_is_vf(core) && !cn_is_mim_en(core)) {
		mm_set->smmu_ops.smmu_add_remap(core, remsg.vaddr, remsg.paddr,
				remsg.forbidden_size, SMMU_RMPTYPE_OS_FORBIDDEN);
		mm_set->smmu_ops.smmu_add_remap(core, remsg.vaddr, remsg.paddr,
				remsg.size, SMMU_RMPTYPE_DRAM);
	}

	mm_set->linear.vaddr = remsg.vaddr;
	mm_set->linear.paddr = remsg.paddr;
	mm_set->linear.size = remsg.size;
	mm_set->linear.mode = LINEAR_MODE_DEFAULT;

	camb_mem_switch_linear_mode_rpc(mm_set, cambr_linear_mode);

	if (remsg.ppool_size) {
		mm_set->ppool.mode = PPOOL_MODE_LINEAR;
		ret = camb_p2p_pool_init(mm_set, remsg.vaddr + remsg.size,
					remsg.ppool_size);
	} else {
		ret = __init_largebar_remap(mm_set, remsg.size);
	}

	if (ret) {
		cn_dev_core_err(core, "Init p2p pool for linear remap failed!");
		return ret;
	}

	cn_dev_core_info(core, "LinearRemap Init: vaddr:%#llx, paddr:%#llx, size:%#lx, ppool size:%#lx",
					 mm_set->linear.vaddr, mm_set->linear.paddr,
					 mm_set->linear.size, remsg.ppool_size);
	return ret;
}

void camb_linear_remap_exit(struct cn_mm_set *mm_set)
{
	struct peer_pool_t *ppool = &mm_set->ppool;

	if (ppool->mode != PPOOL_MODE_LINEAR)
		return;

	camb_p2p_pool_exit(mm_set);
}

void camb_linear_remap_mode_reset(struct cn_mm_set *mm_set)
{
	if (!mm_set->linear.is_support)
		return;

	if (mm_set->linear.mode != cambr_linear_mode)
		camb_mem_switch_linear_mode_rpc(mm_set, cambr_linear_mode);
}

dev_addr_t cn_mem_linear_get_base(struct cn_core_set *core)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)core->mm_set;

	if (mm_set->linear.is_support && mm_set->ppool.mode != PPOOL_MODE_NORMAL) {
		return mm_set->linear.vaddr;
	} else {
		return camb_p2p_pool_get_base(mm_set);
	}
}
