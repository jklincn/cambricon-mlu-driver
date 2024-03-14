#include <linux/pid_namespace.h>
#include <linux/radix-tree.h>
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_genalloc.h"
#include "hal/cn_mem_hal.h"
#include "camb_mm.h"
#include "camb_udvm.h"
#include "camb_mm_priv.h"
#include "camb_bitmap.h"
#include "camb_vmm.h"
#include "camb_vmm_internal.h"

int set_vmm_iova_bitmap(struct camb_vmm_iova *iova, dev_addr_t addr,
				unsigned long size)
{
	unsigned long *map = iova->bitmap;
	int start = addr2bit(addr, iova), nr = size2bits(size);
	int remain = 0;

	remain = bitmap_set_ll(map, start, nr);
	if (remain)
		BUG_ON(bitmap_clear_ll(map, start, nr - remain));

	return remain;
}

int clear_vmm_iova_bitmap(struct camb_vmm_iova *iova, dev_addr_t addr,
				unsigned long size)
{
	unsigned long *map = iova->bitmap;
	int start = addr2bit(addr, iova), nr = size2bits(size);
	int remain = 0;

	remain =  bitmap_clear_ll(map, start, nr);

	BUG_ON(remain);

	return 0;
}

unsigned long size2bits(unsigned long size)
{
	return (unsigned long)(div_u64(size, 1UL << VMM_MINIMUM_SHIFT));
}

unsigned long addr2bit(unsigned long offset, struct camb_vmm_iova *iova)
{
	WARN_ON(offset < iova->node.start || offset > iova->node.end);
	offset -= iova->node.start;

	return (unsigned long)(div_u64(offset, 1UL << VMM_MINIMUM_SHIFT));
}

void insert_vmm_iova(struct vmm_priv_data *vmm_priv, struct camb_vmm_iova *iova)
{
	camb_range_tree_insert(&vmm_priv->iova.range_tree, &iova->node);
}

void delete_vmm_iova(struct vmm_priv_data *vmm_priv, struct camb_vmm_iova *iova)
{
	camb_range_tree_delete(&vmm_priv->iova.range_tree, &iova->node);
}

struct camb_vmm_iova *
search_vmm_iova_compare(struct vmm_priv_data *vmm_priv, dev_addr_t addr,
			unsigned long size)
{
	struct range_tree_node_t *node = NULL;
	struct camb_vmm_iova *iova = NULL;

	node = camb_range_tree_search(&vmm_priv->iova.range_tree, addr);
	if (node && ((node->start != addr) || (node->end != (addr + size - 1)))) {
		iova = NULL;
	} else {
		iova = get_vmm_iova(node);
	}

	return iova;
}

/** VMM mapinfo structure operations **/
void insert_vmm_mapinfo(struct vmm_priv_data *vmm_priv, struct mapinfo *minfo)
{
	write_lock(&vmm_priv->minfo.node_lock);
	minfo->rnode.start = minfo->virt_addr;
	minfo->rnode.end = minfo->rnode.start + minfo->mem_meta.size - 1;
	camb_range_tree_insert(&vmm_priv->minfo.range_tree, &minfo->rnode);
	write_unlock(&vmm_priv->minfo.node_lock);
}

void delete_vmm_mapinfo(struct vmm_priv_data *vmm_priv, struct mapinfo *minfo)
{
	write_lock(&vmm_priv->minfo.node_lock);
	camb_range_tree_delete(&vmm_priv->minfo.range_tree, &minfo->rnode);
	write_unlock(&vmm_priv->minfo.node_lock);
}

struct mapinfo *
search_vmm_mapinfo(struct vmm_priv_data *vmm_priv, dev_addr_t addr)
{
	struct range_tree_node_t *node = NULL;

	read_lock(&vmm_priv->minfo.node_lock);
	node = camb_range_tree_search(&vmm_priv->minfo.range_tree, addr);
	read_unlock(&vmm_priv->minfo.node_lock);

	return node ? get_mapinfo(node) : NULL;
}
