/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_VMM_IOVA_H_
#define __CAMBRICON_VMM_IOVA_H_
#include "camb_range_tree.h"

/*** camb_vmm_iova structure operations interface. ***/
CAMB_STATIC struct camb_vmm_iova *get_vmm_iova(struct range_tree_node_t *node)
{
	if (!node)
		return NULL;

	return container_of(node, struct camb_vmm_iova, node);
}

void insert_vmm_iova(struct vmm_priv_data *vmm_priv, struct camb_vmm_iova *iova);
void delete_vmm_iova(struct vmm_priv_data *vmm_priv, struct camb_vmm_iova *iova);

struct camb_vmm_iova *
search_vmm_iova_compare(struct vmm_priv_data *vmm_priv, dev_addr_t addr,
			unsigned long size);

CAMB_RANGE_TREE_DECLARE_CALLBACKS(vmm_iova, struct vmm_priv_data, \
			iova.range_tree, struct camb_vmm_iova, node, get_vmm_iova, true)

#define vmm_iova_for_each_in(iova, first, priv, start, end) \
	for ((iova) = vmm_iova_iter_first((priv), (start), (end)), \
		 (first) = (iova); (iova); \
		 (iova) = vmm_iova_iter_next((priv), (iova), (end)))

#define vmm_iova_for_each_in_first(iova, first, priv, end) \
	for ((iova) = (first); (iova); \
		 (iova) = vmm_iova_iter_next((priv), (iova), (end)))

unsigned long size2bits(unsigned long size);
unsigned long addr2bit(unsigned long offset, struct camb_vmm_iova *iova);
int set_vmm_iova_bitmap(struct camb_vmm_iova *iova, dev_addr_t addr,
				unsigned long size);
int clear_vmm_iova_bitmap(struct camb_vmm_iova *iova, dev_addr_t addr,
				unsigned long size);

/*** mapinfo structure operations interface. ***/
CAMB_STATIC struct mapinfo *get_mapinfo(struct range_tree_node_t *node)
{
	if (!node)
		return NULL;

	return container_of(node, struct mapinfo, rnode);
}

CAMB_RANGE_TREE_DECLARE_CALLBACKS(vmm_minfo, struct vmm_priv_data, \
			minfo.range_tree, struct mapinfo, rnode, get_mapinfo, true)

#define vmm_minfo_for_each_in(minfo, first, priv, start, end) \
	for ((minfo) = vmm_minfo_iter_first((priv), (start), (end)), \
		 (first) = (minfo); (minfo); \
		 (minfo) = vmm_minfo_iter_next((priv), (minfo), (end)))

#define vmm_minfo_for_each_in_first(minfo, first, priv, end) \
	for ((minfo) = (first); (minfo); \
		 (minfo) = vmm_minfo_iter_next((vmm_priv), (minfo), (end)))

#define vmm_minfo_for_each_in_first_safe(minfo, next, first, priv, end) \
	for ((minfo) = (first), \
		 (next) = vmm_minfo_iter_next((vmm_priv), (minfo), end); \
		 (minfo); \
		 (minfo) = (next), \
		 (next) = vmm_minfo_iter_next((vmm_priv), (minfo), (end)))
#endif /* __CAMBRICON_VMM_IOVA_H_ */
