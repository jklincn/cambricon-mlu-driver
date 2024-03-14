/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_P2P_REMAP_H_
#define __CAMBRICON_P2P_REMAP_H_

/* rpc_mem_iova_remap structure */
/* input size and iova need aligned with 16K */
enum handle_type {
	REMAP_IOVA = 0x0,
};

struct remap_info_t {
	uint64_t handle;
	uint64_t mapped_iova;
	uint64_t size;
	uint32_t prot;
	uint8_t  type;  /* type for input handle, current only support iova */
};

struct p2p_remap_node {
	dev_addr_t mapped_addr;
	dev_addr_t orig_addr;
	unsigned long size;
	struct mapinfo *minfo;
	struct list_head minfo_node;
	struct list_head lru_node;
	atomic_t refcnt;
};

int camb_mem_p2p_remap(struct mapinfo *pminfo, dev_addr_t orig_iova, size_t size,
				dev_addr_t *mapped_iova);

int camb_mem_p2p_unmap(struct mapinfo *pminfo, dev_addr_t mapped_iova);

dev_addr_t camb_p2p_pool_get_base(struct cn_mm_set *mm_set);

int camb_p2p_normal_remap_init(struct cn_mm_set *mm_set);
void camb_p2p_normal_remap_exit(struct cn_mm_set *mm_set);

int camb_p2p_pool_init(struct cn_mm_set *mm_set, dev_addr_t dev_vaddr,
			unsigned long size);
void camb_p2p_pool_exit(struct cn_mm_set *mm_set);

void camb_p2p_remap_release(struct mapinfo *pminfo);

bool camb_p2p_range_in_pool(struct cn_mm_set *mm_set, dev_addr_t base,
				unsigned long size);
#endif /* __CAMBRICON_P2P_REMAP_H_ */
