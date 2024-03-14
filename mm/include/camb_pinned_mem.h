/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#ifndef __CAMBRICON_MM_PINNED_MEM_H__
#define __CAMBRICON_MM_PINNED_MEM_H__
#include "camb_udvm.h"

int camb_pinned_mem_init(struct cn_udvm_set *udvm);
void camb_pinned_mem_exit(void);

int camb_pinned_mem_ipc_get_handle(struct file *fp, host_addr_t host_vaddr,
			dev_ipc_handle_t *handle, unsigned int *flags);
int camb_pinned_mem_ipc_open_handle(struct file *fp, unsigned long kva, int tgid,
			host_addr_t *host_vaddr, unsigned long *size, unsigned int *flags);
int camb_pinned_mem_ipc_close_handle(struct file *fp, host_addr_t host_vaddr);
int camb_pinned_get_mem_range(struct file *fp, host_addr_t host_vaddr,
			host_addr_t *base, unsigned long *size);
int camb_pinned_obd_map_init(void);

unsigned long cn_pinned_mem_copy_cp_node(void *buf, int *skip, unsigned long size,
		int (*do_copy)(void *, unsigned long, unsigned long, unsigned long));

/*export for udvm api*/
int cn_pinned_mem_alloc_internal(struct file *fp, unsigned long *p_va,
								 unsigned long size, int flags);
int cn_pinned_mem_free_internal(unsigned long va);
int cn_pinned_mem_ob_create(u64 uaddr);

int cn_pinned_mem_host_register_internal(struct file *fp, u64 va, u64 size,
		int flags, int card_id);

int cn_pinned_mem_host_unregister_internal(struct file *fp, u64 uaddr, int card_id);

int cn_pinned_mem_iova_alloc(u64 uva, unsigned long *iova_alloc);
int cn_pinned_mem_iova_free(u64 uva);

int cn_pinned_mem_map_dma(u64 uaddr, int card_id);
int cn_pinned_mem_unmap_dma(u64 uaddr, int card_id);
int cn_pinned_mem_map_ob(u64 uaddr, int card_id);
int cn_pinned_mem_unmap_ob(u64 uaddr, int card_id);

#endif /* __CAMBRICON_MM_PINNED_MEM_H__ */
