/************************************************************************
 *  @file cndrv_pci_private.h
 *
 *  @brief For pcie support definitions.
 **************************************************************************/

/*************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ***************************************************************************/

#ifndef _PCIE_DMA_H_
#define _PCIE_DMA_H_

#include <linux/kfifo.h>
#include "cndrv_genalloc.h"

#define CHANNEL_IDLE                       0
#define CHANNEL_ASSIGNED                   1
#define CHANNEL_READY                      2
#define CHANNEL_LOCK                       3
#define CHANNEL_RUNNING                    4
#define CHANNEL_COMPLETED                  5
#define CHANNEL_COMPLETED_ERR              6
#define CHANNEL_ASYNC_FREE                 7

/*
 * set pcie dma timeout longer than soft/hard lockup stuck 21s
 * otherwise crazy print dump reg and dma desc
 */
#define TIME_OUT_VALUE                     (HZ*60)
#define DMA_BUFFER_SIZE			   (1*1024*1024UL)
struct dma_buf_info {
	u64              dma_addr;
	unsigned char   *vir_addr;
	unsigned int     size;
};

#define DMA_TASK_MAX (32)

#define DMA_TASK_IDLE                       1
#define DMA_TASK_ASSIGNED                   2
#define DMA_TASK_EXIT                       3

#define  ASYNC_DMA_DESC                     (64)

enum CN_PCIE_DMA_TYPE {
	PCIE_DMA_USER,
	PCIE_DMA_KERNEL,
	PCIE_DMA_P2P,
	PCIE_DMA_USER_REMOTE,
	PCIE_DMA_PINNED_MEM,
	PCIE_DMA_MEMSET,
};

struct dma_channel_info {
	struct cn_pcie_set                *pcie_set;
	struct pcie_dma_task              *task;

	DMA_DIR_TYPE                       direction;
	size_t                             transfer_length;
	unsigned long                      cpu_addr;
	u64                                ram_addr;
	u64                                pinned_kvaddr;
	volatile int                       status;

	void                             **pp_pages;
	void                              *sg;
	int                                nents;
	int                                page_cnt;

	void __iomem                      *desc_virt_base;
	u64                                desc_device_va;
	unsigned long                      desc_size;
	int                                desc_order;

	int                                desc_len;

	struct dma_buf_info                *dma_buf;
	int				   dma_buf_cnt;
	enum CN_PCIE_DMA_TYPE              dma_type;
	int                                dma_copy;

	volatile int                       fetch_buf_num;
	int fix_count;
};

struct dma_desc_order_table {
	int number;
	int block; /* 2^n */
	struct dma_channel_info **list;
};

struct async_task {
	/*
	 *
	 * [NOTE] These values before reserved can be set to 0
	 *        when get idle sysc task by cn_pci_get_async_dma_idle_task
	 *
	 */
	enum CN_PCIE_DMA_TYPE           dma_type;
	u64                             index;
	u64                             tags;
	struct cn_pcie_set             *pcie_set;
	struct cn_pcie_set             *pcie_set_stream;
	int                             clockid;

	// mem release
	u64                             user;
	int                             abort_flag;

	// h2d or d2h
	struct task_struct             *tsk;
	struct mm_struct               *tsk_mm;
	struct transfer_s               transfer;

	// memset
	struct memset_s		        memset;

	// p2p
	struct peer_s                   peer;
	struct cn_pcie_set             *pcie_set_src;

	int                             trigger_type;
	struct dma_async_info_s        *async_info;
	struct work_struct              trigger_work;

	unsigned long                   kvaddr;
	unsigned long                   kvaddr_cur;
	unsigned long                   kvaddr_align;

	struct hlist_node               hlist;

	int                             chunk[ASYNC_DMA_DESC];
	int                             nents;
	unsigned long                   offset;

	struct scatterlist              sg_list[ASYNC_DMA_DESC];
	int                             sg_list_nents;

	int                             desc_len;

	void                           *prev_task;
	void                           *next_task;

	int                             dynamic_alloc_flag; /* indicate the way of task alloc */
	int                             dynamic_desc_num;
	int                             bit_index;

	/*
	 *
	 * [NOTE] Values before reserved can be memset 0 in cn_pci_get_async_dma_idle_task
	 *
	 */
	u64                             reserved;

	int                             id;
	unsigned long                   host_desc_addr;
	u64                             dev_desc_addr;
	void                           *desc_buf;
	void                          **pp_pages;
};

struct non_align_s {
	size_t cnt;
	u64    ia;       /* device addr */
	u64    ca;       /* host addr */
};

struct pcie_dma_task {
	/*
	 *
	 * [NOTE] These values can be set to 0 until reserved
	 *        when get idle task by cn_pci_get_dma_idle_task
	 *
	 */
	struct cn_pcie_set                *pcie_set;
	struct transfer_s                 *transfer;
	size_t                             count;
	size_t                             align_offset;

	enum CN_PCIE_DMA_TYPE              dma_type;
	struct task_struct                *tsk;
	struct mm_struct                  *tsk_mm;

	/* the head data and tail for dma write 64 bytes align */
	struct non_align_s                 non_align[2];
	int                                non_align_flag;
	int                                dma_copy;

	/* optimization for data less than 256KB */
	int                              dma_async;
	unsigned long			 kvaddr;
	unsigned long			 kvaddr_cur;
	unsigned long			 kvaddr_align;

	/* for async transfer task */
	struct cn_pcie_set                *pcie_set_dst;
	u64                                src_addr;
	u64                                dst_addr;
	/* Sloving 290 p2p 4bit align and mdr lock bar, so p2p only use p2p_bar*/
	struct bar_resource		  *p2p_src_bar;
	struct bar_resource		  *p2p_dst_bar;

	/* use the special physical dma or use physical addr */
	struct dma_config_t                cfg;
	int poison_flag;

	/*
	 *
	 * [NOTE] Values before reserved can be memset 0 in cn_pci_get_dma_idle_task
	 *
	 */
	u64 reserved;

	wait_queue_head_t                  channel_wq;

	volatile unsigned long             status; /* idle or assigned should atomic access */

	struct kfifo ready_fifo;
	struct kfifo finish_fifo;
	spinlock_t                         ready_fifo_lock;

	void **pp_pages;
	int *chunk;   /* continuous page number */
	int page_cnt; /* total page number */
	int nents;    /* continuous page block number */
	unsigned long offset;

	struct dma_desc_order_table       *priv_order_table; /* form 0 to 8*/

	void                              *desc_buf; /* desc buf for all channels related to this task*/
};


#define LOWER32(ld) ((unsigned int)(ld & 0xFFFFFFFFu))
#define UPPER32(ld) ((unsigned int)(((unsigned long)ld >> 32) & 0xFFFFFFFFu))

#endif
