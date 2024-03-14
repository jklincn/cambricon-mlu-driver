#ifndef __CNDRV_FA_ALLOCATOR_H
#define __CNDRV_FA_ALLOCATOR_H

#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/mutex.h>

#include "cndrv_mm.h"
#include "../mm/fa_mem/cndrv_allocator_struct.h"
#include "cndrv_core.h"

enum shrink_list_type {
	NORMAL_LIST = 1UL << 0,
	UNUSED_LIST = 1UL << 1,
};

struct fa_stat {
	size_t total_size;
	size_t used_size;
	size_t require_mem;
	size_t shrink_size;
};

struct fa_init_info {
	unsigned int mem_type_cnt;
	unsigned int mem_affinity_cnt;
	unsigned int mem_flags;
	unsigned int alloc_order;
	unsigned int chunk_size;
	unsigned int alloc_size;
	unsigned long low_watermark;
	unsigned long high_watermark;
	unsigned int devid;
};

struct fa_dev_ops {
	int cmd;
	union {
		struct fa_stat stat;
		unsigned long en;
	};
};

#define FA_OPS_GET_STAT 0x1
#define FA_OPS_CTL_EN   0x2
#define FA_OPS_MASK_CHUNKS   0x3

int camb_fa_get_pool_id(unsigned int mem_type, unsigned int affinity,
			            unsigned int flag, struct cn_fa_array *fa);
unsigned int camb_fixsize(struct cn_fa_array *arr, unsigned int size);
struct cn_fa_array *camb_fast_alloc_init(struct cn_core_set *core, struct fa_init_info *info);
void camb_fast_alloc_exit(struct cn_fa_array *arr);
struct cn_fa_pool *camb_fa_pool_create(struct cn_fa_array *arr, int alloc_order);
int camb_fa_pool_add_chunk(struct cn_fa_array *arr,
						 struct cn_fa_pool *pool, struct mem_attr *pattr);
int camb_fa_statistic(struct cn_fa_array *arr, struct fa_stat *stat);
int camb_fa_mask_chunks(struct cn_fa_array *arr);
void camb_fa_reset_count(struct cn_fa_array *arr, struct cn_fa_pool *pool);
dev_addr_t camb_fa_alloc(struct cn_fa_array *arr, struct mem_attr *attr,
					   size_t size,
					   void *fa_priv);
int camb_fa_free(struct cn_fa_array *arr, void *fa_priv);
unsigned int camb_get_chunk_avail(struct cn_fa_array *arr,
							   struct cn_fa_pool_chunk *chunk);
void camb_chunk_destroy(struct cn_fa_array *arr,
							   struct cn_fa_pool_chunk *chunk);
void camb_fa_shrink(struct cn_mm_set *mm_set, struct cn_fa_array *arr,
						  bool mem_sync_commu_point);
void camb_fa_clear_unused(struct cn_fa_array *arr);
int camb_fa_init(void *pcore);
#endif
