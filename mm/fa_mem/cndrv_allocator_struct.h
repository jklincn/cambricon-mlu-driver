#ifndef __CNDRV_ALLOCATOR_STRUCT_H
#define __CNDRV_ALLOCATOR_STRUCT_H

#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/mutex.h>

#include "cndrv_mm.h"
#include "cndrv_core.h"

struct cn_fa_pool;
struct cn_fa_array;
struct cn_core_set;
struct cn_fa_pool_chunk;

#define LEFT_LEAF(index) ((index) * 2 + 1)
#define RIGHT_LEAF(index) ((index) * 2 + 2)
#define PARENT(index) (((index) + 1) / 2 - 1)

#define IS_POWER_OF_2(x) (!((x)&((x)-1)))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

struct fa_plat_sp_ops {
	void (*camb_reset_count)(struct cn_fa_array *arr, struct cn_fa_pool *pool);
	int (*camb_fa_pool_add_chunk)(struct cn_fa_array *arr,
								struct cn_fa_pool *pool, struct mem_attr
								*pattr);
	int (*camb_fa_mask_chunks)(struct cn_fa_array *arr);
	dev_addr_t (*camb_fa_alloc)(struct cn_fa_array *arr, struct mem_attr *attr,
							  size_t size,
							  void *fa_priv);
	int (*camb_fa_free)(struct cn_fa_array *arr, void *fa_priv);
	unsigned int (*camb_get_chunk_avail)(struct cn_fa_array *arr,
									   struct cn_fa_pool_chunk *chunk);
	void (*camb_chunk_destroy)(struct cn_fa_array *arr,
							 struct cn_fa_pool_chunk *chunk);
	unsigned int (*camb_fixsize)(struct cn_fa_array *arr,
							   unsigned int size);
};
/*
 *  General purpose special memory pool descriptor.
 */

struct cn_fa_array {
	struct cn_core_set *core;
	unsigned int type;
	unsigned int affinity;
	unsigned int flags;
	unsigned int alloc_order;
	unsigned int chunk_size;
	unsigned int alloc_size;
	spinlock_t lock;
	struct cn_mm_set *mm_set;
	unsigned long low_watermark;
	unsigned long high_watermark;
	unsigned long long total_chunk;
	atomic_t total_free_chunk;/*all pools free chunk cnt*/
	unsigned long long used_mem;
	unsigned long long require_mem;
	unsigned int enable;
	struct fa_plat_sp_ops *fa_ops;
	struct cn_fa_pool *pool[0];
};

/*
 *  General purpose special memory pool chunk descriptor.
 */
struct cn_fa_pool_chunk {
	struct cn_fa_pool *pool;
	spinlock_t lock;
	struct list_head next_chunk;	/* next chunk in pool */
	dev_addr_t start_addr;		/* start address of memory chunk */
	dev_addr_t end_addr;			/* end address of memory chunk (inclusive) */
	union {
		struct buddy2 *buddy_chunk;
		struct genpool2 *alloc_chunk;
	};

	bool is_linear;
	/**
	 * unused is true, means this chunks need free once it's free,
	 * it's default value is false. unless this chunk is moved into unused_list
	 **/
	bool unused;
};

/*
 *  General purpose special memory pool descriptor.
 */
struct cn_fa_pool {
	spinlock_t lock;
	struct mutex chunk_lock;  /* lock cnt_check and chunk_add */
	int alloc_order;				/* minimum allocation order, 9 = 2^9 = 512 Bytes */
	atomic_t longest;
	atomic_t shortest;
	atomic_t chunk_cnt;
	atomic_t free_chunk_cnt;
	struct mutex rpc_times;			/*just use for genpool*/
	struct cn_mm_set *mm_set;		/* mm attributes*/
	struct cn_fa_array *arr;
	struct list_head chunks;		    /* list of chunks in this pool */
	struct list_head unused_chunks;		/* list of unused_chunks in this pool */
	unsigned long low_watermark;
	unsigned long high_watermark;
	unsigned int watermark_flag;	/* low = 1, high = 2 */
	struct work_struct worker;
	struct mem_attr mm_attr;	/* allocation parameters */
	struct cn_fa_pool_chunk *shortest_chunk;
};

#endif
