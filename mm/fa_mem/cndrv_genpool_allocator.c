#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/rbtree.h>
#include <linux/delay.h>

#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_allocator_struct.h"
#include "cndrv_genpool_allocator.h"
#include "cndrv_fa.h"
#include "camb_mm.h"
#include "camb_bitmap.h"
#include "camb_mm_rpc.h"
#include "cndrv_commu.h"
#include "cndrv_debug.h"

static int fa_order_trans(unsigned int mem_size, int order)
{
	int gran_size = 0;

	if (((1 << order) - 1) & mem_size) {
		gran_size = (mem_size >> order) + 1;
	} else {
		gran_size = mem_size >> order;
	}

	return gran_size;
}

static unsigned int camb_genpool2_fixsize(struct cn_fa_array *arr,
						unsigned int size)
{
	unsigned int gran_size;
	gran_size = fa_order_trans(size, arr->alloc_order);

	return (gran_size << arr->alloc_order);
}

static struct genpool2 *genpool2_new(int size)
{
	struct genpool2 *self;
	int nbytes;

	if (size < 1 || !IS_POWER_OF_2(size))
		return NULL;

	/*Add chunk by genpool alloc*/
	nbytes = sizeof(unsigned int) * 2 +
				BITS_TO_LONGS(size) * sizeof(long);

	self = cn_kzalloc(nbytes, GFP_KERNEL);
	if (!self) {
		cn_dev_err("alloc memory for genpool2 failed!\n");
		return NULL;
	}
	self->size = size;/*genpool size is shift right by order*/
	self->avail_size = size;/*genpool avail size is shift right by order*/

	return self;
}

static void genpool2_destroy(struct genpool2 *self)
{
	cn_kfree(self);
}

static void camb_genpool2_chunk_destroy(struct cn_fa_array *arr,
							   struct cn_fa_pool_chunk *chunk)
{
	return genpool2_destroy(chunk->alloc_chunk);
}

static unsigned long genpool2_alloc(struct genpool2 *self,
							 int size,/*is shift by order*/
							 int *ret)
{
	int remain;
	unsigned long end_bit = self->size;
	unsigned long start_bit = 0;
	unsigned int nbits = size;

retry:
	start_bit = bitmap_find_next_zero_area(self->bits, end_bit, start_bit, nbits, 0);

	if (start_bit >= end_bit) {
		/*FIXME: set avail able*/
		*ret = -EACCES;
		return 0;
	}

	remain = bitmap_set_ll(self->bits, start_bit, nbits);

	if (remain) {
		remain = bitmap_clear_ll(self->bits, start_bit,
								 nbits - remain);
		BUG_ON(remain);
		goto retry;
	}

	*ret = 0;
	self->avail_size -= nbits;

	return start_bit;
}

static void genpool2_free(struct genpool2 *self, unsigned long addr,
				   int size)
{
	int start_bit, nbits, remain;

	nbits = size;
	start_bit = addr;
	remain = bitmap_clear_ll(self->bits, start_bit, nbits);
	BUG_ON(remain);

	self->avail_size += nbits;

	return;
}

static unsigned int camb_genpool2_chunk_avail(struct cn_fa_array *arr,
							   struct cn_fa_pool_chunk *chunk)
{
	return chunk->alloc_chunk->avail_size;
}

static void
camb_genpool2_reset_count(struct cn_fa_array *arr, struct cn_fa_pool *pool)
{
	struct cn_fa_pool_chunk *chunk;
	int pool_cnt;
	unsigned int pre_chunk_nbits;

	if (!pool)
		return;

	/*longest and shortest is not used*/
	pre_chunk_nbits = (arr->chunk_size * 1024) >> pool->alloc_order;
	pool_cnt = atomic_read(&pool->free_chunk_cnt);
	atomic_set(&pool->free_chunk_cnt, 0);
	atomic_sub(pool_cnt, &arr->total_free_chunk);

	list_for_each_entry(chunk, &pool->chunks, next_chunk) {
		if (camb_genpool2_chunk_avail(arr, chunk) == pre_chunk_nbits) {
			atomic_inc(&pool->free_chunk_cnt);
			atomic_inc(&arr->total_free_chunk);
		}
	}

	cn_dev_core_debug(arr->core, "pool %d %d %d longest %x free cnt %d.",
				  pool->mm_attr.type, pool->mm_attr.affinity,
				  pool->mm_attr.flag, atomic_read(&pool->longest),
				  atomic_read(&pool->free_chunk_cnt));
}

static int cnt_check(struct cn_fa_pool *pool)
{
	int ret = 0;

	/* Check whether the FA is disabled */
	if (pool->arr->enable == 0) {
		cn_dev_core_err(pool->arr->core, "Pre FA is disabled, exit.");
		return 0;
	}

	spin_lock(&pool->lock);
	ret = list_empty_careful(&pool->chunks);
	spin_unlock(&pool->lock);

	return ret;
}

static int camb_genpool2_fa_mask_chunks(struct cn_fa_array *arr)
{
	int i = 0;
	struct cn_fa_pool *pool;
	struct cn_fa_pool_chunk *chunk;

	for (i = 0; i < arr->type * arr->affinity * arr->flags; i++) {
		pool = arr->pool[i];

		spin_lock(&pool->lock);

		list_splice_init(&pool->chunks, &pool->unused_chunks);
		camb_genpool2_reset_count(arr, pool);

		spin_unlock(&pool->lock);

		list_for_each_entry(chunk, &pool->unused_chunks, next_chunk)
			chunk->unused = true;
	}

	return 0;
}

static int camb_genpool2_fa_pool_add_chunk(struct cn_fa_array *arr,
							struct cn_fa_pool *pool, struct mem_attr *pattr)
{
	int ret = 0;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	struct mem_attr attr;
	struct cn_fa_pool_chunk *chunk;
	int pre_chunk_nbits = 0;

	if (!pool)
		return -EINVAL;

	arr = pool->arr;
	chunk = cn_kzalloc(sizeof(struct cn_fa_pool_chunk), GFP_KERNEL);
	if (unlikely(chunk == NULL)) {
		cn_dev_core_err(arr->core, "No host mem.");
		return -ENOMEM;
	}

	pre_chunk_nbits = (arr->chunk_size * 1024) >> pool->alloc_order;
	chunk->alloc_chunk = genpool2_new(pre_chunk_nbits);
	if (unlikely(chunk->alloc_chunk == NULL)) {
		cn_kfree(chunk);
		cn_dev_core_err(pool->arr->core, "genpool new failed.");
		return -ENOMEM;
	}

	memcpy(&attr, pattr, sizeof(struct mem_attr));
	memset(&remsg, 0x00, sizeof(struct ret_msg));
	attr.size = arr->chunk_size * 1024;

	if (attr.affinity == 4)
		attr.affinity = -2;

	/*TODO:call RPC to malloc a memory*/
	cn_dev_core_debug(pool->arr->core,
		"pool of mem_type-affinity-flag %d-%d-%d adds a chunk with sync endpoint.",
		pool->mm_attr.type, pool->mm_attr.affinity, pool->mm_attr.flag);

	ret = __mem_call_rpc(pool->mm_set->core, pool->mm_set->endpoint,
						 "rpc_mem_alloc",
						 (void *)&attr,
						 sizeof(struct mem_attr),
						 &remsg, &result_len, sizeof(struct ret_msg));


	if (attr.affinity == -2)
		attr.affinity = 4;

	if (ret < 0) {
		cn_dev_core_err(pool->arr->core, "cnrpc client request mem failed.");
		genpool2_destroy(chunk->alloc_chunk);
		cn_kfree(chunk);
		return -EPIPE;
	}

	if (remsg.ret) {
		if (remsg.ret == -ENOSPC) {
			cn_dev_core_err(pool->arr->core, "No space left on the device.");
		} else {
			cn_dev_core_err(pool->arr->core,
							"rpc_mem_alloc error status is %d", remsg.ret);
		}

		genpool2_destroy(chunk->alloc_chunk);
		cn_kfree(chunk);
		return remsg.ret;
	}

	chunk->pool = pool;
	chunk->start_addr = remsg.device_addr;
	chunk->end_addr = remsg.device_addr + attr.size - 1;
	chunk->unused = false;
	chunk->is_linear = remsg.is_linear;
	spin_lock_init(&chunk->lock);

	/*add chunk to pool*/
	spin_lock(&pool->lock);
	list_add(&chunk->next_chunk, &pool->chunks);
	/*Updata pool free_chunk_cnt in reset pool*/
	camb_genpool2_reset_count(arr, pool);
	spin_unlock(&pool->lock);

	atomic_inc(&pool->chunk_cnt);

	spin_lock(&arr->lock);
	arr->total_chunk++;
	spin_unlock(&arr->lock);

	return 0;
}

static dev_addr_t camb_genpool2_fa_alloc(struct cn_fa_array *arr,
									   struct mem_attr *attr,
									   size_t size,
									   void *fa_priv)
{
	int ret = 0;
	int m_size = 0;
	int affinity = (int)attr->affinity;
	int gran_size = 0;
	unsigned long start_addr = 0;
	struct cn_fa_pool_chunk *chunk = NULL;
	struct genpool2 *allocator= NULL;
	struct cn_fa_pool *pool = NULL;
	struct fa_addr_t *priv = (struct fa_addr_t *)fa_priv;
	int chunk_cnt_of_pool = 0;
	bool finish_alloc = false;
	int pool_id;
	int pre_chunk_nbits = 0;

	/*delete short so not used -1*/
	if (affinity == -1) {
		affinity = 0;
	}

	pool_id = camb_fa_get_pool_id(attr->type, affinity, attr->flag, arr);
	pool = arr->pool[pool_id];

	/* Check whether the requested size is bigger than upper limit */
	if (size > arr->chunk_size * 1024) {
		cn_dev_core_err(arr->core, "Too large allocation request.");
		return -EINVAL;
	}

	/* Check whether the pool is empty or the longest space is smaller than requested */
	mutex_lock(&pool->chunk_lock);
	if (cnt_check(pool)) {
		ret = camb_genpool2_fa_pool_add_chunk(arr, pool, attr);
		if (ret) {
			mutex_unlock(&pool->chunk_lock);
			cn_dev_core_info(arr->core, "No space to add chunk.");
			return ret;
		}
	}
	mutex_unlock(&pool->chunk_lock);

	if (arr->enable == 0) {
		cn_dev_core_err(arr->core, "FA is disabled, exit.");
		return -ENOMEM;
	}

	/* The granularity is alloc_order, but the requested size may not be aligned */
	gran_size = fa_order_trans(size, pool->alloc_order);

	pre_chunk_nbits = (arr->chunk_size * 1024) >> pool->alloc_order;
	/*loop all chunk*/
	chunk_cnt_of_pool = atomic_read(&pool->chunk_cnt);
fa_alloc:
	spin_lock(&pool->lock);
	list_for_each_entry(chunk, &pool->chunks, next_chunk) {
		if (camb_genpool2_chunk_avail(arr, chunk) < gran_size) {
			/*check avail is not enough, try next*/
			continue;
		} else {
			allocator = chunk->alloc_chunk;
			if (allocator == NULL) {
				cn_dev_core_err(arr->core, "FA out of free mem, try again.");
				continue;
			}

			if ((attr->flag & ATTR_FLAG_ALLOC_LINEAR) && !chunk->is_linear)
				continue;

			start_addr = genpool2_alloc(allocator, gran_size, &ret);
			if ((ret < 0) || (start_addr > pre_chunk_nbits)) {
				/*check avail is not enough, try next*/
				continue;
			}
			/*finish malloc*/
			finish_alloc = true;
			break;
		}
	}
	spin_unlock(&pool->lock);

	if (!finish_alloc) {
		mutex_lock(&pool->chunk_lock);

		if (chunk_cnt_of_pool < atomic_read(&pool->chunk_cnt)) {
			chunk_cnt_of_pool = atomic_read(&pool->chunk_cnt);
			mutex_unlock(&pool->chunk_lock);
			goto fa_alloc;
		} else {
			ret = camb_genpool2_fa_pool_add_chunk(arr, pool, attr);
			if (ret) {
				cn_dev_core_info(arr->core, "No space to add chunk.");
				mutex_unlock(&pool->chunk_lock);
				return ret;
			}
			mutex_unlock(&pool->chunk_lock);
			goto fa_alloc;
		}
	}
	/* Update the shortest and longest info */
	spin_lock(&pool->lock);
	camb_genpool2_reset_count(arr, pool);

	priv->vaddr = (1 << pool->alloc_order) * start_addr + chunk->start_addr;
	priv->chunk = chunk;
	priv->size = size;
	priv->is_linear = chunk->is_linear;
	spin_unlock(&pool->lock);
	m_size = gran_size;

	/* Update Statistics */
	spin_lock(&arr->lock);
	arr->used_mem = arr->used_mem + m_size;
	arr->require_mem = arr->require_mem + size;
	spin_unlock(&arr->lock);

	return 0;
}

static int camb_genpool2_fa_free(struct cn_fa_array *arr, void *fa_priv)
{
	int ret = 0;
	int size = 0;
	struct ret_msg remsg;
	unsigned int free_flag = 0;
	struct fa_addr_t *priv = (struct fa_addr_t *)fa_priv;
	struct cn_fa_pool *pool = NULL;
	struct cn_fa_pool_chunk *chunk = NULL;
	dev_addr_t dev_vaddr = 0UL;
	bool free_chunk = false;
	unsigned int pre_chunk_nbits;

	chunk = priv->chunk;
	if (!chunk) {
		cn_dev_core_err(arr->core, "FA free Addr doesn't exsist.");
		return -EINVAL;
	}
	dev_vaddr = udvm_get_iova_from_addr(priv->vaddr);
	pool = chunk->pool;
	cn_dev_core_debug(arr->core, "pool %d %d %d fa free.",
					  pool->mm_attr.type, pool->mm_attr.affinity,
					  pool->mm_attr.flag);
	/*get size*/
	size = fa_order_trans(priv->size, pool->alloc_order);
	spin_lock(&pool->lock);
	genpool2_free(chunk->alloc_chunk,
	              (dev_vaddr - chunk->start_addr) >> (pool->alloc_order),
				  size);

	pre_chunk_nbits = (arr->chunk_size * 1024) >> pool->alloc_order;
	if (camb_genpool2_chunk_avail(arr, chunk) == pre_chunk_nbits) {
		/*Updata pool free_chunk_cnt*/
		atomic_inc(&pool->free_chunk_cnt);
		atomic_inc(&arr->total_free_chunk);
		free_chunk = true;
	}

	if (free_chunk &&
		((atomic_read(&pool->free_chunk_cnt) > pool->high_watermark) ||
		 chunk->unused == true)) {
		genpool2_destroy(chunk->alloc_chunk);
		list_del(&chunk->next_chunk);
		free_flag = 1;
	}

	/*If need do chunk free, dec pool free_chunk_cnt in reset count*/
	camb_genpool2_reset_count(arr, pool);
	spin_unlock(&pool->lock);

	/* Update Statistics */
	spin_lock(&arr->lock);
	arr->used_mem = arr->used_mem - size;
	arr->require_mem = arr->require_mem - priv->size;
	spin_unlock(&arr->lock);

	if (free_flag) {
		ret = camb_free_mem_rpc(pool->mm_set, pool->mm_attr.type,
	                            chunk->start_addr, 0, 0, &remsg, true);
		if (ret) {
			cn_dev_core_err(arr->core, "FA free error status (%d,%d)", remsg.ret, ret);
			if (ret != ERROR_RPC_RESET) {
				chunk->alloc_chunk = genpool2_new(pre_chunk_nbits);
				if (chunk->alloc_chunk) {
					spin_lock(&pool->lock);
					list_add(&chunk->next_chunk, &pool->chunks);
					camb_genpool2_reset_count(arr, pool);
					spin_unlock(&pool->lock);
				}
			}

			cn_dev_core_err(arr->core, "FA free RPC error.");
			return 0;
		}

		cn_kfree(chunk);
		atomic_dec(&pool->chunk_cnt);

		/* Update Statistics */
		spin_lock(&arr->lock);
		arr->total_chunk--;
		spin_unlock(&arr->lock);
	}

	return 0;
}

void genpool_fa_ops_register(void *fops)
{
	struct fa_plat_sp_ops *genpool_ops = (struct fa_plat_sp_ops *)fops;

	if (genpool_ops) {
		genpool_ops->camb_reset_count = camb_genpool2_reset_count;
		genpool_ops->camb_fa_mask_chunks = camb_genpool2_fa_mask_chunks;
		genpool_ops->camb_fa_pool_add_chunk = camb_genpool2_fa_pool_add_chunk;
		genpool_ops->camb_fa_alloc = camb_genpool2_fa_alloc;
		genpool_ops->camb_fa_free = camb_genpool2_fa_free;
		genpool_ops->camb_get_chunk_avail = camb_genpool2_chunk_avail;
		genpool_ops->camb_chunk_destroy = camb_genpool2_chunk_destroy;
		genpool_ops->camb_fixsize = camb_genpool2_fixsize;
	}
	return;
}

