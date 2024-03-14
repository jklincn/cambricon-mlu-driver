#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/rbtree.h>
#include <linux/delay.h>

#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_allocator_struct.h"
#include "cndrv_buddy_allocator.h"
#include "cndrv_fa.h"
#include "camb_mm.h"
#include "camb_mm_rpc.h"
#include "cndrv_commu.h"
#include "cndrv_debug.h"

static unsigned int __do_camb_buddy2_fixsize(unsigned int size)
{
	size |= size >> 1;
	size |= size >> 2;
	size |= size >> 4;
	size |= size >> 8;
	size |= size >> 16;

	return size + 1;
}

static unsigned int camb_buddy2_fixsize(struct cn_fa_array *arr,
						unsigned int size)
{
	return __do_camb_buddy2_fixsize(size);
}

static struct buddy2 *buddy2_new(int size)
{
	struct buddy2 *self;
	unsigned int node_size;
	int i;

	if (size < 1 || !IS_POWER_OF_2(size))
		return NULL;

	self = cn_kzalloc(2*size*sizeof(unsigned int), GFP_KERNEL);
	if (!self) {
		cn_dev_err("alloc memory for buddy2 failed!\n");
		return NULL;
	}
	self->size = size;
	node_size = size * 2;

	for (i = 0; i < 2 * size - 1; ++i) {
		if (IS_POWER_OF_2(i + 1))
			node_size /= 2;

		self->longest[i] = node_size;
	}

	return self;
}

static void buddy2_destroy(struct buddy2 *self)
{
	cn_kfree(self);
}

static unsigned long buddy2_alloc(struct buddy2 *self, int size, int *ret)
{
	unsigned int index = 0;
	unsigned int node_size;
	unsigned int offset = 0;

	if (self == NULL) {
		*ret = -1;
		return 0;
	}


	if (size <= 0)
		size = 1;
	else if (!IS_POWER_OF_2(size))
		size = __do_camb_buddy2_fixsize(size);

	if (self->longest[index] < size) {
		*ret = -1;
		return -1;
	}

	for (node_size = self->size; node_size != size; node_size /= 2) {
		if (self->longest[LEFT_LEAF(index)] >= size)
			index = LEFT_LEAF(index);
		else
			index = RIGHT_LEAF(index);
	}

	self->longest[index] = 0;
	offset = (index + 1) * node_size - self->size;

	while (index) {
		index = PARENT(index);
		self->longest[index] =
			MAX(self->longest[LEFT_LEAF(index)], self->longest[RIGHT_LEAF(index)]);
	}

	return offset;
}

static void buddy2_free(struct buddy2 *self, int offset)
{
	unsigned int node_size, index = 0;
	unsigned int left_longest, right_longest;

	if (self && offset >= 0 && offset < self->size) {
		node_size = 1;
		index = offset + self->size - 1;

		for (; self->longest[index]; index = PARENT(index)) {
			node_size *= 2;

			if (index == 0)
				return;
		}

		self->longest[index] = node_size;

		while (index) {
			index = PARENT(index);
			node_size *= 2;

			left_longest = self->longest[LEFT_LEAF(index)];
			right_longest = self->longest[RIGHT_LEAF(index)];

			if (left_longest + right_longest == node_size)
				self->longest[index] = node_size;
			else
				self->longest[index] = MAX(left_longest, right_longest);
		}
	} else {
		return;
	}
}

static int buddy2_size(struct buddy2 *self, int offset)
{
	unsigned int node_size, index = 0;

	if (self && offset >= 0 && offset < self->size) {
		node_size = 1;
		for (index = offset + self->size - 1; self->longest[index]; index = PARENT(index)) {
			node_size *= 2;
		}

		return node_size;
	}

	return -1;
}

static void camb_buddy2_reset_count(struct cn_fa_array *arr, struct cn_fa_pool *pool)
{
	struct cn_fa_pool_chunk *chunk;
	int pool_cnt;

	if (pool) {
		atomic_set(&pool->longest, 0);
		atomic_set(&pool->shortest, 0xFFFFFFFF);

		pool_cnt = atomic_read(&pool->free_chunk_cnt);
		atomic_set(&pool->free_chunk_cnt, 0);
		atomic_sub(pool_cnt, &arr->total_free_chunk);

		list_for_each_entry(chunk, &pool->chunks, next_chunk) {
			if (chunk->buddy_chunk->longest[0] < atomic_read(&pool->shortest)) {
				atomic_set(&pool->shortest, chunk->buddy_chunk->longest[0]);
				pool->shortest_chunk = chunk;
			}

			if (chunk->buddy_chunk->longest[0] > atomic_read(&pool->longest)) {
				atomic_set(&pool->longest, chunk->buddy_chunk->longest[0]);
			}

			if (chunk->buddy_chunk->longest[0] == (arr->chunk_size * 1024) >> pool->alloc_order) {
				atomic_inc(&pool->free_chunk_cnt);
				atomic_inc(&arr->total_free_chunk);
			}
		}
		cn_dev_core_debug(arr->core, "pool %d %d %d longest %x free cnt %d.",
					  pool->mm_attr.type, pool->mm_attr.affinity,
					  pool->mm_attr.flag, atomic_read(&pool->longest),
					  atomic_read(&pool->free_chunk_cnt));
	}
}

static unsigned int camb_buddy2_get_chunk_avail(struct cn_fa_array *arr,
							   struct cn_fa_pool_chunk *chunk)
{
	return chunk->buddy_chunk->longest[0];
}

static int cnt_check(struct cn_fa_pool *pool, int gran_size)
{
	int ret = 0;

	/* Check whether the FA is disabled */
	if (pool->arr->enable == 0) {
		cn_dev_core_err(pool->arr->core, "Pre FA is disabled, exit.");
		return 0;
	}

	spin_lock(&pool->lock);
	ret = list_empty_careful(&pool->chunks) || (gran_size > atomic_read(&pool->longest));
	spin_unlock(&pool->lock);

	return ret;
}

static int camb_buddy2_fa_pool_add_chunk(struct cn_fa_array *arr,
							struct cn_fa_pool *pool, struct mem_attr *pattr)
{
	int ret = 0;
	struct ret_msg remsg;
	size_t result_len = sizeof(struct ret_msg);
	struct mem_attr attr;
	struct cn_fa_pool_chunk *chunk;

	if (!pool)
		return -EINVAL;

	chunk = cn_kzalloc(sizeof(struct cn_fa_pool_chunk), GFP_KERNEL);
	if (unlikely(chunk == NULL)) {
		return -ENOMEM;
	}

	chunk->buddy_chunk = buddy2_new((arr->chunk_size * 1024) >> pool->alloc_order);
	if (unlikely(chunk->buddy_chunk == NULL)) {
		cn_kfree(chunk);
		cn_dev_core_err(pool->arr->core, "buddy new failed.");
		return -ENOMEM;
	}

	memcpy(&attr, pattr, sizeof(struct mem_attr));
	memset(&remsg, 0x00, sizeof(struct ret_msg));
	attr.size = arr->chunk_size * 1024;

	if (attr.affinity == 4)
		attr.affinity = -2;

	/*TODO:call RPC to malloc a memory*/
	cn_dev_core_debug(pool->arr->core,
		"pool(mem_type-affinity-flag %d-%d-%d) adds a chunk with sync endpoint.",
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
		buddy2_destroy(chunk->buddy_chunk);
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

		buddy2_destroy(chunk->buddy_chunk);
		cn_kfree(chunk);
		return remsg.ret;
	}

	chunk->pool = pool;
	chunk->start_addr = remsg.device_addr;
	chunk->end_addr = remsg.device_addr + attr.size - 1;
	chunk->unused = false;
	chunk->is_linear = remsg.is_linear;
	spin_lock_init(&chunk->lock);

	spin_lock(&pool->lock);
	list_add(&chunk->next_chunk, &pool->chunks);
	/*Updata pool free_chunk_cnt in reset pool*/
	camb_buddy2_reset_count(arr, pool);
	spin_unlock(&pool->lock);

	atomic_inc(&pool->chunk_cnt);

	spin_lock(&arr->lock);
	arr->total_chunk++;
	spin_unlock(&arr->lock);

	return 0;
}

static dev_addr_t camb_buddy2_fa_alloc(struct cn_fa_array *arr, struct mem_attr *attr,
					   size_t size,
					   void *fa_priv)
{
	int ret = 0;
	int m_size = 0;
	int affinity = (int)attr->affinity;
	unsigned long longest = 0;
	struct cn_fa_pool *longest_pool = NULL;
	int gran_size = 0;
	unsigned long start_addr = 0;
	struct cn_fa_pool_chunk *chunk = NULL;
	struct buddy2 *buddy = NULL;
	struct cn_fa_pool *pool = NULL;
	struct fa_addr_t *priv = (struct fa_addr_t *)fa_priv;
	int pool_id;

	if (affinity == -1) {
		for (affinity = 0; affinity < 4; affinity++) {
			pool_id =
				camb_fa_get_pool_id(attr->type, affinity, attr->flag, arr);
			pool = arr->pool[pool_id];

			spin_lock(&pool->lock);
			if (atomic_read(&pool->longest) > longest) {
				longest = atomic_read(&pool->longest);
				longest_pool = pool;
			}
			spin_unlock(&pool->lock);
		}

		if (longest_pool != NULL)
			pool = longest_pool;
	} else {
		pool_id = camb_fa_get_pool_id(attr->type, affinity, attr->flag, arr);
		pool = arr->pool[pool_id];
	}

	/* Check whether the requested size is bigger than upper limit */
	if (size > arr->chunk_size * 1024) {
		cn_dev_core_err(arr->core, "Too large allocation request.");
		return -EINVAL;
	}

	/* The granularity is alloc_order, but the requested size may not be aligned */
	if (((1 << pool->alloc_order) - 1) & size) {
		gran_size = (size >> pool->alloc_order) + 1;
	} else {
		gran_size = size >> pool->alloc_order;
	}
repeat:
	/* Check whether the pool is empty or the longest space is smaller than requested */
	mutex_lock(&pool->chunk_lock);
	if (cnt_check(pool, gran_size)) {
		ret = camb_buddy2_fa_pool_add_chunk(arr, pool, attr);
		if (ret) {
			mutex_unlock(&pool->chunk_lock);
			cn_dev_core_info(arr->core, "No space to add chunk.");
			return ret;
		}
	}
	mutex_unlock(&pool->chunk_lock);

	spin_lock(&pool->lock);
	/* Check whether the FA is disabled */
	if (arr->enable == 0) {
		cn_dev_core_err(arr->core, "FA is disabled, exit.");
		spin_unlock(&pool->lock);
		return -ENOMEM;
	}
	/* If the shorest space is bigger than requested, use it */
	/* Otherwise, find a proper one in the chunk pool */
	if (atomic_read(&pool->shortest) >= gran_size) {
		buddy = pool->shortest_chunk->buddy_chunk;
		chunk = pool->shortest_chunk;
	} else {
		list_for_each_entry(chunk, &pool->chunks, next_chunk) {
			if (chunk->buddy_chunk->longest[0] < gran_size) {
				continue;
			} else {
				if ((attr->flag & ATTR_FLAG_ALLOC_LINEAR) && !chunk->is_linear)
					continue;

				buddy = chunk->buddy_chunk;
				break;
			}
		}
	}

	if (buddy == NULL) {
		cn_dev_core_debug(arr->core, "FA out of free mem, try again.");
		spin_unlock(&pool->lock);
		goto repeat;
	}

	/* Use the buddy system to allocate space */
	start_addr = buddy2_alloc(buddy, gran_size, &ret);
	if ((ret < 0) || (start_addr > (arr->chunk_size * 1024) >> pool->alloc_order)) {
		cn_dev_core_err(arr->core, "FA buddy failed.");
		spin_unlock(&pool->lock);
		return -EACCES;
	}

	/* Update the shortest and longest info */
	camb_buddy2_reset_count(arr, pool);

	priv->vaddr = (1 << pool->alloc_order) * start_addr + chunk->start_addr;
	priv->chunk = chunk;
	priv->size = size;
	priv->is_linear = chunk->is_linear;
	spin_unlock(&pool->lock);

	m_size = buddy2_size(buddy, start_addr);

	/* Update Statistics */
	spin_lock(&arr->lock);
	arr->used_mem = arr->used_mem + m_size;
	arr->require_mem = arr->require_mem + size;
	spin_unlock(&arr->lock);

	return 0;
}

static int camb_buddy2_fa_free(struct cn_fa_array *arr, void *fa_priv)
{
	int ret = 0;
	int size = 0;
	struct ret_msg remsg;
	unsigned int free_flag = 0;

	struct fa_addr_t *priv = (struct fa_addr_t *)fa_priv;
	struct cn_fa_pool *pool = NULL;
	struct cn_fa_pool_chunk *chunk = NULL;
	dev_addr_t dev_vaddr = 0UL;
	int pre_chunk_nbits;

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
	size = buddy2_size(chunk->buddy_chunk,
					   (dev_vaddr - chunk->start_addr) >> (pool->alloc_order));
	spin_lock(&pool->lock);
	buddy2_free(chunk->buddy_chunk,
				(dev_vaddr - chunk->start_addr) >> (pool->alloc_order));

	pre_chunk_nbits = (arr->chunk_size * 1024) >> pool->alloc_order;
	if (chunk->buddy_chunk->longest[0] == pre_chunk_nbits) {
		/*Updata pool free_chunk_cnt*/
		atomic_inc(&pool->free_chunk_cnt);
		atomic_inc(&arr->total_free_chunk);
	}

	if ((chunk->buddy_chunk->longest[0] == pre_chunk_nbits) &&
		((atomic_read(&pool->free_chunk_cnt) > pool->high_watermark) ||
		 chunk->unused == true)) {
		buddy2_destroy(chunk->buddy_chunk);
		list_del(&chunk->next_chunk);
		free_flag = 1;
	}

	/*If need do chunk free, dec pool free_chunk_cnt in reset count*/
	camb_buddy2_reset_count(arr, pool);
	spin_unlock(&pool->lock);

	/* Update Statistics */
	spin_lock(&arr->lock);
	arr->used_mem = arr->used_mem - size;
	arr->require_mem = arr->require_mem - priv->size;
	spin_unlock(&arr->lock);

	if (free_flag) {
		ret = camb_free_mem_rpc(pool->mm_set, pool->mm_attr.type,
								chunk->start_addr, 0, 0, &remsg,
								true);
		if (ret) {
			cn_dev_core_err(arr->core, "FA free error status (%d %d)", remsg.ret, ret);

			if (ret != ERROR_RPC_RESET) {
				chunk->buddy_chunk = buddy2_new(pre_chunk_nbits);
				if (chunk->buddy_chunk) {
					spin_lock(&pool->lock);
					list_add(&chunk->next_chunk, &pool->chunks);
					camb_buddy2_reset_count(arr, pool);
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

static int camb_buddy2_fa_mask_chunks(struct cn_fa_array *arr)
{
	int i = 0;
	struct cn_fa_pool *pool;
	struct cn_fa_pool_chunk *chunk;

	for (i = 0; i < arr->type * arr->affinity * arr->flags; i++) {
		pool = arr->pool[i];

		spin_lock(&pool->lock);

		list_splice_init(&pool->chunks, &pool->unused_chunks);
		camb_buddy2_reset_count(arr, pool);

		spin_unlock(&pool->lock);

		list_for_each_entry(chunk, &pool->unused_chunks, next_chunk)
			chunk->unused = true;
	}

	return 0;
}

static void camb_buddy2_chunk_destroy(struct cn_fa_array *arr,
							   struct cn_fa_pool_chunk *chunk)
{
	return buddy2_destroy(chunk->buddy_chunk);
}

void buddy_fa_ops_register(void *fops)
{
	struct fa_plat_sp_ops *buddy_ops = (struct fa_plat_sp_ops *)fops;

	if (buddy_ops) {
		buddy_ops->camb_reset_count = camb_buddy2_reset_count;
		buddy_ops->camb_fa_mask_chunks = camb_buddy2_fa_mask_chunks;
		buddy_ops->camb_fa_pool_add_chunk = camb_buddy2_fa_pool_add_chunk;
		buddy_ops->camb_fa_alloc = camb_buddy2_fa_alloc;
		buddy_ops->camb_fa_free = camb_buddy2_fa_free;
		buddy_ops->camb_get_chunk_avail = camb_buddy2_get_chunk_avail;
		buddy_ops->camb_chunk_destroy = camb_buddy2_chunk_destroy;
		buddy_ops->camb_fixsize = camb_buddy2_fixsize;
	}
	return;
}

