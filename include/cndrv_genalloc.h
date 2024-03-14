/*
 * Basic general purpose allocator for managing special purpose
 * memory, for example, memory that is not managed by the regular
 * kmalloc/kfree interface.  Uses for this includes on-device special
 * memory, uncached memory etc.
 *
 * It is safe to use the allocator in NMI handlers and other special
 * unblockable contexts that could otherwise deadlock on locks.  This
 * is implemented by using atomic operations and retries on any
 * conflicts.  The disadvantage is that there may be livelocks in
 * extreme cases.  For better scalability, one allocator can be used
 * for each CPU.
 *
 * The lockless operation only works if there is enough memory
 * available.  If new memory is added to the pool a lock has to be
 * still taken.  So any user relying on locklessness has to ensure
 * that sufficient memory is preallocated.
 *
 * The basic atomic operation of this allocator is cmpxchg on long.
 * On architectures that don't have NMI-safe cmpxchg implementation,
 * the allocator can NOT be used in NMI handler.  So code uses the
 * allocator in NMI handler should depend on
 * CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */


#ifndef __CN_GENALLOC_H__
#define __CN_GENALLOC_H__

#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/atomic.h>

struct device;
struct device_node;
struct cn_gen_pool;

/**
 * Allocation callback function type definition
 * @map: Pointer to bitmap
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @data: optional additional data used by @genpool_algo_t
 */
typedef unsigned long (*cn_genpool_algo_t)(unsigned long *map,
			unsigned long size,
			unsigned long start,
			unsigned int nr,
			void *data, struct cn_gen_pool *pool);

/*
 *  General purpose special memory pool descriptor.
 */
struct cn_gen_pool {
	spinlock_t lock;
	struct list_head chunks;	/* list of chunks in this pool */
	int min_alloc_order;		/* minimum allocation order */

	cn_genpool_algo_t algo;		/* allocation function */
	void *data;

	const char *name;
};

/*
 *  General purpose special memory pool chunk descriptor.
 */
struct cn_gen_pool_chunk {
	struct list_head next_chunk;	/* next chunk in pool */
	atomic_long_t avail;
	phys_addr_t phys_addr;		/* physical starting address of memory chunk */
	unsigned long start_addr;	/* start address of memory chunk */
	unsigned long end_addr;		/* end address of memory chunk (inclusive) */
	unsigned long bits[0];		/* bitmap for allocating memory chunk */
};

/*
 *  gen_pool data descriptor for gen_pool_first_fit_align.
 */
struct cn_genpool_data_align {
	int align;		/* alignment by bytes for starting address */
};

/*
 *  gen_pool data descriptor for gen_pool_fixed_alloc.
 */
struct cn_genpool_data_fixed {
	unsigned long offset;		/* The offset of the specific region */
};

extern struct cn_gen_pool *cn_gen_pool_create(int, int);
extern phys_addr_t cn_gen_pool_virt_to_phys(struct cn_gen_pool *pool, unsigned long);
extern unsigned long cn_gen_pool_virt_offset(struct cn_gen_pool *pool, unsigned long);
extern int cn_gen_pool_add_virt(struct cn_gen_pool *, unsigned long, phys_addr_t,
			     size_t, int);
/**
 * cn_gen_pool_add - add a new chunk of special memory to the pool
 * @pool: pool to add new memory chunk to
 * @addr: starting address of memory chunk to add to pool
 * @size: size in bytes of the memory chunk to add to pool
 * @nid: node id of the node the chunk structure and bitmap should be
 *       allocated on, or -1
 *
 * Add a new chunk of special memory to the specified pool.
 *
 * Returns 0 on success or a -ve errno on failure.
 */
static inline int cn_gen_pool_add(struct cn_gen_pool *pool, unsigned long addr,
			       size_t size, int nid)
{
	return cn_gen_pool_add_virt(pool, addr, -1, size, nid);
}
extern void cn_gen_pool_destroy(struct cn_gen_pool *);
extern unsigned long cn_gen_pool_alloc(struct cn_gen_pool *, size_t);
extern unsigned long cn_gen_pool_alloc_algo(struct cn_gen_pool *, size_t,
		cn_genpool_algo_t algo, void *data);
extern void *cn_gen_pool_dma_alloc(struct cn_gen_pool *pool, size_t size,
		dma_addr_t *dma);
extern void *cn_gen_pool_dma_alloc_aligned(struct cn_gen_pool *pool,
		size_t size, size_t alignment, dma_addr_t *dma);
extern void cn_gen_pool_free(struct cn_gen_pool *, unsigned long, size_t);
extern void cn_gen_pool_for_each_chunk(struct cn_gen_pool *,
	void (*)(struct cn_gen_pool *, struct cn_gen_pool_chunk *, void *), void *);
extern size_t cn_gen_pool_avail(struct cn_gen_pool *);
extern size_t cn_gen_pool_size(struct cn_gen_pool *);

extern void cn_gen_pool_set_algo(struct cn_gen_pool *pool, cn_genpool_algo_t algo,
		void *data);

extern unsigned long cn_gen_pool_first_fit(unsigned long *map, unsigned long size,
		unsigned long start, unsigned int nr, void *data,
		struct cn_gen_pool *pool);

extern unsigned long cn_gen_pool_fixed_alloc(unsigned long *map,
		unsigned long size, unsigned long start, unsigned int nr,
		void *data, struct cn_gen_pool *pool);

extern unsigned long cn_gen_pool_first_fit_align(unsigned long *map,
		unsigned long size, unsigned long start, unsigned int nr,
		void *data, struct cn_gen_pool *pool);


extern unsigned long cn_gen_pool_first_fit_order_align(unsigned long *map,
		unsigned long size, unsigned long start, unsigned int nr,
		void *data, struct cn_gen_pool *pool);

extern unsigned long cn_gen_pool_best_fit(unsigned long *map, unsigned long size,
		unsigned long start, unsigned int nr, void *data,
		struct cn_gen_pool *pool);

bool cn_addr_in_gen_pool(struct cn_gen_pool *pool, unsigned long start,
			size_t size);

static inline struct gen_pool *cn_of_gen_pool_get(struct device_node *np,
	const char *propname, int index)
{
	return NULL;
}
#endif /* __CN_GENALLOC_H__ */
