#include <linux/bitops.h>
#include <linux/slab.h>
#include "cndrv_debug.h"
#include "camb_mm.h"
#include "camb_vmm.h"
#include "camb_iova_allocator.h"

/**
 * NOTE: allocator default alloc address starting from highest area, which not
 * support expand virtual address range with multi times allocate. Use start_at_low
 * could change allocator's behavior to alloc virtual address start from lowest area.
 *
 * default start_at_low is set, if allocator have bug need to be located, we can
 * use allocator default behavior by set start_at_low as zero.
 **/
static bool start_at_low = 1;

static struct camb_iova_node *to_iova_node(struct rb_node *node)
{
	return rb_entry(node, struct camb_iova_node, node);
}

void camb_create_iova_allocator(struct camb_iova_domain *iovad,
		unsigned long start_pfn, unsigned long end_pfn, unsigned long granule)
{
	BUG_ON(!is_power_of_2(granule));

	spin_lock_init(&iovad->iova_rbtree_lock);
	iovad->rbroot = RB_ROOT;
	iovad->cached_node = &iovad->anchor.node;
	iovad->granule = granule;
	iovad->start_pfn = start_pfn;
	iovad->end_pfn = end_pfn;
	if (start_at_low)
		iovad->anchor.pfn_lo = iovad->anchor.pfn_hi = iovad->start_pfn - 1;
	else
		iovad->anchor.pfn_lo = iovad->anchor.pfn_hi = iovad->end_pfn + 1;

	rb_link_node(&iovad->anchor.node, NULL, &iovad->rbroot.rb_node);
	rb_insert_color(&iovad->anchor.node, &iovad->rbroot);
}

static struct camb_iova_node *__alloc_iova_mem(void)
{
	return cn_kzalloc(sizeof(struct camb_iova_node), GFP_KERNEL);
}

static void __free_iova_mem(struct camb_iova_node *iova)
{
	cn_kfree(iova);
}

static struct rb_node *
__get_cached_rbnode(struct camb_iova_domain *iovad)
{
	return iovad->cached_node;
}

static void
__cached_rbnode_insert_update(struct camb_iova_domain *iovad,
			struct camb_iova_node *new)
{
	iovad->cached_node = &new->node;
}

static void
__cached_rbnode_delete_update(struct camb_iova_domain *iovad,
			struct camb_iova_node *free)
{
	struct camb_iova_node *cached_iova = to_iova_node(iovad->cached_node);

	if (start_at_low && (free->pfn_lo <= cached_iova->pfn_lo))
		iovad->cached_node = rb_prev(&free->node);

	if (!start_at_low && (free->pfn_lo >= cached_iova->pfn_lo))
		iovad->cached_node = rb_next(&free->node);
}

static struct rb_node *
__camb_iova_find_limit(struct camb_iova_domain *iovad, unsigned long limit_pfn)
{
	struct rb_node *node, *next;

	node = iovad->rbroot.rb_node;
	while (to_iova_node(node)->pfn_hi < limit_pfn)
		node = node->rb_right;

search_left:
	while (node->rb_left && to_iova_node(node->rb_left)->pfn_lo >= limit_pfn)
		node = node->rb_left;

	if (!node->rb_left)
		return node;

	next = node->rb_right;
	while (next->rb_right) {
		next = next->rb_right;
		if (to_iova_node(next)->pfn_lo >= limit_pfn) {
			node = next;
			goto search_left;
		}
	}

	return node;
}

static struct rb_node *
__camb_iova_find_low(struct camb_iova_domain *iovad, unsigned long start_pfn)
{
	struct rb_node *node, *next;

	node = iovad->rbroot.rb_node;
	while (to_iova_node(node)->pfn_lo > start_pfn)
		node = node->rb_left;

search_right:
	while (node->rb_right && to_iova_node(node->rb_right)->pfn_hi <= start_pfn)
		node = node->rb_right;

	if (!node->rb_right)
		return node;

	next = node->rb_left;
	while (next->rb_left) {
		next = next->rb_left;
		if (to_iova_node(next)->pfn_hi <= start_pfn) {
			node = next;
			goto search_right;
		}
	}

	return node;
}

static void
__iova_insert_rbtree(struct rb_root *root, struct camb_iova_node *iova,
			struct rb_node *start)
{
	struct rb_node **new, *parent = NULL;

	new = (start) ? &start : &(root->rb_node);

	while (*new) {
		struct camb_iova_node *this = to_iova_node(*new);

		parent = *new;

		if (iova->pfn_lo < this->pfn_lo) {
			new = &((*new)->rb_left);
		} else if (iova->pfn_lo > this->pfn_lo) {
			new = &((*new)->rb_right);
		} else {
			WARN_ON(1);
			return;
		}
	}

	rb_link_node(&iova->node, parent, new);
	rb_insert_color(&iova->node, root);
}

static struct camb_iova_node *
private_find_iova(struct camb_iova_domain *iovad, unsigned long pfn)
{
	struct rb_node *node = iovad->rbroot.rb_node;

	assert_spin_locked(&iovad->iova_rbtree_lock);
	while (node) {
		struct camb_iova_node *iova = to_iova_node(node);

		if (pfn < iova->pfn_lo)
			node = node->rb_left;
		else if (pfn > iova->pfn_hi)
			node = node->rb_right;
		else
			return iova;
	}

	return NULL;
}

static void
__remove_iova(struct camb_iova_domain *iovad, struct camb_iova_node *iova)
{
	assert_spin_locked(&iovad->iova_rbtree_lock);
	__cached_rbnode_delete_update(iovad, iova);
	rb_erase(&iova->node, &iovad->rbroot);
}

static int
__alloc_insert_iova(struct camb_iova_domain *iovad, unsigned long size,
		unsigned long limit_pfn, struct camb_iova_node *new,
		bool size_aligned)
{
	struct rb_node *curr = NULL, *prev = NULL;
	struct camb_iova_node *curr_iova = NULL;
	unsigned long flags;
	unsigned long new_pfn, retry_pfn;
	unsigned long align_mask = ~0UL;
	unsigned long high_pfn = limit_pfn, low_pfn = iovad->start_pfn;

	if (size_aligned)
		align_mask <<= fls_long(size - 1);

	spin_lock_irqsave(&iovad->iova_rbtree_lock, flags);
	curr = __get_cached_rbnode(iovad);
	curr_iova = to_iova_node(curr);
	retry_pfn = curr_iova->pfn_hi + 1;

retry:
	do {
		high_pfn = min_t(unsigned long, high_pfn, curr_iova->pfn_lo);
		new_pfn = (high_pfn - size) & align_mask;
		prev = curr;
		curr = rb_prev(curr);
		curr_iova = to_iova_node(curr);
	} while (curr && new_pfn <= curr_iova->pfn_hi && new_pfn >= low_pfn);

	if (high_pfn < size || new_pfn < low_pfn) {
		if (low_pfn == iovad->start_pfn && retry_pfn < limit_pfn) {
			high_pfn = limit_pfn;
			low_pfn = retry_pfn;
			curr = __camb_iova_find_limit(iovad, limit_pfn);
			curr_iova = to_iova_node(curr);
			goto retry;
		}

		spin_unlock_irqrestore(&iovad->iova_rbtree_lock, flags);
		return -ENOMEM;
	}

	new->pfn_lo = new_pfn;
	new->pfn_hi = new->pfn_lo + size - 1;

	__iova_insert_rbtree(&iovad->rbroot, new, prev);
	__cached_rbnode_insert_update(iovad, new);

	spin_unlock_irqrestore(&iovad->iova_rbtree_lock, flags);
	return 0;
}

static int
__alloc_insert_iova_lowstart(struct camb_iova_domain *iovad, unsigned long size,
			unsigned long align, unsigned long start_pfn,
			struct camb_iova_node *new)
{
	struct rb_node *curr = NULL, *next = NULL;
	struct camb_iova_node *curr_iova = NULL;
	unsigned long flags;
	unsigned long new_pfn, retry_pfn;
	unsigned long high_pfn = iovad->end_pfn, low_pfn = start_pfn;
	bool do_align = false;

	if (align && is_power_of_2(align))
		do_align = true;

	spin_lock_irqsave(&iovad->iova_rbtree_lock, flags);
	curr = __get_cached_rbnode(iovad);
	curr_iova = to_iova_node(curr);
	retry_pfn = curr_iova->pfn_lo - 1;

retry:
	do {
		low_pfn = max_t(unsigned long, low_pfn, curr_iova->pfn_hi + 1);
		if (do_align) low_pfn = ALIGN(low_pfn, align);

		new_pfn = low_pfn + size;
		next = curr;
		curr = rb_next(curr);
		curr_iova = to_iova_node(curr);
	} while (curr && new_pfn >= curr_iova->pfn_lo && new_pfn <= high_pfn);

	if (high_pfn < size || new_pfn > high_pfn) {
		if (high_pfn == iovad->end_pfn && retry_pfn >= start_pfn) {
			high_pfn = retry_pfn;
			low_pfn = start_pfn;
			curr = __camb_iova_find_low(iovad, start_pfn);
			curr_iova = to_iova_node(curr);
			goto retry;
		}

		spin_unlock_irqrestore(&iovad->iova_rbtree_lock, flags);
		return -ENOMEM;
	}

	new->pfn_lo = new_pfn - size;
	new->pfn_hi = new->pfn_lo + size - 1;

	__iova_insert_rbtree(&iovad->rbroot, new, next);
	__cached_rbnode_insert_update(iovad, new);

	spin_unlock_irqrestore(&iovad->iova_rbtree_lock, flags);
	return 0;
}

struct camb_iova_node *
camb_alloc_iova_internal(struct camb_iova_domain *iovad,
		unsigned long start_pfn, unsigned long size, unsigned long align)
{
	struct camb_iova_node *new_iova = NULL;
	unsigned long limit_pfn = iovad->end_pfn;
	int ret = 0;

	new_iova = __alloc_iova_mem();
	if (!new_iova)
		return NULL;

	if (start_pfn + size > iovad->end_pfn) {
		__free_iova_mem(new_iova);
		return NULL;
	}

	if ((start_pfn < iovad->start_pfn))
		start_pfn = iovad->start_pfn;

	if (start_at_low) {
		ret = __alloc_insert_iova_lowstart(iovad, size, align, start_pfn, new_iova);
	} else {
		limit_pfn = start_pfn + size;
		ret = __alloc_insert_iova(iovad, size, limit_pfn, new_iova, false);
	}

	if (ret) {
		__free_iova_mem(new_iova);
		return NULL;
	}

	return new_iova;
}

dev_addr_t camb_alloc_iova(struct camb_iova_domain *iovad, dev_addr_t start,
					unsigned long size, unsigned long align)
{
	struct camb_iova_node *iova = NULL;
	unsigned long shift = camb_iova_shift(iovad);
	unsigned long counts = camb_iova_align(iovad, size) >> shift;

	align = camb_iova_align(iovad, align) >> shift;
	iova = camb_alloc_iova_internal(iovad, camb_iova_pfn(iovad, start),
					counts, align);

	return iova ? camb_iova_addr(iovad, iova) : 0;
}

static void
camb_free_iova_internal(struct camb_iova_domain *iovad, unsigned long pfn)
{
	unsigned long flags = 0;
	struct camb_iova_node *iova = NULL;

	spin_lock_irqsave(&iovad->iova_rbtree_lock, flags);
	iova = private_find_iova(iovad, pfn);
	if (!iova) {
		spin_unlock_irqrestore(&iovad->iova_rbtree_lock, flags);
		return ;
	}

	__remove_iova(iovad, iova);
	spin_unlock_irqrestore(&iovad->iova_rbtree_lock, flags);
	__free_iova_mem(iova);
}

void camb_free_iova(struct camb_iova_domain *iovad, dev_addr_t addr)
{
	camb_free_iova_internal(iovad, camb_iova_pfn(iovad, addr));
}

void camb_destroy_iova_allocator(struct camb_iova_domain *iovad)
{
	struct camb_iova_node *iova;
	struct rb_node *node;
	unsigned long flags;

	spin_lock_irqsave(&iovad->iova_rbtree_lock, flags);
	node = rb_first(&iovad->rbroot);
	while (node) {
		iova = to_iova_node(node);
		spin_unlock_irqrestore(&iovad->iova_rbtree_lock, flags);

		if (iova != &iovad->anchor)
			__free_iova_mem(iova);

		spin_lock_irqsave(&iovad->iova_rbtree_lock, flags);
		rb_erase(node, &iovad->rbroot);
		node = rb_first(&iovad->rbroot);
	}
	spin_unlock_irqrestore(&iovad->iova_rbtree_lock, flags);
}

int camb_generic_iova_init(struct camb_iova_pool *pool)
{
	struct camb_iova_domain *iovad;

	pool->base       = GENERIC_IOVA_BASE;
	pool->total_size = GENERIC_IOVA_SIZE;
	pool->shift      = GENERIC_MINIMUM_SHIFT;

	iovad = cn_kzalloc(sizeof(struct camb_iova_domain), GFP_KERNEL);
	if (!iovad) {
		cn_dev_err("alloc buffer for iova allocator failed");
		return -ENOMEM;
	}

	camb_create_iova_allocator(iovad, pool->base >> pool->shift,
					(pool->base + pool->total_size) >> pool->shift,
					1UL << pool->shift);

	cn_dev_info("generic mem iova pool Init:(%#llx) start:%#llx, size:%#lx, shift:%d", (u64)pool,
				pool->base, pool->total_size, pool->shift);
	pool->allocator = (void *)iovad;
	return 0;
}

void camb_generic_iova_exit(struct camb_iova_pool *iova_pool)
{
	camb_destroy_iova_allocator((struct camb_iova_domain *)iova_pool->allocator);
	cn_kfree(iova_pool->allocator);
	iova_pool->allocator = NULL;
}

