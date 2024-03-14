/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#ifndef __CAMBRICON_RANGE_TREE_H_
#define __CAMBRICON_RANGE_TREE_H_

#include <linux/list.h>
#include <linux/rbtree.h>

/* NOTE: Some interfaces maybe not used in source files */
#define CAMB_STATIC __attribute__((unused)) static

struct range_tree_t {
	struct rb_root rb_root;
	struct list_head lhead;
};

/* NOTE: end = start + size - 1 */
struct range_tree_node_t {
	dev_addr_t start;
	dev_addr_t end;
	struct rb_node rb_node;
	struct list_head lnode;
};

void camb_range_tree_init(struct range_tree_t *tree);

int camb_range_tree_insert(struct range_tree_t *tree,
		struct range_tree_node_t *node);

CAMB_STATIC void
camb_range_tree_delete(struct range_tree_t *tree, struct range_tree_node_t *node)
{
	rb_erase(&node->rb_node, &tree->rb_root);
	list_del(&node->lnode);
}

struct range_tree_node_t *
camb_range_tree_search(struct range_tree_t *tree, dev_addr_t addr);

static inline int
camb_list_is_first(const struct list_head *list, const struct list_head *head)
{
	return list->prev == head;
}

static inline int
camb_list_is_last(const struct list_head *list, const struct list_head *head)
{
	return list->next == head;
}

CAMB_STATIC struct range_tree_node_t *
camb_range_tree_prev(struct range_tree_t *tree, struct range_tree_node_t *node)
{
	if (camb_list_is_first(&node->lnode, &tree->lhead))
		return NULL;

	return list_prev_entry(node, lnode);
}

CAMB_STATIC struct range_tree_node_t *
camb_range_tree_next(struct range_tree_t *tree, struct range_tree_node_t *node)
{
	if (camb_list_is_last(&node->lnode, &tree->lhead))
		return NULL;

	return list_next_entry(node, lnode);
}

CAMB_STATIC int camb_range_tree_empty(struct range_tree_t *tree)
{
	return list_empty(&tree->lhead);
}

CAMB_STATIC struct range_tree_node_t *
camb_range_tree_first(struct range_tree_t *tree)
{
	return list_first_entry_or_null(&tree->lhead, struct range_tree_node_t, lnode);
}

CAMB_STATIC unsigned long camb_range_tree_node_size(struct range_tree_node_t *node)
{
	return node->end - node->start + 1;
}

struct range_tree_node_t *
camb_range_tree_iter_first(struct range_tree_t *tree, dev_addr_t start,
			dev_addr_t end);

CAMB_STATIC struct range_tree_node_t *
camb_range_tree_iter_next(struct range_tree_t *tree,
			struct range_tree_node_t *node, dev_addr_t end)
{
	struct range_tree_node_t *next = camb_range_tree_next(tree, node);

	if (next && next->start <= end)
		return next;

	return NULL;
}

#define camb_range_tree_for_each(node, tree)  \
	list_for_each_entry((node), &(tree)->lhead, lnode)

#define camb_range_tree_for_each_safe(node, next, tree)  \
	list_for_each_entry_safe((node), (next), &(tree)->lhead, lnode)

#define camb_range_tree_for_each_in(node, tree, start, end) \
	for ((node) = camb_range_tree_iter_first((tree), (start), (end)); \
		 (node); \
		 (node) = camb_range_tree_iter_next((tree), (node), (end)))


#define CAMB_RANGE_TREE_DECLARE_CALLBACKS(rtname, rootstruct, rootfield, \
				rtstruct, rtfield, rbcontainer, iscontigous) \
CAMB_STATIC rtstruct *  \
rtname##_iter_first(rootstruct *root, unsigned long start, unsigned long end) \
{ \
	struct range_tree_t *range_tree = &root->rootfield; \
	struct range_tree_node_t *node = NULL; \
	node  = camb_range_tree_iter_first(range_tree, start, end); \
	return node ? rbcontainer(node) : NULL; \
} \
CAMB_STATIC rtstruct *  \
rtname##_iter_next(rootstruct *root, rtstruct *curr, unsigned long end) \
{ \
	struct range_tree_t *range_tree = &root->rootfield; \
	struct range_tree_node_t *node = NULL; \
	if (!curr) return NULL; \
	node  = camb_range_tree_iter_next(range_tree, &curr->rtfield, end); \
	if (iscontigous) { \
		return ((node) && (node->start == curr->rtfield.end + 1)) ? rbcontainer(node) : NULL; \
	} else { \
		return node ? rbcontainer(node) : NULL; \
	} \
} \
CAMB_STATIC unsigned long rtname##_size(rtstruct *curr) \
{ \
	return camb_range_tree_node_size(&curr->rtfield); \
}

#endif /* __CAMBRICON_RANGE_TREE_H_ */
