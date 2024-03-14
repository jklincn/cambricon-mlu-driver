#include "cndrv_debug.h"
#include "cndrv_mm.h"
#include "camb_range_tree.h"

/** Cambricon VMM range tree(rbtree + sorted list) operations **/
static struct range_tree_node_t *__get_range_node(struct rb_node *rb_node)
{
	return rb_entry(rb_node, struct range_tree_node_t, rb_node);
}

static int __range_nodes_overlap(struct range_tree_node_t *node1,
						struct range_tree_node_t *node2)
{
	return (node1->end >= node2->start) && (node2->end >= node1->start);
}

static struct range_tree_node_t *
__range_node_find(struct range_tree_t *tree, dev_addr_t addr,
				  struct range_tree_node_t **parent,
				  struct range_tree_node_t **next)
{
	struct rb_node *rb_node = tree->rb_root.rb_node;
	struct range_tree_node_t *node = NULL;
	struct range_tree_node_t *__parent = NULL;

	while (rb_node) {
		node = __get_range_node(rb_node);
		if (addr < node->start)
			rb_node = rb_node->rb_left;
		else if (addr > node->end)
			rb_node = rb_node->rb_right;
		else
			break;

		__parent = node;
	}

	if (!rb_node) node = NULL;

	if (parent) *parent = __parent;

	if (!next)
		return node;

	*next = NULL;
	if (node) {
		*next = camb_range_tree_next(tree, node);
	} else if (__parent) {
		*next = (__parent->start > addr) ? __parent :
			camb_range_tree_prev(tree, __parent);
	}

	return node;
}

void camb_range_tree_init(struct range_tree_t *tree)
{
	tree->rb_root = RB_ROOT;
	INIT_LIST_HEAD(&tree->lhead);
}

int camb_range_tree_insert(struct range_tree_t *tree,
			struct range_tree_node_t *node)
{
	struct range_tree_node_t *match, *parent, *prev, *next;

	BUG_ON(node->start > node->end);

	match = __range_node_find(tree, node->start, &parent, NULL);
	if (match)
		return -EBUSY;

	if (!parent) {
		rb_link_node(&node->rb_node, NULL, &tree->rb_root.rb_node);
		list_add(&node->lnode, &tree->lhead);
		goto exit;
	}

	if (__range_nodes_overlap(node, parent))
		return -EBUSY;

	if (node->start < parent->start) {
		prev = camb_range_tree_prev(tree, parent);
		if (prev)
			BUG_ON(__range_nodes_overlap(node, prev));

		rb_link_node(&node->rb_node, &parent->rb_node, &parent->rb_node.rb_left);
		list_add_tail(&node->lnode, &parent->lnode);
	} else {
		next = camb_range_tree_next(tree, parent);
		if (next && __range_nodes_overlap(node, next))
			return -EBUSY;

		rb_link_node(&node->rb_node, &parent->rb_node, &parent->rb_node.rb_right);
		list_add(&node->lnode, &parent->lnode);
	}

exit:
	rb_insert_color(&node->rb_node, &tree->rb_root);
	return 0;
}

struct range_tree_node_t *
camb_range_tree_search(struct range_tree_t *tree, dev_addr_t addr)
{
	return __range_node_find(tree, addr, NULL, NULL);
}

struct range_tree_node_t *
camb_range_tree_iter_first(struct range_tree_t *tree, dev_addr_t start,
				dev_addr_t end)
{
	struct range_tree_node_t *node, *next;

	WARN(start > end, "invalid parameters(start:%#llx, end:%#llx)", start, end);

	node = __range_node_find(tree, start, NULL, &next);
	if (node)
		return node;

	if (next) {
		/* Sanity checks, which shouldn't happened. */
		BUG_ON(start >= next->start);
		if (camb_range_tree_prev(tree, next))
			BUG_ON(camb_range_tree_prev(tree, next)->end >= start);

		if (next->start <= end)
			return next;
	}

	return NULL;
}
