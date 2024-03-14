/*
 * sbts/sbts_set.h
 *
 * NOTICE:
 * Copyright (C) 2021 Cambricon, Inc. All rights reserved.
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
 */

#ifndef __SBTS_SET_H
#define __SBTS_SET_H

#include <linux/list.h>
#include <linux/rbtree.h>

struct sbts_set_container_st {
	struct list_head head;
	struct rb_root root;
};

struct sbts_set_iter_st {
	struct list_head entry;
	struct rb_node node;
};

#define __SBTS_SET_CONTAINER_INIT(name)		\
{						\
	.head = LIST_HEAD_INIT((name).head),	\
	.root = RB_ROOT,			\
}

#define DEFINE_SBTS_SET_CONTAINER(name)	\
	struct sbts_set_container_st name = __SBTS_SET_CONTAINER_INIT(name)

static inline void sbts_set_container_init(struct sbts_set_container_st *container)
{
	*container = (struct sbts_set_container_st)
			__SBTS_SET_CONTAINER_INIT(*container);
}

/* list helper */
#define sbts_set_list_head(container) (&(container)->head)
#define sbts_set_list_first(container) ((container)->head.next)

#define sbts_set_list_first_entry(container, type, member) \
	sbts_set_list_iter_entry(sbts_set_list_first(container), type, member)

#define sbts_set_list_next_entry(obj, member) \
	sbts_set_list_iter_entry((obj)->member.entry.next, typeof(*obj), member)

#define sbts_set_list_iter_entry(list, type, member) \
	sbts_set_entry(sbts_set_list_iter(list), type, member)

#define sbts_set_list_iter(ptr) \
	sbts_set_entry(ptr, struct sbts_set_iter_st, entry)

/* rb-tree helper */
#define sbts_set_tree_root(container) ((container)->root.rb_node)

#define sbts_set_tree_iter_entry(node, type, member) \
	sbts_set_entry(sbts_set_tree_iter(node), type, member)

#define sbts_set_tree_iter(ptr) \
	sbts_set_entry(ptr, struct sbts_set_iter_st, node)

/* container-of macro */
#define sbts_set_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define sbts_set_find(container, obj, cmp, member) \
({ \
	typeof((container) + 1) __container = (container); \
	typeof((obj) + 1) iter = NULL; \
	struct rb_node *n = sbts_set_tree_root(__container); \
	int res = 0; \
	int err = -EINVAL; \
	while (n) { \
		iter = sbts_set_tree_iter_entry(n, typeof(*iter), member); \
		res = cmp(obj, iter); \
		if (res < 0) { \
			n = n->rb_left; \
		} else if (res > 0) { \
			n = n->rb_right; \
		} else { \
			err = 0; \
			break; \
		} \
	} \
	err ? NULL : iter; \
})

#define sbts_set_insert(container, obj, cmp, member) \
({ \
	typeof((container) + 1) __container = (container); \
	typeof((obj) + 1) __obj = (obj); \
	typeof((obj) + 1) iter = NULL; \
	struct rb_node **p = &sbts_set_tree_root(__container); \
	struct rb_node *parent = NULL; \
	int res = 0; \
	int err = 0; \
	while (*p) { \
		parent = *p; \
		iter = sbts_set_tree_iter_entry(parent, typeof(*iter), member); \
		res = cmp(obj, iter); \
		if (res < 0) { \
			p = &parent->rb_left; \
		} else if (res > 0) { \
			p = &parent->rb_right; \
		} else { \
			err = -EINVAL; \
			break; \
		} \
	} \
	if (!err) { \
		rb_link_node(&__obj->member.node, parent, p); \
		rb_insert_color(&__obj->member.node, &__container->root); \
		list_add(&__obj->member.entry, &__container->head); \
	} \
	err ? NULL : __obj; \
})

#define sbts_set_erase(container, obj, member) \
(void)({ \
	typeof((container) + 1) __container = (container); \
	typeof((obj) + 1) __obj = (obj); \
	rb_erase(&__obj->member.node, &__container->root); \
	RB_CLEAR_NODE(&__obj->member.node); \
	list_del_init(&__obj->member.entry); \
})

#define sbts_set_is_empty(container) list_empty(&(container)->head)

#define sbts_set_for_each_entry_safe(pos, n, container, member) \
	for (pos = sbts_set_list_first_entry(container, typeof(*pos), member), \
			n = sbts_set_list_next_entry(pos, member); \
			&(pos->member.entry) != sbts_set_list_head(container); \
			pos = n, n = sbts_set_list_next_entry(n, member))

#define sbts_set_for_each_entry(pos, container, member) \
	for (pos = sbts_set_list_first_entry(container, typeof(*pos), member); \
			&(pos->member.entry) != sbts_set_list_head(container); \
			pos = sbts_set_list_next_entry(pos, member))


#endif /* __SBTS_SET_H */
