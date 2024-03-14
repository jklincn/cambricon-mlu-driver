#ifndef __SMLU_RBTREE_H__
#define __SMLU_RBTREE_H__

#define SEARCH_RB_NODE_OPS(info_struct, active_ns, name) \
	static struct info_struct *search_##name##_rb_node(struct rb_root *root,\
									struct pid_namespace *ns) \
{	\
	struct rb_node *__this_node = root->rb_node;	\
	struct info_struct *__this_info = NULL;			\
	while (__this_node) {							\
		__this_info = rb_entry(__this_node, struct info_struct, ns_node);		\
		if (__this_info->active_ns > ns)		\
			__this_node = __this_node->rb_left;		\
		else if ((__this_info->active_ns) < ns) \
			__this_node = __this_node->rb_right;	\
		else										\
			return __this_info;						\
	}								\
	return NULL;					\
}

#define INSERT_RB_NODE_OPS(info_struct, active_ns, name)	\
	static void insert_##name##_rb_node(struct rb_root *root,	\
										struct info_struct *info)	\
{	\
	struct rb_node *__parent = NULL;		\
	struct rb_node **__new = NULL;			\
	__new = &(root->rb_node);				\
	while (*__new) {						\
		__parent = *__new;					\
		if (info->active_ns < rb_entry(*__new, struct info_struct,	\
						ns_node)->active_ns) {	\
			__new = &__parent->rb_left;		\
		} else {							\
			__new = &__parent->rb_right;	\
		}									\
	}										\
	rb_link_node(&info->ns_node, __parent, __new);	\
	rb_insert_color(&info->ns_node, root);	\
}

#define DELETE_RB_NODE_OPS(info_struct, name) \
	static void delete_##name##_rb_node(struct rb_root *root,	\
							struct info_struct *info)	\
{	\
	rb_erase(&info->ns_node, root);	\
	RB_CLEAR_NODE(&info->ns_node);	\
}

#define SEARCH_INFO_OPS(parent_struct, member_lock, member_root, info_struct, name) \
	static struct info_struct *search_##name(struct parent_struct *data,	\
											struct pid_namespace *ns) \
{		\
	struct info_struct *info = NULL;	\
	info = search_##name##_rb_node(&data->member_root, ns);	\
	return info;	\
}

#define INSERT_INFO_OPS(parent_struct, member_lock, member_root, info_struct, name) \
	static void insert_##name(struct parent_struct *data,	\
							struct info_struct *info)	\
{	\
	insert_##name##_rb_node(&data->member_root, info);	\
}

#define DELETE_INFO_OPS(parent_struct, member_lock, member_root, info_struct, name) \
	static void delete_##name(struct parent_struct *data,	\
								struct info_struct *info)	\
{	\
	if (info) {	\
		delete_##name##_rb_node(&data->member_root, info);	\
	}	\
}

#define tree_traverse_and_operate(rb_root, info_struct, block) { \
	struct info_struct *post = NULL; \
	struct rb_node *p = NULL; \
	int ret = 0; \
	p = rb_first(&rb_root); \
	while (p != NULL) { \
		post = rb_entry(p, struct info_struct, ns_node); \
		block; \
		if (ret) { \
			p = rb_first(&rb_root); \
		} else { \
			p = rb_next(p); \
		} \
		ret = 0; \
	} \
}

#endif /* __SMLU_RBTREE_H__ */
