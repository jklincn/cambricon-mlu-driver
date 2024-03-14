/*
 * include/cndrv_os_compat.h
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

#ifndef __CNDRV_OS_COMPAT_H__
#define __CNDRV_OS_COMPAT_H__

#include <linux/version.h>
#ifndef CONFIG_CNDRV_EDGE
#include "functions.h"
#include "generic.h"
#include "macros.h"
#include "symbols.h"
#include "types.h"
#endif

#ifndef READ_ONCE
#define READ_ONCE(var) (*((volatile typeof(var) *) (&(var))))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(var, val) (*((volatile typeof(val) *)(&(var))) = (val))
#endif

#if !defined(llist_entry)
#define llist_entry(ptr, type, member)	\
	container_of(ptr, type, member)
#endif

#if !defined(member_address_is_nonnull)
#define member_address_is_nonnull(ptr, member)	\
	((uintptr_t)(ptr) + offsetof(typeof(*(ptr)), member) != 0)
#endif

#if !defined(llist_for_each_entry_safe)
#define llist_for_each_entry_safe(pos, n, node, member)	\
	for (pos = llist_entry((node), typeof(*pos), member);	\
			member_address_is_nonnull(pos, member) &&	\
			(n = llist_entry(pos->member.next, typeof(*n), member), true);	\
			pos = n)
#endif

#ifndef ioremap_nocache
#define ioremap_nocache ioremap
#endif

#if !defined(CONFIG_CNDRV_EDGE) && \
	!defined(CN_PRECOMPILE_LLIST_REVERSE_ORDER)
	#include <linux/llist.h>
	static inline
	struct llist_node *llist_reverse_order(struct llist_node *head)
	{
		struct llist_node *new_head = NULL;

		while (head) {
			struct llist_node *tmp = head;
			head = head->next;
			tmp->next = new_head;
			new_head = tmp;
		}

		return new_head;
	}
#endif


#endif /* __CNDRV_OS_COMPAT_H__ */
