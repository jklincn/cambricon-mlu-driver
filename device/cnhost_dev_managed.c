/*
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
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
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <linux/string.h>

#include "cndrv_debug.h"

#include "device/cnhost_dev_managed.h"

struct devm_node {
	struct list_head	entry;
	devm_res_release_t	release;
	char		*name;
	size_t			size;
};

struct devm_res {
	struct devm_node		node;
	u8 __aligned(ARCH_KMALLOC_MINALIGN) data[];
};

static void free_dr(struct devm_res *dr)
{
	kfree(dr->node.name);
	cn_kfree(dr);
}

void cnhost_devm_release(struct cnhost_device *dev)
{
	struct devm_res *dr, *tmp;

	cn_dev_debug("devm_res release begin\n");
	list_for_each_entry_safe(dr, tmp, &dev->managed.resources, node.entry) {
		cn_dev_debug("REL %px %s (%zu bytes)\n",
			       dr, dr->node.name, dr->node.size);

		if (dr->node.release)
			dr->node.release(dev, dr->node.size ? *(void **)&dr->data : NULL);

		list_del(&dr->node.entry);
		free_dr(dr);
	}
	cn_dev_debug("devm_res release end\n");
}

static __always_inline struct devm_res * alloc_dr(devm_res_release_t release,
						size_t size, gfp_t gfp, int nid)
{
	size_t tot_size;
	struct devm_res *dr;

	if (sizeof(*dr) > ULONG_MAX - size)
		return NULL;

	tot_size = sizeof(*dr) +  size;

	dr = cn_kmalloc(tot_size, gfp);
	if (unlikely(!dr))
		return NULL;

	memset(dr, 0, offsetof(struct devm_res, data));

	INIT_LIST_HEAD(&dr->node.entry);
	dr->node.release = release;
	dr->node.size = size;

	return dr;
}

static void del_dr(struct cnhost_device *dev, struct devm_res *dr)
{
	list_del_init(&dr->node.entry);

	cn_dev_debug("DEL %px %s (%lu bytes)\n",
		       dr, dr->node.name, (unsigned long) dr->node.size);
}

static void add_dr(struct cnhost_device *dev, struct devm_res *dr)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->managed.lock, flags);
	list_add(&dr->node.entry, &dev->managed.resources);
	spin_unlock_irqrestore(&dev->managed.lock, flags);

	cn_dev_debug("ADD %px %s (%lu bytes)\n",
		       dr, dr->node.name, (unsigned long) dr->node.size);
}

void cnhost_devm_add_final_kfree(struct cnhost_device *dev, void *container)
{
	WARN_ON(dev->managed.final_kfree);
	WARN_ON(dev < (struct cnhost_device *) container);
	WARN_ON(dev + 1 > (struct cnhost_device *) (container + ksize(container)));
	dev->managed.final_kfree = container;
}

int __cnhost_devm_add_action(struct cnhost_device *dev,
		      devm_res_release_t action,
		      void *data, const char *name)
{
	struct devm_res *dr;
	void **void_ptr;

	dr = alloc_dr(action, data ? sizeof(void*) : 0,
		      GFP_KERNEL | __GFP_ZERO,
		      dev_to_node(dev->dev));
	if (!dr) {
		cn_dev_err("failed to add action %s for %px\n",
			       name, data);
		return -ENOMEM;
	}

	dr->node.name = kstrdup(name, GFP_KERNEL);
	if (data) {
		void_ptr = (void **)&dr->data;
		*void_ptr = data;
	}

	add_dr(dev, dr);

	return 0;
}

int __cnhost_devm_add_action_or_reset(struct cnhost_device *dev,
			       devm_res_release_t action,
			       void *data, const char *name)
{
	int ret;

	ret = __cnhost_devm_add_action(dev, action, data, name);
	if (ret)
		action(dev, data);

	return ret;
}

void *cnhost_devm_kmalloc(struct cnhost_device *dev, size_t size, gfp_t gfp)
{
	struct devm_res *dr;

	dr = alloc_dr(NULL, size, gfp, dev_to_node(dev->dev));
	if (!dr) {
		cn_dev_err("failed to allocate %zu bytes, %u flags\n",
			       size, gfp);
		return NULL;
	}
	dr->node.name = kstrdup("kmalloc", GFP_KERNEL);

	add_dr(dev, dr);

	return dr->data;
}

char *cnhost_devm_kstrdup(struct cnhost_device *dev, const char *s, gfp_t gfp)
{
	size_t size;
	char *buf;

	if (!s)
		return NULL;

	size = strlen(s) + 1;
	buf = cnhost_devm_kmalloc(dev, size, gfp);
	if (buf)
		memcpy(buf, s, size);
	return buf;
}

void cnhost_devm_kfree(struct cnhost_device *dev, void *data)
{
	struct devm_res *dr_match = NULL, *dr;
	unsigned long flags;

	if (!data)
		return;

	spin_lock_irqsave(&dev->managed.lock, flags);
	list_for_each_entry(dr, &dev->managed.resources, node.entry) {
		if (dr->data == data) {
			dr_match = dr;
			del_dr(dev, dr_match);
			break;
		}
	}
	spin_unlock_irqrestore(&dev->managed.lock, flags);

	if (WARN_ON(!dr_match))
		return;

	free_dr(dr_match);
}
