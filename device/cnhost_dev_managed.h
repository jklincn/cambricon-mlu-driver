// SPDX-License-Identifier: GPL-2.0

#ifndef _CNHOST_DEV_MANAGED_H_
#define _CNHOST_DEV_MANAGED_H_

#include <linux/gfp.h>
#include <linux/types.h>

struct cnhost_device;

typedef void (*devm_res_release_t)(struct cnhost_device *dev, void *res);

#define cnhost_devm_add_action(dev, action, data) \
	__cnhost_devm_add_action(dev, action, data, #action)

int __must_check __cnhost_devm_add_action(struct cnhost_device *dev,
				   devm_res_release_t action,
				   void *data, const char *name);

#define cnhost_devm_add_action_or_reset(dev, action, data) \
	__cnhost_devm_add_action_or_reset(dev, action, data, #action)

int __must_check __cnhost_devm_add_action_or_reset(struct cnhost_device *dev,
					    devm_res_release_t action,
					    void *data, const char *name);

void *cnhost_devm_kmalloc(struct cnhost_device *dev, size_t size, gfp_t gfp);


static inline void *cnhost_devm_kzalloc(struct cnhost_device *dev, size_t size, gfp_t gfp)
{
	return cnhost_devm_kmalloc(dev, size, gfp | __GFP_ZERO);
}

static inline void *cnhost_devm_kmalloc_array(struct cnhost_device *dev,
				       size_t n, size_t size, gfp_t flags)
{
	size_t bytes;

	if (size == 0 || n > ULONG_MAX / size)
		return NULL;
	bytes = n * size;

	return cnhost_devm_kmalloc(dev, bytes, flags);
}

static inline void *cnhost_devm_kcalloc(struct cnhost_device *dev,
				 size_t n, size_t size, gfp_t flags)
{
	return cnhost_devm_kmalloc_array(dev, n, size, flags | __GFP_ZERO);
}

char *cnhost_devm_kstrdup(struct cnhost_device *dev, const char *s, gfp_t gfp);

void cnhost_devm_kfree(struct cnhost_device *dev, void *data);

void cnhost_devm_release(struct cnhost_device *dev);

void cnhost_devm_add_final_kfree(struct cnhost_device *dev, void *container);

#endif
