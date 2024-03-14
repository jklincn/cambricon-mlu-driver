/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _IPCM_COMMON_H
#define _IPCM_COMMON_H

#include <linux/genalloc.h>
#include <linux/device.h>

#define  POOL_PAGE_SHIFT    12

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#ifndef BIT_ULL
#define BIT_ULL(nr) (1ULL << (nr))
#endif

#ifndef __ATTR
#define __ATTR(_name, _mode, _show, _store) {                           \
		.attr = {.name = __stringify(_name),                            \
				.mode = _mode},             \
		.show   = _show,                                                \
		.store  = _store,                                               \
}
#endif

#ifndef __ATTR_RO
#define __ATTR_RO(_name) {                                              \
		.attr   = { .name = __stringify(_name), .mode = 0444 },      \
		.show   = _name##_show,                                         \
}
#endif

#ifndef __ATTR_WO
#define __ATTR_WO(_name) {                                              \
		.attr   = { .name = __stringify(_name), .mode = 0200 },      \
		.store  = _name##_store,                                        \
}
#endif

#ifndef __ATTR_RW
#define __ATTR_RW(_name) __ATTR(_name, 0644,             \
						_name##_show, _name##_store)
#endif

#ifndef DEVICE_ATTR
#define DEVICE_ATTR(_name, _mode, _show, _store) \
		struct device_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store)
#endif

#ifndef DEVICE_ATTR_RW
#define DEVICE_ATTR_RW(_name) \
		struct device_attribute dev_attr_##_name = __ATTR_RW(_name)
#endif

#ifndef DEVICE_ATTR_RO
#define DEVICE_ATTR_RO(_name) \
		struct device_attribute dev_attr_##_name = __ATTR_RO(_name)
#endif

#ifndef DEVICE_ATTR_WO
#define DEVICE_ATTR_WO(_name) \
		struct device_attribute dev_attr_##_name = __ATTR_WO(_name)
#endif

#ifndef __ATTRIBUTE_GROUPS
#define __ATTRIBUTE_GROUPS(_name)                               \
static const struct attribute_group *_name##_groups[] = {       \
		&_name##_group,                                         \
		NULL,                                                   \
}
#endif

#ifndef ATTRIBUTE_GROUPS
#define ATTRIBUTE_GROUPS(_name)                                 \
static const struct attribute_group _name##_group = {           \
		.attrs = _name##_attrs,                                 \
};                                                              \
__ATTRIBUTE_GROUPS(_name)
#endif

#ifndef struct_size
#define struct_size(p, member, count) (((count) * sizeof(*(p)->member)) + sizeof(*(p)))
#endif

#ifndef READ_ONCE
#define READ_ONCE(var) (*((volatile typeof(var) *) (&(var))))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(var, val) (*((volatile typeof(val) *)(&(var))) = (val))
#endif

#ifndef ioremap_nocache
#define ioremap_nocache ioremap
#endif

#ifndef WITHOUT_DEV
#define WITHOUT_DEV 0
#endif

/* Barriers for virtual machine guests when talking to an SMP host */
#ifndef virt_mb
#define virt_mb() mb() /* barrier */
#endif

#ifndef virt_rmb
#define virt_rmb() rmb() /* barrier */
#endif

#ifndef virt_wmb
#define virt_wmb() wmb() /* barrier */
#endif

#ifndef virt_store_mb
#define virt_store_mb(var, value) /* barrier */ \
	do { \
		WRITE_ONCE(var, value); \
		mb();  /* barrier */ \
	} while (0)
#endif

#ifndef dma_rmb
#define dma_rmb() rmb() /* barrier */
#endif

#ifndef dma_wmb
#define dma_wmb() wmb() /* barrier */
#endif

#ifndef CONFIG_GENERIC_ALLOCATOR
#ifdef IN_CNDRV_HOST
#include "cndrv_genalloc.h"

#undef gen_pool
#undef gen_pool_create
#undef gen_pool_destroy
#undef gen_pool_alloc
#undef gen_pool_free
#undef gen_pool_add_virt
#undef gen_pool_virt_to_phys

#define gen_pool cn_gen_pool
#define gen_pool_create cn_gen_pool_create
#define gen_pool_destroy cn_gen_pool_destroy
#define gen_pool_alloc cn_gen_pool_alloc
#define gen_pool_free cn_gen_pool_free
#define gen_pool_add_virt cn_gen_pool_add_virt
#define gen_pool_virt_to_phys cn_gen_pool_virt_to_phys
#endif
#endif

static inline struct gen_pool *cambr_gen_pool_create(unsigned long virt,
				   phys_addr_t phys, size_t size)
{
	struct gen_pool *pool = NULL;

	pool = gen_pool_create(POOL_PAGE_SHIFT, -1);
	if (!pool) {
		pr_err("gen_pool_create() failed!\n");
	} else {
		pr_debug("[genpool] va(0x%lx), pa(0x%llx), size(%zu)\n",
				virt, phys, size);
		if (gen_pool_add_virt(pool, virt, phys, size, -1)) {
			pr_err("failed to register genpool!\n");
			gen_pool_destroy(pool);
			return NULL;
		}
	}
	return pool;
}

static inline void cambr_gen_pool_destroy(struct gen_pool *pool)
{
	gen_pool_destroy(pool);
}

static inline void *cambr_gen_pool_dma_alloc(struct gen_pool *pool, size_t size, dma_addr_t *dma)
{
	unsigned long vaddr;

	if (!pool)
		return NULL;

	vaddr = gen_pool_alloc(pool, size);
	if (!vaddr)
		return NULL;

	if (dma)
		*dma = gen_pool_virt_to_phys(pool, vaddr);

	return (void *)vaddr;
}

static inline void cambr_gen_pool_dma_free(struct gen_pool *pool, size_t size, unsigned long vaddr)
{
	if (!pool)
		return;

	gen_pool_free(pool, vaddr, size);
}

#endif /* _IPCM_COMMON_H */
