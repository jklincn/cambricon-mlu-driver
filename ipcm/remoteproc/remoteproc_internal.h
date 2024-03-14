/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Remote processor framework
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 * Copyright (C) 2011 Google, Inc.
 *
 * Ohad Ben-Cohen <ohad@wizery.com>
 * Brian Swetland <swetland@google.com>
 */

#ifndef REMOTEPROC_INTERNAL_H
#define REMOTEPROC_INTERNAL_H

#include <linux/irqreturn.h>
#include <linux/firmware.h>
#include <linux/device.h>

#include "../include/ipcm_common.h"

struct rproc;

struct rproc_debug_trace {
	struct rproc *rproc;
	struct dentry *tfile;
	struct list_head node;
	struct rproc_mem_entry trace_mem;
};

/* from remoteproc_core.c */
void rproc_release(struct kref *kref);
irqreturn_t rproc_vq_interrupt(struct rproc *rproc, int vq_id);
void rproc_vdev_release(struct kref *ref);

/* from remoteproc_virtio.c */
int rproc_add_virtio_dev(struct rproc_vdev *rvdev, int id);
int rproc_remove_virtio_dev(struct device *dev, void *data);

/* from remoteproc_vhost.c */
int rproc_add_vhost_dev(struct rproc_vdev *rvdev, int id);
int rproc_remove_vhost_dev(struct device *dev, void *data);

/* from remoteproc_debugfs.c */
void rproc_remove_trace_file(struct dentry *tfile);
struct dentry *rproc_create_trace_file(const char *name, struct rproc *rproc,
				       struct rproc_debug_trace *trace);
void rproc_delete_debug_dir(struct rproc *rproc);
void rproc_create_debug_dir(struct rproc *rproc);
void rproc_init_debugfs(void);
void rproc_exit_debugfs(void);

/* from remoteproc_sysfs.c */
extern struct class rproc_class;
int rproc_init_sysfs(void);
void rproc_exit_sysfs(void);

void rproc_free_vring(struct rproc_vring *rvring);
int rproc_alloc_vring(struct rproc_vdev *rvdev, int i);

void *rproc_da_to_va(struct rproc *rproc, u64 da, size_t len);
phys_addr_t rproc_va_to_pa(struct rproc *rproc, void *cpu_addr);
int rproc_trigger_recovery(struct rproc *rproc);

int rproc_elf_sanity_check(struct rproc *rproc, const struct firmware *fw);
u64 rproc_elf_get_boot_addr(struct rproc *rproc, const struct firmware *fw);
int rproc_elf_load_segments(struct rproc *rproc, const struct firmware *fw);
int rproc_elf_load_rsc_table(struct rproc *rproc, const struct firmware *fw);
struct resource_table *rproc_elf_find_loaded_rsc_table(struct rproc *rproc,
						       const struct firmware *fw);
struct rproc_mem_entry *
rproc_find_carveout_by_name(struct rproc *rproc, const char *name, ...);

static inline int rproc_prepare_device(struct rproc *rproc)
{
	if (rproc->ops->prepare)
		return rproc->ops->prepare(rproc);

	return 0;
}

static inline int rproc_unprepare_device(struct rproc *rproc)
{
	if (rproc->ops->unprepare)
		return rproc->ops->unprepare(rproc);

	return 0;
}

static inline
int rproc_fw_sanity_check(struct rproc *rproc, const struct firmware *fw)
{
	if (rproc->ops->sanity_check)
		return rproc->ops->sanity_check(rproc, fw);

	return 0;
}

static inline
u64 rproc_get_boot_addr(struct rproc *rproc, const struct firmware *fw)
{
	if (rproc->ops->get_boot_addr)
		return rproc->ops->get_boot_addr(rproc, fw);

	return 0;
}

static inline
int rproc_load_segments(struct rproc *rproc, const struct firmware *fw)
{
	if (rproc->ops->load)
		return rproc->ops->load(rproc, fw);

	return -EINVAL;
}

static inline int rproc_parse_fw(struct rproc *rproc, const struct firmware *fw)
{
	if (rproc->ops->parse_fw)
		return rproc->ops->parse_fw(rproc, fw);

	return 0;
}

static inline
int rproc_handle_rsc(struct rproc *rproc, u32 rsc_type, void *rsc, int offset,
		     int avail)
{
	if (rproc->ops->handle_rsc)
		return rproc->ops->handle_rsc(rproc, rsc_type, rsc, offset,
					      avail);

	return RSC_IGNORED;
}

static inline
struct resource_table *rproc_find_loaded_rsc_table(struct rproc *rproc,
						   const struct firmware *fw)
{
	if (rproc->ops->find_loaded_rsc_table)
		return rproc->ops->find_loaded_rsc_table(rproc, fw);

	return NULL;
}

static inline
bool rproc_u64_fit_in_size_t(u64 val)
{
	if (sizeof(size_t) == sizeof(u64))
		return true;

	return (val <= (size_t) -1);
}

/* cambricon */
#define QUIRK_AVOID_VF_READ_INBOUND            (1)
#define QUIRK_SRIOV_NO_SUPPORT_DATA_OUTBOUND   (2)
#define QUIRK_AVOID_ACPU_READ_DATA_OUTBOUND    (4)

static inline
int rproc_get_role(struct rproc *rproc)
{
	if (rproc->ops->get_role)
		return rproc->ops->get_role(rproc);
	/* master default */
	return 0;
}

static inline
bool rproc_get_outbound(struct rproc *rproc)
{
	if (rproc->ops->get_outbound)
		return rproc->ops->get_outbound(rproc);
	/* disable default */
	return 0;
}

static inline
bool rproc_is_vf(struct rproc *rproc)
{
	if (rproc->ops->is_vf)
		return rproc->ops->is_vf(rproc);
	/* pf default */
	return false;
}

static inline
bool rproc_get_data_outbound(struct rproc *rproc)
{
	if (rproc->ops->get_data_outbound)
		return rproc->ops->get_data_outbound(rproc);
	/* disable default */
	return 0;
}

static inline
int rproc_get_rvdev_index(struct rproc *rproc)
{
	if (rproc->ops->get_rvdev_index)
		return rproc->ops->get_rvdev_index(rproc);
	/* pf default */
	return 0;
}

static inline
int rproc_get_quirks(struct rproc *rproc)
{
	if (rproc->ops->get_quirks)
		return rproc->ops->get_quirks(rproc);
	/* no quirks default */
	return 0;
}
/* cambricon */

#endif /* REMOTEPROC_INTERNAL_H */
