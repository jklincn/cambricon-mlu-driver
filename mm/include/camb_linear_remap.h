/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_LINEAR_REMAP_H_
#define __CAMBRICON_LINEAR_REMAP_H_

enum {
	LINEAR_MODE_DISABLE = 0x0,
	LINEAR_MODE_DEFAULT = 0x1,
	LINEAR_MODE_ENABLE  = 0x2,
};

struct linear_info_t;
static inline const char *__linear_mode_str(struct linear_info_t *info)
{
	if (!info->is_support) return "UNSUPPORT";

	switch (info->mode) {
	case LINEAR_MODE_DISABLE: return "DISABLE";
	case LINEAR_MODE_DEFAULT:   return "DEFAULT";
	case LINEAR_MODE_ENABLE:  return "ENABLE";
	default: break;
	}
	return NULL;
}

struct linear_remsg_t {
	unsigned long paddr;
	unsigned long vaddr;
	unsigned long size;
	unsigned long forbidden_size;
	unsigned long ppool_size;
	int ret;
};

int camb_linear_remap_init(struct cn_mm_set *mm_set);
void camb_linear_remap_exit(struct cn_mm_set *mm_set);

void camb_linear_remap_mode_reset(struct cn_mm_set *mm_set);

struct sg_table *
camb_linear_sglist_translate(struct mapinfo *pminfo, dev_addr_t start, unsigned long size, u64 offset);

#endif /* __CAMBRICON_LINEAR_REMAP_H_ */
