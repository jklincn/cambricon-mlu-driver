#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/kthread.h>	//kthread_should_stop
#include <linux/pci.h>
#include <linux/delay.h>        //for msleep
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_commu.h"
#include "cndrv_domain.h"
#include "dmlib/include/domain.h"
#include "../../include/cndrv_sbts.h"
#include "../../include/cndrv_mm.h"
#include "dmlib/domain_private.h"
#include "dmlib/domain_resource_dictionary.h"
#include "binn.h"
#include "internal_interface.h"

s32 init_pf_resource_cache(struct cn_core_set *core)
{
	struct domain_set_type *set;
	struct domain_type *domain;
	struct resource_cache *rc;

	set = core->domain_set;
	domain = dm_get_domain(set, DM_FUNC_OVERALL);
	if (domain == NULL) {
		cn_domain_err(set, "get domain OVERALL fail");
		return -1;
	}
	rc = domain->resource_cache;
	if (rc == NULL) {
		rc = dm_zalloc(sizeof(struct resource_cache));
		if (rc == NULL) {
			cn_domain_err(set,
					"fail alloc mem for resource_cache\n");
			return -ENOMEM;
		}
	}
	domain->resource_cache = rc;
	rc->cache_size = core->board_info.cache_size;
	rc->bus_width = core->board_info.bus_width;
	cn_domain_info(set, "platform cache_size %d bus_width %d",
						rc->cache_size, rc->bus_width);
	return 0;
}

s32 domain_set_attr_init(struct domain_set_type *set,
				struct cn_bus_set *bus_set, struct domain_resource *resource)
{
	struct domain_set_attr *attr = NULL;

	if (set->attr == NULL) {
		attr = dm_zalloc(sizeof(struct domain_set_attr));
		if (attr == NULL) {
			cn_domain_err(set, "fail alloc domain_set_attr\n");
			return -ENOMEM;
		}
	} else {
		attr = set->attr;
	}
	set->attr = attr;
	setup_domain_work_mode(set, bus_set, resource);
	return 0;
}

s32 domain_set_attr_sync_max_vf(struct domain_set_type *set)
{
	s8 cached_resource[2] = {
		c_max_vf,
		-1,
	};
	struct dm_resource_discriptor cached_res_set[] = {
		[0] = {.mod_idx = DM_BOARD_IDX, .res = cached_resource},
		[1] = {.mod_idx = -1, .res = NULL},
	};
	s8 _res_offset[ARRAY_SIZE(cached_resource)];
	s8 *res_offset[] = {
		_res_offset,
	};
	u64 res[ARRAY_SIZE(cached_resource) - 1];
	u64 *ress[] = {
		res,
	};
	s32 ret;
	struct domain_set_attr *attr;

	if (set->attr == NULL) {
		cn_domain_err(set, "domain_set_attr error");
		return -EINVAL;
	}
	memset(_res_offset, 0, sizeof(_res_offset));
	ret = dm_rpc_get_resource_host(set, ress,
			cached_res_set, res_offset, 3,
			set->overall);
	if (ret < 0) {
		cn_domain_err(set, "fail on init domain set attr");
		return -EINVAL;
	}
	attr = set->attr;
	attr->max_vf = res[0];
	cn_domain_info(set, "max_vf %d\n", attr->max_vf);
	return 0;
}

s32 domain_set_attr_get_max_vf(struct domain_set_type *domain_set)
{
	struct domain_set_type *set = (struct domain_set_type *)domain_set;
	struct domain_set_attr *attr;

	attr = set->attr;
	if (attr == NULL) {
		cn_domain_err(set, "attr not exist");
		return -EINVAL;
	}
	if (attr->max_vf == 0)
		cn_domain_warn(set, "max_vf is invald 0");

	return attr->max_vf;
}

s32 domain_set_attr_set_sriov_func_num(struct domain_set_type *set, s32 num)
{
	struct domain_set_attr *attr;

	attr = set->attr;
	if (attr == NULL) {
		cn_domain_err(set, "attr not exist");
		return -EINVAL;
	}
	if (attr->sriov_func_num != 0)
		cn_domain_warn(set, "sriov_func_num already exist!");

	attr->sriov_func_num = num;
	return 0;
}

s32 domain_set_attr_get_sriov_func_num(struct domain_set_type *set)
{
	struct domain_set_attr *attr;

	attr = set->attr;
	if (attr == NULL) {
		cn_domain_err(set, "attr not exist");
		return -EINVAL;
	}

	return attr->sriov_func_num;
}

s32 sync_resouce_cache(struct domain_set_type *set, struct domain_type *target)
{
	s8 cached_resource[4] = {
		a_ipu_cores,
		d_tiny_cores,
		-1,
	};
	struct dm_resource_discriptor cached_res_set[] = {
		[0] = {.mod_idx = DM_IPU_IDX, .res = cached_resource},
		[1] = {.mod_idx = -1, .res = NULL},
	};
	s8 _res_offset[ARRAY_SIZE(cached_resource)];
	s8 *res_offset[] = {
		_res_offset,
	};
	u64 res[ARRAY_SIZE(cached_resource) - 1];
	u64 *ress[] = {
		res,
	};
	struct resource_cache *rc;
	s32 ret;

	memset(_res_offset, 0, sizeof(_res_offset));
	ret = dm_rpc_get_resource_host(set, ress,
			cached_res_set, res_offset, 3,
			target);
	if (ret < 0) {
		print_err("fail on get sync_resource_cache\n");
		return -EINVAL;
	}
	if (target->resource_cache == NULL) {
		rc = dm_zalloc(sizeof(struct resource_cache));
		if (rc == NULL) {
			print_err("fail alloc mem for resource_cache\n");
			return -ENOMEM;
		}
		target->resource_cache = rc;
	} else {
		rc = target->resource_cache;
	}
	rc->ipu_mask = res[0];
	rc->tiny_core_mask = res[1];
	cached_resource[0] = c_mem_cache_size;
	cached_resource[1] = d_mem_bus_width;
	cached_resource[2] = e_mem_ch_num;
	cached_resource[3] = -1;
	cached_res_set[0].mod_idx = DM_MEM_IDX;
	cached_res_set[0].res = cached_resource;
	cached_res_set[1].mod_idx = -1;
	cached_res_set[1].res = NULL;
	ret = dm_rpc_get_resource_host(set, ress,
			cached_res_set, res_offset, 3,
			target);
	if (ret < 0) {
		print_err("fail on get sync_resource_cache\n");
		return -EINVAL;
	}
	rc->cache_size = res[0];
	rc->bus_width = res[1];
	rc->mem_ch_num = res[2];
	cached_resource[0] = a_vpu_cores;
	cached_resource[1] = -1;
	cached_res_set[0].mod_idx = DM_VPU_IDX;
	cached_res_set[0].res = cached_resource;
	cached_res_set[1].mod_idx = -1;
	cached_res_set[1].res = NULL;
	ret = dm_rpc_get_resource_host(set, ress,
			cached_res_set, res_offset, 3,
			target);
	if (ret < 0) {
		print_err("fail on get sync_resource_cache\n");
		return -EINVAL;
	}
	rc->vpu_mask = res[0];
	cached_resource[0] = a_jpu_cores;
	cached_resource[1] = -1;
	cached_res_set[0].mod_idx = DM_JPU_IDX;
	cached_res_set[0].res = cached_resource;
	cached_res_set[1].mod_idx = -1;
	cached_res_set[1].res = NULL;
	ret = dm_rpc_get_resource_host(set, ress,
			cached_res_set, res_offset, 3,
			target);
	if (ret < 0) {
		print_err("fail on get sync_resource_cache\n");
		return -EINVAL;
	}
	rc->jpu_mask = res[0];
	cached_resource[0] = f_mem_size_gb;
	cached_resource[1] = g_quadrant;
	cached_resource[2] = -1;
	cached_res_set[0].mod_idx = DM_MEM_IDX;
	cached_res_set[0].res = cached_resource;
	cached_res_set[1].mod_idx = -1;
	cached_res_set[1].res = NULL;
	ret = dm_rpc_get_resource_host(set, ress,
			cached_res_set, res_offset, 3,
			target);
	if (ret < 0) {
		print_err("fail on get sync_resource_cache\n");
		return -EINVAL;
	}
	rc->mem_size_gb = res[0];
	rc->quadrant = res[1];
	cached_resource[0] = a_gdma_host_ch;
	cached_resource[1] = -1;
	cached_res_set[0].mod_idx = DM_GDMA_IDX;
	cached_res_set[0].res = cached_resource;
	cached_res_set[1].mod_idx = -1;
	cached_res_set[1].res = NULL;
	ret = dm_rpc_get_resource_host(set, ress,
			cached_res_set, res_offset, 3,
			target);
	if (ret < 0) {
		print_err("fail on get sync_resource_cache\n");
		return -EINVAL;
	}
	rc->gdma_host_ch = res[0];

	return 0;
}

void *check_and_get_valid_res_cache(struct cn_core_set *core)
{
	struct domain_type *domain = NULL;
	struct domain_set_type *set;
	u32 func_id = DM_FUNC_PF;

	set = core->domain_set;
	if (__cn_dm_is_pf_only_mode(core))
		func_id = DM_FUNC_PF;
	else if (cn_core_is_vf(core))
		func_id = DM_FUNC_VF;
	else
		return NULL;

	domain = dm_get_domain(set, func_id);
	if (domain == NULL || domain->resource_cache == NULL) {
		cn_domain_err(set,
		  "Could not get func_id<%s> or domain resource_cache is NULL",
							dm_funcid2str(func_id));
		return NULL;
	}
	return domain->resource_cache;
}

/* CN_DEVICE_ATTRIBUTE_TINY_CORE_SUPPORTED */
s32 cn_dm_attr_tiny_core_mask(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	cn_domain_debug(set, "tiny_core_mask %d", rc->tiny_core_mask);
	return rc->tiny_core_mask;
}

/* CN_DEVICE_ATTRIBUTE_CODEC_JPEG_SUPPORTED */
s32 cn_dm_attr_jpeg_codec_mask(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	if (rc->jpu_mask == 0)
		cn_domain_warn(set, "jpu_mask invald 0");

	cn_domain_debug(set, "jpu_mask %d", rc->jpu_mask);
	return rc->jpu_mask;
}

/**
 * CN_DEVICE_ATTRIBUTE_CODEC_H264_SUPPORTED
 * CN_DEVICE_ATTRIBUTE_CODEC_H265_SUPPORTED
 */
s32 cn_dm_attr_video_codec_mask(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	if (rc->vpu_mask == 0)
		cn_domain_warn(set, "vpu_mask invald 0");

	cn_domain_debug(set, "vpu_mask %d", rc->vpu_mask);
	return rc->vpu_mask;
}

/* CN_DEVICE_ATTRIBUTE_MAX_CLUSTER_COUNT */
s32 cn_dm_attr_cluster_num(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	if (rc->ipu_mask == 0)
		cn_domain_warn(set, "ipu mask invalid 0");

	cn_domain_debug(set, "ipu_mask %d", rc->ipu_mask);
	return hweight32(rc->ipu_mask);
}

/* CN_DEVICE_ATTRIBUTE_MAX_QUADRANT_COUNT */
s32 cn_dm_attr_quadrant_num(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	if (rc->quadrant <= 0)
		cn_domain_warn(set, "Quadrant invalid %d", rc->quadrant);

	cn_domain_debug(set, "quadrant %d", rc->quadrant);
	return rc->quadrant;
}

/* CN_DEVICE_ATTRIBUTE_MAX_L2_CACHE_SIZE */
s32 cn_dm_attr_llc_cache_size(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	if (rc->cache_size <= 0)
		cn_domain_warn(set, "cache_size invalid %d", rc->cache_size);

	cn_domain_debug(set, "cache_size %d", rc->cache_size);
	return rc->cache_size;
}

s32 cn_dm_attr_llc_max_persisting_size(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	if (core->device_id != MLUID_590V
		&& core->device_id != MLUID_580V
		&& core->device_id != MLUID_570V)
		return -1;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	if (rc->cache_size <= 0)
		cn_domain_warn(set, "cache_size invalid %d", rc->cache_size);

	cn_domain_debug(set, "cache_size %d", rc->cache_size);
	return rc->cache_size / 4 * 3;
}

/**
 * CN_DEVICE_ATTRIBUTE_TOTAL_CONST_MEMORY_SIZE
 * CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_TOTAL_SIZE
 */
s64 cn_dm_attr_memory_size(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	if (rc->mem_size_gb <= 0)
		cn_domain_warn(set, "mem_size_gb invalid %d", rc->mem_size_gb);

	cn_domain_debug(set, "mem_size_gb %d", rc->mem_size_gb);
	return ((s64)rc->mem_size_gb) << 30;
}

/* CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_NODE_COUNT */
s32 cn_dm_attr_memory_nodes(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	if (rc->mem_ch_num <= 0)
		cn_domain_warn(set, "mem_ch_num invalid %d", rc->mem_ch_num);

	cn_domain_debug(set, "mem_ch_num %d", rc->mem_ch_num);
	return rc->mem_ch_num;
}

/* CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_BUS_WIDTH */
s32 cn_dm_attr_memory_bus_width(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	if (rc->bus_width <= 0)
		cn_domain_warn(set, "bus_width invalid %d", rc->bus_width);

	cn_domain_debug(set, "bus_width %d", rc->bus_width);
	return rc->bus_width;
}

s32 cn_dm_attr_gdma_host_ch(struct cn_core_set *core)
{
	struct resource_cache *rc;
	struct domain_set_type *set;

	set = core->domain_set;
	rc = check_and_get_valid_res_cache(core);
	if (rc == NULL)
		return -1;

	cn_domain_debug(set, "gdma_host_ch %d", rc->gdma_host_ch);
	return rc->gdma_host_ch;
}
