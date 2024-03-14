#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/pid_namespace.h>
#include <linux/ftrace.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_sbts.h"
#include "cndrv_mcu.h"
#include "../include/cndrv_debug.h"
#include "cndrv_attr_common.h"
#include "cndrv_domain.h"
#include "cndrv_attr_res.h"
#include "cndrv_attr_internal.h"

/*take the integer to the nth power of 2*/
int cn_attr_round_down_powerof2nth(unsigned int num)
{
	unsigned int value = num;
	int count = 0;

	do {
		value >>= 1;
		count++;
	} while (value > 0);

	return num > 0 ? (1 << (count - 1)) : num;
}

void cn_attr_fill_hardware_cap_vf(void *pcore)
{
	struct bar_info_s bar_info;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_hardware_cap *phard_cap = NULL;
	s64 total_mem = 0;
	s32 ret = 0;
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}

	memset(&bar_info, 0x0, sizeof(struct bar_info_s));
	cn_bus_get_bar_info(core->bus_set, &bar_info);

	attr_set = core->attr_set;
	phard_cap = &attr_set->attr_info.hardware_cap;
	phard_cap->ecc_support = pboardi->ecc_support;
	phard_cap->cluster_clock_rate = pboardi->rated_ipu_freq * 1000;
	phard_cap->memory_clock_rate = pboardi->ddr_freq * 1000;
	phard_cap->bus_width = pboardi->bus_width;
	phard_cap->pci_bus_id = pboardi->pci_bus_num;
	phard_cap->pci_device_id = pboardi->pci_device_id;
	phard_cap->pci_domain_id = pboardi->pci_domain_id;
	phard_cap->pci_mps = pboardi->pci_mps;
	phard_cap->pci_mrrs = pboardi->pci_mrrs;

	total_mem = cn_dm_attr_memory_size(core);
	if (total_mem < 0) {
		cn_dev_core_err(core, "attribute memory size failed %lld", total_mem);
	} else {
		pboardi->total_memory = total_mem;
		phard_cap->global_memory_total_size = BYTES_TO_MB(pboardi->total_memory);
	}

	phard_cap->mdr_memory_size =
		min(BYTES_TO_MB(bar_info.bar[4].bar_sz), phard_cap->global_memory_total_size);

	ret = cn_dm_attr_memory_bus_width(core);
	if (ret < 0) {
		cn_dev_core_err(core, "attribute memory bus width failed %d", ret);
	} else {
		pboardi->bus_width = ret;
		phard_cap->bus_width = pboardi->bus_width;
	}
}


void cn_attr_fill_elastic_cap_vf(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_elastic_cap *pelastic_cap = NULL;
	s32 ret = 0;
	unsigned int max_quadrant_count = 0;
	int value = 0;
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;
	pelastic_cap = &attr_set->attr_info.elastic_cap;
	pelastic_cap->max_dimx = pboardi->max_dimx;
	pelastic_cap->max_dimy = pboardi->max_dimy;
	pelastic_cap->max_dimz = pboardi->max_dimz;
	pelastic_cap->max_core_count_per_cluster = pboardi->ipu_core_num;

	ret = cn_dm_attr_cluster_num(core);
	if (ret < 0) {
		cn_dev_core_err(core, "attribute cluster num failed %d", ret);
	} else {
		pboardi->cluster_num = ret;
		pelastic_cap->max_cluster_count = pboardi->cluster_num;
	}

	ret = cn_dm_attr_quadrant_num(core);
	if (ret < 0) {
		cn_dev_core_err(core, "attribute quadrant num failed %d", ret);
	} else {
		max_quadrant_count = ret;
		pelastic_cap->max_quadrant_count = ret;
	}

	/* calc union type per quadrant */
	if (pelastic_cap->max_cluster_count > 0) {

		value = cn_attr_round_down_powerof2nth(pelastic_cap->max_cluster_count);

		if (max_quadrant_count > 0) {
			pelastic_cap->max_union_type_per_quadrant = value / max_quadrant_count;
		}

		pboardi->kc_limit = value;
		pelastic_cap->max_cluster_count_per_union_task = pboardi->kc_limit;

		pboardi->o_kc_limit = value * 4;
		pelastic_cap->o_max_cluster_count_per_union_task = pboardi->o_kc_limit;
	}
}

void cn_attr_fill_heterogeneous_cap_vf(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_heterogeneous_cap *pheterogeneous_cap	= NULL;
	s32 ret = 0;
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;
	pheterogeneous_cap = &attr_set->attr_info.heterogeneous_cap;

	pheterogeneous_cap->queue_prio_support = pboardi->queue_prio_support;
	pheterogeneous_cap->max_queue = pboardi->max_queue;
	pheterogeneous_cap->max_notifier = pboardi->max_notifier;

	ret = cn_dm_attr_tiny_core_mask(core);
	if (ret > 0) {
		pheterogeneous_cap->tiny_core = ATTR_SUPPORT;
	} else {
		cn_dev_core_warn(core, "attribute tiny core %d", ret);
	}

	ret = cn_dm_attr_jpeg_codec_mask(core);
	if (ret > 0) {
		pheterogeneous_cap->codec_jpeg = ATTR_SUPPORT;
	} else {
		cn_dev_core_warn(core, "attribute jpeg codec %d", ret);
	}

	ret = cn_dm_attr_video_codec_mask(core);
	if (ret > 0) {
		pheterogeneous_cap->codec_h264 = ATTR_SUPPORT;
		pheterogeneous_cap->codec_h265 = ATTR_SUPPORT;
	} else {
		cn_dev_core_warn(core, "attribute video codec %d", ret);
	}

	pheterogeneous_cap->isp_core = 0;
}

void cn_attr_fill_memory_cap_vf(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_memory_cap *pmem_cap = NULL;
	s32 ret = 0;
	s64 total_mem = 0;
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;
	pmem_cap = &attr_set->attr_info.memory_cap;
	pmem_cap->cluster_l1_cache_support = 0;
	pmem_cap->max_persisting_l2_cache_size = 0;
	pmem_cap->max_shared_memory_size_per_union_task = 0;

	ret = cn_dm_attr_llc_cache_size(core);
	if (ret < 0) {
		cn_dev_core_err(core, "attribute llc cache size failed %d", ret);
	} else {
		pboardi->cache_size = ret;
		pmem_cap->max_l2_cache_size = pboardi->cache_size;
	}

	total_mem = cn_dm_attr_memory_size(core);
	if (total_mem < 0) {
		cn_dev_core_err(core, "attribute memory size failed %lld", total_mem);
	} else {
		pboardi->total_memory = total_mem;
		pmem_cap->total_const_mem_size = BYTES_TO_MB(pboardi->total_memory);
	}

	ret = cn_dm_attr_memory_nodes(core);
	if (ret < 0) {
		cn_dev_core_err(core, "attribute memory nodes failed %d", ret);
	} else {
		pboardi->mem_channel = ret;
		pmem_cap->global_memory_node_count = pboardi->mem_channel;
	}
}

int cn_attr_get_resource(struct cn_core_set *core, u32 res_index, u64 *value)
{
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("attribute core is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(value)) {
		cn_dev_core_err(core, "attribute value is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_core_err(core, "attr set is null");
		return -EINVAL;
	}
	if (res_index >= RES_BASIC_INFO_END ) {
		cn_dev_core_err(core, "attr set invalid parameter %d", res_index);
		return -EINVAL;
	}

	attr_set = core->attr_set;
	*value = attr_set->resource[res_index];

	return 0;
}

int cn_attr_fill_resource(struct cn_core_set *core, void *resource, u32 res_len)
{
	struct cndev_attr_set *attr_set = NULL;
	u32 real_length = 0;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("attribute core is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(resource)) {
		cn_dev_core_err(core, "attribute resource is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_core_err(core, "attr set is null");
		return -EINVAL;
	}

	attr_set = core->attr_set;
	real_length = res_len > RES_BASIC_INFO_END ? RES_BASIC_INFO_END : res_len;
	memcpy(attr_set->resource, resource, sizeof(u64) * real_length);

	return 0;
}

static struct cn_attr_fill_ops_vf fill_ops_vf = {
	.fill_heterogeneous_vf = cn_attr_fill_heterogeneous_cap_vf,
	.fill_elastic_vf = cn_attr_fill_elastic_cap_vf,
	.fill_memory_vf = cn_attr_fill_memory_cap_vf,
	.fill_hardware_vf = cn_attr_fill_hardware_cap_vf,
};

static struct cn_attr_fill_ops_vf mlu590_fill_ops_vf = {
	.fill_heterogeneous_vf = cn_attr_fill_heterogeneous_cap_vf,
	.fill_elastic_vf = cn_attr_fill_elastic_cap_vf,
	.fill_memory_vf = cn_attr_fill_memory_cap_mlu590_vf,
	.fill_hardware_vf = cn_attr_fill_hardware_cap_vf,
};

static struct cn_attr_fill_ops_vf mlu580_fill_ops_vf = {
	.fill_heterogeneous_vf = cn_attr_fill_heterogeneous_cap_vf,
	.fill_elastic_vf = cn_attr_fill_elastic_cap_vf,
	.fill_memory_vf = cn_attr_fill_memory_cap_mlu590_vf,
	.fill_hardware_vf = cn_attr_fill_hardware_cap_vf,
};

int init_device_attr_info(struct cn_core_set *core)
{
	struct cndev_attr_set *attr_set = core->attr_set;

	attr_set->attr_info.head.version = ATTR_VERSION1;
	return 0;
}

void cn_attr_init_default_cap(struct cn_core_set *core)
{
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;
	memset(&attr_set->attr_info.compute_cap, 0, sizeof(struct cn_computing_cap));
	memset(&attr_set->attr_info.elastic_cap, 0, sizeof(struct cn_elastic_cap));
	memset(&attr_set->attr_info.memory_cap, 0, sizeof(struct cn_memory_cap));
	memset(&attr_set->attr_info.hardware_cap, 0, sizeof(struct cn_hardware_cap));
	memset(&attr_set->attr_info.heterogeneous_cap, 0, sizeof(struct cn_heterogeneous_cap));
}

int cn_attr_init(struct cn_core_set *core)
{
	struct cndev_attr_set *attr_set = NULL;
	int ret = -1;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("attribute core is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(core->attr_set)) {
		core->attr_set = cn_kzalloc(sizeof(struct cndev_attr_set), GFP_KERNEL);
	}
	if (!core->attr_set) {
		cn_dev_core_err(core, "attribute attr_set is null");
		return -EINVAL;
	}
	cn_attr_init_default_cap(core);
	attr_set = core->attr_set;

	/* manage version for CAMB_GET_DEVICE_PRIVATE_ATTR ioctl */
	attr_set->extra_version = ATTR_VERSION;

	ret = init_device_attr_info(core);
	if (ret) {
		if (core->attr_set) {
			cn_kfree(core->attr_set);
		}
		core->attr_set = NULL;
		cn_dev_core_err(core, "device attribute init failed");
	} else {
		cn_dev_core_debug(core, "device attribute init success");
	}

	return 0;
}

void cn_attr_exit(struct cn_core_set *core)
{
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("attribute core is null");
		return;
	}
	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_info("attribute attr_set is null");
		return;
	}

	cn_kfree(core->attr_set);
	core->attr_set = NULL;
}

int cn_attr_late_init(struct cn_core_set *pcore)
{
	struct cndev_attr_set *attr_set = NULL;

	cn_attr_fill_attr(pcore);

	attr_set = pcore->attr_set;
	if (IS_ERR_OR_NULL(attr_set)) {
		cn_dev_core_err(pcore, "attribute attr_set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(attr_set->init_ops)) {
		cn_dev_core_info(pcore, "current MLUID is not vf");
		return 0;
	}
	if (attr_set->init_ops->init_boardinfo_vf) {
		attr_set->init_ops->init_boardinfo_vf(pcore);
	}
	if (attr_set->init_ops->init_attribute_vf) {
		attr_set->init_ops->init_attribute_vf(pcore);
	}


	return 0;
}

void cn_attr_late_exit(struct cn_core_set *pcore)
{
	return;
}

struct cn_attr_init_ops_vf mlu270_attr_init_vf = {
	.init_boardinfo_vf = fill_boardinfo_mlu270_vf,
	.init_attribute_vf = fill_attribute_mlu270_vf,
};

struct cn_attr_init_ops_vf mlu290_attr_init_vf = {
	.init_boardinfo_vf = NULL,
	.init_attribute_vf = fill_attribute_mlu290_vf,
};

struct cn_attr_init_ops_vf mlu370_attr_init_vf = {
	.init_boardinfo_vf = fill_boardinfo_mlu370_vf,
	.init_attribute_vf = fill_attribute_mlu370_vf,
};

struct cn_attr_init_ops_vf mlu590_attr_init_vf = {
	.init_boardinfo_vf = fill_boardinfo_mlu590_vf,
	.init_attribute_vf = fill_attribute_mlu590_vf,
};

struct cn_attr_init_ops_vf mlu580_attr_init_vf = {
	.init_boardinfo_vf = fill_boardinfo_mlu580_vf,
	.init_attribute_vf = fill_attribute_mlu580_vf,
};

void cn_attr_update_aiisp(struct cn_core_set *pcore, __u32 nn_num, __u32 isp_num)
{
	struct cndev_attr_set *attr_set = NULL;

	attr_set = pcore->attr_set;
	attr_set->attr_info.elastic_cap.max_cluster_count = nn_num;
	pcore->board_info.cluster_num = nn_num;
	attr_set->attr_info.heterogeneous_cap.isp_core = isp_num;
}

void cn_attr_fill_attr(struct cn_core_set *core)
{
	struct cndev_attr_set *attr_set = NULL;

	attr_set = core->attr_set;
	if (IS_ERR_OR_NULL(attr_set)) {
		cn_dev_core_err(core, "attribute attr_set is null");
		return;
	}

	switch (core->device_id) {
	case MLUID_220:
	case MLUID_220_EDGE:
		fill_attribute_mlu220(core);
		break;
	case MLUID_270:
		fill_attribute_mlu270(core);
		break;
	case MLUID_270V:
	case MLUID_270V1:
		attr_set->init_ops = &mlu270_attr_init_vf;
		attr_set->fill_ops = &fill_ops_vf;
		break;
	case MLUID_290:
		fill_attribute_mlu290(core);
		break;
	case MLUID_290V1:
		attr_set->init_ops = &mlu290_attr_init_vf;
		attr_set->fill_ops = &fill_ops_vf;
		break;
	case MLUID_370:
		fill_attribute_mlu370(core);
		break;
	case MLUID_370V:
		attr_set->init_ops = &mlu370_attr_init_vf;
		attr_set->fill_ops = &fill_ops_vf;
		break;
	case MLUID_CE3226:
	case MLUID_CE3226_EDGE:
		fill_attribute_ce3226(core);
		break;
	case MLUID_590:
		fill_attribute_mlu590(core);
		break;
	case MLUID_590V:
		attr_set->init_ops = &mlu590_attr_init_vf;
		attr_set->fill_ops = &mlu590_fill_ops_vf;
		break;
	case MLUID_PIGEON:
	case MLUID_PIGEON_EDGE:
		fill_attribute_pigeon(core);
		break;
	case MLUID_580:
		fill_attribute_mlu580(core);
		break;
	case MLUID_580V:
		attr_set->init_ops = &mlu580_attr_init_vf;
		attr_set->fill_ops = &mlu580_fill_ops_vf;
		break;
	default:
		attr_set->init_ops = NULL;
		attr_set->fill_ops = NULL;
		cn_dev_core_err(core, "device [%#llx] not support attribute", core->device_id);
		break;
	}
}
