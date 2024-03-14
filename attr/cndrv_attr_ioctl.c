/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
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
#include "cndrv_debug.h"

#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "cndrv_mm.h"
#include "../core/version.h"
#include "cndrv_proc.h"
#include "cndrv_commu.h"
#include "../include/cndrv_debug.h"
#include "cndrv_attr.h"
#include "cndrv_sbts.h"
#include "cndrv_driver_capability.h"
#include "cndrv_attr_common.h"
#include "cndrv_attr_res.h"
#include "cndrv_ioctl.h"
#include "cndrv_smlu.h"

#ifdef CONFIG_CNDRV_EDGE
#include "../ipcm/cambr_ipcm.h"
#else
#include "cndrv_ipcm.h"
#endif

void cn_computing_capabilities(struct cn_core_set *core, unsigned int *data)
{
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;

	data[CN_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR] = attr_set->attr_info.compute_cap.major;
	data[CN_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR] = attr_set->attr_info.compute_cap.minor;
	data[CN_DEVICE_ATTRIBUTE_SPARSE_COMPUTING_SUPPORTED] = attr_set->attr_info.compute_cap.sparse;
	data[CN_DEVICE_ATTRIBUTE_FP16_COMPUTING_SUPPORTED] = attr_set->attr_info.compute_cap.fp16;
	data[CN_DEVICE_ATTRIBUTE_INT4_COMPUTING_SUPPORTED] = attr_set->attr_info.compute_cap.int4;
	data[CN_DEVICE_ATTRIBUTE_INT8_COMPUTING_SUPPORTED] = attr_set->attr_info.compute_cap.int8;
	data[CN_DEVICE_ATTRIBUTE_BF16_COMPUTING_SUPPORTED] = attr_set->attr_info.compute_cap.bf16;
	data[CN_DEVICE_ATTRIBUTE_TF32_COMPUTING_SUPPORTED] = attr_set->attr_info.compute_cap.tf32;
	data[CN_DEVICE_ATTRIBUTE_COMPUTE_MODE] = core->exclusive_mode;
}

void cn_fill_heterogeneous_capabilities(void *pcore)
{
	struct sbts_info_s sbts_info;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;

	memset(&sbts_info, 0, sizeof(struct sbts_info_s));
	cn_sbts_get_sbts_info(core, &sbts_info);
	attr_set->attr_info.heterogeneous_cap.multi_dev_notifier_wait = sbts_info.multi_dev_notifier;
	attr_set->attr_info.heterogeneous_cap.ipcnotifier_support = sbts_info.ipc_notifier;

}

void cn_heterogeneous_capabilities(struct cn_core_set *core, unsigned int *data)
{
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;

	cn_fill_heterogeneous_capabilities(core);

	data[CN_DEVICE_ATTRIBUTE_MAX_QUEUE_COUNT] =
		attr_set->attr_info.heterogeneous_cap.max_queue;
	data[CN_DEVICE_ATTRIBUTE_MAX_NOTIFIER_COUNT] =
		attr_set->attr_info.heterogeneous_cap.max_notifier;
	data[CN_DEVICE_ATTRIBUTE_QUEUE_PRIORITIES_SUPPORTED] =
		attr_set->attr_info.heterogeneous_cap.queue_prio_support;

	data[CN_DEVICE_ATTRIBUTE_TINY_CORE_SUPPORTED] =
		attr_set->attr_info.heterogeneous_cap.tiny_core;
	data[CN_DEVICE_ATTRIBUTE_CODEC_JPEG_SUPPORTED] =
		attr_set->attr_info.heterogeneous_cap.codec_jpeg;
	data[CN_DEVICE_ATTRIBUTE_CODEC_H264_SUPPORTED] =
		attr_set->attr_info.heterogeneous_cap.codec_h264;
	data[CN_DEVICE_ATTRIBUTE_CODEC_H265_SUPPORTED] =
		attr_set->attr_info.heterogeneous_cap.codec_h265;

	data[CN_DEVICE_ATTRIBUTE_MULTI_CTX_NOTIFIER_WAIT_SUPPORTED] =
		attr_set->attr_info.heterogeneous_cap.multi_dev_notifier_wait;
	data[CN_DEVICE_ATTRIBUTE_IPCNOTIFIER_SUPPORTED] =
		attr_set->attr_info.heterogeneous_cap.ipcnotifier_support;
}

void cn_elastic_capabilities(struct cn_core_set *core, unsigned int *data)
{
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;

	data[CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_X] = attr_set->attr_info.elastic_cap.max_dimx;
	data[CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_Y] = attr_set->attr_info.elastic_cap.max_dimy;
	data[CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_Z] = attr_set->attr_info.elastic_cap.max_dimz;
	data[CN_DEVICE_ATTRIBUTE_MAX_CLUSTER_COUNT_PER_UNION_TASK] =
		attr_set->attr_info.elastic_cap.o_max_cluster_count_per_union_task;
	data[CN_DEVICE_ATTRIBUTE_MAX_CLUSTER_COUNT] = attr_set->attr_info.elastic_cap.max_cluster_count;
	data[CN_DEVICE_ATTRIBUTE_MAX_CORE_COUNT_PER_CLUSTER] =
		attr_set->attr_info.elastic_cap.max_core_count_per_cluster;
	data[CN_DEVICE_ATTRIBUTE_MAX_QUADRANT_COUNT] =
		attr_set->attr_info.elastic_cap.max_quadrant_count;
	data[CN_DEVICE_ATTRIBUTE_MAX_UNION_TYPE_PER_QUADRANT] =
		attr_set->attr_info.elastic_cap.max_union_type_per_quadrant;
}

void cn_fill_part_memory_capabilities(void *pcore)
{
	struct sbts_info_s sbts_info;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;
	memset(&sbts_info, 0, sizeof(struct sbts_info_s));
	cn_sbts_get_sbts_info(core, &sbts_info);

	attr_set->attr_info.memory_cap.n_ram_size_per_core = sbts_info.ct_ram_size;
	attr_set->attr_info.memory_cap.weight_ram_size_per_core = sbts_info.lt_ram_size;

	attr_set->attr_info.memory_cap.local_mem_size_per_core = sbts_info.ldram_max_size;
	attr_set->attr_info.memory_cap.max_shared_ram_size_per_cluster = sbts_info.shared_mem_size;
}

void cn_memory_capabilities(struct cn_core_set *core, unsigned int *data)
{
	struct mem_feats_t status;
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;

	cn_fill_part_memory_capabilities(core);

	data[CN_DEVICE_ATTRIBUTE_MAX_L2_CACHE_SIZE] =
		attr_set->attr_info.memory_cap.max_l2_cache_size;
	data[CN_DEVICE_ATTRIBUTE_N_RAM_SIZE_PER_CORE] =
		attr_set->attr_info.memory_cap.n_ram_size_per_core;
	data[CN_DEVICE_ATTRIBUTE_WEIGHT_RAM_SIZE_PER_CORE] =
		attr_set->attr_info.memory_cap.weight_ram_size_per_core;

	data[CN_DEVICE_ATTRIBUTE_TOTAL_CONST_MEMORY_SIZE] =
		attr_set->attr_info.memory_cap.total_const_mem_size;
	data[CN_DEVICE_ATTRIBUTE_LOCAL_MEMORY_SIZE_PER_CORE] =
		attr_set->attr_info.memory_cap.local_mem_size_per_core;
	data[CN_DEVICE_ATTRIBUTE_MAX_SHARED_RAM_SIZE_PER_CLUSTER] =
		attr_set->attr_info.memory_cap.max_shared_ram_size_per_cluster;
	data[CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_NODE_COUNT] =
		attr_set->attr_info.memory_cap.global_memory_node_count;

	data[CN_DEVICE_ATTRIBUTE_CLUSTER_L1_CACHE_SUPPORTED] =
		attr_set->attr_info.memory_cap.cluster_l1_cache_support;
	data[CN_DEVICE_ATTRIBUTE_MAX_PERSISTING_L2_CACHE_SIZE] =
		attr_set->attr_info.memory_cap.max_persisting_l2_cache_size;
	data[CN_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_SIZE_PER_UNION_TASK] =
		attr_set->attr_info.memory_cap.max_shared_memory_size_per_union_task;

	cn_mem_get_feats_status(core, &status);
	data[CN_DEVICE_ATTRIBUTE_VIRTUAL_ADDRESS_MANAGEMENT_SUPPORTED] = status.vmm;
	data[CN_DEVICE_ATTRIBUTE_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR_SUPPORTED] =
		status.vmm_handle2fd;
	data[CN_DEVICE_ATTRIBUTE_GENERIC_COMPRESSION_SUPPORTED] = status.compression;
	data[CN_DEVICE_ATTRIBUTE_LINEAR_MAPPING_SUPPORTED] = status.linear;
	data[CN_DEVICE_ATTRIBUTE_LINEAR_RECOMMEND_GRANULARITY] = status.linear_granularity;

	data[CN_DEVICE_ATTRIBUTE_CAN_USE_HOST_POINTER_FOR_REGISTERED_MEM] =
		attr_set->attr_info.memory_cap.can_use_host_pointer_for_register_mem;
	data[CN_DEVICE_ATTRIBUTE_CAN_MAP_HOST_MEMORY] =
		attr_set->attr_info.memory_cap.can_map_host_memory;

}

void cn_hardware_proterties(struct cn_core_set *core, unsigned int *data)
{
	struct cndev_attr_set *attr_set = NULL;
	struct smlu_cgroup_res *res;
	int ret = 0;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}
	attr_set = core->attr_set;
	data[CN_DEVICE_ATTRIBUTE_ECC_ENABLED] =
		attr_set->attr_info.hardware_cap.ecc_support;
	data[CN_DEVICE_ATTRIBUTE_CLUSTER_CLOCK_RATE] =
		attr_set->attr_info.hardware_cap.cluster_clock_rate;
	data[CN_DEVICE_ATTRIBUTE_MEMORY_CLOCK_RATE] =
		attr_set->attr_info.hardware_cap.memory_clock_rate;
	data[CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_BUS_WIDTH] =
		attr_set->attr_info.hardware_cap.bus_width;
	data[CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_TOTAL_SIZE] =
		attr_set->attr_info.hardware_cap.global_memory_total_size;
	data[CN_DEVICE_ATTRIBUTE_MDR_MEMORY_SIZE] =
		attr_set->attr_info.hardware_cap.mdr_memory_size;

	data[CN_DEVICE_ATTRIBUTE_PCI_BUS_ID] = attr_set->attr_info.hardware_cap.pci_bus_id;
	data[CN_DEVICE_ATTRIBUTE_PCI_DEVICE_ID] = attr_set->attr_info.hardware_cap.pci_device_id;
	data[CN_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID] = attr_set->attr_info.hardware_cap.pci_domain_id;
	data[CN_DEVICE_ATTRIBUTE_PCI_MPS] = attr_set->attr_info.hardware_cap.pci_mps;
	data[CN_DEVICE_ATTRIBUTE_PCI_MRRS] = attr_set->attr_info.hardware_cap.pci_mrrs;

	res = cn_kmalloc(sizeof(*res), GFP_KERNEL);
	if (res == NULL)
		return;

	/* correct to split size */
	ret = cn_smlu_query_namespace_quota(core, mem_cgrp_id, NULL, res);
	if (ret == 0) {/* smlu enabled && name space in rbtree */
		cn_dev_core_debug(core, "correct phy_total 0x%llx MB -> 0x%llx MB",
			attr_set->attr_info.hardware_cap.global_memory_total_size, res->max >> 20);
		data[CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_TOTAL_SIZE] = (res->max >> 20);
	}
	cn_kfree(res);
}

void cn_get_attribute_info(struct cn_core_set *core, void *attr, unsigned int *data)
{
	/* Computing Capabilities */
	cn_computing_capabilities(core, data);

	/* Heterogeneous Capabilities */
	cn_heterogeneous_capabilities(core, data);

	/* Elastic Capabilities */
	cn_elastic_capabilities(core, data);

	/* Memory Capacities */
	cn_memory_capabilities(core, data);

	/* Hardware Proterties */
	cn_hardware_proterties(core, data);
}

void cn_get_extra_attribute_info(struct cn_core_set *core, unsigned int *data, int attr_cnt)
{
	struct cndev_attr_set *attr_set = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("core is null");
		return;
	}

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attr_set is null");
		return;
	}
	attr_set = core->attr_set;

	if (IS_ERR_OR_NULL(data)) {
		cn_dev_err("data is null");
		return;
	}

	if (attr_cnt > CN_DEVICE_EXTRA_ATTRIBUTE_MAX) {
		cn_dev_err("invalid attr cnt %u", attr_cnt);
		return;
	}

	data[CN_DEVICE_EXTRA_ATTRIBUTE_MAX_CLUSTERS_PER_UNION_LIMIT_TASK] =
		attr_set->attr_info.elastic_cap.max_cluster_count_per_union_task;
	data[CN_DEVICE_EXTRA_ATTRIBUTE_MAX_QUADRANT_COUNT] =
		attr_set->attr_info.elastic_cap.max_quadrant_count;
	data[CN_DEVICE_EXTRA_ATTRIBUTE_MAX_UNION_TYPE_PER_QUADRANT] =
		attr_set->attr_info.elastic_cap.max_union_type_per_quadrant;
	/* new add two info */
	data[CN_DEVICE_EXTRA_ATTRIBUTE_MLU_ISA_VERSION] =
		attr_set->attr_info.elastic_cap.mlu_isa_version;
	data[CN_DEVICE_EXTRA_ATTRIBUTE_IS_MULTIPLE_TENSOR_PROCESSOR] =
		attr_set->attr_info.elastic_cap.is_multiple_tensor_processor;
	/* new add one info for 3226 */
	data[CN_DEVICE_EXTRA_ATTRIBUTE_AIISP_CORE_COUNT] =
		attr_set->attr_info.heterogeneous_cap.isp_core;
}

static int cn_get_attribute_info_v2(struct cn_core_set *core, unsigned long arg)
{
	struct cn_device_attr attr;
	unsigned int *data = NULL;
	struct cndev_attr_set *attr_set = NULL;
	int attr_cnt = 0;
	int ret = 0;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return -EFAULT;
	}
	attr_set = core->attr_set;

	if (copy_from_user((void *)&attr, (void *)arg,
			sizeof(struct cn_device_attr))) {
		cn_dev_core_err(core, "get device attribute failed!");
		return -ENOMEM;
	}

	/* @attr.version represents driver-api version and
	 * @core->extra_version represents driver extra version, this ioctl
	 * return -EINVAL if driver-api version greater than driver version
	 */
	if (attr.version > attr_set->extra_version) {
		return -EINVAL;
	}

	if (attr.cnt < 0) {
		return -EINVAL;
	}

	/* alloc all buffer for ATTR_VERSION3 currently */
	data = cn_kzalloc(CN_DEVICE_EXTRA_ATTRIBUTE_MAX *
			sizeof(unsigned int), GFP_KERNEL);
	if (unlikely(!data)) {
		cn_dev_core_info(core, "alloc attribute data failed!");
		return -ENOMEM;
	}

	switch (attr.version) {
	case ATTR_VERSION2: {
		/* only support report driver build version on data0 */
		attr_cnt = min_t(u32, attr.cnt, 1);
		data[0] = DRV_BUILD;
		break;
	}
	case ATTR_VERSION3: {
		attr_cnt = min_t(u32, attr.cnt, CN_DEVICE_EXTRA_ATTRIBUTE_MAX);

		cn_get_extra_attribute_info(core, data, attr_cnt);
		break;
	}
	default:
		cn_dev_core_err(core, "unknown attribute v2 version %d",
				attr.version);
		ret = -EINVAL;
	}

	if (!ret) {
		if (copy_to_user(attr.data, data,
				attr_cnt * sizeof(unsigned int))) {
			cn_dev_core_info(core,
					"return device attribute failed!");
			ret = -EFAULT;
		}

	}

	cn_kfree(data);
	return ret;
}

static long cn_get_device_name(struct cn_core_set *core, unsigned long arg)
{
	long ret = 0;
	struct cn_board_info *pboardi = &core->board_info;

	if (pboardi) {
		if (copy_to_user((void *)arg, (void *)&(pboardi->board_model_name),
					BOARD_MODEL_NAME_LEN)) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
		}
	} else {
		ret = -EFAULT;
	}

	return ret;
}

static long cn_get_device_work_mode(struct cn_core_set *core, unsigned long arg)
{
	long ret = 0;
	enum core_work_mode mode;

	mode = cn_core_get_work_mode(core);
	if (copy_to_user((void *)arg, (void *)&mode, sizeof(mode))) {
		cn_dev_core_err(core, "copy_to_user failed.");
		ret = -EFAULT;
	}

	return ret;
}

static long cn_get_device_unique_id(struct file *fp,
				struct cn_core_set *core,
				unsigned long arg)
{
	long ret = 0;
	struct inode *inode = fp->f_inode;
	uint64_t unique_id = inode->i_rdev;

	if (copy_to_user((void *)arg, (void *)&unique_id, sizeof(unique_id))) {
		cn_dev_core_err(core, "copy_to_user failed.");
		ret = -EFAULT;
	}

	return ret;
}

int camb_get_mlu_id(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	if (copy_to_user((void *)arg, (void *)&core->idx,
				sizeof(core->idx))) {
		cn_dev_core_err(core, "copy_to_user failed.");
		ret = -EFAULT;
	}

	return ret;
}

int camb_rd_driver_version(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	unsigned int driver_serial_number[DRV_SERIAL_NUM_LEN] = {0};
	uint32_t proj_id = cn_core_get_proj_id(core);

	driver_serial_number[1] = VENDOR_TO_SERIAL(
			VENDOR_CAMBRICON) | PROJ_TO_SERIAL(proj_id);

	driver_serial_number[0] = CHIPVERSION_TO_SERIAL(
			CHIP_V1_0_ES) | DRVVERSION_TO_SERIAL(DRV_VERSION);

	if (copy_to_user((void *)arg, (void *)driver_serial_number,
				sizeof(unsigned int) * DRV_SERIAL_NUM_LEN)) {
		cn_dev_core_err(core, "<RD_DRIVER_VERSION> copy to user failed!");
		ret = -EFAULT;
	}

	return ret;
}

int camb_get_device_attr_v1(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	u8 attr_max = CAMB_GET_DEVICE_ATTR_V1_MAX;
	struct c20_device_attr attr = {};
	unsigned int *data = NULL;
	struct bus_info_s bus_info = {};
	struct sbts_info_s sbts_info = {};
	struct smlu_cgroup_res *res;

	if (copy_from_user((void *)&attr, (void *)arg,
				sizeof(struct c20_device_attr))) {
		cn_dev_core_err(core, "get device attribute failed!");
		ret = -EFAULT;
		return ret;
	}

	if (attr.size < 0) {
		cn_dev_core_err(core, "invalid attribute buf size %d", attr.size);
		ret = -EFAULT;
		return ret;
	}

	data = cn_kzalloc(CAMB_GET_DEVICE_ATTR_V1_MAX * sizeof(unsigned int),
			GFP_KERNEL);
	if (unlikely(!data)) {
		cn_dev_core_info(core, "alloc attribute data failed!");
		ret = -EFAULT;
		return ret;
	}

	if (attr.size >= 21) {
		/**< Maximum cluster of the device */
		data[0] = core->board_info.cluster_num;
		/**< Maximum MLU core of the per cluster */
		data[1] = core->board_info.ipu_core_num;
		/**< the type of the mlu core */
		data[2] = _1M;
		if (core->device_id == MLUID_370) {
			data[2] = _1V;
		}
		/**< Device has ECC support enabled */
		data[3] = core->board_info.ecc_support;
		/**< memory clock frequency in kilohertz */
		data[4] = core->board_info.ddr_freq * 1000;
		/**< Maximum Cluster clock frequency in kilohertz */
		data[5] = core->board_info.rated_ipu_freq * 1000;
		/**< PCI bus ID of the device */
		memset(&bus_info, 0, sizeof(struct bus_info_s));
		cn_bus_get_bus_info(core->bus_set, &bus_info);
		if (bus_info.bus_type == BUS_TYPE_EDGE) {
			data[6] = 0;
			data[7] = 0;
			data[8] = 0;
		} else {
			data[6] = bus_info.info.pcie.bus_num;
			/**< PCI device ID of the device */
			data[7] = bus_info.info.pcie.device_id;
			/**< PCI domain ID of the device */
			data[8] = bus_info.info.pcie.domain_id;
		}
		/**< Maximum stack memory available per MLU Core in MB */
		data[9] = core->board_info.stack_size;
		/**< Maximum sram memory available per MLU Core in bytes */
		data[10] = core->board_info.sram_size;
		/**< Maximum available total memory in MB */
		data[11] = core->board_info.total_memory >> 20;

		res = cn_kmalloc(sizeof(*res), GFP_KERNEL);
		if (res == NULL) {
			cn_kfree(data);
			return -EFAULT;
		}

		/* correct to split size */
		ret = cn_smlu_query_namespace_quota(core, mem_cgrp_id, NULL, res);
		if (ret == 0) {/* smlu enabled && name space in rbtree */
			cn_dev_core_debug(core, "correct total_memory 0x%llx MB -> 0x%llx MB",
					core->board_info.total_memory >> 20, res->max >> 20);
			data[11] = (res->max >> 20);
		} else
			ret = 0;

		cn_kfree(res);

		/**< Global memory bus width in bits */
		data[12] = core->board_info.bus_width;
		/**< Size of system cache in bytes */
		data[13] = core->board_info.cache_size;
		/**< Maximum block dimension X */
		data[14] = core->board_info.max_dimx;
		/**< Maximum block dimension Y */
		data[15] = core->board_info.max_dimy;
		/**< Maximum block dimension Z */
		data[16] = core->board_info.max_dimz;
		/**< Maximum queue count */
		data[17] = core->board_info.max_queue;
		/**< Maximum notifier count */
		data[18] = core->board_info.max_notifier;
		/**< Specifies whether there is a run time limit on kernels */
		data[19] = core->board_info.o_kc_limit;
		/**< Device supports queue priorities */
		data[20] = core->board_info.queue_prio_support;
	}

	if (attr.size >= 24) {
		cn_sbts_get_sbts_info(core, &sbts_info);
		/* change sram to its real size */
		data[10] = sbts_info.shared_mem_size;
		/* Device ctram size */
		data[21] = sbts_info.ct_ram_size;
		/* Device ltram size */
		data[22] = sbts_info.lt_ram_size;
		data[23] = core->board_info.mem_channel;
	}

	attr_max = min_t(u32, attr.size, CAMB_GET_DEVICE_ATTR_V1_MAX);
	if (copy_to_user(attr.data, data,
				attr_max * sizeof(unsigned int))) {
		cn_dev_core_info(core,
				"return device attribute failed!");
		ret = -EFAULT;
	}

	cn_kfree(data);

	return ret;
}

int camb_get_device_attr(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_device_attr attr;
	unsigned int *data = NULL;
	struct cndev_attr_set *attr_set = NULL;
	u32 attr_cnt = 0;

	if (IS_ERR_OR_NULL(core->attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return -EFAULT;
	}
	attr_set = core->attr_set;

	if (copy_from_user((void *)&attr, (void *)arg,
				sizeof(struct cn_device_attr))) {
		cn_dev_core_err(core, "get device attribute failed!");
		ret = -ENOMEM;
		return ret;
	}

	if (attr.cnt < 0) {
		cn_dev_core_err(core, "invalid attribute buf count %d", attr.cnt);
		ret = -EINVAL;
		return ret;
	}

	if (attr.version < attr_set->attr_info.head.version) {
		ret = -EINVAL;
		return ret;
	}
	attr_cnt = min_t(u32, attr.cnt, CN_DEVICE_ATTRIBUTE_MAX);

	data = cn_kzalloc(CN_DEVICE_ATTRIBUTE_MAX *
			sizeof(unsigned int), GFP_KERNEL);
	if (unlikely(!data)) {
		cn_dev_core_info(core, "alloc attribute data failed!");
		ret = -ENOMEM;
		cn_kfree(data);
		return ret;
	}

	cn_get_attribute_info(core, (void *)&attr, data);

	if (copy_to_user(attr.data, data, attr_cnt * sizeof(unsigned int))) {
		cn_dev_core_info(core, "return device attribute failed!");
		ret = -ENOMEM;
	}

	cn_kfree(data);

	return ret;
}

int camb_get_device_private_attr(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	ret = cn_get_attribute_info_v2(core, arg);
	return ret;
}

int camb_get_device_name(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	ret = cn_get_device_name(core, arg);
	return ret;
}

int camb_get_device_work_mode(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	ret = cn_get_device_work_mode(core, arg);
	return ret;
}

int camb_get_device_unique_id(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	ret = cn_get_device_unique_id(fp, core, arg);
	return ret;
}

static void api_limit_low_ver_update(int *major, int *minor, int *patch)
{
	uint32_t proj_id;
	int card_idx;
	struct cn_core_set *core;
	bool update = true;

	for (card_idx = 0; card_idx < MAX_PHYS_CARD; card_idx++) {
		core = cn_core_get_ref(card_idx);
		if (!core) {
			continue;
		}
		proj_id = cn_core_get_proj_id(core);

		/* note: default will be 2.7.0 at least
		*     For 300/200/edge/ce: need capcity to 2.0.0
		*     For 500 and later: need 2.7.0 or higher because of lt freq
		*/
		if (!isEdgePlatform(core) && (proj_id >= C50_PROJ)) {
			update = false;
		}
		cn_core_put_deref(core);
	}

	/* cn_core_lt_cap_enable just for debug */
	if (update || (!cn_core_lt_cap_enable())) {
		*minor = 0;
	}
}

int camb_get_api_limit_ver(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	uint32_t proj_id = cn_core_get_proj_id(core);
	struct camb_drv_support_api_ver api_ver = {
		.low_major  = SUPPORT_API_VER_LOW_MAJOR,
		.low_minor  = SUPPORT_API_VER_LOW_MINOR,
		.low_build  = SUPPORT_API_VER_LOW_BUILD,
		.high_major = SUPPORT_API_VER_HIGH_MAJOR,
		.high_minor = SUPPORT_API_VER_HIGH_MINOR,
		.high_build = SUPPORT_API_VER_HIGH_BUILD,
	};

	if ((!cn_core_lt_cap_enable())
		|| isEdgePlatform(core) || (proj_id < C50_PROJ)) {
		api_ver.low_minor = 0;
	}

	if (copy_to_user((void *)arg, (void *)&api_ver,
				sizeof(struct camb_drv_support_api_ver))) {
		cn_dev_core_err(core, "copy_to_user failed.");
		ret = -EFAULT;
	}

	return ret;
}

int camb_driver_capability(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	ret = cn_get_driver_capability(core, (void *)arg);
	return ret;
}

typedef int (*attr_ioctl_func)(struct file *fp, unsigned long arg,
	unsigned int cmd, struct cn_core_set *core);

static const struct {
	attr_ioctl_func funcs;
	u64 flags;
} attr_funcs[ATTR_MAX_NR_COUNT] = {
	[_CAMB_GET_MLU_ID_NR] = {camb_get_mlu_id, 0},
	[_CAMB_RD_DRIVER_VERSION_NR] = {camb_rd_driver_version, 0},

	/** old driver api */
	[_CAMB_GET_DEVICE_ATTR_V1_NR] = {camb_get_device_attr_v1, 0},
	/** new driver api ver 4.8  */
	[_CAMB_GET_DEVICE_ATTR_NR] = {camb_get_device_attr, 0},

	[_CAMB_GET_DEVICE_PRIVATE_ATTR_NR] = {camb_get_device_private_attr, 0},
	[_CAMB_GET_DEVICE_NAME_NR] = {camb_get_device_name, 0},
	[_CAMB_GET_DEVICE_WORK_MODE_NR] = {camb_get_device_work_mode, 0},
	[_CAMB_GET_DEVICE_UNIQUE_ID_NR] = {camb_get_device_unique_id, 0},
	[_CAMB_GET_API_LIMIT_VER_NR] = {camb_get_api_limit_ver, 0},
	[_CAMB_DRIVER_CAPABILITY_NR] = {camb_driver_capability, 0},
};

long cn_attr_ioctl(struct file *fp, struct cn_core_set *core, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	unsigned int ioc_nr = _IOC_NR(cmd);

	if (attr_funcs[ioc_nr].funcs) {
		ret = attr_funcs[ioc_nr].funcs(fp, arg, cmd, core);
	} else {
		cn_dev_core_err(core, "IOCTRL command mismatch! %d", cmd);
		return -EINVAL;
	}

	return ret;
}

u64 g_drv_to_api_seq;
static long cn_get_driver_info(struct file *fp, unsigned int cmd, unsigned long arg)
{
	struct cndrv_cmd_header *cmd_header;
	struct driver_info_ioctl_st *drv_cmd_st;
	struct driver_info_st *driver_info;
	struct dev_info_s *phys_dev_info;
	unsigned int dev_max_count, ipcm_max_count;
	unsigned int msg_size, cpy_size;
	long ret = 0;
	u64 seq;

	cmd_header = cn_kzalloc(sizeof(*cmd_header), GFP_KERNEL);
	if (!cmd_header) {
		cn_dev_err("cn_kzalloc cmd_header failed");
		return -ENOMEM;
	}

	if (copy_from_user((void *)cmd_header, (void *)arg, sizeof(*cmd_header))) {
		cn_dev_err("copy_from_user failed");
		ret = -EFAULT;
		goto free_drv_cmd_header;
	}

	msg_size = cmd_header->msg_size;

	drv_cmd_st = cn_kzalloc(sizeof(*drv_cmd_st), GFP_KERNEL);
	if (!drv_cmd_st) {
		cn_dev_err("cn_kzalloc drv_cmd_st failed");
		ret = -ENOMEM;
		goto free_drv_cmd_header;
	}

	cpy_size = min((unsigned int)(msg_size + sizeof(*cmd_header)),
			(unsigned int)_IOC_SIZE(cmd));
	if (copy_from_user((void *)drv_cmd_st, (void *)arg, cpy_size)) {
		cn_dev_err("copy_from_user failed");
		ret = -EFAULT;
		goto free_drv_cmd_st;
	}

	dev_max_count = drv_cmd_st->dev_max_count;
	ipcm_max_count = drv_cmd_st->ipcm_max_count;

	driver_info = cn_kzalloc(sizeof(*driver_info), GFP_KERNEL);
	if (!driver_info) {
		cn_dev_err("cn_kzalloc driver_info failed");
		ret = -ENOMEM;
		goto free_drv_cmd_st;
	}

	/* version info */
	driver_info->low_ver.major = SUPPORT_API_VER_LOW_MAJOR;
	driver_info->low_ver.minor = SUPPORT_API_VER_LOW_MINOR;
	driver_info->low_ver.patch = SUPPORT_API_VER_LOW_BUILD;

	driver_info->high_ver.major = SUPPORT_API_VER_HIGH_MAJOR;
	driver_info->high_ver.minor = SUPPORT_API_VER_HIGH_MINOR;
	driver_info->high_ver.patch = SUPPORT_API_VER_HIGH_BUILD;

	api_limit_low_ver_update(&driver_info->low_ver.major,
			&driver_info->low_ver.minor, &driver_info->low_ver.patch);

	driver_info->curr_ver.major = DRV_MAJOR;
	driver_info->curr_ver.minor = DRV_MINOR;
	driver_info->curr_ver.patch = DRV_BUILD;

	/* drv_global_seq_num */
	seq = __sync_add_and_fetch(&g_drv_to_api_seq, 1);
	driver_info->drv_global_seq_num = seq;

	/* vendor id */
	driver_info->vendor_id = VENDOR_CAMBRICON;

	/* device num */
	phys_dev_info = cn_kzalloc(sizeof(*phys_dev_info), GFP_KERNEL);
	if (!phys_dev_info) {
		cn_dev_err("cn_kzalloc phys_dev_info failed");
		ret = -ENOMEM;
		goto free_driver_info;
	}

	cn_core_get_phys_dev_info(phys_dev_info);
	driver_info->device_num = min((unsigned int)phys_dev_info->dev_num,
					(unsigned int)dev_max_count);

	/* device unique id */
	cpy_size = min((unsigned int)dev_max_count, (unsigned int)MAX_PHYS_CARD);
	memcpy(driver_info->dev_unique_id, phys_dev_info->unique_id,
		sizeof(uint64_t) * cpy_size);

	/* ipcm num */
#ifndef CONFIG_CNDRV_EDGE
	driver_info->ipcm_num = min((unsigned int)driver_info->device_num,
					(unsigned int)ipcm_max_count);
#else
	driver_info->ipcm_num = min((unsigned int)ipcm_get_device_count(),
					(unsigned int)ipcm_max_count);
#endif

	/* copy to user */
	cpy_size = min((unsigned int)sizeof(*driver_info),
			(unsigned int)drv_cmd_st->cmd_header.out_buffer_size);
	if (copy_to_user((void *)drv_cmd_st->cmd_header.out_buffer,
			(void *)driver_info, cpy_size)) {
		cn_dev_err("copy_to_user failed.");
		ret = -EFAULT;
	}

	cn_kfree(phys_dev_info);

free_driver_info:
	cn_kfree(driver_info);
free_drv_cmd_st:
	cn_kfree(drv_cmd_st);
free_drv_cmd_header:
	cn_kfree(cmd_header);

	return ret;
}

static long cn_get_device_info(struct file *fp, unsigned int cmd, unsigned long arg)
{
	struct cndrv_cmd_header *cmd_header;
	struct device_info_ioctl_st *dev_cmd_st;
	struct device_basic_info_st *device_info;
	struct cn_core_set *core;
	struct dev_info_s *sub_dev_info;
	unsigned int sub_dev_max_count;
	unsigned int ipcm_major, ipcm_minor;
	uint64_t unique_id;
	unsigned int msg_size, cpy_size;
	long ret = 0;

	cmd_header = cn_kzalloc(sizeof(*cmd_header), GFP_KERNEL);
	if (!cmd_header) {
		cn_dev_err("cn_kzalloc cmd_header failed");
		return -ENOMEM;
	}

	if (copy_from_user((void *)cmd_header, (void *)arg, sizeof(*cmd_header))) {
		cn_dev_err("copy_from_user failed");
		ret = -EFAULT;
		goto free_dev_cmd_header;
	}

	msg_size = cmd_header->msg_size;

	dev_cmd_st = cn_kzalloc(sizeof(*dev_cmd_st), GFP_KERNEL);
	if (!dev_cmd_st) {
		cn_dev_err("cn_kzalloc dev_cmd_st failed");
		ret = -ENOMEM;
		goto free_dev_cmd_header;
	}

	cpy_size = min((unsigned int)(msg_size + sizeof(*cmd_header)),
			(unsigned int)_IOC_SIZE(cmd));
	if (copy_from_user((void *)dev_cmd_st, (void *)arg, cpy_size)) {
		cn_dev_err("copy_from_user failed");
		ret = -EFAULT;
		goto free_dev_cmd_st;
	}

	sub_dev_max_count = dev_cmd_st->mi_max_num;

	device_info = cn_kzalloc(sizeof(*device_info), GFP_KERNEL);
	if (!device_info) {
		cn_dev_err("cn_kzalloc device_info failed");
		ret = -ENOMEM;
		goto free_dev_cmd_st;
	}

	/* this unique_id maybe any mode, i.e. FULL,MIM_EN,MI,SMLU */
	unique_id = dev_cmd_st->dev_unique_id;
	core = cn_core_get_with_unique_id(unique_id);
	if (!core) {
		cn_dev_err("invalid unique_id:%lld", unique_id);
		ret = -ENODEV;
		goto free_device_info;
	}

	/* device type */
	device_info->device_type = cn_core_get_work_mode(core);

	/* project id */
	device_info->project_id = cn_core_get_proj_id(core);

	/* device index, smlu index is same with pf core? */
	device_info->index = core->idx;

	/* instance id */
	device_info->instance_id = core->vf_idx; // MI: core->vf_idx

	if (device_info->device_type == SMLU) {
		struct cnhost_minor *minor;

		minor = cnhost_dev_minor_acquire(MAJOR(unique_id), MINOR(unique_id));
		if (IS_ERR_OR_NULL(minor)) {
			cn_dev_core_err(core, "invalid unique_id:%d:%d", MAJOR(unique_id), MINOR(unique_id));
			ret = -ENODEV;
			cn_core_put(core);
			goto free_device_info;
		}
		device_info->instance_id = minor->dev->vf_index;
		cnhost_dev_minor_release(minor);
	}

	/* device_handle is used same as cnmon, i.e. pf_card | (vf_card << 8),
	 * now construct it in driver, provided to cnmon also cndrv and cndev */
	device_info->device_handle = (core->pf_idx & 0xff) |
		((device_info->instance_id & 0xff) << 8);

	/* ipcm unique_id */
	if (device_info->device_type == MI) {
		device_info->ipcm_unique_id = 0;
	} else {
		ipcm_major = cn_ipcm_get_rpmsg_major();
		ipcm_minor = MINOR(unique_id);
		device_info->ipcm_unique_id = MKDEV(ipcm_major, ipcm_minor);
	}

	/* sub dev num */
	sub_dev_info = cn_kzalloc(sizeof(*sub_dev_info), GFP_KERNEL);
	if (!sub_dev_info) {
		cn_dev_err("cn_kzalloc sub_dev_info failed");
		ret = -ENOMEM;
		cn_core_put(core);
		goto free_device_info;
	}

	cn_core_get_sub_dev_info(core, sub_dev_info);
	device_info->sub_dev_num = min((unsigned int)sub_dev_info->dev_num,
					(unsigned int)sub_dev_max_count);

	// put the core after cn_core_get_with_unique_id
	cn_core_put(core);

	/* sub dev unique_id */
	cpy_size = min((unsigned int)sub_dev_max_count, (unsigned int)sub_dev_info->dev_num);
	memcpy(device_info->sub_dev_unique_id, sub_dev_info->unique_id,
				sizeof(uint64_t) * cpy_size);

	/* copy to user */
	cpy_size = min((unsigned int)sizeof(*device_info),
			(unsigned int)dev_cmd_st->cmd_header.out_buffer_size);
	if (copy_to_user((void *)dev_cmd_st->cmd_header.out_buffer,
			(void *)device_info, cpy_size)) {
		cn_dev_err("copy_to_user failed.");
		ret = -EFAULT;
	}

	cn_kfree(sub_dev_info);

free_device_info:
	cn_kfree(device_info);
free_dev_cmd_st:
	cn_kfree(dev_cmd_st);
free_dev_cmd_header:
	cn_kfree(cmd_header);

	return ret;
}

long cn_attr_ctl_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	u64 seq;

	switch (cmd) {
	case CAMB_GET_API_GLOBAL_SEQ: {
		seq = __sync_add_and_fetch(&g_drv_to_api_seq, 1);
		if (copy_to_user((void *)arg, (void *)&seq,
					sizeof(u64))) {
			cn_dev_err("copy_to_user failed.");
			ret = -EFAULT;
		}
		break;
	}
	case CAMB_GET_DRIVER_INFO: {
		ret = cn_get_driver_info(fp, cmd, arg);
		break;
	}
	case CAMB_GET_DEVICE_INFO: {
		ret = cn_get_device_info(fp, cmd, arg);
		break;
	}
	default:
		cn_dev_err("IOCTRL command mismatch! %d", cmd);
		ret = -EINVAL;
	}

	return ret;
}
