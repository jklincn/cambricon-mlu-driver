/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2019 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_CNDRV_ATTR_H__
#define __CAMBRICON_CNDRV_ATTR_H__

#include "cndrv_core.h"

#define CAMB_GET_DEVICE_ATTR_V1_MAX 32

enum cndev_attr_version {
	ATTR_VERSION1 = 1,
	ATTR_VERSION2 = 2,
	ATTR_VERSION3 = 3,
	ATTR_VERSION = ATTR_VERSION3,
	ATTR_VERSION_END,
};

enum resource_name {
	/*refer 'enum board_id'*/
	RES_BOARD_ID,
	/*0 - */
	RES_WAFER_VERSION,
	/*0 - */
	RES_CHIP_VERSION,
	/*memory channel number*/
	RES_MEM_CHANNEL_NUM,
	/*Per channel in MByte*/
	RES_MEM_CAP_PER_CHNL,
	/*ipu cluster number */
	RES_IPU_CLUSTER_NUM,
	/*ipu cluster num in mask, normal 270: 0x0F*/
	RES_IPU_CLUSTER_MASK,
	/*ipu number in each cluster*/
	RES_IPU_CORE_PER_CLTR,
	/*memcore number in each cluster*/
	RES_IPU_MEMC_PER_CLTR,
	/*scalar number in mask*/
	RES_SCALAR_MASK,
	/*vpu cluster number in dec*/
	RES_VPU_CLUSTER_NUM,
	/*vpu cluster num in mask, normal 270: 0x3F*/
	RES_VPU_CLUSTER_MASK,
	/*vpu decoder only num in mask, normal 270: 0x3A*/
	RES_VPU_DECODER_MASK,
	/*vpu codec(encoder/decoder) num in mask, normal 270: 0x05*/
	RES_VPU_CODEC_MASK,
	RES_VPU_ENCODER_MASK = RES_VPU_CODEC_MASK,
	/*jpu cluster num in mask, normal 270: 0x3F*/
	/*jpu sub-system always include in vpu system*/
	RES_JPU_NUMBER_MASK,
	/*return chip is numa*/
	RES_IS_NUMA,
	/*phy ipu cluster mask*/
	RES_IPU_CLUSTER_PHYBIT,
	/*Die cnt*/
	RES_DIE_COUNT,
	/*tiny mask*/
	RES_TINYCORE_MASK,
	/*for memory base addr*/
	RES_MEM_BASE_IN_CHNL,
	RES_LLC_NUM,
	RES_C2C_PORT_COUNT,
	RES_JPU_NUM,
	RES_C2C_PORT_MASK,
	RES_DIE_BOARD_TYPE,
	/*BAD HBM ID, only for MLU590*/
	RES_BAD_HBM_ID,
	RES_MEM_HBM_NUMS,
	RES_MEM_HBM_CAPACITY,
	RES_ISSE_SUPPORT,
	RES_SPM_SUPPORT,
	RES_IPU_FULL_CLUSTER_NUM,
	RES_CHIP_ID,
	RES_GDMA_COUNT,
	RES_GDMA_MASK,
	RES_TNC_CAP_RW_PCIE_OUTB_MASK,

	/* NEW CODEC RESOURCE VALUE */
	RES_MAX_VENC_NUM,
	RES_VENC_MASK,
	RES_MAX_VDEC_NUM,
	RES_VDEC_MASK,
	RES_MAX_JPU_NUM,
	RES_JPU_MASK,

	RES_LLC_EVENT_TIMEOUT_LIMIT,
	RES_SUPPORT_COMPRESS,
	RES_MEM_MASK,
	RES_MIM_DISABLE,

	/* 0- */
	RES_MLU_PLAT_ID,
	RES_BASIC_INFO_END,

	RES_NAME_END,
};

int cn_attr_init(struct cn_core_set *core);
void cn_attr_exit(struct cn_core_set *core);
void cn_attr_update_aiisp(struct cn_core_set *core, __u32 nn_num, __u32 isp_num);
int cn_attr_late_init(struct cn_core_set *core);
void cn_attr_late_exit(struct cn_core_set *core);
long cn_attr_ioctl(struct file *fp, struct cn_core_set *core, __u32 cmd, unsigned long arg);
long cn_attr_ctl_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);
int cn_attr_init_attr_vf(struct cn_core_set *core);
void cn_attr_exit_attr_vf(struct cn_core_set *core);
int cn_attr_get_resource(struct cn_core_set *core, u32 res_index, u64 *value);
int cn_attr_fill_resource(struct cn_core_set *core, void *resource, u32 res_len);
void cn_get_attribute_info(struct cn_core_set *core, void *attr, unsigned int *data);
void cn_get_extra_attribute_info(struct cn_core_set *core, unsigned int *data, int attr_cnt);

#endif
