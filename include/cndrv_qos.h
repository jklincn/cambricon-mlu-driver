/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_NOC_QOS_H__
#define __CAMBRICON_NOC_QOS_H__


#include "cndrv_core.h"

#define QOS_NAME_LEN         32
#define MLU2X0_QOS_WEIGHT_MASK		(0xFFFFFF00)
enum cndev_qos_group {
	CNDEV_QOS_IPU = 0,
	CNDEV_QOS_VPU = 1,
	CNDEV_QOS_PCIE = 2,
	CNDEV_QOS_MAX
};

struct cndev_qos_info_s {
	u16 max_value;
	u16 min_value;
	u16 default_value;
	u32 reg32;

	char name[QOS_NAME_LEN];
};

struct cndev_qos_data_s {
	struct cndev_qos_info_s *qos_info;
	u32 cnt;
};

struct cndev_qos_policy {

	u32 qos_policy;
	u32 qos_base;
	u32 qos_up;
	u32 group_id;
};

struct cndev_qos_detail_info {

	u16 qos_desc_num;
	struct cndev_qos_desc *desc;
};

struct cndev_qos_desc_info_s {
	struct cndev_qos_info_s *desc;
	u16 cnt;
};

struct cndev_qos_setting_s {
	u8 max_qos_base;
	u8 max_qos_up;
	u8 min_qos_base;
	u8 min_qos_up;

	u32 qos_group_count;
};

struct cndev_qos_conf_s {

	struct cndev_qos_desc_info_s qos[CNDEV_QOS_MAX];

	struct cndev_qos_setting_s *qos_setting;
};

extern int noc_qos_reset_common(void *core_set);
extern int noc_qos_policy_common(void *core_set,
				struct cndev_qos_policy *qos_info);
extern int noc_qos_desc_common(void *core_set,
				struct cndev_qos_detail_info *qos_info);
extern int set_qos_group_weight(void *core_set, u8 qos_weight,
		enum cndev_qos_group group);
extern int set_qos_weight(void *core_set,
		u8 qos_weight, enum cndev_qos_group group, int index);
extern int cndev_qos_init(void *core_set);
extern int noc_qos_reset_bandwidth(void *core_set);
extern int set_qos_group_bandwidth(void *core_set, u16 bandwidth, enum cndev_qos_group group);
extern int set_qos_bandwidth(void *core_set, u16 bandwidth, enum cndev_qos_group group, u32 items);

#endif
