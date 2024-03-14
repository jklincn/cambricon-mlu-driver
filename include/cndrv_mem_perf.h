/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2023 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CNDRV_MEM_PERF_H__
#define __CNDRV_MEM_PERF_H__

#include <linux/version.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>

#include "monitor/monitor.h"
#include "camb_mm.h"

int cn_mem_perf_version_check(void *fp, struct cn_core_set *core,
		__u64 papi_version, __u64 *feature_data, __u64 fdata_len, __u64 *perf_version);
int cn_mem_perf_init(struct cn_mm_set *mm_set);
void cn_mem_perf_exit(struct cn_mm_set *mm_set);
int cn_mem_perf_enable(__u64 tag);
u64 cn_mem_perf_get_version(void *fp, struct cn_core_set *core);

int cn_mem_perf_private_data_init(struct fp_priv_data *data);
void cn_mem_perf_private_data_exit(struct fp_priv_data *priv_data);
void cn_mem_perf_tgid_entry_show(struct seq_file *m, struct cn_core_set *core);
int cn_mem_perf_mode_config(void *fp, struct cn_core_set *core,
		struct __perf_mode_cfg *mode_cfg, struct perf_cfg_data __perf_cfg_data);
int cn_mem_perf_put_details(__u64 correlation_id, struct mapinfo *pminfo, u64 entry_type);
int cn_mem_perf_tsinfo_size_get(void *fp, struct cn_core_set *core, struct perf_info_size_get *size_get);
int cn_mem_perf_task_type_config(void *fp, struct cn_core_set *core, struct perf_task_type_config *config);
int cn_mem_perf_task_type_config_v2(void *fp, struct cn_core_set *core,
		u64* cfg_data, u32 len, struct perf_task_type_config_v2 *config);
int cn_mem_perf_tsinfo_get(void *fp, struct cn_core_set *core, struct perf_task_info_get *info_get);
int __task_type_is_mem(u64 task_type);

#endif  /* __CNDRV_MEM_PERF_H__ */
