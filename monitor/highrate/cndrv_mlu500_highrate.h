#ifndef __CAMBRICON_DIRECT_CNDRV_MONITOR_MLU500_H__
#define __CAMBRICON_DIRECT_CNDRV_MONITOR_MLU500_H__

#include "cndrv_bus.h"
#include "./axi_monitor/cndrv_axi_monitor.h"
#include "cndrv_monitor_highrate.h"

int mlu500_pfmu_get_monitor_info_by_phyid(void *mset,
	int phy_cid,
	int core_id,
	int *table_index);
int mlu500_pfmu_ipu_map_info(void *mset,
	int phy_cid,
	int logic_cid,
	void *map_info);
int mlu500_pfmu_tinycore_map_info(void *mset,
	int phy_cid,
	int logic_cid,
	int internal_phy_cid,
	int smmu_group_id,
	void *map_info);
int mlu500_pfmu_hubtrace_l2p(void *mset,
	struct pfmu_hubtrace_l2p *l2p_info);
int mlu500_pfmu_hubtrace_map_info(void *mset,
	void *map_info);

unsigned long mlu500_copy_data_from_devbuf(
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size);
unsigned long mlu500_dummy_flush_data(
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size);
int mlu500_dummy_mem_mmap_kernel(void *context);
int mlu500_dummy_mem_unmmap_kernel(void *context);

#endif
