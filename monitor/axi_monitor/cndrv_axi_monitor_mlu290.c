#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>


#include "cndrv_bus.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_monitor_usr.h"
#include "../monitor.h"
#include "cndrv_axi_monitor.h"

#define MLU290_HUB0_MONITOR_CNT 29
#define MLU290_HUB1_MONITOR_CNT 32
#define MLU290_HUB2_MONITOR_CNT 31
#define MLU290_HUB3_MONITOR_CNT 30

struct cn_axi_monitor_config mlu290_config[MLU290_MAX_AXI_MON_NUM] = {
	{MLU290_CPUGIC__AXIMHUB_0_IRQ, MLU290_HUB0_MONITOR_CNT,
		0x20000, aximhub_mlu200_intr_handle, ((1ULL << MLU290_HUB0_MONITOR_CNT) - 1)},
	{MLU290_CPUGIC__AXIMHUB_1_IRQ, MLU290_HUB1_MONITOR_CNT,
		0x21000, aximhub_mlu200_intr_handle, ((1ULL << MLU290_HUB1_MONITOR_CNT) - 1)},
	{MLU290_CPUGIC__AXIMHUB_2_IRQ, MLU290_HUB2_MONITOR_CNT,
		0x22000, aximhub_mlu200_intr_handle, ((1ULL << MLU290_HUB2_MONITOR_CNT) - 1)},
	{MLU290_CPUGIC__AXIMHUB_3_IRQ, MLU290_HUB3_MONITOR_CNT,
		0x23000, aximhub_mlu200_intr_handle, ((1ULL << MLU290_HUB3_MONITOR_CNT) - 1)},
};

struct cn_aximhub_ops aximon_mlu290_ops = {
	.stop_hub = axihub_mlu200s_stop_hub,
	.start_hub = axihub_mlu200s_start_hub,
};

struct cn_aximon_zone_info mlu290_zone_info = {
	/*interrupt is trigged every zone size bytes*/
	ZONE_SIZE_16MB,
	ZONE_CONUT,
	/*device buffer size*/
	DEV_BUFFER_SIZE(ZONE_SIZE_16MB, ZONE_CONUT),
	/*raw data count per zone, 32bytes unit*/
	PFMU_RAW_DATA_COUNT_PER_ZONE(ZONE_SIZE_16MB),
	/*raw mode, request min block count to malloc memory, 32bytes per block*/
	MIN_RAW_RING_BUFFER_BLOCK_COUNT(ZONE_SIZE_16MB),
};

void mlu290_axi_monitor_config(void *p)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)p;
	u64 *res_param = monitor_set->res_param;

	monitor_set->hub_num = MLU290_MAX_AXI_MON_NUM;
	monitor_set->config = mlu290_config;
	monitor_set->ops = aximon_mlu290_ops;
	monitor_set->highrate_mode = AXI_MONITOR_NORMAL_MODE;
	monitor_set->parse_ops = NULL;
	monitor_set->monitor_ops = NULL;
	monitor_set->zone_info = &mlu290_zone_info;
	monitor_set->support_data_mode = (1ULL << AXIM_NORMAL_MODE);
	if (res_param) {
		res_param[PMU_MONITOR_SIZE] = sizeof(struct axi_monitor_data);
		res_param[PMU_LLC_PERF_SIZE] = sizeof(struct monitor_llc_perf_data);
		res_param[PMU_IPU_PERF_SIZE] = sizeof(struct pmu_pfmu_perf_data_s);
		res_param[PMU_SMMU_PERF_SIZE] = sizeof(struct monitor_smmu_perf_data);
		res_param[PMU_SMMU_EXP_SIZE] = sizeof(struct monitor_smmu_exception_data);
		res_param[PMU_L1C_PERF_SIZE] = sizeof(struct monitor_l1c_perf_data);
		res_param[PMU_VALID_HBM_MASK] = 0;
		res_param[PMU_TOTAL_TINYCORE_CLUSTER_NUM] = 0;
		res_param[PMU_VALID_TINYCORE_MASK] = 0;
	}
}

