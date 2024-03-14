#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/init.h>


#include "cndrv_bus.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_monitor_usr.h"
#include "../monitor.h"
#include "cndrv_axi_monitor.h"
#include "./highrate/cndrv_monitor_highrate.h"

irqreturn_t aximhub_mlu370_intr_handle(int index, void *data);

#define MLU370_HUB0_MONITOR_CNT 15
#define MLU370_HUB1_MONITOR_CNT 18
#define MLU370_HUB2_MONITOR_CNT 18
#define MLU370_HUB3_MONITOR_CNT 18
#define MLU370_HUB4_MONITOR_CNT 15
#define MLU370_HUB5_MONITOR_CNT 18
#define MLU370_HUB6_MONITOR_CNT 18
#define MLU370_HUB7_MONITOR_CNT 18

struct cn_axi_monitor_config mlu370_config[MLU370_DOUBLE_DIE_MAX_AXI_MON_NUM] = {
	{MLU370_AXIMHUB_0_IRQ, MLU370_HUB0_MONITOR_CNT,
		0x8349000, aximhub_mlu370_intr_handle, ((1ULL << MLU370_HUB0_MONITOR_CNT) - 1), 0x0},
	{MLU370_AXIMHUB_1_IRQ, MLU370_HUB1_MONITOR_CNT,
		0x349000, aximhub_mlu370_intr_handle, ((1ULL << MLU370_HUB1_MONITOR_CNT) - 1), 0x0},
	{MLU370_AXIMHUB_2_IRQ, MLU370_HUB2_MONITOR_CNT,
		0x8348000, aximhub_mlu370_intr_handle, 0XFF, 0x3FF00},
	{MLU370_AXIMHUB_3_IRQ, MLU370_HUB3_MONITOR_CNT,
		0x348000, aximhub_mlu370_intr_handle, 0XFF, 0x3FF00},
	{MLU370_AXIMHUB_4_IRQ, MLU370_HUB4_MONITOR_CNT,
		0x18349000, aximhub_mlu370_intr_handle, ((1ULL << MLU370_HUB4_MONITOR_CNT) - 1), 0x0},
	{MLU370_AXIMHUB_5_IRQ, MLU370_HUB5_MONITOR_CNT,
		0x10349000, aximhub_mlu370_intr_handle, ((1ULL << MLU370_HUB7_MONITOR_CNT) - 1), 0x0},
	{MLU370_AXIMHUB_6_IRQ, MLU370_HUB6_MONITOR_CNT,
		0x18348000, aximhub_mlu370_intr_handle, 0XFF, 0x3FF00},
	{MLU370_AXIMHUB_7_IRQ, MLU370_HUB7_MONITOR_CNT,
		0x10348000, aximhub_mlu370_intr_handle, 0XFF, 0x3FF00},
};

struct cn_aximon_zone_info mlu370_zone_info = {
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

irqreturn_t aximhub_mlu370_intr_handle(int index, void *data)
{
	struct cambr_amh_hub *axi_set = (struct cambr_amh_hub *)data;
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	u32 reg = 0;
	u32 clear_reg = 0;
	u8 data_buff_index = 0;

	reg = reg_read32(core->bus_set, axi_set->base + 0x13c);

	if (axihub_highrate_mode(axi_set)) {
		reg = 3;
		reg_write32(core->bus_set, axi_set->base + 0x13c, reg);
		return IRQ_HANDLED;
	}

	if (reg & (1 << 1)) {
		if (axi_set->loops >= ZONE_CONUT) {
			axi_set->start = 0;
			axi_set->loops = 0;
		} else {
			axi_set->start = axi_set->end;
		}
		data_buff_index = axi_set->loops;
		axi_set->loops++;
		axi_set->end = axi_set->loops * axi_set->zone_size;
		axi_set->size = axi_set->zone_size;
		axi_set->entry++;

		atomic64_set(&axi_set->handle_index, data_buff_index);
		wakeup_highrate_workqueue(axi_set, 0);
		clear_reg |= 1 << 1;
	}

	if (reg & (1 << 0)) {
		clear_reg |= 1 << 0;
	}

	/* CLEAR IRQ */
	reg_write32(core->bus_set, axi_set->base + 0x13c, clear_reg);

	atomic64_inc(&axi_set->data_ref_cnt[data_buff_index]);

	return IRQ_HANDLED;
}


int axihub_mlu370_stop_hub(struct cambr_amh_hub *axi_set)
{
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	u32 reg32 = 0;
	int ret = 0;
	u32 timeout = 100;

	/* STOP HUB */
	reg32 = reg_read32(core->bus_set, axi_set->base + 0x10C);
	reg32 &= ~(0x01);
	reg32 |= AMH_HUB_STOP;
	reg_write32(core->bus_set, axi_set->base + 0x10C, reg32);

	/* WAIT FOR HUB STOP */
	do {
		reg32 = reg_read32(core->bus_set, axi_set->base + 0x138);
		if (reg32 & (1 << 8)) {
			break;
		}
		udelay(1);
	} while (--timeout);

	if (!timeout) {
		ret = -EINVAL;
		goto out;
	}

	if (!axihub_highrate_mode(axi_set)) {
		aximhub_update_lastdata(axi_set);
	}

	/* RESET */
	axi_set->loops = 0;
	axi_set->opened_count = 0;
	memset(axi_set->monitors, 0, axi_set->config->monitor_num);

out:
	return ret;
}

int axihub_mlu370_start_hub(struct cambr_amh_hub *axi_set)
{
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	u32 reg32 = 0;

	axi_set->loops = 0;
	axi_set->start = 0;
	axi_set->end = 0;
	axi_set->status = AH_STATUS_RUNNING;

	/* START HUB */
	reg32 = reg_read32(core->bus_set, axi_set->base + 0x10C);
	reg32 &= ~(0x01);
	reg32 |= AMH_HUB_START;
	reg_write32(core->bus_set, axi_set->base + 0x10C, reg32);

	return 0;
}

struct cn_aximhub_ops aximon_mlu370_ops = {
	.stop_hub = axihub_mlu370_stop_hub,
	.start_hub = axihub_mlu370_start_hub,
};

void mlu370_axi_monitor_config(void *p)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)p;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;
	u64 *res_param = monitor_set->res_param;

	if (core->die_cnt == 2) {
		monitor_set->hub_num = MLU370_DOUBLE_DIE_MAX_AXI_MON_NUM;
	} else {
		monitor_set->hub_num = MLU370_SINGLE_DIE_MAX_AXI_MON_NUM;
	}
	monitor_set->config = mlu370_config;
	monitor_set->ops = aximon_mlu370_ops;
	monitor_set->highrate_mode = AXI_MONITOR_MATCH_ALL_MODE;
	monitor_set->parse_ops = &aximhub_common_parse_ops;
	monitor_set->monitor_ops = &aximon_mlu300_ops;
	monitor_set->zone_info = &mlu370_zone_info;
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
