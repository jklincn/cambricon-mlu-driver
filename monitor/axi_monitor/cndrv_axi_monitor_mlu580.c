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
#include "cndrv_mcc.h"

/*
    Addrdec hbm id  0    1    2    3    4    5
    top hbm id      0    2    1    4    3    5
*/
const u32 mlu580_decid_topid_to_ddr[MLU580_DDR_CHANNEL_COUNT] = {0, 2, 1, 4, 3, 5};

irqreturn_t aximhub_mlu580_intr_handle(int index, void *data);

#define MLU580_HUB0_MONITOR_CNT     7
#define MLU580_HUB1_MONITOR_CNT     30
#define MLU580_HUB2_MONITOR_CNT     29
#define MLU580_HUB3_MONITOR_CNT     14
#define MLU580_HUB4_MONITOR_CNT     14
#define MLU580_HUB5_MONITOR_CNT     28
#define MLU580_HUB6_MONITOR_CNT     17
#define MLU580_HUB7_MONITOR_CNT     17

#define MLU580_AXIMHUB_0_IRQ        262
#define MLU580_AXIMHUB_1_IRQ        270
#define MLU580_AXIMHUB_2_IRQ        235
#define MLU580_AXIMHUB_3_IRQ        237
#define MLU580_AXIMHUB_4_IRQ        238
#define MLU580_AXIMHUB_5_IRQ        240
#define MLU580_AXIMHUB_6_IRQ        258
#define MLU580_AXIMHUB_7_IRQ        260

extern struct cn_aximhub_data_parse_ops aximhub_mlu580_parse_ops;
extern struct axi_hubtrace_map_ipu_info mlu580_hubtrace_table[];

struct cn_axi_monitor_config mlu580_config[MLU580_DOUBLE_DIE_MAX_AXI_MON_NUM] = {
	{MLU580_AXIMHUB_0_IRQ, MLU580_HUB0_MONITOR_CNT,
		0x0480000, aximhub_mlu580_intr_handle, 0X3F, 0x40},
	{MLU580_AXIMHUB_1_IRQ, MLU580_HUB1_MONITOR_CNT,
		0x0E40000, aximhub_mlu580_intr_handle, ((1ULL << MLU580_HUB1_MONITOR_CNT) - 1), 0x0},
	{MLU580_AXIMHUB_2_IRQ, MLU580_HUB2_MONITOR_CNT,
		0x1A40000, aximhub_mlu580_intr_handle, 0x1FF, 0x1FFFFE00},
	{MLU580_AXIMHUB_3_IRQ, MLU580_HUB3_MONITOR_CNT,
		0x1E50000, aximhub_mlu580_intr_handle, 0xF, 0x3FF0},
	{MLU580_AXIMHUB_4_IRQ, MLU580_HUB4_MONITOR_CNT,
		0x2050000, aximhub_mlu580_intr_handle, 0xF, 0x3FF0},
	{MLU580_AXIMHUB_5_IRQ, MLU580_HUB5_MONITOR_CNT,
		0x2460000, aximhub_mlu580_intr_handle, 0xFF, 0xFFFFF00},
	{MLU580_AXIMHUB_6_IRQ, MLU580_HUB6_MONITOR_CNT,
		0x3000000, aximhub_mlu580_intr_handle, 0x1FFFF, 0x0},
	{MLU580_AXIMHUB_7_IRQ, MLU580_HUB7_MONITOR_CNT,
		0x3800000, aximhub_mlu580_intr_handle, 0x1FFFF, 0x0},
};

struct cn_aximon_zone_info mlu580_zone_info = {
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

irqreturn_t aximhub_mlu580_intr_handle(int index, void *data)
{
	struct cambr_amh_hub *axi_set = (struct cambr_amh_hub *)data;
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	u32 reg = 0;
	u32 clear_reg = 0;
	struct cn_monitor_set *monitor_set = NULL;
	struct cn_monitor_highrate_set *d2h_set = NULL;
	struct highrate_thread_context *thread_context = NULL;
	u8 hub_id = axi_set->hub_id;
	u64 dev_phy_addr = 0;
	u8 data_buff_index = 0;
	u64 zone_size = 0;

	monitor_set = core->monitor_set;
	if (!monitor_set)
		return IRQ_HANDLED;

	d2h_set = monitor_set->monitor_highrate_set;
	if (!d2h_set)
		return IRQ_HANDLED;

	zone_size = axi_set->zone_size;
	
	thread_context = (struct highrate_thread_context *)&(d2h_set->thread_context);
	if (!thread_context)
		return IRQ_HANDLED;

	reg = reg_read32(core->bus_set, axi_set->base + 0x20C);

	if (axihub_highrate_mode(axi_set) || !(reg & (1 << 1))) {
		clear_reg = 0x0E;
		reg_write32(core->bus_set, axi_set->base + 0x208, reg);
		return IRQ_HANDLED;
	}

	/* stop write mem,clear report limit stop intr */
	if (reg & (1 << 3)) {
		/* write stop intr addr */
		if (reg & (1 << 2)) {
			/* limit irq,write base + ZONE_SIZE to stop register */
			dev_phy_addr = (u64)(thread_context[hub_id].dev_buff + zone_size);
		} else {
			/* write base to stop register */
			dev_phy_addr = (u64)(thread_context[hub_id].dev_buff);
		}

		reg = dev_phy_addr & 0xffffffff;
		reg_write32(core->bus_set, axi_set->base + 0x138, reg);

		/* clear report limit stop intr */
		reg = 0x0E;
		reg_write32(core->bus_set, axi_set->base + 0x208, reg);

		return IRQ_HANDLED;
	}

	/* bit1:1,bit2:0 */
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
	}

	if (reg & 0x0e) {
		clear_reg = 0x0e;
	}
	/* CLEAR IRQ */
	reg_write32(core->bus_set, axi_set->base + 0x208, clear_reg);

	atomic64_inc(&axi_set->data_ref_cnt[data_buff_index]);

	return IRQ_HANDLED;
}

int axihub_mlu580_stop_hub(struct cambr_amh_hub *axi_set)
{
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	u32 reg32 = 0;
	int ret = 0;
	u32 timeout = 100;

	/* STOP HUB */
	reg32 = reg_read32(core->bus_set, axi_set->base + 0x144);
	reg32 &= ~(0x01);
	reg32 |= AMH_HUB_STOP;
	reg_write32(core->bus_set, axi_set->base + 0x144, reg32);

	/* WAIT FOR HUB STOP */
	do {
		reg32 = reg_read32(core->bus_set, axi_set->base + 0x140);
		if (reg32 & (1 << 0)) {
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
	reg_write32(core->bus_set, axi_set->base + 0x204, 0x0);
	return ret;
}

int axihub_mlu580_start_hub(struct cambr_amh_hub *axi_set)
{
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	u32 reg32 = 0;

	axi_set->loops = 0;
	axi_set->start = 0;
	axi_set->end = 0;
	axi_set->status = AH_STATUS_RUNNING;

	reg_write32(core->bus_set, axi_set->base + 0x204, 0x5);

	/* START HUB */
	reg32 = reg_read32(core->bus_set, axi_set->base + 0x144);
	reg32 &= ~(0x01);
	reg32 |= AMH_HUB_START;
	reg_write32(core->bus_set, axi_set->base + 0x144, reg32);

	return 0;
}

struct cn_aximhub_ops aximon_mlu580_ops = {
	.stop_hub = axihub_mlu580_stop_hub,
	.start_hub = axihub_mlu580_start_hub,
};

void mlu580_axi_monitor_config(void *p)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)p;
	struct cn_core_set *core = monitor_set->core;
	u64 *res_param = monitor_set->res_param;
	struct cn_board_info *pboardi = &core->board_info;
	u64 bad_ddr_mask = 0;
	u64 val = 0;

	monitor_set->hub_num = MLU580_DOUBLE_DIE_MAX_AXI_MON_NUM;
	monitor_set->config = mlu580_config;
	monitor_set->ops = aximon_mlu580_ops;
	monitor_set->highrate_mode = AXI_MONITOR_MATCH_ALL_MODE;
	monitor_set->mlu_hubtrace_table = mlu580_hubtrace_table;
	monitor_set->parse_ops = &aximhub_mlu580_parse_ops;
	monitor_set->monitor_ops = &aximon_mlu300_ops;
	monitor_set->zone_info = &mlu580_zone_info;
	monitor_set->support_data_mode =
		(1ULL << AXIM_NORMAL_MODE) | (1ULL << AXIM_BW_DATA_MODE) | (1ULL << AXIM_EQUAL_DATA_MODE);
	if (res_param) {
		res_param[PMU_MONITOR_SIZE] = sizeof(struct axi_monitor_data);
		res_param[PMU_LLC_PERF_SIZE] = sizeof(struct mlu590_monitor_llc_perf_data);
		res_param[PMU_IPU_PERF_SIZE] = sizeof(struct pmu_pfmu_perf_data_s);
		res_param[PMU_SMMU_PERF_SIZE] = sizeof(struct monitor_smmu_perf_data);
		res_param[PMU_SMMU_EXP_SIZE] = sizeof(struct monitor_smmu_exception_data);
		res_param[PMU_L1C_PERF_SIZE] = sizeof(struct monitor_l1c_perf_data);

		if (pboardi) {
			if (pboardi->bad_hbm_mask) {
				val = __ffs(pboardi->bad_hbm_mask);
				if (val < MLU580_DDR_CHANNEL_COUNT) {
					if (pboardi->hbm_cnt == MLU580_A5_DDR_CHANNEL_COUNT) {
						bad_ddr_mask |= (1ULL << mlu580_decid_topid_to_ddr[val]);
					} else if (pboardi->hbm_cnt == MLU580_A3_DDR_CHANNEL_COUNT) {
						bad_ddr_mask |= (1ULL << mlu580_decid_topid_to_ddr[val]);
						//todo
					} else {
						bad_ddr_mask = 0;
					}
				}
			}
		}
		res_param[PMU_VALID_HBM_MASK] = (~bad_ddr_mask & 0x3F);
	}
}
