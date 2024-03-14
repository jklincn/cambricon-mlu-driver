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
#include "cndrv_mcu.h"

/*
    Addrdec hbm id  0    1    2    3    4    5
    top hbm id      0    2    1    4    3    5
*/
const u32 mlu590_decid_topid_to_hbm[MLU590_HBM_CHANNEL_COUNT] = {0, 2, 1, 4, 3, 5};

irqreturn_t aximhub_mlu590_intr_handle(int index, void *data);

#define MLU590_HUB0_MONITOR_CNT     27
#define MLU590_HUB1_MONITOR_CNT     27
#define MLU590_HUB2_MONITOR_CNT     36
#define MLU590_HUB3_MONITOR_CNT     36
#define MLU590_HUB4_MONITOR_CNT     29
#define MLU590_HUB5_MONITOR_CNT     14
#define MLU590_HUB6_MONITOR_CNT     14
#define MLU590_HUB7_MONITOR_CNT     28
#define MLU590_HUB8_MONITOR_CNT     17

#define MLU590_AXIMHUB_0_IRQ        294
#define MLU590_AXIMHUB_1_IRQ        299
#define MLU590_AXIMHUB_2_IRQ        280
#define MLU590_AXIMHUB_3_IRQ        283
#define MLU590_AXIMHUB_4_IRQ        272
#define MLU590_AXIMHUB_5_IRQ        274
#define MLU590_AXIMHUB_6_IRQ        275
#define MLU590_AXIMHUB_7_IRQ        277
#define MLU590_AXIMHUB_8_IRQ        287

/* MLU590E */
// #define MLU590E_HUB0_MONITOR_CNT     27
// #define MLU590E_HUB1_MONITOR_CNT     27
// #define MLU590E_HUB2_MONITOR_CNT     42
// #define MLU590E_HUB3_MONITOR_CNT     36
// #define MLU590E_HUB4_MONITOR_CNT     29
// #define MLU590E_HUB5_MONITOR_CNT     28
// #define MLU590E_HUB6_MONITOR_CNT     17

// #define MLU590E_AXIMHUB_0_IRQ        294
// #define MLU590E_AXIMHUB_1_IRQ        299
// #define MLU590E_AXIMHUB_2_IRQ        280
// #define MLU590E_AXIMHUB_3_IRQ        283
// #define MLU590E_AXIMHUB_4_IRQ        272
// #define MLU590E_AXIMHUB_5_IRQ        274
// #define MLU590E_AXIMHUB_8_IRQ        287

#define MLU590E_AXIMHUB_0_IRQ        287
#define MLU590E_HUB0_MONITOR_CNT     1

extern struct cn_aximhub_data_parse_ops aximhub_mlu590_parse_ops;
extern struct axi_hubtrace_map_ipu_info mlu590_hubtrace_table[];

struct cn_axi_monitor_config mlu590_config[MLU590_DOUBLE_DIE_MAX_AXI_MON_NUM] = {
	{MLU590_AXIMHUB_0_IRQ, MLU590_HUB0_MONITOR_CNT,
		0x19EC000, aximhub_mlu590_intr_handle, ((1ULL << MLU590_HUB0_MONITOR_CNT) - 1), 0x0},
	{MLU590_AXIMHUB_1_IRQ, MLU590_HUB1_MONITOR_CNT,
		0x19ED000, aximhub_mlu590_intr_handle, ((1ULL << MLU590_HUB1_MONITOR_CNT) - 1), 0x0},
	{MLU590_AXIMHUB_2_IRQ, MLU590_HUB2_MONITOR_CNT,
		0x19EE000, aximhub_mlu590_intr_handle, 0x3FFFFFFFF, 0xC00000000},
	{MLU590_AXIMHUB_3_IRQ, MLU590_HUB3_MONITOR_CNT,
		0x19EF000, aximhub_mlu590_intr_handle, 0x3FFFFFFFF, 0xC00000000},
	{MLU590_AXIMHUB_4_IRQ, MLU590_HUB4_MONITOR_CNT,
		0x19F0000, aximhub_mlu590_intr_handle, 0x1FF, 0x1FFFFE00},
	{MLU590_AXIMHUB_5_IRQ, MLU590_HUB5_MONITOR_CNT,
		0x19F1000, aximhub_mlu590_intr_handle, 0x0F, 0x3FF0},
	{MLU590_AXIMHUB_6_IRQ, MLU590_HUB6_MONITOR_CNT,
		0x19F2000, aximhub_mlu590_intr_handle, 0x0F, 0x3FF0},
	{MLU590_AXIMHUB_7_IRQ, MLU590_HUB7_MONITOR_CNT,
		0x19F3000, aximhub_mlu590_intr_handle, 0xFF, 0xFFFFF00},
	{MLU590_AXIMHUB_8_IRQ, MLU590_HUB8_MONITOR_CNT,
		0x19F4000, aximhub_mlu590_intr_handle, 0x1FFF, 0x1E000},
};

struct cn_axi_monitor_config mlu590e_config[MLU590E_DOUBLE_DIE_MAX_AXI_MON_NUM] = {
	{MLU590E_AXIMHUB_0_IRQ, MLU590E_HUB0_MONITOR_CNT,
		0x19F4000, aximhub_mlu590_intr_handle, 0x1000, 0x0},
};

struct cn_aximon_zone_info mlu590_zone_info = {
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

irqreturn_t aximhub_mlu590_intr_handle(int index, void *data)
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

int axihub_mlu590_stop_hub(struct cambr_amh_hub *axi_set)
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

int axihub_mlu590_start_hub(struct cambr_amh_hub *axi_set)
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

struct cn_aximhub_ops aximon_mlu590_ops = {
	.stop_hub = axihub_mlu590_stop_hub,
	.start_hub = axihub_mlu590_start_hub,
};

void mlu590_axi_monitor_config(void *p)
{
	struct cn_monitor_set *monitor_set = NULL;
	struct cn_core_set *core = NULL;
	u64 *res_param = NULL;
	struct cn_board_info *pboardi = NULL;
	u64 bad_hbm_mask = 0;
	u64 val = 0;

	monitor_set = (struct cn_monitor_set *)p;
	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("Invalid montior set");
		return;
	}

	core = monitor_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("Invalid core set");
		return;
	}

	res_param = monitor_set->res_param;
	if (IS_ERR_OR_NULL(res_param)) {
		cn_dev_err("Invalid dev resource");
		return;
	}

	pboardi = &core->board_info;
	if (IS_ERR_OR_NULL(pboardi)) {
		cn_dev_err("Invalid dev info");
		return;
	}

	if (pboardi->board_type == SUBSYS_MLU590_E) {
		monitor_set->hub_num = MLU590E_DOUBLE_DIE_MAX_AXI_MON_NUM;
		monitor_set->config = mlu590e_config;
	} else {
		monitor_set->hub_num = MLU590_DOUBLE_DIE_MAX_AXI_MON_NUM;
		monitor_set->config = mlu590_config;
	}

	monitor_set->ops = aximon_mlu590_ops;
	monitor_set->highrate_mode = AXI_MONITOR_MATCH_ALL_MODE;
	monitor_set->mlu_hubtrace_table = mlu590_hubtrace_table;
	monitor_set->parse_ops = &aximhub_mlu590_parse_ops;
	monitor_set->monitor_ops = &aximon_mlu300_ops;
	monitor_set->zone_info = &mlu590_zone_info;
	monitor_set->support_data_mode =
		(1ULL << AXIM_NORMAL_MODE) | (1ULL << AXIM_BW_DATA_MODE) | (1ULL << AXIM_EQUAL_DATA_MODE);

	res_param[PMU_MONITOR_SIZE] = sizeof(struct axi_monitor_data);
	res_param[PMU_LLC_PERF_SIZE] = sizeof(struct mlu590_monitor_llc_perf_data);
	res_param[PMU_IPU_PERF_SIZE] = sizeof(struct pmu_pfmu_perf_data_s);
	res_param[PMU_SMMU_PERF_SIZE] = sizeof(struct monitor_smmu_perf_data);
	res_param[PMU_SMMU_EXP_SIZE] = sizeof(struct monitor_smmu_exception_data);
	res_param[PMU_L1C_PERF_SIZE] = sizeof(struct monitor_l1c_perf_data);

	if (pboardi->bad_hbm_mask) {
		val = __ffs(pboardi->bad_hbm_mask);
		if (val < MLU590_HBM_CHANNEL_COUNT) {
			if (pboardi->hbm_cnt == MLU590_A5_HBM_CHANNEL_COUNT) {
				bad_hbm_mask |= (1ULL << mlu590_decid_topid_to_hbm[val]);
			} else if (pboardi->hbm_cnt == MLU590_A3_HBM_CHANNEL_COUNT) {
				bad_hbm_mask |= (1ULL << mlu590_decid_topid_to_hbm[val]);
				bad_hbm_mask |= ((1ULL << 1) | (1ULL << 4));
			} else {
				bad_hbm_mask = 0;
			}
		}
	}

	res_param[PMU_VALID_HBM_MASK] = (~bad_hbm_mask & 0x3F);

}
