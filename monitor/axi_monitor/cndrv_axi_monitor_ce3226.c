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

extern struct cn_aximhub_data_parse_ops aximhub_ce3226_edge_parse_ops;

#if defined(CONFIG_CNDRV_CE3226_SOC)

#include <linux/soc/cambricon/irqs.h>
// #define CPUGIC__AXIMHUB            (DECLARE_SPI(58))
#define CE3226_AXIMHUB_0_IRQ         (DECLARE_SPI(119))
#define CE3226_AXIMHUB_1_IRQ         (DECLARE_SPI(120))
#define CE3226_AXIMHUB_2_IRQ         (DECLARE_SPI(359))
#define CE3226_AXIMHUB_3_IRQ         (DECLARE_SPI(360))
#else
#define CE3226_AXIMHUB_0_IRQ         (0)
#define CE3226_AXIMHUB_1_IRQ         (0)
#define CE3226_AXIMHUB_2_IRQ         (0)
#define CE3226_AXIMHUB_3_IRQ         (0)
#endif


irqreturn_t aximhub_ce3226_intr_handle(int index, void *data);

#define CE3226_HUB0_MONITOR_CNT 18
#define CE3226_HUB1_MONITOR_CNT 12
#define CE3226_HUB2_MONITOR_CNT 18
#define CE3226_HUB3_MONITOR_CNT 12

struct cn_axi_monitor_config ce3226_config[CE3226_DOUBLE_DIE_MAX_AXI_MON_NUM] = {
	{0, CE3226_HUB0_MONITOR_CNT,
		0x00061000, aximhub_ce3226_intr_handle, 0x27FFF, 0x18000},
	{0, CE3226_HUB1_MONITOR_CNT,
		0x0000A000, aximhub_ce3226_intr_handle, 0xFFF, 0x0},
	{0, CE3226_HUB2_MONITOR_CNT,
		0x08061000, aximhub_ce3226_intr_handle, 0x27FFF, 0x18000},
	{0, CE3226_HUB3_MONITOR_CNT,
		0x0800A000, aximhub_ce3226_intr_handle, 0xFFF, 0x0},
};

int aximhub_ce3226_edge_config_intr_irq(void)
{
	ce3226_config[0].irq = CE3226_AXIMHUB_0_IRQ;
	ce3226_config[1].irq = CE3226_AXIMHUB_1_IRQ;
	ce3226_config[2].irq = CE3226_AXIMHUB_2_IRQ;
	ce3226_config[3].irq = CE3226_AXIMHUB_3_IRQ;
	return 0;
}

struct cn_aximon_zone_info ce3226_zone_info = {
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

struct cn_aximon_zone_info ce3226_d2d_zone_info = {
	/*interrupt is trigged every zone size bytes*/
	ZONE_SIZE_8MB,
	ZONE_CONUT,
	/*device buffer size*/
	DEV_BUFFER_SIZE(ZONE_SIZE_8MB, ZONE_CONUT),
	/*raw data count per zone, 32bytes unit*/
	PFMU_RAW_DATA_COUNT_PER_ZONE(ZONE_SIZE_8MB),
	/*raw mode, request min block count to malloc memory, 32bytes per block*/
	MIN_RAW_RING_BUFFER_BLOCK_COUNT(ZONE_SIZE_8MB),
};

irqreturn_t aximhub_ce3226_intr_handle(int index, void *data)
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
	zone_size = axi_set->zone_size;
	d2h_set = monitor_set->monitor_highrate_set;
	if (!d2h_set)
		return IRQ_HANDLED;

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

int axihub_ce3226_stop_hub(struct cambr_amh_hub *axi_set)
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

int axihub_ce3226_start_hub(struct cambr_amh_hub *axi_set)
{
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	u32 reg32 = 0;

	axi_set->loops = 0;
	axi_set->start = 0;
	axi_set->end = 0;
	axi_set->status = AH_STATUS_RUNNING;

	reg_write32(core->bus_set, axi_set->base + 0x204, 0x5);

	/* START HUB */
	reg32 = reg_read32(core->bus_set, axi_set->base + 0x10C);
	reg32 &= ~(0x01);
	reg32 |= AMH_HUB_START;
	reg_write32(core->bus_set, axi_set->base + 0x10C, reg32);

	return 0;
}
struct cn_aximhub_ops aximon_ce3226_ops = {
	.stop_hub = axihub_ce3226_stop_hub,
	.start_hub = axihub_ce3226_start_hub,
};

void ce3226_axi_monitor_config(void *p)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)p;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;
	u64 *res_param = monitor_set->res_param;

	if (core->die_cnt == 2) {
		monitor_set->hub_num = CE3226_DOUBLE_DIE_MAX_AXI_MON_NUM;
		monitor_set->zone_info = &ce3226_d2d_zone_info;
	} else {
		monitor_set->hub_num = CE3226_SINGLE_DIE_MAX_AXI_MON_NUM;
		monitor_set->zone_info = &ce3226_zone_info;
	}
	monitor_set->config = ce3226_config;
	monitor_set->ops = aximon_ce3226_ops;
	monitor_set->highrate_mode = AXI_MONITOR_MATCH_ALL_MODE;
	monitor_set->parse_ops = &aximhub_ce3226_edge_parse_ops;
	monitor_set->monitor_ops = &aximon_mlu300_ops;
	aximhub_ce3226_edge_config_intr_irq();
	monitor_set->support_data_mode =
		(1ULL << AXIM_NORMAL_MODE) | (1ULL << AXIM_BW_DATA_MODE);
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
