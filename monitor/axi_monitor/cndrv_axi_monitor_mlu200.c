#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>

#include "cndrv_bus.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_monitor_usr.h"
#include "../monitor.h"
#include "cndrv_axi_monitor.h"
#include "./highrate/cndrv_monitor_highrate.h"

irqreturn_t aximhub_mlu200_intr_handle(int index, void *data)
{
	struct cambr_amh_hub *axi_set = (struct cambr_amh_hub *)data;
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	u32 reg = 0;
	u32 clear_reg = 0;
	u8 data_buff_index = 0;

	reg = reg_read32(core->bus_set, axi_set->base + 0x100);

	if (axihub_highrate_mode(axi_set)) {
		reg = 3 << 8;
		reg_write32(core->bus_set, axi_set->base + 0x100, reg);
		return IRQ_HANDLED;
	}

	if (reg & (1 << 9)) {
		if (axi_set->loops >= ZONE_CONUT) {
			axi_set->start = 0;
			axi_set->loops = 0;
		} else {
			axi_set->start = axi_set->end;
		}
		data_buff_index = axi_set->loops;
		axi_set->loops++;
		axi_set->end = axi_set->loops * axi_set->zone_size;
		axi_set->size = axi_set->end - axi_set->start;
		axi_set->entry++;

		atomic64_set(&axi_set->handle_index, data_buff_index);
		wakeup_highrate_workqueue(axi_set, 0);
		clear_reg |= 1 << 9;
	}

	if (reg & (1 << 8)) {
		clear_reg |= 1 << 8;
	}

	/* CLEAR IRQ */
	reg_write32(core->bus_set, axi_set->base + 0x100, clear_reg);

	atomic64_inc(&axi_set->data_ref_cnt[data_buff_index]);

	return IRQ_HANDLED;
}

int axihub_mlu200s_stop_hub(struct cambr_amh_hub *axi_set)
{
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	u32 reg32 = 0;
	int ret = 0;
	u32 timeout = 100;

	reg32 = reg_read32(core->bus_set, axi_set->base + 0x10C);
	reg32 &= ~(0x01);
	reg32 |= AMH_HUB_STOP;
	reg_write32(core->bus_set, axi_set->base + 0x10C, reg32);
	reg32 = reg_read32(core->bus_set, axi_set->base + 0x10C);

	do {
		reg32 = reg_read32(core->bus_set, axi_set->base + 0x100);
		if (reg32 & (1 << 24)) {
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

	axi_set->loops = 0;
	axi_set->opened_count = 0;
	memset(axi_set->monitors, 0, axi_set->config->monitor_num);
	axi_set->status = AH_STATUS_FINISH;
out:
	return ret;
}


int axihub_mlu200s_start_hub(struct cambr_amh_hub *axi_set)
{
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	u32 reg32 = 0;

	axi_set->loops = 0;
	axi_set->start = 0;
	axi_set->end = 0;
	axi_set->status = AH_STATUS_RUNNING;

	reg32 = reg_read32(core->bus_set, axi_set->base + 0x10C);
	reg32 &= ~(0x01);
	reg32 |= AMH_HUB_START;
	reg_write32(core->bus_set, axi_set->base + 0x10C, reg32);
	reg32 = reg_read32(core->bus_set, axi_set->base + 0x10C);

	return 0;
}
