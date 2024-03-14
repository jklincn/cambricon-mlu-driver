/*
 * gdma/gdma_drv.c
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <asm/atomic.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/delay.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_mm.h"
#include "gdma_drv.h"
#include "gdma_sched.h"
#include "gdma_common.h"
#include "gdma_desc.h"
#include "gdma_hal.h"
#include "gdma_debug.h"
#include "gdma_common_api.h"
#include "cndrv_domain.h"

#define IS_CTRL_ONLN(gdma_set, ctrlid)  (gdma_set->ctrl_onln[ctrlid])
#define IS_CTRL_CHAN_ONLN(gdma_set, ctrlid, pchanid)   (gdma_set->ctrl_pchan_onln[ctrlid][pchanid])
#define IS_CHAN_ONLN(gdma_set, topchanid)   ({ \
	int _ctrlid = topchanid / gdma_set->info->ctrl_chan_num; \
	int _pchanid = topchanid % gdma_set->info->ctrl_chan_num; \
	int _onln = IS_CTRL_CHAN_ONLN(gdma_set, _ctrlid, _pchanid); \
	_onln; \
})

#ifdef CONFIG_CNDRV_EDGE
#include "linux/soc/cambricon/cndrv_diag.h"
#else
#define DIAG_MODULE_ACPU_GDMAC (0x10)
#define DIAG_INST_ACPU_GDMA_CH0 (0x1)

#define DIAG_OK (0)
#define DIAG_FAIL (-1)

#define DIAG_DECLARE(__module_name)

#define DIAG_REGISTER(__module_id, __inst_id, __handler)                       \
	({                                                                     \
		int32_t diag_ret = DIAG_OK;                                    \
		diag_ret;                                                      \
	})

#define DIAG_UNREGISTER(__module_id, __inst_id)                                \
	({                                                                     \
		int32_t diag_ret = DIAG_OK;                                    \
		diag_ret;                                                      \
	})

#define diag_module_report(__module_id, __inst_id, __info_type, __inst_status, \
			   ...)                                                \
	({                                                                     \
		int32_t diag_ret = DIAG_OK;                                    \
		diag_ret;                                                      \
	})

#define diag_warning_report(__inst_id, ...)                                    \
	({                                                                     \
		int32_t diag_ret = DIAG_OK;                                    \
		diag_ret;                                                      \
	})

#define diag_error_report(__inst_id, __inst_status, ...)                       \
	({                                                                     \
		int32_t diag_ret = DIAG_OK;                                    \
		diag_ret;                                                      \
	})

#define diag_fatal_report(__inst_id, ...)                                      \
	({                                                                     \
		int32_t diag_ret = DIAG_OK;                                    \
		diag_ret;                                                      \
	})
#endif

DIAG_DECLARE(cn_gdma);

static void gdma_iobc_halt_handler(char *name, struct cn_gdma_phy_chan *pchan)
{
	struct cn_gdma_set *gdma_set = pchan->gdma_set;
	struct cn_gdma_virt_chan *vchan = NULL;
	struct cn_gdma_task *task = NULL;
	unsigned long flags;
	int ret = 0;

	vchan = pchan->vchan;
	pchan->vchan = NULL;

	if (!vchan) {
		cn_dev_gdma_err(gdma_set, "channel %d.%d should not with NULL vchan",
				pchan->ctrl->idx, pchan->idx);
		goto out;
	}

	cn_dev_gdma_debug(pchan->gdma_set,
				"chan %d.%d with vchan %d-->task%d irq tasklet run",
				pchan->ctrl->idx, pchan->idx,
				vchan->idx, vchan->task->idx);

	task = vchan->task;

	__sync_fetch_and_add(&task->finish_tx_num, 1);
	__sync_lock_test_and_set(&task->channel_done, 1);
	__sync_fetch_and_sub(&task->channel_tx_count, 1);
	wake_up(&task->channel_wq);
	cn_gdma_put_idle_virt_chan(vchan);

	if (task->status != GDMA_TASK_SCHED || task->total_tx_num == task->finish_tx_num) {
		goto out;
	}

	/* keep sched same task's vchan if still have ready vchan */
	spin_lock_irqsave(&task->ready_vchan_lock, flags);
	if (!kfifo_is_empty(&task->ready_vchan_fifo)) {
		ret = kfifo_out(&task->ready_vchan_fifo,
				(void *)&vchan, sizeof(vchan));
		if (unlikely(ret != sizeof(vchan))) {
			cn_dev_gdma_err(gdma_set, "task %d ready vchan fifo out failed",
					task->idx);
			spin_unlock_irqrestore(&task->ready_vchan_lock, flags);
			goto out;
		}
	} else {
		spin_unlock_irqrestore(&task->ready_vchan_lock, flags);
		goto out;
	}
	spin_unlock_irqrestore(&task->ready_vchan_lock, flags);

	pchan->vchan = vchan;
	vchan->status = GDMA_CHANNEL_RUN;

	pchan->ctrl->ops->channel_setup_descrpt_tx(pchan, vchan->desc_shm.dev_va);
	pchan->ctrl->ops->channel_irq_enable(pchan);
	/*
	 *!!!Note,cn_bus_mb must before channel_start,make sure operation finished
	 *before gdma transform start
	 */
	cn_bus_mb(pchan->gdma_set->core->bus_set);
	pchan->ctrl->ops->channel_start(pchan);

	return;

out:
	cn_gdma_put_idle_phy_chan(pchan);
	return;
}

static void gdma_suspend_handler(char *name, struct cn_gdma_phy_chan *pchan)
{
	cn_dev_gdma_debug(pchan->gdma_set, "channel %d.%d suspend occur",
			pchan->ctrl->idx, pchan->idx);
}

static void gdma_default_error_handler(char *name, struct cn_gdma_phy_chan *pchan)
{
	struct cn_gdma_virt_chan *vchan = NULL;
	struct cn_gdma_task *task;
	u32 status;
	u32 retry_count = 0;
	u32 id;
	u32 chan_int_out = 0;

	chan_int_out = pchan->ctrl->ops->read_channel_intr_out(pchan);
	pchan->ctrl->ops->get_id(pchan->ctrl, &id);
	cn_dev_gdma_err(pchan->gdma_set, "channel %d.%d read id 0x%x, intr out 0%x",
					pchan->ctrl->idx, pchan->idx,
					id, chan_int_out);

	diag_warning_report(DIAG_INST_ACPU_GDMA_CH0 + pchan->idx, name);

	vchan = pchan->vchan;
	pchan->vchan = NULL;

	if (vchan) {
		task = vchan->task;
		cn_dev_gdma_info(pchan->gdma_set,
					"task id %d gdma transfer info:\n"
					"type:%d src:0x%llx dst:0x%llx size:0x%llx value 0x%llx",
					task->idx,
					task->transfer.type,
					task->transfer.src,
					task->transfer.dst,
					task->transfer.len,
					task->transfer.memset_value);

		__sync_lock_test_and_set(&vchan->task->status, GDMA_TASK_ERROR);
		__sync_lock_test_and_set(&vchan->task->channel_done, 1);
		__sync_fetch_and_sub(&vchan->task->channel_tx_count, 1);
		__sync_lock_test_and_set(&vchan->task->error_flag, 1);
		wake_up(&vchan->task->channel_wq);
		cn_gdma_put_idle_virt_chan(vchan);
	} else {
		cn_dev_gdma_info(pchan->gdma_set, "channel %d.%d vchan is NULL",
				pchan->ctrl->idx, pchan->idx);
	}

	pchan->ctrl->ops->ctrl_reg_dump(pchan->ctrl);
	pchan->ctrl->ops->channel_reg_dump(pchan);

	pchan->ctrl->ops->channel_abort(pchan);
	retry_count = GDMA_PCHAN_RETRY_COUNT;
	do {
		pchan->ctrl->ops->get_channel_status(pchan->ctrl, pchan->idx, &status);
		if (status == GDMA_CHAN_HW_IDLE) {
			break;
		}
		cn_dev_gdma_err(pchan->gdma_set,
				"channel %d.%d status 0x%x, retry %d",
				pchan->ctrl->idx, pchan->idx,
				status, retry_count);
		pchan->ctrl->ops->reset_channel(pchan->ctrl, pchan->idx);
		cn_bus_mb(pchan->gdma_set->core->bus_set);
		pchan->ctrl->ops->channel_hardware_init(pchan);
		cpu_relax();
	} while (retry_count--);

	if (status == GDMA_CHAN_HW_IDLE) {
		cn_dev_gdma_debug(pchan->gdma_set,
				"channel %d.%d status 0x%x recovery!",
				pchan->ctrl->idx, pchan->idx, status);
		cn_gdma_put_idle_phy_chan(pchan);
	} else {
		cn_dev_gdma_err(pchan->gdma_set,
				"channel %d.%d status 0x%x, failed,lost a channel",
				pchan->ctrl->idx, pchan->idx, status);

		diag_fatal_report(DIAG_INST_ACPU_GDMA_CH0 + pchan->idx,
				"channel %d.%d cannot recover to idle",
				pchan->ctrl->idx, pchan->idx);

		pchan->ctrl->ops->ctrl_reg_dump(pchan->ctrl);
		pchan->ctrl->ops->channel_reg_dump(pchan);
		__sync_lock_test_and_set(&pchan->status, GDMA_CHANNEL_FAILED);
	}

	return;
}

static struct cn_gdma_irq_entry gdma_irq_handler_table[] = {
	{0,  "gdma_irq_iobc",                gdma_iobc_halt_handler},
	{1,  "gdma_irq_suspend",             gdma_suspend_handler},
	{2,  "gdma_irq_halt",                gdma_iobc_halt_handler},
	{3,  "gdma_irq_desc_hit_tail",       gdma_default_error_handler},
	{4,  "gdma_irq_rd_desc_resp_err",    gdma_default_error_handler},
	{5,  "gdma_irq_rd_data_resp_err",    gdma_default_error_handler},
	{6,  "gdma_irq_rd_stat_resp_err",    NULL},
	{7,  "gdma_irq_wr_desc_resp_err",    NULL},
	{8,  "gdma_irq_wr_data_resp_err",    gdma_default_error_handler},
	{9,  "gdma_irq_desc_own_err",        gdma_default_error_handler},
	{10, "gdma_irq_desc_addr_err",       gdma_default_error_handler},
	{11, "gdma_irq_desc_data_err",       gdma_default_error_handler},
	{12, "gdma_irq_ill_acc_err",         NULL},
	{13, "gdma_irq_ill_trans_err",       NULL},
	{14, "gdma_irq_tx_addr_underfl_err", gdma_default_error_handler},
	{15, "gdma_irq_tx_addr_overfl_err",  gdma_default_error_handler},
	{16, "gdma_irq_rx_addr_underfl_err", gdma_default_error_handler},
	{17, "gdma_irq_rx_addr_overfl_err",  gdma_default_error_handler},
	{18, "gdma_irq_ecc_err",             gdma_default_error_handler},
};

static int gdma_channel_process_error(struct cn_gdma_phy_chan *pchan)
{
	int retry_count;
	int status;

	pchan->ctrl->ops->channel_abort(pchan);
	retry_count = GDMA_PCHAN_RETRY_COUNT;
	do {
		pchan->ctrl->ops->get_channel_status(pchan->ctrl, pchan->idx, &status);
		if (status == GDMA_CHAN_HW_IDLE) {
			break;
		}
		cn_dev_gdma_err(pchan->gdma_set,
				"channel %d.%d status 0x%x, retry %d",
				pchan->ctrl->idx, pchan->idx,
				status, retry_count);
		pchan->ctrl->ops->reset_channel(pchan->ctrl, pchan->idx);
		cn_bus_mb(pchan->gdma_set->core->bus_set);
		pchan->ctrl->ops->channel_hardware_init(pchan);
		cpu_relax();
	} while (retry_count--);

	if (status == GDMA_CHAN_HW_IDLE) {
		cn_dev_gdma_debug(pchan->gdma_set,
				"channel %d.%d status 0x%x recovery!",
				pchan->ctrl->idx, pchan->idx, status);
		return GDMA_SUCCESS;
	} else {
		cn_dev_gdma_err(pchan->gdma_set,
				"channel %d.%d status 0x%x, failed,lost a channel",
				pchan->ctrl->idx, pchan->idx, status);
		pchan->ctrl->ops->ctrl_reg_dump(pchan->ctrl);
		pchan->ctrl->ops->channel_reg_dump(pchan);
		__sync_lock_test_and_set(&pchan->status, GDMA_CHANNEL_FAILED);
		return -GDMA_ERROR;
	}
}

static int gdma_do_channel_irq(struct cn_gdma_phy_chan *pchan)
{
	u32 chan_int_out = 0;
	u32 irq_bit;

	cn_dev_gdma_debug(pchan->gdma_set,
				"chan %d.%d channel irq handle run",
				pchan->ctrl->idx, pchan->idx);

	chan_int_out = pchan->ctrl->ops->read_channel_intr_out(pchan);
	if (chan_int_out > 0x7) {
		cn_dev_gdma_err(pchan->gdma_set,
				"chan %d.%d chan_int_out 0x%x",
				pchan->ctrl->idx, pchan->idx, chan_int_out);
	}
	pchan->ctrl->ops->channel_intr_clear(pchan);
	pchan->ctrl->ops->channel_irq_disable(pchan);

	while (chan_int_out) {
		irq_bit = __ffs(chan_int_out);
		CLR_BIT(chan_int_out, irq_bit);
		if (gdma_irq_handler_table[irq_bit].irq_handler) {
			cn_dev_gdma_debug(pchan->gdma_set,
				"chan %d.%d irq %d %s occur\n",
				pchan->ctrl->idx, pchan->idx, irq_bit,
				gdma_irq_handler_table[irq_bit].irq_name);
			gdma_irq_handler_table[irq_bit].irq_handler(
					gdma_irq_handler_table[irq_bit].irq_name,
					pchan);
		}
	}

	return GDMA_SUCCESS;
}

static irqreturn_t gdma_ctrl_isr(int irq, void *argv)
{
	irqreturn_t irq_ret = IRQ_NONE;
	u32 dma_int_state;
	int chan_index;
	struct cn_gdma_phy_chan *pchan = NULL;
	struct cn_gdma_controller *ctrl = (struct cn_gdma_controller *)argv;
	int irq_flag;

	irq_flag = ctrl->ops->do_ctrl_irq(ctrl, &dma_int_state);
	cn_dev_gdma_debug(ctrl->gdma_set,
			"ctrl %d irq occur, irq flag %d, gdma intr state 0x%x",
			ctrl->idx, irq_flag, dma_int_state);
	if (irq_flag) {
		cn_dev_gdma_debug(ctrl->gdma_set,
			"ctrl %d irq occur, irq flag %d, gdma intr state 0x%x",
			ctrl->idx, irq_flag, dma_int_state);
		while (dma_int_state) {
			chan_index = __ffs(dma_int_state);
			CLR_BIT(dma_int_state, chan_index);
			if (chan_index) {
				pchan = ctrl->pchans[chan_index - 1];
				gdma_do_channel_irq(pchan);
			}
		}
		if (ctrl->ops->main_intr_clear) {
			ctrl->ops->main_intr_clear(ctrl);
		}

		irq_ret = IRQ_HANDLED;
	} else {
		cn_dev_gdma_debug(ctrl->gdma_set, "irq not for gdma ctrl %d",
							ctrl->idx);
	}

	return irq_ret;
}

static irqreturn_t gdma_channel_isr(int irq, void *argv)
{
	struct cn_gdma_phy_chan *pchan = (struct cn_gdma_phy_chan *)argv;

	if (!pchan) {
		return IRQ_NONE;
	}

	cn_dev_gdma_debug(pchan->gdma_set, "chan %d.%d irq occur",
					pchan->ctrl->idx, pchan->idx);

	gdma_do_channel_irq(pchan);

	return IRQ_HANDLED;
}

static void gdma_phy_chan_exit(struct cn_gdma_set *gdma_set)
{
	int i;
	struct cn_gdma_controller *ctrl = NULL;
	struct cn_gdma_phy_chan *pchan = NULL;

	for (i = 0; i < gdma_set->total_pchan_num; i++) {
		pchan = gdma_set->pchan_pool[i];
		cn_kfree(pchan);
	}
	cn_kfree(gdma_set->pchan_pool);
	for (i = 0; i < gdma_set->ctrl_num; i++) {
		ctrl = gdma_set->ctrl_pool[i];
		cn_kfree(ctrl);
	}
	cn_kfree(gdma_set->ctrl_pool);
}

static int gdma_phy_chan_init(struct cn_gdma_set *gdma_set)
{
	int i, j;
	struct cn_gdma_controller *ctrl = NULL;
	struct cn_gdma_phy_chan *pchan = NULL;
	int ret = 0;

	gdma_set->ctrl_pool = cn_kzalloc(sizeof(struct cn_gdma_controller *) *
			gdma_set->ctrl_num, GFP_KERNEL);
	if (!gdma_set->ctrl_pool) {
		cn_dev_gdma_err(gdma_set, "alloc gdma controller failed!");
		return -ENOMEM;
	}
	for (i = 0; i < gdma_set->ctrl_num; i++) {
		ctrl = cn_kzalloc(sizeof(struct cn_gdma_controller), GFP_KERNEL);
		if (!ctrl) {
			cn_dev_gdma_err(gdma_set, "alloc ctrl %d object failed", i);
			return -ENOMEM;
		}
		gdma_set->ctrl_pool[i] = ctrl;
	}

	gdma_set->total_pchan_num = cn_gdma_get_ctrl_num(gdma_set) *
					cn_gdma_get_ctrl_chan_num(gdma_set);
	if (!gdma_set->total_pchan_num) {
		cn_dev_gdma_err(gdma_set, "Bug! gdma reources info invalid");
		return -EINVAL;
	}
	sema_init(&gdma_set->total_pchan_sem, gdma_set->total_pchan_num);
	gdma_set->pchan_pool = cn_kzalloc(sizeof(struct cn_gdma_phy_chan *) *
			gdma_set->total_pchan_num, GFP_KERNEL);
	if (!gdma_set->pchan_pool) {
		cn_dev_gdma_err(gdma_set, "alloc phy channel pool failed!");
		return -ENOMEM;
	}
	for (i = 0; i < gdma_set->total_pchan_num; i++) {
		pchan = cn_kzalloc(sizeof(struct cn_gdma_phy_chan), GFP_KERNEL);
		if (!pchan) {
			cn_dev_gdma_err(gdma_set, "alloc pchan %d object failed", i);
			return -ENOMEM;
		}
		gdma_set->pchan_pool[i] = pchan;
	}

	for (i = 0; i < gdma_set->ctrl_num; i++) {
		ctrl = gdma_set->ctrl_pool[i];
		ctrl->gdma_set = gdma_set;
		ctrl->idx = i;
		ctrl->pchan_num = cn_gdma_get_ctrl_chan_num(gdma_set);
		ret = cn_gdma_init_ctrl_resource(gdma_set, ctrl, i);
		if (ret) {
			cn_dev_gdma_err(gdma_set, "initialize resource for ctrl %d failed",
							i);
			return -GDMA_ERROR;
		}
		cn_gdma_dbg_show_ctrl_info(gdma_set, ctrl);
		for (j = 0; j < ctrl->pchan_num; j++) {
			pchan = gdma_set->pchan_pool[i * ctrl->pchan_num + j];
			pchan->gdma_set = gdma_set;
			pchan->ctrl = ctrl;
			pchan->status = GDMA_CHANNEL_IDLE;
			ret = cn_gdma_get_pchan_resource(ctrl, pchan, j);
			if (ret) {
				cn_dev_gdma_err(gdma_set,
						"ctrl %d get pchan %d resourced failed",
						i, j);
				return -GDMA_ERROR;
			}
			cn_gdma_dbg_show_chan_info(gdma_set, pchan);
		}
	}

	cn_dev_gdma_info(gdma_set, "All %d.%d.%d gdmac phy chan init done",
		gdma_set->ctrl_num, gdma_set->total_pchan_num,
		gdma_set->available_pchan_num);

	return GDMA_SUCCESS;
}

static int gdma_hardware_init(struct cn_gdma_set *gdma_set)
{
	int ret = 0;
	int i, j;
	struct cn_gdma_controller *ctrl = NULL;
	struct cn_gdma_phy_chan *pchan = NULL;

	for (i = 0; i < gdma_set->ctrl_num; i++) {
		if (!IS_CTRL_ONLN(gdma_set, i)) {
			continue;
		}
		ctrl = gdma_set->ctrl_pool[i];
#if HOST_GDMA_CLOSE_CTRL_CONFIG
		/***
		 * Only MLU580 be assigned ctrl init in ARM.
		 */
		if (gdma_set->core->device_id != MLUID_580) {
			ret = ctrl->ops->ctrl_hardware_init(ctrl);
			if (ret) {
				cn_dev_gdma_err(gdma_set, "gdma%d(%d) hardware init failed",
						i, gdma_set->ctrl_num);
				return ret;
			}
		}
#endif
		for (j = 0; j < ctrl->pchan_num; j++) {
			if (!IS_CTRL_CHAN_ONLN(gdma_set, i, j)) {
				continue;
			}
			pchan = ctrl->pchans[j];
			ret = ctrl->ops->channel_hardware_init(pchan);
			if (ret) {
				cn_dev_gdma_err(gdma_set, "pchan %d.%d init failed",
						pchan->ctrl->idx, pchan->idx);
				return ret;
			}
		}
	}

	return ret;
}

static void gdma_hardware_exit(struct cn_gdma_set *gdma_set)
{
	int i, j;
	struct cn_gdma_controller *ctrl = NULL;
	struct cn_gdma_phy_chan *pchan = NULL;

	for (i = 0; i < gdma_set->ctrl_num; i++) {
		if (!IS_CTRL_ONLN(gdma_set, i)) {
			continue;
		}
		ctrl = gdma_set->ctrl_pool[i];

		for (j = 0; j < ctrl->pchan_num; j++) {
			if (!IS_CTRL_CHAN_ONLN(gdma_set, i, j)) {
				continue;
			}
			pchan = ctrl->pchans[j];
			//ctrl->ops->channel_abort(pchan);
			ctrl->ops->channel_irq_disable(pchan);
			ctrl->ops->channel_intr_clear(pchan);
		}
	}
}

static int gdma_ctrl_irq_install(struct cn_gdma_set *gdma_set)
{
	struct cn_gdma_controller *ctrl = NULL;
	int i = 0;
	int ret = 0;

	for (i = 0; i < gdma_set->ctrl_num; i++) {
		if (!IS_CTRL_ONLN(gdma_set, i)) {
			continue;
		}
		ctrl = gdma_set->ctrl_pool[i];
		ret = cn_bus_register_interrupt(gdma_set->core->bus_set,
				ctrl->irq, (interrupt_cb_t)gdma_ctrl_isr,
				(void *)ctrl);
		if (ret) {
			cn_dev_gdma_err(gdma_set,
					"register irq for controller %d irq %d failed",
					ctrl->idx, ctrl->irq);
			return ret;
		}

		ret = cn_bus_enable_irq(gdma_set->core->bus_set, ctrl->irq);
		if (ret) {
			cn_dev_gdma_err(gdma_set,
					"enable irq for gdma controller %d irq %d failed",
					ctrl->idx, ctrl->irq);
			return ret;
		}

		cn_dev_gdma_debug(gdma_set,
				"install irq for controller %d irq %d success",
				ctrl->idx, ctrl->irq);
	}

	return ret;
}

static int gdma_channel_irq_install(struct cn_gdma_set *gdma_set)
{
	struct cn_gdma_phy_chan *pchan = NULL;
	int i = 0;
	int ret = 0;

	for (i = 0; i < gdma_set->total_pchan_num; i++) {
		if (!IS_CHAN_ONLN(gdma_set, i)) {
			continue;
		}
		pchan = gdma_set->pchan_pool[i];
#ifdef CONFIG_CNDRV_EDGE
		snprintf(pchan->irq_name, sizeof(pchan->irq_name), "gdma%dchan%d",
				pchan->ctrl->idx,  pchan->idx);
		cn_dev_gdma_debug(gdma_set, "register channel %d.%d irq %d name %s",
				pchan->ctrl->idx, pchan->idx, pchan->irq, pchan->irq_name);
		ret = request_irq(pchan->irq, (interrupt_cb_t)gdma_channel_isr, 0,
				pchan->irq_name, (void *)pchan);
#else
		ret = cn_bus_register_interrupt(gdma_set->core->bus_set,
				pchan->irq, (interrupt_cb_t)gdma_channel_isr,
				(void *)pchan);
#endif
		if (ret) {
			cn_dev_gdma_err(gdma_set,
				"register interrupt for chan %d.%d irq %d failed",
				pchan->ctrl->idx, pchan->idx, pchan->irq);
			return ret;
		}

		ret = cn_bus_enable_irq(gdma_set->core->bus_set, pchan->irq);
		if (ret) {
			cn_dev_gdma_err(gdma_set,
				"enable irq for gdma channel %d.%d irq %d failed",
				pchan->ctrl->idx, pchan->idx, pchan->irq);
			return ret;
		}

		cn_dev_gdma_debug(gdma_set,
				"install irq for chan %d.%d irq %d success",
				pchan->ctrl->idx, pchan->idx, pchan->irq);
	}

	return ret;
}

static int gdma_irq_install(struct cn_gdma_set *gdma_set)
{
	int ret = 0;
	u8 irq_type;

	irq_type = cn_gdma_get_irq_type(gdma_set);
	switch (irq_type) {
	case GDMA_IRQ_CTRL_TYPE:
		ret = gdma_ctrl_irq_install(gdma_set);
		break;
	case GDMA_IRQ_CHANNEL_TYPE:
		ret = gdma_channel_irq_install(gdma_set);
		break;
	default:
		cn_dev_gdma_err(gdma_set, "invalid irq type");
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int gdma_channel_diag_register(struct cn_gdma_set *gdma_set)
{
	struct cn_gdma_phy_chan *pchan = NULL;
	int i = 0;
	int ret = 0;

	for (i = 0; i < gdma_set->total_pchan_num; i++) {
		if (!IS_CHAN_ONLN(gdma_set, i)) {
			continue;
		}
		pchan = gdma_set->pchan_pool[i];

		ret = DIAG_REGISTER(DIAG_MODULE_ACPU_GDMAC,
			DIAG_INST_ACPU_GDMA_CH0 + i, NULL);
		if (ret) {
			cn_dev_gdma_err(gdma_set,
				"register diagnose for chan %d.%d failed",
				pchan->ctrl->idx, pchan->idx);
			return ret;
		}
	}

	return ret;
}

static void gdma_channel_diag_unregister(struct cn_gdma_set *gdma_set)
{
	int i = 0;

	for (i = 0; i < gdma_set->total_pchan_num; i++) {
		if (!IS_CHAN_ONLN(gdma_set, i)) {
			continue;
		}
		DIAG_UNREGISTER(DIAG_MODULE_ACPU_GDMAC, DIAG_INST_ACPU_GDMA_CH0 + i);
	}
}

static int gdma_ctrl_irq_uninstall(struct cn_gdma_set *gdma_set)
{
	struct cn_gdma_controller *ctrl = NULL;
	int i = 0;

	for (i = 0; i < gdma_set->ctrl_num; i++) {
		if (!IS_CTRL_ONLN(gdma_set, i)) {
			continue;
		}
		ctrl = gdma_set->ctrl_pool[i];
		cn_bus_disable_irq(gdma_set->core->bus_set, ctrl->irq);
		cn_bus_unregister_interrupt(gdma_set->core->bus_set, ctrl->irq);
	}

	return GDMA_SUCCESS;
}

static int gdma_channel_irq_uninstall(struct cn_gdma_set *gdma_set)
{
	struct cn_gdma_phy_chan *pchan = NULL;
	int i = 0;

	for (i = 0; i < gdma_set->total_pchan_num; i++) {
		if (!IS_CHAN_ONLN(gdma_set, i)) {
			continue;
		}
		pchan = gdma_set->pchan_pool[i];
		cn_bus_disable_irq(gdma_set->core->bus_set, pchan->irq);
#ifdef CONFIG_CNDRV_EDGE
		free_irq(pchan->irq, pchan);
#else
		cn_bus_unregister_interrupt(gdma_set->core->bus_set, pchan->irq);
#endif
	}

	return GDMA_SUCCESS;
}

static void gdma_irq_uninstall(struct cn_gdma_set *gdma_set)
{
	u8 irq_type;

	irq_type = cn_gdma_get_irq_type(gdma_set);
	switch (irq_type) {
	case GDMA_IRQ_CTRL_TYPE:
		gdma_ctrl_irq_uninstall(gdma_set);
		break;
	case GDMA_IRQ_CHANNEL_TYPE:
		gdma_channel_irq_uninstall(gdma_set);
		break;
	default:
		break;
	}
}

struct cn_gdma_phy_chan *cn_gdma_get_idle_phy_chan(struct cn_gdma_set *gdma_set)
{
	struct cn_gdma_phy_chan *pchan = NULL;
	int i;
	u32 index;
	int ret;
	u32 retry_count = 0;

	ret = down_trylock(&gdma_set->total_pchan_sem);
	if (ret) {
		usleep_range(1, 10);
		return NULL;
	}

	/*
	 * !!!Note: retry count maybe insuffient for same extreme situation
	 */
	retry_count = GDMA_SEARCH_RETRY_COUNT;
	do {
		index = gdma_set->pchan_search_start % gdma_set->total_pchan_num;
		for (i = 0; i < gdma_set->total_pchan_num; i++) {
			pchan = gdma_set->pchan_pool[index];
			if (__sync_bool_compare_and_swap(&pchan->status,
							GDMA_CHANNEL_IDLE,
							GDMA_CHANNEL_ASSIGNED)) {
				if (index / gdma_set->info->ctrl_chan_num) {
					/* pchan->ctrl->idx != 0 */
					__sync_fetch_and_add(&gdma_set->pchan_search_start,
							gdma_set->info->ctrl_chan_num);
				} else {
					/* pchan->ctrl->idx == 0 */
					if ((index % gdma_set->info->ctrl_chan_num) ==
						(gdma_set->info->ctrl_chan_num - 1)) {
						__sync_fetch_and_add(&gdma_set->pchan_search_start, 1);
					} else {
						__sync_fetch_and_add(&gdma_set->pchan_search_start,
								gdma_set->info->ctrl_chan_num + 1);
					}
				}

				cn_dev_gdma_debug(gdma_set, "Get pchan: %d-%d", gdma_set->total_pchan_num, index);

				return pchan;
			}
			index++;
			index %= gdma_set->total_pchan_num;
		}
		usleep_range(1, 10);
	} while (retry_count--);

	cn_dev_gdma_info(gdma_set, "No enough idle pchan,return NULL");

	up(&gdma_set->total_pchan_sem);
	return NULL;
}

int cn_gdma_put_idle_phy_chan(struct cn_gdma_phy_chan *pchan)
{
	__sync_lock_test_and_set(&pchan->status, GDMA_CHANNEL_IDLE);
	up(&pchan->gdma_set->total_pchan_sem);

	return GDMA_SUCCESS;
}

static int gdma_intr_tx_go(struct cn_gdma_phy_chan *pchan,
		struct cn_gdma_virt_chan *vchan)
{
	cn_dev_gdma_debug(pchan->gdma_set,
			"chan %d.%d with vchan %d-->task %d intr tx start",
			pchan->ctrl->idx, pchan->idx, vchan->idx, vchan->task->idx);

	pchan->ctrl->ops->channel_intr_clear(pchan);
	pchan->ctrl->ops->channel_setup_descrpt_tx(pchan, vchan->desc_shm.dev_va);
	pchan->ctrl->ops->channel_irq_enable(pchan);
	/*
	 *!!!Note,cn_bus_mb must before channel_start,make sure operation finished
	 *before gdma transform start
	 */
	cn_bus_mb(pchan->gdma_set->core->bus_set);
	pchan->ctrl->ops->channel_start(pchan);

	return GDMA_SUCCESS;
}

static int gdma_poll_tx_go(struct cn_gdma_phy_chan *pchan,
		struct cn_gdma_virt_chan *vchan)
{
	u32 main_chan_status = GDMA_CHAN_HW_ERROR;
	int retry_count = GDMA_POLL_TIMEOUT;
	int ret = GDMA_SUCCESS;
	int read_times = 0;
	u32 channel_status = 0;

	cn_dev_gdma_debug(pchan->gdma_set,
			"chan %d.%d with vchan %d-->task %d poll tx start",
			pchan->ctrl->idx, pchan->idx, vchan->idx, vchan->task->idx);

	pchan->ctrl->ops->channel_setup_descrpt_tx(pchan, vchan->desc_shm.dev_va);
	/*
	 *!!!Note,cn_bus_mb must before channel_start,make sure operation finished
	 *before gdma transform start
	 */
	cn_bus_mb(pchan->gdma_set->core->bus_set);
	pchan->ctrl->ops->channel_start(pchan);

retry:
	do {
		main_chan_status = reg_read32(pchan->gdma_set->core->bus_set,
							pchan->ctrl->main_csr_base + 0x20);
		channel_status = (main_chan_status >> (pchan->idx * 4)) & 0xf;
		if (channel_status != GDMA_CHAN_HW_RUN) {
			if (channel_status != GDMA_CHAN_HW_IDLE) {
				read_times++;
				cn_dev_gdma_debug(pchan->gdma_set,
					"gdmac%d channel%d main status:0x%x channel status:0x%x",
					pchan->ctrl->idx, pchan->idx,
					main_chan_status, channel_status);
				if (read_times < 1000) {
					usleep_range(10, 20);
					cn_dev_gdma_debug(pchan->gdma_set,
						"gdmac%d channel%d retry:%d",
						pchan->ctrl->idx, pchan->idx,
						read_times);
					goto retry;
				}
			}
			break;
		}
		cpu_relax();
	} while (retry_count--);

	if (channel_status == GDMA_CHAN_HW_IDLE) {
		cn_dev_gdma_debug(pchan->gdma_set,
				"chan %d.%d with vchan %d-->task%d poll tx done",
				pchan->ctrl->idx, pchan->idx, vchan->idx, vchan->task->idx);
		vchan->task->finish_tx_num += 1;
		vchan->task->channel_done = 1;
		vchan->task->channel_tx_count--;
		ret = GDMA_SUCCESS;
	} else {
		cn_dev_gdma_err(pchan->gdma_set,
			"gdmac%d channel%d with vchan %d-->task%d poll tx error status:0x%x",
			pchan->ctrl->idx, pchan->idx, vchan->idx, vchan->task->idx,
			channel_status);

		cn_dev_gdma_info(pchan->gdma_set,
			"task id %d gdma transfer info:\n"
			"type:%d src:0x%llx dst:0x%llx size:0x%llx value 0x%llx",
			vchan->task->idx,
			vchan->task->transfer.type,
			vchan->task->transfer.src,
			vchan->task->transfer.dst,
			vchan->task->transfer.len,
			vchan->task->transfer.memset_value);
		ret = gdma_channel_process_error(pchan);

		vchan->task->error_flag = 1;
		vchan->task->channel_tx_count--;
	}

	cn_gdma_put_idle_virt_chan(vchan);

	if (!ret) {
		cn_gdma_put_idle_phy_chan(pchan);
	}

	return ret;
}

int cn_gdma_tx_go(struct cn_gdma_phy_chan *pchan,
		struct cn_gdma_virt_chan *vchan)
{
	int ret = GDMA_SUCCESS;

	if (unlikely(!pchan || !vchan || !vchan->task)) {
		return -EINVAL;
	}

	cn_dev_gdma_debug(pchan->gdma_set, "pchan %d.%d tx go",
			pchan->ctrl->idx, pchan->idx);

	pchan->vchan = vchan;
	pchan->status = GDMA_CHANNEL_RUN;
	vchan->status = GDMA_CHANNEL_RUN;
	if (vchan->dma_tx_mode == GDMA_TX_POLL_MODE) {
		ret = gdma_poll_tx_go(pchan, vchan);
	} else {
		ret = gdma_intr_tx_go(pchan, vchan);
	}

	return ret;
}

static int record_onln_state(struct cn_gdma_set *gdma_set, int top_pchan_id)
{
	u32 ctrl_num = gdma_set->info->ctrl_num;
	u32 ctrl_chan_num = gdma_set->info->ctrl_chan_num;
	u32 ctrl_chan_num_mask = (1 << ctrl_chan_num) - 1;
	u32 i;
	u32 j;

	for (i = 0; i < ctrl_num; i++) {
		if ((1 << top_pchan_id) & (ctrl_chan_num_mask << (i * ctrl_chan_num))) {
			gdma_set->ctrl_onln[i] = 1;
			j = top_pchan_id - (i * ctrl_chan_num);
			gdma_set->ctrl_pchan_onln[i][j] = 1;
			break;
		}
	}

	return (i * ctrl_chan_num + j);
}

static int frozen_offln_pchan(struct cn_gdma_set *gdma_set)
{
	int i, j;
	int offln_cnt = 0;
	int index;
	struct cn_gdma_phy_chan *pchan = NULL;

	for (i = 0; i < gdma_set->info->ctrl_num; i++) {
		for (j = 0; j < gdma_set->info->ctrl_chan_num; j++) {
			if (!gdma_set->ctrl_pchan_onln[i][j]) {
				offln_cnt += 1;
				index = i * gdma_set->info->ctrl_chan_num + j;
				pchan = gdma_set->pchan_pool[index];
				down(&gdma_set->total_pchan_sem);
				__sync_lock_test_and_set(&pchan->status, GDMA_CHANNEL_OFFLN);
				cn_dev_gdma_info(pchan->gdma_set, "gdma frozen pchan %d", index);
			}
		}
	}

	return offln_cnt;
}

static void check_and_update_gdma_mask(struct cn_gdma_set *gdma_set)
{
	u32 gdma_mask_init = gdma_set->hw_gdma_mask;
	u32 gdma_mask = 0;
	int i;

	for (i = 0; i < gdma_set->ctrl_num; i++) {
		if (gdma_set->ctrl_onln[i]) {
			gdma_mask |= (1 << i);
		}
	}

	if (gdma_mask != gdma_mask_init) {
		cn_dev_gdma_info(gdma_set, "gdma controller mask(0 means all): init=0x%x  used=0x%x [From DM]",
			gdma_mask_init, gdma_mask);
	}

	gdma_set->hw_gdma_mask = gdma_mask;
}

static int update_gdma_pchan_available_info(struct cn_gdma_set *gdma_set)
{
	struct cn_core_set *core = gdma_set->core;
	int pchan_mask = 0;
	int pchan_available_cnt = 0;
	int pchan_bit_index;
	int i, j;
	u32 gdma_mask = gdma_set->hw_gdma_mask; //Original Hardware gdma controler mask info

	if (!gdma_mask) {
		gdma_mask = ~gdma_mask;
	}

	if (core->device_id != MLUID_580) {
		pchan_available_cnt = gdma_set->info->ctrl_num * gdma_set->info->ctrl_chan_num;
		for (i = 0; i < gdma_set->info->ctrl_num; i++) {
			if (!(gdma_mask & (1 << i))) {
				continue;
			}
			gdma_set->ctrl_onln[i] = 1;
			for (j = 0; j < gdma_set->info->ctrl_chan_num; j++) {
				gdma_set->ctrl_pchan_onln[i][j] = 1;
			}
		}
		goto LABEL_EXIT;
	}

	/***
	 * Get pchan_mask from domain for Card Type MLU580
	 */
	pchan_mask = cn_dm_attr_gdma_host_ch(core);
	if (pchan_mask <= 0) {
		cn_dev_gdma_err(gdma_set, "host gdma has no resource can be used.\n");
		goto LABEL_EXIT;
	}

	/***
	 * Update based on pchan_mask which will also update hw_gdma_mask
	 */
	cn_dev_gdma_info(gdma_set, "host gdma pchan_mask=%x", pchan_mask);
	while (pchan_mask) {
		pchan_bit_index = __ffs(pchan_mask);
		CLR_BIT(pchan_mask, pchan_bit_index);
		pchan_available_cnt += 1;
		record_onln_state(gdma_set, pchan_bit_index);
	}
	check_and_update_gdma_mask(gdma_set);

LABEL_EXIT:
	gdma_set->available_pchan_num = pchan_available_cnt;

	return pchan_available_cnt;
}

int cn_gdma_drv_init(struct cn_gdma_set *gdma_set)
{
	int ret = 0;

	ret = cn_gdma_plat_probe(gdma_set);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "gdma info probe failed\n");
		return ret;
	}

	/***
	 * update pchan info that host gdma hold for Magpie
	 *	1. ARM hold some pchan which is used by JS
	 *	2. HOST hold some pchan which is used as common sync mode
	 */
	if (!update_gdma_pchan_available_info(gdma_set)) {
		cn_dev_gdma_info(gdma_set, "host gdma has no available pchan to init\n");
		return ret;
	}

	/***
	 * To "alloc" and "init ops and RegZone" all ctrl and its pchan that is available
	 * which shall consider about the 'available info' that updated up on.
	 */
	ret = gdma_phy_chan_init(gdma_set);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "gdma get hardware resource failed");
		goto phy_chan_exit;
	}
	frozen_offln_pchan(gdma_set);

	ret = gdma_hardware_init(gdma_set);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "gdma init hardware failed");
		goto hardware_exit;
	}

	ret = gdma_irq_install(gdma_set);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "gdma install irq failed");
		goto irq_exit;
	}

	ret = gdma_channel_diag_register(gdma_set);
	if (ret) {
		cn_dev_gdma_err(gdma_set, "gdma register diagnose failed");
		goto irq_exit;
	}

	return ret;

irq_exit:
	gdma_irq_uninstall(gdma_set);
hardware_exit:
	gdma_hardware_exit(gdma_set);
phy_chan_exit:
	gdma_phy_chan_exit(gdma_set);
	cn_dev_gdma_err(gdma_set, "gdma drv init failed");
	return ret;
}

int cn_gdma_drv_deinit(struct cn_gdma_set *gdma_set)
{
	if (!gdma_set) {
		return -EINVAL;
	}

	if (gdma_set->available_pchan_num) {
		gdma_channel_diag_unregister(gdma_set);
		gdma_irq_uninstall(gdma_set);
		gdma_hardware_exit(gdma_set);
		gdma_phy_chan_exit(gdma_set);
	} else {
		cn_dev_gdma_info(gdma_set, "host gdma has no available pchan to deinit\n");
	}

	return 0;
}
