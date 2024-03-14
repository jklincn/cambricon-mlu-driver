/*
 * gdma/plat/mlu370/gdma_c30s.c
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
#include <linux/delay.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "gdma_c30s.h"
#include "gdma_smmu.h"
#include "../../gdma_common.h"
#include "../../gdma_debug.h"

/*Controller phy resource define*/
static const struct resource cn_c30s_gdma_0_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x0834c000,
		.end = 0x0834c000 + 0x2000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x08340400,
		.end = 0x08340400 + 0x400,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x0834D000,
		.end = 0x0834D000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
};

static const struct resource cn_c30s_gdma_1_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x0034c000,
		.end = 0x0034c000 + 0x2000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x00340000,
		.end = 0x00340000 + 0x400,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x0034D000,
		.end = 0x0034D000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
};

static const struct resource cn_c30s_gdma_2_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x1834c000,
		.end = 0x1834c000 + 0x2000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x18340400,
		.end = 0x18340400 + 0x400,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x1834D000,
		.end = 0x1834D000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
};

static const struct resource cn_c30s_gdma_3_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x1034c000,
		.end = 0x1034c000 + 0x2000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x10340000,
		.end = 0x10340000 + 0x400,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x1034D000,
		.end = 0x1034D000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
};

static const struct cn_gdma_set_info c30s_gdma_single_die_info = {
	.irq_type = GDMA_IRQ_CTRL_TYPE,
	.ctrl_num = 2,
	.ctrl_chan_num = 4,
	.vchan_num = 2048,
	.priv_vchan_num = 64,
	.task_num = 64,
	.memset_buf_size = 2048,
	.smmu_info = {	{0, 0},
			{0, 1},
				}
};

static const struct cn_gdma_set_info c30s_gdma_double_die_info = {
	.irq_type = GDMA_IRQ_CTRL_TYPE,
	.ctrl_num = 4,
	.ctrl_chan_num = 4,
	.vchan_num = 2048,
	.priv_vchan_num = 64,
	.task_num = 64,
	.memset_buf_size = 2048,
	.smmu_info = {	{0, 0},
			{0, 1},
			{1, 0},
			{1, 1},
				}
};

static const int gdma_ctrl_reg_file[] = {
	0x00,
	0x04,
	0x08,
	0x10,
	0x14,
	0x18,
	0x1c,
	0x20,
	0x24,
	0x28,
	0x30,
	0x34,
	0x40,
	0x50,
	0x60,
	0x64,
	0x68,
	0x6c,
};

static const int gdma_chan_reg_file[] = {
	0x00,
	0x04,
	0x08,
	0x0c,
	0x10,
	0x2c,
	0x30,
	0x34,
	0x38,
	0x40,
	0x44,
	0x48,
	0x4c,
	0x50,
	0x54,
	0x58,
	0x5c,
	0x98,
	0x104,
	0x108,
};

static inline u32 cn_gdma_read_reg(struct cn_gdma_set *gdma_set,
		unsigned long base, unsigned long reg)
{
	return reg_read32(gdma_set->core->bus_set, base + reg);
}

static inline void cn_gdma_write_reg(struct cn_gdma_set *gdma_set,
		unsigned long base, unsigned long reg, u32 value)
{
	reg_write32(gdma_set->core->bus_set, base + reg, value);
}

static int cn_gdma_reset_channel(struct cn_gdma_controller *ctrl,
		u32 chnnl)
{
	u32 reg;

	if (chnnl > ctrl->pchan_num) {
		return -EINVAL;
	}

	reg = cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_RST_CTRL);
	reg &= ~(0x1 << chnnl);
	reg |= (0x01 << (chnnl + 16));
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_RST_CTRL, reg);
	udelay(CN_GDMA_MAX_DELAY);
	reg |= (0x1 << chnnl);
	reg |= (0x01 << (chnnl + 16));
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_RST_CTRL, reg);

	return GDMA_SUCCESS;
}

static int cn_gdma_enable_channel_clk(struct cn_gdma_controller *ctrl,
		u32 chnnl)
{
	u32 reg;
	int retry_count;

	if (chnnl > ctrl->pchan_num) {
		return -EINVAL;
	}

	reg = cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_CLK_CTRL);
	reg |= (CLK_CTRL_EANBLE << chnnl);
	reg |= (0x01 << (chnnl + 16));
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_CLK_CTRL, reg);

	retry_count = CN_GDMA_COMMON_RETRY_COUNT;
	do {
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->main_csr_base, GDMA_CLK_STATUS);
		if (reg & (0x01 << chnnl)) {
			break;
		}
		usleep_range(CN_GDMA_MIN_DELAY, CN_GDMA_MAX_DELAY);
	} while (retry_count--);

	if (reg & (0x01 << chnnl)) {
		return GDMA_SUCCESS;
	} else {
		return -GDMA_ERROR;
	}
}

static int cn_gdma_disable_channel_clk(struct cn_gdma_controller *ctrl,
		u32 chnnl)
{
	u32 reg;
	int retry_count;

	if (chnnl > ctrl->pchan_num) {
		return -EINVAL;
	}

	reg = cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_CLK_CTRL);
	reg &= ~(0x1 << chnnl);
	reg |= (0x01 << (chnnl + 16));
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_CLK_CTRL, reg);

	retry_count = CN_GDMA_COMMON_RETRY_COUNT;
	do {
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->main_csr_base, GDMA_CLK_STATUS);
		if (!(reg & (0x01 << chnnl))) {
			break;
		}
		usleep_range(CN_GDMA_MIN_DELAY, CN_GDMA_MAX_DELAY);
	} while (retry_count--);

	if (reg & (0x01 << chnnl)) {
		return GDMA_SUCCESS;
	} else {
		return -GDMA_ERROR;
	}
}

static int cn_gdma_release_reset(struct cn_gdma_controller *ctrl)
{
	int ret = 0;
	int retry_count;
	u32 reg;

	cn_dev_gdma_debug(ctrl->gdma_set, "ctrl %d top_csr_base 0x%lx\n",
							ctrl->idx,
							ctrl->top_csr_base);

	retry_count = CN_GDMA_COMMON_RETRY_COUNT;
	do {
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->top_csr_base, TOP_CSR_GDMA_RSTN_SW_REG);
		reg &= ~TOP_CSR_GDMA_RSTN_MASK;
		cn_gdma_write_reg(ctrl->gdma_set,
				ctrl->top_csr_base, TOP_CSR_GDMA_RSTN_SW_REG, reg);
		usleep_range(CN_GDMA_MIN_DELAY, CN_GDMA_MAX_DELAY);
		reg |= TOP_CSR_GDMA_RSTN_MASK;
		cn_gdma_write_reg(ctrl->gdma_set,
				ctrl->top_csr_base, TOP_CSR_GDMA_RSTN_SW_REG, reg);
		usleep_range(CN_GDMA_MIN_DELAY, CN_GDMA_MAX_DELAY);
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->top_csr_base, TOP_CSR_GDMA_RSTN_SW_REG);
		if ((reg & TOP_CSR_GDMA_RSTN_MASK) == TOP_CSR_GDMA_RSTN_DONE) {
			break;
		}
	} while (retry_count--);

	if ((reg & TOP_CSR_GDMA_RSTN_MASK) != TOP_CSR_GDMA_RSTN_DONE) {
		cn_dev_gdma_err(ctrl->gdma_set, "ctrl %d release reset failed",
						ctrl->idx);
		ret = -GDMA_ERROR;
	}

	return ret;
}

static u32 cn_gdma_read_main_intr_out(struct cn_gdma_controller *ctrl)
{
	return cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_MAIN_CTRL_INT_OUT);
}

static int cn_gdma_main_intr_clear(struct cn_gdma_controller *ctrl)
{
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_MAIN_CTRL_INT_CLR, MAIN_CTRL_INT_CLR_VALUE);

	return GDMA_SUCCESS;
}

static int cn_gdma_get_channel_status(struct cn_gdma_controller *ctrl,
		u32 chnnl, u32 *status)
{
	u32 reg;

	if (chnnl > ctrl->pchan_num) {
		return -EINVAL;
	}

	reg = cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_CHNL_STATUS);
	reg >>= CHNL_STATUS_SHIFT(chnnl);
	*status = reg & CHNL_STATUS_MASK;

	return GDMA_SUCCESS;
}

static u32 cn_gdma_read_dma_int_stat(struct cn_gdma_controller *ctrl)
{
	return cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_DMA_INTSTAT);
}

static int cn_gdma_get_id(struct cn_gdma_controller *ctrl, u32 *id)
{
	*id = cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_ID_REG);

	return GDMA_SUCCESS;
}

static void cn_gdma_channel_start(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CTRL, CHNL_CTRL_START);
}

static void cn_gdma_channel_suspend(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CTRL, CHNL_CTRL_SUSPEND);
}

static void cn_gdma_channel_halt(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CTRL, CHNL_CTRL_HALT);
}

static void cn_gdma_channel_resume(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CTRL, CHNL_CTRL_RESUME);
}

static void cn_gdma_channel_abort(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CTRL, CHNL_CTRL_ABORT);
}

static int cn_gdma_channel_config(struct cn_gdma_phy_chan *chan,
		struct cn_gdma_chan_config *config)
{
	u32 reg = 0;

	reg = config->mode & CHNL_CFG_MODE_MASK;
	reg |= (config->read_ostd << CHNL_CFG_READ_OSTD_SHIFT);
	reg |= (config->write_ostd << CHNL_CFG_WRITE_OSTD_SHIFT);
	reg |= (0x01 << CHNL_CFG_GM_ALIGNED_ENABLE_SHIFT);
	if (config->intr_enable) {
		reg |= (0x01 << CHNL_CFG_INT_ENABLE_SHIFT);
	}
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CFG, reg);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_RGM_AXI_WATTR, config->axi_wattr);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_RGM_AXI_RATTR, config->axi_rattr);
	chan->config_reg = cn_gdma_read_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CFG);

	return GDMA_SUCCESS;
}

static int cn_gdma_channel_descrpt_config(struct cn_gdma_phy_chan *chan,
		struct cn_gdma_descrpt_config *config)
{
	u32 reg = 0;

	reg = (config->store_type << CHNL_DSCRPT_STORE_TYPE_SHIFT);
	reg |= (config->osf_mode << CHNL_DSCRPT_OSF_MODE_SHIFT);
	reg |= (config->buf_block_size << CHNL_DSCRPT_BLOCK_SIZE_SHIFT);
	reg |= (config->prefetch_num << CHNL_DSCRPT_PREFETCH_NUM_SHIFT);
	reg |= (config->prefetch_thresd << CHNL_DSCRPT_PREFETCH_THRESD_SHIFT);
	reg |= (config->write_back_thresd << CHNL_DSCRPT_WB_THRESD_SHIFT);

	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_DSCRPT_CTRL, reg);

	return GDMA_SUCCESS;
}

static int cn_gdma_channel_setup_descrpt_tx(struct cn_gdma_phy_chan *chan,
		u64 desc)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_DSCRPT_ADDR_LO, desc & 0xffffffff);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_DSCRPT_ADDR_HI, (desc >> 32) & 0xffff);

	return GDMA_SUCCESS;
}

static int cn_gdma_channel_setup_reg_mode_tx(struct cn_gdma_phy_chan *chan,
		u64 src, u64 dst, u32 data_len)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_RGM_SRCADDR_LO, src & 0xffffffff);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_RGM_SRCADDR_HI, (src >> 32) & 0xffff);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_RGM_DSTADDR_LO, dst & 0xffffffff);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_RGM_DSTADDR_HI, (dst >> 32) & 0xffff);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_RGM_DATA_LEN, data_len - 1);

	return GDMA_SUCCESS;
}

static int cn_gdma_channel_intr_clear(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_INT_CLR, CHNL_INT_CLR_VALUE);

	return GDMA_SUCCESS;
}

static u32 cn_gdma_read_channel_intr_out(struct cn_gdma_phy_chan *chan)
{
	return cn_gdma_read_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_INT_OUT);
}

static int cn_gdma_ctrl_hardware_init(struct cn_gdma_controller *ctrl)
{
	int ret = 0;
	u32 id;
	u32 reg;
	int i;

	ret = cn_gdma_release_reset(ctrl);
	if (ret) {
		cn_dev_gdma_err(ctrl->gdma_set, "ctrl %d release reset failed", ctrl->idx);
		return ret;
	}

	cn_gdma_get_id(ctrl, &id);
	cn_dev_gdma_debug(ctrl->gdma_set, "gdma ctrl %d id 0x%x", ctrl->idx, id);

	if (ctrl->idx == 0 || ctrl->idx == 2) {
		/* configure DET response data */
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->top_csr_base, TOP_CSR_GDMA_DET_REG);
		cn_gdma_write_reg(ctrl->gdma_set,
				ctrl->top_csr_base, TOP_CSR_GDMA_DET_REG, TOP_CSR_GDMA_DET_VALUE);
	}

	for (i = 0; i < ctrl->pchan_num; i++) {
		ret = cn_gdma_enable_channel_clk(ctrl, i);
		if (ret) {
			cn_dev_gdma_err(ctrl->gdma_set,
					"ctrl %d channel %d clk enable failed",
					ctrl->idx, i);
			return ret;
		}
		cn_dev_gdma_debug(ctrl->gdma_set,
				"ctrl %d channel %d clk enable success",
				ctrl->idx, i);
	}

	//reset gdma channel
	for (i = 0; i < ctrl->pchan_num; i++) {
		ret = cn_gdma_reset_channel(ctrl, i);
		if (ret) {
			cn_dev_gdma_err(ctrl->gdma_set, "ctrl %d reset channel %d failed",
					ctrl->idx, i);
			return ret;
		}
		cn_dev_gdma_debug(ctrl->gdma_set, "ctrl %d reset channel %d success",
				ctrl->idx, i);
	}

	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_DMA_LP_DELAY_CNT, 0xff);

	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_CHNL_AXI0_CFG, 0x6ffe);

	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_SMMU_AUTO_INV_EN, 0xf0f);

	return ret;
}

static int cn_gdma_channel_hardware_init(struct cn_gdma_phy_chan *chan)
{
	struct cn_gdma_chan_config chan_config = {0};
	struct cn_gdma_descrpt_config descrpt_config = {0};
	int ret = 0;

	chan_config.mode = GDMA_CHANNEL_MODE_DSEC;
	chan_config.read_ostd = 0x1f;
	chan_config.write_ostd = 0x1f;
	chan_config.intr_enable = 0;
	chan_config.axi_wattr = 0x11f;
	chan_config.axi_rattr = 0x11f;

	descrpt_config.store_type = GDMA_DESCRPT_STORE_LINK_LIST;
	descrpt_config.osf_mode = 1;
	descrpt_config.buf_block_size = GDMA_DESCRPT_BUF_BLOCK_SIZE_1024;
	descrpt_config.prefetch_num = 1;
	descrpt_config.prefetch_thresd = 1;
	descrpt_config.write_back_thresd = 0;

	ret = cn_gdma_channel_config(chan, &chan_config);
	if (ret) {
		cn_dev_gdma_err(chan->gdma_set,
				"channel %d.%d config failed",
				chan->ctrl->idx, chan->idx);
		return ret;
	}

	ret = cn_gdma_channel_descrpt_config(chan, &descrpt_config);
	if (ret) {
		cn_dev_gdma_err(chan->gdma_set,
				"channel %d.%d desc config failed",
				chan->ctrl->idx, chan->idx);
		return ret;
	}

	return ret;
}

static int cn_gdma_smmu_irq_handle(struct cn_gdma_controller *ctrl)
{
	unsigned int fsr;

	cn_dev_gdma_debug(ctrl->gdma_set, "ctrl %d smmu interrupt ocurr!",
						ctrl->idx);
	smmu370_get_fault(ctrl, &fsr);
	smmu370_dumpreg(ctrl);
	smmu370_clear_fault(ctrl, fsr);

	return GDMA_SUCCESS;
}

static int cn_gdma_do_ctrl_irq(struct cn_gdma_controller *ctrl, u32 *intr_stat)
{
	u32 dma_intr_stat = 0;
	u32 top_irq_status = 0;
	struct cn_gdma_phy_chan *pchan;
	int i = 0;

	top_irq_status = cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->top_csr_base, GDMA_COMMON_INTER);
	if (top_irq_status & 0x01) {
		dma_intr_stat = cn_gdma_read_dma_int_stat(ctrl);
		*intr_stat = dma_intr_stat;
		if (!dma_intr_stat) {
			cn_gdma_smmu_irq_handle(ctrl);
		}
	} else if (top_irq_status & GDMA_MHR_BUS_TT_INTR_MASK) {
		cn_dev_gdma_info(ctrl->gdma_set,
					"ctrl %d mhr tt interrupt,top irq status 0x%x",
					ctrl->idx, top_irq_status);
		ctrl->ops->ctrl_reg_dump(ctrl);
		for( i = 0; i < ctrl->pchan_num; i++) {
			pchan = ctrl->pchans[i];
			ctrl->ops->channel_reg_dump(pchan);
		}

		cn_gdma_write_reg(ctrl->gdma_set,
				ctrl->top_csr_base, GDMA_COMMON_INTER,
				top_irq_status & GDMA_MHR_BUS_TT_INTR_MASK);
	}

	return top_irq_status;
}

static int cn_gdma_channel_irq_enable(struct cn_gdma_phy_chan *chan)
{
	chan->config_reg |= (0x01 << CHNL_CFG_INT_ENABLE_SHIFT);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CFG, chan->config_reg);

	return GDMA_SUCCESS;
}

static int cn_gdma_channel_irq_disable(struct cn_gdma_phy_chan *chan)
{
	chan->config_reg &= ~(0x01 << CHNL_CFG_INT_ENABLE_SHIFT);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CFG, chan->config_reg);

	return GDMA_SUCCESS;
}

static void cn_gdma_ctrl_reg_dump(struct cn_gdma_controller *ctrl)
{
	u32 reg;
	int i;

	cn_dev_gdma_info(ctrl->gdma_set, "gdma%d reg dump:", ctrl->idx);
	for (i = 0; i < ARRAY_SIZE(gdma_ctrl_reg_file); i++) {
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				 ctrl->main_csr_base, gdma_ctrl_reg_file[i]);
		cn_dev_gdma_info(ctrl->gdma_set,
			"0x%x --- 0x%x", gdma_ctrl_reg_file[i], reg);
	}
}

static u32 c30s_gdma_ctrl_reg_dfx_dump(struct cn_gdma_controller *ctrl, char *buf)
{
	u32 reg;
	int i;
	u32 len = 0;
	u32 temp = 0;

	cn_dev_gdma_info(ctrl->gdma_set, "gdma%d reg dfx dump:", ctrl->idx);
	for (i = 0; i < ARRAY_SIZE(gdma_ctrl_reg_file); i++) {
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->main_csr_base, gdma_ctrl_reg_file[i]);
		temp = sprintf(buf + len, "[ctrl 0x%x]:[reg 0x%.4x]:[value 0x%.8x]\n",
				ctrl->idx,
				gdma_ctrl_reg_file[i],
				reg);
		len += temp;
	}
	return len;
}

static void cn_gdma_chan_reg_dump(struct cn_gdma_phy_chan *channel)
{
	u32 reg;
	int i;

	cn_dev_gdma_info(channel->gdma_set, "gdma%d channel%d reg dump:",
			channel->ctrl->idx, channel->idx);
	for (i = 0; i < ARRAY_SIZE(gdma_chan_reg_file); i++) {
		reg = cn_gdma_read_reg(channel->gdma_set,
				 channel->base, gdma_chan_reg_file[i]);
		cn_dev_gdma_info(channel->gdma_set,
			"0x%x --- 0x%x", gdma_chan_reg_file[i], reg);
	}
}

static u32 c30s_gdma_chan_reg_dfx_dump(struct cn_gdma_phy_chan *channel, char *buf)
{
	u32 reg;
	int i;
	u32 len = 0;
	u32 temp = 0;

	cn_dev_gdma_info(channel->gdma_set, "gdma%d channel%d reg dump:",
			channel->ctrl->idx, channel->idx);
	for (i = 0; i < ARRAY_SIZE(gdma_chan_reg_file); i++) {
		reg = cn_gdma_read_reg(channel->gdma_set,
				channel->base, gdma_chan_reg_file[i]);
		temp = sprintf(buf + len, "ctrl:%d,channel:%d,[0x%.4x] --- 0x%.8x\n",
				channel->ctrl->idx,
				channel->idx, gdma_chan_reg_file[i],
				reg);
		len += temp;
	}
	return len;
}

static void gdma_chan_ecc_inject(struct cn_gdma_phy_chan *channel, int enable)
{
	cn_dev_gdma_info(channel->gdma_set, "gdma%d channel%d not support buffer ecc",
			channel->ctrl->idx, channel->idx);
	return;
}

static const struct cn_gdma_ops gdma_plat_c30s_ops = {
	.release_reset = cn_gdma_release_reset,
	.reset_channel = cn_gdma_reset_channel,
	.enable_channel_clk = cn_gdma_enable_channel_clk,
	.disable_channel_clk = cn_gdma_disable_channel_clk,
	.read_main_intr_out = cn_gdma_read_main_intr_out,
	.main_intr_clear = cn_gdma_main_intr_clear,
	.get_channel_status = cn_gdma_get_channel_status,
	.read_dma_int_stat = cn_gdma_read_dma_int_stat,
	.get_id = cn_gdma_get_id,
	.channel_start = cn_gdma_channel_start,
	.channel_suspend = cn_gdma_channel_suspend,
	.channel_halt = cn_gdma_channel_halt,
	.channel_resume = cn_gdma_channel_resume,
	.channel_abort = cn_gdma_channel_abort,
	.channel_setup_descrpt_tx = cn_gdma_channel_setup_descrpt_tx,
	.channel_setup_reg_mode_tx = cn_gdma_channel_setup_reg_mode_tx,
	.channel_intr_clear = cn_gdma_channel_intr_clear,
	.read_channel_intr_out = cn_gdma_read_channel_intr_out,
	.ctrl_hardware_init = cn_gdma_ctrl_hardware_init,
	.channel_hardware_init = cn_gdma_channel_hardware_init,
	.do_ctrl_irq = cn_gdma_do_ctrl_irq,
	.ctrl_reg_dump = cn_gdma_ctrl_reg_dump,
	.channel_reg_dump = cn_gdma_chan_reg_dump,
	.channel_irq_enable = cn_gdma_channel_irq_enable,
	.channel_irq_disable = cn_gdma_channel_irq_disable,
	.channel_ecc_inject = gdma_chan_ecc_inject,
	.ctrl_reg_dfx_dump = c30s_gdma_ctrl_reg_dfx_dump,
	.channel_reg_dfx_dump = c30s_gdma_chan_reg_dfx_dump,
};

static const struct resource *cn_plat_c30s_gdma_resource(int dev_num)
{
	switch (dev_num) {
	case 0:
		return cn_c30s_gdma_0_resource;
	case 1:
		return cn_c30s_gdma_1_resource;
	case 2:
		return cn_c30s_gdma_2_resource;
	case 3:
		return cn_c30s_gdma_3_resource;
	default:
		return NULL;
	}
}

int cn_gdma_plat_c30s_init(void *dev, int dev_num)
{
	struct cn_gdma_controller *ctrl = (struct cn_gdma_controller *)dev;
	const struct resource *res = NULL;
	char gdma_name[32] = {0};

	cn_dev_gdma_debug(ctrl->gdma_set, "gdma plat c30s ctrl %d init begin",
					dev_num);

	if (dev_num < 0 || dev_num >= ctrl->gdma_set->ctrl_num) {
		return -EINVAL;
	}

	res = cn_plat_c30s_gdma_resource(dev_num);
	if (!res) {
		cn_dev_gdma_err(ctrl->gdma_set,
				"gdma plat c30s ctrl %d resource is null",
				dev_num);
		return -GDMA_ERROR;
	}

	ctrl->main_csr_base = res[CN_GDMA_PLAT_C30S_MAIN_CSR_INDEX].start;
	ctrl->top_csr_base = res[CN_GDMA_PLAT_C30S_TOP_CSR_INDEX].start;
	snprintf(gdma_name, sizeof(gdma_name) - 1, "gdma%d", dev_num);
	ctrl->irq = cn_bus_get_irq_by_desc(ctrl->gdma_set->core->bus_set, gdma_name);
	cn_dev_gdma_debug(ctrl->gdma_set, "gdma c30s ctrl %d irq %d",
				dev_num, ctrl->irq);
	ctrl->smmu_base = res[CN_GDMA_PLAT_C30S_SMMU_INDEX].start;
	ctrl->ops = &gdma_plat_c30s_ops;

	cn_dev_gdma_debug(ctrl->gdma_set, "gdma plat c30s ctrl %d init end",
				dev_num);

	return GDMA_SUCCESS;
}

int cn_gdma_plat_c30s_info_probe(void *set)
{
	int ret = 0;
	struct cn_gdma_set *gdma_set = set;
	struct cn_core_set *core = gdma_set->core;

	switch (core->die_cnt) {
	case 1:
		gdma_set->info = &c30s_gdma_single_die_info;
		break;
	case 2:
		gdma_set->info = &c30s_gdma_double_die_info;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	gdma_set->ctrl_num = gdma_set->info->ctrl_num;

	return ret;
}
