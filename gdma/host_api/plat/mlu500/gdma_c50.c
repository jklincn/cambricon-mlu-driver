/*
 * gdma/plat/mlu590/gdma_c50.c
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
#include "gdma_c50.h"
#include "../../gdma_common.h"
#include "../../gdma_debug.h"

/*Controller phy resource define*/
static const struct resource c50_gdma_0_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x01964000,
		.end = 0x01964000 + 0x4000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x00915508,
		.end = 0x00915508 + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x01966000,
		.end = 0x01966000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 259,
		.end = 259,
		.flags = IORESOURCE_IRQ,
	}
};

static const struct resource c50_gdma_1_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x01968000,
		.end = 0x01968000 + 0x4000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x0091550c,
		.end = 0x0091550c + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x0196a000,
		.end = 0x0196a000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 261,
		.end = 261,
		.flags = IORESOURCE_IRQ,
	}
};
static const struct resource c50_gdma_2_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x0196c000,
		.end = 0x0196c000 + 0x4000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x00915564,
		.end = 0x00915564 + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x0196e000,
		.end = 0x0196e000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 263,
		.end = 263,
		.flags = IORESOURCE_IRQ,
	}
};

static const struct resource c50_gdma_3_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x01970000,
		.end = 0x01970000 + 0x4000,
		.flags = IORESOURCE_MEM,

	},
	//TOP CSR
	[1] = {
		.start = 0x00915568,
		.end = 0x00915568 + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x01972000,
		.end = 0x01972000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 265,
		.end = 265,
		.flags = IORESOURCE_IRQ,
	}
};

static const struct resource c50_gdma_4_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x01974000,
		.end = 0x01974000 + 0x4000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x0091556c,
		.end = 0x0091556c + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x01976000,
		.end = 0x01976000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 267,
		.end = 267,
		.flags = IORESOURCE_IRQ,
	}
};

static const struct resource c50_gdma_5_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x01978000,
		.end = 0x01978000 + 0x4000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x00915570,
		.end = 0x00915570 + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x0197a000,
		.end = 0x0197a000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 269,
		.end = 269,
		.flags = IORESOURCE_IRQ,
	}
};

//MLU585
static const struct resource c50s_gdma_0_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x00A20000,
		.end = 0x00A20000 + 0x4000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x002A0508,
		.end = 0x002A0108 + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x00A22000,
		.end = 0x00A22000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 222,
		.end = 222,
		.flags = IORESOURCE_IRQ,
	}
};

static const struct resource c50s_gdma_1_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x00C20000,
		.end = 0x00C20000 + 0x4000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x002A050C,
		.end = 0x002A010C + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x00C22000,
		.end = 0x00C22000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 224,
		.end = 224,
		.flags = IORESOURCE_IRQ,
	}
};

static const struct resource c50s_gdma_2_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x00C30000,
		.end = 0x00C30000 + 0x4000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x002A0510,
		.end = 0x002A0110 + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x00C32000,
		.end = 0x00C32000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 226,
		.end = 226,
		.flags = IORESOURCE_IRQ,
	}
};

static const struct resource c50s_gdma_3_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x01620000,
		.end = 0x01620000 + 0x4000,
		.flags = IORESOURCE_MEM,

	},
	//TOP CSR
	[1] = {
		.start = 0x002A0514,
		.end = 0x002A0114 + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x01622000,
		.end = 0x01622000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 228,
		.end = 228,
		.flags = IORESOURCE_IRQ,
	}
};

static const struct resource c50s_gdma_4_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x01630000,
		.end = 0x01630000 + 0x4000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x002A0518,
		.end = 0x002A0118 + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x01632000,
		.end = 0x01632000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 230,
		.end = 230,
		.flags = IORESOURCE_IRQ,
	}
};

static const struct resource c50s_gdma_5_resource[] = {
	//MAIN CSR
	[0] = {
		.start = 0x01820000,
		.end = 0x01820000 + 0x4000,
		.flags = IORESOURCE_MEM,
	},
	//TOP CSR
	[1] = {
		.start = 0x002A051C,
		.end = 0x002A011C + 0x4,
		.flags = IORESOURCE_MEM,
	},
	//SMMU
	[2] = {
		.start = 0x01822000,
		.end = 0x01822000 + 0x1000,
		.flags = IORESOURCE_MEM,
	},
	//IRQ
	[3] = {
		.start = 232,
		.end = 232,
		.flags = IORESOURCE_IRQ,
	}
};


static struct cn_gdma_set_info c50s_gdma_single_die_info = {
	.irq_type = GDMA_IRQ_CTRL_TYPE,
	.ctrl_num = 6,
	.ctrl_chan_num = 2,
	.vchan_num = 2048,
	.priv_vchan_num = 64,
	.task_num = 64,
	.memset_buf_size = 2048,
	.smmu_info = {	{0, 0},
			{0, 1},
			{0, 2},
			{0, 3},
			{0, 4},
			{0, 5},
				}
};

static struct cn_gdma_set_info c50_gdma_single_die_info = {
	.irq_type = GDMA_IRQ_CTRL_TYPE,
	.ctrl_num = 6,
	.ctrl_chan_num = 2,
	.vchan_num = 2048,
	.priv_vchan_num = 64,
	.task_num = 64,
	.memset_buf_size = 2048,
	.smmu_info = {	{0, 0},
			{0, 1},
			{0, 2},
			{0, 3},
			{0, 4},
			{0, 5},
				}
};


static const struct gdma_reg gdma_ctrl_reg_file[] = {
	{0x00, "ID_REG"},
	{0x04, "TEST_REG"},
	{0x08, "SECU_CTRL"},
	{0x10, "CLK_CTRL"},
	{0x14, "CLK_STATUS"},
	{0x18, "RST_CTRL"},
	{0x1c, "DMA_INTSTAT"},
	{0x20, "CHNL_STATUS"},
	{0x24, "CHNL_NS"},
	{0x28, "CHNL_PRIORITY"},
	{0x30, "CHNL_AXI0_CFG"},
	{0x34, "CHNL_AXI1_CFG"},
	{0x40, "SMMU_AUTO_INV_EN"},
	{0x50, "DMA_LP_DELAY_CNT"},
	{0x70, "XMIF0_GMW_DEBUG"},
	{0x74, "XMIF0_GMR_DEBUG"},
	{0x78, "XMIF1_GMW_DEBUG"},
	{0x7c, "XMIF1_GMR_DEBUG"},
};

static const struct gdma_reg gdma_chan_reg_file[] = {
	{0x00, "CHNL_CTRL"},
	{0x04, "CHNL_CFG"},
	{0x08, "CHNL_DSCRPT_CTRL"},
	{0x0c, "CHNL_DSCRPT_ADDR_LO"},
	{0x10, "CHNL_DSCRPT_ADDR_HI"},
	{0x14, "CHNL_DSCRPT_BUF_HEAD_LO"},
	{0x18, "CHNL_DSCRPT_BUF_HEAD_HI"},
	{0x1c, "CHNL_DSCRPT_TAIL_PTR_LO"},
	{0x20, "CHNL_DSCRPT_TAIL_PTR_HI"},
	{0x24, "CHNL_DSCRPT_AXI_ATTR"},
	{0x28, "CHNL_DSCRPT_USER_ATTR"},
	{0x2c, "CHNL_REGMODE_CTRL"},
	{0x30, "CHNL_RGM_SRCADDR_LO"},
	{0x34, "CHNL_RGM_SRCADDR_HI"},
	{0x38, "CHNL_RGM_DSTADDR_LO"},
	{0x3c, "CHNL_RGM_DSTADDR_HI"},
	{0x40, "CHNL_RGM_DATA_LEN"},
	{0x44, "CHNL_RGM_AXI_WATTR"},
	{0x48, "CHNL_RGM_AXI_RATTR"},
	{0x4c, "CHNL_RGM_USER_ATTR"},
	{0x98, "CHNL_RAW_INT"},
	{0x9c, "CHNL_INT_MASK"},
	{0x100, "CHNL_INT_CLR"},
	{0x104, "CHNL_INT_OUT"},
	{0x108, "CHNL_INT_CNT"},
	{0x10c, "ECC_ERR_INJECT"},
	{0x180, "CHNL_DBG_CFG0"},
	{0x184, "CHNL_DBG_CFG1"},
	{0x184, "CHNL_DBG_CFG1"},
	{0x188, "CHNL_DBG_DSCRPT0"},
	{0x18c, "CHNL_DBG_DSCRPT1"},
	{0x190, "CHNL_DBG_DSCRPT2"},
	{0x194, "CHNL_DBG_DSCRPT3"},
	{0x198, "CHNL_DBG_DSCRPT4"},
	{0x19c, "CHNL_DBG_DSCRPT5"},
	{0x1a0, "CHNL_DBG_DSCRPT0_INFO"},
	{0x1a4, "CHNL_DBG_DSCRPT1_INFO"},
	{0x1a8, "CHNL_DBG_DSCRPT_FSM"},
	{0x1ac, "CHNL_DBG_TX0"},
	{0x1b0, "CHNL_DBG_TX1"},
	{0x1b4, "CHNL_DBG_TX2"},
	{0x1b8, "CHNL_DBG_RX0"},
	{0x1bc, "CHNL_DBG_RX1"},
	{0x1c0, "CHNL_DBG_RX2"},
	{0x1c4, "CHNL_DBG_SF0"},
	{0x1c8, "CHNL_DBG_SF1"},
	{0x1cc, "CHNL_DBG_SF2"},
	{0x1d0, "CHNL_DBG_SF3"},
	{0x1d4, "CHNL_DBG_SF_FSM"},
	{0x1d8, "CHNL_DBG_MEM0"},
	{0x1dc, "CHNL_DBG_FSM0"},
	{0x1e0, "CHNL_DBG_FSM1"},
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

static int c50_gdma_reset_channel(struct cn_gdma_controller *ctrl,
		u32 chnnl)
{
	u32 reg;

	reg = cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_RST_CTRL);
	reg &= ~(0x1 << chnnl);
	reg |= (0x01 << (chnnl + 16));
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_RST_CTRL, reg);
	udelay(GDMA_MAX_DELAY);
	reg |= (0x1 << chnnl);
	reg |= (0x01 << (chnnl + 16));
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_RST_CTRL, reg);

	if (ctrl->gdma_set->core->device_id == MLUID_580) {
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->main_csr_base, GDMA_RST_CTRL);
		reg &= ~(0x1 << 1);
		reg |= (0x01 << (1 + 16));
		cn_gdma_write_reg(ctrl->gdma_set,
				ctrl->main_csr_base, GDMA_RST_CTRL, reg);
		udelay(GDMA_MAX_DELAY);
		reg |= (0x1 << 1);
		reg |= (0x01 << (1 + 16));
		cn_gdma_write_reg(ctrl->gdma_set,
				ctrl->main_csr_base, GDMA_RST_CTRL, reg);
	}
	return GDMA_SUCCESS;
}

static int c50_gdma_enable_channel_clk(struct cn_gdma_controller *ctrl,
		u32 chnnl)
{
	u32 reg;

	if (chnnl > ctrl->pchan_num) {
		return -EINVAL;
	}

	reg = cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_CLK_CTRL);
	reg |= (CLK_CTRL_EANBLE << chnnl);
	reg |= (CLK_CTRL_EANBLE << (chnnl + 16));
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_CLK_CTRL, reg);

	if (ctrl->gdma_set->core->device_id == MLUID_580) {
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->main_csr_base, GDMA_CLK_CTRL);
		reg |= (1 << 1);
		reg |= (1 << (1 + 16));
		cn_gdma_write_reg(ctrl->gdma_set,
				ctrl->main_csr_base, GDMA_CLK_CTRL, reg);
	}

	if (reg & (0x01 << chnnl)) {
		return GDMA_SUCCESS;
	} else {
		return -GDMA_ERROR;
	}
}

static int c50_gdma_disable_channel_clk(struct cn_gdma_controller *ctrl,
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

	retry_count = GDMA_COMMON_RETRY_COUNT;
	do {
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->main_csr_base, GDMA_CLK_STATUS);
		if (!(reg & (0x01 << chnnl))) {
			break;
		}
		usleep_range(GDMA_MIN_DELAY, GDMA_MAX_DELAY);
	} while (retry_count--);

	if (reg & (0x01 << chnnl)) {
		return GDMA_SUCCESS;
	} else {
		return -GDMA_ERROR;
	}
}

static int c50_gdma_release_reset(struct cn_gdma_controller *ctrl)
{
	int ret = 0;
	int retry_count;
	u32 reg;

	retry_count = GDMA_COMMON_RETRY_COUNT;
	do {
		cn_gdma_write_reg(ctrl->gdma_set,
				ctrl->top_csr_base, TOP_CSR_GDMA_RSTN_SW_REG, 0x10000);
		usleep_range(5, 10);
		cn_gdma_write_reg(ctrl->gdma_set,
				ctrl->top_csr_base, TOP_CSR_GDMA_RSTN_SW_REG, 0x10001);
		usleep_range(5, 10);
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

static u32 c50_gdma_read_main_intr_out(struct cn_gdma_controller *ctrl)
{
	return 0;
}

static int c50_gdma_main_intr_clear(struct cn_gdma_controller *ctrl)
{
	return 0;
}


static int c50_gdma_get_channel_status(struct cn_gdma_controller *ctrl,
		u32 chnnl, u32 *status)
{
	u32 reg;

	reg = cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_CHNL_STATUS);
	reg >>= CHNL_STATUS_SHIFT(chnnl);
	*status = reg & CHNL_STATUS_MASK;

	return GDMA_SUCCESS;
}

static u32 c50_gdma_read_dma_int_stat(struct cn_gdma_controller *ctrl)
{
	return cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_DMA_INTSTAT);
}

static int c50_gdma_get_id(struct cn_gdma_controller *ctrl, u32 *id)
{
	*id = cn_gdma_read_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_ID_REG);

	return GDMA_SUCCESS;
}

static void c50_gdma_channel_start(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CTRL, CHNL_CTRL_START);
}

static void c50_gdma_channel_suspend(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CTRL, CHNL_CTRL_SUSPEND);
}

static void c50_gdma_channel_halt(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CTRL, CHNL_CTRL_HALT);
}

static void c50_gdma_channel_resume(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CTRL, CHNL_CTRL_RESUME);
}

static void c50_gdma_channel_abort(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CTRL, CHNL_CTRL_ABORT);
}

static int c50_gdma_channel_config(struct cn_gdma_phy_chan *chan,
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

	if (chan->gdma_set->core->device_id == MLUID_580) {
		reg &= 0xfffffffe;
		cn_gdma_write_reg(chan->gdma_set,
				chan->base + 0x200, GDMA_CHNL_CFG, reg);
		cn_gdma_write_reg(chan->gdma_set,
				chan->base + 0x200, GDMA_CHNL_RGM_AXI_WATTR, config->axi_wattr);
		cn_gdma_write_reg(chan->gdma_set,
				chan->base + 0x200, GDMA_CHNL_RGM_AXI_RATTR, config->axi_rattr);
	}

	return GDMA_SUCCESS;
}

static int c50_gdma_channel_descrpt_config(struct cn_gdma_phy_chan *chan,
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

static int c50_gdma_channel_setup_descrpt_tx(struct cn_gdma_phy_chan *chan,
		u64 desc)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_DSCRPT_ADDR_LO, desc & 0xffffffff);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_DSCRPT_ADDR_HI, (desc >> 32) & 0xffff);

	return GDMA_SUCCESS;
}

static int c50_gdma_channel_setup_reg_mode_tx(struct cn_gdma_phy_chan *chan,
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

static int c50_gdma_channel_intr_clear(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_INT_CLR, CHNL_INT_CLR_VALUE);

	return GDMA_SUCCESS;
}

static u32 c50_gdma_read_channel_intr_out(struct cn_gdma_phy_chan *chan)
{
	return cn_gdma_read_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_INT_OUT);
}

static void c50s_gdma_js_mode(struct cn_gdma_controller *ctrl)
{
	//set chan1 to js mode
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_INT_CTRL, 0x02);
}

static int c50_gdma_ctrl_hardware_init(struct cn_gdma_controller *ctrl)
{
	int ret = 0;
	u32 id;
	int i;
	u32 reg;

	ret = c50_gdma_release_reset(ctrl);
	if (ret) {
		cn_dev_gdma_err(ctrl->gdma_set, "ctrl %d release reset failed", ctrl->idx);
		return ret;
	}

	c50_gdma_get_id(ctrl, &id);
	if (id != GDMA_ID) {
		cn_dev_gdma_err(ctrl->gdma_set, "ctrl %d get id 0x%x not equal 0x%x",
			ctrl->idx, id, GDMA_ID);
		return -1;
	}

	//GDMA_TEST_REG test read & write
	for (i = 0; i < 32; i++) {
		cn_gdma_write_reg(ctrl->gdma_set,
				ctrl->main_csr_base, GDMA_TEST_REG, 0x01 << i);
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->main_csr_base, GDMA_TEST_REG);
		if (reg != (0x01 << i)) {
			cn_dev_gdma_err(ctrl->gdma_set,
				"ctrl %d test reg write 0x%x, read back 0x%x failed",
				ctrl->idx, 0x1 << i, reg);
			return -1;
		}
	}

	if (ctrl->gdma_set->core->device_id == MLUID_580) {
		cn_dev_gdma_info(ctrl->gdma_set, "set ctrl chan1 js mode");
		c50s_gdma_js_mode(ctrl);
	}

	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_DMA_LP_DELAY_CNT, 0xff);

	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_CHNL_AXI0_CFG, 0x18fefe);

	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_SMMU_AUTO_INV_EN, 0xffff);

	/* SMMU and gdmac clock enable */
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, CLK_CTRL, 0x10001);

	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, GDMA_SECU_CTRL, 0x00);

	/*config AXSECU_CFG as all allow*/
	cn_gdma_write_reg(ctrl->gdma_set,
			ctrl->main_csr_base, AXSECU_CFG, 0x21);

	return ret;
}

static int c50_gdma_channel_clken_and_reset(struct cn_gdma_phy_chan *chan)
{
	struct cn_gdma_controller *ctrl = chan->ctrl;
	int idx = chan->idx;
	int ret = 0;

	cn_dev_gdma_info(ctrl->gdma_set, "ctrl %d channel %d do clken and reset",
				ctrl->idx, idx);
	//clk enable
	ret = c50_gdma_enable_channel_clk(ctrl, idx);
	if (ret) {
		cn_dev_gdma_err(ctrl->gdma_set,
			"ctrl %d channel %d clk enable failed",
			ctrl->idx, idx);
		return ret;
	}

	//reset gdma channel
	ret = c50_gdma_reset_channel(ctrl, idx);
	if (ret) {
		cn_dev_gdma_err(ctrl->gdma_set, "ctrl %d reset channel %d failed",
			ctrl->idx, idx);
		return ret;
	}

	return ret;
}

static int c50_gdma_channel_hardware_init(struct cn_gdma_phy_chan *chan)
{
	struct cn_gdma_chan_config chan_config = {0};
	struct cn_gdma_descrpt_config descrpt_config = {0};
	int ret = 0;

	/* Do channel clken and reset at first */
	c50_gdma_channel_clken_and_reset(chan);

	/* Config channel work mode */
	chan_config.mode = GDMA_CHANNEL_MODE_DSEC;
	chan_config.read_ostd = 0x7;
	chan_config.write_ostd = 0x7;
	chan_config.intr_enable = 0;
	chan_config.axi_wattr = 0x813f;
	chan_config.axi_rattr = 0x813f;

	descrpt_config.store_type = GDMA_DESCRPT_STORE_LINK_LIST;
	//descrpt_config.osf_mode = 1;
	descrpt_config.osf_mode = 0;
	descrpt_config.buf_block_size = GDMA_DESCRPT_BUF_BLOCK_SIZE_1024;
	descrpt_config.prefetch_num = 1;
	descrpt_config.prefetch_thresd = 1;
	descrpt_config.write_back_thresd = 0;

	ret = c50_gdma_channel_config(chan, &chan_config);
	if (ret) {
		cn_dev_gdma_err(chan->gdma_set,
				"channel %d.%d config failed",
				chan->ctrl->idx, chan->idx);
		return ret;
	}

	ret = c50_gdma_channel_descrpt_config(chan, &descrpt_config);
	if (ret) {
		cn_dev_gdma_err(chan->gdma_set,
				"channel %d.%d desc config failed",
				chan->ctrl->idx, chan->idx);
		return ret;
	}

	return ret;
}

static int c50_gdma_do_ctrl_irq(struct cn_gdma_controller *ctrl, u32 *intr_stat)
{
	u32 dma_intr_stat = 0;

	dma_intr_stat = c50_gdma_read_dma_int_stat(ctrl);
	*intr_stat = dma_intr_stat;

	return dma_intr_stat;
}

static int c50_gdma_channel_irq_enable(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_INT_MASK, 0x0000);
	chan->config_reg |= (0x01 << CHNL_CFG_INT_ENABLE_SHIFT);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CFG, chan->config_reg);

	return GDMA_SUCCESS;
}

static int c50_gdma_channel_irq_disable(struct cn_gdma_phy_chan *chan)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_INT_MASK, 0x7efff);
	chan->config_reg &= ~(0x01 << CHNL_CFG_INT_ENABLE_SHIFT);
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_CHNL_CFG, chan->config_reg);

	return GDMA_SUCCESS;
}

static void c50_gdma_ctrl_reg_dump(struct cn_gdma_controller *ctrl)
{
	u32 reg;
	int i;

	cn_dev_gdma_info(ctrl->gdma_set, "gdma%d reg dump:", ctrl->idx);
	for (i = 0; i < ARRAY_SIZE(gdma_ctrl_reg_file); i++) {
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				 ctrl->main_csr_base, gdma_ctrl_reg_file[i].addr);
		cn_dev_gdma_info(ctrl->gdma_set,
			"[0x%.4x] --- 0x%.8x --- %s",
			gdma_ctrl_reg_file[i].addr, reg,
			gdma_ctrl_reg_file[i].name);
	}
}

static void c50_gdma_chan_reg_dump(struct cn_gdma_phy_chan *channel)
{
	u32 reg;
	int i;

	cn_dev_gdma_info(channel->gdma_set, "gdma%d channel%d reg dump:",
			channel->ctrl->idx, channel->idx);
	for (i = 0; i < ARRAY_SIZE(gdma_chan_reg_file); i++) {
		reg = cn_gdma_read_reg(channel->gdma_set,
				 channel->base, gdma_chan_reg_file[i].addr);
		cn_dev_gdma_info(channel->gdma_set,
			"[0x%.4x] --- 0x%.8x --- %s",
			gdma_chan_reg_file[i].addr, reg,
			gdma_chan_reg_file[i].name);
	}
}

static u32 c50_gdma_ctrl_reg_dfx_dump(struct cn_gdma_controller *ctrl, char *buf)
{
	u32 reg;
	int i;
	u32 len = 0;
	u32 temp = 0;

	cn_dev_gdma_info(ctrl->gdma_set, "gdma%d reg dfx dump:", ctrl->idx);
	for (i = 0; i < ARRAY_SIZE(gdma_ctrl_reg_file); i++) {
		reg = cn_gdma_read_reg(ctrl->gdma_set,
				ctrl->main_csr_base, gdma_ctrl_reg_file[i].addr);
		temp = sprintf(buf + len, "[ctrl 0x%x]:[reg 0x%.4x]:[value 0x%.8x]:[name %s]\n",
				ctrl->idx,
				gdma_ctrl_reg_file[i].addr, reg,
				gdma_ctrl_reg_file[i].name);
		len += temp;
	}
	return len;
}

static u32 c50_gdma_chan_reg_dfx_dump(struct cn_gdma_phy_chan *channel, char *buf)
{
	u32 reg;
	int i;
	u32 len = 0;
	u32 temp = 0;

	cn_dev_gdma_info(channel->gdma_set, "gdma%d channel%d reg dump:",
			channel->ctrl->idx, channel->idx);
	for (i = 0; i < ARRAY_SIZE(gdma_chan_reg_file); i++) {
		reg = cn_gdma_read_reg(channel->gdma_set,
				channel->base, gdma_chan_reg_file[i].addr);
		temp = sprintf(buf + len, "ctrl:%d,channel:%d,[0x%.4x] --- 0x%.8x --- %s\n",
				channel->ctrl->idx, channel->idx,
				gdma_chan_reg_file[i].addr, reg,
				gdma_chan_reg_file[i].name);
		len += temp;
	}
	return len;
}

static void c50_gdma_chan_ecc_inject(struct cn_gdma_phy_chan *chan, int enable)
{
	cn_gdma_write_reg(chan->gdma_set,
			chan->base, GDMA_ECC_ERR_INJECT, enable);
}

static const struct cn_gdma_ops gdma_plat_c50_ops = {
	.release_reset = c50_gdma_release_reset,
	.reset_channel = c50_gdma_reset_channel,
	.enable_channel_clk = c50_gdma_enable_channel_clk,
	.disable_channel_clk = c50_gdma_disable_channel_clk,
	.read_main_intr_out = c50_gdma_read_main_intr_out,
	.main_intr_clear = c50_gdma_main_intr_clear,
	.get_channel_status = c50_gdma_get_channel_status,
	.read_dma_int_stat = c50_gdma_read_dma_int_stat,
	.get_id = c50_gdma_get_id,
	.channel_start = c50_gdma_channel_start,
	.channel_suspend = c50_gdma_channel_suspend,
	.channel_halt = c50_gdma_channel_halt,
	.channel_resume = c50_gdma_channel_resume,
	.channel_abort = c50_gdma_channel_abort,
	.channel_setup_descrpt_tx = c50_gdma_channel_setup_descrpt_tx,
	.channel_setup_reg_mode_tx = c50_gdma_channel_setup_reg_mode_tx,
	.channel_intr_clear = c50_gdma_channel_intr_clear,
	.read_channel_intr_out = c50_gdma_read_channel_intr_out,
	.ctrl_hardware_init = c50_gdma_ctrl_hardware_init,
	.channel_hardware_init = c50_gdma_channel_hardware_init,
	.do_ctrl_irq = c50_gdma_do_ctrl_irq,
	.ctrl_reg_dump = c50_gdma_ctrl_reg_dump,
	.channel_reg_dump = c50_gdma_chan_reg_dump,
	.channel_irq_enable = c50_gdma_channel_irq_enable,
	.channel_irq_disable = c50_gdma_channel_irq_disable,
	.channel_ecc_inject = c50_gdma_chan_ecc_inject,
	.ctrl_reg_dfx_dump = c50_gdma_ctrl_reg_dfx_dump,
	.channel_reg_dfx_dump = c50_gdma_chan_reg_dfx_dump,
};

static const struct resource *cn_plat_c50_gdma_resource(int dev_num)
{
	switch (dev_num) {
	case 0:
		return c50_gdma_0_resource;
	case 1:
		return c50_gdma_1_resource;
	case 2:
		return c50_gdma_2_resource;
	case 3:
		return c50_gdma_3_resource;
	case 4:
		return c50_gdma_4_resource;
	case 5:
		return c50_gdma_5_resource;
	default:
		return NULL;
	}
}

static const struct resource *cn_plat_c50s_gdma_resource(int dev_num)
{
	switch (dev_num) {
	case 0:
		return c50s_gdma_0_resource;
	case 1:
		return c50s_gdma_1_resource;
	case 2:
		return c50s_gdma_2_resource;
	case 3:
		return c50s_gdma_3_resource;
	case 4:
		return c50s_gdma_4_resource;
	case 5:
		return c50s_gdma_5_resource;
	default:
		return NULL;
	}
}

int cn_gdma_plat_c50_init(void *dev, int dev_num)
{
	struct cn_gdma_controller *ctrl = (struct cn_gdma_controller *)dev;
	struct cn_gdma_set_info *info = &c50_gdma_single_die_info;
	const struct resource *res = NULL;

	if (dev_num < 0 || dev_num >= info->ctrl_num) {
		cn_dev_gdma_err(ctrl->gdma_set,
				"gdma index value %d (%d - %d)is error",
				dev_num, 0, info->ctrl_num);
		return -EINVAL;
	}

	if (ctrl->gdma_set->plat_drv->device_id == MLUID_580) {
		res = cn_plat_c50s_gdma_resource(dev_num);
	} else {
		dev_num = ctrl->gdma_set->info->smmu_info[dev_num].smmu_index;
		res = cn_plat_c50_gdma_resource(dev_num);
		ctrl->idx = dev_num;
	}
	if (!res) {
		cn_dev_gdma_err(ctrl->gdma_set,
				"gdma plat c50 ctrl %d resource is null", dev_num);
		return -GDMA_ERROR;
	}

	ctrl->main_csr_base = res[C50_MAIN_CSR_INDEX].start;
	ctrl->top_csr_base = res[C50_TOP_CSR_INDEX].start;
	ctrl->irq = res[C50_IRQ_INDEX].start;
	ctrl->smmu_base = res[C50_SMMU_INDEX].start;
	ctrl->ops = &gdma_plat_c50_ops;

	cn_dev_gdma_debug(ctrl->gdma_set, "gdma plat c50 ctrl %d init end", dev_num);

	return GDMA_SUCCESS;
}

int cn_gdma_plat_c50_info_probe(void *set)
{
	int ret = 0;
	struct cn_gdma_set *gdma_set = set;
	struct cn_core_set *core = gdma_set->core;
	int i;
	struct cn_board_info *pboardi = &core->board_info;
	u32 gdma_mask = 0;
	u32 gdma_bit = 0;
	int ctrl_num = 0;
	struct cn_gdma_set_info *info;

	switch (core->die_cnt) {
	case 1:
		if (core->device_id == MLUID_590 || core->device_id == MLUID_590V) {
			info = &c50_gdma_single_die_info;
			gdma_mask = pboardi->gdma_mask;
			gdma_mask &= 0x3f;
			if (gdma_mask == 0) {
				ret = -EINVAL;
				cn_dev_gdma_err(gdma_set, "gdma mask error,can not to be 0!");
				goto out;
			}
		} else {
			/*MLU585 & MLU585V*/
			info = &c50s_gdma_single_die_info;
		}
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if (core->device_id == MLUID_590 || core->device_id == MLUID_590V) {
		while (gdma_mask) {
			gdma_bit = __ffs(gdma_mask);
			CLR_BIT(gdma_mask, gdma_bit);
			info->smmu_info[ctrl_num].smmu_index = gdma_bit;
			ctrl_num++;
			info->ctrl_num = ctrl_num;
		}
		gdma_set->hw_gdma_mask = gdma_mask;
	} else {
		for (i = 0; i < info->ctrl_num; i++) {
			info->smmu_info[ctrl_num].smmu_index = i;
			ctrl_num++;
		}
	}
	gdma_set->ctrl_num = ctrl_num;
	gdma_set->info = info;

out:
	return ret;
}
