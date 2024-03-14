/*
 * gdma/plat/mlu370/gdma_reg.h
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

#ifndef __CNDRV_GDMA_REG_H__
#define __CNDRV_GDMA_REG_H__

#define TOP_CSR_GDMA_RSTN_SW_REG (0x08)
#define TOP_CSR_GDMA_RSTN_MASK (0x03)
#define TOP_CSR_GDMA_RSTN_DONE (0x03)

#define TOP_CSR_GDMA_DET_REG (0x48)
#define TOP_CSR_GDMA_DET_VALUE (0x30)

#define TOP_CSR_COMMN_INTR_REG (0x70)
#define GDMA_MHR_BUS_TT_INTR_MASK (0x1f << 6)

//GDMA CSR MAIN Registers
#define GDMA_ID_REG (0x00)
#define GDMA_TEST_REG (0x04)
#define GDMA_SECU_CTRL (0x08)
#define GDMA_CLK_CTRL (0x10)
#define GDMA_CLK_STATUS (0x14)
#define GDMA_RST_CTRL (0x18)
#define GDMA_DMA_INTSTAT (0x1c)
#define GDMA_CHNL_STATUS (0x20)
#define GDMA_CHNL_NS (0x24)
#define GDMA_CHNL_PRIORITY (0x28)
#define GDMA_CHNL_AXI0_CFG (0x30)
#define GDMA_CHNL_AXI1_CFG (0x34)
#define GDMA_SMMU_AUTO_INV_EN (0x40)
#define GDMA_DMA_LP_DELAY_CNT (0x50)

#define GDMA_MAIN_CTRL_RAW_INT (0x60)
#define GDMA_MAIN_CTRL_INT_MASK (0x64)
#define GDMA_MAIN_CTRL_INT_CLR (0x68)
#define GDMA_MAIN_CTRL_INT_OUT (0x6c)

//Tirgger has
#define GDMA_XMIF0_GMW_DEBUG (0x70)
#define GDMA_XMIF0_GMR_DEBUG (0x74)
#define GDMA_XMIF1_GMW_DEBUG (0x78)
#define GDMA_XMIF1_GMR_DEBUG (0x7c)
#define GDMA_MODULE_ID_INFO (0x1ff0)
#define GDMA_DATE_INTO (0x1ff4)
#define GDMA_RESERVED1 (0x1ff8)
#define GDMA_RESERVED2 (0x1ffc)

#define GDMA_CHNL_CTRL (0x00)
#define GDMA_CHNL_CFG (0x04)
#define GDMA_CHNL_DSCRPT_CTRL (0x08)
#define GDMA_CHNL_DSCRPT_ADDR_LO (0x0c)
#define GDMA_CHNL_DSCRPT_ADDR_HI (0x10)
#define GDMA_CHNL_DSCRPT_BUF_HEAD_PTR_LO (0x14)
#define GDMA_CHNL_DSCRPT_BUF_HEAD_PTR_HI (0x18)
#define GDMA_CHNL_DSCRPT_BUF_TAIL_PTR_LO (0x1c)
#define GDMA_CHNL_DSCRPT_BUF_TAIL_PTR_HI (0x20)
#define GDMA_CHNL_DSCRPT_AXI_ATTR (0x24)
#define GDMA_CHNL_DSCRPT_USER_ATTR (0x28)
#define GDMA_CHNL_REGMODE_CTRL (0x2c)
#define GDMA_CHNL_RGM_SRCADDR_LO (0x30)
#define GDMA_CHNL_RGM_SRCADDR_HI (0x34)
#define GDMA_CHNL_RGM_DSTADDR_LO (0x38)
#define GDMA_CHNL_RGM_DSTADDR_HI (0X3c)
#define GDMA_CHNL_RGM_DATA_LEN (0x40)
#define GDMA_CHNL_RGM_AXI_WATTR (0x44)
#define GDMA_CHNL_RGM_AXI_RATTR (0x48)
#define GDMA_CHNL_RGM_USER_ATTR (0x4c)
#define GDMA_CHNL_SRCSTAT_ADDR_LO (0x50)
#define GDMA_CHNL_SRCSTAT_ADDR_HI (0x54)
#define GDMA_CHNL_DSTSTAT_ADDR_LO (0x58)
#define GDMA_CHNL_DSTSTAT_ADDR_HI (0x5c)
#define GDMA_CHNL_MD_CTRL (0x64)
#define GDMA_CHNL_MD_SRC_CFG0 (0x68) //src dim1 len
#define GDMA_CHNL_MD_SRC_CFG1 (0x6c) //src dim2 len
#define GDMA_CHNL_MD_SRC_CFG2 (0x70) //src dim2 stride
#define GDMA_CHNL_MD_SRC_CFG3 (0x74) //src dim3 stride lo
#define GDMA_CHNL_MD_SRC_CFG4 (0x78) //src dim3 stride hi
#define GDMA_CHNL_MD_DST_CFG0 (0x7c) //dst dim1 len
#define GDMA_CHNL_MD_DST_CFG1 (0x80) //dst dim2 len
#define GDMA_CHNL_MD_DST_CFG2 (0x84) //dst dim2 stride
#define GDMA_CHNL_MD_DST_CFG3 (0x88) //dst dim3 stride lo
#define GDMA_CHNL_MD_DST_CFG4 (0x90) //dst dims stride hi
#define GDMA_CHNL_LP_DELAY_CNT (0X94)
#define GDMA_CHNL_RAW_INT (0x98)
#define GDMA_CHNL_INT_MASK (0x9c)
#define GDMA_CHNL_INT_CLR (0x100)
#define GDMA_CHNL_INT_OUT (0x104)
#define GDMA_CHNL_INT_CNT (0x108)
#define GDMA_ECC_ERR_INJECT (0x10c)
#define GDMA_CHNL_DBG_CFG0 (0x180)
#define GDMA_CHNL_DBG_CFG1 (0x184)
#define GDMA_CHNL_DBG_DSCRPT0 (0x188)
#define GDMA_CHNL_DBG_DSCRPT1 (0x18c)
#define GDMA_CHNL_DBG_DSCRPT2 (0x190)
#define GDMA_CHNL_DBG_DSCRPT3 (0x194)
#define GDMA_CHNL_DBG_DSCRPT4 (0x198)
#define GDMA_CHNL_DBG_DSCRPT5 (0x19c)
#define GDMA_CHNL_DBG_DSCRPT0_INFO (0x1a0)
#define GDMA_CHNL_DBG_DSCRPT1_INFO (0x1a4)
#define GDMA_CHNL_DBG_DSCRPT_FSM (0x1a8)
#define GDMA_CHNL_DBG_TX0 (0x1ac)
#define GDMA_CHNL_DBG_TX1 (0x1b0)
#define GDMA_CHNL_DBG_TX2 (0x1b4)
#define GDMA_CHNL_DBG_RX0 (0x1b8)
#define GDMA_CHNL_DBG_RX1 (0x1bc)
#define GDMA_CHNL_DBG_RX2 (0x1c0)
#define GDMA_CHNL_DBG_SF0 (0x1c4)
#define GDMA_CHNL_DBG_SF1 (0x1c8)
#define GDMA_CHNL_DBG_SF2 (0x1cc)
#define GDMA_CHNL_DBG_SF3 (0x1d0)
#define GDMA_CHNL_DBG_SF_FSM (0x1d4)
#define GDMA_CHNL_DBG_MEM0 (0x1d8)
#define GDMA_CHNL_DBG_FSM0 (0x1dc)
#define GDMA_CHNL_DBG_FSM1 (0x1e0)

//GDMA Channel ctrl register bits
#define CHNL_CTRL_START (0x01)
#define CHNL_CTRL_SUSPEND (0x02)
#define CHNL_CTRL_HALT (0x04)
#define CHNL_CTRL_RESUME (0x08)
#define CHNL_CTRL_ABORT (0x10)
#define CHNL_CTRL_DESC_REFRESH (0x20)

//GDMA Channel status register bits
#define CHNL_STATUS_IDLE (0x01)
#define CHNL_STATUS_RUNNING (0x02)
#define CHNL_STATUS_SUSPEND (0x04)
#define CHNL_STATUS_ERROR (0x08)
#define CHNL_STATUS_MASK (0x0f)
#define CHNL_STATUS_SHIFT(X) ((X * 4))

//GDMA Channel reset register bits
#define CHNL_RST_CTRL_MASK (0x01)

//GDMA Channel Clk CTRL bits
#define CLK_CTRL_EANBLE (0x101)

//GDMA Channel CLK Status bits
#define CHNL_CLK_STATUS_MASK (0x01)

/* GDMA_CHNL_CFG Bits */
#define CHNL_CFG_MODE_MASK (0x03)
#define CHNL_CFG_TRANS_TYPE_MASK (0x03)
#define CHNL_CFG_TRANS_TYPE_SHIFT (2)
#define CHNL_CFG_PERI_MODE_MASK (0x01)
#define CHNL_CFG_PRRI_MODE_SHIFT (4)
#define CHNL_CFG_FLOW_CTRL_MASK (0x01)
#define CHNL_CFG_FLOW_CTRL_SHIFT (6)
#define CHNL_CFG_PACKSIZE_MASK (0x07)
#define CHNL_CFG_PACKSIZE_SHIFT (7)
#define CHNL_CFG_UNPACKSIZE_MASK (0x07)
#define CHNL_CFG_UNPACKSIZE_SHIFT (10)
#define CHNL_CFG_READ_OSTD_MASK (0x1f)
#define CHNL_CFG_READ_OSTD_SHIFT (13)
#define CHNL_CFG_WRITE_OSTD_MASK (0x1f)
#define CHNL_CFG_WRITE_OSTD_SHIFT (18)
#define CHNL_CFG_INT_ENABLE_MASK (0x01)
#define CHNL_CFG_INT_ENABLE_SHIFT (23)
#define CHNL_CFG_GM_ALIGNED_ENABLE_MASK (0x01)
#define CHNL_CFG_GM_ALIGNED_ENABLE_SHIFT (24)

#define CHNL_MODE_REGISTER (0x00)
#define CHNL_MODE_DESCRIPTION (0x01)
#define CHNL_TRANS_TYPE_M2M (0x00)
#define CHNL_TRANS_TYPE_M2P (0x01)
#define CHNL_TRANS_TYPE_P2M (0x02)
#define CHNL_PERI_MODE_EANBLE (0x01)
#define CHNL_FLOW_CTRL_DMA (0x00)
#define CHNL_FLOW_CTRL_PERI (0x01)

/*GDMA DESCRPC CTRL*/

#define CHNL_DSCRPT_STORE_TYPE_MASK (0x01)
#define CHNL_DSCRPT_STORE_TYPE_SHIFT (1)
#define CHNL_DSCRPT_OSF_MODE_MASK (0x01)
#define CHNL_DSCRPT_OSF_MODE_SHIFT (2)
#define CHNL_DSCRPT_BLOCK_SIZE_MASK (0x07)
#define CHNL_DSCRPT_BLOCK_SIZE_SHIFT (3)
#define CHNL_DSCRPT_PREFETCH_NUM_MASK (0x03)
#define CHNL_DSCRPT_PREFETCH_NUM_SHIFT (6)
#define CHNL_DSCRPT_PREFETCH_THRESD_MASK (0x03)
#define CHNL_DSCRPT_PREFETCH_THRESD_SHIFT (9)
#define CHNL_DSCRPT_WB_THRESD_MASK (0x03)
#define CHNL_DSCRPT_WB_THRESD_SHIFT (12)

#define CHNL_INT_CLR_VALUE (0x3ffff)
#define MAIN_CTRL_INT_CLR_VALUE (0x01)

/*GDMA PRIORITY Register*/
#define CHNL_PRIORITY_MASK (0x07)
#define CHNL_PRIRIOTY_SHIFT(X) (X * 4)

#define CHANNEL_BASE_OFFSET (0x400)
#define CHANNEL_WINDOWS_SIZE (0x200)
#define CHANNEL_BASE(base, chnnl) \
((base) + CHANNEL_BASE_OFFSET + (chnnl) * CHANNEL_WINDOWS_SIZE)

//GDMA IP ID value
#define GDMA_ID (0x09)

#endif
