/************************************************************************
 *
 *  @file cndrv_pci_c50.h
 *
 *  @brief This file is designed to support pcie functions.
 * ######################################################################
 *
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 *
 **************************************************************************/

/*************************************************************************
 * Software License Agreement:
 * -----------------------------------------------------------------------
 * Copyright (C) [2018] by Cambricon, Inc.
 * This code is licensed under MIT license (see below for details)
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *************************************************************************/
/************************************************************************
 *  Include files
 ************************************************************************/

#ifndef __CNDRV_PCI_C50_H
#define __CNDRV_PCI_C50_H

/* sofeware macro */
#define SHARED_DMA_DESC_TOTAL_SIZE      (0x400000)
#define PRIV_DMA_DESC_TOTAL_SIZE        (0x400000)
#define ASYNC_DMA_DESC_TOTAL_SIZE       (0x200000)
#define PER_DESC_MAX_SIZE               (0x1000000)
#define DMA_DESC_PER_SIZE               (32)
#define ASYNC_MAX_DESC_NUM              (256)
#define ASYNC_STATIC_TASK_NUM           (1024)

/* pcie ctrl register */
#define K_GEN_REG                       (0x80)
#define PCIE_DUMMY_WRITE                (0x5510)
/* add pcie pf_info reg */
#define PCIE_INFO_REG_BASE              (0x5100)
#define PCIE_INFO_SHM_BASE              (0x5108)
#define PCIE_INFO_SRAM_BASE             (0x5110)
#define PCIE_INFO_DOB_PAGE_BASE         (0x5118)

/* BAR remap register */
#define BAR_REMAP                       (0x60000)
#define BAR0_MAX_SIZE                   (0x10000000)
#define BAR_BASE_SIZE                   (0x100000UL)
#define AXI_CONFIG_SIZE                 (1024 * 1024 * 1024)
#define BAR0_MASK                       ((AXI_CONFIG_SIZE) - 1)
#define QUADRANT_BASE(i)                (0x80000 + (i) * 0x80)
#define C50_BAR0_LEVEL0_4M              (0x400000UL)
/* bar0 window(0~10) */
#define BAR0_TO_AXI_SRC_WIN(i)          (BAR_REMAP + 0x1020 + (i) * 0xC)
#define BAR0_TO_AXI_MASK_WIN(i)         (BAR_REMAP + 0x1024 + (i) * 0xC)
#define BAR0_TO_AXI_TGT_WIN(i)          (BAR_REMAP + 0x1028 + (i) * 0xC)
/* bar2/bar4 slip window */
#define PF_BAR_ADDR_MASK(index)         (BAR_REMAP + 0x109c + 0x4 * (index))
#define PF_BAR_ADDR_BASE(index)         (BAR_REMAP + 0x10a0 + 0x4 * (index))
/* bar debug register */
#define BAR_REMAP_IRQ_STATUS            (BAR_REMAP + 0x10c0)
#define BAR_REMAP_IRQ_CLEAR             (BAR_REMAP + 0x10c4)
#define BAR_REMAP_ERR_ADDR              (BAR_REMAP + 0x10c8)
#define BAR_REMAP_ERR_STREAM            (BAR_REMAP + 0x10cc)
/* share memory register */
#define PF_SHARE_MEM_MASK               (BAR_REMAP + 0x1100) /* 0xfffff00 128MB */
#define PF_SHARE_MEM_BASE               (BAR_REMAP + 0x1104) /* 0x0080400 512TB+1GB */
/* dbg dma irq flag(0~8) */
#define DBG_DMA_IRQ_FLGA_BUFFER(i)      (BAR_REMAP + 0x1200 + (i) * 0x4)
/* WIN0 bar window reg */
#define ATR_PCIE_WIN0                   (0x600)
#define WIN0_TABLE_BASE                 (0x20)
#define WIN0_SRC_ADDRL(i)               (ATR_PCIE_WIN0 + (i) * WIN0_TABLE_BASE + 0x0)
#define WIN0_SRC_ADDRU(i)               (ATR_PCIE_WIN0 + (i) * WIN0_TABLE_BASE + 0x4)
#define WIN0_TRSL_ADDRL(i)              (ATR_PCIE_WIN0 + (i) * WIN0_TABLE_BASE + 0x8)
#define WIN0_TRSL_ADDRU(i)              (ATR_PCIE_WIN0 + (i) * WIN0_TABLE_BASE + 0xC)
#define WIN0_TRSL_PARAM(i)              (ATR_PCIE_WIN0 + (i) * WIN0_TABLE_BASE + 0x10)
#define WIN0_TRSL_MASKL(i)              (ATR_PCIE_WIN0 + (i) * WIN0_TABLE_BASE + 0x18)
#define WIN0_TRSL_MASKU(i)              (ATR_PCIE_WIN0 + (i) * WIN0_TABLE_BASE + 0x1C)
/* vf bar window reg */
#define VF_BAR0_WIN0_SRC(vf_i)          (BAR_REMAP + 0x20 + (vf_i) * 0x100)
#define VF_BAR0_WIN0_MASK(vf_i)         (BAR_REMAP + 0x24 + (vf_i) * 0x100)
#define VF_BAR0_WIN0_TGT(vf_i)          (BAR_REMAP + 0x28 + (vf_i) * 0x100)
#define VF_BAR0_WIN1_SRC(vf_i)          (BAR_REMAP + 0x2c + (vf_i) * 0x100)
#define VF_BAR0_WIN1_MASK(vf_i)         (BAR_REMAP + 0x30 + (vf_i) * 0x100)
#define VF_BAR0_WIN1_TGT(vf_i)          (BAR_REMAP + 0x34 + (vf_i) * 0x100)
#define	VF_SHARE_MEM_MASK(vf_i)         (BAR_REMAP + 0x80 + (vf_i) * 0x100)
#define	VF_SHARE_MEM_BASE(vf_i)         (BAR_REMAP + 0x84 + (vf_i) * 0x100)

//reset register begin
#define TOP_SOUTH_1_CSR		0x00600000
#define	TOP_SOUTH_1_DATA_MHR_IDLE	(TOP_SOUTH_1_CSR + 0x10)
#define TOP_SOUTH_1_DATA_MHR_REQ	(TOP_SOUTH_1_CSR + 0x18)

#define PCI_CLASS_PROCESSING_ACCEL 0x1200

/*TOP SOUTH0*/
#define MLU580_TOP_SOUTH0_CSR			0x00400000
/*JS*/
/*MHR Register*/
#define MLU580_JS_DATA_MHR_REG         (MLU580_TOP_SOUTH0_CSR + 0x30)
#define MLU580_JS_DATA_MHR_MASK        0x04
#define MLU580_JS_CFG_MHR_REG          (MLU580_TOP_SOUTH0_CSR + 0x34)
#define MLU580_JS_CFG_MHR_MASK         0x10
/*MHR Bus Idle*/
#define MLU580_JS_DATA_IDLE_REG        (MLU580_TOP_SOUTH0_CSR + 0x18)
#define MLU580_JS_DATA_IDLE_MASK       0x10
#define MLU580_JS_CFG_IDLE_REG         (MLU580_TOP_SOUTH0_CSR + 0x1C)
#define MLU580_JS_CFG_IDLE_MASK        0x10
/*Reset Protect*/
#define MLU580_JS_CFG_PRO_REG          (MLU580_TOP_SOUTH0_CSR + 0x14)
#define MLU580_JS_CFG_PRO_MASK         0x100
#define MLU580_JS_DATA_PRO_REG         (MLU580_TOP_SOUTH0_CSR + 0x10)
#define MLU580_JS_DATA_PRO_MASK        0x1110

/*TOP SOUTH1*/
#define MLU590_TOP_SOUTH1_CSR           0x00947000
/*JS*/
/*MHR Register*/
#define MLU590_JS_DATA_MHR_REG         (MLU590_TOP_SOUTH1_CSR + 0x20)
#define MLU590_JS_DATA_MHR_MASK        0x10000
#define MLU590_JS_CFG_MHR_REG          (MLU590_TOP_SOUTH1_CSR + 0x24)
#define MLU590_JS_CFG_MHR_MASK         0x100
/*MHR Bus Idle*/
#define MLU590_JS_DATA_IDLE_REG        (MLU590_TOP_SOUTH1_CSR + 0x18)
#define MLU590_JS_DATA_IDLE_MASK       0x10000
#define MLU590_JS_CFG_IDLE_REG         (MLU590_TOP_SOUTH1_CSR + 0x1C)
#define MLU590_JS_CFG_IDLE_MASK        0x100
/*Reset Protect*/
#define MLU590_JS_CFG_PRO_REG          (MLU590_TOP_SOUTH1_CSR + 0x14)
#define MLU590_JS_CFG_PRO_MASK         0x1000000
#define MLU590_JS_DATA_PRO_REG         (MLU590_TOP_SOUTH1_CSR + 0x10)
#define MLU590_JS_DATA_PRO_MASK        0xE110000

#define TNC_REG_BASE					0x00700000
#define TNC_ROB_PORT_PROT0				(TNC_REG_BASE + 0x30000 + 0x20)
#define TNC_ROB_PORT_PROT1				(TNC_REG_BASE + 0x30000 + 0x24)
#define TNC_REMOTE_XBAR_DYN_RST_REQ		(TNC_REG_BASE + 0x10000 + 0x0)
#define TNC_REMOTE_XBAR_DYN_RST_ACK		(TNC_REG_BASE + 0x10000 + 0x4)

#define TINYCORE_RESET					0x00002a0434

/* interrupt register */
#define GBO                             (0x2000) /*gic base address offset in bar0*/
#define SUB_GBO                         (0x3000) /*gic base address sub offset in bar0*/
#define GIC_CTRL                        (GBO + SUB_GBO + 0x0C0) /*gic interrupt control register*/
#define GIC_MASK                        (GBO + SUB_GBO + 0x000) /*gic mask register(0~15)*/
#define GIC_STATUS                      (GBO + SUB_GBO + 0x040) /*gic status register(0~15)*/
/* gic MSIX clear, first write 1 for clear 1bit then write 1 for begin next time */
#define GIC_MSIX_PEND_CLR               (GBO + SUB_GBO + 0x080) /*msix clear register(0~15)*/
#define GIC_MSIX_VECTOR_COUNT           (GBO + SUB_GBO + 0x0C4) /* msix vector count register*/
/* total INT clear, first write 0x1 for clear interrupt then write 0x0 begin next time */
#define GLOBAL_INTX_CLR                 (GBO + SUB_GBO + 0x0C8) /*gic int clear register*/
#define PF_GIC_INFO_REG_0               (GBO + SUB_GBO + 0x100)
#define PF_GIC_INFO_REG_1               (GBO + SUB_GBO + 0x104)
#define PF_GIC_INFO_REG_4               (GBO + SUB_GBO + 0x110)
/* pcie irq status :open irq->write 1 to PCIE_IRQ_MASK->*/
#define PCIE_IRQ_STATUS(i)              (GBO + 0x2000 + 0x200 + (i) * 4) /* 0~31 32(0~2)*/
#define PCIE_IRQ_MASK(i)                (GBO + 0x2000 + 0x300 + (i) * 4) /* 0~31 32(0~2)*/
/* interrupt group */
#define MSI_COUNT_POWER                 (0)
#define MSI_COUNT                       (1 << MSI_COUNT_POWER)
#define MSIX_COUNT                      (16)
#define INTX_COUNT                      (1)
/* set interrupt mode for GIC_CTRL */
#define GIC_ENABLE_MSI_BIT              (1<<0)
#define GIC_ENABLE_MSIX_BIT             (2)
#define GIC_ENABLE_INTX_BIT             (0<<0)
#define GIC_OPEN_GI_BIT                 (0<<8)
/* interrupt number */
#define GIC_INTERRUPT_NUM               (512)
#define PCIE_IRQ_DMA                    (0)/*(0~7)8DMA end and (8~15)8DMA error*/
#define PCIE_IRQ_DMA_END                (7)


/* DMA register */
#define DBO                             (0x30000) /*DMA BASE OFFSET in bar0*/
/* DMA interrupt regs offset */
#define DI_BASE                         (0x180) /*DMA interrupt regs offset*/

/* DMA control register */
#define DMA_CTRL                        (DBO + 0x9000)

/* DMA engine register */
#define PF_ENG_NUM                      (0)
#define ENGINE(i)                       (DBO + (i) * 0x1000)
#define CMD_BUF_CTRL_ENGINE(i)          (ENGINE(i) + 0x0)
#define CMD_BUF_ABORT_ENGINE(i)         (ENGINE(i) + 0x4)
#define CMD_BUF_STATUS_ENGINE(i)        (ENGINE(i) + 0x8)
#define CMD_STATUS_BUF_STATUS_ENGINE(i) (ENGINE(i) + 0xc)
#define CMD_BUF_OVERFLOW_IRQ_ENGINE(i)  (ENGINE(i) + 0x10)
#define DYNCLK_ENABLE_ENGINE(i)         (ENGINE(i) + 0x14)
#define IRQ_TRANS_END_ENGINE(i)         (ENGINE(i) + 0x18)
#define IDLE_SIGNAL_ENGINE(i)           (ENGINE(i) + 0x1c)

/* DMA engine ctrl register */
#define ENGINE_CTRL(i)                  (DBO + 0xa000 + (i) * 0x100)
#define ENG_CMD_SEL_ENGINE(i)           (ENGINE_CTRL(i) + 0x0)
#define ABORT_CMD_STOP_ENGINE(i)        (ENGINE_CTRL(i) + 0x4)
#define ALIGN_CONFIG_ENGINE(i)          (ENGINE_CTRL(i) + 0x8)
#define DBG_SM_ENGINE(i)                (ENGINE_CTRL(i) + 0xc)
#define DBG_REG0_ENGINE(i)              (ENGINE_CTRL(i) + 0x10)
#define DBG_REG1_ENGINE(i)              (ENGINT_CTRL(i) + 0x14)
#define DBG_REG2_ENGINE(i)              (ENGINT_CTRL(i) + 0x18)
#define DBG_REG3_ENGINE(i)              (ENGINT_CTRL(i) + 0x1c)
#define DBG_REG4_ENGINE(i)              (ENGINT_CTRL(i) + 0x20)
#define DBG_REG5_ENGINE(i)              (ENGINT_CTRL(i) + 0x24)
#define DBG_REG6_ENGINE(i)              (ENGINT_CTRL(i) + 0x28)
#define DBG_REG7_ENGINE(i)              (ENGINT_CTRL(i) + 0x2c)
#define DBG_REG8_ENGINE(i)              (ENGINT_CTRL(i) + 0x30)
#define DBG_REG9_ENGINE(i)              (ENGINT_CTRL(i) + 0x34)
#define DBG_REG10_ENGINE(i)             (ENGINT_CTRL(i) + 0x38)
#define DBG_REG11_ENGINE(i)             (ENGINT_CTRL(i) + 0x3c)
#define DBG_MEMSET_REG0_ENGINE(i)       (ENGINT_CTRL(i) + 0x40)
#define DBG_MEMSET_REG1_ENGINE(i)       (ENGINT_CTRL(i) + 0x44)

/* DMA queue register */
#define QUEUE(i, j)                     (ENGINE(i) + (j + 1) * 0x100)
#define CTRL_LOW_QUEUE(i, j)            (QUEUE(i, j) + 0x0)
#define CTRL_HIGH_QUEUE(i, j)           (QUEUE(i, j) + 0x4)
#define CTRL_DESC_NUM_QUEUE(i, j)       (QUEUE(i, j) + 0x8)
#define CTRL_CMD_CTRL1_QUEUE(i, j)      (QUEUE(i, j) + 0xc)
#define CTRL_CMD_CTRL2_QUEUE(i, j)      (QUEUE(i, j) + 0x20)
#define DMA_STATUS_QUEUE(i, j)          (QUEUE(i, j) + 0x24)
#define DMA_STATUS_UP_QUEUE(i, j)       (QUEUE(i, j) + 0x28)
#define DBG_SEL_QUEUE(i, j)             (QUEUE(i, j) + 0x3c)
#define DBG_DATA0_QUEUE(i, j)           (QUEUE(i, j) + 0x40)
#define DBG_DATA1_QUEUE(i, j)           (QUEUE(i, j) + 0x44)
#define DBG_DATA2_QUEUE(i, j)           (QUEUE(i, j) + 0x48)
#define DBG_DATA3_QUEUE(i, j)           (QUEUE(i, j) + 0x4c)
#define DBG_DATA4_QUEUE(i, j)           (QUEUE(i, j) + 0x50)
#define DMA_QUEUE_ERR_FLAG              ((0x1) << 2)
#define DMA_QUEUE_ERR_CHECK(status)     ((status) & (DMA_QUEUE_ERR_FLAG))
#define DMA_MAX_CMD_BUF_NUM             (0x9)// 9 cmd buf
#define DMA_MAX_QUEUE_NUM               (0x4)// 4 queue
#define DMA_MAX_QUEUE_MASK              ((1 << DMA_MAX_QUEUE_NUM) - 1)
#define HOST_QUEUE_CNT                  (0x2)// host queue count
#define ARM_QUEUE_CNT                   (0x2)// arm queue count
#define DMA_QUEUE_BUFF                  (0x8)// 8 cmd buf
#define DMA_REG_CHANNEL_NUM             (9)
#define DMA_REG_CHANNEL_MASK            ((1 << DMA_REG_CHANNEL_NUM) - 1)

#define VER2_DEV_ENG_START              (0x5)
#define VER2_DEV_ENG_END                (0x9)

/* DMA new register */
#define DMA_OVERIDE_EN_AXFUNX           (DBO + 0xa980)
#define DMA_OVERIDE_VALUE_AXFUNC(i)     (DBO + 0xa984 + (i) * 0x4)

/* atomic register */
#define PCIE_APP_LAYER_SIDEBAND         (0x58000)
#define ATOMIC_PAGE_BASE_ADDR_L         (PCIE_APP_LAYER_SIDEBAND + 0x0)
#define ATOMIC_PAGE_BASE_ADDR_H         (PCIE_APP_LAYER_SIDEBAND + 0x4)
#define ATOMIC_QUEUE_DEPTH_PREG         (PCIE_APP_LAYER_SIDEBAND + 0x8)
#define ATOMIC_AXI_PARAM_PREG           (PCIE_APP_LAYER_SIDEBAND + 0xc)
#define ATOMIC_QUEUE_HEAD_PREG          (PCIE_APP_LAYER_SIDEBAND + 0x10)
#define ATOMIC_QUEUE_TAIL_PREG          (PCIE_APP_LAYER_SIDEBAND + 0x14)
#define ATOMIC_IRQ_CLEAR                (PCIE_APP_LAYER_SIDEBAND + 0x18)
#define ATOMIC_ERR_WB_STATUS            (PCIE_APP_LAYER_SIDEBAND + 0x20)
#define ATOMIC_STATE_DEBUG_PREG         (PCIE_APP_LAYER_SIDEBAND + 0x24)
#define ATOMIC_IRQ_INDEX                (29)
#define ATOMIC_IRQ_ENABLE               (~(1 << ATOMIC_IRQ_INDEX))

/* data outbound register */
#define PCIE_IF_LAYER_SIDEBAND          (0x5C000)
#define SLV_WIN_ATR_PARAM               (PCIE_IF_LAYER_SIDEBAND + 0x60)
#define VF_DOMAIN_ID(vf_i)              (PCIE_IF_LAYER_SIDEBAND + 0x80 + 0x4 * vf_i)
#define DOB_PAGE_BASE                   (0x7803020000ULL)
#define C50_AXI_SHM_DOB_VA_PAGE_BASE    (0x7803020000ULL)
#define DOB_PRE_PAGE_SIZE               (0x10) //16B
#define DOB_PAGE_CNT                    (0x1000) //4K
#define DOB_PAGE_LEVEL1                 (0x1000) //4KB
#define DOB_PAGE_LEVEL2                 (0x100000) //1MB
#define DOB_PAGE_LEVEL2_RESERVE_SIZE    (0x1000000) //16MB
#define DOB_PAGE_LEVEL2_RESERVE_CNT     (DOB_PAGE_LEVEL2_RESERVE_SIZE / DOB_PAGE_LEVEL2)
#define DOB_PAGE_RESERVE_FUNC_CNT       (0x8)
#define DOB_AXI_BASE                    (0xC000000000ULL)
#define SLV_WIN_AR_CNT                  (PCIE_APP_LAYER_SIDEBAND + 0x130)

/* sync write register */
#define PF_SYNC_WRITE_ADDR_L(i)         (PCIE_IF_LAYER_SIDEBAND + 0x100 + (i) * 0x10)
#define PF_SYNC_WRITE_ADDR_H(i)         (PCIE_IF_LAYER_SIDEBAND + 0x104 + (i) * 0x10)
#define PF_FLAG_QUEUE_ADDR_L(i)         (PCIE_IF_LAYER_SIDEBAND + 0x108 + (i) * 0x10)
#define PF_FLAG_QUEUE_ADDR_H(i)         (PCIE_IF_LAYER_SIDEBAND + 0x10C + (i) * 0x10)
#define PF_SYNC_WRITE_MODE              (PCIE_IF_LAYER_SIDEBAND + 0x340)
#define PF_SYNC_WRITE_IRQ_CLEAR         (PCIE_IF_LAYER_SIDEBAND + 0x344)
#define PF_SYNC_WRITE_AXUSER            (PCIE_IF_LAYER_SIDEBAND + 0x348)
#define SYNC_WRITE_MODE                 (1) //4Byte(0)/8Byte(1)
#define SYNC_WRITE_IDLE                 (0)
#define SYNC_WRITE_ASSIGNED             (1)

/* reset register */
/* soft reset*/
#define SOFT_RESET_PREG                 (PCIE_IF_LAYER_SIDEBAND + 0xa8)
#define SOFT_RESET_DEBUG                (PCIE_IF_LAYER_SIDEBAND + 0xac)
/* hot reset/linkdown reset*/
#define PCIE_CTRL_SIDEBAND              (0x51000)
#define HOT_RESET_IGNORE                (PCIE_CTRL_SIDEBAND + 0xd10)
#define HOT_RESET_IRQ_CLEAR             (PCIE_CTRL_SIDEBAND + 0xd14)
/* flr reset*/
#define LOCAL_FLR_ACK_BY_ARM            (PCIE_CTRL_SIDEBADN + 0xd00)
#define LOCAL_FLR_ACK_REG               (PCIE_CTRL_SIDEBAND + 0xd04)
#define LOCAL_FLR_IRQ_CLEAR             (PCIE_CTRL_SIDEBAND + 0xd08)

/* Definition of communication information format between PF and VF */
#define CMD_GET_INBOUND_INFO            (0xabc0)
#define CMD_GET_OUTBOUND_INFO           (0xabc1)
#define CMD_SET_OUTBOUND_INFO           (0xabc2)
#define CMD_GET_DMA_INFO                (0xabc3)
#define CMD_GET_BDF                     (0xabc4)
#define CMD_SRIOV_INIT                  (0xabc5)
#define CMD_SRIOV_EXIT                  (0xabc6)
#define CMD_SRIOV_LATE_INIT             (0xabc7)
#define CMD_SRIOV_PRE_EXIT              (0xabc8)
#define CMD_GET_SRAM_INFO               (0xabc9)
#define CMD_ALLOC_COMMU_CTRLQ           (0xcabc)
#define MAILBOX_INIT_REG                (0x2701)
/* total 32 bits, [0]:end_flag, [31:16]:CMD*/
#define CMD_END_FLAG                    (0)
#define CMD_BIT_STATRT                  (16)

#define MASK_BITS(nEnd, nStart) \
	(((1 << ((nEnd) - (nStart) + 1)) - 1) << (nStart))

#define GET_BITS_VAL(nVal, nEnd, nStart) \
	(((nVal) & MASK_BITS(nEnd, nStart)) >> (nStart))

#define SET_BITS_VAL(nVal, nEnd, nStart, nNum) \
	do {\
		(nVal) &= (~MASK_BITS(nEnd, nStart));\
		(nVal) |= (((nNum) << (nStart)) & MASK_BITS(nEnd, nStart));\
	} while (0)\

/* pll cfg */
#define PLL_CTRL                        (0x8)
#define PLL_INT_EN                      (0x6)
#define PLL_INT_STS                     (0x7)

#define MLU590_CRG_SOUTH_C2C_MAC        (0x00912000)
#define MLU590_CRG_SOUTH_C2C_CORE       (0x00913000)
#define MLU590_CRG_SOUTH_CPU_SYS        (0x00911000)
#define MLU590_CRG_SOUTH_CPU_CORE       (0x00910000)
#define MLU590_CRG_SOUTH_TINY_CORE      (0x00914000)
#define MLU590_CRG_SOUTH_PCIE_2G        (0x0090F000)
#define MLU590_CRG_SOUTH_CACG           (0x0090E000)
#define MLU590_CRG_WEST_C2C_MAC         (0x00903000)
#define MLU590_CRG_WEST_C2C_CORE        (0x00904000)
#define MLU590_CRG_WEST_VPU_SYS         (0x00901000)
#define MLU590_CRG_WEST_VPU_DEC         (0x00902000)
#define MLU590_CRG_WEST_TINY_CORE       (0x00905000)
#define MLU590_CRG_WEST_CACG            (0x00900000)
#define MLU590_CRG_EAST_C2C_MAC         (0x00909000)
#define MLU590_CRG_EAST_C2C_CORE        (0x0090A000)
#define MLU590_CRG_EAST_VPU_SYS         (0x00907000)
#define MLU590_CRG_EAST_VPU_DEC         (0x00908000)
#define MLU590_CRG_EAST_TINY_CORE       (0x0090B000)
#define MLU590_CRG_EAST_CACG            (0x00906000)
#define MLU590_CRG_MIDDLE_SYS0_CACG     (0x0090C000)
#define MLU590_CRG_MIDDLE_LLC_CACG      (0x0090D000)
#define MLU590_CRG_BAR00_CACG           (0x00916000)
#define MLU590_CRG_BAR10_CACG           (0x00919000)
#define MLU590_CRG_BAR21_CACG           (0x0091B000)
#define MLU590_CRG_BAR31_CACG           (0x0091D000)
#define MLU590_CRG_IPU_SYSTEM0          (0x00917000)
#define MLU590_CRG_IPU_SYSTEM1          (0x0091C000)
#define MLU590_CRG_IPU_SYSTEM2          (0x00918000)
#define MLU590_CRG_IPU_SYSTEM3          (0x0091E000)
#define MLU590_CRG_IPU_SYSTEM4          (0x0091A000)
#define MLU590_CRG_IPU_SYSTEM5          (0x0091F000)

#define MLU590E_CRG_SOUTH_C2C_MAC       (0x00912000)
#define MLU590E_CRG_SOUTH_C2C_CORE      (0x00913000)
#define MLU590E_CRG_SOUTH_CPU_SYS       (0x00911000)
#define MLU590E_CRG_SOUTH_CPU_CORE      (0x00910000)
#define MLU590E_CRG_SOUTH_TINY_CORE     (0x00914000)
#define MLU590E_CRG_SOUTH_PCIE_2G       (0x0090F000)
#define MLU590E_CRG_SOUTH_CACG          (0x0090E000)
#define MLU590E_CRG_WEST_C2C_MAC        (0x00903000)
#define MLU590E_CRG_WEST_C2C_CORE       (0x00904000)
#define MLU590E_CRG_WEST_VPU_SYS        (0x00901000)
#define MLU590E_CRG_WEST_VPU_DEC        (0x00902000)
#define MLU590E_CRG_WEST_TINY_CORE      (0x00905000)
#define MLU590E_CRG_WEST_CACG           (0x00900000)
#define MLU590E_CRG_EAST_C2C_MAC        (0x00909000)
#define MLU590E_CRG_EAST_C2C_CORE       (0x0090A000)
#define MLU590E_CRG_EAST_VPU_SYS        (0x00907000)
#define MLU590E_CRG_EAST_VPU_DEC        (0x00908000)
#define MLU590E_CRG_EAST_TINY_CORE      (0x0090B000)
#define MLU590E_CRG_EAST_CACG           (0x00906000)
#define MLU590E_CRG_MIDDLE_SYS0_CACG    (0x0090C000)
#define MLU590E_CRG_MIDDLE_LLC_CACG     (0x0090D000)
#define MLU590E_CRG_IPU_SYSTEM02_2      (0x00916000)
#define MLU590E_CRG_IPU_SYSTEM13_2      (0x0091D000)
#define MLU590E_CRG_IPU_SYSTEM0         (0x00917000)
#define MLU590E_CRG_IPU_SYSTEM1         (0x0091E000)
#define MLU590E_CRG_IPU_SYSTEM2         (0x00918000)
#define MLU590E_CRG_IPU_SYSTEM3         (0x0091F000)

#define MLU580_CRG_SOUTH_CPU_SYS        (0x00420000)
#define MLU580_CRG_SOUTH_CPU_CORE       (0x00410000)
#define MLU580_CRG_SOUTH_SYS0           (0x00440000)
#define MLU580_CRG_SOUTH_PCIE_2G        (0x00430000)
#define MLU580_CRG_WEST_VDEC            (0x03020000)
#define MLU580_CRG_WEST_JPU             (0x03030000)
#define MLU580_CRG_WEST_SYS0            (0x03040000)
#define MLU580_CRG_EAST_VDEC            (0x03820000)
#define MLU580_CRG_EAST_JPU             (0x03830000)
#define MLU580_CRG_EAST_SYS0            (0x03840000)
#define MLU580_CRG_MIDDLE_SYS0_CACG     (0x010A0000)
#define MLU580_CRG_MIDDLE_LLC_CACG      (0x012A0000)
#define MLU580_CRG_BAR00_CACG           (0x002B0000)
#define MLU580_CRG_BAR10_CACG           (0x01C10000)
#define MLU580_CRG_BAR21_CACG           (0x02210000)
#define MLU580_CRG_BAR31_CACG           (0x02610000)
#define MLU580_CRG_IPU_SYSTEM0          (0x01A10000)
#define MLU580_CRG_IPU_SYSTEM1          (0x02010000)
#define MLU580_CRG_IPU_SYSTEM2          (0x01A20000)
#define MLU580_CRG_IPU_SYSTEM3          (0x02410000)
#define MLU580_CRG_IPU_SYSTEM4          (0x01E10000)
#define MLU580_CRG_IPU_SYSTEM5          (0x02420000)

#endif
