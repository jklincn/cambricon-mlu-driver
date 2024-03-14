/************************************************************************
 *
 *  @file cndrv_pci_c20.h
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

#ifndef __CNDRV_PCI_C20_H
#define __CNDRV_PCI_C20_H

#define BAR0_DRR_ADDR			(256 * 1024 * 1024)
#define DMA_REG_CHANNEL_NUM		(8)
#define DMA_REG_CHANNEL_MASK		((1 << DMA_REG_CHANNEL_NUM) - 1)
/* arm trigger */
#define HOST_PHY_CHANNEL_NUM		(4)
#define ARM_PHY_CHANNEL_NUM		(4)
#define HOST_PHY_CHANNEL_MASK		((1 << HOST_PHY_CHANNEL_NUM) - 1)
/* TODO split data when size is greater than 16MB */
#define ARM_TRIGGER_MAX_SIZE		(0x1000000)

#define SHARED_DMA_DESC_TOTAL_SIZE	(0x100000)
#define ASYNC_STATIC_DESC_SIZE		(0x200000)
#define ASYNC_DYNAMIC_DESC_SIZE		(0x200000)
#define PRIV_DMA_DESC_TOTAL_SIZE	(0x100000)
#define DMA_DESC_PER_SIZE		(32)

#define MSI_COUNT_POWER			(0)
#define MSI_COUNT			(1 << MSI_COUNT_POWER)
#define MSIX_COUNT			(16)
#define INTX_COUNT			(1)

	/*DMA control regs offset*/
#define DBO			(0x100400) /*DMA BASE OFFSET in bar0*/
#define DI_BASE			(0x100180) /*DMA interrupt regs offset*/

	/*GIC register */
#define GBO			(0x140000) /*gic base address offset in bar0*/
#define SUB_GBO			(0x4000) /*gic base address sub offset in bar0*/

#define GIC_CTRL		(GBO + SUB_GBO + 0x078) /*gic interrupt control register*/
#define GIC_MASK		(GBO + SUB_GBO + 0x000) /*gic mask register(0~7)*/
#define GIC_STATUS		(GBO + SUB_GBO + 0x020) /*gic status register(0~7)*/

	/* gic MSIX clear, first write 1 for clear 1bit then write 1 for begin next time */
#define GIC_MSIX_PEND_CLR	(GBO + SUB_GBO + 0x044) /*msix clear register(0~7)*/
#define GIC_MSIX_VECTOR_COUNT	(GBO + SUB_GBO + 0x084)	/* msix vector count register*/
	/* total INT clear, first write 0x1 for clear interrupt then write 0x0 begin next time */
#define GLOBAL_INTX_CLR 	(GBO + SUB_GBO + 0x08C)    /*gic int clear register*/
#define PCI_CONFIG_MSI_MASK	(0x1010f0)

	/* msix addr outbound window reg */
#define ATR_AXI4_SLV0		(0x100800)
#define SLV0_TABLE_BASE		(0x20)
#define SLV0_SRC_ADDRL(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x0)
#define SLV0_SRC_ADDRU(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x4)
#define SLV0_TRSL_ADDRL(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x8)
#define SLV0_TRSL_ADDRU(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0xC)
#define SLV0_TRSL_PARAM(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x10)
#define SLV0_TRSL_MASKL(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x18)
#define SLV0_TRSL_MASKU(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x1C)

	/*local management register*/
#define BAR2_TO_AXI_ADDR_REG_L         (0x100648)
#define BAR2_TO_AXI_ADDR_REG_U         (0x10064C)

#define BAR4_TO_AXI_ADDR_REG_L         (0x100688)
#define BAR4_TO_AXI_ADDR_REG_U         (0x10068C)

#define LOCAL_MANAGEMENT_REGISTER      (0x169000)
	/*debug mux control register 2*/
#define DMCR                           (LOCAL_MANAGEMENT_REGISTER+0x234)
#define MSI_PENDING_STATUS_SHIFT       (9)
#define UPDATE_MSI_PENDING_BIT         (1 << 9)
	/*local error and status register*/
#define LOCAL_ERROR_STATUS_REG         (LOCAL_MANAGEMENT_REGISTER+0x20c)
	/* Completion timeout limit reg0 */
#define LOCAL_COMPLETION_TIMEOUT_0     (LOCAL_MANAGEMENT_REGISTER + 0x38)
	/* Completion timeout limit reg1 */
#define LOCAL_COMPLETION_TIMEOUT_1     (LOCAL_MANAGEMENT_REGISTER + 0x3c)
	/* LCRC count error register */
#define LOCAL_ERROR_COUNT              (LOCAL_MANAGEMENT_REGISTER + 0x214)
	/* debug mux control 2 */
#define LOCAL_DEBUG_MUX_CTRL2          (LOCAL_MANAGEMENT_REGISTER + 0x234)
	/* Phy status */
#define LOCAL_PHY_STATUS               (LOCAL_MANAGEMENT_REGISTER + 0x238)

#define GIC_ENABLE_MSI_BIT		(1<<0)
#define GIC_ENABLE_MSIX_BIT		(2)
#define GIC_ENABLE_INTX_BIT		(0<<0)
	/*open global interrupt.*/
#define GIC_OPEN_GI_BIT			(0<<8)
	/*msi shift*/
#define MSI_ADDR_64_SHIFT		(23)
#define MSI_ADDR_IS_64			(1<<MSI_ADDR_64_SHIFT)

#define GIC_INTERRUPT_NUM		(256)
#define PCIE_IRQ_DMA			(0)/*(0~7)8DMA end and (8~15)8DMA error*/
#define PCIE_IRQ_DMA_END		(16)

	/*sideband register*/
#define SIDEBAND_BASE_ADDR		(0x120000)

#define SIDEBAND(n)			(SIDEBAND_BASE_ADDR + 0x4 * (n))
#define V2PDMA_CTRL(ch_i)		(SIDEBAND(ch_i) + 0x10100)

	/* arm trigger dma register */
#define ARM_TRIGGER_HOST_PHY_CHANNEL	(SIDEBAND_BASE_ADDR + 0x2e0) //vf8_bar0_addr_mask_l
#define ARM_TRIGGER_ARM_PHY_CHANNEL	(SIDEBAND_BASE_ADDR + 0x2e4) //vf8_bar0_base_addr_l
#define ARM_TRIGGER_REG			(SIDEBAND_BASE_ADDR + 0x2e8) //vf8_bar0_addr_mask_h

#define AER_BASE_ADDR			(0x101200)
#define AER_STATUS(n)			(AER_BASE_ADDR + 0x4 * (n))

#define CMD_GET_INBOUND_INFO            (0xabc0)
#define CMD_GET_OUTBOUND_INFO           (0xabc1)
#define CMD_SET_OUTBOUND_INFO           (0xabc2)
#define CMD_GET_DMA_INFO                (0xabc3)
#define CMD_GET_BDF                     (0xabc4)
#define CMD_SRIOV_INIT                  (0xabc5)
#define CMD_SRIOV_EXIT                  (0xabc6)
#define CMD_ALLOC_COMMU_CTRLQ           (0xcabc)

#define PCIE_IRQ_VF_2_PF        (37)
#define MAILBOX_INIT_REG        (0x2701)

#define OUTBOUND_FIRST         (1)
#define PF_OUTBOUND_CNT        (7)
#define OUTBOUND_CNT           (15)
#define OUTBOUND_POWER         (21UL)
#define OUTBOUND_SIZE          (1ULL<<OUTBOUND_POWER)
#define OUTBOUND_SIZE_TOTAL    (OUTBOUND_SIZE*OUTBOUND_CNT)
#define OUTBOUND_AXI_BASE      (0x8006200000)

/* fixed : dummy reg */
#define PCIE_DUMMY_WRITE       (0x101000)

/* pcie firmware version reg*/
#define PCIE_FW_ADDR_L		(0x100330)
#define PCIE_FW_ADDR_H		(0x100334)

/* BA SN */
#define IPC4			(0x14)
#define K_GEN_REG		(0x100080)

#endif
