/************************************************************************
 *
 *  @file cndrv_pci_pigeon.h
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

#ifndef __CNDRV_PCI_PIGEON_H
#define __CNDRV_PCI_PIGEON_H

#include <linux/semaphore.h>

/* Set About : asic or fpga plat */
#define PLAT_ASIC_PIGEON

#ifdef PLAT_ASIC_PIGEON
	#undef FPGA
#else
	#define FPGA
#endif

/* DMA IP Controller Register and capability setting */
#define DMA_REG_CHANNEL_NUM             (8) /*The PLDA IP Real capability*/
#define ARM_PHY_CHANNEL_NUM             (0)
#define HOST_PHY_CHANNEL_NUM            (2) /*How many the PIGEON uses - ONLY HOST USE*/
#define HOST_PHY_CHANNEL_MASK           ((1 << HOST_PHY_CHANNEL_NUM) - 1) /*Default Setting DMA0-1*/
#define DMA_REG_CHANNEL_MASK		(HOST_PHY_CHANNEL_MASK)
#define INTR_DMA_CHANNEL_NUM		(HOST_PHY_CHANNEL_NUM + ARM_PHY_CHANNEL_NUM)
#define INTR_DMA_CHANNEL_MASK		((1 << INTR_DMA_CHANNEL_NUM) - 1)

#define SHARED_DMA_DESC_TOTAL_SIZE      (0x100000)
#define PRIV_DMA_DESC_TOTAL_SIZE        (0x100000)
#define DMA_DESC_PER_SIZE               (32) /*PLDA IP each one Description*/

#define MSI_COUNT_POWER                 0
#define MSI_COUNT                       (1 << MSI_COUNT_POWER) /*1 2 4 8 16 32*/
#define MSIX_COUNT                      (16)
#define INTX_COUNT                      (1)

#define RETRANSFER_COUNT         1 /*DMA retransfer count when dma transfer failed.*/
#define NEED_SUB_IRQ_MASK
/*
 ***************************************************************
 *DMA control regs offset in BAR0 default map zone PLDA IP
 ***************************************************************
 */
#define PCIE_REG_BASE   (0x180000) /*Attention: The PCIe System Register Base Address*/

#define CTL_BASE        (PCIE_REG_BASE)     /*PCIE CONTROLLER BASE OFFSET in bar0*/

/*DMA register*/
#define DBO             (PCIE_REG_BASE + 0x000400)     /*DMA BASE OFFSET in bar0 - access PLDA DMA channel register*/
#define DI_BASE		(PCIE_REG_BASE + 0x000180)     /*DMA interrupt regs offset -  access PLDA Interrupt register*/

/*GIC register
	0x0000~0x1FFF msix_entry 0~511  <Mask - Data - AddrHigh - AddrLow>
	0x2000~0x203F pending Bit  1 means pending JUST arrive-flag - RO as EP

	0x3000~0x303F mask Bit     1 means Not enable this one
	0x3040~0x307F status Bit   1 means Not enable this one

	0x3080~0x30BF MSIX Clear     1 means Not enable this one

	0x30C0	      GIC control
	0x30C4	      MSIX Vector Number Default is 16.
	0x30C8	      INTx Clear

 */
#define GBO             (PCIE_REG_BASE + 0x010000)  /*gic base address offset in bar0*/
#define SUB_GBO         (0x2000)	    /*gic base address sub offset in bar0*/
#define SUB_GBO_ASSIST  (0x01C000)          /*Design located at GIC of RC*/

#define GIC_CTRL        (GBO + SUB_GBO + 0x10C0)    /*gic interrupt control register - Mode and TopMask*/
#define GIC_MASK        (GBO + SUB_GBO + 0x1000)    /*gic mask register 512 Bit Mask*/
#define GIC_STATUS      (GBO + SUB_GBO + 0x1040)    /*gic status register 512 Bit Status*/

#define GLOBAL_INTX_CLR       (GBO + SUB_GBO + 0x10C8)    /*gic int clear register*/
#define PCI_CONFIG_MSI_MASK   (PCIE_REG_BASE + 0x001000 + 0xF0) /*Recording which PLDA MSI Interrupt arrived 32 Bit Mask 1-enable*/
#define GIC_MSIX_PEND_CLR     (GBO + SUB_GBO + 0x1080)    /*msix clear register 512 Bit Clear*/
#define GIC_MSIX_VECTOR_COUNT (GBO + SUB_GBO + 0x10C4)    /*msi group count (0:16 group) (1:32 group)*/
#define GIC_STATUS_CLR        (GBO + SUB_GBO + 0x1040)    /*status clear register 512 Bit Clear*/

/* BAR2/4 target regioster */
#define BAR2_TO_AXI_ADDR_REG_L         (CTL_BASE + 0x648)
#define BAR2_TO_AXI_ADDR_REG_U         (CTL_BASE + 0x64C)

#define BAR4_TO_AXI_ADDR_REG_L         (CTL_BASE + 0x688)
#define BAR4_TO_AXI_ADDR_REG_U         (CTL_BASE + 0x68C)

/* Local management register */
#define LOCAL_MANAGEMENT_REGISTER      (PCIE_REG_BASE + 0x005000)
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

#define LOCAL_ASPM_L1_ENTRY_TIMEOUT    (LOCAL_MANAGEMENT_REGISTER + 0x48)
	/* LCRC count error register */
#define LOCAL_ERROR_COUNT              (LOCAL_MANAGEMENT_REGISTER + 0x214)
	/* debug mux control 2 */
#define LOCAL_DEBUG_MUX_CTRL2          (LOCAL_MANAGEMENT_REGISTER + 0x234)
	/* Phy status */
#define LOCAL_PHY_STATUS               (LOCAL_MANAGEMENT_REGISTER + 0x238)

#define LINK_WIDTH_CTL                 (LOCAL_MANAGEMENT_REGISTER + 0x50)
	/*number bit axi address to pci address .
	 *
	 *note that valied number is this value +1 .
	 */
#define NUMBER_BIT_AXI_TO_PCI_ADDR  (7)

#define GIC_ENABLE_MSI_BIT          (1<<0)
#define GIC_ENABLE_MSIX_BIT         (2)
#define GIC_ENABLE_INTX_BIT         (0<<0)
	/*open global interrupt.*/
#define GIC_OPEN_GI_BIT             (0<<8)
	/*msi shift*/
#define MSI_ADDR_64_SHIFT           (23)
#define MSI_ADDR_IS_64              (1<<MSI_ADDR_64_SHIFT)

#define GIC_INTERRUPT_NUM           (512)
#define PCIE_IRQ_DMA                (324)  /*324/325 - DMA engine0/1*/

	/*sideband register*/
#define SIDEBAND_BASE_ADDR          (PCIE_REG_BASE + 0x002000)

#define SIDEBAND(n)                 (SIDEBAND_BASE_ADDR + 0x4 * (n))

	/* SLV0 outbound window reg */
#define ATR_AXI4_SLV0		(PCIE_REG_BASE + 0x800)
#define SLV0_TABLE_BASE		(0x20)
#define SLV0_SRC_ADDRL(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x0)
#define SLV0_SRC_ADDRU(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x4)
#define SLV0_TRSL_ADDRL(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x8)
#define SLV0_TRSL_ADDRU(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0xC)
#define SLV0_TRSL_PARAM(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x10)
#define SLV0_TRSL_MASKL(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x18)
#define SLV0_TRSL_MASKU(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x1C)

/* Function setting mask and its value */
#define OUTBOUND_FIRST         (0)
#define OUTBOUND_CNT           (8)
#define OUTBOUND_POWER         (21UL) /*2M per window*/
#define OUTBOUND_SIZE          (1ULL<<OUTBOUND_POWER)
#define OUTBOUND_SIZE_TOTAL    (OUTBOUND_SIZE*OUTBOUND_CNT)
#define OUTBOUND_AXI_BASE      (0x4200000000)
#define PF_OUTBOUND_CNT        OUTBOUND_CNT
#define INIT_WITH_OB_AXI_BASE

#define PMU_SYS_RST_CTRL	   (0x7428)
#define MCU_BASIC_INFO		   (0x7490)
#define MCU_DDRTRAINED_FLAG_SHIFT	30
#define MCU_DDRTRAINED_FLAG_MASK	0x01

#define BAR0_MAX_SIZE			(0x1000000) /*16M*/
#define BAR0_MAX_SIZE_MASK              (BAR0_MAX_SIZE - 1)
#define BAR0_FIXED_TOP_SIZE		(0x800000)  /*8M*/
#define BAR0_FIXED_TOP_SIZE_MASK        (BAR0_FIXED_TOP_SIZE - 1)
#define BAR0_WIN0_SIZE                  (0x800000) /*8M*/
#define BAR0_WIN0_SIZE_MASK             (BAR0_WIN0_SIZE - 1) /*8M*/
#define BAR0_TO_AXI_SRC_WIN(i)		(SIDEBAND_BASE_ADDR + 0x900 + (i) * 0xC)
#define BAR0_TO_AXI_MASK_WIN(i)		(SIDEBAND_BASE_ADDR + 0x904 + (i) * 0xC)
#define BAR0_TO_AXI_TGT_WIN(i)		(SIDEBAND_BASE_ADDR + 0x908 + (i) * 0xC)
#define RESERVED_REG                    (SIDEBAND_BASE_ADDR + 0x098)

/* fixed : dummy reg */
#define PCIE_DUMMY_WRITE       (0x158000)

/*Only record Win0*/
struct pigeon_bar0_set {
	struct semaphore		   bar0_window_sem;
	u8				   bar0_window_flag;
	unsigned long			   bar0_window_base;
};

struct pigeon_priv_set {
	struct pigeon_bar0_set bar0_set;
};

void pigeon_memory_and_d2d_init(void *pcie);
#endif
