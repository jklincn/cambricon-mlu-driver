/************************************************************************
 *
 *  @file cndrv_pci_c20l.h
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

#ifndef __CNDRV_PCI_C20L_H
#define __CNDRV_PCI_C20L_H

//#define C20L_FPGA
#define PCIE_SMMU_ENABLE  1

#define GIC_MASK_BIT_0		(0x0)
#define GIC_MASK_BIT_1		((0x1 << 25) | (0x1 << 26) | (0x1 << 27))

/*dma buffer offset in bar4*/
#define DMA_BUFFER_OFFSET 0

#define DEV_CONTROL_STATUS_REG		(0xC8)
#define VF_NUM_REG                      (0x20C)
#define COMMAND_STATUS_REG		(0x4)

#define BAR0_DRR_ADDR                   (128*1024*1024)

#define DESC_BASE_ADDR			(0UL)

#define DMA_REG_CHANNEL_NUM             (8)
#ifdef FPGA
#define DMA_MAX_CHANNEL                 (2)
#define DMA_MAX_PHY_CHANNEL             (1)
#else
#define DMA_MAX_CHANNEL                 (16)
#define DMA_MAX_PHY_CHANNEL             (4)
#endif
#define MAX_PHY_CHANNEL_MASK            ((1 << DMA_MAX_PHY_CHANNEL) - 1)

#define DMA_DESC_TOTAL_SIZE             (0x100000)

#define MSI_COUNT_POWER     0
#define MSI_COUNT           (1 << MSI_COUNT_POWER)

#define MSIX_COUNT           (16)

#define INTX_COUNT             1

	/*DMA retransfer count when dma transfer failed.*/
#define RETRANSFER_COUNT         1

	/*DMA control regs offset*/
#define DBO              (0x10B000)     /*DMA BASE OFFSET in bar0*/

	/*GIC register */
#define GBO             (0x140000)	    /*gic base address offset in bar0*/
#define GIC_CTRL        (GBO + 0x120dc)    /*gic interrupt control register*/
#define GIC_MASK        (GBO + 0x12000)    /*gic mask register*/
#define GIC_STATUS      (GBO + 0x12020)    /*gic status register*/
#define GIC_AXI_PARA    (GBO + 0x12040)    /*gic axi bus param register*/
#define GIC_MSI_CLR     (GBO + 0x120a0)    /*msi clear register*/
#define GIC_MSI_ADDR_L  (GBO + 0x12044)    /*msi address low*/
#define GIC_MSI_ADDR_U  (GBO + 0x12048)    /*msi address upper*/
#define GIC_MSI_DATA    (GBO + 0x1204c)    /*mis data*/

#define GIC_INT_CLR      (GBO + 0x12050)    /*gic int clear register*/
#define GIC_MSIX_CLR     (GBO + 0x12070)    /*msix clear register*/
#define GIC_MSIX_ADDR_U  (GBO + 0x120b0)    /*msix address upper*/

#ifdef C20L_FPGA
#define GIC_MSI_GROUP_MASK        (GBO + 0x12138)    /*mask msi group*/
#define GIC_MSI_ENABLE            (GBO + 0x1213c)    /*enable*/
#else
#define GIC_MSIX_AXI_ADDR_SIZE    (GBO + 0x12138)    /*mask msi group*/
#endif
	/*msi group count (0:1 group) (1:2 group) (2:4 group) (3:8 group) 3 bit valid*/
#define GIC_MSI_VECTOR_COUNT      (GBO + 0x12140)

#define GIC_MSIX_GROUP_MASK       (GBO + 0x12144)    /*mask msi group*/
#define GIC_MSIX_ENABLE           (GBO + 0x12148)    /*enable*/
	/*msi group count (0:16 group) (1:32 group)*/
#define GIC_MSIX_VECTOR_COUNT     (GBO + 0x12134)


	/*AXI config register*/
#define AXI_CONFIG_REGISTER_BASE    (0x10a000)
#define REGION_REGISTER_SIZE        (0x20)
#define A2P_ADDR_REG_0(i)           (AXI_CONFIG_REGISTER_BASE + \
											(i) * REGION_REGISTER_SIZE + 0x0)
#define A2P_ADDR_REG_1(i)           (AXI_CONFIG_REGISTER_BASE + \
											(i) * REGION_REGISTER_SIZE + 0x4)
#define OB_PCIE_DESC_REG_1(i)       (AXI_CONFIG_REGISTER_BASE +\
											(i) * REGION_REGISTER_SIZE + 0x8)
#define OB_PCIE_DESC_REG_2(i)       (AXI_CONFIG_REGISTER_BASE + \
											(i) * REGION_REGISTER_SIZE + 0xC)
#define OB_PCIE_DESC_REG_3(i)       (AXI_CONFIG_REGISTER_BASE + \
											(i) * REGION_REGISTER_SIZE + 0x10)
#define AXI_REGION_BASE_REG_0(i)    (AXI_CONFIG_REGISTER_BASE + \
											(i) * REGION_REGISTER_SIZE + 0x18)
#define AXI_REGION_BASE_REG_1(i)    (AXI_CONFIG_REGISTER_BASE + \
											(i) * REGION_REGISTER_SIZE + 0x1C)

	/*local management register*/
#define BAR2_TO_AXI_ADDR_REG_LINK_DOWN (AXI_CONFIG_REGISTER_BASE + 0x824)
#define BAR2_TO_AXI_ADDR_REG_L         (AXI_CONFIG_REGISTER_BASE + 0x850)
#define BAR2_TO_AXI_ADDR_REG_U         (AXI_CONFIG_REGISTER_BASE + 0x854)

#define BAR4_TO_AXI_ADDR_REG_L         (AXI_CONFIG_REGISTER_BASE + 0x860)
#define BAR4_TO_AXI_ADDR_REG_U         (AXI_CONFIG_REGISTER_BASE + 0x864)

#define LOCAL_MANAGEMENT_REGISTER      (0x109000)
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

	/*number bit axi address to pci address .
	 *
	 *note that valied number is this value +1 .
	 */
#define NUMBER_BIT_AXI_TO_PCI_ADDR  (7)

#define ALL_CFG_UPPER_ADDR      (0x80ULL)
#define PCIE_MEM_BASE           (0x6000000)

#define GIC_ENABLE_MSI_BIT          (1<<0)
#define GIC_ENABLE_MSIX_BIT         (2)
#define GIC_ENABLE_INTX_BIT         (0<<0)
	/*open global interrupt.*/
#define GIC_OPEN_GI_BIT             (0<<8)
	/*msi shift*/
#define MSI_ADDR_64_SHIFT           (23)
#define MSI_ADDR_IS_64              (1<<MSI_ADDR_64_SHIFT)

#define GIC_INTERRUPT_NUM           (256)
#define PCIE_IRQ_POWER_CHANGE       (91)
#define PCIE_IRQ_DPA                (92)
#define PCIE_IRQ_LOCAL              (93)
#define PCIE_IRQ_SOFT               (108)
#define PCIE_IRQ_F0_VSEC            (94)
#define PCIE_IRQ_DMA                (39)

	/*sideband register*/
#define SIDEBAND_BASE_ADDR          (0x10c000)

#define SIDEBAND(n)			(SIDEBAND_BASE_ADDR + 0x4 * (n))
#define V2PDMA_CTRL(ch_i)		(SIDEBAND(ch_i) + 0x100)

#define OUTBOUND_FIRST         (16)
#define OUTBOUND_CNT           (16)
#define OUTBOUND_POWER         (19UL)
#define OUTBOUND_SIZE          (1ULL<<OUTBOUND_POWER)
#define OUTBOUND_SIZE_TOTAL    (OUTBOUND_SIZE*OUTBOUND_CNT)
#define OUTBOUND_AXI_BASE      (PCIE_MEM_BASE + (16UL*1024*1024))

/* for pcie order bug, add dummy write */
#define PCIE_DUMMY_WRITE       (0x158000)
#define PMU_SYS_RST_CTRL	   (0x7428)
#define MCU_BASIC_INFO		   (0x7490)
#define MCU_DDRTRAINED_FLAG_SHIFT	30
#define MCU_DDRTRAINED_FLAG_MASK	0x01

#ifdef C20L_FPGA
#define C20L_DMA_MAX_PHY_CHANNEL             (1)
#else
#define C20L_DMA_MAX_PHY_CHANNEL             (4)
#endif

#define PCIE_IRQ_VF0_2_PF               (47)
#define PCIE_IRQ_VF1_2_PF               (48)
#define PCIE_IRQ_VF2_2_PF               (49)
#define PCIE_IRQ_VF3_2_PF               (50)

#define MAILBOX_INIT_REG                (0x2701)

#define CMD_GET_INBOUND_INFO            (0xabc0)
#define CMD_GET_OUTBOUND_INFO           (0xabc1)
#define CMD_SET_OUTBOUND_INFO           (0xabc2)
#define CMD_GET_DMA_INFO                (0xabc3)
#define CMD_GET_BDF                     (0xabc4)
#define CMD_SRIOV_INIT                  (0xabc5)
#define CMD_SRIOV_EXIT                  (0xabc6)
#define CMD_ALLOC_COMMU_CTRLQ           (0xcabc)

#endif
