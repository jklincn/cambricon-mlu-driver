/************************************************************************
 *
 *  @file cndrv_pci_c30s.h
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

#ifndef __CNDRV_PCI_C30S_H
#define __CNDRV_PCI_C30S_H

#define K_GEN_REG			(0x80)
#define AXI_CONFIG_SIZE			(512 * 1024 * 1024)
/* arm trigger */
#define HOST_PHY_CHANNEL_NUM		(4)
#define ARM_PHY_CHANNEL_NUM		(3)
#define HOST_PHY_CHANNEL_MASK		((1 << HOST_PHY_CHANNEL_NUM) - 1)
#define SMALL_PACKET_CHANNEL_ID		(7) /* do not set 0 because of vf */
/* interrupt dma number */
#define INTR_DMA_CHANNEL_NUM		(HOST_PHY_CHANNEL_NUM + ARM_PHY_CHANNEL_NUM)
#define INTR_DMA_CHANNEL_MASK		((1 << INTR_DMA_CHANNEL_NUM) - 1)
/* total dma number */
#define DMA_REG_CHANNEL_NUM		(8)
#define DMA_REG_CHANNEL_MASK		((1 << DMA_REG_CHANNEL_NUM) - 1)

#define SHARED_DMA_DESC_TOTAL_SIZE	(0x1000000)
#define PRIV_DMA_DESC_TOTAL_SIZE	(0x400000)
#define VF_SHARED_DMA_DESC_TOTAL_SIZE	(0x400000)
#define VF_PRIV_DMA_DESC_TOTAL_SIZE	(0x400000)
#define ASYNC_DMA_DESC_TOTAL_SIZE       (0x800000)
#define PER_DESC_MAX_SIZE               (0x1000000)
#define DMA_DESC_PER_SIZE		(32)
#define ASYNC_MAX_DESC_NUM              (256)
#define ASYNC_STATIC_TASK_NUM           (1024)

#define MSI_COUNT_POWER			(0)
#define MSI_COUNT			(1<<MSI_COUNT_POWER)
#define MSIX_COUNT			(16)
#define INTX_COUNT			(1)

	/*DMA control regs offset*/
#define DBO			(0x400) /*DMA BASE OFFSET in bar0*/
#define DI_BASE			(0x180) /*DMA interrupt regs offset*/

	/*GIC register */
#define GBO			(0x20000) /*gic base address offset in bar0*/
#define SUB_GBO			(0x4000) /*gic base address sub offset in bar0*/

#define GIC_CTRL		(GBO + SUB_GBO + 0x0C0) /*gic interrupt control register*/
#define GIC_MASK		(GBO + SUB_GBO + 0x000) /*gic mask register(0~15)*/
#define GIC_STATUS		(GBO + SUB_GBO + 0x040) /*gic status register(0~15)*/

	/* gic MSIX clear, first write 1 for clear 1bit then write 1 for begin next time */
#define GIC_MSIX_PEND_CLR	(GBO + SUB_GBO + 0x080) /*msix clear register(0~15)*/
#define GIC_MSIX_VECTOR_COUNT	(GBO + SUB_GBO + 0x0C4)	/* msix vector count register*/
	/* total INT clear, first write 0x1 for clear interrupt then write 0x0 begin next time */
#define GLOBAL_INTX_CLR		(GBO + SUB_GBO + 0x0C8) /*gic int clear register*/

	/* pcie irq status :open irq->write 1 to PCIE_IRQ_MASK->*/
#define PCIE_IRQ_STATUS(i)	(GBO + 0x2000 + 0x200 + (i) * 4) /* 0~23*/
#define PCIE_IRQ_MASK(i)	(GBO + 0x2000 + 0x300 + (i) * 4) /* 0~23*/

	/* SLV0 outbound window reg */
#define ATR_AXI4_SLV0		(0x800)
#define SLV0_TABLE_BASE		(0x20)
#define SLV0_SRC_ADDRL(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x0)
#define SLV0_SRC_ADDRU(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x4)
#define SLV0_TRSL_ADDRL(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x8)
#define SLV0_TRSL_ADDRU(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0xC)
#define SLV0_TRSL_PARAM(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x10)
#define SLV0_TRSL_MASKL(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x18)
#define SLV0_TRSL_MASKU(i)	(ATR_AXI4_SLV0 + (i) * SLV0_TABLE_BASE + 0x1C)
#define SLV0_SNOOP_SET_REG	(0x304)

	/*dma fetch*/
#define PCIE_DMA_CTRL_TYPE			(SIDEBAND_BASE_ADDR + 0x480)
#define SPKG_DMA_FETCH_BUFF			(0x4) /* small packet fetch cmd depth */
#define DMA_FETCH_BUFF				(0x10)//16 cmd_buf
#define DESC_FETCH_BASE				(0x101000)
#define DMA_DESC_ADDR_L_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x0)
#define DMA_DESC_ADDR_H_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x4)
#define DMA_DESC_NUM_FETCH(i)			(DESC_FETCH_BASE + (i) * 0x100 + 0x8)
#define DMA_DESC_CTRL_FETCH(i)			(DESC_FETCH_BASE + (i) * 0x100 + 0xC)
#define DMA_DESC_CTRL2_FETCH(i)			(DESC_FETCH_BASE + (i) * 0x100 + 0x10)
#define DMA_STATUS_FETCH(i)			(DESC_FETCH_BASE + (i) * 0x100 + 0x20)
#define DMA_STATUS_UP_FETCH(i)			(DESC_FETCH_BASE + (i) * 0x100 + 0x24)
#define DMA_CMD_BUFF_STATUS_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x30)
#define DMA_CMD_STATUS_BUFF_STATUS_FETCH(i)	(DESC_FETCH_BASE + (i) * 0x100 + 0x34)
#define DMA_DESC_DBG_SEL_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x3C)
#define DMA_DESC_DBG_DATA0_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x40)
#define DMA_DESC_DBG_DATA1_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x44)
#define DMA_DESC_DBG_DATA2_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x48)
#define DMA_DESC_DBG_DATA3_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x4C)
#define DMA_DESC_DBG_DATA4_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x50)
#define DMA_DESC_DBG_DATA5_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x54)
#define DMA_DESC_DBG_DATA6_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x58)
#define DMA_DESC_DBG_DATA7_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x5C)
#define DMA_DESC_DBG_SM_FETCH(i)		(DESC_FETCH_BASE + (i) * 0x100 + 0x60)
#define DMA_FETCH_ERR_FLAG                      ((0x1) << 3)
#define DMA_FETCH_ERR_CHECK(status)             ((status) & (DMA_FETCH_ERR_FLAG))
//#define DMA_FETCH_DUG_PRT

#define OUTBOUND_FIRST         (0)
#define OUTBOUND_CNT           (16)
#define PF_OUTBOUND_CNT        (7)
#define OUTBOUND_POWER         (21UL)
#define OUTBOUND_SIZE          (1ULL<<OUTBOUND_POWER)
#define OUTBOUND_SIZE_TOTAL    (OUTBOUND_SIZE*OUTBOUND_CNT)
#define OUTBOUND_AXI_BASE      (0x8004000000ULL)
#define USE_DATA_OUTBOUND

	/*local management register*/
#define BAR_REMAP			(0x102000)
#define BAR0_MAX_SIZE			(0x10000000)
#define BAR_BASE_SIZE			(0x100000UL)
#define BAR0_MASK			(0xFFFFFFFF)
#define QUADRANT_BASE(i)		(0x80000 + (i) * 0x80)
#define QUADRANT_SIZE			(0x8000000UL)
#define QUADRANT_MASK			(QUADRANT_SIZE - 1)
#define C30S_BAR0_LEVEL0_4M		(0x400000UL)
	/*bar0 window(0~10)*/
#define BAR0_TO_AXI_SRC_WIN(i)		(BAR_REMAP + 0x1020 + (i) * 0xC)
#define BAR0_TO_AXI_MASK_WIN(i)		(BAR_REMAP + 0x1024 + (i) * 0xC)
#define BAR0_TO_AXI_TGT_WIN(i)		(BAR_REMAP + 0x1028 + (i) * 0xC)
#define VF_BAR0_WIN0_SRC(vf_i)		(BAR_REMAP + 0x20 + (vf_i) * 0x100)
#define VF_BAR0_WIN0_MASK(vf_i)		(BAR_REMAP + 0x24 + (vf_i) * 0x100)
#define VF_BAR0_WIN0_TGT(vf_i)		(BAR_REMAP + 0x28 + (vf_i) * 0x100)
#define VF_BAR0_WIN1_SRC(vf_i)		(BAR_REMAP + 0x2c + (vf_i) * 0x100)
#define VF_BAR0_WIN1_MASK(vf_i)		(BAR_REMAP + 0x30 + (vf_i) * 0x100)
#define VF_BAR0_WIN1_TGT(vf_i)		(BAR_REMAP + 0x34 + (vf_i) * 0x100)
	/*bar2/bar4 slip window*/
#define PF_BAR_ADDR_MASK(index)         (BAR_REMAP + 0x109c + 0x4 * (index))
#define PF_BAR_ADDR_BASE(index)         (BAR_REMAP + 0x10a0 + 0x4 * (index))
	/*bar debug register*/
#define BAR_REMAP_IRQ_STATUS		(BAR_REMAP + 0x10c0)
#define BAR_REMAP_IRQ_CLEAR		(BAR_REMAP + 0x10c4)
#define BAR_REMAP_ERR_ADDR		(BAR_REMAP + 0x10c8)
#define BAR_REMAP_ERR_STREAM		(BAR_REMAP + 0x10cc)
	/*share memory register*/
#define PF_SHARE_MEM_MASK		(BAR_REMAP + 0x1100)//0xffffe00 512MB
#define PF_SHARE_MEM_BASE		(BAR_REMAP + 0x1104)//0x0080200 512TB+512MB
	/*dbg dma irq flag(0~8)*/
#define DBG_DMA_IRQ_FLGA_BUFFER(i)	(BAR_REMAP + 0x1200 + (i) * 0x4)

#define GIC_ENABLE_MSI_BIT		(1<<0)
#define GIC_ENABLE_MSIX_BIT		(2)
#define GIC_ENABLE_INTX_BIT		(0<<0)
	/*open global interrupt.*/
#define GIC_OPEN_GI_BIT			(0<<8)
	/*msi shift*/
#define MSI_ADDR_64_SHIFT		(23)
#define MSI_ADDR_IS_64			(1<<MSI_ADDR_64_SHIFT)

#define GIC_INTERRUPT_NUM		(512)
#define PCIE_IRQ_DMA			(0)/*(0~7)8DMA end and (8~15)8DMA error*/
#define PCIE_IRQ_DMA_END		(7)

	/*sideband register*/
#define SIDEBAND_BASE_ADDR		(0xA0000)
#define VF_DOMAIN_ID(vf_id)		(SIDEBAND_BASE_ADDR	\
						+ 0x500 + (vf_id) * 0x4)

#define SIDEBAND(n)			(SIDEBAND_BASE_ADDR + 0x4 * (n))
#define LTSSM				(SIDEBAND(11))

	/* arm trigger dma register */
#define ARM_TRIGGER_HOST_PHY_CHANNEL	(SIDEBAND_BASE_ADDR + 0x600) //spare_reg_rw0
#define ARM_TRIGGER_ARM_PHY_CHANNEL	(SIDEBAND_BASE_ADDR + 0x604) //spare_reg_rw1
#define ARM_TRIGGER_DMA_FETCH_ENABLE	(SIDEBAND_BASE_ADDR + 0x608) //spare_reg_rw2
#define ARM_TRIGGER_REG			(SIDEBAND_BASE_ADDR + 0x60c) //spare_reg_rw3

	/*SLV3 outbound window reg */
#define ATR_AXI4_SLV3	(SIDEBAND_BASE_ADDR + 0x800)
#define SLV3_TABLE_BASE	(0x10)
#define SLV3_SRC_ADDRL(i)	(ATR_AXI4_SLV3 + (i) * SLV3_TABLE_BASE + 0x0)
#define SLV3_SRC_ADDRU(i)	(ATR_AXI4_SLV3 + (i) * SLV3_TABLE_BASE + 0x4)
#define SLV3_TRSL_ADDRL(i)	(ATR_AXI4_SLV3 + (i) * SLV3_TABLE_BASE + 0x8)
#define SLV3_TRSL_ADDRU(i)	(ATR_AXI4_SLV3 + (i) * SLV3_TABLE_BASE + 0xC)
#define SLV3_OUTBOUND_FIRST         (0)
#define SLV3_OUTBOUND_CNT           (1)
#define SLV3_OUTBOUND_POWER         (20UL)
#define SLV3_OUTBOUND_SIZE          (1ULL<<SLV3_OUTBOUND_POWER)
#define SLV3_OUTBOUND_SIZE_TOTAL    (SLV3_OUTBOUND_SIZE*SLV3_OUTBOUND_CNT)
#define SLV3_OUTBOUND_AXI_BASE      (0xB00000000ULL)//(0xB_0000_0000~0xC_0000_0000
#define SLV_WIN_AR_CNT              (SIDEBAND_BASE_ADDR + 0x157c)

/* fixed : dummy reg */
#define PCIE_DUMMY_WRITE       (0xa0000)

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
#define CMD_ALLOC_COMMU_CTRLQ           (0xcabc)
#define MAILBOX_INIT_REG		(0x2701)
/* total 32 bits, [0]:end_flag, [31:16]:CMD*/
#define CMD_END_FLAG			(0)
#define CMD_BIT_STATRT			(16)

#define RSV_BASE  0x368000
#define IPC_5     (RSV_BASE + 0x1C) /* card SN high 16 bit */

struct data_outbound_set {
	void                              *share_priv;
	struct page                      **share_mem_pages;
	u64                                ob_mask;
	int                                ob_cnt;
	int                                ob_size;
	int                                ob_total_size;
	u64                                ob_axi_addr;
	u32                                dob_ar_cnt;
};
struct c30s_bar0_set {
	struct semaphore		   bar0_window_sem[4];
	u8				   bar0_window_flag[4];
	u8				   bar0_window_base;
};

struct c30s_priv_set {
	struct c30s_bar0_set bar0_set;
	struct data_outbound_set dob_set;
};
#define C30S_PCIE_SMMU_ENABLE


#endif
