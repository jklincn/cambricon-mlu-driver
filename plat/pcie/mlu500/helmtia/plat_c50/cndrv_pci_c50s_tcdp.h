/************************************************************************
 *
 *  @file cndrv_pci_c30_tcdp.h
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

#ifndef __CNDRV_PCI_C50S_TCDP_H
#define __CNDRV_PCI_C50S_TCDP_H

#define TCDP_MAX_QP_NUM			(8)
	/* encode(TX) init*/
#define TCDP_TX_BASE			(0x48000)
#define TCDP_TX_ENABLE_ALL_QP		(TCDP_TX_BASE + 0x0)  //wmf 0~7 QP enable
#define TCDP_TX_ENABLE_ALL_DIR_QP	(TCDP_TX_BASE + 0x4)  //wmf 0~7 QP DIR enable
#define TCDP_TX_ENABLE_HOST		(TCDP_TX_BASE + 0x8)  //bit0 to control enable
#define TCDP_TX_DIR_SRC_QP(qp_id)	(TCDP_TX_BASE + 0x40 * (qp_id) + 0x40) //qp_id(0~7) QP_ID
#define TCDP_TX_DIR_MASK_QP(qp_id)	(TCDP_TX_BASE + 0x40 * (qp_id) + 0x44) //mask
#define TCDP_TX_DIR_TGT_L_QP(qp_id)	(TCDP_TX_BASE + 0x40 * (qp_id) + 0x48) //tgt_l
#define TCDP_TX_DIR_TGT_H_QP(qp_id)	(TCDP_TX_BASE + 0x40 * (qp_id) + 0x4c) //tgt_h
#define TCDP_TX_DIR_SIDEBAND_QP(qp_id)	(TCDP_TX_BASE + 0x40 * (qp_id) + 0x50) //sideband
#define TCDP_TX_INDIR_SP_L_QP(qp_id)	(TCDP_TX_BASE + 0x40 * (qp_id) + 0x60) //spaddr_l
#define TCDP_TX_INDIR_SP_H_QP(qp_id)	(TCDP_TX_BASE + 0x40 * (qp_id) + 0x64) //spaddr_h
#define TCDP_TX_INDIR_SIDEBAND_QP(qp_id)(TCDP_TX_BASE + 0x40 * (qp_id) + 0x68) //sideband
	/* encode(TX) debug*/
#define TCDP_TX_CNT_ENABLE		(TCDP_TX_BASE + 0x400)  //wmf 0~7 dir_qp 8~15 indir qp
#define TCDP_TX_CNT_CLEAR		(TCDP_TX_BASE + 0x410)  //wmf 0~7 dir_qp 8~15 indir qp
#define TCDP_TX_DIR_CNT_QP(qp_id)	(TCDP_TX_BASE + 0x420 + 0x8 * (qp_id)) //dir cnt
#define TCDP_TX_INDIR_CNT_QP(qp_id)	(TCDP_TX_BASE + 0x424 + 0x8 * (qp_id)) //indir cnt
#define TCDP_TX_LINK_STATUS_CNT_QP	(TCDP_TX_BASE + 0x480) //0~2
#define TCDP_TX_LINK_STATUS_CNT_ENABLE	(TCDP_TX_BASE + 0x484)
#define TCDP_TX_LINK_STATUS_CNT_CLEAR	(TCDP_TX_BASE + 0x488)
#define TCDP_TX_AW_HANDSHAKE_CNT	(TCDP_TX_BASE + 0x48c) //ro
#define TCDP_TX_AW_BACKPRESSURE_CNT	(TCDP_TX_BASE + 0x490) //ro
#define TCDP_HOST_WRITE_ADDR		(TCDP_TX_BASE + 0x530) //wr [9:0]
#define TCDP_HOST_WRITE_ADDR_CHECK_ENABLE (TCDP_TX_BASE + 0x534) //wr [0:0]

		/* interrupt*/
#define TCDP_TX_INTER_CLEAR		(TCDP_TX_BASE + 0x500) // 0/4/8
#define TCDP_TX_INTER_RAW_STATUS	(TCDP_TX_BASE + 0x504) // 0/4/8
#define TCDP_TX_INTER_STATUS		(TCDP_TX_BASE + 0x508) // 0/4/8
#define TCDP_TX_INTER_FORCE		(TCDP_TX_BASE + 0x50c) // 0/4/8
#define TCDP_TX_INTER_MASK		(TCDP_TX_BASE + 0x510) // 0/4/8
#define TCDP_TX_INTER_ENABLE		(TCDP_TX_BASE + 0x514) // 0/4/8
#define TCDP_TX_ILLGAL_QP_TRANS_INFO	(TCDP_TX_BASE + 0x518) //ro
#define TCDP_TX_ILLGAL_DIR_TRANS_INFO	(TCDP_TX_BASE + 0x51c) //ro
#define TCDP_TX_IRQ			(TCDP_TX_BASE + 0x520) //ro
#define TCDP_TX_DFX_EN			(TCDP_TX_BASE + 0x600)

	/* decode(RX) init*/
#define TCDP_DET_ADDR_BASE		(0x7803030000ULL)
#define TCDP_RX_BASE			(0x49000)
#define TCDP_RX_ENABLE_ALL_QP		(TCDP_RX_BASE + 0x0) //wmf 0 all enable
#define TCDP_RX_ENABLE_DET		(TCDP_RX_BASE + 0x4) //wmf 0x1 default enable
#define TCDP_RX_DET_L			(TCDP_RX_BASE + 0x8)
#define TCDP_RX_DET_H			(TCDP_RX_BASE + 0xc)
#define TCDP_RX_SP_RESV_L		(TCDP_RX_BASE + 0x10)
#define TCDP_RX_SP_RESV_H		(TCDP_RX_BASE + 0x14)
	/* bar set*/
#define TCDP_BAR_BASE_SIZE		(256 * 1024) //256KB
#define TCDP_RX_BAR_WIN_ENABLE		(TCDP_RX_BASE + 0x100) //wmf 0
#define TCDP_RX_SRC_BAR			(TCDP_RX_BASE + 0x104)
#define TCDP_RX_MASK_BAR		(TCDP_RX_BASE + 0x108)
#define TCDP_RX_TGT_BAR			(TCDP_RX_BASE + 0x10c)
	/* mdr set*/
#define TCDP_RX_ENABLE_MDR(mdr_id)	(TCDP_RX_BASE + 0x200 + 0x10 * (mdr_id)) //wmf 0 mdr_id(0~6)
#define TCDP_RX_SRC_MDR(mdr_id)		(TCDP_RX_BASE + 0x204 + 0x10 * (mdr_id))
#define TCDP_RX_MASK_MDR(mdr_id)	(TCDP_RX_BASE + 0x208 + 0x10 * (mdr_id))
#define TCDP_RX_TGT_MDR(mdr_id)		(TCDP_RX_BASE + 0x20c + 0x10 * (mdr_id))
	/* qp dir set*/
#define TCDP_RX_DIR_ENABLE_QP(qp_id)	(TCDP_RX_BASE + 0x300 + 0x10 * (qp_id)) // wmf 0 qp_id(0~7)
#define TCDP_RX_DIR_SRC_QP(qp_id)	(TCDP_RX_BASE + 0x304 + 0x10 * (qp_id))
#define TCDP_RX_DIR_MASK_QP(qp_id)	(TCDP_RX_BASE + 0x308 + 0x10 * (qp_id))
#define TCDP_RX_DIR_TGT_QP(qp_id)	(TCDP_RX_BASE + 0x30c + 0x10 * (qp_id))
	/* qp indir set*/
#define TCDP_INDIR_BASE_SIZE		(8 * 1024) //4KB align
#define TCDP_RX_INDIR_ENABLE_QP(qp_id)	(TCDP_RX_BASE + 0x400 + 0x20 * (qp_id)) // wmf 0 qp_id(0~7)
#define TCDP_RX_INDIR_SP_L_QP(qp_id)	(TCDP_RX_BASE + 0x404 + 0x20 * (qp_id))
#define TCDP_RX_INDIR_SP_H_QP(qp_id)	(TCDP_RX_BASE + 0x408 + 0x20 * (qp_id))
#define TCDP_RX_INDIR_SRC_QP(qp_id)	(TCDP_RX_BASE + 0x40c + 0x20 * (qp_id))
#define TCDP_RX_INDIR_CAU_QP(qp_id)	(TCDP_RX_BASE + 0x410 + 0x20 * (qp_id))
#define TCDP_RX_SP_RESV_ENABLE_QP(qp_id)(TCDP_RX_BASE + 0x414 + 0x20 * (qp_id)) // wmf 0 qp_id(0~7)
	/* decode(RX) debug*/
		/* cnt total*/
#define TCDP_RX_MONITOR_QP(qp_id)	(TCDP_RX_BASE + 0x40 + 0x4 * (qp_id)) //or qp_id(0~7)
#define TCDP_RX_DIR_RECORD_QP(qp_id)	(TCDP_RX_BASE + 0x80 + 0x4 * (qp_id)) //or qp_id(0~7)
#define TCDP_RX_INDIR_RECORD_QP(qp_id)	(TCDP_RX_BASE + 0xa0 + 0x4 * (qp_id)) //or qp_id(0~7)
#define TCDP_RX_DIR_RECORD_ENABLE_QP	(TCDP_RX_BASE + 0xc8) //wmf 0~7
#define TCDP_RX_INDIR_RECORD_ENABLE_QP	(TCDP_RX_BASE + 0xcc) //wmf 0~7
#define TCDP_RX_DIR_RECORD_CLEAR_QP	(TCDP_RX_BASE + 0xd8) //wmf 0~7
#define TCDP_RX_INDIR_RECORD_CLEAR_QP	(TCDP_RX_BASE + 0xdc) //wmf 0~7
		/* interrupt*/
#define TCDP_RX_INTR_CLEAR		(TCDP_RX_BASE + 0x500) //wmf 0 4 8
#define TCDP_RX_INTR_RAW_STATUS		(TCDP_RX_BASE + 0x504) //wmf 0 4 8
#define TCDP_RX_INTR_STATUS		(TCDP_RX_BASE + 0x508) //wmf 0 4 8
#define TCDP_RX_INTR_FORCE		(TCDP_RX_BASE + 0x50c) //wmf 0 4 8
#define TCDP_RX_INTR_MASK		(TCDP_RX_BASE + 0x510) //wmf 0 4 8
#define TCDP_RX_INTR_ENABLE		(TCDP_RX_BASE + 0x514) //wmf 0 4 8
#define TCDP_RX_WR_NO_WIN_HIT_INFO_L	(TCDP_RX_BASE + 0x518) //ro
#define TCDP_RX_WR_NO_WIN_HIT_INFO_H	(TCDP_RX_BASE + 0x51c) //ro
#define TCDP_RX_RD_NO_WIN_HIT_INFO_L	(TCDP_RX_BASE + 0x520) //ro
#define TCDP_RX_RD_NO_WIN_HIT_INFO_H	(TCDP_RX_BASE + 0x524) //ro
#define TCDP_RX_RD_DETECTED_INFO_L	(TCDP_RX_BASE + 0x528) //ro
#define TCDP_RX_RD_DETECTED_INFO_H	(TCDP_RX_BASE + 0x52c) //ro
#define TCDP_RX_DEC_INTR		(TCDP_RX_BASE + 0x530) //ro
#define TCDP_RX_DFX_EN			(TCDP_RX_BASE + 0x600) //ro
	/* WROB init*/
#define TCDP_WROB_BASE			(0x4a000)
#define TCDP_HEAD_TAIL_ENABLE		(TCDP_WROB_BASE + 0x0) //wmf (head/tail)(0/1) 2 * 8
#define TCDP_HEAD_L_QP(qp_id)		(TCDP_WROB_BASE + 0x10 + 0x10 * (qp_id))
#define TCDP_HEAD_H_QP(qp_id)		(TCDP_WROB_BASE + 0x14 + 0x10 * (qp_id))
#define TCDP_TAIL_L_QP(qp_id)		(TCDP_WROB_BASE + 0x18 + 0x10 * (qp_id))
#define TCDP_TAIL_H_QP(qp_id)		(TCDP_WROB_BASE + 0x1c + 0x10 * (qp_id))
#define TCDP_JS_QUEUE_QP(qp_id)		(TCDP_WROB_BASE + 0x90 + 0x4 * (qp_id)) // (head/tail)(0~3/8~11) 2^4 = 16
	/* WROB debug*/
#define TCDP_CNT_ENABLE			(TCDP_WROB_BASE + 0x100) //wmf (head/tail)(0~7/8~15)
#define TCDP_CNT_CLEAR			(TCDP_WROB_BASE + 0x104) //wmf (head/tail)(0~7/8~15)
#define TCDP_HEAD_CNT_QP(qp_id)		(TCDP_WROB_BASE + 0x120 + 0x8 * (qp_id))
#define TCDP_TAIL_CNT_QP(qp_id)		(TCDP_WROB_BASE + 0x124 + 0x8 * (qp_id))

#define QP_INDIR_CAU(qp_id)		(10 + (qp_id) * 2) //10/12/.../36

#define QP_WIN_MASK			(0x3FFFFFFF)
#define SET_RX_WIN_MASK(size, mask)	\
	((u32)(mask << ilog2((size >> ilog2(TCDP_BAR_BASE_SIZE)))) & mask)

#define SET_QP_WIN_MASK(size)	\
		((u32)(QP_WIN_MASK << ilog2((size >> ilog2(TCDP_BAR_BASE_SIZE)))) & QP_WIN_MASK)
#define SET_QP_DIR_WIN(base, size, qp_id)   \
		((base) + ((qp_id) * size))
#define SET_QP_INDIR_WIN(base, size, qp_id)   \
			((base) + ((size) * TCDP_MAX_QP_NUM + (qp_id) * TCDP_INDIR_BASE_SIZE))

#define PCIE_KEY_SIZE			(8)
#define PCIE_QP_IND(qp)			((qp) & 0x7fffffff)
#define PCIE_QP_SEQ(qp)			(((qp) >> 32) & 0xffffffff)
#define PCIE_QP_DIR(qp)			(((qp) & 0xffffffff) >> 31)

#define MODIFY_TIME_OUT_VALUE		(60 * HZ)

#endif
