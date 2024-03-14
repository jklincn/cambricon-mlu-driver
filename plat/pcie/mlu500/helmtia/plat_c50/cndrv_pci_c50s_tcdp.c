/************************************************************************
 *
 *  @file cndrv_pci_c50s_tcdp.c
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
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif
#include "cndrv_pci_c50s_tcdp.h"
#include "cndrv_sbts.h"

#define TCDP_TOPO_SZ (8)
#define SOFT_BAR_INDEX_START (6)
#define BAR2_WIN_MASK			(0x3FFFFFFF)
#define SET_BAR2_WIN_MASK(size)	\
	((u32)(QP_WIN_MASK << ilog2((size >> ilog2(TCDP_BAR_BASE_SIZE)))) & BAR2_WIN_MASK)
/*
 * This is TCDP INDIR TXRX Work about tcdp win
 *
 *  TNC ->ENC(INDIR)  ======>>>  RX
 *  TNC <-DEC(INDIR)  <<=======  TX
 */
struct c50s_indir_tx_val {
	__u64 remote_win_base_pci;
};

struct c50s_indir_rx_val {
	__u64 local_win_base_offset;
};

struct c50s_indir_tx_val indir_tx_val[TCDP_TOPO_SZ][TCDP_TOPO_SZ];
struct c50s_indir_rx_val indir_rx_val[TCDP_TOPO_SZ][TCDP_TOPO_SZ];

/*
 * TCDP over PCIe DIR TX hugebar TOPO
 * Support 8 cards at most in one platform for MLU580
 * The channel 0 is reserved for Host Access.
 */

static int tcdp_chnl_relation[TCDP_TOPO_SZ][TCDP_TOPO_SZ] = {
	{-1,  1,  2,  3,  4,  5,  6,  7},
	{ 1, -1,  2,  3,  4,  5,  6,  7},
	{ 2,  1, -1,  3,  4,  5,  6,  7},
	{ 3,  1,  2, -1,  4,  5,  6,  7},
	{ 4,  1,  2,  3, -1,  5,  6,  7},
	{ 5,  1,  2,  3,  4, -1,  6,  7},
	{ 6,  1,  2,  3,  4,  5, -1,  7},
	{ 7,  1,  2,  3,  4,  5,  6, -1},
};

static void all_bar_call_iommu_unmap_when_exit(struct cn_pcie_set * pcie_set);

static int set_bar2_wins_under_tcdp_mode(struct cn_pcie_set *pcie_set)
{
	int bar2_win_cnt = 0;
	struct bar_resource *bar;
	int index;

	list_for_each_entry(bar, &pcie_set->bar_resource_head, list) {
		if (bar->type == PF_BAR &&
			(bar->index == 2 || bar->index >= SOFT_BAR_INDEX_START)) {
			/*
			 * enable + src + mask (+ target will be set when be used)
			 */
			if (bar->index == 2) {
				//The tiny BAR2 normal-win src keep 0x0000 As default value.
				cn_pci_reg_write32(pcie_set, TCDP_RX_MASK_BAR,
					SET_RX_WIN_MASK(bar->size, QP_WIN_MASK)); //Maks As 256KB(2^18) align
				cn_pci_reg_write32(pcie_set, TCDP_RX_BAR_WIN_ENABLE, 0x10001); //Enable As wmf 0
			} else {
				index = bar->index - SOFT_BAR_INDEX_START;
				cn_pci_reg_write32(pcie_set, TCDP_RX_ENABLE_MDR(index), 0x10001);
				cn_pci_reg_write32(pcie_set, TCDP_RX_SRC_MDR(index), (bar->size << index));
				cn_pci_reg_write32(pcie_set, TCDP_RX_MASK_MDR(index), SET_BAR2_WIN_MASK(bar->size));
			}
			bar2_win_cnt += 1;
		}
	}

	return bar2_win_cnt;
}

static void c50s_pcie_tcdp_bar_unmap(struct cn_pcie_set *pcie_set,
						__u64 win_base, __u64 win_size)
{
	dma_addr_t dma_addr;

	dma_addr = win_base;
	if (!dma_mapping_error(&pcie_set->pdev->dev, dma_addr)) {
		dma_unmap_page(&pcie_set->pdev->dev, dma_addr,
						win_size, DMA_BIDIRECTIONAL);
	}
}

static dma_addr_t c50s_pcie_tcdp_bar_map(struct cn_pcie_set *pcie_set,
						__u64 win_base, __u64 win_size)
{
	dma_addr_t dma_addr = 0;
	unsigned long offset;

	offset = win_base & (~PAGE_MASK);
	win_base &= PAGE_MASK;
	pcie_set->tcdp_set.p_page = pfn_to_page(win_base >> PAGE_SHIFT);
	dma_addr = dma_map_page(&pcie_set->pdev->dev,
			pcie_set->tcdp_set.p_page, offset, win_size, DMA_FROM_DEVICE);
	if (dma_mapping_error(&pcie_set->pdev->dev, dma_addr)) {
		cn_dev_pcie_err(pcie_set, "dma mapping error");
		return 0;
	}

	return dma_addr;
}

static u64 c50s_pcie_get_tcdp_host_buff(struct cn_pcie_set *pcie_set)
{
	int ret = 0;
	struct tcdp_set *tcdp_set = NULL;
	size_t size = pcie_set->tcdp_set.qp_win_size;

	if (!pcie_set->cfg.tcdp_able) {
		cn_dev_pcie_info(pcie_set, "not support pcie-tcdp no init");
		return 0;
	}

	tcdp_set = &pcie_set->tcdp_set;

	/***
	 * Try get host-shm via OB(return Device PA)
	 * Use rcard_id as index.
	 */
	if (tcdp_set->proxy_host_addr) {
		return tcdp_set->proxy_dev_addr;
	}
	ret = cn_host_share_mem_alloc(0, &tcdp_set->proxy_host_addr,
				&tcdp_set->proxy_dev_addr, size,
				pcie_set->bus_set->core->mm_set);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "proxy outbound alloc error");
		return 0;
	}
	memset((void *)tcdp_set->proxy_host_addr, 0, size);

	cn_dev_pcie_info(pcie_set, "dev_pa=%#llx, host_va=%#lx",
				tcdp_set->proxy_dev_addr,
				tcdp_set->proxy_host_addr);

	return tcdp_set->proxy_dev_addr;
}

/* Call Trace
 * 	cn_core_probe
 *		cn_bus_init
 *		   .post_init : cn_pci_init ....................POST-ONE-HANDLE
 *			pcie_set->ops->pcie_init : helmtia.h
 */
static int c50s_pcie_tcdp_top_init(struct cn_pcie_set *pcie_set)
{
	int ret = 0;
	int size = 0x2000; /*Len Equal to Crash_Space For INDIR TCDP*/
	struct pci_dev *pdev = pcie_set->pdev;
	struct bar_resource *bar = NULL;
	dma_addr_t dma_addr = 0;
	u64 bar2_top_size;
	/***
	 * Attention:
	 *	IPC Register : See fw_manager_c50.c:525
	 *		cn_pci_probe
	 *		cn_bus_probe->cn_core_probe->cn_bus_set_stru
	 *		.pre_init .............................. PRE-ONE-HADNLE
	 *		  c50_pcie_pre_init
	 *		    cn_platform_init --------+___ Begin Affect Whole SW System
	 *		    ... ... 		     V
	 *		   pcie_register_bar(pcie_set)
	 */
	if (!pcie_set->cfg.tcdp_able) {
		cn_dev_pcie_info(pcie_set, "not support pcie-tcdp no init");
		return 0;
	}

	/* RX init : For common crash_space 8K about INDIR Transfer JUST as RSP */
	ret = cn_device_share_mem_alloc(0, &pcie_set->tcdp_set.qp_crash_space_hva,
		&pcie_set->tcdp_set.qp_crash_space_dva, size, pcie_set->bus_set->core);
	if (ret) {
		cn_dev_pcie_err(pcie_set, "tcdp qp_crash_space alloc fail");
		return -1;
	}
	memset_io((void *)pcie_set->tcdp_set.qp_crash_space_hva, 0, size);
	/* RX enable*/
	cn_pci_reg_write32(pcie_set, TCDP_RX_ENABLE_ALL_QP, 0x10001);//wmf 0

	/* RX set sp_addr crash space*/
	cn_pci_reg_write64(pcie_set, TCDP_RX_SP_RESV_L, pcie_set->tcdp_set.qp_crash_space_dva);

	/* RX set det space : This is default Fixed Address */
	cn_pci_reg_write64(pcie_set, TCDP_RX_DET_L, TCDP_DET_ADDR_BASE);
	cn_pci_reg_write32(pcie_set, TCDP_RX_ENABLE_DET, 0x10001);//wmf 0

	/* enable Rx interrupt*/
	cn_pci_reg_write32(pcie_set, TCDP_RX_INTR_ENABLE, 0x11111111);//wmf 0

	/* enable Tx interrupt*/
	cn_pci_reg_write32(pcie_set, TCDP_TX_INTER_ENABLE, 0x1110111);//wmf 0

	/* RX BAR win init
	 *  1. Normal tiny-BAR2 for common use same as BAR4
	 *  2. qp_win_size : Half of Original BAR2 (= total_len - bar->size - mdr_win_size)
	 *  3. qp_win_base : The start addrss of QPs (Total QP0~7)  BUS-ADDR
	 */
	list_for_each_entry(bar, &pcie_set->bar_resource_head, list) {
		if (bar->type == PF_BAR && bar->index == 2) {
			break;
		}
	}
	if (!bar) {
		cn_dev_pcie_err(pcie_set, "bar2 resource NULL");
		return -1;
	}
	bar2_top_size = bar->rediv_size;
	pcie_set->tcdp_set.qp_win_size = pci_resource_len(pdev, 2) - bar2_top_size;
	cn_dev_pcie_info(pcie_set, "BAR2 Seprate [%llx] : [%llx] | [%llx]",
			pci_resource_len(pdev, 2), bar2_top_size, pcie_set->tcdp_set.qp_win_size);

	/***
	 * Get offset bwtween Bus-Addr and Host-Phy-Addr.
	 */
	pcie_set->tcdp_set.bus_offset = pci_resource_start(pcie_set->pdev, 0) -
					cn_pci_bus_address(pcie_set->pdev, 0);

	/***
	 * Attention:
	 *	In order keep high-speed for TCDP.
	 *	1. The best topo is twos have same upstream(sw) with ACS OFF.
	 *			iommu-ON   OFF
	 *		x86	---	   ---
	 *		aarch64 Needmaybe  ---
	 *	2. Besides, when the twos have common UPS and ACS ON, it
	 *	   may be slowdown when do duplex working.
	 *			iommu-ON   OFF
	 *		x86	---	   ---
	 *		aarch64 Needmaybe  ---
	 *	3. And, when the twos belong different RP, it shall do try process to
	 *	   decide whether they can connect to each other.
	 *			iommu-ON   OFF
	 *		x86	---	   ---
	 *		aarch64 Needmaybe  ---
	 */
	if (iommu_present(pdev->dev.bus) && !tcdp_ignore_iommu) {
		cn_dev_pcie_info(pcie_set, "iommu on : TCDP shall work with ACS-ON");
		dma_addr = c50s_pcie_tcdp_bar_map(pcie_set,
			bar->phy_base + bar2_top_size, pcie_set->tcdp_set.qp_win_size); /*NOTE: the top Half have Jump*/
		if (unlikely(!dma_addr))
			cn_dev_pcie_err(pcie_set, "tcdp bar map error");
		pcie_set->tcdp_set.qp_win_base = dma_addr - pcie_set->tcdp_set.bus_offset;
		cn_dev_pcie_info(pcie_set, "iommu on : qp_win_base = %llx ([%llx] - [%lx])",
				pcie_set->tcdp_set.qp_win_base, dma_addr,
				pcie_set->tcdp_set.bus_offset);

	} else {
		pcie_set->tcdp_set.qp_win_base =
			(bar->phy_base - pcie_set->tcdp_set.bus_offset) + bar2_top_size;
		cn_dev_pcie_info(pcie_set, "iommu off(ign-%d) : qp_win_base = %llx ([%llx] - [%lx] + [%llx])",
				tcdp_ignore_iommu, pcie_set->tcdp_set.qp_win_base,
				bar->phy_base, pcie_set->tcdp_set.bus_offset, bar2_top_size);
	}

	cn_dev_pcie_info(pcie_set, "tcdp init ok");

	return ret;
}

static void c50s_pcie_tcdp_top_exit(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;

	if (!pcie_set->cfg.tcdp_able) {
		cn_dev_pcie_info(pcie_set, "not support pcie-tcdp no exit");
		return;
	}
	/* RX exit : free SHM about 8K INDIR crash Space and Host Proxy Buffer
	 * 	It dose not matter without call "cn_device_share_mem_free" and
	 *	the "cn_host_share_mem_free" Because the device will reboot after rmmod driver.
	 * 	And, beseides, when arrive here, the mm_set has
	 *	been NULL, which will lead panic error if we call 'cn_xxx_free'.
	 */

	if (iommu_present(pdev->dev.bus) && !tcdp_ignore_iommu) {
		c50s_pcie_tcdp_bar_unmap(pcie_set,
					pcie_set->tcdp_set.qp_win_base + pcie_set->tcdp_set.bus_offset,
					pcie_set->tcdp_set.qp_win_size);
	}

	/* RX disable*/
	cn_pci_reg_write32(pcie_set, TCDP_RX_ENABLE_ALL_QP, 0x10000);//wmf 0

	/* RX BAR win clear*/
	cn_pci_reg_write32(pcie_set, TCDP_RX_BAR_WIN_ENABLE, 0x10000); //wmf 0
	cn_pci_reg_write32(pcie_set, TCDP_RX_MASK_BAR, 0x0);
	cn_pci_reg_write32(pcie_set, TCDP_RX_TGT_BAR, 0x0);

	/* RX clear sp_addr crash space
	 * cn_device_share_mem_free can not work for mem_set is null.
	 */
	pcie_set->tcdp_set.qp_crash_space_hva = 0x0;
	pcie_set->tcdp_set.qp_crash_space_dva = 0x0;
	cn_pci_reg_write64(pcie_set, TCDP_RX_SP_RESV_L, 0x0);

	/* Clear host proxy buffer
	 * cn_host_share_mem_free can not work for mem_set is null.
	 */
	pcie_set->tcdp_set.proxy_host_addr = 0x0;
	pcie_set->tcdp_set.proxy_dev_addr = 0x0;

	/*
	 * Do unmap for bar when exit
	 */
	all_bar_call_iommu_unmap_when_exit(pcie_set);

	/*
	 * Clean config record info
	 */
	memset(&indir_rx_val[pcie_set->idx][0], 0x00, sizeof(struct c50s_indir_rx_val) * TCDP_TOPO_SZ);
	memset(&indir_tx_val[pcie_set->idx][0], 0x00, sizeof(struct c50s_indir_tx_val) * TCDP_TOPO_SZ);

	cn_dev_pcie_info(pcie_set, "tcdp exit ok");
}


#define QP0_WR_ADDR_CHECK_MASK (0x804000000000 >> 38)
static void c50s_pcie_qp0_wrhost_enable(struct cn_pcie_set *pcie_set)
{
	/***
	 * enable qp0 to write host-shm as default
	 */
	cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_HOST, 0x1);
	cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_ALL_QP, 0x10001);
	cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_ALL_DIR_QP, 0x10001);
	cn_pci_reg_write32(pcie_set, TCDP_HOST_WRITE_ADDR, QP0_WR_ADDR_CHECK_MASK);
	cn_pci_reg_write32(pcie_set, TCDP_HOST_WRITE_ADDR_CHECK_ENABLE, 0x1);
	cn_pci_reg_read32(pcie_set, TCDP_TX_ENABLE_HOST);
	cn_dev_pcie_info(pcie_set, "qp0 wrhost enable");
}

static void c50s_pcie_qp0_wrhost_disable(struct cn_pcie_set *pcie_set)
{
	/***
	 * disable qp0 to write host-shm as default
	 */
	cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_HOST, 0x0);
	cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_ALL_QP, 0x10000);
	cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_ALL_DIR_QP, 0x10000);
	cn_pci_reg_write32(pcie_set, TCDP_HOST_WRITE_ADDR, 0x0);
	cn_pci_reg_write32(pcie_set, TCDP_HOST_WRITE_ADDR_CHECK_ENABLE, 0x0);
	cn_pci_reg_read32(pcie_set, TCDP_TX_ENABLE_HOST);
	cn_dev_pcie_info(pcie_set, "qp0 wrhost disable");
}

static u64 c50s_pcie_get_tcdp_win_base(struct cn_pcie_set *pcie_set)
{
	return pcie_set->tcdp_set.qp_win_base; /*Bus Addr after dma_map*/
}

/*
 * The qp_win_size is the total size of the bottom zone in BAR2 for tcdp.
 * Format:  single_qp_win_sz * 8 + 8K * 8
 *
 *	1. single_qp_win_sz used for DIR
 *	2. 8k used for INDIR
 *
 * In view the size-change about BAR2, then single_qp_win_sz may be not 8M at some time.
 * single_qp_win_sz = qp_win_size / 8 : This will be same formula in ARM.
 *	256 -> 128 -> 8   OR   128 -> 64 -> 4   OR   64 -> 32 -> 2
 */
static u64 c50s_pcie_get_tcdp_win_size(struct cn_pcie_set *pcie_set)
{
	return pcie_set->tcdp_set.qp_win_size;
}

/*
 * This is TCDP DIR TX Work on huge bar (linear bar)
 *
 *  TNC ->ENC(DIR)  ======>>>  RX (BAR4)
 */
static int c50s_pcie_tcdp_tx_dir_linear_bar_cfg(struct cn_pcie_set *pcie_set,
						int tx_card, int rx_card,
						u64 rx_liner_bar_bus_base,
						u64 rx_liner_bar_axi_base,
						u64 rx_liner_bar_size)
{
	int tx_chnl = 0;
	int ret = 0;

	if (tx_card >= TCDP_TOPO_SZ || rx_card >= TCDP_TOPO_SZ) {
		ret = -1;
		cn_dev_pcie_err(pcie_set, "tcdp topo support %d member at most [tx=%d rx=%d]",
			TCDP_TOPO_SZ, tx_card, rx_card);
		goto exit;
	}

	tx_chnl = tcdp_chnl_relation[tx_card][rx_card];
	if (tx_chnl > 0) {
		cn_dev_pcie_debug(pcie_set, "lcard=%d rcard=%d DIR tx_chnl=%d config",
				tx_card, rx_card, tx_chnl);
		cn_pci_reg_write32(pcie_set, TCDP_TX_DIR_SRC_QP(tx_chnl),
				rx_liner_bar_axi_base >> ilog2(TCDP_BAR_BASE_SIZE));
		cn_pci_reg_write32(pcie_set, TCDP_TX_DIR_MASK_QP(tx_chnl),
				SET_QP_WIN_MASK(rx_liner_bar_size));
		cn_pci_reg_write32(pcie_set, TCDP_TX_DIR_TGT_H_QP(tx_chnl),
				rx_liner_bar_bus_base >> 32);
		cn_pci_reg_write32(pcie_set, TCDP_TX_DIR_TGT_L_QP(tx_chnl),
				rx_liner_bar_bus_base & 0xfffc0000);
		cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_ALL_DIR_QP, (0x10001 << tx_chnl));

		cn_pci_reg_read32(pcie_set, TCDP_TX_DIR_SRC_QP(tx_chnl));
	} else {
		ret = -1;
		cn_dev_pcie_err(pcie_set, "tcdp_chnl_relation[%d] invalid", tx_chnl);
	}
exit:
	return ret;
}

#define DEFAULT_QP_ZONE_128M  (128 * 1024 * 1024)
#define DEFAULT_QP_WIN_SZ_8M  (8 * 1024 * 1024)

#define cfg_indir_tx_remote_win_base_pci(pcie_set, qpair, rqpair, rtcdp_win_base) do { \
	u64 base; \
	base = SET_QP_INDIR_WIN(rtcdp_win_base, DEFAULT_QP_WIN_SZ_8M, rqpair); \
	if (__sync_lock_test_and_set(&indir_tx_val[pcie_set->idx][qpair].remote_win_base_pci, base) != base) { \
		cn_pci_reg_write32(pcie_set, TCDP_TX_INDIR_SP_H_QP(qpair), base >> 32); \
		cn_pci_reg_write32(pcie_set, TCDP_TX_INDIR_SP_L_QP(qpair), base & 0xffffe000); \
	} \
} while (0)

#define cfg_indir_rx_local_win_base_offset(pcie_set, qpair) do { \
	u64 base; \
	base = SET_QP_INDIR_WIN(DEFAULT_QP_ZONE_128M, DEFAULT_QP_WIN_SZ_8M, qpair); \
	if (__sync_lock_test_and_set(&indir_rx_val[pcie_set->idx][qpair].local_win_base_offset, base) != base) { \
		cn_pci_reg_write32(pcie_set, TCDP_RX_INDIR_SP_H_QP(qpair), base >> 32); \
		cn_pci_reg_write32(pcie_set, TCDP_RX_INDIR_SP_L_QP(qpair), base & 0xffffe000); \
		cn_pci_reg_write32(pcie_set, TCDP_RX_INDIR_CAU_QP(qpair), QP_INDIR_CAU(qpair)); \
		cn_pci_reg_write32(pcie_set, TCDP_RX_SP_RESV_ENABLE_QP(qpair), 0x10001); \
	} \
} while (0)


static int c50s_pcie_tcdp_txrx_indir_cfg(struct cn_pcie_set *pcie_set,
						int tx_card, int rx_card,
						u64 rx_tcdp_win_bus_base)
{
	int chnl = 0;
	int rchnl = 0;
	int ret = 0;

	if (tx_card >= TCDP_TOPO_SZ || rx_card >= TCDP_TOPO_SZ) {
		ret = -1;
		cn_dev_pcie_err(pcie_set, "tcdp topo support %d member at most [tx=%d rx=%d]",
			TCDP_TOPO_SZ, tx_card, rx_card);
		goto exit;
	}

	chnl = tcdp_chnl_relation[tx_card][rx_card];
	rchnl = tcdp_chnl_relation[rx_card][tx_card];
	if (chnl > 0) {
		cn_dev_pcie_debug(pcie_set, "lcard=%d rcard=%d INDIR chnl=%d rchnl=%d rtcdp_win_base=%llx config",
				tx_card, rx_card, chnl, rchnl, rx_tcdp_win_bus_base);
		cfg_indir_tx_remote_win_base_pci(pcie_set, chnl, rchnl, rx_tcdp_win_bus_base);
		cfg_indir_rx_local_win_base_offset(pcie_set, chnl);
		cn_pci_reg_read32(pcie_set, TCDP_HEAD_TAIL_ENABLE);
	} else {
		ret = -1;
		cn_dev_pcie_err(pcie_set, "tcdp_chnl_relation[%d] invalid", chnl);
	}
exit:
	return ret;
}

/*
 * All bars bus_offset treated as same one.
 */
#define NOT_LINEAR_BAR_SIZE_MARK (0x10000000) /*256M*/
struct cn_bar_iommu_remap {
	u64 phy_base;
	u64 bus_base_org;
	u64 bus_base_map;
	u64 size;
};
struct cn_pcie_set_and_card_id {
	struct cn_pcie_set *pcie_set;
	int card_id;
};


enum {
	LINEAR_BAR = 1,
	TCDP_BAR = 2,
};

static struct cn_pcie_set_and_card_id  pcie_set_and_card_id[TCDP_TOPO_SZ];
static struct cn_bar_iommu_remap linear_bar_iommu_remap_tbl[TCDP_TOPO_SZ][TCDP_TOPO_SZ]; /*Support 8 card at most*/
static struct cn_bar_iommu_remap tcdp_win_base_iommu_remap_tbl[TCDP_TOPO_SZ][TCDP_TOPO_SZ]; /*Support 8 card at most*/

static u64 one_bar_call_iommu_remap(struct cn_pcie_set * pcie_set, u64 bus_base, u64 phy_base,
				u64 size, int card_id, int rcard_id)
{
	dma_addr_t dma_addr;
	struct cn_bar_iommu_remap *bar_iommu_remap_tbl = NULL;
	int type;

	if (rcard_id >= TCDP_TOPO_SZ) {
		return 0;
	}
	/*Record pcie_set and card_id*/
	pcie_set_and_card_id[card_id].card_id = card_id;
	pcie_set_and_card_id[card_id].pcie_set = pcie_set;

	if (!bus_base) {
		bar_iommu_remap_tbl = &tcdp_win_base_iommu_remap_tbl[card_id][rcard_id];
		type = TCDP_BAR;
	} else {
		bar_iommu_remap_tbl = &linear_bar_iommu_remap_tbl[card_id][rcard_id];
		type = LINEAR_BAR;
	}

	if (bar_iommu_remap_tbl->bus_base_map) {
		return bar_iommu_remap_tbl->bus_base_map;
	}
	dma_addr = c50s_pcie_tcdp_bar_map(pcie_set, phy_base, size);

	bar_iommu_remap_tbl->bus_base_org = bus_base;
	bar_iommu_remap_tbl->phy_base = phy_base;
	bar_iommu_remap_tbl->bus_base_map = (u64)dma_addr;
	bar_iommu_remap_tbl->size = size;

	cn_dev_pcie_debug(pcie_set, "card-%d for rcard-%d %s bar remap : %llx[%llx] -> %llx size=%llx",
		card_id, rcard_id,
		type == LINEAR_BAR ? "libnear" : "tcdp_win_base",
		bus_base, phy_base,
		bar_iommu_remap_tbl->bus_base_map,
		bar_iommu_remap_tbl->size);

	return (u64)dma_addr;
}

static void one_bar_call_iommu_unmap(struct cn_pcie_set * pcie_set, int card_id, int rcard_id)
{
	if (linear_bar_iommu_remap_tbl[card_id][rcard_id].bus_base_map) {
		c50s_pcie_tcdp_bar_unmap(pcie_set,
			linear_bar_iommu_remap_tbl[card_id][rcard_id].bus_base_map,
			linear_bar_iommu_remap_tbl[card_id][rcard_id].size);

		linear_bar_iommu_remap_tbl[card_id][rcard_id].bus_base_map = 0;
	}

	if (tcdp_win_base_iommu_remap_tbl[card_id][rcard_id].bus_base_map) {
		c50s_pcie_tcdp_bar_unmap(pcie_set,
			tcdp_win_base_iommu_remap_tbl[card_id][rcard_id].bus_base_map,
			tcdp_win_base_iommu_remap_tbl[card_id][rcard_id].size);

		tcdp_win_base_iommu_remap_tbl[card_id][rcard_id].bus_base_map = 0;
	}
}

static void all_bar_call_iommu_unmap_when_exit(struct cn_pcie_set *pcie_set)
{
	int i;
	int card_id = -1; /*without work and just do load/unload -1 means no card remapped*/

	for (i = 0; i < TCDP_TOPO_SZ; i++) {
		if (pcie_set_and_card_id[i].pcie_set == pcie_set) {
			card_id = i;
			break;
		}
	}
	if (card_id < 0) {
		return;
	}
	if (card_id >= TCDP_TOPO_SZ) {
		cn_dev_pcie_err(pcie_set, "not found pcie_set to do unmap when exit");
	} else {
		for (i = 0; i < TCDP_TOPO_SZ; i++) {
			one_bar_call_iommu_unmap(pcie_set, card_id, i);
		}
	}
}

static u64 c50s_pcie_linear_bar_iommu_remap(struct cn_pcie_set *pcie_set_src,
			struct cn_pcie_set *pcie_set_dst, int src_card_id, int dst_card_id)
{
	/*
	 * Do iommu remap based on next situation
	 * 	1. UPS-SW + ACS OFF : not
	 *	2. UPS-SW + ACS ON  : yes
	 *	3. DIFF RP	    : yes
	 */
	u64 addr_remap;

	addr_remap = one_bar_call_iommu_remap(pcie_set_src,
			pcie_set_dst->linear_bar.resource->bus_base,
			pcie_set_dst->linear_bar.resource->phy_base,
			pcie_set_dst->linear_bar.resource->size,
			src_card_id,
			dst_card_id);
	addr_remap -= pcie_set_dst->tcdp_set.bus_offset;

	return addr_remap;
}

static u64 c50s_pcie_tcdp_win_base_iommu_remap(struct cn_pcie_set *pcie_set_src,
			struct cn_pcie_set *pcie_set_dst, int src_card_id, int dst_card_id)
{
	/*
	 * Do iommu remap based on next situation
	 * 	1. UPS-SW + ACS OFF : not
	 *	2. UPS-SW + ACS ON  : yes
	 *	3. DIFF RP	    : yes
	 */
	u64 addr_remap;

	addr_remap = one_bar_call_iommu_remap(pcie_set_src,
			0, /*Just for format*/
			pcie_set_dst->tcdp_set.qp_win_base + pcie_set_dst->tcdp_set.bus_offset,
			pcie_set_dst->tcdp_set.qp_win_size,
			src_card_id,
			dst_card_id);
	addr_remap -= pcie_set_dst->tcdp_set.bus_offset;

	return addr_remap;
}

static int c50s_pcie_tcdp_change_channel_state(struct cn_pcie_set *pcie_set,
			int rcard_id, int dir, int state)
{
	int self_id = pcie_set->idx;
	int chnl_id = 0;
	int ret = 0;

	if (rcard_id >= TCDP_TOPO_SZ || self_id >= TCDP_TOPO_SZ) {
		cn_dev_pcie_err(pcie_set, "Can not support these cards: self=%d remote=%d",
			self_id, rcard_id);
		ret = -1;
		goto LABEL_EXIT;
	} else {
		chnl_id = tcdp_chnl_relation[self_id][rcard_id];
	}

	/***
	 * Close TCDP DIR MODE
	 * 'DIR' : TXon   RXoff (TX to Remote HugeBar)
	 * INDIR : TXon   RXon
	 */
	if (dir & TCDP_DIR_TX) {
		if (state == TCDP_CHAN_ON) {
			cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_ALL_QP, (0x10001 << chnl_id));
			cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_ALL_DIR_QP, (0x10001 << chnl_id));
			cn_dev_pcie_debug(pcie_set, "TX: card%d->card%d chan%d ON",
				self_id, rcard_id, chnl_id);
		} else {
			cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_ALL_QP, (0x10000 << chnl_id));
			cn_pci_reg_write32(pcie_set, TCDP_TX_ENABLE_ALL_DIR_QP, (0x10000 << chnl_id));
			cn_dev_pcie_debug(pcie_set, "TX: card%d->card%d chan%d OFF",
				self_id, rcard_id, chnl_id);
		}
	}
	if (dir & TCDP_DIR_RX) {
		if (state == TCDP_CHAN_ON) {
			cn_pci_reg_write32(pcie_set, TCDP_RX_INDIR_ENABLE_QP(chnl_id), 0x10001);
			/*cn_pci_reg_write32(pcie_set, TCDP_RX_DIR_ENABLE_QP(chnl_id), 0x10001);*/
			cn_dev_pcie_debug(pcie_set, "RX: card%d<-card%d chan%d ON",
				self_id, rcard_id, chnl_id);
		} else {
			cn_pci_reg_write32(pcie_set, TCDP_RX_INDIR_ENABLE_QP(chnl_id), 0x10000);
			/*cn_pci_reg_write32(pcie_set, TCDP_RX_DIR_ENABLE_QP(chnl_id), 0x10000);*/
			cn_dev_pcie_debug(pcie_set, "RX: card%d<-card%d chan%d OFF",
				self_id, rcard_id, chnl_id);
		}
	}

	cn_pci_reg_read32(pcie_set, TCDP_HEAD_TAIL_ENABLE);

LABEL_EXIT:
	return ret;
}
