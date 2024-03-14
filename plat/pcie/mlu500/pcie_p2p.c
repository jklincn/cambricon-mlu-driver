/*
 * This file is part of cambricon pcie driver
 *
 * Copyright (c) 2018, Cambricon Technologies Corporation Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/pci.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "pcie_dma.h"
#include "cndrv_pci.h"
#include "cndrv_mm.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_debug.h"

/*
 * The table record p2p able status; 1: enable_fast_lane,
 * 2: enable_slow_lane, 3: enable_acs_open, -1: disable
 * do not read switch pcie config space for fast access
 */
static int p2p_able[MAX_FUNCTION_NUM][MAX_FUNCTION_NUM];

/*
 * Check if a PCI bridge has its ACS redirection bits set to redirect P2P
 * TLPs upstream via ACS. Returns 1 if the packets will be redirected
 * upstream, 0 otherwise.
 */
static int pci_bridge_has_acs_redir(struct pci_dev *pdev)
{
	int pos;
	u16 ctrl;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ACS);
	if (!pos)
		return 0;

	pci_read_config_word(pdev, pos + PCI_ACS_CTRL, &ctrl);

	if (ctrl & (PCI_ACS_RR | PCI_ACS_CR | PCI_ACS_EC))
		return 1;

	return 0;
}

static struct pci_dev *cn_pci_upstream_bridge(struct pci_dev *dev)
{
	dev = pci_physfn(dev);
	if (pci_is_root_bus(dev->bus))
		return NULL;

	return dev->bus->self;
}

/*
 * Find the distance through the nearest common upstream bridge between
 * two PCI devices.
 *
 * If the two devices are the same device then 0 will be returned.
 *
 * If there are two virtual functions of the same device behind the same
 * bridge port then 2 will be returned (one step down to the PCIe switch,
 * then one step back to the same device).
 *
 * In the case where two devices are connected to the same PCIe switch, the
 * value 4 will be returned. This corresponds to the following PCI tree:
 *
 *     -+  Root Port
 *      \+ Switch Upstream Port
 *       +-+ Switch Downstream Port
 *       + \- Device A
 *       \-+ Switch Downstream Port
 *         \- Device B
 *
 * The distance is 4 because we traverse from Device A through the downstream
 * port of the switch, to the common upstream port, back up to the second
 * downstream port and then to Device B.
 *
 * Any two devices that don't have a common upstream bridge will return -1.
 * In this way devices on separate PCIe root ports will be rejected, which
 * is what we want for peer-to-peer seeing each PCIe root port defines a
 * separate hierarchy domain and there's no way to determine whether the root
 * complex supports forwarding between them.
 *
 * In the case where two devices are connected to different PCIe switches,
 * this function will still return a positive distance as long as both
 * switches eventually have a common upstream bridge. Note this covers
 * the case of using multiple PCIe switches to achieve a desired level of
 * fan-out from a root port. The exact distance will be a function of the
 * number of switches between Device A and Device B.
 *
 * If a bridge which has any ACS redirection bits set is in the path
 * then this functions will return -2. This is so we reject any
 * cases where the TLPs are forwarded up into the root complex.
 * In this case, a list of all infringing bridge addresses will be
 * populated in acs_list (assuming it's non-null) for printk purposes.
 */
static int upstream_bridge_distance(struct pci_dev *a,
				    struct pci_dev *b)
{
	int dist_a = 0;
	int dist_b = 0;
	struct pci_dev *bb = NULL;
	int acs_cnt = 0;

	/*
	 * Note, we don't need to take references to devices returned by
	 * pci_upstream_bridge() seeing we hold a reference to a child
	 * device which will already hold a reference to the upstream bridge.
	 */

	while (a) {
		dist_b = 0;

		if (pci_bridge_has_acs_redir(a))
			acs_cnt++;

		bb = b;

		while (bb) {
			if (a == bb)
				goto check_b_path_acs;

			bb = cn_pci_upstream_bridge(bb);
			dist_b++;
		}

		a = cn_pci_upstream_bridge(a);
		dist_a++;
	}

	return -1;

check_b_path_acs:
	bb = b;

	while (bb) {
		if (a == bb)
			break;

		if (pci_bridge_has_acs_redir(bb))
			acs_cnt++;

		bb = cn_pci_upstream_bridge(bb);
	}

	if (acs_cnt)
		return -2;

	return dist_a + dist_b;
}

__attribute__((unused))
static int cn_pci_dma_try_p2p(struct cn_pcie_set *src, struct cn_pcie_set *dst)
{
	int i = 0;
	int ret = 0;
	int able = 0;
	struct mem_attr src_mm = {0};
	struct mem_attr dst_mm = {0};
	dev_addr_t src_vaddr;
	dev_addr_t dst_vaddr;
	unsigned char value = 0xcb;
	void *h_addr = NULL;

	if (!src || !dst)
		return -1;

	INIT_MEM_ATTR(&src_mm, 0x1000, 0x10000, CN_IPU_MEM, -1, 0);
	memcpy(&dst_mm, &src_mm, sizeof(src_mm));
	/* alloc src and dst device addr*/
	ret = cn_mem_alloc(0, &src_vaddr, &src_mm, src->bus_set->core);
	if (ret) {
		cn_dev_pcie_err(src, "src ipu memory alloc failed(%d -- %#lx).",
					src_mm.affinity, src_mm.size);
		return -1;
	}

	ret = cn_mem_alloc(0, &dst_vaddr, &dst_mm, dst->bus_set->core);
	if (ret) {
		cn_dev_pcie_err(dst, "dst ipu memory alloc failed(%d -- %#lx).",
					dst_mm.affinity, dst_mm.size);
		able = -1;
		goto free_src_mm;
	}
	/* set src p2p data*/
	ret = cn_mem_dma_memsetD8(src->bus_set->core, src_vaddr, src_mm.size, value, 0);
	if (ret) {
		cn_dev_pcie_err(src, "src_vaddr memset %#x error", value);
		able = -1;
		goto free_dst_mm;
	}
	/* set dst p2p data*/
	ret = cn_mem_dma_memsetD8(dst->bus_set->core, dst_vaddr, dst_mm.size, 0, 0);
	if (ret) {
		cn_dev_pcie_err(dst, "dst_vaddr memset 0 error");
		able = -1;
		goto free_dst_mm;
	}
	/* go p2p*/
	ret = cn_mem_dma_p2p(src->bus_set->core, dst->bus_set->core,
						 src_vaddr, 0, dst_vaddr, 0, src_mm.size);
	if (ret) {
		cn_dev_pcie_err(src, "p2p test error");
		able = -1;
		goto free_dst_mm;
	}
	/* read dst p2p result*/
	h_addr = cn_kzalloc(dst_mm.size, GFP_KERNEL);
	if (!h_addr) {
		cn_dev_pcie_err(src, "bar.h_addr kzalloc error");
		able = -1;
		goto free_dst_mm;
	}
	ret = cn_mem_bar_copy_d2h(0, dst_vaddr, (unsigned long)h_addr,
				dst_mm.size, dst->bus_set->core);
	if (ret) {
		cn_dev_pcie_err(src, "cn_mem_bar_read error");
		able = -1;
		goto free_bar;
	}
	/* check */
	for (i = 0; i < dst_mm.size; i++) {
		if (*(unsigned char *)(h_addr + i) != value) {
			able = -1;
			break;
		}
	}
free_bar:
	cn_kfree(h_addr);

free_dst_mm:
	ret = cn_mem_free(0, dst_vaddr, dst->bus_set->core);
	if (ret) {
		cn_dev_pcie_err(src, "dst ipu mem_free failed.");
		return ret;
	}

free_src_mm:
	ret = cn_mem_free(0, src_vaddr, src->bus_set->core);
	if (ret) {
		cn_dev_pcie_err(src, "src ipu mem_free failed.");
		return ret;
	}

	return able;
}

static int cn_pci_force_p2p_xchg(void *pcie_priv, int force)
{
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;

	pcie_set->dfx.force_p2p_xchg_flag = (force == 1) ? 1 : 0;

	return 0;
}

static int cn_pci_dma_p2p_able(void *pcie_priv_src, void *pcie_priv_dst)
{
	int src_id, dst_id;
	int ret;
	int able = P2P_HOST_TRANSFER;
	struct cn_pcie_set *src = (struct cn_pcie_set *)pcie_priv_src;
	struct cn_pcie_set *dst = (struct cn_pcie_set *)pcie_priv_dst;

	src_id = src->bus_set->core->idx;
	dst_id = dst->bus_set->core->idx;

	if (src->dfx.force_p2p_xchg_flag || dst->dfx.force_p2p_xchg_flag) {
		return -1;
	}

	if (p2p_able[src_id][dst_id] == 0) {
		ret = upstream_bridge_distance(src->pdev, dst->pdev);
		switch (ret) {
		case 0:
			/* the two devices are the same device */
			break;
		case 2:
			/* two virtual functions
			 * of the same devices behind the same bridge port
			 */
			break;
		case -1:
			/* two devices that don't have a common upstream bridge */
#if defined(__x86_64__)
			if (src->cfg.p2p_mode == P2P_PUSH_MODE) {
				if (!cn_pci_dma_try_p2p(src, dst)) {
					/* able = 2 mark two devices more distance*/
					able = P2P_NO_COMMON_UPSTREAM_BRIDGE;
				}
			}
#endif
			break;
		case -2:
			/* a bridge with any ACS redirection bits set is in the path */
#if defined(__x86_64__)
			if (src->cfg.p2p_mode == P2P_PUSH_MODE) {
				if (!cn_pci_dma_try_p2p(src, dst)) {
					/* able = 3 mark two devices acs open*/
					able = P2P_ACS_OPEN;
				}
			}
#endif
			break;
		default:
			able = P2P_FAST_ABLE;
			break;
		}

		p2p_able[src_id][dst_id] = able;
	}

	return p2p_able[src_id][dst_id];
}

/*
 * Note:
 *	we shall know that "cn_p2pshm_global_post_init/../__p2p_matrix_test" have
 *	got the able information matrix.  See 'cn_pci_dma_p2p_able', init with
 *	'-1 : host transfer'
 *	'1  : switch directly'
 */
__attribute__((unused))
static int cn_pci_tcdp_link_on_able(void *pcie_priv_src, void *pcie_priv_dst)
{
	int src_id, dst_id;
	struct cn_pcie_set *src = (struct cn_pcie_set *)pcie_priv_src;
	struct cn_pcie_set *dst = (struct cn_pcie_set *)pcie_priv_dst;

	src_id = src->bus_set->core->idx;
	dst_id = dst->bus_set->core->idx;

	/***
	 * Attention:
	 *	For postsi verify, maybe shall force it able. And why? Because these
	 *	devices may be plug-in to RP directly and which will lead the p2p able
	 *	check as 'P2P_HOST_TRANSFER(-1)' and lead tcdp can not link on.
	 *	If need, just add "return 1" here.
	 */

	/***
	 * Attention:
	 *	Update p2p_able when it is init state.
	 *	As we know, "cn_p2pshm_global_post_init/../__p2p_matrix_test" have
	 *	inited the p2p_able[][]. In future, if the 'p2pshm' logic changed, here
	 *	maybe need add UpdateLogic to fill full 'p2p_able[][]'.
	 */

	if (!src->cfg.tcdp_able ||
			!dst->cfg.tcdp_able) {
		cn_dev_pcie_info(src, "card[%d] tcdp cap=%d;card[%d] tcdp cap=%d",
			src_id, src->cfg.tcdp_able,
			dst_id, dst->cfg.tcdp_able);
		return -1;
	}

	if (!p2p_able[src_id][dst_id]) {
		cn_pci_dma_p2p_able(pcie_priv_src, pcie_priv_dst);
	}
	if (!p2p_able[dst_id][src_id]) {
		cn_pci_dma_p2p_able(pcie_priv_dst, pcie_priv_src);
	}

	if ((p2p_able[src_id][dst_id] > 0) &&
			(p2p_able[dst_id][src_id] > 0)) {
		cn_dev_pcie_debug(src, "p2p_able[%d][%d] = %d;p2p_able[%d][%d] = %d",
				src_id, dst_id, p2p_able[src_id][dst_id],
				dst_id, src_id, p2p_able[dst_id][src_id]);
		return 1;
	}

	return 0;
}

static int alloc_kernel_pingpong_buffer(unsigned long *buf1, unsigned long *buf2,
			size_t count, int node)
{
	int order = get_order(min_t(u64, count, DMA_BUFFER_SIZE)); /* 1MB */
	struct page *buf1_pages;
	struct page *buf2_pages;

retry:
	if (order < 0) {
		return -1;
	}

	buf1_pages = alloc_pages_node(node, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY, order);
	if (!buf1_pages)
		buf1_pages = alloc_pages(GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY, order);

	buf2_pages = alloc_pages_node(node, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY, order);
	if (!buf2_pages)
		buf2_pages = alloc_pages(GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY, order);

	if (buf1_pages == NULL || buf2_pages == NULL) {
		if (buf1_pages)
			__free_pages(buf1_pages, order);
		if (buf2_pages)
			__free_pages(buf2_pages, order);
		--order;
		goto retry;
	} else {
		*buf1 = (unsigned long)page_address(buf1_pages);
		*buf2 = (unsigned long)page_address(buf2_pages);
	}

	return order;
}

static void free_kernel_pingpong_buffer(unsigned long buf1, unsigned long buf2, int order)
{
	if (order < 0)
		return;
	if (buf1)
		free_pages(buf1, order);
	if (buf2)
		free_pages(buf2, order);
}

static int get_idle_task_pair(struct cn_pcie_set *src, struct cn_pcie_set *dst,
		struct pcie_dma_task **task_d2h, struct pcie_dma_task **task_h2d)
{
	*task_d2h = cn_pci_get_dma_idle_task(src, DMA_D2H);
	if (*task_d2h == NULL)
		return -1;

	*task_h2d = cn_pci_get_dma_idle_task(dst, DMA_H2D);
	if (*task_h2d == NULL) {
		cn_pci_put_dma_idle_task(src, *task_d2h);
		return -1;
	}

	return 0;
}

static void put_idle_task_pair(struct cn_pcie_set *src, struct cn_pcie_set *dst,
	struct pcie_dma_task *task_d2h, struct pcie_dma_task *task_h2d)
{
	if (task_d2h)
		cn_pci_put_dma_idle_task(src, task_d2h);
	if (task_h2d)
		cn_pci_put_dma_idle_task(dst, task_h2d);
}

static int dma_soft_prepare(struct pcie_dma_task *task, struct dma_channel_info **channel)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int nents;
	struct dma_channel_info *p;

	__sync_fetch_and_add(&pcie_set->dma_set.task_num, 1);
	task->transfer_len = 0;

	nents = cn_pci_get_pages(task, task->transfer->ca, task->count);
	if (nents < 0) {
		return -1;
	}

	p = cn_pci_get_idle_channel(pcie_set, task, nents);
	if (p == NULL) {
		cn_dev_pcie_err(pcie_set, "get idle channel failed");
		return -1;
	}

	p->direction = task->transfer->direction;
	p->transfer_length = task->count;
	p->cpu_addr = task->transfer->ca;
	p->ram_addr = task->transfer->ia;
	p->dma_type = task->dma_type;
	*channel = p;

	if (cn_pci_channel_update_sgl(p)) {
		cn_pci_set_idle_channel(p);
		cn_dev_pcie_err(pcie_set, "update sgl failed");
		return -1;
	}

	return 0;
}

static void dma_soft_release(struct pcie_dma_task *task)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;

	__sync_fetch_and_sub(&pcie_set->dma_set.task_num, 1);
}

static int dma_wait_complete(struct pcie_dma_task *task, struct dma_channel_info *channel)
{
	struct cn_pcie_set *pcie_set = task->pcie_set;
	int ret;
	u64 prt_start, cur;

	if (!task->spkg_polling_flag) {
retry:
		ret = wait_event_interruptible_timeout(task->channel_wq,
				(task->transfer_len >= task->count) || task->err_flag, pcie_set->dma_set.dma_timeout);
		if (ret == -ERESTARTSYS) {
			if (!fatal_signal_pending(current)) {
				cn_dev_pcie_debug(pcie_set, "dequeue now%lx",
						current->pending.signal.sig[0]);
				usleep_range(20, 50);
				goto retry;
			}
		}
		if (ret < 0) {
			cn_dev_pcie_err(pcie_set, "Task is breaked by signal");
			return -1;
		} else if (!ret) {
			if (down_killable(&pcie_set->dfx.timeout_log_sem)) {
				cn_dev_pcie_err(pcie_set, "get timeout log sem is breaked by signal");
				return -1;
			}
			cn_pci_dump_reg_info(pcie_set);
			cn_pci_print_channel_state(task, pcie_set);
			up(&pcie_set->dfx.timeout_log_sem);
			return -1;
		}
	} else {
		prt_start = get_jiffies_64();
polling_retry:
		if (!((task->transfer_len >= task->count) || task->err_flag)) {
			if (unlikely(pcie_set->state == PCIE_STATE_STOP)) {
				cn_dev_pcie_info(pcie_set, "dma stop");
				return -1;
			}

			cur = get_jiffies_64();
			if (time_after64(cur, prt_start + HZ * 10)) {
				cn_dev_pcie_info(pcie_set, "polling dma status is busy %dms",
						jiffies_to_msecs(cur - prt_start));
				prt_start = get_jiffies_64();
				schedule();
			}
			goto polling_retry;
		}
	}

	if (cn_pci_finish_fifo_complete_out(pcie_set, task))
		return -1;

	return 0;
}

static size_t cn_pci_dma_p2p_pipeline(
	struct pcie_dma_task *task_d2h, struct pcie_dma_task *task_h2d)
{
	struct cn_pcie_set *src = task_d2h->pcie_set;
	struct dma_channel_info *ch_d2h = NULL;
	struct dma_channel_info *ch_h2d = NULL;
	long ret;

	ret = dma_soft_prepare(task_d2h, &ch_d2h);
	if (ret) {
		goto release_soft_d2h;
	}

	ret = dma_soft_prepare(task_h2d, &ch_h2d);
	if (ret) {
		cn_pci_set_idle_channel(ch_d2h);
		goto release_soft_h2d;
	}

	/* dma go */
	ret = cn_pci_channel_dma_ready(ch_d2h, 0);
	if (ret) {
		goto wait_error;
	}

	ret = cn_pci_channel_dma_ready(ch_h2d, 0);
	if (ret) {
		goto wait_error;
	}

	/* wait complete*/
	ret = dma_wait_complete(task_d2h, ch_d2h);
	if (ret) {
		goto wait_error;
	}

	ret = dma_wait_complete(task_h2d, ch_h2d);
	if (ret) {
		goto wait_error;
	}

	dma_soft_release(task_h2d);
	dma_soft_release(task_d2h);
	__sync_fetch_and_add(&src->dfx.p2p_exchg_cnt, 1);
	return ret;

wait_error:
	cn_dev_pcie_err(src, "wait error");
	cn_pci_check_error_wait(task_h2d);
	cn_pci_check_error_wait(task_d2h);
release_soft_h2d:
	dma_soft_release(task_h2d);
release_soft_d2h:
	dma_soft_release(task_d2h);
	return -1;
}

static size_t cn_pci_dma_p2p_exchange(struct peer_s *peer)
{
	struct cn_bus_set *src_bus_set = (struct cn_bus_set *)peer->src_bus_set;
	struct cn_pcie_set *src = (struct cn_pcie_set *)src_bus_set->priv;
	struct cn_bus_set *dst_bus_set = (struct cn_bus_set *)peer->dst_bus_set;
	struct cn_pcie_set *dst = (struct cn_pcie_set *)dst_bus_set->priv;
	u64 src_addr = peer->src_addr;
	u64 dst_addr = peer->dst_addr;
	size_t count = peer->size;
	unsigned long buf1, buf2;
	unsigned long d2h_buf, h2d_buf;
	size_t d2h_len, h2d_len;
	size_t remain = count, block;
	int order, ret;
	struct pcie_dma_task *task_h2d = NULL, *task_d2h = NULL;
	struct transfer_s t_h2d, t_d2h;
	int node;

	node = dev_to_node(&dst->pdev->dev);
	order = alloc_kernel_pingpong_buffer(&buf1, &buf2, count, node);
	if (order < 0) {
		cn_dev_pcie_err(src, "get kernel pingpong buffer fail");
		return -1;
	}

	block = PAGE_SIZE << order;
	d2h_len = min_t(size_t, remain, block);

	/* d2h */
	d2h_buf = buf1;
	ret = cn_pci_dma_kernel(d2h_buf, src_addr,
			d2h_len, DMA_D2H, src);
	if (ret) {
		cn_dev_pcie_err(src, "d2h fail");
		goto free;
	}

	remain -= d2h_len;
	src_addr += d2h_len;

	/*
	 * get two idle-tasks from pcie_src and pcie_dst
	 */
	if (remain) {
		ret = get_idle_task_pair(src, dst, &task_d2h, &task_h2d);
		if (ret) {
			cn_dev_pcie_err(src, "get dma pair task fail");
			goto free;
		}
	}

	/*
	 * h2d last ready buffer and d2h to get next new
	 */
	while (remain) {
		h2d_buf = d2h_buf;
		h2d_len = d2h_len;

		d2h_buf = (d2h_buf == buf1) ? buf2 : buf1;
		d2h_len = min_t(size_t, remain, block);

		/* int task d2h */
		TRANSFER_INIT(t_d2h, d2h_buf, src_addr, d2h_len, DMA_D2H);
		cn_pci_init_dma_task(task_d2h, &t_d2h, PCIE_DMA_KERNEL, src);

		/* int task h2d */
		TRANSFER_INIT(t_h2d, h2d_buf, dst_addr, h2d_len, DMA_H2D);
		cn_pci_init_dma_task(task_h2d, &t_h2d, PCIE_DMA_KERNEL, dst);

		ret = cn_pci_dma_p2p_pipeline(task_d2h, task_h2d);
		if (ret) {
			cn_dev_pcie_err(src, "p2p pipeline fail");
			goto exit;
		}

		remain -= d2h_len;
		src_addr += d2h_len;
		dst_addr += h2d_len;
	}

	put_idle_task_pair(src, dst, task_d2h, task_h2d);

	/* h2d */
	h2d_buf = d2h_buf;
	h2d_len = d2h_len;
	ret = cn_pci_dma_kernel(h2d_buf, dst_addr,
			h2d_len, DMA_H2D, dst);
	if (ret) {
		cn_dev_pcie_err(dst, "h2d fail");
		goto free;
	}

	free_kernel_pingpong_buffer(buf1, buf2, order);
	return 0;
exit:
	put_idle_task_pair(src, dst, task_d2h, task_h2d);
free:
	free_kernel_pingpong_buffer(buf1, buf2, order);
	return -1;
}

static size_t cn_pci_dma_p2p(struct peer_s *peer)
{
	struct cn_bus_set *src_bus_set = (struct cn_bus_set *)peer->src_bus_set;
	struct cn_pcie_set *src = (struct cn_pcie_set *)src_bus_set->priv;
	struct cn_bus_set *dst_bus_set = (struct cn_bus_set *)peer->dst_bus_set;
	struct cn_pcie_set *dst = (struct cn_pcie_set *)dst_bus_set->priv;
	u64 src_addr = peer->src_addr;
	u64 dst_addr = peer->dst_addr;
	size_t count = peer->size;
	struct pcie_dma_task *task;
	struct transfer_s transfer;
	struct cn_pcie_set *pcie_set_master;
	struct cn_pcie_set *pcie_set_slv;
	int dst_id;
	int src_id;
	struct bar_resource *bar_slv = NULL;
	u64 slv_addr;
	u64 master_addr;
	void *slv_minfo;
	size_t ret = -1;
	int desc_num;
	int max_desc_num;

	if (!src || !dst) {
		cn_dev_pcie_err(src, "src or dst is null");
		return ret;
	}

	dst_id = dst->bus_set->core->idx;
	src_id = src->bus_set->core->idx;
	if (p2p_able[src_id][dst_id] == P2P_HOST_TRANSFER ||
		p2p_able[src_id][dst_id] == P2P_NO_COMMON_UPSTREAM_BRIDGE ||
		p2p_able[src_id][dst_id] == P2P_ACS_OPEN) {
		return cn_pci_dma_p2p_exchange(peer);
	}

	if (dst->cfg.p2p_mode == P2P_PULL_MODE) {
		pcie_set_master = dst;
		pcie_set_slv = src;
		slv_addr = src_addr;
		master_addr = dst_addr;
		slv_minfo = peer->src_minfo;
	} else {
		pcie_set_master = src;
		pcie_set_slv = dst;
		slv_addr = dst_addr;
		master_addr = src_addr;
		slv_minfo = peer->dst_minfo;
	}

	task = cn_pci_get_dma_idle_task(pcie_set_master, DMA_P2P);
	if (!task)
		return ret;

	task->p2p_sg_tb = cn_mem_linear_remap(slv_minfo, slv_addr, peer->size);
	if (IS_ERR_OR_NULL(task->p2p_sg_tb)) {
p2p_use_bar_window:
		/* we just need slv device bar for p2p */
		bar_slv = pcie_get_bar(BLOCK, pcie_set_slv);
		if (!bar_slv)
			return ret;

		while (count) {
			u64 base, offset, size;
			size_t len;

			/* set slv window and calculate size */
			base = pcie_set_slv->ops->set_bar_window(slv_addr, bar_slv, pcie_set_slv);
			offset = slv_addr - base;
			size = bar_slv->size - offset;
			len = min_t(size_t, count, size);

			/* init transfer task */
			transfer.d_ipu = master_addr;
			transfer.d_bar = bar_slv->bus_base + offset;
			transfer.size = len;
			transfer.direction = DMA_P2P;

			/* use master dma for transfer */
			cn_pci_init_dma_task(task, &transfer, PCIE_DMA_P2P, pcie_set_master);
			if (p2p_able[src_id][dst_id] == P2P_FAST_ABLE) {
				task->p2p_trans_type = P2P_TRANS_BUS_ADDRESS;
			} else {
				task->p2p_trans_type = P2P_TRANS_DMA_MAP;
			}

			ret = cn_pci_dma_transfer(task);
			if (ret == 0) {
				count -= len;
				master_addr += len;
				slv_addr += len;
			} else {
				cn_dev_pcie_err(pcie_set_master, "p2p fail");
				break;
			}
		}

		cn_pci_put_dma_idle_task(pcie_set_master, task);
		if (bar_slv)
			pcie_put_bar(bar_slv, pcie_set_slv);
	} else {
		/* check the number limit of descriptors */
		max_desc_num = roundup_pow_of_two((pcie_set_master->dma_set.dma_buffer_size / PAGE_SIZE) + 1);
		desc_num = cn_pci_get_linear_p2p_desc_num(pcie_set_master, task->p2p_sg_tb);
		if (desc_num > max_desc_num) {
			cn_mem_linear_unmap(slv_minfo, task->p2p_sg_tb);
			goto p2p_use_bar_window;
		}

		/* init transfer task */
		transfer.d_ipu = master_addr;
		transfer.d_bar = sg_dma_address(task->p2p_sg_tb->sgl);
		transfer.size = count;
		transfer.direction = DMA_P2P;

		/* use master dma for transfer */
		cn_pci_init_dma_task(task, &transfer, PCIE_DMA_P2P, pcie_set_master);
		if (p2p_able[src_id][dst_id] == P2P_FAST_ABLE) {
			task->p2p_trans_type = P2P_TRANS_BUS_ADDRESS;
		} else {
			task->p2p_trans_type = P2P_TRANS_DMA_MAP;
		}

		task->p2p_linear_remap = 1;

		ret = cn_pci_dma_transfer(task);

		cn_mem_linear_unmap(slv_minfo, task->p2p_sg_tb);
		cn_pci_put_dma_idle_task(pcie_set_master, task);
	}

	return ret;
}

static void cn_pci_get_p2p_able_info(void *pcie_priv, struct p2p_stat *able, int *index)
{
	int i;
	struct cn_pcie_set *src = (struct cn_pcie_set *)pcie_priv;
	int src_id = src->bus_set->core->idx;

	if (able && index) {
		for (i = 0; i < MAX_FUNCTION_NUM; i++)
			if (p2p_able[src_id][i]) {
				able[*index].x = src_id;
				able[*index].y = i;
				able[*index].able = p2p_able[src_id][i];
				(*index)++;
			}
	}
}
