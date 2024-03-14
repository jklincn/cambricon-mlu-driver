/*
 * This file is part of cambricon device driver
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
#include <linux/fs.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_domain.h"
#include "./platform/cndrv_edge.h"

size_t cn_bus_dma(struct cn_bus_set *bus_set, struct transfer_s *t)
{
	return bus_set->ops->dma(t, bus_set->priv);
}

int cn_bus_core_type_switch(struct cn_bus_set *bus_set, __u32 policy)
{
	struct cn_edge_set *edge_set = (struct cn_edge_set*)bus_set->priv;
	if (bus_set->ops == NULL) {
		return 1;
	}
	if (bus_set->ops->core_type_switch(edge_set, policy)) {
		return 1;
	}
	return 0;
}

size_t cn_bus_dma_cfg(struct cn_bus_set *bus_set, struct transfer_s *t,
	struct dma_config_t *cfg)
{
	return bus_set->ops->dma_cfg(t, cfg, bus_set->priv);
}

size_t cn_bus_dma_remote(struct cn_bus_set *bus_set, struct transfer_s *t,
	struct task_struct *tsk, struct mm_struct *tsk_mm)
{
	return bus_set->ops->dma_remote(t, tsk, tsk_mm, bus_set->priv);
}

size_t cn_bus_dma_async(struct cn_bus_set *bus_set, struct transfer_s *t,
	struct dma_async_info_s **async_info)
{
	return bus_set->ops->dma_async(t, async_info, bus_set->priv);
}

int cn_bus_dma_memset_async(struct cn_bus_set *bus_set, struct memset_s *t,
	struct dma_async_info_s **async_info)
{
	return bus_set->ops->dma_memset_async(t, async_info, bus_set->priv);
}

size_t cn_bus_dma_kernel(struct cn_bus_set *bus_set, unsigned long host_addr,
	u64 device_addr, size_t count, DMA_DIR_TYPE direction)
{
	return bus_set->ops->dma_kernel(host_addr, device_addr,
		count, direction, bus_set->priv);
}

size_t cn_bus_dma_kernel_cfg(struct cn_bus_set *bus_set, unsigned long host_addr,
	u64 device_addr, size_t count,
	DMA_DIR_TYPE direction, struct dma_config_t *cfg)
{
	return bus_set->ops->dma_kernel_cfg(host_addr, device_addr,
		count, direction, cfg, bus_set->priv);
}

size_t cn_bus_boot_image(struct cn_bus_set *bus_set, unsigned long host_addr,
	u64 device_addr, size_t	count)
{
	return bus_set->ops->boot_image(host_addr, device_addr,
				count, bus_set->priv);
}

size_t cn_bus_check_image(struct cn_bus_set *bus_set, unsigned char *host_data,
	u64 device_addr, size_t count)
{
	return bus_set->ops->check_image(host_data, device_addr, count, bus_set->priv);
}

int cn_bus_dma_bypass_smmu_all(struct cn_bus_set *bus_set, bool en)
{
	if (!bus_set->ops->dma_bypass_smmu_all)
		return 0;

	return bus_set->ops->dma_bypass_smmu_all(bus_set->priv, en);
}

size_t cn_bus_dma_p2p(struct cn_bus_set *bus_set, struct peer_s *peer)
{
	struct cn_bus_set *src_bus_set = (struct cn_bus_set *)peer->src_bus_set;
	struct cn_bus_set *dst_bus_set = (struct cn_bus_set *)peer->dst_bus_set;

	if (!src_bus_set || !dst_bus_set) {
		cn_dev_core_err(bus_set->core, "src or dst is null");
		return -EINVAL;
	}

	if (cn_core_is_vf(src_bus_set->core) || cn_core_is_vf(dst_bus_set->core)) {
		cn_dev_core_err(bus_set->core, "vf not support p2p");
		return -EPERM;
	}

	return bus_set->ops->dma_p2p(peer);
}

size_t cn_bus_dma_p2p_async(struct cn_bus_set *bus_set, struct peer_s *peer,
	struct dma_async_info_s **async_info)
{
	struct cn_bus_set *src_bus_set = (struct cn_bus_set *)peer->src_bus_set;
	struct cn_bus_set *dst_bus_set = (struct cn_bus_set *)peer->dst_bus_set;

	if (!src_bus_set || !dst_bus_set) {
		cn_dev_core_err(bus_set->core, "src or dst is null");
		return -EINVAL;
	}

	if (cn_core_is_vf(src_bus_set->core) || cn_core_is_vf(dst_bus_set->core)) {
		cn_dev_core_err(bus_set->core, "vf not support p2p");
		return -EPERM;
	}

	return bus_set->ops->dma_p2p_async(peer, async_info, bus_set->priv);
}

int cn_bus_dma_abort(struct cn_bus_set *bus_set, u64 tags, u64 index)
{
	return bus_set->ops->dma_abort(tags, index, bus_set->priv);
}

int cn_bus_dma_async_message_process(struct cn_bus_set *bus_set, void *message)
{
	if (!bus_set->ops->dma_async_message_process)
		return -1;

	return bus_set->ops->dma_async_message_process(bus_set->priv,
			(struct arm_trigger_message *)message);
}

int cn_bus_dma_af_ctrl(struct cn_bus_set *bus_set, unsigned int enable)
{
	if (!bus_set->ops->dma_af_ctrl)
		return 0;

	return bus_set->ops->dma_af_ctrl(bus_set->priv, enable);
}

int cn_bus_dma_des_set(struct cn_bus_set *bus_set, unsigned int enable)
{
	if (!bus_set->ops->dma_des_set)
		return 0;

	return bus_set->ops->dma_des_set(bus_set->priv, enable);
}

int cn_bus_force_p2p_xchg(struct cn_bus_set *bus_set, int force)
{
	if (!bus_set->ops->force_p2p_xchg)
		return 0;

	return bus_set->ops->force_p2p_xchg(bus_set->priv, force);
}

int cn_bus_mlu_mem_client_init(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->mlu_mem_client_init)
		return -1;

	return bus_set->ops->mlu_mem_client_init(bus_set->priv);
}

u32 cn_bus_get_p2p_exchg_cnt(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->get_p2p_exchg_cnt)
		return 0;

	return bus_set->ops->get_p2p_exchg_cnt(bus_set->priv);
}

int cn_bus_dma_p2p_able(struct cn_bus_set *bus_set_src, struct cn_bus_set *bus_set_dst)
{
	if (cn_core_is_vf(bus_set_src->core) || cn_core_is_vf(bus_set_dst->core))
		return P2P_HOST_TRANSFER;

	return bus_set_src->ops->dma_p2p_able(bus_set_src->priv, bus_set_dst->priv);
}

void cn_bus_get_p2p_able_info(struct cn_bus_set *bus_set, struct p2p_stat *able, int *index)
{
	if (!bus_set->ops->get_p2p_able_info)
		return;

	bus_set->ops->get_p2p_able_info(bus_set->priv, able, index);
}

int cn_bus_get_p2pshm_info(struct cn_bus_set *bus_set, struct p2pshm_attr *attr)
{
	if (!bus_set->ops->get_p2pshm_info)
		return -1;

	return bus_set->ops->get_p2pshm_info(bus_set->priv, attr);
}

int cn_bus_tcdp_link_on_able(struct cn_bus_set *bus_set_src, struct cn_bus_set *bus_set_dst)
{
	return bus_set_src->ops->tcdp_link_on_able(bus_set_src->priv, bus_set_dst->priv);
}

int cn_bus_dma_memset(struct cn_bus_set *bus_set, struct memset_s *t)
{
	return bus_set->ops->dma_memset(bus_set->priv, t);
}

int cn_bus_copy_to_usr_fromio(u64 dst, u64 src, size_t size, struct cn_bus_set *bus_set)
{
	return bus_set->ops->copy_to_usr_fromio(dst, src, size, bus_set->priv);
}

int cn_bus_copy_from_usr_toio(u64 dst, u64 src, size_t size, struct cn_bus_set *bus_set)
{
	return bus_set->ops->copy_from_usr_toio(dst, src, size, bus_set->priv);
}

void reg_write32(void *bus_set, unsigned long offset, unsigned int val)
{
	struct cn_bus_set *p = (struct cn_bus_set *)bus_set;

	return p->ops->reg_write32(p->priv, offset, val);
}

unsigned int reg_read32(void *bus_set, unsigned long offset)
{
	struct cn_bus_set *p = (struct cn_bus_set *)bus_set;

	return p->ops->reg_read32(p->priv, offset);
}

void mem_write32(void *bus_set, unsigned long offset, unsigned int val)
{
	struct cn_bus_set *p = (struct cn_bus_set *)bus_set;

	return p->ops->mem_write32(p->priv, offset, val);
}

u32 mem_read32(void *bus_set, unsigned long offset)
{
	struct cn_bus_set *p = (struct cn_bus_set *)bus_set;

	return p->ops->mem_read32(p->priv, offset);
}

int cn_bus_bar_copy_h2d(struct cn_bus_set *bus_set, u64 d_addr, unsigned long h_addr, size_t len)
{
	return bus_set->ops->bar_copy_h2d(bus_set->priv, d_addr, h_addr, len);
}

int cn_bus_bar_copy_d2h(struct cn_bus_set *bus_set, u64 d_addr, unsigned long h_addr, size_t len)
{
	return bus_set->ops->bar_copy_d2h(bus_set->priv, d_addr, h_addr, len);
}

void cn_bus_mb(struct cn_bus_set *bus_set)
{
	bus_set->ops->mem_mb(bus_set->priv);
}

int cn_bus_check_available(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->check_available)
		return 0;

	return bus_set->ops->check_available(bus_set->priv);
}

int cn_bus_get_mem_cnt(struct cn_bus_set *bus_set)
{
	return bus_set->ops->get_mem_cnt(bus_set->priv);
}

size_t cn_bus_get_mem_size(struct cn_bus_set *bus_set, int index)
{
	return bus_set->ops->get_mem_size(bus_set->priv, index);
}

void *cn_bus_get_mem_base(struct cn_bus_set *bus_set, int index)
{
	return bus_set->ops->get_mem_base(bus_set->priv, index);
}

unsigned long cn_bus_get_mem_phyaddr(struct cn_bus_set *bus_set, int index)
{
	return bus_set->ops->get_mem_phyaddr(bus_set->priv, index);
}

unsigned long cn_bus_get_mem_virtaddr(struct cn_bus_set *bus_set, int index)
{
	if (!bus_set->ops->get_mem_virtaddr)
		return 0;

	return bus_set->ops->get_mem_virtaddr(bus_set->priv, index);
}

CN_MEM_TYPE cn_bus_get_mem_type(struct cn_bus_set *bus_set, int index)
{
	return bus_set->ops->get_mem_type(bus_set->priv, index);
}

u64 cn_bus_get_device_addr(struct cn_bus_set *bus_set, int index)
{
	return bus_set->ops->get_device_addr(bus_set->priv, index);
}

unsigned long cn_bus_get_reg_size(struct cn_bus_set *bus_set)
{
	return bus_set->ops->get_reg_size(bus_set->priv);
}

void *cn_bus_get_reg_base(struct cn_bus_set *bus_set)
{
	return bus_set->ops->get_reg_base(bus_set->priv);
}

unsigned long cn_bus_get_reg_phyaddr(struct cn_bus_set *bus_set)
{
	return bus_set->ops->get_reg_phyaddr(bus_set->priv);
}

int cn_bus_soft_reset(struct cn_bus_set *bus_set, bool reset)
{
	if (!bus_set->ops->soft_reset)
		return 0;

	return bus_set->ops->soft_reset(bus_set->priv, reset);
}

int cn_bus_set_cspeed(unsigned int cspeed, struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->set_cspeed)
		return 0;

	return bus_set->ops->set_cspeed(cspeed, bus_set->priv);
}

int cn_bus_enable_irq(struct cn_bus_set *bus_set, int irq_hw)
{
	return bus_set->ops->enable_irq(irq_hw, bus_set->priv);
}

int cn_bus_disable_irq(struct cn_bus_set *bus_set, int irq_hw)
{
	return bus_set->ops->disable_irq(irq_hw, bus_set->priv);
}

int cn_bus_disable_all_irqs(struct cn_bus_set *bus_set)
{
	bus_set->ops->disable_all_irqs(bus_set->priv);

	return 0;
}

int cn_bus_register_interrupt(
		struct cn_bus_set *bus_set, int irq_hw, interrupt_cb_t handler, void *data)
{
	return bus_set->ops->register_interrupt(irq_hw,
				handler, data, bus_set->priv);
}

void cn_bus_unregister_interrupt(struct cn_bus_set *bus_set, int irq_hw)
{
	return bus_set->ops->unregister_interrupt(irq_hw, bus_set->priv);
}

int cn_bus_get_irq_by_desc(struct cn_bus_set *bus_set, char *irq_desc)
{
	if (!bus_set->ops->get_irq_by_desc)
		return -1;

	return bus_set->ops->get_irq_by_desc(bus_set->priv, irq_desc);
}

void cn_bus_show_info(struct cn_bus_set *bus_set)
{
	return bus_set->ops->show_info(bus_set->priv);
}

void cn_bus_debug_dump_reg(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->debug_dump_reg)
		bus_set->ops->debug_dump_reg(bus_set->priv);
}

struct device *cn_bus_get_dev(struct cn_bus_set *bus_set)
{
	return bus_set->ops->get_dev(bus_set->priv);
}

struct device *cn_bus_get_vf_dev(struct cn_bus_set *bus_set, int vf_idx)
{
	if (!bus_set->ops->get_vf_dev)
		return NULL;

	return bus_set->ops->get_vf_dev(bus_set->priv, vf_idx);
}

int cn_bus_get_dma_info(struct cn_bus_set *bus_set, struct dma_info_s *dma_info)
{
	return bus_set->ops->get_dma_info(bus_set->priv, dma_info);
}

int cn_bus_get_bar_info(struct cn_bus_set *bus_set, struct bar_info_s *bar_info)
{
	return bus_set->ops->get_bar_info(bus_set->priv, bar_info);
}

int cn_bus_get_int_occur_info(struct cn_bus_set *bus_set, struct int_occur_info_s *int_occur_info)
{
	if (!bus_set->ops->interrupt_info)
		return 0;

	return bus_set->ops->interrupt_info(bus_set->priv, int_occur_info);
}

int cn_bus_set_dma_err_inject_flag(struct cn_bus_set *bus_set, int data)
{
	if (!bus_set->ops->set_dma_err_inject_flag)
		return 0;

	return bus_set->ops->set_dma_err_inject_flag(bus_set->priv, data);
}

int cn_bus_get_inbound_cnt(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->inbound_cnt)
		return 0;

	return bus_set->ops->inbound_cnt(bus_set->priv);
}

u32 cn_bus_get_outbound_size(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->outbound_size)
		return 0;

	return bus_set->ops->outbound_size(bus_set->priv);
}

struct page *cn_bus_get_outbound_pages(struct cn_bus_set *bus_set, int index)
{
	if (!bus_set->ops->get_outbound_pages)
		return NULL;

	return bus_set->ops->get_outbound_pages(bus_set->priv, index);
}

int cn_bus_outbound_able(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->outbound_able)
		return 0;

	return bus_set->ops->outbound_able(bus_set->priv);
}

int cn_bus_pcie_sram_able(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->pcie_sram_able)
		return 0;

	return bus_set->ops->pcie_sram_able(bus_set->priv);
}

int cn_bus_sync_write_able(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->sync_write_able)
		return 0;

	return bus_set->ops->sync_write_able(bus_set->priv);
}

int cn_bus_get_dob_iova(struct cn_bus_set *bus_set_src, struct cn_bus_set *bus_set_dst,
				u64 dob_pa, size_t size, struct sg_table **iova_sgt)
{
	if (!bus_set_src->ops->get_dob_iova)
		return -1;

	return bus_set_src->ops->get_dob_iova(bus_set_src->priv, bus_set_dst->priv,
				dob_pa, size, iova_sgt);
}

void cn_bus_put_dob_iova(struct cn_bus_set *bus_set_dst, struct sg_table **iova_sgt)
{
	if (!bus_set_dst->ops->put_dob_iova)
		return;

	bus_set_dst->ops->put_dob_iova(bus_set_dst->priv, iova_sgt);
}

int cn_bus_get_dob_win_info(struct cn_bus_set *bus_set,
				int *lvl1_pg, int *lvl1_pg_cnt, u64 *lvl1_base,
				int *lvl2_pg, int *lvl2_pg_cnt, u64 *lvl2_base)
{
	if (!bus_set->ops->get_dob_win_info)
		return -1;

	return bus_set->ops->get_dob_win_info(bus_set->priv, lvl1_pg, lvl1_pg_cnt, lvl1_base,
						lvl2_pg, lvl2_pg_cnt, lvl2_base);
}

void *cn_bus_dob_win_alloc(struct cn_bus_set *bus_set, u64 device_addr, size_t size)
{
	if (!bus_set->ops->dob_win_alloc)
		return NULL;

	return bus_set->ops->dob_win_alloc(bus_set->priv, device_addr, size);
}

void cn_bus_dob_win_free(struct cn_bus_set *bus_set, u64 device_addr)
{
	if (!bus_set->ops->dob_win_free)
		return;

	bus_set->ops->dob_win_free(bus_set->priv, device_addr);
}

u32 cn_bus_get_non_align_cnt(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->non_align_cnt)
		return 0;

	return bus_set->ops->non_align_cnt(bus_set->priv);
}

u32 cn_bus_get_heartbeat_cnt(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->heartbeat_cnt)
		return 0;

	return bus_set->ops->heartbeat_cnt(bus_set->priv);
}

u32 cn_bus_get_soft_retry_cnt(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->soft_retry_cnt)
		return 0;

	return bus_set->ops->soft_retry_cnt(bus_set->priv);
}

int cn_bus_get_async_proc_info(struct cn_bus_set *bus_set, struct async_proc_info_s *async_proc_info)
{
	if (!bus_set->ops->get_async_proc_info)
		return -1;

	return bus_set->ops->get_async_proc_info(bus_set->priv, async_proc_info);
}

int cn_bus_get_dma_channel_info(struct cn_bus_set *bus_set, struct dma_channel_info_s *dma_channel_info)
{
	if (!bus_set->ops->get_dma_channel_info)
		return -1;

	return bus_set->ops->get_dma_channel_info(bus_set->priv, dma_channel_info);
}

int cn_bus_dump_dma_info(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->dump_dma_info)
		return -1;

	return bus_set->ops->dump_dma_info(bus_set->priv);
}

int cn_bus_get_async_htable(struct cn_bus_set *bus_set)
{
	return bus_set->ops->get_async_htable(bus_set->priv);
}

int cn_bus_get_bus_info(struct cn_bus_set *bus_set, struct bus_info_s *bus_info)
{
	return bus_set->ops->get_bus_info(bus_set->priv, bus_info);
}

int cn_bus_get_isr_type(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->get_isr_type)
		return -1;

	return bus_set->ops->get_isr_type(bus_set->priv);
}

int cn_bus_get_pcie_fw_info(struct cn_bus_set *bus_set, u64 *pcie_fw_info)
{
	if (!bus_set->ops->get_pcie_fw_info)
		return 0;

	return bus_set->ops->get_pcie_fw_info(bus_set->priv, pcie_fw_info);
}

int cn_bus_get_lnkcap(struct cn_bus_set *bus_set, struct bus_lnkcap_info *lnk_info)
{
	return bus_set->ops->get_bus_lnkcap(bus_set->priv, lnk_info);
}

int cn_bus_get_curlnk(struct cn_bus_set *bus_set, struct bus_lnkcap_info *lnk_info)
{
	return bus_set->ops->get_bus_curlnk(bus_set->priv, lnk_info);
}

int cn_bus_get_vf_idx(struct cn_bus_set *pf_bus_set, struct cn_bus_set *vf_bus_set)
{
	return pf_bus_set->ops->get_vf_idx(pf_bus_set->priv, vf_bus_set->priv);
}

/* get pf host bdf */
u32 cn_bus_get_bdf(struct cn_bus_set *bus_set)
{
	return bus_set->ops->get_bus_bdf(bus_set->priv);
}

/* get bdf in current environment, it is different from pf host bdf in qemu virtual machine*/
u32 cn_bus_get_current_bdf(struct cn_bus_set *bus_set)
{
	return bus_set->ops->get_current_bdf(bus_set->priv);
}

/* check the pdev's status, if is_virfn, return 1, else return 0 */
bool cn_bus_check_pdev_virtfn(struct cn_bus_set *bus_set)
{
	return bus_set->ops->check_pdev_virtfn(bus_set->priv);
}

/* return 1 if support, other is un-support */
int cn_bus_get_pcie_atomicop_support(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->get_pcie_atomicop_support)
		return -EFAULT;

	return bus_set->ops->get_pcie_atomicop_support(bus_set->priv);
}

int cn_bus_get_pcie_atomicop_info(struct cn_bus_set *bus_set, struct pcie_atomicop_info_s *info)
{
	if (!bus_set->ops->get_pcie_atomicop_info)
		return -1;

	return bus_set->ops->get_pcie_atomicop_info(bus_set->priv, info);
}

int cn_bus_get_linear_bar_offset(struct cn_bus_set *bus_set, u64 *offset)
{
	if (!bus_set->ops->get_linear_bar_offset)
		return -1;

	*offset = bus_set->ops->get_linear_bar_offset(bus_set->priv);
	return 0;
}

u32 cn_bus_get_device_ko_bootinfo(struct cn_bus_set *bus_set)
{
	if (!bus_set->ops->get_device_ko_bootinfo)
		return -1;

	return bus_set->ops->get_device_ko_bootinfo(bus_set->priv);
}

int cn_bus_set_bdf(struct cn_bus_set *bus_set, u32 bdf)
{
	return bus_set->ops->set_bus_bdf(bus_set->priv, bdf);
}

int cn_bus_set_stru_init(struct cn_core_set *core)
{
	int ret;
	struct cn_bus_set *bus_set = core->bus_set;
	void *priv = bus_set->priv;

	ret = bus_set->pre_init(priv);
	if (ret)
		return -1;

	bus_set->core = core;
	if (bus_set->ops->set_bus)
		ret = bus_set->ops->set_bus(priv, bus_set);

	return ret;
}

void cn_bus_set_stru_exit(struct cn_core_set *core)
{
	struct cn_bus_set *bus_set = core->bus_set;
	void *priv = bus_set->priv;

	bus_set->pre_exit(priv);
	bus_set->core = NULL;
}

int cn_bus_sync_write_alloc(struct cn_bus_set *bus_set, u64 flag_dev_pa)
{
	if (!bus_set->ops->sync_write_alloc)
		return 0;

	return bus_set->ops->sync_write_alloc(bus_set->priv, flag_dev_pa);
}

void cn_bus_sync_write_free(struct cn_bus_set *bus_set, u64 flag_dev_pa)
{
	if (bus_set->ops->sync_write_free)
		bus_set->ops->sync_write_free(bus_set->priv, flag_dev_pa);
}

void cn_bus_sync_write_val(struct cn_bus_set *bus_set, u64 dev_pa, u32 val)
{
	if (bus_set->ops->sync_write_trigger)
		bus_set->ops->sync_write_trigger(bus_set->priv, dev_pa, val);
}

void cn_bus_sync_write_info(struct cn_bus_set *bus_set, struct sync_write_info *sw_info)
{
	if (bus_set->ops->sync_write_info)
		bus_set->ops->sync_write_info(bus_set->priv, sw_info);
}

void cn_bus_tcdp_qp0_wrhost_enable(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->tcdp_qp0_wrhost_enable)
		bus_set->ops->tcdp_qp0_wrhost_enable(bus_set->priv);
}

void cn_bus_tcdp_qp0_wrhost_disable(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->tcdp_qp0_wrhost_disable)
		bus_set->ops->tcdp_qp0_wrhost_disable(bus_set->priv);
}

int cn_bus_get_tcdp_able(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->get_tcdp_able == NULL)
		return 0;

	return bus_set->ops->get_tcdp_able(bus_set->priv);
}

/*
 * rcard_id: for the remote card id who occupy some channel
 * dir: RX or TX or all b'1 means selected
 * state: ON/OFF
 */
int cn_bus_tcdp_change_channel_state(struct cn_bus_set *bus_set,
	int rcard_id, int dir, int state)
{
	if (bus_set->ops->tcdp_change_channel_state == NULL)
		return 0;

	return bus_set->ops->tcdp_change_channel_state(bus_set->priv,
			rcard_id, dir, state);
}

u64 cn_bus_get_tcdp_host_buff(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->get_tcdp_host_buff == NULL)
		return 0;

	return bus_set->ops->get_tcdp_host_buff(bus_set->priv);
}

u64 cn_bus_get_tcdp_win_base(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->get_tcdp_win_base == NULL)
		return 0;

	return bus_set->ops->get_tcdp_win_base(bus_set->priv);
}

u64 cn_bus_get_tcdp_win_size(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->get_tcdp_win_size == NULL)
		return 0;

	return bus_set->ops->get_tcdp_win_size(bus_set->priv);
}

u64 cn_bus_get_linear_bar_bus_base(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->get_linear_bar_bus_base == NULL)
		return 0;

	return bus_set->ops->get_linear_bar_bus_base(bus_set->priv);
}

u64 cn_bus_get_linear_bar_phy_base(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->get_linear_bar_phy_base == NULL)
		return 0;

	return bus_set->ops->get_linear_bar_phy_base(bus_set->priv);
}

u64 cn_bus_linear_bar_do_iommu_remap(struct cn_bus_set *bus_set_src,
		struct cn_bus_set *bus_set_dst, int card_id, int rcard_id)
{
	if (bus_set_src->ops->linear_bar_do_iommu_remap == NULL)
		return 0;

	return bus_set_src->ops->linear_bar_do_iommu_remap(bus_set_src->priv,
				bus_set_dst->priv, card_id, rcard_id);
}

u64 cn_bus_tcdp_win_base_do_iommu_remap(struct cn_bus_set *bus_set_src,
		struct cn_bus_set *bus_set_dst, int card_id, int rcard_id)
{
	if (bus_set_src->ops->tcdp_win_base_do_iommu_remap == NULL)
		return 0;

	return bus_set_src->ops->tcdp_win_base_do_iommu_remap(bus_set_src->priv,
				bus_set_dst->priv, card_id, rcard_id);
}

u64 cn_bus_get_linear_bar_axi_base(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->get_linear_bar_axi_base == NULL)
		return 0;

	return bus_set->ops->get_linear_bar_axi_base(bus_set->priv);
}

u64 cn_bus_get_linear_bar_size(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->get_linear_bar_size == NULL)
		return 0;

	return bus_set->ops->get_linear_bar_size(bus_set->priv);
}

int cn_bus_tcdp_tx_dir_linear_bar_cfg(struct cn_bus_set *bus_set,
						int tx_card, int rx_card,
						u64 rx_liner_bar_bus_base,
						u64 rx_liner_bar_axi_base,
						u64 rx_liner_bar_size)
{
	if (bus_set->ops->tcdp_tx_dir_linear_bar_cfg == NULL)
		return 0;

	return bus_set->ops->tcdp_tx_dir_linear_bar_cfg(bus_set->priv,
						tx_card, rx_card,
						rx_liner_bar_bus_base,
						rx_liner_bar_axi_base,
						rx_liner_bar_size);
}

int cn_bus_tcdp_txrx_indir_cfg(struct cn_bus_set *bus_set,
					int tx_card, int rx_card,
					u64 rx_tcdp_win_bus_base)
{
	if (bus_set->ops->tcdp_txrx_indir_cfg == NULL)
		return 0;

	return bus_set->ops->tcdp_txrx_indir_cfg(bus_set->priv,
						tx_card, rx_card,
						rx_tcdp_win_bus_base);
}

/* add for MIM */
int cn_bus_probe_mi(struct cn_bus_set *bus_set, int domain_id)
{
	if (bus_set->ops->probe_mi == NULL)
		return -1;

	return bus_set->ops->probe_mi(bus_set->priv, domain_id);
}

int cn_bus_remove_mi(struct cn_bus_set *bus_set, int domain_id)
{
	if (bus_set->ops->remove_mi == NULL)
		return -1;

	return bus_set->ops->remove_mi(bus_set->priv, domain_id);
}

#ifdef CONFIG_CNDRV_MNT
typedef	int (*report_fn_t)(void *data,
			unsigned long action, void *fp);
extern struct cn_report_block *cn_register_report(struct cn_core_set *core, char *name,
						int prio, report_fn_t fn, void *data);
extern int cn_unregister_report(struct cn_core_set *core, struct cn_report_block *nb);
#endif
int cn_bus_init(struct cn_core_set *core)
{
	int ret = 0;
	struct cn_bus_set *bus_set = core->bus_set;

	bus_set->core = core;
	if (bus_set->ops->post_init)
		ret = bus_set->ops->post_init(bus_set->priv, core->bus_set);/*cn_pci_init*/

#ifdef CONFIG_CNDRV_MNT
	bus_set->bus_report = cn_register_report(core, "bus_debug_report", 0, cn_bus_get_bug_report, core);
#endif
	return ret;
}

void cn_bus_exit(struct cn_core_set *core)
{
	struct cn_bus_set *bus_set = core->bus_set;

	if (bus_set->ops->post_exit)
		bus_set->ops->post_exit(bus_set->priv);/*cn_pci_exit_cb*/

#ifdef CONFIG_CNDRV_MNT
	 cn_unregister_report(core, bus_set->bus_report);
#endif
}

int cn_bus_late_init(struct cn_core_set *core)
{
	int ret = 0;
	struct cn_bus_set *bus_set = (struct cn_bus_set *)core->bus_set;

	if (bus_set->ops->late_init) {
		ret = bus_set->ops->late_init(bus_set->priv);
	}

	return ret;
}

void cn_bus_late_exit(struct cn_core_set *core)
{
	struct cn_bus_set *bus_set = (struct cn_bus_set *)core->bus_set;

	if (bus_set->ops->late_exit) {
		bus_set->ops->late_exit(bus_set->priv);
	}
}

int ib_state;

#ifdef CONFIG_CNDRV_PCIE
extern int cn_pci_drv_init_mlu220_mlu270(void);
extern int cn_pci_drv_init_mlu290_ce3226(void);
extern int cn_pci_drv_init_mlu370_pigeon(void);
extern int cn_pci_drv_init_mlu500(void);
extern void cn_pci_drv_exit_mlu220_mlu270(void);
extern void cn_pci_drv_exit_mlu290_ce3226(void);
extern void cn_pci_drv_exit_mlu370_pigeon(void);
extern void cn_pci_drv_exit_mlu500(void);
#else
static inline int cn_pci_drv_init_mlu220_mlu270(void)
{
	return 0;
}
static inline int cn_pci_drv_init_mlu290_ce3226(void)
{
	return 0;
}
static inline int cn_pci_drv_init_mlu370_pigeon(void)
{
	return 0;
}
static inline int cn_pci_drv_init_mlu500(void)
{
	return 0;
}
static inline void cn_pci_drv_exit_mlu220_mlu270(void){}
static inline void cn_pci_drv_exit_mlu290_ce3226(void){}
static inline void cn_pci_drv_exit_mlu370_pigeon(void){}
static inline void cn_pci_drv_exit_mlu500(void){}
#endif

extern struct cn_bus_driver bus_driver;

int cn_bus_driver_reg(void)
{
	int ret;

	if (IS_ERR_OR_NULL(&bus_driver))
		return -EFAULT;

	ret = cn_pci_drv_init_mlu220_mlu270();
	if (ret)
		return 0;

	ret = cn_pci_drv_init_mlu290_ce3226();
	if (ret)
		return 0;

	ret = cn_pci_drv_init_mlu370_pigeon();
	if (ret)
		return 0;

	ret = cn_pci_drv_init_mlu500();
	if (ret)
		return 0;

	cn_edge_drv_init();
	return 0;
}

void cn_bus_driver_unreg(void)
{
	cn_pci_drv_exit_mlu220_mlu270();
	cn_pci_drv_exit_mlu290_ce3226();
	cn_pci_drv_exit_mlu370_pigeon();
	cn_pci_drv_exit_mlu500();
	cn_edge_drv_exit();
}

struct cn_bus_set
*cn_bus_set_init(void *priv, struct device *dev,
		struct bus_ops *ops, int (*setup)(void *priv),
		int (*pre_init)(void *priv), int (*pre_exit)(void *priv),
		int (*get_resource)(void *priv, struct domain_resource *get_resource))
{
	struct cn_bus_set *new;

	new = devm_kzalloc(dev, sizeof(*new), GFP_KERNEL);
	if (!new)
		return NULL;

	new->priv = priv;
	new->ops = ops;
	new->setup = setup;
	new->pre_init = pre_init;
	new->pre_exit = pre_exit;
	new->get_resource = get_resource;
	new->heartbeat_thread = NULL;
	new->thread_exit = true;

	return new;
}

void cn_bus_set_exit(struct cn_bus_set *bus_set, struct device *dev)
{
	devm_kfree(dev, bus_set);
}

int cn_bus_probe(struct cn_bus_set *bus_set,
			u64 device_id, u8 type, int idx)
{
	int ret = 0;
	void *priv = bus_set->priv;

	ret = bus_set->setup(priv);
	if (ret)
		return -1;

	cn_dm_host_early_init(bus_set, device_id);

	ret = bus_driver.probe(bus_set, device_id, type, idx);
	if (ret == 0)
		heartbeat_thread_init(bus_set->core);

	return ret;
}

int cn_bus_remove(struct cn_bus_set *bus_set, u64 device_id)
{
	heartbeat_thread_exit(bus_set->core);
	bus_driver.remove(bus_set->core);
	cn_dm_host_early_exit(bus_set, device_id);

	return 0;
}

void cn_bus_shutdown(struct cn_bus_set *bus_set)
{
	bus_driver.shutdown(bus_set->core);
}

int cn_bus_suspend(struct cn_bus_set *bus_set, u64 state)
{
	return bus_driver.suspend(bus_set->core, state);
}

int  cn_bus_resume(struct cn_bus_set *bus_set)
{
	return bus_driver.resume(bus_set->core);
}
u64 get_host_ns_time(void)
{
	u64 time;
#if (KERNEL_VERSION(3, 17, 0) > LINUX_VERSION_CODE)
	struct timespec tp;

	ktime_get_ts(&tp);
	time = timespec_to_ns(&tp);
#else
	time = ktime_get_ns();
#endif

	return time;
}

struct cn_core_set *cn_bus_get_core_set_via_card_id(int card_id)
{
	return cn_core_get_with_idx(card_id);
}

/*
 * bus debug report call back entry
 * data : core
 * action : optional
 * fp : report file handle
 */
#ifdef CONFIG_CNDRV_MNT
int cn_bus_get_bug_report(void *data, unsigned long action, void *fp)
{
	struct cn_core_set *core = (struct cn_core_set *)data;
	struct cn_bus_set *bus_set = core->bus_set;

	if (bus_set->ops->get_bug_report == NULL)
		return 0;

	return bus_set->ops->get_bug_report(bus_set->priv, action, fp);
}
#endif

int cn_bus_pll_irq_sts_dump(struct cn_bus_set *bus_set)
{
	if (bus_set->ops->pll_irq_sts_dump == NULL)
		return 0;

	return bus_set->ops->pll_irq_sts_dump(bus_set->priv);
}
