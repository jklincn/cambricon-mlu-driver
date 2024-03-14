#include <linux/types.h>
#include <linux/string.h>
#include "include/domain.h"
#include "cndrv_bus.h"
#include "domain_private.h"
#include "internal_interface.h"
#include "cndrv_domain.h"

s32 get_res_unrealized(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	print_err("some one get host res which is unrealized\n");
	return 0;
}

s32 get_mem_cache_size(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	struct resource_cache *rc;

	rc = target_domain->resource_cache;
	*val = rc->cache_size;
	print_debug("0x%llx\n", *val);
	if (*val == 0)
		print_warn("func<%d> 0x%llx\n", target_domain->func_id, *val);

	return 0;
}

s32 get_mem_bus_width(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	struct resource_cache *rc;

	rc = target_domain->resource_cache;
	*val = rc->bus_width;
	print_debug("0x%llx\n", *val);
	if (*val == 0)
		print_warn("func<%d> 0x%llx\n", target_domain->func_id, *val);

	return 0;
}

s32 get_pci_ob_host_addr(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	*val = (u64)target_domain->pci.data->shms[OUT_BOUND_HOST].bs;
	return 0;
}

s32 get_pci_ob_axi_addr(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	*val = (u64)target_domain->pci.data->shms[OUT_BOUND_AXI].bs;
	return 0;
}

s32 get_pci_ob_sz(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	*val = (u64)target_domain->pci.data->shms[OUT_BOUND_HOST].sz;
	return 0;
}

s32 get_pci_bar_shm_sz(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	*val = cn_dm_pci_get_bars_shm_sz((const void *)domain, res_offset);
	return 0;
}

s32 get_pci_dma_ch(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	*val = cn_dm_pci_get_dma_ch((const void *)domain);
	return 0;
}

s32 get_pci_bar_reg_total_sz(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	*val = cn_dm_pci_get_bars_reg_total_sz((const void *)domain, res_offset);
	return 0;
}

s32 get_pci_sram_pa(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	*val = (u64)target_domain->pci.data->sram.pa;
	return 0;
}

s32 get_pci_sram_sz(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	*val = (u64)target_domain->pci.data->sram.sz;
	return 0;
}

s32 get_pci_large_bar_bs(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	*val = (u64)target_domain->pci.data->large_bar.bs;
	return 0;
}

s32 get_pci_large_bar_sz(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{
	*val = (u64)target_domain->pci.data->large_bar.sz;
	return 0;
}

s32 get_mem_cfg_phys_card_idx(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{

	*val = (u64)target_domain->pci.data->mem_cfg.phys_card_idx;

	return 0;
}

s32 get_mem_cfg_size_limit(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain)
{

	*val = (u64)target_domain->pci.data->mem_cfg.size_limit;
	print_info("mem limit coef is 0x%llx\n", *val);

	return 0;
}

s32 set_res_not_allowed(struct domain_type *domain,
				u64 val, s8 res_offset,
				struct domain_type *target_domain)
{
	print_err("some one set host res to 0x%llx by rpc, but not allowed\n",
									val);
	return -1;
}
