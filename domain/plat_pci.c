#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/kthread.h>	//kthread_should_stop
#include <linux/pci.h>
#include <linux/delay.h>        //for msleep
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_commu.h"
#include "cndrv_domain.h"
#include "dmlib/include/domain.h"
#include "cndrv_mm.h"
#include "../../include/cndrv_sbts.h"
#include "../../include/cndrv_mm.h"
#include "../../include/cndrv_mcc.h"
#include "dmlib/domain_private.h"
#include "dmlib/domain_resource_dictionary.h"
#include "binn.h"
#include "cndrv_gdma.h"
#include "cndrv_ipcm.h"
#include "internal_interface.h"

#ifndef OUTBOUND_FIRST
#define OUTBOUND_FIRST             (16)
#endif /* OUTBOUND_FIRST */
#ifndef OUTBOUND_CNT
#define OUTBOUND_CNT               (16)
#endif /* OUTBOUND_CNT */

#define OUTBOUND_FIRST_290_PF      (1)
#define OUTBOUND_FIRST_290_VF      (8)
#define OUTBOUND_CNT_290_PF        (7)
#define OUTBOUND_CNT_290_VF        (1)

#define OUTBOUND_FIRST_370_PF      (0)
#define OUTBOUND_FIRST_370_VF      (8)
#define OUTBOUND_CNT_370_PF        (8)
#define OUTBOUND_CNT_370_VF        (1)
void  __cn_dm_preset_ob_mask(struct cn_bus_set *bus_set,
				struct domain_type *domain, u32 is_sriov)
{
	struct domain_resource resource;
	u32 func_id = -1;
	u64 ob_mask = -1;

	if (!domain || !bus_set || !bus_set->priv)
		return;
	if (bus_set->get_resource(bus_set->priv, &resource))
		return;
	if (resource.id == MLUID_220_EDGE)
		return;
	func_id = domain->func_id;
	ob_mask = resource.ob_mask;
	/*
	 * 0 - 4 for msi in sriov(1 for each function)
	 * 5 - 9 for pf sriov
	 * 10-14 for vf0
	 */
	if (resource.id == MLUID_270
		|| resource.id == MLUID_270V
		|| resource.id == MLUID_270V1) {
		if (dm_is_func_vf(func_id))
			domain->pci.data->ob.mask = (((1UL << 5) - 1) <<
							((func_id + 1) * 5));
		else if (dm_is_func_pf(func_id) && !is_sriov)
			domain->pci.data->ob.mask = ob_mask;
		else if (dm_is_func_pf(func_id) && is_sriov)
			domain->pci.data->ob.mask = (((1UL << 5) - 1) <<
							((func_id + 1) * 5));
		else if (dm_is_func_overall(func_id))
			domain->pci.data->ob.mask = 0xfffffff0;//0xf for msi
	} else if (resource.id == MLUID_290
		|| resource.id == MLUID_290V1) {
		if (dm_is_func_vf(func_id))
			domain->pci.data->ob.mask =
				(((1UL << OUTBOUND_CNT_290_VF) - 1)
				<< (func_id + OUTBOUND_FIRST_290_VF - 1));
		else if (dm_is_func_pf(func_id) && !is_sriov)
			domain->pci.data->ob.mask =
				(((1UL << OUTBOUND_CNT_290_PF) - 1)
					<< OUTBOUND_FIRST_290_PF);
		else if (dm_is_func_pf(func_id) && is_sriov)
			domain->pci.data->ob.mask =
				(((1UL << OUTBOUND_CNT_290_PF) - 1)
					<< OUTBOUND_FIRST_290_PF);
		else if (dm_is_func_overall(func_id))
			domain->pci.data->ob.mask =
				(((1UL << OUTBOUND_CNT_290_PF) - 1)
					<< OUTBOUND_FIRST_290_PF);
	} else if (resource.id == MLUID_370 || resource.id == MLUID_370V) {
		if (dm_is_func_vf(func_id))
			domain->pci.data->ob.mask =
				(((1UL << OUTBOUND_CNT_370_VF) - 1)
				<< (func_id + OUTBOUND_FIRST_370_VF - 1));
		else if (dm_is_func_pf(func_id) && !is_sriov)
			domain->pci.data->ob.mask =
				(((1UL << OUTBOUND_CNT_370_PF) - 1)
				<< OUTBOUND_FIRST_370_PF);
		else if (dm_is_func_pf(func_id) && is_sriov)
			domain->pci.data->ob.mask =
				(((1UL << OUTBOUND_CNT_370_PF) - 1)
				<< OUTBOUND_FIRST_370_PF);
		else if (dm_is_func_overall(func_id))
			domain->pci.data->ob.mask =
				(((1UL << OUTBOUND_CNT_290_PF) - 1)
				<< OUTBOUND_FIRST_370_PF);
	}
}

int dm_bar_pcie2dm(struct cn_bus_set *bus_set,
			struct domain_resource *resource, struct bar_cfg *cfg)
{
	int id;

	id = (resource->id >> 16) & 0xffff;
	print_info("id.device<0x%x>, pcie id<0x%x>\n", id, resource->id);
	if (resource->id == MLUID_270 ||
	    resource->id == MLUID_270V ||
	    resource->id == MLUID_270V1) {
		print_info("\n");
		cfg->va = 0x8000000000ull;
		cfg->pa = 0x4108000000ull;
	} else if (resource->id == MLUID_290 || resource->id == MLUID_290V1) {
		print_info("MLU290 series\n");
		cfg->va = 0x8000000000ull;
		cfg->pa = 0x3808000000ul;
	} else if (resource->id == MLUID_CE3226) {
		print_info("\n");
		cfg->va = 0x8000000000ull;
		cfg->pa = 0x410000000ul;
	} else if (resource->id == MLUID_CE3226_EDGE) {
		print_info("\n");
		/*no use this code,domain owner think also.*/
		cfg->va = 0x8000000000ull;
		cfg->pa = 0x410000000ul;
	} else if (resource->id == MLUID_PIGEON) {
		print_info("\n");
		cfg->va = 0x8000000000ull;
		cfg->pa = 0x10000000ul;
	} else if (resource->id == MLUID_PIGEON_EDGE) {
		print_info("\n");
		/*no use this code,domain owner think also.*/
		cfg->va = 0x8000000000ull;
		cfg->pa = 0x10000000ul;
	} else if (resource->id == MLUID_220) {
		print_info("\n");
		//FIXME: va is difference from C20E_REMAP_BASE_ADDR.
		cfg->va = 0x8000000000ull;
		cfg->pa = 0x1018000000ul;
		//FIXME: 16k is the value 20l(aka: 270). PCIe and memory do not
		//know this valud
	} else if (resource->id == MLUID_220_EDGE) {
		print_info("\n");
		//FIXME: va is difference from C20E_REMAP_BASE_ADDR.
		cfg->va = 0x8000000000ull;
		cfg->pa = 0x1002000000ul;
		//FIXME: 16k is the value 20l(aka: 270). PCIe and memory do not
		//know this valud
	} else if (resource->id == MLUID_370 || resource->id == MLUID_370V) {
		print_info("\n");
		//FIXME: va is difference from C30S_REMAP_BASE_ADDR.
		cfg->va = C30S_AXI_SHM_BASE;
		cfg->pa = C30S_AXI_SHM_PA_BASE;
		//FIXME: 16k is the value 30s(aka: 370). PCIe and memory do not
		//know this valud
	} else if (resource->id == MLUID_365 || resource->id == MLUID_365V) {
		print_info("\n");
		//FIXME: va is difference from C30S_REMAP_BASE_ADDR.
		cfg->va = C30S_AXI_SHM_BASE;
		cfg->pa = C30S_AXI_SHM_PA_BASE;
		//FIXME: 16k is the value 30s(aka: 365). PCIe and memory do not
		//know this valud
	} else if (resource->id == MLUID_590 || resource->id == MLUID_590V) {
		print_info("\n");
		//FIXME: va is difference from C50_REMAP_BASE_ADDR.
		cfg->va = C50_AXI_SHM_BASE;
		cfg->pa = C50_AXI_SHM_PA_BASE;
		//FIXME: 16k is the value 30(aka: 590). PCIe and memory do not
		//know this valud
	} else if (resource->id == MLUID_580 || resource->id == MLUID_580V) {
		print_info("\n");
		//FIXME: va is difference from C50_REMAP_BASE_ADDR.
		cfg->va = C50_AXI_SHM_BASE;
		cfg->pa = C50_AXI_SHM_PA_BASE;
		//FIXME: 16k is the value 30(aka: 585). PCIe and memory do not
		//know this valud
	} else {
		print_err("unsupported device\n");
		return -1;
	}
	cfg->sz = resource->cfg_reg_size + resource->share_mem_size;
	cfg->reg_total_sz = resource->cfg_reg_size;
	cfg->shm_sz = resource->share_mem_size;
	//cfg->shm_va = resource->share_mem_base;
	cfg->reg_sz = KB(16);
	cfg->reg_bs = 0;
	cfg->shm_bs = 0;
	return 0;
}

void setup_domain_work_mode(struct domain_set_type *set,
				struct cn_bus_set *bus_set, struct domain_resource *resource)
{
	struct domain_set_attr *attr = set->attr;
	bool is_pdev_virtfn;
	u32 curr_bdf;

	is_pdev_virtfn = cn_bus_check_pdev_virtfn(bus_set);
	curr_bdf = cn_bus_get_current_bdf(bus_set);

	switch (resource->id) {
	case MLUID_270V:
	case MLUID_270V1:
	case MLUID_290V1:
	case MLUID_370V:
	case MLUID_365V:
	case MLUID_580V:
	case MLUID_590V:
		attr->work_mode = DM_MODE_VF;
		cn_domain_info(set, "Domain work mode DM_MODE_VF");
		break;
	default:
		if (cn_is_mim_en_bdf(curr_bdf, is_pdev_virtfn)) {
			attr->work_mode = DM_MODE_SRIOV;
			cn_domain_info(set, "Domain work mode DM_MODE_SRIOV");
		} else {
			attr->work_mode = DM_MODE_PF;
			cn_domain_info(set, "Domain work mode DM_MODE_PF");
		}
		break;
	}
}

#define MAP_TYPE(x)	(x)
int dm_set_dev_addr_map_type(struct domain_set_type *set)
{
	int map_type[2] = {-1};
	char tmp[COMMU_RPC_SIZE];
	int ret_size;

	memset(tmp, 0, COMMU_RPC_SIZE);
	if (set->core->device_id == MLUID_590 || set->core->device_id == MLUID_580) {
		cn_mcc_get_map_mode(set->core, map_type, map_type + 1);
		if (map_type[0] == -1) {
			return 0;
		}

		if (map_type[0] == MAP_TYPE(1) || map_type[0] == MAP_TYPE(2)) {
			cn_domain_info(set, "set map type:%d, sel_hbm_chl:%d",
							map_type[0], map_type[1]);
			return dm_compat_rpc((void *)set, "dm_set_map_way", map_type,
					sizeof(int) * 2, tmp, &ret_size, sizeof(tmp));
		}
	}

	return 0;
}
