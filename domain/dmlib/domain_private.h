
#ifndef __DOMAIN_PRIVATE_H__
#define __DOMAIN_PRIVATE_H__

#ifndef DM_VERSION
#define DM_VERSION(m,i,r) 1
#endif /* DM_VERSION */

#ifndef DM_HEADER_VERSION_CUR
#define DM_HEADER_VERSION_CUR 1
#endif /* DM_HEADER_VERSION_CUR */

#define DM_VERSION_CUR DM_VERSION(1, 0, 0)

#define DM_ERROR_BASE		(0x400)
#define DM_UNSUPPORTED_VERSION	(DM_ERROR_BASE + 0x100)

#define DM_EXPORT_SYMBOL_GPL(a)

#define DM_NO_PCIE_SYNC (0)

/**
 * Functionality
 * DM_GENERIC_PCIE: get from pcie instead of fix value. Fix value only support
 *     MLU270.
 */
#define DM_GENERIC_PCIE

#define OPS_GET(module, name, return_type, is_state) \
static return_type __dm_##module##_get_##name(const struct module##_cfg *module) \
{									\
	if (!module)							\
		return (return_type)-1;					\
									\
	if (!(module->domain->state & (is_state))) {			\
		print_err("Invalid state<%s:%x> not in <%x>\n",	\
				dm_state2str(module->domain->state),	\
				module->domain->state, (is_state));	\
		return (return_type)-1;					\
	}								\
	if (module->data)						\
		return module->data->name;				\
	else								\
		return (return_type)-1;					\
}

#define PRINT_u64 "%llx"
#define PRINT_u32 "%x"

#define OPS_PRINT_SUB_IDX_type(module, submodule, name, idx, type)	\
{									\
	type val;							\
	if (module->get_##submodule##_##name) {				\
		val = module->get_##submodule##_##name(module, idx);	\
		if ((type)-1 != val) {					\
			print_info("    %s->%s[%d]->%s: 0x"PRINT_##type"\n", #module, #submodule, idx, #name, val);	\
			print_debug("    %s<%px>->%s[%d]->%s: 0x"PRINT_##type"\n", #module, module, #submodule, idx, #name, val);	\
		} else {						\
			print_debug("     Invalid value. Skip\n");	\
		}							\
	}								\
}

#define OPS_PRINT_SUB_u64(module, submodule, name)			\
{									\
	u64 val;							\
	if (module->get_##submodule##_##name) {				\
		val = module->get_##submodule##_##name(module);		\
		if ((u64)-1 != val) {					\
			print_info("    %s->%s->%s: 0x"PRINT_u64"\n", #module, #submodule, #name, val);	\
			print_debug("    %s<%px>->%s->%s: 0x"PRINT_u64"\n", #module, module, #submodule, #name, val);	\
		} else {						\
			print_debug("     Invalid value. Skip\n");	\
		}							\
	}								\
}

#define OPS_PRINT_SUB_u32(module, submodule, name)			\
{									\
	u32 val;							\
	if (module->get_##submodule##_##name) {				\
		val = module->get_##submodule##_##name(module);		\
		if ((u32)-1 != val) {					\
			print_info("    %s->%s->%s: 0x%x\n", #module, #submodule, #name, val);	\
			print_debug("    %s<%px>->%s->%s: 0x%x\n", #module, module, #submodule, #name, val);	\
		} else {						\
			print_debug("     Invalid value. Skip\n");	\
		}							\
	}								\
}

#define OPS_PRINT_u32(module, name) 						\
{										\
	u32 val;								\
	if (module->get_##name)	{						\
		val = module->get_##name(module);				\
		if ((u32)-1 != val) {						\
			print_info("    %s->%s: 0x%x\n", #module, #name, val);\
			print_debug("    %s<%px>->%s: 0x%x\n", #module, module, #name, val);\
		} else {							\
			print_debug("     Invalid value. Skip\n");		\
		}								\
	}									\
}

#define OPS(dir, module, name) \
	dir##_##name = __dm_##module##_##dir##_##name;

#define OPS_PRINT_OPS(cfg)							\
do {										\
	/*TODO: print all exisiting ops*/					\
	if (!cfg->ops)								\
		break;								\
										\
	print_info("    ops<%px>, init<%px>, exit<%px>\n", cfg->ops,		\
		   cfg->ops->init, cfg->ops->exit);				\
										\
} while(0);

#define COMMU_ENDPOINT_RPC_BUFFER_IN_SIZE (512)
#define COMMU_ENDPOINT_RPC_BUFFER_OUT_SIZE (128)
#define COMMU_RPC_SIZE COMMU_ENDPOINT_RPC_BUFFER_OUT_SIZE

#include "include/domain.h"
s32 get_res_unrealized(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_mem_cache_size(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_mem_bus_width(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_pci_ob_host_addr(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_pci_ob_axi_addr(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_pci_ob_sz(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_pci_bar_shm_sz(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_pci_dma_ch(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_pci_bar_reg_total_sz(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_pci_sram_pa(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_pci_sram_sz(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_pci_large_bar_bs(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_pci_large_bar_sz(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_mem_cfg_phys_card_idx(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 get_mem_cfg_size_limit(struct domain_type *domain, u64 *val,
			s8 res_offset, struct domain_type *target_domain);
s32 set_res_not_allowed(struct domain_type *domain,
				u64 val, s8 res_offset,
				struct domain_type *target_domain);

int dm_early_init_module(struct domain_type *domain, enum module_id module);
int dm_init_module(struct domain_type *domain, enum module_id module);
int dm_exit_module(struct domain_type *domain, enum module_id module);
int dm_stop_module(struct domain_type *domain, enum module_id module);
int dm_reinit_module(struct domain_type *domain, enum module_id module);
int dm_save_prepare_module(struct domain_type *domain, enum module_id module);
int dm_restore_complete_module(struct domain_type *domain, enum module_id module);

int dm_is_state(struct domain_type *domain, enum dm_state state);

/**
 * @is_state: the checker of state of domain. return -1 if empty.
 * @is_lock: whether the @domain is locked by mutex. It must be 0 when called
 *           by module(dm_register_ops_kernel, dm_register_ops_user).
 */
int dm_register_ops(struct domain_type *domain, enum module_id module,
		    struct dm_per_module_ops *ops,
		    void *priv,	int is_locked);
struct dm_per_module_ops *dm_unregister_ops(struct domain_type *domain,
					    enum module_id module, int is_locked);

struct domain_type *__dm_get_domain(u32 func_id);

/**
 * duplicate module data
 */
void dm_domain_dup_module_data(struct domain_type *dst, struct domain_type *src);

void __dm_domain_init_vf(struct domain_type *domain, u32 testu);

int __dm_scale_domains(struct domain_set_type *set, unsigned long domains_mask);

void dm_mutex_lock(struct mutex *lock);
void dm_mutex_unlock(struct mutex *lock);

struct dm_resource_discriptor {
	s8 mod_idx;
	s8 *res;
};
s32 dm_rpc_get_resource_host(struct domain_set_type *set, u64 *res_val[],
			const struct dm_resource_discriptor *res_set,
			s8 *res_offset[], s32 max_res_num,
			struct domain_type *target_domain)
			__attribute__ ((unused));
s32 dm_rpc_set_resource_host(struct domain_set_type *set, struct domain_type *domain,
			struct domain_type *target_domain,
			const struct dm_resource_discriptor *res_set,
			s8 *res_offset[], s32 max_res_num)
			__attribute__ ((unused));

//#define DM_UT_TEST_GLOBAL_ENABLE
#ifdef DM_UT_TEST_GLOBAL_ENABLE
extern const struct dm_resource_discriptor dm_outbound_distribute_resource_set[];
extern const struct dm_resource_discriptor dm_mig_res_set[];

int dm_ut_test_start(struct domain_set_type *set);
#endif
#endif /* __DOMAIN_PRIVATE_H__ */
