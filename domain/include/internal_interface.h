#ifndef __INTERNAL_INTERFACE_H__
#define __INTERNAL_INTERFACE_H__

#include "dmlib/include/domain.h"

/* domain.c domain_type creater */
struct domain_type *dm_alloc_vf_domain(
				struct domain_set_type *set, u32 func_id);
struct domain_type *dm_alloc_pf_domain(
				struct domain_set_type *set, u32 func_id);
/* domain.c domain_type creater */

/* misc.c */
int __cn_dm_is_pf(struct cn_core_set *core);
int __cn_dm_is_supported_platform(struct cn_core_set *core);
int __cn_dm_is_pf_only_mode(struct cn_core_set *core);
int __cn_dm_is_pf_sriov_mode(struct cn_core_set *core);
/* misc.c */

/* rpc_interface.c */
s32 dm_build_rpc_connection(struct cn_core_set *core);
void dm_destroy_rpc_connection(struct cn_core_set *core);

int dm_queue_rpc(struct domain_set_type *set, char *cmd, char *msg);
int dm_rpc_set_domain_set_daemon_state(
			struct domain_set_type *set, unsigned long attr);
#include "dmlib/domain_resource_dictionary.h"
/* Notice:
 *	max rpc buffer size is 128B, no need to suture across module,
 *	rerealize it as rpc buffer get bigger.
 * Parameter:
 *	res_val pointer array should meet the format of target
 *		dm_resource_discriptor, will be fill with result parsed out
 */
s32 dm_rpc_get_resource_host(struct domain_set_type *set, u64 *res_val[],
			const struct dm_resource_discriptor *res_set,
			s8 *res_offset[], s32 max_res_num,
			struct domain_type *target_domain);
/* Parameter:
 *	res_set is pointer to resource set that needed to transfer
 *	eg. dm_rpc_ob_res_set/dm_rpc_mig_res_set
 *	res_offset sometimes depend on target vfid,
 *	but normally it is a s8 array of zero
 *	max_res_num is max resource number of module in a resource set
 * Return:
 *	+n is resource number that already send out
 *	-1 is fail
 */
s32 dm_rpc_set_resource_host(struct domain_set_type *set, struct domain_type *domain,
				struct domain_type *target_domain,
				const struct dm_resource_discriptor *res_set,
				s8 *res_offset[], s32 max_res_num);
/* rpc_interface.c */

/* resource_cache.c */
enum dm_work_mode {
	DM_MODE_PF = 0x1,
	DM_MODE_VF = 0x2,
	DM_MODE_SRIOV = 0x4,
	DM_MODE_SRIOV_MIM = 0xc
};
enum domain_set_state {
	DM_UNDEF,
	DM_STARTED
};
struct domain_set_attr {
	union {
		/* SRIOV */
		struct {
			s32 max_vf;
			s32 sriov_func_num;
		};
	};
	struct {
		enum dm_work_mode work_mode;
		enum domain_set_state state;
	};
};
#define dm_get_work_mode(set) \
({ \
	struct domain_set_attr *attr = set->attr; \
	attr->work_mode; \
})
#define is_valid_mode(mode) \
({ \
	mode == DM_MODE_PF || mode == DM_MODE_VF || mode == DM_MODE_SRIOV; \
})
#define dm_mode_pf(set) \
({ \
	struct domain_set_attr *attr = set->attr; \
	attr->work_mode & DM_MODE_PF; \
})
#define dm_mode_sriov(set) \
({ \
	struct domain_set_attr *attr = set->attr; \
	attr->work_mode & DM_MODE_SRIOV; \
})
#define dm_mode_sriov_pf(set) \
({ \
	struct domain_set_attr *attr = set->attr; \
	attr->work_mode & DM_MODE_SRIOV; \
})
#define dm_mode_vf(set) \
({ \
	struct domain_set_attr *attr = set->attr; \
	attr->work_mode & DM_MODE_VF; \
})
#define dm_set_state_started(set) \
({ \
	struct domain_set_attr *attr = set->attr; \
	attr->state = DM_STARTED; \
})
#define dm_state_started(set) \
({ \
	struct domain_set_attr *attr = set->attr; \
	attr->state == DM_STARTED; \
})
struct resource_cache {
	struct {
		u32 cache_size;
		u32 bus_width;
		u32 mem_size_gb;
		u32 mem_ch_num;
		u32 quadrant;
	};
	struct {
		u32 ipu_mask;
		u32 tiny_core_mask;
	};
	u32 vpu_mask;
	u32 jpu_mask;
	u32 gdma_host_ch;
	struct {
		u16 bus_num;
		u16 devfn;
	};
};
s32 init_pf_resource_cache(struct cn_core_set *core);
s32 init_domain_set_attr(struct domain_set_type *set);
s32 domain_set_attr_init(struct domain_set_type *set,
				struct cn_bus_set *bus_set, struct domain_resource *resource);
s32 domain_set_attr_get_max_vf(struct domain_set_type *set);
s32 domain_set_attr_set_sriov_func_num(struct domain_set_type *set, s32 num);
s32 domain_set_attr_get_sriov_func_num(struct domain_set_type *set);
s32 domain_set_attr_set_bdf_num(struct domain_set_type *set,
						u16 bus_num, u16 devfn);
s32 domain_set_attr_sync_max_vf(struct domain_set_type *set);
s32 sync_resouce_cache(struct domain_set_type *set, struct domain_type *target);
/* resource_cache.c */

/* plat_pci.c */
void  __cn_dm_preset_ob_mask(struct cn_bus_set *bus_set,
				struct domain_type *domain, u32 is_sriov);
int dm_bar_pcie2dm(struct cn_bus_set *bus_set,
			struct domain_resource *resource, struct bar_cfg *cfg);
void  setup_domain_work_mode(struct domain_set_type *set,
			struct cn_bus_set *bus_set, struct domain_resource *resource);
/* plat_pci.c */

/* life_cycle_control.c */
struct domain_life_cycle_operation {
	/* SRIOV PF for VF driver load/unload */
	s32 (*shadow_domain_init_on_vf_driver_probe)
				(struct domain_set_type *set, u32 func_id);
	s32 (*shadow_domain_exit_on_vf_driver_remove)
				(struct domain_set_type *set, u32 func_id);
	/* Host domain init before device communication establish. */
	s32 (*host_pf_init_before_connect_device)(struct domain_set_type *set);
	s32 (*guest_vf_init_before_connect_device)(struct domain_set_type *set);
	s32 (*sriov_pf_init_before_connect_device)(struct domain_set_type *set);
	/* PF/VF/SRIOV PF any mode will connect with device */
	s32 (*connect_device)(struct domain_set_type *set);
	/* Device DM config and setup after connect established */
	s32 (*host_pf_setup_device)(struct domain_set_type *set);
	s32 (*guest_vf_setup_device)(struct domain_set_type *set);
	s32 (*sriov_pf_setup_device)(struct domain_set_type *set);
	/* As Host DM and Device DM settled down modules have dependency with
	 * domain will triger work.
	 */
	s32 (*domain_init_related_modules)(struct domain_set_type *set);
	s32 (*domain_exit_related_modules)(struct domain_set_type *set);
};
struct domain_life_cycle_operation *dm_get_life_cycle_op(void);
/* life_cycle_control.c */
int dm_set_dev_addr_map_type(struct domain_set_type *set);
#endif
