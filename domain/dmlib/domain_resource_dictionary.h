#ifndef __DOMAIN_RESOURCE_DICTIONARY_H__
#define __DOMAIN_RESOURCE_DICTIONARY_H__

struct dm_rpc_res_head {
	s32 ret;
	s32 size;
	u32 funcid;
	u32 version;
};
static inline s32 dm_rpc_res_head_get_ret(void *msg)
{
	return ((struct dm_rpc_res_head *)msg)->ret;
}

static inline s32 dm_rpc_res_head_set_ret(void *msg, s32 ret)
{
	return ((struct dm_rpc_res_head *)msg)->ret = ret;
}

static inline s32 dm_rpc_res_head_get_size(void *msg)
{
	return ((struct dm_rpc_res_head *)msg)->size;
}

static inline s32 dm_rpc_res_head_set_size(void *msg, s32 size)
{
	return ((struct dm_rpc_res_head *)msg)->size = size;
}

static inline s32 dm_rpc_res_head_get_funcid(void *msg)
{
	return ((struct dm_rpc_res_head *)msg)->funcid;
}

static inline s32 dm_rpc_res_head_set_funcid(void *msg, u32 funcid)
{
	return ((struct dm_rpc_res_head *)msg)->funcid = funcid;
}

static inline s32 dm_rpc_res_head_get_version(void *msg)
{
	return ((struct dm_rpc_res_head *)msg)->version;
}

static inline s32 dm_rpc_res_head_set_version(void *msg, u32 ver)
{
	return ((struct dm_rpc_res_head *)msg)->version = ver;
}
#include "domain_private.h"
#define DM_RESOURCE_DICTIONARY_INDEX_OFFSET_BYTE 1
#define DM_RESOURCE_DICTIONARY_INDEX_OFFSET_CODE ' '
#define DM_RESOURCE_DICTIONARY_INDEX_BYTES_NUM 2
#define DM_RESOURCE_VALUE_TYPE u64
#define DM_IPU_IDX (DM_IPU - DM_IPU)
#define DM_VPU_IDX (DM_VPU - DM_IPU)
#define DM_JPU_IDX (DM_JPU - DM_IPU)
#define DM_MEM_IDX (DM_MEM - DM_IPU)
#define DM_PCI_IDX (DM_PCI - DM_IPU)
#define DM_BOARD_IDX (DM_PCI_IDX + 1)
#define DM_GDMA_IDX (DM_BOARD_IDX + 1)
#define DICTIONARY_MAX_MODULE_NUMBER (DM_GDMA_IDX + 1)
_Static_assert(DM_IPU_IDX == 0 &&
	       DM_VPU_IDX == 1 &&
	       DM_JPU_IDX == 2 &&
	       DM_MEM_IDX == 3 &&
	       DM_PCI_IDX == 4 &&
	       DM_GDMA_IDX == 6 ,
	       "DM_XXX_IDX should start from zero and keep sequence");

#define DICTIONARY_INDEX_BYTE 0x0
enum dm_ipu_resource {
	a_ipu_cores,
	b_ipu_caps,
	c_ipu_mems,
	d_tiny_cores,
	IPU_RESOURCE_NUM
};
enum dm_vpu_resource {
	a_vpu_cores,
	b_vpu_caps,
	c_vpu_mems,
	VPU_RESOURCE_NUM
};
enum dm_jpu_resource {
	a_jpu_cores,
	b_jpu_mems,
	JPU_RESOURCE_NUM
};
enum dm_mem_resource {
	a_mem_num_of_zones,
	b_mem_zone,
	c_mem_cache_size,
	d_mem_bus_width,
	e_mem_ch_num,
	f_mem_size_gb,
	g_quadrant,
	MEM_RESOURCE_NUM
};
enum dm_pci_resource {
	a_pci_ob_num,
	b_pci_ob_host_addr,
	c_pci_ob_axi_addr,
	d_pci_ob_sz,
	e_pci_bar_num,
	f_pci_bar_sz,
	g_pci_bar_reg_bs,
	h_pci_bar_reg_sz,
	i_pci_bar_shm_bs,
	j_pci_bar_shm_sz,
	k_pci_dma_ch,
	l_pci_bar_reg_total_sz,
	m_pci_bar_shm_va,
	n_pci_sram_pa,
	o_pci_sram_sz,
	p_pci_large_bar_bs,
	q_pci_large_bar_sz,
	r_pci_mem_cfg_phys_card_idx,
	s_pci_mem_cfg_size_limit,
	PCI_RESOURCE_NUM
};

enum dm_gdma_resource {
	a_gdma_host_ch,
	GDMA_RESOURCE_NUM
};

enum dm_board_resource {
	a_chip_ver,
	b_board_id,
	c_max_vf,
	BOARD_RESOURCE_NUM
};
struct dm_struct_resource_dictionary {
	s8 *name;
	s32 (*get_resource)(struct domain_type *domain, u64 *val,
			     s8 offset, struct domain_type *target_domain);
	s32 (*set_resource)(struct domain_type *domain, u64 val, s8 offset,
			     struct domain_type *target_domain);
};

extern s8 *dm_rpc_ob_res_set[];
extern const struct dm_struct_resource_dictionary *dm_resource_dictionary_idx[];
struct dm_struct_module_dictionary {
	s8 *name;
	s32 last_res;
};
extern const struct dm_struct_module_dictionary dm_module_dictionary[];
s32 _dm_resource_parse_idx(void *pmsg, s32 *mod_idx, s32 *res_idx, s8 **head,
			   s32 *ulen);
s32 _dm_parse_resource_value(s8 *in_msg, s32 *len, u64 *out_msg,
			     s32 *mod_idx, s32 *res_idx, s8 **head);
s32 _dm_resource_suture(s8 *mod_str, s8 *res_table[], u64 value[],
			s8 *buf, s32 *len, s8 res_offset[]);
s32 dm_resource_parse_idxs_and_suture_with_value(struct domain_type *domain,
			s8 *in_msg, s32 in_len, s32 *len, s8 *buf,
			s8 **last_parse_module, struct domain_type *target_domain);
static inline s32 get_module_string(s32 mod_idx, s8 **mod_str)
{
	*mod_str = dm_module_dictionary[mod_idx].name;
	return 0;
}

static inline s32 get_resource_string(s32 mod_idx, s32 res_idx,
				      s8 **res_table)
{
	*res_table = dm_resource_dictionary_idx[mod_idx][res_idx].name;
	return 0;
}

static inline s32 get_resource_value(struct domain_type *domain, s32 mod_idx,
				s32 res_idx, u64 *val, s8 offset,
				struct domain_type *target_domain)
{
	return dm_resource_dictionary_idx[mod_idx][res_idx].get_resource(
					domain, val, offset, target_domain);
}

static inline s32 set_resource_value(struct domain_type *domain, s32 mod_idx,
				     s32 res_idx, u64 val, s8 offset,
				     struct domain_type *target_domain)
{
	return dm_resource_dictionary_idx[mod_idx][res_idx].set_resource(
					domain, val, offset, target_domain);
}

static inline s32 get_max_resource_dictionary_number(void)
{
	s32 i = 0, max = 0;
	for (i = 0; i < DICTIONARY_MAX_MODULE_NUMBER; i++) {
		max =
		    dm_module_dictionary[i].last_res >
		    max ? dm_module_dictionary[i].last_res : max;
	}
	return max;
}

/* Notice: this function designed as invoke once per discriptor,
 * place declear static value in function avoid recalculate max_res_number
 */
static inline s32 get_max_resource_number(const struct dm_resource_discriptor *res_set)
{
	s32 a = 0, i, j;
	for (i = 0;res_set[i].mod_idx != -1;i++) {
		j = 0;
		while(res_set[i].res[j] != -1) {
			j++;
		}
		a = a > j ? a : j;
	}
	return a;
}
#endif
