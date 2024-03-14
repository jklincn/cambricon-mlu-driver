#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include "domain_resource_dictionary.h"

#define RESOURCE_DICTIONARY_STATIC_INIT(enum_name, func_get, func_set) \
	[enum_name] = { \
		.name = #enum_name, \
		.get_resource = func_get, \
		.set_resource = func_set, \
	}
struct domain_type;
static struct dm_struct_resource_dictionary dm_ipu_resource_dictionary[] = {
	RESOURCE_DICTIONARY_STATIC_INIT(a_ipu_cores, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(b_ipu_caps, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(c_ipu_mems, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(d_tiny_cores, get_res_unrealized,
					set_res_not_allowed),
	[IPU_RESOURCE_NUM] = {.name = NULL, .get_resource = NULL,
					.set_resource = NULL},
};

static struct dm_struct_resource_dictionary dm_vpu_resource_dictionary[] = {
	RESOURCE_DICTIONARY_STATIC_INIT(a_vpu_cores, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(b_vpu_caps, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(c_vpu_mems, get_res_unrealized,
					set_res_not_allowed),
	[VPU_RESOURCE_NUM] = {.name = NULL, .get_resource = NULL,
					.set_resource = NULL},
};

static struct dm_struct_resource_dictionary dm_jpu_resource_dictionary[] = {
	RESOURCE_DICTIONARY_STATIC_INIT(a_jpu_cores, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(b_jpu_mems, get_res_unrealized,
					set_res_not_allowed),
	[JPU_RESOURCE_NUM] = {.name = NULL, .get_resource = NULL,
					.set_resource = NULL},
};

static struct dm_struct_resource_dictionary dm_mem_resource_dictionary[] = {
	RESOURCE_DICTIONARY_STATIC_INIT(a_mem_num_of_zones, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(b_mem_zone, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(c_mem_cache_size, get_mem_cache_size,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(d_mem_bus_width, get_mem_bus_width,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(e_mem_ch_num, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(f_mem_size_gb, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(g_quadrant, get_res_unrealized,
					set_res_not_allowed),
	[MEM_RESOURCE_NUM] = {.name = NULL,.get_resource = NULL,
					.set_resource = NULL},
};

static struct dm_struct_resource_dictionary dm_pci_resource_dictionary[] = {
	RESOURCE_DICTIONARY_STATIC_INIT(a_pci_ob_num, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(b_pci_ob_host_addr,
					get_pci_ob_host_addr,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(c_pci_ob_axi_addr, get_pci_ob_axi_addr,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(d_pci_ob_sz, get_pci_ob_sz,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(e_pci_bar_num, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(f_pci_bar_sz, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(g_pci_bar_reg_bs, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(h_pci_bar_reg_sz, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(i_pci_bar_shm_bs, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(j_pci_bar_shm_sz, get_pci_bar_shm_sz,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(k_pci_dma_ch, get_pci_dma_ch,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(l_pci_bar_reg_total_sz,
					get_pci_bar_reg_total_sz,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(m_pci_bar_shm_va,
					get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(n_pci_sram_pa,
					get_pci_sram_pa,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(o_pci_sram_sz,
					get_pci_sram_sz,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(p_pci_large_bar_bs,
					get_pci_large_bar_bs,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(q_pci_large_bar_sz,
					get_pci_large_bar_sz,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(r_pci_mem_cfg_phys_card_idx,
					get_mem_cfg_phys_card_idx,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(s_pci_mem_cfg_size_limit,
					get_mem_cfg_size_limit,
					set_res_not_allowed),
	[PCI_RESOURCE_NUM] = {.name = NULL, .get_resource = NULL,
					.set_resource = NULL},
};

static struct dm_struct_resource_dictionary dm_board_resource_dictionary[] = {
	RESOURCE_DICTIONARY_STATIC_INIT(a_chip_ver, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(b_board_id, get_res_unrealized,
					set_res_not_allowed),
	RESOURCE_DICTIONARY_STATIC_INIT(c_max_vf, get_res_unrealized,
					set_res_not_allowed),
	[BOARD_RESOURCE_NUM] = {.name = NULL,.get_resource =
				NULL,.set_resource = NULL},
};

static struct dm_struct_resource_dictionary dm_gdma_resource_dictionary[] = {
	RESOURCE_DICTIONARY_STATIC_INIT(a_gdma_host_ch, get_res_unrealized,
					set_res_not_allowed),
	[GDMA_RESOURCE_NUM] = {.name = NULL,.get_resource =
				NULL,.set_resource = NULL},
};

const struct dm_struct_resource_dictionary *dm_resource_dictionary_idx[] = {
	[DM_IPU_IDX] = dm_ipu_resource_dictionary,
	[DM_VPU_IDX] = dm_vpu_resource_dictionary,
	[DM_JPU_IDX] = dm_jpu_resource_dictionary,
	[DM_MEM_IDX] = dm_mem_resource_dictionary,
	[DM_PCI_IDX] = dm_pci_resource_dictionary,
	[DM_BOARD_IDX] = dm_board_resource_dictionary,
	[DM_GDMA_IDX] = dm_gdma_resource_dictionary,
	NULL
};

const struct dm_struct_module_dictionary dm_module_dictionary[] = {
	[DM_IPU_IDX] = {
			.name = "A_ipu",
			.last_res =
			sizeof(dm_ipu_resource_dictionary) /
			sizeof(struct dm_struct_resource_dictionary) - 1 - 1},
	[DM_VPU_IDX] = {
			.name = "B_vpu",
			.last_res =
			sizeof(dm_vpu_resource_dictionary) /
			sizeof(struct dm_struct_resource_dictionary) - 1 - 1},
	[DM_JPU_IDX] = {
			.name = "C_jpu",
			.last_res =
			sizeof(dm_jpu_resource_dictionary) /
			sizeof(struct dm_struct_resource_dictionary) - 1 - 1},
	[DM_MEM_IDX] = {
			.name = "D_mem",
			.last_res =
			sizeof(dm_mem_resource_dictionary) /
			sizeof(struct dm_struct_resource_dictionary) - 1 - 1},
	[DM_PCI_IDX] = {
			.name = "E_pci",
			.last_res =
			sizeof(dm_pci_resource_dictionary) /
			sizeof(struct dm_struct_resource_dictionary) - 1 - 1},
	[DM_BOARD_IDX] = {
			  .name = "F_board",
			  .last_res =
			  sizeof(dm_board_resource_dictionary) /
			  sizeof(struct dm_struct_resource_dictionary) - 1 - 1},
	[DM_GDMA_IDX] = {
			  .name = "G_gdma",
			  .last_res =
			  sizeof(dm_gdma_resource_dictionary) /
			  sizeof(struct dm_struct_resource_dictionary) - 1 - 1},

	[DM_GDMA_IDX + 1] = {
			      .name = NULL,
			      .last_res = 0}
};

#define MODULE_DICTIONARY_FIRST_ASCII_CODE 'A'
#define MODULE_DICTIONARY_LAST_ASCII_CODE \
	dm_module_dictionary[sizeof(dm_module_dictionary) / sizeof(struct dm_struct_module_dictionary) - 1 - 1].name[0]
static inline s32 check_and_get_valid_dictionary_difference(s8 *val,
							    s8 start,
							    s8 end)
{
	return val[0] > (start - 1) ? (val[0] <
				       (end + 1) ? val[0] - start : -1) : -1;
}

/* ShortEncodingFormat: "X_modY_res"
 * ContinuesEncodingFormat: "X_modY_resVALUEZ_resVALUE..."
 * Parameter:
 *	ori_msg, come pos32 to incomeing string
 *	mod_idx, return module idx
 *	res_idx, return resource idx
 *	head, for ContinuesEncodingFormat which hold module strings
 *	len, come with ori_msg size, return with string len that parse idx consume
 * Return:
 *	res_offset, which is third stage index
 *
 * TODO: for compatible of module/resource's in/decrease, unkonwn module/resource
 * need search here, realize it if non-uniform dictionary is support between host
 * and device. error return is also need removed.
 */
s32 _dm_resource_parse_idx(void *ori_msg, s32 *mod_idx, s32 *res_idx,
			   s8 **head, s32 *len)
{
	s8 *msg, *bmsg, *res_msg, *pmsg = ori_msg;
	s32 mod_num, res_num, len_tmp;
	mod_num = check_and_get_valid_dictionary_difference(pmsg,
					MODULE_DICTIONARY_FIRST_ASCII_CODE,
					MODULE_DICTIONARY_LAST_ASCII_CODE);
	if (mod_num < 0) {
		if (NULL != *head) {
			mod_num =
			    check_and_get_valid_dictionary_difference(*head,
					MODULE_DICTIONARY_FIRST_ASCII_CODE,
					MODULE_DICTIONARY_LAST_ASCII_CODE);
			if (mod_num < 0) {
				print_warn
				    ("invalid module alphabet head %c of head/pmsg\n"
				     "%s, %s \nneed compatible search\n",
				     (*head)[0], *head, (s8 *)pmsg);
				goto err;
			} else {
				msg = *head;
			}
		} else {
			print_warn
			    ("invalid module alphabet head %c of pmsg %s, start-%c:end-%c\n"
			     "need compatible search\n",
			     ((s8 *)pmsg)[0], (s8 *)pmsg, MODULE_DICTIONARY_FIRST_ASCII_CODE,
			     MODULE_DICTIONARY_LAST_ASCII_CODE);
			goto err;
		}
	} else {
		msg = pmsg;
		*head = pmsg;
	}
	len_tmp = strlen(dm_module_dictionary[mod_num].name);
	if (0 != memcmp(msg, dm_module_dictionary[mod_num].name, len_tmp)) {
		print_warn
		    ("invalid module key string %s, need compatible search\n",
		     msg);
		goto err;
	}
	/* msg equal head but not equal pmsg, that means pmsg does not have module head */
	if (msg != pmsg) {
		msg = pmsg;
	} else {
		msg += len_tmp;
	}
	res_num = check_and_get_valid_dictionary_difference(msg,
			dm_resource_dictionary_idx[mod_num][0].name[0],
			dm_resource_dictionary_idx[mod_num]
				[dm_module_dictionary[mod_num].last_res].name
					[DICTIONARY_INDEX_BYTE]);
	if (res_num < 0) {
		print_warn
		    ("invalid resource alphabet head %c of %s, need compatible search\n",
		     msg[0], msg);
		goto err;
	}
	res_msg = msg;
	msg += DM_RESOURCE_DICTIONARY_INDEX_BYTES_NUM;
	bmsg =
	    dm_resource_dictionary_idx[mod_num][res_num].name +
	    DM_RESOURCE_DICTIONARY_INDEX_BYTES_NUM;
	len_tmp = strlen(bmsg);
	if (0 != memcmp(msg, bmsg, len_tmp)) {
		print_warn
		    ("invalid module key string %s, need compatible search\n",
		     msg);
		goto err;
	}
	*mod_idx = mod_num;
	*res_idx = res_num;
	*len = msg - (s8 *)ori_msg + len_tmp;
	return res_msg[DM_RESOURCE_DICTIONARY_INDEX_OFFSET_BYTE] -
	    DM_RESOURCE_DICTIONARY_INDEX_OFFSET_CODE;
err:
	*mod_idx = -1;
	*res_idx = -1;
	*len = -1;
	return -1;
}

/* Parameter:
 *	len come with buffer size, back with parsed string len
 * Return:
 *	+ret is res_offset, which is third stage index
 */
s32 _dm_parse_resource_value(s8 *in_msg, s32 *len, u64 *out_msg,
			     s32 *mod_idx, s32 *res_idx, s8 **head)
{
	s8 *msg = in_msg;
	s32 ret, len_consume = *len;

	ret = _dm_resource_parse_idx(msg, mod_idx, res_idx, head, &len_consume);
	if (ret < 0) {
		print_err("fail on parse resource idx len %d\n", *len);
		return -1;
	}
	print_debug("len=%d len_consume=%d mod_idx=%d res_idx=%d msg=%s\n",
		    *len, len_consume, *mod_idx, *res_idx, msg);
	memcpy(out_msg, msg + len_consume, sizeof(DM_RESOURCE_VALUE_TYPE));
	*len = len_consume + sizeof(DM_RESOURCE_VALUE_TYPE);
	return ret;
}

/* Parameter:
 *	res_table last element should be NULL
 *	res_offset third stage index
 *		members of res_table should equal to res_offset,
 *		members in res_offset could be zero, which means no third stage index
 * 	len come with buf size, back with sutured string len
 * Return:
 *	+n is numbers of res that sutured
 *	-n means no enough buf to suture target res_tables,
 *		but if len(as it return) is not zero, some job is done rightly
 *		and len is length in res_table that rightly sutured
 */
s32 _dm_resource_suture(s8 *mod_str, s8 *res_table[], u64 value[],
			s8 *buf, s32 *len, s8 res_offset[])
{
	s32 len_left = *len, i, len_tmp;
	s32 len_value = 0;
	if (value != NULL) {
		len_value = sizeof(DM_RESOURCE_VALUE_TYPE);
	}
	if (len_left < len_value + strlen(mod_str) + strlen(res_table[0])) {
		*len = 0;
		return 0;
	}
	len_tmp = strlen(mod_str);
	memcpy(buf, mod_str, len_tmp);
	buf += len_tmp;
	len_left -= len_tmp;
	i = 0;
	do {
		len_tmp = strlen(res_table[i]);
		if (len_left < len_tmp + len_value) {
			*len = *len - len_left;
			print_debug
			    ("suture_idx NOMEM i<%d>, len_left<%d>, len<%d>, len_next<%d>\n",
			     i, len_left, *len, len_tmp);
			return -(i - 1);
		}
		memcpy(buf, res_table[i], len_tmp);
		buf[DM_RESOURCE_DICTIONARY_INDEX_OFFSET_BYTE] =
		    DM_RESOURCE_DICTIONARY_INDEX_OFFSET_CODE + res_offset[i];
		buf += len_tmp;
		len_left -= len_tmp;
		if (value != NULL) {
			memcpy(buf, &value[i], len_value);
			print_debug("suture with value 0x%llx\n", value[i]);
			buf += len_value;
			len_left -= len_value;
		}
	} while (res_table[++i] != NULL);
	*len = *len - len_left;
	return i - 1;
}

static inline s32 get_max_mig_res_set(void)
{
	s32 i = 0, max = 0;
	for (i = 0; i < DICTIONARY_MAX_MODULE_NUMBER; i++) {
	}
	return max;
}

/* Parameter:
 *	len come with buf size, return with buf used
 * Return:
 *	+ret is sutured resource number
 *	0 is fail, because no resource can parsed out rightly
 *	-ret is no enough buf, but it's value is sutured resource number
 */
s32 dm_resource_parse_idxs_and_suture_with_value(struct domain_type *domain,
			s8 *in_msg, s32 msg_len, s32 *len, s8 *buf,
			s8 **last_parse_module,
			struct domain_type *target_domain)
{
	s8 *msg = in_msg, *msg_backup;
	s8 *mod_str;
#define res_table_size 8
	s8 *res_table[res_table_size + 1];
	s32 ret, len_left, len_tmp, len_still, i, sutured_num, sutured_len;
	s32 mod_idx0, mod_idx, res_idx0, res_idx;
	u64 res_val[res_table_size];
	s8 res_offset[res_table_size];
	len_left = *len;
	len_still = msg_len;
	sutured_num = 0;
	sutured_len = 0;
	do {
		i = 0;
		ret =
		    _dm_resource_parse_idx(msg, &mod_idx0, &res_idx0,
					   last_parse_module, &len_tmp);
		if (ret < 0) {
			print_err("error on parse resource idx from %s \n",
				  in_msg);
			*len = 0;
			return 0;
		}
		msg += len_tmp;
		len_still -= len_tmp;
		res_offset[i] = ret;
		ret = get_resource_value(domain, mod_idx0, res_idx0,
				 &res_val[i], res_offset[0], target_domain);
		if (ret < 0) {
			print_err("error on get res val mod0=%d res0=%d\n",
				   mod_idx0, res_idx0);
			*len = 0;
			return 0;
		}
		get_resource_string(mod_idx0, res_idx0, &res_table[i]);
		print_debug
		    ("mod_idx0=%d res_idx0=%d res_offset[0]=%d res_val[0]=%llx res_table[0]=%s\n",
		     mod_idx0, res_idx0, res_offset[i], res_val[i],
		     res_table[i]);
		while (++i < res_table_size && len_still > 0) {
			msg_backup = msg;
			ret =
			    _dm_resource_parse_idx(msg, &mod_idx, &res_idx,
						   last_parse_module, &len_tmp);
			if (ret < 0) {
				print_err
				    ("error on parse resource idxx from %s\n",
				     in_msg);
				*len = 0;
				return 0;
			}
			if (mod_idx != mod_idx0) {
				msg = msg_backup;
				break;
			}
			msg += len_tmp;
			len_still -= len_tmp;
			res_offset[i] = ret;
			ret = get_resource_value(domain, mod_idx, res_idx,
				   &res_val[i], res_offset[i] -
				   DM_RESOURCE_DICTIONARY_INDEX_OFFSET_CODE,
				   target_domain);
			if (ret < 0) {
				print_err("err on get res val mod=%d res=%d\n",
					   mod_idx, res_idx);
				*len = 0;
				return 0;
			}
			get_resource_string(mod_idx, res_idx, &res_table[i]);
			print_debug
			    ("i=%d res_val[i]=%llx res_table[i]=%s res_offset[i]=%d\n",
			     i, res_val[i], res_table[i], res_offset[i]);
		}
		res_table[i] = NULL;
		mod_str = dm_module_dictionary[mod_idx0].name;
		len_tmp = len_left;
		ret =
		    _dm_resource_suture(mod_str, res_table, res_val, buf,
					&len_tmp, res_offset);
		if (ret < 0) {
			print_debug
			    ("res suture run out of buf buf_len=%d ret=%d used_len=%d\n",
			     msg_len, ret, len_tmp);
			sutured_num += -ret;
			*len = sutured_len + len_tmp;
			return -sutured_num;
		} else {
			sutured_num += ret;
			sutured_len += len_tmp;
		}
		len_left -= len_tmp;
	} while (len_left > 0 && len_still > 0);

	*len = sutured_len;
	return sutured_num;
}
