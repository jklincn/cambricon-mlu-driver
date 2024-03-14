#include "cndrv_bus.h"
#include "cndrv_domain.h"
#include "dmlib/domain_resource_dictionary.h"
#include "binn.h"
#include "internal_interface.h"

int cn_dm_mig_src_host_start(struct cn_core_set *core, u32 func_id)
{
	struct domain_set_type *set;
	struct domain_type *sriov = NULL;
	struct domain_type *pf = NULL;
	int ret;

	if (!core) {
		print_info("\n");
		return -1;
	}
	if (!__cn_dm_is_supported_platform(core)) {
		print_info("\n");
		return -1;
	}
	set = (struct domain_set_type *)core->domain_set;
	if (!set) {
		print_info("\n");
		return -1;
	}
	sriov = cn_dm_get_domain(core, func_id);
	if (!sriov) {
		print_err("Could not get func_id<%s> from core<%px>\n",
			   dm_funcid2str(func_id), core);
		return -1;
	}
	if (!sriov->pci.data) {
		print_err("err: sriov->pci.data is NULL, func_id:%s\n",
			   dm_funcid2str(func_id));
		return -1;
	}
	//Notice merge with guest start by skip the following PF part.
	pf = cn_dm_get_domain(core, DM_FUNC_PF);
	if (!pf) {
		print_err("Could not get func_id<%s> from core<%px>\n",
			   dm_funcid2str(func_id), core);
		return -1;
	}
	if (!pf->pci.data) {
		print_err("err: pf->pci.data is NULL, func_id:%s\n",
			   dm_funcid2str(func_id));
		return -1;
	}
	//Notice release resource of pcie of vf and allocate pf.
	print_info("pcie dma channel(vf->pf) vf[%x] pf[%x]\n",
		   sriov->pci.data->dma.ch, pf->pci.data->dma.ch);
	sriov->lock_func(&sriov->lock);
	if (sriov->pci.ops && sriov->pci.data && sriov->pci.ops->stop) {
		ret = sriov->pci.ops->stop(sriov->pci.data->priv);
		if (ret < 0) {
			print_err("PCI stop failed.\n");
			sriov->unlock_func(&sriov->lock);
			return ret;
		}
	} else {
		print_warn("Warning: PCI stop empty. exit\n");
	}
	sriov->state = DM_STATE_MIGRAING_START;
	sriov->unlock_func(&sriov->lock);
	pf->lock_func(&pf->lock);
	if (pf->pci.ops && pf->pci.data && pf->pci.ops->reinit) {
		pf->pci.data->priv = pf->pci.ops->reinit(pf,
						pf->pci.data->top_priv);
	} else {
		print_warn("Warning: PCI reinit empty. exit\n");
	}
	pf->state = DM_STATE_STARTED;
	pf->unlock_func(&pf->lock);
	return 0;
}

int cn_dm_mig_dst_host_start(struct cn_core_set *core, u32 func_id)
{
	struct domain_set_type *set;
	struct domain_type *pf = NULL;
	struct domain_type *sriov = NULL;
	int ret;

	if (!core) {
		print_info("\n");
		return -EINVAL;
	}
	if (!__cn_dm_is_supported_platform(core)) {
		print_info("\n");
		return -EINVAL;
	}
	set = (struct domain_set_type *)core->domain_set;
	if (!set) {
		print_info("\n");
		return -EINVAL;
	}
	//Notice merge with guest start by skip the following PF part.
	pf = cn_dm_get_domain(core, DM_FUNC_PF);
	if (!pf) {
		print_err("Could not get func_id<%s> from core<%px>\n",
			   dm_funcid2str(DM_FUNC_PF), core);
		return -1;
	}
	if (!pf->pci.data) {
		print_err("err: pf->pci.data is NULL, func_id:%s\n",
			   dm_funcid2str(DM_FUNC_PF));
		return -1;
	}
	sriov = cn_dm_get_domain(core, func_id);
	if (!sriov) {
		print_err("Could not get func_id<%s> from core<%px>\n",
			   dm_funcid2str(func_id), core);
		return -1;
	}
	if (!sriov->pci.data) {
		print_err("err: sriov->pci.data is NULL, func_id:%s\n",
			   dm_funcid2str(func_id));
		return -1;
	}
	//Notice release resource of pcie of vf and allocate pf.
	print_info("pcie dma channel(pf->vf) vf[%x] pf[%x]\n",
		   sriov->pci.data->dma.ch, pf->pci.data->dma.ch);
	print_info("pcie dma channel(pf->vf) vf[%x] pf[%x]\n",
		   sriov->pci.data->dma.ch, pf->pci.data->dma.ch);

	pf->lock_func(&pf->lock);
	if (pf->pci.ops && pf->pci.data && pf->pci.ops->stop) {
		ret = pf->pci.ops->stop(pf->pci.data->priv);
		if (ret < 0) {
			print_err("PCI stop failed.\n");
			pf->unlock_func(&pf->lock);
			return ret;
		}
	} else {
		print_warn("Warning: PCI stop empty. exit\n");
	}
	pf->state = DM_STATE_MIGRAING_START;
	pf->unlock_func(&pf->lock);
	sriov->lock_func(&sriov->lock);
	if (sriov->pci.ops && sriov->pci.data && sriov->pci.ops->reinit) {
		sriov->pci.data->priv = sriov->pci.ops->reinit(sriov,
						sriov->pci.data->top_priv);
	} else {
		print_warn("Warning: PCI reinit empty. exit\n");
	}
	sriov->state = DM_STATE_STARTED;
	sriov->unlock_func(&sriov->lock);
	return 0;
}

int cn_dm_mig_guest_save_prepare(struct cn_core_set *core)
{
	struct domain_set_type *set;
	struct domain_type *domain = NULL;
	u32 func_id = DM_FUNC_VF;
	int ret = -1;
	enum dm_state prev = DM_STATE_INVALID;

	if (!core) {
		print_info("\n");
		return -EINVAL;
	}
	if (!__cn_dm_is_supported_platform(core)) {
		print_info("\n");
		return -EINVAL;
	}
	set = (struct domain_set_type *)core->domain_set;
	if (!set) {
		print_info("\n");
		return -EINVAL;
	}
	domain = cn_dm_get_domain(core, func_id);
	if (!domain) {
		print_err("Could not get func_id<%s> from core<%px>\n",
			   dm_funcid2str(func_id), core);
		return -1;
	}
	if (!dm_check_state(domain->state, DM_STATE_MIGRAING_START)) {
		prev = domain->state;
		domain->state = DM_STATE_MIGRAING_START;
	} else {
		print_info("domain is %s. could not save_prepare. ignored.\n",
			   dm_state2str(domain->state));
		return -1;
	}
	if (domain->pci.ops && domain->pci.data
			&& domain->pci.ops->save_prepare) {
		ret = domain->pci.ops->save_prepare(domain->pci.data->priv);
		if (ret < 0) {
			print_err("PCI save_prepare failed.\n");
			goto err;
		}
	} else {
		print_warn("Warning: PCI save_prepare empty. exit\n");
	}
	domain->unlock_func(&domain->lock);
	print_info("FLOW: save_prepare domain<%px> in func <%s> done\n", domain,
		   dm_funcid2str(domain->func_id));
	return 0;
err:
	domain->state = prev;
	domain->unlock_func(&domain->lock);
	print_err("FLOW: save_prepare domain<%px> in func <%s> fail<%d>\n",
			domain, dm_funcid2str(domain->func_id), ret);
	return ret;
}

int cn_dm_mig_guest_restore_complete(struct cn_core_set *core)
{
	struct domain_set_type *set;
	struct domain_type *domain = NULL;
	u32 func_id = DM_FUNC_VF;
	enum dm_state prev = DM_STATE_INVALID;
	int ret = -1;

	if (!core) {
		print_info("\n");
		return -EINVAL;
	}
	if (!__cn_dm_is_supported_platform(core)) {
		print_info("\n");
		return -EINVAL;
	}
	set = (struct domain_set_type *)core->domain_set;
	if (!set) {
		print_info("\n");
		return -EINVAL;
	}
	domain = cn_dm_get_domain(core, func_id);
	if (!domain) {
		print_err("Could not get func_id<%s> from core<%px>\n",
			   dm_funcid2str(func_id), core);
		return -1;
	}

	domain->lock_func(&domain->lock);
	print_info("FLOW: restore complete domain<%px> in func <%s>\n", domain,
		   dm_funcid2str(domain->func_id));
	if (!dm_check_state(domain->state, DM_STATE_STARTED)) {
		prev = domain->state;
		domain->state = DM_STATE_STARTED;
	} else {
		print_info("domain is %s. could not restore_complete. ignored.\n",
			   dm_state2str(domain->state));
		goto err;
	}
	if (domain->pci.ops && domain->pci.data
			&& domain->pci.ops->restore_complete) {
		ret = domain->pci.ops->restore_complete(domain->pci.data->priv);
		if (ret < 0) {
			print_err("PCI restore_complete failed.\n");
			goto err;
		}
	} else {
		print_warn("Warning: PCI restore_complet empty. exit\n");
	}
	domain->unlock_func(&domain->lock);
	print_info("FLOW: restore_complete domain<%px> in func <%s> done\n",
			domain, dm_funcid2str(domain->func_id));
	return 0;
err:
	domain->state = prev;
	domain->unlock_func(&domain->lock);
	print_info("FLOW: restore_complete domain<%px> in func <%s> fail<%d>\n",
			domain, dm_funcid2str(domain->func_id), ret);
	return ret;
}

int cn_dm_mig_src_host_save_complete(struct cn_core_set *core, u32 func_id)
{
	enum dm_state next = DM_STATE_DEFINED;
	enum dm_state prev = DM_STATE_INVALID;
	struct domain_set_type *set;
	struct domain_type *domain = NULL;

	if (!core) {
		print_info("\n");
		return -EINVAL;
	}
	if (!__cn_dm_is_supported_platform(core)) {
		print_info("\n");
		return -EINVAL;
	}
	set = (struct domain_set_type *)core->domain_set;
	if (!set) {
		print_info("\n");
		return -EINVAL;
	}
	domain = cn_dm_get_domain(core, func_id);
	if (!domain) {
		print_err("Could not get func_id<%s> from core<%px>\n",
			   dm_funcid2str(func_id), core);
		return -1;
	}
	if (dm_check_domain_magic(domain) == 0)
		return -1;

	domain->lock_func(&domain->lock);
	print_info("FLOW: save complete domain<%px> in func <%s>\n", domain,
				dm_funcid2str(domain->func_id));
	if (!dm_check_state(domain->state, next)) {
		prev = domain->state;
		domain->state = next;
	} else {
		print_info("domain is %s. could not save_complete. ignored.\n",
				dm_state2str(domain->state));
		goto err;
	}
	domain->unlock_func(&domain->lock);
	print_info("FLOW: save_complete domain<%px> in func <%s> done\n", domain,
				dm_funcid2str(domain->func_id));
	return 0;
err:
	domain->state = prev;
	domain->unlock_func(&domain->lock);
	print_info("FLOW: save_complete domain<%px> in func <%s> fail\n", domain,
				dm_funcid2str(domain->func_id));
	return -1;
}

int cn_dm_mig_dst_host_complete(struct cn_core_set *core, u32 func_id)
{
	return 0;
}

static s8 mig_ipu_resource[] = {
	a_ipu_cores,
	b_ipu_caps,
	c_ipu_mems,
	-1,
};
static s8 mig_vpu_resource[] = {
	a_vpu_cores,
	b_vpu_caps,
	c_vpu_mems,
	-1,
};
static s8 mig_jpu_resource[] = {
	a_jpu_cores,
	b_jpu_mems,
	-1,
};
static s8 mig_mem_resource[] = {
	a_mem_num_of_zones,
	b_mem_zone,
	-1
};
static s8 mig_pci_resource[] = {
	j_pci_bar_shm_sz,
	f_pci_bar_sz,
	k_pci_dma_ch,
	-1
};
static s8 mig_board_resource[] = {
	a_chip_ver,
	b_board_id,
	-1
};
const struct dm_resource_discriptor dm_mig_res_set[] = {
	[0] = {.mod_idx = DM_IPU_IDX, .res = mig_ipu_resource},
	[1] = {.mod_idx = DM_VPU_IDX, .res = mig_vpu_resource},
	[2] = {.mod_idx = DM_JPU_IDX, .res = mig_jpu_resource},
	[3] = {.mod_idx = DM_MEM_IDX, .res = mig_mem_resource},
	[4] = {.mod_idx = DM_PCI_IDX, .res = mig_pci_resource},
	[5] = {.mod_idx = DM_BOARD_IDX, .res = mig_board_resource},
	[6] = {.mod_idx = -1, .res = NULL},
};
/* mig_res_offset are all zero and thread safe,
 * remove static const if res_offset need change
 */
static s8 _res_offset_ipu[ARRAY_SIZE(mig_ipu_resource)];
static s8 _res_offset_vpu[ARRAY_SIZE(mig_vpu_resource)];
static s8 _res_offset_jpu[ARRAY_SIZE(mig_jpu_resource)];
static s8 _res_offset_mem[ARRAY_SIZE(mig_mem_resource)];
static s8 _res_offset_pci[ARRAY_SIZE(mig_pci_resource)];
static s8 _res_offset_board[ARRAY_SIZE(mig_board_resource)];
static s8 *mig_res_offset[6] = {
	_res_offset_ipu,
	_res_offset_vpu,
	_res_offset_jpu,
	_res_offset_mem,
	_res_offset_pci,
	_res_offset_board,
};
#define MOD_RES_COMBINE_STR_SIZE 64
static inline s32 _dm_mig_get_cfg(void *cfg_binn, s8 *buff,
				   u64 *mig_res_val[], s32 i, s32 j)
{
	if (binn_object_set_uint64(cfg_binn, buff, mig_res_val[i][j]) == FALSE)
		return -1;

	return 0;
}
static inline s32 _dm_mig_test_cfg(void *cfg_binn, s8 *buff,
				   u64 *mig_res_val[], s32 i, s32 j)
{
	u64 val;

	if (!binn_object_get_uint64(cfg_binn, buff, &val))
		return -1;

	if (mig_res_val[i][j] != val) {
		print_err("fail on match %s 0x%llx!=0x%llx",
			   buff, mig_res_val[i][j], val);
		return -1;
	}
	return 0;
}
/* TODO: these res_val_* cost a little too many memory, use kmalloc
 * or memory in domain_type, not stack.
 * fix this after domain_type refactor as key-value.
 */
s32 cn_dm_mig_get_cfg(struct cn_core_set *core, u32 func_id, void *cfg_binn)
{
	struct domain_set_type *set;
	struct domain_type *target_domain;
	s8 *res_str;
	s8 *mod_str;
	s8 buff[MOD_RES_COMBINE_STR_SIZE];
	s32 ret, i, j, res_idx, mod_idx;
	u64 _res_val_ipu[ARRAY_SIZE(mig_ipu_resource) - 1];
	u64 _res_val_vpu[ARRAY_SIZE(mig_vpu_resource) - 1];
	u64 _res_val_jpu[ARRAY_SIZE(mig_jpu_resource) - 1];
	u64 _res_val_mem[ARRAY_SIZE(mig_mem_resource) - 1];
	u64 _res_val_pci[ARRAY_SIZE(mig_pci_resource) - 1];
	u64 _res_val_board[ARRAY_SIZE(mig_board_resource) - 1];
	u64 *mig_res_val[] = {
		_res_val_ipu,
		_res_val_vpu,
		_res_val_jpu,
		_res_val_mem,
		_res_val_pci,
		_res_val_board
	};
	/* max_res_num for mig is definite thread safe */
	static s32 max_res_num;

	if (max_res_num == 0)
		max_res_num = get_max_resource_number(dm_mig_res_set);

	if (!core) {
		print_info("\n");
		return -EINVAL;
	}
	if (!__cn_dm_is_pf(core)) {
		print_info("\n");
		return -EINVAL;
	}
	set = (struct domain_set_type *)core->domain_set;
	if (!set) {
		print_info("\n");
		return -EINVAL;
	}
	target_domain = dm_get_domain(set, func_id);
	if (!target_domain) {
		print_err("can not get target_domain\n");
		return -EINVAL;
	}
	ret = dm_rpc_get_resource_host(set, mig_res_val,
			dm_mig_res_set, mig_res_offset, max_res_num,
			target_domain);
	if (ret < 0) {
		print_err("fail on get mig_res_val\n");
		return -EINVAL;
	}
	for (i = 0; dm_mig_res_set[i].mod_idx != -1; i++) {
		mod_idx = dm_mig_res_set[i].mod_idx;
		get_module_string(mod_idx, &mod_str);
		for (j = 0; dm_mig_res_set[i].res[j] != -1; j++) {
			res_idx = dm_mig_res_set[i].res[j];
			get_resource_string(mod_idx, res_idx, &res_str);
			snprintf(buff, strlen(mod_str) + strlen(res_str) + 1,
				 "%s.%s", mod_str, res_str);
			ret = _dm_mig_get_cfg(cfg_binn, buff,
						      mig_res_val, i, j);
			if (ret < 0) {
				ret = -EINVAL;
				break;
			}
		}
		if (ret < 0)
			break;

	}
	if (ret < 0)
		print_err("mig get cfg fail\n");
	else
		print_info("mig get cfg ok\n");

	return ret;
}

s32 cn_dm_mig_test_cfg(struct cn_core_set *core, u32 func_id, void *cfg_binn)
{
	struct domain_set_type *set;
	struct domain_type *target_domain;
	s8 *res_str;
	s8 *mod_str;
	s8 buff[MOD_RES_COMBINE_STR_SIZE];
	s32 ret, i, j, res_idx, mod_idx;
	u64 _res_val_ipu[ARRAY_SIZE(mig_ipu_resource) - 1];
	u64 _res_val_vpu[ARRAY_SIZE(mig_vpu_resource) - 1];
	u64 _res_val_jpu[ARRAY_SIZE(mig_jpu_resource) - 1];
	u64 _res_val_mem[ARRAY_SIZE(mig_mem_resource) - 1];
	u64 _res_val_pci[ARRAY_SIZE(mig_pci_resource) - 1];
	u64 _res_val_board[ARRAY_SIZE(mig_board_resource) - 1];
	u64 *mig_res_val[] = {
		_res_val_ipu,
		_res_val_vpu,
		_res_val_jpu,
		_res_val_mem,
		_res_val_pci,
		_res_val_board
	};
	/* max_res_num for mig is definite thread safe */
	static s32 max_res_num;

	if (max_res_num == 0)
		max_res_num = get_max_resource_number(dm_mig_res_set);

	if (!core) {
		print_info("\n");
		return -EINVAL;
	}
	if (!__cn_dm_is_pf(core)) {
		print_info("\n");
		return -EINVAL;
	}
	set = (struct domain_set_type *)core->domain_set;
	if (!set) {
		print_info("\n");
		return -EINVAL;
	}
	target_domain = dm_get_domain(set, func_id);
	if (!target_domain) {
		print_err("can not get target_domain\n");
		return -EINVAL;
	}
	ret = dm_rpc_get_resource_host(set, mig_res_val,
			dm_mig_res_set, mig_res_offset, max_res_num,
			target_domain);
	if (ret < 0) {
		print_err("fail on get mig_res_val\n");
		return -EINVAL;
	}
	for (i = 0; dm_mig_res_set[i].mod_idx != -1; i++) {
		mod_idx = dm_mig_res_set[i].mod_idx;
		get_module_string(mod_idx, &mod_str);
		for (j = 0; dm_mig_res_set[i].res[j] != -1; j++) {
			res_idx = dm_mig_res_set[i].res[j];
			get_resource_string(mod_idx, res_idx, &res_str);
			snprintf(buff, strlen(mod_str) + strlen(res_str) + 1,
				 "%s.%s", mod_str, res_str);
			ret = _dm_mig_test_cfg(cfg_binn, buff,
						      mig_res_val, i, j);
			if (ret < 0) {
				ret = -EINVAL;
				break;
			}
		}
		if (ret < 0)
			break;

	}
	if (ret < 0) {
		print_err("mig test cfg fail\n");
	} else {
		print_info("mig test cfg ok\n");
		if (target_domain->state == DM_STATE_STARTED) {
			ret = cn_dm_exit_domain_sriov_with_rpc(core, func_id);
			if (ret < 0)
				print_err("migration clear environment fail\n");
			else
				print_info("migration clear environment done\n");

		}
	}
	return ret;
}
