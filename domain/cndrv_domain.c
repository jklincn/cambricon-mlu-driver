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
#include "dmlib/domain_private.h"
#include "dmlib/domain_resource_dictionary.h"
#include "binn.h"
#include "cndrv_gdma.h"
#include "cndrv_ipcm.h"
#include "internal_interface.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif

#undef print_debug
#define print_debug(s, ...) do{}while(0)

DEFINE_MUTEX(global_lock);

//TODO move to domain_set
int verbose = 1;

#define DM_STATE_ACCESS_NORMAL                                                 \
       (DM_STATE_CONFIGURED | DM_STATE_DEFINED | DM_STATE_INIT         \
        | DM_STATE_STARTED)

#define DM_STATE_ACCESS_REZ_NOR (DM_STATE_ACCESS_NORMAL)

#define OPS_GET_SUB_IDX(submodule, name, idx, return_type, is_state) \
return_type cn_dm_pci_get_##submodule##_##name(const void *param, u32 idx) \
{										\
	const struct domain_type *domain = param;					\
	if (!domain)								\
		return (return_type)-1;						\
										\
	if (!(domain->state & (is_state))) {				\
		print_err("Invalid state<%s:%x> not in <%x>\n",		\
				dm_state2str(domain->state),		\
				domain->state, (is_state));		\
		return (return_type)-1;						\
	}									\
	if ((domain->state & (is_state)) && domain->pci.data && (idx < domain->pci.data->num_of_##submodule))	\
		return domain->pci.data->submodule[idx].name;			\
	else									\
		return (return_type)-1;						\
}

#define OPS_GET_SUB(submodule, name, return_type, is_state) \
return_type cn_dm_pci_get_##submodule##_##name(const void *param) \
{										\
	const struct domain_type *domain = param;					\
	if (!domain)								\
		return (return_type)-1;						\
										\
	if (!(domain->state & (is_state))) {				\
		print_err("Invalid state<%s:%x> not in <%x>\n",		\
				dm_state2str(domain->state),		\
				domain->state, (is_state));		\
		return (return_type)-1;						\
	}									\
	if ((domain->state & (is_state)) && domain->pci.data)	\
		return domain->pci.data->submodule.name;				\
	else									\
		return (return_type)-1;						\
}

/*
 * expand to functions for outside modules getting related values
 *
 * u32 cn_dm_pci_get_bars_reg_total_sz(const void *domain, u32 idx);
 * u32 cn_dm_pci_get_bars_shm_bs(const void *domain, u32 idx);
 * u32 cn_dm_pci_get_bars_shm_sz(const void *domain, u32 idx);
 * u32 cn_dm_pci_get_dma_ch(const void *domain);
 * u32 cn_dm_pci_get_ob_mask(const void *domain);
 * u64 cn_dm_pci_get_sram_pa(const void *domain);
 * u64 cn_dm_pci_get_sram_sz(const void *domain);
 * u64 cn_dm_pci_get_large_bar_bs(const void *domain);
 * u64 cn_dm_pci_get_large_bar_sz(const void *domain);
 * u64 cn_dm_pci_get_mem_cfg_phys_card_idx(const void *domain);
 * u64 cn_dm_pci_get_mem_cfg_size_limit(const void *domain);
 */
OPS_GET_SUB_IDX(bars, reg_total_sz, idx, u32, DM_STATE_ACCESS_REZ_NOR)
OPS_GET_SUB_IDX(bars, shm_bs, idx, u32, DM_STATE_ACCESS_REZ_NOR)
OPS_GET_SUB_IDX(bars, shm_sz, idx, u32, DM_STATE_ACCESS_REZ_NOR)
OPS_GET_SUB(dma, ch, u32, DM_STATE_ACCESS_REZ_NOR)
OPS_GET_SUB(ob, mask, u32, DM_STATE_ACCESS_REZ_NOR)
OPS_GET_SUB(sram, pa, u64, DM_STATE_ACCESS_REZ_NOR)
OPS_GET_SUB(sram, sz, u64, DM_STATE_ACCESS_REZ_NOR)
OPS_GET_SUB(large_bar, bs, u64, DM_STATE_ACCESS_REZ_NOR)
OPS_GET_SUB(large_bar, sz, u64, DM_STATE_ACCESS_REZ_NOR)
OPS_GET_SUB(mem_cfg, phys_card_idx, u64, DM_STATE_ACCESS_REZ_NOR)
OPS_GET_SUB(mem_cfg, size_limit, u64, DM_STATE_ACCESS_REZ_NOR)

u32 cn_dm_get_func_id(const void *param)
{
	const struct domain_type *domain = param;
	return domain->func_id;
}

u32 cn_dm_get_vf_func_id(const void *param)
{
	const struct domain_type *domain = param;
	return (domain->func_id - DM_FUNC_VF0);
}

int cn_dm_get_vf_idx_by_domain_id(int domain_id)
{
	if (domain_id < 0) {
		print_err("Invalid domain_id:%d", domain_id);
		return -1;
	} else if (domain_id == DM_FUNC_PF) {
		print_err("Input domain_id is not VF, error");
		return -1;
	} else {
		return (domain_id - 1);
	}
}

unsigned long cn_dm_get_domain_mask(void *set)
{
	struct domain_set_type *domain_set = set;
	return domain_set->domains_mask;
}

static inline int dm_rpc_set_domain_set_domains_mask(
			struct domain_set_type *set, unsigned long attr)
{
	char tmp[COMMU_RPC_SIZE];
	int ret = -1;
	int ret_size;

	memset(tmp, 0, COMMU_RPC_SIZE);
	ret = dm_compat_rpc((void *)set, "dm_rpc_set_domain_set_domains_mask", &attr,
			sizeof(unsigned long), tmp, &ret_size, sizeof(tmp));
	cn_domain_debug(set, "return<%d, %s>", ret_size, tmp);
	if (dm_is_rpc_ok(tmp))
		return 0;

	return -1;
}

static inline int dm_rpc_set_domain_host(struct domain_set_type *set)
{
	//TOOD idx
	char in[COMMU_RPC_SIZE];
	int ret = -1;
	char *rpc_name = "dm_rpc_set_domain";

	memset(in, 0, COMMU_RPC_SIZE);
	dm_compat_rpc((void *)set, rpc_name, in, 2, in, &ret, sizeof(in));
	cn_domain_debug(set, "rpc<%s> return<%d: %s>", rpc_name, ret, in);
	if (dm_is_rpc_ok(in))
		ret = 0;

	return ret;
}

static int _dm_rpc_get_buf_pci(struct domain_set_type *set,
			      struct domain_type *domain,
			      struct bar_cfg *data)
{
	int ret = -1;
	s8 _res_offset[5] = {0, 0, 0, 0, 0};
	s8 *res_offset[1] = {_res_offset};
	s8 pci_resources0[] = {
		i_pci_bar_shm_bs,
		j_pci_bar_shm_sz,
		k_pci_dma_ch,
		-1
	};
	s8 pci_resources1[] = {
		n_pci_sram_pa,
		o_pci_sram_sz,
		-1
	};
	struct dm_resource_discriptor dm_pci_resource_set[] = {
		[0] = {.mod_idx = DM_PCI_IDX, .res = pci_resources0},
		[1] = {.mod_idx = -1, .res = NULL},
	};
	u64 _res_val_pci0[ARRAY_SIZE(pci_resources0) - 1];
	u64 _res_val_pci1[ARRAY_SIZE(pci_resources1) - 1];
	u64 *pci_res_val[] = {
		_res_val_pci0,
	};

	ret = dm_rpc_get_resource_host(set, pci_res_val, dm_pci_resource_set,
				  res_offset, 3, domain);
	if (ret < 0) {
		cn_domain_err(set, "fail on get res");
		return -1;
	}

	domain->pci.data->bars[0].shm_bs = _res_val_pci0[0];
	domain->pci.data->bars[0].shm_sz = _res_val_pci0[1];
	domain->pci.data->dma.ch = _res_val_pci0[2];
	cn_domain_debug(set, "0x%llx 0x%llx 0x%llx",
			_res_val_pci0[0], _res_val_pci0[1], _res_val_pci0[2]);
	if (cn_bus_pcie_sram_able(set->core->bus_set)) {
		dm_pci_resource_set[0].res = pci_resources1;
		pci_res_val[0] = _res_val_pci1;
		ret = dm_rpc_get_resource_host(set, pci_res_val, dm_pci_resource_set,
					  res_offset, 3, domain);
		if (ret < 0) {
			cn_domain_err(set, "fail on get sram res");
			return -1;
		}

		domain->pci.data->sram.pa = _res_val_pci1[0];
		domain->pci.data->sram.sz = _res_val_pci1[1];
		cn_domain_debug(set, "0x%llx 0x%llx",
				_res_val_pci1[0], _res_val_pci1[1]);
	}
	return 0;
}

/**
 * set_domain_manager_info()
 *
 * This function is used to pass domain configuration to device. User
 * SHOULD call it after cn_dm_chk_cfg return successful.
 *
 * Return: return 0 for successful
 * TODO err
 */
static int __dm_sync_vfs_cfg(struct domain_set_type *set, int num)
{
	int i;
	int ret = -1;
	unsigned long domains_mask = 0;

	if (!set)
		return -EINVAL;

	if (0 == num)
		return -EINVAL;

	cn_domain_info(set, "Set domain configuration in device.");
	for (i = 0; i < num; i++)
		__set_bit(i, &domains_mask);

	set->lock_func(&set->lock);
	ret = dm_rpc_set_domain_set_domains_mask(set, domains_mask);
	if (ret) {
		cn_domain_err(set, "Set domain mask fail.");
		goto err;
	}
	ret = dm_rpc_set_domain_host(set);
	if (ret) {
		goto err;
	}
	if (set->daemon_state != DM_STATE_STARTED) {
		ret = dm_rpc_set_domain_set_daemon_state(set, DM_STATE_STARTED);
		if (ret)
			goto err;
	}
	set->unlock_func(&set->lock);
	if (domains_mask != set->domains_mask) {
		ret = __dm_scale_domains(set, domains_mask);
		if (ret)
			goto err;
	} else {
		cn_domain_info(set, "Do not need to scale domain");
	}
	return cn_dm_get_cfg(set->core);
err:
	cn_domain_err(set, "Set domain configuration failed");
	set->daemon_state = DM_STATE_UNDEF;
	set->unlock_func(&set->lock);
	return ret;
}

void *cn_dm_get_domain_early(struct cn_bus_set *bus_set, u32 func_id)
{
	struct domain_type *domain = NULL;

	if (bus_set == NULL) {
		print_err("bus_set empty\n");
		return NULL;
	}
	if (bus_set->rsv_set)
		domain = dm_get_domain(bus_set->rsv_set, func_id);
	else
		print_err("bus_set->rsv_set empty, this function must "
			  "be called after cn_dm_host_early_init and "
			  "before cn_dm_host_early_exit\n");

	return (void *)domain;
}

void *cn_dm_get_domain(struct cn_core_set *core, u32 func_id)
{
	struct domain_set_type *set;
	struct domain_type *domain = NULL;

	if (!core) {
		print_err("cn_core_set empty");
		return NULL;
	}
	set = core->domain_set;
	if (set == NULL) {
		print_err("cn_core_set->set empty");
		return NULL;
	}
	if (dm_is_func_vf(func_id) || dm_is_func_pf(func_id)
			    || dm_is_func_overall(func_id)) {
		set->lock_func(&set->lock);
		domain = dm_get_domain(set, func_id);
		set->unlock_func(&set->lock);
	} else {
		print_err("Invalid function id<%d>\n", func_id);
	}
	return (void *)domain;
}

int cn_dm_sync_vfs_cfg(struct cn_core_set *core, u32 num_of_vf)
{
	struct domain_set_type *set = NULL;
	int num_of_func = num_of_vf + 1;
	int ret = -1;

	if (!core) {
		print_info("\n");
		return ret;
	}
	set = (struct domain_set_type *)core->domain_set;
	if (!set) {
		print_info("\n");
		return ret;
	}
	if (!__cn_dm_is_supported_platform(core)) {
		cn_domain_err(set, "platform err\n");
		return -ENODEV;
	}
	if (!__cn_dm_is_pf_sriov_mode(core)) {
		cn_domain_err(set, "driver mode not SRIOV\n");
		return -ENODEV;
	}
	if (core->state != CN_RUNNING) {
		cn_domain_err(set, "firmare booting is not finished, please configure later");
		return -EINVAL;
	}
	ret = domain_set_attr_get_max_vf(set);
	if (ret < 0 || ret < num_of_vf) {
		cn_domain_err(set, "limit max_vf fail: %d wanted vf num %d",
							ret, num_of_vf);
		return -EINVAL;
	}
	ret = domain_set_attr_set_sriov_func_num(set, num_of_vf);
	if (ret < 0) {
		cn_domain_err(set, "fail");
		return -EINVAL;
	}
	cn_domain_info(set, "FLOW: start\n");
	ret = __dm_sync_vfs_cfg(set, num_of_func);
	cn_domain_debug(set, "ret: %d", ret);
	if (ret)
		goto err;

	cn_domain_info(set, "FLOW: done");
	dm_domain_set_print(set);
	return ret;
err:
	cn_domain_err(set, "FLOW: fail<ret: %d>", ret);
	return ret;
}

void cn_dm_cancel_vfs_cfg(struct cn_core_set *core)
{
	struct domain_set_type *set = NULL;
	int i, ret;

	if (!core) {
		print_info("\n");
		return;
	}
	if (!__cn_dm_is_supported_platform(core)) {
		print_info("\n");
		return;
	}
	if (!__cn_dm_is_pf_sriov_mode(core)) {
		print_info("\n");
		return;
	}
	set = (struct domain_set_type*)core->domain_set;
	if (!set) {
		print_info("\n");
		return;
	}
	ret = domain_set_attr_set_sriov_func_num(set, 0);
	if (ret < 0) {
		cn_domain_err(set, "fail");
		return;
	}
	cn_domain_info(set, "FLOW: start");
	for_each_set_bit(i, &set->domains_mask,
			 sizeof(set->domains_mask) * BITS_PER_BYTE) {
		struct domain_type *domain = NULL;

		if (dm_is_func_pf(i))
			continue;

		domain = cn_dm_get_domain(core, i);
		if (!domain) {
			cn_domain_err(set, "Could not get func_id<%s> from core<%px>",
				   dm_funcid2str(i), core);
			continue;
		}
		cn_domain_info(set, "get domain %s[%d: %px]", dm_funcid2str(i), i, domain);
		if (DM_STATE_STARTED == domain->state)
			cn_dm_exit_domain_sriov_with_rpc(core, i);
		else
			cn_domain_info(set, "Domain is %s. skip exit",
				   dm_state2str(domain->state));

	}
	dm_rpc_set_domain_set_daemon_state(set, DM_STATE_CONFIGURED);
	set->daemon_state = DM_STATE_CONFIGURED;
	cn_domain_info(set, "FLOW: end");
}

/**
 * Set user configuration from proc interface. User could input the
 * requirement. It is not used in released software stack because
 * only 1, 2, 4 splits are supported.
 */
void cn_dm_set_vf_cfg(struct domain_set_type *set, void *vf_cfg)
{
	return;
}

int cn_dm_get_cfg(struct cn_core_set *core)
{
	struct bus_info_s bus_info;
	struct domain_set_type *set = NULL;
	struct domain_type *cur = NULL;
	int i;
	int ret = -1;

	if (!core)
		return -EINVAL;

	if (!__cn_dm_is_supported_platform(core))
		return -ENODEV;

	set = (struct domain_set_type*)core->domain_set;
	if (!set)
		return -EINVAL;

	set->lock_func(&set->lock);
	cn_domain_info(set, "Get domain configuration from device.");
	cn_bus_get_bus_info(core->bus_set, &bus_info);
	for_each_set_bit(i, &set->domains_mask,
			 sizeof(set->domains_mask) * BITS_PER_BYTE) {
		cur = dm_get_domain(set, i);
		if (!cur)
			goto err_free_vf_domains;

		if (cur->pci.data == NULL) {
			ret = -EINVAL;
			cn_domain_err(set, "pci data not alloced");
			goto err_free_vf_domains;
		}
		ret = _dm_rpc_get_buf_pci(set, cur, &cur->pci.data->bars[0]);
		if (ret < 0) {
			ret = -EINVAL;
			cn_domain_err(set, "fail on _dm_rpc_get_buf_pci %d", ret);
			goto err_free_vf_domains;
		}
		__cn_dm_preset_ob_mask((struct cn_bus_set *)core->bus_set, cur,
						cn_is_mim_en(core));
		/* TODO-Today:
		 * Need get All VF bdf num
		 *
		 */
		cur->state = DM_STATE_DEFINED;
	}
	set->daemon_state = DM_STATE_STARTED;
	cn_domain_info(set, "Get domain configuration in host done");
	set->unlock_func(&set->lock);
	ret = 0;
	return ret;

err_free_vf_domains:
	for_each_set_bit(i, &set->domains_mask,
			 sizeof(set->domains_mask) * BITS_PER_BYTE) {
		if (dm_is_func_pf(i))
			continue;

		if (DM_FUNC_VF0 == i)
			continue;

		cur = dm_get_domain(set, i);
		if (!cur)
			continue;

		dm_domain_free_data(cur);
		clear_bit(i, &set->domains_mask);
		dm_free(set->domains[i]);
		set->domains[i] = NULL;
	}
	set->daemon_state = DM_STATE_UNDEF;
	set->unlock_func(&set->lock);
	return ret;
}

int cn_dm_init_domain(struct cn_core_set *core)
{
	struct domain_set_type *set = NULL;
	int ret;
	struct domain_life_cycle_operation *life_op;

	if (!core) {
		print_err("core null\n");
		return -EINVAL;
	}

	if (!__cn_dm_is_supported_platform(core)) {
		print_err("invalid plat\n");
		return -ENODEV;
	}

	set = core->domain_set;
	if (!set) {
		print_err("set null\n");
		return -EINVAL;
	}

	life_op = dm_get_life_cycle_op();
	ret = life_op->domain_init_related_modules(set);
	if (ret < 0) {
		cn_domain_err(set, "Fail on domain_init_on_driver_probe");
		return -EINVAL;
	}

	cn_domain_info(set, "Done");

	return 0;
}

int cn_dm_exit_domain(struct cn_core_set *core)
{
	struct domain_set_type *set = NULL;
	int ret;
	struct domain_life_cycle_operation *life_op;

	if (!core)
		return -EINVAL;

	if (!__cn_dm_is_supported_platform(core))
		return -ENODEV;

	set = core->domain_set;
	if (!set)
		return -EINVAL;

	life_op = dm_get_life_cycle_op();
	ret = life_op->domain_exit_related_modules(set);
	if (ret < 0) {
		cn_domain_err(set, "fail");
		return ret;
	}
	cn_domain_info(set, "Done\n");
	return 0;
}

int cn_dm_exit_domain_sriov_with_rpc(struct cn_core_set *core, u32 func_id)
{
	int ret = -1;
	struct domain_set_type *set;
	struct domain_life_cycle_operation *life_op;

	if (!core)
		return -EINVAL;

	if (!__cn_dm_is_supported_platform(core))
		return -ENODEV;

	set = (struct domain_set_type*)core->domain_set;
	if (!set)
		return -EINVAL;

	if (!dm_mode_sriov(set)) {
		cn_domain_err(set, "Fail state check");
		return -EINVAL;
	}
	if (!dm_state_started(set)) {
		cn_domain_err(set, "Fail state check");
		return -EINVAL;
	}
	life_op = dm_get_life_cycle_op();
	ret = life_op->shadow_domain_exit_on_vf_driver_remove(set, func_id);
	if (ret < 0) {
		cn_domain_err(set, "shadow func%d try exit fail!\n", func_id);
		return ret;
	}
	cn_domain_info(set, "Done\n");
	return 0;
}

int cn_dm_init_domain_sriov_smart(struct cn_core_set *core, u32 func_id)
{
	int ret = -1;
	struct domain_set_type *set;
	struct domain_life_cycle_operation *life_op;

	if (!core) {
		print_info("\n");
		return ret;
	}
	if (!core->domain_set) {
		print_err("No domain_set\n");
		return ret;
	}
	set = (struct domain_set_type *)core->domain_set;
	if (!set)
		return -EINVAL;

	if (!__cn_dm_is_supported_platform(core)) {
		cn_domain_err(set, "Fail");
		return -ENODEV;
	}
	if (!dm_mode_sriov(set)) {
		cn_domain_err(set, "Fail mode check");
		return -ENODEV;
	}
	if (!dm_state_started(set)) {
		cn_domain_err(set, "Fail state check");
		return -ENODEV;
	}
	life_op = dm_get_life_cycle_op();
	ret = life_op->shadow_domain_init_on_vf_driver_probe(set, func_id);
	if (ret < 0) {
		cn_domain_err(set, "Fail init");
		return -EINVAL;
	}
	cn_domain_info(set, "Done");
	return 0;
}

int cn_dm_late_init(struct cn_core_set *core)
{
	struct domain_set_type *set = NULL;
	int ret;
	struct domain_life_cycle_operation *life_op;
	struct domain_type *domain = NULL;
	enum dm_work_mode mode;

	if (!core) {
		print_err("core null\n");
		return -EINVAL;
	}
	if (!__cn_dm_is_supported_platform(core)) {
		print_err("not support this platform\n");
		return -ENODEV;
	}
	set = (struct domain_set_type *)core->domain_set;
	if (!set) {
		print_err("domain_set null\n");
		return -EINVAL;
	}

	mode = dm_get_work_mode(set);
	if (mode & (DM_MODE_PF | DM_MODE_VF)) {
		domain = (mode & DM_MODE_PF) ? dm_get_domain(set, DM_FUNC_PF) :
			dm_get_domain(set, DM_FUNC_VF);
		if (!domain) {
			cn_domain_info(set, "Could not get func");
			return -1;
		}

		if (domain->pci.ops && domain->pci.data) {
			domain->pci.data->priv = domain->pci.ops->init(domain,
						domain->pci.data->top_priv);
		} else {
			cn_domain_warn(set, "PCI init ops empty. exit");
		}
	}

	life_op = dm_get_life_cycle_op();
	ret = life_op->connect_device(set);
	if (ret < 0) {
		print_err("connect_device fail\n");
		return -EINVAL;
	}
	if (dm_mode_pf(set)) {
		ret = life_op->host_pf_setup_device(set);
		if (ret < 0) {
			print_err("host pf setup fail\n");
			return -EINVAL;
		}
	} else if (dm_mode_sriov(set)) {
		ret = life_op->sriov_pf_setup_device(set);
		if (ret < 0) {
			print_err("sriov pf setup fail\n");
			return -EINVAL;
		}
	} else if (dm_mode_vf(set)) {
		ret = life_op->guest_vf_setup_device(set);
		if (ret < 0) {
			print_err("guest vf setup fail\n");
			return -EINVAL;
		}
	} else {
		print_err("unknown dm mode\n");
		return -EINVAL;
	}
	return 0;
}

void cn_dm_late_exit(struct cn_core_set *core)
{
	struct domain_set_type *set;
	struct domain_type *domain = NULL;
	enum dm_work_mode mode;
#ifdef CONFIG_CNDRV_EDGE
	char tmp[COMMU_RPC_SIZE] = {0};
	s32 ret, func_id = DM_FUNC_PF, ret_size = 0;
#endif

	set = (struct domain_set_type *)core->domain_set;
	mode = dm_get_work_mode(set);
	if (mode & (DM_MODE_PF | DM_MODE_VF)) {
		domain = (mode & DM_MODE_PF) ? dm_get_domain(set, DM_FUNC_PF) :
			dm_get_domain(set, DM_FUNC_VF);
		if (!domain) {
			cn_domain_err(set, "Could not get func");
			return;
		}

		if (domain->pci.ops && domain->pci.data) {
			domain->pci.ops->exit(domain->pci.data->priv);
		} else {
			cn_domain_warn(set, "pci exit is empty");
		}

#ifdef CONFIG_CNDRV_EDGE
		ret = dm_compat_rpc((void *)set, "domain_exit", &func_id, sizeof(u32),
						tmp, &ret_size, sizeof(tmp));
		if (ret < 0 || !dm_is_rpc_ok(tmp)) {
			cn_domain_err(set, "rpc domain_exit func_id: %d> return<%d, %s>\n",
						DM_FUNC_PF, ret_size, tmp);
			return;
		}
#endif
		domain->state = DM_STATE_UNDEF;
	}

	dm_destroy_rpc_connection(core);
}

int cn_dm_init(struct cn_core_set *core)
{
	struct domain_set_type *set = NULL;
	struct cn_bus_set *bus;
	int ret = -1;
	struct domain_life_cycle_operation *life_op;

	if (!core) {
		print_info("\n");
		return -EINVAL;
	}

	if ((core->device_id == MLUID_370_DEV) || (core->device_id == MLUID_590_DEV)) {
		print_info("no support 370 or 590 dev.\n");
		return 0;
	}

	bus = core->bus_set;
	if (!__cn_dm_is_supported_platform(core)) {
		print_err("\n");
		return -ENODEV;
	}
	if (!bus->rsv_set) {
		print_err("\n");
		return -1;
	}
	cn_domain_info(set, "FLOW: start");
	set = bus->rsv_set;
	core->domain_set = (void*)set;
	set->core = core;
	life_op = dm_get_life_cycle_op();
	if (dm_mode_pf(set)) {
		ret = life_op->host_pf_init_before_connect_device(set);
		if (ret < 0) {
			goto err_free;
		}
	} else if (dm_mode_sriov(set)) {
		ret = life_op->sriov_pf_init_before_connect_device(set);
		if (ret < 0)
			goto err_free;

	} else if (dm_mode_vf(set)) {
		ret = life_op->guest_vf_init_before_connect_device(set);
		if (ret < 0)
			goto err_free;

	} else {
		cn_domain_err(set, "Unknown mode");
		goto err_free;
	}
	ret = dm_launch_kdaemon(set);
	if (ret)
		goto err_free;

	cn_domain_info(set, "FLOW: done");
	return ret;
err_free:
	dm_free_domain_set((void **)(&set));
	cn_domain_err(set, "FLOW: fail");
	return ret;
}

void cn_dm_exit(struct cn_core_set *core)
{
	struct domain_set_type *set;
	int timeout = 10;

	if (!core) {
		print_info("\n");
		return;
	}
	if (!__cn_dm_is_supported_platform(core)) {
		print_info("\n");
		return;
	}
	set = (struct domain_set_type*)core->domain_set;
	if (!set) {
		print_info("\n");
		return;
	}
	cn_domain_info(set, "FLOW: start");
	dm_stop_kdaemon(set);
	while (set->daemon_state != DM_STATE_UNDEF && timeout > 0) {
		cn_domain_info(set, "waiting for kheartbeatd exiting(%d: %s)",
				timeout, dm_state2str(set->daemon_state));
		msleep(1000);
		timeout--;
	}
	if (timeout <= 0)
		cn_domain_err(set, "kheartbeatd exiting timeout!");

	cn_domain_info(set, "FLOW: done");
	return;
}

int cn_dm_host_early_init(struct cn_bus_set *bus_set, u64 device_id)
{
	struct domain_type *domain = NULL;
	struct domain_set_type *set;
	struct domain_resource resource;
	struct bar_cfg *cfg;
	int i, ret = -1;
	bool is_pdev_virtfn;
	u32 curr_bdf;

	if ((device_id == MLUID_370_DEV) ||
		(device_id == MLUID_580_DEV) ||
		(device_id == MLUID_590_DEV)) {
		return 0;
	}

	if (!bus_set) {
		print_err("bus_set==NULL\n");
		return -EINVAL;
	}
	memset(&resource, 0, sizeof(resource));
	memset(&cfg, 0, sizeof(cfg));
	if (!bus_set->priv) {
		print_err("bus_set->priv==NULL\n");
		return -EINVAL;
	}
	print_info("FLOW: start\n");
	if (bus_set->rsv_set != NULL) {
		dm_free_domain_set(&(bus_set->rsv_set));
	}
	set = (struct domain_set_type *)dm_zalloc(
					sizeof(struct domain_set_type));
	if (set == NULL) {
		print_err("malloc domain_set_type failed\n");
		return -ENOMEM;
	}
	mutex_init(&set->lock);
	mutex_init(&set->mim_lock);
	set->lock_func = dm_mutex_lock;
	set->unlock_func = dm_mutex_unlock;
	set->overall = dm_alloc_pf_domain(set, DM_FUNC_OVERALL);
	if (!set->overall) {
		print_err("malloc overall domain failed\n");
		goto err_free;
	}
	set->domains[DM_FUNC_PF] = dm_alloc_pf_domain(set, DM_FUNC_PF);
	if (!set->domains[DM_FUNC_PF]) {
		print_err("malloc pf domain failed\n");
		goto err_free;
	}
	set->domains[DM_FUNC_VF] = dm_alloc_vf_domain(set, DM_FUNC_VF);
	if (!set->domains[DM_FUNC_VF]) {
		print_err("malloc vf domain failed\n");
		goto err_free;
	}
	__set_bit(DM_FUNC_PF, &set->domains_mask);
	__set_bit(DM_FUNC_VF, &set->domains_mask);
	set->daemon_state = DM_STATE_UNDEF;
	set->mim_dev_support = DM_MIM_DEV_NOT_INIT;
	bus_set->rsv_set = set;
	domain = cn_dm_get_domain_early(bus_set, DM_FUNC_OVERALL);
	if (!domain) {
		print_err("BUG: domain data struct constructor fail\n");
		goto err_free;
	}
	if (bus_set->get_resource(bus_set->priv, &resource)) {
		print_err("PCI: can not get pci bar res\n");
		goto err_free;
	}
	if (domain_set_attr_init(set, bus_set, &resource) < 0) {
		print_err("domain_set_attr: can not init\n");
		goto err_free;
	}
	cfg = &(domain->pci.data->bars[0]);
	ret = dm_bar_pcie2dm(bus_set, &resource, cfg);
	if (ret < 0) {
		print_err("PCI: fail on dm_bar_pcie2dm\n");
		goto err_free;
	}
	if (resource.max_phy_channel > BITS_PER_U8 *
				sizeof(typeof(domain->pci.data->dma.ch))) {
		print_err("PCI: dma channel overflow %d > %ld\n",
				resource.max_phy_channel, BITS_PER_U8 *
				sizeof(typeof(domain->pci.data->dma.ch)));
		goto err_free;
	}
	for (i = 0; i < resource.max_phy_channel; i++)
		domain->pci.data->dma.ch |= BIT(i);

	is_pdev_virtfn = cn_bus_check_pdev_virtfn(bus_set);
	curr_bdf = cn_bus_get_current_bdf(bus_set);

	__cn_dm_preset_ob_mask(bus_set, domain,
		cn_is_mim_en_bdf(curr_bdf, is_pdev_virtfn));
	print_info("FLOW: done\n");
	return 0;
err_free:
	dm_free_domain_set((void **)(&set));
	bus_set->rsv_set = NULL;
	return -1;
}

void cn_dm_host_early_exit(struct cn_bus_set *bus_set, u64 device_id)
{
	if ((device_id == MLUID_370_DEV) ||
		(device_id == MLUID_580_DEV) ||
		(device_id == MLUID_590_DEV)) {
		return;
	}

	if (!bus_set)
		return;

	if (!bus_set->rsv_set)
		return;

	print_info("FLOW: start\n");
	mutex_lock(&global_lock);
	dm_free_domain_set(&(bus_set->rsv_set));
	bus_set->rsv_set = NULL;
	mutex_unlock(&global_lock);
	print_info("FLOW: done\n");
}
