#include "cndrv_bus.h"
#include "cndrv_domain.h"
#include "dmlib/domain_private.h"
#include "internal_interface.h"

int __cn_dm_is_pf(struct cn_core_set *core)
{
	int ret;

	ret = core->device_id == MLUID_270
		|| core->device_id == MLUID_590
		|| core->device_id == MLUID_580
		|| core->device_id == MLUID_370
		|| core->device_id == MLUID_370_DEV
		|| core->device_id == MLUID_590_DEV
		|| core->device_id == MLUID_290
		|| core->device_id == MLUID_220
		|| core->device_id == MLUID_220_EDGE
		|| core->device_id == MLUID_CE3226
		|| core->device_id == MLUID_CE3226_EDGE
		|| core->device_id == MLUID_PIGEON
		|| core->device_id == MLUID_PIGEON_EDGE;
	return ret;
}

int __cn_dm_is_supported_platform(struct cn_core_set *core)
{
	int ret;

	ret = __cn_dm_is_pf(core)
		|| cn_core_is_vf(core);
	print_debug("core->device_id: 0x%llx, ret: %d\n", core->device_id, ret);
	return ret;
}

int __cn_dm_is_pf_only_mode(struct cn_core_set *core)
{
	print_debug("cn_is_mim_en: %d\n", cn_is_mim_en(core));
	return __cn_dm_is_pf(core) && !cn_is_mim_en(core);
}

int __cn_dm_is_pf_sriov_mode(struct cn_core_set *core)
{
	print_debug("cn_is_mim_en: %d\n", cn_is_mim_en(core));
	return __cn_dm_is_pf(core) && cn_is_mim_en(core);
}

enum dm_state dm_str2state(const char *str)
{
	enum dm_state state;

	if (!strcmp(str, "undef")) {
		state = DM_STATE_UNDEF;
	} else if (!strcmp(str, "configured")) {
		state = DM_STATE_CONFIGURED;
	} else if (!strcmp(str, "defined")) {
		state = DM_STATE_DEFINED;
	} else if (!strcmp(str, "init")) {
		state = DM_STATE_INIT;
	} else if (!strcmp(str, "started")) {
		state = DM_STATE_STARTED;
	} else if (!strcmp(str, "suspend")) {
		state = DM_STATE_SUSPEND;
	} else if (!strcmp(str, "migraing")) {
		state = DM_STATE_MIGRAING;
	} else if (!strcmp(str, "failure")) {
		state = DM_STATE_FAILURE;
	} else {
		print_err("invalid state: %s\n", str);
		state = DM_STATE_INVALID;
	}
	return state;
}

const char *dm_state2str(enum dm_state state)
{
	switch (state) {
	case DM_STATE_UNDEF:
		return "undef";
	case DM_STATE_CONFIGURED:
		return "configured";
	case DM_STATE_DEFINED:
		return "defined";
	case DM_STATE_EARLY_INIT:
		return "early_init";
	case DM_STATE_INIT:
		return "init";
	case DM_STATE_STARTED:
		return "started";
	case DM_STATE_SUSPEND:
		return "suspend";
	case DM_STATE_MIGRAING:
		return "migraing";
	case DM_STATE_FAILURE:
		return "failure";
	default:
		return "invalid";
	}
}

int dm_check_state(enum dm_state cur, enum dm_state next)
{
	if (next == DM_STATE_UNDEF)
		goto suc;
	if (cur != DM_STATE_UNDEF && next == DM_STATE_FAILURE)
		goto suc;
	if (cur == DM_STATE_UNDEF && next == DM_STATE_CONFIGURED)
		goto suc;
	if (cur == DM_STATE_UNDEF && next == DM_STATE_DEFINED)
		goto suc;
	if (cur == DM_STATE_CONFIGURED && next == DM_STATE_DEFINED)
		goto suc;
	if (cur == DM_STATE_DEFINED && next == DM_STATE_INIT)
		goto suc;
	if (cur == DM_STATE_DEFINED && next == DM_STATE_EARLY_INIT)
		goto suc;
	if (cur == DM_STATE_EARLY_INIT && next == DM_STATE_INIT)
		goto suc;
	if (cur == DM_STATE_INIT && next == DM_STATE_STARTED)
		goto suc;
	if (cur == DM_STATE_STARTED && next == DM_STATE_MIGRAING_START)
		goto suc;
	if (cur == DM_STATE_MIGRAING_START && next == DM_STATE_STARTED)
		goto suc;
	if (cur == DM_STATE_MIGRAING_START && next == DM_STATE_DEFINED)
		goto suc;

	print_info("current state<%s> could not push to <%s>.\n",
		   dm_state2str(cur), dm_state2str(next));
	return -1;
suc:
	print_info("current state<%s> could push to <%s>.\n",
		   dm_state2str(cur), dm_state2str(next));
	return 0;
}

const char *dm_module2str(enum module_id id)
{
	switch (id) {
	case TESTU:
		return "testu";
	case IPU:
		return "ipu";
	case VPU:
		return "vpu";
	case JPU:
		return "jpu";
	case MEM:
		return "mem";
	case PCI:
		return "pci";
	default:
		return "invalid";
	}
}

enum module_id dm_str2module(const char *str)
{
	enum module_id id;

	if (!strcmp(str, "testu"))
		id = TESTU;
	else if (!strcmp(str, "ipu"))
		id = IPU;
	else if (!strcmp(str, "vpu"))
		id = VPU;
	else if (!strcmp(str, "jpu"))
		id = JPU;
	else if (!strcmp(str, "mem"))
		id = MEM;
	else if (!strcmp(str, "pci"))
		id = PCI;
	else
		id = DM_INVALID_MODULE;

	return id;
}

//not re-entry able!!!
char *dm_funcid2str(u32 i)
{
	static char vf[] = "VFn";

	if (i == DM_FUNC_PF)
		return "PF";
	else if (i == DM_FUNC_OVERALL)
		return "OVERALL";

	snprintf(vf, sizeof(vf), "VF%d", i - 1);
	return vf;
}

/**
 * TODO define macro when need to print ops
 */
void dm_domain_print_pci(const struct pci_cfg *pci)
{
	u64 va = -1;
	u64 pa = -1;
	u32 reg_bs = -1;
	u32 reg_sz = -1;
	u32 reg_total_sz = -1;
	u32 shm_bs = -1;
	u32 shm_sz = -1;
	u32 dma_ch = -1;
	u64 ob_mask = -1;
	const void *domain = pci->domain;

	print_debug("    pci_cfg<%ld bytes>\n", sizeof(*pci));
	print_debug("    pci_data<%ld bytes>\n", sizeof(*pci->data));
	print_debug("    num_of_bar<%d>\n", pci->data->num_of_bars);
	if (-1u == pci->data->num_of_bars)
		return;

	reg_total_sz = cn_dm_pci_get_bars_reg_total_sz(domain, 0);

	shm_bs = cn_dm_pci_get_bars_shm_bs(domain, 0);
	shm_sz = cn_dm_pci_get_bars_shm_sz(domain, 0);

	print_info("bar0: va[0x%llx] pa[0x%llx], reg(base[0x%x], size[0x%x])"
		   " reg_total_sz[0x%x]), shm(base[0x%x], sz[0x%x])\n",
		   va, pa, reg_bs, reg_sz, reg_total_sz, shm_bs, shm_sz);
	dma_ch = cn_dm_pci_get_dma_ch(domain);
	ob_mask = cn_dm_pci_get_ob_mask(domain);

	print_info("dma_ch[0x%x] ob_mask[0x%llx]\n", dma_ch, ob_mask);
}
DM_EXPORT_SYMBOL_GPL(dm_domain_print_pci);

void dm_domain_set_print_domain(const struct domain_type *domain)
{
	const struct pci_cfg *pci = &domain->pci;

	print_info("  domain[%s] state [0x%x: %s]\n",
		  dm_funcid2str(domain->func_id), domain->state,
		  dm_state2str(domain->state));
	if (domain == pci->domain && pci->data)
		dm_domain_print_pci(pci);

}
DM_EXPORT_SYMBOL_GPL(dm_domain_set_print_domain);

void dm_domain_set_print(const struct domain_set_type *set)
{
	u32 i;

	print_info("dump domain_set daemon_state<%s>\n",
					dm_state2str(set->daemon_state));
	if (set->overall)
		dm_domain_set_print_domain(set->overall);
	for (i = 0; i < sizeof(set->domains_mask) * BITS_PER_U8; i++) {
		if (BIT(i) & set->domains_mask) {
			struct domain_type *domain = dm_get_domain(
					(struct domain_set_type *)set, i);
			if (domain) {
				print_info("domain<%d>:\n", i);
				dm_domain_set_print_domain(domain);
			}
		}
	}
}
DM_EXPORT_SYMBOL_GPL(dm_domain_set_print);

int dm_is_func_overall(int func_id)
{
	return func_id == DM_FUNC_OVERALL;
}

int dm_is_func_pf(int func_id)
{
	return func_id == DM_FUNC_PF;
}

int dm_is_func_vf(int func_id)
{
	return func_id != DM_FUNC_PF && func_id != DM_FUNC_OVERALL
		&& func_id < DM_MAX_FUNCS;
}

int dm_check_domain_magic(struct domain_type *domain)
{
	u32 func_id;
	u64 magic;

	if (!domain)
		return 0;

	func_id = domain->func_id;
	magic = domain->magic;

	if (dm_is_func_vf(func_id) && DOMAIN_HOST_VF_MAGIC == magic)
		return 1;
	else if (dm_is_func_pf(func_id) && DOMAIN_HOST_PF_MAGIC == magic)
		return 1;
	else if (dm_is_func_overall(func_id) && DOMAIN_HOST_PF_MAGIC == magic)
		return 1;

	print_err("Invalid domainmagic<0x%llx>\n", magic);
	return 0;
}

struct domain_type *dm_get_domain(struct domain_set_type *set, u32 func_id)
{
	struct domain_type *domain = NULL;

	if (!set)
		return NULL;

	if (func_id == DM_FUNC_OVERALL) {
		domain = set->overall;
		if (!domain)
			return NULL;

	} else {

		if (func_id >= DM_MAX_FUNCS) {
			print_err("Invliad domain id, %u out of range %u \n",
				func_id, DM_MAX_FUNCS);
			return NULL;
		}

		if (!(set->domains_mask & BIT(func_id))) {
			print_err("%s: function<%d> does not exist\n",
					__func__, func_id);
			return NULL;
		}
		domain = set->domains[func_id];
	}
	if (!dm_check_domain_magic(domain)) {
		print_err("magic<%llx> invalid\n", domain->magic);
		return NULL;
	}
	return domain;
}
DM_EXPORT_SYMBOL_GPL(dm_get_domain);

void dm_mutex_lock(struct mutex *lock)
{
	mutex_lock(lock);
}

void dm_mutex_unlock(struct mutex *lock)
{
	mutex_unlock(lock);
}
