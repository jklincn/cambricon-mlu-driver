
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kthread.h>	//kthread_run
#include "include/domain.h"
//#undef print_debug
//#define print_debug(s, ...) do{}while(0)
#include "domain_private.h"
#include "cndrv_domain.h"
#include "cndrv_core.h"
#include "cndrv_kthread.h"

int dryrun = 0;

#define DM_IS_STATE(wanted)							\
int inline dm_is_state_##wanted(struct domain_type *domain)			\
{										\
	if ((domain && domain->state & (wanted))) {				\
		return 0;							\
	}									\
	print_err								\
	    ("domain is not in %s, could not register.(domain<%px>@%s(0x%x)\n",	\
	     dm_state2str(wanted), domain, dm_state2str(domain->state), domain->state);	\
	return -1;								\
}
/**
 * dm_is_state_DM_STATE_UNDEF
 * dm_is_state_DM_STATE_DEFINED
 */
DM_IS_STATE(DM_STATE_UNDEF)
DM_IS_STATE(DM_STATE_DEFINED)

/**
 * Return 1 if @val is valid
 */
static inline int __dm_is_valid_u32(u32 val)
{
	return (val !=0 && val < INVAL_U32);
}

/**
 * It is intended to move state to DM_STATE_DEFINED before register the ops.
 * TODO: finish the state machine.
 * TODO: register to all the vf when func_id == DM_FUNC_VF
 */
int dm_register_ops(struct domain_type *domain, enum module_id module,
		    struct dm_per_module_ops *new_ops,
		    void *new_priv, int is_locked)
{
	struct dm_per_module_ops **ops;
	void **top_priv;
	int ret = 0;

	if (!is_locked)
		domain->lock_func(&domain->lock);

	switch (module) {
	case PCI:
		ops = &domain->pci.ops;
		if (domain->pci.data)
			top_priv = &domain->pci.data->top_priv;
		else
			ret = -1;

		break;
	default:
		ret = -1;
		print_err("invalid module\n");
	}
	if (ret) {
		print_err
		    ("ERROR: register module<%s> ops<%px> to domain[%s: %px] "
		     "fail: data is empty\n", dm_module2str(module), new_ops,
		     dm_funcid2str(domain->func_id), domain);
		if (!is_locked)
			domain->unlock_func(&domain->lock);

		return ret;
	}

	if (*ops != NULL) {
		print_err
		    ("ERROR: register module<%s> ops<%px> to domain[%s: %px] "
		     "fail: ops already registered\n",
		     dm_module2str(module), new_ops,
		     dm_funcid2str(domain->func_id), domain);
		if (!is_locked)
			domain->unlock_func(&domain->lock);

		return 0;
	} else {
		*ops = new_ops;
		*top_priv = new_priv;
	}
	if (!ret)
		print_info
		    ("register module<%s> new_ops<%px> with top_priv<%px> to "
		     "domain[%s: %px] successful\n", dm_module2str(module),
		     *ops, *top_priv, dm_funcid2str(domain->func_id), domain);
	else
		print_err
		    ("register module<%s> new_ops<%px> with top_priv<%px> to "
		     "domain[%s: %px] failed\n", dm_module2str(module), *ops,
		     *top_priv, dm_funcid2str(domain->func_id), domain);

	if (!is_locked)
		domain->unlock_func(&domain->lock);

	return ret;
}

/**
 * unregister ops
 */
struct dm_per_module_ops *dm_unregister_ops(struct domain_type *domain,
					    enum module_id module, int is_locked)
{
	struct dm_per_module_ops *ops;

	if (!domain)
		return ERR_PTR(-EINVAL);

	if (!is_locked)
		domain->lock_func(&domain->lock);

	switch (module) {
	case PCI:
		ops = domain->pci.ops;
		domain->pci.ops = NULL;
		if (domain->pci.data) {
			domain->pci.data->top_priv = NULL;
			domain->pci.data->priv = NULL;
		}
		break;
	default:
		ops = NULL;
		print_err("invalid module\n");
	}
	if (!is_locked)
		domain->unlock_func(&domain->lock);

	return ops;
}

int dm_domain_initialization(struct domain_type *domain, u32 func_id)
{
	return 0;
}

void dm_domain_free_data(struct domain_type *domain)
{
        domain->magic = FIXME_U32;
	if (domain->pci.data) {
		if (domain->pci.data->shms) {
			dm_free(domain->pci.data->shms);
			domain->pci.data->shms = NULL;
		}
		if (domain->pci.data->bars) {
			dm_free(domain->pci.data->bars);
			domain->pci.data->bars = NULL;
		}
		dm_free(domain->pci.data);
	}
	if (domain->resource_cache) {
		dm_free(domain->resource_cache);
	}
}

static struct domain_type *dm_alloc_domain(
				struct domain_set_type *set, u32 func_id)
{
	struct domain_type *domain;
	struct bar_cfg *bars = NULL;
	struct shm_cfg *shms = NULL;

	domain = dm_zalloc(sizeof(struct domain_type));
	if (!domain)
		return NULL;

	mutex_init(&domain->lock);
	domain->lock_func = dm_mutex_lock;
	domain->unlock_func = dm_mutex_unlock;
	domain->version = 0xfefefefe;	//fe means fix me!
	domain->func_id = func_id;
	domain->bdf = 0xfefefefe;
	domain->set = set;
	domain->pci.domain = (void *)domain;
	domain->pci.data = dm_zalloc(sizeof(struct pci_data));
	if (!domain->pci.data) {
		print_err("pci data allocation failed\n");
		goto err_free;
	}
	domain->pci.data->num_of_shms = 5;	//1 for inbound, 4 for outbound
	shms = dm_calloc(domain->pci.data->num_of_shms, sizeof(struct shm_cfg));
	if (!shms)
		goto err_free;

	domain->pci.data->shms = shms;
	domain->pci.data->num_of_bars = 1;
	bars = dm_calloc(domain->pci.data->num_of_bars, sizeof(struct bar_cfg));
	if (!bars)
		goto err_free;

	domain->pci.data->bars = bars;
	domain->state = DM_STATE_CONFIGURED;
	return domain;
err_free:
	if (domain->pci.data)
		dm_free(domain->pci.data);

	if (shms)
		dm_free(shms);

	if (bars)
		dm_free(bars);

	dm_free(domain);
	return NULL;
}

struct domain_type *dm_alloc_vf_domain(struct domain_set_type *set, u32 func_id)
{
	struct domain_type *domain;

	domain = dm_alloc_domain(set, func_id);
	domain->magic = DOMAIN_HOST_VF_MAGIC;
	return domain;
}

struct domain_type *dm_alloc_pf_domain(struct domain_set_type *set, u32 func_id)
{
	struct domain_type *domain;

	domain = dm_alloc_domain(set, func_id);
	domain->magic = DOMAIN_HOST_PF_MAGIC;
	return domain;
}

void dm_free_domain_set(void **domain_set)
{
	int i;
	struct domain_set_type **set = (struct domain_set_type **)domain_set;

	if (!set || !(*set))
		return;

	for (i = 0; i < DM_MAX_FUNCS; i++) {
		if ((*set)->domains[i]) {
			dm_domain_free_data((*set)->domains[i]);
			dm_free((*set)->domains[i]);
		}
	}
	if ((*set)->overall) {
		dm_domain_free_data((*set)->overall);
		dm_free((*set)->overall);
	}
	if ((*set)->attr) {
		dm_free((*set)->attr);
	}
	dm_free((*set));
	(*set) = NULL;
}

int __dm_scale_domains(struct domain_set_type *set, unsigned long domains_mask)
{
	struct domain_type *domains;
	int i;
	int ret = -1;

	set->lock_func(&set->lock);
	for (i = DM_FUNC_VF0; i < DM_MAX_FUNCS; i++) {
		if (BIT(i) & domains_mask) {
			if (set->domains[i]) {
				dm_domain_free_data(set->domains[i]);
				dm_free(set->domains[i]);
				set->domains[i] = NULL;
			}

			domains = dm_alloc_vf_domain(set, i);
			if (domains == NULL) {
				cn_domain_err(set, "No mem");
				ret = -ENOMEM;
				goto err_free;
			}
			set->domains[i] = domains;
			continue;
		}

		if (set->domains[i]) {
			dm_domain_free_data(set->domains[i]);
			dm_free(set->domains[i]);
			set->domains[i] = NULL;
		}
	}
	cn_domain_info(set, "Scale function by domains_mask 0x%lx done",
								domains_mask);
	set->domains_mask = domains_mask;
	set->unlock_func(&set->lock);
	ret = 0;
	return ret;
err_free:
	for (i = DM_FUNC_VF0; i < DM_MAX_FUNCS; i++) {
		dm_domain_free_data(set->domains[i]);
		dm_free(set->domains[i]);
		set->domains[i] = NULL;
	}
	set->unlock_func(&set->lock);
	return ret;
}

int dm_register_ops_kernel(void *domain_set, u32 func_id, enum module_id module,
				struct dm_per_module_ops *ops, void *priv)
{
	struct domain_type *domain;
	struct domain_set_type *set = domain_set;
	int i;
	int ret = -1;

	if (!set || !ops || !ops->init || !ops->exit)
		return ret;

	set->lock_func(&set->lock);
	if (set->daemon_state < DM_STATE_STARTED) {
		cn_domain_info(set, "daemon is not started. register to PF or the only VF");
		domain = dm_get_domain(set, func_id);
		if (!domain) {
			cn_domain_err(set, "Could not get domain[%d] from domains<%px> "
				   "of set<%px>.", func_id, set->domains, set);
			ret = -EINVAL;
			goto exit;
		}
		ret = dm_register_ops(domain, module, ops, priv, 0);
	} else if (DM_STATE_STARTED == set->daemon_state) {
		if (dm_is_func_pf(func_id)) {
			cn_domain_info(set, "daemon is started. register to PF");
			domain = dm_get_domain(set, func_id);
			if (!domain) {
				cn_domain_err(set, "Could not get domain[%d] from "
					  "domains<%px> of set<%px>.", func_id,
					  set->domains, set);
				ret = -EINVAL;
				goto exit;
			}
			ret = dm_register_ops(domain, module, ops, priv, 0);
		} else if (dm_is_func_vf(func_id)) {
			cn_domain_info(set, "daemon is started. register to all VFs");
			for (i = DM_FUNC_VF0; i < sizeof(set->domains_mask) * BITS_PER_U8; i++) { if (BIT(i) & set->domains_mask) {
					struct domain_type *domain
						= dm_get_domain(set, i);

					if (!domain) {
						cn_domain_err(set, "Domain[%i] do not initialized properly.",
						i);
						ret = -EFAULT;
						goto exit;
					}
					ret = dm_register_ops
						(domain, module, ops, priv, 0);
				}
			}
		} else {
			cn_domain_err(set, "Error: invalid function id<%d>", func_id);
		}
	} else {
		cn_domain_err(set, "Error: per-module ops could not be registered after"
			  " %s state(current state: %s)",
			  dm_state2str(DM_STATE_STARTED),
			  dm_state2str(set->daemon_state));
	}
exit:
	set->unlock_func(&set->lock);
	return ret;
}
DM_EXPORT_SYMBOL_GPL(dm_register_ops_kernel);

/**
 * unregister all the VFs(if func_id == DM_FUNC_VF) or PF
 * (if func_id == DM_FUNC_PF)
 */
struct dm_per_module_ops *dm_unregister_ops_kernel(void *domain_set, u32 func_id,
						   enum module_id module)
{
	u32 func_id_start = -1;
	u32 func_id_end = -1;
	struct dm_per_module_ops *ops = NULL;
	struct domain_set_type *set = domain_set;
	int i;

	if (!set)
		return ERR_PTR(-EINVAL);

	set->lock_func(&set->lock);
	if (dm_is_func_pf(func_id)) {
		func_id_start = DM_FUNC_PF;
		func_id_end = DM_FUNC_PF;
	} else if (dm_is_func_vf(func_id)) {
		func_id_start = DM_FUNC_VF0;
		func_id_end = DM_FUNC_OVERALL - 1;
	} else {
		cn_domain_err(set, "Do not support func_id[%d: %s]\n", func_id,
			  dm_funcid2str(func_id));
		return ERR_PTR(-EINVAL);
	}
	for (i = func_id_start; i < sizeof(set->domains_mask) * BITS_PER_U8; i++) {
		if (BIT(i) & set->domains_mask && i <= func_id_end) {
			struct domain_type *domain = dm_get_domain(set, i);
			if (!domain) {
				cn_domain_err(set, "func[%i] not inited", i);
				ops = ERR_PTR(-EFAULT);
				goto exit;
			}
			ops = dm_unregister_ops(domain, module, 0);
		}
	}
exit:
	set->unlock_func(&set->lock);
	return ops;
}
DM_EXPORT_SYMBOL_GPL(dm_unregister_ops_kernel);

static void kheartbeatd(void *priv)
{
	struct domain_set_type *set = (struct domain_set_type *)priv;
	struct cn_core_set *core;

	if (!set || !set->core)
		return;

	core = set->core;
	if ((set->daemon_state == DM_STATE_DEFINED
		|| set->daemon_state == DM_STATE_INIT)
		&& core->state != CN_RUNNING) {
		print_debug("ERROR: invalid state<%s>. Domain manager"
			  " init failed!!!\n",
			  dm_state2str(set->daemon_state));
	} else if (set->daemon_state == DM_STATE_INIT) {
		print_info_once("waiting for domain configuration\n");
	}

	#ifdef DM_UT_TEST_GLOBAL_ENABLE
	dm_ut_test_start(set);
	#endif
}

#define KHEARTBEATD_PERIOD 1000  // ms
int dm_launch_kdaemon(struct domain_set_type *set)
{
	struct cn_core_set *core = set->core;
	struct cn_kthread_set *kthread_set;
	char *kthread_name;
	struct cn_kthread_t t;
	void *ret;

	kthread_set = dm_zalloc(sizeof(struct cn_kthread_set));
	set->daemon = (void *)kthread_set;
	kthread_name = kthread_set->name;
	snprintf(kthread_name, 64, "kheartbeatd_%d", core->idx);

	t.name = kthread_name;
	t.expire = KHEARTBEATD_PERIOD;
	t.fn = kheartbeatd;
	t.arg = (void *)set;
	t.type = CN_TIMER_GLOBAL;

	ret = cn_timer_kthread_register(core, &t);
	if (!ret) {
		print_err("kheartbeatd register error");
		return -1;
	}

	kthread_set->node = (struct list_head *)ret;

	return 0;
}

int dm_stop_kdaemon(struct domain_set_type *set)
{
	struct cn_core_set *core = set->core;
	struct cn_kthread_set *kthread_set = set->daemon;

	if (kthread_set) {
		cn_timer_kthread_unregister(core, kthread_set->node);
		print_info("kheartbeatd unregisterd");
		dm_free(kthread_set);
	}

	set->daemon_state = DM_STATE_UNDEF;

	return 0;
}
