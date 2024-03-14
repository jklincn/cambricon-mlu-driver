#include "cndrv_debug.h"

#ifndef __INCLUDE_DOMAIN_H__
#define __INCLUDE_DOMAIN_H__

#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/slab.h>		//kzalloc, kcalloc
#include <linux/mmu_notifier.h>
#include <linux/kobject.h>      //kobject
#include <linux/vfio.h>
#include "cndrv_core.h"
#include "cndrv_domain.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif

/**
 * TEST MACRO
 * DM_TEST_BASE: Test the infrastructure of domain.
 * DM_DUMMY_PER_MODULE_OPS_TEST: register domain per module ops in domain
 *     initialization in order to test module ops registration and calling.
 */
#define DM_TEST_BASE
//#define DM_DUMMY_PER_MODULE_OPS_TEST

/**
 * 46: 'F'
 * 4b: 'K'
 * 4c: 'L'
 * 4f: 'O'
 * 64: 'd' means device
 * 68: 'h' means host
 * 70: 'p' means pf
 * 76: 'v' means vf
 */
#define DOMAIN_MAGIC		(0xcabc0000)
#define DOMAIN_DEVICE_VF_MAGIC	(DOMAIN_MAGIC | 0x6476)
#define DOMAIN_DEVICE_PF_MAGIC	(DOMAIN_MAGIC | 0x6470)
#define DOMAIN_HOST_VF_MAGIC	(DOMAIN_MAGIC | 0x6876)
#define DOMAIN_HOST_PF_MAGIC	(DOMAIN_MAGIC | 0x6870)

#define DOMAIN_RPC_OK		(DOMAIN_MAGIC | 0x4f4b)
#define DOMAIN_RPC_FAIL		(DOMAIN_MAGIC | 0x464c)

#define KB(x)			((x) * 1024)
#define MB(x)			(KB(x) * 1024)

#define __domain_print(fn, level, domain, str, arg...) \
do { \
       if (domain && domain->core) \
               fn("%s: [%s][%s][%d][CPU %d]: " str "\n", \
                       level, domain->core->core_name, __func__, \
                       __LINE__, raw_smp_processor_id(), ##arg); \
       else \
               fn("%s: [%s][%d][CPU %d]: " str "\n", \
                       level, __func__, __LINE__, \
                       raw_smp_processor_id(), ##arg); \
} while (0)


#define cn_domain_info(domain, str, arg...) \
       __domain_print(pr_info, "DM_Info", (domain), str, ##arg)

#define cn_domain_err(domain, str, arg...) \
       __domain_print(pr_err, "DM_Err", (domain), str, ##arg)

//#define DOMAIN_DEBUG
#ifdef DOMAIN_DEBUG
#define cn_domain_debug(domain, str, arg...) \
	__domain_print(pr_info, "DM_Debug", (domain), str, ##arg);
#else
#define cn_domain_debug(domain, str, arg...)
#endif
#define cn_domain_warn(domain, str, arg...) \
       __domain_print(pr_warn, "DM_Warn", (domain), str, ##arg)

//print wrapper in kernel
#define print(fmt, ...) printk("Domain: [%s][%d][CPU %d]: "fmt, __FUNCTION__, __LINE__, raw_smp_processor_id(), ##__VA_ARGS__)
#define print_crit(fmt, ...) pr_crit("DM_Crit: [%s][%d][CPU %d]: "fmt, __FUNCTION__, __LINE__, raw_smp_processor_id(), ##__VA_ARGS__)
#define print_err(fmt, ...) pr_err("DM_Err:[%s][%d][CPU %d]: "fmt, __FUNCTION__, __LINE__, raw_smp_processor_id(), ##__VA_ARGS__)
#define print_info(fmt, ...) pr_info("DM_Info: [%s][%d][CPU %d]: "fmt, __FUNCTION__, __LINE__, raw_smp_processor_id(), ##__VA_ARGS__)
#define print_info_once(fmt, ...) pr_info_once("DM_Info: [%s][%d][CPU %d]: "fmt, __FUNCTION__, __LINE__, raw_smp_processor_id(), ##__VA_ARGS__)
#define print_debug(fmt, ...) pr_debug("DM_DBG: [%s][%d][CPU %d]: "fmt, __FUNCTION__, __LINE__, raw_smp_processor_id(), ##__VA_ARGS__)
#define print_warn(fmt, ...) pr_warn("DM_Warn: [%s][%d][CPU %d]: "fmt, __FUNCTION__, __LINE__, raw_smp_processor_id(), ##__VA_ARGS__)
#define raw_print printk
#ifndef DOMAIN_DEBUG
#  define raw_print_debug(fmt,...) do{}while(0)
#else
#  define raw_print_debug(fmt,...) printk(fmt, ##__VA_ARGS__)
#endif /* DOMAIN_DEBUG == DOMAIN_DEBUG_DISABLE */

#define dm_asprintf(fmt, ...)  kasprintf(GFP_KERNEL, fmt, ##__VA_ARGS__)
//memory wrapper in kernel
#define dm_calloc(n, s)	cn_kcalloc(n, s, GFP_KERNEL)
#define dm_zalloc(s)	cn_kzalloc(s, GFP_KERNEL)
#define dm_free(s)	cn_kfree(s)

#define DM_MAX_VFS (8)
#define DM_MAX_FUNCS (DM_MAX_VFS + 1)
#define FIXME_U32 (0xfefefefe)
#define INVAL_U32 (0xf0000000)
#define MEMSET_U8 (0xfd)		//0xfd: d means domain manager

struct pci_cfg;
struct domain_type;

/**
 * The attribute ops should check the state before do get/set the ops.
 *
 * ref the domain-manager-arch in jira: C20-1271
 */
enum dm_state {
	/**
	 * Configuration range from 0x1 to 0x80
	 */
	/**
	 * The default state of domain. It means that such domain requirement
	 * is not inputed by user. Or such domain is undefined by dm_undef_domain.
	 */
	DM_STATE_UNDEF = 0x1,
	/**
	 * Only valid for the module which need to reserve resource before the
	 * real allocation. In the state, module could get the minimal
	 * resources. Such resource maybe changed after state transfered to
	 * DM_STATE_DEFINED.
	 */
	DM_STATE_RESERVED = 0x2,
	/**
	 * After domain requirement is set by user through dm_set_domain_cfg.
	 * Domain state change from DM_STATE_UNDEF to DM_STATE_CONFIGURED.
	 */
	DM_STATE_CONFIGURED = 0x4,
	/**
	 * After domain manager calcuate and allcoate all the DM_STATE_CONFIGURED
	 * domain. state change from DM_STATE_CONFIGURED to DM_STATE_DEFINE by
	 * dm_def_domain.
	 */
	DM_STATE_DEFINED = 0x8,
	/**
	 * Initialization and exiting range: from 0x100 to 0x8000
	 */
	DM_STATE_EARLY_INIT = 0x100,
	/**
	 * for domain:
	 * set init when domain manager notify module to do the domain init.
	 * after all the module in such domain finish init. domain switch to
	 * DM_STATE_STARTED.
	 *
	 * for daemon:
	 * set when daemon thread started. transfer to started after
	 * handshaking
	 */
	DM_STATE_INIT = 0x200,
	/**
	 * When domain manager receive "domain_init", domain manager will call
	 * all the init domain function registered by each module. Ater
	 * initialization, domain manager will set domain state to DM_STATE_RUNING.
	 * If fail, raise error and keep state as DM_STATE_DEFINED.
	 *
	 * Notes that it might be allowed that change the domain configration
	 * during domain running in future.
	 */
	DM_STATE_STARTED = 0x400,
	/**
	 * Live upgrade and live migration range. start from 0x1 0000 to 0x80 0000
	 */
	/**
	 * for virtual machine suspend
	 */
	DM_STATE_SUSPEND = 0x10000,
	/**
	 * for virtual machine migration
	 */
	DM_STATE_MIGRAING = 0x20000,
	DM_STATE_MIGRAING_START = 0x20000,
	/**
	 * Any failure state: start from 0x100 0000 to 0x8000 0000
	 */
	DM_STATE_FAILURE = 0x1000000,
	//
	DM_STATE_INVALID = 0x2000000
};

/**
 * dm_overall_ops
 *
 * The overall operation of domain.
 * The idea of def, undef, alloc and free came from libvirt api. At the moment,
 * hotplog or alloc/free for dedidated resources(e.g. alloc 1 video encoder) is
 * not supported.
 *
 * It is rpc in host(vf and pf) side, function in device side.
 */
struct dm_overall_ops {
	/**
         * return priv for module. priv will be passed to function
         * in dm_per_module_ops.
         */
	//proc->data.priv = init(domain);
	int (*init) (struct domain_type * cfg);
	int (*reset) (struct domain_type * cfg);
	/**
         * Exit domain and release all the resource.
         */
	int (*exit) (struct domain_type * cfg);
	/* switch from DM_STATE_STARTED to DM_STATE_MIGRAING */
	int (*save_prepare)(struct domain_type *cfg);
	/* switch from DM_STATE_MIGRAING to DM_STATE_STARTED */
	int (*restore_complete)(struct domain_type *cfg);
	/**
         * stop and reinit for living updating.
         */
	int (*stop) (struct domain_type * cfg);
	int (*reinit) (struct domain_type * cfg);
};

enum shm_type {
	IN_BOUND,
	OUT_BOUND_HOST,
	OUT_BOUND_AXI,
};

struct bar_cfg {
	u64 va;
	u64 pa;
	u32 sz;
	u32 reg_bs;
	u32 reg_sz;
	u32 reg_total_sz;
	u32 shm_bs;
	u32 shm_sz;
	u64 shm_va;
	u32 rsrvd_shm_sz;
	u32 rsrvd_shm_bs;
};

/**
 * share memory(in bound)
 * share memory(out bound)
 *
 * Define as 32bit make it easier to pass it through mailbox before
 * ctrlq is ready. The next generation of edge only support 32bit
 * mailbox.
 */
struct shm_cfg {
	enum shm_type type;
	u64 bs;
	u64 sz;
	u64 max_sz;
	u64 ch;
};

/**
 * Notes that set_xxx function could be only called in DOMAIN_UNDEF or
 * DOMAIN_CONFIGURED state.
 */
struct dma_cfg {
	u32 ch;
};

struct ob_cfg {
	unsigned long mask;
};

struct sram_cfg {
	u64 pa;
	u64 sz;
};

struct large_bar_cfg {
	u64 bs;
	u64 sz;
};

struct mem_cfg_info_s {
	u64 phys_card_idx;
	u64 size_limit;
};

struct pci_data {
	u32 num_of_shms;
	//TODO split to bar and share memory
	struct shm_cfg *shms;
	//should set num to 5, for bar0, 2, 4.
	u32 num_of_bars;
	struct bar_cfg *bars;
	struct dma_cfg dma;
	struct pci_reg_data *reg;
	struct ob_cfg ob;
	struct sram_cfg sram;
	struct large_bar_cfg large_bar;
	struct mem_cfg_info_s mem_cfg;
	u64 rsrvd[2];
	void *priv;
	void *top_priv;
};

/**
 * @num_of_shm: number of share memory, we could not pre alloc the share memory
 *              because it is read from hw info. so as to @num_of_bar
 *
 * Example usage of memory
 * domain = dm_get_domain(dm_get_domain_set(), i);
 * u64 va = get_bars_va(&domain->pci, 0);
 * u64 pa = get_bars_pa(&domain->pci, 0);
 * u32 reg_total_sz = get_bars_reg_sz(&domain->pci, 0); //128M
 * u32 shm_bs_va = va + reg_total_sz + get_bars_shm_bs(&domain->pci, 0); //PF: 0; VF0: 64M
 * u32 shm_bs_pa = pa + reg_total_sz + get_bars_shm_bs(&domain->pci, 0); //PF: 0; VF0: 64M
 * u32 shm_sz = get_bars_shm_sz(&domain->pci, 0); //PF: 64M; VF0: 16M
 *
 */
struct pci_cfg {
	void *domain;
	struct kobject kobj;
	struct pci_data *data;
	enum dm_state state;
	struct dm_per_module_ops *ops;
};

#if (defined(VFIO_GROUP_NOTIFY_SET_KVM)&&defined(CONFIG_MMU_NOTIFIER))
#define MMU_RELEASE_NOFIFIER
#endif

struct domain_set_type;
/**
 * include struct instead of pointer. make it easier to get func_id
 * in upper &struct domain_type.
 *
 * PF: 4M BAR0 share memory. ARM cluster and dedicated memory.
 *
 * &lock: lock in kernel or userspace. TODO use __KERNEL__
 * &version: the version of domain. for userspace and kernel.
 * &func_id
 */
struct domain_type {
	struct domain_set_type *set;
	struct mutex lock;
	void (*lock_func) (struct mutex * lock);
	void (*unlock_func) (struct mutex * lock);
	u64 magic;
	u64 version;
	u32 func_id;
	u32 bdf;
	enum dm_state state;
	struct dm_overall_ops *ops;
	struct pci_cfg pci;
	void *resource_cache;
#ifdef MMU_RELEASE_NOFIFIER
	struct notifier_block gp;
	struct mmu_notifier mn;
	struct kvm *k;
#endif
};

/**
 * @core: poiner to the upper struct
 * @daemon: save the pointer of list_head node returned by kthread_register
 *	    and the kthread name
 * @overall: hold all the resource of the dedicated hw(board, wafer and so on).
 * @domains_mask: domain mask for valid domain in @domains. In PF only and VF
 *           mode, there are both PF and VF. Only corresponding PF and VF is
 *           valid. In PF sriov mode, it is valid when set->daemon_state
 *           between [DM_STATE_STARTED, DM_STATE_FAILURE).
 * @domains: DM_FUNC_PF: pf; DM_FUNC_VF + 0 .. n-1: vf(1-n). The resources of
 *           domain whether user input(DM_STATE_CONFIGURED,
 *           DM_STATE_USER_CONFIGURED) or defined(DM_STATE_DEFIEND) reference
 *           DM_STATE_ for all the information.
 */
struct domain_set_type {
	struct cn_core_set *core;
	enum dm_state daemon_state;
	void *daemon;
	struct mutex lock;
	void (*lock_func) (struct mutex * lock);
	void (*unlock_func) (struct mutex * lock);
	u64 device_id;
	void *ep_rpc;
	struct domain_type *overall;
	unsigned long domains_mask;
	void *attr;
	struct domain_type *domains[DM_MAX_FUNCS];

	int mim_enable;
	/* core support mim operation */
	int is_mim_support;
	/* device support mim platform */
	u32 mim_dev_support;
	u32 mlu_instance_mask;
	struct mutex mim_lock;
};

/**
 * RPC relative data.
 */
/**
 *
 * @func_id: valid when rpc set vf_id to COMMU_PF.
 */
struct dm_rpc_pkg_hdr {
	u64 ret;
	u64 hash;	//reserved for future.
	u32 offset;
	u32 size;
	u32 func_id;
	u64 version;
	enum module_id module;
};

struct dm_rpc_pkg {
	struct dm_rpc_pkg_hdr hdr;
	void *priv;
};

/**
 * dm_domain_init_default()
 *
 * This function is used to initialized default data of domain besides module
 * configuration.
 * @domain: domain cfg need to be init
 * @func_id: set function id in domain->func_id
 */
void dm_domain_init_default(struct domain_type *domain, u32 func_id);

/**
 * dm_domain_initialization()
 *
 * initialized the domain according to the given function id. alloc data in each module.
 */
int dm_domain_initialization(struct domain_type *domain, u32 func_id);

/**
 * Free domain data in each domain. Do not free the domain.
 */
void dm_domain_free_data(struct domain_type *domain);

/**
 * Copy domain struct and data pointer in each module if exist and set
 * module->domain as dst;
 *
 * dm_domain_dup_priv is used to duplicated the private pointer of each
 * module from source domain to destination domain. It must be called
 * before domain init(rpc). Because after init, priv of data of module will
 * be replaced by per domain private pointer.
 */
void dm_domain_dup(struct domain_type *dst, struct domain_type *src);

/**
 * Copy priv of module->data from @src to @dst
 */
void dm_domain_dup_priv(struct domain_type *dst, struct domain_type *src);

void dm_domain_copy_per_module_ops(struct domain_type *dst,
				   struct domain_type *src);


/**
 * It is designed to monitor the domain changes in order to do somethings
 * by the service/daemon of module. return the wanted state.
 *
 * TODO add timeout. and nonblock wait
 */
void dm_wait_state(enum module_id module, enum dm_state wanted);

/**
 * domain set apis
 */
/**
 * allocation domain_set_type and domains.
 */
struct domain_set_type *dm_alloc_domain_set(u32 num_of_func);
struct domain_set_type *dm_alloc_and_init_domain_set(u32 num_of_func);
void dm_free_domain_set(void **set);

/**
 * dm_expand_domains()
 *
 * This function is used to expand domain to @domains_mask.
 *
 * @domains_mask: the valid domain which will be expanded to. The mask should be
 * contiguous.
 *
 * @dm_expand_domains will expand the current @set->domains to @domains_mask.
 * It will copy the following things:
 * 1. domain configuration, such as func_id.
 * 2. copy the data and ops(@dm_per_module_ops) of each module from PF to PF
 * and VF0 to all VFs. E.g. copyset->domains[VF0].pci.data all the VFs.
 * It WILL NOT copy the ops of each domain. e.g. get_cores. Such ops is copied
 * during domain initialization(@dm_domain_initialization).
 *
 */
int dm_expand_domains(struct domain_set_type *set, unsigned long domains_mask);

/**
 * domain level apis
 */
/**
 * get domain by domain_set
 */
struct domain_type *dm_get_domain(struct domain_set_type *set, u32 func_id);

/**
 * Return 0 means magic is valid
 */
int dm_check_domain_magic(struct domain_type *domain);

struct domain_type *dm_alloc_domains(u32 num_of_func);
struct domain_type *dm_alloc_and_init_domains(u32 num_of_func);

/**
 * launch and stop daemon. In host side: it is heartbeat. In device side, it is
 * domain manager daemon.
 *
 * This daemon itself should set set->daemon_state to DM_STATE_DEFINED in order
 * to indicate domain manager is ready to handle domain level request.
 */
int dm_launch_kdaemon(struct domain_set_type *set);
int dm_stop_kdaemon(struct domain_set_type *set);

int dm_undef_domain(struct domain_set_type *set, unsigned long mask);

//util function
enum dm_state dm_str2state(const char *str);
const char *dm_state2str(enum dm_state state);
enum module_id dm_str2module(const char *str);
const char *dm_module2str(enum module_id id);
//return 0 suc, -1 fail
int dm_check_state(enum dm_state cur, enum dm_state next);
char *dm_funcid2str(u32 i);
void dm_domain_set_print_domain(const struct domain_type *domain);
void dm_domain_set_print(const struct domain_set_type *set);
void dm_domain_print_pci(const struct pci_cfg *pci);
const char *dm_get_domain_path(struct domain_type *domain);
int dm_is_func_vf(int func_id);
int dm_is_func_pf(int func_id);
int dm_is_func_overall(int func_id);

#define DM_RPC_ok	("okok")
#define DM_RPC_fail	("fail")

#define DM_IS_RPC(state)							\
	static inline int dm_is_rpc_##state(void *buf) 				\
	{									\
		return !strncmp(buf, DM_RPC_##state, strlen(DM_RPC_##state));	\
	}

#define DM_SET_RPC(state)							\
	static inline void dm_set_rpc_##state(void *out_msg, int *out_len)	\
	{									\
		strcpy(out_msg, DM_RPC_##state);				\
		*out_len = sizeof(DM_RPC_##state);				\
	}

/**
 * dm_is_rpc_ok
 * dm_set_rpc_ok
 * dm_is_rpc_fail
 * dm_set_rpc_fail
 */
DM_IS_RPC(ok)
DM_SET_RPC(ok)
DM_IS_RPC(fail)
DM_SET_RPC(fail)

/* misc.c */
void dm_mutex_lock(struct mutex *lock);
void dm_mutex_unlock(struct mutex *lock);
/* misc.c */
#endif /* __INCLUDE_DOMAIN_H__ */
