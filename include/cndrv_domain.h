
#ifndef __CNDRV_DOMAIN_H__
#define __CNDRV_DOMAIN_H__

#include "cndrv_core.h"

#define BITS_PER_U8 (8)

enum IGNORE_ERR_MODE {
	NOT_IGNORE = 0,
	DO_IGNORE
};

enum TRIGGER_MODE {
	PF = 0x1,
	VF = 0x2,
	SRIOV = 0x4
};

/*
 * A structure used in domain_trigger_modules_init/exit after connection with
 * device. It should be initialized in the following late_fn_t array.
 *
 * @late_init: pointer of late init function
 * @late_exit: pointer of late exit function
 * @name: module's name of the funtion, used for printing log
 * @trigger_mode: in which dm_work_mode this module will be implemented
 * @flag: ignore or not the error when late init function return false
 */
struct late_fn_s {
	int (*late_init)(struct cn_core_set *core);
	void (*late_exit)(struct cn_core_set *core);
	const char *name;
	enum TRIGGER_MODE trigger_mode;
	enum IGNORE_ERR_MODE flag;
};

struct late_fn_s *cn_dm_get_late_fn_t(void);
int cn_dm_get_late_fn_num(void);
struct fn_state_s *cn_dm_get_late_fn_state(int idx);

/**
 * FIXME: switch to DM_XXX gradually.
 * DM_PMU: cnperf, cndev
 */
enum module_id {
	//INVALID, //comment out INVALID in order to get number of process and module easier.
	FIRST_MODULE,
	FIRST_PROCESSOR = FIRST_MODULE,
	TESTU = FIRST_PROCESSOR,
	DM_IPU,
	DM_VPU,
	DM_JPU,
	LAST_PROCESSOR = DM_JPU,
	DM_MEM,
	DM_PCI,
	DM_PMU,
	DM_COMMU,
	DM_CRYPTO,
	DM_VPU_ENC,
	DM_GDMA,
	DM_NUM_OF_MODULE,
	DM_INVALID_MODULE,
	NUM_OF_U = LAST_PROCESSOR + 1,
	IPU = DM_IPU,
	VPU = DM_VPU,
	JPU = DM_JPU,
	MEM = DM_MEM,
	PCI = DM_PCI,
	NUM_OF_MODULE = DM_NUM_OF_MODULE,
};

enum func_id_type {
	DM_FUNC_PF,
	DM_FUNC_VF0,
	DM_FUNC_VF = DM_FUNC_VF0,
	//the last one is overall domain
	DM_FUNC_OVERALL = sizeof(unsigned long) * BITS_PER_U8 - 1,
	DM_FUNC_ALL = DM_FUNC_OVERALL - 1
};

enum dm_dev_mim_support {
	DM_MIM_DEV_NOT_SUPPORT = 0,
	DM_MIM_DEV_SUPPORT = 1,
	DM_MIM_DEV_NOT_INIT = 0xff,
};

/**
 * dm_per_module_ops
 *
 * Register by dm_register_ops for dedicated module.
 *
 */
struct dm_per_module_ops {
	int (*early_init) (const void *cfg);
	/**
         * Init domain. @priv is provided by module in dm_register_ops_xxx.
	 */
	void *(*init) (const void *cfg, void *priv);
	int (*reset) (void *priv);
	/**
         * Exit domain and release all the resource.
         */
	int (*exit) (void *priv);
	/* switch from DM_STATE_STARTED to DM_STATE_MIGRAING */
	int (*save_prepare)(void *priv);
	/* switch from DM_STATE_MIGRAING to DM_STATE_STARTED */
	int (*restore_complete)(void *priv);
	/**
         * stop and reinit for living updating.
         */
	int (*stop) (void *priv);
	void *(*reinit)(const void *cfg, void *priv);
};

/**
 * dm_register_ops
 *
 * This function is used to register the operation of module for a
 * given domain.
 *
 * If the @ops is registered before DM_STATE_STARTED, after domain manager
 * know the real number of virtual function(s), the registered ops will be
 * copied from DM_FUNC_VF0 to other VFs.
 * The @ops could not be registered after DM_STATE_STARTED.
 *
 * @priv: The private data provided by module. In host/device side, module may
 *        need this to get the top level core struct. e.g. @cn_core_set
 *
 * Return: return negative value if domain is not ready to be registered.
 */
int dm_register_ops_kernel(void *domain_set, u32 func_id, enum module_id module,
				struct dm_per_module_ops *ops, void *priv);
//TODO: convert to kernel and userspace common function if needed
struct dm_per_module_ops *dm_unregister_ops_kernel(void *domain_set, u32 func_id,
						   enum module_id module);

/* rpc_interface.c */
s32 dm_compat_rpc(void *domain_set, char *name,
		void *in, int in_size, void *out, int *out_size, s32 buf_sz);

u32 cn_dm_pci_get_bars_reg_total_sz(const void *domain, u32 idx);
u32 cn_dm_pci_get_bars_shm_bs(const void *domain, u32 idx);
u32 cn_dm_pci_get_bars_shm_sz(const void *domain, u32 idx);
u32 cn_dm_pci_get_dma_ch(const void *domain);
u32 cn_dm_pci_get_ob_mask(const void *domain);
u64 cn_dm_pci_get_sram_pa(const void *domain);
u64 cn_dm_pci_get_sram_sz(const void *domain);
u64 cn_dm_pci_get_large_bar_bs(const void *domain);
u64 cn_dm_pci_get_large_bar_sz(const void *domain);
u64 cn_dm_pci_get_mem_cfg_phys_card_idx(const void *domain);

u32 cn_dm_get_func_id(const void *domain);
u32 cn_dm_get_vf_func_id(const void *domain);
int cn_dm_get_vf_idx_by_domain_id(int domain_id);

unsigned long cn_dm_get_domain_mask(void *set);

/**
 * cn_dm_attr_* - domain interfaces for device attribute acquisition
 *
 * Those functions return 0 on not support or negative on fail,
 * positive means support or resource number.
 */
/* CN_DEVICE_ATTRIBUTE_TINY_CORE_SUPPORTED */
s32 cn_dm_attr_tiny_core_mask(struct cn_core_set *core);
/* CN_DEVICE_ATTRIBUTE_CODEC_JPEG_SUPPORTED */
s32 cn_dm_attr_jpeg_codec_mask(struct cn_core_set *core);
/**
 * CN_DEVICE_ATTRIBUTE_CODEC_H264_SUPPORTED
 * CN_DEVICE_ATTRIBUTE_CODEC_H265_SUPPORTED
 */
s32 cn_dm_attr_video_codec_mask(struct cn_core_set *core);
/* CN_DEVICE_ATTRIBUTE_MAX_CLUSTER_COUNT */
s32 cn_dm_attr_cluster_num(struct cn_core_set *core);
/* CN_DEVICE_ATTRIBUTE_MAX_QUADRANT_COUNT */
s32 cn_dm_attr_quadrant_num(struct cn_core_set *core);
/* CN_DEVICE_ATTRIBUTE_MAX_L2_CACHE_SIZE */
s32 cn_dm_attr_llc_cache_size(struct cn_core_set *core);
/* CN_DEVICE_ATTRIBUTE_MAX_L2_PERSISTING_CACHE_SIZE */
s32 cn_dm_attr_llc_max_persisting_size(struct cn_core_set *core);
/**
 * CN_DEVICE_ATTRIBUTE_TOTAL_CONST_MEMORY_SIZE
 * CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_TOTAL_SIZE
 */
s64 cn_dm_attr_memory_size(struct cn_core_set *core);
/* CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_NODE_COUNT */
s32 cn_dm_attr_memory_nodes(struct cn_core_set *core);
/* CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_BUS_WIDTH */
s32 cn_dm_attr_memory_bus_width(struct cn_core_set *core);

s32 cn_dm_attr_gdma_host_ch(struct cn_core_set *core);
/**
 * API short list of domain manager in host.
 *
 * 1. cn_dm_get_domain: get domain pointer with @core and @func_id. ref
 *    domain/cndrv_domain.c for details.
 * 2. cn_dm_set_cfg: set domain configuration to kdomaind in devide.
 * 3. per module api, e.g. (ignore the error checks for simplicity, user should
 * check the result!):
 * ```
 * //VF2
 * void *domain = cn_dm_get_domain(set->core, DM_FUNC_VF + 2);
 * u32 dma_ch = cn_dm_pci_get_dma_ch(domain);
 * ```
 * notes:
 * 1. DM_FUNC_PF means physical function; DM_FUNC_VF + i for VFn(n from 0 to
 *     num). DM_FUNC_VF means VF0, DM_FUNC_VF + 2 means VF2.
 */

/**
 * cn_dm_get_domain()
 *
 * This function is used to get domain pointer with @core and @func_id.
 *
 * In pf:
 * If core is NULL, domain manager might return the reserved pf domain.
 * In this case, @func_id should be DM_FUNC_PF. Returning NULL means
 * reserved domain is not valid any more.
 *
 * If core is not NULL, domain manager will return the function by @func_id,
 * pf could access its domain(DM_FUNC_PF) or VFs(DM_FUNC_VF0...).
 *
 * In vf:
 * If core is NULL, return NULL
 * *
 * If core is not NULL, domain manager will return the domain when
 * @func_id equals VF(DM_FUNC_VF).
 */
void *cn_dm_get_domain_early(struct cn_bus_set *bus_set, u32 func_id);
void *cn_dm_get_domain(struct cn_core_set *core, u32 func_id);

/**
 * preset domain cfg and sync with device.
 *
 * preset domain cfg according to @num_of_vf and send cfg to device. Domain
 * manager in device will allocated domain to switch to state of such domains
 * to DM_STATE_DEFINED. And then host will retrieve the defined domain
 * configuration from domain manager(device side).
 */
int cn_dm_sync_vfs_cfg(struct cn_core_set *core, u32 num_of_vf);

void cn_dm_cancel_vfs_cfg(struct cn_core_set *core);

/**
 * cn_dm_set_cfg()
 *
 * Set domain configuration to kdomaind in devide.
 *
 * This api will set the user
 * configuration of each domain and send them to device. If set successful read
 * the defined domain(fake function right now) from device. And other modules
 * could read the resources through the function with corresponding @domain.
 *
 * CAUTION: only valid when DM_FUNC_PF is valid(exists in set->domains_mask)
 */
int cn_dm_set_cfg(struct cn_core_set *core, void *domain, int num);

/**
 * Get domain configuraiton from domain manager(device).
 * 1. Used in PF only and VF mode: get from device directly;
 * 2. Used in PF sriov mode: set domain configuration from host to device
 *    then get from device. reference cn_dm_sync_vfs_cfg for more information.
 *
 * This function will get configurtion according to domains in
 * @set->domains_mask. And switch to domain to DM_STATE_DEFINED if get
 * successful. Set daemon to DM_STATE_STARTED if all the domain in
 * @set->domains_mask successful.
 */
int cn_dm_get_cfg(struct cn_core_set *core);

/**
 * PF only and VF.
 *
 * Init the domain belong to @core, including host and device side.
 * The initialization sequence is host, device, host late init. Note that it
 * should be distinguished with sriov init which are registered in PF and
 * called during sriov init and/or passthrough.
 */
int cn_dm_init_domain(struct cn_core_set *core);

int cn_dm_exit_domain(struct cn_core_set *core);
/**
 * Triggered by mailbox. it should be called before pcie setup(aka xxx_pre_init)
 * in the VF.
 */
int cn_dm_init_domain_sriov(struct cn_core_set *core, u32 func_id);

//exit domain in device first if double init
int cn_dm_init_domain_sriov_smart(struct cn_core_set *core, u32 func_id);

/**
 * Triggered by mailbox. it should be called at the end of rmmod module of VF.
 */
int cn_dm_exit_domain_sriov(struct cn_core_set *core, u32 func_id);

/**
 * PF sriov
 * Exit the domain belong to @core only for host (sriov callback) and device.
 * It will be exited at the end of VM exit. triggered from VF to PF through
 * mailbox. Then send rpc to device side.
 *
 * There is no late init callback in host side right now. The correspond exit
 * of ipu late init is in sbts_exit
 */
int cn_dm_exit_domain_sriov_with_rpc(struct cn_core_set *core, u32 func_id);

/**
 * cn_dm_host_early_init()
 *
 * Preserve the minimal resouces.
 *
 * Only call the early init in 20L right now. could support all the devices
 * when HW caps available.
 *
 * Notes: Early init is global for a type of card. init is per card.
 */
int cn_dm_host_early_init(struct cn_bus_set *bus_set, u64 device_id);
void cn_dm_host_early_exit(struct cn_bus_set *bus_set, u64 device_id);

/**
 * cn_dm_init()
 *
 * Per card init for domain manager in host side.
 *
 * Allocate and initialize the domain_set struct under cn_core_set. Launch
 * kheartbeatd for monitoring the status of kdomaind in device.
 */
int cn_dm_init(struct cn_core_set *core);

/**
 * cn_dm_exit()
 *
 * Per card exit.
 *
 * Free the domain_set and stop the kheartbeatd.
 */
void cn_dm_exit(struct cn_core_set *core);

int cn_dm_late_init(struct cn_core_set *core);
void cn_dm_late_exit(struct cn_core_set *core);

int cn_dm_domain_init(struct cn_core_set *core);

/**
 * Release reource of vf of pcie.
 * Allocate resource of pf of pcie.
 */
int cn_dm_mig_src_host_start(struct cn_core_set *core, u32 func_id);

int cn_dm_mig_dst_host_start(struct cn_core_set *core, u32 func_id);
int cn_dm_mig_guest_save_prepare(struct cn_core_set *core);
int cn_dm_mig_guest_restore_complete(struct cn_core_set *core);

/* Source host PF driver call this function when live migration complete,
 * If cancel, dst will call it to complete.
 * return: 0:success other:fail
 */
int cn_dm_mig_src_host_save_complete(struct cn_core_set *core, u32 func_id);
/* Dst host PF driver call this function when live migration complete,
 * If cancel, source will call it to complete.
 * return: 0:success other:fail
 */
int cn_dm_mig_dst_host_complete(struct cn_core_set *core, u32 func_id);

/*
 * Source PF driver get the live migration config, use binn serialization data.
 * Migration module get domain/host_drv_ver/cahce_size information,
 * domain get chipset_model/board_ver/mcu_ver/firmware_ver/guest_drv_ver/ipu_cfg/
 * mem_cfg/vpu_cfg/jpu_cfg/pci_cfg
 * return: 0:success other:fail
 */
int cn_dm_mig_get_cfg(struct cn_core_set *core, u32 func_id, void *cfg_binn);

/*
 * Dst PF driver test the live migration config, if can live migration return 0.
 * Migration module compare domain/host_drv_ver/cahce_size information,
 * domain compare chipset_model/board_ver/mcu_ver/firmware_ver/guest_drv_ver/
 * ipu_cfg/mem_cfg/vpu_cfg/jpu_cfg/pci_cfg
 * return: 0:success other:fail
 */
int cn_dm_mig_test_cfg(struct cn_core_set *core, u32 func_id, void *cfg_binn);

/*
 *  MIM data struct and interface
 */
enum mlu_instance_profile {
	MLU_INSTANCE_PROFILE_1_SLICE,
	MLU_INSTANCE_PROFILE_1_SLICE_IPU_2_SLICE_VPU,
	MLU_INSTANCE_PROFILE_2_SLICE,
	MLU_INSTANCE_PROFILE_2_SLICE_IPU_1_SLICE_MEM,
	MLU_INSTANCE_PROFILE_3_SLICE,
	MLU_INSTANCE_PROFILE_4_SLICE,
	MLU_INSTANCE_PROFILE_5_SLICE,
	MLU_INSTANCE_PROFILE_6_SLICE,
	MLU_INSTANCE_PROFILE_UNKONW = -1,
};

struct mlu_instance_placement {
	u32 start;
	u32 size;
};

struct mlu_instance_profile_info {
	u32 profile_id;
	int ipu_num;
	u64 mem_size;
	int vpu_num;
	int jpu_num;
	int gdma_num;
	char name[64];
};

struct mlu_instance_info {
	u32 profile_id;
	u32 mlu_instance_id;
	int domain_nr;
	u32 bus_num;
	u32 devfn;
	char device_name[64];
	struct mlu_instance_placement placement;
	char ipcm_device_name[64];
};

/* MIM interface ret val */
#define MI_ID_ERR		(1)
#define MI_ON_USE		(2)
#define OTHER_ERR		(EINVAL)
#define ESAON			(EBUSY) /* SR-IOV already is ON */
#define EUNSUP			(EACCES) /* unsupported operation */
/**
 * Return 0 if enable success, -1 if failed
 */
int cn_dm_enable_sriov(struct cn_core_set *core);

/**
 * Return 0 if disable success, -1 if failed
 */
int cn_dm_disable_sriov(struct cn_core_set *core);

/**
 * Return 1 if sriov is enabled, 0 if not, -1 if failed
 */
int cn_dm_is_sriov_enable(struct cn_core_set *core);

/**
 * Return true if mim mode is support, false if is not support
 */
bool cn_dm_is_mim_support(struct cn_core_set *core);

/**
 * Return 0 if device support mim operation is support or not,
 */
int cn_dm_device_is_support_mim(struct cn_core_set *core, u32 *support);

/**
 * Return true if mim mode is enabled, false if is not enabled
 */
bool cn_dm_is_mim_mode_enable(struct cn_core_set *core);

/**
 * Return 0 if query success, -1 if failed
 */
int cn_dm_query_mlu_instance_possible_placement(struct cn_core_set *core,
				unsigned int profile_id, int *count,
				struct mlu_instance_placement *placement);

/**
 * Return profile total mlu instance num if query success, -1 if failed
 */
int cn_dm_query_profile_total_mlu_instance_num(struct cn_core_set *core,
				unsigned int profile_id);

/**
 * Return profile acailable mlu instance num if query success, -1 if failed
 */
int cn_dm_query_profile_available_mlu_instance_num(struct cn_core_set *core,
				unsigned int profile_id);

/**
 * Return 0 if query success, -1 if failed
 */
int cn_dm_query_mlu_instance_info(struct cn_core_set *core,
				unsigned int mlu_instance_id,
				struct mlu_instance_info *instance_info);

/**
 * Return 0 if query success, -1 if failed
 */
int cn_dm_query_all_mlu_instance_info(struct cn_core_set *core, int *count,
				struct mlu_instance_info *instance_info);

/**
 * Return 0 if query success, 1 if profile not support, -1 if failed
 */
int cn_dm_query_mlu_instance_profile_info(struct cn_core_set *core,
						enum mlu_instance_profile profile,
						struct mlu_instance_profile_info *info);
/**
 * Return 0 if query success, -1 if failed
 */
int cn_dm_query_mlu_instance_mask(struct cn_core_set *core, u32 *mlu_instance_mask);

/**
 * Return 0 if query success, -1 if failed
 */
int cn_dm_query_onhost_mlu_instance_mask(struct cn_core_set *core, u32 *mlu_instance_mask);

/**
 * Return max mim device num that card supoort or -1 if err occur
 */
int cn_dm_query_max_mim_device_count(struct cn_core_set *core);

/**
 * Return created mlu instance id or -1 if create faild
 */
int cn_dm_create_mlu_instance(struct cn_core_set *core, unsigned int profile_id);

/**
 * Return created mlu instance id or -1 if create faild
 */
int cn_dm_create_mlu_instance_with_placement(struct cn_core_set *core,
					unsigned int profile_id, unsigned int start);

/**
 * Return 0 or -1 if destroy failed
 */
int cn_dm_destroy_mlu_instance(struct cn_core_set *core, unsigned int mlu_instance_id);

#define DOMAIN_MAJOR_VERSION_MASK (0xff)
#define DOMAIN_MAJOR_VERSION_OFF (16)
#define DOMAIN_MINOR_VERSION_MASK (0xff)
#define DOMAIN_MINOR_VERSION_OFF (8)
#define DOMAIN_REVISION_VERSION_MASK (0xff)
#define DOMAIN_REVISION_VERSION_OFF (0)
#define DOMAIN_VERSION(major, minor, revision)      \
        ((major & DOMAIN_MAJOR_VERSION_MASK) << DOMAIN_MAJOR_VERSION_OFF        \
        | (minor & DOMAIN_MINOR_VERSION_MASK) << DOMAIN_MINOR_VERSION_OFF       \
        | (revision & DOMAIN_REVISION_VERSION_MASK) << DOMAIN_REVISION_VERSION_OFF)

#define DOMAIN_HOST_VERSION_CUR DOMAIN_VERSION(1, 0, 0)

#endif /* __CNDRV_DOMAIN_H__ */
