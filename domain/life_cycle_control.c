
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/kvm_host.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include "cndrv_core.h"
#include "cndrv_cap.h"
#include "cndrv_mm.h"
#include "cndrv_sbts.h"
#include "cndrv_gdma.h"
#include "cndrv_bus.h"
#include "cndrv_domain.h"
#include "dmlib/include/domain.h"
#include "internal_interface.h"
#include "dmlib/domain_private.h"
#include "dmlib/include/domain.h"
#include "cndrv_ipcm.h"
#include "cndrv_mig.h"
#include "cndrv_monitor.h"
#include "cndrv_lpm.h"
#include "log_vuart.h"
#include "cndrv_commu.h"
#ifndef CONFIG_CNDRV_EDGE
#include "exp_mgnt.h"
#endif
#include "cndrv_qdev.h"
#include "cndrv_mcc.h"
#include "cndrv_attr.h"
#include "cndrv_kthread.h"
#include "cndrv_proc.h"
#include "cndrv_smlu.h"

#define SET_OB_RESOURCE_ERR	(-512)

#define SUB_LATE_PROCESS(fname, mode, eflag) \
	{.late_init = cn_##fname##_late_init, .late_exit = cn_##fname##_late_exit, .name = #fname, \
		.trigger_mode = mode, .flag = eflag}
#define SUB_LAST_PROCESS(fname, mode, eflag) \
	{.late_init = cn_##fname##_last_init, .late_exit = cn_##fname##_last_exit, .name = #fname, \
		.trigger_mode = mode, .flag = eflag}

/*
 * ref the defination of struct late_fn_s in cndrv_domain.h
 */
static struct late_fn_s late_fn_t[] = {
	/* cn_commu_late_init, cn_commu_late_exit */
	SUB_LATE_PROCESS(commu, PF|SRIOV, NOT_IGNORE),
	/* cn_dm_late_init, cn_dm_late_exit */
	SUB_LATE_PROCESS(dm, PF|VF|SRIOV, NOT_IGNORE),
	/* cn_mm_rpc_late_init, cn_mm_rpc_late_exit */
	SUB_LATE_PROCESS(mm_rpc, PF|VF|SRIOV, NOT_IGNORE),
	/* cn_log_vuart_late_init, cn_log_vuart_late_exit */
	SUB_LATE_PROCESS(log_vuart, PF|SRIOV, NOT_IGNORE),
#ifndef CONFIG_CNDRV_EDGE
	/* cn_mnt_rpc_late_init, cn_mnt_rpc_late_exit */
	SUB_LATE_PROCESS(mnt_rpc, PF, NOT_IGNORE),
#endif
	/* cn_mm_late_init, cn_mm_late_exit */
	SUB_LATE_PROCESS(mm, PF|VF|SRIOV, NOT_IGNORE),
	/* cn_sbts_late_init, cn_sbts_late_exit */
	SUB_LATE_PROCESS(sbts, PF|VF, NOT_IGNORE),
	/* cn_bus_late_init, cn_bus_late_exit */
	SUB_LATE_PROCESS(bus, PF|VF, NOT_IGNORE),
	/* cn_gdma_late_init, cn_gdma_late_exit */
	SUB_LATE_PROCESS(gdma, PF, NOT_IGNORE),
	/* cn_monitor_late_init, cn_monitor_late_exit */
	SUB_LATE_PROCESS(monitor, PF|VF|SRIOV, NOT_IGNORE),
	/* cn_mig_late_init, cn_mig_late_exit */
	SUB_LATE_PROCESS(mig, VF|SRIOV, NOT_IGNORE),
	/* cn_monitor_ts_offset_calculate_in_late_init, cn_monitor_ts_offset_calculate_in_late_exit */
	SUB_LATE_PROCESS(monitor_ts_offset_calculate_in, PF|VF|SRIOV, NOT_IGNORE),
	/* cn_attr_late_init, cn_attr_late_exit */
	SUB_LATE_PROCESS(attr, PF|VF|SRIOV, DO_IGNORE),
	/* cn_p2pshm_late_init, cn_p2pshm_late_exit */
	SUB_LATE_PROCESS(p2pshm, PF|VF|SRIOV, DO_IGNORE),
	/* cn_ipcm_late_init, cn_ipcm_late_exit */
	SUB_LATE_PROCESS(ipcm, PF|VF|SRIOV, NOT_IGNORE),
	/* cn_mm_last_init, cn_mm_last_exit */
	SUB_LAST_PROCESS(mm, PF|VF, NOT_IGNORE),
#ifndef CONFIG_CNDRV_EDGE
	/* cn_ncs_late_init, cn_ncs_late_exit */
	SUB_LATE_PROCESS(ncs, PF, NOT_IGNORE),
#endif
	/* cn_qdev_late_init, cn_qdev_late_exit */
	SUB_LATE_PROCESS(qdev, VF, NOT_IGNORE),
	/* cn_lpm_late_init, cn_lpm_late_exit */
	SUB_LATE_PROCESS(lpm, PF|VF, NOT_IGNORE),
	/* cn_kthread_late_init, cn_kthread_late_exit */
	SUB_LATE_PROCESS(kthread, PF|VF|SRIOV, NOT_IGNORE),
#ifndef CONFIG_CNDRV_EDGE
	/* cn_cdev_late_init, cn_cdev_late_exit */
	SUB_LATE_PROCESS(cdev, PF|VF|SRIOV, NOT_IGNORE),
#endif
	/* cn_proc_late_init, cn_proc_late_exit */
	SUB_LATE_PROCESS(proc, PF|VF|SRIOV, NOT_IGNORE),
#ifndef CONFIG_CNDRV_EDGE
	/* cn_mi_cap_node_late_init, cn_mi_cap_node_late_exit */
	SUB_LATE_PROCESS(mi_cap_node, VF, NOT_IGNORE),
	/* cn_smlu_late_init, cn_smlu_late_exit */
	SUB_LATE_PROCESS(smlu, PF, NOT_IGNORE),
#endif
};

static struct fn_state_s late_fn_state[MAX_FUNCTION_NUM][ARRAY_SIZE(late_fn_t)];

struct late_fn_s *cn_dm_get_late_fn_t(void)
{
	return (struct late_fn_s *)late_fn_t;
}

int cn_dm_get_late_fn_num(void)
{
	return ARRAY_SIZE(late_fn_t);
}

struct fn_state_s *cn_dm_get_late_fn_state(int idx)
{
	return (struct fn_state_s *)late_fn_state[idx];
}

static int dm_rpc_pf_set_device_res(struct domain_set_type *set,
				     struct domain_type *domain)
{
	s8 resource[] = {
		j_pci_bar_shm_sz,
		k_pci_dma_ch,
		l_pci_bar_reg_total_sz,
		-1
	};
	struct dm_resource_discriptor resource_set[] = {
		[0] = {.mod_idx = DM_PCI_IDX, .res = resource},
		[1] = {.mod_idx = -1, .res = NULL},
	};
	s8 _offset[5] = {0, 0, 0, 0};
	s8 *offset[1] = {_offset};
	s32 ret;

	ret = dm_rpc_set_resource_host(set, domain,
				domain, resource_set, offset, 3);
	if (ret <= 0)
		cn_domain_err(set, "rpc set dma resource failed");

	if (cn_bus_pcie_sram_able(set->core->bus_set)) {
		resource_set[0].mod_idx = DM_PCI_IDX;
		resource_set[0].res = resource;
		resource_set[1].mod_idx = -1;
		resource_set[1].res = NULL;
		resource[0] = n_pci_sram_pa;
		resource[1] = o_pci_sram_sz,
		resource[2] = -1;
		ret = dm_rpc_set_resource_host(set, domain,
				domain, resource_set, offset, 3);
		if (ret <= 0)
			cn_domain_err(set, "rpc set sram resource failed");
	}

	resource_set[0].mod_idx = DM_MEM_IDX;
	resource_set[0].res = resource;
	resource_set[1].mod_idx = -1;
	resource_set[1].res = NULL;
	resource[0] = c_mem_cache_size;
	resource[1] = d_mem_bus_width,
	resource[2] = -1;
	ret = dm_rpc_set_resource_host(set, domain,
				domain, resource_set, offset, 3);
	if (ret <= 0) {
		ret = -1;
		cn_domain_err(set, "rpc set mem resource failed");
	}

	return ret;
}

static int dm_rpc_set_ob_cfg(struct domain_set_type *set,
				     struct domain_type *domain,
				     struct cn_bus_set *bus)
{
	s8 ob_distribute_pci_resource[] = {
		b_pci_ob_host_addr,
		c_pci_ob_axi_addr,
		d_pci_ob_sz,
		-1
	};
	const struct dm_resource_discriptor dm_ob_distribute_resource_set[] = {
		[0] = {.mod_idx = DM_PCI_IDX,
					.res = ob_distribute_pci_resource},
		[1] = {.mod_idx = -1, .res = NULL},
	};
	s8 _res_offset[5] = {0, 0, 0, 0, 0};
	s8 *res_offset[1] = {_res_offset};
	s32 ret = 0;

	if (cn_bus_outbound_able(bus)) {
		cn_domain_warn(set, "outbound is supported in this platform");
		ret = dm_rpc_set_resource_host(set, domain, domain,
						dm_ob_distribute_resource_set,
						res_offset, 3);
		if (ret <= 0) {
			cn_domain_err(set, "rpc set ob resource fail");
			ret = SET_OB_RESOURCE_ERR;
			return ret;
		}
	} else {
		cn_domain_info(set, "outbound is not supported in this platform, skip the configuration.");
	}

	return 0;
}

static int dm_rpc_set_large_bar_cfg(struct domain_set_type *set,
				     struct domain_type *domain,
				     struct cn_bus_set *bus)
{
	s8 large_bar_distribute_pci_resource[] = {
		p_pci_large_bar_bs,
		q_pci_large_bar_sz,
		-1
	};

	const struct dm_resource_discriptor dm_large_bar_distribute_resource_set[] = {
		[0] = {.mod_idx = DM_PCI_IDX,
					.res = large_bar_distribute_pci_resource},
		[1] = {.mod_idx = -1, .res = NULL},
	};
	s8 _res_offset[5] = {0, 0, 0, 0, 0};
	s8 *res_offset[1] = {_res_offset};
	s32 ret = 0;

	ret = dm_rpc_set_resource_host(set, domain, domain,
					dm_large_bar_distribute_resource_set,
						res_offset, 2);
	if (ret <= 0) {
		cn_domain_err(set, "rpc set large bar resource fail");
		return -1;
	}

	return 0;
}

static int dm_rpc_set_card_info_cfg(struct domain_set_type *set,
				     struct domain_type *domain,
				     struct cn_bus_set *bus)
{
	s8 card_info_pci_resource[] = {
		r_pci_mem_cfg_phys_card_idx,
		s_pci_mem_cfg_size_limit,
		-1
	};

	const struct dm_resource_discriptor dm_card_info_pci_resource_set[] = {
		[0] = {.mod_idx = DM_PCI_IDX,
					.res = card_info_pci_resource},
		[1] = {.mod_idx = -1, .res = NULL},
	};
	s8 _res_offset[5] = {0, 0, 0, 0, 0};
	s8 *res_offset[1] = {_res_offset};
	s32 ret = 0;

	ret = dm_rpc_set_resource_host(set, domain, domain,
					dm_card_info_pci_resource_set,
						res_offset, 1);
	if (ret <= 0) {
		cn_domain_err(set, "rpc set card meminfo resource fail");
		return -1;
	}

	return 0;
}

struct domain_life_cycle_operation *dm_get_life_cycle_op(void);

#ifdef MMU_RELEASE_NOFIFIER
static void *dm_func_lookup_name(const char *name)
{
	static unsigned long (*f_kallsyms_lookup_name)(const char *name) = NULL;
#if (KERNEL_VERSION(5, 7, 0) <= LINUX_VERSION_CODE)
	struct kprobe kp;
	int r;

	if (!f_kallsyms_lookup_name) {
		memset(&kp, 0, sizeof(kp));
		kp.symbol_name = "kallsyms_lookup_name";
		r = register_kprobe(&kp);
		if (r < 0) {
			return NULL;
		}
		__sync_lock_test_and_set((ulong *)(&f_kallsyms_lookup_name),
			(unsigned long)kp.addr);
		unregister_kprobe(&kp);
	}
#else
	if (!f_kallsyms_lookup_name) {
		__sync_lock_test_and_set((ulong *)(&f_kallsyms_lookup_name),
			(unsigned long)kallsyms_lookup_name);
	}
#endif

	if (!f_kallsyms_lookup_name) {
		return NULL;
	}

	return (void *)f_kallsyms_lookup_name(name);
}

static s32 shadow_domain_exit(struct domain_set_type *set, u32 func_id);
void mmu_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct domain_type *domain;
	s32 ret;

	domain = container_of(mn, struct domain_type, mn);
	cn_dev_info("mmu_release domain->state:%x func_id:%d",
		domain->state, domain->func_id);

	/*
	 * If domain->state is DM_STATE_DEFINED, the normal flow will be called in
	 * shadow_domain_exit, otherwise the qemu is killed, must notify arm the
	 * status in here and call vfio_unregister_notifier.
	 */
	if (domain->state != DM_STATE_DEFINED) {
		domain->k = NULL;
		ret = shadow_domain_exit(domain->set, domain->func_id);
	}

	return;
}

struct mmu_notifier_ops mmu_ops = {
	.release = mmu_release
};

static int group_notifier_ops(struct notifier_block *nb,
				unsigned long action, void *data)
{
	struct kvm *k;
	int ret;
	struct domain_type *domain;

	cn_dev_info("action:%lx data:%lx", action, (ulong)data);

	if (action == VFIO_GROUP_NOTIFY_SET_KVM) {
		if (data) {
			domain = container_of(nb, struct domain_type, gp);
			k = data;
			domain->mn.ops = &mmu_ops;
			domain->k = k;
			ret = mmu_notifier_register(&domain->mn, k->mm);
			if (ret < 0) {
				pr_warn("Add VM mmu notifier fail %d", ret);
			}
		}
	}

	return NOTIFY_OK;
}
#endif

static s32 shadow_domain_init(struct domain_set_type *set, u32 func_id)
{
	struct domain_type *domain;
	s32 ret = 0;
	struct domain_life_cycle_operation *life_op;
#ifdef MMU_RELEASE_NOFIFIER
	unsigned long events;
	struct device *vdev;
	int (*f_vfio_register_notifier)(struct device *, enum vfio_notify_type,
		unsigned long *, struct notifier_block *);
#endif

	domain = dm_get_domain(set, func_id);
	if (!domain) {
		cn_domain_err(set, "Could not get func_id<%s>",
						dm_funcid2str(func_id));
		return -1;
	}
	if (domain->state == DM_STATE_STARTED) {
		/**
		 * PF sriov will send rpc domain_exit at the very beginning of
		 * VF init. Domain manager need to exit before VF init in host
		 * and device. If @domain->state is not DM_STATE_STARTED, there
		 * is no need to exit
		 */
		cn_domain_info(set, "domain[%d] still started try exit!\n",
							   domain->func_id);
		life_op = dm_get_life_cycle_op();
		ret = life_op->
			shadow_domain_exit_on_vf_driver_remove(set, func_id);
		if (ret < 0) {
			cn_domain_err(set, "domain%d started try exit fail!\n",
							   domain->func_id);
			return ret;
		}
	}
	if (domain->pci.ops && domain->pci.data) {
		domain->pci.data->priv = domain->pci.ops->init(domain,
						domain->pci.data->top_priv);
	} else {
		cn_domain_warn(set, "domain %s init is empty\n",
						dm_funcid2str(func_id));
	}

#ifdef MMU_RELEASE_NOFIFIER
	domain->gp.notifier_call = group_notifier_ops;
	vdev = cn_bus_get_vf_dev(set->core->bus_set, func_id - 1);
	events = VFIO_GROUP_NOTIFY_SET_KVM;
	f_vfio_register_notifier = dm_func_lookup_name("vfio_register_notifier");
	if (f_vfio_register_notifier && vdev) {
		ret = f_vfio_register_notifier(vdev, VFIO_GROUP_NOTIFY,
			&events, &domain->gp);
	}
#endif

	domain->state = DM_STATE_STARTED;
	return 0;
}

static s32 shadow_domain_exit(struct domain_set_type *set, u32 func_id)
{
	char tmp[COMMU_RPC_SIZE];
	struct domain_type *domain = NULL;
	int ret_size;
	int ret = -1;
#ifdef MMU_RELEASE_NOFIFIER
	struct device *vdev;
	int (*f_vfio_unregister_notifier)(struct device *, enum vfio_notify_type,
		struct notifier_block *);
#endif

	/* Call IPCM first, and IPCM will return error_code
	 * on modules try send message to VM.
	 */
	cn_domain_info(set, "func<%d> closing ipcm\n", func_id);
	ret = ipcm_announce_vf_status(set->core, false, func_id);
	if (ret < 0) {
		cn_domain_err(set, "func<%d> close ipcm fail %d, continue\n",
							func_id, ret);
	}
	cn_domain_info(set, "func<%d> close ipcm ok\n", func_id);
	memset(tmp, 0, COMMU_RPC_SIZE);
	ret = dm_compat_rpc((void *)set, "domain_exit", &func_id, sizeof(u32),
						tmp, &ret_size, sizeof(tmp));
	if (ret < 0 || !dm_is_rpc_ok(tmp)) {
		cn_domain_err(set, "rpc domain_exit func_id: %d> return<%d, %s>\n",
						func_id, ret_size, tmp);
		return -1;
	}
	domain = dm_get_domain(set, func_id);
	if (!domain) {
		cn_domain_err(set, "Could not get func_id<%d>\n", func_id);
		return -1;
	}
	if (domain->pci.ops && domain->pci.data) {
		ret = domain->pci.ops->exit(domain->pci.data->priv);
		if (ret < 0)
			cn_domain_err(set, "Domain %s exit per module ops failed\n",
						dm_funcid2str(func_id));

	} else {
		cn_domain_warn(set, "Domain %s PCI exit empty\n",
						dm_funcid2str(func_id));
	}

	domain->state = DM_STATE_DEFINED;

#ifdef MMU_RELEASE_NOFIFIER
	vdev = cn_bus_get_vf_dev(domain->set->core->bus_set, domain->func_id - 1);
	if (vdev) {
		if (domain->k) {
			mmu_notifier_unregister(&domain->mn, domain->k->mm);
		}

		f_vfio_unregister_notifier = dm_func_lookup_name("vfio_unregister_notifier");
		if (f_vfio_unregister_notifier) {
			f_vfio_unregister_notifier(vdev, VFIO_GROUP_NOTIFY,
					&domain->gp);
		}
		domain->k = NULL;
	}
#endif

	cn_domain_info(set, "FLOW: end\n");
	return ret;
}

static int traverse_late_init_table(struct domain_set_type *set, enum dm_work_mode mode)
{
	int i, state, trigger_mode, idx, init_cost;
	enum IGNORE_ERR_MODE flag;
	u64 start, end;

	idx = set->core->idx;
	for (i = 0; i < ARRAY_SIZE(late_fn_t); i++) {
		trigger_mode = late_fn_t[i].trigger_mode;
		if (!(trigger_mode & mode)) {
			continue;
		}

		flag = late_fn_t[i].flag;
		start = get_jiffies_64();
		state = late_fn_t[i].late_init(set->core);
		end = get_jiffies_64();
		init_cost = jiffies_to_msecs(end - start);
		if (!state) {
			cn_domain_info(set, "calling %s late init done, time cost:%d(ms)",
				late_fn_t[i].name, init_cost);
			late_fn_state[idx][i].status = INIT_OK;
			late_fn_state[idx][i].init_cost = init_cost;
		} else if (flag == DO_IGNORE) {
			cn_domain_warn(set, "%s late init ignore, time cost:%d(ms)",
				late_fn_t[i].name, init_cost);
			late_fn_state[idx][i].init_cost = init_cost;
		} else {
			cn_domain_err(set, "%s late init failed, time cost:%d(ms)",
				late_fn_t[i].name, init_cost);
			return -1;
		}
	}

	return 0;
}

static int traverse_late_exit_table(struct domain_set_type *set, enum dm_work_mode mode)
{
	int i, trigger_mode, idx, state, exit_cost;
	u64 start, end;

	idx = set->core->idx;
	for (i = ARRAY_SIZE(late_fn_t) - 1; i >= 0; i--) {
		trigger_mode = late_fn_t[i].trigger_mode;
		if (!(trigger_mode & mode)) {
			continue;
		}

		state = late_fn_state[idx][i].status;
		if (state == INIT_OK && late_fn_t[i].late_exit) {
			start = get_jiffies_64();
			late_fn_t[i].late_exit(set->core);
			end = get_jiffies_64();
			exit_cost = jiffies_to_msecs(end - start);
			cn_domain_info(set, "%s late exit ok, time cost:%d(ms)",
				late_fn_t[i].name, exit_cost);
			late_fn_state[idx][i].status = EXIT_OK;
			late_fn_state[idx][i].init_cost = 0;
		}
	}

	return 0;
}

static s32 domain_trigger_modules_init(struct domain_set_type *set)
{
	s32 ret;
	enum dm_work_mode mode;

	set->core->reset_flag = 0;
	mode = dm_get_work_mode(set);
	if (!is_valid_mode(mode)) {
		cn_domain_err(set, "err domain work mode");
		return -1;
	}

	cn_domain_info(set, "domain_trigger_modules_init start");
	ret = traverse_late_init_table(set, mode);
	if (ret) {
		cn_domain_err(set, "domain_trigger_modules_init error");
		return ret;
	}

	cn_domain_info(set, "domain_trigger_modules_init finish");
	dm_domain_set_print(set);

	return ret;
}

static s32 domain_trigger_modules_exit(struct domain_set_type *set)
{
	s32 ret;
	enum dm_work_mode mode;

	mode = dm_get_work_mode(set);
	if (!is_valid_mode(mode)) {
		cn_domain_err(set, "err domain work mode");
		return -1;
	}

	ret = traverse_late_exit_table(set, mode);
	if (ret) {
		cn_domain_err(set, "domain_trigger_modules_exit failed");
		return ret;
	}

	return 0;
}

static s32 config_dev_sriov(struct domain_set_type *set)
{
	s32 ret;
	struct domain_type *domain;

	ret = domain_set_attr_sync_max_vf(set);
	if (ret < 0) {
		cn_domain_err(set, "fail on sync max_vf");
		return -EINVAL;
	}
	domain = dm_get_domain(set, DM_FUNC_OVERALL);
	if (domain == NULL) {
		cn_domain_err(set, "get domain overall fail");
		return -EINVAL;
	}
	ret = dm_rpc_pf_set_device_res(set, domain);
	if (ret < 0) {
		cn_domain_err(set, "fail on rpc set dma and shm cfg");
		return -EINVAL;
	}

	ret = dm_rpc_set_ob_cfg(set, domain, set->core->bus_set);
	if (ret == SET_OB_RESOURCE_ERR) {
		cn_domain_info(set, "ob disable");
	}

	ret = dm_rpc_set_large_bar_cfg(set, domain, set->core->bus_set);
	if (ret) {
		cn_domain_err(set, "rpc set large bar fail");
		return -ENODEV;
	}

	ret = dm_rpc_set_card_info_cfg(set, domain, set->core->bus_set);
	if (ret) {
		cn_domain_err(set, "rpc set card phys idx fail");
		return -ENODEV;
	}

	dm_set_state_started(set);
	cn_domain_info(set, "rpc set device res success");
	return 0;
}

static s32 config_dev_vf(struct domain_set_type *set)
{
	s32 ret;
	struct domain_type *domain;

	domain = dm_get_domain(set, DM_FUNC_VF);
	if (domain == NULL) {
		cn_domain_err(set, "fail get VF domain");
		return -EINVAL;
	}
	ret = dm_rpc_set_ob_cfg(set, domain, set->core->bus_set);
	if (ret == SET_OB_RESOURCE_ERR) {
		cn_domain_info(set, "ob disable");
	}

	ret = dm_rpc_set_large_bar_cfg(set, domain, set->core->bus_set);
	if (ret) {
		cn_domain_err(set, "rpc set large bar fail");
		return -ENODEV;
	}

	cn_domain_info(set, "rpc set device res success");
	domain = dm_get_domain(set, DM_FUNC_VF);
	if (domain == NULL) {
		cn_domain_err(set, "fail get VF domain");
		return -EINVAL;
	}
	ret = sync_resouce_cache(set, domain);
	if (ret < 0) {
		cn_domain_err(set, "fail");
		return -EFAULT;
	}

	set->core->board_info.cluster_num = cn_dm_attr_cluster_num(set->core);
	domain->state = DM_STATE_STARTED;
	set->daemon_state = DM_STATE_STARTED;
	ret = dm_queue_rpc(set, "domain_init", "");
	if (ret) {
		cn_domain_err(set, "fail on device domain_init\n");
		return ret;
	}
	return 0;
}

static s32 config_dev_pf(struct domain_set_type *set)
{
	s32 ret;
	struct domain_type *domain;

	ret = dm_set_dev_addr_map_type(set);
	if (ret < 0) {
		cn_domain_err(set, "fail on set map type");
		return -EINVAL;
	}

	domain = dm_get_domain(set, DM_FUNC_OVERALL);
	if (domain == NULL) {
		cn_domain_err(set, "fail get overall domain");
		return -EINVAL;
	}
	ret = dm_rpc_pf_set_device_res(set, domain);
	if (ret < 0) {
		cn_domain_err(set, "fail on rpc set dma and shm cfg");
		return -EINVAL;
	}

	ret = dm_rpc_set_ob_cfg(set, domain, set->core->bus_set);
	if (ret == SET_OB_RESOURCE_ERR) {
		cn_domain_info(set, "ob disable");
	}

	ret = dm_rpc_set_large_bar_cfg(set, domain, set->core->bus_set);
	if (ret) {
		cn_domain_err(set, "rpc set large bar fail");
		return -ENODEV;
	}

	ret = dm_rpc_set_card_info_cfg(set, domain, set->core->bus_set);
	if (ret) {
		cn_domain_err(set, "rpc set card phys idx fail");
		return -ENODEV;
	}

	cn_domain_info(set, "rpc set device res success");
	ret = dm_queue_rpc(set, "dm_management", "PFonly");
	if (ret)
		return ret;

	ret = dm_rpc_set_domain_set_daemon_state(set, DM_STATE_STARTED);
	if (ret < 0) {
		cn_domain_err(set, "fail set dev daemon start ret %d\n", ret);
		return ret;
	}
	domain = dm_get_domain(set, DM_FUNC_PF);
	if (domain == NULL) {
		cn_domain_err(set, "fail get PF domain");
		return -EINVAL;
	}
	ret = sync_resouce_cache(set, domain);
	if (ret < 0) {
		cn_domain_err(set, "fail");
		return -EFAULT;
	}

	set->core->board_info.cluster_num = cn_dm_attr_cluster_num(set->core);
	domain->state = DM_STATE_STARTED;
	set->daemon_state = DM_STATE_STARTED;
	ret = dm_queue_rpc(set, "domain_init", "");
	if (ret) {
		cn_domain_err(set, "fail on device domain_init\n");
		return ret;
	}
	return 0;
}

static s32 domain_connect_device(struct domain_set_type *set)
{
	s32 ret;

	ret = dm_build_rpc_connection(set->core);
	if (ret < 0) {
		cn_domain_err(set, "dm_build_rpc_connection failed\n");
		return -EFAULT;
	}
	ret = dm_queue_rpc(set, "dm_ping", "");
	if (!ret) {
		set->daemon_state = DM_STATE_INIT;
	} else {
		set->daemon_state = DM_STATE_UNDEF;
		cn_domain_err(set, "queue init fail. switch back to %s state\n",
					dm_state2str(set->daemon_state));
		return ret;
	}
	return 0;
}

static inline void config_outbound(struct domain_set_type *set,
				struct cn_bus_set *bus, enum func_id_type func)
{
	struct domain_resource resource;
	struct domain_type *domain;

	if (!cn_bus_outbound_able(bus))
		return;

	domain = dm_get_domain(set, func);
	if (domain == NULL) {
		cn_domain_err(set, "get domain %d fail", func);
		return;
	}
	bus->get_resource(bus->priv, &resource);
	domain->pci.data->shms[OUT_BOUND_HOST].bs =
					(u64)resource.ob_set[0].virt_addr;
	domain->pci.data->shms[OUT_BOUND_HOST].sz =
					(u64)resource.ob_set[0].win_length;
	domain->pci.data->shms[OUT_BOUND_AXI].bs =
					(u64)resource.ob_set[0].ob_axi_base;
	domain->pci.data->shms[OUT_BOUND_AXI].sz =
					(u64)resource.ob_set[0].win_length;
	cn_domain_info(set,
		"%sob_virt_addr:0x%llx,ob_axi_base:0x%llx,win_length:%llx",
			__func__, domain->pci.data->shms[OUT_BOUND_HOST].bs,
			domain->pci.data->shms[OUT_BOUND_AXI].bs,
			domain->pci.data->shms[OUT_BOUND_AXI].sz);
}

static inline void config_sram(struct domain_set_type *set,
				struct cn_bus_set *bus, enum func_id_type func)
{
	struct domain_resource resource;
	struct domain_type *domain;

	if (!cn_bus_pcie_sram_able(bus))
		return;

	domain = dm_get_domain(set, func);
	if (domain == NULL) {
		cn_domain_err(set, "get domain %d fail", func);
		return;
	}
	bus->get_resource(bus->priv, &resource);
	domain->pci.data->sram.pa = resource.sram_pa_base;
	domain->pci.data->sram.sz = resource.sram_pa_size;
	cn_domain_info(set,
		"%s sram_pa:0x%llx,sram_sz:0x%llx",
			__func__, domain->pci.data->sram.pa,
			domain->pci.data->sram.sz);
}

static inline void config_large_bar(struct domain_set_type *set,
				struct cn_bus_set *bus, enum func_id_type func)
{
	struct domain_resource resource;
	struct domain_type *domain;

	domain = dm_get_domain(set, func);
	if (domain == NULL) {
		cn_domain_err(set, "get domain %d fail", func);
		return;
	}

	domain->pci.data->large_bar.bs = 0;
	domain->pci.data->large_bar.sz = 0;
	if (bus->get_resource) {
		bus->get_resource(bus->priv, &resource);
		domain->pci.data->large_bar.bs = resource.large_bar_base;
		domain->pci.data->large_bar.sz = resource.large_bar_size;
	}

	cn_domain_info(set,
		"%s large_bar bs:0x%llx,large_bar sz:0x%llx",
			__func__, domain->pci.data->large_bar.bs,
			domain->pci.data->large_bar.sz);
}

static inline void config_card_info(struct domain_set_type *set,
				struct cn_bus_set *bus, enum func_id_type func)
{
	struct domain_type *domain;
	unsigned int limit_coef = 0;

	domain = dm_get_domain(set, func);
	if (domain == NULL) {
		cn_domain_err(set, "get domain %d fail", func);
		return;
	}

	/*NOTE: mem limit coef is not support in vf*/
	if (cn_core_is_vf(set->core)) {
		cn_domain_info(set, "mem limit coef is not support in vf!");
	} else {
		cn_mcc_get_mem_limit_coef(set->core, &limit_coef);
	}
	domain->pci.data->mem_cfg.size_limit = limit_coef;

	/*FIXME:
	  *We use the core pf_idx to as respresent value for the phys idx of device.
	  *However, in pf-sriov, the phys_card_idx will send to the overall dm of
	  *arm dev. So need to cp the phys_card_idx in dm resource to every vf res.
	  */
	domain->pci.data->mem_cfg.phys_card_idx = set->core->pf_idx;

	cn_domain_info(set, "%s card info phys idx :0x%llx", __func__,
				   domain->pci.data->mem_cfg.phys_card_idx);
}

static s32 guest_vf_config_domain_set(struct domain_set_type *set)
{
	struct domain_type *domain;

	if (set->domains[DM_FUNC_PF]) {
		cn_domain_info(set, "VF mode: clear PF domain");
		dm_domain_free_data(set->domains[DM_FUNC_PF]);
		__clear_bit(DM_FUNC_PF, &set->domains_mask);
		dm_free(set->domains[DM_FUNC_PF]);
		set->domains[DM_FUNC_PF] = NULL;
	}

	config_outbound(set, set->core->bus_set, DM_FUNC_VF);
	config_sram(set, set->core->bus_set, DM_FUNC_VF);
	config_large_bar(set, set->core->bus_set, DM_FUNC_VF);
	domain = dm_get_domain(set, DM_FUNC_VF);
	if (!domain) {
		cn_domain_err(set, "fail get VF domain");
		return -1;
	}
	__cn_dm_preset_ob_mask(set->core->bus_set, domain,
							cn_is_mim_en(set->core));
	return 0;
}

static s32 sriov_pf_config_domain_set(struct domain_set_type *set)
{
	s32 ret;

	cn_domain_info(set, "PF SRIOV mode");
	config_sram(set, set->core->bus_set, DM_FUNC_OVERALL);
	config_large_bar(set, set->core->bus_set, DM_FUNC_OVERALL);
	config_card_info(set, set->core->bus_set, DM_FUNC_OVERALL);
	ret = init_pf_resource_cache(set->core);
	if (ret < 0)
		return ret;

	return 0;
}

static s32 host_pf_config_domain_set(struct domain_set_type *set)
{
	s32 ret;
	struct domain_type *domain;

	cn_domain_info(set, "PF only mode: clear VF domain");
	if (set->domains[DM_FUNC_VF]) {
		dm_domain_free_data(set->domains[DM_FUNC_VF]);
		dm_free(set->domains[DM_FUNC_VF]);
		set->domains[DM_FUNC_VF] = NULL;
		__clear_bit(DM_FUNC_VF, &set->domains_mask);
	}

	config_outbound(set, set->core->bus_set, DM_FUNC_OVERALL);
	config_sram(set, set->core->bus_set, DM_FUNC_OVERALL);
	config_large_bar(set, set->core->bus_set, DM_FUNC_OVERALL);
	config_card_info(set, set->core->bus_set, DM_FUNC_OVERALL);
	domain = dm_get_domain(set, DM_FUNC_PF);
	if (!domain) {
		cn_domain_err(set, "fail get PF domain");
		return -1;
	}
	__cn_dm_preset_ob_mask(set->core->bus_set, domain,
							cn_is_mim_en(set->core));
	ret = init_pf_resource_cache(set->core);
	if (ret < 0) {
		cn_domain_err(set, "fail");
		return ret;
	}
	return 0;
}

static struct domain_life_cycle_operation domain_life_cycle_interface = {
	/* SRIOV PF for VF driver load/unload */
	.shadow_domain_init_on_vf_driver_probe = shadow_domain_init,
	.shadow_domain_exit_on_vf_driver_remove = shadow_domain_exit,
	/* Host domain init before device communication establish. */
	.host_pf_init_before_connect_device = host_pf_config_domain_set,
	.guest_vf_init_before_connect_device = guest_vf_config_domain_set,
	.sriov_pf_init_before_connect_device = sriov_pf_config_domain_set,
	/* PF/VF/SRIOV PF any mode will connect with device */
	.connect_device = domain_connect_device,
	/* Device DM config and setup after connect established */
	.host_pf_setup_device = config_dev_pf,
	.guest_vf_setup_device = config_dev_vf,
	.sriov_pf_setup_device = config_dev_sriov,
	/* As Host DM and Device DM settled down, modules have dependency with
	 * domain will trigger work.
	 */
	.domain_init_related_modules = domain_trigger_modules_init,
	.domain_exit_related_modules = domain_trigger_modules_exit
};

struct domain_life_cycle_operation *dm_get_life_cycle_op(void)
{
	return &domain_life_cycle_interface;
}
