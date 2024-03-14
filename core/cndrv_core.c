/*
 * core/cndrv_core.c
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/pid_namespace.h>
#include <linux/ftrace.h>
#include <linux/proc_fs.h>

#include "cndrv_fw.h"
#include "cndrv_core.h"
#include "cndrv_cap.h"
#include "cndrv_affinity_internal.h"
#include "cndrv_kthread.h"
#include "cndrv_kwork.h"
#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "cndrv_mm.h"
#include "cndrv_sbts.h"
#include "cndrv_mcc.h"
#include "cndrv_mcu.h"
#include "cndrv_i2c.h"
#include "version.h"
#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_proc.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_commu.h"
#include "cndrv_boot.h"
#include "exp_mgnt.h"
#include "cndrv_debug.h"
#include "cndrv_domain.h"
#include "log_vuart.h"
#include "cndrv_mig.h"
#include "cndrv_attr.h"
#include "cndrv_lpm.h"
#include "cndrv_ctx.h"
#include "cndrv_gdma.h"
#include "cndrv_ipcm.h"
#include "cndrv_nor.h"
#include "cndrv_xid.h"
#include "cndrv_smlu.h"
#include "cndrv_mem_perf.h"


#ifndef VM_RESERVED
#define VM_RESERVED (VM_DONTEXPAND | VM_DONTDUMP)
#endif

#define WORKQ_RUNNING 0x0001
#define WORKQ_FINISH  0x0002
#define WORKQ_ABORT   0x8000

#define VALID_FP_STATE 1
#define INVALID_FP_STATE 0

/*30s*/
#define MLU270_BOOT_MAX_TIME (BASE_BOOT_MAX_TIME)
/*30s: for MLU220 M.2 30s*/
#define MLU220_BOOT_MAX_TIME (BASE_BOOT_MAX_TIME)
/*30s: for MLU290 asic 30s*/
#define MLU290_BOOT_MAX_TIME (BASE_BOOT_MAX_TIME)
/*30s: for MLU370 asic 30s*/
#define MLU370_BOOT_MAX_TIME (BASE_BOOT_MAX_TIME)
/*30s: for MLU500 asic 30s*/
#define MLU500_BOOT_MAX_TIME (BASE_BOOT_MAX_TIME)
/*300000s: for EMU*/
#define EMU_BOOT_MAX_TIME    (3000000)

#define HEARTBEAT_SEC   5

/*
 * Do we need to reset the whole card's hardware units?
 * currently, ./startup_system.sh also don't reset too, only reset pcie link.
 * so for stable, we undef first.
 */
//#define NEED_RESET_ALL_CARD

int cambr_virtcon_en = 0;
static u64 g_fp_global_id = 1;

module_param_named(virtcon_en, cambr_virtcon_en,
				   int, S_IRUGO | S_IWUSR | S_IWGRP);

static int cambr_mcu_version_check = 1;

module_param_named(mcu_version_check, cambr_mcu_version_check,
					int, 0664);

int isr_default_type = MSI;

char *isr_type = NULL;
module_param(isr_type, charp, 0444);
MODULE_PARM_DESC(isr_type, "Set specific interrupt type when loading kernel module");
int isr_type_index = -1;

char *platform_type = NULL;
module_param(platform_type, charp, 0444);
MODULE_PARM_DESC(platform_type, "Set specific platform type when loading kernel module");
int g_platform_type = 0;

static int mparam_launch_turbo = -1;
module_param_named(launch_turbo, mparam_launch_turbo,
				   int, S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(launch_turbo, "Set launch mode to accelerate kernel launch latency");

int mparam_report_mode = 1;
module_param_named(report, mparam_report_mode,
				   int, S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(report, "Set to gen report file automaticlly");

char *mparam_report_path = "/var/log/cambricon";
module_param_named(report_path, mparam_report_path,
				   charp, S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(report_path, "Set report file path. Default path is /var/log/cambricon");

static int cambr_inline_ecc_enable = -1;
module_param_named(inline_ecc_en, cambr_inline_ecc_enable,
				   int, S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(inline_ecc_en, "Set inline ecc enabled when loading kernel module");

/*
	bit 0:check less gen3x8
	bit 1:check slot link
	other bits reserve
	link_check=0.means disable check
*/
int link_check = 0x3;
module_param_named(check_en, link_check, int, 0664);
MODULE_PARM_DESC(check_en, "Allows users to checks by adding parameters when loading kernel module");

int cambr_cancel_heartbeat_check = 0;
module_param_named(cancel_heartbeat_check, cambr_cancel_heartbeat_check, int, 0664);
MODULE_PARM_DESC(cancel_heartbeat_check, "Allows users to cancel heartbeat checks by adding parameters when loading kernel module");

char *mparam_fw_path = NULL;
module_param_named(fw_path, mparam_fw_path,
				   charp, S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(fw_path, "Set firmware file path. Default path is NULL");

static int mparam_lpm_enable = 1;
module_param_named(lpm_enable, mparam_lpm_enable,
				   int, S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(lpm_enable, "Set lowpower manage enable or disable, default is enable");

int cn_core_lpm_enable(void)
{
	return mparam_lpm_enable;
}

static int mparam_lt_freq_cap = 1;
module_param_named(lt_cap, mparam_lt_freq_cap,
				   int, S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(lt_cap, "Set lt freq capping mode, default is enable");

int cn_core_lt_cap_enable(void)
{
	return mparam_lt_freq_cap;
}

static struct cn_core_index cn_core_idx[MAX_FUNCTION_NUM] = {{0}};
static DEFINE_SPINLOCK(core_set_lock);

static int heartbeat_thread_fn(void *data);
int set_core_boot_state(struct cn_core_set *core);
int set_core_boot_max_time(struct cn_core_set *core);

int unset_fw_workq(struct cn_core_set *core);

int cn_pre_check_dev_node(const char *name)
{
	char path[128];
	int ret = 0;
	struct file *f = NULL;

	sprintf(path, "/dev/%s", name);
	f = filp_open(path, O_RDONLY, 0);
	if (f && !IS_ERR(f)) {
		pr_err("[ERROR] Attention : %s shall not be exist\n", path);
		filp_close(f, NULL);
		ret = -1;
	}

	return ret;
}

struct cn_core_set *cn_core_get_with_idx(int idx)
{
	return (idx < 0 || idx >= MAX_FUNCTION_NUM) ? NULL
		: cn_core_idx[idx].cn_core;
}

/**
 * cambricon_dev and cap's unique_id, not compatible for ipcm unique_id
 *
 * Notice: MUST call cn_core_put() after using this core!!!
 */
struct cn_core_set *cn_core_get_with_unique_id(uint64_t unique_id)
{
	struct cnhost_minor *minor;
	struct cn_core_set *core = NULL;

	minor = cnhost_dev_minor_acquire(MAJOR(unique_id), MINOR(unique_id));
	if (IS_ERR_OR_NULL(minor))
		return NULL;

	if (minor->type == CNHOST_DEV_MINOR_SMLU_CAP) {
		core = cn_smlu_get_core(minor);
		if (likely(core)) {
			cnhost_dev_get(core->device);
		}
		cnhost_dev_minor_release(minor);
	} else if (minor->type == CNHOST_DEV_MINOR_MI_CAP || minor->type == CNHOST_DEV_MINOR_PHYSICAL) {
		core = (struct cn_core_set *)(minor->dev->dev_private);
		if (!core) {
			cnhost_dev_minor_release(minor);
		}
	}

	return core;
}

void cn_core_put(struct cn_core_set *core)
{
	cnhost_dev_put(core->device);
}

void core_set_release(struct kref *ref)
{
	struct cn_core_set *core_set = container_of(ref, struct cn_core_set, refcount);

	complete(&core_set->comp);
}

struct cn_core_set *cn_core_get_ref(int idx)
{
	struct cn_core_set *core = NULL;

	spin_lock(&core_set_lock);
	core = cn_core_get_with_idx(idx);
	if (core == NULL) {
		spin_unlock(&core_set_lock);
		return NULL;
	}
	if (!kref_get_unless_zero(&core->refcount)) {
		spin_unlock(&core_set_lock);
		return NULL;
	}
	spin_unlock(&core_set_lock);

	return core;
}

void cn_core_put_deref(struct cn_core_set *core_set)
{
	kref_put(&core_set->refcount, core_set_release);
}

struct cn_core_set *cn_core_get_mi_core(int phy_idx, int mi_idx)
{
	if (phy_idx < 0 || phy_idx >= MAX_PHYS_CARD ||
			mi_idx <= 0 || mi_idx > MAX_MI_COUNT)
		return NULL;

	return cn_core_idx[phy_idx].cn_mi_core[mi_idx];
}

struct cn_core_set *cn_core_get_mi_core_ref(int phy_idx, int mi_idx)
{
	struct cn_core_set *core = NULL;

	spin_lock(&core_set_lock);
	core = cn_core_get_mi_core(phy_idx, mi_idx);
	if (core == NULL) {
		spin_unlock(&core_set_lock);
		cn_dev_err("core set null");
		return NULL;
	}
	if (!kref_get_unless_zero(&core->refcount)) {
		spin_unlock(&core_set_lock);
		return NULL;
	}
	spin_unlock(&core_set_lock);

	return core;
}

uint32_t cn_core_get_proj_id(struct cn_core_set *core)
{
	uint32_t proj_id = 0;

	switch (core->device_id) {
	case MLUID_270:
	case MLUID_270V1:
	case MLUID_270V:
		proj_id = C20L_PROJ;
		break;
	case MLUID_290:
	case MLUID_290V1:
		proj_id = C20_PROJ;
		break;
	case MLUID_220:
		proj_id = C20E_PROJ;
		break;
	case MLUID_220_EDGE:
		proj_id = C20E_EDGE_PROJ;
		break;
	case MLUID_CE3226:
		proj_id = CE3226_PROJ;
		break;
	case MLUID_CE3226_EDGE:
		proj_id = CE3226_EDGE_PROJ;
		break;
	case MLUID_PIGEON:
		proj_id = PIGEON_PROJ;
		break;
	case MLUID_PIGEON_EDGE:
		proj_id = PIGEON_EDGE_PROJ;
		break;
	case MLUID_370:
	case MLUID_370V:
		proj_id = C30S_PROJ;
		break;
	case MLUID_370_DEV:
		proj_id = C30S_ARM_PROJ;
		break;
	case MLUID_590:
	case MLUID_590V:
		proj_id = C50_PROJ;
		break;
	case MLUID_590_DEV:
		proj_id = C50_ARM_PROJ;
		break;
	case MLUID_580:
	case MLUID_580V:
		proj_id = C50S_PROJ;
		break;
	case MLUID_580_DEV:
		proj_id = C50S_ARM_PROJ;
		break;
	default:
		WARN_ON(1);
	}

	return proj_id;
}

u64 cn_core_get_fp_id(struct file *fp)
{
	struct fp_priv_data *priv_data = fp->private_data;

	if (!priv_data || !priv_data->core) {
		cn_dev_warn("get fp id with invalid fp");
		return ~0ULL;
	}

	return priv_data->fp_id;
}

/* physical device consist of FULL_MLU, MIM_EN and SMLU_EN */
void cn_core_get_phys_dev_info(struct dev_info_s *phys_dev_info)
{
	struct cn_core_set *core;
	enum core_work_mode mode;
	dev_t devt;
	int i, idx = 0;

	memset(phys_dev_info, 0, sizeof(*phys_dev_info));

	for (i = 0; i < MAX_PHYS_CARD; i++) {
		core = cn_core_idx[i].cn_core;
		if (!core || core->state != CN_RUNNING)
			continue;

		mode = cn_core_get_work_mode(core);
		if (mode == FULL || mode == MIM_EN || mode == SMLU) {
			devt = cnhost_dev_get_devt(core->device);
			phys_dev_info->unique_id[idx] = (uint64_t)devt;
			idx++;
		}
	}

	phys_dev_info->dev_num = idx;
}

/* sub device consist of MI and SMLU-Instance */
void cn_core_get_sub_dev_info(struct cn_core_set *core,
			struct dev_info_s *sub_dev_info)
{
	struct cn_core_set *mi_core;
	enum core_work_mode mode;
	int i, idx = 0;
	dev_t devt;

	memset(sub_dev_info, 0, sizeof(*sub_dev_info));

	mode = cn_core_get_work_mode(core);
	if (mode == MI || mode == FULL) {
		return;
	} else if (mode == MIM_EN) {
		list_sub_vf_core(core->pf_idx, mi_core, i) {
			if (!mi_core)
				continue;

			devt = cnhost_dev_get_devt(mi_core->device);
			sub_dev_info->unique_id[idx] = (uint64_t)devt;
			idx++;
		}
		sub_dev_info->dev_num = idx;
	} else if (mode == SMLU) {
		cn_smlu_get_sub_dev_info(core, sub_dev_info);
	} else {
		cn_dev_core_err(core, "err core work mode:%d", mode);
		BUG_ON(1);
	}
}

static void cn_bootargs_isolcpus_init(struct cn_core_set *core)
{
	switch (core->device_id) {
	case MLUID_220:
	case MLUID_220_EDGE:
		break;
	case MLUID_270:
	case MLUID_270V:
	case MLUID_270V1:
		break;
	case MLUID_290:
	case MLUID_290V1:
		if (mparam_launch_turbo == 1)
			sprintf(core->cambr_configs, "sbts_isolcpus=1;bootargs_isolcpus=1;");
		else
			sprintf(core->cambr_configs, "sbts_isolcpus=2;bootargs_isolcpus=1,2;");
		break;
	case MLUID_370:
	case MLUID_370V:
		if (mparam_launch_turbo == 1)
			sprintf(core->cambr_configs, "sbts_isolcpus=1;bootargs_isolcpus=1;");
		else if (mparam_launch_turbo == 2)
			sprintf(core->cambr_configs, "sbts_isolcpus=2;bootargs_isolcpus=1,2;");
		else if (mparam_launch_turbo == 3)
			sprintf(core->cambr_configs, "sbts_isolcpus=3;bootargs_isolcpus=1,2,3;");
		else {
			if (core->board_info.board_idx == CN_MLU370_X4
				|| core->board_info.board_idx == CN_MLU370_X4K
				|| core->board_info.board_idx == CN_MLU370_X4L
				|| core->board_info.board_idx == CN_MLU370_X8
				|| core->board_info.board_idx == CN_MLU370_M8)
				sprintf(core->cambr_configs, "sbts_isolcpus=2;bootargs_isolcpus=1,2;");
			else
				sprintf(core->cambr_configs, "sbts_isolcpus=1;bootargs_isolcpus=1;");
		}
		break;
	case MLUID_CE3226:
	case MLUID_CE3226_EDGE:
	case MLUID_PIGEON:
	case MLUID_PIGEON_EDGE:
		break;
	case MLUID_590:
	case MLUID_590V:
	case MLUID_580:
	case MLUID_580V:
		if (mparam_launch_turbo == 1)
			sprintf(core->cambr_configs, "sbts_isolcpus=1;bootargs_isolcpus=1;");
		else if (mparam_launch_turbo == 2)
			sprintf(core->cambr_configs, "sbts_isolcpus=2;bootargs_isolcpus=1,2;");
		else if (mparam_launch_turbo == 3)
			sprintf(core->cambr_configs, "sbts_isolcpus=3;bootargs_isolcpus=1,2,3;");
		else
			sprintf(core->cambr_configs, "sbts_isolcpus=4;bootargs_isolcpus=1,2,3,4;");
		break;
	default:
		cn_dev_err("device [%#llx] not support dynamic loading kernel", core->device_id);
		break;
	}
}

static int cn_cfgs_init(struct cn_core_set *core)
{
	host_addr_t host_cfgs_addr;
	dev_addr_t dev_cfgs_addr;

	if (cn_core_is_vf(core))
		return 0;

	if (isEdgePlatform(core))
		return 0;

	cn_dev_debug("HW Bootargs init write device memory. Based On DeviceID.");
	host_cfgs_addr = cn_shm_get_host_addr_by_name(core, "configs_reserved");
	dev_cfgs_addr = cn_shm_get_dev_addr_by_name(core, "configs_reserved");
	if ((host_cfgs_addr == (host_addr_t)-1)
			|| (dev_cfgs_addr == (dev_addr_t)-1)) {
		cn_dev_core_err(core, "don't found configs_reserved in shm reserved!");
		return -EINVAL;
	}

	memset(core->cambr_configs, 0, sizeof(core->cambr_configs));
	cn_bootargs_isolcpus_init(core);
	cn_mm_bootargs_init(core);
	memcpy_toio((void *)host_cfgs_addr, core->cambr_configs,
					sizeof(core->cambr_configs));
	/* guarantee config data copied */
	smp_wmb();

	cn_dev_core_info(core, "core->cambr_configs = %s", core->cambr_configs);

	return 0;
}

static void cn_cfgs_exit(struct cn_core_set *core)
{

}

void cn_core_free_priv_data(struct file *fp, struct fp_priv_data *priv_data)
{
	if (!priv_data) {
		return;
	}

	if (priv_data->pid_info_node) {
		put_pid(priv_data->pid_info_node->taskpid);
		cn_kfree(priv_data->pid_info_node);
	}

	if (priv_data->monitor_priv_data) {
		cn_monitor_private_data_exit(priv_data);
	}

	if (priv_data->mm_priv_data) {
		cn_mem_private_data_exit((void *)priv_data);
	}

	if(priv_data->smlu_priv_data) {
		cn_smlu_private_data_exit(fp, priv_data);
	}

	if (priv_data->perf_priv_data) {
		cn_perf_private_data_exit(priv_data);
	}

	cn_sbts_priv_data_exit(priv_data);

	if (priv_data->mm_perf_priv_data) {
		cn_mem_perf_private_data_exit(priv_data);
	}

	cn_kfree(priv_data);
}

int cn_core_alloc_priv_data(struct file *fp,
		struct cn_core_set *core,
		struct fp_priv_data **ppdata)
{
	int ret;
	struct fp_priv_data *priv_data;
	struct pid_info_s *pid_info_node;

	priv_data = cn_kzalloc(sizeof(struct fp_priv_data), GFP_KERNEL);
	if (!priv_data) {
		cn_dev_core_err(core, "malloc priv_data fail");
		return -ENOMEM;
	}

	priv_data->core = core;
	priv_data->fp_id = __sync_fetch_and_add(&g_fp_global_id, 1);

	pid_info_node = cn_kzalloc(sizeof(struct pid_info_s), GFP_KERNEL);
	if (!pid_info_node) {
		cn_dev_core_err(core, "malloc pid_info_node fail");
		ret = -ENOMEM;
		goto priv_alloc_err;
	}

	pid_info_node->fp = fp;
	pid_info_node->phy_usedsize = 0;
	pid_info_node->vir_usedsize = 0;
	pid_info_node->tgid = current->tgid;
	pid_info_node->active_ns = task_active_pid_ns(current);
	pid_info_node->active_pid =
		task_tgid_nr_ns(current, pid_info_node->active_ns);
	pid_info_node->pgid =
		task_pgrp_nr_ns(current, pid_info_node->active_ns);
	pid_info_node->taskpid = find_get_pid(current->pid);

	priv_data->pid_info_node = pid_info_node;

	ret = cn_mem_private_data_init(priv_data);
	if (ret) {
		cn_dev_core_err(core, "mem private data init fail");
		goto priv_alloc_err;
	}

	ret = cn_smlu_private_data_init(fp, priv_data);
	if (ret) {
		cn_dev_core_err(core, "smlu private data init fail");
		goto priv_alloc_err;
	}

	ret = cn_monitor_private_data_init(priv_data);
	if (ret) {
		cn_dev_core_err(core, "monitor private data init failed!");
		goto priv_alloc_err;
	}

	ret = cn_perf_private_data_init(priv_data);
	if (ret) {
		cn_dev_core_err(core, "perf private data init failed!\n");
		goto priv_alloc_err;
	}

	ret = cn_sbts_priv_data_init(priv_data);
	if (ret) {
		cn_dev_core_err(core, "sbts private data init failed!\n");
		goto priv_alloc_err;
	}

	ret = cn_mem_perf_private_data_init(priv_data);
	if (ret) {
		cn_dev_core_err(core, "mem perf private data init failed!");
		goto priv_alloc_err;
	}

	*ppdata = priv_data;

	return 0;

priv_alloc_err:
	cn_core_free_priv_data(fp, priv_data);
	return ret;
}

static inline bool need_lpm(struct cn_core_set *core)
{
	/* just less than 500 product or ce, need exit lp when core open.
	 * great and equal than 500 product, will exit lp when create context.
	 * task mode will not exit lp when core open.
	 */
	return (cn_sbts_lpm_mode_check(core, CN_SBTS_LP_USER_RUNTIME)
			&& ((MLUID_MAJOR_ID(core->device_id) < 5) || isCEPlatform(core)));
}

static int cn_core_replace(struct cn_core_set **core, struct cnhost_minor **minor)
{
	struct cn_core_set *mi_core;
	struct tid_cap_node *tid_cap_node;
	struct inode *mi_cap_inode;
	struct list_head *tid_cap_list_head;
	struct mutex *tid_cap_lock;

	tid_cap_list_head = &(*core)->tid_cap_list_head;
	tid_cap_lock = &(*core)->tid_cap_lock;

	mutex_lock(tid_cap_lock);
	list_for_each_entry(tid_cap_node, tid_cap_list_head, list) {
		if (tid_cap_node->pid == current->pid) {
			mi_core = tid_cap_node->core;
			if (!mi_core || mi_core->state == CN_RESET) {
				mutex_unlock(tid_cap_lock);
				return -ENODEV;
			}
			if (mi_core->pf_idx != (*core)->pf_idx) {
				cn_dev_core_err(*core, "bind MI core failed, dev pf_idx:%d, "
					"mi_cap pf_idx:%d, not match", (*core)->pf_idx, mi_core->pf_idx);
				mutex_unlock(tid_cap_lock);
				return -EFAULT;
			}

			*core = mi_core;
			tid_cap_node->core = NULL;
			mi_cap_inode = tid_cap_node->inode;
			cnhost_dev_minor_release(*minor);
			*minor = cnhost_dev_minor_acquire(imajor(mi_cap_inode),
							iminor(mi_cap_inode));
			if (IS_ERR(*minor)) {
				mutex_unlock(tid_cap_lock);
				return PTR_ERR(*minor);
			}

			cn_dev_core_debug(mi_core, "bind MI core success, pf_idx:%d, vf_idx:%d",
				mi_core->pf_idx, mi_core->vf_idx);

			break;
		}
	}
	mutex_unlock(tid_cap_lock);

	return 0;
}

int cn_core_open(struct inode *inode, struct file *fp)
{
	struct cn_core_set *core;
	struct pid_info_s *pid_info_node;
	struct fp_priv_data *priv_data;
	u32 cnt = 200;
	int ret;
	struct cnhost_minor *minor;

	minor = cnhost_dev_minor_acquire(imajor(inode), iminor(inode));
	if (IS_ERR(minor))
		return PTR_ERR(minor);

	core = (struct cn_core_set *)(minor->dev->dev_private);
	if (!core) {
		ret = -ENODEV;
		goto dev_minor_release;
	}

	if (!cn_core_is_vf(core) && cn_dm_is_mim_mode_enable(core)) {
		ret = cn_core_replace(&core, &minor);
		if (ret < 0) {
			cn_dev_core_err(core, "bind MI core failed");
			goto dev_minor_release;
		}
	}

	if (cn_is_smlu_en(core)) {
		/* if cambricon-util_drv.ko exists and the device node is first
		 * opened, then increase cambricon-util_drv.ko refcnt to ensure
		 * it not removed while in using; if not exists, will not support
		 * utilization restriction */
		cn_smlu_get_util_adjust_fn(core);
		ret = smlu_cap_bind_namespace(core);
		if (ret) {
			cn_dev_core_err(core, "bind sMLU instance failed");
			goto smlu_put_util_module;
		}
	}

	/* waiting for boot finished or boot error */
	while ((core->state != CN_RUNNING) && cnt) {
		if (core->state == CN_BOOTERR ||
				core->state == CN_RESET_ERR) {
			cn_dev_core_err(core,
				"open failed, core status is 0x%x",
				core->state);
			ret = -EINVAL;
			goto smlu_put_util_module;
		}
		msleep(50);
		cnt--;
	}

	if (cnt == 0) {
		cn_dev_core_err(core, "open failed, core status is 0x%x",
			core->state);
		ret = -EINVAL;
		goto smlu_put_util_module;
	}

	if (core->exclusive_mode == PROHIBITED_PROCESS) {
		cn_dev_core_err(core, "dev is in prohibit_mode");
		ret = -EBUSY;
		goto smlu_put_util_module;
	}
	ret = cn_core_alloc_priv_data(fp, core, &priv_data);
	if (ret) {
		cn_dev_core_err(core, "alloc for user:%px priv data fail", fp);
		goto smlu_put_util_module;
	}
	pid_info_node = priv_data->pid_info_node;

	spin_lock(&core->pid_info_lock);
	if (core->state != CN_RUNNING) {
		ret = -EFAULT;
		goto priv_data_free;
	}

	__sync_add_and_fetch(&core->open_count, 1);
	list_add_tail(&pid_info_node->pid_list, &core->pid_head);
	spin_unlock(&core->pid_info_lock);

	ret = cn_lpm_get_all_module_with_cond(core, need_lpm(core));
	if (ret) {
		cn_dev_core_err(core, "lpm get error");
		goto lpm_get_err;
	}

	priv_data->fp_minor = minor;
	if(core->exclusive_mode == COMPUTEMODE_EXCLUSIVE_PROCESS) {
		priv_data->state = INVALID_FP_STATE;
	} else {
		priv_data->state = VALID_FP_STATE;
	}

	/* create a reference to out char device in the opened file */
	fp->private_data = priv_data;
	cn_dev_core_debug(core, "device opened!");

	return 0;

lpm_get_err:
	spin_lock(&core->pid_info_lock);
	list_del(&pid_info_node->pid_list);

	if (!__sync_sub_and_fetch(&core->open_count, 1)) {
		cn_sbts_restore_resource(core);
		core->exclusive_pgid = -1;
	}
priv_data_free:
	spin_unlock(&core->pid_info_lock);
	cn_core_free_priv_data(fp, priv_data);

smlu_put_util_module:
	if (cn_is_smlu_en(core))
		cn_smlu_put_util_adjust_fn(core);

dev_minor_release:
	cnhost_dev_minor_release(minor);

	return ret;
}

int cn_core_close(struct inode *inode, struct file *fp)
{
	struct fp_priv_data *priv_data = fp->private_data;
	struct cn_core_set *core = NULL;
	struct pid_info_s *pid_info_node = NULL;
	struct cnhost_minor *minor;

	if (!priv_data) {
		cn_dev_info("priv_data = NULL!");
		return 0;
	}

	minor = priv_data->fp_minor;
	core = priv_data->core;
	pid_info_node = priv_data->pid_info_node;

	cn_sbts_do_exit((cn_user)fp, core);
	cn_mem_do_exit((u64)fp, core);
	cn_monitor_do_exit((u64)fp, core);
	cn_lpm_put_all_module_with_cond(core, need_lpm(core));

	if (cn_is_smlu_en(core)) {
		/* if cambricon-util_drv.ko exists and the device node is the last
		 * closed, then decrease cambricon-util_drv.ko refcnt to ensure
		 * it can be removed later */
		cn_smlu_put_util_adjust_fn(core);
	}

	spin_lock(&core->pid_info_lock);
	list_del(&pid_info_node->pid_list);

	if (!__sync_sub_and_fetch(&core->open_count, 1)) {
		cn_sbts_restore_resource(core);
		core->exclusive_pgid = -1;
	}
	spin_unlock(&core->pid_info_lock);

	cn_core_free_priv_data(fp, priv_data);
	fp->private_data = NULL;
	cnhost_dev_minor_release(minor);
	cn_dev_core_debug(core, "device closed!");

	return 0;
}

ssize_t cn_core_read(
		struct file *fp, char __user *buf,
		size_t count, loff_t *pos)
{
	int ret = 0;

	return count - ret;
}

ssize_t cn_core_write(
		struct file *fp, const char __user *buf,
		size_t count, loff_t *pos)
{
	int ret = 0;

	return ret;
}

static loff_t cn_core_llseek(struct file *fp, loff_t off, int whence)
{
	return 0;
}

/*
 * maps the iomem resources into userspace for memory-like access using mmap()
 */
static int cn_core_mmap(struct file *fp, struct vm_area_struct *vma)
{
	struct fp_priv_data *priv_data = fp->private_data;
	struct cn_core_set *core = NULL;

	if (!priv_data) {
		cn_dev_err("fp_priv_data = NULL");
		return -EINVAL;
	}

	core = (struct cn_core_set *)priv_data->core;

	cn_dev_core_debug(core, "%s", __func__);

	return 0;
}

static
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36))
int
#else
long
#endif
cn_core_ioctl(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36))
		struct inode *inode,
#endif
		struct file *fp,
		unsigned int cmd,
		unsigned long arg)
{
	long ret = 0;
	struct cn_core_set *core = NULL;
	struct fp_priv_data *priv_data = fp->private_data;

	if (!priv_data) {
		return -EINVAL;
	}

	core = priv_data->core;

	if (!core)
		return -EINVAL;

	if (core->state != CN_RUNNING) {
		cn_dev_core_err(core, "Device pending! Please close FD");
		cn_dev_core_err(core, "core status is 0x%x", core->state);
		return -ENODEV;
	}

	if (core->mig_pending) {
		ret = wait_event_killable(core->mig_wq, !core->mig_pending);
		if (ret == -ERESTARTSYS) {
			cn_dev_core_err(core, "fatal signal received when wait_event.");
			goto RETURN;
		}
	}

	if(unlikely(priv_data->state == INVALID_FP_STATE)) {
		if(_IOC_TYPE(cmd) == CAMBRICON_MAGIC_NUM) {
			ret = cn_attr_ioctl(fp, core, cmd, arg);
		} else {
			struct pid_info_s *pid_info_node = priv_data->pid_info_node;

			__sync_bool_compare_and_swap(&core->exclusive_pgid, -1, pid_info_node->pgid);
			if(core->exclusive_pgid == pid_info_node->pgid) {
				priv_data->state = VALID_FP_STATE;
				goto IOCTL_PROC;
			}
			cn_dev_core_err(core, "In exclusive now, dev is owned by user pgid %d.", core->exclusive_pgid);
			ret = -EBUSY;
		}
		goto RETURN;
	}

IOCTL_PROC:
	switch (_IOC_TYPE(cmd)) {
	case CAMBR_BUS_MAGIC:
		ret = cn_bus_ioctl(core, cmd, arg);
		break;
	case CAMBR_MM_MAGIC:
		ret = cn_mm_ioctl(fp, core, cmd, arg);
		break;
	case CAMBR_MONITOR_MAGIC:
		ret = cn_monitor_ioctl(fp, core, cmd, arg);
		break;
	case CAMBRICON_MAGIC_NUM:
		ret = cn_attr_ioctl(fp, core, cmd, arg);
		break;
	case CAMBR_SBTS_MAGIC:
	case CAMBR_NCS_MAGIC:
		ret = cn_sbts_dev_ioctl(core, cmd, arg, fp);
		break;
	case CAMBR_HB_MAGIC:
		ret = cn_expmnt_ioctl(core, cmd, arg);
		break;
	case CAMBR_I2C_MAGIC:
		ret = cn_i2c_ioctl(core, cmd, arg);
		break;
	case CAMBR_MIGRATION_MAGIC:
		ret = cn_mig_ioctl(core, cmd, arg);
		break;
	case CAMBR_CTX_MAGIC:
		ret = cn_ctx_ioctl(core, cmd, arg, fp);
		break;
	default:
		cn_dev_core_err(core, "IOCTRL command type mismatch!, %d",
			_IOC_TYPE(cmd));
		ret = -EINVAL;
	}

RETURN:
	return ret;
}

/*
 * character device file operations for control bus
 */
static const struct file_operations cndrv_core_dev_fops = {
	.owner = THIS_MODULE,
	.open = cn_core_open,
	.release = cn_core_close,
	.llseek = cn_core_llseek,
	.read = cn_core_read,
	.write = cn_core_write,
	.mmap = cn_core_mmap,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36))
	.ioctl   =  cn_core_ioctl,
#else
	.unlocked_ioctl = cn_core_ioctl,
#endif
};

static const struct cnhost_driver cndrv_core_dev_drv = {
	.fops = &cndrv_core_dev_fops,
	.name = "cambricon-dev",
};

int cn_cdev_late_init(struct cn_core_set *core)
{
	int ret = 0;
	struct cnhost_device *ddev;

	if (cn_core_is_vf(core) && cn_is_mim_en(core))
		return 0;

	ddev = core->device;

	ret = cnhost_dev_register(ddev, 0);
	if (ret)
		goto err_put;

	cn_dev_core_info(core, "cdev %u:%u, %s, added",
		core->device->primary->major,
		core->device->primary->index,
		dev_name(core->device->primary->kdev));

	return 0;

err_put:
	cnhost_dev_put(ddev);
	return ret;
}

int cn_cdev_init(struct cn_core_set *core)
{
	int ret = 0;
	struct cnhost_device *ddev;

	if (cn_core_is_vf(core) && cn_is_mim_en(core))
		return 0;

	/* initialize control character devicee */
	spin_lock_init(&core->lock);

	ddev = cnhost_dev_alloc(&cndrv_core_dev_drv, core, CNHOST_DEV_MINOR_PHYSICAL, core->pf_idx, 0);

	if (IS_ERR(ddev))
		return PTR_ERR(ddev);

	core->device = ddev;

	cn_core_idx[core->idx].major = ddev->primary->major;
	cn_core_idx[core->idx].minor = ddev->primary->index;

#ifdef CONFIG_CNDRV_EDGE
	ret = cn_cdev_late_init(core);
#endif

	return ret;
}

void cn_cdev_late_exit(struct cn_core_set *core)
{
	if (cn_core_is_vf(core) && cn_is_mim_en(core))
		return;

	if (core->device) {
		cn_dev_core_info(core, "cdev %u:%u, %s, deleted",
			core->device->primary->major,
			core->device->primary->index,
			dev_name(core->device->primary->kdev));

		cnhost_dev_unregister(core->device);
	}
}

void cn_cdev_exit(struct cn_core_set *core)
{
	if (cn_core_is_vf(core) && cn_is_mim_en(core))
		return;

#ifdef CONFIG_CNDRV_EDGE
	cn_cdev_late_exit(core);
#endif
	cnhost_dev_put(core->device);
	core->device = NULL;
}

int cn_core_edge_boot_check(struct cn_core_set *core)
{
	int state;

	state = service_startup_status(core);
	if (state)
		return state;

	core->boot_count++;
	if (core->boot_count > core->boot_max_time)
		return -1;

	msleep(100);

	return 0;
}

int heartbeat_thread_init(struct cn_core_set *core)
{
	int ret = 0;
	struct cn_bus_set *bus_set = core->bus_set;

	if (cn_core_is_vf(core) || cn_is_mim_en(core) || isEdgePlatform(core)) {
		cn_dev_core_info(core, "heartbeat_thread no support 370 or 590 dev.\n");
		return 0;
	}

	if (cambr_cancel_heartbeat_check) {
		cn_dev_core_info(core, "cancel heartbeat check.\n");
		return 0;
	}

	if (g_platform_type != MLU_PLAT_ASIC) {
		cn_dev_core_info(core, "platform is not asic cancel heartbeat\n");
		return 0;
	}

	cn_dev_core_info(core, "heartbeat_thread init");
	bus_set->thread_exit = false;
	bus_set->heartbeat_thread = kthread_run(heartbeat_thread_fn, bus_set, "cn_dev_hb_wq");
	if (IS_ERR(bus_set->heartbeat_thread)) {
		pr_err("heartbeat thread failed\n");
		return -1;
	}

	return ret;
}

int heartbeat_thread_exit(struct cn_core_set *core)
{
	int ret = 0;
	struct cn_bus_set *bus_set = NULL;

	if (!core) {
		cn_dev_warn("maybe card falled off");
		return -EINVAL;
	}
	bus_set = core->bus_set;

	if (cn_core_is_vf(core) || cn_is_mim_en(core) || isEdgePlatform(core)) {
		cn_dev_core_info(core, "heartbeat_thread no support 370 or 590 dev.\n");
		return 0;
	}

	if (cambr_cancel_heartbeat_check) {
		return 0;
	}

	if (g_platform_type != MLU_PLAT_ASIC) {
		return 0;
	}

	if (!bus_set->heartbeat_thread)
		return ret;

	bus_set->thread_exit = true;
	smp_mb();
	send_sig(SIGKILL, bus_set->heartbeat_thread, 1);
	kthread_stop(bus_set->heartbeat_thread);
	bus_set->heartbeat_thread = NULL;
	cn_dev_core_info(core, "heartbeat_thread exit");

	return ret;
}

static char *str_cnstat[] = {
	"CN_EARLYINITED",
	"CN_BRINGUP",
	"CN_BOOTING",
	"CN_LATEINIT",
	"CN_RUNNING",
	"CN_BOOTERR",
	"CN_RESET",
	"CN_RESET_ERR",
	"CN_UNKNOWN",
	""
};

char *cn_get_core_state_string(enum cn_boot_state state)
{
	if (state >= CN_EARLYINITED && state <= CN_UNKNOWN)
		return str_cnstat[state];
	else
		return "CN_UNKNOWN";
}

void cn_core_dump_device_pc(struct cn_core_set *core)
{
	uint32_t reg_data[2] = {0};
	unsigned long addr_offset = 0;
	int i = 0;
	int acpu_num = 4;

	switch (core->device_id) {
	case MLUID_370:
		addr_offset = 0x8500180;
		break;
	case MLUID_220:
	case MLUID_270:
	case MLUID_290:
	/* CTRL_BASE_ADDR + CPU_SUBSYS_CTRL__CPU_CORE0_PCL__ADDR */
		addr_offset = 0x600200;
		break;
	case MLUID_580:
	case MLUID_590:
		addr_offset = 0x800180;
		break;
	case MLUID_CE3226:
		addr_offset = 0x600180;
		break;
	default:
		cn_dev_core_info(core, "not support dump pc for device 0x%llx", core->device_id);
		return;
	}

	switch (core->device_id) {
	case MLUID_290:
	case MLUID_590:
	case MLUID_580:
		acpu_num = 6;
		break;
	default:
		acpu_num = 4;
		break;
	}

	for (i = 0; i < acpu_num; i++) {
		reg_data[0] = reg_read32(core->bus_set, addr_offset + i * 8);
		reg_data[1] = reg_read32(core->bus_set, addr_offset + i * 8 + 4);
		cn_dev_core_info(core, "apu core[%d] pc = 0x%llx", i, (((uint64_t)reg_data[1]) << 32) | reg_data[0]);
	}
}

void cn_core_dump_device_info(struct cn_core_set *core)
{
	cn_core_dump_device_pc(core);
	cn_core_show_mlumsg(core);
}

int cn_core_bootm(struct cn_core_set *core)
{
	int state, nxtstat;
	int ret;
	ulong current_ts;

	state = core->state;
	nxtstat = state;
	current_ts = jiffies;

	switch (state) {
	case CN_EARLYINITED:
		if (cn_core_is_vf(core))
			nxtstat = CN_LATEINIT;
		else
			nxtstat = CN_BRINGUP;
		break;
	case CN_BRINGUP:
		ret = cn_bringup(core);
		if (!ret) {
			nxtstat = CN_BOOTING;
			current_ts = jiffies;
			cn_dev_core_info(core,
				"%s Firmware Bringup cost:%lus %lu",
				core->core_name, (current_ts - core->boot_ts) / HZ,
				current_ts - core->boot_ts);
			cn_dev_core_info(core,
				"Firmware Version: %s",
				core->firmware_version);
		} else {
			nxtstat = CN_BOOTERR;
		}

		break;
	case CN_BOOTING:
		ret = cn_core_edge_boot_check(core);
		if (ret > 0) {
			if (core->reset_flag == RESET_ACPU_ONLY)
				nxtstat = CN_RUNNING;
			else
				nxtstat = CN_LATEINIT;
			current_ts = jiffies;
			cn_dev_core_info(core,
				"%s ARM Boot cost: %lus %lu",
				core->core_name, (current_ts - core->boot_ts) / HZ,
				current_ts - core->boot_ts);
			if (ret > 1)
				cn_dev_core_err(core,
					"%s boot check value %d is not 1",
					core->core_name, ret);
		} else if (ret < 0) {
			cn_dev_core_err(core,
					"%s Boot Timeout.", core->core_name);
			nxtstat = CN_BOOTERR;
			cn_core_dump_device_info(core);
		}
		break;
	case CN_LATEINIT:
		/***
		 * Do 'information-sync-align' between S/C.
		 */
		cndrv_mcu_set_host_driver_status(core, 1);

		ret = cn_dm_init_domain(core);
		if (!ret) {
			nxtstat = CN_RUNNING;
			current_ts = jiffies;
			cn_dev_core_info(core,
				"%s CardLate Init cost: %lus %lu",
				 core->core_name, (current_ts - core->boot_ts) / HZ,
				 current_ts - core->boot_ts);
		} else
			nxtstat = CN_BOOTERR;

		break;
	case CN_RUNNING:
		cn_dev_core_info(core,
			"%s Boot Finish, Running now...", core->core_name);
		break;
	case CN_BOOTERR:
		cn_dev_core_err(core,
			"%s Boot Error on State: %s",
			core->core_name, cn_get_core_state_string(core->last_state));
		break;
	default:
		cn_dev_core_err(core,
			"%s invalid state:%d", core->core_name, state);
		return -1;
	}

	if (nxtstat != state) {
		core->last_state = state;
		core->state = nxtstat;
		core->boot_ts = current_ts;
		cn_dev_core_info(core, "%s State change from %s to %s",
				core->core_name, cn_get_core_state_string(state),
				cn_get_core_state_string(nxtstat));
		cn_dev_core_info(core, "current time: %lus %lu",
				current_ts / HZ, current_ts);
	}

	return 0;
}

static void cn_bootm_work(struct work_struct *work)
{
	struct cn_core_set* core;
	int ret;

	core = container_of(work, struct cn_core_set, runqueue_work);

	cn_dev_core_info(core, "%s boot working!", core->core_name);
	/*initial the state value*/
	if (!cn_core_is_vf(core))  /*temporary*/
		clear_serv_status(core);

	do {
		mutex_lock(&core->runqueue_mutex);
		if (core->workq_state & WORKQ_ABORT) {
			core->workq_state = WORKQ_FINISH;
			mutex_unlock(&core->runqueue_mutex);
			return;
		}
		mutex_unlock(&core->runqueue_mutex);

		ret = cn_core_bootm(core);
		if (ret) {
			cn_dev_core_err(core,
				"%s boot status error", core->core_name);
			break;
		} else if (core->state == CN_RUNNING) {
			cn_dev_core_info(core, "%s boot ok", core->core_name);
			kref_init(&core->refcount);
			break;
		} else if (core->state == CN_BOOTERR) {
			cn_dev_core_err(core,
				"%s boot error", core->core_name);
			break;
		}
	} while (1);

	mutex_lock(&core->runqueue_mutex);
	core->workq_state = WORKQ_FINISH;
	mutex_unlock(&core->runqueue_mutex);
}

int setup_fw_workq(struct cn_core_set* core)
{
	int ret = 0;

	core->workq_state = WORKQ_RUNNING;
	INIT_WORK(&core->runqueue_work, cn_bootm_work);
	mutex_init(&core->runqueue_mutex);
	queue_work(system_unbound_wq, &core->runqueue_work);

	return ret;
}

int unset_fw_workq(struct cn_core_set *core)
{
	int count = 300;
	bool cancel_ret = false;

	mutex_lock(&core->runqueue_mutex);
	if (core->workq_state & WORKQ_ABORT) {
		cn_dev_core_info(core, "workq already abort, to avoid flush_workqueue crash, just return");
		mutex_unlock(&core->runqueue_mutex);
		return 0;
	}

	cn_dm_exit_domain(core);
	if (core->workq_state != WORKQ_FINISH)
		core->workq_state |= WORKQ_ABORT;

	mutex_unlock(&core->runqueue_mutex);
	while (--count) {
		if (core->workq_state == WORKQ_FINISH) {
			cn_dev_core_info(core, "workq exit on %d", count);
			break;
		}
		msleep(20);
	}
	if (!count) {
		cn_dev_core_err(core, "wait workq exit timeout");
		return -1;
	}
	core->workq_state |= WORKQ_ABORT;
	cancel_ret = flush_work(&core->runqueue_work);
	cancel_ret = cancel_work_sync(&core->runqueue_work);

	if (cancel_ret)
		cn_dev_core_info(core, "cancel_work_sync=%d", cancel_ret);

	return 0;
}

int cn_core_probe(struct cn_bus_set *bus_set, u64 device_id, u8 type, int idx);
int cn_core_remove(void *core_data);

int cn_core_reset(struct cn_core_set *core, bool reset)
{
	struct cn_bus_set *bus_set = core->bus_set;
	struct pid_info_s *pid_info_node;
	u32 cnt = 5;
	int ret = 0;
	struct task_struct *task = NULL;
	u64 device_id = core->device_id;
	u8 type = core->type;
	int idx = core->idx;

	spin_lock(&core->pid_info_lock);
	core->state = CN_RESET;
	spin_unlock(&core->pid_info_lock);

	while (cnt) {
		spin_lock(&core->pid_info_lock);
		if (core->open_count == 0) {
			spin_unlock(&core->pid_info_lock);
			break;
		}
		spin_unlock(&core->pid_info_lock);
		cn_dev_core_info(core,
			"Can't reset, waiting for user to close FD");
		cn_dev_core_info(core, "open count: %d, cnt: %d", core->open_count, cnt);
		ssleep(1);
		cnt--;
	}

	/**
	 * NOTE: vmm alloc device memory not depend core_open. we still need kill vmm process
	 * as well. Avoid these process access memory after mlu reset.
	 **/
	cn_mem_vmm_process_release(core);

	if (core->open_count) {
		spin_lock(&core->pid_info_lock);
		list_for_each_entry(pid_info_node, &core->pid_head, pid_list) {
			task = get_pid_task(pid_info_node->taskpid, PIDTYPE_PID);
			if (task) {
				cn_dev_core_info(core,
						"Killing user processes pid=%d, open count : %d", task_pid_nr(task), core->open_count);
				send_sig(SIGKILL, task, 1);
				mdelay(100);
				put_task_struct(task);
			}
		}
		spin_unlock(&core->pid_info_lock);
	}

	while (core->open_count) {
		cn_dev_core_info(core,
			"Can't reset, waiting for user to close FD, open count : %d", core->open_count);
		ssleep(5);
	}

	if (core->device_id == MLUID_290) {
		if (!(core->board_info.mcu_info.mcu_major < 2 && (core->board_info.mcu_info.mcu_minor > 0 || core->board_info.mcu_info.mcu_build > 0)))
			reset = false;
	}

	cn_core_remove(core);

	ret = cn_bus_soft_reset(bus_set, reset);
	if (ret)
		pr_info("bus reset fail\n");

	return cn_core_probe(bus_set, device_id, type, idx);
}

static void state_monitor_kthread_fn(void *arg)
{
	struct cn_core_set *core = (struct cn_core_set *)arg;
	struct cn_bus_set *bus_set = core->bus_set;
	int i;
	u32 bdf;

	if (cn_bus_check_available(bus_set)) {
		bdf = cn_bus_get_current_bdf(bus_set);
		cn_dev_core_err(core, "MLU has fallen off the bus, bdf is %x", bdf);
	}

	cn_bus_pll_irq_sts_dump(bus_set);

	for (i = 0; i < STAT_TEMPERATURE_NUM; i++) {
		core->temperature[i] = core->temperature[i + 1];
	}

	cndrv_mcu_read_max_temp(core, &core->temperature[STAT_TEMPERATURE_NUM]);
}

#define STATE_MONITOR_PERIOD 5000
int cn_state_monitor_kthread_init(struct cn_core_set *core)
{
	struct cn_kthread_t t;
	struct cn_kthread_set *kthread_set;
	char *kthread_name;
	void *ret;

	if (cn_core_is_vf(core) || cn_is_mim_en(core))
		return 0;

	kthread_set = cn_kzalloc(sizeof(struct cn_kthread_set), GFP_KERNEL);
	if (!kthread_set) {
		cn_dev_core_err(core, "malloc kthread_set fail");
		return -ENOMEM;
	}

	core->state_monitor_kthread = (void *)kthread_set;
	kthread_name = kthread_set->name;
	snprintf(kthread_name, 64, "state_monitor_kthread_%d", core->idx);

	t.name = kthread_name;
	t.expire = STATE_MONITOR_PERIOD;
	t.fn = state_monitor_kthread_fn;
	t.arg = (void *)core;
	t.type = CN_TIMER_GLOBAL;

	ret = cn_timer_kthread_register(core, &t);
	if (!ret) {
		cn_dev_core_err(core, "%s register error", kthread_name);
		return -1;
	}

	kthread_set->node = (struct list_head *)ret;

	return 0;
}

void cn_state_monitor_kthread_exit(struct cn_core_set *core)
{
	struct cn_kthread_set *kthread_set = core->state_monitor_kthread;

	if (cn_core_is_vf(core) || cn_is_mim_en(core))
		return;

	if (kthread_set) {
		cn_timer_kthread_unregister(core, kthread_set->node);
		cn_dev_core_info(core, "state_monitor_kthread unregistered");
		cn_kfree(kthread_set);
	}
}

static int heartbeat_thread_fn(void *data)
{
	struct cn_bus_set *bus_set = data;
	struct cn_core_set *core;
	unsigned long bitmap = 0;
	int ret = 0, timeout_cnt = 0;
	int report_state = 0, report_mode = 0, report_on = 0;

	allow_signal(SIGKILL);
	while (!kthread_should_stop()) {
		core = bus_set->core;
		msleep_interruptible(HEARTBEAT_SEC * 1000);

		cn_dev_core_debug(core, "%s enter", __func__);
		if (bus_set->thread_exit == true) {
			msleep(20);
			continue;
		}

		cn_bus_mlu_mem_client_init(bus_set);
		if (core->mnt_set == NULL)
			continue;

		if (cn_is_smlu_en(core)) {
			continue;
		}

		if (core->state != CN_RUNNING) {
			if (core->heartbeat_wait_cnt == 10)
				cn_core_dump_device_info(core);
			core->heartbeat_wait_cnt++;
			cn_dev_core_info(core,
					"device is not running, core status is %s",
					cn_get_core_state_string(core->state));
			continue;
		}

		if (core->reset_flag)
			goto triger_reset;

		/*debugfs for test*/
		if (core->heartbeat_error) {
			if (!cn_is_mim_en(core) && !cn_core_is_vf(core)) {
				shutdown(core);
				timeout_cnt = 3;
			} else {
				timeout_cnt = 0;
				cn_dev_core_info(core, "do not triger procfs hb in sriov and vf mode!");
			}
			core->heartbeat_error = 0;
		}
		else
			timeout_cnt = 0;

		report_mode = cn_report_get_report_mode(core);
		report_on = cn_report_get_report_on(core);

		if ((report_mode > 0) || (report_on == 1)) {
			ret = cn_report_query(core, &report_state);
			if (((ret >= 0) && (report_state == 1)) || (report_on > 0)) {
				cn_dev_core_info(core, "report flag have been set:%d %d %d",
						ret, report_state, report_on);
				cn_report_run(core, 0xFFFFFFFF, 0);
				cn_report_set_report_on(core, 0);
			}
		}

		do {
			ret = cn_device_status_query(core, &bitmap);
			if (ret < 0) {
				timeout_cnt++;
			}
		} while (ret < 0 && timeout_cnt < 3);

		if (timeout_cnt >= 3)
			cn_dev_core_err(core, "query heartbeat timeout");
		else if (!ret) {
			if (!bitmap)
				continue;
			else {
				show_all_info(core);
			}
		} else
			continue;

		cn_dev_core_info(core, "bitmap : 0x%lx", bitmap);
		cn_dev_core_info(core, "heartbeat exception");

triger_reset:
		cn_core_dump_device_info(core);
		cn_mcc_dump_llc_state(core);
		cn_bus_debug_dump_reg(bus_set);
		cn_report_run(core, 0xFFFFFFFF, 1);
		cn_commu_reset_callback(core);
		ipcm_reset_callback(core);

		if (!cn_is_mim_en(core) && !cn_core_is_vf(core)) {
			core->reset_flag = RESET_ALL;
			ret = cn_core_reset(core, true);
			if (ret) {
				/*Reset Fail to EXIT*/
				return -EINVAL;
			}
		} else {
			cn_dev_core_info(core, "do not reset in sriov and vf mode!");
		}
	}

	return 0;
}

int cn_core_set_idx(struct cn_core_set *core)
{
	int i;
	int vf_idx;

	if (!cn_core_is_vf(core))
		return 0;

	/**
	 * Traverse cn_core_idx array to search the PF core that
	 * this VF core belongs to. If found, vf_idx returned by
	 * cn_bus_get_vf_idx() will >= 0, otherwise not match.
	 */
	for (i = 0; i < MAX_PHYS_CARD; i++) {
		if ((!cn_core_idx[i].cn_core) || cn_core_is_vf(cn_core_idx[i].cn_core))
			continue;

		vf_idx = cn_bus_get_vf_idx(cn_core_idx[i].cn_core->bus_set, core->bus_set);
		if (vf_idx >= 0) {
			core->pf_idx = cn_core_idx[i].cn_core->pf_idx;
			core->vf_idx = vf_idx + 1;
			cn_core_idx[core->pf_idx].cn_mi_core[core->vf_idx] = core;
			sprintf(core->core_name, "Card%d-MI%d",
						core->pf_idx, core->vf_idx);
			return 0;
		}
	}

	cn_dev_core_err(core, "Can't find the pf device");
	return -1;
}

int cn_core_init_idx(struct cn_core_set *core)
{
	/* FULL MLU or MIM-EN-MLU on Host or MI in VM */
	if (!cn_is_mim_en(core) || !cn_core_is_vf(core)) {
		core->pf_idx = core->idx;
		sprintf(core->core_name, "Card%d", core->pf_idx);
		goto RETURN;
	}

	/* MI on Host */
	if (cn_core_is_vf(core)) {
		cn_core_set_idx(core);
		goto RETURN;
	}

RETURN:
	cn_dev_core_info(core, "core idx:%d pf_idx:%d vf_idx:%d",
		core->idx, core->pf_idx, core->vf_idx);

	return 0;
}

int cn_get_mlu_major_minor(int idx, unsigned int *major, unsigned int *minor)
{
	*major = cn_core_idx[idx].major;
	*minor = cn_core_idx[idx].minor;

	return 0;
}

int cn_get_mlu_idx(u32 bdf, bool is_pdev_virtfn)
{
	int i, start, end;

	/* [start, end) */
	start = !is_pdev_virtfn ? 0 : MAX_PHYS_CARD;
	end = !is_pdev_virtfn ? MAX_PHYS_CARD : MAX_FUNCTION_NUM;

#ifndef CONFIG_CNDRV_EDGE
	for (i = start; i < end; i++) {
		if (cn_core_idx[i].cn_bdf == bdf)
			return i;
	}
#endif
	for (i = start; i < end; i++) {
		if (!cn_core_idx[i].cn_core) {
			cn_core_idx[i].cn_bdf = bdf;
			break;
		}
	}

	if (i == end) {
		cn_dev_info("get idx fail");
		return -1;
	}

	return i;
}

static struct cn_core_set *cn_core_struct_init(struct cn_bus_set *bus_set,
				u64 device_id, u8 type, int idx)
{
	struct cn_core_set *core;
	struct device *dev = cn_bus_get_dev(bus_set);
	bool is_pdev_virtfn;
	u32 curr_bdf;

	is_pdev_virtfn = cn_bus_check_pdev_virtfn(bus_set);
	curr_bdf = cn_bus_get_current_bdf(bus_set);

	core = devm_kzalloc(dev, sizeof(*core), GFP_KERNEL);
	if (!core)
		return NULL;

	core->bus_set = bus_set;
	core->idx = idx;
	spin_lock(&core_set_lock);
	cn_core_idx[idx].cn_core = core;
	spin_unlock(&core_set_lock);
	core->mim_enable = cn_is_mim_en_bdf(curr_bdf, is_pdev_virtfn);

	core->device_id = device_id;
	if (device_id == MLUID_365)
		core->device_id = MLUID_370;
	if (device_id == MLUID_585)
		core->device_id = MLUID_590;
	if (device_id == MLUID_585V)
		core->device_id = MLUID_590V;
	if (device_id == MLUID_570 || device_id == MLUID_560)
		core->device_id = MLUID_580;
	if (device_id == MLUID_570V || device_id == MLUID_560V)
		core->device_id = MLUID_580V;

	core->type = type;
	core->reset_flag = 0;
	core->cambr_mcu_version_check = cambr_mcu_version_check;

	/* Only mlu370 support inlineECC dynamic control. */
	if (core->device_id == MLUID_370 || core->device_id == MLUID_370V) {
		core->ile_en = cambr_inline_ecc_enable;
	} else {
		core->ile_en = 0;
	}

	core->open_count = 0;
	core->card_kprintf_timer = 1; /* default timer is 1ms */
	cn_core_init_idx(core);
	init_completion(&core->comp);

	INIT_LIST_HEAD(&core->tid_cap_list_head);
	mutex_init(&core->tid_cap_lock);

	INIT_LIST_HEAD(&core->pid_head);
	spin_lock_init(&core->pid_info_lock);
	mutex_init(&core->user_trace_lock);

	spin_lock(&core->pid_info_lock);
	core->exclusive_mode = 0;
	spin_unlock(&core->pid_info_lock);

	INIT_LIST_HEAD(&core->kthread_list);
	mutex_init(&core->kthread_lock);

	cn_kwork_mlu_init(core);
	return core;
}

static void cn_core_clear_cn_core_idx(struct cn_core_set *core)
{
	if (!core)
		return;

	spin_lock(&core_set_lock);
	cn_core_idx[core->idx].cn_core = NULL;
	if (cn_is_mim_en(core) && cn_core_is_vf(core))
		cn_core_idx[core->pf_idx].cn_mi_core[core->vf_idx] = NULL;
	spin_unlock(&core_set_lock);
}

static void cn_core_struct_exit(struct cn_core_set *core)
{
	struct device *dev = cn_bus_get_dev(core->bus_set);

	cn_dev_core_info(core, "core %d will be removed", core->idx);

	cn_kwork_mlu_exit(core);

	/* while cn_core_probe is failed, cn_core_remove will not be called,
	   thus here set corresponding cn_core_idx NULL */
	cn_core_clear_cn_core_idx(core);

	devm_kfree(dev, core);
}

int set_core_boot_state(struct cn_core_set *core)
{
	if (core->device_id == MLUID_220_EDGE) {
		core->state = CN_BOOTING;
		core->last_state = CN_BOOTING;
	} else if (isPCIeArmPlatform(core)) {
		core->state = CN_RUNNING;
		core->last_state = CN_RUNNING;
	} else if (isCEPlatform(core)) {
		core->state = CN_LATEINIT;
		core->last_state = CN_LATEINIT;
	} else {
		core->state = CN_EARLYINITED;
		core->last_state = CN_EARLYINITED;
		core->boot_count = 0;
	}

	return 0;
}

int set_core_boot_max_time(struct cn_core_set *core)
{
	if (core->board_info.platform != MLU_PLAT_ASIC) {
		core->boot_max_time = EMU_BOOT_MAX_TIME;
		return 0;
	}

	switch (core->device_id) {
	case MLUID_580:
	case MLUID_590:
		core->boot_max_time = MLU500_BOOT_MAX_TIME;
		break;
	case MLUID_290:
		core->boot_max_time = MLU290_BOOT_MAX_TIME;
		break;
	case MLUID_220_EDGE:
	case MLUID_220:
	case MLUID_CE3226_EDGE:
	case MLUID_CE3226:
	case MLUID_PIGEON_EDGE:
	case MLUID_PIGEON:
		core->boot_max_time = MLU220_BOOT_MAX_TIME;
		break;
	case MLUID_370:
		core->boot_max_time = MLU370_BOOT_MAX_TIME;
		break;
	case MLUID_270:
	default:
		core->boot_max_time = MLU270_BOOT_MAX_TIME;
		break;
	}
	return 0;
}

static int cn_acpu_init(struct cn_core_set *core)
{
	int ret;

	/* Set New WQ to do boot job */
	ret = set_core_boot_state(core);
	if (ret)
		goto cn_acpu_err;

	ret = set_core_boot_max_time(core);
	if (ret)
		goto cn_acpu_err;

	if (!cn_core_is_vf(core))  /*temporary*/
		clear_serv_status(core);

	ret = setup_fw_workq(core);
	if (ret)
		goto cn_acpu_err;

	return 0;

cn_acpu_err:
	return -1;
}

static void cn_acpu_exit(struct cn_core_set *core)
{
	unset_fw_workq(core);

	cndrv_mcu_set_host_driver_status(core, 0);

	shutdown(core);
}

#define SUB_INIT(fname) \
	{.init = cn_##fname##_init, .exit = cn_##fname##_exit, .name = #fname}

static struct core_fn_s core_fn_t[] = {
	SUB_INIT(xid), /* cn_xid_init, cn_xid_exit */
	SUB_INIT(bus_set_stru), /* cn_bus_set_stru_init, cn_bus_set_stru_exit */
	SUB_INIT(p2pshm), /* cn_p2pshm_init, cn_p2pshm_exit */
	SUB_INIT(mnt), /* cn_mnt_init, cn_mnt_exit */
	SUB_INIT(mcu), /* cn_mcu_init, cn_mcu_exit */
	SUB_INIT(nor), /* cn_nor_init, cn_nor_exit */
	SUB_INIT(mcc), /* cn_mcc_init, cn_mcc_exit */
	SUB_INIT(mm), /* cn_mm_init, cn_mm_exit */
	SUB_INIT(cfgs), /* cn_cfgs_init, cn_cfgs_exit */
	SUB_INIT(mi_cap_node), /* cn_mi_cap_node_init, cn_mi_cap_node_exit */
	SUB_INIT(ipcm_dev), /* cn_ipcm_dev_init, cn_ipcm_dev_exit */
	SUB_INIT(commu_pre), /* cn_commu_pre_init, cn_commu_pre_exit*/
	SUB_INIT(dm), /* cn_dm_init, cn_dm_exit */
	SUB_INIT(lpm), /* cn_lpm_init, cn_lpm_exit */
	SUB_INIT(sbts), /* cn_sbts_init, cn_sbts_exit */
	SUB_INIT(bus), /* cn_bus_init, cn_bus_exit */
	SUB_INIT(monitor), /* cn_monitor_init, cn_monitor_exit */
	SUB_INIT(i2c), /* cn_i2c_init, cn_i2c_exit */
	SUB_INIT(cdev), /* cn_cdev_init, cn_cdev_exit */
	SUB_INIT(core_proc), /* cn_core_proc_init, cn_core_proc_exit */
	SUB_INIT(attr), /* cn_attr_init, cn_attr_exit */
	SUB_INIT(inject_error), /* cn_inject_error_init, cn_inject_error_exit */
	SUB_INIT(acpu), /* cn_acpu_init, cn_acpu_exit */
#ifndef CONFIG_CNDRV_EDGE
	SUB_INIT(state_monitor_kthread), /* cn_state_monitor_kthread_init,
					    cn_state_monitor_kthread_exit */
#endif
};

static struct fn_state_s core_fn_state[MAX_FUNCTION_NUM][ARRAY_SIZE(core_fn_t)];

struct core_fn_s *cn_core_get_core_fn_t(void)
{
	return (struct core_fn_s *)core_fn_t;
}

int cn_core_get_core_fn_num(void)
{
	return ARRAY_SIZE(core_fn_t);
}

struct fn_state_s *cn_core_get_core_fn_state(int idx)
{
	return (struct fn_state_s *)core_fn_state[idx];
}

void core_fn_exit(struct cn_core_set *core)
{
	int i, exit_cost;
	u64 start, end;

	for (i = ARRAY_SIZE(core_fn_t) - 1; i >= 0; i--) {
		if (core_fn_state[core->idx][i].status == INIT_OK) {
			start = get_jiffies_64();
			core_fn_t[i].exit(core);
			end = get_jiffies_64();
			exit_cost = jiffies_to_msecs(end - start);
			cn_dev_core_info(core, "%s exit ok, time cost:%d(ms)",
				core_fn_t[i].name, exit_cost);
			core_fn_state[core->idx][i].status = EXIT_OK;
			core_fn_state[core->idx][i].init_cost = 0;
		}
	}
}

int cn_core_probe(struct cn_bus_set *bus_set,
			u64 device_id, u8 type, int idx)
{
	struct cn_core_set *core;
	int i, state, init_cost;
	u64 start, end;

	core = cn_core_struct_init(bus_set, device_id, type, idx);
	if (!core)
		return -1;

	for (i = 0; i < ARRAY_SIZE(core_fn_t); i++) {
		start = get_jiffies_64();
		state = core_fn_t[i].init(core);
		end = get_jiffies_64();
		init_cost = jiffies_to_msecs(end - start);
		cn_dev_core_info(core, "%s init %s, time cost:%d(ms)",
			core_fn_t[i].name, state == 0 ? "ok" : "fail", init_cost);
		if (state)
			goto exit;
		core_fn_state[idx][i].status = INIT_OK;
		core_fn_state[idx][i].init_cost = init_cost;
	}

	return 0;

exit:
	core_fn_exit(core);
	cn_core_struct_exit(core);
	return -1;
}

int cn_core_remove(void *core_data)
{
	struct cn_core_set *core = (struct cn_core_set *)core_data;

	if (!core)
		return 0;

#ifndef CONFIG_CNDRV_EDGE
	cn_core_clear_cn_core_idx(core);
#endif

	if (core->state == CN_RUNNING) {

		kref_put(&core->refcount, core_set_release);

		while (!wait_for_completion_interruptible_timeout(&core->comp, msecs_to_jiffies(3000)))
			cn_dev_core_info(core, "core %d refcount %d", core->idx, CN_KREF_READ(&core->refcount));
	}

	core_fn_exit(core);
	cn_core_struct_exit(core);

	return 0;
}

void cn_core_shutdown(void *core_data)
{
}

int cn_core_suspend(void *core_data, u64 state)
{
	return 0;
}

int cn_core_resume(void *core_data)
{
	return 0;
}

struct cn_bus_driver bus_driver =
{
	.probe = cn_core_probe,
	.remove = cn_core_remove,
	.shutdown = cn_core_shutdown,
	.suspend = cn_core_suspend,
	.resume = cn_core_resume,
};

static int sriov_en;
module_param(sriov_en, int, 0000);
static int host_vf_en;
module_param(host_vf_en, int, 0000);

int cn_sriov_is_enable(void)
{
	return sriov_en;
}

int cn_host_vf_enable(void)
{
	if (!cn_sriov_is_enable())
		return 0;

	return host_vf_en;
}

int cn_check_curproc_is_docker(struct pid_info_s *cur_proc)
{
	if (IS_ERR_OR_NULL(cur_proc))
		return 0;

	return (cur_proc->tgid != cur_proc->active_pid ? 1 : 0);
}

int cn_is_host_ns(void)
{
	#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0))
	return task_active_pid_ns(current) == &init_pid_ns;
	#else
	return task_is_in_init_pid_ns(current);
	#endif
}

int cn_core_is_vf(struct cn_core_set *core)
{
	if (core->device_id == MLUID_270V || core->device_id == MLUID_270V1
					|| core->device_id == MLUID_290V1
					|| core->device_id == MLUID_370V
					|| core->device_id == MLUID_365V
					|| core->device_id == MLUID_580V
					|| core->device_id == MLUID_590V)
		return 1;

	return 0;
}

bool isEdgePlatform(struct cn_core_set *core)
{
	if (unlikely(!core)) {
		cn_dev_err("invalid core_set!");
		return false;
	}
	switch(core->device_id) {
	case MLUID_220_EDGE:
	case MLUID_CE3226_EDGE:
	case MLUID_PIGEON_EDGE:
	case MLUID_370_DEV:
	case MLUID_580_DEV:
	case MLUID_590_DEV:
		return true;
	default:
		return false;
	}
	return false;
}

bool isCEPlatform(struct cn_core_set *core)
{
	if (unlikely(!core)) {
		cn_dev_err("invalid core_set!");
		return false;
	}
	switch(core->device_id) {
	case MLUID_CE3226_EDGE:
	case MLUID_PIGEON_EDGE:
		return true;
	default:
		return false;
	}
	return false;
}

bool isPCIeArmPlatform(struct cn_core_set *core)
{
	if (unlikely(!core)) {
		cn_dev_err("invalid core_set!");
		return false;
	}
	switch(core->device_id) {
	case MLUID_370_DEV:
	case MLUID_580_DEV:
	case MLUID_590_DEV:
		return true;
	default:
		return false;
	}
	return false;
}

bool isMlu100SeriesProduct(struct cn_core_set *core)
{
	if (unlikely(!core)) {
		cn_dev_err("invalid core_set!");
		return false;
	}
	switch(core->device_id) {
	case MLUID_100:
		return true;
	default:
		return false;
	}
	return false;
}

static int kernel_para_check(void)
{
	if (isr_type != NULL) {
		if (strcmp(isr_type, "msi") && strcmp(isr_type, "msix")
				&& strcmp(isr_type, "intx")) {
			cn_dev_err("invalid isr_type_name!");
			return -1;
		}

		if (!strcmp(isr_type, "msi"))
			isr_type_index = MSI;
		else if (!strcmp(isr_type, "msix"))
			isr_type_index = MSIX;
		else
			isr_type_index = INTX;
	}

	if (platform_type != NULL) {
		if (strcmp(platform_type, "asic")
			&& strcmp(platform_type, "zebu")
			&& strcmp(platform_type, "pz1")
			&& strcmp(platform_type, "fpga")
			&& strcmp(platform_type, "vdk")) {
			cn_dev_err("invalid loading kernel module platform_type!");
			return -1;
		}

		if (!strcmp(platform_type, "asic"))
			g_platform_type = MLU_PLAT_ASIC;
		else if (!strcmp(platform_type, "zebu"))
			g_platform_type = MLU_PLAT_ZEBU;
		else if (!strcmp(platform_type, "pz1"))
			g_platform_type = MLU_PLAT_PZ1;
		else if (!strcmp(platform_type, "fpga"))
			g_platform_type = MLU_PLAT_FPGA;
		else if (!strcmp(platform_type, "vdk"))
			g_platform_type = MLU_PLAT_VDK;
		else
			g_platform_type = MLU_PLAT_UNKNOW;
		cn_dev_info("g_platform_type=%d", g_platform_type);
	}

	if (dma_align_size & (dma_align_size - 1)) {
		cn_dev_err("dma_align_size need 2^ = 0x%x!", dma_align_size);
		return -1;
	}

	return 0;
}

enum INIT_MODULE_STATE{
  MODULE_INIT_OK = 0,
  MODULE_INIT_FAIL
};

static struct module_fn_s {
	int (*init)(void);
	void (*exit)(void);
	int state;
} module_fn_t[] = {
	{.init = cn_proc_init, .exit = cn_proc_exit, .state = MODULE_INIT_FAIL},
	{.init = cnhost_dev_core_init, .exit = cnhost_dev_core_exit, .state = MODULE_INIT_FAIL},
	{.init = cn_core_setup_dev_ctl, .exit = cn_core_remove_dev_ctl, .state = MODULE_INIT_FAIL},
	{.init = cn_ipcm_driver_init, .exit = cn_ipcm_driver_exit, .state = MODULE_INIT_FAIL},
	{.init = cn_log_vuart_init, .exit = cn_log_vuart_exit, .state = MODULE_INIT_FAIL},
	{.init = cn_sbts_global_init, .exit = cn_sbts_global_exit, .state = MODULE_INIT_FAIL},
	{.init = cn_p2pshm_global_pre_init, .exit = cn_p2pshm_global_pre_exit, .state = MODULE_INIT_FAIL},
	{.init = cn_node_affinity_init, .exit = cn_node_affinity_destroy, .state = MODULE_INIT_FAIL},
	{.init = cn_bus_driver_reg, .exit = cn_bus_driver_unreg, .state = MODULE_INIT_FAIL},
	{.init = cn_p2pshm_global_post_init, .exit = cn_p2pshm_global_post_exit, .state = MODULE_INIT_FAIL},
	{.init = cn_kthread_init, .exit = cn_kthread_exit, .state = MODULE_INIT_FAIL},
	{.init = cn_kwork_init, .exit = cn_kwork_exit, .state = MODULE_INIT_FAIL}
};

static void moudle_table_exit(void)
{
	int i;

	for (i = ARRAY_SIZE(module_fn_t) - 1; i >= 0; i--) {
		if (module_fn_t[i].state == MODULE_INIT_OK)
			module_fn_t[i].exit();
	}
}

static int __init cn_core_init(void)
{
	int i;
	int state;

	if (kernel_para_check())
		return -1;

	for (i = 0; i < MAX_FUNCTION_NUM; i++) {
		cn_core_idx[i].cn_mim_enable = cn_sriov_is_enable();
	}

	for (i = 0; i < ARRAY_SIZE(module_fn_t); i++) {
		state = module_fn_t[i].init();
		if (state) {
			cn_dev_err("The %dth init function failed, err code:[%d]", i, state);
			break;
		}
		module_fn_t[i].state = MODULE_INIT_OK;
	}

	if (i < ARRAY_SIZE(module_fn_t)) {
		moudle_table_exit();
		cn_dev_info("Initialization failed, reverse uninstallation completed.");
		return -1;
	}

	return 0;
}

int cn_core_vf_unload(struct cn_core_set *core)
{
	int i;
	struct device *dev;
	struct cn_core_set *vf_core;

	if (!core) {
		cn_dev_err("Core is NULL");
		return -1;
	}

	if (cn_core_is_vf(core)) {
		cn_dev_core_err(core, "Only sriov pf and host vf support unload vf");
		return -1;
	}

	/* scan the vf core, if any vf is opened return error */
	list_sub_vf_core(core->pf_idx, vf_core, i) {
		if (!vf_core)
			continue;

		if (vf_core->open_count) {
			cn_dev_core_err(vf_core, "pf_idx:%d vf_idx:%d is busy",
				vf_core->pf_idx, vf_core->vf_idx);
			return -1;
		}
	}

	/* scan and unload vf */
	list_sub_vf_core(core->pf_idx, vf_core, i) {
		if (!vf_core)
			continue;

		if (vf_core->open_count) {
			cn_dev_core_err(vf_core, "pf_idx:%d vf_idx:%d is busy",
				vf_core->pf_idx, vf_core->vf_idx);
			return -1;
		}

		dev = cn_bus_get_dev(vf_core->bus_set);
		if (dev) {
			unset_fw_workq(vf_core);
			device_release_driver(dev);
		}
	}

	return 0;
}

/* Be used to allocate host pinned memory with numa node. */
int cn_core_get_numa_node(int id)
{
	struct device *dev = NULL;
	int ret = -1;

	dev = cn_bus_get_dev(cn_core_idx[id].cn_core->bus_set);
	if (dev)
		ret = dev_to_node(dev);

	return ret;
}

/* Be used to dma_map_sg*/
struct device *cn_core_get_dev(int id)
{
	return cn_bus_get_dev(cn_core_idx[id].cn_core->bus_set);
}

int cn_core_get_numa_node_by_core(struct cn_core_set *core)
{
	if (!core) {
		return -1;
	}

	return cn_core_get_numa_node(core->idx);
}

/* when live migaration source guest driver call this function */
int cn_core_mig_suspend(struct cn_core_set *core)
{
	core->mig_pending = 1;
	cn_dm_mig_guest_save_prepare(core);

	return 0;
}

/* when live migaration dst guest driver call this function */
int cn_core_mig_resume(struct cn_core_set *core, u32 new_bdf)
{
	cn_bus_set_bdf(core->bus_set, new_bdf);

	cn_dm_mig_guest_restore_complete(core);
	core->mig_pending = 0;
	wake_up(&core->mig_wq);

	return 0;
}

int cn_core_set_mim_mode(struct cn_core_set *core, int enable)
{
	int idx = core->idx;
	u8 type = core->type;
	u64 device_id = core->device_id;
	u32 support = DM_MIM_DEV_NOT_SUPPORT;
	struct cn_core_set *core_new = NULL;
	struct cn_bus_set *bus_set = core->bus_set;
	int i;

	cn_dm_device_is_support_mim(core, &support);
	if (support == DM_MIM_DEV_NOT_SUPPORT || cn_core_is_vf(core)) {
		cn_dev_core_err(core, "The card don't support set mim mode");
		return -EPERM;
	}

	if (core->mim_enable == enable) {
		return 0;
	}

	if (cn_dm_is_sriov_enable(core) == 1) {
		if (cn_dm_disable_sriov(core)) {
			cn_dev_core_err(core, "Call cn_dm_disable_sriov first fail");
			return -EPERM;
		}
	}

	if (core->open_count) {
		cn_dev_core_err(core, "This card is busy");
		return -EBUSY;
	}

	if (cn_bus_remove(bus_set, device_id)) {
		cn_dev_err("cn_bus_remove failed");
		return -EPERM;
	}

	cn_core_idx[idx].cn_mim_enable = enable;

	if (cn_bus_soft_reset(bus_set, true))
		cn_dev_err("bus reset fail\n");

	if (cn_bus_probe(bus_set, device_id, type, idx)) {
		cn_dev_err("cn_bus_probe failed\n");
		return -EPERM;
	}

	/* Reattach driver will create new core */
	for (i = 0; i < 1000; i++) {
		core_new = (struct cn_core_set *)cn_core_get_with_idx(idx);
		if (core_new) {
			break;
		}
		msleep(10);
	}

	if (!core_new) {
		cn_dev_err("set mim mode failed");
		return -ENOMEM;
	}

	/* Wait boot complite */
	for (i = 0; i < 3000; i++) {
		if (core_new->workq_state & (WORKQ_FINISH | WORKQ_ABORT)) {
			break;
		}
		msleep(20);
		if ((i & 0x0f) == 0x0f) {
			cn_dev_core_debug(core_new, "workq_state:%x state:%x",
				core_new->workq_state, core_new->state);
		}
	}

	if (core_new->state != CN_RUNNING) {
		cn_dev_core_err(core_new, "State error");
		return -EBUSY;
	}

	return 0;
}

int cn_is_mim_en(struct cn_core_set *core)
{
	return core->mim_enable;
}

int cn_is_mim_en_bdf(u32 bdf, bool is_pdev_virtfn)
{
	int idx;

	idx = cn_get_mlu_idx(bdf, is_pdev_virtfn);
	if (idx < 0 || idx >= MAX_FUNCTION_NUM) {
		cn_dev_err("idx:%d error", idx);
		return -1;
	}

	return cn_core_idx[idx].cn_mim_enable;
}

int cn_mim_notify_vf_status(u32 vf_bdf, u32 pf_bdf)
{
	int pf_idx = cn_get_mlu_idx(pf_bdf, 0);
	int vf_idx = cn_get_mlu_idx(vf_bdf, 1);

	if (pf_idx >= 0 && pf_idx < MAX_PHYS_CARD &&
		vf_idx >= MAX_PHYS_CARD && vf_idx < MAX_FUNCTION_NUM) {
		cn_core_idx[vf_idx].cn_mim_enable = cn_core_idx[pf_idx].cn_mim_enable;
	} else {
		cn_dev_err("idx error, pf_idx:%d, vf_idx:%d", pf_idx, vf_idx);
		return -1;
	}

	return 0;
}

int cn_mim_notify_mim_status(u32 pf_bdf, int enable)
{
	int pf_idx = cn_get_mlu_idx(pf_bdf, 0);

	if (pf_idx >= 0 && pf_idx < MAX_PHYS_CARD) {
		cn_core_idx[pf_idx].cn_mim_enable = enable;
		return 0;
	}

	return -1;
}

void cn_reg_write32(int idx, unsigned long offset, unsigned int val)
{
	struct cn_core_set *core;
	struct cn_bus_set *p;

	core = cn_core_get_with_idx(idx);
	if (core == NULL)
		return;

	p = core->bus_set;
	if (p == NULL)
		return;

	return p->ops->reg_write32(p->priv, offset, val);
}
EXPORT_SYMBOL(cn_reg_write32);

unsigned int cn_reg_read32(int idx, unsigned long offset)
{
	struct cn_core_set *core;
	struct cn_bus_set *p;

	core = cn_core_get_with_idx(idx);
	if (core == NULL)
		return 0xdeadbeaf;

	p = core->bus_set;
	if (p == NULL)
		return 0xdeadbeaf;

	return p->ops->reg_read32(p->priv, offset);
}
EXPORT_SYMBOL(cn_reg_read32);


static void __exit cn_core_exit(void)
{
	int i, sleep_cnt;
	struct cn_core_set *core = NULL;

	for (i = 0; i < MAX_FUNCTION_NUM; i++) {
		core = cn_core_idx[i].cn_core;
		if (!core)
			continue;

		sleep_cnt = 0;
		while (sleep_cnt < 30) {
			if (core->state == CN_RUNNING
					|| core->state == CN_BOOTERR
					|| core->state == CN_RESET_ERR)
				break;

			msleep(1000);
			sleep_cnt++;
		}
	}

	moudle_table_exit();

#ifdef CN_KMEM_LEAK_DEBUG
	mdelay(500);
	cn_show_kmem_leak();
#endif

}

module_init(cn_core_init);
module_exit(cn_core_exit);

MODULE_AUTHOR("Cambricon System Software Group");
MODULE_LICENSE("Dual BSD/GPL");
