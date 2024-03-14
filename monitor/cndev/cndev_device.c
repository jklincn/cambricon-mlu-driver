#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/random.h>
#include <linux/mutex.h>
#include <linux/of_device.h>

#include "cndrv_domain.h"
#include "cndrv_core.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_udvm_usr.h"
#include "cndrv_mcu.h"
#include "cndrv_sbts.h"
#include "cndrv_ioctl.h"
#include "../../core/version.h"

#include "cndev_server.h"
#include "../monitor.h"

#include "cndrv_monitor.h"
#include "cnhost_dev_common.h"
#include "cndrv_attr.h"
#include "cndrv_smlu.h"

#define DEVICE_NAME "cambricon_ctl"
#define CLASS_NAME "cambricon_ctl"

#define REGISTER_GET_PRIVDATA(name) \
void *cndev_get_##name##_priv(struct file *fp) \
{ \
	struct cndev_priv_data *priv_data = NULL; \
	if (file_is_cndev(fp)) { \
		priv_data = (struct cndev_priv_data *)fp->private_data; \
		return priv_data->name##_priv_data; \
	} \
	return NULL; \
} \

/* cndev_get_udvm_priv(fp) */
REGISTER_GET_PRIVDATA(udvm);
/* cndev_get_hostmem_priv(fp) */
REGISTER_GET_PRIVDATA(hostmem);

#define CNDEV_VF_CARD  0
#define CNDEV_PHY_CARD 1

struct __cndev_board_initor {

	u64 device_id;

	int (*cndev_init)(struct cn_cndev_set *cndev_set);

	u32 phy_dev;

	u64 quirks;
};

/* only in pf */
int card_num;
int phy_card_num;
int vf_card_num;/*only using in virt machine*/
int cndev_open_count;
DEFINE_MUTEX(open_lock);

struct list_head cndev_list = LIST_HEAD_INIT(cndev_list);
struct list_head cnctrl_list = LIST_HEAD_INIT(cnctrl_list);

int get_cndev_open_count(void)
{
	return cndev_open_count;
}

int cndev_open_count_lock(void)
{
	return mutex_lock_interruptible(&open_lock);
}

void cndev_open_count_unlock(void)
{
	return mutex_unlock(&open_lock);
}

void cndev_print_debug_set(struct cn_core_set *core, unsigned long usr_set)
{
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;

	cndev_set->print_debug = usr_set ? true : false;
}

bool cndev_print_debug_get(struct cn_core_set *core)
{
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;

	return cndev_set->print_debug;
}

static void *core_get_by_num(u32 pf_card, u32 vf_card)
{
	struct cn_core_set *core = NULL;
	u32 mi_on_docker_mask = 0;
	int ret = 0;

	core = cn_core_get_ref(pf_card);
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("Invalid dev core %u", pf_card);
		return NULL;
	}

	if (vf_card) {
		if (cn_dm_is_mim_mode_enable(core) && vf_card >= MAX_MI_COUNT) {
			cn_dev_err("invalid virt card idx");
			cn_core_put_deref(core);
			return NULL;
		}

		if (cn_dm_is_mim_mode_enable(core)) {
			/* in host pf, get mask of mi on dokcer */
			ret = cn_dm_query_onhost_mlu_instance_mask(core, &mi_on_docker_mask);
			if (ret) {
				cn_dev_err("get dev bitmap failed %d", ret);
				cn_core_put_deref(core);
				return NULL;
			}

			/* mi on docker only */
			if (mi_on_docker_mask & (1 << vf_card)) {
				cn_core_put_deref(core);
				core = cn_core_get_mi_core_ref(pf_card, vf_card);
				if (IS_ERR_OR_NULL(core)) {
					cn_dev_err("Invalid dev core %u:%u", pf_card, vf_card);
					return NULL;
				}
			} else {
				return core;
			}
		} else if (cn_is_smlu_en(core)) {
			return core;
		} else {
			cn_core_put_deref(core);
			return NULL;
		}
	}

	return core;
}

static void core_put(struct cn_core_set *core)
{
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("Invalid dev core %p", core);
		return;
	}

	cn_core_put_deref(core);
}

int cndrv_cndev_start(void)
{
	u32 cnt = 0;
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = NULL;
	struct cn_cndev_set *n;

	list_for_each_entry_safe(cndev_set, n, &cndev_list, list) {

		core = cndev_set->core;
		cnt = 100;
		while ((core->state != CN_RUNNING) && cnt) {
			if (core->state == CN_BOOTERR ||
					core->state == CN_RESET_ERR) {
				break;
			}
			msleep(50);
			cnt--;
		}
		if (core->state != CN_RUNNING) {
			continue;
		}
		if (IS_ERR_OR_NULL(cndev_set->ops)) {
			continue;
		}
		if (IS_ERR_OR_NULL(cndev_set->ops->cndev_start)) {
			continue;
		}
		cndev_set->ops->cndev_start(cndev_set);
	}
	return 0;
}

void cndrv_cndev_do_exit(void)
{
	struct cn_cndev_set *cndev_set = NULL;
	struct cn_cndev_set *n;

	list_for_each_entry_safe(cndev_set, n, &cndev_list, list) {
		if (IS_ERR_OR_NULL(cndev_set->ops)) {
			cn_dev_cndev_err(cndev_set, "cndev ops null");
			continue;
		}
		if (IS_ERR_OR_NULL(cndev_set->ops->cndev_do_exit)) {
			continue;
		}
		cndev_set->ops->cndev_do_exit(cndev_set);
	}
}

int cndev_remote_worker_ctrl(struct cndev_host_ctrl *ctrl, int tgid)
{
#if defined(CONFIG_CNDRV_PIGEON_SOC) || defined(CONFIG_CNDRV_CE3226_SOC)
	struct cndev_ctrl_s *ctrl_cfg = NULL, *n = NULL, *new_ctrl = NULL;
	int ret = 0;

	/* check cndev/cnmon already in list */
	if (mutex_lock_interruptible(&open_lock)) {
		return -EBUSY;
	}

	if (ctrl->op) {
		list_for_each_entry_safe(ctrl_cfg, n, &cnctrl_list, list) {
			if (ctrl_cfg && tgid == ctrl_cfg->tgid) {
				goto out;
			}
		}

		/* add new cndev/cnmon to list */
		new_ctrl = cn_kzalloc(sizeof(struct cndev_ctrl_s), GFP_KERNEL);
		if (!ctrl) {
			cn_dev_err("malloc cndev_ctrl_s fail");
			ret = -ENOMEM;
			goto out;
		}
		new_ctrl->tgid = tgid;

		if (list_empty(&cnctrl_list)) {
			list_add_tail(&new_ctrl->list, &cnctrl_list);
			/* start remote */
			if (cndrv_cndev_start()) {
				ret = -EFAULT;
				goto out;
			}
		} else {
			list_add_tail(&new_ctrl->list, &cnctrl_list);
		}
	} else {
		list_for_each_entry_safe(ctrl_cfg, n, &cnctrl_list, list) {
			if (ctrl_cfg && tgid == ctrl_cfg->tgid) {
				/* release ref */
				list_del(&ctrl_cfg->list);
				cn_kfree(ctrl_cfg);
			}
		}
		if (list_empty(&cnctrl_list)) {
			cndrv_cndev_do_exit();
		}
	}

out:
	mutex_unlock(&open_lock);
	return ret;
#else
	return 0;
#endif
}

int cndev_open(struct inode *inode, struct file *fp)
{
	struct cndev_priv_data *priv_data = NULL;
	int ret = 0;

	if (mutex_lock_interruptible(&open_lock)) {
		return -EBUSY;
	}

	cndev_open_count++;
	mutex_unlock(&open_lock);

	priv_data = cn_kzalloc(sizeof(struct cndev_priv_data), GFP_KERNEL);
	if (!priv_data) {
		cn_dev_err("create priv_data buffer failed!");
		ret = -ENOMEM;
		goto failed_create_priv;
	}

	ret = pinned_mem_open(&priv_data->hostmem_priv_data);
	if (ret) {
		cn_dev_err("init pinned_mem structure failed!");
		goto failed_init_pinned;
	}

	ret = cn_udvm_open_entry(inode, &priv_data->udvm_priv_data, (u64)fp);
	if (ret) {
		cn_dev_err("init udvm structure failed!");
		goto failed_init_udvm;
	}

	ret = cn_smlu_private_data_init(fp, priv_data);
	if (ret) {
		cn_dev_err("init smlu priv_data failed!");
		goto failed_init_smlu;
	}

	fp->private_data = (void *)priv_data;
	cn_dev_debug("cndev open");
	return 0;

failed_init_smlu:
	cn_udvm_release_entry(inode, priv_data->udvm_priv_data);
failed_init_udvm:
	pinned_mem_close(priv_data->hostmem_priv_data);
failed_init_pinned:
	cn_kfree(priv_data);
failed_create_priv:

	if (mutex_lock_interruptible(&open_lock)) {
		return -EBUSY;
	}
	cndev_open_count--;
	mutex_unlock(&open_lock);
	return ret;
}

int cndev_release(struct inode *inode, struct file *fp)
{
	struct cndev_priv_data *priv_data =
		(struct cndev_priv_data *)fp->private_data;

#if defined(CONFIG_CNDRV_CE3226_SOC) || defined(CONFIG_CNDRV_PIGEON_SOC)
	struct cndev_ctrl_s *ctrl_cfg, *n;
	int tgid = current->tgid;
#endif

	if (mutex_lock_interruptible(&open_lock)) {
		return -EBUSY;
	}
	cndev_open_count--;

#if defined(CONFIG_CNDRV_CE3226_SOC) || defined(CONFIG_CNDRV_PIGEON_SOC)
	/* remove cndev/cnmon in list */
	list_for_each_entry_safe(ctrl_cfg, n, &cnctrl_list, list) {
		if (ctrl_cfg && tgid == ctrl_cfg->tgid) {
			list_del(&ctrl_cfg->list);
			cn_kfree(ctrl_cfg);
		}
	}

	if (list_empty(&cnctrl_list)) {
		cndrv_cndev_do_exit();
	}
#endif
	mutex_unlock(&open_lock);

	pinned_mem_close(priv_data->hostmem_priv_data);

	cn_udvm_release_entry(inode, priv_data->udvm_priv_data);

	cn_smlu_private_data_exit(fp, priv_data);

	cn_kfree(priv_data);
	fp->private_data = NULL;
	cn_dev_debug("cndev release");
	return 0;
}

static int cndev_mmap(struct file *fp, struct vm_area_struct *vma)
{
	return 0;
}

struct cnhost_dev_ioctl_desc cndev_permits[] = {
	CNHOST_DEV_IOCTL_DEF_DRV(MONITOR_CNDEV_POWERCAPPING, CNHOST_DEV_ROOT_ONLY),
	CNHOST_DEV_IOCTL_DEF_DRV(MONITOR_CNDEV_IPUFREQ_SET, CNHOST_DEV_ROOT_ONLY),
	CNHOST_DEV_IOCTL_DEF_DRV(MONITOR_CNDEV_ACPUUTIL_TIMER, CNHOST_DEV_ROOT_ONLY),
	CNHOST_DEV_IOCTL_DEF_DRV(MONITOR_CNDEV_RETIRE_SWITCH, CNHOST_DEV_ROOT_ONLY),
	CNHOST_DEV_IOCTL_DEF_DRV(MONITOR_CNDEV_NCS_RESET_COUNTER, CNHOST_DEV_ROOT_ONLY),
	CNHOST_DEV_IOCTL_DEF_DRV(MONITOR_CNDEV_NCS_CONFIG, CNHOST_DEV_ROOT_ONLY),
	CNHOST_DEV_IOCTL_DEF_DRV(MONITOR_CNDEV_SET_FEATURE, CNHOST_DEV_ROOT_ONLY),
	CNHOST_DEV_IOCTL_DEF_DRV(MONITOR_CNDEV_IPUFREQ_CTRL, CNHOST_DEV_ROOT_ONLY),
	CNHOST_DEV_IOCTL_DEF_DRV(MONITOR_CNDEV_MLULINK_SWITCH_CTRL, CNHOST_DEV_ROOT_ONLY),
};

static int get_cndev_set(unsigned long arg, struct cn_cndev_set **cndev_set, struct cndev_head *arg_head)
{
	int ret = 0;
	u32 vf_card = 0;
	u32 pf_card = 0;
	struct cn_core_set *core = NULL;

	ret = cndev_cp_from_usr(arg, arg_head, sizeof(struct cndev_head));
	if (ret) {
		return ret;
	}

	vf_card = (arg_head->card >> 8) & 0xff;
	pf_card = arg_head->card & 0xFF;
	/*split vf card num*/
	core = (struct cn_core_set *)core_get_by_num(pf_card, vf_card);

	if (IS_ERR_OR_NULL(core)) {
		*cndev_set = NULL;
		return -EINVAL;
	}

	*cndev_set = core->cndev_set;
	if (IS_ERR_OR_NULL(*cndev_set)) {
		cn_dev_err("Invalid card index");
		*cndev_set = NULL;
		return -EINVAL;
	}

	return 0;
}

static void put_cndev_set(struct cn_cndev_set *cndev_set)
{
	cn_core_put_deref(cndev_set->core);
}

static int cn_cndev_get_mem_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_memory_info minfo;
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	core = (struct cn_core_set *)cndev_set->core;
	cpsize = sizeof(struct cndev_memory_info);

	memset(&minfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read memory info");
	/* clear old data */
	minfo.chl_num = 0;
	minfo.each_chl = NULL;
	cpsize = (cpsize > arg_head.buf_size) ? arg_head.buf_size : cpsize;
	if (cndev_cp_from_usr(arg, &minfo, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_card_memory_info(core, &minfo);
	if (ret) {
		put_cndev_set(cndev_set);
		return ret;
	}

	ret = cndev_cp_to_usr(arg, &minfo, cpsize);

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_card_num(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	struct cndev_cardnum card;

	card.version = CNDEV_CURRENT_VER;
	/* invalid value in host vf mode, check /dev for card num. */
	card.card_count = card_num;
	ret = cndev_cp_to_usr(arg, &card, sizeof(struct cndev_cardnum));

	return ret;
}

static int cn_cndev_get_card_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	ret = cndev_card_info(cndev_set, arg, &arg_head);

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_power_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_power_info pinfo;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_power_info);

	memset(&pinfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read power info");
	cpsize = (cpsize > arg_head.buf_size) ? arg_head.buf_size : cpsize;
	ret = cndev_cp_from_usr(arg, &pinfo, cpsize);
	if (ret) {
		put_cndev_set(cndev_set);
		return ret;
	}
	ret = cndev_card_power_info(cndev_set, &pinfo);
	if (ret) {
		put_cndev_set(cndev_set);
		return ret;
	}
	ret = cndev_cp_to_usr(arg, &pinfo, cpsize);

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_proc_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	struct cndev_proc_info pinfo;
	int ret = 0;
	u32 cpsize = 0;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_proc_info);

	memset(&pinfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read process info");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &pinfo, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_user_proc_info(cndev_set, &pinfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &pinfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_health_state_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_health_state hstate;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_health_state);

	memset(&hstate, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read health state");
	hstate.head = arg_head;

	ret = cndev_card_health_state(cndev_set, &hstate);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &hstate, sizeof(struct cndev_health_state));
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_ecc_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_ecc_info einfo;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_ecc_info);

	memset(&einfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read ecc info");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &einfo, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_card_ecc_info(cndev_set, &einfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &einfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_vm_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_vm_info vinfo;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_vm_info);

	memset(&vinfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read vm info");
	vinfo.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	ret = cndev_card_vm_info(cndev_set, &vinfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &vinfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_iputil_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_ipuutil_info uinfo;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_ipuutil_info);

	memset(&uinfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read ipu util info");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &uinfo, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_card_ipuutil_info(cndev_set, &uinfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &uinfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_codectil_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_codecutil_info uinfo;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}
	cpsize = sizeof(struct cndev_codecutil_info);

	memset(&uinfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read codec util info");
	uinfo.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &uinfo, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_card_codecutil_info(cndev_set, &uinfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &uinfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_ipufreq_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_freq_info finfo;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_freq_info);

	memset(&finfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read ipu freq info");
	finfo.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &finfo, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_card_freq_info(cndev_set, &finfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &finfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_curbus_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_curbuslnk_info linfo;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_curbuslnk_info);

	memset(&linfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read cur bus info");
	linfo.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	ret = cndev_card_curbuslnk(cndev_set, &linfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &linfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_pcie_thoughput_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_pcie_throughput tpinfo;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_pcie_throughput);

	memset(&tpinfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read pcie throughput info");
	tpinfo.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	ret = cndev_card_pciethroughput(cndev_set, &tpinfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &tpinfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_power_capping_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_powercapping_s pcinfo;
	unsigned int cmd = (MONITOR_CNDEV_POWERCAPPING);
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_powercapping_s);

	memset(&pcinfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "power capping");
	pcinfo.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &pcinfo, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	if (pcinfo.ops_type) {
		ret = cnhost_dev_permit_check(fp, cmd, arg, cndev_permits, sizeof(cndev_permits));
		if (ret) {
			put_cndev_set(cndev_set);
			return ret;
		}
	}

	ret = cndev_power_capping(cndev_set, &pcinfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &pcinfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_set_ipufreq_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_ipufreq_set set_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_ipufreq_set);

	memset(&set_info, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "ipufreq set");
	set_info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &set_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	atomic64_inc(&cndev_set->ipu_freq_set_ref);
	ret = cndev_ipufreq_set(cndev_set, &set_info);

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_attr_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_ioctl_attr ioctl_attr_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_ioctl_attr);

	memset(&ioctl_attr_info, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "ioctl attr");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &ioctl_attr_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_ioctl_attribute(cndev_set, &ioctl_attr_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &ioctl_attr_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_ncs_ver_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_NCS_version ncs_version_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_NCS_version);

	memset(&ncs_version_info, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read ncs version");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &ncs_version_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_ncs_version(cndev_set, &ncs_version_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &ncs_version_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_ncs_state_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_NCS_state_info ncs_state_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_NCS_state_info);

	memset(&ncs_state_info, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read ncs state");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &ncs_state_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_ncs_state(cndev_set, &ncs_state_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &ncs_state_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_ncs_speed_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_NCS_speed_info ncs_speed_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_NCS_speed_info);

	memset(&ncs_speed_info, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read ncs speed");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &ncs_speed_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_ncs_speed(cndev_set, &ncs_speed_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &ncs_speed_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_ncs_capability_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_NCS_capability ncs_capability_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_NCS_capability);

	memset(&ncs_capability_info, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read ncs capability");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &ncs_capability_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_ncs_capability(cndev_set, &ncs_capability_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &ncs_capability_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_ncs_err_counter_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_NCS_counter ncs_conuter_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_NCS_counter);

	memset(&ncs_conuter_info, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read ncs counter");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &ncs_conuter_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_ncs_counter(cndev_set, &ncs_conuter_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &ncs_conuter_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_reset_ncs_counter_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_NCS_reset_counter reset_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_NCS_reset_counter);

	memset(&reset_info, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "ret set ncs counter");
	reset_info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &reset_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_reset_ncs_counter(cndev_set, &reset_info);

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_ncs_remote_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_NCS_remote_info ncs_remote_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_NCS_remote_info);

	memset(&ncs_remote_info, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read ncs remote info");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &ncs_remote_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_ncs_remote(cndev_set, &ncs_remote_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &ncs_remote_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_chassis_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_chassis_info chassis_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_chassis_info);

	memset(&chassis_info, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read chassis info");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &chassis_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_chassis_info_fill(cndev_set, &chassis_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &chassis_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_reset_qos_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cn_dev_cndev_debug(cndev_set, "qos reset");

	arg_head.real_size = sizeof(struct cndev_head);
	arg_head.version = CNDEV_CURRENT_VER;
	ret = cndev_reset_qos(cndev_set);

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_qos_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_qos_info qosinfo;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_qos_info);

	memset(&qosinfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "qos info");
	qosinfo.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &qosinfo, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_qos_operation(cndev_set, &qosinfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &qosinfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_qos_desc_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_qos_detail qos_desc;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_qos_detail);

	memset(&qos_desc, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "qos description");
	qos_desc.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &qos_desc, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_qos_desc(cndev_set, &qos_desc);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &qos_desc, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_set_qos_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_qos_param qos_param;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_qos_param);

	memset(&qos_param, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "set qos param");
	qos_param.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &qos_param, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_set_qos_param(cndev_set, &qos_param);

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_set_qos_group_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_qos_group_param qos_group_param;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_qos_group_param);

	memset(&qos_group_param, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "set qos group param");
	qos_group_param.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &qos_group_param, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_set_qos_group_param(cndev_set, &qos_group_param);

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_acpu_util_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_acpuutil_info uinfo;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_acpuutil_info);

	memset(&uinfo, 0, cpsize);
	cn_dev_cndev_debug(cndev_set, "read acpu util info");
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &uinfo, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_card_acpuutil_info(cndev_set, &uinfo);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &uinfo, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_set_acpu_timer_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	unsigned int cmd = (MONITOR_CNDEV_ACPUUTIL_TIMER);
	struct cndev_acpuutil_timer cpu_timer;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_acpuutil_timer);

	memset(&cpu_timer, 0, sizeof(struct cndev_acpuutil_timer));
	cpu_timer.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &cpu_timer, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	if (cpu_timer.ops_type) {
		ret = cnhost_dev_permit_check(fp, cmd, arg, cndev_permits, sizeof(cndev_permits));
		if (ret) {
			put_cndev_set(cndev_set);
			return ret;
		}
	}

	ret = cndev_card_acpuutil_timer(cndev_set, &cpu_timer);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &cpu_timer, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_retire_pages_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_retire_page retire_page;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_retire_page);

	memset(&retire_page, 0, sizeof(struct cndev_retire_page));
	retire_page.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &retire_page, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_retire_pages(cndev_set, &retire_page);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &retire_page, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_retire_status_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_retire_status retire_status;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_retire_status);

	memset(&retire_status, 0, sizeof(struct cndev_retire_status));
	retire_status.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &retire_status, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_retire_status(cndev_set, &retire_status);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &retire_status, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_remapped_rows_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_retire_remapped_rows remapped_rows;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_retire_remapped_rows);

	memset(&remapped_rows, 0, sizeof(struct cndev_retire_remapped_rows));
	remapped_rows.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &remapped_rows, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_retire_remapped_rows(cndev_set, &remapped_rows);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &remapped_rows, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_retire_switch_ctrl(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	unsigned int cmd = (MONITOR_CNDEV_RETIRE_SWITCH);
	struct cndev_retire_op retire_op;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_retire_op);

	memset(&retire_op, 0, sizeof(struct cndev_retire_op));
	retire_op.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &retire_op, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	if (retire_op.op) {
		ret = cnhost_dev_permit_check(fp, cmd, arg, cndev_permits, sizeof(cndev_permits));
		if (ret) {
			put_cndev_set(cndev_set);
			return ret;
		}
	}

	ret = cndev_retire_switch(cndev_set, &retire_op);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &retire_op, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_ncs_config(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	unsigned int cmd = (MONITOR_CNDEV_NCS_CONFIG);
	struct cndev_NCS_config config_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_NCS_config);

	memset(&config_info, 0, sizeof(struct cndev_NCS_config));
	config_info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &config_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	if (config_info.ops_type) {
		ret = cnhost_dev_permit_check(fp, cmd, arg, cndev_permits, sizeof(cndev_permits));
		if (ret) {
			put_cndev_set(cndev_set);
			return ret;
		}
	}

	ret = cndev_ncs_port_config(cndev_set, &config_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &config_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_mlulink_switch_ctrl(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	unsigned int cmd = (MONITOR_CNDEV_MLULINK_SWITCH_CTRL);
	struct cndev_mlulink_switch_ctrl mlulink_switch_ctrl;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_mlulink_switch_ctrl);

	memset(&mlulink_switch_ctrl, 0, sizeof(struct cndev_mlulink_switch_ctrl));
	mlulink_switch_ctrl.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &mlulink_switch_ctrl, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	if (mlulink_switch_ctrl.ops_type) {
		ret = cnhost_dev_permit_check(fp, cmd, arg, cndev_permits, sizeof(cndev_permits));
		if (ret) {
			put_cndev_set(cndev_set);
			return ret;
		}
	}

	ret = cndev_ncs_mlulink_switch_ctrl(cndev_set, &mlulink_switch_ctrl);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &mlulink_switch_ctrl, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_ipufreq_ctrl(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	unsigned int cmd = MONITOR_CNDEV_IPUFREQ_CTRL;
	struct cndev_ipufreq_ctrl ipufreq_ctrl;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_ipufreq_ctrl);

	memset(&ipufreq_ctrl, 0, sizeof(struct cndev_ipufreq_ctrl));
	ipufreq_ctrl.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &ipufreq_ctrl, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	if (ipufreq_ctrl.ops_type) {
		ret = cnhost_dev_permit_check(fp, cmd, arg, cndev_permits, sizeof(cndev_permits));
		if (ret) {
			put_cndev_set(cndev_set);
			return ret;
		}
	}

	ret = cndev_ipu_freq_ctrl(cndev_set, &ipufreq_ctrl);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &ipufreq_ctrl, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_ncs_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_ncs_info ncs_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_ncs_info);

	memset(&ncs_info, 0, sizeof(struct cndev_ncs_info));
	ncs_info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &ncs_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_ncs_info(cndev_set, &ncs_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &ncs_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_card_ext_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_card_info_ext ext_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_card_info_ext);

	memset(&ext_info, 0, sizeof(struct cndev_card_info_ext));
	ext_info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &ext_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_card_info_ext(cndev_set, &ext_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &ext_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_host_ctrl(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_host_ctrl host_ctrl;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_host_ctrl);

	memset(&host_ctrl, 0, sizeof(struct cndev_host_ctrl));
	host_ctrl.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &host_ctrl, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_remote_worker_ctrl(&host_ctrl, current->tgid);

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_process_ipuutil_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_process_ipuutil_info info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_process_ipuutil_info);

	memset(&info, 0, sizeof(struct cndev_process_ipuutil_info));
	info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_get_process_util(cndev_set, &info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_feature(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_feature info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_feature);

	memset(&info, 0, sizeof(struct cndev_feature));
	info.head = arg_head;
	if (cndev_cp_from_usr(arg, &info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_get_feature(cndev_set, &info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_process_codecutil_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_process_codecutil_info info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_process_codecutil_info);

	memset(&info, 0, sizeof(struct cndev_process_codecutil_info));
	info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_get_process_codecutil(cndev_set, &info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_set_feature(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_feature info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_feature);

	memset(&info, 0, sizeof(struct cndev_feature));
	info.head = arg_head;
	if (cndev_cp_from_usr(arg, &info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}
	ret = cndev_set_feature(cndev_set, &info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_mim_vmlu_profile(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_mim_profile_info vmlu_profile;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_mim_profile_info);

	memset(&vmlu_profile, 0, sizeof(struct cndev_mim_profile_info));
	vmlu_profile.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &vmlu_profile, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_mim_profile_info(cndev_set, &vmlu_profile);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &vmlu_profile, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_mim_possible_place(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_mim_possible_place_info possible_palce;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_mim_possible_place_info);

	memset(&possible_palce, 0, sizeof(struct cndev_mim_possible_place_info));
	possible_palce.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &possible_palce, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_mim_possible_place_info(cndev_set, &possible_palce);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &possible_palce, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_mim_vmlu_capacity(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_mim_vmlu_capacity_info capacity_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_mim_vmlu_capacity_info);

	memset(&capacity_info, 0, sizeof(struct cndev_mim_vmlu_capacity_info));
	capacity_info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &capacity_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_card_get_mim_vmlu_capacity_info(cndev_set, &capacity_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &capacity_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_device_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_mim_device_info mim_device_info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_mim_device_info);

	memset(&mim_device_info, 0, sizeof(struct cndev_mim_device_info));
	mim_device_info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &mim_device_info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_card_get_mim_device_info(cndev_set, &mim_device_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &mim_device_info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_card_desc(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_mi_card dev_desc;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_mi_card);

	memset(&dev_desc, 0, sizeof(struct cndev_mi_card));
	dev_desc.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &dev_desc, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_card_get_desc_info(cndev_set, &dev_desc);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &dev_desc, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_card_num_ext(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_cardnum_ext cardnum_ext;
	struct cndev_head arg_head;
	struct cn_core_set *core = NULL;
	u32 i = 0;
	struct cndev_card_desc *desc = NULL;

	desc = (struct cndev_card_desc *)cn_kzalloc(sizeof(struct cndev_card_desc)
		* MAX_PHYS_CARD, GFP_KERNEL);
	if (!desc) {
		cn_dev_err("alloc for dev description failed");
		return -ENOMEM;
	}

	ret = cndev_cp_from_usr(arg, &arg_head, sizeof(struct cndev_head));
	if (ret) {
		goto out;
	}

	cpsize = sizeof(struct cndev_cardnum_ext);

	memset(&cardnum_ext, 0, sizeof(struct cndev_cardnum_ext));
	cardnum_ext.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &cardnum_ext, cpsize)) {
		ret = -EFAULT;
		goto out;
	}

	cardnum_ext.head.card = 0;
	cardnum_ext.head.version = CNDEV_CURRENT_VER;
	cardnum_ext.head.real_size = sizeof(struct cndev_cardnum_ext);
	cardnum_ext.phy_card_count = phy_card_num;
	cardnum_ext.vf_card_count = vf_card_num;

	for (i = 0; i < MAX_PHYS_CARD; i++) {
		core = cn_core_get_ref(i);
		if (IS_ERR_OR_NULL(core)) {
			desc[i].valid = 0;
			desc[i].host_state = CN_UNKNOWN;
			memset(desc[i].core_name, 0x0, sizeof(char) * CNDEV_CORE_NAME_LEN);
		} else {
			desc[i].valid = 1;
			desc[i].host_state = core->state;
			desc[i].idx = core->idx;
			memcpy(desc[i].core_name, core->core_name, CNDEV_CORE_NAME_LEN);

			if (cn_core_is_vf(core)) {
				desc[i].core_type = CNDEV_VF;
			} else {
				desc[i].core_type = CNDEV_PF;
			}
			cn_core_put_deref(core);
		}
	}

	ret = cndev_cp_less_val(
		&cardnum_ext.phy_card_num, MAX_PHYS_CARD,
		cardnum_ext.phy_card_desc, desc, sizeof(struct cndev_cardnum_ext));

	ret |= cndev_cp_to_usr(arg, &cardnum_ext, cpsize);

out:
	cn_kfree(desc);

	return ret;
}

static int cn_cndev_get_cntr_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_cntr_info info = {};
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head = {};

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_cntr_info);

	memset(&info, 0, sizeof(struct cndev_cntr_info));
	info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_card_get_cntr_info(cndev_set, &info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_chassis_power_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_chassis_power_info info = {};
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head = {};

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_chassis_power_info);

	memset(&info, 0, sizeof(struct cndev_chassis_power_info));
	info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_chassis_power_info_fill(cndev_set, &info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_device_state(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	struct cn_core_set *core = NULL;
	struct cndev_device_state device_state = {};
	struct cndev_head arg_head = {};
	u32 vf_card = 0;
	u32 pf_card = 0;
	u32 cpsize = 0;

	/* 1 Copy header from user */
	ret = cndev_cp_from_usr(arg, &arg_head, sizeof(struct cndev_head));
	if (ret) {
		return ret;
	}

	/* 2 get dev index */
	vf_card = (arg_head.card >> 8) & 0xff;
	pf_card = arg_head.card & 0xFF;

	if (vf_card) {
		cn_dev_warn("Operation not permitted on vf dev %u:%u", pf_card, vf_card);
		return -EINVAL;
	}

	cpsize = sizeof(struct cndev_device_state);
	memset(&device_state, 0, sizeof(struct cndev_device_state));
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &device_state, cpsize)) {
		return -EFAULT;
	}

	/* 3 get dev core */
	core = cn_core_get_with_idx(pf_card);
	if (IS_ERR_OR_NULL(core)) {
		device_state.cur_state = CN_EARLYINITED;
	} else if (core->reset_flag){
		device_state.cur_state = CN_RESET;
	} else {
		device_state.cur_state = core->state;
	}

	/* 5 copy data from user */
	ret = cndev_cp_to_usr(arg, &device_state, cpsize);

	return ret;
}

static int cn_cndev_device_reset(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	struct cn_core_set *core = NULL;
	struct cndev_device_reset device_reset = {};
	struct cndev_head arg_head = {};
	u32 vf_card = 0;
	u32 pf_card = 0;
	u32 cpsize = 0;

	/* 1 Copy header from user */
	ret = cndev_cp_from_usr(arg, &arg_head, sizeof(struct cndev_head));
	if (ret) {
		return ret;
	}

	/* 2 get dev index */
	vf_card = (arg_head.card >> 8) & 0xff;
	pf_card = arg_head.card & 0xFF;

	if (vf_card) {
		cn_dev_warn("Operation not permitted on vf dev %u:%u", pf_card, vf_card);
		return -EPERM;
	}

	/* 3 get dev core */
	core = cn_core_get_ref(pf_card);
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("Invalid mlu dev %d", pf_card);
		return -EINVAL;
	}

	cpsize = sizeof(struct cndev_device_reset);
	memset(&device_reset, 0, sizeof(struct cndev_device_reset));
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &device_reset, cpsize)) {
		cn_core_put_deref(core);
		return -EFAULT;
	}

	if (cn_core_is_vf(core)) {
		device_reset.reset_state = CNDEV_DEVICE_VF;
	} else if (cn_is_smlu_en(core)) {
		device_reset.reset_state = CNDEV_DEVICE_SMLU;
	} else if (cn_is_mim_en(core)) {
		device_reset.reset_state = CNDEV_DEVICE_MIM;
	} else {
		if (CN_KREF_READ(&core->refcount) > 2) {
			device_reset.reset_state = CNDEV_DEVICE_BUSY;
		} else {
			device_reset.reset_state = CNDEV_DEVICE_RESET;
			core->reset_flag = RESET_ALL;
		}
	}

	/* 5 copy data from user */
	ret = cndev_cp_to_usr(arg, &device_reset, cpsize);

	cn_core_put_deref(core);

	return ret;
}

static int cn_cndev_mim_mode_switch(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cn_core_set *core = NULL;
	struct cndev_mim_mode_switch mim_mode = {};
	struct cndev_head arg_head = {};
	u32 vf_card = 0;
	u32 pf_card = 0;
	s32 ctrl = 0;
	u32 mim_support = 0;

	/* 1 Copy header from user */
	ret = cndev_cp_from_usr(arg, &arg_head, sizeof(struct cndev_head));
	if (ret) {
		return ret;
	}

	/* 2 get dev index */
	vf_card = (arg_head.card >> 8) & 0xff;
	pf_card = arg_head.card & 0xFF;

	if (vf_card) {
		cn_dev_warn("Operation not permitted on vf dev %u:%u", pf_card, vf_card);
		return -EPERM;
	}

	/* 3 get dev core */
	core = cn_core_get_with_idx(pf_card);
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("Invalid mlu dev %d", pf_card);
		return -EINVAL;
	}

	/* 4 copy data from user */
	cpsize = sizeof(struct cndev_mim_mode_switch);
	mim_mode.head.real_size = cpsize;
	memset(&mim_mode, 0, sizeof(struct cndev_mim_mode_switch));

	mim_mode.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &mim_mode, cpsize)) {
		return -EFAULT;
	}

	/* set mim is support on current platfom */
	if (cn_dm_device_is_support_mim(core, &mim_support))
		return -EFAULT;

	mim_mode.mim_sup = mim_support;
	/* 5 operation */
	switch (mim_mode.mim_op) {
	case CNDEV_MIM_MODE_GET:
			/* 5.1 get mim status */
			mim_mode.mim_state = cn_is_mim_en(core);
			ret = cndev_cp_to_usr(arg, &mim_mode, cpsize);
		break;
	case CNDEV_MIM_MODE_SET:
			/* 5.2 check platform support mim or not */
			if (!mim_mode.mim_sup) {
				cn_dev_warn("Device not support MIM");
			} else {
				/* 5.3 ROOT_ONLY is only for CAP_SYS_ADMIN */
				if (!capable(CAP_SYS_ADMIN)) {
					cn_dev_warn("Permission denied");
					return -EACCES;
				}

				/* 5.4 change mim mode */
				ctrl = mim_mode.mim_state ? 1 : 0;
				ret = cn_core_set_mim_mode(core, ctrl);

				/*!!!! do not using core after change mim mode !!!!*/
			}

			if (!ret) {
				ret = cndev_cp_to_usr(arg, &mim_mode, cpsize);
			}
		break;
	default:
		ret = -EPERM;
		break;
	}

	return ret;
}

static int cn_cndev_smlu_mode_switch(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cn_core_set *core = NULL;
	struct cndev_smlu_mode_switch smlu_mode = {};
	struct cndev_head arg_head = {};
	u32 vf_card = 0;
	u32 pf_card = 0;

	/* 1 Copy header from user */
	ret = cndev_cp_from_usr(arg, &arg_head, sizeof(struct cndev_head));
	if (ret) {
		return ret;
	}

	/* 2 get dev index */
	vf_card = (arg_head.card >> 8) & 0xff;
	pf_card = arg_head.card & 0xFF;

	if (vf_card) {
		cn_dev_warn("Operation not permitted on vf dev %u:%u", pf_card, vf_card);
		return -EPERM;
	}

	/* 3 get dev core */
	core = core_get_by_num(pf_card, 0);
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("Invalid mlu dev %d", pf_card);
		return -EINVAL;
	}

	if (cn_core_is_vf(core)) {
		core_put(core);
		return -EPERM;
	}

	/* 4 copy data from user */
	cpsize = sizeof(struct cndev_smlu_mode_switch);
	smlu_mode.head.real_size = cpsize;
	memset(&smlu_mode, 0, sizeof(struct cndev_smlu_mode_switch));

	smlu_mode.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &smlu_mode, cpsize)) {
		core_put(core);
		return -EFAULT;
	}

	smlu_mode.smlu_sup = cn_is_smlu_support(core);
	/* 5 operation */
	switch (smlu_mode.smlu_mode_op) {
	case CNDEV_SMLU_MODE_GET:
		smlu_mode.smlu_state = cn_is_smlu_en(core);
		ret = cndev_cp_to_usr(arg, &smlu_mode, cpsize);
		break;
	case CNDEV_SMLU_MODE_SET:
		if (!capable(CAP_SYS_ADMIN)) {
			cn_dev_warn("Permission denied");
			core_put(core);
			return -EACCES;
		}

		ret = cn_core_set_smlu_mode(core, smlu_mode.smlu_state);
		if (!ret) {
			ret = cndev_cp_to_usr(arg, &smlu_mode, cpsize);
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}

	core_put(core);
	return ret;
}

static int cn_cndev_get_smlu_profile_id(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_smlu_profile_id info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_smlu_profile_id);

	memset(&info, 0, sizeof(struct cndev_smlu_profile_id));
	info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_smlu_profile_id(cndev_set, &info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_get_smlu_profile_info(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_smlu_profile_info info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_smlu_profile_info);

	memset(&info, 0, sizeof(struct cndev_smlu_profile_info));
	info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_get_smlu_profile_info(cndev_set, &info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_new_smlu_profile(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_smlu_profile_info info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_smlu_profile_info);

	memset(&info, 0, sizeof(struct cndev_smlu_profile_info));
	info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_new_smlu_profile(cndev_set, &info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

static int cn_cndev_delete_smlu_profile(struct file *fp,
	unsigned long arg, unsigned int ioc_size)
{
	int ret = 0;
	u32 cpsize = 0;
	struct cndev_smlu_profile_info info;
	struct cn_cndev_set *cndev_set = NULL;
	struct cndev_head arg_head;

	ret = get_cndev_set(arg, &cndev_set, &arg_head);
	if (ret) {
		return ret;
	}

	cpsize = sizeof(struct cndev_smlu_profile_info);

	memset(&info, 0, sizeof(struct cndev_smlu_profile_info));
	info.head = arg_head;
	cpsize = (cpsize < arg_head.buf_size) ? cpsize : arg_head.buf_size;
	if (cndev_cp_from_usr(arg, &info, cpsize)) {
		put_cndev_set(cndev_set);
		return -EFAULT;
	}

	ret = cndev_delete_smlu_profile(cndev_set, &info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &info, cpsize);
	}

	put_cndev_set(cndev_set);

	return ret;
}

typedef int (*cndev_ioctl_func)(struct file *fp, unsigned long arg, unsigned int ioc_size);
static const struct {
	cndev_ioctl_func funcs;
	enum cnhost_dev_ioctl_flags flags;
} cndev_funcs[_CNDEV_MAX] = {
	[_M_PINNED_MEM_NODE_ALLOC] = {cn_pinned_mem_alloc_node, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_FLAG_NODE_ALLOC] = {cn_pinned_mem_flag_alloc, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_HOST_GET_POINTER] = {cn_pinned_mem_get_device_pointer, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_HOST_REGISTER] = {cn_pinned_mem_host_register, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_HOST_UNREGISTER] = {cn_pinned_mem_host_unregister, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_GET_FLAGS] = {cn_pinned_mem_get_flags, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_ALLOC] = {cn_pinned_mem_alloc, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_LAR4_ALLOC] = {cn_pinned_mem_alloc, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_FREE] = {cn_pinned_mem_free, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_GET_HANDLE] = {cn_pinned_mem_get_handle, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_LAR4_GET_HANDLE] = {cn_pinned_mem_get_handle, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_CLOSE_HANDLE] = {cn_pinned_mem_close_handle, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_LAR4_CLOSE_HANDLE] = {cn_pinned_mem_close_handle, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_OPEN_HANDLE] = {cn_pinned_mem_open_handle, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_LAR4_OPEN_HANDLE] = {cn_pinned_mem_open_handle, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_GET_MEM_RANGE] = {cn_pinned_mem_get_range, CNHOST_DEV_AUTH},
	[_M_PINNED_MEM_LAR4_GET_MEM_RANGE] = {cn_pinned_mem_get_range, CNHOST_DEV_AUTH},
	[_CNDEV_CARDNUM] = {cn_cndev_get_card_num, CNHOST_DEV_AUTH},
	[_CNDEV_CARDINFO] = {cn_cndev_get_card_info, CNHOST_DEV_AUTH},
	[_CNDEV_POWERINFO] = {cn_cndev_get_power_info, CNHOST_DEV_AUTH},
	[_CNDEV_MEMINFO] = {cn_cndev_get_mem_info, CNHOST_DEV_AUTH},
	[_CNDEV_PROCINFO] = {cn_cndev_get_proc_info, CNHOST_DEV_AUTH},
	[_CNDEV_HEALTHSTATE] = {cn_cndev_get_health_state_info, CNHOST_DEV_AUTH},
	[_CNDEV_ECCINFO] = {cn_cndev_get_ecc_info, CNHOST_DEV_AUTH},
	[_CNDEV_VMINFO] = {cn_cndev_get_vm_info, CNHOST_DEV_AUTH},
	[_CNDEV_IPUUTIL] = {cn_cndev_get_iputil_info, CNHOST_DEV_AUTH},
	[_CNDEV_CODECUTIL] = {cn_cndev_get_codectil_info, CNHOST_DEV_AUTH},
	[_CNDEV_IPUFREQ] = {cn_cndev_get_ipufreq_info, CNHOST_DEV_AUTH},
	[_CNDEV_CURBUSINFO] = {cn_cndev_get_curbus_info, CNHOST_DEV_AUTH},
	[_CNDEV_PCIE_THROUGHPUT] = {cn_cndev_get_pcie_thoughput_info, CNHOST_DEV_AUTH},
	[_CNDEV_POWERCAPPING] = {cn_cndev_get_power_capping_info, CNHOST_DEV_AUTH},
	[_CNDEV_IPUFREQ_SET] = {cn_cndev_set_ipufreq_info, CNHOST_DEV_ROOT_ONLY},
	[_CNDEV_GET_IOCTL_ATTR] = {cn_cndev_get_attr_info, CNHOST_DEV_AUTH},
	[_CNDEV_NCS_VERSION] = {cn_cndev_get_ncs_ver_info, CNHOST_DEV_AUTH},
	[_CNDEV_NCS_STATE] = {cn_cndev_get_ncs_state_info, CNHOST_DEV_AUTH},
	[_CNDEV_NCS_SPEED] = {cn_cndev_get_ncs_speed_info, CNHOST_DEV_AUTH},
	[_CNDEV_NCS_CAPABILITY] = {cn_cndev_get_ncs_capability_info, CNHOST_DEV_AUTH},
	[_CNDEV_NCS_COUNTER] = {cn_cndev_get_ncs_err_counter_info, CNHOST_DEV_AUTH},
	[_CNDEV_NCS_RESET_COUNTER] = {cn_cndev_reset_ncs_counter_info, CNHOST_DEV_ROOT_ONLY},
	[_CNDEV_NCS_REMOTE_INFO] = {cn_cndev_get_ncs_remote_info, CNHOST_DEV_AUTH},
	[_CNDEV_CHASSISINFO] = {cn_cndev_get_chassis_info, CNHOST_DEV_AUTH},
	[_CNDEV_QOS_RESET] = {cn_cndev_reset_qos_info, CNHOST_DEV_ROOT_ONLY},
	[_CNDEV_QOS_INFO] = {cn_cndev_get_qos_info, CNHOST_DEV_AUTH},
	[_CNDEV_QOS_DESC] = {cn_cndev_get_qos_desc_info, CNHOST_DEV_AUTH},
	[_CNDEV_SET_QOS] = {cn_cndev_set_qos_info, CNHOST_DEV_AUTH},
	[_CNDEV_SET_QOS_GROUP] = {cn_cndev_set_qos_group_info, CNHOST_DEV_AUTH},
	[_CNDEV_ACPUUTIL] = {cn_cndev_get_acpu_util_info, CNHOST_DEV_AUTH},
	[_CNDEV_ACPUUTIL_TIMER] = {cn_cndev_set_acpu_timer_info, CNHOST_DEV_AUTH},
	[_CNDEV_GET_RETIRE_PAGES] = {cn_cndev_get_retire_pages_info, CNHOST_DEV_AUTH},
	[_CNDEV_GET_RETIRE_STATUS] = {cn_cndev_get_retire_status_info, CNHOST_DEV_AUTH},
	[_CNDEV_GET_REMAPPED_ROWS] = {cn_cndev_get_remapped_rows_info, CNHOST_DEV_AUTH},
	[_CNDEV_RETIRE_SWITCH] = {cn_cndev_retire_switch_ctrl, CNHOST_DEV_AUTH},
	[_CNDEV_NCS_CONFIG] = {cn_cndev_ncs_config, CNHOST_DEV_AUTH},
	[_CNDEV_MLULINK_SWITCH_CTRL] = {cn_cndev_mlulink_switch_ctrl, CNHOST_DEV_AUTH},
	[_CNDEV_IPUFREQ_CTRL] = {cn_cndev_ipufreq_ctrl, CNHOST_DEV_AUTH},
	[_CNDEV_NCS_INFO] = {cn_cndev_get_ncs_info, CNHOST_DEV_AUTH},
	[_CNDEV_CARDINFO_EXT] = {cn_cndev_get_card_ext_info, CNHOST_DEV_AUTH},
	[_CNDEV_HOST_CTRL] = {cn_cndev_host_ctrl, CNHOST_DEV_AUTH},
	[_CNDEV_PROCESS_IPUUTIL] = {cn_cndev_get_process_ipuutil_info, CNHOST_DEV_AUTH},
	[_CNDEV_PROCESS_CODECUTIL] = {cn_cndev_get_process_codecutil_info, CNHOST_DEV_AUTH},
	[_CNDEV_GET_FEATURE] = {cn_cndev_get_feature, CNHOST_DEV_AUTH},
	[_CNDEV_SET_FEATURE] = {cn_cndev_set_feature, CNHOST_DEV_ROOT_ONLY},
	[_CNDEV_GET_MIM_VMLU_PROFILE] = {cn_cndev_get_mim_vmlu_profile, CNHOST_DEV_AUTH},
	[_CNDEV_GET_MIM_POSSIBLE_PLACE] = {cn_cndev_get_mim_possible_place, CNHOST_DEV_AUTH},
	[_CNDEV_GET_MIM_VMLU_CAPACITY] = {cn_cndev_get_mim_vmlu_capacity, CNHOST_DEV_AUTH},
	[_CNDEV_GET_MIM_DEVICE_INFO] = {cn_cndev_get_device_info, CNHOST_DEV_AUTH},
	[_CNDEV_MI_CARD] = {cn_cndev_get_card_desc, CNHOST_DEV_AUTH},
	[_CNDEV_CARDNUM_EXT] = {cn_cndev_get_card_num_ext, CNHOST_DEV_AUTH},
	[_CNDEV_GET_COUNTER] = {cn_cndev_get_cntr_info, CNHOST_DEV_AUTH},
	[_CNDEV_CHASSIS_POWER_INFO] = {cn_cndev_get_chassis_power_info, CNHOST_DEV_AUTH},
	[_CNDEV_MIM_MODE_SWITCH] = {cn_cndev_mim_mode_switch, CNHOST_DEV_AUTH},
	[_CNDEV_SMLU_MODE_SWITCH] = {cn_cndev_smlu_mode_switch, CNHOST_DEV_AUTH},
	[_CNDEV_GET_SMLU_PROFILE_ID] = {cn_cndev_get_smlu_profile_id, CNHOST_DEV_AUTH},
	[_CNDEV_GET_SMLU_PROFILE_INFO] = {cn_cndev_get_smlu_profile_info, CNHOST_DEV_AUTH},
	[_CNDEV_NEW_SMLU_PROFILE] = {cn_cndev_new_smlu_profile, CNHOST_DEV_ROOT_ONLY},
	[_CNDEV_DELETE_SMLU_PROFILE] = {cn_cndev_delete_smlu_profile, CNHOST_DEV_ROOT_ONLY},
	[_CNDEV_DEVICE_RESET] = {cn_cndev_device_reset, CNHOST_DEV_ROOT_ONLY},
	[_CNDEV_DEVICE_STATE] = {cn_cndev_device_state, CNHOST_DEV_AUTH},
};

static int cn_cndev_ioctl(struct file *fp,
	unsigned long arg,
	unsigned int cmd)
{
	unsigned int ioc_nr = _IOC_NR(cmd);
	size_t ioc_size = _IOC_SIZE(cmd);
	u32 flags = 0;

	int ret = 0;

	if (unlikely(ioc_nr >= ARRAY_SIZE(cndev_funcs) || !cndev_funcs[ioc_nr].funcs))
		return -EPERM;

	flags = cndev_funcs[ioc_nr].flags;
	/* ROOT_ONLY is only for CAP_SYS_ADMIN */
	if (unlikely((flags & CNHOST_DEV_ROOT_ONLY) && !capable(CAP_SYS_ADMIN))) {
		cn_dev_warn("Permission denied");
		return -EACCES;
	}

	ret = cndev_funcs[ioc_nr].funcs(fp, arg, ioc_size);

	return ret;
}

static
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36))
int
#else
long
#endif
cndev_ioctl(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36))
		struct inode *inode,
#endif
		struct file *fp,
		unsigned int cmd,
		unsigned long arg)
{
	cn_dev_debug("cndev ioctl");

	if (_IOC_TYPE(cmd) == CAMBR_UDVM_MAGIC)
		return cn_udvm_ioctl(fp, cmd, arg);
	if (_IOC_TYPE(cmd) == CAMBR_SBTS_MAGIC)
		return cn_sbts_idc_ctl(fp, cmd, arg);
	if (_IOC_TYPE(cmd) == CAMBRICON_MAGIC_NUM)
		return cn_attr_ctl_ioctl(fp, cmd, arg);
	if (_IOC_TYPE(cmd) == CAMBR_MONITOR_MAGIC)
		return cn_cndev_ioctl(fp, arg, cmd);

	return 0;
}

const struct file_operations cndev_fops = {
	.owner   =  THIS_MODULE,
	.open    =  cndev_open,
	.release    =  cndev_release,
	.mmap    = cndev_mmap,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36))
	.ioctl = cndev_ioctl,
#else
	.unlocked_ioctl = cndev_ioctl,
#endif
};

bool file_is_cndev(struct file *fp)
{
	return (fp != NULL) && (fp->f_op == &cndev_fops);
}

int cndrv_cndev_lateinit(void *pcore)
{
	int ret;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set =
		(struct cn_cndev_set *)core->cndev_set;

	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ops)) {
		cn_dev_cndev_err(cndev_set, "cndev ops null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ops->cndev_lateinit)) {
		cn_dev_cndev_err(cndev_set, "cndev lateinit func null");
		return -EINVAL;
	}
	ret = cndev_set->ops->cndev_lateinit(core);
	if (ret)
		return ret;
	cndev_card_info_fill(cndev_set);

	return ret;
}

int cndrv_cndev_restart(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set =
		(struct cn_cndev_set *)core->cndev_set;

	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ops)) {
		cn_dev_cndev_err(cndev_set, "cndev ops null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ops->cndev_restart)) {
		return -EINVAL;
	}
	return cndev_set->ops->cndev_restart(cndev_set);
}

void cndrv_cndev_stop(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set =
		(struct cn_cndev_set *)core->cndev_set;

	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return;
	}
	if (IS_ERR_OR_NULL(cndev_set->ops)) {
		cn_dev_cndev_err(cndev_set, "cndev ops null");
		return;
	}
	if (IS_ERR_OR_NULL(cndev_set->ops->cndev_stop)) {
		return;
	}
	return cndev_set->ops->cndev_stop(cndev_set);

}

const struct __cndev_board_initor __cndev_board[] = {
	{MLUID_220, cndev_init_mlu220, CNDEV_PHY_CARD,
		.quirks = CNDEV_QUIRK_PF_ONLY | CNDEV_QUIRK_SUPPORT_SCALER},
	{MLUID_220_EDGE, cndev_init_mlu220, CNDEV_PHY_CARD,
		.quirks = CNDEV_QUIRK_PF_ONLY | CNDEV_QUIRK_SUPPORT_SCALER},
	{MLUID_270, cndev_init_mlu270, CNDEV_PHY_CARD,
		.quirks = 0},
	{MLUID_270V, cndev_init_mlu270, CNDEV_VF_CARD,
		.quirks = 0},
	{MLUID_270V1, cndev_init_mlu270, CNDEV_VF_CARD,
		.quirks = 0},
	{MLUID_290, cndev_init_mlu290, CNDEV_PHY_CARD,
		.quirks = 0},
	{MLUID_290V1, cndev_init_mlu290, CNDEV_VF_CARD,
		.quirks = 0},
	{MLUID_370, cndev_init_mlu370, CNDEV_PHY_CARD,
		.quirks = 0},
	{MLUID_370V, cndev_init_mlu370, CNDEV_VF_CARD,
		.quirks = 0},
	{MLUID_370_DEV, cndev_init_mlu370, CNDEV_PHY_CARD,
		.quirks = 0},
	{MLUID_CE3226, cndev_init_ce3226, CNDEV_PHY_CARD,
		.quirks = CNDEV_QUIRK_PF_ONLY},
	{MLUID_CE3226_EDGE, cndev_init_ce3226, CNDEV_PHY_CARD,
		.quirks = CNDEV_QUIRK_PF_ONLY},
	{MLUID_PIGEON, cndev_init_pigeon, CNDEV_PHY_CARD,
		.quirks = CNDEV_QUIRK_PF_ONLY},
	{MLUID_PIGEON_EDGE, cndev_init_pigeon, CNDEV_PHY_CARD,
		.quirks = CNDEV_QUIRK_PF_ONLY},
	{MLUID_590, cndev_init_mlu590, CNDEV_PHY_CARD,
		.quirks = 0},
	{MLUID_590V, cndev_init_mlu590, CNDEV_VF_CARD,
		.quirks = 0},
	{MLUID_590_DEV, cndev_init_mlu590, CNDEV_PHY_CARD,
		.quirks = 0},
	{MLUID_580, cndev_init_mlu580, CNDEV_PHY_CARD,
		.quirks = 0},
	{MLUID_580V, cndev_init_mlu580, CNDEV_VF_CARD,
		.quirks = 0},
	{MLUID_580_DEV, cndev_init_mlu580, CNDEV_PHY_CARD,
		.quirks = 0},
};

int __cndev_board_init(struct cn_cndev_set *cndev_set)
{
	int ret = 0;
	u32 table_size = ARRAY_SIZE(__cndev_board);
	int i = 0;

	atomic64_set(&cndev_set->ipu_freq_set_ref, 0);
	for (i = 0; i < table_size; i++) {
		if (__cndev_board[i].device_id == cndev_set->device_id) {
			if (__cndev_board[i].phy_dev == CNDEV_PHY_CARD)
				phy_card_num++;
			if (__cndev_board[i].phy_dev == CNDEV_VF_CARD)
				vf_card_num++;

			cndev_set->quirks = __cndev_board[i].quirks;
			ret = __cndev_board[i].cndev_init(cndev_set);

			return ret;
		}
	}

	cn_dev_err("device [%#llx] not support", cndev_set->device_id);

	return -ENODEV;
}

int cndrv_cndev_init(void *pcore)
{
	int ret;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set;

	cndev_set = cn_kzalloc(sizeof(struct cn_cndev_set), GFP_KERNEL);
	if (!cndev_set) {
		cn_dev_err("alloc for cndev set error");
		return -ENOMEM;
	}
	cndev_set->core = core;
	cndev_set->idx = core->idx;
	strcpy(cndev_set->core_name, core->core_name);
	cndev_set->device_id = core->device_id;
	init_rwsem(&core->mcc_state_sem);
	core->cndev_set = cndev_set;

	ret = __cndev_board_init(cndev_set);
	if (ret) {
		cn_kfree(cndev_set);
		core->cndev_set = NULL;
		if (ret == -ENODEV)
			return 0;
		return ret;
	}

	mutex_lock(&open_lock);
	list_add_tail(&cndev_set->list, &cndev_list);
	card_num++;
	mutex_unlock(&open_lock);

	return 0;
}

void cndev_free_codec_process(struct cn_cndev_set *cndev_set)
{
	if (cndev_set->process_info.codec) {
		cn_vfree(cndev_set->process_info.codec);
		cndev_set->process_info.codec = NULL;
	}
	if (cndev_set->process_info.active_pid) {
		cn_vfree(cndev_set->process_info.active_pid);
		cndev_set->process_info.active_pid = NULL;
	}
}

void cndrv_cndev_free(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set = core->cndev_set;
	u32 table_size = ARRAY_SIZE(__cndev_board);
	int i = 0;

	if (cndev_set) {
		mutex_lock(&open_lock);

		for (i = 0; i < table_size; i++) {
			if (__cndev_board[i].device_id == cndev_set->device_id) {
				if (__cndev_board[i].phy_dev == CNDEV_PHY_CARD)
					phy_card_num--;
				if (__cndev_board[i].phy_dev == CNDEV_VF_CARD)
					vf_card_num--;
			}
		}

		list_del(&cndev_set->list);
		card_num--;
		mutex_unlock(&open_lock);

		if (cndev_set->ops && cndev_set->ops->cndev_exit) {
			cndev_set->ops->cndev_exit(cndev_set);
		}
		cndev_free_codec_process(cndev_set);
		cn_kfree(cndev_set);
	}
}
