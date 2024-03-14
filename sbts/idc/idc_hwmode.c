#include <linux/version.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/ptrace.h>


#include "cndrv_core.h"
#include "cndrv_os_compat.h"
#include "idc_internal.h"
#include "cndrv_debug.h"

#define IDC_HWMODE_ADDR_MODE_USER  1
#define IDC_HWMODE_ADDR_MODE_KERN  2

static int g_addr_mode = IDC_HWMODE_ADDR_MODE_KERN;

static inline int __idc_hwmode_alloc_value(
		struct sbts_idc_kaddr_info *info)
{
	struct idc_hwmode_priv *mode_priv = &info->hwmode;
	int ret;

	ret = sbts_p2pshm_alloc64(&mode_priv->addr_key);
	if (unlikely(ret)) {
		return -ENOMEM;
	}
	mode_priv->cpu_addr =
			sbts_p2pshm_get_hostkva(mode_priv->addr_key);
	if (!mode_priv->cpu_addr) {
		sbts_p2pshm_free64(mode_priv->addr_key);
		mode_priv->addr_key = 0;
		return -EINVAL;
	}
	__idc_request_ops((u64 *)mode_priv->cpu_addr, _IDC_REQUEST_SET,
			*(u64 *)info->kern_addr);

	return 0;
}

static int idc_hwmode_info_init(struct sbts_idc_kaddr_info *info)
{

	return 0;
}

static int __idc_hwmode_check_devaddr(
		struct idc_manager *manager,
		struct sbts_idc_kaddr_info *info)
{
	struct cn_core_set *core =
			(struct cn_core_set *)manager->core;
	struct idc_hwmode_priv *mode_priv = &info->hwmode;
	int ret = 0;
	u64 va;

	if (mode_priv->dev_addr[manager->c_idx])
		return 0;

	mutex_lock(&info->mode_lock);
	if (mode_priv->dev_addr[manager->c_idx]) {
		mutex_unlock(&info->mode_lock);
		return 0;
	}
	if (mode_priv->addr_type == IDC_HWMODE_ADDR_MODE_KERN) {
		ret = sbts_p2pshm_get_hostiova_by_card(core,
				mode_priv->addr_key, &va);
		if (!ret)
			mode_priv->dev_addr[manager->c_idx] = va;
	} else {
		//read from pinned mem
		ret = -ENODEV;
	}

	mutex_unlock(&info->mode_lock);
	return ret;
}

static int idc_hwmode_fill_task(
		struct sbts_idc_kaddr_info *info,
		struct idc_manager *manager,
		struct td_idc_task *td_priv,
		u64 task_type)
{
	int ret = 0;
	struct idc_hwmode_priv *mode_priv = &info->hwmode;
	struct td_idc_hwmode_priv *msg_priv = &td_priv->hwmode;

	ret = __idc_hwmode_check_devaddr(manager, info);
	if (ret)
		return ret;

	msg_priv->host_addr = __cpu_to_le64(mode_priv->dev_addr[manager->c_idx]);
	td_priv->kern_mode  = IDC_OPSMODE_HWMODE;

	return 0;
}

static int idc_hwmode_user_request(
		struct sbts_idc_kaddr_info *info,
		struct sbts_place_idc *param)
{
	struct idc_hwmode_priv *mode_priv = &info->hwmode;
	u64 flag = param->flag & IDC_TASK_FLAG_BASIC_MASK;

	__idc_request_ops((u64 *)mode_priv->cpu_addr, flag, param->val);

	return 0;
}

static int idc_hwmode_get_val(
		struct sbts_idc_kaddr_info *info,
		u64 *val)
{
	struct idc_hwmode_priv *mode_priv = &info->hwmode;

	*val = __sync_fetch_and_add((u64 *)mode_priv->cpu_addr, 0);

	return 0;
}

static int idc_hwmode_rx_msg(struct sbts_idc_kaddr_info *info,
			struct idc_manager *manager,
			struct sbts_idc_task idc, u64 type)
{
	struct cn_core_set *core = manager->core;

	cn_dev_core_err(core, "hw mode shouldnt get rx msg");

	return 0;
}

static void __idc_hwmode_dev_disable(
		struct idc_manager *manager,
		struct sbts_idc_kaddr_info *info)
{
	struct sbts_set *sbts;
	//struct idc_hwmode_priv *mode_priv = &info->hwmode;
	struct comm_ctrl_desc tx = {0}, rx = {0};
	struct ctrl_desc_data_v1 *data;
	struct cd_idc_ctrl_msg *priv;
	//struct cd_idc_hwmode_msg *msg;
	int ret;

	tx.version       = cpu_to_le64(SBTS_VERSION);
	data             = (struct ctrl_desc_data_v1 *)tx.data;
	data->type       = cpu_to_le64(IDC_CTRL);
	priv             = (struct cd_idc_ctrl_msg *)data->priv;
	priv->ctrl_type  = cpu_to_le64(IDC_CTRL_HWMODE);

	priv->kern_addr  = cpu_to_le64(info->kern_addr);
	priv->kern_index = cpu_to_le64(info->index);
	priv->cur_val    = 0;

	sbts = manager->sbts;
	ret = idc_ctrl_data_send(sbts, &tx, &rx);
	if (ret || rx.sta) {
		cn_dev_core_err(manager->core, "disable device failed");
	}
}

static void idc_hwmode_dev_info_clear(struct sbts_idc_kaddr_info *info)
{
	struct idc_manager *manager;
	struct idc_hwmode_priv *mode_priv = &info->hwmode;

	down_read(&g_mgrlist_rwsem);
	list_for_each_entry(manager,
				&idcmgr_list_head, mgr_list) {
		if (!mode_priv->dev_addr[manager->c_idx])
			continue;
		if (info->task_cnt[manager->c_idx]) {
			__idc_hwmode_dev_disable(manager, info);
		}
		// TODO may need free dev addr?
		mode_priv->dev_addr[manager->c_idx] = 0;
	}
	up_read(&g_mgrlist_rwsem);
}

static void idc_hwmode_info_free(struct sbts_idc_kaddr_info *info)
{
	struct idc_hwmode_priv *mode_priv = &info->hwmode;

	if (mode_priv->addr_key)
		sbts_p2pshm_free64(mode_priv->addr_key);
	mode_priv->addr_key = 0;
}

static void idc_hwmode_dump_info(struct sbts_idc_kaddr_info *info)
{
	struct idc_hwmode_priv *mode_priv = &info->hwmode;
	int i;

	IDC_DBG_OUT("      type:%d key:%#llx cpu:%#llx val:%llu",
			mode_priv->addr_type,
			mode_priv->addr_key,
			mode_priv->cpu_addr,
			*(u64 *)mode_priv->cpu_addr);
	for (i = 0; i < MAX_FUNCTION_NUM; i++) {
		if (mode_priv->dev_addr[i])
			IDC_DBG_OUT("      Dev[%d]:%#llx", i, mode_priv->dev_addr[i]);
	}
}

static const struct sbts_idc_mode_ops hwmode_ops = {
	.init            = idc_hwmode_info_init,
	.fill_task       = idc_hwmode_fill_task,
	.user_request    = idc_hwmode_user_request,
	.get_val         = idc_hwmode_get_val,
	.rx_msg          = idc_hwmode_rx_msg,
	.dev_clear       = idc_hwmode_dev_info_clear,
	.free            = idc_hwmode_info_free,
	.dump_info       = idc_hwmode_dump_info,
};



int idc_hwmode_init_ops(
		struct sbts_idc_kaddr_info *info,
		u64 flag)
{
	struct idc_hwmode_priv *mode_priv = &info->hwmode;
	int ret;

	memset(mode_priv, 0, sizeof(struct idc_hwmode_priv));
	if (g_addr_mode == IDC_HWMODE_ADDR_MODE_KERN) {
		ret = __idc_hwmode_alloc_value(info);
		if (ret)
			return ret;

		mode_priv->addr_type = IDC_HWMODE_ADDR_MODE_KERN;
	} else if (g_addr_mode == IDC_HWMODE_ADDR_MODE_USER) {
		cn_dev_err("not support user addr mode");
		return -ENODEV;
	} else {
		cn_dev_err("hw mode is invalid");
		return -EINVAL;
	}
	info->mode_ops = &hwmode_ops;

	return 0;
}

