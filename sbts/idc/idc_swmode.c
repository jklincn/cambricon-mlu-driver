#include <linux/version.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/ptrace.h>


#include "cndrv_core.h"
#include "cndrv_os_compat.h"
#include "idc_internal.h"
#include "cndrv_debug.h"


#define IDC_EMODE_READ_DEFAULT_TIME 9999999
#define IDC_EMODE_ON_HOST -1

enum idc_kaddr_emode {
	/* cidx card is E, host is -1 */
	IDC_EMODE_ACTIVE = 1,
	/* multi card req, all sta is S */
	IDC_EMODE_DISABLE,
	IDC_EMODE_CHANGING,
	IDC_EMODE_INIT,
	IDC_EMODE_ERROR,
};

#define swmode_write_p2pshm(info, mode_priv) \
({ \
	sbts_p2pshm_write64((mode_priv)->emode_key, \
			READ_ONCE(*(u64 *)(info)->kern_addr), \
			++((mode_priv)->emode_seq)); \
})

static int emode_timeout = IDC_EMODE_READ_DEFAULT_TIME;

void idc_swmode_set_timeout(int timeout)
{
	/* set a min threshold */
	if (timeout < 9999) {
		IDC_DBG_OUT("Set time %d err", timeout);
		return;
	}

	emode_timeout = timeout;

	IDC_DBG_OUT("Debug Set emode timeout %d success", emode_timeout);
}

int idc_swmode_get_timeout(void)
{
	return emode_timeout;
}

static inline void
__emode_ctrl_fill_desc(
		struct comm_ctrl_desc *desc,
		struct sbts_idc_kaddr_info *info,
		u64 type, u64 flag, u64 val)
{
	struct ctrl_desc_data_v1 *data;
	struct cd_idc_ctrl_msg *priv;
	struct cd_idc_swmode_msg *msg;
	struct idc_swmode_priv *mode_priv = &info->swmode;

	desc->version    = cpu_to_le64(SBTS_VERSION);
	data             = (struct ctrl_desc_data_v1 *)desc->data;
	data->type       = cpu_to_le64(IDC_CTRL);
	priv             = (struct cd_idc_ctrl_msg *)data->priv;
	priv->ctrl_type  = cpu_to_le64(IDC_CTRL_SWMODE);

	priv->kern_addr  = cpu_to_le64(info->kern_addr);
	priv->kern_index = cpu_to_le64(info->index);
	priv->cur_val    = cpu_to_le64(
				__sync_fetch_and_add((u64 *)info->kern_addr, 0));
	msg              = (struct cd_idc_swmode_msg *)&priv->swmode_msg;
	msg->msg_type   = cpu_to_le64(type);
	msg->emode_key  = cpu_to_le64(mode_priv->emode_key);
	msg->req_flag   = cpu_to_le64(flag);
	msg->req_val    = cpu_to_le64(val);
}

static int __emode_to_disable(
		struct sbts_idc_kaddr_info *info,
		u64 *lst_val)
{
	/* msg should send to emode_cidx card */
	struct idc_manager *manager;
	struct sbts_set *sbts;
	struct idc_swmode_priv *mode_priv = &info->swmode;
	struct comm_ctrl_desc tx = {0}, rx = {0};
	struct ctrl_desc_data_v1 *data;
	struct cd_idc_ctrl_msg *priv;
	int ret, find_flag = 0;

	down_read(&g_mgrlist_rwsem);
	list_for_each_entry(manager,
				&idcmgr_list_head, mgr_list) {
		if (manager->c_idx == mode_priv->emode_cidx) {
			find_flag = 1;
			break;
		}
	}

	if (!find_flag) {
		up_read(&g_mgrlist_rwsem);
		cn_dev_err("find emode idx %d manager err", mode_priv->emode_cidx);
		return -EINVAL;
	}

	__emode_ctrl_fill_desc(&tx, info, EMODE_DISABLE, 0, 0);

	sbts = manager->sbts;
	ret = idc_ctrl_data_send(sbts, &tx, &rx);
	up_read(&g_mgrlist_rwsem);
	if (ret || rx.sta) {
		cn_dev_err("disable emode on %d failed %d %llu",
					mode_priv->emode_cidx, ret, rx.sta);
		return -EINVAL;
	}

	data = (struct ctrl_desc_data_v1 *)rx.data;
	priv = (struct cd_idc_ctrl_msg *)data->priv;

	*lst_val = le64_to_cpu(priv->cur_val);

	return 0;
}

static int __emode_send_updateval(
		struct sbts_idc_kaddr_info *info,
		u64 flag, u64 val,
		u64 *new_val)
{
	/* msg should send to emode_cidx card */
	struct idc_manager *manager;
	struct sbts_set *sbts;
	struct idc_swmode_priv *mode_priv = &info->swmode;
	struct comm_ctrl_desc tx = {0}, rx = {0};
	struct ctrl_desc_data_v1 *data;
	struct cd_idc_ctrl_msg *priv;
	int ret, find_flag = 0;

	down_read(&g_mgrlist_rwsem);
	list_for_each_entry(manager,
				&idcmgr_list_head, mgr_list) {
		if (manager->c_idx == mode_priv->emode_cidx) {
			find_flag = 1;
			break;
		}
	}

	if (!find_flag) {
		up_read(&g_mgrlist_rwsem);
		cn_dev_err("find emode idx %d manager err", mode_priv->emode_cidx);
		return -EINVAL;
	}

	__emode_ctrl_fill_desc(&tx, info, EMODE_UPDATEVAL, flag, val);

	sbts = manager->sbts;
	ret = idc_ctrl_data_send(sbts, &tx, &rx);
	up_read(&g_mgrlist_rwsem);
	if (ret || rx.sta) {
		cn_dev_err("disable emode on %d failed %d %llu",
				mode_priv->emode_cidx, ret, rx.sta);
		return -EINVAL;
	}

	data = (struct ctrl_desc_data_v1 *)rx.data;
	priv = (struct cd_idc_ctrl_msg *)data->priv;

	*new_val = le64_to_cpu(priv->cur_val);

	return 0;
}

static int __idc_read_p2pshm_val(
		struct sbts_idc_kaddr_info *info,
		u64 *cur_val, u16 *seq)
{
	struct idc_swmode_priv *mode_priv = &info->swmode;
	int timeout = emode_timeout;
	int ret;

	while (timeout--) {
		ret = sbts_p2pshm_read64(mode_priv->emode_key,
				cur_val, seq);
		if (!ret) {
			return 0;
		}

		if (ret != -EAGAIN) {
			cn_dev_err("read val from shm failed %d", ret);
			return ret;
		}
		usleep_range(3, 10);

		if (fatal_signal_pending(current)) {
			cn_dev_err("read val killed by user exit");
			return ret;
		}
	}

	return -EINVAL;
}

/* if use old commu flow, we still need to write val to shm
 * if mode change from exclusive to share, the compare task dev doesnt known
 * and will still read val from shm */
static inline void __idc_swmode_update_emode_val(
		struct sbts_idc_kaddr_info *info,
		struct idc_swmode_priv *mode_priv)
{
	if (mode_priv->emode_key) {
		mutex_lock(&info->mode_lock);
		swmode_write_p2pshm(info, mode_priv);
		/*sbts_p2pshm_flush_write();*/
		mutex_unlock(&info->mode_lock);
	}
}

static inline int __idc_init_emode_info(
		struct sbts_idc_kaddr_info *info)
{
	struct idc_swmode_priv *mode_priv = &info->swmode;

	mutex_lock(&info->mode_lock);
	if ((mode_priv->init_finish) ||
			(mode_priv->emode_key)) {
		mutex_unlock(&info->mode_lock);
		return 0;
	}
	mode_priv->init_finish = 1;

	/* p2p mode should enabled and user api support too */
	if (mode_priv->emode_sta == IDC_EMODE_ACTIVE) {
		if (!sbts_p2pshm_alloc64(&mode_priv->emode_key)) {
			swmode_write_p2pshm(info, mode_priv);
			/* no need to flush */
			mutex_unlock(&info->mode_lock);
			return 0;
		}
	}

	mode_priv->emode_sta = IDC_EMODE_DISABLE;
	mutex_unlock(&info->mode_lock);

	return 0;
}

static enum idc_kaddr_emode __idc_emode_check(
		struct idc_manager *manager,
		struct sbts_idc_kaddr_info *info,
		u64 task_type)
{
	struct cn_core_set *core = manager->core;
	struct idc_swmode_priv *mode_priv = &info->swmode;
	int ret;
	u64 lst_val, new_val;

	/* should init before call this func */
	/* sta is err cant send new task */
	if ((!mode_priv->init_finish) ||
			(mode_priv->emode_sta == IDC_EMODE_ERROR))
		return IDC_EMODE_ERROR;

	/* disabled, host and card is S */
	if (mode_priv->emode_sta == IDC_EMODE_DISABLE)
		return IDC_EMODE_DISABLE;

	/* compare task always is disable */
	if (task_type == _IDC_COMPARE_OPERATION) {
		return IDC_EMODE_DISABLE;
	}

	/* request task */
	if (mutex_lock_killable(&info->mode_lock)) {
		IDC_KINFO_CORE_PRT(cn_dev_core_err, core, info,
				"wait emode lock intr");
		return IDC_EMODE_ERROR;
	}
	/* not active just ret current sta */
	if (mode_priv->emode_sta != IDC_EMODE_ACTIVE) {
		ret = mode_priv->emode_sta;
		goto finish;
	}

	/* current card is E, no need to send E to card again */
	if (mode_priv->emode_cidx == manager->c_idx) {
		IDC_KINFO_CORE_PRT(cn_dev_core_debug, core, info,
				"current dev is E");
		ret = IDC_EMODE_ACTIVE;
		goto finish;
	}
	/* if host is E emode_cidx is -1*/
	if (mode_priv->emode_cidx == IDC_EMODE_ON_HOST) {
		/* change emode to current cidx */
		IDC_KINFO_CORE_PRT(cn_dev_core_debug, core, info,
				"host is E move to dev");
		/* flush old write */
		sbts_p2pshm_flush_write();
		mode_priv->emode_cidx = manager->c_idx;
		mode_priv->emode_sta = IDC_EMODE_ACTIVE;
		ret = IDC_EMODE_ACTIVE;
		goto finish;
	}

	/* to avoid recv new req msg from dev */
	mode_priv->emode_sta = IDC_EMODE_CHANGING;
	smp_wmb();
	/* disable dev emode */
	ret = __emode_to_disable(info, &lst_val);
	if (ret) {
		mode_priv->emode_sta = IDC_EMODE_ERROR;
		ret = IDC_EMODE_ERROR;
		goto finish;
	}
	IDC_KINFO_CORE_PRT(cn_dev_core_debug, core, info,
			"disable from dev");
	/* flush old write */
	sbts_p2pshm_flush_write();
	__idc_read_p2pshm_val(info, &new_val, &mode_priv->emode_seq);
	__sync_lock_test_and_set((u64 *)info->kern_addr, lst_val);

	mode_priv->emode_sta = IDC_EMODE_DISABLE;
	ret = IDC_EMODE_DISABLE;
	g_dbg_sw_acc_to_basic++;

finish:
	mutex_unlock(&info->mode_lock);
	return ret;
}

static int idc_swmode_info_init(struct sbts_idc_kaddr_info *info)
{

	return __idc_init_emode_info(info);
}

static int idc_swmode_fill_task(
		struct sbts_idc_kaddr_info *info,
		struct idc_manager *manager,
		struct td_idc_task *td_priv,
		u64 task_type)
{
	int ret = 0;
	struct sbts_set *sbts = manager->sbts;
	struct cn_core_set *core =
			(struct cn_core_set *)sbts->core;
	struct idc_swmode_priv *mode_priv = &info->swmode;
	struct td_idc_swmode_priv *msg_priv = &td_priv->swmode;
	enum idc_kaddr_emode emode;

	emode = __idc_emode_check(manager, info, task_type);
	if (emode == IDC_EMODE_ERROR) {
		IDC_KINFO_CORE_PRT(cn_dev_core_err, core, info,
				"idc mode check fail %d", ret);
		return -EFAULT;
	}

	msg_priv->emode_sta = cpu_to_le64(emode);
	msg_priv->emode_key = cpu_to_le64(mode_priv->emode_key);
	td_priv->kern_mode  = IDC_OPSMODE_SWMODE;

	return 0;
}

static int idc_swmode_user_request(
		struct sbts_idc_kaddr_info *info,
		struct sbts_place_idc *param)
{
	struct idc_swmode_priv *mode_priv = &info->swmode;
	int ret = 0;
	u64 new_val;
	u64 flag = param->flag & IDC_TASK_FLAG_BASIC_MASK;

	if (mutex_lock_killable(&info->mode_lock)) {
		IDC_KINFO_PRT(cn_dev_err, info, "wait emode lock intr");
		return -EINTR;
	}

	if (!mode_priv->init_finish) {
		__idc_request_ops((u64 *)info->kern_addr, flag, param->val);
		mutex_unlock(&info->mode_lock);
		return 0;
	}

	if (mode_priv->emode_sta == IDC_EMODE_DISABLE) {
		mutex_unlock(&info->mode_lock);
		/* sta is S, just modify local and send to all */
		__idc_request_ops((u64 *)info->kern_addr, flag, param->val);
		__idc_swmode_update_emode_val(info, mode_priv);
		__idc_prepare_send_task(info, 0, 0, _IDC_UPDATE);
		return 0;
	}

	if (mode_priv->emode_sta == IDC_EMODE_ERROR) {
		mutex_unlock(&info->mode_lock);
		return -EINVAL;
	}

	/* info->emode_sta == IDC_EMODE_ACTIVE */
	/* sta E on dev, send ctrl msg to update val */
	if (mode_priv->emode_cidx != IDC_EMODE_ON_HOST) {
		ret = __emode_send_updateval(info, flag, param->val, &new_val);
		if (ret) {
			goto finish;
		}
		__sync_lock_test_and_set((u64 *)info->kern_addr, new_val);

		mutex_unlock(&info->mode_lock);
		return 0;
	}

	/* sta E on Host, write self and write all dev */
	__idc_request_ops((u64 *)info->kern_addr, flag, param->val);
	swmode_write_p2pshm(info, mode_priv);
	/*sbts_p2pshm_flush_write();*/

finish:
	mutex_unlock(&info->mode_lock);
	return ret;
}

static int idc_swmode_get_val(
		struct sbts_idc_kaddr_info *info,
		u64 *val)
{
	struct idc_swmode_priv *mode_priv = &info->swmode;
	int ret;
	u16 seq;

	if (mutex_lock_killable(&info->mode_lock)) {
		IDC_KINFO_PRT(cn_dev_err, info, "wait emode lock intr");
		return -EINTR;
	}

	if (mode_priv->emode_sta == IDC_EMODE_ERROR) {
		mutex_unlock(&info->mode_lock);
		return -EINVAL;
	}

	/* sta is init */
	/* sta is S, just get val from kern_addr */
	/* or sta E on Host, read self */
	if ((!mode_priv->init_finish) ||
			(mode_priv->emode_sta == IDC_EMODE_DISABLE) ||
			(mode_priv->emode_cidx == IDC_EMODE_ON_HOST)) {
		mutex_unlock(&info->mode_lock);
		*val = __sync_fetch_and_add((u64 *)info->kern_addr, 0);
		return 0;
	}
	/* info->emode_sta == IDC_EMODE_ACTIVE */
	/* sta E on dev, read host shm */
	ret = __idc_read_p2pshm_val(info, val, &seq);

	mutex_unlock(&info->mode_lock);
	return ret;
}

static inline void __idc_sta_wait(
		struct cn_core_set *core,
		struct sbts_idc_kaddr_info *info)
{
	struct idc_swmode_priv *mode_priv = &info->swmode;
	int timeout = 10000;

	if (mode_priv->emode_sta == IDC_EMODE_DISABLE)
		return;

	while ((mode_priv->emode_sta == IDC_EMODE_CHANGING) &&
			--timeout) {
		if (sbts_pause(core, 10, 20))
			return;
	}
}

static int idc_swmode_rx_msg(struct sbts_idc_kaddr_info *info,
			struct idc_manager *manager,
			struct sbts_idc_task idc, u64 type)
{
	struct cn_core_set *core = manager->core;
	struct idc_swmode_priv *mode_priv = &info->swmode;
	int ret = 0;
	int send_flag = 0, use_idx = 0;
	enum idc_msg_type update_type = _IDC_UPDATE;

	/* if info sta is changing, need wait */
	__idc_sta_wait(core, info);

	if ((mode_priv->emode_sta != IDC_EMODE_DISABLE) &&
			(type != _IDC_FORCE)) {
		IDC_KINFO_CORE_PRT(cn_dev_core_err, core, info,
				"info shouldn't recv msg");
		ret = -EINVAL;
		goto out;
	}

	switch (type) {
	case _IDC_FORCE:
		IDC_KINFO_CORE_PRT(cn_dev_core_info, core, info,
				">>> idc idx:%llu type:%llu rval:%llu force update",
				idc.index, idc.type, idc.req_val);
		update_type = _IDC_FORCE;
		if (mode_priv->emode_sta == IDC_EMODE_DISABLE)
			send_flag = 1;
		break;
	case _IDC_FINISH:
		if (likely(idc.type == _IDC_REQUEST_OPERATION)) {
			__idc_request_ops((u64 *)info->kern_addr,
					idc.flag, idc.req_val);
			use_idx = 1;
			send_flag = 1;
		}
		IDC_LOG_CORE_INFO(core,
				"recv idx:%llu type:%llu val:%llu finish",
				idc.index, idc.type, idc.req_val);
		break;
	case _IDC_EXCEP:
		IDC_LOG_CORE_INFO(core,
				"recv idx:%llu type:%llu val:%llu excep",
				idc.index, idc.type, idc.req_val);
		break;
	default:
		IDC_KINFO_CORE_PRT(cn_dev_core_err, core, info,
				"input type %llu invalid", type);
		ret = -EINVAL;
		break;
	}

	if (send_flag) {
		__idc_swmode_update_emode_val(info, mode_priv);
		__idc_prepare_send_task(info,
				idc.index, use_idx, update_type);
	}
out:

	return ret;
}

static void idc_swmode_dev_info_clear(struct sbts_idc_kaddr_info *info)
{
	struct idc_swmode_priv *mode_priv = &info->swmode;
	u64 lst_val;

	if (!mode_priv->init_finish)
		return;

	/* disable dev E mode before free to avoid dev write after host free */
	if ((mode_priv->emode_sta == IDC_EMODE_ACTIVE) &&
			(mode_priv->emode_cidx != IDC_EMODE_ON_HOST)) {
		if (__emode_to_disable(info, &lst_val))
			cn_dev_err("change mode in clear failed");
	}

	mode_priv->emode_sta = IDC_EMODE_ERROR;
	mode_priv->init_finish = 0;
}

static void idc_swmode_info_free(struct sbts_idc_kaddr_info *info)
{
	struct idc_swmode_priv *mode_priv = &info->swmode;

	if (mode_priv->emode_key)
		sbts_p2pshm_free64(mode_priv->emode_key);

	mode_priv->emode_sta = IDC_EMODE_ERROR;
}

static void idc_swmode_dump_info(struct sbts_idc_kaddr_info *info)
{
	struct idc_swmode_priv *mode_priv = &info->swmode;
	u16 seq = 0;
	u64 emodeval = 0;

	if (mode_priv->emode_key)
		sbts_p2pshm_read64(mode_priv->emode_key, &emodeval, &seq);

	IDC_DBG_OUT("      init:%d EM:%d EC:%d EK:%#llx Eval:%llu Eseq:%u %u ",
			mode_priv->init_finish,
			mode_priv->emode_sta, mode_priv->emode_cidx,
			mode_priv->emode_key, emodeval, seq, mode_priv->emode_seq);
}

static const struct sbts_idc_mode_ops swmode_ops = {
	.init            = idc_swmode_info_init,
	.fill_task       = idc_swmode_fill_task,
	.user_request    = idc_swmode_user_request,
	.get_val         = idc_swmode_get_val,
	.rx_msg          = idc_swmode_rx_msg,
	.dev_clear       = idc_swmode_dev_info_clear,
	.free            = idc_swmode_info_free,
	.dump_info       = idc_swmode_dump_info,
};

int idc_swmode_init_ops(
		struct sbts_idc_kaddr_info *info,
		u64 flag)
{
	struct idc_swmode_priv *mode_priv = &info->swmode;

	if (flag & IDC_TASK_FLAG_ACCMODE) {
		mode_priv->emode_sta = IDC_EMODE_ACTIVE;
		g_dbg_sw_acc++;
	} else {
		mode_priv->emode_sta = IDC_EMODE_DISABLE;
		g_dbg_sw_basic++;
	}

	mode_priv->init_finish = 0;
	mode_priv->emode_cidx = IDC_EMODE_ON_HOST;
	mode_priv->emode_seq = 1;
	mode_priv->emode_key = 0;

	info->mode_ops = &swmode_ops;

	return 0;
}
