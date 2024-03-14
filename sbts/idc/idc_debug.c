#include <linux/version.h>
#include <linux/signal.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>

#include "cndrv_core.h"
#include "cndrv_sbts.h"
#include "../sbts.h"
#include "../sbts_set.h"
#include "idc_internal.h"
#include "cndrv_debug.h"

static DEFINE_MUTEX(g_proc_dbg_lock);

u32 g_mode_support_dbg = ~0;
/* just use for debug, no need to record each task */
u64 g_dbg_sw_basic;
u64 g_dbg_sw_acc;
u64 g_dbg_sw_acc_to_basic;

int cn_sbts_idc_ctrl_mode_set(
		struct sbts_set *sbts,
		u64 ops, u64 mode, u64 val)
{
	struct cn_core_set *core = sbts->core;
	struct comm_ctrl_desc tx = {0}, rx = {0};
	struct ctrl_desc_data_v1 *data;
	struct cd_idc_ctrl_msg *priv;
	int ret;

	if (!sbts_set_is_empty(&idc_kaddr_container)) {
		cn_dev_core_err(core,
				"cant set mode while idc kinfo not empty");
		return -EBUSY;
	}

	/* fill desc */
	tx.version         = SBTS_VERSION;
	data               = (struct ctrl_desc_data_v1 *)tx.data;
	data->type         = IDC_CTRL;
	priv               = (struct cd_idc_ctrl_msg *)data->priv;
	priv->ctrl_type    = cpu_to_le64(IDC_CTRL_DBG);
	priv->dbg_msg.ops  = cpu_to_le64(ops);
	priv->dbg_msg.mode = cpu_to_le64(mode);
	priv->dbg_msg.val  = cpu_to_le64(val);

	ret = idc_ctrl_data_send(sbts, &tx, &rx);
	if (unlikely(ret || rx.sta)) {
		cn_dev_core_err(core, "idc ctrl msg send fail!");
		return -EFAULT;
	}
	data = (struct ctrl_desc_data_v1 *)rx.data;
	priv = (struct cd_idc_ctrl_msg *)data->priv;

	return le64_to_cpu(priv->dbg_msg.val);
}

/******** debug interface **********/

static void idc_proc_requestconfirm_set(
		struct cn_core_set *core,
		char *ops_val)
{
	struct idc_manager *manager;
	int ret;

	if (!ops_val) {
		IDC_DBG_OUT("Input Ops val is null");
		return;
	}
	/* set all card sta */
	if (!strncmp(ops_val, "all", 3)) {
		down_read(&g_mgrlist_rwsem);
		list_for_each_entry(manager,
				&idcmgr_list_head, mgr_list) {
			core = manager->core;
			ret = cn_sbts_idc_ctrl_mode_set(manager->sbts,
					_IDC_CTRL_REQUEST_CONFIRM,
					IDC_CTRL_SET, 1);
			cn_dev_core_info(core,
					"idc rc mode set ret %d", ret);
		}
		up_read(&g_mgrlist_rwsem);
	} else if (!strncmp(ops_val, "off_all", 7)) {
		down_read(&g_mgrlist_rwsem);
		list_for_each_entry(manager,
				&idcmgr_list_head, mgr_list) {
			core = manager->core;
			ret = cn_sbts_idc_ctrl_mode_set(manager->sbts,
					_IDC_CTRL_REQUEST_CONFIRM,
					IDC_CTRL_SET, 0);
			cn_dev_core_info(core,
					"idc rc mode set ret %d", ret);
		}
		up_read(&g_mgrlist_rwsem);
	} else if (!strncmp(ops_val, "on", 2)) {
		ret = cn_sbts_idc_ctrl_mode_set(
				core->sbts_set,
				_IDC_CTRL_REQUEST_CONFIRM,
				IDC_CTRL_SET, 1);
		cn_dev_core_info(core, "idc rc mode on ret %d", ret);
	} else {
		/* default is off */
		ret = cn_sbts_idc_ctrl_mode_set(
				core->sbts_set,
				_IDC_CTRL_REQUEST_CONFIRM,
				IDC_CTRL_SET, 0);
		cn_dev_core_info(core, "idc rc mode off ret %d", ret);
	}
}

static void idc_proc_debug_val_read(
		struct cn_core_set *core,
		u64 ops, u64 mode)
{
	int ret;

	ret = cn_sbts_idc_ctrl_mode_set(
				core->sbts_set,
				ops,
				mode, 0);

	cn_dev_core_info(core, "idc dbg ctrl read ret %d", ret);
}

/* set debug ops values */
static void idc_proc_debug_val_set(
		struct cn_core_set *core,
		u64 ops,
		char *ops_val)
{
	int ret;
	int timeout = 0;

	if (!ops_val) {
		IDC_DBG_OUT("Input Ops val is null");
		return;
	}

	if (kstrtoint(ops_val, 0, &timeout)) {
		IDC_DBG_OUT("Convert time val fail");
		return;
	}

	ret = cn_sbts_idc_ctrl_mode_set(
				core->sbts_set,
				ops,
				IDC_CTRL_SET, timeout);

	cn_dev_core_info(core,
			"idc debug mode set ret %d",
			ret);
}
static void idc_proc_dev_tx_msg_dbg_set(
		struct cn_core_set *core,
		char *ops_val)
{
	struct idc_manager *manager;
	int ret;

	if (!ops_val) {
		IDC_DBG_OUT("Input Ops val is null");
		return;
	}
	/* set all card sta */
	if (!strncmp(ops_val, "all", 3)) {
		down_read(&g_mgrlist_rwsem);
		list_for_each_entry(manager,
				&idcmgr_list_head, mgr_list) {
			core = manager->core;
			ret = cn_sbts_idc_ctrl_mode_set(manager->sbts,
					_IDC_CTRL_DBG_TX_MSG_SAVE,
					IDC_CTRL_SET, 1);
			cn_dev_core_info(core,
					"dev tx dbg mode set ret %d", ret);
		}
		up_read(&g_mgrlist_rwsem);
	} else if (!strncmp(ops_val, "off_all", 7)) {
		down_read(&g_mgrlist_rwsem);
		list_for_each_entry(manager,
				&idcmgr_list_head, mgr_list) {
			core = manager->core;
			ret = cn_sbts_idc_ctrl_mode_set(manager->sbts,
					_IDC_CTRL_DBG_TX_MSG_SAVE,
					IDC_CTRL_SET, 0);
			cn_dev_core_info(core,
					"dev tx dbg mode set ret %d", ret);
		}
		up_read(&g_mgrlist_rwsem);
	} else if (!strncmp(ops_val, "on", 2)) {
		ret = cn_sbts_idc_ctrl_mode_set(
				core->sbts_set,
				_IDC_CTRL_DBG_TX_MSG_SAVE,
				IDC_CTRL_SET, 1);
		cn_dev_core_info(core, "dev tx dbg mode on ret %d", ret);
	} else {
		/* default is off */
		ret = cn_sbts_idc_ctrl_mode_set(
				core->sbts_set,
				_IDC_CTRL_DBG_TX_MSG_SAVE,
				IDC_CTRL_SET, 0);
		cn_dev_core_info(core, "dev tx dbg mode off ret %d", ret);
	}
}

static void idc_proc_debug_rx_msg_set(
		struct cn_core_set *core,
		char *ops_val)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct idc_manager *manager = sbts->idc_manager;

	if (!ops_val) {
		IDC_DBG_OUT("Input Ops val is null");
		return;
	}

	if (!strncmp(ops_val, "on", 2))
		manager->save_rx_flag = 1;
	else
		manager->save_rx_flag = 0;

	IDC_DBG_OUT("set save rx msg flag %d", manager->save_rx_flag);
}

static void idc_proc_debug_rx_msg_out(
		struct cn_core_set *core,
		char *ops_val)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct idc_manager *manager = sbts->idc_manager;
	struct td_idc_rx_msg *pbuf;
	int prt_len = 0;
	int prt_index;

	if (!manager->rx_msg_dbg) {
		IDC_DBG_OUT("rx buf is null");
		return;
	}

	if (!ops_val) {
		IDC_DBG_OUT("Input Ops val is null");
		return;
	}

	if (!strncmp(ops_val, "all", 3)) {
		prt_len = IDC_DBG_MSG_MAX;
		prt_index = IDC_DBG_MSG_MAX - 1;
		goto start_prt;
	}

	if (kstrtoint(ops_val, 0, &prt_len)) {
		IDC_DBG_OUT("input val invalid %s", ops_val);
		return;
	}
	prt_len = clamp_t(int, prt_len, 0, IDC_DBG_MSG_MAX);
	prt_index = READ_ONCE(manager->rx_msg_idx) - 1;
start_prt:
	IDC_DBG_OUT("Begin prt %d rx msg from %d >>>>>>",
				prt_len, prt_index);
	while (prt_len--) {
		if (prt_index < 0)
			prt_index = IDC_DBG_MSG_MAX - 1;
		pbuf = manager->rx_msg_dbg + prt_index;
		IDC_DBG_OUT(
			"[%04d] mtype:%llu ka:%llx ki:%llu ti:%llu ttype:%llu flag:%llu val:%llu",
				prt_index,
				pbuf->msg_type,
				pbuf->kern_addr,
				pbuf->kern_index,
				pbuf->task_index,
				pbuf->task_type,
				pbuf->task_flag,
				pbuf->req_val);
		prt_index--;
	}
	IDC_DBG_OUT("Finish <<<<<<<<<<<<");

}


static void idc_proc_debug_emode_timeout_set(
		struct cn_core_set *core,
		char *ops_val)
{
	int timeout = 0;

	if (!ops_val) {
		IDC_DBG_OUT("Input Ops val is null");
		return;
	}

	if (kstrtoint(ops_val, 0, &timeout)) {
		IDC_DBG_OUT("Convert time val fail");
		return;
	}

	idc_swmode_set_timeout(timeout);
}

static void idc_proc_debug_dbg_mode_set(
		struct cn_core_set *core,
		char *ops_val)
{
	u32 new_mode = 0;

	if (!ops_val) {
		IDC_DBG_OUT("Input Ops val is null");
		return;
	}

	if (kstrtou32(ops_val, 0, &new_mode)) {
		IDC_DBG_OUT("Convert mode val fail");
		return;
	}

	IDC_DBG_OUT("set ops mode to %x", new_mode);

	g_mode_support_dbg = new_mode;
}

static void
idc_proc_debug_kaddr_info_out(
		struct cn_core_set *core,
		char *ops_val)
{
	struct sbts_idc_kaddr_info *info, *tmp;
	int i;
	int target_index = 0;
	int is_all = 0;

	if (!ops_val) {
		IDC_DBG_OUT("Input Ops val is null");
		return;
	}

	if (!strncmp(ops_val, "all", 3)) {
		is_all = 1;
		goto start_prt;
	}

	if (kstrtoint(ops_val, 0, &target_index)) {
		IDC_DBG_OUT("input val invalid %s", ops_val);
		return;
	}
start_prt:

	down_read(&g_set_rwsem);
	sbts_set_for_each_entry_safe(info, tmp,
			&idc_kaddr_container, iter) {
		if ((info->index != target_index) && !is_all)
			continue;

		IDC_DBG_OUT("kinfo[%llu] ka:%lx val:%llu seq:%llu is_d:%d",
				info->index, info->kern_addr,
				*(u64 *)info->kern_addr, info->send_ticket,
				info->is_destroy);
		IDC_DBG_OUT("      mode:%llx tgid:%d user:%llx uaddr:%llx",
				info->mode_flag,
				info->tgid, info->user, info->user_addr);

		info->mode_ops->dump_info(info);

		for (i = 0; i < MAX_FUNCTION_NUM; i++) {
			if (info->task_cnt[i])
				IDC_DBG_OUT("        user on card[%d] t:%llu", i, info->task_cnt[i]);
		}
		for (i = 0; i < MAX_FUNCTION_NUM; i++) {
			if (info->msg_cnt[i])
				IDC_DBG_OUT("        msg to card[%d] t:%llu", i, info->msg_cnt[i]);
		}
	}
	up_read(&g_set_rwsem);
}

void idc_proc_debug_set(
		struct cn_core_set *core,
		char *ops_type, char *ops_val)
{
	if (!ops_type) {
		IDC_DBG_OUT("Input Ops type is null");
		return;
	}

	/* device request need host send confirm msg to finish */
	if (!strncmp(ops_type, "requestconfirm", 14)) {
		idc_proc_requestconfirm_set(core, ops_val);
	} else if (!strncmp(ops_type, "comparetimeout", 14)) {
		idc_proc_debug_val_set(core, _IDC_CTRL_COMPARE_TIMEOUT,
				ops_val);
	} else if (!strncmp(ops_type, "requesttimeout", 14)) {
		idc_proc_debug_val_set(core, _IDC_CTRL_REQUEST_TIMEOUT,
				ops_val);
	} else if (!strncmp(ops_type, "tx_msg_dbg", 10)) {
		idc_proc_dev_tx_msg_dbg_set(core, ops_val);
	} else if (!strncmp(ops_type, "save_rx_msg", 11)) {
		idc_proc_debug_rx_msg_set(core, ops_val);
	} else if (!strncmp(ops_type, "emode_read_timeout", 18)) {
		idc_proc_debug_emode_timeout_set(core, ops_val);
	} else if (!strncmp(ops_type, "dbg_mode", 8)) {
		idc_proc_debug_dbg_mode_set(core, ops_val);
	} else {
		IDC_DBG_OUT("ops type:<<%s>> not support", ops_type);
	}
}

void idc_proc_debug_read(
		struct cn_core_set *core,
		char *ops_type, char *ops_val)
{
	if (!ops_type) {
		IDC_DBG_OUT("Input Ops type is null");
		return;
	}

	/* device request need host send confirm msg to finish */
	if (!strncmp(ops_type, "requestconfirm", 14)) {
		idc_proc_debug_val_read(core,
				_IDC_CTRL_REQUEST_CONFIRM,
				IDC_CTRL_READ);
	} else if (!strncmp(ops_type, "comparetimeout", 14)) {
		idc_proc_debug_val_read(core,
				_IDC_CTRL_COMPARE_TIMEOUT,
				IDC_CTRL_READ);
	} else if (!strncmp(ops_type, "requesttimeout", 14)) {
		idc_proc_debug_val_read(core,
				_IDC_CTRL_REQUEST_TIMEOUT,
				IDC_CTRL_READ);
	} else if (!strncmp(ops_type, "rx_msg", 6)) {
		idc_proc_debug_rx_msg_out(core, ops_val);
	} else if (!strncmp(ops_type, "kaddr_info", 10)) {
		idc_proc_debug_kaddr_info_out(core, ops_val);
	} else {
		IDC_DBG_OUT("ops type:<<%s>> not support", ops_type);
	}
}

int cn_sbts_idc_debug_show(struct cn_core_set *core, struct seq_file *m)
{
	struct sbts_set *sbts_set = NULL;
	struct idc_manager *manager = NULL;
	int ret = 0;

	if (!idc_basic_init) {
		cn_dev_info("idc is disabled");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_info("core is null");
		return -EINVAL;
	}
	sbts_set = core->sbts_set;
	if (IS_ERR_OR_NULL(sbts_set)) {
		cn_dev_core_info(core, "sbts set is null");
		return -EINVAL;
	}
	manager = sbts_set->idc_manager;
	if (IS_ERR_OR_NULL(manager)) {
		cn_dev_core_info(core, "manager is null");
		return -EINVAL;
	}
	cn_dev_core_info(core, "idc debug show");

	ret = cn_sbts_idc_ctrl_mode_set(sbts_set,
			 _IDC_CTRL_REQUEST_CONFIRM,
			 IDC_CTRL_READ, 0);

	seq_printf(m, "card index:   %d\n", manager->c_idx);
	seq_printf(m, "work sta:     %d\n", manager->worker_status);
	seq_printf(m, "kaddr_num:    %d\n", g_kaddr_num);
	seq_printf(m, "seq_num:      %llu\n", g_task_seq);
	seq_printf(m, "rc_mode:      %d\n", ret);
	seq_printf(m, "read_timeout: %d\n", idc_swmode_get_timeout());
	seq_printf(m, "rx_msg_save:  %d\n", manager->save_rx_flag);
	seq_printf(m, "mode_support: %#x\n", g_mode_check);
	seq_printf(m, "global_mode:  %#x\n", g_mode_support);
	seq_printf(m, "dbg_support:  %#x\n", g_mode_support_dbg);
	seq_printf(m, "sw_basic:     %llu\n", g_dbg_sw_basic);
	seq_printf(m, "sw_acc  :     %llu\n", g_dbg_sw_acc);
	seq_printf(m, "to_basic:     %llu\n\n", g_dbg_sw_acc_to_basic);

	seq_printf(m, "%s\n", llist_empty(&manager->st_head) ?
			"llist empty" : "llist not empty");

	seq_puts(m, ">>>>IDC DEBUG Commands<<<<\n");
	seq_puts(m, "echo set#requestconfirm#on/off/all/off_all\n");
	seq_puts(m, "echo set#comparetimeout#timein_secs\n");
	seq_puts(m, "echo set#requesttimeout#timein_secs\n");
	seq_puts(m, "echo set#tx_msg_dbg#on/off/all/off_all\n");
	seq_puts(m, "echo set#save_rx_msg#on/off\n");
	seq_puts(m, "echo set#dbg_mode#0x..\n");
	seq_puts(m, "echo read#requestconfirm\n");
	seq_puts(m, "echo read#comparetimeout\n");
	seq_puts(m, "echo read#requesttimeout\n");
	seq_puts(m, "echo read#rx_msg#'msg_cnt'\n");
	seq_puts(m, "echo read#kaddr_info#'index'\n");

	return 0;
}

#define IDC_DBG_STR_LEN 200
void cn_sbts_idc_debug_write(
		struct cn_core_set *core,
		const char __user *user_buf,
		size_t count)
{
	struct sbts_set *sbts_set = NULL;
	struct idc_manager *manager = NULL;
	char cmd[IDC_DBG_STR_LEN];
	size_t cmd_size = min_t(size_t, count, IDC_DBG_STR_LEN);
	char *sep = cmd;
	char *ops_name, *ops_type, *ops_val;

	if (!idc_basic_init) {
		cn_dev_info("idc is disabled");
		return;
	}

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_info("core is null");
		return;
	}
	sbts_set = core->sbts_set;
	if (IS_ERR_OR_NULL(sbts_set)) {
		cn_dev_core_info(core, "sbts set is null");
		return;
	}
	manager = sbts_set->idc_manager;
	if (IS_ERR_OR_NULL(manager)) {
		cn_dev_core_info(core, "manager is null");
		return;
	}
	cn_dev_core_info(core, "idc debug write");

	memset(cmd, 0, IDC_DBG_STR_LEN);
	if (copy_from_user(cmd, user_buf, cmd_size))
		return;

	if (count < 4) {
		IDC_DBG_OUT("User input str Too short : [%s]", cmd);
		return;
	}
	cmd[cmd_size - 1] = 0;

	IDC_DBG_OUT("USER INPUT: [%s]", cmd);

	ops_name = strsep(&sep, "#");
	ops_type = strsep(&sep, "#");
	ops_val = sep;

	IDC_DBG_OUT("ops name:<<%s>>  type:<<%s>>  val:<<%s>>\n",
			ops_name, ops_type, ops_val);

	if (mutex_lock_killable(&g_proc_dbg_lock))
		return;

	if (!strncmp(ops_name, "set", 3)) {
		idc_proc_debug_set(core, ops_type, ops_val);
	} else if (!strncmp(ops_name, "read", 4)) {
		idc_proc_debug_read(core, ops_type, ops_val);
	} else {
		IDC_DBG_OUT("ops name:<<%s>> not support", ops_name);
	}
	mutex_unlock(&g_proc_dbg_lock);
}
