#include <linux/signal.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/rwsem.h>
#include <linux/bitops.h>

#include "cndrv_core.h"
#include "cndrv_sbts.h"
#include "idc_internal.h"
#include "idc.h"
#include "cndrv_debug.h"


int idc_ctrl_data_send(
		struct sbts_set *sbts,
		struct comm_ctrl_desc *tx_desc,
		struct comm_ctrl_desc *rx_desc)
{
	struct sched_manager *sched_mgr = sbts->sched_manager;

	return sched_mgr->ioctl(sched_mgr, tx_desc, rx_desc,
			ANNOY_USER, sizeof(struct comm_ctrl_desc));
}

int __idc_request_ops(u64 *kern_addr, u64 flag, u64 val)
{
	int ret = 0;
	u64 result;

	switch (flag) {
	/* case _IDC_REQUEST_DEFAULT: */
	case _IDC_REQUEST_ADD:
		result = __sync_add_and_fetch(kern_addr, val);
		break;
	case _IDC_REQUEST_SET:
		result = __sync_lock_test_and_set(kern_addr, val);
		break;
	case _IDC_REQUEST_RESET:
		__sync_lock_release(kern_addr);
		break;
	default:
		cn_dev_err("invalid flag in compare ops");
		break;
	}

	return ret;
}

int __idc_compare_ops(u64 cur_val, u64 flag, u64 val)
{
	int ret = -1;

	switch (flag) {
	case _IDC_COMPARE_EQUAL:
		if (val == cur_val)
			ret = 0;
		break;
	case _IDC_COMPARE_LESS_EQUAL:
		if (val <= cur_val)
			ret = 0;
		break;
	case _IDC_COMPARE_LESS:
		if (val < cur_val)
			ret = 0;
		break;
	default:
		cn_dev_err("invalid flag in compare ops");
		ret = 0;
		break;
	}

	return ret;
}

struct idc_send_task *
idc_send_task_alloc(struct idc_manager *manager)
{
	__u32 index = 0;

retry:
	spin_lock(&manager->lock);
	index = find_first_zero_bit(manager->st_map,
				manager->st_num);
	if (unlikely(index >= manager->st_num)) {
		spin_unlock(&manager->lock);
		if (sbts_pause(manager->core, 5, 10)) {
			return NULL;
		}
		goto retry;
	}
	set_bit(index, manager->st_map);

	spin_unlock(&manager->lock);

	return (manager->st_base + index);
}

void idc_send_task_free(
		struct idc_manager *manager,
		struct idc_send_task *task)
{
	struct cn_core_set *core =
			(struct cn_core_set *)manager->core;
	__u32 index = 0;

	index = task - manager->st_base;
	if (index >= manager->st_num) {
		cn_dev_core_err(core,
				"input %llx addr out of range %llx %u",
				(u64)task, (u64)manager->st_base,
				manager->st_num);
		return;
	}

	if (!test_and_clear_bit(index, manager->st_map)) {
		cn_dev_core_err(core, "input task %llx already free",
				(u64)task);
	}
}

void __idc_prepare_send_task(
		struct sbts_idc_kaddr_info *info,
		u64 task_index, u64 idx_valid,
		enum idc_msg_type type)
{
	struct idc_manager *manager;
	struct idc_send_task *send_task;
	u64 msg_index = __sync_add_and_fetch(&info->send_ticket, 1);
	u64 task_req;

	down_read(&g_mgrlist_rwsem);
	list_for_each_entry(manager,
				&idcmgr_list_head, mgr_list) {
		task_req = __sync_fetch_and_add(
				&info->task_cnt[manager->c_idx], 0);
		if (!task_req)
			continue;

		send_task = idc_send_task_alloc(manager);
		if (!send_task) {
			cn_dev_core_err(manager->core, "alloc send buffer fail");
			continue;
		}
		__sync_fetch_and_add(&info->msg_cnt[manager->c_idx], 1);
		send_task->kern_addr = info->kern_addr;
		send_task->kern_index = info->index;
		send_task->msg_index = msg_index;
		send_task->new_val =
				__sync_fetch_and_add((u64 *)info->kern_addr, 0);
		send_task->task_index = task_index;
		send_task->idx_valid = idx_valid;
		send_task->type = type;
		send_task->task_req = task_req;

		llist_add(&send_task->l_node, &manager->st_head);
		wake_up_interruptible(&manager->idc_wait_head);
	}
	up_read(&g_mgrlist_rwsem);
}
