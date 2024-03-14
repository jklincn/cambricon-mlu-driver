#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/rbtree.h>
#include <linux/delay.h>

#include "cndrv_mm.h"
#include "cndrv_commu.h"
#include "cndrv_udvm.h"
#include "cndrv_debug.h"
#include "camb_mm.h"
#include "camb_mm_rpc.h"
#include "camb_mm_pgretire.h"
#include "camb_mm_tools.h"

/*internal func*/

/* mem timer handle func for async free*/
static enum hrtimer_restart camb_hrtimer_work(struct hrtimer *timer)
{
	struct cn_mm_set *mm_set = container_of(timer, struct cn_mm_set,
											hrtimer);

	spin_lock(&mm_set->work_sync_lock);
	if (!llist_empty(&mm_set->free_list)) {
		if (atomic_read(&mm_set->free_worker_state) == WORK_IDLE) {
			spin_unlock(&mm_set->work_sync_lock);
			/* to show that the timer is cold. */
			atomic_set(&mm_set->timer_hot, 0);
			queue_work(system_unbound_wq, &mm_set->free_worker);
		} else {
			spin_unlock(&mm_set->work_sync_lock);
			/* to insure that the timer is hot. */
			atomic_set(&mm_set->timer_hot, 1);
			hrtimer_forward_now(&mm_set->hrtimer, mm_set->time_delay);
			return HRTIMER_RESTART;
		}
	} else {
		spin_unlock(&mm_set->work_sync_lock);
		/* to show that the timer is cold. */
		atomic_set(&mm_set->timer_hot, 0);
	}

	return HRTIMER_NORESTART;
}

static void camb_free_list_rpc(struct cn_mm_set *mm_set,
							   struct mapinfo **pminfo_list,
							   int mem_cnt)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct ret_msg remsg;
	size_t dev_ret_len = sizeof(struct ret_msg);
	int ret = 0, j, pgretire_status = 0, retry_times = 0;
	struct free_mem_list * free_list;
	int list_len = sizeof(struct free_mem_list) + sizeof(struct free_frame)
		* (mem_cnt - 1);
	if (list_len > RPC_TRANS_MAX_LEN(core->support_ipcm)) {
		cn_dev_core_err(core, "mem free list len is large than commu limit");
		return;
	}

	free_list = cn_kzalloc(list_len, GFP_KERNEL);
	if (!free_list) {
		cn_dev_core_err(core, "kzalloc mem free transfer list space error!");
		return;
	}

	free_list->mem_cnt = mem_cnt;
	for(j = 0; j < mem_cnt; j++) {
		camb_free_ts_node_record(pminfo_list[j], FREE_TS_READY_CALLRPC);
		free_list->mem_list[j].tag = pminfo_list[j]->mem_meta.type;
		free_list->mem_list[j].device_addr =
			udvm_get_iova_from_addr(pminfo_list[j]->virt_addr);
	}
	memset(&remsg, 0x00, sizeof(struct ret_msg));

	/*do commu free*/
rpc_retry:
	pgretire_status = camb_set_pgretire_status(mm_set);
	free_list->extra_status = pgretire_status;
	ret = __mem_call_rpc(core, mm_set->mem_async_endpoint, "rpc_mem_free",
										  free_list, list_len, &remsg,
										  &dev_ret_len, sizeof(struct ret_msg));

	if (ret < 0 && ret != ERROR_RPC_RESET) {
		if (retry_times < MAX_FREE_RETRY_TIMES) {
			cn_dev_core_err(core, "delay_free_handle call cnrpc client"
							"free mem failed %d, try again", ret);
			usleep_range(100, 200);
			retry_times++;
			goto rpc_retry;
		} else {
			for(j = 0; j < mem_cnt; j++) {
				camb_add_node_free_failure_list(mm_set,
										   free_list->mem_list[j].device_addr,
										   &pminfo_list[j]->mem_meta,
										   pminfo_list[j]->mem_meta.size,
										   ret,
										   false);
			}
		}
	}
	/*ignore this ret val*/
	if (remsg.ret) {
		cn_dev_core_err(core, "rpc_mem_free error status is %d", remsg.ret);
	}

	camb_get_pgretire_result(mm_set, pgretire_status, remsg.extra_ret);

	cn_kfree(free_list);

	for(j = 0; j < mem_cnt; j++) {
		if (pminfo_list[j]) {
			camb_free_ts_node_record_and_saved(pminfo_list[j], FREE_TS_RPC_RETURNED);
			__sync_sub_and_fetch(&mm_set->phy_used_mem, (unsigned long)pminfo_list[j]->mem_meta.size);
			__sync_sub_and_fetch(&mm_set->vir_used_mem, (unsigned long)pminfo_list[j]->mem_meta.size);
			cn_kfree(pminfo_list[j]);
		}
	}
	__sync_lock_test_and_set(&mm_set->smmu_invalid_mask, 0xfffffffff);

	return;
}

/*external api*/

#ifndef llist_for_each_entry_safe
#define llist_for_each_entry_safe(pos, n, node, member)        \
	for (pos = llist_entry((node), typeof(*pos), member);   \
			member_address_is_nonnull(pos, member) &&       \
			(n = llist_entry(pos->member.next, typeof(*n), member), true);  \
			pos = n)
#endif

#ifndef member_address_is_nonnull
#define member_address_is_nonnull(ptr, member) \
	((uintptr_t)(ptr) + offsetof(typeof(*(ptr)), member) != 0)
#endif

static void camb_do_clear_free_list(struct cn_mm_set *mm_set,
									struct llist_node *first)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mapinfo *mtmp = NULL, *mpos = NULL;
	struct mapinfo **pminfo_list;
	int mem_cnt = 0;

	/*COMMU MAX LEN is 512*/
	pminfo_list = cn_kzalloc(sizeof(struct mapinfo *) *
							 FREE_LIST_MAX(core->support_ipcm),
							 GFP_KERNEL);
	if (!pminfo_list) {
		cn_dev_core_err(core, "kzalloc pminfo_list space error!");
		return;
	}

	llist_for_each_entry_safe(mpos, mtmp, first, free_node) {
		cn_dev_core_debug(core,"delay free pminfo free addr %llx, type %d ",
						  mpos->virt_addr, mpos->mem_meta.type);
		pminfo_list[mem_cnt++] = mpos;

		__sync_add_and_fetch(&mm_set->df_mem_size, mpos->mem_meta.size);
		__sync_add_and_fetch(&mm_set->df_mem_cnt, 1);

		if (mem_cnt == FREE_LIST_MAX(core->support_ipcm)) {
			camb_free_list_rpc(mm_set, pminfo_list, mem_cnt);
			mem_cnt = 0;

			__sync_lock_test_and_set(&mm_set->df_mem_size, 0);
			__sync_lock_test_and_set(&mm_set->df_mem_cnt, 0);
		}
	}

	if (mem_cnt) {
		camb_free_list_rpc(mm_set, pminfo_list, mem_cnt);

		__sync_lock_test_and_set(&mm_set->df_mem_size, 0);
		__sync_lock_test_and_set(&mm_set->df_mem_cnt, 0);
	}

	cn_kfree(pminfo_list);
	return;
}

/* delay free schedule handle function */
void camb_delay_free_handle(struct work_struct *work)
{
	struct cn_mm_set *mm_set = container_of(work, struct cn_mm_set,
											free_worker);
	struct llist_node *first = NULL;
	unsigned long flags;

	/*queue work on system_unbound_wq may cause mul works simultaneously in
	  different cpu core, so add mutex lock to prevent camb_clear_free_list func
	  non-reentrant*/
	spin_lock_irqsave(&mm_set->work_sync_lock, flags);

	if (!llist_empty(&mm_set->free_list) &&
		atomic_read(&mm_set->free_worker_state) == WORK_IDLE) {

		/*state = WORK_RUNNING*/
		atomic_set(&mm_set->free_worker_state, WORK_RUNNING);
		first = llist_del_all(&mm_set->free_list);
		atomic_set(&mm_set->free_mem_cnt, 0);
		spin_unlock_irqrestore(&mm_set->work_sync_lock, flags);

		camb_do_clear_free_list(mm_set, first);
		/*state = WORK_IDLE*/
		spin_lock_irqsave(&mm_set->work_sync_lock, flags);
		atomic_set(&mm_set->free_worker_state, WORK_IDLE);
		/*rpc_free_times inc means llist finished list cut and mem free for once*/
		atomic_inc(&mm_set->rpc_free_times);
		spin_unlock_irqrestore(&mm_set->work_sync_lock, flags);
	} else {
		spin_unlock_irqrestore(&mm_set->work_sync_lock, flags);
	}

	return;
}

void camb_delay_free_init(void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;

	/* create mem free delay worker*/
	atomic_set(&mm_set->free_mem_cnt, 0);
	INIT_WORK(&mm_set->free_worker, camb_delay_free_handle);

	init_llist_head(&mm_set->free_list);
	atomic_set(&mm_set->free_worker_state, WORK_IDLE);
	/*TODO: move to ......*/
	atomic_set(&mm_set->proc_set, 1);
	atomic_set(&mm_set->rpc_free_times, 0);
	spin_lock_init(&mm_set->work_sync_lock);

	switch(mm_set->devid) {
	case MLUID_CE3226_EDGE:
	case MLUID_PIGEON_EDGE:
	case MLUID_370_DEV:
	case MLUID_590_DEV:
		break;
	default:
		mm_set->time_delay = ktime_set(0, DELAY_FREE_TIME_THRESHOLD * 1000);
		hrtimer_init(&mm_set->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		mm_set->hrtimer.function = camb_hrtimer_work;
		atomic_set(&mm_set->timer_hot, 0);
		break;
	}
}

void camb_delay_free_exit(void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;

	switch(mm_set->devid) {
	case MLUID_CE3226_EDGE:
	case MLUID_PIGEON_EDGE:
	case MLUID_370_DEV:
	case MLUID_590_DEV:
		break;
	default:
		if (hrtimer_is_queued(&mm_set->hrtimer))
			hrtimer_cancel(&mm_set->hrtimer);
		break;
	}
}


