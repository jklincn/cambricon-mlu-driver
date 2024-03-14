#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#include "kprintf.h"
#include "cndrv_mm.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "unotify.h"
#include "cndrv_sbts.h"
#include "sbts.h"
#include "cndrv_hpq.h"
#include "queue.h"
#include "../core/cndrv_ioctl.h"

struct sbts_kprintf_set {
	struct sched_manager *sched_mgr;
	struct cn_core_set *core;
	struct sbts_set *sbts;

	void *worker;
};

/* recv 'struct comm_kprintf_desc' data from device */
struct kprintf_priv_msg {
	__le64 queue_id;
	__le64 current_kernel_seq;
};

/* data to user space in 'struct kprintf_to_user_msg' */
struct kprintf_usr_msg {
	u64 queue_id;
	u64 current_kernel_seq;
};

#define KP_MSG_FROM_DEV_MAX \
	((KPRINTF_DESC_SIZE * sizeof(__le64)) / sizeof(struct kprintf_priv_msg))

#define KP_MSG_TO_USR_MAX  10

struct kprintf_to_user_msg {
	u64 version;
	struct kprintf_usr_msg kfdata[KP_MSG_TO_USR_MAX];
	u32 kfdata_cnt;
};


/* call queue_get until success use dev_sid from priv_msg one by one
 * *read_idx will return caller the index of success priv_msg
 */
static struct queue *__kf_get_queue_from_data(
		struct queue_manager *queue_mgr,
		u64 *read_idx,
		u64 recv_msg_cnt,
		struct kprintf_priv_msg *priv)
{
	struct queue *queue = NULL;
	u64 idx = *read_idx;
	u64 dev_sid;

	while (idx < recv_msg_cnt) {
		dev_sid = le64_to_cpu(priv[idx].queue_id);
		queue = queue_get(queue_mgr, dev_sid,
				ANNOY_USER, 0);
		if (queue)
			break;
		idx++;
	}

	/* write idx back to the main loop */
	*read_idx = idx;
	return queue;
}

static inline void __kf_pack_usr_data(
		struct kprintf_to_user_msg *user_priv,
		u64 update_seq,
		u64 dev_sid)
{
	u32 cnt = user_priv->kfdata_cnt;

	user_priv->kfdata[cnt].current_kernel_seq =
			update_seq;
	user_priv->kfdata[cnt].queue_id = dev_sid;
	user_priv->kfdata_cnt++;
}

#define KF_SEND_USR_TRY   10
static void __kf_send_to_usr(
		struct sbts_set *sbts,
		struct queue *queue,
		u64 *ptr)
{
	int loop = KF_SEND_USR_TRY;
	struct cn_core_set *core = sbts->core;

	while (loop--) {
		if (!sbts_unotify_send(sbts, queue, PRINTF_PROCESS, ptr,
				sizeof(struct kprintf_to_user_msg)))
			return;

		if (sbts_pause(core, 10, 100))
			break;
	}

	cn_dev_warn_limit("[%s] signal user space fail %#llx",
			core->core_name, (u64)queue);
}

static inline void signal_user_kprintf(
		struct sbts_set *sbts, struct comm_kprintf_desc *rx_desc)
{
	struct cn_core_set *core = sbts->core;
	struct queue_manager *queue_mgr = sbts->queue_manager;
	struct queue *queue = NULL;
	struct queue *first_queue = NULL;
	struct kprintf_priv_msg *priv =
			(struct kprintf_priv_msg *)rx_desc->data;
	struct kprintf_to_user_msg user_priv = {0};
	u64 read_idx = 0;
	u64 recv_msg_cnt = le64_to_cpu(rx_desc->kfdata_cnt);
	u64 first_user = 0;
	u64 current_user = 0;

	if (!recv_msg_cnt)
		return;

	if (recv_msg_cnt > KP_MSG_FROM_DEV_MAX) {
		cn_dev_core_warn(core, "recv cnt: %llu too big.", recv_msg_cnt);
		recv_msg_cnt = KP_MSG_FROM_DEV_MAX;
	}

	/* loop read first valid queue out */
	queue = __kf_get_queue_from_data(queue_mgr, &read_idx,
					recv_msg_cnt, priv);
	if (!queue)
		return;

	user_priv.version = 0;
	user_priv.kfdata_cnt = 0;
	first_user = queue->user;
	first_queue = queue;
	do {
		__kf_pack_usr_data(&user_priv,
				le64_to_cpu(priv[read_idx++].current_kernel_seq),
				queue->dev_sid);

		/* try get next queue */
		queue = __kf_get_queue_from_data(queue_mgr, &read_idx,
					recv_msg_cnt, priv);
		/* if return is NULL means that the msg is end */
		if (!queue)
			break;
		current_user = queue->user;

		/* send buffer is full, */
		/* or user diff, send old data to last user */
		if ((user_priv.kfdata_cnt >= KP_MSG_TO_USR_MAX) ||
				(first_user != current_user)) {
			__kf_send_to_usr(sbts, first_queue, (u64 *)&user_priv);
			user_priv.kfdata_cnt = 0;

			queue_put(queue_mgr, first_queue);
			first_user = current_user;
			first_queue = queue;
		}
		if (user_priv.kfdata_cnt)
			queue_put(queue_mgr, queue);

	} while (read_idx < recv_msg_cnt);

	/* check and send last data */
	if (user_priv.kfdata_cnt) {
		__kf_send_to_usr(sbts, first_queue, (u64 *)&user_priv);
		queue_put(queue_mgr, first_queue);
	}
}

void sbts_kprintf_wait_work(
		struct cn_core_set *core,
		void *data,
		void *rx_msg,
		int rx_size)
{
	signal_user_kprintf((struct sbts_set *)data,
			(struct comm_kprintf_desc *)rx_msg);
}

int sbts_kprintf_init(struct sbts_set *sbts_set)
{
	int ret = 0;
	struct sbts_kprintf_set *kprintf_set = NULL;
	struct cn_core_set *core = sbts_set->core;

	kprintf_set = cn_numa_aware_kzalloc(core, sizeof(struct sbts_kprintf_set), GFP_KERNEL);
	if (!kprintf_set) {
		cn_dev_core_err(core, "malloc kprintf set mem failed");
		return -ENOMEM;
	}
	kprintf_set->core = core;
	kprintf_set->sbts = sbts_set;
	kprintf_set->sched_mgr = sbts_set->sched_manager;

	kprintf_set->worker = commu_wait_work_run(
			core, "sbts_kpr",
			sbts_set->sched_manager->kprintf_ep,
			sbts_set, sbts_kprintf_wait_work);
	if (!kprintf_set->worker) {
		cn_dev_core_err(core, "create thread failed");
		ret = -EINVAL;
		goto worker_err;
	}

	sbts_set->kprintf_set = kprintf_set;
	return 0;
worker_err:
	cn_kfree(kprintf_set);
	return ret;
}
void sbts_kprintf_exit(struct sbts_kprintf_set *kprintf_set)
{
	struct sbts_set *sbts_set = NULL;

	if (unlikely(!kprintf_set)) {
		cn_dev_err("kprintf set is null!");
		return;
	}
	sbts_set = kprintf_set->sbts;

	commu_wait_work_stop(sbts_set->core, kprintf_set->worker);
	cn_kfree(kprintf_set);
	sbts_set->kprintf_set = NULL;
}

int cn_kprintf_set(struct cn_core_set *core)
{
	int ret = 0;
	u64 payload_size = 0;
	struct comm_ctrl_desc tx_desc = { 0 };
	struct comm_ctrl_desc rx_desc = { 0 };
	struct sbts_set *sbts;
	struct sched_manager *sched_mgr = NULL;
	struct sbts_kprintf_set *kprintf_set = NULL;
	struct ctrl_desc_data_v1 *data = NULL;

	sbts = (struct sbts_set *)core->sbts_set;
	if (sbts == NULL) {
		cn_dev_core_debug(core, "sbts_set is null!");
		return ret;
	}
	kprintf_set = sbts->kprintf_set;
	if (kprintf_set == NULL) {
		cn_dev_core_debug(core, "kprintf_set is null!");
		return ret;
	}
	sched_mgr = kprintf_set->sched_mgr;

	data = (struct ctrl_desc_data_v1 *)tx_desc.data;
	tx_desc.version = SBTS_VERSION;
	data->type = KPRINTF_SET;
	data->priv[0] = core->card_kprintf_timer;
	payload_size = sizeof(struct comm_ctrl_desc);

	ret = sched_mgr->ioctl(sched_mgr, &tx_desc, &rx_desc, ANNOY_USER,
			payload_size);
	if (unlikely(ret || rx_desc.sta)) {
		cn_dev_core_err(core, "sbts ioctl failed:this version don't support set trigger timer!");
		return -EFAULT;
	}

	return ret;
}
