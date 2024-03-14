/*
 * sbts/queue.c
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
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/ptrace.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/bitops.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 11, 0))
#include <linux/sched.h>
#else
#include <linux/sched/mm.h>
#endif
#include <linux/seq_file.h>
#include <linux/ctype.h>
#include <linux/bitmap.h>
#include <asm/io.h>
#include "../core/cndrv_ioctl.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_hpq.h"
#include "sbts.h"
#include "hostfunc.h"
#include "queue.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "unotify.h"
#include "core_dump.h"
#include "monitor/time/cndrv_time.h"

static u64 g_queue_global_id = 1;
static u64 g_queue_ack_global_id = 1;

struct queue *__queue_validate(struct queue_manager *queue_mgr, u64 devsid)
{
	struct queue *queue_item = NULL;
	struct queue *tmp = NULL;
	struct cn_core_set *core = queue_mgr->core;

	list_for_each_entry_safe(queue_item, tmp, &queue_mgr->head, head) {
		if (queue_item->dev_sid == devsid) {
			cn_dev_core_debug(core, "find queue dsid: %#llx", devsid);
			return queue_item;
		}
	}

	return NULL;
}

#define RECORD_FUNC(name, bucket_order, width_order)			\
static inline void							\
record_##name(struct queue_manager *queue_mgr, u64 cnt) 		\
{									\
	u64 bucket = cnt;						\
	int valid_max = (1 << (bucket_order)) - 1;			\
									\
	if (!queue_mgr->record_en) {					\
		return;							\
	}								\
									\
	__sync_fetch_and_add(&queue_mgr->name##_total_cnt, cnt);	\
	bucket >>= (width_order);					\
	if (bucket > valid_max) {					\
		bucket = valid_max;					\
	}								\
									\
	__sync_fetch_and_add(						\
			&queue_mgr->name##_bucket[bucket].bucket, 1);	\
}

QUEUE_RECORD_LIST(RECORD_FUNC);

static void
format_record_show(struct seq_file *m, const char *name,
		struct sbts_bucket *buckets, unsigned int bucket_num,
		unsigned int width, u64 total_cnt)
{
	int i;

	if (!bucket_num) {
		return;
	}

	seq_printf(m, "[record event] %15s\n", name);
	seq_printf(m, "total count %lld\n", total_cnt);
	for (i = 0; i < bucket_num - 1; ++i) {
		seq_printf(m, "[%-d, %d) \t", i * width, (i + 1) * width);
	}

	seq_printf(m, "[%-d, inf) \n", i * width);
	for (i = 0; i < bucket_num; ++i) {
		seq_printf(m, "%-lld \t\t",
				(unsigned long long)buckets[i].bucket);
	}

	seq_printf(m, "\n");
}

void cn_queue_record_show(struct seq_file *m, struct cn_core_set *core)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct queue_manager *queue_mgr;

	if (unlikely(!sbts)) {
		return;
	}

	queue_mgr = sbts->queue_manager;

	seq_printf(m, "queue record %s\n", queue_mgr->record_en ? "on" : "off");

#define RECORD_SHOW(name, bo, wo) \
	format_record_show(m, #name, queue_mgr->name##_bucket, \
			1 << (bo), 1 << (wo), queue_mgr->name##_total_cnt);
	QUEUE_RECORD_LIST(RECORD_SHOW);
#undef RECORD_SHOW
}

static void queue_record_reset(struct queue_manager *manager)
{
#define RECORD_CLEAR(name, border, worder) \
	memset(manager->name##_bucket, 0, \
			sizeof(struct sbts_bucket) * (1 << (border))); \
	manager->name##_total_cnt = 0;
	QUEUE_RECORD_LIST(RECORD_CLEAR);
#undef RECORD_CLEAR
}

static int set_queue_record(struct queue_manager *queue_mgr, unsigned int on)
{
	unsigned int old = queue_mgr->record_en;
	unsigned int new = !!on;

	return !__sync_bool_compare_and_swap(&queue_mgr->record_en, old, new);
}

static int queue_record_on(struct sbts_set *sbts)
{
	return set_queue_record(sbts->queue_manager, 1);
}

static int queue_record_off(struct sbts_set *sbts)
{
	return set_queue_record(sbts->queue_manager, 0);
}

static int queue_record_clear(struct sbts_set *sbts)
{
	queue_record_reset(sbts->queue_manager);
	return 0;
}

#define QR_CMD_MAX_SIZE (128U)
static const struct queue_record_cmd {
	const char name[QR_CMD_MAX_SIZE + 1];
	int (*op)(struct sbts_set *);
} queue_record_cmd_list [] = {
	{.name = "on", .op = queue_record_on },
	{.name = "off", .op = queue_record_off },
	{.name = "clear", .op = queue_record_clear },
};

#define QUEUE_RECORD_CMD_NUM \
	(sizeof(queue_record_cmd_list) / sizeof(struct queue_record_cmd))

int cn_queue_record_cmd(struct cn_core_set *core,
		const char __user *user_buf, size_t count)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	char buf[QR_CMD_MAX_SIZE + 1];
	int cnt = (count > QR_CMD_MAX_SIZE ? QR_CMD_MAX_SIZE : count);
	int i;
	int ret = 0;
	const struct queue_record_cmd *cmd;

	if (unlikely(!sbts)) {
		return -EINVAL;
	}

	if (copy_from_user(buf, user_buf, cnt)) {
		return -EFAULT;
	}

	buf[cnt] = 0;
	for (i = cnt - 1; i > 0 && isspace(buf[i]); i--) {
		buf[i] = 0;
	}

	for (i = 0; i < QUEUE_RECORD_CMD_NUM; ++i) {
		cmd = &queue_record_cmd_list[i];
		if (!strcmp(cmd->name, buf)) {
			ret = cmd->op(sbts);
			cn_dev_core_info(core, "set %s %s", buf,
					ret ? "failed" : "success");
			return 0;
		}

	}

	cn_dev_core_err(core, "unknown command");
	return 0;
}
#undef QR_CMD_MAX_SIZE

int
cn_query_queue(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	int ret = 0;
	struct queue *queue = NULL;
	struct sbts_query_queue param;
	struct hpq_task_ack_desc ack_desc = {0};
	struct queue_manager *queue_mgr = sbts->queue_manager;
	struct cn_core_set *core = sbts->core;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
					struct sbts_query_queue))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	queue = queue_get(sbts->queue_manager, param.hqueue, user, 1);
	if (!queue) {
		cn_dev_core_err(core, "queue_dsid(%#llx) is invalid", param.hqueue);
		return -CN_QUEUE_ERROR_QUEUE_INVALID;
	}

	ret = queue_get_ack_sta(queue, &ack_desc);
	if (ret) {
		cn_dev_core_err(core, "queue(%px) sid %#016llx get ack status fail!", queue, queue->dev_sid);

		ret = -CN_QUEUE_ERROR_QUEUE_INVALID;
		goto out;
	}

	if (ack_desc.sta) {
		if (__sync_bool_compare_and_swap(&queue->sta,
					QUEUE_NORMAL, QUEUE_EXCEPTION)) {
			cn_dev_core_err(core, "queue dsid %#016llx ticket:%llu seq:%llu sta:%llu set exception",
					queue->dev_sid, queue->task_ticket, ack_desc.seq_num, ack_desc.sta);
		}
		ret = queue_ack_sta_parse(core, queue, ack_desc);
	} else {
		if (ack_desc.seq_num != READ_ONCE(queue->task_ticket)) {
			/* cndrv need this ret val as positive number*/
			ret = CN_SBTS_RESOURCE_NOT_READY;
		} else {
			ret = 0;
		}
	}

out:
	queue_put(queue_mgr, queue);

	return ret;
}

/* ret > 0 && ack->sta == 0  success */
int queue_ack_read_ack_data(struct queue_ack_s *ack_info,
		struct hpq_task_ack_desc *ack)
{
	return hpas_read(&ack_info->ack, ack);
}

/* get dev access seq addr
 * the core is current address device
 * the req_core is the device which the request from
 * return *addr is the queue seq_num addr.
 * */
int queue_ack_get_seq_host_iova(
		struct cn_core_set *req_core,
		struct queue_ack_s *ack_info, u64 *addr)
{
	struct queue_manager *queue_manager = ack_info->queue_manager;
	struct cn_core_set *core = queue_manager->core;
	u64 iova;
	int ret;

	if (likely(ack_info->ret_host_iova[req_core->idx]))
		goto out;

	ret = sbts_shm_get_host_iova(core, req_core, queue_manager->shm_mgr,
			ack_info->ret_dev_iova, &iova);
	if (ret) {
		cn_dev_core_err(core, "get host iova for card%d failed %d", req_core->idx, ret);
		return ret;
	}
	ack_info->ret_host_iova[req_core->idx] = iova;

	cn_dev_core_debug(core, "get iova %llx for dev %d", ack_info->ret_host_iova[req_core->idx], req_core->idx);
out:
	*addr = ack_info->ret_host_iova[req_core->idx] + HPAS_STRUCT_USE_SIZE;

	return 0;
}

/* must get queue handle first or already used ack_get before
 * so no need to use lock or check ack status */
int queue_ack_get(struct queue_ack_s *ack_info)
{
	if (!kref_get_unless_zero(&ack_info->ref_cnt)) {
		cn_dev_warn("ack info seq %#llx cnt is invalid", ack_info->seq);
		BUG_ON(1);
	}
	return 0;
}

void queue_ack_release(struct kref *kref)
{

}
/* must call queue_ack_get before */
void queue_ack_put(struct queue_ack_s *ack_info)
{
	struct queue_manager *queue_manager = ack_info->queue_manager;

	if (kref_put(&ack_info->ref_cnt, queue_ack_release)) {
		if (ack_info->addr_valid == true) {
			sbts_shm_free(queue_manager->shm_mgr, ack_info->ret_dev_iova);
		}
		cn_kfree(ack_info);
	}
}

/* call when queue create */
static int __queue_ack_create(struct queue_manager *queue_manager,
		struct queue *queue)
{
	int ret = 0;
	struct cn_core_set *core = queue_manager->core;
	struct queue_ack_s *queue_ack;
	host_addr_t host_vaddr;
	dev_addr_t dev_vaddr;

	queue_ack = cn_numa_aware_kzalloc(core, sizeof(struct queue_ack_s), GFP_KERNEL);
	if (!queue_ack) {
		cn_dev_core_err(core, "alloc memory for queue ack  failed");
		return -ENOMEM;
	}

	ret = sbts_shm_alloc(queue_manager->shm_mgr, core,
			&host_vaddr, &dev_vaddr);
	if (ret) {
		cn_dev_core_err(core, "alloc queue ret shared memory failed");
		ret = -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		goto shm_alloc_fail;
	}
	cn_dev_core_debug(core, "host ret vaddr :0x%lx, paddr :0x%llx",
			host_vaddr, dev_vaddr);

	queue_ack->queue_manager = queue_manager;
	queue_ack->seq = __sync_fetch_and_add(&g_queue_ack_global_id, 1);

	kref_init(&queue_ack->ref_cnt);
	queue_ack->addr_valid = true;
	queue_ack->ret_host_vaddr = host_vaddr;
	queue_ack->ret_dev_iova  = dev_vaddr;
	memset(queue_ack->ret_host_iova, 0, sizeof(u64)*MAX_FUNCTION_NUM);
	hpas_init(&queue_ack->ack, (struct hpq_queue_ack_as *) host_vaddr);

	queue->ack_info = queue_ack;
	return 0;

shm_alloc_fail:
	cn_kfree(queue_ack);

	return ret;
}

/* call when queue destroy env */
static void __queue_ack_free(struct queue_manager *queue_manager,
		struct queue_ack_s *ack_info)
{
	if (queue_manager->driver_unload_flag) {
		/* if current in unload flag(which we really care is heartbeat reset)
		 * we need set shm invalid or just release it, because ack_info may get by others
		 * and the ack_info handle cant be free now. */
		ack_info->addr_valid = false;

		sbts_shm_free(queue_manager->shm_mgr, ack_info->ret_dev_iova);
	}

	queue_ack_put(ack_info);
}

static int create_queue_env(struct queue_manager *queue_manager,
		struct queue **ppqueue,
		u64 user, struct sbts_create_queue *pparam)
{
	int ret = 0;
	struct queue *queue = NULL;
	struct cn_core_set *core = queue_manager->core;
	struct sbts_set *sbts = core->sbts_set;

	if (__sync_add_and_fetch(&queue_manager->count, 1) > sbts->max_queue) {
		cn_dev_core_err(core, "the number of queues arrives the maximum(%u)",
				sbts->max_queue);
		ret = -CN_QUEUE_ERROR_NO_RESOURCE;
		goto err;
	}

	queue = cn_numa_aware_kzalloc(core, sizeof(struct queue), GFP_KERNEL);
	if (!queue) {
		cn_dev_core_err(core, "create queue hqp failed");
		ret = -ENOMEM;
		goto err;
	}

	ret = __queue_ack_create(queue_manager, queue);
	if (ret) {
		cn_dev_core_err(core, "alloc queue ret shared memory failed");
		goto ret_share_mem_err;
	}

	/* init core dump info */
	queue->dump_info = core_dump_info_init(core->sbts_set, pparam);
	if (!queue->dump_info) {
		cn_dev_core_err(core, "core dump info init failed!");
		ret = -ENOMEM;
		goto dump_info_init_err;
	}

	queue->user               = user;
	if (user == 0) {
		queue->user_id = 0;
	} else {
		queue->user_id = ((struct fp_priv_data *)((struct file *)user)
						  ->private_data)
						 ->fp_id;
	}
	queue->sync_flags         = pparam->flags;
	queue->priority           = pparam->priority;
	queue->task_ticket        = 0;
	queue->remote_ticket      = 0;
	queue->core               = core;
	queue->host_hw_time       = 0;
	queue->topo_param_cnt     = 0;
	queue->topo_updating      = false;
	queue->unique_id          = pparam->hqueue;

	mutex_init(&queue->mutex);
	kref_init(&queue->ref_cnt);
	INIT_LIST_HEAD(&queue->head);
	INIT_LIST_HEAD(&queue->sync_entry);

	queue->tgid_entry = tgid_entry_get(user);
	if ((queue->tgid_entry == NULL)
		&& (user != (u64)ANNOY_USER) && (!__cn_perf_by_pass(core))) {
		cn_dev_core_err(core, "user queue get tgid_entry failed");
		ret = -EINVAL;
		goto perf_tgid_get_err;
	}

	*ppqueue = queue;

	return ret;

perf_tgid_get_err:
	core_dump_info_exit(core->sbts_set, queue->dump_info);
dump_info_init_err:
	__queue_ack_free(queue_manager, queue->ack_info);
ret_share_mem_err:
	cn_kfree(queue);
err:
	__sync_fetch_and_sub(&queue_manager->count, 1);
	return ret;
}

static void destroy_queue_env(struct queue_manager *queue_manager,
			struct queue *queue)
{
	struct cn_core_set *core = queue_manager->core;
	struct sbts_set *sbts = core->sbts_set;

	if (queue->tgid_entry) {
		tgid_entry_put(queue->tgid_entry);
		queue->tgid_entry = NULL;
	}

	sbts_hostfn_task_free(sbts->hostfunc_set, queue);

	efd_put(sbts->efd_manager, queue->efd);

	core_dump_info_exit(sbts, queue->dump_info);

	__queue_ack_free(queue_manager, queue->ack_info);

	cn_dev_core_debug(core, "destroy queue sid:%llu", (unsigned long long) queue->sid);
	memset(queue, 0, sizeof(*queue));
	cn_kfree(queue);
	__sync_fetch_and_sub(&queue_manager->count, 1);
}

static inline __u64
fill_desc_create_queue(__u64 version, __u64 user,
		struct comm_ctrl_desc *ctrl_desc, struct queue *queue,
		struct cn_core_set *core)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	__u64 sbts_version = GET_SBTS_VERSION(version);
	struct cd_create_queue *priv = NULL;
	/* version relate structure */
	struct ctrl_desc_data_v1 *data = NULL;

	ctrl_desc->version     = sbts_version;
	/* get ctrl desc data */
	data                   = (struct ctrl_desc_data_v1 *)ctrl_desc->data;
	data->type             = CREATE_QUEUE;
	data->user             = cpu_to_le64(user);
	/* get cd_create_queue structure */
	priv                   = (struct cd_create_queue *)data->priv;
	priv->core_dump_en     = cpu_to_le64(queue->dump_info->enable);
	priv->dump_version	   = cpu_to_le64(queue->dump_info->version);
	priv->host_sid         = cpu_to_le64(queue->sid);
	priv->dev_ret_iova     = cpu_to_le64(queue->ack_info->ret_dev_iova);
	priv->priority         = cpu_to_le64(queue->priority);
	priv->tgid_entry_id    = cpu_to_le64(get_tgid_entry_id(queue->tgid_entry));
	priv->unique_id        = cpu_to_le64(queue->unique_id);

	/* calculate payload_size: version + sta + ctrl + data + priv */
	payload_size = sizeof(struct comm_ctrl_desc);

	return payload_size;
}

static int hpq_create_queue(struct queue_manager *queue_manager,
				struct queue  **pqueue, u64 user,
				struct sbts_create_queue *pparam,
				struct comm_ctrl_desc *tx_desc,
				struct comm_ctrl_desc *rx_desc)
{
	int ret = 0;
	int payload_size = 0;
	struct queue *queue = NULL;
	struct ctrl_desc_data_v1 *data = NULL;
	struct cd_create_queue *priv = NULL;
	struct sched_manager *sched_mgr = queue_manager->sched_mgr;
	struct cn_core_set *core = queue_manager->core;
	struct sbts_set *sbts = core->sbts_set;

	sbts_cd_priv_size_check(sizeof(struct cd_create_queue));
	ret = create_queue_env(queue_manager, &queue, (u64)user, pparam);
	if (ret) {
		cn_dev_core_err(core, "create queue env failed");
		return ret;
	}

	payload_size = fill_desc_create_queue(pparam->version, (__u64)user,
			tx_desc, queue, core);
	if (payload_size == 0) {
		cn_dev_core_err(core, "fill ctrl descriptor failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto err_destroy_queue_env;
	}

	print_time_detail("berfore ioctl");
	ret = sched_mgr->ioctl(sched_mgr, tx_desc, rx_desc,
				(__u64)user, (__u64)payload_size);
	print_time_detail("after ioctl");
	if (ret || rx_desc->sta) {
		cn_dev_core_err(core, "create queue failed");
		ret = -CN_SBTS_ERROR_IOCTL_FAILED;
		goto err_destroy_queue_env;
	}

	queue->sid = __sync_fetch_and_add(&g_queue_global_id, 1);
	/* recv queue sid from device */
	data = (struct ctrl_desc_data_v1 *)rx_desc->data;
	priv = (struct cd_create_queue *)data->priv;
	queue->dev_sid = priv->dev_sid;

	queue->efd = sbts_get_efd_by_user(sbts->efd_manager, user);

	*pqueue = queue;

	cn_dev_core_debug(core, "queue(%px) sid %#016llx", queue, queue->dev_sid);

	return 0;

err_destroy_queue_env:
	destroy_queue_env(queue_manager, queue);
	return ret;
}

static inline __u64
fill_desc_destroy_queue(__u64 version, __u64 user,
		struct comm_ctrl_desc *ctrl_desc, struct queue *queue,
		struct cn_core_set *core)
{
	/* @payload is return value, 0 is wrong, positive is right */
	__u64 payload_size = 0;
	struct cd_destroy_queue *priv = NULL;
	/* version relate structure */
	struct ctrl_desc_data_v1 *data = NULL;

	switch (version) {
	case SBTS_VERSION:
		ctrl_desc->version = version;
		/* get ctrl desc data */
		data               = (struct ctrl_desc_data_v1 *)ctrl_desc->data;
		data->type         = DESTROY_QUEUE;
		data->user         = cpu_to_le64(user);
		/* get cd_destroy_queue structure */
		priv               = (struct cd_destroy_queue *)data->priv;
		priv->dev_sid      = cpu_to_le64(queue->dev_sid);
		priv->queue_ticket = queue->topo_updating ? 0 : cpu_to_le64(queue->task_ticket);
		priv->sync_ticket  = cpu_to_le64(queue->sync_ticket);
		priv->topo_param_cnt = cpu_to_le64(queue->topo_param_cnt);

		/* calculate payload_size: version + sta + ctrl + data + priv */
		payload_size = sizeof(struct comm_ctrl_desc);
		break;

	default:
		cn_dev_core_err(core, "version not match!");
	}

	return payload_size;
}


static int hpq_destroy_queue(struct queue_manager *queue_manager,
				struct queue *queue, u64 user,
				struct comm_ctrl_desc *tx_desc,
				struct comm_ctrl_desc *rx_desc)
{
	int ret = 0;
	int payload_size = 0;
	struct sched_manager *sched_mgr = queue_manager->sched_mgr;
	struct cn_core_set *core = queue_manager->core;
	int cnt = DESTROY_TIMEOUT;
	struct hpq_task_ack_desc ret_as = {0};

	if (queue_manager->driver_unload_flag) {
		destroy_queue_env(queue_manager, queue);
		return 0;
	}
	/* no need to judge the validation of payload_size,
	 * because version is always right
	 */
	payload_size = fill_desc_destroy_queue(SBTS_VERSION, (__u64)user,
			tx_desc, queue, core);

	cn_dev_core_debug(core, "queue(%px) sid %#016llx, task_ticket:%llx",
			queue, queue->dev_sid, (unsigned long long)queue->task_ticket);
	ret = sched_mgr->ioctl(sched_mgr, tx_desc, rx_desc,
			(__u64)user, (__u64)payload_size);
	if (ret || rx_desc->sta) {
		cn_dev_core_err(core, "dev destroy failed");
		destroy_queue_env(queue_manager, queue);
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}

	while (--cnt) {
		queue_ack_read_ack_data(queue->ack_info, &ret_as);
		if (ret_as.seq_num == ~0ULL) {
			cn_dev_core_debug(core, "destroy queue done, seq_num:%llx",
						ret_as.seq_num);
			break;
		}

		if (sbts_pause(core, 20000, 20000)) {
			cn_dev_core_err(core, "destroy queue(%px) sid %#016llx killed",
					queue, queue->dev_sid);
			break;
		}
	}

	if (!cnt) {
		cn_dev_core_err(core, "destroy queue(%px) sid %#016llx timeout", queue, queue->dev_sid);
		cn_dev_core_err(core, "destroy queue task ticket %lld, ack_ticket: %lld",
				(unsigned long long)queue->task_ticket, ret_as.seq_num);
		ret = -ETIMEDOUT;
	}

	destroy_queue_env(queue_manager, queue);

	return ret;
}

static inline void __queue_get(struct queue *queue)
{
	if (!kref_get_unless_zero(&queue->ref_cnt)) {
		cn_dev_warn("queue(0x%px) sid %#016llx", queue, queue->dev_sid);
		cn_dev_warn("queue cnt is invalid");
		WARN_ON(1);
	}
}

struct queue *queue_get(struct queue_manager *queue_mgr,
		u64 devsid, cn_user user,
		int check_excep)
{
	struct queue *queue = NULL;

	if (unlikely(!queue_mgr)) {
		cn_dev_err("param is invalid");
		return NULL;
	}

	read_lock(&queue_mgr->rwlock);
	queue = __queue_validate(queue_mgr, devsid);
	if (!queue) {
		goto queue_get_err;
	}

	if ((check_excep && queue->sta)) {
		queue = NULL;
		goto queue_get_err;
	}

	if (user && (queue->user != (u64)user)) {
		queue = NULL;
		goto queue_get_err;
	}

	__queue_get(queue);

queue_get_err:
	read_unlock(&queue_mgr->rwlock);

	return queue;
}

void queue_release(struct kref *kref)
{
	struct queue *queue = container_of(kref, struct queue, ref_cnt);

	cn_dev_debug("queue(%px) sid %#016llx", queue, queue->dev_sid);
	cn_dev_debug("queue release");
}

int queue_put(struct queue_manager *queue_mgr, struct queue *queue)
{
	int ret = 0;

	/* decrement refcount, and if 0, call queue_release() and hpq_destroy_queue(). */
	if (kref_put(&queue->ref_cnt, queue_release)) {
		struct comm_ctrl_desc tx_desc;
		struct comm_ctrl_desc rx_desc;

		ret = hpq_destroy_queue(queue_mgr, queue, queue->user,
				&tx_desc, &rx_desc);
	}

	return ret;
}

int queue_get_ack_sta(struct queue *queue,
		struct hpq_task_ack_desc *ack)
{
	int ret = 0;

	/* ret > 0: success, otherwise fail*/
	ret = queue_ack_read_ack_data(queue->ack_info, ack);
	if (!ret || ack->sta) {
		if (__sync_bool_compare_and_swap(&queue->sta,
					QUEUE_NORMAL, QUEUE_EXCEPTION)) {
			cn_dev_err("queue(0x%px) sid %#016llx", queue, queue->dev_sid);
			cn_dev_err("queue task seq:%lld, ret:%d, sta:%lld, queue exception",
					(unsigned long long)ack->seq_num, !ret, ack->sta);
		}
	}

	return !ret;
}

int
cn_multi_queue_sync(struct sbts_set *sbts,
		void *args,
		cn_user user)
{
	struct cn_core_set *core = sbts->core;
	struct queue_manager *queue_mgr = sbts->queue_manager;
	int ret = 0;
	struct queue *queue_item = NULL;
	struct queue *tmp = NULL;
	struct sbts_multi_queue_sync sync_param = {0};
	struct list_head queue_list;
	INIT_LIST_HEAD(&queue_list);

	if (copy_from_user((void *)&sync_param, (void *)args, sizeof(
					 struct sbts_multi_queue_sync))) {
		cn_dev_core_err(core, "copy parameters failed!");
		ret = -EFAULT;
		return ret;
	}

	sync_param.except_queue = 0;

	if (mutex_lock_killable(&queue_mgr->mqsync_mutex)) {
		cn_dev_core_err(core, "multi queue sync killed by fatal signal");
		return -EINTR;
	}

	read_lock(&queue_mgr->rwlock);
	list_for_each_entry_safe(queue_item, tmp, &queue_mgr->head, head) {
		if (queue_item->user == (u64)user) {
			__queue_get(queue_item);
			list_move_tail(&queue_item->sync_entry, &queue_list);
		}
	}
	read_unlock(&queue_mgr->rwlock);

	list_for_each_entry_safe(queue_item, tmp, &queue_list, sync_entry) {
		if (!ret) {
			if (queue_item->sta) {
				sync_param.except_queue = queue_item->dev_sid;
				ret = -CN_QUEUE_ERROR_QUEUE_INVALID;
			} else {
				ret = cn_queue_sync_sched(sbts, queue_item);
				if (ret) {
					sync_param.except_queue = queue_item->dev_sid;
				}
			}
		}

		list_del_init(&queue_item->sync_entry);
		queue_put(queue_mgr, queue_item);
	}

	mutex_unlock(&queue_mgr->mqsync_mutex);

	if (copy_to_user((void *)args, (void *)&sync_param,
					sizeof(struct sbts_multi_queue_sync))) {
		cn_dev_core_err(core, "copy parameters to user failed!");
		ret = -EFAULT;
	}

	return ret;
}

/* push task to dev with input queue
 * must __sbts_queue_push_lock mutex lock queue before function.
 * */
int queue_push_task_basic(struct queue_manager *queue_manager,
			struct queue *queue, struct comm_task_desc *task,
			__u64 user, __u64 payload_size,
			u64 *ticket, u64 *is_idle, bool update_ticket)
{
	int ret = 0;
	int cnt;
	u64 task_cnt;
	u64 qc_delay_cnt = 0;
	u64 tc_delay_cnt = 0;
	struct task_desc_data_v1 *data =
			(struct task_desc_data_v1 *)task->data;
	struct hpq_task_ack_desc ack_task = {0};
	struct cn_core_set *core = queue_manager->core;
	struct sbts_set *sbts = core->sbts_set;
	struct sched_manager *sched = sbts->sched_manager;
	struct sbts_basic_info *info =
			(struct sbts_basic_info *)sbts->hw_info->data;

	do {
		if (likely((queue->sta == QUEUE_NORMAL) &&
				((queue->task_ticket - queue->remote_ticket) <
				info->host_queue_depth))) {
			break;
		}

		ret = queue_get_ack_sta(queue, &ack_task);
		if (unlikely(ret)) {
			cn_dev_core_err(core,
					"queue(%px) sid %#016llx get ack status fail!",
					queue, queue->dev_sid);
			ret = -CN_QUEUE_ERROR_QUEUE_INVALID;
			break;
		}

		queue->remote_ticket = ack_task.seq_num;

		if (queue->sta != QUEUE_NORMAL) {
			ret = queue_ack_sta_parse(core, queue, ack_task);
			break;
		}

		task_cnt = queue->task_ticket - ack_task.seq_num;
		if (task_cnt < info->host_queue_depth) {
			*is_idle = !task_cnt;
			data->is_idle = !task_cnt;
			break;
		}

		qc_delay_cnt++;
		ret = sbts_pause_stopable(core, 2, 5);
		if (ret) {
			if (ret == -ERESTARTNOINTR) {
				cn_dev_core_err(core, "queue(%px) sid %#016llx, stop by pending signal(ret %d)",
						queue, queue->dev_sid, ret);
			} else {
				if (__sync_bool_compare_and_swap(&queue->sta,
							QUEUE_NORMAL, QUEUE_EXCEPTION)) {
					cn_dev_core_err(core, "queue(%px) sid %#016llx", queue, queue->dev_sid);
					cn_dev_core_err(core, "queue task seq:%lld, ret:%d, sta:%lld, queue exception",
							(unsigned long long)ack_task.seq_num, !ret, ack_task.sta);
				}
				cn_dev_core_err(core, "queue(%px) sid %#016llx, killed by fatal signal",
						queue, queue->dev_sid);
			}
			break;
		}
	} while (1);

	if (ret) {
		cn_dev_core_err(core, "queue(%px) sid %#016llx", queue, queue->dev_sid);
		cn_dev_core_err(core, "curr ticket:%lld, ack ticket: %lld",
				(unsigned long long)queue->task_ticket,
				(unsigned long long)ack_task.seq_num);
		return ret;
	}

	for (cnt = PUSH_TASK_TIMEOUT; ; cnt--) {
		if (commu_send_message_once(sched->task_ep, (void *)task, payload_size)) {
			if (likely(update_ticket)) {
				__sync_add_and_fetch(&queue->task_ticket, 1);
			}
			*ticket = queue->task_ticket;
			break;
		}

		tc_delay_cnt++;
		if (!cnt) {
			ret = -ETIMEDOUT;
			break;
		}

		ret = sbts_pause_stopable(core, 2, 5);
		if (ret) {
			if (ret == -ERESTARTNOINTR) {
				cn_dev_core_err(core, "queue(%px) sid %#016llx, stop by pending signal(ret %d)",
						queue, queue->dev_sid, ret);
			} else {
				if (__sync_bool_compare_and_swap(&queue->sta,
							QUEUE_NORMAL, QUEUE_EXCEPTION)) {
					cn_dev_core_err(core, "queue(%px) sid %#016llx exception", queue, queue->dev_sid);
				}
				cn_dev_core_err(core, "queue(%px) sid %#016llx, killed by fatal signal, cnt:%d",
						queue, queue->dev_sid, cnt);
			}
			break;
		}

		cn_dev_core_debug(core, "put task failed, try again later");
	}

	if (likely(!ret)) {
		record_queue_backward(queue_manager, qc_delay_cnt);
		record_task_backward(queue_manager, tc_delay_cnt);
	}

	return ret;
}

int queue_push_task_ctrl_ticket(struct queue_manager *queue_manager,
			struct queue *queue, struct comm_task_desc *task,
			__u64 user, __u64 payload_size, bool update_ticket)
{
	int ret;
	u64 ticket, is_idle;

	ret = __sbts_queue_push_lock(queue);
	if (ret) {
		return ret;
	}

	ret = queue_push_task_basic(queue_manager, queue, task,
				user, payload_size, &ticket, &is_idle, update_ticket);
	__sbts_queue_push_unlock(queue);

	return ret;
}

int queue_push_task_check_idle(struct queue_manager *queue_manager,
			struct queue *queue, struct comm_task_desc *task,
			__u64 user, __u64 payload_size, u64 *is_idle)
{
	int ret;
	u64 ticket;

	ret = __sbts_queue_push_lock(queue);
	if (ret) {
		return ret;
	}

	ret = queue_push_task_basic(queue_manager, queue, task,
				user, payload_size, &ticket, is_idle, true);
	__sbts_queue_push_unlock(queue);

	return ret;
}

int queue_push_task_without_lock(struct queue_manager *queue_manager,
			struct queue *queue, struct comm_task_desc *task,
			__u64 user, __u64 payload_size)
{
	u64 ticket, is_idle;

	return queue_push_task_basic(queue_manager, queue, task,
				user, payload_size, &ticket, &is_idle, true);
}

/* lock less and do not update ticket */
int queue_push_task_without_lock_and_ticket(struct queue_manager *queue_manager,
			struct queue *queue, struct comm_task_desc *task,
			__u64 user, __u64 payload_size)
{
	u64 ticket, is_idle;

	return queue_push_task_basic(queue_manager, queue, task,
				user, payload_size, &ticket, &is_idle, false);
}

/* return with current task index ticket */
int queue_push_task_ticket(struct queue_manager *queue_manager,
			struct queue *queue, struct comm_task_desc *task,
			__u64 user, __u64 payload_size, u64 *ticket)
{
	int ret;
	u64 is_idle;

	ret = __sbts_queue_push_lock(queue);
	if (ret) {
		return ret;
	}

	ret = queue_push_task_basic(queue_manager, queue, task,
				user, payload_size, ticket, &is_idle, true);
	__sbts_queue_push_unlock(queue);

	return ret;
}

int queue_push_task(struct queue_manager *queue_manager,
			struct queue *queue, struct comm_task_desc *task,
			__u64 user, __u64 payload_size)
{
	int ret;
	u64 ticket, is_idle;

	ret = __sbts_queue_push_lock(queue);
	if (ret) {
		return ret;
	}

	ret = queue_push_task_basic(queue_manager, queue, task,
				user, payload_size, &ticket, &is_idle, true);
	__sbts_queue_push_unlock(queue);

	return ret;
}

int queue_ticket_reset(struct queue_manager *queue_manager,
		u64 queue_did, u64 user)
{
	struct cn_core_set *core = queue_manager->core;
	struct queue *queue = NULL;
	struct hpq_task_ack_desc ack_task = {0};
	int ret = 0;

	queue = queue_get(queue_manager, queue_did, (cn_user)user, 1);
	if (!queue) {
		cn_dev_core_err(core, "queue_dsid(%#llx) is invalid", queue_did);
		return -CN_QUEUE_ERROR_QUEUE_INVALID;
	}
	if (mutex_lock_killable(&queue->mutex)) {
		cn_dev_core_err(core, "queue(%llx) sid %#llx lock killed by signal",
				(u64)queue, queue->dev_sid);
		ret = -EINTR;
		goto out_put;
	}

	ret = queue_get_ack_sta(queue, &ack_task);
	if (ret || queue->sync_ticket || ack_task.seq_num) {
		cn_dev_core_err(core, "queue ack ret %d sync_ticket:%llu seqnum:%llu",
				ret, queue->sync_ticket, ack_task.seq_num);
		ret = -EINVAL;
		goto out_unlock;
	}
	ret = 0;
	queue->task_ticket = 0;
	queue->topo_updating = false;
out_unlock:
	mutex_unlock(&queue->mutex);
out_put:
	queue_put(queue_manager, queue);
	return ret;
}


int queue_do_exit(u64 user, struct queue_manager *queue_manager)
{
	int ret = 0;
	struct queue *queue = NULL;
	struct queue *tmp = NULL;
	struct cn_core_set *core = queue_manager->core;
	LIST_HEAD(queue_destroy_head);

	write_lock(&queue_manager->rwlock);
	list_for_each_entry_safe(queue, tmp, &queue_manager->head, head) {
		if (queue->user == user) {
			cn_dev_core_debug(core, "find queue: %px", queue);
			__sync_bool_compare_and_swap(&queue->sta,
					QUEUE_NORMAL, QUEUE_WAITING_DESTROY);
			list_move(&queue->head, &queue_destroy_head);
		}
	}
	write_unlock(&queue_manager->rwlock);

	if (list_empty(&queue_destroy_head)) {
		cn_dev_core_debug(core, "not find queues need to be destroyed");
		return 0;
	}

	list_for_each_entry_safe(queue, tmp, &queue_destroy_head, head) {
		cn_dev_core_debug(core, "queue :%px resource start to free", queue);
		queue_put(queue_manager, queue);
	}

	cn_dev_core_debug(core, "ret = %d", ret);
	return ret;
}

static int queue_ack_mmap(__u64 version,  struct sbts_set *sbts_set, struct queue *pqueue, __u64 *vaddr)
{
	struct cn_core_set *core = sbts_set->core;
	unsigned int queue_ack_size = ALIGN(sizeof(*(pqueue->ack_info->ack.d_as)), 64);
	unsigned long va_start = 0;
	int prot = PROT_READ;
	int ret = 0;

	if (GET_HOST_VERSION(version) <= HOST_VERSION(2)) {
		cn_dev_core_debug(core, "current version not support!");
		return 0;
	}

	va_start = cn_share_mem_mmap(pqueue->user,
				pqueue->ack_info->ret_host_vaddr,
				queue_ack_size,
				prot,
				sbts_set->outbd_able,
				core);
	if(IS_ERR_VALUE(va_start)) {
		cn_dev_core_err(core, "mmap queue ret buf error!");
		ret = va_start;
	}

	*vaddr = (__u64)va_start;
	pqueue->map_ret_vaddr = *vaddr;

	return ret;
}

static int queue_ack_munmap(__u64 version, struct sbts_set *sbts_set, struct queue *pqueue)
{
	struct cn_core_set *core = sbts_set->core;
	unsigned int queue_ack_size = ALIGN(sizeof(*(pqueue->ack_info->ack.d_as)), 64);

	if (GET_HOST_VERSION(version) <= HOST_VERSION(2)) {
		cn_dev_core_debug(core, "current version not support!");
		return 0;
	}

	return cn_share_mem_munmap(pqueue->user, pqueue->map_ret_vaddr,
				queue_ack_size,
				sbts_set->outbd_able,
				core);
}

int cn_queue_create(struct sbts_set *sbts_set,
				 void *arg,
				 cn_user user)
{
	int ret = 0;
	struct sbts_create_queue param;
	struct queue *pqueue = NULL;
	struct comm_ctrl_desc tx_desc;
	struct comm_ctrl_desc rx_desc;
	struct queue_manager *queue_manager = sbts_set->queue_manager;
	struct cn_core_set *core = sbts_set->core;

	if (copy_from_user((void *)&param, (void *)arg, sizeof(
					 struct sbts_create_queue))) {
		cn_dev_core_err(core, "copy parameters failed!");
		ret = -EFAULT;
		return ret;
	}

	print_time("queue create>>>");
	ret = hpq_create_queue(queue_manager, &pqueue, (u64)user,
					   &param, &tx_desc, &rx_desc);
	print_time("queue done<<<<");

	if (unlikely(ret)) {
		cn_dev_core_debug(core, "create queue failed!");
		return ret;
	}

	ret = queue_ack_mmap(param.version, sbts_set, pqueue, &param.dump_uvaddr);
	if (ret) {
		cn_dev_core_err(core, "map ack buffer fail!");
		goto error_create_queue;
	}

	param.hqueue = pqueue->dev_sid;
	cn_dev_core_debug(core, "create queue%px dev sid %#016llx", pqueue, pqueue->dev_sid);
	if (copy_to_user((void *)arg, (void *)&param,
					sizeof(struct sbts_create_queue))) {
		cn_dev_core_err(core, "<CREATE_QUEUE> copy parameters to user failed!");
		ret = -EFAULT;
		goto error_mmap;
	}
	cn_dev_core_debug(core, "create queue finish!");

	/* only after all create ops success, can add queue to list */
	write_lock(&queue_manager->rwlock);
	list_add(&pqueue->head, &queue_manager->head);
	write_unlock(&queue_manager->rwlock);

	return 0;

error_mmap:
	(void)queue_ack_munmap(param.version, sbts_set, pqueue);
error_create_queue:
	(void)hpq_destroy_queue(queue_manager, pqueue, pqueue->user,
				&tx_desc, &rx_desc);
	return ret;
}

int cn_queue_create_for_func(struct sbts_set *sbts_set, u32 index)
{
	int ret = 0, cnt = 0;
	struct sbts_create_queue param = {0};
	struct queue *queue = NULL;
	struct comm_ctrl_desc tx_desc;
	struct comm_ctrl_desc rx_desc;
	struct queue_manager *queue_manager;
	struct queue_for_func_mgr *func_mgr;
	struct cn_core_set *core;

	if (unlikely(!sbts_set)) {
		return -EINVAL;
	}

	core = sbts_set->core;
	queue_manager = sbts_set->queue_manager;
	func_mgr = sbts_set->que_func_mgr;

	if (index >= MAX_QUEUE_NUM_FOR_FUNC) {
		cn_dev_core_err(core, "index:%d is invalid!", index);
		return -EINVAL;
	}

#define MAX_RETRY_NUM 3
retry:
	param.version = SET_VERSION(6, SBTS_VERSION);
	param.dump_uvaddr = 0ULL;
	print_time("queue create>>>");
	ret = hpq_create_queue(queue_manager, &queue,
			(u64)ANNOY_USER, &param, &tx_desc, &rx_desc);
	print_time("queue done<<<<");

	if (unlikely(ret)) {
		cn_dev_core_err(core, "create queue cnt[%d] failed!", cnt);
		if (sbts_pause_killable(core, 100, 200)) {
			return ret;
		}

		if (cnt++ < MAX_RETRY_NUM) {
			goto retry;
		}
		return ret;
	}

	func_mgr->array[index] = queue->dev_sid;
	cn_dev_core_debug(core, "create queue%px dev sid %#016llx",
			queue, queue->dev_sid);
	cn_dev_core_debug(core, "create queue cnt[%d] finish!", cnt);

	/* only after all create ops success, can add queue to list */
	write_lock(&queue_manager->rwlock);
	list_add(&queue->head, &queue_manager->head);
	write_unlock(&queue_manager->rwlock);

	return ret;
}

int cn_queue_init_for_func(struct sbts_set *sbts_set)
{
	int ret = 0;
	int i, j;
	struct queue_for_func_mgr *func_mgr = NULL;
	struct cn_core_set *core = sbts_set->core;

	func_mgr = cn_numa_aware_kzalloc(core, sizeof(struct queue_for_func_mgr), GFP_KERNEL);
	if (!func_mgr) {
		cn_dev_core_err(core, "alloc queue for func mgr failed!");
		return -ENOMEM;
	}
	sbts_set->que_func_mgr = func_mgr;

	for (i = 0; i < MAX_QUEUE_NUM_FOR_FUNC; i++) {
		ret = cn_queue_create_for_func(sbts_set, i);
		if (unlikely(ret)) {
			cn_dev_core_err(core,
				"create queue for func index[%d] failed!", i);
			break;
		}
	}

	if (i != MAX_QUEUE_NUM_FOR_FUNC) {
		for (j = 0; j < i; j++) {
			cn_queue_destroy_for_func(sbts_set, j);
		}
		ret = -1;
		goto out_err;
	}

	sema_init(&func_mgr->sema, MAX_QUEUE_NUM_FOR_FUNC);
	spin_lock_init(&func_mgr->lock);
	bitmap_zero(&func_mgr->used_bitmap, MAX_QUEUE_NUM_FOR_FUNC);
	cn_dev_core_info(core, "queue init for func finish!");
	return ret;

out_err:
	cn_kfree(func_mgr);
	sbts_set->que_func_mgr = NULL;
	return ret;
}

int cn_queue_get_for_func(struct sbts_set *sbts_set,
		u32 *index, u64 *que_dsid)
{
	int ret = 0;
	unsigned int bit;
	struct queue_for_func_mgr *func_mgr;
	struct cn_core_set *core;

	if (unlikely(!sbts_set)) {
		return -EINVAL;
	}

	core = sbts_set->core;
	func_mgr = sbts_set->que_func_mgr;

	if (unlikely(down_killable(&func_mgr->sema))) {
		cn_dev_core_err(core, "get sema of queue func mgr failed!");
		return -1;
	}

	spin_lock(&func_mgr->lock);
	bit = find_first_zero_bit(&func_mgr->used_bitmap,
			MAX_QUEUE_NUM_FOR_FUNC);
	set_bit(bit, &func_mgr->used_bitmap);
	spin_unlock(&func_mgr->lock);

	*index = bit;
	*que_dsid = func_mgr->array[bit];
	cn_dev_core_debug(core, "queue_index:%d queue: dev_sid:%#llx",
		*index, func_mgr->array[*index]);
	return ret;
}

void cn_queue_put_for_func(struct sbts_set *sbts_set, u32 index)
{
	struct queue_for_func_mgr *func_mgr;
	struct cn_core_set *core;

	if (unlikely(!sbts_set)) {
		return;
	}

	core = sbts_set->core;
	func_mgr = sbts_set->que_func_mgr;

	if (index >= MAX_QUEUE_NUM_FOR_FUNC) {
		cn_dev_core_err(core, "index:%d is invalid!", index);
		return;
	}

	spin_lock(&func_mgr->lock);
	if (unlikely(!test_bit(index, &func_mgr->used_bitmap))) {
		cn_dev_core_err(core, "index:%d bitmap invalid!", index);
		spin_unlock(&func_mgr->lock);
		return;
	}

	clear_bit(index, &func_mgr->used_bitmap);
	up(&func_mgr->sema);
	spin_unlock(&func_mgr->lock);
}

int cn_queue_destroy(struct sbts_set *sbts_set,
				  void *args,
				  cn_user user)
{
	int ret = 0;
	struct queue_manager *queue_mgr = sbts_set->queue_manager;
	struct queue *queue = NULL;
	struct sbts_destroy_queue param;
	struct cn_core_set *core = sbts_set->core;

	cn_dev_core_debug(core, "destroy queue begin!");
	if (copy_from_user((void *)&param, (void *)args, sizeof(
				 struct sbts_destroy_queue))) {
		cn_dev_core_err(core, "copy parameters failed!");
		ret = -EFAULT;
		return ret;
	}

	write_lock(&queue_mgr->rwlock);
	queue = __queue_validate(queue_mgr, param.hqueue);
	if (queue && (queue->user == (u64)user)) {
		cn_dev_core_debug(core, "destroy queue %px, dev sid %#016llx", queue, queue->dev_sid);
		__sync_bool_compare_and_swap(&queue->sta,
				QUEUE_NORMAL, QUEUE_WAITING_DESTROY);
		list_del(&queue->head);
	} else {
		cn_dev_core_err(core, "queue dsid %#llx is invalid", param.hqueue);
		ret = -CN_QUEUE_ERROR_QUEUE_INVALID;
	}
	write_unlock(&queue_mgr->rwlock);
	if (ret) {
		goto error_out;
	}

	ret = queue_ack_munmap(param.version, sbts_set, queue);
	if (ret) {
		cn_dev_core_err(core, "unmap ack buffer fail!");
	}

	ret = queue_put(queue_mgr, queue);

error_out:
	return ret;
}

#define __alloc_param_try_wait \
({	\
	if (flags & SBTS_ALLOC_PARAM_ONCE) {	\
		return -ENOMEM;	\
	}	\
	if (sbts_udelay_killable(core, 1)) {	\
		cn_dev_core_err(core,	\
				"wait param buffer killed by fatal signal");	\
		return -EINTR;	\
	}	\
	/* udelay 1us --> abort 512ms */	\
	if (unlikely(((++delay_cnt) &	\
			PARAM_WAIT_TIMEOUT_512MS_MASK) == 0)) {	\
		cond_resched();	\
	}	\
	goto alloc_retry;	\
})
int alloc_param_buf(struct queue_manager *pqueue_mgr,
		u32 size, host_addr_t *host_vaddr, dev_addr_t *dev_vaddr,
		u32 flags)
{
	struct cn_core_set *core = pqueue_mgr->core;
	struct param_buf_manager *param_mgr = pqueue_mgr->param_mgr;
	u64 delay_cnt = 0;
	__u32 pcount = 0;
	__u32 index = 0;

	/* allow 0 size alloc */
	if (unlikely(!size)) {
		*host_vaddr = 0;
		*dev_vaddr = 0;
		return 0;
	}

	pcount = DIV_ROUND_UP(size, param_mgr->page_size);

alloc_retry:
	if (mutex_lock_killable(&param_mgr->lock)) {
		cn_dev_core_err(core,
				"wait param buffer killed by fatal signal");
		return -EINTR;
	}

	if (unlikely(flags & SBTS_ALLOC_PARAM_HALF) &&
			(param_mgr->alloced_pages > param_mgr->half_pages)) {
		mutex_unlock(&param_mgr->lock);
		if (__sync_bool_compare_and_swap(
					&pqueue_mgr->halfmem_flag, 0, 1)) {
			cn_dev_core_warn(core,
					"cant alloc more than half of param buffer");
		}
		__alloc_param_try_wait;
	}

	index = bitmap_find_next_zero_area(param_mgr->bitmap,
					param_mgr->bitmap_nr, 0,
					pcount, 0);

	if (index >= param_mgr->bitmap_nr) {
		mutex_unlock(&param_mgr->lock);

		if (__sync_bool_compare_and_swap(
					&pqueue_mgr->nomem_flag, 0, 1)) {
			cn_dev_core_warn(core,
					"no space for param buffer, sleep to retry");
		}

		__alloc_param_try_wait;
	}

	bitmap_set(param_mgr->bitmap, index, pcount);

	param_mgr->alloced_pages += pcount;
	param_mgr->size_buf[index] = size;
	*host_vaddr = param_mgr->host_addr_base + index * param_mgr->page_size;
	*dev_vaddr = param_mgr->dev_addr_base + index * param_mgr->page_size;
	mutex_unlock(&param_mgr->lock);

	record_param_delay(pqueue_mgr, delay_cnt);
	return 0;
}

void free_param_buf_array(struct cn_core_set *core,
		dev_addr_t *dev_vaddrs, int nmemb)
{
	struct sbts_set *sbts = core->sbts_set;
	struct queue_manager *queue_mgr = sbts->queue_manager;
	struct param_buf_manager *param_mgr = queue_mgr->param_mgr;
	__u32 page_size = param_mgr->page_size;
	__u64 dev_addr_base = param_mgr->dev_addr_base;
	int i;
	__u32 pcount = 0;
	__u32 index = 0;
	dev_addr_t dev_vaddr;

	if (!dev_vaddrs || !nmemb) {
		return;
	}

	if (mutex_lock_killable(&param_mgr->lock)) {
		cn_dev_core_err(core,
				"killed by fatal signal");
		return;
	}

	for (i = 0; i < nmemb; ++i) {
		dev_vaddr = dev_vaddrs[i];
		cn_dev_core_debug(core, "dev_vaddr:%#llx", dev_vaddr);
		if (!dev_vaddr)
			continue;

		/* calculate index through dev_addr_base */
		index = (dev_vaddr - dev_addr_base) / page_size;
		if (unlikely(index >= param_mgr->bitmap_nr)) {
			cn_dev_core_err(core,
					"free addr [0x%llx] index [%d] wrong",
					dev_vaddr, index);
			continue;
		}

		pcount = DIV_ROUND_UP(param_mgr->size_buf[index], page_size);
		if (unlikely(index + pcount > param_mgr->bitmap_nr)) {
			cn_dev_core_err(core, "index %d count %d larger than "
					"bitmap_nr %d!",
					index, pcount, param_mgr->bitmap_nr);
			continue;
		}

		param_mgr->alloced_pages -= pcount;
		bitmap_clear(param_mgr->bitmap, index, pcount);
	}

	mutex_unlock(&param_mgr->lock);
}



void free_param_buf(struct cn_core_set *core, dev_addr_t dev_vaddr)
{
	free_param_buf_array(core, &dev_vaddr, 1);
}

static u32 __max_param_size_calc(struct cn_core_set *core)
{
	int i;
	int shm_cnt = 0;
	u64 size = 0;
	u32 param_size;
	u64 max = PARAM_BUF_SIZE_MAX;

	if (core->device_id == MLUID_220 ||
			core->device_id == MLUID_CE3226 ||
			core->device_id == MLUID_CE3226_EDGE ||
			core->device_id == MLUID_PIGEON ||
			core->device_id == MLUID_PIGEON_EDGE)
		return PARAM_BUF_SIZE_SPECIAL;

	if (core->device_id == MLUID_370)
		max = PARAM_BUF_SIZE_370;

	/* get shm size */
	shm_cnt = cn_bus_get_mem_cnt(core->bus_set);
	for (i = 0; i < shm_cnt; i++) {
		if (cn_bus_get_mem_type(core->bus_set, i) == CN_SHARE_MEM_DEV) {
			size += cn_bus_get_mem_size(core->bus_set, i);
		}
	}
	/* divide 2(>>1) */
	param_size = size >> 1;

	if (param_size < PARAM_BUF_SIZE_MIN) {
		cn_dev_core_warn(core, "param buf size %#x less than %#llx",
					param_size, PARAM_BUF_SIZE_MIN);
	}

	return (u32)min(max((u64)param_size, PARAM_BUF_SIZE_MIN),
				max);
}

int param_buf_manager_init(struct cn_core_set *core)
{
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct queue_manager *pqueue_mgr = sbts->queue_manager;
	struct param_buf_manager *param_mgr = NULL;
	host_addr_t host_vaddr;
	dev_addr_t dev_vaddr;
	int ret = 0;

	param_mgr = cn_numa_aware_kzalloc(core, sizeof(struct param_buf_manager), GFP_KERNEL);
	if (!param_mgr) {
		cn_dev_core_err(core, "malloc param buffer manager failed");
		return -EINVAL;
	}

	param_mgr->param_buf_size = __max_param_size_calc(core);

	cn_dev_core_info(core, "alloc param buf size: %#x", param_mgr->param_buf_size);
	param_mgr->page_size = PARAM_BUF_PAGE_SIZE;
	param_mgr->bitmap_nr = DIV_ROUND_UP(
			param_mgr->param_buf_size, param_mgr->page_size);
	param_mgr->half_pages = param_mgr->bitmap_nr >> 1;
	param_mgr->alloced_pages = 0;
	param_mgr->bitmap_size = BITS_TO_LONGS(
			param_mgr->bitmap_nr) * sizeof(long);
	mutex_init(&param_mgr->lock);

	/* alloc device share memory for param buffer. */
	ret = cn_device_share_mem_alloc(0, &host_vaddr, &dev_vaddr,
				param_mgr->param_buf_size, core);
	if (ret) {
		cn_dev_core_err(core, "alloc device shared memory failed");
		ret = -ENOMEM;
		goto parambuf_err;
	}

	param_mgr->host_addr_base = host_vaddr;
	param_mgr->dev_addr_base = dev_vaddr;

	/* alloc kernel memory for bitmap */
	param_mgr->bitmap = cn_numa_aware_kzalloc(core, param_mgr->bitmap_size, GFP_KERNEL);
	if (!param_mgr->bitmap) {
		cn_dev_core_err(core, "malloc param bitmap failed!");
		ret = -ENOMEM;
		goto bitmap_err;
	}
	bitmap_zero(param_mgr->bitmap, param_mgr->bitmap_nr);

	/* alloc buffer for allocated addr->size */
	param_mgr->size_buf = cn_kcalloc(param_mgr->bitmap_nr,
				sizeof(__u32), GFP_KERNEL);
	if (!param_mgr->size_buf) {
		cn_dev_core_err(core, "malloc size buffer failed!");
		ret = -ENOMEM;
		goto buf_err;
	}

	pqueue_mgr->param_mgr = param_mgr;

	return 0;

buf_err:
	cn_kfree(param_mgr->bitmap);
bitmap_err:
	cn_device_share_mem_free(0, param_mgr->host_addr_base,
			param_mgr->dev_addr_base, core);
parambuf_err:
	cn_kfree(param_mgr);
	return ret;
}

void param_buf_manager_exit(struct cn_core_set *core)
{
	struct sbts_set *sbts = core->sbts_set;
	struct queue_manager *queue_mgr = sbts->queue_manager;
	struct param_buf_manager *param_mgr = NULL;

	if (!queue_mgr) {
		cn_dev_core_err(core, "queue_mgr is null!");
		return;
	}

	param_mgr = queue_mgr->param_mgr;
	if (!param_mgr) {
		cn_dev_core_err(core, "param_mgr is null!");
		return;
	}

	cn_kfree(param_mgr->size_buf);
	cn_kfree(param_mgr->bitmap);
	cn_device_share_mem_free(0, param_mgr->host_addr_base,
			param_mgr->dev_addr_base, core);
	cn_kfree(param_mgr);
	queue_mgr->param_mgr = NULL;
}

int cn_queue_destroy_for_func(struct sbts_set *sbts_set, u32 index)
{
	int ret = 0;
	struct queue_manager *queue_mgr;
	struct queue_for_func_mgr *func_mgr;
	struct queue *queue = NULL;
	struct cn_core_set *core;

	if (unlikely(!sbts_set)) {
		return -EINVAL;
	}

	core = sbts_set->core;
	func_mgr = sbts_set->que_func_mgr;
	queue_mgr = sbts_set->queue_manager;

	if (unlikely(!queue_mgr)) {
		cn_dev_err("queue manager is null!");
		return -EINVAL;
	}

	if (unlikely(!func_mgr)) {
		cn_dev_err("queue func manager is null!");
		return -EINVAL;
	}

	if (index >= MAX_QUEUE_NUM_FOR_FUNC) {
		cn_dev_core_err(core, "index:%d is invalid!", index);
		return -EINVAL;
	}

	cn_dev_core_debug(core, "destroy queue begin!");

	write_lock(&queue_mgr->rwlock);
	queue = __queue_validate(queue_mgr, func_mgr->array[index]);
	if (queue) {
		cn_dev_core_debug(core, "destroy queue %px, dev sid %#016llx",
				queue, queue->dev_sid);
		__sync_bool_compare_and_swap(&queue->sta,
				QUEUE_NORMAL, QUEUE_WAITING_DESTROY);
		list_del(&queue->head);
	} else {
		cn_dev_core_err(core, "queue dsid %#llx is invalid!",
				func_mgr->array[index]);
		ret = -CN_QUEUE_ERROR_QUEUE_INVALID;
	}
	write_unlock(&queue_mgr->rwlock);

	if (!ret) {
		ret = queue_put(queue_mgr, queue);
	}

	return ret;
}

int cn_queue_exit_for_func(struct sbts_set *sbts_set)
{
	int ret = 0;
	int i;
	struct queue_for_func_mgr *func_mgr = NULL;

	if (unlikely(!sbts_set)) {
		cn_dev_err("sbts set is null!");
		return -EINVAL;
	}

	func_mgr = sbts_set->que_func_mgr;
	if (unlikely(!func_mgr)) {
		cn_dev_err("queue func manager is null!");
		return -EINVAL;
	}

	for (i = 0; i < MAX_QUEUE_NUM_FOR_FUNC; i++) {
		ret |= cn_queue_destroy_for_func(sbts_set, i);
	}

	cn_kfree(func_mgr);
	sbts_set->que_func_mgr = NULL;
	cn_dev_info("queue exit for func finish!");
	return ret;
}

static u32 __max_queue_shm(struct cn_core_set *core)
{
	struct sbts_set *sbts_set = core->sbts_set;

	if (!sbts_set->outbd_able)
		return sbts_set->max_queue;

	/* use notifier count to create more ack buffer */
	return sbts_set->max_notifier;
}

int queue_manager_init(struct queue_manager **ppqueue_mgr, struct cn_core_set *core)
{
	struct queue_manager *manager = NULL;
	struct sbts_set *sbts_set = NULL;
	struct queue_ack_s *ack_info = NULL;
	int queue_ret_size =  sizeof(*(ack_info->ack.d_as));
	int queue_outbound_size = ALIGN(queue_ret_size, 64);
	int ret = 0;

	cn_dev_core_debug(core, "queue manager init");
	sbts_set = core->sbts_set;
	manager = cn_numa_aware_kzalloc(core, sizeof(struct queue_manager), GFP_KERNEL);
	if (!manager) {
		cn_dev_core_err(core, "malloc queue manager failed");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&manager->head);
	rwlock_init(&manager->rwlock);
	mutex_init(&manager->mqsync_mutex);
	manager->core = core;
	manager->sched_mgr = sbts_set->sched_manager;
	manager->driver_unload_flag = 0;
	manager->count = 0;
	manager->record_en = 0;
	manager->nomem_flag = 0;
	manager->halfmem_flag = 0;
	queue_record_reset(manager);

	ret = sbts_shm_init(&manager->shm_mgr, core,
			__max_queue_shm(core), queue_outbound_size);
	if (ret) {
		cn_dev_core_err(core, "queue share mem init failed");
		cn_kfree(manager);
		return ret;
	}

	*ppqueue_mgr = manager;
	return 0;
}

void queue_manager_exit(struct queue_manager *queue_manager)
{
	struct cn_core_set *core = NULL;
	struct sbts_set *sbts_set = NULL;

	if (!queue_manager) {
		cn_dev_err("queue manager is null");
		return;
	}
	core = queue_manager->core;
	sbts_set = core->sbts_set;

	if (queue_manager->count != 0) {
		cn_dev_core_err(core, "some queues are working, could not be destroyed");
		return;
	}

	sbts_shm_exit(queue_manager->shm_mgr, core);

	cn_kfree(queue_manager);
	sbts_set->queue_manager = NULL;
}
