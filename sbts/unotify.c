#include <linux/version.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/io.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/seq_file.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_hpq.h"
#include "sbts.h"
#include "queue.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "cndrv_monitor.h"
#include "unotify.h"


#define EFD_TASK_LIMIT_OFF  false
#define EFD_TASK_LIMIT_ON   true

#define EFD_TASK_NUM_MIN    32

struct efd_task_type_info {
	/* limit eventfd in list task number */
	bool lmt_en;
	u32 lmt_cnt;
};
struct efd_task_type_info efd_type_info[EFD_TASK_TYPE_NUM] = {
	{EFD_TASK_LIMIT_OFF, 0}, /* CORE_DUMP_COMPLETE */
	{EFD_TASK_LIMIT_OFF, 0}, /* HOST_FUNCTION_PROCESS */
	{EFD_TASK_LIMIT_ON, 64}, /* PRINTF_PROCESS */
	{EFD_TASK_LIMIT_OFF, 0}, /* GDB_PROCESS */
	{EFD_TASK_LIMIT_OFF, 0}, /* EFD_CORE_DUMP_DMA */
	{EFD_TASK_LIMIT_OFF, 0}, /* EFD_JPU_PROCESS */
};

/* list all task in efd and free them
 * no need to lock because no one can access efd in this time*/
static void __efd_free_all_task(
		struct sbts_efd_manager *manager,
		struct sbts_efd *efd)
{
	struct sbts_efd_task *task, *tmp;

	list_for_each_entry_safe(task, tmp, &efd->task_list, entry) {
		kmem_cache_free(manager->task_mem, task);
	}
}

static inline void __efd_get(struct sbts_efd *efd)
{
	if (!kref_get_unless_zero(&efd->ref_cnt)) {
		cn_dev_warn("efd(%#llx)", (u64)efd);
		cn_dev_warn("efd cnt is invalid");
		WARN_ON(1);
	}
	eventfd_ctx_fileget(efd->efd_file);
}

void efd_release(struct kref *kref)
{
	struct sbts_efd *efd = container_of(kref, struct sbts_efd, ref_cnt);

	cn_dev_debug("release efd %#llx todo", (u64)efd);
}

int efd_put(struct sbts_efd_manager *manager,
			struct sbts_efd *efd)
{
	if (!manager || !efd)
		return 0;

	eventfd_ctx_put(efd->ctx);
	if (kref_put(&efd->ref_cnt, efd_release)) {
		fput(efd->efd_file);
		__efd_free_all_task(manager, efd);
		cn_kfree(efd);
	}

	return 0;
}


static struct sbts_efd *__get_efd_by_user(struct sbts_efd_manager *manager, u64 user)
{
	struct sbts_efd *efd_info = NULL;

	list_for_each_entry(efd_info, &manager->efd_head, list) {
		if (efd_info->user == user) {
			return efd_info;
		}
	}
	return NULL;
}

struct sbts_efd *sbts_get_efd_by_user(
		struct sbts_efd_manager *manager,
		u64 user)
{
	struct sbts_efd *efd_info = NULL;

	if (!manager || !user)
		return NULL;

	read_lock(&manager->rwlock);
	efd_info = __get_efd_by_user(manager, user);
	if (!efd_info) {
		read_unlock(&manager->rwlock);
		cn_dev_debug("cant find efd info by user:%#llx",
				(u64)user);
		return NULL;
	}
	__efd_get(efd_info);
	read_unlock(&manager->rwlock);

	return efd_info;
}

static int __efd_task_in(struct sbts_efd *efd,
		struct sbts_efd_task *efd_task,
		enum efd_task_type ptype)
{
	mutex_lock(&efd->list_lock);
	if (unlikely((efd_type_info[ptype].lmt_en == EFD_TASK_LIMIT_ON) &&
			(efd->task_cnt[ptype] >= efd_type_info[ptype].lmt_cnt))) {
		efd->lmt_ctl_cnt[ptype]++;
		mutex_unlock(&efd->list_lock);
		return -EAGAIN;
	}
	efd->task_cnt[ptype]++;
	efd->total_cnt[ptype]++;
	list_add_tail(&efd_task->entry, &efd->task_list);
	mutex_unlock(&efd->list_lock);

	return 0;
}

int sbts_unotify_send(struct sbts_set *sbts,
		struct queue *queue,
		enum efd_task_type ptype,
		u64 *priv_data,
		u32 priv_size)
{
	struct cn_core_set *core = sbts->core;
	struct sbts_efd_manager *manager = sbts->efd_manager;
	struct sbts_efd *efd_info = NULL;
	struct sbts_efd_task *task;
	struct sbts_efd_data *task_msg;
	int ret = 0;

	if (priv_size >= (sizeof(u64) * EFD_DESC_SIZE)) {
		cn_dev_core_err(core, "input priv size %#x invalid", priv_size);
		return -EINVAL;
	}

	if (ptype >= EFD_TASK_TYPE_NUM) {
		cn_dev_core_err(core, "input type %d invalid", ptype);
		return -EINVAL;
	}

	efd_info = queue->efd;
	if (!efd_info) {
		cn_dev_core_info(core, "queue %#llx efd info invalid",
				(u64)queue);
		return -EINVAL;
	}

	task = kmem_cache_zalloc(manager->task_mem, GFP_KERNEL);
	if (!task) {
		cn_dev_core_err(core, "alloc task buf failed EFD[%llu]",
				efd_info->idx);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&task->entry);
	task_msg = &task->msg;

	task_msg->type = ptype;
	task_msg->hqueue = queue->dev_sid;
	memcpy(task_msg->priv, priv_data, priv_size);

	ret = __efd_task_in(efd_info, task, ptype);
	if (ret) {
		if (ptype != PRINTF_PROCESS)
			cn_dev_core_err(core,
					"task buf(type %d) in list failed",
					ptype);
		goto task_in_tail;
	}

	if (eventfd_signal(efd_info->ctx, 1ULL) != 1) {
		cn_dev_core_err(core, "eventfd signal user failed(type %d) EFD[%llu]",
				ptype, efd_info->idx);
		ret = -EFAULT;
		goto signal_fail;
	}
	return ret;

signal_fail:
	mutex_lock(&efd_info->list_lock);
	list_del_init(&task->entry);
	efd_info->task_cnt[ptype]--;
	mutex_unlock(&efd_info->list_lock);
task_in_tail:
	kmem_cache_free(manager->task_mem, task);
	return ret;
}

static int create_efd_env(struct sbts_efd_manager *manager,
		struct sbts_efd **pefd, int user_efd, u64 user)
{
	struct sbts_efd *efd = NULL;
	struct cn_core_set *core = manager->core;
	struct eventfd_ctx *ctx;
	struct file *efile;
	int ret = 0;

	ctx = eventfd_ctx_fdget(user_efd);
	if (IS_ERR(ctx)) {
		cn_dev_core_err(core, "get ctx from user_efd fail");
		return -EINVAL;
	}

	/* need to fput when release */
	efile = eventfd_fget(user_efd);
	if (IS_ERR(efile)) {
		cn_dev_core_err(core, "get file from user_efd fail");
		ret = -EINVAL;
		goto getf_fail;
	}

	efd = cn_numa_aware_kzalloc(core, sizeof(struct sbts_efd), GFP_KERNEL);
	if (!efd) {
		cn_dev_core_err(core, "alloc for efd list fail");
		ret = -ENOMEM;
		goto alloc_fail;
	}

	efd->user = (u64)user;
	efd->user_efd = user_efd;
	efd->ctx = ctx;
	efd->efd_file = efile;
	efd->idx = __sync_add_and_fetch(&manager->ticket, 1);
	efd->tgid = current->tgid;
	memset(efd->task_cnt, 0, sizeof(u64) * EFD_TASK_TYPE_NUM);
	memset(efd->lmt_ctl_cnt, 0, sizeof(u64) * EFD_TASK_TYPE_NUM);
	memset(efd->total_cnt, 0, sizeof(u64) * EFD_TASK_TYPE_NUM);
	memset(efd->read_cnt, 0, sizeof(u64) * EFD_TASK_TYPE_NUM);
	mutex_init(&efd->list_lock);
	kref_init(&efd->ref_cnt);
	INIT_LIST_HEAD(&efd->task_list);
	get_task_comm(efd->proc_name, current);

	INIT_LIST_HEAD(&efd->list);
	write_lock(&manager->rwlock);
	list_add_tail(&efd->list, &manager->efd_head);
	write_unlock(&manager->rwlock);

	return 0;

alloc_fail:
	fput(efile);
getf_fail:
	eventfd_ctx_put(ctx);
	return ret;
}

static int copy_efd_to_user(struct sbts_set *sbts,
		struct sbts_efd_head *head, u64 user)
{
	struct sbts_efd *efd_info = NULL;
	struct sbts_efd_manager *manager = sbts->efd_manager;
	struct cn_core_set *core = sbts->core;
	struct sbts_efd_task *task, *tmp;
	struct sbts_efd_data *data_arr;
	u64 task_count = (head->data_count > MAX_USER_BUF) ?
				MAX_USER_BUF : head->data_count;
	int i, ret = 0;
	LIST_HEAD(task_head);

	data_arr = cn_numa_aware_kzalloc(core,
			sizeof(struct sbts_efd_data) * task_count,
			GFP_KERNEL);
	if (!data_arr) {
		cn_dev_core_err(core, "alloc for data buffer fail");
		return -ENOMEM;
	}

	/* check user efd info */
	efd_info = sbts_get_efd_by_user(manager, user);
	if (!efd_info) {
		cn_dev_core_err(core, "cant find efd info by user:%#llx", user);
		ret = -EINVAL;
		goto get_efd_fail;
	}

	mutex_lock(&efd_info->list_lock);
	for (i = 0; i < task_count; i++) {
		task = list_first_entry_or_null(&efd_info->task_list,
				struct sbts_efd_task,
				entry);
		if (!task) {
			cn_dev_core_err(core, "get task from EFD[%llu] failed",
					efd_info->idx);
			break;
		}

		list_move_tail(&task->entry, &task_head);
		efd_info->task_cnt[task->msg.type]--;
		efd_info->read_cnt[task->msg.type]++;
	}
	mutex_unlock(&efd_info->list_lock);

	/* no task return 0 and datacount 0 */
	head->data_count = i;
	if (!i) {
		cn_dev_core_err(core, "cant find task from EFD[%llu]",
				efd_info->idx);
		ret = -EINVAL;
		goto get_finish;
	}

	/* del all task */
	i = 0;
	list_for_each_entry_safe(task, tmp, &task_head, entry) {
		memcpy((void *)&data_arr[i++], &task->msg,
				sizeof(struct sbts_efd_data));
		kmem_cache_free(manager->task_mem, task);
	}

	/* cpy data */
	if (copy_to_user((void *)head->efd_data, (void *)data_arr,
				sizeof(struct sbts_efd_data) * i)) {
		cn_dev_core_err(core, "cpy efd info to user error");
		ret = -EFAULT;
	}

get_finish:
	efd_put(manager, efd_info);
get_efd_fail:
	cn_kfree(data_arr);

	return ret;
}

int cn_sbts_get_unotify_info(struct sbts_set *sbts, void *args, cn_user user)
{
	int ret = 0;
	struct sbts_efd_head head;
	struct cn_core_set *core = sbts->core;

	if (copy_from_user((void *)&head, (void *)args,
				sizeof(struct sbts_efd_head))) {
		cn_dev_core_err(core, "copy from user error");
		return -EFAULT;
	}

	if (!head.data_count) {
		cn_dev_core_err(core, "data count shouldnt be 0");
		return -EINVAL;
	}

	ret = copy_efd_to_user(sbts, &head, (u64)user);

	/* cpy header back */
	if (copy_to_user((void *)args, (void *)&head,
				sizeof(struct sbts_efd_head))) {
		cn_dev_core_err(core, "cpy efd info header to user error");
		return -EFAULT;
	}

	return ret;
}

int cn_sbts_set_unotify_fd(struct sbts_set *sbts, void *args, cn_user user)
{
	int user_efd = 0;
	struct sbts_efd *efd = NULL;
	struct sbts_efd_manager *manager = sbts->efd_manager;
	struct cn_core_set *core = sbts->core;

	if (copy_from_user((void *)&user_efd, (void *)args, sizeof(int))) {
		cn_dev_core_err(core, "copy from user error");
		return -EFAULT;
	}
	cn_dev_core_debug(core, " user_efd = %d.", user_efd);

	return create_efd_env(manager, &efd, user_efd, (u64)user);
}

int sbts_efd_do_exit(u64 user, struct sbts_efd_manager *manager)
{
	struct sbts_efd *efd = NULL;
	int find_flag = 0;
	struct cn_core_set *core;

	core = manager->core;

	write_lock(&manager->rwlock);
	list_for_each_entry(efd, &manager->efd_head, list) {
		if (efd->user == user) {
			list_del(&efd->list);
			find_flag = 1;
			break;
		}
	}
	write_unlock(&manager->rwlock);

	if (find_flag) {
		cn_dev_core_debug(core, "put efd %#llx %llu", (u64)efd, efd->idx);
		efd_put(manager, efd);
	}

	return 0;
}

int sbts_efd_manager_init(struct sbts_efd_manager **ppmanager,
			struct cn_core_set *core)
{
	struct sbts_efd_manager *manager;
	struct sbts_set *sbts_set = NULL;
	char mem_name[32];
	int ret = 0;

	sbts_set = core->sbts_set;
	manager = cn_numa_aware_kzalloc(core, sizeof(struct sbts_efd_manager), GFP_KERNEL);
	if (!manager) {
		cn_dev_core_err(core, "malloc efd manager failed");
		return -ENOMEM;
	}
	sprintf(mem_name, "cn_efd_data_%d", core->idx);
	manager->task_mem = kmem_cache_create(mem_name,
			sizeof(struct sbts_efd_task),
			64,
			SLAB_HWCACHE_ALIGN, NULL);
	if (!manager->task_mem) {
		cn_dev_core_err(core, "init efd task cache failed");
		ret = -ENOMEM;
		goto mem_alloc_fail;
	}

	manager->core = core;
	manager->sbts = sbts_set;
	INIT_LIST_HEAD(&manager->efd_head);
	rwlock_init(&manager->rwlock);
	manager->ticket = 0;

	*ppmanager = manager;
	return 0;

mem_alloc_fail:
	kfree(manager);
	return ret;
}

void sbts_efd_manager_exit(struct sbts_efd_manager *manager)
{
	struct cn_core_set *core = NULL;
	struct sbts_set *sbts_set = NULL;

	if (!manager) {
		cn_dev_err("sbts efd manager is null");
		return;
	}

	core = manager->core;
	sbts_set = core->sbts_set;

	if (!list_empty(&manager->efd_head)) {
		cn_dev_core_err(core, "some user efd info still working");
		return;
	}

	kmem_cache_destroy(manager->task_mem);
	manager->task_mem = NULL;

	cn_kfree(manager);
	sbts_set->efd_manager = NULL;
}

const char *unotify_type_str[EFD_TASK_TYPE_NUM] = {
	"CORE_DUMP_COMPLETE",
	"HOST_FUNCTION",
	"PRINTF_PROCESS",
	"GDB_PROCESS",
	"CORE_DUMP_DMA",
	"EFD_JPU_PROCESS",
};

void unotify_debug_read_efdinfo(
		struct cn_core_set *core,
		char *ops_val)
{
	struct sbts_set *sbts_set = NULL;
	struct sbts_efd_manager *manager = NULL;
	struct sbts_efd *efd_info = NULL;
	int i;

	sbts_set = core->sbts_set;
	manager = sbts_set->efd_manager;
	if (!write_trylock(&manager->rwlock)) {
		cn_dev_core_info(core, "Get rwLock fail, maybe read later");
		return;
	}

	cn_dev_core_info(core,
			"--------unotify efd_info debug out begin--------");
	list_for_each_entry(efd_info, &manager->efd_head, list) {
		cn_dev_core_info(core, "EFD[%llu] user:%#llx name:%s tgid:%d uefd:%d ref:%d task list is:%s",
				efd_info->idx, efd_info->user, efd_info->proc_name,
				efd_info->tgid, efd_info->user_efd,
				(int)SBTS_KREF_READ(&efd_info->ref_cnt),
				list_empty(&efd_info->task_list) ? "empty" : "not empty");
		for (i = 0; i < EFD_TASK_TYPE_NUM; i++) {
			cn_dev_core_info(core, "\t[%d]%s total:%llu inlist:%llu lmt_time:%llu read:%llu",
					i, unotify_type_str[i], efd_info->total_cnt[i],
					efd_info->task_cnt[i], efd_info->lmt_ctl_cnt[i],
					efd_info->read_cnt[i]);
		}
	}
	write_unlock(&manager->rwlock);
	cn_dev_core_info(core, "--------finish--------");
}

void unotify_debug_read_limitinfo(
		struct cn_core_set *core,
		char *ops_val)
{
	int i;

	for (i = 0; i < EFD_TASK_TYPE_NUM; i++) {
		cn_dev_core_info(core, "[%d]%s  limit:%d lmt_val:%u",
				i, unotify_type_str[i],
				efd_type_info[i].lmt_en,
				efd_type_info[i].lmt_cnt);
	}
}


void unotify_proc_debug_read(
		struct cn_core_set *core,
		char *ops_type, char *ops_val)
{
	if (!ops_type) {
		cn_dev_core_info(core, "Input Ops type is null");
		return;
	}

	if (!strncmp(ops_type, "efd_info", 8)) {
		unotify_debug_read_efdinfo(core, ops_val);
	} else if (!strncmp(ops_type, "g_lmt", 5)) {
		unotify_debug_read_limitinfo(core, ops_val);
	} else {
		cn_dev_core_info(core, "ops type <<%s>> not support", ops_type);
	}
}

void unotify_debug_set_lmt(
		struct cn_core_set *core, char *ops_val)
{
	char *tmp_buf;
	char *sep = ops_val;
	int type_idx = ~0;
	u32 new_limit = 1;

	tmp_buf = strsep(&sep, "#");
	if (kstrtoint(tmp_buf, 0, &type_idx) ||
			(type_idx >= EFD_TASK_TYPE_NUM)) {
		cn_dev_core_info(core, "task type input invalid %d", type_idx);
		return;
	}
	tmp_buf = sep;
	if (kstrtou32(tmp_buf, 0, &new_limit) ||
			(new_limit < EFD_TASK_NUM_MIN)) {
		cn_dev_core_info(core, "input new limit invalid %u", new_limit);
		return;
	}

	if (efd_type_info[type_idx].lmt_en == EFD_TASK_LIMIT_OFF) {
		cn_dev_core_warn(core, "input type %d is unlimit and will change",
				type_idx);
	}
	efd_type_info[type_idx].lmt_en = EFD_TASK_LIMIT_ON;
	efd_type_info[type_idx].lmt_cnt = new_limit;


	cn_dev_core_info(core, "set limit %u to type [%d]%s finish",
			new_limit, type_idx, unotify_type_str[type_idx]);
}

void unotify_debug_set_send_signal(
		struct cn_core_set *core, char *ops_val)
{
	struct sbts_set *sbts_set = NULL;
	struct sbts_efd_manager *manager = NULL;
	struct sbts_efd *efd_info = NULL;
	u64 target_idx;
	int ret;

	if (!ops_val) {
		cn_dev_core_info(core, "Input Ops val is null");
		return;
	}

	if (kstrtou64(ops_val, 0, &target_idx)) {
		cn_dev_info("input val invalid %s", ops_val);
		return;
	}

	sbts_set = core->sbts_set;
	manager = sbts_set->efd_manager;

	if (!write_trylock(&manager->rwlock)) {
		cn_dev_core_info(core, "Get rwLock fail, maybe read later");
		return;
	}
	list_for_each_entry(efd_info, &manager->efd_head, list) {
		if (efd_info->idx != target_idx)
			continue;

		ret = eventfd_signal(efd_info->ctx, 1ULL);
		cn_dev_core_info(core, "EFD[%llu] user:%#llx tgid:%d send debug signal ret %d",
				efd_info->idx, efd_info->user,
				efd_info->tgid, ret);
		break;
	}
	write_unlock(&manager->rwlock);
	cn_dev_core_info(core, "Send finish");
}

void unotify_proc_debug_set(
		struct cn_core_set *core,
		char *ops_type, char *ops_val)
{

	if (!ops_type) {
		cn_dev_core_info(core, "Input Ops type is null");
		return;
	}

	if (!strncmp(ops_type, "task_lmt", 8)) {
		unotify_debug_set_lmt(core, ops_val);
	} else if (!strncmp(ops_type, "send_signal", 11)) {
		unotify_debug_set_send_signal(core, ops_val);
	} else {
		cn_dev_core_info(core, "ops type <<%s>> not support", ops_type);
	}
}

int cn_sbts_unotify_debug_show(struct cn_core_set *core, struct seq_file *m)
{
	struct sbts_set *sbts_set = NULL;
	struct sbts_efd_manager *manager;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_info("core is null");
		return -EINVAL;
	}
	sbts_set = core->sbts_set;
	if (IS_ERR_OR_NULL(sbts_set)) {
		cn_dev_core_info(core, "sbts set is null");
		return -EINVAL;
	}
	manager = sbts_set->efd_manager;
	if (IS_ERR_OR_NULL(manager)) {
		cn_dev_core_info(core, "manager is null");
		return -EINVAL;
	}
	cn_dev_core_info(core, "unotify debug show");

	seq_printf(m, "ticket:      %llu\n\n", manager->ticket);
	seq_printf(m, "User list is %s\n", list_empty(&manager->efd_head) ?
				"empty" : " not empty");

	seq_puts(m, ">>>> DEBUG Commands <<<<\n");
	seq_puts(m, "echo read#efd_info#'index'\n");
	seq_puts(m, "echo read#g_lmt\n");
	seq_puts(m, "echo set#task_lmt#type_idx#value\n");
	seq_puts(m, "echo set#send_signal#'idx'\n");

	return 0;
}

#define EFD_DBG_STR_LEN 200
void cn_sbts_unotify_debug_write(
		struct cn_core_set *core,
		const char __user *user_buf,
		size_t count)
{
	struct sbts_set *sbts_set = NULL;
	struct sbts_efd_manager *manager;
	char cmd[EFD_DBG_STR_LEN];
	size_t cmd_size = min_t(size_t, count, EFD_DBG_STR_LEN);
	char *sep = cmd;
	char *ops_name, *ops_type, *ops_val;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_info("core is null");
		return;
	}
	sbts_set = core->sbts_set;
	if (IS_ERR_OR_NULL(sbts_set)) {
		cn_dev_core_info(core, "sbts set is null");
		return;
	}
	manager = sbts_set->efd_manager;
	if (IS_ERR_OR_NULL(manager)) {
		cn_dev_core_info(core, "manager is null");
		return;
	}
	cn_dev_core_info(core, "unotify debug write");

	memset(cmd, 0, EFD_DBG_STR_LEN);
	if (copy_from_user(cmd, user_buf, cmd_size))
		return;

	if (count < 4) {
		cn_dev_core_info(core, "User input str Too short : [%s]", cmd);
		return;
	}
	cmd[cmd_size - 1] = 0;

	cn_dev_core_info(core, "USER INPUT: [%s]", cmd);

	ops_name = strsep(&sep, "#");
	ops_type = strsep(&sep, "#");
	ops_val = sep;

	cn_dev_core_info(core, "ops name:<<%s>>  type:<<%s>>  val:<<%s>>\n",
			ops_name, ops_type, ops_val);

	if (!strncmp(ops_name, "read", 4)) {
		unotify_proc_debug_read(core, ops_type, ops_val);
	} else if (!strncmp(ops_name, "set", 3)) {
		unotify_proc_debug_set(core, ops_type, ops_val);
	} else {
		cn_dev_core_info(core, "ops name:<<%s>> not support", ops_name);
	}

}
