#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>

#include "cndrv_kthread.h"
#include "cndrv_debug.h"

/* print warn message if any callback function executes more than 100ms */
#define CALLBACK_WARN_TIME (HZ / 10)

LIST_HEAD(cn_global_list_head);
static DEFINE_MUTEX(cn_global_lock);
static long cn_global_slice = 1000; /* default HZ for global thread */

struct list_head *cn_timer_kthread_register(struct cn_core_set *core,
	struct cn_kthread_t *t)
{
	struct cn_kthread_inner_t *new;

	if (core == NULL || t->expire <= 0 || t->fn == NULL)
		return NULL;

	new = cn_kzalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL)
		return NULL;

	memcpy(&new->t, t, sizeof(*t));
	INIT_LIST_HEAD(&new->list);
	new->core = core;

	cn_dev_core_info(core, "name=%s, expire=%ld, type=%d",
				new->t.name, new->t.expire, new->t.type);
	switch (t->type) {
	case CN_TIMER_GLOBAL:
		if ((new->t.expire / cn_global_slice) == 0) { /* TODO: global thread not support less than 1HZ */
			cn_dev_core_err(core, "kthread expire=%ld", new->t.expire);
			goto exit;
		}
		new->time = new->t.expire / cn_global_slice;

		mutex_lock(&cn_global_lock);
		list_add(&new->list, &cn_global_list_head);
		mutex_unlock(&cn_global_lock);
	break;
	case CN_TIMER_PER_MLU:
		mutex_lock(&core->kthread_lock);
		list_add(&new->list, &core->kthread_list);
		mutex_unlock(&core->kthread_lock);
	break;
	case CN_LOOP_WAIT: /* TODO */
	break;
	default:
		cn_dev_core_err(core, "kthread type=%d", t->type);
		goto exit;
	}

	return &new->list;

exit:
	cn_kfree(new);
	return NULL;
}

void cn_timer_kthread_unregister(struct cn_core_set *core,
	struct list_head *plist)
{
	struct cn_kthread_inner_t *p = list_entry(plist, struct cn_kthread_inner_t, list);
	enum cn_kthread_type type = p->t.type;

	if (core == NULL || plist == NULL)
		return;

	cn_dev_core_info(core, "name=%s, expire=%ld, type=%d",
				p->t.name, p->t.expire, p->t.type);
	switch (type) {
	case CN_TIMER_GLOBAL:
		mutex_lock(&cn_global_lock);
		list_del(plist);
		mutex_unlock(&cn_global_lock);
	break;
	case CN_TIMER_PER_MLU:
		mutex_lock(&core->kthread_lock);
		list_del(plist);
		mutex_unlock(&core->kthread_lock);
	break;
	case CN_LOOP_WAIT: /* TODO */
	break;
	default:
		cn_dev_core_err(core, "kthread type=%d", type);
	}
	cn_kfree(p);
}

static long greatest_common_divisor(long a, long b)
{
	while (a != b) {
		if (a > b)
			a = a - b;
		if (a < b)
			b = b - a;
	}
	return a;
}

static void __kthread_share_slice(struct cn_core_set *core)
{
	struct cn_kthread_inner_t *node, *tmp;
	long slice;

	mutex_lock(&core->kthread_lock);

	node = list_first_entry(&core->kthread_list, struct cn_kthread_inner_t, list);
	slice = node->t.expire;

	/* for example: 1000, 3000, 5000. slice will equal 1000 */
	list_for_each_entry_safe(node, tmp, &core->kthread_list, list) {
		slice = greatest_common_divisor(slice, node->t.expire);
	}
	core->slice = slice;

	/* update time for kthread loop cnt */
	list_for_each_entry_safe(node, tmp, &core->kthread_list, list) {
		node->time = node->t.expire / core->slice;
		cn_dev_core_info(core, "name=%s, expire=%ld, time=%ld, slice=%ld",
				node->t.name, node->t.expire, node->time, core->slice);
	}
	mutex_unlock(&core->kthread_lock);
}

static int cn_share_kthread_fn(void *arg)
{
	struct cn_core_set *core = (struct cn_core_set *)arg;
	unsigned long cnt = 0;
	u64 start, end;

	if (current->nr_cpus_allowed > 1)
		CN_CLEAR_CPUMASK(0);

	allow_signal(SIGKILL);
	while (!kthread_should_stop()) {
		struct cn_kthread_inner_t *node, *tmp;

		msleep_interruptible(core->slice);

		mutex_lock(&core->kthread_lock);
		list_for_each_entry_safe(node, tmp, &core->kthread_list, list) {
			if (cnt % node->time == 0) {
				start = get_jiffies_64();
				node->status.interval_time = jiffies_to_msecs(
					start - node->status.last_end);

				node->t.fn(node->t.arg); /* call back */

				end = get_jiffies_64();
				node->status.last_end = end;
				node->status.total_execution++;
				node->status.last_execution_duration = jiffies_to_msecs(end - start);

				if (time_after64(end, start + CALLBACK_WARN_TIME)) {
					cn_dev_core_warn(core, "execute %s spend too long time(%dms)",
						node->t.name, jiffies_to_msecs(end - start));
				}
			}
		}
		mutex_unlock(&core->kthread_lock);
		cnt++;
	}
	return 0;
}

static int __share_kthread_create(struct cn_core_set *core)
{
	int numa_id = cn_core_get_numa_node_by_core(core);
	struct task_struct *k = kthread_create_on_node(cn_share_kthread_fn,
				core, numa_id, "cn_kthread_share%d", core->idx);
	if (IS_ERR(k)) {
		cn_dev_core_err(core, "global kthread creat failed");
		return -1;
	}

	core->kthread = k;
	wake_up_process(k);
	return 0;
}

int cn_kthread_late_init(struct cn_core_set *core)
{
	int ret;

	if (list_empty(&core->kthread_list)) {
		cn_dev_core_info(core, "no kthread has been registered");
		return 0;
	}

	__kthread_share_slice(core);
	ret = __share_kthread_create(core);
	if (ret)
		return -1;

	return 0;
}

static void __share_kthread_destory(struct cn_core_set *core)
{
	send_sig(SIGKILL, core->kthread, 1);
	kthread_stop(core->kthread);
}

void cn_kthread_late_exit(struct cn_core_set *core)
{
	if (list_empty(&core->kthread_list))
		return;

	__share_kthread_destory(core);
}

/* global kthread create and destory */
static struct task_struct *cn_global_kthread;
static int cn_global_timer_kthread_fn(void *arg)
{
	struct cn_core_set *core;
	unsigned long cnt = 0;
	u64 start, end;

	if (current->nr_cpus_allowed > 1)
		CN_CLEAR_CPUMASK(0);

	allow_signal(SIGKILL);
	while (!kthread_should_stop()) {
		struct cn_kthread_inner_t *node, *tmp;

		msleep_interruptible(cn_global_slice); /* sleep default 1HZ */

		mutex_lock(&cn_global_lock);
		list_for_each_entry_safe(node, tmp, &cn_global_list_head, list) {
			if (cnt % node->time == 0) {
				core = node->core;
				start = get_jiffies_64();
				node->status.interval_time = jiffies_to_msecs(
					start - node->status.last_end);

				node->t.fn(node->t.arg); /* call back */

				end = get_jiffies_64();
				node->status.last_end = end;
				node->status.total_execution++;
				node->status.last_execution_duration = jiffies_to_msecs(end - start);

				if (time_after64(end, start + CALLBACK_WARN_TIME)) {
					cn_dev_core_warn(core, "execute %s spend too long time(%dms)",
						node->t.name, jiffies_to_msecs(end - start));
				}
			}
		}
		mutex_unlock(&cn_global_lock);
		cnt++;
	}
	return 0;
}

int cn_kthread_init(void)
{
	int arg;

	cn_global_kthread = kthread_run(cn_global_timer_kthread_fn, &arg, "cn_global_timer_kthread");
	if (IS_ERR(cn_global_kthread)) {
		pr_err("global kthread creat failed");
		return -1;
	}
	return 0;
}

void cn_kthread_exit(void)
{
	send_sig(SIGKILL, cn_global_kthread, 1);
	kthread_stop(cn_global_kthread);
}
