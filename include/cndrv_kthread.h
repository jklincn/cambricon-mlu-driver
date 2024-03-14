#ifndef __CNDRV_KTHREAD_H__
#define __CNDRV_KTHREAD_H__

#include <linux/list.h>
#include <linux/sched.h>
#include "cndrv_core.h"

enum cn_kthread_type {
	CN_TIMER_GLOBAL, /* multiple MLUs share one kthread */
	CN_TIMER_PER_MLU,/* multiple tasks(on one MLU) share one kthread */
	CN_TIMER_PRIVATE,/* one task have one kthread */
	CN_LOOP_WAIT,    /* one task have one kthread and wait commu trigger */
};

struct cn_kthread_t {
	const char *name;
	long expire;
	void (*fn) (void *arg);
	void *arg;
	enum cn_kthread_type type;
};

/**
 * kthread_set is used to save the list node returned by kthread_register
 * function and the corresponding kthread name
 */
struct cn_kthread_set {
	struct list_head *node;
	char name[64];
};

struct kthread_status {
	int last_execution_duration;
	u64 last_end; /* caculate the interval between two adjacent executions */
	int interval_time;
	unsigned long total_execution;
};

struct cn_kthread_inner_t {
	struct cn_kthread_t t;
	unsigned long time;
	struct task_struct *kthread;
	struct list_head list;
	struct cn_core_set *core;
	struct kthread_status status;
};

extern struct list_head cn_global_list_head;

extern int cn_kthread_init(void);
extern void cn_kthread_exit(void);
extern int cn_kthread_late_init(struct cn_core_set *core);
extern void cn_kthread_late_exit(struct cn_core_set *core);

extern struct list_head *cn_timer_kthread_register(struct cn_core_set *core,
	struct cn_kthread_t *t);
extern void cn_timer_kthread_unregister(struct cn_core_set *core,
	struct list_head *list);
#endif
