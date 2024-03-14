/*
 * core/cndrv_kwork.c
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

#include <linux/kthread.h>
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

#include "cndrv_kwork.h"
#include "cndrv_debug.h"

struct cn_kwork_set {
	struct cn_core_set *core;
	struct list_head kworkqueue_list;
	struct mutex kworkqueue_lock;
};

struct list_head* cn_get_core_workqueue_head(struct cn_core_set *core)
{
	struct cn_kwork_set *kwork_set = NULL;

	if (core && core->kwork_set) {
		kwork_set = (struct cn_kwork_set *)core->kwork_set;
		return &kwork_set->kworkqueue_list;
	}

	return NULL;
}

#define _cn_create_workqueue(_core, _name, _flags, _max_active, _is_single) \
	struct workqueue_struct *wq = NULL; \
	struct cn_kwork_set *kwork_set = NULL;\
	struct cn_kworkqueue_inner_t *new;\
	if (!(_core && _core->kwork_set)) {\
		cn_dev_core_err(_core, "work:%s core or kwork_set NULL", _name);\
		dump_stack(); \
		return NULL;\
	}\
	kwork_set = (struct cn_kwork_set *)_core->kwork_set;\
	new = cn_kzalloc(sizeof(*new), GFP_KERNEL);\
	if (new == NULL) {\
		return NULL;\
	}\
	if (_is_single) {\
		wq = create_singlethread_workqueue(_name);\
	} else {\
		wq = alloc_workqueue(_name, _flags, _max_active);\
	}\
	new->wq = wq;\
	snprintf(new->name, sizeof(new->name), _name);\
	mutex_lock(&kwork_set->kworkqueue_lock);\
	list_add(&new->list, &kwork_set->kworkqueue_list);\
	mutex_unlock(&kwork_set->kworkqueue_lock);\
	return wq;

struct workqueue_struct *cn_create_singlethread_workqueue(
	struct cn_core_set *core, const char *name)
{
	_cn_create_workqueue(core, name, 0, 0, 1);
}

struct workqueue_struct *cn_alloc_workqueue(
	struct cn_core_set *core, const char *name, unsigned int flags,
	int max_active)
{
	_cn_create_workqueue(core, name, flags, max_active, 0);
}

bool cn_schedule_work(struct cn_core_set *core,
	struct work_struct *work)
{
	return schedule_work(work);
}

void cn_destroy_workqueue(struct cn_core_set *core,
	struct workqueue_struct *wq)
{
	struct cn_kwork_set *kwork_set = NULL;
	struct mutex *k_lock = NULL;
	struct list_head *k_list = NULL;
	struct cn_kworkqueue_inner_t *kwork_i;
	struct cn_kworkqueue_inner_t *tmp;
	int find_cnt = 0;

	if (!(core && core->kwork_set)) {
		cn_dev_core_err(core, "Core or kwork_set NULL");
		dump_stack();
		return;
	}

	kwork_set = (struct cn_kwork_set *)core->kwork_set;
	k_lock = &kwork_set->kworkqueue_lock;
	k_list = &kwork_set->kworkqueue_list;

	mutex_lock(k_lock);
	list_for_each_entry_safe(kwork_i, tmp, k_list, list) {
		if (kwork_i->wq == wq) {
			list_del(&kwork_i->list);
			cn_kfree(kwork_i);
			find_cnt++;
		}
	}
	mutex_unlock(k_lock);

	destroy_workqueue(wq);
	if (find_cnt != 1) {
		cn_dev_core_err(core, "work find_cnt:%d", find_cnt);
		dump_stack();
	}
}

int cn_kwork_init(void)
{
	return 0;
}

void cn_kwork_exit(void)
{
}

int cn_kwork_mlu_init(struct cn_core_set *core)
{
	struct cn_kwork_set *kwrok_set;

	kwrok_set = cn_kzalloc(sizeof(struct cn_kwork_set), GFP_KERNEL);
	if (!kwrok_set) {
		cn_dev_core_err(core, "kzalloc kwrok_set error!");
		return -ENOMEM;
	}

	mutex_init(&kwrok_set->kworkqueue_lock);
	INIT_LIST_HEAD(&kwrok_set->kworkqueue_list);

	core->kwork_set = (void *)kwrok_set;

	return 0;
}

void cn_kwork_mlu_exit(struct cn_core_set *core)
{
	struct cn_kwork_set *kwrok_set = (struct cn_kwork_set *)core->kwork_set;
	struct cn_kworkqueue_inner_t *kwork_i;
	struct cn_kworkqueue_inner_t *tmp;

	mutex_lock(&kwrok_set->kworkqueue_lock);
	if (!list_empty(&kwrok_set->kworkqueue_list)) {
		list_for_each_entry_safe(kwork_i, tmp, &kwrok_set->kworkqueue_list, list) {
			cn_dev_core_err(core, "work:%s core NULL", kwork_i->name);
		}
	}

	mutex_unlock(&kwrok_set->kworkqueue_lock);
	cn_kfree(core->kwork_set);
}
