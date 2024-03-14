/*
 * lpm/cndrv_lpm.c
 *
 * NOTICE:
 * Copyright (C) 2020 Cambricon, Inc. All rights reserved.
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
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/bitops.h>

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_lpm.h"
#include "cndrv_os_compat.h"

#define LPM_OPS_TIMEOUT	(20 << 20)

enum lpm_status {
	LPM_RESUMED = 0,
	LPM_RESUMING,
	LPM_SUSPENDING,
	LPM_SUSPENDED,
};

struct cn_lpm_module {
	struct list_head entry;
	atomic64_t ref_count;
	u32 module_type;
	u32 suspend_error;
	u32 resume_error;

	volatile enum lpm_status status;
	const struct lpm_module_ops *ops;
};

struct cn_lp_manager {
	atomic64_t count;
	struct cn_core_set *core;
	struct mutex proc_lock;
	u32 module_count;
	struct cn_lpm_module *module;
};

static inline bool
cn_lpm_support(struct cn_core_set *core)
{
	if (isPCIeArmPlatform(core)) {
		cn_dev_core_debug(core, "not support lpm in mlu dev.\n");
		return false;
	}

	/* do init if pf-only or vf */
	if (!cn_core_is_vf(core) && cn_is_mim_en(core)) {
		cn_dev_core_debug(core, "not pf-only or vf");
		return false;
	}

	return true;
}

static inline void
__update_status(struct cn_lpm_module *lp_mod, enum lpm_status new)
{
	__sync_lock_test_and_set(&lp_mod->status, new);
}

static inline bool
__update_status_with_cond(struct cn_lpm_module *lp_mod,
		enum lpm_status old, enum lpm_status new)
{
	return __sync_bool_compare_and_swap(&lp_mod->status, old, new);
}

static int
cn_lpm_module_resume(struct cn_core_set *core, struct cn_lpm_module *lp_mod, u64 count)
{
	int ret = 0;
	int time = LPM_OPS_TIMEOUT;

	atomic64_add(count, &lp_mod->ref_count);

	/* memory order of count and status */
	smp_mb();

retry:
	if (lp_mod->status == LPM_RESUMED)
		return 0;

	if (__update_status_with_cond(lp_mod, LPM_SUSPENDED, LPM_RESUMING)) {
		if (lp_mod->ops) {
			ret = lp_mod->ops->resume(core);
			if (ret) {
				lp_mod->resume_error++;
				atomic64_sub(count, &lp_mod->ref_count);
				__update_status(lp_mod, LPM_SUSPENDED);
				cn_dev_core_err(core, "lpm module %u resume failed!", lp_mod->module_type);
				return ret;
			}
		}

		__update_status(lp_mod, LPM_RESUMED);
		return 0;
	}

	/* Wait for the other resume suspend running in parallel with us. */
	while (time) {
		usleep_range(20, 30);

		if ((lp_mod->status == LPM_RESUMED) ||
				(lp_mod->status == LPM_SUSPENDED))
			goto retry;

		time--;
	}

	cn_dev_core_err(core, "waiting %u resuming timeout!", lp_mod->module_type);

	atomic64_sub(count, &lp_mod->ref_count);
	return -ETIMEDOUT;
}

static int
cn_lpm_module_suspend(struct cn_core_set *core, struct cn_lpm_module *lp_mod, u64 count)
{
	int ret = 0;

	if (!atomic64_sub_and_test(count, &lp_mod->ref_count)) {
		if (atomic64_read(&lp_mod->ref_count) < 0) {
			cn_dev_core_err(core, "module count sub %llu to be negtive!", count);
			BUG_ON(1);
		}
		return 0;
	}

	/* memory order of count and status */
	smp_mb();

	if (!__update_status_with_cond(lp_mod, LPM_RESUMED, LPM_SUSPENDING))
		return 0;

	if (atomic64_read(&lp_mod->ref_count)) {
		__update_status(lp_mod, LPM_RESUMED);
		return 0;
	}

	if (lp_mod->ops) {
		ret = lp_mod->ops->suspend(core);
		if (ret) {
			lp_mod->suspend_error++;
			__update_status(lp_mod, LPM_RESUMED);
			cn_dev_core_err(core, "lpm module %u suspend failed!", lp_mod->module_type);
			return ret;
		}
	}

	__update_status(lp_mod, LPM_SUSPENDED);
	return 0;
}

static int
cn_lpm_resume(struct cn_lp_manager *lp_mgr, u32 lpm_module_type, u64 count)
{
	int module_index = -1;
	struct cn_core_set *core = lp_mgr->core;
	struct cn_lpm_module *cur_module;
	ulong type = lpm_module_type;

	/* for handle all module type */
	if (lpm_module_type == LPM_MODULE_TYPE_ALL) {
		type = LPM_MODULE_TYPE_ALL - 1;
	}

	for (module_index = 0; module_index < lp_mgr->module_count; module_index++) {
		cur_module = &lp_mgr->module[module_index];

		if (test_bit(module_index, (const volatile unsigned long *)&type)) {
			if (cn_lpm_module_resume(core, cur_module, count)) {
				cn_dev_core_err(core, "module %d resume failed", module_index);
				module_index--;
				goto module_err;
			}
		}
	}

	return 0;

module_err:
	for (; module_index >= 0; module_index--) {
		cur_module = &lp_mgr->module[module_index];
		if (test_bit(module_index, (const volatile unsigned long *)&type)) {
			cn_lpm_module_suspend(core, cur_module, count);
		}
	}

	return -EFAULT;
}

static int
cn_lpm_suspend(struct cn_lp_manager *lp_mgr, u32 lpm_module_type, u64 count)
{
	int module_index = -1;
	struct cn_core_set *core = lp_mgr->core;
	struct cn_lpm_module *cur_module;
	ulong type = lpm_module_type;

	/* for handle all module type */
	if (lpm_module_type == LPM_MODULE_TYPE_ALL) {
		type = LPM_MODULE_TYPE_ALL - 1;
	}

	for (module_index = 0; module_index < lp_mgr->module_count; module_index++) {
		cur_module = &lp_mgr->module[module_index];

		if (test_bit(module_index, (const volatile unsigned long *)&type)) {
			if (cn_lpm_module_suspend(core, cur_module, count)) {
				cn_dev_core_err(core, "module %d suspend failed", module_index);
				module_index--;
				goto module_err;
			}
		}
	}

	return 0;

module_err:
	for (; module_index >= 0; module_index--) {
		cur_module = &lp_mgr->module[module_index];
		if (test_bit(module_index, (const volatile unsigned long *)&type)) {
			cn_lpm_module_resume(core, cur_module, count);
		}
	}

	return -EFAULT;
}

int cn_lpm_get(struct cn_core_set *core, u32 lpm_module_type)
{
	int ret;
	struct cn_lp_manager *lp_mgr;

	if (!core) {
		cn_dev_debug("core is NULL!");
		return -EINVAL;
	}

	/* return sucess when lpm function disable.
	 * current must be before atomic64_inc(&lp_mgr->count)!
	 * because of this is for proc switch lpm enable or disable.
	 */
	if (!cn_core_lpm_enable()) {
		return 0;
	}

	/* support lpm or not */
	if (!cn_lpm_support(core)) {
		cn_dev_core_debug(core, "not support lpm");
		return 0;
	}

	if (lpm_module_type > LPM_MODULE_TYPE_ALL) {
		cn_dev_core_err(core, "lpm module type %d is illegal", lpm_module_type);
		return -EINVAL;
	}

	if (lpm_module_type == 0) {
		cn_dev_core_debug(core, "need not suspend any module.");
		return 0;
	}

	if (core->reset_flag) {
		cn_dev_core_err(core, "core reset flag has been set");
		return -EINVAL;
	}

	lp_mgr = core->lpm_set;
	if (!lp_mgr) {
		cn_dev_core_err(core, "low power manager is NULL");
		return -EINVAL;
	}

	atomic64_inc(&lp_mgr->count);

	ret = cn_lpm_resume(lp_mgr, lpm_module_type, 1);
	if (ret) {
		cn_dev_core_err(core, "cn lpm module %d resume failed!", lpm_module_type);
		atomic64_dec(&lp_mgr->count);
	}

	return ret;
}

int cn_lpm_put_cnt(struct cn_core_set *core, u32 lpm_module_type, u64 count)
{
	int ret;
	struct cn_lp_manager *lp_mgr;

	if (!core) {
		cn_dev_debug("core is NULL!");
		return -EINVAL;
	}

	/* return sucess when lpm function disable */
	if (!cn_core_lpm_enable()) {
		return 0;
	}

	/* support lpm or not */
	if (!cn_lpm_support(core)) {
		cn_dev_core_debug(core, "not support lpm");
		return 0;
	}

	if (lpm_module_type > LPM_MODULE_TYPE_ALL) {
		cn_dev_core_err(core, "lpm module type %d is illegal", lpm_module_type);
		return -EINVAL;
	}

	if (lpm_module_type == 0) {
		cn_dev_core_debug(core, "need not suspend any module.");
		return 0;
	}

	if (core->reset_flag) {
		cn_dev_core_err(core, "core reset flag has been set");
		return -EINVAL;
	}

	lp_mgr = core->lpm_set;
	if (!lp_mgr) {
		cn_dev_core_debug(core, "low power manager is NULL");
		return -EINVAL;
	}

	/* param @count maybe is zero, here just return success. */
	if (count == 0) {
		return 0;
	}

	atomic64_sub(count, &lp_mgr->count);

	ret = cn_lpm_suspend(lp_mgr, lpm_module_type, count);
	if (ret) {
		cn_dev_core_err(core, "cn lpm module %d suspend failed!", lpm_module_type);
	}

	return ret;
}

int cn_lpm_put(struct cn_core_set *core, u32 lpm_module_type)
{
	return cn_lpm_put_cnt(core, lpm_module_type, 1);
}

int cn_lpm_register(struct cn_core_set *core, enum cn_lpm_module_type type,
		const struct lpm_module_ops *module_ops)
{
	int module_index;
	struct cn_lp_manager *lp_mgr;
	struct cn_lpm_module *cur_module;
	unsigned long cur_type = type;

	if (!core) {
		cn_dev_err("core is NULL!");
		return -EINVAL;
	}

	/* support lpm or not */
	if (!cn_lpm_support(core)) {
		cn_dev_core_debug(core, "not support lpm");
		return 0;
	}

	lp_mgr = core->lpm_set;
	if (!lp_mgr) {
		cn_dev_core_err(core, "low power manager is NULL");
		return -EINVAL;
	}

	if (type >= LPM_MODULE_TYPE_ALL) {
		cn_dev_core_err(core, "lpm module type %d is illegal!", type);
		return -EINVAL;
	}

	if ((!module_ops) || (!module_ops->suspend) || (!module_ops->resume)) {
		cn_dev_core_err(core, "lpm module %d ops is NULL!", type);
		return -EINVAL;
	}

	module_index = find_next_bit((const unsigned long *)&cur_type, 32, 0);
	cur_module = (struct cn_lpm_module *)&lp_mgr->module[module_index];

	if (cur_module->ops) {
		cn_dev_core_err(core, "module %d has register before!", type);
		return -EINVAL;
	}

	cur_module->module_type = type;
	cur_module->ops = module_ops;

	return 0;
}

int cn_lpm_unregister(struct cn_core_set *core, enum cn_lpm_module_type type)
{
	int module_index;
	struct cn_lp_manager *lp_mgr;
	struct cn_lpm_module *cur_module;
	unsigned long cur_type = type;

	if (!core) {
		cn_dev_err("core is NULL!");
		return -EINVAL;
	}

	if (type >= LPM_MODULE_TYPE_ALL) {
		cn_dev_core_err(core, "lpm module type %d is illegal!", type);
		return -EINVAL;
	}

	/* support lpm or not */
	if (!cn_lpm_support(core)) {
		cn_dev_core_debug(core, "not support lpm");
		return 0;
	}

	lp_mgr = core->lpm_set;
	if (!lp_mgr) {
		cn_dev_core_err(core, "low power manager is NULL");
		return -EINVAL;
	}

	module_index = find_next_bit((const unsigned long *)&cur_type, 32, 0);
	cur_module = (struct cn_lpm_module *)&lp_mgr->module[module_index];
	if (!cur_module->ops) {
		cn_dev_core_err(core, "module %d not register or has unregister before!", type);
		return -EINVAL;
	}

	cur_module->ops = NULL;

	return 0;
}

bool cn_lpm_is_resumed(struct cn_core_set *core)
{
	struct cn_lp_manager *lp_mgr;

	if (!core) {
		cn_dev_err("core is NULL!");
		return true;
	}

	/* support lpm or not */
	if (!cn_lpm_support(core)) {
		cn_dev_core_debug(core, "not support lpm");
		return true;
	}

	lp_mgr = core->lpm_set;
	if (!lp_mgr) {
		cn_dev_core_err(core, "low power manager is NULL");
		return true;
	}

	return (atomic64_read(&lp_mgr->count) > 0);
}

int cn_lpm_late_init(struct cn_core_set *core)
{
	return cn_lpm_put(core, LPM_MODULE_TYPE_ALL);
}

void cn_lpm_late_exit(struct cn_core_set *core)
{
	cn_lpm_get(core, LPM_MODULE_TYPE_ALL);
}

int cn_lpm_init(struct cn_core_set *core)
{
	int module_index;
	int module_count;
	struct cn_lp_manager *lp_mgr;
	struct cn_lpm_module *module, *cur_module;
	unsigned long type = LPM_MODULE_TYPE_ALL;

	if (!core) {
		cn_dev_err("core is NULL!");
		return -EINVAL;
	}

	/* support lpm or not */
	if (!cn_lpm_support(core)) {
		cn_dev_core_debug(core, "not support lpm");
		return 0;
	}

	lp_mgr = (struct cn_lp_manager *)cn_kzalloc(sizeof(struct cn_lp_manager),
				GFP_KERNEL);
	if (!lp_mgr) {
		cn_dev_core_err(core, "malloc low power manager fail");
		return -ENOMEM;
	}

	module_count = find_next_bit((const unsigned long *)&type, 32, 0);
	module = (struct cn_lpm_module *)cn_kzalloc(sizeof(struct cn_lpm_module) * module_count,
				GFP_KERNEL);
	if (!module) {
		cn_dev_core_err(core, "malloc low power manager module fail");
		cn_kfree(lp_mgr);
		return -ENOMEM;
	}

	lp_mgr->module_count = module_count;
	atomic64_set(&lp_mgr->count, 1);
	lp_mgr->core = core;
	mutex_init(&lp_mgr->proc_lock);
	lp_mgr->module = module;

	for (module_index = 0; module_index < lp_mgr->module_count; module_index++) {
		cur_module = &lp_mgr->module[module_index];

		INIT_LIST_HEAD(&cur_module->entry);
		cur_module->suspend_error = 0;
		cur_module->resume_error = 0;
		cur_module->status = LPM_RESUMED;
		cur_module->ops = NULL;
		atomic64_set(&cur_module->ref_count, 1);
	}

	core->lpm_set = lp_mgr;

	return 0;
}

void cn_lpm_exit(struct cn_core_set *core)
{
	int time = 100, module_index;
	struct cn_lp_manager *lp_mgr = core->lpm_set;
	struct cn_lpm_module *cur_module;

	if (!cn_lpm_support(core))
		return;

	if (!lp_mgr) {
		cn_dev_core_err(core, "low power manager is NULL");
		return;
	}

	/* wait if some module is busy */
	while (atomic64_read(&lp_mgr->count) > 1) {
		msleep(100);
		time--;
		if (!time) {
			cn_dev_core_err(core, "wait low power count(%lld) clear timeout",
					(u64)atomic64_read(&lp_mgr->count));
			break;
		}
	}

	for (module_index = 0; module_index < lp_mgr->module_count; module_index++) {
		cur_module = &lp_mgr->module[module_index];

		/* handle unregister module */
		if (cur_module->ops) {
			cn_dev_core_err(core, "module %d: suspend error %d, resume error %d, lpm status %d",
					cur_module->module_type, cur_module->suspend_error, cur_module->resume_error,
					cur_module->status);
			cur_module->ops = NULL;
		}
	}

	cn_kfree(lp_mgr->module);
	cn_kfree(core->lpm_set);
}

/*
 * lpm proc function: show/write
 *     cn_lpm_info_show: for show current lpm and module status
 */
int cn_lpm_info_show(struct seq_file *m, struct cn_core_set *core)
{
	int module_index;
	struct cn_lp_manager *lp_mgr;
	struct cn_lpm_module *cur_module;

	if (!core) {
		cn_dev_err("core is NULL!");
		return -EINVAL;
	}

	if (!m) {
		cn_dev_core_err(core, "seq file is NULL!");
		return -EINVAL;
	}

	/* support lpm or not */
	if (!cn_lpm_support(core)) {
		cn_dev_core_debug(core, "not support lpm");
		return -EINVAL;
	}

	lp_mgr = core->lpm_set;
	if (!lp_mgr) {
		cn_dev_core_err(core, "low power manager is NULL");
		return -EINVAL;
	}

	seq_puts(m, "==== low power manager info ===\n");
	seq_printf(m, "low power manager enable %d\n", (u32)cn_core_lpm_enable());
	seq_printf(m, "current used count %lld\n", (u64)atomic64_read(&lp_mgr->count));
	seq_printf(m, "sub module count is %d\n", (u32)lp_mgr->module_count);

	seq_puts(m, "==== low power sub module ===\n");
	for (module_index = 0; module_index < lp_mgr->module_count; module_index++) {
		cur_module = &lp_mgr->module[module_index];
		seq_printf(m, "module %d\n", cur_module->module_type);
		seq_printf(m, "suspend error %d\n", cur_module->suspend_error);
		seq_printf(m, "resume error %d\n", cur_module->resume_error);
		seq_printf(m, "status %d\n", cur_module->status);
		/* Note: when proc show current information, maybe the ref_count is not zero.
		 *    cn_lpm_get has been called when proc open at mlu370 or ce,
		 *    so the cur_module->ref_count will not zero, it's not bug.
		 */
		seq_printf(m, "used count %lld\n", (u64)atomic64_read(&cur_module->ref_count));

		if (!cur_module->ops) {
			continue;
		}

		if (cur_module->ops->show)
			cur_module->ops->show(core, m);
	}

	return 0;
}
