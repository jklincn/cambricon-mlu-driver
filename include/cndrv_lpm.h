/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2020 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CNDRV_LPM_H__
#define __CNDRV_LPM_H__

struct seq_file;

/*
 * ALL Hw type of lpm managed.
 *     it's bitmap enum, for easy use:
 *     such as: cn_lpm_get(core, LPM_MODULE_TYPE_IPU | LPM_MODULE_TYPE_XXX);
 *     this example means exit lpm for IPU And XXX.
 */
enum cn_lpm_module_type {
	LPM_MODULE_TYPE_IPU = 1 << 0,
	/* keep type all at the last, and modify it's shift bits */
	LPM_MODULE_TYPE_ALL = 1 << 1,
};

struct lpm_module_ops {
	int (*suspend)(struct cn_core_set *core);
	int (*resume)(struct cn_core_set *core);
	void (*show)(struct cn_core_set *core, struct seq_file *m);
};

/* Lpm status interface:
 */
extern bool cn_lpm_is_resumed(struct cn_core_set *core);

/*
 * Register and unregister interface:
 *      For add resume\suspend\mode_switch\show ops for specific module.
 */
extern int cn_lpm_register(struct cn_core_set *core, enum cn_lpm_module_type type,
	const struct lpm_module_ops *module_ops);
extern int cn_lpm_unregister(struct cn_core_set *core, enum cn_lpm_module_type type);

/*
 * Lpm resume or suspend interface:
 *     lpm get: means exit low power(resume)
 *     lpm put: means entry low power(suspend)
 *     lpm put cnt: means entry low power(suspend), and ref count will sub cnt, not dec.
 *                  For cn_lpm_get is called several times but only call cn_lpm_put_cnt once.
 *                  Supporting count is 0.
 *
 * * param @cn_lpm_module_type is enum cn_lpm_module_type!
 */
extern int cn_lpm_get(struct cn_core_set *core, u32 cn_lpm_module_type);
extern int cn_lpm_put(struct cn_core_set *core, u32 cn_lpm_module_type);
extern int cn_lpm_put_cnt(struct cn_core_set *core, u32 cn_lpm_module_type, u64 cnt);

/*
 * Lpm resume or suspend with condition interface:
 *     These interface will be called only when the condition is true, or just return success.
 *     For the caller can easy resume or suspend according to condition.
 *     Such as cn_lpm_get called by cn_core_open should not excute when lpm mode is task mode.
 *
 * param @cn_lpm_module_type is enum cn_lpm_module_type
 */
static inline int cn_lpm_get_with_cond(struct cn_core_set *core, u32 lpm_module_type, bool condition)
{
	if (!condition) {
		return 0;
	}

	return cn_lpm_get(core, lpm_module_type);
}

static inline int cn_lpm_put_with_cond(struct cn_core_set *core, u32 lpm_module_type, bool condition)
{
	if (!condition) {
		return 0;
	}

	return cn_lpm_put(core, lpm_module_type);
}

static inline int cn_lpm_put_cnt_with_cond(struct cn_core_set *core, u32 lpm_module_type, u64 cnt, bool condition)
{
	if (!condition) {
		return 0;
	}

	return cn_lpm_put_cnt(core, lpm_module_type, cnt);
}

/*
 * Easy Interface for Caller:
 *     cn_lpm_get/put_all_module: To exit/entry low power for all module.
 *     cn_lpm_put_cnt_all_module: entry lowpower with count.
 *     cn_lpm_get_all_module_with_cond: exit lowpower conditional.
 *     cn_lpm_put_all_module_with_cond: entry lowpower conditional.
 */
static inline int cn_lpm_get_all_module(struct cn_core_set *core)
{
	return cn_lpm_get(core, LPM_MODULE_TYPE_ALL);
}

static inline int cn_lpm_put_all_module(struct cn_core_set *core)
{
	return cn_lpm_put(core, LPM_MODULE_TYPE_ALL);
}

static inline int cn_lpm_put_cnt_all_module(struct cn_core_set *core, u64 count)
{
	return cn_lpm_put_cnt(core, LPM_MODULE_TYPE_ALL, count);
}

static inline int cn_lpm_get_all_module_with_cond(struct cn_core_set *core, bool condition)
{
	return cn_lpm_get_with_cond(core, LPM_MODULE_TYPE_ALL, condition);
}

static inline int cn_lpm_put_all_module_with_cond(struct cn_core_set *core, bool condition)
{
	return cn_lpm_put_with_cond(core, LPM_MODULE_TYPE_ALL, condition);
}

static inline int cn_lpm_put_cnt_all_module_with_cond(struct cn_core_set *core, u64 cnt, bool condition)
{
	return cn_lpm_put_cnt_with_cond(core, LPM_MODULE_TYPE_ALL, cnt, condition);
}

/* 
 * Init interface:
 *     cn_lpm_init: called when driver load.
 *     cn_lpm_exit: called when driver unload.
 *     cn_lpm_late_init: called when late init.
 *     cn_lpm_late_exit: called when late exit.
 */
extern int cn_lpm_init(struct cn_core_set *core);
extern void cn_lpm_exit(struct cn_core_set *core);
extern int cn_lpm_late_init(struct cn_core_set *core);
extern void cn_lpm_late_exit(struct cn_core_set *core);

/* 
 * Interface for proc:
 *      cn_lpm_info_show: show current lpm info include module info.
 */
extern int cn_lpm_info_show(struct seq_file *m, struct cn_core_set *core);

#endif

