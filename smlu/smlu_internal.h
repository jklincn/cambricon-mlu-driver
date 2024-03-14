#ifndef __SMLU_V2_H__
#define __SMLU_V2_H__

#include "cndrv_debug.h"
#include "cndrv_smlu.h"

#include "smlu_cgroup.h"
#include "smlu_rbtree.h"

#define DEFAULT_SMLU_PROFILE_COUNT (3)
/* default profile: 1, 1/2, 1/4 */
static const int default_profile_spec[DEFAULT_SMLU_PROFILE_COUNT] = {1, 2, 4};


#define SUBSYS(_x) extern struct smlu_cgroup_subsys _x ## _cgrp_subsys;
SMLU_CGROUP_LIST
#undef SUBSYS

extern struct smlu_cgroup_subsys *smlu_cgroup_subsys[];

/**
 * smlu_for_each_subsys - iterate all enabled cgroup subsystems
 * @ss: the iteration cursor
 * @ssid: the index of @ss, SMLU_CGROUP_SUBSYS_COUNT after reaching the end
 */
#define smlu_for_each_subsys(ss, ssid)					\
	for ((ssid) = 0; (ssid) < SMLU_CGROUP_SUBSYS_COUNT &&		\
	     (((ss) = smlu_cgroup_subsys[ssid]) || true); (ssid)++)



/* cgroup callback */
struct smlu_cgroup_subsys {
	int (*css_init)(struct cn_core_set *core);
	int (*css_online)(struct cn_core_set *core);
	int (*css_offline)(struct cn_core_set *core);/* set to max */
	int (*css_try_charge)(struct cn_core_set *core, void *fp, void *active_ns, __u64 usage);
	void (*css_uncharge)(struct cn_core_set *core, void *fp, void *active_ns, __u64 usage);
	int (*css_exit)(struct cn_core_set *core);
};

struct smlu_profile_desc {
	__u32 profile_id;
	__u32 total_capacity;
	struct smlu_cgroup_res profile_res[SMLU_CGROUP_SUBSYS_COUNT];
	char profile_name[CNDEV_MAX_PROFILE_NAME_SIZE];
};

struct smlu_set {
	struct cn_core_set *core;
	struct rb_root ns_tree;/* protect by ns_rwsem */
	struct rw_semaphore ns_rwsem;
	struct list_head caps_head;/* protect by caps_lock, commit to ns_tree when opened */
	struct mutex caps_lock;
	struct ida instance_ida;
	/* ipu util update */
	u32 total_util;
	struct delayed_work util_worker;
	/* new add cgroup must < (total.max - total.usage), protect by quota_lock */
	struct smlu_cgroup_res total[SMLU_CGROUP_SUBSYS_COUNT];/* quota info */
	rwlock_t quota_lock;
	/* profile will support modified by user */
	struct smlu_profile_desc profile_desc_info[MAX_SMLU_PROFILE_COUNT];/* protect by profile_lock */
	struct mutex profile_lock;

	void *util_adjust_fn;
	void *util_output_fn;
};

struct smlu_priv_data {
	int num;
	struct pid_namespace *ns;
	struct smlu_cgroup *smlu_cgroup;
	/* dev_fp has only one item, ctl_fp has max items, collect mm & vmm at the same pid_info_s */
	struct pid_info_s *pid_info_node[0];
};

/* updata raw util data for cambricon-util_drv.ko */
struct smlu_util_data_raw {
	__u64 util_target;
	__u64 util_usage;
};

extern struct smlu_util_data_raw ex_util_data[MAX_PHYS_CARD][MAX_SMLU_INSTANCE_COUNT + 1][UTIL_TYPE_MAX];
int smlu_util_data_raw_update(struct smlu_cap *smlu_cap, enum util_type type);
/* updata raw util data for cambricon-util_drv.ko */

struct tid_cap_node *smlu_find_tid_cap_node(struct cn_core_set *core);

int smlu_cgroup_is_fp_valid(struct smlu_cgroup *smlu_cgroup, struct file *filp);

#endif // __SMLU_V2_H__
