#ifndef __CNDRV_SMLU_H__
#define __CNDRV_SMLU_H__

#include "cndrv_core.h"
#include "cndrv_cndev.h"//struct cndev_priv_data  cndev_card_memory_info()
#include "cndrv_monitor_usr.h"//struct cndev_smlu_cgroup_info
#include "cndrv_monitor.h"//file_is_cndev()
#include "smlu/drv/util.h"

#define MAX_SMLU_PROFILE_COUNT (16)
#define SMLU_MAX_OVERCOMMIT_FACTOR (50)

/* the new add should follow struct cndev_smlu_cgroup_res */
#define SMLU_CGROUP_LIST \
			SUBSYS(mem) \
			SUBSYS(ipu)

/* define the enumeration of all cgroup subsystems */
#define SUBSYS(_x) _x ## _cgrp_id,
enum smlu_cgroup_subsys_id {
	SMLU_CGROUP_LIST
	SMLU_CGROUP_SUBSYS_COUNT,
};
#undef SUBSYS

#define SMLU_AVERAGE_TOTAL 512

/* need to split to different resource types? */
struct smlu_cgroup_res {
	__u32 factor;/* (0 - 100) percentage for overcommit, "no float in kernel" rule */
	__u64 max;/* limited max */
	__u64 usage;/* current usage, for device memory it's bytes; for xPU, it's a bitmask */
	__u64 raw_usage; /* for xPU(now only ipu), store the raw data for accuracy */

	__u64 average; /* for cnmon show to user */
	__u64 head;
	__u64 total;
	__u64 average_t[SMLU_AVERAGE_TOTAL];
};

struct smlu_proc_info {
	union {
		struct proc_mem_info mem;
		struct cndev_process_ipuutil ipu;
		struct cndev_process_codecutil codec;
	};
};

struct smlu_profile_info {
	__u32 profile_id;
	__u32 total_capacity;
	__u32 remain_capacity;
	/* should be same with struct cndev_smlu_cgroup_info's cgroup_item */
	__u64 profile_res[SMLU_RES_COUNT][SMLU_ITEM_COUNT];
	char profile_name[CNDEV_MAX_PROFILE_NAME_SIZE];
};

#ifdef CONFIG_CNDRV_SMLU

/**
 * cn_smlu_cap_node_init(), per-instance. called while cnmon create smlu instance.
 *     smlu-cap node provide interface for smlu to add control group(s),
 *     a control group is a policy for resource(device memory, ipu, etc).
 */
int cn_smlu_cap_node_init(struct cn_core_set *core, struct cndev_smlu_cgroup_info *res);

/**
 * cn_smlu_cap_node_exit(), called while cnmon destroy smlu instance.
 *
 */
int cn_smlu_cap_node_exit(struct cn_core_set *core, int instance_id);

int cn_smlu_late_init(struct cn_core_set *core);

void cn_smlu_late_exit(struct cn_core_set *core);

int cn_smlu_private_data_init(struct file *fp, void *fp_private_data);

int cn_smlu_private_data_exit(struct file *fp, void *fp_private_data);

int smlu_cap_bind_namespace(struct cn_core_set *core);

int cn_smlu_try_charge(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
						void *fp, void *active_ns, __u64 usage);

void cn_smlu_uncharge(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
						void *fp, void *active_ns, __u64 usage);

/* quota & usage info */
int cn_smlu_query_namespace_quota(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			void *active_ns, struct smlu_cgroup_res *res);

/* pid usage info */
int cn_smlu_query_namespace_pid_info(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			struct smlu_proc_info *proc_info);

/* pid usage info */
int cn_smlu_query_namespace_pid_infos(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			u16 instance_id, int *num, struct smlu_proc_info *proc_info);

/* available profile id */
int cn_smlu_query_available_profile_id(struct cn_core_set *core, __u32 *profile_id, int *num);

/* profile info */
int cn_smlu_query_profile_info(struct cn_core_set *core, __u32 profile_id, struct smlu_profile_info *info);

/* new profile */
int cn_smlu_new_profile(struct cn_core_set *core, struct cndev_smlu_cgroup_info *res,
			struct smlu_profile_info *profile_info);

/* delete profile */
int cn_smlu_delete_profile(struct cn_core_set *core, __u32 profile_id);

/* quota & usage info */
int cn_smlu_query_instance(struct cn_core_set *core, struct cndev_smlu_cgroup_info *cgroup_info);

/* quota & usage info */
int cn_smlu_query_all_instances(struct cn_core_set *core, int *num, struct cndev_smlu_cgroup_info *cgroup_info);

int cn_core_set_smlu_mode(struct cn_core_set *core, int enable);

int cn_is_smlu_en(struct cn_core_set *core);

int cn_is_smlu_support(struct cn_core_set *core);

int cn_smlu_cap_show(struct seq_file *m, void *v);

void cn_smlu_get_sub_dev_info(struct cn_core_set *core, struct dev_info_s *sub_dev_info);

struct cn_core_set *cn_smlu_get_core(struct cnhost_minor *minor);

long cn_smlu_util_adjust_output(struct cn_core_set *core,
	void *smlu_cap, enum util_type type);

void cn_smlu_get_util_adjust_fn(struct cn_core_set *core);
void cn_smlu_put_util_adjust_fn(struct cn_core_set *core);
#else
static inline int cn_smlu_cap_node_init(struct cn_core_set *core, struct cndev_smlu_cgroup_info *res)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_cap_node_exit(struct cn_core_set *core, int instance_id)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_late_init(struct cn_core_set *core)
{
	return 0;
}

static inline void cn_smlu_late_exit(struct cn_core_set *core)
{
}

static inline int cn_smlu_private_data_init(struct file *fp, void *fp_private_data)
{
	return 0;
}

static inline int cn_smlu_private_data_exit(struct file *fp, void *fp_private_data)
{
	return 0;
}

static inline int smlu_cap_bind_namespace(struct cn_core_set *core)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_try_charge(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
						void *fp, void *active_ns, __u64 usage)
{
	return 0;/* not split */
}

static inline void cn_smlu_uncharge(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
						void *fp, void *active_ns, __u64 usage)
{
}

static inline int cn_smlu_query_namespace_quota(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			void *active_ns, struct smlu_cgroup_res *res)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_query_namespace_pid_info(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			struct smlu_proc_info *proc_info)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_query_namespace_pid_infos(struct cn_core_set *core, enum smlu_cgroup_subsys_id subsys,
			u16 instance_id, int *num, struct smlu_proc_info *proc_info)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_query_available_profile_id(struct cn_core_set *core, __u32 *profile_id, int *num)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_query_profile_info(struct cn_core_set *core, __u32 profile_id,
						struct smlu_profile_info *info)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_new_profile(struct cn_core_set *core, struct cndev_smlu_cgroup_info *res,
			struct smlu_profile_info *profile_info)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_delete_profile(struct cn_core_set *core, __u32 profile_id)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_query_instance(struct cn_core_set *core, struct cndev_smlu_cgroup_info *cgroup_info)
{
	return -EOPNOTSUPP;
}

static inline int cn_smlu_query_all_instances(struct cn_core_set *core,
			int *num, struct cndev_smlu_cgroup_info *cgroup_info)
{
	return -EOPNOTSUPP;
}

static inline int cn_core_set_smlu_mode(struct cn_core_set *core, int enable)
{
	return -EOPNOTSUPP;
}

static inline int cn_is_smlu_en(struct cn_core_set *core)
{
	return 0;
}

static inline int cn_is_smlu_support(struct cn_core_set *core)
{
	return 0;
}

static inline int cn_smlu_cap_show(struct seq_file *m, void *v)
{
	return -EOPNOTSUPP;
}
static inline void cn_smlu_get_sub_dev_info(struct cn_core_set *core, struct dev_info_s *sub_dev_info)
{
}

static inline struct cn_core_set *cn_smlu_get_core(struct cnhost_minor *minor)
{
	return NULL;
}

static inline long cn_smlu_util_adjust_output(struct cn_core_set *core,
	void *smlu_cap, enum util_type type)
{
	return 0;
}

static inline void cn_smlu_get_util_adjust_fn(struct cn_core_set *core)
{
	return;
}

static inline void cn_smlu_put_util_adjust_fn(struct cn_core_set *core)
{
	return;
}
#endif /* CONFIG_CNDRV_SMLU */

#endif // __CNDRV_SMLU_H__
