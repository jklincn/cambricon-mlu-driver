#ifndef __SMLU_CGROUP_H__
#define __SMLU_CGROUP_H__

#include <linux/atomic.h>

#include "cndrv_smlu.h"

/* same as MI_CAP for compatible of driver-api */
#define SMLU_CAP_GET_INSTANCE_PCIE_INFO	_IOR(0xc0, 0x1, struct bus_info_s)
#define SMLU_CAP_GET_INSTANCE_UNIQUE_ID	_IOR(0xc0, 0x2, uint64_t)

/* smlu_cap, aka smlu_partition, smlu_instance, which keep the quota/profile info */
struct smlu_cap {
	struct cnhost_minor *minor;
	int instance_id;
	int profile_id;
	struct list_head cap_node;
	struct cn_core_set *core;
	struct mutex open_lock;/* protect concurrency smlu_cap_open() to bind active_ns */
	/* actually, we can get res by smlu_set->profile_desc_info[smlu_cap->profile_id].profile_res, duplicated here */
	struct smlu_cgroup_res resources[SMLU_CGROUP_SUBSYS_COUNT];
};

struct smlu_cgroup {
	struct smlu_cap *smlu_cap;/* multi-docker open one smlu_cap node */
	struct rb_node ns_node;
	struct list_head pid_head;/* devfp */
	struct list_head vmm_pid_head;/* ctlfp */
	spinlock_t pid_lock;
	u64 ns_util;/* ipu_util of namespace */
	struct pid_namespace *active_ns; /* key of rbtree, needed to indicate this cap node is occupied, updated when opened */
};

#endif // __SMLU_CGROUP_H__
