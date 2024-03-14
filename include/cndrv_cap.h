#ifndef __CNDRV_CAP_H__
#define __CNDRV_CAP_H__

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_domain.h"

struct tid_cap_node {
	struct list_head list;
	struct cn_core_set *core;
	struct inode *inode;
	pid_t pid;
};

struct mi_cap_fp_priv_data {
	struct cn_core_set *core;
	struct cnhost_minor *minor;
	struct tid_cap_node *tid_cap_node;
};

int cn_mi_cap_node_init(struct cn_core_set *mi_core);
void cn_mi_cap_node_exit(struct cn_core_set *mi_core);

int cn_mi_cap_node_late_init(struct cn_core_set *mi_core);
void cn_mi_cap_node_late_exit(struct cn_core_set *mi_core);


#endif /* __CNDRV_CAP_H__ */
