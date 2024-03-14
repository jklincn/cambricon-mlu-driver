/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_MM_TOOLS_H__
#define __CAMBRICON_MM_TOOLS_H__

#include <linux/radix-tree.h>
#include <linux/kfifo.h>

/* Memory Dump */
#define MMB(val) (unsigned long)((val) >> 20)
#define MKB(val) (unsigned long)((val) >> 10)
#define MGB(val) (unsigned long)((val) >> 30)

#define MEMTOOLS_PROC(s, str, args...) \
	seq_printf(s, str"\n", ##args)

#define MEMTOOLS_LOG(str, args...) \
	cn_dev_core_err((struct cn_core_set *)mm_set->core, "[%d] " str, current->tgid, ##args)

#define MEMTOOLS_PROC_LOG(s, str, args...) \
({ \
	if (s) { \
		MEMTOOLS_PROC(s, str, ##args); \
	} else { \
		MEMTOOLS_LOG(str, ##args); \
	} \
})

enum free_timestamp_type {
	FREE_TS_CALLFREE = 0x0,
	FREE_TS_ZEROREFCNT = 0x1,
	FREE_TS_READY_CALLRPC = 0x2,
	FREE_TS_RPC_RETURNED = 0x3,
	FREE_TS_END,
};

static inline const char *timestamp_str(enum free_timestamp_type type)
{
	switch (type) {
	case FREE_TS_CALLFREE:      return "User Free";
	case FREE_TS_ZEROREFCNT:    return "Zero refcount";
	case FREE_TS_READY_CALLRPC: return "Send RPC";
	case FREE_TS_RPC_RETURNED:  return "RPC return";
	default: break;
	}

	return NULL;
}

struct free_ts_address {
	dev_addr_t address;
	unsigned long size;
	/* use bit field to reduce memory used for saved memory attributes */
	struct {
		unsigned long islinear : 1;
		unsigned long node     : 4;
		unsigned long type     : 4;
		unsigned long prot     : 32;
	};
	char name[EXT_NAME_SIZE];
};

struct free_ts_node {
	struct list_head node;
	u64 timestamps[FREE_TS_END];

	/* process information */
	char comm[TASK_COMM_LEN];
	unsigned int tgid;

	/* address information */
	struct free_ts_address info;
};

#if defined(CONFIG_CNDRV_PCIE_PLATFORM)
#define DEFAULT_KFIFO_LENGTH (512)
#else
#define DEFAULT_KFIFO_LENGTH (64)
#endif

struct free_ts_root {
	/* unfree node list */
	struct radix_tree_root ra_root;
	struct list_head list;
	spinlock_t lock;

	/* backing ringbuffer */
	spinlock_t fifo_lock;
	struct kfifo backing_fifo;
	struct free_ts_node **backing_buf;
	bool enable;
};

struct free_failure_node {
	dev_addr_t dev_vaddr;
	struct mem_attr mem_meta;
	int rpc_ret;
	bool mem_sync_commu_point;
	struct list_head list;
};

struct mapinfo;
struct cn_mm_set;
struct dbg_base_meminfo_t;

void camb_free_ts_node_init(struct mapinfo *pminfo);

void camb_free_ts_node_record(struct mapinfo *pminfo, enum free_timestamp_type type);

void camb_free_ts_node_record_and_saved(struct mapinfo *pminfo,
				enum free_timestamp_type type);

void camb_free_ts_dump_nonfree(struct cn_mm_set *mm_set, struct seq_file *s);

void camb_free_ts_fifo_dump(struct cn_mm_set *mm_set, struct seq_file *s);

int camb_free_ts_fifo_clear(struct cn_mm_set *mm_set);

int camb_free_ts_switch(struct cn_mm_set *mm_set, bool enabled);

int camb_free_ts_init(struct cn_mm_set *mm_set);

void camb_free_ts_deinit(struct cn_mm_set *mm_set);

int camb_config_redzone_size(struct file *fp, struct cn_mm_set *mm_set,
			struct mapinfo *pminfo, unsigned long *allocated_size, bool is_fa);
int camb_set_redzone(struct file *fp, struct mapinfo *pminfo,
			struct cn_mm_set *mm_set);
int camb_check_redzone(struct file *fp, struct mapinfo *pminfo,
			struct cn_mm_set *mm_set);

int camb_dump_error_minfo(u64 tag, struct mem_attr *pattr,
			struct cn_mm_set *mm_set, int errcode,
			struct dbg_base_meminfo_t *info);

void camb_dump_process_list(struct cn_mm_set *mm_set, struct seq_file *s);
void camb_dump_public_rbtree(struct cn_mm_set *mm_set, struct seq_file *s);
void camb_dump_worker_stat(struct cn_mm_set *mm_set, struct seq_file *s);
int camb_proc_dump_error_ctrl(struct cn_mm_set *mm_set, bool isdump);
int camb_align_granularity_ctrl(struct cn_mm_set *mm_set, unsigned int flag);
int camb_align_granularity_set(struct cn_mm_set *mm_set, unsigned int order);
void camb_add_node_free_failure_list(struct cn_mm_set *mm_set,
								dev_addr_t dev_vaddr,
								struct mem_attr *mem_meta,
								size_t mem_size,
								int rpc_ret,
								bool mem_sync_commu_point);
void camb_dmup_free_failure_list(void *mem_set);
void camb_clear_free_failure_list(void *mem_set);
int camb_numa_ctrl(struct cn_mm_set *mm_set, bool flag);
int camb_compress_ctrl(struct cn_mm_set *mm_set, bool flag);

#endif /* __CAMBRICON_MM_TOOLS_H__ */
