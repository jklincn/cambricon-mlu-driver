/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/file.h>
#include <linux/seq_file.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_monitor.h"
#include "cndrv_mm.h"
#include "cndrv_sbts.h"

#include "hal/hal_llc/llc_common.h"
#include "camb_mm.h"
#include "camb_mm_tools.h"
#include "camb_mm_pgretire.h"
#include "camb_linear_remap.h"
enum cn_mem_dump {
	DUMP_PUBLIC  = 0x0,
	DUMP_PROCESS = 0x1,
	DUMP_FREED_TS = 0x2,
	DUMP_UNFREE_TS = 0x3,
	DUMP_DELAY_FREE = 0x4,
	DUMP_MODE_END,
};

static inline const char *__dump_mode_str(int dump_mode)
{
	switch (dump_mode) {
	case DUMP_PUBLIC:  return "public";
	case DUMP_PROCESS: return "process";
	case DUMP_FREED_TS: return "freed timestamp";
	case DUMP_UNFREE_TS: return "unfree timestamp";
	case DUMP_DELAY_FREE: return "delay free";
	default: break;
	}
	return NULL;
}

static unsigned int cn_mem_dump_flag = 1UL << DUMP_PROCESS;

/**  PROC_NODE: cn_mem_dump **/
static int camb_mem_dump_set_mode(struct cn_mm_set *mm_set, unsigned int mode)
{
	struct cn_core_set *core = mm_set->core;
	int i = 0;

	cn_mem_dump_flag = mode & ((1 << DUMP_MODE_END) - 1);
	cn_dev_core_info(core, "cn_mem_dump mode:");
	for (i = 0; i < DUMP_MODE_END; i++) {
		cn_dev_core_info(core, "\t %s(%#x): %s", __dump_mode_str(i),
			1 << i, (mode & (1 << i)) ? "open" : "close");
	}

	return 0;
}
int cn_mem_proc_dump_ctrl(void *pcore, char *cmd)
{
	struct cn_core_set *core = pcore;
	char *value = NULL;
	unsigned int mode = 0x0;
	int i = 0;

	if (strstr(cmd, "set")) {
		value = strsep(&cmd, " ");
		if (!value || !cmd || kstrtou32(cmd, 16, &mode)) {
			cn_dev_core_err(core, "command set need value(hex) input");
			return -EINVAL;
		}

		return camb_mem_dump_set_mode(core->mm_set, mode);
	} else if (strstr(cmd, "ts_clear")) {
		return camb_free_ts_fifo_clear(core->mm_set);
	} else if (strstr(cmd, "ts_switch")) {
		value = strsep(&cmd, " ");
		if (!value || !cmd || kstrtou32(cmd, 10, &mode)) {
			cn_dev_core_err(core, "command set need value(0 -- disable / 1 -- enable) input");
			return -EINVAL;
		}

		return camb_free_ts_switch(core->mm_set, mode & 0x1);
	} else {
		cn_dev_info("usage:command error");
		cn_dev_info("\t ts_clear 0/1: clear free timestamp buffer");
		cn_dev_info("\t ts_switch 0/1: disable/enable free timestamp buffer");
		cn_dev_info("\t set <hex>: set cn_mem_dump show info");
		for (i = 0; i < DUMP_MODE_END; i++) {
			cn_dev_info("\t\t %s(%#x): %s", __dump_mode_str(i), 1 << i,
				(mode & (1 << i)) ? "open" : "close");
		}
	}

	return 0;
}

int cn_mem_proc_dump_info(void *pcore, void *seq_file)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct seq_file *s = (struct seq_file *)seq_file;

	/* 2. dump allocated address info */
	if (cn_mem_dump_flag & (1UL << DUMP_PUBLIC))
		camb_dump_public_rbtree(mm_set, s);
	if (cn_mem_dump_flag & (1UL << DUMP_PROCESS))
		camb_dump_process_list(mm_set, s);
	if (cn_mem_dump_flag & (1UL << DUMP_FREED_TS))
		camb_free_ts_fifo_dump(mm_set, s);
	if (cn_mem_dump_flag & (1UL << DUMP_UNFREE_TS))
		camb_free_ts_dump_nonfree(mm_set, s);
	if (cn_mem_dump_flag & (1UL << DUMP_DELAY_FREE))
		camb_dump_worker_stat(mm_set, s);
	return 0;
}

void __camb_mem_info_show(unsigned long size, const char *str, struct seq_file *s)
{
	unsigned long size_of_mb = TRANS_MM_KB_ALIGN_TO_MB(size);
	unsigned long size_of_kb = TRANS_MM_KB_REMAINDER_TO_MB(size);

	if (size_of_mb && size_of_kb) {
		MEMTOOLS_PROC(s, "%-32s%ld MB + %ld KB", str, size_of_mb, size_of_kb);
	} else if (!size_of_mb && size_of_kb) {
		MEMTOOLS_PROC(s, "%-32s%ld KB", str, size_of_kb);
	} else {
		MEMTOOLS_PROC(s, "%-32s%ld MB", str, size_of_mb);
	}

}

/**  PROC_NODE: cn_mem **/
int cn_mem_proc_mem_show(void *pcore, void *seq_file)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct cn_fa_array *arr = mm_set->fa_array;
	struct seq_file *s = (struct seq_file *)seq_file;
	struct cn_mem_stat stat;
	unsigned long frag_size;
	int frag_rate = 0;
	int ret = 0, is_usage = 0;
	__u64 lmem_size;

	ret = camb_mem_statistics(mm_set, &stat);
	if (ret) {
		MEMTOOLS_PROC(s, "Get mem info failed!");
		return ret;
	}

	ret = cn_sbts_get_lmem_size(core, &lmem_size);
	if (ret) {
		MEMTOOLS_PROC(s, "Get local mem size failed!");
		return ret;
	}

	MEMTOOLS_PROC(s, "Mem Perf Opt Mode State");
	MEMTOOLS_PROC(s, "%-32s%s", "Fast alloc Mode:",
		(arr->enable) ? "ENABLE" : "DISABLE");
	MEMTOOLS_PROC(s, "%-32s%s", "Delay free Mode:",
		(core->delay_free_enable == MEM_DELAYFREE_ENABLE) ? "ENABLE" : "DISABLE");
	MEMTOOLS_PROC(s, "%-32s%s", "CCmalloc Mode:",
		(stat.ccmalloc_state == MEM_CCMALLOC_ENABLE) ? "ENABLE" : "DISABLE");
	MEMTOOLS_PROC(s, "%-32s%s", "Linear Mode:", __linear_mode_str(&mm_set->linear));
	MEMTOOLS_PROC(s, "%-32s%s", "PPool Mode:", __ppool_mode_str(&mm_set->ppool));
	MEMTOOLS_PROC(s, "%-32s%s", "Compress alloc Mode:", mm_set->enable_compress_alloc ? "ENABLE" : "DISABLE");

	MEMTOOLS_PROC(s, "\nMem Top Use Info");
	is_usage = !!(mm_set->vir_used_mem - DEFAULT_VIR_USED_MEM);
	MEMTOOLS_PROC(s, "%-32s%s", "Process Mem Usage State:", is_usage ? "USAGE" : "CLEAR");
	__camb_mem_info_show(stat.phy_total_mem, "MemTotal:", s);

	__camb_mem_info_show(stat.phy_total_mem - stat.phy_used_mem, "MemFree:", s);

	MEMTOOLS_PROC(s, "%-32s%lld MB", "LocalMem Standard:", lmem_size);

	MEMTOOLS_PROC(s, "\nMem FA Array Info");
	__camb_mem_info_show(stat.fa_total_mem, "FA MemTotal:", s);
	__camb_mem_info_show(stat.fa_total_mem - stat.fa_used_mem, "FA MemFree:", s);
	__camb_mem_info_show(stat.fa_shrink_size, "FA MemRecycle:", s);

	MEMTOOLS_PROC(s, "%-32s%d MB", "FA ChunkSz:", TRANS_MM_KB_ALIGN_TO_MB(stat.fa_chunk_size));
	__camb_mem_info_show(stat.fa_alloc_size, "FA MaxAllocSz:", s);
	MEMTOOLS_PROC(s, "%-32s%d Bytes", "FA AllocPageSz:", stat.alloc_order);

	__camb_mem_info_show(stat.fa_dev_total_mem, "FA DEV MemTotal:", s);
	__camb_mem_info_show(stat.fa_dev_total_mem - stat.fa_dev_used_mem, "FA DEV MemFree:", s);

	frag_size = stat.fa_alloc_mem - stat.fa_require_mem;
	if (stat.fa_alloc_mem) {
		frag_rate = 100 * frag_size / stat.fa_alloc_mem;
	}

	MEMTOOLS_PROC(s, "%-32s%ld Bytes", "FA Require Mem:", stat.fa_require_mem);
	MEMTOOLS_PROC(s, "%-32s%ld Bytes", "FA Alloc Mem:", stat.fa_alloc_mem);
	MEMTOOLS_PROC(s, "%-32s%ld Bytes", "FA Frag Mem:", frag_size);
	MEMTOOLS_PROC(s, "%-32s%d", "FA Frag Mem Percentage:", frag_rate);

	return 0;
}

int cn_mem_proc_mem_ctrl(void *pcore, char *cmd)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	/**
	 * FIXME: string compare code need refactor, and we need add command list
	 *		  dump in cn_mem_show.
	 **/
	if (strstr(cmd, "fa enable")) {
		camb_fa_ctrl(mm_set, 1);
	} else if (strstr(cmd, "fa disable")) {
		camb_fa_ctrl(mm_set, 2);
	} else if (strstr(cmd, "fa clear")) {
		camb_fa_ctrl(mm_set, 3);
	} else if (strstr(cmd, "ac enable")) {/*mem alloc/free accelerate optimization ctrl*/
		cn_mem_extension(pcore,
			(ACCLERATE_MODE << MEM_EXTENSION_MODE_BIT) | MEM_DELAYFREE_ENABLE);
	} else if (strstr(cmd, "ac disable")) {
		cn_mem_extension(pcore,
			(ACCLERATE_MODE << MEM_EXTENSION_MODE_BIT) | MEM_DELAYFREE_DISABLE);
	} else if (strstr(cmd, "df enable")) {
		camb_mem_df_ctrl(mm_set, MEM_DELAYFREE_ENABLE);
	} else if (strstr(cmd, "df disable")) {
		camb_mem_df_ctrl(mm_set, MEM_DELAYFREE_DISABLE);
	} else if (strstr(cmd, "cc enable")) {
		camb_mem_cc_ctrl(mm_set, MEM_CCMALLOC_ENABLE);
	} else if (strstr(cmd, "cc disable")) {
		camb_mem_cc_ctrl(mm_set, MEM_CCMALLOC_DISABLE);
	} else if (strstr(cmd, "ac show")) {
		cn_mem_extension(pcore,
			(ACCLERATE_MODE << MEM_EXTENSION_MODE_BIT) | MEM_CCMALLOC_DEBUG);
	} else if (strstr(cmd, "el detail")) {
		camb_proc_dump_error_ctrl(mm_set, true);
	} else if (strstr(cmd, "el simple")) {
		camb_proc_dump_error_ctrl(mm_set, false);
	} else if (strstr(cmd, "pg retire")) {
		cn_mem_proc_do_pgretire(pcore);
	} else if (strstr(cmd, "ffl dump")) {
		camb_dmup_free_failure_list(mm_set);
	} else if (strstr(cmd, "ffl clear")) {
		camb_clear_free_failure_list(mm_set);
	} else if (strstr(cmd, "aa disable")) {
		camb_align_granularity_ctrl(mm_set, MEM_ALLOC_ALIGN_DISABLE);
	} else if (strstr(cmd, "numa disable")) {
		camb_numa_ctrl(mm_set, false);
	} else if (strstr(cmd, "numa enable")) {
		camb_numa_ctrl(mm_set, true);
	} else if (strstr(cmd, "compress enable")) {
		camb_compress_ctrl(mm_set, true);
	} else if (strstr(cmd, "compress disable")) {
		camb_compress_ctrl(mm_set, false);
	} else if (strstr(cmd, "aa enable order:")) {
		char *p = cmd;
		unsigned long order;

		strsep(&p, " ");
		strsep(&p, ":");
		if (*p == '\n') {
			order = 14;
			p = NULL;
			cn_dev_core_debug(core, "default align order 14 without input order.");
		}

		while(p != NULL && *p == ' ') {
			p++;
		}

		if (p != NULL && *p != '\n') {
			if (kstrtoul(p, 10, &order)) {
				cn_dev_core_err(core, "get alloc order faied.");
				return -1;
			}
		} else if (p != NULL && *p == '\n') {
			order = 14;
			p = NULL;
		}

		camb_align_granularity_set(mm_set, order);
	} else if (strstr(cmd, "hai enable")) {
		cn_mem_extension(pcore,
			(HAI_MODE << MEM_EXTENSION_MODE_BIT) | MEM_HAI_ENABLE);
	} else if (strstr(cmd, "hai disable")) {
		cn_mem_extension(pcore,
			(HAI_MODE << MEM_EXTENSION_MODE_BIT) | MEM_HAI_DISABLE);
	} else {
		cn_dev_core_err(core, "invalid command input:%s", cmd);
		return -EINVAL;
	}

	return 0;
}

/* PROC NODE: SYSFS retire_debug */
int cn_mem_proc_show_pgretire(void *pcore, void *seqfile)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	uint32_t counts = 0;
	uint64_t *pages = NULL;
	struct seq_file *m = (struct seq_file *)seqfile;
	int i = 0;

	if (!mm_set->pgretire_enable)
		return 0;

	if (mm_set->llc_ops.llc_get_irq_info)
		mm_set->llc_ops.llc_get_irq_info(core);

	camb_parse_pgretire_status(mm_set, seqfile);

	MEMTOOLS_PROC_LOG(m, " Retired Pages Lists:");
	pages = cn_kzalloc(sizeof(uint64_t) * PGRETIRE_MAX_CNT, GFP_KERNEL);
	if (!pages) {
		cn_dev_core_err(core, "no mem error");
		return -ENOMEM;
	}
	cn_mem_pgr_get_pages(pcore, 0, &counts, pages);
	MEMTOOLS_PROC_LOG(m, " Multi SBE Error:");
	MEMTOOLS_PROC_LOG(m, "\t counts:%d", counts);
	for (i = 0; i < counts; i++)
		MEMTOOLS_PROC_LOG(m, "\t [%d]address:%#llx", i, pages[i]);

	counts = 0;
	cn_mem_pgr_get_pages(pcore, 1, &counts, pages);
	MEMTOOLS_PROC_LOG(m, " DBE Error:");
	MEMTOOLS_PROC_LOG(m, "\t counts:%d", counts);
	for (i = 0; i < counts; i++)
		MEMTOOLS_PROC_LOG(m, "\t [%d]address:%#llx", i, pages[i]);

	cn_kfree(pages);
	return 0;
}

int cn_mem_proc_do_pgretire(void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	struct cn_fa_array *arr = mm_set->fa_array;
	int ccmalloc_status = 0, fa_status = 0;

	if (!mm_set->pgretire_enable) {
		cn_dev_core_info(core, "page retire is not enable");
		return -EPERM;
	}

	if (atomic_read(&mm_set->pgretire_again) == 0) {
		cn_dev_core_info(core, "do not need pageretirement again!");
		return 0;
	}

	if (core->open_count) {
		cn_dev_core_err(core, "Can't set memory extension now! (Device not free)\n");
		return -EINVAL;
	}

	/* save fa and ccmalloc status at first */
	ccmalloc_status = core->delay_free_enable;
	fa_status = arr->enable;

	cn_mem_extension(pcore,
		(ACCLERATE_MODE << MEM_EXTENSION_MODE_BIT) | MEM_CCMALLOC_DISABLE);
	camb_fa_ctrl(mm_set, 0);

	camb_do_page_retirement(mm_set, PGRETIRE_IRQ_MODE);

	/* reset ccmalloc and fa status */
	cn_mem_extension(pcore,
		(ACCLERATE_MODE << MEM_EXTENSION_MODE_BIT) | ccmalloc_status);
	camb_fa_ctrl(mm_set, fa_status);

	return 0;
}
/* PROC NODE: SYSFS retire_debug  END */

/* PROC NODE: llc */
int cn_mem_proc_llc_ctrl(void *pcore, char *buf)
{
	struct cn_core_set *core = pcore;
	unsigned int para = 0;
	int ret = 0;
	char cmd[128] = {0};

	ret = sscanf(buf, "%s %u", cmd, &para);
	if (!strcmp(cmd, "maintenance") && ret == 2) {
		ret = llc_maintanance(core, para);
		cn_dev_core_info(core, "LLC maintenance %s.", !ret ? "successfully" : "failed");
	} else if (!strcmp(cmd, "en_lock")) {
		ret = llc_lock_en(core);
		cn_dev_core_info(core, "LLC persisting enable %s.", !ret ? "successfully" : "failed");
	} else if (!strcmp(cmd, "dis_lock")) {
		ret = llc_lock_dis(core);
		cn_dev_core_info(core, "LLC persisting disable %s.", !ret ? "successfully" : "failed");
	} else if (!strcmp(cmd, "clr_lock")) {
		ret = llc_lock_clr(core);
		cn_dev_core_info(core, "LLC persisting cache clear %s.", !ret ? "successfully" : "failed");
	} else if (!strcmp(cmd, "set_lock_ways") && ret == 2) {
		ret = llc_lock_set_ways(core, para);
		cn_dev_core_info(core, "LLC set persisting ways %u %s.", para, !ret ? "successfully" : "failed");
	} else if (!strcmp(cmd, "get_lock_ways")) {
		ret = llc_lock_get_ways(core, &para);
		cn_dev_core_info(core, "LLC get persisting ways ranges in [0, %d] %s.",
						 para, !ret ? "successfully" : "failed");
	} else {
		cn_dev_core_err(core, "Unknown LLC cmd.");
		return -EINVAL;
	}

	return 0;
}

/* PROC NODE: llc END */
