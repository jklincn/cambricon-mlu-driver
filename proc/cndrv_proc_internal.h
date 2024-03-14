/************************************************************************
 *  @file cndrv_proc_internal.h
 *
 *  @brief For exception support definitions.
 **************************************************************************/

/*************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
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
 ***************************************************************************/
#ifndef __CNDRV_PROC_INTERNAL_H__
#define __CNDRV_PROC_INTERNAL_H__

#include "cndrv_proc.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)			\
	(sizeof(a) / sizeof((a)[0]))
#endif

struct pcie_speed {
	u16 id;
	char *str;
};

struct pcie_width {
	u16 id;
	char *str;
};

struct mlumsg_log {
	u32 ts_nsech;            /* timestamp in nanoseconds */
	u32 ts_nsecl;            /* timestamp in nanoseconds */
	u16 len;                /* length of entire record */
	u16 text_len;           /* length of text buffer */
	u16 dict_len;           /* length of dictionary buffer */
	u8 facility;            /* syslog facility */
	u8 flags:5;             /* internal record flags */
	u8 level:3;             /* syslog level */
};

struct cn_mlumsg_iter {
	u32 log_first_idx;
	u32 log_next_idx;
	u64 log_first_seq;
	u64 log_next_seq;
	unsigned long mlumsg_base;
	unsigned long mlumsg_buf;
};

struct cn_proc_reg {
	SHOW_TYPE show;
	unsigned long offsize;
	unsigned long data;
};

struct cn_proc_mem {
	SHOW_TYPE show;
	unsigned long addr;
	unsigned long data;
	u32 sw_id;
	u32 sram_offset;
};

struct cn_proc_dob {
	SHOW_TYPE show;
	unsigned long host_vaddr;
	u64 device_addr;
	unsigned long offsize;
	unsigned long data;
	size_t size;
	struct commu_endpoint *dob_ep;
};

struct cn_proc_info_array {
	cn_board_model_t board_model_t;
	char *desc;
};

struct cn_proc_file_info {
	char *name;
	umode_t mode;
	union {
		struct proc_dir_entry *proc;
		struct dentry *debugfs;
	} parent;
#if KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE
	const struct file_operations *proc_fops;
#else
	const struct proc_ops *proc_fops;
#endif
	const struct file_operations *debugfs_fops;
	struct dentry *debug_entry;
	void *core;
	int vf_en;
};

struct cn_proc_set {
	struct proc_dir_entry *cndrv_dev_dir;
	struct dentry *cndrv_debug_dir;
	char *dev_name;
	char *dbgfs_name;
	struct cn_proc_reg proc_reg;
	struct cn_proc_mem proc_mem;
	struct cn_mlumsg_iter msg_iter;
	char remote_file_name[PATH_MAX];
	struct rw_semaphore remote_lock;
	struct cn_proc_dob proc_dob;
};

struct kthread_show_s {
	struct list_head *head;
	const char *type_name;
};

#define __proc_print(fn, level, proc, str, arg...) \
do { \
	if (proc) \
		fn("%s: [BusId%s][%s][%d][CPU %d]: " str "\n", \
			level, proc->dev_name, __func__, \
			__LINE__, raw_smp_processor_id(), ##arg); \
	else \
		fn("%s: [%s][%d][CPU %d]: " str "\n", \
			level, __func__, __LINE__, \
			raw_smp_processor_id(), ##arg); \
} while (0)

#define cn_dev_proc_info(proc, str, arg...) \
	__proc_print(pr_info, "INFO", (proc), str, ##arg)
#define cn_dev_proc_warn(proc, str, arg...) \
	__proc_print(pr_warn, "WARNING", (proc), str, ##arg)
#define cn_dev_proc_err(proc, str, arg...) \
	__proc_print(pr_err, "ERROR", (proc), str, ##arg)
#define cn_dev_proc_debug(proc, str, arg...) \
do {\
	if (HIT_PRINT_BDG(DEV_PROC_DBG)) \
		__proc_print(pr_info, "DEBUG", (proc), str, ##arg); \
} while (0)

#endif /*__CNDRV_PROC_INTERNAL_H__*/
