/*
 * include/cndrv_sbts.h
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

#ifndef __CNDRV_SBTS_H__
#define __CNDRV_SBTS_H__

#include <linux/types.h>
#include <linux/compiler.h>
#include "cndrv_mm.h"

/* The macro helper for p2pshm */
#define P2PSHM_GRAIN_SZ_SHIFT           (5)
#define P2PSHM_GRAIN_SZ                 (1U << P2PSHM_GRAIN_SZ_SHIFT)
#define P2PSHM_GRAIN_NUM                (1U << 14)
#define SBTS_P2PSHM_SZ                  (P2PSHM_GRAIN_SZ * P2PSHM_GRAIN_NUM)
#define SBTS_P2PSHM_NAME                "sbts_p2pshm"

/* Forward declaration */
struct pinned_mem;
union sbts_task_priv_data;
/* for reg type */
#define SBTS_P2PSHM_REG_INIT    0
#define SBTS_P2PSHM_REG_SW      (1 << 0)
#define SBTS_P2PSHM_REG_HW      (1 << 1)
#define SBTS_P2PSHM_REG_ALL     (SBTS_P2PSHM_REG_SW | SBTS_P2PSHM_REG_HW)

struct sbts_info_s {
	__u64 ct_ram_size;
	__u64 lt_ram_size;
	__u64 shared_mem_size;
	__u64 ldram_size;
	__u64 ldram_max_size;
	bool multi_dev_notifier;
	bool ipc_notifier;
};

/* aiisp core type policy model */
extern int cn_sbts_set_aiisp_policy(struct cn_core_set *core, __u32 policy);
extern int cn_sbts_get_aiisp_policy(struct cn_core_set *core, char *str, int n);
int cn_sbts_get_old_aiisp_policy(struct cn_core_set *core, __u32 *policy);

/*
 * Lpm mode interface:
 *      cn_sbts_lpm_mode_check: return true when current lpm mode is the specific mode, or return false.
 */
enum cn_sbts_lpm_mode {
	CN_SBTS_LP_BUSY_RUNTIME = 0,
	CN_SBTS_LP_USER_RUNTIME,
	CN_SBTS_LP_TASK_RUNTIME,
	CN_SBTS_LP_LPM_MODE_NUM,
};

extern int cn_sbts_lpm_mode_switch_to_user(struct cn_core_set *core);
extern int cn_sbts_lpm_mode_switch_to_task(struct cn_core_set *core);

#ifdef CONFIG_CNDRV_SBTS
/* user mod ioctl */
extern long cn_sbts_dev_ioctl(struct cn_core_set *core, unsigned int cmd,
			unsigned long arg, struct file *fp);

extern int
cn_sbts_do_exit(cn_user, struct cn_core_set *);

extern int
cn_sbts_priv_data_init(struct fp_priv_data *priv_data);

extern void
cn_sbts_priv_data_exit(struct fp_priv_data *priv_data);

extern void
cn_sbts_dma_finish_wakeup(struct cn_core_set *core);
extern void cn_sbts_dma_finish_set_sta(
		struct cn_core_set *core,
		u64 addr_key, u32 sta,
		__le64 start_ns, __le64 end_ns);


extern int
cn_sbts_idc_debug_show(struct cn_core_set *core, struct seq_file *m);

extern void
cn_sbts_idc_debug_write(
		struct cn_core_set *core,
		const char __user *user_buf,
		size_t count);

extern int
cn_sbts_unotify_debug_show(struct cn_core_set *core,
		struct seq_file *m);

extern void
cn_sbts_unotify_debug_write(
		struct cn_core_set *core,
		const char __user *user_buf,
		size_t count);

extern int cn_hostfn_record_show(struct cn_core_set *core, struct seq_file *m);

extern int cn_sbts_topo_debug_show(struct cn_core_set *core,
		struct seq_file *m);

extern void cn_sbts_topo_debug_write(
		struct cn_core_set *core,
		const char __user *user_buf,
		size_t count);

extern int cn_sbts_shm_debug_show(struct cn_core_set *core,
		struct seq_file *m);
extern void cn_sbts_shm_debug_write(
		struct cn_core_set *core,
		const char __user *user_buf,
		size_t count);

int cn_sbts_invoke_d2d_sync(
		struct cn_core_set *core,
		u64 src_addr, u64 dst_addr, u64 size);

extern void
cn_sbts_restore_resource(struct cn_core_set *);

extern int
sbts_perf_task_tsinfo_size_get(struct cn_core_set *core, __u64 task_type,
		__u64 unique_seq_id, __u32 *normal_size, __u32 *append_size);

/* schedule policy model */
extern int cn_sbts_set_schedule_policy(struct cn_core_set *core, char *str);
extern int cn_sbts_get_schedule_policy(struct cn_core_set *core, char *str);
/* queue schedule policy model */
extern int cn_sbts_set_queue_sch_policy(struct cn_core_set *core, char *str);
extern int cn_sbts_get_queue_sch_policy(struct cn_core_set *core, char *str);

/* queue record */
extern int
cn_queue_record_cmd(struct cn_core_set *core,
		const char __user *user_buf, size_t count);
extern void
cn_queue_record_show(struct seq_file *m, struct cn_core_set *core);

/* p2pshm debug */
extern void
cn_p2pshm_proc_dump(struct seq_file *m, struct cn_core_set *core);

extern void
cn_sbts_get_sbts_info(struct cn_core_set *, struct sbts_info_s *);
extern int
cn_sbts_get_lmem_size(struct cn_core_set *, __u64 *);

extern int cn_kprintf_set(struct cn_core_set *core);

/* init & exit */
extern int
cn_sbts_late_init(struct cn_core_set *);

extern void
cn_sbts_late_exit(struct cn_core_set *);

extern int
cn_sbts_init(struct cn_core_set *);

extern void
cn_sbts_exit(struct cn_core_set *);

extern int cn_sbts_global_init(void);
extern void cn_sbts_global_exit(void);

extern int cn_p2pshm_global_pre_init(void);

extern int cn_p2pshm_global_post_init(void);

extern void cn_p2pshm_global_pre_exit(void);

extern void cn_p2pshm_global_post_exit(void);

extern int cn_p2pshm_init(struct cn_core_set *core);

extern void cn_p2pshm_exit(struct cn_core_set *core);

extern int cn_p2pshm_late_init(struct cn_core_set *set);

extern void cn_p2pshm_late_exit(struct cn_core_set *core);

extern int
cn_sbts_idc_kaddr_rm(struct pinned_mem *pst_blk);

extern long
cn_sbts_idc_ctl( struct file *fp, unsigned int cmd, unsigned long args);

extern int cn_hw_cfg_cacc_handle(struct cn_core_set *core,
		void *param,
		cn_user user);

extern int cn_ncs_late_init(struct cn_core_set *core);
extern void cn_ncs_late_exit(struct cn_core_set *core);
extern bool cn_sbts_lpm_mode_check(struct cn_core_set *core,
		enum cn_sbts_lpm_mode mode);
extern u64 sbts_topo_get_arm_topo_node_bitmap(struct cn_core_set *core);
#else
static inline long cn_sbts_dev_ioctl(struct cn_core_set *core, unsigned int cmd,
			unsigned long arg, struct file *fp)
{
	return 0;
}
static inline void cn_sbts_exit(struct cn_core_set *set)
{
}
static inline void cn_sbts_restore_resource(struct cn_core_set *set)
{
}
static inline int
sbts_perf_task_tsinfo_size_get(struct cn_core_set *core, __u64 task_type,
		__u64 unique_seq_id, __u32 *normal_size, __u32 *append_size)
{
	return 0;
}
static inline void
cn_sbts_dma_finish_wakeup(struct cn_core_set *core)
{
}
static inline void cn_sbts_dma_finish_set_sta(
		struct cn_core_set *core,
		u64 addr_key, __le32 sta,
		__le64 start_ns, __le64 end_ns)
{
}
static inline int cn_sbts_idc_kaddr_rm(struct pinned_mem *pst_blk)
{
	return 0;
}
static inline long
cn_sbts_idc_ctl( struct file *fp, unsigned int cmd, unsigned long args)
{
	return 0;
}

static inline int cn_sbts_global_init(void){
	return 0;
}
static inline void cn_sbts_global_exit(void){}

static inline int cn_p2pshm_global_pre_init(void)
{
	return 0;
}
static inline int cn_p2pshm_global_post_init(void)
{
	return 0;
}
static inline void cn_p2pshm_global_pre_exit(void)
{
}
static inline void cn_p2pshm_global_post_exit(void)
{
}
static inline int cn_p2pshm_init(struct cn_core_set *core)
{
	return 0;
}
static inline void cn_p2pshm_exit(struct cn_core_set *core)
{
}
static inline int cn_sbts_late_init(struct cn_core_set *set)
{
	return 0;
}
static inline void cn_sbts_late_exit(struct cn_core_set *set)
{
	return;
}
static inline int cn_p2pshm_late_init(struct cn_core_set *set)
{
	return 0;
}
static inline void cn_p2pshm_late_exit(struct cn_core_set *core)
{
}
static inline int cn_sbts_init(struct cn_core_set *set)
{
	return 0;
}
static inline void cn_sbts_get_sbts_info(struct cn_core_set *set, struct sbts_info_s *info)
{
}
static inline int cn_sbts_get_lmem_size(struct cn_core_set *core, __u64 *lmem)
{
	return 0;
}
static inline int cn_kprintf_set(struct cn_core_set *core)
{
	return 0;
}
static inline int cn_sbts_do_exit(cn_user u, struct cn_core_set *set)
{
	return 0;
}
static inline int cn_sbts_priv_data_init(struct fp_priv_data *priv_data)
{
	return 0;
}
static inline void cn_sbts_priv_data_exit(struct fp_priv_data *priv_data)
{
	return;
}
static inline int cn_sbts_invoke_d2d_sync(
		struct cn_core_set *core,
		u64 src_addr, u64 dst_addr, u64 size)
{
	return 0;
}

static inline int cn_hw_cfg_cacc_handle(struct cn_core_set *core,
		void *param,
		cn_user user)
{
	return 0;
}

static inline int cn_ncs_late_init(struct cn_core_set *core)
{
	return 0;
}
static inline void cn_ncs_late_exit(struct cn_core_set *core)
{
}
static inline bool cn_sbts_lpm_mode_check(struct cn_core_set *core,
		enum cn_sbts_lpm_mode mode)
{
	return false;
}
static inline u64 sbts_topo_get_arm_topo_node_bitmap(struct cn_core_set *core)
{
	return 0;
}
#endif

#endif /* __CNDRV_SBTS_H__ */
