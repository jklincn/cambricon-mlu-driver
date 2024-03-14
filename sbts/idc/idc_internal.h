/*
 * sbts/idc_internal.h
 *
 * NOTICE:
 * Copyright (C) 2022 Cambricon, Inc. All rights reserved.
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

#ifndef __SBTS_IDC_INTERNAL_H
#define __SBTS_IDC_INTERNAL_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/llist.h>
#include <linux/wait.h>
#include <linux/printk.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/rwsem.h>

#include "cndrv_ioctl.h"
#include "cndrv_os_compat.h"
#include "cndrv_mm.h"
#include "cndrv_core.h"
#include "cndrv_sbts.h"
#include "../sbts.h"
#include "../sbts_set.h"

struct sbts_set;
struct pinned_mem;
struct sched_manager;
struct task_struct;

#define IDC_SEND_TASK_POOL_NUM     (1UL << 10)
#define IDC_DBG_MSG_MAX            (1UL << 11)
#define IDC_KADDR_NUM_MAX          (1 << 13)

#define IDC_TASK_FLAG_BASIC_SHIFT  32
#define IDC_TASK_FLAG_BASIC_MASK   ((1ULL << IDC_TASK_FLAG_BASIC_SHIFT) - 1)
#define IDC_TASK_FLAG_BASIC        0
/* to compat old code flag ACCMODE is default mode.
 * Driver will use hwmode if hardware support.
 * If param flag without value, swmode will only use commu */
#define IDC_TASK_FLAG_ACCMODE      (~IDC_TASK_FLAG_BASIC_MASK & (1ULL << IDC_TASK_FLAG_BASIC_SHIFT))
/* CNDrv debug value, if set env ...ACCMODE=2, param flag will send this to drv
 * Driver will use swmode even if hwmode is support */
#define IDC_TASK_FLAG_SWONLY       (~IDC_TASK_FLAG_BASIC_MASK & (2ULL << IDC_TASK_FLAG_BASIC_SHIFT))
#define IDC_TASK_MODE_UNKNOWN      (~0ULL)


//#define IDC_INFO_LOG

#ifdef IDC_INFO_LOG
#define IDC_LOG_INFO(string, arg...) cn_dev_info(string, ##arg)
#define IDC_LOG_CORE_INFO(core, string, arg...)			\
		cn_dev_core_info(core, string, ##arg)
#else
#define IDC_LOG_INFO(string, arg...) do {} while (0)
#define IDC_LOG_CORE_INFO(core, string, arg...) do {} while (0)
#endif

#define IDC_DBG_OUT SBTS_DBG_OUT

#define IDC_KINFO_PRT(prt_func, info, string, arg...) \
	prt_func("[%llu]kaddr:%lx val:%llu st:%llu " \
			string, \
			(info)->index, (info)->kern_addr, \
			*(u64 *)((info)->kern_addr), \
			(info)->send_ticket, \
			##arg) \

#define IDC_KINFO_CORE_PRT(prt_func, core, info, string, arg...) \
	prt_func(core, "[%llu]kaddr:%lx val:%llu st:%llu " \
			string, \
			(info)->index, (info)->kern_addr, \
			*(u64 *)((info)->kern_addr), \
			(info)->send_ticket, \
			##arg) \

enum idc_task_type {
	_IDC_REQUEST_OPERATION = 0,
	_IDC_COMPARE_OPERATION,
	_IDC_USERCPU_REQUEST = 100,
	_IDC_USERCPU_COMPARE,
	_IDC_USER_READ = 200,
	_IDC_ABANDON_OPERATION = 1000,
};

/* use this to set mode for dev */
enum idc_opsmode_type {
	IDC_OPSMODE_SWMODE = 1,
	IDC_OPSMODE_HWMODE,
};

enum idc_request_flag {
	_IDC_REQUEST_DEFAULT = 0,
	_IDC_REQUEST_ADD = _IDC_REQUEST_DEFAULT,
	_IDC_REQUEST_SET,
	_IDC_REQUEST_RESET,
	_IDC_REQUEST_END,
};

enum idc_compare_flag {
	_IDC_COMPARE_EQUAL = 0,
	_IDC_COMPARE_LESS_EQUAL,
	_IDC_COMPARE_LESS,
	_IDC_COMPARE_END,
};

enum idc_task_status {
	_IDC_STATUS_NORMAL = 0,
	_IDC_STATUS_ABANDON,
};

enum idc_msg_type {
	_IDC_UPDATE = 1,
	_IDC_FINISH,
	/* force read current val by card */
	_IDC_FORCE,
	_IDC_EXCEP,
	_IDC_FREE,
};

/* set this param in data->user */
enum idc_ctrl_msg_type {
	IDC_CTRL_DBG = 1,
	IDC_CTRL_SWMODE,
	IDC_CTRL_HWMODE,
};

enum idc_ctrl_debug_msg_type {
	_IDC_CTRL_REQUEST_CONFIRM = 1,
	_IDC_CTRL_COMPARE_TIMEOUT,
	_IDC_CTRL_REQUEST_TIMEOUT,
	_IDC_CTRL_DBG_TX_MSG_SAVE,
	_IDC_CTRL_DIRECT_RW_SET,
};

enum idc_ctrl_msg_mode {
	IDC_CTRL_READ,
	IDC_CTRL_SET,
};

enum idc_swmode_ctrl_msg_type {
	EMODE_DISABLE = 1,
	EMODE_UPDATEVAL,
	EMODE_READVAL,
};

struct td_idc_swmode_priv {
	__le64 emode_sta;
	__le64 emode_key;
};
struct td_idc_hwmode_priv {
	__le64 host_addr;
};
/* idc task priv struct in task push to dev */
struct td_idc_task {
	__le64 task_index;
	__le32 task_type;
	__le32 task_flag;
	__le64 target_val;
	__le64 user_addr;
	__le64 kern_addr;
	__le64 kern_index;
	__le64 cur_val;
	__le64 msg_cnt;
	union {
		struct td_idc_swmode_priv swmode;
		struct td_idc_hwmode_priv hwmode;
	};
	__le32 kern_mode;
};

/* idc self commu use h -> d */
struct td_idc_tx_msg {
	__le64 kern_addr;
	__le64 kern_index;
	__le64 msg_index;
	__le64 new_val;
	__le64 task_index;
	__le64 msg_type;
	__le64 idx_valid;
	__le64 task_req;
};

/* idc self commu use d -> h */
struct td_idc_rx_msg {
	__le64 msg_type;
	__le64 kern_addr;
	__le64 kern_index;
	__le64 task_index;
	__le64 task_type;
	__le64 task_flag;
	__le64 req_val;
};

/* idc debug ctrl msg use h -> d */
struct cd_idc_debug_msg {
	/* enum idc_ctrl_msg_type */
	__le64 ops;
	/* enum idc_ctrl_msg_mode */
	/* read or set */
	__le64 mode;
	/* value */
	__le64 val;
};

/* idc kaddr emode ctrl msg h -> d */
struct cd_idc_swmode_msg {
	/* enum idc_swmode_ctrl_msg_type */
	__le64 msg_type;
	__le64 emode_key;
	__le64 req_flag;
	__le64 req_val;
};
struct cd_idc_hwmode_msg {
	__le64 msg_type;
	__le64 ctrl_result;
};

struct cd_idc_ctrl_msg {
	/* enum idc_ctrl_msg_type */
	__le64 ctrl_type;
	/* kaddr info */
	__le64 kern_addr;
	__le64 kern_index;
	__le64 cur_val;
	union {
		struct cd_idc_debug_msg dbg_msg;
		struct cd_idc_swmode_msg swmode_msg;
		struct cd_idc_hwmode_msg hwmode_msg;
	};
};

struct idc_send_task {
	u64 kern_addr;
	u64 kern_index;
	/* send msg seq num */
	u64 msg_index;
	/* read kern_addr new val */
	u64 new_val;
	/* recv idc task index if have */
	u64 task_index;
	/* need read task_index */
	u64 idx_valid;
	/* idc task number send to card */
	u64 task_req;

	enum idc_msg_type type;

	struct llist_node l_node;
};

/* rx msg from dev */
struct sbts_idc_task {
	u64 index;

	u64 user_addr;
	u64 kern_addr;
	u64 req_val;

	u64 type;
	u64 flag;
};

struct idc_swmode_priv {
	int init_finish;
	u16 emode_seq;
	volatile int emode_cidx;
	volatile int emode_sta;
	u64 emode_key;
};

struct idc_hwmode_priv {
	/* kern rw addr is user or kern */
	int addr_type;
	/* alloc key by kern shm */
	u64 addr_key;
	/* kern access addr */
	u64 cpu_addr;
	/* dev access addr */
	u64 dev_addr[MAX_FUNCTION_NUM];
};

struct sbts_idc_kaddr_info {
	struct pinned_mem *pst_blk;
	struct kref ref_cnt;
	struct sbts_set_iter_st iter;

	int is_destroy;

	/* save get kern_addr */
	host_addr_t kern_addr;
	/* first used user info */
	pid_t tgid;
	u64 user;
	u64 user_addr;
	/* kaddr_task index in host */
	u64 index;
	/* msg to card index */
	u64 send_ticket;

	u64 mode_flag;
	struct mutex mode_lock;
	union {
		struct idc_swmode_priv swmode;
		struct idc_hwmode_priv hwmode;
	};
	const struct sbts_idc_mode_ops *mode_ops;

	/* idc task num send to each card success */
	u64 task_cnt[MAX_FUNCTION_NUM];
	/* update msg send to each card seq */
	u64 msg_cnt[MAX_FUNCTION_NUM];
};

struct idc_manager {
	struct sched_manager *sched_mgr;
	struct cn_core_set *core;
	struct sbts_set *sbts;
	/* wait work thread */
	void *worker;
	struct task_struct *send_worker;

	/* list to save all manager in global */
	struct list_head mgr_list;

	/* llist head for send task */
	struct llist_head st_head;

	wait_queue_head_t idc_wait_head;

	volatile int worker_status;

	int c_idx;

	/* bitmap for send task */
	u32 st_num;
	u32 st_size;
	u32 stmap_size;
	unsigned long *st_map;
	struct idc_send_task *st_base;
	spinlock_t lock;

	struct td_idc_rx_msg *rx_msg_dbg;
	int rx_msg_idx;
	int save_rx_flag;
};

struct sbts_idc_mode_ops {
	/* after reg ops to kaddr call this to init
	 * to compat old api, this func may called many times
	 * the mode need handle that to save init stat */
	int (*init)(struct sbts_idc_kaddr_info *info);
	/* in place_idc after get kaddr and filling msg priv,
	 * main function  will call this func to let mode fill self data.
	 * */
	int (*fill_task)(struct sbts_idc_kaddr_info *info,
			struct idc_manager *manager,
			struct td_idc_task *td_priv,
			u64 task_type);

	int (*user_request)(struct sbts_idc_kaddr_info *info,
			struct sbts_place_idc *param);
	int (*get_val)(struct sbts_idc_kaddr_info *info,
			u64 *val);

	int (*rx_msg)(struct sbts_idc_kaddr_info *info,
			struct idc_manager *manager,
			struct sbts_idc_task idc, u64 type);
	/* mode may have some sta or resource on device,
	 * and need to free them to avoid some malfunction.
	 * this ops only be called when info will be free,
	 * so no need to acquire lock anymore */
	void (*dev_clear)(struct sbts_idc_kaddr_info *info);
	void (*free)(struct sbts_idc_kaddr_info *info);
	/* dump self kaddr info */
	void (*dump_info)(struct sbts_idc_kaddr_info *info);
};



extern struct list_head idcmgr_list_head;
extern struct rw_semaphore g_mgrlist_rwsem;

extern struct rw_semaphore g_set_rwsem;
extern struct sbts_set_container_st idc_kaddr_container;

extern u64 g_task_seq;
extern int g_kaddr_num;
extern int idc_basic_init;
extern u32 g_mode_support;
extern u32 g_mode_check;
extern u32 g_mode_support_dbg;
extern u64 g_dbg_sw_basic;
extern u64 g_dbg_sw_acc;
extern u64 g_dbg_sw_acc_to_basic;

extern int idc_ctrl_data_send(
		struct sbts_set *sbts,
		struct comm_ctrl_desc *tx_desc,
		struct comm_ctrl_desc *rx_desc);
extern int __idc_request_ops(u64 *kern_addr, u64 flag, u64 val);
extern int __idc_compare_ops(u64 cur_val, u64 flag, u64 val);
extern struct idc_send_task *
idc_send_task_alloc(struct idc_manager *manager);
extern void idc_send_task_free(
		struct idc_manager *manager,
		struct idc_send_task *task);
extern void __idc_prepare_send_task(
		struct sbts_idc_kaddr_info *info,
		u64 task_index, u64 idx_valid,
		enum idc_msg_type type);


extern int idc_swmode_init_ops(
		struct sbts_idc_kaddr_info *info,
		u64 flag);

extern int idc_hwmode_init_ops(
		struct sbts_idc_kaddr_info *info,
		u64 flag);

extern void idc_swmode_set_timeout(int timeout);
extern int idc_swmode_get_timeout(void);

#endif /* __SBTS_IDC_INTERNAL_H */
