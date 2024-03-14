/*
 * sbts/idc/idc_main.c
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

#include <linux/version.h>
#include <linux/signal.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/sched.h>
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/mm.h>
#endif
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/ptrace.h>
#include <linux/rwsem.h>
#include <asm/io.h>
#include "cndrv_ioctl.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "cndrv_pinned_mm.h"
#include "../sbts.h"
#include "../sbts_set.h"
#include "../queue.h"
#include "../sbts_sram.h"
#include "idc_internal.h"
#include "idc.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"


LIST_HEAD(idcmgr_list_head);
DECLARE_RWSEM(g_mgrlist_rwsem);

DECLARE_RWSEM(g_set_rwsem);
DEFINE_SBTS_SET_CONTAINER(idc_kaddr_container);

static u64 g_kinfo_seq;
u64 g_task_seq;
static struct kmem_cache *g_kaddr_mem;
int g_kaddr_num;

int idc_basic_init;

/* this support means acc mode not basic mode */
#define SBTS_IDC_SWMODE_SUPPORT    (1 << 0)
#define SBTS_IDC_HWMODE_SUPPORT    (1 << 1)

u32 g_mode_support = SBTS_IDC_HWMODE_SUPPORT |
		SBTS_IDC_SWMODE_SUPPORT;

/* fill this val in first user call */
u32 g_mode_check;

static int __idc_place_param_check(u64 type, u64 flag)
{
	int ret = 0;

	switch (type) {
	case _IDC_REQUEST_OPERATION:
	case _IDC_USERCPU_REQUEST:
		if (flag >= _IDC_REQUEST_END)
			return -1;
		break;
	case _IDC_COMPARE_OPERATION:
	case _IDC_USERCPU_COMPARE:
		if (flag >= _IDC_COMPARE_END)
			return -1;
		break;
	default:
		return -1;
	}

	return ret;
}

static inline struct pinned_mem *
__idc_get_pinned_kv_info(host_addr_t host_addr, host_addr_t *kern_addr)
{
	struct pinned_mem *pst_blk = NULL;

	pst_blk = cn_pinned_mem_get_kv_pst(current->tgid,
			host_addr, sizeof(__u64), kern_addr);
	if (!pst_blk || !(*kern_addr)) {
		cn_dev_err("get kern addr from user addr %lx fail",
				host_addr);
		return NULL;
	}
	return pst_blk;
}

static inline void __kaddr_init_value(
		struct sbts_idc_kaddr_info *info,
		host_addr_t kern_addr, u64 user_addr,
		struct pinned_mem *pst_blk)
{
	kref_init(&info->ref_cnt);
	info->pst_blk = pst_blk;
	info->kern_addr = kern_addr;
	info->user_addr = user_addr;
	info->tgid = current->tgid;
	info->index = __sync_add_and_fetch(&g_kinfo_seq, 1);
	info->send_ticket = 0;
	info->mode_flag = IDC_TASK_MODE_UNKNOWN;

	info->is_destroy = 0;
	mutex_init(&info->mode_lock);
	memset(info->task_cnt, 0, sizeof(u64) * MAX_FUNCTION_NUM);
	memset(info->msg_cnt, 0, sizeof(u64) * MAX_FUNCTION_NUM);
}

#define SBTS_IDC_MODE_CHECKED (1 << 31)
/* this func in write_lock */
static inline u32 __idc_get_ops_mode(void)
{
	u32 idc_mode = g_mode_support & g_mode_support_dbg;

	if (likely(g_mode_check & SBTS_IDC_MODE_CHECKED))
		return g_mode_check & idc_mode;

	/* first check if p2pshm memory is enable */
	if (!sbts_p2pshm_enable()) {
		g_mode_check |= SBTS_IDC_HWMODE_SUPPORT;
		/* second need check dev rw is enable */
		if (!sbts_p2pshm_dev_rw())
			g_mode_check |= SBTS_IDC_SWMODE_SUPPORT;
	}
	/* check device support */
	if (!sbts_global_atomicop_support()) {
		g_mode_check &= ~SBTS_IDC_HWMODE_SUPPORT;
	}

	g_mode_check |= SBTS_IDC_MODE_CHECKED;

	return g_mode_check & idc_mode;
}

static int __idc_info_alloc_ops(struct sbts_idc_kaddr_info *info, u64 flag)
{
	int ret = 0;
	u32 mode = __idc_get_ops_mode();

	info->mode_flag = flag & ~IDC_TASK_FLAG_BASIC_MASK;

	if (info->mode_flag == IDC_TASK_FLAG_SWONLY) {
		/* user debug swmode only */
		mode &= SBTS_IDC_SWMODE_SUPPORT;
	} else if (info->mode_flag == IDC_TASK_FLAG_BASIC) {
		/* user debug basic mode only */
		mode = 0;
	}

	/* first check hw support */
	if (mode & SBTS_IDC_HWMODE_SUPPORT) {
		ret = idc_hwmode_init_ops(info, flag);
		if (!ret)
			return 0;
	}
	/* if hw init fail, try use swmode */
	if (mode & SBTS_IDC_SWMODE_SUPPORT) {
		return idc_swmode_init_ops(info, IDC_TASK_FLAG_ACCMODE);
	}

	return idc_swmode_init_ops(info, IDC_TASK_FLAG_BASIC);
}

/* compare kaddr val by input */
static int __idc_kaddr_info_compare(struct sbts_idc_kaddr_info *r,
			struct sbts_idc_kaddr_info *l)
{
	host_addr_t rkey = r->kern_addr;
	host_addr_t lkey = l->kern_addr;

	if (rkey < lkey) {
		return -1;
	}

	if (rkey > lkey) {
		return 1;
	}

	return 0;
}

static inline void __kaddr_get(struct sbts_idc_kaddr_info *info)
{
	if (!kref_get_unless_zero(&info->ref_cnt)) {
		cn_dev_warn("info(%#llx) kaddr %#lx",
				(u64)info, info->kern_addr);
		cn_dev_warn("info cnt is invalid");
		WARN_ON(1);
	}
}

static int kaddr_get(struct sbts_idc_kaddr_info *info)
{
	int ret = 0;

	if (info->is_destroy) {
		ret = -EINVAL;
		goto get_err;
	}

	__kaddr_get(info);

get_err:
	return ret;
}

void kaddr_info_release(struct kref *kref)
{
#ifdef IDC_INFO_LOG
	struct sbts_idc_kaddr_info *info =
		container_of(kref, struct sbts_idc_kaddr_info, ref_cnt);
#endif

	IDC_LOG_INFO("info(%#llx) kaddr %#lx", (u64)info, info->kern_addr);
	IDC_LOG_INFO("idc kinfo release");
}

static inline int kaddr_put(
		struct sbts_idc_kaddr_info *info)
{

	if (kref_put(&info->ref_cnt, kaddr_info_release)) {
		/* allow mode ctrl dev to free resource */
		info->mode_ops->dev_clear(info);
		/* send free msg to dev to free kinfo */
		__idc_prepare_send_task(info, 0, 0, _IDC_FREE);
		/* ops free host resource */
		info->mode_ops->free(info);

		if (cn_pinned_mem_pst_kref_put_test(info->pst_blk)) {
			cn_pinned_mem_free_pstblk(info->pst_blk);
		}

		kmem_cache_free(g_kaddr_mem, info);
	}

	return 0;
}

static inline int __kaddr_insert_set(
		struct sbts_idc_kaddr_info *info)
{
	struct sbts_idc_kaddr_info *tmp;

	tmp = sbts_set_insert(&idc_kaddr_container, info,
			__idc_kaddr_info_compare, iter);
	if (tmp) {
		/* get kref after insert ok */
		cn_pinned_mem_pst_kref_get(info->pst_blk);
		return 0;
	}
	return -CN_SBTS_ERROR_IOCTL_FAILED;
}

static inline struct sbts_idc_kaddr_info *
__kaddr_find(host_addr_t kern_addr)
{
	struct sbts_idc_kaddr_info obj;

	obj.kern_addr = kern_addr;

	return (struct sbts_idc_kaddr_info *)sbts_set_find(
			&idc_kaddr_container, &obj,
			__idc_kaddr_info_compare, iter);
}

struct sbts_idc_kaddr_info *kaddr_info_get_by_pa(
		host_addr_t kern_addr)
{
	struct sbts_idc_kaddr_info *info;

	down_read(&g_set_rwsem);
	info = __kaddr_find(kern_addr);
	if (!info) {
		up_read(&g_set_rwsem);
		cn_dev_debug("cant find kaddr task by 0x%lx", kern_addr);
		return NULL;
	}
	if (kaddr_get(info))
		info = NULL;
	up_read(&g_set_rwsem);

	return info;
}

struct sbts_idc_kaddr_info *kaddr_info_get_by_id(
		struct cn_core_set *core,
		host_addr_t kern_addr,
		u64 kern_index)
{
	struct sbts_idc_kaddr_info *info;

	down_read(&g_set_rwsem);
	info = __kaddr_find(kern_addr);
	if (!info) {
		up_read(&g_set_rwsem);
		cn_dev_core_debug(core,
				"cant find kaddr task by 0x%lx %llu",
				kern_addr, kern_index);
		return NULL;
	}
	if (info->index != kern_index) {
		cn_dev_core_warn(core,
			"find kaddr task 0x%llx by 0x%lx with %llu != %llu",
			(u64)info, kern_addr, info->index, kern_index);
		up_read(&g_set_rwsem);
		return NULL;
	}
	if (kaddr_get(info)) {
		cn_dev_core_warn(core,
			"find kaddr task 0x%llx by 0x%lx %llu get fail",
			(u64)info, kern_addr, kern_index);
		up_read(&g_set_rwsem);
		return NULL;
	}
	up_read(&g_set_rwsem);
	IDC_LOG_CORE_INFO(core,
			"find kaddr task 0x%llx by 0x%lx %llu",
			(u64)info, kern_addr, kern_index);

	return info;
}

/* if g_kaddr_num bigger or equal IDC_KADDR_NUM_MAX cant alloc new kaddr */
/* kaddr_num must check and change in write_lock */
static inline int __kaddr_num_try_add(void)
{
	if (g_kaddr_num >= IDC_KADDR_NUM_MAX) {
		cn_dev_warn("Cant alloc new task");
		return -ENOMEM;
	}

	__sync_fetch_and_add(&g_kaddr_num, 1);
	return 0;
}
static inline void __kaddr_num_sub(void)
{
	__sync_fetch_and_sub(&g_kaddr_num, 1);
}

/* must do in lock */
static inline struct sbts_idc_kaddr_info *
__kaddr_init_find_or_alloc(host_addr_t kern_addr, int *is_new)
{
	struct sbts_idc_kaddr_info *info;

	info = __kaddr_find(kern_addr);
	if (info) {
		*is_new = 0;
		return info;
	}

	if (__kaddr_num_try_add())
		return NULL;

	*is_new = 1;
	info = kmem_cache_zalloc(g_kaddr_mem, GFP_KERNEL);
	if (!info) {
		cn_dev_err("malloc memory failed");
		return NULL;
	}

	return info;
}

static struct sbts_idc_kaddr_info *
__find_kaddr_in_push_with_create(
		struct idc_manager *manager,
		struct pinned_mem *pst_blk,
		host_addr_t kern_addr,
		u64 user_addr, u64 flag, u64 user)
{
	int ret = 0;
	struct cn_core_set *core = manager->core;
	struct sbts_idc_kaddr_info *info;
	int is_new = 0;

	down_write(&g_set_rwsem);
	/* before get the lock, others may create */
	info = __kaddr_init_find_or_alloc(kern_addr, &is_new);
	if (!info) {
		up_write(&g_set_rwsem);
		return NULL;
	}
	/* old kaddr info */
	if (!is_new) {
		/* check sta in function */
		__kaddr_get(info);
		up_write(&g_set_rwsem);
		/* init currently wont fail */
		info->mode_ops->init(info);
		return info;
	}
	__kaddr_init_value(info, kern_addr,
			user_addr, pst_blk);
	ret = __idc_info_alloc_ops(info, flag);
	if (ret) {
		up_write(&g_set_rwsem);
		goto alloc_ops_fail;
	}

	__kaddr_get(info);

	ret = __kaddr_insert_set(info);
	up_write(&g_set_rwsem);
	if (ret) {
		/* insert error */
		cn_dev_core_err(core, "add idc %llu to set failed",
				info->index);
		goto insert_fail;
	}

	/* after insert, call init and finish */
	/* init currently wont fail */
	info->mode_ops->init(info);
	return info;

insert_fail:
	info->mode_ops->free(info);
alloc_ops_fail:
	kmem_cache_free(g_kaddr_mem, info);
	return NULL;
}

static struct sbts_idc_kaddr_info *
__find_kaddr_usr_req_with_create(
		struct pinned_mem *pst_blk,
		host_addr_t kern_addr,
		u64 user_addr, u64 flag)
{
	int ret = 0;
	struct sbts_idc_kaddr_info *info;
	int is_new = 0;

	down_write(&g_set_rwsem);
	info = __kaddr_init_find_or_alloc(kern_addr, &is_new);
	if (!info) {
		up_write(&g_set_rwsem);
		return NULL;
	}
	if (!is_new) {
		__kaddr_get(info);
		up_write(&g_set_rwsem);
		return info;
	}

	__kaddr_init_value(info, kern_addr,
			user_addr, pst_blk);

	/* alloc ops but not init it */
	ret = __idc_info_alloc_ops(info, flag);
	if (ret) {
		up_write(&g_set_rwsem);
		goto alloc_fail;
	}
	__kaddr_get(info);

	ret = __kaddr_insert_set(info);
	up_write(&g_set_rwsem);
	if (!ret)
		return info;

	cn_dev_err("add idc %llu to set failed",
				info->index);

	info->mode_ops->free(info);
alloc_fail:
	kmem_cache_free(g_kaddr_mem, info);
	return NULL;
}

static int get_kaddr_info(
		struct idc_manager *manager,
		struct sbts_idc_kaddr_info **ppinfo,
		u64 user_addr, u64 flag, u64 user)
{
	int ret = 0;
	struct sbts_idc_kaddr_info *info;
	struct pinned_mem *pst_blk = NULL;
	host_addr_t kern_addr = 0;

	/* check user input addr and get kv */
	pst_blk = __idc_get_pinned_kv_info((host_addr_t)user_addr, &kern_addr);
	if (!pst_blk)
		return -EFAULT;

	down_read(&g_set_rwsem);
	info = __kaddr_find(kern_addr);
	if (likely(info)) {
		__kaddr_get(info);
		up_read(&g_set_rwsem);
		info->mode_ops->init(info);
	} else {
		up_read(&g_set_rwsem);
		info = __find_kaddr_in_push_with_create(manager,
				pst_blk, kern_addr, user_addr, flag, user);
		ret = (info) ? 0 : -ENOMEM;
	}

	*ppinfo = info;
	cn_pinned_mem_put_kv(current->tgid, kern_addr);
	return ret;
}

static int get_kaddr_in_usr_req(
		struct sbts_idc_kaddr_info **ppinfo,
		host_addr_t kern_addr, u64 user_addr, u64 flag)
{
	int ret = 0;
	struct pinned_mem *pst_blk = NULL;
	struct sbts_idc_kaddr_info *info;

	pst_blk = __idc_get_pinned_kv_info(user_addr, &kern_addr);
	if (!pst_blk)
		return -EFAULT;

	down_read(&g_set_rwsem);
	info = __kaddr_find(kern_addr);
	if (likely(info)) {
		__kaddr_get(info);
		up_read(&g_set_rwsem);
		ret = 0;
	} else {
		up_read(&g_set_rwsem);
		info = __find_kaddr_usr_req_with_create(pst_blk,
				kern_addr, user_addr, flag);
		ret = (info) ? 0 : -ENOMEM;
	}

	*ppinfo = info;
	cn_pinned_mem_put_kv(current->tgid, kern_addr);

	return ret;
}

//TODO  should need to add a ops?
static inline void __idc_task_set_exception(
		struct sbts_idc_kaddr_info *info)
{
	info->is_destroy = 1;

	__idc_prepare_send_task(info, 0, 0, _IDC_EXCEP);
}

/* user call interface */
static int idc_user_request(struct sbts_place_idc *param)
{
	struct sbts_idc_kaddr_info *info = NULL;
	int ret = 0;
	host_addr_t kern_addr = 0;

	ret = __idc_place_param_check(param->type,
			param->flag & IDC_TASK_FLAG_BASIC_MASK);
	if (ret) {
		cn_dev_err("user param invalid");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}

	ret = get_kaddr_in_usr_req(&info, kern_addr,
			param->host_addr, param->flag);
	if (ret) {
		cn_dev_warn("user request %llx %lx init info failed %d",
				param->host_addr, kern_addr, ret);
		goto req_finish;
	}

	/* write with status, clear all task with same addr */
	if (param->status == _IDC_STATUS_ABANDON) {
		IDC_KINFO_PRT(cn_dev_info, info,
				"user request %llx %lx exception",
				param->host_addr, kern_addr);
		/* send exception to each dev and will not update val */
		__idc_task_set_exception(info);
	} else {
		/* find other idc with same kern_addr  */
		ret = info->mode_ops->user_request(info, param);
		if (ret) {
			cn_dev_err("user request op fail %llx %lx",
					param->host_addr, kern_addr);
			ret = -CN_SBTS_ERROR_IOCTL_FAILED;
		}

		IDC_KINFO_PRT(cn_dev_debug, info,
				"usr req flag %#llx val %llu",
				param->flag, param->val);
	}
	kaddr_put(info);
req_finish:
	param->status = 0;

	return ret;
}

static int idc_user_compare(struct sbts_place_idc *param)
{
	struct sbts_idc_kaddr_info *info = NULL;
	int ret = 0;
	host_addr_t kern_addr = 0;
	u64 val;
	u64 flag = param->flag & IDC_TASK_FLAG_BASIC_MASK;

	ret = __idc_place_param_check(param->type, flag);
	if (ret) {
		cn_dev_err("user param invalid");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}

	kern_addr = cn_pinned_mem_get_kv(current->tgid,
			(host_addr_t)param->host_addr, sizeof(__u64));
	if (!kern_addr) {
		cn_dev_err("get kern addr from user addr %llx fail",
					param->host_addr);
		return -EFAULT;
	}

	info = kaddr_info_get_by_pa(kern_addr);
	if (info) {
		IDC_KINFO_PRT(cn_dev_debug, info,
				"usr cmp flag %#llx val %llu",
				param->flag, param->val);

		ret = info->mode_ops->get_val(info, &val);
		kaddr_put(info);
		if (ret) {
			cn_dev_err("get val from info[%llu] ka %llx fail %d",
					info->index, (u64)kern_addr, ret);
			ret = -CN_SBTS_ERROR_IOCTL_FAILED;
			goto cmp_finish;
		}
	} else {
		val = __sync_fetch_and_add((u64 *)kern_addr, 0);
	}

	param->status = __idc_compare_ops(val, flag, param->val);

cmp_finish:
	cn_pinned_mem_put_kv(current->tgid, kern_addr);

	return ret;
}

static int idc_user_read(struct sbts_place_idc *param)
{
	struct sbts_idc_kaddr_info *info = NULL;
	int ret = 0;
	host_addr_t kern_addr = 0;
	u64 val = 0x12345678;

	kern_addr = cn_pinned_mem_get_kv(current->tgid,
			(host_addr_t)param->host_addr, sizeof(__u64));
	if (!kern_addr) {
		cn_dev_err("get kern addr from user addr %llx fail",
					param->host_addr);
		return -EFAULT;
	}

	info = kaddr_info_get_by_pa(kern_addr);
	if (info) {
		ret = info->mode_ops->get_val(info, &val);
		IDC_KINFO_PRT(cn_dev_debug, info,
				"usr read ");
		kaddr_put(info);
		if (ret) {
			cn_dev_err("get val from info[%llu] ka %llx fail %d",
					info->index, (u64)kern_addr, ret);
			ret = -CN_SBTS_ERROR_IOCTL_FAILED;
		}
	} else {
		val = __sync_fetch_and_add((u64 *)kern_addr, 0);
	}
	param->status = val;

	cn_pinned_mem_put_kv(current->tgid, kern_addr);

	return ret;
}

static inline int __idc_task_pre_check(
		struct sbts_set *sbts, struct sbts_idc *idc_param)
{
	struct cn_core_set *core =
			(struct cn_core_set *)sbts->core;
	int ret;

	ret = __idc_place_param_check(idc_param->type,
			idc_param->flag & IDC_TASK_FLAG_BASIC_MASK);
	if (ret) {
		cn_dev_core_err(core, "user input param invalid");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}

	return 0;
}

static inline __u64
fill_desc_place_idc_task(
		struct idc_manager *manager,
		__u64 user,
		struct sbts_queue_invoke_task *user_param,
		struct comm_task_desc *task_desc,
		struct queue *queue,
		struct sbts_idc_kaddr_info *info,
		struct sbts_idc *idc_param)
{
	__u64 payload_size = 0;
	__u32 offset;
	struct sbts_set *sbts = manager->sbts;
	struct cn_core_set *core =
			(struct cn_core_set *)manager->core;
	/* version relate structure */
	struct task_desc_data_v1 *data = NULL;
	struct td_idc_task *priv = NULL;
	u32 priv_size = sizeof(struct td_idc_task);

	sbts_td_priv_size_check(priv_size);

	switch (idc_param->version) {
	case SBTS_VERSION:
		task_desc->version   = idc_param->version;
		/* get task desc data */
		data                 = (struct task_desc_data_v1 *)task_desc->data;
		memset(data, 0, sizeof(struct task_desc_data_v1));
		data->type           = PLACE_IDC_TASK;
		data->user           = cpu_to_le64(user);
		data->dev_sid        = cpu_to_le64(queue->dev_sid);
		data->dev_eid        = 0;

		offset = sbts_task_get_perf_info(sbts, queue, IDC_TS_TASK,
				user_param, data, &priv_size);
		data->priv_size      = priv_size;

		priv                 = (struct td_idc_task *)data->priv;
		priv->task_index     = cpu_to_le64(
				__sync_add_and_fetch(&g_task_seq, 1));
		priv->task_type      = cpu_to_le32(idc_param->type);
		priv->task_flag      = cpu_to_le32(idc_param->flag & IDC_TASK_FLAG_BASIC_MASK);
		priv->target_val     = cpu_to_le64(idc_param->val);
		priv->user_addr      = cpu_to_le64(idc_param->host_addr);
		priv->kern_addr      = cpu_to_le64((u64)info->kern_addr);
		priv->kern_index     = cpu_to_le64(info->index);
		priv->cur_val        = cpu_to_le64(
				__sync_fetch_and_add((u64 *)info->kern_addr, 0));
		priv->msg_cnt        = cpu_to_le64(
				__sync_fetch_and_add(&info->msg_cnt[manager->c_idx], 0));
		/* fill self priv info */
		if (info->mode_ops->fill_task(info, manager, priv, idc_param->type))
			return 0;

		/* calculate payload size: version + task + data + priv_size */
		payload_size = VERSION_SIZE + sizeof(struct task_desc_data_v1) +
				priv_size + offset;
		break;
	default:
		cn_dev_core_err(core, "version not match!");
		break;
	}
	return payload_size;
}

static int place_idc(struct idc_manager *manager, struct queue *queue,
		__u64 user, struct sbts_idc *idc_param,
		struct sbts_queue_invoke_task *user_param)
{
	int ret = 0;
	struct sbts_set *sbts = manager->sbts;
	struct cn_core_set *core =
			(struct cn_core_set *)sbts->core;
	struct sbts_idc_kaddr_info *info;
	struct comm_task_desc task_desc;
	__u64 payload_size;

	ret = __idc_task_pre_check(sbts, idc_param);
	if (ret)
		return ret;

	/* getkv from host_addr, search exist kaddr priv */
	ret = get_kaddr_info(manager, &info, idc_param->host_addr,
			idc_param->flag, user);
	if (ret) {
		cn_dev_core_err(core, "find kaddr info error");
		return -CN_SBTS_ERROR_IOCTL_FAILED;
	}
	/* only add task cnt here */
	__sync_fetch_and_add(&info->task_cnt[manager->c_idx], 1);

	payload_size = fill_desc_place_idc_task(manager, (__u64)user,
			user_param, &task_desc, queue, info, idc_param);
	if (payload_size == 0) {
		IDC_KINFO_CORE_PRT(cn_dev_core_err, core, info,
				"fill task desc failed");
		ret = -CN_SBTS_ERROR_FILL_TASK_DESC;
		goto err_payload;
	}

	ret = queue_push_task_ticket(sbts->queue_manager, queue, &task_desc,
			(__u64)user, payload_size, &idc_param->ticket);
	if (!ret) {
		IDC_KINFO_CORE_PRT(cn_dev_core_debug, core, info,
				"push task type %llu flag %#llx val %llu",
				idc_param->type, idc_param->flag, idc_param->val);

		kaddr_put(info);
		return 0;
	}

	IDC_KINFO_CORE_PRT(cn_dev_core_err, core, info,
			"queue(%px) sid %#016llx push idc task fail",
				queue, queue->dev_sid);
err_payload:
	__sync_fetch_and_sub(&info->task_cnt[manager->c_idx], 1);
	kaddr_put(info);
	return ret;
}

int sbts_place_idc(struct sbts_set *sbts, struct queue *queue,
		cn_user user, struct sbts_queue_invoke_task *user_param)
{
	int ret = 0;
	struct sbts_idc *idc_param = &user_param->priv_data.idc;
	struct idc_manager *manager = sbts->idc_manager;
	struct cn_core_set *core = manager->core;

	if (!idc_basic_init)
		return -ENODEV;

	if ((idc_param->type == _IDC_REQUEST_OPERATION) ||
			idc_param->type == _IDC_COMPARE_OPERATION) {
		ret = place_idc(manager, queue, (u64)user, idc_param, user_param);
	} else {
		ret = -EINVAL;
	}

	if (unlikely(ret))
		cn_dev_core_err(core, "init idc task failed! %d", ret);

	return ret;
}

long cn_sbts_idc_ctl(struct file *fp, unsigned int cmd, unsigned long args)
{
	int ret = 0;
	unsigned int ioc_nr = _IOC_NR(cmd);
	struct sbts_place_idc param;

	if (ioc_nr != _SBTS_IDC_PLACE_TASK)
		return -EINVAL;

	if (!idc_basic_init)
		return -ENODEV;

	if (copy_from_user((void *)&param, (void *)args, sizeof(
					struct sbts_place_idc))) {
		cn_dev_err("copy parameters failed!");
		return -EFAULT;
	}

	if (param.type == _IDC_USERCPU_REQUEST) {
		ret = idc_user_request(&param);
	} else if (param.type == _IDC_USERCPU_COMPARE) {
		ret = idc_user_compare(&param);
	} else if (param.type == _IDC_USER_READ) {
		ret = idc_user_read(&param);
	} else {
		cn_dev_err("User ioctl call invalid type %llu", param.type);
		return -EINVAL;
	}

	if (copy_to_user((void *)args, (void *)&param, sizeof(
					struct sbts_place_idc))) {
		cn_dev_err("copy parameters to user failed!");
		return -EFAULT;
	}

	return ret;
}

static void __idc_rx_check(
		struct comm_ctrl_desc *rx_desc,
		u64 *type,
		u64 *kern_addr,
		u64 *kern_index,
		struct sbts_idc_task *idc)
{
	struct ctrl_desc_data_v1 *data = NULL;
	struct td_idc_rx_msg *priv = NULL;

	data = (struct ctrl_desc_data_v1 *)rx_desc->data;
	priv = (struct td_idc_rx_msg *)data->priv;

	*type        = le64_to_cpu(priv->msg_type);
	*kern_addr   = le64_to_cpu(priv->kern_addr);
	*kern_index  = le64_to_cpu(priv->kern_index);

	idc->index   = le64_to_cpu(priv->task_index);
	idc->type    = le64_to_cpu(priv->task_type);
	idc->flag    = le64_to_cpu(priv->task_flag);
	idc->req_val = le64_to_cpu(priv->req_val);
}

static void __idc_rx_debug_save(
		struct idc_manager *manager,
		struct comm_ctrl_desc *rx_desc)
{
	struct ctrl_desc_data_v1 *data = NULL;
	struct td_idc_rx_msg *priv = NULL;
	struct td_idc_rx_msg *save_buf;

	if (!manager->save_rx_flag)
		return;

	data = (struct ctrl_desc_data_v1 *)rx_desc->data;
	priv = (struct td_idc_rx_msg *)data->priv;

	save_buf = manager->rx_msg_dbg + manager->rx_msg_idx;
	if (++manager->rx_msg_idx >= IDC_DBG_MSG_MAX)
		manager->rx_msg_idx = 0;

	memcpy(save_buf, priv, sizeof(struct td_idc_rx_msg));
}



/* work thread */
void cn_sbts_idc_wait_work(
		struct cn_core_set *core,
		void *priv_data,
		void *rx_msg, int rx_size)
{
	struct comm_ctrl_desc *rx_ctl_desc = (struct comm_ctrl_desc *)rx_msg;
	struct sbts_idc_kaddr_info *info = NULL;
	struct sbts_idc_task idc = {0};
	struct idc_manager *manager = (struct idc_manager *)priv_data;
	host_addr_t kern_addr;
	/* type --> idc_msg_type */
	u64 type, kern_index;

	__idc_rx_debug_save(manager, rx_ctl_desc);
	__idc_rx_check(rx_ctl_desc, &type,
			(u64 *)&kern_addr, &kern_index,
			&idc);

	info = kaddr_info_get_by_id(core, kern_addr, kern_index);
	if (!info) {
		cn_dev_core_warn(core,
				"kaddr 0x%lx %llu invalid from device",
				kern_addr, kern_index);
		return;
	}

	info->mode_ops->rx_msg(info, manager, idc, type);
	kaddr_put(info);

}

static void idc_send_message(struct idc_manager *manager,
		struct idc_send_task *send_task)
{
	struct sched_manager *sched_mgr;
	struct cn_core_set *core;
	struct comm_ctrl_desc tx_ctl_desc;
	struct ctrl_desc_data_v1 *data =
		(struct ctrl_desc_data_v1 *)tx_ctl_desc.data;
	struct td_idc_tx_msg *priv =
		(struct td_idc_tx_msg *)data->priv;
	u64 payload_size = sizeof(__le64) * 2 +
			sizeof(struct ctrl_desc_data_v1) +
			sizeof(struct td_idc_tx_msg);
#define IDC_SEND_CNT   9999999
	int cnt = IDC_SEND_CNT;

	core = manager->core;
	sched_mgr = manager->sched_mgr;

	priv->kern_addr  = cpu_to_le64(send_task->kern_addr);
	priv->kern_index = cpu_to_le64(send_task->kern_index);
	priv->msg_index  = cpu_to_le64(send_task->msg_index);
	priv->new_val    = cpu_to_le64(send_task->new_val);
	priv->task_index = cpu_to_le64(send_task->task_index);
	priv->msg_type   = cpu_to_le64(send_task->type);
	priv->idx_valid  = cpu_to_le64(send_task->idx_valid);
	priv->task_req   = cpu_to_le64(send_task->task_req);

	while (cnt--) {
		if (commu_send_message_once(sched_mgr->idc_ep, &tx_ctl_desc, payload_size))
			return;

		if (sbts_pause(core, 5, 20)) {
			cn_dev_core_err(core, "the reset flag has been set!");
			return;
		}
	}
	cn_dev_core_err(core, "Send data to device timeout, Please check mlu device status");
}

int cn_sbts_idc_send_work(void *data)
{
	struct idc_manager *manager = NULL;
	struct sched_manager *sched_mgr;
	struct cn_core_set *core;
	struct idc_send_task *send_task, *tmp;
	struct llist_node *first;

	manager = (struct idc_manager *)data;
	if (!manager) {
		cn_dev_err("get idc manager failed");
		return -EINVAL;
	}
	sched_mgr = manager->sched_mgr;
	core = manager->core;

	if (current->nr_cpus_allowed > 1)
		CN_CLEAR_CPUMASK(0);

	allow_signal(SIGKILL);
	while (!kthread_should_stop()) {
		if (!manager->worker_status || core->reset_flag) {
			msleep(20);
			continue;
		}

		if (wait_event_interruptible(manager->idc_wait_head,
					!llist_empty(&manager->st_head))) {
			continue;
		}

		first = llist_del_all(&manager->st_head);
		if (!first)
			continue;

		first = llist_reverse_order(first);
		llist_for_each_entry_safe(send_task, tmp, first, l_node) {
			idc_send_message(manager, send_task);
			idc_send_task_free(manager, send_task);
		}
	}
	cn_dev_core_info(core, "idc send work thread finish.");

	return 0;
}

/* cn pinned mem call this func if pst_blk need free */
/* return 1 if pst_blk isnt used in idc */
/* return 0 if idc will call cn_pinned_mem_free_pstblk */
int cn_sbts_idc_kaddr_rm(struct pinned_mem *pst_blk)
{
	struct sbts_idc_kaddr_info *info, *tmp;
	DEFINE_SBTS_SET_CONTAINER(destroy_container);
	int ret = 1;

	if (!idc_basic_init)
		return ret;

	IDC_LOG_INFO("kaddr:%lx size:%lx free",
			pst_blk->kva_start, pst_blk->vm_size);

	down_write(&g_set_rwsem);
	sbts_set_for_each_entry_safe(info, tmp,
				&idc_kaddr_container, iter) {
		if (info->pst_blk != pst_blk)
			continue;

		ret = 0;
		info->is_destroy = 1;
		__kaddr_num_sub();
		sbts_set_erase(&idc_kaddr_container, info, iter);
		(void)sbts_set_insert(&destroy_container, info,
				__idc_kaddr_info_compare, iter);
	}
	up_write(&g_set_rwsem);

	sbts_set_for_each_entry_safe(info, tmp, &destroy_container, iter) {
		sbts_set_erase(&destroy_container, info, iter);
		kaddr_put(info);
	}

	return ret;
}
int sbts_idc_do_exit(u64 user, struct idc_manager *manager)
{
	return 0;
}

static int
idc_send_task_pool_init(struct idc_manager *manager)
{
	spin_lock_init(&manager->lock);

	manager->st_num = IDC_SEND_TASK_POOL_NUM;
	manager->st_size = sizeof(struct idc_send_task);
	manager->stmap_size = sizeof(long) *
				BITS_TO_LONGS(manager->st_num);
	manager->st_map = cn_kzalloc(manager->stmap_size, GFP_KERNEL);
	if (!manager->st_map) {
		return -ENOMEM;
	}
	manager->st_base = (struct idc_send_task *)cn_kzalloc(
				manager->st_size * manager->st_num,
				GFP_KERNEL);
	if (!manager->st_base) {
		cn_kfree(manager->st_map);
		return -ENOMEM;
	}

	bitmap_zero(manager->st_map, manager->st_num);

	return 0;
}

static void
idc_send_task_pool_exit(struct idc_manager *manager)
{

	cn_kfree(manager->st_map);
	cn_kfree(manager->st_base);
	manager->st_map = NULL;
	manager->st_base = NULL;
}

int sbts_idc_manager_init(
		struct idc_manager **ppidc_mgr,
		struct cn_core_set *core)
{
	int ret = 0;
	struct idc_manager *manager = NULL;
	struct sbts_set *sbts_set = NULL;

	cn_dev_core_debug(core, "idc async manager init");
	sbts_set = core->sbts_set;
	manager = cn_kzalloc(sizeof(struct idc_manager), GFP_KERNEL);
	if (!manager) {
		cn_dev_core_err(core, "malloc idc manager failed");
		return -ENOMEM;
	}

	manager->core = core;
	manager->sched_mgr = sbts_set->sched_manager;
	manager->sbts = sbts_set;
	manager->c_idx = core->idx;
	manager->worker_status = 1;
	manager->save_rx_flag = 1;
	init_llist_head(&manager->st_head);
	init_waitqueue_head(&manager->idc_wait_head);

	if (idc_send_task_pool_init(manager)) {
		cn_dev_core_err(core, "init idc st mem cache failed");
		ret = -ENOMEM;
		goto alloc_fail;
	}

	manager->worker = commu_wait_work_run(core, "idc_wait",
			sbts_set->sched_manager->idc_ep, manager,
			cn_sbts_idc_wait_work);
	if (!manager->worker) {
		cn_dev_core_err(core, "create wait thread fail");
		ret = -EINVAL;
		goto create_wait_fail;
	}
	manager->send_worker = kthread_create_on_node(
			cn_sbts_idc_send_work, manager,
			cn_core_get_numa_node_by_core(core),
			"%s%d", "idc_send_", core->idx);
	if (IS_ERR_OR_NULL(manager->send_worker)) {
		cn_dev_core_err(core, "create send thread fail");
		ret = -EINVAL;
		goto create_send_fail;
	}

	manager->rx_msg_idx = 0;
	manager->rx_msg_dbg = cn_kzalloc(IDC_DBG_MSG_MAX *
			sizeof(struct td_idc_rx_msg), GFP_KERNEL);
	if (!manager->rx_msg_dbg) {
		cn_dev_core_warn(core, "alloc dbg buf fail");
	}

	wake_up_process(manager->send_worker);

	down_write(&g_mgrlist_rwsem);
	list_add_tail(&manager->mgr_list, &idcmgr_list_head);
	up_write(&g_mgrlist_rwsem);

	*ppidc_mgr = manager;
	return 0;

create_send_fail:
	commu_wait_work_stop(core, manager->worker);
create_wait_fail:
	idc_send_task_pool_exit(manager);
alloc_fail:
	cn_kfree(manager);
	return ret;
}

void idc_worker_exit(struct idc_manager *manager)
{
	struct idc_send_task *send_task, *tmp;
	struct llist_node *first;

	down_write(&g_mgrlist_rwsem);
	list_del(&manager->mgr_list);
	up_write(&g_mgrlist_rwsem);

	commu_wait_work_stop(manager->core, manager->worker);
	manager->worker = NULL;

	manager->worker_status = 0;
	if (manager->send_worker) {
		send_sig(SIGKILL, manager->send_worker, 1);
		kthread_stop(manager->send_worker);
		manager->send_worker = NULL;
	}

	first = llist_del_all(&manager->st_head);
	if (!first)
		return;

	llist_for_each_entry_safe(send_task, tmp, first, l_node) {
		idc_send_task_free(manager, send_task);
	}
}

void sbts_idc_manager_exit(struct idc_manager *idc_manager)
{
	struct sbts_set *sbts_set = NULL;

	if (!idc_manager) {
		cn_dev_err("idc manager is null");
		return;
	}
	sbts_set = idc_manager->sbts;

	idc_worker_exit(idc_manager);

	if (idc_manager->rx_msg_dbg) {
		cn_kfree(idc_manager->rx_msg_dbg);
		idc_manager->rx_msg_dbg = NULL;
	}
	idc_send_task_pool_exit(idc_manager);

	cn_kfree(idc_manager);
	sbts_set->idc_manager = NULL;
}

int cn_sbts_idc_global_init(void)
{
	g_kaddr_mem = kmem_cache_create(
			"cn_idc_global",
			sizeof(struct sbts_idc_kaddr_info),
			64,
			SLAB_HWCACHE_ALIGN, NULL);
	if (IS_ERR_OR_NULL(g_kaddr_mem)) {
		cn_dev_err("idc global kaddr mem alloc fail");
		g_kaddr_mem = NULL;
	}
	idc_basic_init = 1;
	return 0;
}
void cn_sbts_idc_global_exit(void)
{
	struct sbts_idc_kaddr_info *info, *tmp;
	int del_cnt = 0;

	if (!g_kaddr_mem) {
		cn_dev_info("idc global mem is null");
		return;
	}

	idc_basic_init = 0;

	sbts_set_for_each_entry_safe(info, tmp,
			&idc_kaddr_container, iter) {
		del_cnt++;
		sbts_set_erase(&idc_kaddr_container, info, iter);
		kmem_cache_free(g_kaddr_mem, info);
	}
	cn_dev_info("<<<<<%d kaddr task del in exit>>>>>", del_cnt);

	kmem_cache_destroy(g_kaddr_mem);
	g_kaddr_mem = NULL;
}


