/*
 * mgr/cndrv_mig.c
 *
 * NOTICE:
 * Copyright (C) 2019 Cambricon, Inc. All rights reserved.
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
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/pid_namespace.h>
#include <linux/ftrace.h>
#include <linux/vmalloc.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "cndrv_mm.h"
#include "cndrv_domain.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "cndrv_mig_internal.h"
#include "mig_packet_stru.h"
#include "binn.h"
#include "../core/version.h"
#include "cndrv_xid.h"

#define MIG_CACHE_SIZE        (8 * 1024 * 1024)

#define MIG_HEAD_BUF_SIZE     256
#define MIG_VERSION           0x0100
#define MIG_MAX_BUF_SIZE      (8 * 1024 * 1024)

enum mig_host_save_state_e {
	MIG_SAVE_INIT = 0,
	MIG_SAVE_DEV_PREPARE,
	MIG_SAVE_DEV_READY,
	MIG_SAVE_HOST_START,
	MIG_SAVE_COMPLETE,
	MIG_SAVE_CANCEL
};

enum mig_host_restore_state_e {
	MIG_RESTORE_INIT = 0,
	MIG_RESTORE_DEV_PREPARE,
	MIG_RESTORE_DEV_READY,
	MIG_RESTORE_HOST_START,
	MIG_RESTORE_COMPLETE,
	MIG_RESTORE_CANCEL
};

struct mig_transfer_seg {
	u64        addr;
	u64        size;
};

struct mig_pf_header_t {
	u32 ver;
	u32 host_data;  /* 0:device data       1:host data */
	u8 dev_mem_type;
	u8 data_done;  /* the last data segment for device or host */
	/* Software Component identifier.
	 * The host and device component is not same mean. */
	u8 cpnt;
	u8 sub_cpnt;
	u32 cpnt_done;
	u32 sg_phy_mode;
	u64 addr;
	u64 size;
};

struct cn_vf_mig_set {
	struct cn_mig_set *mig_set;
	int vf;
	enum mig_dir_e mig_dir;
	enum mig_state_e state;
	int host_state;
	int dma_cmd_cnt;
	u32 dev_done_start;
	u32 dev_done_end;

	u64	cache_addr;
	u64	cache_host_addr;
	u64	cache_max_size;
	u64 cache_size;
	u64 cache_offset;

	void *sg_buf;
	int seg_num;
	struct mig_transfer_seg *sg_table;
	int seg_index;
	u64 seg_offset;

	struct mig_pf_header_t pf_head;
	u64 pf_head_offset;
	u8  pf_head_buf[MIG_HEAD_BUF_SIZE];
	struct binn *head_binn;
	u32 dev_mem_type;

	void *host_buf;
	int cur_host_drv;
	u64 host_offset;

	u32 dma_mask;
};

struct mig_host_stru_t {
	void *priv;
	u64 (*get_host_data_size)(void *priv, int vf);
	u64 (*get_host_data)(void *priv, int vf, void *buf, u64 size);
	u64 (*put_host_data)(void *priv, int vf, void *buf, u64 size);
};

struct cn_mig_set {
	struct cn_core_set *core;
	struct cn_vf_mig_set *vf_mig[MIG_MAX_VF];
	struct commu_channel *commu_chn;
	struct commu_endpoint *endpoint;
	struct mig_host_stru_t host_stru[MIG_HOST_CNT];
	u32 mig_cache_size[MIG_MAX_VF];
	struct binn *mig_cfg_binn[MIG_MAX_VF];
};

static int mig_notify(struct cn_mig_set *mig_set, u32 vf, enum mig_dir_e mig_dir,
	enum mig_header_type head_type);
static int mig_release(struct cn_mig_set *mig_set, u32 vf);
static int mig_save_serial_head(struct cn_mig_set *mig_set, u32 vf);
static int mig_restore_deserial_head(struct cn_mig_set *mig_set, u32 vf);

static int mig_commu_dev(struct cn_mig_set *mig_set, void *in_buf, int in_size,
	void *out_buf, int *out_size)
{
	int seq = 0;

	if (!mig_set) {
		cn_dev_err("mig_set NULL");
		return -1;
	}

	if (!mig_set->endpoint) {
		cn_dev_core_err(mig_set->core, "The endpoint NULL");
		return -EFAULT;
	}

	seq = commu_send_message(mig_set->endpoint, in_buf, in_size);
	if (unlikely(!seq)) {
		cn_dev_core_err(mig_set->core, "send message fail");
		return -EFAULT;
	}

	if (seq != commu_wait_for_message_seq(mig_set->endpoint, out_buf,
			out_size, seq)) {
		cn_dev_core_err(mig_set->core, "recv message fail");
		return -EFAULT;
	}

	return 0;
}

static size_t mig_dma(struct cn_mig_set *mig_set, u64 host_addr, u64 dev_addr,
	size_t size, DMA_DIR_TYPE direction, u32 dma_mask, int phy_mode)
{
	struct transfer_s t;
	struct dma_config_t cfg;

	TRANSFER_INIT(t, host_addr, dev_addr, size, direction);

	cfg.phy_dma_mask = dma_mask;
	cfg.phy_mode = phy_mode;

	return cn_bus_dma_cfg(mig_set->core->bus_set, &t, &cfg);
}

/*
 * Notify the device/arm prepare migration
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * mig_dir:  save context/restore context
 * return:
 */
static int mig_prepare_init(struct cn_mig_set *mig_set, u32 vf, enum mig_dir_e mig_dir)
{
	int ret;
	int result_len;
	struct cn_vf_mig_set *vf_mig;
	struct mig_h2d_msg_t h2d_msg;
	struct mig_d2h_res_t d2h_res;
	dev_addr_t	cache_addr = 0;
	host_addr_t	cache_host_addr = 0;
	struct mig_transfer_seg *mem_seg;

	if (mig_set->vf_mig[vf]) {
		cn_dev_core_err(mig_set->core, "The vf:%d mig is going state:%d",
			vf, mig_set->vf_mig[vf]->state);
		return -EINVAL;
	}

	memset((void *)&h2d_msg, 0, sizeof(h2d_msg));
	memset((void *)&d2h_res, 0, sizeof(d2h_res));

	ret = cn_device_share_mem_alloc(0, &cache_host_addr, &cache_addr,
		mig_set->mig_cache_size[vf], mig_set->core);
	if (ret) {
		cn_dev_core_err(mig_set->core, "Alloc share error");
		goto ERR_RET;
	}

	h2d_msg.vf = vf;
	h2d_msg.dir = mig_dir;
	h2d_msg.header_type = MIG_HEADER_PREPARE;

	mem_seg = (struct mig_transfer_seg *)&h2d_msg.pay_load[0];
	mem_seg->addr = cache_addr;
	mem_seg->size = MIG_CACHE_SIZE;
	ret = mig_commu_dev(mig_set, &h2d_msg, sizeof(h2d_msg), &d2h_res,
		&result_len);

	if (ret >= 0 && (!d2h_res.state)) {
		const void *domain;

		mig_set->vf_mig[vf] = cn_kzalloc(sizeof(struct cn_vf_mig_set), GFP_KERNEL);
		vf_mig = mig_set->vf_mig[vf];
		vf_mig->mig_dir = mig_dir;
		vf_mig->cache_addr = (u64)cache_addr;
		vf_mig->cache_max_size = MIG_CACHE_SIZE;
		vf_mig->cache_host_addr = (u64)cache_host_addr;
		vf_mig->cache_size = 0;
		vf_mig->cache_offset = 0;
		vf_mig->state = MIG_STATE_PREPARE;
		vf_mig->mig_set = mig_set;
		vf_mig->vf = vf;

		if (mig_dir == MIG_H2D_SAVE_CTX) {
			vf_mig->host_state = MIG_SAVE_DEV_PREPARE;
		} else {
			vf_mig->host_state = MIG_RESTORE_DEV_PREPARE;
		}

		domain = cn_dm_get_domain(mig_set->core, DM_FUNC_VF0 + vf);
		vf_mig->dma_mask = cn_dm_pci_get_dma_ch(domain);

		cn_dev_core_info(mig_set->core, "migration prepare success mig_dir:%d",
			vf_mig->mig_dir);
		cn_dev_core_info(mig_set->core,
			"cache_addr:%llx cache_host_addr:%llx cache_max_size:%llx",
			vf_mig->cache_addr, vf_mig->cache_host_addr, vf_mig->cache_max_size);
		cn_dev_core_info(mig_set->core, "migration dma_mask:%x",
			vf_mig->dma_mask);
		return 0;
	}

ERR_RET:
	if (cache_host_addr) {
		cn_device_share_mem_free(0, cache_host_addr, cache_addr, mig_set->core);
	}

	return -EINVAL;
}

int mig_save_prepare(void *mig_priv, u32 vf)
{
	return mig_prepare_init((struct cn_mig_set *)mig_priv, vf, MIG_H2D_SAVE_CTX);
}

int mig_restore_prepare(void *mig_priv, u32 vf)
{
	return mig_prepare_init((struct cn_mig_set *)mig_priv, vf, MIG_H2D_RESTORE_CTX);
}

/* when live migaration source host driver call this function */
int mig_save_start(void *mig_priv, u32 vf)
{
	struct cn_mig_set *mig_set = mig_priv;

	if (!mig_set->vf_mig[vf]) {
		return -EINVAL;
	}

	mig_set->vf_mig[vf]->host_state = MIG_SAVE_HOST_START;
	cn_dev_core_info(mig_set->core, "vf:%d", vf);
	cn_dm_mig_src_host_start(mig_set->core, DM_FUNC_VF0 + vf);

	return 0;
}

/* when live migaration dst host driver call this function */
int mig_restore_start(void *mig_priv, u32 vf)
{
	struct cn_mig_set *mig_set = (struct cn_mig_set *)mig_priv;

	if (!mig_set->vf_mig[vf]) {
		return -EINVAL;
	}

	mig_set->vf_mig[vf]->host_state = MIG_RESTORE_HOST_START;
	cn_dev_core_info(mig_set->core, "vf:%d", vf);
	cn_dm_mig_dst_host_start(mig_set->core, DM_FUNC_VF0 + vf);

	return 0;
}

static int mig_check_state(struct cn_mig_set *mig_set, u32 vf,
	enum mig_dir_e mig_dir)
{
	struct cn_vf_mig_set *vf_mig;

	if (!mig_set->vf_mig[vf]) {
		cn_dev_core_err(mig_set->core, "The vf:%d mig is NULL:%d", vf, mig_dir);
		return -EINVAL;
	}

	vf_mig = mig_set->vf_mig[vf];
	if (vf_mig->mig_dir != mig_dir) {
		cn_dev_core_err(mig_set->core, "The vf:%d mig_dir:%d error", vf, mig_dir);
		return -EINVAL;
	}

	return 0;
}

/*
 * Query the device/arm state whether can start migration
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * mig_dir: save context/restore context
 * dev_state: device/arm state
 * return: 0:success   other:fail
 */

int mig_query_state(struct cn_mig_set *mig_set, u32 vf, enum mig_dir_e mig_dir,
	u32 *dev_state)
{
	int ret = 0;
	int result_len;
	struct cn_vf_mig_set *vf_mig;
	struct mig_h2d_msg_t h2d_msg;
	struct mig_d2h_res_t d2h_res;

	if (mig_check_state(mig_set, vf, mig_dir)) {
		return -EINVAL;
	}

	vf_mig = ((struct cn_mig_set *)mig_set)->vf_mig[vf];
	memset((void *)&h2d_msg, 0, sizeof(h2d_msg));
	memset((void *)&d2h_res, 0, sizeof(d2h_res));

	h2d_msg.vf = vf;
	h2d_msg.dir = mig_dir;
	h2d_msg.header_type = MIG_HEADER_QUERY_STATE;
	ret = mig_commu_dev(mig_set, &h2d_msg, sizeof(h2d_msg), &d2h_res,
		&result_len);

	if (ret >= 0 && (!d2h_res.state)) {
		memcpy((void *)dev_state, (void *)&d2h_res.pay_load[0], sizeof(__u32));
		vf_mig->state = mig_get_global_state(*dev_state);

		if (vf_mig->state == MIG_STATE_READY) {
			if (vf_mig->host_state == MIG_SAVE_DEV_PREPARE &&
				mig_dir == MIG_H2D_SAVE_CTX) {
				vf_mig->host_state = MIG_SAVE_DEV_READY;
			} else if (vf_mig->host_state == MIG_RESTORE_DEV_PREPARE &&
				mig_dir == MIG_H2D_RESTORE_CTX) {
				vf_mig->host_state = MIG_RESTORE_DEV_READY;
			}
		}

		return 0;
	}

	return -EINVAL;
}

int mig_save_query_state(void *mig_priv, u32 vf, u32 *dev_state)
{
	int ret;
	u32 arm_state = 0;
	struct cn_mig_set *mig_set = mig_priv;
	struct cn_vf_mig_set *vf_mig;

	vf_mig = mig_set->vf_mig[vf];
	ret = mig_query_state(mig_set, vf, MIG_H2D_SAVE_CTX, &arm_state);
	if (ret) {
		return ret;
	}

	if (vf_mig->state == MIG_STATE_CANCEL_DONE) {
		(void)mig_notify(mig_set, vf, MIG_H2D_SAVE_CTX,
			MIG_HEADER_CANCEL_COMPLETE);

		if (cn_dm_mig_dst_host_complete(mig_set->core, DM_FUNC_VF0 + vf)) {
			cn_dev_core_err(mig_set->core,
				"Mig cn_dm_mig_dst_host_complete error");
		}
		mig_release(mig_set, vf);
	}

	*dev_state = arm_state;
	return 0;
}

int mig_restore_query_state(void *mig_priv, u32 vf, u32 *dev_state)
{
	int ret;
	u32 arm_state = 0;
	struct cn_mig_set *mig_set = mig_priv;
	struct cn_vf_mig_set *vf_mig;

	vf_mig = mig_set->vf_mig[vf];
	ret = mig_query_state(mig_set, vf, MIG_H2D_RESTORE_CTX, &arm_state);
	if (ret) {
		return ret;
	}

	if (vf_mig->state == MIG_STATE_CANCEL_DONE) {
		(void)mig_notify(mig_set, vf, MIG_H2D_RESTORE_CTX,
			MIG_HEADER_CANCEL_COMPLETE);

		if (cn_dm_mig_src_host_save_complete(mig_set->core, DM_FUNC_VF0 + vf)) {
			cn_dev_core_err(mig_set->core,
				"Mig cn_dm_mig_src_host_save_complete error");
		}
		mig_release(mig_set, vf);
	}

	*dev_state = arm_state;
	return 0;
}

/*
 * Notify the device/arm message
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * mig_dir: save context/restore context
 * head_type: message type
 * return: 0:success   other:fail
 */

static int mig_notify(struct cn_mig_set *mig_set, u32 vf, enum mig_dir_e mig_dir,
	enum mig_header_type head_type)
{
	int ret = 0;
	int result_len;
	struct cn_vf_mig_set *vf_mig;
	struct mig_h2d_msg_t h2d_msg;
	struct mig_d2h_res_t d2h_res;

	if (mig_check_state(mig_set, vf, mig_dir)) {
		return -EINVAL;
	}

	vf_mig = mig_set->vf_mig[vf];
	memset((void *)&h2d_msg, 0, sizeof(h2d_msg));
	memset((void *)&d2h_res, 0, sizeof(d2h_res));

	h2d_msg.vf = vf;
	h2d_msg.dir = mig_dir;
	h2d_msg.header_type = head_type;
	ret = mig_commu_dev(mig_set, &h2d_msg, sizeof(h2d_msg), &d2h_res,
		&result_len);

	if (d2h_res.state) {
		ret = d2h_res.state;
	}

	return ret;
}

static int mig_release(struct cn_mig_set *mig_set, u32 vf)
{
	struct cn_vf_mig_set *vf_mig;

	vf_mig = mig_set->vf_mig[vf];
	if (vf_mig) {
		if (vf_mig->cache_host_addr) {
			cn_device_share_mem_free(0, vf_mig->cache_host_addr,
				vf_mig->cache_addr, mig_set->core);
		}

		cn_kfree(vf_mig);
		mig_set->vf_mig[vf] = NULL;
	}

	return 0;
}

int mig_save_complete(void *mig_priv, u32 vf)
{
	int ret;
	struct cn_mig_set *mig_set = mig_priv;

	if (!mig_set->vf_mig[vf]) {
		cn_dev_core_err(mig_set->core, "NULL");
		return -EINVAL;
	}

	mig_set->vf_mig[vf]->host_state = MIG_SAVE_COMPLETE;
	ret = mig_notify(mig_set, vf, MIG_H2D_SAVE_CTX, MIG_HEADER_COMPLETE);
	if (cn_dm_mig_src_host_save_complete(mig_set->core, DM_FUNC_VF0 + vf)) {
		cn_dev_core_err(mig_set->core, "Host complete live migration error");
	}
	mig_release(mig_set, vf);

	return ret;
}

int mig_restore_complete(void *mig_priv, u32 vf)
{
	int ret;
	struct cn_mig_set *mig_set = mig_priv;

	if (!mig_set->vf_mig[vf]) {
		cn_dev_core_err(mig_set->core, "NULL");
		return -EINVAL;
	}

	mig_set->vf_mig[vf]->host_state = MIG_RESTORE_COMPLETE;
	ret = mig_notify(mig_set, vf, MIG_H2D_RESTORE_CTX, MIG_HEADER_COMPLETE);
	if (ret) {
		cn_dev_core_err(mig_set->core, "Device complete live migration error");
		return ret;
	}

	if (cn_dm_mig_dst_host_complete(mig_set->core, DM_FUNC_VF0 + vf)) {
		cn_dev_core_err(mig_set->core, "Host complete live migration error");
	} else {
		mig_release(mig_set, vf);
	}

	return ret;
}

int mig_save_cancel(void *mig_priv, u32 vf)
{
	int ret;
	int host_state_bak;
	struct cn_mig_set *mig_set = mig_priv;
	struct cn_vf_mig_set *vf_mig;

	if (mig_check_state(mig_set, vf, MIG_H2D_SAVE_CTX)) {
		return -EINVAL;
	}

	vf_mig = mig_set->vf_mig[vf];
	host_state_bak = vf_mig->host_state;
	vf_mig->state = MIG_STATE_CANCEL_INPROG;
	vf_mig->host_state = MIG_SAVE_CANCEL;
	while (vf_mig->dma_cmd_cnt) {
		usleep_range(100, 200);
	}

	if (host_state_bak >= MIG_SAVE_HOST_START) {
		cn_dm_mig_dst_host_start(mig_set->core, DM_FUNC_VF0 + vf);
	}

	ret = mig_notify(mig_set, vf, MIG_H2D_SAVE_CTX, MIG_HEADER_CANCEL);
	if (ret) {
		cn_dev_core_err(mig_set->core, "Live migration cancel save error");
	}

	return ret;
}

int mig_restore_cancel(void *mig_priv, u32 vf)
{
	int ret;
	int host_state_bak;
	struct cn_mig_set *mig_set = mig_priv;
	struct cn_vf_mig_set *vf_mig;

	if (mig_check_state(mig_set, vf, MIG_H2D_RESTORE_CTX)) {
		return -EINVAL;
	}

	vf_mig = mig_set->vf_mig[vf];
	host_state_bak = vf_mig->host_state;
	vf_mig->host_state = MIG_RESTORE_CANCEL;

	if (host_state_bak >= MIG_RESTORE_HOST_START) {
		cn_dm_mig_src_host_start(mig_set->core, DM_FUNC_VF0 + vf);
	}

	ret = mig_notify(mig_set, vf, MIG_H2D_RESTORE_CTX, MIG_HEADER_CANCEL);
	if (ret) {
		cn_dev_core_err(mig_set->core, "Live migration cancel restore error");
	}

	if (cn_dm_mig_src_host_save_complete(mig_set->core, DM_FUNC_VF0 + vf)) {
		cn_dev_core_err(mig_set->core, "Mig cn_dm_mig_src_host_save_complete error");
	}

	return ret;
}

/* The pf driver add head */
static int mig_save_header(struct cn_vf_mig_set *vf_mig, u64 *ca,
	u64 *size, u64 *ret_size)
{
	u64 copy_size;

	if (vf_mig->pf_head_offset < MIG_HEAD_BUF_SIZE) {
		if (!vf_mig->pf_head_offset) {
			mig_save_serial_head(vf_mig->mig_set, vf_mig->vf);
		}

		copy_size = MIG_HEAD_BUF_SIZE - vf_mig->pf_head_offset;
		copy_size = min(copy_size, *size);
		if (copy_to_user((void *)*ca,
			&vf_mig->pf_head_buf[0] + vf_mig->pf_head_offset, copy_size)) {
			cn_dev_err("error");
			return -EINVAL;
		}
		*ca += copy_size;
		*ret_size += copy_size;
		*size -= copy_size;
		vf_mig->pf_head_offset += copy_size;

		if (vf_mig->pf_head_offset >= MIG_HEAD_BUF_SIZE) {
			binn_release(vf_mig->head_binn);
			vf_mig->head_binn = NULL;
		}
	}

	return 0;
}

static int mig_dev_seg_is_end(struct cn_mig_set *mig_set, u32 vf)
{
	struct cn_vf_mig_set *vf_mig;

	vf_mig = mig_set->vf_mig[vf];
	if (vf_mig->dev_mem_type == MIG_MEM_SGL) {
		if (vf_mig->sg_table && (vf_mig->seg_index < vf_mig->seg_num)) {
			return 0;
		}
	} else if (vf_mig->cache_offset < vf_mig->cache_size) {
		return 0;
	}

	return 1;
}

/* Source card save scatter list memory in live migration */
static int mig_save_sgl(struct cn_mig_set *mig_set, u32 vf, u64 ca, u64 size,
	u64 *ret_size)
{
	struct cn_vf_mig_set *vf_mig;
	struct mig_transfer_seg *seg;
	u64 copy_size;
	u64 seg_end;

	vf_mig = mig_set->vf_mig[vf];

	while (size > 0 && (vf_mig->seg_index < vf_mig->seg_num)) {
		seg = &vf_mig->sg_table[vf_mig->seg_index];

		if (vf_mig->seg_offset >= seg->size) {
			vf_mig->seg_index++;
			vf_mig->seg_offset = 0;
			vf_mig->pf_head_offset = 0;
			continue;
		}

		if (!vf_mig->pf_head_offset) {
			vf_mig->pf_head.host_data = 0;
			vf_mig->pf_head.dev_mem_type = MIG_MEM_SGL;
			vf_mig->pf_head.addr = seg->addr + vf_mig->seg_offset;
			vf_mig->pf_head.size = min_t(u64, MIG_MAX_BUF_SIZE,
				seg->size - vf_mig->seg_offset);
			seg_end = vf_mig->seg_offset + vf_mig->pf_head.size;

			if (vf_mig->seg_index == vf_mig->seg_num - 1 && seg_end >= seg->size
				&& vf_mig->dev_done_start) {
				vf_mig->pf_head.data_done = 1;
			} else {
				vf_mig->pf_head.data_done = 0;
			}
		}

		if (mig_save_header(vf_mig, &ca, &size, ret_size)) {
			cn_dev_core_err(mig_set->core, "Sgl save header error");
			return -1;
		}

		seg_end = vf_mig->pf_head.addr - seg->addr + vf_mig->pf_head.size;
		copy_size = min_t(u64, size, seg_end - vf_mig->seg_offset);
		mig_dma(mig_set, ca, seg->addr + vf_mig->seg_offset, copy_size, DMA_D2H,
			vf_mig->dma_mask, vf_mig->pf_head.sg_phy_mode);

		ca += copy_size;
		*ret_size += copy_size;
		vf_mig->seg_offset += copy_size;
		size -= copy_size;

		if (vf_mig->seg_offset >= seg_end) {
			vf_mig->pf_head_offset = 0;
		}
	}

	if (vf_mig->seg_index >= vf_mig->seg_num) {
		cn_kfree(vf_mig->sg_buf);
		vf_mig->sg_buf = 0;
		vf_mig->sg_table = 0;
		vf_mig->pf_head_offset = 0;
		vf_mig->dev_mem_type = MIG_MEM_NORMAL;
		vf_mig->cache_offset = 0;
		vf_mig->cache_size = 0;
	}

	return 0;
}

/*
 * get the sgl info
 * phy_mode: 1 means the memory info is phyicall address
 * seg_num: segmemt number
 * sgl_buf: (u64:addr u64:size) array
 */

static int mig_get_sgl_info(struct cn_mig_set *mig_set, u32 vf)
{
	int seg_num = 0;
	int phy_mode = 0;
	int seg_size = 0;
	struct binn *mig_binn = NULL;
	struct cn_vf_mig_set *vf_mig = mig_set->vf_mig[vf];
	int i;

	mig_binn = vf_mig->sg_buf;
	if (!binn_object_get_int32(mig_binn, "phy_mode", &phy_mode)) {
		cn_dev_core_err(mig_set->core, "Sgl memory can't find phy_mode");
	}
	vf_mig->pf_head.sg_phy_mode = phy_mode;

	if (!binn_object_get_int32(mig_binn, "seg_num", &seg_num)) {
		cn_dev_core_err(mig_set->core, "Sgl memory can't find seg_num");
		return -EFAULT;
	}

	if (!binn_object_get_blob(mig_binn, "sgl_buf", (void **)&vf_mig->sg_table,
		&seg_size)) {
		cn_dev_core_err(mig_set->core, "Sgl memory can't find seg_num");
		return -EFAULT;
	}

	vf_mig->seg_num = seg_num;
	vf_mig->seg_index = 0;
	vf_mig->seg_offset = 0;

	cn_dev_core_info(mig_set->core, "mig_dir:%d phy_mode:%d seg_num:%d",
		vf_mig->mig_dir, phy_mode, seg_num);
	for (i = 0; i < seg_num; i++) {
		cn_dev_core_info(mig_set->core, "(addr:%llx size:%llx)",
			vf_mig->sg_table[i].addr, vf_mig->sg_table[i].size);
	}

	return 0;
}

static int mig_save_serial_head(struct cn_mig_set *mig_set, u32 vf)
{
	struct cn_vf_mig_set *vf_mig;

	vf_mig = mig_set->vf_mig[vf];
	vf_mig->head_binn = binn_new(BINN_OBJECT, MIG_HEAD_BUF_SIZE,
		&vf_mig->pf_head_buf[0]);

	vf_mig->pf_head.ver = MIG_VERSION;
	binn_object_set_uint32(vf_mig->head_binn, "ver",
		vf_mig->pf_head.ver);
	binn_object_set_uint32(vf_mig->head_binn, "host_data",
		vf_mig->pf_head.host_data);
	binn_object_set_uint8(vf_mig->head_binn, "dev_mem_type",
		vf_mig->pf_head.dev_mem_type);
	binn_object_set_uint8(vf_mig->head_binn, "data_done",
		vf_mig->pf_head.data_done);
	binn_object_set_uint8(vf_mig->head_binn, "cpnt",
		vf_mig->pf_head.cpnt);
	binn_object_set_uint8(vf_mig->head_binn, "sub_cpnt",
		vf_mig->pf_head.sub_cpnt);
	binn_object_set_uint32(vf_mig->head_binn, "cpnt_done",
		vf_mig->pf_head.cpnt_done);
	binn_object_set_uint32(vf_mig->head_binn, "sg_phy_mode",
		vf_mig->pf_head.sg_phy_mode);
	binn_object_set_uint64(vf_mig->head_binn, "addr",
		vf_mig->pf_head.addr);
	binn_object_set_uint64(vf_mig->head_binn, "size",
		vf_mig->pf_head.size);
	binn_ptr(vf_mig->head_binn);

	return 0;
}

static int mig_restore_deserial_head(struct cn_mig_set *mig_set, u32 vf)
{
	struct cn_vf_mig_set *vf_mig;

	vf_mig = mig_set->vf_mig[vf];
	vf_mig->head_binn = (struct binn *)&vf_mig->pf_head_buf[0];

	if (!binn_object_get_uint32(vf_mig->head_binn, "ver",
		&vf_mig->pf_head.ver)) {
		cn_dev_core_err(mig_set->core, "ver error");
		return -1;
	}
	if (vf_mig->pf_head.ver > MIG_VERSION) {
		cn_dev_core_err(mig_set->core, "The verion is old than source");
		return -1;
	}

	if (!binn_object_get_uint32(vf_mig->head_binn, "host_data",
		&vf_mig->pf_head.host_data)) {
		cn_dev_core_err(mig_set->core, "host_data error");
		return -1;
	}

	if (!binn_object_get_uint8(vf_mig->head_binn, "dev_mem_type",
		&vf_mig->pf_head.dev_mem_type)) {
		cn_dev_core_err(mig_set->core, "dev_mem_type error");
		return -1;
	}

	if (!binn_object_get_uint8(vf_mig->head_binn, "data_done",
		&vf_mig->pf_head.data_done)) {
		cn_dev_core_err(mig_set->core, "data_done error");
		return -1;
	}

	if (!binn_object_get_uint8(vf_mig->head_binn, "cpnt",
		&vf_mig->pf_head.cpnt)) {
		cn_dev_core_err(mig_set->core, "cpnt error");
		return -1;
	}

	if (!binn_object_get_uint8(vf_mig->head_binn, "sub_cpnt",
		&vf_mig->pf_head.sub_cpnt)) {
		cn_dev_core_err(mig_set->core, "sub_cpnt error");
		return -1;
	}

	if (!binn_object_get_uint32(vf_mig->head_binn, "cpnt_done",
		&vf_mig->pf_head.cpnt_done)) {
		cn_dev_core_err(mig_set->core, "cpnt_done error");
		return -1;
	}

	if (!binn_object_get_uint32(vf_mig->head_binn, "sg_phy_mode",
		&vf_mig->pf_head.sg_phy_mode)) {
		cn_dev_core_err(mig_set->core, "sg_phy_mode error");
		return -1;
	}

	if (!binn_object_get_uint64(vf_mig->head_binn, "size",
		&vf_mig->pf_head.size)) {
		cn_dev_core_err(mig_set->core, "size error");
		return -1;
	}

	if (!binn_object_get_uint64(vf_mig->head_binn, "addr",
		&vf_mig->pf_head.addr)) {
		cn_dev_core_err(mig_set->core, "addr error");
		return -1;
	}

	cn_dev_core_info(mig_set->core,
		"ver:%x host_data:%x dev_mem_type:%d data_done:%x",
		vf_mig->pf_head.ver, vf_mig->pf_head.host_data,
		vf_mig->pf_head.dev_mem_type, vf_mig->pf_head.data_done);
	cn_dev_core_info(mig_set->core,
		"cpnt:%x sub_cpnt:%x cpnt_done:%x size:%llx addr:%llx",
		vf_mig->pf_head.cpnt, vf_mig->pf_head.sub_cpnt, vf_mig->pf_head.cpnt_done,
		vf_mig->pf_head.size, vf_mig->pf_head.addr);

	return 0;
}

/*
 * The next device/arm segment, host call rpc and the device response the
 * address and size
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * return: 0:success   other:fail
 */

static int mig_save_fetch_seg(struct cn_mig_set *mig_set, u32 vf)
{
	int ret = 0;
	struct cn_vf_mig_set *vf_mig;
	struct mig_h2d_msg_t h2d_msg;
	struct mig_d2h_res_t d2h_res;
	struct mig_save_payload_res_t *res_payload;
	int result_len = 0;
	struct dma_config_t  cfg;

	vf_mig = mig_set->vf_mig[vf];
	memset((void *)&h2d_msg, 0, sizeof(h2d_msg));
	memset((void *)&d2h_res, 0, sizeof(d2h_res));

	h2d_msg.vf = vf;
	h2d_msg.dir = MIG_H2D_SAVE_CTX;
	h2d_msg.header_type = MIG_HEADER_DATA;
	ret = mig_commu_dev(mig_set, &h2d_msg, sizeof(h2d_msg), &d2h_res,
		&result_len);

	if (ret < 0 || (d2h_res.state)) {
		cn_dev_core_err(mig_set->core, "The vf:%d mig_dir error ret:%d state:%x",
			vf, ret, d2h_res.state);
		return -EINVAL;
	}

	res_payload = (struct mig_save_payload_res_t *)&d2h_res.pay_load[0];
	memset((void *)&vf_mig->pf_head, 0, sizeof(vf_mig->pf_head));
	vf_mig->pf_head.host_data = 0;
	vf_mig->pf_head.dev_mem_type = res_payload->mem_type;
	vf_mig->pf_head.data_done = res_payload->dev_done;
	vf_mig->pf_head.cpnt = res_payload->cpnt;
	vf_mig->pf_head.sub_cpnt = res_payload->sub_cpnt;
	vf_mig->pf_head.cpnt_done = res_payload->cpnt_done;
	vf_mig->pf_head.size = res_payload->size;
	vf_mig->pf_head.addr = 0;
	vf_mig->pf_head.sg_phy_mode = 0;

	vf_mig->pf_head_offset = 0;
	vf_mig->cache_size = res_payload->size + res_payload->offset;
	vf_mig->cache_offset = res_payload->offset;
	vf_mig->dev_done_start = res_payload->dev_done;
	vf_mig->dev_mem_type = res_payload->mem_type;

	if (vf_mig->dev_mem_type == MIG_MEM_SGL) {
		vf_mig->sg_buf = cn_kzalloc(res_payload->size, GFP_KERNEL);
		if (!vf_mig->sg_buf) {
			cn_dev_core_err(mig_set->core, "vf:%d size:%llx error",
				vf, vf_mig->cache_size);
			return -ENOMEM;
		}

		cfg.phy_dma_mask = vf_mig->dma_mask;
		cfg.phy_mode = 0;
		cn_bus_dma_kernel_cfg(mig_set->core->bus_set, (ulong)vf_mig->sg_buf,
			vf_mig->cache_addr + res_payload->offset, res_payload->size,
			DMA_D2H, &cfg);

		ret = mig_get_sgl_info(mig_set, vf);
		if (ret) {
			cn_dev_core_err(mig_set->core, "get_sgl_info error");
			return ret;
		}
	}

	return 0;
}

static int mig_save_dev_data(struct cn_mig_set *mig_set, u32 vf, u64 ca,
	u64 size, u64 *ret_size, u32 *data_category)
{
	int ret = 0;
	struct cn_vf_mig_set *vf_mig;
	u64 copy_addr;
	u64 copy_size;

	vf_mig = mig_set->vf_mig[vf];

	if (mig_dev_seg_is_end(mig_set, vf)) {
		ret = mig_save_fetch_seg(mig_set, vf);
		if (ret) {
			return ret;
		}
	}

	*data_category = vf_mig->pf_head.cpnt;

	if (vf_mig->dev_mem_type == MIG_MEM_SGL) {
		ret = mig_save_sgl(mig_set, vf, ca, size, ret_size);
	} else if (vf_mig->cache_offset < vf_mig->cache_size) {
		ret = mig_save_header(vf_mig, &ca, &size, ret_size);
		if (ret) {
			return ret;
		}

		copy_addr = vf_mig->cache_addr + vf_mig->cache_offset;
		copy_size = min(vf_mig->cache_size - vf_mig->cache_offset, size);
		mig_dma(mig_set, ca, copy_addr, copy_size, DMA_D2H, vf_mig->dma_mask, 0);

		vf_mig->cache_offset += copy_size;
		*ret_size += copy_size;
	}

	if (vf_mig->dev_done_start) {
		if (mig_dev_seg_is_end(mig_set, vf)) {
			vf_mig->dev_done_end = 1;
			vf_mig->pf_head_offset = 0;
			vf_mig->dev_mem_type = MIG_MEM_NORMAL;
		}
	}

	return ret;
}

static int mig_save_host_data(struct cn_mig_set *mig_set, u32 vf, u64 ca,
	u64 size, u64 *ret_size, u32 *data_category)
{
	struct cn_vf_mig_set *vf_mig;
	u64 copy_size;
	int ret = 0;
	struct mig_host_stru_t *host_mig;

	vf_mig = mig_set->vf_mig[vf];

	while (size && vf_mig->cur_host_drv < MIG_HOST_CNT) {
		host_mig = &mig_set->host_stru[vf_mig->cur_host_drv];

		if (!(host_mig->get_host_data_size && host_mig->get_host_data)) {
			vf_mig->cur_host_drv++;
			continue;
		}

		*data_category = 0x80 + vf_mig->cur_host_drv;
		if (!vf_mig->pf_head_offset) {
			memset((void *)&vf_mig->pf_head, 0, sizeof(vf_mig->pf_head));

			vf_mig->pf_head.host_data = 1;
			vf_mig->pf_head.dev_mem_type = MIG_MEM_NORMAL;
			vf_mig->pf_head.cpnt = vf_mig->cur_host_drv;
			vf_mig->pf_head.sub_cpnt = 0;
			vf_mig->pf_head.cpnt_done = 1;
			vf_mig->pf_head.size = host_mig->get_host_data_size(
				host_mig->priv, vf);
			vf_mig->pf_head_offset = 0;

			vf_mig->host_buf = cn_kzalloc(vf_mig->pf_head.size, GFP_KERNEL);
			host_mig->get_host_data(host_mig->priv, vf, vf_mig->host_buf,
				vf_mig->pf_head.size);
		}

		mig_save_header(vf_mig, &ca, &size, ret_size);

		copy_size = min(size, (u64)(vf_mig->pf_head.size - vf_mig->host_offset));
		ret = copy_to_user((void *)ca, vf_mig->host_buf + vf_mig->host_offset,
			copy_size);
		if (ret) {
			cn_dev_err("error");
			return -EINVAL;
		}
		*ret_size += copy_size;
		vf_mig->host_offset += copy_size;

		if (vf_mig->host_offset >= vf_mig->pf_head.size) {
			cn_kfree(vf_mig->host_buf);
			vf_mig->host_buf = NULL;
			memset((void *)&vf_mig->pf_head, 0, sizeof(vf_mig->pf_head));
			vf_mig->host_offset = 0;
			vf_mig->cur_host_drv++;
		}

		break;
	}

	return 0;
}

/*
 * qemu call this function to restore data
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * ca: host buf address, cpu addr
 * size: host buf size
 * flag: 1 is the last data
 */
int mig_get_data(void *mig_priv, u32 vf, u64 ca, u64 size, u32 *flag,
	u64 *ret_size, u32 *data_category)
{
	int ret = 0;
	struct cn_vf_mig_set *vf_mig;
	struct cn_mig_set *mig_set = (struct cn_mig_set *)mig_priv;

	if (mig_check_state(mig_set, vf, MIG_H2D_SAVE_CTX)) {
		return -EINVAL;
	}

	vf_mig = mig_set->vf_mig[vf];
	if (vf_mig->host_state != MIG_SAVE_HOST_START) {
		return -EINVAL;
	}

	__sync_fetch_and_add(&vf_mig->dma_cmd_cnt, 1);

	*ret_size = 0;
	*flag = 0;
	if (!vf_mig->dev_done_end) {
		ret = mig_save_dev_data(mig_set, vf, ca, size, ret_size, data_category);
	} else {
		ret = mig_save_host_data(mig_set, vf, ca, size, ret_size, data_category);
	}

	if (vf_mig->dev_done_end && vf_mig->cur_host_drv >= MIG_HOST_CNT) {
		*flag = 1;
	}

	__sync_fetch_and_sub(&vf_mig->dma_cmd_cnt, 1);

	return ret;
}

/* The pf driver add head */
static int mig_restore_header(struct cn_vf_mig_set *vf_mig, u64 *ca, u64 *size)
{
	u64 copy_size;
	int ret = 0;

	if (vf_mig->pf_head_offset >= MIG_HEAD_BUF_SIZE) {
		return 0;
	}

	copy_size = MIG_HEAD_BUF_SIZE - vf_mig->pf_head_offset;
	copy_size = min(copy_size, *size);
	if (copy_from_user(&vf_mig->pf_head_buf[0] + vf_mig->pf_head_offset,
		(void *)*ca, copy_size)) {
		cn_dev_err("error");
		return -EINVAL;
	}
	*ca += copy_size;
	*size -= copy_size;
	vf_mig->pf_head_offset += copy_size;

	if (vf_mig->pf_head_offset < MIG_HEAD_BUF_SIZE) {
		return 0;
	}

	ret = mig_restore_deserial_head(vf_mig->mig_set, vf_mig->vf);
	if (ret) {
		return ret;
	}

	if (vf_mig->pf_head.host_data) {
		vf_mig->cur_host_drv = vf_mig->pf_head.cpnt;
		vf_mig->host_buf = cn_kzalloc(vf_mig->pf_head.size, GFP_KERNEL);
		if (!vf_mig->host_buf) {
			cn_dev_err("kzalloc vf mig host buf data space error!");
			return -ENOMEM;
		}
		vf_mig->host_offset = 0;
	} else {
		vf_mig->cache_offset = 0;
		vf_mig->dev_done_start = vf_mig->pf_head.data_done;
	}

	return 0;
}

/*
 * The next device/arm segment, host call rpc notify device the
 * address and size
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * return: 0:success   other:fail
 */

static int mig_restore_new_seg(struct cn_mig_set *mig_set, u32 vf)
{
	int ret = 0;
	struct cn_vf_mig_set *vf_mig;
	struct mig_h2d_msg_t h2d_msg;
	struct mig_d2h_res_t d2h_res;
	struct mig_restore_payload_t *h2d_payload;
	int result_len = 0;

	vf_mig = mig_set->vf_mig[vf];

	memset((void *)&h2d_msg, 0, sizeof(h2d_msg));
	memset((void *)&d2h_res, 0, sizeof(d2h_res));

	h2d_msg.vf = vf;
	h2d_msg.dir = MIG_H2D_RESTORE_CTX;
	h2d_msg.header_type = MIG_HEADER_DATA;
	h2d_payload = (struct mig_restore_payload_t *)&h2d_msg.pay_load[0];
	h2d_payload->mem_type = vf_mig->pf_head.dev_mem_type;
	h2d_payload->dev_done = vf_mig->pf_head.data_done;
	h2d_payload->cpnt = vf_mig->pf_head.cpnt;
	h2d_payload->sub_cpnt = vf_mig->pf_head.sub_cpnt;
	h2d_payload->cpnt_done = vf_mig->pf_head.cpnt_done;
	h2d_payload->size = vf_mig->pf_head.size;
	ret = mig_commu_dev(mig_set, &h2d_msg, sizeof(h2d_msg), &d2h_res,
		&result_len);

	if (ret < 0 || (d2h_res.state)) {
		cn_dev_core_err(mig_set->core,
			"The vf:%d cpnt:%d sub_cpnt:%d ret:%d state:0x%x error",
			vf, h2d_payload->cpnt, h2d_payload->sub_cpnt, ret, d2h_res.state);
		return -EINVAL;
	}

	return 0;
}

static int mig_restore_dev_data(struct cn_mig_set *mig_set, u32 vf,
	u64 *ca, u64 *size)
{
	struct cn_vf_mig_set *vf_mig;
	u64 copy_size;
	u64 copy_addr;
	int ret = 0;

	vf_mig = mig_set->vf_mig[vf];

	if (vf_mig->pf_head.dev_mem_type == MIG_MEM_SGL) {
		copy_addr = vf_mig->pf_head.addr + vf_mig->cache_offset;
	} else {
		copy_addr = vf_mig->cache_addr + vf_mig->cache_offset;
	}
	copy_size = vf_mig->pf_head.size - vf_mig->cache_offset;
	copy_size = min(copy_size, *size);
	mig_dma(mig_set, *ca, copy_addr, copy_size, DMA_H2D, vf_mig->dma_mask,
		vf_mig->pf_head.sg_phy_mode);
	vf_mig->cache_offset += copy_size;
	*ca += copy_size;
	*size -= copy_size;

	if (vf_mig->cache_offset >= vf_mig->pf_head.size) {
		if (vf_mig->pf_head.dev_mem_type == MIG_MEM_NORMAL) {
			ret = mig_restore_new_seg(mig_set, vf);
		}

		if (vf_mig->dev_done_start) {
			vf_mig->dev_done_end = 1;
			mig_notify(mig_set, vf, MIG_H2D_RESTORE_CTX, MIG_HEADER_DATA_DONE);
		}

		vf_mig->pf_head_offset = 0;
		vf_mig->pf_head.dev_mem_type = MIG_MEM_NORMAL;
		vf_mig->cache_offset = 0;
	}

	return 0;
}

static int mig_restore_host_data(struct cn_mig_set *mig_set, u32 vf,
	u64 *ca, u64 *size)
{
	struct cn_vf_mig_set *vf_mig;
	u64 copy_size;
	int ret = 0;
	struct mig_host_stru_t *host_mig;

	vf_mig = mig_set->vf_mig[vf];
	copy_size = min(*size, (u64)(vf_mig->pf_head.size - vf_mig->host_offset));
	ret = copy_from_user(vf_mig->host_buf + vf_mig->host_offset, (void *)(*ca),
		copy_size);
	*ca += copy_size;
	*size -= copy_size;
	vf_mig->host_offset += copy_size;
	if (ret) {
		cn_dev_core_err(mig_set->core, "error");
		return -EINVAL;
	}

	host_mig = &mig_set->host_stru[vf_mig->pf_head.cpnt];
	if (vf_mig->host_offset >= vf_mig->pf_head.size) {
		if (host_mig->put_host_data) {
			host_mig->put_host_data(host_mig->priv, vf, vf_mig->host_buf,
				vf_mig->pf_head.size);
		}

		cn_kfree(vf_mig->host_buf);
		vf_mig->host_buf = NULL;
		vf_mig->host_offset = 0;
		vf_mig->pf_head_offset = 0;
	}

	return 0;
}

/*
 * qemu call this function to restore data
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * ca: host buf address, cpu addr
 * size: host buf size
 * flag: 1 is the last data
 */
int mig_put_data(void *mig_priv, u32 vf, u64 ca, u64 size, u32 flag)
{
	int ret = 0;
	struct cn_vf_mig_set *vf_mig;
	struct cn_mig_set *mig_set = (struct cn_mig_set *)mig_priv;

	if (mig_check_state(mig_set, vf, MIG_H2D_RESTORE_CTX)) {
		return -EINVAL;
	}

	vf_mig = mig_set->vf_mig[vf];
	if (vf_mig->host_state != MIG_RESTORE_DEV_READY) {
		return -EINVAL;
	}

	__sync_fetch_and_add(&vf_mig->dma_cmd_cnt, 1);

	while (size) {
		ret = mig_restore_header(vf_mig, &ca, &size);
		if (ret) {
			__sync_fetch_and_sub(&vf_mig->dma_cmd_cnt, 1);
			return ret;
		}

		if (!size) {
			break;
		}

		if (vf_mig->pf_head.host_data) {
			ret = mig_restore_host_data(mig_set, vf, &ca, &size);
		} else {
			ret = mig_restore_dev_data(mig_set, vf, &ca, &size);
		}

		if (ret) {
			__sync_fetch_and_sub(&vf_mig->dma_cmd_cnt, 1);
			return ret;
		}
	}

	__sync_fetch_and_sub(&vf_mig->dma_cmd_cnt, 1);

	return 0;
}

/*
 * qemu call this function to get config information
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * ca: host buf address
 * size: host buf size
 * ret_size: the actual read data size
 * Notes: the user must malloc a enough size to store config onformation, suggest
 *        bigger than 4K.
 */
int mig_get_cfg(void *mig_priv, u32 vf, u64 ca, u64 size, u64 *ret_size)
{
	struct cn_mig_set *mig_set = (struct cn_mig_set *)mig_priv;
	struct binn *mig_binn;
	int ret = 0;

	if (vf >= MIG_MAX_VF) {
		cn_dev_core_err(mig_set->core, "Error vf:%d", vf);
		return -EINVAL;
	}

	mig_set->mig_cache_size[vf] = MIG_CACHE_SIZE;

	if (!mig_set->mig_cfg_binn[vf]) {
		mig_binn = binn_object();

		binn_object_set_uint32(mig_binn, "domain", vf);
		binn_object_set_uint32(mig_binn, "host_drv_ver", DRV_VERSION);
		binn_object_set_uint32(mig_binn, "cahce_size",
			mig_set->mig_cache_size[vf]);
		binn_object_set_uint32(mig_binn, "mcu_major",
			mig_set->core->board_info.mcu_info.mcu_major);
		binn_object_set_uint32(mig_binn, "mcu_minor",
			mig_set->core->board_info.mcu_info.mcu_minor);
		ret = cn_dm_mig_get_cfg(mig_set->core, DM_FUNC_VF0 + vf, (void *)mig_binn);
		if (ret < 0) {
			cn_dev_core_err(mig_set->core, "Error get dm cfg binn_sz=%d", (u32)binn_size(mig_binn));
			return -EINVAL;
		}
		mig_set->mig_cfg_binn[vf] = mig_binn;
	} else {
		mig_binn = mig_set->mig_cfg_binn[vf];
	}

	if (ca && size) {
		*ret_size = min_t(u64, size, binn_size(mig_binn));
		if (copy_to_user((void *)ca, (void *)binn_ptr(mig_binn), *ret_size)) {
			cn_dev_core_err(mig_set->core, "Error ca:%llx", ca);
			ret = -EINVAL;
		}

		binn_free(mig_binn);
		mig_set->mig_cfg_binn[vf] = NULL;
	} else if (mig_binn) {
		*ret_size = binn_size(mig_binn);
	} else {
		*ret_size = 0;
	}

	return ret;
}

/*
 * qemu call this function to restore data
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * ca: host buf address
 * size: host buf size
 * Notes: the user must malloc a enough size to store config onformation
 */
int mig_put_cfg(void *mig_priv, u32 vf, u64 ca, u64 size)
{
	int ret = 0;
	struct cn_mig_set *mig_set = (struct cn_mig_set *)mig_priv;
	struct binn *mig_binn = cn_kzalloc(size, GFP_KERNEL);
	u32 host_drv_ver = 0;
	u32 domain = 0;
	u32 cahce_size = 0;
	u32 mcu_major = 0;
	u32 mcu_minor = 0;
	struct cn_mcu_info *mcu_info;

	if (!mig_binn) {
		cn_dev_core_err(mig_set->core, "kzalloc mig_binn data space error!");
		return -ENOMEM;
	}

	if (copy_from_user((void *)mig_binn, (void *)ca, size)) {
		cn_dev_core_err(mig_set->core, "Error ca:%llx", ca);
		ret = -EINVAL;
		goto RETURN;
	}

	if (!binn_object_get_uint32(mig_binn, "domain", &domain)) {
		cn_dev_core_err(mig_set->core, "No domain");
		ret = -EINVAL;
		goto RETURN;
	}

	if (!binn_object_get_uint32(mig_binn, "host_drv_ver", &host_drv_ver)) {
		cn_dev_core_err(mig_set->core, "No host_drv_ver");
		ret = -EINVAL;
		goto RETURN;
	}

	if (!binn_object_get_uint32(mig_binn, "cahce_size", &cahce_size)) {
		cn_dev_core_err(mig_set->core, "No cahce_size");
		ret = -EINVAL;
		goto RETURN;
	}

	if (!binn_object_get_uint32(mig_binn, "mcu_major", &mcu_major)) {
		cn_dev_core_err(mig_set->core, "No mcu_major");
		ret = -EINVAL;
		goto RETURN;
	}

	if (!binn_object_get_uint32(mig_binn, "mcu_minor", &mcu_minor)) {
		cn_dev_core_err(mig_set->core, "No mcu_minor");
		ret = -EINVAL;
		goto RETURN;
	}

	if (host_drv_ver > DRV_VERSION) {
		cn_dev_core_err(mig_set->core,
			"The source ver is newer than dst (source ver:%x) (dst ver:%x)",
			host_drv_ver, DRV_VERSION);
		ret = -EINVAL;
		goto RETURN;
	}

	if (domain != vf) {
		cn_dev_core_err(mig_set->core, "Domian error %x %x", domain, vf);
		ret = -EINVAL;
		goto RETURN;
	}

	mcu_info = &mig_set->core->board_info.mcu_info;
	if ((mcu_info->mcu_major << 8) + mcu_info->mcu_minor <
		((mcu_major << 8) + mcu_minor)) {
		cn_dev_core_err(mig_set->core,
			"MCU ver is newer than dst source(%d:%d) dst(%d:%d)",
			mcu_major, mcu_minor, mcu_info->mcu_major, mcu_info->mcu_minor);
		ret = -EINVAL;
		goto RETURN;
	}

	ret = cn_dm_mig_test_cfg(mig_set->core, DM_FUNC_VF0 + vf, (void *)mig_binn);
	if (ret) {
		cn_dev_core_err(mig_set->core, "Put cfg error");
		goto RETURN;
	}

	mig_set->mig_cache_size[vf] = cahce_size;
	cn_dev_core_info(mig_set->core,
		"vf:%x host_drv_ver:%x cache_size:%x mcu_major:%d mcu_minor:%d",
		vf, host_drv_ver, mig_set->mig_cache_size[vf], mcu_major, mcu_minor);

RETURN:
	cn_kfree(mig_binn);
	return ret;
}

/*
 * Host pf driver may transfer some data in live migration, if a driver want
 * to transfer data, add a enum in mig_host_drv first, and next call this
 * function to set call back
 * mig_priv: the core->mig_set
 * mig_host_drv: the live migration driver index
 * get_host_data_size: the size of driver want to transfer data
 * get_host_data: callback for source get data
 * put_host_data: callback for dst put data
 */
int mig_reg_host_cb(struct cn_core_set *core, int mig_host_drv, void *priv,
	u64 (*get_host_data_size)(void *priv, int vf),
	u64 (*get_host_data)(void *priv, int vf, void *buf, u64 size),
	u64 (*put_host_data)(void *priv, int vf, void *buf, u64 size))
{
	struct cn_mig_set *mig_set = core->mig_set;

	if (!mig_set) {
		return -EINVAL;
	}

	if (mig_host_drv >= MIG_HOST_CNT) {
		return -EINVAL;
	}

	mig_set->host_stru[mig_host_drv].priv = priv;
	mig_set->host_stru[mig_host_drv].get_host_data_size = get_host_data_size;
	mig_set->host_stru[mig_host_drv].get_host_data = get_host_data;
	mig_set->host_stru[mig_host_drv].put_host_data = put_host_data;

	return 0;
}

int mig_card_support(struct cn_core_set *core)
{
	if (core->device_id == MLUID_270 || core->device_id == MLUID_290) {
		return 1;
	}

	return 0;
}

int mig_set_debug(struct cn_core_set *core, enum mig_debug_type type, int en)
{
	int ret = 0;
	int result_len;
	struct mig_h2d_msg_t h2d_msg;
	struct mig_d2h_res_t d2h_res;
	struct mig_debug_payload_t *dbg_pay;
	struct cn_mig_set *mig_set = core->mig_set;

	if (!mig_set) {
		cn_dev_err("mig_set NULL");
		return -1;
	}

	cn_dev_core_info(mig_set->core, "type:%d en:%d", type, en);

	memset((void *)&h2d_msg, 0, sizeof(h2d_msg));
	memset((void *)&d2h_res, 0, sizeof(d2h_res));
	dbg_pay = (struct mig_debug_payload_t *)(&h2d_msg.pay_load[0]);

	h2d_msg.header_type = MIG_HEADER_DEBUG_INFO;
	dbg_pay->set_flag = 1;
	dbg_pay->type = type;
	dbg_pay->enable = en;
	ret = mig_commu_dev(mig_set, &h2d_msg, sizeof(h2d_msg), &d2h_res,
		&result_len);

	if (d2h_res.state) {
		ret = d2h_res.state;
	}

	return ret;
}

int mig_get_debug_info(struct cn_core_set *core, enum mig_debug_type type, int *en)
{
	int ret = 0;
	int result_len;
	struct mig_h2d_msg_t h2d_msg;
	struct mig_d2h_res_t d2h_res;
	struct mig_debug_payload_t *dbg_pay;
	struct mig_debug_payload_t *dbg_res;
	struct cn_mig_set *mig_set = core->mig_set;

	if (!mig_set) {
		cn_dev_err("mig_set NULL");
		return -1;
	}

	if (!en) {
		return -1;
	}

	memset((void *)&h2d_msg, 0, sizeof(h2d_msg));
	memset((void *)&d2h_res, 0, sizeof(d2h_res));
	dbg_pay = (struct mig_debug_payload_t *)(&h2d_msg.pay_load[0]);
	dbg_res = (struct mig_debug_payload_t *)(&d2h_res.pay_load[0]);

	h2d_msg.header_type = MIG_HEADER_DEBUG_INFO;
	dbg_pay->set_flag = 0;
	dbg_pay->type = type;
	ret = mig_commu_dev(mig_set, &h2d_msg, sizeof(h2d_msg), &d2h_res,
		&result_len);

	*en = (int)dbg_res->enable;
	cn_dev_core_info(mig_set->core, "type:%d en:%d", type, dbg_res->enable);

	if (d2h_res.state) {
		ret = d2h_res.state;
	}

	return ret;
}


int cn_mig_late_init(struct cn_core_set *core)
{
	struct cn_mig_set *mig_set;

	if (!mig_card_support(core)) {
		return 0;
	}

	mig_set = cn_kzalloc(sizeof(struct cn_mig_set), GFP_KERNEL);
	if (!mig_set) {
		cn_dev_core_err(core, "kzalloc mig_set data space error!");
		return -ENOMEM;
	}
	core->mig_set = mig_set;
	mig_set->core = core;

	mig_set->commu_chn = commu_open_a_channel("mgr_commu", core, 0);
	if (!mig_set->commu_chn) {
		cn_xid_err(core, XID_RPC_ERR, "Open channel mig_commu error");
		return -EFAULT;
	}

	mig_set->endpoint = connect_msg_endpoint(mig_set->commu_chn);
	if (!mig_set->endpoint) {
		cn_dev_err("connect endpoint mig_commu failed.");
		return -EFAULT;
	}

	init_waitqueue_head(&core->mig_wq);

	return 0;
}

void cn_mig_late_exit(struct cn_core_set *core)
{
	int i;
	struct cn_mig_set *mig_set;

	if (!mig_card_support(core)) {
		return;
	}

	mig_set = core->mig_set;
	if (!mig_set) {
		return;
	}

	for (i = 0; i < 8; i++) {
		if (!mig_set->vf_mig[i]) {
			continue;
		}

		mig_release(mig_set, i);
	}

	if (mig_set->endpoint) {
		disconnect_endpoint(mig_set->endpoint);
	}
	if (mig_set->commu_chn) {
		close_a_channel(mig_set->commu_chn);
	}
	cn_kfree(core->mig_set);
	core->mig_set = NULL;
}
