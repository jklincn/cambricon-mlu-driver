/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#include "cndrv_ipcm.h"
#include "cndrv_commu.h"
#include "camb_mm.h"
#include "camb_mm_rpc.h"
#include "cndrv_xid.h"

#include "camb_trace.h"

size_t __get_rpc_buf_size(bool ipcm_enabled)
{
	/* FIXME: ipcm create an function interface in the future */
	return ipcm_enabled ? MAX_BUF_LEN : COMMU_TESTQ_DATA_BUF_SIZE;
}

void *__mem_open_channel(char *name, void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	struct commu_channel *commu_chl = NULL;
	void *handle = NULL;

	if (core->support_ipcm) {
		handle = (void *)ipcm_open_channel(core, name);
		if (handle == NULL) {
			cn_xid_err(core, XID_RPC_ERR, "ipcm_open_channel(%s) failed", name);
		}
	} else {
		commu_chl = commu_open_a_channel(name, core, 0);
		if (commu_chl == NULL) {
			cn_xid_err(core, XID_RPC_ERR, "commu_open_a_channel() failed");
			return NULL;
		}
		handle = (void *)connect_rpc_endpoint(commu_chl);
	}

	return handle;
}

void __mem_destroy_channel(struct cn_core_set *core, void **ept)
{
	if (ept == NULL || *ept == NULL) {
		return;
	}

	if (core->support_ipcm) {
		ipcm_destroy_channel((struct rpmsg_device *)*ept);
		*ept = NULL;
	} else {
		disconnect_endpoint((struct commu_endpoint *)*ept);
		*ept = NULL;
	}
}

int __mem_call_rpc(void *pcore, void *handle, char *func, void *msg,
				   size_t msg_len, void *rsp, size_t *real_sz, size_t rsp_len)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	if (!cn_core_is_vf(core) && cn_is_mim_en(core)) {
		cn_dev_core_debug(core, "not support call rpc in PF SRIOV mode");
		return -EACCES;
	}

	if (core->support_ipcm) {
		ret = ipcm_rpc_call((struct rpmsg_device *)handle, func, msg,
		                            msg_len, rsp, (uint32_t *)real_sz, rsp_len);
	} else {
		ret = commu_call_rpc((struct commu_endpoint *)handle, func, msg,
		                     msg_len, rsp, (int *)real_sz);
	}

	trace_mem_rpc(func);

	return ret;
}

extern int commu_proc_list_endpoint(struct commu_endpoint *endpoint);
int __mem_endpoint_dump(void *pcore, void *handle)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	if (core->support_ipcm) {
		return 0;
	} else {
		return commu_proc_list_endpoint((struct commu_endpoint *)handle);
	}
}
