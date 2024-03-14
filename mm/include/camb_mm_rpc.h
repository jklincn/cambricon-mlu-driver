/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#ifndef __CAMBRICON_MM_RPC_H__
#define __CAMBRICON_MM_RPC_H__

#define ERROR_RPC_RESET (-2)

size_t __get_rpc_buf_size(bool ipcm_enabled);

void *__mem_open_channel(char *name, void *mem_set);
void __mem_destroy_channel(struct cn_core_set *core, void **ept);

int __mem_call_rpc(void *pcore, void *handle, char *func, void *msg,
		size_t msg_len, void *rsp, size_t *real_sz, size_t rsp_len);
int __mem_endpoint_dump(void *pcore, void *handle);

#define RPC_TRANS_MAX_LEN(ipcm_enabled)  (__get_rpc_buf_size(ipcm_enabled))
#endif /* __CAMBRICON_MM_RPC_H__ */
