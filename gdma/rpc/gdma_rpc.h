#ifndef _GDMA_RPC_H
#define _GDMA_RPC_H

void *__gdma_open_channel(struct cn_core_set *core, char *name);

int __gdma_close_channel(struct cn_core_set *core, void *handle);

int __gdma_call_rpc(struct cn_core_set *core,
 				void *handle,
				char *func,
				void *in,
				size_t in_size,
				void *out,
				size_t *read_size,
				size_t rsp_size);

#endif
