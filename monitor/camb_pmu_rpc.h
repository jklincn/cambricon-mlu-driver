#ifndef __CAMBRICON_PMU_RPC_H__
#define __CAMBRICON_PMU_RPC_H__

#include "cndrv_core.h"

void *__pmu_open_channel(char *name, void *pcore);

int __pmu_disconnect(void *endpoint, void *pcore);

int __pmu_call_rpc(void *pcore, void *handle, char *func, void *msg, size_t msg_len,
				   void *rsp, void *real_sz, size_t rsp_len);

int __pmu_call_rpc_timeout(struct cn_core_set *core,
		void *handle, char *func, void *msg, size_t msg_len,
		void *rsp, void *real_sz, size_t rsp_len, int timeout);
#endif /* __CAMBRICON_PMU_RPC_H__ */
