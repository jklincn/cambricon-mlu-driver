#include "cndrv_ipcm.h"
#include "cndrv_commu.h"
#include "camb_pmu_rpc.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_xid.h"

void *__pmu_open_channel(char *name, void *pcore)
{
	struct cn_core_set *core = pcore;
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
			cn_xid_err(core, XID_RPC_ERR, "commu_open_a_channel failed");
			return NULL;
		}

		handle = (void *)connect_rpc_endpoint(commu_chl);
	}

	return handle;
}

int __pmu_disconnect(void *endpoint, void *pcore)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	if (!endpoint) {
		return ret;
	}

	if (core->support_ipcm) {
		ret = ipcm_destroy_channel((struct rpmsg_device *)endpoint);
	} else {
		ret = disconnect_endpoint((struct commu_endpoint *)endpoint);
	}

	return ret;
}

int __pmu_call_rpc(void *pcore, void *handle, char *func, void *msg, size_t msg_len,
				   void *rsp, void *real_sz, size_t rsp_len)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	if (IS_ERR_OR_NULL(core)) {
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(handle)) {
		cn_dev_core_err(core, "Invalid handle\n");
		return -EINVAL;
	}

	if (core->support_ipcm) {
		ret = ipcm_rpc_call((struct rpmsg_device *)handle, func, msg,
				msg_len, rsp, (uint32_t *)real_sz, rsp_len);
	} else {
		ret = commu_call_rpc((struct commu_endpoint *)handle, func, msg,
				msg_len, rsp, (int *)real_sz);
	}

	return ret;
}

int __pmu_call_rpc_timeout(struct cn_core_set *core,
		void *handle, char *func, void *msg, size_t msg_len,
		void *rsp, void *real_sz, size_t rsp_len, int timeout)
{
	int ret = 0;
	int timeout_ms = (timeout / HZ) * 1000;

	if (handle == NULL) {
		cn_dev_core_err(core, "Invalid handle\n");
		return -EINVAL;
	}

	if (core->support_ipcm) {
		ret = ipcm_rpc_call_timeout((struct rpmsg_device *)handle, func, msg,
				msg_len, rsp, (uint32_t *)real_sz, rsp_len, timeout_ms);
	} else {
		ret = commu_call_rpc_timeout((struct commu_endpoint *)handle, func, msg,
				msg_len, rsp, (int *)real_sz, timeout);
	}

	return ret;
}
