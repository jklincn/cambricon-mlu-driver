#include "cndrv_core.h"
#include "cndrv_commu.h"
#include "cndrv_ipcm.h"
#include "cndrv_gdma.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif
#include "cndrv_xid.h"
#include "gdma_common_api.h"

void *__gdma_open_channel(struct cn_core_set *core, char *name)
{
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

int __gdma_close_channel(struct cn_core_set *core, void *handle)
{
	if (!core || !handle) {
		return -EINVAL;
	}
	if (core->support_ipcm) {
		ipcm_destroy_channel((struct rpmsg_device *)handle);
	} else {
		disconnect_endpoint((struct commu_endpoint *)handle);
	}

	return 0;
}

int __gdma_call_rpc(struct cn_core_set *core,
 				void *handle,
				char *func,
				void *in,
				size_t in_size,
				void *out,
				size_t *read_size,
				size_t rsp_size)
{
	int ret = 0;

	if (handle == NULL) {
		pr_err("%s: fails, handle == NULL\n", __func__);
		return -EINVAL; }
retry:
	if (core->support_ipcm) {
		ret = ipcm_rpc_call_async((struct rpmsg_device *)handle, func, in,
			in_size, out, (u32 *)read_size, rsp_size);
	} else {
		ret = commu_call_rpc((struct commu_endpoint *)handle, func, in,
			in_size, out, (int *)read_size);
		if (ret < 0) {
			cn_dev_core_err(core, "commu rpc call failed:%d.", ret);
			goto err_ret;
		}
		ret = ((struct memcpy_d2d_out *)out)->ret;
	}

	if (ret == -EBUSY) {
		cn_dev_core_debug(core, "ret:%d need retry.", ret);
		usleep_range(10, 15);
		goto retry;
	}

err_ret:
	if (ret == -2) {
		cn_dev_core_err(core, "ret:%d error deinitialized.", ret);
		ret = -EPIPE;
	}

	return ret;
}
