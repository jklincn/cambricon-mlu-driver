#include "cndrv_core.h"
#include "cndrv_gdma.h"
#include "cndrv_ipcm.h"
#include "cndrv_commu.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif
#include "gdma_rpc.h"
#include "gdma_api.h"
#include "gdma_common.h"
#include "ce_gdma_api.h"
#include "gdma_common_api.h"
#include "gdma_hal.h"
#include <linux/fs.h>
#ifdef CONFIG_CNDRV_MNT
typedef	int (*report_fn_t)(void *data,
			unsigned long action, void *fp);

extern struct cn_report_block *cn_register_report(struct cn_core_set *core,
				char *name, int prio, report_fn_t fn, void *data);
extern int cn_unregister_report(struct cn_core_set *core, struct cn_report_block *nb);
#endif

static const struct cn_gdma_device_id cn_gdma_dev_ids[] = {
	{.device_id = MLUID_365, .mode = GDMA_HOST_MODE},
	{.device_id = MLUID_370, .mode = GDMA_HOST_MODE},
	{.device_id = MLUID_590, .mode = GDMA_HOST_MODE},
	{.device_id = MLUID_580, .mode = GDMA_HOST_MODE},
	{.device_id = MLUID_365V, .mode = GDMA_DEVICE_MODE},
	{.device_id = MLUID_370V, .mode = GDMA_DEVICE_MODE},
	{.device_id = MLUID_590V, .mode = GDMA_DEVICE_MODE},
	{.device_id = MLUID_580V, .mode = GDMA_DEVICE_MODE},
	{.device_id = MLUID_CE3226, .mode = GDMA_DEVICE_MODE},
	{.device_id = MLUID_CE3226_EDGE, .mode = GDMA_DEVICE_MODE},
	{.device_id = MLUID_PIGEON, .mode = GDMA_HOST_MODE},
	{.device_id = MLUID_PIGEON_EDGE, .mode = GDMA_HOST_MODE},
};

static int ce_gdma_late_init(struct cn_gdma_super_set *gdma_set)
{
	struct cn_core_set *core = gdma_set->core;
	struct ce_gdma_set *ce_gdma = NULL;
	int ret = 0;

	/***
	 * Just create RPC pipe with ARM.
	 */
	if (cn_core_is_vf(core)) {
		cn_dev_core_debug(core, "not pf");
		return 0;
	}

	if ((core->device_id == MLUID_370)
		|| (core->device_id == MLUID_370V)
		|| (core->device_id == MLUID_CE3226)
		|| (core->device_id == MLUID_CE3226_EDGE)
		|| (core->device_id == MLUID_PIGEON)
		|| (core->device_id == MLUID_PIGEON_EDGE)
		|| (core->device_id == MLUID_590)
		|| (core->device_id == MLUID_590V)) {
		ce_gdma = cn_kzalloc(sizeof(struct ce_gdma_set), GFP_KERNEL);
		if (!ce_gdma) {
			cn_dev_core_err(core, "ce_gdma_set alloc memory failed.");
			return -ENOMEM;
		}

		gdma_set->ce_gdma = ce_gdma;

		ce_gdma->gdma_submit_endpoint =
			__gdma_open_channel(core, "copy_engine_submit_krpc");
		if (!ce_gdma->gdma_submit_endpoint) {
			pr_err("gdma_submit_endpoint is NULL\n");
			ret = ENODEV;
			goto err_ret;
		}

		ce_gdma->gdma_sync_endpoint =
			__gdma_open_channel(core, "copy_engine_sync_krpc");
		if (!ce_gdma->gdma_sync_endpoint) {
			pr_err("gdma_sync_endpoint is NULL\n");
			ret = ENODEV;
			goto err_ret;
		}

		sema_init(&ce_gdma->ce_gdma_sema, CE_GDMA_CHAN_SEM_NUM);
	}
	return ret;

err_ret:
	if (gdma_set->ce_gdma) {
		cn_kfree(gdma_set->ce_gdma);
	}
	return ret;
}

static int ce_gdma_late_exit(struct cn_gdma_super_set *gdma_set)
{
	struct cn_core_set *core;
	struct ce_gdma_set *ce_gdma;

	if (!gdma_set || !gdma_set->core || !gdma_set->ce_gdma) {
		return -EINVAL;
	}

	core = gdma_set->core;
	ce_gdma = gdma_set->ce_gdma;
	cn_dev_core_info(core, "ce gdma late exit begin");
	if (ce_gdma->gdma_submit_endpoint) {
		__gdma_close_channel(core, ce_gdma->gdma_submit_endpoint);
		ce_gdma->gdma_submit_endpoint = NULL;
	}

	if (ce_gdma->gdma_sync_endpoint) {
		__gdma_close_channel(core, ce_gdma->gdma_sync_endpoint);
		ce_gdma->gdma_sync_endpoint = NULL;
	}

	cn_kfree(gdma_set->ce_gdma);
	cn_dev_core_info(core, "ce gdma late exit end");

	return 0;
}
#ifdef CONFIG_CNDRV_MNT
static int cn_gdma_ctrl_reg_dfx_dump(struct cn_gdma_set *gdma_set, char *buf)
{
	int ret = 0;
	int ctrl_num = 0;
	int ctrl_index = 0;
	int chnl_index = 0;
	int len = 0;
	int pchan_num = 0;
	struct cn_gdma_controller *ctrl = NULL;
	struct cn_gdma_phy_chan *chan = NULL;

	if (gdma_set == NULL || buf == NULL) {
		return -1;
	}
	pchan_num = cn_gdma_get_ctrl_chan_num(gdma_set);
	ctrl_num = cn_gdma_get_ctrl_num(gdma_set);
	for (ctrl_index = 0; ctrl_index < ctrl_num; ctrl_index++) {
		ctrl = gdma_set->ctrl_pool[ctrl_index];
		ret = ctrl->ops->ctrl_reg_dfx_dump(ctrl, buf + len);
		len += ret;
		for (chnl_index = 0; chnl_index < ctrl->pchan_num; chnl_index++) {
			chan = ctrl->pchans[chnl_index];
			ret = ctrl->ops->channel_reg_dfx_dump(chan, buf + len);
			len += ret;
		}

	}
	return len;
}

static int gdma_dump(void *data,
			     unsigned long action, void *fp)
{
	struct cn_core_set *core = (struct cn_core_set *)data;
	struct cn_gdma_super_set *gdma_su_set = core->gdma_set;
	struct cn_gdma_set *gdma_set = gdma_su_set->host_gdma;
	int ret = -1;
	loff_t pos = 0;
	struct file *fp1 = (struct file *)fp;
	char buf[128];
	int len = 0;
	char *dump_buf = NULL;

#if (KERNEL_VERSION(3, 17, 0) < LINUX_VERSION_CODE)
	struct timespec64 ts;

	ktime_get_ts64(&ts);
#else
	struct timespec ts;

	ktime_get_ts(&ts);
#endif
	memset(buf, 0, sizeof(buf));
	ret = sprintf(buf, "Time:%ld.%ld\n", (unsigned long)ts.tv_sec, ts.tv_nsec);
	if (ret > 0)
		ret = cn_fs_write(fp1, buf, ret, &pos);

	dump_buf = cn_kzalloc(64 * 4096, GFP_KERNEL);
	if (!dump_buf) {
		ret = -1;
		return ret;
	}
	len = cn_gdma_ctrl_reg_dfx_dump(gdma_set, dump_buf);
	if (len > 0) {
		ret = cn_fs_write(fp1, dump_buf, len, &pos);
		cn_kfree(dump_buf);
	}

	return ret;
}
#endif

static int host_gdma_late_init(struct cn_gdma_super_set *gdma_set)
{
	int ret;
	struct cn_core_set *core = gdma_set->core;
	struct cn_gdma_set *host_gdma;

	/*
	 * The real late-init support by host_api
	 * When not config "CONFIG_CNDRV_HOST_GDMA-y" this function is dumy shadow.
	 */
	ret = cn_host_gdma_init(gdma_set);
	if (ret) {
		cn_dev_core_err(core, "gdma init failed!");
		return ret;
	}

	ret = cn_host_gdma_rpc_init(gdma_set);
	if (ret) {
		cn_dev_core_err(core, "gdma rpc init failed!");
		goto rpc_exit;
	}

	host_gdma = gdma_set->host_gdma;
#ifdef CONFIG_CNDRV_MNT
	host_gdma->nb_gdma_dump =
			cn_register_report(core, "gdma_dump", 0, gdma_dump, core);
#endif
	return ret;

rpc_exit:
	cn_host_gdma_exit(gdma_set);
	return ret;
}

static void host_gdma_late_exit(struct cn_gdma_super_set *gdma_set)
{
	struct cn_gdma_set *host_gdma;

	if (!gdma_set || !gdma_set->core || !gdma_set->host_gdma) {
		return;
	}

	host_gdma = gdma_set->host_gdma;
#ifdef CONFIG_CNDRV_MNT
	cn_unregister_report(gdma_set->core, host_gdma->nb_gdma_dump);
#endif
	cn_host_gdma_rpc_exit(gdma_set);

	cn_host_gdma_exit(gdma_set);

	return;
}

int cn_gdma_mode_probe(struct cn_core_set *core, struct cn_gdma_super_set *gdma_set)
{
	int i;
	const struct cn_gdma_device_id *dev_id = NULL;
	int ret = -EINVAL;

	cn_dev_core_info(core, "device id is 0x%llx", core->device_id);

	for (i = 0; i < ARRAY_SIZE(cn_gdma_dev_ids); i++) {
		dev_id = cn_gdma_dev_ids + i;
		if (dev_id->device_id == core->device_id) {
			gdma_set->mode = dev_id->mode;
			ret = 0;
			break;
		}
	}

	return ret;
}

int cn_gdma_late_init(struct cn_core_set *core)
{
	int ret = -1;
	struct cn_gdma_super_set *gdma_set = NULL;
	u32 gdma_mask = 0;
	struct cn_board_info *pboardi = &core->board_info;

	if (core->device_id == MLUID_590 || core->device_id == MLUID_590V) {
		gdma_mask = pboardi->gdma_mask;
		gdma_mask &= 0x3f;
		if (gdma_mask == 0x0) {
			cn_dev_core_warn(core, "MLU590 gdma mask 0, no need init");
			return 0;
		}
	}

	gdma_set = cn_kzalloc(sizeof(struct cn_gdma_super_set), GFP_KERNEL);
	if (!gdma_set) {
		cn_dev_core_err(core, "alloc gdma set memory failed");
		return -ENOMEM;
	}

	ret = cn_gdma_mode_probe(core, gdma_set);
	if (ret) {
		cn_kfree(gdma_set);
		return 0;
	}

	core->gdma_set = (void *)gdma_set;
	gdma_set->core = core;
	switch (gdma_set->mode) {
	case GDMA_HOST_MODE:
		cn_dev_core_info(core, "gdma in host mode");
		ret = host_gdma_late_init(gdma_set);
		if (ret) {
			cn_dev_core_err(core, "gdma host late init failed,%d", ret);
			goto error;
		}
		break;
	case GDMA_DEVICE_MODE:
		cn_dev_core_info(core, "gdma in device mode");
		ret = ce_gdma_late_init(gdma_set);
		if (ret) {
			cn_dev_core_err(core, "ce gdma late init failed,%d", ret);
			goto error;
		}
		break;
	default:
		cn_dev_core_err(core, "gdma invalid mode %d", gdma_set->mode);
		ret = -EINVAL;
		goto error;
	}

	return ret;

error:
	cn_gdma_late_exit(core);

	return ret;
}

void cn_gdma_late_exit(struct cn_core_set *core)
{
	struct cn_gdma_super_set *gdma_set;

	if (!core || !core->gdma_set) {
		return;
	}

	gdma_set = core->gdma_set;
	switch (gdma_set->mode) {
	case GDMA_HOST_MODE:
		host_gdma_late_exit(gdma_set);
		break;
	case GDMA_DEVICE_MODE:
		ce_gdma_late_exit(gdma_set);
		break;
	default:
		cn_dev_core_err(core, "invalid gdma mode,%d", gdma_set->mode);
		break;
	}

	cn_kfree(core->gdma_set);
}

int cn_gdma_able(struct cn_core_set *core)
{
    int able = 1;

    /*
     * Note:
     *    In future the check able logic may be more complex and may be
     *    related with device_id.
     */
    if (!core->gdma_set) {
        able = 0;
    }

    return able;
}

int
cn_gdma_memcpy_sync(struct cn_core_set *core,
					u64 src_vaddr,
					u64 dst_vaddr,
					ssize_t size,
					int compress_type)
{
	int ret = -1;
	struct cn_gdma_super_set *gdma_set = (struct  cn_gdma_super_set *)core->gdma_set;

	if (!gdma_set) {
		return -EINVAL;
	}

	/***
	 * Just show warning without handle about result.
	 */
	d2d_1d_overlap_check(core, src_vaddr,
				dst_vaddr,
				size);

	switch (gdma_set->mode) {
	case GDMA_HOST_MODE:
		ret = cn_host_gdma_memcpy(gdma_set, src_vaddr, dst_vaddr, size, compress_type);
		break;
	case GDMA_DEVICE_MODE:
		ret = cn_ce_gdma_memcpy(gdma_set, src_vaddr, dst_vaddr, size, compress_type);
		break;
	default:
		cn_dev_core_err(core, "gdma mode invalid,mode %d", gdma_set->mode);
		break;
	}

	if (unlikely(ret)) {
		cn_dev_core_err(core,
					"[GDMA]:gdma memcpy sync failed,mode %d,ret %d",
					gdma_set->mode,
					ret);
	}

	return ret;
}

int
cn_gdma_memset_sync(struct cn_core_set *core, struct memset_s *t)
{
	int ret = -1;
	struct cn_gdma_super_set *gdma_set = (struct cn_gdma_super_set*)core->gdma_set;

	if (!gdma_set) {
		return -EINVAL;
	}

	switch (gdma_set->mode) {
	case GDMA_HOST_MODE:
		ret = cn_host_gdma_memset(gdma_set, t);
		break;
	case GDMA_DEVICE_MODE:
		ret = cn_ce_gdma_memset(gdma_set, t);
		break;
	default:
		cn_dev_core_err(core, "gdma mode invalid,mode %d", gdma_set->mode);
		break;
	}

	if (unlikely(ret)) {
		cn_dev_core_err(core,
					"[GDMA]:gdma memset sync failed,mode %d,ret %d",
					gdma_set->mode,
					ret);
	}

	return ret;
}

int
cn_gdma_memcpy_2d_sync(struct cn_core_set *core,
						u64 src_vaddr,
						u64 dst_vaddr,
						ssize_t spitch,
						ssize_t dpitch,
						ssize_t width,
						ssize_t height)
{
	int ret = -1;
	struct cn_gdma_super_set *gdma_set = (struct cn_gdma_super_set*)core->gdma_set;

	if (!gdma_set) {
		return -EINVAL;
	}

	switch (gdma_set->mode) {
	case GDMA_HOST_MODE:
		ret = cn_host_gdma_memcpy_2d(gdma_set,
								src_vaddr,
								dst_vaddr,
								spitch,
								dpitch,
								width,
								height);
		break;
	case GDMA_DEVICE_MODE:
		ret = cn_ce_gdma_memcpy_2d(gdma_set,
								src_vaddr,
								dst_vaddr,
								spitch,
								dpitch,
								width,
								height);
		break;
	default:
		cn_dev_core_err(core, "gdma mode invalid,mode %d", gdma_set->mode);
		break;
	}

	if (unlikely(ret)) {
		cn_dev_core_err(core,
					"gdma memcpy 2d sync failed,mode %d,ret %d",
					gdma_set->mode,
					ret);
	}

	return ret;
}

int
cn_gdma_memcpy_3d_sync(struct cn_core_set *core,
						struct memcpy_d2d_3d_compat *p)
{
	int ret = -1;
	struct cn_gdma_super_set *gdma_set = (struct cn_gdma_super_set*)core->gdma_set;

	if (!gdma_set) {
		return -EINVAL;
	}

	switch (gdma_set->mode) {
	case GDMA_HOST_MODE:
		ret = cn_host_gdma_memcpy_3d(gdma_set, p);
		break;
	case GDMA_DEVICE_MODE:
		ret = cn_ce_gdma_memcpy_3d(gdma_set, p);
		break;
	default:
		cn_dev_core_err(core, "gdma mode invalid,mode %d", gdma_set->mode);
		break;
	}

	if (unlikely(ret)) {
		cn_dev_core_err(core,
					"gdma memcpy 3d sync failed,mode %d,ret %d",
					gdma_set->mode,
					ret);
	}

	return ret;
}
