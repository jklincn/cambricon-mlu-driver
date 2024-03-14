#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/platform_device.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/time.h>
#if (KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE)
#include <linux/time64.h>
#include <linux/timekeeping.h>
#else
#include <linux/timex.h>
#endif
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "../monitor.h"
#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"

int cn_pmu_set_version(void *mset, u32 monitor_version);

int cn_monitor_support_max_ver(void)
{
	/* update driver version for interface change */
	return _MONITOR_DRIVER_VER;
}

int cn_monitor_reserved_version(struct monitor_version *mon_ver)
{
	if (mon_ver->version > _MONITOR_DRIVER_V1 && mon_ver->version < _MONITOR_DRIVER_V16) {
		mon_ver->version = _MONITOR_DRIVER_V1;
	}
	return 0;
}

long cn_monitor_axi_driver_ver(void *mset, unsigned long arg)
{
	struct monitor_version mon_ver;
	struct cn_monitor_set *monitor_set = mset;
	long ret = 0;
	int buf_size = 0;
	u32 max_ver = 0;

	memset(&mon_ver, 0, sizeof(struct monitor_version));
	if (copy_from_user((void *)&mon_ver, (void *)arg, sizeof(u32))) {
		cn_dev_err("copy_from_user failed");
		ret = -EFAULT;
	} else {
		if (!monitor_set->endpoint)
			return -EINVAL;

		max_ver = cn_monitor_support_max_ver();
		if (mon_ver.version > max_ver) {
			mon_ver.version = max_ver;
		}
		if (mon_ver.version < _MONITOR_DRIVER_V16) {
			buf_size = sizeof(u32);
		} else {
			buf_size = sizeof(struct monitor_version);
			mon_ver.drv_ver = max_ver;
		}
		ret = cn_pmu_set_version(mset, mon_ver.version);
		if (copy_to_user((void *)arg, (void *)&mon_ver, buf_size)) {
			cn_dev_err("copy_to_user failed");
			ret = -EFAULT;
		}
		if (!ret) {
			monitor_set->monitor_version = mon_ver.version;
		}
	}
	return ret;
}

/* change interface or param,update driver version */
void cn_monitor_init_drv_ver(void *mset)
{
	struct cn_monitor_set *monitor_set = mset;

	if (monitor_set) {
		monitor_set->monitor_version = _MONITOR_DRIVER_VER;
	}
}

struct cn_aximonitor_ops aximon_mlu300_ops = {
	.open_monitor = cn_monitor_axi_open_with_bw_mode,
	.openall_monitor = cn_monitor_axi_highrate_openall,
	.hub_ctrl = cn_monitor_hub_ctrl,
	.read_ringbuf_pos = cn_monitor_read_ringbuf_pos,
	.highrate_param = cn_monitor_get_highrate_param,
	.get_axistruct_size = cn_monitor_get_pmu_struct_size,
	.get_basic_param_size = cn_monitor_get_baisc_param_size,
	.get_basic_param_data = cn_monitor_get_basic_param_data,
};

int cn_pmu_init_default_ver(void *mset)
{
	struct cn_monitor_set *monitor_set = mset;

	monitor_set->monitor_ops = &aximon_mlu300_ops;

	return 0;
}

int cn_pmu_set_version(void *mset, u32 monitor_version)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;

	switch (monitor_version) {
	case _MONITOR_DRIVER_V128:
		ret = cn_pmu_init_default_ver(monitor_set);
		break;
	default:
		ret = -EFAULT;
		cn_dev_err_limit("pmu invalid version %d \n", monitor_version);
		break;
	}
	return ret;
}

int cn_pmu_reinit_version(void *mset)
{
	struct cn_monitor_set *monitor_set = mset;

	if (monitor_set) {
		monitor_set->pmu_version = 0;
		monitor_set->rec_version = 0;
		monitor_set->monitor_ops = &aximon_mlu300_ops;
	}
	return 0;
}

static int
bsp_version_check(struct cn_monitor_set *mset)
{
	int ret = 0;
	struct cn_board_info *pboardi = NULL;
	struct cn_core_set *core = NULL;

	/*PIGEON BSP lower than v1, not support user match*/
	core = mset->core;
	if (!core) {
		cn_dev_monitor_err(mset, "core is null");
		ret = -EFAULT;
		goto err;
	}

	if (core->board_model == LEOPARD_EDGE || core->board_model == PIGEON) {
		pboardi = &core->board_info;
		if (IS_ERR_OR_NULL(pboardi)) {
			ret = -EFAULT;
			goto err;
		}

		if ((pboardi->bsp_major < 1) && (pboardi->bsp_minor < 10)) {
			ret = -EFAULT;
			goto err;
		}
	} else {
		ret = -EFAULT;
		goto err;
	}

	ret = cn_pmu_init_default_ver(mset);
err:
	return ret;
}

static int support_userid_match(struct cn_monitor_set *mset)
{
	struct cn_board_info *pboardi = NULL;
	struct cn_core_set *core = NULL;

	/*PIGEON BSP lower than v1, not support user match*/
	core = mset->core;
	if (!core) {
		cn_dev_monitor_err(mset, "core is null");
		return 0;
	}

	if (core->board_model == LEOPARD_EDGE || core->board_model == PIGEON) {
		pboardi = &core->board_info;
		if (IS_ERR_OR_NULL(pboardi)) {
			return 0;
		}

		if ((pboardi->bsp_major < 1) && (pboardi->bsp_minor < 10)) {
			return 0;
		} else {
			return 1;
		}
	} else {
		return 0;
	}

	return 0;
}

static void
__check_feature_list(struct cn_monitor_set *monitor_set,
	u64 *feature_data, u64 len, u64 version)
{
	u64 support_feat = 0;
	int i = 0;

	if (!feature_data)
		return;
	switch (version) {
	case DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6:
		support_feat = DRIVER_FEAT_MONITOR_LLC_DRAM_V3;
		for (i = 0; i < len; i++) {
			if (feature_data[i] & DRIVER_FEAT_MONITOR_START) {
				if (feature_data[i] > DRIVER_FEAT_MONITOR_MAX_SUPPORT) {
					feature_data[i] = 0;
				}
				support_feat = support_feat < feature_data[i] ? feature_data[i] : support_feat;

				/* toolkit support l1c info */
				if (feature_data[i] == DRIVER_FEAT_MONITOR_L1C_PERF)
					monitor_set->support_l1c = 1;

				if (feature_data[i] == DRIVER_FEAT_MONITOR_USER_ID_V4) {
					if (!support_userid_match(monitor_set))
						feature_data[i] = 0;
				}
			}
		}

		break;
	default:
		break;
	}
}

int cn_pmu_set_last_version(struct cn_monitor_set *monitor_set, u64 *feature_data, u64 len, u64 version)
{
	int ret = 0;

	switch (version) {
	case DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6:
		__check_feature_list(monitor_set, feature_data, len, version);
		ret = cn_pmu_init_default_ver(monitor_set);
		break;
	case DRIVER_MONITOR_USER_ID_VERSION_5:
	/* axi monitor user match */
		ret = bsp_version_check(monitor_set);
		break;
	/*add checkpoint*/
	case DRIVER_DISCARD1_VERSION_4:
	/*add monitor llc to hbm mapping table*/
	case DRIVER_MONITOR_LLC_DRAM_VERSION_3:
	/*add monitor resource mask(llc hbm ipu tinycore mask)*/
	case DRIVER_MONITOR_RESOURCE_MASK_VERSION_2:
	case DRIVER_DIRECT_MODE_VERSION_1:
		ret = cn_pmu_init_default_ver(monitor_set);
		break;
	default:
		ret = -EFAULT;
		break;
	}
	return ret;
}

int cn_pmu_version_check(void *mset, u32 papi_version, u64 *feature_data, u64 len, u64 *pmu_version)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	u64 index_version = papi_version;

	if (!papi_version || !pmu_version) {
		cn_dev_err_limit("pmu invalid papi_version %d \n", papi_version);
		return -EINVAL;
	}
	mutex_lock(&monitor_set->pmu_ver_mutex);

	monitor_set->support_l1c = 0;
	if (monitor_set->rec_version && monitor_set->rec_version != papi_version) {
		__check_feature_list(monitor_set, feature_data, len, monitor_set->pmu_version);
		ret = -EACCES;
		cn_dev_err_limit("pmu last verison is different %llu != %d\n", monitor_set->rec_version, papi_version);
		goto over;
	}
	if (monitor_set->pmu_version) {
		__check_feature_list(monitor_set, feature_data, len, monitor_set->pmu_version);
		goto over;
	}
	do {
		ret = cn_pmu_set_last_version(monitor_set, feature_data, len, index_version);
		if (!ret)
			break;
	} while (--index_version);

	if (!ret) {
		monitor_set->pmu_version = index_version;
	}
	monitor_set->rec_version = (u64)papi_version;
over:
	*pmu_version = monitor_set->pmu_version;

	mutex_unlock(&monitor_set->pmu_ver_mutex);

	return ret;
}
