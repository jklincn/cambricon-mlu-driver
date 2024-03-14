#include <linux/uaccess.h>
#include <linux/kernel.h>
#include "cndrv_ioctl.h"
#include "cndrv_core.h"
#include "cndrv_driver_capability.h"
#include "cndrv_sbts.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"

static const driver_capability_list_t k_capability_default = {};

static const driver_capability_list_t k_capability_c30s = {
	.hostfunc_version = CAPABILITY_HOSTFUNC_VERSION_2,
	.queue_exception_infect_notifier_version = CAPABILITY_QE_NOTIFIER_SUPPORT_V1,
	.queue_exception_infect_idc_version = CAPABILITY_QE_IDC_NOTSUPPORT,
	.task_topo_version = CAPABILITY_TASK_TOPO_VERSION_0,
	.sbts_info_version = CAPABILITY_SBTS_INFO_VERSION_V3,
};

static const driver_capability_list_t k_capability_c50 = {
	.hostfunc_version = CAPABILITY_HOSTFUNC_VERSION_2,
	.queue_exception_infect_notifier_version = CAPABILITY_QE_NOTIFIER_SUPPORT_V1,
	.queue_exception_infect_idc_version = CAPABILITY_QE_IDC_NOTSUPPORT,
	.task_topo_version = CAPABILITY_TASK_TOPO_VERSION_0,
	.sbts_info_version = CAPABILITY_SBTS_INFO_VERSION_V3,
};

#define DEFINE_SWITCH_CAPABILTY(plat, capability, result)                      \
	case plat:                                                             \
		result = &capability;                                          \
		break;

/* these capability table show the capability of current driver version in deferent stage */
#define DEFINE_PLATFORM_CAPABILITY_LIST(MACRO, ...)                            \
	MACRO(MLUID_CE3226_EDGE, k_capability_c30s, ##__VA_ARGS__)             \
	MACRO(MLUID_370, k_capability_c30s, ##__VA_ARGS__)                     \
	MACRO(MLUID_370V, k_capability_c30s, ##__VA_ARGS__)                    \
	MACRO(MLUID_365, k_capability_c30s, ##__VA_ARGS__)                     \
	MACRO(MLUID_365V, k_capability_c30s, ##__VA_ARGS__)                    \
	MACRO(MLUID_590, k_capability_c50, ##__VA_ARGS__)                      \
	MACRO(MLUID_590V, k_capability_c50, ##__VA_ARGS__)                     \
	MACRO(MLUID_580, k_capability_c50, ##__VA_ARGS__)                      \
	MACRO(MLUID_580V, k_capability_c50, ##__VA_ARGS__)                     \
	MACRO(MLUID_PIGEON_EDGE, k_capability_c30s, ##__VA_ARGS__)

const driver_capability_list_t *get_capability(struct cn_core_set *core)
{
	const driver_capability_list_t *cap;

	switch (core->device_id) {
		DEFINE_PLATFORM_CAPABILITY_LIST(DEFINE_SWITCH_CAPABILTY, cap)
	default:
		return &k_capability_default;
	}
	return cap;
}

int cn_get_driver_capability(struct cn_core_set *core, void *args)
{
	struct drv_capability_ioctl_cmd get_cap = { 0 };
	int ret = 0;
	unsigned long size = 0;
	const driver_capability_list_t *cap = get_capability(core);
	driver_capability_list_t cap_t = {0};

	memcpy(&cap_t, cap, sizeof(driver_capability_list_t));

	cap_t.topo_node_bitmap_cap = sbts_topo_get_arm_topo_node_bitmap(core);

	cn_dev_core_debug(core, "get driver capability!");
	if (copy_from_user((void *)&get_cap, (void *)args,
			    sizeof(struct drv_capability_ioctl_cmd))) {
		cn_dev_core_err(core, "copy parameters failed!");
		return -EFAULT;
	}

	if (get_cap.version != CAPABILITY_VERSION_1) {
		cn_dev_core_err(core, "get driver capability failed!");
		return -EFAULT;
	}

	size = min_t(unsigned long, get_cap.size,
			sizeof(driver_capability_list_t));
	ret = copy_to_user((void *)get_cap.user_cap_addr, (void *)&cap_t, size);

	return ret;
}
