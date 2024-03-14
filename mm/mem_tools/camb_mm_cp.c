#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_udvm_usr.h"
#include "cndrv_pinned_mm.h"
#include "../hal/hal_llc/llc_common.h"
#include "camb_mm.h"
#include "camb_udvm.h"
#include "camb_pinned_mem.h"
#include "camb_mm_priv.h"
#include "camb_cp.h"
#include "monitor/monitor.h"

#undef CP_HOST_PINNED_MEM

unsigned long camb_per_cp_node_size(void)
{
	return sizeof(struct checkpoint_malloc_node);
}

int __do_copy_cp_node(void *buf, unsigned long addr, unsigned long size,
					   unsigned long type)
{
	struct checkpoint_malloc_node cp_node;

	cp_node.addr = addr;
	cp_node.size = size;
	cp_node.type = type;

	cn_dev_debug("copy_cp_node(%#lx, %#lx, %#lx)\n", addr, size, type);
	/* NOTES: it will be called in the spin_lock context, so ... */
	memcpy(buf, (void *)&cp_node, sizeof(struct checkpoint_malloc_node));

	return 0;
}

int cn_mem_cp_info_get(struct cn_core_set *core, void *user_buf, unsigned long *size)
{
	unsigned long tmp_size = *size;
	unsigned long dev_size = 0;
	unsigned long host_size = 0;
	unsigned long real_size = 0;
	int skip = 0;
	int idx = core->idx;
	char *buf = NULL;
	char *tmp_buf = NULL;
	int ret = 0;

	buf = cn_kzalloc(tmp_size, GFP_KERNEL);
	if (!buf) {
		cn_dev_err("CHECKPOINT ERROR:alloc tmp buffer as %#lx size!", tmp_size);
		return -ENOMEM;
	}

	tmp_buf = buf;
	cn_dev_debug("CHECKPOINT: cp alloc buffer size %#lx", *size);
	/* to get device memory cp size */
	dev_size = udvm_copy_cp_node(tmp_buf, idx, &skip, tmp_size,
								 __do_copy_cp_node);
	cn_dev_debug("CHECKPOINT: dev mem info size %#lx", dev_size);
	/* to get the remain size and tmp buf */
	tmp_buf += min(tmp_size, dev_size);
	tmp_size -= min(tmp_size, dev_size);

#ifdef CP_HOST_PINNED_MEM
	host_size = cn_pinned_mem_copy_cp_node(tmp_buf, &skip, tmp_size,
										   __do_copy_cp_node);
	cn_dev_debug("CHECKPOINT: host mem info size %#lx", host_size);
#endif
	/* return the real cp size */
	real_size = dev_size + host_size;
	if (real_size > *size) {
		goto out;
	}

	if (copy_to_user(user_buf, buf, real_size)) {
		cn_dev_err("%s, copy_to_user failed", __func__);
		ret = -EFAULT;
	}

out:
	/*realse the tmp buffer */
	cn_kfree(buf);
	/* return the total size */
	*size = real_size;

	return ret;
}

int cn_mem_cp_cc_set(struct cn_core_set *core, int type, int action)
{
	int ret = 0;

	switch (type) {
	case CHECKPOINT_CC_TYPE_L1C: {
		cn_dev_core_debug(core, "CHECKPOINT: DO L1C CLEAN");
		//TODO L1C clean
		break;
	}
	case CHECKPOINT_CC_TYPE_LLC: {
		cn_dev_core_debug(core, "CHECKPOINT: DO LLC %s",
					 action ? "CLEAN AND INVALID" : "INVALID");
		ret = llc_maintanance(core, action);
		break;
	}
	case CHECKPOINT_CC_TYPE_ALL:
	default:
		cn_dev_core_debug(core, "CHECKPOINT: DO ALL!");
		//TODO: L1C clean
		ret = llc_maintanance(core, action);
		break;
	}

	return ret;
}

static void __do_cp_feat_check(u64 papi_version, u64 *fdata, u64 fdata_len,
		u64 *version)
{
	int i;

	/* greater than MAX_SUPPORT_FEAT shoulde be zero  */
	for (i = 0; i < fdata_len; i++) {
		if (fdata[i] & DRIVER_FEAT_MEM_CP_START) {
			if (fdata[i] > DRIVER_FEAT_MEM_CP_MAX_SUPPORT)
				fdata[i] = 0;
		}
	}

	*version = DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6;
}


int cn_mem_cp_version_check(void *fp, struct cn_core_set *core,
		u64 papi_version, u64 *fdata, u64 fdata_len, u64 *cp_version)
{
	u64 version = 0;

	if (papi_version < DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6) {
		cn_dev_core_info(core, "papi_version: %llu not support checkpoint", papi_version);
		return 0;
	}

	/*modify the feature_data value by papi_version*/
	__do_cp_feat_check(papi_version, fdata, fdata_len, &version);

	*cp_version = version;

	return 0;
}

