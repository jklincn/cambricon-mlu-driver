#include "cndrv_debug.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/platform_device.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_mcu.h"

#include "monitor.h"
#include "axi_monitor/cndrv_axi_monitor.h"

#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_lpm.h"
#include "pmu_version/pmu_version.h"

#include "cndrv_mem_perf.h"
#include "monitor/time/cndrv_time.h"

int monitor_read_param(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	void *param = NULL;
	int data_size = 0;
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor read param");

	data_size = cn_monitor_get_param_len();
	param = cn_kzalloc(data_size, GFP_KERNEL);
	if (!param) {
		cn_dev_monitor_err(mset, "alloc param fail");
		return -ENOMEM;
	}

	ret = cn_monitor_get_param(core->monitor_set, param);
	if (copy_to_user((void*)arg, param, data_size)) {
		cn_dev_monitor_err(mset, "copy_to_user failed");
		ret = -EFAULT;
	}
	cn_kfree(param);

	return ret;
}

int monitor_read_default_config(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	void *mon_conf = NULL;
	int data_size = 0;
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor axi default");

	ret = cn_monitor_get_axi_struct_size(core->monitor_set, &data_size);
	if (ret) {
		cn_dev_monitor_err(mset, "get default axi struct size failed");
		return -EFAULT;
	}

	mon_conf = cn_kzalloc(data_size, GFP_KERNEL);
	if (!mon_conf) {
		cn_dev_monitor_err(mset, "alloc mon_conf fail");
		return -ENOMEM;
	}

	if (copy_from_user(mon_conf, (void*)arg, data_size)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		cn_monitor_axi_struct_default(mon_conf);
		if (copy_to_user((void*)arg, mon_conf, data_size)) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}
	cn_kfree(mon_conf);

	return ret;
}

int monitor_axi_open(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	void *mon_conf = NULL;
	u32 data_size = 0;
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor axi open");

	ret = cn_monitor_get_axi_struct_size(core->monitor_set, &data_size);
	if (ret) {
		cn_dev_monitor_err(mset, "get default axi struct size failed");
		goto out;
	}

	mon_conf = cn_kzalloc(data_size, GFP_KERNEL);
	if (!mon_conf) {
		cn_dev_monitor_err(mset, "alloc mon_conf fail");
		ret = -ENOMEM;
		goto out;
	}
	if (copy_from_user(mon_conf, (void*)arg, data_size)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_open(core->monitor_set, mon_conf);
		//if (copy_to_user((void*)arg, (void*)mon_conf, sizeof(monitor_axi_t))) {
		//	cn_dev_monitor_err(mset, "copy_to_user failed");
		//	ret = -EFAULT;
		//}
	}
	cn_kfree(mon_conf);
out:
	return ret;
}

int monitor_axi_close(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	u16 monitor_id;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor axi close");

	if (copy_from_user((void*)&monitor_id, (void*)arg, sizeof(u16))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_close(core->monitor_set, monitor_id);
		//if (copy_to_user((void*)arg, (void*)&mon_conf, sizeof(monitor_axi_t))) {
		//	cn_dev_monitor_err(mset, "copy_to_user failed");
		//	ret = -EFAULT;
		//}
	}

	return ret;
}

int monitor_axi_openall(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	u8 hub_id = 0;
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor axi open all");

	if (copy_from_user((void *)&hub_id, (void*)arg, sizeof(u8))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_openall(core->monitor_set, hub_id);
	}

	return ret;
}

int monitor_axi_closeall(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	u8 hub_id = 0;
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor axi close");

	if (copy_from_user((void*)&hub_id, (void*)arg, sizeof(u8))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_closeall(core->monitor_set, hub_id);
	}

	return ret;
}

int monitor_axi_set_timeset(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	u16  set_param;
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor set timestamp");

	if (copy_from_user((void*)&set_param, (void*)arg, sizeof(u16))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_set_ts_mode(core->monitor_set, set_param);
		//if (copy_to_user((void*)arg, (void*)&mon_conf, sizeof(monitor_axi_t))) {
		//	cn_dev_monitor_err(mset, "copy_to_user failed");
		//	ret = -EFAULT;
		//}
	}

	return ret;
}

int monitor_axi_read_data(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor read data");

	ret = cn_monitor_read_data(mset, (void *)arg);

	return ret;
}

int monitor_pmu_read_data_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct pmu_data_s pmu_info;
	u32 cpsize = sizeof(struct pmu_data_s);
	struct cn_monitor_set *mset = core->monitor_set;

	memset(&pmu_info, 0, cpsize);
	if (copy_from_user((void *)&pmu_info, (void *)arg, cpsize)) {
		ret = -EFAULT;
		goto out;
	}

	ret = cn_pmu_read_data(core->monitor_set, &pmu_info);
	if (!ret) {
		if (copy_to_user((void *)arg, &pmu_info, cpsize)) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}

out:
	return ret;
}

int monitor_axi_update_pmu_data_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor update data async");

	ret = cn_monitor_update_perf_data_async(mset, arg);

	return ret;
}

int monitor_axi_read_irq(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct axi_monitor_irqstatus irq_status;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor read irq status");

	if (copy_from_user((void*)&irq_status, (void*)arg, sizeof(struct axi_monitor_irqstatus))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_read_irqstatus(core->monitor_set, &irq_status);
		if (copy_to_user((void*)arg, (void*)&irq_status, sizeof(struct axi_monitor_irqstatus))) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}

	return ret;
}

int monitor_axi_read_err(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct axi_monitor_errinfo err_info;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor read error info");

	if (copy_from_user((void*)&err_info, (void*)arg, sizeof(struct axi_monitor_errinfo))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_read_errorinfo(core->monitor_set, (void *)&err_info);
		if (copy_to_user((void*)arg, (void*)&err_info, sizeof(struct axi_monitor_errinfo))) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}

	return ret;
}

int monitor_axi_direct_mode(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct monitor_amh_direct_mode mode_info;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor enter direct mode");

	if (copy_from_user((void*)&mode_info, (void*)arg, sizeof(struct monitor_amh_direct_mode))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_direct_mode(core->monitor_set, (void *)&mode_info);
	}

	return ret;
}

int monitor_perf_set_ipuperf(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	void *param = NULL;
	int data_size = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor ipu profiling set");

	data_size = sizeof(struct monitor_ipu_perf);
	param = cn_kzalloc(data_size, GFP_KERNEL);
	if (!param) {
		cn_dev_monitor_err(mset, "alloc fail");
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(param, (void*)arg, data_size)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_set_ipu_perf(core->monitor_set, param);
	}
	cn_kfree(param);

out:
	return ret;
}

int monitor_perf_set_smmuperf(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	void *param = NULL;
	int data_size = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor smmu performance set");

	data_size = sizeof(struct monitor_smmu_perf);
	param = cn_kzalloc(data_size, GFP_KERNEL);
	if (!param) {
		cn_dev_monitor_err(mset, "alloc fail");
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(param, (void*)arg, data_size)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_set_smmu_perf(core->monitor_set, param);
	}
	cn_kfree(param);

out:
	return ret;
}

int monitor_perf_set_llcperf(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	void *param = NULL;
	int data_size = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor llc performance set");

	data_size = sizeof(struct monitor_llc_perf);
	param = cn_kzalloc(data_size, GFP_KERNEL);
	if (!param) {
		cn_dev_monitor_err(mset, "alloc fail");
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(param, (void*)arg, data_size)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_set_llc_perf(core->monitor_set, param);
	}
	cn_kfree(param);

out:
	return ret;
}

int monitor_perf_ctrl_l1cperf(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	void *param = NULL;
	int data_size = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor l1c performance set");

	data_size = sizeof(struct monitor_l1c_perf_ctrl);
	param = cn_kzalloc(data_size, GFP_KERNEL);
	if (!param) {
		cn_dev_monitor_err(mset, "alloc fail");
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(param, (void*)arg, data_size)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_ctrl_l1c_perf(core->monitor_set, param);
	}
	cn_kfree(param);

out:
	return ret;
}

int monitor_perf_set_l1cperf(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	void *param = NULL;
	int data_size = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor l1c performance set");

	data_size = sizeof(struct monitor_l1c_perf_cfg);
	param = cn_kzalloc(data_size, GFP_KERNEL);
	if (!param) {
		cn_dev_monitor_err(mset, "alloc fail");
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(param, (void*)arg, data_size)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_set_l1c_perf(core->monitor_set, param);
	}
	cn_kfree(param);

out:
	return ret;
}

int monitor_perf_clear_pmu_data(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor clear profiling data");

	ret = cn_monitor_clr_pmu_data(mset, NULL);

	return ret;
}

int monitor_perf_set_ipuprof(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	void *param = NULL;
	int data_size = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor ipu profiling set");

	data_size = sizeof(struct monitor_ipu_prof);
	param = cn_kzalloc(data_size, GFP_KERNEL);
	if (!param) {
		cn_dev_monitor_err(mset, "alloc fail");
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(param, (void*)arg, data_size)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_set_ipu_profiling(core->monitor_set, param);
	}
	cn_kfree(param);

out:
	return ret;
}

int monitor_ts_offset_get(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	int struct_size = sizeof(struct monitor_ts_offset);
	struct monitor_ts_offset ts_offset;
	struct cn_monitor_set *mset = core->monitor_set;

	ret = cn_monitor_ts_offset_get(mset, &ts_offset);

	if (!ret) {
		if (copy_to_user((void*)arg, &ts_offset, struct_size)) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}

	return ret;
}

int monitor_version_check(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	int i = 0;
	u64 pmu_version = 0;
	u64 perf_version = 0;
	u64 mem_perf_version = 0;
	u64 checkpoint_version = 0;
	u64 bsp_version = 0;
	u64 tmp_version = 0;
	u64 tmp_size = 0;
	struct monitor_version_check_v1 version_param_v1;
	u64 *version_cfg_data = NULL;
	u64 *version_cfg_data_dst = NULL;
	struct __version_check __vc_header;
	struct cn_monitor_set *mset = core->monitor_set;


	if (copy_from_user((void *)&version_param_v1, (void __user *)arg,
				sizeof(struct monitor_version_check_v1))) {
		cn_dev_monitor_err(mset, "_MONITOR_VERSION_CHECK copy_from_user failed!");
		return -EFAULT;
	}

	if (version_param_v1.papi_version <= DRIVER_MONITOR_USER_ID_VERSION_5) {
		/* old verison */
		ret = cn_pmu_version_check(mset, version_param_v1.papi_version, NULL, 0, &pmu_version);
		ret |= __perf_version_check(fp, mset, version_param_v1.papi_version, NULL, 0, &perf_version);
		tmp_version = pmu_version < perf_version ? perf_version : pmu_version;
		version_param_v1.drv_version = tmp_version < bsp_version ? bsp_version : tmp_version;
		if (ret) {
			cn_dev_monitor_err(mset, "_MONITOR_VERSION_CHECK input different version with before!");
			ret = -EINVAL;
		}

		if (copy_to_user((void __user *)arg, (void *)&version_param_v1, sizeof(struct monitor_version_check_v1))) {
			cn_dev_monitor_err(mset, "_MONITOR_VERSION_CHECK copy_to_user failed!");
			return -EFAULT;
		}
	} else {
		/* new version */
		if (copy_from_user((void *)&__vc_header, (void __user *)arg, sizeof(struct __version_check))) {
			cn_dev_monitor_err(mset, "_MONITOR_VERSION_CHECK copy_from_user failed!");
			return -EFAULT;
		}

		if (__vc_header.len != 0) {
			tmp_size = __vc_header.len * sizeof(u64);
			version_cfg_data = (u64 *)cn_kzalloc(tmp_size, GFP_KERNEL);
			if (!version_cfg_data) {
				cn_dev_monitor_err(mset, "kzalloc version_cfg_data failed!");
				return -EINVAL;
			}
			version_cfg_data_dst = (void *)((u64)arg + sizeof(struct __version_check));

			if (copy_from_user((void *)version_cfg_data, (void __user *)version_cfg_data_dst, tmp_size)) {
				cn_dev_monitor_err(mset, "_MONITOR_VERSION_CHECK copy_from_user failed!, 0x%llx", (u64)version_cfg_data_dst);
				if (__vc_header.len != 0)
					cn_kfree(version_cfg_data);
				return -EFAULT;
			}
		}

		ret |= cn_pmu_version_check(mset, __vc_header.papi_version,
				version_cfg_data, __vc_header.len, &pmu_version);
		ret |= __perf_version_check(fp, mset, mset->rec_version,
				version_cfg_data, __vc_header.len, &perf_version);
		ret |= cn_mem_perf_version_check(fp, core, mset->rec_version,
				version_cfg_data, __vc_header.len, &mem_perf_version);
		ret |= cn_mem_cp_version_check(fp, core, mset->rec_version,
				version_cfg_data, __vc_header.len, &checkpoint_version);
		
		for (i = 0; i < __vc_header.len; i++) {
			if (!(version_cfg_data[i] & DRIVER_FEAT_MASK)) {
				version_cfg_data[i] = 0x0ULL;
			}
		}

		__vc_header.drv_version = pmu_version;

		if (ret) {
			cn_dev_monitor_err(mset, "_MONITOR_VERSION_CHECK failed! ret is %d", ret);
			ret = -EINVAL;
		}

		if (copy_to_user((void __user *)arg, (void *)&__vc_header, sizeof(struct __version_check))) {
			cn_dev_monitor_err(mset, "_MONITOR_VERSION_CHECK copy_to_user failed!");
			if (__vc_header.len != 0)
				cn_kfree(version_cfg_data);
			return -EFAULT;
		}

		if (__vc_header.len != 0) {
			if (copy_to_user((void __user *)version_cfg_data_dst, (void *)version_cfg_data, tmp_size)) {
				cn_dev_monitor_err(mset, "_MONITOR_VERSION_CHECK copy_to_user failed!");
				cn_kfree(version_cfg_data);
				return -EFAULT;
			}
			cn_kfree(version_cfg_data);
		}
	}

	return ret;
}


static inline
u64 __perf_cfg_parse(struct cn_monitor_set *mset, u64 data_size,
		u64 data_host_ptr, struct perf_cfg_data *__cfg_data)
{
	int i;
	u64 task_type;
	struct perf_cfg_tasks *cfg_data;

	if (!(data_size && data_host_ptr)) {
		__cfg_data->ts_perf = NULL;
		__cfg_data->mem_perf = NULL;
		return 0;
	}

	cfg_data = (struct perf_cfg_tasks *)cn_kzalloc(data_size, GFP_KERNEL);
	if (!cfg_data) {
		cn_dev_monitor_err(mset, "alloc 0x%llx bytes cfg data failed!", data_size);
		return -EFAULT;
	}

	if (copy_from_user((void *)cfg_data, (void __user *)data_host_ptr,
						data_size)) {
		cn_dev_monitor_err(mset, "perf copy config data from user failed!, "
				"data_host_ptr is 0x%llx, data_size is %llu",
				data_host_ptr, data_size);
		cn_kfree(cfg_data);
		return -EFAULT;
	}

	memset((void *)__cfg_data, 0, sizeof(struct perf_cfg_data));
	for (i = 0; i < data_size / sizeof(struct perf_cfg_tasks); i++) {
		task_type = (cfg_data[i]).task_type;
		if (__task_type_is_sbts(task_type)) {
			__cfg_data->ts_num++;
			__cfg_data->ts_size += sizeof(struct perf_cfg_tasks);
		} else if (__task_type_is_mem(task_type)) {
			__cfg_data->mem_num++;
			__cfg_data->mem_size += sizeof(struct perf_cfg_tasks);
		} else {
			cn_dev_monitor_warn(mset, "unsupport perf type 0x%llx", task_type);
		}
	}

	if (__cfg_data->ts_size != 0) {
		__cfg_data->ts_perf = (struct perf_cfg_tasks *)cn_kzalloc(__cfg_data->ts_size, GFP_KERNEL);
		if (!__cfg_data->ts_perf) {
			cn_dev_monitor_err(mset, "alloc buffer for ts_perf cfg date failed, "
					"trying to alloc %llu bytes", __cfg_data->ts_size);
			cn_kfree(cfg_data);
			return -EFAULT;
		}
	}

	if (__cfg_data->mem_size != 0) {
		__cfg_data->mem_perf = (struct perf_cfg_tasks *)cn_kzalloc(__cfg_data->mem_size, GFP_KERNEL);
		if (!__cfg_data->mem_perf) {
			cn_dev_monitor_err(mset, "alloc buffer for mem_perf cfg data failed, "
					"trying to alloc %llu bytes", __cfg_data->mem_size);
			cn_kfree(cfg_data);
			return -EFAULT;
		}
	}

	for (i = 0; i < data_size / sizeof(struct perf_cfg_tasks); i++) {
		task_type = (cfg_data[i]).task_type;
		if (__task_type_is_sbts(task_type)) {
			__cfg_data->ts_perf[--__cfg_data->ts_num] = cfg_data[i];
		} else if (__task_type_is_mem(task_type)) {
			__cfg_data->mem_perf[--__cfg_data->mem_num] = cfg_data[i];
		} else {
			cn_dev_monitor_err(mset, "unsupport perf type 0x%llx", task_type);
		}
	}

	cn_kfree(cfg_data);
	return 0;
}

static int inline
__get_perf_cfg_data(struct cn_monitor_set *mset, void *cfg_data,
		unsigned long arg, u64 tsperf_feat)
{
	int ret = 0;
	int cp_size = 0;
	switch (tsperf_feat) {
	case DRIVER_FEAT_TS_PERF_APPEND_DATA_CONFIGURABLE_V2:
		cp_size = sizeof(struct perf_mode_config_v6);
		break;
	case DRIVER_FEAT_TS_PERF_BASE_V1:
		cp_size = sizeof(struct perf_mode_config);
		break;
	default:
		ret = -EINVAL;
		goto err;
	}

	if (copy_from_user((void *)cfg_data, (void __user *)arg, cp_size)) {
		cn_dev_monitor_err(mset, "_PERF_MODE_CONFIG copy_from_user failed!, "
								"copy size is %d, but dst size is %ld", cp_size, sizeof(struct __perf_mode_cfg));
		ret = -EFAULT;
	}

err:
	return ret;
}

int monitor_perf_mode_config(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	u64 ret = 0;
	u64 __ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct __perf_mode_cfg __mode_cfg;
	u64 tsperf_feat;
	struct perf_cfg_data __perf_cfg_data, __dbg_perf_cfg_data;

	memset((void *)&__perf_cfg_data, 0, sizeof(__perf_cfg_data));
	memset((void *)&__dbg_perf_cfg_data, 0, sizeof(__dbg_perf_cfg_data));
	tsperf_feat = __tsperf_get_feature(fp, mset);
	ret = __get_perf_cfg_data(mset, &__mode_cfg, arg, tsperf_feat);
	if (ret) goto err;

	if (tsperf_feat >= DRIVER_FEAT_TS_PERF_APPEND_DATA_CONFIGURABLE_V2) {

		ret = __perf_cfg_parse(mset, __mode_cfg.data_size, (u64)__mode_cfg.data_ptr,
				&__perf_cfg_data);
		if (ret) {
			cn_dev_monitor_err(mset, "pase perf cfg data failed!");
			goto err;
		}

		ret = __perf_cfg_parse(mset, __mode_cfg.debug_data_size, (u64)__mode_cfg.debug_ptr,
				&__dbg_perf_cfg_data);
		if (ret) {
			cn_dev_monitor_err(mset, "pase dbg perf cfg data failed!");
			goto err;
		}

		__ret = cn_monitor_perf_mode_config(fp, mset, &__mode_cfg, __perf_cfg_data, __dbg_perf_cfg_data);
		if (__ret) {
			ret |= TS_PERF_MASK;
			cn_dev_monitor_err(mset, "ts perf mode config failed!");
		}

		__ret = cn_mem_perf_mode_config((void *)fp, core, &__mode_cfg, __perf_cfg_data);
		if (__ret) {
			ret |= MEM_PERF_MASK;
			cn_dev_monitor_err(mset, "mem perf mode config failed!");
		}
	} else {
		ret = cn_monitor_perf_mode_config(fp, mset, &__mode_cfg, __perf_cfg_data, __dbg_perf_cfg_data);
		if (ret) {
			cn_dev_monitor_err(mset, "ts perf mode config failed!");
		}
	}

err:
	if (__perf_cfg_data.ts_perf) cn_kfree(__perf_cfg_data.ts_perf);
	if (__perf_cfg_data.mem_perf) cn_kfree(__perf_cfg_data.mem_perf);
	if (__dbg_perf_cfg_data.ts_perf) cn_kfree(__dbg_perf_cfg_data.ts_perf);
	if (__dbg_perf_cfg_data.mem_perf) cn_kfree(__dbg_perf_cfg_data.mem_perf);
	return ret ? -EINVAL : 0;
}

int monitor_perf_clkid_config(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct perf_clkid_config clkid_config;

	if (copy_from_user((void *)&clkid_config, (void __user *)arg,
					sizeof(clkid_config))) {
		cn_dev_monitor_err(mset, "_PERF_CLKID_CONFIG copy_from_user failed!");
		return -EFAULT;
	}

	ret = cn_monitor_perf_clkid_config(fp, mset, &clkid_config);
	if (ret) {
		cn_dev_monitor_err(mset, "perf clkid config failed!");
		return -EINVAL;
	}

	if (clkid_config.clkid_ops == PERF_CLKID_GET) {
		if (copy_to_user((void __user *)arg, (void *)&clkid_config,
					sizeof(clkid_config))) {
			cn_dev_monitor_err(mset, "_PERF_CLKID_CONFIG copy_to_user failed!");
			return -EFAULT;
		}
	}

	return 0;
}

int monitor_perf_task_type_config_v2(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret1 = 0;
	int ret2 = 0;
	u64 tmp_size;
	u64 *cfg_data = NULL;
	u64 *cfg_data_usr_addr = NULL;
	struct cn_monitor_set *mset = core->monitor_set;
	struct task_config_head cfg_head;
	struct perf_task_type_config_v2 task_type_config;

	/* 1. get cfg_data_head from user  */
	if (copy_from_user((void *)&cfg_head, (void __user *)arg, sizeof(cfg_head))) {
		cn_dev_monitor_err(mset, "_PERF_TASK_TYPE_CONFIG_V2 copy_from_user failed!");
		return -EFAULT;
	}

	/* 2. get cfg data array from user according to cfg_data_head.len */
	if (cfg_head.len == 0)
		return -EINVAL;

	cfg_data_usr_addr = (void *)((u64)arg + sizeof(struct task_config_head));
	if (IS_ERR_OR_NULL(cfg_data_usr_addr)) {
		cn_dev_monitor_err(mset, "_PERF_TASK_TYPE_CONFIG_V2 cfg_data_usr_addr is 0x%llx", (u64)cfg_data_usr_addr);
		return -EINVAL;
	}

	tmp_size = cfg_head.len * sizeof(u64);
	cfg_data = (u64 *)cn_kzalloc(tmp_size, GFP_KERNEL);
	if (!cfg_data) {
		cn_dev_monitor_err(mset, "kzalloc cfg_data failed! tmp size is %llu", tmp_size);
		return -EINVAL;
	}

	if (copy_from_user((void *)cfg_data, (void __user *)cfg_data_usr_addr, tmp_size)) {
		cn_dev_monitor_err(mset, "_PERF_TASK_TYPE_CONFIG_V2 copy_from_user failed!, 0x%llx", (u64)cfg_data_usr_addr);
		if (cfg_head.len != 0)
			cn_kfree(cfg_data);
		return -EFAULT;
	}

	/* 3. process cfg data  */
	ret1 = cn_monitor_perf_task_type_config_v2(fp, mset, cfg_data, cfg_head.len, &task_type_config);
	ret2 = cn_mem_perf_task_type_config_v2(fp, core, cfg_data, cfg_head.len, &task_type_config);

	if (cfg_head.len != 0)
		cn_kfree(cfg_data);

	return (ret1 | ret2);
}


int monitor_perf_task_type_config(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct perf_task_type_config task_type_config;

	if (copy_from_user((void *)&task_type_config, (void __user *)arg,
					sizeof(task_type_config))) {
		cn_dev_monitor_err(mset, "_PERF_TASK_TYPE_CONFIG copy_from_user failed!");
		return -EFAULT;
	}

	if (__task_type_is_sbts(task_type_config.task_type)) {
		ret = cn_monitor_perf_task_type_config(fp, mset, &task_type_config);
	} else if (__task_type_is_mem(task_type_config.task_type)) {
		ret = cn_mem_perf_task_type_config(fp, core, &task_type_config);
	} else {
		ret = -EINVAL;
		cn_dev_monitor_err(mset, "unsupport task type %#llx", task_type_config.task_type);
	}

	if (ret) {
		cn_dev_monitor_err(mset, "perf task type config failed!");
		return -EINVAL;
	}

	if (task_type_config.ops == PERF_TASK_TYPE_GET) {
		if (copy_to_user((void __user *)arg, (void *)&task_type_config,
					sizeof(task_type_config))) {
			cn_dev_monitor_err(mset, "_PERF_TASK_TYPE_CONFIG copy_to_user failed!");
			return -EFAULT;
		}
	}

	return 0;
}

int monitor_perf_tsinfo_size_get(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct perf_info_size_get size_get;

	if (copy_from_user((void *)&size_get, (void __user *)arg,
					sizeof(size_get))) {
		cn_dev_monitor_err(mset, "_PERF_TASK_INFO_SIZE_GET copy_from_user failed!");
		return -EFAULT;
	}

	if (__task_type_is_sbts(size_get.task_type)) {
		ret = cn_monitor_perf_tsinfo_size_get(fp, mset, &size_get);
	} else if (__task_type_is_mem(size_get.task_type)) {
		ret = cn_mem_perf_tsinfo_size_get(fp, core, &size_get);
	} else {
		cn_dev_monitor_err(mset, "unsupport task type!");
		ret = -EFAULT;
	}

	if (ret) {
		cn_dev_monitor_err(mset, "perf info size get failed!");
		return -EFAULT;
	}

	if (copy_to_user((void __user *)arg, (void *)&size_get, sizeof(size_get))) {
		cn_dev_monitor_err(mset, "_PERF_TASK_INFO_SIZE_GET copy_to_user failed!");
		ret = -EFAULT;
	}

	return ret;
}

static u64
perf_tsinfo_get_size(u64 tsperf_feat)
{
	u64 perf_ver_size = 1;

	switch (tsperf_feat) {
	case DRIVER_FEAT_TS_PERF_APPEND_DATA_CONFIGURABLE_V2:
		perf_ver_size = 2;
		break;
	case DRIVER_FEAT_TS_PERF_BASE_V1:
		perf_ver_size = 1;
		break;
	default:
		perf_ver_size = 1;
		break;
	}

	return perf_ver_size;
}

int monitor_perf_tsinfo_get(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	u64 ret = 0, __ret = 0;
	u64 tsperf_feat = 0;
	u64 tsinfo_ver_size = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct perf_task_info_get tsinfo_get;

	tsperf_feat = __tsperf_get_feature(fp, mset);
	tsinfo_ver_size = perf_tsinfo_get_size(tsperf_feat);

	if (copy_from_user((void *)&tsinfo_get, (void __user *)arg,
				tsinfo_ver_size * sizeof(struct perf_task_info))) {
		cn_dev_monitor_err(mset, "_PERF_TASK_INFO_GET copy_from_user failed!");
		return -EFAULT;
	}

	/* ts perf */
	__ret = cn_monitor_perf_tsinfo_get(fp, mset, &tsinfo_get);
	if (__ret) {
		ret |= TS_PERF_MASK;
		cn_dev_monitor_err(mset, "ts perf info get failed!");
	}

	/* mem perf */
	if (tsperf_feat >= DRIVER_FEAT_TS_PERF_APPEND_DATA_CONFIGURABLE_V2) {
		__ret = cn_mem_perf_tsinfo_get(fp, core, &tsinfo_get);
		if (__ret) {
			ret |= MEM_PERF_MASK;
			cn_dev_monitor_err(mset, "mem perf info get failed!");
		}
	}

	if (ret) {
		cn_dev_monitor_err(mset, "perf info get failed!");
		return -EFAULT;
	}

	if (copy_to_user((void __user *)arg, (void *)&tsinfo_get,
				tsinfo_ver_size * sizeof(struct perf_task_info))) {
		cn_dev_monitor_err(mset, "_PERF_TASK_INFO_GET copy_to_user failed!");
		return -EFAULT;
	}

	return 0;
}

int monitor_rpc_open(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;

	ret = (core->state == CN_RUNNING) ? 0 : -1;

	return ret;
}

int monitor_axi_set_highaccurate(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	int state = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	if (copy_from_user(&state, (void*)arg, sizeof(int))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_set_highratemode(core->monitor_set, state);
	}

	return ret;
}

int monitor_lock_pmu(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	unsigned int lock = 0;
	struct cn_monitor_set *monitor_set = core->monitor_set;

	if (copy_from_user(&lock, (void*)arg, sizeof(unsigned int))) {
		cn_dev_monitor_err(monitor_set, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		if (lock == PMU_LOCK) {
			if (monitor_set->lock_fp == 0) {
				cn_dev_monitor_debug(monitor_set,
					"Monitor Lock Flag set %llx", (u64)fp);
				monitor_set->lock_fp = (u64)fp;
				ret = cn_monitor_host_start(monitor_set);
			} else if (monitor_set->lock_fp == (u64)fp) {
				cn_dev_monitor_debug(monitor_set,
					"Monitor Lock Flag already set %llx", monitor_set->lock_fp);
				ret = 0;
			} else {
				cn_dev_monitor_warn(monitor_set,
					"Monitor Lock Failed %llx", (u64)fp);
				ret = -EACCES;
			}
		} else if (lock == PMU_UNLOCK) {
			if (monitor_set->lock_fp == 0) {
				cn_dev_monitor_debug(monitor_set, "Monitor Lock Not set");
				ret = 0;
			} else if (monitor_set->lock_fp == (u64)fp) {
				cn_dev_monitor_debug(monitor_set, "Monitor Unlock");
				ret = cn_monitor_host_exit(monitor_set);
				monitor_set->lock_fp = 0;
			} else {
				ret = 0;
			}
		} else {
			cn_dev_monitor_warn(monitor_set,
				"Invalid Monitor Lock Flag %u", lock);
			ret = -EPERM;
		}
	}

	return ret;
}

int monitor_axi_direct_read_param_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	ret = cn_monitor_highrate_param_common(mset, arg);

	return ret;
}

int monitor_axi_default_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	void *mon_conf = NULL;
	int data_size = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor axi highrate default");

	data_size = cn_monitor_get_pmustruct_len();
	mon_conf = cn_kzalloc(data_size, GFP_KERNEL);
	if (!mon_conf) {
		cn_dev_monitor_err(mset, "alloc mon_conf fail");
		return -ENOMEM;
	}
	if (copy_from_user(mon_conf, (void *)arg, data_size)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		cn_monitor_pmu_struct_default(mon_conf);
		if (copy_to_user((void *)arg, mon_conf, data_size)) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}
	cn_kfree(mon_conf);

	return ret;
}

int monitor_axi_open_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	void *mon_conf = NULL;
	int data_size = 0;

	cn_dev_debug("monitor axi highrate open");

	data_size = cn_monitor_get_pmustruct_len();
	mon_conf = cn_kzalloc(data_size, GFP_KERNEL);
	if (!mon_conf) {
		cn_dev_monitor_err(mset, "alloc mon_conf fail");
		return -ENOMEM;
	}
	if (copy_from_user(mon_conf, (void *)arg, data_size)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_open_common(mset, mon_conf);
	}
	cn_kfree(mon_conf);

	return ret;
}

int monitor_axi_close_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	u16 monitor_id = 0;

	cn_dev_debug("monitor axi highrate close");

	if (copy_from_user((void *)&monitor_id, (void *)arg, sizeof(u16))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_highrate_close(mset, monitor_id);
	}

	return ret;
}

int monitor_axi_openall_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	u8 hub_id = 0;

	cn_dev_debug("monitor axi highrate open all");

	if (copy_from_user((void *)&hub_id, (void *)arg, sizeof(u8))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_openall_common(mset, hub_id);
	}

	return ret;
}

int monitor_axi_closeall_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	u8 hub_id = 0;

	cn_dev_debug("monitor axi highrate close");

	if (copy_from_user((void *)&hub_id, (void *)arg, sizeof(u8))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_highrate_closeall(mset, hub_id);
	}

	return ret;
}

int monitor_axi_direct_mode_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct monitor_direct_mode mode_info;

	memset(&mode_info, 0, sizeof(struct monitor_direct_mode));
	cn_dev_debug("monitor enter highrate mode");

	if (copy_from_user((void *)&mode_info, (void *)arg, sizeof(struct monitor_direct_mode))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_highrate_mode(mset, (void *)&mode_info);
		if (!ret) {
			if (copy_to_user((void *)arg, (void *)&mode_info,
							sizeof(struct monitor_direct_mode))) {
				cn_dev_monitor_err(mset, "copy_to_user failed");
				ret = -EFAULT;
			}
		}
	}

	return ret;
}

int monitor_axi_direct_hub_ctrl_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	ret = cn_monitor_hub_ctrl_common(mset, arg);

	return ret;
}

int monitor_axi_direct_read_ringbuf_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct monitor_read_buffer ring_buf = {};

	memset(&ring_buf, 0, sizeof(struct monitor_read_buffer));
	if (copy_from_user((void *)&ring_buf, (void *)arg, sizeof(struct monitor_read_buffer))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		if (ring_buf.count <= 0) {
			cn_dev_monitor_err(mset, "invalid count failed");
			return -EFAULT;
		}
		ret = cn_monitor_read_ring_buffer(mset, &ring_buf);
		if (!ret) {
			if (copy_to_user((void *)arg, (void *)&ring_buf, sizeof(struct monitor_read_buffer))) {
				cn_dev_monitor_err(mset, "copy_to_user failed");
				ret = -EFAULT;
			}
		}
	}

	return ret;
}

int monitor_axi_direct_read_data_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct monitor_direct_data monitor_data;

	memset(&monitor_data, 0, sizeof(struct monitor_direct_data));
	cn_dev_debug("monitor read highrate data");

	if (copy_from_user((void *)&monitor_data, (void *)arg, sizeof(struct monitor_direct_data))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_highrate_read_data(mset, (void *)&monitor_data);
		if (copy_to_user((void *)arg, (void *)&monitor_data, sizeof(struct monitor_direct_data))) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}

	return ret;
}

int monitor_axi_direct_get_pos_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	ret = cn_monitor_read_ringbuf_pos_common(mset, arg);

	return ret;
}

int monitor_pfmu_hubtrace_config(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct monitor_pfmu_config_hub_trace hub_trace;

	memset(&hub_trace, 0, sizeof(struct monitor_pfmu_config_hub_trace));
	if (copy_from_user((void *)&hub_trace, (void *)arg, sizeof(struct monitor_pfmu_config_hub_trace))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_request_hub_trace(mset, (void *)&hub_trace);
	}

	return ret;
}

int monitor_perf_read_data_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor read data");

	ret = cn_monitor_compatible_read_data(mset, (void *)arg);

	return ret;
}

int monitor_axi_read_irq_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct axi_monitor_irqstatus irq_status;

	cn_dev_debug("monitor read irq status");

	if (copy_from_user((void *)&irq_status, (void *)arg, sizeof(struct axi_monitor_irqstatus))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_read_irqstatus(mset, &irq_status);
		if (copy_to_user((void *)arg, (void *)&irq_status, sizeof(struct axi_monitor_irqstatus))) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}

	return ret;
}

int monitor_axi_read_err_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct axi_monitor_errinfo err_info;

	cn_dev_debug("monitor read error info");

	if (copy_from_user((void *)&err_info, (void *)arg, sizeof(struct axi_monitor_errinfo))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_axi_read_errorinfo(mset, (void *)&err_info);
		if (copy_to_user((void *)arg, (void *)&err_info, sizeof(struct axi_monitor_errinfo))) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}

	return ret;
}

int monitor_fpmu_hubtrace_stop(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct monitor_pfmu_stop_hub_trace stop_hub_trace;

	memset(&stop_hub_trace, 0, sizeof(struct monitor_pfmu_stop_hub_trace));
	if (copy_from_user((void *)&stop_hub_trace, (void *)arg, sizeof(struct monitor_pfmu_stop_hub_trace))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_stop_hub_trace(mset, (void *)&stop_hub_trace);
	}

	return ret;
}

int monitor_axi_drv_ver(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	ret = cn_monitor_axi_driver_ver(mset, arg);

	return ret;
}

int monitor_pfmu_hubtrace_l2p_map(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct monitor_pfmu_hubtrace_table hubtrace_tab;
	u32 cpsize = sizeof(struct monitor_pfmu_hubtrace_table);

	cn_dev_debug("get pfmu ipu map");

	if (copy_from_user((void *)&hubtrace_tab, (void *)arg, cpsize)) {
		return -EFAULT;
	}
	ret = cn_monitor_pfmu_get_hubtrace_l2p(mset, &hubtrace_tab);
	if (copy_to_user((void *)arg, (void *)&hubtrace_tab, cpsize)) {
		ret = -EFAULT;
	}

	return ret;
}

int monitor_pfmu_hubtrace_set(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct monitor_pfmu_config_hub_trace hub_trace;

	memset(&hub_trace, 0, sizeof(struct monitor_pfmu_config_hub_trace));
	if (copy_from_user((void *)&hub_trace, (void *)arg, sizeof(struct monitor_pfmu_config_hub_trace))) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_set_hub_trace(mset, (void *)&hub_trace);
	}

	return ret;
}

int monitor_device_info(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	ret = cn_monitor_card_info(mset, arg);

	return ret;
}

int monitor_axi_read_param_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_read_param *param = NULL;
	u32 data_size = 0;
	u32 real_size = 0;
	struct cn_monitor_set *mset = core->monitor_set;

	cn_dev_debug("monitor read param");

	ret = cn_monitor_get_basic_param_size(core->monitor_set, &data_size);
	if (ret) {
		cn_dev_monitor_err(mset, "get basic param size failed");
		return ret;
	}

	param = cn_kzalloc(data_size, GFP_KERNEL);
	if (!param) {
		cn_dev_monitor_err(mset, "monitor param is null");
		return -EINVAL;
	}

	if (copy_from_user(param, (void *)arg, data_size)) {
		ret = -EFAULT;
	} else {
		real_size = param->buf_size > data_size ? data_size : param->buf_size;
		ret = cn_monitor_get_basic_param(core->monitor_set, param);
		param->buf_size = data_size;
		if (copy_to_user((void*)arg, param, real_size)) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}
	cn_kfree(param);

	return ret;
}

int monitor_axi_get_platform_type_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct monitor_platform_info info;
	u32 cpsize = sizeof(struct monitor_platform_info);
	struct cn_monitor_set *mset = core->monitor_set;

	memset(&info, 0, cpsize);
	if (copy_from_user((void *)&info, (void *)arg, cpsize)) {
		ret = -EFAULT;
		goto out;
	}
	ret = cndrv_mcu_get_platform_info(core, &info);
	if (copy_to_user((void*)arg, &info, cpsize)) {
		cn_dev_monitor_err(mset, "copy_to_user failed");
		ret = -EFAULT;
	}

out:
	return ret;
}

int monitor_axi_get_resource_map_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct monitor_res_map_info info;
	u32 cpsize = sizeof(struct monitor_res_map_info);
	struct cn_monitor_set *mset = core->monitor_set;

	memset(&info, 0, cpsize);
	if (copy_from_user((void *)&info, (void *)arg, cpsize)) {
		ret = -EFAULT;
		goto out;
	}
	ret = cn_monitor_fill_res_map(core->monitor_set, (void *)&info);
	if (copy_to_user((void*)arg, &info, cpsize)) {
		cn_dev_monitor_err(mset, "copy_to_user failed");
		ret = -EFAULT;
	}

out:
	return ret;
}

int monitor_get_resource_param_gen1(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_res_param param = {};
	u32 data_size = sizeof(struct cn_monitor_res_param);
	u32 real_size = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct axi_monitor_head axim_head;

	cn_dev_debug("monitor read resource param");

	memset(&param, 0, sizeof(struct cn_monitor_res_param));
	if (copy_from_user((void *)&axim_head, (void *)arg, sizeof(struct axi_monitor_head)))
		ret = -EFAULT;

	real_size = axim_head.buf_size > data_size ? data_size : axim_head.buf_size;
	if (copy_from_user((void *)&param, (void *)arg, real_size)) {
		ret = -EFAULT;
	} else {
		ret = cn_monitor_get_resource_param(mset, &param);
		param.head.real_size = real_size;
		if (copy_to_user((void*)arg, (void *)&param, real_size)) {
			cn_dev_monitor_err(mset, "copy_to_user failed");
			ret = -EFAULT;
		}
	}

	return ret;
}

int monitor_pfmu_get_cntr_num(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct pfmu_counter_number cnt_num;
	u32 cpsize = sizeof(struct pfmu_counter_number);
	struct cn_monitor_set *mset = core->monitor_set;

	memset(&cnt_num, 0, cpsize);
	cn_dev_debug("get pfmu counter number");

	if (copy_from_user((void *)&cnt_num, (void *)arg, cpsize)) {
		cn_dev_monitor_err(mset, "copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_get_counter_num(mset, &cnt_num);
		if (!ret) {
			ret = copy_to_user((void *)arg, (void *)&cnt_num, cpsize);
		}
	}

	return ret;
}

int monitor_pfmu_get_cntr_type(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct pfmu_counter_type cnt_info;
	u32 cpsize = sizeof(struct pfmu_counter_type);

	memset(&cnt_info, 0, cpsize);
	cn_dev_debug("get pfmu counter type info");

	if (copy_from_user((void *)&cnt_info, (void *)arg, cpsize)) {
		return -EFAULT;
	}
	ret = cn_monitor_get_counter_type(mset, &cnt_info);

	return ret;
}

int monitor_pfmu_set_cntr_type(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct pfmu_counter_type cnt_info;
	u32 cpsize = sizeof(struct pfmu_counter_type);

	memset(&cnt_info, 0, cpsize);
	cn_dev_debug("set pfmu counter type info");

	if (copy_from_user((void *)&cnt_info, (void *)arg, cpsize)) {
		return -EFAULT;
	}
	ret = cn_monitor_set_counter_type(mset, &cnt_info);

	return ret;
}

int monitor_pfmu_set_snapshot_pc(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct pfmu_snapshot_pc snapshot_info;
	u32 cpsize = sizeof(struct pfmu_snapshot_pc);

	memset(&snapshot_info, 0, cpsize);
	cn_dev_debug("set pfmu snapshot pc");

	if (copy_from_user((void *)&snapshot_info, (void *)arg, cpsize)) {
		return -EFAULT;
	}
	ret = cn_monitor_set_snapshot_pc(mset, &snapshot_info);

	return ret;
}

int monitor_pfmu_start(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct monitor_ipu_perf ipu_perf;
	u32 cpsize = sizeof(struct monitor_ipu_perf);

	memset(&ipu_perf, 0, cpsize);
	cn_dev_debug("start pfmu");

	if (copy_from_user((void *)&ipu_perf, (void *)arg, cpsize)) {
		return -EFAULT;
	}
	ret = cn_monitor_pfmu_start(mset, &ipu_perf);

	return ret;
}

int monitor_pfmu_set_event(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct pfmu_event_type pfmu_event;
	u32 cpsize = sizeof(struct pfmu_event_type);

	memset(&pfmu_event, 0, cpsize);
	cn_dev_debug("set pfmu event set");

	if (copy_from_user((void *)&pfmu_event, (void *)arg, cpsize)) {
		return -EFAULT;
	}
	ret = cn_monitor_pfmu_set_event(mset, &pfmu_event);

	return ret;
}

int monitor_pfmu_get_event(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct pfmu_event_info event_info;
	u32 cpsize = sizeof(struct pfmu_event_info);

	memset(&event_info, 0, cpsize);
	if (copy_from_user((void *)&event_info, (void *)arg, cpsize)) {
		return -EFAULT;
	}

	ret = cn_monitor_pfmu_get_event(mset, &event_info);
	if (!ret) {
		ret = copy_to_user((void *)arg, (void *)&event_info, cpsize);
	}

	return ret;
}

int monitor_pfmu_ctrl(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct cn_monitor_set *mset = core->monitor_set;
	struct pfmu_cnt_ctrl pfmu_ctrl;
	u32 cpsize = sizeof(struct pfmu_cnt_ctrl);

	memset(&pfmu_ctrl, 0, cpsize);
	cn_dev_debug("set pfmu ctrl");

	if (copy_from_user((void *)&pfmu_ctrl, (void *)arg, cpsize)) {
		return -EFAULT;
	}
	ret = cn_monitor_pfmu_ctrl(mset, &pfmu_ctrl);

	return ret;
}

int monitor_checkpoint_clear_cache(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct checkpoint_cc_set cc_info;

	memset(&cc_info, 0, sizeof(struct checkpoint_cc_set));
	if (copy_from_user((void *)&cc_info, (void *)arg, sizeof(struct checkpoint_cc_set)))
		return -EFAULT;

	ret = cn_mem_cp_cc_set((void *)core, cc_info.type, cc_info.action);

	return ret;
}

int monitor_checkpoint_get_mem_info(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core)
{
	int ret = 0;
	struct checkpoint_info_get cp_info;
	unsigned long param_size = sizeof(struct checkpoint_info_get);
	unsigned long buf_size = 0;

	memset(&cp_info, 0, param_size);
	if (copy_from_user((void *)&cp_info, (void *)arg, param_size))
		return -EFAULT;

	buf_size = cp_info.buffer_size;
	ret = cn_mem_cp_info_get(core, (void *)cp_info.buffer_addr, &buf_size);
	cp_info.buffer_size = buf_size;
	if (copy_to_user((void*)arg, (void *)&cp_info, param_size)) {
		cn_dev_err("copy_to_user failed");
		ret = -EFAULT;
	}

	return ret;
}
typedef int (*pmu_ioctl_func)(struct file *fp,
	unsigned long arg,
	unsigned int cmd,
	struct cn_core_set *core);

enum monitor_attr {
	ATTR_AXI_MON = 1ULL << 0,
	ATTR_HIGHACCURATE_MODE = 1ULL << 1,
};

static const struct {
	pmu_ioctl_func funcs;
	u64 flags;
} monitor_funcs[MONITOR_MAX_NR_COUNT] = {
	[_MONITOR_READ_PARAM] = {monitor_read_param, ATTR_AXI_MON},
	[_MONITOR_AXI_DEFAULT] = {monitor_read_default_config, ATTR_AXI_MON},
	[_MONITOR_AXI_OPEN] = {monitor_axi_open, ATTR_AXI_MON},
	[_MONITOR_AXI_CLOSE] = {monitor_axi_close, ATTR_AXI_MON},
	[_MONITOR_AXI_OPENALL] = {monitor_axi_openall, ATTR_AXI_MON},
	[_MONITOR_AXI_CLOSEALL] = {monitor_axi_closeall, ATTR_AXI_MON},
	[_MONITOR_SET_TIMEST] = {monitor_axi_set_timeset, ATTR_AXI_MON},
	[_MONITOR_AXI_READIRQ] = {monitor_axi_read_irq, ATTR_AXI_MON},
	[_MONITOR_AXI_READERR] = {monitor_axi_read_err, ATTR_AXI_MON},
	[_MONITOR_AXI_DIRECT_MODE] = {monitor_axi_direct_mode, ATTR_AXI_MON},
	[_MONITOR_READ_DATA] = {monitor_axi_read_data, ATTR_AXI_MON},
	[_MONITOR_GEN1_PMU_DATA_READ] = {monitor_pmu_read_data_gen1, ATTR_AXI_MON},
	[_MONITOR_GEN1_PMU_DATA_UPDATE] = {monitor_axi_update_pmu_data_gen1, ATTR_AXI_MON},

	[_MONITOR_SET_IPUPROF] = {monitor_perf_set_ipuprof, 0},
	[_MONITOR_SET_IPUPMU] = {monitor_perf_set_ipuperf, 0},
	[_MONITOR_SET_SMMUPMU] = {monitor_perf_set_smmuperf, 0},
	[_MONITOR_SET_LLCPMU] = {monitor_perf_set_llcperf, 0},
	[_MONITOR_CLR_PMUDATA] = {monitor_perf_clear_pmu_data, 0},
	[_MONITOR_SET_L1CPMU] = {monitor_perf_set_l1cperf, 0},
	[_MONITOR_CTRL_L1CPMU] = {monitor_perf_ctrl_l1cperf, 0},

	[_MONITOR_TS_INFO_SET] = {NULL, 0},
	[_MONITOR_TS_INFO_GET] = {NULL, 0},
	[_MONITOR_TS_OFFSET_GET] = {monitor_ts_offset_get, 0},
	[_MONITOR_VERSION_CHECK] = {monitor_version_check, 0},
	[_PERF_MODE_CONFIG] = {monitor_perf_mode_config, 0},
	[_PERF_CLKID_CONFIG] = {monitor_perf_clkid_config, 0},
	[_PERF_TASK_TYPE_CONFIG] = {monitor_perf_task_type_config, 0},
	[_PERF_TASK_TYPE_CONFIG_V2] = {monitor_perf_task_type_config_v2, 0},
	[_PERF_TASK_INFO_SIZE_GET] = {monitor_perf_tsinfo_size_get, 0},
	[_PERF_TASK_INFO_GET] = {monitor_perf_tsinfo_get, 0},

	[_MONITOR_PFMU_GET_CNT_NUM] = {monitor_pfmu_get_cntr_num, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_PFMU_GET_CNT_TYPE] = {monitor_pfmu_get_cntr_type, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_PFMU_SET_CNT_TYPE] = {monitor_pfmu_set_cntr_type, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_PFMU_SET_SNAPSHOT_PC] = {monitor_pfmu_set_snapshot_pc, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_PFMU_START] = {monitor_pfmu_start, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_PFMU_EVENT_SET] = {monitor_pfmu_set_event, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_PFMU_EVENT_GET] = {monitor_pfmu_get_event, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_PFMU_CTRL] = {monitor_pfmu_ctrl, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},

	[_MONITOR_SET_HIGHACCURATE] = {monitor_axi_set_highaccurate, 0},
	[_MONITOR_LOCK_PMU] = {monitor_lock_pmu, 0},
	[_MONITOR_TEST_RPCOPEN] = {monitor_rpc_open, 0},

	[_MONITOR_AXI_GEN1_DIRECT_READ_PARAM] = {monitor_axi_direct_read_param_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_DEFAULT] = {monitor_axi_default_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_OPEN] = {monitor_axi_open_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_CLOSE] = {monitor_axi_close_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_OPENALL] = {monitor_axi_openall_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_CLOSEALL] = {monitor_axi_closeall_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_DIRECT_GET_POS] = {monitor_axi_direct_get_pos_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_DIRECT_MODE] = {monitor_axi_direct_mode_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_DIRECT_READ_RINGBUF] = {monitor_axi_direct_read_ringbuf_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_DIRECT_READ_DATA] = {monitor_axi_direct_read_data_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_HUB_TRACE_CONFIG] = {monitor_pfmu_hubtrace_config, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_DIRECT_HUB_CTRL] = {monitor_axi_direct_hub_ctrl_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_READ_DATA] = {monitor_perf_read_data_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_READIRQ] = {monitor_axi_read_irq_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_GEN1_READERR] = {monitor_axi_read_err_gen1, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_HUB_TRACE_STOP] = {monitor_fpmu_hubtrace_stop, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_DRIVER_VER] = {monitor_axi_drv_ver, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_HUB_TRACE_L2P_MAP] = {monitor_pfmu_hubtrace_l2p_map, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},
	[_MONITOR_AXI_HUB_TRACE_SET] = {monitor_pfmu_hubtrace_set, ATTR_AXI_MON |ATTR_HIGHACCURATE_MODE},

	[_MONITOR_AXI_GEN1_CARD_INFO] = {monitor_device_info, 0},
	[_MONITOR_AXI_GEN1_READ_PARAM] = {monitor_axi_read_param_gen1, 0},
	[_MONITOR_AXI_GEN1_PLATFORM_TYPE] = {monitor_axi_get_platform_type_gen1, 0},
	[_MONITOR_AXI_GEN1_RES_MAP] = {monitor_axi_get_resource_map_gen1, 0},

	[_MONITOR_CHECKPOINT_CLEAN_CACHE] = {monitor_checkpoint_clear_cache, 0 },
	[_MONITOR_CHECKPOINT_MEMORY_INFO_GET] = {monitor_checkpoint_get_mem_info, 0},

	[_MONITOR_AXI_GEN1_RES_INFO] = {monitor_get_resource_param_gen1, 0},
};

#define CN_MONITOR_SUPPORT_ATTR(ioc_nr, attr) (monitor_funcs[(ioc_nr) & 0xff].flags & (attr))

static long cn_monitor_attr_check(struct cn_monitor_set *mset,
	unsigned int ioc_nr)
{
	if (unlikely(ioc_nr >= MONITOR_MAX_NR_COUNT || !monitor_funcs[ioc_nr].funcs))
		return -EPERM;

	cn_dev_debug("io_nr: %u, flag: 0x%llx", ioc_nr, monitor_funcs[ioc_nr].flags);

	/* axi monitor support */
	if ((CN_MONITOR_SUPPORT_ATTR(ioc_nr, ATTR_AXI_MON)) &&
		(mset->support_monitor == CN_MONITOR_NOT_SUPPORT)) {
		cn_dev_debug("not support monitor");
		return -EFAULT;
	}

	/* high accurate support */
	if ((CN_MONITOR_SUPPORT_ATTR(ioc_nr, ATTR_HIGHACCURATE_MODE)) &&
		(mset->highrate_mode != AXI_MONITOR_MATCH_ALL_MODE)) {
		cn_dev_debug("not support monitor high accurate mode");
		return -EFAULT;
	}

	return 0;
}


long cn_monitor_ioctl(void *fp,
				void *pcore,
				unsigned int cmd,
				unsigned long arg)
{
	long ret = 0;
	unsigned int ioc_nr = _IOC_NR(cmd);
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_monitor_set *monitor_set;

	cn_dev_debug("monitor ioctl");

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("core is null");
		return -EINVAL;
	}
	monitor_set = core->monitor_set;
	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor is null");
		return -EINVAL;
	}

	if (monitor_set->board_type == BOARD_UNKNOWN)
		return -ENODEV;

	if (unlikely(cndrv_monitor_lpm_get(fp, core))) {
		cn_dev_core_err(core, "monitor get lpm failed!");
		return -EINVAL;
	}

	ret = cn_monitor_attr_check(monitor_set, ioc_nr);
	if (ret)
		goto out;

	ret = monitor_funcs[ioc_nr].funcs(fp, arg, cmd, core);

out:
	cn_dev_debug("monitor ioctl finish");
	return ret;
}
