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
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_commu.h"
#include "cndrv_debug.h"
#include "camb_pmu_rpc.h"
#include "monitor.h"
#include "axi_monitor/cndrv_axi_monitor.h"
#include "cndev/cndev_server.h"
#include "./time/cndrv_time.h"

#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"
#include "./highrate/cndrv_monitor_highrate.h"
#include "cndrv_mm.h"
#include "monitor.h"
#include "cndrv_ipcm.h"
#include "cndrv_lpm.h"
#include "cndrv_mcu.h"
#include "./pmu_version/pmu_version.h"

#define RESULT_MEM_SIZE (0x4000UL)

/*Design value 6.57K  (16K)*/
#define SHARE_MEM_SIZE_MLU270	(0x05000UL)
/*Design value 27.9K  (32K)*/
#define SHARE_MEM_SIZE_CE3226	(0x0D000UL)
/*Design value 30.1K  (64K)*/
#define SHARE_MEM_SIZE_MLU290	(0x11000UL)
/*Design value 27.9K  (32K)*/
#define SHARE_MEM_SIZE_PIGEON	(0x0D000UL)

#define SHARE_MEM_SIZE_MLU370   (0x0D000UL)
#define SHARE_MEM_SIZE_MLU590   (0x17000UL)

#define PROF_SHARE_MEM_SIZE_CE3226 (0x4000UL)
#define PROF_SHARE_MEM_SIZE_MLU370	(0x0A000UL)
#define PROF_SHARE_MEM_SIZE_MLU590	(0x0A000UL)
#define PROF_SHARE_MEM_SIZE_PIGEON (0x4000UL)

/**
* @brief log print function.
*/
void monitor_PrintLog(const char *fmt, ...)
{
	char bufs[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(bufs, 255, fmt, ap);
	printk(KERN_INFO "%s", bufs);
	va_end(ap);
}

int cn_monitor_get_param_len(void)
{
	return sizeof(struct cn_monitor_param);
}
int cn_monitor_get_axiperf_len(void)
{
	return sizeof(struct axi_monitor_data);
}
int cn_monitor_get_axihub_len(void)
{
	return sizeof(struct axi_monitor_data);
}
int cn_monitor_get_pmustruct_len(void)
{
	return sizeof(struct pmu_monitor_config);
}
/**
* @brief read current card's monitor params back.
* @param monitor_set monitor's struct
* @return result
*/
int cn_monitor_get_param(void *mset, void *pdata)
{
	int ret, i;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct axi_param_s axi_param;
	struct cn_monitor_param *param = (struct cn_monitor_param *)pdata;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_GET_PARAM,
				NULL, 0,
				(void *)&axi_param, &in_len, sizeof(struct axi_param_s));
	cn_dev_monitor_debug(monitor_set, "axi get param ret:%d  in_len:%d", ret, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	param->hub_num = axi_param.hub_num;
	for (i = 0; i < 4; i++) {
		param->monitors[i] = axi_param.monitor[i];
	}
	param->card_type = monitor_set->board_type;
	param->sharedata_size = monitor_set->sharememory_size[PMU_INFO];
	return 0;
}

void cn_monitor_fill_resource(struct cn_monitor_set *monitor_set, struct axi_param_s *axi_param, u64 *res_data)
{
	u64 *res_param = monitor_set->res_param;
	u64 i = 0;

	if (res_param) {
		memcpy(res_data, res_param, sizeof(u64) * PMU_MAX_RES);
	}

	for (i = 0; i < axi_param->jpu_num; i++) {
		set_bit(i, (void *)&res_data[PMU_VALID_JPU_MASK]);
	}
	for (i = 0; i < axi_param->llc_num; i++) {
		set_bit(i, (void *)&res_data[PMU_VALID_LLC_MASK]);
	}
	res_data[PMU_VALID_IPU_MASK] = axi_param->phy_ipu_cluster_mask;
	res_data[PMU_VALID_TINYCORE_MASK] = axi_param->phy_tnc_cluster_mask;
	res_data[PMU_TOTAL_IPU_CLUSTER_NUM] = axi_param->ipu_cluster_num;
	res_data[PMU_TOTAL_TINYCORE_CLUSTER_NUM] = axi_param->tnc_cluster_num;
}

int cn_monitor_get_basic_param_data(void *mset, void *pdata)
{
	int ret = 0;
	int i = 0;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct axi_param_s axi_param;
	struct cn_monitor_read_param *param = (struct cn_monitor_read_param *)pdata;
	struct cn_core_set *core = NULL;
	u32 real_count = 0;
	u64 *res_data = NULL;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;
	core = (struct cn_core_set *)monitor_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;
	if (IS_ERR_OR_NULL(monitor_set->endpoint))
		return -EINVAL;

	memset(&axi_param, 0x0, sizeof(struct axi_param_s));

	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_GET_PARAM,
				NULL, 0,
				(void *)&axi_param, &in_len, sizeof(struct axi_param_s));
	cn_dev_monitor_debug(monitor_set, "axi get param ret:%d  in_len:%d", ret, in_len);
	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return -EINVAL;
	}

	param->hub_num = axi_param.hub_num;
	for (i = 0; i < param->hub_num; i++) {
		param->monitors[i] = axi_param.monitor[i];
	}
	param->card_type = monitor_set->board_type;
	param->sharedata_size = monitor_set->sharememory_size[PMU_INFO];
	param->support_data_mode = monitor_set->support_data_mode;

	if (!param->res_cnt) {
		param->res_cnt = PMU_MAX_RES;
		return 0;
	}

	res_data = cn_kzalloc(PMU_MAX_RES * sizeof(u64), GFP_KERNEL);
	if (!res_data) {
		cn_dev_monitor_err(monitor_set, "monitor kzalloc failed");
		return -EINVAL;
	}
	switch (param->version) {
	case 0:
		cn_monitor_fill_resource(monitor_set, &axi_param, res_data);
		break;
	default:
		ret = -EACCES;
		break;
	}

	real_count = param->res_cnt > PMU_MAX_RES ? PMU_MAX_RES : param->res_cnt;
	if (copy_to_user((void *)param->res_data, res_data, real_count * sizeof(u64))) {
		cn_dev_monitor_err(monitor_set, "monitor copy_to_user");
		ret = -EFAULT;
	}

	/* copy tio user the real the count of reasource info */
	param->res_cnt = real_count;
	cn_kfree(res_data);

	return ret;
}

/**
* @brief set user's struct values to default
* @param mon_conf user's config struct
*/
void cn_monitor_axi_struct_default(void *mon_conf)
{
	cndrv_axi_monitor_struct_default(mon_conf);
}

void cn_monitor_pmu_struct_default(void *mon_conf)
{
	cndrv_pmu_monitor_struct_default(mon_conf);
}

int cn_monitor_get_axi_struct_size(void *mset, u32 *size)
{
	int ret = 0;

	if (IS_ERR_OR_NULL(size)) {
		ret = -EFAULT;
	} else {
		*size = sizeof(struct axi_monitor_config);
	}

	return ret;
}

int cn_monitor_get_pmu_struct_size(void *mset, u32 *size)
{
	int ret = 0;

	if (IS_ERR_OR_NULL(size)) {
		ret = -EFAULT;
	} else {
		*size = sizeof(struct pmu_monitor_config);
	}

	return ret;
}

int cn_monitor_get_baisc_param_size(u32 *size)
{
	int ret = 0;

	if (IS_ERR_OR_NULL(size)) {
		ret = -EFAULT;
	} else {
		*size = sizeof(struct cn_monitor_read_param);
	}

	return ret;
}

/**
* @brief open axi monitor by input struct
* @param mset monitor_set
* @param mon_conf monitor config struct
* @return 0 - success
*/
int cn_monitor_axi_open(void *mset, void *mon_conf)
{
	int out_len = 0, ret = 0;
	int in_len = 0;
	u8 hub_id = 0;
	u8 mon_id = 0;
	u32 copy_size = 0;
	struct axi_monitor_config *conf = (struct axi_monitor_config *)mon_conf;
	struct pmu_monitor_config pmu_conf;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	hub_id = (u8)(conf->monitor_id >> 8);
	mon_id = (u8)(conf->monitor_id & 0xff);

	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	out_len = sizeof(struct pmu_monitor_config);
	copy_size = sizeof(struct axi_monitor_config);
	memset(&pmu_conf, 0x0, out_len);
	copy_size = out_len > copy_size ? copy_size : out_len;
	memcpy(&pmu_conf, conf, copy_size);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_OPEN_AXIM,
				&pmu_conf, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi open ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	if (!monitor_set->axi_set) {
		cn_dev_monitor_err(monitor_set, "Invalid axi_set");
		return result;
	}

	if (result) {
		if (!axi_set[hub_id].opened_count) {
		}
	} else {
		if (!axi_set[hub_id].monitors[mon_id]) {
			axi_set[hub_id].monitors[mon_id] = 1;
			axi_set[hub_id].opened_count++;
		}
	}
	return result;
}

int cn_monitor_axi_open_with_bw_mode(void *mset, void *mon_conf)
{
	int out_len, ret;
	int in_len = 0;
	u8 hub_id = 0;
	u8 mon_id = 0;
	struct pmu_monitor_config *pmu_conf = (struct pmu_monitor_config *)mon_conf;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	hub_id = (u8)(pmu_conf->monitor_id>>8);
	mon_id = (u8)(pmu_conf->monitor_id & 0xff);

	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	out_len = sizeof(struct pmu_monitor_config);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_OPEN_AXIM,
				pmu_conf, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi open ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	if (!monitor_set->axi_set) {
		cn_dev_monitor_err(monitor_set, "Invalid axi_set");
		return result;
	}

	if (result) {
		if (!axi_set[hub_id].opened_count) {
		}
	} else {
		if (!axi_set[hub_id].monitors[mon_id]) {
			axi_set[hub_id].monitors[mon_id] = 1;
			axi_set[hub_id].opened_count++;
		}
	}
	return result;
}

/**
* @brief close axi monitor by input id
* @param mset monitor_set
* @param monitor_id monitor id to be close
* @return 0 - success
*/
int cn_monitor_axi_close(void *mset, u16 monitor_id)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	u8 hub_id = 0;
	u8 mon_id = 0;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	hub_id = (u8)(monitor_id>>8);
	mon_id = (u8)(monitor_id & 0xff);

	out_len = sizeof(u16);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_CLOSE_AXIM,
				(void *)&monitor_id, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi close ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	if (!monitor_set->axi_set) {
		cn_dev_monitor_err(monitor_set, "Invalid axi_set");
		return result;
	}

	if (!result && axi_set[hub_id].monitors[mon_id]) {
		axi_set[hub_id].monitors[mon_id] = 0;
		axi_set[hub_id].opened_count--;
	}
	return result;
}

/**
* @brief open axi monitor by input struct
* @param mset monitor_set
* @param mon_conf monitor config struct
* @return 0 - success
*/
int cn_monitor_axi_openall(void *mset, u8 hub_id)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	out_len = 1;
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_OPEN_AXIM,
				&hub_id, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi open ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	if (!monitor_set->axi_set) {
		cn_dev_monitor_err(monitor_set, "Invalid axi_set");
		return result;
	}
	if (!result) {
		axi_set[hub_id].opened_count = axi_set[hub_id].config->monitor_num;
		memset(axi_set[hub_id].monitors, 0x01, axi_set[hub_id].config->monitor_num);
	}
	return result;
}

int cn_monitor_axi_start_openall(void *mset, u8 hub_id)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	out_len = 1;
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_OPEN_AXIM,
				&hub_id, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi open ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

/**
* @brief close axi monitor by input id
* @param mset monitor_set
* @param monitor_id monitor id to be close
* @return 0 - success
*/
int cn_monitor_axi_closeall(void *mset, u8 hub_id)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	out_len = sizeof(u8);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_CLOSE_AXIM,
				(void *)&hub_id, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi close ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	if (!monitor_set->axi_set) {
		cn_dev_monitor_err(monitor_set, "Invalid axi_set");
		return result;
	}
	if (!result) {
		axi_set[hub_id].opened_count = 0;
		memset(axi_set[hub_id].monitors, 0, axi_set[hub_id].config->monitor_num);
	}
	return result;
}

/**
* @brief set timestamp update mode
* @param mset monitor_set
* @param mmode_para update mode
* @return 0 - success
*/
int cn_monitor_set_ts_mode(void *mset, u16 mode_para)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(u16);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_SET_TS,
				(void *)&mode_para, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi set ts ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

/**
* @brief read monitor irq status register [0x00]
* @param mset monitor_set
* @param monitor_id hub and monitor id
* @return irq status code
*/
int cn_monitor_axi_read_irqstatus(void *mset, void *irq_info)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct axi_monitor_irqstatus);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_READ_AXIM_IRQ_STA,
				irq_info, out_len,
				irq_info, &in_len, sizeof(struct axi_monitor_irqstatus));
	cn_dev_monitor_debug(monitor_set, "axi read irqstatus ret:%d in_len:%d", ret, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	return 0;
}

int cn_monitor_axi_read_errorinfo(void *mset, void *err_info)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct axi_monitor_errinfo);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_READ_AXIM_ERR_INF,
				err_info, out_len,
				err_info, &in_len, sizeof(struct axi_monitor_errinfo));
	cn_dev_monitor_debug(monitor_set, "axi read errorinfo ret:%d in_len:%d", ret, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	return 0;
}

int cn_monitor_axi_direct_mode(void *mset, void *mode_info)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_amh_direct_mode);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_SET_AXIH_DIRECT_MODE,
				mode_info, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi set direct mode ret:%d result:%d in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

void cn_monitor_reset_highrate_context(struct highrate_thread_context *thread_context)
{
	if (thread_context) {
		if (thread_context->axi_pfifo) {
			mfifo_reset(thread_context->axi_pfifo);
		}
		thread_context->loss_times = 0;
		atomic64_set(&thread_context->record_times, 0);
		atomic64_set(&thread_context->entry_count, 0);
		thread_context->last_data_flag = 0;
	}
}

int cn_monitor_disable_highrate_mode(void *mset, struct monitor_direct_mode *highrate_mode)
{
	int out_len, ret, in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct highrate_thread_context *thread_context = NULL;
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct amh_high_mode_s direct_mode = {0};
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;
	int i = 0;

	/* check highrate set */
	monitor_highrate_set = monitor_set->monitor_highrate_set;
	if (IS_ERR_OR_NULL(monitor_set->monitor_highrate_set)) {
		cn_dev_monitor_err(monitor_set, "Invalid monitor_highrate_set");
		return -EINVAL;
	}
	thread_context = &monitor_highrate_set->thread_context[highrate_mode->hub_id];

	cn_monitor_axi_closeall(mset, highrate_mode->hub_id);
	ret = monitor_set->ops.stop_hub(&axi_set[highrate_mode->hub_id]);
	if (!ret)
		axi_set[highrate_mode->hub_id].inited = 0;

	if (monitor_set->highrate_start[highrate_mode->hub_id]) {
		cn_dev_monitor_debug(monitor_set, "monitor_highrate cancel work\n");
		cancel_work_sync(&thread_context->hub_work);
	}

	/* assign arguments */
	direct_mode.hub_id = highrate_mode->hub_id;
	direct_mode.status = 0;

	/* direct mode rpc call */
	out_len = sizeof(struct amh_high_mode_s);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_INIT_PMU_HIGHRATE_MODE,
				(void *)&direct_mode, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi set highrate mode ret:%d result:%d in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor highrate rpc call failed, ret = %d", ret);
	}

	/* release resource */
	ret = cn_monitor_release_monitor_highrate_env(monitor_set, thread_context);

	if (monitor_set->highrate_start[highrate_mode->hub_id] == AXI_MON_DIRECT_MODE)
		cndrv_axi_monitor_disable_irq(mset, highrate_mode->hub_id);

	monitor_set->highrate_start[highrate_mode->hub_id] = AXI_MON_NORMAL_MODE;

	for (i = 0; i < ZONE_CONUT; i++) {
		atomic64_set(&axi_set->data_ref_cnt[i], 0);
	}

	return ret;
}

int cn_monitor_enable_highrate_mode(void *mset, struct monitor_direct_mode *highrate_mode)
{
	int out_len, ret, in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct amh_high_mode_s direct_mode = {0};
	int result = 0;
	u16 hub_id = highrate_mode->hub_id;
	struct highrate_thread_context *thread_context = NULL;
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;
	int i = 0;
	u64 zone_size = 0;
	u64 zone_count = 0;
	u64 dev_buffer_size = 0;

	if (IS_ERR_OR_NULL(monitor_set->zone_info)) {
		cn_dev_monitor_err(monitor_set, "Invalid zone info");
		return -EINVAL;
	}
	zone_size = monitor_set->zone_info->zone_size;
	zone_count = monitor_set->zone_info->zone_count;
	dev_buffer_size = monitor_set->zone_info->dev_buffer_size;

	/* check highrate set */
	monitor_highrate_set = monitor_set->monitor_highrate_set;
	if (IS_ERR_OR_NULL(monitor_set->monitor_highrate_set)) {
		cn_dev_monitor_err(monitor_set, "Invalid monitor_highrate_set");
		return -EINVAL;
	}

	thread_context = &monitor_highrate_set->thread_context[hub_id];

	for (i = 0; i < ZONE_CONUT; i++) {
		atomic64_set(&axi_set->data_ref_cnt[i], 0);
	}
	thread_context->cache_size = zone_size;
	direct_mode.report_range_size = zone_size;
	thread_context->dev_buff_size = dev_buffer_size;
	axi_set[hub_id].zone_size = zone_size;

	/* highrate mode env init */
	result = cn_monitor_init_monitor_highrate_env(monitor_set, thread_context, highrate_mode);
	if (result) {
		cn_dev_monitor_err(monitor_set, "init highrate env failed");
		return result;
	}

	/* assign arguments */
	direct_mode.device_addr = thread_context->dev_vaddr;
	direct_mode.buffer_size = thread_context->dev_buff_size;
	direct_mode.hub_id = highrate_mode->hub_id;
	direct_mode.status = highrate_mode->status;
	direct_mode.update_time = 25; // highrate_mode->update_time;

	/* direct mode rpc call */
	out_len = sizeof(struct amh_high_mode_s);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_INIT_PMU_HIGHRATE_MODE,
				(void *)&direct_mode, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi set highrate mode ret:%d result:%d in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor highrate rpc call failed, ret = %d", ret);
		if (result == -100) {
			result = -ENOMEM;
		}
		goto over;
	}

	/* start monitor trace */
	if (!result && direct_mode.status) {
		cndrv_axi_monitor_host_config(mset, highrate_mode);
		monitor_set->highrate_start[highrate_mode->hub_id] = AXI_MON_DIRECT_MODE;
	}

	return result;

over:

	cn_monitor_exit_monitor_highrate_env_by_hubid(monitor_set, highrate_mode->hub_id);
	return result;
}

int cn_monitor_axi_highrate_mode(void *mset, void *mode_info)
{
	struct cn_monitor_set *monitor_set = mset;
	struct monitor_direct_mode *highrate_mode = (struct monitor_direct_mode *)mode_info;
	int ret = 0;
	u16 hub_id = 0;

	/* check monitor set endpoint */
	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	hub_id = highrate_mode->hub_id;
	if (monitor_set->hub_num <= hub_id) {
		cn_dev_monitor_err(monitor_set, "Invalid hub id %u", hub_id);
		return -EINVAL;
	}

	/* re-enable highrate mode */
	if (monitor_set->highrate_start[hub_id] && highrate_mode->status) {
		cn_dev_monitor_err(monitor_set, "can not enable highrate mode. [%u][%u]",
			monitor_set->highrate_start[hub_id], highrate_mode->status);
		return -EINVAL;
	}

	/* disable highrate mode */
	if (!highrate_mode->status) {
		ret = cn_monitor_disable_highrate_mode(mset, highrate_mode);
	} else {
		ret = cn_monitor_enable_highrate_mode(mset, highrate_mode);
		if (!ret) {
			cndrv_axi_monitor_enable_irq(mset, hub_id);
		}
	}

	return ret;
}

size_t cn_monitor_dma(void *bus_set, u64 host_addr, u64 dev_addr, size_t size, DMA_DIR_TYPE direction)
{
	struct transfer_s transfer;

	TRANSFER_INIT(transfer, host_addr, dev_addr, size, direction);

	return cn_bus_dma(bus_set, &transfer);
}

/**
* @brief read monitor data from share memory
* @param mset monitor_set
* @param user's space
* @return 0 - success
*/
int cn_monitor_read_data(void *mset, void *arg)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (core->device_id == MLUID_220_EDGE ||
		core->device_id == MLUID_CE3226_EDGE ||
		core->device_id == MLUID_PIGEON_EDGE) {
		if (copy_to_user(arg,
					(void *)monitor_set->sharememory_host_va[PMU_INFO],
					monitor_set->sharememory_size[PMU_INFO])) {
			cn_dev_monitor_err(monitor_set, "[%s] [%d] copy_to_user failed", __func__, __LINE__);
			ret = -EFAULT;
		}
	} else {
		ret = cn_monitor_dma(monitor_set->bus_set,
				(u64)arg,
				(u64)monitor_set->sharememory_device_va[PMU_INFO],
				monitor_set->sharememory_size[PMU_INFO],
				DMA_D2H);
	}

	return ret;
}

struct pmu_data_layout mlu370_share_mem_layout[TYPE_MAX] = {
	{0, 0},
	{0x6000, 0x4000},
	{0x2000, 0x4000},
	{0, 0x2000},
	{0xA000, 0x2000},
	{0xC000, 0x1000},
};

struct pmu_data_layout ce3226_share_mem_layout[TYPE_MAX] = {
	{0, 0},
	{0x6000, 0x4000},
	{0x2000, 0x4000},
	{0, 0x2000},
	{0xA000, 0x2000},
	{0xC000, 0x1000},
};

struct pmu_data_layout mlu590_share_mem_layout[TYPE_MAX] = {
	{0, 0},
	{0xA000, 0x8000},
	{0x6000, 0x4000},
	{0, 0x6000},
	{0x12000, 0x4000},
	{0x16000, 0x1000},
};

struct pmu_data_layout pigeon_share_mem_layout[TYPE_MAX] = {
	{0, 0},
	{0x6000, 0x4000},
	{0x2000, 0x4000},
	{0, 0x2000},
	{0xA000, 0x2000},
	{0xC000, 0x1000},
};

static int cn_pmu_fill_pmu_data_edge(struct cn_monitor_set *mset, struct pmu_data_s *arg)
{
	int ret = 0;
	u16 type = arg->data_type;

	if (type >= TYPE_MAX)
		return -EFAULT;

	if (IS_ERR_OR_NULL(mset->shmem_layout))
		return -EINVAL;

	if (!arg->buffer) {
		arg->buffer_size = mset->shmem_layout[type].buffer_size;
		return 0;
	}

	switch (type) {
	case TYPE_AXI_MON:
		if (copy_to_user(arg->buffer, (void *)mset->sharememory_host_va[PMU_AXIM_INFO],
				mset->sharememory_size[PMU_AXIM_INFO])) {
			cn_dev_monitor_err(mset, "[%s] [%d] copy_to_user failed", __func__, __LINE__);
			ret = -EFAULT;
		}
	break;
	default:
		if (copy_to_user(arg->buffer,
			(void *)mset->sharememory_host_va[PMU_PERF_INFO] + mset->shmem_layout[type].host_va,
			mset->shmem_layout[type].buffer_size)) {
			cn_dev_monitor_err(mset, "[%s] [%d] copy_to_user failed", __func__, __LINE__);
			ret = -EFAULT;
		}
	break;
	}

	return ret;
}

static int cn_pmu_fill_pmu_data(struct cn_monitor_set *mset, struct pmu_data_s *arg)
{
	int ret = 0;
	u16 type = arg->data_type;

	if (type >= TYPE_MAX)
		return -EFAULT;

	if (IS_ERR_OR_NULL(mset->shmem_layout))
		return -EINVAL;

	if (!arg->buffer) {
		arg->buffer_size = mset->shmem_layout[type].buffer_size;
		return 0;
	}

	switch (type) {
	case TYPE_AXI_MON:
		ret = cn_monitor_dma(mset->bus_set,
			(u64)arg->buffer,
			(u64)mset->sharememory_device_va[PMU_AXIM_INFO],
			mset->sharememory_size[PMU_AXIM_INFO],
			DMA_D2H);

	break;
	default:
		ret = cn_monitor_dma(mset->bus_set,
			(u64)arg->buffer,
			(u64)mset->sharememory_device_va[PMU_PERF_INFO] + mset->shmem_layout[type].host_va,
			mset->shmem_layout[type].buffer_size,
			DMA_D2H);

	break;
	}

	return ret;
}

int cn_monitor_read_data_type(struct cn_monitor_set *mset, void *arg, u16 type, struct monitor_data_head *head)
{
	int ret = 0;
	struct ipu_perf_data_head *ipu_head = NULL;
	struct smmu_perf_data_head *smmu_head = NULL;
	struct llc_perf_data_head *llc_head = NULL;
	struct smmu_exp_data_head *smmu_exp_head = NULL;
	void *sharemem = NULL;
	u64 sharemem_dev = 0;
	int real_size = 0;
	int buffer_size = 0;

	if (type >= TYPE_MAX)
		return -EFAULT;

	if (IS_ERR_OR_NULL(mset->shmem_layout))
		return -EINVAL;

	sharemem = (void *)(mset->sharememory_host_va[PMU_PERF_INFO] + mset->shmem_layout[type].host_va);
	sharemem_dev = (u64)mset->sharememory_device_va[PMU_PERF_INFO] + mset->shmem_layout[type].host_va;

	buffer_size = mset->shmem_layout[type].buffer_size;

	switch (type) {
	case TYPE_IPU_PERF: {
		ipu_head = (struct ipu_perf_data_head *)sharemem;
		head->ipu_perf_num = ipu_head->ipu_perf_num;
		head->ipu_perf_offset = ipu_head->ipu_perf_offset;
		head->entry_count = ipu_head->ipu_perf_entry_count;
		real_size = buffer_size - ipu_head->ipu_perf_offset;
		ret = cn_monitor_dma(mset->bus_set,
					(u64)arg + ipu_head->ipu_perf_offset,
					(u64)sharemem_dev + ipu_head->ipu_perf_offset,
					real_size,
					DMA_D2H);
		break;
	}
	case TYPE_SMMU_PERF: {
		smmu_head = (struct smmu_perf_data_head *)sharemem;
		head->smmu_perf_num = smmu_head->smmu_perf_num;
		head->smmu_perf_offset = 0x4000;
		head->entry_count = smmu_head->smmu_perf_entry_count;
		real_size = buffer_size - smmu_head->smmu_perf_offset;
		ret = cn_monitor_dma(mset->bus_set,
					(u64)arg + head->smmu_perf_offset,
					(u64)sharemem_dev + smmu_head->smmu_perf_offset,
					real_size,
					DMA_D2H);
		break;
	}
	case TYPE_LLC_PERF: {
		llc_head = (struct llc_perf_data_head *)sharemem;
		head->llc_perf_num = llc_head->llc_perf_num;
		head->llc_perf_offset = 0x8000;
		head->entry_count = llc_head->llc_perf_entry_count;
		real_size = buffer_size - llc_head->llc_perf_offset;
		ret = cn_monitor_dma(mset->bus_set,
					(u64)arg + head->llc_perf_offset,
					(u64)sharemem_dev + llc_head->llc_perf_offset,
					real_size,
					DMA_D2H);
		break;
	}
	case TYPE_SMMU_EXP: {
		smmu_exp_head = (struct smmu_exp_data_head *)sharemem;
		head->smmu_exception_num = smmu_exp_head->smmu_exp_num;
		head->smmu_exception_offset = 0xA000;
		head->entry_count = smmu_exp_head->smmu_exp_entry_count;
		real_size = buffer_size - smmu_exp_head->smmu_exp_offset;
		ret = cn_monitor_dma(mset->bus_set,
					(u64)arg + head->smmu_exception_offset,
					(u64)sharemem_dev + smmu_exp_head->smmu_exp_offset,
					real_size,
					DMA_D2H);
		break;
	}
	default:
		break;
	}
	return ret;
}

int cn_pmu_update_perf_data_async(struct cn_monitor_set *mset, void *info)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	int in_len = 0;
	int result = 0;
	int out_len = 0;
	struct perf_update_info_v1 *perf_info = info;
	struct perf_update_rpc_info perf_rpc_info;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	memset(&perf_rpc_info, 0, sizeof(struct perf_update_rpc_info));
	out_len = sizeof(struct perf_update_rpc_info);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_UPADATE_PERF_DATA,
				NULL, 0,
				(void *)&perf_rpc_info, &in_len, sizeof(struct perf_update_rpc_info));
	cn_dev_monitor_debug(monitor_set, "update perf data ret:%d  result:%d  in_len:%d",
			ret, result, in_len);
	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}
	perf_info->update_status = perf_rpc_info.update_status;
	perf_info->ipu_perf_entry_count = perf_rpc_info.ipu_perf_entry_count;
	perf_info->smmu_perf_entry_count = perf_rpc_info.smmu_perf_entry_count;
	perf_info->llc_perf_entry_count = perf_rpc_info.llc_perf_entry_count;
	perf_info->smmu_exp_entry_count = perf_rpc_info.smmu_exp_entry_count;
	perf_info->l1c_perf_entry_count = perf_rpc_info.l1c_entry_count;

	return perf_rpc_info.ret;
}

int cn_monitor_compatible_read_data(void *mset, void *arg)
{
	int ret = 0;
	u16 type = 0;
	struct perf_update_info update_info;
	struct monitor_data_head monitor_head;

	memset(&update_info, 0, sizeof(struct perf_update_info));
	ret = cn_pmu_update_perf_data_async(mset, &update_info);
	if (ret) {
		return ret;
	}

	memset(&monitor_head, 0, sizeof(struct monitor_data_head));

	for (type = TYPE_IPU_PERF; type < TYPE_MAX; type++) {
		ret = cn_monitor_read_data_type(mset, arg, type, &monitor_head);
		if (ret) {
			break;
		}
	}

	if (copy_to_user(arg,
				(void *)&monitor_head,
				sizeof(struct monitor_data_head))) {
		cn_dev_err("copy_to_user monitor head failed");
		ret = -EFAULT;
	}
	return ret;
}

int cn_monitor_update_perf_data_async(void *mset, unsigned long arg)
{
	int ret = -EFAULT;
	int data_size = sizeof(struct perf_update_info);
	struct perf_update_info_v1 update_info;
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(mset))
		return -EINVAL;

	memset(&update_info, 0, sizeof(struct perf_update_info_v1));

	ret = cn_pmu_update_perf_data_async(mset, &update_info);
	if (!ret) {
		if (!monitor_set->support_l1c) {
			data_size = sizeof(struct perf_update_info);
		} else {
			data_size = sizeof(struct perf_update_info_v1);
		}
		ret = cndev_cp_to_usr(arg, &update_info, data_size);
	}

	return ret;
}

int cn_pmu_read_data(struct cn_monitor_set *mset, struct pmu_data_s *arg)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	switch (core->device_id) {
	case MLUID_PIGEON_EDGE:
	case MLUID_CE3226_EDGE: {
		ret = cn_pmu_fill_pmu_data_edge(monitor_set, arg);
	}
	break;
	case MLUID_590:
	case MLUID_370:
	case MLUID_580:
		ret = cn_pmu_fill_pmu_data(monitor_set, arg);
	break;
	default:
	break;
	}

	return ret;
}

int cn_monitor_read_raw_ring_buffer(struct cn_monitor_set *monitor_set,
	void *context,
	struct monitor_read_buffer *ring_info)
{
	int ret = 0;
	struct monitor_read_buffer *ring_buf = ring_info;
	struct highrate_thread_context *thread_context = context;
	u32 block_size = 0;
	u32 block_len = 0;
	u64 pfmu_raw_data_count_per_zone = 0;

	if (IS_ERR_OR_NULL(monitor_set->zone_info)) {
		cn_dev_monitor_err(monitor_set, "Invalid zone info");
		return -EINVAL;
	}

	pfmu_raw_data_count_per_zone = monitor_set->zone_info->pfmu_raw_data_count_per_zone;
	block_len = mfifo_block_len(thread_context->axi_pfifo) * pfmu_raw_data_count_per_zone;
	if (ring_buf->start >= block_len) {
		cn_dev_monitor_err(monitor_set, "Invalid raw pfifo start");
		return -EINVAL;
	}
	if (ring_buf->start + ring_buf->count > block_len) {
		ring_buf->count = block_len - ring_buf->start;
	}

	block_size = ring_buf->count * PFMU_RAW_DATA_SIZE;

	ret = mfifo_copy_to_usr_unit(thread_context->axi_pfifo, ring_buf->start,
		ring_buf->buffer, block_size, PFMU_RAW_DATA_SIZE);

	return ret;
}

int cn_monitor_read_ring_buffer(void *mset, struct monitor_read_buffer *ring_info)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct monitor_read_buffer *ring_buf = ring_info;
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct highrate_thread_context *thread_context = NULL;
	u16 axi_hub_id = 0;

	if (IS_ERR_OR_NULL(monitor_set->monitor_highrate_set)) {
		return -EINVAL;
	}

	axi_hub_id = ring_buf->hub_id;
	if (monitor_set->hub_num <= axi_hub_id) {
		cn_dev_monitor_err(monitor_set, "Invalid hub id %u", axi_hub_id);
		return -EINVAL;
	}

	monitor_highrate_set = monitor_set->monitor_highrate_set;
	thread_context = &monitor_highrate_set->thread_context[axi_hub_id];
	if (IS_ERR_OR_NULL(thread_context->axi_pfifo)) {
		cn_dev_monitor_err(monitor_set, "Invalid axi_pfifo");
		return -EINVAL;
	}
	ret = cn_monitor_read_raw_ring_buffer(monitor_set, thread_context, ring_buf);
	/* fifo is empty */
	if (ret == -ENOSPC) {
		ring_buf->count = 0;
		ret = 0;
	}
	return ret;
}

/**
* @brief set ipu profiling mode
* @param mset monitor struct
* @param prof ipu profiling set struct
* @return 0 - success
*/
int cn_monitor_set_ipu_profiling(void *mset, void *prof)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_ipu_prof);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_SET_IPU_PROF,
				prof, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "set ipu prof ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor set ipu rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

/**
* @brief set ipu profiling mode
* @param mset monitor struct
* @param prof ipu profiling set struct
* @return 0 - success
*/
int cn_monitor_set_ipu_perf(void *mset, void *perf)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_ipu_perf);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_SET_IPU_PERF,
				perf, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "set ipu perf ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor set ipu rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

/**
* @brief set smmu performance mode
* @param mset monitor struct
* @param perf smmu performance set struct
* @return 0 - success
*/
int cn_monitor_set_smmu_perf(void *mset, void *perf)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_smmu_perf);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_SET_SMMU_PERF,
				perf, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "set smmu perf ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor set smmu rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

/**
* @brief set llc performance mode
* @param mset monitor struct
* @param perf llc performance set struct
* @return 0 - success
*/
int cn_monitor_set_llc_perf(void *mset, void *perf)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_llc_perf);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_SET_LLC_PERF,
				perf, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "set llc perf ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor set llc rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_ctrl_l1c_perf(void *mset, void *perf)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_l1c_perf_ctrl);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_CTRL_l1C_PERF,
				perf, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "CTRL l1c perf ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor CTRL l1c rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_set_l1c_perf(void *mset, void *perf)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_l1c_perf_cfg);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_SET_l1C_PERF,
				perf, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "set l1c perf ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor set l1c rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_set_highratemode(void *mset, int state)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(int);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_SET_PMU_HIGHRATE_MODE,
				&state, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "set mode ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor highrate mode rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_clr_pmu_data(void *mset, void *data)
{
	int ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;
	int result = 0;

	if (!monitor_set->endpoint)
		return -EINVAL;

	if (!core->exclusive_mode)
		cn_dev_monitor_warn(monitor_set,
				"CLEAR PMU Data without Exclusive Mode! %X",
				core->exclusive_mode);

	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_CLEAR_PMU_DATA,
				NULL, 0,
				&result, &in_len, sizeof(int));

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_get_counter_num(void *mset, void *cnt_num)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct pfmu_counter_number *cnt_info = (struct pfmu_counter_number *)cnt_num;
	struct counter_num_s num = {0};
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	u32 type = cnt_info->cnt_type;

	out_len = sizeof(cnt_info->cnt_num);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_GET_PFMU_CNTR_NUM,
				&type, out_len,
				&num, &in_len, sizeof(struct counter_num_s));
	cn_dev_monitor_debug(monitor_set, "get counter num ret:%d  result:%u  in_len:%d",
			ret, num.cnt_num, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor pfmu get counter rpc call failed, ret = %d", ret);
		return ret;
	}

	cnt_info->cnt_num = num.cnt_num;
	return num.ret;
}

int cn_monitor_get_counter_type(void *mset, void *cnt_type)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct pfmu_counter_type *cnt_info = (struct pfmu_counter_type *)cnt_type;
	struct counter_info_s *cnt = NULL;
	struct pfmu_id_info_s ipu_id_info;
	u32 *cnt_type_data = NULL;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	out_len = sizeof(struct counter_info_s);

	cnt = cn_kzalloc(out_len, GFP_KERNEL);
	if (!cnt) {
		cn_dev_monitor_err(monitor_set, "alloc cnt info fail");
		return -ENOMEM;
	}
	cnt_type_data = cnt->cnt_type;

	ipu_id_info.cluster_id = cnt_info->cluster_id;
	ipu_id_info.core_id = cnt_info->core_id;
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_GET_PFMU_CNTR,
				&ipu_id_info, sizeof(struct pfmu_id_info_s),
				cnt, &in_len, sizeof(struct counter_info_s));

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "call commu failed");
		cn_kfree(cnt);
		return ret;
	}

	if (cnt->ret) {
		cn_dev_monitor_err(monitor_set, "get pfmu counter type err");
		ret = cnt->ret;
		goto out;
	}

	ret = monitor_cp_less_val(
			&cnt_info->cnt_num, cnt->cnt_num,
			cnt_info->cnt_type, cnt_type_data, sizeof(u32));

	cnt_info->cnt_num = cnt->cnt_num;

out:
	cn_kfree(cnt);
	return ret;
}

int cn_monitor_set_counter_type(void *mset, struct pfmu_counter_type *cnt_type)
{
	int out_len, ret;
	int in_len = 0, result = -EINVAL;
	struct cn_monitor_set *monitor_set = mset;
	struct pfmu_counter_type *cnt_info = (struct pfmu_counter_type *)cnt_type;
	struct counter_info_s *cnt = NULL;
	u32 *cnt_type_data = NULL;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	out_len = sizeof(struct counter_info_s);

	cnt = cn_kzalloc(out_len, GFP_KERNEL);
	if (!cnt) {
		cn_dev_monitor_err(monitor_set, "alloc cnt info fail");
		return -ENOMEM;
	}
	cnt_type_data = cnt->cnt_type;
	cnt->cluster_id = cnt_info->cluster_id;
	cnt->core_id = cnt_info->core_id;
	cnt->cnt_num = 16;

	ret = monitor_cp_from_usr(
			&cnt_info->cnt_num, cnt->cnt_num,
			cnt_info->cnt_type, cnt->cnt_type, sizeof(u32));
	if (ret) {
		goto out;
	}

	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_SET_PFMU_CNTRS,
				cnt, out_len,
				&result, &in_len, sizeof(int));

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "call set counter commu failed");
		goto out;
	}

	ret = 0;

out:
	cn_kfree(cnt);
	return result;
}

int cn_monitor_set_snapshot_pc(void *mset, struct pfmu_snapshot_pc *snapshot)
{
	int out_len, ret;
	int in_len = 0, result = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	out_len = sizeof(struct pfmu_snapshot_pc);

	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_CONFIG_PFMU_SNAPHOST_PC,
				snapshot, out_len,
				&result, &in_len, sizeof(int));

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_pfmu_start(void *mset, void *perf)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_ipu_perf);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_CTRL_PFMU_PERF,
				perf, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "pfmu start ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor pfmu start rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_pfmu_set_event(void *mset, void *event)
{
	int out_len, ret;
	int in_len;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct pfmu_event_type);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_SET_PFMU_CNTR,
				event, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "pfmu set counter alone ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_pfmu_get_event(void *mset, void *cnt_type)
{
	int out_len, ret;
	int in_len;
	struct cn_monitor_set *monitor_set = mset;
	struct pfmu_event_info *cnt_info = (struct pfmu_event_info *)cnt_type;
	struct pfmu_event_info_s *event_info = NULL;
	struct pfmu_id_info_s ipu_id_info;
	u32 *cnt_type_data = NULL;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	out_len = sizeof(struct counter_info_s);

	event_info = cn_kzalloc(out_len, GFP_KERNEL);
	if (!event_info) {
		cn_dev_monitor_err(monitor_set, "alloc cnt info fail");
		return -ENOMEM;
	}
	cnt_type_data = event_info->event_type;

	ipu_id_info.cluster_id = cnt_info->cluster_id;
	ipu_id_info.core_id = cnt_info->core_id;
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_GET_PFMU_CONFIG,
				&ipu_id_info, sizeof(struct pfmu_id_info_s),
				event_info, &in_len, sizeof(struct pfmu_event_info_s));

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "call get counter commu failed");
		cn_kfree(event_info);
		return ret;
	}

	if (event_info->ret) {
		cn_dev_monitor_err(monitor_set, "get pfmu counter type err");
		ret = event_info->ret;
		goto out;
	}

	ret = monitor_cp_less_val(
			&cnt_info->cnt_num, event_info->cnt_num,
			cnt_info->event_type, cnt_type_data, sizeof(u32));

	cnt_info->cnt_num = event_info->cnt_num;
	cnt_info->event_mask = event_info->event_mask;

out:
	cn_kfree(event_info);
	return ret;
}

int cn_monitor_pfmu_ctrl(void *mset, void *ctrl)
{
	int out_len, ret;
	int in_len;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct pfmu_cnt_ctrl);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_CTRL_PFMU,
				ctrl, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "ipu pfmu ctrl ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_request_hub_trace(void *mset, void *hub_trace)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_pfmu_config_hub_trace);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_START_HUB_TRACE,
				hub_trace, out_len,
				&result, &in_len,  sizeof(int));
	cn_dev_monitor_debug(monitor_set, "set and start hub trace ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor set and start hub trace rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_set_hub_trace(void *mset, void *hub_trace)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_pfmu_config_hub_trace);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_CONFIG_HUB_TRACE,
				hub_trace, out_len,
				&result, &in_len,  sizeof(int));
	cn_dev_monitor_debug(monitor_set, "monitor set hub trace ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor set hub trace rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_stop_hub_trace(void *mset, void *data)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;
	out_len = sizeof(struct monitor_pfmu_stop_hub_trace);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_STOP_HUB_TRACE,
				data, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "stop hub trace ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor stop hub trace rpc call failed, ret = %d", ret);
		return ret;
	}

	return result;
}

int cn_monitor_pfmu_get_hubtrace_l2p(void *mset, void *map_info)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct monitor_pfmu_hubtrace_table *hubtrace_map = map_info;
	struct monitor_pfmu_hubtrace_table hubtrace = {};
	int len = 0;
	int buffer_size = 0;

	memset(&hubtrace, 0, sizeof(struct monitor_pfmu_hubtrace_table));

	if (IS_ERR_OR_NULL(map_info)) {
		ret = -EINVAL;
		cn_dev_monitor_err(monitor_set, "map_info is null");
		goto out;
	}

	len = cn_monitor_pfmu_hubtrace_tab_len(monitor_set);
	if (len < 0) {
		ret = -EINVAL;
		goto out;
	}
	if (hubtrace_map->total_item < len) {
		hubtrace_map->total_item = len + 1;
		ret = -EINVAL;
		goto out;
	} else {
		hubtrace_map->total_item = len;
	}

	buffer_size = hubtrace_map->total_item * sizeof(struct pfmu_ipu_l2p_table);

	hubtrace.total_item = 0;
	hubtrace.l2p = cn_kzalloc(buffer_size, GFP_KERNEL);
	if (!hubtrace.l2p) {
		ret = -EINVAL;
		cn_dev_monitor_err(monitor_set, "pfmu_hubtrace_tab_len is null");
		goto out;
	}
	ret = cn_monitor_pfmu_hubtrace_map_info(mset, &hubtrace);
	if (!ret) {
		hubtrace_map->total_item = hubtrace.total_item;
		if (copy_to_user((void *)(hubtrace_map->l2p),
				hubtrace.l2p,
				buffer_size)) {
			ret = -EFAULT;
		}
	}

	if (hubtrace.l2p) {
		cn_kfree(hubtrace.l2p);
	}

out:
	return ret;
}

int cn_monitor_host_start(void *mset)
{
	int ret;
	int in_len = 0;
	int result = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	u8 hub_id = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint)
		return -EINVAL;

	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_START_HOST,
				NULL, 0,
				(void *)&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "monitor start ret:%d result:%d in_len:%d"
			, ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	for (hub_id = 0; hub_id < monitor_set->hub_num; hub_id++) {
		axi_set[hub_id].opened_count = 0;
		memset(axi_set[hub_id].monitors, 0, axi_set[hub_id].config->monitor_num);
		axi_set[hub_id].entry = 0;
	}
	cn_monitor_init_drv_ver(mset);
	return result;
}

int cn_monitor_host_exit(void *mset)
{
	int ret = 0;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	int result = 0;
	struct cn_core_set *core = NULL;

	if (!monitor_set)
		return -EINVAL;

	core = (struct cn_core_set *)monitor_set->core;

	if (monitor_set->support_monitor == CN_MONITOR_NOT_SUPPORT)
		return -EINVAL;
	if (!monitor_set->endpoint)
		return -EINVAL;

	ret = __pmu_call_rpc(core, monitor_set->endpoint,
		MON_EXIT_HOST,
		NULL, 0,
		&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "do exit ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor do exit rpc call failed, ret = %d", ret);
	}

	if (monitor_set->highrate_mode) {
		cn_monitor_exit_monitor_highrate_env(monitor_set);
	}
	cndrv_axi_monitor_host_exit(monitor_set);

	return ret;
}

int cn_monitor_axi_highrate_open(void *mset, void *mon_conf)
{
	int out_len, ret;
	int in_len = 0;
	u8 hub_id = 0;
	u8 mon_id = 0;
	struct pmu_monitor_config *conf = (struct pmu_monitor_config *)mon_conf;
	struct cn_monitor_set *monitor_set = mset;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	hub_id = (u8)(conf->monitor_id >> 8);
	mon_id = (u8)(conf->monitor_id & 0xff);

	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	if (monitor_set->hub_num <= hub_id) {
		cn_dev_monitor_err(monitor_set, "Invalid hub id");
		return -EINVAL;
	}

	if (axi_set[hub_id].monitor_num <= mon_id) {
		cn_dev_monitor_err(monitor_set, "Invalid monitor id");
		return -EINVAL;
	}

	out_len = sizeof(struct pmu_monitor_config);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_OPEN_AXIM,
				mon_conf, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi open ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	if (result) {
		if (!axi_set[hub_id].opened_count) {
		}
	} else {
		if (!axi_set[hub_id].monitors[mon_id]) {
			axi_set[hub_id].monitors[mon_id] = 1;
			axi_set[hub_id].opened_count++;
		}
		axi_set[hub_id].monitors_mode[mon_id] = conf->data_mode;
	}

	return result;
}

int cn_monitor_axi_highrate_close(void *mset, u16 monitor_id)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	int result = 0;
	u8 hub_id = 0;
	u8 mon_id = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	hub_id = (u8)(monitor_id>>8);
	mon_id = (u8)(monitor_id & 0xff);

	if (monitor_set->hub_num <= hub_id) {
		cn_dev_monitor_err(monitor_set, "Invalid hub id");
		return -EINVAL;
	}

	if (axi_set[hub_id].monitor_num <= mon_id) {
		cn_dev_monitor_err(monitor_set, "Invalid monitor id");
		return -EINVAL;
	}

	if ((axi_set[hub_id].opened_count - 1) == 0) {
		//return -EPERM;
	}

	out_len = sizeof(u16);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_CLOSE_AXIM,
				(void *)&monitor_id, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi close ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	if (!result && axi_set[hub_id].monitors[mon_id]) {
		axi_set[hub_id].monitors[mon_id] = 0;
		axi_set[hub_id].opened_count--;
		axi_set[hub_id].monitors_mode[mon_id] = 0;
	}

	return result;
}

int cn_monitor_axi_highrate_openall(void *mset, u8 hub_id)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	if (monitor_set->hub_num <= hub_id) {
		cn_dev_monitor_err(monitor_set, "Invalid hub id");
		return -EINVAL;
	}

	out_len = 1;
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_OPEN_AXIM,
				&hub_id, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi open ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	if (!result) {
		axi_set[hub_id].opened_count = axi_set[hub_id].config->monitor_num;
		memset(axi_set[hub_id].monitors, 0x01, axi_set[hub_id].config->monitor_num);
		memset(axi_set[hub_id].monitors_mode, 0x00, axi_set[hub_id].config->monitor_num);
	}
	return result;
}

int cn_monitor_axi_highrate_closeall(void *mset, u8 hub_id)
{
	int out_len, ret;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	int result = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->endpoint) {
		cn_dev_monitor_err(monitor_set, "Invalid endpoint");
		return -EINVAL;
	}

	if (monitor_set->hub_num <= hub_id) {
		cn_dev_monitor_err(monitor_set, "Invalid hub id");
		return -EINVAL;
	}

	out_len = sizeof(u8);
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_CLOSE_AXIM,
				(void *)&hub_id, out_len,
				&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "axi close ret:%d  result:%d  in_len:%d",
			ret, result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	if (!result) {
		axi_set[hub_id].opened_count = 0;
		memset(axi_set[hub_id].monitors, 0, axi_set[hub_id].config->monitor_num);
		memset(axi_set[hub_id].monitors_mode, 0x00, axi_set[hub_id].config->monitor_num);
	}

	return result;
}

/**
* @brief register rpc client or commu channel
* @return 0 - success
*/
int cn_monitor_rpc_register(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_monitor_set *monitor_set =
		(struct cn_monitor_set *)core->monitor_set;

	monitor_set->endpoint = __pmu_open_channel("monitor-krpc", core);
	if (IS_ERR_OR_NULL(monitor_set->endpoint)) {
		cn_dev_monitor_err(monitor_set, "open rpc channel failed");
		return -EFAULT;
	}

	return 0;
}

static int common_monitor_lateinit(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_monitor_set *monitor_set = core->monitor_set;
	struct cn_monitor_lateset lateinit_param;
	int ret = 0;
	int in_len = 0;
	int result = 0;

	cn_dev_debug("Monitor late init.");

	cndrv_cndev_lateinit(core);

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor set NULL!");
		return -ENOMEM;
	}
	if (monitor_set->support_monitor == CN_MONITOR_NOT_SUPPORT) {
		return 0;
	}
	/*register rpc client*/
	ret = cn_monitor_rpc_register(core);
	if (ret) {
		return ret;
	}

	if (monitor_set->sharememory_host_va[PMU_INFO]) {
		cn_dev_monitor_info(monitor_set, "sharememory already alloced");
		cn_device_share_mem_free(0, monitor_set->sharememory_host_va[PMU_INFO],
					monitor_set->sharememory_device_va[PMU_INFO],
					core);
	}

	ret = cn_device_share_mem_alloc(0, &monitor_set->sharememory_host_va[PMU_INFO],
				&monitor_set->sharememory_device_va[PMU_INFO],
				monitor_set->sharememory_size[PMU_INFO], core);
	if (ret) {
		cn_dev_monitor_debug(monitor_set, "share memory buffer alloc fail!");
		return ret;
	}

	cn_dev_monitor_debug(monitor_set, "sharememory host_va: %#lX device_va: %#llX",
					monitor_set->sharememory_host_va[PMU_INFO],
					monitor_set->sharememory_device_va[PMU_INFO]);

	lateinit_param.sm_info[0].sharememory_va = monitor_set->sharememory_device_va[PMU_INFO];
	lateinit_param.sm_info[0].sharememory_size = monitor_set->sharememory_size[PMU_INFO];
	lateinit_param.sm_info_cnt = 1;
	lateinit_param.sm_info_mask = 0x1;
	lateinit_param.board_type = monitor_set->board_type;

	in_len = 0;
	/*rpc to send param to arm and trigger late init*/
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_GET_PMU_LATEINIT,
				(void *)&lateinit_param,
				sizeof(struct cn_monitor_lateset),
				(void *)&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "ARM lateinit result: %d %d", result, in_len);
	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return ret;
	}

	if (result) {
		cn_dev_monitor_err(monitor_set, "Monitor lateinit error on eevice");
		return result;
	}

	return 0;
}

static void common_monitor_earlyexit(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_monitor_set *monitor_set = core->monitor_set;
	int i = 0;

	for (i = 0; i < TOTAL_PMU_SM_INFO; i++) {
		if (monitor_set->sharememory_host_va[i]) {
			cn_device_share_mem_free(0, monitor_set->sharememory_host_va[i],
				monitor_set->sharememory_device_va[i],
				core);
			monitor_set->sharememory_host_va[i] = 0;
		}
	}
}

static int mlu300_monitor_lateinit(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_monitor_set *monitor_set = core->monitor_set;
	struct cn_monitor_lateset lateinit_param;
	int ret = 0;
	int in_len = 0;
	int i = 0;
	int result = 0;

	cn_dev_debug("Monitor late init.");

	cndrv_cndev_lateinit(core);

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("monitor set NULL!");
		return -ENOMEM;
	}
	if (monitor_set->support_monitor == CN_MONITOR_NOT_SUPPORT) {
		return 0;
	}
	/*register rpc client*/
	ret = cn_monitor_rpc_register(core);
	if (ret) {
		return ret;
	}

	for (i = 0; i < TOTAL_PMU_SM_INFO; i++)	{
		if (monitor_set->sharememory_host_va[i]) {
			cn_dev_monitor_info(monitor_set, "sharememory(%d) already alloced", i);
			cn_device_share_mem_free(0, monitor_set->sharememory_host_va[i],
				monitor_set->sharememory_device_va[i],
				core);
		}
		if (monitor_set->sharememory_size[i]) {

			ret = cn_device_share_mem_alloc(0, &monitor_set->sharememory_host_va[i],
						&monitor_set->sharememory_device_va[i],
						monitor_set->sharememory_size[i], core);
			if (ret) {
				cn_dev_monitor_err(monitor_set, "share memory buffer alloc fail!");
				goto err_1;
			}

		}

		cn_dev_monitor_debug(monitor_set, "sharememory host_va: %#lX device_va: %#llX",
						monitor_set->sharememory_host_va[i],
						monitor_set->sharememory_device_va[i]);

		lateinit_param.sm_info[i].sharememory_va = monitor_set->sharememory_device_va[i];
		lateinit_param.sm_info[i].sharememory_size = monitor_set->sharememory_size[i];
	}

	lateinit_param.sm_info_cnt = 2;
	lateinit_param.sm_info_mask = 0x3;
	lateinit_param.board_type = monitor_set->board_type;

	in_len = 0;
	/*rpc to send param to arm and trigger late init*/
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_GET_PMU_LATEINIT,
				(void *)&lateinit_param,
				sizeof(struct cn_monitor_lateset),
				(void *)&result, &in_len, sizeof(int));
	cn_dev_monitor_debug(monitor_set, "ARM lateinit result: %d %d", result, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor lateinit rpc call failed, ret = %d", ret);
		return ret;
	}

	if (result) {
		cn_dev_monitor_err(monitor_set, "Monitor LateInit error on ARM");
		return result;
	}

	return 0;

err_1:
	for (i = 0; i < TOTAL_PMU_SM_INFO; i++) {
		if (monitor_set->sharememory_host_va[i]) {
			cn_device_share_mem_free(0, monitor_set->sharememory_host_va[i],
				monitor_set->sharememory_device_va[i],
				core);
			monitor_set->sharememory_host_va[i] = 0;
		}
	}

	return ret;
}

int cndrv_monitor_lpm_get(void *user, struct cn_core_set *core)
{
	struct file *fp = (struct file *)user;
	struct fp_priv_data *priv_data = (struct fp_priv_data *)fp->private_data;
	struct cn_monitor_priv_data *monitor_priv = (struct cn_monitor_priv_data *)
		priv_data->monitor_priv_data;

	atomic64_inc(&monitor_priv->monitor_lpm_count);

	/*
	 * this ioctl need exit lowpower when lpm is task mode which do not exit lowpower when open device.
	 * and here may be called sevral times, but only put once when device close,
	 * so cn_lpm_put_all_module_cnt will be called when close and cnt is monitor_priv->monitor_lpm_count.
	 */
	if (cn_lpm_get_all_module(core)) {
		cn_dev_core_err(core, "monitor get lpm failed!");
		atomic64_dec(&monitor_priv->monitor_lpm_count);
		return -EINVAL;
	}
	return 0;
}

void cndrv_monitor_lpm_put(void *user, struct cn_core_set *core)
{
	struct file *fp = (struct file *)user;
	struct fp_priv_data *priv_data = (struct fp_priv_data *)fp->private_data;
	struct cn_monitor_priv_data *monitor_priv = (struct cn_monitor_priv_data *)
		priv_data->monitor_priv_data;

	/* put when dev close */
	cn_lpm_put_cnt_all_module(core, atomic64_read(&monitor_priv->monitor_lpm_count));
}

void cn_monitor_do_exit(u64 fp, void *pcore)
{
	int ret;
	int in_len = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_monitor_set *monitor_set = core->monitor_set;
	int result = 0;

	if (!monitor_set)
		return;

	core = (struct cn_core_set *)monitor_set->core;

	cn_pmu_reinit_version(monitor_set);
	cn_monitor_perf_tgid_exit(fp, monitor_set);
	cndrv_monitor_lpm_put((void *)fp, core);

	if (monitor_set->support_monitor == CN_MONITOR_NOT_SUPPORT)
		return;

	if (!monitor_set->endpoint)
		return;

	if (fp == monitor_set->lock_fp) {
		ret = __pmu_call_rpc(core, monitor_set->endpoint,
					MON_EXIT_HOST,
					NULL, 0,
					&result, &in_len, sizeof(int));
		cn_dev_monitor_debug(monitor_set, "do exit ret:%d  result:%d  in_len:%d",
				ret, result, in_len);

		if (ret < 0) {
			cn_dev_monitor_err(monitor_set, "monitor do exit rpc call failed, ret = %d", ret);
		}

		monitor_set->lock_fp = 0;

		if (monitor_set->highrate_mode) {
			cn_monitor_exit_monitor_highrate_env(monitor_set);
		}
		cndrv_axi_monitor_host_exit(monitor_set);
	}
}

int cn_monitor_private_data_init(struct fp_priv_data *priv_data)
{
	struct cn_core_set *core = priv_data->core;
	struct cn_monitor_priv_data *monitor_priv = NULL;

	monitor_priv = cn_kzalloc(sizeof(struct cn_monitor_priv_data), GFP_KERNEL);
	if (!monitor_priv) {
		cn_dev_core_err(core, "malloc cn_monitor_private_data_init failed!");
		return -ENOMEM;
	}

	atomic64_set(&monitor_priv->monitor_lpm_count, 0);

	priv_data->monitor_priv_data = monitor_priv;
	return 0;
}

void cn_monitor_private_data_exit(struct fp_priv_data *priv_data)
{
	struct cn_monitor_priv_data *monitor_priv = (struct cn_monitor_priv_data *)
		priv_data->monitor_priv_data;

	if (!monitor_priv) {
		return;
	}

	cn_kfree(monitor_priv);
}

#ifdef CONFIG_CNDRV_MNT
#define PMU_REPORT_BUFFER_SIZE 4096
int cn_pmu_debug(void *data, unsigned long action, void *fp)
{
	struct cn_core_set *core = (struct cn_core_set *)data;
	int ret = 0;
	struct cndev_ecc_info einfo;
	struct cn_cndev_set *cndev_set = NULL;
	char *dump_buf = NULL;
	int size = 0;
	loff_t pos = 0;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("core set NULL!");
		return -EINVAL;
	}

	cndev_set = (struct cn_cndev_set *)core->cndev_set;
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set NULL!");
		return -EINVAL;
	}

	dump_buf = cn_kzalloc(PMU_REPORT_BUFFER_SIZE, GFP_KERNEL);
	if (!dump_buf) {
		cn_dev_err("alloc dump buff fail");
		return -ENOMEM;
	}
	memset(&einfo, 0, sizeof(struct cndev_ecc_info));
	memset(dump_buf, 0, PMU_REPORT_BUFFER_SIZE);
	ret = cndev_card_ecc_info(cndev_set, &einfo);
	if (!ret) {
		size += sprintf(dump_buf,
			"One Bit Err        : %llu\n"
			"One Bit Err        : %llu\n"
			"Mul Bits Err       : %llu\n"
			"Mul Mul Bits Err   : %llu\n"
			"Addr Forbidden Err : %llu\n",
			 einfo.single_biterr,
			 einfo.single_multierr,
			 einfo.multi_biterr,
			 einfo.multi_multierr,
			 einfo.addr_forbidden_err);

		cn_fs_write(fp, dump_buf, size, &pos);
	}

	cn_kfree(dump_buf);
	return 0;
}

typedef	int (*report_fn_t)(void *data,
			unsigned long action, void *fp);
extern struct cn_report_block *cn_register_report(struct cn_core_set *core, char *name,
						int prio, report_fn_t fn, void *data);
extern int cn_unregister_report(struct cn_core_set *core, struct cn_report_block *nb);
#endif

struct cn_monitor_ops mlu200_monitor_ops = {
	.pmu_monitor_lateinit = common_monitor_lateinit,
	.pmu_monitor_earlyexit = common_monitor_earlyexit,
};

struct cn_monitor_ops mlu370_monitor_ops = {
	.pmu_monitor_lateinit = mlu300_monitor_lateinit,
	.pmu_monitor_earlyexit = common_monitor_earlyexit,
};

struct cn_monitor_ops ce3226_monitor_ops = {
	.pmu_monitor_lateinit = mlu300_monitor_lateinit,
	.pmu_monitor_earlyexit = common_monitor_earlyexit,
};

struct cn_monitor_ops mlu590_monitor_ops = {
	.pmu_monitor_lateinit = mlu300_monitor_lateinit,
	.pmu_monitor_earlyexit = common_monitor_earlyexit,
};

struct cn_monitor_ops pigeon_monitor_ops = {
	.pmu_monitor_lateinit = mlu300_monitor_lateinit,
	.pmu_monitor_earlyexit = common_monitor_earlyexit,
};

int cn_monitor_late_init(struct cn_core_set *pcore)
{
	struct cn_monitor_set *monitor_set = pcore->monitor_set;

	if (IS_ERR_OR_NULL(monitor_set->mon_ops)) {
		return -EACCES;
	}

	if (IS_ERR_OR_NULL(monitor_set->mon_ops->pmu_monitor_lateinit)) {
		return -EACCES;
	}

	return monitor_set->mon_ops->pmu_monitor_lateinit((void *)pcore);
}

void cn_monitor_late_exit(struct cn_core_set *pcore)
{
	struct cn_monitor_set *monitor_set = pcore->monitor_set;
	struct cn_cndev_set *cndev_set = pcore->cndev_set;

	if (monitor_set->endpoint) {
		__pmu_disconnect(monitor_set->endpoint, (void *)pcore);
		monitor_set->endpoint = NULL;
	}

	if (cndev_set->endpoint) {
		__pmu_disconnect(cndev_set->endpoint, pcore);
		cndev_set->endpoint = NULL;
	}
}

void cn_monitor_earlyexit(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_monitor_set *monitor_set = core->monitor_set;

	if (IS_ERR_OR_NULL(monitor_set->mon_ops)) {
		return;
	}

	if (IS_ERR_OR_NULL(monitor_set->mon_ops->pmu_monitor_earlyexit)) {
		return;
	}

	return monitor_set->mon_ops->pmu_monitor_earlyexit(pcore);
}

void cn_monitor_config_set(struct cn_core_set *core)
{
	struct cn_monitor_set *monitor_set = core->monitor_set;

	monitor_set->support_monitor = CN_MONITOR_SUPPORT;

	if (cn_is_mim_en(core)) {
		monitor_set->support_monitor = CN_MONITOR_NOT_SUPPORT;
	}

	switch (core->device_id) {
	case MLUID_220:
	case MLUID_220_EDGE:
		monitor_set->board_type = BOARD_MLU220;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU270;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = 0;
		monitor_set->amh_type_perf = 0;
		monitor_set->amh_type_time = 7;
		monitor_set->mon_ops = &mlu200_monitor_ops;
		monitor_set->shmem_layout = NULL;
		break;
	case MLUID_290V1:
		monitor_set->mon_ops = &mlu200_monitor_ops;
		monitor_set->board_type = BOARD_MLU290_VF;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU290;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = 0;
		monitor_set->amh_type_perf = 0;
		monitor_set->amh_type_time = 7;
		monitor_set->shmem_layout = NULL;
		monitor_set->support_monitor = CN_MONITOR_NOT_SUPPORT;
		break;
	case MLUID_290:
		monitor_set->board_type = BOARD_MLU290;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU290;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = 0;
		monitor_set->amh_type_perf = 0;
		monitor_set->amh_type_time = 7;
		monitor_set->mon_ops = &mlu200_monitor_ops;
		monitor_set->shmem_layout = NULL;
		break;
	case MLUID_270V:
	case MLUID_270V1:
		monitor_set->mon_ops = &mlu200_monitor_ops;
		monitor_set->board_type = BOARD_MLU270_VF;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU270;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = 0;
		monitor_set->amh_type_perf = 0;
		monitor_set->amh_type_time = 7;
		monitor_set->shmem_layout = NULL;
		monitor_set->support_monitor = CN_MONITOR_NOT_SUPPORT;
		break;
	case MLUID_270:
		monitor_set->board_type = BOARD_MLU270;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU270;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = 0;
		monitor_set->amh_type_perf = 0;
		monitor_set->amh_type_time = 7;
		monitor_set->mon_ops = &mlu200_monitor_ops;
		monitor_set->shmem_layout = NULL;
		break;
	case MLUID_370V:
		monitor_set->mon_ops = &mlu370_monitor_ops;
		monitor_set->board_type = BOARD_MLU370_VF;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU370;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = PROF_SHARE_MEM_SIZE_MLU370;
		monitor_set->amh_type_perf = 1;
		monitor_set->amh_type_time = 7;
		monitor_set->shmem_layout = (struct pmu_data_layout *)&mlu370_share_mem_layout;
		monitor_set->shmem_layout[PMU_PERF_INFO].host_va = 0;
		monitor_set->shmem_layout[PMU_PERF_INFO].buffer_size = SHARE_MEM_SIZE_MLU370;
		monitor_set->support_monitor = CN_MONITOR_SUPPORT;
		break;
	case MLUID_370_DEV:
		monitor_set->mon_ops = &mlu370_monitor_ops;
		monitor_set->board_type = BOARD_UNKNOWN;
		monitor_set->support_monitor = CN_MONITOR_NOT_SUPPORT;
		break;
	case MLUID_370:
		monitor_set->board_type = BOARD_MLU370;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU370;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = PROF_SHARE_MEM_SIZE_MLU370;
		monitor_set->amh_type_perf = 1;
		monitor_set->amh_type_time = 7;
		monitor_set->mon_ops = &mlu370_monitor_ops;
		monitor_set->shmem_layout = (struct pmu_data_layout *)&mlu370_share_mem_layout;
		monitor_set->shmem_layout[PMU_PERF_INFO].host_va = 0;
		monitor_set->shmem_layout[PMU_PERF_INFO].buffer_size = SHARE_MEM_SIZE_MLU370;
		break;
	case MLUID_CE3226_EDGE:
	case MLUID_CE3226:
		monitor_set->board_type = BOARD_CE3226;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_CE3226;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = PROF_SHARE_MEM_SIZE_CE3226;
		monitor_set->amh_type_perf = 1;
		monitor_set->amh_type_time = 7;
		monitor_set->mon_ops = &ce3226_monitor_ops;
		monitor_set->shmem_layout = (struct pmu_data_layout *)&ce3226_share_mem_layout;
		monitor_set->shmem_layout[PMU_PERF_INFO].host_va = 0;
		monitor_set->shmem_layout[PMU_PERF_INFO].buffer_size = PROF_SHARE_MEM_SIZE_CE3226;
		break;
	case MLUID_590V:
		monitor_set->mon_ops = &mlu590_monitor_ops;
		monitor_set->board_type = BOARD_MLU590_VF;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU590;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = 0;
		monitor_set->shmem_layout = (struct pmu_data_layout *)&mlu590_share_mem_layout;
		monitor_set->shmem_layout[PMU_PERF_INFO].host_va = 0;
		monitor_set->shmem_layout[PMU_PERF_INFO].buffer_size = SHARE_MEM_SIZE_MLU590;
		monitor_set->support_monitor = CN_MONITOR_NOT_SUPPORT;
		break;
	case MLUID_590_DEV:
		monitor_set->mon_ops = &mlu590_monitor_ops;
		monitor_set->board_type = BOARD_UNKNOWN;
		monitor_set->support_monitor = CN_MONITOR_NOT_SUPPORT;
		break;
	case MLUID_590:
		monitor_set->board_type = BOARD_MLU590;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU590;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = PROF_SHARE_MEM_SIZE_MLU590;
		monitor_set->amh_type_perf = 1;
		monitor_set->amh_type_time = 3;
		monitor_set->mon_ops = &mlu590_monitor_ops;
		monitor_set->shmem_layout = (struct pmu_data_layout *)&mlu590_share_mem_layout;
		monitor_set->shmem_layout[PMU_PERF_INFO].host_va = 0;
		monitor_set->shmem_layout[PMU_PERF_INFO].buffer_size = SHARE_MEM_SIZE_MLU590;
		break;
	case MLUID_PIGEON_EDGE:
	case MLUID_PIGEON:
		monitor_set->board_type = BOARD_LEOPARD;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_PIGEON;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = PROF_SHARE_MEM_SIZE_PIGEON;
		monitor_set->amh_type_perf = 1;
		monitor_set->amh_type_time = 3;
		monitor_set->mon_ops = &pigeon_monitor_ops;
		monitor_set->shmem_layout = (struct pmu_data_layout *)&pigeon_share_mem_layout;
		monitor_set->shmem_layout[PMU_PERF_INFO].host_va = 0;
		monitor_set->shmem_layout[PMU_PERF_INFO].buffer_size = PROF_SHARE_MEM_SIZE_PIGEON;
		break;
	case MLUID_580_DEV:
		monitor_set->mon_ops = &mlu590_monitor_ops;
		monitor_set->board_type = BOARD_UNKNOWN;
		monitor_set->support_monitor = CN_MONITOR_NOT_SUPPORT;
		break;
	case MLUID_580:
		monitor_set->board_type = BOARD_MLU580;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU590;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = PROF_SHARE_MEM_SIZE_MLU590;
		monitor_set->amh_type_perf = 1;
		monitor_set->amh_type_time = 3;
		monitor_set->mon_ops = &mlu590_monitor_ops;
		monitor_set->shmem_layout = (struct pmu_data_layout *)&mlu590_share_mem_layout;
		monitor_set->shmem_layout[PMU_PERF_INFO].host_va = 0;
		monitor_set->shmem_layout[PMU_PERF_INFO].buffer_size = SHARE_MEM_SIZE_MLU590;
		break;
	case MLUID_580V:
		monitor_set->mon_ops = &mlu590_monitor_ops;
		monitor_set->board_type = BOARD_MLU580_VF;
		monitor_set->sharememory_size[PMU_PERF_INFO] = SHARE_MEM_SIZE_MLU590;
		monitor_set->sharememory_size[PMU_AXIM_INFO] = 0;
		monitor_set->shmem_layout = (struct pmu_data_layout *)&mlu590_share_mem_layout;
		monitor_set->shmem_layout[PMU_PERF_INFO].host_va = 0;
		monitor_set->shmem_layout[PMU_PERF_INFO].buffer_size = SHARE_MEM_SIZE_MLU590;
		monitor_set->support_monitor = CN_MONITOR_NOT_SUPPORT;
		break;
	default:
		monitor_set->board_type = BOARD_UNKNOWN;
		monitor_set->support_monitor = CN_MONITOR_NOT_SUPPORT;
		break;
	}
}

int cn_monitor_restart(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_monitor_set *monitor_set = core->monitor_set;

	if (!monitor_set) {
		return 0;
	}

	monitor_set->bus_set = core->bus_set;
	cn_monitor_config_set(core);

	cndrv_axi_monitor_restart(monitor_set);

	cndrv_cndev_restart(pcore);

	monitor_perf_restart(monitor_set);

	return 0;
}

void cn_monitor_stop(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_monitor_set *monitor_set = core->monitor_set;
	int i = 0;

	if (!monitor_set)
		return;
	/*release share memory*/
	for (i = 0; i < TOTAL_PMU_SM_INFO; i++) {
		if (monitor_set->sharememory_host_va[i]) {
			cn_device_share_mem_free(0, monitor_set->sharememory_host_va[i],
				monitor_set->sharememory_device_va[i],
				core);
			monitor_set->sharememory_host_va[i] = 0;
		}
	}

	if (monitor_set->endpoint) {
		__pmu_disconnect(monitor_set->endpoint, pcore);
		monitor_set->endpoint = NULL;
	}

	cndrv_axi_monitor_stop(monitor_set);

	cndrv_cndev_stop(pcore);

	monitor_perf_stop(monitor_set);
}

int cn_monitor_init(struct cn_core_set *core)
{
	struct cn_monitor_set *monitor_set;
	int ret;

	cn_dev_debug("Monitor Init.");

	monitor_set = cn_kzalloc(sizeof(struct cn_monitor_set), GFP_KERNEL);
	if (!monitor_set) {
		cn_dev_err("alloc monitor set error.");
		return -ENOMEM;
	}
	core->monitor_set = monitor_set;
	monitor_set->core = (void *)core;
	monitor_set->bus_set = core->bus_set;

	mutex_init(&monitor_set->pmu_ver_mutex);

	cn_monitor_config_set(core);

	ret = cndrv_cndev_init((void *)core);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "cnmon server init fail.");
		goto err_cndev;
	}

	ret = cndrv_axi_monitor_init(monitor_set);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "Axi monitor init fail.");
		goto err_monitor;
	}

	ret = monitor_perf_init(monitor_set);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "perf init fail.");
		goto err_perf;
	}

#ifdef CONFIG_CNDRV_MNT
	monitor_set->pmu_report = cn_register_report(core, "pmu_info", 0, cn_pmu_debug, core);
	if (IS_ERR_OR_NULL(monitor_set->pmu_report)) {
		monitor_set->pmu_report = NULL;
	}
#endif

	cn_dev_monitor_debug(monitor_set, "Monitor Init Finish.");

	return 0;
err_perf:
	cn_kfree(monitor_set->axi_set);
	cn_kfree(monitor_set->monitor_highrate_set);
	cn_kfree(monitor_set->res_param);
err_monitor:
	cndrv_cndev_free((void *)core);
err_cndev:
	cn_kfree(monitor_set);
	core->monitor_set = NULL;
	return ret;
}

void cn_monitor_exit(struct cn_core_set *core)
{
	struct cn_monitor_set *monitor_set = core->monitor_set;
	int i = 0;

	if (monitor_set) {

#ifdef CONFIG_CNDRV_MNT
	if (monitor_set->pmu_report)
		cn_unregister_report(core, monitor_set->pmu_report);
#endif

		for (i = 0; i < TOTAL_PMU_SM_INFO; i++) {
			if (monitor_set->sharememory_host_va[i]) {
				cn_device_share_mem_free(0, monitor_set->sharememory_host_va[i],
					monitor_set->sharememory_device_va[i],
					core);
				monitor_set->sharememory_host_va[i] = 0;
			}
		}

		if (monitor_set->highrate_mode)
			cndrv_axi_monitor_unregister_irq(monitor_set);

		cndrv_cndev_free((void *)core);

		monitor_perf_free(monitor_set);

		//TODO: AXI_Monitor Exit
		cndrv_axi_monitor_exit(monitor_set);

		cn_kfree(monitor_set);
		core->monitor_set = NULL;
		monitor_set = NULL;
	}

	cn_dev_debug("Monitor Exit Finish.");
}

int cn_monitor_read_ringbuf(void *mset, void *arg)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct monitor_direct_ringbuf_pos *ringbuf_pos = arg;
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct highrate_thread_context *thread_context = NULL;
	u16 hub_id = 0;
	u64 pfmu_raw_data_count_per_zone = 0;

	if (IS_ERR_OR_NULL(monitor_set->zone_info)) {
		cn_dev_monitor_err(monitor_set, "Invalid zone info");
		return -EINVAL;
	}
	pfmu_raw_data_count_per_zone = monitor_set->zone_info->pfmu_raw_data_count_per_zone;

	if (IS_ERR_OR_NULL(monitor_set->monitor_highrate_set)) {
		return -EINVAL;
	}
	hub_id = ringbuf_pos->hub_id;
	if (monitor_set->hub_num <= hub_id) {
		cn_dev_monitor_err(monitor_set, "Invalid hub id %u", hub_id);
		return -EINVAL;
	}

	monitor_highrate_set = monitor_set->monitor_highrate_set;
	thread_context = &monitor_highrate_set->thread_context[hub_id];

	if (IS_ERR_OR_NULL(thread_context->axi_pfifo)) {
		cn_dev_monitor_err(monitor_set, "Invalid raw_pfifo");
		return -EINVAL;
	}
	ringbuf_pos->index = thread_context->axi_pfifo->entry * pfmu_raw_data_count_per_zone;

	ringbuf_pos->loss_times = thread_context->loss_times;
	ringbuf_pos->entry_count = atomic64_read(&thread_context->entry_count);
	ringbuf_pos->last_data_flag = thread_context->last_data_flag;
	return ret;
}

long cn_monitor_read_ringbuf_pos(void *mset, unsigned long arg)
{
	struct cn_monitor_set *monitor_set = mset;
	long ret = -EFAULT;
	struct monitor_direct_ringbuf_pos ringbuf_pos;
	int size = sizeof(struct monitor_direct_ringbuf_pos);

	memset(&ringbuf_pos, 0, size);
	if (copy_from_user((void *)&ringbuf_pos, (void *)arg, sizeof(struct monitor_direct_ringbuf_pos))) {
		cn_dev_err("monitor copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_read_ringbuf(monitor_set, (void *)&ringbuf_pos);
		if (!ret) {
			if (copy_to_user((void *)arg, &ringbuf_pos, size)) {
				cn_dev_err("monitor copy_to_user failed");
				ret = -EFAULT;
			}
		}
	}
	return ret;
}

int cn_monitor_set_sampling(struct cambr_amh_hub *axi_set,
							struct monitor_direct_op *op,
							struct amh_sampling_info_s *sampling_info_s)
{
	sampling_info_s->mode = 0;
	sampling_info_s->timestamp_update_time = op->timestamp_update_time;
	sampling_info_s->monitor_update_time = op->monitor_update_time;
	return 0;
}

int cn_monitor_hub_ctrl_op(void *mset, struct monitor_direct_op *op)
{
	int out_len = 0;
	int in_len = 0;
	int result = 0;
	struct cn_monitor_set *monitor_set = mset;
	int ret = 0;
	u16 hub_id = op->hub_id;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct cn_monitor_highrate_set *monitor_highrate_set = monitor_set->monitor_highrate_set;
	struct highrate_thread_context *thread_context = NULL;
	struct amh_sampling_info_s sampling_info_s = {0};
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;
	int i = 0;

	if (monitor_set->hub_num <= hub_id) {
		cn_dev_monitor_err(monitor_set, "Invalid hub id %u", hub_id);
		return -EINVAL;
	}

	thread_context = &monitor_highrate_set->thread_context[hub_id];

	if (!axi_set || !thread_context)
		return -EINVAL;
	if (!op->op) {
		cn_monitor_axi_closeall(mset, hub_id);
		ret = monitor_set->ops.stop_hub(&axi_set[hub_id]);
		if (!ret)
			axi_set[hub_id].inited = 0;
	} else {

		if (!axi_set[hub_id].inited && monitor_set->highrate_start[hub_id]) {
			for (i = 0; i < ZONE_CONUT; i++) {
				atomic64_set(&axi_set->data_ref_cnt[i], 0);
			}
			cn_monitor_reset_highrate_context(thread_context);
			cn_monitor_axi_closeall(mset, hub_id);
			/*monitor_rpc_set_sampling*/
			sampling_info_s.hub_id = hub_id;
			sampling_info_s.ratio = 0;
			ret = cn_monitor_set_sampling(&axi_set[hub_id], op, &sampling_info_s);
			if (ret) {
				cn_dev_monitor_err(monitor_set, "Invalid Sampling value");
				return -EINVAL;
			}
			out_len = sizeof(struct amh_sampling_info_s);
			ret = __pmu_call_rpc(core, monitor_set->endpoint,
						MON_SET_AXIM_SAMPLING,
						(void *)&sampling_info_s, out_len,
						&result, &in_len, sizeof(int));
			cn_dev_monitor_debug(monitor_set, "axi set sampling ret:%d result:%d in_len:%d",
					ret, result, in_len);

			if (ret < 0) {
				cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
				return ret;
			}

			if (!result) {
				ret = monitor_set->ops.start_hub(&axi_set[hub_id]);
				if (!ret) {
					axi_set[hub_id].inited = 1;
				}
			}
		} else {
			return -EPERM;
		}
	}
	return ret;
}

long cn_monitor_hub_ctrl(void *mset, unsigned long arg)
{
	struct cn_monitor_set *monitor_set = mset;
	long ret = -EFAULT;
	struct monitor_direct_op op;
	int size = sizeof(struct monitor_direct_op);

	memset(&op, 0, size);
	if (copy_from_user((void *)&op, (void *)arg, size)) {
		cn_dev_err("monitor copy_from_user failed");
		ret = -EFAULT;
	} else {
		ret = cn_monitor_hub_ctrl_op(monitor_set, &op);
	}

	return ret;
}

int cn_monitor_get_highrate_param_op(void *mset, void *pdata)
{
	int ret, i;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct axi_param_s axi_param;
	struct cn_monitor_direct_param *param = (struct cn_monitor_direct_param *)pdata;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct hub_desc *hub_param = NULL;
	int data_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!monitor_set->core)
		return -EINVAL;

	if (!monitor_set->endpoint)
		return -EINVAL;
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_GET_PARAM,
				NULL, 0,
				(void *)&axi_param, &in_len, sizeof(struct axi_param_s));
	cn_dev_monitor_debug(monitor_set, "axi get highrate param ret:%d  in_len:%d", ret, in_len);

	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor highrate rpc call failed, ret = %d", ret);
		return ret;
	}

	data_size = sizeof(struct hub_desc) * axi_param.hub_num;

	hub_param = cn_kzalloc(data_size, GFP_KERNEL);
	if (!hub_param)
		return -ENOMEM;

	param->phy_ipu_cluster_mask = axi_param.phy_ipu_cluster_mask;
	param->logic_ipu_cluster_cnt = axi_param.logic_ipu_cluster_cnt;
	param->ipu_core_pre_cluster = axi_param.ipu_core_pre_cluster;

	param->perf_info.llc_group = axi_param.llc_group;
	param->perf_info.jpu_num = axi_param.jpu_num;
	param->perf_info.smmu_group_num = axi_param.smmu_group_num;
	param->perf_info.ipu_core_num = axi_param.ipu_core_num;
	param->perf_info.ipu_cluster_num = axi_param.ipu_cluster_num;

	for (i = 0; i < axi_param.hub_num; i++) {
		hub_param[i].monitors = axi_param.monitor[i];
		hub_param[i].ipu_pfmu = axi_set[i].ipu_pfmu_count;
		hub_param[i].axi_monitor = axi_set[i].axi_monitor_count;
		hub_param[i].pfmu_data_size =
			axi_set[i].ipu_pfmu_count * sizeof(union cn_monitor_data_t);
		hub_param[i].axi_monitor_block_data_size =
			axi_set[i].axi_monitor_count * sizeof(union cn_monitor_data_t);
	}

	param->card_type = monitor_set->board_type;
	param->sharedata_size = monitor_set->sharememory_size[PMU_INFO];
	param->die_cnt = monitor_set->core->die_cnt;

	ret = cndev_cp_less_val(
			&param->hub_num, axi_param.hub_num,
			param->hub_param, hub_param, sizeof(struct hub_desc));

	param->hub_num = axi_param.hub_num;

	cn_kfree(hub_param);
	return ret;
}

long cn_monitor_get_highrate_param(void *mset, unsigned long arg)
{
	struct cn_monitor_set *monitor_set = mset;
	long ret = -EFAULT;
	struct cn_monitor_direct_param param;
	int data_size = sizeof(struct cn_monitor_direct_param);

	memset(&param, 0, data_size);
	if (copy_from_user(&param, (void *)arg, data_size)) {
		ret = -EFAULT;
		goto over;
	}
	ret = cn_monitor_get_highrate_param_op(monitor_set, &param);
	param.support_data_mode = monitor_set->support_data_mode;
	if (!ret) {
		if (copy_to_user((void *)arg, &param, data_size)) {
			cn_dev_err("copy_to_user failed\n");
			ret = -EFAULT;
		}
	}
over:
	return ret;
}

long cn_monitor_fill_card_info(void *mset, void *info)
{
	struct cn_monitor_set *monitor_set = mset;
	struct axi_monitor_card_info *card_info = info;
	struct cn_core_set *core_set = monitor_set->core;
	int ret = 0;

	card_info->card_type = monitor_set->board_type;
	card_info->die_cnt = core_set->die_cnt;
	if (core_set->device_id == MLUID_PIGEON ||
		core_set->device_id == MLUID_PIGEON_EDGE) {
		card_info->sub_type = core_set->board_info.chip_type;
	} else {
		card_info->sub_type = core_set->board_info.board_idx;
	}
	card_info->head.real_size = sizeof(struct axi_monitor_card_info);

	ret = cndrv_mcu_get_platform_id(core_set, &card_info->chip_type);

	return ret;
}

long cn_monitor_card_info(void *mset, unsigned long arg)
{
	long ret = -EFAULT;
	int data_size = sizeof(struct axi_monitor_card_info);
	struct axi_monitor_head head;
	struct axi_monitor_card_info card_info;

	memset(&card_info, 0, data_size);
	if (copy_from_user(&head, (void *)arg, sizeof(struct axi_monitor_head))) {
		ret = -EFAULT;
		goto over;
	}

	data_size = (data_size < head.buf_size) ? data_size : head.buf_size;
	if (cndev_cp_from_usr(arg, &card_info, data_size)) {
		ret = -EFAULT;
		goto over;
	}

	ret = cn_monitor_fill_card_info(mset, &card_info);
	if (!ret) {
		ret = cndev_cp_to_usr(arg, &card_info, data_size);
	}

over:
	return ret;
}

int cn_monitor_get_resource_param(void *mset, void *pdata)
{
	int ret = 0;
	int i = 0;
	int in_len = 0;
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)mset;
	struct axi_param_s axi_param;
	struct cn_monitor_res_param *param = (struct cn_monitor_res_param *)pdata;
	struct cn_core_set *core = NULL;
	u32 real_count = 0;
	u64 *res_data = NULL;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;
	core = (struct cn_core_set *)monitor_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;
	if (IS_ERR_OR_NULL(monitor_set->endpoint))
		return -EINVAL;

	memset(&axi_param, 0x0, sizeof(struct axi_param_s));

	if (!param->res_cnt) {
		param->res_cnt = PMU_MAX_RES;
		return 0;
	}

	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_GET_PARAM,
				NULL, 0,
				(void *)&axi_param, &in_len, sizeof(struct axi_param_s));
	cn_dev_monitor_debug(monitor_set, "axi get param ret:%d  in_len:%d", ret, in_len);
	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "monitor rpc call failed, ret = %d", ret);
		return -EINVAL;
	}

	param->hub_num = axi_param.hub_num;
	for (i = 0; i < param->hub_num; i++) {
		param->monitors[i] = axi_param.monitor[i];
	}
	param->card_type = monitor_set->board_type;
	param->sharedata_size = monitor_set->sharememory_size[PMU_INFO];
	param->support_data_mode = monitor_set->support_data_mode;

	res_data = cn_kzalloc(PMU_MAX_RES * sizeof(u64), GFP_KERNEL);
	if (!res_data) {
		cn_dev_monitor_err(monitor_set, "monitor kzalloc failed");
		return -EINVAL;
	}
	switch (param->version) {
	case 0:
		cn_monitor_fill_resource(monitor_set, &axi_param, res_data);
		break;
	default:
		ret = -EACCES;
		break;
	}

	real_count = param->res_cnt > PMU_MAX_RES ? PMU_MAX_RES : param->res_cnt;
	if (copy_to_user((void *)param->res_data, (void *)res_data, real_count * sizeof(u64))) {
		cn_dev_monitor_err(monitor_set, "monitor copy_to_user");
		ret = -EFAULT;
	}
	param->res_cnt = PMU_MAX_RES;
	cn_kfree(res_data);

	return ret;
}
