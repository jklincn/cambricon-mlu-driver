#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/pid_namespace.h>
#include <linux/bitmap.h>
#include <asm/io.h>
#if (KERNEL_VERSION(3, 17, 0) > LINUX_VERSION_CODE)
#include <linux/time.h>
#else
#include <linux/timekeeping.h>
#endif

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "camb_pmu_rpc.h"
#include "cndrv_time.h"
#include "../monitor.h"

#include "cndrv_monitor.h"
#include "cndrv_monitor_internal.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_mem_perf.h"
#include "cndrv_sbts.h"
#include "cndrv_mcu.h"

enum perf_rpc_ctrl_ops {
	CTRL_TGID_ENTRY_CREATE = 0,
	CTRL_TGID_ENTRY_ENABLE,
	CTRL_TGID_ENTRY_DISABLE,
	CTRL_TGID_ENTRY_DESTROY,
};

struct cn_perf_priv_data {
	struct perf_tgid_entry *tgid_entry;
};

/*[63:56] is module value, [55:0] is actual task type*/
int __task_type_is_sbts(u64 task_type)
{
	u64 actual_task_type = task_type & TASK_TYPE_VALUE_MASK;
	u64 task_type_bitmap = TS_PERF_TASK & TASK_TYPE_VALUE_MASK;
	u64 module_value = task_type & TASK_TYPE_MODULE_MASK;

	/*for old version, no check actual_task_type*/
	if (module_value == 0)
		return 1;

	if (module_value == TS_PERF && (actual_task_type & task_type_bitmap))
		return 1;
	return 0;
}

static inline struct perf_tgid_entry*
__perf_get_tgid_entry_by_user_priv(u64 user)
{
	struct file *fp = (struct file *)user;
	struct fp_priv_data *priv_data = (struct fp_priv_data *)fp->private_data;
	struct cn_perf_priv_data *perf_priv =
		(struct cn_perf_priv_data *)priv_data->perf_priv_data;

	if (!perf_priv) {
		return NULL;
	}

	return perf_priv->tgid_entry;
}

static int
perf_rpc_ctrl_info(struct monitor_perf_set *perf_set, enum perf_rpc_ctrl_ops ops,
		struct perf_tgid_entry *tgid_entry, u64 *rsp)
{
	int ret;
	u64 __rsp;
	int __rsp_len;
	struct perf_rpc_ctrl_msg ctrl_msg;

	/* init ctrl_msg rpc msg */
	ctrl_msg.ctrl_ops         = ops;
	ctrl_msg.unique_seq_id    = tgid_entry->unique_seq_id;
	ctrl_msg.task_type        = tgid_entry->task_type;
	ctrl_msg.buffer_size      = tgid_entry->buffer_size;
	ctrl_msg.cur_clockid      = tgid_entry->cur_clockid;
	ctrl_msg.version          = tgid_entry->version;
	ctrl_msg.tgid             = tgid_entry->cur_tgid;
	ctrl_msg.record_mode      = tgid_entry->record_mode;
	ctrl_msg.collection_mode  = tgid_entry->collection_mode;
	ctrl_msg.performance_mode = tgid_entry->performance_mode;
	ctrl_msg.tgid_iova        = tgid_entry->util.dev_iova;
	ctrl_msg.perf_iova        = perf_set->util.dev_iova;
#define op(task_type, task_name) bitmap_copy(ctrl_msg.task_name##_bitmap, tgid_entry->task_name##_bitmap, MAX_BITMAP);
	__sbts_task_list(op)
#undef op

	ret = __pmu_call_rpc(perf_set->core, perf_set->perf_ep,
			"perf_rpc_tgid_set",
			&ctrl_msg, sizeof(struct perf_rpc_ctrl_msg),
			&__rsp, &__rsp_len, sizeof(u64));
	if (ret < 0) {
		cn_dev_monitor_err(perf_set->monitor_set,
				"rpc perf_rpc_ts_info_set failed!");
		return -EINVAL;
	}

	if (!__rsp_len) {
		cn_dev_monitor_err(perf_set->monitor_set,
				"monitor arm create tgid entry failed!");
		return -EAGAIN;
	}

	if (rsp)
		*rsp = __rsp;

	return 0;
}

/* The entry create must be locked. This makes sure we never
 * create two different entry for the same tgid.
 */
static struct perf_tgid_entry*
tgid_entry_create(struct cn_monitor_set *monitor_set)
{
	int ret;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;
	struct perf_tgid_entry *tgid_entry;
	host_addr_t host_va;
	dev_addr_t dev_iova;

	/* current tgid not create before, create new tgid entry */
	tgid_entry = cn_kzalloc(sizeof(struct perf_tgid_entry), GFP_KERNEL);
	if (!tgid_entry) {
		cn_dev_monitor_err(monitor_set, "alloc new perf entry failed!");
		return NULL;
	}

	ret = cn_perf_shm_alloc(perf_set, &host_va, &dev_iova, sizeof(struct tgid_shm_data));
	if (ret) {
		cn_dev_monitor_err(monitor_set, "alloc shm failed!");
		cn_kfree(tgid_entry);
		return NULL;
	}

	/* the entry will enable after user enable perf success */
	tgid_entry->enable           = false;
	tgid_entry->cur_tgid         = current->tgid;
	tgid_entry->unique_seq_id    = atomic64_inc_return(&perf_set->seq_id);
	tgid_entry->cur_clockid      = CN_DEFAULT_CLOCKID;
	tgid_entry->collection_mode  = ALL_COLLECTION_MODE;
	tgid_entry->performance_mode = DEFAULT_PERFORMANCE_MODE;
	tgid_entry->version          = 0;
	tgid_entry->host_invoke      = 0;
	tgid_entry->util.host_va     = host_va;
	tgid_entry->util.dev_iova    = dev_iova;
	tgid_entry->util.shm         = (struct tgid_shm_data *)host_va;
	tgid_entry->active_ns        = task_active_pid_ns(current);
	tgid_entry->monitor_set = monitor_set;

	mutex_init(&tgid_entry->enable_lock);
	atomic_set(&tgid_entry->dev_ref_cnt, 1);
	atomic_set(&tgid_entry->usr_ref_cnt, 1);
	INIT_LIST_HEAD(&tgid_entry->entry);
#define op(task_type, task_name) bitmap_zero(tgid_entry->task_name##_bitmap, MAX_BITMAP);
	__sbts_task_list(op)
#undef op

	ret = perf_rpc_ctrl_info(perf_set, CTRL_TGID_ENTRY_CREATE, tgid_entry, NULL);
	if (ret) {
		cn_perf_shm_free(perf_set, host_va, dev_iova);
		cn_kfree(tgid_entry);
		cn_dev_monitor_err(monitor_set, "enable tgid entry failed!");
		return NULL;
	}

	return tgid_entry;
}

static inline void
tgid_entry_destroy(struct perf_tgid_entry *tgid_entry)
{
	int ret;
	struct cn_monitor_set *monitor_set;
	struct monitor_perf_set *perf_set;

	monitor_set = tgid_entry->monitor_set;
	perf_set = monitor_set->perf_set;

	ret = perf_rpc_ctrl_info(perf_set, CTRL_TGID_ENTRY_DESTROY, tgid_entry, NULL);
	if (unlikely(ret)) {
		cn_dev_monitor_err(monitor_set, "destory tgid entry failed!");
	}

	return;
}

void inline
tgid_entry_put(struct perf_tgid_entry *tgid_entry)
{
	struct cn_monitor_set *monitor_set;
	struct monitor_perf_set *perf_set;

	monitor_set = tgid_entry->monitor_set;
	perf_set = monitor_set->perf_set;

	if (atomic_dec_and_test(&tgid_entry->usr_ref_cnt)) {
		cn_perf_shm_free(perf_set, tgid_entry->util.host_va, tgid_entry->util.dev_iova);
		cn_kfree(tgid_entry);
	}
}

struct perf_tgid_entry * tgid_entry_get(u64 user)
{
	struct file *fp = (struct file *)user;
	struct fp_priv_data *priv_data;
	struct cn_perf_priv_data *perf_priv;
	struct perf_tgid_entry *tgid_entry = NULL;
	struct cn_core_set *core;

	if (!user)
		return NULL;

	priv_data = (struct fp_priv_data *)fp->private_data;
	if (!priv_data)
		return NULL;

	perf_priv = (struct cn_perf_priv_data *)priv_data->perf_priv_data;
	if (!perf_priv) {
		cn_dev_core_err(priv_data->core, "get perf_priv failed!");
		return NULL;
	}

	core = priv_data->core;

	tgid_entry = perf_priv->tgid_entry;
	if (!tgid_entry) {
		cn_dev_core_err(priv_data->core, "get tgid_entry failed!");
		return NULL;
	}
	atomic_inc(&tgid_entry->usr_ref_cnt);

	return tgid_entry;
}

u64
get_tgid_entry_id(struct perf_tgid_entry *tgid_entry)
{
	if (!tgid_entry)
		return 0;

	return tgid_entry->unique_seq_id;
}

int get_host_timestamp_clockid(u64 user, struct cn_core_set *core)
{
	struct cn_monitor_set *monitor_set = core->monitor_set;
	struct perf_tgid_entry *tgid_entry;

	if (!user)
		return CN_DEFAULT_CLOCKID;

	tgid_entry = __perf_get_tgid_entry_by_user_priv(user);
	if (unlikely(!tgid_entry)) {
		cn_dev_monitor_debug(monitor_set, "tgid %d user %#llx get tgid entry failed!",
				current->tgid, user);
		return CN_DEFAULT_CLOCKID;
	}

	return tgid_entry->cur_clockid;
}

bool
cn_monitor_perf_type_check_clockid(struct perf_tgid_entry *tgid_entry,
		struct cn_core_set *core, __u64 task_type, int *clock_id)
{

	*clock_id = CN_DEFAULT_CLOCKID;

	if (!tgid_entry)
		return false;

	/* just get current tgid's clock_id without check perf enable */
	*clock_id = tgid_entry->cur_clockid;

	if (!tgid_entry->enable)
		return false;

	/* check task type enable or not */
	if (!(tgid_entry->task_type & task_type))
		return false;

	return true;
}

bool cn_monitor_perf_info_enable_task_type(struct perf_tgid_entry *tgid_entry, struct cn_core_set *core,
		u64 task_type, struct sbts_perf_info *perf_info)
{
	if (!tgid_entry)
		return false;

	if (!tgid_entry->enable)
		return false;

	/* check task type enable or not */
	if (!(tgid_entry->task_type & task_type))
		return false;
	perf_info->clk_id = tgid_entry->cur_clockid;
	perf_info->collection_mode = tgid_entry->collection_mode;
	perf_info->performance_mode = tgid_entry->performance_mode;
	perf_info->host_invoke = (tgid_entry->host_invoke & task_type) ? true : false;
	return true;
}

/* read current enabled perf task type */
u64 cn_monitor_perf_get_sbts_task_type(struct perf_tgid_entry *tgid_entry, int *clock_id)
{

	if (!tgid_entry)
		return 0;

	*clock_id = tgid_entry->cur_clockid;

	if (!tgid_entry->enable)
		return 0;

	return tgid_entry->task_type;
}

u64 __tsperf_get_feature(void *fp, struct cn_monitor_set *mset)
{
	struct perf_tgid_entry *tgid_entry;
	struct monitor_perf_set *perf_set = mset->perf_set;

	if (!perf_set->perf_ep)
		return -EINVAL;

	tgid_entry = __perf_get_tgid_entry_by_user_priv((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_monitor_err(mset, "tgid %d user %px get tgid entry failed!",
				current->tgid, fp);
		return -EINVAL;
	}

	return tgid_entry->feature;
}

int __perf_version_check(void *fp, struct cn_monitor_set *monitor_set,
		u64 papi_version, u64 *feature_data, u64 fdata_len, u64 *perf_version)
{
	int ret = 0;
	int i = 0;
	u64 mode_cfg_feat = 0;
	u64 __version = 0;
	u64 __feature = 0;
	struct perf_tgid_entry *tgid_entry;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	if (!perf_set->perf_ep || !papi_version)
		return -EINVAL;

	tgid_entry = __perf_get_tgid_entry_by_user_priv((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_monitor_err(monitor_set, "tgid %d user %px get tgid entry failed!",
				current->tgid, fp);
		return -EINVAL;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock))
		return -EINTR;

	if (tgid_entry->enable) {
		mutex_unlock(&tgid_entry->enable_lock);
		cn_dev_monitor_err(monitor_set, "tgid %d user %px check version after enable!",
				current->tgid, fp);
		return -EINVAL;
	}

	switch (papi_version) {
	case DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6:
		/* add perf cfg  process and struct cfg data in this version */
		/* 1. greater than MAX_SUPPORT_FEAT shoulde be zero  */
		for (i = 0; i < fdata_len; i++) {
			if (feature_data[i] & DRIVER_FEAT_TS_PERF_START) {
				if (feature_data[i] > DRIVER_FEAT_TS_PERF_MAX_SUPPORT)
					feature_data[i] = 0;
			}
		}
		/* 2. handle base mode cfg v1 and v2, only v1 or only v2 , lesser will be zero*/
		mode_cfg_feat = DRIVER_FEAT_TS_PERF_BASE_V1;
		for (i = 0; i < fdata_len; i++) {
			if (feature_data[i] & DRIVER_FEAT_TS_PERF_START) {
				if (feature_data[i] <= DRIVER_FEAT_TS_PERF_APPEND_DATA_CONFIGURABLE_V2)
					mode_cfg_feat = mode_cfg_feat < feature_data[i] ? feature_data[i] : mode_cfg_feat;
			}
		}

		for (i = 0; i < fdata_len; i++) {
			if (feature_data[i] & DRIVER_FEAT_TS_PERF_START) {
				if (feature_data[i] < mode_cfg_feat)
					feature_data[i] = 0;
			}
		}

		__version = DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6;
		__feature = mode_cfg_feat;
		break;
	case DRIVER_MONITOR_USER_ID_VERSION_5:
	case DRIVER_DISCARD1_VERSION_4:
	case DRIVER_MONITOR_LLC_DRAM_VERSION_3:
	case DRIVER_MONITOR_RESOURCE_MASK_VERSION_2:
	case DRIVER_DIRECT_MODE_VERSION_1:
		__version = DRIVER_DIRECT_MODE_VERSION_1;
		__feature = DRIVER_FEAT_TS_PERF_BASE_V1;
		break;
	default:
		/* add perf cfg  process and struct cfg data in this version */
		/* 1. greater than MAX_SUPPORT_FEAT shoulde be zero  */
		for (i = 0; i < fdata_len; i++) {
			if (feature_data[i] & DRIVER_FEAT_TS_PERF_START) {
				if (feature_data[i] > DRIVER_FEAT_TS_PERF_MAX_SUPPORT)
					feature_data[i] = 0;
			}
		}
		/* 2. handle base mode cfg v1 and v2, only v1 or only v2 , lesser will be zero*/
		mode_cfg_feat = DRIVER_FEAT_TS_PERF_BASE_V1;
		for (i = 0; i < fdata_len; i++) {
			if (feature_data[i] & DRIVER_FEAT_TS_PERF_START) {
				if (feature_data[i] <= DRIVER_FEAT_TS_PERF_APPEND_DATA_CONFIGURABLE_V2)
					mode_cfg_feat = mode_cfg_feat < feature_data[i] ? feature_data[i] : mode_cfg_feat;
			}
		}

		for (i = 0; i < fdata_len; i++) {
			if (feature_data[i] & DRIVER_FEAT_TS_PERF_START) {
				if (feature_data[i] <= mode_cfg_feat)
					feature_data[i] = 0;
			}
		}

		__version = DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6;
		__feature = mode_cfg_feat;
		break;
	}

	if (tgid_entry->version == 0) {
		tgid_entry->version = __version;
	} else if (tgid_entry->version != __version) {
		cn_dev_monitor_err(monitor_set, "tgid %d user %px already version checked",
				current->tgid, fp);
		ret =  -EINVAL;
	}

	tgid_entry->feature = __feature;
	*perf_version = tgid_entry->version;

	mutex_unlock(&tgid_entry->enable_lock);
	return ret;
}

static int
perf_tgid_entry_enable(void *fp, struct perf_tgid_entry *tgid_entry,
		struct cn_monitor_set *monitor_set, struct __perf_mode_cfg *mode_config)
{
	int ret;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	/* param check */
	if (mode_config->buffer_size < TS_INFO_BUF_SIZE_MIN) {
		cn_dev_monitor_err(monitor_set, "tgid %d input buffer size %llu invalid!",
					current->tgid, mode_config->buffer_size);
		return -EINVAL;
	} else if (mode_config->buffer_size > TS_INFO_BUF_SIZE_MAX) {
		mode_config->buffer_size = TS_INFO_BUF_SIZE_MAX;
	}

	/* not support yet! */
	if ((mode_config->record_mode != LOSS_RECORD_MODE) &&
			(mode_config->record_mode != LOSSLESS_RECORD_MODE)) {
		cn_dev_monitor_err(monitor_set, "tgid %d record mode %d invalid!",
					current->tgid, mode_config->record_mode);
		return -EINVAL;
	}

	if ((mode_config->collection_mode != DEFAULT_COLLECTION_MODE) &&
			(mode_config->collection_mode != ALL_COLLECTION_MODE)) {
		cn_dev_monitor_err(monitor_set, "tgid %d clooection mode %d invalid!",
					current->tgid, mode_config->collection_mode);
		return -EINVAL;
	}

	if ((mode_config->performance_mode != DEFAULT_PERFORMANCE_MODE) &&
			(mode_config->performance_mode != CNTRACE_PERFORMANCE_MODE)) {
		cn_dev_monitor_err(monitor_set, "tgid %d performance mode %d invalid!",
					current->tgid, mode_config->perf_ctrl);
		return -EINVAL;
	}

	/* the lock makes sure we never enable twice (create different ts_info buffer)
	 * and never disable twice for same tgid entry. */
	if (mutex_lock_killable(&tgid_entry->enable_lock))
		return -EINTR;

	if (tgid_entry->enable) {
		cn_dev_monitor_err(monitor_set, "tgid %d has enable perf before!",
					current->tgid);
		ret = -EINVAL;
		goto unlock;
	}

	/* init current tgid entry */
	tgid_entry->buffer_size      = mode_config->buffer_size;
	tgid_entry->enable_user      = (u64)fp;
	tgid_entry->record_mode      = LOSS_RECORD_MODE;
	tgid_entry->collection_mode  = mode_config->collection_mode;
	tgid_entry->performance_mode = mode_config->performance_mode;

	ret = perf_rpc_ctrl_info(perf_set, CTRL_TGID_ENTRY_ENABLE, tgid_entry, NULL);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "enable tgid entry failed!");
		ret = -EINVAL;
		goto unlock;
	}

	/* update buffer size */
	tgid_entry->enable       = true;

unlock:
	mutex_unlock(&tgid_entry->enable_lock);
	return ret;
}

static int
perf_tgid_entry_disable(void *fp, struct perf_tgid_entry *tgid_entry,
		struct cn_monitor_set *monitor_set)
{
	int ret = 0;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	/* the lock makes sure we never free ts_info buffer when memcpy and
	 * never disable twice for save tgid entry. */
	if (mutex_lock_killable(&tgid_entry->enable_lock))
		return -EINTR;

	if (!tgid_entry->enable) {
		mutex_unlock(&tgid_entry->enable_lock);
		cn_dev_monitor_debug(monitor_set, "current user has not enable perf before!");
		return ret;
	}

	tgid_entry->enable      = false;
	tgid_entry->cur_clockid = CN_DEFAULT_CLOCKID;

	ret = perf_rpc_ctrl_info(perf_set, CTRL_TGID_ENTRY_DISABLE, tgid_entry, NULL);
	if (unlikely(ret)) {
		cn_dev_monitor_err(monitor_set, "disable tgid entry failed!");
	}
	mutex_unlock(&tgid_entry->enable_lock);

	return ret;
}

void cn_monitor_perf_tgid_exit(u64 fp, struct cn_monitor_set *monitor_set)
{
	struct perf_tgid_entry *tgid_entry = __perf_get_tgid_entry_by_user_priv(fp);

	if (unlikely(!tgid_entry)) {
		cn_dev_monitor_debug(monitor_set, "tgid %d user %#llx get tgid entry failed!",
				current->tgid, fp);
		return;
	}

	if (tgid_entry->enable && (tgid_entry->enable_user == fp))
		perf_tgid_entry_disable((void *)fp, tgid_entry, monitor_set);
}

#define case_func(task_type, task_name)	\
static inline 																			\
void task_name##_case_func(struct perf_tgid_entry *tgid_entry, u64 event_type, struct cn_monitor_set *monitor_set, int extra_idx) \
{																						\
	if (event_type <= (extra_idx + task_type##_TASK_INDEX_NUM)) {										\
		bitmap_set(tgid_entry->task_name##_bitmap, event_type - 1, 1);						\
		tgid_entry->host_invoke |= (event_type == task_type##_TASK_HOST_INVOKE_NS) ? task_type##_TS_TASK : 0ULL; \
	}   \
}

#define op(type, name) 	case_func(type, name)
	__sbts_task_list(op)
#undef op

int perf_tgid_entry_enable_v6(void *fp, struct cn_monitor_set *monitor_set,
		struct perf_tgid_entry *tgid_entry, struct __perf_mode_cfg *mode_cfg,
		struct perf_cfg_data __perf_cfg_data, struct perf_cfg_data __dbg_perf_cfg_data)
{
	DECLARE_BITMAP(check_bitmap, MAX_BITMAP);
	DECLARE_BITMAP(check_ret_bitmap, MAX_BITMAP);
	struct monitor_perf_set *perf_set = monitor_set->perf_set;
	int i = 0;
	int ret = 0;
	int extra_idx = 0;
	u64 task_type;
	u64 event_type;
	u64 tmp_array_idx = 0;

	if (!perf_set->perf_ep)
		return -EINVAL;

	if ((__perf_cfg_data.ts_perf == NULL) &&
		(__dbg_perf_cfg_data.ts_perf == NULL))
		return ret;

	/* the lock makes sure we never free ts_info buffer when memcpy */
	if (mutex_lock_killable(&tgid_entry->enable_lock))
		return -EINTR;

	if (tgid_entry->enable) {
		cn_dev_monitor_err(monitor_set, "perf tgid %d has already enable!",
					current->tgid);
		goto unlock;
	}

	/* param check */
	if (mode_cfg->ts_buffer_size < TS_INFO_BUF_SIZE_MIN) {
		cn_dev_monitor_err(monitor_set, "tgid %d input buffer size %llu invalid!",
					current->tgid, mode_cfg->ts_buffer_size);
		ret = -EINVAL;
		goto unlock;
	} else if (mode_cfg->ts_buffer_size > TS_INFO_BUF_SIZE_MAX) {
		mode_cfg->ts_buffer_size = TS_INFO_BUF_SIZE_MAX;
	}

#define op(type, name) case type##_TS_TASK: name##_case_func(tgid_entry, event_type, monitor_set, extra_idx); break;
#define __bitmap_parse(cfg_data, offset, ex_idx) \
	extra_idx = ex_idx;																\
	tmp_array_idx = cfg_data.ts_size / sizeof(struct perf_cfg_tasks);				\
	for (i = 0; (cfg_data.ts_perf) && (i < tmp_array_idx); i++) {					\
		task_type = ((struct perf_cfg_tasks *)(cfg_data.ts_perf))[i].task_type;		\
		event_type = ((struct perf_cfg_tasks *)(cfg_data.ts_perf))[i].event_type;	\
		event_type += offset;														\
		switch (task_type) {														\
			__sbts_task_list(op)													\
		}																			\
	}

	__bitmap_parse(__perf_cfg_data, 0, 0)
	__bitmap_parse(__dbg_perf_cfg_data, NON_DEBUG_NUM, DEBUG_NUM)

#undef __bitmap_parse
#undef op

	bitmap_zero(check_bitmap, MAX_BITMAP);
	bitmap_set(check_bitmap, MAX_APPEND_NUM, MAX_BITMAP - MAX_APPEND_NUM);
#define op(type, name) \
		bitmap_and(check_ret_bitmap, check_bitmap, tgid_entry->name##_bitmap, MAX_BITMAP);	\
		if (!bitmap_empty(check_ret_bitmap, MAX_BITMAP)) {									\
			cn_dev_monitor_err(monitor_set, "%s task set too many event, enable tgid entry failed!", #name); \
			ret = -EINVAL;																	\
			goto unlock;																	\
		}
	__sbts_task_list(op)
#undef op

	/* init current tgid entry */
	tgid_entry->buffer_size      = mode_cfg->ts_buffer_size;
	tgid_entry->enable_user      = (u64)fp;
	tgid_entry->record_mode      = mode_cfg->record_mode;
	tgid_entry->collection_mode  = 0;	/* unused */
	tgid_entry->performance_mode = 0;   /* unused */

	ret = perf_rpc_ctrl_info(perf_set, CTRL_TGID_ENTRY_ENABLE, tgid_entry, NULL);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "enable tgid entry failed!");
		ret = -EINVAL;
		goto unlock;
	}

	tgid_entry->enable = true;
unlock:
	mutex_unlock(&tgid_entry->enable_lock);
	return ret;
}

static int
__perf_enable(void *fp, struct cn_monitor_set *monitor_set,
		struct perf_tgid_entry *tgid_entry, struct __perf_mode_cfg *mode_cfg,
		struct perf_cfg_data __perf_cfg_data, struct perf_cfg_data __dbg_perf_cfg_data)
{
	int ret = 0;

	switch (tgid_entry->feature) {
	case DRIVER_FEAT_TS_PERF_APPEND_DATA_CONFIGURABLE_V2:
		ret = perf_tgid_entry_enable_v6(fp, monitor_set, tgid_entry, mode_cfg, __perf_cfg_data, __dbg_perf_cfg_data);
		break;
	case DRIVER_FEAT_TS_PERF_BASE_V1:
		ret = perf_tgid_entry_enable(fp, tgid_entry, monitor_set, mode_cfg);
		break;
	default:
		cn_dev_monitor_err(monitor_set, "tgid %d  user %px perf enable version [%llu] is unsupport",
				current->tgid, fp, tgid_entry->version);
		return -EINVAL;
	}

	return ret;
}

int cn_monitor_perf_mode_config(void *fp, struct cn_monitor_set *monitor_set,
		struct __perf_mode_cfg *mode_cfg, struct perf_cfg_data __perf_cfg_data,
		struct perf_cfg_data __dbg_perf_cfg_data)
{
	struct perf_tgid_entry *tgid_entry;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	if (!perf_set->perf_ep)
		return -EINVAL;

	tgid_entry = __perf_get_tgid_entry_by_user_priv((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_monitor_err(monitor_set, "tgid %d user %px get tgid entry failed!",
				current->tgid, fp);
		return -EINVAL;
	}

	if (!tgid_entry->version) {
		cn_dev_monitor_err(monitor_set, "tgid %d user %px not check version yet!",
				current->tgid, fp);
		return -EINVAL;
	}

	switch (mode_cfg->perf_ctrl) {
	case PERF_ENABLE:
		return __perf_enable(fp, monitor_set, tgid_entry, mode_cfg, __perf_cfg_data, __dbg_perf_cfg_data);
	case PERF_DISABLE:
		return perf_tgid_entry_disable(fp, tgid_entry, monitor_set);
	default:
		cn_dev_monitor_err(monitor_set, "tgid %d user %px input invalid perf_ctrl %d!",
				current->tgid, fp, mode_cfg->perf_ctrl);
		return -EINVAL;
	}
	return -EINVAL;
}

int cn_monitor_perf_clkid_config(void *fp, struct cn_monitor_set *monitor_set,
		struct perf_clkid_config *clkid_config)
{
	int ret = 0;
	struct perf_tgid_entry *tgid_entry;

	tgid_entry = __perf_get_tgid_entry_by_user_priv((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_monitor_err(monitor_set, "tgid %d user %px get tgid entry failed!",
				current->tgid, fp);
		return -EINVAL;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock))
		return -EINTR;

	if (tgid_entry->enable) {
		cn_dev_monitor_err(monitor_set, "tgid %d has enable perf, can't config clkid!",
					current->tgid);
		ret = -EINVAL;
		goto unlock;
	}

	if (clkid_config->clkid_ops == PERF_CLKID_GET) {
		clkid_config->clk_id = tgid_entry->cur_clockid;
	} else if (clkid_config->clkid_ops == PERF_CLKID_SET) {
		if ((clkid_config->clk_id != CLOCK_MONOTONIC) &&
				clkid_config->clk_id != CLOCK_MONOTONIC_RAW) {
			cn_dev_monitor_err(monitor_set, "tgid %d clkid config clkid %d invalid!",
					current->tgid, clkid_config->clk_id);
			ret = -EINVAL;
			goto unlock;
		}

		tgid_entry->cur_clockid = clkid_config->clk_id;
	} else {
		cn_dev_monitor_err(monitor_set, "tgid %d clkid config ops %d invalid!",
				current->tgid, clkid_config->clkid_ops);
		ret = -EINVAL;
	}

unlock:
	mutex_unlock(&tgid_entry->enable_lock);
	return ret;
}

int cn_monitor_perf_task_type_config(void *fp, struct cn_monitor_set *monitor_set,
		struct perf_task_type_config *task_type_config)
{
	int ret = 0;
	struct perf_tgid_entry *tgid_entry;

	tgid_entry = __perf_get_tgid_entry_by_user_priv((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_monitor_err(monitor_set, "tgid %d user %px get tgid entry failed!",
				current->tgid, fp);
		return -EINVAL;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock))
		return -EINTR;

	if (task_type_config->ops == PERF_TASK_TYPE_SET) {
		if (task_type_config->task_type & (~tgid_entry->task_type_size_get)) {
			cn_dev_monitor_err(monitor_set,
					"tgid %d get size type %#llx, set task type %#llx invalid!",
					current->tgid, tgid_entry->task_type_size_get,
					task_type_config->task_type);
			ret = -EINVAL;
			goto unlock;
		}

		tgid_entry->task_type = (TS_PERF_TASK & task_type_config->task_type);
	} else if (task_type_config->ops == PERF_TASK_TYPE_GET) {
		task_type_config->task_type |= tgid_entry->task_type;
	} else {
		cn_dev_monitor_err(monitor_set, "tgid %d  task type config ops %d invalid!",
				current->tgid, task_type_config->ops);
		ret = -EINVAL;
	}

unlock:
	mutex_unlock(&tgid_entry->enable_lock);
	return ret;
}

int cn_monitor_perf_task_type_config_v2(void *fp, struct cn_monitor_set *monitor_set,
		u64 *cfg_data, u32 len, struct perf_task_type_config_v2 *task_type_config)
{
	int ret = 0;
	int i = 0;
	struct perf_tgid_entry *tgid_entry;
	u64 tmp_bitmap = 0;

	tgid_entry = __perf_get_tgid_entry_by_user_priv((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_monitor_err(monitor_set, "tgid %d user %px get tgid entry failed!",
				current->tgid, fp);
		return -EINVAL;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock))
		return -EINTR;

	for (i = 0; i < len; i++) {
		if (__task_type_is_sbts(cfg_data[i])) {
			if (cfg_data[i] & (~tgid_entry->task_type_size_get)) {
				cn_dev_monitor_err(monitor_set,
						"tgid %d get size type %#llx, set task type %#llx invalid!",
						current->tgid, tgid_entry->task_type_size_get,
						cfg_data[i]);
				ret = -EINVAL;
				goto unlock;
			}
			tmp_bitmap |= (TS_PERF_MASK & cfg_data[i]);
		}
	}
	tgid_entry->task_type = tmp_bitmap;


unlock:
	mutex_unlock(&tgid_entry->enable_lock);
	return ret;
}
int cn_monitor_perf_tsinfo_size_get(void *fp, struct cn_monitor_set *monitor_set,
		struct perf_info_size_get *size_get)
{
	int ret = 0;
	__u32 __normal_size = 0;
	__u32 __append_size = 0;
	struct perf_tgid_entry *tgid_entry = NULL;

	tgid_entry = __perf_get_tgid_entry_by_user_priv((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_monitor_err(monitor_set, "tgid %d user %px get tgid entry failed!",
				current->tgid, fp);
		return -EINVAL;
	}

	if (size_get->task_type & (~TS_PERF_TASK)) {
		cn_dev_monitor_err(monitor_set, "tgid %d task type %#llx get size invalid!",
				current->tgid, size_get->task_type);
		return -EINVAL;
	}

	if (bitmap_weight((unsigned long *)&size_get->task_type, 64) != 1) {
		cn_dev_monitor_err(monitor_set, "tgid %d task type %#llx more than one!",
				current->tgid, size_get->task_type);
		return -EINVAL;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock))
		return -EINTR;

	if (!tgid_entry->enable) {
		cn_dev_monitor_err(monitor_set,
				"tgid %d not enable, get task type size failed!",
				current->tgid);
		ret = -EINVAL;
		goto unlock;
	}

	ret = sbts_perf_task_tsinfo_size_get(monitor_set->core, size_get->task_type,
			tgid_entry->unique_seq_id, &__normal_size, &__append_size);
	if (ret) {
		cn_dev_monitor_err(monitor_set,
				"tgid %d task type %#llx get size failed!",
				current->tgid, size_get->task_type);
		ret = -EFAULT;
		goto unlock;
	}

	size_get->normal_size = __normal_size;
	size_get->append_size = __append_size;
	tgid_entry->task_type_size_get |= size_get->task_type;

unlock:
	mutex_unlock(&tgid_entry->enable_lock);
	return ret;
}

int cn_monitor_perf_tsinfo_get(void *fp, struct cn_monitor_set *monitor_set,
		struct perf_task_info_get *tsinfo_get)
{
	int ret = 0;
	int rsp_len = 0;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;
	struct perf_tgid_entry *tgid_entry;
	struct perf_rpc_info_get ts_info_get;
	struct perf_task_info *ts_perf_info = &tsinfo_get->ts_perf;

	if (!ts_perf_info)
		return -EINVAL;

	if (!(ts_perf_info->buffer_addr && ts_perf_info->buffer_size))
		return 0;

	tgid_entry = __perf_get_tgid_entry_by_user_priv((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_monitor_err(monitor_set, "tgid %d user %px get tgid entry failed!",
				current->tgid, fp);
		return -EINVAL;
	}

	/* the lock makes sure we never free ts_info buffer when memcpy */
	if (mutex_lock_killable(&tgid_entry->enable_lock))
		return -EINTR;

	if (!tgid_entry->enable) {
		cn_dev_monitor_err(monitor_set, "current user has not enable perf before!");
		ret = -EINVAL;
		goto unlock;
	}

	if (ts_perf_info->buffer_size < tgid_entry->buffer_size) {
		cn_dev_monitor_err(monitor_set,
				"user buffer_size %#llx small than tgid_entry buffer_size %#llx!",
				ts_perf_info->buffer_size, tgid_entry->buffer_size);
		ret = -EINVAL;
		goto unlock;
	}

	/* commu call device to get device buffer addr and size */
	ret = __pmu_call_rpc(perf_set->core, perf_set->perf_ep,
				"perf_rpc_ts_info_get",
				&tgid_entry->unique_seq_id, sizeof(u64),
				&ts_info_get, &rsp_len, sizeof(struct perf_rpc_info_get));
	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "rpc perf_rpc_ts_info_get failed!");
		ret = -EINVAL;
		goto unlock;
	}

	if (rsp_len != sizeof(struct perf_rpc_info_get)) {
		cn_dev_monitor_err(monitor_set,
				"ts info get return rsp_len:%d is not match %lu",
				rsp_len, sizeof(struct perf_rpc_info_get));
		ret = -EINVAL;
		goto unlock;
	}

	/* copy buffer to userspace */
	ret = cn_monitor_dma(monitor_set->bus_set,
			(u64)ts_perf_info->buffer_addr,
			(u64)ts_info_get.dev_buf_addr,
			ts_info_get.buffer_size,
			DMA_D2H);
	if (ret) {
		cn_dev_monitor_err(monitor_set,
				"memcpy size %#llx form device %#llx to host %#llx failed!",
				ts_info_get.buffer_size, ts_info_get.dev_buf_addr,
				ts_perf_info->buffer_addr);
	}

unlock:
	mutex_unlock(&tgid_entry->enable_lock);
	return ret;
}

bool
__cn_perf_by_pass(struct cn_core_set *core)
{
	if (core->board_info.platform != MLU_PLAT_ASIC)
		return true;

	if ((core->device_id == MLUID_370_DEV) ||
		(core->device_id == MLUID_580_DEV) ||
		(core->device_id == MLUID_590_DEV))
		return true;

	if (!cn_core_is_vf(core) && cn_is_mim_en(core))
		return true;

	/* support MIM */
	if ((core->device_id == MLUID_590V) ||
		(core->device_id == MLUID_580V))
		return false;

	if (cn_core_is_vf(core))
		return true;

	return false;
}

u64 perf_process_util_get(struct perf_tgid_entry *entry)
{
	if (entry)
		return entry->util.real_util;
	return 0;
}

u32 perf_chip_util_get(struct monitor_perf_set *perf_set)
{
	return perf_set->util.chip_util;
}

static int __process_util_update_raw(struct monitor_perf_set *perf_set)
{
	struct perf_process_util *util = &perf_set->util;
	struct perf_shm_data *shm = util->shm;
	struct perf_tgid_entry *e;
	u32 lock;
	int ret = 0;

	if (unlikely(!shm))
		return -EINVAL;

	down_read(&perf_set->rwsem);

	lock = shm->rd_seq;
	rmb();

	list_for_each_entry(e, &perf_set->head, entry) {
		e->util.real_util = e->util.shm->util;
	}
	util->chip_util = shm->chip_util;
	util->period_ns = shm->period_ns;

	rmb();
	if (lock != shm->wr_seq)
		ret = -EAGAIN;

	up_read(&perf_set->rwsem);

	return ret;
}

int perf_process_util_update(struct monitor_perf_set *perf_set, int retry)
{
	do {
		if (!__process_util_update_raw(perf_set))
			return 0;
	} while (retry--);

	cn_dev_core_err(perf_set->core, "process util update timeout!");
	return -EAGAIN;
}

struct perf_tgid_entry *pid_info2tgid_entry(struct pid_info_s *pid_info)
{
	struct fp_priv_data *priv = pid_info->fp->private_data;
	struct cn_perf_priv_data *perf_priv;

	if (!priv || !priv->perf_priv_data) {
		return NULL;
	}
	perf_priv = priv->perf_priv_data;

	return perf_priv->tgid_entry;
}

/* smlu helper */
int cn_perf_process_ipu_util_update_from_shm(struct cn_core_set *core, int retry)
{
	struct cn_monitor_set *monitor_set = core->monitor_set;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	return perf_process_util_update(perf_set, retry);
}

int cn_perf_process_ipu_util_fill_pid_info(struct pid_info_s *pid_info)
{
	pid_info->ipu_util = perf_process_util_get(pid_info2tgid_entry(pid_info));
	return 0;
}

int cn_perf_ipu_chip_util_get(struct cn_core_set *core)
{
	struct cn_monitor_set *monitor_set = core->monitor_set;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	return perf_chip_util_get(perf_set);
}

int cn_perf_namespace_ipu_util_get(struct cn_core_set *core, struct pid_namespace *active_ns, u64 *ns_util)
{
	struct cn_monitor_set *monitor_set = core->monitor_set;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;
	struct perf_tgid_entry *e;

	down_read(&perf_set->rwsem);
	list_for_each_entry(e, &perf_set->head, entry) {
		if (e->active_ns == active_ns)
			*ns_util += e->util.real_util;
	}
	up_read(&perf_set->rwsem);
	return 0;
}

int cn_perf_private_data_init(struct fp_priv_data *priv_data)
{
	struct cn_core_set *core = priv_data->core;
	struct cn_monitor_set *monitor_set =
		(struct cn_monitor_set *)core->monitor_set;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;
	struct cn_perf_priv_data *perf_priv = NULL;
	struct perf_tgid_entry *tgid_entry;

	if (__cn_perf_by_pass(core))
		return 0;

	perf_priv = cn_kzalloc(sizeof(struct cn_perf_priv_data), GFP_KERNEL);
	if (!perf_priv) {
		cn_dev_core_err(core, "malloc cn_perf_private_data_init failed!");
		return -ENOMEM;
	}

	down_write(&perf_set->rwsem);
	/* check if current tgid has been alloc before */
	list_for_each_entry(tgid_entry, &perf_set->head, entry) {
		if (tgid_entry->cur_tgid == current->tgid) {
			atomic_inc(&tgid_entry->dev_ref_cnt);
			goto finish;
		}
	}

	tgid_entry = tgid_entry_create(monitor_set);
	if (!tgid_entry) {
		up_write(&perf_set->rwsem);
		cn_dev_core_err(core, "tgid entry create failed!");
		cn_kfree(perf_priv);
		return -ENOMEM;
	}

	__sync_fetch_and_add(&perf_set->tgid_count, 1);
	list_add_tail(&tgid_entry->entry, &perf_set->head);

finish:
	up_write(&perf_set->rwsem);
	perf_priv->tgid_entry = tgid_entry;
	priv_data->perf_priv_data = perf_priv;

	return 0;
}

void cn_perf_private_data_exit(struct fp_priv_data *priv_data)
{
	struct cn_core_set *core = priv_data->core;
	struct cn_perf_priv_data *perf_priv = (struct cn_perf_priv_data *)
		priv_data->perf_priv_data;
	struct perf_tgid_entry *tgid_entry = (struct perf_tgid_entry *)
		perf_priv->tgid_entry;
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)core->monitor_set;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	if (__cn_perf_by_pass(core))
		return;

	if (!tgid_entry)
		return;

	down_write(&perf_set->rwsem);
	if(atomic_dec_and_test(&tgid_entry->dev_ref_cnt)) {
		list_del(&tgid_entry->entry);
		tgid_entry_destroy(tgid_entry);
		__sync_fetch_and_sub(&perf_set->tgid_count, 1);
		if (tgid_entry)
			tgid_entry_put(tgid_entry);
	}
	up_write(&perf_set->rwsem);
	cn_kfree(priv_data->perf_priv_data);
}

void cn_perf_tgid_entry_show(struct seq_file *m, struct cn_core_set *core)
{
	struct cn_monitor_set *monitor_set =
		(struct cn_monitor_set *)core->monitor_set;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;
	struct perf_tgid_entry *tgid_entry;
	int i = 0;

	cn_perf_time_sync_show(m, core);

	down_write(&perf_set->rwsem);
	seq_puts(m, "tgid entry info start >>>>>>>>>\n");
	list_for_each_entry(tgid_entry, &perf_set->head, entry) {
		seq_puts(m, "\n");
		seq_printf(m, "entry %d start\n", i++);

		seq_printf(m, "enable %d\n", tgid_entry->enable);
		seq_printf(m, "cur_clockid %d\n", tgid_entry->cur_clockid);
		seq_printf(m, "cur_tgid %d\n", tgid_entry->cur_tgid);
		seq_printf(m, "unique_seq_id %lld\n", tgid_entry->unique_seq_id);
		seq_printf(m, "task_type %#llx\n", tgid_entry->task_type);
		seq_printf(m, "buffer_size %#llx\n", tgid_entry->buffer_size);
		seq_printf(m, "version %lld\n", tgid_entry->version);
		seq_printf(m, "enable_user %#llx\n", tgid_entry->enable_user);
		seq_printf(m, "usr ref_cnt %d\n", atomic_read(&tgid_entry->usr_ref_cnt));
		seq_printf(m, "dev ref_cnt %d\n", atomic_read(&tgid_entry->dev_ref_cnt));

		seq_printf(m, "entry %d finish\n", i);
		seq_puts(m, "\n");
	}
	seq_puts(m, "tgid entry info finish <<<<<<<<<\n");
	up_write(&perf_set->rwsem);
}
