/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2023 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/spinlock_types.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/ptrace.h>
#include <linux/kthread.h>
#include <linux/mman.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <linux/delay.h>

#include "cndrv_mm.h"
#include "cndrv_mem_perf.h"
#include "cndrv_perf_usr.h"
#include "cndrv_monitor_usr.h"
#include "mem_perf.h"

int __task_type_is_mem(u64 task_type)
 {
        u64 actual_task_type = task_type & TASK_TYPE_VALUE_MASK;
        u64 task_type_bitmap = MEM_PERF_TASK & TASK_TYPE_VALUE_MASK;
        u64 module_value = task_type & TASK_TYPE_MODULE_MASK;

        if (module_value == MEM_PERF && (actual_task_type & task_type_bitmap))
                return 1;

	return 0;
}

int cn_mem_perf_init(struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mem_perf_set *perf_set;

	perf_set = cn_kzalloc(sizeof(struct mem_perf_set), GFP_KERNEL);
	if (!perf_set) {
		cn_dev_core_err(core, "malloc mem_perf_set failed.");
		return -ENOMEM;
	}

	perf_set->mm_set = mm_set;
	atomic64_set(&perf_set->seq_id, 0);
	init_rwsem(&perf_set->rwsem);
	INIT_LIST_HEAD(&perf_set->head);
	mm_set->perf_set = perf_set;

	return 0;
}

void cn_mem_perf_exit(struct cn_mm_set *mm_set)
{
	struct mem_perf_set *perf_set = mm_set->perf_set;

	cn_kfree(perf_set);
}

/*The @tag is devfp.*/
static inline struct mem_perf_tgid_entry *__get_perf_tgid_entry(u64 tag)
{
	struct file *devfp = (struct file *)tag;
	struct fp_priv_data *priv_data;
	struct cn_mem_perf_priv_data *perf_priv;

	if (!devfp) {
		return NULL;
	}

	priv_data = (struct fp_priv_data *)devfp->private_data;
	if (!priv_data) {
		return NULL;
	}

	perf_priv = (struct cn_mem_perf_priv_data *)priv_data->mm_perf_priv_data;
	if (!perf_priv) {
		cn_dev_err("mem perf private data is null!");
		return NULL;
	}

	return perf_priv->tgid_entry;
}

int cn_mem_perf_enable(u64 tag)
{
	struct file *fp = (struct file *)tag;
	struct mem_perf_tgid_entry *tgid_entry;

	if (!fp || !fp->private_data) {
		cn_dev_info("fp or fp private data is null");
		return 0;
	}

	tgid_entry = __get_perf_tgid_entry(tag);
	if (!tgid_entry) {
		return 0;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock)) {
		return -EINTR;
	}

	if (!tgid_entry->enable) {
		mutex_unlock(&tgid_entry->enable_lock);
		return 0;
	}

	mutex_unlock(&tgid_entry->enable_lock);
	return 1;
}

u64 cn_mem_perf_get_version(void *fp, struct cn_core_set *core)
{
	struct mem_perf_tgid_entry *tgid_entry;

	tgid_entry = __get_perf_tgid_entry((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_core_err(core, "tgid %d user %#llxx get tgid entry failed!",
				current->tgid, (u64)fp);
		return -EINVAL;
	}

	return tgid_entry->version;
}

static void __modify_feature_data(u64 papi_version, u64 *fdata, u64 fdata_len, u64 *version, u64 *feature)
{
	int i;

	/* greater than MAX_SUPPORT_FEAT shoulde be zero  */
	for (i = 0; i < fdata_len; i++) {
		if (fdata[i] & DRIVER_FEAT_MEM_PERF_START) {
			if (fdata[i] > DRIVER_FEAT_MEM_PERF_MAX_SUPPORT)
				fdata[i] = 0;
		}
	}

	*version = DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6;
	*feature = 0;
}

int cn_mem_perf_version_check(void *fp, struct cn_core_set *core,
		u64 papi_version, u64 *fdata, u64 fdata_len, u64 *perf_version)
{
	u64 version = 0;
	u64 feature = 0;
	int ret = 0;
	struct mem_perf_tgid_entry *tgid_entry;

	tgid_entry = __get_perf_tgid_entry((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_core_err(core, "tgid %d user %#llx get tgid entry failed!",
				current->tgid, (u64)fp);
		return -EINVAL;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock))
		return -EINTR;

	if (tgid_entry->enable) {
		mutex_unlock(&tgid_entry->enable_lock);
		cn_dev_core_err(core, "tgid %d user %llx check version after enable!",
				current->tgid, (u64)fp);
		return -EINVAL;
	}

	if (papi_version < DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6) {
		mutex_unlock(&tgid_entry->enable_lock);
		cn_dev_core_info(core, "papi_version: %llu not support mem perf", papi_version);
		return 0;
	}

	/*modify the feature_data value by papi_version*/
	__modify_feature_data(papi_version, fdata, fdata_len, &version, &feature);

	if (tgid_entry->version == 0) {
		tgid_entry->version = version;
	} else if (tgid_entry->version != version) {
		cn_dev_core_err(core, "tgid %d user %px already version checked",
				current->tgid, fp);
		ret =  -EINVAL;
	}

	tgid_entry->feature = feature;
	tgid_entry->version_check = true;
	*perf_version = tgid_entry->version;

	mutex_unlock(&tgid_entry->enable_lock);

	return ret;
}

/*Get which are event type in this task_type. The cfg_tasks init from __mem_perf_enable*/
static void __set_bitmap_by_task_type(struct mem_perf_data *perf_data,
		u64 task_type, struct perf_cfg_tasks *cfg_tasks, u32 task_cnt)
{
	int i;
	u64 bitmap = 0;

	for (i = 0; i < task_cnt; i++) {
		/*task type is DEV_MEM_MALLOC, DEV_MEM_FREE...*/
		if (cfg_tasks->task_type == task_type) {
			/**
			 * event_type begine from 1(such as enum dev_mem_malloc_append_index),
			 * so need sub 1 here.
			 **/
			bitmap |= (1 << (cfg_tasks->event_type - 1));
		}

		cfg_tasks++;
	}

	/*enum dev_mem_malloc_append_index or enum dev_mem_free_append_index bitmap*/
	perf_data->event_type_bitmap = bitmap;
}

static inline void __append_data(struct mem_perf_data *perf_data, __u32 debug,
		__u32 index, __u64 data)
{
	if (unlikely(perf_data->append_num >= MAX_APPEND_NUM)) {
		cn_dev_err("append too many data! append num: %u, max support num: %u.",
				perf_data->append_num, MAX_APPEND_NUM);
		WARN_ON(1);
	}

	perf_data->mem_info.append_data_table[perf_data->append_num].debug = debug;
	perf_data->mem_info.append_data_table[perf_data->append_num].index = index;
	perf_data->mem_info.append_data_table[perf_data->append_num].data  = data;
	perf_data->append_num++;

	cn_dev_debug("cur index %u, data %#llx, append sum: %#x",
			index, data, perf_data->append_num);
}

static inline bool __need_append(struct mem_perf_data *perf_data, int index)
{
	return perf_data->event_type_bitmap & (0x1ULL << (index - 1)) ? true : false;
}

static void __perf_data_append_data(struct mem_perf_data *perf_data, int index, __u64 data)
{
	if (!__need_append(perf_data, index))
		return;

	__append_data(perf_data, 0, index, data);
}

static int __append_dev_malloc_perf_data(struct mem_perf_data *perf_data, struct mapinfo *pminfo)
{
	int ret = 0;
	struct cn_mem_stat mem_stat;
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct file *fp = (struct file *)pminfo->tag;
	struct fp_priv_data *priv_data = fp->private_data;
	struct pid_info_s *pid_info_node = priv_data->pid_info_node;

	ret = camb_mem_statistics(mm_set, &mem_stat);
	if (ret) {
		cn_dev_core_err(core, "Get mem info failed!");
		return ret;
	}

	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_REQUEST_SIZE, pminfo->mem_meta.size);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_ALIGNED_SIZE, pminfo->align_size);

	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_FA_TOTAL,
			mem_stat.fa_total_mem << 10);

	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_FA_FREE ,
			(mem_stat.fa_total_mem << 10) - (mem_stat.fa_used_mem << 10));

	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_DEV_FA_TOTAL,
			mem_stat.fa_dev_total_mem << 10);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_DEV_FA_FREE,
			(mem_stat.fa_dev_total_mem << 10) - (mem_stat.fa_dev_used_mem << 10));

	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_TOTAL, mem_stat.phy_total_mem << 10);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_FREE,
			(mem_stat.phy_total_mem << 10) - (mem_stat.phy_used_mem << 10));

	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_PROCESS_USED, pid_info_node->phy_usedsize);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_ADDRESS, pminfo->virt_addr);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_DEVICE_ID, mm_set->devid);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_CONTEXT_ID, pminfo->context_id);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_IS_LINEAR, (pminfo->is_linear) ? 1 : 0);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_MALLOC_MAPINFO, pminfo->mem_type);

	return ret;
}

static int __append_dev_free_perf_data(struct mem_perf_data *perf_data, struct mapinfo *pminfo)
{
	int ret = 0;
	struct cn_mem_stat mem_stat;
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct file *fp = (struct file *)pminfo->tag;
	struct fp_priv_data *priv_data = fp->private_data;
	struct pid_info_s *pid_info_node = priv_data->pid_info_node;

	ret = camb_mem_statistics(mm_set, &mem_stat);
	if (ret) {
		cn_dev_core_err(core, "Get mem info failed!");
		return ret;
	}

	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_REQUEST_SIZE, pminfo->mem_meta.size);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_ALIGNED_SIZE, pminfo->align_size);

	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_FA_TOTAL, mem_stat.fa_total_mem << 10);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_FA_FREE,
			(mem_stat.fa_total_mem << 10) - (mem_stat.fa_used_mem << 10));

	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_DEV_FA_TOTAL, mem_stat.fa_dev_total_mem << 10);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_DEV_FA_FREE,
			(mem_stat.fa_dev_total_mem << 10) - (mem_stat.fa_dev_used_mem << 10));

	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_TOTAL, mem_stat.phy_total_mem << 10);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_FREE,
			(mem_stat.phy_total_mem << 10) - (mem_stat.phy_used_mem << 10));

	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_PROCESS_USED, pid_info_node->phy_usedsize);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_ADDRESS, pminfo->virt_addr);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_DEVICE_ID, mm_set->devid);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_CONTEXT_ID, pminfo->context_id);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_IS_LINEAR, (pminfo->is_linear) ? 1 : 0);
	__perf_data_append_data(perf_data, MEM_PERF_DEV_FREE_MAPINFO , pminfo->mem_type);

	return ret;
}

static int add_perf_data_to_buf(struct mem_perf_set *perf_set,
		struct mem_perf_tgid_entry *tgid_entry, void *actual_perf_data, int add_size)
{
	struct mem_perf_buf *buf = &tgid_entry->perf_buf;

	if (add_size > (buf->total_data_size - buf->valid_data_size)) {
		goto out;
	}

	memcpy((void *)(buf->data_address + buf->valid_data_size), actual_perf_data, add_size);

	buf->valid_entry_num++;
	/*every add_size is not fixed.*/
	buf->valid_data_size += add_size;

out:
	/*seq bigger than valid_entry_num when buffer not enough.*/
	buf->seq++;

	return 0;
}

/*We will append data when task_type in tgid_entry->task_type*/
static int __task_type_in_tgid_entry(struct mem_perf_tgid_entry *tgid_entry, u64 task_type)
{
	u64 all_task_bitmap = tgid_entry->task_type & (~MEM_PERF);

	task_type &= ~MEM_PERF;

	if (all_task_bitmap & task_type)
		return 1;
	return 0;
}

int cn_mem_perf_put_details(__u64 correlation_id, struct mapinfo *pminfo, u64 task_type)
{
	int ret = 0;
	u64 tag = pminfo->tag;
	struct mem_perf_tgid_entry *tgid_entry;
	struct file *fp = (struct file *)tag;
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mem_perf_set *perf_set = mm_set->perf_set;
	struct mem_perf_data perf_data = {0};
	int perf_data_size;

	if (!fp || !fp->private_data) {
		cn_dev_core_info(core, "fp or fp private data is null");
		return 0;
	}

	tgid_entry = __get_perf_tgid_entry(tag);
	if (unlikely(!tgid_entry)) {
		cn_dev_core_err(core, "devfp is error.");
		return -EINVAL;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock)) {
		return -EINTR;
	}

	if (!tgid_entry->enable) {
		mutex_unlock(&tgid_entry->enable_lock);
		return 0;
	}

	if (!__task_type_in_tgid_entry(tgid_entry, task_type)) {
		mutex_unlock(&tgid_entry->enable_lock);
		return 0;
	}

	perf_data.mem_info.entry_type = task_type;

	/*entry_type is task_type*/
	__set_bitmap_by_task_type(&perf_data, perf_data.mem_info.entry_type,
			tgid_entry->cfg_tasks, tgid_entry->cfg_tasks_cnt);

	perf_data.mem_info.correlation_id = correlation_id;

	switch (perf_data.mem_info.entry_type) {
	case DEV_MEM_MALLOC:
		ret = __append_dev_malloc_perf_data(&perf_data, pminfo);
		break;
	case DEV_MEM_FREE:
		ret = __append_dev_free_perf_data(&perf_data, pminfo);
		break;
	default:
		cn_dev_core_err(core, "entry_type: %#llx invalid!", perf_data.mem_info.entry_type);
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	if (ret) {
		mutex_unlock(&tgid_entry->enable_lock);
		return ret;
	}

	cn_dev_core_debug(core, "put details, append_num: %u", perf_data.append_num);

	perf_data_size = sizeof(struct task_ts_info) - sizeof(struct ts_append_data) * MAX_APPEND_NUM;
	perf_data_size += perf_data.append_num * sizeof(struct ts_append_data);

	ret = add_perf_data_to_buf(perf_set, tgid_entry, &(perf_data.mem_info), perf_data_size);

	mutex_unlock(&tgid_entry->enable_lock);

	return ret;
}

static int __mem_perf_buf_init(struct mem_perf_tgid_entry *tgid_entry, __u64 buf_size)
{
	void *buf_addr;
	struct mem_perf_buf *perf_buf = &tgid_entry->perf_buf;
	struct perf_ts_info_header *buf_header = &perf_buf->buf_head;
	int head_size = sizeof(struct perf_ts_info_header);

	perf_buf->buf_size = buf_size;
	buf_addr = cn_vzalloc(perf_buf->buf_size);
	if (!buf_addr) {
		return -ENOMEM;
	}

	buf_header->version = 0;
	buf_header->valid_buffer_size = 0;
	buf_header->valid_entry_num = 0;
	buf_header->last_entry_index = 0;
	buf_header->cur_entry_index = 0;

	perf_buf->address = (u64)buf_addr;

	perf_buf->total_data_size = perf_buf->buf_size - head_size;
	perf_buf->data_address = (u64)buf_addr + head_size;
	perf_buf->valid_data_size = 0;

	perf_buf->seq = 0;
	perf_buf->valid_entry_num = 0;

	return 0;
}

static int __check_user_cfg_tasks(struct perf_cfg_tasks *cfg_tasks, int task_cnt)
{
	int i;
	__u64 max_index = 0;
	__u64 task_type;
	__u64 event_type;

	for (i = 0; i < task_cnt; i++) {
		task_type = cfg_tasks->task_type;
		event_type = cfg_tasks->event_type;
		cn_dev_debug("task_type: %#llx, event_type: %#llx\n", task_type, event_type);

		/*check task type*/
		switch (task_type) {
		case DEV_MEM_MALLOC:
			max_index = MEM_PERF_DEV_MALLOC_INDEX_NUM;
			break;
		case DEV_MEM_FREE:
			max_index = MEM_PERF_DEV_FREE_INDEX_NUM;
			break;
		default:
			cn_dev_err("error [%d]task_type: %#llx, event_type: %#llx\n", i, task_type, event_type);
			return -EINVAL;
		}

		/*check event type*/
		if (event_type > max_index) {
			cn_dev_err("task type: %llu, err event: %llu", task_type, event_type);
			return -EINVAL;
		}

		cfg_tasks++;
	}

	return 0;
}

static int __check_and_adjust_buf_size(struct __perf_mode_cfg *mode_cfg, struct cn_mm_set *mem_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mem_set->core;

	if (mode_cfg->mem_buffer_size < MEM_PERF_BUF_SIZE_MIN) {
		cn_dev_core_err(core, "tgid %u input buffer size %#llx invalid",
				current->tgid, mode_cfg->mem_buffer_size);
		return -EINVAL;
	}

	if (mode_cfg->mem_buffer_size > MEM_PERF_BUF_SIZE_MAX) {
		mode_cfg->mem_buffer_size = MEM_PERF_BUF_SIZE_MAX;
	}

	return 0;
}

static int __mem_perf_enable(u64 fp, struct mem_perf_tgid_entry *tgid_entry,
		struct cn_mm_set *mem_set, struct __perf_mode_cfg *mode_cfg, struct perf_cfg_data mem_cfg_data)
{
	struct cn_core_set *core = (struct cn_core_set *)mem_set->core;
	struct perf_cfg_tasks *cfg_tasks;
	u64 task_array_size = mem_cfg_data.mem_size;
	int task_cnt = task_array_size / sizeof(struct perf_cfg_tasks);
	int ret = 0;

	if (mutex_lock_killable(&tgid_entry->enable_lock)) {
		return -EINTR;
	}

	if (!tgid_entry->version_check) {
		cn_dev_core_err(core, "mem perf not check version yet!");
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	if (tgid_entry->enable) {
		cn_dev_core_err(core, "tgid %u fp %llu has been enabled before!",
			current->tgid, fp);
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	if (__check_and_adjust_buf_size(mode_cfg, mem_set)) {
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	if (__check_user_cfg_tasks(mem_cfg_data.mem_perf, task_cnt)) {
		cn_dev_core_err(core, "User config mem perf task some value error.\n");
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	cfg_tasks = (struct perf_cfg_tasks *)cn_kzalloc(task_array_size, GFP_KERNEL);
	if (unlikely(!cfg_tasks)) {
		mutex_unlock(&tgid_entry->enable_lock);
		return -ENOMEM;
	}

	memcpy(cfg_tasks, mem_cfg_data.mem_perf, task_array_size);

	tgid_entry->cfg_tasks = cfg_tasks;
	tgid_entry->cfg_tasks_cnt = task_cnt;
	tgid_entry->enable_user = fp;
	tgid_entry->enable = true;

	ret = __mem_perf_buf_init(tgid_entry, mode_cfg->mem_buffer_size);
	if (ret) {
		cn_dev_core_err(core, "tgid %u entry %p buffer manager init failed!",
			tgid_entry->cur_tgid, tgid_entry);
		cn_kfree(cfg_tasks);
	}
	mutex_unlock(&tgid_entry->enable_lock);

	return ret;
}

static int __mem_perf_disable(struct mem_perf_tgid_entry *tgid_entry,
		struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct perf_cfg_tasks *cfg_tasks = tgid_entry->cfg_tasks;
	void *addr = (void *)(tgid_entry->perf_buf.address);

	if (mutex_lock_killable(&tgid_entry->enable_lock)) {
		return -EINTR;
	}

	if (!tgid_entry->version_check) {
		cn_dev_core_err(core, "mem perf not check_version");
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	if (!tgid_entry->enable) {
		cn_dev_core_err(core, "tgid %u has disabled mem perf", current->tgid);
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	if (cfg_tasks) {
		cn_kfree(cfg_tasks);
		tgid_entry->cfg_tasks = NULL;
		tgid_entry->cfg_tasks_cnt = 0;
	}

	if (tgid_entry->perf_buf.address) {
		cn_vfree(addr);
		/*must set 0, cn_mem_perf_tgid_exit will recycle resources.*/
		tgid_entry->perf_buf.address = 0;
	}

	tgid_entry->enable = false;

	tgid_entry->task_type = 0;
	tgid_entry->task_type_size_get = 0;

	mutex_unlock(&tgid_entry->enable_lock);

	return 0;
}

static void cn_mem_perf_tgid_exit(struct mem_perf_tgid_entry *tgid_entry)
{
	void *addr = (void *)(tgid_entry->perf_buf.address);
	struct perf_cfg_tasks *cfg_tasks = tgid_entry->cfg_tasks;

	if (addr) {
		cn_vfree(addr);
	}

	if (cfg_tasks) {
		cn_kfree(cfg_tasks);
	}

	if (tgid_entry) {
		cn_kfree(tgid_entry);
	}
}

void cn_mem_perf_private_data_exit(struct fp_priv_data *priv_data)
{
	struct cn_core_set *core = priv_data->core;
	struct cn_mm_set *mem_set = (struct cn_mm_set *)core->mm_set;
	struct mem_perf_set *perf_set = mem_set->perf_set;
	struct cn_mem_perf_priv_data *perf_priv = (struct cn_mem_perf_priv_data *)
		priv_data->mm_perf_priv_data;
	struct mem_perf_tgid_entry *tgid_entry = (struct mem_perf_tgid_entry *)
		perf_priv->tgid_entry;

	/*Do not init mem perf on pf-only */
	if (cn_is_mim_en(core) && !cn_core_is_vf(core)) {
		return;
	}

	down_write(&perf_set->rwsem);
	if (!atomic_dec_and_test(&tgid_entry->ref_cnt)) {
		goto finish;
	}

	list_del(&tgid_entry->entry);
	__sync_fetch_and_sub(&perf_set->tgid_count, 1);
	cn_mem_perf_tgid_exit(tgid_entry);

finish:
	up_write(&perf_set->rwsem);
	cn_kfree(priv_data->mm_perf_priv_data);
}

int cn_mem_perf_mode_config(void *fp, struct cn_core_set *core,
		struct __perf_mode_cfg *mode_cfg, struct perf_cfg_data data_cfg)
{
	struct mem_perf_tgid_entry *tgid_entry;
	struct cn_mm_set *mm_set = (struct cn_mm_set *)core->mm_set;
	struct mem_perf_set *perf_set = mm_set->perf_set;

	if (!fp) {
		return 0;
	}

	if (!perf_set) {
		cn_dev_core_err(core, "mem perf set is null!");
		return -EINVAL;
	}

	tgid_entry = __get_perf_tgid_entry((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_core_err(core, "tgid %u fp %#llx get tgid entry failed!",
				current->tgid, (u64)fp);
		return -EINVAL;
	}

	if (tgid_entry->version < DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6) {
		cn_dev_core_err(core, "mem perf not support!");
		return -EINVAL;
	}

	if (!tgid_entry->feature) {
		cn_dev_core_debug(core, "mem perf feature not support!");
		return 0;
	}

	switch (mode_cfg->perf_ctrl) {
	case PERF_ENABLE:
		return __mem_perf_enable((u64)fp, tgid_entry, mm_set, mode_cfg, data_cfg);
	case PERF_DISABLE:
		return __mem_perf_disable(tgid_entry, mm_set);
	default:
		cn_dev_core_err(core, "mem perf ctrl %u invalid!", mode_cfg->perf_ctrl);
		return -EINVAL;
	}

	return 0;
}

static struct mem_perf_tgid_entry *__mem_perf_tgid_entry_create(struct cn_mm_set *mm_set)
{
	struct pid_namespace *active_ns;
	struct mem_perf_tgid_entry *tgid_entry;
	struct mem_perf_set *perf_set = mm_set->perf_set;

	tgid_entry = cn_kzalloc(sizeof(struct mem_perf_tgid_entry), GFP_KERNEL);
	if (!tgid_entry) {
		cn_dev_err("malloc mem perf tgid_entry failed");
		return NULL;
	}

	active_ns = task_active_pid_ns(current);
	tgid_entry->enable = false;
	tgid_entry->cur_tgid = current->tgid;
	tgid_entry->active_pid = task_pid_nr_ns(current, active_ns);
	tgid_entry->unique_seq_id = atomic64_inc_return(&perf_set->seq_id);

	tgid_entry->version = 0;
	tgid_entry->version_check = false;
	mutex_init(&tgid_entry->enable_lock);
	atomic_set(&tgid_entry->ref_cnt, 1);
	INIT_LIST_HEAD(&tgid_entry->entry);

	return tgid_entry;
}

int cn_mem_perf_private_data_init(struct fp_priv_data *priv_data)
{
	struct cn_core_set *core = priv_data->core;
	struct cn_mm_set *mm_set = (struct cn_mm_set *)core->mm_set;
	struct mem_perf_set *perf_set = mm_set->perf_set;
	struct cn_mem_perf_priv_data *perf_priv;
	struct mem_perf_tgid_entry *tgid_entry;

	/*Do not init mem perf on pf-only */
	if (cn_is_mim_en(core) && !cn_core_is_vf(core)) {
		return 0;
	}

	if (!perf_set) {
		cn_dev_core_err(core, "mem_perf_set is null!\n");
		return -EINVAL;
	}

	perf_priv = cn_kzalloc(sizeof(struct cn_mem_perf_priv_data), GFP_KERNEL);
	if (!perf_priv) {
		cn_dev_core_err(core, "malloc cn_mem_perf_priv_data failed.");
		return -ENOMEM;
	}

	down_write(&perf_set->rwsem);
	list_for_each_entry(tgid_entry, &perf_set->head, entry) {
		if (tgid_entry->cur_tgid == current->tgid) {
			atomic_inc(&tgid_entry->ref_cnt);
			goto finish;
		}
	}

	tgid_entry = __mem_perf_tgid_entry_create(mm_set);
	if (!tgid_entry) {
		up_write(&perf_set->rwsem);
		cn_dev_core_err(core, "create mem tgid entry failed!");
		cn_kfree(perf_priv);
		return -ENOMEM;
	}

	__sync_fetch_and_add(&perf_set->tgid_count, 1);
	list_add_tail(&tgid_entry->entry, &perf_set->head);

finish:
	up_write(&perf_set->rwsem);
	perf_priv->tgid_entry = tgid_entry;
	priv_data->mm_perf_priv_data = perf_priv;

	return 0;
}

static void __get_task_append_size(struct mem_perf_tgid_entry *tgid_entry, __u64 task_type, u32 *append_size)
{
	int i;

	for (i = 0; i < tgid_entry->cfg_tasks_cnt; i++) {
		if ((tgid_entry->cfg_tasks)[i].task_type == task_type) {
			*append_size += sizeof(struct ts_append_data);
		}
	}
}

int cn_mem_perf_tsinfo_size_get(void *fp, struct cn_core_set *core, struct perf_info_size_get *size_get)
{
	u32 append_size = 0;
	struct mem_perf_tgid_entry *tgid_entry;

	tgid_entry = __get_perf_tgid_entry((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_core_err(core, "get mem tgid_entry failed!");
		return -EINVAL;
	}

	if (!tgid_entry->feature) {
		cn_dev_core_debug(core, "mem perf feature not support!");
		return 0;
	}

	if (size_get->task_type & (~MEM_PERF_TASK)) {
		cn_dev_core_err(core, "input invalid mem task type!");
		return -EINVAL;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock)) {
		return -EINTR;
	}

	if (!tgid_entry->enable) {
		cn_dev_core_err(core, "mem perf tgid_entry not enable!");
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	size_get->normal_size = sizeof(struct task_ts_info) - sizeof(struct ts_append_data) * MAX_APPEND_NUM;

	__get_task_append_size(tgid_entry, size_get->task_type, &append_size);
	size_get->append_size = append_size;

	tgid_entry->task_type_size_get |= size_get->task_type;

	cn_dev_core_debug(core, "task_type: %#llx, append_size: %#x, task_type_size_get: %#llx",
			size_get->task_type, append_size, tgid_entry->task_type_size_get);

	mutex_unlock(&tgid_entry->enable_lock);

	return 0;
}

int cn_mem_perf_task_type_config(void *fp, struct cn_core_set *core, struct perf_task_type_config *config)
{
	int ret = 0;
	struct mem_perf_tgid_entry *tgid_entry;

	tgid_entry = __get_perf_tgid_entry((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_core_err(core, "fp %#llx get entry failed!", (u64)fp);
		return -EINVAL;
	}

	if (!tgid_entry->feature) {
		cn_dev_core_debug(core, "mem perf feature not support!");
		return 0;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock)) {
		return -EINTR;
	}

	if (!tgid_entry->enable) {
		cn_dev_core_err(core, "mem perf tgid_entry not enable!");
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	if (config->ops == PERF_TASK_TYPE_SET) {
		/*Must have invoked tsinfo_get ioctl when PERF_TASK_TYPE_SET.*/
		if (config->task_type & (~tgid_entry->task_type_size_get)) {
			cn_dev_core_err(core, "tgid %d type %#llx, set %#llx invalid!",
					current->tgid, tgid_entry->task_type_size_get, config->task_type);
			ret = -EINVAL;
			goto unlock;
		}
		tgid_entry->task_type = config->task_type;
	} else if (config->ops == PERF_TASK_TYPE_GET) {
		config->task_type = tgid_entry->task_type;
	} else {
		cn_dev_core_err(core, "task type config ops %u invalid!", config->ops);
		ret = -EINVAL;
	}

unlock:
	mutex_unlock(&tgid_entry->enable_lock);
	return ret;
}

int cn_mem_perf_task_type_config_v2(void *fp, struct cn_core_set *core,
		u64 *cfg_data, u32 len, struct perf_task_type_config_v2 *config)
{
	int ret = 0;
	int i = 0;
	struct mem_perf_tgid_entry *tgid_entry;
	u64 tmp_bitmap = 0;

	tgid_entry = __get_perf_tgid_entry((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_core_err(core, "fp %#llx get entry failed!", (u64)fp);
		return -EINVAL;
	}

	if (!tgid_entry->feature) {
		cn_dev_core_debug(core, "mem perf feature not support!");
		return 0;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock)) {
		return -EINTR;
	}

	if (!tgid_entry->enable) {
		cn_dev_core_err(core, "mem perf tgid_entry not enable!");
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	for (i = 0; i < len; i++) {
		if (__task_type_is_mem(cfg_data[i])) {
			if (cfg_data[i] & (~tgid_entry->task_type_size_get)) {
				cn_dev_core_err(core, "tgid %d type %#llx, invalid!",
						current->tgid,
						tgid_entry->task_type_size_get);
				ret = -EINVAL;
				goto unlock;
			}
			tmp_bitmap  |= (MEM_PERF_MASK & cfg_data[i]);
		}
	}
	tgid_entry->task_type = tmp_bitmap;

unlock:
	mutex_unlock(&tgid_entry->enable_lock);
	return ret;
}
int cn_mem_perf_tsinfo_get(void *fp, struct cn_core_set *core, struct perf_task_info_get *info_get)
{
	int ret = 0;
	struct mem_perf_tgid_entry *tgid_entry;
	struct perf_ts_info_header *head;
	struct mem_perf_buf *perf_buf;
	struct perf_task_info *perf_info = &info_get->mem_perf;
	int head_size;

	tgid_entry = __get_perf_tgid_entry((u64)fp);
	if (unlikely(!tgid_entry)) {
		cn_dev_core_err(core, "Get tgid entry %u by fp %#llx failed!", current->tgid, (u64)fp);
		return -EINVAL;
	}

	if (tgid_entry->version < DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6) {
		cn_dev_core_err(core, "mem tgid entry %u fp %#llx version %llu not support",
				current->tgid, (u64)fp, tgid_entry->version);
		return -EINVAL;
	}

	if (!tgid_entry->feature) {
		cn_dev_core_debug(core, "mem perf feature not support!");
		return 0;
	}

	if (mutex_lock_killable(&tgid_entry->enable_lock)) {
		return -EINTR;
	}

	if (!tgid_entry->enable) {
		cn_dev_core_err(core, "mem perf tgid_entry not enable!");
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	perf_buf = &tgid_entry->perf_buf;
	if (perf_info->buffer_size < perf_buf->buf_size) {
		cn_dev_core_err(core, "input buffer size %#llx < tgid_entry buffer size %#llx",
				perf_info->buffer_size, perf_buf->buf_size);
		mutex_unlock(&tgid_entry->enable_lock);
		return -EINVAL;
	}

	head_size = sizeof(struct perf_ts_info_header);
	head = &perf_buf->buf_head;

	/*buffer size = head size + data size*/
	head->valid_buffer_size = head_size + perf_buf->valid_data_size;
	head->valid_entry_num   = perf_buf->valid_entry_num;

	/*only record last and current entry index, The value will clear after disable mem perf*/
	head->last_entry_index  = head->cur_entry_index;
	head->cur_entry_index   = head->last_entry_index + perf_buf->seq;

	/*update buf header information to perf_buf->address*/
	memcpy((void *)perf_buf->address, (void *)head, head_size);

	/*copy all buf which include head and data to user*/
	if (copy_to_user((void *)perf_info->buffer_addr, (void *)perf_buf->address, head->valid_buffer_size)) {
		ret = -EFAULT;
		mutex_unlock(&tgid_entry->enable_lock);
		return ret;
	}

	/*clear mem perf buf.*/
	perf_buf->seq             = 0;
	perf_buf->valid_entry_num = 0;
	perf_buf->valid_data_size = 0;

	mutex_unlock(&tgid_entry->enable_lock);

	return ret;
}

void __dump_mem_perf_buf(struct seq_file *m, struct mem_perf_tgid_entry *tgid_entry)
{
	int i, j;
	struct mem_perf_buf *buf = &tgid_entry->perf_buf;
	struct task_ts_info *mem_info;
	int offset = 0;
	int append_size = 0;
	int append_cnt;

	for (i = 0; i < buf->valid_entry_num; i++) {
		mem_info = (struct task_ts_info *)(buf->data_address + offset);
		seq_printf(m, "correlation_id:%lld\n", mem_info->correlation_id);

		append_cnt = append_size / sizeof(struct ts_append_data);
		seq_printf(m, "append_cnt:%d %d\n", append_cnt, offset);

		for (j = 0; j < append_cnt; j++) {
			seq_printf(m, "debug:%d index:%d data:%#llx\n", mem_info->append_data_table[j].debug,
					mem_info->append_data_table[j].index, mem_info->append_data_table[j].data);
		}

		offset += sizeof(struct task_ts_info) - sizeof(struct ts_append_data) * MAX_APPEND_NUM;
		offset += append_cnt * sizeof(struct ts_append_data);
		append_size = 0;
	}
}

void cn_mem_perf_tgid_entry_show(struct seq_file *m, struct cn_core_set *core)
{
	int i = 0;
	struct mem_perf_tgid_entry *tgid_entry;
	struct cn_mm_set *mm_set = core->mm_set;
	struct mem_perf_set *perf_set = mm_set->perf_set;

	down_read(&perf_set->rwsem);
	seq_puts(m, "mem perf tgid entry info start >>>>>>>>>\n");
	list_for_each_entry(tgid_entry, &perf_set->head, entry) {
		seq_puts(m, "\n");
		seq_printf(m, "entry %d start\n", i++);
		seq_printf(m, "enable %d\n", tgid_entry->enable);
		seq_printf(m, "cur_tgid %d\n", tgid_entry->cur_tgid);
		seq_printf(m, "unique_seq_id %lld\n", tgid_entry->unique_seq_id);
		seq_printf(m, "buffer_size %#llx\n", tgid_entry->perf_buf.buf_size);
		seq_printf(m, "version %lld\n", tgid_entry->version);
		seq_printf(m, "enable_user %#llx\n", tgid_entry->enable_user);
		seq_printf(m, "ref_cnt %d\n", atomic_read(&tgid_entry->ref_cnt));

		seq_printf(m, "entry %d finish\n", i);
		seq_puts(m, "\n");

		mutex_lock(&tgid_entry->enable_lock);
		__dump_mem_perf_buf(m, tgid_entry);
		mutex_unlock(&tgid_entry->enable_lock);
	}
	seq_puts(m, "mem perf tgid entry info finish <<<<<<<<<\n");
	up_read(&perf_set->rwsem);
}
