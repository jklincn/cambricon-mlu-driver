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
#include <linux/workqueue.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_commu.h"
#include "cndrv_debug.h"
#include "cndrv_udvm.h"
#include "../monitor.h"
#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_monitor_highrate.h"
#include "cndrv_kwork.h"

/*kernel extern sysmbol,<linux/workqueue.h> is included since kernel version >=3.16*/
extern struct workqueue_struct *system_highpri_wq;

int aximhub_update_lastdata(struct cambr_amh_hub *axi_set)
{
	struct cn_core_set *core;
	u64 addr_pc = 0;
	u32 reg32 = 0;
	u64 addr_start = 0;
	u64 offset = 0;

	if (!axi_set) {
		return 0;
	}
	core = (struct cn_core_set *)axi_set->core;

	reg32 = reg_read32(core->bus_set, axi_set->base + 0x128);
	addr_pc = reg32;
	reg32 = reg_read32(core->bus_set, axi_set->base + 0x12C);
	addr_pc |= (u64)reg32 << 32;

	reg32 = reg_read32(core->bus_set, axi_set->base + 0x118);
	addr_start = reg32;
	reg32 = reg_read32(core->bus_set, axi_set->base + 0x11C);
	addr_start |= (u64)reg32 << 32;

	offset = addr_pc - addr_start;

	if (offset <= axi_set->start) {
		axi_set->last_data_start = 0;
		axi_set->last_data_size = offset;
	} else {
		axi_set->last_data_start = axi_set->end;
		axi_set->last_data_size = offset - axi_set->end;
	}

	axi_set->status = AH_STATUS_FINISH;
	wakeup_highrate_workqueue(axi_set, 1);
	return 0;
}

int axihub_highrate_mode(struct cambr_amh_hub *axi_set)
{
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	struct cn_monitor_set *monitor_set = NULL;
	u8 hub_id = 0;

	monitor_set = core->monitor_set;
	if (!monitor_set)
		return 1;

	hub_id = axi_set->hub_id;

	if (monitor_set->hub_num <= hub_id) {
		cn_dev_monitor_debug(monitor_set, "Invalid hub id");
		return -EINVAL;
	}

	if (monitor_set->highrate_start[hub_id] == AXI_MON_DIRECT_MODE) {
		return 0;
	}
	return 1;
}

void wakeup_highrate_workqueue(struct cambr_amh_hub *axi_set, u16 last)
{
	struct cn_core_set *core = (struct cn_core_set *)axi_set->core;
	struct cn_monitor_set *monitor_set = NULL;
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct highrate_thread_context *thread_context = NULL;
	u8 hub_id = axi_set->hub_id;
	unsigned long flags;

	monitor_set = core->monitor_set;
	if (!monitor_set)
		return;

	monitor_highrate_set = monitor_set->monitor_highrate_set;
	if (!monitor_highrate_set)
		return;

	if (hub_id >= monitor_set->hub_num) {
		return;
	}

	thread_context = (struct highrate_thread_context *)(&(monitor_highrate_set->thread_context[hub_id]));
	if (!thread_context)
		return;
	if (axi_set->last_data_size == 0 && axi_set->status == AH_STATUS_FINISH) {
		thread_context->last_data_flag = 1;
		return;
	}

	if (!last) {
		spin_lock_irqsave(&(thread_context->work_lock), flags);
		if (thread_context->work_status == HUB_WORKQUEUE_READY) {
			queue_work(thread_context->hub_wq, &(thread_context->hub_work));
		} else {
			atomic64_inc(&thread_context->record_times);
		}
		spin_unlock_irqrestore(&(thread_context->work_lock), flags);
	} else {
		spin_lock_irqsave(&(thread_context->work_lock), flags);
		if (thread_context->work_status == HUB_WORKQUEUE_READY) {
			queue_work(thread_context->hub_wq, &(thread_context->hub_work));
		} else if (thread_context->work_status == HUB_WORKQUEUE_RUNNING) {
			queue_work(thread_context->hub_wq, &(thread_context->hub_work));
		}
		spin_unlock_irqrestore(&(thread_context->work_lock), flags);
	}
}

int cn_monitor_highrate_read_data(void *mset, void *arg)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct monitor_direct_data *highrate_data = (struct monitor_direct_data *)arg;
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct highrate_thread_context *thread_context = NULL;
	struct cambr_amh_hub *axi_set = NULL;

	u16 axi_hub_id = 0;
	int real_count = 0;
	int count = 0;

	if (highrate_data->axi_block_count == 0) {
		return 0;
	}
	axi_hub_id = highrate_data->hub_id;

	if (axi_hub_id >= monitor_set->hub_num) {
		cn_dev_monitor_err(monitor_set, "Invalid hub_id");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(monitor_set->monitor_highrate_set)) {
		cn_dev_monitor_err(monitor_set, "Invalid monitor_highrate_set");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(monitor_set->axi_set)) {
		cn_dev_monitor_err(monitor_set, "Invalid axi_set");
		return -EINVAL;
	}

	axi_set = monitor_set->axi_set;
	if (!monitor_set->highrate_start[axi_hub_id] || axi_set[axi_hub_id].inited) {
		cn_dev_monitor_err(monitor_set, "Disable monitor_highrate_set");
		return -EINVAL;
	}

	monitor_highrate_set = monitor_set->monitor_highrate_set;

	/* check context */
	thread_context = (struct highrate_thread_context *)&(monitor_highrate_set->thread_context);
	if (IS_ERR_OR_NULL(thread_context)) {
		cn_dev_monitor_err(monitor_set, "Invalid thread_context");
		return -EINVAL;
	}

	if (!thread_context[axi_hub_id].axi_pfifo) {
		cn_dev_monitor_err(monitor_set, "Invalid fifo");
		return -EINVAL;
	}

	real_count = mfifo_len(thread_context[axi_hub_id].axi_pfifo);
	count = real_count > highrate_data->axi_block_count ? highrate_data->axi_block_count : real_count;
	ret = mfifo_copy_all_to_usr(thread_context[axi_hub_id].axi_pfifo, highrate_data->buff, count);
	highrate_data->real_data_size = atomic64_read(&thread_context[axi_hub_id].axi_pfifo->real_data_size);
	return ret;
}

int cn_monitor_process_data(struct highrate_thread_context *thread_context)
{
	struct cn_monitor_set *monitor_set = NULL;
	struct cambr_amh_hub *axi_set = NULL;
	struct cambr_amh_hub *hub_priv = NULL;
	u64 start = 0;
	u64 size = 0;
	u64 cache_size = 0;
	unsigned long ret_size = 0;
	u8 clear = 0;
	struct cn_core_set *core = NULL;
	u64 current_handle_idx = 0;
	u64 previous_handle_idx = 0;
	u64 previous_ref_val_before = 0;
	u64 previous_ref_val_after = 0;

	if (IS_ERR_OR_NULL(thread_context)) {
		return -ENOMEM;
	}

	if (IS_ERR_OR_NULL(thread_context->cache_buf)) {
		cn_dev_err_limit("invalid cache buffer\n");
		return -ENOMEM;
	}

	monitor_set = thread_context->monitor_set;
	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err_limit("invalid monitor_set\n");
		return -ENOMEM;
	}

	if (IS_ERR_OR_NULL(monitor_set->axi_set)) {
		cn_dev_err_limit("invalid axi_set\n");
		return -ENOMEM;
	}
	axi_set = monitor_set->axi_set;
	core = (struct cn_core_set *)axi_set->core;
	hub_priv = &axi_set[thread_context->hub_id];

	cache_size = thread_context->cache_size;

	/* last or normal data handler */
	if (hub_priv->status == AH_STATUS_FINISH) {
		start = hub_priv->last_data_start;
		size = hub_priv->last_data_size;
		if (size == 0) {
			return 0;
		}
		memset(thread_context->cache_buf, 0, cache_size);
	} else {
		start = hub_priv->start;
		size = hub_priv->size;
	}

	/* data size check */
	if (size > cache_size) {
		size = cache_size;
	}

	/* read atomic, before read data */
	current_handle_idx = atomic64_read(&axi_set->handle_index);
	if (current_handle_idx == 0) {
		previous_handle_idx = ZONE_CONUT - 1;
	} else {
		previous_handle_idx = current_handle_idx - 1;
	}
	previous_ref_val_before = atomic64_read(&axi_set->data_ref_cnt[previous_handle_idx]);

	cn_monitor_flush_data(monitor_set, thread_context, start, size);

	ret_size = cn_monitor_copy_data_from_devbuf(monitor_set, thread_context, start, size);
	/* read atomic, after read data */
	previous_ref_val_after = atomic64_read(&axi_set->data_ref_cnt[previous_handle_idx]);

	if (previous_ref_val_before < previous_ref_val_after) {
		cn_dev_err_limit("monitor buffer re-write\n");
		atomic64_inc(&thread_context->record_times);
		goto out;
	}

	if (ret_size) {
		cn_dev_err_limit("copy_data_from_devbuf ret = %llu\n", (u64)ret_size);
	} else {
		if (size != cache_size) {
			clear = 1;
		} else {
			clear = 0;
		}
		mfifo_put(thread_context->axi_pfifo, thread_context->cache_buf, clear, size);
		atomic64_inc(&thread_context->entry_count);
	}

out:
	if (hub_priv->status == AH_STATUS_FINISH) {
		thread_context->last_data_flag = 1;
	}

	/* update loss times */
	thread_context->loss_times = atomic64_read(&thread_context->record_times);
	return 0;
}

int cn_monitor_alloc_dev_mem(struct cn_monitor_set *monitor_set,
	struct highrate_thread_context *thread_context,
	void *mode_info)
{
	struct cn_core_set *core = (struct cn_core_set *)(monitor_set->core);
	struct mem_attr mm_attr;
	dev_addr_t dev_vaddr = 0;
	int ret = 0;

	if (!thread_context->dev_vaddr) {
		dev_vaddr = 0;
		/* 16MB or 256KB */
		/* 64KB align*/
		INIT_MEM_ATTR(&mm_attr, thread_context->dev_buff_size, 0x10000, CN_IPU_MEM, 0, 1 << 30);
		/* alloc dev mem */
		ret = cn_mem_alloc(0, &dev_vaddr, &mm_attr, core);
		if (ret) {
			cn_dev_monitor_err(monitor_set, "alloc dev memory failed(%d -- %#lx).",
							mm_attr.affinity, mm_attr.size);
			return -ENOMEM;
		}
		thread_context->dev_vaddr = udvm_get_iova_from_addr(dev_vaddr);
		thread_context->host_dev_vaddr = dev_vaddr;
		ret = cn_monitor_mem_mmap(monitor_set, thread_context);
		if (ret) {
			/* free iova */
			cn_mem_free(0, thread_context->host_dev_vaddr, core);
			thread_context->dev_vaddr = 0;
			thread_context->host_dev_vaddr = 0;
			ret = -1;
		}
	}
	return ret;
}

int cn_monitor_free_dev_mem(struct cn_monitor_set *monitor_set)
{
	struct cn_core_set *core = (struct cn_core_set *)(monitor_set->core);
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct highrate_thread_context *thread_context = NULL;
	u32 i = 0;
	u32 hub_num = monitor_set->hub_num;

	monitor_highrate_set = monitor_set->monitor_highrate_set;
	if (IS_ERR_OR_NULL(monitor_highrate_set)) {
		return -EINVAL;
	}

	for (i = 0; i < hub_num; i++) {
		thread_context = &monitor_highrate_set->thread_context[i];
		if (thread_context && thread_context->host_dev_vaddr) {
			cn_monitor_mem_unmmap(monitor_set, thread_context);
			cn_mem_free(0, thread_context->host_dev_vaddr, core);
			thread_context->dev_vaddr = 0;
			thread_context->host_dev_vaddr = 0;
		}
	}

	return 0;
}

int cn_monitor_free_cache_mem(struct cn_monitor_set *monitor_set)
{
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct highrate_thread_context *thread_context = NULL;
	u32 i = 0;
	u32 hub_num = monitor_set->hub_num;

	monitor_highrate_set = monitor_set->monitor_highrate_set;
	if (IS_ERR_OR_NULL(monitor_set->monitor_highrate_set)) {
		return -EINVAL;
	}

	thread_context = (struct highrate_thread_context *)&(monitor_highrate_set->thread_context);
	if (IS_ERR_OR_NULL(thread_context)) {
		cn_dev_monitor_err(monitor_set, "Invalid thread_context");
		return -EINVAL;
	}

	for (i = 0; i < hub_num; i++) {
		if (thread_context[i].cache_buf) {
			cn_vfree(thread_context[i].cache_buf);
			thread_context[i].cache_buf = NULL;
		}
	}

	return 0;
}

int cn_monitor_alloc_cache_mem(struct cn_monitor_set *monitor_set,
	struct highrate_thread_context *thread_context,
	void *mode_info)
{
	/* alloc host phy mem for D2H */
	if (IS_ERR_OR_NULL(thread_context->cache_buf)) {
		thread_context->cache_buf = cn_vmalloc(thread_context->cache_size);
		if (!thread_context->cache_buf) {
			cn_dev_monitor_err(monitor_set, "vmalloc cache data fail.");
			return -ENOMEM;
		}
		memset(thread_context->cache_buf, 0, thread_context->cache_size);
	} else {
		memset(thread_context->cache_buf, 0, thread_context->cache_size);
	}

	return 0;
}

int cn_monitor_free_ring_mem(struct cn_monitor_set *monitor_set)
{
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct highrate_thread_context *thread_context = NULL;
	u32 i = 0;
	u32 hub_num = 0;

	hub_num = monitor_set->hub_num;
	monitor_highrate_set = monitor_set->monitor_highrate_set;
	if (IS_ERR_OR_NULL(monitor_highrate_set)) {
		cn_dev_monitor_err(monitor_set, "invalid monitor_highrate_set");
		return -EINVAL;
	}

	for (i = 0; i < hub_num; i++) {
		thread_context = &monitor_highrate_set->thread_context[i];
		if (thread_context && thread_context->axi_pfifo) {
			mfifo_free(thread_context->axi_pfifo);
			thread_context->axi_pfifo = NULL;
		}
	}

	return 0;
}

int cn_monitor_alloc_raw_ring_mem(struct cn_monitor_set *monitor_set,
	struct highrate_thread_context *thread_context,
	void *mode_info)
{
	struct monitor_direct_mode *highrate_mode = (struct monitor_direct_mode *)mode_info;
	u32 block_size = 0;
	u16 hub_id = highrate_mode->hub_id;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	int ret = 0;
	u64 raw_block_count = 0;
	u32 zone_raw_block_count = 0;
	u64 min_raw_ring_buffer_block_count = 0;
	u64 pfmu_raw_data_count_per_zone = 0;
	u64 zone_size = 0;

	if (IS_ERR_OR_NULL(monitor_set->zone_info)) {
		cn_dev_monitor_err(monitor_set, "Invalid zone info");
		return -EINVAL;
	}

	min_raw_ring_buffer_block_count = monitor_set->zone_info->min_raw_ring_buffer_block_count;
	pfmu_raw_data_count_per_zone = monitor_set->zone_info->pfmu_raw_data_count_per_zone;
	zone_size = monitor_set->zone_info->zone_size;
	if (pfmu_raw_data_count_per_zone == 0) {
		cn_dev_monitor_err(monitor_set, "Invalid raw data count");
		return -EINVAL;
	}
	if (axi_set[hub_id].monitor_num == 0) {
		cn_dev_monitor_err(monitor_set, "monitor num is zero failed");
		return -EPERM;
	}
	block_size = zone_size;

	raw_block_count = highrate_mode->raw_block_count;

	if (raw_block_count < min_raw_ring_buffer_block_count) {
		raw_block_count = min_raw_ring_buffer_block_count;
	} else {
		if (highrate_mode->raw_block_count % min_raw_ring_buffer_block_count) {
			raw_block_count = highrate_mode->raw_block_count / pfmu_raw_data_count_per_zone;
			raw_block_count = (raw_block_count + 1) * pfmu_raw_data_count_per_zone;
		}
	}
	highrate_mode->raw_data_count_per_zone = pfmu_raw_data_count_per_zone;
	highrate_mode->raw_block_count = raw_block_count;
	zone_raw_block_count = raw_block_count / pfmu_raw_data_count_per_zone;
	thread_context->fifo_buf_size = block_size * zone_raw_block_count;
	thread_context->block_size = block_size;

	if (!thread_context->axi_pfifo) {
		thread_context->axi_pfifo = mfifo_alloc(zone_raw_block_count, thread_context->block_size);
		if (!thread_context->axi_pfifo) {
			cn_dev_monitor_err(monitor_set, "ring fifo buff alloc failed");
			ret = -ENOMEM;
			goto out;
		}
	} else {
		mfifo_reset(thread_context->axi_pfifo);
	}

	return 0;

out:

	return ret;
}

int cn_monitor_alloc_ring_mem(struct cn_monitor_set *monitor_set,
	struct highrate_thread_context *thread_context,
	void *mode_info)
{
	struct monitor_direct_mode *highrate_mode = (struct monitor_direct_mode *)mode_info;
	u16 hub_id = highrate_mode->hub_id;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	int ret = 0;

	if (axi_set[hub_id].monitor_num == 0) {
		cn_dev_monitor_err(monitor_set, "monitor num is zero failed");
		return -EPERM;
	}

	ret = cn_monitor_alloc_raw_ring_mem(monitor_set, thread_context, mode_info);

	return ret;
}



static int cn_monitor_free_ring_mem_by_hubid(struct cn_monitor_set *monitor_set,
	struct highrate_thread_context *thread_context)
{
	if (thread_context && thread_context->axi_pfifo) {
		mfifo_free(thread_context->axi_pfifo);
		thread_context->axi_pfifo = NULL;
	}
	return 0;
}

static int cn_monitor_free_dev_mem_by_hubid(struct cn_monitor_set *monitor_set,
	struct highrate_thread_context *thread_context)
{
	struct cn_core_set *core = (struct cn_core_set *)(monitor_set->core);

	if (thread_context && thread_context->host_dev_vaddr) {
		cn_monitor_mem_unmmap(monitor_set, thread_context);
		cn_mem_free(0, thread_context->host_dev_vaddr, core);
		thread_context->dev_vaddr = 0;
		thread_context->host_dev_vaddr = 0;
	}

	return 0;
}

static int cn_monitor_free_cache_mem_by_hubid(struct cn_monitor_set *monitor_set,
	struct highrate_thread_context *thread_context)
{
	if (thread_context && thread_context->cache_buf) {
		cn_vfree(thread_context->cache_buf);
		thread_context->cache_buf = NULL;
	}

	return 0;
}

void cn_monitor_highrate_workqueue(struct work_struct *work)
{
	struct highrate_thread_context *thread_context = NULL;
	unsigned long flags;

	thread_context = container_of(work, struct highrate_thread_context, hub_work);
	if (IS_ERR_OR_NULL(thread_context)) {
		cn_dev_err_limit("work context is null");
		return;
	}

	spin_lock_irqsave(&thread_context->work_lock, flags);
	thread_context->work_status = HUB_WORKQUEUE_RUNNING;
	spin_unlock_irqrestore(&thread_context->work_lock, flags);

	cn_monitor_process_data(thread_context);

	spin_lock_irqsave(&thread_context->work_lock, flags);
	thread_context->work_status = HUB_WORKQUEUE_READY;
	spin_unlock_irqrestore(&thread_context->work_lock, flags);

}

int cn_monitor_create_workqueue(struct cn_monitor_set *monitor_set,
	struct highrate_thread_context *thread_context,
	void *mode_info)
{
	char work_name[32] = {0};
	struct monitor_direct_mode *highrate_mode = (struct monitor_direct_mode *)mode_info;

	if (!thread_context->hub_wq) {
		memset(work_name, 0, sizeof(work_name));
		sprintf(work_name, "monitor_hubwq_%d", highrate_mode->hub_id);
		spin_lock_init(&(thread_context->work_lock));
		INIT_WORK(&(thread_context->hub_work), cn_monitor_highrate_workqueue);
		thread_context->hub_wq = system_highpri_wq;
		thread_context->monitor_set = monitor_set;
		thread_context->hub_id = highrate_mode->hub_id;
		thread_context->work_status = HUB_WORKQUEUE_READY;
	}

	return 0;
}

int cn_monitor_destroy_workqueue(struct cn_monitor_set *monitor_set)
{
	u32 hub_num = monitor_set->hub_num;
	u32 i = 0;
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct highrate_thread_context *thread_context = NULL;

	monitor_highrate_set = monitor_set->monitor_highrate_set;

	for (i = 0; i < hub_num; i++) {
		thread_context = &monitor_highrate_set->thread_context[i];
		if (thread_context && thread_context->hub_wq) {
			flush_work(&thread_context->hub_work);
			cancel_work_sync(&thread_context->hub_work);
			thread_context->hub_wq = NULL;
		}
	}

	return 0;
}

int cn_monitor_init_monitor_highrate_env(void *mset,
	struct highrate_thread_context *thread_context,
	void *mode_info)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;

	ret = cn_monitor_alloc_cache_mem(monitor_set, thread_context, mode_info);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "monitor cache malloc error.");
		ret = -ENOMEM;
		goto err;
	}

	/* alloc dev mem */
	ret = cn_monitor_alloc_dev_mem(monitor_set, thread_context, mode_info);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "monitor dev mem malloc error.");
		ret = -ENOMEM;
		goto err_cache;
	}

	/* alloc host ring buffer */
	ret = cn_monitor_alloc_ring_mem(monitor_set, thread_context, mode_info);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "monitor alloc fifo error.");
		ret = -ENOMEM;
		goto err_dev_mem;
	}

	ret = cn_monitor_create_workqueue(monitor_set, thread_context, mode_info);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "monitor highrate mode create workqueue failed.");
		goto err_fifo_mem;
	}

	return 0;

err_fifo_mem:
	cn_monitor_free_ring_mem_by_hubid(monitor_set, thread_context);

err_dev_mem:
	cn_monitor_free_dev_mem_by_hubid(monitor_set, thread_context);

err_cache:
	cn_monitor_free_cache_mem_by_hubid(monitor_set, thread_context);

err:
	return ret;
}

int cn_monitor_exit_monitor_highrate_env(void *mset)
{
	u16 hub_id = 0;
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("Invalid monitor_set");
		return 0;
	}

	cn_monitor_destroy_workqueue(monitor_set);

	cn_monitor_free_dev_mem(monitor_set);

	cn_monitor_free_ring_mem(monitor_set);

	for (hub_id = 0; hub_id < monitor_set->hub_num; hub_id++) {
		if (monitor_set->highrate_start[hub_id] == AXI_MON_DIRECT_MODE)
			cndrv_axi_monitor_disable_irq(monitor_set, hub_id);
		monitor_set->highrate_start[hub_id] = AXI_MON_NORMAL_MODE;
	}

	cn_monitor_free_cache_mem(monitor_set);

	return 0;
}

int cn_monitor_release_monitor_highrate_env(void *monitor_set,
	struct highrate_thread_context *thread_context)
{
	cn_monitor_free_ring_mem_by_hubid(monitor_set, thread_context);

	cn_monitor_free_dev_mem_by_hubid(monitor_set, thread_context);

	cn_monitor_free_cache_mem_by_hubid(monitor_set, thread_context);

	return 0;
}


int cn_monitor_exit_monitor_highrate_env_by_hubid(void *mset, int hub_id)
{
	int ret = 0;
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	struct highrate_thread_context *thread_context = NULL;
	u32 hub_num = 0;
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err("Invalid monitor_set");
		return -EINVAL;
	}

	hub_num = monitor_set->hub_num;
	if (hub_id >= hub_num) {
		cn_dev_monitor_err(monitor_set, "Invalid hubid");
		return -EINVAL;
	}
	monitor_highrate_set = monitor_set->monitor_highrate_set;
	thread_context = &monitor_highrate_set->thread_context[hub_id];
	if (IS_ERR_OR_NULL(thread_context)) {
		cn_dev_monitor_err(monitor_set, "Invalid thread context");
		return -EINVAL;
	}

	if (monitor_set->highrate_start[hub_id] == AXI_MON_DIRECT_MODE)
		cndrv_axi_monitor_disable_irq(monitor_set, hub_id);
	monitor_set->highrate_start[hub_id] = AXI_MON_NORMAL_MODE;

	if (thread_context->hub_wq) {
		flush_work(&thread_context->hub_work);
		cancel_work_sync(&thread_context->hub_work);
		thread_context->hub_wq = NULL;
	}

	ret = cn_monitor_release_monitor_highrate_env(monitor_set, thread_context);

	return ret;
}

#if defined(CONFIG_CNDRV_PIGEON_SOC) || defined(CONFIG_CNDRV_CE3226_SOC)
extern void cn_mem_unmap(void* kva);
extern void *cn_mem_map_cached(u64 iova, u64 size);
int cn_monitor_mem_mmap_kernel(u64 iova, u64 *kernel_va, u64 size)
{
	u64 kva = 0;

	kva = (u64)cn_mem_map_cached(iova, size);
	if (!kva) {
		cn_dev_err_limit("mlu dev address %#llx map error", (u64)iova);
		return -EINVAL;
	}

	*kernel_va = kva;
	return 0;
}

int cn_monitor_mem_unmmap_kernel(u64 iova, u64 *kernel_va)
{
	cn_mem_unmap(kernel_va);

	return 0;
}
#else
int cn_monitor_mem_mmap_kernel(u64 iova, u64 *kernel_va, u64 size)
{
	return -1;
}

int cn_monitor_mem_unmmap_kernel(u64 iova, u64 *kernel_va)
{
	return -1;
}
#endif

unsigned long cn_monitor_copy_data_from_devbuf(void *mset,
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	if (IS_ERR_OR_NULL(monitor_set->parse_ops)) {
		cn_dev_err_limit("Invalid parse_ops\n");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(monitor_set->parse_ops->copy_data_from_devbuf)) {
		cn_dev_err_limit("Invalid copy data function\n");
		return -EINVAL;
	}

	return monitor_set->parse_ops->copy_data_from_devbuf(thread_context, start, size);
}


unsigned long cn_monitor_flush_data(void *mset,
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	if (IS_ERR_OR_NULL(monitor_set->parse_ops)) {
		cn_dev_err_limit("Invalid parse_ops\n");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(monitor_set->parse_ops->flush_data)) {
		cn_dev_err_limit("Invalid flush data func\n");
		return -EINVAL;
	}

	return monitor_set->parse_ops->flush_data(thread_context, start, size);
}

int cn_monitor_pfmu_hubtrace_map_info(void *mset, void *map_info)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	if (IS_ERR_OR_NULL(monitor_set->parse_ops)) {
		cn_dev_monitor_err(monitor_set, "Invalid parse_ops");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(monitor_set->parse_ops->pfmu_hubtrace_map_info)) {
		cn_dev_monitor_err(monitor_set, "Invalid pfmu hubtrace map func");
		return -EINVAL;
	}

	return monitor_set->parse_ops->pfmu_hubtrace_map_info(monitor_set, map_info);
}

int cn_monitor_pfmu_hubtrace_tab_len(void *mset)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	if (IS_ERR_OR_NULL(monitor_set->parse_ops)) {
		cn_dev_monitor_err(monitor_set, "Invalid parse_ops");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(monitor_set->parse_ops->pfmu_hubtrace_tab_len)) {
		cn_dev_monitor_err(monitor_set, "Invalid pfmu hubtrace table len func");
		return -EINVAL;
	}

	return monitor_set->parse_ops->pfmu_hubtrace_tab_len(mset);
}

int cn_monitor_mem_mmap(void *mset, void *context)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	if (IS_ERR_OR_NULL(monitor_set->parse_ops)) {
		cn_dev_monitor_err(monitor_set, "Invalid parse_ops");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(monitor_set->parse_ops->mem_mmap_kernel)) {
		cn_dev_monitor_err(monitor_set, "Invalid mem mmap func");
		return -EINVAL;
	}

	return monitor_set->parse_ops->mem_mmap_kernel(context);
}

int cn_monitor_mem_unmmap(void *mset, void *context)
{
	struct cn_monitor_set *monitor_set = mset;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	if (IS_ERR_OR_NULL(monitor_set->parse_ops)) {
		cn_dev_monitor_err(monitor_set, "Invalid parse_ops");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(monitor_set->parse_ops->mem_unmmap_kernel)) {
		cn_dev_monitor_err(monitor_set, "Invalid mem unmap func");
		return -EINVAL;
	}

	return monitor_set->parse_ops->mem_unmmap_kernel(context);
}

int cn_monitor_fill_res_map(void *mset, void *res_map)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct monitor_res_map_info *info = res_map;
	u32 res_len = 0;
	u32 real_res_len = 0;
	u32 buf_size = 0;
	void *map_info = NULL;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	if (IS_ERR_OR_NULL(monitor_set->parse_ops)) {
		cn_dev_monitor_debug(monitor_set, "Invalid parse_ops");
		goto next;
	}

	if (IS_ERR_OR_NULL(monitor_set->parse_ops->monitor_res_tab_len)) {
		cn_dev_monitor_debug(monitor_set, "Invalid monitor resource map table");
		goto next;
	}

	if (IS_ERR_OR_NULL(monitor_set->parse_ops->monitor_res_info)) {
		cn_dev_monitor_debug(monitor_set, "Invalid monitor res map");
		goto next;
	}

	monitor_set->parse_ops->monitor_res_info(info->res_type, &map_info);
	res_len = monitor_set->parse_ops->monitor_res_tab_len(info->res_type);
	if (!res_len || !map_info) {
		goto next;
	}

	if (!info->res_num) {
		real_res_len = res_len;
		goto next;
	}

	real_res_len = info->res_num > res_len ? res_len : info->res_num;
	if (map_info) {
		buf_size = sizeof(struct monitor_llc_mem) * real_res_len;
		if (copy_to_user(info->res_info, map_info, buf_size)) {
			cn_dev_monitor_err(monitor_set, "copy_to_user failed");
			ret = -EFAULT;
		}
	}

next:

	info->res_num = real_res_len;
	return ret;
}
