#include <linux/version.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/ptrace.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/bitops.h>
#include <linux/kthread.h>
#include <linux/bitmap.h>
#include <asm/io.h>

#include "jpu_async.h"
#include "cndrv_sbts.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"
#include "sbts.h"
#include "queue.h"
#include "unotify.h"

static void cn_sbts_jpu_async_work(
		struct cn_core_set *core, void *data, void *rx_msg, int rx_size)
{
	struct comm_ctrl_desc *msg_desc = (struct comm_ctrl_desc *)rx_msg;
	struct eh_jpu_msg *rx_data = (struct eh_jpu_msg *)msg_desc->data;
	struct efd_jpu_msg sx_data = {0};
	struct sbts_set *sbts = core->sbts_set;
	struct queue *queue;

	if (msg_desc->sta != JPU_COMM_INIT) {
		cn_dev_core_err(core, "Recv jpu with invalid status %llu",
				msg_desc->sta);
		return;
	}

	/* __queue_get called in this func if queue valid */
	queue = queue_get(sbts->queue_manager, le64_to_cpu(rx_data->queue_dsid),
	    ANNOY_USER, 0);
	if (!queue) {
		cn_dev_core_err(core, "could not find queue with dsid %llu",
				rx_data->queue_dsid);
		return;
	}

	sx_data.cb_func = le64_to_cpu(rx_data->cb_func);
	sx_data.strmbuf_hdl = le64_to_cpu(rx_data->strmbuf_hdl);
	sx_data.block_id = le32_to_cpu(rx_data->block_id);

	if (sbts_unotify_send(sbts, queue, EFD_JPU_PROCESS, (u64 *)&sx_data,
			    sizeof(struct efd_jpu_msg))) {
		cn_dev_core_err(core, "send queue(%#llx) msg to usr failed!",
				(u64)queue);
	}
	queue_put(sbts->queue_manager, queue);

	return;
}

int sbts_jpu_manager_init(
		struct jpu_manager **ppjpu_mgr, struct cn_core_set *core)
{
	int ret;
	struct jpu_manager *manager = NULL;
	struct sbts_set *sbts_set = core->sbts_set;
	__u64 generation;

	sbts_get_board_generation(sbts_set, &generation);
	
	cn_dev_core_debug(core, "jpu async manager init");
	manager = cn_numa_aware_kzalloc(
			core, sizeof(struct jpu_manager), GFP_KERNEL);
	if (!manager) {
		cn_dev_core_err(core, "malloc jpu manager failed!");
		return -ENOMEM;
	}

	if (generation >= SBTS_BOARD_GENERATION_5) {
		/* create worker */
		manager->worker = commu_wait_work_run(core, "async_jpu",
				sbts_set->sched_manager->jpu_ep, manager,
				cn_sbts_jpu_async_work);

		if (IS_ERR(manager->worker)) {
			cn_dev_core_err(core, "create jpu thread failed!");
			ret = PTR_ERR(manager->worker);
			goto thread_init_fail;
		}
	}
	manager->core = core;
	manager->sbts = sbts_set;

	*ppjpu_mgr = manager;

	return 0;

thread_init_fail:
	cn_kfree(manager);

	return ret;
}

void sbts_jpu_manager_exit(struct jpu_manager *jpu_manager)
{
	struct sbts_set *sbts_set = NULL;
	__u64 generation;

	if (!jpu_manager) {
		cn_dev_err("jpu manager is null");
		return;
	}

	sbts_set = jpu_manager->sbts;

	sbts_get_board_generation(sbts_set, &generation);
	if (generation >= SBTS_BOARD_GENERATION_5) {
		commu_wait_work_stop(sbts_set->core, jpu_manager->worker);
	}
	jpu_manager->worker = NULL;
	jpu_manager->sbts->jpu_mgr = NULL;

	cn_kfree(jpu_manager);
}
