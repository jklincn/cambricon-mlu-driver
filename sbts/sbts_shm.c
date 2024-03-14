/*
 * sbts/sbts_shm.c
 *
 * NOTICE:
 * Copyright (C) 2023 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/ktime.h>
#include <linux/pid_namespace.h>
#include <linux/llist.h>
#include <linux/fdtable.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_os_compat.h"
#include "sbts.h"
#include "queue.h"

/* only support get and save queue shm info */
struct sbts_shm_global_info {

	/* lock for cross-device info lock */
	struct mutex iova_lock;
	/* [src_idx][req_idx] */
	struct sbts_shm_iova_top iova[MAX_FUNCTION_NUM][MAX_FUNCTION_NUM];
};

struct sbts_shm_global_info *g_sbts_shm_info;

/* sbts share memory manage for notifier and queue */
int sbts_shm_init(struct sbts_shm_manager **pshm_mgr, struct cn_core_set *core,
		u32 nbits, u32 page_size)
{
	struct sbts_shm_manager *shm_mgr;
	struct sbts_set *sbts_set = core->sbts_set;
	int ret;

	shm_mgr = cn_numa_aware_kzalloc(core, sizeof(struct sbts_shm_manager), GFP_KERNEL);
	if (!shm_mgr) {
		cn_dev_core_err(core, "malloc share mem manager failed");
		ret = -ENOMEM;
		goto err_shm_mgr;
	}

	mutex_init(&shm_mgr->shm_lock);
	shm_mgr->nbits = nbits;
	shm_mgr->bitmap_size = BITS_TO_LONGS(shm_mgr->nbits) * sizeof(long);
	shm_mgr->bitmap = cn_numa_aware_kzalloc(core, shm_mgr->bitmap_size, GFP_KERNEL);
	if (!shm_mgr->bitmap) {
		cn_dev_core_err(core, "malloc queue share mem bitmap failed!");
		ret = -ENOMEM;
		goto err_bitmap_alloc;
	}

	bitmap_zero(shm_mgr->bitmap, shm_mgr->nbits);

	shm_mgr->page_size = page_size;

	/* alloc queue return shared memory */
	if (sbts_set->outbd_able) {
		ret = cn_host_share_mem_alloc(0,
				&shm_mgr->host_vaddr, &shm_mgr->dev_vaddr,
				nbits * page_size, core);
		cn_dev_core_info(core, "alloc outbound share mem, shm_mgr->host_vaddr:%#lx, shm_mgr->dev_vaddr:%#llx",
					shm_mgr->host_vaddr, shm_mgr->dev_vaddr);
	} else {
		ret = cn_device_share_mem_alloc(0,
				&shm_mgr->host_vaddr, &shm_mgr->dev_vaddr,
				nbits * page_size, core);
		cn_dev_core_info(core, "alloc inbound share mem, shm_mgr->host_vaddr:%#lx, shm_mgr->dev_vaddr:%#llx",
					shm_mgr->host_vaddr, shm_mgr->dev_vaddr);
	}
	if (ret) {
		cn_dev_core_err(core, "alloc queue ret shared memory failed");
		ret = -CN_SBTS_ERROR_SHARE_MEM_ALLOC;
		goto err_shm_alloc;
	}

	*pshm_mgr = shm_mgr;

	return 0;

err_shm_alloc:
	cn_kfree(shm_mgr->bitmap);
err_bitmap_alloc:
	cn_kfree(shm_mgr);
err_shm_mgr:

	return ret;
}

void sbts_shm_exit(struct sbts_shm_manager *shm_mgr, struct cn_core_set *core)
{
	struct sbts_set *sbts_set = core->sbts_set;

	if (IS_ERR_OR_NULL(shm_mgr)) {
		cn_dev_core_err(core, "shm_mgr is null");
		return;
	}

	if (sbts_set->outbd_able) {
		cn_host_share_mem_free(0,
				shm_mgr->host_vaddr, shm_mgr->dev_vaddr,
				core);
	} else {
		cn_device_share_mem_free(0,
				shm_mgr->host_vaddr, shm_mgr->dev_vaddr,
				core);
	}
	mutex_destroy(&shm_mgr->shm_lock);
	cn_kfree(shm_mgr->bitmap);
	cn_kfree(shm_mgr);
}

int sbts_shm_alloc(struct sbts_shm_manager *shm_mgr, struct cn_core_set *core,
		host_addr_t *host_vaddr, dev_addr_t *dev_vaddr)
{
	u32 index;

	if (mutex_lock_killable(&shm_mgr->shm_lock)) {
		cn_dev_core_err(core, "get shm_lock failed");
		return -EINTR;
	}

	index = find_first_zero_bit(shm_mgr->bitmap, shm_mgr->nbits);
	if (unlikely(index >= shm_mgr->nbits)) {
		cn_dev_core_err(core, "malloc queue share mem failed");
		mutex_unlock(&shm_mgr->shm_lock);
		return -ENOMEM;
	}
	set_bit(index, shm_mgr->bitmap);

	*host_vaddr = shm_mgr->host_vaddr + index * shm_mgr->page_size;
	*dev_vaddr = shm_mgr->dev_vaddr + index * shm_mgr->page_size;

	mutex_unlock(&shm_mgr->shm_lock);
	return 0;
}

/* need g_sbts_shm_info->iova_lock */
static int sbts_shm_host_iova_ready(struct cn_core_set *core,
		struct cn_core_set *req_core,
		struct sbts_shm_manager *shm_mgr)
{
	int ret = 0;
	int i;
	size_t shm_total_size = shm_mgr->nbits * shm_mgr->page_size;
	u32 sg_total_size = 0;
	u32 sg_total_idx = 0;
	struct scatterlist *sg;
	struct sg_table *iova_sgt;
	struct sbts_shm_iova_top *host_iova;
	struct sbts_shm_iova_info *info;

	host_iova = &g_sbts_shm_info->iova[core->idx][req_core->idx];
	if (host_iova->sta) {
		if (host_iova->sta == SBTS_SHM_IOVA_ERROR) {
			return -EINVAL;
		}

		/* host_iova->sta == SBTS_SHM_IOVA_READY */
		if (host_iova->host_vaddr != shm_mgr->host_vaddr) {
			cn_dev_core_err(core, "host va:%#lx != card%d va:%#lx",
					host_iova->host_vaddr, req_core->idx, shm_mgr->host_vaddr);
			dump_stack();
			return -EFAULT;
		}
		return 0;
	}
	ret = cn_bus_get_dob_iova(core->bus_set, req_core->bus_set, shm_mgr->dev_vaddr,
			shm_total_size, &iova_sgt);
	if (ret) {
		cn_dev_core_err(core, "get dob host iova for card%d failed %d",
				req_core->idx, ret);
		ret = -ENOMEM;
		goto get_fail;
	}

	info = cn_kzalloc(sizeof(struct sbts_shm_iova_info) * iova_sgt->nents, GFP_KERNEL);
	if (!info) {
		cn_dev_core_err(core, "alloc info buf for card%d failed", req_core->idx);
		ret = -ENOMEM;
		goto alloc_fail;
	}

	if (iova_sgt->nents > 8) {
		cn_dev_core_err(core, "get dob host iova for card%d too many sgl %u",
				req_core->idx, iova_sgt->nents);
		ret = -EINVAL;
		goto check_fail;
	}

	for_each_sg(iova_sgt->sgl, sg, iova_sgt->nents, i) {
		info[i].addr = sg_dma_address(sg);
		info[i].addr_len = sg_dma_len(sg);
		info[i].idx_start = sg_total_idx;
		info[i].idx_num = info[i].addr_len / shm_mgr->page_size;
		sg_total_size += info[i].addr_len;
		sg_total_idx += info[i].idx_num;
		info[i].max_idx = sg_total_idx;
	}

	if ((sg_total_size != shm_total_size) || (sg_total_idx != shm_mgr->nbits)) {
		cn_dev_core_err(core, "check sg data fail size %#x %lx idx %u %u",
				sg_total_size, shm_total_size, sg_total_idx, shm_mgr->nbits);
		ret = -EINVAL;
		goto check_fail;
	}

	host_iova->host_vaddr = shm_mgr->host_vaddr;
	host_iova->nents = iova_sgt->nents;
	host_iova->iova_sgt = iova_sgt;
	host_iova->req_bus = req_core->bus_set;
	host_iova->info = info;
	host_iova->sta = SBTS_SHM_IOVA_READY;
	return 0;

check_fail:
	cn_kfree(info);
alloc_fail:
	cn_bus_put_dob_iova(req_core->bus_set, &iova_sgt);
get_fail:
	host_iova->sta = SBTS_SHM_IOVA_ERROR;
	return ret;
}

int sbts_shm_get_host_iova(struct cn_core_set *core, struct cn_core_set *req_core,
		struct sbts_shm_manager *shm_mgr, dev_addr_t dev_vaddr, u64 *iova)
{
	int ret, i;
	u32 index;
	struct sbts_set *sbts = (struct sbts_set *)core->sbts_set;
	struct sbts_shm_iova_top *host_iova;
	struct sbts_shm_iova_info *info;

	if (!sbts->outbd_able) {
		cn_dev_core_err(core, "dev not support outbound");
		return -ENOMEM;
	}

	index = (dev_vaddr - shm_mgr->dev_vaddr) / shm_mgr->page_size;

	if (index >= shm_mgr->nbits) {
		cn_dev_core_err(core, "dev_vaddr %#llx is out of range", dev_vaddr);
		return -EINVAL;
	}

	if (mutex_lock_killable(&g_sbts_shm_info->iova_lock)) {
		cn_dev_core_err(core, "get shm_lock failed");
		return -EINTR;
	}

	ret = sbts_shm_host_iova_ready(core, req_core, shm_mgr);
	if (ret) {
		cn_dev_core_err(core, "check shm iova ready fail");
		goto out;
	}

	host_iova = &g_sbts_shm_info->iova[core->idx][req_core->idx];
	info = host_iova->info;

	for (i = 0; i < host_iova->nents; i++) {
		if (index >= info[i].max_idx)
			continue;

		*iova = info[i].addr + (index - info[i].idx_start) * shm_mgr->page_size;
		goto out;
	}

	cn_dev_core_err(core, "cant find iova by index %u", index);
	ret = -ENOMEM;
out:
	mutex_unlock(&g_sbts_shm_info->iova_lock);
	return ret;
}

void sbts_shm_free(struct sbts_shm_manager *shm_mgr, dev_addr_t dev_vaddr)
{
	u32 index;

	index = (dev_vaddr - shm_mgr->dev_vaddr) / shm_mgr->page_size;
	if (index >= shm_mgr->nbits) {
		cn_dev_err("dev_vaddr is out of range");
		return;
	}

	if (!test_and_clear_bit(index, shm_mgr->bitmap)) {
		cn_dev_err("dev_vaddr has been free");
	}
}

static void __sbts_shm_iova_free(struct sbts_shm_iova_top *host_iova)
{

	cn_bus_put_dob_iova(host_iova->req_bus, &host_iova->iova_sgt);
	cn_kfree(host_iova->info);

	memset((void *)host_iova, 0, sizeof(struct sbts_shm_iova_top));
	host_iova->sta = SBTS_SHM_IOVA_INIT;
}

void sbts_shm_global_dev_exit(struct sbts_set *sbts)
{
	struct cn_core_set *core = sbts->core;
	struct sbts_shm_iova_top *host_iova;
	int i;

	mutex_lock(&g_sbts_shm_info->iova_lock);
	for (i = 0; i < MAX_FUNCTION_NUM; i++) {
		host_iova = &g_sbts_shm_info->iova[core->idx][i];
		if (host_iova->sta == SBTS_SHM_IOVA_READY) {
			__sbts_shm_iova_free(host_iova);
		}

		host_iova = &g_sbts_shm_info->iova[i][core->idx];
		if (host_iova->sta == SBTS_SHM_IOVA_READY) {
			__sbts_shm_iova_free(host_iova);
		}
	}
	mutex_unlock(&g_sbts_shm_info->iova_lock);
}

int sbts_shm_global_init(void)
{

	g_sbts_shm_info = cn_kzalloc(sizeof(struct sbts_shm_global_info), GFP_KERNEL);

	if (!g_sbts_shm_info) {
		cn_dev_err("alloc mem for shm global failed");
		return -ENOMEM;
	}

	mutex_init(&g_sbts_shm_info->iova_lock);

	return 0;
}

void sbts_shm_global_exit(void)
{
	int i, j;
	struct sbts_shm_iova_top *host_iova;

	if (!g_sbts_shm_info)
		return;

	for (i = 0; i < MAX_FUNCTION_NUM; i++) {
		for (j = 0; j < MAX_FUNCTION_NUM; j++) {
			host_iova = &g_sbts_shm_info->iova[i][j];
			if (host_iova->sta != SBTS_SHM_IOVA_READY)
				continue;

			cn_dev_err("iova[%d][%d] sta %d with info[%llx]",
					i, j, host_iova->sta, (u64)host_iova->info);
			if (host_iova->info)
				cn_kfree(host_iova->info);
		}
	}

	cn_kfree(g_sbts_shm_info);
}

int cn_sbts_shm_debug_show(struct cn_core_set *core, struct seq_file *m)
{
	struct sbts_shm_iova_top *host_iova;
	int idx = 0;
	int i;

	if (!g_sbts_shm_info) {
		seq_puts(m, "global shm info is invalid\n");
		return 0;
	}

	if (!core || !core->sbts_set) {
		seq_puts(m, "core or sbts is null\n");
		return 0;
	}
	idx = core->idx;

	if (mutex_lock_killable(&g_sbts_shm_info->iova_lock)) {
		seq_puts(m, "wait lock fail\n");
		return 0;
	}

	seq_printf(m, "Current Dev Index [%d]:\n", idx);
	seq_puts(m, "Used on Card Index:      ");
	for (i = 0; i < MAX_FUNCTION_NUM; i++) {
		host_iova = &g_sbts_shm_info->iova[idx][i];
		if (host_iova->sta == SBTS_SHM_IOVA_READY) {
			seq_printf(m, "%d,", i);
		}

	}
	seq_puts(m, "\nUsed from Card Index:  ");
	for (i = 0; i < MAX_FUNCTION_NUM; i++) {
		host_iova = &g_sbts_shm_info->iova[i][idx];
		if (host_iova->sta == SBTS_SHM_IOVA_READY) {
			seq_printf(m, "%d,", i);
		}
	}
	seq_puts(m, "\n");
	mutex_unlock(&g_sbts_shm_info->iova_lock);

	return 0;
}

void cn_sbts_shm_debug_write(
		struct cn_core_set *core,
		const char __user *user_buf,
		size_t count)
{

}
