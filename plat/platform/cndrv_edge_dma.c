#include <linux/version.h>
#include <linux/uaccess.h>/*copy_from_user*/
#include <linux/sched.h>
#include <linux/vmalloc.h>
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/mm.h>
#endif

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "cndrv_edge.h"
#include "./cndrv_edge_dma.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_pinned_mm.h"
#include "cndrv_debug.h"

int
edge_init_device_addr(void *addr, struct ion_device_addr *ion_dev_addr)
{
	int ret = 0;

	if (addr_is_udvm((unsigned long)addr)) {
		ion_dev_addr->iova = (u64)addr;
		ion_dev_addr->handle_id = -1;
		ion_dev_addr->version = 1;
	} else {
		if (copy_from_user((void *)ion_dev_addr, addr,
						   sizeof(struct ion_device_addr))) {
			cn_dev_err("copy_from_user failed");
			ret = -EFAULT;
		}
	}

	return 0;
}

int cn_edge_init_dma_task(
		struct edge_dma_task *task,
		struct transfer_s *t,
		enum CN_EDGE_DMA_TYPE dma_type,
		void *edge_priv)
{
	int ret = 0;
	struct ion_device_addr ion_dev_addr;

	memset(task, 0, sizeof(*task));
	task->edge_set = (struct cn_edge_set *)edge_priv;
	task->transfer = t;
	/*not use in edge platform.*/
	task->dma_type = dma_type;
	task->tsk = current;
	task->tsk_mm = current->mm;

	ret = edge_init_device_addr((void *)t->ia, &ion_dev_addr);
	if (ret) {
		return ret;
	}

	/*ia don't use after, clear it*/
	task->transfer->ia = 0;

	if (ion_dev_addr.version != 1) {
		pr_err("version is error");
		return -1;
	}

	task->ion_cntx.iova = ion_dev_addr.iova;
	task->ion_cntx.handle_id = ion_dev_addr.handle_id;

	if (dma_type == EDGE_DMA_P2P) {
		pr_err("not support EDGE_DMA_P2P");
		return 0;
	}

	if (dma_type == EDGE_DMA_PINNED_MEM) {
		task->kvaddr = cn_pinned_mem_get_kv(current->tgid, t->ca, t->size);
		if (!task->kvaddr) {
			pr_err("get pinned mem(%#llx %#llx) kva error.", (u64)t->ca, (u64)t->size);
			return -EINVAL;
		}
	}

	return ret;
}

