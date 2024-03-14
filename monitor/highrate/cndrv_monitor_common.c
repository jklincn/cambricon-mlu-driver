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
#include "cndrv_debug.h"
#include "cndrv_monitor_highrate.h"

void mfifo_reset(struct mfifo *p)
{
	if (IS_ERR_OR_NULL(p)) {
		return;
	}

	atomic64_set(&p->real_data_size, 0);
	p->entry = 0;
	p->head = 0;
	p->tail = 0;
	memset(p->buffer, 0, p->size * p->unit);
}

int mfifo_block_len(struct mfifo *p)
{
	int block_len = 0;

	if (IS_ERR_OR_NULL(p)) {
		return -EINVAL;
	}

	block_len = p->size;

	return block_len;
}

int mfifo_len(struct mfifo *p)
{
	if (IS_ERR_OR_NULL(p)) {
		return -EINVAL;
	}

	if (p->tail >= p->head) {
		return p->tail - p->head;
	} else {
		return p->size + p->tail - p->head;
	}

	return 0;
}

int mfifo_full(struct mfifo *p)
{
	return ((p->tail + 1) % p->size) == p->head;
}

int mfifo_empty(struct mfifo *p)
{
	return p->head == p->tail;
}

int mfifo_copy_all_to_usr(struct mfifo *p, void *pdata, int count)
{
	int ret = 0;
	int i = 0;

	if (IS_ERR_OR_NULL(p) || IS_ERR_OR_NULL(pdata)) {
		return -EINVAL;
	}

	while (!mfifo_empty(p) && count--) {
		if (copy_to_user((void *)pdata + p->unit * (i++),
							p->buffer + p->head * p->unit,
							p->unit)) {
			ret = -EFAULT;
			break;
		}
		p->head = (p->head + 1) % p->size;
	}
	return ret;
}

int mfifo_copy_to_usr(struct mfifo *p, u32 offset, void *pdata, u32 len)
{
	int ret = 0;

	if (IS_ERR_OR_NULL(p) || IS_ERR_OR_NULL(pdata)) {
		cn_dev_err_limit("p or pdata is null\n");
		return -EINVAL;
	}

	if (mfifo_empty(p)) {
		return -ENOSPC;
	}

	if (copy_to_user(pdata, (u8 *)(p->buffer) + offset * p->unit, len)) {
		ret = -EFAULT;
	}

	return ret;
}

int mfifo_copy_to_usr_unit(struct mfifo *p, u32 offset, void *pdata, u32 len, u32 unit)
{
	int ret = 0;

	if (IS_ERR_OR_NULL(p) || IS_ERR_OR_NULL(pdata)) {
		cn_dev_err_limit("p or pdata is null\n");
		return -EINVAL;
	}

	if (mfifo_empty(p)) {
		return -ENOSPC;
	}

	if (len > (p->size * p->unit)) {
		return -ENOMEM;
	}

	if (copy_to_user(pdata, (void *)((u8 *)(p->buffer) + offset * unit), len)) {
		ret = -EFAULT;
	}

	return ret;
}

int mfifo_get(struct mfifo *p, char *pdata)
{
	if (IS_ERR_OR_NULL(p) || IS_ERR_OR_NULL(pdata)) {
		return -EINVAL;
	}

	if (mfifo_empty(p)) {
		return -ENOSPC;
	}

	memcpy(pdata, p->buffer + p->head * p->unit, p->unit);
	p->head = (p->head + 1) % p->size;

	return 0;
}

int mfifo_put(struct mfifo *p, char *pdata, u8 clear, u32 data_size)
{
	u32 tail = 0;

	if (IS_ERR_OR_NULL(p)) {
		return -EINVAL;
	}

	if (mfifo_full(p)) {
		p->head = (p->head + 1) % p->size;
	}

	atomic64_set(&p->real_data_size, ((s64)mfifo_len(p) * p->unit + data_size));
	tail = p->tail;
	p->tail = (tail + 1) % p->size;
	if (clear)
		memset(p->buffer + tail * p->unit, 0, p->unit);
	memcpy(p->buffer + tail * p->unit, pdata, p->unit);

	p->entry++;
	return 0;
}

struct mfifo *mfifo_alloc(u32 count, u32 unit)
{
	struct mfifo *axi_pfifo = NULL;
	char *buffer = NULL;

	if (!count || !unit) {
		cn_dev_err("fifo buff failed, %u %u\n", count, unit);
		return NULL;
	}

	/* vmalloc ring buffer */
	buffer = vmalloc(count * unit);
	if (!buffer) {
		cn_dev_err("fifo buff vmalloc failed, size = %u\n", count * unit);
		goto err_vmalloc;
	}

	/* zalloc mfifo handler */
	axi_pfifo = cn_kzalloc(sizeof(struct mfifo), GFP_KERNEL);
	if (!axi_pfifo) {
		cn_dev_err("fifo alloc failed");
		goto err_cn_kzalloc;
	}

	/* init mfifo */
	atomic64_set(&axi_pfifo->real_data_size, 0);
	axi_pfifo->buffer = buffer;
	axi_pfifo->size = count;
	axi_pfifo->head = axi_pfifo->tail = 0;
	axi_pfifo->unit = unit;

	/* return mfifo handler */
	return axi_pfifo;

	/* zalloc mfifo handler failed, free ring buffer */
err_cn_kzalloc:
	vfree(buffer);

	/* vmalloc ring buffer failed */
err_vmalloc:
	return NULL;
}

void mfifo_free(struct mfifo *p)
{
	if (p) {
		/* frre ring buffer */
		if (p->buffer)
			vfree(p->buffer);
		p->buffer = NULL;

		/* free mfifo handler */
		cn_kfree(p);
	}
}
