#ifndef __CNDRV_GENPOOL_ALLOCATOR_H
#define __CNDRV_GENPOOL_ALLOCATOR_H

#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/mutex.h>

struct genpool2 {
	unsigned int size;/*size of genpool*/
	unsigned int avail_size;/*max alloc size*/
	unsigned long bits[0];		/* bitmap for allocating memory chunk */
};

void genpool_fa_ops_register(void *fops);
#endif
