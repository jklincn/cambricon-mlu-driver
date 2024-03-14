#ifndef __CNDRV_BUDDY_ALLOCATOR_H
#define __CNDRV_BUDDY_ALLOCATOR_H

#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/mutex.h>

#include "cndrv_mm.h"
#include "cndrv_core.h"


struct buddy2 {
	unsigned int size;
	unsigned int longest[1];
};

void buddy_fa_ops_register(void *fops);
#endif
