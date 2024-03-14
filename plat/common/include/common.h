#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/highmem.h>
#include <asm/pgalloc.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/percpu.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/smp.h>
#include <linux/dmaengine.h>
#include <linux/completion.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/cpumask.h>

/* Endian conversion macro's */

#define IO_BE_WRITE64(val, addr)        { \
	iowrite32(__cpu_to_be32((uint32_t)(val>>32)), (void *)addr); \
	iowrite32(__cpu_to_be32((uint32_t)val), \
		((uint8_t *)addr + sizeof(uint32_t)));\
	};

#define IO_BE_WRITE64_PTR(val, addr)        { \
	iowrite32(__cpu_to_be32((uint32_t)(*val>>32)), (void *)addr); \
	iowrite32(__cpu_to_be32((uint32_t)val), \
		((uint8_t *)addr + sizeof(uint32_t)));\
	};

#define IO_BE_READ64(val, addr)         { \
	val = (__cpu_to_be32(ioread32((void *)addr))); \
	val = (val << 32); \
	val = val | \
		(__cpu_to_be32(ioread32((uint8_t *)addr + sizeof(uint32_t)))); \
	};

#define IO_LE_READ64(val, addr)         { \
	val = (__cpu_to_le32(ioread32((void *)addr))); \
	val = (val << 32); \
	val = val | \
		(__cpu_to_le32(ioread32((uint8_t *)addr + sizeof(uint32_t)))); \
	};

#define IO_BE_WRITE32(val, addr)    iowrite32(__cpu_to_be32(val), (void *)addr)
#define IO_BE_READ32(addr)          __cpu_to_be32(ioread32(addr))

#define IO_BE_WRITE16(val, addr)    iowrite16(__cpu_to_be16(val), (void *)addr)
#define IO_BE_READ16(addr)          __cpu_to_be16(ioread16(addr))

#define IO_BE_WRITE8(val, addr)     iowrite8(val, (void *)addr)
#define IO_BE_READ8(addr)			ioread8((void *)addr)

#define IO_LE_WRITE64(val, addr) { \
	iowrite32(__cpu_to_le32((uint32_t)(val>>32)), (void *)addr); \
	iowrite32(__cpu_to_le32((uint32_t)val), \
		((uint8_t *)addr + sizeof(uint32_t)));\
	};

#define IO_LE_WRITE32(val, addr)	\
	iowrite32(__cpu_to_le32(val), (void *)addr)
#define IO_LE_READ32(addr)	\
	__cpu_to_le32(ioread32(addr))

#define IO_LE_WRITE16(val, addr)	\
	iowrite16(__cpu_to_le16(val), (void *)addr)
#define IO_LE_READ16(addr)	\
	__cpu_to_le16(ioread16(addr))

#define IO_LE_WRITE8(val, addr)	\
	iowrite8(val, (void *)addr)
#define IO_LE_READ8(addr)	\
	ioread8((void *)addr)

#endif
