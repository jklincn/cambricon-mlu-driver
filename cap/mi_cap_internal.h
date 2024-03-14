#ifndef __MI_CAP_INTERNAL_H__
#define __MI_CAP_INTERNAL_H__

#include <linux/ioctl.h>
#include <linux/types.h>
#include "cndrv_bus.h"
#include "cndrv_core.h"

#define MI_CAP_GET_INSTANCE_PCIE_INFO	_IOR(0xc0, 0x1, struct bus_info_s)
#define MI_CAP_GET_INSTANCE_UNIQUE_ID	_IOR(0xc0, 0x2, uint64_t)

int mi_cap_get_instance_pcie_info(struct file *fp,
			struct cn_core_set *mi_core,
			unsigned int cmd,
			unsigned long arg);
int mi_cap_get_instance_unique_id(struct file *fp,
			struct cn_core_set *mi_core,
			unsigned int cmd,
			unsigned long arg);
#endif /* __MI_CAP_INTERNAL_H__ */
