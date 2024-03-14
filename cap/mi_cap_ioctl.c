#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "cndrv_core.h"
#include "cndrv_cap.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "mi_cap_internal.h"

int mi_cap_get_instance_pcie_info(struct file *fp,
			struct cn_core_set *mi_core,
			unsigned int cmd,
			unsigned long arg)
{
	struct bus_info_s bus_info;

	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(mi_core->bus_set, &bus_info);
	if (copy_to_user((void *)arg, (void *)&bus_info,
			sizeof(struct bus_info_s))) {
		cn_dev_core_err(mi_core, "copy_to_user failed.");
		return -EFAULT;
	}

	return 0;
}

int mi_cap_get_instance_unique_id(struct file *fp,
				struct cn_core_set *mi_core,
				unsigned int cmd,
				unsigned long arg)
{
	struct inode *inode = fp->f_inode;
	uint64_t unique_id = inode->i_rdev;

	if (copy_to_user((void *)arg, (void *)&unique_id, sizeof(unique_id))) {
		cn_dev_core_err(mi_core, "copy_to_user failed.");
		return -EFAULT;
	}

	return 0;
}
