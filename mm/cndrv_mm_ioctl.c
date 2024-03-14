/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/pid_namespace.h>
#include <linux/ftrace.h>
#include <linux/proc_fs.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_monitor.h"
#include "cndrv_mm.h"
#include "camb_mm.h"
#include "camb_udvm.h"

#include "cndrv_ioctl.h"
#include "cndrv_gdma.h"
#include "cndrv_proc.h"

static int cn_get_absolute_path(struct cn_core_set *core, struct task_struct *task)
{
	char *ret_ptr = NULL;
	char *tpath = NULL;
	struct vm_area_struct *vma = NULL;
	struct path base_path;

	if (task == NULL)
		return -EINVAL;

	tpath = (char *)cn_kzalloc(512, GFP_KERNEL);
	if (tpath == NULL)
		return -EINVAL;

	task_lock(task);
	if (task->mm && task->mm->mmap) {
		vma = task->mm->mmap;
	} else {
		task_unlock(task);
		cn_kfree(tpath);
		return -1;
	}
	while (vma) {
		if (vma->vm_file) {
			base_path = vma->vm_file->f_path;
			break;
		}
		vma = vma->vm_next;
	}
	task_unlock(task);

#if KERNEL_VERSION(2, 6, 25) <= LINUX_VERSION_CODE
	ret_ptr = d_path(&base_path, tpath, 512);
#else
	ret_ptr = d_path(base_path.dentry, base_path.mnt, tpath, 512);
#endif
	cn_dev_core_info(core, "pid:%d process:%s", task->pid, ret_ptr);
	cn_kfree(tpath);

	return 0;
}

int m_mem_alloc(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *mm_alloc = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!mm_alloc) {
		cn_dev_core_err(core, "kmalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "MEM_ALLOC  BEGIN");
	if (copy_from_user((void *)mm_alloc, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		struct mem_attr mm_attr;
		dev_addr_t dev_vaddr;
		int cond = _IOC_SIZE(cmd);

		mm_attr.tag = (u64)fp;
		mm_attr.size = GET_COMPAT_PARAM(mm_alloc, alloc, cond, size);
		mm_attr.align = GET_COMPAT_PARAM(mm_alloc, alloc, cond, align);
		mm_attr.type = CN_IPU_MEM;
		mm_attr.affinity = GET_COMPAT_PARAM(mm_alloc, alloc, cond, affinity);
		mm_attr.flag = GET_COMPAT_PARAM(mm_alloc, alloc, cond, flag);
		mm_attr.vmid = PF_ID;

		ret = cn_mem_alloc((u64)fp, &dev_vaddr, &mm_attr, core);
		if (ret) {
			cn_dev_core_err(core, "global memory alloc failed(%d -- %#lx).",
					mm_attr.affinity, mm_attr.size);
			cn_kfree(mm_alloc);
			return ret;
		}

		SET_COMPAT_PARAM(mm_alloc, alloc, cond, ret_addr, (__u64)dev_vaddr);
		if (copy_to_user((void *)arg, (void *)mm_alloc, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
		}
	}

	cn_dev_core_debug(core, "MEM_ALLOC  END");
	cn_kfree(mm_alloc);
	return ret;
}

int m_mem_free(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct mem_free_param_s mm_free;

	cn_dev_core_debug(core, "MEM_FREE  BEGIN");
	if (copy_from_user((void *)&mm_free, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		ret = cn_mem_free((u64)fp, mm_free.ret_addr, core);
		if (IS_ERR_VALUE((long)ret)) {
			cn_dev_core_err(core, "mem_free failed.");
			return ret;
		}

		mm_free.size = ret;

		if (copy_to_user((void *)arg, (void *)&mm_free, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
			return ret;
		}
	}
	cn_dev_core_debug(core, "MEM_FREE  END");
	return ret;
}

int m_mem_merge(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct mem_merge_param_s mm_merge;
	__u64 *virt_addr = NULL;

	cn_dev_core_debug(core, "MEM_MERGE  BEGIN");
	if (copy_from_user((void *)&mm_merge, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		virt_addr = cn_kcalloc(mm_merge.cnt, sizeof(__u64), GFP_KERNEL);
		if (!virt_addr) {
			cn_dev_core_err(core, "kcalloc error.");
			ret = -ENOMEM;
			return ret;
		}

		if (copy_from_user((void *)virt_addr,
					(void *)mm_merge.virt_addrs,
					sizeof(__u64)*mm_merge.cnt)) {
			cn_dev_core_err(core, "copy_from_user failed.");
			ret = -EFAULT;
			cn_kfree(virt_addr);
			return ret;
		}

		if (mm_merge.cnt < 2) {
			cn_dev_core_err(core,
					"memory merge count(%d) < 2.",
					mm_merge.cnt);
			ret = -EINVAL;
			cn_kfree(virt_addr);
			return ret;
		}

		ret = cn_mem_merge((u64)fp,
				&mm_merge.merged_addr,
				virt_addr, mm_merge.cnt,
				core);
		if (ret) {
			cn_dev_core_err(core, "mem_merge failed.");
			cn_kfree(virt_addr);
			return ret;
		}

		if (copy_to_user((void *)arg, (void *)&mm_merge, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			cn_kfree(virt_addr);
			ret = -EFAULT;
			return ret;
		}

		cn_kfree(virt_addr);
	}

	cn_dev_core_debug(core, "MEM_MERGE END");
	return ret;
}

int m_mem_copy_h2d(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *h2d = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!h2d) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "MEM_COPY_H2D  BEGIN");
	if (copy_from_user((void *)h2d, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		unsigned long ret_size = 0;
		int cond = _IOC_SIZE(cmd);

		ret_size = cn_mem_copy_h2d((u64)fp,
				GET_COMPAT_PARAM(h2d, copy_h2d, cond, ca),
				GET_COMPAT_PARAM(h2d, copy_h2d, cond, ia),
				GET_COMPAT_PARAM(h2d, copy_h2d, cond, total_size),
				core);

		SET_COMPAT_PARAM(h2d, copy_h2d, cond, residual_size, ret_size);
		if (copy_to_user((void *)arg, (void *)h2d, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
		}
	}
	cn_dev_core_debug(core, "MEM_COPY_H2D  END");
	cn_kfree(h2d);
	return ret;
}

int m_mem_copy_d2h(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *d2h = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!d2h) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "MEM_COPY_D2H BEGIN");
	if (copy_from_user((void *)d2h, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		unsigned long ret_size = 0;
		int cond = _IOC_SIZE(cmd);

		ret_size = cn_mem_copy_d2h((u64)fp,
				GET_COMPAT_PARAM(d2h, copy_d2h, cond, ca),
				GET_COMPAT_PARAM(d2h, copy_d2h, cond, ia),
				GET_COMPAT_PARAM(d2h, copy_d2h, cond, total_size),
				core);

		SET_COMPAT_PARAM(d2h, copy_d2h, cond, residual_size, ret_size);
		if (copy_to_user((void *)arg, (void *)d2h, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
		}
	}

	cn_dev_core_debug(core, "MEM_COPY_D2H  END");
	cn_kfree(d2h);
	return ret;
}

int m_mem_copy_d2d(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *d2d = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!d2d) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "MEM_COPY_D2D BEGIN");
	if (copy_from_user((void *)d2d, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy parameters failed!");
		ret = -EFAULT;
	} else {
		int cond = _IOC_SIZE(cmd);

		ret = cn_mem_copy_d2d((u64)fp,
				(dev_addr_t)GET_COMPAT_PARAM(d2d, copy_d2d, cond, src),
				(dev_addr_t)GET_COMPAT_PARAM(d2d, copy_d2d, cond, dst),
				GET_COMPAT_PARAM(d2d, copy_d2d, cond, size),
				core,
				MEMCPY_D2D_NO_COMPRESS);
		if (unlikely(ret)) {
			cn_dev_core_err(core, "d2d copy failed!");
		}
	}

	cn_dev_core_debug(core, "MEM_COPY_D2D END");
	cn_kfree(d2d);
	return ret;
}

int m_mem_copy_d2d_2d(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *d2d_2d = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!d2d_2d) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "MEM_COPY_D2D_2D BEGIN");
	if (copy_from_user((void *)d2d_2d, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy parameters failed!");
		ret = -EFAULT;
	} else {
		struct mem_copy_d2d_2d_compat_s *p =
			(struct mem_copy_d2d_2d_compat_s *)d2d_2d;

		ret = cn_mem_copy_d2d_2d((u64)fp, (dev_addr_t)p->dst, p->dpitch,
				(dev_addr_t)p->src, p->spitch,
				p->width, p->height, core);
		if (unlikely(ret)) {
			cn_dev_core_err(core, "d2d 2D copy failed!");
		}
	}

	cn_dev_core_debug(core, "MEM_COPY_D2D_2D END");
	cn_kfree(d2d_2d);
	return ret;
}

int m_mem_copy_d2d_3d(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *d2d_3d = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!d2d_3d) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "MEM_COPY_D2D_3D BEGIN");
	if (copy_from_user((void *)d2d_3d, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy parameters failed!");
		ret = -EFAULT;
	} else {
		struct memcpy_d2d_3d_compat *p =
			(struct memcpy_d2d_3d_compat *)d2d_3d;

		ret = cn_mem_copy_d2d_3d((u64)fp, p, core);
		if (unlikely(ret)) {
			cn_dev_core_err(core, "d2d 3D copy failed!");
		}
	}

	cn_dev_core_debug(core, "MEM_COPY_D2D_3D END");
	cn_kfree(d2d_3d);
	return ret;
}

int m_frame_buffer_alloc(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *mm_alloc = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!mm_alloc) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "MEM_ALLOC  BEGIN");
	if (copy_from_user((void *)mm_alloc, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		struct mem_attr mm_attr;
		dev_addr_t dev_vaddr;
		int cond = _IOC_SIZE(cmd);

		mm_attr.tag = (u64)fp;
		mm_attr.size = GET_COMPAT_PARAM(mm_alloc, alloc, cond, size);
		mm_attr.align = GET_COMPAT_PARAM(mm_alloc, alloc, cond, align);
		mm_attr.type = CN_VPU_MEM;
		mm_attr.affinity = GET_COMPAT_PARAM(mm_alloc, alloc, cond, affinity);
		mm_attr.flag = GET_COMPAT_PARAM(mm_alloc, alloc, cond, flag);
		mm_attr.vmid = PF_ID;

		ret = cn_mem_alloc((u64)fp, &dev_vaddr, &mm_attr, core);
		if (ret) {
			cn_dev_core_err(core,
					"framebuffer memory alloc failed(%d -- %#lx).",
					mm_attr.affinity, mm_attr.size);
			cn_kfree(mm_alloc);
			return ret;
		}

		SET_COMPAT_PARAM(mm_alloc, alloc, cond, ret_addr, (__u64)dev_vaddr);
		if (copy_to_user((void *)arg, (void *)mm_alloc, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
		}
	}

	cn_dev_core_debug(core, "MEM_ALLOC  END");
	cn_kfree(mm_alloc);
	return ret;
}

int m_fb_mem_alloc(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *mm_alloc = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!mm_alloc) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "MEM_ALLOC  BEGIN");
	if (copy_from_user((void *)mm_alloc, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		struct mem_attr mm_attr;
		dev_addr_t dev_vaddr;
		int cond = _IOC_SIZE(cmd);

		mm_attr.tag = (u64)fp;
		mm_attr.size = GET_COMPAT_PARAM(mm_alloc, alloc, cond, size);
		mm_attr.align = GET_COMPAT_PARAM(mm_alloc, alloc, cond, align);
		mm_attr.type = CN_VPU_MEM;
		mm_attr.affinity = GET_COMPAT_PARAM(mm_alloc, alloc, cond, affinity);
		mm_attr.flag = GET_COMPAT_PARAM(mm_alloc, alloc, cond, flag);
		mm_attr.vmid = PF_ID;

		ret = cn_mem_alloc((u64)fp, &dev_vaddr, &mm_attr, core);
		if (ret) {
			cn_dev_core_err(core, "fb memory alloc failed(%d -- %#lx).",
					mm_attr.affinity, mm_attr.size);
			cn_kfree(mm_alloc);
			return ret;
		}

		SET_COMPAT_PARAM(mm_alloc, alloc, cond, ret_addr, (__u64)dev_vaddr);
		if (copy_to_user((void *)arg, (void *)mm_alloc, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
		}
	}

	cn_dev_core_debug(core, "MEM_ALLOC  END");
	cn_kfree(mm_alloc);
	return ret;
}

int m_peer_to_peer(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct file *p_file;
	struct cn_core_set *peer_core;
	__u64 src_addr;
	__u64 dst_addr;
	unsigned long count;
	struct fp_priv_data *priv_data;
	void *p2p = NULL;
	int cond = _IOC_SIZE(cmd);

	cn_dev_core_debug(core, "PEER_TO_PEER BEGIN");
	p2p = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);
	if (!p2p) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	if (copy_from_user((void *)p2p, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EINVAL;
		cn_kfree(p2p);
		return ret;
	}

	p_file = udvm_fcheck(GET_COMPAT_PARAM(p2p, copy_p2p, cond, peer_fd));
	if (!p_file) {
		cn_dev_core_err(core, "no p2p open device(%d) file.",
				(int)GET_COMPAT_PARAM(p2p, copy_p2p, cond, peer_fd));
		ret = -EINVAL;
		cn_kfree(p2p);
		return ret;
	}

	priv_data = p_file->private_data;
	peer_core = priv_data->core;

	cn_dev_core_debug(core, "peer open device(%d) name = %s",
			(int)GET_COMPAT_PARAM(p2p, copy_p2p, cond, peer_fd),
			peer_core->node_name);

	if (core == peer_core) {
		ret = -EINVAL;
		cn_kfree(p2p);
		return ret;
	}

	src_addr = GET_COMPAT_PARAM(p2p, copy_p2p, cond, src_addr);
	dst_addr = GET_COMPAT_PARAM(p2p, copy_p2p, cond, dst_addr);
	count = GET_COMPAT_PARAM(p2p, copy_p2p, cond, count);

	ret = cn_mem_dma_p2p(core, peer_core,
			src_addr, (u64)fp, dst_addr,
			(u64)p_file, count);

	if (!ret)
		cn_dev_core_debug(core, "cn_bus_dma_p2p finish");
	else
		cn_dev_core_err(core, "cn_bus_dma_p2p error:%ld", (long)ret);

	cn_kfree(p2p);
	cn_dev_core_debug(core, "PEER_TO_PEER END");
	return ret;
}

int m_peer_able(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct p2p_able_s param;
	struct file *p_file;
	struct cn_core_set *peer_core;
	void *bus_set_src;
	void *bus_set_dst;
	struct fp_priv_data *priv_data;

	ret = -EFAULT;
	if (copy_from_user((void *)&param, (void *)arg, sizeof(param))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		return ret;
	}

	p_file = udvm_fcheck(param.peer_fd);
	if (!p_file) {
		cn_dev_core_err(core,
				"no p2p open device(%d) file.",
				param.peer_fd);
		return ret;
	}

	priv_data = p_file->private_data;
	peer_core = priv_data->core;

	cn_dev_core_debug(core, "peer open device(%d) name = %s",
			param.peer_fd, peer_core->node_name);

	if (cn_core_is_vf(core) || cn_core_is_vf(peer_core)) {
		ret = -EPERM;
		cn_dev_core_err(core, "vf not support p2p");
		return ret;
	}

	bus_set_src = (void *)core->bus_set;
	bus_set_dst = (void *)peer_core->bus_set;

	/* p2p able */
	ret = cn_bus_dma_p2p_able(bus_set_src, bus_set_dst);
	ret = (bus_set_src == bus_set_dst) ? -1 : 0;
	return ret;
}

int m_phy_peer_able(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct p2p_able_s param;
	struct file *p_file;
	struct cn_core_set *peer_core;
	void *bus_set_src;
	void *bus_set_dst;
	struct fp_priv_data *priv_data;

	ret = -EFAULT;
	if (copy_from_user((void *)&param, (void *)arg, sizeof(param))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		return ret;
	}

	p_file = udvm_fcheck(param.peer_fd);
	if (!p_file) {
		cn_dev_core_err(core,
				"no p2p open device(%d) file.",
				param.peer_fd);
		return ret;
	}

	priv_data = p_file->private_data;
	peer_core = priv_data->core;

	cn_dev_core_debug(core, "peer open device(%d) name = %s",
			param.peer_fd, peer_core->node_name);

	if (cn_core_is_vf(core) || cn_core_is_vf(peer_core)) {
		ret = -EPERM;
		cn_dev_core_err(core, "vf not support p2p");
		return ret;
	}

	bus_set_src = (void *)core->bus_set;
	bus_set_dst = (void *)peer_core->bus_set;

	/* p2p able */
	ret = cn_bus_dma_p2p_able(bus_set_src, bus_set_dst);
	ret = (ret <= 0) ? -1 : 0;
	return ret;
}

int m_dma_memset(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *param = NULL;
	int cond = _IOC_SIZE(cmd);

	param = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);
	if (!param) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	if (copy_from_user((void *)param, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from user failed");
		ret = -EFAULT;
		cn_kfree(param);
		return ret;
	}

	ret = cn_mem_dma_memsetD8(core,
			GET_COMPAT_PARAM(param, bar_memset, cond, dev_addr),
			GET_COMPAT_PARAM(param, bar_memset, cond, number),
			GET_COMPAT_PARAM(param, bar_memset, cond, val),
			(u64)fp);
	if (ret)
		cn_dev_core_err(core, "dma memset error");

	cn_kfree(param);
	return ret;
}

int m_dma_memset16(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *param = NULL;
	int cond = _IOC_SIZE(cmd);

	param = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);
	if (!param) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	if (copy_from_user((void *)param, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from user failed");
		ret = -EFAULT;
		cn_kfree(param);
		return ret;
	}

	ret = cn_mem_dma_memsetD16(core,
			GET_COMPAT_PARAM(param, bar_memsetd16, cond, dev_addr),
			GET_COMPAT_PARAM(param, bar_memsetd16, cond, number),
			GET_COMPAT_PARAM(param, bar_memsetd16, cond, val),
			(u64)fp);
	if (ret)
		cn_dev_core_err(core, "dma memset error");

	cn_kfree(param);
	return ret;
}

int m_dma_memset32(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *param = NULL;
	int cond = _IOC_SIZE(cmd);

	param = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);
	if (!param) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	if (copy_from_user((void *)param, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from user failed");
		ret = -EFAULT;
		cn_kfree(param);
		return ret;
	}

	ret = cn_mem_dma_memsetD32(core,
			GET_COMPAT_PARAM(param, bar_memsetd32, cond, dev_addr),
			GET_COMPAT_PARAM(param, bar_memsetd32, cond, number),
			GET_COMPAT_PARAM(param, bar_memsetd32, cond, val),
			(u64)fp);
	if (ret)
		cn_dev_core_err(core, "dma memset error");

	cn_kfree(param);
	return ret;
}

int m_ipcm_get_handle(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_ipcm_handle ipcm_param;

	if (copy_from_user((void *)&ipcm_param, (void *)arg,
				sizeof(struct cn_ipcm_handle))) {
		cn_dev_core_err(core, "copy_from user failed");
		return -EFAULT;
	}

	ret = camb_ipc_shm_get_handle((u64)fp,
			&ipcm_param.handle,
			ipcm_param.dev_vaddr,
			core->mm_set);

	if (ret) {
		cn_dev_core_err(core, "ipc memory get handle failed");
		return ret;
	}

	if (copy_to_user((void *)arg, (void *)&ipcm_param,
				sizeof(struct cn_ipcm_handle))) {
		cn_dev_core_err(core, "copy_to_user failed.");
		ret = -EFAULT;
	}
	return ret;
}

int m_ipcm_open_handle(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_ipcm_handle ipcm_param;

	if (copy_from_user((void *)&ipcm_param, (void *)arg,
				sizeof(struct cn_ipcm_handle))) {
		cn_dev_core_err(core, "copy_from user failed");
		return -EFAULT;
	}

	ret = camb_ipc_shm_open_handle((u64)fp, ipcm_param.handle,
			&ipcm_param.dev_vaddr, core->mm_set);

	if (ret) {
		cn_dev_core_err(core, "ipc memory open handle failed");
		return ret;
	}

	if (copy_to_user((void *)arg, (void *)&ipcm_param,
				sizeof(struct cn_ipcm_handle))) {
		cn_dev_core_err(core, "copy_to_user failed.");
		ret = -EFAULT;
	}
	return ret;
}

int m_ipcm_close_handle(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_ipcm_handle ipcm_param;

	if (copy_from_user((void *)&ipcm_param, (void *)arg,
				sizeof(struct cn_ipcm_handle))) {
		cn_dev_core_err(core, "copy_from user failed");
		return -EFAULT;
	}

	ret = camb_ipc_shm_close_handle((u64)fp,
			ipcm_param.dev_vaddr, core->mm_set);

	if (ret) {
		cn_dev_core_err(core,
				"ipc memory close handle failed");
		return ret;
	}
	return ret;
}

int m_mdr_alloc(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *mm_alloc = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!mm_alloc) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "MEM_ALLOC  BEGIN");
	if (copy_from_user((void *)mm_alloc, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		struct mem_attr mm_attr;
		dev_addr_t dev_vaddr;
		int cond = _IOC_SIZE(cmd);

		mm_attr.tag = (u64)fp;
		mm_attr.size = GET_COMPAT_PARAM(mm_alloc, alloc, cond, size);
		mm_attr.align = GET_COMPAT_PARAM(mm_alloc, alloc, cond, align);
		mm_attr.type = CN_MDR_MEM;
		mm_attr.affinity = GET_COMPAT_PARAM(mm_alloc, alloc, cond, affinity);
		mm_attr.flag = GET_COMPAT_PARAM(mm_alloc, alloc, cond, flag);
		mm_attr.vmid = PF_ID;

		ret = cn_mdr_alloc((u64)fp, &dev_vaddr, &mm_attr, core);
		if (ret) {
			cn_dev_core_err(core,
					"global memory alloc failed(%d -- %#lx).",
					mm_attr.affinity, mm_attr.size);
			cn_kfree(mm_alloc);
			return ret;
		}

		SET_COMPAT_PARAM(mm_alloc, alloc, cond, ret_addr, (__u64)dev_vaddr);
		if (copy_to_user((void *)arg, (void *)mm_alloc, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
		}
	}

	cn_dev_core_debug(core, "MEM_ALLOC  END");
	cn_kfree(mm_alloc);
	return ret;
}

int m_enable_memcheck(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_mem_check memcheck;

	cn_dev_core_debug(core, "MEMCHECK ENABLE BEGIN");
	if (copy_from_user((void *)&memcheck, (void *)arg,
				sizeof(struct cn_mem_check))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		return -EFAULT;
	}

	ret = camb_mem_enable_memcheck((u64)fp, memcheck.magic, core->mm_set);
	if (ret) {
		cn_dev_core_err(core, "enable memcheck error!\n");
		return ret;
	}

	cn_dev_core_debug(core, "MEMCHECK ENABLE END");
	return ret;
}

int m_get_mem_range(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_get_mem_range get_mem_range;

	cn_dev_core_debug(core, "GET_MEM_RANGE BEGIN");
	if (copy_from_user((void *)&get_mem_range, (void *)arg,
				sizeof(struct cn_get_mem_range))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		get_mem_range.status =
			camb_get_mem_range((u64)fp, get_mem_range.dev_vaddr,
					(dev_addr_t *)&get_mem_range.vaddr_base,
					(ssize_t *)&get_mem_range.vaddr_size,
					core->mm_set);

		if (copy_to_user((void *)arg, (void *)&get_mem_range,
					sizeof(struct cn_get_mem_range))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
		}
	}

	cn_dev_core_debug(core, "WHITELIST_MEM_COPY_H2D END");
	return ret;
}

int m_mem_bar_copy_h2d(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct mem_bar_copy_h2d_s h2d;

	cn_dev_core_debug(core, "MEM_BAR_COPY_H2D  BEGIN");
	memset(&h2d, 0, sizeof(h2d));
	if (copy_from_user((void *)&h2d, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		ret = cn_mem_bar_copy_h2d((u64)fp, h2d.ia, h2d.ca,
				h2d.total_size, core);
	}
	cn_dev_core_debug(core, "MEM_BAR_COPY_H2D  END");
	return ret;
}

int m_mem_bar_copy_d2h(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct mem_bar_copy_d2h_s d2h;

	if (core->device_id == MLUID_370) {
		cn_dev_core_err(core, "mlu370 don't support MEM_BAR_COPY_D2H");
		ret = -EPERM;
		return ret;
	}

	cn_dev_core_debug(core, "MEM_BAR_COPY_D2H BEGIN");
	memset(&d2h, 0, sizeof(d2h));
	if (copy_from_user((void *)&d2h, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		ret = cn_mem_bar_copy_d2h((u64)fp, d2h.ia, d2h.ca,
				d2h.total_size, core);
	}
	cn_dev_core_debug(core, "MEM_BAR_COPY_D2H  END");
	return ret;
}

int m_mem_set_prot(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct mem_set_prot_s mem_set_prot;

	if (copy_from_user((void *)&mem_set_prot, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {

		ret = cn_mem_set_prot((u64)fp, (dev_addr_t)mem_set_prot.dev_vaddr,
				mem_set_prot.size,
				mem_set_prot.prot_flag,
				core);
		if (IS_ERR_VALUE((long)ret)) {
			cn_dev_core_err(core, "mem set prot failed.");
			return ret;
		}
	}
	cn_dev_core_debug(core, "MEM_SET_PROT END");
	return ret;
}

int m_prt_user_trace(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_user_trace *trace_info;

	trace_info = cn_kzalloc(sizeof(struct cn_user_trace), GFP_KERNEL);
	if (!trace_info) {
		cn_dev_core_err(core, "kzalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	if (copy_from_user((void *)trace_info, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		char *strings;
		int i = 0;

		strings = cn_kzalloc(trace_info->size, GFP_KERNEL);
		if (!strings) {
			cn_dev_core_err(core, "kzalloc error.");
			cn_kfree(trace_info);
			ret = -ENOMEM;
			return ret;
		}

		mutex_lock(&core->user_trace_lock);
		cn_get_absolute_path(core, current);
		for (i = 0; i < trace_info->row; i++) {
			if (copy_from_user((void *)strings,
						(void *)trace_info->strings[i],
						trace_info->size)) {
				cn_dev_core_err(core, "copy_from_user failed.");
				ret = -EFAULT;
				break;
			}

			cn_dev_core_info(core, "%s", strings);
		}
		mutex_unlock(&core->user_trace_lock);
		cn_kfree(strings);
	}
	cn_kfree(trace_info);
	cn_dev_core_debug(core, "M_PRT_USER_TRACE END");
	return ret;
}

int m_prt_user_trace_enable(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	if (!core->user_trace_enable) {
		ret = -EPERM;
	}
	return ret;
}

#ifdef PEER_FREE_TEST
int m_inbd_shm_alloc_test(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *mm_alloc = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!mm_alloc) {
		cn_dev_core_err(core, "kmalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "INBD_SHM_ALLOC_TEST BEGIN");
	if (copy_from_user((void *)mm_alloc, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		struct mem_attr mm_attr;
		host_addr_t host_vaddr;
		dev_addr_t dev_vaddr;
		int cond = _IOC_SIZE(cmd);

		mm_attr.tag = (u64)fp;
		mm_attr.size = GET_COMPAT_PARAM(mm_alloc, alloc, cond, size);
		mm_attr.align = GET_COMPAT_PARAM(mm_alloc, alloc, cond, align);
		mm_attr.type = CN_IPU_MEM;
		mm_attr.affinity = GET_COMPAT_PARAM(mm_alloc, alloc, cond, affinity);
		mm_attr.flag = GET_COMPAT_PARAM(mm_alloc, alloc, cond, flag);
		mm_attr.vmid = PF_ID;

		ret = cn_device_share_mem_alloc(0, &host_vaddr, &dev_vaddr,
				mm_attr.size, core);
		if (ret) {
			cn_dev_core_err(core, "device share memory alloc failed(%#lx).",
					mm_attr.size);
			cn_kfree(mm_alloc);
			return ret;
		}

		SET_COMPAT_PARAM(mm_alloc, alloc, cond, ret_addr, (__u64)dev_vaddr);
		if (copy_to_user((void *)arg, (void *)mm_alloc, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
		}
	}

	cn_dev_core_debug(core, "INBD_SHM_ALLOC_TEST END");
	cn_kfree(mm_alloc);
	return ret;
}

int m_outbd_shm_alloc_test(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	void *mm_alloc = cn_kzalloc(_IOC_SIZE(cmd), GFP_KERNEL);

	if (!mm_alloc) {
		cn_dev_core_err(core, "kmalloc error.");
		ret = -ENOMEM;
		return ret;
	}

	cn_dev_core_debug(core, "OUTBD_SHM_ALLOC_TEST BEGIN");
	if (copy_from_user((void *)mm_alloc, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		struct mem_attr mm_attr;
		host_addr_t host_vaddr;
		dev_addr_t dev_vaddr;
		int cond = _IOC_SIZE(cmd);

		mm_attr.tag = (u64)fp;
		mm_attr.size = GET_COMPAT_PARAM(mm_alloc, alloc, cond, size);
		mm_attr.align = GET_COMPAT_PARAM(mm_alloc, alloc, cond, align);
		mm_attr.type = CN_IPU_MEM;
		mm_attr.affinity = GET_COMPAT_PARAM(mm_alloc, alloc, cond, affinity);
		mm_attr.flag = GET_COMPAT_PARAM(mm_alloc, alloc, cond, flag);
		mm_attr.vmid = PF_ID;

		ret = cn_host_share_mem_alloc(0, &host_vaddr, &dev_vaddr,
				mm_attr.size, core);
		if (ret) {
			cn_dev_core_err(core, "device share memory alloc failed(%#lx).",
					mm_attr.size);
			cn_kfree(mm_alloc);
			return ret;
		}

		SET_COMPAT_PARAM(mm_alloc, alloc, cond, ret_addr, (__u64)dev_vaddr);
		if (copy_to_user((void *)arg, (void *)mm_alloc, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			ret = -EFAULT;
		}
	}

	cn_dev_core_debug(core, "OUTBD_SHM_ALLOC_TEST END");
	cn_kfree(mm_alloc);
	return ret;
}

int m_peer_free_test(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct mem_merge_param_s mm_merge;
	__u64 *virt_addr = NULL;

	cn_dev_core_debug(core, "PEER_FREE_TEST BEGIN");
	if (copy_from_user((void *)&mm_merge, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		virt_addr = cn_kcalloc(mm_merge.cnt, sizeof(__u64), GFP_KERNEL);
		if (!virt_addr) {
			cn_dev_core_err(core, "kcalloc error.");
			ret = -ENOMEM;
			return ret;
		}

		if (copy_from_user((void *)virt_addr,
					(void *)mm_merge.virt_addrs,
					sizeof(__u64)*mm_merge.cnt)) {
			cn_dev_core_err(core, "copy_from_user failed.");
			ret = -EFAULT;
			cn_kfree(virt_addr);
			return ret;
		}

		if (mm_merge.cnt < 2) {
			cn_dev_core_err(core,
					"memory merge count(%d) < 2.",
					mm_merge.cnt);
			ret = -EINVAL;
			cn_kfree(virt_addr);
			return ret;
		}

		ret = camb_peer_free_test((u64)fp,
				mm_merge.merged_addr,
				virt_addr, mm_merge.cnt,
				core);
		if (ret) {
			cn_dev_core_err(core, "mem_merge failed.");
			cn_kfree(virt_addr);
			return ret;
		}

		if (copy_to_user((void *)arg, (void *)&mm_merge, _IOC_SIZE(cmd))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			cn_kfree(virt_addr);
			ret = -EFAULT;
			return ret;
		}

		cn_kfree(virt_addr);
	}

	cn_dev_core_debug(core, "PEER_FREE_TEST END");
	return ret;
}
#endif	//#ifdef PEER_FREE_TEST

int m_mem_get_uva(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct mem_get_uva_s get_uva = {0};
	int cond = _IOC_SIZE(cmd);

	WARN_ON(cond != sizeof(get_uva));

	cn_dev_core_debug(core, "MEM_GET  BEGIN");

	if (copy_from_user((void *)&get_uva, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "get uva copy_from_user failed.");
		ret = -EFAULT;
		return ret;
	}

	if (get_uva.version != 0) {
		cn_dev_core_err(core, "the version of get uva is error.");
		ret = -EINVAL;
		return ret;
	}

	ret = cn_mem_uva_get((u64)fp, get_uva.iova, get_uva.size,
			&get_uva.uva, get_uva.attr, core);
	if (IS_ERR_VALUE((long)ret)) {
		cn_dev_core_err(core, "get uva failed.");
		return ret;
	}

	if (copy_to_user((void *)arg, (void *)&get_uva, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "get uva copy_to_user failed.");
		ret = -EFAULT;
	}
	return ret;
}

int m_mem_put_uva(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct mem_put_uva_s put_uva = {0};
	int cond = _IOC_SIZE(cmd);

	WARN_ON(cond != sizeof(put_uva));

	cn_dev_core_debug(core, "MEM_PUT  BEGIN");

	if (copy_from_user((void *)&put_uva, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "put uva copy_from_user failed.");
		ret = -EFAULT;
		return ret;
	}

	if (put_uva.version != 0) {
		cn_dev_core_err(core, "the version of get uva is error.");
		ret = -EINVAL;
		return ret;
	}

	ret = cn_mem_uva_put((u64)fp, put_uva.uva, put_uva.size, put_uva.iova, put_uva.attr, core);
	if (IS_ERR_VALUE((long)ret)) {
		cn_dev_core_err(core, "put uva failed.");
		return ret;
	}

	if (copy_to_user((void *)arg, (void *)&put_uva, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "put uva copy_to_user failed.");
		ret = -EFAULT;
	}
	return ret;
}

int m_mem_get_ipu_resv_mem(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct mem_get_ipu_resv_s ipu_addr;
	struct ipu_mem_addr_get ipu_mem_addr;

	cn_dev_core_debug(core, "IPU_MEM_GET BEGIN");

	if (unlikely(camb_mem_lpm_get(fp, core))) {
		cn_dev_core_err(core, "mem get lpm failed!");
		return -EINVAL;
	}

	if (copy_from_user((void *)&ipu_addr, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "get ipu addr copy_from_user failed.");
		ret = -EFAULT;
	}

	ret = camb_mem_get_ipu_resv((u64)fp, &ipu_mem_addr, core->mm_set);
	if (IS_ERR_VALUE((long)ret)) {
		cn_dev_core_err(core, "get ipu addr failed.");
		return ret;
	}
	ipu_addr.ipu_resv_addr = ipu_mem_addr.resv_iova;
	ipu_addr.group_off = ipu_mem_addr.group_offset;
	ipu_addr.core_off = ipu_mem_addr.core_offset;
	cn_dev_core_debug(core, "debug %lx %lx %lx debug2 %lx %lx %lx.",
			(unsigned long)ipu_addr.ipu_resv_addr, (unsigned long)ipu_addr.group_off,
			(unsigned long)ipu_addr.core_off, ipu_mem_addr.resv_iova,
			ipu_mem_addr.group_offset,
			ipu_mem_addr.core_offset);

	if (copy_to_user((void *)arg, (void *)&ipu_addr, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "get ipu addr copy_to_user failed.");
		ret = -EFAULT;
	}
	return ret;
}

int m_mem_kernel_test(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	ret = cn_mem_kernel_test(arg);
	return ret;
}

int m_pcie_dob_alloc(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct dob_alloc_t dob_alloc;

	if (sizeof(dob_alloc) != _IOC_SIZE(cmd)) {
		cn_dev_core_err(core, "user ioctl dob alloc struct error.");
		ret = -EFAULT;
		return ret;
	}
	cn_dev_core_debug(core, "DOB_ALLOC  BEGIN");
	if (copy_from_user((void *)&dob_alloc, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	}
	cn_dev_core_debug(core, "DOB_ALLOC  END");
	return ret;
}

int m_pcie_dob_free(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct dob_free_t dob_free;

	if (sizeof(dob_free) != _IOC_SIZE(cmd)) {
		cn_dev_core_err(core, "user ioctl dob free struct error.");
		ret = -EFAULT;
		return ret;
	}
	cn_dev_core_debug(core, "DOB_FREE  BEGIN");
	if (copy_from_user((void *)&dob_free, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	}
	cn_dev_core_debug(core, "DOB_FREE  END");
	return ret;
}

int m_pcie_dob_write(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct dob_write_t dob_write;

	if (sizeof(dob_write) != _IOC_SIZE(cmd)) {
		cn_dev_core_err(core, "user ioctl dob write struct error.");
		ret = -EFAULT;
		return ret;
	}
	cn_dev_core_debug(core, "DOB_WRITE  BEGIN");
	if (copy_from_user((void *)&dob_write, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		if (dob_write.host_kva)
			if (copy_from_user((void *)dob_write.host_kva,
						dob_write.buf, dob_write.size)) {
				cn_dev_core_err(core, "copy_from_user failed.");
				ret = -EFAULT;
			}
	}
	cn_dev_core_debug(core, "DOB_WRITE  END");
	return ret;
}

int m_pcie_dob_read(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct dob_read_t dob_read;

	if (sizeof(dob_read) != _IOC_SIZE(cmd)) {
		cn_dev_core_err(core, "user ioctl dob read struct error.");
		ret = -EFAULT;
		return ret;
	}
	cn_dev_core_debug(core, "DOB_READ  BEGIN");
	if (copy_from_user((void *)&dob_read, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		if (dob_read.host_kva)
			if (copy_to_user(dob_read.buf,
						(void *)dob_read.host_kva, dob_read.size)) {
				cn_dev_core_err(core, "copy_to_user failed.");
				ret = -EFAULT;
			}
	}
	cn_dev_core_debug(core, "DOB_READ  END");
	return ret;
}

int m_pcie_dob_rpc_write(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct dob_write_t dob_write;
	struct dob_set_t dob_set;

	if (sizeof(dob_write) != _IOC_SIZE(cmd)) {
		cn_dev_core_err(core, "user ioctl dob write struct error.");
		ret = -EFAULT;
		return ret;
	}
	cn_dev_core_debug(core, "DOB_RPC_WRITE  BEGIN");
	if (copy_from_user((void *)&dob_write, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		dob_set.dev_va = dob_write.device_va;
		dob_set.size = dob_write.size;
		dob_set.data = dob_write.data;
		if (dob_set.dev_va) {
			ret = data_outbound_rpc_write(core, &dob_set);
			if (ret)
				cn_dev_core_err(core, "dob rpc write failed.");
		}
	}
	cn_dev_core_debug(core, "DOB_RPC_WRITE  END");
	return ret;
}

int m_pcie_dob_rpc_read(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct dob_read_t dob_read;
	struct dob_set_t dob_set;

	if (sizeof(dob_read) != _IOC_SIZE(cmd)) {
		cn_dev_core_err(core, "user ioctl dob read struct error.");
		ret = -EFAULT;
		return ret;
	}
	cn_dev_core_debug(core, "DOB_RPC_READ  BEGIN");
	if (copy_from_user((void *)&dob_read, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		dob_set.dev_va = dob_read.device_va;
		dob_set.size = dob_read.size;
		dob_set.data = dob_read.data;
		if (dob_set.dev_va) {
			ret = data_outbound_rpc_read(core, &dob_set);
			if (ret)
				cn_dev_core_err(core, "dob rpc read failed.");
		}
	}
	cn_dev_core_debug(core, "DOB_RPC_READ  END");
	return ret;
}

int m_pcie_dob_rpc_open(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	ret = proc_open_channel(core);
	return ret;
}

int m_pcie_dob_rpc_close(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	proc_close_channel(core);
	return ret;
}

int m_pcie_sram_rpc_write(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct sram_write_t sram_write;
	struct sram_set_t sram_set;

	if (sizeof(sram_write) != _IOC_SIZE(cmd)) {
		cn_dev_core_err(core, "user ioctl sram write struct error.");
		ret = -EFAULT;
		return ret;
	}
	cn_dev_core_debug(core, "SRAM_RPC_WRITE  BEGIN");
	if (copy_from_user((void *)&sram_write, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		sram_set.dev_va = sram_write.device_va;
		sram_set.size = sram_write.size;
		sram_set.data = sram_write.data;
		if (sram_set.dev_va) {
			ret = sram_rpc_write(core, &sram_set);
			if (ret)
				cn_dev_core_err(core, "sram rpc write failed.");
		}
	}
	cn_dev_core_debug(core, "SRAM_RPC_WRITE  END");
	return ret;
}

int m_pcie_sram_rpc_read(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct sram_read_t sram_read;
	struct sram_set_t sram_set;

	if (sizeof(sram_read) != _IOC_SIZE(cmd)) {
		cn_dev_core_err(core, "user ioctl sram read struct error.");
		ret = -EFAULT;
		return ret;
	}
	cn_dev_core_debug(core, "SRAM_RPC_READ  BEGIN");
	if (copy_from_user((void *)&sram_read, (void *)arg, _IOC_SIZE(cmd))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		sram_set.dev_va = sram_read.device_va;
		sram_set.size = sram_read.size;
		sram_set.data = sram_read.data;
		if (sram_set.dev_va) {
			ret = sram_rpc_read(core, &sram_set);
			if (ret)
				cn_dev_core_err(core, "sram rpc read failed.");
		}
	}
	cn_dev_core_debug(core, "SRAM_RPC_READ  END");
	return ret;
}

typedef int (*mm_ioctl_func)(struct file *fp, unsigned long arg,
		unsigned int cmd, struct cn_core_set *core);

static const struct {
	mm_ioctl_func funcs;
	u64 flags;
} mm_funcs[MM_MAX_NR_COUNT] = {
	[_M_MEM_ALLOC] = {m_mem_alloc, 0},
	[_M_MEM_FREE] = {m_mem_free, 0},
	[_M_MEM_MERGE] = {m_mem_merge, 0},
	[_M_MEM_COPY_H2D] = {m_mem_copy_h2d, 0},
	[_M_MEM_COPY_D2H] = {m_mem_copy_d2h, 0},
	[_M_MEM_COPY_D2D] = {m_mem_copy_d2d, 0},
	[_M_MEM_COPY_D2D_2D] = {m_mem_copy_d2d_2d, 0},
	[_M_MEM_COPY_D2D_3D] = {m_mem_copy_d2d_3d, 0},
	[_M_FRAME_BUFFER_ALLOC] = {m_frame_buffer_alloc, 0},
	[_M_FB_MEM_ALLOC] = {m_fb_mem_alloc, 0},
	[_M_PEER_TO_PEER] = {m_peer_to_peer, 0},
	[_M_PEER_ABLE] = {m_peer_able, 0},
	[_M_PHY_PEER_ABLE] = {m_phy_peer_able, 0},
	[_M_DMA_MEMSET] = {m_dma_memset, 0},
	[_M_DMA_MEMSETD16] = {m_dma_memset16, 0},
	[_M_DMA_MEMSETD32] = {m_dma_memset32, 0},
	[_M_IPCM_GET_HANDLE] = {m_ipcm_get_handle, 0},
	[_M_IPCM_OPEN_HANDLE] = {m_ipcm_open_handle, 0},
	[_M_IPCM_CLOSE_HANDLE] = {m_ipcm_close_handle, 0},
	[_M_MDR_ALLOC] = {m_mdr_alloc, 0},
	[_M_ENABLE_MEMCHECK] = {m_enable_memcheck, 0},
	[_M_GET_MEM_RANGE] = {m_get_mem_range, 0},
	[_M_MEM_BAR_COPY_H2D] = {m_mem_bar_copy_h2d, 0},
	[_M_MEM_BAR_COPY_D2H] = {m_mem_bar_copy_d2h, 0},
	[_M_MEM_SET_PROT] = {m_mem_set_prot, 0},
	[_M_PRT_USER_TRACE] = {m_prt_user_trace, 0},
	[_M_PRT_USER_TRACE_ENABLE] = {m_prt_user_trace_enable, 0},
#ifdef PEER_FREE_TEST
	[_M_INBD_SHM_ALLOC_TEST] = {m_inbd_shm_alloc_test, 0},
	[_M_OUTBD_SHM_ALLOC_TEST] = {m_outbd_shm_alloc_test, 0},
	[_M_PEER_FREE_TEST] = {m_peer_free_test, 0},
#endif	//#ifdef PEER_FREE_TEST
	[_M_MEM_GET_UVA] = {m_mem_get_uva, 0},
	[_M_MEM_PUT_UVA] = {m_mem_put_uva, 0},
	[_M_MEM_GET_IPU_RESV_MEM] = {m_mem_get_ipu_resv_mem, 0},
	[_M_MEM_KERNEL_TEST] = {m_mem_kernel_test, 0},
	[_M_PCIE_DOB_ALLOC] = {m_pcie_dob_alloc, 0},
	[_M_PCIE_DOB_FREE] = {m_pcie_dob_free, 0},
	[_M_PCIE_DOB_WRITE] = {m_pcie_dob_write, 0},
	[_M_PCIE_DOB_READ] = {m_pcie_dob_read, 0},
	[_M_PCIE_DOB_RPC_WRITE] = {m_pcie_dob_rpc_write, 0},
	[_M_PCIE_DOB_RPC_READ] = {m_pcie_dob_rpc_read, 0},
	[_M_PCIE_DOB_RPC_OPEN] = {m_pcie_dob_rpc_open, 0},
	[_M_PCIE_DOB_RPC_CLOSE] = {m_pcie_dob_rpc_close, 0},
	[_M_PCIE_SRAM_RPC_WRITE] = {m_pcie_sram_rpc_write, 0},
	[_M_PCIE_SRAM_RPC_READ] = {m_pcie_sram_rpc_read, 0},
};

long cn_mm_ioctl(void *fp, struct cn_core_set *core, unsigned int cmd,
		unsigned long arg)
{
	long ret = 0;
	unsigned int ioc_nr = _IOC_NR(cmd);

	if (mm_funcs[ioc_nr].funcs) {
		ret = mm_funcs[ioc_nr].funcs(fp, arg, cmd, core);
	} else {
		cn_dev_core_err(core, "IOCTRL command# %d is invalid!", ioc_nr);
		ret = -EINVAL;
	}

	return ret;
}
