/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/file.h>
#include <linux/semaphore.h>
#include <linux/idr.h>

#include "asm-generic/errno-base.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_monitor.h"
#include "cndrv_mm.h"
#include "camb_mm.h"
#include "camb_linear_remap.h"
#include "camb_mm_compat.h"
#include "camb_pinned_mem.h"
#include "camb_ob.h"

#include "cndrv_udvm_usr.h" /* ioctl command and structure */
#include "cndrv_udvm.h"     /* udvm api and structure used and called by other modules */
#include "camb_udvm.h"     /* udvm api and structure used and called by memory modules */
#include "camb_vmm.h"
#include "cndrv_ext.h"
#include "camb_trace.h"
#include "camb_cp.h"
#include "linux/gfp.h"
#include "linux/pid.h"

bool fp_is_udvm(struct file *fp)
{
	return file_is_cndev(fp);
}

static int udvm_check_devfp_is_registered(struct file *devfp, struct file *fp);

int udvm_camb_kref_get(struct mapinfo **ppminfo, u64 *ptag, dev_addr_t udvm_addrs, struct cn_mm_set *mm_set,
		int (*camb_kref_get_func)(u64 tag, dev_addr_t device_vaddr, struct mapinfo **ppminfo,
			struct cn_mm_set *mm_set))
{
	struct udvm_priv_data *udvm = NULL, *tmp = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	u64 tag = 0;

	if (addr_is_public(udvm_addrs)) {
		*ptag = tag;
		return camb_kref_get_func(tag, udvm_addrs, ppminfo, mm_set);
	}

	spin_lock(&udvm_set->udvm_lock);
	list_for_each_entry_safe(udvm, tmp, &udvm_set->udvm_head, unode) {
		tag = udvm->tag;
		if (!camb_kref_get_func(tag, udvm_addrs, ppminfo, mm_set)) {
			spin_unlock(&udvm_set->udvm_lock);
			*ptag = tag;
			return 0;
		}
	}
	spin_unlock(&udvm_set->udvm_lock);

	cn_dev_err("addrsss:%#llx is invalid\n", udvm_addrs);
	return -ENXIO;
}

struct udvm_priv_data *get_udvm_priv_data(struct file *fp)
{
	return (struct udvm_priv_data *)cndev_get_udvm_priv(fp);
}

/** uva address decode/encode interface **/
dev_addr_t set_udvm_address(int index, dev_addr_t addr, int type)
{
	addr &= MLU_VIRT_ADDRESS_MASK;

	addr |= (index & MLU_CARD_IDX_MASK) << MLU_CARD_IDX_SHIFT;
	addr |= (type & MLU_ADDRESS_MAGIC_MASK) << MLU_ADDRESS_MAGIC_SHIFT;

	return addr;
}

dev_addr_t udvm_get_iova_from_addr(dev_addr_t udvm_address)
{
	return (udvm_address & MLU_VIRT_ADDRESS_MASK);
}
EXPORT_SYMBOL(udvm_get_iova_from_addr);

dev_addr_t udvm_get_head_from_addr(dev_addr_t udvm_address)
{
	return (udvm_address & (~MLU_VIRT_ADDRESS_MASK));
}
EXPORT_SYMBOL(udvm_get_head_from_addr);

static int __get_cardid(struct file *fp, dev_addr_t udvm_address)
{
#ifdef CONFIG_CNDRV_EDGE
	return 0;
#else
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct udvm_priv_data *udvm = NULL;
	struct mapinfo *pminfo = NULL;

	if (!addr_is_udvm(udvm_address))
		return -EINVAL;

	if (addr_is_vmm(udvm_address)) {
		if (fp == NULL) {
			spin_lock(&udvm_set->udvm_lock);
			list_for_each_entry(udvm, &udvm_set->udvm_head, unode) {
				fp = (struct file *)udvm->tag;
				pminfo = search_mapinfo_with_fp(fp, udvm_address, NULL);
				if (!IS_ERR_OR_NULL(pminfo))
					break;
			}
			spin_unlock(&udvm_set->udvm_lock);

			return IS_ERR_OR_NULL(pminfo) ? -EINVAL : get_index_with_mmset(pminfo->mm_set);
		} else {
			pminfo = search_mapinfo_with_fp(fp, udvm_address, NULL);
			if (IS_ERR_OR_NULL(pminfo))
				return -EINVAL;

			return get_index_with_mmset(pminfo->mm_set);
		}
	} else {
		return __parse_address2index(udvm_address);
	}
#endif
}

int udvm_get_cardid_from_addr(dev_addr_t udvm_address)
{
	return addr_is_udvm(udvm_address) ? __get_cardid(NULL, udvm_address) : -ENXIO;
}
EXPORT_SYMBOL(udvm_get_cardid_from_addr);

int udvm_get_address_magic(dev_addr_t udvm_addr)
{
	return (udvm_addr >> MLU_ADDRESS_MAGIC_SHIFT) & MLU_ADDRESS_MAGIC_MASK;
}

bool addr_is_udvm(dev_addr_t address)
{
	address &= UDVM_TYPE_MASK;
	return (address != UDVM_TYPE_MASK) && (address != 0x0);
}
EXPORT_SYMBOL(addr_is_udvm);

/* It is ugly here. Because of the permission for media memory accessed in
 * the ai context, it is using the hard code here. */
bool addr_is_export(dev_addr_t address)
{
	address = (address >> MLU_ADDRESS_MAGIC_SHIFT) & MLU_ADDRESS_MAGIC_MASK;
	if (address == 0xFF || address == 0xFE) {
		return true;
	} else {
		return false;
	}
}

#ifdef CONFIG_CNDRV_EDGE
bool addr_is_public(dev_addr_t address)
{
	address = (address >> MLU_ADDRESS_MAGIC_SHIFT) & MLU_ADDRESS_MAGIC_MASK;

	return (address == UDVM_ADDR_PUBLIC);
}
#else
bool addr_is_public(dev_addr_t address)
{
	return false;
}
#endif

bool addr_is_vmm(dev_addr_t address)
{
	address = (address >> MLU_ADDRESS_MAGIC_SHIFT) & MLU_ADDRESS_MAGIC_MASK;

	return (address == UDVM_ADDR_VMM);
}

static struct cn_mm_set *
__get_mmset(struct file *fp, dev_addr_t udvm_addr)
{
	int index = __get_cardid(fp, udvm_addr);

	if (index < 0)
		return NULL;

	return __get_mmset_with_index(index);
}

int get_index_with_mmset(void *mmset)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mmset;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	return core->idx;
}

static inline void *__get_core_with_devfp(struct file *devfp)
{
	struct fp_priv_data *priv_data = NULL;
	if (!fp_is_udvm(devfp)) {
		priv_data = (struct fp_priv_data *)devfp->private_data;
		return (priv_data == NULL) ? NULL : priv_data->core;
	} else {
		return NULL;
	}
}

static inline int __get_index_with_devfp(struct file *devfp)
{
	struct cn_core_set *core = __get_core_with_devfp(devfp);
	return (core == NULL) ? -EINVAL : core->idx;
}

static inline void *__get_mmset_with_devfp(struct file *devfp)
{
	struct cn_core_set *core = __get_core_with_devfp(devfp);
	return (core == NULL) ? NULL : core->mm_set;
}

static int
udvm_ioctl_mem_alloc(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_alloc_s params;
	struct mem_attr mm_attr;
	struct file *devfp = NULL;
	struct cn_mm_set *mm_set = NULL;
	dev_addr_t udvm_addr = 0UL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	devfp = udvm_fget(params.dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) goto exit;

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	if ((mm_set->devid == MLUID_590 || mm_set->devid == MLUID_590V ||
		mm_set->devid == MLUID_580 || mm_set->devid == MLUID_580V ||
		mm_set->devid == MLUID_590_DEV) && params.type == CN_VPU_MEM) {
		ret = -ERROR_UDVM_NOT_SUPPORTED;
		goto exit;
	}

	mm_attr.tag      = (u64)devfp;
	mm_attr.size     = params.size;
	mm_attr.align    = params.align;
	mm_attr.type     = params.type;
	mm_attr.affinity = params.affinity;
	mm_attr.flag     = params.flag;
	mm_attr.vmid     = PF_ID;
	memset(mm_attr.name, '\0', EXT_NAME_SIZE);

	if (mm_attr.type == CN_MDR_MEM)
		ret = cn_mdr_alloc((u64)devfp, &udvm_addr, &mm_attr, mm_set->core);
	else
		ret = cn_mem_alloc((u64)devfp, &udvm_addr, &mm_attr, mm_set->core);

	if (!ret) {
		params.udvm_addr = udvm_addr;
	}

exit:
	if (devfp)
		udvm_fput(devfp);

	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_mem_perf_alloc(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_perf_alloc_s params;
	struct mem_attr mm_attr = {};
	struct mem_perf_attr perf_attr;
	struct file *devfp = NULL;
	struct cn_mm_set *mm_set = NULL;
	dev_addr_t udvm_addr = 0UL;
	int name_len;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	devfp = udvm_fget(params.dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret)
		goto exit;

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	if ((mm_set->devid == MLUID_590 || mm_set->devid == MLUID_590V ||
			mm_set->devid == MLUID_580 || mm_set->devid == MLUID_580V ||
			mm_set->devid == MLUID_590_DEV) && params.type == CN_VPU_MEM) {
		ret = -ERROR_UDVM_NOT_SUPPORTED;
		goto exit;
	}

	mm_attr.tag      = (u64)devfp;
	mm_attr.size     = params.size;
	mm_attr.align    = params.align;
	mm_attr.type     = params.type;
	mm_attr.affinity = params.affinity;
	mm_attr.flag     = params.flag;
	mm_attr.vmid     = PF_ID;

	name_len = strlen(params.name);
	if (name_len == 0) {
		strncpy(mm_attr.name, EXT_ANONYMOUS_NAME, strlen(EXT_ANONYMOUS_NAME));
		mm_attr.name[strlen(EXT_ANONYMOUS_NAME)] = '\0';
	} else {
		strncpy(mm_attr.name, params.name, name_len);
		mm_attr.name[name_len] = '\0';
	}

	perf_attr.attr = mm_attr;
	perf_attr.context_id = params.context_id;
	perf_attr.correlation_id = params.correlation_id;

	if (mm_attr.type == CN_MDR_MEM)
		ret = cn_mdr_alloc((u64)devfp, &udvm_addr, &mm_attr, mm_set->core);
	else
		ret = cn_mem_perf_alloc((u64)devfp, &udvm_addr, &mm_attr, &perf_attr, mm_set->core);

	if (!ret) {
		params.udvm_addr = udvm_addr;
	}

exit:
	if (devfp)
		udvm_fput(devfp);

	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_mem_free(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_free_s params;
	struct cn_mm_set *mm_set = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (!addr_is_udvm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	if (addr_is_vmm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	mm_set = __get_mmset(fp, params.udvm_addr);
	if (!mm_set) {
		ret = -ENXIO;
		goto exit;
	}

	ret = cn_mem_free((u64)fp, params.udvm_addr, mm_set->core);

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_mem_perf_free(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_perf_free_s params;
	struct cn_mm_set *mm_set = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (!addr_is_udvm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	if (addr_is_vmm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	mm_set = __get_mmset(fp, params.udvm_addr);
	if (!mm_set) {
		ret = -ENXIO;
		goto exit;
	}

	ret = cn_mem_perf_free((u64)fp, params.udvm_addr, params.correlation_id, mm_set->core);

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);

	return ret;
}

bool udvm_memcpy_dir_check(int dir, int params_dir)
{
	if (params_dir == UDVM_MEMCPY_DIR_RANDOM)
		return true;

	/* MemcpyDtoD and MemcpyPeer called in driverAPI need compatible with each other. */
	if ((dir == UDVM_MEMCPY_DIR_D2D) && (params_dir == UDVM_MEMCPY_DIR_D2D ||
		  params_dir == UDVM_MEMCPY_DIR_P2P)) {
		return true;
	}

	return dir == params_dir;
}

int udvm_get_memcpy_dir(dev_addr_t src_addr, dev_addr_t dst_addr)
{
	if (addr_is_udvm(src_addr)) {
		return addr_is_udvm(dst_addr) ? UDVM_MEMCPY_DIR_D2D : UDVM_MEMCPY_DIR_D2H;
	} else {
		return addr_is_udvm(dst_addr) ? UDVM_MEMCPY_DIR_H2D : UDVM_MEMCPY_DIR_H2H;
	}
}

static int
udvm_internal_memcpy_h2d(struct file *fp, struct udvm_memcpy_s *info)
{
	struct cn_mm_set *mm_set = NULL;

	mm_set = __get_mmset(fp, info->dst_addr);
	if (!mm_set)
		return -EINVAL;

	return cn_mem_copy_h2d((u64)fp, info->src_addr, info->dst_addr,
				info->size, mm_set->core);
}

static int
udvm_internal_memcpy_d2h(struct file *fp, struct udvm_memcpy_s *info)
{
	struct cn_mm_set *mm_set = NULL;

	mm_set = __get_mmset(fp, info->src_addr);
	if (!mm_set)
		return -EINVAL;

	return cn_mem_copy_d2h((u64)fp, info->dst_addr, info->src_addr,
				info->size, mm_set->core);
}

static int
udvm_mem_copy_p2p(struct file *fp, dev_addr_t src_addr,
		struct cn_mm_set *src_mm_set, dev_addr_t dst_addr,
		struct cn_mm_set *dst_mm_set, unsigned long size)
{
	struct cn_core_set *src_core = NULL, *dst_core = NULL;

	src_core = (struct cn_core_set *)src_mm_set->core;
	dst_core = (struct cn_core_set *)dst_mm_set->core;

	return cn_mem_dma_p2p(src_core, dst_core, src_addr, (u64)fp, dst_addr,
					(u64)fp, size);
}

static int
udvm_internal_memcpy_d2d(struct file *fp, struct udvm_memcpy_s *info)
{
	struct cn_mm_set *src_mm_set = NULL, *dst_mm_set = NULL;

	src_mm_set = __get_mmset(fp, info->src_addr);
	if (!src_mm_set)
		return -EINVAL;

	dst_mm_set = __get_mmset(fp, info->dst_addr);
	if (!dst_mm_set)
		return -EINVAL;

	if (src_mm_set == dst_mm_set) {
		return cn_mem_copy_d2d((u64)fp, info->src_addr, info->dst_addr, info->size,
						(void *)src_mm_set->core, MEMCPY_D2D_NO_COMPRESS);
	} else {
		return udvm_mem_copy_p2p(fp, info->src_addr, src_mm_set,
					info->dst_addr, dst_mm_set, info->size);
	}
}

static int
udvm_internal_memcpy_compress_d2d(struct file *fp, struct udvm_memcpy_compress_s *info)
{
	struct cn_mm_set *src_mm_set = NULL, *dst_mm_set = NULL;

	src_mm_set = __get_mmset(fp, info->src_addr);
	if (!src_mm_set)
		return -EINVAL;

	dst_mm_set = __get_mmset(fp, info->dst_addr);
	if (!dst_mm_set)
		return -EINVAL;

	if (src_mm_set == dst_mm_set) {
		return cn_mem_copy_d2d((u64)fp, info->src_addr, info->dst_addr, info->size,
					src_mm_set->core, info->compress_type);
	} else {
		return udvm_mem_copy_p2p(fp, info->src_addr, src_mm_set, info->dst_addr,
					dst_mm_set, info->size);
	}
}

static int
udvm_internal_memcpy_d2d_2d(struct file *fp, struct udvm_memcpy_2d_s *info)
{
	struct cn_mm_set *src_mm_set = NULL, *dst_mm_set = NULL;
	struct udvm_memcpy_2d_s *p = info;

	src_mm_set = __get_mmset(fp, info->src_addr);
	if (!src_mm_set)
		return -EINVAL;

	dst_mm_set = __get_mmset(fp, info->dst_addr);
	if (!dst_mm_set)
		return -EINVAL;

	if (src_mm_set != dst_mm_set)
		return -ENXIO;

	return cn_mem_copy_d2d_2d((u64)fp, (dev_addr_t)p->dst_addr, p->dpitch,
					(dev_addr_t)p->src_addr, p->spitch,
					p->width, p->height, src_mm_set->core);
}

static int
udvm_internal_memcpy_d2d_3d(struct file *fp, struct udvm_memcpy_3d_s *info)
{
	struct cn_mm_set *src_mm_set = NULL, *dst_mm_set = NULL;
	struct udvm_memcpy_3d_s *pudvm = info;
	struct memcpy_d2d_3d_compat p;

	p.dst = pudvm->dst_addr;
	p.dst_pos = pudvm->dst_pos;
	p.dst_ptr = pudvm->dst_ptr;
	p.extent = pudvm->extent;
	p.src = pudvm->src_addr;
	p.src_pos = pudvm->src_pos;
	p.src_ptr = pudvm->src_ptr;

	src_mm_set = __get_mmset(fp, info->src_addr);
	if (!src_mm_set)
		return -EINVAL;

	dst_mm_set = __get_mmset(fp, info->dst_addr);
	if (!dst_mm_set)
		return -EINVAL;

	if (src_mm_set != dst_mm_set)
		return -ENXIO;

	return cn_mem_copy_d2d_3d((u64)fp, &p, src_mm_set->core);
}

static int
udvm_ioctl_memcpy(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0, dir = 0;
	struct udvm_memcpy_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	dir = udvm_get_memcpy_dir(params.src_addr, params.dst_addr);
	if (!udvm_memcpy_dir_check(dir, params.dir)) {
		ret = -ENXIO;
		goto exit;
	}

	switch (dir) {
	case UDVM_MEMCPY_DIR_H2D:
		ret = udvm_internal_memcpy_h2d(fp, &params);
		break;
	case UDVM_MEMCPY_DIR_D2H:
		ret = udvm_internal_memcpy_d2h(fp, &params);
		break;
	case UDVM_MEMCPY_DIR_P2P:
	case UDVM_MEMCPY_DIR_D2D:
		ret = udvm_internal_memcpy_d2d(fp, &params);
		break;
	case UDVM_MEMCPY_DIR_H2H:
		ret = -ERROR_UDVM_MEMCPY_H2H;
		break;
	default:
		ret = -EINVAL;
		break;
	}

exit:
	params.udvm_status = ret > 0 ? -EPIPE : ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_memcpy_compress(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0, dir = 0;
	struct udvm_memcpy_compress_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	dir = udvm_get_memcpy_dir(params.src_addr, params.dst_addr);
	if (!udvm_memcpy_dir_check(dir, params.dir)) {
		ret = -ENXIO;
		goto exit;
	}

	switch (dir) {
	case UDVM_MEMCPY_DIR_D2D:
		ret = udvm_internal_memcpy_compress_d2d(fp, &params);
		break;
	case UDVM_MEMCPY_DIR_H2D:
	case UDVM_MEMCPY_DIR_D2H:
	case UDVM_MEMCPY_DIR_P2P:
	case UDVM_MEMCPY_DIR_H2H:
	default:
		ret = -EINVAL;
		break;
	}

exit:
	params.udvm_status = ret > 0 ? -EPIPE : ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

/*host mem udvm api*/
int udvm_ioctl_pinned_mem_rm_alloc(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_pinned_mem_rm_alloc_s pm_param = {0};
	int ret;
	unsigned long va = 0;
	unsigned long size;
	struct file *devfp = NULL;
	struct cn_mm_set *mm_set = NULL;

	ret = udvm_copy_from_user(arg, &pm_param, len);
	if (ret)
		return ret;

	/*need map ob if flags is devmap*/
	if (pm_param.flags == CN_MEMHOSTALLOC_DEVICEMAP) {
		devfp = udvm_fget(pm_param.card_dev_fd);
		if (!devfp) {
			ret = -ERROR_UDVM_INVALID_DEVFP;
			goto exit;
		}

		ret = udvm_check_devfp_is_registered(devfp, fp);
		if (ret) {
			goto exit;
		}

		mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
		if (!mm_set) {
			ret = -ERROR_UDVM_INVALID_DEVFP;
			goto exit;
		}

		size = camb_dob_size_align(pm_param.size, mm_set);
		if ((long)size == 0) {
			/*We want to map ob, but this card no support ob, return fail.*/
			cn_dev_err("pinned mem size : %ld invalid", (long)size);
			ret = -ERROR_UDVM_NOT_SUPPORTED;
			goto exit;
		}

		/*return the adjusted size*/
		pm_param.size = size;
	}

	ret = cn_pinned_mem_alloc_internal(fp, &va, pm_param.size, pm_param.flags);
	if (ret) {
		cn_dev_err("alloc pinned mem failed.");
		goto exit;
	}

	pm_param.uaddr = (unsigned long)va;

exit:
	if (devfp)
		udvm_fput(devfp);
	pm_param.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &pm_param, len);

	return ret;
}

int udvm_ioctl_pinned_mem_rm_register(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_pinned_mem_rm_register_s pm_param = {0};
	int ret;
	struct file *devfp = NULL;
	unsigned long size;
	struct cn_mm_set *mm_set = NULL;

	ret = udvm_copy_from_user(arg, &pm_param, len);
	if (ret)
		return ret;

	devfp = udvm_fget(pm_param.card_dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) {
		goto exit;
	}

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	size = pm_param.size;
	if ((long)size <= 0) {
		cn_dev_err("pinned mem size : %ld invalid", (long)size);
		ret = -EINVAL;
		goto exit;
	}

	ret = cn_pinned_mem_host_register_internal(fp, pm_param.uaddr, pm_param.size,
									 pm_param.flags, pm_param.card_id);
exit:
	if (devfp)
		udvm_fput(devfp);
	pm_param.udvm_status = ret;
	return udvm_copy_to_user(arg, &pm_param, len);

}

int udvm_ioctl_pinned_mem_rm_free(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_pinned_mem_rm_free_s pm_param = {0};
	int ret = -1;

	ret = udvm_copy_from_user(arg, &pm_param, len);
	if (ret)
		return ret;

	ret = cn_pinned_mem_free_internal(pm_param.uaddr);

	pm_param.udvm_status = ret;

	return udvm_copy_to_user(arg, &pm_param, len);
}

int udvm_ioctl_pinned_mem_rm_unregister(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_pinned_mem_rm_unregister_s pm_param = {0};
	int ret = -1;
	struct cn_mm_set *mm_set = NULL;
	struct file *devfp = NULL;

	ret = udvm_copy_from_user(arg, &pm_param, len);
	if (ret)
		return ret;

	devfp = udvm_fget(pm_param.card_dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) {
		goto exit;
	}

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = cn_pinned_mem_host_unregister_internal(fp, pm_param.uaddr, pm_param.card_id);

exit:
	if (devfp)
		udvm_fput(devfp);
	pm_param.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &pm_param, len);

	return ret;
}

int udvm_ioctl_pinned_mem_iova_alloc(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_pinned_mem_iova_alloc_s pm_param = {0};
	int ret;
	unsigned long iova = 0;

	ret = udvm_copy_from_user(arg, &pm_param, len);
	if (ret)
		return ret;

	ret = cn_pinned_mem_iova_alloc(pm_param.uaddr, &iova);
	if (ret) {
		cn_dev_err("alloc pinned mem iova failed.");
		ret = -EINVAL;
	}

	pm_param.iova = (unsigned long)iova;

	pm_param.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &pm_param, len);

	return ret;
}

int udvm_ioctl_pinned_mem_iova_free(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_pinned_mem_iova_free_s pm_param = {0};
	int ret;

	ret = udvm_copy_from_user(arg, &pm_param, len);
	if (ret)
		return ret;

	ret = cn_pinned_mem_iova_free(pm_param.uaddr);
	if (ret) {
		cn_dev_err("free pinned mem iova failed.");
		ret = -EINVAL;
	}

	pm_param.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &pm_param, len);

	return ret;
}

int udvm_ioctl_pinned_mem_dup_mem(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_pinned_mem_dup_mem_s pm_param = {0};
	int ret;
	struct cn_mm_set *mm_set = NULL;
	struct file *devfp = NULL;

	ret = udvm_copy_from_user(arg, &pm_param, len);
	if (ret)
		return ret;

	devfp = udvm_fget(pm_param.card_dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) {
		goto exit;
	}

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = cn_pinned_mem_map_dma(pm_param.uaddr, pm_param.card_id);
	if (ret) {
		cn_dev_err("pinned mem dup failed.");
		ret = -EINVAL;
	}

exit:
	if (devfp)
		udvm_fput(devfp);
	pm_param.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &pm_param, len);

	return ret;
}

int udvm_ioctl_pinned_mem_unmap_dma(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_pinned_mem_unmap_dma_s pm_param = {0};
	int ret;
	struct cn_mm_set *mm_set = NULL;
	struct file *devfp = NULL;

	ret = udvm_copy_from_user(arg, &pm_param, len);
	if (ret)
		return ret;

	devfp = udvm_fget(pm_param.card_dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) {
		goto exit;
	}

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = cn_pinned_mem_unmap_dma(pm_param.uaddr, pm_param.card_id);
	if (ret) {
		cn_dev_err("pinned mem unmap dma failed.");
		ret = -EINVAL;
	}

exit:
	if (devfp)
		udvm_fput(devfp);
	pm_param.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &pm_param, len);

	return ret;
}

int udvm_ioctl_pinned_mem_map_device(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_pinned_mem_map_device_s pm_param = {0};
	int ret;
	struct cn_mm_set *mm_set = NULL;
	struct file *devfp = NULL;

	ret = udvm_copy_from_user(arg, &pm_param, len);
	if (ret)
		return ret;

	devfp = udvm_fget(pm_param.card_dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) {
		goto exit;
	}

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = cn_pinned_mem_map_ob(pm_param.uaddr, pm_param.card_id);
	if (ret) {
		cn_dev_err("pinned mem map outbound failed.");
		ret = -EINVAL;
	}

exit:
	if (devfp)
		udvm_fput(devfp);
	pm_param.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &pm_param, len);

	return ret;
}

int udvm_ioctl_pinned_mem_unmap_device(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_pinned_mem_unmap_device_s pm_param = {0};
	int ret;
	struct cn_mm_set *mm_set = NULL;
	struct file *devfp = NULL;

	ret = udvm_copy_from_user(arg, &pm_param, len);
	if (ret)
		return ret;

	devfp = udvm_fget(pm_param.card_dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) {
		goto exit;
	}

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = cn_pinned_mem_unmap_ob(pm_param.uaddr, pm_param.card_id);
	if (ret) {
		cn_dev_err("pinned mem unmap outbound failed.");
		ret = -EINVAL;
	}

exit:
	if (devfp)
		udvm_fput(devfp);
	pm_param.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &pm_param, len);

	return ret;
}

static int
udvm_ioctl_memcpy_2d(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0, dir = 0;
	struct udvm_memcpy_2d_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	dir = udvm_get_memcpy_dir(params.src_addr, params.dst_addr);
	if (!((params.dir == UDVM_MEMCPY_DIR_RANDOM) ||
		((params.dir == UDVM_MEMCPY_DIR_D2D) && (dir == UDVM_MEMCPY_DIR_D2D)))) {
		ret = -ENXIO;
		goto exit;
	}

	switch (dir) {
	case UDVM_MEMCPY_DIR_D2D:
		ret = udvm_internal_memcpy_d2d_2d(fp, &params);
		break;
	default:
		cn_dev_err("Error direction: %#x.", dir);
		ret = -EINVAL;
		break;
	}

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_memcpy_3d(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0, dir = 0;
	struct udvm_memcpy_3d_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret) {
		cn_dev_err("Copy parameters form user space fail:%#x.", ret);
		return ret;
	}

	dir = udvm_get_memcpy_dir(params.src_addr, params.dst_addr);
	if (!((params.dir == UDVM_MEMCPY_DIR_RANDOM) ||
		((params.dir == UDVM_MEMCPY_DIR_D2D) && (dir == UDVM_MEMCPY_DIR_D2D)))) {
		cn_dev_err("Error direction: %#x - %#x.", params.dir, dir);
		ret = -ENXIO;
		goto exit;
	}

	switch (dir) {
	case UDVM_MEMCPY_DIR_D2D:
		ret = udvm_internal_memcpy_d2d_3d(fp, &params);
		break;
	default:
		cn_dev_err("Error direction: %#x.", dir);
		ret = -EINVAL;
		break;
	}

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_peer_able(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_peerable_s params;
	struct cn_mm_set *src_mm_set = NULL, *dst_mm_set = NULL;
	struct cn_core_set *src_core = NULL, *dst_core = NULL;
	struct file *srcfp = NULL, *dstfp = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	srcfp = udvm_fget(params.src_fd);
	if (!srcfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	dstfp = udvm_fget(params.dst_fd);
	if (!dstfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	src_mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(srcfp);
	if (!src_mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	dst_mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(dstfp);
	if (!dst_mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	src_core = (struct cn_core_set *)src_mm_set->core;
	dst_core = (struct cn_core_set *)dst_mm_set->core;

	if (cn_core_is_vf(src_core) || cn_core_is_vf(dst_core)) {
		ret = -EPERM;
		goto exit;
	}

	ret = cn_bus_dma_p2p_able(src_core->bus_set, dst_core->bus_set);

	ret = (src_core->bus_set == dst_core->bus_set) ? -1 : 0;

exit:
	if (srcfp)
		udvm_fput(srcfp);

	if (dstfp)
		udvm_fput(dstfp);

	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_phy_peer_able(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_peerable_s params;
	struct cn_mm_set *src_mm_set = NULL, *dst_mm_set = NULL;
	struct cn_core_set *src_core = NULL, *dst_core = NULL;
	struct file *srcfp = NULL, *dstfp = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	srcfp = udvm_fget(params.src_fd);
	if (!srcfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	dstfp = udvm_fget(params.dst_fd);
	if (!dstfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	src_mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(srcfp);
	if (!src_mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	dst_mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(dstfp);
	if (!dst_mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	src_core = (struct cn_core_set *)src_mm_set->core;
	dst_core = (struct cn_core_set *)dst_mm_set->core;

	if (cn_core_is_vf(src_core) || cn_core_is_vf(dst_core)) {
		ret = -EPERM;
		goto exit;
	}

	ret = cn_bus_dma_p2p_able(src_core->bus_set, dst_core->bus_set);
	ret = (ret <= 0) ? -1 : 0;

exit:
	if (srcfp)
		udvm_fput(srcfp);

	if (dstfp)
		udvm_fput(dstfp);

	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

enum udvm_memset_width {
	UDVM_MEMSET_D8_WIDTH,
	UDVM_MEMSET_D16_WIDTH,
	UDVM_MEMSET_D32_WIDTH,
};

static int
udvm_internal_memset(void __user *arg, struct file *fp, size_t len, int width)
{
	int ret = 0;
	struct udvm_memset_s params;
	struct cn_mm_set *mm_set = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (!addr_is_udvm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	mm_set = __get_mmset(fp, params.udvm_addr);
	if (!mm_set) {
		ret = -ENXIO;
		goto exit;
	}

	switch (width) {
	case UDVM_MEMSET_D8_WIDTH: {
		__u8 value = (__u8)params.val;
		ret = cn_mem_dma_memsetD8(mm_set->core, params.udvm_addr, params.number,
		                          value, (u64)fp);
		break;
	}
	case UDVM_MEMSET_D16_WIDTH: {
		__u16 value = (__u16)params.val;
		ret = cn_mem_dma_memsetD16(mm_set->core, params.udvm_addr, params.number,
		                           value, (u64)fp);
		break;

	}
	case UDVM_MEMSET_D32_WIDTH: {
		__u32 value = (__u32)params.val;
		ret = cn_mem_dma_memsetD32(mm_set->core, params.udvm_addr, params.number,
		                           value, (u64)fp);
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

exit:
	params.udvm_status = ret > 0 ? -EPIPE : ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int udvm_ioctl_memset(void __user *arg, struct file *fp, size_t len)
{
	return udvm_internal_memset(arg, fp, len, UDVM_MEMSET_D8_WIDTH);
}

static int udvm_ioctl_memsetd16(void __user *arg, struct file *fp, size_t len)
{
	return udvm_internal_memset(arg, fp, len, UDVM_MEMSET_D16_WIDTH);
}

static int udvm_ioctl_memsetd32(void __user *arg, struct file *fp, size_t len)
{
	return udvm_internal_memset(arg, fp, len, UDVM_MEMSET_D32_WIDTH);
}

static int udvm_ipc_handle_create(dev_ipc_handle_t handle, unsigned int flags,
			int type, dev_ipc_handle_t *udvm_handle)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct udvm_ipc_handle *ipc_handle = NULL;
	int ret = 0;

	ipc_handle = cn_kzalloc(sizeof(struct udvm_ipc_handle), GFP_KERNEL);
	if (!ipc_handle) {
		cn_dev_err("failed to create udvm_ipc_handle");
		return -ENOMEM;
	}

	ipc_handle->udvm_handle = handle;
	ipc_handle->memory_type = type;
	ipc_handle->flags = flags;
	ipc_handle->tgid = current->tgid;
	if (ipc_handle->memory_type == UDVM_MEMORY_TYPE_DEVICE)
		ipc_handle->mm_set = ipc_handle->pminfo->mm_set;

	spin_lock(&udvm_set->udvm_ipc_lock);
	ret = radix_tree_insert(&udvm_set->udvm_ipc_raroot, ipc_handle->udvm_handle,
				(void *)ipc_handle);
	spin_unlock(&udvm_set->udvm_ipc_lock);

	if (ret) {
		cn_dev_err("insert udvm_ipc_handle failed");
		cn_kfree(ipc_handle);
		return ret;
	}

	*udvm_handle = handle;
	return 0;
}

static int get_peer_access_table_index(int local_card, int remote_card)
{
	return (local_card & 0x7f) | (remote_card << 8);
}

static int __udvm_lazy_init_mlupriv(struct udvm_priv_data *udvm_priv, int index);
static void udvm_clear_peer_access(struct udvm_peer_st *peer_info);
static int udvm_set_peer_access(struct file *fp, int local_card, int remote_card)
{
	struct udvm_priv_data *udvm = get_udvm_priv_data(fp);
	struct cn_core_set *remote_core = cn_core_get_ref(remote_card);
	struct pid_info_s *pid_info_node;
	struct udvm_peer_st *peer_info;
	unsigned long dummy;
	int table_index = get_peer_access_table_index(local_card, remote_card);
	int ret = 0;
	void *retp = NULL;

	if (!remote_core) {
		return -EINVAL;
	}

	if (remote_core->state != CN_RUNNING) {
		cn_core_put_deref(remote_core);
		return -EINVAL;
	}

	spin_lock(&udvm->peer_lock);
	if (idr_find(&udvm->peer_idr, table_index) != NULL) {
		spin_unlock(&udvm->peer_lock);
		cn_core_put_deref(remote_core);
		return 0;
	}

	ret = idr_alloc(&udvm->peer_idr, &dummy, table_index, table_index + 1, GFP_ATOMIC);
	if (ret >= 0 && ret != table_index)
		idr_remove(&udvm->peer_idr, ret);
	spin_unlock(&udvm->peer_lock);

	if (ret < 0 || ret != table_index) {
		cn_dev_err("set peer access between(Card %d, Card%d) is failed", local_card, remote_card);
		ret = -EBUSY;
		goto exit;
	}

	peer_info = cn_kzalloc(sizeof(struct udvm_peer_st), GFP_KERNEL);
	if (!peer_info) {
		cn_dev_core_err(remote_core, "alloc pid_info_node failed");
		ret = -ENOMEM;
		goto exit;
	}

	pid_info_node = &peer_info->pid_info;

	pid_info_node->fp = NULL;
	pid_info_node->phy_usedsize = 0;
	pid_info_node->vir_usedsize = 0;
	pid_info_node->tgid = current->tgid;
	pid_info_node->active_ns = task_active_pid_ns(current);
	pid_info_node->active_pid =
		task_tgid_nr_ns(current, pid_info_node->active_ns);
	pid_info_node->pgid =
		task_pgrp_nr_ns(current, pid_info_node->active_ns);
	pid_info_node->taskpid = find_get_pid(current->pid);

	spin_lock(&remote_core->pid_info_lock);
	__sync_add_and_fetch(&remote_core->open_count, 1);
	list_add_tail(&pid_info_node->pid_list, &remote_core->pid_head);
	spin_unlock(&remote_core->pid_info_lock);

	peer_info->local_card = local_card;
	peer_info->remote_card = remote_card;

	spin_lock(&udvm->peer_lock);
	retp = idr_replace(&udvm->peer_idr, peer_info, table_index);
	spin_unlock(&udvm->peer_lock);
	if (IS_ERR_OR_NULL(retp) || retp != (void *)&dummy) {
		cn_dev_err("set peer access between(Card %d, Card%d) is failed", local_card, remote_card);
		ret = -EINVAL;
		goto fail_replace;
	}

	ret = __udvm_lazy_init_mlupriv(udvm, remote_card);
	if (ret) {
		cn_dev_err("try to lazy initialize mlu_priv_data failed");
		goto fail_replace;
	}

	cn_core_put_deref(remote_core);
	return 0;

fail_replace:
	udvm_clear_peer_access(peer_info);
exit:
	spin_lock(&udvm->peer_lock);
	idr_remove(&udvm->peer_idr, table_index);
	spin_unlock(&udvm->peer_lock);
	cn_core_put_deref(remote_core);
	return ret;
}

static void udvm_clear_peer_access(struct udvm_peer_st *peer_info)
{
	struct cn_core_set *remote_core = cn_core_get_ref(peer_info->remote_card);
	struct pid_info_s *pid_info_node = &peer_info->pid_info;

	/**
	 * When clear_peer_access is called during udvm_release_entry, remote_core
	 * maybe in RESET flow and send kill signal to us. So we need do clear task
	 * even core->state not only in RUNNING state
	 **/
	if (remote_core) {
		if ((remote_core->state == CN_RUNNING || remote_core->state == CN_RESET)) {
			spin_lock(&remote_core->pid_info_lock);
			__sync_sub_and_fetch(&remote_core->open_count, 1);
			list_del(&pid_info_node->pid_list);
			spin_unlock(&remote_core->pid_info_lock);
		}
		cn_core_put_deref(remote_core);
	}

	put_pid(pid_info_node->taskpid);
	cn_kfree(peer_info);
}

struct udvm_ipc_handle_params {
	dev_ipc_handle_t udvm_handle;
	struct cn_mm_set *mm_set;
	unsigned int flag;
};

static int
udvm_ipc_handle_kref_get(struct file *fp, struct udvm_ipc_handle_params *params,
						 struct udvm_ipc_handle **ipc_phandle)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct mapinfo *pminfo = NULL;
	struct udvm_ipc_handle *ipc_handle = NULL;
	int ret = 0;

	rcu_read_lock();
	ipc_handle = radix_tree_lookup(&udvm_set->udvm_ipc_raroot, params->udvm_handle);
	if (!ipc_handle) {
		rcu_read_unlock();
		cn_dev_err("invalid udvm_handle(%#llx) input", params->udvm_handle);
		return -EINVAL;
	}

	if (ipc_handle->memory_type != UDVM_MEMORY_TYPE_DEVICE)
		goto exit;

	if (ipc_handle->mm_set != params->mm_set) {
		if (params->flag != UDVM_IPC_MEM_NEED_PEER_ACCESS) {
			ret = -ERROR_UDVM_INVALID_DEVFP;
		} else {
			ret = udvm_set_peer_access(fp, get_index_with_mmset(params->mm_set),
							  get_index_with_mmset(ipc_handle->mm_set));
		}

		if (ret) {
			rcu_read_unlock();
			cn_dev_err("current context is not permitted to open input handle");
			return -ERROR_UDVM_INVALID_DEVFP;
		}
	}

	pminfo = ipc_handle->pminfo;
	ret = atomic_add_unless(pminfo->ipcm_info->ipcm_refcnt, 1, 0);
	if (!ret) {
		rcu_read_unlock();
		cn_dev_err("Handle(%#llx) in radix_tree is invaild", params->udvm_handle);
		return -ENOSPC;
	}

exit:
	*ipc_phandle = ipc_handle;
	rcu_read_unlock();
	return 0;
}

static void
udvm_ipc_handle_put_release(dev_ipc_handle_t handle, int memory_type)
{
	struct mapinfo *pminfo = NULL;

	if (memory_type != UDVM_MEMORY_TYPE_DEVICE)
		return;

	pminfo = (struct mapinfo *)handle;
	cn_kfree(pminfo->ipcm_info->ipcm_refcnt);
	pminfo->ipcm_info->ipcm_refcnt = NULL;
	cn_kfree(pminfo->ipcm_info);
	pminfo->ipcm_info = NULL;
}

static void
udvm_ipc_handle_kref_put(struct udvm_ipc_handle *ipc_handle)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct mapinfo *pminfo = NULL;
	struct udvm_ipc_handle *ret = NULL;
	int do_free = 0;

	if (!ipc_handle) return ;

	if (ipc_handle->memory_type != UDVM_MEMORY_TYPE_DEVICE)
		return;

	pminfo = ipc_handle->pminfo;

	spin_lock(&udvm_set->udvm_ipc_lock);
	if (atomic_sub_and_test(1, pminfo->ipcm_info->ipcm_refcnt)) {
		 ret = radix_tree_delete(&udvm_set->udvm_ipc_raroot, ipc_handle->udvm_handle);
		if (ret == ipc_handle) do_free = 1;
	}
	spin_unlock(&udvm_set->udvm_ipc_lock);

	if (!do_free)
		return ;

	/**
	 * mapinfo stored in radixtree must belongs to creator process. And if
	 * ipcm_refcnt decrease into zero, means that the pminfo->refcnt is zero
	 * as well. So we need release pminfo now.
	 **/
	udvm_ipc_handle_put_release(ipc_handle->udvm_handle, ipc_handle->memory_type);

	cn_kfree(pminfo);

	cn_kfree(ipc_handle);
}

int udvm_ipc_handle_release(dev_ipc_handle_t handle)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct udvm_ipc_handle *ipc_handle = NULL;

	spin_lock(&udvm_set->udvm_ipc_lock);
	ipc_handle = radix_tree_delete(&udvm_set->udvm_ipc_raroot, handle);
	spin_unlock(&udvm_set->udvm_ipc_lock);

	if (ipc_handle) cn_kfree(ipc_handle);

	return 0;
}

static int
udvm_ioctl_ipc_get_handle(void __user *arg, struct file *fp, size_t len)
{
	dev_ipc_handle_t handle = (dev_ipc_handle_t)0;
	unsigned int flags = 0;
	struct udvm_ipc_s params;
	int ret = 0, memory_type = UDVM_MEMORY_TYPE_UNKNOWN;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (addr_is_udvm(params.udvm_addr)) {
		ret = camb_mem_ipc_get_handle((u64)fp, params.udvm_addr, IPC_MODE_UDVM, &handle);
		memory_type = UDVM_MEMORY_TYPE_DEVICE;
	} else {
		ret = camb_pinned_mem_ipc_get_handle(fp, params.udvm_addr, &handle, &flags);
		memory_type = UDVM_MEMORY_TYPE_HOST;
	}

	if (ret) goto exit;

	ret = udvm_ipc_handle_create(handle, flags, memory_type, &params.handle);
	if (ret) udvm_ipc_handle_put_release(handle, memory_type);

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_ipc_open_handle(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_ipc_s params;
	struct file *devfp = NULL;
	struct cn_mm_set *mm_set = NULL;
	struct udvm_ipc_handle_params inparams = {};
	struct udvm_ipc_handle *ipc_handle = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	devfp = udvm_fget(params.dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) goto exit;

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	/* not need check return value, if kref_get failed, memory_type will not be assigned */
	inparams.udvm_handle = params.handle;
	inparams.mm_set = mm_set;
	inparams.flag = UDVM_IPC_MEM_INVALID;
	ret = udvm_ipc_handle_kref_get(fp, &inparams, &ipc_handle);
	if (ret) goto exit;

	switch (ipc_handle->memory_type) {
	case UDVM_MEMORY_TYPE_DEVICE:
		ret = camb_mem_ipc_open_handle((u64)devfp, ipc_handle->pminfo,
					&params.udvm_addr);
		break;
	case UDVM_MEMORY_TYPE_HOST:
		ret = camb_pinned_mem_ipc_open_handle(fp, ipc_handle->kva, 0,
					(host_addr_t *)&params.udvm_addr, NULL, NULL);
		break;
	default :
		ret = -EINVAL;
		goto exit;
	}

	if (ret) udvm_ipc_handle_kref_put(ipc_handle);

exit:
	if (devfp)
		udvm_fput(devfp);

	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_ipc_open_handle_v2(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_ipc_v2_s params;
	struct file *devfp = NULL;
	struct cn_mm_set *mm_set = NULL;
	struct udvm_ipc_handle_params inparams = {};
	struct udvm_ipc_handle *ipc_handle = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	devfp = udvm_fget(params.dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) goto exit;

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	/* not need check return value, if kref_get failed, memory_type will not be assigned */
	inparams.udvm_handle = params.handle;
	inparams.mm_set = mm_set;
	inparams.flag = params.flags;
	ret = udvm_ipc_handle_kref_get(fp, &inparams, &ipc_handle);
	if (ret) goto exit;

	switch (ipc_handle->memory_type) {
	case UDVM_MEMORY_TYPE_DEVICE:
		ret = camb_mem_ipc_open_handle((u64)devfp, ipc_handle->pminfo,
					&params.udvm_addr);
		break;
	case UDVM_MEMORY_TYPE_HOST:
		ret = camb_pinned_mem_ipc_open_handle(fp, ipc_handle->kva, ipc_handle->tgid,
					(host_addr_t *)&params.udvm_addr, NULL, &params.oflags);
		break;
	default :
		ret = -EINVAL;
		goto exit;
	}

	if (ret) {
		udvm_ipc_handle_kref_put(ipc_handle);
	} else {
		params.oflags = ipc_handle->flags;
		params.type = ipc_handle->memory_type;
	}

exit:
	if (devfp)
		udvm_fput(devfp);

	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_ipc_close_handle(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_free_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (!params.udvm_addr) {
		goto exit;
	}

	if (addr_is_udvm(params.udvm_addr)) {
		ret = camb_mem_ipc_close_handle((u64)fp, params.udvm_addr);
	} else {
		ret = -ERROR_UDVM_IPC_CLOSE_HANDLE_HOST;
	}

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_enable_memcheck(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_enable_memcheck_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	params.udvm_status = camb_mem_enable_memcheck((u64)fp, params.magic, NULL);

	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_get_addr_range(void __user *arg, struct file *fp, size_t len)
{
	dev_addr_t udvm_base = 0UL;
	struct udvm_range_get_s params;
	struct cn_mm_set *mm_set = NULL;
	size_t size = 0UL;
	int ret = 0;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (addr_is_udvm(params.udvm_addr)) {
		mm_set = __get_mmset(fp, params.udvm_addr);
		if (!mm_set) {
			ret = -ENXIO;
			goto exit;
		}

		ret = camb_get_mem_range((u64)fp, params.udvm_addr, &udvm_base, &size, mm_set);
	} else {
		ret = camb_pinned_get_mem_range(fp, params.udvm_addr, (host_addr_t *)&udvm_base, &size);
	}

	if (!ret) {
		params.udvm_base = udvm_base;
		params.size      = size;
	}

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_set_prot(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_prot_set_s params;
	struct cn_mm_set *mm_set = NULL;
	int ret = 0;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (!addr_is_udvm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	if (addr_is_vmm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	mm_set = __get_mmset(fp, params.udvm_addr);
	if (!mm_set) {
		ret = -ENXIO;
		goto exit;
	}

	ret = cn_mem_set_prot((u64)fp, params.udvm_addr, params.size,
						  params.flag, mm_set->core);

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_get_uva(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_uva_get_s params;
	struct cn_mm_set *mm_set = NULL;
	user_addr_t uva = 0UL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (!addr_is_udvm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	mm_set = __get_mmset(fp, params.udvm_addr);
	if (!mm_set) {
		ret = -ENXIO;
		goto exit;
	}

	if (params.version != 0) {
		ret = -EINVAL;
		goto exit;
	}

	ret = cn_mem_uva_get((u64)fp, params.udvm_addr, params.size, &uva,
					params.attr, mm_set->core);
	if (!ret)
		params.uva = uva;

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_put_uva(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_uva_put_s params;
	struct cn_mm_set *mm_set = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret) {
		return ret;
	}

	/*Maybe params.udvm_addr is 0, but is udvm address.*/
	if (params.udvm_addr && !addr_is_udvm(params.udvm_addr)) {
		cn_dev_err("address is not udvm address");
		ret = -ENXIO;
		goto exit;
	}

	mm_set = __get_mmset(fp, params.udvm_addr);
	if (!mm_set) {
		cn_dev_err("get mm_set error.");
		ret = -ENXIO;
		goto exit;
	}

	if (params.version != 0) {
		cn_dev_err("param.version si error.");
		ret = -EINVAL;
		goto exit;
	}

	ret = cn_mem_uva_put((u64)fp, params.uva, params.size, params.udvm_addr,
						 params.attr, mm_set->core);

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_get_attributes(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_attr_s params;
	struct cn_mm_set *mm_set = NULL;
	__u64 *data = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (params.counts > UDVM_ATTRIBUTE_MAX)
		return -EINVAL;

	if (params.version < UDVM_ATTRIBUTE_VERSION)
		return -EINVAL;

	data = cn_kzalloc(sizeof(__u64) * UDVM_ATTRIBUTE_MAX, GFP_KERNEL);
	if ((unlikely(!data))) {
		cn_dev_err("alloc udvm attribute buffer failed!");
		return -ENOMEM;
	}

	if (addr_is_udvm(params.addr)) {
		mm_set = __get_mmset(fp, params.addr);
		if (!mm_set) {
			ret = -ENXIO;
			goto exit;
		}
	}

	ret = camb_mem_get_attributes((__u64)fp, params.addr, data, mm_set);
exit:
	data[0] = (__u64)ret;
	ret = udvm_copy_to_user(params.data, data, params.counts * sizeof(__u64));
	cn_kfree(data);
	return ret;
}

/**  link / unlink mm_priv_data and udvm_priv_data **/
static int udvm_check_devfp_is_registered(struct file *devfp, struct file *fp)
{
	struct udvm_priv_data *priv_data = get_udvm_priv_data(fp);
	struct cn_mm_priv_data *mm_priv_data = NULL;

	mm_priv_data = __get_mm_priv(devfp, NULL);
	if (!mm_priv_data)
		return -ERROR_UDVM_INVALID_DEVFP;


	return mm_priv_data->udvm_priv == priv_data ? 0 : -ERROR_UDVM_INVALID_DEVFP;
}

static int
__udvm_lazy_init_mlupriv(struct udvm_priv_data *udvm_priv, int index)
{
	struct mlu_priv_data *mlu_priv = NULL;

	mutex_lock(&udvm_priv->mlu_lock);
	if (udvm_priv->mlu_priv[index]) {
		mutex_unlock(&udvm_priv->mlu_lock);
		return 0;
	}

	mlu_priv = cn_kzalloc(sizeof(struct mlu_priv_data), GFP_KERNEL);
	if (!mlu_priv) {
		mutex_unlock(&udvm_priv->mlu_lock);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&mlu_priv->mm_priv_list);
	spin_lock_init(&mlu_priv->mm_priv_lock);
	mlu_priv->mmroot = RB_ROOT;
	rwlock_init(&mlu_priv->node_lock);
	spin_lock_init(&mlu_priv->minfo_lock);
	mutex_init(&mlu_priv->uva_lock);

	/* NOTE: udvm_priv->memcheck_magic is set from enable_memcheck ioctl, which is called after
	 * cambricon_ctl is opened, and is the first ioctl after cambricon_ctl. so we don't care about
	 * the situation that enable_memcheck is called after register_privdata.
	 **/
	if (udvm_priv->memcheck_magic) {
		struct cn_mm_set *mm_set = __get_mmset_with_index(index);
		if (mm_set) {
			cn_dev_info("Porcess[%d][%s] switch Card[%d] linear mode from %s to DISABLE",
			   current->tgid, current->comm, index, __linear_mode_str(&mm_set->linear));
			camb_mem_switch_linear_mode_rpc(mm_set, LINEAR_MODE_DISABLE);
		}
	}

	udvm_priv->mlu_priv[index] = mlu_priv;
	mutex_unlock(&udvm_priv->mlu_lock);

	return 0;
}

static int
udvm_ioctl_register_privdata(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0, index = 0;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct udvm_register_data_s params;
	struct udvm_priv_data *priv_data = get_udvm_priv_data(fp), *tmp = NULL;
	struct mlu_priv_data *mlu_priv = NULL;
	struct cn_mm_priv_data *mm_priv_data = NULL;
	struct file *devfp = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	devfp = udvm_fget(params.dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	mm_priv_data = __get_mm_priv(devfp, NULL);
	if (!mm_priv_data) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	/**
	 * NOTE: cambricon_ctl maybe open multi times in some monitor test case, so we need only insert
	 * the real cambricon_ctl udvm_priv_data into radix_tree.
	 **/
	spin_lock(&udvm_set->udvm_lock);
	tmp = radix_tree_lookup(&udvm_set->udvm_raroot, priv_data->tgid);
	if (!tmp)
		ret = radix_tree_insert(&udvm_set->udvm_raroot, priv_data->tgid, (void *)priv_data);
	spin_unlock(&udvm_set->udvm_lock);

	if (ret) {
		cn_dev_err("try to insert udvm_priv_data into radix tree failed:%d", ret);
		goto exit;
	}

	index = mm_priv_data->udvm_index;

	if (__udvm_lazy_init_mlupriv(priv_data, index)) {
		cn_dev_err("lazy init mlu_priv_data failed");
		ret = -ENOMEM;
		goto exit;
	}

	mlu_priv = priv_data->mlu_priv[index];

	/**
	 * udvm_kref_get return zero which shouldn't happened.
	 * the reason for check return value is fix cross compile warning.
	 **/
	if (!udvm_kref_get(priv_data)) {
		WARN(1, "udvm_priv_data's refcount is not correct as expected");
		ret = -EINVAL;
		goto exit;
	}

	spin_lock(&mlu_priv->mm_priv_lock);
	list_add(&mm_priv_data->udvm_node, &mlu_priv->mm_priv_list);
	mm_priv_data->udvm_priv = priv_data;
	mm_priv_data->memcheck_magic = priv_data->memcheck_magic;
	spin_unlock(&mlu_priv->mm_priv_lock);

exit:
	if (devfp)
		udvm_fput(devfp);

	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static void udvm_do_exit(struct mlu_priv_data *mlu_priv)
{
	struct rb_root *mmroot = &mlu_priv->mmroot;

	read_lock(&mlu_priv->node_lock);
	while (!RB_EMPTY_ROOT(mmroot)) {
		struct mapinfo *pminfo =
			rb_entry(rb_first(mmroot), struct mapinfo, node);

		read_unlock(&mlu_priv->node_lock);

		trace_udvm_do_exit(pminfo);

		mapinfo_release(pminfo);

		read_lock(&mlu_priv->node_lock);
	}
	read_unlock(&mlu_priv->node_lock);
}

static void udvm_kref_put(struct udvm_priv_data *udvm)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct list_head *udvm_head = NULL;
	struct mlu_priv_data *mlu_priv = NULL;
	struct cn_mm_priv_data *pos = NULL, *tmp = NULL;
	int i = 0;

	if (!udvm)
		return ;

	if (atomic_long_dec_and_test(&udvm->udvm_counts)) {
		for (i = 0; i < MAX_FUNCTION_NUM; i++) {
			mlu_priv = udvm->mlu_priv[i];
			if (!mlu_priv) {
				continue;
			}

			if (!list_empty(&mlu_priv->mm_priv_list)) {
				udvm_head = &mlu_priv->mm_priv_list;

				spin_lock(&mlu_priv->mm_priv_lock);
				list_for_each_entry_safe(pos, tmp, udvm_head, udvm_node) {
					list_del_init(&pos->udvm_node);
					pos->udvm_priv = NULL;
				}
				spin_unlock(&mlu_priv->mm_priv_lock);
			}
			udvm_do_exit(mlu_priv);

			if (udvm->memcheck_magic) {
				struct cn_mm_set *mm_set = __get_mmset_with_index(i);
				if (mm_set) {
					camb_linear_remap_mode_reset(mm_set);
					cn_dev_info("Porcess[%d][%s] reset Card[%d] linear mode to %s",
						current->tgid, current->comm, i, __linear_mode_str(&mm_set->linear));
				}
			}

			cn_kfree(mlu_priv);
			udvm->mlu_priv[i] = NULL;
		}

		camb_mem_vmm_priv_release(udvm->vmm_priv);

		camb_mem_extn_priv_release(udvm->extn_priv);

		spin_lock(&udvm_set->udvm_lock);
		list_del_init(&udvm->unode);
		spin_unlock(&udvm_set->udvm_lock);

		cn_kfree(udvm);
	}
}

int udvm_unregister_privdata(void *priv)
{
	struct cn_mm_priv_data *mm_priv_data = (struct cn_mm_priv_data *)priv;
	struct udvm_priv_data *udvm_priv = NULL;
	struct mlu_priv_data *mlu_priv = NULL;
	int index = 0;

	if (!mm_priv_data)
		return -EINVAL;

	index = mm_priv_data->udvm_index;
	udvm_priv = mm_priv_data->udvm_priv;
	if (!udvm_priv)
		return -EINVAL;

	mlu_priv = udvm_mlu_priv_must_valid(udvm_priv, index);

	spin_lock(&mlu_priv->mm_priv_lock);
	list_del_init(&mm_priv_data->udvm_node);
	mm_priv_data->udvm_priv = NULL;
	spin_unlock(&mlu_priv->mm_priv_lock);

	udvm_kref_put(udvm_priv);

	return 0;
}

static int
udvm_ioctl_bar_copy(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0, dir = 0;
	struct udvm_bar_copy_s params;
	struct cn_mm_set *mm_set = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	dir = udvm_get_memcpy_dir(params.src_addr, params.dst_addr);

	switch (dir) {
	case UDVM_MEMCPY_DIR_H2D: {
		mm_set = __get_mmset(fp, params.dst_addr);
		if (!mm_set) {
			ret = -EINVAL;
			goto exit;
		}

		ret = cn_mem_bar_copy_h2d((u64)fp, params.dst_addr,
						params.src_addr, params.size, mm_set->core);
		break;
	}
	case UDVM_MEMCPY_DIR_D2H: {
		mm_set = __get_mmset(fp, params.src_addr);
		if (!mm_set) {
			ret = -EINVAL;
			goto exit;
		}

		/* DRIVER-4217, mlu370 not support bar read because pcie hardware bug */
		if (mm_set->devid == MLUID_370) {
			cn_dev_err("mlu370 not support bar copy_d2h");
			ret = -EPERM;
			goto exit;
		}

		ret = cn_mem_bar_copy_d2h((u64)fp, params.src_addr,
						params.dst_addr, params.size, mm_set->core);
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_mem_alloc_ext(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_alloc_ext_s params;
	struct mem_attr mm_attr;
	struct file *devfp = NULL;
	struct cn_mm_set *mm_set = NULL;
	dev_addr_t udvm_addr = 0UL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret) {
		return ret;
	}

	devfp = udvm_fget(params.dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) goto exit;

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	mm_attr.tag      = (u64)devfp;
	mm_attr.size     = params.size;
	mm_attr.align    = params.align;
	mm_attr.type     = params.type;
	mm_attr.affinity = params.affinity;
	mm_attr.flag     = params.flag;
	mm_attr.vmid     = PF_ID;

	memset(mm_attr.name, '\0', EXT_NAME_SIZE);
	if (params.name[0] == '\0') {
		strcpy(mm_attr.name, EXT_ANONYMOUS_NAME);
	} else {
		strncpy(mm_attr.name, params.name, EXT_NAME_SIZE - 1);
	}

	if (params.type == CN_MDR_MEM) {
		ret = cn_mdr_alloc((u64)devfp, &udvm_addr, &mm_attr, mm_set->core);
	} else {
		ret = cn_mem_alloc((u64)devfp, &udvm_addr, &mm_attr, mm_set->core);
	}

	if (!ret) {
		params.udvm_addr = udvm_addr;
	}

exit:
	if (devfp) {
		udvm_fput(devfp);
	}

	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);

	return ret;
}

static int
udvm_ioctl_mem_info_adj(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct cn_core_set *core = NULL;
	struct udvm_info_adj_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	core = (struct cn_core_set *)cn_core_get_with_idx(params.cid);
	if (!core) {
		cn_dev_err("MemAdj:It's failed to get core_set with cid(%d)!", params.cid);
		ret = -EINVAL;
		goto exit;
	}

	ret = camb_mem_info_adj(core, params.dir, params.size);
exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_cache_op(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_cache_s params;
	struct cn_mm_set *mm_set = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret) {
		return ret;
	}

	mm_set = __get_mmset(fp, params.udvm_addr);
	if (!mm_set) {
		cn_dev_err("udvm_addr:%#llx get mm_set error.",params.udvm_addr);
		ret = -ENXIO;
		goto exit;
	}

	ret = cn_mem_cache_op((u64)fp, params.udvm_addr, params.uva, params.size,
						 params.op, mm_set->core);
exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_mem_create(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_mem_create_s params;
	struct cn_mm_set *mm_set = NULL;
	unsigned long handle = 0;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret) {
		return ret;
	}

	mm_set = __get_mmset_with_index(params.mlu_id);
	if (!mm_set) {
		cn_dev_err("mlu_id:%#x get mm_set error.",params.mlu_id);
		ret = -ERROR_UDVM_INVALID_DEVICE;
		goto exit;
	}

	ret = cn_vmm_mem_create((u64)fp, params.size, params.flags, &handle, mm_set);
	if (!ret) params.udvm_handle = handle;

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_mem_release(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_mem_release_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret) {
		return ret;
	}

	if (!addr_is_vmm(params.udvm_handle)) {
		ret = -EINVAL;
		goto exit;
	}

	ret = cn_vmm_mem_release((u64)fp, params.udvm_handle);

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_address_reserve(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_addr_reserve_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	ret = cn_vmm_mem_address_reserve((u64)fp, params.size, params.align,
				params.start, params.flags, &params.udvm_addr);

	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_address_free(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_addr_free_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (!addr_is_vmm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	ret = cn_vmm_mem_address_free((u64)fp, params.udvm_addr, params.size);

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_mem_map(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_mem_map_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (!addr_is_vmm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	if (!addr_is_vmm(params.udvm_handle)) {
		ret = -EINVAL;
		goto exit;
	}

	if (params.offset) {
		ret = -ERROR_UDVM_NOT_SUPPORTED;
		goto exit;
	}

	ret = cn_vmm_mem_map((u64)fp, params.udvm_addr, params.size, params.offset,
				params.udvm_handle);

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_mem_set_access(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_set_access_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (!addr_is_vmm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	ret = cn_vmm_set_access((u64)fp, params.udvm_addr, params.size,
							params.flags, params.mlu_id);

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_mem_unmap(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_mem_unmap_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	if (!addr_is_vmm(params.udvm_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	ret = cn_vmm_mem_unmap((u64)fp, params.udvm_addr, params.size);

exit:
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_rst_pst_l2cache(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct cn_mm_set *mm_set = NULL;
	struct file *devfp = NULL;
	struct udvm_rst_pst_l2cache_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	devfp = udvm_fget(params.dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret) goto exit;

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}
	ret = camb_rst_pst_l2cache((u64)devfp, mm_set);

exit:
	if (devfp)
		udvm_fput(devfp);
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

static int
udvm_ioctl_vmm_attribute_v1(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_vmm_attr_v1_s paramsV1;
	unsigned long data;

	ret = udvm_copy_from_user(arg, &paramsV1, len);
	if (ret)
		return ret;

	ret = cn_vmm_get_attribute((u64)fp, (unsigned long *)&paramsV1.args,
					1, paramsV1.type, &data);

	paramsV1.data = data;
	paramsV1.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &paramsV1, len);

	return ret;
}

static int
udvm_ioctl_vmm_attribute(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_vmm_attr_s params;
	unsigned long data;

	ret = udvm_copy_from_user(arg, &params, len);

	if (ret)
		return ret;

	ret = cn_vmm_get_attribute((u64)fp, (unsigned long *)params.args,
					params.nums, params.type, &data);

	params.data = data;
	params.udvm_status = ret;
	ret = udvm_copy_to_user(arg, &params, len);

	return ret;
}

static int udvm_ioctl_vmm_export(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_vmm_share_s params;

	ret = udvm_copy_from_user(arg, &params, len);

	if (ret)
		return ret;

	ret = cn_vmm_export_share_handle((u64)fp, params.udvm_handle, params.type,
						(unsigned int *)&params.shareable_handle);

	params.udvm_status = ret;

	return udvm_copy_to_user(arg, &params, len);
}

static int udvm_ioctl_vmm_import(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_vmm_share_s params;

	ret = udvm_copy_from_user(arg, &params, len);

	if (ret)
		return ret;

	ret = cn_vmm_import_share_handle((u64)fp, params.shareable_handle,
					params.type, (unsigned long *)&params.udvm_handle);

	params.udvm_status = ret;

	return udvm_copy_to_user(arg, &params, len);
}

static int udvm_ioctl_import_extn_mem(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_import_ext_mem_s params;
	struct cn_mm_set *mm_set = NULL;
	unsigned long handle = 0;
	struct file *devfp = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	devfp = udvm_fget(params.dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret)
		goto exit;

	mm_set = (struct cn_mm_set *)__get_mmset_with_devfp(devfp);
	if (!mm_set) {
		ret = -ERROR_UDVM_INVALID_DEVICE;
		goto exit;
	}

	ret = camb_import_extn_mem((u64)fp, params.import_handle, params.size, &handle, mm_set);

	params.udvm_handle = handle;

exit:
	if (devfp) {
		udvm_fput(devfp);
	}

	params.udvm_status = ret;
	return udvm_copy_to_user(arg, &params, len);
}

static int udvm_ioctl_map_extn_mem(void __user *arg, struct file *fp, size_t len)
{
	struct udvm_map_ext_mem_s params;
	dev_addr_t iova = 0;
	int ret = 0;
	struct file *devfp = NULL;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret)
		return ret;

	devfp = udvm_fget(params.dev_fd);
	if (!devfp) {
		ret = -ERROR_UDVM_INVALID_DEVFP;
		goto exit;
	}

	ret = udvm_check_devfp_is_registered(devfp, fp);
	if (ret)
		goto exit;

	ret = camb_map_extn_mem((u64)devfp, params.udvm_handle, params.size, params.offset, params.flag, &iova);

	params.udvm_addr = iova;
exit:
	if (devfp)
		udvm_fput(devfp);

	params.udvm_status = ret;
	return udvm_copy_to_user(arg, &params, len);
}

static int udvm_ioctl_destroy_extn_mem(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_destroy_ext_mem_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret) {
		return ret;
	}

	if (!addr_is_udvm(params.udvm_handle)) {
		return -EINVAL;
	}

	params.udvm_status = camb_destroy_extn_mem((u64)fp, params.udvm_handle);

	return udvm_copy_to_user(arg, &params, len);
}

static int udvm_graph_memcpycheck(struct file *fp, struct udvm_memcpy_3d_s *p)
{
	int ret = 0, dir;
	struct udvm_memcpy_3d_s *params = p;
	struct cn_mm_set *mm_set = NULL;
	u64 src_addr, dst_addr, size;

	src_addr = params->src_addr;
	dst_addr = params->dst_addr;
	size = params->extent.depth * params->extent.height * params->extent.width;

	dir = udvm_get_memcpy_dir(src_addr, dst_addr);
	if (!udvm_memcpy_dir_check(dir, params->dir)) {
		ret = -ENXIO;
		goto exit;
	}

	switch (dir) {
	case UDVM_MEMCPY_DIR_H2D:
		mm_set = __get_mmset(fp, dst_addr);
		if (!mm_set) {
			ret = -EINVAL;
			goto exit;
		}

		if (dma_hmsc_enable) {
			ret = camb_host_mem_check(src_addr, size);
			if (ret < 0)
				goto exit;
		}

		ret = camb_mem_check_without_ref((u64)fp, dst_addr, size, mm_set);
		break;
	case UDVM_MEMCPY_DIR_D2H:
		mm_set = __get_mmset(fp, src_addr);
		if (!mm_set) {
			ret = -EINVAL;
			goto exit;
		}

		if (dma_hmsc_enable) {
			ret = camb_host_mem_check(dst_addr, size);
			if (ret < 0)
				goto exit;
		}

		ret = camb_mem_check_without_ref((u64)fp, src_addr, size, mm_set);
		break;
	case UDVM_MEMCPY_DIR_D2D:
		if (src_addr == dst_addr) {
			cn_dev_err("the inputted src(%#llx) and dst(%#llx) is the same value!",
					   src_addr, dst_addr);
			ret = -ENXIO;
			goto exit;
		}

		mm_set = __get_mmset(fp, src_addr);
		if (!mm_set) {
			ret = -EINVAL;
			goto exit;
		}

		ret = camb_mem_check_without_ref((u64)fp, src_addr, size, mm_set);
		if (ret)
			goto exit;

		ret = camb_mem_check_without_ref((u64)fp, dst_addr, size, mm_set);
		break;
	case UDVM_MEMCPY_DIR_P2P:
		mm_set = __get_mmset(fp, src_addr);
		if (!mm_set) {
			ret = -EINVAL;
			goto exit;
		}

		ret = camb_mem_check_without_ref((u64)fp, src_addr, size, mm_set);
		if (ret)
			goto exit;

		mm_set = __get_mmset(fp, dst_addr);
		if (!mm_set) {
			ret = -EINVAL;
			goto exit;
		}

		ret = camb_mem_check_without_ref((u64)fp, dst_addr, size, mm_set);
		break;
	case UDVM_MEMCPY_DIR_H2H:
		ret = -ERROR_UDVM_MEMCPY_H2H;
		break;
	default:
		ret = -EINVAL;
		break;
	}

exit:
	params->udvm_status = ret > 0 ? -EPIPE : ret;
	return ret;
}

static int udvm_graph_memsetcheck(struct file *fp, struct udvm_memset_2d_s *p)
{
	int ret = 0, type;
	struct udvm_memset_2d_s *params = p;
	struct cn_mm_set *mm_set = NULL;
	u64 dst_addr, size;
	unsigned int element_size = 1;

	dst_addr = params->udvm_addr;
	size = params->height * params->width;
	type = params->element_size; /* must be 8, 16, 32 */

	if (!addr_is_udvm(dst_addr)) {
		ret = -ENXIO;
		goto exit;
	}

	mm_set = __get_mmset(fp, dst_addr);
	if (!mm_set) {
		ret = -ENXIO;
		goto exit;
	}

	switch (type / 16) {
	case UDVM_MEMSET_D8_WIDTH:
		element_size = sizeof(unsigned char);
		break;
	case UDVM_MEMSET_D16_WIDTH:
		element_size = sizeof(unsigned short);
		break;
	case UDVM_MEMSET_D32_WIDTH:
		element_size = sizeof(unsigned int);
		break;
	default:
		cn_dev_err("memset WIDTH (%d) is error", type);
		ret = -EINVAL;
		goto exit;
	}

	size *= element_size;
	ret = camb_mem_check_without_ref((u64)fp, dst_addr, size, mm_set);

exit:
	params->udvm_status = ret > 0 ? -EPIPE : ret;
	return ret;
}

static int
udvm_ioctl_graph_memcheck(void __user *arg, struct file *fp, size_t len)
{
	int ret = 0;
	struct udvm_graph_memcheck_s params;

	ret = udvm_copy_from_user(arg, &params, len);
	if (ret) {
		return ret;
	}

	if (params.type == 0) {
		ret = udvm_graph_memcpycheck(fp, &params.memcpy);
	} else if (params.type == 1) {
		ret = udvm_graph_memsetcheck(fp, &params.memset);
	} else {
		cn_dev_err("input type (%d) is error", params.type);
		ret = -EINVAL;
	}

	ret = udvm_copy_to_user(arg, &params, len);
	return ret;
}

typedef int (*udvm_ioctl_func)(void __user *arg, struct file *fp, size_t len);
static const udvm_ioctl_func udvm_funcs[] = {
	[__UDVM_MEM_ALLOC]         = udvm_ioctl_mem_alloc,
	[__UDVM_MEM_PERF_ALLOC]      = udvm_ioctl_mem_perf_alloc,
	[__UDVM_MEM_FREE]          = udvm_ioctl_mem_free,
	[__UDVM_MEM_PERF_FREE]       = udvm_ioctl_mem_perf_free,
	[__UDVM_FB_MEM_ALLOC]      = udvm_ioctl_mem_alloc,
	[__UDVM_MDR_ALLOC]         = udvm_ioctl_mem_alloc,
	[__UDVM_MEMCPY]            = udvm_ioctl_memcpy,
	[__UDVM_PEER_ABLE]         = udvm_ioctl_peer_able,
	[__UDVM_MEMSET]            = udvm_ioctl_memset,
	[__UDVM_MEMSETD16]         = udvm_ioctl_memsetd16,
	[__UDVM_MEMSETD32]         = udvm_ioctl_memsetd32,
	[__UDVM_IPC_GET_HANDLE]    = udvm_ioctl_ipc_get_handle,
	[__UDVM_IPC_OPEN_HANDLE]   = udvm_ioctl_ipc_open_handle,
	[__UDVM_IPC_CLOSE_HANDLE]  = udvm_ioctl_ipc_close_handle,
	[__UDVM_ENABLE_MEMCHECK]   = udvm_ioctl_enable_memcheck,
	[__UDVM_GET_ADDR_RANGE]    = udvm_ioctl_get_addr_range,
	[__UDVM_PHY_PEER_ABLE]     = udvm_ioctl_phy_peer_able,
	[__UDVM_SET_PROT]          = udvm_ioctl_set_prot,
	[__UDVM_GET_UVA]           = udvm_ioctl_get_uva,
	[__UDVM_PUT_UVA]           = udvm_ioctl_put_uva,
	[__UDVM_REGISTER_PRIVDATA] = udvm_ioctl_register_privdata,
	[__UDVM_BAR_COPY]          = udvm_ioctl_bar_copy,
	[__UDVM_MEM_ALLOC_EXT]     = udvm_ioctl_mem_alloc_ext,
	[__UDVM_MEMCPY_2D]         = udvm_ioctl_memcpy_2d,
	[__UDVM_MEMCPY_3D]         = udvm_ioctl_memcpy_3d,
	[__UDVM_MEM_INFO_ADJ]	   = udvm_ioctl_mem_info_adj,
	[__UDVM_MEM_GET_ATTR]      = udvm_ioctl_get_attributes,
	[__UDVM_CACHE_OP]          = udvm_ioctl_cache_op,
	[__UDVM_ADDRESS_RESERVE]   = udvm_ioctl_address_reserve,
	[__UDVM_ADDRESS_FREE]      = udvm_ioctl_address_free,
	[__UDVM_MEM_CREATE]        = udvm_ioctl_mem_create,
	[__UDVM_MEM_RELEASE]       = udvm_ioctl_mem_release,
	[__UDVM_MEM_MAP]           = udvm_ioctl_mem_map,
	[__UDVM_MEM_SET_ACCESS]	   = udvm_ioctl_mem_set_access,
	[__UDVM_MEM_UNMAP]         = udvm_ioctl_mem_unmap,
	[__UDVM_RST_PST_L2CACHE]   = udvm_ioctl_rst_pst_l2cache,
	[__UDVM_VMM_ATTRIBUTE_V1]  = udvm_ioctl_vmm_attribute_v1,
	[__UDVM_GRAPH_MEMCHECK]    = udvm_ioctl_graph_memcheck,
	[__UDVM_VMM_ATTRIBUTE]     = udvm_ioctl_vmm_attribute,
	[__UDVM_MEMCPY_COMPRESS]   = udvm_ioctl_memcpy_compress,
	[__UDVM_VMM_EXPORT]        = udvm_ioctl_vmm_export,
	[__UDVM_VMM_IMPORT]        = udvm_ioctl_vmm_import,
	[__UDVM_IMPORT_EXTERNAL]   = udvm_ioctl_import_extn_mem,
	[__UDVM_MAP_EXTERNAL]      = udvm_ioctl_map_extn_mem,
	[__UDVM_DESTROY_EXTERNAL]  = udvm_ioctl_destroy_extn_mem,
	[__UDVM_IPC_OPEN_HANDLE_V2] = udvm_ioctl_ipc_open_handle_v2,
	[__UDVM_PINNED_MEM_RM_ALLOC]      = udvm_ioctl_pinned_mem_rm_alloc,
	[__UDVM_PINNED_MEM_IOVA_ALLOC]    = udvm_ioctl_pinned_mem_iova_alloc,
	[__UDVM_PINNED_MEM_MAP_DEVICE]    = udvm_ioctl_pinned_mem_map_device,
	[__UDVM_PINNED_MEM_DUP_MEM]       = udvm_ioctl_pinned_mem_dup_mem,
	[__UDVM_PINNED_MEM_IOVA_FREE]     = udvm_ioctl_pinned_mem_iova_free,
	[__UDVM_PINNED_MEM_UNMAP_DEVICE]  = udvm_ioctl_pinned_mem_unmap_device,
	[__UDVM_PINNED_MEM_UNMAP_DMA]     = udvm_ioctl_pinned_mem_unmap_dma,
	[__UDVM_PINNED_MEM_RM_FREE]	  = udvm_ioctl_pinned_mem_rm_free,
	[__UDVM_PINNED_MEM_RM_REGISTER]   = udvm_ioctl_pinned_mem_rm_register,
	[__UDVM_PINNED_MEM_RM_UNREGISTER] = udvm_ioctl_pinned_mem_rm_unregister,
	[__UDVM_IOCTL_END]         = NULL,
};

long cn_udvm_ioctl( struct file *fp, unsigned int cmd, unsigned long arg)
{
	unsigned int ioc_nr = _IOC_NR(cmd);
	size_t ioc_size = _IOC_SIZE(cmd);

	if (unlikely(ioc_nr >= __UDVM_IOCTL_END || !udvm_funcs[ioc_nr]))
		return -EPERM;

	return udvm_funcs[ioc_nr]((void *)arg, fp, ioc_size);
}

int udvm_register_async_tasks(void *udvm_priv)
{
	struct udvm_priv_data *udvm = (struct udvm_priv_data *)udvm_priv;

	if (atomic_long_inc_return(&udvm->udvm_async_tasks) == 1) {
		if (!udvm_kref_get(udvm)) {
			atomic_long_dec(&udvm->udvm_async_tasks);
			return -EINVAL;
		}
	}

	return 0;
}

void udvm_unregister_async_tasks(void *udvm_priv)
{
	struct udvm_priv_data *udvm = (struct udvm_priv_data *)udvm_priv;

	if (atomic_long_dec_and_test(&udvm->udvm_async_tasks))
		udvm_kref_put(udvm);
}

static unsigned long __get_cp_type(struct mapinfo *pmapinfo)
{
	if (MEM_AP_FROM_PROT(pmapinfo->mem_meta.flag) == AP_OR)
		return CHECKPOINT_MEMORY_TYPE_OR;

	if (pmapinfo->ipcm_info)
		return CHECKPOINT_MEMORY_TYPE_IPC;
	else
		return CHECKPOINT_MEMORY_TYPE_NORMAL;
}

unsigned long udvm_copy_cp_node(
		void *tmp_buf, int idx, int *skip, unsigned long size,
		int (*do_copy)(void *, unsigned long, unsigned long, unsigned long))
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct udvm_priv_data *udvm = NULL;
	struct mlu_priv_data *mlu = NULL;
	struct mapinfo *post = NULL;
	struct rb_node *p = NULL;
	unsigned long real_size = 0;
	unsigned long per_cp_node_size = camb_per_cp_node_size();

	rcu_read_lock();
	udvm = radix_tree_lookup(&udvm_set->udvm_raroot, current->tgid);
	if (!udvm)
		goto out;

	mlu = udvm->mlu_priv[idx];
	if (!mlu || RB_EMPTY_ROOT(&mlu->mmroot))
		goto out;

	read_lock(&mlu->node_lock);
	p = rb_first(&mlu->mmroot);
	while (p != NULL) {
		post = rb_entry(p, struct mapinfo, node);
		real_size += per_cp_node_size;
		/* When the real size is larger than the input size, it skips to
		 * fill in the input buffer.
		 * And we need to get the total real size, so to do it continue.
		 */
		if (*skip)
			goto do_skip;

		if (real_size > size) {
			*skip = 1;
			goto do_skip;
		}

		do_copy(tmp_buf, post->virt_addr, post->mem_meta.size, __get_cp_type(post));
		tmp_buf += per_cp_node_size;
do_skip:
		p = rb_next(p);
	}
	read_unlock(&mlu->node_lock);

out:
	rcu_read_unlock();

	return real_size;
}

int cn_udvm_open_entry(struct inode *inode, void **udvm_priv, u64 tag)
{
	int ret = 0;
	struct udvm_priv_data *udvm = NULL;
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();

	udvm = cn_kzalloc(sizeof(struct udvm_priv_data), GFP_KERNEL);
	if (!udvm) {
		return -ENOMEM;
	}

	ret = camb_mem_vmm_priv_init(&udvm->vmm_priv);
	if (ret) {
		cn_kfree(udvm);
		return ret;
	}

	ret = camb_mem_extn_priv_init(&udvm->extn_priv);
	if (ret) {
		camb_mem_vmm_priv_release(udvm->vmm_priv);
		cn_kfree(udvm);
		return ret;
	}

	idr_init(&udvm->peer_idr);
	spin_lock_init(&udvm->peer_lock);
	mutex_init(&udvm->mlu_lock);

	*udvm_priv = (void *)udvm;
	udvm->tag = (u64)tag;
	udvm->tgid = current->tgid;
	atomic_long_set(&udvm->udvm_counts, 1);
	atomic_long_set(&udvm->udvm_async_tasks, 0);

	spin_lock(&udvm_set->udvm_lock);
	list_add_tail(&udvm->unode, &udvm_set->udvm_head);
	spin_unlock(&udvm_set->udvm_lock);

	return 0;
}

static int udvm_idr_clear_peer_access(int id, void *priv, void *data)
{
	struct udvm_peer_st *peer_info = priv;

	udvm_clear_peer_access(peer_info);

	return 0;
}

void cn_udvm_release_entry(struct inode *inode, void *udvm_priv)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct udvm_priv_data *udvm = (struct udvm_priv_data *)udvm_priv, *tmp = NULL;

	spin_lock(&udvm_set->udvm_lock);
	tmp = radix_tree_lookup(&udvm_set->udvm_raroot, udvm->tgid);
	if (tmp == udvm)
		tmp = radix_tree_delete(&udvm_set->udvm_raroot, udvm->tgid);
	spin_unlock(&udvm_set->udvm_lock);

	idr_for_each(&udvm->peer_idr, udvm_idr_clear_peer_access, NULL);

	idr_destroy(&udvm->peer_idr);

	udvm_kref_put(udvm);
}


int cn_udvm_init(void **pudvm)
{
	struct cn_udvm_set *udvm;
	int ret = 0;

	udvm = cn_kzalloc(sizeof(struct cn_udvm_set), GFP_KERNEL);
	if (!udvm) {
		return -ENOMEM;
	}

	spin_lock_init(&udvm->udvm_lock);
	INIT_LIST_HEAD(&udvm->udvm_head);
	INIT_RADIX_TREE(&udvm->udvm_raroot, GFP_ATOMIC);

	spin_lock_init(&udvm->udvm_ipc_lock);
	INIT_RADIX_TREE(&udvm->udvm_ipc_raroot, GFP_ATOMIC);

	camb_pinned_mem_init(udvm);

	ret = camb_vmm_init(&udvm->vmm_set);
	if (ret) {
		camb_pinned_mem_exit();
		cn_kfree(udvm);
		return -EINVAL;
	}

	ret = camb_generic_iova_init(&udvm->iova_pool);
	if (ret) {
		camb_vmm_exit(&udvm->vmm_set);
		camb_pinned_mem_exit();
		cn_kfree(udvm);
		return -EINVAL;
	}

	*pudvm = (void *)udvm;
	return 0;
}

void cn_udvm_exit(void *pudvm)
{
	struct cn_udvm_set *udvm = (struct cn_udvm_set *)pudvm;

	WARN(!list_empty(&udvm->udvm_head), "Memory resource not clear before driver unload, maybe memory leak happened");

	WARN(!cn_radix_tree_empty(&udvm->udvm_ipc_raroot), "ipc share Handle not clear before driver unload, maybe memory leak happened");

	WARN(!cn_radix_tree_empty(&udvm->udvm_raroot), "udvm_priv_data not clear before driver unload, maybe memory leak happened");

	camb_pinned_mem_exit();
	camb_vmm_exit(&udvm->vmm_set);
	camb_generic_iova_exit(&udvm->iova_pool);

	cn_kfree(udvm);
}
