#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/sched.h>
#include <linux/timex.h>
#include <linux/timer.h>
#include<linux/miscdevice.h>
#if KERNEL_VERSION(4, 11, 0) < LINUX_VERSION_CODE
#include <linux/sched/signal.h>
#endif
#include"../include/cndrv_mm.h"
#include <linux/scatterlist.h>
/**
 * HAVE_UNLOCKED_IOCTL has been dropped in kernel version 5.9.
 * There is a chance that the removal might be ported back to 5.x.
 * So if HAVE_UNLOCKED_IOCTL is not defined in kernel v5, we define it.
 * This also allows backward-compatibility with kernel < 2.6.11.
 */
#if KERNEL_VERSION(5, 0, 0) < LINUX_VERSION_CODE && !defined(HAVE_UNLOCKED_IOCTL)
#define HAVE_UNLOCKED_IOCTL 1
#endif

//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------

#if KERNEL_VERSION(2, 6, 32) > LINUX_VERSION_CODE
/**
 * This API is available after Linux kernel 2.6.32
 */
void address_space_init_once(struct address_space *mapping)
{
	memset(mapping, 0, sizeof(*mapping));
	INIT_RADIX_TREE(&mapping->page_tree, GFP_ATOMIC);

#if KERNEL_VERSION(2, 6, 26) > LINUX_VERSION_CODE
	//
	// The .tree_lock member variable was changed from type rwlock_t, to
	// spinlock_t, on 25 July 2008, by mainline commit
	// 19fd6231279be3c3bdd02ed99f9b0eb195978064.
	//
	rwlock_init(&mapping->tree_lock);
#else
	spin_lock_init(&mapping->tree_lock);
#endif

	spin_lock_init(&mapping->i_mmap_lock);
	INIT_LIST_HEAD(&mapping->private_list);
	spin_lock_init(&mapping->private_lock);
	INIT_RAW_PRIO_TREE_ROOT(&mapping->i_mmap);
	INIT_LIST_HEAD(&mapping->i_mmap_nonlinear);
}
#endif

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_32)

#define get_tsc_khz() cpu_khz // tsc_khz
#elif defined(CONFIG_PPC64)

#define get_tsc_khz() (get_cycles()/1000) // dirty hack

#else
#endif

#include "gdrdrv.h"

#define DEVNAME "gdrdrv"

#define gdr_msg(KRNLVL, FMT, ARGS...) printk(KRNLVL DEVNAME ":%s:" FMT, __func__, ## ARGS)
//#define gdr_msg(KRNLVL, FMT, ARGS...) printk_ratelimited(KRNLVL DEVNAME ":" FMT, ## ARGS)

static int dbg_enabled;
#define gdr_dbg(FMT, ARGS...)                               \
	do {                                                    \
		if (dbg_enabled)                                    \
			gdr_msg(KERN_DEBUG, FMT, ## ARGS);              \
	} while (0)

static int info_enabled;
#define gdr_info(FMT, ARGS...)                               \
	do {                                                     \
		if (info_enabled)                                    \
			gdr_msg(KERN_INFO, FMT, ## ARGS);                \
	} while (0)

#define gdr_err(FMT, ARGS...)                               \
	gdr_msg(KERN_DEBUG, FMT, ## ARGS)
#define GPU_PAGE_SHIFT   14
#define GPU_PAGE_SIZE    ((u64)1 << GPU_PAGE_SHIFT)
#define GPU_PAGE_OFFSET  (GPU_PAGE_SIZE-1)
#define GPU_PAGE_MASK    (~GPU_PAGE_OFFSET)

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? a : b)
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? a : b)
#endif

struct gdr_mr {
	struct list_head node;
	gdr_hnd_t handle;
	u64 offset;
	u64 length;
	u64 p2p_token;
	u32 va_space;
	u32 page_size;
	u64 va;
	u64 mapped_size;
	enum { GDR_MR_NONE, GDR_MR_WC, GDR_MR_CACHING } cpu_mapping_type;
	struct sg_table *page_table;
	int cb_flag;
	cycles_t tm_cycles;
	unsigned int tsc_khz;
	struct vm_area_struct *vma;
	struct address_space *mapping;
	struct rw_semaphore sem;
};

/**
 * Prerequisite:
 * - mr must be protected by down_read(mr->sem) or stronger.
 */
static int gdr_mr_is_mapped(struct gdr_mr *mr)
{
	return mr->cpu_mapping_type != GDR_MR_NONE;
}

/**
 * Prerequisite:
 * - mr must be protected by down_read(mr->sem) or stronger.
 */
static int gdr_mr_is_wc_mapping(struct gdr_mr *mr)
{
	return (mr->cpu_mapping_type == GDR_MR_WC) ? 1 : 0;
}

static inline void gdrdrv_zap_vma(struct address_space *mapping, struct vm_area_struct *vma)
{
	// This function is mainly used for files and the address is relative to
	// the file offset. We use vma->pg_off here to unmap this entire range but
	// not the other mapped ranges.
	unmap_mapping_range(mapping, vma->vm_pgoff << PAGE_SHIFT, vma->vm_end - vma->vm_start, 0);
}

/**
 * Prerequisite:
 * - mr must be protected by down_write(mr->sem).
 */
static void gdr_mr_destroy_all_mappings(struct gdr_mr *mr)
{
	// there is a single mapping at the moment
	if (mr->vma)
		gdrdrv_zap_vma(mr->mapping, mr->vma);

	mr->cpu_mapping_type = GDR_MR_NONE;
}

//-----------------------------------------------------------------------------

struct gdr_info {
	// simple low-performance linked-list implementation
	struct list_head        mr_list;
	struct mutex            lock;

	// Pointer to the pid struct of the creator task group.
	// We do not use numerical pid here to avoid issues from pid reuse.
	struct pid             *tgid;

	// Address space unique to this opened file. We need to create a new one
	// because filp->f_mapping usually points to inode->i_mapping.
	struct address_space    mapping;

	// The handle number and mmap's offset are equivalent. However, the mmap
	// offset is used by the linux kernel when doing m(un)map; hence the range
	// cannot be overlapped. We place two ranges next two each other to avoid
	// this issue.
	gdr_hnd_t               next_handle;
	int                     next_handle_overflow;
};

static int gdrdrv_check_same_process(struct gdr_info *info, struct task_struct *tsk)
{
	int same_proc;

	WARN_ON(info == 0);
	WARN_ON(tsk == 0);
	same_proc = (info->tgid == task_tgid(tsk)) ; // these tasks belong to the same task group
	if (!same_proc) {
		gdr_dbg("check failed, info:{tgid=%lx} this tsk={tgid=%lx}\n",
				(unsigned long)info->tgid, (unsigned long)task_tgid(tsk));
	}
	return same_proc;
}

//-----------------------------------------------------------------------------

static int gdrdrv_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct gdr_info *info = NULL;

	info = kzalloc(sizeof(struct gdr_info), GFP_KERNEL);
	if (!info) {
		gdr_err("can't alloc kernel memory\n");
		ret = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&info->mr_list);
	mutex_init(&info->lock);

	// GPU driver does not support sharing GPU allocations at fork time. Hence
	// here we track the task group owning the driver fd and prevent other processes
	// to use it.
	info->tgid = task_tgid(current);

	address_space_init_once(&info->mapping);
	info->mapping.host = inode;
	info->mapping.a_ops = inode->i_mapping->a_ops;
#if KERNEL_VERSION(4, 0, 0) > LINUX_VERSION_CODE
	info->mapping.backing_dev_info = inode->i_mapping->backing_dev_info;
#endif
	filp->f_mapping = &info->mapping;

	filp->private_data = info;

out:
	return ret;
}

//-----------------------------------------------------------------------------

/**
 * Clean up and free all resources (e.g., page_table) associated with this mr.
 *
 * Prerequisites:
 * - mr->sem must be under down_write before calling this function.
 * - There is no mapping associated with this mr.
 *
 * After this function returns, mr is freed and cannot be accessed anymore.
 *
 */
static void gdr_free_mr_unlocked(struct gdr_mr *mr)
{
	int status = 0;
	struct sg_table *page_table;

	WARN_ON(!mr);
	WARN_ON(gdr_mr_is_mapped(mr));

	page_table = mr->page_table;
	if (page_table) {
		gdr_info("invoking cn_p2p_put_pages(va=0x%lx p2p_tok=%lx va_tok=%lx)\n",
				(unsigned long)mr->va, (unsigned long)mr->p2p_token, (unsigned long)mr->va_space);

		// We reach here before gdrdrv_get_pages_free_callback.
		// However, it might be waiting on semaphore.
		// Release the semaphore to let it progresses.
		up_write(&mr->sem);

		status = cn_mem_gdr_linear_unremap(mr->va, page_table);
		if (status) {
			gdr_err("cn_p2p_put_pages error %d, async callback may have been fired\n", status);
		}
	} else {
		gdr_dbg("invoking unpin_buffer while callback has already been fired\n");

		// From this point, no other code paths will access this mr.
		// We release semaphore and clear the mr.
		up_write(&mr->sem);
	}

	memset(mr, 0, sizeof(*mr));
	kfree(mr);
}


//-----------------------------------------------------------------------------

static int gdrdrv_release(struct inode *inode, struct file *filp)
{
	struct gdr_info *info = filp->private_data;
	struct gdr_mr *mr = NULL;
	struct list_head *p, *n;

	gdr_dbg("closing\n");

	if (!info) {
		gdr_err("filp contains no info\n");
		return -EIO;
	}
	// Check that the caller is the same process that did gdrdrv_open
	if (!gdrdrv_check_same_process(info, current)) {
		gdr_dbg("filp is not opened by the current process\n");
		return -EACCES;
	}

	mutex_lock(&info->lock);
	list_for_each_safe(p, n, &info->mr_list) {

		mr = list_entry(p, struct gdr_mr, node);

		down_write(&mr->sem);
		gdr_info("freeing MR=0x%lx\n", (unsigned long)mr);

		if (gdr_mr_is_mapped(mr)) {
			gdr_mr_destroy_all_mappings(mr);
		}

		list_del(&mr->node);

		gdr_free_mr_unlocked(mr);
	}
	mutex_unlock(&info->lock);

	filp->f_mapping = NULL;

	kfree(info);
	filp->private_data = NULL;

	return 0;
}

//-----------------------------------------------------------------------------

static struct gdr_mr *gdr_mr_from_handle_unlocked(struct gdr_info *info, gdr_hnd_t handle)
{
	struct gdr_mr *mr = NULL;
	struct list_head *p;

	list_for_each(p, &info->mr_list) {
		mr = list_entry(p, struct gdr_mr, node);
		gdr_dbg("mr->handle=0x%lx handle=0x%lx\n", (unsigned long)mr->handle, (unsigned long)handle);
		if (handle == mr->handle)
			break;
	}

	return mr;
}

/**
 * Convert handle to mr and semaphore-acquire it with read or write.
 * If success, that mr is guaranteed to be available until gdr_put_mr is called.
 * On success, return mr. Otherwise, return NULL.
 */
static inline struct gdr_mr *gdr_get_mr_from_handle(struct gdr_info *info, gdr_hnd_t handle, int write)
{
	struct gdr_mr *mr;

	mutex_lock(&info->lock);
	mr = gdr_mr_from_handle_unlocked(info, handle);
	if (mr) {
		if (write)
			down_write(&mr->sem);
		else
			down_read(&mr->sem);
	}
	mutex_unlock(&info->lock);
	return mr;
}

#define gdr_get_mr_from_handle_read(info, handle)   (gdr_get_mr_from_handle((info), (handle), 0))
#define gdr_get_mr_from_handle_write(info, handle)  (gdr_get_mr_from_handle((info), (handle), 1))

//-----------------------------------------------------------------------------

/**
 * Put the mr object. The `write` parameter must match the previous gdr_get_mr_from_handle call.
 * After this function returns, mr may cease to exist (freed). It must not be accessed again.
 */
static inline void gdr_put_mr(struct gdr_mr *mr, int write)
{
	if (write)
		up_write(&mr->sem);
	else
		up_read(&mr->sem);
}

#define gdr_put_mr_read(mr)     (gdr_put_mr((mr), 0))
#define gdr_put_mr_write(mr)    (gdr_put_mr((mr), 1))

//-----------------------------------------------------------------------------
// off is host page aligned, because of the kernel interface
// could abuse extra available bits for other purposes

static gdr_hnd_t gdrdrv_handle_from_off(unsigned long off)
{
	return (gdr_hnd_t)(off);
}

//-----------------------------------------------------------------------------

/**
 * Generate mr->handle. This function should be called under info->lock.
 *
 * Prerequisite:
 * - mr->mapped_size is set and round to max(PAGE_SIZE, GPU_PAGE_SIZE)
 * - mr->sem must be under down_write before calling this function.
 *
 * Return 0 if success, -1 if failed.
 */
static inline int gdr_generate_mr_handle(struct gdr_info *info, struct gdr_mr *mr)
{
	// The user-space library passes the memory (handle << PAGE_SHIFT) as the
	// mmap offset, and offsets are used to determine the VMAs to delete during
	// invalidation.
	// Hence, we need [(handle << PAGE_SHIFT), (handle << PAGE_SHIFT) + size - 1]
	// to correspond to a unique VMA.  Note that size here must match the
	// original mmap size

	gdr_hnd_t next_handle;

	WARN_ON(!mutex_is_locked(&info->lock));

	// We run out of handle, so fail.
	if (unlikely(info->next_handle_overflow)) {
		return -1;
	}

	next_handle = info->next_handle + (mr->mapped_size >> PAGE_SHIFT);

	// The next handle will be overflowed, so we mark it.
	if (unlikely((next_handle & ((gdr_hnd_t)(-1) >> PAGE_SHIFT)) < info->next_handle))
		info->next_handle_overflow = 1;

	mr->handle = info->next_handle;
	info->next_handle = next_handle;

	return 0;
}

//-----------------------------------------------------------------------------

static int __gdrdrv_pin_buffer(struct gdr_info *info, u64 addr, u64 size,
	u64 p2p_token, u32 va_space, gdr_hnd_t *p_handle)
{
	int ret = 0;
	struct sg_table *page_table;
	int i = 0;
	struct scatterlist *sg = NULL;
	u64 page_virt_start;
	u64 page_virt_end;
	u64 tmp_size;
	u64 paddr;
	size_t rounded_size;
	struct gdr_mr *mr = NULL;
#ifndef CONFIG_ARM64
	cycles_t ta, tb;
#endif

	mr = kmalloc(sizeof(struct gdr_mr), GFP_KERNEL);
	if (!mr) {
		gdr_err("can't alloc kernel memory\n");
		ret = -ENOMEM;
		goto out;
	}
	memset(mr, 0, sizeof(*mr));

	// do proper alignment, as required by RM
	page_virt_start  = addr & GPU_PAGE_MASK;
	page_virt_end    = addr + size - 1;
	rounded_size     = page_virt_end - page_virt_start + 1;

	init_rwsem(&mr->sem);

	mr->offset       = addr & GPU_PAGE_OFFSET;
	mr->length       = size;
	mr->p2p_token    = p2p_token;
	mr->va_space     = va_space;
	mr->va           = page_virt_start;
	mr->mapped_size  = rounded_size;
	mr->cpu_mapping_type = GDR_MR_NONE;
	mr->page_table   = 0;
	mr->cb_flag      = 0;
	mr->page_size = 4*1024;
	gdr_info("invoking cn_p2p_get_pages(va=0x%lx len=%lx p2p_tok=%lx va_tok=%lx)\n",
			(unsigned long)mr->va, (unsigned long)mr->mapped_size,
			(unsigned long)mr->p2p_token, (unsigned long)mr->va_space);

#ifndef CONFIG_ARM64
	ta = get_cycles();
#endif

	mutex_lock(&info->lock);
	// mr setup must be done before calling that API. The memory barrier is included in down_write.

	// We take this semaphore to prevent race with gdrdrv_get_pages_free_callback.
	down_write(&mr->sem);
	ret = cn_mem_gdr_linear_remap(mr->va, mr->length,(void **)&page_table);
	//                         gdrdrv_get_pages_free_callback, mr);
#ifndef CONFIG_ARM64
	tb = get_cycles();
#endif
	if (ret < 0) {
		gdr_err("cn_p2p_get_pages(va=%lx len=%lx p2p_token=%lx va_space=%x) failed [ret = %d]\n",
				(unsigned long)mr->va, (unsigned long)mr->mapped_size,
				(unsigned long)mr->p2p_token, mr->va_space, ret);
		goto out;
	}

	for_each_sg(page_table->sgl, sg, page_table->nents, i) {
		tmp_size = sg_dma_len(sg);
		paddr = sg_dma_address(sg);
		gdr_info("sg[%d], size 0x%llx, paddr 0x%llx", i, tmp_size, paddr);
	}

	gdr_info("page_table %llx", (u64)page_table);
	mr->page_table = page_table;
#ifndef CONFIG_ARM64
	mr->tm_cycles = tb - ta;
	mr->tsc_khz = get_tsc_khz();
#endif

	if (gdr_generate_mr_handle(info, mr) != 0) {
		gdr_err("No address space left for BAR1 mapping.\n");
		ret = -ENOMEM;
	}

	if (!ret) {
		list_add(&mr->node, &info->mr_list);
		*p_handle = mr->handle;
		up_write(&mr->sem);
	}

out:
	if (ret && mr) {
		gdr_free_mr_unlocked(mr);
		mr = NULL;
	}
	mutex_unlock(&info->lock);
	return ret;
}

//-----------------------------------------------------------------------------

static int __gdrdrv_unpin_buffer(struct gdr_info *info, gdr_hnd_t handle)
{
	int ret = 0;

	struct gdr_mr *mr = NULL;

	// someone might try to traverse the list and/or to do something
	// to the mr at the same time, so let's lock here
	mutex_lock(&info->lock);
	mr = gdr_mr_from_handle_unlocked(info, handle);
	if (mr == NULL) {
		gdr_err("unexpected handle %lx while unmapping buffer\n", (unsigned long)handle);
		ret = -EINVAL;
	} else {
		// Found the mr. Let's lock it.
		down_write(&mr->sem);
		if (gdr_mr_is_mapped(mr)) {
			gdr_mr_destroy_all_mappings(mr);
		}

		// Remove this handle from the list under info->lock.
		// Now race with gdrdrv_get_pages_free_callback is the only thing we need to care about.
		list_del(&mr->node);
	}
	mutex_unlock(&info->lock);

	if (ret)
		goto out;

	gdr_free_mr_unlocked(mr);

out:
	return ret;
}

//-----------------------------------------------------------------------------

static int gdrdrv_pin_buffer(struct gdr_info *info, void __user *_params)
{
	int ret = 0;

	struct GDRDRV_IOC_PIN_BUFFER_PARAMS params = {0};

	int has_handle = 0;
	gdr_hnd_t handle;

	if (copy_from_user(&params, _params, sizeof(params))) {
		gdr_err("copy_from_user failed on user pointer 0x%lx\n", (unsigned long)_params);
		ret = -EFAULT;
		goto out;
	}

	if (!params.addr) {
		gdr_err("NULL device pointer\n");
		ret = -EINVAL;
		goto out;
	}

	ret = __gdrdrv_pin_buffer(info, params.addr, params.size, params.p2p_token, params.va_space, &handle);
	if (ret)
		goto out;

	has_handle = 1;
	params.handle = handle;

	if (copy_to_user(_params, &params, sizeof(params))) {
		gdr_err("copy_to_user failed on user pointer 0x%lx\n", (unsigned long)_params);
		ret = -EFAULT;
	}


out:
	if (ret) {
		if (has_handle)
			__gdrdrv_unpin_buffer(info, handle);
	}

	return ret;
}

//-----------------------------------------------------------------------------

static int gdrdrv_unpin_buffer(struct gdr_info *info, void __user *_params)
{
	struct GDRDRV_IOC_UNPIN_BUFFER_PARAMS params = {0};
	int ret = 0;

	if (copy_from_user(&params, _params, sizeof(params))) {
		gdr_err("copy_from_user failed on user pointer 0x%lx\n", (unsigned long)_params);
		return -EFAULT;
	}

	ret = __gdrdrv_unpin_buffer(info, params.handle);

	return ret;
}

//-----------------------------------------------------------------------------

static int gdrdrv_get_cb_flag(struct gdr_info *info, void __user *_params)
{
	struct GDRDRV_IOC_GET_CB_FLAG_PARAMS params = {0};
	int ret = 0;
	struct gdr_mr *mr = NULL;

	if (copy_from_user(&params, _params, sizeof(params))) {
		gdr_err("copy_from_user failed on user pointer 0x%lx\n", (unsigned long)_params);
		return -EFAULT;
	}

	mr = gdr_get_mr_from_handle_read(info, params.handle);
	if (mr == NULL) {
		gdr_err("unexpected handle %lx in get_cb_flag\n", (unsigned long)params.handle);
		ret = -EINVAL;
		goto out;
	}

	params.flag = !!(mr->cb_flag);

	gdr_put_mr_read(mr);

	if (copy_to_user(_params, &params, sizeof(params))) {
		gdr_err("copy_to_user failed on user pointer 0x%lx\n", (unsigned long)_params);
		ret = -EFAULT;
	}

out:
	return ret;
}

//-----------------------------------------------------------------------------

static int gdrdrv_get_info(struct gdr_info *info, void __user *_params)
{
	struct GDRDRV_IOC_GET_INFO_PARAMS params = {0};
	int ret = 0;
	struct gdr_mr *mr = NULL;

	if (copy_from_user(&params, _params, sizeof(params))) {
		gdr_err("copy_from_user failed on user pointer 0x%lx\n", (unsigned long)_params);
		ret = -EFAULT;
		goto out;
	}

	mr = gdr_get_mr_from_handle_read(info, params.handle);
	if (mr == NULL) {
		gdr_err("unexpected handle %lx in get_cb_flag\n", (unsigned long)params.handle);
		ret = -EINVAL;
		goto out;
	}

	params.va          = mr->va;
	params.mapped_size = mr->mapped_size;
	params.page_size   = mr->page_size;
	params.tm_cycles   = mr->tm_cycles;
	params.tsc_khz     = mr->tsc_khz;
	params.mapped      = gdr_mr_is_mapped(mr);
	params.wc_mapping  = gdr_mr_is_wc_mapping(mr);

	gdr_put_mr_read(mr);

	if (copy_to_user(_params, &params, sizeof(params))) {
		gdr_err("copy_to_user failed on user pointer 0x%lx\n", (unsigned long)_params);
		ret = -EFAULT;
	}
out:
	return ret;
}

//-----------------------------------------------------------------------------

static int gdrdrv_get_version(struct gdr_info *info, void __user *_params)
{
	struct GDRDRV_IOC_GET_VERSION_PARAMS params = {0};
	int ret = 0;

	params.gdrdrv_version = GDRDRV_VERSION;
	params.minimum_gdr_api_version = MINIMUM_GDR_API_VERSION;

	if (copy_to_user(_params, &params, sizeof(params))) {
		gdr_err("copy_to_user failed on user pointer %lx\n", (unsigned long)_params);
		ret = -EFAULT;
	}

	return ret;
}

//-----------------------------------------------------------------------------

static int gdrdrv_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct gdr_info *info = filp->private_data;
	void __user *argp = (void __user *)arg;

	gdr_dbg("ioctl called (cmd 0x%x)\n", cmd);

	if (_IOC_TYPE(cmd) != GDRDRV_IOCTL) {
		gdr_err("malformed IOCTL code type=%08x\n", _IOC_TYPE(cmd));
		return -EINVAL;
	}

	if (!info) {
		gdr_err("filp contains no info\n");
		return -EIO;
	}
	// Check that the caller is the same process that did gdrdrv_open
	if (!gdrdrv_check_same_process(info, current)) {
		gdr_dbg("filp is not opened by the current process\n");
		return -EACCES;
	}

	switch (cmd) {
	case GDRDRV_IOC_PIN_BUFFER:
		ret = gdrdrv_pin_buffer(info, argp);
		break;

	case GDRDRV_IOC_UNPIN_BUFFER:
		ret = gdrdrv_unpin_buffer(info, argp);
		break;

	case GDRDRV_IOC_GET_CB_FLAG:
		ret = gdrdrv_get_cb_flag(info, argp);
		break;

	case GDRDRV_IOC_GET_INFO:
		ret = gdrdrv_get_info(info, argp);
		break;

	case GDRDRV_IOC_GET_VERSION:
		ret = gdrdrv_get_version(info, argp);
		break;

	default:
		gdr_err("unsupported IOCTL code\n");
		ret = -ENOTTY;
	}
	return ret;
}

//-----------------------------------------------------------------------------

#ifdef HAVE_UNLOCKED_IOCTL
static long gdrdrv_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return gdrdrv_ioctl(0, filp, cmd, arg);
}
#endif

/*----------------------------------------------------------------------------*/

void gdrdrv_vma_close(struct vm_area_struct *vma)
{
	struct gdr_mr *mr = (struct gdr_mr *)vma->vm_private_data;

	gdr_dbg("closing vma=0x%lx vm_file=0x%lx vm_private_data=0x%lx mr=0x%lx mr->vma=0x%lx\n",
			(unsigned long)vma, (unsigned long)vma->vm_file,
			(unsigned long)vma->vm_private_data, (unsigned long)mr,
			(unsigned long)mr->vma);
	// TODO: handle multiple vma's
	mr->vma = NULL;
	mr->cpu_mapping_type = GDR_MR_NONE;
}

/*----------------------------------------------------------------------------*/

static const struct vm_operations_struct gdrdrv_vm_ops = {
	.close = gdrdrv_vma_close,
};

/*----------------------------------------------------------------------------*/
static int gdrdrv_remap_gpu_mem(struct vm_area_struct *vma, unsigned long vaddr, unsigned long paddr, size_t size)
{
	int ret = 0;
	unsigned long pfn;

	gdr_dbg("mmaping phys mem addr=0x%lx size=%zu at user virt addr=0x%lx\n",
			paddr, size, vaddr);

	if (!size) {
		gdr_dbg("size == 0\n");
		goto out;
	}
	// in case the original user address was not properly host page-aligned
	if (0 != (paddr & (PAGE_SIZE-1))) {
		gdr_err("paddr=%lx, original mr address was not host page-aligned\n", paddr);
		ret = -EINVAL;
		goto out;
	}
	if (0 != (vaddr & (PAGE_SIZE-1))) {
		gdr_err("vaddr=%lx, trying to map to non page-aligned vaddr\n", vaddr);
		ret = -EINVAL;
		goto out;
	}
	pfn = paddr >> PAGE_SHIFT;

	// Disallow mmapped VMA to propagate to children processes
	vma->vm_flags |= VM_DONTCOPY;

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	if (io_remap_pfn_range(vma, vaddr, pfn, size, vma->vm_page_prot)) {
		gdr_err("error in remap_pfn_range()\n");
		ret = -EAGAIN;
		goto out;
	}

out:
	return ret;
}
//-----------------------------------------------------------------------------
// BUG: should obtain GPU_PAGE_SIZE from page_table!!!

static int gdrdrv_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret = 0;
	//int p = 0;
	int i = 0;
	size_t size = vma->vm_end - vma->vm_start;
	struct gdr_info *info = filp->private_data;
	gdr_hnd_t handle;
	struct gdr_mr *mr = NULL;
	struct scatterlist *osg = NULL;
	struct scatterlist *sg = NULL;
	u64 offset;
	u64 sg_size = 0;
	u64 len = 0;
	u64 tmp_size = 0;
	unsigned long vaddr;
	unsigned long paddr;

	if (!info) {
		gdr_err("filp contains no info\n");
		return -EIO;
	}
	// Check that the caller is the same process that did gdrdrv_open
	if (!gdrdrv_check_same_process(info, current)) {
		gdr_dbg("filp is not opened by the current process\n");
		return -EACCES;
	}

	handle = gdrdrv_handle_from_off(vma->vm_pgoff);
	mr = gdr_get_mr_from_handle_write(info, handle);
	if (!mr) {
		gdr_dbg("cannot find handle in mr_list\n");
		ret = -EINVAL;
		goto out;
	}
	offset = mr->offset;
	if (gdr_mr_is_mapped(mr)) {
		gdr_dbg("mr has been mapped already\n");
		ret = -EINVAL;
		goto out;
	}
	if (mr->cb_flag) {
		gdr_dbg("mr has been invalidated\n");
		ret = -EINVAL;
		goto out;
	}
	if (!mr->page_table) {
		gdr_dbg("invalid mr state\n");
		ret = -EINVAL;
		goto out;
	}
	if (offset) {
		gdr_dbg("offset != 0 is not supported\n");
		ret = -EINVAL;
		goto out;
	}
	if (mr->page_table->nents <= 0) {
		gdr_dbg("invalid entries in page table\n");
		ret = -EINVAL;
		goto out;
	}

	osg = mr->page_table->sgl;
	for_each_sg(osg, sg, mr->page_table->nents, i) {
		sg_size += sg_dma_len(sg);
	}
	if (size + offset > sg_size) {
		gdr_dbg("size %zu too big\n", size);
		ret = -EINVAL;
		goto out;
	}
	if (size % PAGE_SIZE != 0) {
		gdr_dbg("size is not multiple of PAGE_SIZE\n");
	}
	// let's assume this mapping is not WC
	// this also works as the mapped flag for this mr
	mr->cpu_mapping_type = GDR_MR_CACHING;
	vma->vm_ops = &gdrdrv_vm_ops;
	gdr_dbg("overwriting vma->vm_private_data=%lx with mr=%lx\n",
			(unsigned long)vma->vm_private_data, (unsigned long)mr);
	vma->vm_private_data = mr;

	// check for physically contiguous IO ranges
	vaddr = vma->vm_start;
	mr->cpu_mapping_type = GDR_MR_WC;
	for_each_sg(osg, sg, mr->page_table->nents, i) {
		tmp_size = sg_dma_len(sg);
		paddr = sg_dma_address(sg);

		len = MIN(size, tmp_size);
		ret = gdrdrv_remap_gpu_mem(vma, vaddr, paddr, len);
		if (ret) {
			gdr_err("error %d in gdrdrv_remap_gpu_mem\n", ret);
			goto out;
		}
		size -= len;
		vaddr += len;
		if (size == 0) {
			break;
		}
	}

	if (vaddr != vma->vm_end) {
		gdr_err("vaddr=%lx != vm_end=%lx\n", (unsigned long)vaddr, (unsigned long)vma->vm_end);
		ret = -EINVAL;
	}

out:
	if (ret) {
		if (mr) {
			mr->vma = NULL;
			mr->mapping = NULL;
			mr->cpu_mapping_type = GDR_MR_NONE;
		}
	} else {
		mr->vma = vma;
		mr->mapping = filp->f_mapping;
		gdr_dbg("mr vma=0x%lx mapping=0x%lx\n", (unsigned long)mr->vma, (unsigned long)mr->mapping);
	}

	if (mr)
		gdr_put_mr_write(mr);

	return ret;
}

struct file_operations const gdrdrv_fops = {
	.owner    = THIS_MODULE,

#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl = gdrdrv_unlocked_ioctl,
#else
	.ioctl    = gdrdrv_ioctl,
#endif
	.open     = gdrdrv_open,
	.release  = gdrdrv_release,
	.mmap     = gdrdrv_mmap
};

struct miscdevice misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "cambricon_gdr",
	.fops = &gdrdrv_fops
};
static int __init gdrdrv_init(void)
{
	misc.mode = 0666;
	misc_register(&misc);
	gdr_err("load module success!\r\n");
	return 0;
}

static void __exit gdrdrv_exit(void)
{
	gdr_err("unregister gdrdrv!\n");
	misc_deregister(&misc);
}
module_init(gdrdrv_init);
module_exit(gdrdrv_exit);
module_param(dbg_enabled, int, 0000);
MODULE_PARM_DESC(dbg_enabled, "enable debug tracing");
module_param(info_enabled, int, 0000);
MODULE_PARM_DESC(info_enabled, "enable info tracing");
MODULE_DESCRIPTION("Cambricon gdrcopy Module");
MODULE_LICENSE("GPL v2");
