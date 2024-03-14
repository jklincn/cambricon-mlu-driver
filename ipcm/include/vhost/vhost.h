#ifndef _VHOST_H
#define _VHOST_H

#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/virtio_config.h>
#include <linux/atomic.h>
#include <linux/genalloc.h>
#include "vringh.h"

struct vhost_work;
typedef void (*vhost_work_fn_t)(struct vhost_work *work);

#define VHOST_WORK_QUEUED 1
struct vhost_work {
	struct llist_node	  node;
	vhost_work_fn_t		  fn;
	wait_queue_head_t	  done;
	int			  flushing;
	unsigned int		  queue_seq;
	unsigned int		  done_seq;
	unsigned long		  flags;
};

/* Poll a file (eventfd or socket) */
/* Note: there's nothing vhost specific about this structure. */
struct vhost_poll {
	poll_table                table;
	wait_queue_head_t        *wqh;
	//wait_queue_t              wait;
	struct vhost_work	  work;
	unsigned long		  mask;
	struct vhost_dev	 *dev;
};

void vhost_work_init(struct vhost_work *work, vhost_work_fn_t fn);
void vhost_work_queue(struct vhost_dev *dev, struct vhost_work *work);
bool vhost_has_work(struct vhost_dev *dev);

void vhost_poll_init(struct vhost_poll *poll, vhost_work_fn_t fn,
		     unsigned long mask, struct vhost_dev *dev);
int vhost_poll_start(struct vhost_poll *poll, struct file *file);
void vhost_poll_stop(struct vhost_poll *poll);
void vhost_poll_flush(struct vhost_poll *poll);
void vhost_poll_queue(struct vhost_poll *poll);
void vhost_work_flush(struct vhost_dev *dev, struct vhost_work *work);
long vhost_vring_ioctl(struct vhost_dev *d, int ioctl, void __user *argp);

struct vhost_log {
	u64 addr;
	u64 len;
};

#define START(node) ((node)->start)
#define LAST(node) ((node)->last)

struct vhost_umem_node {
	struct rb_node rb;
	struct list_head link;
	__u64 start;
	__u64 last;
	__u64 size;
	__u64 userspace_addr;
	__u32 perm;
	__u32 flags_padding;
	__u64 __subtree_last;
};

struct vhost_umem {
	struct rb_root umem_tree;
	struct list_head umem_list;
	int numem;
};

enum vhost_type {
	VHOST_TYPE_UNKNOWN,
	VHOST_TYPE_USER,
	VHOST_TYPE_KERN,
	VHOST_TYPE_MMIO,
};

/* The virtqueue structure describes a queue attached to a device. */
struct vhost_virtqueue {
	struct vhost_dev *dev;
	enum vhost_type type;
	struct vringh vringh;
	void (*callback)(struct vhost_virtqueue *vq);
	void (*notify)(struct vhost_virtqueue *vq);
	unsigned long intr_cnt;
	unsigned long msg_cnt;
	phys_addr_t pa_base;
	unsigned long va_base;
	size_t size;

	/* The actual ring of buffers. */
	struct mutex mutex;
	unsigned int num;
	struct vring_desc __user *desc;
	struct vring_avail __user *avail;
	struct vring_used __user *used;
	struct file *kick;
	struct file *call;
	struct file *error;
	struct eventfd_ctx *call_ctx;
	struct eventfd_ctx *error_ctx;
	struct eventfd_ctx *log_ctx;

	struct vhost_poll poll;

	/* The routine to call when the Guest pings us, or timeout. */
	vhost_work_fn_t handle_kick;

	/* Last available index we saw. */
	u16 last_avail_idx;

	/* Caches available index value from user. */
	u16 avail_idx;

	/* Last index we used. */
	u16 last_used_idx;

	/* Used flags */
	u16 used_flags;

	/* Last used index value we have signalled on */
	u16 signalled_used;

	/* Last used index value we have signalled on */
	bool signalled_used_valid;

	/* Log writes to used structure. */
	bool log_used;
	u64 log_addr;

	struct iovec iov[UIO_MAXIOV];
	struct iovec iotlb_iov[64];
	struct iovec *indirect;
	struct vring_used_elem *heads;
	/* Protected by virtqueue mutex. */
	struct vhost_umem *umem;
	struct vhost_umem *iotlb;
	void *private_data;
	u64 acked_features;
	/* Log write descriptors */
	void __user *log_base;
	struct vhost_log *log;

	/* Ring endianness. Defaults to legacy native endianness.
	 * Set to true when starting a modern virtio device.
	 */
	bool is_le;
#ifdef CONFIG_VHOST_CROSS_ENDIAN_LEGACY
	/* Ring endianness requested by userspace for cross-endian support. */
	bool user_be;
#endif
	u32 busyloop_timeout;
};

struct vhost_msg_node {
	struct vhost_msg msg;
	struct vhost_virtqueue *vq;
	struct list_head node;
};

enum vhost_notify_event {
	NOTIFY_SET_STATUS,
	NOTIFY_FINALIZE_FEATURES,
	NOTIFY_RESET,
};

typedef void vhost_vq_callback_t(struct vhost_virtqueue *);
/**
 * struct vhost_config_ops - set of function pointers for performing vhost
 *   device specific operation
 * @create_vqs: ops to create vhost virtqueue
 * @del_vqs: ops to delete vhost virtqueue
 * @write: ops to write data to buffer provided by remote virtio driver
 * @read: ops to read data from buffer provided by remote virtio driver
 * @set_features: ops to set vhost device features
 * @set_status: ops to set vhost device status
 * @get_status: ops to get vhost device status
 */
struct vhost_config_ops {
	int (*create_vqs)(struct vhost_dev *vdev, unsigned int nvqs,
			  unsigned int num_bufs, struct vhost_virtqueue *vqs[],
			  vhost_vq_callback_t *callbacks[],
			  const char * const names[]);
	void (*del_vqs)(struct vhost_dev *vdev);
	void (*reset_vqs)(struct vhost_dev *vdev);
	int (*write)(struct vhost_dev *vdev, u64 vhost_dst, void *src, int len);
	int (*read)(struct vhost_dev *vdev, void *dst, u64 vhost_src, int len);
	int (*set_features)(struct vhost_dev *vdev, u64 device_features);
	int (*set_status)(struct vhost_dev *vdev, u8 status);
	u8 (*get_status)(struct vhost_dev *vdev);
};

struct vhost_driver {
	struct device_driver driver;
	struct virtio_device_id *id_table;
	int (*probe)(struct vhost_dev *dev);
	int (*remove)(struct vhost_dev *dev);
};

#define to_vhost_driver(drv) (container_of((drv), struct vhost_driver, driver))

struct vhost_dev {
	struct device dev;
	struct vhost_driver *driver;
	struct virtio_device_id id;
	int index;
	const struct vhost_config_ops *ops;
	struct blocking_notifier_head notifier;
	struct mm_struct *mm;
	struct mutex mutex;
	struct vhost_virtqueue **vqs;
	u64 features;
	int nvqs;
	struct file *log_file;
	struct eventfd_ctx *log_ctx;
	struct llist_head work_list;
	struct task_struct *worker;
	struct vhost_umem *umem;
	struct vhost_umem *iotlb;
	spinlock_t iotlb_lock;
	struct list_head read_list;
	struct list_head pending_list;
	wait_queue_head_t wait;
	bool vf_start;
	bool outbound;
	struct gen_pool *OB_pool;
};

static inline bool vhost_get_outbound(struct vhost_dev *vdev)
{
	return vdev->outbound;
}

static inline void vhost_init_mem_region(struct vhost_virtqueue *vq, phys_addr_t pa, unsigned long va, size_t size)
{
	dev_info(&vq->dev->dev, "%s, 0x%llx<--->0x%lx, size:0x%zx!\n", __func__, pa, va, size);
	vq->pa_base = pa;
	vq->va_base = va;
	vq->size = size;
}

static inline void *vhost_phys_to_virt(struct vhost_virtqueue *vq, phys_addr_t phys)
{
	/* sanity check */
	if (phys >= vq->pa_base && phys <= (vq->pa_base + vq->size))
		return (void *)(vq->va_base + (phys - vq->pa_base));
	dev_err(&vq->dev->dev, "%s, invalid pa(0x%llx)!!!\n", __func__, phys);
	return NULL;
}

#define to_vhost_dev(d) container_of((d), struct vhost_dev, dev)

static inline void vhost_set_drvdata(struct vhost_dev *vdev, void *data)
{
	dev_set_drvdata(&vdev->dev, data);
}

static inline void *vhost_get_drvdata(struct vhost_dev *vdev)
{
	return dev_get_drvdata(&vdev->dev);
}

int vhost_register_driver(struct vhost_driver *driver);
void vhost_unregister_driver(struct vhost_driver *driver);
int vhost_register_device(struct vhost_dev *vdev);
void vhost_unregister_device(struct vhost_dev *vdev);

int vhost_create_vqs(struct vhost_dev *vdev, unsigned int nvqs,
		     unsigned int num_bufs, struct vhost_virtqueue *vqs[],
		     vhost_vq_callback_t *callbacks[],
		     const char * const names[]);
void vhost_del_vqs(struct vhost_dev *vdev);
void vhost_reset_vqs(struct vhost_dev *vdev);
int vhost_write(struct vhost_dev *vdev, u64 vhost_dst, void *src, int len);
int vhost_read(struct vhost_dev *vdev, void *dst, u64 vhost_src, int len);
int vhost_set_features(struct vhost_dev *vdev, u64 device_features);
u64 vhost_get_features(struct vhost_dev *vdev);
int vhost_set_status(struct vhost_dev *vdev, u8 status);
u8 vhost_get_status(struct vhost_dev *vdev);

int vhost_register_notifier(struct vhost_dev *vdev, struct notifier_block *nb);

void *vhost_virtqueue_get_outbuf(struct vhost_virtqueue *vq, u16 *head, int *len);
void *vhost_virtqueue_get_inbuf(struct vhost_virtqueue *vq, u16 *head, int *len);
int vhost_virtqueue_put_buf(struct vhost_virtqueue *vq, u16 head, int len);

void vhost_virtqueue_disable_cb(struct vhost_virtqueue *vq);
bool vhost_virtqueue_enable_cb(struct vhost_virtqueue *vq);
void vhost_virtqueue_notify(struct vhost_virtqueue *vq);
void vhost_virtqueue_kick(struct vhost_virtqueue *vq);
void vhost_virtqueue_callback(struct vhost_virtqueue *vq);
void vhost_dev_init(struct vhost_dev *dev, struct vhost_virtqueue **vqs, int nvqs);
long vhost_dev_set_owner(struct vhost_dev *dev);
bool vhost_dev_has_owner(struct vhost_dev *dev);
long vhost_dev_check_owner(struct vhost_dev *dev);
struct vhost_umem *vhost_dev_reset_owner_prepare(void);
void vhost_dev_reset_owner(struct vhost_dev *dev, struct vhost_umem *umem);
void vhost_dev_cleanup(struct vhost_dev *dev, bool locked);
void vhost_dev_stop(struct vhost_dev *dev);
long vhost_dev_ioctl(struct vhost_dev *dev, unsigned int ioctl, void __user *argp);
long vhost_vring_ioctl(struct vhost_dev *d, int ioctl, void __user *argp);
int vhost_vq_access_ok(struct vhost_virtqueue *vq);
int vhost_log_access_ok(struct vhost_dev *dev);

int vhost_get_vq_desc(struct vhost_virtqueue *vq,
		      struct iovec iov[], unsigned int iov_count,
		      unsigned int *out_num, unsigned int *in_num,
		      struct vhost_log *log, unsigned int *log_num);
void vhost_discard_vq_desc(struct vhost_virtqueue *vq, int n);

int vhost_vq_init_access(struct vhost_virtqueue *vq);
int vhost_add_used(struct vhost_virtqueue *vq, unsigned int head, int len);
int vhost_add_used_n(struct vhost_virtqueue *vq, struct vring_used_elem *heads,
		     unsigned int count);
void vhost_add_used_and_signal(struct vhost_dev *dev, struct vhost_virtqueue *vq,
			       unsigned int id, int len);
void vhost_add_used_and_signal_n(struct vhost_dev *dev, struct vhost_virtqueue *vq,
			       struct vring_used_elem *heads, unsigned int count);
void vhost_signal(struct vhost_dev *dev, struct vhost_virtqueue *vq);
void vhost_disable_notify(struct vhost_dev *dev, struct vhost_virtqueue *vq);
bool vhost_vq_avail_empty(struct vhost_dev *dev, struct vhost_virtqueue *vq);
bool vhost_enable_notify(struct vhost_dev *dev, struct vhost_virtqueue *vq);

int vhost_log_write(struct vhost_virtqueue *vq, struct vhost_log *log,
		    unsigned int log_num, u64 len);
int vq_iotlb_prefetch(struct vhost_virtqueue *vq);

struct vhost_msg_node *vhost_new_msg(struct vhost_virtqueue *vq, int type);
void vhost_enqueue_msg(struct vhost_dev *dev,
		       struct list_head *head,
		       struct vhost_msg_node *node);
struct vhost_msg_node *vhost_dequeue_msg(struct vhost_dev *dev,
					 struct list_head *head);
unsigned int vhost_chr_poll(struct file *file, struct vhost_dev *dev,
			    poll_table *wait);
ssize_t vhost_chr_read_iter(struct vhost_dev *dev, struct iov_iter *to,
			    int noblock);
ssize_t vhost_chr_write_iter(struct vhost_dev *dev,
			     struct iov_iter *from);
int vhost_init_device_iotlb(struct vhost_dev *d, bool enabled);

#define vq_err(vq, fmt, ...) do {                                  \
		pr_debug(pr_fmt(fmt), ##__VA_ARGS__);       \
		if ((vq)->error_ctx)                               \
			eventfd_signal((vq)->error_ctx, 1);\
	} while (0)

enum {
	VHOST_FEATURES = (1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) |
			 (1ULL << VIRTIO_RING_F_INDIRECT_DESC) |
			 (1ULL << VIRTIO_RING_F_EVENT_IDX) |
			 (1ULL << VHOST_F_LOG_ALL) |
			 (1ULL << VIRTIO_F_ANY_LAYOUT) |
			 (1ULL << VIRTIO_F_VERSION_1)
};

/**
 * vhost_vq_set_backend - Set backend.
 *
 * @vq            Virtqueue.
 * @private_data  The private data.
 *
 * Context: Need to call with vq->mutex acquired.
 */
static inline void vhost_vq_set_backend(struct vhost_virtqueue *vq,
					void *private_data)
{
	vq->private_data = private_data;
}

/**
 * vhost_vq_get_backend - Get backend.
 *
 * @vq            Virtqueue.
 *
 * Context: Need to call with vq->mutex acquired.
 * Return: Private data previously set with vhost_vq_set_backend.
 */
static inline void *vhost_vq_get_backend(struct vhost_virtqueue *vq)
{
	return vq->private_data;
}

static inline bool vhost_has_feature(struct vhost_dev *vdev, int bit)
{
	return vdev->features & (1ULL << bit);
}


#ifdef CONFIG_VHOST_CROSS_ENDIAN_LEGACY
static inline bool vhost_is_little_endian(struct vhost_virtqueue *vq)
{
	return vq->is_le;
}
#else
static inline bool vhost_is_little_endian(struct vhost_virtqueue *vq)
{
	return virtio_legacy_is_little_endian() || vq->is_le;
}
#endif

/* Memory accessors */
static inline u16 vhost16_to_cpu(struct vhost_virtqueue *vq, __virtio16 val)
{
	return __virtio16_to_cpu(vhost_is_little_endian(vq), val);
}

static inline __virtio16 cpu_to_vhost16(struct vhost_virtqueue *vq, u16 val)
{
	return __cpu_to_virtio16(vhost_is_little_endian(vq), val);
}

static inline u32 vhost32_to_cpu(struct vhost_virtqueue *vq, __virtio32 val)
{
	return __virtio32_to_cpu(vhost_is_little_endian(vq), val);
}

static inline __virtio32 cpu_to_vhost32(struct vhost_virtqueue *vq, u32 val)
{
	return __cpu_to_virtio32(vhost_is_little_endian(vq), val);
}

static inline u64 vhost64_to_cpu(struct vhost_virtqueue *vq, __virtio64 val)
{
	return __virtio64_to_cpu(vhost_is_little_endian(vq), val);
}

static inline __virtio64 cpu_to_vhost64(struct vhost_virtqueue *vq, u64 val)
{
	return __cpu_to_virtio64(vhost_is_little_endian(vq), val);
}

/* for core_initcall*/
int vhost_init(void);
void vhost_exit(void);
#endif
