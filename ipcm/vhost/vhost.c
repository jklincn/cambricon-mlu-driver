#include <linux/version.h>
#include "../include/vhost/vhost.h"

static DEFINE_IDA(vhost_index_ida);
static DEFINE_MUTEX(vhost_index_mutex);

/**
 * vhost_virtqueue_disable_cb_mmio() - Write to used ring in virtio accessed
 *   using MMIO to stop notification
 * @vq: vhost_virtqueue for which callbacks have to be disabled
 *
 * Write to used ring in virtio accessed using MMIO to stop sending notification
 * to the vhost virtqueue.
 */
static void vhost_virtqueue_disable_cb_mmio(struct vhost_virtqueue *vq)
{
	struct vringh *vringh;

	vringh = &vq->vringh;
	vringh_notify_disable_mmio(vringh);
}

/**
 * vhost_virtqueue_disable_cb() - Write to used ring in virtio to stop
 *   notification
 * @vq: vhost_virtqueue for which callbacks have to be disabled
 *
 * Wrapper to write to used ring in virtio to stop sending notification
 * to the vhost virtqueue.
 */
void vhost_virtqueue_disable_cb(struct vhost_virtqueue *vq)
{
	enum vhost_type type;

	type = vq->type;

	/* TODO: Add support for other VHOST TYPES */
	if (type == VHOST_TYPE_MMIO && vq->dev->vf_start)
		return vhost_virtqueue_disable_cb_mmio(vq);
}

/**
 * vhost_virtqueue_enable_cb_mmio() - Write to used ring in virtio accessed
 *   using MMIO to enable notification
 * @vq: vhost_virtqueue for which callbacks have to be enabled
 *
 * Write to used ring in virtio accessed using MMIO to enable notification
 * to the vhost virtqueue.
 */
static bool vhost_virtqueue_enable_cb_mmio(struct vhost_virtqueue *vq)
{
	struct vringh *vringh;

	vringh = &vq->vringh;
	return vringh_notify_enable_mmio(vringh);
}

/**
 * vhost_virtqueue_enable_cb() - Write to used ring in virtio to enable
 *   notification
 * @vq: vhost_virtqueue for which callbacks have to be enabled
 *
 * Wrapper to write to used ring in virtio to enable notification to the
 * vhost virtqueue.
 */
bool vhost_virtqueue_enable_cb(struct vhost_virtqueue *vq)
{
	enum vhost_type type;

	type = vq->type;

	/* TODO: Add support for other VHOST TYPES */
	if (type == VHOST_TYPE_MMIO && vq->dev->vf_start)
		return vhost_virtqueue_enable_cb_mmio(vq);

	return false;
}

/**
 * vhost_virtqueue_notify() - Send notification to the remote virtqueue
 * @vq: vhost_virtqueue that sends the notification
 *
 * Invokes ->notify() callback to send notification to the remote virtqueue.
 */
void vhost_virtqueue_notify(struct vhost_virtqueue *vq)
{
	if (!vq->notify)
		return;

	vq->notify(vq);
}

/**
 * vhost_virtqueue_kick_mmio() - Check if the remote virtqueue has enabled
 *   notification (by reading available ring in virtio accessed using MMIO)
 *   before sending notification
 * @vq: vhost_virtqueue that sends the notification
 *
 * Check if the remote virtqueue has enabled notification (by reading available
 * ring in virtio accessed using MMIO) and then invoke vhost_virtqueue_notify()
 * to send notification to the remote virtqueue.
 */
static void vhost_virtqueue_kick_mmio(struct vhost_virtqueue *vq)
{
	if (vringh_need_notify_mmio(&vq->vringh))
		vhost_virtqueue_notify(vq);
}

/**
 * vhost_virtqueue_kick() - Check if the remote virtqueue has enabled
 *   notification before sending notification
 * @vq: vhost_virtqueue that sends the notification
 *
 * Wrapper to send notification to the remote virtqueue using
 * vhost_virtqueue_kick_mmio() that checks if the remote virtqueue has
 * enabled notification before sending the notification.
 */
void vhost_virtqueue_kick(struct vhost_virtqueue *vq)
{
	enum vhost_type type;

	type = vq->type;

	/* TODO: Add support for other VHOST TYPES */
	if (type == VHOST_TYPE_MMIO && vq->dev->vf_start)
		return vhost_virtqueue_kick_mmio(vq);
}

/**
 * vhost_virtqueue_callback() - Invoke vhost virtqueue callback provided by
 *   vhost client driver
 * @vq: vhost_virtqueue for which the callback is invoked
 *
 * Invoked by the driver that creates vhost device when the remote virtio
 * driver sends notification to this virtqueue.
 */
void vhost_virtqueue_callback(struct vhost_virtqueue *vq)
{
	if (!vq->callback)
		return;

	vq->callback(vq);
}

/**
 * vhost_virtqueue_get_outbuf_mmio() - Get the output buffer address by reading
 *   virtqueue descriptor accessed using MMIO
 * @vq: vhost_virtqueue used to access the descriptor
 * @head: head index for passing to vhost_virtqueue_put_buf()
 * @len: Length of the buffer
 *
 * Get the output buffer address by reading virtqueue descriptor accessed using
 * MMIO.
 */
static void *vhost_virtqueue_get_outbuf_mmio(struct vhost_virtqueue *vq,
					   u16 *head, int *len)
{
	struct vringh_mmiov wiov;
	struct mmiovec *mmiovec;
	struct vringh *vringh;
	int desc;
	struct mmiovec _mmiovec;

	vringh = &vq->vringh;
	vringh_mmiov_init(&wiov, &_mmiovec, 1);

	desc = vringh_getdesc_mmio(vringh, NULL, &wiov, head, GFP_ATOMIC);
	if (desc <= 0)
		return NULL;
	mmiovec = &wiov.iov[0];

	*len = mmiovec->iov_len;
	dev_dbg(&vq->dev->dev, "head %d [out] 0x%llx\n", *head, mmiovec->iov_base);
	return vhost_phys_to_virt(vq, mmiovec->iov_base);
}

/**
 * vhost_virtqueue_get_outbuf() - Get the output buffer address by reading
 *   virtqueue descriptor
 * @vq: vhost_virtqueue used to access the descriptor
 * @head: head index for passing to vhost_virtqueue_put_buf()
 * @len: Length of the buffer
 *
 * Wrapper to get the output buffer address by reading virtqueue descriptor.
 */
void *vhost_virtqueue_get_outbuf(struct vhost_virtqueue *vq, u16 *head, int *len)
{
	enum vhost_type type;

	type = vq->type;

	/* TODO: Add support for other VHOST TYPES */
	if (type == VHOST_TYPE_MMIO && vq->dev->vf_start)
		return vhost_virtqueue_get_outbuf_mmio(vq, head, len);

	return NULL;
}

/**
 * vhost_virtqueue_get_inbuf_mmio() - Get the input buffer address by reading
 *   virtqueue descriptor accessed using MMIO
 * @vq: vhost_virtqueue used to access the descriptor
 * @head: Head index for passing to vhost_virtqueue_put_buf()
 * @len: Length of the buffer
 *
 * Get the input buffer address by reading virtqueue descriptor accessed using
 * MMIO.
 */
static void *vhost_virtqueue_get_inbuf_mmio(struct vhost_virtqueue *vq,
					  u16 *head, int *len)
{
	struct vringh_mmiov riov;
	struct mmiovec *mmiovec;
	struct vringh *vringh;
	int desc;
	struct mmiovec _mmiovec;

	vringh = &vq->vringh;
	vringh_mmiov_init(&riov, &_mmiovec, 1);

	desc = vringh_getdesc_mmio(vringh, &riov, NULL, head, GFP_ATOMIC);
	if (desc <= 0)
		return NULL;

	mmiovec = &riov.iov[0];

	*len = mmiovec->iov_len;
	dev_dbg(&vq->dev->dev, "head %d [in] 0x%llx\n", *head, mmiovec->iov_base);
	return vhost_phys_to_virt(vq, mmiovec->iov_base);
}

/**
 * vhost_virtqueue_get_inbuf() - Get the input buffer address by reading
 *   virtqueue descriptor
 * @vq: vhost_virtqueue used to access the descriptor
 * @head: head index for passing to vhost_virtqueue_put_buf()
 * @len: Length of the buffer
 *
 * Wrapper to get the input buffer address by reading virtqueue descriptor.
 */
void *vhost_virtqueue_get_inbuf(struct vhost_virtqueue *vq, u16 *head, int *len)
{
	enum vhost_type type;

	type = vq->type;

	/* TODO: Add support for other VHOST TYPES */
	if (type == VHOST_TYPE_MMIO && vq->dev->vf_start)
		return vhost_virtqueue_get_inbuf_mmio(vq, head, len);

	return NULL;
}

/**
 * vhost_virtqueue_put_buf_mmio() - Publish to the remote virtio (update
 * used ring in virtio using MMIO) to indicate the buffer has been processed
 * @vq: vhost_virtqueue used to update the used ring
 * @head: Head index receive from vhost_virtqueue_get_*()
 * @len: Length of the buffer
 *
 * Publish to the remote virtio (update used ring in virtio using MMIO) to
 * indicate the buffer has been processed
 */
static int vhost_virtqueue_put_buf_mmio(struct vhost_virtqueue *vq,
					 u16 head, int len)
{
	struct vringh *vringh;

	vringh = &vq->vringh;

	return vringh_complete_mmio(vringh, head, len);
}

/**
 * vhost_virtqueue_put_buf() - Publish to the remote virtio to indicate the
 *   buffer has been processed
 * @vq: vhost_virtqueue used to update the used ring
 * @head: Head index receive from vhost_virtqueue_get_*()
 * @len: Length of the buffer
 *
 * Wrapper to publish to the remote virtio to indicate the buffer has been
 * processed.
 */
int vhost_virtqueue_put_buf(struct vhost_virtqueue *vq, u16 head, int len)
{
	enum vhost_type type;

	type = vq->type;

	/* TODO: Add support for other VHOST TYPES */
	if (type == VHOST_TYPE_MMIO && vq->dev->vf_start)
		return vhost_virtqueue_put_buf_mmio(vq, head, len);
	return -EOPNOTSUPP;
}

/**
 * vhost_create_vqs() - Invoke vhost_config_ops to create virtqueue
 * @vdev: Vhost device that provides create_vqs() callback to create virtqueue
 * @nvqs: Number of vhost virtqueues to be created
 * @num_bufs: The number of buffers that should be supported by the vhost
 *   virtqueue (number of descriptors in the vhost virtqueue)
 * @vqs: Pointers to all the created vhost virtqueues
 * @callback: Callback function associated with the virtqueue
 * @names: Names associated with each virtqueue
 *
 * Wrapper that invokes vhost_config_ops to create virtqueue.
 */
int vhost_create_vqs(struct vhost_dev *vdev, unsigned int nvqs,
		     unsigned int num_bufs, struct vhost_virtqueue *vqs[],
		     vhost_vq_callback_t *callbacks[],
		     const char * const names[])
{
	int ret;

	if (IS_ERR_OR_NULL(vdev))
		return -EINVAL;

	if (!vdev->ops || !vdev->ops->create_vqs)
		return -EINVAL;

	mutex_lock(&vdev->mutex);
	ret = vdev->ops->create_vqs(vdev, nvqs, num_bufs, vqs, callbacks,
				    names);
	mutex_unlock(&vdev->mutex);

	return ret;
}

/* vhost_del_vqs - Invoke vhost_config_ops to delete the created virtqueues
 * @vdev: Vhost device that provides del_vqs() callback to delete virtqueue
 *
 * Wrapper that invokes vhost_config_ops to delete all the virtqueues
 * associated with the vhost device.
 */
void vhost_del_vqs(struct vhost_dev *vdev)
{
	if (IS_ERR_OR_NULL(vdev))
		return;

	if (!vdev->ops || !vdev->ops->del_vqs)
		return;

	mutex_lock(&vdev->mutex);
	vdev->ops->del_vqs(vdev);
	mutex_unlock(&vdev->mutex);
}

/* vhost_reset_vqs - Invoke vhost_config_ops to reset the created virtqueues
 * @vdev: Vhost device that provides reset_vqs() callback to reset virtqueue
 *
 * Wrapper that invokes vhost_config_ops to reset all the virtqueues
 * associated with the vhost device.
 */
void vhost_reset_vqs(struct vhost_dev *vdev)
{
	if (IS_ERR_OR_NULL(vdev))
		return;

	if (!vdev->ops || !vdev->ops->reset_vqs)
		return;

	mutex_lock(&vdev->mutex);
	vdev->ops->reset_vqs(vdev);
	mutex_unlock(&vdev->mutex);
}

/* vhost_write - Invoke vhost_config_ops to write data to buffer provided
 *   by remote virtio driver
 * @vdev: Vhost device that provides write() callback to write data
 * @dst: Buffer address in the remote device provided by the remote virtio
 *   driver
 * @src: Buffer address in the local device provided by the vhost client driver
 * @len: Length of the data to be copied from @src to @dst
 *
 * Wrapper that invokes vhost_config_ops to write data to buffer provided by
 * remote virtio driver from buffer provided by vhost client driver.
 */
int vhost_write(struct vhost_dev *vdev, u64 vhost_dst, void *src, int len)
{
	if (IS_ERR_OR_NULL(vdev))
		return -EINVAL;

	if (!vdev->ops || !vdev->ops->write)
		return -EINVAL;

	return vdev->ops->write(vdev, vhost_dst, src, len);
}

/* vhost_read - Invoke vhost_config_ops to read data from buffers provided by
 *   remote virtio driver
 * @vdev: Vhost device that provides read() callback to read data
 * @dst: Buffer address in the local device provided by the vhost client driver
 * @src: Buffer address in the remote device provided by the remote virtio
 *   driver
 * @len: Length of the data to be copied from @src to @dst
 *
 * Wrapper that invokes vhost_config_ops to read data from buffers provided by
 * remote virtio driver to the address provided by vhost client driver.
 */
int vhost_read(struct vhost_dev *vdev, void *dst, u64 vhost_src, int len)
{
	if (IS_ERR_OR_NULL(vdev))
		return -EINVAL;

	if (!vdev->ops || !vdev->ops->read)
		return -EINVAL;

	return vdev->ops->read(vdev, dst, vhost_src, len);
}

/* vhost_set_status - Invoke vhost_config_ops to set vhost device status
 * @vdev: Vhost device that provides set_status() callback to set device status
 * @status: Vhost device status configured by vhost client driver
 *
 * Wrapper that invokes vhost_config_ops to set vhost device status.
 */
int vhost_set_status(struct vhost_dev *vdev, u8 status)
{
	int ret;

	if (IS_ERR_OR_NULL(vdev))
		return -EINVAL;

	if (!vdev->ops || !vdev->ops->set_status)
		return -EINVAL;

	mutex_lock(&vdev->mutex);
	ret = vdev->ops->set_status(vdev, status);
	mutex_unlock(&vdev->mutex);

	return ret;
}

/* vhost_get_status - Invoke vhost_config_ops to get vhost device status
 * @vdev: Vhost device that provides get_status() callback to get device status
 *
 * Wrapper that invokes vhost_config_ops to get vhost device status.
 */
u8 vhost_get_status(struct vhost_dev *vdev)
{
	u8 status;

	if (IS_ERR_OR_NULL(vdev))
		return 0;

	if (!vdev->ops || !vdev->ops->get_status)
		return 0;

	mutex_lock(&vdev->mutex);
	status = vdev->ops->get_status(vdev);
	mutex_unlock(&vdev->mutex);

	return status;
}

/* vhost_set_features - Invoke vhost_config_ops to set vhost device features
 * @vdev: Vhost device that provides set_features() callback to set device
 *   features
 *
 * Wrapper that invokes vhost_config_ops to set device features.
 */
int vhost_set_features(struct vhost_dev *vdev, u64 device_features)
{
	int ret;

	if (IS_ERR_OR_NULL(vdev))
		return -EINVAL;

	if (!vdev->ops || !vdev->ops->set_features)
		return -EINVAL;

	mutex_lock(&vdev->mutex);
	ret = vdev->ops->set_features(vdev, device_features);
	mutex_unlock(&vdev->mutex);

	return ret;
}

/* vhost_register_notifier - Register notifier to receive notification from
 *   vhost device
 * @vdev: Vhost device from which notification has to be received.
 * @nb: Notifier block holding the callback function
 *
 * Invoked by vhost client to receive notification from vhost device.
 */
int vhost_register_notifier(struct vhost_dev *vdev, struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&vdev->notifier, nb);
}

static inline int vhost_id_match(const struct vhost_dev *vdev,
				 const struct virtio_device_id *id)
{
	if (id->device != vdev->id.device && id->device != VIRTIO_DEV_ANY_ID)
		return 0;

	return id->vendor == VIRTIO_DEV_ANY_ID || id->vendor == vdev->id.vendor;
}

static int vhost_dev_match(struct device *dev, struct device_driver *drv)
{
	struct vhost_driver *driver = to_vhost_driver(drv);
	struct vhost_dev *vdev = to_vhost_dev(dev);
	const struct virtio_device_id *ids;
	int i;

	ids = driver->id_table;
	for (i = 0; ids[i].device; i++)
		if (vhost_id_match(vdev, &ids[i]))
			return 1;

	return 0;
}

static int vhost_dev_probe(struct device *dev)
{
	struct vhost_driver *driver = to_vhost_driver(dev->driver);
	struct vhost_dev *vdev = to_vhost_dev(dev);

	if (!driver->probe)
		return -ENODEV;

	vdev->driver = driver;

	return driver->probe(vdev);
}

#if (KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE)
static void vhost_dev_remove(struct device *dev)
#else
static int vhost_dev_remove(struct device *dev)
#endif
{
	struct vhost_driver *driver = to_vhost_driver(dev->driver);
	struct vhost_dev *vdev = to_vhost_dev(dev);
	int ret = 0;

	if (driver->remove)
		ret = driver->remove(vdev);
	vdev->driver = NULL;
#if (KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE)
	(void)ret;
#else
	return ret;
#endif
}

static struct bus_type vhost_bus_type = {
	.name  = "cn_vhost",
	.match = vhost_dev_match,
	.probe = vhost_dev_probe,
	.remove = vhost_dev_remove,
};

/**
 * vhost_register_driver() - Register a vhost driver
 * @driver: Vhost driver that has to be registered
 *
 * Register a vhost driver.
 */
int vhost_register_driver(struct vhost_driver *driver)
{
	int ret;

	driver->driver.bus = &vhost_bus_type;

	ret = driver_register(&driver->driver);
	if (ret)
		return ret;

	return 0;
}

/**
 * vhost_unregister_driver() - Unregister a vhost driver
 * @driver: Vhost driver that has to be un-registered
 *
 * Unregister a vhost driver.
 */
void vhost_unregister_driver(struct vhost_driver *driver)
{
	driver_unregister(&driver->driver);
}

/**
 * vhost_register_device() - Register vhost device
 * @vdev: Vhost device that has to be registered
 *
 * Allocate a ID and register vhost device.
 */
int vhost_register_device(struct vhost_dev *vdev)
{
	struct device *dev = &vdev->dev;
	int ret;

	mutex_lock(&vhost_index_mutex);
	ret = ida_simple_get(&vhost_index_ida, 0, 0, GFP_KERNEL);
	mutex_unlock(&vhost_index_mutex);
	if (ret < 0)
		return ret;

	vdev->index = ret;
	dev->bus = &vhost_bus_type;
	device_initialize(dev);

	dev_set_name(dev, "vhost%u", ret);
	BLOCKING_INIT_NOTIFIER_HEAD(&vdev->notifier);

	ret = device_add(dev);
	if (ret) {
		put_device(dev);
		goto err;
	}

	return 0;

err:
	mutex_lock(&vhost_index_mutex);
	ida_simple_remove(&vhost_index_ida, vdev->index);
	mutex_unlock(&vhost_index_mutex);

	return ret;
}

/**
 * vhost_unregister_device() - Un-register vhost device
 * @vdev: Vhost device that has to be un-registered
 *
 * Un-register vhost device and free the allocated ID.
 */
void vhost_unregister_device(struct vhost_dev *vdev)
{
	device_unregister(&vdev->dev);
	mutex_lock(&vhost_index_mutex);
	ida_simple_remove(&vhost_index_ida, vdev->index);
	mutex_unlock(&vhost_index_mutex);
}

int vhost_init(void)
{
	int ret;

	ret = bus_register(&vhost_bus_type);
	if (ret) {
		pr_err("failed to register vhost bus --> %d\n", ret);
		return ret;
	}
	pr_info("%s, %d\n", __func__, __LINE__);
	return 0;
}

void vhost_exit(void)
{
	pr_info("%s, %d\n", __func__, __LINE__);
	bus_unregister(&vhost_bus_type);
	ida_destroy(&vhost_index_ida);
}

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Michael S. Tsirkin");
MODULE_DESCRIPTION("Host kernel accelerator for virtio");
