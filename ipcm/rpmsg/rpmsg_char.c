// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2016, Linaro Ltd.
 * Copyright (c) 2012, Michal Simek <monstr@monstr.eu>
 * Copyright (c) 2012, PetaLogix
 * Copyright (c) 2011, Texas Instruments, Inc.
 * Copyright (c) 2011, Google, Inc.
 *
 * Based on rpmsg performance statistics driver by Michal Simek, which in turn
 * was based on TI & Google OMX rpmsg driver.
 */
#include <linux/cdev.h>
#include <linux/device.h>
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
#include <linux/ktime.h>
#include <linux/delay.h>

#include "../include/rpmsg/rpmsg.h"
#include "../include/uapi/linux/rpmsg.h"
#include "../include/uapi/linux/eventpoll.h"
#include "rpmsg_internal.h"

#ifdef IN_CNDRV_HOST
#include "cndrv_core.h"
#include "cndrv_cap.h"
#endif

/* the original version /dev/rpmsgX before anon file */
//#define KEEP_DEV_RPMSGX

#define RPMSG_DEV_MAX	(MINORMASK + 1)

static dev_t rpmsg_major;
static struct class *rpmsg_class;

static DEFINE_IDA(rpmsg_ctrl_ida);
static DEFINE_IDA(rpmsg_ept_ida);
static DEFINE_IDA(rpmsg_minor_ida);

#define dev_to_eptdev(dev) container_of(dev, struct rpmsg_eptdev, dev)
#define cdev_to_eptdev(i_cdev) container_of(i_cdev, struct rpmsg_eptdev, cdev)

#define dev_to_ctrldev(dev) container_of(dev, struct rpmsg_ctrldev, dev)
#define cdev_to_ctrldev(i_cdev) container_of(i_cdev, struct rpmsg_ctrldev, cdev)

/**
 * struct rpmsg_ctrldev - control device for instantiating endpoint devices
 * @rpdev:	underlaying rpmsg device
 * @cdev:	cdev for the ctrl device
 * @dev:	device for the ctrl device
 */
struct rpmsg_ctrldev {
	struct rpmsg_device *rpdev;
	struct cdev cdev;
	struct device dev;
};

/**
 * struct rpmsg_eptdev - endpoint device context
 * @dev:	endpoint device
 * @cdev:      cdev for the endpoint device
 * @rpdev:	underlaying rpmsg device
 * @chinfo:	info used to open the endpoint
 * @ept_lock:	synchronization of @ept modifications
 * @ept:	rpmsg endpoint reference, when open
 * @queue_lock:	synchronization of @queue operations
 * @queue:	incoming message queue
 * @readq:	wait object for incoming queue
 */
struct rpmsg_eptdev {
	struct device dev;
	struct cdev cdev;

	struct rpmsg_device *rpdev;
	struct rpmsg_channel_info chinfo;

	struct mutex ept_lock;
	struct rpmsg_endpoint *ept;

	spinlock_t queue_lock;
	struct sk_buff_head queue;
	wait_queue_head_t readq;
	bool break_read;
};

dev_t cn_ipcm_get_rpmsg_major(void)
{
	return MAJOR(rpmsg_major);
}
#ifndef IN_CNDRV_HOST
EXPORT_SYMBOL(cn_ipcm_get_rpmsg_major);
#endif

static int rpmsg_eptdev_destroy(struct device *dev, void *data)
{
	struct rpmsg_eptdev *eptdev = dev_to_eptdev(dev);

	dev_dbg(dev, "%s, %s\n", __func__, eptdev->chinfo.name);

	mutex_lock(&eptdev->ept_lock);
	eptdev->rpdev = NULL;
	if (eptdev->ept) {
		cn_rpmsg_destroy_ept(eptdev->ept);
		eptdev->ept = NULL;
	}
	mutex_unlock(&eptdev->ept_lock);

	/* wake up any blocked readers */
	wake_up_interruptible(&eptdev->readq);

	/* cdev_device_del() */
	device_del(&eptdev->dev);
#ifdef KEEP_DEV_RPMSGX
	cdev_del(&eptdev->cdev);
#endif
	put_device(&eptdev->dev);

	return 0;
}

static inline void *_skb_put_data(struct sk_buff *skb, const void *data,
						unsigned int len)
{
	void *tmp = skb_put(skb, len);

	memcpy(tmp, data, len);

	return tmp;
}

static int rpmsg_ept_cb(struct rpmsg_device *rpdev, void *buf, int len,
			void *priv, u32 addr)
{
	struct rpmsg_eptdev *eptdev = priv;
	struct sk_buff *skb;

	dev_dbg(&eptdev->dev, "%s, %d\n", __func__, __LINE__);

	/* cambricon for userspace server */
	if (eptdev->chinfo.dst != addr) {
		/*
		 * last message received from the remote side,
		 * update channel destination address
		 */
		eptdev->chinfo.dst = addr;
	}

	skb = alloc_skb(len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	_skb_put_data(skb, buf, len);

	spin_lock(&eptdev->queue_lock);
	skb_queue_tail(&eptdev->queue, skb);
	spin_unlock(&eptdev->queue_lock);

	/* wake up any blocking processes, waiting for new data */
	wake_up_interruptible(&eptdev->readq);

	return 0;
}

static int rpmsg_eptdev_open(struct inode *inode, struct file *filp)
{
	struct rpmsg_eptdev *eptdev = cdev_to_eptdev(inode->i_cdev);
	struct rpmsg_endpoint *ept;
	struct rpmsg_device *rpdev = eptdev->rpdev;
	struct device *dev = &eptdev->dev;

	mutex_lock(&eptdev->ept_lock);
	if (eptdev->ept) {
		mutex_unlock(&eptdev->ept_lock);
		return -EBUSY;
	}

	if (!rpdev) {
		mutex_unlock(&eptdev->ept_lock);
		return -ENETRESET;
	}

	get_device(dev);

	ept = cn_rpmsg_create_ept(rpdev, rpmsg_ept_cb, eptdev, eptdev->chinfo);
	if (!ept) {
		dev_err(dev, "failed to open %s\n", eptdev->chinfo.name);
		put_device(dev);
		mutex_unlock(&eptdev->ept_lock);
		return -EINVAL;
	}

	eptdev->ept = ept;
	if (eptdev->chinfo.src == RPMSG_ADDR_ANY)
		eptdev->chinfo.src = ept->addr;
	filp->private_data = eptdev;
	mutex_unlock(&eptdev->ept_lock);

	return 0;
}

static int rpmsg_eptdev_send_hup_signal(struct rpmsg_eptdev *eptdev)
{
	struct ipcm_device_header *dev_hdr;
	int total_size = sizeof(*dev_hdr);
	struct device *dev = &eptdev->dev;
	ktime_t timeout;
	int ret;

	dev_hdr = kzalloc(sizeof(*dev_hdr), GFP_KERNEL);
	if (!dev_hdr) {
		dev_err(dev, "%s: no os memory\n", __func__);
		return -ENOMEM;
	}
	dev_hdr->packet_type = RPMSG_IPC_PACKET_TYPE_HUP;
	dev_hdr->packet_source = RPMSG_IPC_PACKET_SOURCE_CLIENT;
	dev_hdr->packet_size = total_size;
	dev_hdr->src = eptdev->ept->addr;

	timeout = ktime_add_us(ktime_get(), 5 * USEC_PER_SEC);//5s
	do {
		ret = cn_rpmsg_trysendto(eptdev->ept, dev_hdr, total_size, eptdev->chinfo.dst);
		if (!ret)
			break;
		if (ktime_compare(ktime_get(), timeout) > 0)
			break;
		usleep_range(100, 200);
	} while (ret == -ENOMEM);// wait for a tx buffer
	if (ret) {
		dev_err(dev, "%s: rpmsg_send failed: %d\n", __func__, ret);
		goto out;
	}

out:
	kfree(dev_hdr);
	return ret;
}

static int rpmsg_eptdev_release(struct inode *inode, struct file *filp)
{
	struct rpmsg_eptdev *eptdev = (struct rpmsg_eptdev *)filp->private_data;
	struct device *dev = &eptdev->dev;

	if (0) {
		/* Close the endpoint, if it's not already destroyed by the parent */
		mutex_lock(&eptdev->ept_lock);
		if (eptdev->ept) {
			cn_rpmsg_destroy_ept(eptdev->ept);
			eptdev->ept = NULL;
		}
		mutex_unlock(&eptdev->ept_lock);
	} else {
		/* send HUP & Close the endpoint, if it's not already destroyed by the parent */
		mutex_lock(&eptdev->ept_lock);
		if (eptdev->ept) {
			dev_dbg(dev, "%s send HUP\n", __func__);
			rpmsg_eptdev_send_hup_signal(eptdev);
			cn_rpmsg_destroy_ept(eptdev->ept);
			eptdev->ept = NULL;
			/* wake up any blocked readers */
			wake_up_interruptible(&eptdev->readq);
		}
		mutex_unlock(&eptdev->ept_lock);
	}

	/* Discard all SKBs */
	skb_queue_purge(&eptdev->queue);

	/* Use put_device() to give up reference in device_initialize() */
	put_device(dev);

	return 0;
}

#if (KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE)
static ssize_t rpmsg_eptdev_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *filp = iocb->ki_filp;
#else
static ssize_t rpmsg_eptdev_read(struct file *filp, char __user *buf, size_t len, loff_t *f_pos)
{
#endif
	struct rpmsg_eptdev *eptdev = filp->private_data;
	unsigned long flags;
	struct sk_buff *skb;
	int use;

	if (!eptdev->ept)
		return -EPIPE;

	spin_lock_irqsave(&eptdev->queue_lock, flags);

	/* Wait for data in the queue */
	if (skb_queue_empty(&eptdev->queue)) {
		spin_unlock_irqrestore(&eptdev->queue_lock, flags);

		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;

		/* Wait until we get data or the endpoint goes away */
		if (wait_event_interruptible(eptdev->readq,
					     !skb_queue_empty(&eptdev->queue) ||
					     !eptdev->ept ||
					     eptdev->break_read))
			return -ERESTARTSYS;

		/* We lost the endpoint while waiting */
		if (!eptdev->ept)
			return -EPIPE;

		if (eptdev->break_read) {
			eptdev->break_read = false;
			return -EIO;
		}

		spin_lock_irqsave(&eptdev->queue_lock, flags);
	}

	skb = skb_dequeue(&eptdev->queue);
	spin_unlock_irqrestore(&eptdev->queue_lock, flags);
	if (!skb)
		return -EFAULT;

	#if (KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE)
	use = min_t(size_t, iov_iter_count(to), skb->len);
	if (copy_to_iter(skb->data, use, to) != use)
		use = -EFAULT;
	#else
	use = min_t(size_t, len, skb->len);
	if (copy_to_user(buf, skb->data, use))
		use = -EFAULT;
	#endif

	kfree_skb(skb);

	return use;
}

#if (KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE)
static ssize_t rpmsg_eptdev_write_iter(struct kiocb *iocb,
				       struct iov_iter *from)
{
	struct file *filp = iocb->ki_filp;
	size_t len = iov_iter_count(from);
#else
static ssize_t rpmsg_eptdev_write(struct file *filp, const char __user *buf, size_t len, loff_t *f_pos)
{
#endif
	struct rpmsg_eptdev *eptdev = filp->private_data;
	void *kbuf;
	int ret;

	#if (KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE)
	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (!copy_from_iter_full(kbuf, len, from)) {
		ret = -EFAULT;
		goto free_kbuf;
	}
	#else
	kbuf = memdup_user(buf, len);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);
	#endif

	if (mutex_lock_interruptible(&eptdev->ept_lock)) {
		ret = -ERESTARTSYS;
		goto free_kbuf;
	}

	if (!eptdev->ept) {
		ret = -EPIPE;
		goto unlock_eptdev;
	}

	if (filp->f_flags & O_NONBLOCK)
		//ret = cn_rpmsg_trysend(eptdev->ept, kbuf, len);
		ret = cn_rpmsg_trysendto(eptdev->ept, kbuf, len, eptdev->chinfo.dst);
	else
		//ret = cn_rpmsg_send(eptdev->ept, kbuf, len);
		ret = cn_rpmsg_sendto(eptdev->ept, kbuf, len, eptdev->chinfo.dst);
unlock_eptdev:
	mutex_unlock(&eptdev->ept_lock);

free_kbuf:
	kfree(kbuf);
	return ret < 0 ? ret : len;
}

static __poll_t rpmsg_eptdev_poll(struct file *filp, poll_table *wait)
{
	struct rpmsg_eptdev *eptdev = filp->private_data;
	__poll_t mask = 0;

	pr_info("%s, %d\n", __func__, __LINE__);

	if (!eptdev->ept) {
		mask |= EPOLLERR;
		return mask;
	}

	poll_wait(filp, &eptdev->readq, wait);

	if (!skb_queue_empty(&eptdev->queue))
		mask |= EPOLLIN | EPOLLRDNORM;

	mutex_lock(&eptdev->ept_lock);
	mask |= cn_rpmsg_poll(eptdev->ept, filp, wait);
	mutex_unlock(&eptdev->ept_lock);

	return mask;
}

static int rpmsg_eptdev_user_sendto_port(struct file *fp, unsigned long arg)
{
	struct rpmsg_eptdev *eptdev = fp->private_data;
	struct ipcm_server_port_msg port_msg = {0};
	void __user *argp = (void __user *)arg;
	void *kbuf;
	int len;
	int ret;

	if (copy_from_user(&port_msg, argp, sizeof(port_msg)))
		return -EFAULT;

	len = port_msg.len;
	kbuf = memdup_user(port_msg.msg, len);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	if (mutex_lock_interruptible(&eptdev->ept_lock)) {
		ret = -ERESTARTSYS;
		goto free_kbuf;
	}

	if (!eptdev->ept) {
		ret = -EPIPE;
		goto unlock_eptdev;
	}

	if (fp->f_flags & O_NONBLOCK)
		ret = cn_rpmsg_trysendto(eptdev->ept, kbuf, len, port_msg.port);
	else
		ret = cn_rpmsg_sendto(eptdev->ept, kbuf, len, port_msg.port);
unlock_eptdev:
	mutex_unlock(&eptdev->ept_lock);

free_kbuf:
	kfree(kbuf);
	return ret < 0 ? ret : len;
}

static int rpmsg_eptdev_read_break(struct file *fp)
{
	struct rpmsg_eptdev *eptdev = fp->private_data;

	eptdev->break_read = true;
	wake_up_interruptible(&eptdev->readq);

	return 0;
}

static long rpmsg_eptdev_ioctl(struct file *fp, unsigned int cmd,
			       unsigned long arg)
{
	switch (cmd) {
	case RPMSG_SERVER_PORT_SEND_IOCTL:
		return rpmsg_eptdev_user_sendto_port(fp, arg);
	case RPMSG_DESTROY_EPT_IOCTL: {
		struct rpmsg_eptdev *eptdev = fp->private_data;

		return rpmsg_eptdev_destroy(&eptdev->dev, NULL);
	}
	case RPMSG_READ_BREAK_IOCTL: {
		return rpmsg_eptdev_read_break(fp);
	}
	case RPMSG_GET_PORT_PID: {
		struct rpmsg_eptdev *eptdev = fp->private_data;
		struct rpmsg_device *rpdev;
		struct rpmsg_channel_info chinfo = {};
		struct device *tmp;
		void __user *argp = (void __user *)arg;
		int addr;
		int tgid = -1;
		int resp_len = 0;
		int ret = 0;

		if (copy_from_user(&addr, argp, sizeof(int)))
			return -EFAULT;

		strncpy(chinfo.name, RPSMG_QUERY_PORT_NAME, sizeof(chinfo.name));
		chinfo.src = RPMSG_QUERY_PORT_ADDR;
		chinfo.dst = RPMSG_ADDR_ANY;
		tmp = cn_rpmsg_find_device(eptdev->rpdev->dev.parent, &chinfo);
		if (tmp) {
			/* decrement the matched device's refcount back */
			put_device(tmp);
			rpdev = to_rpmsg_device(tmp);
			ret = ipcm_send_request_with_response_to_port(rpdev, true, (void *)&addr, sizeof(addr),
				&tgid, &resp_len, sizeof(tgid), RPMSG_QUERY_PORT_ADDR);
			if (copy_to_user(argp, &tgid, sizeof(tgid))) {
				dev_err(&eptdev->dev, "%s copy_to_user failed\n", __func__);
				return -EFAULT;
			}
			return ret;
		}
		return -ENODEV;
	}
	default:
		return -EINVAL;
	}
}

static const struct file_operations rpmsg_eptdev_fops = {
	.owner = THIS_MODULE,
	.open = rpmsg_eptdev_open,
	.release = rpmsg_eptdev_release,
	#if (KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE)
	.read_iter = rpmsg_eptdev_read_iter,
	.write_iter = rpmsg_eptdev_write_iter,
	#else
	.read = rpmsg_eptdev_read,
	.write = rpmsg_eptdev_write,
	#endif
	.poll = rpmsg_eptdev_poll,
	.unlocked_ioctl = rpmsg_eptdev_ioctl,
	.compat_ioctl = rpmsg_eptdev_ioctl,
};

static ssize_t name_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct rpmsg_eptdev *eptdev = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%s\n", eptdev->chinfo.name);
}
static DEVICE_ATTR_RO(name);

static ssize_t src_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct rpmsg_eptdev *eptdev = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", eptdev->chinfo.src);
}
static DEVICE_ATTR_RO(src);

static ssize_t dst_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct rpmsg_eptdev *eptdev = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", eptdev->chinfo.dst);
}
static DEVICE_ATTR_RO(dst);

static struct attribute *rpmsg_eptdev_attrs[] = {
	&dev_attr_name.attr,
	&dev_attr_src.attr,
	&dev_attr_dst.attr,
	NULL
};
ATTRIBUTE_GROUPS(rpmsg_eptdev);

static void rpmsg_eptdev_release_device(struct device *dev)
{
	struct rpmsg_eptdev *eptdev = dev_to_eptdev(dev);

	dev_dbg(dev, "%s: %s\n", __func__, eptdev->chinfo.name);

	ida_simple_remove(&rpmsg_ept_ida, dev->id);
#ifdef KEEP_DEV_RPMSGX
	ida_simple_remove(&rpmsg_minor_ida, MINOR(eptdev->dev.devt));
#endif
	mutex_destroy(&eptdev->ept_lock);
	kfree(eptdev);
}

static char *rpmsg_chrdev_devnode(struct device *dev, umode_t *mode)
{
	if (mode) {
		*mode |= 0666;
	}

	return NULL;
}

static struct rpmsg_eptdev *rpmsg_eptdev_alloc(struct rpmsg_ctrldev *ctrldev,
	struct rpmsg_channel_info chinfo)
{
	struct rpmsg_device *rpdev = ctrldev->rpdev;
	struct rpmsg_eptdev *eptdev = NULL;

	eptdev = kzalloc(sizeof(*eptdev), GFP_KERNEL);
	if (!eptdev)
		return NULL;

	eptdev->rpdev = rpdev;
	eptdev->chinfo = chinfo;
	eptdev->break_read = false;

	mutex_init(&eptdev->ept_lock);
	spin_lock_init(&eptdev->queue_lock);
	skb_queue_head_init(&eptdev->queue);
	init_waitqueue_head(&eptdev->readq);

	return eptdev;
}

static int rpmsg_anon_file_create(struct rpmsg_eptdev *eptdev, struct rpmsg_device *rpdev,
	int *rfd, int *addr)
{
	int fd = -1;
	struct file *file = NULL;
	int ret = -1;
	struct rpmsg_endpoint *ept = NULL;

	if (!rfd || !addr) {
		dev_err(&eptdev->dev, "rfg or addr pointer null.\n");
		return -EINVAL;
	}

	/* OK, here is the deal:
	 * We allocate fd and file and make connection between them,
	 * and most importantly hook etpdev into file, and create ept.
	 */
	fd = get_unused_fd_flags(O_RDWR);
	if (unlikely(fd < 0)) {
		dev_err(&eptdev->dev, "get_unused_fd_flags() fails:%d\n", fd);

		ret = fd;
		return ret;
	}

	/* Get file backed by anon inode */
	file = anon_inode_getfile("[rpmsg]", &rpmsg_eptdev_fops, eptdev, O_RDWR);
	if (unlikely(IS_ERR(file))) {
		dev_err(&eptdev->dev, "anon_inode_getfile() fails\n");

		put_unused_fd(fd);

		ret = PTR_ERR(file);
		return ret;
	}

	get_device(&eptdev->dev);

	/* TODO: In original implementation, it needs ept_lock's protection */
	ept = cn_rpmsg_create_ept(rpdev, rpmsg_ept_cb, eptdev, eptdev->chinfo);
	if (unlikely(!ept)) {
		dev_err(&eptdev->dev, "failed to open %s\n", eptdev->chinfo.name);

		fput(file);
		put_unused_fd(fd);

		put_device(&eptdev->dev);

		ret = -EINVAL;
		return ret;
	}

	fd_install(fd, file);

	eptdev->ept = ept;
	if (eptdev->chinfo.src == RPMSG_ADDR_ANY)
		eptdev->chinfo.src = ept->addr;

	*rfd = fd;
	*addr = ept->addr;

	dev_dbg(&eptdev->dev, "%s, file = %px, fd = %d, pid = %d\n",
			__func__, file, fd, current->tgid);

	return 0;
}

static int rpmsg_eptdev_create(struct rpmsg_ctrldev *ctrldev,
	struct rpmsg_channel_info chinfo, int *rfd, int *addr)
{
	struct rpmsg_device *rpdev = ctrldev->rpdev;
	struct rpmsg_eptdev *eptdev = NULL;
	struct device *dev = NULL;
	int ret = -1;

	eptdev = rpmsg_eptdev_alloc(ctrldev, chinfo);
	if (!eptdev)
		return -ENOMEM;

	dev = &eptdev->dev;

	/*
	 * keep dev but no cdev for dev_xxx and DEVICE_ATTR, and device_for_each_child() for remove, see DRIVER-14968
	 * not devnode if dev->devt not initialize
	 */
	device_initialize(dev);
	dev->class = rpmsg_class;
	dev->parent = &ctrldev->dev;
	dev->groups = rpmsg_eptdev_groups;
	dev_set_drvdata(dev, eptdev);
#ifdef KEEP_DEV_RPMSGX
	cdev_init(&eptdev->cdev, &rpmsg_eptdev_fops);
	eptdev->cdev.owner = THIS_MODULE;
	/* cdev_device_add() */
	eptdev->cdev.kobj.parent = &eptdev->dev.kobj;

	ret = ida_simple_get(&rpmsg_minor_ida, 0, RPMSG_DEV_MAX, GFP_KERNEL);
	if (ret < 0)
		goto free_eptdev;
	dev->devt = MKDEV(MAJOR(rpmsg_major), ret);
#endif
	ret = ida_simple_get(&rpmsg_ept_ida, 0, 0, GFP_KERNEL);
	if (ret < 0)
		goto free_minor_ida;
	dev->id = ret;

	dev_set_name(dev, "rpmsg%d", ret);

#ifdef KEEP_DEV_RPMSGX
	ret = cdev_add(&eptdev->cdev, dev->devt, 1);
	if (ret)
		goto free_ept_ida;
#endif

	/* We can now rely on the release function for cleanup */
	dev->release = rpmsg_eptdev_release_device;

	ret = device_add(dev);
	if (ret) {
		dev_err(dev, "device_add failed: %d\n", ret);
		goto free_ept_ida;
	}

	ret = rpmsg_anon_file_create(eptdev, rpdev, rfd, addr);
	if (ret) {
		dev_err(&eptdev->dev, "%s: rpmsg_anon_file_create() failed with: %d", __func__, ret);
	}

	return ret;

free_ept_ida:
	ida_simple_remove(&rpmsg_ept_ida, dev->id);
free_minor_ida:
#ifdef KEEP_DEV_RPMSGX
	ida_simple_remove(&rpmsg_minor_ida, MINOR(dev->devt));
free_eptdev:
#endif
	put_device(dev);
	kfree(eptdev);

	dev_info(&ctrldev->dev, "%s, %d, failed(%d)\n", __func__, __LINE__, ret);

	return ret;
}

#ifdef IN_CNDRV_HOST
extern struct cn_core_set *cambr_dev_to_core(struct device *dev);

static int rpmsg_ctrldev_match(struct device *dev, const void *data)
{
	char *name = (char *)data;

	return strcmp(dev_name(dev), name) == 0;
}
/* pf_core's ctrldev to real ctrldev(mi_core's) */
static int rpmsg_ctrldev_replace(struct rpmsg_ctrldev **ctrldev)
{
	struct rpmsg_ctrldev *mi_ctrldev;
	struct cn_core_set *core, *mi_core;
	struct tid_cap_node *tid_cap_node;
	struct device *dev = &(*ctrldev)->dev;
	struct list_head *tid_cap_list_head;
	struct mutex *tid_cap_lock;

	core = cambr_dev_to_core(dev);
	if (!core) {
		dev_err(dev, "%s can't get core by ctrldev\n", __func__);
		return -EINVAL;
	}

	if (cn_core_is_vf(core) || !cn_is_mim_en(core))
		return 0;

	tid_cap_list_head = &core->tid_cap_list_head;
	tid_cap_lock = &core->tid_cap_lock;

	mutex_lock(tid_cap_lock);
	list_for_each_entry(tid_cap_node, tid_cap_list_head, list) {
		char ctrldev_name[32];

		if (tid_cap_node->pid == current->pid) {
			mi_core = tid_cap_node->core;
			if (!mi_core) {
				mutex_unlock(tid_cap_lock);
				return -ENODEV;
			}
			if (mi_core->pf_idx != core->pf_idx) {
				dev_err(dev, "bind MI ipcm failed, ipcm pf_idx:%d, "
					"mi_cap pf_idx:%d, not match", core->pf_idx, mi_core->pf_idx);
				mutex_unlock(tid_cap_lock);
				return -EFAULT;
			}
			/*
			vdev = cambr_rproc_get_virtio_device(mi_core);
			struct rpmsg_channel_info chinfo = {};

			strncpy(chinfo.name, "rpmsg_chrdev", sizeof(chinfo.name));
			chinfo.src = RPMSG_ADDR_ANY;
			chinfo.dst = RPMSG_ADDR_ANY;
			dev = cn_rpmsg_find_device(&vdev->dev, &chinfo);
			put_device(dev);
			mi_ctrldev = dev_get_drvdata(dev);
			*/
			snprintf(ctrldev_name, 32, "cambricon_ipcm%dmi%d", mi_core->pf_idx, mi_core->vf_idx);

			dev = class_find_device(rpmsg_class, NULL, ctrldev_name, rpmsg_ctrldev_match);
			if (dev) {
				/* decrement the matched device's refcount back */
				put_device(dev);
				mi_ctrldev = dev_to_ctrldev(dev);
			} else {
				dev_err(&(*ctrldev)->dev, "%s can't get %s ctrldev\n", __func__, ctrldev_name);
				mutex_unlock(tid_cap_lock);
				return -ENODEV;
			}

			*ctrldev = mi_ctrldev;
			dev_dbg(dev, "bind MI ipcm success, pf_idx:%d, vf_idx:%d",
				mi_core->pf_idx, mi_core->vf_idx);
			break;
		}
	}
	mutex_unlock(tid_cap_lock);

	return 0;
}
#endif

static int rpmsg_ctrldev_open(struct inode *inode, struct file *filp)
{
	struct rpmsg_ctrldev *ctrldev = cdev_to_ctrldev(inode->i_cdev);

	#ifdef IN_CNDRV_HOST
	int ret;
	ret = rpmsg_ctrldev_replace(&ctrldev);
	if (ret < 0) {
		dev_err(&ctrldev->dev, "bind MI ipcm failed\n");
		return ret;
	}
	#endif

	get_device(&ctrldev->dev);
	filp->private_data = ctrldev;

	return 0;
}

static int rpmsg_ctrldev_release(struct inode *inode, struct file *filp)
{
	struct rpmsg_ctrldev *ctrldev = filp->private_data;

	put_device(&ctrldev->dev);

	return 0;
}

static long rpmsg_ctrldev_ioctl(struct file *fp, unsigned int cmd,
				unsigned long arg)
{
	struct rpmsg_ctrldev *ctrldev = fp->private_data;
	void __user *argp = (void __user *)arg;
	struct rpmsg_channel_info chinfo = {};

	if (cmd == RPMSG_GET_CDEV_NAME_IOCTL) {
		if (copy_to_user((void *)arg, (void *)dev_name(&ctrldev->dev),
			min_t(size_t, strlen(dev_name(&ctrldev->dev)), 32)))
			return -EFAULT;
		return 0;
	}

	if (cmd == RPMSG_CREATE_EPT_IOCTL_V3) {
		struct rpmsg_endpoint_info_V3 eptinfo_V3;
		int rfd = -1;
		int ret = -1;
		int addr = -1;

		if (copy_from_user(&eptinfo_V3, argp, _IOC_SIZE(cmd)))
			return -EFAULT;

		memcpy(chinfo.name, eptinfo_V3.name, RPMSG_NAME_SIZE);
		chinfo.name[RPMSG_NAME_SIZE-1] = '\0';
		chinfo.src = eptinfo_V3.src;
		chinfo.dst = eptinfo_V3.dst;
		chinfo.desc[0] = '\0';

		ret = rpmsg_eptdev_create(ctrldev, chinfo, &rfd, &addr);
		if (ret) {
			dev_err(&ctrldev->dev, "%s fails for V3 path:%d\n", __func__, ret);
			return -ENOENT;
		}

		eptinfo_V3.rfd = rfd;
		eptinfo_V3.addr = addr;
		if (copy_to_user(argp, &eptinfo_V3, sizeof(eptinfo_V3))) {
			dev_err(&ctrldev->dev, "%s exit abnormal, copy_to_user() fails\n", __func__);
			return -EFAULT;
		}

		dev_dbg(&ctrldev->dev, "%s EXIT for V3 path\n", __func__);

		return 0;
	}

	if (cmd == RPMSG_GET_DEV_UNIQUE_ID) {
		struct inode *inode = fp->f_inode;
		uint64_t unique_id = inode->i_rdev;

		if (copy_to_user((void *)arg, (void *)&unique_id, sizeof(unique_id)))
			return -EFAULT;

		return 0;
	}

	dev_err(&ctrldev->dev, "%s invalid cmd %d\n", __func__, cmd);

	return -EINVAL;
};

static const struct file_operations rpmsg_ctrldev_fops = {
	.owner = THIS_MODULE,
	.open = rpmsg_ctrldev_open,
	.release = rpmsg_ctrldev_release,
	.unlocked_ioctl = rpmsg_ctrldev_ioctl,
	.compat_ioctl = rpmsg_ctrldev_ioctl,
};

static void rpmsg_ctrldev_release_device(struct device *dev)
{
	struct rpmsg_ctrldev *ctrldev = dev_to_ctrldev(dev);

	dev_info(dev, "%s\n", __func__);

	ida_simple_remove(&rpmsg_ctrl_ida, dev->id);
	if (dev->devt != WITHOUT_DEV)
		ida_simple_remove(&rpmsg_minor_ida, MINOR(dev->devt));

	kfree(ctrldev);
}

static int rpmsg_chrdev_probe(struct rpmsg_device *rpdev)
{
	struct rpmsg_ctrldev *ctrldev;
	struct device *dev;
	int ret;
	#ifdef IN_CNDRV_HOST
	struct cn_core_set *core;

	core = cambr_dev_to_core(&rpdev->dev);
	if (!core) {
		dev_err(&rpdev->dev, "%s can't get core by rpdev\n", __func__);
		return -EINVAL;
	}
	#endif

	ctrldev = kzalloc(sizeof(*ctrldev), GFP_KERNEL);
	if (!ctrldev)
		return -ENOMEM;

	ctrldev->rpdev = rpdev;

	dev = &ctrldev->dev;
	device_initialize(dev);
	dev->parent = &rpdev->dev;
	dev->class = rpmsg_class;

	cdev_init(&ctrldev->cdev, &rpmsg_ctrldev_fops);
	ctrldev->cdev.owner = THIS_MODULE;
	/* cdev_device_add() */
	ctrldev->cdev.kobj.parent = &ctrldev->dev.kobj;

	ret = ida_simple_get(&rpmsg_minor_ida, 0, RPMSG_DEV_MAX, GFP_KERNEL);
	if (ret < 0)
		goto free_ctrldev;
	dev->devt = MKDEV(MAJOR(rpmsg_major), ret);

	ret = ida_simple_get(&rpmsg_ctrl_ida, 0, 0, GFP_KERNEL);
	if (ret < 0)
		goto free_minor_ida;
	dev->id = ret;

	#ifdef IN_CNDRV_HOST
	if (cn_is_mim_en(core) && cn_core_is_vf(core)) {
		dev_set_name(&ctrldev->dev, "cambricon_ipcm%dmi%d", core->pf_idx, core->vf_idx);
		ida_simple_remove(&rpmsg_minor_ida, MINOR(dev->devt));
		dev->devt = WITHOUT_DEV;
	} else {
		dev_set_name(&ctrldev->dev, "cambricon_ipcm%d", core->idx);
		ret = cdev_add(&ctrldev->cdev, dev->devt, 1);
		if (ret)
			goto free_ctrl_ida;
	}
	#else
	dev_set_name(&ctrldev->dev, "cambricon_ipcm%d", ret);
	ret = cdev_add(&ctrldev->cdev, dev->devt, 1);
	if (ret)
		goto free_ctrl_ida;
	#endif

	/* We can now rely on the release function for cleanup */
	dev->release = rpmsg_ctrldev_release_device;

	ret = device_add(dev);
	if (ret) {
		dev_err(&rpdev->dev, "device_add failed: %d\n", ret);
		goto free_ctrl_ida;
	}

	dev_set_drvdata(&rpdev->dev, ctrldev);

	return ret;

free_ctrl_ida:
	ida_simple_remove(&rpmsg_ctrl_ida, dev->id);
free_minor_ida:
	if (dev->devt != WITHOUT_DEV)
		ida_simple_remove(&rpmsg_minor_ida, MINOR(dev->devt));
free_ctrldev:
	put_device(dev);
	kfree(ctrldev);

	return ret;
}

static void rpmsg_chrdev_remove(struct rpmsg_device *rpdev)
{
	struct rpmsg_ctrldev *ctrldev = dev_get_drvdata(&rpdev->dev);
	int ret;

	/* Destroy all endpoints */
	ret = device_for_each_child(&ctrldev->dev, NULL, rpmsg_eptdev_destroy);
	if (ret)
		dev_warn(&rpdev->dev, "failed to nuke endpoints: %d\n", ret);

	/* cdev_device_del() */
	device_del(&ctrldev->dev);
	if (ctrldev->dev.devt != WITHOUT_DEV)
		cdev_del(&ctrldev->cdev);
	put_device(&ctrldev->dev);

	dev_info(&rpdev->dev, "%s, %d\n", __func__, __LINE__);
}

static const struct rpmsg_device_id rpmsg_char_id_table[] = {
	{ .name	= "rpmsg_chrdev" },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, rpmsg_char_id_table);

static struct rpmsg_driver rpmsg_chrdev_driver = {
	.probe = rpmsg_chrdev_probe,
	.remove = rpmsg_chrdev_remove,
	.drv = {
		.name = "rpmsg_chrdev",
	},
	.id_table	= rpmsg_char_id_table,
};

int rpmsg_char_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&rpmsg_major, 0, RPMSG_DEV_MAX, "cn_rpmsg");
	if (ret < 0) {
		pr_err("rpmsg: failed to allocate char dev region\n");
		return ret;
	}

	rpmsg_class = class_create(THIS_MODULE, "cn_rpmsg");
	if (IS_ERR(rpmsg_class)) {
		pr_err("failed to create rpmsg class\n");
		unregister_chrdev_region(rpmsg_major, RPMSG_DEV_MAX);
		return PTR_ERR(rpmsg_class);
	}

	rpmsg_class->devnode = rpmsg_chrdev_devnode;

	ret = cn_register_rpmsg_driver(&rpmsg_chrdev_driver);
	if (ret < 0) {
		pr_err("rpmsgchr: failed to register rpmsg driver\n");
		class_destroy(rpmsg_class);
		unregister_chrdev_region(rpmsg_major, RPMSG_DEV_MAX);
	}

	return ret;
}

void rpmsg_chrdev_exit(void)
{
	pr_info("%s, %d\n", __func__, __LINE__);
	cn_unregister_rpmsg_driver(&rpmsg_chrdev_driver);
	class_destroy(rpmsg_class);
	unregister_chrdev_region(rpmsg_major, RPMSG_DEV_MAX);
}
