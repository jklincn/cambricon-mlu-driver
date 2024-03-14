#ifndef _CNHOST_DEV_COMMON_H_
#define _CNHOST_DEV_COMMON_H_

#include <linux/list.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/idr.h>

struct cnhost_driver;
struct cnhost_minor;
struct inode;

enum cnhost_minor_type {
	CNHOST_DEV_MINOR_CONTROL,
	CNHOST_DEV_MINOR_PHYSICAL,
	CNHOST_DEV_MINOR_MI_CAP,
	CNHOST_DEV_MINOR_SMLU_CAP,
	CNHOST_DEV_MINOR_BUTT
};

struct cnhost_device {
	struct kref ref;

	/** vf */
	int card_index;
	int vf_index;/* reuse for sMLU instance id */

	struct device *dev;

	struct {
		struct list_head resources;
		void *final_kfree;
		spinlock_t lock;
	} managed;

	const struct cnhost_driver *driver;

	void *dev_private;

	struct cnhost_minor *primary;

	bool registered;

	struct mutex struct_mutex;

	atomic_t open_count;
};

struct cnhost_minor {
	/* private: */
	int major;
	int index;
	int type;
	struct device *kdev;
	struct cnhost_device *dev;
};

struct cnhost_driver {
	char *name;

	void (*release) (struct cnhost_device *);

	const struct file_operations *fops;
};

enum cnhost_dev_ioctl_flags {
	CNHOST_DEV_AUTH		 = BIT(0),
	CNHOST_DEV_ROOT_ONLY = BIT(1),

};

#define CNHOST_DEV_IOCTL_DEF_DRV(ioctl, _flags)				\
	[_IOC_NR(ioctl)] = {	\
		.cmd = ioctl,				\
		.flags = _flags,					\
		.name = #ioctl						\
	}

struct cnhost_dev_ioctl_desc {
	unsigned int cmd;
	enum cnhost_dev_ioctl_flags flags;
	const char *name;
};

struct cnhost_device *cnhost_dev_alloc(const struct cnhost_driver *driver,
	void *private, unsigned int type, int card_index, int vf_index);
dev_t cnhost_dev_get_devt(struct cnhost_device *dev);
int cnhost_dev_core_init(void);
void cnhost_dev_core_exit(void);
int cnhost_dev_register(struct cnhost_device *dev, unsigned long flags);
void cnhost_dev_unregister(struct cnhost_device *dev);
void cnhost_dev_get(struct cnhost_device *dev);
void cnhost_dev_put(struct cnhost_device *dev);
unsigned int cnhost_dev_read(struct cnhost_device *dev);
struct cnhost_minor *cnhost_dev_minor_acquire(unsigned int major_id, unsigned int minor_id);
void cnhost_dev_minor_release(struct cnhost_minor *minor);
struct cnhost_minor *find_cnhost_minor(unsigned int type, unsigned int minor_id);
int cnhost_dev_permit_check(struct file *fp, unsigned int cmd, unsigned long arg, struct cnhost_dev_ioctl_desc *ioctl_desc, int size);

#endif
