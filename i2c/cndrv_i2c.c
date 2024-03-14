#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <asm/delay.h>

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_i2c_internal.h"
#include "cndrv_ioctl.h"

extern int dw_i2c_init(void *iset);


int cn_config_i2c_speed(void *iset, enum i2c_speed speed)
{
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)iset;

	if (IS_ERR_OR_NULL(i2c_set)) {
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(i2c_set->i2c_ops)) {
		cn_dev_i2c_err(i2c_set, "i2c ops is null");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(i2c_set->i2c_ops->config_i2c_speed)) {
		cn_dev_i2c_err(i2c_set, "i2c write func null");
		return -EINVAL;
	}

	return i2c_set->i2c_ops->config_i2c_speed(i2c_set, speed);
}


int cn_i2c_write(void *iset, void *i2c_msg)
{
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)iset;
	int ret = 0;

	if (IS_ERR_OR_NULL(i2c_set)) {
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(i2c_set->i2c_ops)) {
		cn_dev_i2c_err(i2c_set, "i2c ops is null");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(i2c_set->i2c_ops->i2c_write)) {
		cn_dev_i2c_err(i2c_set, "i2c write func null");
		return -EINVAL;
	}

	ret = i2c_set->i2c_ops->i2c_write(i2c_set, i2c_msg);
	if (ret) {
		cn_dev_i2c_err(i2c_set, "call write func error");
	}

	return ret;
}

int cn_i2c_read(void *iset, void *i2c_msg)
{
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)iset;
	int ret = 0;

	if (IS_ERR_OR_NULL(i2c_set)) {
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(i2c_set->i2c_ops)) {
		cn_dev_i2c_err(i2c_set, "i2c ops is null");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(i2c_set->i2c_ops->i2c_read)) {
		cn_dev_i2c_err(i2c_set, "i2c read func null");
		return -EINVAL;
	}

	ret = i2c_set->i2c_ops->i2c_read(i2c_set, i2c_msg);
	if (ret) {
		cn_dev_i2c_err(i2c_set, "call read func error");
	}

	return ret;
}
int i2c_config_speed(unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)core->i2c_set;
	enum i2c_speed speed;

	if (copy_from_user((void *)&speed, (void *)arg, sizeof(enum i2c_speed))) {
		cn_dev_i2c_err(i2c_set, "copy_from_user failed.");
		return -EFAULT;
	}
	ret = cn_config_i2c_speed(i2c_set, speed);

	return ret;
}

int i2c_read(unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)core->i2c_set;
	struct cn_i2c_msg read_msg;

	if (copy_from_user((void *)&read_msg, (void *)arg,
				sizeof(struct cn_i2c_msg))) {
		cn_dev_i2c_err(i2c_set, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		ret = cn_i2c_read(i2c_set, &read_msg);
		/* copy read result to user in the func */
	}
	
	return ret;
}

int i2c_write(unsigned long arg,
	unsigned int cmd, struct cn_core_set *core)
{
	int ret = 0;
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)core->i2c_set;
	struct cn_i2c_msg write_msg;

	if (copy_from_user((void *)&write_msg, (void *)arg,
				sizeof(struct cn_i2c_msg))) {
		cn_dev_i2c_err(i2c_set, "copy_from_user failed.");
		ret = -EFAULT;
	} else {
		ret = cn_i2c_write(i2c_set, &write_msg);
	}
	
	return ret;
}

typedef int (*i2c_ioctl_func)(unsigned long arg,
	unsigned int cmd, struct cn_core_set *core);

static const struct {
	i2c_ioctl_func funcs;
	u64 flags;
} i2c_funcs[I2C_MAX_NR_COUNT] = {
	[_I2C_CONFIG_SPEED] = {i2c_config_speed, 0},
	[_I2C_READ] = {i2c_read, 0},
	[_I2C_WRITE] = {i2c_write, 0},
};

#define I2C_IOCTL

long cn_i2c_ioctl(void *pcore, unsigned int cmd, unsigned long arg)
{
#ifdef I2C_IOCTL
	long ret = 0;
	unsigned int ioc_nr = _IOC_NR(cmd);
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)core->i2c_set;

	if (i2c_funcs[ioc_nr].funcs) {
		ret = i2c_funcs[ioc_nr].funcs(arg, cmd, core);
	} else {
		cn_dev_i2c_err(i2c_set, "IOCTRL command# %d is invalid!", _IOC_NR(cmd));
		ret = -EINVAL;
	}
	cn_dev_i2c_debug(i2c_set, "i2c ioctl finish");
	return ret;
#else
	cn_dev_i2c_err(i2c_set, "unsupport call i2c ioctl from user space");
	return -EFAULT;
#endif
}

int cn_i2c_init(struct cn_core_set *core)
{
	struct cn_i2c_set *i2c_set;

	if ((core->device_id == MLUID_370_DEV) || (core->device_id == MLUID_590_DEV)) {
		cn_dev_core_info(core, "no support 370 dev.\n");
		return 0;
	}

	cn_dev_core_info(core, "i2c init");

	i2c_set = cn_kzalloc(sizeof(struct cn_i2c_set), GFP_KERNEL);
	if (!i2c_set) {
		cn_dev_core_err(core, "alloc i2c set error");
		return -ENOMEM;
	}
	core->i2c_set = i2c_set;
	i2c_set->core = core;

	switch (core->device_id) {
	case MLUID_270:
		/* dw_apb_i2c in mlu270 */
		dw_i2c_init(i2c_set);
		break;
	default:
		cn_dev_i2c_info(i2c_set, "i2c not support in this platform");
		core->i2c_set = NULL;
		cn_kfree(i2c_set);
		return 0;
	}

	return 0;
}

void cn_i2c_exit(struct cn_core_set *core)
{
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)core->i2c_set;

	cn_dev_core_info(core, "i2c free");

	if (i2c_set) {
		if (i2c_set->i2c_ops) {
			if (i2c_set->i2c_ops->i2c_free) {
				i2c_set->i2c_ops->i2c_free(i2c_set);
			}
		}
		cn_kfree(i2c_set);
	}
}


