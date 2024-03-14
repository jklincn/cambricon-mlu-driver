#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <asm/delay.h>
#include <linux/semaphore.h>
#include <linux/compiler.h>

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_i2c_internal.h"
#include "dw_apb_i2c.h"


static void dw_writel(void *pcore, unsigned long offset, u32 val)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	reg_write32(core->bus_set, I2C_REG_BASE + offset, val);
}

static u32 dw_readl(void *pcore, unsigned long offset)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	return reg_read32(core->bus_set, I2C_REG_BASE + offset);
}

/*
 * @brief enable or disable dw_apb_i2c module
 * @param enable : 1 enable
 *				   0 disable
 */
static int __dw_enable(void *pcore, bool enable)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)core->i2c_set;
	int timeout = MAX_POLL_COUNT;

	do {
		dw_writel(pcore, IC_ENABLE, enable);
		if ((dw_readl(pcore, IC_ENABLE_STATUS) & 0x01) == enable)
			return 0;

		usleep_range(25, 250);
	} while (timeout--);

	cn_dev_i2c_err(i2c_set, "timeout in %sabling dw_apb_i2c", enable ? "en" : "dis");
	return -ETIMEDOUT;
}

/*
 * @brief polling spec bit in interrupt state register
 * @param check_bit specific bit
 */
static int __wait_interrupt_stat(void *pcore, int check_bit)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)core->i2c_set;
	int timeout = MAX_POLL_COUNT;

	do {
		if (((dw_readl(pcore, IC_RAW_INTR_STAT) >>
						check_bit) & 0x01) == 1)
			return 0;

		usleep_range(25, 250);
	} while (timeout--);

	cn_dev_i2c_err(i2c_set, "wait IC_RAW_INTR_STAT[%d] timeout", check_bit);
	return -ETIMEDOUT;
}

static int __wait_i2c_idle(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)core->i2c_set;
	int timeout = MAX_POLL_COUNT;

	do {
		if (((dw_readl(pcore, IC_STATUS) >>
						IC_MST_ACTIVITY) & 0x01) == 0)
			return 0;

		usleep_range(25, 250);
	} while (timeout--);

	cn_dev_i2c_err(i2c_set, "wait i2c bus idle timeout");
	return -ETIMEDOUT;

}

int dw_config_i2c_speed(void *iset, enum i2c_speed speed)
{
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)iset;
	struct cn_core_set *core = i2c_set->core;
	u32 reg;

	if (unlikely(down_killable(&i2c_set->dw_i2c_sem))) {
		cn_dev_i2c_err(i2c_set, "get dw_i2c_sem error");
		return -EINTR;
	}

	/* IC_CON only can be written when DW_apb_i2c is disabled */
	__dw_enable(core, DW_DISABLE);

	/* only support STD_SPEED and FAST_SPEED in firt version */
	cn_dev_i2c_info(i2c_set, "config i2c bus speed: %d", speed);
	reg = dw_readl(core, IC_CON);
	reg &= ~(0x3 << 1);
	switch (speed) {
	case STD_SPEED:
		reg |= (0x01 << 1);
		break;
	case FAST_SPEED:
		reg |= (0x02 << 1);
		break;
	default:
		cn_dev_i2c_err(i2c_set, "unspport i2c speed config");
		break;
	}

	cn_dev_i2c_debug(i2c_set, "config IC_CON reg : %#x", reg);
	dw_writel(core, IC_CON, reg);

	__dw_enable(core, DW_ENABLE);
	up(&i2c_set->dw_i2c_sem);
	return 0;
}

int dw_i2c_write(void *iset, struct cn_i2c_msg *i2c_msg)
{
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)iset;
	struct cn_core_set *core = (struct cn_core_set *)i2c_set->core;
	int count = i2c_msg->len;
	u8 *w_msg = NULL;
	int i = 0;
	int ret;

	cn_dev_i2c_info(i2c_set, "write %d byte", count);
	w_msg = cn_kzalloc(count, GFP_KERNEL);
	if (!w_msg) {
		cn_dev_i2c_err(i2c_set, "kzalloc failed, count = %d", count);
		return -ENOMEM;
	}
	/* TODO: no need use copy_from_user if in kernel space */
	if (copy_from_user((void *)w_msg, (void *)i2c_msg->buff,
						sizeof(u8) * count)) {
		cn_dev_i2c_err(i2c_set, "copy_from_user failed.");
		cn_kfree(w_msg);
		return -EFAULT;
	}

	if (unlikely(down_killable(&i2c_set->dw_i2c_sem))) {
		cn_dev_i2c_err(i2c_set, "get dw_i2c_sem error");
		cn_kfree(w_msg);
		return -EINTR;
	}

	__dw_enable(core, DW_DISABLE);
	dw_writel(core, IC_TAR, i2c_msg->addr);
	__dw_enable(core, DW_ENABLE);

	/* send count-1 byte */
	for (i = 0; i < (count - 1); i++) {
		cn_dev_i2c_debug(i2c_set, "w_msg: %#x", w_msg[i]);
		dw_writel(core, IC_DATA_CMD, (unsigned short)w_msg[i]);
		ret = __wait_interrupt_stat(core, IC_INTR_TX_EMPTY);
		if (ret)
			goto wait_intr_err;
	}

	/* send the last byte and generate stop */
	cn_dev_i2c_debug(i2c_set, "w_msg: %#x", w_msg[i]);
	dw_writel(core, IC_DATA_CMD, 0x200 | (unsigned short)w_msg[i]);
	ret = __wait_interrupt_stat(core, IC_INTR_TX_EMPTY);
	if (ret)
		goto wait_intr_err;

	ret = __wait_i2c_idle(core);

wait_intr_err:
	__dw_enable(core, DW_DISABLE);
	up(&i2c_set->dw_i2c_sem);
	cn_kfree(w_msg);
	return ret;
}

static int dw_i2c_read_byte(void *pcore, u32 data_cmd, u8 *r_byte)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	int ret;

	dw_writel(core, IC_DATA_CMD, data_cmd);
	ret = __wait_interrupt_stat(core, IC_INTR_RX_FULL);
	if (ret)
		return ret;

	*r_byte = (u8)dw_readl(pcore, IC_DATA_CMD);
	cn_dev_i2c_debug(((struct cn_i2c_set *)core->i2c_set),
						"r_byte: %#x", *r_byte);
	return __wait_interrupt_stat(pcore, IC_INTR_TX_EMPTY);

}


int dw_i2c_read(void *iset, struct cn_i2c_msg *i2c_msg)
{
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)iset;
	struct cn_core_set *core = i2c_set->core;
	u8 *r_msg = NULL;
	int count;
	u32 data_cmd = 0x100;
	u16 flag = i2c_msg->flag;
	int i = 0;
	int ret;

	if (flag & I2C_R_SLAVE_LEN) {
		cn_dev_i2c_info(i2c_set, "read length is the first byte receive");
		count = 255;
	} else {
		count = i2c_msg->len;
		cn_dev_i2c_info(i2c_set, "read %d byte", count);
	}

	r_msg = cn_kzalloc(sizeof(u8) * count, GFP_KERNEL);
	if (!r_msg) {
		cn_dev_i2c_err(i2c_set, "kzalloc failed, count = %d", count);
		return -ENOMEM;
	}

	if (unlikely(down_killable(&i2c_set->dw_i2c_sem))) {
		cn_dev_i2c_err(i2c_set, "get dw_i2c_sem error");
		cn_kfree(r_msg);
		return -EINTR;
	}

	__dw_enable(core, DW_DISABLE);
	dw_writel(core, IC_TAR, i2c_msg->addr);
	__dw_enable(core, DW_ENABLE);

	/* receive first count-1 bytes of r_msg */
	if (flag & I2C_R_SLAVE_LEN) {
		ret = dw_i2c_read_byte(core, data_cmd, r_msg);
		if (ret)
			goto wait_intr_err;
		count = r_msg[0];
		cn_dev_i2c_info(i2c_set, "read %d byte", count);

		for (i = 1; i < (count - 1); i++) {
			ret = dw_i2c_read_byte(core, data_cmd, r_msg + i);
			if (ret)
				goto wait_intr_err;
		}
	} else {
		for (i = 0; i < (count - 1); i++) {
			ret = dw_i2c_read_byte(core, data_cmd, r_msg + i);
			if (ret)
				goto wait_intr_err;
		}
	}

	/* receive last byte and than generate STOP */
	data_cmd |= 0x200;
	cn_dev_i2c_debug(i2c_set, "data_cmd %#x", data_cmd);
	ret = dw_i2c_read_byte(core, data_cmd, r_msg + i);
	if (ret)
		goto wait_intr_err;

	ret = __wait_i2c_idle(core);
	if (ret)
		goto wait_intr_err;

	__dw_enable(core, DW_DISABLE);
	up(&i2c_set->dw_i2c_sem);

	/* TODO: no need use copy_to_user  if in kernel space */
	if (copy_to_user((void *)i2c_msg->buff, (void *)r_msg,
					count * sizeof(u8))) {
		cn_dev_i2c_err(i2c_set, "copy_to_user failed.");
		cn_kfree(r_msg);
		__dw_enable(core, DW_DISABLE);
		return -EFAULT;
	}
	cn_kfree(r_msg);
	return 0;

wait_intr_err:
	__dw_enable(core, DW_DISABLE);
	up(&i2c_set->dw_i2c_sem);
	cn_kfree(r_msg);
	return ret;
}

void dw_i2c_free(void *iset)
{
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)iset;
	struct cn_core_set *core = i2c_set->core;

	cn_dev_i2c_info(i2c_set, "dw_apb_i2c module free");
	__dw_enable(core, DW_DISABLE);
}


static const struct cn_i2c_ops dw_i2c_ops = {
	.i2c_free = dw_i2c_free,
	.config_i2c_speed = dw_config_i2c_speed,

	.i2c_read = dw_i2c_read,
	.i2c_write = dw_i2c_write,
};

int dw_i2c_init(void *iset)
{
	struct cn_i2c_set *i2c_set = (struct cn_i2c_set *)iset;
	struct cn_core_set *core = i2c_set->core;
	u32 reg;

	cn_dev_i2c_info(i2c_set, "dw_apb_i2c module init");

	i2c_set->i2c_ops = &dw_i2c_ops;

	/* IC_CON only can be written when DW_apb_i2c is disabled */
	__dw_enable(core, DW_DISABLE);

	reg = IC_CON_SLAVE_DISABLE | IC_CON_RESTART_EN |
		  IC_CON_SPEED_STD | IC_CON_MASTER;
	cn_dev_i2c_info(i2c_set, "IC_CON reg initialized: %#x", reg);
	dw_writel(core, IC_CON, reg);

	/* FIFO is not use */
	dw_writel(core, IC_RX_TL, 0x00);
	dw_writel(core, IC_TX_TL, 0x00);

	sema_init(&i2c_set->dw_i2c_sem, 1);
	/* __dw_enable(core, DW_ENABLE); */
	return 0;
}

