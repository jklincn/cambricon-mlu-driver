#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/platform_device.h>

#include <linux/kthread.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_mcu.h"
#include "cndrv_debug.h"

#include "cndrv_trans.h"
#include "trans.h"

unsigned int host_mcu_read32_reg(void *tran_set, unsigned long offset)
{
	struct cn_host_mcu_tran_set *p = (struct cn_host_mcu_tran_set *)tran_set;
	struct cn_core_set *core = (struct cn_core_set *)(p->core);

	return reg_read32(core->bus_set, offset);
}
void host_mcu_write32_reg(void *tran_set, unsigned long offset, unsigned int value)
{
	struct cn_host_mcu_tran_set *p = (struct cn_host_mcu_tran_set *)tran_set;
	struct cn_core_set *core = (struct cn_core_set *)(p->core);

	reg_write32(core->bus_set, offset, value);
}

int set_start_tran_data(struct cn_host_mcu_tran_set *host_mcu_tran_set)
{
	host_mcu_write32_reg(host_mcu_tran_set, MAILBOX_CH1_INFO, 0x1);
	return 0;
}

int check_cur_data_status(void *tran_set)
{
	unsigned long flags = 0;
	struct cn_host_mcu_tran_set *host_mcu_tran = (struct cn_host_mcu_tran_set *)tran_set;

	spin_lock_irqsave(&host_mcu_tran->trans_lock, flags);
	if (host_mcu_tran->w_len) {
		spin_unlock_irqrestore(&host_mcu_tran->trans_lock, flags);
		return 1;
	}
	spin_unlock_irqrestore(&host_mcu_tran->trans_lock, flags);

	return 0;
}

int pre_trans_data_init(void *tran_set, unsigned int *info, unsigned int count)
{
	unsigned long flags = 0;
	struct cn_host_mcu_tran_set *host_mcu_tran = (struct cn_host_mcu_tran_set *)tran_set;


	if ((count + host_mcu_tran->cur_index) > host_mcu_tran->max_len || !count) {

		cn_dev_err("trans count is tool big or count is 0");
		return -1;
	}

	spin_lock_irqsave(&host_mcu_tran->trans_lock, flags);

	host_mcu_tran->w_buffer = info;
	host_mcu_tran->w_len = count;
	host_mcu_tran->w_index = 0;
	host_mcu_tran->w_retry = 0;
	host_mcu_tran->w_delay = 0;
	host_mcu_tran->w_status = 0;
	if (host_mcu_tran->ready == HOST_MCU_TRANS_STATUS_SUCCESS) {
		host_mcu_tran->ready = 0;
	}
	spin_unlock_irqrestore(&host_mcu_tran->trans_lock, flags);

	return 0;
}

u32 update_data_to_buffer(void *tran_set)
{
	u32 index = 0;
	u32 *buffer = NULL;
	unsigned long flags = 0;
	struct cn_host_mcu_tran_set *host_mcu_tran = (struct cn_host_mcu_tran_set *)tran_set;

	spin_lock_irqsave(&host_mcu_tran->trans_lock, flags);

	if (host_mcu_tran->w_status) {

		buffer = host_mcu_tran->buffer;
		index = host_mcu_tran->w_index;

		if (host_mcu_tran->w_status != HOST_MCU_TRANS_STATUS_SUCCESS) {
			if (index) {
				index = index - 1;
			}
		}

		if (index) {
			memcpy(buffer + host_mcu_tran->cur_index, host_mcu_tran->w_buffer, index*sizeof(u32));
		}
		host_mcu_tran->cur_index += index;
		host_mcu_tran->w_status = 0;
		host_mcu_tran->w_buffer = NULL;
		host_mcu_tran->w_len = 0;
		host_mcu_tran->w_index = 0;
	}

	if (!host_mcu_tran->ready) {
		host_mcu_tran->ready = HOST_MCU_TRANS_STATUS_SUCCESS;
	}

	spin_unlock_irqrestore(&host_mcu_tran->trans_lock, flags);

	return index;
}

void clear_data_odd_bit(struct cn_host_mcu_tran_set *host_mcu_tran)
{
	u32 len = host_mcu_tran->cur_index;
	int i = 0;
	u32 value = 0x1;
	u32 *buffer = host_mcu_tran->buffer;

	for (i = 0; i < len; i++) {
		buffer[i] = (buffer[i] & (~value));
	}
}


int cn_bus_get_soft_repair_info(void *bus_set, unsigned int *info, unsigned int *count)
{
	struct cn_bus_set *bus = bus_set;

	struct cn_core_set *core = NULL;
	struct cn_host_mcu_tran_set *host_mcu_tran = NULL;
	unsigned long flags = 0;
	int ret = -1;
	u8 ready = 0;
	u32 max_len = 0;

	if (IS_ERR_OR_NULL(bus_set)) {
		cn_dev_err("trans bus_set is null");
		return ret;
	}

	core = bus->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("trans refresh repair core is null");
		return ret;
	}

	host_mcu_tran = (struct cn_host_mcu_tran_set *)core->trans_set;
	if (IS_ERR_OR_NULL(host_mcu_tran)) {
		cn_dev_err("trans trans_set is null");
		return ret;
	}

	spin_lock_irqsave(&host_mcu_tran->trans_lock, flags);

	ready = host_mcu_tran->ready;
	max_len = host_mcu_tran->max_len;

	if (ready == HOST_MCU_TRANS_STATUS_SUCCESS && *count <= max_len) {

		clear_data_odd_bit(host_mcu_tran);

		*count = host_mcu_tran->cur_index;
		if (*count) {
			memcpy(info, host_mcu_tran->buffer, (*count)*sizeof(u32));
		}

		ret = 0;
	}
	spin_unlock_irqrestore(&host_mcu_tran->trans_lock, flags);

	return ret;
}

int cn_bus_is_support_soft_repair_info(void *bus_set)
{
	int ret = -1;
	struct cn_core_set *core = NULL;
	struct cn_bus_set *bus = bus_set;

	if (IS_ERR_OR_NULL(bus_set)) {
		cn_dev_err("trans refresh repair bus set or info is null");
		return ret;
	}

	core = bus->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("trans refresh repair trans core is null");
		return ret;
	}

	if (IS_ERR_OR_NULL(core->trans_set)) {
		cn_dev_info("trans is not support hbm repair");
		return ret;
	}

	return 0;
}

int cn_bus_refresh_soft_repair_info(void *bus_set, unsigned int *info, unsigned int count)
{
	struct cn_bus_set *bus = bus_set;
	struct cn_core_set *core = NULL;
	struct cn_host_mcu_tran_set *host_mcu_tran = NULL;
	unsigned long flags = 0;
	int ret = -1;
	u8 status = 0;
	int timeout = 32;
	int times = 0;
	u32 data  = 0;

	cn_dev_info("trans refresh soft repair info");

	if (IS_ERR_OR_NULL(bus_set) || IS_ERR_OR_NULL(info)) {
		cn_dev_err("trans refresh repair bus set or info is null");
		return ret;
	}
	core = bus->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("trans refresh repair trans core is null");
		return ret;
	}

	host_mcu_tran = (struct cn_host_mcu_tran_set *)(core->trans_set);
	if (IS_ERR_OR_NULL(host_mcu_tran)) {
		cn_dev_err("trans refresh repair trans is null");
		return ret;
	}
	if (check_cur_data_status(host_mcu_tran)) {
		cn_dev_info("trans refresh repair is updating data");
		return ret;
	}
	ret = pre_trans_data_init(host_mcu_tran, info, count);
	if (ret) {
		cn_dev_err("trans refresh repair pre start error");
		return ret;
	}
	host_mcu_tran->w_index = 1;
	/*first to write data to trigger mailbox int0 signal*/
	data = *info;
	if (!check_odd_parity(data)) {
		data |= 1;
	}
	host_mcu_write32_reg(host_mcu_tran, MAILBOX_CH0_INFO, data);

	while (1) {
		msleep(20);
		spin_lock_irqsave(&host_mcu_tran->trans_lock, flags);
		status = host_mcu_tran->w_status;
		spin_unlock_irqrestore(&host_mcu_tran->trans_lock, flags);
		if (status || times > timeout) {

			if (status == HOST_MCU_TRANS_STATUS_SUCCESS) {
				ret = 0;
				cn_dev_info("trans refresh repair status:%d", status);
				break;
			}
			if (times > timeout) {
				spin_lock_irqsave(&host_mcu_tran->trans_lock, flags);
				host_mcu_tran->w_status = HOST_MCU_TRANS_STATUS_TIMEOUT;
				ret = 0;
				spin_unlock_irqrestore(&host_mcu_tran->trans_lock, flags);
			}

			cn_dev_info("trans refresh repair status:%d", status);
			break;
		}
		times++;
	}

	ret = update_data_to_buffer(host_mcu_tran);
	if (!ret) {
		ret = -1;
	}

	return ret;
}

int cn_trans_check_mcu_ver_mlu290(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("trans host mcu pcore is null");
		return -EINVAL;
	}

	if (core->board_info.mcu_info.mcu_major == TRANS_MCU_TEST_VER_MAJOR) {
		goto over;
	}

	if (core->board_info.mcu_info.mcu_major >= TRANS_MCU_VER_MAJOR) {
		return 0;
	}

over:
	cn_dev_info("trans mcu version(v%x.%x.%x) is not support hbm repair",
		core->board_info.mcu_info.mcu_major,
		core->board_info.mcu_info.mcu_minor,
		core->board_info.mcu_info.mcu_build);

	return -EINVAL;
}

int cn_host_mcu_trans_init(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	int ret = 0;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("trans host mcu core is null");
		return -EINVAL;
	}
	core->trans_set = NULL;

	switch (core->device_id) {
	case MLUID_290:
		ret = cn_trans_check_mcu_ver_mlu290(core);
		if (ret) {
			return 0;
		}
		ret = host_mcu_init_mlu290(core);
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

void cn_host_mcu_free(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_host_mcu_tran_set *host_mcu_tran = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("core is null");
		return;
	}

	host_mcu_tran = (struct cn_host_mcu_tran_set *)(core->trans_set);
	if (IS_ERR_OR_NULL(host_mcu_tran)) {
		goto finish;
	}
	unregister_host_mcu_trans_irq(host_mcu_tran);

	if (IS_ERR_OR_NULL(host_mcu_tran->buffer)) {
		goto free_trans;
	}

	/* freee trans buffer */
	cn_kfree(host_mcu_tran->buffer);
	host_mcu_tran->buffer = NULL;

free_trans:
	cn_kfree(host_mcu_tran);
	core->trans_set = NULL;

finish:
	cn_dev_info("trans host mcu trans free finish");
}
