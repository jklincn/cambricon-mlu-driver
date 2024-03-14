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
#include <linux/pci.h>

#include <linux/sched.h>
#include <linux/kthread.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_mcu.h"
#include "cndrv_debug.h"


#include "trans.h"


/**
 * @brief clear mailbox interrupt register for mcu send data
 * @param tran_set mcu trans set struct
 * @return
 */
void clear_register_for_mcu_reused(void *tran_set)
{
	unsigned long offset = 0;

	for (offset = MAILBOX_CH2_INFO; offset <= MAILBOX_CH13_INFO;) {
		host_mcu_write32_reg(tran_set, offset, 0x00);
		offset += 4;
	}
}

int check_mailbox_reg0(void *tran_set)
{
	u32 reg = 0;

	reg = host_mcu_read32_reg(tran_set, MAILBOX_CH0_INFO);
	if (reg) {
		return 1;
	}
	return 0;
}

void inc_mailbox_delay_count(void *tran_set)
{
	struct cn_host_mcu_tran_set *pcore = (struct cn_host_mcu_tran_set *)tran_set;

	pcore->w_delay++;
	if (pcore->w_delay > HOST_MCU_TRANS_RETRY_COUNT) {
		pcore->w_delay = HOST_MCU_TRANS_RETRY_COUNT + 1;
		spin_lock(&pcore->trans_lock);
		pcore->w_status = HOST_MCU_TRANS_STATUS_TIMEOUT;
		cn_dev_debug("trans timeout,w_status:%d\n", pcore->w_status);
		spin_unlock(&pcore->trans_lock);
	}
}

/**
 * @brief check mailbox interrupt register status,to receive data from mcu
 * @param host mcu trans set struct
 * @return 0 - not trigger interrupt
 *         1 - trigger interrupt
 */
int check_mailbox_interrupt_recv_status(void *tran_set)
{
	u32 reg = 0;

	/*check register status two bit,to prevent interrupt loss*/
	reg = host_mcu_read32_reg(tran_set, MAILBOX_INT_STATUS0_INFO);
	if (reg & MAILBOX_INT_STATUS0_BIT3) {
		return 1;
	}
	reg = host_mcu_read32_reg(tran_set, MAILBOX_INT_STATUS0_INFO);
	if (reg & MAILBOX_INT_STATUS0_BIT2) {
		return 1;
	}
	return 0;
}

/**
 * @brief check register status,whether to resend data to mcu
 * @param host mcu trans set struct
 * @return 0 - trigger interrupt
 *         1 - not trigger interrupt
 */
int check_mailbox_resend_register_status(void *tran_set)
{
	u32 reg = 0;

	if (IS_ERR_OR_NULL(tran_set)) {
		cn_dev_err("trans_set is null");
		return 0;
	}
	reg = host_mcu_read32_reg(tran_set, MAILBOX_INT_STATUS0_INFO);
	if (reg & MAILBOX_INT_STATUS0_BIT1) {
		return 1;
	}
	return 0;
}
/**
 * @brief check register status,whether trigger interrupt,send data to mcu
 * @param host mcu trans set struct
 * @return 0 - not trigger interrupt
 *         1 - trigger interrupt
 */
int check_mailbox_send_register_status(void *tran_set)
{
	u32 reg = 0;

	if (IS_ERR_OR_NULL(tran_set)) {
		cn_dev_err("trans_set is null");
		return 0;
	}
	reg = host_mcu_read32_reg(tran_set, MAILBOX_INT_STATUS0_INFO);
	if (reg & MAILBOX_INT_STATUS0_BIT0) {
		return 1;
	}
	return 0;
}


/**
 * @brief clear mailbox register,trigger interrupt for mcu send data
 * @param host mcu trans set struct
 * @return
 */
void clear_mailbox_interrupt_recv_status(void *tran_set, u32 type)
{
	u32 reg = 0;
	u32 value = type;

	if (IS_ERR_OR_NULL(tran_set)) {
		cn_dev_err("trans_set is null");
		return;
	}

	switch (value) {
	case MAILBOX_INT_STATUS0_BIT2:
		reg = host_mcu_read32_reg(tran_set, MAILBOX_INT_STATUS0_INFO);
		if (reg & value) {
			value = ((~value) & reg) | MAILBOX_INT_STATUS0_BIT18;
			host_mcu_write32_reg(tran_set, MAILBOX_INT_STATUS0_INFO, value);
		}
		break;
	case MAILBOX_INT_STATUS0_BIT3:
		reg = host_mcu_read32_reg(tran_set, MAILBOX_INT_STATUS0_INFO);
		if (reg & value) {
			value = ((~value) & reg) | MAILBOX_INT_STATUS0_BIT19;
			host_mcu_write32_reg(tran_set, MAILBOX_INT_STATUS0_INFO, value);
		}
		break;
	default:
		break;
	}
}

void clear_mailbox_resend_register_status(void *tran_set)
{
	u32 reg = 0;
	u32 value = MAILBOX_INT_STATUS0_BIT1;

	reg = host_mcu_read32_reg(tran_set, MAILBOX_INT_STATUS0_INFO);
	if (reg & value) {
		value = ((~value) & reg) | MAILBOX_INT_STATUS0_BIT17;

		host_mcu_write32_reg(tran_set, MAILBOX_INT_STATUS0_INFO, value);
	}
}

void clear_mailbox_send_register_status(void *tran_set)
{
	u32 reg = 0;
	u32 value = MAILBOX_INT_STATUS0_BIT0;

	reg = host_mcu_read32_reg(tran_set, MAILBOX_INT_STATUS0_INFO);
	if (reg & value) {
		value = ((~value) & reg) | MAILBOX_INT_STATUS0_BIT16;
		host_mcu_write32_reg(tran_set, MAILBOX_INT_STATUS0_INFO, value);
	}
}
/**
 * @brief read mailbox register data to temp struct
 * @param core cn_host_mcu_tran_set struct
 * @param host mailbox_reg_data struct
 * @return
 */
void read_reg2_13_data(void *core, struct mailbox_reg_data *reg_data)
{
	u16 i = 0;
	unsigned long j = 0;
	struct cn_host_mcu_tran_set *pcore = core;

	for (i = 0, j = MAILBOX_CH2_INFO; j <= MAILBOX_CH13_INFO; i++) {
		if (i == MAILBOX_TRANS_DATA_REG_COUNT) {
			break;
		}
		reg_data->reg_buf[i] = host_mcu_read32_reg(pcore, j);
		j += 4;
	}
	reg_data->real_count = MAILBOX_TRANS_DATA_REG_COUNT;
}

void clear_reg_odd_bit(struct mailbox_reg_data *reg_data)
{
	u32 len = reg_data->real_count;
	int i = 0;
	u32 value = 0x1;

	for (i = 0; i < len; i++) {
		reg_data->reg_buf[i] = (reg_data->reg_buf[i] & (~value));
	}
}

int update_reg_data_to_buffer(void *core, struct mailbox_reg_data *reg_data)
{
	struct cn_host_mcu_tran_set *pcore = core;
	u32 len = reg_data->real_count;
	u32 cur_index = 0;
	u32 *buffer = pcore->buffer;

	if ((len + pcore->cur_index) > pcore->max_len) {

		spin_lock(&pcore->trans_lock);

		pcore->ready = HOST_MCU_TRANS_STATUS_FAILED;
		pcore->cur_index = pcore->max_len;
		cn_dev_debug("trans update data,ready:%d\n", pcore->ready);

		spin_unlock(&pcore->trans_lock);

		return 0;
	}

	cur_index = pcore->cur_index;

	memcpy(buffer+cur_index, reg_data->reg_buf, sizeof(u32)*len);
	pcore->cur_index += len;

	return 0;
}

int check_reg1_info(void *core)
{
	u32 reg = 0;

	reg = host_mcu_read32_reg(core, MAILBOX_CH1_INFO);
	if (reg) {
		return 1;
	}
	return 0;
}

int check_recv_data_full_zero(struct mailbox_reg_data *reg_data)
{
	u32 i = 0;

	for (i = 0; i < reg_data->real_count; i++) {
		if (reg_data->reg_buf[i]) {
			return 0;
		}
	}
	return 1;
}

int get_last_recv_data_end_index(struct mailbox_reg_data *reg_data)
{
	u32 i = 0;
	u32 value = TRANS_DATA_END_FLAG;

	for (i = 0; i < reg_data->real_count; i++) {
		if (reg_data->reg_buf[i] & value) {
			reg_data->reg_buf[i] = (reg_data->reg_buf[i] & (~value));
			return i;
		}
	}
	return -1;
}

int trans_check_data_ready(void *core)
{
	struct cn_host_mcu_tran_set *pcore = core;

	spin_lock(&pcore->trans_lock);

	if (pcore->ready) {

		spin_unlock(&pcore->trans_lock);

		return 1;
	}
	spin_unlock(&pcore->trans_lock);

	return 0;
}

void trans_set_data_ready(void *core, u8 value)
{
	struct cn_host_mcu_tran_set *pcore = core;

	spin_lock(&pcore->trans_lock);
	pcore->ready = value;
	spin_unlock(&pcore->trans_lock);
}

u8 check_odd_parity(u32 value)
{
	u8 flag = 0;

	while (value) {
		flag = !flag;
		value = value & (value-1);
	}
	return flag;
}

int check_odd_data(void *core)
{
	u32 i = 0;
	struct cn_host_mcu_tran_set *pcore = core;
	u32 *buffer = (u32 *)pcore->buffer;

	for (i = 0; i < pcore->cur_index; i++) {
		if (!check_odd_parity(buffer[i])) {
			return 0;
		}
	}
	return 1;
}

int trans_set_mcu_resend_data_flag(void *core)
{
	struct cn_host_mcu_tran_set *pcore = core;

	pcore->cur_index = 0;
	memset(pcore->buffer, 0, pcore->max_len);
	host_mcu_write32_reg(core, MAILBOX_CH1_INFO, 0x01);
	pcore->retry++;

	if (pcore->retry > HOST_MCU_TRANS_RETRY_COUNT) {
		pcore->retry = HOST_MCU_TRANS_RETRY_COUNT + 1;

		trans_set_data_ready(core, HOST_MCU_TRANS_STATUS_FAILED);
	}
	return 0;
}

int trans_resend_data_to_mcu(void *core)
{
	struct cn_host_mcu_tran_set *pcore = core;
	u32 data = 0;
	u32 *buffer = NULL;

	if (pcore->w_index > pcore->w_len) {
		return 0;
	}
	if (pcore->w_index > 0) {

		if (pcore->w_index <= pcore->w_len) {
			buffer = (u32 *)pcore->w_buffer;
			data = *(buffer + pcore->w_index - 1);
			if (!check_odd_parity(data)) {
				data |= 1;
			}
			host_mcu_write32_reg(core, MAILBOX_CH0_INFO, data);
		}

		pcore->w_retry++;
		if (pcore->w_retry > HOST_MCU_TRANS_RETRY_COUNT) {

			spin_lock(&pcore->trans_lock);
			pcore->w_status = HOST_MCU_TRANS_STATUS_FAILED;

			cn_dev_debug("trans resend,w_status:%d\n", pcore->w_status);

			spin_unlock(&pcore->trans_lock);

			pcore->w_retry = HOST_MCU_TRANS_RETRY_COUNT + 1;
		}
	}

	return 0;
}

int trans_send_data_to_mcu(void *core)
{
	struct cn_host_mcu_tran_set *trans_set = core;
	u32 data = 0;
	u32 *buffer = (u32 *)trans_set->w_buffer;

	if (trans_set->w_index > trans_set->w_len) {
		return 0;
	}

	if (trans_set->w_index == trans_set->w_len) {

		spin_lock(&trans_set->trans_lock);

		trans_set->w_status = HOST_MCU_TRANS_STATUS_SUCCESS;

		cn_dev_debug("trans send success,w_status:%d\n", trans_set->w_status);

		spin_unlock(&trans_set->trans_lock);

		return 0;
	}

	data = *(buffer + trans_set->w_index);
	if (!check_odd_parity(data)) {
		data |= 1;
	}

	host_mcu_write32_reg(core, MAILBOX_CH0_INFO, data);
	trans_set->w_retry = 0;
	trans_set->w_delay = 0;
	trans_set->w_index++;

	return 0;
}

u8 check_send_data_status(void *core)
{
	struct cn_host_mcu_tran_set *trans_set = core;
	u8 status = 0;

	spin_lock(&trans_set->trans_lock);
	status = trans_set->w_status;
	spin_unlock(&trans_set->trans_lock);

	return  status;
}

int check_send_data_length(void *core)
{
	struct cn_host_mcu_tran_set *trans_set = core;

	if (!trans_set->w_len) {

		return 1;
	}

	return  0;
}

void trans_data_to_mcu_mlu290_int_handle(int irq_index, void *data)
{
	struct cn_host_mcu_tran_set *tran_set = data;

	if (IS_ERR_OR_NULL(tran_set)) {
		cn_dev_err("Invalid core\n");
		goto out;
	}

	if (!check_mailbox_send_register_status(tran_set) && !check_mailbox_resend_register_status(tran_set)) {
		goto out;
	}

	/*check whether host send data complete or data length is 0*/
	if (check_send_data_status(tran_set) || check_send_data_length(tran_set)) {
		goto out;
	}

	/*odd check failed,resend last time data*/
	if (check_mailbox_resend_register_status(tran_set)) {
		trans_resend_data_to_mcu(tran_set);
		cn_dev_debug("trans write data w_retry:%d\n", tran_set->w_retry);
		goto out;
	}

	/*check whether MCU read MAILBOX_CH0_INFO*/
	if (check_mailbox_reg0(tran_set)) {
		inc_mailbox_delay_count(tran_set);
		cn_dev_debug("trans mcu read w_delay:%d\n", tran_set->w_delay);
		goto out;
	}

	trans_send_data_to_mcu(tran_set);

out:

	clear_mailbox_send_register_status(tran_set);
	clear_mailbox_resend_register_status(tran_set);

	return;

}


void trans_data_from_mcu_mlu290_int_handle(int irq_index, void *data)
{
	struct cn_host_mcu_tran_set *trans_set = NULL;
	struct mailbox_reg_data reg_data;
	int last_index = 0;

	/* checking core */
	trans_set = (struct cn_host_mcu_tran_set *)data;
	if (IS_ERR_OR_NULL(trans_set)) {
		cn_dev_err("trans invalid core\n");
		goto out;
	}
	if (!check_mailbox_interrupt_recv_status(trans_set)) {
		goto out;
	}

	if (trans_check_data_ready(trans_set)) {
		goto out;
	}

	memset(&reg_data, 0, sizeof(struct mailbox_reg_data));

	read_reg2_13_data(trans_set, &reg_data);

	/*check whether all data are received completed*/
	if (check_reg1_info(trans_set)) {

		update_reg_data_to_buffer(trans_set, &reg_data);
		clear_register_for_mcu_reused(trans_set);
		goto out;
	}
	/*check data is full 0*/
	if (check_recv_data_full_zero(&reg_data)) {

		if (!check_odd_data(trans_set)) {
			/*check odd failed*/
			trans_set_mcu_resend_data_flag(trans_set);
			clear_register_for_mcu_reused(trans_set);
			cn_dev_debug("trans resend0 retry:%d\n", trans_set->retry);
			goto out;
		}

		trans_set_data_ready(trans_set, HOST_MCU_TRANS_STATUS_SUCCESS);

		goto out;
	}
	/*get the last data end index*/
	last_index = get_last_recv_data_end_index(&reg_data);
	if (last_index != -1) {
		reg_data.real_count = last_index + 1;
	} else {
		clear_register_for_mcu_reused(trans_set);
		trans_set_data_ready(trans_set, HOST_MCU_TRANS_STATUS_FAILED);
		cn_dev_err("trans format error\n");
		goto out;
	}

	update_reg_data_to_buffer(trans_set, &reg_data);

	if (!check_odd_data(trans_set)) {
		/*check odd failed*/
		trans_set_mcu_resend_data_flag(trans_set);
		clear_register_for_mcu_reused(trans_set);
		cn_dev_debug("trans resend1 retry:%d\n", trans_set->retry);
		goto out;
	}

	cn_dev_debug("trans from mcu success\n");
	trans_set_data_ready(trans_set, HOST_MCU_TRANS_STATUS_SUCCESS);

out:

	clear_mailbox_interrupt_recv_status(trans_set, MAILBOX_INT_STATUS0_BIT2);
	clear_mailbox_interrupt_recv_status(trans_set, MAILBOX_INT_STATUS0_BIT3);

}

irqreturn_t host_mcu_trans_mlu290_intr_handle(int irq_index, void *data)
{
	struct cn_host_mcu_tran_set *core = NULL;

	core = (struct cn_host_mcu_tran_set *)data;
	if (!core) {
		cn_dev_err("trans Invalid core\n");
		goto out;
	}

	if (check_mailbox_interrupt_recv_status(core)) {
		trans_data_from_mcu_mlu290_int_handle(irq_index, data);
	}

	if (check_mailbox_send_register_status(core) || check_mailbox_resend_register_status(core)) {
		trans_data_to_mcu_mlu290_int_handle(irq_index, data);
	}

out:
	return IRQ_HANDLED;
}


int register_host_mcu_trans_irq(struct cn_host_mcu_tran_set *tran_set)
{
	int ret = 0;
	struct cn_core_set *core = NULL;
	struct cn_bus_set *bus_set = NULL;
	int irq_num = 0;

	if (IS_ERR_OR_NULL(tran_set)) {
		cn_dev_err("trans_set is null");
		return -EINVAL;
	}
	core = (struct cn_core_set *)tran_set->core;
	/* Check mcu_set pointer */
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("trans_set core is null");
		return -EINVAL;
	}

	bus_set = core->bus_set;
	if (IS_ERR_OR_NULL(bus_set)) {
		cn_dev_err("trans_set core is null");
		return -EINVAL;
	}

	irq_num = cn_bus_get_irq_by_desc(bus_set, MAILBOX_INT0_NAME);

	if (irq_num == -1) {
		cn_dev_err("trans get irq num error");
		return -EINVAL;
	}

	ret = cn_bus_register_interrupt(core->bus_set,
			irq_num,
			host_mcu_trans_mlu290_intr_handle,
			(void *)tran_set);
	ret |= cn_bus_enable_irq(core->bus_set, irq_num);
	if (ret) {
		cn_dev_core_err(core,
				"trans register mailbox irq %d failed", irq_num);
		goto over;
	}

	cn_dev_info("trans register & enable host to mcu irq %d successfully",
		irq_num);

	return 0;
over:

	cn_bus_disable_irq(core->bus_set, irq_num);

	cn_bus_unregister_interrupt(core->bus_set, irq_num);

	return -EINVAL;
}

void unregister_host_mcu_trans_irq(struct cn_host_mcu_tran_set *tran_set)
{
	struct cn_core_set *core = NULL;
	struct cn_bus_set *bus_set = NULL;
	int irq_num = 0;

	if (IS_ERR_OR_NULL(tran_set)) {
		cn_dev_err("trans tran_set is null");
		return;
	}
	core = (struct cn_core_set *)tran_set->core;
	/* Check mcu_set pointer */
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("trans core set is null");
		return;
	}

	bus_set = core->bus_set;
	if (IS_ERR_OR_NULL(bus_set)) {
		cn_dev_err("trans_set core is null");
		return;
	}

	irq_num = cn_bus_get_irq_by_desc(bus_set, MAILBOX_INT0_NAME);

	if (irq_num == -1) {
		cn_dev_err("trans free irq num error");
		return;
	}

	cn_bus_disable_irq(core->bus_set, irq_num);

	cn_bus_unregister_interrupt(core->bus_set, irq_num);

}


void start_get_mailbox_data(void *tran_set)
{
	clear_register_for_mcu_reused(tran_set);
	host_mcu_write32_reg(tran_set, MAILBOX_CH1_INFO, 0x01);
}

int wait_for_get_epprom_storage_info(struct cn_host_mcu_tran_set *tran_set)
{
	unsigned long flags = 0;
	int ret = -EINVAL;
	u8 ready = 0;
	int count = 0;
	/*actual experience value,one interrupt process time about 15ms*/
	int timeout = 30;

	while (1) {

		msleep(30);
		spin_lock_irqsave(&tran_set->trans_lock, flags);
		ready = tran_set->ready;
		spin_unlock_irqrestore(&tran_set->trans_lock, flags);
		if (ready || count > timeout) {
			if (ready == HOST_MCU_TRANS_STATUS_SUCCESS) {
				ret = 0;
			}
			cn_dev_info("trans get storage info ready:%d\n", ready);
			break;
		}
		count++;
	}

	return ret;
}

int init_hbm_bad_block_info(struct cn_host_mcu_tran_set *tran_set)
{
	int ret = 0;

	cn_dev_info("trans init hbm bad block\n");

	start_get_mailbox_data(tran_set);

	ret = wait_for_get_epprom_storage_info(tran_set);
	if (ret) {
		cn_dev_err("trans init hbm block info error\n");
	}

	return ret;
}


int host_mcu_init_mlu290(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_host_mcu_tran_set *host_mcu_tran = NULL;
	int ret;
	u32 max_len = 0;

	host_mcu_tran = cn_kzalloc(sizeof(struct cn_host_mcu_tran_set), GFP_KERNEL);
	if (!host_mcu_tran) {
		cn_dev_err("trans alloc trans_set error.");
		ret = -ENOMEM;
		goto nomem;
	}

	core->trans_set = host_mcu_tran;
	host_mcu_tran->core = core;

	max_len = MAX_BUFFER_LENGTH;

	host_mcu_tran->max_len = max_len;
	host_mcu_tran->buffer = cn_kzalloc(sizeof(u32)*max_len, GFP_KERNEL);

	if (!host_mcu_tran->buffer) {
		cn_dev_err("trans alloc buffer error.");
		ret = -ENOMEM;
		goto trans_set_free;
	}

	spin_lock_init(&host_mcu_tran->trans_lock);

	ret = register_host_mcu_trans_irq(host_mcu_tran);
	if (ret) {
		goto trans_err;
	}

	ret = init_hbm_bad_block_info(host_mcu_tran);
	return ret;

trans_err:
	if (host_mcu_tran) {
		if (host_mcu_tran->buffer) {
			cn_kfree(host_mcu_tran->buffer);
		}
		cn_kfree(host_mcu_tran);
	}

trans_set_free:
	cn_kfree(host_mcu_tran);

nomem:
	core->trans_set = NULL;
	return -ENOMEM;
}
