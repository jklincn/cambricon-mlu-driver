#ifndef __CAMBRICON_TRANS_H__
#define __CAMBRICON_TRANS_H__


#define TRANS_MCU_TEST_VER_MAJOR                 (0x0A)
#define TRANS_MCU_VER_MAJOR                      (1)
#define TRANS_MCU_VER_MINOR                      (0)
#define TRANS_MCU_VER_BUILD                      (0)

#define MAILBOX_INT0_NAME                        "MAILBOX_INT0"

#define MAIL_BOX_BASE_ADDR                       (0x7000)

#define HOST_MCU_BASE_ADDR                       MAIL_BOX_BASE_ADDR
#define MAILBOX_INT_STATUS0_INFO                 (HOST_MCU_BASE_ADDR + 0x00)
#define MAILBOX_INT_STATUS1_INFO                 (HOST_MCU_BASE_ADDR + 0x04)

#define MAILBOX_CH0_INFO                         (HOST_MCU_BASE_ADDR + 0x08)
#define MAILBOX_CH1_INFO                         (HOST_MCU_BASE_ADDR + 0x0C)
#define MAILBOX_CH2_INFO                         (HOST_MCU_BASE_ADDR + 0x10)
#define MAILBOX_CH3_INFO                         (HOST_MCU_BASE_ADDR + 0x14)
#define MAILBOX_CH4_INFO                         (HOST_MCU_BASE_ADDR + 0x18)
#define MAILBOX_CH5_INFO                         (HOST_MCU_BASE_ADDR + 0x1C)
#define MAILBOX_CH6_INFO                         (HOST_MCU_BASE_ADDR + 0x20)
#define MAILBOX_CH7_INFO                         (HOST_MCU_BASE_ADDR + 0x24)
#define MAILBOX_CH8_INFO                         (HOST_MCU_BASE_ADDR + 0x28)
#define MAILBOX_CH9_INFO                         (HOST_MCU_BASE_ADDR + 0x2C)
#define MAILBOX_CH10_INFO                        (HOST_MCU_BASE_ADDR + 0x30)
#define MAILBOX_CH11_INFO                        (HOST_MCU_BASE_ADDR + 0x34)
#define MAILBOX_CH12_INFO                        (HOST_MCU_BASE_ADDR + 0x38)
#define MAILBOX_CH13_INFO                        (HOST_MCU_BASE_ADDR + 0x3C)


#define MAILBOX_INI_STATUS_BIT0_SHIFT            (0)
#define MAILBOX_INI_STATUS_BIT1_SHIFT            (1)
#define MAILBOX_INI_STATUS_BIT2_SHIFT            (2)
#define MAILBOX_INI_STATUS_BIT3_SHIFT            (3)

#define MAILBOX_INI_STATUS_BIT16_SHIFT           (16)
#define MAILBOX_INI_STATUS_BIT17_SHIFT           (17)
#define MAILBOX_INI_STATUS_BIT18_SHIFT           (18)
#define MAILBOX_INI_STATUS_BIT19_SHIFT           (19)

#define MAILBOX_INT_STATUS0_BIT0                 ((0x1) << MAILBOX_INI_STATUS_BIT0_SHIFT)
#define MAILBOX_INT_STATUS0_BIT1                 ((0x1) << MAILBOX_INI_STATUS_BIT1_SHIFT)
#define MAILBOX_INT_STATUS0_BIT2                 ((0x1) << MAILBOX_INI_STATUS_BIT2_SHIFT)
#define MAILBOX_INT_STATUS0_BIT3                 ((0x1) << MAILBOX_INI_STATUS_BIT3_SHIFT)

#define MAILBOX_INT_STATUS0_BIT16                ((0x1) << MAILBOX_INI_STATUS_BIT16_SHIFT)
#define MAILBOX_INT_STATUS0_BIT17                ((0x1) << MAILBOX_INI_STATUS_BIT17_SHIFT)
#define MAILBOX_INT_STATUS0_BIT18                ((0x1) << MAILBOX_INI_STATUS_BIT18_SHIFT)
#define MAILBOX_INT_STATUS0_BIT19                ((0x1) << MAILBOX_INI_STATUS_BIT19_SHIFT)


#define MAILBOX_TRANS_DATA_REG_COUNT             (12)
#define TRANS_DATA_END_FLAG                      (0x60000000)

#define MAX_BUFFER_LENGTH                        (512)

struct mailbox_reg_data {
	u32 reg_buf[MAILBOX_TRANS_DATA_REG_COUNT];
	u8  max_count;
	u8  real_count;
};
struct cn_host_mcu_tran_set {
	struct cn_core_set *core;

	spinlock_t trans_lock;
	void *buffer;/*current bad block cache*/
	void *w_buffer;/*ready to write bad block cache*/
	u32 w_len;/*ready to write bad block info length*/
	u32 w_index;/*which bad block is being written*/
	u8  w_retry;/*write data,odd check failed count*/
	u8  w_delay;/*write data success,MCU not read times */

#define HOST_MCU_TRANS_STATUS_SUCCESS 0x01
#define HOST_MCU_TRANS_STATUS_FAILED  0x02
#define HOST_MCU_TRANS_STATUS_TIMEOUT 0x03
	u8  w_status;/*current data write status*/
	u32 max_len;/*max bad block cache length*/

#define HOST_MCU_TRANS_RETRY_COUNT 0x03
	u8  retry;/*read bad block,odd check failed count*/
	u32 cur_index;/*which bad block is being readed*/
	u8 ready;/*current data read status*/

};


int host_mcu_init_mlu290(void *pcore);
u8 check_odd_parity(u32 value);

void host_mcu_write32_reg(void *tran_set, unsigned long offset, unsigned int value);
unsigned int host_mcu_read32_reg(void *tran_set, unsigned long offset);
void unregister_host_mcu_trans_irq(struct cn_host_mcu_tran_set *tran_set);


#endif
