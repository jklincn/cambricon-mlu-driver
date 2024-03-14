#ifndef __CAMBRICON_I2C_H__
#define __CAMBRICON_I2C_H__

/* i2c register base in mlu270 */
#define I2C_REG_BASE 0x1000

/* dw_apb_i2c register*/
#define IC_CON		0x0
#define IC_TAR		0x4
#define IC_SAR		0x8
#define IC_DATA_CMD		0x10
#define IC_SS_SCL_HCNT	0x14
#define IC_SS_SCL_LCNT	0x18
#define IC_FS_SCL_HCNT	0x1c
#define IC_FS_SCL_LCNT	0x20
#define IC_HS_SCL_HCNT	0x24
#define IC_HS_SCL_LCNT	0x28
#define IC_INTR_STAT		0x2c
#define IC_INTR_MASK		0x30
#define IC_RAW_INTR_STAT	0x34
#define IC_RX_TL		0x38
#define IC_TX_TL		0x3c
#define IC_CLR_INTR		0x40
#define IC_CLR_RX_UNDER	0x44
#define IC_CLR_RX_OVER	0x48
#define IC_CLR_TX_OVER	0x4c
#define IC_CLR_RD_REQ	0x50
#define IC_CLR_TX_ABRT	0x54
#define IC_CLR_RX_DONE	0x58
#define IC_CLR_ACTIVITY	0x5c
#define IC_CLR_STOP_DET	0x60
#define IC_CLR_START_DET	0x64
#define IC_CLR_GEN_CALL	0x68
#define IC_ENABLE		0x6c
#define IC_STATUS		0x70
#define IC_TXFLR		0x74
#define IC_RXFLR		0x78
#define IC_SDA_HOLD		0x7c
#define IC_TX_ABRT_SOURCE	0x80
#define IC_ENABLE_STATUS	0x9c
#define IC_CLR_RESTART_DET	0xa8
#define IC_COMP_PARAM_1	0xf4
#define IC_COMP_VERSION	0xf8
#define IC_SDA_HOLD_MIN_VERS	0x3131312A
#define IC_COMP_TYPE		0xfc
#define IC_COMP_TYPE_VALUE	0x44570140

/* bit spec in IC_RAW_INTR_STAT */
#define IC_INTR_RX_FULL		2
#define IC_INTR_TX_EMPTY	4

/* bit spec in IC_STATUS*/
#define IC_MST_ACTIVITY		5

#define IC_CON_MASTER		0x1
#define IC_CON_SPEED_STD		0x2
#define IC_CON_SPEED_FAST		0x4
#define IC_CON_SPEED_HIGH		0x6
#define IC_CON_SPEED_MASK		0x6
#define IC_CON_10BITADDR_SLAVE		0x8
#define IC_CON_10BITADDR_MASTER	0x10
#define IC_CON_RESTART_EN		0x20
#define IC_CON_SLAVE_DISABLE		0x40
#define IC_CON_STOP_DET_IFADDRESSED		0x80
#define IC_CON_TX_EMPTY_CTRL		0x100
#define IC_CON_RX_FIFO_FULL_HLD_CTRL		0x200

#define MAX_POLL_COUNT 100

#define DW_ENABLE	1
#define DW_DISABLE	0

#endif
