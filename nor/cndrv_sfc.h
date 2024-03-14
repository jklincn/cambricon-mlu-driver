#ifndef __CAMBRICON_SFC_H__
#define __CAMBRICON_SFC_H__
#ifndef __ASSEMBLY__

#include <linux/types.h>
#include "cndrv_nor_internal.h"
#include "cndrv_nor.h"

#define MLU370_NOR_BASE (0x620D000UL)

#define SPI_CONTROL (0x00)
#define SPI_HOLD_WRITE_PROTECT (0x04)
#define SPI_TRANS_DATA (0x08)
#define SPI_RECEIVE_DATA (0x0c)
#define SPI_TRANS_SIZE (0x10)
#define SPI_PRESCALE (0x14)
#define SPI_START (0x18)
#define SPI_FIFO_STATUS (0x1c)
#define SPI_INT_RAW (0x20)
#define SPI_INT_MASK (0x24)
#define SPI_INT_CLEAR (0x28)
#define SPI_INT_STAT (0x2c)
#define SPI_FIFO_RESET (0x30)
#define SFC_IDLE (0x34)
#define SFC_NOR_NAND_SEL (0x38)
#define SFC_RX_SAMPLE_DLY (0x40)
#define SFC_AXIMSTCTRL (0x60)
#define SFC_BADDRL (0x64)
#define SFC_BADDRM (0x68)
#define SFC_AWUSER (0x70)
#define SFC_AWATTR (0x74)
#define SFC_ARUSER (0x78)
#define SFC_ARATTR (0x7c)
#define SFC_AXIMSTSTATUS (0x80)
#define SFC_AXITRANSCNT (0x84)
#define SFC_ID (0xffc)

#define SPI_TX_PUSH_FULL (0x08)
#define SPI_RX_POP_EMPTY (0x20)
#define SPI_TRANS_END (0x400)
#define SPI_TRANS_ERROR (0x4000)
#define DMA_TRANS_ERROR (0x2000)

#define SPI_DATA_MODE(a) ((a)&0x03)
#define SPI_TRANS_SELECT(a) ((a << 5) & 0x20)
#define SPI_POLARITY(a) ((a << 2) & 0x04)
#define SPI_PHASE(a) ((a << 3) & 0x08)
#define SPI_TRANS_CONTINUE(a) ((a << 4) & 0x10)
#define SPI_FUNCTION_MODE(a) ((a << 6) & 0x40)
#define SPI_PRESCALE_INS(a) ((a)&0xff)

#define FLASH_BUSY 0x01
#define STATUS_WAIT 100
#define RX_DADA_NUM 2
#define SFC_WP_HOLD_VAL 0x03
#define SFC_PRESCALE_VAL 0x04
#define SFC_FIFO_RESET 0x30000
#define SFC_FIFO_DERESET 0x30003
#define SFC_RX_SAMPLE_DLY_V 0xf0001

#define SPI_TRANS_END_DMA 0x800
#define SPI_TRANS_END_DMA_CLEAR 0xc00

#define AXIMST_CTRL_DIS 0xf0000

//flash trans mode
#define SFC_QUAD 0x03
#define SFC_DUAL 0x01
#define SFC_STANDARD 0x00
#define SPI_TRANS_MODE (SFC_STANDARD)
//#define SPI_TRANS_MODE (SFC_QUAD)

//for delay time
#define DMA_MAXTIMES 20000
#define MAXTIMES 600000 //for flash status check
#define SFC_MAXTIMES 20
#define REG_WAIT 5
//mask
#define LOW_16MASK 0xffff
#define ORDER_16 16
#define LOW_8MASK 0xff
#define ORDER_8 8
#define LOW_4MASK 0xf
#define ORDER_4 4
#define LOW_2MASK 0x3
#define ORDER_2 2
#define LOW_1MASK 0x1
#define ORDER_1 1
#define B1_MASK 0xff
#define B2_MASK 0xff00
#define B3_MASK 0xff0000
#define B4_MASK 0xff000000
#define B4_B1 24
#define B3_B2 8

#define BURST_MODE 0x00
#define OUTSTANDING 0x00
#define AXIMST_SEL 0x01
#define AWCACHE 0x02
#define H16_MASK 0xf0000
#define BIT0_MASK 0x01
#define BIT1_MASK 0x02
#define BIT2_3_MASK 0x0c

#define SFC_AXIMSTCTRL_VAL                                                     \
	(H16_MASK | (AXIMST_SEL & BIT0_MASK) |                                 \
			((OUTSTANDING << 1) & BIT1_MASK) |                     \
			((BURST_MODE << 2) & BIT2_3_MASK))
#define H32BIT_MASK 0xffffffff
#define L32BIT_MASK 0xffffffff
#define DEFAULT 0x00
#define L4BIT_MASK 0x0f
#define SPI_EN 0x01
#define CACHE_VAL 0x00 //for sysram;
//#define CACHE_VAL 0x02  //for ddr;

#define SPI_RX_DATA_CONTROL(mode)                                              \
	(SPI_FUNCTION_MODE(1) | SPI_TRANS_SELECT(0) | SPI_TRANS_CONTINUE(0) |  \
			SPI_PHASE(1) | SPI_POLARITY(1) | SPI_DATA_MODE(mode))

#define SPI_TX_DADA_CONTROL(cs, mode)                                          \
	(SPI_FUNCTION_MODE(1) | SPI_TRANS_SELECT(1) | SPI_TRANS_CONTINUE(cs) | \
			SPI_PHASE(1) | SPI_POLARITY(1) | SPI_DATA_MODE(mode))

//MODE
#define MODE4(length) (length & 0x03)
#define BYTE4_ALIGN(length) ((length >> 2) << 2)

#define delay_us udelay
#define delay_ms mdelay
/*
 * a[31:24] - reserved
 * a[23:0]  - SFC error
 * b[7:0]   - NOR error
 */
#define EEROR_NUM(a, b) -(((-a) << 8) + (b))

#define sfc_min(X, Y)                                                          \
	({                                                                     \
		__typeof__(X) __x = (X);                                       \
		__typeof__(Y) __y = (Y);                                       \
		(__x < __y) ? __x : __y;                                       \
	})

//sfc error code
#define ETRANSEND 1 /* sfc trans data to/from flash complete error */
#define ERXFIFO 2 /* sfc receive data from flash fifo error*/
#define ETRANS 3 /* sfc receive info from flash error*/
#define ETXFIFO 4 /* sfc check TX_FIFO error*/
#define ETXFIFO_REG 5 /* sfc check TX_FIFO error*/
#define ESFCRD 9 /* sfc send read buffer addr  to flash error*/
#define ESFCRD_REG 10 /* sfc send read buffer addr  to flash error*/
#define ESFCRD_OF 17 /* sfc send read buffer addr  to flash error*/
#define ETRANSEND_AXI 27
#define ETRANSEND_TRANS 55
#define ETRANSEND_AXI_TRANS 56
#define ETRANSEND_SPI 57
#define ETRANSEND_SPI_TRANS 58

int sfc_ffs(uint32_t x);
uint32_t sfc_rever(uint32_t src);
int32_t check_trans_endflag(struct cn_nor_set *nor_set);
int sfc_check_rxfifo(struct cn_nor_set *nor_set);
int sfc_check_txfifo(struct cn_nor_set *nor_set);
ssize_t sfc_read_data(struct cn_nor_set *nor_set);
ssize_t sfc_write_data(struct cn_nor_set *nor_set);
int sfc_trans_tx(struct cn_nor_set *nor_set);
int sfc_trans_rx(struct cn_nor_set *nor_set);
void sfc_init(struct cn_nor_set *nor_set);

#endif /*__ASSEMBLY__*/
#endif /*__CAMBRICON_SFC_H__*/
