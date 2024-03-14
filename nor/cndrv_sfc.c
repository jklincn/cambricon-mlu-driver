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

#include "cndrv_sfc.h"

void sfc_writel(void *bus_set, unsigned long offset, unsigned int val)
{
	reg_write32(bus_set, offset, val);
	reg_read32(bus_set, offset);
}

uint32_t sfc_readl(void *bus_set, unsigned long offset)
{
	u32 val;

	val = reg_read32(bus_set, offset);
	return val;
}

int sfc_ffs(uint32_t x)
{
	uint32_t r = 1;

	if (!x)
		return 0;
	if (!(x & LOW_16MASK)) {
		x >>= ORDER_16;
		r += ORDER_16;
	}
	if (!(x & LOW_8MASK)) {
		x >>= ORDER_8;
		r += ORDER_8;
	}
	if (!(x & LOW_4MASK)) {
		x >>= ORDER_4;
		r += ORDER_4;
	}
	if (!(x & LOW_2MASK)) {
		x >>= ORDER_2;
		r += ORDER_2;
	}
	if (!(x & LOW_1MASK)) {
		x >>= ORDER_1;
		r += ORDER_1;
	}
	return r;
}

uint32_t sfc_rever(uint32_t src)
{
	uint32_t tmp = 0;

	tmp = ((src >> B4_B1) & B1_MASK) | ((src >> B3_B2) & B2_MASK) |
	      ((src << B3_B2) & B3_MASK) | ((src << B4_B1) & B4_MASK);
	return tmp;
}

int32_t check_trans_endflag(struct cn_nor_set *nor_set)
{
	uint32_t read_res = 0;
	int32_t timeout = SFC_MAXTIMES;
	struct sfc_sig *sfc = &(nor_set->signal.sfc_info);
	struct cn_core_set *core = nor_set->core;

	if (sfc->is_dma)
		timeout = DMA_MAXTIMES;
	while (timeout--) {
		read_res = sfc_readl(core->bus_set, nor_set->base + SPI_INT_RAW);
		if ((read_res & SPI_TRANS_END) &&
				(!(read_res & SPI_TRANS_ERROR))) {
			sfc_writel(core->bus_set, nor_set->base + SPI_INT_CLEAR, SPI_TRANS_END);
			break;
		} else if (read_res & SPI_TRANS_ERROR) {
			cn_dev_core_err(core, "trans endflag err info: %x",
					read_res);
			sfc->error_status = -ETRANSEND_TRANS;
			return -1;
		}
		usleep_range(5, 10);
	}

	if (timeout < 0) {
		cn_dev_core_err(core, "trans endflag info: %x", read_res);
		sfc->error_status = -ETRANSEND;
		return -1;
	}

	if (sfc->is_dma && sfc->is_data) {
		timeout = DMA_MAXTIMES;
		while (timeout--) {
			read_res = sfc_readl(core->bus_set, nor_set->base + SPI_INT_RAW);
			if ((read_res & SPI_TRANS_END_DMA) &&
					(!(read_res & DMA_TRANS_ERROR))) {
				sfc_writel(core->bus_set, nor_set->base + SPI_INT_CLEAR,
						SPI_TRANS_END_DMA_CLEAR); // clear axi symbol
				break;
			} else if (read_res & DMA_TRANS_ERROR) {
				cn_dev_core_err(core, "trans dma endflag err info: %x",
						read_res);
				return -ETRANSEND_AXI_TRANS;
			}
			usleep_range(5, 10);
		}
		if (timeout < 0) {
			sfc->error_status = -ETRANSEND_AXI;
			return -1;
		}
	}
	return 0;
}
int sfc_check_rxfifo(struct cn_nor_set *nor_set)
{
	int timeout = SFC_MAXTIMES;
	struct cn_core_set *core = nor_set->core;

	while (timeout--) {
		if (!(sfc_readl(core->bus_set, nor_set->base + SPI_FIFO_STATUS) &
				    SPI_RX_POP_EMPTY))
			break;
		usleep_range(5, 10);
	}
	if (timeout < 0) {
		cn_dev_core_err(core, "error sfc rxfifo");
		return -1;
	}
	return 0;
}

int sfc_check_txfifo(struct cn_nor_set *nor_set)
{
	int32_t timeout = SFC_MAXTIMES;
	struct cn_core_set *core = nor_set->core;

	while (timeout--) {
		if (!(sfc_readl(core->bus_set, nor_set->base + SPI_FIFO_STATUS) &
				    SPI_TX_PUSH_FULL))
			break;
		usleep_range(5, 10);
	}
	if (timeout < 0) {
		cn_dev_core_err(core, "error sfc txfifo");
		return -1;
	}
	return 0;
}

ssize_t sfc_read_data(struct cn_nor_set *nor_set)
{
	unsigned int *p;
	size_t readlen = 0;
	uint32_t mask = 0xff;
	struct sfc_signal *flash_info = &(nor_set->signal);
	struct sfc_sig *sfc = &(flash_info->sfc_info);
	struct cn_core_set *core = nor_set->core;
	size_t i = 0;

	p = (unsigned int *)flash_info->pdata;
	//read status or ID
	if (!sfc->is_data) {
		if (sfc_check_rxfifo(nor_set)) {
			sfc->error_status = -ESFCRD_REG;
			return -1;
		}
		flash_info->flash_status =
				sfc_readl(core->bus_set, nor_set->base + SPI_RECEIVE_DATA);
		return 0;
	}
	//read data
	for (i = 0; i < BYTE4_ALIGN(flash_info->data_len); i += 4) {
		if (sfc_check_rxfifo(nor_set)) {
			sfc->error_status = -ESFCRD;
			return -1;
		}

		p[readlen] = sfc_readl(core->bus_set, nor_set->base + SPI_RECEIVE_DATA);
		readlen++;
	}
	if (MODE4(flash_info->data_len)) {
		if (sfc_check_rxfifo(nor_set)) {
			sfc->error_status = -ESFCRD_OF;
			return -1;
		}

		for (i = 1; i < (MODE4(flash_info->data_len)); i++) {
			mask = mask << 8;
			mask = mask | 0xff;
		}

		p[readlen] = sfc_readl(core->bus_set, nor_set->base + SPI_RECEIVE_DATA) & mask;
	}

	return 0;
}
ssize_t sfc_write_data(struct cn_nor_set *nor_set)
{
	size_t writelen = 0;
	uint32_t val_tmp = 0;
	size_t i = 0;
	int32_t j = 0;
	struct sfc_signal *flash_info = &(nor_set->signal);
	size_t length = flash_info->data_len;
	unsigned char *p = flash_info->pdata;
	struct sfc_sig *sfc = &(flash_info->sfc_info);
	struct cn_core_set *core = nor_set->core;
	//send cmd && addr
	if (!sfc->is_data) {
		if (sfc_check_txfifo(nor_set)) {
			sfc->error_status = -ETXFIFO_REG;
			return sfc->error_status;
		}
		sfc_writel(core->bus_set, nor_set->base + SPI_TRANS_DATA, sfc->op);
		return 0;
	}
	//send data
	for (i = 0; i < BYTE4_ALIGN(length); i += 4) {
		val_tmp = 0;
		if (sfc_check_txfifo(nor_set)) {
			sfc->error_status = -ETXFIFO;
			return sfc->error_status;
		}
		for (j = 0; j < 4; j++) { // fifo is 4-Byte width
			val_tmp = val_tmp | p[writelen];
			writelen++;
			if (j == 3)
				continue;
			val_tmp = val_tmp << ORDER_8;
		}
		sfc_writel(core->bus_set, nor_set->base + SPI_TRANS_DATA, sfc_rever(val_tmp));
	}
	val_tmp = 0;

	if (MODE4(length)) {
		for (j = 0; j < (MODE4(length)); j++) { // fifo is 4-Byte width
			val_tmp = val_tmp | p[writelen];
			writelen++;
			val_tmp = val_tmp << ORDER_8;
		}
		if (sfc_check_txfifo(nor_set)) {
			sfc->error_status = -ETXFIFO;
			return sfc->error_status;
		}
		sfc_writel(core->bus_set, nor_set->base + SPI_TRANS_DATA,
				sfc_rever(val_tmp) >> ((3 - (MODE4(length))) *
								      ORDER_8));
	}
	return 0;
}

//for tx
int sfc_trans_tx(struct cn_nor_set *nor_set)
{
	struct sfc_signal *flash_info = &(nor_set->signal);
	struct sfc_sig *sfc = &(flash_info->sfc_info);
	struct cn_core_set *core = nor_set->core;

	//config
	sfc_writel(core->bus_set, nor_set->base + SPI_CONTROL,
			SPI_TX_DADA_CONTROL(sfc->cs, sfc->trans_mode));
	if (sfc->is_dma && sfc->is_data) {
		sfc_writel(core->bus_set, nor_set->base + SFC_AXIMSTCTRL, SFC_AXIMSTCTRL_VAL);
		sfc_writel(core->bus_set, nor_set->base + SFC_BADDRL,
				(flash_info->dma_addr) & H32BIT_MASK);
		sfc_writel(core->bus_set, nor_set->base + SFC_BADDRM,
				(flash_info->dma_addr >> 32) & L32BIT_MASK);
		sfc_writel(core->bus_set, nor_set->base + SFC_ARUSER, DEFAULT);
		sfc_writel(core->bus_set, nor_set->base + SFC_ARATTR, CACHE_VAL & L4BIT_MASK);
	} else {
		sfc_writel(core->bus_set, nor_set->base + SFC_AXIMSTCTRL, AXIMST_CTRL_DIS);
	}
	sfc_writel(core->bus_set, nor_set->base + SPI_TRANS_SIZE, sfc->size);
	sfc_writel(core->bus_set, nor_set->base + SPI_START, SPI_EN);

	//SEND_DATA
	if (!(sfc->is_dma) || !(sfc->is_data)) {
		if (sfc_write_data(nor_set))
			return sfc->error_status;
	}
	//trans end flag
	if (check_trans_endflag(nor_set))
		return sfc->error_status;
	return 0;
}

//for rx
int sfc_trans_rx(struct cn_nor_set *nor_set)
{
	struct sfc_signal *flash_info = &(nor_set->signal);
	struct sfc_sig *sfc = &(flash_info->sfc_info);
	struct cn_core_set *core = nor_set->core;

	//sfc config
	sfc_writel(core->bus_set, nor_set->base + SPI_CONTROL,
			SPI_RX_DATA_CONTROL(sfc->trans_mode));
	if (sfc->is_dma && sfc->is_data) { //check is dma trans data
		sfc_writel(core->bus_set, nor_set->base + SFC_AXIMSTCTRL, SFC_AXIMSTCTRL_VAL);
		sfc_writel(core->bus_set, nor_set->base + SFC_BADDRL,
				(flash_info->dma_addr) & H32BIT_MASK);
		sfc_writel(core->bus_set, nor_set->base + SFC_BADDRM,
				(flash_info->dma_addr >> 32) & L32BIT_MASK);
		sfc_writel(core->bus_set, nor_set->base + SFC_AWUSER, DEFAULT);
		sfc_writel(core->bus_set, nor_set->base + SFC_AWATTR, CACHE_VAL & L4BIT_MASK);
	} else {
		sfc_writel(core->bus_set, nor_set->base + SFC_AXIMSTCTRL, AXIMST_CTRL_DIS);
	}
	sfc_writel(core->bus_set, nor_set->base + SPI_TRANS_SIZE, sfc->size);
	sfc_writel(core->bus_set, nor_set->base + SPI_START, SPI_EN);

	//get data
	if (!(sfc->is_dma) || !(sfc->is_data)) {
		if (sfc_read_data(nor_set))
			return sfc->error_status;
	}
	//check trans end
	if (check_trans_endflag(nor_set))
		return sfc->error_status;

	return 0;
}
//for init

void sfc_init(struct cn_nor_set *nor_set)
{
	struct sfc_signal *flash_info = &(nor_set->signal);
	struct sfc_sig *sfc = &(flash_info->sfc_info);
	struct cn_core_set *core = nor_set->core;

	sfc_writel(core->bus_set, nor_set->base + SPI_HOLD_WRITE_PROTECT,
			SFC_WP_HOLD_VAL);

	sfc_writel(core->bus_set, nor_set->base + SPI_PRESCALE,
			SPI_PRESCALE_INS(SFC_PRESCALE_VAL));
	sfc_writel(core->bus_set, nor_set->base + SPI_FIFO_RESET,
			SFC_FIFO_RESET); // clear tx fifo
	sfc_writel(core->bus_set, nor_set->base + SPI_FIFO_RESET, SFC_FIFO_DERESET);
	sfc_writel(core->bus_set, nor_set->base + SFC_RX_SAMPLE_DLY, SFC_RX_SAMPLE_DLY_V);

	sfc->cs = 0;
	sfc->is_dma = 0; //is use dma?
	sfc->is_data = 0; //0:trans cmd&&addr  1:trans data
	sfc->trans_mode = 0; //standard or quad
	sfc->size = 0; //use for transize
	sfc->op = 0; //use for cmd
	sfc->error_status = 0;

	flash_info->pdata = NULL; //use for trans data
	flash_info->flash_status = 0;
	flash_info->addr = 0;
	flash_info->dma_addr = 0;
	flash_info->data_len = 0; //use for transize
	flash_info->standard_quad = nor_set->op; //standard or quad mode
}
