#include <asm/delay.h>
#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "cndrv_bus.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"

#include "cndrv_sfc.h"

#pragma weak plat_sfc_sw_reset

const struct flash norflash[] = {
	{ 0xc8, QUAD_PROGRAM_32, 0 }, { 0xef, QUAD_PROGRAM_32, 0 },
	{ 0x0b, QUAD_PROGRAM_32, 0 }, { 0x20, QUAD_PROGRAM_32, 0 },
	{ 0xc2, QUAD_PROGRAM, 0x03 }, { 0, 0, 0 },
};
void plat_sfc_sw_reset(void)
{
}

static int32_t check_norflash_busy(struct cn_nor_set *nor_set)
{
	int timeout = MAXTIMES;
	struct sfc_signal *nor_info = &(nor_set->signal);
	struct sfc_sig *sfc = &(nor_set->signal.sfc_info);

	while (timeout--) {
		sfc->op = NOR_STATUS;
		sfc->size = 1;
		sfc->cs = 1;
		if (sfc_trans_tx(nor_set))
			return sfc->error_status;

		sfc->size = 1;
		if (sfc_trans_rx(nor_set))
			return sfc->error_status;
		if (!((nor_info->flash_status) & FLASH_BUSY)) {
			break;
		}
		usleep_range(100, 200);
	}

	if (timeout < 0) {
		sfc->error_status = -ETRANS;
		return -1;
	}

	return 0;
}

int32_t nor_reset(struct cn_nor_set *nor_set)
{
	struct sfc_sig *sfc = &(nor_set->signal.sfc_info);

	nor_set->check_unit = -1;

	// send nor reset_e
	sfc->op = NOR_RESET_E;
	sfc->size = 1;
	sfc->cs = 0;

	if (sfc_trans_tx(nor_set))
		return EEROR_NUM(sfc->error_status, EWINS);
	// send nor reset
	sfc->op = NOR_RESET;
	sfc->size = 1;
	sfc->cs = 0;
	if (sfc_trans_tx(nor_set))
		return EEROR_NUM(sfc->error_status, ERESETINS);

	// check flash status;
	if (check_norflash_busy(nor_set))
		return sfc->error_status;

	return 0;
}

int32_t nor_scan_id(struct cn_nor_set *nor_set)
{
	uint32_t reg_val = 0;
	uint32_t val_status_1 = 0;
	struct sfc_sig *sfc = &(nor_set->signal.sfc_info);
	struct sfc_signal *nor_info = &(nor_set->signal);
	struct cn_core_set *core = nor_set->core;

	// send ID ins
	sfc->op = NOR_ID_INS;
	sfc->size = 1;
	sfc->cs = 1;
	if (sfc_trans_tx(nor_set))
		return sfc->error_status;

	// get flash id
	sfc->size = 2;
	if (sfc_trans_rx(nor_set))
		return sfc->error_status;
	nor_info->flash_id = nor_info->flash_status;

	cn_dev_core_info(core, "Norflash id: 0x%x",
			nor_info->flash_id & LOW_16MASK);

	if (nor_info->standard_quad == 0x03) {
		if ((nor_info->flash_id & 0xff) == 0x20) { // MICON

			sfc->op = NOR_WRITE_E;
			sfc->size = 1;
			sfc->cs = 0;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status,
						ECON_MICON_WRITE_E);

			sfc->op = MICRON_W_REG;
			sfc->size = 1;
			sfc->cs = 1;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(
						sfc->error_status, ESET_NONREG);

			sfc->op = MICRON_DATA;
			sfc->size = 1;
			sfc->cs = 0;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status,
						ECON_MICON_DATA);

			if (check_norflash_busy(nor_set))
				return sfc->error_status;
		} else if ((nor_info->flash_id & 0xff) == 0xc2) { // MX

			// read status reg
			sfc->op = MX25_R_REG;
			sfc->size = 1;
			sfc->cs = 1;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status,
						ECON_MX_WRITE_R);

			// get flash status
			sfc->size = 1;
			if (sfc_trans_rx(nor_set))
				return EEROR_NUM(sfc->error_status, ER_REG);
			reg_val = (nor_info->flash_status & LOW_8MASK);

			// write status reg
			sfc->op = NOR_WRITE_E;
			sfc->size = 1;
			sfc->cs = 0;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status, EID_WEL);

			sfc->op = MX25_W_REG;
			sfc->size = 1;
			sfc->cs = 1;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(
						sfc->error_status, ESET_NONREG);

			sfc->op = (reg_val | MX25_DATA_MASK);
			sfc->size = 1;
			sfc->cs = 0;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status,
						ECON_MX_DATA);

			// check flash status
			if (check_norflash_busy(nor_set))
				return sfc->error_status;
		} else if (((nor_info->flash_id & 0xff) == 0x0b) ||
				((nor_info->flash_id & 0xff) == 0xc8)) {
			// read status reg  bit15-bit8
			sfc->op = XTX_REG_W;
			sfc->size = 1;
			sfc->cs = 1;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status,
						ECON_XTX_READ_REG_END);

			sfc->size = 1;
			if (sfc_trans_rx(nor_set))
				return EEROR_NUM(sfc->error_status, ER_REG);

			reg_val = nor_info->flash_status & LOW_8MASK;
			reg_val = reg_val << 8;

			// read status reg bit7-bit0

			sfc->op = XTX_REG_R;
			sfc->size = 1;
			sfc->cs = 1;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status, ER_REG);

			sfc->size = 1;
			if (sfc_trans_rx(nor_set))
				return EEROR_NUM(sfc->error_status,
						ERX_DATA_REG);

			val_status_1 = nor_info->flash_status & LOW_8MASK;
			reg_val = reg_val | val_status_1;

			// write status reg
			sfc->op = NOR_WRITE_E;
			sfc->size = 1;
			sfc->cs = 0;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status, EID_WEL);

			sfc->op = MX25_W_REG;
			sfc->size = 1;
			sfc->cs = 1;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status,
						EXTX_WRITE_E);

			// get flash info
			sfc->op = reg_val | XTX_DATA_MASK;
			sfc->size = 2;
			sfc->cs = 0;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status,
						EXTX_WRITE_REG);

			// check status
			if (check_norflash_busy(nor_set))
				return sfc->error_status;
		} else if ((nor_info->flash_id & 0xff) == 0xef) {
			// write enable
			sfc->op = NOR_WRITE_E;
			sfc->size = 1;
			sfc->cs = 0;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(
						sfc->error_status, SET_WEL_ERR);

			// send status register status-2 read cmd
			sfc->op = R_FLASH_STAT2_CMD;
			sfc->size = 1;
			sfc->cs = 1;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status,
						SET_QUAD_ERR_R);

			sfc->size = 1;
			if (sfc_trans_rx(nor_set))
				return EEROR_NUM(sfc->error_status,
						SET_QUAD_ERR_END_R);

			reg_val = nor_info->flash_status & LOW_8MASK;

			// send status register status-2 write cmd
			sfc->op = W_FLASH_STAT2_CMD;
			sfc->size = 1;
			sfc->cs = 1;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status,
						SET_QUAD_ERR);

			// enable QE bit
			sfc->op = reg_val | FLASH_QUAD_EN;
			sfc->size = 1;
			sfc->cs = 0;
			if (sfc_trans_tx(nor_set))
				return EEROR_NUM(sfc->error_status,
						SET_QUAD_ERR_D);

			// check status
			if (check_norflash_busy(nor_set))
				return sfc->error_status;
		} else {
			cn_dev_core_err(core, "this norflash is not supported !");
			return -EFLASH;
		}
	}
	return 0;
}

int nor_init(struct cn_nor_set *nor_set, uint32_t mode)
{
	int32_t flag = 0;
	struct cn_core_set *core = nor_set->core;

	nor_set->op = mode; // other api will use this flag
	if ((nor_set->op != SFC_STANDARD) && (nor_set->op != SFC_QUAD)) {
		cn_dev_core_err(core, "err trans mode");
		return -1;
	}
	sfc_init(nor_set);

	flag = nor_reset(nor_set);
	if (flag)
		return flag;

	flag = nor_scan_id(nor_set);
	if (flag)
		return EEROR_NUM(flag, EID);

	return 0;
}

ssize_t nor_do_read_ops(struct cn_nor_set *nor_set)
{
	uint32_t sfc_addr_in = 0;
	uint32_t dummy = 0;
	struct sfc_sig *sfc = &(nor_set->signal.sfc_info);
	struct sfc_signal *nor_info = &(nor_set->signal);
	struct cn_core_set *core = nor_set->core;

	// send read cmd
	sfc->size = 1;
	sfc->cs = 1;
	if (nor_info->standard_quad == 0x00) {
		cn_dev_core_info(core, "standard mode");
		sfc->op = NOR_READ;
	} else if (nor_info->standard_quad == 0x03) {
		cn_dev_core_info(core, "quad mode");
		sfc->op = QUAD_CMD_R;
	} else {
		cn_dev_core_err(core, "mode error");
		return -MODE_ERR;
	}
	if (sfc_trans_tx(nor_set))
		return EEROR_NUM(sfc->error_status, ERDINSEND);
	// send flash addr
	sfc_addr_in = sfc_rever(nor_info->addr);
	sfc_addr_in = sfc_addr_in >> ORDER_8;

	if (nor_info->standard_quad == 0x00) {
		sfc->op = sfc_addr_in;
		sfc->size = 3;
		sfc->cs = 1;
		if (sfc_trans_tx(nor_set))
			return EEROR_NUM(sfc->error_status, ERD_ADDR);
	} else if (nor_info->standard_quad == 0x03) {
		sfc->op = sfc_addr_in;
		sfc->size = 4;
		sfc->cs = 1;
		sfc->trans_mode = nor_info->standard_quad;
		if (sfc_trans_tx(nor_set))
			return EEROR_NUM(sfc->error_status, ERD_ADDR);

		sfc->op = dummy;
		sfc->size = 2;
		sfc->cs = 1;
		sfc->trans_mode = nor_info->standard_quad;
		if (sfc_trans_tx(nor_set))
			return EEROR_NUM(sfc->error_status, ERD_ADDR);
	} else {
		cn_dev_core_err(core, "error flash trans mode");
		return -MODE_ERR;
	}
	// get data info
	sfc->trans_mode = nor_info->standard_quad;
	sfc->size = nor_info->data_len;
	sfc->is_data = 1;
	if (sfc_trans_rx(nor_set)) {
		return EEROR_NUM(sfc->error_status, EDATANOR);
	}

	return 0;
}

ssize_t nor_read(struct cn_core_set *core_set, uint32_t *buffer, uint32_t addr,
		size_t length)
{
	int flag = 0;
	struct cn_nor_set *nor_set = (struct cn_nor_set *)core_set->nor_set;
	struct sfc_signal *nor_info = &(nor_set->signal);

	if (length == 0)
		return 0;
	// init flag;
	sfc_init(nor_set);

	nor_info->pdata = (unsigned char *)buffer;
	nor_info->addr = addr;
	nor_info->data_len = length;
	flag = nor_do_read_ops(nor_set);
	if (flag)
		return flag;

	return length;
}

int nor_erase(struct cn_nor_set *nor_set, uint32_t addr)
{
	struct sfc_sig *sfc = &(nor_set->signal.sfc_info);

	sfc->size = 1;
	sfc->cs = 0;
	sfc->op = NOR_WRITE_E;
	if (sfc_trans_tx(nor_set))
		return EEROR_NUM(sfc->error_status, ECMDE);

	sfc->size = 1;
	sfc->cs = 1;
	sfc->op = NOR_ERASE_4K;
	if (sfc_trans_tx(nor_set))
		return EEROR_NUM(sfc->error_status, ECMDNOR);

	sfc->size = 3;
	sfc->cs = 0;
	sfc->op = sfc_rever(addr) >> ORDER_8;
	if (sfc_trans_tx(nor_set))
		return EEROR_NUM(sfc->error_status, EADDRNOR);

	if (check_norflash_busy(nor_set))
		return EEROR_NUM(sfc->error_status, ESTATUS);

	return 0;
}
static int get_flash_info(struct cn_nor_set *nor_set, struct flash *info)
{
	int i = 0;

	while (norflash[i].flashid) {
		if ((nor_set->signal.flash_id & 0xff) == norflash[i].flashid) {
			*info = norflash[i];
			break;
		}
		i++;
	}
	if (!norflash[i].flashid)
		return -1;
	return 0;
}
static int block_erase(struct cn_nor_set *nor_set)
{
	int32_t index = 0;
	uint32_t erase_size = ERASE_SIZE;
	uint32_t erase_addr = nor_set->signal.addr;
	uint32_t length = nor_set->signal.data_len;
	int32_t start_unit = 0;
	int32_t end_unit = 0;
	int32_t flag = 0;

	start_unit = erase_addr >> (sfc_ffs(erase_size) - 1);
	end_unit = (erase_addr + length - 1) >> (sfc_ffs(erase_size) - 1);
	index = start_unit;

	// erase only enter a new sector
	if ((start_unit != nor_set->check_unit) || (start_unit != end_unit)) {
		if (start_unit == nor_set->check_unit) {
			index = start_unit + 1;
		}

		for (; index <= end_unit; index++) {
			flag = nor_erase(nor_set,
					index << (sfc_ffs(erase_size) - 1));
			if (flag) {
				return flag;
			}
		}

		nor_set->check_unit = start_unit;
	}
	return 0;
}

ssize_t nor_do_write_ops(struct cn_nor_set *nor_set)
{
	struct sfc_sig *sfc = &(nor_set->signal.sfc_info);
	struct sfc_signal *nor_info = &(nor_set->signal);
	struct flash info;
	int flag = 0;
	// erase
	flag = block_erase(nor_set);
	if (flag)
		return flag;
	// enable flash write
	sfc->op = NOR_WRITE_E;
	sfc->size = 1;
	sfc->cs = 0;
	if (sfc_trans_tx(nor_set))
		return EEROR_NUM(sfc->error_status, EWRITENOR);

	// send write cmd
	sfc->size = 1;
	sfc->cs = 1;
	sfc->op = NOR_WRITE;

	if (nor_info->standard_quad == 0x03) {
		flag = get_flash_info(nor_set, &info);
		if (flag)
			return EEROR_NUM(flag, EFLASHCMD);
		sfc->op = info.op;
	}

	if (sfc_trans_tx(nor_set))
		return EEROR_NUM(sfc->error_status, EWRITECMD);

	// send addr cmd
	sfc->op = sfc_rever(nor_info->addr) >> ORDER_8;
	sfc->size = 3;
	sfc->cs = 1;

	if (nor_info->standard_quad == 0x03) {
		flag = get_flash_info(nor_set, &info);
		if (flag)
			return EEROR_NUM(flag, EFLASHADDR);
		sfc->trans_mode = info.cfg_mode;
	}
	if (sfc_trans_tx(nor_set))
		return EEROR_NUM(sfc->error_status, EADDRCMD);

	// send data and cfg trans mode
	sfc->cs = 0;
	sfc->trans_mode = nor_info->standard_quad;
	sfc->size = nor_info->data_len;
	sfc->is_data = 1;
	if (sfc_trans_tx(nor_set))
		return EEROR_NUM(sfc->error_status, EDATACMD);

	// init sfc flag;
	sfc_init(nor_set);
	// check status
	if (check_norflash_busy(nor_set))
		return EEROR_NUM(sfc->error_status, ESTATUS);

	return 0;
}

ssize_t nor_write(struct cn_core_set *core_set, uint32_t *src_buffer,
		uint32_t dst_addr, size_t length)
{
	struct cn_nor_set *nor_set = (struct cn_nor_set *)core_set->nor_set;
	int32_t flag = 0;
	int32_t col = 0;
	uint32_t left = length;
	uint32_t bytes = 0;
	ssize_t writelen = 0;
	struct sfc_signal *nor_info = &(nor_set->signal);
	unsigned char *data = (unsigned char *)src_buffer;

	/*
	 * in case nor_write called twice for same address
	 */
	nor_set->check_unit = -1;

	if (length == 0)
		return 0;
	// init sfc flag;
	sfc_init(nor_set);
	col = (dst_addr & (PROGRAM_SIZE - 1));

	do {
		bytes = sfc_min(PROGRAM_SIZE - col, left);
		nor_info->data_len = bytes;
		nor_info->pdata = data;
		nor_info->addr = dst_addr;
		// write by page for nor, after write the nor_info will be inited
		flag = nor_do_write_ops(nor_set);
		if (flag < 0) {
			cn_dev_core_err(core_set, "already write:%lx error code:%x",
					writelen, flag);
			return flag;
		}
		col = 0;
		left -= bytes;
		data += bytes;
		dst_addr += bytes;
		writelen += bytes;
	} while (left > 0);

	return writelen;
}

int cn_nor_init(struct cn_core_set *core)
{
	struct cn_nor_set *nor_set = NULL;
	int ret = 0;

	core->nor_set = NULL;

	switch (core->device_id) {
	case MLUID_370:
	case MLUID_365:
		break;
	default:
		cn_dev_core_info(core, "nor not support device_id = 0x%08x",
				(uint32_t)core->device_id);
		return 0;
	}

	cn_dev_core_info(core, "nor init");

	nor_set = cn_kzalloc(sizeof(struct cn_nor_set), GFP_KERNEL);
	if (!nor_set) {
		cn_dev_core_err(core, "alloc nor_set failed");
		return -ENOMEM;
	}

	core->nor_set = nor_set;
	nor_set->core = core;

	switch (core->device_id) {
	case MLUID_370:
	case MLUID_365:
		nor_set->base = MLU370_NOR_BASE;
		ret = nor_init(nor_set, SFC_QUAD);
		if (ret) {
			cn_dev_core_err(core, "nor init failed");
			core->nor_set = NULL;
			cn_kfree(nor_set);
			return ret;
		}
		break;
	default:
		cn_dev_core_err(core, "nor not support device_id = 0x%08x",
				(uint32_t)core->device_id);
		core->nor_set = NULL;
		cn_kfree(nor_set);
		return 0;
	}

	return 0;
}

void cn_nor_exit(struct cn_core_set *core)
{
	struct cn_nor_set *nor_set = (struct cn_nor_set *)core->nor_set;

	cn_dev_core_info(core, "nor free");

	if (nor_set) {
		cn_kfree(nor_set);
		core->nor_set = NULL;
	}
}
