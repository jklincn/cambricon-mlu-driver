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
#include <linux/interrupt.h>
#include "cndrv_xid.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_mcc.h"
#include "mcc_main.h"

#define MLU270_DDR_COUNT	4

#define DDR_MC(n)	(0x200000 + (n) * 0x10000)

#define DDR_IRQ_BASE	101
#define DDR_IRQ_OFF(n)	(DDR_IRQ_BASE + (n) * 4)

#define DDR_INTERRUPT_COUNT 43


char *ddr_interrupt_info[DDR_INTERRUPT_COUNT] = {
	[0] = "The memory reset is valid on the DFI bus.",
	[1] = "A memory access outside the defined PHYSICAL memory space has occurred.",
	[2] = "Multiple accesses outside the defined PHYSICAL memory space have	occurred",
	[3] = "A correctable ECC event has been detected.",
	[4] = "Multiple correctable ECC events have been detected.",
	[5] = "An uncorrectable ECC event has been detected ",
	[6] = "Multiple uncorrectable ECC events have been detected.",
	[7] = "One or more ECC writeback commands could not be executed.",
	[8] = "The scrub operation triggered by setting param_ecc_scrub_start has completed",
	[9] = "An ECC correctable error has been detected in a scrubbing read operation.",
	[10] = "An error occurred on the port command channel.",
	[11] = "The MC initialization has been completed.",
	[12] = "The low power operation has been completed",
	[13] = "The BIST operation has been completed.",
	[14] = "A wrap cycle crossing a DRAM page has been detected. This is \
			unsupported & may result in memory data corruption.",
	[15] = "The user has programmed an invalid setting associated with user words \
			per burst. Examples: Setting param_reduc when burst length = 2. A 1:2\
				MC:PHY lock ratio with burst length = 2.",
	[16] = "A read leveling error has occurred. Error information can be found in \
			the RDLVL_ERROR_STATUS parameter.",
	[17] = "A read leveling gate training error has occurred. Error information \
			can be found in the RDLVL_ERROR_STATUS parameter.",
	[18] = "A write leveling error has occurred. Error information can be found in \
			the WRLVL_ERROR_STATUS parameter.",
	[19] = "A RDIMM_CWW request error has occurred. Error information can be found \
			in the RDIMM_CWW_ERROR_STATUS parameter.",
	[20] = "A DFI update error has occurred.Error information can be found in the \
			UPDATE_ERROR_STATUS parameter.",
	[21] = "A DFI PHY Master Interface error has occurred. Error information can \
			be found in the PHYMSTR_ERROR_STATUS parameter.",
	[22] = "A write leveling operation has been requested.",
	[23] = "A read leveling operation has been requested.",
	[24] = "A read leveling gate training operation has been requested.",
	[25] = "The leveling operation has completed.",
	[26] = "A parity error has been detected on the address/control bus on a \
			registered DIMM.",
	[27] = "Error received from the PHY on the DFI bus.",
	[28] = "MPR read command, initiated with a software MPR_READ request, is complete.",
	[29] = "A Low Power Interface (LPI) timeout error has occurred.	",
	[30] = "The register interface-initiated mode register write has completed and \
			another mode register write may be issued.",
	[31] = "The assertion of the INHIBIT_DRAM_CMD parameter has successfully \
			inhibited the command queue.",
	[32] = "A state change has been detected on the dfi_init_complete signal after \
			initialization.",
	[33] = "The user-initiated DLL resync has completed.",
	[34] = "The DFI tINIT_COMPLETE value has timed out. This value is specified in \
			the TDFI_INIT_COMPLETE parameter.",
	[35] = "The DFS hardware has completed all operations.",
	[36] = "The DFS operation has resulted in a status bit being set.",
	[37] = "The refresh operation has resulted in a status bit being set.",
	[38] = "The ZQ calibration operation has resulted in a status bit being set.",
	[39] = "The software-initiated control word write has completed.",
	[40] = "A CRC error occurred on the write data bus.",
	[41] = "A CA Parity or a CRC error happened during CRC Retry.",
	[42] = "Logical OR of all lower bits."

};


void ddr_mlu270_write32(void *pcore, u8 ddr_index, u32 reg_index, u32 value)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	unsigned long offset = DDR_MC(ddr_index) + (reg_index << 2);

	reg_write32(core->bus_set, offset, value);
}

u32 ddr_mlu270_read32(void *pcore, u8 ddr_index, u32 reg_index)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	unsigned long offset = DDR_MC(ddr_index) + (reg_index << 2);

	return reg_read32(core->bus_set, offset);
}

static void ddr_print_out_range_info_mlu270(struct cn_core_set *core,
	int ddr_index, struct cn_mcc_set *mcc_set)
{
	u64 out_addr;
	u32 out_length, out_type;

	out_addr = ddr_mlu270_read32(mcc_set->core, ddr_index, 261);
	out_addr |= ((u64)ddr_mlu270_read32(mcc_set->core, ddr_index,
							262) & 0xff) << 32;
	out_length = ddr_mlu270_read32(mcc_set->core, ddr_index, 262) >> 8;
	out_type = ddr_mlu270_read32(mcc_set->core, ddr_index, 263) & 0x3f;

	cn_xid_err(core, XID_ILLEGAL_ACCESS_ERR,
		"ddr%d out of range addr:%#llx length:%#x, type:%#x",
		ddr_index, out_addr, out_length, out_type);
}

static void ddr_int_check_mlu270(int ddr_index,
				u64 status,
				struct cn_mcc_set *mcc_set)
{
	int i;
	struct ecc_info_t *ecc_info;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	cn_dev_core_info(core, "irq status: %#llX", status);

	if (IS_ERR_OR_NULL(mcc_set->ecc_status)) {
		cn_dev_core_err(core, "ecc status is null");
		return ;
	}
	ecc_info = ((struct ecc_info_t *)mcc_set->ecc_status) + ddr_index;

	for (i = 0; i < DDR_INTERRUPT_COUNT; i++) {
		if (status & 0x01) {
			if (i >= 3 && i <= 6) {
				cn_xid_err(core, XID_ECC_ERR, "ECC Error, ddr%d %d:%s",
					ddr_index, i, ddr_interrupt_info[i]);
			} else {
				cn_dev_core_info(core, "ddr%d %d:%s",
					ddr_index, i, ddr_interrupt_info[i]);
			}
			switch (i) {
			case 1:
			case 2:
				ddr_print_out_range_info_mlu270(core, ddr_index, mcc_set);
				break;
			case 3:
				ecc_info->one_bit_ecc_error++;
				break;
			case 4:
				ecc_info->multiple_one_bit_ecc_error++;
				break;
			case 5:
				ecc_info->multiple_bit_ecc_error++;
				break;
			case 6:
				ecc_info->multiple_multiple_bit_ecc_error++;
				break;
			}
		}
		status >>= 1;
		if (!status) {
			break;
		}
	}
}

static irqreturn_t ddr_mlu270_intr_handle(int index, void *data)
{
	unsigned int int_index;
	u64 status = 0;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)data;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	int_index = (index - DDR_IRQ_BASE) >> 2;
	cn_dev_core_info(core, "DDR%d irq", int_index);

	status = ddr_mlu270_read32(core, int_index, 256);
	status <<= 32;
	status |= ddr_mlu270_read32(core, int_index, 255);

	ddr_int_check_mlu270(int_index, status, mcc_set);

	ddr_mlu270_write32(core, int_index, 258, status>>32);
	status &= 0xffffffff;
	ddr_mlu270_write32(core, int_index, 257, status);

	status = ddr_mlu270_read32(core, int_index, 256);
	status <<= 32;
	status |= ddr_mlu270_read32(core, int_index, 255);


	return IRQ_HANDLED;
}

int ddr_get_channel_num_mlu270(void *mset)
{

	return 4;
}

void *ddr_get_ecc_status_mlu270(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;

	return mcc_set->ecc_status;
}

void ddr_exit_mlu270(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	int i;

	for (i = 0; i < MLU270_DDR_COUNT; i++) {
		cn_bus_disable_irq(core->bus_set, DDR_IRQ_OFF(i));
		cn_bus_unregister_interrupt(core->bus_set, DDR_IRQ_OFF(i));
	}

	if (mcc_set->ecc_status) {
		cn_kfree(mcc_set->ecc_status);
	}
}


static const struct cn_mcc_ops ddr_ops_mlu270 = {
	.get_channel_num = ddr_get_channel_num_mlu270,
	.get_ecc_status = ddr_get_ecc_status_mlu270,

	.mcc_exit = ddr_exit_mlu270,
	.get_d2dc_num = NULL,
	.get_d2dc_status = NULL,
};

int ddr_init_mlu270(struct cn_mcc_set *mcc_set)
{
	int i, ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "memory ctrl set is null");
		return -EINVAL;
	}
	mcc_set->mcc_ops = &ddr_ops_mlu270;

	mcc_set->d2dc_status = NULL;
	mcc_set->ecc_status = cn_kzalloc(MLU270_DDR_COUNT * sizeof(struct ecc_info_t), GFP_KERNEL);
	if (!mcc_set->ecc_status) {
		cn_dev_core_err(core, "malloc for ecc struct fail");
		return -ENOMEM;
	}

	cn_dev_core_info(core, "ddr: %X",
		ddr_mlu270_read32(mcc_set->core, 0, 200));
	// register irq
	for (i = 0; i < MLU270_DDR_COUNT; i++) {
		ret = cn_bus_register_interrupt(core->bus_set,
				DDR_IRQ_OFF(i),
				ddr_mlu270_intr_handle,
				(void *)mcc_set);
		ret |= cn_bus_enable_irq(core->bus_set, DDR_IRQ_OFF(i));
		if (ret)
			break;
	}

	return ret;
}
