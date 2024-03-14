#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/pci.h>
#include <linux/delay.h>

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_xid.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_trans.h"
#include "cndrv_mcc.h"
#include "cndrv_mm.h"
#include "mcc_main.h"
#include "cndrv_mcu.h"
#include "mlu580_ddr_data.h"
#include "module_param.h"
#include "cndrv_kwork.h"

/* name length */
#define MAX_STRING_LEN                    (32)
#define SMMU_BUSY_WAIT_TIMEOUT_MS (100)

/* --------- MAILBOX CONFIG -------- */
#define MLU580_PERI_MCU_MAILBOX_PCIE_IRQ (339)
#define MLU580_PERI_MAILBOX1_BASE (0x2c7000)
#define MLU580_MAILBOX_INT_STATUS0 (0x00)
#define MLU580_MAILBOX_INT_STATUS1 (0x04)
#define MLU580_MAILBOX_CH0_INFO    (0x08)
#define MLU580_GDDR_ECC_OFFSET                    (0x1)
/* Support CH0 ~ CH31 */
#define MLU580_MAILBOX_CH_INFO(ch) (MLU580_MAILBOX_CH0_INFO + (ch) * 0x4)

static int reg_read32_and_wait(void *bus_set, int reg, u32 condition)
{
	unsigned int timeout = 0;

retry:
	if (reg_read32(bus_set, reg) == condition)
		return 0;

	if (++timeout == SMMU_BUSY_WAIT_TIMEOUT_MS)
		return -ETIMEDOUT;
	else {
		usleep_range(2000, 3000);//2ms
		goto retry;
	}
}

/*
 *NOTE: use hbm mask(memg mask) to get llcg mask.
 */
static unsigned int __mlu580_hbm_mask_to_llc_mask(unsigned int hbm_mask)
{
	unsigned int hbm_id = 0, bitmap;
	unsigned int llc_mask = 0;

	bitmap = hbm_mask;

	while (bitmap) {
		hbm_id = __ffs(bitmap);
		switch (hbm_id) {
		case 0:
			llc_mask |= (0x1 << 0) | (0x1 << 1);
			break;
		case 1:
			llc_mask |= (0x1 << 2) | (0x1 << 3);
			break;
		case 2:
			llc_mask |= (0x1 << 4) | (0x1 << 5);
			break;
		case 3:
			llc_mask |= (0x1 << 6) | (0x1 << 7);
			break;
		case 4:
			llc_mask |= (0x1 << 8) | (0x1 << 9);
			break;
		case 5:
			llc_mask |= (0x1 << 10) | (0x1 << 11);
			break;
		}
		bitmap &= ~(1 << hbm_id);
	}
	return llc_mask;
}


struct hbm_resetn_reg {
	const u32 reg_base;
} mlu580_hbm_resetn_reg[MLU580_A6_MEMG_CHANNEL_COUNT] = {
	{MLU580_MEMG0_DEC_RESETN_BASE},
	{MLU580_MEMG1_DEC_RESETN_BASE},
	{MLU580_MEMG2_DEC_RESETN_BASE},
	{MLU580_MEMG3_DEC_RESETN_BASE},
	{MLU580_MEMG4_DEC_RESETN_BASE},
	{MLU580_MEMG5_DEC_RESETN_BASE},
};

struct llc_resetn_reg {
	const u32 reg_base;
} mlu580_llc_resetn_reg[MLU580_LLCG_CNT] = {
	{MLU580_LLCG0_RESETN_BASE},
	{MLU580_LLCG1_RESETN_BASE},
	{MLU580_LLCG2_RESETN_BASE},
	{MLU580_LLCG3_RESETN_BASE},
	{MLU580_LLCG4_RESETN_BASE},
	{MLU580_LLCG5_RESETN_BASE},
	{MLU580_LLCG6_RESETN_BASE},
	{MLU580_LLCG7_RESETN_BASE},
	{MLU580_LLCG8_RESETN_BASE},
	{MLU580_LLCG9_RESETN_BASE},
	{MLU580_LLCG10_RESETN_BASE},
	{MLU580_LLCG11_RESETN_BASE},
};

struct llc_groupconfig_reg {
	const u32 reg_base;
} mlu580_llc_groupconfig_reg[MLU580_LLCG_CNT * 2] = {
	{MLU580_LLC_GROUP0_0_BASE},
	{MLU580_LLC_GROUP0_1_BASE},
	{MLU580_LLC_GROUP1_0_BASE},
	{MLU580_LLC_GROUP1_1_BASE},
	{MLU580_LLC_GROUP2_0_BASE},
	{MLU580_LLC_GROUP2_1_BASE},
	{MLU580_LLC_GROUP3_0_BASE},
	{MLU580_LLC_GROUP3_1_BASE},
	{MLU580_LLC_GROUP4_0_BASE},
	{MLU580_LLC_GROUP4_1_BASE},
	{MLU580_LLC_GROUP5_0_BASE},
	{MLU580_LLC_GROUP5_1_BASE},
	{MLU580_LLC_GROUP6_0_BASE},
	{MLU580_LLC_GROUP6_1_BASE},
	{MLU580_LLC_GROUP7_0_BASE},
	{MLU580_LLC_GROUP7_1_BASE},
	{MLU580_LLC_GROUP8_0_BASE},
	{MLU580_LLC_GROUP8_1_BASE},
	{MLU580_LLC_GROUP9_0_BASE},
	{MLU580_LLC_GROUP9_1_BASE},
	{MLU580_LLC_GROUP10_0_BASE},
	{MLU580_LLC_GROUP10_1_BASE},
	{MLU580_LLC_GROUP11_0_BASE},
	{MLU580_LLC_GROUP11_1_BASE},
};

/*************************MLU580 ECC PageRetire BEGIN*************************/
struct ddr_retire_set {
	struct cn_mcc_set *mcc_set;
	struct hbm_retire_info_t retire_info[EEPROM_MAX_NUM];
	unsigned int retire_num;

	uint8_t llc_config;

	u64 address_swap_list[EEPROM_MAX_NUM];
	unsigned int repair_nums;

	u64 retired_pages[EEPROM_MAX_NUM];
	unsigned int retired_nums;
	atomic_t retire_enable;

	struct work_struct retire_work;
};

static irqreturn_t peri_mailbox_mlu580_intr_handle(int irq, void *data);

static const struct gddr_memsys_irq {
	const char irq_name[MAX_STRING_LEN];
	const int irq;
	irqreturn_t (*isr_t)(int irq, void *data);
} peri_mailbox_mlu580_ecc_irq = {
	.irq_name = "PERI_MCU_MAILBOX_PCIE_IRQ",
	.irq      = MLU580_PERI_MCU_MAILBOX_PCIE_IRQ,
	.isr_t    = peri_mailbox_mlu580_intr_handle,
};
/*
 *Ball		Bump		mem id		llcg id
 *ddr 0		mem00		mem0		llcg0
 *ddr 1		mem01		mem1		llcg1
 *ddr 2		mem02		mem2		llcg4
 *ddr 3		mem03		mem3		llcg5
 *ddr 4		mem04		mem4		llcg2
 *ddr 5		mem10		mem6		llcg8
 *ddr 6		mem11		mem7		llcg9
 *ddr 7		mem12		mem8		llcg6
 *ddr 8		mem13		mem9		llcg7
 *ddr 9		mem14		mem10		llcg10
 *ddr 10	mem20		mem5		llcg3
 *ddr 11	mem21		mem11		llcg11
 */
const u32 ddr_topid_to_llcgid[MLU580_DDR_CHANNEL_COUNT * 2] = {0, 1, 4, 5, 2, 8, 9, 6, 7, 10, 3, 11};

static void hbm_trigger_pgretire_work(struct work_struct *work)
{
	struct ddr_retire_set *retire_set = NULL;
	struct cn_mcc_set *mcc_set;
	struct cn_core_set *core;

	retire_set = container_of(work, struct ddr_retire_set, retire_work);
	if (!retire_set || !retire_set->mcc_set)
		return;

	mcc_set = (struct cn_mcc_set *)retire_set->mcc_set;
	if (!mcc_set->core)
		return;

	core = (struct cn_core_set *)mcc_set->core;

	if (core->state == CN_RUNNING && atomic_read(&retire_set->retire_enable)) {
		cn_mem_pageretire_handle(core);
	} else {
		cn_xid_err(core, XID_ECC_ERR, "Current status not support trigger pageRetire");
	}
}

static int
__is_address_saved(struct hbm_retire_info_t *retire_info, unsigned int counts,
		struct hbm_retire_info_t *input, unsigned int *index)
{
	int i = 0;

	for (i = counts - 1; i >= 0; i--) {
		if (input->info == retire_info[i].info)
			break;
	}

	if (index) *index = i;

	return !(i < 0);
}

static void
__parse_irq_info(struct cn_mcc_set *mcc_set, unsigned int irq_info)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set =
		(struct ddr_retire_set *)mcc_set->repair_set;
	struct hbm_retire_info_t *info = NULL, curr = {};
	unsigned int llcg_id = 0, index = 0;

	if (!retire_set)
		return;

	if (retire_set->retire_num >= EEPROM_MAX_NUM) {
		cn_xid_err(core, XID_ECC_ERR, "ecc irq ocur too much, out of pageretire ability");
		return;
	}

	/** irq data Format from isse M0:
	 *  Bit[31] ... Bit[30:27] .... Bit[26:23] ..... Bit[22] .... Bit[21:0]
	 *  DBE/SBE ... header[3:0] ... memsys[3:0]..... chl_id[1:0] .... mem_addr[30:8]
	 *
	 *  hbm_id in irq_info is top_id, we need translate it into decoder_id.
	 **/
	cn_dev_core_debug(core, "bit[30~27] %ld bit[26~23] %ld bit[31] %ld bit[22] %ld addr %lx"
			   , BITS(irq_info, 30, 27), BITS(irq_info, 26, 23),
			   BITS(irq_info, 31, 31), BITS(irq_info, 22, 22), BITS(irq_info, 21, 0));

	/*Note: use 'hbm_num' means llcgid, sys_num means llc_id in group, and
	 * pmc_num means llc_config*/
	llcg_id = ddr_topid_to_llcgid[BITS(irq_info, 26, 23)];
	SET_BITS(curr.hbm_num, 3, 0, llcg_id);
	curr.sys_num  = BITS(irq_info, 22, 22);/*llc id in group*/
	curr.pmc_num  = retire_set->llc_config;
	curr.ecc_type = BITS(irq_info, 31, 31);
	curr.ecc_addr = BITS(irq_info, 21, 0) << 9;

	if (__is_address_saved(retire_set->retire_info, retire_set->retire_num, &curr, &index)) {
		info = &retire_set->retire_info[index];
		/* update ecc error type, while memory ecc error worse than before */
		if (curr.ecc_type == ECC_BIT_2 && info->ecc_type == ECC_BIT_1)
			info->ecc_type = curr.ecc_type;
		goto do_retire;
	} else {
		info = &retire_set->retire_info[retire_set->retire_num];
		*info = curr;
		retire_set->retire_num++;
	}

do_retire:
	cn_dev_core_debug(core, "llcg_id:%d, llc_id:%d, type:%d, addr:%#x",
		info->hbm_num, info->sys_num, info->ecc_type, info->ecc_addr);

	cn_schedule_work(core, &retire_set->retire_work);
}

static irqreturn_t peri_mailbox_mlu580_intr_handle(int irq, void *data)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)data;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int reg_base = MLU580_PERI_MAILBOX1_BASE;
	unsigned int int_status = 0, info = 0;

	/* read status first */
	int_status = reg_read32(core->bus_set, reg_base + MLU580_MAILBOX_INT_STATUS1);

	/* ECC error happenend */
	if (int_status & MLU580_GDDR_ECC_OFFSET) {
		unsigned int count = cn_mcu_read32(core, MLU580_IPC_6);

		info = reg_read32(core->bus_set, reg_base + MLU580_MAILBOX_CH_INFO(0));

		cn_xid_err(core, XID_ECC_ERR, "%s ECC error irq occurred, irq info: %#x, SBE counts:%ld, DBE counts:%ld",
				   (BITS(info, 31, 31) == ECC_BIT_2) ? "DBE": "SBE", info, BITS(count, 15, 0), BITS(count, 31, 16));

		if (cambr_mcc_module_param_res_get(SBE_RETIRE_ENABLE) ||
				(BITS(info, 31, 31) != ECC_BIT_1)) {
			__parse_irq_info(mcc_set, info);
		}
	}

	/* Clear Mailbox Intr */
	reg_write32(core->bus_set, reg_base + MLU580_MAILBOX_INT_STATUS1, int_status << 16);
	int_status = reg_read32(core->bus_set, reg_base + MLU580_MAILBOX_INT_STATUS1);

	return IRQ_HANDLED;
}

static void
ddr_get_retire_info(void *mset, struct hbm_retire_info_t **retire_info,
		unsigned int *retire_num, int irq_flag)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set;

	if (retire_num)
		*retire_num = 0;

	retire_set = (struct ddr_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "repair_set is NULL");
		return;
	}

	if (!retire_info || !retire_num)
		return;
	if (irq_flag) {
		*retire_info = retire_set->retire_info;
		*retire_num = retire_set->retire_num;
	} else {
		*retire_info = NULL;
		*retire_num = 0;
	}
}

static int ddr_get_retire_pages(void *mset, int cause, unsigned int *pagecount,
			u64 **page_addr)
{
	int ret = -1;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set;

	if (pagecount)
		*pagecount = 0;

	if (cause != ECC_BIT_1 && cause != ECC_BIT_2) {
		cn_dev_core_err(core, "cause%d is invalid", cause);
		return ret;
	}

	retire_set = (struct ddr_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "repair_set is NULL");
		return ret;
	}

	memset(retire_set->retired_pages, 0, sizeof(retire_set->retired_pages));
	ret = cn_mem_pgr_get_pages(core, cause, &retire_set->retired_nums,
						retire_set->retired_pages);
	if (ret)
		return ret;

	if (pagecount)
		*pagecount = retire_set->retired_nums;

	if (page_addr)
		*page_addr = retire_set->retired_pages;

	return ret;
}

static int ddr_get_retire_pages_pending_status(void *mset, int *ispending,
								int *isfailure)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set =
		(struct ddr_retire_set *)mcc_set->repair_set;

	cn_mem_pgr_get_status(core, ispending, isfailure);

	if (retire_set->retire_num >= EEPROM_MAX_NUM)
		*isfailure = 1;

	return 0;
}

static int ddr_retire_switch(void *mset, int status)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set;

	retire_set = (struct ddr_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "retire_set is NULL");
		return -1;
	}

	if (status != 0 && status != 1)
		return atomic_read(&retire_set->retire_enable);

	atomic_set(&retire_set->retire_enable, status);

	return atomic_read(&retire_set->retire_enable);
}

static int
ddr_get_address_swap_info(void *mset, unsigned int *corr_rows,
				unsigned int *unc_rows, unsigned int *pending_rows,
				unsigned int *fail_rows)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int val = 0;

	val = reg_read32(core->bus_set, MLU580_IPC_4);

	cn_dev_core_debug(core, "read from register val is %#x", val);

	if (corr_rows) *corr_rows = BITS(val, 15, 0);
	if (unc_rows) *unc_rows  = BITS(val, 31, 16);
	if (fail_rows) *fail_rows = 0;
	if (pending_rows) {
		unsigned int retired_pages = 0;

		*pending_rows = 0;

		ddr_get_retire_pages(mcc_set, ECC_BIT_1, &retired_pages, NULL);
		*pending_rows += retired_pages;

		ddr_get_retire_pages(mcc_set, ECC_BIT_2, &retired_pages, NULL);
		*pending_rows += retired_pages;
	}

	return 0;
}

static int ddr_ecc_irq_inject(void *mset, u32 sys_mc_num,
				u32 mc_state, u32 ecc_addr)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set;
	unsigned long ecc_addr_bound = 0;
	int input_top_hbm_id = 0, bad_top_hbm_id = 0;
	unsigned int inject_value = 0, llcg_id = 0, llc_id = 0;
	unsigned int reg_base = 0;
	static unsigned int memsys_core_base[] = {
		0x2F00000, 0x2D00000, 0x2D80000, 0x3300000,
		0x3380000, 0x3700000, 0x3500000, 0x3580000,
		0x3B00000, 0x3B80000, 0x2900000, 0x2B00000 };


	retire_set = (struct ddr_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "retire_set is NULL");
		return -EINVAL;
	}

	ecc_addr_bound =
		1UL << (29 + mcc_set->msys_config.mlu590.hbm_capacity);

	if ((sys_mc_num >= (MLU580_A6_MEMG_CHANNEL_COUNT * 4)) || mc_state > 2 ||
		ecc_addr > ecc_addr_bound) {
		cn_dev_core_info(core, "Invalid parameters input! Each paramter valid ranges:");
		cn_dev_core_info(core, "sys_mc_num: 0 ~ %d, mc_state: 0 or 1, ecc_addr: 0 ~ %#lx",
						 MLU580_A6_MEMG_CHANNEL_COUNT * 4, ecc_addr_bound);
		return 0;
	}

	bad_top_hbm_id = BITS(reg_read32(core->bus_set, MLU580_CFG), 14, 12);
	input_top_hbm_id = BITS(sys_mc_num, 4, 1);

	if (mcc_set->msys_config.mlu590.hbm_nums != 6 &&
			input_top_hbm_id / 2 == bad_top_hbm_id) {
		cn_dev_core_err(core, "input sys_mc_num(%d) pointer to bad hbm id",
					sys_mc_num);
		return 0;
	}

	llc_id   = BITS(sys_mc_num, 0, 0);
	llcg_id  = BITS(sys_mc_num, 4, 1);
	SET_BITS(inject_value, 31, 31, mc_state & 0x1);
	SET_BITS(inject_value, 30, 27, 0x7);
	SET_BITS(inject_value, 26, 23, llcg_id);
	SET_BITS(inject_value, 22, 22, llc_id);
	SET_BITS(inject_value, 21, 0, ((ecc_addr >> 9) & ((1UL << 22) - 1)));

	reg_base = memsys_core_base[input_top_hbm_id];

	reg_write32(core->bus_set, reg_base + 0x200A0, inject_value);
	cn_bus_mb(core->bus_set);
	reg_write32(core->bus_set, reg_base + 0x20048, 0x10001);
	cn_bus_mb(core->bus_set);
	return 0;
}

static int ddr_get_sys_mc_nums(void *mset, unsigned int *sys_mc_num)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	if (!sys_mc_num) {
		cn_dev_core_err(core, "input sys_mc_num buffer is null");
		return -EINVAL;
	}

	*sys_mc_num = MLU580_A6_MEMG_CHANNEL_COUNT * 4;

	return 0;
}

static const struct cn_repair_ops ddr_retire_ops_mlu580 = {
	.get_retire_info = ddr_get_retire_info,
	.get_retire_pages = ddr_get_retire_pages,
	.get_retire_pages_pending_status = ddr_get_retire_pages_pending_status,
	.get_remapped_rows = ddr_get_address_swap_info,
	.retire_switch = ddr_retire_switch,
	.ecc_irq_inject = ddr_ecc_irq_inject,
	/* Debug mode current not support */
	.get_eeprom_switch = NULL,
	.get_eeprom_info = NULL,
	.get_sys_mc_nums = ddr_get_sys_mc_nums,
};

void mlu580_get_ile_status(struct cn_core_set *core)
{
	core->ile_en = (reg_read32(core->bus_set, 0x280224) >> 1) & 0x1;

	cn_dev_core_debug(core, "inlineECC mode is [%s]!", core->ile_en ? "ENABLE" : "DISABLE");
}	

int  mlu580_ddr_ecc_info_init(void *bus_set)
{
	struct cn_core_set *core = ((struct cn_bus_set *)bus_set)->core;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	struct ddr_retire_set *retire_set = NULL;
	int ret = 0;

	if (!core->ile_en)
		return 0;

	ret = cn_bus_register_interrupt(core->bus_set, peri_mailbox_mlu580_ecc_irq.irq,
		peri_mailbox_mlu580_ecc_irq.isr_t, (void *)mcc_set);
	if (ret) {
		cn_dev_core_err(core, "register ddr ecc irq isr error");
		return ret;
	}

	ret = cn_bus_enable_irq(core->bus_set, peri_mailbox_mlu580_ecc_irq.irq);
	if (ret) {
		cn_dev_core_err(core, "enable ddr ecc irq isr error");
		goto register_failed;
	}

	retire_set = cn_kzalloc(sizeof(struct ddr_retire_set), GFP_KERNEL);
	if (!retire_set) {
		cn_dev_core_err(core, "create retire_set failed");
		ret = -ENOMEM;
		goto failed_create_buf;
	}

	if (!cn_core_is_vf(core) && !cn_is_mim_en(core)) {
		atomic_set(&retire_set->retire_enable, 1);
	} else {
		atomic_set(&retire_set->retire_enable, 0);
	}

	SET_BITS(retire_set->llc_config, 0, 0, !mcc_set->msys_config.mlu590.shuffle_dis);
	SET_BITS(retire_set->llc_config, 2, 1, mcc_set->msys_config.mlu590.interleave_size);
	SET_BITS(retire_set->llc_config, 3, 3, !mcc_set->msys_config.mlu590.llc_shuffle_dis);
	SET_BITS(retire_set->llc_config, 5, 4, mcc_set->msys_config.mlu590.llc_interleave_size);
	SET_BITS(retire_set->llc_config, 7, 6, mcc_set->msys_config.mlu590.llc_interleave_mode);

	INIT_WORK(&retire_set->retire_work, hbm_trigger_pgretire_work);

	retire_set->mcc_set = mcc_set;

	mcc_set->repair_set = (void *)retire_set;
	mcc_set->repair_ops = &ddr_retire_ops_mlu580;

	return 0;

failed_create_buf:
	/* release mlu580 peri mailbox ecc irq */
	cn_bus_disable_irq(core->bus_set, peri_mailbox_mlu580_ecc_irq.irq);
	cn_bus_unregister_interrupt(core->bus_set, peri_mailbox_mlu580_ecc_irq.irq);
	return ret;

register_failed:
	cn_bus_unregister_interrupt(core->bus_set, peri_mailbox_mlu580_ecc_irq.irq);
	return ret;
}

void mlu580_ddr_ecc_info_exit(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set =
		(struct ddr_retire_set *)mcc_set->repair_set;
	int ret = 0;

	if (retire_set) {
		flush_work(&retire_set->retire_work);
		ret = cancel_work_sync(&retire_set->retire_work);
		if (ret) {
			cn_dev_core_warn(core, "retire_work sync return %d", ret);
		}

		cn_kfree(retire_set);
		mcc_set->repair_ops = NULL;
		mcc_set->repair_set = NULL;
	}

	cn_bus_disable_irq(core->bus_set, peri_mailbox_mlu580_ecc_irq.irq);
	cn_bus_unregister_interrupt(core->bus_set, peri_mailbox_mlu580_ecc_irq.irq);
}
/*************************MLU580 ECC PageRetire End*************************/

void hbm_exit_mlu580(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;

	/* release mlu580 peri mailbox ecc irq */
	mlu580_ddr_ecc_info_exit(mcc_set);

	if (mcc_set->ecc_status) {
		cn_kfree(mcc_set->ecc_status);
	}
}

void get_map_mode_mlu580(void *mset, unsigned int *map_mode, unsigned int *hbm_idx)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int hbm_num;
	unsigned int hbm_mem_channel =
		cambr_mcc_module_param_res_get(HBM_MEM_CHANNEL);
	unsigned int hbm_bitmap;

	hbm_bitmap = mcc_set->msys_config.mlu590.hbm_bitmap;
	hbm_num = mcc_set->msys_config.mlu590.hbm_nums;
	hbm_mem_channel = hbm_mem_channel % MLU580_A6_MEMG_CHANNEL_COUNT;

	*map_mode = mcc_set->msys_config.mlu590.llcg_interleave_mode & 0x3;

	switch (hbm_num) {
	case MLU580_A6_MEMG_CHANNEL_COUNT:
		if (*map_mode == LLCG_INTERLEAVE_MAP2) {
			unsigned int tmp_group;
			tmp_group = hbm_mem_channel / 2;
			hbm_mem_channel = tmp_group * 2;
		}
		*hbm_idx = hbm_mem_channel;
		break;
	case MLU580_A5_MEMG_CHANNEL_COUNT:
		if (*map_mode == LLCG_INTERLEAVE_MAP1) {
			if (((0x1 << hbm_mem_channel) & MLU580_MEMG_BITMAP) ==
				(~(hbm_bitmap) & MLU580_MEMG_BITMAP)) {
				cn_dev_core_info(core, "a5 change hbm_mem_channel %d",
								 hbm_mem_channel);
				hbm_mem_channel = (hbm_mem_channel + 1) % MLU580_A6_MEMG_CHANNEL_COUNT;
				cn_dev_core_info(core, "a5 change hbm_mem_channel %d",
								 hbm_mem_channel);
			}
			*hbm_idx = hbm_mem_channel;
		} else if (*map_mode == LLCG_INTERLEAVE_MAP2) {
			unsigned int tmp_group;
			unsigned int tmp_group2;
			tmp_group = hbm_mem_channel / 2;
			tmp_group2 = __ffs(~(hbm_bitmap) & MLU580_MEMG_BITMAP) / 2;

			cn_dev_core_info(core, "a5 dump group1 %d group2 %d", tmp_group,
							 tmp_group2);
			if (tmp_group == tmp_group2) {
				tmp_group = (tmp_group + 1) % (MLU580_A6_MEMG_CHANNEL_COUNT / 2);
				cn_dev_core_info(core, "a5 need change old hbm_mem_channel %d",
								 hbm_mem_channel);
				hbm_mem_channel = tmp_group * 2;
				cn_dev_core_info(core, "a5 change new hbm_mem_channel %d",
								 hbm_mem_channel);
			} else {
				hbm_mem_channel = tmp_group * 2;
			}
			*hbm_idx = hbm_mem_channel;
		}
		break;
	case MLU580_A3_MEMG_CHANNEL_COUNT:
		if (*map_mode == LLCG_INTERLEAVE_MAP1) {
			if (((0x1 << hbm_mem_channel) & MLU580_MEMG_BITMAP) &
				(~(hbm_bitmap) & MLU580_MEMG_BITMAP)) {
				cn_dev_core_info(core, "a3 need change hbm_mem_channel %d",
								 hbm_mem_channel);
hbm_a3_map1_check:
				hbm_mem_channel = (hbm_mem_channel + 1) % MLU580_A6_MEMG_CHANNEL_COUNT;
				cn_dev_core_info(core, "a3 need change new hbm_mem_channel %d",
								 hbm_mem_channel);
				if (((0x1 << hbm_mem_channel) & MLU580_MEMG_BITMAP) &
					(~(hbm_bitmap) & MLU580_MEMG_BITMAP))
					goto hbm_a3_map1_check;
			}
			*hbm_idx = hbm_mem_channel;
		} else if (*map_mode == LLCG_INTERLEAVE_MAP2) {
			unsigned int tmp_group;
			unsigned int tmp_group2;
			unsigned int tmp_bitmap;
			tmp_group = hbm_mem_channel / 2;
			tmp_bitmap = (~((hbm_bitmap) | (0x3 << 2)) & MLU580_MEMG_BITMAP);/*get bad hbm idx*/
			tmp_group2 = __ffs(tmp_bitmap) / 2;
			cn_dev_core_info(core, "a3 dump group1 %d group2 %d", tmp_group,
							 tmp_group2);

			if (tmp_group == tmp_group2 || tmp_group == 0x1) {
hbm_a3_map2_check:
				tmp_group = (tmp_group + 1) % (MLU580_A6_MEMG_CHANNEL_COUNT / 2);
				cn_dev_core_info(core, "a3 need change new hbm_mem_group %d",
							tmp_group);
				if (tmp_group == tmp_group2 || tmp_group == 0x1)
					goto hbm_a3_map2_check;
			} else {
				hbm_mem_channel = tmp_group * 2;
			}
			hbm_mem_channel = tmp_group * 2;
			*hbm_idx = hbm_mem_channel;
		}
		break;
	}
	cn_dev_core_info(core, "llcg interleave %d hbm idx %d", *map_mode, *hbm_idx);
	return;
}

int ddr_get_channel_num_mlu580(void *mset)
{
	return MLU580_A6_MEMG_CHANNEL_COUNT;
}

void *ddr_get_ecc_status_mlu580(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core_set = NULL;
	struct ecc_info_t *ecc_info = NULL;
	u32 reg32 = 0;

	if (IS_ERR_OR_NULL(mcc_set)) {
		return NULL;
	}

	core_set = (struct cn_core_set *)mcc_set->core;
	if (IS_ERR_OR_NULL(core_set)) {
		return NULL;
	}

	/* read hbm ecc info form reg */
	reg32 = cn_mcu_read32(core_set, MLU580_IPC_6);

	ecc_info = ((struct ecc_info_t*)mcc_set->ecc_status);
	if (IS_ERR_OR_NULL(ecc_info)) {
		return NULL;
	}

	ecc_info->one_bit_ecc_error = BITS(reg32, 15, 0);
	ecc_info->multiple_multiple_bit_ecc_error = 0;
	ecc_info->addr_forbidden_error = 0;
	ecc_info->multiple_one_bit_ecc_error = 0;
	ecc_info->multiple_bit_ecc_error = BITS(reg32, 31, 16);

	return mcc_set->ecc_status;
}

/*TODO: use union for diff platform */
static const struct cn_mcc_ops hbm_ops_mlu580 = {
	.get_channel_num = ddr_get_channel_num_mlu580,
	.get_ecc_status = ddr_get_ecc_status_mlu580,
	.get_map_mode = get_map_mode_mlu580,
	.get_compress_info = NULL,
	.mcc_exit = hbm_exit_mlu580,
	.repair_exit = NULL,
	.get_d2dc_num = NULL,
	.get_d2dc_status = NULL,
};

static inline void mlu580_config_llc_slice(void *bus_set, unsigned int llc_slice_base)
{
	struct cn_core_set *core = ((struct cn_bus_set *)bus_set)->core;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	unsigned int compress_space_value = 0;
	unsigned int compress_space_mask = 0;
	unsigned int cfg_llc_comp_addr_map_value = 0;
	unsigned int cfg_llc_comp_addr_map_mask = 0;
	unsigned int cfg_ddr_size_ile[] = {0x1E0FFFFF, 0x3C2FFFFF, 0x786FFFFF, 0xF0EFFFFF};
	unsigned int cfg_ddr_size_normal[] = {0x1FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF};

	/*pool state for work*/
	reg_read32_and_wait(bus_set, llc_slice_base + 0xd8, 0x0);

	/*conflg llc slice*/
	reg_write32(bus_set, llc_slice_base + 0x160, 0xffffffff);
	reg_write32(bus_set, llc_slice_base + 0x98, 0x210);
	reg_write32(bus_set, llc_slice_base + 0x1d8, 0x0);

	if (mcc_set->msys_config.mlu590.llc_compress_dis == CONFIG_DISABLE) {
		reg_write32(bus_set, llc_slice_base + 0xc4, 0x0);
		cn_dev_core_info(core, "compress is set disable.");
		return;
	}

	/*
	 * NOTE:
	 * 1. cambr_llc_compress_mode 0 (low interleave): use all mem as common to
	 * shield the differences between compress and non-compress.
	 *	compress_space_mask = 0x1f_ffff,
	 *	compress_space_value = 0,
	 *	cfg_llc_comp_addr_map_value = 0x0,
	 *	cfg_llc_comp_addr_map_mask = 0x1.
	 *
	 * 2. cambr_llc_compress_mode 1 (high interleave):
	 *	a) use top half as compress, and bottom half as non-compress:
	 *	compress_space_mask = 0,
	 *	compress_space_value = 1,
	 *	cfg_llc_comp_addr_map_value = 0x0,
	 *	cfg_llc_comp_addr_map_mask = 0x1f_ffff.
	 *
	 *	b) use top half as non-compress, and bottom half as compress:
	 *	compress_space_mask = 0,
	 *	compress_space_value = 0,
	 *	cfg_llc_comp_addr_map_value = 0x0,
	 *	cfg_llc_comp_addr_map_mask = 0x1f_ffff.
	 *
	 * 3. cambr_llc_compress_mode 2 (make all memory non-differential):
	 *	If per_hbm capatinity is 16GB it uses low interleave as mode0, otherwise
	 *	uses the high interleave as mode1;
	 */

	if (mcc_set->msys_config.mlu590.llc_compress_mode == LLC_LOW_INTERLEAVE_COMPRESS) {
		/*low interweave*/
		compress_space_mask = 0x1fffff;
		compress_space_value = 0;
		cfg_llc_comp_addr_map_value = 0x0;
		cfg_llc_comp_addr_map_mask = 0x1;
		cn_dev_core_info(core, "compress is set low interweave.");
	} else if (mcc_set->msys_config.mlu590.llc_compress_mode == LLC_HIGH_INTERLEAVE_COMPRESS) {
		if (mcc_set->msys_config.mlu590.llc_compress_high_mode ==
			LLC_COMPRESS_HIGH_MODE_LOW) {
			/*high interweave use bottom addr*/
			compress_space_mask = 0x0;
			compress_space_value = 0x0;
			cfg_llc_comp_addr_map_value = 0x0;
			cfg_llc_comp_addr_map_mask = 0x1fffff;
			cn_dev_core_info(core, "compress is set high interweave use low addr.");
		} else if (mcc_set->msys_config.mlu590.llc_compress_high_mode ==
				   LLC_COMPRESS_HIGH_MODE_HIGH) {
			/*high interweave use top addr*/
			compress_space_mask = 0x0;
			compress_space_value = 0x1;
			cfg_llc_comp_addr_map_value = 0x0;
			cfg_llc_comp_addr_map_mask = 0x1fffff;
			cn_dev_core_info(core, "compress is set high interweave use high addr.");
		} else if (mcc_set->msys_config.mlu590.llc_compress_high_mode ==
				   LLC_COMPRESS_HIGH_MODE_ALL) {
			if (mcc_set->msys_config.mlu590.hbm_capacity == MEMG_CAPACITY_SIZE_16G) {
				/*high interweave use bottom addr*/
				compress_space_mask = 0x0;
				compress_space_value = 0x0;
				cfg_llc_comp_addr_map_value = 0x0;
				cfg_llc_comp_addr_map_mask = 0x1fffff;
				cn_dev_core_info(core, "compress is set high interweave use bottom addr.");
			} else{
				/*high interweave use top addr*/
				compress_space_mask = 0x0;
				compress_space_value = 0x1;
				cfg_llc_comp_addr_map_value = 0x0;
				cfg_llc_comp_addr_map_mask = 0x1fffff;
				cn_dev_core_info(core, "compress is set high interweave use top addr");
			}
		}
	} else if (mcc_set->msys_config.mlu590.llc_compress_mode == LLC_ND_INTERLEAVE_COMPRESS) {
		if (mcc_set->msys_config.mlu590.hbm_capacity == MEMG_CAPACITY_SIZE_16G) {
			/*low interweave*/
			compress_space_mask = 0x1fffff;
			compress_space_value = 0;
			cfg_llc_comp_addr_map_value = 0x0;
			cfg_llc_comp_addr_map_mask = 0x1;
			cn_dev_core_debug(core, "compress is set low interweave.");
		} else {
			/*high interweave use bottom addr*/
			compress_space_mask = 0x0;
			compress_space_value = 0x0;
			cfg_llc_comp_addr_map_value = 0x0;
			cfg_llc_comp_addr_map_mask = 0x1fffff;
			cn_dev_core_debug(core, "compress is set high interweave use bottom addr");
		}
	}

	reg_write32(bus_set, llc_slice_base + 0xec,
				compress_space_value << 24 | compress_space_mask);

	reg_write32(bus_set, llc_slice_base + 0x1c0, cfg_llc_comp_addr_map_value);
	reg_write32(bus_set, llc_slice_base + 0x1c4, cfg_llc_comp_addr_map_mask);

	if (core->ile_en) {
		reg_write32(bus_set, llc_slice_base + 0x160, cfg_ddr_size_ile[mcc_set->msys_config.mlu590.hbm_capacity]);
	} else {
		reg_write32(bus_set, llc_slice_base + 0x160, cfg_ddr_size_normal[mcc_set->msys_config.mlu590.hbm_capacity]);
	}

	cn_dev_core_debug(core, "set reg: mode %x value %x mask %x",
					  reg_read32(bus_set, llc_slice_base + 0xec),
					  reg_read32(bus_set, llc_slice_base + 0x1c0),
					  reg_read32(bus_set, llc_slice_base + 0x1c4));
}

static void mlu580_config_llc_sys(void *bus_set, unsigned int llc_sys_base)
{
	u32 reg_val = 0x0;

	usleep_range(2000, 3000);//2ms
	reg_write32(bus_set, llc_sys_base + 0x1020, 0x3f);
	reg_read32(bus_set, llc_sys_base + 0x1020);
	usleep_range(2000, 3000);//2ms
	reg_write32(bus_set, llc_sys_base + 0x1028, 0x0);
	reg_read32(bus_set, llc_sys_base + 0x1028);
	usleep_range(2000, 3000);//2ms

	reg_val = reg_read32(bus_set, llc_sys_base + 0x1028);
	reg_val |= (0x1 << 4);
	reg_write32(bus_set, llc_sys_base + 0x1028, reg_val);

	/*Now config slice in dev module*/
	reg_val |= (0x3 << 0);
	reg_write32(bus_set, llc_sys_base + 0x1028, reg_val);
	reg_val |= ((0x1 << 2) | (0x1 << 3) | (0x1 << 5));
	reg_write32(bus_set, llc_sys_base + 0x1028, reg_val);

	/*Enable LPC in default*/
	reg_val = 0x5;
	reg_write32(bus_set, llc_sys_base + 0x102c, reg_val);

	mlu580_config_llc_slice(bus_set, llc_sys_base);

	return;
}

/*
 *NOTE: config llc groups by group mask get from mcu info.
 */
static int mlu580_mem_mask_info(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int hbm_bad_mask;

	mcc_set->msys_config.mlu590.hbm_nums = core->board_info.hbm_cnt; /*3: A3, 5: A5, 6: A6*/

	if (mcc_set->msys_config.mlu590.hbm_nums == MLU580_A5_MEMG_CHANNEL_COUNT) {
		hbm_bad_mask = core->board_info.bad_hbm_mask;/*use bit to represent hbm idx*/
	} else if (mcc_set->msys_config.mlu590.hbm_nums == MLU580_A3_MEMG_CHANNEL_COUNT) {
		hbm_bad_mask = core->board_info.bad_hbm_mask;
		/* NOTE: In mlu580/mlu57x mcu give the bad_hbm_mask just one bit set.
		 * If bad_hbm_mask is one of the bit 0/1/2, the dummy mem sys groups are
		 * 0, 1 and 2. That's the active mem_sys groups are 3, 4 and 5.
		 * If bad_hbm_mask is one of the bit 3/4/5, the dummy mem sys groups are
		 * 3, 4 and 5. That's the active mem_sys groups are 0, 1 and 2.
		 */
		if (core->board_info.bad_hbm_mask & 0x7) {
			hbm_bad_mask = 0x7;
		} else if (core->board_info.bad_hbm_mask & 0x38) {
			hbm_bad_mask = 0x38;
		} else {
			cn_dev_core_err(core, "mem bad id is not legal");
			return -EINVAL;
		}
	} else {
		hbm_bad_mask = 0;/*use bit to represent hbm idx*/
	}

	mcc_set->msys_config.mlu590.hbm_bitmap = MLU580_MEMG_BITMAP & (~(hbm_bad_mask));

	cn_dev_core_info(core, "MEMG NUMS %d BAD ID %x, MEMG BIT MAP %x",
					 mcc_set->msys_config.mlu590.hbm_nums,
					 core->board_info.bad_hbm_mask,
					 mcc_set->msys_config.mlu590.hbm_bitmap);

	return 0;
}

static void mlu580_hbm_capacity_info(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	/*1: single hbm size 16GB, 0: single hbm size 8GB*/
	cn_dev_core_info(core, "MEMG CAPACITY %xGB", core->board_info.ddr_cap);
	if (core->board_info.ddr_cap == 0x10) {
		mcc_set->msys_config.mlu590.hbm_capacity = MEMG_CAPACITY_SIZE_16G;
	} else if (core->board_info.ddr_cap == 0x8) {
		mcc_set->msys_config.mlu590.hbm_capacity = MEMG_CAPACITY_SIZE_8G;
	} else if (core->board_info.ddr_cap == 0x4) {
		mcc_set->msys_config.mlu590.hbm_capacity = MEMG_CAPACITY_SIZE_4G;
	} else if (core->board_info.ddr_cap == 0x2) {
		mcc_set->msys_config.mlu590.hbm_capacity = MEMG_CAPACITY_SIZE_2G;
	} else {
		cn_dev_core_err(core, "Get MEMG CAPACITY %xGB is invalid", core->board_info.ddr_cap);
	}
}

#define backlist_for_next(pos, back_list)	\
		for (pos = __ffs(back_list); back_list > 0; \
					back_list &= ~(1 << pos), pos = __ffs(back_list))

static void mlu580_hbm_llc_init(void *bus_set)
{
	struct cn_core_set *core = ((struct cn_bus_set *)bus_set)->core;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	unsigned int hbm_bitmap, llcg_bitmap;
	unsigned int hbm_rt_base, llc_rt_base, llc_cf_base;
	int index;

	hbm_bitmap = mcc_set->msys_config.mlu590.hbm_bitmap;
	llcg_bitmap =  __mlu580_hbm_mask_to_llc_mask(hbm_bitmap);

	backlist_for_next(index, hbm_bitmap) {
		/*reset hbm*/
		hbm_rt_base = mlu580_hbm_resetn_reg[index].reg_base;
		cn_dev_core_info(core, "memg %d reset base %x", index, hbm_rt_base);
		reg_write32(bus_set, hbm_rt_base, MLU580_MEMG_RESETN_MASK);
		cn_dev_core_info(core, "memg %d reset base %x", index, hbm_rt_base + MLU580_MEM_RESETN_OFF);
		reg_write32(bus_set, hbm_rt_base + MLU580_MEM_RESETN_OFF, MLU580_MEMG_RESETN_MASK);
	}

	backlist_for_next(index, llcg_bitmap) {
		/*reset llc*/
		llc_rt_base = mlu580_llc_resetn_reg[index].reg_base;
		cn_dev_core_info(core, "llcg %d reset sys0 base %x sys1 base %x", index,
						 llc_rt_base, llc_rt_base + MLU580_LLC_SYS_RESETN_OFF);
		reg_write32(bus_set, llc_rt_base, MLU580_LLCG_RESETN_MASK);
		reg_write32(bus_set, llc_rt_base + MLU580_LLC_SYS_RESETN_OFF, MLU580_LLCG_RESETN_MASK);
		cn_dev_core_info(core, "llcg %d reset read sys0 %x sys1 %x", index,
				reg_read32(bus_set, llc_rt_base),
				reg_read32(bus_set, llc_rt_base + MLU580_LLC_SYS_RESETN_OFF));

		usleep_range(1000, 1050);//1ms
		/*config llc*/
		cn_dev_core_info(core, "llcg %d config sys0 base %x sys1 base %x",
						  index,
						  mlu580_llc_groupconfig_reg[index * 2].reg_base,
						  mlu580_llc_groupconfig_reg[index * 2 + 1].reg_base);
		llc_cf_base = mlu580_llc_groupconfig_reg[index * 2].reg_base;
		mlu580_config_llc_sys(bus_set, llc_cf_base);
		llc_cf_base = mlu580_llc_groupconfig_reg[index * 2 + 1].reg_base;
		mlu580_config_llc_sys(bus_set, llc_cf_base);
	}

	return;
}

static void mlu580_memsys_config_default(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	mcc_set->msys_config.mlu590.shuffle_dis = CONFIG_ENABLE;
	cn_dev_core_info(core, "mlu580 llc group shuffle is %s",
					 llc_mode_en[mcc_set->msys_config.mlu590.shuffle_dis]);
	mcc_set->msys_config.mlu590.interleave_size = INTERLEAVE_GRAN_512B;
	cn_dev_core_info(core, "mlu580 llc group interleave size is %d B",
					 (0x1 << mcc_set->msys_config.mlu590.interleave_size) * 512);

	mcc_set->msys_config.mlu590.llc_interleave_mode = LLC_INTERLEAVE_NUMS_4;
	cn_dev_core_info(core, "mlu580 llc interleave mode is %s",
					 llc_interleave_mode_name[LLC_INTERLEAVE_NUMS_2]);

	mcc_set->msys_config.mlu590.llc_interleave_size = INTERLEAVE_GRAN_512B;
	cn_dev_core_info(core, "mlu580 llc interleave size is %d B",
					 (0x1 << mcc_set->msys_config.mlu590.llc_interleave_size) * 512);
	mcc_set->msys_config.mlu590.llc_shuffle_dis = CONFIG_ENABLE;
	cn_dev_core_info(core, "mlu580 llc shuffle is %s",
					 llc_mode_en[mcc_set->msys_config.mlu590.llc_shuffle_dis]);

	mcc_set->msys_config.mlu590.sp_interleave_en = 0;/*reserve config*/

	mcc_set->msys_config.mlu590.llcg_interleave_mode = LLCG_INTERLEAVE_MAP3;
	cn_dev_core_info(core, "mlu580 llcg_interleave_mode is %d",
					 mcc_set->msys_config.mlu590.llcg_interleave_mode);
}

/*Get interleave set from module param*/
static void mlu580_memsys_config_parse_param(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int llcg_shuffle_dis =	cambr_mcc_module_param_res_get(LLCG_SHUFFLE_DIS);
	unsigned int llcg_interleave_size =	cambr_mcc_module_param_res_get(LLCG_INTERLEAVE_SIZE);
	unsigned int llc_interleave_mode = cambr_mcc_module_param_res_get(LLC_INTERLEAVE_MODE);
	unsigned int llc_shuffle_dis = cambr_mcc_module_param_res_get(LLC_SHUFFLE_DIS);
	unsigned int llc_interleave_size = cambr_mcc_module_param_res_get(LLC_INTERLEAVE_SIZE);
	unsigned int llcg_interleave_mode =	cambr_mcc_module_param_res_get(LLCG_INTERLEAVE_MODE);
	unsigned int hbm_mem_channel = cambr_mcc_module_param_res_get(HBM_MEM_CHANNEL);

	cn_dev_core_info(core, "mlu580 llc config module param:");
	cn_dev_core_info(core, "llcg shuffle disable %d llcg interleave size %d "
					 "llc interleave mode %d llc shuffle disable %d llc interleave size %d",
					 llcg_shuffle_dis, llcg_interleave_size,
					 llc_interleave_mode, llc_shuffle_dis, llc_interleave_size);

	cn_dev_core_info(core, "llcg interleave %d hbm idx %d",
					 llcg_interleave_mode, hbm_mem_channel);

	if (llcg_interleave_mode != LLCG_INTERLEAVE_MAP3) {
		mcc_set->msys_config.mlu590.llcg_interleave_mode = llcg_interleave_mode;
		cn_dev_core_info(core, "mlu580 llcg interleave mode is %s",
						 llcg_interleave_mode_name[mcc_set->msys_config.mlu590.llcg_interleave_mode]);
	}

	if (llcg_shuffle_dis != CONFIG_ENABLE) {
		mcc_set->msys_config.mlu590.shuffle_dis = CONFIG_DISABLE;
		cn_dev_core_info(core, "mlu580 llc group shuffle is %s",
				 llc_mode_en[mcc_set->msys_config.mlu590.shuffle_dis]);
	}
	if (llcg_interleave_size != INTERLEAVE_GRAN_512B) {
		mcc_set->msys_config.mlu590.interleave_size = llcg_interleave_size;
		cn_dev_core_info(core, "mlu580 llc group interleave size is %d B",
						 (0x1 << mcc_set->msys_config.mlu590.interleave_size) * 512);
	}

	if (llc_interleave_mode != LLC_INTERLEAVE_NUMS_4) {
		mcc_set->msys_config.mlu590.llc_interleave_mode = llc_interleave_mode;
		cn_dev_core_info(core, "mlu580 llc interleave mode is %s",
						 llc_interleave_mode_name[mcc_set->msys_config.mlu590.llc_interleave_mode]);
	} else {
		/*using default value*/
	}

	if (llc_shuffle_dis != CONFIG_ENABLE) {
		mcc_set->msys_config.mlu590.llc_shuffle_dis = CONFIG_DISABLE;
		cn_dev_core_info(core, "mlu580 llc shuffle is %s",
				llc_mode_en[mcc_set->msys_config.mlu590.llc_shuffle_dis]);
	}
	if (llc_interleave_size != INTERLEAVE_GRAN_512B) {
		mcc_set->msys_config.mlu590.llc_interleave_size = llc_interleave_size;
		cn_dev_core_info(core, "mlu580 llc interleave size is %d B",
						 (0x1 << mcc_set->msys_config.mlu590.llc_interleave_size) * 512);
	}

}

static void mlu580_llc_interleave_and_shuffle_set(void* bus_set)
{
	struct cn_core_set *core = ((struct cn_bus_set *)bus_set)->core;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	unsigned int reg_val;

	reg_val = reg_read32(bus_set, MLU580_SYSCTRL_ADDRESS_MAP);

	reg_val &= ~(MLU580_SYSCTRL_SHUFFLE_MASK << MLU580_SYSCTRL_SHUFFLE_OFF);
	reg_val &= ~(MLU580_SYSCTRL_INTERLEAVING_SIZE_MASK << MLU580_SYSCTRL_INTERLEAVING_SIZE_OFF);
	reg_val &= ~(MLU580_SYSCTRL_LLC_INTERLEAVING_MODE_MASK << MLU580_SYSCTRL_LLC_INTERLEAVING_MODE_OFF);
	reg_val &= ~(MLU580_SYSCTRL_LLC_INTERLEAVING_SIZE_MASK << MLU580_SYSCTRL_LLC_INTERLEAVING_SIZE_OFF);
	reg_val &= ~(MLU580_SYSCTRL_LLC_SHUFFLE_MASK << MLU580_SYSCTRL_LLC_SHUFFLE_OFF);

	cn_dev_core_info(core, "set mlu580 llc interleave reg to initial val %x",
					 reg_val);

	reg_val |= (~(mcc_set->msys_config.mlu590.shuffle_dis) & MLU580_SYSCTRL_SHUFFLE_MASK) <<
		MLU580_SYSCTRL_SHUFFLE_OFF;
	reg_val |= mcc_set->msys_config.mlu590.interleave_size <<
		MLU580_SYSCTRL_INTERLEAVING_SIZE_OFF;
	reg_val |= mcc_set->msys_config.mlu590.llc_interleave_mode <<
		MLU580_SYSCTRL_LLC_INTERLEAVING_MODE_OFF;
	reg_val |= mcc_set->msys_config.mlu590.llc_interleave_size <<
		MLU580_SYSCTRL_LLC_INTERLEAVING_SIZE_OFF;
	reg_val |= (~(mcc_set->msys_config.mlu590.llc_shuffle_dis) & MLU580_SYSCTRL_LLC_SHUFFLE_MASK) <<
		MLU580_SYSCTRL_LLC_SHUFFLE_OFF;

	reg_write32(bus_set, MLU580_SYSCTRL_ADDRESS_MAP, reg_val);
	cn_dev_core_info(core, "mlu580 llc interleave set reg %x val %x",
					 MLU580_SYSCTRL_ADDRESS_MAP, reg_val);
	/*FIXME: need mcu config MEM_CAPACITY*/
}

static void mlu580_llc_compress_config_parse_param(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int llc_ipu_compress_dis =	cambr_mcc_module_param_res_get(LLC_IPU_COMPRESS_DIS);
	unsigned int llc_compress_mode = cambr_mcc_module_param_res_get(LLC_COMPRESS_MODE);
	unsigned int llc_compress_high_mode =
		cambr_mcc_module_param_res_get(LLC_COMPRESS_HIGH_MODE);

	if (llc_ipu_compress_dis != CONFIG_ENABLE) {
		mcc_set->msys_config.mlu590.llc_compress_dis = CONFIG_DISABLE;
		cn_dev_core_info(core, "FORCE SET COMPRESS DISABLE!");
	} else {
		mcc_set->msys_config.mlu590.llc_compress_dis = CONFIG_ENABLE;
	}

	if (llc_compress_mode != LLC_ND_INTERLEAVE_COMPRESS) {
		cn_dev_core_info(core, "set llc compress_mode force to %s",
						 comp_mode_mode[llc_compress_mode]);
	}
	if (llc_compress_high_mode != LLC_COMPRESS_HIGH_MODE_ALL) {
		cn_dev_core_info(core, "set llc compress_addr force to %s",
						 comp_high_mode[llc_compress_high_mode]);
	}

	mcc_set->msys_config.mlu590.llc_compress_mode = llc_compress_mode ;
	mcc_set->msys_config.mlu590.llc_compress_high_mode = llc_compress_high_mode;

}

/*Noc ctrl, hw limit this config must before bringup in stopped-flow state*/
static void mlu580_noc_data_crl_set(void* bus_set)
{
	unsigned int reg_val;

	reg_val = reg_read32(bus_set, MLU580_SYSCTRL_NOC_DATA_CTL);
	reg_val &= ~(0x3);
	reg_write32(bus_set, MLU580_SYSCTRL_NOC_DATA_CTL, reg_val);

	reg_write32(bus_set, NOC_DATA_MIDDLE2_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE21_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE2_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE21_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE3_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE3_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE4_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE4_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE5_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE51_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE5_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE51_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);

	reg_write32(bus_set, NOC_DATA_MIDDLE2_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE21_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE2_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE21_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE3_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE3_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE4_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE4_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE5_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE51_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE5_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE51_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);

	reg_write32(bus_set, NOC_DATA_IPUBAR00_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR2_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR00_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR2_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR01_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR01_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR1_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR31_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR1_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR31_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR30_RD0	+ NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR30_RD1	+ NOC_VC_NUM_TABLE0_OFF, 0);

	reg_write32(bus_set, NOC_DATA_IPUBAR00_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR2_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR00_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR2_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR01_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR01_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR1_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR31_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR1_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR31_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR30_RD0	+ NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_IPUBAR30_RD1	+ NOC_VC_NUM_TABLE1_OFF, 0);

	/* CONFIG ALL CLUSTER READ OUTSTANDING TO 128, for NOC MASTER */
	reg_write32(bus_set, MLU580_IPUBAR01_IPU0_0_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR01_IPU0_0_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR00_IPU0_1_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR00_IPU0_1_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR20_IPU1_0_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR20_IPU1_0_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR21_IPU1_1_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR21_IPU1_1_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR01_IPU2_0_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR01_IPU2_0_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR00_IPU2_1_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR00_IPU2_1_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR30_IPU3_0_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR30_IPU3_0_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR31_IPU3_1_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR31_IPU3_1_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR11_IPU4_0_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR11_IPU4_0_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR10_IPU4_1_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR10_IPU4_1_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR30_IPU5_0_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR30_IPU5_0_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR31_IPU5_1_M0,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, MLU580_IPUBAR31_IPU5_1_M1,  MLU580_NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);

	return;
}

/*
 *Need config below reg in this func.
 *1. ddr and llc capatinity and sw reset.
 *2. llc system reset and init(the llc slice will config in arm boot).
 *3. address interleave and shuffle.
 *4. outstanding and other noc config.
 */
int gddr_init_mlu580(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = NULL;
	int ret = 0;

	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "memory ctrl set is null");
		return -EINVAL;
	}

	core = (struct cn_core_set *)mcc_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_core_err(core, "core set is null");
		return -EINVAL;
	}

	mlu580_hbm_capacity_info(mcc_set);

	if(mlu580_mem_mask_info(mcc_set)) {
		return -EINVAL;
	}

	/* NOTE: cfg_llc_ddr_size depends by inlineECC status, we must get inlineECC status before llc init */
	mlu580_get_ile_status(core);

	mlu580_memsys_config_default(mcc_set);

	cambr_mcc_module_param_res_create();
	mlu580_memsys_config_parse_param(mcc_set);
	mlu580_llc_compress_config_parse_param(mcc_set);

	mlu580_llc_interleave_and_shuffle_set(core->bus_set);
	mlu580_noc_data_crl_set(core->bus_set);

	/* memsys & llc init */
	mlu580_hbm_llc_init(core->bus_set);

	ret = mlu580_ddr_ecc_info_init(core->bus_set);
	if (ret) return ret;

	mcc_set->mcc_ops = &hbm_ops_mlu580;

	mcc_set->d2dc_status = NULL;
	mcc_set->ecc_status =
		cn_kcalloc(MLU580_A6_MEMG_CHANNEL_COUNT, sizeof(struct ecc_info_t),
				GFP_KERNEL);
	if (!mcc_set->ecc_status) {
		cn_dev_core_err(core, "malloc for ecc struct fail");
		return -ENOMEM;
	}
	memset(mcc_set->ecc_status, 0,
			MLU580_A6_MEMG_CHANNEL_COUNT * sizeof(struct ecc_info_t));

	return 0;
}

