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
#include "mlu590_hbm_data.h"
#include "module_param.h"
#include "cndrv_kwork.h"

/* name length */
#define MAX_STRING_LEN                    (32)

/*UMC CONFIG*/
#define HBM_CORE_ADDR(i) ((i < 3) ? (0x200000 + (i * 0x200000)) : (0xA00000 + ((i - 3) * 0x200000)))
#define HBM_CORE_CSR(i)		((HBM_CORE_ADDR(i)) + 0x10000)
#define UMC_ADDR_BASE(i, j)	((HBM_CORE_ADDR(i)) + 0x30000 + (j * 0x10000))
#define UMC_SELF_REFRESH        (0x45d8)
#define UMC_SELF_REFRESH_STATUS (0x45dc)
/* type:0 -- 1bit; type:1 -- 2bit */
#define UMC_ECC_INJECT(type)    (0x680c + (type) * 0x4)

/* --------- MAILBOX CONFIG -------- */
#define MLU590_PERI_MCU_MAILBOX_PCIE_IRQ (371)
#define PERI_MAILBOX1_BASE (0x928000)
#define MAILBOX_INT_STATUS0 (0x00)
#define MAILBOX_INT_STATUS1 (0x04)
#define MAILBOX_CH0_INFO    (0x08)
/* Support CH0 ~ CH31 */
#define MAILBOX_CH_INFO(ch) (MAILBOX_CH0_INFO + (ch) * 0x4)

#define SMMU_BUSY_WAIT_TIMEOUT_MS (100)

#define backlist_for_next(pos, back_list)	\
		for (pos = __ffs(back_list); back_list > 0; \
					back_list &= ~(1 << pos), pos = __ffs(back_list))

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

static unsigned int __mlu590_hbm_mask_to_llc_mask(struct cn_core_set *core, unsigned int hbm_mask)
{
	unsigned int hbm_id = 0;
	unsigned int llc_mask = 0;
	unsigned int mask = (core->board_info.platform == MLU_PLAT_FPGA) ? 0x2 : 0x3;

	for_each_set_bit(hbm_id, (unsigned long *)&hbm_mask, 6)
		llc_mask |= (mask) << (hbm_id * 2);

	return llc_mask;
}


struct hbm_resetn_reg {
	const u32 reg_base;
} mlu590_hbm_resetn_reg[MLU590_A6_HBM_CHANNEL_COUNT] = {
	{MLU590_HBM0_DEC_RESETN_BASE},
	{MLU590_HBM1_DEC_RESETN_BASE},
	{MLU590_HBM2_DEC_RESETN_BASE},
	{MLU590_HBM3_DEC_RESETN_BASE},
	{MLU590_HBM4_DEC_RESETN_BASE},
	{MLU590_HBM5_DEC_RESETN_BASE},
};

struct llc_resetn_reg {
	const u32 reg_base;
} mlu590_llc_resetn_reg[MLU590_LLCG_CNT] = {
	{MLU590_LLCG0_RESETN_BASE},
	{MLU590_LLCG1_RESETN_BASE},
	{MLU590_LLCG2_RESETN_BASE},
	{MLU590_LLCG3_RESETN_BASE},
	{MLU590_LLCG4_RESETN_BASE},
	{MLU590_LLCG5_RESETN_BASE},
	{MLU590_LLCG6_RESETN_BASE},
	{MLU590_LLCG7_RESETN_BASE},
	{MLU590_LLCG8_RESETN_BASE},
	{MLU590_LLCG9_RESETN_BASE},
	{MLU590_LLCG10_RESETN_BASE},
	{MLU590_LLCG11_RESETN_BASE},
};

struct llc_groupconfig_reg {
	const u32 reg_base;
} mlu590_llc_groupconfig_reg[MLU590_LLCG_CNT] = {
	{MLU590_LLC_GROUP0_BASE},
	{MLU590_LLC_GROUP1_BASE},
	{MLU590_LLC_GROUP2_BASE},
	{MLU590_LLC_GROUP3_BASE},
	{MLU590_LLC_GROUP4_BASE},
	{MLU590_LLC_GROUP5_BASE},
	{MLU590_LLC_GROUP6_BASE},
	{MLU590_LLC_GROUP7_BASE},
	{MLU590_LLC_GROUP8_BASE},
	{MLU590_LLC_GROUP9_BASE},
	{MLU590_LLC_GROUP10_BASE},
	{MLU590_LLC_GROUP11_BASE},
};

/*** MLU590 PageRetire Start ***/
struct hbm_retire_set {
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

static irqreturn_t peri_mailbox_mlu590_intr_handle(int irq, void *data);

static struct {
	const char irq_name[MAX_STRING_LEN];
	const int irq;
	irqreturn_t (*isr_t)(int irq, void *data);
} peri_mailbox_mlu590_ecc_irq = {
	.irq_name = "PERI_MCU_MAILBOX_PCIE_IRQ",
	.irq      = MLU590_PERI_MCU_MAILBOX_PCIE_IRQ,
	.isr_t    = peri_mailbox_mlu590_intr_handle,
};

extern const u32 hbm_topid_to_decid[MLU590_HBM_CHANNEL_COUNT];

static void hbm_trigger_pgretire_work(struct work_struct *work)
{
	struct hbm_retire_set *retire_set = NULL;
	struct cn_mcc_set *mcc_set;
	struct cn_core_set *core;

	retire_set = container_of(work, struct hbm_retire_set, retire_work);
	if (!retire_set || !retire_set->mcc_set)
		return ;

	mcc_set = (struct cn_mcc_set *)retire_set->mcc_set;
	if (!mcc_set->core)
		return ;

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
	struct hbm_retire_set *retire_set =
		(struct hbm_retire_set *)mcc_set->repair_set;
	struct hbm_retire_info_t *info = NULL, curr = {};
	unsigned int hbm_id = 0, index = 0;

	if (!retire_set)
		return ;

	if (retire_set->retire_num >= EEPROM_MAX_NUM) {
		cn_xid_err(core, XID_ECC_ERR, "ecc irq ocur too much, out of pageretire ability");
		return;
	}

	/** irq data Format from isse M0:
	 *  Bit[31] ... Bit[28:26] .... Bit[25] ..... Bit[24:23] .... Bit[22:0]
	 *  DBE/SBE ... hbm_id[2:0] ... llcg_id[0] .. llc_id[1:0] ... llc_addr[30:8]
	 *
	 *  hbm_id in irq_info is top_id, we need translate it into decoder_id.
	 **/
	hbm_id = hbm_topid_to_decid[BITS(irq_info, 28, 26)];
	SET_BITS(curr.hbm_num, 0, 0, BITS(irq_info, 25, 25));
	SET_BITS(curr.hbm_num, 3, 1, hbm_id);
	curr.sys_num  = BITS(irq_info, 24, 23);
	curr.pmc_num  = retire_set->llc_config;
	curr.ecc_type = BITS(irq_info, 31, 31);
	curr.ecc_addr = BITS(irq_info, 22, 0) << 8;

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

static irqreturn_t peri_mailbox_mlu590_intr_handle(int irq, void *data)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)data;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int reg_base = PERI_MAILBOX1_BASE;
	unsigned int int_status = 0, info = 0;

	/* read status first */
	int_status = reg_read32(core->bus_set, reg_base + MAILBOX_INT_STATUS1);

	/* ECC error happenend */
	if (int_status & 0x1) {
		info = reg_read32(core->bus_set, reg_base + MAILBOX_CH_INFO(0));

		cn_xid_err(core, XID_ECC_ERR, "%s ECC error irq occurred, irq info: %#x",
				(BITS(info, 31, 31) == ECC_BIT_2) ? "DBE": "SBE", info);

		if (cambr_mcc_module_param_res_get(SBE_RETIRE_ENABLE) ||
				(BITS(info, 31, 31) != ECC_BIT_1)) {
			__parse_irq_info(mcc_set, info);
		}
	}

	/* clear irq status */
	reg_write32(core->bus_set, reg_base + MAILBOX_INT_STATUS1, int_status << 16);

	return IRQ_HANDLED;
}

static void
hbm_get_retire_info(void *mset, struct hbm_retire_info_t **retire_info,
		unsigned int *retire_num, int irq_flag)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_retire_set *retire_set;

	if (retire_num)
		*retire_num = 0;

	retire_set = (struct hbm_retire_set *)mcc_set->repair_set;
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
		/* mlu590 not need do pagretire during driver load */
		*retire_info = NULL;
		*retire_num = 0;
	}
}

static int hbm_get_retire_pages(void *mset, int cause, unsigned int *pagecount,
			u64 **page_addr)
{
	int ret = -1;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_retire_set *retire_set;

	if (pagecount)
		*pagecount = 0;

	if (cause != ECC_BIT_1 && cause != ECC_BIT_2) {
		cn_dev_core_err(core, "cause%d is invalid", cause);
		return ret;
	}

	retire_set = (struct hbm_retire_set *)mcc_set->repair_set;
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

static int hbm_get_retire_pages_pending_status(void *mset, int *ispending,
								int *isfailure)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_retire_set *retire_set =
		(struct hbm_retire_set *)mcc_set->repair_set;

	cn_mem_pgr_get_status(core, ispending, isfailure);

	if (retire_set->retire_num >= EEPROM_MAX_NUM)
		*isfailure = 1;

	return 0;
}

static int hbm_retire_switch(void *mset, int status)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_retire_set *retire_set;

	retire_set = (struct hbm_retire_set *)mcc_set->repair_set;
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
hbm_get_address_swap_info(void *mset, unsigned int *corr_rows,
				unsigned int *unc_rows, unsigned int *pending_rows,
				unsigned int *fail_rows)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int val = 0;

	val = reg_read32(core->bus_set, MLU590_IPC_4);

	cn_dev_core_debug(core, "read from register val is %#x", val);

	if (corr_rows) *corr_rows = BITS(val, 15, 0);
	if (unc_rows) *unc_rows  = BITS(val, 31, 16);
	if (fail_rows) *fail_rows = 0;
	if (pending_rows) {
		unsigned int retired_pages = 0;

		*pending_rows = 0;

		hbm_get_retire_pages(mcc_set, ECC_BIT_1, &retired_pages, NULL);
		*pending_rows += retired_pages;

		hbm_get_retire_pages(mcc_set, ECC_BIT_2, &retired_pages, NULL);
		*pending_rows += retired_pages;
	}

	return 0;
}

static int
__inject_hbm_ecc_irq(struct cn_mcc_set *mcc_set, unsigned int hbm_id,
		unsigned int chl_id, unsigned int type)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int reg_base = UMC_ADDR_BASE(hbm_id, chl_id);

	cn_dev_core_info(core, "ready to inject ecc in HBM:%d, chl:%d, type:%d",
				hbm_id, chl_id, type);

	/* 1. enable sr */
	reg_write32(core->bus_set, reg_base + UMC_SELF_REFRESH, 1);
	cn_bus_mb(core->bus_set);
	reg_read32_and_wait(core->bus_set, reg_base + UMC_SELF_REFRESH_STATUS, 0x1);

	/* 2. trigger ecc error */
	reg_write32(core->bus_set, reg_base + UMC_ECC_INJECT(type), 1);
	cn_bus_mb(core->bus_set);

	/* 3. disable sr */
	reg_write32(core->bus_set, reg_base + UMC_SELF_REFRESH, 0);
	cn_bus_mb(core->bus_set);
	reg_read32_and_wait(core->bus_set, reg_base + UMC_SELF_REFRESH_STATUS, 0x0);

	return 0;
}

static int hbm_ecc_irq_inject(void *mset, u32 sys_mc_num,
				u32 mc_state, u32 ecc_addr)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_retire_set *retire_set;
	unsigned long ecc_addr_bound = 0;
	int input_top_hbm_id = 0, bad_top_hbm_id = 0;
	unsigned int inject_value = 0, llcg_id = 0, llc_id = 0;
	unsigned int reg_base = 0;

	retire_set = (struct hbm_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "retire_set is NULL");
		return -EINVAL;
	}

	ecc_addr_bound =
		1UL << (30 + mcc_set->msys_config.mlu590.hbm_capacity);

	if ((sys_mc_num >= (MLU590_A6_HBM_CHANNEL_COUNT * 8)) || mc_state > 2 ||
		ecc_addr > ecc_addr_bound) {
		cn_dev_core_info(core, "Invalid parameters input! Each paramter valid ranges:");
		cn_dev_core_info(core, "sys_mc_num: 0 ~ %d, mc_state: 0 or 1, ecc_addr: 0 ~ %#lx",
						 MLU590_A6_HBM_CHANNEL_COUNT * 8, ecc_addr_bound);
		return 0;
	}

	bad_top_hbm_id = reg_read32(core->bus_set, MLU590_CFG);
	bad_top_hbm_id = BITS(bad_top_hbm_id, 14, 12);
	input_top_hbm_id = BITS(sys_mc_num, 5, 3);

	if (input_top_hbm_id == bad_top_hbm_id) {
		cn_dev_core_err(core, "input sys_mc_num(%d) pointer to bad hbm id",
					sys_mc_num);
		return 0;
	}

	if (ecc_addr_bound == ecc_addr) {
		cn_dev_core_info(core, "Debug mode, next access will inject ecc irq");
		__inject_hbm_ecc_irq(mcc_set, input_top_hbm_id, BITS(sys_mc_num, 2, 0), mc_state & 0x1);
		return 0;
	}

	llc_id   = BITS(sys_mc_num, 1, 0);
	llcg_id  = BITS(sys_mc_num, 5, 2);
	SET_BITS(inject_value, 31, 31, mc_state & 0x1);
	SET_BITS(inject_value, 28, 25, llcg_id);
	SET_BITS(inject_value, 24, 23, llc_id);
	SET_BITS(inject_value, 22, 0, ((ecc_addr >> 8) & ((1UL << 23) - 1)));

	reg_base = HBM_CORE_ADDR(input_top_hbm_id);

	reg_write32(core->bus_set, reg_base + 0xF00A0, inject_value);
	cn_bus_mb(core->bus_set);
	reg_write32(core->bus_set, reg_base + 0xF0048, 0x10001);
	cn_bus_mb(core->bus_set);
	return 0;
}

static int hbm_get_sys_mc_nums(void *mset, unsigned int *sys_mc_num)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	if (!sys_mc_num) {
		cn_dev_core_err(core, "input sys_mc_num buffer is null");
		return -EINVAL;
	}

	*sys_mc_num = MLU590_HBM_NUM_MAX * 8;

	return 0;
}

static const struct cn_repair_ops hbm_retire_ops_mlu590 = {
	.get_retire_info = hbm_get_retire_info,
	.get_retire_pages = hbm_get_retire_pages,
	.get_retire_pages_pending_status = hbm_get_retire_pages_pending_status,
	.get_remapped_rows = hbm_get_address_swap_info,
	.retire_switch = hbm_retire_switch,
	.ecc_irq_inject = hbm_ecc_irq_inject,
	/* Debug mode current not support */
	.get_eeprom_switch = NULL,
	.get_eeprom_info = NULL,
	.get_sys_mc_nums = hbm_get_sys_mc_nums,
};

int mlu590_hbm_ecc_info_init(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_retire_set *retire_set = NULL;
	int ret = 0;

	ret = cn_bus_register_interrupt(core->bus_set,
				peri_mailbox_mlu590_ecc_irq.irq,
				peri_mailbox_mlu590_ecc_irq.isr_t, (void *)mcc_set);
	if (ret) {
		cn_dev_core_err(core, "register hbm ecc irq isr error");
		return -EINVAL;
	}

	ret = cn_bus_enable_irq(core->bus_set, peri_mailbox_mlu590_ecc_irq.irq);
	if (ret) {
		cn_dev_core_err(core, "enable hbm ecc irq isr error");
		cn_bus_unregister_interrupt(core->bus_set,
				peri_mailbox_mlu590_ecc_irq.irq);
		return -EINVAL;
	}

	retire_set = cn_kzalloc(sizeof(struct hbm_retire_set), GFP_KERNEL);
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
	mcc_set->repair_ops = &hbm_retire_ops_mlu590;
	return 0;

failed_create_buf:
	/* release mlu590 peri mailbox ecc irq */
	cn_bus_disable_irq(core->bus_set, peri_mailbox_mlu590_ecc_irq.irq);
	cn_bus_unregister_interrupt(core->bus_set, peri_mailbox_mlu590_ecc_irq.irq);
	return ret;
}

void mlu590_hbm_ecc_info_exit(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_retire_set *retire_set =
		(struct hbm_retire_set *)mcc_set->repair_set;
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

	cn_bus_disable_irq(core->bus_set, peri_mailbox_mlu590_ecc_irq.irq);
	cn_bus_unregister_interrupt(core->bus_set, peri_mailbox_mlu590_ecc_irq.irq);
}
/*** MLU590 PageRetire End ***/

void hbm_exit_mlu590(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;

	/* release mlu590 peri mailbox ecc irq */
	mlu590_hbm_ecc_info_exit(mcc_set);

	if (mcc_set->ecc_status) {
		cn_kfree(mcc_set->ecc_status);
	}
}

void get_map_mode_mlu590(void *mset, unsigned int *map_mode,
						 unsigned int *hbm_idx)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int hbm_num;
	unsigned int hbm_bitmap;
	unsigned int hbm_mem_channel =
		cambr_mcc_module_param_res_get(HBM_MEM_CHANNEL);

	hbm_bitmap = mcc_set->msys_config.mlu590.hbm_bitmap;
	hbm_num = mcc_set->msys_config.mlu590.hbm_nums;
	hbm_mem_channel = hbm_mem_channel % MLU590_A6_HBM_CHANNEL_COUNT;

	*map_mode = mcc_set->msys_config.mlu590.llcg_interleave_mode & 0x3;

	switch (hbm_num) {
	case MLU590_A6_HBM_CHANNEL_COUNT:
		if (*map_mode == LLCG_INTERLEAVE_MAP2) {
			unsigned int tmp_group;
			tmp_group = hbm_mem_channel / 2;
			hbm_mem_channel = tmp_group * 2;
		}
		*hbm_idx = hbm_mem_channel;
		break;
	case MLU590_A5_HBM_CHANNEL_COUNT:
		if (*map_mode == LLCG_INTERLEAVE_MAP1) {
			if (((0x1 << hbm_mem_channel) & MLU590_HBM_BITMAP) ==
				(~(hbm_bitmap) & MLU590_HBM_BITMAP)) {
				cn_dev_core_info(core, "a5 change hbm_mem_channel %d",
								 hbm_mem_channel);
				hbm_mem_channel = (hbm_mem_channel + 1) % MLU590_A6_HBM_CHANNEL_COUNT;
				cn_dev_core_info(core, "a5 change hbm_mem_channel %d",
								 hbm_mem_channel);
			}
			*hbm_idx = hbm_mem_channel;
		} else if (*map_mode == LLCG_INTERLEAVE_MAP2) {
			unsigned int tmp_group;
			unsigned int tmp_group2;
			tmp_group = hbm_mem_channel / 2;
			tmp_group2 = __ffs(~(hbm_bitmap) & MLU590_HBM_BITMAP) / 2;

			cn_dev_core_info(core, "a5 dump group1 %d group2 %d", tmp_group,
							 tmp_group2);
			if (tmp_group == tmp_group2) {
				tmp_group = (tmp_group + 1) % (MLU590_A6_HBM_CHANNEL_COUNT / 2);
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
	case MLU590_A3_HBM_CHANNEL_COUNT:
		if (*map_mode == LLCG_INTERLEAVE_MAP1) {
			if (((0x1 << hbm_mem_channel) & MLU590_HBM_BITMAP) &
				(~(hbm_bitmap) & MLU590_HBM_BITMAP)) {
				cn_dev_core_info(core, "a3 need change hbm_mem_channel %d",
								 hbm_mem_channel);
hbm_a3_map1_check:
				hbm_mem_channel = (hbm_mem_channel + 1) % MLU590_A6_HBM_CHANNEL_COUNT;
				cn_dev_core_info(core, "a3 need change new hbm_mem_channel %d",
								 hbm_mem_channel);
				if (((0x1 << hbm_mem_channel) & MLU590_HBM_BITMAP) &
					(~(hbm_bitmap) & MLU590_HBM_BITMAP))
					goto hbm_a3_map1_check;
			}
			*hbm_idx = hbm_mem_channel;
		} else if (*map_mode == LLCG_INTERLEAVE_MAP2) {
			unsigned int tmp_group;
			unsigned int tmp_group2;
			unsigned int tmp_bitmap;
			tmp_group = hbm_mem_channel / 2;
			tmp_bitmap = (~((hbm_bitmap) | (0x3 << 2)) & MLU590_HBM_BITMAP);/*get bad hbm idx*/
			tmp_group2 = __ffs(tmp_bitmap) / 2;
			cn_dev_core_info(core, "a3 dump group1 %d group2 %d", tmp_group,
							 tmp_group2);

			if (tmp_group == tmp_group2 || tmp_group == 0x1) {
hbm_a3_map2_check:
				tmp_group = (tmp_group + 1) % (MLU590_A6_HBM_CHANNEL_COUNT / 2);
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

void get_mem_limit_coef_mlu590(void *mset, unsigned int *limit_coef)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	*limit_coef = mcc_set->msys_config.mlu590.hbm_mem_size_limit;

	cn_dev_core_info(core, "limit mem size %dGB >> %d",
	 (mcc_set->msys_config.mlu590.hbm_capacity == HBM_CAPACITY_SIZE_16G)
			? 16 : 8, *limit_coef);

	return;
}

void dump_llc_state_mlu590(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct cn_bus_set *bus_set = core->bus_set;
	unsigned int hbm_bitmap, llcg_bitmap;
	unsigned int offset[4] = {0x0, 0x1000, 0x4000, 0x5000};
	int index, i;
	unsigned int llc_cf_base;

	hbm_bitmap = mcc_set->msys_config.mlu590.hbm_bitmap;
	llcg_bitmap = __mlu590_hbm_mask_to_llc_mask(core, hbm_bitmap);

	backlist_for_next(index, llcg_bitmap) {
		llc_cf_base = mlu590_llc_groupconfig_reg[index].reg_base;
		for (i = 0; i < 4; i++) {
			cn_dev_core_info(core, "llcg %d dump addr %x", index,
							 llc_cf_base + offset[i]);
				cn_dev_core_info(core, "dump offset 0x334 val %x,  0x338 val %x, 0x33c val %x",
					reg_read32(bus_set, llc_cf_base + offset[i] + 0x334),
					reg_read32(bus_set, llc_cf_base + offset[i] + 0x338),
					reg_read32(bus_set, llc_cf_base + offset[i] + 0x33c));
		}
	}

	return;
}

void get_compress_info_mlu590(void *mset, unsigned int *compress_en,
				unsigned int *compress_mode, unsigned int *compress_high_mode)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int llc_compress_high_mode;

	*compress_en = mcc_set->msys_config.mlu590.llc_compress_dis;

	if (mcc_set->msys_config.mlu590.llc_compress_mode != LLC_ND_INTERLEAVE_COMPRESS) {
		*compress_mode = mcc_set->msys_config.mlu590.llc_compress_mode;
	} else {
		if (mcc_set->msys_config.mlu590.hbm_capacity == HBM_CAPACITY_SIZE_16G) {
			*compress_mode = LLC_LOW_INTERLEAVE_COMPRESS;
		} else {
			*compress_mode = LLC_HIGH_INTERLEAVE_COMPRESS;
		}
	}

	llc_compress_high_mode = cambr_mcc_module_param_res_get(LLC_COMPRESS_HIGH_MODE);
	if (llc_compress_high_mode != LLC_COMPRESS_HIGH_MODE_ALL) {
		*compress_high_mode = mcc_set->msys_config.mlu590.llc_compress_high_mode;
	} else {
		if (*compress_mode == LLC_HIGH_INTERLEAVE_COMPRESS &&
			mcc_set->msys_config.mlu590.hbm_capacity == HBM_CAPACITY_SIZE_16G) {
			*compress_high_mode = LLC_COMPRESS_HIGH_MODE_HIGH;
		} else {
			*compress_high_mode = LLC_COMPRESS_HIGH_MODE_LOW;
		}
	}

	cn_dev_core_info(core, "mlu590 compress en [%d/%s] mode [%d/%s] addr off [%d/%s]",
					 *compress_en, comp_mode_en[*compress_en], *compress_mode,
					 comp_mode_mode[*compress_mode], *compress_high_mode,
					 comp_high_mode[*compress_high_mode]);
	return;
}

int ddr_get_channel_num_mlu590(void *mset)
{
	return MLU590_A6_HBM_CHANNEL_COUNT;
}

void *ddr_get_ecc_status_mlu590(void *mset)
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
	reg32 = cn_mcu_read32(core_set, MLU590_IPC_6);

	ecc_info = ((struct ecc_info_t *)mcc_set->ecc_status);
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
static const struct cn_mcc_ops hbm_ops_mlu590 = {
	.get_channel_num = ddr_get_channel_num_mlu590,
	.get_ecc_status = ddr_get_ecc_status_mlu590,
	.get_map_mode = get_map_mode_mlu590,
	.get_compress_info = get_compress_info_mlu590,
	.get_mem_limit_coef = get_mem_limit_coef_mlu590,
	.dump_llc_state = dump_llc_state_mlu590,
	.mcc_exit = hbm_exit_mlu590,
	.repair_exit = NULL,
	.get_d2dc_num = NULL,
	.get_d2dc_status = NULL,
};

static inline void mlu590_config_llc_slice(void *bus_set, unsigned int llc_slice_base)
{
	struct cn_core_set *core = ((struct cn_bus_set *)bus_set)->core;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	unsigned int compress_space_value = 0;
	unsigned int compress_space_mask = 0;
	unsigned int cfg_llc_comp_addr_map_value = 0;
	unsigned int cfg_llc_comp_addr_map_mask = 0;

	/* do config LLC_HBM_SIZE: 8G as 0, and 16G as 1 */
	reg_write32(bus_set, llc_slice_base + 0xf0, mcc_set->msys_config.mlu590.hbm_capacity);

	/*pool state for work*/
	reg_read32_and_wait(bus_set, llc_slice_base + 0xc0, 0x0);

	if (mcc_set->msys_config.mlu590.llc_compress_dis == CONFIG_DISABLE) {
		reg_write32(bus_set, llc_slice_base + 0xb0, 0x0);
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
			if (mcc_set->msys_config.mlu590.hbm_capacity == HBM_CAPACITY_SIZE_16G) {
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
		if (mcc_set->msys_config.mlu590.hbm_capacity == HBM_CAPACITY_SIZE_16G) {
			/*low interweave*/
			compress_space_mask = 0x1fffff;
			compress_space_value = 0;
			cfg_llc_comp_addr_map_value = 0x0;
			cfg_llc_comp_addr_map_mask = 0x1;
			cn_dev_core_debug(core, "compress is set low interweave.");
		} else {
			/*high interweave use top addr*/
			compress_space_mask = 0x0;
			compress_space_value = 0x1;
			cfg_llc_comp_addr_map_value = 0x0;
			cfg_llc_comp_addr_map_mask = 0x1fffff;
			cn_dev_core_debug(core, "compress is set high interweave use top addr");
		}
	}

	reg_write32(bus_set, llc_slice_base + 0xd4,
				compress_space_value << 24 | compress_space_mask);

	reg_write32(bus_set, llc_slice_base + 0x128, cfg_llc_comp_addr_map_value);
	reg_write32(bus_set, llc_slice_base + 0x12c, cfg_llc_comp_addr_map_mask);

	/* vdk set llc non allocate */
	if (core->board_info.platform == MLU_PLAT_VDK) {
		reg_write32(bus_set, llc_slice_base + 0x7c, 0x1);
	}

	cn_dev_core_debug(core, "set reg: mode %x value %x mask %x",
					 reg_read32(bus_set, llc_slice_base + 0xd4),
					 reg_read32(bus_set, llc_slice_base + 0x128),
					 reg_read32(bus_set, llc_slice_base + 0x12c));
}

static void mlu590_config_llc_sys(void *bus_set, unsigned int llc_sys_base)
{
	u32 reg_val = 0x0;

	usleep_range(2000, 3000);//2ms
	reg_write32(bus_set, llc_sys_base + 0x2020, 0x1ff);
	reg_read32(bus_set, llc_sys_base + 0x2020);
	usleep_range(2000, 3000);//2ms
	reg_write32(bus_set, llc_sys_base + 0x2028, 0x0);
	reg_read32(bus_set, llc_sys_base + 0x2028);
	usleep_range(2000, 3000);//2ms

	reg_val = reg_read32(bus_set, llc_sys_base + 0x201c);
	reg_val |= (0x5 << 12);
	reg_write32(bus_set, llc_sys_base + 0x201c, reg_val);

	reg_val = reg_read32(bus_set, llc_sys_base + 0x2028);
	reg_val |= (0x3 << 6);
	reg_write32(bus_set, llc_sys_base + 0x2028, reg_val);

	/*Now config slice in dev module*/

	reg_val |= (0x3 << 4);
	reg_write32(bus_set, llc_sys_base + 0x2028, reg_val);
	reg_val |= (0x3 << 0);
	reg_write32(bus_set, llc_sys_base + 0x2028, reg_val);
	reg_val |= (0x3 << 2);
	reg_write32(bus_set, llc_sys_base + 0x2028, reg_val);
	reg_val |= (0x1 << 8);
	reg_write32(bus_set, llc_sys_base + 0x2028, reg_val);

	/*Enable LPC in default*/
	reg_val = 0x7;
	reg_write32(bus_set, llc_sys_base + 0x202c, reg_val);

	mlu590_config_llc_slice(bus_set, llc_sys_base);
	mlu590_config_llc_slice(bus_set, llc_sys_base + 0x1000);

	return;
}

/*
 *NOTE: config llc groups by group mask get from mcu info.
 */
static void mlu590_mem_mask_info(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	mcc_set->msys_config.mlu590.hbm_nums = core->board_info.hbm_cnt; /*3: A3, 5: A5, 6: A6*/

	mcc_set->msys_config.mlu590.hbm_bitmap = core->board_info.hbm_mask;

	cn_dev_core_info(core, "HBM NUMS %d HBM BIT MAP %x", mcc_set->msys_config.mlu590.hbm_nums,
					mcc_set->msys_config.mlu590.hbm_bitmap);
}

static void mlu590_hbm_capacity_info(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	/*1: single hbm size 16GB, 0: single hbm size 8GB*/
	cn_dev_core_info(core, "HBM CAPACITY %xGB", core->board_info.ddr_cap);
	if (core->board_info.ddr_cap == 0x10) {
		mcc_set->msys_config.mlu590.hbm_capacity = HBM_CAPACITY_SIZE_16G;
	} else if (core->board_info.ddr_cap == 0x8) {
		mcc_set->msys_config.mlu590.hbm_capacity = HBM_CAPACITY_SIZE_8G;
	} else {
		cn_dev_core_err(core, "Get HBM CAPACITY %xGB is invalid", core->board_info.ddr_cap);
	}
}

static void mlu590_hbm_llc_init(void *bus_set)
{
	struct cn_core_set *core = ((struct cn_bus_set *)bus_set)->core;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	unsigned int hbm_bitmap, llcg_bitmap;
	unsigned int hbm_rt_base, llc_rt_base, llc_cf_base;
	int index;

	hbm_bitmap = mcc_set->msys_config.mlu590.hbm_bitmap;
	llcg_bitmap = __mlu590_hbm_mask_to_llc_mask(core, hbm_bitmap);

	backlist_for_next(index, hbm_bitmap) {
		/*reset hbm*/
		hbm_rt_base = mlu590_hbm_resetn_reg[index].reg_base;
		cn_dev_core_debug(core, "hbm %d reset base %x", index, hbm_rt_base);
		reg_write32(bus_set, hbm_rt_base, MLU590_HBM_RESETN_MASK);  //HBM_SYS5
	}

	backlist_for_next(index, llcg_bitmap) {
		/*reset llc*/
		llc_rt_base = mlu590_llc_resetn_reg[index].reg_base;
		cn_dev_core_debug(core, "llcg %d reset sys0 base %x sys1 base %x", index,
						 llc_rt_base, llc_rt_base + MLU590_LLC_SYS_RESETN_OFF);
		reg_write32(bus_set, llc_rt_base, MLU590_LLCG_RESETN_MASK);
		reg_write32(bus_set, llc_rt_base + MLU590_LLC_SYS_RESETN_OFF, MLU590_LLCG_RESETN_MASK);

		usleep_range(1000, 1050);//1ms
		/*config llc*/
		llc_cf_base = mlu590_llc_groupconfig_reg[index].reg_base;
		cn_dev_core_debug(core, "llcg %d config sys0 base %x sys1 base %x", index,
						 llc_cf_base, llc_cf_base + MLU590_LLC_SYS_CONFIG_OFF);
		mlu590_config_llc_sys(bus_set, llc_cf_base);
		mlu590_config_llc_sys(bus_set, llc_cf_base + MLU590_LLC_SYS_CONFIG_OFF);
	}

	return;
}

static void mlu590_memsys_read_config_default(struct cn_mcc_set *mcc_set)
{
#define VAL(reg, name) BITS_MASK(reg, MLU590_SYSCTRL_##name##_MASK, MLU590_SYSCTRL_##name##_OFF)
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct cn_bus_set *bus_set = core->bus_set;
	unsigned int reg_val;

	reg_val = reg_read32(bus_set, MLU590_SYSCTRL_ADDRESS_MAP);
	mcc_set->msys_config.mlu590.shuffle_dis = !VAL(reg_val, SHUFFLE);
	cn_dev_core_info(core, "mlu590 llc group shuffle is %s",
					 llc_mode_en[mcc_set->msys_config.mlu590.shuffle_dis]);
	mcc_set->msys_config.mlu590.interleave_size = VAL(reg_val, INTERLEAVING_SIZE);
	cn_dev_core_info(core, "mlu590 llc group interleave size is %d B",
					 (0x1 << mcc_set->msys_config.mlu590.interleave_size) * 512);
	mcc_set->msys_config.mlu590.llc_interleave_mode = VAL(reg_val, LLC_INTERLEAVING_MODE);
	cn_dev_core_info(core, "mlu590 llc interleave mode is %s",
					 llc_interleave_mode_name[mcc_set->msys_config.mlu590.llc_interleave_mode]);
	mcc_set->msys_config.mlu590.llc_interleave_size = VAL(reg_val, LLC_INTERLEAVING_SIZE);
	cn_dev_core_info(core, "mlu590 llc interleave size is %d B",
					 (0x1 << mcc_set->msys_config.mlu590.llc_interleave_size) * 512);
	mcc_set->msys_config.mlu590.llc_shuffle_dis = !VAL(reg_val, LLC_SHUFFLE);
	cn_dev_core_info(core, "mlu590 llc shuffle is %s",
					 llc_mode_en[mcc_set->msys_config.mlu590.llc_shuffle_dis]);

	mcc_set->msys_config.mlu590.sp_interleave_en = VAL(reg_val, SP_INTERLEAVING);

	mcc_set->msys_config.mlu590.llcg_interleave_mode = LLCG_INTERLEAVE_MAP3;
	cn_dev_core_info(core, "mlu590 llcg_interleave_mode is %d",
					 mcc_set->msys_config.mlu590.llcg_interleave_mode);
#undef VAL
}

/*Get interleave set from module param*/
static void mlu590_memsys_config_parse_param(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct memsys_config_st *config = &mcc_set->msys_config;

	unsigned int llcg_shuffle_dis =	cambr_mcc_module_param_res_get(LLCG_SHUFFLE_DIS);
	unsigned int llcg_interleave_size =	cambr_mcc_module_param_res_get(LLCG_INTERLEAVE_SIZE);
	unsigned int llc_interleave_mode = cambr_mcc_module_param_res_get(LLC_INTERLEAVE_MODE);
	unsigned int llc_shuffle_dis = cambr_mcc_module_param_res_get(LLC_SHUFFLE_DIS);
	unsigned int llc_interleave_size = cambr_mcc_module_param_res_get(LLC_INTERLEAVE_SIZE);
	unsigned int llcg_interleave_mode =	cambr_mcc_module_param_res_get(LLCG_INTERLEAVE_MODE);
	unsigned int hbm_mem_channel = cambr_mcc_module_param_res_get(HBM_MEM_CHANNEL);
	unsigned int hbm_mem_size_limit = cambr_mcc_module_param_res_get(HBM_SIZE_LIMIT_COEF);

	cn_dev_core_info(core, "mlu590 llc config module param:");
	cn_dev_core_info(core, "llcg shuffle disable %d llcg interleave size %d "
					 "llc interleave mode %d llc shuffle disable %d llc interleave size %d",
					 llcg_shuffle_dis, llcg_interleave_size,
					 llc_interleave_mode, llc_shuffle_dis, llc_interleave_size);

	cn_dev_core_info(core, "llcg interleave %d hbm idx %d",
					 llcg_interleave_mode, hbm_mem_channel);

	if (llcg_interleave_mode != config->mlu590.llcg_interleave_mode) {
		config->mlu590.llcg_interleave_mode = llcg_interleave_mode;
		cn_dev_core_info(core, "mlu590 llcg interleave mode is %s",
						 llcg_interleave_mode_name[config->mlu590.llcg_interleave_mode]);
	}

	if (llcg_shuffle_dis != config->mlu590.shuffle_dis) {
		config->mlu590.shuffle_dis = llcg_shuffle_dis;
		cn_dev_core_info(core, "mlu590 llc group shuffle is %s", llc_mode_en[config->mlu590.shuffle_dis]);
	}

	if (llcg_interleave_size != config->mlu590.interleave_size) {
		config->mlu590.interleave_size = llcg_interleave_size;
		cn_dev_core_info(core, "mlu590 llc group interleave size is %d B",
						 (0x1 << config->mlu590.interleave_size) * 512);
	}

	if (llc_interleave_mode != config->mlu590.llc_interleave_mode) {
		config->mlu590.llc_interleave_mode = llc_interleave_mode;
		cn_dev_core_info(core, "mlu590 llc interleave mode is %s",
						 llc_interleave_mode_name[config->mlu590.llc_interleave_mode]);
	}

	if (llc_shuffle_dis != config->mlu590.llc_shuffle_dis) {
		config->mlu590.llc_shuffle_dis = llc_shuffle_dis;
		cn_dev_core_info(core, "mlu590 llc shuffle is %s", llc_mode_en[config->mlu590.llc_shuffle_dis]);
	}

	if (llc_interleave_size != config->mlu590.llc_interleave_size) {
		config->mlu590.llc_interleave_size = llc_interleave_size;
		cn_dev_core_info(core, "mlu590 llc group interleave size is %d B",
						 (0x1 << config->mlu590.llc_interleave_size) * 512);
	}

	if (hbm_mem_size_limit > MM_SIZE_LIMIT4) {
		hbm_mem_size_limit = MM_SIZE_LIMIT4;
	}
	if (hbm_mem_size_limit == MM_SIZE_LIMIT4 &&
		config->mlu590.hbm_capacity == HBM_CAPACITY_SIZE_8G) {
		hbm_mem_size_limit = MM_SIZE_LIMIT3;
	}

	config->mlu590.hbm_mem_size_limit = hbm_mem_size_limit;
}

////u32 llc_groupconfig_reg[12] = {
//	MLU590_LLC_GROUP0_BASE,
//	MLU590_LLC_GROUP1_BASE,
//	MLU590_LLC_GROUP2_BASE,
//	MLU590_LLC_GROUP3_BASE,
//	MLU590_LLC_GROUP4_BASE,
//	MLU590_LLC_GROUP5_BASE,
//	MLU590_LLC_GROUP6_BASE,
//	MLU590_LLC_GROUP7_BASE,
//	MLU590_LLC_GROUP8_BASE,
//	MLU590_LLC_GROUP9_BASE,
//	MLU590_LLC_GROUP10_BASE,
//	MLU590_LLC_GROUP11_BASE,
//};
//
//static void mlu590_llc_dump(void* bus_set)
//{
//	struct cn_core_set *core = ((struct cn_bus_set *)bus_set)->core;
//	unsigned int hbm_nums, hbm_bad_mask, hbm_bitmap, llcg_bitmap;
//	unsigned int offset[4] = {0x0, 0x1000, 0x4000, 0x5000};
//	int index, i;
//
//	hbm_nums = core->board_info.hbm_cnt; /*3: A3, 5: A5, 6: A6*/
//
//	if (hbm_nums == 5) {
//		hbm_bad_mask = core->board_info.bad_hbm_mask;/*use bit to represent hbm idx*/
//	} else if (hbm_nums == 3) {
//		hbm_bad_mask = core->board_info.bad_hbm_mask;
//		hbm_bad_mask |= ((0x1 << 2) | (0x1 << 3));
//	} else {
//		hbm_bad_mask = 0;/*use bit to represent hbm idx*/
//	}
//
//	hbm_bitmap = 0x3f & (~(hbm_bad_mask));
//	llcg_bitmap = __mlu590_hbm_mask_to_llc_mask(core, hbm_bitmap);
//
//	cn_dev_core_info(core, "HBM NUMS %d HBM BIT MAP %x", hbm_nums, hbm_bitmap);
//
//	backlist_for_next(index, llcg_bitmap) {
//		for (i = 0; i < 4; i++) {
//			cn_dev_core_info(core, "llcg %d dump addr %x", index,
//							 llc_groupconfig_reg[index] + offset[i]);
//				cn_dev_core_info(core, "dump offset 0x334 val %x,  0x338 val %x, 0x33c val %x",
//					reg_read32(bus_set, llc_groupconfig_reg[index] + offset[i] + 0x334),
//					reg_read32(bus_set, llc_groupconfig_reg[index] + offset[i] + 0x338),
//					reg_read32(bus_set, llc_groupconfig_reg[index] + offset[i] + 0x33c));
//		}
//	}
//}

static void mlu590_llc_interleave_and_shuffle_set(void* bus_set)
{
	struct cn_core_set *core = ((struct cn_bus_set *)bus_set)->core;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	unsigned int reg_val;

	reg_val = reg_read32(bus_set, MLU590_SYSCTRL_ADDRESS_MAP);

	reg_val &= ~(MLU590_SYSCTRL_SHUFFLE_MASK << MLU590_SYSCTRL_SHUFFLE_OFF);
	reg_val &= ~(MLU590_SYSCTRL_INTERLEAVING_SIZE_MASK << MLU590_SYSCTRL_INTERLEAVING_SIZE_OFF);
	reg_val &= ~(MLU590_SYSCTRL_LLC_INTERLEAVING_MODE_MASK << MLU590_SYSCTRL_LLC_INTERLEAVING_MODE_OFF);
	reg_val &= ~(MLU590_SYSCTRL_LLC_INTERLEAVING_SIZE_MASK << MLU590_SYSCTRL_LLC_INTERLEAVING_SIZE_OFF);
	reg_val &= ~(MLU590_SYSCTRL_LLC_SHUFFLE_MASK << MLU590_SYSCTRL_LLC_SHUFFLE_OFF);

	cn_dev_core_info(core, "set mlu590 llc interleave reg to initial val %x",
					 reg_val);

	reg_val |= (~(mcc_set->msys_config.mlu590.shuffle_dis) & MLU590_SYSCTRL_SHUFFLE_MASK) <<
		MLU590_SYSCTRL_SHUFFLE_OFF;
	reg_val |= mcc_set->msys_config.mlu590.interleave_size <<
		MLU590_SYSCTRL_INTERLEAVING_SIZE_OFF;
	reg_val |= mcc_set->msys_config.mlu590.llc_interleave_mode <<
		MLU590_SYSCTRL_LLC_INTERLEAVING_MODE_OFF;
	reg_val |= mcc_set->msys_config.mlu590.llc_interleave_size <<
		MLU590_SYSCTRL_LLC_INTERLEAVING_SIZE_OFF;
	reg_val |= (~(mcc_set->msys_config.mlu590.llc_shuffle_dis) & MLU590_SYSCTRL_LLC_SHUFFLE_MASK) <<
		MLU590_SYSCTRL_LLC_SHUFFLE_OFF;

	reg_write32(bus_set, MLU590_SYSCTRL_ADDRESS_MAP, reg_val);
	cn_dev_core_info(core, "mlu590 llc interleave set reg %x val %x",
					 MLU590_SYSCTRL_ADDRESS_MAP, reg_val);
}

static void mlu590_llc_compress_config_parse_param(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int llc_ipu_compress_dis =	cambr_mcc_module_param_res_get(LLC_IPU_COMPRESS_DIS);
	unsigned int llc_compress_mode = cambr_mcc_module_param_res_get(LLC_COMPRESS_MODE);
	unsigned int llc_compress_high_mode = cambr_mcc_module_param_res_get(LLC_COMPRESS_HIGH_MODE);

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
static void mlu590_noc_data_crl_set(void* bus_set)
{
	unsigned int reg_val;

	reg_val = reg_read32(bus_set, MLU590_SYSCTRL_NOC_DATA_CTL);
	reg_val &= ~(0x1);
	reg_write32(bus_set, MLU590_SYSCTRL_NOC_DATA_CTL, reg_val);

	reg_write32(bus_set, NOC_DATA_MIDDLE01_RD1 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE01_RD2 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE01_RD0 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE01_RD3 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE02_RD1 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE02_RD2 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE02_RD3 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE02_RD4 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE04_RD1 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE04_RD2 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE04_RD3 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE04_RD4 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE11_RD1 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE11_RD2 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE11_RD3 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE11_RD4 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE13_RD1 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE13_RD2 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE13_RD3 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE13_RD4 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE14_RD1 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE14_RD2 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE14_RD3 + NOC_VC_NUM_TABLE0_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE14_RD4 + NOC_VC_NUM_TABLE0_OFF, 0);

	reg_write32(bus_set, NOC_DATA_MIDDLE01_RD1 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE01_RD2 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE01_RD0 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE01_RD3 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE02_RD1 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE02_RD2 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE02_RD3 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE02_RD4 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE04_RD1 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE04_RD2 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE04_RD3 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE04_RD4 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE11_RD1 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE11_RD2 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE11_RD3 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE11_RD4 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE13_RD1 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE13_RD2 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE13_RD3 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE13_RD4 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE14_RD1 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE14_RD2 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE14_RD3 + NOC_VC_NUM_TABLE1_OFF, 0);
	reg_write32(bus_set, NOC_DATA_MIDDLE14_RD4 + NOC_VC_NUM_TABLE1_OFF, 0);

	/* CONFIG ALL CLUSTER OUTSTANDING TO 128 */
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER0_RD0,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER0_RD1,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER1_RD0,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER1_RD1,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER2_RD0,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER2_RD1,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER3_RD0,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER3_RD1,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER4_RD0,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER4_RD1,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER5_RD0,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER5_RD1,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER6_RD0,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER6_RD1,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER7_RD0,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER7_RD1,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER8_RD0,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER8_RD1,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER9_RD0,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_NORTH_CLUSTER9_RD1,  NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER10_RD0, NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER10_RD1, NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER11_RD0, NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
	reg_write32(bus_set, NOC_DATA_SOUTH_CLUSTER11_RD1, NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE);
}

static void mlu590_noc_data_m2_crl_set(void* bus_set)
{

}

/*
 *Need config below reg in this func.
 *1. hbm and llc capatinity and sw reset.
 *2. llc system reset and init(the llc slice will config in arm boot).
 *3. address interleave and shuffle.
 *4. outstanding and other noc config.
 */
int hbm_llc_noc_init_mlu590(struct cn_mcc_set *mcc_set)
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

	mlu590_hbm_capacity_info(mcc_set);
	mlu590_mem_mask_info(mcc_set);

	mlu590_memsys_read_config_default(mcc_set);
	if (core->board_info.platform == MLU_PLAT_ASIC) {
		cambr_mcc_module_param_res_create();
		mlu590_memsys_config_parse_param(mcc_set);
	}

	mlu590_llc_compress_config_parse_param(mcc_set);

	mlu590_llc_interleave_and_shuffle_set(core->bus_set);
	if (core->board_info.noc_mode == NOC_MODE1) {
		mlu590_noc_data_crl_set(core->bus_set);
	} else {
		mlu590_noc_data_m2_crl_set(core->bus_set);
	}
	/* memsys & llc init */
	mlu590_hbm_llc_init(core->bus_set);

	ret = mlu590_hbm_ecc_info_init(mcc_set);
	if (ret) return ret;

	mcc_set->mcc_ops = &hbm_ops_mlu590;

	mcc_set->d2dc_status = NULL;
	mcc_set->ecc_status =
		cn_kcalloc(MLU590_A6_HBM_CHANNEL_COUNT, sizeof(struct ecc_info_t),
				GFP_KERNEL);
	if (!mcc_set->ecc_status) {
		cn_dev_core_err(core, "malloc for ecc struct fail");
		return -ENOMEM;
	}
	memset(mcc_set->ecc_status, 0,
			MLU590_A6_HBM_CHANNEL_COUNT * sizeof(struct ecc_info_t));

	return 0;
}

