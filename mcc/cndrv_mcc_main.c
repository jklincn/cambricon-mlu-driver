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
#include <linux/workqueue.h>

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_mcc.h"
#include "mcc_main.h"

void cn_mcc_get_retire_info(void *pcore, struct hbm_retire_info_t **retire_info,
			unsigned int *retire_num, int irq_flag)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcc_set *mcc_set;
	const struct cn_repair_ops *ops = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("input pcore is invalid");
		return ;
	}

	mcc_set = (struct cn_mcc_set *)core->mcc_set;
	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "mcc_set is NULL");
		return ;
	}

	ops = mcc_set->repair_ops;
	if (IS_ERR_OR_NULL(ops) || IS_ERR_OR_NULL(ops->get_retire_info)) {
		return ;
	}

	ops->get_retire_info(mcc_set, retire_info, retire_num, irq_flag);
}

int cn_mcc_get_retire_pages(void *pcore, int cause, unsigned int *pagecount,
			u64 **page_addr)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcc_set *mcc_set;
	const struct cn_repair_ops *ops = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("input pcore is invalid");
		return -EINVAL;
	}

	mcc_set = (struct cn_mcc_set *)core->mcc_set;
	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "mcc_set is NULL");
		return -EINVAL;
	}

	ops = mcc_set->repair_ops;
	if (IS_ERR_OR_NULL(ops) || IS_ERR_OR_NULL(ops->get_retire_pages)) {
		cn_dev_err("get retire_pages func null");
		return -EINVAL;
	}

	return ops->get_retire_pages(mcc_set, cause, pagecount, page_addr);
}

int cn_mcc_get_retire_pages_pending_status(void *pcore, int *ispending,
			int *isfailure)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcc_set *mcc_set;
	const struct cn_repair_ops *ops = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("input pcore is invalid");
		return -EINVAL;
	}

	mcc_set = (struct cn_mcc_set *)core->mcc_set;
	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "mcc_set is NULL");
		return -EINVAL;
	}

	ops = mcc_set->repair_ops;
	if (IS_ERR_OR_NULL(ops) ||
		IS_ERR_OR_NULL(ops->get_retire_pages_pending_status)) {
		cn_dev_err("get retire_pages_pending_status func null");
		return -EINVAL;
	}

	return ops->get_retire_pages_pending_status(mcc_set, ispending, isfailure);
}

int cn_mcc_get_remapped_rows(void *pcore, unsigned int *corr_rows,
			unsigned int *unc_rows, unsigned int *pending_rows,
			unsigned int *fail_rows)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcc_set *mcc_set;
	const struct cn_repair_ops *ops = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("input pcore is invalid");
		return -EINVAL;
	}

	mcc_set = (struct cn_mcc_set *)core->mcc_set;
	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "mcc_set is NULL");
		return -EINVAL;
	}

	ops = mcc_set->repair_ops;
	if (IS_ERR_OR_NULL(ops) || IS_ERR_OR_NULL(ops->get_remapped_rows)) {
		cn_dev_err("get remapped_rows func null");
		return -EINVAL;
	}

	return ops->get_remapped_rows(mcc_set, corr_rows, unc_rows, pending_rows,
								fail_rows);
}

int cn_mcc_retire_switch(void *pcore, int status)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcc_set *mcc_set;
	const struct cn_repair_ops *ops = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("input pcore is invalid");
		return -EINVAL;
	}

	mcc_set = (struct cn_mcc_set *)core->mcc_set;
	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "mcc_set is NULL");
		return -EINVAL;
	}

	ops = mcc_set->repair_ops;
	if (IS_ERR_OR_NULL(ops) || IS_ERR_OR_NULL(ops->retire_switch)) {
		cn_dev_err("get retire_switch func null");
		return -EINVAL;
	}

	return ops->retire_switch(mcc_set, status);
}

int cn_mcc_ecc_irq_inject(void *pcore, u32 sys_mc_num,
			u32 mc_state, u32 ecc_addr)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcc_set *mcc_set;
	const struct cn_repair_ops *ops = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("input pcore is invalid");
		return -EINVAL;
	}

	mcc_set = (struct cn_mcc_set *)core->mcc_set;
	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "mcc_set is NULL");
		return -EINVAL;
	}

	ops = mcc_set->repair_ops;
	if (IS_ERR_OR_NULL(ops) || IS_ERR_OR_NULL(ops->ecc_irq_inject)) {
		cn_dev_err("get ecc_irq_inject func null");
		return -EINVAL;
	}

	return ops->ecc_irq_inject(mcc_set, sys_mc_num, mc_state, ecc_addr);
}

int cn_mcc_get_eeprom_switch(void *pcore, int status)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcc_set *mcc_set;
	const struct cn_repair_ops *ops = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("input pcore is invalid");
		return -EINVAL;
	}

	mcc_set = (struct cn_mcc_set *)core->mcc_set;
	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "mcc_set is NULL");
		return -EINVAL;
	}

	ops = mcc_set->repair_ops;
	if (IS_ERR_OR_NULL(ops) || IS_ERR_OR_NULL(ops->get_eeprom_switch)) {
		cn_dev_err("get eeprom_switch func null");
		return -EINVAL;
	}

	return ops->get_eeprom_switch(mcc_set, status);
}

int cn_mcc_get_eeprom_info(void *pcore, unsigned int **rom_info,
			unsigned int *eeprom_num)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcc_set *mcc_set;
	const struct cn_repair_ops *ops = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("input pcore is invalid");
		return -EINVAL;
	}

	mcc_set = (struct cn_mcc_set *)core->mcc_set;
	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "mcc_set is NULL");
		return -EINVAL;
	}

	ops = mcc_set->repair_ops;
	if (IS_ERR_OR_NULL(ops) || IS_ERR_OR_NULL(ops->get_eeprom_info)) {
		cn_dev_err("get eeprom_info func null");
		return -EINVAL;
	}

	return ops->get_eeprom_info(mcc_set, rom_info, eeprom_num);
}

int cn_mcc_get_sys_mc_nums(void *pcore, unsigned int *sys_mc_nums)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mcc_set *mcc_set;
	const struct cn_repair_ops *ops = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("input pcore is invalid");
		return -EINVAL;
	}

	mcc_set = (struct cn_mcc_set *)core->mcc_set;
	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "mcc_set is NULL");
		return -EINVAL;
	}

	ops = mcc_set->repair_ops;
	if (IS_ERR_OR_NULL(ops) || IS_ERR_OR_NULL(ops->get_sys_mc_nums)) {
		cn_dev_err("get sys_mc_nums func null");
		return -EINVAL;
	}

	return ops->get_sys_mc_nums(mcc_set, sys_mc_nums);
}

int cn_mcc_get_d2dc_num(void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;

	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_err("mcc set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcc_set->mcc_ops->get_d2dc_num)) {
		cn_dev_err("get d2dc func null");
		return -EINVAL;
	}
	return mcc_set->mcc_ops->get_d2dc_num(mcc_set);
}

void cn_mcc_get_mem_limit_coef(void *pcore, unsigned int *limit_coef)
{
	struct cn_core_set *core = pcore;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;

	/*
	 *NOTE: just cloud platform which has hbm or ddr, support mcc ops.
	 *In func __mcc_unit_init we check the plat and set valid val for mcc_set.
	 */
	if (!mcc_set) {
		cn_dev_info("dev is not support mcc ops");
		return;
	}
	if (IS_ERR(mcc_set)) {
		cn_dev_err("mcc set is null");
		return;
	}
	if (IS_ERR_OR_NULL(mcc_set->mcc_ops->get_mem_limit_coef)) {
		cn_dev_info("get mem limit coef func null");
		return;
	}

	return mcc_set->mcc_ops->get_mem_limit_coef(mcc_set, limit_coef);
}

int cn_mcc_get_channel_num(void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;

	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_err("memory ctrl set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(mcc_set->mcc_ops)) {
		cn_dev_err("memory ctrl ops set is null");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(mcc_set->mcc_ops->get_channel_num)) {
		cn_dev_err("get channel func null");
		return -EINVAL;
	}
	return mcc_set->mcc_ops->get_channel_num(mcc_set);
}

void *cn_mcc_get_ecc_status(void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;

	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_err("memory ctrl set is null");
		return NULL;
	}
	if (IS_ERR_OR_NULL(mcc_set->mcc_ops->get_ecc_status)) {
		cn_dev_err("get ecc status func null");
		return NULL;
	}
	return mcc_set->mcc_ops->get_ecc_status(mcc_set);
}

void *cn_mcc_get_d2dc_status(void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;

	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_err("mcc set is null");
		return NULL;
	}
	if (IS_ERR_OR_NULL(mcc_set->mcc_ops->get_d2dc_status)) {
		cn_dev_err("get d2dc status func null");
		return NULL;
	}
	return mcc_set->mcc_ops->get_d2dc_status(mcc_set);
}

void cn_mcc_get_map_mode(void *pcore, unsigned int *map_mode,
						  unsigned int *hbm_idx)
{
	struct cn_core_set *core = pcore;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;

	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_err("mcc set is null");
		return;
	}
	if (IS_ERR_OR_NULL(mcc_set->mcc_ops->get_map_mode)) {
		cn_dev_err("get map mode status func null");
		return;
	}
	return mcc_set->mcc_ops->get_map_mode(mcc_set, map_mode, hbm_idx);
}

void cn_mcc_get_compress_info(void *pcore, unsigned int *compress_en,
				unsigned int *compress_mode, unsigned int *compress_high_mode)
{
	struct cn_core_set *core = pcore;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;

	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_err("mcc set is null");
		return;
	}
	if (IS_ERR_OR_NULL(mcc_set->mcc_ops->get_compress_info)) {
		cn_dev_err("get compress status func null");
		return;
	}
	return mcc_set->mcc_ops->get_compress_info(mcc_set, compress_en,
				compress_mode, compress_high_mode);
}

void cn_mcc_dump_llc_state(void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;

	if (!mcc_set) {
		cn_dev_info("dev is not support mcc ops");
		return;
	}
	if (IS_ERR(mcc_set)) {
		cn_dev_err("mcc set is null");
		return;
	}
	if (IS_ERR_OR_NULL(mcc_set->mcc_ops->dump_llc_state)) {
		cn_dev_info("dump llc state func null");
		return;
	}

	return mcc_set->mcc_ops->dump_llc_state(mcc_set);
}

int __mcc_unit_init(struct cn_core_set *core)
{
	int ret = 0;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
#ifdef MLU290_HBM
	u64 start_jiffies, end_jiffies;
#endif

	switch (core->device_id) {
	case MLUID_270:
		ret = ddr_init_mlu270(mcc_set);
		break;
	case MLUID_370:
		ret = ddr_init_mlu370(mcc_set);
		if (ret)
			break;

		/* NOTE: mlu370 retire init process depend on the status of inlineECC,
		 * so we need do ddr_init_mlu370 first! */
		ret = ddr_retire_init_mlu370(mcc_set);
		if (ret && mcc_set->mcc_ops->mcc_exit) {
			mcc_set->mcc_ops->mcc_exit(mcc_set);
		}

		break;
	case MLUID_590:
		ret = hbm_llc_noc_init_mlu590(mcc_set);
		break;
	case MLUID_290:
#ifdef MLU290_HBM
		start_jiffies = get_jiffies_64();
		ret = hbm_repair_init_mlu290(mcc_set);
		end_jiffies = get_jiffies_64();
		cn_dev_core_info(core, "hbm training time:%dms",
				jiffies_to_msecs(end_jiffies - start_jiffies));
		if (ret)
			break;
#endif
		ret = hbm_init_mlu290(mcc_set);
		break;
	case MLUID_580:
		ret = gddr_init_mlu580(mcc_set);
		break;
	default:
		cn_dev_core_info(core, "board mcc not support");
		ret = -ENODEV;
		break;
	}
	return ret;
}

int cn_mcc_init(struct cn_core_set *core)
{
	struct cn_mcc_set *mcc_set;
	int ret;

	if (core->device_id == MLUID_370_DEV) {
		cn_dev_core_info(core, "no support 370 dev.");
		return 0;
	}

	if (core->device_id == MLUID_590_DEV) {
		cn_dev_core_info(core, "no support 590 dev.");
		return 0;
	}

	cn_dev_core_info(core, "mcc init");
	mcc_set = cn_kzalloc(sizeof(struct cn_mcc_set), GFP_KERNEL);
	if (!mcc_set) {
		cn_dev_core_err(core, "alloc mcc set error.");
		return -ENOMEM;
	}
	core->mcc_set = mcc_set;
	mcc_set->core = core;

	ret = __mcc_unit_init(core);
	if (ret) {
		core->mcc_set = NULL;
		cn_kfree(mcc_set);
	}
	if (ret == -ENODEV)
		return 0;

	return ret;
}

void cn_mcc_exit(struct cn_core_set *core)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;

	cn_dev_core_info(core, "mcc free");
	if (mcc_set) {
		if (mcc_set->mcc_ops->repair_exit)
			mcc_set->mcc_ops->repair_exit(mcc_set);

		if (mcc_set->mcc_ops->mcc_exit)
			mcc_set->mcc_ops->mcc_exit(mcc_set);

		/* mcc_set will freed in release_after_shutdown */
	}

	cn_mcc_release_after_shutdown(core);
}

void cn_mcc_release_after_shutdown(struct cn_core_set *core)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;

	cn_dev_core_info(core, "mcc release after shutdown");
	if (mcc_set) {
		if (mcc_set->mcc_ops->ile_exit)
			mcc_set->mcc_ops->ile_exit(mcc_set);

		down_write(&core->mcc_state_sem);
		mcc_set->mcc_ops = NULL;
		core->mcc_set = NULL;
		up_write(&core->mcc_state_sem);
		cn_kfree(mcc_set);
	}
}
