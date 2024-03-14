#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"
#include "cndrv_ioctl.h"
#include "exp_mgnt_private.h"
#include "cndrv_commu.h"
#include "mlu370_regmap.h"
#include "mlu590_regmap.h"
#include "mlu580_regmap.h"

static int dump_register(struct cn_core_set *core, struct file *fp,
						 struct cndump_reg_map *reg_map, loff_t *pos)
{
	int ret = -1;
	char buf[128];
	unsigned int i;

	memset(buf, 0, sizeof(buf));
	ret = sprintf(buf, "%s\n", reg_map->model);
	ret = cn_fs_write(fp, buf, ret, pos);
	for (i = reg_map->addr_start; i <= reg_map->addr_end; i+=4) {
		memset(buf, 0, sizeof(buf));
		ret = sprintf(buf, "0x%08x:0x%08x\n", i, reg_read32(core->bus_set, i));
		ret = cn_fs_write(fp, buf, ret, pos);
	}
	return 0;
}

static int dumpreg_notifier(void *data,
			     unsigned long action, void *fp)
{
	struct cn_core_set *core = (struct cn_core_set *)data;
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct cndump_reg_map *reg_map = mnt_set->reg_map;
	struct cndump_reg_map *reg_map_temp;
	loff_t pos = 0;
	struct file *fp1 = (struct file*)fp;
	int i;

	for (i = 0; i < mnt_set->reg_map_len; i++) {
		reg_map_temp = reg_map + i;
		if ((reg_map_temp->call_check != NULL) &&
			(reg_map_temp->call_check(core, reg_map_temp->index) == 0))
			continue;
		dump_register(core, fp1, reg_map_temp, &pos);
	}

	return 0;
}

void cn_dumpreg_init(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	switch (core->device_id) {
	case MLUID_370:
		mnt_set->reg_map = mlu370_regmap;
		mnt_set->reg_map_len = sizeof(mlu370_regmap)/sizeof(struct cndump_reg_map);
		break;
	case MLUID_590:
		mnt_set->reg_map = mlu590_regmap;
		mnt_set->reg_map_len = sizeof(mlu590_regmap)/sizeof(struct cndump_reg_map);
		break;
	case MLUID_580:
		mnt_set->reg_map = mlu580_regmap;
		mnt_set->reg_map_len = sizeof(mlu580_regmap)/sizeof(struct cndump_reg_map);
		break;
	default:
		mnt_set->reg_map_len = 0;
		break;
	}
	mnt_set->nb_dumpreg = cn_register_report(core, "reg", 0, dumpreg_notifier, core);
}

void cn_dumpreg_free(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	cn_unregister_report(core, mnt_set->nb_dumpreg);
}
