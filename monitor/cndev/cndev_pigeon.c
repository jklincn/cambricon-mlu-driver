#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/hrtimer.h>
#include <linux/random.h>
#include <linux/pid_namespace.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"
#include "cndrv_mcu.h"
#include "cndrv_mcc.h"
#include "../../core/version.h"
#include "cndrv_commu.h"
#include "cndrv_ioctl.h"
#include "cndrv_sbts.h"
#include "cndev_server.h"
#include "../monitor.h"

#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_attr.h"

const char *pigeon_name[CN_CHIP_ID_MAX] = {
	"1V-2201",//leopard
	"1V-2201",//pigeon
	"1V-2202",//pigeon c
	"1V-2301",//dove
	"1V-2302",//dove c
	"UNKNOW",
};

void card_info_fill_pigeon_common(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;
	struct cn_board_info *pbrdinfo = &core->board_info;
	struct cndev_card_info *info = &cndev_set->card_static_info;
	struct bus_info_s bus_info;
	struct bus_lnkcap_info lnk_info;

	memset(&bus_info, 0, sizeof(struct bus_info_s));
	memset(&lnk_info, 0, sizeof(struct bus_lnkcap_info));
	info->head.card = core->idx;
	info->head.version = CNDEV_CURRENT_VER;
	info->head.buf_size = sizeof(struct cndev_card_info);
	info->head.real_size = sizeof(struct cndev_card_info);
	info->mcu_major_ver = pbrdinfo->mcu_info.mcu_major;
	info->mcu_minor_ver = pbrdinfo->mcu_info.mcu_minor;
	info->mcu_build_ver = pbrdinfo->mcu_info.mcu_build;
	info->driver_major_ver = DRV_MAJOR;
	info->driver_minor_ver = DRV_MINOR;
	info->driver_build_ver = DRV_BUILD;
	info->subsystem_id = pbrdinfo->board_type;

	/*get from pci_dev*/
	info->bus_type = bus_info.bus_type;
	info->device_id = bus_info.info.pcie.device;
	info->vendor_id = bus_info.info.pcie.vendor;
	info->subsystem_vendor = bus_info.info.pcie.subsystem_vendor;
	info->domain = bus_info.info.pcie.domain_id;
	info->bus = bus_info.info.pcie.bus_num;
	info->device = (bus_info.info.pcie.device_id >> 3) & 0x1f;
	info->func = bus_info.info.pcie.device_id & 0x07;

	info->ipu_cluster = pbrdinfo->cluster_num;
	info->ipu_core = pbrdinfo->ipu_core_num;

	info->max_speed = lnk_info.speed;
	info->max_width = lnk_info.width;

	info->card_name = core->board_model;
	info->card_sn = pbrdinfo->serial_num;

	strcpy(info->board_model, pigeon_name[pbrdinfo->chip_type]);
	strcpy(pbrdinfo->board_model_name, pigeon_name[pbrdinfo->chip_type]);

	info->mother_board_sn = pbrdinfo->BA_serial_num;
	info->mother_board_mcu_fw_ver = pbrdinfo->BA_mcu_fw_ver;
	info->slot_id = pbrdinfo->slot_id;
	info->chip_id = pbrdinfo->chip_id;

	info->qdd_status = pbrdinfo->qdd_status;

	/*CE uuid, get uuid after bl3 init */
	cndrv_mcu_read_uuid(core, info->uuid);
	/* SOC ID*/
	info->secure_mode = pbrdinfo->secure_mode;
	memcpy(info->soc_id, pbrdinfo->soc_id.soc_id_data, SOC_ID_SIZE);

	/* mem data width */
	info->data_width = pbrdinfo->bus_width;
	info->bandwidth = pbrdinfo->bandwidth;
	info->bandwidth_decimal = pbrdinfo->bandwidth_decimal;
}

int card_power_info_pigeon(void *cset,
			struct cndev_power_info *power_info)
{
	int ret = 0;
	struct board_power_info pinfo;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core;
	struct cn_board_info *pbrdinfo;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	pbrdinfo = &core->board_info;

	power_info->head.version = CNDEV_CURRENT_VER;
	power_info->head.real_size = sizeof(struct cndev_power_info);

	ret = cndrv_mcu_read_power_info(core, &pinfo);
	if (ret) {
		return ret;
	}

	power_info->max_power = pinfo.peak_power ?
			pinfo.peak_power : pbrdinfo->peak_power;
	power_info->power_usage = pinfo.board_power;
	power_info->power_usage_decimal = pinfo.board_power_decimal;
	power_info->max_power_decimal = pinfo.max_power_decimal;
	power_info->fan_speed = pinfo.fan_speed;
	power_info->machine_power = 0;
	power_info->min_power_cap = pbrdinfo->min_power_cap;
	power_info->min_power_cap_decimal = pbrdinfo->min_power_cap_dec;
	power_info->max_power_cap_decimal = pbrdinfo->max_power_cap_dec;
	power_info->perf_limit_num = 0;
	power_info->edpp_count = 0;
	power_info->tdp_freq_capping_count = 0;

	/* pigeon set tdp equal peak power */
	power_info->tdp = pbrdinfo->peak_power;
	power_info->ipu_cluster_freq_num = 0;
	power_info->instantaneous_power = power_info->power_usage;
	power_info->instantaneous_power_decimal = power_info->power_usage_decimal;
	power_info->ipu_cluster_mask = 0;

	ret = cndev_cp_less_val(
			&power_info->temperature_num, pinfo.temperature_num,
			power_info->temp, pinfo.temp, sizeof(s8));

	power_info->ignore_chassis_power_info = 1;

	/*free temp buf in power_info struct which alloced in mcu function.*/
	cn_kfree(pinfo.temp);
	return ret;
}

int card_vm_info_pigeon(void *cset,
	struct cndev_vm_info *vinfo)
{

	vinfo->head.version = CNDEV_CURRENT_VER;
	vinfo->head.real_size = sizeof(struct cndev_vm_info);

	vinfo->vm_check = VM_PF;
	vinfo->vm_num = 0;

	return 0;
}

static u32 pigeon_die_base[2] = {
	0x0,
	0x0,
};

const struct xpll_freq_frac pigeon_ipu0_freq_frac_div2[] = {
	// { 100,  33,  5033165, 1, 4, 2},
	// { 200,  50,        0, 1, 3, 2},
	// { 300,  75,        0, 1, 3, 2},
	// { 400,  50,        0, 1, 3, 1},
	// { 500,  41, 11184811, 1, 2, 1},
	{ 600,  50,        0, 1, 2, 1},
	{ 640,  53,  5592405, 1, 2, 1},
	{ 720,  60,        0, 1, 2, 1},
	{ 800,  66, 11184811, 1, 2, 1},
	{ 936,  78,        0, 1, 2, 1},
	{1000,  83,  5592405, 1, 2, 1},
	{1200, 100,        0, 1, 2, 1},
};

const struct xpll_freq_frac pigeon_ipu0_freq_frac_div3[] = {
	// { 100,  33, 5033165, 1, 4, 2},
	// { 200,  50,       0, 1, 3, 2},
	// { 300,  75,       0, 1, 3, 2},
	// { 400,  50,       0, 1, 3, 1},
	// { 500,  62, 8388608, 1, 3, 1},
	{ 600,  75,       0, 1, 3, 1},
	{ 640,  80,       0, 1, 3, 1},
	{ 720,  90,       0, 1, 3, 1},
	{ 800, 100,       0, 1, 3, 1},
	{ 936, 117,       0, 1, 3, 1},
	{1000, 125,       0, 1, 3, 1},
	{1200, 150,        0, 1, 3, 1}
};


const struct xpll_freq_frac pigeon_ipu1_freq_frac_div2[] = {
	// { 100,  33,  5033165, 1, 4, 2},
	// { 200,  50,        0, 1, 3, 2},
	// { 300,  75,        0, 1, 3, 2},
	// { 400,  50,        0, 1, 3, 1},
	// { 500,  41, 11184810, 1, 2, 1},
	{ 600,  50,        0, 1, 2, 1},
	{ 640,  53,  5592405, 1, 2, 1},
	{ 720,  60,        0, 1, 2, 1},
	{ 800,  66, 11184810, 1, 2, 1},
	{ 936,  78,        0, 1, 2, 1},
	{1000,  83,  5592405, 1, 2, 1},
	{1200, 100,        0, 1, 2, 1}
};

const struct xpll_freq_frac pigeon_ipu1_freq_frac_div3[] = {
	// { 100,  33,  5033165, 1, 4, 2},
	// { 200,  50,        0, 1, 3, 2},
	// { 300,  75,        0, 1, 3, 2},
	// { 400,  50,        0, 1, 3, 1},
	// { 500,  62,  8388608, 1, 3, 1},
	{ 600,  75,        0, 1, 3, 1},
	{ 640,  80,        0, 1, 3, 1},
	{ 720,  90,        0, 1, 3, 1},
	{ 800, 100,        0, 1, 3, 1},
	{ 936, 117,        0, 1, 3, 1},
	{1000, 125,        0, 1, 3, 1},
	{1200, 150,        0, 1, 3, 1}
};

const struct xpll_reg pigeon_ipupll[IPU_TYPE_MAX] = {
	{0x1240, 0x1244, 0x1248, 0x1380, 0x1390, 0x1394, 0x1398,
		0x139c, 0x13a0, 0x13a4, 0x13a8, 0x13ac, 0x1388, 0x138c},
	{0x1280, 0x1284, 0x1288, 0x13c0, 0x13d0, 0x13d4, 0x13d8,
		0x13dc, 0x13e0, 0x13e4, 0x13e8, 0x13ec, 0x13c8, 0x13cc},
};

int pigeon_ipupll_frac_clear(void *cset, u32 mode, u32 base)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;

	reg_write32(core->bus_set, base + pigeon_ipupll[mode].xpll_frac_adj_en, 0);
	reg_write32(core->bus_set, base + pigeon_ipupll[mode].xpll_frac_step0_up_cfg0, 0);
	reg_write32(core->bus_set, base + pigeon_ipupll[mode].xpll_frac_step0_up_cfg1, 0);
	reg_write32(core->bus_set, base + pigeon_ipupll[mode].xpll_frac_step1_up_cfg0, 0);
	reg_write32(core->bus_set, base + pigeon_ipupll[mode].xpll_frac_step1_up_cfg1, 0);
	reg_write32(core->bus_set, base + pigeon_ipupll[mode].xpll_frac_step0_down_cfg0, 0);
	reg_write32(core->bus_set, base + pigeon_ipupll[mode].xpll_frac_step0_down_cfg1, 0);
	reg_write32(core->bus_set, base + pigeon_ipupll[mode].xpll_frac_step1_down_cfg0, 0);
	reg_write32(core->bus_set, base + pigeon_ipupll[mode].xpll_frac_step1_down_cfg1, 0);

	return 0;
}

void pigeon_set_pll_cfgs(void *cset, const struct xpll_freq_frac *frac, u32 base, u32 mode)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;
	u32 reg32 = 0;
	u64 pllcfg0 = pigeon_ipupll[mode].xpll_cfg0;
	u64 pllcfg1 = pigeon_ipupll[mode].xpll_cfg1;

	reg32 = reg_read32(core->bus_set, base + pllcfg0);
	reg32 = reg32 & (~0x3f);
	reg32 |= frac->refdiv;
	reg32 = reg32 & (~(0xfff<<8));
	reg32 |= (frac->fbdiv << 8);
	reg32 = reg32 & (~(0x7 << 24));
	reg32 = reg32 | (frac->postdiv2 << 24);
	reg32 = reg32 & (~(0x7 << 27));
	reg32 = reg32 | (frac->postdiv1 << 27);
	reg_write32(core->bus_set, base + pllcfg0, reg32);

	reg32 = reg_read32(core->bus_set, base + pllcfg1);
	reg32 = reg32 & (~0xffffff);
	reg32 = reg32 | frac->fracdiv;
	reg_write32(core->bus_set, base + pllcfg1, reg32);
}

int pigeon_read_ipu_freq(void *pcore, enum cndev_ipu_type type, u32 *freq)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)core->cndev_set;

	int ret = 0;
	struct ipu_freq_info info;

	ret = cndrv_mcu_read_ipu_freq(pcore, &info);
	if (ret) {
		cn_ce_dev_cndev_debug(cndev_set, "Read ipu freq %d failed", type);
		return -EINVAL;
	}

	*freq = info.die_ipu_freq.ipu_freq[type];

	return 0;
}

static int pigeon_cacc_ctrl(struct cn_core_set *core, u32 ctrl, u32 type)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)core->cndev_set;
	struct sbts_hw_cfg_hdl param = {0};
	int ret = 0;

	param.version = SBTS_VERSION;
	param.type = type;
	param.val = ctrl;
	ret = cn_hw_cfg_cacc_handle(core, &param, 0);
	if (ret) {
		cn_ce_dev_core_err(cndev_set, "cacc type %u, ctrl %u, ret %d", type, ctrl, ret);
	}

	return ret;
}

static int pigeon_static(void *cset,
	u32 base,
	enum cndev_ipu_type ctrl_mode,
	const struct xpll_freq_frac *frac)
{
	u32 reg32 = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;

	/* static */
	pigeon_ipupll_frac_clear(cset, ctrl_mode, base);

	// step b:
	reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl, 0x200000);
	reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl, 0x20000);

	// step d:
	pigeon_set_pll_cfgs(cset, frac, base, ctrl_mode);

	// step g:
	reg32 = reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_frac_adj_en);
	reg32 = reg32 | 0x1;
	reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_frac_adj_en, reg32);

	// step h
	mdelay(200);
	reg32 = reg32 & (~0x1);
	reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_frac_adj_en, reg32);

	// step i
	mdelay(200);

	// step j:
	reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl, 0x20002);
	reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl, 0x200020);

	return 0;
}

static unsigned int pigeon_pll_mode_val[] = {0, 0x3000000};
static int pigeon_dynamic1(void *cset,
	u32 base,
	enum cndev_ipu_type ctrl_mode,
	const struct xpll_freq_frac *frac)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;
	int i = 0;
	u32 val = 0;
	u32 step = 0;
	u32 diff_val = 0;
	u32 dir = 0;
	u32 target_val = 0;
	u32 cur_val = 0;
	u32 cnt = 0;
	u32 cur_fbdiv = 0;
	u32 cur_fracdiv = 0;
	u32 cfg = 0;
	u32 new_fbdiv = 0;
	u32 new_cfg0 = 0;
	u32 new_fracdiv = 0;
	u32 new_cfg1 = 0;

	/* set pigeon_ipupll mode */
	cfg = reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_cfg1);
	if (pigeon_pll_mode_val[1] != (0x3000000 & cfg)) {
		reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl, 0x400000);
		reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl, 0x200000);

		reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl, 0x20000);

		reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl,
						cfg | pigeon_pll_mode_val[ctrl_mode]);
		msleep(1);
		reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl, 0x20002);
		msleep(1);
		reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl, 0x200020);
		reg_write32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_ctrl, 0x400040);
	}

	pigeon_ipupll_frac_clear(cset, ctrl_mode, base);

	cur_fbdiv = reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_cfg0);
	cur_fbdiv = (0xfff00 & cur_fbdiv) >> 8;

	cur_fracdiv = reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_cfg1);
	cur_fracdiv &= 0xffffff;
	cur_val = (cur_fbdiv << 24) | cur_fracdiv;

	target_val = (frac->fbdiv << 24) | frac->fracdiv;
	if (target_val == cur_val) {
		return 0;
	}

	if (target_val > cur_val) {
		val = cur_val;
		dir = 1;
		diff_val = target_val - cur_val;
	} else {
		val = target_val;
		dir = 0;
		diff_val = cur_val - target_val;
	}

	step = val / 20000;
	cnt = (diff_val + step / 2) / step;

	if (dir) {
		val = (step << 4) | 0x1;
		reg_write32(core->bus_set,
			base + pigeon_ipupll[ctrl_mode].xpll_frac_step0_up_cfg0, val);
		val = (cnt << 16);
		reg_write32(core->bus_set,
			base + pigeon_ipupll[ctrl_mode].xpll_frac_step0_up_cfg1, val);
	} else {
		val = (step << 4) | 0x1;
		reg_write32(core->bus_set,
			base + pigeon_ipupll[ctrl_mode].xpll_frac_step0_down_cfg0, val);
		val = (cnt << 16);
		reg_write32(core->bus_set,
			base + pigeon_ipupll[ctrl_mode].xpll_frac_step0_down_cfg1, val);
	}

	val = reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_frac_adj_en);
	val = (dir << 4) | 0x1;
	reg_write32(core->bus_set,
		base + pigeon_ipupll[ctrl_mode].xpll_frac_adj_en, val);

	for (i = 0; i < 100; i++) {
		val = reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_frac_adj_en);
		if (!(val & 0x1))
			break;
		else
			msleep(10);
	}

	if (i >= 100) {
		cn_ce_dev_core_err(core, "ipu%dupll clk set timeout", ctrl_mode);
		return -EINVAL;
	} else {
		reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_frac_cur_fbdiv);

		//update xpll_cfg0 and xpll_cfg1
		new_fbdiv = reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_frac_cur_fbdiv);
		new_cfg0 = reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_cfg0);

		reg_write32(core->bus_set,
			base + pigeon_ipupll[ctrl_mode].xpll_cfg0, (new_cfg0 & (~0xfff00)) | (new_fbdiv << 8));

		new_fracdiv = reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_frac_cur_fracdiv);
		new_cfg1 = reg_read32(core->bus_set, base + pigeon_ipupll[ctrl_mode].xpll_cfg1);

		reg_write32(core->bus_set,
			base + pigeon_ipupll[ctrl_mode].xpll_cfg1, (new_cfg1 & (~0xffffff)) | new_fracdiv);

		if (dir) {
			reg_write32(core->bus_set,
				base + pigeon_ipupll[ctrl_mode].xpll_frac_step0_up_cfg1, 0);
		} else {
			reg_write32(core->bus_set,
				base + pigeon_ipupll[ctrl_mode].xpll_frac_step0_down_cfg1, 0);
		}
	}

	return 0;
}

static int __set_ipu_freq(struct cn_core_set *core,
	u32 count,
	u32 mode,
	u32 freq,
	const struct xpll_freq_frac *frac,
	const struct xpll_freq_frac *frac_div3)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)core->cndev_set;
	int target = 0, cur = 0;
	int ret = 0;
	u32 cur_postdiv1 = 0;
	u32 base = 0;
	int i = 0, j = 0;

	for (i = 0; i < count; i++) {
		if (freq >= frac[i].freq) {
			target = i;
		} else {
			break;
		}
	}
	if (IS_ERR_OR_NULL(&frac[target])) {
		cn_ce_dev_core_err(core, "ipu%upll clk get failed, index = %u\n", mode, target);
		return -EINVAL;
	} else {
		for (i = 0; i < core->die_cnt; i++) {
			base = pigeon_die_base[i];

			cur_postdiv1 = reg_read32(core->bus_set, base + pigeon_ipupll[mode].xpll_cfg0) >> 27 & 0x7;
			if(cur_postdiv1 == 3) {
				frac = frac_div3;
			}

			ret = pigeon_read_ipu_freq(core, mode, &freq);
			if (ret) {
				cn_ce_dev_core_err(cndev_set, "Set ipu freq %d failed", mode);
				return -EINVAL;
			}

			for (j = 0; j < count; j++) {
				if (freq >= frac[j].freq) {
					cur = j;
				} else {
					break;
				}
			}

			if (frac[target].freq < 500 || freq < 500) {
				cn_ce_dev_cndev_debug(cndev_set, "[static] current freq %u, target freq %u", freq, frac[target].freq);

				/* case 2: target < 500 && current >= 500 */
				if (frac[target].freq < 500 && freq >= 500) {
					/*bypass cacc*/
					ret = pigeon_cacc_ctrl(core, 1, CACC_SET_BYPASS);
					cn_ce_dev_cndev_debug(cndev_set, "cacc bypass ret = %d\n", ret);
					if (ret)
						return ret;
					/*disable cacc*/
					ret = pigeon_cacc_ctrl(core, 0, CACC_SET_ENABLE);
					cn_ce_dev_cndev_debug(cndev_set, "cacc disable ret = %d\n", ret);
					if (ret) {
						pigeon_cacc_ctrl(core, 0, CACC_SET_BYPASS);
						return ret;
					}
				}

				pigeon_static(cndev_set, base, mode, &frac[target]);

				/* case 4: target >= 500 && current < 500 */
				if (frac[target].freq >= 500 && freq < 500) {
					/*enable cacc */
					ret = pigeon_cacc_ctrl(core, 1, CACC_SET_ENABLE);
					cn_ce_dev_cndev_debug(cndev_set, "cacc enable ret = %d\n", ret);
					if (ret)
						goto static_err;

					/*un-bypass cacc*/
					ret = pigeon_cacc_ctrl(core, 0, CACC_SET_BYPASS);
					cn_ce_dev_cndev_debug(cndev_set, "cacc un-bypass ret = %d\n", ret);
					if (ret) {
						pigeon_cacc_ctrl(core, 1, CACC_SET_ENABLE);
						goto static_err;
					}
				}
			} else {
				/* case 1: target >= 500 && current >= 500 */
				cn_ce_dev_cndev_debug(cndev_set, "[dynamic1] current freq %u, target freq %u", freq, frac[target].freq);
				/* dynamic1 */
				if ((freq >= (frac[target].freq - 3)) && (freq <= (frac[target].freq + 3))) {
					continue;
				}

				ret = pigeon_dynamic1(cndev_set, base, mode, &frac[target]);
				if (ret)
					return ret;
			}
		}
	}

	return 0;

static_err:
	cn_ce_dev_cndev_debug(cndev_set, "[static] recovery freq %u, cur %d", frac[cur].freq, cur);
	pigeon_static(cndev_set, base, mode, &frac[cur]);
	return ret;
}

int card_ipufreq_set_pigeon(void *cset,
	struct cndev_ipufreq_set *setinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;
	u32 count[IPU_TYPE_MAX] = {0, 0};
	int ret = 0;
	struct cn_board_info *pbrdinfo = &core->board_info;
	u8 chip_type = pbrdinfo->chip_type;

	count[CT] = ARRAY_SIZE(pigeon_ipu0_freq_frac_div3);
	count[LT] = ARRAY_SIZE(pigeon_ipu1_freq_frac_div2);

	if ((chip_type == CN_CHIP_ID_PIGEONC) ||
		(chip_type == CN_CHIP_ID_1V_2302)) {
		count[LT] -= 1;
		count[CT] -= 1;
	}

	switch (setinfo->ctrl_mode) {
	case CT:
		ret = __set_ipu_freq(core,
				count[CT],
				CT,
				setinfo->ipu_freq,
				&pigeon_ipu0_freq_frac_div2[0],
				&pigeon_ipu0_freq_frac_div3[0]);
		break;
	case LT:
		if (chip_type != CN_CHIP_ID_PIGEONC ||
			chip_type != CN_CHIP_ID_1V_2302) {
			ret = __set_ipu_freq(core,
				count[LT],
				LT,
				setinfo->ipu_freq,
				&pigeon_ipu1_freq_frac_div2[0],
				&pigeon_ipu1_freq_frac_div3[0]);
		} else {
			ret = -ENODEV;
		}
		break;
	case ALL:
		ret = __set_ipu_freq(core,
				count[CT],
				CT,
				setinfo->ipu_freq,
				&pigeon_ipu0_freq_frac_div2[0],
				&pigeon_ipu0_freq_frac_div3[0]);
		if ((chip_type != CN_CHIP_ID_PIGEONC) ||
			(chip_type != CN_CHIP_ID_1V_2302)) {
			ret |= __set_ipu_freq(core,
				count[LT],
				LT,
				setinfo->ipu_freq,
				&pigeon_ipu1_freq_frac_div2[0],
				&pigeon_ipu1_freq_frac_div3[0]);
		}
		break;
	default:
		return -EINVAL;
		break;
	}

	return ret;
}

int cndev_card_freq_info_pigeon(void *cset,
	struct cndev_freq_info *finfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;
	struct cn_board_info *pbrdinfo = &core->board_info;
	u16 vcard;
	struct ipu_freq_info info = {0};
	const struct xpll_freq_frac *frac = NULL;
	u32 size = 0;
	int i = 0;
	u16 freq_data[16];

	vcard = (finfo->head.card >> 8) & 0x0f;
	if (vcard)
		return -ENODEV;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	finfo->head.version = CNDEV_CURRENT_VER;
	finfo->head.real_size = sizeof(struct cndev_freq_info);

	finfo->ddr_freq = pbrdinfo->ddr_speed;
	ret = cndrv_mcu_read_ipu_freq(cndev_set->core, &info);
	finfo->rated_ipu_freq = info.rated_ipu_freq;
	finfo->ipu_freq = info.ipu_freq;
	finfo->ipu_fast_dfs_flag = info.ipu_fast_dfs_flag;
	finfo->ipu_overtemp_dfs_flag = info.ipu_overtemp_dfs_flag;

	if (finfo->type != CT && finfo->type != LT) {
		return -EINVAL;
	}

	switch (finfo->type) {
	case CT:
		frac = &pigeon_ipu0_freq_frac_div3[0];
		size = ARRAY_SIZE(pigeon_ipu0_freq_frac_div3);
		break;
	case LT:
		frac = &pigeon_ipu1_freq_frac_div3[0];
		size = ARRAY_SIZE(pigeon_ipu1_freq_frac_div3);
		break;
	default:
		return -EINVAL;
		break;
	}

	if ((pbrdinfo->chip_type == CN_CHIP_ID_PIGEONC) ||
		(pbrdinfo->chip_type == CN_CHIP_ID_1V_2302)) {
		size -= 1;
	}

	finfo->range[0] = frac[0].freq;
	finfo->range[1] = frac[size - 1].freq;

	for (i = 0; i < size; i++) {
		freq_data[i] = frac[i].freq;
	}

	ret = cndev_cp_less_val(
		&finfo->freq_num, size,
		finfo->freq, freq_data, sizeof(u16));
	finfo->freq_num = size;

	/*send user how many die ipu freq we can send*/
	/*copy shorter length of die to ipu freq user*/
	ret = cndev_cp_less_val(
			&finfo->die_ipu_cnt, info.die_ipu_freq.die_ipu_cnt,
			finfo->die_ipu_freq, info.die_ipu_freq.ipu_freq, sizeof(u32));
	finfo->die_ipu_cnt = info.die_ipu_freq.die_ipu_cnt;
	return ret;
}
int cndev_card_powercapping_pigeon(void *cset,
	struct cndev_powercapping_s *pcinfo)
{
	struct power_capping_info *mcu_param;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	u16 vcard;

	vcard = (pcinfo->head.card >> 8) & 0x0f;
	if (vcard)
		return -ENODEV;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	pcinfo->head.version = CNDEV_CURRENT_VER;
	pcinfo->head.real_size = sizeof(struct cndev_powercapping_s);

	mcu_param = (struct power_capping_info *)&pcinfo->ops_type;

	/* TODO: SET/GET POWER CAPPING*/
	return 0;
}

int cndev_start_pigeon_edge(void *cset)
{
	int in_len = 0;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int ret = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	if (IS_ERR_OR_NULL(cndev_set->endpoint)) {
		cn_ce_dev_cndev_err(cndev_set, "cndev commu endpoint null");
		return -EINVAL;
	}

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_host_start",
			NULL, 0,
			NULL, &in_len, 0);

	if (ret < 0) {
		cn_ce_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
	}

	return ret;
}

int cndev_do_exit_pigeon_edge(void *cset)
{
	int in_len = 0;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int ret = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	if (IS_ERR_OR_NULL(cndev_set->endpoint)) {
		cn_ce_dev_cndev_err(cndev_set, "cndev commu endpoint null");
		return -EINVAL;
	}

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;
	ret = __pmu_call_rpc(core, cndev_set->endpoint,
			"rpc_cndev_do_exit",
			NULL, 0,
			NULL, &in_len, 0);

	if (ret < 0) {
		cn_ce_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
	}

	return 0;
}

static const struct cn_cndev_ioctl cndev_pigeon_ioctl = {
	.card_info_fill = card_info_fill_pigeon_common,
	.card_power_info = card_power_info_pigeon,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = NULL,
	.card_vm_info = card_vm_info_pigeon,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = cndev_card_codecutil_info_common,
	.card_freq_info = cndev_card_freq_info_pigeon,
	.card_curbuslnk = NULL,
	.card_pciethroughput = NULL,
	.card_power_capping = NULL, // cndev_card_powercapping_pigeon,
	.card_ipufreq_set = card_ipufreq_set_pigeon,
	.card_ncs_version = NULL,
	.card_ncs_state = NULL,
	.card_ncs_speed = NULL,
	.card_ncs_capability = NULL,
	.card_ncs_counter = NULL,
	.card_ncs_remote = NULL,
	.card_reset_ncs_counter = NULL,
	.card_chassis_info = NULL,
	.card_qos_reset = NULL,
	.card_qos_info = NULL,
	.card_qos_desc = NULL,
	.card_set_qos = NULL,
	.card_set_qos_group = NULL,
	.card_acpuutil_info = cndev_card_acpuutil_info_common,
	.card_acpuutil_timer = cndev_card_acpuutil_timer_common,
	.card_get_retire_pages = NULL,
	.card_get_retire_status = NULL,
	.card_get_retire_remapped_rows = NULL,
	.card_retire_switch = NULL,
	.card_ncs_port_config = NULL,
	.card_mlulink_switch_ctrl = NULL,
	.card_ipufreq_ctrl = NULL,
	.card_get_ncs_info = card_get_ncs_info_common,
	.card_get_card_info_ext = NULL,
	.card_get_process_iputil = NULL,
	.card_get_process_codecutil = NULL,
	.card_get_feature = cndev_card_get_feature_common,
	.card_set_feature = cndev_card_set_feature_common,
	.card_get_mim_profile_info = NULL,
	.card_get_mim_possible_place_info = NULL,
	.card_get_mim_vmlu_capacity_info = NULL,
	.card_get_mim_device_info = NULL,
	.card_get_desc_info = NULL,
	.card_get_cntr_info = NULL,
	.chassis_power_info = NULL,
	.card_get_smlu_profile_id = NULL,
	.card_get_smlu_profile_info = NULL,
	.card_new_smlu_profile = NULL,
	.card_delete_smlu_profile = NULL,
};

static const struct cn_cndev_ioctl cndev_pigeon_edge_ioctl = {
	.card_info_fill = card_info_fill_pigeon_common,
	.card_power_info = card_power_info_pigeon,
	.card_memory_info = cndev_card_memory_info_common,
	.user_proc_info = cndev_user_proc_info_common,
	.card_health_state = cndev_card_health_status_common,
	.card_ecc_info = NULL,
	.card_vm_info = card_vm_info_pigeon,
	.card_ipuutil_info = cndev_card_ipuutil_info_common,
	.card_codecutil_info = cndev_card_codecutil_info_common,
	.card_freq_info = cndev_card_freq_info_pigeon,
	.card_curbuslnk = NULL,
	.card_pciethroughput = NULL,
	.card_power_capping = NULL, //cndev_card_powercapping_pigeon,
	.card_ipufreq_set = card_ipufreq_set_pigeon,
	.card_ncs_version = NULL,
	.card_ncs_state = NULL,
	.card_ncs_speed = NULL,
	.card_ncs_capability = NULL,
	.card_ncs_counter = NULL,
	.card_ncs_remote = NULL,
	.card_reset_ncs_counter = NULL,
	.card_chassis_info = NULL,
	.card_qos_reset = NULL,
	.card_qos_info = NULL,
	.card_qos_desc = NULL,
	.card_set_qos = NULL,
	.card_set_qos_group = NULL,
	.card_acpuutil_info = cndev_card_acpuutil_info_common,
	.card_acpuutil_timer = cndev_card_acpuutil_timer_common,
	.card_get_retire_pages = NULL,
	.card_get_retire_status = NULL,
	.card_get_retire_remapped_rows = NULL,
	.card_retire_switch = NULL,
	.card_ncs_port_config = NULL,
	.card_mlulink_switch_ctrl = NULL,
	.card_ipufreq_ctrl = NULL,
	.card_get_ncs_info = card_get_ncs_info_common,
	.card_get_card_info_ext = NULL,
	.card_get_process_iputil = NULL,
	.card_get_process_codecutil = NULL,
	.card_get_feature = cndev_card_get_feature_common,
	.card_set_feature = cndev_card_set_feature_common,
	.card_get_mim_profile_info = NULL,
	.card_get_mim_possible_place_info = NULL,
	.card_get_mim_vmlu_capacity_info = NULL,
	.card_get_mim_device_info = NULL,
	.card_get_desc_info = NULL,
	.card_get_cntr_info = NULL,
	.chassis_power_info = NULL,
	.card_get_smlu_profile_id = NULL,
	.card_get_smlu_profile_info = NULL,
	.card_new_smlu_profile = NULL,
	.card_delete_smlu_profile = NULL,
};

int cndev_lateinit_pigeon(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;
	int ret = 0;
	struct cndev_ipufreq_set setinfo = {};
	struct cn_board_info *pbrdinfo = &core->board_info;
	u64 chip_type = 0;

	ret = cndev_rpc_client_register(pcore);
	if (ret) {
		cn_ce_dev_cndev_err(cndev_set, "cndev rpc call commu register failed");
		goto out;
	}

	ret = cndev_rpc_resource(cndev_set);
	if (ret) {
		cn_ce_dev_cndev_err(cndev_set, "cndev get resource failed");
	} else {
		cn_attr_get_resource(core, RES_CHIP_ID, &chip_type);
		pbrdinfo->chip_type = chip_type;
		if ((pbrdinfo->chip_type == CN_CHIP_ID_PIGEONC) ||
			(pbrdinfo->chip_type == CN_CHIP_ID_1V_2302)) {
			setinfo.ipu_freq = 1000;
			setinfo.ctrl_mode = ALL;
			card_ipufreq_set_pigeon(cndev_set, &setinfo);
		}
	}

out:
	return ret;
}

static const struct cn_cndev_ops cndev_pigeon_ops = {
	.cndev_start = cndev_start_common,
	.cndev_do_exit = cndev_do_exit_common,
	.cndev_lateinit = cndev_lateinit_pigeon,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_common,
	.cndev_exit = cndev_exit_common,
};

static const struct cn_cndev_ops cndev_pigeon_edge_ops = {

	.cndev_start = cndev_start_pigeon_edge,
	.cndev_do_exit = cndev_do_exit_pigeon_edge,
	.cndev_lateinit = cndev_lateinit_common,
	.cndev_restart = cndev_restart_common,
	.cndev_stop = cndev_stop_common,
	.cndev_exit = cndev_exit_common,
};

int cndev_init_pigeon(struct cn_cndev_set *cndev_set)
{
	cn_ce_dev_cndev_info(cndev_set, "cndev init");

	switch (cndev_set->device_id) {
	case MLUID_PIGEON:
		cndev_set->ops = &cndev_pigeon_ops;
		// cndev_set->ops = &cndev_pigeon_ops;
		cndev_set->ioctl = &cndev_pigeon_ioctl;
		break;
	case MLUID_PIGEON_EDGE:
		cndev_set->ops = &cndev_pigeon_ops;
		// cndev_set->ops = &cndev_pigeon_edge_ops;
		cndev_set->ioctl = &cndev_pigeon_edge_ioctl;
		break;
	default:
		break;
	}

	cndev_common_init(cndev_set);

	return 0;
}
