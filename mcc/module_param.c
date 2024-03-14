#include <linux/module.h>
#include "module_param.h"
#include "cndrv_mcc.h"

/*llcg interleave mode use map3 default, use param to modify*/
static int cambr_llcg_interleave_mode = LLCG_INTERLEAVE_MAP3;
module_param_named(llcg_interleave_mode, cambr_llcg_interleave_mode, int, S_IRUGO | S_IWUSR | S_IWGRP);
/*mem channel*/
static int cambr_hbm_mem_channel = 0;
module_param_named(hbm_mem_channel, cambr_hbm_mem_channel, int, S_IRUGO | S_IWUSR | S_IWGRP);

/*llcg shuffle in enable default, use param to disable*/
static int cambr_llcg_shuffle_dis = CONFIG_ENABLE;
module_param_named(llcg_shuffle_dis, cambr_llcg_shuffle_dis, int, S_IRUGO | S_IWUSR | S_IWGRP);

/*llcg interleave_size is 512B, use param to set 2^llcg_interleave_size * 512 Byte,*/
static int cambr_llcg_interleave_size = INTERLEAVE_GRAN_512B;
module_param_named(llcg_interleave_size, cambr_llcg_interleave_size, int, S_IRUGO | S_IWUSR | S_IWGRP);

/*llcg interleave mode use map3 default, use param to modify*/
/*llc interleave mode in 4llc interleave default, use param to modify*/
static int cambr_llc_interleave_mode = LLC_INTERLEAVE_NUMS_4;
module_param_named(llc_interleave_mode, cambr_llc_interleave_mode, int, S_IRUGO | S_IWUSR | S_IWGRP);

/*llc shuffle in enable default, use param to disable*/
static int cambr_llc_shuffle_dis = CONFIG_ENABLE;
module_param_named(llc_shuffle_dis, cambr_llc_shuffle_dis, int, S_IRUGO | S_IWUSR | S_IWGRP);

/*llc interleave_size is 512B, use param to set 2^llcg_interleave_size * 512 Byte,*/
static int cambr_llc_interleave_size = INTERLEAVE_GRAN_512B;
module_param_named(llc_interleave_size, cambr_llc_interleave_size, int, S_IRUGO | S_IWUSR | S_IWGRP);

/*compress mode is default enable, use param to disable in llc and ipu*/
static int cambr_llc_ipu_compress_dis = CONFIG_ENABLE;
module_param_named(llc_ipu_compress_dis, cambr_llc_ipu_compress_dis, int, S_IRUGO | S_IWUSR | S_IWGRP);

/*llc default compress mode[2] to use set all memory non-differential, use 0 to
 * set low interweave and 1 to set high interweave*/
static int cambr_llc_compress_mode = LLC_ND_INTERLEAVE_COMPRESS;
module_param_named(llc_compress_mode, cambr_llc_compress_mode, int, S_IRUGO | S_IWUSR | S_IWGRP);

static int cambr_llc_compress_high_mode = LLC_COMPRESS_HIGH_MODE_ALL;
module_param_named(llc_compress_high_mode, cambr_llc_compress_high_mode, int, S_IRUGO | S_IWUSR | S_IWGRP);

static int cambr_hbm_size_limit_coef = MM_SIZE_ALL;
module_param_named(hbm_size_limit_coef, cambr_hbm_size_limit_coef, int, S_IRUGO | S_IWUSR | S_IWGRP);

static int cambr_sbe_retire = 0;
module_param_named(sbe_retire, cambr_sbe_retire, int, S_IRUGO | S_IWUSR | S_IWGRP);

static unsigned int mcc_module_param_res[MCC_PARAM_END];

void cambr_mcc_module_param_res_create(void)
{
	mcc_module_param_res[LLCG_INTERLEAVE_MODE] = cambr_llcg_interleave_mode;
	mcc_module_param_res[HBM_MEM_CHANNEL] = cambr_hbm_mem_channel;
	mcc_module_param_res[LLCG_SHUFFLE_DIS] = cambr_llcg_shuffle_dis;
	mcc_module_param_res[LLCG_INTERLEAVE_SIZE] = cambr_llcg_interleave_size;
	mcc_module_param_res[LLC_INTERLEAVE_MODE] = cambr_llc_interleave_mode;
	mcc_module_param_res[LLC_SHUFFLE_DIS] = cambr_llc_shuffle_dis;
	mcc_module_param_res[LLC_INTERLEAVE_SIZE] = cambr_llc_interleave_size;
	mcc_module_param_res[LLC_IPU_COMPRESS_DIS] = cambr_llc_ipu_compress_dis;
	mcc_module_param_res[LLC_COMPRESS_MODE] = cambr_llc_compress_mode;
	mcc_module_param_res[LLC_COMPRESS_HIGH_MODE] = cambr_llc_compress_high_mode;
	mcc_module_param_res[HBM_SIZE_LIMIT_COEF] = cambr_hbm_size_limit_coef;
	mcc_module_param_res[SBE_RETIRE_ENABLE] = cambr_sbe_retire;
}

unsigned int cambr_mcc_module_param_res_get(enum mcc_module_param_name param)
{
	if (param >= MCC_PARAM_END) {
		return -EINVAL;
	}
	return mcc_module_param_res[param];
}
