#ifndef __MCC_MODULE_PARAM__
#define __MCC_MODULE_PARAM__

enum LLCG_INTERLEAVE_MODE {
	LLCG_INTERLEAVE_MAP0 = 0,
	LLCG_INTERLEAVE_MAP1,
	LLCG_INTERLEAVE_MAP2,
	LLCG_INTERLEAVE_MAP3,
};

enum PARAM_CONFIG_EN {
	CONFIG_ENABLE = 0,
	CONFIG_DISABLE,
};

enum PARAM_INTERLEAVE_SIZE{
	INTERLEAVE_GRAN_512B = 0,
	INTERLEAVE_GRAN_1024B,
	INTERLEAVE_GRAN_2048B,
};

enum LLC_INTERLEAVE_MODE {
	LLC_INTERLEAVE_NUMS_0 = 0,
	LLC_INTERLEAVE_NUMS_2,
	LLC_INTERLEAVE_NUMS_4,
};

__attribute__((unused))
static const char *llcg_interleave_mode_name[4] = {
	[LLCG_INTERLEAVE_MAP0] = "map_0",
	[LLCG_INTERLEAVE_MAP1] = "map_1",
	[LLCG_INTERLEAVE_MAP2] = "map_2",
	[LLCG_INTERLEAVE_MAP3] = "map_3",
};

__attribute__((unused))
static const char *llc_interleave_mode_name[3] = {
	[LLC_INTERLEAVE_NUMS_0] = "no interleave",
	[LLC_INTERLEAVE_NUMS_2] = "2 llc interleave",
	[LLC_INTERLEAVE_NUMS_4] = "4 llc interleave",
};

__attribute__((unused))
static const char *llc_mode_en[2] = {
	[CONFIG_ENABLE] = "SET ENABLE",
	[CONFIG_DISABLE] = "SET DISABLE",
};

enum mcc_module_param_name {
	LLCG_INTERLEAVE_MODE,
	HBM_MEM_CHANNEL,
	LLCG_SHUFFLE_DIS,
	LLCG_INTERLEAVE_SIZE,
	LLC_INTERLEAVE_MODE,
	LLC_SHUFFLE_DIS,
	LLC_INTERLEAVE_SIZE,
	LLC_IPU_COMPRESS_DIS,
	LLC_COMPRESS_MODE,
	LLC_COMPRESS_HIGH_MODE,
	HBM_SIZE_LIMIT_COEF,
	SBE_RETIRE_ENABLE,
	MCC_PARAM_END,
};

void cambr_mcc_module_param_res_create(void);
unsigned int cambr_mcc_module_param_res_get(enum mcc_module_param_name param);
#endif
