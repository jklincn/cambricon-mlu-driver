#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_ioctl.h"
#include "exp_mgnt_private.h"

static int check_580(struct cn_core_set *core, unsigned int index)
{
	return 1;
}

struct cndump_reg_map mlu580_regmap[] = {
	{"TOP_Bar00_DATA_Intr:",  0x290200, 0x290200, 0, NULL},
	{"TOP_Bar00_CFG_Intr:",   0x290204, 0x290204, 0, NULL},
	{"TOP_Bar01_DATA_Intr:",  0x1a30200, 0x1a30200, 0, NULL},
	{"TOP_Bar10_DATA_Intr:",  0x1c20100, 0x1c20100, 0, NULL},
	{"TOP_Bar11_DATA_Intr:",  0x1e20100, 0x1e20100, 0, NULL},
	{"TOP_Bar20_DATA_Intr:",  0x2020100, 0x2020100, 0, NULL},
	{"TOP_Bar21_DATA_Intr:",  0x2220100, 0x2220100, 0, NULL},
	{"TOP_Bar30_DATA_Intr:",  0x2430200, 0x2430200, 0, NULL},
	{"TOP_Bar31_DATA_Intr:",  0x2620200, 0x2620200, 0, NULL},
	{"TOP_Middle0_Intr:",     0xa80120, 0xa80120, 0, NULL},
	{"TOP_Middle1_Intr:",     0xc80120, 0xc80120, 0, NULL},
	{"TOP_Middle2_Intr:",     0xe80120, 0xe80120, 0, NULL},
	{"TOP_Middle6_Intr:",     0x1680120, 0x1680120, 0, NULL},
	{"TOP_Middle7_Intr:",     0x1880120, 0x1880120, 0, NULL},
	{"TOP_South0_DATA_Intr:", 0x400078, 0x400078, 0, NULL},
	{"TOP_South0_CFG_Intr:",  0x400094, 0x400094, 0, NULL},
	{"TOP_South1_DATA_Intr:", 0x600064, 0x600064, 0, NULL},
	{"TOP_South1_CFG_Intr:",  0x600074, 0x600074, 0, NULL},
	{"TOP_West2_DATA_Intr:",  0x3010050, 0x3010050, 0, NULL},
	{"TOP_West4_DATA_Intr:",  0x2800038, 0x2800038, 0, NULL},
	{"TOP_Eest2_DATA_Intr:",  0x3810050, 0x3810050, 0, NULL},
	{"TOP_Eest4_DATA_Intr:",  0x2a00038, 0x2a00038, 0, NULL},
	{"TOP_Bar00_Data_Idle:",  0x290014, 0x290014, 0, NULL},
	{"TOP_Bar00_CFG_Idle:",   0x290018, 0x290018, 0, NULL},
	{"TOP_Bar01_DATA_Idle:",  0x1a30014, 0x1a30014, 0, NULL},
	{"TOP_Bar10_DATA_Idle:",  0x1c20028, 0x1c20028, 0, NULL},
	{"TOP_Bar11_DATA_Idle:",  0x1e2002c, 0x1e2002c, 0, NULL},
	{"TOP_Bar20_DATA_Idle:",  0x202002c, 0x202002c, 0, NULL},
	{"TOP_Bar21_DATA_Idle:",  0x2220028, 0x2220028, 0, NULL},
	{"TOP_Bar30_DATA_Idle:",  0x2430014, 0x2430014, 0, NULL},
	{"TOP_Bar31_DATA_Idle:",  0x2620014, 0x2620014, 0, NULL},
	{"TOP_Middle0_Idle:",     0xa80010, 0xa80010, 0, NULL},
	{"TOP_Middle1_Idle:",     0xc80010, 0xc80010, 0, NULL},
	{"TOP_Middle2_Idle:",     0xe80010, 0xe80010, 0, NULL},
	{"TOP_Middle6_Idle:",     0x1680010, 0x1680010, 0, NULL},
	{"TOP_Middle7_Idle:",     0x1880010, 0x1880010, 0, NULL},
	{"TOP_South0_Data_Idle:", 0x400018, 0x400018, 0, NULL},
	{"TOP_South0_CFG_Idle:",  0x40001c, 0x40001c, 0, NULL},
	{"TOP_South1_Data_Idle:", 0x600010, 0x600010, 0, NULL},
	{"TOP_South1_CFG_Idle:",  0x600014, 0x600014, 0, NULL},
	{"TOP_West2_DATA_Idle:",  0x3010010, 0x3010010, 0, NULL},
	{"TOP_West4_DATA_Idle:",  0x280000c, 0x280000c, 0, NULL},
	{"TOP_Eest2_DATA_Idle:",  0x3810010, 0x3810010, 0, NULL},
	{"TOP_Eest4_DATA_Idle:",  0x2a0000c, 0x2a0000c, 0, NULL},
	{"PCIE_GIC:", 0x5040, 0x5080, 0, NULL},
	{"PCIE_Counter:", 0x580a0, 0x58174, 0, check_580},
	{"CPU:", 0x800180, 0x8001b0, 0, NULL},
	{"CPU:", 0x800104, 0x800108, 0, NULL},
	{"CPU:", 0x8001E0, 0x800210, 0, NULL},
	{"CPU:", 0x800360, 0x8003fc, 0, NULL},
	{"CPU:", 0x800240, 0x80024c, 0, NULL}
};

