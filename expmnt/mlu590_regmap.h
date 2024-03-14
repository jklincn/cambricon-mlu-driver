#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_ioctl.h"
#include "exp_mgnt_private.h"

static int check_590(struct cn_core_set *core, unsigned int index)
{
	return 1;
}

struct cndump_reg_map mlu590_regmap[] = {
	{"TOP_Bar00_DATA_Intr:",  0x949200, 0x949200, 0, NULL},
	{"TOP_Bar00_CFG_Intr:",   0x949204, 0x949204, 0, NULL},
	{"TOP_Bar01_DATA_Intr:",  0x94a200, 0x94a200, 0, NULL},
	{"TOP_Bar10_DATA_Intr:",  0x94b100, 0x94b100, 0, NULL},
	{"TOP_Bar11_DATA_Intr:",  0x94c100, 0x94c100, 0, NULL},
	{"TOP_Bar20_DATA_Intr:",  0x94d100, 0x94d100, 0, NULL},
	{"TOP_Bar21_DATA_Intr:",  0x94e100, 0x94e100, 0, NULL},
	{"TOP_Bar30_DATA_Intr:",  0x94f200, 0x94f200, 0, NULL},
	{"TOP_Bar31_DATA_Intr:",  0x950200, 0x950200, 0, NULL},
	{"TOP_Middle00_0_Intr:",  0x95104c, 0x95104c, 0, NULL},
	{"TOP_Middle00_1_Intr:",  0x951058, 0x951058, 0, NULL},
	{"TOP_Middle10_0_Intr:",  0x957028, 0x957028, 0, NULL},
	{"TOP_Middle10_1_Intr:",  0x957060, 0x957060, 0, NULL},
	{"TOP_Middle05_Intr:",    0x956038, 0x956038, 0, NULL},
	{"TOP_Middle15_0_Intr:",  0x95c070, 0x95c070, 0, NULL},
	{"TOP_Middle15_1_Intr:",  0x95c07c, 0x95c07c, 0, NULL},
	{"TOP_South0_DATA_Intr:", 0x946100, 0x946100, 0, NULL},
	{"TOP_South1_DATA_Intr:", 0x947100, 0x947100, 0, NULL},
	{"TOP_South1_CFG_Intr:",  0x94710c, 0x94710c, 0, NULL},
	{"TOP_South2_DATA_Intr:", 0x948100, 0x948100, 0, NULL},
	{"TOP_West0_DATA_Intr:",  0x943124, 0x943124, 0, NULL},
	{"TOP_West1_DATA_Intr:",  0x944124, 0x944124, 0, NULL},
	{"TOP_West2_DATA_Intr:",  0x945120, 0x945120, 0, NULL},
	{"TOP_Eest0_DATA_Intr:",  0x940124, 0x940128, 0, NULL},
	{"TOP_Eest1_DATA_Intr:",  0x941124, 0x941124, 0, NULL},
	{"TOP_Eest2_DATA_Intr:",  0x942120, 0x942120, 0, NULL},
	{"TOP_Bar00_Data_Idle:",  0x949014, 0x949014, 0, NULL},
	{"TOP_Bar00_CFG_Idle:",   0x949018, 0x949018, 0, NULL},
	{"TOP_Bar01_DATA_Idle:",  0x94a014, 0x94a014, 0, NULL},
	{"TOP_Bar10_DATA_Idle:",  0x94b028, 0x94b028, 0, NULL},
	{"TOP_Bar11_DATA_Idle:",  0x94c02c, 0x94c02c, 0, NULL},
	{"TOP_Bar20_DATA_Idle:",  0x94d02c, 0x94d02c, 0, NULL},
	{"TOP_Bar21_DATA_Idle:",  0x94e028, 0x94e028, 0, NULL},
	{"TOP_Bar30_DATA_Idle:",  0x94f014, 0x94f014, 0, NULL},
	{"TOP_Bar31_DATA_Idle:",  0x950014, 0x950014, 0, NULL},
	{"TOP_Middle00_Idle:",    0x951068, 0x951068, 0, NULL},
	{"TOP_Middle10_0_Idle:",  0x957034, 0x957034, 0, NULL},
	{"TOP_Middle10_1_Idle:",  0x95706c, 0x95706c, 0, NULL},
	{"TOP_Middle05_Idle:",    0x956044, 0x956044, 0, NULL},
	{"TOP_Middle15_0_Idle:",  0x95c034, 0x95c034, 0, NULL},
	{"TOP_Middle15_1_Idle:",  0x95c08c, 0x95c08c, 0, NULL},
	{"TOP_South0_Data_Idle:", 0x946014, 0x946014, 0, NULL},
	{"TOP_South1_Data_Idle:", 0x947018, 0x947018, 0, NULL},
	{"TOP_South1_CFG_Idle:",  0x94701c, 0x94701c, 0, NULL},
	{"TOP_South2_Data_Idle:", 0x948014, 0x948014, 0, NULL},
	{"TOP_West0_DATA_Idle:",  0x94300c, 0x94300c, 0, NULL},
	{"TOP_West1_DATA_Idle:",  0x944010, 0x944010, 0, NULL},
	{"TOP_West2_DATA_Idle:",  0x94500c, 0x94500c, 0, NULL},
	{"TOP_Eest0_DATA_Idle:",  0x94000c, 0x94000c, 0, NULL},
	{"TOP_Eest1_DATA_Idle:",  0x941010, 0x941010, 0, NULL},
	{"TOP_Eest2_DATA_Idle:",  0x94200c, 0x94200c, 0, NULL},
	{"PCIE_GIC:",             0x5040, 0x5080, 0, NULL},
	{"PCIE_Counter:",         0x580a0, 0x58174, 0, check_590},
	{"PCIE_Slave_Bridge:", 0x19db130, 0x19db138, 0, NULL},
	{"PCIE_Slave_Bridge:", 0x19da130, 0x19da138, 0, NULL},
	{"TOP_South_CSR:",     0x19840b0, 0x19840c8, 0, NULL},
	{"CPU:", 0x800180, 0x8001b0, 0, NULL},
	{"CPU:", 0x800104, 0x800108, 0, NULL},
	{"CPU:", 0x8001E0, 0x800210, 0, NULL},
	{"CPU:", 0x800360, 0x8003fc, 0, NULL},
	{"CPU:", 0x800240, 0x80024c, 0, NULL}
};


