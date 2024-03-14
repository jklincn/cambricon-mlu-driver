#include "cndrv_qos.h"
#include "qos_inter.h"
/* 200s common configuration */
struct cndev_qos_setting_s mlu2x0_qos_setting = {
	MAX_QOS_BASE, MAX_QOS_UP, MIN_QOS_BASE, MIN_QOS_UP, CNDEV_QOS_MAX
};

/* 220 edge configuration */
struct cndev_qos_setting_s mlu220e_qos_setting = {
	MAX_QOS_BASE, MAX_QOS_UP, MIN_QOS_BASE, MIN_QOS_UP, 2
};

/* 370 edge configuration */
struct cndev_qos_setting_s mlu370_qos_setting = {
	MAX_QOS_BASE, MAX_QOS_UP, MIN_QOS_BASE, MIN_QOS_UP, CNDEV_QOS_MAX
};

struct cndev_qos_setting_s ce3226_qos_setting = {
	CE3226_MAX_QOS_BASE, CE3226_MAX_QOS_UP, CE3226_MIN_QOS_BASE, CE3226_MIN_QOS_UP, CNDEV_QOS_MAX
};

/*270 qos master config*/
struct cndev_qos_info_s mlu270_ipu_qos_info[4] = {
	{255, 3, 12, MLU270_IPU0, "IPU0"}, // IPU0
	{255, 3, 12, MLU270_IPU1, "IPU1"}, // IPU1
	{255, 3, 12, MLU270_IPU2, "IPU2"}, // IPU2
	{255, 3, 12, MLU270_IPU3, "IPU3"} // IPU3
};
struct cndev_qos_info_s mlu270_vpu_qos_info[6] = {
	{255, 3, 3, MLU270_VPU0, "VPU0"}, // VPU0
	{255, 3, 3, MLU270_VPU1, "VPU1"}, // VPU1
	{255, 3, 3, MLU270_VPU2, "VPU2"}, // VPU2
	{255, 3, 3, MLU270_VPU3, "VPU3"}, // VPU3
	{255, 3, 3, MLU270_VPU4, "VPU4"}, // VPU4
	{255, 3, 3, MLU270_VPU5, "VPU5"} // VPU5
};

struct cndev_qos_info_s mlu270_pcie_qos_info[1] = {
	{255, 3, 3, MLU270_PCIE, "PCIE"}, // PCIE
};

struct cndev_qos_info_s mlu370_vpu_qos_info[40] = {
	{255, 3, 3, MLU370_VPU0_P0, "D0_VPU0_P0"},
	{255, 3, 3, MLU370_VPU0_P1, "D0_VPU0_P1"},
	{255, 3, 3, MLU370_VPU0_P2, "D0_VPU0_P2"},
	{255, 3, 3, MLU370_VPU0_P3, "D0_VPU0_P3"},
	{255, 3, 3, MLU370_VPU1_P0, "D0_VPU1_P0"},
	{255, 3, 3, MLU370_VPU1_P1, "D0_VPU1_P1"},
	{255, 3, 3, MLU370_VPU1_P2, "D0_VPU1_P2"},
	{255, 3, 3, MLU370_VPU1_P3, "D0_VPU1_P3"},
	{255, 3, 3, MLU370_VPU2_P0, "D0_VPU2_P0"},
	{255, 3, 3, MLU370_VPU2_P1, "D0_VPU2_P1"},
	{255, 3, 3, MLU370_VPU2_P2, "D0_VPU2_P2"},
	{255, 3, 3, MLU370_VPU2_P3, "D0_VPU2_P3"},
	{255, 3, 3, MLU370_VPU3_P0, "D0_VPU3_P0"},
	{255, 3, 3, MLU370_VPU3_P1, "D0_VPU3_P1"},
	{255, 3, 3, MLU370_VPU3_P2, "D0_VPU3_P2"},
	{255, 3, 3, MLU370_VPU3_P3, "D0_VPU3_P3"},
	{255, 3, 3, MLU370_VPU4_P0, "D0_VPU4_P0"},
	{255, 3, 3, MLU370_VPU4_P1, "D0_VPU4_P1"},
	{255, 3, 3, MLU370_VPU4_P2, "D0_VPU4_P2"},
	{255, 3, 3, MLU370_VPU4_P3, "D0_VPU4_P3"},

	{255, 3, 3, MLU370_D1_VPU0_P0, "D1_VPU0_P0"},
	{255, 3, 3, MLU370_D1_VPU0_P1, "D1_VPU0_P1"},
	{255, 3, 3, MLU370_D1_VPU0_P2, "D1_VPU0_P2"},
	{255, 3, 3, MLU370_D1_VPU0_P3, "D1_VPU0_P3"},
	{255, 3, 3, MLU370_D1_VPU1_P0, "D1_VPU1_P0"},
	{255, 3, 3, MLU370_D1_VPU1_P1, "D1_VPU1_P1"},
	{255, 3, 3, MLU370_D1_VPU1_P2, "D1_VPU1_P2"},
	{255, 3, 3, MLU370_D1_VPU1_P3, "D1_VPU1_P3"},
	{255, 3, 3, MLU370_D1_VPU2_P0, "D1_VPU2_P0"},
	{255, 3, 3, MLU370_D1_VPU2_P1, "D1_VPU2_P1"},
	{255, 3, 3, MLU370_D1_VPU2_P2, "D1_VPU2_P2"},
	{255, 3, 3, MLU370_D1_VPU2_P3, "D1_VPU2_P3"},
	{255, 3, 3, MLU370_D1_VPU3_P0, "D1_VPU3_P0"},
	{255, 3, 3, MLU370_D1_VPU3_P1, "D1_VPU3_P1"},
	{255, 3, 3, MLU370_D1_VPU3_P2, "D1_VPU3_P2"},
	{255, 3, 3, MLU370_D1_VPU3_P3, "D1_VPU3_P3"},
	{255, 3, 3, MLU370_D1_VPU4_P0, "D1_VPU4_P0"},
	{255, 3, 3, MLU370_D1_VPU4_P1, "D1_VPU4_P1"},
	{255, 3, 3, MLU370_D1_VPU4_P2, "D1_VPU4_P2"},
	{255, 3, 3, MLU370_D1_VPU4_P3, "D1_VPU4_P3"},
};

struct cndev_qos_info_s mlu370_ipu_qos_info[32] = {
	{255, 3, 3, MLU370_IPU_BAR0_M02_P0, "D0_IPU_BAR0_M02_P0"},
	{255, 3, 3, MLU370_IPU_BAR0_M02_P1, "D0_IPU_BAR0_M02_P1"},
	{255, 3, 3, MLU370_IPU_BAR0_M02_P2, "D0_IPU_BAR0_M02_P2"},
	{255, 3, 3, MLU370_IPU_BAR0_M02_P3, "D0_IPU_BAR0_M02_P3"},

	{255, 3, 3, MLU370_IPU_BAR0_M13_P0, "D0_IPU_BAR0_M13_P0"},
	{255, 3, 3, MLU370_IPU_BAR0_M13_P1, "D0_IPU_BAR0_M13_P1"},
	{255, 3, 3, MLU370_IPU_BAR0_M13_P2, "D0_IPU_BAR0_M13_P2"},
	{255, 3, 3, MLU370_IPU_BAR0_M13_P3, "D0_IPU_BAR0_M13_P3"},

	{255, 3, 3, MLU370_IPU_BAR1_M04_P0, "D0_IPU_BAR1_M04_P0"},
	{255, 3, 3, MLU370_IPU_BAR1_M04_P1, "D0_IPU_BAR1_M04_P1"},
	{255, 3, 3, MLU370_IPU_BAR1_M04_P2, "D0_IPU_BAR1_M04_P2"},
	{255, 3, 3, MLU370_IPU_BAR1_M04_P3, "D0_IPU_BAR1_M04_P3"},

	{255, 3, 3, MLU370_IPU_BAR1_M15_P0, "D0_IPU_BAR1_M15_P0"},
	{255, 3, 3, MLU370_IPU_BAR1_M15_P1, "D0_IPU_BAR1_M15_P1"},
	{255, 3, 3, MLU370_IPU_BAR1_M15_P2, "D0_IPU_BAR1_M15_P2"},
	{255, 3, 3, MLU370_IPU_BAR1_M15_P3, "D0_IPU_BAR1_M15_P3"},

	{255, 3, 3, MLU370_IPU_D1_BAR0_M02_P0, "D1_IPU_BAR0_M02_P0"},
	{255, 3, 3, MLU370_IPU_D1_BAR0_M02_P1, "D1_IPU_BAR0_M02_P1"},
	{255, 3, 3, MLU370_IPU_D1_BAR0_M02_P2, "D1_IPU_BAR0_M02_P2"},
	{255, 3, 3, MLU370_IPU_D1_BAR0_M02_P3, "D1_IPU_BAR0_M02_P3"},

	{255, 3, 3, MLU370_IPU_D1_BAR0_M13_P0, "D1_IPU_BAR0_M13_P0"},
	{255, 3, 3, MLU370_IPU_D1_BAR0_M13_P1, "D1_IPU_BAR0_M13_P1"},
	{255, 3, 3, MLU370_IPU_D1_BAR0_M13_P2, "D1_IPU_BAR0_M13_P2"},
	{255, 3, 3, MLU370_IPU_D1_BAR0_M13_P3, "D1_IPU_BAR0_M13_P3"},

	{255, 3, 3, MLU370_IPU_D1_BAR1_M04_P0, "D1_IPU_BAR1_M04_P0"},
	{255, 3, 3, MLU370_IPU_D1_BAR1_M04_P1, "D1_IPU_BAR1_M04_P1"},
	{255, 3, 3, MLU370_IPU_D1_BAR1_M04_P2, "D1_IPU_BAR1_M04_P2"},
	{255, 3, 3, MLU370_IPU_D1_BAR1_M04_P3, "D1_IPU_BAR1_M04_P3"},

	{255, 3, 3, MLU370_IPU_D1_BAR1_M15_P0, "D1_IPU_BAR1_M15_P0"},
	{255, 3, 3, MLU370_IPU_D1_BAR1_M15_P1, "D1_IPU_BAR1_M15_P1"},
	{255, 3, 3, MLU370_IPU_D1_BAR1_M15_P2, "D1_IPU_BAR1_M15_P2"},
	{255, 3, 3, MLU370_IPU_D1_BAR1_M15_P3, "D1_IPU_BAR1_M15_P3"},
};

struct cndev_qos_info_s mlu370_pcie_qos_info[8] = {
	{255, 3, 3, MLU370_PCIE_0, "D0_PCIE0"}, // PCIE0
	{255, 3, 3, MLU370_PCIE_1, "D0_PCIE1"}, // PCIE1
	{255, 3, 3, MLU370_PCIE_2, "D0_PCIE2"}, // PCIE2
	{255, 3, 3, MLU370_PCIE_3, "D0_PCIE3"}, // PCIE3
	{255, 3, 3, MLU370_D1_PCIE_0, "D1_PCIE0"}, // PCIE0
	{255, 3, 3, MLU370_D1_PCIE_1, "D1_PCIE1"}, // PCIE1
	{255, 3, 3, MLU370_D1_PCIE_2, "D1_PCIE2"}, // PCIE2
	{255, 3, 3, MLU370_D1_PCIE_3, "D1_PCIE3"}, // PCIE3
};

/*220 qos master config*/
struct cndev_qos_info_s mlu220_ipu_qos_info[1] = {
	{255, 3, 12, MLU220_IPU0, "IPU"}, // IPU
};
struct cndev_qos_info_s mlu220_vpu_qos_info[2] = {
	{255, 3, 3, MLU220_VPU0, "VPU0"}, // VPU0
	{255, 3, 3, MLU220_VPU1, "VPU1"} // VPU1
};

struct cndev_qos_info_s mlu220_pcie_qos_info[2] = {
	{255, 3, 3, MLU220_PCIE0, "PCIE0"}, // PCIE0
	{255, 3, 3, MLU220_PCIE1, "PCIE1"} // PCIE1
};

/*290 qos master config*/
struct cndev_qos_info_s mlu290_ipu_qos_info[16] = {
	{255, 3, 3, MLU290_L0_IPU_CROSS_0_U_0, "L0_IPU_CROSS0_U0"}, //L0 IPU CROSS 0 U 0
	{255, 3, 3, MLU290_L0_IPU_CROSS_0_U_1, "L0_IPU_CROSS0_U1"}, //L0 IPU CROSS 0 U 1
	{255, 3, 3, MLU290_L0_IPU_CROSS_1_U_0, "L0_IPU_CROSS1_U0"}, //L0 IPU CROSS 1 U 0
	{255, 3, 3, MLU290_L0_IPU_CROSS_1_U_1, "L0_IPU_CROSS1_U1"}, //L0 IPU CROSS 1 U 1
	{255, 3, 3, MLU290_L0_IPU_CROSS_2_U_0, "L0_IPU_CROSS2_U0"}, //L0 IPU CROSS 2 U 0
	{255, 3, 3, MLU290_L0_IPU_CROSS_2_U_1, "L0_IPU_CROSS2_U1"}, //L0 IPU CROSS 2 U 1
	{255, 3, 3, MLU290_L0_IPU_CROSS_3_U_0, "L0_IPU_CROSS3_U0"}, //L0 IPU CROSS 3 U 0
	{255, 3, 3, MLU290_L0_IPU_CROSS_3_U_1, "L0_IPU_CROSS3_U1"}, //L0 IPU CROSS 3 U 1

	{255, 3, 3, MLU290_L1_IPU_CROSS_0_U_0, "L1_IPU_CROSS0_U0"}, //L1 IPU CROSS 0 U 0
	{255, 3, 3, MLU290_L1_IPU_CROSS_0_U_1, "L1_IPU_CROSS0_U1"}, //L1 IPU CROSS 0 U 1
	{255, 3, 3, MLU290_L1_IPU_CROSS_1_U_0, "L1_IPU_CROSS1_U0"}, //L1 IPU CROSS 1 U 0
	{255, 3, 3, MLU290_L1_IPU_CROSS_1_U_1, "L1_IPU_CROSS1_U1"}, //L1 IPU CROSS 1 U 1
	{255, 3, 3, MLU290_L1_IPU_CROSS_2_U_0, "L1_IPU_CROSS2_U0"}, //L1 IPU CROSS 2 U 0
	{255, 3, 3, MLU290_L1_IPU_CROSS_2_U_1, "L1_IPU_CROSS2_U1"}, //L1 IPU CROSS 2 U 1
	{255, 3, 3, MLU290_L1_IPU_CROSS_3_U_0, "L1_IPU_CROSS3_U0"}, //L1 IPU CROSS 3 U 0
	{255, 3, 3, MLU290_L1_IPU_CROSS_3_U_1, "L1_IPU_CROSS3_U1"}, //L1 IPU CROSS 3 U 1
};
struct cndev_qos_info_s mlu290_vpu_qos_info[8] = {
	{255, 3, 3, MLU290_L0_VPU_0, "L0_VPU0"}, // VPU0
	{255, 3, 3, MLU290_L0_VPU_2, "L0_VPU2"}, // VPU2
	{255, 3, 3, MLU290_L0_VPU_4, "L0_VPU4"}, // VPU4
	{255, 3, 3, MLU290_L1_VPU_1, "L1_VPU1"}, // VPU1
	{255, 3, 3, MLU290_L1_VPU_3, "L1_VPU3"}, // VPU3
	{255, 3, 3, MLU290_L1_VPU_5, "L1_VPU5"}, // VPU5
	{255, 3, 3, MLU290_L1_VPU_6, "L1_VPU6"}, // VPU6
	{255, 3, 3, MLU290_L1_VPU_7, "L1_VPU7"}, // VPU7
};

struct cndev_qos_info_s mlu290_pcie_qos_info[1] = {
	{255, 3, 3, MLU290_PCIE, "PCIE"}, // PCIE
};


/* QOS DATA STRUCT DEFINE */
struct cndev_qos_data_s mlu220_qos_infos[CNDEV_QOS_MAX] = {
	{mlu220_ipu_qos_info, 1},
	{mlu220_vpu_qos_info, 2},
	{mlu220_pcie_qos_info, 2},
};

struct cndev_qos_data_s mlu220e_qos_infos[2] = {
	{mlu220_ipu_qos_info, 1},
	{mlu220_pcie_qos_info, 2},
};

struct cndev_qos_data_s mlu270_qos_infos[CNDEV_QOS_MAX] = {
	{mlu270_ipu_qos_info, 4},
	{mlu270_vpu_qos_info, 6},
	{mlu270_pcie_qos_info, 1},
};
struct cndev_qos_data_s mlu290_qos_infos[CNDEV_QOS_MAX] = {
	{mlu290_ipu_qos_info, 16},
	{mlu290_vpu_qos_info, 8},
	{mlu290_pcie_qos_info, 1},
};

struct cndev_qos_data_s mlu370_qos_infos[CNDEV_QOS_MAX] = {
	{mlu370_ipu_qos_info, 16},
	{mlu370_vpu_qos_info, 20},
	{mlu370_pcie_qos_info, 4},
};

struct cndev_qos_info_s ce3226_ipu_qos_info[2] = {
	{0x1FFF, 0, 0x1000, CE3226_IPU0, "D0_IPU"}, // IPU0
	{0x1FFF, 0, 0x1000, CE3226_D1_IPU0, "D1_IPU"}, // IPU0
};
struct cndev_qos_info_s ce3226_vpu_qos_info[4] = {
	{0x1FFF, 0, 0x800, CE3226_VDEC, "D0_VDEC"}, // VDEC
	{0x1FFF, 0, 0x800, CE3226_VENC, "D0_VENC"}, // VENC
	{0x1FFF, 0, 0x800, CE3226_D1_VDEC, "D1_VDEC"}, // VDEC
	{0x1FFF, 0, 0x800, CE3226_D1_VENC, "D1_VENC"}, // VENC
};

struct cndev_qos_info_s ce3226_pcie_qos_info[2] = {
	{0x1FFF, 0, 0x800, CE3226_PCIE, "D0_PCIE"}, // PCIE
	{0x1FFF, 0, 0x800, CE3226_D1_PCIE, "D1_PCIE"}, // PCIE
};

struct cndev_qos_data_s ce3226_qos_infos[CNDEV_QOS_MAX] = {
	{ce3226_ipu_qos_info, 1},
	{ce3226_vpu_qos_info, 2},
	{ce3226_pcie_qos_info, 1},
};
