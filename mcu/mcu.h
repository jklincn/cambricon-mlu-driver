#ifndef __CAMBRICON_MCU_H__
#define __CAMBRICON_MCU_H__


#define PMU_IPU_FRAC_CUR_FBDIV          0x7108
#define PMU_IPU_FRAC_CUR_FRACDIV        0x710c
#define PMU_IPU_PLLCFG0                 0x7010

#define PMU_IPU_FRAC_CUR_FBDIV_MLU220   0x21408
#define PMU_IPU_FRAC_CUR_FRACDIV_MLU220 0x2140c
#define PMU_IPU_PLLCFG0_MLU220          0x21030

#define CHIP_VERSION_INFO	(0x5000)

/*update chip_ver ddr info*/
#define MCU_BASIC_INFO		(0x7490)
#define MCU_BASIC_INFO_MLU220		(0x20004)
#define MCU_UPDATE_SET_SHIFT	31
#define MCU_UPDATE_SET_MASK	0x01
#define MCU_DDRTRAINED_FLAG_SHIFT	30
#define MCU_DDRTRAINED_FLAG_MASK	0x01
#define MCU_DDRUPDATE_SET_SHIFT	29
#define MCU_DDRUPDATE_SET_MASK	0x01
#define MCU_DDRTRAINED_BUSY_SHIFT	28
#define MCU_DDRTRAINED_BUSY_MASK	0x01
#define MCU_CHIP_VERSION_SHIFT	20
#define MCU_CHIP_VERSION_MASK	0xFF
#define MCU_WRITE_FLAG_SHIFT	16
#define MCU_WRITE_FLAG_MASK	0x0F
#define MCU_DDR_FREQ_SHIFT	12
#define MCU_DDR_FREQ_MASK	0x0F
#define MCU_DDR_TYPE_SHIFT	8
#define MCU_DDR_TYPE_MASK	0x03
#define MCU_DDR_CAPACITY_SHIFT	4
#define MCU_DDR_CAPACITY_MASK	0x03

/*board version*/
#define MCU_VERSION_INFO	(0x7494)
#define MCU_VERSION_INFO_MLU220	(0x20008)
#define MCU_MAIN_VERSION_SHIFT	24
#define MCU_BOARD_TYPE_SHIFT	16
#define MCU_SW_MAJOR_VER_SHIFT	8
#define MCU_SW_MINOR_VER_SHIFT	0
#define MCU_VERSION_MASK	0xFF

/*sn low*/
#define MCU_SN_INFO_LOW		(0x7498)
#define A_TYPE_BOARD_SHIFT	20
#define A_TYPE_BOARD_MASK	0xF
#define MCU_SN_INFO_LOW_MLU220		(0x2000c)
/*sn high*/
#define MCU_SN_INFO_HIGH	(0x749C)
#define MCU_SN_INFO_HIGH_MLU220	(0x20010)

/*uuid*/
#define UUID_2_SHIFT            27
#define UUID_2_MASK             0x1F
#define MCU_UUID_2_INFO_MLU220 (0x20020)
#define MCU_UUID_1_INFO_MLU220 (0x20024)
#define MCU_UUID_0_INFO_MLU220 (0x20028)

/*memsys temp 0 - 3*/
#define MCU_MSG_INFO0		(0x74A0)
#define MCU_MSG_INFO0_MLU220		(0x20014)
#define MCU_MEMSYS_TEMP0_SHIFT	24
#define MCU_MEMSYS_TEMP1_SHIFT	16
#define MCU_MEMSYS_TEMP2_SHIFT	8
#define MCU_MEMSYS_TEMP3_SHIFT	0

/*top_temp fan power pvt_flag*/
#define MCU_MSG_INFO1		(0x74A4)
#define MCU_MSG_INFO1_MLU220		(0x20018)
#define MCU_TOP_TEMP_SHIFT	24
/*rpm (read_val * 25) */
#define MCU_FAN_SPEED_SHIFT	16
#define MCU_POWER_SHIFT	8
#define MCU_INFO_MASK	0xFF
#define MCU_PVT_FLAG_SHIFT	7

/*reserve*/
#define MCU_MSG_INFO2		(0x74A8)
#define MCU_MSG_INFO2_MLU220		(0x2001c)
#define MCU_IPUDFS_TEMP_DFS_SHIFT 11
#define MCU_IPUDFS_FAST_DFS_SHIFT 10

/*power capping*/
#define MCU_MSG_INFO3		(0x74AC)
#define MCU_MSG_INFO3_MLU220		(0x20020)

#define MCU_POWER_CAP_MASK	0xFF
#define MCU_POWER_CAP_ENABLE	0x100
#define MCU_MACHINE_TEMP_SHIFT	16

/*QOD Status*/
#define MCU_QDD_STATUS_SHIFT	18

#define UNKNOWN_BOOT    0X0
#define SECURE_BOOT     0X1
#define NORMAL_BOOT     0X2
#define SEC_BYPASS_BOOT 0X3

#define MCU_BITS(addr, msb, lsb) \
	(((addr) >> (lsb)) & ((1UL << ((msb) - (lsb) + 1)) - 1))

enum mcu_chip_type {
	MLU100 = 1,
	MLU270,
};

enum mcu_print_exception_reason {
	NO_EXCEPTION_REASON_PRINT = 0,
	EXCEPTION_REASON_PRINT = 1,
};

#define MCU_TEMP_CORRECTION_FACTOR	100

typedef union mcu_split_reg_byte {
	u32 data;
	struct {
		unsigned data0	:8;
		unsigned data1	:8;
		unsigned data2	:8;
		unsigned data3	:8;
	}bit;
} mcu_split_reg_byte_t;

enum mlu_special_id {
	SPECIAL_M9 = 0,
	SPECIAL_M9U = 1,
	SPECIAL_M9L = 2,
	SPECIAL_M9B = 3,
	SPECIAL_M9C = 4,
};

struct mlu_board_model {
	cn_board_model_t board_model_val;
	int board_info_idx;
};

struct mlu_board_basic_info {
	u32 peak_power;
	char board_model_name[BOARD_MODEL_NAME_LEN];
	u32 max_power_cap;
	u8 max_power_decimal;
	u32 bandwidth;
	u8 bandwidth_decimal;
	u32 min_power_cap_ctrl;
	u32 platform_id;
	u16 min_ipu_freq_cap;
	u16 max_ipu_freq_cap;
};

enum cn_mcu_chip_type {
	CN_CHIP_TYPE_C20E = 0,
	CN_CHIP_TYPE_C20L,
	CN_CHIP_TYPE_C20,
	CN_CHIP_TYPE_C30S,
	CN_CHIP_TYPE_C30S_DUAL_DIE,
	CN_CHIP_TYPE_CE3226_V101,
	CN_CHIP_TYPE_CE3226_V100,
	CN_CHIP_TYPE_CE3226_ES,
	CN_CHIP_TYPE_C50,
	CN_CHIP_TYPE_LEOPARD,
	CN_CHIP_TYPE_PIGEON,
	CN_CHIP_TYPE_PIGEONC,
	CN_CHIP_TYPE_C50S,
	CN_CHIP_TYPE_1V_2301,
	CN_CHIP_TYPE_1V_2302,
	CN_CHIP_TYPE_UNKNOWN,
	CN_CHIP_TYPE_MAX,
};

extern struct cn_mcu_info cn_mlu270_mcu_ver_control[CN_MLU270_MAX];
extern struct cn_mcu_info cn_mlu220_mcu_ver_control[CN_MLU220_MAX];
extern struct cn_mcu_info cn_mlu290_mcu_ver_control[CN_MLU290_MAX];
extern struct cn_mcu_info cn_mlu370_mcu_ver_control[CN_MLU370_MAX];

extern const struct mlu_board_basic_info mlu270_basic_info_table[CN_MLU270_MAX];
extern const struct mlu_board_basic_info mlu220_basic_info_table[CN_MLU220_MAX];
extern const struct mlu_board_basic_info mlu290_basic_info_table[CN_MLU290_MAX];
extern const struct mlu_board_basic_info mlu370_basic_info_table[CN_MLU370_MAX];
extern const struct mlu_board_basic_info ce3226_basic_info_table[CN_CE3226_MAX];
extern const struct mlu_board_basic_info mlu590_basic_info_table[CN_MLU590_MAX];
extern const struct mlu_board_basic_info mlu580_basic_info_table[CN_MLU580_MAX];

struct cn_mcu_ops {
	int (*read_basic_info)(void *pcore);
	int (*read_power_info)(void *pcore, struct board_power_info *info);
	int (*read_ipu_freq)(void *pcore, struct ipu_freq_info *info);
	int (*read_max_temp)(void *pcore, int *max_temp);
	int (*read_over_temp_flag)(void *pcore, int *poweroff_flag);
	int (*read_ddr_freq)(void *pcore, u32 *freq);
	int (*power_capping)(void *pcore, struct power_capping_info *pcinfo);
	int (*set_host_drv_status)(void *pcore, int status);
	int (*read_overtemp_freq)(void *pcore, struct mlu_overtemp_value *overtemp);
	void (*mcu_exit)(void *mset);
	int (*get_overtemp_policy)(void *pcore,
		struct cndev_overtemp_param *overtemp);
	int (*set_overtemp_policy)(void *pcore,
		struct cndev_overtemp_param *overtemp);
	int (*read_uuid)(void *pcore, unsigned char *uuid);
	int (*set_d2d_crc_err)(void *pcore,
		u32 status);
	int (*read_exception_info)(void *pcore,
		struct exception_info *info, u8 klog);
};


struct cn_mcu_set {
	void *core;
	const struct cn_mcu_ops *mcu_ops;

	atomic64_t enable_power_cap_ref;
	atomic64_t disable_power_cap_ref;
};


#ifndef CONFIG_CNDRV_EDGE
static inline int mcu_init_ce3226(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
static inline int mcu_init_pigeon(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
int mcu_init_mlu270(struct cn_mcu_set *mcu_set);
int mcu_init_mlu220(struct cn_mcu_set *mcu_set);
int mcu_init_mlu290(struct cn_mcu_set *mcu_set);
int mcu_init_mlu370(struct cn_mcu_set *mcu_set);
int mcu_init_mlu590(struct cn_mcu_set *mcu_set);
int mcu_init_mlu580(struct cn_mcu_set *mcu_set);
#else
static inline int mcu_init_mlu270(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
static inline int mcu_init_mlu290(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
static inline int mcu_init_mlu370(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
static inline int mcu_init_mlu590(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
static inline int mcu_init_mlu580(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
#if defined(CONFIG_CNDRV_C20E_SOC)
int mcu_init_mlu220(struct cn_mcu_set *mcu_set);
static inline int mcu_init_ce3226(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
static inline int mcu_init_pigeon(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
#elif defined(CONFIG_CNDRV_CE3226_SOC)
int mcu_init_ce3226(struct cn_mcu_set *mcu_set);
static inline int mcu_init_mlu220(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
static inline int mcu_init_pigeon(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
#elif defined(CONFIG_CNDRV_PIGEON_SOC)
int mcu_init_pigeon(struct cn_mcu_set *mcu_set);
static inline int mcu_init_mlu220(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
static inline int mcu_init_ce3226(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
#else
static inline int mcu_init_mlu220(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
static inline int mcu_init_ce3226(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
static inline int mcu_init_pigeon(struct cn_mcu_set *mcu_set)
{
	return -ENODEV;
}
#endif
#endif

int mcu_version_contorl(struct cn_core_set *core,
						struct cn_mcu_info *ver,
						int board_idx,
						struct cn_mcu_info version_control[]);

int mcu_read_ipu_freq_ce3226(void *pcore, struct ipu_freq_info *info);
void cn_mcu_fill_platform_info(struct cn_core_set *core);
int mcu_get_platform_id_common(void *pcore, u32 *chip_type);
int mcu_get_platform_info_common(void *pcore, struct monitor_platform_info *monitor_platform);
#endif
