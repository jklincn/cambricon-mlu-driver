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
#include "cndrv_xid.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_trans.h"
#include "cndrv_mcc.h"
#include "cndrv_mm.h"
#include "mcc_main.h"
#include "cndrv_kwork.h"

#define MLU290_HBM_CHANNEL_COUNT 4
#define MC_NUM_EACH_HBM_IRQ  8
#define MLU290_HBM_IRQ_BASE  187
#define MLU290_HBM_IRQ_OFF(i) (MLU290_HBM_IRQ_BASE + (i))

#define TOTAL_MC_NUM  32
#define MC_CFG_BASE(i)\
	(0x01000000 + ((i)/4) * 0x100000 + ((i)%4) * 0x40000)

#define STAT_INTERRUPT             0x294c
#define INIT_INTERRUPT_MASK        0x2950

#define STAT_ECC_1BIT_ERROR_ADDR   0x2958
#define STAT_ECC_1BIT_ERROR_POS    0x295c
#define STAT_ECC_1BIT_ERROR_RMW    0x2960
#define STAT_ECC_2BIT_ERROR_ADDR   0x2964
#define STAT_ECC_2BIT_ERROR_RMW    0x2968

#define STAT_AXI_DECERR_SHIFT               0
#define STAT_WRITE_DATA_PARITY_ERROR_SHIFT  1
#define STAT_READ_DATA_PARITY_ERROR_SHIFT   2
#define ONE_BIT_ECC_ERROR_SHIFT             3
#define STAT_INT_ECC_1BIT_THRESH_SHIFT      4
#define TWO_BIT_ECC_ERROR_SHIFT             5
#define STAT_WRITE_DATA_PARITY_ERROR2_SHIFT 6
#define STAT_CA_PARITY_ERROR_SHIFT          16
#define STAT_DFI_CATTRIP_SHIFT              17
#define DFI_TEMP_SHIFT                      18

#define STAT_AXI_DECERR_MASK  \
					(0x1 << STAT_AXI_DECERR_SHIFT)
#define STAT_WRITE_DATA_PARITY_ERROR_MASK  \
					(0x1 << STAT_WRITE_DATA_PARITY_ERROR_SHIFT)
#define STAT_READ_DATA_PARITY_ERROR_MASK  \
					(0x1 << STAT_READ_DATA_PARITY_ERROR_SHIFT)
#define ONE_BIT_ECC_ERROR_MASK  \
					(0x1 << ONE_BIT_ECC_ERROR_SHIFT)
#define STAT_INT_ECC_1BIT_THRESH_MASK  \
					(0x1 << STAT_INT_ECC_1BIT_THRESH_SHIFT)
#define TWO_BIT_ECC_ERROR_MASK  \
					(0x1 << TWO_BIT_ECC_ERROR_SHIFT)
#define STAT_WRITE_DATA_PARITY_ERROR2_MASK  \
					(0x1 << STAT_WRITE_DATA_PARITY_ERROR2_SHIFT)
#define STAT_CA_PARITY_ERROR_MASK  \
					(0x1 << STAT_CA_PARITY_ERROR_SHIFT)
#define STAT_DFI_CATTRIP_MASK  \
					(0x1 << STAT_DFI_CATTRIP_SHIFT)
#define DFI_TEMP_MASK  \
					(0x1 << DFI_TEMP_SHIFT)

#define INIT_SELF_REFRESH       0x4234
#define INIT_SELF_REFRESH_STAT  0x4238
#define SELF_REFRESH_SHIFT      0
#define ENABLE_SELF_REFRESH     (0x1 << SELF_REFRESH_SHIFT)
#define DISABLE_SELF_REFRESH    (0x0 << SELF_REFRESH_SHIFT)
#define INIT_SELF_REFRESH_TIMEOUT 100

#define STAT_DFI_TCR_TEMP       0x10048
#define STAT_DFI_TCR_TEMP_MASK  0x7

extern int cn_core_reset(struct cn_core_set *core, bool reset);

void hbm_mlu290_write32(void *pcore, u8 mc_index, u32 reg_index, u32 value)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	u64 offset = MC_CFG_BASE(mc_index) + reg_index;

	if (mc_index < 32) {
		reg_write32(core->bus_set, offset, value);
	} else {
		cn_dev_core_err(core, "mc_index[%d] is too big", mc_index);
	}
}

u32 hbm_mlu290_read32(void *pcore, u8 mc_index, u32 reg_index)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	u64 offset = MC_CFG_BASE(mc_index) + reg_index;
	u32 value = 0;

	if (mc_index < 32) {
		value = reg_read32(core->bus_set, offset);
	} else {
		cn_dev_core_err(core, "mc_index[%d] is too big", mc_index);
	}

	return value;
}

#define HBM_PHY_BASE_ADDR		(0x00040000) //0x20000*4
#define GET_HBM_ADDR(i)			(HBM_PHY_BASE_ADDR + (0x20000 * (i)))
#define HBM_MBIST_REPAIR_MODE		(31)
#define FW_HBM_RUN_CELL_REPAIR		(41)
#define FW_HBM_RUN_FUSE_SCAN		(42)
#define SPARE_3_REG			(73)
#define SPARE_4_REG			(74)
#define SOFT_REPAIR_MODE		(2)

#define HBM_MAX_NUM			(4)
#define HBM_CHN_NUM			(8)
#define HBM_SID_NUM			(2)
#define HBM_BNK_NUM			(16)
#define HBM_FUSE_NUM			(HBM_CHN_NUM * HBM_SID_NUM * HBM_BNK_NUM)
#define HBM_MAX_FUSE			(0)
#define REPAIR_STOP			(0x0)
#define REPAIR_RUNNING			(0x1)
#define REPAIR_FINISH			(0x2)
#define REPAIR_ABORT			(0x3)

#define MAX_1BIT_ECC_CNT		(20)
#define GET_ECC_BIT(info)		(GET_BITS_VAL(info, 31, 31))
#define GET_HBM_NUM(info)		(GET_BITS_VAL(info, 26, 25))
#define GET_CHN_NUM(info)		(GET_BITS_VAL(info, 24, 22))
#define GET_ECC_ADDR(info)		((GET_BITS_VAL(info, 21, 2) << 10) | \
					(GET_BITS_VAL(info, 1, 1) << 7))

#define GET_BANK(ecc_addr)		((GET_BITS_VAL(ecc_addr, 14, 14) << 3) | \
					(GET_BITS_VAL(ecc_addr, 7, 7) << 2) | \
					(GET_BITS_VAL(ecc_addr, 13, 12) << 0))
#define GET_SID(ecc_addr)		(GET_BITS_VAL(ecc_addr, 15, 15))
#define GET_ROW(ecc_addr)		(GET_BITS_VAL(ecc_addr, 29, 16))
#define SET_DECODE_FUSE_PHY_SPARE_3(nVal, decode) \
	do {\
		u32 tmp; \
		tmp = decode.bank; \
		SET_BITS_VAL(nVal, 17, 14, tmp); \
		tmp = decode.info.eeprom_info; \
		SET_BITS_VAL(nVal, 21, 19, tmp); \
		tmp = decode.sid; \
		SET_BITS_VAL(nVal, 22, 22, tmp); \
	} while (0)
#define SET_DECODE_REPAIR_PHY_SPARE_3(nVal, decode) \
	do {\
		u32 tmp; \
		tmp = decode.row; \
		SET_BITS_VAL(nVal, 13, 0, tmp); \
		tmp = decode.bank; \
		SET_BITS_VAL(nVal, 17, 14, tmp); \
		tmp = GET_CHN_NUM(decode.info.eeprom_info); \
		SET_BITS_VAL(nVal, 21, 19, tmp); \
		tmp = decode.sid; \
		SET_BITS_VAL(nVal, 22, 22, tmp); \
	} while (0)
#define GET_FUSE_SCAN_INFO(phy_spare_4)		((phy_spare_4 & 0xf))
/* flag = 0 is 1bit_ecc flag = 1 is 2bit_ecc*/
#define SET_EEPROM_ECC_ERROR_INFO(nVal, encode, flag) \
	do {\
		u32 tmp; \
		tmp = flag; \
		SET_BITS_VAL(nVal, 31, 31, tmp); \
		tmp = hbm_info[encode.info.sys_mc_num].hbm_num; \
		SET_BITS_VAL(nVal, 26, 25, tmp); \
		tmp = hbm_info[encode.info.sys_mc_num].chn_num; \
		SET_BITS_VAL(nVal, 24, 22, tmp); \
		tmp = GET_BITS_VAL(encode.ecc_addr, 29, 10); \
		SET_BITS_VAL(nVal, 21, 2, tmp); \
		tmp = GET_BITS_VAL(encode.ecc_addr, 7, 7); \
		SET_BITS_VAL(nVal, 1, 1, tmp); \
	} while (0)

struct hbm_map_info {
	u8 hbm_num;
	u8 sys_num;
	u8 pmc_num; /*phy_mc_num*/
	u8 chn_num;
};

/* sys_mc_num = {0,1,2...,31} phy_mc_num keep in hbm_info*/
struct hbm_map_info hbm_info[] = {
		{0, 0, 0, 4},
		{0, 0, 1, 0},
		{0, 0, 2, 5},
		{0, 0, 3, 1},
		{0, 1, 0, 6},
		{0, 1, 1, 2},
		{0, 1, 2, 7},
		{0, 1, 3, 3},
		{1, 0, 0, 4},
		{1, 0, 1, 0},
		{1, 0, 2, 5},
		{1, 0, 3, 1},
		{1, 1, 0, 6},
		{1, 1, 1, 2},
		{1, 1, 2, 7},
		{1, 1, 3, 3},
		{2, 0, 0, 4},
		{2, 0, 1, 0},
		{2, 0, 2, 5},
		{2, 0, 3, 1},
		{2, 1, 0, 6},
		{2, 1, 1, 2},
		{2, 1, 2, 7},
		{2, 1, 3, 3},
		{3, 0, 0, 4},
		{3, 0, 1, 0},
		{3, 0, 2, 5},
		{3, 0, 3, 1},
		{3, 1, 0, 6},
		{3, 1, 1, 2},
		{3, 1, 2, 7},
		{3, 1, 3, 3}
};

enum HBM_FIX_TYPE {
	FIX_UNKNOWN,
	FIX_REPAIR,
	FIX_RETIRE,
	FIX_PENDING,
	FIX_FAILURE,
};

struct hbm_repair_info_set {
	u8 bank;
	u8 sid;
	u16 row;
	u32 ecc_addr;
	union {
		u32 sys_mc_num; //encode info
		u32 eeprom_info; //decode info
	} info;
	enum HBM_FIX_TYPE fix_type;
};

struct hbm_repair_set {
	struct cn_mcc_set *mcc_set;
	unsigned int rom_info[EEPROM_MAX_NUM];
	unsigned int eeprom_num;
	unsigned int fuse_info[HBM_FUSE_NUM * HBM_MAX_NUM];
	unsigned int fuse_flag;
	struct hbm_repair_info_set decode[EEPROM_MAX_NUM];
	unsigned int decode_num;
	unsigned int decode_rom_index;
	unsigned int ecc_info[EEPROM_MAX_NUM * 4];
	unsigned int ecc_1bit_cnt[EEPROM_MAX_NUM * 4];
	unsigned int ecc_num;
	struct hbm_repair_info_set encode[EEPROM_MAX_NUM];
	unsigned int encode_num;
	struct hbm_retire_info_t retire_info[EEPROM_MAX_NUM];
	unsigned int retire_num;
	unsigned int retire_rom_index;
	u64 retire_page[EEPROM_MAX_NUM];
	unsigned int retire_page_num;
	volatile int eeprom_enable;

	volatile int retire_enable;

	volatile int repair_state;
	struct mutex repair_mutex;
};

#include "fw/fw_manager_mlu290.c"

#ifdef HBM_SOFT_REPAIR
static void mcc_hbm_sbus_write(u8 hbm_num, unsigned int device_addr,
	unsigned int local_addr, unsigned int data, struct cn_core_set *core)
{
	unsigned int device_addr_offset = GET_BITS_VAL(device_addr, 6, 0);
	unsigned int local_addr_offset = GET_BITS_VAL(local_addr, 7, 0);
	unsigned int addr = 0;

	SET_BITS_VAL(addr, 1, 0, 0);
	SET_BITS_VAL(addr, 9, 2, local_addr_offset);
	SET_BITS_VAL(addr, 16, 10, device_addr_offset);
	SET_BITS_VAL(addr, 31, 17, 0);
	reg_write32(core->bus_set, GET_HBM_ADDR(hbm_num) + addr, data);
}

static unsigned int mcc_hbm_sbus_read(u8 hbm_num, unsigned int device_addr,
			unsigned int local_addr, struct cn_core_set *core)
{
	unsigned int device_addr_offset = GET_BITS_VAL(device_addr, 6, 0);
	unsigned int local_addr_offset = GET_BITS_VAL(local_addr, 7, 0);
	unsigned int addr = 0;

	SET_BITS_VAL(addr, 1, 0, 0);
	SET_BITS_VAL(addr, 9, 2, local_addr_offset);
	SET_BITS_VAL(addr, 16, 10, device_addr_offset);
	SET_BITS_VAL(addr, 31, 17, 0);

	return reg_read32(core->bus_set, GET_HBM_ADDR(hbm_num) + addr);
}

static int mcc_sbus_master_spico_interrupt(u8 hbm_num, unsigned int interrupt_code,
			unsigned int interrupt_value, unsigned int *data,
			struct cn_core_set *core)
{
	int ret = 0;
	unsigned int timeout = 0;
	unsigned int rd_data;

	// Set spico interrupt code and value
	mcc_hbm_sbus_write(hbm_num, SNAP_ADDR, 2,
			((interrupt_value << 16) | interrupt_code), core);
	// Assert Interrupt
	rd_data = mcc_hbm_sbus_read(hbm_num, SNAP_ADDR, 7, core);
	mcc_hbm_sbus_write(hbm_num, SNAP_ADDR, 7, rd_data | 1, core);
	// Lower Interrupt
	mcc_hbm_sbus_write(hbm_num, SNAP_ADDR, 7, rd_data & 0xFFFFFFFE, core);
	// Wait for interrupt to complete
	while (timeout < 1000) {
		rd_data = mcc_hbm_sbus_read(hbm_num, SNAP_ADDR, 8, core);
		if ((rd_data & 0x8000) == 0)
			break;
		timeout++;
		usleep_range(1000, 1500);
	}
	if (timeout >= 1000) {
		cn_dev_core_err(core, "hbm%d interrupt%#x timeout rd_data=%#x",
						hbm_num, interrupt_code, rd_data);
		ret = -1;
	} else {
		rd_data = mcc_hbm_sbus_read(hbm_num, SNAP_ADDR, 8, core);
		*data = (rd_data >> 16) & 0xFFFF;
	}

	return ret;
}

static void mcc_set_hbm_parameter(u8 hbm_num, unsigned int offset,
				unsigned int value, struct cn_core_set *core)
{
	int ret = 0;
	unsigned int rd_data;

	ret = mcc_sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_SET_PARAM,
						offset, &rd_data, core);
	if (rd_data != 1 || ret) {
		cn_dev_core_err(core, "FW_SET_PARAM error:rd_data=%d,ret=%d",
							rd_data, ret);
	}
	ret = mcc_sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_SET_PARAM_VALUE,
							value, &rd_data, core);
	if (rd_data != 1 || ret) {
		cn_dev_core_err(core, "FW_SET_VALUE error:rd_data=%d,ret=%d",
							rd_data, ret);
	}
	/* check write value*/
	ret = mcc_sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_GET_PARAM_VALUE,
							offset, &rd_data, core);
	if (rd_data != value || ret) {
		cn_dev_core_err(core, "FW_GET_VALUE error:rd_data=%d,ret=%d",
							rd_data, ret);
	}
}

static int mcc_hbm_firmware_operation(struct cn_core_set *core, u8 hbm_num,
							unsigned int operation)
{
	int ret = 0;
	unsigned int rd_data;
	unsigned int time_out = 0;

	// Run a firmware test operation
	ret = mcc_sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_OP_ON_ALL_CHN,
						operation, &rd_data, core);
	if (rd_data != 1 || ret) {
		cn_dev_core_err(core, "sbus_master_spico_interrupt error");
		return -1;
	}
	ret = mcc_sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_GET_OP_RESULT,
							0, &rd_data, core);
	while (GET_BITS_VAL(rd_data, 1, 0) == 0x2 && (time_out < 1000)) {//0b10
		usleep_range(50, 60);//must wait 50us
		mcc_sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_GET_OP_RESULT,
							0, &rd_data, core);
		time_out++;
	}
	if (time_out >= 1000) {
		cn_dev_core_err(core, "read reg:%#x=%#x timeout",
					FW_INTERRUPT_GET_OP_RESULT, rd_data);
		return -1;
	}
	ret = GET_BITS_VAL(rd_data, 2, 2);

	return ret;
}

static int mcc_decode_cell_repair(struct cn_core_set *core,
					struct hbm_repair_info_set decode)
{
	int ret = 0;
	u8 hbm_num = GET_HBM_NUM(decode.info.eeprom_info);
	u32 phy_spare_3 = 0;
	unsigned int rd_data = 0;

	SET_DECODE_REPAIR_PHY_SPARE_3(phy_spare_3, decode);
	/* disable mcu*/
	phy_disable_mcu_access(core);
	/* select soft repair mode */
	mcc_set_hbm_parameter(hbm_num, HBM_MBIST_REPAIR_MODE, SOFT_REPAIR_MODE, core);

	cn_dev_core_info(core, "repair:hbm_num%d, phy_spare_3%#x", hbm_num, phy_spare_3);

	mcc_hbm_sbus_write(hbm_num, APC_ADDR, SPARE_3_REG, phy_spare_3, core);
	ret = mcc_hbm_firmware_operation(core, hbm_num, FW_HBM_RUN_CELL_REPAIR);
	if (ret) {
		cn_dev_core_err(core, "hbm_num=%d, ecc_addr=%#x, error_code=%d",
						hbm_num, decode.ecc_addr, ret);
		phy_enable_mcu_access(core);
		return ret;
	}
	ret = mcc_sbus_master_spico_interrupt(hbm_num, FW_INTERRUPT_GET_OP_RESULT,
							18, &rd_data, core);
	if (ret) {
		cn_dev_core_err(core, "hbm_num=%d, ecc_addr=%#x, error_code=%d",
						hbm_num, decode.ecc_addr, ret);
		phy_enable_mcu_access(core);
		return ret;
	}
	/* enable mcu*/
	phy_enable_mcu_access(core);

	return ret;
}

static void hbm_repair_encode(struct hbm_repair_set *repair_set)
{
	int i;
	unsigned int ecc_num;
	unsigned int *ecc_info;
	struct hbm_repair_info_set *encode;
	int repair_index = 0;

	if (!repair_set)
		return;
	ecc_num = repair_set->ecc_num;
	ecc_info = repair_set->ecc_info;
	encode = repair_set->encode;

	/* clear encode*/
	memset(repair_set->encode, 0, sizeof(repair_set->encode));
	repair_set->encode_num = 0;
	/* keep 2BIT_ECC error info*/
	for (i = 0; i < ecc_num; i++) {
		if (GET_ECC_BIT(ecc_info[i]) != ECC_BIT_2)
			continue;
		if (repair_index >= EEPROM_MAX_NUM)
			break;
		encode[repair_index].info.eeprom_info = ecc_info[i];
		encode[repair_index].ecc_addr = GET_ECC_ADDR(ecc_info[i]);
		encode[repair_index].bank = GET_BANK(encode[repair_index].ecc_addr);
		encode[repair_index].sid = GET_SID(encode[repair_index].ecc_addr);
		encode[repair_index].row = GET_ROW(encode[repair_index].ecc_addr);
		repair_index++;
	}
	/* keep 20-times 1BIT_ECC error info*/
	for (i = 0; i < ecc_num; i++) {
		if (GET_ECC_BIT(ecc_info[i]) != ECC_BIT_1)
			continue;
		if (repair_set->ecc_1bit_cnt[i] < MAX_1BIT_ECC_CNT)
			continue;
		if (repair_index >= EEPROM_MAX_NUM)
			break;
		encode[repair_index].info.eeprom_info = ecc_info[i];
		encode[repair_index].ecc_addr = GET_ECC_ADDR(ecc_info[i]);
		encode[repair_index].bank = GET_BANK(encode[repair_index].ecc_addr);
		encode[repair_index].sid = GET_SID(encode[repair_index].ecc_addr);
		encode[repair_index].row = GET_ROW(encode[repair_index].ecc_addr);
		repair_index++;
	}
	/* 2BIT_ECC add 20-times 1BIT_ECC total number*/
	repair_set->encode_num = repair_index;
}
#endif

static int hbm_retire_decode(struct hbm_repair_set *repair_set, u32 eeprom_info)
{
	int i;
	int index;
	unsigned int hbm_num;
	unsigned int chn_num;

	hbm_num = GET_HBM_NUM(eeprom_info);
	chn_num = GET_CHN_NUM(eeprom_info);
	for (i = 0; i < ARRAY_SIZE(hbm_info); i++) {
		if (hbm_info[i].hbm_num == hbm_num
				&& hbm_info[i].chn_num == chn_num) {
			break;
		}
	}

	if (i >= ARRAY_SIZE(hbm_info)) {
		cn_dev_err("hbm_num=%d, chn_num=%d error", hbm_num, chn_num);
		return -1;
	}
	index = repair_set->retire_num;
	if (index >= EEPROM_MAX_NUM) {
		repair_set->retire_num = 0;
		repair_set->retire_rom_index = repair_set->retire_num;
		index = repair_set->retire_num;
	}

	repair_set->retire_info[index].hbm_num = hbm_info[i].hbm_num;
	repair_set->retire_info[index].sys_num = hbm_info[i].sys_num;
	repair_set->retire_info[index].pmc_num = hbm_info[i].pmc_num;
	repair_set->retire_info[index].chn_num = hbm_info[i].chn_num;
	repair_set->retire_info[index].ecc_addr = GET_ECC_ADDR(eeprom_info);
	repair_set->retire_info[index].ecc_type = GET_ECC_BIT(eeprom_info);
	repair_set->retire_num++;

	return 0;
}

#ifdef HBM_SOFT_REPAIR
static void hbm_ecc_repair_work(struct work_struct *work)
{
	int ret = 0;
	int i, j;
	struct hbm_repair_set *repair_set;
	struct cn_mcc_set *mcc_set;
	struct cn_core_set *core;
	u32 eeprom_info;
	int eeprom_num = 0;
	int repair_flag = 1;

	core = container_of(work, struct cn_core_set, repair_work);
	if (!core || !core->mcc_set)
		return;
	mcc_set = (struct cn_mcc_set *)core->mcc_set;
	if (!mcc_set->repair_set)
		return;
	repair_set = (struct hbm_repair_set *)mcc_set->repair_set;

	mutex_lock(&repair_set->repair_mutex);

	repair_set->repair_state = REPAIR_RUNNING;
	if (core->repair_active)
		goto ERROR;

	eeprom_num = repair_set->decode_num;
	/* ecc error info encode*/
	hbm_repair_encode(repair_set);

	cn_dev_core_debug(core, "ecc_num = %d, encode_num = %d",
				repair_set->ecc_num, repair_set->encode_num);
	for (i = 0; i < repair_set->encode_num; i++) {
		if (repair_set->repair_state == REPAIR_ABORT) {
			goto ERROR;
		}
		for (j = 0; j < repair_set->decode_num; j++) {
			if ((repair_set->encode[i].info.eeprom_info << 1) ==
				(repair_set->decode[j].info.eeprom_info << 1)) {
				repair_flag = 0;
				break;
			}
		}
		if (!repair_flag) {
			repair_flag = 1;
			continue;
		}
		/* keep ecc_info to eeprom*/
		if (repair_set->eeprom_num >= EEPROM_MAX_NUM) {
			cn_dev_core_debug(core, "EEPROM OVERFLOW >= 512");
			goto retire;
		}
		cn_dev_core_info(core, "eeprom_id = %d, eeprom_info = %#x",
			eeprom_num, repair_set->encode[i].info.eeprom_info);
		if (repair_set->eeprom_enable) {
			ret = cn_bus_refresh_soft_repair_info(core->bus_set,
				&repair_set->encode[i].info.eeprom_info, 1);
			if (ret != 1) {
				cn_dev_core_err(core, "refresh soft repair info error");
				goto ERROR;
			}
		}
		j = repair_set->decode_num;
		eeprom_info = repair_set->encode[i].info.eeprom_info;
		repair_set->decode[j].info.eeprom_info = eeprom_info;
		repair_set->decode[j].ecc_addr = GET_ECC_ADDR(eeprom_info);
		repair_set->decode[j].bank = repair_set->encode[i].bank;
		repair_set->decode[j].sid = repair_set->encode[i].sid;
		repair_set->decode[j].row = repair_set->encode[i].row;
		repair_set->decode[j].fix_type = FIX_PENDING;
		repair_set->decode_num++;
		repair_set->rom_info[repair_set->eeprom_num] = eeprom_info;
		repair_set->eeprom_num++;
retire:
		eeprom_info = repair_set->encode[i].info.eeprom_info;
		ret = hbm_retire_decode(repair_set, eeprom_info);
		if (ret)
			goto ERROR;
	}
	if (core->state != CN_RUNNING && (repair_set->decode_num > eeprom_num)) {
		if (core->state == CN_RESET)
			goto ERROR;
		cn_dev_core_err(core, "arm bringup memory happend ecc error");
		repair_set->repair_state = REPAIR_FINISH;
		core->repair_active = 1;
		mutex_unlock(&repair_set->repair_mutex);
		cn_core_reset(core, true);
		return;
	}
	/* trigger soft retair*/
	if (core->state == CN_RUNNING && repair_set->retire_enable)
		cn_mem_pageretire_handle(core);
ERROR:
	repair_set->repair_state = REPAIR_FINISH;
	mutex_unlock(&repair_set->repair_mutex);
}
#endif

#ifdef HBM_SOFT_REPAIR
static int mcc_hbm_soft_repair(struct cn_mcc_set *mcc_set, u8 sys_mc_num,
						u32 mc_state, u32 ecc_test)
{
	int i = 0, j = 0, flag = 0;
	int ret = 0;
	u32 encode = 0;
	u32 ecc_addr = 0;
	struct hbm_repair_info_set decode;
	struct hbm_repair_set *repair_set =
				(struct hbm_repair_set *)mcc_set->repair_set;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	cn_dev_core_info(core, "mc_state=%#x(3:1bit_ecc,5:2bit_ecc)", mc_state);
	/* mcu keep ecc error info in eeprom*/
	if (mc_state & ONE_BIT_ECC_ERROR_MASK) {
		if (repair_set->eeprom_enable) {
			ecc_addr = hbm_mlu290_read32(core, sys_mc_num,
						STAT_ECC_1BIT_ERROR_ADDR);
		} else {
			ecc_addr = ecc_test;
		}
		memset(&decode, 0, sizeof(decode));
		/* get 30bit phy_ecc_addr*/
		decode.info.sys_mc_num = sys_mc_num;
		decode.ecc_addr = GET_BITS_VAL(ecc_addr, 23, 0) << 6;
		decode.bank = GET_BANK(decode.ecc_addr);
		decode.sid = GET_SID(decode.ecc_addr);
		decode.row = GET_ROW(decode.ecc_addr);

		cn_dev_core_info(core, "1bit ecc_err_addr=%#x", ecc_addr);
		cn_dev_core_info(core, "sys_mc_num=%d", sys_mc_num);
		cn_dev_core_info(core, "hbm_num%d sys_num%d pmc_num%d chn_num%d",
						hbm_info[sys_mc_num].hbm_num,
						hbm_info[sys_mc_num].sys_num,
						hbm_info[sys_mc_num].pmc_num,
						hbm_info[sys_mc_num].chn_num);
		SET_EEPROM_ECC_ERROR_INFO(encode, decode, 0);
		cn_dev_core_info(core, "ecc encode info = %#x", encode);
		if (encode == 0)
			return ret;
		if (repair_set->ecc_num < (EEPROM_MAX_NUM * 4)) {
			for (i = 0; i < repair_set->ecc_num; i++) {
				if ((repair_set->ecc_info[i] << 1) == (encode << 1)) {
					break;
				}
			}
			repair_set->ecc_info[i] = encode;
			repair_set->ecc_1bit_cnt[i]++;
			if (i == repair_set->ecc_num)
				repair_set->ecc_num++;
		} else {
			repair_set->ecc_num = 0;
			memset(repair_set->ecc_1bit_cnt, 0, sizeof(repair_set->ecc_1bit_cnt));
			repair_set->ecc_info[repair_set->ecc_num] = encode;
			repair_set->ecc_1bit_cnt[repair_set->ecc_num]++;
			repair_set->ecc_num++;
		}
		flag = 1;
	}
	if (mc_state & TWO_BIT_ECC_ERROR_MASK) {
		if (repair_set->eeprom_enable) {
			ecc_addr = hbm_mlu290_read32(core, sys_mc_num,
						STAT_ECC_2BIT_ERROR_ADDR);
		} else {
			ecc_addr = ecc_test;
		}
		memset(&decode, 0, sizeof(decode));
		/* get 30bit phy_ecc_addr*/
		decode.info.sys_mc_num = sys_mc_num;
		decode.ecc_addr = GET_BITS_VAL(ecc_addr, 23, 0) << 6;
		decode.bank = GET_BANK(decode.ecc_addr);
		decode.sid = GET_SID(decode.ecc_addr);
		decode.row = GET_ROW(decode.ecc_addr);

		cn_dev_core_info(core, "2bit ecc_err_addr=%#x", ecc_addr);
		cn_dev_core_info(core, "sys_mc_num=%d", sys_mc_num);
		cn_dev_core_info(core, "hbm_num%d sys_num%d pmc_num%d chn_num%d",
						hbm_info[sys_mc_num].hbm_num,
						hbm_info[sys_mc_num].sys_num,
						hbm_info[sys_mc_num].pmc_num,
						hbm_info[sys_mc_num].chn_num);
		SET_EEPROM_ECC_ERROR_INFO(encode, decode, 1);
		cn_dev_core_info(core, "ecc encode info = %#x", encode);
		if (repair_set->ecc_num < (EEPROM_MAX_NUM * 4)) {
			for (j = 0; j < repair_set->ecc_num; j++) {
				if ((repair_set->ecc_info[j] << 1) == (encode << 1)) {
					break;
				}
			}
			repair_set->ecc_info[j] = encode;
			if (j == repair_set->ecc_num) {
				repair_set->ecc_num++;
				flag = 1;
			}
		} else {
			repair_set->ecc_num = 0;
			repair_set->ecc_info[repair_set->ecc_num] = encode;
			repair_set->ecc_num++;
			flag = 1;
		}
	}

	if (flag) {
		if ((mc_state & TWO_BIT_ECC_ERROR_MASK) ||
				((mc_state & ONE_BIT_ECC_ERROR_MASK) &&
				(repair_set->ecc_1bit_cnt[i] >= MAX_1BIT_ECC_CNT)))
			cn_schedule_work(core, &core->repair_work);
	}

	return ret;
}
#endif

static int hbm_ecc_irq_inject(void *mset, u32 sys_mc_num,
				u32 mc_state, u32 ecc_addr)
{
	int ret = 0;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_repair_set *repair_set;

	repair_set = (struct hbm_repair_set *)mcc_set->repair_set;
	if (!repair_set) {
		cn_dev_core_err(core, "repair_set is NULL");
		return -1;
	}

#ifdef HBM_SOFT_REPAIR
	/* hbm soft repair*/
	/* mcu version < 1.0.0 unsupport soft_repair*/
	switch (mc_state) {
	case ECC_BIT_1:
		mc_state = ONE_BIT_ECC_ERROR_MASK;
		break;
	case ECC_BIT_2:
		mc_state = TWO_BIT_ECC_ERROR_MASK;
		break;
	case ECC_BIT_1_2:
		mc_state = ONE_BIT_ECC_ERROR_MASK | TWO_BIT_ECC_ERROR_MASK;
		break;
	default:
		cn_dev_core_err(core, "mc_state error=(%d != 0/1/2)", mc_state);
		return -1;
	}
	if (!cn_bus_is_support_soft_repair_info(core->bus_set) && !core->repair_active) {

		mcc_hbm_soft_repair(mcc_set, sys_mc_num, mc_state, ecc_addr);
	}
#endif

	return ret;
}

static irqreturn_t hbm_mlu290_intr_handle(int irq_index, void *data)
{
	int i;
	u32 reg_val, reg32, reg_clear_irq;
	unsigned int irq_offset = irq_index - MLU290_HBM_IRQ_BASE;
	u8 sys_mc_num;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)data;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ecc_info_t *ecc_info;

	if (IS_ERR_OR_NULL(mcc_set->ecc_status)) {
		cn_dev_core_err(core, "ecc status is null");
		return IRQ_HANDLED;
	}
	ecc_info = ((struct ecc_info_t *)mcc_set->ecc_status) + irq_offset;

	cn_dev_core_debug(core, "irq_index:%d", irq_index);
	for (i = 0; i < MC_NUM_EACH_HBM_IRQ; i++) {
		sys_mc_num = i + irq_offset * MC_NUM_EACH_HBM_IRQ;
		reg_val = hbm_mlu290_read32(core, sys_mc_num, STAT_INTERRUPT);
		if (reg_val) {
			cn_dev_core_info(core, "mc[%d] irq stat:%#x",
							sys_mc_num, reg_val);
#ifdef HBM_SOFT_REPAIR
				/* hbm soft repair*/
				/* mcu version < 1.0.0 unsupport soft_repair*/
			if (!cn_bus_is_support_soft_repair_info(core->bus_set)
					&& !core->repair_active)
				mcc_hbm_soft_repair(mcc_set, sys_mc_num, reg_val, 0);
#endif
			if (reg_val & STAT_DFI_CATTRIP_MASK) {
				hbm_mlu290_write32(core, sys_mc_num,
					STAT_INTERRUPT, STAT_DFI_CATTRIP_MASK);
				/* reset whole board */
				cn_dev_core_err(core, "STAT_DFI_CATTRIP occurred");
				cn_dev_core_err(core, "please reset MLU_card%d", core->idx);
				return IRQ_HANDLED;
			}

			reg_clear_irq = 0;
			if (reg_val & STAT_AXI_DECERR_MASK) {
				cn_dev_core_err(core,
							"mc[%d] STAT_AXI_DECERR occurred",
							sys_mc_num);
				reg_clear_irq |= STAT_AXI_DECERR_MASK;
			}
			if (reg_val & STAT_WRITE_DATA_PARITY_ERROR_MASK) {
				cn_dev_core_err(core,
							"mc[%d] STAT_WRITE_DATA_PARITY_ERROR occurred",
							sys_mc_num);
				reg_clear_irq |= STAT_WRITE_DATA_PARITY_ERROR_MASK;
			}
			if (reg_val & STAT_READ_DATA_PARITY_ERROR_MASK) {
				cn_dev_core_err(core,
							"mc[%d] STAT_READ_DATA_PARITY_ERROR occurred occurred",
							sys_mc_num);
				reg_clear_irq |= STAT_READ_DATA_PARITY_ERROR_MASK;
			}
			if (reg_val & ONE_BIT_ECC_ERROR_MASK) {
				cn_xid_err(core, XID_ECC_ERR, "mc[%d] ONE_BIT_ECC_ERROR occurred occurred",
					sys_mc_num);
				ecc_info->one_bit_ecc_error++;
				reg_clear_irq |= ONE_BIT_ECC_ERROR_MASK;

				reg32 = hbm_mlu290_read32(core, sys_mc_num, STAT_ECC_1BIT_ERROR_ADDR);
				cn_dev_core_debug(core, "STAT_ECC_1BIT_ERROR_ADDR: %#x ", reg32);

				reg32 = hbm_mlu290_read32(core, sys_mc_num,
								STAT_ECC_1BIT_ERROR_POS);
				cn_dev_core_debug(core, "STAT_ECC_1BIT_ERROR_POS: %#x ", reg32);
				reg32 = hbm_mlu290_read32(core, sys_mc_num,
								STAT_ECC_1BIT_ERROR_RMW);
				cn_dev_core_debug(core, "STAT_ECC_1BIT_ERROR_RMW: %#x ", reg32);

			}
			if (reg_val & STAT_INT_ECC_1BIT_THRESH_MASK) {
				cn_xid_err(core, XID_ECC_ERR, "mc[%d] STAT_INT_ECC_1BIT_THRESH occurred",
					sys_mc_num);
				reg_clear_irq |= STAT_INT_ECC_1BIT_THRESH_MASK;
			}
			if (reg_val & TWO_BIT_ECC_ERROR_MASK) {
				cn_xid_err(core, XID_ECC_ERR, "mc[%d] TWO_BIT_ECC_ERROR occurred",
							sys_mc_num);
				ecc_info->multiple_one_bit_ecc_error++;
				reg_clear_irq |= TWO_BIT_ECC_ERROR_MASK;

				reg32 = hbm_mlu290_read32(core, sys_mc_num,
								STAT_ECC_2BIT_ERROR_ADDR);
				cn_dev_core_debug(core, "STAT_ECC_2BIT_ERROR_ADDR: %#x ", reg32);

				reg32 = hbm_mlu290_read32(core, sys_mc_num,
								STAT_ECC_2BIT_ERROR_RMW);
				cn_dev_core_debug(core, "STAT_ECC_2BIT_ERROR_RMW: %#x ", reg32);
			}
			if (reg_val & STAT_CA_PARITY_ERROR_MASK) {
				cn_dev_core_err(core,
							"mc[%d] STAT_CA_PARITY_ERROR occurred",
							sys_mc_num);
				reg_clear_irq |= STAT_CA_PARITY_ERROR_MASK;
			}

			hbm_mlu290_write32(core, sys_mc_num,
						STAT_INTERRUPT, reg_clear_irq);
		}
	}

	return IRQ_HANDLED;
}

void hbm_exit_mlu290(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	int i;
	/* mask all hbm irq */
	for (i = 0; i < TOTAL_MC_NUM; i++) {
		hbm_mlu290_write32(core, i, INIT_INTERRUPT_MASK, 0xFFFFFFFF);
	}

	for (i = 0; i < MLU290_HBM_CHANNEL_COUNT; i++) {
		cn_bus_disable_irq(core->bus_set, MLU290_HBM_IRQ_OFF(i));
		cn_bus_unregister_interrupt(core->bus_set, MLU290_HBM_IRQ_OFF(i));
	}

	if (mcc_set->ecc_status) {
		cn_kfree(mcc_set->ecc_status);
	}
}

int ddr_get_channel_num_mlu290(void *mset)
{
	return MLU290_HBM_CHANNEL_COUNT;
}

void *ddr_get_ecc_status_mlu290(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;

	return mcc_set->ecc_status;
}

void hbm_repair_exit_mlu290(void *mset)
{
	int count = 100;
	bool workq_ret = false;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core;
	struct hbm_repair_set *repair_set;

	if (!mcc_set)
		return;
	core = (struct cn_core_set *)mcc_set->core;
	repair_set = (struct hbm_repair_set *)mcc_set->repair_set;
	if (!repair_set)
		return;

	if (repair_set->repair_state == REPAIR_STOP ||
		repair_set->repair_state == REPAIR_ABORT) {
		goto FREE;
	}
	if (repair_set->repair_state != REPAIR_FINISH)
		repair_set->repair_state = REPAIR_ABORT;
	while (--count) {
		if (repair_set->repair_state == REPAIR_FINISH) {
			break;
		}
		msleep(20);
	}
	if (!count) {
		cn_dev_core_err(core, "repair workq exit timeout");
		goto FREE;
	}
	repair_set->repair_state = REPAIR_ABORT;
	if (!core->repair_active) {
		flush_work(&core->repair_work);
		workq_ret = cancel_work_sync(&core->repair_work);
		if (workq_ret)
			cn_dev_core_info(core,
				"repair 1bit work sync = %d", workq_ret);
	}
FREE:
	if (repair_set)
		cn_kfree(repair_set);
	mcc_set->repair_set = NULL;
	mcc_set->repair_ops = NULL;
	cn_dev_core_info(core, "done");
}

/*TODO: use union for diff platform */
static const struct cn_mcc_ops hbm_ops_mlu290 = {
	.get_channel_num = ddr_get_channel_num_mlu290,
	.get_ecc_status = ddr_get_ecc_status_mlu290,
	.mcc_exit = hbm_exit_mlu290,
	.repair_exit = hbm_repair_exit_mlu290,
	.get_d2dc_num = NULL,
	.get_d2dc_status = NULL,
};

int hbm_init_mlu290(struct cn_mcc_set *mcc_set)
{
	int i, ret = 0;
	u32 reg_val = 0;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	if (IS_ERR_OR_NULL(mcc_set)) {
		pr_err("memory ctrl set is null");
		return -EINVAL;
	}

	mcc_set->mcc_ops = &hbm_ops_mlu290;

	mcc_set->d2dc_status = NULL;
	mcc_set->ecc_status =
		cn_kcalloc(MLU290_HBM_CHANNEL_COUNT, sizeof(struct ecc_info_t),
				GFP_KERNEL);
	if (!mcc_set->ecc_status) {
		cn_dev_core_err(core, "malloc for ecc struct fail");
		return -ENOMEM;
	}
	memset(mcc_set->ecc_status, 0,
			MLU290_HBM_CHANNEL_COUNT * sizeof(struct ecc_info_t));

	cn_dev_core_debug(core,
			"enable hbm overheating irq for overheating protection");
	for (i = 0; i < TOTAL_MC_NUM; i++) {
		/* clear the err irq status of DFI_TEMP [DRIVER-2106] */
		hbm_mlu290_write32(core, i, STAT_INTERRUPT, DFI_TEMP_MASK);
		/* set irq mask reg to disable irq */
		reg_val = DFI_TEMP_MASK + STAT_WRITE_DATA_PARITY_ERROR2_MASK;
		hbm_mlu290_write32(core, i, INIT_INTERRUPT_MASK, reg_val);
	}

	cn_dev_core_debug(core, "register hbm irq for overheating protection");
	for (i = 0; i < MLU290_HBM_CHANNEL_COUNT; i++) {
		ret = cn_bus_register_interrupt(core->bus_set,
				MLU290_HBM_IRQ_OFF(i),
				hbm_mlu290_intr_handle,
				(void *)mcc_set);
		ret |= cn_bus_enable_irq(core->bus_set, MLU290_HBM_IRQ_OFF(i));
		if (ret) {
			cn_dev_core_err(core,
					"register hbm irq %d failed", MLU290_HBM_IRQ_OFF(i));
			break;
		}
	}

	return ret;
}
#ifdef HBM_SOFT_REPAIR
static void hbm_repair_decode(struct hbm_repair_set *repair_set)
{
	int i, j;
	unsigned int eeprom_num;
	unsigned int *rom_info;
	struct hbm_repair_info_set *decode;
	int repair_index = 0;
	int flag = 0;

	if (!repair_set)
		return;

	eeprom_num = repair_set->eeprom_num;
	rom_info = repair_set->rom_info;
	decode = repair_set->decode;
	for (i = 0; i < eeprom_num; i++) {
		/* fix: repeat the recorded information already in eeprom*/
		if (rom_info[i] == 0) {
			continue;
		}
		for (j = 0; j < repair_index; j++) {
			if ((decode[j].info.eeprom_info << 1) == (rom_info[i] << 1)) {
				flag = 1;
				break;
			}
		}
		if (!flag) {
			decode[repair_index].info.eeprom_info = rom_info[i];
			decode[repair_index].ecc_addr = GET_ECC_ADDR(rom_info[i]);
			decode[repair_index].bank = GET_BANK(decode[repair_index].ecc_addr);
			decode[repair_index].sid = GET_SID(decode[repair_index].ecc_addr);
			decode[repair_index].row = GET_ROW(decode[repair_index].ecc_addr);
			repair_index++;
		}
		flag = 0;
	}
	/* 2BIT_ECC add 20-times 1BIT_ECC total number*/
	repair_set->decode_rom_index = repair_index;
	repair_set->decode_num = repair_index;
}
#endif

static void
hbm_get_retire_info(void *mset, struct hbm_retire_info_t **retire_info,
		unsigned int *retire_num, int irq_flag)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_repair_set *repair_set;

	if (retire_num)
		*retire_num = 0;

	repair_set = (struct hbm_repair_set *)mcc_set->repair_set;
	if (!repair_set) {
		cn_dev_core_err(core, "repair_set is NULL");
		return;
	}
	if (!retire_info || !retire_num)
		return;
	if (irq_flag) {
		*retire_info = &repair_set->retire_info[repair_set->retire_rom_index];
		*retire_num = repair_set->retire_num - repair_set->retire_rom_index;
	} else {
		*retire_info = repair_set->retire_info;
		*retire_num = repair_set->retire_rom_index;
	}
}

static int hbm_get_retire_pages(void *mset, int cause, unsigned int *pagecount,
			u64 **page_addr)
{
	int ret = -1;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_repair_set *repair_set;

	if (pagecount)
		*pagecount = 0;

	if (cause != ECC_BIT_1 && cause != ECC_BIT_2) {
		cn_dev_err("cause%d is error", cause);
		return ret;
	}

	repair_set = (struct hbm_repair_set *)mcc_set->repair_set;
	if (!repair_set) {
		cn_dev_core_err(core, "repair_set is NULL");
		return ret;
	}
	memset(repair_set->retire_page, 0, sizeof(repair_set->retire_page));
	ret = cn_mem_pgr_get_pages(core, cause, &repair_set->retire_page_num,
						repair_set->retire_page);
	if (ret)
		return ret;
	if (!pagecount || !page_addr)
		return -1;
	*pagecount = repair_set->retire_page_num;
	*page_addr = repair_set->retire_page;

	return ret;
}

static int hbm_get_retire_pages_pending_status(void *mset, int *ispending,
								int *isfailure)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	return cn_mem_pgr_get_status(core, ispending, isfailure);
}

static int hbm_get_remapped_rows(void *mset, unsigned int *corr_rows,
			unsigned int *unc_rows, unsigned int *pending_rows,
			unsigned int *fail_rows)
{
	int i;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_repair_set *repair_set;

	repair_set = (struct hbm_repair_set *)mcc_set->repair_set;
	if (!repair_set) {
		cn_dev_core_err(core, "repair_set is NULL");
		return -1;
	}

	*corr_rows = 0;
	*unc_rows = 0;
	*pending_rows = 0;
	*fail_rows = 0;
	for (i = 0; i < repair_set->decode_num; i++) {
		if (GET_ECC_BIT(repair_set->decode[i].info.eeprom_info) == ECC_BIT_1)
			(*corr_rows)++;
		else
			(*unc_rows)++;
		if (repair_set->decode[i].fix_type == FIX_PENDING)
			(*pending_rows)++;
		if (repair_set->decode[i].fix_type == FIX_FAILURE)
			(*fail_rows)++;
	}

	return 0;
}

static int hbm_retire_switch(void *mset, int status)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_repair_set *repair_set;

	repair_set = (struct hbm_repair_set *)mcc_set->repair_set;
	if (!repair_set) {
		cn_dev_core_err(core, "repair_set is NULL");
		return -1;
	}

	if (status != 0 && status != 1)
		return repair_set->retire_enable;

	__sync_lock_test_and_set(&repair_set->retire_enable, status);

	return repair_set->retire_enable;
}

static int hbm_get_eeprom_switch(void *mset, int status)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_repair_set *repair_set;

	repair_set = (struct hbm_repair_set *)mcc_set->repair_set;
	if (!repair_set) {
		cn_dev_core_err(core, "repair_set is NULL");
		return -1;
	}

	if (status != 0 && status != 1)
		return repair_set->eeprom_enable;

	__sync_lock_test_and_set(&repair_set->eeprom_enable, status);

	return repair_set->eeprom_enable;
}

static int hbm_get_eeprom_info(void *mset, unsigned int **rom_info,
			unsigned int *eeprom_num)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct hbm_repair_set *repair_set;
	int i;

	repair_set = (struct hbm_repair_set *)mcc_set->repair_set;
	if (!repair_set) {
		cn_dev_core_err(core, "repair_set is NULL");
		return -1;
	}

	if (!repair_set->eeprom_enable) {
		cn_dev_core_err(core, "driver debug ecc mode!!!");
		cn_dev_core_err(core, "ecc_info is total ecc_num=%#x",
							repair_set->ecc_num);
		for (i = 0; i < repair_set->ecc_num; i++) {
			cn_dev_core_info(core, "[%d]:[%#x]:[%d]",
				i, repair_set->ecc_info[i], repair_set->ecc_1bit_cnt[i]);
		}
		cn_dev_core_err(core, "encode_info is total encode_num=%#x",
							repair_set->encode_num);
		cn_dev_core_err(core,
			"id\teeprom_info\t30biteccaddr\t24biteccaddr\tbank\tsid\trow\t");
		for (i = 0; i < repair_set->encode_num; i++) {
			cn_dev_core_info(core, "[%d]:[%#x]:[%#x]:[%#x]:[%d]:[%d]:[%d]",
						i,
						repair_set->encode[i].info.eeprom_info,
						repair_set->encode[i].ecc_addr,
						repair_set->encode[i].ecc_addr >> 6,
						repair_set->encode[i].bank,
						repair_set->encode[i].sid,
						repair_set->encode[i].row);
		}
		cn_dev_core_err(core,
			"decode_info is total decode_num=%#x, eeprom_index=%#x",
				repair_set->decode_num, repair_set->decode_rom_index);
		cn_dev_core_err(core,
			"id\teeprom_info\t30biteccaddr\t24biteccaddr\tbank\tsid\trow\t");
		for (i = 0; i < repair_set->decode_num; i++) {
			cn_dev_core_info(core, "[%d]:[%#x]:[%#x]:[%#x]:[%d]:[%d]:[%d]",
						i,
						repair_set->decode[i].info.eeprom_info,
						repair_set->decode[i].ecc_addr,
						repair_set->decode[i].ecc_addr >> 6,
						repair_set->decode[i].bank,
						repair_set->decode[i].sid,
						repair_set->decode[i].row);
		}
	}

	*rom_info = &repair_set->rom_info[0];
	*eeprom_num = repair_set->eeprom_num;

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

	*sys_mc_num = TOTAL_MC_NUM;

	return 0;
}

#ifdef MLU290_HBM
static const struct cn_repair_ops hbm_repair_ops_mlu290 = {
	.get_retire_info = hbm_get_retire_info,
	.get_retire_pages = hbm_get_retire_pages,
	.get_retire_pages_pending_status = hbm_get_retire_pages_pending_status,
	.get_remapped_rows = hbm_get_remapped_rows,
	.retire_switch = hbm_retire_switch,
	.ecc_irq_inject = hbm_ecc_irq_inject,
	.get_eeprom_switch = hbm_get_eeprom_switch,
	.get_eeprom_info = hbm_get_eeprom_info,
	.get_sys_mc_nums = hbm_get_sys_mc_nums,
};

int hbm_repair_init_mlu290(struct cn_mcc_set *mcc_set)
{
	int ret = 0;
	int i;
#ifdef HBM_SOFT_REPAIR
	int index;
	unsigned int hbm_num;
	unsigned int chn_num;
#endif
	struct hbm_repair_set *repair_set = NULL;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	repair_set = cn_kzalloc(sizeof(struct hbm_repair_set), GFP_KERNEL);
	if (!repair_set) {
		cn_dev_core_err(core, "kzalloc repair_set error");
		return -1;
	}
	repair_set->eeprom_num = EEPROM_MAX_NUM;
#ifdef HBM_SOFT_REPAIR
	repair_set->retire_enable = 1;
	repair_set->eeprom_enable = 1;
#endif
	repair_set->mcc_set = mcc_set;
	mcc_set->repair_set = repair_set;
	mcc_set->repair_ops = &hbm_repair_ops_mlu290;

	/* hbm init and get not fuse info*/
	repair_set->fuse_flag = 1;
	ret = hbm_boot_prepare(repair_set);
	if (ret) {
		cn_dev_core_err(core, "first hbm_boot_prepare error");
		goto exit;
	}

	if (cn_bus_is_support_soft_repair_info(core->bus_set))
		return ret;

	/* mcu get eeprom_info interface*/
	ret = cn_bus_get_soft_repair_info(core->bus_set,
			repair_set->rom_info, &repair_set->eeprom_num);
	if (ret) {
		cn_dev_core_err(core, "get soft repair info error");
		goto exit;
	}
	cn_dev_core_info(core, "eeprom_num = %d", repair_set->eeprom_num);
	for (i = 0; i < repair_set->eeprom_num; i++)
		cn_dev_core_info(core, "rom_info[%d]=%#x", i,
						repair_set->rom_info[i]);
	if (repair_set->eeprom_num >= EEPROM_MAX_NUM) {
		ret = -1;
		cn_dev_core_err(core, "retire eeprom num >= 512 !!!");
		goto exit;
	}

#ifdef HBM_SOFT_REPAIR
	/* eeprom info decode*/
	hbm_repair_decode(repair_set);

	for (i = 0; i < repair_set->decode_num; i++) {
		hbm_num = GET_HBM_NUM(repair_set->decode[i].info.eeprom_info);
		chn_num = GET_CHN_NUM(repair_set->decode[i].info.eeprom_info);
		index = repair_set->decode[i].bank +
			repair_set->decode[i].sid * HBM_BNK_NUM +
				chn_num * HBM_SID_NUM * HBM_BNK_NUM +
				hbm_num * HBM_FUSE_NUM;
		if ((int)repair_set->fuse_info[index] < HBM_MAX_FUSE) {
			ret = mcc_decode_cell_repair(core, repair_set->decode[i]);
			if (ret) {
				cn_dev_core_info(core, "cell repair failed");
				/* goto retire process*/
				cn_dev_core_info(core, "keep retire info");
				ret = hbm_retire_decode(repair_set,
					repair_set->decode[i].info.eeprom_info);
				if (ret)
					goto exit;
				repair_set->decode[i].fix_type = FIX_FAILURE;

			} else {
				repair_set->decode[i].fix_type = FIX_REPAIR;
				repair_set->fuse_info[index]++;
			}
		} else {
			/* goto retire process*/
			ret = hbm_retire_decode(repair_set,
				repair_set->decode[i].info.eeprom_info);
			if (ret)
				goto exit;
			repair_set->decode[i].fix_type = FIX_FAILURE;
		}
	}
	repair_set->retire_rom_index = repair_set->retire_num;
	cn_dev_core_info(core, "HBM retire_num = %d", repair_set->retire_num);

	repair_set->repair_state = REPAIR_STOP;
	if (!core->repair_active)
		INIT_WORK(&core->repair_work, hbm_ecc_repair_work);
	mutex_init(&repair_set->repair_mutex);
#endif

	return ret;
exit:
	hbm_repair_exit_mlu290(mcc_set);

	return ret;
}
#endif
