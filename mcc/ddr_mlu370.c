#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/kthread.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include "cndrv_xid.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_pre_compile.h"
#include "cndrv_nor.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_gdma.h"
#include "cndrv_mcc.h"
#include "mcc_main.h"
#include "cndrv_mcu.h"
#include "ddr_retire_mlu370.h"
#include "cndrv_kwork.h"

/* d2dc count */
#define	MLU370_D2DC_CNT                   (4)
/* d2dc ctrl count */
#define	MLU370_D2DC_CTRL_CNT              (MLU370_D2DC_CNT * 2)
/* name length */
#define MAX_STRING_LEN                    (16)
/* shuffle register */
#define MLU370_SYSCTRL_BASE               (0x368000)
#define MLU370_SYSCTRL_ADDRESS_MAP        (MLU370_SYSCTRL_BASE + 0x90)

#define	MLU370_TOPCRG_MEM_RESET_BASE      0x083d4420
#define	MLU370_LLC0_BASE                  0x0834A000
#define	MLU370_LLC1_BASE                  0x0834B000
#define	MLU370_LLC2_BASE                  0x0034A000
#define	MLU370_LLC3_BASE                  0x0034B000
#define	MLU370_DIE_CFG_OFFSET             0x10000000
/* timer expires */
#define MCC_TIMER_EXPIRES_MSEC(x)         (jiffies + msecs_to_jiffies(x))
/* d2d_ctrl*/
#define MLU370_D2DC_PER_SYSTEM_CNT        (2)
#define RX_ARQ_ACK_TIMEOUT_OFFSET         (2)
#define RX_ARQ_CRC_ECO_OFFSET             (11)
#define RX_CRC_ECO_OFFSET                 (12)
#define D2DC_CRC_MASK                     (~((1<<RX_ARQ_ACK_TIMEOUT_OFFSET) | \
	(1<<RX_ARQ_CRC_ECO_OFFSET) |\
	(1<<RX_CRC_ECO_OFFSET)))
/* DIE BASE ADDRESS*/
#define MLU370_DIE0_BASE                  (0x0)
#define MLU370_DIE1_BASE                  (0x10000000)
/* D2DC SYS BASE ADDRESS */
#define MLU370_D2DC_SYSTEM0_BASE          (0x8370000)
#define MLU370_D2DC_SYSTEM1_BASE          (0x3d0000)
/* D2DC SYS CTRL BASE ADDRESS */
#define MLU370_D2DC_CTRL0_OFFSET          (0x1000)
#define MLU370_D2DC_CTRL1_OFFSET          (0x2000)
/* D2DC REG OFFSET */
#define MLU370_D2DC_RX_CRC_ERR_OFFSET     (0x20)
#define MLU370_D2DC_RX_ARQ_CRC_ERR_OFFSET (0x24)
#define MLU370_D2DC_INTR_STATE_OFFSET     (0x10)
#define MLU370_D2DC_INTR_MASK_OFFSET      (0x14)
/* D2DC irq */
#define MLU370_D2DC0_SYSTEM0_IRQ          (163)
#define MLU370_D2DC0_SYSTEM1_IRQ          (164)
#define MLU370_D2DC1_SYSTEM0_IRQ          (358)
#define MLU370_D2DC1_SYSTEM1_IRQ          (359)
#define DAY_TO_MSEC(x)                    ((u64)(x) * 24 * 60 * 60 * 1000)

#define MLU370_D0_SYS0_D2DC0_BASE         (0x8371000)
#define MLU370_D0_SYS0_D2DC1_BASE         (0x8372000)
#define MLU370_D0_SYS1_D2DC0_BASE         (0x3d1000)
#define MLU370_D0_SYS1_D2DC1_BASE         (0x3d2000)
#define MLU370_D1_SYS0_D2DC0_BASE         (0x18371000)
#define MLU370_D1_SYS0_D2DC1_BASE         (0x18372000)
#define MLU370_D1_SYS1_D2DC0_BASE         (0x103d1000)
#define MLU370_D1_SYS1_D2DC1_BASE         (0x103d2000)

/*D2DC CRC ERROR THRESHOLD */
#define MLU370_D2DC_RX_CRC_ERR_THRESHOLD  (1000)
#define MLU370_D2DC_CRC_CNT_MASK          (0x7FFF)
#define MLU370_D2DC_CRC_OF_MASK           ((1) << 15)

/* DDR INLINE ECC irq */
#define MLU370_DIE0_MEMSYS0_IRQ           (80)
#define MLU370_DIE0_MEMSYS1_IRQ           (81)
#define MLU370_DIE0_MEMSYS2_IRQ           (82)
#define MLU370_DIE0_MEMSYS3_IRQ           (83)
#define MLU370_DIE0_MEMSYS4_IRQ           (84)
#define MLU370_DIE0_MEMSYS5_IRQ           (85)
#define MLU370_D2D_IRQ_OFFSET             (195)
#define MLU370_DIE1_MEMSYS0_IRQ           ((MLU370_DIE0_MEMSYS0_IRQ) + MLU370_D2D_IRQ_OFFSET)
#define MLU370_DIE1_MEMSYS1_IRQ           ((MLU370_DIE0_MEMSYS1_IRQ) + MLU370_D2D_IRQ_OFFSET)
#define MLU370_DIE1_MEMSYS2_IRQ           ((MLU370_DIE0_MEMSYS2_IRQ) + MLU370_D2D_IRQ_OFFSET)
#define MLU370_DIE1_MEMSYS3_IRQ           ((MLU370_DIE0_MEMSYS3_IRQ) + MLU370_D2D_IRQ_OFFSET)
#define MLU370_DIE1_MEMSYS4_IRQ           ((MLU370_DIE0_MEMSYS4_IRQ) + MLU370_D2D_IRQ_OFFSET)
#define MLU370_DIE1_MEMSYS5_IRQ           ((MLU370_DIE0_MEMSYS5_IRQ) + MLU370_D2D_IRQ_OFFSET)

#define	MLU370_DIE0_MEMSYS0_BASE          (0x08400000)
#define	MLU370_DIE0_MEMSYS1_BASE          (0x08440000)
#define	MLU370_DIE0_MEMSYS2_BASE          (0x08480000)
#define	MLU370_DIE0_MEMSYS3_BASE          (0x00400000)
#define	MLU370_DIE0_MEMSYS4_BASE          (0x00440000)
#define	MLU370_DIE0_MEMSYS5_BASE          (0x00480000)
#define	MLU370_DIE_OFFSET                 (0x10000000)
#define	MLU370_DIE1_MEMSYS0_BASE          ((MLU370_DIE0_MEMSYS0_BASE) + MLU370_DIE_OFFSET)
#define	MLU370_DIE1_MEMSYS1_BASE          ((MLU370_DIE0_MEMSYS1_BASE) + MLU370_DIE_OFFSET)
#define	MLU370_DIE1_MEMSYS2_BASE          ((MLU370_DIE0_MEMSYS2_BASE) + MLU370_DIE_OFFSET)
#define	MLU370_DIE1_MEMSYS3_BASE          ((MLU370_DIE0_MEMSYS3_BASE) + MLU370_DIE_OFFSET)
#define	MLU370_DIE1_MEMSYS4_BASE          ((MLU370_DIE0_MEMSYS4_BASE) + MLU370_DIE_OFFSET)
#define	MLU370_DIE1_MEMSYS5_BASE          ((MLU370_DIE0_MEMSYS5_BASE) + MLU370_DIE_OFFSET)
#define	MLU370_MEMSYS_CNT                 (12)
#define	MLU370_CHL_PER_MEMSYS_CNT         (2)
#define MLU370_MSYS_CNT(die_cnt) \
	(((die_cnt) >= 2) ? MLU370_MEMSYS_CNT : (MLU370_MEMSYS_CNT >> 1))

/* NOTE: 8 LLC total reserved size is 1GB + 50MB, each LLC reserved size:
 * 128MB + 7MB. LLC internal interleaving mode is uneven, each channel
 * in LLC reserved size without consider 7MB is (44MB, 44MB, 40MB), so
 * we set each channel div1 start at 44MB + 7MB is much more safe */
static unsigned long ile_unprotect_base = 0x0;
static unsigned long ile_unprotect_size = 0x33UL << 20;

enum retire_work_status {
	RETIRE_WORK_IDLE,
	RETIRE_WORK_READY,
	RETIRE_WORK_RUNNING,
};

enum address_check_mode {
	CHECK_USE_DMA = 0x0,
	CHECK_USE_GDMA = 0x1,
};

struct norflash_info_t {
	uint16_t magic;
	uint16_t length;
	uint16_t counts;
	uint64_t addrs[0];
} __attribute__ ((aligned(4))); /* norflash read/write need make sure buffer 4Btye aligned */

#define NORFLASH_PADDR  (0x1C0000)
#define NORFLASH_MAGIC  ((0x0104) + (0x370) + 'P' + 'N')
#define NORFLASH_LEN(count) \
	(sizeof(struct norflash_info_t) + sizeof(uint64_t) * (count))

#define MAX_IECC_NODE_COUNTS (64)
struct iecc_node_t {
	unsigned long secs;
	unsigned char type[MLU370_CHL_PER_MEMSYS_CNT];
};

struct iecc_info_t {
	unsigned long sbe;
	unsigned long dbe;
	unsigned long over_flow;
	unsigned long others;
	struct iecc_node_t nodes[MAX_IECC_NODE_COUNTS];
	unsigned int total_counts;
};

struct ddr_retire_set {
	/* structure used for find error address */
	struct cn_mcc_set *mcc_set;
	struct retire_bits_t *bitmap;
	unsigned int check_mode;
	union {
		void *host_buffer;
		struct {
			unsigned long dev_vaddr;
			unsigned long host_vaddr;
		};
	};

	struct iecc_info_t *iecc_status;

	unsigned int work_params;
	atomic_t work_status;
	struct work_struct retire_work;

	/* data used for page retired */
	struct hbm_retire_info_t retire_info[EEPROM_MAX_NUM];
	unsigned int retire_num;
	unsigned int retire_index; /* specific retire address numbers in init process */

	/* data saved in norflash */
	struct norflash_info_t *norflash_info;
	/* norflash_enable 0: only support read norflash, 1: support read write norflash */
	atomic_t norflash_enable;

	/* data saved retire pages read from memory module */
	u64 retire_page[EEPROM_MAX_NUM];
	unsigned int retire_page_num;
	/* retire_enable 0: not support do memory module page retire*/
	atomic_t retire_enable;

	/* used for debug inject error */
	unsigned long dbg_level_idx[MAX_LEVEL];
	unsigned long dbg_level_times[MAX_LEVEL];
	bool debug_mode;
};

struct die2die_reg {
	const char d2dc_ctrl[MAX_STRING_LEN];
	const u32 reg_base;
} mlu370_die2die_reg[MLU370_D2DC_CTRL_CNT] = {
	{"D0-SYS0-D2DC0", MLU370_D0_SYS0_D2DC0_BASE},
	{"D0-SYS0-D2DC1", MLU370_D0_SYS0_D2DC1_BASE},
	{"D0-SYS1-D2DC0", MLU370_D0_SYS1_D2DC0_BASE},
	{"D0-SYS1-D2DC1", MLU370_D0_SYS1_D2DC1_BASE},
	{"D1-SYS0-D2DC0", MLU370_D1_SYS0_D2DC0_BASE},
	{"D1-SYS0-D2DC1", MLU370_D1_SYS0_D2DC1_BASE},
	{"D1-SYS1-D2DC0", MLU370_D1_SYS1_D2DC0_BASE},
	{"D1-SYS1-D2DC1", MLU370_D1_SYS1_D2DC1_BASE},
};

struct memsys_reg {
	const char name[MAX_STRING_LEN];
	const u32 reg_base;
} mlu370_memsys_reg[MLU370_MEMSYS_CNT] = {
	{"DIE0_MEMSYS0_UMC", MLU370_DIE0_MEMSYS0_BASE},
	{"DIE0_MEMSYS1_UMC", MLU370_DIE0_MEMSYS1_BASE},
	{"DIE0_MEMSYS2_UMC", MLU370_DIE0_MEMSYS2_BASE},
	{"DIE0_MEMSYS3_UMC", MLU370_DIE0_MEMSYS3_BASE},
	{"DIE0_MEMSYS4_UMC", MLU370_DIE0_MEMSYS4_BASE},
	{"DIE0_MEMSYS5_UMC", MLU370_DIE0_MEMSYS5_BASE},
	{"DIE1_MEMSYS0_UMC", MLU370_DIE1_MEMSYS0_BASE},
	{"DIE1_MEMSYS1_UMC", MLU370_DIE1_MEMSYS1_BASE},
	{"DIE1_MEMSYS2_UMC", MLU370_DIE1_MEMSYS2_BASE},
	{"DIE1_MEMSYS3_UMC", MLU370_DIE1_MEMSYS3_BASE},
	{"DIE1_MEMSYS4_UMC", MLU370_DIE1_MEMSYS4_BASE},
	{"DIE1_MEMSYS5_UMC", MLU370_DIE1_MEMSYS5_BASE},
};


static inline void __mlu370_add_llc_base(int index, unsigned long *addrs)
{
	switch ((index) % 4) {
	case 0:
		*addrs += MLU370_LLC0_BASE;
		break;
	case 1:
		*addrs += MLU370_LLC1_BASE;
		break;
	case 2:
		*addrs += MLU370_LLC2_BASE;
		break;
	case 3:
		*addrs += MLU370_LLC3_BASE;
		break;
	default:
		break;
	}
}

static u64 __mlu370_get_real_time(void)
{
	u64 tv_sec = 0;
#if (KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE)
	struct timespec64 ts64;
	ktime_get_real_ts64(&ts64);
	tv_sec = ts64.tv_sec;
#else
	struct timeval tv;
	do_gettimeofday(&tv);
	tv_sec = tv.tv_sec;
#endif

	return tv_sec;
}

/* NOTE: input params ddr_cap's unit is GB, return value unit is Byte */
static unsigned long __per_chl_size(struct cn_core_set *core, bool ile_status)
{
	struct cn_board_info *pboardi = &core->board_info;
	unsigned long per_chl_sz_gb = pboardi->ddr_cap >> 3;

	/* if inline ECC enable, each channel remain 910MB per GB */
	return ile_status ? (910UL << 20) * per_chl_sz_gb : per_chl_sz_gb << 30;
}

static void memsys_llc_init(void *bus_set, int die_cnt)
{
	unsigned int i = 0;
	unsigned int read_result = 0;
	unsigned int memsys_cnt = 0;
	unsigned int llc_cnt = 0;
	unsigned long llc_reset_addr = 0;
	unsigned long llc_remap_addr = 0;
	unsigned long llc_chcap_addr = 0;
	unsigned long sys_addrmap_addr = 0;
	struct cn_core_set *core = ((struct cn_bus_set *)bus_set)->core;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	struct memsys_config_st *msys_config = &mcc_set->msys_config;

	unsigned int shuffle_en = msys_config->mlu370.shuffle_en;
	unsigned int interleave_size = msys_config->mlu370.interleave_size;
	unsigned int llc_interleave_mode = msys_config->mlu370.llc_interleave_mode;
	unsigned int llc_3chl_mode = msys_config->mlu370.llc_3chl_mode;
	unsigned int chl_remap_mode = msys_config->mlu370.chl_remap_mode;
	unsigned int ch_cap_x512 = msys_config->mlu370.ch_cap_x512;

	memsys_cnt = die_cnt * 6;
	llc_cnt = die_cnt * 4;

	/* Die0 east intr from d2d.*/
	reg_write32(bus_set, 0x368098, 0x1);

	/* MEMSYS dereset */
	for (i = 0; i < memsys_cnt; i++)
		reg_write32(bus_set, (i / 6) * MLU370_DIE_CFG_OFFSET
				+ MLU370_TOPCRG_MEM_RESET_BASE + (i % 6) * 0x04, 0x1);

	/* LLC dereset */
	for (i = 0; i < llc_cnt; i++) {
		llc_reset_addr = MLU370_DIE_CFG_OFFSET * (i/4) + 0x104;
		__mlu370_add_llc_base(i, &llc_reset_addr);
		reg_write32(bus_set, llc_reset_addr, 0x1);
	}

	/* LLC remap */
	for (i = 0; i < llc_cnt; i++) {
		llc_remap_addr = MLU370_DIE_CFG_OFFSET * (i / 4) + 0x8C;

		__mlu370_add_llc_base(i, &llc_remap_addr);

		read_result = reg_read32(bus_set, llc_remap_addr);
		/* Set LLC remap mode as 3chl interleave no waste */
		read_result = read_result & ~(0x7ff);
		read_result |= (llc_interleave_mode & 0x3);
		read_result |= (llc_3chl_mode & 0x1) << 4;
		read_result |= (chl_remap_mode & 0x7) << 8;
		reg_write32(bus_set, llc_remap_addr, read_result);
	}

	/* LLC capacity */
	for (i = 0; i < llc_cnt; i++) {
		llc_chcap_addr = MLU370_DIE_CFG_OFFSET * (i / 4) + 0x90;

		__mlu370_add_llc_base(i, &llc_chcap_addr);

		read_result = reg_read32(bus_set, llc_chcap_addr);
		read_result = read_result & ~0xffffff;
		read_result = read_result | ch_cap_x512;
		reg_write32(bus_set, llc_chcap_addr, read_result);
	}

	/* ddr shuffle init */
	for (i = 0; i < die_cnt; i++) { /* die_cnt equal to 1 / 2 */
		sys_addrmap_addr =
			MLU370_SYSCTRL_ADDRESS_MAP + i * MLU370_DIE_CFG_OFFSET;
		read_result = reg_read32(bus_set, sys_addrmap_addr);
		read_result ^= read_result;
		read_result |= (interleave_size & 0x3);
		read_result |= (shuffle_en << 8);
		reg_write32(bus_set, sys_addrmap_addr, read_result);
	}

	/* CPU dereset */
	reg_write32(bus_set, 0x83d4448, 0x1);  //cpu reset 0x80083d4448
}

void ddr_mlu370_write32(void *pcore, u8 ddr_index, u32 reg_index, u32 value)
{
}

u32 ddr_mlu370_read32(void *pcore, u8 ddr_index, u32 reg_index)
{
	return 0;
}

int ddr_get_channel_num_mlu370(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = NULL;

	core = (struct cn_core_set *)mcc_set->core;
	if (!core) {
		cn_dev_err("core is null");
		return 0;
	}

	return MLU370_MSYS_CNT(core->die_cnt);
}

int ddr_get_d2dc_num_mlu370(void *mset)
{
	return MLU370_D2DC_CTRL_CNT;
}

void *ddr_get_d2dc_status_mlu370(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;

	return mcc_set->d2dc_status;
}

void *ddr_get_ecc_status_mlu370(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;

	return mcc_set->ecc_status;
}

void d2dc_crc_callback(struct cn_core_set *core, struct cn_mcc_set *mcc_set,
	struct die2die_crc_info_t  *crc_info)
{
	int i = 0;
	u32 reg_addr = 0;
	u32 crc_cnt = 0;
	u32 crc_of = 0;
	u64 day_crc_cnt = 0;

	for (i = 0; i < MLU370_D2DC_CTRL_CNT; i++) {
		reg_addr = mlu370_die2die_reg[i].reg_base;

		crc_cnt = reg_read32(core->bus_set,
			reg_addr + MLU370_D2DC_RX_CRC_ERR_OFFSET);
		crc_of = crc_cnt & MLU370_D2DC_CRC_OF_MASK;
		crc_cnt = crc_cnt & MLU370_D2DC_CRC_CNT_MASK;

		/* print counter overflow err */
		if (crc_of) {
			cn_dev_core_err(core, "Die2Die rx crc err overflow");
		}

		/* update crc cnt */
		crc_info[i].rx_crc_err += crc_cnt;

		/* policy warning */
		day_crc_cnt = crc_info[i].rx_crc_err - crc_info[i].prev_rx_crc_err;

		/* policy */
		if (MLU370_D2DC_RX_CRC_ERR_THRESHOLD < day_crc_cnt &&
			crc_info[i].prev_crc_err_inc < day_crc_cnt) {
			crc_info[i].rx_crc_err_duration++;
		} else {
			crc_info[i].rx_crc_err_duration = 0;
		}

		/* update previously crc cnt */
		crc_info[i].prev_rx_crc_err = crc_info[i].rx_crc_err;
		crc_info[i].prev_crc_err_inc = day_crc_cnt;

		/* warning print */
		if (crc_info[i].rx_crc_err_duration >= MLU370_D2DC_RX_CRC_ERR_DURATION) {
			crc_info[i].rx_crc_of++;
			cn_dev_core_err(core, "Die2Die rx crc err over %d lasted for %d days",
				MLU370_D2DC_RX_CRC_ERR_THRESHOLD, MLU370_D2DC_RX_CRC_ERR_DURATION);
		}

		crc_cnt = reg_read32(core->bus_set,
			reg_addr + MLU370_D2DC_RX_ARQ_CRC_ERR_OFFSET);
		crc_of = crc_cnt & MLU370_D2DC_CRC_OF_MASK;
		crc_cnt = crc_cnt & MLU370_D2DC_CRC_CNT_MASK;

		/* warning */
		/* print counter overflow err */
		if (crc_of) {
			cn_dev_core_err(core, "Die2Die rx arq crc err overflow");
		}

		/* update arq crc cnt */
		crc_info[i].rx_arq_crc_err += crc_cnt;

		/* policy warning */
		day_crc_cnt = crc_info[i].rx_arq_crc_err - crc_info[i].prev_rx_arq_crc_err;

		/* policy */
		if (MLU370_D2DC_RX_CRC_ERR_THRESHOLD < day_crc_cnt &&
			crc_info[i].prev_arq_crc_err_inc < day_crc_cnt) {
			crc_info[i].rx_arq_crc_err_duration++;
		} else {
			crc_info[i].rx_arq_crc_err_duration = 0;
		}
		/* update previously arq crc cnt */
		crc_info[i].prev_rx_arq_crc_err = crc_info[i].rx_arq_crc_err;
		crc_info[i].prev_arq_crc_err_inc = day_crc_cnt;

		/* warning print */
		if (crc_info[i].rx_arq_crc_err_duration >= MLU370_D2DC_RX_CRC_ERR_DURATION) {
			crc_info[i].arq_rx_crc_of++;
			cn_dev_core_err(core, "Die2Die rx arq crc err over %d lasted for %d days",
				MLU370_D2DC_RX_CRC_ERR_THRESHOLD, MLU370_D2DC_RX_CRC_ERR_DURATION);
		}
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void mcc_timer_callback(struct timer_list *timer)
{
	struct die2die_crc_info_t  *crc_info = NULL;
	struct cn_core_set *core = NULL;

	struct cn_mcc_set *mcc_set = container_of(timer, struct cn_mcc_set,
		mcc_timer);

	if (!mcc_set) {
		cn_dev_err("mcc_set is null");
		return;
	}
	crc_info = (struct die2die_crc_info_t  *)mcc_set->d2dc_status;

	core = (struct cn_core_set *)mcc_set->core;
	if (!core) {
		cn_dev_err("core is null");
		return;
	}

	d2dc_crc_callback(core, mcc_set, crc_info);

	mod_timer(&mcc_set->mcc_timer, MCC_TIMER_EXPIRES_MSEC(DAY_TO_MSEC(1)));

	return;
}
#else
static void mcc_timer_callback(unsigned long data)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)data;
	struct cn_core_set *core = NULL;
	struct die2die_crc_info_t *crc_info = NULL;

	if (!mcc_set) {
		cn_dev_err("mcc_set is null");
		return;
	}
	crc_info = (struct die2die_crc_info_t  *)mcc_set->d2dc_status;

	core = (struct cn_core_set *)mcc_set->core;
	if (!core) {
		cn_dev_err("core is null");
		return;
	}

	d2dc_crc_callback(core, mcc_set, crc_info);

	mod_timer(&mcc_set->mcc_timer, MCC_TIMER_EXPIRES_MSEC(DAY_TO_MSEC(1)));

	return;
}
#endif

static irqreturn_t die2die_mlu370_intr_handle(int irq, void *data);

static const struct die2die_irq {
	const char irq_name[MAX_STRING_LEN];
	const int irq;
	irqreturn_t (*isr_t)(int irq, void *data);
} mlu370_die2die_irq[MLU370_D2DC_CNT] = {
	{"D0_D2D_SYS0", MLU370_D2DC0_SYSTEM0_IRQ, die2die_mlu370_intr_handle},
	{"D0_D2D_SYS1", MLU370_D2DC0_SYSTEM1_IRQ, die2die_mlu370_intr_handle},
	{"D1_D2D_SYS0", MLU370_D2DC1_SYSTEM0_IRQ, die2die_mlu370_intr_handle},
	{"D1_D2D_SYS1", MLU370_D2DC1_SYSTEM1_IRQ, die2die_mlu370_intr_handle},
};

static void ddr_print_d2dc_crc_info_mlu370(struct cn_core_set *core,
	int d2dc_index, u32 reg32, struct die2die_crc_info_t *crc_info)
{
	u32 reg_addr = 0;
	u32 crc_cnt = 0;

	if (reg32 & (0x01 << RX_ARQ_ACK_TIMEOUT_OFFSET)) {
		cn_dev_core_err(core, "%s rx arq ack timeout",
			mlu370_die2die_reg[d2dc_index].d2dc_ctrl);
	}

	if (reg32 & (0x01 << RX_ARQ_CRC_ECO_OFFSET)) {
		/* d2dc ctrl base reg */
		reg_addr = mlu370_die2die_reg[d2dc_index].reg_base;
		/* read cnt */
		crc_cnt = reg_read32(core->bus_set,
			reg_addr + MLU370_D2DC_RX_ARQ_CRC_ERR_OFFSET);
		crc_info[d2dc_index].rx_arq_crc_err += crc_cnt & 0xFFFF;
		/* overflow update */
		crc_info[d2dc_index].rx_arq_crc_err_overflow += 1;
		cn_dev_core_err(core, "%s rx arq crc cnt overflow",
			mlu370_die2die_reg[d2dc_index].d2dc_ctrl);
	}

	if (reg32 & (0x01 << RX_CRC_ECO_OFFSET)) {
		/* d2dc ctrl base reg */
		reg_addr = mlu370_die2die_reg[d2dc_index].reg_base;
		/* read cnt */
		crc_cnt = reg_read32(core->bus_set,
			reg_addr + MLU370_D2DC_RX_CRC_ERR_OFFSET);
		crc_info[d2dc_index].rx_crc_err += crc_cnt & 0xFFFF;
		/* overflow update */
		crc_info[d2dc_index].rx_crc_err_overflow += 1;
		cn_dev_core_err(core, "%s rx crc cnt overflow",
			mlu370_die2die_reg[d2dc_index].d2dc_ctrl);
	}
}

int die2die_intr_read(struct cn_core_set *core, int d2d_system,
	struct die2die_crc_info_t *crc_info)
{
	u32 reg_addr = 0;
	u32 reg32 = 0;
	int i = 0;
	int ret = 0;
	int index = 0;

	for (i = 0; i < MLU370_D2DC_PER_SYSTEM_CNT; i++) {
		index = d2d_system * MLU370_D2DC_PER_SYSTEM_CNT + i;
		reg_addr = mlu370_die2die_reg[index].reg_base;
		reg32 = reg_read32(core->bus_set,
			reg_addr + MLU370_D2DC_INTR_STATE_OFFSET);
		if (reg32) {
			reg_write32(core->bus_set,
				reg_addr + MLU370_D2DC_INTR_STATE_OFFSET, reg32);
			ddr_print_d2dc_crc_info_mlu370(core, d2d_system + i, reg32, crc_info);
			ret = 1;
		}
	}

	return ret;
}

static irqreturn_t die2die_mlu370_intr_handle(int irq, void *data)
{
	int ret = 0;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)data;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct die2die_crc_info_t *crc_info = (struct die2die_crc_info_t  *)mcc_set->d2dc_status;

	switch (irq)
	{
	case MLU370_D2DC0_SYSTEM0_IRQ:
		ret = die2die_intr_read(core, 0, crc_info);
		break;
	case MLU370_D2DC0_SYSTEM1_IRQ:
		ret = die2die_intr_read(core, 1, crc_info);
		break;
	case MLU370_D2DC1_SYSTEM0_IRQ:
		ret = die2die_intr_read(core, 2, crc_info);
		break;
	case MLU370_D2DC1_SYSTEM1_IRQ:
		ret = die2die_intr_read(core, 3, crc_info);
		break;
	default:
		return IRQ_NONE;
	}

	if (ret) {
		cn_xid_err(core, XID_CRC_ERR, "D2D CRC Err");
		cndrv_set_d2d_crc_err(core, 1);
	}
	return ret ? IRQ_HANDLED : IRQ_NONE;
}

static irqreturn_t memsys_mlu370_intr_handle(int irq, void *data);

static const struct ddr_memsys_irq {
	const char irq_name[MAX_STRING_LEN];
	const int irq;
	irqreturn_t (*isr_t)(int irq, void *data);
} memsys_mlu370_irq[MLU370_MEMSYS_CNT] = {
	{"DIE0_MEMSYS0", MLU370_DIE0_MEMSYS0_IRQ, memsys_mlu370_intr_handle},
	{"DIE0_MEMSYS1", MLU370_DIE0_MEMSYS1_IRQ, memsys_mlu370_intr_handle},
	{"DIE0_MEMSYS2", MLU370_DIE0_MEMSYS2_IRQ, memsys_mlu370_intr_handle},
	{"DIE0_MEMSYS3", MLU370_DIE0_MEMSYS3_IRQ, memsys_mlu370_intr_handle},
	{"DIE0_MEMSYS4", MLU370_DIE0_MEMSYS4_IRQ, memsys_mlu370_intr_handle},
	{"DIE0_MEMSYS5", MLU370_DIE0_MEMSYS5_IRQ, memsys_mlu370_intr_handle},
	{"DIE1_MEMSYS0", MLU370_DIE1_MEMSYS0_IRQ, memsys_mlu370_intr_handle},
	{"DIE1_MEMSYS1", MLU370_DIE1_MEMSYS1_IRQ, memsys_mlu370_intr_handle},
	{"DIE1_MEMSYS2", MLU370_DIE1_MEMSYS2_IRQ, memsys_mlu370_intr_handle},
	{"DIE1_MEMSYS3", MLU370_DIE1_MEMSYS3_IRQ, memsys_mlu370_intr_handle},
	{"DIE1_MEMSYS4", MLU370_DIE1_MEMSYS4_IRQ, memsys_mlu370_intr_handle},
	{"DIE1_MEMSYS5", MLU370_DIE1_MEMSYS5_IRQ, memsys_mlu370_intr_handle},
};

static inline int __find_msys_index_with_irq(int irq, int msys_counts)
{
	int i = 0;

	for (i = 0; i < msys_counts; i++) {
		if (memsys_mlu370_irq[i].irq == irq)
			return i;
	}

	return -EINVAL;
}

static void ddr_retire_find_address_mlu370(struct cn_mcc_set *mcc_set,
				unsigned int msys_index, unsigned int chl_index);

static void
__clear_others_intr(struct cn_core_set *core, unsigned int reg_base,
		unsigned int irq_value)
{
	int i = 0;
	struct intr_info_t {
		int shift;
		int mask;
		int reg_ofs;
	} intrs[] = {
		[0] = { /* AIC */
			.shift = 3,
			.mask  = (1UL << 14) - (1UL << 3),
			.reg_ofs  = 0xA1C,
		},
		[1] = { /* EAC */
			.shift = 14,
			.mask  = (1UL << 23) - (1UL << 14),
			.reg_ofs = 0x22C,
		},
		[2] = { /* ROB */
			.shift = 23,
			.mask  = (1UL << 25) - (1UL << 23),
			.reg_ofs = 0x880,
		},

		[3] = { /* EMC */
			.shift = 25,
			.mask  = (1UL << 27) - (1UL << 25),
			.reg_ofs = 0x60C,
		},

		[4] = { /* DTI */
			.shift = 27,
			.mask  = (1UL << 29) - (1UL << 27),
			.reg_ofs = 0x1E8,
		},
	};

	for (i = 0; i < ARRAY_SIZE(intrs); i++) {
		unsigned int clear = (irq_value & intrs[i].mask) >> intrs[i].shift;
		if (clear) {
			reg_write32(core->bus_set, reg_base + intrs[i].reg_ofs, clear);
			cn_bus_mb(core->bus_set);
		}
	}
}

static irqreturn_t memsys_mlu370_intr_handle(int irq, void *data)
{
	struct ecc_info_t *ecc_info = NULL;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)data;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set =
		(struct ddr_retire_set *)mcc_set->repair_set;
	struct iecc_info_t *iecc_info = NULL;
	struct iecc_node_t *iecc_node = NULL;

	struct memsys_reg *msys_reg = NULL;
	unsigned long umc_base[MLU370_CHL_PER_MEMSYS_CNT] = {0x1c000, 0x20000};
	unsigned int addr_base = 0;
	unsigned int reg_value = 0;
	unsigned int reg_value_wb = 0;
	int msys_index = 0, i = 0;
	int chl_index = 0, find_2bit_error = 0;

	msys_index =
		__find_msys_index_with_irq(irq, MLU370_MSYS_CNT(core->die_cnt));
	if (msys_index < 0)
		return IRQ_NONE;

	msys_reg = &mlu370_memsys_reg[msys_index];

	if (retire_set) {
		iecc_info = retire_set->iecc_status;
		iecc_node = &iecc_info->nodes[iecc_info->total_counts % MAX_IECC_NODE_COUNTS];
	} else {
		return IRQ_NONE;
	}

	/* 1. disable clock gates */
	addr_base = msys_reg->reg_base + 0x10000;
	reg_write32(core->bus_set, addr_base + 0x900, 0x3f0000);
	cn_bus_mb(core->bus_set);

	ecc_info = ((struct ecc_info_t *)mcc_set->ecc_status) + msys_index;
	for (i = 0; i < MLU370_CHL_PER_MEMSYS_CNT; i++) {
		addr_base = msys_reg->reg_base + umc_base[i];

		reg_value = reg_read32(core->bus_set, addr_base + 0xC00);
		if (!reg_value)
			continue;

		if (reg_value & 0x01) {
			reg_value_wb |= 0x01;

			/* NOTE: Add the counts of SBE without DBE happened at the same time. */
			if (!(reg_value & 0x02)) {
				ecc_info->one_bit_ecc_error++;
				cn_xid_err(core, XID_ECC_ERR, "%s chl %d one bit ecc!", msys_reg->name, i);
			}

			iecc_info[msys_index].sbe++;
		}

		if (reg_value & 0x02) {
			reg_value_wb |= 0x02;

			/* NOTE: Add the counts of DBE while find error address in workqueue. */
			cn_dev_core_info(core, "%s chl %d status: two", msys_reg->name, i);

			/* NOTE: current only support handler first happened ecc error */
			if (!find_2bit_error) {
				find_2bit_error = 1;
				chl_index = i;
			}

			iecc_info[msys_index].dbe++;
		}

		if (reg_value & 0x04) {
			reg_value_wb |= 0x04;
			ecc_info->addr_forbidden_error++;

			cn_xid_err(core, XID_ILLEGAL_ACCESS_ERR, "%s chl %d addr overflow!", msys_reg->name, i);

			iecc_info[msys_index].over_flow++;
		}

		iecc_node->type[i] = reg_value_wb;

		reg_write32(core->bus_set, addr_base + 0xB04, reg_value_wb);
		cn_bus_mb(core->bus_set);

		if (reg_value != reg_value_wb) {
			cn_dev_core_err(core, "%s chl %d other err, status: %#x!",
							msys_reg->name, i, reg_value);
			__clear_others_intr(core, addr_base, reg_value);
			iecc_info[msys_index].others++;
			iecc_node->type[i] |= 1UL << 3;
		}
	}

	/* re-enable clock gates again */
	addr_base = msys_reg->reg_base + 0x10000;
	reg_write32(core->bus_set, addr_base + 0x900, 0x3f003f);
	cn_bus_mb(core->bus_set);

	/* each memory system irq_handler access different list, not race condition happened */
	iecc_node->secs = __mlu370_get_real_time();
	iecc_info->total_counts++;

	if (find_2bit_error) {
		ddr_retire_find_address_mlu370(mcc_set, msys_index, chl_index);
	}

	return IRQ_HANDLED;
}

static int
__ile_flush_ddr_zero(struct cn_mcc_set *mcc_set, unsigned long reg_base,
					 unsigned int rank_nums)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned long flush_size = 0;
	unsigned int reg_addr = 0;
	unsigned int old_ile_status = 0, reg_value = 0;
	unsigned long dte_base[MLU370_CHL_PER_MEMSYS_CNT] = {0x14000, 0x18000};
	int i = 0, j = 0, counts = 0;

	/* read ile status from umc0 register. */
	reg_addr = reg_base + 0x1C000;
	old_ile_status = reg_read32(core->bus_set, reg_addr + 0xA0C);
	if (old_ile_status == 0x3) {
		flush_size = reg_read32(core->bus_set, reg_addr + 0xB18);
		flush_size <<= 20;
	} else {
		/* input rank_nums's unit is GB */
		flush_size = (1UL << 30) * rank_nums;
	}

	/* NOTE: dte flush size minium unit is 64Byte */
	flush_size >>= 6;

	for (i = 0; i < MLU370_CHL_PER_MEMSYS_CNT; i++) {
		reg_addr = reg_base + dte_base[i];

		/* set default data into DTE SRAM (512 * 32bits registers) */
		for (j = 0; j < 512; j++) {
			reg_write32(core->bus_set, reg_addr + 0x200 + j * 0x4, 0);
		}

		reg_write32(core->bus_set, reg_addr + 0x08, 0x0);
		reg_write32(core->bus_set, reg_addr + 0x0C, flush_size);
		reg_write32(core->bus_set, reg_addr + 0x10, 0x0);
		reg_write32(core->bus_set, reg_addr + 0x14, flush_size);
		reg_write32(core->bus_set, reg_addr + 0x1C, 0x1f);
		reg_write32(core->bus_set, reg_addr + 0x04, 0x9);

		reg_write32(core->bus_set, reg_addr + 0x00, 0x1);
		do {
			reg_value = reg_read32(core->bus_set, reg_addr + 0x00);
			/* NOTE: dte flush may cost so many times, timeout set 1000000 is correct */
			if (counts++ == 1000000) {
				cn_dev_core_err(core, "dte flush for %#x failed!", reg_addr);
				return -1;
			}

			usleep_range(10, 15);
		} while (reg_value);
	}

	return 0;
}

static int
__ile_sr_ctrl(struct cn_mcc_set *mcc_set, unsigned long reg_base, bool status)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int reg_value = 0;
	int i = 0;

	/* set bit[0] as zero will both trigger rank0 and rank1 on dual ranks card */
	if (status) {
		reg_write32(core->bus_set, reg_base + 0x208, 0xB00);
	} else {
		reg_write32(core->bus_set, reg_base + 0x208, 0xD00);
	}

	reg_write32(core->bus_set, reg_base + 0x204, 0x1);
	do {
		reg_value = reg_read32(core->bus_set, reg_base + 0x204);
		if (i++ == 1000000) {
			cn_dev_core_err(core, "self refresh for %#lx failed!", reg_base);
			return -1;
		}
	} while (reg_value);

	return 0;
}

static int
__ile_enable_setting(struct cn_mcc_set *mcc_set, unsigned long reg_base,
					 unsigned int rank_nums, bool status)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int reg_addr = 0;
	int i = 0;
	unsigned long umc_base[MLU370_CHL_PER_MEMSYS_CNT] = {0x1c000, 0x20000};
	unsigned long div_start = (ile_unprotect_base + ile_unprotect_size) >> 20;
	unsigned long div_end = __per_chl_size(core, status) >> 20;

	for (i = 0; i < MLU370_CHL_PER_MEMSYS_CNT; i++) {
		reg_addr = reg_base + umc_base[i];

		/* self-refresh  enter */
		__ile_sr_ctrl(mcc_set, reg_addr, true);

		if (status) { /* enable mlu370 inlineECC */
			reg_write32(core->bus_set, reg_addr + 0xB00, 0x0);
			reg_write32(core->bus_set, reg_addr + 0x828, 0xa7F);
			reg_write32(core->bus_set, reg_addr + 0xA0C, 0x3);

			reg_write32(core->bus_set, reg_addr + 0xB10, 0x1);
			reg_write32(core->bus_set, reg_addr + 0xB14, div_start);
			reg_write32(core->bus_set, reg_addr + 0xB18, div_end);
			reg_write32(core->bus_set, reg_addr + 0xB24, rank_nums << 10);
		} else { /* disable mlu370 inlineECC */
			reg_write32(core->bus_set, reg_addr + 0xB00, 0x1);
			reg_write32(core->bus_set, reg_addr + 0x828, 0xa7B);
			reg_write32(core->bus_set, reg_addr + 0xA0C, 0x6);

			/* HW BugFix: set ile_addr_xxx registers as default value during disable inlineECC */
			reg_write32(core->bus_set, reg_addr + 0xB10, 0xffff);
			reg_write32(core->bus_set, reg_addr + 0xB14, 0x1fff);
			reg_write32(core->bus_set, reg_addr + 0xB18, 0x1fff);
			reg_write32(core->bus_set, reg_addr + 0xB24, 0x1fff);
		}

		/*clear ddr ile irq */
		reg_write32(core->bus_set, reg_addr + 0xB04, 0x07);

		/* self-refresh  exit */
		__ile_sr_ctrl(mcc_set, reg_addr, false);
	}

	return 0;
}

static int
__single_memsys_ile_ctrl(struct cn_mcc_set *mcc_set, int msys_idx, bool status)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct cn_board_info *pboardi = &core->board_info;
	unsigned int reg_base = mlu370_memsys_reg[msys_idx].reg_base;
	unsigned int clkgate_addr = 0, rank_nums = 0;
	int ret = 0;

	/* rank_nums = ddr_cap / 8, unit: GB */
	rank_nums = pboardi->ddr_cap >> 3;

	/* NOTE: need close clock gate before set memory system registers  */
	/* 1. disable clock gates */
	clkgate_addr = reg_base + 0x10000 + 0x900;
	reg_write32(core->bus_set, clkgate_addr, 0x3f0000);
	cn_bus_mb(core->bus_set);

	if (status) {
		/* flush all ddr channel data as zero */
		ret = __ile_flush_ddr_zero(mcc_set, reg_base, rank_nums);
		if (ret) {
			cn_dev_core_err(core, "flush ddr as zero failed, forced disable inlineECC!");
			status = false;
		}
	}

	/* each memory system have 2 channel need set */
	__ile_enable_setting(mcc_set, reg_base, rank_nums, status);

	if (status) {
		/**
		 * NOTE: some hardware module may access device memory after inlineECC
		 * enabled, which will trigger incorrect inlineECC irq. so we'd better
		 * flush ddr and clear irq again after inlineECC is enabled.
		 **/
		__ile_flush_ddr_zero(mcc_set, reg_base, rank_nums);

		reg_write32(core->bus_set, reg_base + 0x1c000 + 0xB04, 0x07);
		reg_write32(core->bus_set, reg_base + 0x20000 + 0xB04, 0x07);
	}

	/* re-enable clock gates again */
	reg_write32(core->bus_set, clkgate_addr, 0x3f003f);
	cn_bus_mb(core->bus_set);

	return ret;
}

static int
__single_memsys_timing_reset(struct cn_mcc_set *mcc_set, int msys_idx)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned int reg_base = mlu370_memsys_reg[msys_idx].reg_base;
	unsigned int reg_addr = 0, val = 0;
	unsigned long umc_base[MLU370_CHL_PER_MEMSYS_CNT] = {0x1c000, 0x20000};
	unsigned int clkgate_addr = 0;
	int i = 0;

	/* NOTE: need close clock gate before set memory system registers  */
	/* 1. disable clock gates */
	clkgate_addr = reg_base + 0x10000 + 0x900;
	reg_write32(core->bus_set, clkgate_addr, 0x3f0000);
	cn_bus_mb(core->bus_set);

	for (i = 0; i < MLU370_CHL_PER_MEMSYS_CNT; i++) {
		reg_addr = reg_base + umc_base[i];

		/* self-refresh  enter */
		__ile_sr_ctrl(mcc_set, reg_addr, true);

		val = reg_read32(core->bus_set, reg_addr + 0x84);
		val &= ~(0x1FUL << 24);
		val |= (0x11 << 24);

		reg_write32(core->bus_set, reg_addr + 0x84, val);
		cn_bus_mb(core->bus_set);

		/* self-refresh  exit */
		__ile_sr_ctrl(mcc_set, reg_addr, false);
	}

	/* re-enable clock gates again */
	reg_write32(core->bus_set, clkgate_addr, 0x3f003f);
	cn_bus_mb(core->bus_set);

	return 0;
}

struct ile_ctrl_params {
	struct cn_mcc_set *mcc_set;
	struct completion entered;
	int msys_index;
	int status;
};

/* return 0 for setting succeed, other value is failed and need disable inlinECC forced*/
static int __kthread_ile_ctrl(void *args)
{
	struct ile_ctrl_params *params = (struct ile_ctrl_params *)args;
	int ret = 0;

	complete(&params->entered);

	ret = __single_memsys_ile_ctrl(params->mcc_set, params->msys_index,
								   params->status);

	/* DRIVER-8643 Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	set_current_state(TASK_RUNNING);

	return ret;
}

static int
__memsys_ile_ctrl(struct cn_mcc_set *mcc_set, int memsys_cnt,
				  bool status, int mode)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	int i = 0, retry_flag = 0;

retry:
	if (status && mode) {
		struct ile_ctrl_params *params_arr;
		struct task_struct **ile_task;

		params_arr = (struct ile_ctrl_params *)cn_kzalloc(sizeof(struct ile_ctrl_params) * memsys_cnt, GFP_KERNEL);
		if (!params_arr) {
			cn_dev_core_err(core, "malloc ile_ctrl_params fail");
			return -ENOMEM;
		}

		ile_task = (struct task_struct **)cn_kzalloc(sizeof(struct task_struct *) * memsys_cnt, GFP_KERNEL);
		if (!ile_task) {
			cn_dev_core_err(core, "malloc task_struct fail");
			cn_kfree(params_arr);
			return -ENOMEM;
		}

		for (i = 0; i < memsys_cnt; i++) {
			params_arr[i].mcc_set = mcc_set;
			params_arr[i].msys_index = i;
			params_arr[i].status = status;
			/**
			 * use complete to make sure kthread has been start running before
			 * kthread_stop called.
			 **/
			init_completion(&params_arr[i].entered);

			ile_task[i] = kthread_run(__kthread_ile_ctrl, &params_arr[i],
							"ile_ctrl_thread/%d:%d", core->idx, i);
			if (IS_ERR(ile_task[i])) {
				ile_task[i] = NULL;
				cn_dev_core_err(core, "try to enable inlineECC failed, force disable!");
				retry_flag = 1;
			}
		}

		for (i = 0; i < memsys_cnt && ile_task[i]; i++) {
			wait_for_completion(&params_arr[i].entered);
			retry_flag = kthread_stop(ile_task[i]) ? 1 : 0;
		}

		cn_kfree(params_arr);
		cn_kfree(ile_task);

		if (retry_flag) {
			status = false;
			goto retry;
		}

	} else {
		/**
		 * disable inlineECC not need flush ddr, just do each memory system
		 * setting serially
		 **/
		for (i = 0; i < memsys_cnt; i++)
			__single_memsys_ile_ctrl(mcc_set, i, status);
	}

	return status;
}

void mlu370_ddr_ecc_info_init(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	int ret = 0, i = 0, cnt = 0, mode = 1, k = 0;

	cnt = MLU370_MSYS_CNT(core->die_cnt);

	cn_dev_core_debug(core, "%s %s inlineECC mode!", mode ? "Quick" : "Normal",
					 core->ile_en ? "ENABLE" : "DISABLE");

	core->ile_en = __memsys_ile_ctrl(mcc_set, cnt, core->ile_en, mode);

	if (!core->ile_en)
		return ;

	/* register irq */
	for (i = 0; i < cnt; i++) {
		ret = cn_bus_register_interrupt(core->bus_set,
			memsys_mlu370_irq[i].irq,
			memsys_mlu370_irq[i].isr_t,
			(void *)mcc_set);
		if (ret) {
			cn_dev_core_err(core, "register ddr inline-ecc %d irq isr error", i);
			k = i;
			goto register_failed;
		}
	}

	for (i = 0; i < cnt; i++) {
		ret = cn_bus_enable_irq(core->bus_set, memsys_mlu370_irq[i].irq);
		if (ret) {
			cn_dev_core_err(core, "enable ddr inline-ecc %d irq isr error", i);
			k = cnt;
			goto register_failed;
		}
	}

	return;

register_failed:
	for (i = 0; i < k; i++)
		cn_bus_unregister_interrupt(core->bus_set, memsys_mlu370_irq[i].irq);

	core->ile_en = __memsys_ile_ctrl(mcc_set, cnt, 0, mode);
	return;
}

void d2dsys_crc_info_init(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	int i = 0;
	int ret = 0;
	u32 reg_addr = 0;

	/* Die2Die support only */
	if (core->die_cnt < 2)
		return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	timer_setup(&mcc_set->mcc_timer, mcc_timer_callback, 0);
#else
	setup_timer(&mcc_set->mcc_timer, mcc_timer_callback, (unsigned long)mcc_set);
#endif
	mod_timer(&mcc_set->mcc_timer, MCC_TIMER_EXPIRES_MSEC(1));

	/* mask intr */
	for (i = 0; i < MLU370_D2DC_CTRL_CNT; i++) {
		reg_addr = mlu370_die2die_reg[i].reg_base;
		reg_write32(core->bus_set, reg_addr + 0x14, D2DC_CRC_MASK);

		/*clear Die2Die irq */
		reg_write32(core->bus_set,
			reg_addr + MLU370_D2DC_INTR_STATE_OFFSET, 0xffffffff);
	}

	/* register irq */
	for (i = 0; i < MLU370_D2DC_CNT; i++) {
		ret = cn_bus_register_interrupt(core->bus_set,
			mlu370_die2die_irq[i].irq,
			mlu370_die2die_irq[i].isr_t,
			(void *)mcc_set);
		ret |= cn_bus_enable_irq(core->bus_set, mlu370_die2die_irq[i].irq);
		if (ret) {
			cn_dev_core_err(core, "register die2die %d irq isr error", i);
			cn_bus_unregister_interrupt(core->bus_set, mlu370_die2die_irq[i].irq);
		}
	}

	return;
}

void ddr_retire_exit_mlu370(struct cn_mcc_set *mcc_set);
void ile_release_mlu370(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	int i = 0;
	int cnt = 0;

	if (core->ile_en) {
		cnt = MLU370_MSYS_CNT(core->die_cnt);

		for (i = 0; i < cnt; i++) {
			cn_bus_disable_irq(core->bus_set, memsys_mlu370_irq[i].irq);
			cn_bus_unregister_interrupt(core->bus_set, memsys_mlu370_irq[i].irq);
		}

		/* disable inlinECC while remove driver */
		__memsys_ile_ctrl(mcc_set, cnt, false, 0);
	}

	ddr_retire_exit_mlu370(mcc_set);

	if (mcc_set->ecc_status) {
		cn_kfree(mcc_set->ecc_status);
	}

	return;
}

void d2dsys_crc_info_release(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	int i = 0;

	if (core->die_cnt < 2)
		return;

	del_timer_sync(&mcc_set->mcc_timer);

	for (i = 0; i < MLU370_D2DC_CNT; i++) {
		cn_bus_disable_irq(core->bus_set, mlu370_die2die_irq[i].irq);
		cn_bus_unregister_interrupt(core->bus_set, mlu370_die2die_irq[i].irq);
	}

	return;
}

void ddr_exit_mlu370(void *mset)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;

	d2dsys_crc_info_release(mcc_set);

	if (mcc_set->d2dc_status) {
		cn_kfree(mcc_set->d2dc_status);
	}
}


static const struct cn_mcc_ops ddr_ops_mlu370 = {
	.get_channel_num = ddr_get_channel_num_mlu370,
	.get_ecc_status = ddr_get_ecc_status_mlu370,
	.mcc_exit = ddr_exit_mlu370,
	.ile_exit = ile_release_mlu370, /* ile enabled in ddr_init_mlu370 */
	.get_d2dc_num = ddr_get_d2dc_num_mlu370,
	.get_d2dc_status = ddr_get_d2dc_status_mlu370,
};

static void mlu370_memsys_config_init(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	mcc_set->msys_config.mlu370.shuffle_en = 1; /* 1: shuffle enable, 0: shuffle disable */
	mcc_set->msys_config.mlu370.interleave_size = 0; /* 0: 512B, 1: 1024B, 2: 2048B */
	mcc_set->msys_config.mlu370.llc_interleave_mode = 2; /* 0: no interleave, 1: 2chl interleave, 3: 3chl interleave */
	mcc_set->msys_config.mlu370.llc_3chl_mode = 1; /* 0: waste 3chl interleave, 1: no waste 3chl interleave */
	mcc_set->msys_config.mlu370.chl_remap_mode = 0; /* 0: default remap mode */
	mcc_set->msys_config.mlu370.ch_cap_x512 = __per_chl_size(core, core->ile_en) >> 9;
}

static void __set_ile_status(struct cn_core_set *core)
{
	if (core->ile_en != -1)
		return ;

	switch (core->board_info.board_idx) {
		case CN_MLU370_M8:
		case CN_MLU370_M83U:
			core->ile_en = 1;
			break;
		default:
			core->ile_en = 0;
	}
}

int ddr_init_mlu370(struct cn_mcc_set *mcc_set)
{
	int ret = 0, i = 0;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	if (IS_ERR_OR_NULL(mcc_set)) {
		cn_dev_core_err(core, "memory ctrl set is null");
		return -EINVAL;
	}

	mcc_set->ecc_status =
		cn_kzalloc(MLU370_MEMSYS_CNT * sizeof(struct ecc_info_t), GFP_KERNEL);
	if (!mcc_set->ecc_status) {
		cn_dev_core_err(core, "malloc for ecc struct fail");
		return -ENOMEM;
	}

	/* DRIVER-12773, lpddr5 default parameters is incorrect need reset. */
	if (core->board_info.board_idx == CN_MLU370_M8) {
		/* NOTE: loop reset config cost ~310us, not need reset in parallel */
		for (i = 0; i < MLU370_MSYS_CNT(core->die_cnt); i++)
			__single_memsys_timing_reset(mcc_set, i);
	}

	__set_ile_status(core);

	mlu370_ddr_ecc_info_init(mcc_set);

	mlu370_memsys_config_init(mcc_set);

	/* memsys & llc init */
	memsys_llc_init(core->bus_set, core->die_cnt);

	mcc_set->mcc_ops = &ddr_ops_mlu370;

	mcc_set->d2dc_status = cn_kzalloc(MLU370_D2DC_CTRL_CNT *
		sizeof(struct die2die_crc_info_t), GFP_KERNEL);
	if (!mcc_set->d2dc_status) {
		cn_dev_core_err(core, "malloc for d2dc struct fail");
		cn_kfree(mcc_set->ecc_status);
		mcc_set->ecc_status = NULL;
		return -ENOMEM;
	}

	/* d2dsys crc info init */
	d2dsys_crc_info_init(mcc_set);

	return ret;
}

/*** Start mlu370 inlineECC PageRetirement ***/

/**
 * __single_memsys_check_unprotect_area - check single memory system's unprotect
 *                                        area is validate.
 *
 * Returns -ETIMEDOUT means dte operation timeout, postive value means unprotect area
 * have uncorrectable error, 0 for success
 */
static int
__single_memsys_check_unprotect_area(struct cn_mcc_set *mcc_set,
					unsigned int msys_idx)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned long flush_start = ile_unprotect_base;
	unsigned long flush_size = ile_unprotect_size;
	unsigned int reg_base = 0, clkgate_addr = 0;
	unsigned int reg_addr = 0, reg_value = 0;
	unsigned long dte_base[MLU370_CHL_PER_MEMSYS_CNT] = {0x14000, 0x18000};
	int i = 0, counts = 0, ret = 0;

	reg_base = mlu370_memsys_reg[msys_idx].reg_base;

	/* NOTE: need close clock gate before set memory system registers  */
	/* 1. disable clock gates */
	clkgate_addr = reg_base + 0x10000 + 0x900;
	reg_write32(core->bus_set, clkgate_addr, 0x3f0000);
	cn_bus_mb(core->bus_set);

	/* NOTE: dte flush size minium unit is 64Byte */
	flush_size >>= 6;

	for (i = 0; i < MLU370_CHL_PER_MEMSYS_CNT; i++) {
		reg_addr = reg_base + dte_base[i];

		reg_write32(core->bus_set, reg_addr + 0x08, flush_start);
		reg_write32(core->bus_set, reg_addr + 0x0C, flush_size);
		reg_write32(core->bus_set, reg_addr + 0x10, flush_start);
		reg_write32(core->bus_set, reg_addr + 0x14, flush_size);
		reg_write32(core->bus_set, reg_addr + 0x04, 0x6);

		reg_write32(core->bus_set, reg_addr + 0x00, 0x1);
		do {
			reg_value = reg_read32(core->bus_set, reg_addr + 0x00);
			if (counts++ == 10000) {
				cn_dev_core_err(core, "dte check write dir timeout!");
				return -ETIMEDOUT;
			}

			usleep_range(10, 15);
		} while (reg_value);

		reg_write32(core->bus_set, reg_addr + 0x00, 0x2);
		do {
			reg_value = reg_read32(core->bus_set, reg_addr + 0x00);
			if (counts++ == 10000) {
				cn_dev_core_err(core, "dte check read dir timeout!");
				return -ETIMEDOUT;
			}

			usleep_range(10, 15);
		} while (reg_value);

		ret += reg_read32(core->bus_set, reg_addr + 0x20);
		ret += reg_read32(core->bus_set, reg_addr + 0x24);
	}

	/* re-enable clock gates again */
	reg_write32(core->bus_set, clkgate_addr, 0x3f003f);
	cn_bus_mb(core->bus_set);

	return ret;
}

static int
__memsys_unprotect_area_check(struct cn_mcc_set *mcc_set, unsigned int msys_cnt)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	unsigned long msys_bitmap = 0x0;
	unsigned int reg_addr = 0, value = 0;
	int ret = 0, i = 0;

	/* 1. find run dte failed memory system */
	for (i = 0; i < msys_cnt; i++) {
		reg_addr = mlu370_memsys_reg[i].reg_base + 0xbc14;
		value = reg_read32(core->bus_set, reg_addr);

		/* NOTE:
		 * return value: 0x55aa0000 means that current memory system dte
		 *      check error, need check its unprotect area's validate.
		 * return value: 0x55aa1234 means that current memory system dte check
		 *      no error happened, not need check unprotect area.
		 * return value: other means that register read is invalid. hardware's
		 *      status may be dangerous.
		 **/
		if (value == 0x55aa0000) {
			set_bit(i, &msys_bitmap);
		} else if (value == 0x55aa1234) {
			continue;
		} else {
			cn_dev_core_err(core, "unknown value(%#x) of %d memsys %#x", value,
					i, reg_addr);
			return -EINVAL;
		}
	}

	/* only check bit 0 ~ 11 is enough */
	for_each_set_bit(i, &msys_bitmap, msys_cnt) {
		ret = __single_memsys_check_unprotect_area(mcc_set, i);
		if (ret) {
			ret = -EPERM;
			break;
		}
	}

	return ret;
}

static void
ddr_get_retire_info(void *mset, struct hbm_retire_info_t **retire_info,
		unsigned int *retire_num, int irq_flag)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set;

	if (!retire_info || !retire_num)
		return;

	if (retire_num)
		*retire_num = 0;

	retire_set = (struct ddr_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "retire_set is NULL");
		return;
	}

	if (irq_flag) {
		*retire_info = &retire_set->retire_info[retire_set->retire_index];
		*retire_num = retire_set->retire_num - retire_set->retire_index;
	} else {
		*retire_info = retire_set->retire_info;
		*retire_num = retire_set->retire_index;
	}
}

static int ddr_get_retire_pages(void *mset, int cause, unsigned int *pagecount,
				u64 **page_addr)
{
	int ret = -EINVAL;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set;

	if (!pagecount || !page_addr)
		return ret;

	if (pagecount)
		*pagecount = 0;

	if (cause != ECC_BIT_1 && cause != ECC_BIT_2) {
		cn_dev_err("cause%d is error", cause);
		return ret;
	}

	if (cause == ECC_BIT_1) {
		cn_dev_core_debug(core, "mlu370 not support page retire for SBE");

		*pagecount = 0;
		*page_addr = NULL;
		return 0;
	}

	retire_set = (struct ddr_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "retire_set is NULL");
		return ret;
	}

	memset(retire_set->retire_page, 0, sizeof(retire_set->retire_page));
	ret = cn_mem_pgr_get_pages(core, cause, &retire_set->retire_page_num,
						retire_set->retire_page);
	if (ret)
		return ret;

	*pagecount = retire_set->retire_page_num;
	*page_addr = retire_set->retire_page;

	return ret;
}

static int ddr_get_retire_pages_pending_status(void *mset, int *ispending,
				int *isfailure)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	return cn_mem_pgr_get_status(core, ispending, isfailure);
}

static int ddr_retire_switch(void *mset, int status)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set;

	retire_set = (struct ddr_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "retire_set is NULL");
		return -EINVAL;
	}

	if ((status != 0 && status != 1) || !core->ile_en)
		return atomic_read(&retire_set->retire_enable);

	/* NOTE: current only support pf only enable page retire */
	if (!cn_core_is_vf(core) && !cn_is_mim_en(core))
		atomic_set(&retire_set->retire_enable, status);

	return atomic_read(&retire_set->retire_enable);
}

static int ddr_get_norflash_switch(void *mset, int status)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set;

	retire_set = (struct ddr_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "retire_set is NULL");
		return -EINVAL;
	}

	if ((status != 0 && status != 1) || !core->ile_en)
		return atomic_read(&retire_set->norflash_enable);

	atomic_set(&retire_set->norflash_enable, status);

	return atomic_read(&retire_set->norflash_enable);
}

static int ddr_get_norflash_info(void *mset, unsigned int **rom_info,
				unsigned int *norflash_num)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct memsys_config_st *msys_config = &mcc_set->msys_config;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set;
	struct norflash_info_t *norflash;
	unsigned long div_base = ile_unprotect_base + ile_unprotect_size;
	unsigned long eaddr = 0;
	int i = 0;

	retire_set = (struct ddr_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "retire_set is NULL");
		return -EINVAL;
	}

	/* NOTE: Current ops only used by proc debug, mlu370 norflash saved address
	 * is 64Bits, not support output as 32bits. just dump norflash address
	 * with pr_info. */
	if (!atomic_read(&retire_set->norflash_enable)) {
		cn_dev_core_err(core, "driver debug ecc mode!!!");
		cn_dev_core_err(core, "ile error address total number: %#x",
				retire_set->retire_num);

		cn_dev_core_err(core, "ile error address retire_info list:");
		cn_dev_core_err(core, "id:\tmodule index\tllc index\tconfig\terror type\tllc address\t");
		for (i = 0; i < retire_set->retire_num; i++) {
			cn_dev_core_err(core, "[%d]:[%d]\t[%d]\t[%#x]\t[%d]\t[%#x]", i,
							 retire_set->retire_info[i].hbm_num,
							 retire_set->retire_info[i].sys_num,
							 retire_set->retire_info[i].pmc_num,
							 retire_set->retire_info[i].ecc_type,
							 retire_set->retire_info[i].ecc_addr);
		}

		cn_dev_core_err(core, "ile error address encode saved in norflash:");
		for (i = 0; i < retire_set->retire_num; i++) {
			eaddr = mlu370_info2addr(retire_set->retire_info[i]);
			eaddr = mlu370_address_encode(eaddr, msys_config->mlu370.ch_cap_x512,
						div_base, msys_config->mlu370.chl_remap_mode);

			cn_dev_core_err(core, "[%d]: %#lx", i, eaddr);
		}
	} else {
		cn_dev_core_err(core, "ile error address encode saved in norflash:");
		norflash = retire_set->norflash_info;
		for (i = 0; i < norflash->counts; i++) {
			cn_dev_core_err(core, "[%d]: %#llx", i, norflash->addrs[i]);
		}
	}

	*rom_info = NULL;
	*norflash_num = 0;
	return 0;
}

static int __clear_norflash_data(struct cn_core_set *core,
			struct ddr_retire_set *retire_set);
static int __recheck_norflash_data(struct cn_core_set *core,
			struct ddr_retire_set *retire_set);
static int __dump_iecc_info_data(struct cn_core_set *core);

static int ddr_ecc_irq_inject(void *mset, u32 sys_mc_num,
				u32 mc_state, u32 ecc_addr)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set;
	unsigned int msys_counts = MLU370_MSYS_CNT(core->die_cnt);
	unsigned int l1_index = 0, l2_index = 0;

	if (!core->ile_en)
		return 0;

	retire_set = (struct ddr_retire_set *)mcc_set->repair_set;
	if (!retire_set) {
		cn_dev_core_err(core, "retire_set is NULL");
		return -EINVAL;
	}

	if ((sys_mc_num >= msys_counts) || mc_state > 2 ||
		(ecc_addr >= __per_chl_size(core, core->ile_en))) {

		cn_dev_core_info(core, "Invalid parameters input! Each paramter valid ranges:");
		cn_dev_core_info(core, "sys_mc_num: 0 ~ %d, mc_state: 0 or 1, ecc_addr: 0 ~ %#lx",
						 msys_counts, __per_chl_size(core, core->ile_en));
		return 0;
	}

	if (mc_state == 2 && ecc_addr == 0 && sys_mc_num == 0) {
		cn_dev_core_warn(core, "ATTENTION: try to flush norflash as zero!!!!");
		__clear_norflash_data(core, retire_set);
		return 0;
	}

	if (mc_state == 2 && ecc_addr == 1 && sys_mc_num == 1) {
		cn_dev_core_warn(core, "ATTENTION: try to recheck norflash saved address!!!!");
		__recheck_norflash_data(core, retire_set);
		return 0;
	}

	if (mc_state == 2 && ecc_addr == 2 && sys_mc_num == 2) {
		cn_dev_core_warn(core, "ATTENTION: try to dump internal ecc info!!!!");
		__dump_iecc_info_data(core);
		return 0;
	}

	l1_index = ecc_addr >> level_bit_shift[L1_BITS];
	l2_index = BITS(ecc_addr, 14, 0) >> level_bit_shift[L2_BITS];

	retire_set->dbg_level_idx[L1_BITS] = l1_index;
	retire_set->dbg_level_idx[L2_BITS] = l2_index;
	retire_set->dbg_level_times[L1_BITS] = 0;
	retire_set->dbg_level_times[L2_BITS] = 0;
	retire_set->debug_mode = true;

	cn_dev_core_info(core, "inject parameter: msys:%d, chl:%d, ofs:%#x, l1_index:%d, l2_index:%d",
					 sys_mc_num, mc_state, ecc_addr, l1_index, l2_index);

	ddr_retire_find_address_mlu370(mcc_set, sys_mc_num, mc_state);

	return 0;
}

static int ddr_get_sys_mc_nums(void *mset, unsigned int *sys_mc_num)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)mset;
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;

	if (!sys_mc_num) {
		cn_dev_core_err(core, "input sys_mc_num buffer is null");
		return -EINVAL;
	}

	*sys_mc_num =
		core->die_cnt >= 2 ? MLU370_MEMSYS_CNT : MLU370_MEMSYS_CNT >> 1;

	return 0;
}

static const struct cn_repair_ops ddr_retire_ops_mlu370 = {
	.get_retire_info = ddr_get_retire_info,
	.get_retire_pages = ddr_get_retire_pages,
	.get_retire_pages_pending_status = ddr_get_retire_pages_pending_status,
	.get_remapped_rows = NULL,
	.retire_switch = ddr_retire_switch,
	.ecc_irq_inject = ddr_ecc_irq_inject,
	.get_eeprom_switch = ddr_get_norflash_switch,
	.get_eeprom_info = ddr_get_norflash_info,
	.get_sys_mc_nums = ddr_get_sys_mc_nums,
};

/* NOTE: during cn_bus_disable_irq and cn_bus_enable_irq running, we need make
 * sure that no irq happened. */
static int __single_memsys_enable_irq(struct cn_core_set *core, int index)
{
	int ret = 0;

	reg_write32(core->bus_set, mlu370_memsys_reg[index].reg_base + 0x10900, 0x3f0000);
	cn_bus_mb(core->bus_set);

	ret = cn_bus_enable_irq(core->bus_set, memsys_mlu370_irq[index].irq);

	/* clear irq status */
	reg_write32(core->bus_set, mlu370_memsys_reg[index].reg_base + 0x1CB04, 0x7);
	reg_write32(core->bus_set, mlu370_memsys_reg[index].reg_base + 0x20B04, 0x7);
	/* reenable irq mask */
	reg_write32(core->bus_set, mlu370_memsys_reg[index].reg_base + 0x1CB08, 0x0);
	reg_write32(core->bus_set, mlu370_memsys_reg[index].reg_base + 0x20B08, 0x0);
	cn_bus_mb(core->bus_set);

	reg_write32(core->bus_set, mlu370_memsys_reg[index].reg_base + 0x10900, 0x3f003f);
	cn_bus_mb(core->bus_set);

	return ret;
}

static void __single_memsys_disable_irq(struct cn_core_set *core, int index)
{
	reg_write32(core->bus_set, mlu370_memsys_reg[index].reg_base + 0x10900, 0x3f0000);
	cn_bus_mb(core->bus_set);

	reg_write32(core->bus_set, mlu370_memsys_reg[index].reg_base + 0x1CB08, 0x7);
	reg_write32(core->bus_set, mlu370_memsys_reg[index].reg_base + 0x20B08, 0x7);
	cn_bus_mb(core->bus_set);

	cn_bus_disable_irq(core->bus_set, memsys_mlu370_irq[index].irq);

	reg_write32(core->bus_set, mlu370_memsys_reg[index].reg_base + 0x10900, 0x3f003f);
	cn_bus_mb(core->bus_set);
}

static void
ddr_retire_find_address_mlu370(struct cn_mcc_set *mcc_set,
				unsigned int msys_index, unsigned int chl_index)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set =
		(struct ddr_retire_set *)mcc_set->repair_set;
	unsigned int work_params = 0;
	int i = 0;

	if (!retire_set || !core)
		return ;

	/* 1. check is half bottom work is working */
	if (atomic_cmpxchg(&retire_set->work_status, RETIRE_WORK_IDLE,
		RETIRE_WORK_READY) != RETIRE_WORK_IDLE) {
		cn_dev_core_warn(core, "retire work is running, abandon current irq work");
		return ;
	}

	for (i = 0; i < MLU370_MSYS_CNT(core->die_cnt); i++)
		__single_memsys_disable_irq(core, i);

	SET_BITS(work_params, 0, 0, chl_index);
	SET_BITS(work_params, 4, 1, msys_index);

	__sync_lock_test_and_set(&retire_set->work_params, work_params);
	cn_schedule_work(core, &retire_set->retire_work);
}

static int
__read_2bit_status(struct cn_core_set *core, unsigned int emsys,
				unsigned int echl)
{
	unsigned long umc_base[MLU370_CHL_PER_MEMSYS_CNT] = {0x1c000, 0x20000};
	unsigned long reg_base = mlu370_memsys_reg[emsys].reg_base;
	unsigned int reg_value = 0;

	reg_value = reg_read32(core->bus_set, reg_base + 0x10000 + 0x900);
	if (reg_value) {
		WARN(1, "should disable clock gate before read register");
		return 0;
	}

	reg_value = reg_read32(core->bus_set, reg_base + umc_base[echl] + 0xC00);

	reg_write32(core->bus_set, reg_base + umc_base[echl] + 0xB04, (reg_value & 0x7));
	cn_bus_mb(core->bus_set);

	return reg_value & 0x2;
}

static int
__prepare_address_check(struct cn_core_set *core, struct ddr_retire_set *retire,
			unsigned int msys_idx)
{
	int ret = 0;

	switch (retire->check_mode) {
	case CHECK_USE_GDMA:
		ret = mlu370_retire_create_shm_buffer(core, &retire->dev_vaddr,
					&retire->host_vaddr);
		break;
	case CHECK_USE_DMA:
	default:
		ret = mlu370_retire_create_host_buffer(&retire->host_buffer);
		break;
	}

	if (ret)
		return ret;

	reg_write32(core->bus_set, mlu370_memsys_reg[msys_idx].reg_base + 0x10900, 0x3f0000);
	cn_bus_mb(core->bus_set);
	return 0;
}

static void
__release_address_check(struct cn_core_set *core, struct ddr_retire_set *retire,
				unsigned int msys_idx)
{
	reg_write32(core->bus_set, mlu370_memsys_reg[msys_idx].reg_base + 0x10900, 0x3f003f);
	cn_bus_mb(core->bus_set);

	switch (retire->check_mode) {
	case CHECK_USE_GDMA:
		mlu370_retire_destroy_shm_buffer(core, retire->dev_vaddr, retire->host_vaddr);
		retire->dev_vaddr = 0;
		retire->host_vaddr = 0;
		break;
	case CHECK_USE_DMA:
	default:
		mlu370_retire_destroy_host_buffer(retire->host_buffer);
		retire->host_buffer = NULL;
		break;
	}
}

static int
__ddr_read_check(struct cn_core_set *core, struct ddr_retire_set *retire_set,
		unsigned long base, unsigned long size)
{
	unsigned long tmp_buffer = 0UL;
	int ret = 0;

	switch (retire_set->check_mode) {
	case CHECK_USE_GDMA:
		tmp_buffer = (unsigned long)retire_set->dev_vaddr;
		if (!tmp_buffer)
			return -EINVAL;
		ret = cn_gdma_memcpy_sync(core, base, tmp_buffer, size, MEMCPY_D2D_NO_COMPRESS);
		break;
	case CHECK_USE_DMA:
	default:
		tmp_buffer = (unsigned long)retire_set->host_buffer;
		if (!tmp_buffer)
			return -EINVAL;
		ret = cn_bus_dma_kernel(core->bus_set, tmp_buffer, base, size, DMA_D2H);
		break;
	}

	return ret;
}

/* return 1 -- input address is error address, else return 0 */
static bool
__address_is_bad(void *pretire, unsigned long base, unsigned long size,
		unsigned int emsys, unsigned int echl, bool recheck)
{
	struct ddr_retire_set *retire_set = (struct ddr_retire_set *)pretire;
	struct cn_mcc_set *mcc_set = NULL;
	struct cn_core_set *core = NULL;
	int ret = 0, recheck_times = 1, level = 0, force_bad = 0;

	if (!retire_set)
		return 0;

	mcc_set = retire_set->mcc_set;
	core = (struct cn_core_set *)mcc_set->core;

	if (retire_set->debug_mode) {
		level = mlu370_size2level(size);
		if (level < 0) {
			WARN(1, "Invalid size input(%#lx), which is forbidden", size);
			return 0;
		}

		if (retire_set->dbg_level_times[level]++ ==
			retire_set->dbg_level_idx[level]) {

			cn_dev_core_info(core, "debug inject error enter level:%d, (%#lx, %#lx)!",
							 level, base, size);

			force_bad = 1;
			retire_set->dbg_level_idx[level] = 0;
			retire_set->dbg_level_times[level] = 0;
			if (level == L2_BITS)
				retire_set->debug_mode = false;
		}
	}

do_recheck:
	ret = __ddr_read_check(core, retire_set, base, size);
	if (!ret && !force_bad)
		return 0;

	ret = __read_2bit_status(core, emsys, echl);
	if (!ret && !force_bad)
		return 0;

	if (recheck && recheck_times-- > 0)
		goto do_recheck;

	return 1;
}

static int __set_and_check_config(struct cn_bus_set *bus_set,
				struct ddr_retire_set *retire_set)
{
	struct cn_core_set *core = ((struct cn_bus_set *)bus_set)->core;
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	struct memsys_config_st *msys_config = &mcc_set->msys_config;

	if (msys_config->mlu370.shuffle_en != SHUFFLE_STATUS) {
		cn_dev_core_err(core, "mlu370 not enable shuffle, couldn't support pageRetire!");
		return -EPERM;
	}

	if (msys_config->mlu370.interleave_size != INTERLEAVE_SIZE) {
		cn_dev_core_err(core, "mlu370 interleave size isn't 512B, couldn't support pageRetire!");
		return -EPERM;
	}

	if (msys_config->mlu370.llc_interleave_mode != LLC_INTERLEAVE_MODE) {
		cn_dev_core_err(core, "mlu370 isn't 3chl llc interleave, couldn't support pageRetire!");
		return -EPERM;
	}

	if (msys_config->mlu370.llc_3chl_mode != LLC_3CHL_MODE) {
		cn_dev_core_err(core, "mlu370 isn't 3chl no waste interleave, couldn't support pageRetire!");
		return -EPERM;
	}

	return 0;
}

/* norflash write need read first, so called norflash_data_check before each write
 *
 * Return Value:
 *	0 for success, 1 for norflash data is invalid or null(need rewrite during
 *	init), other situation is error code returned.
 **/
static int __norflash_read_check(struct cn_core_set *core,
					struct ddr_retire_set *retire_set)
{
	struct norflash_info_t *norflash = retire_set->norflash_info;
	unsigned int len = NORFLASH_LEN(EEPROM_MAX_NUM), retlen = 0;

	retlen = nor_read(core, (uint32_t *)norflash, NORFLASH_PADDR, len);
	if (retlen != len)
		return -EINVAL;

	return (norflash->magic != NORFLASH_MAGIC) ||
		(NORFLASH_LEN(norflash->counts) != norflash->length);
}

static int __clear_norflash_data(struct cn_core_set *core,
			struct ddr_retire_set *retire_set)
{
	struct norflash_info_t *norflash_buf = retire_set->norflash_info;
	int i = 0, ret = 0;

	ret = __norflash_read_check(core, retire_set);
	if (ret < 0) {
		cn_dev_core_err(core, "read norflash failed as unexpect!");
		return -EPERM;
	}

	cn_dev_core_info(core, "Old data saved in Norflash:");
	for (i = 0; i < norflash_buf->counts; i++)
		cn_dev_core_info(core, "\t[%d]: %#llx", i, norflash_buf->addrs[i]);

	norflash_buf->magic = NORFLASH_MAGIC;
	norflash_buf->counts = 0;
	norflash_buf->length = NORFLASH_LEN(norflash_buf->counts);
	memset(norflash_buf->addrs, 0, sizeof(uint64_t) * EEPROM_MAX_NUM);

	ret = nor_write(core, (uint32_t *)norflash_buf, NORFLASH_PADDR,
					NORFLASH_LEN(EEPROM_MAX_NUM));
	if (ret != NORFLASH_LEN(EEPROM_MAX_NUM)) {
		cn_dev_core_err(core, "try to rewrite initial data into norflash failed!");
		return -EINVAL;
	}

	return 0;
}

static void
__dump_iecc_node_data(struct cn_core_set *core, struct iecc_node_t *iecc_node,
			int index)
{
	struct tm tm;
	char err_string[128] = " ";
	unsigned int type = 0;
	int i = 0;

	/* NOTE: output time is UTC+0, should add/sub timezone manually */
	cn_time64_to_tm(iecc_node->secs, 0, &tm);

	for (i = 0; i < MLU370_CHL_PER_MEMSYS_CNT; i++) {
		type = iecc_node->type[i];
		if (!type) continue;

		memset(err_string, 0x0, sizeof(char) * 128);
		if (type & 0x1) strcat(err_string, "SBE ");
		if (type & 0x2) strcat(err_string, "DBE ");
		if (type & 0x4) strcat(err_string, "OVERFLOW ");
		if (type & 0x8) strcat(err_string, "OTHERS ");

		cn_dev_core_info(core, "    %d : [(UTC+0): %04ld-%02d-%02d %02d:%02d:%02d] channel: %d, reason: %s", index,
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
				tm.tm_min, tm.tm_sec, i, err_string);
	}
}

static int __dump_iecc_info_data(struct cn_core_set *core)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	struct ddr_retire_set *retire_set =
		(struct ddr_retire_set *)mcc_set->repair_set;
	struct iecc_info_t *iecc_info = retire_set->iecc_status;
	struct iecc_node_t *iecc_node = NULL;
	int i = 0, j = 0, counts = 0;

	cn_dev_core_info(core, "Internal ECC info list: ");

	for (i = 0; i < MLU370_MSYS_CNT(core->die_cnt); i++) {
		if (!iecc_info[i].total_counts)
			continue;

		cn_dev_core_info(core, "  Memsys%d, (SBE:%ld, DBE:%ld, OF:%ld, OTHERS:%ld)",
				i, iecc_info[i].sbe, iecc_info[i].dbe, iecc_info[i].over_flow,
				iecc_info[i].others);

		for (j = iecc_info[i].total_counts - 1, counts = 0;
			 j >= 0 && counts < MAX_IECC_NODE_COUNTS; j--, counts++) {
			iecc_node = &iecc_info[i].nodes[j % MAX_IECC_NODE_COUNTS];
			__dump_iecc_node_data(core, iecc_node, j);
		}
	}

	return 0;
}

static int __recheck_norflash_data(struct cn_core_set *core,
			struct ddr_retire_set *retire_set)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	struct memsys_config_st *msys_config = &mcc_set->msys_config;
	struct norflash_info_t *norflash_buf = retire_set->norflash_info;
	unsigned long div_base = ile_unprotect_base + ile_unprotect_size;
	unsigned long eaddr = 0;
	unsigned int msys_cnt = 0, msys_idx = 0, chl_idx = 0;
	int i = 0, ret = 0;

	msys_cnt = MLU370_MSYS_CNT(core->die_cnt);
	for (i = 0; i < msys_cnt; i++)
		cn_bus_disable_irq(core->bus_set, memsys_mlu370_irq[i].irq);

	cn_dev_core_info(core, "Error address saved in Norflash:");
	for (i = 0; i < norflash_buf->counts; i++) {
		eaddr = BITS(norflash_buf->addrs[i], 39, 0);
		msys_idx = BITS(norflash_buf->addrs[i], 63, 60);
		chl_idx = BITS(norflash_buf->addrs[i], 59, 59);
		eaddr = mlu370_address_decode(eaddr, msys_config->mlu370.ch_cap_x512, div_base,
						msys_config->mlu370.chl_remap_mode, core->ile_en);

		ret = __prepare_address_check(core, retire_set, 0);
		if (ret)
			continue;

		ret = __address_is_bad(retire_set, eaddr, 1UL << 9, msys_idx, chl_idx, false);
		cn_dev_core_info(core, "[%d]: address in norflash: %#llx, eaddr:%#lx, recheck value:%d",
				i, norflash_buf->addrs[i], eaddr, ret);

		__release_address_check(core, retire_set, 0);
	}

	for (i = 0; i < msys_cnt; i++)
		cn_bus_enable_irq(core->bus_set, memsys_mlu370_irq[i].irq);

	return 0;
}

static void
__save_address_in_retire(struct cn_core_set *core,
			struct ddr_retire_set *retire_set, unsigned long eaddr,
			unsigned int msys_idx, unsigned int chl_idx)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	struct memsys_config_st *msys_config = &mcc_set->msys_config;
	struct norflash_info_t *norflash_info = retire_set->norflash_info;
	unsigned long div_base = ile_unprotect_base + ile_unprotect_size;
	unsigned int index = 0;
	int ret = 0;

	if (retire_set->retire_num >= EEPROM_MAX_NUM)
		return ;

	/* NOTE: mlu370 only new DBE address will come here */
	mlu370_addr2info(eaddr, ECC_BIT_2,
		&retire_set->retire_info[retire_set->retire_num]);
	retire_set->retire_num++;

	if (!atomic_read(&retire_set->norflash_enable))
		return ;

	ret = __norflash_read_check(core, retire_set);
	if (ret < 0)
		return;

	if ((norflash_info->counts + 1) < EEPROM_MAX_NUM) {
		index = norflash_info->counts;

		norflash_info->magic = NORFLASH_MAGIC;
		norflash_info->addrs[index] = mlu370_address_encode(eaddr,
				msys_config->mlu370.ch_cap_x512, div_base, msys_config->mlu370.chl_remap_mode);
		SET_BITS(norflash_info->addrs[index], 63, 60, msys_idx);
		SET_BITS(norflash_info->addrs[index], 59, 59, chl_idx);

		norflash_info->counts++;
		norflash_info->length = NORFLASH_LEN(norflash_info->counts);
		nor_write(core, (uint32_t *)norflash_info,
				  NORFLASH_PADDR, norflash_info->length);
	}
}

static int
__init_norflash_and_retire_info(struct cn_core_set *core,
				struct ddr_retire_set *retire)
{
	struct cn_mcc_set *mcc_set = (struct cn_mcc_set *)core->mcc_set;
	struct memsys_config_st *msys_config = &mcc_set->msys_config;
	struct norflash_info_t *norflash_buf = retire->norflash_info;
	unsigned long div_base = ile_unprotect_base + ile_unprotect_size;
	unsigned long eaddr = 0;
	int rewrite_flag = 0, i = 0, ret = 0;

	/* 1. read data from norflash, if norflash data is invalid, rewrite and init */
	ret = __norflash_read_check(core, retire);
	if (ret < 0)
		return ret;

	/* first use norflash saved data, norflash not have data in. */
	if (ret == 1) {
		norflash_buf->magic = NORFLASH_MAGIC;
		norflash_buf->counts = 0;
		norflash_buf->length = NORFLASH_LEN(norflash_buf->counts);
		memset(norflash_buf->addrs, 0, sizeof(uint64_t) * EEPROM_MAX_NUM);
		rewrite_flag = 1;
	}

	if (rewrite_flag) {
		ret = nor_write(core, (uint32_t *)norflash_buf, NORFLASH_PADDR,
					norflash_buf->length);
		if (ret != norflash_buf->length) {
			cn_dev_core_err(core, "try to rewrite initial data into norflash failed!");
			return -EINVAL;
		}
	}

	if (!norflash_buf->counts)
		return 0;

	/* 2. use norflash_info's address init retire_info */
	for (i = 0; i < norflash_buf->counts; i++) {
		eaddr = BITS(norflash_buf->addrs[i], 39, 0);
		eaddr = mlu370_address_decode(eaddr, msys_config->mlu370.ch_cap_x512, div_base,
						msys_config->mlu370.chl_remap_mode, core->ile_en);

		ret = mlu370_retire_set_addr(retire->bitmap, eaddr);
		if (ret)
			return ret;

		cn_dev_core_info(core, "%d: address in norflash: %#llx, after decode:%#lx",
					i, norflash_buf->addrs[i], eaddr);
		mlu370_addr2info(eaddr, ECC_BIT_2, &retire->retire_info[i]);
	}

	retire->retire_num = i;
	retire->retire_index = i;
	return 0;
}

static void ddr_retire_find_address_work(struct work_struct *work)
{
	struct ddr_retire_set *retire_set = NULL;
	struct ecc_info_t *ecc_info = NULL;
	struct cn_mcc_set *mcc_set;
	struct cn_core_set *core;
	unsigned int msys_index = 0, chl_index = 0;
	unsigned long eaddr = 0;
	int ret = 0, i = 0, do_retire = 0;

	retire_set = container_of(work, struct ddr_retire_set, retire_work);
	if (!retire_set || !retire_set->mcc_set)
		return ;

	mcc_set = (struct cn_mcc_set *)retire_set->mcc_set;
	if (!mcc_set->core)
		return ;

	core = (struct cn_core_set *)mcc_set->core;

	if (atomic_cmpxchg(&retire_set->work_status, RETIRE_WORK_READY,
			RETIRE_WORK_RUNNING) != RETIRE_WORK_READY)
		return ;

	msys_index = BITS(retire_set->work_params, 4, 1);
	chl_index = BITS(retire_set->work_params, 0, 0);
	ecc_info = ((struct ecc_info_t *)mcc_set->ecc_status) + msys_index;

	ret = __prepare_address_check(core, retire_set, msys_index);
	if (ret) {
		cn_dev_core_err(core, "failed to create host buffer");
		goto exit;
	}

	ret = mlu370_retire_find_addr(retire_set->bitmap, msys_index, chl_index,
			&eaddr, __address_is_bad);
	if (!ret) {
		do_retire = 1;
	}
	__release_address_check(core, retire_set, msys_index);

exit:
	for (i = 0; i < MLU370_MSYS_CNT(core->die_cnt); i++) {
		ret = __single_memsys_enable_irq(core, i);
		if (ret) {
			cn_dev_core_err(core, "reenable inline-ecc %d irq isr failed", i);
		}
	}

	atomic_set(&retire_set->work_status, RETIRE_WORK_IDLE);

	if (do_retire) {
		__save_address_in_retire(core, retire_set, eaddr, msys_index, chl_index);

		if (core->state == CN_RUNNING && atomic_read(&retire_set->retire_enable))
			cn_mem_pageretire_handle(core);

		cn_xid_err(core, XID_ECC_ERR, "%s chl %d two bit ecc occured in address:%#lx",
			 mlu370_memsys_reg[msys_index].name, chl_index, eaddr);

		ecc_info->multiple_one_bit_ecc_error++;
	} else {
		cn_dev_core_debug(core, "Find error address failed for(msys:%d, chl:%d)",
				msys_index, chl_index);
	}
}

int ddr_retire_init_mlu370(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set = NULL;
	unsigned int msys_cnt = MLU370_MSYS_CNT(core->die_cnt);
	int ret = 0;

	/* 1. loop dte check ddr is validate for use */
	ret = __memsys_unprotect_area_check(mcc_set, msys_cnt);
	if (ret) {
		cn_dev_core_err(core, "unprotect area have uncorrectable ecc error,"
						" driver is forbidden to load!");
		return -EPERM;
	}

	retire_set = cn_kzalloc(sizeof(struct ddr_retire_set), GFP_KERNEL);
	if (!retire_set) {
		cn_dev_core_err(core, "failed to create ddr_retire_set");
		return -ENOMEM;
	}

	retire_set->iecc_status =
		cn_kzalloc(msys_cnt * sizeof(struct iecc_info_t), GFP_KERNEL);
	if (!retire_set->iecc_status) {
		cn_dev_core_err(core, "create internal ecc status buffer failed!");
		ret = -ENOMEM;
		goto failed_create_iecc;
	}

	/* 2. Create and init bitmap for search error address in irq_handler */
	retire_set->bitmap = mlu370_retire_bitmap_init(mcc_set, (void *)retire_set,
				msys_cnt, __per_chl_size(core, core->ile_en),
				ile_unprotect_base + ile_unprotect_size);
	if (IS_ERR_OR_NULL(retire_set->bitmap)) {
		cn_dev_core_err(core, "failed to create ddr bitmap st");
		ret = -ENOMEM;
		goto failed_create_bitmap;
	}

	retire_set->check_mode = CHECK_USE_GDMA;
	/* 3. get and check system and llc config is supported */
	ret = __set_and_check_config(core->bus_set, retire_set);
	if (ret) {
		cn_dev_core_err(core, "mlu370 config is error, couldn't support pageRetire");
		goto failed_check_config;
	}

	/* 4. Get addresses which need to be retired from EEPROM */
	atomic_set(&retire_set->norflash_enable, core->ile_en);
	retire_set->norflash_info =
		cn_kzalloc(NORFLASH_LEN(EEPROM_MAX_NUM), GFP_KERNEL);
	if (!retire_set->norflash_info) {
		ret = -ENOMEM;
		cn_dev_core_err(core, "alloc for norflash buffer failed");
		goto failed_check_config;
	}

	ret = __init_norflash_and_retire_info(core, retire_set);
	if (ret) {
		cn_dev_core_err(core, "init norflash_info and retire_info failed");
		goto failed_init_norflash;
	}

	/* 5. Init inlineECC irq handler half bottom workqueue */
	retire_set->work_params = 0;
	atomic_set(&retire_set->work_status, RETIRE_WORK_IDLE);
	INIT_WORK(&retire_set->retire_work, ddr_retire_find_address_work);

	/* NOTE: current only support pf only enable page retire */
	if (!cn_core_is_vf(core) && !cn_is_mim_en(core)) {
		atomic_set(&retire_set->retire_enable, core->ile_en);
	} else {
		atomic_set(&retire_set->retire_enable, 0);
	}

	retire_set->mcc_set = mcc_set;
	retire_set->debug_mode = false;

	mcc_set->repair_ops = &ddr_retire_ops_mlu370;
	mcc_set->repair_set = (void *)retire_set;
	return 0;

failed_init_norflash:
	cn_kfree(retire_set->norflash_info);
	retire_set->norflash_info = NULL;
failed_check_config:
	mlu370_retire_bitmap_exit(retire_set->bitmap);
	retire_set->bitmap = NULL;
failed_create_bitmap:
	cn_kfree(retire_set->iecc_status);
	retire_set->iecc_status = NULL;
failed_create_iecc:
	cn_kfree(retire_set);
	return ret;
}

void ddr_retire_exit_mlu370(struct cn_mcc_set *mcc_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct ddr_retire_set *retire_set =
		(struct ddr_retire_set *)mcc_set->repair_set;
	int ret = 0;

	if (!retire_set)
		return ;

	/* 1. destroy work for page retire */
	flush_work(&retire_set->retire_work);
	ret = cancel_work_sync(&retire_set->retire_work);
	if (ret) {
		cn_dev_core_warn(core, "retire_work sync return %d", ret);
	}

	/* 2. release norflash_info */
	cn_kfree(retire_set->norflash_info);
	retire_set->norflash_info = NULL;

	/* 3. destroy bitmap */
	mlu370_retire_bitmap_exit(retire_set->bitmap);
	retire_set->bitmap = NULL;

	cn_kfree(retire_set->iecc_status);
	retire_set->iecc_status = NULL;

	/* 4. release retire_set */
	cn_kfree(retire_set);
	mcc_set->repair_set = NULL;
	mcc_set->repair_ops = NULL;

	cn_dev_core_info(core, "mlu370 retire resource release finished!");
}
/*** End   mlu370 inlineECC PageRetirement ***/
