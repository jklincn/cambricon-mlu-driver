#include <linux/delay.h>
#include <linux/printk.h>

#include "cndrv_core.h"

#include "cpu_subsys_ctrl_c30s.h"
#include "cpu_subsys_gt_c30s.h"

#define COREN_WARM_FLAG	(0xf)

#define CPU_ROOT_RESETN		(0x083D4448)
#define CPU_RESET_PROTECT_REG	(0x083D5004)
#define CPU_MHR_IDLE_REG	(0x83D5008)
#define CPU_MHR_REQ_REG		(0x83D501C)

#define CFG_CPU_DATA_RESET_PROC_EN_OFFSET	(0)
#define CFG_JS_DATA_RESET_PROC_EN_OFFSET	(4)
#define CFG_CPU_CFG_M_RESET_PROC_EN_OFFSET	(8)
#define CFG_JS_CFG_M_RESET_PROC_EN_OFFSET	(12)
#define CFG_CPU_CFG_S_RESET_PROC_EN_OFFSET	(16)
#define CFG_D2D_M0_CFG_M_RESET_PROC_EN_OFFSET	(20)
#define CFG_D2D_M0_CFG_S_RESET_PROC_EN_OFFSET	(24)
#define CFG_JS_CPU_RESET_PROC_EN_OFFSET		(28)

#define CFG_CPU_CFG_MHR_REQ_OFFSET	(0)
#define CFG_CPU_DATA_MHR_REQ_OFFSET	(4)

#define INFO_CPU_DATA_MHR_IDLE_OFFSET	(0)
#define INFO_CPU_CFG_MHR_IDLE_OFFSET	(8)


#define CPU_SET_START_ADDR			(0x08500000)
#define CPU_SET_END_ADDR			(0x08501000)

extern void reg_write32(void *bus_set, unsigned long offset, u32 val);
extern u32 reg_read32(void *bus_set, unsigned long offset);

void sync_wr_reg32(void *bus_set, unsigned long offset, u32 val)
{
	reg_write32(bus_set, offset, val);
	reg_read32(bus_set, offset);
}

u32 sync_rd_reg32(void *bus_set, unsigned long offset)
{
	u32 val;

	val = reg_read32(bus_set, offset);
	return val;
}

#define TOP_NORTH1_CSR_UART		(0x83d5038)
#define TOP_NORTH2_CSR_UART		(0x034f080)

static void uart_enable(struct cn_core_set *core)
{
	unsigned int val = 0;
	sync_wr_reg32(core->bus_set, TOP_NORTH1_CSR_UART, 0);
	sync_wr_reg32(core->bus_set, TOP_NORTH2_CSR_UART, 0x100);
	reg_read32(core->bus_set, TOP_NORTH2_CSR_UART);

	/* pad uart0 tx & rx set */
	val = sync_rd_reg32(core->bus_set, 0x36007c);
	val &= ~(0x3);
	val |= 0x1;
	sync_wr_reg32(core->bus_set, 0x36007c, val);

	val = sync_rd_reg32(core->bus_set, 0x360080);
	val &= ~(0x3);
	val |= 0x1;
	sync_wr_reg32(core->bus_set, 0x360080, val);
}

int c30s_boot_pre_non_secure(struct cn_core_set *core)
{
	unsigned int val, set_val;
	int ret = 0;
	unsigned int timeout_cnt = 0x1000000;

	uart_enable(core);

	val = sync_rd_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPURSTCTRL_OFFSET_REG);
	pr_info("=== pre boot stage: rst ctrl register data = 0x%x\n", val);

	if (val & COREN_WARM_FLAG) { /* will reset cpu */
		/* step 0: enable mhr request, back press cpu request */
		val = sync_rd_reg32(core->bus_set, CPU_MHR_REQ_REG);
		set_val = (1 << CFG_CPU_CFG_MHR_REQ_OFFSET) | (1 << CFG_CPU_DATA_MHR_REQ_OFFSET);
		set_val = val | set_val;
		sync_wr_reg32(core->bus_set, CPU_MHR_REQ_REG, set_val);

		/* step 1: wait bus idle */
		set_val = (1 << INFO_CPU_DATA_MHR_IDLE_OFFSET) | (1 << INFO_CPU_CFG_MHR_IDLE_OFFSET);
		do {
			val = sync_rd_reg32(core->bus_set, CPU_MHR_IDLE_REG);
			timeout_cnt--;
		} while (((val & set_val) != set_val) && timeout_cnt);

		if (!timeout_cnt)
		{
			pr_err("boot pre stage: wait cpu idle timeout.\n");
		}

		/* step 2: start reset protect */
		val = sync_rd_reg32(core->bus_set, CPU_RESET_PROTECT_REG);
		set_val = (1 << CFG_CPU_DATA_RESET_PROC_EN_OFFSET) | (1 << CFG_CPU_CFG_M_RESET_PROC_EN_OFFSET) | (1 << CFG_CPU_CFG_S_RESET_PROC_EN_OFFSET) | (1 << CFG_JS_CPU_RESET_PROC_EN_OFFSET);
		set_val = val & (~set_val);
		sync_wr_reg32(core->bus_set, CPU_RESET_PROTECT_REG, set_val);

		/* step 3: set cpu root reset */
		sync_wr_reg32(core->bus_set, CPU_ROOT_RESETN, 0);

		/* step 4: release mhr request */
		val = sync_rd_reg32(core->bus_set, CPU_MHR_REQ_REG);
		set_val = (1 << CFG_CPU_CFG_MHR_REQ_OFFSET) | (1 << CFG_CPU_DATA_MHR_REQ_OFFSET);
		set_val = val & (~set_val);
		sync_wr_reg32(core->bus_set, CPU_MHR_REQ_REG, set_val);

		/* step 5: release reset protect */
		val = sync_rd_reg32(core->bus_set, CPU_RESET_PROTECT_REG);
		set_val = (1 << CFG_CPU_DATA_RESET_PROC_EN_OFFSET) | (1 << CFG_CPU_CFG_M_RESET_PROC_EN_OFFSET) | (1 << CFG_CPU_CFG_S_RESET_PROC_EN_OFFSET) | (1 << CFG_JS_CPU_RESET_PROC_EN_OFFSET);
		set_val = val | set_val;
		sync_wr_reg32(core->bus_set, CPU_RESET_PROTECT_REG, set_val);

		/* step 6: de-assert cpu_system */
		sync_wr_reg32(core->bus_set, CPU_ROOT_RESETN, 1);
	}

	return ret;
}

int c30s_cpu_boot_non_secure(struct cn_core_set *core, uint64_t boot_entry)
{
	uint64_t pc_low, pc_high;
	uint64_t pc;

	printk("\n");
	pr_info("#################################\n");
	pr_info("# ACPU boot, entry point 0x%llx\n", boot_entry);
	pr_info("###################################\n");

	/* step-3-2: assign boot cpu reset address */
	/* only cpu0 assignment */
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_RVBARADDR0L_OFFSET_REG, boot_entry);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_RVBARADDR0H_OFFSET_REG, boot_entry >> 32);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_RVBARADDR1L_OFFSET_REG, boot_entry);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_RVBARADDR1H_OFFSET_REG, boot_entry >> 32);

	/* step-3-3: peripheral address configure */
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_ASTARTMP_OFFSET_REG, 0x80000);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_AENDMP_OFFSET_REG, 0x80200);

	/* step-3-4: open clock*/
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CRGREGEN0_OFFSET_REG, 0x01ff01ff);

	/* read back for checking */
	sync_rd_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CRGREGEN0_OFFSET_REG);

	//sync_wr_reg32(core->bus_set, CRGREGEN1_ADDR, val);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CRGREGEN1_OFFSET_REG, 0xffffffff);

	/* read back for checking */
	sync_rd_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CRGREGEN1_OFFSET_REG);

	/* step-5: de-assert reset */
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_BUSRSTCTRL_OFFSET_REG, 0x0fff0fff);

	//sync_wr_reg32(core->bus_set, OTHER_RSTCTRL_ADDR, val);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_OTHERRSTCTRL0_OFFSET_REG, 0xffffffff);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_OTHERRSTCTRL1_OFFSET_REG, 0xffffffff);

	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CBWBYPASS_OFFSET_REG, 0x30000);

	/* extra non-allocate on LLC */
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CLUSTER_CACHE_M0_BYP_OFFSET_REG, 0xff00ff);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CLUSTER_AWCACHE_M0_VAL_OFFSET_REG, 0xffff2222);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CLUSTER_ARCACHE_M0_VAL_OFFSET_REG, 0xffff2222);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CLUSTER_CACHE_M1_BYP_OFFSET_REG, 0xff00ff);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CLUSTER_AWCACHE_M1_VAL_OFFSET_REG, 0xffff2222);
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CLUSTER_ARCACHE_M1_VAL_OFFSET_REG, 0xffff2222);

	/* new reliable de-assert flow */
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPURSTCTRL_OFFSET_REG, 0x01000100); // nMBISTRESET
	sync_rd_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPURSTCTRL_OFFSET_REG);

	/* nCPUPORESET[0]. nSPORESET. nPRESET. nATRESET. nGICRESET. nPERIPHRESET */
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPURSTCTRL_OFFSET_REG, 0xf610f610);
	sync_rd_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPURSTCTRL_OFFSET_REG);

	/* nSRESET */
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPURSTCTRL_OFFSET_REG, 0x08000800);
	sync_rd_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPURSTCTRL_OFFSET_REG);

	/* nCORERESET[0] */
	sync_wr_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPURSTCTRL_OFFSET_REG, 0x00010001);
	sync_rd_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPURSTCTRL_OFFSET_REG);

	pc_low = (uint64_t)sync_rd_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPU_CORE0_PCL_OFFSET_REG);
	pc_high = (uint64_t)sync_rd_reg32(core->bus_set, CTRL_BASE_ADDR + CPU_SUBSYS_CTRL_CPU_CORE0_PCH_OFFSET_REG);
	pc = (pc_high << 32) + pc_low;
	if (pc > 0) {
		pr_info("ARM bringup CORE0 ok, pc = 0x%llx\n", pc);
	}


	return 0;
}

/*
 * default value of commu regs, clear relevant commu reg fields when a service
 * triggered
 */
#define DEFAULT_COMMU_VAL (0)

/* open_response */
#define SESSION_OPENED (1)

/* task result*/
#define COMMU_PASS (1)
#define COMMU_ERR_OP (2)
#define COMMU_ERR_IMG (3)
#define COMMU_ERR_TIMEOUT (4)

/* close_response */
#define SESSION_CLOSED (1)

/* update_response */
#define UPDATE_FW_OPENED (1)

/* sec_en */
#define SECURE_BOOT (1)
#define NORMAL_BOOT (2)
#define SECURE_BOOT_BYPASS (3)

/* boot_status */
#define PCIE_INIT_DONE (1)
#define D2D_INIT_DONE (2)
#define MEMSYS_INIT_DONE (3)
#define BOOT_DONE (4)

/* acpu_fw_start_die0_response */
/* acpu_fw_start_die1_response */
#define ACPU_BOOT_DONE (1)

#define ISSE_COMMU_REG (0x36800C)

/*written by isse m0*/
union isse_commu_reg {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	struct {
		/*
		 * bit 0
		 * open response, indicate receive session with host
		 */
		unsigned int open_response : 1;
		/*
		 * bit 4:1
		 * open response, indicate task result
		 */
		unsigned int task_result : 4;
		/*
		 * bit 5
		 * close response, indicate session with host closed
		 */
		unsigned int close_response : 1;
		/*
		 * bit 6
		 * response update, indicate firewall is opened
		 */
		unsigned int update_response : 1;
		/*
		 * bit 7
		 * for convience of different endianness
		 */
		unsigned int rsv1 : 1;
		/*
		 * bit 10:8
		 * sec en, indicate is secure boot/normal boot/secure bypass boot
		 */
		unsigned int sec_en : 3;
		/*
		 * bit 13:11
		 * boot status, indicate init status pcie/d2d/ddr/done
		 */
		unsigned int boot_status : 3;
		/*
		 * bit 15:14
		 * for convience of different endianness
		 */
		unsigned int rsv2 : 2;
		unsigned int rsv3 : 8;
		/*
		 * bit 24
		 */
		unsigned int version_revision : 1;
		/*
		 * bit 26:25
		 */
		unsigned int version_minor : 2;
		/*
		 * bit 31:27
		 */
		unsigned int version_major : 5;
	} bits;
#elif defined(__BIG_ENDIAN_BITFIELD)
	struct {
		unsigned int version_major : 5;
		unsigned int version_minor : 2;
		unsigned int version_revision : 1;
		unsigned int rsv3 : 8;
		unsigned int rsv2 : 3;
		unsigned int boot_status : 3;
		unsigned int sec_en : 2;
		unsigned int rsv1 : 1;
		unsigned int update_response : 1;
		unsigned int close_response : 1;
		unsigned int task_result : 4;
		unsigned int open_response : 1;
	} bits;
#endif
	unsigned int flagsWord;
};

#define ISSE_COMMU_GET(field, pval)              \
do {                                              \
	union isse_commu_reg config;                     \
	config.flagsWord = sync_rd_reg32(core->bus_set, ISSE_COMMU_REG); \
	*pval = config.bits.field;                   \
} while (0)

#define OPERATION_TIMEOUT (10000)  /*10s*/

#define ISSE_COMMU_WAIT(field, exp, pret)          \
do {                                                \
	union isse_commu_reg config;                       \
	unsigned int cnt = OPERATION_TIMEOUT;          \
	*pret = 0;                                     \
	do {                                           \
		config.flagsWord = sync_rd_reg32(core->bus_set, ISSE_COMMU_REG); \
		if (exp == config.bits.field) \
			break;         \
		usleep_range(1000, 2000);                  \
	} while (--cnt);                               \
	if (!cnt) \
		*pret = 1;                           \
} while (0)

#define HOST_COMMU_REG (0x368010)

/* open */
#define OPEN_SESSION (1)

/* task_id */
#define IMG_UPDATE (1)
#define MCU_UPDATE (2)
#define IMG_ERASE (3)
#define ACPU_BOOT (4)

/* close */
#define CLOSE_SESSION (1)

/* update_start */
#define UPDATE_IMG_IN_SRAM (1)

/* acpu_fw_start_die0 */
/* acpu_fw_start_die1 */
#define ACPU_IMG_IN_DRAM (1)

/*written by host*/
union host_commu_reg {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	struct {
		/*
		 * bit 0
		 * open, open session with isse m0
		 */
		unsigned int open : 1;
		/*
		 * bit 4:1
		 * task_id, 0001 : image update
		 *          0010 : mcu update
		 *          0011 : image erase
		 *          0100 : a55 boot
		 *          0101-1111 : reserved
		 *
		 */
		unsigned int task_id : 4;
		/*
		 * bit 5
		 * open, close session with isse m0
		 */
		unsigned int close : 1;
		/*
		 * bit 6
		 * update start, indicate image already in isse sram
		 */
		unsigned int update_start : 1;
		/*
		 * bit 7
		 * acpu fw start die0, indicate die0 acpu image in dram
		 */
		unsigned int acpu_fw_start_die0 : 1;
		/*
		 * bit 8
		 * acpu fw start die1, indicate die1 acpu image in dram
		 */
		unsigned int acpu_fw_start_die1 : 1;
		unsigned int rsv1 : 7;
		unsigned int rsv2 : 16;
	} bits;
#elif defined(__BIG_ENDIAN_BITFIELD)
	struct {
		unsigned int rsv2 : 16;
		unsigned int rsv1 : 7;
		unsigned int acpu_fw_start_die1 : 1;
		unsigned int acpu_fw_start_die0 : 1;
		unsigned int update_start : 1;
		unsigned int close : 1;
		unsigned int task_id : 4;
		unsigned int open : 1;
	} bits;
#endif
	unsigned int flagsWord;
};

#define HOST_COMMU_SET(field, val)               \
do {                                              \
	union host_commu_reg config;                     \
	config.flagsWord = sync_rd_reg32(core->bus_set, HOST_COMMU_REG); \
	config.bits.field = val;                     \
	sync_wr_reg32(core->bus_set, HOST_COMMU_REG, config.flagsWord); \
} while (0)

/*
 * secure entry_point specified in mailbox1 channel info 8-9 in peri system
 * addr : 0x8000367028 - 0x800036702c
 */
#define PERI_MBX1 (0x8000367000)
#define MBX_CH8_OFFSET (0x28)
#define MBX_CH9_OFFSET (0x2c)
#define MBX_CH10_OFFSET (0x30)
#define MBX_CH11_OFFSET (0x34)

/*open session*/
int session_open(struct cn_core_set *core)
{
	int ret = 0;

	/*wait session idle*/
	ISSE_COMMU_WAIT(open_response, DEFAULT_COMMU_VAL, &ret);
	if (ret) {
		pr_err("%s: session busy\n", __func__);
		return -1;
	}

	HOST_COMMU_SET(open, OPEN_SESSION);

	ISSE_COMMU_WAIT(open_response, SESSION_OPENED, &ret);
	if (!ret) {
		HOST_COMMU_SET(open, DEFAULT_COMMU_VAL); /*clear as quick as possible*/
		return 0;
	}

	HOST_COMMU_SET(open, DEFAULT_COMMU_VAL); /*clear as quick as possible*/
	pr_err("%s: response timeout\n", __func__);
	return -1;
}

static inline void set_task_id(struct cn_core_set *core, unsigned int task)
{
	HOST_COMMU_SET(task_id, task);
}

static int get_task_result_timeout(struct cn_core_set *core, unsigned int *ptask_result)
{
	unsigned int val = 0;
	unsigned int cnt = OPERATION_TIMEOUT;

	do {
		ISSE_COMMU_GET(task_result, &val);
		usleep_range(1000, 2000);
	} while ((--cnt) && (val == DEFAULT_COMMU_VAL));

	if (cnt) {
		*ptask_result = val;
		return 0;
	}

	pr_err("%s: response timeout\n", __func__);
	return -1;
}

/*close session*/
int session_close(struct cn_core_set *core)
{
	int ret = 0;

	/*clear open here, in case M0 receive again after close response*/
	HOST_COMMU_SET(open, DEFAULT_COMMU_VAL);

	HOST_COMMU_SET(close, CLOSE_SESSION);

	ISSE_COMMU_WAIT(close_response, SESSION_CLOSED, &ret);
	if (!ret) {
		return 0;
	}

	pr_err("%s: response timeout\n", __func__);
	return -1;
}

/*
 * @brief: free commu regs used in task, including wait close response
 * @param[in]
 * @return
 */
static void sesssion_free(struct cn_core_set *core)
{
	HOST_COMMU_SET(open, DEFAULT_COMMU_VAL);
	set_task_id(core, DEFAULT_COMMU_VAL);
	HOST_COMMU_SET(close, DEFAULT_COMMU_VAL);

	HOST_COMMU_SET(acpu_fw_start_die0, DEFAULT_COMMU_VAL);
	HOST_COMMU_SET(acpu_fw_start_die1, DEFAULT_COMMU_VAL);
}

int c30s_cpu_boot_secure(struct cn_core_set *core, uint64_t boot_entry)
{
	uint32_t val = 0;
	int32_t ret = 0;
	int32_t ret1 = 0;

	sync_wr_reg32(core->bus_set, PERI_MBX1 + MBX_CH8_OFFSET, boot_entry & 0xFFFFFFFF);
	sync_wr_reg32(core->bus_set, PERI_MBX1 + MBX_CH9_OFFSET, boot_entry >> 32);
	sync_wr_reg32(core->bus_set, PERI_MBX1 + MBX_CH10_OFFSET, core->certs_addr  & 0xFFFFFFFF);
	sync_wr_reg32(core->bus_set, PERI_MBX1 + MBX_CH11_OFFSET, core->certs_addr  >> 32);

	ret = session_open(core);
	if (ret) {
		goto bail;
	}

	HOST_COMMU_SET(acpu_fw_start_die0, ACPU_IMG_IN_DRAM);
	set_task_id(core, ACPU_BOOT);

	ret = get_task_result_timeout(core, &val);
	if (ret) {
		goto bail;
	}

	if (val == COMMU_PASS) {
		pr_info("ARM bringup CORE0 ok!\n");
	} else {
		pr_err("ARM bringup CORE0 failed: %d!\n", val);
		ret1 = val;
	}

	ret = session_close(core);
	if (ret) {
		goto bail;
	}

bail:
	sesssion_free(core);
	return ((ret1 << 8) | ret);
}

int c30s_boot_pre(struct cn_core_set *core)
{
	uint32_t val = 0;
	int ret = 0;

	ISSE_COMMU_GET(sec_en, &val);

	if (val == SECURE_BOOT) {
		ret = 0;
	} else if ((val == NORMAL_BOOT) || (val == SECURE_BOOT_BYPASS)) {
		ret = c30s_boot_pre_non_secure(core);
	} else {
		pr_err("%s: get secure status error!\n", __func__);
		ret = -1;
	}

	return ret;
}

int c30s_cpu_boot(struct cn_core_set *core, uint64_t boot_entry)
{
	uint32_t val = 0;
	int ret = 0;

	ISSE_COMMU_GET(sec_en, &val);

	if (val == SECURE_BOOT) {
		pr_info("Card[%d] secure boot\n", core->idx);
		ret = c30s_cpu_boot_secure(core, boot_entry);
	} else if ((val == NORMAL_BOOT) || (val == SECURE_BOOT_BYPASS)) {
		pr_info("Card[%d] normal boot\n", core->idx);
		ret = c30s_cpu_boot_non_secure(core, boot_entry);
	} else {
		pr_err("%s: get secure status error!\n", __func__);
		ret = -1;
	}

	return ret;
}
