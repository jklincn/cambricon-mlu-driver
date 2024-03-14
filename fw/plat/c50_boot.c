#include <linux/delay.h>
#include <linux/printk.h>

#include "cndrv_core.h"
#include "cpu_subsys_ctrl_c50.h"

#define PMU_CPU_RST_OFF		(0x7014)

extern void reg_write32(void *bus_set, unsigned long offset, u32 val);
extern u32 reg_read32(void *bus_set, unsigned long offset);


int c50_cpu_boot(struct cn_core_set *core, uint64_t boot_entry)
{
//	uint32_t val;

	printk("\n");
	pr_info("###################################\n");
	pr_info("# ACPU boot, entry point 0x%llx\n", boot_entry);
	pr_info("###################################\n");

	/* step1: assign boot cpu reset address */
	/* only cpu0 assignment */
	reg_write32(core->bus_set, RVBARADDR0L, boot_entry);
	reg_write32(core->bus_set, RVBARADDR0H, boot_entry >> 32);

	reg_write32(core->bus_set, RVBARADDR1L, boot_entry);
	reg_write32(core->bus_set, RVBARADDR1H, boot_entry >> 32);

	reg_write32(core->bus_set, RVBARADDR2L, boot_entry);
	reg_write32(core->bus_set, RVBARADDR2H, boot_entry >> 32);

	reg_write32(core->bus_set, RVBARADDR3L, boot_entry);
	reg_write32(core->bus_set, RVBARADDR3H, boot_entry >> 32);

	reg_write32(core->bus_set, RVBARADDR4L, boot_entry);
	reg_write32(core->bus_set, RVBARADDR4H, boot_entry >> 32);

	reg_write32(core->bus_set, RVBARADDR5L, boot_entry);
	reg_write32(core->bus_set, RVBARADDR5H, boot_entry >> 32);


	//step2:set axt access address
	reg_write32(core->bus_set, ASTARTMP, 0x80000);
	reg_write32(core->bus_set, AENDMP, 0x80400);

	//step3:enable buswrapper
	reg_write32(core->bus_set, CBWBYPASS, 0x30000);

	//step4:enable other modules
	reg_write32(core->bus_set, BUSRSTCTRL, 0x1fff1fff);
	reg_write32(core->bus_set, OTHERRSTCTRL0, 0xffffffff);
	reg_write32(core->bus_set, OTHERRSTCTRL1, 0xffffffff);

	//step5:enable axcache
	reg_write32(core->bus_set, CLUSTER_CACHE_M0_BYP, 0x00ff00ff);
	reg_write32(core->bus_set, CLUSTER_AWCACHE_M0_VAL, 0xffff2222);
	reg_write32(core->bus_set, ARCACHE_M0_VAL, 0xffff2222);

	reg_write32(core->bus_set, CLUSTER_CACHE_M1_BYP, 0xff00ff);
	reg_write32(core->bus_set, CLUSTER_AWCACHE_M1_VAL, 0xffff2222);
	reg_write32(core->bus_set, ARCACHE_M1_VAL, 0xffff2222);

	//step6:enable cpu cluster's mdist reset
	reg_write32(core->bus_set, CPURSTCTRL_1, 0x00800080);

	//step7:enable dsu and core0's cold resetn
	reg_write32(core->bus_set, CPURSTCTRL_1, 0x007b007b);
	reg_write32(core->bus_set, CPURSTCTRL_0, 0x01000100);

	//step8:enable dsu warm reset
	reg_write32(core->bus_set, CPURSTCTRL_1, 0x00040004);

	//step9:enable core0 warm reset
	reg_write32(core->bus_set, CPURSTCTRL_0, 0x00010001);

	return 0;
}

int c50_boot_pre_m2(struct cn_core_set *core)
{

	unsigned int reg;
	unsigned int timeout = 0;

	//step1: raise data master and cfg master's mhr req
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_DATA_MHR_REQ_M2);
	reg_write32(core->bus_set, TOP_SOUTH_0_DATA_MHR_REQ_M2, reg | 0x01);
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_CFG_MHR_REQ_M2);
	reg_write32(core->bus_set, TOP_SOUTH_0_CFG_MHR_REQ_M2, reg | 0x01);
	udelay(100);

	//step2: wait mhr bus idle
	while (timeout < 1000) {
		if ((reg_read32(core->bus_set, TOP_SOUTH_0_DATA_MHR_IDLE_M2) & 0x1) == 0x01 &&
		    (reg_read32(core->bus_set, TOP_SOUTH_0_CFG_MHR_IDLE_M2) & 0x1) == 0x01)
			break;
		timeout++;
		udelay(100);
	}
	if (timeout >= 1000) {
		pr_err("Bus Occupy! DATA MHR IDLE Value: %#x, CFG MHR IDLE Value: %#x",
		(reg_read32(core->bus_set, TOP_SOUTH_0_DATA_MHR_IDLE_M2) & 0x1),
		(reg_read32(core->bus_set, TOP_SOUTH_0_CFG_MHR_IDLE_M2) & 0x1));
		return -1;
	}
	udelay(100);

	//step3: open data mater, cfg_master, cfg_slave, acp_slave's reset protect
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_DATA_RESET_PROC_M2);
	reg_write32(core->bus_set, TOP_SOUTH_0_DATA_RESET_PROC_M2, reg & (~0x100001));
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_CFG_RESET_PROC_M2);
	reg_write32(core->bus_set, TOP_SOUTH_0_CFG_RESET_PROC_M2, reg & (~0x11));
	udelay(100);

	//step4: reset cpu_root_resetn
	reg_write32(core->bus_set, CPU_ROOT_RESETN, 0x10000);
	udelay(100);

	//step5:close reset protect
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_DATA_RESET_PROC_M2);
	reg_write32(core->bus_set, TOP_SOUTH_0_DATA_RESET_PROC_M2, reg | 0x100001);
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_CFG_RESET_PROC_M2);
	reg_write32(core->bus_set, TOP_SOUTH_0_CFG_RESET_PROC_M2, reg | 0x11);
	udelay(100);

	//step6: reset cpu root resetn
	reg_write32(core->bus_set, CPU_ROOT_RESETN, 0x10001);
	udelay(100);

	//step7; release mhr req
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_DATA_MHR_REQ_M2);
	reg_write32(core->bus_set, TOP_SOUTH_0_DATA_MHR_REQ_M2, reg & (~0x01));
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_CFG_MHR_REQ_M2);
	reg_write32(core->bus_set, TOP_SOUTH_0_CFG_MHR_REQ_M2, reg & (~0x01));
	udelay(100);

	return 0;
}

int c50_boot_pre(struct cn_core_set *core)
{

	unsigned int reg;
	unsigned int timeout = 0;

	//step1: raise data master and cfg master's mhr req
	reg = reg_read32(core->bus_set, TOP_SOUTH_1_DATA_MHR_REQ);
	reg_write32(core->bus_set, TOP_SOUTH_1_DATA_MHR_REQ, reg | 0x01);
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_1_CFG_MHR_REQ);
	reg_write32(core->bus_set, TOP_SOUTH_1_CFG_MHR_REQ, reg | 0x01);
	udelay(100);

	//step2: wait mhr bus idle
	while (timeout < 1000) {
		if ((reg_read32(core->bus_set, TOP_SOUTH_1_DATA_MHR_IDLE) & 0x1) == 0x01 &&
		    (reg_read32(core->bus_set, TOP_SOUTH_1_CFG_MHR_IDLE) & 0x1) == 0x01)
			break;
		timeout++;
		udelay(100);
	}
	if (timeout >= 1000) {
		pr_err("Bus Occupy! DATA MHR IDLE Value: %#x, CFG MHR IDLE Value: %#x",
		(reg_read32(core->bus_set, TOP_SOUTH_1_DATA_MHR_IDLE) & 0x1),
		(reg_read32(core->bus_set, TOP_SOUTH_1_CFG_MHR_IDLE) & 0x1));
		return -1;
	}
	udelay(100);

	//step3: open data mater, cfg_master, cfg_slave, acp_slave's reset protect
	reg = reg_read32(core->bus_set, TOP_SOUTH_1_DATA_RESET_PROC);
	reg_write32(core->bus_set, TOP_SOUTH_1_DATA_RESET_PROC, reg & (~0x100001));
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_1_CFG_RESET_PROC);
	reg_write32(core->bus_set, TOP_SOUTH_1_CFG_RESET_PROC, reg & (~0x11));
	udelay(100);

	//step4: reset cpu_root_resetn
	reg_write32(core->bus_set, CPU_ROOT_RESETN, 0x10000);
	udelay(100);

	//step5:close reset protect
	reg = reg_read32(core->bus_set, TOP_SOUTH_1_DATA_RESET_PROC);
	reg_write32(core->bus_set, TOP_SOUTH_1_DATA_RESET_PROC, reg | 0x100001);
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_1_CFG_RESET_PROC);
	reg_write32(core->bus_set, TOP_SOUTH_1_CFG_RESET_PROC, reg | 0x11);
	udelay(100);

	//step6: reset cpu root resetn
	reg_write32(core->bus_set, CPU_ROOT_RESETN, 0x10001);
	udelay(100);

	//step7; release mhr req
	reg = reg_read32(core->bus_set, TOP_SOUTH_1_DATA_MHR_REQ);
	reg_write32(core->bus_set, TOP_SOUTH_1_DATA_MHR_REQ, reg & (~0x01));
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_1_CFG_MHR_REQ);
	reg_write32(core->bus_set, TOP_SOUTH_1_CFG_MHR_REQ, reg & (~0x01));
	udelay(100);

	return 0;
}

int c50s_boot_pre(struct cn_core_set *core)
{

	unsigned int reg;
	unsigned int timeout = 0;

	//step1: raise data master and cfg master's mhr req
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_DATA_MHR_REQ);
	reg_write32(core->bus_set, TOP_SOUTH_0_DATA_MHR_REQ, reg | 0x01);
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_CFG_MHR_REQ);
	reg_write32(core->bus_set, TOP_SOUTH_0_CFG_MHR_REQ, reg | 0x01);
	udelay(100);

	//step2: wait mhr bus idle
	while (timeout < 1000) {
		if ((reg_read32(core->bus_set, TOP_SOUTH_0_DATA_MHR_IDLE) & 0x1) == 0x01 &&
		    (reg_read32(core->bus_set, TOP_SOUTH_0_CFG_MHR_IDLE) & 0x1) == 0x01)
			break;
		timeout++;
		udelay(100);
	}
	if (timeout >= 1000) {
		if ((reg_read32(core->bus_set, TOP_SOUTH_0_DATA_MHR_IDLE) & 0x1) != 0x1) {
			pr_err("Data Mhr Bus Busy! id :%#x", TOP_SOUTH_0_DATA_MHR_IDLE);
			pr_err("%#x != 0x1, please reset %s",
				reg_read32(core->bus_set, TOP_SOUTH_0_DATA_MHR_IDLE),
				core->core_name);
		}
		if ((reg_read32(core->bus_set, TOP_SOUTH_0_CFG_MHR_IDLE) & 0x1) != 0x1) {
			pr_err("Cfg Mhr Bus Busy! id :%#x", TOP_SOUTH_0_CFG_MHR_IDLE);
			pr_err("%#x != 0x1, please reset %s",
				reg_read32(core->bus_set, TOP_SOUTH_0_CFG_MHR_IDLE),
				core->core_name);
		}
		return -1;
	}
	udelay(100);

	//step3: open data mater, cfg_master, cfg_slave, acp_slave's reset protect
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_DATA_RESET_PROC);
	reg_write32(core->bus_set, TOP_SOUTH_0_DATA_RESET_PROC, reg & (~0x100001));
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_CFG_RESET_PROC);
	reg_write32(core->bus_set, TOP_SOUTH_0_CFG_RESET_PROC, reg & (~0x11));
	udelay(100);

	//step4: reset cpu_root_resetn
	reg_write32(core->bus_set, C50S_CPU_ROOT_RESETN, 0x10000);
	udelay(100);

	//step5:close reset protect
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_DATA_RESET_PROC);
	reg_write32(core->bus_set, TOP_SOUTH_0_DATA_RESET_PROC, reg | 0x100001);
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_CFG_RESET_PROC);
	reg_write32(core->bus_set, TOP_SOUTH_0_CFG_RESET_PROC, reg | 0x11);
	udelay(100);

	//step6: reset cpu root resetn
	reg_write32(core->bus_set, C50S_CPU_ROOT_RESETN, 0x10001);
	udelay(100);

	//step7; release mhr req
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_DATA_MHR_REQ);
	reg_write32(core->bus_set, TOP_SOUTH_0_DATA_MHR_REQ, reg & (~0x01));
	udelay(100);
	reg = reg_read32(core->bus_set, TOP_SOUTH_0_CFG_MHR_REQ);
	reg_write32(core->bus_set, TOP_SOUTH_0_CFG_MHR_REQ, reg & (~0x01));
	udelay(100);

	return 0;
}
