#include <linux/delay.h>
#include <linux/printk.h>

#include "cndrv_bus.h"
#include "cndrv_core.h"
#include "cpusys_ce3226.h"

extern void reg_write32(void *bus_set, unsigned long offset, u32 val);
extern u32 reg_read32(void *bus_set, unsigned long offset);

u64 reg_read64(void *bus_set, unsigned long offset)
{
	u64 hi, lo;

	lo = reg_read32(bus_set, offset);
	hi = reg_read32(bus_set, offset+4);
	return lo + (hi << 32);
}

void reg_write64(void *bus_set, unsigned long offset, u64 val)
{
	u32 hi, lo;

	hi = (val >> 32);
	lo = (val & 0xffffffff);
	reg_write32(bus_set, offset, lo);
	reg_write32(bus_set, offset+4, hi);
}

void regwrite32(void *bus_set, unsigned long offset, u32 val)
{
	uint32_t val_b;

	reg_write32(bus_set, offset, val);
	pr_info(">>> reg[0x%lx] val[0x%x]\n", offset, val);
	mdelay(100);
	val_b = reg_read32(bus_set, offset);
	pr_info("<<< reg[0x%lx] val[0x%x]\n", offset, val_b);
}

int ce3226_boot_pre(struct cn_core_set *core)
{
	int ret = 0;
	return ret;
}

int ce3226_cpu_boot(struct cn_core_set *core, uint64_t boot_entry)
{
	pr_info("\n#################################\n");
	pr_info("# ACPU boot, entry point 0x%llx\n", boot_entry);
	pr_info("###################################\n");

	/* de-assert all clock */
	regwrite32(core->bus_set, OTHERRSTCTRL0_ADDR, 0xffffffff);

	/* RST_CTRL assert */
	regwrite32(core->bus_set, RSTCTRL_ADDR, 0xffff0000);

	/* assign boot cpu reset address */
	regwrite32(core->bus_set, RVBADDR0_L, boot_entry);
	regwrite32(core->bus_set, RVBADDR0_H, boot_entry >> 32);
	regwrite32(core->bus_set, RVBADDR1_L, boot_entry);
	regwrite32(core->bus_set, RVBADDR1_H, boot_entry >> 32);

	/* peripheral address config */
	regwrite32(core->bus_set, ASTARTMP_ADDR, 0x80000);
	regwrite32(core->bus_set, AENDMP_ADDR, 0x800F0);

	/* FIXME: CBWBYPASS set 0 */
	regwrite32(core->bus_set, CBWBYPASS_ADDR, 0x30000);

	/* open clock */
	regwrite32(core->bus_set, CRGREGEN0_ADDR, 0x1ff01ff);
	regwrite32(core->bus_set, CRGREGEN1_ADDR, 0xfffffff);
	regwrite32(core->bus_set, CRGREGEN2_ADDR, 0x01ff01ff);

	/* BUSRST */
	regwrite32(core->bus_set, BUSRSTCTRL_ADDR, 0x0fff0fff);

	/* OTHER RESET */
	regwrite32(core->bus_set, OTHERRSTCTRL1_ADDR, 0xffffffff);

	/* cpu non-allocate on LLC */
	regwrite32(core->bus_set, CLUSTER_CACHE_M0_BYP_ADDR, 0x00ff00ff);
	regwrite32(core->bus_set, CLUSTER_AWCACHE_M0_ADDR, 0xffff2222);
	regwrite32(core->bus_set, CLUSTER_ARCACHE_M0_ADDR, 0xffff2222);
	regwrite32(core->bus_set, CLUSTER_CACHE_M1_BYP_ADDR, 0x00ff00ff);
	regwrite32(core->bus_set, CLUSTER_AWCACHE_M1_ADDR, 0xffff2222);
	regwrite32(core->bus_set, CLUSTER_ARCACHE_M1_ADDR, 0xffff2222);

	/* second de-assert cluster pro reset */
	regwrite32(core->bus_set, RSTCTRL_ADDR, 0x01000100);
	regwrite32(core->bus_set, RSTCTRL_ADDR, 0xf610f610);
	regwrite32(core->bus_set, RSTCTRL_ADDR, 0x08000800);
	regwrite32(core->bus_set, RSTCTRL_ADDR, 0x10001);

	pr_info("pc[0]lo = 0x%x\n", reg_read32(core->bus_set, 0x00600180));
	pr_info("pc[0]hi = 0x%x\n", reg_read32(core->bus_set, 0x00600184));
	pr_info("pc[0]lo = 0x%x\n", reg_read32(core->bus_set, 0x00600180));
	pr_info("pc[0]hi = 0x%x\n", reg_read32(core->bus_set, 0x00600184));
	return 0;
}
