#include <linux/printk.h>
#include <linux/delay.h>

#include "cndrv_core.h"
#include "cndrv_boot.h"
#include "cndrv_mcu.h"

int boot_prepare(struct cn_core_set *core)
{
	int ret = 0;

	switch(core->device_id) {
	case MLUID_100:
		pr_err("[UNIMPLEMENT] C10 bringup\n");
		break;
	case MLUID_290:
		pr_info("Card[%d] MLU290 %s()\n", core->idx, __func__);
		ret = c20_boot_pre(core);
		if (ret < 0) {
			pr_err("Card[%d] boot_prepare failure\n", core->idx);
			return ret;
		}
		break;
	case MLUID_220:
		pr_info("Card[%d] MLU220 %s()\n", core->idx, __func__);
		ret = c20e_boot_pre(core);
		if (ret < 0) {
			pr_err("Card[%d] boot_prepare failure\n", core->idx);
			return ret;
		}
		break;
	case MLUID_270:
		pr_info("Card[%d] MLU270 %s()\n", core->idx, __func__);
		ret = c20l_asic_boot_pre(core);
		if (ret < 0) {
			pr_err("Card[%d] boot_prepare failure\n", core->idx);
			return ret;
		}
		break;
	case MLUID_370:
		pr_info("Card[%d] MLU370 %s()\n", core->idx, __func__);
		ret = c30s_boot_pre(core);
		if (ret < 0) {
			pr_err("Card[%d] boot_prepare failure\n", core->idx);
			return ret;
		}
		break;
	case MLUID_CE3226:
		pr_info("Card[%d] CE3226 %s()\n", core->idx, __func__);
		ret = ce3226_boot_pre(core);
		if (ret < 0) {
			pr_err("Card[%d] boot prepare failure\n", core->idx);
			pr_err("bus idle can not blocking-up, and normally stop\n");
			return ret;
		}
		break;
	case MLUID_PIGEON:
		pr_info("Card[%d] PIGEON %s()\n", core->idx, __func__);
		ret = pigeon_boot_pre(core);
		if (ret < 0) {
			pr_err("Card[%d] boot prepare failure\n", core->idx);
			pr_err("bus idle can not blocking-up, and normally stop\n");
			return ret;
		}
		break;
	case MLUID_580:
		pr_info("[%s] MLU500 %s()\n", core->core_name, __func__);
		ret = c50s_boot_pre(core);
		if (ret < 0) {
			pr_err("[%s] boot prepare failure\n", core->core_name);
			return ret;
		}
		break;
	case MLUID_590:
		pr_info("[%s] MLU500 %s()\n", core->core_name, __func__);
		if (core->board_info.noc_mode == NOC_MODE1) {
			ret = c50_boot_pre(core);
		} else {
			ret = c50_boot_pre_m2(core);
		}
		if (ret < 0) {
			pr_err("[%s] boot prepare failure\n", core->core_name);
			return ret;
		}
		break;
	default:
		pr_err("[FAIL] can not recognite hard platform\n");
		break;
	}
	return 0;
}

int bringup(struct cn_core_set *core, uint64_t boot_entry)
{
	switch (core->device_id) {
	case MLUID_100:
		pr_err("[UNIMPLEMENT] C10 %s()\n", __func__);
		break;
	case MLUID_290:
		pr_info("Card[%d] MLU290 %s()\n", core->idx, __func__);
		c20_cpu_boot(core, boot_entry);
		break;
	case MLUID_270:
		pr_info("Card[%d] MLU270 %s()\n", core->idx, __func__);
		c20l_asic_cpu_boot(core, boot_entry);
		break;
	case MLUID_220:
		pr_info("Card[%d] MLU220 %s()\n", core->idx, __func__);
		c20e_cpu_boot(core, boot_entry);
		break;
	case MLUID_370:
		pr_info("Card[%d] MLU370 %s()\n", core->idx, __func__);
		c30s_cpu_boot(core, boot_entry);
		break;
	case MLUID_CE3226:
		pr_info("Card[%d] CE3226 %s()\n", core->idx, __func__);
		ce3226_cpu_boot(core, boot_entry);
		break;
	case MLUID_PIGEON:
		pr_info("Card[%d] PIGEON %s()\n", core->idx, __func__);
		pigeon_cpu_boot(core, boot_entry);
		break;
	case MLUID_580:
	case MLUID_590:
		pr_info("[%s] MLU500 %s()\n", core->core_name, __func__);
		c50_cpu_boot(core, boot_entry);
		break;
	default:
		pr_err("[FAIL] can not recognite hard platform\n");
		break;
	}

	return 0;
}

int shutdown(struct cn_core_set *core)
{
	int ret = 0;
	if (cn_core_is_vf(core))
		return 0;

	switch (core->device_id) {
	case MLUID_100:
		pr_err("[UNIMPLEMENT] C10 close\n");
		break;
	case MLUID_290:
		ret = c20_boot_pre(core);
		if (ret < 0) {
			pr_err("arm-close failure, bus idle can not blocking-up, and normally stop\n");
			return ret;
		}
		break;
	case MLUID_270:
		pr_info(">>> this is C20L asic platform\n");
		ret = c20l_asic_boot_pre(core);
		if (ret < 0) {
			pr_err("arm-close failure, bus idle can not blocking-up, and normally stop\n");
			return ret;
		}
		break;
	case MLUID_220:
		pr_info(">>> this is C20E asic platform\n");
		ret = c20e_boot_pre(core);
		if (ret < 0) {
			pr_err("arm-close failure, bus idle can not bocking-up, and normally stop\n");
			return ret;
		}
		break;
	case MLUID_370:
		ret = c30s_boot_pre(core);
		if (ret < 0) {
			pr_err("arm-close failure, bus idle can not blocking-up, and normally stop\n");
			return ret;
		}
		break;
	case MLUID_CE3226:
		pr_info(">>> this is CE3226 platform\n");
		ret = ce3226_boot_pre(core);
		if (ret < 0) {
			pr_err("boot_prepare failure, bus idle can not blocking-up, and normally stop\n");
			return ret;
		}
		break;
	case MLUID_PIGEON:
		pr_info(">>> this is PIGEON platform\n");
		ret = pigeon_boot_pre(core);
		if (ret < 0) {
			pr_err("boot_prepare failure, bus idle can not blocking-up, and normally stop\n");
			return ret;
		}
		break;
	case MLUID_580:
		ret = c50s_boot_pre(core);
		if (ret < 0) {
			pr_err("arm-close failure, bus idle can not blocking-up, and normally stop\n");
			return ret;
		}
		break;
	case MLUID_590:
		if (core->board_info.noc_mode == NOC_MODE1) {
			ret = c50_boot_pre(core);
		} else {
			ret = c50_boot_pre_m2(core);
		}
		if (ret < 0) {
			pr_err("arm-close failure, bus idle can not blocking-up, and normally stop\n");
			return ret;
		}
		break;
	default:
		pr_err("[FAIL] can not recognite hard platform\n");
		break;
	}

	return 0;
}
