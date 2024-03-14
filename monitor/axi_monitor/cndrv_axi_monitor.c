#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>


#include "cndrv_bus.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_monitor_usr.h"
#include "../monitor.h"
#include "cndrv_axi_monitor.h"
#include "../highrate/cndrv_monitor_highrate.h"
#include "../pmu_version/pmu_version.h"

void cndrv_config_axi_monitor(struct cn_monitor_set *monitor_set,
	struct cn_axi_monitor_config *config, u32 count)
{
	int i = 0;
	int j = 0;
	int k = 0;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;

	for (i = 0; i < count; i++) {
		atomic64_set(&axi_set[i].handle_index, 0);
		for (k = 0; k < ZONE_CONUT; k++) {
			atomic64_set(&axi_set[i].data_ref_cnt[k], 0);
		}

		axi_set[i].hub_id = i;
		axi_set[i].config = &config[i];
		axi_set[i].core = monitor_set->core;
		axi_set[i].irq = config[i].irq;
		axi_set[i].base = config[i].base;
		axi_set[i].monitor_num = config[i].monitor_num;
		axi_set[i].monitor_type_mask = config[i].axim_type_mask | config[i].pfmu_type_mask;
		axi_set[i].aximhub_intr_handle = config[i].aximhub_intr_handle;
		for (j = 0; j < config[i].monitor_num; j++) {
			axi_set[i].monitors_type[j] = RESERVED_MONITOR;

			if ((config[i].axim_type_mask >> j) & 0x1)
				axi_set[i].monitors_type[j] = AXI_MONITOR;

			if ((config[i].pfmu_type_mask >> j) & 0x1)
				axi_set[i].monitors_type[j] = IPU_PFMU;
		}

		axi_set[i].axi_monitor_count += bitmap_weight((unsigned long *)&config[i].axim_type_mask, 64);
		axi_set[i].ipu_pfmu_count += bitmap_weight((unsigned long *)&config[i].pfmu_type_mask, 64);
	}
}

void cndrv_axi_monitor_struct_default(void *conf)
{
	struct axi_monitor_config *mon_conf = (struct axi_monitor_config *)conf;
	mon_conf->monitor_id = 0;
	mon_conf->cross_bound_mode = AM_ERROR_OUTRANGE;
	mon_conf->match_mode = AM_ADDR_MATCH_MODE;
	//mon_conf->id_match_module = VPU_SYS_BEGIN;
	mon_conf->match_address_low = 0;
	mon_conf->match_address_high = 0xFFFFFFFFFFUL;
	mon_conf->user_match_read = 0;
	mon_conf->user_match_write = 0;
	mon_conf->user_match_read_mask = 0;
	mon_conf->user_match_write_mask = 0;
	mon_conf->timeout_threshold = 0x4000000;
	mon_conf->protect_addr_low = 0;
	mon_conf->protect_addr_high = 0xFFFFFFFFFFUL;
}

void cndrv_pmu_monitor_struct_default(void *conf)
{
	struct pmu_monitor_config *mon_conf = (struct pmu_monitor_config *)conf;

	mon_conf->monitor_id = 0;
	mon_conf->cross_bound_mode = AM_ERROR_OUTRANGE;
	mon_conf->match_mode = AM_ADDR_MATCH_MODE;
	//mon_conf->id_match_module = VPU_SYS_BEGIN;
	mon_conf->match_address_low = 0;
	mon_conf->match_address_high = 0xFFFFFFFFFFUL;
	mon_conf->user_match_read = 0;
	mon_conf->user_match_write = 0;
	mon_conf->user_match_read_mask = 0;
	mon_conf->user_match_write_mask = 0;
	mon_conf->timeout_threshold = 0x4000000;
	mon_conf->protect_addr_low = 0;
	mon_conf->protect_addr_high = 0xFFFFFFFFFFUL;
	mon_conf->data_mode = 0;
}

void cndrv_axi_monitor_config(struct cn_monitor_set *monitor_set)
{
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	switch (core->device_id) {
	case MLUID_270:
		mlu270_axi_monitor_config(monitor_set);
		break;
	case MLUID_220_EDGE:
	case MLUID_220:
		mlu220_axi_monitor_config(monitor_set);
		break;
	case MLUID_290:
		mlu290_axi_monitor_config(monitor_set);
		break;
	case MLUID_CE3226_EDGE:
	case MLUID_CE3226:
		ce3226_axi_monitor_config(monitor_set);
		break;
	case MLUID_370:
		mlu370_axi_monitor_config(monitor_set);
		break;
	case MLUID_590:
		mlu590_axi_monitor_config(monitor_set);
		break;
	case MLUID_580:
		mlu580_axi_monitor_config(monitor_set);
		break;
	case MLUID_PIGEON_EDGE:
	case MLUID_PIGEON:
		pigeon_axi_monitor_config(monitor_set);
		break;
	default:
		monitor_set->highrate_mode = AXI_MONITOR_NORMAL_MODE;
		break;
	}
}

int cndrv_axi_monitor_restart(void *mset)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)mset;

	cndrv_axi_monitor_config(monitor_set);

	return 0;
}

void cndrv_axi_monitor_stop(void *mset)
{
	//TODO
}

static int cn_monitor_register_aximhub_irq(void *aximon_set, int irq)
{
	struct cambr_amh_hub *axi_set = (struct cambr_amh_hub *)aximon_set;
	struct cn_core_set *core = axi_set->core;
	int ret = 0;

	if (core->device_id == MLUID_CE3226_EDGE ||
		core->device_id == MLUID_PIGEON_EDGE) {
		ret = request_irq(irq, axi_set->config->aximhub_intr_handle,
			IRQF_SHARED, CN_MON_MOD_NAME, (void *)(axi_set));
		if (ret) {
			cn_dev_err("register irq %d handler failed", irq);
			return ret;
		}
	} else {
		/* register interrupt */
		ret = cn_bus_register_interrupt(core->bus_set,
				irq,
				axi_set->config->aximhub_intr_handle,
				(void *)axi_set);
		if (ret) {
			cn_dev_err("register aximhub irq %d failed", irq);
			return ret;
		}

		/* enable irq */
		ret = cn_bus_enable_irq(core->bus_set, irq);
		if (ret) {
			cn_dev_err("enable aximhub irq %d failed", irq);
			return ret;
		}
	}

	axi_set->irq_enabled = 1;
	return 0;
}

static int cn_monitor_unregister_aximhub_irq(void *aximon_set, int irq)
{
	struct cambr_amh_hub *axi_set = (struct cambr_amh_hub *)aximon_set;
	struct cn_core_set *core = axi_set->core;

	axi_set->irq_enabled = 0;
	if (core->device_id == MLUID_CE3226_EDGE ||
		core->device_id == MLUID_PIGEON_EDGE) {
		free_irq(irq, aximon_set);
	} else {
		cn_bus_disable_irq(core->bus_set, irq);
		cn_bus_unregister_interrupt(core->bus_set, irq);
	}
	return 0;
}

int cndrv_axi_monitor_register_irq(void *mset)
{
	int i = 0;
	int ret = 0;
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)mset;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;

	/* Register irq for every hub */
	for (i = 0; i < monitor_set->hub_num; i++) {
		if (axi_set[i].aximhub_intr_handle) {
			ret = cn_monitor_register_aximhub_irq(&axi_set[i], axi_set[i].irq);
			if (ret) {
				cn_dev_monitor_err(monitor_set, "Axi monitor irq register fail.\n");
				goto over;
			}
		}
	}

	return 0;

over:
	/* Register irq failed */
	for (; i >= 0; i--)
		cn_monitor_unregister_aximhub_irq(&axi_set[i], axi_set[i].irq);

	return -EINVAL;
}


int cndrv_axi_monitor_unregister_irq(void *mset)
{
	int i = 0;
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)mset;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	/* Unregister irq */
	for (i = 0; i < monitor_set->hub_num; i++) {
		if (core->device_id == MLUID_CE3226_EDGE ||
			core->device_id == MLUID_PIGEON_EDGE) {
			disable_irq(axi_set[i].irq);
			free_irq(axi_set[i].irq, &axi_set[i]);
		} else {
			cn_bus_disable_irq(core->bus_set, axi_set[i].irq);
			cn_bus_unregister_interrupt(core->bus_set, axi_set[i].irq);
		}
		axi_set[i].irq_enabled = 0;
	}

	return 0;
}

int cndrv_axi_monitor_host_exit(void *mset)
{
	u32 hub_id = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct cambr_amh_hub *axi_set = NULL;
	struct cambr_amh_hub *hub_priv = NULL;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	axi_set = monitor_set->axi_set;
	if (IS_ERR_OR_NULL(axi_set))
		return -EINVAL;

	for (hub_id = 0; hub_id < monitor_set->hub_num; hub_id++) {
		hub_priv = &axi_set[hub_id];
		if (IS_ERR_OR_NULL(hub_priv)) {
			cn_dev_monitor_err(monitor_set, "Axi monitor invalid hub_priv.\n");
			continue;
		}
		hub_priv->opened_count = 0;
		memset(hub_priv->monitors, 0, hub_priv->config->monitor_num);
		hub_priv->start = 0;
		hub_priv->end = 0;
		hub_priv->opened_count = 0;
		hub_priv->loops = 0;
		hub_priv->pc = 0;
		hub_priv->status = 0;
		hub_priv->size = 0;
		hub_priv->inited = 0;
	}
	return 0;
}

int cndrv_axi_monitor_host_config(void *mset, struct monitor_direct_mode *highrate_mode)
{
	struct cn_monitor_set *monitor_set = mset;
	struct cambr_amh_hub *axi_set = NULL;
	struct cambr_amh_hub *hub_priv = NULL;

	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	axi_set = monitor_set->axi_set;
	if (IS_ERR_OR_NULL(axi_set))
		return -EINVAL;

	hub_priv = &axi_set[highrate_mode->hub_id];
	if (IS_ERR_OR_NULL(hub_priv))
		return -EINVAL;

	hub_priv->size = hub_priv->zone_size;
	hub_priv->start = 0;
	hub_priv->opened_count = 0;
	memset(hub_priv->monitors, 0, hub_priv->config->monitor_num);
	hub_priv->end = 0;
	hub_priv->opened_count = 0;
	hub_priv->pc = 0;
	hub_priv->status = 0;

	return 0;
}

int cndrv_axi_monitor_init(void *mset)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)mset;
	struct cambr_amh_hub *axi_set = NULL;
	struct cn_monitor_highrate_set *monitor_highrate_set = NULL;
	int ret = 0;
	int i = 0;

	cn_dev_monitor_debug(monitor_set, "AXI Monitor Init.");

	monitor_set->res_param = cn_kzalloc(sizeof(u64) * PMU_MAX_RES, GFP_KERNEL);
	if (!monitor_set->res_param) {
		cn_dev_monitor_debug(monitor_set, "alloc monitor resource error.");
		return -ENOMEM;
	}

	cndrv_axi_monitor_config(monitor_set);

	if (monitor_set->hub_num) {
		axi_set = cn_kzalloc(sizeof(struct cambr_amh_hub) * monitor_set->hub_num, GFP_KERNEL);
		if (!axi_set) {
			cn_dev_monitor_debug(monitor_set, "alloc axi_set error.");
			ret = -ENOMEM;
			goto err_res;
		}
	}

	monitor_set->axi_set = axi_set;

	cn_dev_monitor_info(monitor_set, "highrate mode %d", monitor_set->highrate_mode);

	if (monitor_set->config) {
		cndrv_config_axi_monitor(monitor_set, monitor_set->config, monitor_set->hub_num);
	}

	if (monitor_set->highrate_mode) {
		monitor_highrate_set = cn_kzalloc(sizeof(struct cn_monitor_highrate_set),
		GFP_KERNEL);
		if (!monitor_highrate_set) {
			cn_dev_monitor_debug(monitor_set, "alloc monitor d2h_set error.");
			ret = -ENOMEM;
			goto err_cambr_amh_hub;
		}
		monitor_set->monitor_highrate_set = monitor_highrate_set;

		ret = cndrv_axi_monitor_register_irq(monitor_set);
		if (ret) {
			cn_dev_monitor_err(monitor_set, "Axi monitor irq reg fail.");
			goto err_direct;
		}
		for (i = 0; i < monitor_set->hub_num; i++) {
			cndrv_axi_monitor_disable_irq(monitor_set, i);
		}
	}

	return 0;

err_direct:
	if (monitor_set->monitor_highrate_set) {
		cn_kfree(monitor_set->monitor_highrate_set);
		monitor_set->monitor_highrate_set = NULL;
	}
err_cambr_amh_hub:
	if (monitor_set->axi_set) {
		cn_kfree(monitor_set->axi_set);
		monitor_set->axi_set = NULL;
	}
err_res:
	if (monitor_set->res_param) {
		cn_kfree(monitor_set->res_param);
		monitor_set->res_param = NULL;
	}
	return ret;
}

void cndrv_axi_monitor_exit(void* mset)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)mset;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;

	cn_dev_monitor_debug(monitor_set, "AXI Monitor Exit.");

	if (axi_set) {
		cn_kfree(axi_set);
		monitor_set->axi_set = NULL;
	}

	if (monitor_set->monitor_highrate_set) {
		cn_kfree(monitor_set->monitor_highrate_set);
		monitor_set->monitor_highrate_set = NULL;
	}
	if (monitor_set->res_param) {
		cn_kfree(monitor_set->res_param);
		monitor_set->res_param = NULL;
	}
}

int cndrv_axi_monitor_disable_irq(void *mset, int hub_id)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)mset;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (axi_set[hub_id].irq_enabled) {
		/* disable irq */
		if (core->device_id == MLUID_CE3226_EDGE ||
			core->device_id == MLUID_PIGEON_EDGE) {
			disable_irq(axi_set[hub_id].irq);
		} else {
			cn_bus_disable_irq(core->bus_set, axi_set[hub_id].irq);
		}
		axi_set[hub_id].irq_enabled = 0;
	}

	return 0;
}

int cndrv_axi_monitor_enable_irq(void *mset, int hub_id)
{
	struct cn_monitor_set *monitor_set = (struct cn_monitor_set *)mset;
	struct cambr_amh_hub *axi_set = monitor_set->axi_set;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;

	if (!axi_set[hub_id].irq_enabled) {
		/* enable irq */
		if (core->device_id == MLUID_CE3226_EDGE ||
			core->device_id == MLUID_PIGEON_EDGE) {
			enable_irq(axi_set[hub_id].irq);
		} else {
			cn_bus_enable_irq(core->bus_set, axi_set[hub_id].irq);
		}
		axi_set[hub_id].irq_enabled = 1;
	}

	return 0;
}
