#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/platform_device.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_commu.h"
#include "cndrv_debug.h"
#include "camb_pmu_rpc.h"

#include "../monitor.h"
#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_monitor_highrate.h"
#include "cndrv_mlu500_highrate.h"

int mlu500_pfmu_get_monitor_info_by_phyid(void *mset, int phy_cid, int core_id, int *table_index)
{
	int ret = -1;
	int i = 0;
	int len = 0;
	struct cn_monitor_set *monitor_set = mset;

	len = cn_monitor_pfmu_hubtrace_tab_len(monitor_set);
	for (i = 0; i < len; i++) {
		if (monitor_set->mlu_hubtrace_table[i].phy_cid == phy_cid && monitor_set->mlu_hubtrace_table[i].core_id == core_id) {
			*table_index = i;
			ret = 0;
			break;
		}
	}
	return ret;
}

int mlu500_pfmu_ipu_map_info(void *mset, int phy_cid, int logic_cid, void *map_info)
{
	int ret = 0;
	int core_id = 0;
	struct monitor_pfmu_hubtrace_table *hubtrace_tab = map_info;
	int cur_item = hubtrace_tab->total_item;
	int index = 0;
	int cur_index = 0;
	int table_index = 0;
	struct cn_monitor_set *monitor_set = mset;

	for (core_id = 0; core_id <= IPU_CORE_4; core_id++) {

		ret = mlu500_pfmu_get_monitor_info_by_phyid(mset, phy_cid, core_id, &table_index);
		if (ret) {
			continue;
		}
		index = cur_item + cur_index;
		hubtrace_tab->l2p[index].ipu_core.core_id = core_id;
		hubtrace_tab->l2p[index].phy_cid = phy_cid;
		hubtrace_tab->l2p[index].logic_cid = logic_cid;
		hubtrace_tab->l2p[index].hub_id = monitor_set->mlu_hubtrace_table[table_index].hub_id;
		hubtrace_tab->l2p[index].mon_id = monitor_set->mlu_hubtrace_table[table_index].mon_id;
		hubtrace_tab->l2p[index].ipu_core.core_type = monitor_set->mlu_hubtrace_table[table_index].core_type;
		cur_index++;
	}
	hubtrace_tab->total_item += cur_index;

	return 0;
}

int mlu500_pfmu_tinycore_map_info(void *mset, int phy_cid, int logic_cid, int internal_phy_cid, 
									int smmu_group_id, void *map_info)
{
	int ret = 0;
	int core_id = 0;
	struct monitor_pfmu_hubtrace_table *hubtrace_tab = map_info;
	int cur_item = hubtrace_tab->total_item;
	int index = 0;
	int cur_index = 0;
	int table_index = 0;
	struct cn_monitor_set *monitor_set = mset;

	for (core_id = 0; core_id <= IPU_CORE_0; core_id++) {
		ret = mlu500_pfmu_get_monitor_info_by_phyid(mset, phy_cid, core_id, &table_index);
		if (ret) {
			continue;
		}
		index = cur_item + cur_index;
		hubtrace_tab->l2p[index].tiny_core.core_id = core_id;
		hubtrace_tab->l2p[index].phy_cid = phy_cid;
		hubtrace_tab->l2p[index].logic_cid = logic_cid;
		hubtrace_tab->l2p[index].hub_id = monitor_set->mlu_hubtrace_table[table_index].hub_id;
		hubtrace_tab->l2p[index].mon_id = monitor_set->mlu_hubtrace_table[table_index].mon_id;
		hubtrace_tab->l2p[index].tiny_core.core_type = monitor_set->mlu_hubtrace_table[table_index].core_type;
		hubtrace_tab->l2p[index].tiny_core.tinycore = internal_phy_cid;
		hubtrace_tab->l2p[index].tiny_core.smmu_group_id = smmu_group_id;
		cur_index++;
	}

	hubtrace_tab->total_item += cur_index;

	return 0;
}

int mlu500_pfmu_hubtrace_l2p(void *mset, struct pfmu_hubtrace_l2p *l2p_info)
{
	struct cn_monitor_set *monitor_set = mset;
	struct cn_core_set *core = (struct cn_core_set *)monitor_set->core;
	int ret = 0;
	int in_len = 0;
	struct pfmu_hubtrace_l2p info;

	memcpy(&info, l2p_info, sizeof(struct pfmu_hubtrace_l2p));
	ret = __pmu_call_rpc(core, monitor_set->endpoint,
				MON_GET_IPU_L2P_MAP,
				&info, sizeof(struct pfmu_hubtrace_l2p),
				l2p_info, &in_len, sizeof(struct pfmu_hubtrace_l2p));
	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "get ipu logic2phy commu failed");
		return ret;
	}
	if (l2p_info->ret) {
		cn_dev_monitor_err(monitor_set, "get pfmu logic2phy value failed");
		ret = l2p_info->ret;
	}

	return ret;
}

int mlu500_pfmu_hubtrace_map_info(void *mset, void *map_info)
{
	int i = 0;
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct monitor_pfmu_hubtrace_table *hubtrace_map = (struct monitor_pfmu_hubtrace_table *)map_info;
	u16 phy_cid = 0;
	u16 logic_cid = 0;
	u32 full_cluster_num = 0;
	struct pfmu_hubtrace_l2p hubtrace_l2p;

	memset(&hubtrace_l2p, 0, sizeof(struct pfmu_hubtrace_l2p));
	//ipu l2p
	hubtrace_l2p.type = PFMU_IPU;
	ret = mlu500_pfmu_hubtrace_l2p(mset, &hubtrace_l2p);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "get ipu l2p table failed");
		return ret;
	}
	for (i = 0; i < hubtrace_l2p.cluster_num; i++) {
		phy_cid = hubtrace_l2p.l2p[i];
		ret = mlu500_pfmu_ipu_map_info(mset, phy_cid, i, hubtrace_map);
		if (ret) {
			cn_dev_monitor_err(monitor_set, "pfmu ipu map info failed");
			break;
		}
	}
	full_cluster_num = hubtrace_l2p.full_cluster_num;
	memset(&hubtrace_l2p, 0, sizeof(struct pfmu_hubtrace_l2p));
	//tinycore l2p
	hubtrace_l2p.type = PFMU_TINYCORE;
	ret = mlu500_pfmu_hubtrace_l2p(mset, &hubtrace_l2p);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "get tinycore l2p table failed");
		return ret;
	}
	for (i = 0; i < hubtrace_l2p.cluster_num; i++) {
		phy_cid = hubtrace_l2p.l2p[i] + full_cluster_num;
		logic_cid = i + full_cluster_num;
		ret = mlu500_pfmu_tinycore_map_info(mset, phy_cid, logic_cid, hubtrace_l2p.l2p[i], i, hubtrace_map);
		if (ret) {
			cn_dev_monitor_err(monitor_set, "pfmu tinycore map info failed");
			break;
		}
	}
	return ret;
}

unsigned long mlu500_copy_data_from_devbuf(
		struct highrate_thread_context *thread_context,
		u64 start,
		u64 size)
{
	struct cn_monitor_set *monitor_set = NULL;
	unsigned long ret_size = 0;

	monitor_set = thread_context->monitor_set;
	if (IS_ERR_OR_NULL(monitor_set)) {
		cn_dev_err_limit("invalid monitor_set\n");
		return -ENOMEM;
	}

	ret_size = cn_bus_dma_kernel(monitor_set->core->bus_set, (unsigned long)thread_context->cache_buf,
			thread_context->dev_vaddr + start, size, DMA_D2H);
	return ret_size;
}

unsigned long mlu500_dummy_flush_data(
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size)
{
	return 0;
}

int mlu500_dummy_mem_mmap_kernel(void *context)
{
	return 0;
}

int mlu500_dummy_mem_unmmap_kernel(void *context)
{
	return 0;
}
