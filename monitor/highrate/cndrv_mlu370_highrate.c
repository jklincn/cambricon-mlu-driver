
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

struct axi_hubtrace_map_ipu_info mlu370_hubtrace_table[48] = {
	/*hub2 cluster 0 - 1*/
	{IPU_CLUSTER_0, IPU_CORE_0, 2, 8, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_1, 2, 9, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_2, 2, 10, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_3, 2, 11, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_0, 2, 12, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_1, 2, 13, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_2, 2, 14, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_3, 2, 15, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_4, 2, 16, IPU_MEMCORE},
	{IPU_CLUSTER_1, IPU_CORE_4, 2, 17, IPU_MEMCORE},
	/*hub3 cluster 2 - 3*/
	{IPU_CLUSTER_2, IPU_CORE_0, 3, 8, IPU_CORE},
	{IPU_CLUSTER_2, IPU_CORE_1, 3, 9, IPU_CORE},
	{IPU_CLUSTER_2, IPU_CORE_2, 3, 10, IPU_CORE},
	{IPU_CLUSTER_2, IPU_CORE_3, 3, 11, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_0, 3, 12, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_1, 3, 13, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_2, 3, 14, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_3, 3, 15, IPU_CORE},
	{IPU_CLUSTER_2, IPU_CORE_4, 3, 16, IPU_MEMCORE},
	{IPU_CLUSTER_3, IPU_CORE_4, 3, 17, IPU_MEMCORE},
	/*hub6 cluster 4 - 5*/
	{IPU_CLUSTER_4, IPU_CORE_0, 6, 8, IPU_CORE},
	{IPU_CLUSTER_4, IPU_CORE_1, 6, 9, IPU_CORE},
	{IPU_CLUSTER_4, IPU_CORE_2, 6, 10, IPU_CORE},
	{IPU_CLUSTER_4, IPU_CORE_3, 6, 11, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_0, 6, 12, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_1, 6, 13, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_2, 6, 14, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_3, 6, 15, IPU_CORE},
	{IPU_CLUSTER_4, IPU_CORE_4, 6, 16, IPU_MEMCORE},
	{IPU_CLUSTER_5, IPU_CORE_4, 6, 17, IPU_MEMCORE},
	/*hub7 cluster 6 - 7*/
	{IPU_CLUSTER_6, IPU_CORE_0, 7, 8, IPU_CORE},
	{IPU_CLUSTER_6, IPU_CORE_1, 7, 9, IPU_CORE},
	{IPU_CLUSTER_6, IPU_CORE_2, 7, 10, IPU_CORE},
	{IPU_CLUSTER_6, IPU_CORE_3, 7, 11, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_0, 7, 12, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_1, 7, 13, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_2, 7, 14, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_3, 7, 15, IPU_CORE},
	{IPU_CLUSTER_6, IPU_CORE_4, 7, 16, IPU_MEMCORE},
	{IPU_CLUSTER_7, IPU_CORE_4, 7, 17, IPU_MEMCORE},
};


int mlu370_pfmu_hubtrace_tab_len(void *mset)
{
	return sizeof(mlu370_hubtrace_table) / sizeof(struct axi_hubtrace_map_ipu_info);
}

int mlu370_pfmu_get_monitor_info_by_phyid(void *mset, int phy_cid, int core_id, int *table_index)
{
	int ret = -1;
	int i = 0;
	int len = 0;

	len = mlu370_pfmu_hubtrace_tab_len(mset);
	for (i = 0; i < len; i++) {
		if (mlu370_hubtrace_table[i].phy_cid == phy_cid && mlu370_hubtrace_table[i].core_id == core_id) {
			*table_index = i;
			ret = 0;
			break;
		}
	}
	return ret;
}

int mlu370_pfmu_ipu_map_info(void *mset, int phy_cid, int logic_cid, void *map_info)
{
	int ret = 0;
	int core_id = 0;
	struct monitor_pfmu_hubtrace_table *hubtrace_tab = map_info;
	int cur_item = hubtrace_tab->total_item;
	int index = 0;
	int table_index = 0;

	for (core_id = 0; core_id <= IPU_CORE_4; core_id++) {

		ret = mlu370_pfmu_get_monitor_info_by_phyid(mset, phy_cid, core_id, &table_index);
		if (ret) {
			cn_dev_err_limit("Invalid ipu cluster id\n");
			return ret;
		}
		index = cur_item + core_id;
		hubtrace_tab->l2p[index].ipu_core.core_id = core_id;
		hubtrace_tab->l2p[index].phy_cid = phy_cid;
		hubtrace_tab->l2p[index].logic_cid = logic_cid;
		hubtrace_tab->l2p[index].hub_id = mlu370_hubtrace_table[table_index].hub_id;
		hubtrace_tab->l2p[index].mon_id = mlu370_hubtrace_table[table_index].mon_id;
		hubtrace_tab->l2p[index].ipu_core.core_type = mlu370_hubtrace_table[table_index].core_type;
	}

	hubtrace_tab->total_item += core_id;

	return ret;
}

unsigned long common_copy_data_from_devbuf(
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

unsigned long dummy_flush_data(
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size)
{
	return 0;
}


int dummy_mem_mmap_kernel(void *context)
{
	return 0;
}

int dummy_mem_unmmap_kernel(void *context)
{
	return 0;
}

int mlu370_pfmu_hubtrace_l2p(struct cn_monitor_set *monitor_set, struct pfmu_hubtrace_l2p *l2p_info)
{
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

int mlu370_pfmu_hubtrace_map_info(void *mset, void *map_info)
{
	int i = 0;
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct monitor_pfmu_hubtrace_table *hubtrace_map = (struct monitor_pfmu_hubtrace_table *)map_info;
	u16 phy_cid = 0;
	struct pfmu_hubtrace_l2p hubtrace_l2p;

	memset(&hubtrace_l2p, 0, sizeof(struct pfmu_hubtrace_l2p));
	hubtrace_l2p.type = PFMU_IPU;
	ret = mlu370_pfmu_hubtrace_l2p(mset, &hubtrace_l2p);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "get ipu l2p table failed");
		return ret;
	}
	for (i = 0; i < hubtrace_l2p.cluster_num; i++) {
		phy_cid = hubtrace_l2p.l2p[i];
		ret = mlu370_pfmu_ipu_map_info(mset, phy_cid, i, hubtrace_map);
		if (ret) {
			cn_dev_monitor_err(monitor_set, "pfmu ipu map info failed");
			break;
		}
	}
	return ret;
}

int mlu370_dummy_res_tab_len(u32 res_type)
{
	return 0;
}

int mlu370_dummy_res_info(u32 res_type, void **info)
{
	*info = NULL;
	return 0;
}

struct cn_aximhub_data_parse_ops aximhub_common_parse_ops = {
	.copy_data_from_devbuf = common_copy_data_from_devbuf,
	.flush_data = dummy_flush_data,
	.pfmu_hubtrace_map_info = mlu370_pfmu_hubtrace_map_info,
	.pfmu_hubtrace_tab_len = mlu370_pfmu_hubtrace_tab_len,
	.mem_mmap_kernel = dummy_mem_mmap_kernel,
	.mem_unmmap_kernel = dummy_mem_unmmap_kernel,
	.monitor_res_tab_len = mlu370_dummy_res_tab_len,
	.monitor_res_info = mlu370_dummy_res_info,
};
