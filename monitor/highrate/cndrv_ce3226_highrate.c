
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

struct axi_hubtrace_map_ipu_info ce3226_hubtrace_table[4] = {
	/*hub0 cluster 0*/
	{IPU_CLUSTER_0, IPU_CORE_0, 0, 15, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_1, 0, 16, IPU_MEMCORE},
	/*hub2 cluster 1*/
	{IPU_CLUSTER_1, IPU_CORE_0, 2, 15, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_1, 2, 16, IPU_MEMCORE},
};

unsigned long ce3226_copy_data_from_devbuf(
		struct highrate_thread_context *thread_context,
		u64 start,
		u64 size)

{
	memcpy(thread_context->cache_buf, thread_context->dev_buff + start, size);

	return 0;
}

#if defined(CONFIG_CNDRV_CE3226_SOC)
extern int cn_mem_flush_cache(void *kva, u64 len);
unsigned long ce3226_flush_data(
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size)
{
	cn_mem_flush_cache((void *)thread_context->dev_buff + start, size);
	return 0;
}
#else
unsigned long ce3226_flush_data(
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size)
{
	return 0;
}
#endif

int ce3226_pfmu_hubtrace_tab_len(void *mset)
{
	return sizeof(ce3226_hubtrace_table) / sizeof(struct axi_hubtrace_map_ipu_info);
}

int ce3226_pfmu_get_monitor_info_by_phyid(void *mset, int phy_cid, int core_id, int *table_index)
{
	int ret = -1;
	int i = 0;
	int len = 0;

	len = ce3226_pfmu_hubtrace_tab_len(mset);

	for (i = 0; i < len; i++) {
		if (ce3226_hubtrace_table[i].phy_cid == phy_cid && ce3226_hubtrace_table[i].core_id == core_id) {
			*table_index = i;
			ret = 0;
			break;
		}
	}
	return ret;
}

int ce3226_pfmu_ipu_map_info(void *mset, int phy_cid, int logic_cid, void *map_info)
{
	int ret = 0;
	int core_id = 0;
	struct monitor_pfmu_hubtrace_table *hubtrace_tab = map_info;
	int cur_item = hubtrace_tab->total_item;
	int index = 0;
	int cur_index = 0;
	int table_index = 0;

	for (core_id = 0; core_id <= IPU_CORE_4; core_id++) {

		ret = ce3226_pfmu_get_monitor_info_by_phyid(mset, phy_cid, core_id, &table_index);
		if (ret) {
			continue;
		}
		index = cur_item + cur_index;
		hubtrace_tab->l2p[index].ipu_core.core_id = core_id;
		hubtrace_tab->l2p[index].phy_cid = phy_cid;
		hubtrace_tab->l2p[index].logic_cid = logic_cid;
		hubtrace_tab->l2p[index].hub_id = ce3226_hubtrace_table[table_index].hub_id;
		hubtrace_tab->l2p[index].mon_id = ce3226_hubtrace_table[table_index].mon_id;
		hubtrace_tab->l2p[index].ipu_core.core_type = ce3226_hubtrace_table[table_index].core_type;
		cur_index++;
	}
	hubtrace_tab->total_item += cur_index;

	return 0;
}

int ce3226_mem_mmap_kernel(void *context)
{
	int ret = 0;
	struct highrate_thread_context *thread_context = context;
	u64 kernel_va = 0;
	dev_addr_t dev_vaddr = thread_context->dev_vaddr;

	if (thread_context->dev_buff == NULL) {
		ret = cn_monitor_mem_mmap_kernel(dev_vaddr, &kernel_va, thread_context->dev_buff_size);
		if (!ret) {
			thread_context->dev_buff = (void *)kernel_va;
			memset((void *)kernel_va, 0x00, thread_context->dev_buff_size);
		}
	}
	return ret;
}

int ce3226_mem_unmmap_kernel(void *context)
{
	struct highrate_thread_context *thread_context = context;

	if (thread_context->dev_buff) {
		cn_monitor_mem_unmmap_kernel(thread_context->dev_vaddr,
									thread_context->dev_buff);
				thread_context->dev_buff = NULL;
	}
	return 0;
}

int ce3226_pfmu_hubtrace_l2p(struct cn_monitor_set *monitor_set, struct pfmu_hubtrace_l2p *l2p_info)
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

int ce3226_pfmu_hubtrace_map_info(void *mset, void *map_info)
{
	int i = 0;
	int ret = 0;
	struct cn_monitor_set *monitor_set = mset;
	struct monitor_pfmu_hubtrace_table *hubtrace_map = (struct monitor_pfmu_hubtrace_table *)map_info;
	u16 phy_cid = 0;
	struct pfmu_hubtrace_l2p hubtrace_l2p;

	memset(&hubtrace_l2p, 0, sizeof(struct pfmu_hubtrace_l2p));
	hubtrace_l2p.type = PFMU_IPU;
	ret = ce3226_pfmu_hubtrace_l2p(mset, &hubtrace_l2p);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "get ipu l2p table failed");
		return ret;
	}
	for (i = 0; i < hubtrace_l2p.cluster_num; i++) {
		phy_cid = hubtrace_l2p.l2p[i];
		ret = ce3226_pfmu_ipu_map_info(mset, phy_cid, i, hubtrace_map);
		if (ret) {
			cn_dev_monitor_err(monitor_set, "pfmu ipu map info failed");
			break;
		}
	}
	return ret;
}

int ce3226_dummy_res_tab_len(u32 res_type)
{
	return 0;
}

int ce3226_dummy_res_info(u32 res_type, void **info)
{
	*info = NULL;

	return 0;
}

struct cn_aximhub_data_parse_ops aximhub_ce3226_edge_parse_ops = {
	.copy_data_from_devbuf = ce3226_copy_data_from_devbuf,
	.flush_data = ce3226_flush_data,
	.pfmu_hubtrace_map_info = ce3226_pfmu_hubtrace_map_info,
	.pfmu_hubtrace_tab_len = ce3226_pfmu_hubtrace_tab_len,
	.mem_mmap_kernel = ce3226_mem_mmap_kernel,
	.mem_unmmap_kernel = ce3226_mem_unmmap_kernel,
	.monitor_res_tab_len = ce3226_dummy_res_tab_len,
	.monitor_res_info = ce3226_dummy_res_info,
};
