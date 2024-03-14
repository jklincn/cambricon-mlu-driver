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

struct axi_hubtrace_map_ipu_info mlu580_hubtrace_table[] = {
	/*hub2 cluster 0-1*/
	{IPU_CLUSTER_0, IPU_CORE_0, 2, 9, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_1, 2, 10, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_2, 2, 11, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_3, 2, 12, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_0, 2, 13, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_1, 2, 14, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_2, 2, 15, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_3, 2, 16, IPU_CORE},
	/*hub2 mem core*/
	{IPU_CLUSTER_0, IPU_CORE_4, 2, 17, IPU_MEMCORE},
	{IPU_CLUSTER_1, IPU_CORE_4, 2, 18, IPU_MEMCORE},

	/*hub2 cluster 4-5*/
	{IPU_CLUSTER_4, IPU_CORE_0, 2, 19, IPU_CORE},
	{IPU_CLUSTER_4, IPU_CORE_1, 2, 20, IPU_CORE},
	{IPU_CLUSTER_4, IPU_CORE_2, 2, 21, IPU_CORE},
	{IPU_CLUSTER_4, IPU_CORE_3, 2, 22, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_0, 2, 23, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_1, 2, 24, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_2, 2, 25, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_3, 2, 26, IPU_CORE},
	/*hub2 mem core*/
	{IPU_CLUSTER_4, IPU_CORE_4, 2, 27, IPU_MEMCORE},
	{IPU_CLUSTER_5, IPU_CORE_4, 2, 28, IPU_MEMCORE},

	/*hub3 cluster 8-9*/
	{IPU_CLUSTER_8, IPU_CORE_0, 3, 4, IPU_CORE},
	{IPU_CLUSTER_8, IPU_CORE_1, 3, 5, IPU_CORE},
	{IPU_CLUSTER_8, IPU_CORE_2, 3, 6, IPU_CORE},
	{IPU_CLUSTER_8, IPU_CORE_3, 3, 7, IPU_CORE},
	{IPU_CLUSTER_9, IPU_CORE_0, 3, 8, IPU_CORE},
	{IPU_CLUSTER_9, IPU_CORE_1, 3, 9, IPU_CORE},
	{IPU_CLUSTER_9, IPU_CORE_2, 3, 10, IPU_CORE},
	{IPU_CLUSTER_9, IPU_CORE_3, 3, 11, IPU_CORE},
	/*hub3 mem core*/
	{IPU_CLUSTER_8, IPU_CORE_4, 3, 12, IPU_MEMCORE},
	{IPU_CLUSTER_9, IPU_CORE_4, 3, 13, IPU_MEMCORE},

	/*hub4 cluster 2-3*/
	{IPU_CLUSTER_2, IPU_CORE_0, 4, 4, IPU_CORE},
	{IPU_CLUSTER_2, IPU_CORE_1, 4, 5, IPU_CORE},
	{IPU_CLUSTER_2, IPU_CORE_2, 4, 6, IPU_CORE},
	{IPU_CLUSTER_2, IPU_CORE_3, 4, 7, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_0, 4, 8, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_1, 4, 9, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_2, 4, 10, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_3, 4, 11, IPU_CORE},
	/*hub4 mem core*/
	{IPU_CLUSTER_2, IPU_CORE_4, 4, 12, IPU_MEMCORE},
	{IPU_CLUSTER_3, IPU_CORE_4, 4, 13, IPU_MEMCORE},

	/*hub5 cluster 6-7*/
	{IPU_CLUSTER_6, IPU_CORE_0, 5, 8, IPU_CORE},
	{IPU_CLUSTER_6, IPU_CORE_1, 5, 9, IPU_CORE},
	{IPU_CLUSTER_6, IPU_CORE_2, 5, 10, IPU_CORE},
	{IPU_CLUSTER_6, IPU_CORE_3, 5, 11, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_0, 5, 12, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_1, 5, 13, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_2, 5, 14, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_3, 5, 15, IPU_CORE},
	/*hub5 mem core*/
	{IPU_CLUSTER_6, IPU_CORE_4, 5, 16, IPU_MEMCORE},
	{IPU_CLUSTER_7, IPU_CORE_4, 5, 17, IPU_MEMCORE},
	/*hub5 cluster 10-11*/
	{IPU_CLUSTER_10, IPU_CORE_0, 5, 18, IPU_CORE},
	{IPU_CLUSTER_10, IPU_CORE_1, 5, 19, IPU_CORE},
	{IPU_CLUSTER_10, IPU_CORE_2, 5, 20, IPU_CORE},
	{IPU_CLUSTER_10, IPU_CORE_3, 5, 21, IPU_CORE},
	{IPU_CLUSTER_11, IPU_CORE_0, 5, 22, IPU_CORE},
	{IPU_CLUSTER_11, IPU_CORE_1, 5, 23, IPU_CORE},
	{IPU_CLUSTER_11, IPU_CORE_2, 5, 24, IPU_CORE},
	{IPU_CLUSTER_11, IPU_CORE_3, 5, 25, IPU_CORE},
	/*hub5 mem core*/
	{IPU_CLUSTER_10, IPU_CORE_4, 5, 26, IPU_MEMCORE},
	{IPU_CLUSTER_11, IPU_CORE_4, 5, 27, IPU_MEMCORE},

	/*tinycore*/
	/*hub0 tiny core*/
	{IPU_CLUSTER_12, IPU_CORE_0, 0, 6, TINYCORE},
};

struct monitor_llc_mem mlu580_llc_mem_table[] = {
	{LLC_ID(0), HBM_ID(0)},
	{LLC_ID(1), HBM_ID(0)},

	{LLC_ID(2), HBM_ID(2)},
	{LLC_ID(3), HBM_ID(2)},

	{LLC_ID(4), HBM_ID(1)},
	{LLC_ID(5), HBM_ID(1)},

	{LLC_ID(6), HBM_ID(4)},
	{LLC_ID(7), HBM_ID(4)},

	{LLC_ID(8), HBM_ID(3)},
	{LLC_ID(9), HBM_ID(3)},

	{LLC_ID(10), HBM_ID(5)},
	{LLC_ID(11), HBM_ID(5)},

};

int mlu580_pfmu_hubtrace_tab_len(void *mset)
{
	return sizeof(mlu580_hubtrace_table) / sizeof(struct axi_hubtrace_map_ipu_info);
}

int mlu580_monitor_res_tab_len(u32 res_type)
{
	int res_tab_len = 0;

	switch (res_type) {
	case PMU_LLC_MEM:
		res_tab_len = sizeof(mlu580_llc_mem_table) / sizeof(struct monitor_llc_mem);
		break;
	default:
		break;
	}
	return res_tab_len;
}

int mlu580_monitor_res_info(u32 res_type, void **info)
{
	int ret = 0;

	switch (res_type) {
	case PMU_LLC_MEM:
		*info = mlu580_llc_mem_table;
		break;
	default:
		*info = NULL;
		break;
	}

	return ret;
}

struct cn_aximhub_data_parse_ops aximhub_mlu580_parse_ops = {
	.copy_data_from_devbuf = mlu500_copy_data_from_devbuf,
	.flush_data = mlu500_dummy_flush_data,
	.pfmu_hubtrace_map_info = mlu500_pfmu_hubtrace_map_info,
	.pfmu_hubtrace_tab_len = mlu580_pfmu_hubtrace_tab_len,
	.mem_mmap_kernel = mlu500_dummy_mem_mmap_kernel,
	.mem_unmmap_kernel = mlu500_dummy_mem_unmmap_kernel,
	.monitor_res_tab_len = mlu580_monitor_res_tab_len,
	.monitor_res_info = mlu580_monitor_res_info,
};
