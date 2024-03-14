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

struct axi_hubtrace_map_ipu_info mlu590_hubtrace_table[] = {
	/*hub4 cluster 0-1*/
	{IPU_CLUSTER_0, IPU_CORE_0, 4, 9, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_1, 4, 10, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_2, 4, 11, IPU_CORE},
	{IPU_CLUSTER_0, IPU_CORE_3, 4, 12, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_0, 4, 13, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_1, 4, 14, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_2, 4, 15, IPU_CORE},
	{IPU_CLUSTER_1, IPU_CORE_3, 4, 16, IPU_CORE},
	/*hub4 mem core*/
	{IPU_CLUSTER_0, IPU_CORE_4, 4, 17, IPU_MEMCORE},
	{IPU_CLUSTER_1, IPU_CORE_4, 4, 18, IPU_MEMCORE},

	/*hub4 cluster 4-5*/
	{IPU_CLUSTER_4, IPU_CORE_0, 4, 19, IPU_CORE},
	{IPU_CLUSTER_4, IPU_CORE_1, 4, 20, IPU_CORE},
	{IPU_CLUSTER_4, IPU_CORE_2, 4, 21, IPU_CORE},
	{IPU_CLUSTER_4, IPU_CORE_3, 4, 22, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_0, 4, 23, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_1, 4, 24, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_2, 4, 25, IPU_CORE},
	{IPU_CLUSTER_5, IPU_CORE_3, 4, 26, IPU_CORE},
	/*hub4 mem core*/
	{IPU_CLUSTER_4, IPU_CORE_4, 4, 27, IPU_MEMCORE},
	{IPU_CLUSTER_5, IPU_CORE_4, 4, 28, IPU_MEMCORE},

	/*hub5 cluster 8-9*/
	{IPU_CLUSTER_8, IPU_CORE_0, 5, 4, IPU_CORE},
	{IPU_CLUSTER_8, IPU_CORE_1, 5, 5, IPU_CORE},
	{IPU_CLUSTER_8, IPU_CORE_2, 5, 6, IPU_CORE},
	{IPU_CLUSTER_8, IPU_CORE_3, 5, 7, IPU_CORE},
	{IPU_CLUSTER_9, IPU_CORE_0, 5, 8, IPU_CORE},
	{IPU_CLUSTER_9, IPU_CORE_1, 5, 9, IPU_CORE},
	{IPU_CLUSTER_9, IPU_CORE_2, 5, 10, IPU_CORE},
	{IPU_CLUSTER_9, IPU_CORE_3, 5, 11, IPU_CORE},
	/*hub5 mem core*/
	{IPU_CLUSTER_8, IPU_CORE_4, 5, 12, IPU_MEMCORE},
	{IPU_CLUSTER_9, IPU_CORE_4, 5, 13, IPU_MEMCORE},

	/*hub6 cluster 2-3*/
	{IPU_CLUSTER_2, IPU_CORE_0, 6, 4, IPU_CORE},
	{IPU_CLUSTER_2, IPU_CORE_1, 6, 5, IPU_CORE},
	{IPU_CLUSTER_2, IPU_CORE_2, 6, 6, IPU_CORE},
	{IPU_CLUSTER_2, IPU_CORE_3, 6, 7, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_0, 6, 8, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_1, 6, 9, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_2, 6, 10, IPU_CORE},
	{IPU_CLUSTER_3, IPU_CORE_3, 6, 11, IPU_CORE},
	/*hub6 mem core*/
	{IPU_CLUSTER_2, IPU_CORE_4, 6, 12, IPU_MEMCORE},
	{IPU_CLUSTER_3, IPU_CORE_4, 6, 13, IPU_MEMCORE},

	/*hub7 cluster 6-7*/
	{IPU_CLUSTER_6, IPU_CORE_0, 7, 8, IPU_CORE},
	{IPU_CLUSTER_6, IPU_CORE_1, 7, 9, IPU_CORE},
	{IPU_CLUSTER_6, IPU_CORE_2, 7, 10, IPU_CORE},
	{IPU_CLUSTER_6, IPU_CORE_3, 7, 11, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_0, 7, 12, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_1, 7, 13, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_2, 7, 14, IPU_CORE},
	{IPU_CLUSTER_7, IPU_CORE_3, 7, 15, IPU_CORE},
	/*hub7 mem core*/
	{IPU_CLUSTER_6, IPU_CORE_4, 7, 16, IPU_MEMCORE},
	{IPU_CLUSTER_7, IPU_CORE_4, 7, 17, IPU_MEMCORE},
	/*hub7 cluster 10-11*/
	{IPU_CLUSTER_10, IPU_CORE_0, 7, 18, IPU_CORE},
	{IPU_CLUSTER_10, IPU_CORE_1, 7, 19, IPU_CORE},
	{IPU_CLUSTER_10, IPU_CORE_2, 7, 20, IPU_CORE},
	{IPU_CLUSTER_10, IPU_CORE_3, 7, 21, IPU_CORE},
	{IPU_CLUSTER_11, IPU_CORE_0, 7, 22, IPU_CORE},
	{IPU_CLUSTER_11, IPU_CORE_1, 7, 23, IPU_CORE},
	{IPU_CLUSTER_11, IPU_CORE_2, 7, 24, IPU_CORE},
	{IPU_CLUSTER_11, IPU_CORE_3, 7, 25, IPU_CORE},
	/*hub7 mem core*/
	{IPU_CLUSTER_10, IPU_CORE_4, 7, 26, IPU_MEMCORE},
	{IPU_CLUSTER_11, IPU_CORE_4, 7, 27, IPU_MEMCORE},

	/*tinycore*/
	/*hub2 tiny core*/
	{IPU_CLUSTER_12, IPU_CORE_0, 2, 34, TINYCORE},
	{IPU_CLUSTER_13, IPU_CORE_0, 2, 35, TINYCORE},
	/*hub3 tiny core*/
	{IPU_CLUSTER_16, IPU_CORE_0, 3, 34, TINYCORE},
	{IPU_CLUSTER_17, IPU_CORE_0, 3, 35, TINYCORE},
	/*hub8 tiny core*/
	{IPU_CLUSTER_14, IPU_CORE_0, 8, 13, TINYCORE},
	{IPU_CLUSTER_15, IPU_CORE_0, 8, 14, TINYCORE},
	{IPU_CLUSTER_18, IPU_CORE_0, 8, 15, TINYCORE},
	{IPU_CLUSTER_19, IPU_CORE_0, 8, 16, TINYCORE},
};

struct monitor_llc_mem mlu590_llc_mem_table[] = {
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

int mlu590_pfmu_hubtrace_tab_len(void *mset)
{
	return sizeof(mlu590_hubtrace_table) / sizeof(struct axi_hubtrace_map_ipu_info);
}

int mlu590_monitor_res_tab_len(u32 res_type)
{
	int res_tab_len = 0;

	switch (res_type) {
	case PMU_LLC_MEM:
		res_tab_len = sizeof(mlu590_llc_mem_table) / sizeof(struct monitor_llc_mem);
		break;
	default:
		break;
	}
	return res_tab_len;
}

int mlu590_monitor_res_info(u32 res_type, void **info)
{

	switch (res_type) {
	case PMU_LLC_MEM:
		*info = mlu590_llc_mem_table;
		break;
	default:
		*info = NULL;
		break;
	}
	return 0;
}

struct cn_aximhub_data_parse_ops aximhub_mlu590_parse_ops = {
	.copy_data_from_devbuf = mlu500_copy_data_from_devbuf,
	.flush_data = mlu500_dummy_flush_data,
	.pfmu_hubtrace_map_info = mlu500_pfmu_hubtrace_map_info,
	.pfmu_hubtrace_tab_len = mlu590_pfmu_hubtrace_tab_len,
	.mem_mmap_kernel = mlu500_dummy_mem_mmap_kernel,
	.mem_unmmap_kernel = mlu500_dummy_mem_unmmap_kernel,
	.monitor_res_tab_len = mlu590_monitor_res_tab_len,
	.monitor_res_info = mlu590_monitor_res_info,
};

