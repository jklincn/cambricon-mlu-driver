#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/platform_device.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_mcu.h"
#include "cndrv_attr_common.h"
#include "cndrv_attr_res.h"

const u32 ce3226_attr_info[CN_CE3226_MAX][INFO_TYPE_NUM] = {
	/* CE3226 */
	{QUAD_CNT1, UNION_PER_QUAD0, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* CE3226 D2D */
	{QUAD_CNT1, UNION_PER_QUAD0, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM2, 0},
	/* UNKNOWN */
	{QUAD_CNT1, UNION_PER_QUAD0, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
};

const u32 ce3226_attr_cap_info[ATTR_MAX_CAP][COMPUT_MAX] = {
	/* computing cap */
	/* major      minor */
	{ATTR_MAJOR3, ATTR_MINOR0,
	/* sparse         fp16          int4          int8          bf16          tf32 */
	ATTR_NOT_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT, ATTR_NOT_SUPPORT},
	/* heterogeneous cap */
	/* jpeg        h264          h265 */
	{ATTR_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT},
	/* elastic cap */
	/* isa       is multiple tensor processor */
	{ATTR_CE3226_ISA, ATTR_NOT_SUPPORT},
	/* memory cap */
	/* l1 cache        l2 cache          sharemem */
	{ATTR_NOT_SUPPORT, ATTR_NOT_SUPPORT, ATTR_NOT_SUPPORT},
};

void fill_computing_cap_ce3226(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_computing_cap *pcompute_cap = NULL;
	struct cndev_attr_set *attr_set = NULL;

	attr_set = core->attr_set;
	if (IS_ERR_OR_NULL(attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}

	pcompute_cap = &attr_set->attr_info.compute_cap;

	pcompute_cap->major = ce3226_attr_cap_info[ATTR_COMPUTING][COMPUT_MAJOR];
	pcompute_cap->minor = ce3226_attr_cap_info[ATTR_COMPUTING][COMPUT_MINOR];
	pcompute_cap->sparse = ce3226_attr_cap_info[ATTR_COMPUTING][COMPUT_SPARSE];
	pcompute_cap->fp16 = ce3226_attr_cap_info[ATTR_COMPUTING][COMPUT_FP16];
	pcompute_cap->int4 = ce3226_attr_cap_info[ATTR_COMPUTING][COMPUT_INT4];
	pcompute_cap->int8 = ce3226_attr_cap_info[ATTR_COMPUTING][COMPUT_INT8];
	pcompute_cap->bf16 = ce3226_attr_cap_info[ATTR_COMPUTING][COMPUT_BF16];
	pcompute_cap->tf32 = ce3226_attr_cap_info[ATTR_COMPUTING][COMPUT_TF32];

}

void fill_heterogeneous_cap_ce3226(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_heterogeneous_cap *pheterogeneous_cap	= NULL;
	int subtype = core->board_info.board_idx;
	struct cndev_attr_set *attr_set = NULL;

	attr_set = core->attr_set;
	if (IS_ERR_OR_NULL(attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}

	pheterogeneous_cap = &attr_set->attr_info.heterogeneous_cap;

	pheterogeneous_cap->max_queue = pboardi->max_queue;
	pheterogeneous_cap->max_notifier = pboardi->max_notifier;
	pheterogeneous_cap->queue_prio_support = pboardi->queue_prio_support;
	pheterogeneous_cap->tiny_core = ce3226_attr_info[subtype][TINY_CORE];
	pheterogeneous_cap->codec_jpeg = ce3226_attr_cap_info[ATTR_HETEROG][HETEROG_JPEG];
	pheterogeneous_cap->codec_h264 = ce3226_attr_cap_info[ATTR_HETEROG][HETEROG_H264];
	pheterogeneous_cap->codec_h265 = ce3226_attr_cap_info[ATTR_HETEROG][HETEROG_H265];
	pheterogeneous_cap->isp_core = 0;
}

void fill_elastic_cap_ce3226(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_elastic_cap *pelastic_cap = NULL;
	int subtype = core->board_info.board_idx;
	struct cndev_attr_set *attr_set = NULL;

	attr_set = core->attr_set;
	if (IS_ERR_OR_NULL(attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}

	pelastic_cap = &attr_set->attr_info.elastic_cap;

	pelastic_cap->max_dimx = pboardi->max_dimx;
	pelastic_cap->max_dimy = pboardi->max_dimy;
	pelastic_cap->max_dimz = pboardi->max_dimz;
	pelastic_cap->max_cluster_count_per_union_task = pboardi->kc_limit;
	pelastic_cap->o_max_cluster_count_per_union_task =
		ce3226_board_info[subtype][INFO_O_KC_LIMIT];

	pelastic_cap->max_cluster_count = pboardi->cluster_num;
	pelastic_cap->max_core_count_per_cluster = pboardi->ipu_core_num;
	pelastic_cap->max_quadrant_count = ce3226_attr_info[subtype][QUADRANDT_COUNT];
	pelastic_cap->max_union_type_per_quadrant = ce3226_attr_info[subtype][UNIONT_PER_QUADRANT];
	pelastic_cap->mlu_isa_version = ce3226_attr_cap_info[ATTR_ELASTIC][ELASTIC_ISA];
	pelastic_cap->is_multiple_tensor_processor = ce3226_attr_cap_info[ATTR_ELASTIC][ELASTIC_IS_MULT_TP];

}

void fill_memory_cap_ce3226(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_memory_cap *pmem_cap = NULL;
	int subtype = core->board_info.board_idx;
	struct cndev_attr_set *attr_set = NULL;

	attr_set = core->attr_set;
	if (IS_ERR_OR_NULL(attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}

	pmem_cap = &attr_set->attr_info.memory_cap;

	pmem_cap->max_l2_cache_size = ce3226_board_info[subtype][INFO_CACHE_SIZE];
	pmem_cap->total_const_mem_size = BYTES_TO_MB(pboardi->total_memory);
	pmem_cap->global_memory_node_count = pboardi->mem_channel;
	pmem_cap->cluster_l1_cache_support = ce3226_attr_cap_info[ATTR_MEMORY][MEM_CLUSTER_LI_CACHE];
	pmem_cap->max_persisting_l2_cache_size = ce3226_attr_info[subtype][ATTR_PERSIS_L2_CACHE];
	pmem_cap->max_shared_memory_size_per_union_task = ce3226_attr_cap_info[ATTR_MEMORY][MEM_MAX_SHARE_MEM];

}

void fill_hardware_cap_ce3226(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_hardware_cap *phard_cap = NULL;
	int subtype = core->board_info.board_idx;
	struct cndev_attr_set *attr_set = NULL;

	attr_set = core->attr_set;
	if (IS_ERR_OR_NULL(attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}

	phard_cap = &attr_set->attr_info.hardware_cap;

	pboardi->rated_ipu_freq = pboardi->rated_ipu_freq;
	phard_cap->ecc_support = ce3226_board_info[subtype][INFO_ECC_SUPPORT];
	phard_cap->cluster_clock_rate =
		ce3226_board_info[subtype][INFO_MAX_IPU_FREQ] * 1000;
	phard_cap->memory_clock_rate = pboardi->ddr_freq * 1000;
	phard_cap->bus_width = ce3226_board_info[subtype][INFO_BUS_WIDTH];
	phard_cap->global_memory_total_size = BYTES_TO_MB(pboardi->total_memory);
	phard_cap->mdr_memory_size = 0;

	phard_cap->pci_bus_id = 0;
	phard_cap->pci_device_id = 0;
	phard_cap->pci_domain_id = 0;
	phard_cap->pci_mps = 0;
	phard_cap->pci_mrrs = 0;
}

void fill_attribute_ce3226(struct cn_core_set *core)
{
	/* Computing Capabilities */
	fill_computing_cap_ce3226(core);

	/* Heterogeneous Capabilities */
	fill_heterogeneous_cap_ce3226(core);

	/* Elastic Capabilities */
	fill_elastic_cap_ce3226(core);

	/* Memory Capacities */
	fill_memory_cap_ce3226(core);

	/* Hardware Proterties */
	fill_hardware_cap_ce3226(core);
}
