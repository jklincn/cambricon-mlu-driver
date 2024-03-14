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
#include "cndrv_ioctl.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"
#include "cndrv_mcu.h"
#include "cndrv_attr_common.h"
#include "cndrv_attr_res.h"

/* array to record each board model's information */
const u32 mlu220_attr_info[CN_MLU220_MAX][INFO_TYPE_NUM] = {
	/* MLU220_M2 */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* MLU220_EDGE */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* MLU220_EVB */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* CN_MLU220_M2i */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* CN_MLU220_M2RA */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* CN_MLU220_U.2 */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* CN_MLU220_M2t */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* CN_MLU220_SOM */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* CN_MLU220_MXM */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* CN_MLU220_MXMT */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
	/* UNKNOWN */
	{QUAD_CNT1, UNION_PER_QUAD1, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM1, 0},
};

const u32 mlu220_attr_cap_info[ATTR_MAX_CAP][COMPUT_MAX] = {
	/* computing cap */
	/* major      minor */
	{ATTR_MAJOR2, ATTR_MINOR0,
	/* sparse         fp16          int4          int8          bf16          tf32 */
	ATTR_NOT_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT, ATTR_NOT_SUPPORT, ATTR_NOT_SUPPORT},
	/* heterogeneous cap */
	/* jpeg        h264          h265 */
	{ATTR_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT},
	/* elastic cap */
	/* isa       is multiple tensor processor */
	{ATTR_MLU220_ISA, ATTR_SUPPORT},
	/* memory cap */
	/* l1 cache        l2 cache          sharemem */
	{ATTR_NOT_SUPPORT, ATTR_NOT_SUPPORT, ATTR_NOT_SUPPORT},
};

void fill_computing_cap_mlu220(void *pcore)
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
	pcompute_cap->major = mlu220_attr_cap_info[ATTR_COMPUTING][COMPUT_MAJOR];
	pcompute_cap->minor = mlu220_attr_cap_info[ATTR_COMPUTING][COMPUT_MINOR];
	pcompute_cap->sparse = mlu220_attr_cap_info[ATTR_COMPUTING][COMPUT_SPARSE];
	pcompute_cap->fp16 = mlu220_attr_cap_info[ATTR_COMPUTING][COMPUT_FP16];
	pcompute_cap->int4 = mlu220_attr_cap_info[ATTR_COMPUTING][COMPUT_INT4];
	pcompute_cap->int8 = mlu220_attr_cap_info[ATTR_COMPUTING][COMPUT_INT8];
	pcompute_cap->bf16 = mlu220_attr_cap_info[ATTR_COMPUTING][COMPUT_BF16];
	pcompute_cap->tf32 = mlu220_attr_cap_info[ATTR_COMPUTING][COMPUT_TF32];
}

void fill_heterogeneous_cap_mlu220(void *pcore)
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
	pheterogeneous_cap->tiny_core = mlu220_attr_info[subtype][TINY_CORE];
	pheterogeneous_cap->codec_jpeg = mlu220_attr_cap_info[ATTR_HETEROG][HETEROG_JPEG];
	pheterogeneous_cap->codec_h264 = mlu220_attr_cap_info[ATTR_HETEROG][HETEROG_H264];
	pheterogeneous_cap->codec_h265 = mlu220_attr_cap_info[ATTR_HETEROG][HETEROG_H265];
	pheterogeneous_cap->isp_core = 0;
}

void fill_elastic_cap_mlu220(void *pcore)
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
	pelastic_cap->max_cluster_count_per_union_task =
		mlu220_board_info[subtype][INFO_KC_LIMIT];
	pelastic_cap->o_max_cluster_count_per_union_task =
		mlu220_board_info[subtype][INFO_O_KC_LIMIT];
	pelastic_cap->max_cluster_count = pboardi->cluster_num;
	pelastic_cap->max_core_count_per_cluster = pboardi->ipu_core_num;
	pelastic_cap->max_quadrant_count = mlu220_attr_info[subtype][QUADRANDT_COUNT];
	pelastic_cap->max_union_type_per_quadrant = mlu220_attr_info[subtype][UNIONT_PER_QUADRANT];

	pelastic_cap->mlu_isa_version = mlu220_attr_cap_info[ATTR_ELASTIC][ELASTIC_ISA];
	pelastic_cap->is_multiple_tensor_processor = mlu220_attr_cap_info[ATTR_ELASTIC][ELASTIC_IS_MULT_TP];
}

void fill_memory_cap_mlu220(void *pcore)
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

	pmem_cap->max_l2_cache_size = mlu220_board_info[subtype][INFO_CACHE_SIZE];
	pmem_cap->total_const_mem_size = BYTES_TO_MB(pboardi->total_memory);
	pmem_cap->global_memory_node_count = pboardi->mem_channel;
	pmem_cap->cluster_l1_cache_support = mlu220_attr_cap_info[ATTR_MEMORY][MEM_CLUSTER_LI_CACHE];
	pmem_cap->max_persisting_l2_cache_size = mlu220_attr_info[subtype][ATTR_PERSIS_L2_CACHE];
	pmem_cap->max_shared_memory_size_per_union_task = mlu220_attr_cap_info[ATTR_MEMORY][MEM_MAX_SHARE_MEM];
}

void fill_hardware_cap_mlu220(void *pcore)
{
	struct bus_info_s bus_info;
	struct bar_info_s bar_info;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_hardware_cap *phard_cap = NULL;
	struct cndev_attr_set *attr_set = NULL;
	int subtype = core->board_info.board_idx;

	attr_set = core->attr_set;
	if (IS_ERR_OR_NULL(attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}

	phard_cap = &attr_set->attr_info.hardware_cap;

	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);

	memset(&bar_info, 0x0, sizeof(struct bar_info_s));
	cn_bus_get_bar_info(core->bus_set, &bar_info);

	phard_cap->ecc_support = mlu220_board_info[subtype][INFO_ECC_SUPPORT];
	phard_cap->cluster_clock_rate =
		mlu220_board_info[subtype][INFO_MAX_IPU_FREQ] * 1000;
	phard_cap->memory_clock_rate = pboardi->ddr_freq * 1000;
	phard_cap->bus_width = mlu220_board_info[subtype][INFO_BUS_WIDTH];
	phard_cap->global_memory_total_size = BYTES_TO_MB(pboardi->total_memory);
	phard_cap->mdr_memory_size =
		min(BYTES_TO_MB(bar_info.bar[4].bar_sz), phard_cap->global_memory_total_size);

	phard_cap->pci_bus_id = bus_info.info.pcie.bus_num;
	phard_cap->pci_device_id = bus_info.info.pcie.device_id;
	phard_cap->pci_domain_id = bus_info.info.pcie.domain_id;
}

void fill_attribute_mlu220(struct cn_core_set *core)
{
	/* Computing Capabilities */
	fill_computing_cap_mlu220(core);

	/* Heterogeneous Capabilities */
	fill_heterogeneous_cap_mlu220(core);

	/* Elastic Capabilities */
	fill_elastic_cap_mlu220(core);

	/* Memory Capacities */
	fill_memory_cap_mlu220(core);

	/* Hardware Proterties */
	fill_hardware_cap_mlu220(core);
}
