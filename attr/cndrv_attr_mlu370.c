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
#include "cndrv_sbts.h"
#include "cndrv_attr_common.h"
#include "cndrv_attr_res.h"

#define MLU370_VF_TABLE_BASE 0x50

/* array to record each board type attribute information */
const u32 mlu370_attr_info[CN_MLU370_MAX][ATTR_TYPE_NUM] = {
	/* MLU370_EVB_D */
	{QUAD_CNT2, UNION_PER_QUAD4, ATTR_SUPPORT, MAX_CLUSTER_NUM8, 0},
	/* MLU370_EVB_S */
	{QUAD_CNT1, UNION_PER_QUAD4, ATTR_SUPPORT, MAX_CLUSTER_NUM4, 0},
	/* MLU370_X4L */
	{QUAD_CNT2, UNION_PER_QUAD4, ATTR_SUPPORT, MAX_CLUSTER_NUM8, 0},
	/* MLU370_S4 */
	{QUAD_CNT2, UNION_PER_QUAD2, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM6, 0},
	/* MLU370_X8 */
	{QUAD_CNT2, UNION_PER_QUAD2, ATTR_SUPPORT, MAX_CLUSTER_NUM4, 0},
	/* MLU370_M8 */
	{QUAD_CNT2, UNION_PER_QUAD4, ATTR_SUPPORT, MAX_CLUSTER_NUM8, 0},
	/* MLU365_D2 */
	{QUAD_CNT1, UNION_PER_QUAD2, ATTR_NOT_SUPPORT, MAX_CLUSTER_NUM2, 0},
	/* MLU370_X4 */
	{QUAD_CNT2, UNION_PER_QUAD4, ATTR_SUPPORT, MAX_CLUSTER_NUM8, 0},
	/* MLU370_M83U */
	{QUAD_CNT2, UNION_PER_QUAD4, ATTR_SUPPORT, MAX_CLUSTER_NUM8, 0},
	/* MLU370_X4K */
	{QUAD_CNT2, UNION_PER_QUAD4, ATTR_SUPPORT, MAX_CLUSTER_NUM8, 0},
	/* MLU370-VF */
	{QUAD_CNT2, UNION_PER_QUAD4, ATTR_SUPPORT, MAX_CLUSTER_NUM4, 0},
	/* MLU370-UNKNOWN */
	{QUAD_CNT2, UNION_PER_QUAD4, ATTR_SUPPORT, MAX_CLUSTER_NUM4, 0},
};

const u32 mlu370_attr_cap_info[ATTR_MAX_CAP][COMPUT_MAX] = {
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
	{ATTR_MLU370_ISA, ATTR_SUPPORT},
	/* memory cap */
	/* l1 cache        l2 cache          sharemem */
	{ATTR_NOT_SUPPORT, ATTR_NOT_SUPPORT, ATTR_NOT_SUPPORT},
};

const u32 mlu370_board_vf_info[BOARD_VF_NUM] = {
	/* ipu core num */
	IPUCORE_NUM4,
	/* ddr freq */
	DDR_FREQ3200
};

const u32 mlu370_vf_index_table[] = {
	CN_MLU370_EVB_D,
	CN_MLU370_EVB_S,
	CN_MLU370_X4L,
	CN_MLU370_S4,
	CN_MLU370_X8,
	CN_MLU370_M8,
	CN_MLU365_D2,
	CN_MLU370_X4,
	CN_MLU370_M83U,
	CN_MLU370_X4K,
	CN_MLU370_VF,
	CN_MLU370_UNKNOWN_TYPE,
	CN_MLU370_MAX,
};

void fill_computing_cap_mlu370(void *pcore)
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

	pcompute_cap->major = mlu370_attr_cap_info[ATTR_COMPUTING][COMPUT_MAJOR];
	pcompute_cap->minor = mlu370_attr_cap_info[ATTR_COMPUTING][COMPUT_MINOR];
	pcompute_cap->sparse = mlu370_attr_cap_info[ATTR_COMPUTING][COMPUT_SPARSE];
	pcompute_cap->fp16 = mlu370_attr_cap_info[ATTR_COMPUTING][COMPUT_FP16];
	pcompute_cap->int4 = mlu370_attr_cap_info[ATTR_COMPUTING][COMPUT_INT4];
	pcompute_cap->int8 = mlu370_attr_cap_info[ATTR_COMPUTING][COMPUT_INT8];
	pcompute_cap->bf16 = mlu370_attr_cap_info[ATTR_COMPUTING][COMPUT_BF16];
	pcompute_cap->tf32 = mlu370_attr_cap_info[ATTR_COMPUTING][COMPUT_TF32];
}

void fill_heterogeneous_cap_mlu370(void *pcore)
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
	pheterogeneous_cap->codec_jpeg =
		mlu370_attr_cap_info[ATTR_HETEROG][HETEROG_JPEG];
	pheterogeneous_cap->codec_h264 =
		mlu370_attr_cap_info[ATTR_HETEROG][HETEROG_H264];
	pheterogeneous_cap->codec_h265 =
		mlu370_attr_cap_info[ATTR_HETEROG][HETEROG_H265];

	pheterogeneous_cap->tiny_core =
		mlu370_attr_info[subtype][TINY_CORE];
	pheterogeneous_cap->isp_core = 0;
}

void fill_elastic_cap_mlu370(void *pcore)
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
		mlu370_board_info[subtype][INFO_KC_LIMIT];
	pelastic_cap->o_max_cluster_count_per_union_task =
		mlu370_board_info[subtype][INFO_O_KC_LIMIT];
	pboardi->cluster_num =
		mlu370_attr_info[subtype][ATTR_CLUSTER_NUM];
	pelastic_cap->max_cluster_count = pboardi->cluster_num;
	pelastic_cap->max_core_count_per_cluster = pboardi->ipu_core_num;
	pelastic_cap->max_quadrant_count =
		mlu370_attr_info[subtype][QUADRANDT_COUNT];
	pelastic_cap->max_union_type_per_quadrant =
		mlu370_attr_info[subtype][UNIONT_PER_QUADRANT];
	pelastic_cap->mlu_isa_version =
		mlu370_attr_cap_info[ATTR_ELASTIC][ELASTIC_ISA];
	pelastic_cap->is_multiple_tensor_processor =
		mlu370_attr_cap_info[ATTR_ELASTIC][ELASTIC_IS_MULT_TP];
}

void fill_memory_cap_mlu370(void *pcore)
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

	pmem_cap->max_l2_cache_size =
		mlu370_board_info[subtype][INFO_CACHE_SIZE];
	pmem_cap->total_const_mem_size =
		BYTES_TO_MB(pboardi->total_memory);
	pmem_cap->global_memory_node_count =
		pboardi->mem_channel;
	pmem_cap->cluster_l1_cache_support =
		mlu370_attr_cap_info[ATTR_MEMORY][MEM_CLUSTER_LI_CACHE];
	pmem_cap->max_persisting_l2_cache_size =
		mlu370_attr_info[subtype][ATTR_PERSIS_L2_CACHE];
	pmem_cap->max_shared_memory_size_per_union_task =
		mlu370_attr_cap_info[ATTR_MEMORY][MEM_MAX_SHARE_MEM];
}

void fill_hardware_cap_mlu370(void *pcore)
{
	struct bus_info_s bus_info;
	struct bar_info_s bar_info;
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

	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);

	memset(&bar_info, 0x0, sizeof(struct bar_info_s));
	cn_bus_get_bar_info(core->bus_set, &bar_info);

	phard_cap->ecc_support = core->ile_en;
	phard_cap->cluster_clock_rate =
		mlu370_board_info[subtype][INFO_MAX_IPU_FREQ] * 1000;
	phard_cap->memory_clock_rate = pboardi->ddr_freq * 1000;
	phard_cap->bus_width = mlu370_board_info[subtype][INFO_BUS_WIDTH];
	phard_cap->global_memory_total_size = BYTES_TO_MB(pboardi->total_memory);
	phard_cap->mdr_memory_size =
		min(BYTES_TO_MB(bar_info.bar[4].bar_sz), phard_cap->global_memory_total_size);

	phard_cap->pci_bus_id = bus_info.info.pcie.bus_num;
	phard_cap->pci_device_id = bus_info.info.pcie.device_id;
	phard_cap->pci_domain_id = bus_info.info.pcie.domain_id;
	phard_cap->pci_mps = bus_info.info.pcie.mps;
	phard_cap->pci_mrrs = bus_info.info.pcie.mrrs;
}

void fill_boardinfo_mlu370_vf(struct cn_core_set *core)
{
	struct cn_board_info *pboardi = &core->board_info;
	int board_idx = 0;
	int subtype = 0;

	subtype = ((pboardi->serial_num >> 40) & 0xff) - MLU370_VF_TABLE_BASE;
	if (subtype >= CN_MLU370_MAX || subtype < 0)
		subtype = CN_MLU370_VF;

	board_idx = mlu370_vf_index_table[subtype];
	pboardi->ecc_support = core->ile_en;
	pboardi->stack_size = mlu370_board_info[board_idx][INFO_STACK_SIZE];
	pboardi->sram_size = mlu370_board_info[board_idx][INFO_SRAM_SIZE];
	pboardi->rated_ipu_freq = mlu370_board_info[board_idx][INFO_MAX_IPU_FREQ];
	pboardi->ipu_core_num = mlu370_board_vf_info[ATTR_IPU_CORE];
	pboardi->ddr_freq = mlu370_board_vf_info[ATTR_DDR_FREQ];
}

void fill_attribute_mlu370(struct cn_core_set *core)
{
	/* Computing Capabilities */
	fill_computing_cap_mlu370(core);

	/* Heterogeneous Capabilities */
	fill_heterogeneous_cap_mlu370(core);

	/* Elastic Capabilities */
	fill_elastic_cap_mlu370(core);

	/* Memory Capacities */
	fill_memory_cap_mlu370(core);

	/* Hardware Proterties */
	fill_hardware_cap_mlu370(core);
}

void fill_elastic_cap_mlu370_vf(struct cn_core_set *core)
{
	struct cn_elastic_cap *pelastic_cap = NULL;
	struct cndev_attr_set *attr_set = NULL;

	attr_set = core->attr_set;
	if (IS_ERR_OR_NULL(attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}

	pelastic_cap = &attr_set->attr_info.elastic_cap;
	if (attr_set->fill_ops->fill_elastic_vf)
		attr_set->fill_ops->fill_elastic_vf(core);

	pelastic_cap->mlu_isa_version = mlu370_attr_cap_info[ATTR_ELASTIC][ELASTIC_ISA];
	pelastic_cap->is_multiple_tensor_processor = mlu370_attr_cap_info[ATTR_ELASTIC][ELASTIC_IS_MULT_TP];
}

void fill_attribute_mlu370_vf(struct cn_core_set *core)
{
	struct cndev_attr_set *attr_set = core->attr_set;

	if (IS_ERR_OR_NULL(attr_set->fill_ops)) {
		cn_dev_core_err(core, "attribute fill_ops is null");
		return;
	}
	/* Computing Capabilities */
	fill_computing_cap_mlu370(core);

	/* Heterogeneous Capabilities */
	if (attr_set->fill_ops->fill_heterogeneous_vf)
		attr_set->fill_ops->fill_heterogeneous_vf(core);

	/* Elastic Capabilities */
	fill_elastic_cap_mlu370_vf(core);

	/* Memory Capacities */
	if (attr_set->fill_ops->fill_memory_vf)
		attr_set->fill_ops->fill_memory_vf(core);

	/* Hardware Proterties */
	if (attr_set->fill_ops->fill_hardware_vf)
		attr_set->fill_ops->fill_hardware_vf(core);
}
