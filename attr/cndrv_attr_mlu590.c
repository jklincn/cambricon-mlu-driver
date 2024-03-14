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
#include "cndrv_domain.h"
#include "cndrv_attr_res.h"

const u32 mlu590_attr_info[CN_MLU590_MAX][ATTR_TYPE_NUM] = {
	/* MLU585 */
	{QUAD_CNT1, UNION_PER_QUAD8, ATTR_SUPPORT, MAX_CLUSTER_NUM8, 0x600000},
	/* MLU590-H8 */
	{QUAD_CNT1, UNION_PER_QUAD8, ATTR_SUPPORT, MAX_CLUSTER_NUM12, 0x600000},
	/* MLU590-M9 */
	{QUAD_CNT1, UNION_PER_QUAD8, ATTR_SUPPORT, MAX_CLUSTER_NUM12, 0x600000},
	/* MLU590-M9U */
	{QUAD_CNT1, UNION_PER_QUAD8, ATTR_SUPPORT, MAX_CLUSTER_NUM12, 0x600000},
	/* MLU590-M9L */
	{QUAD_CNT1, UNION_PER_QUAD8, ATTR_SUPPORT, MAX_CLUSTER_NUM12, 0x600000},
	/* MLU585 */
	{QUAD_CNT1, UNION_PER_QUAD8, ATTR_SUPPORT, MAX_CLUSTER_NUM10, 0x600000},
	/* MLU590-M9B */
	{QUAD_CNT1, UNION_PER_QUAD8, ATTR_SUPPORT, MAX_CLUSTER_NUM12, 0x600000},
	/* MLU590-M9C */
	{QUAD_CNT1, UNION_PER_QUAD8, ATTR_SUPPORT, MAX_CLUSTER_NUM10, 0x600000},
	/* MLU590_VF */
	{QUAD_CNT1, UNION_PER_QUAD8, ATTR_SUPPORT, MAX_CLUSTER_NUM12, 0x600000},
	/* UNKNOWN */
	{QUAD_CNT1, UNION_PER_QUAD8, ATTR_SUPPORT, MAX_CLUSTER_NUM12, 0x600000},
};

const u32 mlu590_attr_cap_info[ATTR_MAX_CAP][COMPUT_MAX] = {
	/* computing cap */
	/* major      minor */
	{ATTR_MAJOR5, ATTR_MINOR0,
	/* sparse     fp16          int4          int8          bf16          tf32 */
	ATTR_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT},
	/* heterogeneous cap */
	/* jpeg        h264          h265 */
	{ATTR_SUPPORT, ATTR_SUPPORT, ATTR_SUPPORT},
	/* elastic cap */
	/* isa       is multiple tensor processor */
	{ATTR_MLU590_ISA, ATTR_SUPPORT},
	/* memory cap */
	/* l1 cache 256KB   l2 cache      sharemem */
	{0x40000, ATTR_SUPPORT, ATTR_NOT_SUPPORT},
};

const u32 mlu590_board_vf_info[BOARD_VF_NUM] = {
	/* ipu core num */
	IPUCORE_NUM4,
	/* ddr freq */
	DDR_FREQ1600
};

void fill_computing_cap_mlu590(void *pcore)
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
	pcompute_cap->major = mlu590_attr_cap_info[ATTR_COMPUTING][COMPUT_MAJOR];
	pcompute_cap->minor = mlu590_attr_cap_info[ATTR_COMPUTING][COMPUT_MINOR];
	pcompute_cap->sparse = mlu590_attr_cap_info[ATTR_COMPUTING][COMPUT_SPARSE];
	pcompute_cap->fp16 = mlu590_attr_cap_info[ATTR_COMPUTING][COMPUT_FP16];
	pcompute_cap->int4 = mlu590_attr_cap_info[ATTR_COMPUTING][COMPUT_INT4];
	pcompute_cap->int8 = mlu590_attr_cap_info[ATTR_COMPUTING][COMPUT_INT8];
	pcompute_cap->bf16 = mlu590_attr_cap_info[ATTR_COMPUTING][COMPUT_BF16];
	pcompute_cap->tf32 = mlu590_attr_cap_info[ATTR_COMPUTING][COMPUT_TF32];

}

void fill_heterogeneous_cap_mlu590(void *pcore)
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
	pheterogeneous_cap->tiny_core = mlu590_attr_info[subtype][TINY_CORE];
	pheterogeneous_cap->codec_jpeg = mlu590_attr_cap_info[ATTR_HETEROG][HETEROG_JPEG];
	pheterogeneous_cap->codec_h264 = mlu590_attr_cap_info[ATTR_HETEROG][HETEROG_H264];
	pheterogeneous_cap->codec_h265 = mlu590_attr_cap_info[ATTR_HETEROG][HETEROG_H265];
	pheterogeneous_cap->isp_core = 0;
}

void fill_elastic_cap_mlu590(void *pcore)
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
		mlu590_board_info[subtype][INFO_KC_LIMIT];
	pelastic_cap->o_max_cluster_count_per_union_task =
		mlu590_board_info[subtype][INFO_O_KC_LIMIT];
	pelastic_cap->max_cluster_count = pboardi->cluster_num;
	pelastic_cap->max_core_count_per_cluster = pboardi->ipu_core_num;
	pelastic_cap->max_quadrant_count =
		mlu590_attr_info[subtype][QUADRANDT_COUNT];
	pelastic_cap->max_union_type_per_quadrant =
		mlu590_attr_info[subtype][UNIONT_PER_QUADRANT];
	pelastic_cap->mlu_isa_version =
		mlu590_attr_cap_info[ATTR_ELASTIC][ELASTIC_ISA];
	pelastic_cap->is_multiple_tensor_processor =
		mlu590_attr_cap_info[ATTR_ELASTIC][ELASTIC_IS_MULT_TP];
}

void fill_memory_cap_mlu590(void *pcore)
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
		mlu590_board_info[subtype][INFO_CACHE_SIZE];
	pmem_cap->total_const_mem_size =
		BYTES_TO_MB(pboardi->total_memory);
	pmem_cap->global_memory_node_count =
		pboardi->mem_channel;
	pmem_cap->cluster_l1_cache_support =
		mlu590_attr_cap_info[ATTR_MEMORY][MEM_CLUSTER_LI_CACHE];
	pmem_cap->max_persisting_l2_cache_size =
	mlu590_attr_info[subtype][ATTR_PERSIS_L2_CACHE] * pboardi->hbm_cnt;
	pmem_cap->max_shared_memory_size_per_union_task =
		mlu590_attr_cap_info[ATTR_MEMORY][MEM_MAX_SHARE_MEM];

	pmem_cap->can_use_host_pointer_for_register_mem = 1;
	pmem_cap->can_map_host_memory = 1;
}

void fill_hardware_cap_mlu590(void *pcore)
{
	struct bus_info_s bus_info;
	struct bar_info_s bar_info;
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_hardware_cap *phard_cap = NULL;
	struct cndev_attr_set *attr_set = NULL;
	int board_idx = core->board_info.board_idx;

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

	phard_cap->ecc_support =
		mlu590_board_info[board_idx][INFO_ECC_SUPPORT];
	phard_cap->cluster_clock_rate =
		mlu590_board_info[board_idx][INFO_MAX_IPU_FREQ] * 1000;
	phard_cap->memory_clock_rate =
		pboardi->ddr_freq * 1000;
	phard_cap->bus_width =
		mlu590_board_info[board_idx][INFO_BUS_WIDTH];
	phard_cap->global_memory_total_size =
		BYTES_TO_MB(pboardi->total_memory);
	phard_cap->mdr_memory_size =
		min(BYTES_TO_MB(bar_info.bar[4].bar_sz), phard_cap->global_memory_total_size);

	phard_cap->pci_bus_id = bus_info.info.pcie.bus_num;
	phard_cap->pci_device_id = bus_info.info.pcie.device_id;
	phard_cap->pci_domain_id = bus_info.info.pcie.domain_id;
	phard_cap->pci_mps = bus_info.info.pcie.mps;
	phard_cap->pci_mrrs = bus_info.info.pcie.mrrs;
}

void fill_boardinfo_mlu590_vf(struct cn_core_set *core)
{
	struct cn_board_info *pboardi = &core->board_info;
	int board_idx = core->board_info.board_idx;

	pboardi->stack_size = mlu590_board_info[board_idx][INFO_STACK_SIZE];
	pboardi->sram_size = mlu590_board_info[board_idx][INFO_SRAM_SIZE];
	pboardi->rated_ipu_freq = mlu590_board_info[board_idx][INFO_MAX_IPU_FREQ];
	pboardi->ipu_core_num = mlu590_board_vf_info[ATTR_IPU_CORE];
	pboardi->ddr_freq = mlu590_board_vf_info[ATTR_DDR_FREQ];
}

void fill_attribute_mlu590(struct cn_core_set *core)
{
	/* Computing Capabilities */
	fill_computing_cap_mlu590(core);

	/* Heterogeneous Capabilities */
	fill_heterogeneous_cap_mlu590(core);

	/* Elastic Capabilities */
	fill_elastic_cap_mlu590(core);

	/* Memory Capacities */
	fill_memory_cap_mlu590(core);

	/* Hardware Proterties */
	fill_hardware_cap_mlu590(core);
}

void fill_elastic_cap_mlu590_vf(struct cn_core_set *core)
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
	pelastic_cap->mlu_isa_version = mlu590_attr_cap_info[ATTR_ELASTIC][ELASTIC_ISA];
	pelastic_cap->is_multiple_tensor_processor = mlu590_attr_cap_info[ATTR_ELASTIC][ELASTIC_IS_MULT_TP];
}

void cn_attr_fill_memory_cap_mlu590_vf(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_board_info *pboardi = &core->board_info;
	struct cn_memory_cap *pmem_cap = NULL;
	s32 ret = 0;
	s64 total_mem = 0;
	struct cndev_attr_set *attr_set = NULL;

	attr_set = core->attr_set;
	if (IS_ERR_OR_NULL(attr_set)) {
		cn_dev_err("attribute attr_set is null");
		return;
	}

	pmem_cap = &attr_set->attr_info.memory_cap;
	pmem_cap->cluster_l1_cache_support = mlu590_attr_cap_info[ATTR_MEMORY][MEM_CLUSTER_LI_CACHE];
	pmem_cap->max_persisting_l2_cache_size = cn_dm_attr_llc_max_persisting_size(core);
	pmem_cap->max_shared_memory_size_per_union_task = 0;
	pmem_cap->can_use_host_pointer_for_register_mem = 0;
	pmem_cap->can_map_host_memory = 0;

	ret = cn_dm_attr_llc_cache_size(core);
	if (ret < 0) {
		cn_dev_core_err(core, "attribute llc cache size failed %d", ret);
	} else {
		pboardi->cache_size = ret;
		pmem_cap->max_l2_cache_size = pboardi->cache_size;
	}

	total_mem = cn_dm_attr_memory_size(core);
	if (total_mem < 0) {
		cn_dev_core_err(core, "attribute memory size failed %lld", total_mem);
	} else {
		pboardi->total_memory = total_mem;
		pmem_cap->total_const_mem_size = BYTES_TO_MB(pboardi->total_memory);
	}

	ret = cn_dm_attr_memory_nodes(core);
	if (ret < 0) {
		cn_dev_core_err(core, "attribute memory nodes failed %d", ret);
	} else {
		pboardi->mem_channel = ret;
		pmem_cap->global_memory_node_count = pboardi->mem_channel;
	}
}

void fill_attribute_mlu590_vf(struct cn_core_set *core)
{
	struct cndev_attr_set *attr_set = core->attr_set;

	if (IS_ERR_OR_NULL(attr_set->fill_ops)) {
		cn_dev_core_err(core, "attribute fill_ops is null");
		return;
	}
	/* Computing Capabilities */
	fill_computing_cap_mlu590(core);

	/* Heterogeneous Capabilities */
	if (attr_set->fill_ops->fill_heterogeneous_vf)
		attr_set->fill_ops->fill_heterogeneous_vf(core);

	/* Elastic Capabilities */
	fill_elastic_cap_mlu590_vf(core);

	/* Memory Capacities */
	if (attr_set->fill_ops->fill_memory_vf)
		attr_set->fill_ops->fill_memory_vf(core);

	/* Hardware Proterties */
	if (attr_set->fill_ops->fill_hardware_vf)
		attr_set->fill_ops->fill_hardware_vf(core);
}
