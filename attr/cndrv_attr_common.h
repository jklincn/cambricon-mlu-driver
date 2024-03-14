#ifndef __CAMBRICON_ATTR_COMMON_H__
#define __CAMBRICON_ATTR_COMMON_H__

#define BYTES_TO_MB(b) ((b) >> 20UL)

/* extra attribute interface buffer count */
#define ATTR_EXTRA_CNT3    (3)
#define ATTR_EXTRA_CNT5    (5)
#define ATTR_EXTRA_CNT6    (6)

#define ATTR_NOT_SUPPORT   (0)
#define ATTR_SUPPORT       (1)

enum attr_board_vf_type {
	ATTR_IPU_CORE = 0,
	ATTR_DDR_FREQ = 1,
	BOARD_VF_NUM,
};

enum attr_ddr_freq_type {
	DDR_FREQ1600 = 1600,
	DDR_FREQ3200 = 3200,
};

enum attr_ipucore_num {
	IPUCORE_NUM4 = 4,
};

/* max quadrant count */
enum max_quadrant_cnt {
	QUAD_CNT1 = 1,
	QUAD_CNT2 = 2,
	QUAD_CNT4 = 4,
};

enum max_union_per_quadrant {
	UNION_PER_QUAD0 = 0,
	UNION_PER_QUAD1 = 1,
	UNION_PER_QUAD2 = 2,
	UNION_PER_QUAD4 = 4,
	UNION_PER_QUAD8 = 8,
};

enum max_cluster_num {
	MAX_CLUSTER_NUM1 = 1,
	MAX_CLUSTER_NUM2 = 2,
	MAX_CLUSTER_NUM4 = 4,
	MAX_CLUSTER_NUM6 = 6,
	MAX_CLUSTER_NUM8 = 8,
	MAX_CLUSTER_NUM10 = 10,
	MAX_CLUSTER_NUM12 = 12,
	MAX_CLUSTER_NUM16 = 16,
};


enum attr_info_type {
	QUADRANDT_COUNT = 0,
	UNIONT_PER_QUADRANT = 1,
	TINY_CORE = 2,
	ATTR_CLUSTER_NUM = 3,
	ATTR_PERSIS_L2_CACHE = 4,
	ATTR_TYPE_NUM,
};

enum attr_major_type {
	ATTR_MAJOR1 = 1,
	ATTR_MAJOR2 = 2,
	ATTR_MAJOR3 = 3,
	ATTR_MAJOR5 = 5,
};

enum attr_minor_type {
	ATTR_MINOR0 = 0,
	ATTR_MINOR1 = 1,
};

enum attr_cap_type {
	ATTR_COMPUTING = 0,
	ATTR_HETEROG,
	ATTR_ELASTIC,
	ATTR_MEMORY,
	ATTR_MAX_CAP,
};

enum attr_computing_type {
	COMPUT_MAJOR = 0,
	COMPUT_MINOR,
	COMPUT_SPARSE,
	COMPUT_FP16,
	COMPUT_INT4,
	COMPUT_INT8,
	COMPUT_BF16,
	COMPUT_TF32,
	COMPUT_MAX,
};

enum attr_heterogeneous_type {
	HETEROG_JPEG = 0,
	HETEROG_H264,
	HETEROG_H265,
};

enum attr_elastic_type {
	ELASTIC_ISA = 0,
	ELASTIC_IS_MULT_TP,
};

enum attr_isa_type {
	ATTR_UNKNOW_ISA = 0,
	ATTR_MLU220_ISA = 220,
	ATTR_MLU270_ISA = 270,
	ATTR_MLU290_ISA = 290,
	ATTR_MLU370_ISA = 372,
	ATTR_CE3226_ISA = 322,
	ATTR_MLU590_ISA = 592,
	ATTR_MLU580_ISA = ATTR_MLU590_ISA,
	ATTR_LEOPARD_ISA = 520,
	ATTR_PIGEON_ISA = 520,
	ATTR_1V_2301_ISA = 522,
};

enum attr_memory_type {
	MEM_CLUSTER_LI_CACHE = 0,
	MEM_MAX_L2_CACHE,
	MEM_MAX_SHARE_MEM,
};

#ifndef CONFIG_CNDRV_EDGE
void fill_attribute_mlu220(struct cn_core_set *core);
void fill_attribute_mlu270(struct cn_core_set *core);
void fill_attribute_mlu270_vf(struct cn_core_set *core);
void fill_boardinfo_mlu270_vf(struct cn_core_set *core);
void fill_attribute_mlu290(struct cn_core_set *core);
void fill_attribute_mlu290_vf(struct cn_core_set *core);
static inline void fill_attribute_ce3226(struct cn_core_set *core) {};
static inline void fill_attribute_pigeon(struct cn_core_set *core) {};
void fill_attribute_mlu370(struct cn_core_set *core);
void fill_boardinfo_mlu370_vf(struct cn_core_set *core);
void fill_attribute_mlu370_vf(struct cn_core_set *core);
void fill_attribute_mlu590(struct cn_core_set *core);
void fill_boardinfo_mlu590_vf(struct cn_core_set *core);
void fill_attribute_mlu590_vf(struct cn_core_set *core);
void fill_attribute_mlu580(struct cn_core_set *core);
void fill_boardinfo_mlu580_vf(struct cn_core_set *core);
void fill_attribute_mlu580_vf(struct cn_core_set *core);
void cn_attr_fill_memory_cap_mlu590_vf(void *pcore);

#else
static inline void fill_attribute_mlu270(struct cn_core_set *core)
{
}
static inline void fill_attribute_mlu270_vf(struct cn_core_set *core)
{
}
static inline void fill_boardinfo_mlu270_vf(struct cn_core_set *core)
{
}
static inline void fill_attribute_mlu290(struct cn_core_set *core)
{
}
static inline void fill_attribute_mlu290_vf(struct cn_core_set *core)
{
}
static inline void fill_attribute_mlu370(struct cn_core_set *core)
{
}
static inline void fill_boardinfo_mlu370_vf(struct cn_core_set *core)
{
}
static inline void fill_attribute_mlu370_vf(struct cn_core_set *core)
{
}
static inline void fill_attribute_mlu590(struct cn_core_set *core)
{
}
static inline void fill_boardinfo_mlu590_vf(struct cn_core_set *core)
{
}
static inline void fill_attribute_mlu590_vf(struct cn_core_set *core)
{
}
static inline void fill_attribute_mlu580(struct cn_core_set *core)
{
}
static inline void fill_boardinfo_mlu580_vf(struct cn_core_set *core)
{
}
static inline void fill_attribute_mlu580_vf(struct cn_core_set *core)
{
}
static inline void cn_attr_fill_memory_cap_mlu590_vf(void *pcore)
{
}
#if defined(CONFIG_CNDRV_C20E_SOC)
void fill_attribute_mlu220(struct cn_core_set *core);
static inline void fill_attribute_ce3226(struct cn_core_set *core)
{
}
static inline void fill_attribute_pigeon(struct cn_core_set *core)
{
}
#elif defined(CONFIG_CNDRV_CE3226_SOC)
void fill_attribute_ce3226(struct cn_core_set *core);
static inline void fill_attribute_mlu220(struct cn_core_set *core)
{
}
static inline void fill_attribute_pigeon(struct cn_core_set *core)
{
}
#elif defined(CONFIG_CNDRV_PIGEON_SOC)
void fill_attribute_pigeon(struct cn_core_set *core);
static inline void fill_attribute_mlu220(struct cn_core_set *core)
{
}
static inline void fill_attribute_ce3226(struct cn_core_set *core)
{
}
#else
static inline void fill_attribute_mlu220(struct cn_core_set *core)
{
}
static inline void fill_attribute_ce3226(struct cn_core_set *core)
{
}
static inline void fill_attribute_pigeon(struct cn_core_set *core)
{
}
#endif
#endif

#endif
