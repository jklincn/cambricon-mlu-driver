/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_CNDRV_MM_H__
#define __CAMBRICON_CNDRV_MM_H__

#include "cndrv_core.h"

typedef unsigned long	host_addr_t;
typedef u64 dev_addr_t;
typedef u64 user_addr_t;
typedef u64 phy_addr_t;
typedef u64 dev_ipc_handle_t;
typedef u64 kvirt_t;
typedef u32 flags_t;

#define PF_ID	(0x10000)
#define	VMID_MAX (8)
#define C20L_AXI_SHM_BASE (0x8008000000ULL)
#define C20_AXI_SHM_BASE  (0x8008000000ULL)
#define C30S_AXI_SHM_BASE (0x800000000000ULL)
#define C30S_AXI_SHM_PA_BASE (0x4018000000ULL)
#define C30S_MDR_RESERVE_SZ (0x4000000UL)
#define CE3226_AXI_SHM_BASE (0x800000000000ULL)
#define PIGEON_AXI_SHM_BASE (0x800000000000ULL)
#define C50_AXI_SHM_BASE (0x800000000000ULL)
#define C50_AXI_SHM_PA_BASE (0x6000000000ULL)
#define C50_AXI_SRAM_PA_BASE (0x7803000000ULL)
#define C50_AXI_SRAM_VA_BASE C30_AXI_SHM_BASE
#define C50_AXI_SRAM_TOTAL_SIZE (0x20000)

#define MEM_EXTENSION_MODE_BIT	(4)
#define MEM_EXTENSION_MODE_MASK	(0xF)
#define MEM_EXTENSION_OPS_MASK	(0xF)

#define EXT_NAME_SIZE	(32)

#define align_up(a, size)    ALIGN(a, size)

/*for pcie module to dump error status*/
#define C20_PCIE_SMMU_BASE_ADDR		(0x1c0000)
#define C20L_PCIE_SMMU_BASE_ADDR	(0x1c0000)
#define C20E_PCIE_SMMU_BASE_ADDR	(0xB30000)
#define MLU370_PCIE_SMMU_BASE_ADDR	(0x100000)

enum mm_proc_ctrl_type {
	CODEC_TURBO_MODE = 0,
	/* 1 unused */
	CCMALLOC_MODE    = 2,
	ACCLERATE_MODE   = 3,
	HAI_MODE         = 4,
	FA_REMOTE_MODE   = 5,
	SNAPSHOT_MODE    = 6,
	FA_MASK_CHUNKS   = 7,
	PGRETIRE_TRIGGER = 8,
	LINEAR_MODE      = 9,
	LINEAR_COMPRESS_MODE = 10,
};

enum pcie_smmu_cau_id {
	CN_PCIE_BAR2_R = 1,
	CN_PCIE_BAR2_W,
	CN_PCIE_BAR4_R,
	CN_PCIE_BAR4_W,
};

#define GET_BAR2_READ_CAU_ID_OF_VF(n)	(CN_PCIE_BAR2_R + (n + 1) * 4)
#define GET_BAR2_WRITE_CAU_ID_OF_VF(n)	(CN_PCIE_BAR2_W + (n + 1) * 4)
#define GET_BAR4_READ_CAU_ID_OF_VF(n)	(CN_PCIE_BAR4_R + (n + 1) * 4)
#define GET_BAR4_WRITE_CAU_ID_OF_VF(n)	(CN_PCIE_BAR4_W + (n + 1) * 4)

/* alloc memory type */
enum cn_mem_type {
	CN_SHARE_MEM    = 0,
	CN_LOCAL_MEM    = 1,
	CN_IPU_MEM      = 2,
	CN_VPU_MEM      = 3,
	CN_MDR_MEM      = 4,
	/* 5, 6, 7 reserved */
	CN_OUTB_MEM     = 8,
	CN_PEER_MEM     = 9,
	/* 10 reserved */
	CN_COMPRESS_MEM = 11,
	CN_SEPARATE_MEM = 12,
	CN_CONST_MEM    = 13,
	CN_SEC_MEM      = 14,
	CN_MAX_MEM,
};

static inline const char *mem_type_str(enum cn_mem_type type)
{
	switch (type) {
	case CN_SHARE_MEM: return "CN_SHARE_MEM";
	case CN_IPU_MEM: return "CN_IPU_MEM";
	case CN_VPU_MEM: return "CN_VPU_MEM";
	case CN_MDR_MEM: return "CN_MDR_MEM";
	case CN_COMPRESS_MEM: return "CN_COMPRESS_MEM";
	case CN_SEPARATE_MEM: return "CN_SEPARATE_MEM";
	case CN_CONST_MEM: return "CN_CONST_MEM";
	case CN_SEC_MEM: return "CN_SEC_MEM";
	default: break;
	}
	return NULL;
}
#define CN_MEM_BIT 4

#define	MEM_TURBO_ENABLE 0x1
#define	MEM_TURBO_DISABLE 0

#define	MEM_DELAYFREE_ENABLE 1
#define	MEM_DELAYFREE_DISABLE 2

#define	MEM_CCMALLOC_ENABLE 1
#define	MEM_CCMALLOC_DISABLE 2
#define	MEM_CCMALLOC_DEBUG 3

#define MEM_ALLOC_ALIGN_ENABLE 1
#define MEM_ALLOC_ALIGN_DISABLE 0

#define MEM_HAI_ENABLE        1
#define MEM_HAI_DISABLE       2
#define	MEM_FA_ENABLE 0x1
#define	MEM_FA_DISABLE 0x2

/*for AxCache*/
enum cn_mem_mair {
	CN_C_nA	= 0, /*CACHEABLE_NON_ALLOCATE*/
	CN_OR_C = 1, /*ONLY_READ_CACHEABLE*/
	CN_OW_C = 2, /*ONLY_WRITE_CACHEABLE*/
	CN_C_A  = 3, /*CACHEABLE_AND_ALLOCATE*/
};

enum mapinfo_type {
	MEM_INV  = 0x0, /* don't support */
	MEM_FA   = 0x1, /* fast alloc */
	MEM_LG   = 0x2, /* normal memory, size is large than 32M */
	MEM_FAKE = 0x3, /* fake memory, used in the arm_dev platform */
	MEM_VMM  = 0x4, /* virtual memory management */
	MEM_CD   = 0x5, /* constant memory for data */
	MEM_CI   = 0x6, /* constant memory for instruction */
	MEM_KEXT = 0x7, /* kernel mallocExt */
	MEM_IE  = 0x8, /* import external memory */
};

struct mem_attr {
	u64 tag;
	unsigned long size;
	unsigned int align;
	unsigned int type;/*ipu/vpu/jpu/stack memory*/
	unsigned int affinity;/*bank & channel id*/
	unsigned int flag;/*AP and MAIR attributes*/
	unsigned int vmid;
	unsigned int padding;
	char name[EXT_NAME_SIZE];
};

struct mem_perf_attr {
	struct mem_attr attr;
	__u64 correlation_id;
	__u64 context_id;
};

#define INIT_MEM_ATTR(attr, _size, _align, _type, _affinity, _flag) \
{\
	(attr)->size     = _size; \
	(attr)->align    = _align; \
	(attr)->type     = _type; \
	(attr)->affinity = _affinity; \
	(attr)->flag     = _flag; \
	(attr)->vmid     = PF_ID; \
	(attr)->name[0]  = '\0'; \
}

struct mem_attr_get {
	u64 tag;
	unsigned long iova;
	unsigned long size;
	unsigned int flag;/*AP and MAIR attributes*/
	unsigned int vmid;
	unsigned int ret;
};

struct ipu_mem_addr_get {
	unsigned long resv_iova;
	unsigned long group_offset;
	unsigned long core_offset;
};

struct mem_size_info {
	unsigned long phy_total_mem;
	unsigned long phy_used_mem;
	unsigned long vir_total_mem;
	unsigned long vir_used_mem;
	/*Add FA info*/
	unsigned long fa_total_mem;
	unsigned long fa_used_mem;
};

struct async_params_t {
	u64 queue;
	u64 version;
	u64 user;
	void *core;
};

struct mem_feats_t {
	u8 vmm;
	u8 vmm_handle2fd;
	u8 compression;
	u8 linear;
	u64 linear_granularity;
};

int cn_smmu_cau_bypass(struct cn_core_set *core, int phy_ch, bool en);

int cn_smmu_cau_invalid(struct cn_core_set *core, unsigned int s_id);

int cn_host_share_mem_alloc(u64 tag, host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, size_t size, void *pcore);

int cn_host_share_mem_free(u64 tag,  host_addr_t host_vaddr,
		dev_addr_t device_vaddr, void *pcore);

int cn_device_share_mem_alloc(u64 tag, host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, size_t size, void *pcore);

int cn_device_share_mem_alloc_aligned(u64 tag, host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, size_t size, size_t alignment, void *pcore);

int cn_device_share_mem_free(u64 tag,  host_addr_t host_vaddr,
		dev_addr_t device_vaddr, void *pcore);

int cn_sram_get_base_addr(u64 tag, host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, phy_addr_t *phy_addr, size_t *size,
		void *pcore);

int cn_sram_alloc(u64 tag, host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, size_t size, void *pcore);

int cn_sram_free(u64 tag,  host_addr_t host_vaddr,
		dev_addr_t device_vaddr, void *pcore);

int cn_sram_get_paddr(u64 tag, dev_addr_t device_vaddr,
		phys_addr_t *device_paddr, void *pcore);

int cn_mem_alloc(u64 tag,
		dev_addr_t *dev_vaddr, struct mem_attr *pattr, void *pcore);

int cn_mem_perf_alloc(u64 tag, dev_addr_t *dev_vaddr,
		struct mem_attr *pmattr, struct mem_perf_attr *pattr, void *pcore);

int cn_mem_set_prot(u64 tag, dev_addr_t device_vaddr, unsigned long size,
		int prot_flag, void *pcore);

int cn_mdr_alloc(u64 tag,
		dev_addr_t *dev_vaddr, struct mem_attr *pattr, void *pcore);

int cn_mem_free(u64 tag, dev_addr_t virt_addr, void *pcore);

int cn_mem_perf_free(u64 tag, dev_addr_t virt_addr,
		__u64 correlation_id, void *pcore);

int cn_mem_merge(u64 tag, dev_addr_t *merged_addr, dev_addr_t *virt_addr,
		int cnt, void *pcore);

unsigned long cn_mem_copy_h2d(u64 tag, host_addr_t host_vaddr,
		dev_addr_t device_vaddr, size_t size, void *pcore);

unsigned long cn_mem_copy_d2h(u64 tag, host_addr_t host_vaddr,
		dev_addr_t device_vaddr, ssize_t size, void *pcore);

int cn_mem_copy_d2d(u64 tag, dev_addr_t src_vaddr, dev_addr_t dst_vaddr,
		ssize_t size, void *pcore, int compress_type);

int cn_mem_debugfs(void *pcore);

dev_addr_t  cn_shm_get_dev_addr_by_name(void *pcore, unsigned char *name);

dev_addr_t cn_get_dev_virt_base(void *pcore);

host_addr_t cn_shm_get_host_addr_by_name(void *pcore, unsigned char *name);

phy_addr_t cn_shm_get_phy_addr_by_name(void *pcore, unsigned char *name);

size_t cn_shm_get_size_by_name(void *pcore, unsigned char *name);

int cn_shm_get_sram_dev_info(void *pcore, dev_addr_t *pa_addr, dev_addr_t *pa_sz);

dev_addr_t cn_shm_get_dev_va_base(void *pcore);

int cn_mem_bar_copy_d2h(u64 tag, dev_addr_t device_vaddr,
		host_addr_t host_vaddr, size_t size, void *pcore);

int cn_mem_bar_copy_h2d(u64 tag, dev_addr_t device_vaddr,
		host_addr_t host_vaddr, size_t size, void *pcore);

int cn_mem_dma_memsetD8(void *pcore, u64 device_addr,
		unsigned long number, unsigned char val, u64 tag);

int cn_mem_dma_memsetD16(void *pcore, u64 device_addr,
		unsigned long number, unsigned short val, u64 tag);

int cn_mem_dma_memsetD32(void *pcore, u64 device_addr,
		unsigned long number, unsigned int val, u64 tag);

unsigned long cn_mem_dma_p2p(void *pcore_src, void *pcore_dst,
			 u64 src_addr, u64 src_tag,
			 u64 dst_addr, u64 dst_tag,
			 unsigned long count);

int cn_mem_private_data_init(void *fp_private_data);

int cn_mem_private_data_exit(void *fp_private_data);

int cn_mem_extension(void *pcore, int en);

unsigned long cn_share_mem_mmap(u64 tag, host_addr_t host_vaddr,
		unsigned long size, int prot, int shm_type, void *pcore);

int cn_share_mem_munmap(u64 tag, unsigned long va,
		unsigned long size, int shm_type, void *pcore);

int cn_mm_init(struct cn_core_set *pcore);

void cn_mm_reinit(void *pcore);

int cn_mem_do_exit(u64 tag, void *pcore);

void cn_mm_exit(struct cn_core_set *pcore);

void cn_mm_release_res(void *pcore);

int cn_mm_reset_callback(void *pcore);

int cn_mm_late_init(struct cn_core_set *pcore);

void cn_mm_late_exit(struct cn_core_set *pcore);

int cn_mm_last_init(struct cn_core_set *pcore);

void cn_mm_last_exit(struct cn_core_set *pcore);

int cn_mm_bootargs_init(struct cn_core_set *pcore);

int cn_mm_rpc_late_init(struct cn_core_set *pcore);

void cn_mm_rpc_late_exit(struct cn_core_set *pcore);

int cn_mem_pageretire_handle(void *pcore);

int cn_mem_pgr_get_pages(void *pcore, int ecc_type, uint32_t *counts, uint64_t *pages);

int cn_mem_pgr_get_status(void *pcore, int *is_pending, int *error_status);

int cn_mem_proc_dump_info(void *pcore, void *seq_file);

int cn_mem_proc_dump_ctrl(void *pcore, char *cmd);

int cn_mem_proc_mem_ctrl(void *pcore, char *cmd);

int cn_mem_proc_mem_show(void *pcore, void *seq_file);

int cn_mem_proc_do_pgretire(void *pcore);

int cn_mem_proc_show_pgretire(void *pcore, void *seqfile);

int cn_mem_proc_llc_ctrl(void *pcore, char *buf);

#ifdef CONFIG_CNDRV_EDGE
long cn_mem_kernel_test(unsigned long arg);
void cn_edge_cache_clean(void *start, u64 len);
void cn_edge_cache_invalid(void *start, u64 len);
void cn_edge_cache_flush(void *start, u64 len);
int cn_mem_uva_get(u64 tag, dev_addr_t device_vaddr, __u64 size, user_addr_t *uva, __u32 prot, void *pcre);
int cn_mem_uva_put(u64 tag, user_addr_t uva, __u64 size, dev_addr_t iova,  __u32 prot, void *pcore);
int cn_mem_cache_op(u64 tag, dev_addr_t iova, user_addr_t uva, __u64 size, __u32 op, void *pcore);
#else
static inline long cn_mem_kernel_test(unsigned long arg)
{
	return 0;
}
static inline int cn_mem_uva_get(u64 tag, dev_addr_t device_vaddr, __u64 size,
								 user_addr_t *uva, __u32 prot, void *pcore)
{
	return 0;
}
static inline int cn_mem_uva_put(u64 tag, user_addr_t uva, __u64 size,
								 dev_addr_t iova,  __u32 prot, void *pcore)
{
	return 0;
}
static inline int cn_mem_cache_op(u64 tag, dev_addr_t iova, user_addr_t uva,
								  __u64 size, __u32 op, void *pcore)
{
	return 0;
}
#endif
int cn_mem_gdr_linear_remap(dev_addr_t iova, u64 size, void **page_table);
int cn_mem_gdr_linear_unremap(dev_addr_t iova, void *page_table);
int cn_mem_remap(u64 virtual_address, u64 size, u64 *pa);

int cn_mem_unremap(u64 virtual_address, u64 pa);

long cn_mm_ioctl(void *fp, struct cn_core_set *core, unsigned int cmd, unsigned long arg);

void cn_mem_get_feats_status(void *pcore, struct mem_feats_t *status);

int cn_mem_get_vmm_pid_info(void *pcore, int pid, u64 *vir_usedsize,
		u64 *phy_usedsize);

int cn_mem_vmm_process_release(struct cn_core_set *core);

int cn_mem_get_size_info(void *mem_info, void *pcore);

struct sbts_dma_async;
struct sbts_dma_priv;

int cn_async_address_kref_get(struct sbts_dma_async *params,
		struct sbts_dma_priv *priv);

void cn_async_address_kref_put(__u64 minfo, dev_addr_t dev_vaddr,
		unsigned long size);

struct sg_table *cn_mem_linear_remap(void *minfo, dev_addr_t start,
		unsigned long size);

void cn_mem_linear_unmap(void *minfo, struct sg_table *table);

int cn_mem_peer_register(struct cn_core_set *lcore, dev_addr_t addr,
			size_t size, struct cn_core_set *rcore, u32 flags);

int cn_mem_peer_unregister(struct cn_core_set *core, dev_addr_t addr,
			struct cn_core_set *rcore);

int cn_mem_peer_get_pointer(struct cn_core_set *lcore,
			dev_addr_t addr, struct cn_core_set *rcore, dev_addr_t *oaddr, u32 flags);

int cn_mem_p2p_pin_mem(dev_addr_t iova, u64 size, struct sg_table **pin_table);
int cn_mem_p2p_unpin_mem(dev_addr_t iova, struct sg_table *pin_table);

dev_addr_t cn_mem_linear_get_base(struct cn_core_set *core);

int cn_mem_cp_info_get(struct cn_core_set *core, void *user_buf, unsigned long *size);
int cn_mem_cp_cc_set(struct cn_core_set *core, int type, int action);
int cn_mem_cp_version_check(void *fp, struct cn_core_set *core,
		u64 papi_version, u64 *fdata, u64 fdata_len, u64 *cp_version);
#endif /*__CAMBRICON_CNDRV_MM_H__*/
