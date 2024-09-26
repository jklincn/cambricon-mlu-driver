/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#ifndef __CAMBRICON_MM_H__
#define __CAMBRICON_MM_H__

#include <linux/version.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_fa.h"
#include "camb_mm_rpc.h"
#include "camb_mm_tools.h"
#include "camb_range_tree.h"
#include "cndrv_pre_compile.h"

#define DEVICE_BAR0_VA          (0x8000000000)

#define PHYS_ADDRESS_BITS       (40)
#define VIRT_TOTAL_SIZE         (1ULL << PHYS_ADDRESS_BITS)
#define DEFAULT_VIR_USED_MEM    (512UL * 1024 * 1024 * 20)
#define DEFAULT_PHY_USED_MEM    (512UL * 1024 * 1024)

#define CN_SHM_INBD             (0)
#define CN_SHM_OUTBD            (1)
#define CN_MEM_MALLOC           (2)
#define CN_SHM_SRAM		(4)

#define TRANS_MM_KB_ALIGN_TO_MB(x)				 ((x) >> 10)
#define TRANS_MM_KB_REMAINDER_TO_MB(x)			 ((x) & ((1 << 10) - 1))

/*share memory attributes list*/
struct shm_attr {
	int type;/*host or device share memory*/
	int index;/*for multiple address segments of the same type*/
	unsigned long size;
	host_addr_t host_virt_addr;
	phys_addr_t host_phys_addr;/*is NULL when has multiple phys address*/
	dev_addr_t  dev_virt_addr;
};

struct shm_rsrv_info {
	char *name;
	size_t rev_size;
};

enum SHM_RESV_IDX {
	SHM_RPC_RESV,
	SHM_COMMU_RESV,
	SHM_KDBG_RESV,
	SHM_PGRE_RESV,
	SHM_CFGS_RESV,
	SHM_KDUMP_RESV,
	SHM_VRING0,
	SHM_VRING1,
	SHM_VBUFFER,
	SHM_RSC,
	SHM_MDR_RESV,
};

#define MAX_NAME_LEN	40
struct shm_rsrv_priv {
	char name[MAX_NAME_LEN];
	size_t rev_size;
	int type; /* INBD or OUTBD */
	host_addr_t rev_host_vaddr;
	dev_addr_t rev_dev_vaddr;
	phy_addr_t rev_phy_addr;
	struct list_head list;
};

enum camb_shm_type {
	CN_DEV_SHM = 0x0,
	CN_HOST_SHM = 0x1,
	CN_HOST_DATA_SHM = 0x2,
	CN_SRAM_SHM = 0x3,
	CN_SHM_MAX,
};

static inline const char *shm_type_str(int shm_type)
{
	switch (shm_type) {
	case CN_DEV_SHM: return "CN_SHM_INBD";
	case CN_HOST_SHM: return "CN_SHM_OUTBD";
	case CN_HOST_DATA_SHM: return "CN_SHM_OUTBD_DATA";
	case CN_SRAM_SHM: return "CN_SHM_SRAM";
	default: break;
	}

	return NULL;
}

static inline const char *mapinfo_type_str(enum mapinfo_type type)
{
	switch (type) {
	case MEM_FA:   return "MEM_FA";
	case MEM_LG:   return "MEM_LG";
	case MEM_FAKE: return "MEM_FAKE";
	case MEM_VMM:  return "MEM_VMM";
	case MEM_CD:   return "MEM_CONST_DATA";
	case MEM_CI:   return "MEM_CONST_INST";
	case MEM_KEXT: return "MEM_KEXT";
	default: break;
	}
	return NULL;
}

#define	FREE_LIST_MAX(ipcm_enabled) \
	(RPC_TRANS_MAX_LEN(ipcm_enabled) / sizeof(struct free_mem_list))
#define	SYNC_FREE_TAG				(1UL << 8)
#define	DELAY_FREE_SIZE_MAX			(512UL << 20)
#define	DELAY_FREE_UNIT_SIZE		(64UL << 20)
#define	DELAY_FREE_CNT_THRESHOLD	(10)
/* define the threshold of delay free time as us, now we set it to 10ms. */
#define	DELAY_FREE_TIME_THRESHOLD	(10 * 1000)
#define	WORK_IDLE				(0)
#define	WORK_RUNNING			(1)
#define MAX_RETRY_TIMES			(50)
#define MAX_FREE_RETRY_TIMES	(1)
#define TIMER_EXPIRES_MSEC(x) (jiffies + msecs_to_jiffies(x))

#define FA_HIGH_WATERMARK		(2)
#define FA_LOW_WATERMARK		(1)

#define MEM_ALLOC_RANDOM_CHL    (0xffffffff)
#define MEM_ALLOC_MULTI_CHL     (0xfffffffe)


#define COMMU_MSG_CNT_LIMIT	(50)
#define COMMU_MSG_LE64_NUM	(60)
#define COMMU_MSG_DATA_NUM	(COMMU_MSG_LE64_NUM /	\
			(sizeof(struct commu_message_data) / sizeof(__le64)))

struct mempool_t {
	host_addr_t virt;
	phys_addr_t phys;
	size_t size;
	atomic_long_t used_size;
	unsigned int vm_num;
	struct cn_gen_pool *pool;
};

struct mdr_addr_t {
	dev_addr_t device_addr;
	dev_addr_t mdr_addr;
	size_t mdr_size;
};

struct shm_addr {
	dev_addr_t device_vaddr;
	host_addr_t host_vaddr;
	phys_addr_t device_paddr;
	int type;
	void *caller;
};

struct free_frame {
	unsigned int tag;
	union {
		struct mdr_addr_t mdr_va;
		dev_addr_t device_addr;
	};
};

struct free_mem_list {
	unsigned long mem_cnt;
	unsigned int extra_status;
	struct free_frame mem_list[1];
};

struct ob_data_payload {
	__le64 pci_addr;
	__le32 size;
} __attribute__((__packed__));

#define OB_DATA_MAP_SMMU_SOF             (0x01)
#define OB_DATA_MAP_SMMU_MOF             (0x02)
#define OB_DATA_MAP_SMMU_EOF             (0x03)
#define OB_DATA_UNMAP_SMMU_SOF           (0x11)
#define OB_DATA_UNMAP_SMMU_MOF           (0x12)
#define OB_DATA_UNMAP_SMMU_EOF           (0x13)

#define MAX_OB_PCI_ADDR_CNT		\
	((RPC_TRANS_MAX_LEN(1) - sizeof(struct ob_data_rpc_t)) / sizeof(struct ob_data_payload) + 1)

/*outbound cfg*/
struct ob_data_rpc_t {
	unsigned long device_pa;
	unsigned long iova;
	unsigned long size;
	unsigned long offset;
	unsigned short tag;
	unsigned short t_cnt;
	unsigned short s_cnt;
	unsigned short cnt;
	struct ob_data_payload data[1];
} __attribute__((__packed__));

enum mem_ob_cmd {
	OB_CMD_CONFIG_OB = 1,
	OB_CMD_GET_ADDRESS = 2,
};

/*send to device*/
struct mem_ob_info {
	unsigned long device_pa;
	unsigned long lvl1;
	unsigned long lvl2;
	unsigned int total_win_cnt;
};

/*receive from device*/
struct ob_addr_t {
	unsigned long device_pa;
	unsigned long iova_start;
	unsigned long iova_size;
};

struct mem_ob_ctrl {
	/*value is mem_ob_cmd*/
	unsigned int cmd;
	union {
		struct mem_ob_info ob_info;
	};
};

struct mem_ctrl {
	unsigned int flag;
	unsigned int extra_status;
};

/* rpc_mem_debug structure */
#define MEM_DBG_MAX_CHANNELS (4)
enum mem_dbg_cmd {
	MEM_DBG_DUMPINFO = 0x0,
	MEM_DBG_GETINFO,
	MEM_DBG_PGR_GETPAGES,
	MEM_DBG_PGR_GETRET,
	MEM_DBG_ZONEINFO,
};

struct mem_dbg_t {
	unsigned int cmd;
	union {
		unsigned int pid;
		unsigned int ecc_type;
	};
};

struct chl_info_t {
	unsigned long chl_total_mem;
	unsigned long chl_used_mem;
};

struct dbg_base_meminfo_t {
	unsigned int chl_counts;
	unsigned long total_mem;
	unsigned long used_mem;
	unsigned long fa_dev_mem;
	unsigned long fa_dev_used_mem;
	struct chl_info_t per_chl_info[MEM_DBG_MAX_CHANNELS];
};

struct dbg_meminfo_t {
	int ret;
	unsigned long allocated_with_ion;
	unsigned long reserved_mem;
	unsigned long ccmalloc_state;
	struct dbg_base_meminfo_t base;
};
/* rpc_mem_debug cmd end */

struct ret_msg {
	union {
		struct mdr_addr_t mdr_va;
		dev_addr_t device_addr;
		struct dbg_base_meminfo_t meminfo;
		struct ob_addr_t ob_addr;
		struct {
			unsigned int handle_id;
			unsigned int flag;
		};
	};

	int is_linear;
	int ret;
	int extra_ret;
};

struct sglist_param_t {
	unsigned long iova;
	unsigned long size;
	int host_page_shift;
};

struct sglist_node_t {
	unsigned int pfn;
	unsigned int length;
};

struct sglist_remsg_t {
	int ret;
	int total_counts;
	int curr_counts;
	struct sglist_node_t nodes[0];
};

#define SGLIST_MAX_COUNTS(ipcm_enabled) \
	((RPC_TRANS_MAX_LEN(ipcm_enabled) - sizeof(struct sglist_remsg_t)) / sizeof(struct sglist_node_t))


/* rpc_mem_mdr_init */
struct mdr_info_t {
	unsigned long shm_axi_addr;
	size_t size;
};

struct sram_mem_addr_set {
	unsigned long shm_iova;
	unsigned long shm_pa;
	unsigned long shm_size;
};

enum {
	IPC_MODE_MEM = 0x1,
	IPC_MODE_UDVM = 0x2,
};

struct ipc_shm_info {
	struct mapinfo *parent;
	atomic_t *ipcm_refcnt;
	int mode;
};

/* mem_attr flags defination */
/**
 * flags: ... | cache_lock | security | ap | mair
 *	  <<< ... |     4      |     3    |  2 | 1:0 >>>
 **/
#define MEM_PROT_MAIR_OFFSET	    (0)
#define MEM_PROT_AP_OFFSET	        (2)

/* NOTE: mem_attr->flags, bit[15:0] used by iommu remap, bit[31:16] used for others */
#define ATTR_FLAG_RESERVED_HEAP    (1UL << 16)
#define ATTR_FLAG_ALLOC_LINEAR     (1UL << 17) /* 2023/02/21: not used anymore */

#define MEM_MAIR_FROM_PROT(prot)	   \
	(((prot) >> MEM_PROT_MAIR_OFFSET) & 0x3)
#define MEM_AP_FROM_PROT(prot)		   \
	(((prot) >> MEM_PROT_AP_OFFSET) & 0x1)

enum MAIR_FLAGS {
	LLC_C_NO = 0,
	LLC_OR_A,
	LLC_OW_A,
	LLC_RW_A,
};

enum AP_FLAGS {
	AP_WR = 0,
	AP_OR,
};

struct mm_vma_list {
	struct list_head list_node;
	struct vm_area_struct *vma;
};

struct fa_addr_t {
	dev_addr_t vaddr;
	unsigned int size;/*fa size is not exceed 32MB*/
	void *chunk;
	bool is_linear;
};

struct vmm_addr_t {
	dev_addr_t vaddr;
	atomic_t isvalid;
	void *piova;
	void *phandle;
};

struct extn_addr_t {
	dev_addr_t vaddr;/*start iova*/
	dev_addr_t offset;/*offset when map.cnFree check iova statr address*/
	void *phandle;
};

struct kext_addr_t {
	kvirt_t kva;
	int kva_cached;
};

struct vma_priv_t {
	atomic_t refcnt;
	dev_addr_t offset;
	int cached;
	struct mapinfo *minfo;
};

struct mapinfo {
	union {
		struct shm_addr shm_info;
		struct fa_addr_t fa_info;
		struct vmm_addr_t vmm_info;
		struct extn_addr_t extn_info;
		dev_addr_t virt_addr;
	};

	struct kext_addr_t kva_info;

	/**
	 * NOTE: Update 2020/08/09
	 * uva is hiddenned, for HtoD to accelerate in CE platformuva refcnt bound with iova.
	 *
	 * sg_table will be reused in mlu platform, It's will store sg_table cover
	 * the virtual address range this mapinfo standby.
	 **/
	struct sg_table *sg_table;
	user_addr_t uva;
	int uva_cached;
	struct list_head vma_head;
	spinlock_t vma_lock;
	atomic_t map_refcnt;

	unsigned long mdr_peer_addr;
	/*for ipc shared memory*/
	struct ipc_shm_info *ipcm_info;

	unsigned int tgid;/*for performance*/
	unsigned long tag;/*id tag is used to check legality when memory ops*/

	/**
	 * free_flag: bool atomic value (only 0 or 1).
	 * means this address has been freed by memory release interface, not need
	 * call memory_release interface again.
	 **/
	atomic_t free_flag;
	atomic_t refcnt;

	/* only valid while redzone is enabled */
	unsigned long redzone_size;

	struct list_head priv_node;
	struct llist_node free_node;
	struct list_head cp_node;

	struct mem_attr mem_meta;

	unsigned long align_size;
	unsigned long context_id;

	union {
		struct rb_node node;
		/* range tree node: valid while mem_type == MEM_VMM */
		struct range_tree_node_t rnode;
	};

	unsigned int mem_type;  /* fast alloc mem or legency */
	bool is_linear;
	atomic_t async_used;

	struct list_head p2p_remap_list;
	struct list_head obmap_list;
	struct list_head ipcm_list;

	spinlock_t obmap_lock;

	void *mm_set;
	void *mm_priv_data;
	void *udvm_priv;
	void *active_ns;
};

enum {
	SMMU_RMPTYPE_SRAM = 0x1,
	SMMU_RMPTYPE_OS_FORBIDDEN = 0x2,
	SMMU_RMPTYPE_DRAM = 0x3,
};

struct pcie_smmu_ops {
	int (*smmu_cau_invalid) (void *pcore, unsigned int s_id);
	int (*smmu_cau_bypass)(void *pcore, unsigned int s_id, bool en);
	int (*smmu_init) (void *pcore, dev_addr_t, dev_addr_t);
	int (*smmu_release) (void *pcore);
	int (*smmu_add_remap) (void *pcore, dev_addr_t va_addr,  dev_addr_t pa_addr,
					unsigned long size, int type);
	int (*smmu_reset_remap) (void *pcore, dev_addr_t va_addr,  dev_addr_t pa_addr,
					unsigned long size, int type, int flag);
};

struct llc_ops {
	void (*llc_cds_enable) (void *pcore);
	void (*llc_remap_set)(void *pcore, unsigned int remap);
	int (*llc_maintanance)(void *pcore, unsigned int action);
	int (*llc_lock_en)(void *pcore);
	int (*llc_lock_dis)(void *pcore);
	int (*llc_lock_clr)(void *pcore);
	int (*llc_lock_set_ways)(void *pcore, unsigned int ways);
	int (*llc_lock_get_ways)(void *pcore, unsigned int *ways);
	int (*llc_get_irq_info)(void *pcore);
};

struct cn_mm_priv_data {
	struct rb_root mmroot;
	rwlock_t node_lock;
	spinlock_t minfo_lock;
	struct mutex uva_lock;
	unsigned int memcheck_magic;
	atomic_long_t used_size;
	struct list_head priv_list;

	struct list_head udvm_node;
	int udvm_index;
	void *udvm_priv;
	struct list_head minfo_list;
	spinlock_t mmlist_lock;

	atomic64_t mem_lpm_count;
};

struct commu_message_data {
	__le64 tag;
	__le64 iova;
	__le64 type;
};

struct commu_message_buffer {
	__le64 num;
	__le64 data[COMMU_MSG_LE64_NUM];
};

struct peer_free_task_set {
	struct task_struct *wait_msg_thread;
	volatile int exit_flag;
};

struct cn_mem_ext_t {
	dev_addr_t iova_start;
	dev_addr_t iova_end;
	kvirt_t kernel_addr;
	flags_t flag;
	size_t length;
	char name[EXT_NAME_SIZE];
};

struct cn_mem_stat {
	unsigned long phy_total_mem;
	unsigned long phy_used_mem;
	unsigned long fa_total_mem;
	unsigned long fa_used_mem;
	unsigned long fa_require_mem;
	unsigned long fa_alloc_mem;
	unsigned long fa_shrink_size;
	unsigned int fa_chunk_size;
	unsigned int fa_alloc_size;
	unsigned int alloc_order;
	unsigned long fa_dev_total_mem;
	unsigned long fa_dev_used_mem;
	unsigned long ccmalloc_state;
};

struct cn_alloc_align_t {
	unsigned int align_enable;
	unsigned int align_order;
};

enum {
	PPOOL_MODE_DISABLE = 0x0,
	PPOOL_MODE_NORMAL = 0x1,
	PPOOL_MODE_LINEAR = 0x2,
};

struct peer_pool_t {
	dev_addr_t start;
	size_t     total_size;
	size_t     used_size;
	size_t     lru_size;
	rwlock_t   size_lock;
	unsigned int shift;
	struct cn_gen_pool *pool;
	struct cn_mm_set *mm_set;

	struct list_head lru_list;
	spinlock_t peer_lock;
	int mode;
};

static inline const char *__ppool_mode_str(struct peer_pool_t *ppool)
{
	switch (ppool->mode) {
	case PPOOL_MODE_DISABLE:   return "DISABLE";
	case PPOOL_MODE_NORMAL:   return "NORMAL";
	case PPOOL_MODE_LINEAR:   return "LINEAR";
	default: break;
	}
	return NULL;
}

struct linear_info_t {
	dev_addr_t vaddr;
	dev_addr_t paddr;
	unsigned long size;
	bool is_support;
	unsigned int mode;
};

enum fa_remote_ctrl_type{
	FA_RE_CTRL_NONE = 0,
	FA_RE_CTRL_SERVER,/*which is device*/
	FA_RE_CTRL_CLIENT,/*which is host*/
};

struct mem_perf_set {
	struct cn_mm_set *mm_set;
	u64 tgid_count;
	atomic64_t seq_id;
	struct rw_semaphore rwsem;
	struct list_head head;
};

struct cn_mm_set {
	void	*core;
	void	*client;
	/* for config shared memory */
	struct mempool_t	hostpool;
	/* for data shared memory axi addr*/
	struct mempool_t	hostpool_l;
	struct mempool_t	hostpool_h;
	/* for device shared memory */
	struct mempool_t	devpool;

	struct mempool_t	sram_pool;
	dev_addr_t sram_virt_base;/*to get sram iova*/

	struct peer_pool_t  ppool;
	struct linear_info_t linear;
	dev_addr_t	dev_virt_base;
	/* same as core->dev_id*/
	unsigned int devid;
	/* for cambricon_devx private data */
	struct cn_mm_priv_data mm_priv_data;
	spinlock_t ffl_lock;
	struct list_head free_failure_list;
	struct list_head shm_rsrv_list;
	/* for ipc shared memory */
	spinlock_t ipcm_lock;
	struct list_head ipcm_head;
	/* for delay free management */
	struct llist_head free_list;
	atomic_t free_mem_cnt;
	atomic_t timer_hot;
	struct hrtimer hrtimer;
	ktime_t time_delay;
	/* for fast alloc memory watermark management */
	struct timer_list watermark_timer;
	struct work_struct fa_water_worker;
	/**
	 * NOTE: we will do cn_fa_shrink after the last process exit, if
	 * fa_watermark_dis is setting, disable fa watermark timer and workqueue.
	 **/
	bool fa_watermark_dis;

	/**
	 * NOTE: fa_remote_ctrl means use host fa (as FA_RE_CTRL_CLIENT) to ctrl
	 * device fa (as FA_RE_CTRL_SERVER). FA_RE_CTRL_NONE means no this relation
	 * in current platform.
	 **/
	int fa_remote_ctrl;

	struct work_struct free_worker;
	atomic_t free_worker_state;
	atomic_t rpc_free_times;
	spinlock_t work_sync_lock;
	/* for cnmon memory information display */
	unsigned long phy_total_mem;
	unsigned long phy_used_mem;
	unsigned long vir_total_mem;
	unsigned long vir_used_mem;
	/* for fast alloc memory */
	struct cn_fa_array *fa_array;
	/* for hardware level */
	struct pcie_smmu_ops smmu_ops;
	unsigned long pcie_reg_size;
	unsigned long pcie_mem_size;
	struct llc_ops llc_ops;
	/* for ipcm/commu channel */
	void *endpoint;
	void *mem_async_endpoint;
	/* for peer free */
	bool peer_free_enable;
	struct commu_endpoint *peer_free_endpoint;
	struct peer_free_task_set peer_free_task;
	/* for pcie smmu invalid management */
	unsigned long smmu_invalid_mask;
	/* for proc dfx */
	atomic_t proc_set;
	unsigned long df_mem_size;
	unsigned long df_mem_cnt;
	bool is_dump_meminfo;
	/* for page retirement management */
	bool pgretire_enable;
	/* set true while the platform host side enable pageRetire */
	bool pgretire_server_enable;
	int pgretire_ret;
	host_addr_t pgretire_buf;
	atomic_t pgretire_status;
	atomic_t pgretire_again;
	unsigned int pgretire_counts;

	struct cn_alloc_align_t alloc_align;
	bool numa_enable;

	spinlock_t vmm_pid_lock;
	struct list_head vmm_pid_head;
	bool vmm_enable;

	struct free_ts_root free_ts;

	bool mdr_in_shm;
	/* Decide to flush the L1C(IPU) or not when the date of the iova allocated
	 * as a constant memory has been changed.
	 * And it will be disable as default. It will be used only in the mlu590
	 * platform. */
	bool notify_l1c_sync;
	bool compress_support;
	bool enable_compress_alloc;
	bool separate_support;
	bool obmap_support;
	struct mem_perf_set *perf_set;
	int lvl1_size;
	int lvl2_size;
};

extern const struct vm_operations_struct camb_vma_dummy_ops;

/* used in cndrv_buddy_allocator.h */
int camb_free_mem_rpc(struct cn_mm_set *mm_set, unsigned int type,
					  dev_addr_t device_addr, dev_addr_t mdr_addr,
					  size_t size, struct ret_msg *remsg,
					  bool use_ccache);

int camb_fa_ctrl(void *mem_set, unsigned int en);

int camb_mem_df_ctrl(void *mem_set, unsigned int flag);

int camb_mem_cc_ctrl(void *mem_set, unsigned int flag);

int camb_mem_snapshot_ctrl(void *mem_set);

int camb_kref_get(u64 tag, dev_addr_t device_vaddr,
		struct mapinfo **minfo, struct cn_mm_set *mm_set);

int camb_kref_get_without_vmm_check(u64 tag, dev_addr_t device_vaddr,
		struct mapinfo **minfo, struct cn_mm_set *mm_set);

unsigned int camb_kref_put(struct mapinfo *pminfo,
		int (*release)(struct mapinfo *pminfo));

int camb_mem_release(struct mapinfo *pminfo);

struct cn_mm_priv_data *__get_mm_priv(struct file *fp, struct cn_mm_set *mm_set);

int mapinfo_release(struct mapinfo *pminfo);

void camb_init_mapinfo_basic(struct mapinfo *minfo, struct cn_mm_set *mm_set, u64 tag);

int camb_priv_data_list_release(struct cn_mm_priv_data *mm_priv_data);

void camb_priv_data_rbtree_release(struct cn_mm_priv_data *mm_priv_data,
							   void *mem_set, u64 tag);

int camb_shm_do_exit(u64 tag, void *mem_set);

void camb_peer_free_exit(void *pcore);

int camb_peer_free_init(void *pcore);

int camb_peer_free_msg_list_clear(u64 tag, void *mem_set);

#ifdef PEER_FREE_TEST
int camb_peer_free_test(u64 tag, dev_addr_t test_flag, dev_addr_t *virt_addr,
		int cnt, void *pcore);
#endif

struct shm_rsrv_priv *
__shm_get_handle_by_name(void *mem_set, unsigned char *name);

char *__shm_get_name_by_dev_vaddr(void *mem_set, dev_addr_t dev_vaddr);

int camb_mem_fa_dev_ctrl(void *mem_set, unsigned int flag);

int camb_call_mem_ob_ctl_rpc(struct cn_mm_set *mm_set,
		struct mem_ob_ctrl *ctrl_info, struct ret_msg *remsg);

int camb_mem_fa_dev_mask_chunks(void *mem_set);

int camb_mem_statistics(void *mem_set, struct cn_mem_stat *mem_stat);

int camb_dob_iova_alloc(dev_addr_t *iova, dev_addr_t *device_pa, size_t size, struct sg_table *table);

int camb_dob_dev_mem_alloc(dev_addr_t *device_pa, dev_addr_t *iova, size_t size,
		struct sg_table *table, void *mem_set);

int camb_dob_iova_free(u64 iova, size_t size);

void camb_ob_iova_exit(void);

int camb_dob_dev_mem_free(u64 iova, dev_addr_t dev_phy_addr, size_t size, void *mem_set);

int camb_init_vma_priv_data(struct vm_area_struct *vma,
		struct mapinfo *minfo, unsigned long offset, int cached);

int camb_device_share_mem_alloc(host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, phys_addr_t *phyaddr, size_t size,
		size_t align, void *mem_set);

int camb_mem_alloc_internal(u64 tag, dev_addr_t *device_vaddr,
		struct mem_attr *pattr, void *mem_set, struct mapinfo **ppminfo);

int camb_mem_trigger_pgretire_rpc(void *mem_set);

int camb_mem_switch_linear_mode_rpc(void *mem_set, int mode);

int camb_mem_switch_linear_compress_rpc(void *mem_set, int mode);

int camb_mem_ipc_get_handle(u64 tag, dev_addr_t dev_vaddr, int mode,
		dev_ipc_handle_t *handle);

int camb_mem_ipc_open_handle(u64 tag, struct mapinfo *ppminfo,
		dev_addr_t *dev_vaddr);

int camb_mem_ipc_close_handle(u64 tag, dev_addr_t virt_addr);

int camb_sram_alloc_internal(u64 tag, host_addr_t *host_vaddr,
		dev_addr_t *device_vaddr, phy_addr_t *phy_addr,
		size_t size, void *pcore, void *caller);

int camb_vma_is_dummy(struct vm_area_struct *vma);

int camb_fill_mapinfo_sgtable(struct mapinfo *pminfo);

size_t camb_get_page_size(void);

unsigned int camb_mem_put_release(u64 tag,
		dev_addr_t device_vaddr, void *mem_set);

int camb_ipc_shm_get_handle(u64 tag,
		dev_ipc_handle_t *handle, dev_addr_t dev_vaddr, void *mem_set);

int camb_ipc_shm_open_handle(u64 tag,
		dev_ipc_handle_t handle, dev_addr_t *dev_vaddr, void *mem_set);

int camb_ipc_shm_close_handle(u64 tag, dev_addr_t virt_addr, void *mem_set);

int camb_get_mem_range(u64 tag, dev_addr_t device_vaddr,
		dev_addr_t *base, ssize_t *size, void *mem_set);

int camb_mem_info_adj(void *pcore, unsigned int dir, unsigned long size);

int camb_mem_get_ipu_resv(u64 tag,
		struct ipu_mem_addr_get *ipu_mem_addr, void *mem_set);

int camb_mem_get_attributes(u64 tag,
		dev_addr_t addr, __u64 *data, void *mem_set);

int camb_host_mem_check(host_addr_t host_vaddr, size_t size);

int camb_mem_check_without_ref(unsigned long tag,
		unsigned long device_vaddr, unsigned long size, void *mm_set);

int camb_rst_pst_l2cache(u64 tag, void *mem_set);

int camb_mem_enable_memcheck(u64 tag, unsigned int magic, void *mem_set);

int camb_mem_lpm_get(void *user, struct cn_core_set *core);
void camb_mem_lpm_put(void *user, struct cn_core_set *core);

int camb_peer_register(u64 tag, struct cn_mm_set *lmset, dev_addr_t addr, size_t size,
			struct cn_mm_set *rmset, u32 flags);

int camb_peer_unregister(u64 tag, struct cn_mm_set *lmset, dev_addr_t addr,
			struct cn_mm_set *rmset);

int camb_peer_get_pointer(u64 tag, struct cn_mm_set *lmset, dev_addr_t addr, struct cn_mm_set *rmset,
			dev_addr_t *oaddr, u32 flags);

void mempool_destroy(struct mempool_t *pool);
int mempool_init(struct mempool_t *pool, host_addr_t virt,
			phys_addr_t phys, unsigned long size, struct cn_mm_set *mm_set);
int mempool_add_pool(struct mempool_t *pool, int min_alloc_order, unsigned long virt,
				phys_addr_t phys, unsigned long size, struct cn_mm_set *mm_set);

static inline void *__get_mmset_with_index(int index)
{
	struct cn_core_set *core =
		(struct cn_core_set *)cn_core_get_with_idx(index);

	return (!core || core->state != CN_RUNNING) ? NULL : core->mm_set;
}

/* params_check function  */
static inline int
__params_check_range(struct mapinfo *pminfo, dev_addr_t addr, unsigned long size)
{
	struct cn_mm_set *mm_set = pminfo->mm_set;
	/**
	 * BUG: DRIVER-8182, check size is necessary. only check addr + size can't
	 * cover input size is negative value.
	 **/
	if (size > pminfo->mem_meta.size) {
		cn_dev_core_err((struct cn_core_set *)mm_set->core,
						"OutOfBound: size input(%#lx) is bigger than allocated(%#lx)",
						size, pminfo->mem_meta.size);
		return -ENXIO;
	}

	if ((addr + size) > (pminfo->virt_addr + pminfo->mem_meta.size)) {
		cn_dev_core_err((struct cn_core_set *)mm_set->core,
						"OutOfBound: input(bs:%#llx sz:%#lx), search(bs:%#llx sz:%#lx) not match!",
						addr, size, pminfo->virt_addr, pminfo->mem_meta.size);
		return -ENXIO;
	}

	return 0;
}

static inline int
__params_check_addr_equal(struct mapinfo *pminfo, dev_addr_t addr)
{
	struct cn_mm_set *mm_set = pminfo->mm_set;

	if (pminfo->mem_type == MEM_IE) {
		if (addr != (pminfo->extn_info.vaddr + pminfo->extn_info.offset)) {
			cn_dev_core_err((struct cn_core_set *)mm_set->core,
					"AddressNotEqual: input(bs:%#llx), search(bs:%#llx) not match!",
					addr, pminfo->virt_addr);
			return -ENXIO;
		}

		return 0;
	}

	if (addr != pminfo->virt_addr) {
		cn_dev_core_err((struct cn_core_set *)mm_set->core,
						"AddressNotEqual: input(bs:%#llx), search(bs:%#llx) not match!",
						addr, pminfo->virt_addr);
		return -ENXIO;
	}

	return 0;
}

static inline int
__params_check_size_equal(struct mapinfo *pminfo, unsigned long size)
{
	struct cn_mm_set *mm_set = pminfo->mm_set;

	if (size != pminfo->mem_meta.size) {
		cn_dev_core_err((struct cn_core_set *)mm_set->core,
						"SizeNotEqual: input(sz:%#lx), search(sz:%#lx) not equal!",
						size, pminfo->mem_meta.size);
		return -ENXIO;
	}

	return 0;
}

static inline int
__params_check_equal(struct mapinfo *pminfo, dev_addr_t addr,
					 unsigned long size)
{
	int ret = 0;

	ret = __params_check_addr_equal(pminfo, addr);
	if (ret)
		return ret;

	ret = __params_check_size_equal(pminfo, size);
	if (ret)
		return ret;

	return 0;
}

#endif /*__CAMBRICON_MM_H__*/
