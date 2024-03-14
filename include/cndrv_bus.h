/************************************************************************
 *  @file cndrv_bus.h
 *
 *  @brief For pcie support definitions.
 **************************************************************************/

/*************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ***************************************************************************/

#ifndef __CNDRV_BUS_H
#define __CNDRV_BUS_H

#include <linux/interrupt.h>
#include <linux/scatterlist.h>

#define INTERRUPT_IRQ_NUM                (512)
#define MLUMSG_SHM_SIZE                  (0x100000 - 24)
#define REG_VALUE_INVALID                (0xFFFFFFFF)

#define P2P_HOST_TRANSFER                (-1)
#define P2P_FAST_ABLE                    (1)
#define P2P_NO_COMMON_UPSTREAM_BRIDGE    (2)
#define P2P_ACS_OPEN                     (3)

#define DMA_RELEASE_TASK                 (1)
#define DMA_HOST_TRIGGER                 (2)
#define MAX_BATCH_NUM                    (8)

#define TCDP_DIR_RX                      (0x1)
#define TCDP_DIR_TX                      (0x2)
#define TCDP_CHAN_ON                     (1)
#define TCDP_CHAN_OFF                    (0)

#define TRANSFER_INIT(t, h, d, s, dir) \
{\
	t.ca = h; \
	t.ia = d; \
	t.size = s; \
	t.direction = dir; \
}

#define MEMSET_INIT(t, v, d, n, dir) \
{ \
	t.val = v; \
	t.dev_addr = d; \
	t.number = n; \
	t.direction = dir; \
}

typedef irqreturn_t (*interrupt_cb_t)(int irq, void *data);

typedef enum {
	DMA_H2D = 0,
	DMA_D2H,
	DMA_P2P,
	MEMSET_D8,
	MEMSET_D16,
	MEMSET_D32,
	DMA_D2D,
	DMA_RANDOM,
	DMA_D2D_2D,
	DMA_D2D_3D,
	DMA_DATA_TYPE,
} DMA_DIR_TYPE;

struct transfer_s {
	union {
		struct {
			unsigned long ca;  /* host addr */
			u64 ia;      /* device addr */
		};
		struct {
			u64 d_bar;   /* p2p or d2d */
			u64 d_ipu;   /* p2p or d2d */
		};
	};
	size_t size;
	void *bus_set; /* only used in async memcpy */
	void *pminfo;
	DMA_DIR_TYPE direction;

	u64 tags;
	u64 index;
	u64 user;
};

struct peer_s {
	void *src_minfo;
	void *src_bus_set;
	u64 src_addr;
	void *dst_minfo;
	void *dst_bus_set;
	u64 dst_addr;
	size_t size;

	/* async p2p */
	u64 tags;
	u64 index;
	u64 user;
};

struct memset_s {
	unsigned int val; /* use max length */
	u64 dev_addr;	/* dev addr */
	size_t number;
	void *bus_set; /* only used in async memcpy */
	void *pminfo;
	DMA_DIR_TYPE direction;

	u64 tags;
	u64 index;
	u64 user;
};

struct dma_info_s {
    	u64 dma_data_total[2];
};

enum dma_async_status_type {
	/*
	 * notice: need agree with copyengine
	 */
	DMA_TASK_INIT = 0,
	DMA_TASK_CFGTASK_FINISH = 2,
	DMA_TASK_FINISH = 19,
	/* 0 - 19 is normal status */
	DMA_TASK_PCIE_NOT_FINISH_START = 20,
	DMA_TASK_WAIT_P2P_PULL = DMA_TASK_PCIE_NOT_FINISH_START,
	/* 20 - 29 is pcie internal intermediate code */
	DMA_TASK_SBTS_ERR_START = 30,
	DMA_TASK_SBTS_ERR_CFGTASK_ERR,
	DMA_TASK_SBTS_ERR_TRIGGER_FAIL,
	/* 30 - 59 is sbts internal err code */
	DMA_TASK_PCIE_ERR_START = 60,
	DMA_TASK_FINISH_ERR = DMA_TASK_PCIE_ERR_START,
	/* 60 - ... pcie err code */
};

struct dma_async_ack_desc {
	__le64 dma_start_ns;
	__le64 dma_finish_ns;
	__le64 status;
};

struct trigger_task_info {
	u64 index;
};

struct arm_trigger_message {
	u64 tags;
	u32 trigger_type;
	u32 task_num;
	struct trigger_task_info task_info[MAX_BATCH_NUM];
};

enum async_reason {
	/* 0 - 10 is device trigger */
	ASYNC_REASON_INIT = 0,
	ASYNC_REASON_DEVICE_H2D_D2H,
	ASYNC_REASON_DEVICE_P2P,
	ASYNC_REASON_DEVICE_MEMSET,
	/* 20 - 39 is host trigger common reason */
	ASYNC_REASON_HOST_COMMON_START = 20,
	ASYNC_REASON_DEVICE_DISABLE = ASYNC_REASON_HOST_COMMON_START,
	ASYNC_REASON_DEVICE_NOTSUPPORT,
	ASYNC_REASON_STREAM_INVALID,
	ASYNC_REASON_DESC_NOT_ENOUGH,
	ASYNC_REASON_SYNC_PAGEABLE_MEM = 24,
	/* 40 - 59 is host trigger h2d d2h reason */
	ASYNC_REASON_HOST_H2D_D2H_START = 40,
	ASYNC_REASON_H2D_D2H_NOT_PINNED = ASYNC_REASON_HOST_H2D_D2H_START,
	ASYNC_REASON_H2D_D2H_GET_DESC_NUM_ERR,
	ASYNC_REASON_H2D_D2H_GET_PAGES_ERR,
	ASYNC_REASON_H2D_D2H_UP_SGL_ERR,
	ASYNC_REASON_H2D_D2H_FILL_DESC_ERR,
	/* 60 - ... is host trigger p2p reason*/
	ASYNC_REASON_HOST_P2P_START = 60,
	ASYNC_REASON_P2P_HOST_TRANSFER = ASYNC_REASON_HOST_P2P_START,
	ASYNC_REASON_P2P_EXCEED_SIZE,
	ASYNC_REASON_P2P_LINEAR_REMAP_ERR,
	ASYNC_REASON_P2P_UP_SGL_ERR,
	ASYNC_REASON_P2P_FILL_DESC_ERR,
	ASYNC_REASON_P2P_FILL_PULL_DESC_ERR,
	/* if add new item, then should sync with cndrv_perf_usr.h  */
};

struct dma_async_info_s {
	u64 tags;
	u64 index;

	/* in p2p mode this is src addr */
	/* in memset mode this is value */
	u64 host_vaddr;
	/* in p2p mode this is dst addr */
	u64 device_vaddr;
	u64 total_size;
	int direction;
	enum async_reason reason;

	/* arm trigger flag */
	u64 desc_device_va;
	int desc_len;
	/* ack addr when task finish */
	u64 ack_host_va;
};

struct bar_s {
	u64 bar_base;
	u64 bar_sz;
};

struct bar_info_s {
	struct bar_s bar[6];
};

struct int_occur_info_s {
	u64 int_occur_count[INTERRUPT_IRQ_NUM];
};

struct dma_channel_info_s {
	int phy_channel;
	int spkg_phy_channel;
	int sh_virt_channel;
	int priv_virt_channel;
	int async_desc_resource;
	int async_task_resource;
	int normal_task_resource;
};

struct async_proc_info_s {
	u64 arm_trigger_dma_cnt;
	u64 host_trigger_dma_cnt;
	u64 arm_trigger_p2p_cnt;
	u64 host_trigger_p2p_cnt;
};

struct pcie_atomicop_info_s {
	int atomicop_support;
	u64 atomicop_host_va;
	u64 atomicop_dev_va;
	u32 atomicop_desc_cnt;
};

typedef enum {
	CN_SHARE_MEM_DEV,
	CN_SHARE_MEM_HOST,
	CN_SHARE_MEM_HOST_DATA,
} CN_MEM_TYPE;

typedef enum {
	BUS_TYPE_PCIE,
	BUS_TYPE_EDGE,
} bus_type_t;

struct bus_info_s {
	u8 bus_type;
	union {
		struct {
			u16 device_id;
			u16 vendor;
			u16 subsystem_vendor;
			u16 bus_num;
			u16 device;
			u16 domain_id;
			u16 mps;
			u16 mrrs;
		} pcie;

		struct {
			u16 device_id;
			u16 vendor;
			u16 subsystem_vendor;
			u16 device;
			u16 domain_id;
		} edge;
	} info;
};

struct pci_bdf_info_s {
	int domain_nr;
	u32 bus_num;
	u32 devfn;
};

struct bus_lnkcap_info {
	u16 speed;
	u16 width;
	u16 min_speed;
	u16 min_width;
};

struct dma_config_t {
	u32                  phy_dma_mask;
	int                  phy_mode;
};

struct p2p_stat {
	u16 x;
	u16 y;
	int able;
};

struct sync_write_info {
	u32 sw_id;
	int status;
	u64 sw_trigger_pa;
	unsigned long sw_trigger_kva;
	u64 sw_flag_pa;
	u32 sw_trigger_count;
};

/* enumerated value for outbound window type */
enum outb_win_type {
	OUTB_WIN_CFG = 1,
	OUTB_WIN_DATA,
};

struct p2pshm_attr {
	int reg_type;
	enum outb_win_type win_type;
	__u8 outb_win_idx;
	__u64 outb_win_dev_pa;
	__u64 outb_win_sz;

	__u64 shm_pci_bus_addr;
	__u64 shm_cpu_phy_addr;
	void *shm_host_kva;
	__u64 shm_dev_va;
	__u32 shm_sz;
	__u8 single_copy_min_sz;
	__u8 single_copy_max_sz;
	struct device *dev;
};

struct outbound_set {
	void __iomem *virt_addr;
	unsigned long win_length;
	u64 ob_axi_base;
};

struct domain_resource {
	int id;
	int max_phy_channel;
	u64 vf_cfg_limit;
	u64 cfg_reg_size;
	u64 share_mem_base;
	u64 share_mem_size;
	u64 ob_mask;
	u64 sram_pa_base;
	u64 sram_pa_size;
	struct outbound_set ob_set[1];
	u64 large_bar_base;
	u64 large_bar_size;
	u32 bdf;
};

struct cn_bus_set {
	void *priv;
	struct cn_core_set *core;
	void *rsv_set;
	bool thread_exit;
	struct task_struct *heartbeat_thread;
	struct bus_ops *ops;
	int (*setup)(void *priv);
	int (*pre_init)(void *priv);
	int (*pre_exit)(void *priv);
	int (*get_resource)(void *priv, struct domain_resource *get_resource);

	/*bug report dfx*/
	struct cn_report_block *bus_report;
};

struct cn_bus_driver {
	int (*probe)(struct cn_bus_set *bus_set, u64 device_id, u8 type, int idx);
	int (*remove)(void *core_data);
	void (*shutdown)(void *core_data);
	int (*suspend)(void *core_data, u64 state);
	int (*resume)(void *core_data);
};

struct bus_ops {
	/* init functions */
	int (*post_init)(void *priv, void *bus_set);
	void (*post_exit)(void *priv);
	int (*late_init)(void *priv);
	int (*late_exit)(void *priv);
	int (*set_bus)(void *priv, void *bus_set);

	/* register space */
	void (*reg_write32)(void *priv, unsigned long offset, unsigned int val);
	unsigned int (*reg_read32)(void *priv, unsigned long offset);
	void (*mem_mb)(void *priv);
	unsigned long (*get_reg_size)(void *priv);
	void * (*get_reg_base)(void *priv);
	unsigned long (*get_reg_phyaddr)(void *priv);

	/* sharememory */
	void (*mem_write32)(void *priv, unsigned long offset, unsigned int val);
	unsigned int (*mem_read32)(void *priv, unsigned long offset);
	int (*get_mem_cnt)(void *priv);
	size_t (*get_mem_size)(void *priv, int index);
	void *(*get_mem_base)(void *priv, int index);
	unsigned long (*get_mem_phyaddr)(void *priv, int index);
	unsigned long (*get_mem_virtaddr)(void *priv, int index);
	CN_MEM_TYPE(*get_mem_type)(void *priv, int index);
	u64 (*get_device_addr)(void *priv, int index);

	/* outbound */
	int (*outbound_able)(void *priv);
	u32 (*outbound_size)(void *priv);
	struct page *(*get_outbound_pages)(void *priv, int index);
	int (*get_dob_win_info)(void *priv,
			int *lvl1_pg, int *lvl1_pg_cnt, u64 *lvl1_base,
			int *lvl2_pg, int *lvl2_pg_cnt, u64 *lvl2_base);
	void *(*dob_win_alloc)(void *priv, u64 device_addr, size_t size);
	void (*dob_win_free)(void *priv, u64 device_addr);
	int (*get_dob_iova)(void *priv_src, void *priv_dst,
			u64 dob_pa, size_t size, struct sg_table **iova_sgt);
	void (*put_dob_iova)(void *priv_dst, struct sg_table **iova_sgt);

	/* bar memcpy */
	int (*bar_copy_h2d)(void *priv, u64 d_addr, unsigned long h_addr, size_t len);
	int (*bar_copy_d2h)(void *priv, u64 d_addr, unsigned long h_addr, size_t len);
	int (*copy_to_usr_fromio)(u64 dst, u64 src, size_t size, void *priv);
	int (*copy_from_usr_toio)(u64 dst, u64 src, size_t size, void *priv);

	/* sync memcpy */
	size_t (*dma)(struct transfer_s *transfer, void *priv);
	size_t (*dma_cfg)(struct transfer_s *transfer,
			struct dma_config_t *cfg, void *priv);
	size_t (*dma_remote)(struct transfer_s *transfer,
			struct task_struct *tsk, struct mm_struct *tsk_mm, void *priv);
	size_t (*dma_kernel)(unsigned long host_addr, u64 device_addr,
			size_t count, DMA_DIR_TYPE direction, void *priv);
	size_t (*dma_kernel_cfg)(unsigned long host_addr, u64 device_addr,
			size_t count, DMA_DIR_TYPE direction,
			struct dma_config_t *cfg, void *priv);
	size_t (*dma_p2p)(struct peer_s *peer);
	int (*dma_p2p_able)(void *priv_src, void *priv_dst);
	int (*dma_memset)(void *pcie_priv, struct memset_s *t);
	size_t (*boot_image)(unsigned long host_addr, u64 device_addr,
			size_t count, void *priv);
	size_t (*check_image)(unsigned char *host_data, u64 device_addr,
			size_t count, void *priv);
	int (*dma_bypass_smmu_all)(void *priv, bool en);

	/* async memcopy */
	size_t (*dma_async)(struct transfer_s *transfer,
			struct dma_async_info_s **async_info, void *priv);
	size_t (*dma_p2p_async)(struct peer_s *peer,
			struct dma_async_info_s **async_info, void *priv_src);
	int (*dma_memset_async)(struct memset_s *transfer,
			struct dma_async_info_s **async_info, void *priv);
	int (*dma_async_message_process)(void *priv, struct arm_trigger_message *message);
	int (*dma_abort)(u64 tags, u64 index, void *priv);

	/* interrupt */
	int (*enable_irq)(int irq_hw, void *priv);
	int (*disable_irq)(int irq_hw, void *priv);
	void (*disable_all_irqs)(void *priv);
	int (*register_interrupt)(int irq_hw,
			interrupt_cb_t handler, void *data, void *priv);
	void (*unregister_interrupt)(int irq_hw, void *priv);
	int (*get_irq_by_desc)(void *priv, char *irq_desc);

	/* sync write */
	int (*sync_write_able)(void *priv);
	int (*sync_write_alloc)(void *priv, u64 flag_dev_pa);
	void (*sync_write_free)(void *priv, u64 flag_dev_pa);
	void (*sync_write_trigger)(void *priv, u64 dev_pa, u32 val);
	void (*sync_write_info)(void *priv, struct sync_write_info *sw_info);

	/* atomicop */
	int (*get_pcie_atomicop_support)(void *priv);
	int (*get_pcie_atomicop_info)(void *priv, struct pcie_atomicop_info_s *info);

	/* tcdp */
	int (*get_tcdp_able)(void *priv);
	u64 (*get_tcdp_win_base)(void *priv);
	u64 (*get_tcdp_win_size)(void *priv);
	int (*tcdp_link_on_able)(void *priv_src, void *priv_dst);
	u64 (*get_tcdp_host_buff)(void *priv);
	void (*tcdp_qp0_wrhost_enable)(void *priv);
	void (*tcdp_qp0_wrhost_disable)(void *priv);
	int (*tcdp_tx_dir_linear_bar_cfg)(void *priv,
			int tx_card, int rx_card, u64 rx_liner_bar_bus_base,
			u64 rx_liner_bar_axi_base, u64 rx_liner_bar_size);
	u64 (*tcdp_win_base_do_iommu_remap)(void *pcie_priv_src,
			void *pcie_priv_dst, int card_id, int rcard_id);
	int (*tcdp_txrx_indir_cfg)(void *priv,
			int tx_card, int rx_card, u64 rx_tcdp_win_bus_base);
	int (*tcdp_change_channel_state)(void *pcie_priv, int rcard_id, int dir, int state);

	/* linear bar */
	u64 (*get_linear_bar_bus_base)(void *priv);
	u64 (*get_linear_bar_phy_base)(void *priv);
	u64 (*get_linear_bar_size)(void *priv);
	u64 (*get_linear_bar_axi_base)(void *priv);
	u64 (*get_linear_bar_offset)(void *priv);
	u64 (*linear_bar_do_iommu_remap)(void *pcie_priv_src,
			void *pcie_priv_dst, int card_id, int rcard_id);

	/* PCI Express basic */
	struct device *(*get_dev)(void *priv);
	u32 (*get_bus_bdf)(void *bus_set);
	u32 (*get_current_bdf)(void *bus_set);
	int (*set_bus_bdf)(void *bus_set, u32 bdf);
	int (*set_cspeed)(unsigned int cspeed, void *priv);
	int (*soft_reset)(void *priv, bool reset);
	int (*check_available)(void *priv);
	int (*get_bus_lnkcap)(void *priv, struct bus_lnkcap_info *lnk_info);
	int (*get_bus_curlnk)(void *priv, struct bus_lnkcap_info *lnk_info);

	/* virtual function */
	int (*get_vf_idx)(void *pf_priv, void *vf_priv);
	struct device *(*get_vf_dev)(void *priv, int vf_idx);
	bool (*check_pdev_virtfn)(void *priv);
	/* mim */
	int (*enable_sriov)(void *pcie_priv, int num_of_vf);
	int (*disable_sriov)(void *pcie_priv);
	int (*is_sriov_enable)(void *pcie_priv);
	int (*get_pci_virtfn_bdf_info)(void *priv, int domain_id,
					struct pci_bdf_info_s *bdf_info);
	int (*probe_mi)(void *pcie_priv, int domain_id);
	int (*remove_mi)(void *pcie_priv, int domain_id);

	/* get info */
	int (*pcie_sram_able)(void *priv);
	int (*get_bus_info)(void *priv, struct bus_info_s *bus_info);
	int (*get_dma_info)(void *priv, struct dma_info_s *dma_info);
	int (*get_bar_info)(void *priv, struct bar_info_s *bar_info);
	int (*get_p2pshm_info)(void *priv, struct p2pshm_attr *attr);
	int (*get_pcie_fw_info)(void *priv, u64 *pcie_fw_info);
	void (*show_info)(void *priv);
	void (*debug_dump_reg)(void *priv);

	/* proc info */
	void (*get_p2p_able_info)(void *priv, struct p2p_stat *able, int *index);
	int (*inbound_cnt)(void *priv);
	u32 (*heartbeat_cnt)(void *priv);
	u32 (*soft_retry_cnt)(void *priv);
	u32 (*get_p2p_exchg_cnt)(void *priv);
	int (*get_async_proc_info)(void *priv, struct async_proc_info_s *async_proc_info);
	int (*get_dma_channel_info)(void *priv, struct dma_channel_info_s *dma_channel_info);
	int (*dump_dma_info)(void *priv);
	int (*get_async_htable)(void *priv);
	int (*interrupt_info)(void *priv, struct int_occur_info_s *int_occur_info);
	u32 (*non_align_cnt)(void *priv);
	int (*get_isr_type)(void *priv);
	u32 (*get_device_ko_bootinfo)(void *priv);

	/* dfx */
	int (*dma_af_ctrl)(void *priv, unsigned int enable);
	int (*force_p2p_xchg)(void *priv, int force);
	int (*dma_des_set)(void *priv, unsigned int value);
	int (*set_dma_err_inject_flag)(void *priv, int data);
	int (*get_bug_report)(void *pcie_priv, unsigned long action, void *fp);
	int (*pll_irq_sts_dump)(void *pcie_priv);

	/* others */
	int (*mlu_mem_client_init)(void *priv);
	int (*core_type_switch)(void *priv, __u32 policy);
};

/* functions */
/* init functions */
int cn_bus_driver_reg(void);
void cn_bus_driver_unreg(void);
int cn_bus_init(struct cn_core_set *core);
void cn_bus_exit(struct cn_core_set *core);
int cn_bus_late_init(struct cn_core_set *core);
void cn_bus_late_exit(struct cn_core_set *core);
int cn_bus_set_stru_init(struct cn_core_set *core);
void cn_bus_set_stru_exit(struct cn_core_set *core);
struct cn_bus_set *cn_bus_set_init(void *priv, struct device *dev,
		struct bus_ops *ops, int (*setup)(void *priv),
		int (*pre_init)(void *priv), int (*pre_exit)(void *priv),
		int (*get_resource)(void *priv, struct domain_resource *get_resource));
void cn_bus_set_exit(struct cn_bus_set *bus_set, struct device *dev);
int cn_bus_probe(struct cn_bus_set *bus, u64 id, u8 type, int idx);
int cn_bus_remove(struct cn_bus_set *bus_set, u64 device_id);
void cn_bus_shutdown(struct cn_bus_set *bus_set);
int cn_bus_suspend(struct cn_bus_set *bus_set, u64 state);
int cn_bus_resume(struct cn_bus_set *bus_set);

/* register space */
void reg_write32(void *bus_set, unsigned long offset, u32 val);
u32 reg_read32(void *bus_set, unsigned long offset);
void cn_bus_mb(struct cn_bus_set *bus_set);
size_t cn_bus_get_reg_size(struct cn_bus_set *bus_set);
void *cn_bus_get_reg_base(struct cn_bus_set *bus_set);
unsigned long cn_bus_get_reg_phyaddr(struct cn_bus_set *bus_set);

/* sharememory */
void mem_write32(void *bus_set, unsigned long offset, unsigned int val);
u32 mem_read32(void *bus_set, unsigned long offset);
int cn_bus_get_mem_cnt(struct cn_bus_set *bus_set);
size_t cn_bus_get_mem_size(struct cn_bus_set *bus_set, int index);
void *cn_bus_get_mem_base(struct cn_bus_set *bus_set, int index);
unsigned long cn_bus_get_mem_phyaddr(struct cn_bus_set *bus_set, int index);
unsigned long cn_bus_get_mem_virtaddr(struct cn_bus_set *bus_set, int index);
CN_MEM_TYPE cn_bus_get_mem_type(struct cn_bus_set *bus_set, int index);
u64 cn_bus_get_device_addr(struct cn_bus_set *bus_set, int index);

/* outbound */
int cn_bus_outbound_able(struct cn_bus_set *bus_set);
u32 cn_bus_get_outbound_size(struct cn_bus_set *bus_set);
struct page *cn_bus_get_outbound_pages(struct cn_bus_set *bus_set, int index);
int cn_bus_get_dob_win_info(struct cn_bus_set *bus_set,
		int *lvl1_pg, int *lvl1_pg_cnt, u64 *lvl1_base,
		int *lvl2_pg, int *lvl2_pg_cnt, u64 *lvl2_base);
void *cn_bus_dob_win_alloc(struct cn_bus_set *bus_set, u64 device_addr, size_t size);
void cn_bus_dob_win_free(struct cn_bus_set *bus_set, u64 device_addr);
int cn_bus_get_dob_iova(struct cn_bus_set *bus_set_src, struct cn_bus_set *bus_set_dst,
		u64 dob_pa, size_t size, struct sg_table **iova_sgt);
void cn_bus_put_dob_iova(struct cn_bus_set *bus_set_dst, struct sg_table **iova_sgt);

/* bar memcpy */
int cn_bus_bar_copy_h2d(struct cn_bus_set *bus_set, u64 d_addr, unsigned long h_addr, size_t len);
int cn_bus_bar_copy_d2h(struct cn_bus_set *bus_set, u64 d_addr, unsigned long h_addr, size_t len);
int cn_bus_copy_from_usr_toio(u64 dst, u64 src, size_t size, struct cn_bus_set *bus_set);
int cn_bus_copy_to_usr_fromio(u64 dst, u64 src, size_t size, struct cn_bus_set *bus_set);

/* sync memcpy */
size_t cn_bus_dma(struct cn_bus_set *bus_set, struct transfer_s *transfer);
size_t cn_bus_dma_cfg(struct cn_bus_set *bus_set, struct transfer_s *transfer,
		struct dma_config_t *cfg);
size_t cn_bus_dma_remote(struct cn_bus_set *bus_set, struct transfer_s *transfer,
		struct task_struct *tsk, struct mm_struct *tsk_mm);
size_t cn_bus_dma_kernel(struct cn_bus_set *bus_set,
		unsigned long host_addr, u64 device_addr,
		unsigned long count, DMA_DIR_TYPE direction);
size_t cn_bus_dma_kernel_cfg(struct cn_bus_set *bus_set,
		unsigned long host_addr, u64 device_addr,
		unsigned long count, DMA_DIR_TYPE direction, struct dma_config_t *cfg);
size_t cn_bus_dma_p2p(struct cn_bus_set *bus_set, struct peer_s *peer);
int cn_bus_dma_p2p_able(struct cn_bus_set *bus_set_src, struct cn_bus_set *bus_set_dst);
int cn_bus_dma_memset(struct cn_bus_set *bus_set, struct memset_s *t);
size_t cn_bus_boot_image(struct cn_bus_set *bus_set,
	unsigned long host_addr, u64 device_addr, unsigned long count);
size_t cn_bus_check_image(struct cn_bus_set *bus_set,
	unsigned char *host_data, u64 device_addr, unsigned long count);
int cn_bus_dma_bypass_smmu_all(struct cn_bus_set *bus_set, bool en);

/* async memcopy */
size_t cn_bus_dma_async(struct cn_bus_set *bus_set, struct transfer_s *t,
		struct dma_async_info_s **async_info);
size_t cn_bus_dma_p2p_async(struct cn_bus_set *bus_set, struct peer_s *peer,
		struct dma_async_info_s **async_info);
int cn_bus_dma_memset_async(struct cn_bus_set *bus_set, struct memset_s *t,
		struct dma_async_info_s **async_info);
int cn_bus_dma_async_message_process(struct cn_bus_set *bus_set, void *message);
int cn_bus_dma_abort(struct cn_bus_set *bus_set, u64 tags, u64 index);

/* interrupt */
int cn_bus_enable_irq(struct cn_bus_set *bus_set, int irq_hw);
int cn_bus_disable_irq(struct cn_bus_set *bus_set, int irq_hw);
int cn_bus_disable_all_irqs(struct cn_bus_set *bus_set);
int cn_bus_register_interrupt(struct cn_bus_set *bus_set,
		int irq_hw, interrupt_cb_t handler, void *data);
void cn_bus_unregister_interrupt(struct cn_bus_set *bus_set, int irq_hw);
int cn_bus_get_irq_by_desc(struct cn_bus_set *bus_set, char *irq_desc);

/* sync write */
int cn_bus_sync_write_able(struct cn_bus_set *bus_set);
int cn_bus_sync_write_alloc(struct cn_bus_set *bus_set, u64 flag_dev_pa);
void cn_bus_sync_write_free(struct cn_bus_set *bus_set, u64 flag_dev_pa);
void cn_bus_sync_write_val(struct cn_bus_set *bus_set, u64 dev_pa, u32 val);
void cn_bus_sync_write_info(struct cn_bus_set *bus_set, struct sync_write_info *sw_info);

/* atomicop */
int cn_bus_get_pcie_atomicop_support(struct cn_bus_set *bus_set);
int cn_bus_get_pcie_atomicop_info(struct cn_bus_set *bus_set, struct pcie_atomicop_info_s *info);

/* tcdp */
int cn_bus_get_tcdp_able(struct cn_bus_set *bus_set);
u64 cn_bus_get_tcdp_win_base(struct cn_bus_set *bus_set);
u64 cn_bus_get_tcdp_win_size(struct cn_bus_set *bus_set);
int cn_bus_tcdp_link_on_able(struct cn_bus_set *bus_set_src, struct cn_bus_set *bus_set_dst);
u64 cn_bus_get_tcdp_host_buff(struct cn_bus_set *bus_set);
void cn_bus_tcdp_qp0_wrhost_enable(struct cn_bus_set *bus_set);
void cn_bus_tcdp_qp0_wrhost_disable(struct cn_bus_set *bus_set);
int cn_bus_tcdp_tx_dir_linear_bar_cfg(struct cn_bus_set *bus_set,
		int tx_card, int rx_card, u64 rx_liner_bar_bus_base,
		u64 rx_liner_bar_axi_base, u64 rx_liner_bar_size);
u64 cn_bus_tcdp_win_base_do_iommu_remap(struct cn_bus_set *bus_set_src,
		struct cn_bus_set *bus_set_dst, int card_id, int rcard_id);
int cn_bus_tcdp_txrx_indir_cfg(struct cn_bus_set *bus_set,
		int tx_card, int rx_card, u64 rx_tcdp_win_bus_base);
int cn_bus_tcdp_change_channel_state(struct cn_bus_set *bus_set,
		int rcard_id, int dir, int state);

/* linear bar */
u64 cn_bus_get_linear_bar_bus_base(struct cn_bus_set *bus_set);
u64 cn_bus_get_linear_bar_phy_base(struct cn_bus_set *bus_set);
u64 cn_bus_get_linear_bar_axi_base(struct cn_bus_set *bus_set);
u64 cn_bus_get_linear_bar_size(struct cn_bus_set *bus_set);
int cn_bus_get_linear_bar_offset(struct cn_bus_set *bus_set, u64 *offset);
u64 cn_bus_linear_bar_do_iommu_remap(struct cn_bus_set *bus_set_src,
		struct cn_bus_set *bus_set_dst, int card_id, int rcard_id);

/* PCI Express basic */
struct device *cn_bus_get_dev(struct cn_bus_set *bus_set);
u32 cn_bus_get_bdf(struct cn_bus_set *bus_set);
u32 cn_bus_get_current_bdf(struct cn_bus_set *bus_set);
int cn_bus_set_bdf(struct cn_bus_set *bus_set, u32 bdf);
int cn_bus_set_cspeed(unsigned int cspeed, struct cn_bus_set *bus_set);
int cn_bus_soft_reset(struct cn_bus_set *bus_set, bool reset);
int cn_bus_check_available(struct cn_bus_set *bus_set);
int cn_bus_get_lnkcap(struct cn_bus_set *bus_set, struct bus_lnkcap_info *lnk_info);
int cn_bus_get_curlnk(struct cn_bus_set *bus_set, struct bus_lnkcap_info *lnk_info);

/* virtual function */
int cn_bus_get_vf_idx(struct cn_bus_set *pf_bus_set, struct cn_bus_set *vf_bus_set);
struct device *cn_bus_get_vf_dev(struct cn_bus_set *bus_set, int vf_idx);
bool cn_bus_check_pdev_virtfn(struct cn_bus_set *bus_set);

/* get info */
int cn_bus_pcie_sram_able(struct cn_bus_set *bus_set);
int cn_bus_get_bus_info(struct cn_bus_set *bus_set, struct bus_info_s *bus_info);
int cn_bus_get_dma_info(struct cn_bus_set *bus_set, struct dma_info_s *dma_info);
int cn_bus_get_bar_info(struct cn_bus_set *bus_set, struct bar_info_s *bar_info);
int cn_bus_get_p2pshm_info(struct cn_bus_set *bus_set, struct p2pshm_attr *attr);
int cn_bus_get_pcie_fw_info(struct cn_bus_set *bus_set, u64 *pcie_fw_info);
void cn_bus_show_info(struct cn_bus_set *bus_set);
void cn_bus_debug_dump_reg(struct cn_bus_set *bus_set);

/* proc info */
void cn_bus_get_p2p_able_info(struct cn_bus_set *bus_set, struct p2p_stat *able, int *index);
int cn_bus_get_inbound_cnt(struct cn_bus_set *bus_set);
u32 cn_bus_get_heartbeat_cnt(struct cn_bus_set *bus_set);
u32 cn_bus_get_soft_retry_cnt(struct cn_bus_set *bus_set);
u32 cn_bus_get_p2p_exchg_cnt(struct cn_bus_set *bus_set);
int cn_bus_get_async_proc_info(struct cn_bus_set *bus_set, struct async_proc_info_s *async_proc_info);
int cn_bus_get_dma_channel_info(struct cn_bus_set *bus_set, struct dma_channel_info_s *dma_channel_info);
int cn_bus_dump_dma_info(struct cn_bus_set *bus_set);
int cn_bus_get_async_htable(struct cn_bus_set *bus_set);
int cn_bus_get_int_occur_info(struct cn_bus_set *bus_set, struct int_occur_info_s *int_occur_info);
u32 cn_bus_get_non_align_cnt(struct cn_bus_set *bus_set);
int cn_bus_get_isr_type(struct cn_bus_set *bus_set);
u32 cn_bus_get_device_ko_bootinfo(struct cn_bus_set *bus_set);

/* dfx */
int cn_bus_dma_af_ctrl(struct cn_bus_set *bus_set, unsigned int enable);
int cn_bus_force_p2p_xchg(struct cn_bus_set *bus_set, int force);
int cn_bus_dma_des_set(struct cn_bus_set *bus_set, unsigned int enable);
int cn_bus_set_dma_err_inject_flag(struct cn_bus_set *bus_set, int data);
int cn_bus_debug_report_cb(void *data, unsigned long action, void *fp);
#ifdef CONFIG_CNDRV_MNT
int cn_bus_get_bug_report(void *data, unsigned long action, void *fp);
#endif
int cn_bus_pll_irq_sts_dump(struct cn_bus_set *bus_set);

/* others */
int cn_bus_mlu_mem_client_init(struct cn_bus_set *bus_set);
int cn_bus_core_type_switch(struct cn_bus_set *bus_set, __u32 policy);
struct cn_core_set *cn_bus_get_core_set_via_card_id(int card_id);
u64 get_host_ns_time(void);

/*user ioctl function*/
long cn_bus_ioctl(struct cn_core_set *core, unsigned int cmd, unsigned long arg);

#endif

/* MIM */
int cn_bus_probe_mi(struct cn_bus_set *bus_set, int domain_id);
int cn_bus_remove_mi(struct cn_bus_set *bus_set, int domain_id);
