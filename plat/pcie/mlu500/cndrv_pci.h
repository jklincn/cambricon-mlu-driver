/************************************************************************
 *  @file cndrv_pci.h
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

#ifndef __CNDRV_PCIE_H
#define __CNDRV_PCIE_H

#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>
#include <linux/hashtable.h>
#include "cndrv_pre_compile.h"
#include "cndrv_domain.h"
#include "pcie_dma.h"
#include "pcie_bar.h"

enum {
	INT_MODE_MSIX = 0,
	INT_MODE_MSI,
	INT_MODE_LEGACY,
};


#define IRQ_SHARED_NUM	8

struct cn_pci_irq_desc {
	struct cn_pcie_set          *priv; /* parent device */
	interrupt_cb_t               handler[IRQ_SHARED_NUM];
	void                        *data[IRQ_SHARED_NUM];
	u64                         occur_count;
};

#define MAX_BAR_SEGMENTS     (2)

struct pcibar_seg_s {
	void                   *virt;
	u64                     base;
	u64                     size;
};

struct pci_sharemem_s {
	void __iomem          *virt_addr;
	unsigned long         phy_addr;
	unsigned long         win_length;
	CN_MEM_TYPE           type;
	u64                   device_addr;
};

struct cn_pci_vf_priv_data {
	u32 bdf;
	u32 dma_phy_mask;
	u32 share_mem_base;
	u32 share_mem_size;
	u64 inbdmem_dev_va_base;
	u64 sram_pa;
	u64 sram_size;
	wait_queue_head_t p2v_wait_queue;
	u32 wait_flag;
};

#define MAX_MBX_MSG_COUNT	(64)

struct cn_pci_sriov {
	struct work_struct           vf2pf_work;
	u32                          vf_id;
	u32			     vf_dma_phy_channel_mask;
	u64                          ob_mask;
	struct dm_per_module_ops     sriov_dm_ops;
	struct cn_pcie_set          *pcie_set;
	void                        *domain;
	void                        *mig_bin;
	int			     msg_index;
	u64                          mbx_msg[MAX_MBX_MSG_COUNT];
};

struct cn_pci_ops {
	/* register space */
	u32 (*reg_read32)(u64 axi_addr, struct cn_pcie_set *pcie_set);
	void (*reg_write32)(u64 axi_addr, u32 data, struct cn_pcie_set *pcie_set);
	u64 (*reg_read64)(u64 axi_addr, struct cn_pcie_set *pcie_set);
	void (*reg_write64)(u64 axi_addr, u64 data, struct cn_pcie_set *pcie_set);
	void (*pci_mb)(struct cn_pcie_set *pcie_set);

	/* outbound */
	void (*dob_desc_pg_init)(struct cn_pcie_set *pcie_set);
	void (*get_dob_win_info)(struct cn_pcie_set *pcie_set,
			int *lvl1_page, int *lvl1_pg_cnt, u64 *lvl1_base,
			int *lvl2_page, int *lvl2_pg_cnt, u64 *lvl2_base);
	void *(*dob_win_alloc)(struct cn_pcie_set *pcie_set,
			u64 device_addr, size_t size);
	void (*dob_win_free)(struct cn_pcie_set *pcie_set, u64 device_addr);
	int (*get_dob_iova)(struct cn_pcie_set *src, struct cn_pcie_set *dst,
			u64 device_addr, size_t size, struct sg_table **iova_sgt);
	void (*put_dob_iova)(struct cn_pcie_set *pcie_set, struct sg_table **iova_sgt);

	/* bar memcpy */
	u64 (*set_bar_window)(u64 bar_address, struct bar_resource *resource,
			struct cn_pcie_set *pcie_set);

	/* sync memcpy */
	int (*dma_go_command)(struct dma_channel_info *channel, int phy_channel);
	int (*dma_bypass_size)(struct cn_pcie_set *pcie_set);
	int (*dma_bypass_smmu)(int phy_ch, bool en, struct cn_pcie_set *pcie_set);
	int (*dma_bypass_smmu_all)(bool en, struct cn_pcie_set *pcie_set);
	int (*fill_desc_list)(struct dma_channel_info *channel);
	void (*show_desc_list)(struct dma_channel_info *channel);

	/* async memcopy */
	int (*async_dma_fill_desc_list)(struct async_task *async_task);
	int (*async_dma_fill_p2p_pull_desc)(struct async_task *async_task);

	/* interrupt */
	void (*isr_hw_enable)(struct cn_pcie_set *pcie_set);
	void (*isr_hw_disable)(struct cn_pcie_set *pcie_set);
	irqreturn_t (*intx_isr)(int irq, void *pcie_set);
	irqreturn_t (*msi_isr)(int irq, void *pcie_set);
	irqreturn_t (*msix_isr)(int irq, void *pcie_set);
	int (*gic_mask)(int irq, struct cn_pcie_set *pcie_set);
	int (*gic_unmask)(int irq, struct cn_pcie_set *pcie_set);
	int (*gic_mask_all)(struct cn_pcie_set *pcie_set);
	void (*save_msix_ram)(struct cn_pcie_set *pcie_set);
	int (*get_irq_by_desc)(char *irq_desc, struct cn_pcie_set *pcie_set);

	/* sync write */
	int (*sync_write_init)(struct cn_pcie_set *pcie_set);
	void (*sync_write_exit)(struct cn_pcie_set *pcie_set);
	int (*sync_write_alloc)(struct cn_pcie_set *pcie_set, u64 flag_dev_pa);
	void (*sync_write_free)(struct cn_pcie_set *pcie_set, u64 flag_dev_pa);
	void (*sync_write_trigger)(struct cn_pcie_set *pcie_set, u64 dev_pa, u32 val);
	void (*sync_write_info)(struct cn_pcie_set *pcie_set, struct sync_write_info *sw_info);

	/* atomicop */
	void (*pcie_atomicop_init)(struct cn_pcie_set *pcie_set);
	void (*pcie_atomicop_exit)(struct cn_pcie_set *pcie_set);

	/* tcdp */
	int (*tcdp_top_init)(struct cn_pcie_set *pcie_set);
	void (*tcdp_top_exit)(struct cn_pcie_set *pcie_set);
	u64 (*get_tcdp_win_base)(struct cn_pcie_set *pcie_set);
	u64 (*get_tcdp_win_size)(struct cn_pcie_set *pcie_set);
	u64 (*get_tcdp_host_buff)(struct cn_pcie_set *pcie_set);
	void (*tcdp_qp0_wrhost_enable)(struct cn_pcie_set *pcie_set);
	void (*tcdp_qp0_wrhost_disable)(struct cn_pcie_set *pcie_set);
	int (*tcdp_tx_dir_linear_bar_cfg)(struct cn_pcie_set *pcie_set,
			int tx_card, int rx_card, u64 rx_liner_bar_bus_base,
			u64 rx_liner_bar_axi_base, u64 rx_liner_bar_size);
	int (*tcdp_txrx_indir_cfg)(struct cn_pcie_set *pcie_set,
			int tx_card, int rx_card, u64 rc_tcdp_win_bus_base);
	u64 (*linear_bar_do_iommu_remap)(struct cn_pcie_set *pcie_set_src,
			struct cn_pcie_set *pcie_set_dst, int src_card_id, int dst_card_id);
	u64 (*tcdp_win_base_do_iommu_remap)(struct cn_pcie_set *pcie_set_src,
			struct cn_pcie_set *pcie_set_dst, int src_card_id, int dst_card_id);
	int (*tcdp_change_channel_state)(struct cn_pcie_set *pcie_set,
			int rcard_id, int dir, int state);

	/* PCI Express basic */
	int (*soft_reset)(struct cn_pcie_set *pcie_set);
	int (*chip_reset)(struct cn_pcie_set *pcie_set);
	int (*ddr_set_done)(struct cn_pcie_set *pcie_set);
	int (*check_available)(struct cn_pcie_set *pcie_set);

	/* virtual function */
	int (*sriov_support)(struct cn_pcie_set *pcie_set);
	int (*sriov_vf_init)(struct cn_pci_sriov *sriov);
	int (*sriov_vf_exit)(struct cn_pci_sriov *sriov);
	int (*iov_virtfn_bus)(struct cn_pcie_set *pcie_set, unsigned int vf_i);
	int (*iov_virtfn_devfn)(struct cn_pcie_set *pcie_set, unsigned int vf_i);
	int (*sriov_pre_init)(struct cn_pci_sriov *sriov);
	int (*sriov_later_exit)(struct cn_pci_sriov *sriov);
	int (*vf_notify_late_init)(struct cn_pcie_set *pcie_set);
	int (*flush_irq)(struct cn_pcie_set *pcie_set);

	/* dfx */
	int (*pll_irq_sts_dump)(struct cn_pcie_set *pcie_set);
	int (*pll_irq_enable)(struct cn_pcie_set *pcie_set);
	void (*pcie_debug_dump_reg)(struct cn_pcie_set *pcie_set);
	void (*dump_reg)(struct cn_pcie_set *pcie_set);
};

enum {
	PCIE_STATE_PRE_INIT,
	PCIE_STATE_SET_BUS,
	PCIE_STATE_INIT,
	PCIE_STATE_STOP,
	PCIE_STATE_SUSPEND,
	PCIE_STATE_PRE_START,
	PCIE_STATE_START,
	PCIE_STATE_NORMAL,
};

struct cn_pci_irq_str_index {
	int hw_irq_num;
	char *str_index;
};

struct cn_pci_pll_cfg {
	u32 base_addr;
	char *name;
};

/* PCIe device specific book-keeping */
struct cn_pci_info {
	int (*setup)(void *priv);
	int (*pre_init)(void *priv);
	int (*pre_exit)(void *priv);
	int (*get_resource)(void *priv, struct domain_resource *resource);
	char *dev_name;
};

struct outbound_mem {
	void *virt_addr;
	dma_addr_t pci_addr;
	struct page *pages;
	int order;
};

struct data_outbound_map_t {
	struct cn_pcie_set	*src;
	u64			device_addr;
	size_t			size;
	struct sg_table *sgt;
	struct list_head	list;
};

struct data_outbound_node_t {
	void			*share_priv;
	struct page		**share_mem_pages;
	u64			win_base;
	int			win_cnt;
	int			per_win_size;
	int			pre_win_npages;
	int			total_size;
	CN_MEM_TYPE		type;
	void __iomem		*virt_addr;
	u64			device_addr;
	struct list_head	list;
};

struct pcie_dob_page_set {
	u64 page_addr;
	u64 val;
};

struct data_outbound_set {
	/* axi data_outbound va set*/
	u32			dob_cnt;
	u64			dob_lvl1_pg;
	u64			dob_lvl2_pg;
	u64			dob_lvl1_axi_base;
	u64			dob_lvl2_axi_base;
	u64			dob_total_size;
	/* axi data_outbound page set*/
	u32			dob_axi_pg_cnt;
	u32			dob_axi_per_pg_size;
	u64			dob_axi_pg_base;
	/* axi data_outbound reserve info set for commu and ipcm 8MB*/
	u32			dob_lvl2_pg_reserve_cnt;
	int                     dob_reserve_size;
	u32                     dob_ar_cnt;

	struct list_head	dob_head;
	struct list_head	dob_iova_head;
	struct mutex		dob_lock;

	u64                     ob_axi_addr;
	struct page           **share_mem_pages;
};

struct sync_write {
	volatile int                       status;
	u64                                sw_trigger_pa;//self set
	unsigned long                      sw_trigger_kva;//self set
	u64                                sw_flag_pa;//user set
	size_t                             sw_flag_size;//user set
	u32                                sw_trigger_count;
};

#define PF_SW_NUM		(0x4)
struct sync_write_set {
	struct sync_write                  sw[PF_SW_NUM];

	u32                                mode;
	u32                                sw_num;
	u64                                sw_dev_va;
	unsigned long                      sw_host_kva;
	size_t                             sw_total_size;
};

struct bar0_set {
	u64                                base;
	u64                                size;
	struct pcibar_seg_s                seg[MAX_BAR_SEGMENTS];

	struct semaphore                   bar0_window_sem[4];
	u8                                 bar0_window_flag[4];
	u8                                 bar0_window_base;
	u32                                bar0_window_tgt[4];

	void __iomem                      *reg_virt_base;
	unsigned long                      reg_phy_addr;
	unsigned long                      reg_win_length;
};

struct tcdp_set {
	__u64 qp_crash_space_dva; //sharemem 8KB
	unsigned long qp_crash_space_hva;

	__u64 qp_win_base; //bar2 base;
	__u64 qp_win_size; //8M (This wins have 8 ones)
	struct page *p_page;

	unsigned long proxy_host_addr; //host va of OB's RAM
	__u64 proxy_dev_addr; //device pa of OB

	/* The gap between Bus-Addr and Host-Phy-Addr*/
	long 				   bus_offset;
};

struct pcie_cfg_set {
	int                                outbound_able;
	int                                pcie_sram_able;
	int                                sync_write_able;
	int                                tcdp_able;
	int                                atomicop_support;
	int                                arm_trigger_enable;
	int                                af_enable;
	int                                p2p_mode;
};

struct pcie_dfx_set {
	/* dfx info */
	u32                                heartbeat_cnt;
	u32                                p2p_exchg_cnt;
	u64                                total_data[DMA_DATA_TYPE];

	/* dfx */
	int				   des_set;
	int                                dma_err_inject_flag;
	int                                force_p2p_xchg_flag;
	struct semaphore                   timeout_log_sem;

	/* bug report */
	struct file                       *fp;
	loff_t                             log_file_pos;
};

struct pcie_atomicop_set {
	u64                                atomicop_host_va;
	u64                                atomicop_dev_va;
	u32                                atomicop_desc_cnt;
};

struct linear_bar_set {
	struct bar_resource               *resource;
	u64                                axi_addr;
	u64                                offset;
};

struct pcie_irq_set {
	int                                irq;
	int                                irq_num;
	int                                irq_type;
	int                                affinity[INTERRUPT_IRQ_NUM];
	struct cpumask                     cpu_mask[INTERRUPT_IRQ_NUM];
	int				   msi_pos;
	struct cn_pci_irq_desc             irq_desc[INTERRUPT_IRQ_NUM];   /* user IRQ management */
	struct msix_entry                  msix_entry_buf[INTERRUPT_IRQ_NUM]; /* interrupt number */
	u32                                msix_ram[INTERRUPT_IRQ_NUM * 4]; /* store the msix ram */
	u32                                gic_mask[INTERRUPT_IRQ_NUM / 32];
	spinlock_t                         interrupt_lock;
};

struct pcie_dma_set {
	/* dma task */
	struct pcie_dma_task             **task_table;
	struct semaphore                   task_sem_h2d;
	struct semaphore                   task_sem_d2h;
	volatile int                       task_num;
	volatile int                       task_suspend_num;
	wait_queue_head_t                  task_suspend_wq;

	/* shared dma desc memory */
	size_t                             shared_desc_total_size;
	u64                                shared_desc_dev_va;
	unsigned long                      shared_desc_host_kva;

	/* shared dma channel */
	int                                shared_channel_cnt;
	int                                shared_channel_desc_cnt;
	struct dma_channel_info          **shared_channel_list;
	unsigned int                       shared_channel_search;
	volatile unsigned int              channel_search_start;

	/* * private dma desc memroy */
	int                                max_desc_order;
	size_t                             priv_desc_total_size;
	u64                                priv_desc_dev_va;
	unsigned long                      priv_desc_host_kva;

	/* running channels */
	unsigned long                    **running_channels;

	/* phy resource */
	u32                                domain_phy_channel_mask;
	int                                max_phy_channel;
	u32                                dma_phy_channel_mask;

	/* dma bypass size  */
	int                                dma_bypass_custom_size;
	int                                dma_bypass_pinned_size;
	int                                dma_memsetD8_custom_size;
	int                                dma_memsetD16_custom_size;
	int                                dma_memsetD32_custom_size;
	int                                d2h_bypass_custom_size;

	int                                dma_fetch_buff;
	spinlock_t                         fetch_lock[8];
	u32                                dma_timeout;
	size_t                             dma_buffer_size;
};

struct pcie_async_dma_set {
	/* async dma task */
	struct async_task                **async_task_table;
	struct dma_async_info_s          **async_info_table;
	unsigned long                     *async_task_bitmap;
	spinlock_t                         async_task_lock;

	/* async dma desc memroy */
	int                                async_max_desc_num;
	int                                async_static_task_num;
	size_t                             async_desc_size;
	u64                                async_desc_dev_va;
	unsigned long                      async_desc_host_kva;
	int                                async_desc_num;
	unsigned long                     *async_desc_bitmap;
	spinlock_t                         async_desc_lock;

	/* async dma desc host memroy */
	void                              *async_desc_buf;
	struct page                      **async_pp_pages;
	int                               *async_chunk;
	struct scatterlist                *async_sg_list;

	/* async hash table */
	DECLARE_HASHTABLE(async_task_htable, 8);
	struct mutex                       async_task_hash_lock;

	/* dfx */
	u32                                arm_trigger_dma_cnt;
	u32                                arm_trigger_p2p_cnt;
	u32                                host_trigger_dma_cnt;
	u32                                host_trigger_p2p_cnt;
};

struct cn_pcie_set {
	/*
	 * the offset of bar_resource_head and ops in struct cn_pcie_set
	 * must be consistent in directories mlu220_mlu270, mlu290_ce3226, mlu370
	 * otherwise, there will be a bug by forced conversion
	 */
	struct list_head                   bar_resource_head;
	struct cn_pci_ops                 *ops;
	struct cn_bus_set                 *bus_set;
	struct pci_dev                    *pdev;
	int                                id;
	int                                idx; /* core->idx*/
	char                               dev_name[32];
	char				   core_name[32];
	volatile int                       state;
	int                                node;
	u32                                sn_h16;

	struct pcie_cfg_set                cfg;
	struct pcie_irq_set                irq_set;
	struct bar0_set                    bar0_set;
	struct pcie_dma_set                dma_set;
	struct pcie_async_dma_set          async_set;
	struct sync_write_set              sw_set;
	struct data_outbound_set           dob_set;
	struct tcdp_set                    tcdp_set;
	struct pcie_atomicop_set           atom_set;
	struct linear_bar_set              linear_bar;
	struct pcie_dfx_set                dfx;

	/* bar */
	int                                share_mem_cnt;
	struct pci_sharemem_s              share_mem[8];

	/* dma */
	int                                per_desc_size;
	int                                per_desc_max_size;

	/* async_free */
	struct kfifo                       af_fifo;
	struct work_struct                 async_free_work;

	/* add for sriov */
	u8                                 is_virtfn;
	u32                                nums_vf;
	struct cn_pci_sriov               *sriov;
	struct cn_pci_vf_priv_data        *vf_priv_data;
	struct dm_per_module_ops           dm_ops;
	struct cn_pci_irq_str_index       *irq_str_index_ptr;
	u32                                bdf;
};


/* interrupt */
struct cn_bus_get_phy_bar_addr {
	u64 bar_phy_addr[6];
	u64 bar_phy_size[6];
	int vf_bar_number;
};

/*
 * Save for live migration in source guest.
 * Suspend the dma task when live migration start
 * Return 0:Success otherwise:fail
 */
/*
 * Restore for live migration in dst guest.
 * Restart the dma task when live migration complete
 * Return 0:Success otherwise:fail
 */


#define assert(x)

/* VendorID & DeviceID */
#define cambricon_dm_VID  0xcabc
#define CN_C50_DID		((MLUID_590 >> 16) & 0xffff)
#define CN_C50_VF_DID		((MLUID_590V >> 16) & 0xffff)
#define CN_C50_S_DID		((MLUID_585 >> 16) & 0xffff)
#define CN_C50_S_VF_DID		((MLUID_585V >> 16) & 0xffff)
#define CN_C50_M_DID		((MLUID_580 >> 16) & 0xffff)
#define CN_C50_M_VF_DID		((MLUID_580V >> 16) & 0xffff)
#define CN_C50_L_DID		((MLUID_570 >> 16) & 0xffff)
#define CN_C50_L_VF_DID		((MLUID_570V >> 16) & 0xffff)
#define CN_C50_T_DID		((MLUID_560 >> 16) & 0xffff)
#define CN_C50_T_VF_DID		((MLUID_560V >> 16) & 0xffff)

#ifndef PCI_EXP_LNKCTL2_TLS
#define PCI_EXP_LNKCTL2_TLS		0x000f
#define PCI_EXP_LNKCTL2_TLS_2_5GT	0x0001 /* Supported Speed 2.5GT/s */
#define PCI_EXP_LNKCTL2_TLS_5_0GT	0x0002 /* Supported Speed 5GT/s */
#define PCI_EXP_LNKCTL2_TLS_8_0GT	0x0003 /* Supported Speed 8GT/s */
#define PCI_EXP_LNKCTL2_TLS_16_0GT	0x0004 /* Supported Speed 16GT/s */
#endif

#ifndef PCI_EXP_LNKCAP_SLS
#define  PCI_EXP_LNKCAP_SLS	0x0000000f /* Supported Link Speeds */
#endif

#ifndef PCI_EXP_LNKCAP_SLS_2_5GB
#define  PCI_EXP_LNKCAP_SLS_2_5GB 0x00000001 /* LNKCAP2 SLS Vector bit 0 */
#endif

#ifndef PCI_EXP_LNKCAP_SLS_5_0GB
#define  PCI_EXP_LNKCAP_SLS_5_0GB 0x00000002 /* LNKCAP2 SLS Vector bit 1 */
#endif

#ifndef PCI_EXP_LNKCAP_SLS_8_0GB
#define  PCI_EXP_LNKCAP_SLS_8_0GB 0x00000003 /* LNKCAP2 SLS Vector bit 2 */
#endif

#ifndef PCI_EXP_LNKCAP_SLS_16_0GB
#define  PCI_EXP_LNKCAP_SLS_16_0GB 0x00000004 /* LNKCAP2 SLS Vector bit 3 */
#endif

#ifndef PCI_EXP_LNKCAP_SLS_32_0GB
#define PCI_EXP_LNKCAP_SLS_32_0GB 0x00000005 /* LNKCAP2 SLS Vector bit 4 */
#endif

#ifndef PCI_EXP_LNKCTL2_TLS_32_0GT
#define PCI_EXP_LNKCTL2_TLS_32_0GT	0x0005	/* Supported Speed 32GT/s */
#endif

#ifndef PCI_EXP_LNKSTA_NLW
#define PCI_EXP_LNKSTA_NLW	0x03f0	/* Negotiated Link Width */
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X1
#define PCI_EXP_LNKSTA_NLW_X1	0x0010	/* Current Link Width x1 */
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X2
#define PCI_EXP_LNKSTA_NLW_X2	0x0020	/* Current Link Width x2 */
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X4
#define PCI_EXP_LNKSTA_NLW_X4	0x0040	/* Current Link Width x4 */
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X8
#define PCI_EXP_LNKSTA_NLW_X8	0x0080	/* Current Link Width x8 */
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X16
#define PCI_EXP_LNKSTA_NLW_X16	0x0100	/* Current Link Width x16 */
#endif


#ifndef PCI_EXP_LNKSTA_CLS_8_0GB
#define PCI_EXP_LNKSTA_CLS_8_0GB        0x0003 /* Current Link Speed 8.0GT/s */
#endif

#define PCIE_LINKCAP_STR(linkcap) \
	(linkcap == PCI_EXP_LNKCAP_SLS_32_0GB ? "32.0GT/s" : \
	 linkcap == PCI_EXP_LNKCAP_SLS_16_0GB ? "16.0GT/s" : \
	 linkcap == PCI_EXP_LNKCAP_SLS_8_0GB	? "8.0GT/s" : \
	 linkcap == PCI_EXP_LNKCAP_SLS_5_0GB	? "5.0GT/s" : \
	 linkcap == PCI_EXP_LNKCAP_SLS_2_5GB	? "2.5GT/s" : \
	 "Unknown")

#define PCIE_SPEED_STR(speed) \
	(speed == PCI_EXP_LNKCTL2_TLS_32_0GT ? "32.0GT/s" : \
	 speed == PCI_EXP_LNKCTL2_TLS_16_0GT ? "16.0GT/s" : \
	 speed == PCI_EXP_LNKCTL2_TLS_8_0GT	? "8.0GT/s" : \
	 speed == PCI_EXP_LNKCTL2_TLS_5_0GT	? "5.0GT/s" : \
	 speed == PCI_EXP_LNKCTL2_TLS_2_5GT	? "2.5GT/s" : \
	 "Unknown")

#define PCIE_WIDTH_STR(width) \
	(width == PCI_EXP_LNKSTA_NLW_X16 ? "X16" : \
	 width == PCI_EXP_LNKSTA_NLW_X8 ? "X8" : \
	 width == PCI_EXP_LNKSTA_NLW_X4	? "X4" : \
	 width == PCI_EXP_LNKSTA_NLW_X2	? "X2" : \
	 width == PCI_EXP_LNKSTA_NLW_X1	? "X1" : \
	 "Unknown")

#endif
