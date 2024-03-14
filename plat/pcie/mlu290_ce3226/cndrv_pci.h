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

struct pcibar_s {
	u64                     base;
	u64                     size;
	struct pcibar_seg_s     seg[MAX_BAR_SEGMENTS];
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
	wait_queue_head_t p2v_wait_queue;
	u32 wait_flag;
};

#define MAX_MBX_MSG_COUNT	(8)

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
	int (*pcie_pre_exit)(struct cn_pcie_set *pcie_set);
	int (*pcie_init)(struct cn_pcie_set *pcie_set);
	int (*pcie_exit)(struct cn_pcie_set *pcie_set);
	int (*fill_desc_list)(struct dma_channel_info *channel);
	void (*show_desc_list)(struct dma_channel_info *channel);
	void (*dump_reg)(struct cn_pcie_set *pcie_set);
	u64 (*set_bar_window)(u64 bar_address, struct bar_resource *resource,
		struct cn_pcie_set *pcie_set);

	void (*pci_mb)(struct cn_pcie_set *pcie_set);
	int (*check_available)(struct cn_pcie_set *pcie_set);

	irqreturn_t (*intx_isr)(int irq, void *pcie_set);
	irqreturn_t (*msi_isr)(int irq, void *pcie_set);
	irqreturn_t (*msix_isr)(int irq, void *pcie_set);

	void (*isr_hw_enable)(struct cn_pcie_set *pcie_set);
	void (*isr_hw_disable)(struct cn_pcie_set *pcie_set);

	int (*gic_mask)(int irq, struct cn_pcie_set *pcie_set);
	int (*gic_unmask)(int irq, struct cn_pcie_set *pcie_set);
	int (*gic_mask_all)(struct cn_pcie_set *pcie_set);

	int (*get_irq_by_desc)(char *irq_desc, struct cn_pcie_set *pcie_set);
	int (*dma_align)(struct transfer_s *t, size_t *head, size_t *tail);
	int (*dma_go_command)(struct dma_channel_info *channel, int phy_channel);
	int (*dma_bypass_size)(struct cn_pcie_set *pcie_set);
	int (*dma_bypass_smmu)(int phy_ch, bool en, struct cn_pcie_set *pcie_set);
	int (*async_dma_fill_desc_list)(struct async_task *async_task);

	int (*soft_reset)(struct cn_pcie_set *pcie_set);
	int (*ddr_set_done)(struct cn_pcie_set *pcie_set);
	int (*bar_read)(unsigned long host_addr, u64 device_addr, size_t count,
						struct cn_pcie_set *pcie_set);
	int (*bar_write)(unsigned long host_addr, u64 device_addr, size_t count,
						struct cn_pcie_set *pcie_set);

	int (*enable_pf_bar)(struct cn_pcie_set *pcie_set);
	int (*enable_vf_bar)(struct cn_pcie_set *pcie_set);
	void (*disable_vf_bar)(struct cn_pcie_set *pcie_set);

	u32 (*reg_read32)(u64 axi_addr, struct cn_pcie_set *pcie_set);
	void (*reg_write32)(u64 axi_addr, u32 data, struct cn_pcie_set *pcie_set);
	u64 (*reg_read64)(u64 axi_addr, struct cn_pcie_set *pcie_set);
	void (*reg_write64)(u64 axi_addr, u64 data, struct cn_pcie_set *pcie_set);

	/* add for sriov */
	int (*sriov_support)(struct cn_pcie_set *pcie_set);
	int (*sriov_vf_init)(struct cn_pci_sriov *sriov);
	int (*sriov_vf_exit)(struct cn_pci_sriov *sriov);
	int (*iov_virtfn_bus)(struct cn_pcie_set *pcie_set, unsigned int vf_i);
	int (*iov_virtfn_devfn)(struct cn_pcie_set *pcie_set, unsigned int vf_i);
	int (*sriov_pre_init)(struct cn_pci_sriov *sriov);
	int (*sriov_later_exit)(struct cn_pci_sriov *sriov);

	int (*domain_init)(struct cn_pcie_set *pcie_set);
	int (*domain_exit)(struct cn_pcie_set *pcie_set);

	/*
	 * When live migration, the arm may generate irq before guest ready,
	 * this will cause the guest can't receive irq after guest ready.
	 */
	int (*flush_irq)(struct cn_pcie_set *pcie_set);
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

/* PCIe device specific book-keeping */
struct cn_pci_info {
	int (*setup)(void *priv);
	int (*pre_init)(void *priv);
	int (*pre_exit)(void *priv);
	int (*get_resource)(void *priv, struct domain_resource *resource);
	char *dev_name;
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
	char                               dev_name[32];
	u64				   pcie_fw_id;
	int                                idx; /* core->idx*/
	char				   core_name[32];
	int                                id;
	unsigned int                       hid;
	volatile int                       state;

	struct semaphore                   timeout_log_sem;
	struct semaphore                   vf_smmu_flush_sem;

	struct pcibar_s			pcibar[6];

	struct bar_resource               *mdr_resource;

	/* inbound stream number must be no greater than 8 in C20L platform*/
	atomic_t			inbound_count;
	int                 max_inbound_cnt;

	unsigned long                     *running_channels;
	volatile unsigned int              channel_run_flag;

	struct pcie_dma_task             **task_table;
	struct semaphore                   task_sem_h2d;
	struct semaphore                   task_sem_d2h;

	/*
	 * shared dma desc memory
	 */
	size_t                             shared_desc_total_size;
	u64                                shared_desc_dev_va;
	unsigned long                      shared_desc_host_kva;
	struct dma_desc_order_table       *order_table; /* form 0 to 9*/
	int                                max_desc_order;
	int                                per_desc_size;

	/*
	 * private dma desc memroy
	 */
	size_t                             priv_desc_total_size;
	u64                                priv_desc_dev_va;
	unsigned long                      priv_desc_host_kva;

	/*
	 * async dma desc memroy
	 */
	int                                async_max_desc_num;
	size_t                             async_static_desc_size;
	u64                                async_static_desc_dev_va;
	unsigned long                      async_static_desc_host_kva;
	int                                async_static_task_num;
	size_t                             async_dynamic_desc_size;
	u64                                async_dynamic_desc_dev_va;
	unsigned long                      async_dynamic_desc_host_kva;
	int                                async_dynamic_desc_num;
	unsigned long                     *async_dynamic_desc_bitmap;
	spinlock_t                         async_dynamic_desc_lock;

	volatile int                       task_num;
	volatile int                       task_suspend_num;
	wait_queue_head_t                  task_suspend_wq;
	volatile unsigned int              task_search_start;
	volatile unsigned int              channel_search_start;

	size_t                             dma_buffer_size;

	/* dma bypass size  */
	int                                dma_bypass_custom_size;
	int                                dma_bypass_pinned_size;
	int                                dma_memsetD8_custom_size;
	int                                dma_memsetD16_custom_size;
	int                                dma_memsetD32_custom_size;

	/* async_free */
	int                                af_enable;
	struct kfifo                       af_fifo;
	struct work_struct                 async_free_work;

	/* Interrupt management */
	spinlock_t                         interrupt_lock;
	int                                irq;
	int                                irq_type;
	int                                node;
	int                                affinity;
	struct cpumask                     cpu_mask;
	int				   msi_pos;
	struct cn_pci_irq_desc             irq_desc[INTERRUPT_IRQ_NUM];   /* user IRQ management */
	struct msix_entry                  msix_entry_buf[INTERRUPT_IRQ_NUM]; /* interrupt number */
	u32                                msix_ram[INTERRUPT_IRQ_NUM * 4]; /* store the msix ram */

	/* the functions and variable must init by specail driver */
	int                                max_phy_channel;
	u32				dma_phy_channel_mask; /*controllable dma mask*/
	void __iomem                      *reg_virt_base;
	unsigned long                      reg_phy_addr;
	unsigned long                      reg_win_length;

	int                                share_mem_cnt;
	struct pci_sharemem_s              share_mem[8];

	void                              *share_priv;
	struct page                      **share_mem_pages;
	u64                                ob_mask;
	int                                ob_cnt;
	int                                ob_size;
	int                                ob_total_size;
	u64                                ob_axi_addr;

	int irq_num;

	/*
	 * point to platform private struct
	 * for example: c30 have bar0 window sem, other platform no this feature
	 */
	void				  *priv_set;

	/* async transfer management*/
	DECLARE_HASHTABLE(async_task_htable, 8);
	struct mutex async_task_hash_lock;

	struct async_task                **async_task_table;
	struct dma_async_info_s          **async_info_table;
	unsigned long                     *async_task_bitmap;
	spinlock_t                         async_task_lock;

	int                                arm_trigger_enable;
	int                                arm_trigger_max_size;
	u32                                arm_trigger_dma_cnt;
	u32                                arm_trigger_p2p_cnt;
	u32                                host_trigger_dma_cnt;
	u32                                host_trigger_p2p_cnt;

	/* dma inbount/outbount/p2p data total count*/
	u64                                total_data[DMA_DATA_TYPE];
	u64                                gic_mask[8];
	int                                do_dma_irq_status;

	/* add for sriov */
	u8                                 is_virtfn;
	u32 nums_vf;
	struct cn_pci_sriov               *sriov;
	struct cn_pci_vf_priv_data        *vf_priv_data;
	struct dm_per_module_ops           dm_ops;
	struct cn_pci_irq_str_index       *irq_str_index_ptr;

	u32                                bdf;
	int                                outbound_able;
	u32                                non_align_cnt;
	u32                                heartbeat_cnt;
	u32                                soft_retry_cnt;

	u32                                p2p_exchg_cnt;
	int                                force_p2p_xchg_flag;
	/* Add private data for debug dma retransfer used. */
	int dma_err_inject_flag;
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
#define CN_C20_DID		((MLUID_290 >> 16) & 0xffff)
#define CN_C20_VF1_DID		((MLUID_290V1 >> 16) & 0xffff)
#define CN_CE3226_DID		((MLUID_CE3226 >> 16) & 0xffff)
#define CN_CE3226_EDGE_DID	((MLUID_CE3226_EDGE >> 16) & 0xffff)

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
	(linkcap == PCI_EXP_LNKCAP_SLS_16_0GB ? "16.0GT/s" : \
	 linkcap == PCI_EXP_LNKCAP_SLS_8_0GB	? "8.0GT/s" : \
	 linkcap == PCI_EXP_LNKCAP_SLS_5_0GB	? "5.0GT/s" : \
	 linkcap == PCI_EXP_LNKCAP_SLS_2_5GB	? "2.5GT/s" : \
	 "Unknown")

#define PCIE_SPEED_STR(speed) \
	(speed == PCI_EXP_LNKCTL2_TLS_16_0GT ? "16.0GT/s" : \
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
