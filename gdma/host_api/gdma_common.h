/*
 * gdma/gdma_common.h
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
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
 */

#ifndef __CNDRV_GDMA_COMMON_H__
#define __CNDRV_GDMA_COMMON_H__

#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#include <linux/kfifo.h>

#include "cndrv_core.h"
#include "gdma_api.h"

#define GDMA_CONTROLLER_MAX_CHANNEL (4)
#define GDMA_VCHAN_DESC_BUFFER_SIZE (4 * 32)
#define GDMA_MEMSET_BUFFER_SIZE (1024)
#define GDMA_SEARCH_RETRY_COUNT (128)
#define GDMA_PCHAN_RETRY_COUNT (5)
#define GDMA_MAX_CTRL_NUM (6)
#define GDMA_IRQ_NUM (19)
#define GDMA_POLL_TIMEOUT (5000000)
//#define GDMA_POLL_TIMEOUT (500) //ZEBU TEST
#define GDMA_POLL_MODE_TX_SIZE (4 * 1024 * 1024)
#define GDMA_LOW_TRANSFER_SIZE (4 * 1024 * 1024)
#define GDMA_MEDIUM_TRANSFER_SIZE (32 * 1024 * 1024)
#define GDMA_LOW_TX_LOAD (2 * 1024 * 1024)
#define GDMA_MEDIUM_TX_LOAD (4 * 1024 * 1024)
#define GDMA_HIGH_TX_LOAD (8 * 1024 * 1024)

#define SET_BIT(X, BIT) ((X) = (X) | (0x01 << (BIT)))
#define CLR_BIT(X, BIT) ((X) = (X) & ~(0x01 << (BIT)))

enum cn_gdma_mode {
	GDMA_INVAILD_MODE = 0,
	GDMA_HOST_MODE,
	GDMA_DEVICE_MODE,
};

enum cn_gdma_tx_mode {
	GDMA_TX_POLL_MODE = 0,
	GDMA_TX_INTR_MODE = 1,
};

enum cn_gdma_hw_status {
	GDMA_CHAN_HW_IDLE = 0x01,
	GDMA_CHAN_HW_RUN = 0x02,
	GDMA_CHAN_HW_SUSPEND = 0x04,
	GDMA_CHAN_HW_ERROR = 0x08,
};

enum cn_gdma_irq_type {
	GDMA_IRQ_CTRL_TYPE = 0,
	GDMA_IRQ_CHANNEL_TYPE,
};

enum cn_gdma_task_status {
	GDMA_TASK_IDLE = 0,
	GDMA_TASK_ASSIGNED,
	GDMA_TASK_READY,
	GDMA_TASK_SCHED,
	GDMA_TASK_SUSPEND,
	GDMA_TASK_PENDING,
	GDMA_TASK_DONE,
	GDMA_TASK_EXIT,
	GDMA_TASK_ERROR,
};

enum cn_gdma_channel_status {
	GDMA_CHANNEL_IDLE = 0,
	GDMA_CHANNEL_ASSIGNED,
	GDMA_CHANNEL_READY,
	GDMA_CHANNEL_RUN,
	GDMA_CHANNEL_SUSPEND,
	GDMA_CHANNEL_PENDING,
	GDMA_CHANNEL_DONE,
	GDMA_CHANNEL_ABORT,
	GDMA_CHANNEL_FAILED,
	GDMA_CHANNEL_OFFLN, //Means the pchan not on line to be used
};

/*GDMA Channel mode*/
enum cn_gdma_channel_mode_t {
	GDMA_CHANNEL_MODE_REG  = 0,
	GDMA_CHANNEL_MODE_DSEC,
	GDMA_CHANNEL_MAX_MODE,
};

/*GDMA Channel descriptor store type*/
enum cn_gdma_descrpt_store_type_t {
	GDMA_DESCRPT_STORE_RING_BUFFER = 0,
	GDMA_DESCRPT_STORE_LINK_LIST,
	GDMA_DESCRPT_MAX_STORE_TYPE,
};

/*GDMA Ringbuffer mode buf block size*/
enum cn_gdma_descrpt_buf_block_size_t {
	GDMA_DESCRPT_BUF_BLOCK_SIZE_16 = 0,
	GDMA_DESCRPT_BUF_BLOCK_SIZE_32,
	GDMA_DESCRPT_BUF_BLOCK_SIZE_64,
	GDMA_DESCRPT_BUF_BLOCK_SIZE_128,
	GDMA_DESCRPT_BUF_BLOCK_SIZE_256,
	GDMA_DESCRPT_BUF_BLOCK_SIZE_512,
	GDMA_DESCRPT_BUF_BLOCK_SIZE_1024,
	GDMA_DESCRPT_BUF_BLOCK_SIZE_2048,
};

/*GDMA channel config struct*/
struct cn_gdma_chan_config {
	unsigned char mode;
	unsigned char read_ostd;
	unsigned char write_ostd;
	unsigned char intr_enable;
	u32 axi_wattr;
	u32 axi_rattr;
};

/*GDMA channel desc config struct*/
struct cn_gdma_descrpt_config {
	unsigned char store_type;
	unsigned char osf_mode;
	unsigned char buf_block_size;
	unsigned char prefetch_num;
	unsigned char prefetch_thresd;
	unsigned char write_back_thresd;
};

struct context_1_desc_param {
	u64 src;
	u64 dst;
	size_t len;
	u32 data_line;
	u32 data_column;
	u32 total_copy;

	u32 dim2_en;
	u32 dim3_en;
	u32 dim1_len;
	u32 dim2_len;
	u32 dim2_stride;
	u64 dim3_stride;
	u32 dim3_stride_sign;
	u32 halt;
	u32 sod;
};

struct cn_shm {
	unsigned long                      host_kva;
	u64                                dev_va;
	u64                                size;
};

struct cn_gdma_package {
	u64                                src;
	u64                                dst;
	u64                                len;
	u32                                type;
};

struct cn_gdma_task {
	volatile u8 status;
	volatile u8 error_flag;
	volatile u8 channel_done;
	volatile u8 trigger_tx;
	volatile int channel_tx_count;
	u64 tx_max_load;
	u64 remain_src;
	u64 remain_dst;
	volatile u64 remain_size;
	volatile u64 total_tx_num;
	volatile u64 finish_tx_num;

	struct cn_gdma_set                *gdma_set;
	u32                                idx;
	struct cn_gdma_transfer            transfer;
	volatile u8                        dma_tx_mode;

	/* memset */
	u64                                memset_value;
	struct cn_shm                      memset_shm;

	/* chan */
	struct cn_gdma_phy_chan           *pchan;
	u32                                priv_vchan_num;
	struct cn_gdma_virt_chan         **priv_vchan;
	struct kfifo                       ready_vchan_fifo;
	spinlock_t                         ready_vchan_lock;
	wait_queue_head_t                  channel_wq;
};

struct cn_gdma_phy_chan;

struct cn_gdma_controller;

struct cn_gdma_virt_chan {
	struct cn_gdma_set                *gdma_set;
	volatile u8                        status;
	struct cn_shm                      desc_shm;
	struct cn_gdma_task               *task;
	volatile u8                        dma_tx_mode;
	struct cn_gdma_package             pkg;
	u32                                idx;
};

struct cn_gdma_phy_chan {
	struct cn_gdma_set                *gdma_set;
	struct cn_gdma_controller         *ctrl;
	struct cn_gdma_virt_chan          *vchan;
	u32                                idx;
	u32                                config_reg;
	unsigned long                      base;
	volatile u8                        status;
	u16                                irq;
	char                               irq_name[20];
};

struct cn_gdma_ops;

struct cn_gdma_controller {
	struct cn_gdma_set                *gdma_set;
	const struct cn_gdma_ops          *ops;
	u32                                idx;
	u16                                irq;
	unsigned long                      main_csr_base;
	unsigned long                      top_csr_base;
	unsigned long                      top_sec_base;
	unsigned long                      smmu_base;
	u32                                pchan_num;
	struct cn_gdma_phy_chan           *pchans[GDMA_CONTROLLER_MAX_CHANNEL];
};

struct cn_gdma_ops {
	int (*release_reset)(struct cn_gdma_controller *ctrl);
	int (*reset_channel)(struct cn_gdma_controller *ctrl, u32 chnnl);
	int (*enable_channel_clk)(struct cn_gdma_controller *ctrl, u32 chnnl);
	int (*disable_channel_clk)(struct cn_gdma_controller *ctrl, u32 chnnl);
	u32 (*read_main_intr_out)(struct cn_gdma_controller *ctrl);
	int (*main_intr_clear)(struct cn_gdma_controller *ctrl);
	int (*get_channel_status)(struct cn_gdma_controller *ctrl,
					u32 chnnl, u32 *status);
	u32 (*read_dma_int_stat)(struct cn_gdma_controller *ctrl);
	int (*get_id)(struct cn_gdma_controller *ctrl, u32 *id);
	void (*channel_start)(struct cn_gdma_phy_chan *chan);
	void (*channel_suspend)(struct cn_gdma_phy_chan *chan);
	void (*channel_halt)(struct cn_gdma_phy_chan *chan);
	void (*channel_resume)(struct cn_gdma_phy_chan *chan);
	void (*channel_abort)(struct cn_gdma_phy_chan *chan);
	int (*channel_setup_descrpt_tx)(struct cn_gdma_phy_chan *chanl, u64 desc);
	int (*channel_setup_reg_mode_tx)(struct cn_gdma_phy_chan *chan,
					u64 src, u64 dst, u32 data_len);
	int (*channel_irq_enable)(struct cn_gdma_phy_chan *chan);
	int (*channel_irq_disable)(struct cn_gdma_phy_chan *chan);
	int (*channel_intr_clear)(struct cn_gdma_phy_chan *chan);
	u32 (*read_channel_intr_out)(struct cn_gdma_phy_chan *chan);
	int (*ctrl_hardware_init)(struct cn_gdma_controller *ctrl);
	int (*channel_hardware_init)(struct cn_gdma_phy_chan *chan);
	int (*smmu_irq_handle)(struct cn_gdma_controller *ctrl);
	int (*do_ctrl_irq)(struct cn_gdma_controller *ctrl, u32 *intr_stat);
	void (*ctrl_reg_dump)(struct cn_gdma_controller *ctrl);
	void (*channel_reg_dump)(struct cn_gdma_phy_chan *chan);
	void (*channel_ecc_inject)(struct cn_gdma_phy_chan *chan, int enable);
	u32 (*ctrl_reg_dfx_dump)(struct cn_gdma_controller *ctrl, char *buf);
	u32 (*channel_reg_dfx_dump)(struct cn_gdma_phy_chan *chan, char *buf);
};

struct cn_gdma_plat_driver {
	uint64_t device_id;
	int (*info_probe)(void *gdma_set);
	int (*init_ctrl_res)(void *dev, int dev_num);
};

struct cn_gdma_smmu_info {
	int smmu_group;
	int smmu_index;
};

struct cn_gdma_set_info {
	u32                                irq_type;
	u32                                ctrl_num;
	u32                                ctrl_chan_num;
	u32                                vchan_num;
	u32                                priv_vchan_num;
	u32                                task_num;
	u32                                memset_buf_size;
	struct cn_gdma_smmu_info           smmu_info[GDMA_MAX_CTRL_NUM];
};

struct cn_gdma_load_param {
	int                                mode;
	int                                ctrl_num;
	struct cn_gdma_smmu_info           smmu_info[GDMA_MAX_CTRL_NUM];
};

struct cn_gdma_set {
	struct cn_core_set                *core;
	char                               core_name[32];
	void                              *load_endpoint;
	struct cn_gdma_plat_driver        *plat_drv;
	const struct cn_gdma_set_info     *info;

	/* online state record */
	u32 ctrl_onln[GDMA_MAX_CTRL_NUM];
	u32 ctrl_pchan_onln[GDMA_MAX_CTRL_NUM][GDMA_CONTROLLER_MAX_CHANNEL];
	u32 available_pchan_num;

	/* Some plat(zebu.eg) not all gdma OK. If 0x00 means all OK */
	u32 hw_gdma_mask;

	/* vchan */
	u32                                vchan_num;
	struct cn_gdma_virt_chan         **vchan_pool;
	volatile u32                       vchan_search_start;
	struct cn_shm                      shared_desc_shm;
	struct cn_shm                      priv_desc_shm;

	/* ctrl */
	u32                                ctrl_num;
	struct cn_gdma_controller        **ctrl_pool;

	/* pchan */
	u32                                total_pchan_num;
	struct cn_gdma_phy_chan          **pchan_pool;
	struct semaphore                   total_pchan_sem;
	volatile u32                       pchan_search_start;

	/* task */
	u32                                task_num;
	struct cn_gdma_task              **task_pool;
	struct semaphore                   task_sem;
	volatile u32                       task_search_start;
	struct cn_shm                      memset_shm;

	/* dfx */
	u8                                 debug_print;
	u8                                 inject_ecc_error;
	u64                                inject_error_src;
	struct cn_report_block            *nb_gdma_dump;
	u32                                poll_size;
};

struct cn_gdma_irq_entry {
	int irq_index;
	char *irq_name;
	void (*irq_handler)(char *, struct cn_gdma_phy_chan *);
};

struct cn_gdma_device_id {
	uint64_t device_id;
	int mode;
};

#endif
