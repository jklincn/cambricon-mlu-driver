#ifndef COMMU_INTERNAL_API
#define COMMU_INTERNAL_API
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/hashtable.h>
#include "./commu/ctrlqueue.h"
#include "./commu/channel.h"

struct commu_user_mmap {
	struct ctrlq_desc desc;
	void *ep;
	/* flag for polling */
	volatile uint64_t sign;
	uint64_t pair;
	void *ep_user;
	uint64_t on_polling_addr;
	uint64_t channel_on_polling_addr;
	uint64_t head_addr;
	uint64_t tail_addr;
};

/* MACRO to enable host polling in case of interrupt not available */
//#define COMMU_HOST_POLL

/* Host write mailbox to inform device, SHOULD enable with device interrupt */
//#define COMMU_ENABLE_DATA_INTERRUPT

struct commu_vf_controller {
	/* msi/base/ctrlq */
	struct ctrlq_queue vf2pf;
	struct ctrlq_queue arm2vf;
	struct ctrlq_queue arm2vf_user;
	void *ob_va;
	dma_addr_t ob_ba;
	wait_queue_head_t commu_waitqueue;
	void *pci_adapter;
	void (*doorbell)(void *adapter);

	struct cdev   commu_dev;
	struct class *commu_class;
	dev_t dev_no;
};

struct commu_pcie_sram_set {
	u64 sram_va;
	u64 sram_ba;
	u64 sram_dev_pa;
};

struct commu_set {
	/* pf */
	struct ctrlq_queue pf2arm;
	struct ctrlq_queue arm2pf;
	struct ctrlq_queue vf2pf_pf[COMMU_VF_NUM];
	int init_sign[COMMU_VF_NUM];
	struct ctrlq_queue arm2pf_host;
	struct ctrlq_queue arm2pf_user;
	struct ctrlq_queue pf_user2arm;

	/* vf */
	struct ctrlq_queue vf2pf;
	struct ctrlq_queue arm2vf;
	struct ctrlq_queue vf2arm;
	struct ctrlq_queue arm2vf_user;
	struct ctrlq_queue vf_user2arm;
	void *ob_va;
	dma_addr_t ob_ba;
	u64 ib_va;
	u64 ib_ba;
	wait_queue_head_t commu_waitqueue;
	u32 ctrlq_alloc_wait_flag;
	void (*doorbell)(void *core_set);
	void (*data_doorbell)(void *ep);

	struct cdev   commu_dev;
	struct class *commu_class;
	dev_t dev_no;
	struct mutex mutex;

	/* common */
	void *core_set;
	struct ctrlq_queue *ctrlq_send;
	struct ctrlq_queue *ctrlq_recv;
	struct ctrlq_queue *ctrlq_recv_user;
	struct ctrlq_queue *ctrlq_send_user;
	struct hlist_head commu_channel_head[256];

	struct ctrlq_desc desc;
	/* flag for commu_ctrlq_sync */
	volatile int64_t on_polling;
	wait_queue_head_t commu_hup_waitqueue;
	struct ctrlq_desc hup_desc;

#ifdef COMMU_HOST_POLL
	struct task_struct *poll_worker;
#endif
	int reset_sign;
#ifdef CONFIG_CNDRV_EDGE
	struct delayed_work poll_work;
#endif
	struct work_struct migration_work;
	wait_queue_head_t migration_waitqueue;
	int32_t suspend_tx;
	int32_t suspend_rx;
	int32_t migration_command;
	int32_t en_outbound;
	int32_t en_pcie_sram;
	int32_t en_sync_write;
	struct mutex user_mutex;

	u32 pf_id;

	struct commu_pcie_sram_set *sram;
};

struct commu_channel *open_a_channel(char *name, void *controller, int fd);
struct commu_channel *search_channel_by_name(void *controller, char *name);
struct commu_fd_listener *search_listener_by_fp(struct commu_channel *channel, void *fp);
struct commu_fd_listener *search_listener_in_ep_by_fp(struct commu_endpoint *ep, void *fp);
int commu_spin_lock(volatile uint64_t *sign);
int commu_spin_unlock(volatile uint64_t *sign);

#endif /* COMMU_INTERNAL_API */
