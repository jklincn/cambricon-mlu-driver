#ifndef COMMU_CHANNEL
#define COMMU_CHANNEL
#include <linux/eventfd.h>
#include <linux/hashtable.h>
#include <linux/semaphore.h>
#include <linux/llist.h>
#include "queue_common.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif

#define COMMU_CHANNEL_NAME_MAX_LEN  32
#define COMMU_VF_NUM (0x8)
#define COMMU_VF_PF_NUM (COMMU_VF_NUM + 1)
#define COMMU_ENDPOINT_QUEUE_SIZE  (0x4000)
#define COMMU_ENDPOINT_RTE_QUEUE_SIZE  (0x21000)
#define COMMU_ENDPOINT_QUEUE_DEPTH (32)
#define COMMU_ENDPOINT_RPC_BUFFER_IN_SIZE (512)
#define COMMU_ENDPOINT_RPC_BUFFER_OUT_SIZE (128)
#define COMMU_ENDPOINT_MAX_PORT  (65536)
#define COMMU_OUTBOUND_CFG_OFFSET (4092)

#define COMMU_KERNEL_QUEUE_DATA_BUF_SIZE (496)
#define COMMU_USER_QUEUE_DATA_BUF_SIZE (4096)
#define COMMU_QUEUE_NUM (32)
#define COMMU_SET_SHADOW_HEAD_TAIL (1UL << 32)
//#define COMMU_DEBUG
#define COMMU_ENABLE_INFO

#ifdef COMMU_DEBUG
#define COMMU_DBG(string, arg...) \
do { \
	pr_debug(string, ##arg); \
} while (0)
#else
#define COMMU_DBG(string, arg...) \
do { \
	\
} while (0)
#endif

#ifdef COMMU_ENABLE_INFO
#define COMMU_INFO_LIMIT(string, arg...) \
	printk_ratelimited("[%s][%d][%d] " string, __func__, __LINE__,\
			current->pid, ##arg)

#define COMMU_INFO(string, arg...) \
do { \
	pr_info("[%s][%d][%d] " string, __func__, __LINE__,\
			current->pid, ##arg); \
} while (0)
#else
#define RTEQ_INFO(string, arg...) \
do { \
	\
} while (0)
#endif

enum {
	COMMU_PLAT_HOST,
	COMMU_PLAT_DEV
};

enum commu_ctrlq_host_command {
	/*
	 * CRE Connect Rpc Endpoint
	 * DE  Disconnect Endpoint
	 * CPP Connect Port Proxy
	 * CE Connect Endpoint
	 */
	COMMU_CMD_SET_ARM2VF_ADDR = 0xc002,
	COMMU_CMD_CRE_UPPER = 0xc003,
	COMMU_CMD_CRE_UPPER_PLUS = 0xc004,
	COMMU_CMD_CRE_BOTTOM = 0xc005,
	COMMU_CMD_CME_UPPER = 0xc006,
	COMMU_CMD_CME_BOTTOM = 0xc007,
	COMMU_CMD_DE_UPPER = 0xc008,
	COMMU_CMD_DE_BOTTOM = 0xc009,
	COMMU_CMD_CPE_UPPER = 0xc010,
	COMMU_CMD_CPE_BOTTOM = 0xc011,
	COMMU_CMD_CPP = 0xc012,
	COMMU_CMD_VF_EXIT = 0xc013,
	COMMU_CMD_HOSTP_HUP = 0xc015,
	COMMU_CMD_HOSTR_HUP = 0xc016,
	COMMU_CMD_CE_CANCEL = 0xc017,
	COMMU_CMD_RESET_SERVER = 0xc018,
	COMMU_CMD_QUERY_STATUS = 0xc019,
	COMMU_CMD_CME_UPPER_PLUS = 0xc020,
	COMMU_CMD_CPE_UPPER_PLUS = 0xc021,
	COMMU_CMD_PCIE_SRAM_INIT = 0xc022,
	COMMU_CMD_CME_UPPER_SRAM = 0xc023
};

enum commu_ctrlq_reply {
	COMMU_RET_SET_ARM2VF_ADDR = 0xc002,
	COMMU_RET_CRE_UPPER = 0xc003,
	COMMU_RET_CRE_UPPER_PLUS = 0xc004,
	COMMU_RET_CRE_BOTTOM = 0xc005,
	COMMU_RET_CME_UPPER = 0xc006,
	COMMU_RET_CME_BOTTOM = 0xc007,
	COMMU_RET_DE_UPPER = 0xc008,
	COMMU_RET_DE_BOTTOM = 0xc009,
	COMMU_RET_CPE_UPPER = 0xc010,
	COMMU_RET_CPE_BOTTOM = 0xc011,
	COMMU_RET_CPP = 0xc012,
	COMMU_RET_VF_EXIT = 0xc013,
	COMMU_RET_HOSTP_HUP = 0xc015,
	COMMU_RET_HOSTR_HUP = 0xc016,
	COMMU_RET_CE_CANCEL = 0xc017,
	COMMU_RET_RESET_SERVER = 0xc018,
	COMMU_RET_QUERY_STATUS = 0xc019,
	COMMU_RET_CME_UPPER_PLUS = 0xc020,
	COMMU_RET_CPE_UPPER_PLUS = 0xc021,
	COMMU_RET_PCIE_SRAM_INIT = 0xc022,
	COMMU_RET_CME_UPPER_SRAM = 0xc023,
	/* ERRNO */
	COMMU_RET_FAILED = 0xe002,
	COMMU_RET_ALLOC_EP_FAILED = 0xe003,
	COMMU_RET_COMMU_COMMAND_FAILED = 0xe004,
	COMMU_RET_NO_SERVER = 0xe005,
	COMMU_RET_NO_CHANNEL = 0xeeee
};

enum commu_ctrlq_dev_command {
	COMMU_DCMD_DATA_SENT = 0xd002,
	COMMU_DCMD_DEV_HUP = 0xd003,
	COMMU_DCMD_QUEUE_SUSPEND = 0xd004,
	COMMU_DCMD_EP_REBUILD = 0xd005
};

enum {
	COMMU_MIGRATION_SUSPEND_RX,
	COMMU_MIGRATION_SUSPEND_TX,
	COMMU_MIGRATION_RESUME_RX,
	COMMU_MIGRATION_RESUME_TX,
	COMMU_MIGRATION_RESUME_TX_RX,
	COMMU_MIGRATION_UPDATE_EP_PAIR
};

enum {
	COMMU_QUEUE_RX,
	COMMU_QUEUE_TX
};

struct commu_vqueue {
	void *core_set;
	struct commu_ops *ops;
	void *real_queue;
	void *base_addr;
	u32 entry_num;
	u32 entry_size;
};

#define DEF_CALLBACK_PAIR(fn) \
	{#fn, fn}
#define DEF_CALLBACK_PAIR_END \
	{NULL, NULL}

#define DECLARE_CALLBACK_FUNC(fn) \
static int fn(void *, int, void *, int *)

typedef int (*commu_callback_func)(void *in_msg, int in_len, void *out_msg, int *out_len);

struct commu_callback_map {
	char *func_name;
	commu_callback_func func;
};

struct commu_fd_listener {
	void *fd;
	struct eventfd_ctx *listener;
	struct hlist_node fd_listener_node;
};

struct commu_endpoint {
	u64 id;
	u64 pair; /* pointer to pair struct ep another side */
	u64 ep_user;
	u64 rpc_flag;
	u16 vf_id;
	u16 type;
	u16 use_pcie_sram;
	u16 use_sync_write;
	u64 sync_write_pa;

	struct eventfd_ctx *listener;
	struct hlist_head process_listeners[256];
	wait_queue_head_t waitqueue;
	struct work_struct work;
	spinlock_t ep_lock;
	struct semaphore ep_sema;
	int on_polling;
	int free_me;

	struct commu_callback_map *callbacks;
	struct commu_vqueue tx;
	struct commu_vqueue rx;
	u32 priority;
	u32 no_rx;
	struct commu_channel *channel;
	void (*callback)(struct commu_vqueue *queue);
	struct llist_node all_poll_node;
	struct llist_node channel_node;
	struct llist_node vf_node;

	struct commu_port_proxy *ports;
	int ports_alloc;/*kzalloc or vmalloc*/

	struct semaphore ep_user_sema;
	u64 lock_owner;
	struct mutex ep_mutex;
};

struct commu_port_proxy {
	u32 port;
	int32_t in_using;
	struct commu_endpoint *ep;
	union {
		wait_queue_head_t waitqueue;
		struct {
			struct eventfd_ctx *listener;
			void *ep_user;
			void *fp;
		};
	};
};
//struct commu_endpoints

struct commu_channel {
	char name[COMMU_CHANNEL_NAME_MAX_LEN];
	u64 hash_name;

	struct eventfd_ctx *listener;
	struct hlist_head process_listeners[256];
	//struct commu_endpoint *endpoints;
	struct llist_head channel_endpoints_head;
	struct hlist_node channel_node;
	void (*callback)(struct commu_endpoint *endpoint);

	u8 kernel_channel;
	void *desc_to_user; /* buffer between user and kernel */
	void *current_desc_user;

	/* TODO define struct commu_adapter to manage msi/control queue/base addr ... */
	void (*doorbell)(int vf_id, u64 pair_pointer);
	void* controller;
	void* core_set;

	/* used for msg queue */
	wait_queue_head_t waitqueue;
	struct commu_endpoint *current_ep;
	int on_polling;
	struct commu_endpoint *ep[COMMU_VF_PF_NUM];

	/* used for port queue */
	struct commu_endpoint *real_ep;
	struct commu_endpoint *port_ep[COMMU_VF_PF_NUM];

	u8 raw_callback;
	struct work_struct hup_work;
	struct mutex mutex;
};

u64 commu_string_hash(char *name);

struct commu_channel * register_a_channel(char *name, void *callback, int fd, void *doorbell);
struct commu_channel * register_a_channel_in_kernel(char *name, void *callback, void *doorbell);
struct commu_channel * register_a_channel_nodb(char *name, void *callback);
struct commu_channel * register_a_channel_with_rawcb(char *name, void *callback);
void unregister_a_channel(char *name);
void update_channel(struct commu_channel *channel);
struct commu_channel * get_commu_channel_by_hash_name(u64 hash_name);
struct commu_channel * get_commu_channel_by_name(char *name);
struct commu_endpoint * get_commu_endpoint_by_name(struct commu_channel *channel, int vf_id);
int query_commu_endpoint_by_name(struct commu_channel *channel, int vf_id);

struct commu_endpoint * open_an_endpoint(struct commu_channel*, u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length);
struct commu_endpoint * open_an_endpoint_by_ops(struct commu_channel*, u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length, struct commu_ops *ops);
struct commu_endpoint * open_an_endpoint_in_host(struct commu_channel*, u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length);
struct commu_endpoint * open_an_endpoint_in_host_by_ops(struct commu_channel*, u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length, struct commu_ops *ops, int32_t en_cross);
struct commu_endpoint * create_rpc_endpoint(char *name, u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length, struct commu_callback_map *callbacks);
struct commu_endpoint * create_msg_endpoint(char *name, u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length, struct commu_callback_map *callbacks);
struct commu_endpoint * create_port_endpoint(char *name, u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length);
int commu_enable_endpoint(struct commu_endpoint *endpoint, int host_or_dev);

int commu_wait_for_message_arm(struct commu_channel *channel, void *buf, int *size, int *vf_id);
int commu_send_message_arm(struct commu_channel *channel, void *buf, int size, int vf_id, int seq);

int channel_module_init(void);
int commu_all_poll_worker(void *data);

int close_an_endpoint(struct commu_endpoint *ep);

void endpoint_set_sync_write(struct commu_endpoint *ep);
#endif
