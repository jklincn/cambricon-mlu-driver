#ifndef CNDRV_COMMU
#define CNDRV_COMMU

#include <linux/fs.h>

struct commu_channel;
struct commu_endpoint;
struct commu_port_proxy;
struct commu_fd_listener;

enum commu_endpoint_type {
	COMMU_ENDPOINT_KERNEL_RPC,
	COMMU_ENDPOINT_USER_RPC,
	COMMU_ENDPOINT_KERNEL_MSG,
	COMMU_ENDPOINT_USER_MSG,
	COMMU_ENDPOINT_KERNEL_PORT,
	COMMU_ENDPOINT_USER_PORT
};

#define COMMU_TESTQ_DESC_SIZE (512)
#define COMMU_TESTQ_DESC_META_SIZE (16)
#define COMMU_TESTQ_DATA_BUF_SIZE (COMMU_TESTQ_DESC_SIZE - COMMU_TESTQ_DESC_META_SIZE)

#ifdef CONFIG_CNDRV_COMMU
int cn_commu_late_init(struct cn_core_set *core);
void cn_commu_late_exit(struct cn_core_set *core);
int cn_commu_reset_callback(struct cn_core_set *core);
void cn_commu_pre_exit(struct cn_core_set *core);
int cn_commu_pre_init(struct cn_core_set *core);
int commu_endpoint_show(struct seq_file *m, void *v);
ssize_t commu_endpoint_write(struct file *file, const char __user *buf,
		size_t count, loff_t *pos);
struct commu_endpoint * connect_rpc_endpoint(struct commu_channel *channel);
struct commu_endpoint *connect_rpc_user_endpoint(struct commu_channel *channel, int eventfd,
						void *ep_user, uint64_t queue_num,
						uint64_t data_size, void *fp, int32_t en_cross);
/* enqueue can be forced quit when SIGHUP received */
int commu_call_rpc(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size);
/* NOT return until enqueue success */
int commu_call_rpc_nokillable(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size);
/* @timeout: timeout, in jiffies */
int commu_call_rpc_timeout(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size, int time_out);
int commu_call_rpc_killable_timeout(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size, int time_out);

struct commu_endpoint * connect_sram_msg_endpoint(struct commu_channel *channel);
struct commu_endpoint * connect_msg_endpoint(struct commu_channel *channel);
struct commu_endpoint *connect_msg_user_endpoint(struct commu_channel *channel, int eventfd,
						void *ep_user, uint64_t queue_num,
						uint64_t data_size, int32_t en_cross);
int commu_send_message(struct commu_endpoint *ep, void *buf, int size);
int commu_send_message_once(struct commu_endpoint *ep, void *buf, int size);
int commu_send_message_until_reset(struct commu_endpoint *ep, void *buf, int size);
int commu_wait_for_message(struct commu_endpoint *ep, void *buf, int *size);
int commu_wait_for_message_seq(struct commu_endpoint *ep, void *buf, int *size, int seq);
int commu_wait_for_message_seq_until_reset(struct commu_endpoint *ep, void *buf, int *size, int seq);

struct commu_port_proxy * connect_port_endpoint(struct commu_channel *channel, u16 port);
struct commu_endpoint *connect_port_user_endpoint(struct commu_channel *channel, void *ep_user,
						int ep_eventfd, uint64_t queue_num,
						uint64_t data_size, void *fp, int32_t en_cross);
int connect_port_user_proxy(struct commu_channel *channel, u16 port, int port_eventfd,
			void *ep_user, int ep_eventfd, uint64_t queue_num,
			uint64_t data_size, void *fp, int32_t en_cross);

int disconnect_port_user_endpoint(struct commu_endpoint *ep, u16 port, void *ep_user);
int disconnect_rpc_user_endpoint(struct commu_endpoint *ep, void *fp);
int disconnect_endpoint(struct commu_endpoint *ep);
int close_a_channel(struct commu_channel *channel);

struct commu_endpoint *search_endpoint_by_type(struct commu_channel *channel, int type);

void *commu_wait_work_run(
		struct cn_core_set *core,
		const char *thread_name,
		struct commu_endpoint *ep,
		void *priv_data,
		void (*call_back)(struct cn_core_set *core,
			void *priv_data,
			void *rx_msg, int rx_size)
		);
void commu_wait_work_stop(
		struct cn_core_set *core,
		void *work_data);

struct commu_channel *commu_open_a_channel(char *name, void *pcore, int fd);
struct commu_channel *commu_search_channel_by_name(void *pcore, char *name);
/* for migration */
u64 commu_get_vf_ctrlq_base(void *pcore, int vf_id);
void commu_set_vf_ctrlq_base(void *pcore, int vf_id, u64 ctrlq_base);
u32 commu_get_vf_ctrlq_head(void *pcore, int vf_id);
void commu_set_vf_ctrlq_head(void *pcore, int vf_id, u32 head);
u32 commu_get_vf_ctrlq_tail(void *pcore, int vf_id);
void commu_set_vf_ctrlq_tail(void *pcore, int vf_id, u32 tail);
u32 commu_get_vf_init_flag(void *pcore, int vf_id);
void commu_set_vf_init_flag(void *pcore, int vf_id, u32 flags);
void commu_restore_vf_ctrlq(void *pcore, int vf, u64 ctrlq_base, u32 head, u32 tail, u32 num);
/* for SRIOV */
void commu_vf2pf_handler(void *pcore, u32 vf_id);
void commu_ctrlq_alloc(void *pcore, u32 vf_id, void *addr, int size);
irqreturn_t commu_ctrlq_alloc_done(void *pcore);
#else
static inline int cn_commu_reset_callback(struct cn_core_set *core)
{
	return -1;
}
static inline int cn_commu_late_init(struct cn_core_set *core)
{
	return -1;
}
static inline void cn_commu_late_exit(struct cn_core_set *core)
{
	return;
}
static inline void cn_commu_pre_exit(struct cn_core_set *core)
{
}
static inline int cn_commu_pre_init(struct cn_core_set *core)
{
	return 0;
}

struct commu_rpc_func {
	char *name;
	int32_t (*func)(void *, int, void *, int *, int);
};

extern struct commu_rpc_func rpc_func[];
int commu_call_rpc(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size);


static inline int commu_call_rpc_timeout(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size, int time_out)
{
	return commu_call_rpc(ep, name, in, in_size, out, out_size);

}

static inline int disconnect_endpoint(struct commu_endpoint *ep)
{
	return 0;
}

static inline int close_a_channel(struct commu_channel *channel)
{
	return 0;
}

static inline struct commu_endpoint *connect_rpc_endpoint(struct commu_channel *channel)
{
	return NULL;
}

static inline struct commu_channel *commu_open_a_channel(char *name, void *pcore, int fd)
{
	return NULL;
}

static inline int commu_wait_for_message(struct commu_endpoint *ep, void *buf, int *size)
{
	return -1;
}

static inline struct commu_endpoint *connect_sram_msg_endpoint(struct commu_channel *channel)
{
	return NULL;
}

static inline struct commu_endpoint *connect_msg_endpoint(struct commu_channel *channel)
{
	return NULL;
}

static inline int commu_proc_list_endpoint(struct commu_endpoint *endpoint)
{
	return 0;
}

static inline void *commu_wait_work_run(
		struct cn_core_set *core,
		const char *thread_name,
		struct commu_endpoint *ep,
		void *priv_data,
		void (*call_back)(struct cn_core_set *core,
			void *priv_data,
			void *rx_msg, int rx_size)
		)
{
	return NULL;
}
static inline void commu_wait_work_stop(
		struct cn_core_set *core,
		void *work_data)
{
}

#endif /* CONFIG_CNDRV_COMMU */
void cn_commu_mailbox_handler(struct cn_core_set *core);

#endif /* CNDRV_COMMU */

