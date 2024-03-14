#ifndef __CN_IPCM_H__
#define __CN_IPCM_H__

#include "cndrv_core.h"

#define IPCM_DAEMON_PORT    (0xcabc)

/* physical size */
#define MAX_RPMSG_BUF_SIZE	(1024)
/* MAX_RPMSG_BUF_SIZE - package_hdr(34) - rpmsg_hdr(16) */
/* user available size */
#define MAX_BUF_LEN	(MAX_RPMSG_BUF_SIZE - 64)

struct rpmsg_device;

typedef int (*request_cb_t)(void *data, void *req, int req_sz, void *resp, int resp_sz);

typedef int (*ipcm_rx_cb_t)(struct rpmsg_device *rpdev, unsigned long packet_id,
		void *message, int message_size, void *priv, u32 src);

#define DEF_CALLBACK_PAIR(fn) \
	{#fn, fn}
#define DEF_CALLBACK_PAIR_END \
	{NULL, NULL}

#define IPCM_DECLARE_CALLBACK_FUNC(fn) \
static int fn(void *, int, void *, int *, int)

typedef int (*rpmsg_rpc_service_t)(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id);

dev_t cn_ipcm_get_rpmsg_major(void);

struct rpmsg_rpc_service_set {
	char *func_name;
	rpmsg_rpc_service_t func;
};

#ifdef CONFIG_CNDRV_IPCM
extern int cn_ipcm_dev_init(struct cn_core_set *core);

extern void cn_ipcm_dev_exit(struct cn_core_set *core);

extern int cn_ipcm_late_init(struct cn_core_set *core);
extern void cn_ipcm_late_exit(struct cn_core_set *core);

/*
 * edge's driver register already in ipcm_drv.ko,
 * cndrv_host only register device
 */
#ifndef CONFIG_CNDRV_EDGE
extern int cn_ipcm_driver_init(void);

extern void cn_ipcm_driver_exit(void);
#else
static inline int cn_ipcm_driver_init(void) { return 0; }

static inline void cn_ipcm_driver_exit(void) {}
#endif /* CONFIG_CNDRV_EDGE */

/* public api */

/* for test only, use the latest vrp */
struct rpmsg_device *__ipcm_open_channel(char *channel_name);
struct rpmsg_device *__ipcm_open_user_channel(char *channel_name, u32 dst);

static inline bool cn_ipcm_enable(void *core)
{
	struct cn_core_set *_core = (struct cn_core_set *)core;

	if (isEdgePlatform(_core))
		return false;

	if (MLUID_MAJOR_ID(_core->device_id) >= 3)
		return true;

	return false;
}

struct rpmsg_device *ipcm_open_channel(void *core, char *channel_name);
struct rpmsg_device *ipcm_open_user_channel(void *core, char *channel_name, u32 dst);
int ipcm_destroy_channel(struct rpmsg_device *rpdev);
void ipcm_set_rx_callback(struct rpmsg_device *rpdev, ipcm_rx_cb_t rx_callback);
void ipcm_set_rx_async_callback(struct rpmsg_device *rpdev, ipcm_rx_cb_t rx_callback);
void ipcm_set_rpc_services(struct rpmsg_device *rpdev, struct rpmsg_rpc_service_set *functions);
/* priv is use at ipcm_rx_cb_t */
void ipcm_set_priv_data(struct rpmsg_device *rpdev, void *priv);
void *ipcm_get_priv_data(struct rpmsg_device *rpdev);
int ipcm_get_vf_id(struct rpmsg_device *rpdev);
/* break all waitq while remote crash */
int ipcm_reset_callback(void *core);
/* file xfer api */
int ipcm_remote_open(void *core, struct rpmsg_device **rpdev, const char *filename, int flags, int mode);
int ipcm_remote_close(struct rpmsg_device *rpdev, int fd);
int ipcm_remote_read(struct rpmsg_device *rpdev, int fd, unsigned char *buffer, int buflen);
int ipcm_remote_write(struct rpmsg_device *rpdev, int fd, const unsigned char *ptr, int len);
/* cmd exec api */
int cmd_exec_dummy_cb(struct rpmsg_device *rpdev, unsigned long packet_id,
		void *message, int message_size, void *priv, u32 src);
int ipcm_exec_cmd(void *core, const char *cmd, ipcm_rx_cb_t rx_callback);
int ipcm_announce_vf_status(void *core, bool start, int vf_id);
int ipcm_enable_perf_record(void *core, int test_cnt, int record_en);
int ipcm_record_show(struct seq_file *m, void *v);

bool ipcm_channel_ready(struct rpmsg_device *rpdev);

/* send msg non-blocking/async, when response arrive will call the callback */
int ipcm_send_request_with_callback(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size, void *cb_data,
		request_cb_t callback);

/* send msg blocking/sync, blocked until the response arrived */
int ipcm_send_request_with_response(struct rpmsg_device *rpdev,
		bool interruptible, void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size);

int ipcm_send_request_with_response_to_port(struct rpmsg_device *rpdev,
		bool interruptible,	void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size, int port);

/* send msg without response */
int ipcm_send_message(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size);

/* try send msg without response */
int ipcm_trysend_message(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size);

/* send response to the related package_id */
int ipcm_send_response(struct rpmsg_device *rpdev, unsigned long packet_id,
		void *response, uint32_t response_size);

/* caller must make sure the sizeof out */
int ipcm_rpc_call(struct rpmsg_device *rpdev, char *fn_name,
		void *in, uint32_t in_size,
		void *out, uint32_t *real_size, uint32_t out_size);

int ipcm_rpc_call_no_killable(struct rpmsg_device *rpdev, char *fn_name,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size);

int ipcm_rpc_call_timeout(struct rpmsg_device *rpdev, char *fn_name,
		void *in, uint32_t in_size,
		void *out, uint32_t *real_size, uint32_t out_size, int time_out_ms);

int ipcm_rpc_call_async(struct rpmsg_device *rpdev, char *fn_name,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size);
#else /* !CONFIG_CNDRV_IPCM */
static inline int cn_ipcm_dev_init(struct cn_core_set *core)
{
	return 0;
}

static inline void cn_ipcm_dev_exit(struct cn_core_set *core)
{
}

static inline int cn_ipcm_late_init(struct cn_core_set *core)
{
	return 0;
}

static inline void cn_ipcm_late_exit(struct cn_core_set *core)
{
	return;
}

static inline int cn_ipcm_driver_init(void)
{
	return 0;
}

static inline void cn_ipcm_driver_exit(void)
{
}

static inline bool cn_ipcm_enable(void *core)
{
	return false;
}
static inline struct rpmsg_device *ipcm_open_channel(void *core, char *channel_name)
{
	return NULL;
}
static inline struct rpmsg_device *ipcm_open_user_channel(void *core, char *channel_name, u32 dst)
{
	return NULL;
}
static inline int ipcm_destroy_channel(struct rpmsg_device *rpdev)
{
	return 0;
}
static inline void ipcm_set_rx_callback(struct rpmsg_device *rpdev, ipcm_rx_cb_t rx_callback)
{
}
static inline void ipcm_set_rx_async_callback(struct rpmsg_device *rpdev, ipcm_rx_cb_t rx_callback)
{
}
static inline void ipcm_set_rpc_services(struct rpmsg_device *rpdev, struct rpmsg_rpc_service_set *functions)
{
}
static inline void ipcm_set_priv_data(void *core)
{
}
static inline void *ipcm_get_priv_data(struct rpmsg_device *rpdev)
{
	return NULL;
}
static inline int ipcm_get_vf_id(struct rpmsg_device *rpdev)
{
	return 0;
}
static inline int ipcm_reset_callback(void *core)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_remote_open(struct rpmsg_device *rpdev, const char *filename, int flags, int mode)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_remote_close(struct rpmsg_device *rpdev, int fd)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_remote_read(struct rpmsg_device *rpdev, int fd, unsigned char *buffer, int buflen)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_remote_write(struct rpmsg_device *rpdev, int fd, const unsigned char *ptr, int len)
{
	return -EOPNOTSUPP;
}
static inline int cmd_exec_dummy_cb(struct rpmsg_device *rpdev, unsigned long packet_id,
		void *message, int message_size, void *priv, u32 src)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_exec_cmd(int card, const char *cmd, ipcm_rx_cb_t rx_callback)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_announce_vf_status(void *core, bool start, int vf_id)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_enable_perf_record(void *core, int test_cnt, int record_en)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_record_show(struct seq_file *m, void *v)
{
	return -EOPNOTSUPP;
}
static inline bool ipcm_channel_ready(struct rpmsg_device *rpdev)
{
	return false;
}
static inline int ipcm_send_request_with_callback(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size, void *cb_data,
		request_cb_t callback)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_send_request_with_response(struct rpmsg_device *rpdev,
		bool interruptible, void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_send_request_with_response_to_port(struct rpmsg_device *rpdev,
		bool interruptible,	void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size, int port)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_send_message(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_trysend_message(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_send_response(struct rpmsg_device *rpdev, unsigned long packet_id,
		void *response, uint32_t response_size)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_rpc_call(struct rpmsg_device *rpdev, char *fn_name,
		void *in, uint32_t in_size,
		void *out, uint32_t *real_size, uint32_t out_size)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_rpc_call_no_killable(struct rpmsg_device *rpdev, char *fn_name,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_rpc_call_timeout(struct rpmsg_device *rpdev, char *fn_name,
		void *in, uint32_t in_size,
		void *out, uint32_t *real_size, uint32_t out_size, int time_out_ms)
{
	return -EOPNOTSUPP;
}
static inline int ipcm_rpc_call_async(struct rpmsg_device *rpdev, char *fn_name,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_CNDRV_IPCM */

#endif // __CN_IPCM_H__
