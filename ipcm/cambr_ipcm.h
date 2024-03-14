#ifndef _CAMBR_IPCM_H
#define _CAMBR_IPCM_H

#include <linux/version.h>
#include <linux/types.h>


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

struct rpmsg_rpc_service_set {
	char *func_name;
	rpmsg_rpc_service_t func;
};

struct rpmsg_device_proxy {
	int pf_vf_num;
	struct rpmsg_device *rpdev[0];
};

#if defined(CONFIG_CAMBR_SOC_C30S) || defined(CONFIG_CAMBR_SOC_C50) || defined(CONFIG_CAMBR_SOC_C50S)
dev_t cn_ipcm_get_rpmsg_major(void);

static inline bool cn_ipcm_enable(void)
{
	return true;
}

int ipcm_get_device_count(void);

struct rpmsg_device_proxy *ipcm_create_channel(char *channel_name);
struct rpmsg_device_proxy *ipcm_create_user_channel(char *channel_name, u32 addr);
int ipcm_destroy_channel(struct rpmsg_device_proxy *proxy);
void ipcm_set_rx_callback(struct rpmsg_device_proxy *proxy, ipcm_rx_cb_t rx_callback);
void ipcm_set_rx_async_callback(struct rpmsg_device_proxy *proxy, ipcm_rx_cb_t rx_callback);
void ipcm_set_rpc_services(struct rpmsg_device_proxy *proxy, struct rpmsg_rpc_service_set *functions);
/* priv is use at ipcm_rx_cb_t */
void ipcm_set_priv_data(struct rpmsg_device_proxy *proxy, void *priv);
void *ipcm_get_priv_data(struct rpmsg_device *rpdev);
int ipcm_get_vf_id(struct rpmsg_device *rpdev);
int ipcm_rpc_log(char *fmt, ...);

static inline struct rpmsg_device *ipcm_get_rpdev_by_vf_id(struct rpmsg_device_proxy *proxy, int vf_id)
{
	if (vf_id >= 0 && vf_id < proxy->pf_vf_num)
		return proxy->rpdev[vf_id];
	return NULL;
}

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

#else /* NO_IPCM */
static inline dev_t cn_ipcm_get_rpmsg_major(void)
{
	return 0;
}

static inline bool cn_ipcm_enable(void)
{
	return false;
}

static inline int ipcm_get_device_count(void)
{
	return 0;
}

static inline struct rpmsg_device_proxy *ipcm_create_channel(char *channel_name)
{
	return NULL;
}
static inline struct rpmsg_device_proxy *ipcm_create_user_channel(char *channel_name, u32 addr)
{
	return NULL;
}
static inline int ipcm_destroy_channel(struct rpmsg_device_proxy *proxy)
{
	return -EOPNOTSUPP;
}
static inline void ipcm_set_rx_callback(struct rpmsg_device_proxy *proxy, ipcm_rx_cb_t rx_callback)
{
}
static inline void ipcm_set_rx_async_callback(struct rpmsg_device_proxy *proxy, ipcm_rx_cb_t rx_callback)
{
}
static inline void ipcm_set_rpc_services(struct rpmsg_device_proxy *proxy, struct rpmsg_rpc_service_set *functions)
{
}
/* priv is use at ipcm_rx_cb_t */
static inline void ipcm_set_priv_data(struct rpmsg_device_proxy *proxy, void *priv)
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
static inline int ipcm_rpc_log(char *fmt, ...)
{
	return -EOPNOTSUPP;
}
static inline struct rpmsg_device *ipcm_get_rpdev_by_vf_id(struct rpmsg_device_proxy *proxy, int vf_id)
{
	return NULL;
}
static inline bool ipcm_channel_ready(struct rpmsg_device *rpdev)
{
	return false;
}
/* send msg non-blocking/async, when response arrive will call the callback */
static inline int ipcm_send_request_with_callback(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size, void *cb_data,
		request_cb_t callback)
{
	return -EOPNOTSUPP;
}
/* send msg blocking/sync, blocked until the response arrived */
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
/* send msg without response */
static inline int ipcm_send_message(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size)
{
	return -EOPNOTSUPP;
}
/* try send msg without response */
static inline int ipcm_trysend_message(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size)
{
	return -EOPNOTSUPP;
}
/* send response to the related package_id */
static inline int ipcm_send_response(struct rpmsg_device *rpdev, unsigned long packet_id,
		void *response, uint32_t response_size)
{
	return -EOPNOTSUPP;
}
/* caller must make sure the sizeof out */
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
#endif /* NO_IPCM */

#endif /* _CAMBR_IPCM_H */
