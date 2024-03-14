// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Cambricon - All Rights Reserved
 *
 * Based on rpmsg_kdrv.c
 * Copyright (C) 2018 Texas Instruments Incorporated - http://www.ti.com/
 * Author: Subhajit Paul <subahjit_paul@ti.com>
 */
#include <linux/atomic.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/idr.h>
#include <linux/delay.h>
#include "../include/virtio/virtio.h"
#include "../include/rpmsg/rpmsg.h"

#include "rpmsg_internal.h"
#ifdef IN_CNDRV_HOST
#include "cndrv_ipcm.h"
#else
#include "../cambr_ipcm.h"
#endif

/*
 * Packet IDs are assigned dynamically (for REQUEST packets)
 * starting from RPMSG_IPC_PACKET_ID_FIRST
 * For MESSAGE packets, framework can use RPMSG_IPC_PACKET_ID_NONE
 */
#define RPMSG_IPC_PACKET_ID_NONE		(0x10)
#define RPMSG_IPC_PACKET_ID_FIRST		(RPMSG_IPC_PACKET_ID_NONE + 1)

static int ipcm_send_rpc_result(struct rpmsg_device *rpdev, unsigned long packet_id, int rpc_ret_val,
		struct ipcm_device_header *dev_hdr, uint32_t response_size);
static struct ipcm_device_header *ipcm_dev_hdr_alloc_for_rpc(struct rpmsg_device *rpdev);

u64 ipcm_string_hash(char *name)
{
	u64 base = 131;
	u64 mod = 212370440130137957ll;
	u64 ans = 0;
	int len = strlen(name);
	int i = 0;

	for (i = 0; i < len; i++)
		ans = (ans * base + (u64)name[i]) % mod;

	return ans;
}

struct ipcm_hdr_ctx_manager {
	spinlock_t lock;
	void *addr;
	u32 block_size;
	u32 nbits;
	u32 bitmap_size;
	unsigned long *bitmap;
};

struct ipcm_priv {
	struct rpmsg_device *rpdev;

	struct idr message_idr;
	spinlock_t message_lock;

	struct ipcm_hdr_ctx_manager *hdr_mgr;
	struct ipcm_hdr_ctx_manager *ctx_mgr;
};

struct ipcm_ctx {
	struct rpmsg_device *rpdev;
	bool wait_for_response;
	request_cb_t callback;
	void *cb_data;
	bool response_recv;
	wait_queue_head_t response_wq;
	bool expire;

	struct ipcm_device_header *dev_hdr;
	void *req;
	void *resp;
	int req_size;
	int resp_size;
	int rpc_ret_val;
	int real_size;
};

struct ipcm_async_data {
	unsigned long packet_id;
	int packet_type;
	struct rpmsg_device *rpdev;
	struct list_head list;
	union {
		struct {
			struct rpmsg_rpc_service_set *service;
		} rpc;
		struct {
			void *priv;
			u32 src;
		} req;
	};
	int msg_len;
	u8 msg[0];
};

static DEFINE_MUTEX(ipcm_async_mutex);
static LIST_HEAD(ipcm_async_list);

/* TODO need to protect from rpdev release */
static void ipcm_async_work_fn(struct work_struct *work)
{
	struct ipcm_async_data *ipcm_async, *tmp;
	struct rpmsg_device *rpdev;
	int ret;

	mutex_lock(&ipcm_async_mutex);
	list_for_each_entry_safe(ipcm_async, tmp, &ipcm_async_list, list) {
		mutex_unlock(&ipcm_async_mutex);
		rpdev = ipcm_async->rpdev;

		if (ipcm_async->packet_type == RPMSG_IPC_PACKET_TYPE_RPC_ASYNC) {
			struct ipcm_device_header *resp_buffer;
			void *response = NULL;
			int response_size = 0;

			resp_buffer = ipcm_dev_hdr_alloc_for_rpc(rpdev);
			if (!resp_buffer) {
				dev_err(&rpdev->dev, "%s: %s() device header allocation failed\n",
					__func__, ipcm_async->rpc.service->func_name);
				return;
			}
			response = (void *)(&resp_buffer[1]);
			atomic_inc(&rpdev->rpc_flag);
			ret = ipcm_async->rpc.service->func(ipcm_async->msg, ipcm_async->msg_len,
						response, &response_size, rpdev->vf_id);
			atomic_dec(&rpdev->rpc_flag);
			ipcm_send_rpc_result(rpdev, ipcm_async->packet_id, ret, resp_buffer, response_size);
		} else {
			ret = rpdev->rx_callback(rpdev, ipcm_async->packet_id, ipcm_async->msg, ipcm_async->msg_len, ipcm_async->req.priv, ipcm_async->req.src);
			if (ret)
				dev_err(&rpdev->dev, "%s: message callback returns %d\n", __func__, ret);
		}

		mutex_lock(&ipcm_async_mutex);
		list_del(&ipcm_async->list);
		kfree(ipcm_async);
	}
	mutex_unlock(&ipcm_async_mutex);
}

static DECLARE_WORK(ipcm_async_work, ipcm_async_work_fn);

static void ipcm_driver_handle_data(struct rpmsg_device *rpdev, void *data, int len, void *private, u32 src)
{
	struct ipcm_device_header *hdr;
	void *message;
	int message_size;
	int ret;
	#if defined(IN_CNDRV_HOST) && defined(__aarch64__)
	struct ipcm_device_header tmp_hdr = {0};

	/* avoid non-aligned 4B access in inbound shm, struct ipcm_device_header are __packed */
	hdr = &tmp_hdr;
	memcpy_fromio(hdr, data, sizeof(struct ipcm_device_header));
	#else
	hdr = data;
	#endif

	message = data + sizeof(*hdr);
	message_size = len - sizeof(*hdr);

	/* cambricon */
	if (hdr->packet_type == RPMSG_IPC_PACKET_TYPE_RPC || hdr->packet_type == RPMSG_IPC_PACKET_TYPE_RPC_ASYNC) {
		struct rpmsg_rpc_service_set *service;
		bool found = false;
		struct ipcm_device_header *resp_buffer;
		void *response = NULL;
		int response_size = 0;

		/* search func from table by name */
		for (service = rpdev->services; service->func_name; service++) {
			if (ipcm_string_hash(service->func_name) == hdr->func_name) {
				found = true;
				break;
			}
		}
		if (!found) {
			resp_buffer = ipcm_dev_hdr_alloc_for_rpc(rpdev);
			if (!resp_buffer) {
				dev_err(&rpdev->dev, "%s: device header allocation failed\n", __func__);
				return;
			}
			response = (void *)(&resp_buffer[1]);

			memcpy(response, "no func found", strlen("no func found"));
			ret = 0xcabc;
			response_size = strlen("no func found");
			dev_err(&rpdev->dev, "%s: no func found, returns %d\n", __func__, ret);
			ipcm_send_rpc_result(rpdev, hdr->ctx, ret, resp_buffer, response_size);
		} else {
			if (unlikely(hdr->packet_type == RPMSG_IPC_PACKET_TYPE_RPC_ASYNC)) {
				struct ipcm_async_data *rpc_async;

				rpc_async = kzalloc(sizeof(struct ipcm_async_data) + message_size, GFP_KERNEL);
				if (!rpc_async) {
					dev_dbg(&rpdev->dev, "ipcm_rpc_call_async: %s() failed with ENOMEM, try sync!\n",
						service->func_name);
					goto rpc_call_sync;
				}

				rpc_async->rpdev = rpdev;
				rpc_async->rpc.service = service;
				rpc_async->packet_id = hdr->ctx;
				rpc_async->packet_type = hdr->packet_type;
				/* vhost will return buffer */
				memcpy_fromio(rpc_async->msg, message, message_size);
				rpc_async->msg_len = message_size;

				mutex_lock(&ipcm_async_mutex);
				list_add_tail(&rpc_async->list, &ipcm_async_list);
				mutex_unlock(&ipcm_async_mutex);

				schedule_work(&ipcm_async_work);
				return;
			}
rpc_call_sync:
			resp_buffer = ipcm_dev_hdr_alloc_for_rpc(rpdev);
			if (!resp_buffer) {
				dev_err(&rpdev->dev, "%s: %s() device header allocation failed\n",
					__func__, service->func_name);
				return;
			}
			response = (void *)(&resp_buffer[1]);

			atomic_inc(&rpdev->rpc_flag);
			ret = service->func(message, message_size, response, &response_size, rpdev->vf_id);
			atomic_dec(&rpdev->rpc_flag);
			ipcm_send_rpc_result(rpdev, hdr->ctx, ret, resp_buffer, response_size);
		}
		return;
	}

	if (rpdev->rx_callback) {
		if (rpdev->rx_cb_async) {
			struct ipcm_async_data *msg_async;

			msg_async = kzalloc(sizeof(struct ipcm_async_data) + message_size, GFP_KERNEL);
			if (!msg_async) {
				dev_dbg(&rpdev->dev, "rx_async_callback: failed with ENOMEM, try sync!\n");
				goto msg_sync;
			}

			msg_async->rpdev = rpdev;
			msg_async->packet_id = hdr->ctx;
			msg_async->packet_type = hdr->packet_type;
			msg_async->req.priv = private;
			msg_async->req.src = src;
			/* vhost will return buffer */
			memcpy_fromio(msg_async->msg, message, message_size);
			msg_async->msg_len = message_size;

			mutex_lock(&ipcm_async_mutex);
			list_add_tail(&msg_async->list, &ipcm_async_list);
			mutex_unlock(&ipcm_async_mutex);

			schedule_work(&ipcm_async_work);
			return;
		}
msg_sync:
		ret = rpdev->rx_callback(rpdev, hdr->ctx, message, message_size, private, src);
		if (ret)
			dev_err(&rpdev->dev, "%s: message callback returns %d\n", __func__, ret);
	} else {
		dev_err(&rpdev->dev, "%s: callback function is NULL\n", __func__);
	}

}

static void ipcm_del_packet_id(struct rpmsg_device *rpdev, int id)
{
	struct ipcm_priv *priv = dev_get_drvdata(&rpdev->dev);

	if (id == RPMSG_IPC_PACKET_ID_NONE)
		return;
	spin_lock(&priv->message_lock);
	idr_remove(&priv->message_idr, id);
	spin_unlock(&priv->message_lock);
}

static uint32_t ipcm_new_packet_id(struct rpmsg_device *rpdev, void *data)
{
	struct ipcm_priv *priv = dev_get_drvdata(&rpdev->dev);
	int id;

	spin_lock(&priv->message_lock);
	id = idr_alloc_cyclic(&priv->message_idr, data, RPMSG_IPC_PACKET_ID_FIRST, 0, GFP_NOWAIT);
	spin_unlock(&priv->message_lock);

	if (id < 0)
		return 0;

	return id;
}

static struct ipcm_hdr_ctx_manager *ipcm_hdr_ctx_mem_init(struct rpmsg_device *rpdev, u32 nbits, u32 block_size)
{
	struct ipcm_hdr_ctx_manager *mgr = NULL;

	if (unlikely(!rpdev))
		return NULL;

	mgr = kzalloc(sizeof(struct ipcm_hdr_ctx_manager), GFP_KERNEL);
	if (!mgr) {
		dev_err(&rpdev->dev, "malloc hdr ctx mem manager failed");
		goto err_mgr;
	}

	spin_lock_init(&mgr->lock);
	mgr->nbits = nbits;
	mgr->bitmap_size = BITS_TO_LONGS(mgr->nbits) * sizeof(long);
	mgr->bitmap = kzalloc(mgr->bitmap_size, GFP_KERNEL);
	if (!mgr->bitmap) {
		dev_err(&rpdev->dev, "malloc hdr ctx mem bitmap failed!");
		goto err_bitmap_alloc;
	}

	bitmap_zero(mgr->bitmap, mgr->nbits);

	mgr->block_size = block_size;

	mgr->addr = vzalloc(nbits * block_size);
	if (!mgr->addr) {
		dev_err(&rpdev->dev, "alloc hdr ctx memory failed");
		goto err_alloc;
	}

	return mgr;

err_alloc:
	kfree(mgr->bitmap);
err_bitmap_alloc:
	kfree(mgr);
err_mgr:
	return NULL;
}

static void ipcm_hdr_ctx_mem_exit(struct rpmsg_device *rpdev, struct ipcm_hdr_ctx_manager *mgr)
{
	if (unlikely(!rpdev))
		return;

	if (IS_ERR_OR_NULL(mgr)) {
		dev_err(&rpdev->dev, "mgr is null");
		return;
	}

	vfree(mgr->addr);
	kfree(mgr->bitmap);
	kfree(mgr);
}

static void ipcm_dev_hdr_delete(struct rpmsg_device *rpdev, struct ipcm_device_header *hdr)
{
	struct ipcm_priv *priv;
	u32 index;

	if (unlikely(!rpdev))
		return;

	priv = dev_get_drvdata(&rpdev->dev);

	if (unlikely(!priv || !priv->hdr_mgr))
		return;

	ipcm_del_packet_id(rpdev, hdr->packet_id);

	index = ((void *)hdr - priv->hdr_mgr->addr) / priv->hdr_mgr->block_size;
	if (index >= priv->hdr_mgr->nbits) {
		dev_err(&rpdev->dev, "hdr is out of range");
		return;
	}

	//memset(0, hdr, priv->hdr_mgr->block_size);

	if (!test_and_clear_bit(index, priv->hdr_mgr->bitmap)) {
		dev_err(&rpdev->dev, "hdr has been free");
	}
}

static struct ipcm_device_header *ipcm_dev_hdr_alloc(struct rpmsg_device *rpdev,
		int size, int pkt_type, int pkt_src, void *msg, int len, struct ipcm_ctx *ctx)
{
	struct ipcm_device_header *dev_hdr;
	struct ipcm_priv *priv;
	u32 index;
	void *dst;

	if (unlikely(!rpdev))
		return NULL;

	priv = dev_get_drvdata(&rpdev->dev);

	if (unlikely(!priv || !priv->hdr_mgr))
		return NULL;

	spin_lock(&priv->hdr_mgr->lock);

	index = find_first_zero_bit(priv->hdr_mgr->bitmap, priv->hdr_mgr->nbits);
	if (unlikely(index >= priv->hdr_mgr->nbits)) {
		dev_err(&rpdev->dev, "malloc hdr mem failed");
		spin_unlock(&priv->hdr_mgr->lock);
		return NULL;
	}
	set_bit(index, priv->hdr_mgr->bitmap);

	dev_hdr = priv->hdr_mgr->addr + index * priv->hdr_mgr->block_size;

	spin_unlock(&priv->hdr_mgr->lock);

	dev_hdr->packet_type = pkt_type;
	dev_hdr->packet_source = pkt_src;
	dev_hdr->packet_size = size;
	dev_hdr->packet_id = RPMSG_IPC_PACKET_ID_NONE;
	/* for uapi cross commu */
	dev_hdr->src = rpdev->src;

	dst = (void *)(&dev_hdr[1]);
	memcpy(dst, msg, len);

	if (pkt_type != RPMSG_IPC_PACKET_TYPE_REQUEST
		&& pkt_type != RPMSG_IPC_PACKET_TYPE_RPC
		&& pkt_type != RPMSG_IPC_PACKET_TYPE_RPC_ASYNC)
		return dev_hdr;

	dev_hdr->packet_id = ipcm_new_packet_id(rpdev, ctx);
	if (!dev_hdr->packet_id) {
		dev_hdr->packet_id = RPMSG_IPC_PACKET_ID_NONE;
		ipcm_dev_hdr_delete(rpdev, dev_hdr);
		return NULL;
	}

	ctx->dev_hdr = dev_hdr;

	return dev_hdr;
}

static struct ipcm_device_header *ipcm_dev_hdr_alloc_for_rpc(struct rpmsg_device *rpdev)
{
	struct ipcm_device_header *dev_hdr;
	struct ipcm_priv *priv;
	u32 index;

	if (unlikely(!rpdev))
		return NULL;

	priv = dev_get_drvdata(&rpdev->dev);

	if (unlikely(!priv || !priv->hdr_mgr))
		return NULL;

	spin_lock(&priv->hdr_mgr->lock);

	index = find_first_zero_bit(priv->hdr_mgr->bitmap, priv->hdr_mgr->nbits);
	if (unlikely(index >= priv->hdr_mgr->nbits)) {
		dev_err(&rpdev->dev, "malloc hdr mem failed");
		spin_unlock(&priv->hdr_mgr->lock);
		return NULL;
	}
	set_bit(index, priv->hdr_mgr->bitmap);

	dev_hdr = priv->hdr_mgr->addr + index * priv->hdr_mgr->block_size;

	spin_unlock(&priv->hdr_mgr->lock);

	dev_hdr->packet_type = RPMSG_IPC_PACKET_TYPE_RPC_RET;
	dev_hdr->packet_source = RPMSG_IPC_PACKET_SOURCE_SERVER;
	/* for uapi cross commu */
	dev_hdr->src = rpdev->src;

	return dev_hdr;
}

static void ipcm_ctx_free(struct ipcm_ctx *ctx)
{
	struct rpmsg_device *rpdev = ctx->rpdev;
	struct ipcm_priv *priv = dev_get_drvdata(&rpdev->dev);
	u32 index;

	if (unlikely(!priv || !priv->ctx_mgr))
		return;

	index = ((void *)ctx - priv->ctx_mgr->addr) / priv->ctx_mgr->block_size;
	if (index >= priv->ctx_mgr->nbits) {
		dev_err(&rpdev->dev, "ctx is out of range");
		return;
	}

	//memset(0, ctx, priv->ctx_mgr->block_size);

	if (!test_and_clear_bit(index, priv->ctx_mgr->bitmap)) {
		dev_err(&rpdev->dev, "ctx has been free");
	}
}

static struct ipcm_ctx *ipcm_ctx_alloc(struct rpmsg_device *rpdev, bool blocking,
		request_cb_t callback, void *cb_data, void *req, int req_size, void *resp, int resp_size)
{
	struct ipcm_ctx *ctx;
	struct ipcm_priv *priv;
	u32 index;

	if (unlikely(!rpdev))
		return NULL;

	priv = dev_get_drvdata(&rpdev->dev);

	if (unlikely(!priv || !priv->ctx_mgr))
		return NULL;

	spin_lock(&priv->ctx_mgr->lock);

	index = find_first_zero_bit(priv->ctx_mgr->bitmap, priv->ctx_mgr->nbits);
	if (unlikely(index >= priv->ctx_mgr->nbits)) {
		dev_err(&rpdev->dev, "malloc ctx mem failed");
		spin_unlock(&priv->ctx_mgr->lock);
		return NULL;
	}
	set_bit(index, priv->ctx_mgr->bitmap);

	ctx = priv->ctx_mgr->addr + index * priv->ctx_mgr->block_size;

	spin_unlock(&priv->ctx_mgr->lock);

	ctx->rpdev = rpdev;
	if (blocking) {
		ctx->wait_for_response = true;
		ctx->response_recv = false;
		init_waitqueue_head(&ctx->response_wq);
	} else {
		ctx->wait_for_response = false;
		ctx->callback = callback;
	}
	ctx->expire = false;

	ctx->cb_data = cb_data;
	ctx->req = req;
	ctx->req_size = req_size;
	ctx->resp = resp;
	ctx->resp_size = resp_size;

	return ctx;
}

static int ipcm_send_packet(struct rpmsg_device *rpdev, void *data, int len)
{
	if (unlikely(!rpdev || !rpdev->ept))
		return -EINVAL;

	return cn_rpmsg_send(rpdev->ept, data, len);
}

static int ipcm_trysend_packet(struct rpmsg_device *rpdev, void *data, int len)
{
	if (unlikely(!rpdev || !rpdev->ept))
		return -EINVAL;

	return cn_rpmsg_trysend(rpdev->ept, data, len);
}

static int ipcm_send_packet_to_port(struct rpmsg_device *rpdev, void *data, int len, int port)
{
	if (unlikely(!rpdev || !rpdev->ept))
		return -EINVAL;

	return cn_rpmsg_sendto(rpdev->ept, data, len, port);
}

/*
 * ipcm_send_request_with_callback
 *
 * Send a message where
 * a) the caller does not block
 * b) the caller expects multile responses
 *
 * The callback function must return
 * a) RRMSG_KDRV_CALLBACK_DONE when no more responses are expected
 * b) RPMSG_KDRV_CALLBACK_MORE when more responses are awaited
 *
 * The caller is expected to destroy message when it does not
 * expect any more responses
 */
int ipcm_send_request_with_callback(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size,
		void *cb_data, request_cb_t callback)
{
	struct ipcm_device_header *dev_hdr;
	int total_size = message_size + sizeof(*dev_hdr);
	struct ipcm_ctx *ctx = NULL;
	int ret;

	if (unlikely(!rpdev))
		return -EINVAL;

	ctx = ipcm_ctx_alloc(rpdev, false, callback, cb_data, message, message_size, NULL, 0);
	if (!ctx) {
		dev_err(&rpdev->dev, "%s: ctx allocation failed\n", __func__);
		return -ENOMEM;
	}

	dev_hdr = ipcm_dev_hdr_alloc(rpdev, total_size,
			RPMSG_IPC_PACKET_TYPE_REQUEST,
			RPMSG_IPC_PACKET_SOURCE_CLIENT,
			message, message_size,
			ctx);
	if (!dev_hdr) {
		dev_err(&rpdev->dev, "%s: device header allocation failed\n", __func__);
		ret = -ENOMEM;
		goto dev_hdr_fail;
	}

	ret = ipcm_send_packet(rpdev, dev_hdr, total_size);
	if (ret) {
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);
		goto nosend;
	}

	return 0;

nosend:
	ipcm_dev_hdr_delete(rpdev, dev_hdr);
dev_hdr_fail:
	ipcm_ctx_free(ctx);
	return ret;
}
EXPORT_SYMBOL(ipcm_send_request_with_callback);

/*
 * ipcm_send_request_with_response
 *
 * Send a message where the caller will block for a response
 *
 * The caller is expected to destroy message and response
 * when this function returns
 */
int ipcm_send_request_with_response(struct rpmsg_device *rpdev, bool interruptible,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size)
{
	struct ipcm_device_header *dev_hdr;
	int total_size = message_size + sizeof(*dev_hdr);
	struct ipcm_ctx *ctx = NULL;
	int ret;

	if (unlikely(!rpdev))
		return -EINVAL;

	ctx = ipcm_ctx_alloc(rpdev, true, NULL, NULL, message, message_size, response, response_size);
	if (!ctx) {
		dev_err(&rpdev->dev, "%s: ctx allocation failed\n", __func__);
		return -ENOMEM;
	}

	dev_hdr = ipcm_dev_hdr_alloc(rpdev, total_size,
			RPMSG_IPC_PACKET_TYPE_REQUEST,
			RPMSG_IPC_PACKET_SOURCE_CLIENT,
			message, message_size,
			ctx);
	if (!dev_hdr) {
		dev_err(&rpdev->dev, "%s: device header allocation failed\n", __func__);
		ret = -ENOMEM;
		goto dev_hdr_fail;
	}

	ret = ipcm_send_packet(rpdev, dev_hdr, total_size);
	if (ret) {
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);
		goto nosend;
	}

	if (!interruptible) {
		/* never timeout, warn every 10s */
		do {
			ret = wait_event_timeout(ctx->response_wq, ctx->response_recv || rpdev->reset_flag, 10 * HZ);
			if (!ret) {
				dev_warn(&rpdev->dev, "%s(), wait too long time!\n", __func__);
			} else if (rpdev->reset_flag) {
				dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
				/* compat commu */
				ret = -2;
				break;
			} else {
				ret = 0;
				break;
			}
		} while (!ret);
	} else {
		/* never timeout, warn every 10s untill break by signal */
		do {
			ret = wait_event_interruptible_timeout(ctx->response_wq, ctx->response_recv || rpdev->reset_flag,
					10 * HZ);
			if (!ret) {
				dev_warn(&rpdev->dev, "%s(), wait too long time!\n", __func__);
			} else if (unlikely(rpdev->reset_flag)) {
				dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
				/* compat commu */
				ret = -2;
			} else if (unlikely(ret == -ERESTARTSYS)) {
				/* still wait remote's reply in max 10s */
				dev_dbg_ratelimited(&rpdev->dev, "fatal signal received when wait_event. keep wait for a while\n");
				ret = wait_event_timeout(ctx->response_wq, ctx->response_recv || rpdev->reset_flag, 10 * HZ);
				if (unlikely(rpdev->reset_flag)) {
					dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
					/* compat commu */
					ret = -2;
				} else if (unlikely(!ret)) {
					dev_info_ratelimited(&rpdev->dev, "fatal signal received, aborted\n");
					ret = -ERESTARTSYS;
				}
			} else {
				ret = 0;
				break;
			}
		} while (!ret);
	}
	if (ret < 0) {
		dev_err_ratelimited(&rpdev->dev, "wait respond failed: %d\n", ret);
		*real_size = 0;
		/* delete hdr but reserved the idr to avoid new packet reuse, also reserved ctx */
		dev_hdr->packet_id = RPMSG_IPC_PACKET_ID_NONE;
		ipcm_dev_hdr_delete(rpdev, dev_hdr);
		ctx->expire = true;
		return ret;
	}

	*real_size = ctx->real_size;

nosend:
	ipcm_dev_hdr_delete(rpdev, dev_hdr);
dev_hdr_fail:
	ipcm_ctx_free(ctx);
	return ret;
}
EXPORT_SYMBOL(ipcm_send_request_with_response);

int ipcm_send_request_with_response_to_port(struct rpmsg_device *rpdev, bool interruptible,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size, int port)
{
	struct ipcm_device_header *dev_hdr;
	int total_size = message_size + sizeof(*dev_hdr);
	struct ipcm_ctx *ctx = NULL;
	int ret;

	if (unlikely(!rpdev))
		return -EINVAL;

	ctx = ipcm_ctx_alloc(rpdev, true, NULL, NULL, message, message_size, response, response_size);
	if (!ctx) {
		dev_err(&rpdev->dev, "%s: ctx allocation failed\n", __func__);
		return -ENOMEM;
	}

	dev_hdr = ipcm_dev_hdr_alloc(rpdev, total_size,
			RPMSG_IPC_PACKET_TYPE_REQUEST,
			RPMSG_IPC_PACKET_SOURCE_CLIENT,
			message, message_size,
			ctx);
	if (!dev_hdr) {
		dev_err(&rpdev->dev, "%s: device header allocation failed\n", __func__);
		ret = -ENOMEM;
		goto dev_hdr_fail;
	}

	ret = ipcm_send_packet_to_port(rpdev, dev_hdr, total_size, port);
	if (ret) {
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);
		goto nosend;
	}

	if (!interruptible) {
		/* never timeout, warn every 10s */
		do {
			ret = wait_event_timeout(ctx->response_wq, ctx->response_recv || rpdev->reset_flag, 10 * HZ);
			if (!ret) {
				dev_warn(&rpdev->dev, "%s(), spend too long time!\n", __func__);
			} else if (rpdev->reset_flag) {
				dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
				/* compat commu */
				ret = -2;
				break;
			} else {
				ret = 0;
				break;
			}
		} while (!ret);
	} else {
		/* never timeout, warn every 10s untill break by signal */
		do {
			ret = wait_event_interruptible_timeout(ctx->response_wq, ctx->response_recv || rpdev->reset_flag,
					10 * HZ);
			if (!ret) {
				dev_warn(&rpdev->dev, "%s(), wait too long time!\n", __func__);
			} else if (unlikely(rpdev->reset_flag)) {
				dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
				/* compat commu */
				ret = -2;
			} else if (unlikely(ret == -ERESTARTSYS)) {
				/* still wait remote's reply in max 10s */
				dev_dbg_ratelimited(&rpdev->dev, "fatal signal received when wait_event. keep wait for a while\n");
				ret = wait_event_timeout(ctx->response_wq, ctx->response_recv || rpdev->reset_flag, 10 * HZ);
				if (unlikely(rpdev->reset_flag)) {
					dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
					/* compat commu */
					ret = -2;
				} else if (unlikely(!ret)) {
					dev_info_ratelimited(&rpdev->dev, "fatal signal received, aborted\n");
					ret = -ERESTARTSYS;
				}
			} else {
				ret = 0;
				break;
			}
		} while (!ret);
	}
	if (ret < 0) {
		dev_err_ratelimited(&rpdev->dev, "wait respond failed: %d\n", ret);
		*real_size = 0;
		/* delete hdr but reserved the idr to avoid new packet reuse, also reserved ctx */
		dev_hdr->packet_id = RPMSG_IPC_PACKET_ID_NONE;
		ipcm_dev_hdr_delete(rpdev, dev_hdr);
		ctx->expire = true;
		return ret;
	}

	*real_size = ctx->real_size;

nosend:
	ipcm_dev_hdr_delete(rpdev, dev_hdr);
dev_hdr_fail:
	ipcm_ctx_free(ctx);
	return ret;
}
EXPORT_SYMBOL(ipcm_send_request_with_response_to_port);


int ipcm_record;
int ipcm_record_index;

#ifdef IN_CNDRV_HOST
extern void *cambr_rproc_get_virtio_device(void *core);
struct cn_core_set *cambr_dev_to_core(struct device *dev);
extern void cn_core_dump_device_pc(struct cn_core_set *core);
extern int virtio_rpmsg_query_endpoint(struct rpmsg_device *rpdev, int addr);
extern void cn_core_dump_device_info(struct cn_core_set *core);

extern int ipcm_dump_dfx(struct virtio_device *vdev);
#endif

/*
 * __rpmsg_rpc_call
 *
 * Send a message where the caller will block for rpc return
 *
 * The caller is expected to destroy message and response
 * when this function returns
 *
 * @time_out: the unit of time_out is ms
 */
static int __ipcm_rpc_call(struct rpmsg_device *rpdev, char *fn_name, bool interruptible,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size,
		bool async, int time_out)
{
	struct ipcm_device_header *dev_hdr;
	int total_size = message_size + sizeof(*dev_hdr);
	struct ipcm_ctx *ctx = NULL;
	int ret;

	if (!rpdev || !fn_name)
		return -EINVAL;

	#ifdef IN_CNDRV_HOST
	if (unlikely(ipcm_record)) {
		perf_host_kva[ipcm_record_index].rpc_in_ns = get_host_timestamp_by_clockid(CLOCK_MONOTONIC_RAW);
	}
	#endif

	ctx = ipcm_ctx_alloc(rpdev, true, NULL, NULL, message, message_size, response, response_size);
	if (!ctx) {
		dev_err(&rpdev->dev, "%s: ctx allocation failed\n", __func__);
		return -ENOMEM;
	}

	dev_hdr = ipcm_dev_hdr_alloc(rpdev, total_size,
			async ? RPMSG_IPC_PACKET_TYPE_RPC_ASYNC : RPMSG_IPC_PACKET_TYPE_RPC,
			RPMSG_IPC_PACKET_SOURCE_CLIENT,
			message, message_size,
			ctx);
	if (!dev_hdr) {
		dev_err(&rpdev->dev, "%s: device header allocation failed\n", __func__);
		ret = -ENOMEM;
		goto dev_hdr_fail;
	}

	dev_hdr->func_name = ipcm_string_hash(fn_name);

	ret = ipcm_send_packet(rpdev, dev_hdr, total_size);
	if (ret) {
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);
		goto nosend;
	}

	atomic_inc(&rpdev->rpc_flag);

	if (!interruptible) {
		if (time_out == 0) {
			/* never timeout, warn every 10s */
			do {
				ret = wait_event_timeout(ctx->response_wq, ctx->response_recv || rpdev->reset_flag,
						10 * HZ);
				if (!ret) {
					dev_warn(&rpdev->dev, "%s(), rpc:%s spend too long time!\n", __func__, fn_name);
				} else if (rpdev->reset_flag) {
					dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
					/* compat commu */
					ret = -2;
					break;
				}
			} while (!ret);
		} else {
			ret = wait_event_timeout(ctx->response_wq, ctx->response_recv || rpdev->reset_flag,
						msecs_to_jiffies(time_out));
			if (!ret) {
				dev_warn(&rpdev->dev, "%s(), rpc:%s timeouted!\n", __func__, fn_name);
				#ifdef IN_CNDRV_HOST
				if (!strcmp(fn_name, "rpc_arm_action")) {//heartbeat
					struct cn_core_set *core = cambr_dev_to_core(&rpdev->dev);
					struct virtio_device *vdev = cambr_rproc_get_virtio_device(core);

					ipcm_dump_dfx(vdev);
				}
				#endif
				ret = -ETIMEDOUT;
			} else if (rpdev->reset_flag) {
				dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
				/* compat commu */
				ret = -2;
			}
		}
	} else {
		/* never timeout, warn every 10s untill break by signal */
		do {
			ret = wait_event_interruptible_timeout(ctx->response_wq, ctx->response_recv || rpdev->reset_flag,
					10 * HZ);
			if (!ret) {
				dev_warn(&rpdev->dev, "%s(), rpc:%s spend too long time!\n", __func__, fn_name);
			} else if (unlikely(rpdev->reset_flag)) {
				dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
				/* compat commu */
				ret = -2;
			} else if (unlikely(ret == -ERESTARTSYS)) {
				/* still wait remote's reply in max 10s */
				dev_dbg_ratelimited(&rpdev->dev, "fatal signal received when wait_event. keep wait for a while\n");
				ret = wait_event_timeout(ctx->response_wq, ctx->response_recv || rpdev->reset_flag, 10 * HZ);
				if (unlikely(rpdev->reset_flag)) {
					dev_dbg(&rpdev->dev, "%s(), arm may hung!\n", __func__);
					/* compat commu */
					ret = -2;
				} else if (unlikely(!ret)) {
					dev_info_ratelimited(&rpdev->dev, "%s: fatal signal received, aborted\n", fn_name);
					ret = -ERESTARTSYS;
				}
			}
		} while (!ret);
	}
	atomic_dec(&rpdev->rpc_flag);
	if (ret < 0) {
		dev_err_ratelimited(&rpdev->dev, "%s: wait respond failed: %d\n", fn_name, ret);
		*real_size = 0;
		/* delete hdr but reserved the idr to avoid new packet reuse, also reserved ctx */
		dev_hdr->packet_id = RPMSG_IPC_PACKET_ID_NONE;
		ipcm_dev_hdr_delete(rpdev, dev_hdr);
		ctx->expire = true;
		return ret;
	}
	ret = ctx->rpc_ret_val;
	*real_size = ctx->real_size;

	#ifdef IN_CNDRV_HOST
	if (unlikely(ipcm_record)) {
		perf_host_kva[ipcm_record_index++].rpc_out_ns = get_host_timestamp_by_clockid(CLOCK_MONOTONIC_RAW);
		if (ipcm_record_index == ipcm_record)
			ipcm_record = 0;
	}
	#endif

nosend:
	ipcm_dev_hdr_delete(rpdev, dev_hdr);
dev_hdr_fail:
	ipcm_ctx_free(ctx);
	return ret;
}

int ipcm_rpc_call(struct rpmsg_device *rpdev, char *fn_name,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size)
{
	return __ipcm_rpc_call(rpdev, fn_name, true, message, message_size,
		response, real_size, response_size, false, 0);
}
EXPORT_SYMBOL(ipcm_rpc_call);

int ipcm_rpc_call_no_killable(struct rpmsg_device *rpdev, char *fn_name,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size)
{
	return __ipcm_rpc_call(rpdev, fn_name, false, message, message_size,
		response, real_size, response_size, false, 0);
}
EXPORT_SYMBOL(ipcm_rpc_call_no_killable);

int ipcm_rpc_call_timeout(struct rpmsg_device *rpdev, char *fn_name,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size, int time_out_ms)
{
	return __ipcm_rpc_call(rpdev, fn_name, false, message, message_size,
		response, real_size, response_size, false, time_out_ms);
}
EXPORT_SYMBOL(ipcm_rpc_call_timeout);

int ipcm_rpc_call_async(struct rpmsg_device *rpdev, char *fn_name,
		void *message, uint32_t message_size,
		void *response, uint32_t *real_size, uint32_t response_size)
{
	return __ipcm_rpc_call(rpdev, fn_name, true, message, message_size,
		response, real_size, response_size, true, 0);
}
EXPORT_SYMBOL(ipcm_rpc_call_async);

/*
 * ipcm_send_message
 *
 * Send a message and dont expect a response
 *
 * The caller is expected to destroy message when
 * this function returns
 */
int ipcm_send_message(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size)
{
	struct ipcm_device_header *dev_hdr;
	int total_size = message_size + sizeof(*dev_hdr);
	int ret;

	if (unlikely(!rpdev))
		return -EINVAL;
	/* We don't need a ctx for direct messages */

	dev_hdr = ipcm_dev_hdr_alloc(rpdev, total_size,
			RPMSG_IPC_PACKET_TYPE_MESSAGE,
			RPMSG_IPC_PACKET_SOURCE_CLIENT,
			message, message_size,
			NULL);
	if (!dev_hdr) {
		dev_err(&rpdev->dev, "%s: device header allocation failed\n", __func__);
		return -ENOMEM;
	}

	ret = ipcm_send_packet(rpdev, dev_hdr, total_size);
	if (ret) {
		dev_err(&rpdev->dev, "%s: rpmsg_send failed: %d\n", __func__, ret);
		goto out;
	}

out:
	ipcm_dev_hdr_delete(rpdev, dev_hdr);
	return ret;
}
EXPORT_SYMBOL(ipcm_send_message);

/*
 * ipcm_trysend_message
 *
 * Try send a message and dont expect a response, it may fail while no tx buffer
 *
 * The caller is expected to destroy message when
 * this function returns
 */
int ipcm_trysend_message(struct rpmsg_device *rpdev,
		void *message, uint32_t message_size)
{
	struct ipcm_device_header *dev_hdr;
	int total_size = message_size + sizeof(*dev_hdr);
	int ret;

	if (unlikely(!rpdev))
		return -EINVAL;
	/* We don't need a ctx for direct messages */

	dev_hdr = ipcm_dev_hdr_alloc(rpdev, total_size,
			RPMSG_IPC_PACKET_TYPE_MESSAGE,
			RPMSG_IPC_PACKET_SOURCE_CLIENT,
			message, message_size,
			NULL);
	if (!dev_hdr) {
		dev_err(&rpdev->dev, "%s: device header allocation failed\n", __func__);
		return -ENOMEM;
	}

	ret = ipcm_trysend_packet(rpdev, dev_hdr, total_size);
	if (ret) {
		dev_err(&rpdev->dev, "%s: rpmsg_trysend failed: %d\n", __func__, ret);
		goto out;
	}

out:
	ipcm_dev_hdr_delete(rpdev, dev_hdr);
	return ret;
}
EXPORT_SYMBOL(ipcm_trysend_message);

/*
 * ipcm_send_response
 *
 * Send a response message
 *
 * The caller is expected to destroy message when
 * this function returns
 */
int ipcm_send_response(struct rpmsg_device *rpdev, unsigned long packet_id,
		void *response, uint32_t response_size)
{
	struct ipcm_device_header *dev_hdr;
	int total_size = response_size + sizeof(*dev_hdr);
	int ret;

	if (unlikely(!rpdev))
		return -EINVAL;
	/* We don't need a ctx for direct messages */

	dev_hdr = ipcm_dev_hdr_alloc(rpdev, total_size,
			RPMSG_IPC_PACKET_TYPE_RESPONSE,
			RPMSG_IPC_PACKET_SOURCE_SERVER,
			response, response_size,
			NULL);
	if (!dev_hdr) {
		dev_err(&rpdev->dev, "%s: device header allocation failed\n", __func__);
		return -ENOMEM;
	}

	dev_hdr->ctx = packet_id;

	ret = ipcm_send_packet(rpdev, dev_hdr, total_size);
	if (ret) {
		dev_err(&rpdev->dev, "%s: rpmsg_send failed: %d\n", __func__, ret);
		goto out;
	}

out:
	dev_hdr->packet_id = RPMSG_IPC_PACKET_ID_NONE;
	ipcm_dev_hdr_delete(rpdev, dev_hdr);
	return ret;
}
EXPORT_SYMBOL(ipcm_send_response);

int ipcm_send_response_to_port(struct rpmsg_device *rpdev, unsigned long packet_id,
		void *response, uint32_t response_size, int port)
{
	struct ipcm_device_header *dev_hdr;
	int total_size = response_size + sizeof(*dev_hdr);
	int ret;

	if (unlikely(!rpdev))
		return -EINVAL;
	/* We don't need a ctx for direct messages */

	dev_hdr = ipcm_dev_hdr_alloc(rpdev, total_size,
			RPMSG_IPC_PACKET_TYPE_RESPONSE,
			RPMSG_IPC_PACKET_SOURCE_SERVER,
			response, response_size,
			NULL);
	if (!dev_hdr) {
		dev_err(&rpdev->dev, "%s: device header allocation failed\n", __func__);
		return -ENOMEM;
	}

	dev_hdr->ctx = packet_id;

	ret = ipcm_send_packet_to_port(rpdev, dev_hdr, total_size, port);
	if (ret) {
		dev_err(&rpdev->dev, "%s: rpmsg_send failed: %d\n", __func__, ret);
		goto out;
	}

out:
	dev_hdr->packet_id = RPMSG_IPC_PACKET_ID_NONE;
	ipcm_dev_hdr_delete(rpdev, dev_hdr);
	return ret;
}
EXPORT_SYMBOL(ipcm_send_response_to_port);

static int ipcm_send_rpc_result(struct rpmsg_device *rpdev, unsigned long packet_id, int rpc_ret_val,
		struct ipcm_device_header *dev_hdr, uint32_t response_size)
{
	int total_size = response_size + sizeof(*dev_hdr);
	int ret;

	if (unlikely(!rpdev))
		return -EINVAL;

	dev_hdr->ctx = packet_id;
	dev_hdr->rpc_ret_val = rpc_ret_val;
	dev_hdr->packet_size = total_size;

	ret = ipcm_send_packet(rpdev, dev_hdr, total_size);
	if (ret) {
		dev_err(&rpdev->dev, "%s: rpmsg_send failed: %d\n", __func__, ret);
		goto out;
	}

out:
	dev_hdr->packet_id = RPMSG_IPC_PACKET_ID_NONE;
	ipcm_dev_hdr_delete(rpdev, dev_hdr);
	return ret;
}

/* the rpmsg default endpoint's callback function of this channel */
static int ipcm_cb(struct rpmsg_device *rpdev, void *data, int len,
						void *private, u32 src)
{
	struct ipcm_priv *priv = dev_get_drvdata(&rpdev->dev);
	struct ipcm_device_header *hdr;
	void *msg;
	int msg_len;
	struct ipcm_ctx *ctx;
	int ret;
	int retry = 0;
	int i;

	#if defined(IN_CNDRV_HOST) && defined(__aarch64__)
	struct ipcm_device_header tmp_hdr = {0};

again:
	/* avoid non-aligned 4B access in inbound shm, struct ipcm_device_header are __packed */
	hdr = &tmp_hdr;
	memcpy_fromio(hdr, data, sizeof(struct ipcm_device_header));
	#else
again:
	hdr = data;
	#endif

	dev_dbg(&rpdev->dev, "len:%d, src(%d), packet_type(%d), packet_id(%d)|ctx(0x%llx)\n",
					len, src, hdr->packet_type, hdr->packet_id, hdr->ctx);

	/* for user to kernel cross commu */
	if (rpdev->dst != src) {
		/*
		 * last message received from the remote side,
		 * update channel destination address
		 */
		rpdev->dst = src;
	}

	if (hdr->packet_type != RPMSG_IPC_PACKET_TYPE_RESPONSE && hdr->packet_type != RPMSG_IPC_PACKET_TYPE_RPC_RET) {
		ipcm_driver_handle_data(rpdev, data, len, private, src);
		return 0;
	}

	spin_lock(&priv->message_lock);
	ctx = idr_find(&priv->message_idr, hdr->packet_id);
	spin_unlock(&priv->message_lock);

	if (!ctx) {
		dev_err(&rpdev->dev, "%s: [%d] response received with no pending request\n", __func__, retry);
		dev_err(&rpdev->dev, "len:%d, src(%d), packet_type(%d), packet_id(%d), expect packet_id:\n",
					len, src, hdr->packet_type, hdr->packet_id);
		spin_lock(&priv->message_lock);
		idr_for_each_entry(&priv->message_idr, ctx, i) {
			dev_err(&rpdev->dev, "(%d)", i);
		}
		spin_unlock(&priv->message_lock);
		dev_err(&rpdev->dev, "\n");
		if (retry++ < 5) {
			usleep_range(100, 200);
			goto again;
		}
		return 0;
	}

	if (ctx->expire) {
		dev_err(&rpdev->dev, "%s: response received but expire\n", __func__);
		ipcm_del_packet_id(rpdev, hdr->packet_id);
		ipcm_ctx_free(ctx);
		return 0;
	}

	msg = data + sizeof(*hdr);
	msg_len = len - sizeof(*hdr);

	/* process callback if expected */
	if (ctx->callback) {
		ret = ctx->callback(ctx->cb_data, ctx->req, ctx->req_size, msg, msg_len);
		/* No need to keep the ctx alive */
		ipcm_dev_hdr_delete(rpdev, ctx->dev_hdr);
		ipcm_ctx_free(ctx);

		return ret;
	}

	if (hdr->packet_type == RPMSG_IPC_PACKET_TYPE_RPC_RET) {
		ctx->rpc_ret_val = hdr->rpc_ret_val;
	}

	ctx->real_size = msg_len;
	WARN(ctx->resp_size < msg_len, "%s %s: resp_size(%d) < real_size(%d)",
		dev_driver_string(&rpdev->dev), dev_name(&rpdev->dev), ctx->resp_size, msg_len);

	/* copy the response and wake up caller, caller will destroy ctx & dev_hdr */
	memcpy_fromio(ctx->resp, msg, min(msg_len, ctx->resp_size));

	ctx->response_recv = true;
	wake_up_all(&ctx->response_wq);

	return 0;
}

#ifdef IN_CNDRV_HOST
void ipcm_set_rx_callback(struct rpmsg_device *rpdev, ipcm_rx_cb_t rx_callback)
{
	if (likely(rpdev)) {
		rpdev->rx_callback = rx_callback;
		rpdev->rx_cb_async = false;
	}
}

void ipcm_set_rx_async_callback(struct rpmsg_device *rpdev, ipcm_rx_cb_t rx_callback)
{
	if (likely(rpdev)) {
		rpdev->rx_callback = rx_callback;
		rpdev->rx_cb_async = true;
	}
}

void ipcm_set_rpc_services(struct rpmsg_device *rpdev, struct rpmsg_rpc_service_set *services)
{
	if (likely(rpdev))
		rpdev->services = services;
}

void ipcm_set_priv_data(struct rpmsg_device *rpdev, void *priv)
{
	if (likely(rpdev && rpdev->ept))
		rpdev->ept->priv = priv;
}

static int ipcm_break_wait(struct device *dev, void *data)
{
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);
	struct rpmsg_driver *rpdrv = to_rpmsg_driver(rpdev->dev.driver);
	struct ipcm_priv *priv = NULL;
	struct ipcm_ctx *ctx;
	unsigned long flags;
	int i;

	/* ipcm_probe may failed, see more in driver_attach()-> driver_probe_device()-->really_probe() */
	if (unlikely(!rpdrv)) {
		dev_dbg(dev, "%s, rpdev:%s has no rpdrv\n", __func__, rpdev->id.name);
		return 0;
	}

	dev_dbg(dev, "%s, rpdev:%s rpdrv:%s\n", __func__, rpdev->id.name, rpdrv->drv.name);

	rpdev->reset_flag = true;

	if (strncmp(rpdrv->drv.name, "rpmsg-ipcm", strlen("rpmsg-ipcm"))) {
		return 0;
	}
	priv = dev_get_drvdata(dev);
	if (unlikely(!priv))
		return 0;

	spin_lock_irqsave(&priv->message_lock, flags);
	idr_for_each_entry(&priv->message_idr, ctx, i) {
		if (ctx->wait_for_response)
			wake_up_all(&ctx->response_wq);
	}
	spin_unlock_irqrestore(&priv->message_lock, flags);

	return 0;
}

int ipcm_reset_callback(void *core)
{
	struct virtio_device *vdev = cambr_rproc_get_virtio_device(core);
	int ret;

	if (unlikely(!vdev))
		return -EINVAL;

	dev_info(&vdev->dev, "%s begin\n", __func__);

	cn_core_dump_device_pc(core);
	ipcm_dump_dfx(vdev);
	ret = device_for_each_child(&vdev->dev, NULL, ipcm_break_wait);
	if (ret)
		dev_warn(&vdev->dev, "can't wake up rpmsg device: %d\n", ret);
	dev_info(&vdev->dev, "%s end\n", __func__);
	return ret;
}

/* File Operations System call definitions */
#define OPEN_SYSCALL_ID  0x1UL
#define CLOSE_SYSCALL_ID 0x2UL
#define WRITE_SYSCALL_ID 0x3UL
#define READ_SYSCALL_ID  0x4UL
#define ACK_STATUS_ID    0x5UL
#define TERM_SYSCALL_ID  0x6UL

struct rpmsg_rpc_syscall_header {
	int32_t int_field1;
	int32_t int_field2;
	uint32_t data_len;
};

struct rpmsg_rpc_syscall {
	uint32_t id;
	struct rpmsg_rpc_syscall_header args;
};


int ipcm_remote_open(void *core, struct rpmsg_device **rpdev, const char *filename, int flags, int mode)
{
	struct rpmsg_rpc_syscall *syscall = NULL;
	struct rpmsg_rpc_syscall resp;
	int resp_len = 0;
	int filename_len;
	unsigned int payload_size;
	unsigned char *tmpbuf = NULL;
	int ret = -1;

	if (!core || !rpdev || !filename) {
		return -EINVAL;
	}

	filename_len = strlen(filename) + 1;
	payload_size = sizeof(*syscall) + filename_len;

	if (payload_size > MAX_BUF_LEN) {
		return -EINVAL;
	}

	tmpbuf = kzalloc(MAX_BUF_LEN, GFP_KERNEL);
	if (!tmpbuf) {
		pr_err("%s %d no memory.", __func__, __LINE__);
		return -ENOMEM;
	}

	*rpdev = ipcm_open_channel(core, "ipcm_file");
	if (IS_ERR_OR_NULL(*rpdev)) {
		kfree(tmpbuf);
		return -ENODEV;
	}

	/* Construct rpc payload */
	syscall = (struct rpmsg_rpc_syscall *)tmpbuf;
	syscall->id = OPEN_SYSCALL_ID;
	syscall->args.int_field1 = flags;
	syscall->args.int_field2 = mode;
	syscall->args.data_len = filename_len;
	memcpy(tmpbuf + sizeof(*syscall), filename, filename_len);

	resp.id = 0;
	ret = ipcm_rpc_call(*rpdev, "rpc_syscall_open", syscall, payload_size,
			     (void *)&resp, &resp_len, sizeof(resp));
	if (resp.id == OPEN_SYSCALL_ID)
		ret = resp.args.int_field1;

	kfree(tmpbuf);

	return ret;
}

int ipcm_remote_close(struct rpmsg_device *rpdev, int fd)
{
	struct rpmsg_rpc_syscall syscall;
	struct rpmsg_rpc_syscall resp;
	int resp_len = 0;
	unsigned int payload_size = sizeof(syscall);
	int ret;

	if (!rpdev)
		return -EINVAL;

	/* Construct rpc payload */
	syscall.id = CLOSE_SYSCALL_ID;
	syscall.args.int_field1 = fd;
	syscall.args.int_field2 = 0;	/*not used */
	syscall.args.data_len = 0;	/*not used */

	resp.id = 0;
	ret = ipcm_rpc_call(rpdev, "rpc_syscall_close", (void *)&syscall, payload_size,
			     (void *)&resp, &resp_len, sizeof(resp));
	if (resp.id == CLOSE_SYSCALL_ID)
		ret = resp.args.int_field1;

	return ret;
}

int ipcm_remote_read(struct rpmsg_device *rpdev, int fd, unsigned char *buffer, int buflen)
{
	struct rpmsg_rpc_syscall syscall;
	struct rpmsg_rpc_syscall *resp = NULL;
	int resp_len = 0;
	int payload_size = sizeof(syscall);
	unsigned char *tmpbuf = NULL;
	int ret = -1;

	if (!rpdev || !buffer || buflen == 0)
		return -EINVAL;

	tmpbuf = kzalloc(MAX_BUF_LEN, GFP_KERNEL);
	if (!tmpbuf) {
		pr_err("%s %d no memory.", __func__, __LINE__);
		return -ENOMEM;
	}

	/* Construct rpc payload */
	syscall.id = READ_SYSCALL_ID;
	syscall.args.int_field1 = fd;
	syscall.args.int_field2 = min(buflen, (int)(MAX_BUF_LEN - sizeof(*resp)));
	syscall.args.data_len = 0;	/*not used */

	resp = (struct rpmsg_rpc_syscall *)tmpbuf;
	resp->id = 0;
	ret = ipcm_rpc_call(rpdev, "rpc_syscall_read", &syscall, payload_size,
			     resp, &resp_len, MAX_BUF_LEN);

	/* Obtain return args and return to caller */
	if (ret >= 0) {
		if (resp->id == READ_SYSCALL_ID) {
			if (resp->args.int_field1 > 0) {
				int real_read_len = resp->args.data_len;
				unsigned char *tmpptr = tmpbuf;

				tmpptr += sizeof(*resp);
				memcpy(buffer, tmpptr, real_read_len);
			}
			ret = resp->args.int_field1;
		} else {
			ret = -EINVAL;
		}
	}

	kfree(tmpbuf);

	return ret;
}

int ipcm_remote_write(struct rpmsg_device *rpdev, int fd, const unsigned char *ptr, int len)
{
	int ret = -1;
	struct rpmsg_rpc_syscall *syscall = NULL;
	struct rpmsg_rpc_syscall resp;
	int resp_len = 0;
	int payload_size = sizeof(*syscall) + len;
	unsigned char *tmpbuf = NULL;
	unsigned char *tmpptr = NULL;
	int null_term = 0;

	if (!rpdev || !ptr || len > (MAX_BUF_LEN - sizeof(*syscall)))
		return -EINVAL;

	tmpbuf = kzalloc(MAX_BUF_LEN, GFP_KERNEL);
	if (!tmpbuf) {
		pr_err("%s %d no memory.", __func__, __LINE__);
		return -ENOMEM;
	}

	if (fd == 1)
		null_term = 1;

	syscall = (struct rpmsg_rpc_syscall *)tmpbuf;
	syscall->id = WRITE_SYSCALL_ID;
	syscall->args.int_field1 = fd;
	syscall->args.int_field2 = len;
	syscall->args.data_len = len + null_term;
	tmpptr = tmpbuf + sizeof(*syscall);
	memcpy(tmpptr, ptr, len);
	if (null_term == 1) {
		*(char *)(tmpptr + len + null_term) = 0;
		payload_size += 1;
	}
	resp.id = 0;
	ret = ipcm_rpc_call(rpdev, "rpc_syscall_write", syscall, payload_size,
			     (void *)&resp, &resp_len, sizeof(resp));

	if (ret >= 0) {
		if (resp.id == WRITE_SYSCALL_ID)
			ret = resp.args.int_field1;
		else
			ret = -EINVAL;
	}

	kfree(tmpbuf);

	return ret;
}

int cmd_exec_dummy_cb(struct rpmsg_device *rpdev, unsigned long packet_id,
		void *message, int message_size, void *priv, u32 src)
{
	if (message_size > 0) {
		char *token;
		char *split = "\n";

		while ((token = strsep(message, split)) != NULL) {
			pr_info("%s\n", token);
		}
	}

	return 0;
}

int ipcm_exec_cmd(void *core, const char *cmd, ipcm_rx_cb_t rx_callback)
{
	struct rpmsg_device *rpdev;
	char resp = '\0';
	int resp_len;
	int ret = 0;

	if ((strlen(cmd) + 1) > MAX_BUF_LEN) {
		return -EINVAL;
	}

	rpdev = ipcm_open_channel(core, "ipcm_cmd");
	if (IS_ERR_OR_NULL(rpdev)) {
		return -ENODEV;
	}

	ipcm_set_rx_callback(rpdev, rx_callback);

	/* resp MUST be a '\n' reply from ipcm_server */
	ret = ipcm_send_request_with_response(rpdev, true, (void *)cmd, strlen(cmd) + 1,
								&resp, &resp_len, sizeof(resp));

	return ret;
}

#include "../../include/cndrv_debug.h"

static int ipcm_rpc_log_rx_cb(struct rpmsg_device *rpdev, unsigned long packet_id, void *data, int len,
	void *priv, u32 src)
{
	struct cn_core_set *core = (struct cn_core_set *)ipcm_get_priv_data(rpdev);

	cn_dev_core_info(core, "[ARM]: %s", (char *)data);

	return 0;
}

void ipcm_rpc_log_init(void *_core)
{
	struct rpmsg_device *rpdev;
	struct cn_core_set *core = (struct cn_core_set *)_core;

	if (cn_core_is_vf(core)) {
		pr_info("%s only can called by pf.\n", __func__);
		return;
	}

	rpdev = ipcm_open_channel(core, RPSMG_LOG_CHANNEL_NAME);
	if (rpdev) {
		ipcm_set_rx_callback(rpdev, ipcm_rpc_log_rx_cb);
		ipcm_set_priv_data(rpdev, core);
	} else {
		pr_err("%s() failed\n", __func__);
	}
}

static int ipcm_query_port_rx_cb(struct rpmsg_device *rpdev, unsigned long packet_id, void *data, int len,
	void *priv, u32 src)
{
	int tgid = 0;
	int port = *((int *)data);


	tgid = virtio_rpmsg_query_endpoint(rpdev, port);
	dev_dbg(&rpdev->dev, "%s, port(%d) tgid(%d)\n", __func__, port, tgid);

	return ipcm_send_response_to_port(rpdev, packet_id, &tgid, sizeof(tgid), src);
}

void ipcm_query_port_service_init(void *core)
{
	struct rpmsg_device *rpdev;

	rpdev = ipcm_open_channel(core, RPSMG_QUERY_PORT_NAME);
	if (rpdev) {
		ipcm_set_rx_async_callback(rpdev, ipcm_query_port_rx_cb);
	} else {
		pr_err("%s() failed\n", __func__);
	}
}

int ipcm_announce_vf_status(void *_core, bool start, int vf_id)//in cxx_pcie_vf_work()
{
	struct cn_core_set *core = (struct cn_core_set *)_core;
	struct rpmsg_device *rpdev;
	uint32_t resp_size = 0;
	int resp = 0;
	struct cn_core_set *vf_core;
	struct virtio_device *vdev;
	int ret = 0;

	if (cn_core_is_vf(core)) {
		pr_err("%s only can called by pf.\n", __func__);
		return -EINVAL;
	}

	vf_core = cn_core_get_mi_core(core->idx, vf_id);
	vdev = vf_core ? cambr_rproc_get_virtio_device(vf_core) : NULL;

	rpdev = ipcm_open_channel(core, VS_CHANNEL_NAME);
	if (IS_ERR_OR_NULL(rpdev)) {
		return -ENODEV;
	}
	if (start)
		ret = ipcm_rpc_call_timeout(rpdev, "rpc_vf_start", &vf_id, sizeof(int), &resp, &resp_size, sizeof(int), 5000);
	else
		ret = ipcm_rpc_call_timeout(rpdev, "rpc_vf_exit", &vf_id, sizeof(int), &resp, &resp_size, sizeof(int), 5000);
	/* ignore rpc result */
	if (vdev)
		vdev->vf_start = start;
	else if (ret < 0) {
		cn_dev_core_err(core, "ret = %d", ret);
		cn_core_dump_device_info(core);
	}

	return 0;
}

struct ipcm_timestamp_info *perf_host_kva;
static dev_addr_t perf_dev_iova;

int ipcm_enable_perf_record(void *_core, int test_cnt, int record_en)
{
	struct cn_core_set *core = (struct cn_core_set *)_core;
	struct rpmsg_device *rpdev;
	uint32_t resp_size = 0;
	int resp = 0;
	char in[100];
	char out[100];
	int i;
	struct ipcm_perf_test_info test_info = {0};
	host_addr_t host_vaddr;
	u64 start, end, duration, sum = 0;
	int ret = 0;

	if (perf_host_kva && perf_dev_iova) {
		cn_device_share_mem_free(0, (host_addr_t)perf_host_kva, perf_dev_iova,
					core);
		perf_dev_iova = 0;
		perf_host_kva = NULL;
	}

	if (record_en) {
		ret = cn_device_share_mem_alloc(0, &host_vaddr, &perf_dev_iova,
				sizeof(struct ipcm_timestamp_info) * test_cnt,
				core);
		if (ret) {
			cn_dev_core_err(core, "shared perf record alloc fail.");
			return -ENOMEM;
		}
		perf_host_kva = (struct ipcm_timestamp_info *)host_vaddr;
		memset_io(perf_host_kva, 0, sizeof(struct ipcm_timestamp_info) * test_cnt);
		wmb();/* make sure buffer clear */
	}

	rpdev = ipcm_open_channel(core, RPSMG_REC_CHANNEL_NAME);
	if (IS_ERR_OR_NULL(rpdev)) {
		ret = -ENODEV;
		goto free_shm_mem;
	}

	test_info.perf_dev_iova = perf_dev_iova;
	test_info.test_cnt = test_cnt;
	test_info.record_en = record_en;

	ret = ipcm_rpc_call(rpdev, "rpc_enable_perf_record",
			&test_info, sizeof(struct ipcm_perf_test_info), &resp, &resp_size, sizeof(int));
	if (ret) {
		cn_dev_core_err(core, "rpc_enable_perf_record fail with ret:%d.", ret);
		ret = -ENOMEM;
		goto free_shm_mem;
	}

	ipcm_record_index = 0;
	ipcm_record = record_en ? test_cnt : 0;

	for (i = 0; i < test_cnt; i++) {
		start = get_host_timestamp_by_clockid(CLOCK_MONOTONIC_RAW);
		ret = ipcm_rpc_call(rpdev, "rpc_perf_test", in, 1, out, &resp, sizeof(out));
		end = get_host_timestamp_by_clockid(CLOCK_MONOTONIC_RAW);
		duration = end - start;
		dev_info(&rpdev->dev, "[%d]:%llu ns\n", i, duration);
		if (unlikely(ret != 0x88)) {
			dev_err(&rpdev->dev, "error occur on [%d], ret:%d\n", i, ret);
			goto out;
		}
		sum += duration;
	}
	dev_info(&rpdev->dev, "AVG time:  %llu/%d = %llu ns\n", sum, test_cnt, sum/test_cnt);

out:
	ipcm_record = 0;
	return 0;

free_shm_mem:
	if (record_en) {
		cn_device_share_mem_free(0, (host_addr_t)perf_host_kva, perf_dev_iova, core);
		perf_host_kva = NULL;
		perf_dev_iova = 0;
	}

	return ret;
}

int ipcm_record_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	int i;

	if (!perf_host_kva) {
		seq_puts(m, "echo $test_cnt $record_en > ipcm_perf_record && cat ipcm_perf_record\n");
		return 0;
	}
	seq_printf(m, "totol record: %d\n", ipcm_record_index);
	seq_puts(m, "--------------------------------------------------------------------------\n");
	for (i = 0; i < ipcm_record_index; i++) {
		seq_printf(m, "| rpc_start | <--%llu--> | get_tx_buf | <--%llu--> | kick_mbox |",
			perf_host_kva[i].get_tx_buf_ns - perf_host_kva[i].rpc_in_ns,
			perf_host_kva[i].kick_mbox_ns - perf_host_kva[i].get_tx_buf_ns);
		seq_printf(m, " <--%llu--> | remote recv_buf | <--%llu--> | remote real_cb_end |",
			perf_host_kva[i].remote_recv_buf_ns - perf_host_kva[i].kick_mbox_ns,
			perf_host_kva[i].remote_real_cb_end_ns - perf_host_kva[i].remote_recv_buf_ns);
		seq_printf(m, " <--%llu--> | remote get_tx_buf | <--%llu--> | remote kick_mbox |",
			perf_host_kva[i].remote_get_tx_buf_ns - perf_host_kva[i].remote_real_cb_end_ns,
			perf_host_kva[i].remote_kick_mbox_ns - perf_host_kva[i].remote_get_tx_buf_ns);
		seq_printf(m, " <--%llu--> | recv_buf | <--%llu--> | ept_cb_end | <--%llu--> | rpc_end |\n",
				perf_host_kva[i].recv_buf_ns - perf_host_kva[i].remote_kick_mbox_ns,
				perf_host_kva[i].ept_cb_end_ns - perf_host_kva[i].recv_buf_ns,
				perf_host_kva[i].rpc_out_ns - perf_host_kva[i].ept_cb_end_ns);
		seq_printf(m, "====>total %llu ns.\n", perf_host_kva[i].rpc_out_ns - perf_host_kva[i].rpc_in_ns);
		seq_puts(m, "--------------------------------------------------------------------------\n\n");
	}
	cn_device_share_mem_free(0, (host_addr_t)perf_host_kva, perf_dev_iova,
			core);
	perf_host_kva = NULL;
	perf_dev_iova = 0;

	return 0;
}
#else
extern int pf_vf_num;

int ipcm_get_device_count(void)
{
	return pf_vf_num;
}
EXPORT_SYMBOL(ipcm_get_device_count);

void ipcm_set_rx_callback(struct rpmsg_device_proxy *proxy, ipcm_rx_cb_t rx_callback)
{
	int vf_id;
	struct rpmsg_device *rpdev;

	for (vf_id = 0; vf_id < proxy->pf_vf_num; vf_id++) {
		rpdev = proxy->rpdev[vf_id];
		if (likely(rpdev)) {
			rpdev->rx_callback = rx_callback;
			rpdev->rx_cb_async = false;
		} else {
			pr_err("%s: rpdev of vf_id:%d is NULL\n", __func__, vf_id);
		}
	}
}
EXPORT_SYMBOL(ipcm_set_rx_callback);

void ipcm_set_rx_async_callback(struct rpmsg_device_proxy *proxy, ipcm_rx_cb_t rx_callback)
{
	int vf_id;
	struct rpmsg_device *rpdev;

	for (vf_id = 0; vf_id < proxy->pf_vf_num; vf_id++) {
		rpdev = proxy->rpdev[vf_id];
		if (likely(rpdev)) {
			rpdev->rx_callback = rx_callback;
			rpdev->rx_cb_async = true;
		} else {
			pr_err("%s: rpdev of vf_id:%d is NULL\n", __func__, vf_id);
		}
	}
}
EXPORT_SYMBOL(ipcm_set_rx_async_callback);

void ipcm_set_rpc_services(struct rpmsg_device_proxy *proxy, struct rpmsg_rpc_service_set *services)
{
	int vf_id;
	struct rpmsg_device *rpdev;

	for (vf_id = 0; vf_id < proxy->pf_vf_num; vf_id++) {
		rpdev = proxy->rpdev[vf_id];
		if (likely(rpdev)) {
			rpdev->services = services;
		} else {
			pr_err("%s: rpdev of vf_id:%d is NULL\n", __func__, vf_id);
		}
	}
}
EXPORT_SYMBOL(ipcm_set_rpc_services);

void ipcm_set_priv_data(struct rpmsg_device_proxy *proxy, void *priv)
{
	int vf_id;
	struct rpmsg_device *rpdev;

	for (vf_id = 0; vf_id < proxy->pf_vf_num; vf_id++) {
		rpdev = proxy->rpdev[vf_id];
		if (likely(rpdev && rpdev->ept))
			rpdev->ept->priv = priv;
		else
			pr_err("%s: rpdev of vf_id:%d is NULL\n", __func__, vf_id);
	}
}
EXPORT_SYMBOL(ipcm_set_priv_data);
#endif

void *ipcm_get_priv_data(struct rpmsg_device *rpdev)
{
	if (!rpdev || !rpdev->ept)
		return NULL;
	return rpdev->ept->priv;
}
EXPORT_SYMBOL(ipcm_get_priv_data);

int ipcm_get_vf_id(struct rpmsg_device *rpdev)
{
	if (!rpdev)
		return 0;
	return rpdev->vf_id;
}
EXPORT_SYMBOL(ipcm_get_vf_id);

static int ipcm_probe(struct rpmsg_device *rpdev)
{
	struct ipcm_priv *priv;
	struct ipcm_hdr_ctx_manager *hdr_mgr;
	struct ipcm_hdr_ctx_manager *ctx_mgr;
	int ctx_size =  sizeof(struct ipcm_ctx);
	/* cacheline align */
	int ctx_size_align = ALIGN(ctx_size, 64);
	int hdr_size = MAX_RPMSG_BUF_SIZE;
	int ret = 0;

	dev_dbg(&rpdev->dev, "%s: probing %s\n", __func__, rpdev->id.name);

	priv = devm_kzalloc(&rpdev->dev, sizeof(*priv), GFP_KERNEL);
	if (unlikely(!priv))
		return -ENOMEM;

	dev_set_drvdata(&rpdev->dev, priv);
	priv->rpdev = rpdev;

	idr_init(&priv->message_idr);
	spin_lock_init(&priv->message_lock);

	/* TODO get tx buffer pointer from rpmsg core to reduce memcpy */
	hdr_mgr = ipcm_hdr_ctx_mem_init(rpdev, MAX_RPMSG_NUM_BUFS, hdr_size);
	if (!hdr_mgr) {
		ret = -ENOMEM;
		goto free_priv;
	}
	priv->hdr_mgr = hdr_mgr;

	ctx_mgr = ipcm_hdr_ctx_mem_init(rpdev, MAX_RPMSG_NUM_BUFS, ctx_size_align);
	if (!ctx_mgr) {
		ret = -ENOMEM;
		goto free_hdr;
	}
	priv->ctx_mgr = ctx_mgr;

	return 0;

free_hdr:
	ipcm_hdr_ctx_mem_exit(rpdev, priv->hdr_mgr);
free_priv:
	devm_kfree(&rpdev->dev, priv);
	return ret;
}

static void ipcm_remove(struct rpmsg_device *rpdev)
{
	struct ipcm_priv *priv = dev_get_drvdata(&rpdev->dev);

	dev_dbg(&rpdev->dev, "%s: removing %s\n", __func__, rpdev->id.name);

	flush_work(&ipcm_async_work);

	ipcm_hdr_ctx_mem_exit(rpdev, priv->hdr_mgr);
	priv->hdr_mgr = NULL;
	ipcm_hdr_ctx_mem_exit(rpdev, priv->ctx_mgr);
	priv->ctx_mgr = NULL;

	idr_destroy(&priv->message_idr);

	/* TODO check for pending responses for any of the child devices, do in ipcm_reset_callback() */
	/* TODO disconnect them all */
	dev_set_drvdata(&rpdev->dev, NULL);
	devm_kfree(&rpdev->dev, priv);
}

static struct rpmsg_device_id ipcm_id_table[] = {
	{ .name	= "rpmsg-ipcm" },
	{ },
};

static struct rpmsg_driver rpmsg_ipcm = {
	.drv.name	= "rpmsg-ipcm",
	.id_table	= ipcm_id_table,
	.probe		= ipcm_probe,
	.callback	= ipcm_cb,
	.remove		= ipcm_remove,
};

int ipcm_init(void)
{
	int ret;

	ret = cn_register_rpmsg_driver(&rpmsg_ipcm);
	if (ret) {
		pr_err("failed to register ipcm driver: %d\n", ret);
		goto out;
	}

	pr_info("registered ipcm driver\n");

	return 0;

out:
	return ret;
}

void ipcm_fini(void)
{
	pr_info("unregistering ipcm driver\n");

	cn_unregister_rpmsg_driver(&rpmsg_ipcm);
}

MODULE_DESCRIPTION("Cambricon Inter Processor Communication Driver");
