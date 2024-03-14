/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/device.h>
//#include <linux/rpmsg.h>
#ifdef IN_CNDRV_HOST
#include "../../../include/cndrv_ipcm.h"
#else
#include "../../cambr_ipcm.h"
#endif

/* client open_channel(). server create_channel() & server load first */

struct mm_info {
	unsigned long addr;
	int size;
};

#ifndef IN_CNDRV_HOST
static struct rpmsg_device_proxy *mm_rpdev;
static struct rpmsg_device_proxy *log_rpdev;
static struct rpmsg_device_proxy *sbts_rpdev;
static struct rpmsg_device_proxy *async_demo_rpdev;
static struct rpmsg_device_proxy *rpc_perf_rpdev;
static struct rpmsg_device_proxy *user_rpdev;

/* only ipcm_send_response() need packet_id */
static int rpmsg_log_server_rx_cb(struct rpmsg_device *rpdev, unsigned long packet_id, void *data, int len,
						void *priv, u32 src)
{
	pr_info("recv msg from src: %d, len %d, data:%s\n", src, len, (char *)data);

	ipcm_send_message(rpdev, "log vuart msg from server", strlen("log vuart msg from server"));

	//inster to tty, not need klog_daemon now, do it in rx_cb
	//log_vuart_recv_func()

	return 0;
}

/* only ipcm_send_response() need packet_id */
static int rpmsg_sbts_server_rx_cb(struct rpmsg_device *rpdev, unsigned long packet_id, void *data, int len,
						void *priv, u32 src)
{
	int i = 100000;

	pr_info("recv msg from src: %d, len %d, data:%s\n", src, len, (char *)data);
	//Do sth...
	while (i--)
		;

	ipcm_send_response(rpdev, packet_id, "i am sbts response", strlen("i am sbts response"));

	return 0;
}

static int rpmsg_async_demo_rx_cb(struct rpmsg_device *rpdev, unsigned long packet_id, void *data, int len,
						void *priv, u32 src)
{
	int i = 100000;

	pr_info("recv msg from src: %d, len %d, data:%s\n", src, len, (char *)data);
	//Do sth...
	while (i--)
		;

	ipcm_send_response(rpdev, packet_id, "i am async_demo response", strlen("i am async_demo response"));

	return 0;
}

IPCM_DECLARE_CALLBACK_FUNC(rpc_mem_alloc);
IPCM_DECLARE_CALLBACK_FUNC(rpc_mem_free);

static struct rpmsg_rpc_service_set service_table[] = {
		DEF_CALLBACK_PAIR(rpc_mem_alloc),
		DEF_CALLBACK_PAIR(rpc_mem_free),
		DEF_CALLBACK_PAIR_END,
};
#define COMMU_SERVICE_TABLE service_table

int32_t
rpc_mem_alloc(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct mm_info *info = in_msg;
	void *addr;

	if (in_len != sizeof(struct mm_info)) {
		pr_info("%s, in_len %d invalid, expect %ld\n", __func__, in_len, sizeof(struct mm_info));
		return -EINVAL;
	}
	pr_info("%s, size:%d, vf_id:%d\n", __func__, info->size, vf_id);
	addr = kmalloc(info->size, GFP_KERNEL);
	if (!addr)
		return -ENOMEM;
	((struct mm_info *)out_msg)->addr = (unsigned long)addr;
	((struct mm_info *)out_msg)->size = info->size;
	pr_info("%s, addr:0x%lx\n", __func__, ((struct mm_info *)out_msg)->addr);
	*out_len = sizeof(struct mm_info);
	return 0xa5;
}

int32_t
rpc_mem_free(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct mm_info *info = in_msg;

	if (in_len != sizeof(struct mm_info)) {
		pr_info("%s, in_len %d invalid\n", __func__, in_len);
		return -EINVAL;
	}
	pr_info("%s, addr:0x%lx, size:%d, vf_id:%d\n", __func__, info->addr, info->size, vf_id);
	kfree((void *)(info->addr));
	*(int *)out_msg = 0;
	*out_len = sizeof(int);
	return 0x4b;
}

IPCM_DECLARE_CALLBACK_FUNC(rpc_perf_test);

static struct rpmsg_rpc_service_set perf_service_table[] = {
		DEF_CALLBACK_PAIR(rpc_perf_test),
		DEF_CALLBACK_PAIR_END,
};
#define PERF_SERVICE_TABLE perf_service_table

int32_t
rpc_perf_test(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	*out_len = in_len;
	memcpy(out_msg, in_msg, in_len);
	return 0x88;
}

/* only ipcm_send_response() need packet_id */
static int user_to_kernel_rx_cb(struct rpmsg_device *rpdev, unsigned long packet_id, void *data, int len,
						void *priv, u32 src)
{
	pr_info("recv msg from src: %d, len %d, data:%s\n", src, len, (char *)data);
	if (strncmp("client msg from user to kernel", data, len))
		ipcm_send_message(rpdev, "user_to_kernel test FAILED!", strlen("user_to_kernel test FAILED!"));
	else
		ipcm_send_message(rpdev, "server msg from kernel to user", strlen("server msg from kernel to user"));

	return 0;
}

#else
static struct rpmsg_device *mm_rpdev;
static struct rpmsg_device *log_rpdev;
static struct rpmsg_device *sbts_rpdev;
static struct rpmsg_device *async_demo_rpdev;
static struct rpmsg_device *rpc_perf_rpdev;
static struct rpmsg_device *user_rpdev;

/* only ipcm_send_response() need packet_id */
static int rpmsg_log_client_rx_cb(struct rpmsg_device *rpdev, unsigned long packet_id, void *data, int len,
						void *priv, u32 src)
{
	pr_info("recv msg from src: %d, len %d, data:%s\n", src, len, (char *)data);

	//inster to tty, not need klog_daemon now, do it in rx_cb
	//log_vuart_recv_func()

	return 0;
}

static int rpmsg_async_demo_cb(void *cb_data, void *req, int req_sz, void *resp, int resp_sz)
{
	struct rpmsg_device *rpdev = cb_data;

	pr_info("recv msg len %d, data:%s\n", resp_sz, (char *)resp);

	return 0;
}

#endif

static int ipcm_demo_init(void)
{
	#ifndef IN_CNDRV_HOST
	//rpc
	rpc_perf_rpdev =  ipcm_create_channel("rpc_perf_test");
	if (!rpc_perf_rpdev) {
		pr_err("rpc_perf_test channel create failed\n");
		return -1;
	}
	ipcm_set_rpc_services(rpc_perf_rpdev, PERF_SERVICE_TABLE);

	//rpc
	mm_rpdev =  ipcm_create_channel("cn_mm_krpc");
	if (!mm_rpdev) {
		pr_err("cn_mm_krpc channel create failed\n");
		goto out;
	}
	ipcm_set_rpc_services(mm_rpdev, COMMU_SERVICE_TABLE);


	//msg without response
	log_rpdev = ipcm_create_channel("log_channel_name");
	if (!log_rpdev) {
		pr_err("log channel create failed\n");
		goto out;
	}
	ipcm_set_rx_callback(log_rpdev, rpmsg_log_server_rx_cb);
	/* normally, server will not send message firstly, for test purpose,
	 * we wait for client ack to update his rpmsg addr info
	 */
	//while (!ipcm_channel_ready(log_rpdev))
	//	msleep(100);
	//ipcm_send_message(log_rpdev, "log vuart msg from server", strlen("log vuart msg from server"));


	//msg with response
	sbts_rpdev = ipcm_create_channel("sbts_channel");
	if (!sbts_rpdev) {
		pr_err("sbts channel create failed\n");
		goto out;
	}
	ipcm_set_rx_callback(sbts_rpdev, rpmsg_sbts_server_rx_cb);


	//msg with response async
	async_demo_rpdev = ipcm_create_channel("async_demo_channel");
	if (!async_demo_rpdev) {
		pr_err("async_demo channel create failed\n");
		goto out;
	}
	ipcm_set_rx_callback(async_demo_rpdev, rpmsg_async_demo_rx_cb);


	user_rpdev = ipcm_create_user_channel("user_channel", 0xbbbb);
	if (!user_rpdev) {
		pr_err("user channel create failed\n");
		goto out;
	}
	/* reuse cb */
	ipcm_set_rx_callback(user_rpdev, user_to_kernel_rx_cb);
	ipcm_set_rpc_services(user_rpdev, COMMU_SERVICE_TABLE);

	#else
	int ret = 0;
	//rpc
	rpc_perf_rpdev = __ipcm_open_channel("rpc_perf_test");
	if (!rpc_perf_rpdev) {
		pr_err("cn_mm_krpc channel create failed\n");
		goto out;
	} else {
		char tmp[100];
		int out;
		int i;
		ktime_t start, end, delta;
		unsigned long long duration, sum = 0;

		for (i = 0; i < 1024; i++) {
			start = ktime_get();
			ret = ipcm_rpc_call(rpc_perf_rpdev, "rpc_perf_test", tmp, 1, tmp, &out, sizeof(tmp));
			end = ktime_get();
			delta = ktime_sub(end, start);
			duration = (unsigned long long)ktime_to_ns(delta) >> 10;
			pr_info("thread %d time: %llu us, ret: %d\n", current->pid, duration, ret);
			if (unlikely(ret < 0))
				goto out;
			sum += duration;
		}
		pr_info("thread %d all time: %llu average time: %llu us\n", current->pid, sum, sum / (1024));
	}
	//rpc
	mm_rpdev = __ipcm_open_channel("cn_mm_krpc");
	if (!mm_rpdev) {
		pr_err("cn_mm_krpc channel create failed\n");
		goto out;
	} else {
		struct mm_info alloc_info = { .size = 512, };
		struct mm_info out;
		int out_len;
		int free_ret = -1;

		ret = ipcm_rpc_call(mm_rpdev, "rpc_mem_alloc",
			&alloc_info, sizeof(struct mm_info),
			&out, &out_len, sizeof(struct mm_info));
		pr_info("alloc addr = %lx, ret = 0x%x, out_size:%d\n", out.addr, ret, out_len);
		if (unlikely(ret < 0))
			goto out;

		ret = ipcm_rpc_call(mm_rpdev, "rpc_mem_free",
			&out, sizeof(struct mm_info),
			&free_ret, &out_len, sizeof(struct mm_info));
		pr_info("free out:%d ret = 0x%x, out_size:%d\n", free_ret, ret, out_len);
		if (unlikely(ret < 0))
			goto out;
	}

	//msg without response
	log_rpdev = __ipcm_open_channel("log_channel_name");
	if (!log_rpdev) {
		pr_err("log channel create failed\n");
		goto out;
	}
	ipcm_set_rx_callback(log_rpdev, rpmsg_log_client_rx_cb);
	ret = ipcm_send_message(log_rpdev, "log vuart msg from client", strlen("log vuart msg from client"));
	if (unlikely(ret < 0))
		goto out;

	//msg with response
	sbts_rpdev = __ipcm_open_channel("sbts_channel");
	if (!sbts_rpdev) {
		pr_err("sbts channel create failed\n");
		goto out;
	} else {
		char resp[512] = {0};
		int resp_len;

		pr_info("send request...\n");
		ret = ipcm_send_request_with_response(sbts_rpdev, true, "sbts wait response test",
			strlen("sbts wait response test"), &resp[0], &resp_len, 512);
		if (unlikely(ret < 0))
			goto out;
		pr_info("got response len: %d, %s.\n", resp_len, resp);
	}

	//msg with response async
	async_demo_rpdev = __ipcm_open_channel("async_demo_channel");
	if (!async_demo_rpdev) {
		pr_err("async_demo channel create failed\n");
		goto out;
	} else {
		pr_info("send request... async\n");
		ret = ipcm_send_request_with_callback(async_demo_rpdev, "async wait response test",
			strlen("async wait response test"), async_demo_rpdev, rpmsg_async_demo_cb);
		if (unlikely(ret < 0))
			goto out;
	}

	//msg without response
	user_rpdev = __ipcm_open_user_channel("user_channel", 0xcccc);
	if (!user_rpdev) {
		pr_err("user channel create failed\n");
		goto out;
	} else {
		struct mm_info alloc_info = { .size = 512, };
		struct mm_info out;
		int out_len;
		int free_ret = -1;
		int ret;

		ipcm_set_rx_callback(user_rpdev, rpmsg_log_client_rx_cb);
		ret = ipcm_send_message(user_rpdev, "client msg from kernel to user",
			strlen("client msg from kernel to user"));
		if (unlikely(ret < 0))
			goto out;

		ret = ipcm_rpc_call(user_rpdev, "rpc_mem_alloc",
			&alloc_info, sizeof(struct mm_info),
			&out, &out_len, sizeof(struct mm_info));
		pr_info("alloc addr = %lx, ret = 0x%x, out_size:%d\n", out.addr, ret, out_len);
		if (unlikely(ret < 0))
			goto out;

		ret = ipcm_rpc_call(user_rpdev, "rpc_mem_free",
			&out, sizeof(struct mm_info),
			&free_ret, &out_len, sizeof(struct mm_info));
		pr_info("free out:%d ret = 0x%x, out_size:%d\n", free_ret, ret, out_len);
		if (unlikely(ret < 0))
			goto out;
	}
	#endif

	return 0;

out:
	if (rpc_perf_rpdev)
		ipcm_destroy_channel(rpc_perf_rpdev);
	if (mm_rpdev)
		ipcm_destroy_channel(mm_rpdev);
	if (log_rpdev)
		ipcm_destroy_channel(log_rpdev);
	if (sbts_rpdev)
		ipcm_destroy_channel(sbts_rpdev);
	if (async_demo_rpdev)
		ipcm_destroy_channel(async_demo_rpdev);
	if (user_rpdev)
		ipcm_destroy_channel(user_rpdev);
	return 0;
}
module_init(ipcm_demo_init);

static void ipcm_demo_exit(void)
{
	if (rpc_perf_rpdev)
		ipcm_destroy_channel(rpc_perf_rpdev);
	if (mm_rpdev)
		ipcm_destroy_channel(mm_rpdev);
	if (log_rpdev)
		ipcm_destroy_channel(log_rpdev);
	if (sbts_rpdev)
		ipcm_destroy_channel(sbts_rpdev);
	if (async_demo_rpdev)
		ipcm_destroy_channel(async_demo_rpdev);
	if (user_rpdev)
		ipcm_destroy_channel(user_rpdev);
}
module_exit(ipcm_demo_exit);

MODULE_LICENSE("GPL v2");
