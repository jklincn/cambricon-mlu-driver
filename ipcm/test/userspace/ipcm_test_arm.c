/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <limits.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <semaphore.h>
#include <assert.h>

#include "ipcm.h"

#define TEST_SYNC_MSG_ADDR       (0xccc0)
#define TEST_RPC_ADDR            (0xccc1)
#define TEST_PORT_ADDR           (0xccc2)
#define TEST_SYNC_MSG_BREAK_ADDR (0xccc3)
#define TEST_ASYNC_MSG_ADDR      (0xccc4)
#define TEST_ASYNC_RESP_CB_ADDR  (0xccc5)
#define TEST_PERF_RPC_ADDR       (0xccc6)
#define TEST_SYNC_PORT_ADDR      (0xccc7)
#define TEST_STRESS_PORT_ADDR    (0xccc8)
#define TEST_KERN2USER_ADDR      (0xcccc)
#define TEST_USER2KERN_ADDR      (0xbbbb)

void usage(void)
{
	printf("1.   ./ipcm_test -c0 -r1 -s10000 -d10000 -l10 -t\n");
	printf("2.   ./ipcm_test -r is required, others are optionals\n");
	printf("3.   ./ipcm_test card role src dst loop_cnt thread_num\n");
}

static struct ipcm_proxy *rcdev9;

struct pthread_arg {
	struct ipcm_dev *rcdev;
	int loop;
	int role;
};

static void *self_routine1(void *arg)
{
	struct pthread_arg *th_arg = (struct pthread_arg *)arg;
	int i;
	char data[512] = {0};//same as driver MAX
	int n = 0;

	while (1) {
		/* receive data from remote device */
		n = ipcm_recv_packet(th_arg->rcdev, &data, sizeof(data));
		data[n] = '\0';
		printf("read[%d]: %s\n", n, data);
		if (!strcmp(data, "shutdown")) {
			printf("read thread exit\n");
			break;
		}
		/* write */
		snprintf(data, sizeof(data), "%d", atoi(data) + 100000);//echo
		/* send data to remote device */
		ipcm_send_packet(th_arg->rcdev, data, strlen(data));
	}
}

void msg_sync_test(struct ipcm_proxy *proxy, int role, int loop, int thread_num)
{
	int i;
	pthread_t *thread = calloc(sizeof(pthread_t), proxy->pf_vf_num);
	struct pthread_arg *th_arg = calloc(sizeof(struct pthread_arg), proxy->pf_vf_num);

	for (i = 0; i < proxy->pf_vf_num; i++) {
		th_arg[i].rcdev = proxy->rcdev[i];
		th_arg[i].loop = loop;
		th_arg[i].role = role;

		pthread_create(&thread[i], NULL,
				self_routine1, (void *)&th_arg[i]);
	}

	for (i = 0; i < proxy->pf_vf_num; i++) {
		pthread_join(thread[i], NULL);
	}
	free(thread);
	free(th_arg);
}

static int msg_async_test_rx_cb(struct ipcm_dev *rcdev, unsigned long packet_id,
		void *message, int message_size, unsigned int src)
{
	printf("%s, recv msg from src:%u vf_id:%d packet_id:%lu len: %d, data:%s\n",
		__func__, src, rcdev->id, packet_id, message_size, (char *)message);

	if (strncmp("async msg from client", message, message_size))
		ipcm_send_message(rcdev, "msg async test FAILED!", strlen("msg async test FAILED!"));
	else
		ipcm_send_message(rcdev, "async msg from server", strlen("async msg from server"));

	return 0;
}

static int test_with_resp_callback_rx_cb(struct ipcm_dev *rcdev, unsigned long packet_id,
		void *message, int message_size, unsigned int src)
{
	printf("%s, recv msg from src:%u vf_id:%d packet_id:%lu len: %d, data:%s\n",
		__func__, src, rcdev->id, packet_id, message_size, (char *)message);

	ipcm_send_response(rcdev, packet_id, "response from server", strlen("response from server"));

	return 0;
}

static int kernel_to_user_rx_cb(struct ipcm_dev *rcdev, unsigned long packet_id,
		void *message, int message_size, unsigned int src)
{
	printf("%s, recv msg from src:%u vf_id:%d len %d, data:%s\n",
		__func__, src, rcdev->id, message_size, (char *)message);

	ipcm_send_message(rcdev, "server msg from user to kernel", strlen("server msg from user to kernel"));

	return 0;
}

IPCM_DECLARE_CALLBACK_FUNC(rpc_mem_alloc);
IPCM_DECLARE_CALLBACK_FUNC(rpc_mem_free);
IPCM_DECLARE_CALLBACK_FUNC(rpc_mem_time_out_free);
IPCM_DECLARE_CALLBACK_FUNC(rpc_stress_test);

static struct rpmsg_rpc_service_set service_table[] = {
		DEF_CALLBACK_PAIR(rpc_mem_alloc),
		DEF_CALLBACK_PAIR(rpc_mem_free),
		DEF_CALLBACK_PAIR(rpc_mem_time_out_free),
		DEF_CALLBACK_PAIR(rpc_stress_test),
		DEF_CALLBACK_PAIR_END,
};
#define COMMU_SERVICE_TABLE service_table

struct mm_info {
	unsigned long addr;
	int size;
};

int
rpc_mem_alloc(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct mm_info *info = in_msg;
	void *addr;

	if (in_len != sizeof(struct mm_info)) {
		printf("%s, in_len %d invalid, expect %ld\n", __func__, in_len, sizeof(struct mm_info));
		return -EINVAL;
	}
	printf("%s, size:%d\n", __func__, info->size);
	addr = malloc(info->size);
	if (!addr)
		return -ENOMEM;
	((struct mm_info *)out_msg)->addr = (unsigned long)addr;
	((struct mm_info *)out_msg)->size = info->size;
	printf("%s, addr:0x%lx\n", __func__, ((struct mm_info *)out_msg)->addr);
	*out_len = sizeof(struct mm_info);
	return 0xa5;
}

int
rpc_mem_free(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct mm_info *info = in_msg;

	if (in_len != sizeof(struct mm_info)) {
		printf("%s, in_len %d invalid\n", __func__, in_len);
		return -EINVAL;
	}
	printf("%s, addr:0x%lx, size:%d\n", __func__, info->addr, info->size);
	free((void *)(info->addr));
	*(int *)out_msg = 0;
	*out_len = sizeof(int);
	return 0x4b;
}

int
rpc_mem_time_out_free(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct mm_info *info = in_msg;

	if (in_len != sizeof(struct mm_info)) {
		printf("%s, in_len %d invalid\n", __func__, in_len);
		return -EINVAL;
	}
	printf("%s, addr:0x%lx, size:%d\n", __func__, info->addr, info->size);
	free((void *)(info->addr));
	*(int *)out_msg = 0;
	*out_len = sizeof(int);

	usleep(3000000);

	return 0x4b;
}

int
rpc_stress_test(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	int i = 0;
	int ret = 0;
	int in = *((int *)in_msg);

	if (!rcdev9) {
		printf("vf_id[%d]stress port rcdev is null\n", vf_id);
		return -ENODEV;
	}

	if (vf_id < 0 || vf_id >= rcdev9->pf_vf_num) {
		printf("pf_vf_num = %d, vf_id = %d is invalid\n", rcdev9->pf_vf_num, vf_id);
		return -EINVAL;
	}

	if (in == 0x4b) {
		printf("test connection\n");
		*(int *)out_msg = 0xb4;
		*out_len = sizeof(int);
		return 0xb4;
	}

	for (i = 0; i < 1000; i++) {
		ret = ipcm_get_remote_pid(rcdev9->rcdev[vf_id], in);
	}
	*(int *)out_msg = ret;
	*out_len = sizeof(int);
	return ret;
}

static int port_hup_handler(struct ipcm_dev *rcdev, void *priv, unsigned int src)
{
	printf("%s, port:%u ctrl-c occurred, do sth...\n", __func__, src);
	/* after use ipcm_set_hup_handler_vfs(), priv changed to ipcm_proxy, will not equal rcdev */
	//assert(rcdev == priv);
	return 0;
}

static int port_server_async_rx_cb(struct ipcm_dev *rcdev, unsigned long packet_id,
		void *message, int message_size, unsigned int src)
{
	printf("%s, recv msg from port:%u, vf_id:%d, len %d, data:%s\n",
		__func__, src, rcdev->id, message_size, (char *)message);
	if (strncmp("port msg from client", message, message_size))
		ipcm_send_message_to_port(rcdev, "port async test FAILED!",
			strlen("port async test FAILED!"), src);
	else
		ipcm_send_message_to_port(rcdev, "port msg from server async",
			strlen("port msg from server async"), src);

	return 0;
}

static int port_server_sync_rx_cb(struct ipcm_dev *rcdev, unsigned long packet_id,
		void *message, int message_size, unsigned int src)
{
	printf("%s, recv msg from port:%u, vf_id:%d, len %d, data:%s\n",
		__func__, src, rcdev->id, message_size, (char *)message);

	ipcm_send_packet_to_port(rcdev, "message from ARM", strlen("message from ARM"), src);

	return 0;
}

IPCM_DECLARE_CALLBACK_FUNC(rpc_perf_test);

static struct rpmsg_rpc_service_set perf_service_table[] = {
		DEF_CALLBACK_PAIR(rpc_perf_test),
		DEF_CALLBACK_PAIR_END,
};
#define PERF_SERVICE_TABLE perf_service_table

int
rpc_perf_test(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	*out_len = in_len;
	memcpy(out_msg, in_msg, in_len);
	return 0x88;
}

void writePidFile(void)
{
	char str[32];
	int pidfile = open("/var/run/ipcm_test.pid", O_WRONLY|O_CREAT|O_TRUNC, 0644);

	if (pidfile < 0) {
		printf("open /var/run/ipcm_test.pid failed:%d\n", pidfile);
		exit(1);
	}

	if (lockf(pidfile, F_TLOCK, 0) < 0) {
		printf("/var/run/ipcm_test.pid locked, some instant may running\n");
		exit(0);
	}

	sprintf(str, "%d\n", getpid());
	write(pidfile, str, strlen(str));
}

int main(int argc, char **argv)
{
	int role = 0;
	int card = 0;
	int loop = 1;
	int test_item;
	struct timeval start;
	struct timeval end;
	unsigned long elapse = 0;
	char devname[PATH_MAX] = {0};
	int thread_num = 1;
	int ch;
	struct ipcm_proxy *rcdev;
	struct ipcm_proxy *rcdev1;
	struct ipcm_proxy *rcdev2;
	struct ipcm_proxy *rcdev3;
	struct ipcm_proxy *rcdev4;
	struct ipcm_proxy *rcdev5;
	struct ipcm_proxy *rcdev6;
	struct ipcm_proxy *rcdev7;
	struct ipcm_proxy *rcdev8;
	int addr;
	int flags = 0;
	int ret;

	opterr = 0;

	printf("***********************ipcm test************************\n");
	while ((ch = getopt(argc, argv, "a:c::r:l::t::")) != -1) {
		switch (ch) {
		case 'c':
			card = atoi(optarg);
			break;
		case 'r':
			role = atoi(optarg);
			break;
		case 'a':
			addr = atoi(optarg);
			break;
		case 'l':
			loop = atoi(optarg);
			break;
		case 't':
			thread_num = atoi(optarg);
			break;
		default:
			printf("unknown opts:%c\n", ch);
			usage();
			break;
		}
	}

	writePidFile();

	//if (daemon(0, 1) != 0) {
	//	printf("daemonize failed!\n");
	//	exit(1);
	//}

	printf("run in card:%d role:%s addr:%d, loop:%d, thread_num:%d\n",
			card, role ? "server" : "client", addr, loop, thread_num);

	ret = ipcm_lib_init();
	if (ret < 0) {
		printf("ipcm_lib_init failed, ret = %d\n", ret);
		return ret;
	}

	//create all endpoints
	snprintf(devname, sizeof(devname), "rpmsg-test-%d", TEST_SYNC_MSG_ADDR);
	rcdev = ipcm_create_endpoint_vfs(TEST_SYNC_MSG_ADDR,
					devname, flags, RPMSG_SERVER);
	if (!rcdev) {
		perror("Can't create sync msg endpoint");
		return -EPERM;
	}
	ipcm_set_sync_mode_vfs(rcdev);

	snprintf(devname, sizeof(devname), "rpmsg-test-%d", TEST_RPC_ADDR);
	rcdev1 = ipcm_create_endpoint_vfs(TEST_RPC_ADDR,
					devname, flags, RPMSG_SERVER);
	if (!rcdev1) {
		perror("Can't create rpc endpoint");
		return -EPERM;
	}
	ipcm_set_rpc_services_vfs(rcdev1, COMMU_SERVICE_TABLE);

	snprintf(devname, sizeof(devname), "rpmsg-test-%d", TEST_PORT_ADDR);
	rcdev2 = ipcm_create_port_vfs(devname, TEST_PORT_ADDR,
					RPMSG_SERVER);
	if (!rcdev2) {
		perror("Can't create async port endpoint");
		return -EPERM;
	}
	ipcm_set_rx_callback_vfs(rcdev2, port_server_async_rx_cb);
	ipcm_set_rpc_services_vfs(rcdev2, COMMU_SERVICE_TABLE);
	ipcm_set_hup_handler_vfs(rcdev2, port_hup_handler, rcdev2);

	snprintf(devname, sizeof(devname), "rpmsg-test-%d", TEST_SYNC_MSG_BREAK_ADDR);
	rcdev3 = ipcm_create_port_vfs(devname, TEST_SYNC_MSG_BREAK_ADDR,
					RPMSG_SERVER);
	if (!rcdev3) {
		perror("Can't create sync msg break endpoint");
		return -EPERM;
	}
	ipcm_set_rx_callback_vfs(rcdev3, port_server_sync_rx_cb);
	ipcm_set_hup_handler_vfs(rcdev3, port_hup_handler, rcdev3);

	snprintf(devname, sizeof(devname), "rpmsg-test-%d", TEST_ASYNC_MSG_ADDR);
	rcdev4 = ipcm_create_endpoint_vfs(TEST_ASYNC_MSG_ADDR,
					devname, flags, RPMSG_SERVER);
	if (!rcdev4) {
		perror("Can't create async msg endpoint");
		return -EPERM;
	}
	ipcm_set_rx_callback_vfs(rcdev4, msg_async_test_rx_cb);

	snprintf(devname, sizeof(devname), "rpmsg-test-%d", TEST_ASYNC_RESP_CB_ADDR);
	rcdev5 = ipcm_create_endpoint_vfs(TEST_ASYNC_RESP_CB_ADDR,
					devname, flags, RPMSG_SERVER);
	if (!rcdev5) {
		perror("Can't create async msg endpoint");
		return -EPERM;
	}
	ipcm_set_rx_callback_vfs(rcdev5, test_with_resp_callback_rx_cb);

	snprintf(devname, sizeof(devname), "rpmsg-test-%d", TEST_PERF_RPC_ADDR);
	rcdev6 = ipcm_create_endpoint_vfs(TEST_PERF_RPC_ADDR,
					devname, flags, RPMSG_SERVER);
	if (!rcdev6) {
		perror("Can't create perf endpoint");
		return -EPERM;
	}
	ipcm_set_rpc_services_vfs(rcdev6, PERF_SERVICE_TABLE);

	snprintf(devname, sizeof(devname), "rpmsg-test-%d", TEST_SYNC_PORT_ADDR);
	rcdev7 = ipcm_create_port_vfs(devname, TEST_SYNC_PORT_ADDR,
					RPMSG_SERVER);
	if (!rcdev7) {
		perror("Can't create sync port endpoint");
		return -EPERM;
	}
	ipcm_set_rx_callback_vfs(rcdev7, port_server_sync_rx_cb);
	ipcm_set_hup_handler_vfs(rcdev7, port_hup_handler, rcdev7);

	snprintf(devname, sizeof(devname), "rpmsg-cross-test-%d", TEST_KERN2USER_ADDR);
	rcdev8 = ipcm_create_endpoint_vfs(TEST_KERN2USER_ADDR,
					devname, 0, RPMSG_SERVER);
	if (!rcdev8) {
		perror("Can't create kern2user endpoint");
		return -EPERM;
	}
	ipcm_set_rx_callback_vfs(rcdev8, kernel_to_user_rx_cb);
	ipcm_set_rpc_services_vfs(rcdev8, COMMU_SERVICE_TABLE);

	snprintf(devname, sizeof(devname), "rpmsg-stress-test-%d", TEST_STRESS_PORT_ADDR);
	rcdev9 = ipcm_create_endpoint_vfs(TEST_STRESS_PORT_ADDR,
					devname, 0, RPMSG_SERVER);
	if (!rcdev9) {
		perror("Can't create kern2user endpoint");
		return -EPERM;
	}
	ipcm_set_rx_callback_vfs(rcdev9, kernel_to_user_rx_cb);
	ipcm_set_rpc_services_vfs(rcdev9, COMMU_SERVICE_TABLE);

	printf("ipcm_test env setup ok..\n");

	msg_sync_test(rcdev, role, loop, thread_num);

	while (true) {
		sleep(5);
	}

	//destroy all endpoints
	ipcm_destroy_endpoint_vfs(rcdev);
	ipcm_destroy_endpoint_vfs(rcdev1);
	ipcm_destroy_endpoint_vfs(rcdev2);
	ipcm_destroy_endpoint_vfs(rcdev3);
	ipcm_destroy_endpoint_vfs(rcdev4);
	ipcm_destroy_endpoint_vfs(rcdev5);
	ipcm_destroy_endpoint_vfs(rcdev6);
	ipcm_destroy_endpoint_vfs(rcdev7);
	ipcm_destroy_endpoint_vfs(rcdev8);
	ipcm_destroy_endpoint_vfs(rcdev9);

	ipcm_lib_exit();
	return 0;
}
