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
#include <stdbool.h>
#include <errno.h>
#include "cn_api.h"
#include "ipcm_server.h"

#include "ipcm.h"

static CNdev device;

static int ipcm_server_cmd_cb(struct ipcm_dev *rcdev, unsigned long packet_id,
		void *message, int message_size, unsigned int src)
{
	FILE *fp = NULL;
	char temp_line[MAX_BUF_LEN] = {0};
	int ret = 0;

	snprintf(temp_line, (message_size < sizeof(temp_line)) ? message_size : sizeof(temp_line), "%s", message);
	/* message_size - 1 = '\0' */
	if (temp_line[message_size - 2] != '&') {
		if (strlen(temp_line) + strlen(" 2>&1") + 1 < sizeof(temp_line))
			strcat(temp_line, " 2>&1");
		printf("the real command : %s\n", temp_line);
		fp = popen(temp_line, "r");
		if (fp == NULL) {
			printf("\n ! error ! popen execute error.\n");
			return -EPERM;
		}

		while (memset(temp_line, 0, sizeof(temp_line)), fgets(temp_line, sizeof(temp_line), fp) != NULL) {
			ret = ipcm_send_message_to_port(rcdev, temp_line, strlen(temp_line) + 1, src);
			if (ret < 0)
				goto out;
		}
	} else {
		printf("bg command : %s\n", message);
		system(message);
	}

	ret = 0;
out:
	ipcm_send_response_to_port(rcdev, packet_id, "\n", strlen("\n"), src);
	if (fp)
		pclose(fp);
	return ret;
}

IPCM_DECLARE_CALLBACK_FUNC(rpc_syscall_open);
IPCM_DECLARE_CALLBACK_FUNC(rpc_syscall_read);
IPCM_DECLARE_CALLBACK_FUNC(rpc_syscall_write);
IPCM_DECLARE_CALLBACK_FUNC(rpc_syscall_close);
IPCM_DECLARE_CALLBACK_FUNC(rpc_get_file_size);
IPCM_DECLARE_CALLBACK_FUNC(rpc_writeFile);
IPCM_DECLARE_CALLBACK_FUNC(rpc_readFile);

static struct rpmsg_rpc_service_set service_table[] = {
		DEF_CALLBACK_PAIR(rpc_syscall_open),
		DEF_CALLBACK_PAIR(rpc_syscall_read),
		DEF_CALLBACK_PAIR(rpc_syscall_write),
		DEF_CALLBACK_PAIR(rpc_syscall_close),
		DEF_CALLBACK_PAIR(rpc_get_file_size),
		DEF_CALLBACK_PAIR(rpc_writeFile),
		DEF_CALLBACK_PAIR(rpc_readFile),
		DEF_CALLBACK_PAIR_END,
};
#define COMMU_SERVICE_TABLE service_table

/**
 * is_directory - Check if the path is a directory
 *  @path:
 *  @returns: zero on success
 */
static int is_directory(const char *path)
{
	int res;
	struct stat st;

	if (!path)
		return -EINVAL;

	/*get file or directory attribute*/
	res = stat(path, &st);
	if (res) {
		printf("%s, stat exec fail, errno %d, %s\n",
			__func__, errno, strerror(errno));
		return -errno;
	}

	if (!(st.st_mode & S_IFDIR))
		return -ENOTDIR;

	return 0;
}

/**
 * is_file - Check if the path is a file
 *  @path:
 *  @returns: zero on success
 */
static int is_file(const char *path)
{
	int res;
	struct stat st;

	if (!path)
		return -EINVAL;

	/*get file or directory attribute*/
	res = stat(path, &st);
	if (res) {
		printf("%s, stat exec fail, errno %d, %s\n",
			__func__, errno, strerror(errno));
		return -errno;
	}

	if (!(st.st_mode & S_IFREG)) {
		printf("%s, %s is not a file\n", __func__, path);
		return -ENOENT;
	}

	return 0;
}

/**
 *  get_file_size - get file size
 *  @path:
 *  @returns: file size on success, errno on failure
 */
static int get_file_size(const char *path, int *size)
{
	int res;
	struct stat st;

	if (!path)
		return -EINVAL;

	/*get file attribute*/
	res = stat(path, &st);
	if (res) {
		printf("%s, stat exec fail, errno %d, %s\n",
			__func__, errno, strerror(errno));
		return -errno;
	}

	if (!(st.st_mode & S_IFREG)) {
		printf("%s, %s is not a file\n", __func__, path);
		return -ENOENT;
	}

	*size = st.st_size;

	return 0;
}

/**
 *  read file - read file data and copy to cnrt memory.
 *  @file: file path
 *  @buf:  pointer to cnrt memory.
 *  @size: cnrt memroy buffer size.
 *  @returns: zero on success, errno on failure.
 */
static unsigned long read_file(char *file, unsigned char *buf, unsigned long size)
{
	int fd;
	int nread;
	int remain;
	int res = 0;
	unsigned char *ptr = buf;

	if (!buf || !file || size <= 0)
		return -EINVAL;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		printf("%s, open %s fail, errno %d, %s\n",
			__func__, file, errno, strerror(errno));
		return -errno;
	}

	remain = size;
	do {
		nread = read(fd, ptr, remain);
		if (nread < 0) {
			printf("%s, read %s fail, errno %d, %s\n",
			__func__, file, errno, strerror(errno));
			res = -errno;
			break;
		} else if (nread > 0) {
			ptr += nread;
			remain -= nread;
		} else {
			break;
		}
	} while (remain > 0);

	if (fd > 0)
		close(fd);

	return res;
}

/**
 *  write_file
 *  @file:      file path
 *  @buf:       Point to the file data buf
 *  @size:        buf size
 *  @returns:     zero on success or errno on failure
 */
static int write_file(char *file, unsigned char *buf, unsigned long size)
{
	int fd = 0;
	int nwrite;
	unsigned long remain;
	int res = 0;
	unsigned char *ptr = buf;

	if (!file || !buf || (size <= 0))
		return -EINVAL;

	/*open file*/
	fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd < 0) {
		printf("%s, open %s fail, errno %d, %s\n",
			__func__, file, errno, strerror(errno));
		res = -errno;
		goto done;
	}

	remain = size;
	do {
		/*write file data to file*/
		nwrite = write(fd, ptr, remain);
		if (nwrite < 0) {
			printf("%s, write %s fail, errno %d, %s\n",
			__func__, file, errno, strerror(errno));
			res = -errno;
			goto done;
		}
		remain -= nwrite;
		ptr += nwrite;
	} while (remain > 0);

done:
	if (fd > 0)
		close(fd);
	return res;
}

/*
 * send file:
 * 1. host cnrtMalloc mlu_addr
 * 2. host read file to buffer
 * 3. host buffer dma to mlu_addr(H2D)
 * 4. host rpc write file: a. cnrtMmap mlu_addr to uva, b. buffer write to file c. cnrtMunmap cnrtFree
 */
int rpc_writeFile(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct rpmsg_rpc_args *req = (struct rpmsg_rpc_args *)in_msg;
	struct rpmsg_rpc_ret *resp = (struct rpmsg_rpc_ret *)out_msg;
	void *cpu_addr = NULL;
	CNcontext context;
	int ret = CN_SUCCESS;

	ret = cnCtxCreate(&context, 0, device);
	if (ret != CN_SUCCESS) {
		fprintf(stderr, "cnCtxCreate failed with %d.\n", ret);
		goto out;
	}

	ret = cnMmapCached(req->mlu_addr, &cpu_addr, req->len);
	if (ret != CN_SUCCESS) {
		fprintf(stderr, "cnMmap failed with %d.\n", ret);
		goto failed;
	}

	ret = write_file(req->filename, cpu_addr, req->len);
	if (ret < 0)
		fprintf(stderr, "save to file:%s failed.\n", req->filename);

	ret = cnMunmap(cpu_addr, req->len);
	if (ret != CN_SUCCESS) {
		fprintf(stderr, "cnMunmap failed with %d.\n", ret);
	}

failed:
	cnCtxDestroy(context);

out:
	/* Construct rpc response */
	resp->ret = ret;
	*out_len = sizeof(*resp);
	return ret;
}

/*
 * recv file:
 * 1. host rpc get file size then malloc buffer & cnrtMalloc
 * 2. host rpc read file to buffer
 * 3. host buffer dma to buffer(D2H), write buffer to file
 */

int rpc_get_file_size(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct rpmsg_rpc_args *req = (struct rpmsg_rpc_args *)in_msg;
	struct rpmsg_rpc_ret *resp = (struct rpmsg_rpc_ret *)out_msg;
	size_t len = 0;
	int ret = 0;

	ret = get_file_size(req->filename, (int *)&len);

	resp->len = len;
	resp->ret = ret;
	*out_len = sizeof(*resp);
	return ret;
}

int rpc_readFile(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct rpmsg_rpc_args *req = (struct rpmsg_rpc_args *)in_msg;
	struct rpmsg_rpc_ret *resp = (struct rpmsg_rpc_ret *)out_msg;
	CNaddr mlu_addr;
	void *cpu_addr = NULL;
	size_t len = 0;
	CNcontext context;
	int ret = CN_SUCCESS;

	ret = cnCtxCreate(&context, 0, device);
	if (ret != CN_SUCCESS) {
		fprintf(stderr, "cnCtxCreate failed with %d.\n", ret);
		goto out;
	}

	ret = cnMmap((CNaddr)req->mlu_addr, &cpu_addr, req->len);
	if (ret != CN_SUCCESS) {
		fprintf(stderr, "cnMmap failed with %d.\n", ret);
		goto failed;
	}

	ret = read_file(req->filename, cpu_addr, req->len);
	if (ret < 0) {
		fprintf(stderr, "read file:%s failed.\n", req->filename);
	} else {
		ret = 0;
	}
	cnCacheOperation((CNaddr)req->mlu_addr, cpu_addr, len, CN_FLUSH_CACHE);

	cnMunmap(cpu_addr, req->len);

failed:
	cnCtxDestroy(context);
out:
	/* Construct rpc response */
	resp->ret = ret;
	*out_len = sizeof(*resp);
	return ret;
}

int rpc_syscall_open(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct rpmsg_rpc_syscall *syscall = (struct rpmsg_rpc_syscall *)in_msg;
	struct rpmsg_rpc_syscall *resp = (struct rpmsg_rpc_syscall *)out_msg;
	char *filename;
	int fd;

	if (syscall->id != OPEN_SYSCALL_ID)
		return -EINVAL;

	filename = in_msg + sizeof(*syscall);
	//printf("open file:%s\n", filename);

	fd = open(filename, syscall->args.int_field1, syscall->args.int_field2);
	/* Construct rpc response */
	resp->id = OPEN_SYSCALL_ID;
	resp->args.int_field1 = fd;
	resp->args.int_field2 = 0;	/*not used */
	resp->args.data_len = 0;	/*not used */
	*out_len = sizeof(*resp);
	return fd;
}

int rpc_syscall_close(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct rpmsg_rpc_syscall *syscall = (struct rpmsg_rpc_syscall *)in_msg;
	struct rpmsg_rpc_syscall *resp = (struct rpmsg_rpc_syscall *)out_msg;
	int ret;

	if (syscall->id != CLOSE_SYSCALL_ID)
		return -EINVAL;

	//printf("close fd:%d\n",  syscall->args.int_field1);

	ret = close(syscall->args.int_field1);
	/* Construct rpc response */
	resp->id = CLOSE_SYSCALL_ID;
	resp->args.int_field1 = ret;
	resp->args.int_field2 = 0;	/*not used */
	resp->args.data_len = 0;	/*not used */
	*out_len = sizeof(*resp);
	return ret;
}

int rpc_syscall_read(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct rpmsg_rpc_syscall *syscall = (struct rpmsg_rpc_syscall *)in_msg;
	struct rpmsg_rpc_syscall *resp = (struct rpmsg_rpc_syscall *)out_msg;
	unsigned char *buf;
	int bytes_read;

	if (syscall->id != READ_SYSCALL_ID)
		return -EINVAL;

	buf = (unsigned char *)resp;
	buf += sizeof(*resp);
	bytes_read = read(syscall->args.int_field1, buf,
				  syscall->args.int_field2);

	/* Construct rpc response */
	resp->id = READ_SYSCALL_ID;
	resp->args.int_field1 = bytes_read;
	resp->args.int_field2 = 0;	/* not used */
	resp->args.data_len = bytes_read;

	*out_len = sizeof(*resp) +
			   ((bytes_read > 0) ? bytes_read : 0);

	return bytes_read;
}

int rpc_syscall_write(void *in_msg, int in_len, void *out_msg, int *out_len, int vf_id)
{
	struct rpmsg_rpc_syscall *syscall = (struct rpmsg_rpc_syscall *)in_msg;
	struct rpmsg_rpc_syscall *resp = (struct rpmsg_rpc_syscall *)out_msg;
	unsigned char *buf;
	int bytes_written;

	if (syscall->id != WRITE_SYSCALL_ID)
		return -EINVAL;

	buf = (unsigned char *)syscall;
	buf += sizeof(*syscall);
	/* Write to remote fd */
	bytes_written = write(syscall->args.int_field1, buf,
				  syscall->args.int_field2);

	/* Construct rpc response */
	resp->id = WRITE_SYSCALL_ID;
	resp->args.int_field1 = bytes_written;
	resp->args.int_field2 = 0;	/*not used */
	resp->args.data_len = 0;	/*not used */

	*out_len = sizeof(*resp);

	return bytes_written;
}

int main(int argc, char **argv)
{
	char eptname[PATH_MAX] = {0};
	struct ipcm_proxy *rcdev;
	int device_count = 0;
	int ret = 0;

	ret = ipcm_lib_init();
	if (ret) {
		printf("ipcm_lib_init failed, ret = %d\n", ret);
		return ret;
	}

	/* cn Init*/
	if (cnInit(0)) {
		printf("Init cndrv error\n");
		return -ENODEV;
	}
	/* get mlu device count*/
	cnDeviceGetCount(&device_count);
	if (device_count == 0) {
		printf("no mlu device can use\n");
		return -ENODEV;
	}
	/* get mlu0 device handle*/
	if (cnDeviceGet(&device, 0) != CN_SUCCESS) {
		printf("can't get mlu device\n");
		return -ENODEV;
	}

	/*
	 * Open the remote rpmsg device identified by dev_name and bind the
	 * device to a local end-point used for receiving messages from
	 * remote processor
	 */
	snprintf(eptname, sizeof(eptname), "ipcm_server-%d", getpid());
	rcdev = ipcm_create_endpoint_vfs(IPCM_DAEMON_PORT,
				eptname, 0, RPMSG_SERVER);
	if (!rcdev) {
		perror("Can't create ipcm_server endpoint device");
		return -EPERM;
	}
	//printf("running %s, fd = %d port = %d\n", eptname,
	//	rcdev->fd, rcdev->endpt);

	ipcm_set_rpc_services_vfs(rcdev, COMMU_SERVICE_TABLE);
	ipcm_set_rx_callback_vfs(rcdev, ipcm_server_cmd_cb);

	/* make us as a daemon */
	while (true) {
		sleep(5);
	}
	ret = ipcm_destroy_endpoint_vfs(rcdev);
	if (ret < 0)
		perror("ipcm_server Can't delete the endpoint device\n");

	ipcm_lib_exit();
	fprintf(stderr, "ipcm_server exited!\n");
}
