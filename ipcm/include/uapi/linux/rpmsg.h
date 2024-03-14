/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2016, Linaro Ltd.
 */

#ifndef _UAPI_RPMSG_H_
#define _UAPI_RPMSG_H_

#include <linux/ioctl.h>
#include <linux/types.h>

/**
 * struct rpmsg_endpoint_info - endpoint info representation
 * @name: name of service
 * @src: local address
 * @dst: destination address
 */
struct rpmsg_endpoint_info {
	char name[32];
	__u32 src;
	__u32 dst;
};

struct rpmsg_endpoint_info_V1 {
	char name[32];
	__u32 src;
	__u32 dst;
	__u64 extra_size;
	__u64 extra;
};

struct rpmsg_endpoint_info_V2 {
	char name[32];
	__u32 src;
	__u32 dst;
	__s32 rfd;
};

struct rpmsg_endpoint_info_V3 {
	char name[32];
	__u32 src;
	__u32 dst;
	__s32 rfd;
	__s32 addr;
};

struct ipcm_server_port_msg {
	int port;
	int len;
	void *msg;
};

#define RPMSG_CREATE_EPT_IOCTL        _IOW(0xb5, 0x1, struct rpmsg_endpoint_info)
#define RPMSG_CREATE_EPT_IOCTL_V1     _IOW(0xb5, 0x1, struct rpmsg_endpoint_info_V1)
#define RPMSG_CREATE_EPT_IOCTL_V2     _IOWR(0xb5, 0x1, struct rpmsg_endpoint_info_V2)
#define RPMSG_CREATE_EPT_IOCTL_V3     _IOWR(0xb5, 0x1, struct rpmsg_endpoint_info_V3)
#define RPMSG_DESTROY_EPT_IOCTL       _IO(0xb5, 0x2)
#define RPMSG_SERVER_PORT_SEND_IOCTL  _IOW(0xb5, 0x3, struct ipcm_server_port_msg)
#define RPMSG_READ_BREAK_IOCTL        _IO(0xb5, 0x4)
#define RPMSG_GET_CDEV_NAME_IOCTL     _IOR(0xb5, 0x5, char[32])
#define RPMSG_GET_PORT_PID            _IOWR(0xb5, 0x6, int)
#define RPMSG_GET_DEV_UNIQUE_ID     _IOR(0xb5, 0x7, uint64_t)

#endif
