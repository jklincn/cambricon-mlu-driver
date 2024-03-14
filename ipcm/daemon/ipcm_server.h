
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
#include <stdint.h>


#define IPCM_DAEMON_PORT (0xcabc)

/* File Operations System call definitions */
#define OPEN_SYSCALL_ID  0x1UL
#define CLOSE_SYSCALL_ID 0x2UL
#define WRITE_SYSCALL_ID 0x3UL
#define READ_SYSCALL_ID  0x4UL
#define ACK_STATUS_ID    0x5UL
#define TERM_SYSCALL_ID  0x6UL

struct rpmsg_rpc_syscall_header {
	int int_field1;
	int int_field2;
	unsigned int data_len;
};

struct rpmsg_rpc_syscall {
	unsigned int id;
	struct rpmsg_rpc_syscall_header args;
};

struct rpmsg_rpc_args {
	unsigned long mlu_addr;
	unsigned long cpu_addr;
	size_t len;
	char filename[256];
};

struct rpmsg_rpc_ret {
	unsigned long mlu_addr;
	unsigned long cpu_addr;
	size_t len;
	int ret;
};
