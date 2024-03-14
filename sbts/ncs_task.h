/*
 * sbts/ncs_task.h
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef __SBTS_NCS_TASK_H
#define __SBTS_NCS_TASK_H

#define C2C_KEY_SIZE 8
struct cd_create_qp {
	__u32 clique;
	__u32 port_id;
	__u32 type;
	__u64 qp;
	__u64 key[C2C_KEY_SIZE];
};

struct cd_modify_qp {
        __u64 qp;
	__u64 rqp;
	__u64 rkey[C2C_KEY_SIZE];
};

enum ncs_cmd_type {
	NCS_GET_TOPO = 0,
	NCS_CREATE_QP,
	NCS_MODIFY_QP,
	NCS_DESTROY_QP,
	NCS_CREATE_TEMPLATE,
	NCS_DESTROY_TEMPLATE,
	NCS_ABORT_TASK,
	NCS_DESTROY_RESOURCE,
	NCS_UPDOWN_LINK,
	NCS_GET_BER,
	NCS_PORT_CTRL,
	NCS_GET_ATTR,
	NCS_CMD_CNT,
};

static char *ncs_cmd_name[NCS_CMD_CNT] = {
	"NCS_GET_TOPO",
	"NCS_CREATE_QP",
	"NCS_MODIFY_QP",
	"NCS_DESTROY_QP",
	"NCS_CREATE_TEMPLATE",
	"NCS_DESTROY_TEMPLATE",
	"NCS_ABORT_TASK",
	"NCS_DESTROY_RESOURCE",
	"NCS_UPDOWN_LINK",
	"NCS_GET_BER",
	"NCS_PORT_CTRL",
	"NCS_GET_ATTR",
};

#endif /* __SBTS_NCS_TASK_H */
