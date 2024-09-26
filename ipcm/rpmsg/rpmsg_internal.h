/* SPDX-License-Identifier: GPL-2.0 */
/*
 * remote processor messaging bus internals
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 * Copyright (C) 2011 Google, Inc.
 *
 * Ohad Ben-Cohen <ohad@wizery.com>
 * Brian Swetland <swetland@google.com>
 */

#ifndef __RPMSG_INTERNAL_H__
#define __RPMSG_INTERNAL_H__

#include "../include/rpmsg/rpmsg.h"
#include <linux/poll.h>
#include <linux/device.h>

#include "../include/ipcm_common.h"

extern int ipcm_record;
extern int ipcm_record_index;

struct ipcm_perf_test_info {
	u64 perf_dev_iova;
	int test_cnt;
	int record_en;
};
struct ipcm_timestamp_info {
	u64 rpc_in_ns;
	u64 get_tx_buf_ns;
	u64 kick_mbox_ns;
	u64 remote_recv_buf_ns;
	u64 remote_real_cb_end_ns;
	u64 remote_get_tx_buf_ns;
	u64 remote_kick_mbox_ns;
	u64 recv_buf_ns;
	u64 ept_cb_end_ns;
	u64 rpc_out_ns;
};

#ifdef IN_CNDRV_HOST
#include "cndrv_core.h"
#include "cndrv_mm.h"
#include "cndrv_monitor.h"

extern struct ipcm_timestamp_info *perf_host_kva;
#endif

enum ipcm_packet_source {
	RPMSG_IPC_PACKET_SOURCE_SERVER,
	RPMSG_IPC_PACKET_SOURCE_CLIENT,
	RPMSG_IPC_PACKET_SOURCE_MAX,
};

enum ipcm_packet_type {
	RPMSG_IPC_PACKET_TYPE_REQUEST,
	RPMSG_IPC_PACKET_TYPE_RESPONSE,
	RPMSG_IPC_PACKET_TYPE_MESSAGE,
	RPMSG_IPC_PACKET_TYPE_RPC,
	RPMSG_IPC_PACKET_TYPE_RPC_RET,
	RPMSG_IPC_PACKET_TYPE_HUP,
	RPMSG_IPC_PACKET_TYPE_RPC_ASYNC,
	RPMSG_IPC_PACKET_TYPE_MAX,
};

/*RPMSG_KDRV message :
 * => device_header
 * => message_header : defined by each device type
 * => request / response / message payload
 */
struct ipcm_device_header {
	/* enum: ipcm_packet_type */
	u8 packet_type;
	/* enum: ipcm_packet_source */
	u8 packet_source;
	/* size of packet */
	u32 packet_size;
	/* rpc function return value */
	int32_t rpc_ret_val;
	/* response or rpc real return size */
	u32 real_size;
	/* rpc function name hash only if packet_type is RPMSG_IPC_PACKET_TYPE_RPC */
	u64 func_name;
	/* user package src ept addr */
	u32 src;
	union {
		/* uapi: ctx ptr for response matching */
		u64 ctx;
		/* kapi: dynamically assigned packet ID for response matching */
		u32 packet_id;
	};
} __attribute__((__packed__));

/* The feature bitmap for virtio rpmsg */
#define VIRTIO_RPMSG_F_NS	0 /* RP supports name service notifications */
#define VIRTIO_RPMSG_F_AS	1 /* RP supports address service notifications */

/**
 * struct rpmsg_hdr - common header for all rpmsg messages
 * @src: source address
 * @dst: destination address
 * @reserved: reserved for future use
 * @len: length of payload (in bytes)
 * @flags: message flags
 * @data: @len bytes of message payload data
 *
 * Every message sent(/received) on the rpmsg bus begins with this header.
 */
struct rpmsg_hdr {
	u32 src;
	u32 dst;
	u32 reserved;
	u16 len;
	u16 flags;
	u8 data[0];
} __attribute__((__packed__));

/**
 * struct rpmsg_ns_msg - dynamic name service announcement message
 * @name: name of remote service that is published
 * @addr: address of remote service that is published
 * @flags: indicates whether service is created or destroyed
 *
 * This message is sent across to publish a new service, or announce
 * about its removal. When we receive these messages, an appropriate
 * rpmsg channel (i.e device) is created/destroyed. In turn, the ->probe()
 * or ->remove() handler of the appropriate rpmsg driver will be invoked
 * (if/as-soon-as one is registered).
 */
struct rpmsg_ns_msg {
	char name[RPMSG_NAME_SIZE];
	u32 addr;
	u32 flags;
} __attribute__((__packed__));

/**
 * struct rpmsg_ns_msg - dynamic name service announcement message V2
 * @name: name of remote service that is published
 * @desc: description of remote service
 * @addr: address of remote service that is published
 * @flags: indicates whether service is created or destroyed
 *
 * This message is sent across to publish a new service, or announce
 * about its removal. When we receive these messages, an appropriate
 * rpmsg channel (i.e device) is created/destroyed. In turn, the ->probe()
 * or ->remove() handler of the appropriate rpmsg driver will be invoked
 * (if/as-soon-as one is registered).
 */
struct rpmsg_ns_msg_ext {
	char name[RPMSG_NAME_SIZE];
	u32 addr;
	u32 flags;
	char desc[RPMSG_NAME_SIZE];
} __attribute__((__packed__));

/**
 * struct rpmsg_as_msg - dynamic address service announcement message
 * @name: name of the created channel
 * @dst: destination address to be used by the backend rpdev
 * @src: source address of the backend rpdev (the one that sent name service
 * announcement message)
 * @flags: indicates whether service is created or destroyed
 *
 * This message is sent (by virtio_rpmsg_bus) when a new channel is created
 * in response to name service announcement message by backend rpdev to create
 * a new channel. This sends the allocated source address for the channel
 * (destination address for the backend rpdev) to the backend rpdev.
 */
struct rpmsg_as_msg {
	char name[RPMSG_NAME_SIZE];
	u32 dst;
	u32 src;
	u32 flags;
} __attribute__((__packed__));

/**
 * enum rpmsg_ns_flags - dynamic name service announcement flags
 *
 * @RPMSG_NS_CREATE: a new remote service was just created
 * @RPMSG_NS_DESTROY: a known remote service was just destroyed
 */
enum rpmsg_ns_flags {
	RPMSG_NS_CREATE		= 0,
	RPMSG_NS_DESTROY	= 1,
	RPMSG_AS_ANNOUNCE	= 2,
};

/**
 * enum rpmsg_as_flags - dynamic address service announcement flags
 *
 * @RPMSG_AS_ASSIGN: address has been assigned to the newly created channel
 * @RPMSG_AS_FREE: assigned address is freed from the channel and no longer can
 * be used
 */
enum rpmsg_as_flags {
	RPMSG_AS_ASSIGN		= 1,
	RPMSG_AS_FREE		= 2,
};

/*
 * We're allocating buffers of 512 bytes each for communications. The
 * number of buffers will be computed from the number of buffers supported
 * by the vring, upto a maximum of 512 buffers (256 in each direction).
 *
 * Each buffer will have 16 bytes for the msg header and 496 bytes for
 * the payload.
 *
 * This will utilize a maximum total space of 256KB for the buffers.
 *
 * We might also want to add support for user-provided buffers in time.
 * This will allow bigger buffer size flexibility, and can also be used
 * to achieve zero-copy messaging.
 *
 * Note that these numbers are purely a decision of this driver - we
 * can change this without changing anything in the firmware of the remote
 * processor.
 */
#define MAX_RPMSG_NUM_BUFS	(512)

/*
 * Local addresses are dynamically allocated on-demand.
 * We do not dynamically assign addresses from the low 1024 range,
 * in order to reserve that address range for predefined services.
 */
#define RPMSG_RESERVED_ADDRESSES	(1024)
#define RPMSG_RESERVED_ADDRESSES_END (65535)

/* Address 53 is reserved for advertising remote services */
#define RPMSG_NS_ADDR			(53)

/* Address 54 is reserved for advertising address services */
#define RPMSG_AS_ADDR			(54)

/* Address 55 is reserved for advertising vf state services */
#define RPMSG_VS_ADDR			(55)
#define VS_CHANNEL_NAME "vf_state_srvc"

/* Address 56 is reserved for advertising log to host services */
#define RPSMG_LOG_ADDR          (56)
#define RPSMG_LOG_CHANNEL_NAME "ipcm-rpc-log"

/* Address 57 is reserved for advertising perf record services */
#define RPMSG_REC_ADDR          (57)
#define RPSMG_REC_CHANNEL_NAME "ipcm_perf_record"

/* Address 58 is reserved for codec query port tgid services */
#define RPMSG_QUERY_PORT_ADDR   (58)
#define RPSMG_QUERY_PORT_NAME "ipcm_port_query"

#define to_rpmsg_device(d) container_of(d, struct rpmsg_device, dev)
#define to_rpmsg_driver(d) container_of(d, struct rpmsg_driver, drv)

/**
 * struct rpmsg_device_ops - indirection table for the rpmsg_device operations
 * @create_ept:		create backend-specific endpoint, required
 * @announce_create:	announce presence of new channel, optional
 * @announce_destroy:	announce destruction of channel, optional
 *
 * Indirection table for the operations that a rpmsg backend should implement.
 * @announce_create and @announce_destroy are optional as the backend might
 * advertise new channels implicitly by creating the endpoints.
 */
struct rpmsg_device_ops {
	struct rpmsg_endpoint *(*create_ept)(struct rpmsg_device *rpdev,
					    rpmsg_rx_cb_t cb, void *priv,
					    struct rpmsg_channel_info chinfo);

	int (*announce_create)(struct rpmsg_device *ept);
	int (*announce_destroy)(struct rpmsg_device *ept);
};

/**
 * struct rpmsg_endpoint_ops - indirection table for rpmsg_endpoint operations
 * @destroy_ept:	see @cn_rpmsg_destroy_ept(), required
 * @send:		see @cn_rpmsg_send(), required
 * @sendto:		see @cn_rpmsg_sendto(), optional
 * @send_offchannel:	see @cn_rpmsg_send_offchannel(), optional
 * @trysend:		see @cn_rpmsg_trysend(), required
 * @trysendto:		see @cn_rpmsg_trysendto(), optional
 * @trysend_offchannel:	see @cn_rpmsg_trysend_offchannel(), optional
 * @poll:		see @cn_rpmsg_poll(), optional
 *
 * Indirection table for the operations that a rpmsg backend should implement.
 * In addition to @destroy_ept, the backend must at least implement @send and
 * @trysend, while the variants sending data off-channel are optional.
 */
struct rpmsg_endpoint_ops {
	void (*destroy_ept)(struct rpmsg_endpoint *ept);

	int (*send)(struct rpmsg_endpoint *ept, void *data, int len);
	int (*sendto)(struct rpmsg_endpoint *ept, void *data, int len, u32 dst);
	int (*send_offchannel)(struct rpmsg_endpoint *ept, u32 src, u32 dst,
				  void *data, int len);

	int (*trysend)(struct rpmsg_endpoint *ept, void *data, int len);
	int (*trysendto)(struct rpmsg_endpoint *ept, void *data, int len, u32 dst);
	int (*trysend_offchannel)(struct rpmsg_endpoint *ept, u32 src, u32 dst,
			     void *data, int len);
	__poll_t (*poll)(struct rpmsg_endpoint *ept, struct file *filp,
			     poll_table *wait);
};

int cn_rpmsg_register_device(struct rpmsg_device *rpdev);
int cn_rpmsg_unregister_device(struct device *parent,
			    struct rpmsg_channel_info *chinfo);

struct device *cn_rpmsg_find_device(struct device *parent,
				 struct rpmsg_channel_info *chinfo);

/**
 * rpmsg_chrdev_register_device() - register chrdev device based on rpdev
 * @rpdev:	prepared rpdev to be used for creating endpoints
 *
 * This function wraps cn_rpmsg_register_device() preparing the rpdev for use as
 * basis for the rpmsg chrdev.
 */
static inline int rpmsg_chrdev_register_device(struct rpmsg_device *rpdev)
{
	strncpy(rpdev->id.name, "rpmsg_chrdev", RPMSG_NAME_SIZE);
	rpdev->driver_override = "rpmsg_chrdev";

	return cn_rpmsg_register_device(rpdev);
}
#endif
