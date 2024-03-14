
/*
 * sbts/ncs.c
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
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/signal.h>
#include <linux/kthread.h>
#include <linux/llist.h>
#include <linux/delay.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_domain.h"
#include "cndrv_ioctl.h"
#include "cndrv_commu.h"
#include "cndrv_xid.h"
#include "cndrv_ipcm.h"

struct ncs_set {
	struct cn_core_set *core_set;
	struct rpmsg_device *rpdev;
};

struct info_desc {
	__u64 magic;
	__u64 size;
	__u64 rqp_id;
	__u64 data[0];
};

#define NCS_QP_CARD_ID(qp)	(((qp) >> 60) & 0xf)

static int ncs_qp_info_deliver(struct rpmsg_device *rpdev, unsigned long packet_id,
		void *data, int len, void *priv, u32 src)
{
	struct info_desc *desc = (struct info_desc *)data;
	u32 card_id = (u32)NCS_QP_CARD_ID(desc->rqp_id);
	struct cn_core_set *core = NULL;
	struct ncs_set *ncs_ctrl = NULL;
	int ret = 0;

	core = cn_bus_get_core_set_via_card_id(card_id);
	if (!core) {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "card[%d] state is invalid", card_id);
		return 0;
	}
	ncs_ctrl = (struct ncs_set *)core->ncs_set;
	ret = ipcm_send_message(ncs_ctrl->rpdev, data, len);
	return 0;
}

extern int linear_bar_info_init(struct cn_core_set *core);
extern int linear_bar_info_exit(struct cn_core_set *core);

int cn_ncs_late_init(struct cn_core_set *core)
{
	struct ncs_set *ncs_ctrl = NULL;
	//struct cn_bus_set *bus = core->bus_set;
	struct rpmsg_device *ncs_rpdev = NULL;

	if (core->device_id != MLUID_580) {
	    return 0;
	}

	cn_bus_tcdp_qp0_wrhost_enable(core->bus_set);

	ncs_ctrl = cn_kzalloc(sizeof(*ncs_ctrl), GFP_KERNEL);
	if (!ncs_ctrl) {
		cn_xid_err(core, XID_SW_NOTIFY_ERR, "kmalloc commu_set failed");
		return -1;
	}

	ncs_rpdev = ipcm_open_channel(core, "ncs_qp_info");
	if (ncs_rpdev == NULL) {
		cn_xid_err(core, XID_RPC_ERR, "ipcm_open_channel(ncs_qp_info) failed");
		cn_kfree(ncs_ctrl);
		return -1;
	}

	ipcm_set_rx_async_callback(ncs_rpdev, ncs_qp_info_deliver);
	ncs_ctrl->core_set = core;
	ncs_ctrl->rpdev = ncs_rpdev;
	core->ncs_set = ncs_ctrl;

	linear_bar_info_init(core);

	return 0;
}

void cn_ncs_late_exit(struct cn_core_set *core)
{
	struct ncs_set *ncs_ctrl = core->ncs_set;

	if (core->device_id != MLUID_580) {
	    return;
	}

	cn_bus_tcdp_qp0_wrhost_disable(core->bus_set);

	if (ncs_ctrl->rpdev)
		ipcm_destroy_channel(ncs_ctrl->rpdev);
	cn_kfree(ncs_ctrl);
	core->ncs_set = NULL;

	linear_bar_info_exit(core);
}
