#include "cndrv_debug.h"
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */



#include <linux/of.h>
#include <linux/io.h>
#include <linux/tty.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/serial.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/kthread.h>
#include <linux/console.h>
#include <linux/tty_flip.h>
#include <linux/semaphore.h>
#include <linux/interrupt.h>
#include <linux/of_device.h>
#include <linux/serial_core.h>
#include <linux/platform_device.h>
#include "log_vuart.h"
#include "cndrv_commu.h"
#include "cndrv_ipcm.h"
#include "cndrv_xid.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif

#define print_crit(fmt, ...)	\
pr_crit("CRIT: vuart: %s@%d: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define print_err(fmt, ...)	\
pr_err("ERR: vuart: %s@%d: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define print_info(fmt, ...)	\
pr_info("INFO: vuart: %s@%d: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define print_info_once(fmt, ...)	\
pr_info_once("INFO: vuart: %s@%d: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define print_debug(fmt, ...)	\
pr_debug("DBG: vuart: %s@%d: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define print_warn(fmt, ...)	\
pr_warn("WARN: vuart: %s@%d: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define vuart_asprintf(fmt, ...)	\
kasprintf(GFP_KERNEL, fmt, ##__VA_ARGS__)

#define vuart_calloc(n, s)		cn_kcalloc(n, s, GFP_KERNEL)
#define vuart_zalloc(s)			cn_kzalloc(s, GFP_KERNEL)
#define vuart_free(s)			cn_kfree(s)

/* the maximum number of vuart port */
#define LOG_VUART_NR		256
#define PORT_VUART		0x7

#define DRV_NAME_PF		"log_vuart_pf"

#define MAX_BUF_SIZE		4096
#define BUF_SIZE		480
#define LOG_CHANNEL_NAME	"log_channel_name"

#define VUART_INIT		0
#define VUART_CHANNEL_OK	1
#define VUART_ENDPOINT_OK	2
#define VUART_RXTHRD_OK		3
#define VUART_PORT_OK		4

#define VUART_REGISTER_PF_FAILED		1
#define VUART_REGISTER_VF_FAILED		2
#define VUART_REGISTER_OK			0

#define	PROTO_LOAD		0x1
#define	PROTO_UNLOAD		0x2
#define	PROTO_DATA		0x4

#define	TX_DATA_OFFSET		0x8
#define	TX_BUF_SIZE		(UART_XMIT_SIZE + TX_DATA_OFFSET)

/*
 * header(8 bytes) + data *
 */
struct vuart_proto_header {
	int type;
};

struct log_vuart_port {
	void *core;
	struct device dev;
	struct uart_port port;
	int opened;
	int status;

	struct commu_channel *channel;
	struct commu_endpoint *uart_ep;
	struct rpmsg_device *ipcm_channel;
	struct task_struct *kdaemon;
	char rx_buf[MAX_BUF_SIZE];
	char tx_buf[UART_XMIT_SIZE];
	char real_tx_buf[TX_BUF_SIZE];

	int idx;
	int pf_idx;
	int vf_idx;
};

static int register_status = 1;
static bool ipcm_enable = false;

static int vuart_tx_buf_transfer(struct log_vuart_port *up, char *buf,
		int len, int type)
{
	struct vuart_proto_header *h;

	if (up) {
		if (len)
			memcpy(up->real_tx_buf + TX_DATA_OFFSET,
					up->tx_buf, len);

		h = (struct vuart_proto_header *) up->real_tx_buf;
		h->type = type;
	}

	return (len + TX_DATA_OFFSET);
}

static int ipcm_send_message_arm(struct log_vuart_port *up,
		char *buf, int len, int type)
{
	int ret;
#define IPCM_WAIT_MSGQ_TIMEOUT   1000
	int time = IPCM_WAIT_MSGQ_TIMEOUT;
	int newlen;

	newlen = vuart_tx_buf_transfer(up, buf, len, type);

	while (--time) {
		ret = ipcm_trysend_message(up->ipcm_channel, up->real_tx_buf, newlen);
		if (ret)
			udelay(100);
		else
			break;
	}

	if (!time) {
		print_err("host doesn't take data out\n");
		return -1;
	}

	return 0;
}

static int log_commu_send_message_arm(struct log_vuart_port *up,
		char *buf, int len, int type)
{
	int ret;
	int newlen;

	newlen = vuart_tx_buf_transfer(up, buf, len, type);
	ret = commu_send_message(up->uart_ep, up->real_tx_buf, newlen);
	if (ret <= 0)
		return -1;

	return ret;
}

static int send_message_arm(struct log_vuart_port *up,
		char *buf, int len, int type)
{
	if (ipcm_enable)
		return ipcm_send_message_arm(up, buf, len, type);
	else
		return log_commu_send_message_arm(up, buf, len, type);
}

static int log_vuart_recv_func(struct log_vuart_port *up, void *data, int len)
{
	struct uart_port *port = &up->port;
	u8 *buf = data;
	u8 *end = data + len;
	unsigned char ch, flag;
	unsigned long flags;
	int opened;

	spin_lock_irqsave(&up->port.lock, flags);
	opened = up->opened;
	spin_unlock_irqrestore(&up->port.lock, flags);

	if (!opened)
		return 0;

	while (buf < end) {
		ch = *buf;
		flag = TTY_NORMAL;
		port->icount.rx++;
		buf++;

#if defined(CN_PRECOMPILE_UART_HANDLE_SYSRQ_CHAR)
		if (uart_handle_sysrq_char(port, ch))
			continue;
#endif

		uart_insert_char(port, 0, 0, ch, flag);
	}

	if (len)
		tty_flip_buffer_push(&port->state->port);

	return 0;
}

static int klog_daemon(void *priv)
{
	int len;
	int ret;
	struct log_vuart_port *up;

	up = (struct log_vuart_port *) priv;

	allow_signal(SIGKILL);
	for (;;) {
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}
		len = 0;
		ret = commu_wait_for_message(up->uart_ep, up->rx_buf, &len);
		if (!ret) {
			print_info("commu wait func exit\n");
			break;
		}
		if (len > 0)
			log_vuart_recv_func(up, up->rx_buf, len);

	}
	for (;;) {
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}
		msleep(20);
	}

	up->kdaemon = NULL;
	return 0;
}

static int rpmsg_log_server_rx_cb(struct rpmsg_device *rpdev, long unsigned int packet_id,
		void *data, int len, void *priv, u32 src)
{
	struct log_vuart_port *vuart;

	vuart = ipcm_get_priv_data(rpdev);
	return log_vuart_recv_func(vuart, data, len);
}

static unsigned int vuart_tx_empty(struct uart_port *port)
{
	return TIOCSER_TEMT;
}

static int vuart_tx_chars(struct log_vuart_port *up, char *pkt, size_t size)
{
	struct uart_port *port = &up->port;
	int ret;

	ret = send_message_arm(up, pkt, size, PROTO_DATA);
	if (!ret)
		port->icount.tx += size;

	return ret;
}

static void vuart_start_tx(struct uart_port *port)
{
	struct log_vuart_port *up =
		container_of(port, struct log_vuart_port, port);
	struct circ_buf *xmit = &port->state->xmit;
	int start, len;

	if (port->x_char) {
		/* Send special char- probale flow control */
		vuart_tx_chars(up, &port->x_char, 1);
		port->x_char = 0;
		port->icount.tx++;
		return;
	}

	len = 0;
	while (!uart_circ_empty(xmit)) {
		up->tx_buf[len] = xmit->buf[xmit->tail];
		xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
		port->icount.tx++;
		len++;
	}

	start = 0;
	while (len != 0) {
		if (!(len / BUF_SIZE)) {
			vuart_tx_chars(up, up->tx_buf + start, len);
			len = 0;
			break;
	}

		vuart_tx_chars(up, up->tx_buf + start, BUF_SIZE);
		len = len - BUF_SIZE;
		start = start + BUF_SIZE;
	}

	if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
		uart_write_wakeup(port);

}

static void vuart_shutdown(struct uart_port *port)
{
	struct log_vuart_port *up =
		container_of(port, struct log_vuart_port, port);
	unsigned long flags;

	spin_lock_irqsave(&up->port.lock, flags);
	up->opened = 0;
	spin_unlock_irqrestore(&up->port.lock, flags);
}

static const char *vuart_type(struct uart_port *port)
{
	return (port->type == PORT_VUART) ? "log-vuart" : NULL;
}

static int vuart_request_port(struct uart_port *port)
{
	/* UARTs always present */
	return 0;
}

static void vuart_config_port(struct uart_port *port, int flags)
{
	port->type = PORT_VUART;
}

static int vuart_verify_port(struct uart_port *port,
				   struct serial_struct *ser)
{
	if ((ser->type != PORT_UNKNOWN) && (ser->type != PORT_VUART))
		return -EINVAL;
	return 0;
}

static void vuart_release_port(struct uart_port *port)
{
}

static void vuart_set_termios(struct uart_port *port,
					struct ktermios *termios,
#if defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,1) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
					const
#endif
					struct ktermios *old)
{

}

static void vuart_break_ctl(struct uart_port *port, int break_state)
{
}

static void vuart_enable_ms(struct uart_port *port)
{
}

static int vuart_startup(struct uart_port *port)
{
	struct log_vuart_port *up =
		container_of(port, struct log_vuart_port, port);
	unsigned long flags;

	spin_lock_irqsave(&up->port.lock, flags);
	up->opened = 1;
	spin_unlock_irqrestore(&up->port.lock, flags);

	return 0;
}

static unsigned int vuart_get_mctrl(struct uart_port *port)
{
	return 0;
}

static void vuart_set_mctrl(struct uart_port *port, unsigned int sigs)
{
}

static void vuart_stop_tx(struct uart_port *port)
{
}

static void vuart_stop_rx(struct uart_port *port)
{
}

/*
 *	Define the basic serial functions we support.
 */
static const struct uart_ops log_vuart_ops = {
	.tx_empty	= vuart_tx_empty,
	.get_mctrl	= vuart_get_mctrl,
	.set_mctrl	= vuart_set_mctrl,
	.start_tx	= vuart_start_tx,
	.stop_tx	= vuart_stop_tx,
	.stop_rx	= vuart_stop_rx,
	.enable_ms	= vuart_enable_ms,
	.break_ctl	= vuart_break_ctl,
	.startup	= vuart_startup,
	.set_termios	= vuart_set_termios,
	.shutdown	= vuart_shutdown,
	.type		= vuart_type,
	.request_port	= vuart_request_port,
	.release_port	= vuart_release_port,
	.config_port	= vuart_config_port,
	.verify_port	= vuart_verify_port,
};

static struct uart_driver log_vuart_pf_driver = {
	.owner		= THIS_MODULE,
	.driver_name	= DRV_NAME_PF,
	.dev_name	= "ttyMS",
	.nr		= LOG_VUART_NR,
};

static int vuart_setup_port(struct log_vuart_port *up, struct cn_core_set *core)
{
	up->idx = core->idx;
	up->pf_idx = core->pf_idx;
	up->vf_idx = core->vf_idx;

	up->port.ops = &log_vuart_ops;
	up->port.flags = UPF_BOOT_AUTOCONF;
	up->port.line = up->idx;
	up->port.type = PORT_VUART;

	return 0;
}

static int vuart_register_port(struct log_vuart_port *up,
		struct cn_core_set *core)
{
	int ret = 0;

	ret = uart_add_one_port(&log_vuart_pf_driver, &up->port);
	if (ret) {
		print_err("add uart pf port pf_idx:%d error\n",
				up->pf_idx);
		return ret;
	}
	up->status = VUART_PORT_OK;
	return ret;
}

__attribute__((unused))
static int vuart_late_init(struct cn_core_set *core)
{
	struct log_vuart_port *up;
	int ret = 0;

	if (register_status != VUART_REGISTER_OK)
		return -EINVAL;

	if (!core) {
		print_err("core is NULL\n");
		return -EINVAL;
	}
	core->vuart_set = NULL;

	ipcm_enable = cn_ipcm_enable(core);

	up = vuart_zalloc(sizeof(struct log_vuart_port));
	if (!up) {
		print_err("alloc vuart error\n");
		return -ENOMEM;
	}
	up->status = VUART_INIT;

	core->vuart_set = up;
	up->core = core;

	if (ipcm_enable) {
		up->ipcm_channel = ipcm_open_channel(core, LOG_CHANNEL_NAME);

		if (!up->ipcm_channel) {
			cn_xid_err(core, XID_RPC_ERR, "ipcm channel open error");
			return -EINVAL;
		}

		ipcm_set_priv_data(up->ipcm_channel, up);
		ipcm_set_rx_callback(up->ipcm_channel, rpmsg_log_server_rx_cb);

	} else {
		up->channel = commu_open_a_channel(LOG_CHANNEL_NAME, core, 0);
		if (!up->channel) {
			cn_xid_err(core, XID_RPC_ERR, "channel open error");
			return -EINVAL;
		}
	}

	up->status = VUART_CHANNEL_OK;

	if (!ipcm_enable) {
		up->uart_ep = connect_msg_endpoint(up->channel);
		if (!up->uart_ep) {
			print_err("connect to endpoint error\n");
			return -EINVAL;
		}
	}

	up->status = VUART_ENDPOINT_OK;

	if (!ipcm_enable) {
		up->kdaemon = kthread_run(klog_daemon, up,
			"vuart-pf%d-vf:%d", core->pf_idx, core->vf_idx);
		if (!up->kdaemon) {
			print_err("create kthread failed\n");
			return -EINVAL;
		}
	} else {
		up->kdaemon = NULL;
	}

	up->status = VUART_RXTHRD_OK;

	/* this uart is not opened util we call uart_startup() */
	up->opened = 0;
	vuart_setup_port(up, core);
	ret = vuart_register_port(up, core);

	if (!ret)
		/* send load message to arm */
		send_message_arm(up, NULL, 0, PROTO_LOAD);
	print_info("vuart status:%x\n", up->status);

	return ret;
}

int cn_log_vuart_late_init(struct cn_core_set *core)
{
	int ret = 0;

	if (!cambr_virtcon_en) {
		return ret;
	}

#if defined(CN_PRECOMPILE_UART_HANDLE_SYSRQ_CHAR)
	ret = vuart_late_init(core);
	if (ret) {
		print_err("virtcon init failed.\n");
		return ret;
	}
#else
	print_info("unsupport uart_handle_sysrq_char close virtcon\n");
	cambr_virtcon_en = 0;
#endif
	return ret;
}

void cn_log_vuart_late_exit(struct cn_core_set *core)
{
	int ret;
	struct log_vuart_port *up;

	if (!cambr_virtcon_en)
		return;

	if (register_status != VUART_REGISTER_OK)
		return;

	if (!core) {
		print_err("core does't exist\n");
		return;
	}
	up = core->vuart_set;
	if (up != NULL) {
		print_info("vuart status:%x\n", up->status);
		if (up->kdaemon) {
			send_sig(SIGKILL, up->kdaemon, 1);
			if (up->kdaemon) {
				ret = kthread_stop(up->kdaemon);
				if (-EINTR == ret)
					print_err(
					"stop daemon failed. wake up not called\n");

				up->kdaemon = NULL;
			}
		}

		if (up->status == VUART_PORT_OK) {
			ret = uart_remove_one_port(&log_vuart_pf_driver,
					&up->port);
			print_info("remove pf uart port ret:%x\n",
					ret);
		}
		if (up->uart_ep) {
			disconnect_endpoint(up->uart_ep);
			up->uart_ep = NULL;
		}
		if (up->channel) {
			close_a_channel(up->channel);
			up->channel = NULL;
		}
		if (up->ipcm_channel) {
			ipcm_destroy_channel(up->ipcm_channel);
			up->ipcm_channel = NULL;
		}
		core->vuart_set = NULL;
		vuart_free(up);
	} else {
		print_warn("didn't allocate vuart_set in core\n");
	}
}

int cn_log_vuart_init(void)
{
	int ret = 0;

	register_status = VUART_REGISTER_PF_FAILED;
	ret = uart_register_driver(&log_vuart_pf_driver);
	if (ret) {
		print_err("Failed to register vuart pf driver, ret = %d\n",
			ret);
		return ret;
	}
	register_status = VUART_REGISTER_OK;
	print_info("init register status:%x\n", register_status);
	return ret;
}

void cn_log_vuart_exit(void)
{
	print_info("exit register status:%x\n", register_status);
	if (register_status == VUART_REGISTER_OK)
		uart_unregister_driver(&log_vuart_pf_driver);

}

