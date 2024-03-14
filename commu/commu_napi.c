#include "cndrv_debug.h"
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pci.h>
#include <linux/jiffies.h>
#include "cndrv_os_compat.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "commu_internal.h"
#include "cndrv_commu.h"
#include "commu_init.h"
#include <linux/delay.h>
#include <linux/ptrace.h>
#include <linux/mutex.h>
#include <linux/kallsyms.h>
#include "commu/testqueue.h"

#ifdef CONFIG_CNDRV_COMMU
extern struct commu_ops rteq_ops;

struct commu_channel* search_channel_by_name(void *controller, char *name)
{
	struct commu_set *ctrl = (struct commu_set *)controller;
	struct commu_channel *channel;
	int found = 0;
	u64 hash_name = commu_string_hash(name);

	hash_for_each_possible(ctrl->commu_channel_head, channel, channel_node, hash_name){
		if(channel->hash_name == hash_name) {
			found = 1;
			break;
		}
	}

	if (!found)
		return NULL;
	return channel;
}

struct commu_channel *commu_search_channel_by_name(void *pcore, char *name)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	if (unlikely(!core || !core->commu_set)) {
		pr_err("%s %d core or commu_set is null\n", __func__, __LINE__);
		return NULL;
	}

	return search_channel_by_name(core->commu_set, name);
}

struct eventfd_ctx* search_eventfd_by_fp(struct commu_channel *channel, void *fp)
{
	int found = 0;
	struct commu_fd_listener *listener;

	hash_for_each_possible(channel->process_listeners, listener, fd_listener_node, (u64)fp){
		if(listener->fd == fp) {
			found = 1;
			break;
		}
	}

	if (!found)
		return NULL;
	return listener->listener;
}

struct commu_fd_listener* search_listener_by_fp(struct commu_channel *channel, void *fp)
{
	int found = 0;
	struct commu_fd_listener *listener;

	hash_for_each_possible(channel->process_listeners, listener, fd_listener_node, (u64)fp){
		if(listener->fd == fp) {
			found = 1;
			break;
		}
	}

	if (!found)
		return NULL;
	return listener;
}

struct commu_fd_listener* search_listener_in_ep_by_fp(struct commu_endpoint *ep, void *fp)
{
	int found = 0;
	struct commu_fd_listener *listener;

	hash_for_each_possible(ep->process_listeners, listener, fd_listener_node, (u64)fp){
		if(listener->fd == fp) {
			found = 1;
			break;
		}
	}

	if (!found)
		return NULL;
	return listener;
}

struct commu_endpoint *search_endpoint_by_type(struct commu_channel *channel, int type)
{
	struct llist_head *head;
	struct llist_node *first, *pre;
	struct commu_endpoint *ep, *ep_next, *ep_ret = NULL;

	if (!channel)
		return 0;

	mutex_lock(&channel->mutex);
	head = &channel->channel_endpoints_head;
	first = llist_del_all(head);
	if (!first) {
		mutex_unlock(&channel->mutex);
		return 0;
	}
	pre = first;

	llist_for_each_entry_safe(ep, ep_next, first, channel_node) {
		if (ep->type == type) {
			pre = &ep->channel_node;
			ep_ret = ep;
			continue;
		}
		pre = &ep->channel_node;
	}

	if (first)
		llist_add_batch(first, pre, head);
	mutex_unlock(&channel->mutex);

	if (ep_ret)
		return ep_ret;
	else
		return 0;
}

#define COMMU_SPIN_USER_TIMEOUT (1)

int commu_spin_lock_killable(volatile uint64_t *sign)
{
	/* Do we need to disable preempt here */
	while (test_and_set_bit(0, (long unsigned int *)sign)) {
		if (fatal_signal_pending(current)) {
			COMMU_INFO("fatal signal detected, lock abort.\n");
			return 1;
		}
		usleep_range(2, 5);
	}

	return 0;
}

int commu_spin_unlock_killable(struct commu_channel *channel, volatile uint64_t *sign)
{
	struct commu_set *ctrl = (struct commu_set *)channel->controller;
	u64 start, end;

	start = get_jiffies_64();
	while (*sign) {
		if (fatal_signal_pending(current)) {
			COMMU_INFO("fatal signal detected, unlock abort.\n");
			return 1;
		}
		end = get_jiffies_64();
		if (*sign && time_after64(end, start + COMMU_SPIN_USER_TIMEOUT * HZ)) {
			mutex_unlock(&ctrl->mutex);
			usleep_range(20, 50);
			mutex_lock(&ctrl->mutex);
			start = get_jiffies_64();
		} else {
			usleep_range(2, 5);
		}
	}

	return 0;
}

#define COMMU_SPIN_LOCK_TIMEOUT (10)
int commu_spin_lock(volatile uint64_t *sign)
{
	u64 start, end;

	start = get_jiffies_64();
	while (test_and_set_bit(0, (long unsigned int *)sign)) {
		end = get_jiffies_64();
		if (time_after64(end, start + COMMU_SPIN_LOCK_TIMEOUT * HZ)) {
			COMMU_INFO("[err]wait lock timeout.\n");
			return -ETIMEDOUT;
		}
		usleep_range(2, 5);
	}

	return 0;
}

int commu_spin_unlock(volatile uint64_t *sign)
{
	u64 start, end;

	start = get_jiffies_64();
	while (*sign) {
		end = get_jiffies_64();
		if (time_after64(end, start + COMMU_SPIN_LOCK_TIMEOUT * HZ)) {
			COMMU_INFO("[err]wait unlock timeout.\n");
			return -ETIMEDOUT;
		}
		usleep_range(2, 5);
	}

	return 0;
}

/* handle the userspace server hup event in device side */
/*
 * device side userspace server down, we have to use kernel ctrlq to send this message,
 * we recv an interrupt, then schedule a workqueue, and here we are.
 */
static void commu_channel_hup_user_handler(struct work_struct *work)
{
	struct commu_channel *channel = (struct commu_channel *)container_of(work,
			struct commu_channel, hup_work);
	struct commu_set *controller = (struct commu_set *)channel->controller;
	struct commu_fd_listener *listener;
	struct commu_user_mmap *desc_to_user;
	struct commu_endpoint *endpoint, *ep_next;
	int i;

	desc_to_user = (struct commu_user_mmap *)channel->desc_to_user;

	if (mutex_lock_killable(&controller->mutex))
		return;
	hash_for_each(channel->process_listeners, i, listener, fd_listener_node) {
		if (commu_spin_lock(&desc_to_user->sign))
			goto release;
		channel->current_desc_user = listener->fd;
		desc_to_user->desc.command = COMMU_DCMD_DEV_HUP;
		eventfd_signal(listener->listener, 1);
		if (commu_spin_unlock(&desc_to_user->sign))
			__sync_fetch_and_and(&desc_to_user->sign, 0);

		break;
	}

	llist_for_each_entry_safe(endpoint, ep_next,
			channel->channel_endpoints_head.first,
			channel_node) {
		if (!endpoint->rx.ops)
			continue;
		if (endpoint->channel->kernel_channel) {
			COMMU_INFO("Device server hup\n");
			endpoint->tx.ops->stop(endpoint->tx.real_queue);
			wake_up(&endpoint->waitqueue);
		}

		*(u32 *)(endpoint->rx.ops->head_addr(endpoint->rx.real_queue)) = 0;
		*(u32 *)(endpoint->rx.ops->tail_addr(endpoint->rx.real_queue)) = 0;
		*(u32 *)(endpoint->tx.ops->head_addr(endpoint->tx.real_queue)) = 0;
		*(u32 *)(endpoint->tx.ops->tail_addr(endpoint->tx.real_queue)) = 0;
	}
release:
	mutex_unlock(&controller->mutex);
	return;
}

int commu_send_user_command_and_wait(struct commu_endpoint *endpoint,
		struct ctrlq_desc *desc, u16 command, void *fp, void *ep_user,
		u64 port, u64 seq_addr)
{
	struct commu_channel *channel = endpoint->channel;
	struct commu_user_mmap *desc_to_user;
	struct eventfd_ctx *ctx;

	desc_to_user = (struct commu_user_mmap *)channel->desc_to_user;
	if (commu_spin_lock_killable(&desc_to_user->sign))
		return -1;

	channel->current_desc_user = fp;
	memcpy(&desc_to_user->desc, desc, sizeof(struct ctrlq_desc));
	desc_to_user->desc.command = command;
	desc_to_user->ep = endpoint;
	desc_to_user->ep_user = ep_user;
	desc_to_user->pair = port;
	/* mmap user_seq to userspace for gen seq between multi-process */
	desc_to_user->on_polling_addr = seq_addr;

	desc_to_user->head_addr = __pa(endpoint->tx.ops->head_addr(endpoint->tx.real_queue));
	desc_to_user->tail_addr = __pa(endpoint->tx.ops->tail_addr(endpoint->tx.real_queue));
	desc_to_user->channel_on_polling_addr = __pa(endpoint->tx.ops->head_addr(endpoint->rx.real_queue));
	desc_to_user->desc.name = __pa(endpoint->tx.ops->tail_addr(endpoint->rx.real_queue));

	if ((ctx = search_eventfd_by_fp(channel, fp)) != NULL)
		eventfd_signal(ctx, 1);
	else {
		COMMU_INFO("[ERR]no listener belong to fd %px found", fp);
		goto err;
	}

	if (commu_spin_unlock_killable(channel, &desc_to_user->sign))
		goto err;

	return 0;
err:
	__sync_fetch_and_and(&desc_to_user->sign, 0);
	return -1;
}

struct commu_channel * open_a_channel(char *name, void *controller, int fd)
{
	struct commu_channel *channel;

	/*TODO replace kernel hashtable
	 * can't use get_commu_channel_by_name, for hashtable can't
	 * passed in function as a pointer.
	 * */
	if (search_channel_by_name(controller, name)) {
		printk("%s: channel named %s opened already!\n", __func__, name);
		return NULL;
	}

	channel = (struct commu_channel *)cn_kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel) {
		COMMU_INFO("[ERR] malloc channel failed when %s!", __func__);
		return channel;
	}

	memset(channel->name, 0x0, sizeof(channel->name));
	memcpy(channel->name, name,
		strlen(name) < (COMMU_CHANNEL_NAME_MAX_LEN - 1) ?
		strlen(name) : (COMMU_CHANNEL_NAME_MAX_LEN - 1));

	/* insert ourself to channel hash table */
	channel->hash_name = commu_string_hash(name);
	mutex_init(&channel->mutex);

	if (!fd) {
		channel->kernel_channel = 1;
		INIT_WORK(&channel->hup_work, commu_channel_hup_user_handler);
	} else {
		channel->listener = eventfd_ctx_fdget(fd);
		channel->kernel_channel = 0;
		hash_init(channel->process_listeners);
		INIT_WORK(&channel->hup_work, commu_channel_hup_user_handler);
	}

	hash_add(((struct commu_set *)controller)->commu_channel_head,
			&channel->channel_node, channel->hash_name);
	COMMU_DBG("%s: channel name:%s\n channel hash:0x%llx\n", __func__,
			channel->name, commu_string_hash(name));

	/* init the list head to link all endpoints belong to the channel*/
	init_llist_head(&channel->channel_endpoints_head);
	channel->real_ep = 0;

	channel->controller = controller;
	channel->core_set = ((struct commu_set *)controller)->core_set;
	return channel;
}

struct commu_channel *commu_open_a_channel(char *name, void *pcore, int fd)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	if (unlikely(!core || !core->commu_set)) {
		pr_err("%s %d core or commu_set is null\n", __func__, __LINE__);
		return NULL;
	}

	return open_a_channel(name, core->commu_set, fd);
}

static int commu_alloc_inbound_outbound_addr(void *commu_set, struct ctrlq_desc *desc, int size)
{
	struct commu_set *controller = (struct commu_set *)commu_set;
	struct cn_core_set *core = (struct cn_core_set *)controller->core_set;
	host_addr_t in_host_vaddr, out_host_vaddr;
	dev_addr_t in_device_vaddr, out_device_vaddr;
	int ret;

	ret = cn_device_share_mem_alloc(0, &in_host_vaddr, &in_device_vaddr,
		size, core);

	if (ret) {
		COMMU_INFO("[ERR]tx share memory alloc failed.\n");
		return ret;
	}

	/* ib_va replace ib_ba, for pci save the bar0 physical addr, not the
	 * pci addr, can't get the offset by (pci addr - phy addr)*/
	desc->pci_addr = in_host_vaddr - controller->ib_va;
	COMMU_DBG("[COMMU API] alloc inbound host->arm %llx %llx\n",
			(u64)in_device_vaddr,
			controller->ib_va);

	if (controller->en_outbound) {
		ret = cn_host_share_mem_alloc(0, &out_host_vaddr, &out_device_vaddr,
			size, core);
	} else {
		ret = cn_device_share_mem_alloc(0, &out_host_vaddr, &out_device_vaddr,
			size, core);
	}
	if (ret) {
		cn_device_share_mem_free(0, in_host_vaddr, in_device_vaddr, core);
		return ret;
	}

	desc->shadow_addr = (u64)out_host_vaddr - (u64)controller->ob_va;
	COMMU_DBG("[COMMU API] alloc outbound arm->host %llx %llx\n",
			(u64)out_device_vaddr,
			(u64)controller->ob_va);

	return 0;
}

static int commu_free_inbound_outbound_addr(void *commu_set, u64 tx_addr, u64 rx_addr)
{
	struct commu_set *controller = (struct commu_set *)commu_set;
	struct cn_core_set *core = (struct cn_core_set *)controller->core_set;
	dev_addr_t device_vaddr;
	u64 addr;

	/* release inbound/outbound */
	core = (struct cn_core_set *)controller->core_set;
	addr = tx_addr;
	device_vaddr = (addr - controller->ib_va) + controller->ib_ba;
	cn_device_share_mem_free(0, addr, device_vaddr, core);

	addr = rx_addr;
	device_vaddr = (addr - (u64)controller->ob_va) + (u64)controller->ob_ba;
	if (controller->en_outbound) {
		cn_host_share_mem_free(0, addr, device_vaddr, core);
	} else {
		cn_device_share_mem_free(0, addr, device_vaddr, core);
	}

	return 0;
}

struct commu_endpoint * connect_rpc_endpoint(struct commu_channel *channel)
{
	struct commu_endpoint *endpoint;
	struct commu_set *controller;
	struct ctrlq_desc desc, wait;
	struct ctrlq_desc *seq = &wait;
	uint64_t tx_addr, rx_addr;
	int ret;

	if (!channel)
		return NULL;

	controller = (struct commu_set *)channel->controller;

	ret = commu_alloc_inbound_outbound_addr(controller, &desc,
			COMMU_ENDPOINT_QUEUE_SIZE);

	if (ret)
		return NULL;

	tx_addr = desc.pci_addr;
	rx_addr = desc.shadow_addr;

	ret = commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CRE_UPPER, channel->hash_name,
			tx_addr, rx_addr);

	if (ret)
		goto connect_pre_alloc;

	if (seq->command != COMMU_RET_CRE_UPPER) {
		COMMU_INFO("[ERR]channel %s connect endpoint failed %x\n", channel->name, seq->command);
		goto connect_pre_alloc;
	}

	/* use the shadow_addr passed from arm to init an endpoint */
	endpoint = open_an_endpoint_in_host(channel,
			(u64)controller->ib_va + seq->pci_addr,
			(u64)controller->ob_va + seq->shadow_addr,
			0, COMMU_ENDPOINT_QUEUE_DEPTH);

	if (!endpoint)
		goto connect_upper_half;

	endpoint->id = seq->name;
	endpoint->type = COMMU_ENDPOINT_KERNEL_RPC;

#ifdef COMMU_SHADOW_HEAD_TAIL
	ret = commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CRE_UPPER_PLUS, seq->name,
			COMMU_QUEUE_NUM | COMMU_SET_SHADOW_HEAD_TAIL,
			COMMU_KERNEL_QUEUE_DATA_BUF_SIZE);
#else
	ret = commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CRE_UPPER_PLUS, seq->name,
			COMMU_QUEUE_NUM,
			COMMU_KERNEL_QUEUE_DATA_BUF_SIZE);
#endif
	if (ret)
		goto connect_upper_half;

	/* set the ep pointer to another end as the pair id */
	ret = commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CRE_BOTTOM, seq->name,
			desc.pci_addr, (u64)endpoint);

	if (ret)
		goto connect_bottom_half;

	commu_enable_endpoint(endpoint, COMMU_PLAT_HOST);

	return endpoint;

connect_bottom_half:
	close_an_endpoint(endpoint);
	cn_kfree(endpoint);

connect_upper_half:
	/* send cmd_connect_cancel to device */
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CE_CANCEL, seq->name,
			0, 0);

	if (seq->command == COMMU_RET_FAILED)
		COMMU_INFO("[ERR]channel %s CE_CANCEL failed\n", channel->name);

connect_pre_alloc:
	commu_free_inbound_outbound_addr(controller,
			(u64)controller->ib_va + tx_addr,
			(u64)controller->ob_va + rx_addr);

	return NULL;
}

struct commu_endpoint *connect_rpc_user_endpoint(struct commu_channel *channel, int eventfd,
		void *ep_user, uint64_t queue_num, uint64_t data_size, void *fp, int32_t en_cross)
{
	struct commu_endpoint *endpoint;
	struct commu_set *controller;
	struct ctrlq_desc desc, wait;
	struct ctrlq_desc *seq = &wait;
	struct commu_fd_listener *listener;
	uint64_t tx_addr, rx_addr;
	void *user_seq;
	int ret;

	if (!channel)
		return NULL;

	controller = (struct commu_set *)channel->controller;

	if ((endpoint = search_endpoint_by_type(channel,
					COMMU_ENDPOINT_USER_RPC)) != NULL) {
		desc.pci_addr = (u64)endpoint->tx.base_addr - (u64)controller->ib_va;
		desc.shadow_addr = (u64)endpoint->rx.base_addr - (u64)controller->ob_va;
		user_seq = endpoint->tx.ops->user_seq_addr(endpoint->tx.real_queue);

		ret = commu_send_user_command_and_wait(endpoint, &desc,
				COMMU_CMD_CRE_UPPER, fp, ep_user, 0,
				__pa(user_seq));

		if (ret == -1)
			return NULL;

		/* record kernel listener, call rpc send this to arm
		 * arm send back this listener by ctrlq, host use it
		 * to notify userspace directly */
		endpoint->listener = eventfd_ctx_fdget(eventfd);
		endpoint->ep_user = (u64)ep_user;

	} else {
		/* create an endpoint */
		COMMU_DBG("open a rpc endpoint\n");

		ret = commu_alloc_inbound_outbound_addr(controller, &desc,
				COMMU_ENDPOINT_RTE_QUEUE_SIZE);

		if (ret)
			return NULL;

		tx_addr = desc.pci_addr;
		rx_addr = desc.shadow_addr;

		ret = commu_send_command_and_wait(controller, &desc, seq,
				COMMU_CMD_CRE_UPPER, channel->hash_name,
				tx_addr, rx_addr);

		if (ret)
			goto connect_pre_alloc;

		if (seq->command != COMMU_RET_CRE_UPPER) {
			COMMU_INFO("[ERR]channel %s connect endpoint failed %x\n", channel->name, seq->command);
			goto connect_pre_alloc;
		}

		/* use the shadow_addr passed from arm to init an endpoint */
		endpoint = open_an_endpoint_in_host_by_ops(channel,
				(u64)controller->ib_va + seq->pci_addr,
				(u64)controller->ob_va + seq->shadow_addr,
				0, COMMU_ENDPOINT_QUEUE_DEPTH, &rteq_ops,
				en_cross);

		if (!endpoint)
			goto connect_upper_half;

		endpoint->id = seq->name;
		endpoint->ep_user = (u64)ep_user;
		endpoint->listener = eventfd_ctx_fdget(eventfd);
		endpoint->type = COMMU_ENDPOINT_USER_RPC;
		hash_init(endpoint->process_listeners);

		user_seq = endpoint->tx.ops->user_seq_addr(endpoint->tx.real_queue);
		*(int64_t *)user_seq = 1;
		ret = commu_send_user_command_and_wait(endpoint, &desc,
				COMMU_CMD_CRE_UPPER, fp, ep_user, 0,
				__pa(user_seq));

		if (ret == -1)
			goto connect_bottom_half;

		if (en_cross)
			queue_num |= COMMU_SET_SHADOW_HEAD_TAIL;

		ret = commu_send_command_and_wait(controller, &desc, seq,
				COMMU_CMD_CRE_UPPER_PLUS, seq->name,
				queue_num, data_size);
		if (ret)
			goto connect_bottom_half;

		/* set the ep pointer to another end as the pair id */
		ret = commu_send_command_and_wait(controller, &desc, seq,
				COMMU_CMD_CRE_BOTTOM, seq->name,
				desc.pci_addr, (u64)endpoint);

		if (ret)
			goto connect_bottom_half;

		commu_enable_endpoint(endpoint, COMMU_PLAT_HOST);
	}

	if (!search_listener_in_ep_by_fp(endpoint, fp)) {
		listener = cn_kzalloc(sizeof(*listener), GFP_KERNEL);
		/* check ret */
		listener->fd = fp;
		listener->listener = endpoint->listener;
		hash_add(endpoint->process_listeners,
				&listener->fd_listener_node, (u64)listener->fd);
		COMMU_DBG("[commu] new process detected %px, new eventfd inited %px\n",
				fp, listener->listener);
	}

	return endpoint;

connect_bottom_half:
	close_an_endpoint(endpoint);
	cn_kfree(endpoint);

connect_upper_half:
	/* send cmd_connect_cancel to device */
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CE_CANCEL, seq->name,
			0, 0);

	if (seq->command == COMMU_RET_FAILED)
		COMMU_INFO("[ERR]channel %s CE_CANCEL failed\n", channel->name);

connect_pre_alloc:
	commu_free_inbound_outbound_addr(controller,
			(u64)controller->ib_va + tx_addr,
			(u64)controller->ob_va + rx_addr);

	return NULL;
}

#define COMMU_RPC_KILLABLE (1)
#define COMMU_RPC_NO_KILLABLE (0)
#define COMMU_RPC_NO_TIMEOUT (-1)
static int __commu_call_rpc(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size,
		int time_out, int killable)
{
#define COMMU_CALL_RPC_RETRY   (16UL)
#define COMMU_CALL_RPC_SEQ_INUSED_BITS 63
	struct commu_set *controller = NULL;
	char tmp[COMMU_ENDPOINT_RPC_BUFFER_IN_SIZE] = {0};
	int seq, glance_seq;
	int seq_bit, first_bit;
	u64 func;
	int ret;
	int remaining_time = time_out;
	int retry = COMMU_CALL_RPC_RETRY;

	if (!ep || !ep->channel || !ep->tx.ops || !ep->channel->controller)
		return -EINVAL;

	controller = (struct commu_set *)ep->channel->controller;

	if (unlikely(controller->reset_sign)) {
		COMMU_DBG("arm may hang, quit here.\n");
		return -2;
	}

	func = commu_string_hash(name);
	memcpy(tmp, &func, sizeof(func));
	memcpy(tmp + sizeof(func) + 8, in, in_size);
	seq = ep->tx.ops->gen_seq(ep->tx.real_queue);

	while (1) {
		ret = ep->tx.ops->enqueue(ep->tx.real_queue, tmp, in_size + sizeof(func) + 8, seq);

		if (ret == 0) {
			usleep_range(2, 5);
			if (killable && fatal_signal_pending(current)) {
				COMMU_INFO_LIMIT("fatal signal received, enqueue abort.\n");
				ret =  -EINTR;
				goto up;
			}
		}
		/* queue is stopped, quit */
		else if (ret == -1) {
			goto up;
		}
		/* queue is suspended, migration begin */
		else if (ret == -3) {
			wait_event_killable(controller->migration_waitqueue,
					(!controller->suspend_tx));
		}
		else
			break;
	}

	controller->data_doorbell(ep);

	/*
	 * Map seq to the corresponding bit of ep->rpc_flag
	 * Set bit for the state of wait_event,
	 * clear bit for the state of event come or timeout
	 */
	seq_bit = seq & COMMU_CALL_RPC_SEQ_INUSED_BITS;
	set_bit(seq_bit, (unsigned long int *)&ep->rpc_flag);

	if (unlikely(ep->tx.ops->is_stopped(ep->tx.real_queue))) {
		COMMU_INFO("queue is stopped, quit\n");
		ret = -1;
		goto up;
	}
retry:
	if (time_out == COMMU_RPC_NO_TIMEOUT)
		ret = wait_event_killable(ep->waitqueue,
			(!controller->suspend_rx &&
			 (seq == ep->rx.ops->glance(ep->rx.real_queue) ||
			  ep->tx.ops->is_stopped(ep->tx.real_queue) ||
			  controller->reset_sign))
			);
	else {
		/* ret 0 timeout | > 0 event come */
		ret = wait_event_timeout(ep->waitqueue,
			((ep->rx.ops->query_new(ep->rx.real_queue)
			  && seq >= ep->rx.ops->glance(ep->rx.real_queue))
			 || ep->tx.ops->is_stopped(ep->tx.real_queue)
			 || controller->reset_sign), remaining_time);

		if (mutex_lock_killable(&ep->ep_mutex)) {
			COMMU_INFO("get ep_mutex failed\n");
			clear_bit(seq_bit, (unsigned long int *)&ep->rpc_flag);
			goto up;
		}

		/* 0 if the @condition evaluated to %false after the @timeout elapsed */
		if (ret == 0) {
			ret = -ETIMEDOUT;
			COMMU_INFO("seq %d timeout\n", seq);
			goto clear;
		}
		glance_seq = ep->rx.ops->glance(ep->rx.real_queue);
		/*
		 * If the glance_seq is not equal seq and the bit belonging
		 * to this glance_seq in ep->rpc_flag is not set, that means a
		 * timeout package received.
		 */
		if (seq != glance_seq &&
			!test_bit(glance_seq & COMMU_CALL_RPC_SEQ_INUSED_BITS,
					(unsigned long int *)&ep->rpc_flag)
					&& !controller->reset_sign
					&& !ep->tx.ops->is_stopped(ep->tx.real_queue)) {
			remaining_time = ret;
			/*
			 * Always choose the thread waiting for the seq whose
			 * belonging bit is the first set bit in ep->rpc_flag,
			 * and then use this thread to discard the timeout package.
			 */
			first_bit = find_first_bit((unsigned long int *)&ep->rpc_flag,
					COMMU_CALL_RPC_SEQ_INUSED_BITS + 1);

			if (seq_bit == first_bit) {
				COMMU_INFO("Seq %d first_bit %d wait_event receive timeout seq %d\n",
						seq, first_bit, glance_seq);
				ret = ep->rx.ops->dequeue_rpc(ep->rx.real_queue, out, out_size);
			}

			mutex_unlock(&ep->ep_mutex);

			goto retry;
		}
	}

	if (unlikely(ret == -ERESTARTSYS)) {
		COMMU_INFO_LIMIT("fatal signal received when wait_event.\n");
		remaining_time = 2 * HZ;
		while (--retry) {
			ret = wait_event_timeout(ep->waitqueue,
				((ep->rx.ops->query_new(ep->rx.real_queue)
				&& seq == ep->rx.ops->glance(ep->rx.real_queue))
				|| ep->tx.ops->is_stopped(ep->tx.real_queue)
				|| controller->reset_sign), remaining_time);

			if (ret)
				break;

			if (retry == (COMMU_CALL_RPC_RETRY - 1)) {
				COMMU_INFO("user abort, rpc dequeue seq %d failed rtail %u.\n",
						seq,
						*(u32 *)ep->tx.ops->get_shadow_tail(ep->tx.real_queue));
			}
		}

		if (unlikely(ret == 0)) {
			COMMU_INFO("user abort, rpc dequeue seq %d timeout.\n", seq);
			ret = -EINTR;
			goto clear;
		}
	}

	if (unlikely(controller->reset_sign)) {
		COMMU_DBG("arm may hang, quit here.\n");
		ret = -2;
		goto clear;
	}

	if (unlikely(ep->tx.ops->is_stopped(ep->tx.real_queue))) {
		COMMU_INFO("queue is stopped, quit\n");
		ret = -1;
		goto clear;
	}
	ret = ep->rx.ops->dequeue_rpc(ep->rx.real_queue, out, out_size);
	if (!ret) {
		COMMU_INFO("dequeue failed, retey now. seq w%d/r%d\n",
				seq, ep->rx.ops->glance(ep->rx.real_queue));
		ret = ep->rx.ops->dequeue_rpc(ep->rx.real_queue, out, out_size);
		if (!ret) {
			COMMU_INFO("dequeue retry failed, go back to wait.\n");
			if (time_out != COMMU_RPC_NO_TIMEOUT)
				mutex_unlock(&ep->ep_mutex);
			usleep_range(2, 5);
			goto retry;
		} else {
			ret = 0;
		}
	} else {
		ret = 0;
	}

	if (ep->rx.ops->query_new(ep->rx.real_queue))
		wake_up(&ep->waitqueue);
clear:
	clear_bit(seq_bit, (unsigned long int *)&ep->rpc_flag);
	if (time_out != COMMU_RPC_NO_TIMEOUT)
		mutex_unlock(&ep->ep_mutex);
up:
	return ret;
}

#ifndef CONFIG_CNDRV_EDGE
int commu_call_rpc(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size)
{
	int ret;

	if (!ep)
		return -EINTR;

	if (down_killable(&ep->ep_sema)) {
		COMMU_INFO("rpc abort by signal when wait semaphore.\n");
		return -EINTR;
	}

	ret =  __commu_call_rpc(ep, name, in, in_size, out, out_size,
			COMMU_RPC_NO_TIMEOUT, COMMU_RPC_KILLABLE);
	up(&ep->ep_sema);

	return ret;
}
#else
extern int commu_call_rpc_handler(u64 _ep, char *name,
		void *in, int in_size, void *out, int *out_size);

int commu_call_rpc(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size)
{
	return commu_call_rpc_handler(ep->id, name, in, in_size, out, out_size);
}
#endif

/* This call will NOT return until enqueue success */
int commu_call_rpc_nokillable(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size)
{
	int ret;

	down(&ep->ep_sema);
	ret =  __commu_call_rpc(ep, name, in, in_size, out, out_size,
			COMMU_RPC_NO_TIMEOUT, COMMU_RPC_NO_KILLABLE);
	up(&ep->ep_sema);

	return ret;
}

int commu_call_rpc_timeout(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size, int time_out)
{
	return __commu_call_rpc(ep, name, in, in_size, out, out_size,
			time_out, COMMU_RPC_NO_KILLABLE);
}

int commu_call_rpc_killable_timeout(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size, int time_out)
{
	int ret;

	if (down_killable(&ep->ep_sema)) {
		COMMU_INFO("rpc abort by signal when wait semaphore.\n");
		return -EINTR;
	}

	ret = __commu_call_rpc(ep, name, in, in_size, out, out_size,
			time_out, COMMU_RPC_KILLABLE);
	up(&ep->ep_sema);

	return ret;
}

static int commu_free_sram_outbound_addr(void *commu_set, u64 tx_addr, u64 rx_addr)
{
	struct commu_set *controller = (struct commu_set *)commu_set;
	struct cn_core_set *core = (struct cn_core_set *)controller->core_set;
	dev_addr_t device_vaddr;
	u64 addr;

	addr = tx_addr;
	device_vaddr = (addr - controller->sram->sram_va) + controller->sram->sram_ba;
	cn_sram_free(0, addr, device_vaddr, core);

	addr = rx_addr;
	device_vaddr = (addr - (u64)controller->ob_va) + (u64)controller->ob_ba;
	if (controller->en_outbound) {
		cn_host_share_mem_free(0, addr, device_vaddr, core);
	} else {
		cn_device_share_mem_free(0, addr, device_vaddr, core);
	}

	return 0;
}

static int commu_alloc_sram_outbound_addr(void *commu_set, struct ctrlq_desc *desc, int size)
{
	struct commu_set *controller = (struct commu_set *)commu_set;
	struct cn_core_set *core = (struct cn_core_set *)controller->core_set;
	host_addr_t in_host_vaddr, out_host_vaddr;
	dev_addr_t in_device_vaddr, out_device_vaddr;
	int ret;

	ret = cn_sram_alloc(0, &in_host_vaddr, &in_device_vaddr, size, core);
	if (ret) {
		COMMU_INFO("[ERR]tx sram memory alloc failed.\n");
		return ret;
	}

	desc->pci_addr = (u64)in_host_vaddr - (u64)controller->sram->sram_va;
	COMMU_DBG("[COMMU API] alloc host->arm %#llx %#llx %#llx\n",
			(u64)in_host_vaddr, (u64)in_device_vaddr,
			(u64)controller->sram->sram_va);

	if (controller->en_outbound) {
		ret = cn_host_share_mem_alloc(0, &out_host_vaddr, &out_device_vaddr,
			size, core);
	} else {
		ret = cn_device_share_mem_alloc(0, &out_host_vaddr, &out_device_vaddr,
			size, core);
	}
	if (ret) {
		COMMU_INFO("[ERR]rx outbound memory alloc failed.\n");
		cn_sram_free(0, in_host_vaddr, in_device_vaddr, core);
		return ret;
	}

	desc->shadow_addr = (u64)out_host_vaddr - (u64)controller->ob_va;
	COMMU_DBG("[COMMU API] alloc arm->host %#llx %#llx %#llx\n",
			(u64)out_host_vaddr, (u64)out_device_vaddr,
			(u64)controller->ob_va);

	return 0;
}

static void
endpoint_acquire_sync_write(struct commu_set *controller,
	struct commu_endpoint *endpoint, u64 sram_host_vaddr)
{
	struct cn_core_set *core = (struct cn_core_set *)controller->core_set;
	struct commu_pcie_sram_set *sram = controller->sram;
	u64 sram_dev_paddr;
	int ret = 0;

	if (!controller->en_sync_write) {
		return;
	}

	sram_dev_paddr = sram->sram_dev_pa + (sram_host_vaddr - sram->sram_va);
	if (!IS_ALIGNED(sram_dev_paddr, 64)) {
		COMMU_INFO("sram_dev_paddr:%#llx isn't aligned with 64Bytes!\n",
			sram_dev_paddr);
		return;
	}

	ret = cn_bus_sync_write_alloc(core->bus_set, sram_dev_paddr);
	if (ret) {
		COMMU_INFO("sync write acquire full.\n");
		return;
	}

	endpoint->sync_write_pa = sram_dev_paddr;
	endpoint_set_sync_write(endpoint);
	endpoint->use_sync_write = 1;
}

struct commu_endpoint * connect_sram_msg_endpoint(struct commu_channel *channel)
{
	struct commu_endpoint *endpoint;
	struct commu_set *controller;
	struct ctrlq_desc desc, wait;
	struct ctrlq_desc *seq = &wait;
	u64 sram_host_vaddr;

	if (!channel)
		return NULL;

	controller = (struct commu_set *)channel->controller;

	/* create an endpoint */
	COMMU_INFO("open a sram msg endpoint start\n");
	commu_alloc_sram_outbound_addr(controller, &desc,
			COMMU_ENDPOINT_QUEUE_SIZE);

	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_UPPER_SRAM, channel->hash_name,
			desc.pci_addr, desc.shadow_addr);

	if (seq->command == COMMU_RET_NO_CHANNEL) {
		COMMU_INFO("[ERR]channel %s have not registered\n", channel->name);
		return NULL;
	}

	sram_host_vaddr = (u64)controller->sram->sram_va + seq->pci_addr;
	/* use the shadow_addr passed from arm to init an endpoint */
	endpoint = open_an_endpoint_in_host(channel, sram_host_vaddr,
			(u64)controller->ob_va + seq->shadow_addr,
			0, COMMU_ENDPOINT_QUEUE_DEPTH);
	endpoint->id = seq->name;
	endpoint->type = COMMU_ENDPOINT_KERNEL_MSG;

#ifdef COMMU_SHADOW_HEAD_TAIL
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_UPPER_PLUS, seq->name,
			COMMU_QUEUE_NUM | COMMU_SET_SHADOW_HEAD_TAIL,
			COMMU_KERNEL_QUEUE_DATA_BUF_SIZE);
#else
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_UPPER_PLUS, seq->name,
			COMMU_QUEUE_NUM,
			COMMU_KERNEL_QUEUE_DATA_BUF_SIZE);
#endif
	/* set the ep pointer to another end as the pair id */
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_BOTTOM, seq->name,
			desc.pci_addr, (u64)endpoint);

	commu_enable_endpoint(endpoint, COMMU_PLAT_HOST);

	endpoint_acquire_sync_write(controller, endpoint, sram_host_vaddr);

	endpoint->use_pcie_sram = 1;
	COMMU_INFO("open a sram msg endpoint finish\n");
	return endpoint;
}

struct commu_endpoint * connect_msg_endpoint(struct commu_channel *channel)
{
	struct commu_endpoint *endpoint;
	struct commu_set *controller;
	struct ctrlq_desc desc, wait;
	struct ctrlq_desc *seq = &wait;

	if (!channel)
		return NULL;

	controller = (struct commu_set *)channel->controller;

	/* create an endpoint */
	COMMU_DBG("open a msg endpoint\n");
	commu_alloc_inbound_outbound_addr(controller, &desc,
			COMMU_ENDPOINT_QUEUE_SIZE);

	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_UPPER, channel->hash_name,
			desc.pci_addr, desc.shadow_addr);

	if (seq->command == COMMU_RET_NO_CHANNEL) {
		COMMU_INFO("[ERR]channel %s have not registered\n", channel->name);
		return NULL;
	}

	/* use the shadow_addr passed from arm to init an endpoint */
	endpoint = open_an_endpoint_in_host(channel,
			(u64)controller->ib_va + seq->pci_addr,
			(u64)controller->ob_va + seq->shadow_addr,
			0, COMMU_ENDPOINT_QUEUE_DEPTH);
	endpoint->id = seq->name;
	endpoint->type = COMMU_ENDPOINT_KERNEL_MSG;

#ifdef COMMU_SHADOW_HEAD_TAIL
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_UPPER_PLUS, seq->name,
			COMMU_QUEUE_NUM | COMMU_SET_SHADOW_HEAD_TAIL,
			COMMU_KERNEL_QUEUE_DATA_BUF_SIZE);
#else
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_UPPER_PLUS, seq->name,
			COMMU_QUEUE_NUM,
			COMMU_KERNEL_QUEUE_DATA_BUF_SIZE);
#endif
	/* set the ep pointer to another end as the pair id */
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_BOTTOM, seq->name,
			desc.pci_addr, (u64)endpoint);

	commu_enable_endpoint(endpoint, COMMU_PLAT_HOST);

	return endpoint;
}

struct commu_endpoint *connect_msg_user_endpoint(struct commu_channel *channel, int eventfd,
		void *ep_user, uint64_t queue_num, uint64_t data_size, int32_t en_cross)
{
	struct commu_endpoint *endpoint;
	struct commu_set *controller;
	struct ctrlq_desc desc, wait;
	struct ctrlq_desc *seq = &wait;
	struct commu_user_mmap *desc_to_user;

	if (!channel)
		return NULL;

	controller = (struct commu_set *)channel->controller;

	/* create an endpoint */
	COMMU_DBG("open a msg endpoint\n");
	commu_alloc_inbound_outbound_addr(controller, &desc,
			COMMU_ENDPOINT_RTE_QUEUE_SIZE);

	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_UPPER, channel->hash_name,
			desc.pci_addr, desc.shadow_addr);

	if (seq->command == COMMU_RET_NO_CHANNEL) {
		COMMU_INFO("[ERR]channel %s not registered\n", channel->name);
	}

	/* use the shadow_addr passed from arm to init an endpoint */
	endpoint = open_an_endpoint_in_host_by_ops(channel,
			(u64)controller->ib_va + seq->pci_addr,
			(u64)controller->ob_va + seq->shadow_addr,
			0, COMMU_ENDPOINT_QUEUE_DEPTH, &rteq_ops,
			en_cross);
	endpoint->id = seq->name;
	endpoint->ep_user = (u64)ep_user;
	endpoint->listener = eventfd_ctx_fdget(eventfd);

	desc_to_user = (struct commu_user_mmap*)channel->desc_to_user;
	while (test_and_set_bit(0, (long unsigned int *)&(desc_to_user->sign)))
		;
	memcpy(&desc_to_user->desc, seq, sizeof(struct ctrlq_desc));
	desc_to_user->desc.command = COMMU_CMD_CME_UPPER;
	desc_to_user->ep = endpoint;
	desc_to_user->ep_user = (void *)endpoint->ep_user;
	eventfd_signal(channel->listener, 1);

	/* wait until userspace COMMU_CMD_CME_UPPER finished */
	while (desc_to_user->sign)
		;

	if (en_cross)
		queue_num |= COMMU_SET_SHADOW_HEAD_TAIL;
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_UPPER_PLUS, seq->name,
			queue_num, data_size);

	/* set the ep pointer to another end as the pair id */
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CME_BOTTOM, seq->name,
			desc.pci_addr, (u64)endpoint);
	commu_enable_endpoint(endpoint, COMMU_PLAT_HOST);
	return endpoint;
}

struct commu_port_proxy *connect_port_endpoint(struct commu_channel *channel, u16 port)
{
	struct commu_endpoint *endpoint;
	struct commu_set *controller;
	struct ctrlq_desc desc, wait;
	struct ctrlq_desc *seq = &wait;
	struct commu_port_proxy *proxy;

	//channel = get_commu_channel_by_name(name);
	if (!channel)
		return NULL;

	controller = (struct commu_set *)channel->controller;

	/* endpoint has been alloced */
	if (unlikely(channel->real_ep)) {
		printk("open a port endpoint\n");
		commu_alloc_inbound_outbound_addr(controller, &desc,
				COMMU_ENDPOINT_QUEUE_SIZE);

		commu_send_command_and_wait(controller, &desc, seq,
				COMMU_CMD_CPE_UPPER, channel->hash_name,
				desc.pci_addr, desc.shadow_addr);

		if (seq->command == COMMU_RET_NO_CHANNEL) {
			COMMU_INFO("[ERR]channel %s not registered\n", channel->name);
			return NULL;
		}

		/* use the shadow_addr passed from arm to init an endpoint */
		endpoint = open_an_endpoint_in_host(channel,
				(u64)controller->ib_va + seq->pci_addr,
				(u64)controller->ob_va + seq->shadow_addr,
				0, COMMU_ENDPOINT_QUEUE_DEPTH);
		endpoint->id = seq->name;
		endpoint->type = COMMU_ENDPOINT_KERNEL_PORT;

#ifdef COMMU_SHADOW_HEAD_TAIL
		commu_send_command_and_wait(controller, &desc, seq,
				COMMU_CMD_CPE_UPPER_PLUS, seq->name,
				COMMU_QUEUE_NUM | COMMU_SET_SHADOW_HEAD_TAIL,
				COMMU_KERNEL_QUEUE_DATA_BUF_SIZE);
#else
		commu_send_command_and_wait(controller, &desc, seq,
				COMMU_CMD_CPE_UPPER_PLUS, seq->name,
				COMMU_QUEUE_NUM,
				COMMU_KERNEL_QUEUE_DATA_BUF_SIZE);
#endif
		/* set the ep pointer to another end as the pair id */
		commu_send_command_and_wait(controller, &desc, seq,
				COMMU_CMD_CPE_BOTTOM, seq->name,
				desc.pci_addr, (u64)endpoint);

		endpoint->ports = cn_kzalloc(sizeof(struct commu_port_proxy) *
				COMMU_ENDPOINT_MAX_PORT, GFP_KERNEL);

		if (!endpoint->ports) {
			pr_info("alloc ports failed\n");
			return NULL;
		}
		commu_enable_endpoint(endpoint, COMMU_PLAT_HOST);
		channel->real_ep = endpoint;
	}

	endpoint = channel->real_ep;
	proxy = &endpoint->ports[port];
	if (proxy->in_using)
		return NULL;
	proxy->in_using = 1;

	proxy->ep = channel->real_ep;
	proxy->port = port;
	init_waitqueue_head(&proxy->waitqueue);

	printk("open a port proxy\n");
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CPP, endpoint->id,
			0, port);

	return proxy;
}

struct commu_endpoint *connect_port_user_endpoint(struct commu_channel *channel,
			void *ep_user, int ep_eventfd, uint64_t queue_num,
			uint64_t data_size, void *fp, int32_t en_cross)
{
	struct commu_endpoint *endpoint;
	struct commu_set *controller;
	struct ctrlq_desc desc, wait;
	struct ctrlq_desc *seq = &wait;
	uint64_t tx_addr, rx_addr;
	int ret;

	if (!channel)
		return NULL;

	controller = (struct commu_set *)channel->controller;

	COMMU_INFO("open a port endpoint for channel %s\n", channel->name);
	ret = commu_alloc_inbound_outbound_addr(controller, &desc,
			COMMU_ENDPOINT_RTE_QUEUE_SIZE);

	if (ret)
		return NULL;

	tx_addr = desc.pci_addr;
	rx_addr = desc.shadow_addr;

	ret = commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CPE_UPPER, channel->hash_name,
			tx_addr, rx_addr);

	if (ret)
		goto connect_pre_alloc;

	if (seq->command != COMMU_RET_CPE_UPPER) {
		COMMU_INFO("[ERR]channel %s connect endpoint failed %x\n", channel->name, seq->command);
		goto connect_pre_alloc;
	}

	/* use the shadow_addr passed from arm to init an endpoint */
	endpoint = open_an_endpoint_in_host_by_ops(channel,
			(u64)controller->ib_va + seq->pci_addr,
			(u64)controller->ob_va + seq->shadow_addr,
			0, COMMU_ENDPOINT_QUEUE_DEPTH, &rteq_ops,
			en_cross);

	if (!endpoint)
		goto connect_upper_half;

	endpoint->id = seq->name;
	endpoint->type = COMMU_ENDPOINT_USER_PORT;
	endpoint->ep_user = (u64)ep_user;
	endpoint->listener = eventfd_ctx_fdget(ep_eventfd);
	hash_init(endpoint->process_listeners);

	ret = commu_send_user_command_and_wait(endpoint, seq,
			COMMU_CMD_CPE_UPPER, fp, ep_user, 0, 0);

	if (ret == -1)
		goto connect_bottom_half;

	if (en_cross)
		queue_num |= COMMU_SET_SHADOW_HEAD_TAIL;
	ret = commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CPE_UPPER_PLUS, seq->name,
			queue_num, data_size);
	if (ret)
		goto connect_bottom_half;

	/* set the ep pointer to another end as the pair id */
	ret = commu_send_command_and_wait(controller, &desc, seq,
				COMMU_CMD_CPE_BOTTOM, seq->name,
				desc.pci_addr, (u64)endpoint);

	if (ret)
		goto connect_bottom_half;

	/*FIXME kzalloc 4.5M failed, reduce port number or using list */
	endpoint->ports = cn_kzalloc(sizeof(struct commu_port_proxy) *
			COMMU_ENDPOINT_MAX_PORT, GFP_KERNEL | __GFP_NOWARN);

	if (!endpoint->ports) {
		endpoint->ports = cn_vmalloc(sizeof(struct commu_port_proxy) *
				COMMU_ENDPOINT_MAX_PORT);
		if (!endpoint->ports) {
			COMMU_INFO("[ERR]alloc ports %lx failed.\n",
					sizeof(struct commu_port_proxy) * COMMU_ENDPOINT_MAX_PORT);
			goto connect_bottom_half;
		} else {
			memset(endpoint->ports, 0x0, sizeof(struct commu_port_proxy) * COMMU_ENDPOINT_MAX_PORT);
			endpoint->ports_alloc = 1;
		}
	}
	commu_enable_endpoint(endpoint, COMMU_PLAT_HOST);
	channel->real_ep = endpoint;
	return endpoint;

connect_bottom_half:
	close_an_endpoint(endpoint);
	cn_kfree(endpoint);

connect_upper_half:
	/* send cmd_connect_cancel to device */
	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CE_CANCEL, seq->name,
			0, 0);

	if (seq->command == COMMU_RET_FAILED)
		COMMU_INFO("[ERR]channel %s CE_CANCEL failed\n", channel->name);

connect_pre_alloc:
	commu_free_inbound_outbound_addr(controller,
			(u64)controller->ib_va + tx_addr,
			(u64)controller->ob_va + rx_addr);

	return NULL;


}

int connect_port_user_proxy(struct commu_channel *channel, u16 port,
		int port_eventfd, void *ep_user, int ep_eventfd,
		uint64_t queue_num, uint64_t data_size, void *fp, int32_t en_cross)
{
	struct commu_endpoint *endpoint;
	struct commu_set *controller;
	struct ctrlq_desc desc, wait;
	struct ctrlq_desc *seq = &wait;
	struct commu_port_proxy *proxy;
	int ret;

	/*TODO check ret value and free */
	if (!channel)
		return -1;

	controller = (struct commu_set *)channel->controller;

	/* endpoint hasn't been allocated */
	if (unlikely(!channel->real_ep)) {
		endpoint = connect_port_user_endpoint(channel, ep_user,
						ep_eventfd, queue_num,
						data_size, fp, en_cross);
		if (!endpoint)
			return -1;
		else
			channel->real_ep = endpoint;
	}

	endpoint = channel->real_ep;
	proxy = &endpoint->ports[port];
	if (proxy->in_using)
		return -2;

	/*
	 * if userspace hup, this api break up sleep immediately, if interrupt
	 * comes afterwards, on_polling will be set but never be cleared.
	 *
	 * solutions:
	 * 1) use wait_event
	 * 2) timeout in interrupt
	 * 3) timeout in condition check here
	 */
	ret = commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_CPP, endpoint->id,
			(u64)fp, port);

	if (ret)
		return -1;

	if (seq->command != COMMU_RET_CPP) {
		COMMU_INFO("[ERR]channel %s connect port proxy failed %x\n", channel->name, seq->command);
		return -1;
	}

	endpoint->ep_user = (u64)ep_user;
	desc.pci_addr = (u64)endpoint->tx.base_addr - (u64)controller->ib_va;
	desc.shadow_addr = (u64)endpoint->rx.base_addr - (u64)controller->ob_va;
	ret = commu_send_user_command_and_wait(endpoint, &desc,
			COMMU_CMD_CPP, fp, ep_user, port, 0);

	if (ret == -1)
		goto cancel_command;

	COMMU_DBG("open a port proxy %d\n", port);
	proxy->in_using = 1;
	proxy->ep = channel->real_ep;
	proxy->port = port;
	proxy->listener = eventfd_ctx_fdget(port_eventfd);
	/* check owner when disconnect */
	proxy->ep_user = ep_user;
	/* check when process exit */
	proxy->fp = fp;
	/*
	 * in reconnect case(server down, app continue retry connect,
	 * server up), interrupt may run on another core,
	 * we should sync proxy updated data immediately
	 */
	mb();

	return 0;

cancel_command:
	/*TODO  free CMD_CPP */
	return -1;
}

int commu_send_message_until_reset(struct commu_endpoint *ep, void *buf, int size)
{
	struct commu_set *controller = NULL;
	int seq;
	int ret = 0;

	if (!ep || !ep->channel || !ep->tx.ops || !ep->channel->controller)
		return 0;

	controller = (struct commu_set *)ep->channel->controller;

	if (unlikely(controller->reset_sign)) {
		COMMU_DBG("arm may hang, quit here.\n");
		return 0;
	}

	seq = ep->tx.ops->gen_seq(ep->tx.real_queue);

	while (!*(volatile int *)(&controller->reset_sign)) {
		ret = ep->tx.ops->enqueue(ep->tx.real_queue, buf, size, seq);

		if (ret == 0) {
			usleep_range(2, 5);
			pr_debug("tx queue is full\n");
		} else if (ret == -1) {
			/* queue is stopped */
			return ret;
		} else if (ret == -3) {
			/* queue is suspended, migration begin */
			wait_event_killable(controller->migration_waitqueue,
					(!controller->suspend_tx));
		} else if (ret > 0) {
			break;
		}
	}

	COMMU_DBG("%s [core] %d ret %d [pid]:%d-- seq:%d--- head %u tail%u\n", __func__,
			raw_smp_processor_id(), ret, current->pid, seq,
			//ep->tx.ops->glance(ep->tx.real_queue),
			*(u32 *)ep->tx.ops->head_addr(ep->tx.real_queue),
			*(u32 *)ep->tx.ops->tail_addr(ep->tx.real_queue));

	if (ret <= 0)
		return 0;

	controller->data_doorbell(ep);

	return seq;
}

int commu_send_message(struct commu_endpoint *ep, void *buf, int size)
{
	struct commu_set *controller = NULL;
	int seq;
	int ret;
#define COMMU_WAIT_MSGQ_TIMEOUT (1999999UL)
	int time = COMMU_WAIT_MSGQ_TIMEOUT;


	if (!ep || !ep->channel || !ep->tx.ops || !ep->channel->controller)
		return 0;

	controller = (struct commu_set *)ep->channel->controller;
	if (unlikely(controller->reset_sign)) {
		COMMU_DBG("arm may hang, quit here.\n");
		return 0;
	}

	seq = ep->tx.ops->gen_seq(ep->tx.real_queue);

	while (--time) {
		ret = ep->tx.ops->enqueue(ep->tx.real_queue, buf, size, seq);

		if (ret == 0) {
			usleep_range(2, 5);
			pr_debug("tx queue is full or suspended\n");
			if (fatal_signal_pending(current)) {
				COMMU_INFO_LIMIT("[COMMU]signal received %lx, msg enqueue abort.\n",
						current->pending.signal.sig[0]);
				break;
			}
		} else if (ret == -1) {
			/* queue is stopped */
			return ret;
		} else if (ret == -3) {
			/* queue is suspended, migration begin */
			wait_event_killable(controller->migration_waitqueue,
					(!controller->suspend_tx));
		} else if (ret > 0) {
			break;
		}
	}

	if (unlikely(!time)) {
		pr_err("[COMMU]timeout, msgq enqueue wait seq %d timeout.\n", seq);
	}

	COMMU_DBG("%s [core] %d ret %d [pid]:%d-- seq:%d--- head %u tail%u\n", __func__,
			raw_smp_processor_id(), ret, current->pid, seq,
			//ep->tx.ops->glance(ep->tx.real_queue),
			*(u32 *)ep->tx.ops->head_addr(ep->tx.real_queue),
			*(u32 *)ep->tx.ops->tail_addr(ep->tx.real_queue));

	if (ret <= 0)
		return 0;

	controller->data_doorbell(ep);

	return seq;
}

int commu_send_message_once(struct commu_endpoint *ep, void *buf, int size)
{
	struct commu_set *controller = NULL;
	int ret;

	if (!ep || !ep->channel || !ep->tx.ops || !ep->channel->controller)
		return 0;

	controller = (struct commu_set *)ep->channel->controller;

	if (unlikely(controller->reset_sign)) {
		COMMU_DBG("arm may hang, quit here.\n");
		return 0;
	}

	ret = ep->tx.ops->enqueue(ep->tx.real_queue, buf, size, 0);

	if (ret == 0) {
		pr_debug("tx queue is full or suspended\n");
	} else if (ret == -1) {
		/* queue is stopped */
		return ret;
	} else if (ret == -3) {
		/* queue is suspended, migration begin */
		wait_event_killable(controller->migration_waitqueue,
				(!controller->suspend_tx));
	} else if (ret > 0) {
		/* send succ */
	}

	COMMU_DBG("%s [core] %d ret %d [pid]:%d-- seq:%d--- head %u tail%u\n", __func__,
			raw_smp_processor_id(), ret, current->pid, seq,
			//ep->tx.ops->glance(ep->tx.real_queue),
			*(u32 *)ep->tx.ops->head_addr(ep->tx.real_queue),
			*(u32 *)ep->tx.ops->tail_addr(ep->tx.real_queue));

	if (ret <= 0)
		return 0;

	controller->data_doorbell(ep);

	return 1;
}

int commu_wait_for_message_seq_until_reset(struct commu_endpoint *ep, void *buf, int *size, int seq)
{
	int ret;
	struct commu_set *controller = NULL;

	if (!ep || !ep->channel)
		return 0;

	controller = (struct commu_set *)ep->channel->controller;
retry:
	wait_event(ep->waitqueue,
			(!controller->suspend_rx &&
			(seq == ep->rx.ops->glance(ep->rx.real_queue)
			 || controller->reset_sign)));

	if (unlikely(controller->reset_sign)) {
		COMMU_DBG("arm may hang, quit here.\n");
		return 0;
	}

	COMMU_DBG("%s pid:%d-- seq:%d---%d head %u tail%u\n", __func__,
			current->pid, seq,
			ep->rx.ops->glance(ep->rx.real_queue),
			*(u32 *)ep->rx.ops->head_addr(ep->rx.real_queue),
			*(u32 *)ep->rx.ops->tail_addr(ep->rx.real_queue));
	ret = ep->rx.ops->dequeue(ep->rx.real_queue, buf, size);

	if (!ret) {
		pr_info("%s --- dequeue failed, retey now. seq%d == %d\n",
				__func__, seq, ep->rx.ops->glance(ep->rx.real_queue));
		ret = ep->rx.ops->dequeue(ep->rx.real_queue, buf, size);
		if (!ret) {
			pr_err("dequeue retry failed, go back to wait!\n");
			usleep_range(2, 5);
			goto retry;
		}
	}

	if (ep->rx.ops->query_new(ep->rx.real_queue))
		wake_up(&ep->waitqueue);

	return ret;
}

int commu_wait_for_message_seq(struct commu_endpoint *ep, void *buf, int *size, int seq)
{
#define COMMU_WAIT_MSGQ_TIMEOUT (1999999UL)
	int time = COMMU_WAIT_MSGQ_TIMEOUT;
	int ret;
	struct commu_set *controller = NULL;

	if (!ep || !ep->channel)
		return 0;

	controller = (struct commu_set *)ep->channel->controller;

retry:
	ret = wait_event_interruptible(ep->waitqueue,
			(!controller->suspend_rx &&
			(seq == ep->rx.ops->glance(ep->rx.real_queue)
			 || controller->reset_sign)));

	if (unlikely(controller->reset_sign)) {
		COMMU_DBG("arm may hang, quit here.\n");
		return 0;
	}

	if (ret == -ERESTARTSYS) {
		if (!fatal_signal_pending(current)) {
			pr_debug("[COMMU] normal signal received, dequeue now%lx\n", current->pending.signal.sig[0]);
			usleep_range(20, 50);
			goto retry;
		} else {
			COMMU_INFO_LIMIT("[COMMU] fatal signal received %lx\n", current->pending.signal.sig[0]);

			while (--time) {
				if (seq == ep->rx.ops->glance(ep->rx.real_queue)) {
					ret = ep->rx.ops->dequeue(ep->rx.real_queue, buf, size);
					COMMU_INFO_LIMIT("[COMMU] user abort, msgq dequeue success.\n");
					return ret;
				}
				usleep_range(2, 5);
			}

			if (unlikely(!time)) {
				pr_err("[COMMU] user abort, msgq dequeue wait seq %d timeout.\n", seq);
				return 0;
			}
		}
	}

	COMMU_DBG("%s pid:%d-- seq:%d---%d head %u tail%u\n", __func__,
			current->pid, seq,
			ep->rx.ops->glance(ep->rx.real_queue),
			*(u32 *)ep->rx.ops->head_addr(ep->rx.real_queue),
			*(u32 *)ep->rx.ops->tail_addr(ep->rx.real_queue));
	ret = ep->rx.ops->dequeue(ep->rx.real_queue, buf, size);

	if (!ret) {
		pr_info("%s --- dequeue failed, retey now. seq%d == %d \n",
				__func__, seq, ep->rx.ops->glance(ep->rx.real_queue));
		ret = ep->rx.ops->dequeue(ep->rx.real_queue, buf, size);
		if (!ret) {
			pr_err("dequeue retry failed, go back to wait!\n");
			usleep_range(2, 5);
			goto retry;
		}
	}

	if (ep->rx.ops->query_new(ep->rx.real_queue))
		wake_up_interruptible(&ep->waitqueue);

	return ret;
}

/* return seq */
int commu_wait_for_message(struct commu_endpoint *ep, void *buf, int *size)
{
#define RETRY_MAX (3U)
	struct commu_set *controller = NULL;
	int retry_cnt = 0;
	int ret;

	if (!ep || !ep->channel)
		return 0;

	controller = (struct commu_set *)ep->channel->controller;

retry:
	wait_event_interruptible(ep->waitqueue,
			(ep->rx.ops->query_new(ep->rx.real_queue)
			 || controller->reset_sign));

	if (unlikely(controller->reset_sign)) {
		COMMU_DBG("arm may hang, quit here.\n");
		return 0;
	}

	ret = ep->rx.ops->dequeue(ep->rx.real_queue, buf, size);
	if (unlikely(!ret && (retry_cnt != RETRY_MAX))) {
		retry_cnt++;
		goto retry;
	}

	return ret;
}

int commu_send_message_by_port(struct commu_port_proxy *proxy, void *buf, int size)
{
	int seq;
	int ret;

	seq = proxy->ep->tx.ops->gen_seq(proxy->ep->tx.real_queue);
	COMMU_DBG("%s====seq%d\n", __func__, seq);
	ret = proxy->ep->tx.ops->enqueue(proxy->ep->tx.real_queue, buf, size, seq);
	if (ret <= 0)
		return 0;

	return seq;
}

int commu_wait_for_message_seq_by_port(struct commu_port_proxy *proxy, void *buf, int *size, int seq)
{
	struct commu_set *controller = NULL;

	if (!proxy || !proxy->ep || !proxy->ep->channel)
		return 0;

	controller = (struct commu_set *)proxy->ep->channel->controller;

	/*FIXME  Maybe should still use the ep->waitqueue,
	 * change the condition to seq && port
	 * MAX 65536 waitqueue, is it a problem?
	 * */
	wait_event_interruptible(proxy->waitqueue,
			(seq == proxy->ep->rx.ops->glance(proxy->ep->rx.real_queue)
			 || controller->reset_sign));

	if (unlikely(controller->reset_sign)) {
		COMMU_DBG("arm may hang, quit here.\n");
		return 0;
	}

	return proxy->ep->rx.ops->dequeue(proxy->ep->rx.real_queue, buf, size);
}

int detach_endpoint_from_channel_list(struct commu_endpoint *endpoint)
{
	struct llist_head *head;
	struct llist_node *first, *pre;
	struct commu_endpoint *ep, *ep_next;

	if (!endpoint)
		return -1;

	head = &endpoint->channel->channel_endpoints_head;
	first = llist_del_all(head);
	if (!first)
		return 0;
	pre = first;

	llist_for_each_entry_safe(ep, ep_next, first, channel_node) {
		if (ep != endpoint) {
			pre = &ep->channel_node;
			continue;
		}

		if (&ep->channel_node == first) {
			first = ep->channel_node.next;
			pre = first;
		} else
			pre->next = ep->channel_node.next;
	}

	if (first)
		llist_add_batch(first, pre, head);

	return 0;
}

static void
endpoint_release_sync_write(struct commu_set *controller,
		struct commu_endpoint *ep)
{
	struct cn_core_set *core = (struct cn_core_set *)controller->core_set;

	if (!ep->use_sync_write) {
		return;
	}

	cn_bus_sync_write_free(core->bus_set, ep->sync_write_pa);
}

static void
endpoint_free_in_out_addr(struct commu_set *controller,
		struct commu_endpoint *ep)
{
	if (ep->use_pcie_sram) {
		commu_free_sram_outbound_addr(controller,
			(u64)ep->tx.base_addr, (u64)ep->rx.base_addr);
	} else {
		commu_free_inbound_outbound_addr(controller,
			(u64)ep->tx.base_addr, (u64)ep->rx.base_addr);
	}
}

int disconnect_endpoint(struct commu_endpoint *ep)
{
	/* add a sign, queue will suspend any new message enqueue */
	/* then we send a disconnect command, and wait for response */
	/* Arm side release endpoint resources */
	/* then we release resource
	 * */
	/* do we need a flush command? */
	struct commu_set *controller;
	struct ctrlq_desc desc, wait;
	struct ctrlq_desc *seq = &wait;
	int ret;

	if (!ep)
		return -1;

	controller = (struct commu_set *)ep->channel->controller;

	ret = ep->tx.ops->stop(ep->tx.real_queue);
	if (!ep->tx.ops->is_stopped(ep->tx.real_queue))
		return -1;

	COMMU_INFO("channel %s\n", ep->channel->name);

	ret = commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_DE_UPPER, ep->id,
			desc.pci_addr,
			*(u32 *)ep->tx.ops->head_addr(ep->tx.real_queue));

	if (!ret) {
		if (ret == -2)
			COMMU_INFO("skip disconnect when CN_RESET.\n");
		goto clean;
	}

	/* tx can release now */
	//ep->tx.ops->free(ep->tx.real_queue);

	commu_send_command_and_wait(controller, &desc, seq,
			COMMU_CMD_DE_BOTTOM, ep->id,
			0, 0);
	ep->id = 0;

clean:
	endpoint_release_sync_write(controller, ep);
	endpoint_free_in_out_addr(controller, ep);

	ret = detach_endpoint_from_channel_list(ep);

	ret = close_an_endpoint(ep);

	if (ep->type == COMMU_ENDPOINT_USER_PORT) {
		if (!ep->ports_alloc)
			cn_kfree(ep->ports);
		else
			cn_vfree(ep->ports);
	}

	cn_kfree(ep);

	return ret;
}

int disconnect_port_user_endpoint(struct commu_endpoint *ep, u16 port, void *ep_user)
{
	struct commu_port_proxy *proxy;

	if (!ep)
		return -1;


	proxy = &ep->ports[port];
	if (!proxy->in_using)
		return 0;

	/* check owner */
	if (proxy->ep_user == ep_user) {
		/*
		 * 1. disconnect port
		 * 2. this port still has a used desc in rx ring
		 * (because of multiget, value get but tail not move)
		 * 3. process is HANGUP
		 * 4. queue locked
		 */
		ep->rx.ops->set_flag_sigint(ep->rx.real_queue, port, "RX");
		memset(proxy, 0x0, sizeof(*proxy));
		proxy->port = port;
	} else
		return -2;

	/*TODO notify pair side? */

	return 0;
}

int disconnect_rpc_user_endpoint(struct commu_endpoint *ep, void *fp)
{
	struct commu_fd_listener *listener;
	struct hlist_node *tmp;

	if (!ep)
		return -1;

	/* free listeners belong to the fp in each channel */
	hash_for_each_possible_safe(ep->process_listeners,
			listener, tmp, fd_listener_node, (u64)fp) {
		if (listener->fd == fp) {
			struct eventfd_ctx *ctx = listener->listener;
			hash_del(&listener->fd_listener_node);
			ep->rx.ops->set_rpc_sigint(ep->rx.real_queue, ctx, "RX");
			cn_kfree(listener);
		}
	}

	return 0;
}

int close_a_channel(struct commu_channel *channel)
{
	struct llist_head *head;
	struct llist_node *first;
	struct commu_endpoint *ep, *ep_next;
	int ret = 0;

	if (!channel)
		return -1;

	/* remove all endpoints */
	head = &channel->channel_endpoints_head;
	first = llist_del_all(head);
	if (!first)
		goto hash_ret;

	/* we have call llist_del_all, so the detach_from_list
	 * call in disconnect_endpoint will return directly */
	llist_for_each_entry_safe(ep, ep_next, first, channel_node) {
		ret = disconnect_endpoint(ep);
	}

hash_ret:
	/* remove channel from hashtable */
	hash_del(&channel->channel_node);
	cn_kfree(channel);

	return ret;
}

#define COMMU_WAIT_WORK_INFO_NAME_LEN 128
struct commu_wait_work_info {
	/* work thread name */
	char work_name[COMMU_WAIT_WORK_INFO_NAME_LEN];
	/* work check ep name */
	struct commu_endpoint *work_ep;
	/* callback data */
	void *priv_data;
	void (*call_back)(struct cn_core_set *core,
			void *priv_data,
			void *rx_msg, int rx_size);
	struct task_struct *worker;

	volatile bool exit_flag;

	struct cn_core_set *core;
};

#define LOCKUP_PROTECT_MASK       ((1ULL << 6) - 1)
/* commu kthread for ep wait message
 * */
static int commu_wait_work_thread(void *data)
{
#define COMMU_THREAD_SHOULD_STOP() \
	(work_info->exit_flag || core->reset_flag)

	int rx_size = 0;
	u8 rx_msg[COMMU_TESTQ_DATA_BUF_SIZE];
	struct cn_core_set *core = NULL;
	struct commu_wait_work_info *work_info = NULL;
	__u64 lockup_counter = 0;

	work_info = (struct commu_wait_work_info *)data;
	core = work_info->core;

	if (current->nr_cpus_allowed > 1)
		CN_CLEAR_CPUMASK(0);

	allow_signal(SIGKILL);
	while (!kthread_should_stop()) {
		if (COMMU_THREAD_SHOULD_STOP()) {
			msleep(20);
			continue;
		}
		if (!commu_wait_for_message(work_info->work_ep,
					(void *)rx_msg, &rx_size)) {
			if (!COMMU_THREAD_SHOULD_STOP())
				cn_dev_core_err_limit(core,
						"%s work wait message err\n",
						work_info->work_name);
			continue;
		}
		work_info->call_back(core, work_info->priv_data, (void *)rx_msg, rx_size);

		/* When user use multithread invoke task, there
		 * will be a huge number of commu message from device in
		 * this thread, in this condition, commu_wait_for_message
		 * have no chance call wait_event_interruptible to schedule
		 * the thread out, and the continuous working of this
		 * thread will cause kernel soft lockup.
		 * In order to prevent this bug, we add lockup_counter to
		 * allow this thread have chance to schedule out event in
		 * very busy condition.
		 */
		if (((++lockup_counter) & LOCKUP_PROTECT_MASK) == 0) {
			usleep_range(2, 5);
		}
	}
	cn_dev_core_info(core, "%s work thread finish.", work_info->work_name);

	return 0;

#undef COMMU_THREAD_SHOULD_STOP
}

void *commu_wait_work_run(
		struct cn_core_set *core,
		const char *thread_name,
		struct commu_endpoint *ep,
		void *priv_data,
		void (*call_back)(struct cn_core_set *core,
			void *priv_data,
			void *rx_msg, int rx_size)
		)
{
	struct commu_wait_work_info *work_info = NULL;

	work_info = cn_kzalloc(sizeof(struct commu_wait_work_info), GFP_KERNEL);
	if (!work_info) {
		cn_dev_core_err(core, "alloc memory for work info fail");
		return NULL;
	}
	work_info->core = core;
	work_info->work_ep = ep;
	work_info->priv_data = priv_data;
	work_info->call_back = call_back;
	work_info->exit_flag = false;
	sprintf(work_info->work_name, "%s_%d", thread_name, core->idx);

	work_info->worker =
			kthread_create_on_node(commu_wait_work_thread, work_info,
			cn_core_get_numa_node_by_core(core),
			work_info->work_name);
	if (IS_ERR(work_info->worker)) {
		cn_kfree(work_info);
		return NULL;
	}
	wake_up_process(work_info->worker);

	return work_info;
}

void commu_wait_work_stop(
		struct cn_core_set *core,
		void *work_data)
{
	struct commu_wait_work_info *work_info =
			(struct commu_wait_work_info *)work_data;

	if (!work_info) {
		cn_dev_core_warn(core, "input work info is NULL");
		dump_stack();
		return;
	}

	work_info->exit_flag = true;
	/* comment */
	smp_mb();
	send_sig(SIGKILL, work_info->worker, 1);
	kthread_stop(work_info->worker);

	cn_kfree(work_info);
}

u64 commu_get_vf_ctrlq_base(void *pcore, int vf_id)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;

	return (u64)commu_set->vf2pf_pf[vf_id].ring;
}

void commu_set_vf_ctrlq_base(void *pcore, int vf_id, u64 ctrlq_base)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;

	commu_set->vf2pf_pf[vf_id].ring = (struct ctrlq_ring *)ctrlq_base;
}

u32 commu_get_vf_ctrlq_head(void *pcore, int vf_id)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;

	return commu_set->vf2pf_pf[vf_id].head;
}

void commu_set_vf_ctrlq_head(void *pcore, int vf_id, u32 head)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;

	commu_set->vf2pf_pf[vf_id].head = head;
}

u32 commu_get_vf_ctrlq_tail(void *pcore, int vf_id)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;

	return commu_set->vf2pf_pf[vf_id].tail;
}

void commu_set_vf_ctrlq_tail(void *pcore, int vf_id, u32 tail)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;

	commu_set->vf2pf_pf[vf_id].tail = tail;
}

u32 commu_get_vf_init_flag(void *pcore, int vf_id)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;

	return commu_set->init_sign[vf_id];
}

void commu_set_vf_init_flag(void *pcore, int vf_id, u32 flags)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;

	commu_set->init_sign[vf_id] = flags;
}

void commu_restore_vf_ctrlq(void *pcore, int vf, u64 ctrlq_base, u32 head, u32 tail, u32 num)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;

	commu_set->vf2pf_pf[vf].ring = (void *)ctrlq_base;
	commu_set->vf2pf_pf[vf].num = num;
	spin_lock_init(&commu_set->vf2pf_pf[vf].lock);
	atomic_set(&commu_set->vf2pf_pf[vf].seq, 1);
	commu_set->vf2pf_pf[vf].head = head;
	commu_set->vf2pf_pf[vf].tail = tail;

	commu_set->vf2pf_pf[vf].shadow_head = &(commu_set->vf2pf_pf[vf].ring->head);
	commu_set->vf2pf_pf[vf].shadow_tail = &(commu_set->vf2pf_pf[vf].ring->tail);

	commu_set->init_sign[vf] = 1;
}

void commu_vf2pf_handler(void *pcore, u32 vf_id)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;
	struct ctrlq_queue *queue = &commu_set->vf2pf_pf[vf_id];
	struct ctrlq_desc desc;
	int commu_id = vf_id;

	if (commu_set->pf_id == 0) {
		commu_id++;
	}

	while (ctrlq_get(queue, &desc)) {
		cn_dev_core_info(core, "ctrlq work %x",
				desc.command);

		switch (desc.command) {
		case COMMU_CMD_SET_ARM2VF_ADDR:
			desc.vf_num = commu_id;
			ctrlq_put(&commu_set->pf2arm, &desc);
			break;
		/* vf exit */
		case COMMU_CMD_VF_EXIT:
			desc.vf_num = commu_id;
			commu_set->init_sign[vf_id] = 0;
			ctrlq_put(&commu_set->pf2arm, &desc);
			break;
		default:
			desc.vf_num = commu_id;
			ctrlq_put(&commu_set->pf2arm, &desc);
			break;
		}
	}
}

void commu_ctrlq_alloc(void *pcore, u32 vf_id, void *addr, int size)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *commu_set = core->commu_set;
	struct ctrlq_queue *queue = &commu_set->vf2pf_pf[vf_id];

	ctrlq_alloc(queue, addr, size);
}

irqreturn_t commu_ctrlq_alloc_done(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct commu_set *controller;

	if (!core || !core->commu_set)
		return IRQ_HANDLED;

	controller = core->commu_set;
	controller->ctrlq_alloc_wait_flag = 1;
	wake_up_interruptible(&controller->commu_waitqueue);
	return IRQ_HANDLED;
}
#else
/* MLU200's PF ID is COMMU_VF_NUM, MLU300's PF ID is 0.
 * !CONFIG_CNDRV_COMMU only if CONFIG_CNDRV_PCIE_ARM_PLATFORM, its 300s+ only
 */
#define COMMU_PF_ID (0)

extern s32 dm_xpu_pid2vf_id(s32 pid);

extern int commu_call_rpc_pcie_arm(char *name,
		void *in, int in_size, void *out, int *out_size, int vf_id);

/* to avoid PCIE_ARM:cambricon_drv: module uses symbols from proprietary module mem_server, inheriting taint. */
int commu_call_rpc(struct commu_endpoint *ep, char *name,
		void *in, int in_size, void *out, int *out_size)
{
	int vf_id = dm_xpu_pid2vf_id(current->tgid);
	char buf[TASK_COMM_LEN];
	struct task_struct *task = NULL;

	task = get_pid_task(find_vpid(current->tgid), PIDTYPE_PID);
	if (task) {
		get_task_comm(buf, task);
		put_task_struct(task);
	}

	pr_debug("%s %d, comm(%s) dm_xpu_pid2vf_id(tgid = %d) = %d\n", __func__, __LINE__, buf, current->tgid, vf_id);
	if (unlikely(vf_id < 0)) {
		vf_id = COMMU_PF_ID;
	}

	return commu_call_rpc_pcie_arm(name, in, in_size, out, out_size, vf_id);
}
#endif
