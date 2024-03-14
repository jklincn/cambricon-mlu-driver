#include "cndrv_debug.h"
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/sys.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>

#include "channel.h"

/*struct llist_head commu_all_poll;*/
/* IPU JPU VPU DMA MM */
/*struct hlist_head commu_channel_head[256];*/
struct llist_head commu_vf[4];
LLIST_HEAD(commu_all_poll);
DEFINE_HASHTABLE(commu_channel_head, 8);
spinlock_t all_poll_lock;
struct task_struct *worker;

u64 commu_string_hash(char *name)
{
	u64 base = 131;
	u64 mod = 212370440130137957ll;
	u64 ans = 0;
	int len = strlen(name);
	int i= 0;
	for (i = 0; i < len; i++)
		ans = (ans * base + (u64)name[i]) % mod;

	return ans;
}

extern struct commu_ops testq_ops;
extern struct commu_ops rteq_ops;

int commu_init_vqueue(struct commu_vqueue *vqueue, u64 addr, u32 size, struct commu_ops *ops)
{
	vqueue->ops = ops;
	vqueue->real_queue = vqueue->ops->alloc((void *)addr, size, vqueue->core_set);
	vqueue->entry_size = size;
	vqueue->base_addr = (void *)addr;

	return 0;
}

struct commu_channel * get_commu_channel_by_hash_name(u64 hash_name)
{
	struct commu_channel *channel;
	int found = 0;

	hash_for_each_possible(commu_channel_head, channel, channel_node, hash_name){
		if(channel->hash_name == hash_name) {
			found = 1;
			break;
		}
	}

	printk("==%s --- %px --- %llx\n", __func__, channel, hash_name);
	if (!found)
		return NULL;

	return channel;
}

struct commu_channel * get_commu_channel_by_name(char *name)
{
	 return get_commu_channel_by_hash_name(commu_string_hash(name));
}

void commu_set_shadow_head_tail(struct commu_endpoint *endpoint, int32_t en_cross)
{
	endpoint->tx.ops->set_shadow_head(endpoint->tx.real_queue,
				endpoint->tx.ops->get_ring_head(endpoint->tx.real_queue));
	endpoint->rx.ops->set_shadow_head(endpoint->rx.real_queue,
				endpoint->rx.ops->get_ring_head(endpoint->rx.real_queue));
	if (en_cross) {
		endpoint->tx.ops->set_shadow_tail(endpoint->tx.real_queue,
				endpoint->rx.ops->get_ring_tail(endpoint->rx.real_queue));
		endpoint->rx.ops->set_shadow_tail(endpoint->rx.real_queue,
				endpoint->tx.ops->get_ring_tail(endpoint->tx.real_queue));
	} else {
		endpoint->tx.ops->set_shadow_tail(endpoint->tx.real_queue,
				endpoint->tx.ops->get_ring_tail(endpoint->tx.real_queue));
		endpoint->rx.ops->set_shadow_tail(endpoint->rx.real_queue,
				endpoint->rx.ops->get_ring_tail(endpoint->rx.real_queue));
	}
}


struct commu_endpoint * __open_an_endpoint(struct commu_channel *channel,
		u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length, struct commu_ops *ops)
{
	struct commu_endpoint *endpoint;

	endpoint = cn_kzalloc(sizeof(*endpoint), GFP_KERNEL);
	if (!endpoint) {
		WARN_ON(1);
		return NULL;
	}

	endpoint->channel = channel;
	endpoint->vf_id = vf_id;
	endpoint->on_polling = 0;
	endpoint->free_me = 0;
	spin_lock_init(&endpoint->ep_lock);

	endpoint->id = (u64)endpoint; /* use pointer as id temporarily */
	printk("==%s --- %px\n", __func__, endpoint);

	/* init tx/rx queue */
	endpoint->tx.core_set = channel->core_set;
	endpoint->rx.core_set = channel->core_set;
	commu_init_vqueue(&endpoint->tx, tx_addr, queue_length, ops);
	commu_init_vqueue(&endpoint->rx, rx_addr, queue_length, ops);

	/* add ourself to all kinds of lists */
	//llist_add(&endpoint->channel_node, &channel->channel_endpoints_head);
	//llist_add(&endpoint->all_poll_node, &commu_all_poll);

	printk("===commu_all_poll %px===\n", commu_all_poll.first);

	return endpoint;


}

struct commu_endpoint * open_an_endpoint(struct commu_channel *channel,
		u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length)
{
	return __open_an_endpoint(channel, tx_addr, rx_addr, vf_id,
			queue_length, &testq_ops);
}

struct commu_endpoint * open_an_endpoint_by_ops(struct commu_channel *channel,
		u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length, struct commu_ops *ops)
{
	return __open_an_endpoint(channel, tx_addr, rx_addr, vf_id,
			queue_length, ops);
}

struct commu_endpoint * __open_an_endpoint_in_host(struct commu_channel *channel,
		u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length, struct commu_ops *ops, int32_t en_cross)
{
#define COMMU_Q_LEN_ORDER     (5)
#define COMMU_Q_LEN           (1 << (COMMU_Q_LEN_ORDER))
	struct commu_endpoint *endpoint;

	if (!channel)
		return NULL;

	endpoint = cn_kzalloc(sizeof(*endpoint), GFP_KERNEL);
	if (!endpoint)
		return NULL;

	endpoint->channel = channel;
	endpoint->type = 0;
	endpoint->use_pcie_sram = 0;
	endpoint->use_sync_write = 0;
	spin_lock_init(&endpoint->ep_lock);
	sema_init(&endpoint->ep_sema, COMMU_Q_LEN);
	sema_init(&endpoint->ep_user_sema, 1);
	mutex_init(&endpoint->ep_mutex);
	init_waitqueue_head(&endpoint->waitqueue);
	COMMU_DBG("channel %s tx_addr %llx rx_addr %llx\n", channel->name,
			tx_addr, rx_addr);

	/* init tx/rx queue */
	endpoint->tx.core_set = channel->core_set;
	endpoint->rx.core_set = channel->core_set;
	commu_init_vqueue(&endpoint->tx, tx_addr, queue_length, ops);
	commu_init_vqueue(&endpoint->rx, rx_addr, queue_length, ops);

	commu_set_shadow_head_tail(endpoint, en_cross);
	/* add ourself to all kinds of lists */
	//llist_add(&endpoint->channel_node, &channel->channel_endpoints_head);

	return endpoint;
}

struct commu_endpoint * open_an_endpoint_in_host(struct commu_channel *channel,
		u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length)
{
#ifdef COMMU_SHADOW_HEAD_TAIL
	int32_t en_cross = 1;
#else
	int32_t en_cross = 0;
#endif

	return __open_an_endpoint_in_host(channel, tx_addr, rx_addr, vf_id,
			queue_length, &testq_ops, en_cross);
}

struct commu_endpoint * open_an_endpoint_in_host_by_ops(struct commu_channel *channel,
		u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length, struct commu_ops *ops, int32_t en_cross)
{

	return __open_an_endpoint_in_host(channel, tx_addr, rx_addr, vf_id,
			queue_length, ops, en_cross);
}

void endpoint_set_sync_write(struct commu_endpoint *ep)
{
	struct commu_vqueue *vqueue = &ep->tx;

	/* queue depth is 1 current, so entry_id should be 0 */
	vqueue->ops->set_sync_write(vqueue->real_queue, ep->sync_write_pa);
}

int commu_enable_endpoint(struct commu_endpoint *endpoint, int host_or_dev)
{
	/* add ourself to all kinds of lists */
	if (host_or_dev == COMMU_PLAT_HOST) {
		llist_add(&endpoint->channel_node, &endpoint->channel->channel_endpoints_head);
	} else if (host_or_dev == COMMU_PLAT_DEV) {
		llist_add(&endpoint->channel_node, &endpoint->channel->channel_endpoints_head);
		llist_add(&endpoint->all_poll_node, &commu_all_poll);
	}

	return 0;
}

static void endpoint_redirect_message_to_user(struct work_struct *work)
{
	struct commu_endpoint *ep = (struct commu_endpoint *)container_of(work,
			struct commu_endpoint, work);

	printk("=======%s =====%px===\n",__func__, ep->listener);
	eventfd_signal(ep->listener, 1);
	/*ep->on_polling = 0;*/


}

static void endpoint_redirect_port_message_to_user(struct work_struct *work)
{
	struct commu_endpoint *ep = (struct commu_endpoint *)container_of(work,
			struct commu_endpoint, work);
	u16 port;

	printk("=======%s =====%px===\n",__func__, ep->listener);
	port = ep->tx.ops->glance_port(ep->tx.real_queue);

	//if (port == 0)

	eventfd_signal(ep->ports[port].listener, 1);
	/*ep->on_polling = 0;*/
}

static void endpoint_invoke_callbacks(struct work_struct *work)
{
	struct commu_endpoint *ep = (struct commu_endpoint *)container_of(work,
			struct commu_endpoint, work);
	char tmp[COMMU_ENDPOINT_RPC_BUFFER_IN_SIZE];
	u64 *index = (u64 *)tmp;
	char out[COMMU_ENDPOINT_RPC_BUFFER_OUT_SIZE];
	int in_size, out_size;
	int ret;
	int seq;
	struct commu_callback_map *callback;

	seq = ep->tx.ops->dequeue(ep->tx.real_queue, tmp, &in_size);

	if (!seq) {
		ep->on_polling = 0;
		return;
	}
	ep->on_polling = 0;

	/* TODO should enqueue some error message to pair endpoint */
	if (unlikely(!ep->callbacks)) {
		memcpy(out, "no func registered", strlen("no func registered"));
		out_size = 20;
		goto touch_bell;
	}

	/* search func from table by name */
	for (callback = ep->callbacks; callback->func_name; callback++) {
		if (commu_string_hash(callback->func_name) == *index)
			break;
	}
	pr_debug("%s ----%llx found:%s \n", __func__, *index, callback->func_name);

	if (!callback->func_name) {
		memcpy(out, "no func found", strlen("no func found"));
		out_size = 20;
		goto touch_bell;
	}

	/* check ret!*/
	ret = callback->func(tmp + 8, in_size - 8, out, &out_size);

touch_bell:
	/* check ret!*/
	ret = ep->rx.ops->enqueue(ep->rx.real_queue, out, out_size, seq);
	if (!ret)
		pr_info("rx queue if full\n");
	ep->channel->doorbell(ep->vf_id, ep->pair);


	return;
}

static void endpoint_recv_messages(struct work_struct *work)
{
	struct commu_endpoint *ep = (struct commu_endpoint *)container_of(work,
			struct commu_endpoint, work);

	ep->channel->current_ep = ep;
	wake_up_interruptible(&ep->channel->waitqueue);

	return;
}

static void endpoint_recv_port_messages(struct work_struct *work)
{
	struct commu_endpoint *ep = (struct commu_endpoint *)container_of(work,
			struct commu_endpoint, work);
	u16 port;

	port = ep->tx.ops->glance_port(ep->tx.real_queue);

	//if (port == 0)

	wake_up_interruptible(&ep->ports[port].waitqueue);

	return;
}

struct commu_endpoint * create_rpc_endpoint(char *name, u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length, struct commu_callback_map *callbacks)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;

	channel = get_commu_channel_by_name(name);
	if (!channel)
		return NULL;

	endpoint = open_an_endpoint(channel, tx_addr, rx_addr,
		vf_id, queue_length);
	endpoint->type = 1;
	endpoint->callbacks = callbacks;
	if (endpoint->channel->kernel_channel)
		INIT_WORK(&endpoint->work, endpoint_invoke_callbacks);
	else
		INIT_WORK(&endpoint->work, endpoint_redirect_message_to_user);

	return endpoint;
}

struct commu_endpoint * create_msg_endpoint(char *name, u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length, struct commu_callback_map *callbacks)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;

	channel = get_commu_channel_by_name(name);
	if (!channel)
		return NULL;

	endpoint = open_an_endpoint(channel, tx_addr, rx_addr,
		vf_id, queue_length);
	endpoint->type = 2;
	endpoint->channel->ep[vf_id] = endpoint;

	if (endpoint->channel->kernel_channel)
		INIT_WORK(&endpoint->work, endpoint_recv_messages);
	else
		INIT_WORK(&endpoint->work, endpoint_redirect_message_to_user);

	return endpoint;
}

int commu_reset_vqueue(struct commu_vqueue *vqueue)
{
	vqueue->ops->free(vqueue->real_queue);
	vqueue->ops = NULL;
	vqueue->real_queue = NULL;
	vqueue->entry_size = 0;
	vqueue->base_addr = NULL;

	return 0;
}

struct commu_endpoint * create_port_endpoint(char *name, u64 tx_addr, u64 rx_addr,
		u16 vf_id, u32 queue_length)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;

	channel = get_commu_channel_by_name(name);
	if (!channel)
		return NULL;

	endpoint = open_an_endpoint(channel, tx_addr, rx_addr,
		vf_id, queue_length);
	endpoint->type = 3;
	endpoint->channel->port_ep[vf_id] = endpoint;

	endpoint->ports = cn_kzalloc(sizeof(struct commu_port_proxy) *
			COMMU_ENDPOINT_MAX_PORT, GFP_KERNEL);

	if (!endpoint->ports) {
		pr_info("alloc ports failed\n");
		commu_reset_vqueue(&endpoint->tx);
		commu_reset_vqueue(&endpoint->rx);
		cn_kfree(endpoint);
		return NULL;
	}

	if (endpoint->channel->kernel_channel)
		INIT_WORK(&endpoint->work, endpoint_recv_port_messages);
	else
		INIT_WORK(&endpoint->work, endpoint_redirect_port_message_to_user);

	return endpoint;
}

int close_an_endpoint(struct commu_endpoint *ep)
{
	/* remove ep from polling list */
	/* NOT really remove it.
	 * just set free_me sign to 1
	 * polling thread will remove the ep */
	ep->free_me = 1;
	mutex_destroy(&ep->ep_mutex);
	/* release tx rx safely */
	commu_reset_vqueue(&ep->tx);
	commu_reset_vqueue(&ep->rx);

	return 0;
}

int commu_wait_for_message_arm(struct commu_channel *channel, void *buf, int *size, int *vf_id)
{
	int seq;
	struct commu_endpoint *ep;
	wait_event_interruptible(channel->waitqueue, (channel->current_ep != NULL));

	ep = channel->current_ep;
	if(!ep)
		return -1;

	seq = ep->tx.ops->dequeue(ep->tx.real_queue, buf, size);
	*vf_id = ep->vf_id;

	channel->current_ep = NULL;
	ep->on_polling = 0;
	ep->channel->on_polling = 0;
	return seq;
}

int commu_send_message_arm(struct commu_channel *channel, void *buf, int size, int vf_id, int seq)
{
	int ret;
	struct commu_endpoint *ep;
	ep = channel->ep[vf_id];

	if(!ep)
		return -1;
	ret = ep->rx.ops->enqueue(ep->rx.real_queue, buf, size, seq);

	ep->channel->doorbell(ep->vf_id, ep->pair);
	return ret;
}

struct commu_endpoint * get_commu_endpoint_by_name(struct commu_channel *channel, int vf_id)
{
	if (!channel)
		return NULL;
	else
		return channel->ep[vf_id];
}

int query_commu_endpoint_by_name(struct commu_channel *channel, int vf_id)
{
	if (!channel)
		return 0;

	if (channel->ep[vf_id])
		return 1;
	else
		return 0;
}
