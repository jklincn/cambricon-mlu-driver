#include "cndrv_debug.h"
#include "rtequeue.h"
//#include <asm-generic/barrier.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "queue_common.h"

//#define RTEQ_DEBUG
#define RTEQ_INF

#ifdef RTEQ_DEBUG
#define RTEQ_DBG(string, arg...) \
do { \
	pr_debug(string, ##arg); \
} while (0)
#else
#define RTEQ_DBG(string, arg...) \
do { \
	\
} while (0)
#endif

#ifdef RTEQ_INF
#define RTEQ_INFO(string, arg...) \
do { \
	pr_info("[COMMU]%s[%d] " string, __func__, __LINE__, ##arg); \
} while (0)
#else
#define RTEQ_INFO(string, arg...) \
do { \
	\
} while (0)
#endif

static inline int rteq_is_empty(struct rteq_queue *queue)
{
	if (*(queue->shadow_head) == *(queue->shadow_tail))
		return 1;
	else
		return 0;
}

static inline int rteq_is_full(struct rteq_queue *queue)
{
	/* no special loop to check ring->tail, just check before each put */
	if (*(queue->shadow_head) - *(queue->shadow_tail) < queue->num - 1)
		return 0;
	else
		return 1;
}

int rteq_reset(struct rteq_queue *queue, void *addr, int size) {
	queue->ring = addr;
	queue->head = 0;
	queue->tail = 0;
	queue->num = size;
	spin_lock_init(&queue->lock);
	atomic_set(&queue->seq, 1);
	queue->flag = 0;

	/*
	 * In both sides of pcie, this init code will be called, so
	 * only after both sides finished init, data can be sent.
	 */
	queue->ring->head = 0;
	queue->ring->tail = 0;

	return 0;
}

int rteq_put(struct rteq_queue* queue, void *buf, int size, int seq, uint16_t port) {
	struct rteq_desc* dest;
	u32 head;
	u32 *d, *src;
	int i;
	unsigned long flags;
	size = size < COMMU_RTEQ_DATA_BUF_SIZE ? size : COMMU_RTEQ_DATA_BUF_SIZE;

	spin_lock_irqsave(&queue->lock, flags);
	/* move this check in lock, we can get head more precisely when release*/
	if (rteq_is_stopped(queue)) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return -1;
	}

	if (rteq_is_suspended(queue)) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return -3;
	}

	if (rteq_is_full(queue)) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return 0;
	}

	head = queue->head & (queue->num - 1);
	RTEQ_DBG("==in rteq_put %d== %px == %px\n", head, queue->ring, queue->ring->buf);

	dest = (struct rteq_desc*)(&queue->ring->buf);
	dest += head;
	dest->seq = seq;
	dest->size = size;
	dest->flag = 0;
	dest->port = port;
	/*memcpy(dest->data, buf, size);*/
	for (i = 0, d=(u32*)dest->data, src=(u32*)buf; i < (size >> 2); i++) {
		*(d + i) = *(src + i);
	}
	memcpy(d+i, src+i, size%4);

	//queue->head++;
	__sync_fetch_and_add(&queue->head, 1);

	wmb();
	RTEQ_DBG("==in rteq_put %d== %px == %px\n", head, queue->ring, queue->ring->buf);
	RTEQ_DBG("==in rteq_put == %d\n", dest->size);
	*(queue->shadow_head) = queue->head;
	spin_unlock_irqrestore(&queue->lock, flags);

	RTEQ_DBG("%s -- [native head]%d -- [remote head]%d\n",
			__func__,
			queue->head,
			queue->ring->head);

	return 1;
}

int rteq_get(struct rteq_queue* queue, void *buf, int *size) {
	struct rteq_desc* desc;
	u32 tail;
	//unsigned long flags;

	if (rteq_is_empty(queue))
		return 0;

	//spin_lock_irqsave(&queue->lock, flags);
	tail = queue->tail & (queue->num - 1);
	RTEQ_DBG("==in rteq_get %d== %px == %px\n", tail, queue->ring, queue->ring->buf);
	desc = (struct rteq_desc*)(&queue->ring->buf);
	desc += tail;

	memcpy(buf, desc->data, desc->size);
	*size = desc->size;

	queue->tail++;

	wmb();
	*(queue->shadow_tail) = queue->tail;
	//spin_unlock_irqrestore(&queue->lock, flags);

	RTEQ_DBG("%s -- [native tail]%d -- [remote tail]%d\n",
			__func__,
			queue->tail,
			queue->ring->tail);

	return desc->seq;

}

struct rteq_queue * rteq_alloc(void *addr, int size) {
	struct rteq_queue *queue;

	queue = cn_kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue) {
		RTEQ_DBG("kzalloc queue error!");
		return NULL;
	}

	rteq_reset(queue, addr, size);

	return queue;
}

int rteq_enqueue(void* queue, void *buf, int size, int seq) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return rteq_put(q, buf, size, seq, 0);
}

int rteq_dequeue(void* queue, void *buf, int *size) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return rteq_get(q, buf, size);
}

void *rteq_newqueue(void *addr, int size, void *core_set) {
	/* core_set not use in this interface */
	return (void*)rteq_alloc(addr, size);
}

int rteq_query_new(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return !rteq_is_empty(q);
}

int rteq_search_by_seq(void* queue, int seq) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return q->head;
}

int rteq_glance_tail(void* q) {
	struct rteq_queue *queue = (struct rteq_queue *)q;
	struct rteq_desc* desc;
	u32 tail;

	if (rteq_is_empty(queue))
		return 0;

	tail = queue->tail & (queue->num - 1);
	desc = (struct rteq_desc*)(&queue->ring->buf);
	desc += tail;

	return desc->seq;
}

int rteq_generate_seq(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	/*return q->head + 0xf000;*/
	return atomic_inc_return(&q->seq);
}

void* rteq_get_tail_addr(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return (void*)&q->tail;
}

void* rteq_get_head_addr(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return (void*)&q->head;
}

void* rteq_get_ring_tail_addr(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return (void*)&q->ring->tail;
}

void* rteq_get_ring_head_addr(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return (void*)&q->ring->head;
}

int rteq_set_shadow_tail(void* queue, void* tail) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	q->shadow_tail = (u32*)tail;
	return 0;
}

void *rteq_get_shadow_tail(void *queue)
{
	struct rteq_queue *q = (struct rteq_queue *)queue;

	return (void *)q->shadow_tail;
}

int rteq_set_shadow_head(void* queue, void* head) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	q->shadow_head = (u32*)head;
	return 0;
}

int rteq_free(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	cn_kfree(q);

	return 0;
}

int rteq_stop_enqueue(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	/* should atomic or lock */
	set_bit(COMMU_STOP_ENQUEUE, (long unsigned int *)&q->flag);
	return 0;
}

int rteq_is_stopped(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return test_bit(COMMU_STOP_ENQUEUE, (long unsigned int *)&q->flag);
}

int rteq_suspend_enqueue(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	/* should atomic or lock */
	set_bit(COMMU_SUSPEND_ENQUEUE, (long unsigned int *)&q->flag);
	//q->flag |= COMMU_SUSPEND_ENQUEUE;
	return 0;
}

int rteq_resume_enqueue(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	clear_bit(COMMU_SUSPEND_ENQUEUE, (long unsigned int *)&q->flag);
	//q->flag &= ~COMMU_SUSPEND_ENQUEUE;
	return 0;
}

int rteq_is_suspended(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return test_bit(COMMU_SUSPEND_ENQUEUE, (long unsigned int *)&q->flag);
}

uint16_t rteq_glance_port(void* q) {
	struct rteq_queue *queue = (struct rteq_queue *)q;
	struct rteq_desc* desc;
	u32 tail;

	if (rteq_is_empty(queue))
		return 0;

	tail = queue->tail & (queue->num - 1);
	desc = (struct rteq_desc*)(&queue->ring->buf);
	desc += tail;

	return desc->port;
}

int rteq_peek(void* q, void *buf, int *size) {
	struct rteq_queue *queue = (struct rteq_queue *)q;
	struct rteq_desc* desc;
	u32 tail;
	unsigned long flags;

	if (rteq_is_empty(queue))
		return 0;

	spin_lock_irqsave(&queue->lock, flags);
	tail = queue->tail & (queue->num - 1);
	RTEQ_DBG("==in rteq_peek %d== %px == %px\n", tail, queue->ring, queue->ring->buf);
	desc = (struct rteq_desc*)(&queue->ring->buf);
	desc += tail;

	memcpy(buf, desc->data, desc->size);
	*size = desc->size;

	spin_unlock_irqrestore(&queue->lock, flags);

	return desc->seq;
}

int rteq_skip(void* q) {
	struct rteq_queue *queue = (struct rteq_queue *)q;
	u32 tail;
	unsigned long flags;

	if (rteq_is_empty(queue))
		return 0;

	spin_lock_irqsave(&queue->lock, flags);
	tail = queue->tail & (queue->num - 1);
	RTEQ_DBG("==in rteq_skip %d== %px == %px\n", tail, queue->ring, queue->ring->buf);
	queue->tail++;

	wmb();
	*(queue->shadow_tail) = queue->tail;
	spin_unlock_irqrestore(&queue->lock, flags);

	return 1;
}

int rteq_enqueue_port(void* queue, void *buf, int size, int seq, uint16_t port) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return rteq_put(q, buf, size, seq, port);
}

int rteq_query_full(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return rteq_is_full(q);
}

void* rteq_get_user_seq_addr(void* queue) {
	struct rteq_queue *q = (struct rteq_queue *)queue;
	return (void*)&q->user_seq;
}

int rteq_set_desc_flag_sigint(void *q, int port, char *dir)
{
	struct rteq_queue *queue = (struct rteq_queue *)q;
	struct rteq_desc *desc, *desc_base;
	u32 i, tail;
	int cnt = 0;

	desc_base = (struct rteq_desc *)(&queue->ring->buf);
	for (i = *queue->shadow_tail; i <= queue->ring->head; i++) {
		tail = i & (queue->num - 1);
		desc = desc_base + tail;
		RTEQ_DBG("loop %d in queue port%d seq%d size%d flag%d %s\n",i ,desc->port, desc->seq,
				desc->size, desc->flag, desc->data);

		if (desc->flag != 0 || desc->port != port)
			continue;

		/*
		 * __sync_fetch_and_or(&desc->flag, (u16)COMMU_DESC_SIGINT);
		 * __sync_fetch_and_or may return 0xffff in some test machine,
		 * it may be caused by TLP timeout when RC is not support
		 * AtomicOps.
		 */
		desc->flag |= (u16)COMMU_DESC_SIGINT;
		cnt++;
		RTEQ_DBG("tail %u/%u port %d flag%d ring t%u h%u\n",
				tail, i, port, desc->flag,
				*queue->shadow_tail, queue->ring->head);
	}

	if (cnt)
		RTEQ_INFO("%s current ring rt %u rh%u  %d descs have been set SIGINT, port is %d\n",
			dir, *queue->shadow_tail, queue->ring->head, cnt, port);
	return 0;
}

int rteq_set_desc_flag_sigint_rpc(void *q, void *eventfd, char *dir)
{
	struct rteq_queue *queue = (struct rteq_queue *)q;
	struct rteq_desc *desc, *desc_base;
	u32 i, tail;
	u64 *fd_in_desc;
	int cnt = 0;
	desc_base = (struct rteq_desc *)(&queue->ring->buf);
	for (i = *queue->shadow_tail; i <= queue->ring->head; i++) {
		tail = i & (queue->num - 1);
		desc = desc_base + tail;
		fd_in_desc = (u64 *)desc->data;
		fd_in_desc++;
		RTEQ_DBG("loop %d in queue fd_in_desc%llx seq%d size%d flag%d %s\n",i ,*fd_in_desc, desc->seq,
				desc->size, desc->flag, desc->data);

		if (desc->flag != 0 || *fd_in_desc != (u64)eventfd)
			continue;

		desc->flag |= (u16)COMMU_DESC_SIGINT;
		cnt++;
		RTEQ_INFO("cur%u/%u flag%d  ring t%u h%u seq%d, listener %llx, pid %d\n",
				tail, i, desc->flag, *queue->shadow_tail,
				queue->ring->head, desc->seq,
				(u64)*fd_in_desc, current->pid);
	}

	if (cnt)
		RTEQ_INFO("%s current ring rt %u rh%u  %d descs have been set SIGINT, listener is %llx\n",
			dir, *queue->shadow_tail, queue->ring->head, cnt, (u64)eventfd);

	return 0;
}

int rteq_dump_queue(void* q) {
	struct rteq_queue *queue = (struct rteq_queue *)q;
	struct rteq_desc *desc, *desc_base;
	u64 *fd_in_desc;
	u32 i;

	desc_base = (struct rteq_desc *)(&queue->ring->buf);
	for (i = 0; i < 32; i++) {
		desc = desc_base + i;
		fd_in_desc = (u64 *)desc->data;
		fd_in_desc++;
		if (desc->port == 0)
			RTEQ_INFO("cur%u flag%x  rt%u rh%u seq%d listener %llx head %u tail %u\n",
				i, desc->flag, *queue->shadow_tail,
				queue->ring->head, desc->seq, *fd_in_desc,
				queue->ring->head & (queue->num - 1),
				*queue->shadow_tail & (queue->num - 1));
		else
			RTEQ_INFO("cur%u flag%x  rt%u rh%u seq%d port%d head %u tail %u\n",
				i, desc->flag, *queue->shadow_tail,
				queue->ring->head, desc->seq, desc->port,
				queue->ring->head & (queue->num - 1),
				*queue->shadow_tail & (queue->num - 1));
	}

	return 0;
}

int rteq_set_desc_flag(void *q, int index, uint16_t flag)
{
	struct rteq_queue *queue = (struct rteq_queue *)q;
	struct rteq_desc *desc, *desc_base;
	u32 tail;

	desc_base = (struct rteq_desc *)(&queue->ring->buf);
	tail = index & (queue->num - 1);
	desc = desc_base + tail;

	desc->flag = flag;
	RTEQ_INFO("tail %u/%d flag%x\n", tail, index, desc->flag);

	return 0;
}

struct commu_ops rteq_ops = {
	.enqueue = rteq_enqueue,
	.dequeue = rteq_dequeue,
	.alloc = rteq_newqueue,
	.query_new = rteq_query_new,
	.search = rteq_search_by_seq,
	.glance = rteq_glance_tail,
	.gen_seq = rteq_generate_seq,
	.tail_addr = rteq_get_tail_addr,
	.head_addr = rteq_get_head_addr,
	.get_ring_tail = rteq_get_ring_tail_addr,
	.get_ring_head = rteq_get_ring_head_addr,
	.set_shadow_tail = rteq_set_shadow_tail,
	.set_shadow_head = rteq_set_shadow_head,
	.get_shadow_tail = rteq_get_shadow_tail,
	.free = rteq_free,
	.stop = rteq_stop_enqueue,
	.is_stopped = rteq_is_stopped,
	.suspend = rteq_suspend_enqueue,
	.resume = rteq_resume_enqueue,
	.is_suspended = rteq_is_suspended,
	/* for port */
	.glance_port = rteq_glance_port,
	.enqueue_port = rteq_enqueue_port,
	/* for ipu */
	.peek =  rteq_peek,
	.skip =  rteq_skip,
	.is_full = rteq_query_full,
	.user_seq_addr = rteq_get_user_seq_addr,
	.set_flag_sigint = rteq_set_desc_flag_sigint,
	.set_rpc_sigint = rteq_set_desc_flag_sigint_rpc,
	.dump_queue = rteq_dump_queue,
	.dump_errinfo = NULL,
	.set_desc_flag = rteq_set_desc_flag,
};
