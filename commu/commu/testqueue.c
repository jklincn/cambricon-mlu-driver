#include "cndrv_debug.h"
#include "testqueue.h"
//#include <asm-generic/barrier.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/io.h>
#include "queue_common.h"

#define TESTQ_DEBUG

#ifdef TESTQ_DEBUG
#define TESTQ_DBG(string, arg...) \
do { \
	pr_debug(string, ##arg); \
} while (0)
#else
#define TESTQ_DBG(string, arg...) \
do { \
	\
} while (0)
#endif


/* @src is the pointer to data stored in little-endian fashion */
static inline u32 fast_le_checksum32(unsigned char const *src, unsigned int len)
{
	unsigned int l = len >> 2;
	unsigned int remain = len & 3U;
	int i;
	u32 checksum = 0;

	while (l--) {
		checksum ^= le32_to_cpu(*(__le32 const *)src);
		src += 4;
	}

	for (i = 0; i < remain; ++i) {
		checksum ^= ((*src++) << (i << 3));
	}

	return checksum;
}

static inline int testq_is_empty_updatehead(struct testq_queue *queue)
{
	queue->head = *(queue->shadow_head);
	/* write barrier */
	wmb();

	if (queue->head == queue->tail)
		return 1;
	else
		return 0;
}

static inline int testq_is_empty(struct testq_queue *queue)
{

	if (queue->head == queue->tail)
		return 1;
	else
		return 0;
}

static inline int testq_is_full(struct testq_queue* queue) {
	/* no special loop to check ring->tail, just check before each put */
	queue->tail = *(queue->shadow_tail);

	if (queue->head - queue->tail < queue->num - 1)
		return 0;
	else
		return 1;
}

int testq_reset(struct testq_queue *queue, void *addr, int size, void *core_set) {
	queue->core_set = (struct cn_core_set *)core_set;
	queue->ring = addr;
	queue->head = 0;
	queue->tail = 0;
	queue->num = size;
	spin_lock_init(&queue->lock);
	queue->seq = 1;
	queue->flag = 0;

	/*
	 * In both sides of pcie, this init code will be called, so
	 * only after both sides finished init, data can be sent.
	 */
	queue->ring->head = 0;
	queue->ring->tail = 0;
	queue->err_num = 0;

	return 0;
}

void testq_set_sync_write(void *queue, u64 sync_write_pa)
{
	struct testq_queue *q = (struct testq_queue *)queue;

	q->en_sync_write = 1;
	q->sync_write_pa = sync_write_pa;
}

static void inline
testq_put_update_head(struct testq_queue *queue)
{
	queue->head++;

#ifdef CONFIG_CNDRV_EDGE
	wmb();
	*(queue->shadow_head) = queue->head;
#else
	if (queue->en_sync_write) {
		 cn_bus_sync_write_val(queue->core_set->bus_set,
			queue->sync_write_pa, queue->head);
	} else {
		cn_bus_mb(queue->core_set->bus_set);
		*(queue->shadow_head) = queue->head;
	}
#endif

	wmb();
}

int testq_put(struct testq_queue* queue, void *buf, int size, int seq, uint16_t port) {
#define TESTQ_DESC_HDR_SIZE (offsetof(struct testq_desc, data))
	struct testq_desc* dest;
	u32 head;
	char hdr_buf[TESTQ_DESC_HDR_SIZE];
	struct testq_desc *hdr = (struct testq_desc *)hdr_buf;

	size = size < COMMU_TESTQ_DATA_BUF_SIZE ? size : COMMU_TESTQ_DATA_BUF_SIZE;

	hdr->seq = seq;
	hdr->size = size;
	hdr->flag = 0;
	hdr->port = port;
	spin_lock(&queue->lock);
	/* move this check in lock, we can get head more precisely when release*/
	if (testq_is_stopped(queue)) {
		spin_unlock(&queue->lock);
		return -1;
	}

	if (testq_is_suspended(queue)) {
		spin_unlock(&queue->lock);
		return -3;
	}

	if (testq_is_full(queue)) {
		spin_unlock(&queue->lock);
		return 0;
	}

	if(seq == 0) {
		/* for commu_send_message_once better performance */
		hdr->seq = __sync_add_and_fetch(&queue->seq, 1);
		if (unlikely(hdr->seq == 0)) {
			hdr->seq = __sync_add_and_fetch(&queue->seq, 1);
		}
	}

	head = queue->head & (queue->num - 1);
	TESTQ_DBG("==in testq_put %d== %px == %px\n", head, queue->ring, queue->ring->buf);

	dest = (struct testq_desc*)(&queue->ring->buf);
	dest += head;

	#ifdef CONFIG_CNDRV_EDGE
	memcpy(dest, hdr, TESTQ_DESC_HDR_SIZE);
	memcpy(dest->data, buf, size);
	#else
	memcpy_toio(dest, hdr, TESTQ_DESC_HDR_SIZE);
	memcpy_toio(dest->data, buf, size);

	#endif

	testq_put_update_head(queue);
	TESTQ_DBG("==in testq_put %d== %px == %px\n", head, queue->ring, queue->ring->buf);
	TESTQ_DBG("==in testq_put == %d\n", dest->size);
	spin_unlock(&queue->lock);

	TESTQ_DBG("%s -- [native head]%d -- [remote head]%d\n",
			__func__,
			queue->head,
			queue->ring->head);

	return 1;
#undef TESTQ_DESC_HDR_SIZE
}

#ifndef CONFIG_CNDRV_EDGE
static void __testq_save_err_info(
		struct testq_queue *queue,
		void *buf,
		u32 tail, int size,
		int seq,
		u32 origin_checksum,
		u32 checksum)
{
	struct testq_errinfo *errinfo;
	u64 index;

	index = __sync_fetch_and_add(&queue->err_num, 1) % TESTQ_MAX_ERR;

	errinfo = &queue->err_buf[index];

	errinfo->tail = tail;
	errinfo->size = size;
	errinfo->desc_seq = seq;
	errinfo->origin_checksum = origin_checksum;
	errinfo->checksum = checksum;

	/* save frame message buf */
	memcpy(errinfo->buf, buf, size);

	/* save ring buffer */
	memcpy_fromio(errinfo->data, queue->ring, COMMU_ENDPOINT_QUEUE_SIZE);

}
#endif

int testq_get(struct testq_queue* queue, void *buf, int *size) {
	struct testq_desc* desc;
	u32 tail;
	int desc_seq;
	__le32 origin_checksum;
	u32 checksum;

	if (testq_is_empty(queue))
		return 0;

	tail = queue->tail & (queue->num - 1);
	TESTQ_DBG("==in testq_get %d== %px == %px\n", tail, queue->ring, queue->ring->buf);
	desc = (struct testq_desc*)(&queue->ring->buf);
	desc += tail;

	memcpy_fromio(buf, desc->data, desc->size);

	*size = desc->size;

	desc_seq = desc->seq;
	/* checksum of @desc must be laid out in a little-endian fashion */
	origin_checksum = desc->checksum;
	checksum = fast_le_checksum32((unsigned char const *)buf, *size);

	if (le32_to_cpu(origin_checksum) != checksum) {
		pr_err("%s@%d check sum %#x failed(expect for %#x)", __func__,
				__LINE__, checksum, le32_to_cpu(origin_checksum));
		pr_err("%s@%d tail:%u size:%d seq:%d ", __func__,
				__LINE__, tail, *size, desc_seq);
#ifndef CONFIG_CNDRV_EDGE
		__testq_save_err_info(queue, buf, tail, *size, desc_seq,
				le32_to_cpu(origin_checksum), checksum);
#endif
		return 0;
	}

	spin_lock(&queue->lock);
	__sync_fetch_and_add(&queue->tail, 1);

	*(queue->shadow_tail) = queue->tail;

	/* write barrier */
	wmb();
	spin_unlock(&queue->lock);

	TESTQ_DBG("%s -- [native tail]%d -- [remote tail]%d\n",
			__func__,
			queue->tail,
			queue->ring->tail);

	return desc_seq;
}

int testq_get_rpc(struct testq_queue *queue, void *buf, int *size)
{
	struct testq_desc *desc;
	u32 tail;
	int desc_seq;

	if (testq_is_empty(queue))
		return 0;

	tail = queue->tail & (queue->num - 1);
	TESTQ_DBG("==in testq_get %d== %px == %px\n", tail, queue->ring, queue->ring->buf);
	desc = (struct testq_desc *)(&queue->ring->buf);
	desc += tail;

	memcpy_fromio(buf, desc->data + 16, desc->size - 16);

	*size = desc->size - 16;

	desc_seq = desc->seq;

	spin_lock(&queue->lock);
	__sync_fetch_and_add(&queue->tail, 1);

	*(queue->shadow_tail) = queue->tail;
	/* write barrier */
	wmb();
	spin_unlock(&queue->lock);

	TESTQ_DBG("%s -- [native tail]%d -- [remote tail]%d\n",
			__func__,
			queue->tail,
			queue->ring->tail);

	return desc_seq;
}

struct testq_queue * testq_alloc(void *addr, int size, void *core_set) {
	struct testq_queue *queue;

	queue = cn_kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue) {
		TESTQ_DBG("kzalloc queue error!");
		return NULL;
	}

	testq_reset(queue, addr, size, core_set);

	return queue;
}

int testq_enqueue(void* queue, void *buf, int size, int seq) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return testq_put(q, buf, size, seq, 0);
}

int testq_dequeue_rpc(void *queue, void *buf, int *size)
{
	struct testq_queue *q = (struct testq_queue *)queue;

	return testq_get_rpc(q, buf, size);
}

int testq_dequeue(void* queue, void *buf, int *size) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return testq_get(q, buf, size);
}

void *testq_newqueue(void *addr, int size, void *core_set) {
	return (void*)testq_alloc(addr, size, core_set);
}

int testq_query_new(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	int is_empty = 0;

	spin_lock(&q->lock);
	is_empty = testq_is_empty_updatehead(q);
	spin_unlock(&q->lock);

	return !is_empty;
}

int testq_search_by_seq(void* queue, int seq) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return q->head;
}

int testq_glance_tail(void* q) {
	struct testq_queue *queue = (struct testq_queue *)q;
	struct testq_desc* desc;
	u32 tail;
	int seq = 0;

	spin_lock(&queue->lock);
	if (testq_is_empty_updatehead(queue)) {
		spin_unlock(&queue->lock);
		return 0;
	}

	tail = queue->tail & (queue->num - 1);
	desc = (struct testq_desc*)(&queue->ring->buf);
	desc += tail;
	seq = desc->seq;
	spin_unlock(&queue->lock);

	return seq;
}

int testq_generate_seq(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	int seq = 0;

	seq = __sync_add_and_fetch(&q->seq, 1);
	if (unlikely(seq == 0)) {
		seq = __sync_add_and_fetch(&q->seq, 1);
	}

	return seq;
}

void* testq_get_tail_addr(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return (void*)&q->tail;
}

void* testq_get_head_addr(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return (void*)&q->head;
}

void* testq_get_ring_tail_addr(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return (void*)&q->ring->tail;
}

void* testq_get_ring_head_addr(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return (void*)&q->ring->head;
}

int testq_set_shadow_tail(void* queue, void* tail) {
	struct testq_queue *q = (struct testq_queue *)queue;
	q->shadow_tail = (u32*)tail;
	return 0;
}

void *testq_get_shadow_tail(void *queue)
{
	struct testq_queue *q = (struct testq_queue *)queue;

	return (void *)q->shadow_tail;
}

int testq_set_shadow_head(void* queue, void* head) {
	struct testq_queue *q = (struct testq_queue *)queue;
	q->shadow_head = (u32*)head;
	return 0;
}

int testq_free(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	cn_kfree(q);

	return 0;
}

int testq_stop_enqueue(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	/* should atomic or lock */
	set_bit(COMMU_STOP_ENQUEUE, (long unsigned int *)&q->flag);
	return 0;
}

int testq_restart_enqueue(void *queue)
{
	struct testq_queue *q = (struct testq_queue *)queue;
	/* should atomic or lock */
	clear_bit(COMMU_STOP_ENQUEUE, (unsigned long int *)&q->flag);
	return 0;
}

int testq_is_stopped(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return test_bit(COMMU_STOP_ENQUEUE, (long unsigned int *)&q->flag);
}

int testq_suspend_enqueue(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	/* should atomic or lock */
	set_bit(COMMU_SUSPEND_ENQUEUE, (long unsigned int *)&q->flag);
	//q->flag |= COMMU_SUSPEND_ENQUEUE;
	return 0;
}

int testq_resume_enqueue(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	clear_bit(COMMU_SUSPEND_ENQUEUE, (long unsigned int *)&q->flag);
	//q->flag &= ~COMMU_SUSPEND_ENQUEUE;
	return 0;
}

int testq_is_suspended(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return test_bit(COMMU_SUSPEND_ENQUEUE, (long unsigned int *)&q->flag);
}

uint16_t testq_glance_port(void* q) {
	struct testq_queue *queue = (struct testq_queue *)q;
	struct testq_desc* desc;
	u32 tail;

	if (testq_is_empty(queue))
		return 0;

	tail = queue->tail & (queue->num - 1);
	desc = (struct testq_desc*)(&queue->ring->buf);
	desc += tail;

	return desc->port;
}

int testq_peek(void* q, void *buf, int *size) {
	struct testq_queue *queue = (struct testq_queue *)q;
	struct testq_desc* desc;
	u32 tail;

	if (testq_is_empty(queue))
		return 0;

	spin_lock(&queue->lock);
	tail = queue->tail & (queue->num - 1);
	TESTQ_DBG("==in testq_peek %d== %px == %px\n", tail, queue->ring, queue->ring->buf);
	desc = (struct testq_desc*)(&queue->ring->buf);
	desc += tail;

	memcpy_fromio(buf, desc->data, desc->size);

	*size = desc->size;

	spin_unlock(&queue->lock);

	return desc->seq;
}

int testq_skip(void* q) {
	struct testq_queue *queue = (struct testq_queue *)q;
	u32 tail;

	if (testq_is_empty(queue))
		return 0;

	spin_lock(&queue->lock);
	tail = queue->tail & (queue->num - 1);
	TESTQ_DBG("==in testq_skip %d== %px == %px\n", tail, queue->ring, queue->ring->buf);
	queue->tail++;

	wmb();
	*(queue->shadow_tail) = queue->tail;
	spin_unlock(&queue->lock);

	return 1;
}

int testq_enqueue_port(void* queue, void *buf, int size, int seq, uint16_t port) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return testq_put(q, buf, size, seq, port);
}

int testq_query_full(void* queue) {
	struct testq_queue *q = (struct testq_queue *)queue;
	return testq_is_full(q);
}

int testq_dump_queue(void* q) {
	struct testq_queue *queue = (struct testq_queue *)q;
	struct testq_desc *desc, *desc_base;
	u32 i;

	desc_base = (struct testq_desc *)(&queue->ring->buf);
	pr_info("queue->flag %llx\n", queue->flag);
	for (i = 0; i < 32; i++) {
		desc = desc_base + i;
		pr_info("cur%u flag%x  rt%u rh%u seq%d port%d "
				"head %u tail %u\n",
				i, desc->flag, *queue->shadow_tail,
				queue->ring->head, desc->seq, desc->port,
				queue->ring->head & (queue->num - 1),
				*queue->shadow_tail & (queue->num - 1));
	}

	return 0;
}

int testq_dump_errinfo(void *q)
{
#ifdef CONFIG_CNDRV_EDGE
	pr_info("%s ---- dumpinfo not support on edge ----\n", __func__);
#else
	struct testq_queue *queue = (struct testq_queue *)q;
	struct testq_errinfo *einfo;
	int cnt;
	u64 frame_buf_size = COMMU_TESTQ_DATA_BUF_SIZE/sizeof(u64);
	u64 *buf;
	u32 i, j;

	cnt = (queue->err_num < TESTQ_MAX_ERR) ? queue->err_num : TESTQ_MAX_ERR;
	pr_info("%s ---- dump saved errinfo num:%d ----\n", __func__, cnt);
	for (i = 0; i < cnt; i++) {
		einfo = &queue->err_buf[i];
		buf = (u64 *)einfo->buf;
		pr_info("%s: err[%d] seq:%d tail:%u size:%d checksum(%#08x - %#08x)\n",
				__func__, i, einfo->desc_seq, einfo->tail,
				einfo->size, einfo->origin_checksum,
				einfo->checksum);
		pr_info("Dump buf data:\n");
		for (j = 0; j < frame_buf_size; j += 4) {
			pr_info("%04u %016llX %016llX %016llX %016llX\n",
					j, buf[j], buf[j+1],
					buf[j+2], buf[j+3]);
		}
		pr_info("......\n");
		pr_info("Dump ring data:\n");
		for (j = 0; j < COMMU_ENDPOINT_QUEUE_SIZE_64; j += 4) {
			pr_info("%04u %016llX %016llX %016llX %016llX\n",
					j, einfo->data[j], einfo->data[j+1],
					einfo->data[j+2], einfo->data[j+3]);
		}
	}
	pr_info("%s ---- dump finish ----\n", __func__);
	__sync_lock_release(&queue->err_num);
#endif
	return 0;
}

int testq_set_desc_flag(void *q, int index, uint16_t flag)
{
	struct testq_queue *queue = (struct testq_queue *)q;
	struct testq_desc *desc, *desc_base;
	u32 tail;

	desc_base = (struct testq_desc *)(&queue->ring->buf);
	tail = index & (queue->num - 1);
	desc = desc_base + tail;

	desc->flag = flag;
	pr_info("tail %u/%d flag%x\n", tail, index, desc->flag);

	return 0;
}

struct commu_ops testq_ops = {
	.enqueue = testq_enqueue,
	.dequeue = testq_dequeue,
	.dequeue_rpc = testq_dequeue_rpc,
	.alloc = testq_newqueue,
	.query_new = testq_query_new,
	.search = testq_search_by_seq,
	.glance = testq_glance_tail,
	.gen_seq = testq_generate_seq,
	.tail_addr = testq_get_tail_addr,
	.head_addr = testq_get_head_addr,
	.get_ring_tail = testq_get_ring_tail_addr,
	.get_ring_head = testq_get_ring_head_addr,
	.set_shadow_tail = testq_set_shadow_tail,
	.set_shadow_head = testq_set_shadow_head,
	.get_shadow_tail = testq_get_shadow_tail,
	.free = testq_free,
	.stop = testq_stop_enqueue,
	.restart = testq_restart_enqueue,
	.is_stopped = testq_is_stopped,
	.suspend = testq_suspend_enqueue,
	.resume = testq_resume_enqueue,
	.is_suspended = testq_is_suspended,
	/* for port */
	.glance_port = testq_glance_port,
	.enqueue_port = testq_enqueue_port,
	/* for ipu */
	.peek =  testq_peek,
	.skip =  testq_skip,
	.is_full = testq_query_full,
	.dump_queue = testq_dump_queue,
	.dump_errinfo = testq_dump_errinfo,
	.set_desc_flag = testq_set_desc_flag,
	.set_sync_write = testq_set_sync_write,
};
