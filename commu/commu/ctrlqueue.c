#include "ctrlqueue.h"
#include <linux/version.h>
/*
 *#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0))
 *#include <asm-generic/barrier.h>
 *#endif
 *#include <linux/printk.h>
 */
#include <linux/slab.h>

#define COMMU_DEBUG

#ifdef COMMU_DEBUG
#define COMMU_DBG(string, arg...) \
do { \
	pr_debug(string, ##arg); \
} while (0)
#else
#define COMMU_DBG(string, arg...) \
do { \
	\
} while (0)
#endif

static inline int ctrlq_is_empty(struct ctrlq_queue* queue){
	queue->head = *queue->shadow_head;

	if (queue->head == queue->tail)
		return 1;
	else
		return 0;
}

static inline int ctrlq_is_full(struct ctrlq_queue* queue) {
	/* no special loop to check ring->tail, just check before each put */
	queue->tail = *queue->shadow_tail;

	if (queue->head - queue->tail < queue->num)
		return 0;
	else
		return 1;
}

void ctrlq_alloc(struct ctrlq_queue *queue, void *addr, int size)
{
	queue->ring = addr;
	queue->head = 0;
	queue->tail = 0;
	queue->num = size;
	spin_lock_init(&queue->lock);
	atomic_set(&queue->seq, 1);

	queue->ring->head = 0;
	queue->ring->tail = 0;

	queue->shadow_head = &(queue->ring->head);
	queue->shadow_tail = &(queue->ring->tail);

//	memset(addr, 0x0, 8 + sizeof(struct ctrlq_desc)*size);
}

int32_t ctrlq_set_shadow(struct ctrlq_queue *tx, struct ctrlq_queue *rx)
{
	if (tx == NULL || rx == NULL) {
		COMMU_DBG("Patameters Error!\n");
		return -1;
	}
	tx->shadow_head = &(tx->ring->head);
	tx->shadow_tail = &(rx->ring->tail);
	rx->shadow_head = &(rx->ring->head);
	rx->shadow_tail = &(tx->ring->tail);

	return 0;
}

static inline void set_u64_via_pcie(u64 *dest, u64 *src)
{
	*(u32*)dest = *(u32*)src;
	*((u32*)dest + 1) = *((u32*)src + 1);
}

int ctrlq_put(struct ctrlq_queue* queue, struct ctrlq_desc* desc) {
	struct ctrlq_desc* dest;
	unsigned long flags;
	u32 head;
	volatile u32 pci_read;

	spin_lock_irqsave(&queue->lock, flags);

	if (ctrlq_is_full(queue)) {
		//pr_info("ctrlq is full! head:%d tail%d\n",queue->head, queue->tail);
		spin_unlock_irqrestore(&queue->lock, flags);
		return 0;
	}

	head = queue->head & (queue->num - 1);
	dest = (struct ctrlq_desc*)(&queue->ring->buf);
	dest += head;

	set_u64_via_pcie(&dest->shadow_addr, &desc->shadow_addr);
	set_u64_via_pcie(&dest->name, &desc->name);
	dest->command = desc->command;
	dest->vf_num = desc->vf_num;
	set_u64_via_pcie(&dest->pci_addr, &desc->pci_addr);
	/* seq is used to wait_event, return head as seq to caller */
	/* set seq outside to make tx/rx put logic equal */
	/*desc->seq = head;*/
	dest->seq = desc->seq;
	COMMU_DBG("==after in ctrlq_put seq %d\n", dest->seq);

	queue->head++;
	pci_read = dest->seq;

	wmb();
	*queue->shadow_head = queue->head;
	spin_unlock_irqrestore(&queue->lock, flags);

	COMMU_DBG("%s -- [native head]%d -- [remote head]%d\n",
			__func__,
			queue->head,
			queue->ring->head);

	return 1;
}

int ctrlq_get(struct ctrlq_queue* queue, struct ctrlq_desc* dest) {
	struct ctrlq_desc* desc;
	u32 tail;
#ifdef CONFIG_CNDRV_EDGE
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	if (ctrlq_is_empty(queue)) {
		spin_unlock_irqrestore(&queue->lock, flags);
#else
	if (ctrlq_is_empty(queue)) {
#endif
		return 0;
	}

	tail = queue->tail & (queue->num - 1);
	COMMU_DBG("==in ctrlq_get %d== %px == %px\n", tail, queue->ring, queue->ring->buf);
	desc = (struct ctrlq_desc*)(&queue->ring->buf);
	desc += tail;
	dest->shadow_addr = desc->shadow_addr;
	dest->name = desc->name;
	dest->command = desc->command;
	dest->vf_num = desc->vf_num;
	dest->pci_addr = desc->pci_addr;
	dest->seq = desc->seq;

	queue->tail++;

	wmb();
	*queue->shadow_tail = queue->tail;
#ifdef CONFIG_CNDRV_EDGE
	spin_unlock_irqrestore(&queue->lock, flags);
#endif

	COMMU_DBG("%s -- [native tail]%d -- [remote tail]%d\n",
			__func__,
			queue->tail,
			*queue->shadow_tail);

	return 1;

}

int ctrlq_get_tail_seq(struct ctrlq_queue* queue)
{
	struct ctrlq_desc* desc;
	u32 tail;

	if (ctrlq_is_empty(queue))
		return -1;

	tail = queue->tail & (queue->num - 1);
	desc = (struct ctrlq_desc*)(&queue->ring->buf);
	desc += tail;

	COMMU_DBG("== %s %d== %d\n", __func__, tail, desc->seq);
	return desc->seq;
}

struct ctrlq_desc *ctrlq_find_desc_in_queue_by_seq(struct ctrlq_queue* queue, u32 seq)
{
	int i,j=0;
	struct ctrlq_desc* desc;
	desc = (struct ctrlq_desc*)(&queue->ring->buf);
	for (i = 0; i < queue->num; i++,desc++) {
		if(desc->seq == seq){
			j=1;
			break;
		}
	}
	if(j) {
	COMMU_DBG("== %s %d== %d\n", __func__, desc->seq, seq);
		return desc;
	} else {
		COMMU_DBG("==can't find a desc = %d\n",seq);
		return NULL;
	}
}

/* different between get and glance
 *
 * both return desc at tail
 * get move the tail (tail++)
 * glance not move the tail
 *
 * */
int ctrlq_glance(struct ctrlq_queue* queue, struct ctrlq_desc* dest)
{
	struct ctrlq_desc* desc;
	u32 tail;

	if (ctrlq_is_empty(queue))
		return 0;

	tail = queue->tail & (queue->num - 1);
	COMMU_DBG("==in ctrlq_glance %d== %px == %px\n", tail, queue->ring, queue->ring->buf);
	desc = (struct ctrlq_desc*)(&queue->ring->buf);
	desc += tail;
	dest->shadow_addr = desc->shadow_addr;
	dest->name = desc->name;
	dest->command = desc->command;
	dest->vf_num = desc->vf_num;
	dest->pci_addr = desc->pci_addr;
	dest->seq = desc->seq;

	COMMU_DBG("%s -- [native tail]%d -- [remote tail]%d\n",
			__func__,
			queue->tail,
			*queue->shadow_tail);

	return 1;

}

int ctrlq_gen_seq(struct ctrlq_queue* queue) {
	return atomic_inc_return(&queue->seq);
}

void ctrlq_enqueue(struct ctrlq_queue* queue, struct ctrlq_desc* desc) {

}
