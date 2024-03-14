#ifndef COMMU_CTRL_QUEUE
#define COMMU_CTRL_QUEUE
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

struct ctrlq_desc {
	u64 shadow_addr;
	u64 pci_addr;
	u64 name;
	u16 command;
	u16 vf_num;
	u32 seq;
};

struct ctrlq_ring {
	u32 head;
	u32 tail;
	struct ctrlq_desc* buf;
};

struct ctrlq_queue {
	struct ctrlq_ring *ring;
	u32 head;
	u32 tail;
	u32 *shadow_head;
	u32 *shadow_tail;
	u32 num;
	spinlock_t lock;
	atomic_t seq;
};

void ctrlq_alloc(struct ctrlq_queue *queue, void *addr, int size);
int ctrlq_put(struct ctrlq_queue* queue, struct ctrlq_desc* desc);
int ctrlq_get(struct ctrlq_queue* queue, struct ctrlq_desc* dest);
int ctrlq_glance(struct ctrlq_queue* queue, struct ctrlq_desc* dest);
int ctrlq_get_tail_seq(struct ctrlq_queue* queue);
struct ctrlq_desc *ctrlq_find_desc_in_queue_by_seq(struct ctrlq_queue* queue, u32 seq);
int ctrlq_gen_seq(struct ctrlq_queue* queue);
int32_t ctrlq_set_shadow(struct ctrlq_queue *tx, struct ctrlq_queue *rx);
#endif
