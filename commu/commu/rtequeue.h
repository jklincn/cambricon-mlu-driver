#include <linux/types.h>
#include <linux/spinlock.h>

#define COMMU_RTEQ_DESC_SIZE (4112)
#define COMMU_RTEQ_DESC_META_SIZE (16)
#define COMMU_RTEQ_DATA_BUF_SIZE (COMMU_RTEQ_DESC_SIZE - COMMU_RTEQ_DESC_META_SIZE)

struct rteq_desc {
	int32_t seq;
	volatile u16 flag;
	u16 size;
	volatile u32 port;
	u32 padding;
	char data[COMMU_RTEQ_DATA_BUF_SIZE];
};

struct rteq_ring {
	volatile u32 head;
	volatile u32 tail;
	struct rteq_desc* buf;
};

struct rteq_queue {
	struct rteq_ring *ring;
	volatile u32 head;
	volatile u32 tail;
	u32 *shadow_head;
	u32 *shadow_tail;
	u32 num;
	spinlock_t lock;
	atomic_t seq;
	volatile u64 flag;
	volatile u64 user_seq;
};

int rteq_reset(struct rteq_queue *queue, void *addr, int size);
int rteq_put(struct rteq_queue* queue, void *buf, int size, int seq, u16 port);
int rteq_get(struct rteq_queue* queue, void *buf, int* size);
struct rteq_queue * rteq_alloc(void *addr, int size);
int rteq_is_suspended(void *queue);
int rteq_is_stopped(void *queue);
