#include <linux/types.h>
#include <linux/spinlock.h>
#include "channel.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_commu.h"

struct testq_desc {
	int32_t seq;
	u16 flag;
	u16 size;
	u32 port;
	u32 checksum;
	char data[COMMU_TESTQ_DATA_BUF_SIZE];
};

struct testq_ring {
	volatile u32 head;
	volatile u32 tail;
	struct testq_desc* buf;
};

#define COMMU_ENDPOINT_QUEUE_SIZE_64 (COMMU_ENDPOINT_QUEUE_SIZE/sizeof(u64))
struct testq_errinfo {
	u32 tail;
	int size;
	int desc_seq;
	u32 origin_checksum;
	u32 checksum;
	u8  buf[COMMU_TESTQ_DATA_BUF_SIZE];
	u64 data[COMMU_ENDPOINT_QUEUE_SIZE_64];
};

struct cn_core_set;
#define TESTQ_MAX_ERR   5
struct testq_queue {
	struct cn_core_set *core_set;
	struct testq_ring *ring;
	volatile u32 head;
	volatile u32 tail;
	u32 *shadow_head;
	u32 *shadow_tail;
	u32 num;
	spinlock_t lock;
	int seq;
	volatile u64 flag;
	u64 err_num;

	/* sync write */
	int en_sync_write;
	u64 sync_write_pa;

#ifndef CONFIG_CNDRV_EDGE
	struct testq_errinfo err_buf[TESTQ_MAX_ERR];
#endif
};

int testq_put(struct testq_queue* queue, void *buf, int size, int seq, u16 port);
int testq_get(struct testq_queue* queue, void *buf, int* size);
int testq_is_suspended(void *queue);
int testq_is_stopped(void *queue);
