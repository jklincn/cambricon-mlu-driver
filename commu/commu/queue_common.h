#ifndef COMMU_QUEUE_COMMON
#define COMMU_QUEUE_COMMON

#define COMMU_SHADOW_HEAD_TAIL
#define COMMU_SUSPEND_ENQUEUE 0x1
#define COMMU_STOP_ENQUEUE 0x2
#define COMMU_DESC_SIGINT 0x1

struct commu_ops {
	int (*enqueue)(void *queue, void *buf, int size, int seq);
	int (*dequeue)(void *queue, void *buf, int *size);
	int (*dequeue_rpc)(void *queue, void *buf, int *size);
	void* (*alloc)(void *addr, int size, void *core_set);
	int (*query_new)(void *queue);
	int (*search)(void *queue, int seq);
	int (*glance)(void *queue);
	int (*gen_seq)(void *queue);
	void* (*tail_addr)(void *queue);
	void* (*head_addr)(void *queue);
	void* (*get_ring_tail)(void *queue);
	void* (*get_ring_head)(void *queue);
	int (*set_shadow_tail)(void *queue, void *tail);
	int (*set_shadow_head)(void *queue, void *head);
	void* (*get_shadow_tail)(void *queue);
	int (*free)(void *queue);
	int (*stop)(void *queue);
	int (*restart)(void *queue);
	int (*is_stopped)(void *queue);
	int (*suspend)(void *queue);
	int (*resume)(void *queue);
	int (*is_suspended)(void *queue);
	uint16_t (*glance_port)(void* q);
	int (*enqueue_port)(void *queue, void *buf, int size, int seq, uint16_t port);
	int (*peek)(void *queue, void *buf, int *size);
	int (*skip)(void *queue);
	int (*is_full)(void *queue);
	void* (*user_seq_addr)(void *queue);
	int (*set_flag_sigint)(void *queue, int port, char *dir);
	int (*set_rpc_sigint)(void *queue, void *eventfd, char *dir);
	int (*dump_queue)(void *queue);
	int (*dump_errinfo)(void *queue);
	int (*set_desc_flag)(void *queue, int index, uint16_t flag);
	void (*set_sync_write)(void *queue, u64 sync_write_pa);
};

#endif
