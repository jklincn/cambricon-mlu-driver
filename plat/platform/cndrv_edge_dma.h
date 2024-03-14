#ifndef __CNDRV_EDGE_DMA_H_
#define __CNDRV_EDGE_DMA_H_

enum CN_EDGE_DMA_TYPE {
	EDGE_DMA_USER,
	EDGE_DMA_KERNEL,
	EDGE_DMA_P2P,
	EDGE_DMA_USER_ASYNC,
	EDGE_DMA_P2P_ASYNC,
	EDGE_DMA_USER_REMOTE,
	EDGE_DMA_PINNED_MEM,
	EDGE_DMA_MEMSET_ASYNC,
};

struct ion_device_addr {
	/*first version is 1*/
	u64 version;
	u64 iova;
	u64 handle_id;
	u64 reserved;
	u64 priv;
};

struct ion_iova_context {
	/*user data*/
	u64 iova;
	u64 handle_id;
	/*ion data*/
	u64 kva;
	/*ion_user_handle*/
	/*struct ion_handle of ion*/
	void *ion_handle;
	/*struct ion_buffer of ion*/
	void *ion_buffer;
};

struct edge_dma_task {
	struct cn_edge_set                *edge_set;
	/*transfer_s->ia is user space struct ion_device_addr of edge platform*/
	struct transfer_s                 *transfer;
	struct memset_s                   *memset;
	/*iova information of ion driver*/
	struct ion_iova_context            ion_cntx;
	int                                clockid;

	u64                                user;
	int                                abort_flag;
	u64                                device_vaddr;
	void                              *pminfo;
	struct dma_async_info_s           *async_info;
	struct work_struct                 trigger_work;
	enum CN_EDGE_DMA_TYPE              dma_type;
	int                                channel_used_num;
	int                                task_id;

	volatile int                       trigger_type;
	struct task_struct                *tsk;
	struct mm_struct                  *tsk_mm;

	/* for async transfer task */
	struct cn_edge_set                *edge_set_stream;
	void                              *prev_task;
	void                              *next_task;
	struct hlist_node                  hlist;
	u64                                tags;
	u64                                index;
	struct cn_edge_set                *edge_set_dst;
	u64                                kvaddr;
	int                                dma_async;
};

int cn_edge_dma_async_init(struct cn_edge_set *edge_set);
size_t cn_edge_dma_transfer(struct edge_dma_task *task);
int cn_edge_init_dma_task(
		struct edge_dma_task *task,
		struct transfer_s *transfer_s,
		enum CN_EDGE_DMA_TYPE               dma_type,
		void                          *edge_priv
		);

int cn_edge_dma_abort(u64 tags, u64 index, void *edge_priv);
int cn_edge_dma_async_message_process(void *edge_priv,
		struct arm_trigger_message *message);
size_t cn_edge_dma_async(struct transfer_s *t,
		struct dma_async_info_s **pinfo, void *edge_priv);
int cn_edge_memset_async(struct memset_s *t, struct dma_async_info_s **pinfo, void *edge_priv);
int cn_edge_dma_memset(struct edge_dma_task *task);
void cn_edge_dma_async_exit(struct cn_edge_set *edge_set);

int edge_init_device_addr(void *addr,
		struct ion_device_addr *ion_dev_addr);

#endif
