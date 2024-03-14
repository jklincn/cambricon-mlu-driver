#ifndef __CAMBRICON_DIRECT_CNDRV_MONITOR_H__
#define __CAMBRICON_DIRECT_CNDRV_MONITOR_H__

#include "cndrv_bus.h"
#include "./axi_monitor/cndrv_axi_monitor.h"

/* 64KB */
#define LOW_PRECISON_ZONE_SIZE        0x10000
/* 512KB */
#define LOW_DEV_BUFFER_SIZE  (LOW_PRECISON_ZONE_SIZE * ZONE_CONUT)


#define MAX_MONITOR_NUM                      (48)

#define HUB_WORKQUEUE_READY                  (0x0)
#define HUB_WORKQUEUE_RUNNING                (0x1)
#define HUB_WORKQUEUE_STOPPED                (0x2)

#define MIN_RING_BUFFER_BLOCK_COUNT          (10000)
#define MIN_RAW_BUFFER_BLOCK_COUNT           (8)
/* 800us */
#define AXI_MONITOR_SAMPLING_TIME_INTERVAL   (800)
#define AXI_MONITOR_SAMPLING_RATIO           (3)

#define LLC_ID(x)                            (x)
#define HBM_ID(x)                            (x)

struct mfifo {

	atomic64_t real_data_size;
	u32 head;
	u32 tail;
	u64 entry;
	u32 size;
	u32 unit;
	char *buffer;
};

void mfifo_reset(struct mfifo *p);
int mfifo_len(struct mfifo *p);
int mfifo_get(struct mfifo *p, char *pdata);
int mfifo_copy_all_to_usr(struct mfifo *p, void *pdata, int len);
int mfifo_put(struct mfifo *p, char *pdata, u8 clear, u32 data_size);
struct mfifo *mfifo_alloc(u32 count, u32 unit);
void mfifo_free(struct mfifo *p);
int mfifo_copy_to_usr(struct mfifo *p, u32 offset, void *pdata, u32 len);
int mfifo_block_len(struct mfifo *p);
int mfifo_copy_to_usr_unit(struct mfifo *p, u32 offset, void *pdata, u32 len, u32 unit);

enum hub_mode {
	AXI_MON_NORMAL_MODE = 0,
	AXI_MON_DIRECT_MODE,
};

struct highrate_thread_context {
	void *monitor_set;
	u32 hub_id;
	u64 dev_vaddr;
	u64 host_dev_vaddr;
	u64 dev_buff_size;

	struct workqueue_struct *hub_wq;
	struct work_struct hub_work;
	char workname[32];

	struct mfifo *axi_pfifo;

	u32 work_status;
	spinlock_t work_lock;

	u32 fifo_buf_size;
	u32 block_size;

	void *cache_buf;
	u32 cache_size;
	u64 loss_times;
	atomic64_t record_times;
	atomic64_t entry_count;
	void *dev_buff;
	u16 last_data_flag;
};

struct cn_monitor_highrate_set {
	struct highrate_thread_context thread_context[AM_MAX_HUB_NUM];
};

struct axi_monitor_sampling {
	int timestamp;
	int monitor_timestamp;
};

enum axi_data_type {
	MONITOR_DATA = 0,
	PFMU_DATA,
	RAW_DATA,
};

#define AXI_MONITOR_LOOP_FOUND_ERROR   (0)
#define AXI_MONITOR_LOOP_FOUND_TIME    (1)
#define AXI_MONITOR_LOOP_FOUND_PFMU    (2)
#define AXI_MONITOR_LOOP_FOUND_END     (3)

enum IPU_PHY_CLUSTER_ID {
	IPU_CLUSTER_0 = 0,
	IPU_CLUSTER_1,
	IPU_CLUSTER_2,
	IPU_CLUSTER_3,
	IPU_CLUSTER_4,
	IPU_CLUSTER_5,
	IPU_CLUSTER_6,
	IPU_CLUSTER_7,
	IPU_CLUSTER_8,
	IPU_CLUSTER_9,
	IPU_CLUSTER_10,
	IPU_CLUSTER_11,
	IPU_CLUSTER_12,
	IPU_CLUSTER_13,
	IPU_CLUSTER_14,
	IPU_CLUSTER_15,
	IPU_CLUSTER_16,
	IPU_CLUSTER_17,
	IPU_CLUSTER_18,
	IPU_CLUSTER_19,
	IPU_CLUSTER_MAX,
};

enum IPU_CORE_ID {
	IPU_CORE_0 = 0,
	IPU_CORE_1,
	IPU_CORE_2,
	IPU_CORE_3,
	IPU_CORE_4,
	CORE_ID_MAX,
};

struct axi_hubtrace_map_ipu_info {
	u16 phy_cid;
	u16 core_id;
	u16 hub_id;
	u16 mon_id;
	u16 core_type;
};

int cn_monitor_process_data(struct highrate_thread_context *thread_context);

int axihub_highrate_mode(struct cambr_amh_hub *axi_set);
void wakeup_highrate_workqueue(struct cambr_amh_hub *axi_set, u16 last);

int aximhub_update_lastdata(struct cambr_amh_hub *axi_set);

unsigned long common_copy_data_from_devbuf(
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size);
int cn_monitor_release_monitor_highrate_env(void *mset,
	struct highrate_thread_context *thread_context);
int cn_monitor_exit_monitor_highrate_env_by_hubid(void *mset, int hub_id);
int cn_monitor_init_monitor_highrate_env(void *mset,
	struct highrate_thread_context *thread_context,
	void *mode_info);
int cn_monitor_exit_monitor_highrate_env(void *monitor_set);

struct cn_aximhub_data_parse_ops {

	/* copy data from hw buff */
	unsigned long (*copy_data_from_devbuf)(
		struct highrate_thread_context *thread_context,
		u64 start,
		u64 size);
	/* flush buff */
	unsigned long (*flush_data)(
		struct highrate_thread_context *thread_context,
		u64 start,
		u64 size);
	int (*pfmu_hubtrace_map_info)(void *mset, void *map_info);
	int (*pfmu_hubtrace_tab_len)(void *mset);
	int (*mem_mmap_kernel)(void *context);
	int (*mem_unmmap_kernel)(void *context);

	int (*monitor_res_tab_len)(u32 res_type);
	int (*monitor_res_info)(u32 res_type, void **info);
};

extern struct cn_aximhub_data_parse_ops aximhub_common_parse_ops;

int cn_monitor_pfmu_hubtrace_tab_len(void *mset);
int cn_monitor_pfmu_hubtrace_map_info(void *mset, void *map_info);
unsigned long cn_monitor_copy_data_from_devbuf(void *mset,
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size);
unsigned long cn_monitor_flush_data(void *mset,
	struct highrate_thread_context *thread_context,
	u64 start,
	u64 size);
int cn_monitor_mem_mmap(void *mset, void *context);
int cn_monitor_mem_unmmap(void *mset, void *context);

int cn_monitor_mem_unmmap_kernel(u64 iova, u64 *kernel_va);
int cn_monitor_mem_mmap_kernel(u64 iova, u64 *kernel_va, u64 size);
int cn_monitor_fill_res_map(void *mset, void *res_map);

#endif
