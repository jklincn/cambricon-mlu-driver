#ifndef __CAMBRICON_CNDRV_AXIMONITOR_H__
#define __CAMBRICON_CNDRV_AXIMONITOR_H__

#define MLU270_MAX_AXI_MON_NUM    2
#define MLU220_MAX_AXI_MON_NUM    1
#define MLU290_MAX_AXI_MON_NUM    4
#define MLU370_SINGLE_DIE_MAX_AXI_MON_NUM    4
#define MLU370_DOUBLE_DIE_MAX_AXI_MON_NUM    8
#define CE3226_SINGLE_DIE_MAX_AXI_MON_NUM    2
#define CE3226_DOUBLE_DIE_MAX_AXI_MON_NUM    4
#define MLU590_DOUBLE_DIE_MAX_AXI_MON_NUM    9
#define MLU590E_DOUBLE_DIE_MAX_AXI_MON_NUM   1
#define MLU580_DOUBLE_DIE_MAX_AXI_MON_NUM    8
#define PIGEON_SINGLE_DIE_MAX_AXI_MON_NUM    2

#define MLU270_CPUGIC__AXIMHUB_NORTH_IRQ    77
#define MLU270_CPUGIC__AXIMHUB_SOUTH_IRQ    78
#define MLU220_CPUGIC__CPUSYS_AXIMHUB_IRQ   58
#define MLU290_CPUGIC__AXIMHUB_0_IRQ        134
#define MLU290_CPUGIC__AXIMHUB_1_IRQ        135
#define MLU290_CPUGIC__AXIMHUB_2_IRQ        136
#define MLU290_CPUGIC__AXIMHUB_3_IRQ        137

#define MLU370_AXIMHUB_0_IRQ        144
#define MLU370_AXIMHUB_1_IRQ        145
#define MLU370_AXIMHUB_2_IRQ        146
#define MLU370_AXIMHUB_3_IRQ        147
#define MLU370_AXIMHUB_4_IRQ        (144 + 195)
#define MLU370_AXIMHUB_5_IRQ        (145 + 195)
#define MLU370_AXIMHUB_6_IRQ        (146 + 195)
#define MLU370_AXIMHUB_7_IRQ        (147 + 195)

#define AMH_HUB_START			1
#define AMH_HUB_STOP			0

#define MLU590_A5_HBM_CHANNEL_COUNT 5
#define MLU590_A3_HBM_CHANNEL_COUNT 3
#define MLU580_A5_DDR_CHANNEL_COUNT 5
#define MLU580_A3_DDR_CHANNEL_COUNT 3

/*16MB*/
#define ZONE_SIZE_16MB          0x1000000
/*8MB*/
#define ZONE_SIZE_8MB           (ZONE_SIZE_16MB / 2)
#define ZONE_CONUT              8
/*Max monitor per hub*/
#define MON_NUMBER_MAX          (48)

#define AH_STATUS_IDLE          0
#define AH_STATUS_RUNNING       1
#define AH_STATUS_FINISH        2
/*PFMU_RAW_DATA_SIZE = 32 byte */
#define PFMU_RAW_DATA_SIZE      (32)
#define PFMU_RAW_DATA_COUNT_PER_ZONE(x)     ((x) / PFMU_RAW_DATA_SIZE)
#define DEV_BUFFER_SIZE(x, y)               ((x) * (y))
#define MIN_RAW_RING_BUFFER_BLOCK_COUNT(x)  (MIN_RAW_BUFFER_BLOCK_COUNT * PFMU_RAW_DATA_COUNT_PER_ZONE(x))

#define CN_MON_MOD_NAME         "cn_monitor-mod"

enum monitor_type {
	RESERVED_MONITOR = 0,
	AXI_MONITOR = 1,
	IPU_PFMU = 2,
};

#include <asm/atomic.h>
struct cambr_amh_hub {

	u8 inited;
	/*hub id*/
	u8 hub_id;
	/*hub irq num*/
	u32 irq;
	/*total monitor count*/
	u32 monitor_num;
	/*hub irq status reg address*/
	u32 base;
	/*cn core set*/
	struct cn_core_set *core;
	/* monitor config */
	struct cn_axi_monitor_config *config;
	/*hub irq handler*/
	irqreturn_t (*aximhub_intr_handle)(int index, void *data);
	/*monitors opened list*/
	char monitors[MON_NUMBER_MAX];
	u64 monitor_type_mask;
	u32 axi_monitor_count;
	u32 ipu_pfmu_count;
	/*monitors opened list*/
	char monitors_mode[MON_NUMBER_MAX];
	/*monitors opened list*/
	enum monitor_type monitors_type[MON_NUMBER_MAX];
	/*opened count*/
	int opened_count;
	/*axi mon data mode*/
	u8 data_mode;
	/*HUB STATUS*/
	u64 status;
	/*intr conut*/
	u64 loops;
	/*Counter*/
	u64 entry;
	/*Current offset*/
	u64 pc;
	/*Window start offset*/
	u64 start;
	/*Window end offset*/
	u64 end;
	/*Windows size*/
	u64 size;
	/*the last data start*/
	u64 last_data_start;
	/*the last data size*/
	u64 last_data_size;
	u32 zone_size;

	u8 irq_enabled;

	atomic64_t handle_index;
	atomic64_t data_ref_cnt[ZONE_CONUT];
};

struct cn_axi_monitor_config {
	u32 irq;
	u32 monitor_num;
	u32 base;
	irqreturn_t (*aximhub_intr_handle)(int index, void *data);
	u64 axim_type_mask;
	u64 pfmu_type_mask;
};

struct cn_aximhub_ops {

	/* stop hub & update pc */
	int (*stop_hub)(
		struct cambr_amh_hub *hub_priv);

	/* start hub & reset reg */
	int (*start_hub)(
		struct cambr_amh_hub *hub_priv);
};

struct cn_aximonitor_ops {

	/* open monitor */
	int (*open_monitor)(void *mset, void *mon_conf);

	/* open all monitor */
	int (*openall_monitor)(void *mset, u8 hub_id);

	long (*hub_ctrl)(void *mset, unsigned long arg);
	long (*read_ringbuf_pos)(void *mset, unsigned long arg);
	long (*highrate_param)(void *mset, unsigned long arg);
	int (*get_axistruct_size)(void *mset, u32 *pdata);
	int (*get_basic_param_size)(u32 *size);
	int (*get_basic_param_data)(void *mset, void *pdata);
};

struct cn_aximon_zone_info {
	u64 zone_size;
	u64 zone_count;
	u64 dev_buffer_size;
	u64 pfmu_raw_data_count_per_zone;
	u64 min_raw_ring_buffer_block_count;
};

extern struct cn_aximonitor_ops aximon_mlu300_ops;

#ifndef CONFIG_CNDRV_EDGE
void mlu220_axi_monitor_config(void *monitor_set);
void mlu270_axi_monitor_config(void *monitor_set);
void mlu290_axi_monitor_config(void *monitor_set);
void mlu370_axi_monitor_config(void *monitor_set);
void mlu580_axi_monitor_config(void *monitor_set);
void mlu590_axi_monitor_config(void *monitor_set);
static inline void ce3226_axi_monitor_config(void *monitor_set) {}
static inline void pigeon_axi_monitor_config(void *monitor_set) {}
#else
static inline void mlu270_axi_monitor_config(void *monitor_set) {}
static inline void mlu290_axi_monitor_config(void *monitor_set) {}
static inline void mlu370_axi_monitor_config(void *monitor_set) {}
static inline void mlu580_axi_monitor_config(void *monitor_set) {}
static inline void mlu590_axi_monitor_config(void *monitor_set) {}
#if defined(CONFIG_CNDRV_C20E_SOC)
static inline void ce3226_axi_monitor_config(void *monitor_set) {}
static inline void pigeon_axi_monitor_config(void *monitor_set) {}
void mlu220_axi_monitor_config(void *monitor_set);
#elif defined(CONFIG_CNDRV_CE3226_SOC)
static inline void mlu220_axi_monitor_config(void *monitor_set) {}
static inline void pigeon_axi_monitor_config(void *monitor_set) {}
void ce3226_axi_monitor_config(void *monitor_set);
#elif defined(CONFIG_CNDRV_PIGEON_SOC)
static inline void mlu220_axi_monitor_config(void *monitor_set) {}
static inline void ce3226_axi_monitor_config(void *monitor_set) {}
void pigeon_axi_monitor_config(void *monitor_set);
#else /* PCIE_ARM */
static inline void mlu220_axi_monitor_config(void *monitor_set) {}
static inline void ce3226_axi_monitor_config(void *monitor_set) {}
static inline void pigeon_axi_monitor_config(void *monitor_set) {}
#endif
#endif

void cndrv_axi_monitor_struct_default(void *conf);
void cndrv_pmu_monitor_struct_default(void *conf);

/*axi monitor function*/

int cndrv_axi_monitor_restart(void *mset);
void cndrv_axi_monitor_stop(void *mset);

int cndrv_axi_monitor_init(void *pcore);
void cndrv_axi_monitor_exit(void *mset);

int cndrv_axi_monitor_register_irq(void *mset);
int cndrv_axi_monitor_unregister_irq(void *mset);

irqreturn_t aximhub_mlu200_intr_handle(int index, void *data);
int axihub_mlu200s_start_hub(struct cambr_amh_hub *axi_set);
int axihub_mlu200s_stop_hub(struct cambr_amh_hub *axi_set);

int cndrv_axi_monitor_host_config(void *mset,
	struct monitor_direct_mode *direct_mode_info);
int cndrv_axi_monitor_host_exit(void *mset);

int cndrv_axi_monitor_enable_irq(void *mset, int hub_id);
int cndrv_axi_monitor_disable_irq(void *mset, int hub_id);

#endif
