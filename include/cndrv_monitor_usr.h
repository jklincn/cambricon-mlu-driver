/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_CNDRV_MONUSR_H__
#define __CAMBRICON_CNDRV_MONUSR_H__

#include "cndrv_perf_usr.h"

/* AXI Monitor and PMU */
#define AM_MAX_HUB_NUM		16

#define AM_ERROR_OUTRANGE	0
#define AM_ERROR_INRANGE	1

/*for mlu200 mlu370 ce3226 to use*/
#define AM_ID_MATCH_MODE	0x00
#define AM_ADDR_MATCH_MODE	0x01
#define AM_USER_MATCH_MODE	0x02
#define AM_MATCH_COMBINE	0x04

/*for pigeon mlu580 mlu590 to use*/
#define MLU500_AM_ID_MATCH_MODE	     0x00
#define MLU500_AM_ADDR_MATCH_MODE    0x01
#define MLU500_AM_USER_MATCH_MODE    0x04

#define PMU_UNLOCK          0
#define PMU_LOCK            1

#define MLU590_MAX_IPUSYS_COUNT      (6)
#define MLU590_MAX_IPUCLUSTER_COUNT  ((MLU590_MAX_IPUSYS_COUNT) * 2)
#define MLU580_MAX_IPUSYS_COUNT      (6)
#define MLU580_MAX_IPUCLUSTER_COUNT  ((MLU580_MAX_IPUSYS_COUNT) * 2)

#define AMH_MAX 128

enum board_name {
	BOARD_MLU100 = 0,
	BOARD_MLU220,
	BOARD_MLU270,
	BOARD_MLU290,
	BOARD_MLU370,
	BOARD_MLU365 = BOARD_MLU370,
	BOARD_CE3226,
	BOARD_MLU590,
	BOARD_MLU585 = BOARD_MLU590,
	BOARD_LEOPARD,
	BOARD_PIGEON = BOARD_LEOPARD,
	BOARD_1V_2301 = BOARD_PIGEON,
	BOARD_MLU580,
	BOARD_MLU560 = BOARD_MLU580,
	BOARD_MLU570 = BOARD_MLU580,
	BOARD_MLU270_VF,
	BOARD_MLU290_VF,
	BOARD_MLU370_VF,
	BOARD_MLU590_VF,
	BOARD_MLU580_VF,
	BOARD_UNKNOWN_VF,
	BOARD_UNKNOWN,
	BOARD_MAX,
};

#define BOARD_MODEL_NAME_LEN 32
#define BA_VENDOR_NAME_LEN   16
#define BOARD_PART_NUM_LEN   8
#define ADDRESS_LEN          16
#define DRIVER_PMU_UUID_SIZE 16
#define QOS_NAME_LEN         32
#define SOC_ID_SIZE          32
#define PLATFORM_NAME_LEN    64
#define DRIVER_IPCM_DEV_NAME_SIZE 64

#define CHASSIS_SN_READY_SHIFT                 0
#define CHASSIS_PRODUCT_DATE_READY_SHIFT       1
#define CHASSIS_PART_NUM_READY_SHIFT           2
#define CHASSIS_VENDOR_NAME_READY_SHIFT        3

#define NVME_SN_READY_SHIFT                    0
#define NVME_MODEL_READY_SHIFT                 1
#define NVME_FW_READY_SHIFT                    2
#define NVME_MFC_READY_SHIFT                   3

#define PSU_SN_READY_SHIFT                     0
#define PSU_MODEL_READY_SHIFT                  1
#define PSU_FW_READY_SHIFT                     2
#define PSU_MFC_READY_SHIFT                    3

#define IB_SN_READY_SHIFT                      0
#define IB_MODEL_READY_SHIFT                   1
#define IB_FW_READY_SHIFT                      2
#define IB_MFC_READY_SHIFT                     3

#define CHASSIS_SN_READY                       ((0x1) << CHASSIS_SN_READY_SHIFT)
#define CHASSIS_PRODUCT_DATE_READY             ((0x1) << CHASSIS_PRODUCT_DATE_READY_SHIFT)
#define CHASSIS_PART_NUM_READY                 ((0x1) << CHASSIS_PART_NUM_READY_SHIFT)
#define CHASSIS_VENDOR_NAME_READY              ((0x1) << CHASSIS_VENDOR_NAME_READY_SHIFT)

#define NVME_SN_READY                          ((0x1) << NVME_SN_READY_SHIFT)
#define NVME_MODEL_READY                       ((0x1) << NVME_MODEL_READY_SHIFT)
#define NVME_FW_READY                          ((0x1) << NVME_FW_READY_SHIFT)
#define NVME_MFC_READY                         ((0x1) << NVME_MFC_READY_SHIFT)

#define PSU_SN_READY                           ((0x1) << PSU_SN_READY_SHIFT)
#define PSU_MODEL_READY                        ((0x1) << PSU_MODEL_READY_SHIFT)
#define PSU_FW_READY                           ((0x1) << PSU_FW_READY_SHIFT)
#define PSU_MFC_READY                          ((0x1) << PSU_MFC_READY_SHIFT)

#define IB_SN_READY                            ((0x1) << IB_SN_READY_SHIFT)
#define IB_MODEL_READY                         ((0x1) << IB_MODEL_READY_SHIFT)
#define IB_FW_READY                            ((0x1) << IB_FW_READY_SHIFT)
#define IB_MFC_READY                           ((0x1) << IB_MFC_READY_SHIFT)

#define CNDEV_CORE_NAME_LEN                    (32)

enum cn_monitor_data_mode {
	AXIM_NORMAL_MODE     = 0,
	AXIM_BW_DATA_MODE    = 1,
	AXIM_EQUAL_DATA_MODE = 2,
};

struct hub_desc {
	/* total montior count */
	__u8 monitors;
	/* pfmu monitor count */
	__u8 ipu_pfmu;
	/* axi monitor count */
	__u8 axi_monitor;
	/* axi monitor data block size in bytes */
	__u32 axi_monitor_block_data_size;
	/* pfmu data block size in bytes */
	__u32 pfmu_data_size;
};

/* use for param read*/
struct cn_monitor_param {
	__u8 card_type;
	/* hub count */
	__u8 hub_num;
	/* axi monitor count in each hub */
	__u8 monitors[4];
	/* user use this to alloc buffer for sharememory */
	size_t sharedata_size;
};

enum pmu_res_info {
	/* pmu struct size */
	PMU_MONITOR_SIZE,
	PMU_LLC_PERF_SIZE,
	PMU_IPU_PERF_SIZE,
	PMU_SMMU_PERF_SIZE,
	PMU_SMMU_EXP_SIZE,
	/* pmu resource info */
	PMU_VALID_LLC_MASK,
	PMU_VALID_JPU_MASK,
	PMU_VALID_HBM_MASK,
	PMU_VALID_IPU_MASK,
	PMU_VALID_TINYCORE_MASK,
	PMU_TOTAL_IPU_CLUSTER_NUM,
	PMU_TOTAL_TINYCORE_CLUSTER_NUM,
	PMU_L1C_PERF_SIZE,
	PMU_MAX_RES
};

struct cn_monitor_read_param {
	__u8 card_type;
	/* hub count */
	__u8 hub_num;
	/* axi monitor count in each hub */
	__u8 monitors[AMH_MAX];
	/* user use this to alloc buffer for sharememory */
	size_t sharedata_size;

	__u64 support_data_mode;
	/*different version express interface */
	__u32 version;
	/* express sizeof(struct cn_monitor_read_param) bytes */
	__u32 buf_size;
	/*express resource count, per count size is 8 byte*/
	__u32 res_cnt;
	void *res_data;
};

struct cn_monitor_perf_info {
	__u8 llc_group;
	__u8 jpu_num;
	__u8 smmu_group_num;
	__u8 ipu_core_num;
	__u8 ipu_cluster_num;
};

struct cn_monitor_direct_param {
	__u8 card_type;
	/* total hub count */
	__u8 hub_num;
	/* user use this to alloc buffer for sharememory, unit:Bytes */
	size_t sharedata_size;
	/* die count */
	__u8 die_cnt;
	/* detail hub information */
	void *hub_param;

	__u64 phy_ipu_cluster_mask;
	__u16 logic_ipu_cluster_cnt;
	__u16 ipu_core_pre_cluster;
	struct cn_monitor_perf_info perf_info;

	__u64 support_data_mode;
};

/* axi monitor config struct */
struct axi_monitor_config {
	/* split for Hub_id and Monitor_id */
	__u16 monitor_id;
	/* cross boundary mode */
	__u16 cross_bound_mode;
	__u16 match_mode;
	/* enum id_match_name id_match_module; */
	__u32 id_match_read;
	__u32 id_match_write;
	__u32 id_match_read_mask;
	__u32 id_match_write_mask;
	__u64 match_address_low;
	__u64 match_address_high;
	__u32 user_match_read;
	__u32 user_match_write;
	__u32 user_match_read_mask;
	__u32 user_match_write_mask;
	__u32 timeout_threshold;
	__u64 protect_addr_low;
	__u64 protect_addr_high;
};

struct pmu_monitor_config {
	/* split for Hub_id and Monitor_id */
	__u16 monitor_id;
	/* cross boundary mode */
	__u16 cross_bound_mode;
	__u16 match_mode;
	/* enum id_match_name id_match_module; */
	__u32 id_match_read;
	__u32 id_match_write;
	__u32 id_match_read_mask;
	__u32 id_match_write_mask;
	__u64 match_address_low;
	__u64 match_address_high;
	__u32 user_match_read;
	__u32 user_match_write;
	__u32 user_match_read_mask;
	__u32 user_match_write_mask;
	__u32 timeout_threshold;
	__u64 protect_addr_low;
	__u64 protect_addr_high;
	__u64 data_mode;
};

/* all monitor data header */
struct monitor_data_head {
	/* use for R/W Handshake */
	__u16 monitor_status;
	__u16 axi_monitor_num;
	__u16 axi_monitor_offset;
	__u16 ipu_profiling_num;
	__u16 ipu_profiling_offset;
	__u16 ipu_perf_num;
	__u16 ipu_perf_offset;
	__u16 smmu_perf_num;
	__u16 smmu_perf_offset;
	__u16 llc_perf_num;
	__u16 llc_perf_offset;
	__u16 entry_count;
	__u16 smmu_exception_num;
	__u16 smmu_exception_offset;
};

/* monitor performance data struct */
struct axi_monitor_data {
	__u16 monitor_id;
	__u16 status;
	__u8 data_mode;
	__u64 write_throughput;
	__u64 read_throughput;
	__u32 write_max_latency;
	__u32 read_max_latency;
	union {
		__u64 write_total_latency; /* normal mode */
		__u64 write_bw_of; /* bw mode */
		__u64 write_bw_equay; /* equay mode */
	};
	union {
		__u64 read_total_latency; /* normal mode */
		__u64 read_bw_of; /* bw mode */
		__u64 read_bw_equay; /* equay mode */
	};
	__u64 write_bw;
	__u64 read_bw;
	__u64 time_stamp;
};

struct axi_monitor_head {
	__u32 buf_size;
	__u32 real_size;
};

struct cn_monitor_res_param {
	struct axi_monitor_head head;
	/*different version express interface */
	__u32 version;
	__u32 card_type;
	/* hub count */
	__u32 hub_num;
	/* axi monitor count in each hub */
	__u8 monitors[AMH_MAX];
	/* user use this to alloc buffer for sharememory */
	size_t sharedata_size;

	__u64 support_data_mode;

	/*express resource count, per count size is 8 byte*/
	__u32 res_cnt;
	void *res_data;
};

/* ipu profiling settings */
struct monitor_ipu_prof {
	/* include ipu cluster(0-15) */
	/* ipu/mem core num(0-4) */
	__u8 cluster_id;
	__u8 core_id;
	__u8 prof_id;
	__u64 start_pc;
	__u64 finish_pc;
};

struct monitor_ipu_prof_data {
	__u8 cluster_id;
	__u8 core_id;
	__u8 prof_id;
	/* same as ipu register */
	__u8 status;
	__u64 start_time;
	__u64 finish_time;
};

/* ipu performance settings */
struct monitor_ipu_perf {
	__u8 cluster_id;
	__u8 core_id;
	/* enable - 1, disable - 2 */
	__u8 command;
};

struct monitor_ipu_perf_data {
	__u8 cluster_id;
	__u8 core_id;
	/*
	 * 0 - not init
	 * 1 - enable
	 * 2 - disable
	 * 3 - config
	 * */
	__u8 status;
	__u8 reserved;
	__u32 raw_data[22];

};

#define SMMU_PCIE	1
#define SMMU_IPU	2
#define SMMU_JPU	3

/* smmu event settings */
struct monitor_smmu_perf {
	/*
	 * PCIE 1
	 * IPU 2
	 * JPU 3
	 * */
	__u8 smmu_type;
	/*
	 * IPU  : cluster num
	 * JPU  : 0
	 * PCIE : 0
	 * */
	__u8 smmu_group;
	/*
	 * IPU  : core num
	 * JPU  : jpu number 0 - 5
	 * PCIE : 0
	 * */
	__u8 smmu_index;
	/* 0 - 7 */
	__u8 event_id;
	/* 9bit */
	__u16 event_index;
	/* enable or disable */
	__u8 command;
};

struct monitor_smmu_perf_data {
	__u8 smmu_type;
	__u8 smmu_group;
	__u8 smmu_index;
	__u8 event_id;
	__u8 status;
	__u8 reserved;
	__u16 event_index;
	__u64 event_data;
};

/* llc event settings */
struct monitor_llc_perf {
	/* llc number 0 - 3 */
	__u8 llc_id;
	union {
		/* event number 0 - 3 */
		__u8 event_index;
		/* llc system */
		__u8 llc_system;
	};
	/* llc event type */
	__u16 event_type;
};

struct monitor_l1c_perf_cfg {
	/* cluster id */
	__u32 cluster_id;
	/* event type */
	__u32 cnt_type;
	/* enable or disable */
	__u8 command;
};

struct monitor_l1c_perf_ctrl {
	/* cluster id */
	__u32 cluster_id;
	/* start or stop */
	__u8 command;
};

struct monitor_llc_perf_data {
	__u8 llc_id;
	__u8 event_index;
	__u16 event_type;
	__u16 status;
	__u32 event_data;
};

struct mlu590_monitor_llc_perf_data {
	__u8 llc_id;
	__u8 llc_system;
	__u16 event_type;
	__u16 status;
	__u64 event_data;
	__u64 bias;
};

struct monitor_smmu_exception_data {
	__u8 smmu_type;
	__u8 smmu_group;
	__u8 smmu_index;

	__u32 total_count;
	__u32 per_count[24];
	__u64 reg[4];
};

struct monitor_l1c_perf_data {
	__u8 cluster_id;
	__u8 num;
	__u16 status;
	__u32 event_type;
	__u64 event_data[5];
};

struct pfmu_counter_number {
	/* in: counter type */
	__u32 cnt_type;
	/* out: counter number */
	__u32 cnt_num;
};

struct pfmu_counter_type {
	/* cluster id */
	__u32 cluster_id;
	/* core id */
	__u32 core_id;
	/* counter buffer size */
	__u32 cnt_num;
	/* counter variable, (type: u32) */
	void *cnt_type;
};

struct pfmu_event_type {
	/* cluster id */
	__u32 cluster_id;
	/* core id */
	__u32 core_id;
	/* counter index */
	__u32 cnt_index;
	/* counter variable, (type: u32) */
	__u32 cnt_type;
	/* enable : 1, disable : 0 */
	__u32 op;
};

struct pfmu_event_info {
	/* cluster id */
	__u32 cluster_id;
	/* core id */
	__u32 core_id;
	/* counter buffer size */
	__u32 cnt_num;
	/* event_type mask */
	__u64 event_mask;
	/* counter variable, (type: u32) */
	__u32 *event_type;
};

struct pfmu_cnt_ctrl {
	__u32 cluster_id;
	__u32 core_id;
	/* start - 1, stop - 0 */
	__u32 op;
};

struct pfmu_snapshot_pc {
	/* cluster id */
	__u32 cluster_id;
	/* core id */
	__u32 core_id;
	/* gid: counter group id, 0: snapshot0 counters; 1: snapshot1 counters; */
	__u32 gid;
	/* snapshot trigger PC 0 */
	__u64 snapshot_pc_0;
	/* snapshot trigger PC 1 */
	__u64 snapshot_pc_1;
};

struct axi_monitor_irqstatus {
	__u16 monitor_id;
	__u8 irq_status;
};

struct axi_monitor_errinfo {
	__u16 monitor_id;
	__u64 error_address;
	__u16 error_id;
	__u16 error_channel;
};

struct axi_monitor_pos {
	/* hub id */
	__u16 hub_id;
	/* valid buffer start */
	__u64 start;
	/* valid buffer end */
	__u64 end;
	/* counter */
	__u64 entry;
};

struct monitor_amh_direct_mode {
	__u16 hub_id;
	/* 0 - disable, 1 - enable */
	__u16 status;
	/* monitor update time in us */
	__u16 update_time;
	__u64 device_va_addr;
	__u64 buffer_size;
};

struct amh_high_mode_s {
	__u16 hub_id;
	/* 0 - disable, 1 - enable */
	__u16 status;
	/* monitor update time in us */
	__u16 update_time;
	/* 1 - normal, 0 - highrate */
	__u16 mode;
	__u64 device_addr;
	__u64 buffer_size;

	/* report range */
	__u32 report_range_size;
};

struct amh_sampling_info_s {
	/* hub id */
	__u16 hub_id;
	/* 0 - Low, 1 - High */
	__u16 mode;
	/* monitor update time in us */
	__u16 timestamp_update_time;
	/* axi monitor data sampling */
	__u16 monitor_update_time;
	/* for feature */
	__u16 ratio;
};

struct monitor_pfmu_config_hub_trace {
	/* cluster id */
	__u32 cluster_id;
	/* core id */
	__u32 core_id;
	/* trace mode 0 ~ 3 */
	__u32 trace_mode;
	__u32 trace_times;
	__u32 trace_period;
};

struct monitor_pfmu_stop_hub_trace {
	/* cluster id */
	__u32 cluster_id;
	/* core id */
	__u32 core_id;
};

enum pfmu_ipu_core_type {
	IPU_CORE,
	IPU_MEMCORE,
	TINYCORE,
	AIISP_CORE,
};

struct pfmu_ipu_l2p_table {
	__u16 hub_id;
	__u16 mon_id;
	__u32 logic_cid;
	__u32 phy_cid;
	union {
		struct {
			__u32 core_id:24;
			__u32 core_type:8;
		} ipu_core;
		struct {
			__u8 smmu_group_id;
			/* tinycore id */
			__u8 core_id;
			/* internal phycial id(0-7) */
			__u8 tinycore;
			__u8 core_type;
		} tiny_core;
	};
};

struct monitor_pfmu_hubtrace_table {
	__u32 total_item;
	struct pfmu_ipu_l2p_table *l2p;
};

#define DIRECT_DATA_MOD    0
#define DIRECT_RAW_MODE    1

struct monitor_direct_mode {
	/* hub id */
	__u16 hub_id;
	/* 0 - disable, 1 - enable */
	__u16 status;
	/* raw block count */
	__u32 raw_block_count;
	/* raw data block count per zone */
	__u32 raw_data_count_per_zone;
};

struct monitor_direct_data {
	/* hub id */
	__u16 hub_id;
	/* buff size */
	__u64 real_data_size;
	/* real data block */
	__u32 axi_block_count;
	/* buffer */
	void *buff;
};

struct monitor_direct_op {
	/* hub id */
	__u16 hub_id;
	__u32 op;
	/* monitor update time in us */
	__u16 timestamp_update_time;
	/* axi monitor data sampling */
	__u16 monitor_update_time;
};

struct monitor_read_buffer {
	/* hub id */
	__u16 hub_id;
	/* read start*/
	__u32 start;
	/* read count in data block */
	__u32 count;
	/* user buffer */
	void *buffer;
};

struct monitor_direct_ringbuf_pos {
	/* hub id */
	__u16 hub_id;
	/* data block index */
	__u64 index;
	/* driver loss data counter */
	__u64 loss_times;

	__u64 entry_count;
	/* last data,set flag */
	__u16 last_data_flag;
};

#pragma pack(1)
/*********************************************
c20l -> mlu270/mlu370
c20 -> mlu290
c50 -> mlu580/mlu590 pigeon

times_t ->mlu370/ce3226
times_c50_t ->  mlu580/mlu590 pigeon
pfmu_mode_x_t -> mlu370/ce3226
pfmu_mode_x_c50_t -> mlu580/mlu590 pigeon
*********************************************/
union axi_result_data_t {
	__u64 data[4];
	struct {
		__u64 data_type              :2;
		__u64 monitor_id             :6;
		__u64 write_throughput       :24;
		__u64 read_throughput        :24;
		__u64 write_outstanding      :12;
		__u64 write_max_latency      :20;
		__u64 read_outstanding       :12;
		__u64 read_max_latency       :20;
		__u64 write_total_latency    :32;
		__u64 read_total_latency     :32;
		__u64 write_bw               :36;
		__u64 read_bw                :36;
	} perf_c50_mode0_t;
	struct {
		__u64 data_type              :2;
		__u64 monitor_id             :6;
		__u64 write_throughput       :24;
		__u64 read_throughput        :24;
		__u64 write_outstanding      :12;
		__u64 write_max_latency      :20;
		__u64 read_outstanding       :12;
		__u64 read_max_latency       :20;
		__u64 write_bw_low           :32;
		__u64 read_bw_low            :32;
		__u64 write_bw_high          :36;
		__u64 read_bw_high           :36;
	} perf_c50_mode1_t;
	struct {
		__u64 data_type              :2;
		__u64 monitor_id             :6;
		__u64 write_throughput       :24;
		__u64 read_throughput        :24;
		__u64 write_outstanding      :12;
		__u64 write_bw_equay_high    :20;
		__u64 read_outstanding       :12;
		__u64 read_bw_equay_high     :20;
		__u64 write_bw_equay_low     :32;
		__u64 read_bw_equay_low      :32;
		__u64 write_bw               :36;
		__u64 read_bw                :36;
	} perf_c50_mode2_t;
	struct {
		__u64 data_type             :3;
		__u64 monitor_id            :5;
		__u64 write_throughput      :24;
		__u64 read_throughput       :24;
		__u8 write_outstanding      :8;
		__u64 write_max_latency     :24;
		__u8 read_outstanding       :8;
		__u64 read_max_latency      :24;
		__u64 write_bw_l            :32;
		__u64 read_bw_l             :32;
		__u64 write_bw_h            :36;
		__u64 read_bw_h             :36;
	} perf_ce3226_bw_mode_t;
	struct {
		__u64 data_type             :3;
		__u64 monitor_id            :5;
		__u64 write_throughput      :24;
		__u64 read_throughput       :24;
		__u8 write_outstanding      :8;
		__u64 write_max_latency     :24;
		__u8 read_outstanding       :8;
		__u64 read_max_latency      :24;
		__u64 write_total_latency   :32;
		__u64 read_total_latency    :32;
		__u64 write_bw              :36;
		__u64 read_bw               :36;
	} perf_ce3226_t;
	struct {
		__u64 data_type             :3;
		__u64 monitor_id            :5;
		__u64 write_throughput      :30;
		__u64 read_throughput       :30;
		__u64 write_max_latency     :16;
		__u64 read_max_latency      :16;
		__u64 write_total_latency   :40;
		__u64 read_total_latency    :40;
		__u64 write_bw              :38;
		__u64 read_bw               :38;
	} perf_c20_t;
	struct {
		__u64 data_type             :3;
		__u64 monitor_id            :5;
		__u64 write_throughput      :24;
		__u64 read_throughput       :24;
		__u64 write_max_latency     :32;
		__u64 read_max_latency      :32;
		__u64 write_total_latency   :32;
		__u64 read_total_latency    :32;
		__u64 write_bw              :36;
		__u64 read_bw               :36;
	} perf_c20l_t;
	struct {
		__u64 data_type             :3;
		__u64 reserved0             :61;
		__u64 time_stamp            :64;
		__u64 reserved1             :64;
		__u64 reserved2             :64;
	} times_t;
	struct {
		__u64 data_type             :2;
		__u64 reserved0             :62;
		__u64 time_stamp            :64;
		__u64 reserved1             :64;
		__u64 reserved2             :64;
	} times_c50_t;
	struct {
		__u64 data_type             :3;
		__u64 monitor_id            :5;
		__u64 reserved1             :14;
		__u64 domain_id             :4;
		__u64 core_id               :3;
		__u64 cluster_id            :3;
		__u64 cnt_6                 :32;
		__u64 cnt_2                 :64;
		__u64 cnt_1                 :64;
		__u64 cnt_0                 :64;
	} pfmu_mode_0_t;
	struct {
		__u64 data_type             :3;
		__u64 monitor_id            :5;
		__u64 reserved1             :14;
		__u64 domain_id             :4;
		__u64 core_id               :3;
		__u64 cluster_id            :3;
		__u64 cnt_6                 :32;
		__u64 cnt_5                 :32;
		__u64 cnt_4                 :32;
		__u64 cnt_1                 :64;
		__u64 cnt_0                 :64;
	} pfmu_mode_1_t;
	struct {
		__u64 data_type             :3;
		__u64 monitor_id            :5;
		__u64 reserved1             :14;
		__u64 domain_id             :4;
		__u64 core_id               :3;
		__u64 cluster_id            :3;
		__u64 cnt_6                 :32;
		__u64 cnt_5                 :32;
		__u64 cnt_4                 :32;
		__u64 cnt_3                 :32;
		__u64 cnt_2                 :32;
		__u64 cnt_0                 :64;
	} pfmu_mode_2_t;
	struct {
		__u64 data_type             :3;
		__u64 monitor_id            :5;
		__u64 reserved1             :14;
		__u64 domain_id             :4;
		__u64 core_id               :3;
		__u64 cluster_id            :3;
		__u64 cnt_6                 :32;
		__u64 cnt_5                 :32;
		__u64 cnt_4                 :32;
		__u64 cnt_3                 :32;
		__u64 cnt_2                 :32;
		__u64 cnt_1                 :32;
		__u64 cnt_0                 :32;
	} pfmu_mode_3_t;
	struct {
		__u64 data_type             :2;
		__u64 monitor_id            :6;
		__u64 reserved0             :10;
		__u64 trace_mode            :2;
		__u64 domain_id             :4;
		__u64 core_id               :3;
		__u64 cluster_id            :5;
		__u64 cnt_6                 :32;
		__u64 cnt_2                 :64;
		__u64 cnt_1                 :64;
		__u64 cnt_0                 :64;
	} pfmu_mode_0_c50_t;
	struct {
		__u64 data_type             :2;
		__u64 monitor_id            :6;
		__u64 reserved0             :10;
		__u64 trace_mode            :2;
		__u64 domain_id             :4;
		__u64 core_id               :3;
		__u64 cluster_id            :5;
		__u64 cnt_6                 :32;
		__u64 cnt_5                 :32;
		__u64 cnt_4                 :32;
		__u64 cnt_1                 :64;
		__u64 cnt_0                 :64;
	} pfmu_mode_1_c50_t;
	struct {
		__u64 data_type             :2;
		__u64 monitor_id            :6;
		__u64 reserved0             :10;
		__u64 trace_mode            :2;
		__u64 domain_id             :4;
		__u64 core_id               :3;
		__u64 cluster_id            :5;
		__u64 cnt_6                 :32;
		__u64 cnt_5                 :32;
		__u64 cnt_4                 :32;
		__u64 cnt_3                 :32;
		__u64 cnt_2                 :32;
		__u64 cnt_0                 :64;
	} pfmu_mode_2_c50_t;
	struct {
		__u64 data_type             :2;
		__u64 monitor_id            :6;
		__u64 reserved0             :10;
		__u64 trace_mode            :2;
		__u64 domain_id             :4;
		__u64 core_id               :3;
		__u64 cluster_id            :5;
		__u64 cnt_6                 :32;
		__u64 cnt_5                 :32;
		__u64 cnt_4                 :32;
		__u64 cnt_3                 :32;
		__u64 cnt_2                 :32;
		__u64 cnt_1                 :32;
		__u64 cnt_0                 :32;
	} pfmu_mode_3_c50_t;
};
#pragma pack()

#define MAX_PFMU_MODE_COUNTER (7)
union cn_monitor_data_t {
	struct {
		__u16 monitor_id;
		__u64 write_throughput;
		__u64 read_throughput;
		__u32 write_max_latency;
		__u32 read_max_latency;
		__u64 write_total_latency;
		__u64 read_total_latency;
		__u64 write_bw;
		__u64 read_bw;
		__u64 time_stamp;
	} monitor_perf_data;
	struct {
		__u16 monitor_id;
		__u16 mode;
		__u8 cluster_id;
		__u8 core_id;
		__u8 domain_id;
		__u8 reserve;
		__u64 cnt[MAX_PFMU_MODE_COUNTER];
	} monitor_pfmu_data;
};

#define MLU370_PFMU_SNAPSHOT_COUNTER_GID_MAX (2)
#define MLU370_PFMU_COUNTER_MAX              (16)

struct pmu_pfmu_rawdata_s {
	__u64 counter[MLU370_PFMU_COUNTER_MAX];
	__u64 snapshot_counter0[MLU370_PFMU_COUNTER_MAX];
	__u64 snapshot_counter1[MLU370_PFMU_COUNTER_MAX];
};

struct pmu_pfmu_perf_data_s {
	__u32 cluster_id;
	__u32 core_id;
	__u32 gid[MLU370_PFMU_SNAPSHOT_COUNTER_GID_MAX];
	__u8 status;
	__u8 reserved;
	struct pmu_pfmu_rawdata_s perf_data __attribute__((aligned(8)));
};

struct monitor_version {
	/* driver version */
	__u32 version;
	__u32 drv_ver;
};

struct monitor_ts_offset {
	/* host MONOTONIC RAW CLOCK time, driver to cnperf */
	__u64 host_timestamp_ns;
	/* device timestamp, driver to cnperf */
	__u64 device_timestamp_ns;
	__u64 max_err_ns;
};

/* used for ioctl _MONITOR_VERSION_CHECK */
enum driver_papi_version_check {
	DRIVER_DIRECT_MODE_VERSION_1 = 1,
	DRIVER_MONITOR_RESOURCE_MASK_VERSION_2,
	DRIVER_MONITOR_LLC_DRAM_VERSION_3,
	DRIVER_DISCARD1_VERSION_4,
	DRIVER_MONITOR_USER_ID_VERSION_5,
	DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6,
	DRVIER_PAPI_MAX_VERSION = DRIVER_PAPI_DEVICE_CAPACITY_VERSION_6,
};
enum driver_cnpapi_feature_enum {
	DRIVER_FEAT_TS_PERF_START = ((0X1ULL << 1) << 32),
	DRIVER_FEAT_TS_PERF_BASE_V1 = DRIVER_FEAT_TS_PERF_START,
	DRIVER_FEAT_TS_PERF_APPEND_DATA_CONFIGURABLE_V2 = DRIVER_FEAT_TS_PERF_START + 1,
	DRIVER_FEAT_TS_PERF_TILED_TASK_TYPE_CONFIG = DRIVER_FEAT_TS_PERF_START + 2,
	DRIVER_FEAT_TS_PERF_UNIQUE_ID = DRIVER_FEAT_TS_PERF_START + 3,
	DRIVER_FEAT_TS_PERF_END,

	DRIVER_FEAT_MONITOR_START = ((0X1ULL << 2) << 32),
	DRIVER_FEAT_MONITOR_BASE_V1 = DRIVER_FEAT_MONITOR_START,
	DRIVER_FEAT_MONITOR_RESOURCE_MASK_V2 = DRIVER_FEAT_MONITOR_START + 1,
	DRIVER_FEAT_MONITOR_LLC_DRAM_V3 = DRIVER_FEAT_MONITOR_START + 2,
	DRIVER_FEAT_MONITOR_USER_ID_V4 = DRIVER_FEAT_MONITOR_START + 3,
	DRIVER_FEAT_MONITOR_L1C_PERF = DRIVER_FEAT_MONITOR_START + 4,
	DRIVER_FEAT_MONITOR_END,

	DRIVER_FEAT_MEM_PERF_START = ((0X1ULL << 3) << 32),
	DRIVER_FEAT_MEM_PERF_BASE_V1 = DRIVER_FEAT_MEM_PERF_START,
	DRIVER_FEAT_MEM_PERF_END,

	/* DEPRECATED. */
	DRIVER_FEAT_CHECKPOINT_START = ((0X1ULL << 4) << 32),
	DRIVER_FEAT_CHECKPOINT_BASE_V1 = DRIVER_FEAT_CHECKPOINT_START,
	DRIVER_FEAT_CHECKPOINT_END,

	/* The feature of CHECKPOINT uses this group definition. */
	DRIVER_FEAT_MEM_CP_START = ((0X1ULL << 5) << 32),
	DRIVER_FEAT_MEM_CP_BASE = DRIVER_FEAT_MEM_CP_START,
	DRIVER_FEAT_MEM_CP_END,

	DRIVER_CNPAPI_RESERVE_FEATURE = ((0X1ULL << 31) << 32),   /* reserved for cnpapi moduleid */
};

#define MAX_FEATURE_NUM ((DRIVER_FEAT_TS_PERF_END - DRIVER_FEAT_TS_PERF_START) + \
						(DRIVER_FEAT_MONITOR_END - DRIVER_FEAT_MONITOR_START) + \
						(DRIVER_FEAT_MEM_PERF_END - DRIVER_FEAT_MEM_PERF_START) + \
						(DRIVER_FEAT_MEM_CP_END - DRIVER_FEAT_MEM_CP_START))

struct __version_check {
	__u32 papi_version;
	__u32 drv_version;
	__u64 len;
}__attribute__((__packed__));

struct monitor_version_check {
	struct __version_check ver_check;
	__u64 data[MAX_FEATURE_NUM];
}__attribute__((__packed__));

/* used for ioctl _PERF_MODE_CONFIG */
enum perf_ctrl {
	PERF_ENABLE = 1,
	PERF_DISABLE,
};

struct perf_cfg_tasks {
	__u64 task_type;
	__u64 event_type;
}__attribute__((__packed__));

struct perf_mode_config {
	__u32 perf_ctrl;
	__u32 record_mode;
	__u32 work_mode;
	__u32 collection_mode;
	__u32 performance_mode;
	__u64 buffer_size;
}__attribute__((__packed__));

struct perf_mode_config_v6 {
	__u32 perf_ctrl;
	__u32 record_mode;
	__u32 data_size;
	__u32 debug_data_size;
	struct perf_cfg_tasks *data_ptr;
	struct perf_cfg_tasks *debug_ptr;
	__u64 ts_buffer_size;
	__u64 mem_buffer_size;
}__attribute__((__packed__));

/* used for ioctl _PERF_CLKID_CONFIG */
enum perf_clkid_ops {
	PERF_CLKID_GET = 1,
	PERF_CLKID_SET,
};

struct perf_clkid_config {
	__u32 clkid_ops;
	__s32 clk_id;
} __attribute__((__packed__));

/* used for ioctl _PERF_TASK_TYPE_CONFIG */
enum perf_task_type_config_ops {
	PERF_TASK_TYPE_SET = 1,
	PERF_TASK_TYPE_GET,
};


struct perf_task_type_config {
	__u32 ops;
	__u64 task_type;
} __attribute__((__packed__));

#define MAX_CONFIGABLE_NUM (MAX_TS_TASK_NUM + MAX_MEM_TASK_NUM)
struct task_config_head {
	__u32 ops;
	__u32 len;
} __attribute__((__packed__));

struct perf_task_type_config_v2 {
	struct task_config_head head;
	__u64 data[MAX_CONFIGABLE_NUM];
} __attribute__((__packed__));


/* used for ioctl _PERF_TASK_INFO_SIZE_GET */
struct perf_info_size_get {
	__u64 task_type;
	__u32 normal_size;
	__u32 append_size;
} __attribute__((__packed__));

/* used for ioctl _PERF_TASK_INFO_GET */
struct perf_task_info {
	__u64 buffer_addr;
	__u64 buffer_size;
} __attribute__((__packed__));

struct perf_task_info_get {
	struct perf_task_info ts_perf;
	struct perf_task_info mem_perf;
} __attribute__((__packed__));

enum monitor_perf_type {
	TYPE_AXI_MON = 0,
	TYPE_IPU_PERF,
	TYPE_SMMU_PERF,
	TYPE_LLC_PERF,
	TYPE_SMMU_EXP,
	TYPE_L1C,
	TYPE_MAX
};

struct pmu_data_s {
	__u16 data_type;
	__u32 buffer_size;

	void *buffer;
};

struct axi_monitor_data_head {
	__u16 axi_monitor_entry_count;
	__u16 axi_monitor_num;
	__u16 axi_monitor_offset;
};

struct l1c_perf_data_head {
	__u16 l1c_perf_entry_count;
	__u16 l1c_perf_num;
	__u16 l1c_perf_offset;
};

struct smmu_exp_data_head {
	__u16 smmu_exp_entry_count;
	__u16 smmu_exp_num;
	__u16 smmu_exp_offset;
};

struct ipu_perf_data_head {
	__u16 ipu_perf_entry_count;
	__u16 ipu_perf_num;
	__u16 ipu_perf_offset;
};

struct smmu_perf_data_head {
	__u16 smmu_perf_entry_count;
	__u16 smmu_perf_num;
	__u16 smmu_perf_offset;
};

struct llc_perf_data_head {
	__u16 llc_perf_entry_count;
	__u16 llc_perf_num;
	__u16 llc_perf_offset;
};

/* monitor_mlu370_subtype is bind cn_board_mlu370_info_idx */
enum monitor_mlu370_subtype {
	MLU370_SUBTYPE_EVBD = 0,
	MLU370_SUBTYPE_EVBS,
	MLU370_SUBTYPE_X4L,
	MLU370_SUBTYPE_S4,
	MLU370_SUBTYPE_X8,
	MLU370_SUBTYPE_M8,
	MLU365_SUBTYPE_D2,
	MLU370_SUBTYPE_X4,
	MLU370_SUBTYPE_M83U,
	MLU370_SUBTYPE_X4K,
	MLU370_SUBTYPE_VF,
	MLU370_SUBTYPE_UNKNOWN,
	MLU370_SUBTYPE_MAX,
};

enum monitor_mlu590_subtype {
	MLU585_SUBTYPE = 0,
	MLU590_SUBTYPE_H8,
	MLU590_SUBTYPE_M9,
	MLU590_SUBTYPE_M9U,
	MLU590_SUBTYPE_M9L,
	MLU585_SUBTYPE_V1,
	MLU590_SUBTYPE_M9B,
	MLU590_SUBTYPE_M9C,
	MLU590_SUBTYPE_E,
	MLU590_SUBTYPE_VF,
	MLU590_SUBTYPE_UNKNOWN,
	MLU590_SUBTYPE_MAX,
};

enum monitor_pigeon_subtype {
	LEOPARD_SUBTYPE = 0,
	PIGEON_SUBTYPE,
	PIGEONC_SUBTYPE,
	DOVE_1V_2301_SUBTYPE,
	DOVE_1V_2302_SUBTYPE,
	PIGEON_SUBTYPE_UNKNOWN,
	PIGEON_SUBTYPE_MAX,
};

enum monitor_mlu580_subtype {
	MLU580_SUBTYPE_EVB = 0,
	MLU560_SUBTYPE,
	MLU560F_SUBTYPE,
	MLU580_SUBTYPE,
	MLU570_SUBTYPE,
	MLU570F_SUBTYPE,
	MLU580_SUBTYPE_VF,
	MLU580_SUBTYPE_UNKNOWN,
	MLU580_SUBTYPE_MAX,
};

struct axi_monitor_card_info {
	struct axi_monitor_head head;
	__u16 card_type;
	__u32 sub_type;
	__u16 die_cnt;
	__u32 chip_type;
};

struct perf_update_info {
	__u32 update_status;
	__u16 ipu_perf_entry_count;
	__u16 smmu_perf_entry_count;
	__u16 llc_perf_entry_count;
	__u16 smmu_exp_entry_count;
};

struct perf_update_info_v1 {
	__u32 update_status;
	__u16 ipu_perf_entry_count;
	__u16 smmu_perf_entry_count;
	__u16 llc_perf_entry_count;
	__u16 smmu_exp_entry_count;
	__u16 l1c_perf_entry_count;
};

struct monitor_chip_info {
	__u32 chip_type;
	__s8 chip_name[PLATFORM_NAME_LEN];
};

struct monitor_platform_info {
	__u32 buf_size;
	/* total chip count */
	__u32 total_chip;
	struct monitor_chip_info *info;
};

struct monitor_llc_mem {
	__u32 llc_id;
	__u32 mem_id;
};

enum monitor_res_type {
	PMU_LLC_MEM = 0,/*->struct monitor_llc_mem*/
	PMU_RES_MAX,
};

struct monitor_res_map_info {
	__u32 res_type;
	__u32 res_num;
	/*pointer to the struct that the enum monitor_res_type points to*/
	/* usage:                                    */
	/* res_type    <----> res_info               */
	/* PMU_LLC_MEM <----> struct monitor_llc_mem */
	void *res_info;
};

/* ioctl interface */
#define CAMBR_MONITOR_MAGIC 'Z'

/* monitor pmu */
#define MONITOR_AXIMON_NUMBER           1
#define MONITOR_PMU_NUMBER              20
#define MONITOR_TS_INFO_NUMBER          30
#define MONITOR_PFMU_NUMBER             40
#define MONITOR_GEN                     100
#define MONITOR_AXI_PARAM_START         140
#define MONITOR_CHECKPOINT_NUMBER       180
#define MONITOR_AXI_RES_START           200
#define MONITOR_MAX_NR_COUNT            256

enum monitor_nr_type {
	/* enum monitor_axi_type [1, 20] */
	_MONITOR_READ_PARAM = MONITOR_AXIMON_NUMBER,
	_MONITOR_AXI_DEFAULT,
	_MONITOR_AXI_OPEN,
	_MONITOR_AXI_CLOSE,
	_MONITOR_AXI_OPENALL,
	_MONITOR_AXI_CLOSEALL,
	_MONITOR_SET_TIMEST,
	_MONITOR_AXI_READIRQ = 10,
	_MONITOR_AXI_READERR = 11,
	_MONITOR_AXI_DIRECT_MODE,
	_MONITOR_READ_DATA = 15,
	_MONITOR_GEN1_PMU_DATA_READ,
	_MONITOR_GEN1_PMU_DATA_UPDATE,
	_MONITOR_AXI_FINISH = 20,

	/* enum monitor_pmu_type [20, 26] */
	_MONITOR_SET_IPUPROF = MONITOR_PMU_NUMBER,
	_MONITOR_SET_IPUPMU,
	_MONITOR_SET_SMMUPMU,
	_MONITOR_SET_LLCPMU,
	_MONITOR_CLR_PMUDATA,
	_MONITOR_SET_L1CPMU,
	_MONITOR_CTRL_L1CPMU,
	_MONITOR_PMU_FINISH,

	/* enum monitor_ts_info_type [30, 39]*/
	_MONITOR_TS_INFO_SET = MONITOR_TS_INFO_NUMBER,  /* deprecation */
	_MONITOR_TS_INFO_GET,  /* deprecation */
	_MONITOR_TS_OFFSET_GET,  /* deprecation */
	_MONITOR_VERSION_CHECK,
	_PERF_MODE_CONFIG,
	_PERF_CLKID_CONFIG,
	_PERF_TASK_TYPE_CONFIG,
	_PERF_TASK_INFO_SIZE_GET,
	_PERF_TASK_INFO_GET,
	_PERF_TASK_TYPE_CONFIG_V2,
	_MONITOR_TS_INFO_FINISH,

	/* enum monitor_pfmu_type [40, 48] */
	_MONITOR_PFMU_GET_CNT_NUM = MONITOR_PFMU_NUMBER,
	_MONITOR_PFMU_GET_CNT_TYPE,
	_MONITOR_PFMU_SET_CNT_TYPE,
	_MONITOR_PFMU_SET_SNAPSHOT_PC,
	_MONITOR_PFMU_START,
	_MONITOR_PFMU_EVENT_SET,
	_MONITOR_PFMU_EVENT_GET,
	_MONITOR_PFMU_CTRL,
	_MONITOR_PFMU_FINISH,

	_MONITOR_SET_HIGHACCURATE = 51,
	_MONITOR_LOCK_PMU = 60,
	_MONITOR_TEST_RPCOPEN = 99,

	/* enum axi monitor gen1 [100, 130] */
	_MONITOR_AXI_GEN1_DIRECT_READ_PARAM = MONITOR_GEN,
	_MONITOR_AXI_GEN1_DEFAULT,
	_MONITOR_AXI_GEN1_OPEN,
	_MONITOR_AXI_GEN1_CLOSE,
	_MONITOR_AXI_GEN1_OPENALL,
	_MONITOR_AXI_GEN1_CLOSEALL,
	_MONITOR_AXI_GEN1_DIRECT_GET_POS,
	_MONITOR_AXI_GEN1_DIRECT_MODE,
	_MONITOR_AXI_GEN1_DIRECT_READ_RINGBUF,
	_MONITOR_AXI_GEN1_DIRECT_READ_DATA,
	_MONITOR_AXI_HUB_TRACE_CONFIG,
	_MONITOR_AXI_GEN1_DIRECT_HUB_CTRL,
	_MONITOR_AXI_GEN1_READ_DATA,
	_MONITOR_AXI_GEN1_READIRQ,
	_MONITOR_AXI_GEN1_READERR,
	_MONITOR_AXI_HUB_TRACE_STOP,
	_MONITOR_AXI_DRIVER_VER,
	_MONITOR_AXI_HUB_TRACE_L2P_MAP,
	_MONITOR_AXI_HUB_TRACE_SET,
	_MONITOR_GEN_END = 130,

	/* enum monitor_axi_param_type [140 ,160] */
	_MONITOR_AXI_GEN1_CARD_INFO = MONITOR_AXI_PARAM_START,
	_MONITOR_AXI_GEN1_READ_PARAM,
	_MONITOR_AXI_GEN1_PLATFORM_TYPE,
	_MONITOR_AXI_GEN1_RES_MAP,
	_MONITOR_AXI_PARAM_END = 160,

	/* enum monitor_cp_param_type [180 ,190] */
	_MONITOR_CHECKPOINT_CLEAN_CACHE = MONITOR_CHECKPOINT_NUMBER,
	_MONITOR_CHECKPOINT_MEMORY_INFO_GET,
	_MONITOR_CHECKPOINT_FINISH = 190,

	/* enum monitor_axi_res_type [200, 220]*/
	_MONITOR_AXI_GEN1_RES_INFO = MONITOR_AXI_RES_START,
	_MONITOR_AXI_RES_END = 220,

	/* NR [0-255] */
	_MONITOR_MAX_NR = MONITOR_MAX_NR_COUNT,
};

enum monitor_driver_ver {
	_MONITOR_DRIVER_V0 = 0,
	_MONITOR_DRIVER_V1 = 1,
	/* version2-15 is use by hotfix */
	/* driver 16,return real max version */
	_MONITOR_DRIVER_V16 = 16,
	/* driver 32,support raw hubtrace data */
	_MONITOR_DRIVER_V32 = 32,
	/* driver 48,support hubtrace cluster logic to phyical */
	_MONITOR_DRIVER_V48 = 48,
	/* driver 64,keep 4.15.4 */
	_MONITOR_DRIVER_V64 = 64,
	/* add hubtrace config interface */
	_MONITOR_DRIVER_V80 = 80,
	/* driver 96,support bw mode */
	_MONITOR_DRIVER_V96 = 96,
	/* add platform table */
	_MONITOR_DRIVER_V112 = 112,
	/* add drv5.0 delete data parse mode and temporay version */
	_MONITOR_DRIVER_V128 = 128,
	_MONITOR_DRIVER_VER = _MONITOR_DRIVER_V128,
};
/* monitor pmu */
#define MONITOR_READ_PARAM	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_READ_PARAM, unsigned long)
#define MONITOR_AXI_DEFAULT	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_DEFAULT, unsigned long)
#define MONITOR_AXI_OPEN	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_OPEN, unsigned long)
#define MONITOR_AXI_CLOSE	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_CLOSE, unsigned int)
#define MONITOR_AXI_OPENALL	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_OPENALL, unsigned int)
#define MONITOR_AXI_CLOSEALL	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_CLOSEALL, unsigned int)
#define MONITOR_SET_TIMEST	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_SET_TIMEST, unsigned int)
#define MONITOR_AXI_READIRQ	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_READIRQ, unsigned int)
#define MONITOR_AXI_READERR	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_READERR, unsigned long)
#define MONITOR_AXI_DIRECT_MODE	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_DIRECT_MODE, struct monitor_amh_direct_mode)
#define MONITOR_READ_DATA	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_READ_DATA, unsigned long)
#define MONITOR_SET_IPUPROF	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_SET_IPUPROF, unsigned long)
#define MONITOR_SET_IPUPMU	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_SET_IPUPMU, unsigned long)
#define MONITOR_SET_SMMUPMU	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_SET_SMMUPMU, unsigned long)
#define MONITOR_SET_LLCPMU	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_SET_LLCPMU, unsigned long)
#define MONITOR_CLR_PMUDATA	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_CLR_PMUDATA, unsigned long)
#define MONITOR_SET_L1CPMU	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_SET_L1CPMU, unsigned long)
#define MONITOR_CTRL_L1CPMU	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_CTRL_L1CPMU, unsigned long)
#define MONITOR_GEN1_PMU_DATA_READ	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_GEN1_PMU_DATA_READ, unsigned long)
#define MONITOR_GEN1_PMU_DATA_UPDATE	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_GEN1_PMU_DATA_UPDATE, unsigned long)

/* task timestamp info */
#define MONITOR_VERSION_CHECK \
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_VERSION_CHECK, struct monitor_version_check)
#define PERF_MODE_CONFIG \
	_IOW(CAMBR_MONITOR_MAGIC, _PERF_MODE_CONFIG, struct perf_mode_config_v6)
#define PERF_CLKID_CONFIG \
	_IOW(CAMBR_MONITOR_MAGIC, _PERF_CLKID_CONFIG, struct perf_clkid_config)
#define PERF_TASK_TYPE_CONFIG \
	_IOW(CAMBR_MONITOR_MAGIC, _PERF_TASK_TYPE_CONFIG, struct perf_task_type_config)
#define PERF_TASK_TYPE_CONFIG_V2 \
	_IOW(CAMBR_MONITOR_MAGIC, _PERF_TASK_TYPE_CONFIG_V2, struct perf_task_type_config_v2)
#define PERF_TASK_INFO_SIZE_GET \
	_IOW(CAMBR_MONITOR_MAGIC, _PERF_TASK_INFO_SIZE_GET, struct perf_info_size_get)
#define PERF_TASK_INFO_GET \
	_IOW(CAMBR_MONITOR_MAGIC, _PERF_TASK_INFO_GET, struct perf_task_info_get)

/* monitor test */
#define MONITOR_SET_HIGHACCURATE	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_SET_HIGHACCURATE, unsigned long)
#define MONITOR_LOCK_PMU	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_LOCK_PMU, unsigned long)
#define MONITOR_TEST_RPCOPEN		\
	_IO(CAMBR_MONITOR_MAGIC,  _MONITOR_TEST_RPCOPEN)

/* high rate */
#define MONITOR_AXI_GEN1_DIRECT_READ_PARAM	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_DIRECT_READ_PARAM, unsigned long)
#define MONITOR_AXI_GEN1_DEFAULT	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_DEFAULT, unsigned long)
#define MONITOR_AXI_GEN1_OPEN	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_OPEN, unsigned long)
#define MONITOR_AXI_GEN1_CLOSE	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_CLOSE, unsigned int)
#define MONITOR_AXI_GEN1_OPENALL	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_OPENALL, unsigned int)
#define MONITOR_AXI_GEN1_CLOSEALL	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_CLOSEALL, unsigned int)
#define MONITOR_AXI_GEN1_DIRECT_READ_RINGBUF	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_DIRECT_READ_RINGBUF, unsigned long)
#define MONITOR_AXI_GEN1_DIRECT_READ_DATA	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_DIRECT_READ_DATA, unsigned long)
#define MONITOR_AXI_GEN1_DIRECT_HUB_CTRL	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_DIRECT_HUB_CTRL, struct monitor_direct_op)
#define MONITOR_AXI_GEN1_DIRECT_MODE	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_DIRECT_MODE, struct monitor_direct_mode)
#define MONITOR_AXI_HUB_TRACE_CONFIG	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_HUB_TRACE_CONFIG, unsigned long)
#define MONITOR_AXI_GEN1_READ_DATA	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_READ_DATA, unsigned long)
#define MONITOR_AXI_GEN1_DIRECT_GET_POS	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_DIRECT_GET_POS, unsigned long)
#define MONITORPFMU_GET_CNT_NUM	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_PFMU_GET_CNT_NUM, unsigned long)
#define MONITOR_PFMU_GET_CNT_TYPE	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_PFMU_GET_CNT_TYPE, unsigned long)
#define MONITOR_PFMU_SET_CNT_TYPE	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_PFMU_SET_CNT_TYPE, unsigned long)
#define MONITOR_PFMU_SET_SNAPSHOT_PC	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_PFMU_SET_SNAPSHOT_PC, unsigned long)
#define MONITOR_PFMU_START	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_PFMU_START, unsigned long)
#define MONITOR_PFMU_EVENT_SET	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_PFMU_EVENT_SET, unsigned long)
#define MONITOR_PFMU_EVENT_GET	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_PFMU_EVENT_GET, unsigned long)
#define MONITOR_PFMU_CTRL	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_PFMU_CTRL, unsigned long)

#define MONITOR_AXI_GEN1_READIRQ	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_READIRQ, unsigned long)
#define MONITOR_AXI_GEN1_READERR	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_READERR, unsigned long)

#define MONITOR_AXI_HUB_TRACE_STOP	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_HUB_TRACE_STOP, unsigned long)
#define MONITOR_AXI_DRIVER_VER	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_DRIVER_VER, unsigned long)
#define MONITOR_AXI_CARD_INFO	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_CARD_INFO, unsigned long)

#define MONITOR_AXI_GEN1_READ_PARAM	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_READ_PARAM, unsigned long)
#define MONITOR_AXI_HUB_TRACE_L2P_MAP	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_HUB_TRACE_L2P_MAP, unsigned long)
#define MONITOR_AXI_HUB_TRACE_SET	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_HUB_TRACE_SET, unsigned long)
#define MONITOR_AXI_PLATFORM_TYPE	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_PLATFORM_TYPE, unsigned long)
#define MONITOR_AXI_GEN1_RES_INFO	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_RES_INFO, unsigned long)
#define MONITOR_AXI_GEN1_RES_MAP	\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_AXI_GEN1_RES_MAP, unsigned long)

/* CNDev */

struct cndev_cardnum {
	/* driver version */
	__u16 version;
	/* total mlu card number */
	__u8 card_count;
};

struct cndev_head {
	/* cndev driver version */
	__u16 version;
	/* input userspace buffer max size(except pointer length in struct) */
	__u32 buf_size;
	/* output kernel buffer size */
	__u32 real_size;
	/* spicify card number */
	__u16 card;
};

/* chassis info */
#define CHASSIS_SN_BYTES                       (8)
#define CHASSIS_PRODUCT_DATE_BYTES             (4)
#define CHASSIS_PART_NUMBER_BYTES              (8)
#define CHASSIS_VENDOR_NAME_BYTES              (16)

/* chassis info */
#define FAN_SPEED                              (12)

/* ib info */
#define IB_CARD_SN_BYTES                       (24)
#define IB_CARD_MODEL_BYTES                    (16)
#define IB_CARD_FW_BYTES                       (2)
#define IB_CARD_MFC_BYTES                      (8)
#define IB_BOARD_COUNT                         (2)

/* nvme info */
#define NVME_SN_BYTES                          (20)
#define NVME_MODEL_BYTES                       (16)
#define NVME_FW_BYTES                          (8)
#define NVME_MFC_BYTES                         (8)
#define NVME_SSD_COUNT                         (4)

/* psu info */
#define PSU_SN_BYTES                           (16)
#define PSU_MODEL_BYTES                        (16)
#define PSU_FW_BYTES                           (16)
#define PSU_MFC_BYTES                          (16)
#define PSU_COUNT                              (2)

/* chassis info v5 */
#define MLU590_CHASSIS_SN_BYTES                (8)
#define MLU590_CHASSIS_PRODUCT_DATE_BYTES      (4)
#define MLU590_CHASSIS_PART_NUMBER_BYTES       (12)
#define MLU590_CHASSIS_VENDOR_NAME_BYTES       (16)

/* chassis info v5 */
#define MLU590_FAN_COUNT                       (28)
#define MLU290_CHASSIS_TEMP_COUNT              (2)
#define MLU370_CHASSIS_TEMP_COUNT              (2)
#define MLU590_CHASSIS_TEMP_COUNT              (2)

/* ib info v5 */
#define MLU590_IB_CARD_SN_BYTES                (24)
#define MLU590_IB_CARD_MODEL_BYTES             (16)
#define MLU590_IB_CARD_FW_BYTES                (4)
#define MLU590_IB_CARD_MFC_BYTES               (8)
#define MLU590_IB_BOARD_COUNT                  (8)

/* nvme info v5 */
#define MLU590_NVME_SN_BYTES                   (20)
#define MLU590_NVME_MODEL_BYTES                (16)
#define MLU590_NVME_FW_BYTES                   (4)
#define MLU590_NVME_MFC_BYTES                  (8)
#define MLU590_NVME_SSD_COUNT                  (8)

/* psu info v5 */
#define MLU590_PSU_SN_BYTES                    (16)
#define MLU590_PSU_MODEL_BYTES                 (16)
#define MLU590_PSU_FW_BYTES                    (16)
#define MLU590_PSU_MFC_BYTES                   (16)
#define MLU590_PSU_COUNT                       (6)

struct cndev_nvme_ssd_info {
	__u8 nvme_info_ready;

	__u8 nvme_sn[NVME_SN_BYTES];

	__u8 nvme_model[NVME_MODEL_BYTES];

	__u8 nvme_fw[NVME_FW_BYTES];

	__u8 nvme_mfc[NVME_MFC_BYTES];
};

struct cndev_psu_info {
	__u8 psu_info_ready;

	__u8 psu_sn[PSU_SN_BYTES];

	__u8 psu_model[PSU_MODEL_BYTES];

	__u8 psu_fw[PSU_FW_BYTES];

	__u8 psu_mfc[PSU_MFC_BYTES];
};

struct cndev_ib_info {
	__u8 ib_info_ready;

	__u8 ib_sn[IB_CARD_SN_BYTES];

	__u8 ib_model[IB_CARD_MODEL_BYTES];

	__u8 ib_fw[IB_CARD_FW_BYTES];

	__u8 ib_mfc[IB_CARD_MFC_BYTES];
};

struct cndev_card_info {
	struct cndev_head head;

	__u16 mcu_major_ver; /* MCU major id */
	__u16 mcu_minor_ver; /* MCU minor id */
	__u16 mcu_build_ver; /* MCU build id */
	__u16 driver_major_ver; /* Driver major id */
	__u16 driver_minor_ver; /* Driver minor id */
	__u16 driver_build_ver; /* Driver build id */

	__u16 bus_type;
	__u32 subsystem_id; /* PCIe Sub-System ID */
	__u32 device_id; /* PCIe Device ID */
	__u16 vendor_id; // NOLINT /* PCIe Vendor ID */
	__u16 subsystem_vendor; // NOLINT /* PCIe Sub-Vendor ID */
	__u32 domain; /* PCIe domain */
	__u32 bus; /* PCIe bus_num */
	__u32 device; /* PCIe device, slot */
	__u32 func; /* PCIe function, func */

	__u16 ipu_cluster; /* card cluster count */
	__u32 ipu_core; /* card core count */

	__u32 max_speed; /* PCI max speed */
	__u32 max_width; /* PCI width */

	//cndevNameEnum_t id; /* card name */
	__u32 card_name;
	__u64 card_sn; /* card SN in hex */

	char board_model[BOARD_MODEL_NAME_LEN]; /* boaed model name */

	__u64 mother_board_sn; /* mother board SN in hex */
	__u8 qdd_status; /* QDD status */

	__u8 uuid[DRIVER_PMU_UUID_SIZE]; /* device uuid */

	__u16 mother_board_mcu_fw_ver;

	__u16 slot_id;

	__u64 pcie_fw_info;

	__u8 chip_id;

	__u8 secure_mode; /* boot mode */

	__u8 soc_id[SOC_ID_SIZE]; /* soc id 256bit*/

	__u32 data_width; /* mem data width, unit: bits */

	__u32 bandwidth; /* DDR Bandwidth, unit: B/ns */
	__u32 bandwidth_decimal; /* DDR Bandwidth decimal */
};

struct card_mac_info_s {
	__u8 mac_addr_ready[2];
	/* MAC ADDRESS */
	__u8 card_mac_address[2][6];
};

struct card_pre_setting_info_s {
	__u8 pre_setting_ready;

	__u16 tdp;
	__u8 over_temp_duce_freq_temp;
	__u8 over_temp_poweroff_temp;
	__u8 max_core_temp;
	__u8 max_mem_temp;
};

struct cndev_card_info_ext {
	struct cndev_head head;

	struct card_mac_info_s mac_info;
	struct card_pre_setting_info_s pre_setting_info;
};

struct cndev_chassis_info {

	struct cndev_head head;

	__u8 info_ready; /* bitmap 0:sn, 1:prd_date, 2:part_num, 3:vendor_name */

	__u64 chassis_sn; /* chassis sn*/

	__u32 chassis_product_date; /* chassis product date, seconds from 1970-1-1 */

	char chassis_part_num[CHASSIS_PART_NUMBER_BYTES];

	char chassis_vendor_name[CHASSIS_VENDOR_NAME_BYTES];

	__u8 nvme_ssd_num;
	struct cndev_nvme_ssd_info nvme_info[NVME_SSD_COUNT];

	__u8 ib_board_num;
	struct cndev_ib_info ib_info[IB_BOARD_COUNT];

	__u8 psu_num;
	struct cndev_psu_info psu_info[PSU_COUNT];

	__u32 chassis_part_name_size;
	void *chassis_part_name;

	/*only for MLU500*/
	/* indicated struct cndev_nvme_ssd_info */
	void *p_nvme_info;

	/* indicated struct cndev_ib_info_v5 */
	void *p_ib_info;

	/* indicated struct cndev_psu_info */
	void *p_psu_info;
};

struct cndev_chassis_power_info {

	struct cndev_head head;

	/* chassis power unit:W */
	__u16 chassis_power;
	/* kernel set this var to user to indicate actual number of chassis fan */
	__u8 chassis_fan_num;
	/* chassis fan variable, (type: __s16) */
	void *chassis_fan;

	/* user set this var to kernel to indicate userspace length of (*temp) */
	/* kernel set this var to user to indicate actual number of temperature */
	__u8 chassis_temperature_num;
	/* temperature variable, (type: __s8) */
	void *chassis_temp;
};

enum cndev_perf_limit {
	CNDEV_PERF_LIMIT_TDP,
	CNDEV_PERF_LIMIT_POWER_CAPPING,
	CNDEV_PERF_LIMIT_FREQ_LIMIT,
	CNDEV_PERF_LIMIT_FREQ_LOCK,
	CNDEV_PERF_LIMIT_POWER_BRAKE,
	CNDEV_PERF_LIMIT_OVERTEMP_UNDERCLOCKING,

	CNDEV_PERF_LIMIT_MAX_COUNT,
};

struct cndev_ib_info_v5 {
	__u8 ib_info_ready;

	__u8 ib_sn[MLU590_IB_CARD_SN_BYTES];

	__u8 ib_model[MLU590_IB_CARD_MODEL_BYTES];

	__u8 ib_fw[MLU590_IB_CARD_FW_BYTES];

	__u8 ib_mfc[MLU590_IB_CARD_MFC_BYTES];
};

struct cndev_power_info {
	struct cndev_head head;
	/* board max power unit:W */
	__u16 max_power;
	/* current power unit:W */
	__u16 power_usage;
	/* MLU fan speed, the percentage of the max fan speed */
	__u16 fan_speed;
	/* user set this var to kernel to indicate userspace length of (*temp) */
	/* kernel set this var to user to indicate actual number of temperature */
	__u8 temperature_num;
	/* temperature variable, (type: __s8) */
	void *temp;

	__u16 power_usage_decimal;
	/* current machine power unit:W */
	__u16 machine_power;
	__u16 max_power_decimal;

	/* kernel set this var to user to indicate actual number of fan */
	__u8 fan_num;
	/* fan variable, (type: __s16) */
	void *fan;
	/* Thermal Design Power */
	__u16 tdp;
	/* board min power cap unit:W */
	__u16 min_power_cap;
	/* board min power cap decimal */
	__u16 min_power_cap_decimal;
	/* board max power cap decimal */
	__u16 max_power_cap_decimal;
	/* over temperature power-off times. */
	__u32 over_temp_poweroff_times;
	/* over temperature under clocking times. */
	__u32 over_temp_underclock_times;
	/* over temperature power-off tmeperature. unit: degrees Celsius */
	__s8 over_temp_poweroff_temp;
	/* over temperature under clocking tmeperature. unit: degrees Celsius */
	__s8 over_temp_underclock_temp;
	/* total limit count */
	__u8 perf_limit_num;
	/* power limit reason detail */
	__u8 *perf_limit;

	__u16 instantaneous_power;
	__u16 instantaneous_power_decimal;

	__u64 ipu_cluster_mask;
	__u16 ipu_cluster_freq_num;
	/* ipu cluster freq, u16, unit MHz*/
	void *ipu_cluster_freq;

	/* request chassis power info, 0:request chassis power info, 1: ingore chassis power info */
	__u32 ignore_chassis_power_info;

	__u32 edpp_count;
	__u32 tdp_freq_capping_count;
};

struct cndev_memory_info_old {
	struct cndev_head head;
	/* MLU physical total memory, unit:MB */
	__u64 phy_total;
	/* MLU physical used memory, unit:MB */
	__u64 phy_used;
	/* MLU virtual total memory, unit:MB */
	__u64 virt_total;
	/* MLU virtual used memory, unit:MB */
	__u64 virt_used;
};

enum cndev_mlu_memory_unit {
	MLU_MEM_UNIT_DEFAULT = 0,
	MLU_MEM_UNIT_MB = MLU_MEM_UNIT_DEFAULT,
	MLU_MEM_UNIT_KB,
	MLU_MEM_UNIT_B,
	MLU_MEM_UNIT_UNKNOWN,
};

struct cndev_memory_info {
	struct cndev_head head;
	/* MLU physical total memory */
	__u64 phy_total;
	/* MLU physical used memory */
	__u64 phy_used;
	/* MLU virtual total memory */
	__u64 virt_total;
	/* MLU virtual used memory */
	__u64 virt_used;
	/* memory channel number */
	__u64 chl_num;
	/* memory used each channel, (type: __u64) */
	void *each_chl;
	/**< ARM OS Total memory, unit:Bytes*/
	__u64 sys_totalram;
	/**< ARM OS Free memory, unit:Bytes*/
	__u64 sys_freeram;
	/*  MLU memory unit ctrl, 0:MB, 1:KB, 2:B*/
	__u8 mlu_memory_unit;
	/* MLU FA total memory */
	__u64 fa_total;
	/* MLU FA used memory */
	__u64 fa_used;
	/* MLU Global Memory size */
	__u64 global_mem;
};

struct proc_mem_info {
	/* process pid */
	__s32 pid;
	/* process used physical memory */
	__u64 phy_memused;
	/* process used virtual memory */
	__u64 virt_memused;
};
struct cndev_proc_info {
	struct cndev_head head;
	/* process number */
	__u32 proc_num;
	struct proc_mem_info *proc_info_node;
};


struct cndev_health_state {
	struct cndev_head head;
	/* use to indicate host driver state */
	/* check in cndrv_core.h 'enum cn_boot_state' */
	__u8 host_state;
	__u8 card_state;
};

enum ECC_TYPE {
	ECC_SBE      = 0,
	ECC_DBE      = 1,
	ECC_PARITY   = 2,
	ECC_MAX_TYPE,
};

enum TNC_LOCATION_TYPE {
	TNC_LOCATION_CTRAM  = 0,
	TNC_LOCATION_ICACHE = 1,
	TNC_LOCATION_ROB    = 2,
	TNC_LOCATION_NUM,
};

/* IPU location enum */
enum IPU_LOCATION_TYPE {
	IPU_LOCATION_CTRAM  = 0,
	IPU_LOCATION_LTRAM  = 1,
	IPU_LOCATION_ICACHE = 2,
	IPU_LOCATION_DCACHE = 3,
	IPU_LOCATION_L1C    = 4,
	IPU_LOCATION_ROB    = 5,
	IPU_LOCATION_SMU    = 6,
	IPU_LOCATION_NUM,
};

/* PCIE ecc location enum */
enum PCIE_LOCATION_TYPE {
	PCIE_LOCATION_BRIDGE = 0,
	PCIE_LOCATION_TRX    = 1,
	PCIE_LOCATION_SRAM   = 2,
	PCIE_LOCATION_NUM,
};

/* SMMU parity location enum */
enum SMMU_LOCATION_TYPE {
	/* TLB RAM */
	SMMU_LOCATION_TLB  = 0,
	/* PTW data cache RAM */
	SMMU_LOCATION_PTW  = 1,
	/* L3 cache tag RAM */
	SMMU_LOCATION_L3CT = 2,
	/* L3 cache data RAM */
	SMMU_LOCATION_L3CD = 3,
	SMMU_LOCATION_NUM,
};

/* LLC ecc location enum */
enum LLC_LOCATION_TYPE {
	LLC_LOCATION_CT   = 0,
	LLC_LOCATION_DR   = 1,
	LLC_LOCATION_DB   = 2,
	LLC_LOCATION_TR   = 3,
	LLC_LOCATION_CQ   = 4,
	LLC_LOCATION_RDB  = 5,
	LLC_LOCATION_RCQ  = 6,
	LLC_LOCATION_NUM,
};

/* NCS ecc location enum */
enum NCS_LOCATION_TYPE {
	NCS_LOCATION_MAC = 0,
	NCS_LOCATION_AOBC = 1,
	NCS_LOCATION_ROCE = 2,
	NCS_LOCATION_RXDMA = 3,
	NCS_LOCATION_NUM,
};

enum cndev_ecc_module {
	CNDEV_IPU_ECC  = 0,
	CNDEV_TNC_ECC  = 1,
	CNDEV_PCIE_ECC = 2,
	CNDEV_SMMU_ECC = 3,
	CNDEV_LLC_ECC  = 4,
	CNDEV_NCS_ECC  = 5,
	CNDEV_ECC_NUM,
};

struct cndev_ecc_desc_info {
	__u32 type;
	__u32 module;
	__u64 ecc_location;
	__u64 ecc_counter;
};

struct cndev_ecc_info {
	struct cndev_head head;
	/* single single-bit error / corrected */
	__u64 single_biterr;
	/* multiple single-bit error / corrected */
	/* when 290/370 it means two bit err */
	__u64 multi_biterr;
	/* single multiple-bits error / uncorrected */
	__u64 single_multierr;
	/* multiple multiple-bits error / uncorrected */
	__u64 multi_multierr;
	/* corrected error */
	__u64 corrected_err;
	/* uncorrected error */
	__u64 uncorrect_err;
	/* ECC error total times */
	__u64 total_err;
	/* D2DC crc error */
	__u64 die2die_crc_err;
	/* D2DC crc error overflow */
	__u64 die2die_crc_err_overflow;
	/* memsys addr forbidden */
	__u64 addr_forbidden_err;
	/* inline ecc support */
	__u8 inline_ecc_support;

	__u32 ecc_desc_num;
	void *ecc_desc;
};

struct cndev_vm_info {
	struct cndev_head head;
	/* running in vf or pf */
	__u8 vm_check;
	/* vm number if in pf */
	__u8 vm_num;
};

struct cndev_ipuutil_info {
	struct cndev_head head;
	__u16 chip_util;
	__u8 core_num;
	void *core_util;
	__u8 tinycore_num;
};

struct cndev_acpuutil_info {
	struct cndev_head head;
	__u16 chip_util;
	__u8 core_num;
	void *core_util;
};

struct cndev_acpuutil_timer {
	struct cndev_head head;
	__u32 ops_type;
	__u32 timer;
};
struct cndev_codecutil_info {
	struct cndev_head head;
	__u8 vpu_num;
	__u8 jpu_num;
	__u8 scaler_num;
	void *codec_util;
};

/* old struct */
struct cndev_ipufreq_info {
	struct cndev_head head;
	/* MHz */
	__u32 ipu_freq;
};
/* new struct for freq */
struct cndev_freq_info {
	struct cndev_head head;
	/* MHz */
	__u32 ipu_freq;
	__u32 ddr_freq;
	/* IPU over temperature dynamic freq */
	__u8 ipu_overtemp_dfs_flag;
	/* IPU fast dynamic freq */
	__u8 ipu_fast_dfs_flag;

	__u8 die_ipu_cnt;
	/* __u32 data, 0:die 0 ipu freq, 1:die 1 ipu freq */
	void *die_ipu_freq;

	/* CE3226:0:CT, 1:LT, 2:all MLU:N/A */
	/* PIGEON:0:ipu0, 1:ipu1, 2:all MLU:N/A */
	__u16 type;
	/* range for freq (0:min, 1:max) */
	__u16 range[2];
	/* enum available freq(MHz) count, 0:all */
	__u16 freq_num;
	/* freq , (type: __u16) */
	void *freq;

	/* MHz */
	__u32 rated_ipu_freq;
};

struct cndev_curbuslnk_info {
	struct cndev_head head;

	__u32 cur_speed;
	__u32 cur_width;
};

struct cndev_pcie_throughput {
	struct cndev_head head;

	__u64 pcie_read;
	__u64 pcie_write;

	__u64 soft_retry_cnt;
};

struct pinned_mem_param {
	__u32 size;
	__u64 uaddr;
	__u64 handle;
};

struct pinned_mem_compat_param {
	__u64 size;
	__u64 uaddr;
	__u64 handle;
	__u64 pad;
};

/* adapt to alloc host pinned memory with numa node */
struct pinned_mem_node_param {
	__u64 size;
	__u64 uaddr;
	__u64 handle;
	__u32 id;
};

struct pinned_mem_host_reg_param {
	__u64 size;
	__u64 uaddr;
	__u32 card_id;
	__u32 flags;
};

struct pinned_mem_host_unreg_param {
	__u64 uaddr;
	__u32 card_id;
};

struct pinned_mem_get_flags_param {
	__u64 uaddr;
	__u32 card_id;
	__u32 flags;
};

struct pinned_mem_get_device_pointer_param {
	__u64 uaddr;
	__u64 iova;/*outbound iova address*/
	__u32 card_id;
	__u32 flags;
};

struct pinned_mem_flag_param {
	__u64 size;
	__u64 uaddr;
	__u64 handle;
	__u32 card_id;
	__u32 flags;
};

enum powercap_ops {
	READ_POWERCAP = 0,
	WRITE_POWERCAP,
};

enum powercap_mode {
	TEMPORARY = 0,
	PERMANENT = 1,
	DISABLE_PERMANENT = 2,
};

struct cndev_powercapping_s {
	struct cndev_head head;
	__u32 ops_type;
	__u32 cap_value;

	__u32 mode;

	/* card support high precision power cap */
	__u16 high_precision_support;
	/* decimal power cap */
	__u16 dec_cap_value;
};

enum cndev_ipufreq_mode {
	IPUDFS_MODE_STATIC,
	/* default */
	IPUDFS_MODE_DYNAMIC,
};
struct cndev_ipufreq_set {
	struct cndev_head head;
	/* MHz */
	__u32 ipu_freq;
	__u32 ctrl_mode;
};

struct cndev_retire_page {
	struct cndev_head head;
	__u32 cause;
	__u32 page_count;
	void *page_addr;
};

struct cndev_retire_status {
	struct cndev_head head;
	__u32 is_pending;
	__u32 is_failure;
};

struct cndev_retire_remapped_rows {
	struct cndev_head head;
	__u32 corr_rows;
	__u32 unc_rows;
	__u32 pending_rows;
	__u32 fail_rows;
};

struct cndev_retire_op {
	struct cndev_head head;
	__u32 op;
	__u32 retire_switch;
};

struct cndev_host_ctrl {
	struct cndev_head head;

	__u32 op;
};

enum ioctl_attr {
	CNDEV_CARDINFO = 0,
	CNDEV_POWERINFO,
	CNDEV_MEMINFO,
	CNDEV_PROCINFO,
	CNDEV_HEALTHSTATE,
	CNDEV_ECCINFO,
	CNDEV_VMINFO,
	CNDEV_IPUUTIL,
	CNDEV_CODECUTIL,
	CNDEV_IPUFREQ,
	CNDEV_CURBUSINFO,
	CNDEV_PCIE_THROUGHPUT,
	CNDEV_POWERCAPPING,
	CNDEV_IPUFREQ_SET,
	CNDEV_NCS_VERSION,
	CNDEV_NCS_STATE,
	CNDEV_NCS_SPEED,
	CNDEV_NCS_CAPABILITY,
	CNDEV_NCS_COUNTER,
	CNDEV_NCS_REMOTE_INFO,
	CNDEV_NCS_RESET_COUNTER,
	CNDEV_CHASSIS_INFO,
	CNDEV_QOS_RESET,
	CNDEV_QOS_POLICY,
	CNDEV_QOS_DESCRIPTION,
	CNDEV_QOS_WEIGHT,
	CNDEV_QOS_GROUP_WEIGHT,
	CNDEV_ACPUUTIL,
	CNDEV_SET_ACPUUTIL_TIMER,
	CNDEV_GET_RETIRE_PAGES,
	CNDEV_GET_RETIRE_STATUS,
	CNDEV_GET_REMAPPED_ROWS,
	CNDEV_RETIRE_SWITCH,
	CNDEV_NCS_CONFIG,
	CNDEV_MLULINK_SWITCH_CTRL,
	CNDEV_IPUFREQ_CTRL,
	CNDEV_NCS_INFO,
	CNDEV_CARD_INFO_EXT,
	CNDEV_PROCESS_IPUUTIL,
	CNDEV_PROCESS_CODECUTIL,
	CNDEV_GET_FEATURE,
	CNDEV_SET_FEATURE,
	CNDEV_GET_MIM_VMLU_PROFILE,
	CNDEV_GET_MIM_POSSIBLE_PLACE,
	CNDEV_GET_MIM_VMLU_CAPACITY,
	CNDEV_GET_MIM_DEVICE_INFO,
	CNDEV_GET_CARD_DESC,
	CNDEV_GET_CNTR,
	MAX_IOCTL,
};

struct cndev_ioctl_attr {
	struct cndev_head head;

	__u32 attr_num;
	void *ioctl_attr;
};

struct cndev_qos_info {
	struct cndev_head head;

	/* QoS Policy, range 0~9,
	 * 0: reset to default,
	 * 1: Level 1,
	 * 2: Level 2
	 * ...
	 * 9: Level 9
	 */
	__u32 qos_policy;

	/* QoS Weight Base value */
	__u32 qos_base;
	/* QoS Weight Up value */
	__u32 qos_up;

	__u32 group_id;
};

union qos_value_s {
	/* QoS weight of master */
	__u8 qos_weight;
	/* only for ce3226*/
	__u16 qos_bandwidth;
};

struct cndev_qos_desc {

	/* QoS value of master */
	union qos_value_s qos_value;

	/* QoS group index */
	__u16 qos_group;

	/* QoS master name */
	char qos_name[QOS_NAME_LEN];
};

struct cndev_qos_detail {
	struct cndev_head head;

	__u16 qos_desc_num;
	struct cndev_qos_desc *desc;
};

struct cndev_qos_param {
	struct cndev_head head;

	/* QoS value of master */
	union qos_value_s qos_value;

	/* QoS group index */
	__u16 qos_group;

	/* QoS master index */
	__u16 master_index;
};

struct cndev_qos_group_param {
	struct cndev_head head;

	/* QoS value */
	union qos_value_s qos_value;

	/* QoS group index */
	__u16 qos_group;
};

struct cndev_process_ipuutil {
	__u64 tgid;
	__u64 util;
};

struct cndev_process_ipuutil_info {
	struct cndev_head head;
	__u32 total_util;
	__u32 process_num;
	void *ipu_util;
};

struct cndev_process_codecutil {
	__u64 tgid;
	__u32 jpu_util;
	__u32 vpu_dec_util;
	__u32 vpu_enc_util;
	__u32 reserve;
};

struct cndev_process_codecutil_info {
	struct cndev_head head;
	__u32 process_num;
	struct cndev_process_codecutil *codec_util;
};

enum xid_select {
	XID_SELECT_XID = 0,
	XID_SELECT_XIDS_STATUS = 1,
	XID_SELECT_XIDS_SWITCH = 2,
};

enum xid_ctrl {
	XID_CTRL_CLEAR = 0,
	XID_CTRL_ENABLE = 1,
	XID_CTRL_DISABLE = 2,
};

enum xid_type {
	XID_NO_ERR = 0,
	/* general user application faults */
	XID_SW_NOTIFY_ERR,
	/* internal micro-controller error */
	XID_MCU_ERR,
	/* DDR or HBM ECC error */
	XID_ECC_ERR,
	/* commu or ipcm error */
	XID_RPC_ERR,
	/* mem/resource access error */
	XID_ILLEGAL_ACCESS_ERR,
	/* CRC error */
	XID_CRC_ERR,
	/* mlulink error */
	XID_MLULINK_ERR,
	/* hbm & ddr error */
	XID_HBM_ERR,
	/* over-tempertature */
	XID_OVER_TEMP_ERR,
	/* previously halt */
	XID_PREV_HALT_ERR,

	XID_MAX_ERR,
};

struct cndev_feature_set_xid {
	/* xid ctrl code, 0:clear, 1:enable 2:disable */
	__u32 ctrl;
	/* scope: indicate the data section, 0:xid 1:all */
	__u32 select;

	__u64 xid;
};

struct cndev_feature_get_xid {
	__u32 reserved;
	/* xid select code, indicate the data section, 0:cn_xid, 1:cn_xids 2:status */
	__u32 select;

	union {
		/* lastest xid */
		struct {
			__u64 xid;
		} cn_xid;

		struct {
			__u32 xid_num;
			void *xids;
		} cn_xids;
	} data;
};

enum cndev_computing_power_type {
	CNDEV_PEAK_INT4_TENSOR_PER_CYCLE_PER_CORE,
	CNDEV_PEAK_INT8_TENSOR_PER_CYCLE_PER_CORE,
	CNDEV_PEAK_INT16_TENSOR_PER_CYCLE_PER_CORE,
	CNDEV_PEAK_FP16_TENSOR_PER_CYCLE_PER_CORE,
	CNDEV_PEAK_BF16_TENSOR_PER_CYCLE_PER_CORE,
	CNDEV_PEAK_FP32_TENSOR_PER_CYCLE_PER_CORE,

	CNDEV_PEAK_FP16_VECTOR_PER_CYCLE_PER_CORE_SIMD,
	CNDEV_PEAK_BF16_VECTOR_PER_CYCLE_PER_CORE_SIMD,
	CNDEV_PEAK_FP32_VECTOR_PER_CYCLE_PER_CORE_SIMD,
	CNDEV_PEAK_INT8_VECTOR_PER_CYCLE_PER_CORE_SIMD,
	CNDEV_PEAK_INT16_VECTOR_PER_CYCLE_PER_CORE_SIMD,
	CNDEV_MAX_COMPUTING_POWER_TYPE
};

struct cndev_feature_get_computing_power {
	__u64 num;
	void *buffer;
};

enum exclusive_mode_ops {
	CNDEV_GET_EXCLUSIVE_MODE = 0,
	CNDEV_SET_EXCLUSIVE_MODE = 1,
};

struct cndev_feature_exclusive_mode {

	__u32 mode;
};

struct cndev_feature_ile_ctrl {

	/* input, 0:disable ile, 1:enable ile */
	__u32 op;
};

enum {
	CN_FEAT_RESERVE = 0x00,
	CN_FEAT_XID = 0x01,
	/*computing power*/
	CN_FEAT_CMP_PW = 0x02,
	/*exclusive mode*/
	CN_FEAT_EXCLUSIVE_MOD = 0x03,
	/*SRIOV mode*/
	CN_FEAT_SRIOV_MOD = 0x04,
	/*VMLU op*/
	CN_FEAT_MIM_VMLU = 0x05,
	/*ile ctrl*/
	CN_FEAT_INLINE_ECC_CTRL = 0x06,
	/*SMLU op*/
	CN_FEAT_SMLU = 0x07,

	CN_FEAT_MAX,
};

struct cndev_mim_vmlu_placement {
	int start;
	int size;
};

enum cndev_mim_version {
	/* mim init VERSION */
	CNDEV_MIM_VERSION_0 = 0,
	/* instance info add device_name*/
	CNDEV_MIM_VERSION_1 = 1,
};

struct cndev_mim_head {
	/* mim ver: enum cndev_mim_version */
	__u32 version;

	/* size */
	__u32 size;
};

enum sriov_mode_ops {
	CNDEV_GET_SRIOV_MODE = 0,
	CNDEV_SET_SRIOV_MODE = 1,
};

struct cndev_feature_sriov_mode {

	/* mim head */
	struct cndev_mim_head head;

	/* indicate enum sriov_mode_ops */
	__u32 ops;

	/* SRIOV mode */
	__s32 mode;
};

enum mim_vmlu_ops {
	CNDEV_CREATE_VMLU = 0,
	CNDEV_CREATE_VMLU_WITH_PLACE = 1,
	CNDEV_DESTROY_VMLU = 2,
};

struct cndev_feature_mim_vmlu {

	/* mim head */
	struct cndev_mim_head head;

	/* ops, 0:create only, 1:create with palce, 2:destroy */
	__u32 ops;

	union {
		/* create instance */
		struct {
			__u32 profile_id;
			__u32 instance_id;
		} create_mi;

		/*create instance with placement*/
		struct {
			__u32 profile_id;
			struct cndev_mim_vmlu_placement placement;
			__u32 instance_id;
		} create_mi_with_place;

		/* destroy instance id */
		struct {
			__u32 instance_id;
		} destroy_mi;
	};
};

//////////////////////////////////////////////////////
// cndevGetVMLUProfileInfo
#define CNDEV_MAX_PROFILE_NAME_SIZE 64

enum cndev_mlu_instance_profile {
	CNDEV_MLU_INSTANCE_PROFILE_1_SLICE,
	CNDEV_MLU_INSTANCE_PROFILE_1_SLICE_IPU_2_SLICE_VPU,
	CNDEV_MLU_INSTANCE_PROFILE_2_SLICE,
	CNDEV_MLU_INSTANCE_PROFILE_2_SLICE_IPU_1_SLICE_MEM,
	CNDEV_MLU_INSTANCE_PROFILE_3_SLICE,
	CNDEV_MLU_INSTANCE_PROFILE_4_SLICE,
	CNDEV_MLU_INSTANCE_PROFILE_5_SLICE,
	CNDEV_MLU_INSTANCE_PROFILE_6_SLICE,
	CNDEV_MLU_INSTANCE_PROFILE_UNKONW = -1,
};

struct cndev_mim_profile_info {
	struct cndev_head head;

	__u32 profile;

	__u32 version;
	__u32 profile_id;
	__u32 ipu_count;
	__u32 vpu_count;
	__u32 jpu_count;
	// __u32 HBMCount;
	__u32 gdma_count;
	__u64 mem_size;
	__u32 profile_name_size;
	char *name;
};

#define MONITOR_CNDEV_GET_MIM_VMLU_PROFILE_INFO     \
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_GET_MIM_VMLU_PROFILE, struct cndev_mim_profile_info)

//////////////////////////////////////////////////////
//cndevGetVMLUPossiblePlacements
struct cndev_mim_possible_place_info {
	struct cndev_head head;

	__u32 profile_id;

	/*place desc*/
	__u32 count;

	/* indecate struct cndev_mim_vmlu_placement */
	struct cndev_mim_vmlu_placement *place_info;
};
#define MONITOR_CNDEV_GET_MIM_VMLU_POSSIBLE_PLACE       \
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_GET_MIM_POSSIBLE_PLACE, struct cndev_mim_possible_place_info)

//////////////////////////////////////////////////////
// cndevGetVMLURemainingCapacity
struct cndev_mim_vmlu_capacity_info {
	struct cndev_head head;

	__u32 profile_id;

	/*profile capacity*/
	__u32 count;
};
#define MONITOR_CNDEV_GET_MIM_VMLU_CAPACITY     \
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_GET_MIM_VMLU_CAPACITY, struct cndev_mim_vmlu_capacity_info)

//////////////////////////////////////////////////////
// cndevGetMaxMimDeviceCount
struct cndev_mim_device_info {
	struct cndev_head head;

	__u32 profile_id;

	__u32 max_dev_count;
};
#define MONITOR_CNDEV_GET_MIM_DEVICE_INFO       \
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_GET_MIM_DEVICE_INFO, struct cndev_mim_device_info)

//////////////////////////////////////////////////////
// cndevGetVMLUInfo

#define CNDEV_MAX_INSTANCE_COUNT 64
#define CNDEV_DEVICE_NAME_LEN    64

struct cndev_instance_info {
	__u32 profile_id;
	__u32 instance_id;
	__u8 uuid[DRIVER_PMU_UUID_SIZE];
	__u32 bus;
	__u32 device;
	__u32 function;
	struct cndev_mim_vmlu_placement placement;
	int domain;
	char ipcm_device_name[DRIVER_IPCM_DEV_NAME_SIZE];
	char device_name[CNDEV_DEVICE_NAME_LEN];
};

enum mi_select {
	MI_SELECT_ALL = 0,
	MI_SELECT_INSTANCE_ID = 1,
};

struct cndev_feature_mim_vmlu_info {
	struct cndev_mim_head head;

	/* input */
	__u32 select;
	/* select instance id */
	__u32 instance_id;

	__u32 instance_num;
	/* struct cndev_instance_info */
	void *instance_info;
};

struct cndev_feature {
	struct cndev_head head;

	/* Feature Identifier */
	__u32 FID;

	/* Feature Supported */
	__u32 SUP;

	/*Data Pointer*/
	void *DPTR;
};

struct cndev_mi_card {
	struct cndev_head head;

	/* total vf mlu card number */
	__u64 vf_count;

	/* vf mlu card mask */
	__u64 virt_card_mask;

	/* mi on docker mask */
	__u64 mi_on_docker_mask;
};

enum cndev_card_type {
	CNDEV_PF = 0,
	CNDEV_VF = 1,
};

struct cndev_card_desc {
	/* indicate device invalid or not*/
	__u8 valid;
	/* same as struct cndev_health_state host state*/
	__u8 host_state;
	/* device core type */
	__s32 core_type;
	/* dev index in drv */
	__s32 idx;
	/* dev core type name */
	char core_name[CNDEV_CORE_NAME_LEN];
};

struct cndev_cardnum_ext {
	struct cndev_head head;

	/* total phy mlu card number */
	__u32 phy_card_count;

	/* in vf */
	__u32 vf_card_count;

	/* phy dev desc, indicate struct cndev_cardnum_ext */
	__u32 phy_card_num;
	void *phy_card_desc;
};

struct cndev_cntr_info {
	struct cndev_head head;

	__u64 parity_err_cntr;
};

enum cndev_mim_mode_op {
	CNDEV_MIM_MODE_GET = 1,
	CNDEV_MIM_MODE_SET = 2,
};

enum cndev_mim_mode_state {
	CNDEV_MIM_MODE_DISABLE = 0,
	CNDEV_MIM_MODE_ENABLE  = 1,
};

struct cndev_mim_mode_switch {
	struct cndev_head head;

	/* ref enum cndev_mim_mode_op */
	__u32 mim_op;

	/* enum cndev_mim_mode_state */
	__s32 mim_state;

	__u32 mim_sup;
};

enum cndev_device_reset_state {
	CNDEV_DEVICE_RESET = 0,
	CNDEV_DEVICE_BUSY = 1,
	CNDEV_DEVICE_VF = 2,
	CNDEV_DEVICE_MIM = 3,
	CNDEV_DEVICE_SMLU = 4,
};

struct cndev_device_reset {
	struct cndev_head head;

	/* enum cndev_device_reset_state */
	__u32 reset_state;
};

struct cndev_device_state {
	struct cndev_head head;

	/* enum cn_boot_state */
	__u32 cur_state;
};

/*
 * ==================
 * smlu_cap
 * ==================
 */
//cn_cndev_smlu_mode_switch()
enum cndev_smlu_mode_op {
	CNDEV_SMLU_MODE_GET = 1,
	CNDEV_SMLU_MODE_SET = 2,
};

enum cndev_smlu_mode_state {
	CNDEV_SMLU_MODE_DISABLE = 0,
	CNDEV_SMLU_MODE_ENABLE  = 1,
};

struct cndev_smlu_mode_switch {
	struct cndev_head head;

	/* enum cndev_smlu_mode_op */
	__u32 smlu_mode_op;

	/* enum cndev_smlu_mode_state */
	__s32 smlu_state;

	__u32 smlu_sup;
};

//cndev_card_set_smlu_common()
enum cndev_smlu_version {
	/* SMLUv2 */
	CNDEV_SMLU_VERSION_2 = 2,
};

struct cndev_smlu_head {
	/* smlu ver: enum cndev_smlu_version */
	__u32 version;

	/* size */
	__u32 size;
};

enum smlu_ops {
	CNDEV_CREATE_SMLU_CGROUP = 0,
	CNDEV_DESTROY_SMLU_CGROUP = 1,
};

struct cndev_feature_smlu {

	/* smlu head */
	struct cndev_smlu_head head;

	/* enum smlu_ops */
	__u32 ops;

	union {
		/* quota data */
		struct {
			__u32 cgrp_id;/* cap node id, instance id */
			__u32 profile_id;/* wrapper quota data */
		} create_cgrp;

		struct {
			__u32 cgrp_id;
		} destroy_cgrp;
	};
};

//cndev_card_get_smlu_info_common()
/* MUST be same as enum smlu_cgroup_subsys_id */
enum cndev_smlu_cgroup_res {
	SMLU_MEM = 0,//mem_size in Byte
	SMLU_IPU,//ipu util percentage
	SMLU_VPU,//TODO
	SMLU_JPU,//TODO
	SMLU_GDMA,//TODO
	SMLU_RES_COUNT,
};

enum cndev_smlu_cgroup_item {
	SMLU_MAX = 0,
	SMLU_USAGE,
	SMLU_FACTOR,
	SMLU_ITEM_COUNT,
};

struct cndev_smlu_cgroup_info {
	__u32 profile_id;
	__u32 cgrp_id;/* instance_id */
	__u8 uuid[DRIVER_PMU_UUID_SIZE];
	__u32 bus;
	__u32 device;
	__u32 function;
	int domain;
	char device_name[CNDEV_DEVICE_NAME_LEN];
	__u64 cgroup_item[SMLU_RES_COUNT][SMLU_ITEM_COUNT];
};

enum smlu_select {
	SMLU_SELECT_ALL = 0,
	SMLU_SELECT_INSTANCE_ID = 1,
};

struct cndev_feature_smlu_info {
	struct cndev_smlu_head head;

	/* input */
	__u32 select;
	/* select instance id, in pf's view */
	__u32 instance_id;

	__u32 instance_num;
	/* struct cndev_smlu_cgroup_info */
	void *instance_info;
};

//cn_cndev_get_smlu_profile_id
struct cndev_smlu_profile_id {
	struct cndev_head head;

	__u32 profile_count;
	__u32 *profile_id;
};

//cn_cndev_get_smlu_profile_info
//cn_cndev_new_smlu_profile
struct cndev_smlu_profile_info {
	struct cndev_head head;
	__u32 profile; /* input profile_id */
	__u32 version;

	__u32 profile_id; /* output profile_id */
	__u32 total_capacity;
	__u32 remain_capacity;
	__u64 profile_res[SMLU_RES_COUNT][SMLU_ITEM_COUNT];
	__u32 profile_name_size;
	char *profile_name;
};

/* monitor cndev */

enum {
	_CNDEV_CARDNUM = 0,
	_CNDEV_CARDINFO = 1,
	_CNDEV_POWERINFO = 2,
	_CNDEV_MEMINFO = 3,
	_CNDEV_PROCINFO = 4,
	_CNDEV_HEALTHSTATE = 5,
	_CNDEV_ECCINFO = 6,
	_CNDEV_VMINFO = 7,
	_CNDEV_IPUUTIL = 8,
	_CNDEV_CODECUTIL = 9,
	_CNDEV_IPUFREQ = 10,
	_CNDEV_CURBUSINFO = 11,
	_CNDEV_PCIE_THROUGHPUT = 12,
	_M_PINNED_MEM_ALLOC = 13,
	_M_PINNED_MEM_FREE = 14,
	_CNDEV_POWERCAPPING = 15,
	_CNDEV_IPUFREQ_SET = 16,
	_M_PINNED_MEM_GET_HANDLE = 17,
	_M_PINNED_MEM_CLOSE_HANDLE = 18,
	_M_PINNED_MEM_OPEN_HANDLE = 19,
	_M_PINNED_MEM_GET_MEM_RANGE = 20,
	_CNDEV_GET_IOCTL_ATTR = 21,
	_CNDEV_NCS_VERSION = 22,
	_CNDEV_NCS_STATE = 23,
	_CNDEV_NCS_SPEED = 24,
	_CNDEV_NCS_CAPABILITY = 25,
	_CNDEV_NCS_COUNTER = 26,
	_CNDEV_NCS_RESET_COUNTER = 27,
	_CNDEV_NCS_REMOTE_INFO = 28,
	/*29 reserve*/
	_M_PINNED_MEM_LAR4_ALLOC = 30,
	_M_PINNED_MEM_LAR4_GET_HANDLE = 31,
	_M_PINNED_MEM_LAR4_CLOSE_HANDLE = 32,
	_M_PINNED_MEM_LAR4_OPEN_HANDLE = 33,
	_M_PINNED_MEM_LAR4_GET_MEM_RANGE = 34,
	_CNDEV_CHASSISINFO = 35,
	_CNDEV_QOS_RESET = 36,
	_CNDEV_QOS_INFO = 37,
	_CNDEV_QOS_DESC = 38,
	_CNDEV_SET_QOS = 39,
	_CNDEV_SET_QOS_GROUP = 40,
	_CNDEV_ACPUUTIL = 41,
	_CNDEV_ACPUUTIL_TIMER = 42,
	_CNDEV_GET_RETIRE_PAGES = 43,
	_CNDEV_GET_RETIRE_STATUS = 44,
	_CNDEV_GET_REMAPPED_ROWS = 45,
	_CNDEV_RETIRE_SWITCH = 46,
	_CNDEV_NCS_CONFIG = 47,
	_CNDEV_MLULINK_SWITCH_CTRL = 48,
	_CNDEV_IPUFREQ_CTRL = 49,
	_CNDEV_NCS_INFO = 50,
	_M_PINNED_MEM_NODE_ALLOC = 51,
	_CNDEV_CARDINFO_EXT = 52,
	_CNDEV_HOST_CTRL = 53,
	_CNDEV_PROCESS_IPUUTIL = 54,
	_CNDEV_PROCESS_CODECUTIL = 55,
	_M_PINNED_MEM_FLAG_NODE_ALLOC = 56,
	_M_PINNED_MEM_HOST_GET_POINTER = 57,
	_M_PINNED_MEM_HOST_REGISTER = 58,
	_M_PINNED_MEM_HOST_UNREGISTER = 59,
	_M_PINNED_MEM_GET_FLAGS = 60,
	_CNDEV_GET_FEATURE = 61,
	_CNDEV_SET_FEATURE = 62,
	_CNDEV_GET_MIM_VMLU_PROFILE = 63,
	_CNDEV_GET_MIM_POSSIBLE_PLACE = 64,
	_CNDEV_GET_MIM_VMLU_CAPACITY = 65,
	_CNDEV_GET_MIM_DEVICE_INFO = 66,
	_CNDEV_MI_CARD = 67,
	_CNDEV_CARDNUM_EXT = 68,
	_CNDEV_GET_COUNTER = 69,
	_CNDEV_CHASSIS_POWER_INFO = 70,
	_CNDEV_MIM_MODE_SWITCH = 71,
	_CNDEV_SMLU_MODE_SWITCH = 72,
	_CNDEV_GET_SMLU_PROFILE_ID = 73,
	_CNDEV_GET_SMLU_PROFILE_INFO = 74,
	_CNDEV_NEW_SMLU_PROFILE = 75,
	_CNDEV_DELETE_SMLU_PROFILE = 76,
	_CNDEV_DEVICE_RESET = 77,
	_CNDEV_DEVICE_STATE = 78,
	_CNDEV_MAX,
};


#define GET_COMPAT_PARAM_MON(d, type, cond, member) \
({	\
	__u64 val;	\
	void *__pdata = d;	\
	WARN_ON(!__pdata);	\
	if ((sizeof(struct type##_compat_param)) > cond) {\
		val = ((struct type##_param *)__pdata)->member;\
	} else { \
		val = ((struct type##_compat_param *)__pdata)->member;\
	} \
	\
	val;\
})

#define SET_COMPAT_PARAM_MON(d, type, cond, member, value) \
({	\
	void *__pdata = d;	\
	WARN_ON(!__pdata);	\
	if ((sizeof(struct type##_compat_param)) > cond) {\
		((struct type##_param *)__pdata)->member = value;\
	} else { \
		((struct type##_compat_param *)__pdata)->member = value;\
	} \
})


#define MONITOR_CNDEV_MI_CARD		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_MI_CARD, struct cndev_mi_card)
#define MONITOR_CNDEV_CARDNUM_EXT		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_CARDNUM_EXT, struct cndev_cardnum_ext)
#define MONITOR_CNDEV_CARDNUM		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_CARDNUM, unsigned long)
#define MONITOR_CNDEV_CARDINFO		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_CARDINFO, struct cndev_card_info)
#define MONITOR_CNDEV_POWERINFO		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_POWERINFO, struct cndev_power_info)
#define MONITOR_CNDEV_MEMINFO		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_MEMINFO, struct cndev_memory_info)
#define MONITOR_CNDEV_PROCINFO		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_PROCINFO, struct cndev_proc_info)
#define MONITOR_CNDEV_HEALTHSTATE		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_HEALTHSTATE, struct cndev_health_state)
#define MONITOR_CNDEV_ECCINFO		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_ECCINFO, struct cndev_ecc_info)
#define MONITOR_CNDEV_VMINFO		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_VMINFO, struct cndev_vm_info)
#define MONITOR_CNDEV_IPUUTIL		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_IPUUTIL, struct cndev_ipuutil_info)
#define MONITOR_CNDEV_CODECUTIL		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_CODECUTIL, struct cndev_codecutil_info)
#define MONITOR_CNDEV_IPUFREQ		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_IPUFREQ, struct cndev_ipufreq_info)
#define MONITOR_CNDEV_CURBUSINFO		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_CURBUSINFO, struct cndev_curbuslnk_info)
#define MONITOR_CNDEV_PCIE_THROUGHPUT		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_PCIE_THROUGHPUT, struct cndev_pcie_throughput)
#define M_PINNED_MEM_ALLOC				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_ALLOC, struct pinned_mem_param)
#define M_PINNED_MEM_FREE           \
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_FREE, unsigned long)
#define MONITOR_CNDEV_POWERCAPPING		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_POWERCAPPING, struct cndev_powercapping_s)
#define MONITOR_CNDEV_IPUFREQ_SET		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_IPUFREQ_SET, struct cndev_ipufreq_set)
#define M_PINNED_MEM_GET_HANDLE				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_GET_HANDLE, struct pinned_mem_param)
#define M_PINNED_MEM_CLOSE_HANDLE				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_CLOSE_HANDLE, struct pinned_mem_param)
#define M_PINNED_MEM_OPEN_HANDLE				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_OPEN_HANDLE, struct pinned_mem_param)
#define M_PINNED_MEM_GET_MEM_RANGE				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_GET_MEM_RANGE, struct pinned_mem_param)
#define MONITOR_CNDEV_GET_IOCTL_ATTR				\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_GET_IOCTL_ATTR, struct cndev_ioctl_attr)
#define M_PINNED_MEM_LAR4_ALLOC				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_LAR4_ALLOC, struct pinned_mem_compat_param)
#define M_PINNED_MEM_LAR4_GET_HANDLE				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_LAR4_GET_HANDLE, struct pinned_mem_compat_param)
#define M_PINNED_MEM_LAR4_CLOSE_HANDLE				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_LAR4_CLOSE_HANDLE, struct pinned_mem_compat_param)
#define M_PINNED_MEM_LAR4_OPEN_HANDLE				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_LAR4_OPEN_HANDLE, struct pinned_mem_compat_param)
#define M_PINNED_MEM_LAR4_GET_MEM_RANGE				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_LAR4_GET_MEM_RANGE, struct pinned_mem_compat_param)
#define MONITOR_CNDEV_CHASSISINFO		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_CHASSISINFO, struct cndev_chassis_info)
#define MONITOR_CNDEV_ACPUUTIL		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_ACPUUTIL, struct cndev_acpuutil_info)
#define MONITOR_CNDEV_ACPUUTIL_TIMER		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_ACPUUTIL_TIMER, struct cndev_acpuutil_timer)

#define MONITOR_CNDEV_GET_RETIRE_PAGES		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_GET_RETIRE_PAGES, struct cndev_retire_page)
#define MONITOR_CNDEV_GET_RETIRE_STATUS		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_GET_RETIRE_STATUS, struct cndev_retire_status)
#define MONITOR_CNDEV_GET_REMAPPED_ROWS		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_GET_REMAPPED_ROWS, struct cndev_retire_remapped_rows)
#define MONITOR_CNDEV_RETIRE_SWITCH		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_RETIRE_SWITCH, struct cndev_retire_op)
#define MONITOR_CNDEV_PROCESS_CODECUTIL		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_PROCESS_CODECUTIL, struct cndev_process_codecutil_info)

/* adapt to alloc host pinned memory with numa node */
#define M_PINNED_MEM_NODE_ALLOC				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_NODE_ALLOC, struct pinned_mem_node_param)
#define MONITOR_CNDEV_CARDINFO_EXT		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_CARDINFO_EXT, struct cndev_card_info_ext)
#define MONITOR_CNDEV_HOST_CTRL		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_HOST_CTRL, struct cndev_host_ctrl)
#define MONITOR_CNDEV_PROCESS_IPUUTIL		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_PROCESS_IPUUTIL, struct cndev_process_ipuutil_info)
#define M_PINNED_MEM_FLAG_NODE_ALLOC				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_FLAG_NODE_ALLOC, struct pinned_mem_flag_param)
#define M_PINNED_MEM_HOST_GET_POINTER				\
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_HOST_GET_POINTER, struct pinned_mem_get_device_pointer_param)
#define M_PINNED_MEM_HOST_REGISTER                           \
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_HOST_REGISTER, struct pinned_mem_host_reg_param)
#define M_PINNED_MEM_HOST_UNREGISTER                           \
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_HOST_UNREGISTER, struct pinned_mem_host_unreg_param)
#define M_PINNED_MEM_GET_FLAGS                          \
	_IOW(CAMBR_MONITOR_MAGIC, _M_PINNED_MEM_GET_FLAGS, struct pinned_mem_get_flags_param)


#define MONITOR_CNDEV_SET_FEATURE		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_SET_FEATURE, struct cndev_feature)
#define MONITOR_CNDEV_GET_FEATURE		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_GET_FEATURE, struct cndev_feature)

#define MONITOR_CNDEV_GET_COUNTER		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_GET_COUNTER, struct cndev_cntr_info)
#define MONITOR_CNDEV_CHASSIS_POWER_INFO		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_CHASSIS_POWER_INFO, struct cndev_chassis_power_info)
#define MONITOR_CNDEV_MIM_MODE_SWITCH		\
	_IOWR(CAMBR_MONITOR_MAGIC, _CNDEV_MIM_MODE_SWITCH, struct cndev_mim_mode_switch)

#define MONITOR_CNDEV_DEVICE_RESET		\
	_IOWR(CAMBR_MONITOR_MAGIC, _CNDEV_DEVICE_RESET, struct cndev_device_reset)
#define MONITOR_CNDEV_DEVICE_STATE		\
	_IOWR(CAMBR_MONITOR_MAGIC, _CNDEV_DEVICE_STATE, struct cndev_device_state)

/*
 * ==================
 * smlu_cap
 * ==================
 */
#define MONITOR_CNDEV_SMLU_MODE_SWITCH		\
	_IOWR(CAMBR_MONITOR_MAGIC, _CNDEV_SMLU_MODE_SWITCH, struct cndev_smlu_mode_switch)
#define MONITOR_CNDEV_GET_SMLU_PROFILE_ID		\
	_IOWR(CAMBR_MONITOR_MAGIC, _CNDEV_GET_SMLU_PROFILE_ID, struct cndev_smlu_profile_id)
#define MONITOR_CNDEV_GET_SMLU_PROFILE_INFO		\
	_IOWR(CAMBR_MONITOR_MAGIC, _CNDEV_GET_SMLU_PROFILE_INFO, struct cndev_smlu_profile_info)
#define MONITOR_CNDEV_NEW_SMLU_PROFILE		\
	_IOWR(CAMBR_MONITOR_MAGIC, _CNDEV_NEW_SMLU_PROFILE, struct cndev_smlu_profile_info)
#define MONITOR_CNDEV_DELETE_SMLU_PROFILE		\
	_IOWR(CAMBR_MONITOR_MAGIC, _CNDEV_DELETE_SMLU_PROFILE, struct cndev_smlu_profile_info)

/* CCLink */

enum cclink_speed_format {
	CCLINK_FMT_NRZ = 0,
	CCLINK_FMT_PM4 = 1,
	CCLINK_FMT_NUM
};

enum cclink_capability {
	CCLINK_CAP_P2P_TSF = 0,
	CCLINK_CAP_ILKN_FEC = 1,
	CCLINK_CAP_NUM
};

enum cclink_counter {
	CCLINK_CNTR_RD_BYTE = 0,
	CCLINK_CNTR_RD_PKG = 1,
	CCLINK_CNTR_WR_BYTE = 2,
	CCLINK_CNTR_WR_PKG = 3,
	CCLINK_ERR_RPY = 4,
	CCLINK_ERR_FTL = 5,
	CCLINK_ERR_ECC_DBE = 6,
	CCLINK_ERR_CRC24 = 7,
	CCLINK_ERR_CRC32 = 8,
	CCLINK_ERR_CORR = 9,
	CCLINK_ERR_UNCORR = 10,
	CCLINK_ERR_NUM_V1,
	/* start at MLU500s */
	CCLINK_ERR_RD_ERR_PKG = 11,
	CCLINK_ERR_WR_ERR_PKG = 12,
	CCLINK_ERR_SMMU = 13,
	CCLINK_CNTR_CNP_PKGS = 14,
	CCLINK_CNTR_PFC_PKGS = 15,
	CCLINK_ERR_NUM
};

enum cclink_connect_type {
	CONNECT_DRIECT	= 0,
	CONNECT_SET		= 1,
	CONNECT_TYPE_NUM
};

#define MONITOR_CNDEV_NCS_VERSION		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_NCS_VERSION, struct cndev_NCS_version)
#define MONITOR_CNDEV_NCS_STATE		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_NCS_STATE, struct cndev_NCS_state_info)
#define MONITOR_CNDEV_NCS_SPEED		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_NCS_SPEED, struct cndev_NCS_speed_info)
#define MONITOR_CNDEV_NCS_CAPABILITY		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_NCS_CAPABILITY, struct cndev_NCS_capability)
#define MONITOR_CNDEV_NCS_COUNTER		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_NCS_COUNTER, struct cndev_NCS_counter)
#define MONITOR_CNDEV_NCS_RESET_COUNTER		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_NCS_RESET_COUNTER, struct cndev_NCS_reset_counter)
#define MONITOR_CNDEV_NCS_REMOTE_INFO		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_NCS_REMOTE_INFO, struct cndev_NCS_remote_info)
#define MONITOR_CNDEV_NCS_CONFIG		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_NCS_CONFIG, struct cndev_NCS_config)
#define MONITOR_CNDEV_MLULINK_SWITCH_CTRL		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_MLULINK_SWITCH_CTRL, struct cndev_mlulink_switch_ctrl)
#define MONITOR_CNDEV_IPUFREQ_CTRL		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_IPUFREQ_CTRL, struct cndev_ipufreq_ctrl)
#define MONITOR_CNDEV_NCS_INFO		\
	_IOR(CAMBR_MONITOR_MAGIC, _CNDEV_NCS_INFO, struct cndev_ncs_info)

struct cndev_NCS_version {
	struct cndev_head head;

	__u32 link;
	__u8 major_version;
	__u8 minor_version;
	__u8 build_version;
};

struct cndev_NCS_speed_info {
	struct cndev_head head;

	__u32 link;
	__s32 speed;
	__s32 speed_fmt;
};

enum cndev_mlulink_cable_state {
	CNDEV_MLULINK_UNCONNECTED = 0,
	CNDEV_MLULINK_CONNECTED = 1,
	CNDEV_MLULINK_UNIMPLEMENTED = 2,
};

struct cndev_NCS_state_info {
	struct cndev_head head;

	__u32 link;
	__s32 state;
	__s32 serdes_state;

	/* ref: enum cndev_mlulink_cable_state */
	__s32 cable_state;
};

struct cndev_NCS_capability {
	struct cndev_head head;

	__u32 link;
	__u32 cap_p2p_tsf;
	__u32 cap_ilkn_fec;
};

struct NCS_counter_info_s {

	__u64 cntr_rd_byte;
	__u64 cntr_rd_pkg;
	__u64 cntr_wr_byte;
	__u64 cntr_wr_pkg;
	__u64 err_rpy;
	__u64 err_ftl;
	__u64 err_ecc_dbe;
	__u64 err_crc24;
	__u64 err_crc32;
	__u64 err_corr;
	__u64 err_uncorr;

	int ret;
	__u64 err_rd_err_pkg;
	__u64 err_wr_err_pkg;
	__u64 err_smmu;
	__u64 cntr_cnp_pkg;
	__u64 cntr_pfc_pkg;
};

struct cndev_NCS_counter {
	struct cndev_head head;

	__u32 link;
	struct NCS_counter_info_s info;
};

struct cndev_NCS_reset_counter {
	struct cndev_head head;

	__u32 link;
	enum cclink_counter cntr;
};

struct cndev_NCS_remote_info {
	struct cndev_head head;

	__u64 mc_sn;
	__u64 ba_sn;

	__u32 slot_id;
	__u32 port_id;

	__u8 dev_ip[ADDRESS_LEN];
	__u8 uuid[DRIVER_PMU_UUID_SIZE];

	__u32 dev_ip_version;
	__u32 is_ip_valid;

	enum cclink_connect_type type;
	__u32 link;

	__u64 ncs_uuid64;
};

enum NCS_PORT_WORK_MODE {
	NCS_PORT_WORK_MODE_NONE = 0,
	NCS_PORT_WORK_MODE_ILKN = 1 << 0,
	NCS_PORT_WORK_MODE_SWITCH = 1 << 1,
	NCS_PORT_WORK_MODE_PCIE = 1 << 2,
};

struct cndev_NCS_config {
	struct cndev_head head;

	__u8 ops_type;
	__s32 port_idx;
	__u32 support_mode_flags;
	__u32 current_mode_flags;
};

enum MLULNK_FIELD {
	MLULINK_FIELD_IP_VERSION = 0, /* 6:IPV6, 4:IPV4 */
	MLULINK_FIELD_VLAN_TPID,  /* big endian, 16 bit */
	MLULINK_FIELD_VLAN_CFI,   /* default 0: standard foramt, 1 bit */
	MLULINK_FIELD_VLAN_VID,   /* big endian, 12 bit, 1 ~ 4094 */
	MLULINK_FIELD_VLAN_EN,    /* enable vlan, 1 bit */

	MLULINK_FIELD_IP_TTL,     /* ONLY WORK WITH IPV4, BIT 7~0 */
	MLULINK_FIELD_FLOW_LABLE, /* ONLY WORK WITH IPV6, BIT 19~0  */
	MLULINK_FIELD_HOP_LIMIT,  /* ONLY WORK WITH IPV6, BIT 7~0 */

	MLULINK_FIELD_PFC_XON_ENABLE,    /* 0: Disable 1: Enable */
	MLULINK_FIELD_PFC_XOFF_ENABLE,    /* 0: Disable 1: Enable */
	MLULINK_FIELD_PFC_XON_PERIOD,    /* XON PAUSE TIME, BIT 15-0 */
	MLULINK_FIELD_PFC_XOFF_PERIOD,   /* XOFF PAUSE TIME, BIT 15-0 */
	MLULINK_FIELD_PFC_PERIOD, /* the retransim pause time, bit 23 ~ 0 */
	MLULINK_FIELD_PFC_EN,     /* BITMAP BIT[n] = 1, priority n fpc enable, n:0~7 */

	MLULINK_FIELD_QOS_TRUST,     /* 0: dot1p, 1 dscp */

	MLULINK_FIELD_VLAN_DOT1P,      /* map table bit 31~28: pri, bit 0~2: vlan */
	MLULINK_FIELD_DATA_DOT1P, /* map table bit 31~28: pri, bit 0~2: vlan */
	MLULINK_FIELD_CTRL_DOT1P, /* map table bit 31~28: pri, bit 0~2: vlan */
	MLULINK_FIELD_RESP_DOT1P, /* map table bit 31~28: pri, bit 0~2: vlan */

	MLULINK_FIELD_TCP_DSCP,      /* map table bit 31~28: pri, bit 0~5: dscp */
	MLULINK_FIELD_DATA_DSCP, /* map table bit 31~28: pri, bit 0~5: dscp */
	MLULINK_FIELD_CTRL_DSCP, /* map table bit 31~28: pri, bit 0~5: dscp */
	MLULINK_FIELD_RESP_DSCP, /* map table bit 31~28: pri, bit 0~5: dscp */

	MLULINK_FIELD_NUM,
};

struct cndev_mlulink_switch_ctrl {
	struct cndev_head head;

	__u8 ops_type;
	__s32 port_idx;
	__s32 field;
	__u32 value;
};

enum {
	CNDEV_IPU_FREQ_LOCK_STATUS = 0,
	CNDEV_IPU_FREQ_LOCK_CLEAR = 1,
};

struct cndev_ipufreq_ctrl {
	struct cndev_head head;

	__u8 ops_type;
	__u8 ipufreq_lock_status;
};

enum mlu_link_err {
	MLU_LINK_SUCCESS,
	MLU_LINK_ERROR_LINK_NOT_INITIAL,
	MLU_LINK_ERROR_INVALID_ARGUMENT,
	MLU_LINK_ERROR_NOT_SUPPORT,
	MLU_LINK_ERROR_PORT_NOT_ENABLE,
	MLU_LINK_ERROR_PORT_REPEAT_CONFIG,
	MLU_LINK_ERROR_LINK_NOT_SUPPORT,
	MLU_LINK_ERROR_MODE_INIT_FAILED,
	MLU_LINK_ERROR_DMA_INIT_FAILED,
	MLU_LINK_ERROR_JS_INIT_FAILED,
	MLU_LINK_ERROR_SMMU_INIT_FAILED,
	MLU_LINK_ERROR_LINK_INIT_FAILED,
	MLU_LINK_ERROR_PORT_NOT_SUPPORT,
	MLU_LINK_ERROR_NUM,
};

struct cndev_ncs_basic_info {

	__s32 ip_supported;
	__u8 dev_ip_version;
	__u8 dev_ip[ADDRESS_LEN];
};

struct cndev_ncs_info {
	struct cndev_head head;

	__s32 support_mlulink;
	__u64 ncs_uuid64;
	__u32 ncs_num;
	struct cndev_ncs_basic_info *ncs_info;
};

#define MONITOR_CNDEV_QOS_RESET		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_QOS_RESET, struct cndev_head)
#define MONITOR_CNDEV_QOS_INFO		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_QOS_INFO, struct cndev_qos_info)
#define MONITOR_CNDEV_QOS_DESC		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_QOS_DESC, struct cndev_qos_detail)
#define MONITOR_CNDEV_SET_QOS		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_SET_QOS, struct cndev_qos_param)
#define MONITOR_CNDEV_SET_QOS_GROUP		\
	_IOW(CAMBR_MONITOR_MAGIC, _CNDEV_SET_QOS_GROUP, struct cndev_qos_group_param)

enum checkpoint_cc_type {
	CHECKPOINT_CC_TYPE_L1C,
	CHECKPOINT_CC_TYPE_LLC,
	CHECKPOINT_CC_TYPE_ALL,
};

enum checkpoint_cc_action {
	CHECKPOINT_CC_ACTION_INVALID,
	CHECKPOINT_CC_ACTION_CLEAN_AND_INVALID,
};

enum checkpoint_memory_type {
	CHECKPOINT_MEMORY_TYPE_NORMAL,
	CHECKPOINT_MEMORY_TYPE_OR,
	CHECKPOINT_MEMORY_TYPE_IPC,
	CHECKPOINT_MEMORY_TYPE_HOST,
};

struct checkpoint_malloc_node {
	unsigned long addr;
	unsigned long size;
	unsigned long type;
};

struct checkpoint_cc_set {
	__s32 type; /* LLC or IPU/TNC L1C */
	__s32 action; /* Invalid or clean and invalid */
};

struct checkpoint_info_get {
	__u64 buffer_addr;
	__u64 buffer_size;
};

#define MONITOR_CHECKPOINT_CLEAN_CACHE		\
	_IOW(CAMBR_MONITOR_MAGIC, _MONITOR_CHECKPOINT_CLEAN_CACHE, struct checkpoint_cc_set)
#define MONITOR_CHECKPOINT_MEMORY_INFO_GET		\
	_IOWR(CAMBR_MONITOR_MAGIC, _MONITOR_CHECKPOINT_MEMORY_INFO_GET, struct checkpoint_info_get)

#endif /* __CAMBRICON_CNDRV_MONUSR_H__ */
