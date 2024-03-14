#ifndef __CAMBRICON_ATTR_RES_H__
#define __CAMBRICON_ATTR_RES_H__
#include "cndrv_attr.h"

struct attr_head {
	__u16 version;
};

struct cn_computing_cap {
	__u32 major;
	__u32 minor;
	__u32 sparse;
	__u32 fp16;
	__u32 int4;
	__u32 int8;
	__u32 bf16;
	__u32 tf32;
};
struct cn_heterogeneous_cap {
	__u32 max_queue;
	__u32 max_notifier;
	__u32 queue_prio_support;
	__u32 tiny_core;
	__u32 codec_jpeg;
	__u32 codec_h264;
	__u32 codec_h265;
	__u32 isp_core;
	bool multi_dev_notifier_wait;
	bool ipcnotifier_support;
};

struct cn_elastic_cap {
	__u32 max_dimx;
	__u32 max_dimy;
	__u32 max_dimz;
	__u32 max_cluster_count_per_union_task;
	__u32 o_max_cluster_count_per_union_task;
	__u32 max_cluster_count;
	__u32 max_core_count_per_cluster;
	__u32 max_quadrant_count;
	__u32 max_union_type_per_quadrant;
	__u32 mlu_isa_version;
	__u32 is_multiple_tensor_processor;
};

struct cn_memory_cap {
	__u32 max_l2_cache_size;
	__u64 n_ram_size_per_core;
	__u64 weight_ram_size_per_core;
	__u64 total_const_mem_size;

	__u64 local_mem_size_per_core;
	__u64 max_shared_ram_size_per_cluster;
	__u8 global_memory_node_count;
	__u32 cluster_l1_cache_support;
	__u32 max_persisting_l2_cache_size;
	__u32 max_shared_memory_size_per_union_task;
	__u32 can_use_host_pointer_for_register_mem;
	__u32 can_map_host_memory;
};

struct cn_hardware_cap {
	__u32 ecc_support;
	__u32 cluster_clock_rate;
	__u32 memory_clock_rate;
	__u32 bus_width;
	__u64 global_memory_total_size;
	__u32 mdr_memory_size;

	__u32 pci_bus_id;
	__u32 pci_device_id;
	__u32 pci_domain_id;
	__u32 pci_mps;
	__u32 pci_mrrs;
};

struct cn_attr_info {
	struct attr_head head;
    /*Computing Capabilities*/
	struct cn_computing_cap compute_cap;
    /* Heterogeneous Capabilities */
	struct cn_heterogeneous_cap heterogeneous_cap;
    /* Elastic Capabilities */
	struct cn_elastic_cap elastic_cap;
    /* Memory Capacities */
	struct cn_memory_cap memory_cap;
    /* Hardware Proterties */
	struct cn_hardware_cap hardware_cap;
};

struct cn_attr_fill_ops_vf {
	void (*fill_computing_vf)(void *core);
	void (*fill_heterogeneous_vf)(void *core);
	void (*fill_elastic_vf)(void *core);
	void (*fill_memory_vf)(void *core);
	void (*fill_hardware_vf)(void *core);
};

struct cn_attr_init_ops_vf {
	void (*init_boardinfo_vf)(struct cn_core_set *core);
	void (*init_attribute_vf)(struct cn_core_set *core);
};

struct cndev_attr_set {
	struct cn_attr_info attr_info;
	struct cn_attr_fill_ops_vf *fill_ops;
	struct cn_attr_init_ops_vf *init_ops;
	/* for CAMB_GET_DEVICE_PRIVATE_ATTR ioctl */
	__u32 extra_version;

	/* resource value, after cndev lateinit */
	u64 resource[RES_BASIC_INFO_END];
};

#endif
