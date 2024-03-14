/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_CNDRV_UDVMUSR_H__
#define __CAMBRICON_CNDRV_UDVMUSR_H__

#include "cndrv_gdma.h"

#define CAMBR_UDVM_MAGIC 'M'
enum {
	__UDVM_MEM_ALLOC         = 1,
	__UDVM_MEM_FREE          = 2,
	__UDVM_FB_MEM_ALLOC      = 4,
	__UDVM_MDR_ALLOC         = 5,
	__UDVM_MEMCPY            = 6,
	__UDVM_MEMCPY_ASYNC      = 7, /* deprecated */
	__UDVM_PEER_ABLE         = 8,
	__UDVM_MEMSET            = 9,
	__UDVM_MEMSETD16         = 10,
	__UDVM_MEMSETD32         = 11,
	__UDVM_MEMSET_ASYNC      = 12, /* deprecated */
	__UDVM_MEMSETD16_ASYNC   = 13, /* deprecated */
	__UDVM_MEMSETD32_ASYNC   = 14, /* deprecated */
	__UDVM_IPC_GET_HANDLE    = 15,
	__UDVM_IPC_OPEN_HANDLE   = 16,
	__UDVM_IPC_CLOSE_HANDLE  = 17,
	__UDVM_ENABLE_MEMCHECK   = 18,
	__UDVM_GET_ADDR_RANGE    = 19,
	__UDVM_PHY_PEER_ABLE     = 20,
	__UDVM_SET_PROT          = 22,
	__UDVM_GET_UVA           = 23,
	__UDVM_PUT_UVA           = 24,
	__UDVM_REGISTER_PRIVDATA = 25,
	__UDVM_BAR_COPY          = 26, /* only used for debug */
	__UDVM_MEM_ALLOC_EXT     = 27,
	__UDVM_MEMCPY_2D         = 28,
	__UDVM_MEMCPY_3D         = 29,
	__UDVM_MEM_INFO_ADJ      = 30,
	__UDVM_MEM_GET_ATTR      = 31,
	__UDVM_CACHE_OP          = 32,
	__UDVM_ADDRESS_RESERVE   = 33,
	__UDVM_ADDRESS_FREE      = 34,
	__UDVM_MEM_CREATE        = 35,
	__UDVM_MEM_RELEASE       = 36,
	__UDVM_MEM_MAP           = 37,
	__UDVM_MEM_SET_ACCESS	 = 38,
	__UDVM_MEM_UNMAP         = 39,
	__UDVM_VMM_ATTRIBUTE_V1  = 40,
	__UDVM_VMM_ATTRIBUTE     = 41,
	__UDVM_VMM_EXPORT        = 42,
	__UDVM_VMM_IMPORT        = 43,
	__UDVM_RST_PST_L2CACHE   = 44,
	__UDVM_MEMSET_2D         = 45,
	__UDVM_GRAPH_MEMCHECK    = 46,
	__UDVM_MEMCPY_COMPRESS   = 47,
	__UDVM_IMPORT_EXTERNAL   = 48,
	__UDVM_MAP_EXTERNAL      = 49,
	__UDVM_DESTROY_EXTERNAL  = 50,
	__UDVM_MEM_PERF_ALLOC     = 51,
	__UDVM_MEM_PERF_FREE      = 52,
	__UDVM_IPC_OPEN_HANDLE_V2 = 53,
	__UDVM_PINNED_MEM_RM_ALLOC = 54,
	__UDVM_PINNED_MEM_IOVA_ALLOC = 55,
	__UDVM_PINNED_MEM_MAP_DEVICE = 56,
	__UDVM_PINNED_MEM_DUP_MEM = 57,
	__UDVM_PINNED_MEM_IOVA_FREE = 58,
	__UDVM_PINNED_MEM_UNMAP_DEVICE = 59,
	__UDVM_PINNED_MEM_UNMAP_DMA = 60,
	__UDVM_PINNED_MEM_RM_FREE = 61,
	__UDVM_PINNED_MEM_RM_REGISTER = 62,
	__UDVM_PINNED_MEM_RM_UNREGISTER = 63,
	__UDVM_IOCTL_END,
};

/* Cambricon UDVM special error code */
#define UDVM_ERRCODE(num) (CAMBR_UDVM_MAGIC * 100 + (num))
enum udvm_error_code {
	ERROR_UDVM_MEMCPY_H2H = UDVM_ERRCODE(0),
	/**
	 * UDVM_ERRCODE(1) ~ UDVM_ERRCODE(4) will not be used again, compatible for old code.
	 *
	 * ERROR_UDVM_IPC_GET_HANDLE_HOST = UDVM_ERRCODE(1),
	 * ERROR_UDVM_IPC_OPEN_HANDLE_HOST = UDVM_ERRCODE(2),
	 * ERROR_UDVM_IPC_CLOSE_HANDLE_HOST = UDVM_ERRCODE(3),
	 * ERROR_UDVM_GET_ADDRESS_RANGE_HOST = UDVM_ERRCODE(4),
	 **/
	ERROR_UDVM_IPC_CLOSE_HANDLE_HOST = UDVM_ERRCODE(3),
	ERROR_UDVM_INVALID_DEVFP = UDVM_ERRCODE(5),
	ERROR_UDVM_NOT_SUPPORTED = UDVM_ERRCODE(6),
	ERROR_UDVM_INVALID_DEVICE = UDVM_ERRCODE(7),
};

enum udvm_attr_flags {
	ATTR_mair = 0x0,
	ATTR_ap = 0x2,
	ATTR_security = 0x3,
	ATTR_cachelocked = 0x4,
	ATTR_compress = 0x5,
};

enum udvm_modify_flags_index {
	MFIDX_mair = 0x0,
	MFIDX_ap = 0x1,
	MFIDX_security = 0x2,
	MFIDX_cachelocked = 0x3,
	MFIDX_compress = 0x4,
};

#define MF_KEY_OFFSET (16)
#define SET_MODIFY_FLAGS(flags, name, val) \
	(flags) |= ((val) << ATTR_##name) | (1 << (MF_KEY_OFFSET + MFIDX_##name))

struct udvm_alloc_s {
	__u64 size;
	__u32 align;
	__u32 type;
	__u32 affinity;
	__u32 flag;
	__u64 udvm_addr;
	__u32 dev_fd;
	__u32 udvm_status;
};

#define EXT_NAME_SIZE (32)
#define EXT_ANONYMOUS_NAME	"anonymous_ext"

struct udvm_perf_alloc_s {
	__u64 size;
	__u32 align;
	__u32 type;
	__u32 affinity;
	__u32 flag;
	__u64 udvm_addr;
	__u32 dev_fd;
	__u32 udvm_status;
	char name[EXT_NAME_SIZE];
	__u64 correlation_id;
	__u64 context_id;
};

struct udvm_alloc_ext_s {
	__u64 size;
	__u32 align;
	__u32 type;
	__u32 affinity;
	__u32 flag;
	__u64 udvm_addr;
	__u32 dev_fd;
	__u32 udvm_status;
	char name[EXT_NAME_SIZE];
};

#define UDVM_MEM_ALLOC \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_ALLOC, struct udvm_alloc_s)

#define UDVM_MEM_PERF_ALLOC \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_PERF_ALLOC, struct udvm_perf_alloc_s)

#define UDVM_FB_MEM_ALLOC \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_FB_MEM_ALLOC, struct udvm_alloc_s)

#define UDVM_MDR_MEM_ALLOC \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MDR_ALLOC, struct udvm_alloc_s)

#define UDVM_MEM_ALLOC_EXT \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_ALLOC_EXT, struct udvm_alloc_ext_s)

struct udvm_free_s {
	__u64 udvm_addr;
	__u64 udvm_status; /* set udvm_status as __u64 support memcheck return size */
};

struct udvm_perf_free_s {
	__u64 udvm_addr;
	__u64 udvm_status;
	__u64 correlation_id;
	__u64 context_id;
};

#define UDVM_MEM_FREE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_FREE, struct udvm_free_s)

#define UDVM_MEM_PERF_FREE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_PERF_FREE, struct udvm_perf_free_s)

enum udvm_memcpy_dir {
	UDVM_MEMCPY_DIR_RANDOM,
	UDVM_MEMCPY_DIR_H2H,
	UDVM_MEMCPY_DIR_H2D,
	UDVM_MEMCPY_DIR_D2H,
	UDVM_MEMCPY_DIR_D2D,
	UDVM_MEMCPY_DIR_P2P,
};

struct udvm_memcpy_s {
	__u64 src_addr;
	__u64 dst_addr;
	__u64 size;
	__u32 dir;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_MEMCPY \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMCPY, struct udvm_memcpy_s)

struct udvm_memcpy_compress_s {
	__u64 src_addr;
	__u64 dst_addr;
	__u64 size;
	__s32 compress_type;
	__u32 dir;
	__u64 reserve;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_MEMCPY_COMPRESS \
    _IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMCPY_COMPRESS, struct udvm_memcpy_compress_s)

struct udvm_pinned_mem_rm_alloc_s {
	__u64 size;
	__u64 uaddr;
	__u32 flags;
	__u32 card_dev_fd;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_PINNED_MEM_RM_ALLOC \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_RM_ALLOC, struct udvm_pinned_mem_rm_alloc_s)

struct udvm_pinned_mem_iova_alloc_s {
	__u64 size;
	__u64 uaddr;
	__u64 iova;/*reserve*/
	__u32 card_dev_fd;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_PINNED_MEM_IOVA_ALLOC \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_IOVA_ALLOC, struct udvm_pinned_mem_iova_alloc_s)

struct udvm_pinned_mem_map_device_s {
	__u64 uaddr;
	__u64 iova;/*reserve*/
	__u32 card_id;
	__u32 card_dev_fd;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_PINNED_MEM_MAP_DEVICE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_MAP_DEVICE, struct udvm_pinned_mem_map_device_s)

struct udvm_pinned_mem_dup_mem_s {
	__u64 uaddr;
	__u32 card_id;
	__u32 card_dev_fd;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_PINNED_MEM_DUP_MEM \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_DUP_MEM, struct udvm_pinned_mem_dup_mem_s)

struct udvm_pinned_mem_iova_free_s {
	__u64 uaddr;
	__u64 iova;/*reserve*/
	__u32 card_dev_fd;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_PINNED_MEM_IOVA_FREE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_IOVA_FREE, struct udvm_pinned_mem_iova_free_s)

struct udvm_pinned_mem_unmap_device_s {
	__u64 uaddr;
	__u64 iova;/*reserve*/
	__u32 card_id;
	__u32 card_dev_fd;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_PINNED_MEM_UNMAP_DEVICE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_UNMAP_DEVICE, struct udvm_pinned_mem_unmap_device_s)

struct udvm_pinned_mem_unmap_dma_s {
	__u64 uaddr;
	__u64 iova;/*reserve*/
	__u32 card_id;
	__u32 card_dev_fd;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_PINNED_MEM_UNMAP_DMA \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_UNMAP_DMA, struct udvm_pinned_mem_unmap_dma_s)

struct udvm_pinned_mem_rm_free_s {
	__u64 size;
	__u64 uaddr;
	__u32 card_id;
	__u32 card_dev_fd;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_PINNED_MEM_RM_FREE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_RM_FREE, struct udvm_pinned_mem_rm_free_s)

struct udvm_pinned_mem_rm_register_s {
	__u64 size;
	__u64 uaddr;
	__u64 iova;/*reserve*/
	__u32 flags;
	__u32 card_id;
	__u32 card_dev_fd;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_PINNED_MEM_RM_REGISTER \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_RM_REGISTER, struct udvm_pinned_mem_rm_register_s)

struct udvm_pinned_mem_rm_unregister_s {
	__u64 uaddr;
	__u32 card_id;
	__u32 card_dev_fd;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_PINNED_MEM_RM_UNREGISTER \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_RM_UNREGISTER, struct udvm_pinned_mem_rm_unregister_s)

struct udvm_pinned_mem_get_handle_s {
	__u64 uaddr;
	__u64 handle;
	__u32 card_id;
	__u32 card_dev_fd;
	__u64 udvm_status;
};

#define UDVM_PINNED_MEM_GET_HANDLE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_GET_HANDLE, struct udvm_pinned_mem_get_handle_s)

struct udvm_pinned_mem_open_handle_s {
	__u64 size;
	__u64 uaddr;
	__u64 handle;
	__u32 card_id;
	__u32 card_dev_fd;
	__u64 udvm_status;
};

#define UDVM_PINNED_MEM_OPEN_HANDLE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_OPEN_HANDLE, struct udvm_pinned_mem_open_handle_s)
struct udvm_pinned_mem_close_handle_s {
	__u64 size;
	__u64 uaddr;
	__u64 handle;
	__u32 card_id;
	__u32 card_dev_fd;
	__u64 udvm_status;
};

#define UDVM_PINNED_MEM_CLOSE_HANDLE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PINNED_MEM_CLOSE_HANDLE, struct udvm_pinned_mem_close_handle_s)

struct udvm_memcpy_2d_s {
	__u64 dst_addr;
	__u64 dpitch;
	__u64 src_addr;
	__u64 spitch;
	__u64 width;
	__u64 height;
	__u32 dir;
	__u64 udvm_status; /* camb_u64_t return value used to save residual_size */
};

#define UDVM_MEMCPY_2D _IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMCPY_2D, struct udvm_memcpy_2d_s)

struct udvm_memcpy_3d_s {
	__u64 dst_addr;
	struct memcpy_d2d_3d_pos dst_pos;
	struct memcpy_d2d_3d_pitch dst_ptr;
	struct memcpy_d2d_3d_extent extent;
	__u64 src_addr;
	struct memcpy_d2d_3d_pos src_pos;
	struct memcpy_d2d_3d_pitch src_ptr;
	__u32 dir;
	__u64 udvm_status; /* camb_u64_t return value used to save residual_size */
};

#define UDVM_MEMCPY_3D _IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMCPY_3D, struct udvm_memcpy_3d_s)

struct udvm_memcpy_async_s {
	__u64 version;
	__u64 hqueue;
	__u64 queue_fd;
	__u64 src_addr;
	__u64 dst_addr;
	__u64 size;
	__u32 dir;
	__u64 udvm_status; /* __u64 return value used to save residual_size */
};

#define UDVM_MEMCPY_ASYNC \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMCPY_ASYNC, struct udvm_memcpy_async_s)

struct udvm_peerable_s {
	__u32 src_fd;
	__u32 dst_fd;
	__u32 udvm_status;
};

#define UDVM_PEER_ABLE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PEER_ABLE, struct udvm_peerable_s)

#define UDVM_PHY_PEER_ABLE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PHY_PEER_ABLE, struct udvm_peerable_s)

struct udvm_memset_s {
	__u64 udvm_addr;
	__u32 val;
	__u64 number;
	__u32 udvm_status;
};

#define UDVM_MEMSET \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMSET, struct udvm_memset_s)

#define UDVM_MEMSETD16 \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMSETD16, struct udvm_memset_s)

#define UDVM_MEMSETD32 \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMSETD32, struct udvm_memset_s)

struct udvm_memset_async_s {
	__u64 version;
	__u64 hqueue;
	__u64 queue_fd;
	__u64 udvm_addr;
	__u32 val;
	__u64 number;
	__u32 udvm_status;
};

#define UDVM_MEMSET_ASYNC \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMSET_ASYNC, struct udvm_memset_async_s)

#define UDVM_MEMSETD16_ASYNC \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMSETD16_ASYNC, struct udvm_memset_async_s)

#define UDVM_MEMSETD32_ASYNC \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMSETD32_ASYNC, struct udvm_memset_async_s)

/**
 * FIXME: memory ipc interfaces not support running on different device Context
 * and not support running twice in same process.
 **/
struct udvm_ipc_s {
	__u64 udvm_addr;    /* IN for ipc_get_handle,  OUT for ipc_open_handle */
	__u64 handle;       /* IN for ipc_open_handle, OUT for ipc_get_handle */
	__u32 dev_fd;		/* IN for ipc_open_handle */
	__u32 udvm_status;  /* OUT */
};

enum {
	/* UDVM_IPC_MEM_LAZY_ENABLE_PEER_ACCESS = 0x1, // for reserved */
	UDVM_IPC_MEM_NEED_PEER_ACCESS = 0x2,
	UDVM_IPC_MEM_INVALID,
};
struct udvm_ipc_v2_s {
	__u64 udvm_addr;    /* IN for ipc_get_handle,  OUT for ipc_open_handle */
	__u64 handle;       /* IN for ipc_open_handle, OUT for ipc_get_handle */
	__u32 flags;        /* IN for ipc_open handle */
	__u32 dev_fd;		/* IN for ipc_open_handle */
	__u32 oflags;
	__u32 type;
	__u32 udvm_status;  /* OUT */
};

#define UDVM_IPC_GET_HANDLE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_IPC_GET_HANDLE, struct udvm_ipc_s)

#define UDVM_IPC_OPEN_HANDLE_V2 \
	_IOWR(CAMBR_UDVM_MAGIC, __UDVM_IPC_OPEN_HANDLE_V2, struct udvm_ipc_v2_s)

#define UDVM_IPC_OPEN_HANDLE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_IPC_OPEN_HANDLE, struct udvm_ipc_s)

#define UDVM_IPC_CLOSE_HANDLE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_IPC_CLOSE_HANDLE, struct udvm_free_s)

struct udvm_enable_memcheck_s {
	__u32 magic; /* if input magic is zero means disable memcheck */
	__u32 udvm_status;
};

#define UDVM_ENABLE_MEMCHECK \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_ENABLE_MEMCHECK, struct udvm_enable_memcheck_s)

struct udvm_range_get_s {
	__u64 udvm_addr;
	__u64 udvm_base;
	__u64 size;
	__u32 udvm_status;
};

#define UDVM_GET_ADDR_RANGE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_GET_ADDR_RANGE, struct udvm_range_get_s)

struct udvm_prot_set_s {
	__u64 udvm_addr;
	__u64 size;
	__u32 flag;
	__u32 udvm_status;
};

#define UDVM_SET_PROT \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_SET_PROT, struct udvm_prot_set_s)

struct udvm_uva_get_s {
	__u32 version;
	__u32 attr;
	__u64 udvm_addr;
	__u64 uva;
	__u64 size;
	__u32 dev_fd;
	__u32 udvm_status;
	__u64 priv[0];
};

#define UDVM_GET_UVA \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_GET_UVA, struct udvm_uva_get_s)

struct udvm_uva_put_s {
	__u32 version;
	__u32 attr;
	__u64 udvm_addr;
	__u64 uva;
	__u64 size;
	__u32 udvm_status;
	__u64 priv[0];
};

#define UDVM_PUT_UVA \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_PUT_UVA, struct udvm_uva_put_s)

struct udvm_register_data_s {
	__u32 dev_fd;
	__u32 udvm_status;
};

#define UDVM_REGISTER_PRIVDATA \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_REGISTER_PRIVDATA, struct udvm_register_data_s)

/* only used for debug */
struct udvm_bar_copy_s {
	__u64 src_addr;
	__u64 dst_addr;
	__u64 size;
	__u32 udvm_status;
};

#define UDVM_BAR_COPY \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_BAR_COPY, struct udvm_bar_copy_s)

/* used to adjust the memory information */
struct udvm_info_adj_s {
	__u32 cid; /* card id */
	__u32 dir;
	__u64 size;
	__u32 udvm_status;
};

#define UDVM_MEM_INFO_ADJ \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_INFO_ADJ, struct udvm_info_adj_s)

#define UDVM_ATTRIBUTE_VERSION (1)
typedef enum udvm_attribute_enum {
	/**< 0x0 used to save udvm_status which is the return value of this command **/
	UDVM_ATTRIBUTE_TYPE =           0x1, /**< The memory type describes of the input address */
	UDVM_ATTRIBUTE_DEVICE_POINTER =	0x2, /**< The address at which a pointer's memory may be accessed on the Device. */
	UDVM_ATTRIBUTE_HOST_POINTER =   0x3, /**< The address at which a pointer's memory may be accessed on the host. */
	UDVM_ATTRIBUTE_SUPPORT_CACHE_OPS = 0x4, /**< Indicates if the pointer points to do cache operation */
	UDVM_ATTRIBUTE_CONTEXT =        0x5, /**< The ::CNcontext on which a pointer was allocated or registered. */
	UDVM_ATTRIBUTE_DEVICE_ORDINAL = 0x6, /**< A Device ordinal of a Device on which a pointer was allocated or registered. */
	UDVM_ATTRIBUTE_START_ADDR =     0x7, /**< Starting address for this requested pointer. */
	UDVM_ATTRIBUTE_SIZE =           0x8, /**< Size of the address range for this requested pointer. */
	UDVM_ATTRIBUTE_HOST_CACHE_TYPE = 0x9, /**< specificed host pointer cache type */
	UDVM_ATTRIBUTE_MAPPED = 0xa,          /**< specificed the pointer input whether has been mapped device memory. */
	UDVM_ATTRIBUTE_ALLOWED_HANDLE_TYPES = 0xb, /* return a bitmask of allowed handle types for an allocation. */
	UDVM_ATTRIBUTE_ISLINEAR = 0xc, /* specificed the pointer input is linear device memory. */
	UDVM_ATTRIBUTE_MAX = 0x40,           /**< Reserved. */
} udvm_attrubte;

enum udvm_memory_type {
	UDVM_MEMORY_TYPE_UNKNOWN = 0x0,
	UDVM_MEMORY_TYPE_HOST    = 0x1,
	UDVM_MEMORY_TYPE_DEVICE  = 0x2,
};

enum udvm_host_cache_type {
	UDVM_HOST_CACHE_NOT_SUPPORT = -1,
	UDVM_HOST_CACHE_UNKNOWN = 0x0,
	UDVM_HOST_NONCACHE  = 0x1,
	UDVM_HOST_CACHEABLE  = 0x2,
};

struct udvm_attr_s {
	__u64 addr;
	__u32 version;
	__u32 counts;
	__u64 *data; /* sizeof(data) == UDVM_ATTRIBUTE_MAX * __u64 */
};
#define UDVM_MEM_GET_ATTR \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_GET_ATTR, struct udvm_attr_s)

enum udvm_cache_op_type {
	UDVM_CACHE_OP_UNKNOWN = 0x0,
	UDVM_CACHE_OP_FLUSH = 0x1,
	UDVM_CACHE_OP_INVALID = 0x2,
	UDVM_CACHE_OP_CLEAN = 0x3,
};

struct udvm_cache_s {
	__u64 uva;
	__u64 udvm_addr;
	__u64 size;
	__u32 op;
	__u32 udvm_status;
};
#define UDVM_CACHE_OP \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_CACHE_OP, struct udvm_cache_s)

/* NOTE: mlu_id is physical mlu device id, we need do Virtual2Physical translate in driverAPI */
struct udvm_mem_create_s {
	__u64 size;
	__u32 mlu_id;
	__u32 flags;
	__u64 udvm_handle;
	__u32 udvm_status;
};
#define UDVM_MEM_CREATE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_CREATE, struct udvm_mem_create_s)

struct udvm_mem_release_s {
	__u64 udvm_handle;
	__u32 udvm_status;
};
#define UDVM_MEM_RELEASE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_RELEASE, struct udvm_mem_release_s)

struct udvm_addr_reserve_s {
	__u64 size;
	__u64 align;
	__u64 start;
	__u64 flags;
	__u64 udvm_addr;
	__u32 udvm_status;
};
#define UDVM_ADDRESS_RESERVE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_ADDRESS_RESERVE, struct udvm_addr_reserve_s)

struct udvm_addr_free_s {
	__u64 udvm_addr;
	__u64 size;
	__u32 udvm_status;
};
#define UDVM_ADDRESS_FREE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_ADDRESS_FREE, struct udvm_addr_free_s)

struct udvm_mem_map_s {
	__u64 udvm_handle;
	__u64 udvm_addr;
	__u64 offset;
	__u64 size;
	__u32 udvm_status;
};
#define UDVM_MEM_MAP \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_MAP, struct udvm_mem_map_s)

struct udvm_set_access_s {
	__u64 udvm_addr;
	__u64 size;
	__u32 mlu_id;
	__u32 flags;
	__u32 udvm_status;
};
#define UDVM_MEM_SET_ACCESS \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_SET_ACCESS, struct udvm_set_access_s)

struct udvm_mem_unmap_s {
	__u64 udvm_addr;
	__u64 size;
	__u32 udvm_status;
};
#define UDVM_MEM_UNMAP \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_MEM_UNMAP, struct udvm_mem_unmap_s)

struct udvm_rst_pst_l2cache_s {
	__u32 dev_fd;
	__u32 udvm_status;
};
#define UDVM_RST_PST_L2CACHE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_RST_PST_L2CACHE, struct udvm_rst_pst_l2cache_s)


enum udvm_vmm_attribute_enum {
	UDVM_VMM_ATTRIBUTE_GRANULARITY = 0x0,
	UDVM_VMM_ATTRIBUTE_HANDLE_PROP = 0x1,
	UDVM_VMM_ATTRIBUTE_POINTER_ACCESS = 0x2,
	UDVM_VMM_ATTRIBUTE_POINTER_HANDLE = 0x3,
};

enum udvm_vmm_granularity {
	UDVM_VMM_GRANULARITY_MINIMUM = 0x0,
	UDVM_VMM_GRANULARITY_RECOMMENDED = 0x1,
};

/**
 * NOTE: udvm_vmm_prop_xx used for cnMemGetAllocationPropertiesFromHandle.
 * user input an handle_id to query its allocation_prop(flags, location.id,
 * location.type).
 *
 * return data is u64 type:
 * bit[31:0]: flags, bit[39:32]: location id, bit[41:40]: location type.
 **/
enum udvm_vmm_handle_prop_ofs {
	VMM_HANDLE_PROP_FLAGS_OFS = 0,
	VMM_HANDLE_PROP_LOCATION_ID_OFS = 32,
	VMM_HANDLE_PROP_LOCATION_TYPE_OFS = 40,
};

enum udvm_vmm_handle_prop_width {
	VMM_HANDLE_PROP_WIDTH_FLAGS = 32,
	VMM_HANDLE_PROP_WIDTH_LOCATION_ID = 8,
	VMM_HANDLE_PROP_WIDTH_LOCATION_TYPE = 2,
};

#define VMM_SET_HANDLE_PROP_DATA(prop, name, val) \
	do { \
		(prop) &= ~(((1UL << VMM_HANDLE_PROP_WIDTH_##name) - 1) << (VMM_HANDLE_PROP_##name##_OFS)); \
		(prop) |= (__u64)((val) & ((1UL << VMM_HANDLE_PROP_WIDTH_##name) - 1)) << (VMM_HANDLE_PROP_##name##_OFS); \
	} while (0)

#define VMM_GET_HANDLE_PROP_DATA(prop, name) \
	(((prop) >> (VMM_HANDLE_PROP_##name##_OFS)) & ((1UL << (VMM_HANDLE_PROP_WIDTH_##name)) - 1))

struct udvm_vmm_attr_s {
	__u64 args[4];
	__u32 nums;
	__u64 type;
	__u64 data;
	__u32 udvm_status;
};
#define UDVM_VMM_ATTRIBUTE \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_VMM_ATTRIBUTE, struct udvm_vmm_attr_s)

struct udvm_vmm_attr_v1_s {
	__u64 args;
	__u64 type;
	__u64 data;
	__u32 udvm_status;
};
#define UDVM_VMM_ATTRIBUTE_V1 \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_VMM_ATTRIBUTE_V1, struct udvm_vmm_attr_v1_s)

enum vmm_shareable_handle_type {
	VMM_HANDLE_TYPE_FILE_DESCRIPTOR = 0x1,
};

struct udvm_vmm_share_s {
	__u64 udvm_handle;
	__u64 shareable_handle;
	__u32 type;
	__u32 flags;
	__u32 udvm_status;
};
#define UDVM_VMM_EXPORT \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_VMM_EXPORT, struct udvm_vmm_share_s)

#define UDVM_VMM_IMPORT \
	_IOW(CAMBR_UDVM_MAGIC, __UDVM_VMM_IMPORT, struct udvm_vmm_share_s)

struct udvm_memset_2d_s {
	__u64 udvm_addr;
	__u64 pitch;
	__u32 val;
	__u32 element_size;
	__u64 width;
	__u64 height;
	__u32 udvm_status;
};
#define UDVM_MEMSET_2D                             \
        _IOW(CAMBR_UDVM_MAGIC, __UDVM_MEMSET_2D, struct udvm_memset_2d_s)

struct udvm_graph_memcheck_s {
	__u32 type; /* 0 as memcpy3D and the 1 indicates memset2D */
	union {
		struct udvm_memcpy_3d_s memcpy;
		struct udvm_memset_2d_s memset;
	};
};
#define UDVM_GRAPH_MEMCHECK                             \
        _IOW(CAMBR_UDVM_MAGIC, __UDVM_GRAPH_MEMCHECK, struct udvm_graph_memcheck_s)

struct udvm_import_ext_mem_s {
	__u64 size;
	__u64 udvm_handle;
	__u32 udvm_status;
	__u32 import_handle;
	__u32 dev_fd; /*to get mm_set*/
};

#define UDVM_IMPORT_EXTERNAL                             \
	_IOWR(CAMBR_UDVM_MAGIC, __UDVM_IMPORT_EXTERNAL, struct udvm_import_ext_mem_s)

struct udvm_destroy_ext_mem_s {
	__u64 udvm_handle;
	__u32 udvm_status;
};
#define UDVM_DESTROY_EXTERNAL \
	_IOWR(CAMBR_UDVM_MAGIC, __UDVM_DESTROY_EXTERNAL, struct udvm_destroy_ext_mem_s)

struct udvm_map_ext_mem_s {
	__u64 udvm_handle;
	__u64 offset;
	__u64 size;
	__u64 udvm_addr;
	__u32 udvm_status;
	__u32 dev_fd;
	__u32 flag;
};

#define UDVM_MAP_EXTERNAL                             \
	_IOWR(CAMBR_UDVM_MAGIC, __UDVM_MAP_EXTERNAL, struct udvm_map_ext_mem_s)

#endif /* __CAMBRICON_CNDRV_UDVMUSR_H__ */
