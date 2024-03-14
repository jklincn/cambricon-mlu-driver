/*
 * core/cndrv_ioctl.h
 * For sbts ioctl definitions.
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _CNDRV_IOCTL_H_
#define _CNDRV_IOCTL_H_

#if defined(__KERNEL__)
/*for kernel*/
#include <linux/types.h>
#include <asm/ioctl.h>

#elif defined(__linux__)
/*for userspace*/
#include <linux/types.h>
#include <asm/ioctl.h>

#else /* One of the BSDs */
/*for other BSDs*/
#include <sys/ioccom.h>
#include <sys/types.h>
typedef int8_t   __s8;
typedef uint8_t  __u8;
typedef int16_t  __s16;
typedef uint16_t __u16;
typedef int32_t  __s32;
typedef uint32_t __u32;
typedef int64_t  __s64;
typedef uint64_t __u64;
typedef size_t   __kernel_size_t;
#endif

#if defined(__cplusplus)
extern "C" {
#endif

/* module ioctl magic */
#define CAMBR_BUS_MAGIC              'B'    /* pcie bus */
#define CAMBR_MM_MAGIC               'M'    /* memory */
#define CAMBRICON_MAGIC_NUM          'Y'    /* device attribute */
#define CAMBR_SBTS_MAGIC             'S'    /* sbts */
#define CAMBR_HB_MAGIC               'E'    /* exp_mgnt */
#define CAMBR_NCS_MAGIC              'N'    /* ncs */
#define CAMBR_MIGRATION_MAGIC        0xee
#define CAMBR_CTX_MAGIC              'C'    /* ctx */



#define DRV_SERIAL_NUM_LEN 2	/*should be define in ioctl.h*/

/* Sync Type is same as driver-api type.
 * Instruction detail of each type in driver-api.
 */
enum cn_ctx_sched_type {
	/* Default Sync Pattern is same as Spin,
	 * Please reference spin sync type.
	 */
	CN_CTX_SCHED_SYNC_DEFAULT = 0,

	/* Thread blocking spin wait for result from MLU,
	 * this mode decrease latency but may the lower performance
	 * of CPU threads and high CPU usage.
	 */
	CN_CTX_SCHED_SYNC_SPIN = CN_CTX_SCHED_SYNC_DEFAULT,

	/* Thread is blocked and waiting for sleep,
	 * this mode has low CPU usage.
	 */
	CN_CTX_SCHED_SYNC_WAIT,

	/* Thread will yield to other thread when waiting
	 * the result, this mode may increase latency but
	 * increase the performance of CPU threads.
	 */
	CN_CTX_SCHED_SYNC_YIELD,
	CN_CTX_SCHED_SYNC_BUTT,
	CN_CTX_SCHED_SYNC_MASK = 0xffU,
};

/*read pcie config with dword*/
struct read_pci_config_s {
	__u32 offset;
	__u32 val;
};

/*write pcie config with dword*/
struct write_pci_config_s {
	__u32 offset;
	__u32 val;
};


/*COPY_TO_RAM_PHY*/
struct copy_to_ram_s {
	__u32 size;
	__u64 cpu_addr;
	__u64 ram_addr;/*ipu physical addr*/
};
/*COPY_FORM_RAM_PHY*/
struct copy_from_ram_s {
	__u32 size;
	__u64 cpu_addr;
	__u64 ram_addr;/*ipu physical addr*/
};

/*PCIE_BAR_WRITE_MEMSET*/
struct mem_bar_memset_s {
	__u64 dev_addr;
	unsigned char val;
	__u32 number;
};

struct mem_bar_memsetd16_s {
	__u64 dev_addr;
	unsigned short val;
	__u32 number;
};

struct mem_bar_memsetd32_s {
	__u64 dev_addr;
	unsigned int val;
	__u32 number;
};

/*64-bit size compatible. Note that the padding parament don't be deleted at
 * anytime. If not, the size of struct xxx_compat_s is same as the old
 * struct's. Then it is impossible to distinguish the old or new struct.*/
struct mem_bar_memset_compat_s {
	__u64 dev_addr;
	__u8 val;
	__u8 padding[3];
	__u64 number;
};

struct mem_bar_memsetd16_compat_s {
	__u64 dev_addr;
	__u16 val;
	__u16 padding;
	__u64 number;
};

struct mem_bar_memsetd32_compat_s {
	__u64 dev_addr;
	__u32 val;
	__u64 number;
};

/*MEM_ALLOC*/
struct mem_alloc_s {
	__u32 size;
	__u32 align;
	__u32 type;
	__u32 affinity;
	__u32 flag;
	__u64 ret_addr;
};
/*64-bit size compatible. Note that the padding parament don't be deleted at
 * anytime. If not, the size of struct xxx_compat_s is same as the old
 * struct's. Then it is impossible to distinguish the old or new struct.*/
struct mem_alloc_compat_s {
	__u64 size;
	__u32 align;
	__u32 type;
	__u32 affinity;
	__u32 flag;
	__u64 ret_addr;
	__u64 padding;
};

/*set prot of allocated memory*/
struct mem_set_prot_s {
	__u64 dev_vaddr;
	__u64 size;
	__u32 prot_flag;
};

/*MEM_FREE*/
struct mem_free_param_s {
	__u64 ret_addr;
	__u32 size;
};

/*MEM_MERGE*/
struct mem_merge_param_s {
	__u32 cnt;
	__u64 *virt_addrs;
	__u64 merged_addr;
};

/*BAR_COPY_TO_DDR*/
struct mem_bar_copy_h2d_s {
	__u64 ca;
	__u64 ia;
	__u64 total_size;
};

/*BAR_COPY_FROM_DDR*/
struct mem_bar_copy_d2h_s {
	__u64 ca;
	__u64 ia;
	__u64 total_size;
};

/*COPY_TO_DDR*/
struct mem_copy_h2d_s {
	__u64 ca;
	__u64 ia;
	__u32 total_size;
	__u32 residual_size;
};

/*MEM_GET_UVA*/
struct mem_get_uva_s {
	__u32 version;
	__u32 attr;
	__u64 iova;
	__u64 uva;
	__u64 size;
	__u64 priv[0];
};

/*MEM_PUT_UVA*/
struct mem_put_uva_s {
	__u32 version;
	__u32 attr;
	__u64 iova;
	__u64 uva;
	__u64 size;
	__u64 priv[0];
};

/**/
struct mem_get_ipu_resv_s {
	__u64 ipu_resv_addr;
	__u64 group_off;
	__u64 core_off;
};


/*COPY_TO_DDR*/
struct mem_copy_h2d_compat_s {
	__u64 ca;
	__u64 ia;
	__u64 total_size;
	__u64 residual_size;
};

/*COPY_FROM_DDR*/
struct mem_copy_d2h_s {
	__u64 ca;
	__u64 ia;
	__u32 total_size;
	__u32 residual_size;
};
/*COPY_FROM_DDR*/
struct mem_copy_d2h_compat_s {
	__u64 ca;
	__u64 ia;
	__u64 total_size;
	__u64 residual_size;
};

/*COPY_FROM_DDR_TO_DDR*/
struct mem_copy_d2d_s {
	__u64 src;
	__u64 dst;
	__u32 size;
//	__u32 residual_size;
};

/*COPY_FROM_DDR_TO_DDR*/
struct mem_copy_d2d_compat_s {
	__u64 src;
	__u64 dst;
	__u64 size;
	__u64 residual_size;
};

/*COPY_2D_FROM_DDR_TO_DDR*/
struct mem_copy_d2d_2d_compat_s {
	__u64 src;
	__u64 dst;
	__u64 spitch;
	__u64 dpitch;
	__u64 width;
	__u64 height;
	__u64 residual_size;
};

/* p2p */
struct mem_copy_p2p_s {
	int peer_fd;    /* peer open fd */
	__u64 src_addr; /* self ram addr */
	__u64 dst_addr; /* peer ram addr */
	__u32 count;
};

/*64-bit size compatible. Note that the padding parament don't be deleted at
 * anytime. If not, the size of struct xxx_compat_s is same as the old
 * struct's. Then it is impossible to distinguish the old or new struct.*/
struct mem_copy_p2p_compat_s {
	int peer_fd;    /* peer open fd */
	__u64 src_addr; /* self ram addr */
	__u64 dst_addr; /* peer ram addr */
	__u64 count;
	__u64 padding;
};

#define GET_COMPAT_PARAM(d, type, cond, member) \
({	\
	__u64 val;	\
	void *__pdata = d;	\
	BUG_ON(!__pdata);	\
	if ((sizeof(struct mem_##type##_compat_s)) > cond) {\
		val = ((struct mem_##type##_s *)__pdata)->member;\
	} else { \
		val = ((struct mem_##type##_compat_s *)__pdata)->member;\
	} \
	\
	val;\
})

#define SET_COMPAT_PARAM(d, type, cond, member, value) \
({	\
	void *__pdata = d;	\
	BUG_ON(!__pdata);	\
	if ((sizeof(struct mem_##type##_compat_s)) > cond) {\
		((struct mem_##type##_s *)__pdata)->member = value;\
	} else { \
		((struct mem_##type##_compat_s *)__pdata)->member = value;\
	} \
})

/* p2p able */
struct p2p_able_s {
	int peer_fd;    /* peer open fd */
};

struct user_va_s {
	__u64 va;
};

struct c20_device_attr {
	int size;
	void *data;
};

struct cn_device_attr {
	__u16 version;
	int cnt;
	void *data;
};

struct cn_ipcm_handle {
	__u64 dev_vaddr;
	__u64 handle;
};

struct cn_mem_check {
	unsigned int flag;
	unsigned int magic;
};

struct cn_get_mem_range {
	__u64 dev_vaddr;
	__u64 vaddr_base;
	__u64 vaddr_size;
	int	  status;
};

struct cn_user_trace {
	int row;
	int size;
	char *strings[100];
};

struct dob_alloc_t {
	size_t size;
	__u64 device_va;
	unsigned long host_kva;
};

struct dob_free_t {
	__u64 device_va;
	unsigned long host_kva;
};

struct dob_write_t {
	__u64 device_va;
	unsigned long host_kva;
	size_t size;
	__u8 data;
	void *buf;
};

struct dob_read_t {
	__u64 device_va;
	unsigned long host_kva;
	size_t size;
	__u8 data;
	void *buf;
};

struct sram_write_t {
	__u64 device_va;
	size_t size;
	__u32 data;
	void *buf;
};

struct sram_read_t {
	__u64 device_va;
	size_t size;
	__u32 data;
	void *buf;
};

enum bus_nr_type {
	_B_SHOW_PCIE_INFO = 7,
	_B_PCIE_CSPEED = 10,
	_B_GET_PCIE_BAR_INFO,
	_B_GET_PCIE_INFO,
	_BUS_MAX_NR_COUNT,
};
#define BUS_MAX_NR_COUNT		13

#define B_SHOW_PCIE_INFO   _IO(CAMBR_BUS_MAGIC, _B_SHOW_PCIE_INFO)
#define B_GET_PCIE_BAR_INFO   _IO(CAMBR_BUS_MAGIC, _B_GET_PCIE_BAR_INFO)
#define B_GET_PCIE_INFO   _IO(CAMBR_BUS_MAGIC, _B_GET_PCIE_INFO)
#define B_PCIE_CSPEED     _IOW(CAMBR_BUS_MAGIC, _B_PCIE_CSPEED, unsigned int)

/*for memory moudle*/

enum mm_nr_type{
	_M_MEM_ALLOC = 1,
	_M_MEM_FREE,
	_M_MEM_MERGE,
	_M_MEM_COPY_H2D,
	_M_MEM_COPY_D2H,
	_M_FRAME_BUFFER_ALLOC = 7,
	_M_FB_MEM_ALLOC,
	_M_PHY_PEER_ABLE = 10,
	_M_MEM_COPY_D2D,
	_M_PEER_TO_PEER,
	_M_PEER_ABLE,
	_M_DMA_MEMSET,
	_M_IPCM_GET_HANDLE,
	_M_IPCM_OPEN_HANDLE,
	_M_IPCM_CLOSE_HANDLE,
	_M_MEM_COPY_ASYNC_H2D = 20,
	_M_MEM_COPY_ASYNC_D2H,
	_M_PEER_TO_PEER_ASYNC,
	_M_MDR_ALLOC,
	_M_ENABLE_MEMCHECK,
	_M_GET_MEM_RANGE,
	_M_MEM_COPY_ASYNC_D2D,
	_M_DMA_MEMSETD32,
	_M_DMA_MEMSET_ASYNC,
	_M_DMA_MEMSETD32_ASYNC,
	_M_MEM_BAR_COPY_H2D,
	_M_MEM_BAR_COPY_D2H,
	_M_DMA_MEMSETD16,
	_M_DMA_MEMSETD16_ASYNC,
	_M_MEM_SET_PROT,
	_M_PRT_USER_TRACE,
	_M_PRT_USER_TRACE_ENABLE,
	_M_MEM_GET_UVA,
	_M_MEM_PUT_UVA,
	_M_MEM_GET_IPU_RESV_MEM,
	_M_MEM_KERNEL_TEST,
	_M_MEM_COPY_D2D_2D,
	_M_MEM_COPY_D2D_3D,
	_M_PCIE_DOB_ALLOC,
	_M_PCIE_DOB_FREE,
	_M_PCIE_DOB_WRITE,
	_M_PCIE_DOB_READ,
	_M_PCIE_DOB_RPC_WRITE,
	_M_PCIE_DOB_RPC_READ,
	_M_PCIE_DOB_RPC_OPEN,
	_M_PCIE_DOB_RPC_CLOSE,
	_M_PCIE_SRAM_RPC_WRITE,
	_M_PCIE_SRAM_RPC_READ,

#ifdef PEER_FREE_TEST
	_M_INBD_SHM_ALLOC_TEST = 97,
	_M_OUTBD_SHM_ALLOC_TEST,
	_M_PEER_FREE_TEST,
#endif
	_MM_MAX_NR_COUNT,
};
#define MM_MAX_NR_COUNT	100

#define M_MEM_ALLOC				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_ALLOC, struct mem_alloc_compat_s)
#define M_MEM_SET_PROT				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_SET_PROT, struct mem_set_prot_s)
#define M_PRT_USER_TRACE				\
	_IOW(CAMBR_MM_MAGIC, _M_PRT_USER_TRACE, struct cn_user_trace)
#define M_PRT_USER_TRACE_ENABLE				\
	_IO(CAMBR_MM_MAGIC, _M_PRT_USER_TRACE_ENABLE)
#define M_MEM_FREE				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_FREE, struct mem_free_param_s)
#define M_MEM_MERGE				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_MERGE, struct mem_merge_param_s)
#define M_MEM_COPY_H2D				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_COPY_H2D, struct mem_copy_h2d_compat_s)
#define M_MEM_COPY_D2H				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_COPY_D2H, struct mem_copy_d2h_compat_s)
#define M_FRAME_BUFFER_ALLOC		\
	_IOW(CAMBR_MM_MAGIC, _M_FRAME_BUFFER_ALLOC, struct mem_alloc_compat_s)
#define M_FB_MEM_ALLOC			\
	_IOW(CAMBR_MM_MAGIC, _M_FB_MEM_ALLOC, struct mem_alloc_compat_s)
#define M_MEM_COPY_D2D				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_COPY_D2D, struct mem_copy_d2d_compat_s)
#define M_MEM_COPY_D2D_2D			\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_COPY_D2D_2D, struct mem_copy_d2d_2d_compat_s)
#define M_MEM_COPY_D2D_3D         \
	_IOW(CAMBR_MM_MAGIC, _M_MEM_COPY_D2D_3D, struct mem_copy_d2d_3d_compat)

#define M_PEER_TO_PEER    \
	_IOW(CAMBR_MM_MAGIC,  _M_PEER_TO_PEER, struct mem_copy_p2p_compat_s)
#define M_PEER_ABLE    \
	_IOW(CAMBR_MM_MAGIC,  _M_PEER_ABLE, struct p2p_able_s)
#define M_PHY_PEER_ABLE    \
	_IOW(CAMBR_MM_MAGIC,  _M_PHY_PEER_ABLE, struct p2p_able_s)
#define M_DMA_MEMSET	\
	_IOW(CAMBR_MM_MAGIC, _M_DMA_MEMSET, struct mem_bar_memset_compat_s)

#define M_DMA_MEMSETD16	\
	_IOW(CAMBR_MM_MAGIC, _M_DMA_MEMSETD16, struct mem_bar_memsetd16_compat_s)

#define M_DMA_MEMSETD32	\
	_IOW(CAMBR_MM_MAGIC, _M_DMA_MEMSETD32, struct mem_bar_memsetd32_compat_s)

#define M_IPCM_GET_HANDLE	\
	_IOW(CAMBR_MM_MAGIC, _M_IPCM_GET_HANDLE, struct cn_ipcm_handle)

#define M_IPCM_OPEN_HANDLE	\
	_IOW(CAMBR_MM_MAGIC, _M_IPCM_OPEN_HANDLE, struct cn_ipcm_handle)

#define M_IPCM_CLOSE_HANDLE	\
	_IOW(CAMBR_MM_MAGIC, _M_IPCM_CLOSE_HANDLE, struct cn_ipcm_handle)

#define M_MDR_ALLOC				\
	_IOW(CAMBR_MM_MAGIC, _M_MDR_ALLOC, struct mem_alloc_compat_s)
#define M_ENABLE_MEMCHECK				\
	_IOW(CAMBR_MM_MAGIC, _M_ENABLE_MEMCHECK, struct cn_mem_check)
#define M_GET_MEM_RANGE				\
	_IOW(CAMBR_MM_MAGIC, _M_GET_MEM_RANGE, struct cn_get_mem_range)

#define M_MEM_BAR_COPY_H2D				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_BAR_COPY_H2D, struct mem_bar_copy_h2d_s)
#define M_MEM_BAR_COPY_D2H				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_BAR_COPY_D2H, struct mem_bar_copy_d2h_s)
#define M_MEM_GET_UVA				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_GET_UVA, struct mem_get_uva_s)
#define M_MEM_PUT_UVA				\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_PUT_UVA, struct mem_put_uva_s)
#define M_MEM_GET_IPU_RESV_MEM		\
	_IOW(CAMBR_MM_MAGIC, _M_MEM_GET_IPU_RESV_MEM, struct mem_get_ipu_resv_s)

#define M_PCIE_DOB_ALLOC		_IOW(CAMBR_MM_MAGIC, _M_PCIE_DOB_ALLOC, struct dob_alloc_t)
#define M_PCIE_DOB_FREE			_IOW(CAMBR_MM_MAGIC, _M_PCIE_DOB_FREE, struct dob_free_t)
#define M_PCIE_DOB_WRITE		_IOW(CAMBR_MM_MAGIC, _M_PCIE_DOB_WRITE, struct dob_write_t)
#define M_PCIE_DOB_READ			_IOW(CAMBR_MM_MAGIC, _M_PCIE_DOB_READ, struct dob_read_t)
#define M_PCIE_DOB_RPC_WRITE		_IOW(CAMBR_MM_MAGIC, _M_PCIE_DOB_RPC_WRITE, struct dob_write_t)
#define M_PCIE_DOB_RPC_READ		_IOW(CAMBR_MM_MAGIC, _M_PCIE_DOB_RPC_READ, struct dob_read_t)
#define M_PCIE_DOB_RPC_OPEN		_IO(CAMBR_MM_MAGIC, _M_PCIE_DOB_RPC_OPEN)
#define M_PCIE_DOB_RPC_CLOSE		_IO(CAMBR_MM_MAGIC, _M_PCIE_DOB_RPC_CLOSE)
#define M_PCIE_SRAM_RPC_WRITE		_IOW(CAMBR_MM_MAGIC, _M_PCIE_SRAM_RPC_WRITE, struct sram_write_t)
#define M_PCIE_SRAM_RPC_READ		_IOW(CAMBR_MM_MAGIC, _M_PCIE_SRAM_RPC_READ, struct sram_read_t)

#ifdef PEER_FREE_TEST
#define M_INBD_SHM_ALLOC_TEST				\
	_IOW(CAMBR_MM_MAGIC, _M_INBD_SHM_ALLOC_TEST, struct mem_alloc_compat_s)
#define M_OUTBD_SHM_ALLOC_TEST				\
	_IOW(CAMBR_MM_MAGIC, _M_OUTBD_SHM_ALLOC_TEST, struct mem_alloc_compat_s)
#define M_PEER_FREE_TEST				\
	_IOW(CAMBR_MM_MAGIC, _M_PEER_FREE_TEST, struct mem_merge_param_s)
#endif

/***************************************************** ATTR *************************************************************/

/* Never modify this struct!!! */
struct drv_capability_ioctl_cmd {
	__u64 version;
	__u64 size;
	__u64 user_cap_addr;
};

struct camb_drv_support_api_ver {
	int low_major;
	int low_minor;
	int low_build;

	int high_major;
	int high_minor;
	int high_build;
};

/**
 * Device properties
 */
typedef enum CNdevice_attribute_enum {
	/* Computing Capabilities */
	CN_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR = 0x01,                      /**< Major compute capability version number */
	CN_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR = 0x02,                      /**< Minor compute capability version number */
	CN_DEVICE_ATTRIBUTE_SPARSE_COMPUTING_SUPPORTED = 0x03,                    /**< Device supports sparse convolution or matrix multiplication by core's weight function unit */
	CN_DEVICE_ATTRIBUTE_FP16_COMPUTING_SUPPORTED = 0x04,                      /**< Device supports fp16 type computing by core's all function unit */
	CN_DEVICE_ATTRIBUTE_INT4_COMPUTING_SUPPORTED = 0x05,                      /**< Device supports int4 type convolution or matrix multiplication by core's weight function unit */
	CN_DEVICE_ATTRIBUTE_INT8_COMPUTING_SUPPORTED = 0x06,                      /**< Device supports int8 type convolution or matrix multiplication by core's weight function unit */
	CN_DEVICE_ATTRIBUTE_BF16_COMPUTING_SUPPORTED = 0x07,                      /**< Device supports bf16 type convolution or matrix multiplication by core's weight function unit */
	CN_DEVICE_ATTRIBUTE_TF32_COMPUTING_SUPPORTED = 0x08,                      /**< Device supports tf32 type convolution or matrix multiplication by core's weight function unit */
	CN_DEVICE_ATTRIBUTE_COMPUTE_MODE = 0x09,                                  /**< Device is in exclusive mode or not */

	/* Heterogeneous Capabilities */
	CN_DEVICE_ATTRIBUTE_MAX_QUEUE_COUNT = 0x101,                               /**< The maximum count of Queues that can be created on Device */
	CN_DEVICE_ATTRIBUTE_MAX_NOTIFIER_COUNT = 0x102,                            /**< The maximum count of Notifiers that can be created on Device */
	CN_DEVICE_ATTRIBUTE_QUEUE_PRIORITIES_SUPPORTED = 0x103,                    /**< The Queue priorities supported by Device */
	CN_DEVICE_ATTRIBUTE_TINY_CORE_SUPPORTED = 0x104,                           /**< Device supports using tiny core to accelerate collective communication inter-device or intra-device */
	CN_DEVICE_ATTRIBUTE_CODEC_JPEG_SUPPORTED = 0x105,                          /**< Device supports hardware jpeg codec acceleration */
	CN_DEVICE_ATTRIBUTE_CODEC_H264_SUPPORTED = 0x106,                          /**< Device supports hardware video h.264 codec acceleration */
	CN_DEVICE_ATTRIBUTE_CODEC_H265_SUPPORTED = 0x107,                          /**< Device supports hardware video h.265 codec acceleration */
	CN_DEVICE_ATTRIBUTE_AIISP_CORE_SUPPORTED = 0x108,                                /**< Device ai isp num */
	/* new notifier use */
	CN_DEVICE_ATTRIBUTE_MULTI_CTX_NOTIFIER_WAIT_SUPPORTED = 0x109,
	CN_DEVICE_ATTRIBUTE_IPCNOTIFIER_SUPPORTED = 0x10a,

	/* Elastic Capabilities */
	CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_X = 0x201,                          /**< Maximum x-dimension of a task */
	CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_Y = 0x202,                          /**< Maximum y-dimension of a task */
	CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_Z = 0x203,                          /**< Maximum z-dimension of a task */
	CN_DEVICE_ATTRIBUTE_MAX_CLUSTER_COUNT_PER_UNION_TASK = 0x204,              /**< Maximum number of clusters per union task */
	CN_DEVICE_ATTRIBUTE_MAX_CLUSTER_COUNT = 0x205,                             /**< Number of clusters on device */
	CN_DEVICE_ATTRIBUTE_MAX_CORE_COUNT_PER_CLUSTER = 0x206,                    /**< Maximum number of MLU cores per cluster */
	CN_DEVICE_ATTRIBUTE_MAX_QUADRANT_COUNT = 0x207,                            /**< Maximum count of quadrants per Device, intra-quadrant clusters have best unified memroy access performance */
	CN_DEVICE_ATTRIBUTE_MAX_UNION_TYPE_PER_QUADRANT = 0x208,                   /**< Maximum union task type that can maintain unified memory access intra-quadrant */
	/* these three is get from v2 */
	CN_DEVICE_ATTRIBUTE_MAX_CLUSTERS_PER_UNION_LIMIT_TASK = 0x209,
	CN_DEVICE_ATTRIBUTE_MLU_ISA_VERSION = 0x20a,
	CN_DEVICE_ATTRIBUTE_IS_MULTIPLE_TENSOR_PROCESSOR = 0x20b,
	/* this is by CNDrv, driver no need set currently */
	CN_DEVICE_ATTRIBUTE_IPCRESOURCE_PER_CTX = 0x20c,

	/* Memory Capacities */
	CN_DEVICE_ATTRIBUTE_MAX_L2_CACHE_SIZE = 0x301,                             /**< Size of L2 cache in bytes */
	CN_DEVICE_ATTRIBUTE_N_RAM_SIZE_PER_CORE = 0x302,					       /**< Maximum size of N-RAM available per MLU core in bytes */
	CN_DEVICE_ATTRIBUTE_WEIGHT_RAM_SIZE_PER_CORE = 0x303,                      /**< Maximum size of Weight-RAM available per MLU core in bytes */
	CN_DEVICE_ATTRIBUTE_TOTAL_CONST_MEMORY_SIZE = 0x304,                       /**< Memory available on device for __mlu_const__ variables in a BANG C kernel in megabytes */
	CN_DEVICE_ATTRIBUTE_LOCAL_MEMORY_SIZE_PER_CORE = 0x305,                    /**< Maximum size of local memory available per MLU core(i.e. __ldram__) in megabytes */
	CN_DEVICE_ATTRIBUTE_MAX_SHARED_RAM_SIZE_PER_CLUSTER = 0x306,               /**< Maximum size of shared memory per cluster(i.e. __mlu_shared__) in bytes */
	CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_NODE_COUNT = 0x307,                      /**< Number of NUMA nodes on device */
	CN_DEVICE_ATTRIBUTE_CLUSTER_L1_CACHE_SUPPORTED = 0x308,                    /**< Not supported yet */
	CN_DEVICE_ATTRIBUTE_MAX_PERSISTING_L2_CACHE_SIZE = 0x309,                  /**< Not supported yet */
	CN_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_SIZE_PER_UNION_TASK = 0x30A,         /**< Not supported yet */
	CN_DEVICE_ATTRIBUTE_VIRTUAL_ADDRESS_MANAGEMENT_SUPPORTED = 0x30B,          /**< Device supports virtual address management APIs. */
	CN_DEVICE_ATTRIBUTE_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR_SUPPORTED = 0x30C,   /**< Device supports exporting memory to a posix file descriptor. */
	CN_DEVICE_ATTRIBUTE_GENERIC_COMPRESSION_SUPPORTED = 0x30D, /**< Device supports compression of memory. */
	CN_DEVICE_ATTRIBUTE_CAN_USE_HOST_POINTER_FOR_REGISTERED_MEM =
		0x30E, /**< Device can access host registered memory at the same virtual address as the MLU Device*/
	CN_DEVICE_ATTRIBUTE_CAN_MAP_HOST_MEMORY =
		0x30F, /**< Device can map host memory into MLU address space */
	CN_DEVICE_ATTRIBUTE_LINEAR_MAPPING_SUPPORTED =
		0x310, /**< Device can map device memory into linear virtual address space. */
	CN_DEVICE_ATTRIBUTE_LINEAR_RECOMMEND_GRANULARITY =
		0x311, /**< Devcie can alloc linear memory with input size is aligned with the recommmend granularity . */

	/* Hardware Proterties */
	CN_DEVICE_ATTRIBUTE_ECC_ENABLED = 0x401,                                   /**< Device has ECC support enabled */
	CN_DEVICE_ATTRIBUTE_CLUSTER_CLOCK_RATE = 0x402,                            /**< Typical cluster clock frequency in kilohertz */
	CN_DEVICE_ATTRIBUTE_MEMORY_CLOCK_RATE = 0x403,                             /**< Peak memory clock frequency in kilohertz */
	CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_BUS_WIDTH = 0x404,                       /**< Global memory bus width in bits */
	CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_TOTAL_SIZE = 0x405,                      /**< Total global memory size in megabytes */
	CN_DEVICE_ATTRIBUTE_PCI_BUS_ID = 0x406,                                    /**< PCI bus ID of the mlu device */
	CN_DEVICE_ATTRIBUTE_PCI_DEVICE_ID = 0x407,                                 /**< PCI device ID of the mlu device */
	CN_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID = 0x408,                                 /**< PCI domain ID of the mlu device */
	CN_DEVICE_ATTRIBUTE_MDR_MEMORY_SIZE = 0x409,                               /**< MDR Memory size in megabytes. */
	CN_DEVICE_ATTRIBUTE_PCI_MPS = 0x40A,                                       /**< PCI max payload size */
	CN_DEVICE_ATTRIBUTE_PCI_MRRS = 0x40B,                                      /**< PCI max read request size */

	CN_DEVICE_ATTRIBUTE_MAX
} CNdevice_attribute;

typedef enum CNdevice_extra_attribute_enum {
	CN_DEVICE_EXTRA_ATTRIBUTE_MAX_CLUSTERS_PER_UNION_LIMIT_TASK = 0x00,              /**< Maximum number of clusters per union task */
	CN_DEVICE_EXTRA_ATTRIBUTE_MAX_QUADRANT_COUNT = 0x01,                       /**< Maximum count of quadrants per Device, intra-quadrant clusters have best unified memroy access performance */
	CN_DEVICE_EXTRA_ATTRIBUTE_MAX_UNION_TYPE_PER_QUADRANT = 0x02,              /**< Maximum union task type that can maintain unified memory access intra-quadrant */
	CN_DEVICE_EXTRA_ATTRIBUTE_MLU_ISA_VERSION = 0x03,                          /**< ISA version of current MLU device in the form of three digits number (e.g. '270' for MLU270-X5K device). */
	CN_DEVICE_EXTRA_ATTRIBUTE_IS_MULTIPLE_TENSOR_PROCESSOR = 0x4,              /**< MLU ISA version has two prefixes 'tp_xxx' and 'mtp_xxx'. 'mtp_xxx' architecture contains at least one cluster, so ``cnDeviceGetAttribute()`` return '1' if current MLU device is multi-tensor-processor architecture. */
	CN_DEVICE_EXTRA_ATTRIBUTE_AIISP_CORE_COUNT = 0x05,
	CN_DEVICE_EXTRA_ATTRIBUTE_MAX
} CNdevice_extra_attribute;

/* ioctl communication header */
struct cndrv_cmd_header {
	__u32 version;
	__u32 msg_size;		/* which size not include cmd_header */
	__u32 out_buffer_size;
	void *out_buffer;
};

/* for cndrv version check */
struct cndrv_version_st {
	int major;
	int minor;
	int patch;
};

/**
 * struct of ioctl cmd: CAMB_GET_DRIVER_INFO.
 * input: struct driver_info_ioctl_st
 * output: struct driver_info_st
 */
#define CN_DEVICE_MAX_COUNT	128
#define CN_DEV_MAX_INSTANCE_COUNT	64
struct driver_info_st {
	struct cndrv_version_st curr_ver;
	struct cndrv_version_st low_ver;
	struct cndrv_version_st high_ver;
	__u64 drv_global_seq_num;
	__u32 vendor_id;
	__u32 ipcm_num;
	__u32 device_num; /* physical device number, consist of FULL, MIM_EN, SMLU */
	__u64 dev_unique_id[CN_DEVICE_MAX_COUNT]; /* never be zero! */
};

struct driver_info_ioctl_st {
	struct cndrv_cmd_header cmd_header;
	__u32 dev_max_count;
	__u32 ipcm_max_count;
};

/**
 * Ioctl for get each device info.
 * reused by MI or CI or SMLU.
 * input: struct device_info_ioctl_st
 * output: struct device_basic_info_st
 */
struct device_basic_info_st {
	__u32 device_type;           /* enum device_work_type */
	__u32 project_id;            /* C50_PROJ/... */
	__u32 index;                 /* device index in driver: core->idx */
	__u32 instance_id;   	     /* instance id begin with 1 */
	__u64 ipcm_unique_id;        /* 0 with instance */
	__u32 sub_dev_num;           /* MI number or smlu number or CI number */
	__u64 sub_dev_unique_id[CN_DEV_MAX_INSTANCE_COUNT];
	__u32 device_handle;         /* (pf_card & 0xff) | ((vf_card & 0xff) << 8), same with cnmon */
};

struct device_info_ioctl_st {
	struct cndrv_cmd_header cmd_header;
	 /* max number of this device, same with length of
	  * sub_dev_unique_id[CN_DEV_MAX_INSTANCE_COUNT] */
	 __u32 mi_max_num;
	 /* device id which is come from dev_unique_id[] of
	  * struct driver_info_st */
	 __u64 dev_unique_id;
};

enum attr_nr_type {
	_CAMB_GET_API_GLOBAL_SEQ_NR = 10,
	_CAMB_GET_DRIVER_INFO_NR,
	_CAMB_GET_DEVICE_INFO_NR,
	_CAMB_RD_DRIVER_VERSION_NR = 38,
	_CAMB_GET_DEVICE_ATTR_V1_NR = 46,
	_CAMB_GET_DEVICE_ATTR_NR,
	_CAMB_GET_DEVICE_PRIVATE_ATTR_NR,
	_CAMB_GET_MLU_ID_NR = 51,
	_CAMB_GET_DEVICE_NAME_NR,
	_CAMB_GET_API_LIMIT_VER_NR,
	_CAMB_DRIVER_CAPABILITY_NR,
	_CAMB_GET_DEVICE_WORK_MODE_NR,
	_CAMB_GET_DEVICE_UNIQUE_ID_NR,
	_ATTR_MAX_NR_COUNT,
};
#define ATTR_MAX_NR_COUNT	57

#define CAMB_GET_API_GLOBAL_SEQ 	_IOWR(CAMBRICON_MAGIC_NUM, _CAMB_GET_API_GLOBAL_SEQ_NR, __u64)
#define CAMB_GET_DRIVER_INFO		_IOWR(CAMBRICON_MAGIC_NUM, _CAMB_GET_DRIVER_INFO_NR, struct driver_info_ioctl_st)
#define CAMB_GET_DEVICE_INFO		_IOWR(CAMBRICON_MAGIC_NUM, _CAMB_GET_DEVICE_INFO_NR, struct device_info_ioctl_st)

#define CAMB_RD_DRIVER_VERSION	_IOR(CAMBRICON_MAGIC_NUM, _CAMB_RD_DRIVER_VERSION_NR, unsigned int[DRV_SERIAL_NUM_LEN])
#define CAMB_GET_DEVICE_ATTR_V1 _IOWR(CAMBRICON_MAGIC_NUM, _CAMB_GET_DEVICE_ATTR_V1_NR, struct c20_device_attr)
#define CAMB_GET_DEVICE_ATTR _IOWR(CAMBRICON_MAGIC_NUM, _CAMB_GET_DEVICE_ATTR_NR, struct c20_device_attr)
#define CAMB_GET_DEVICE_PRIVATE_ATTR _IOWR(CAMBRICON_MAGIC_NUM, _CAMB_GET_DEVICE_PRIVATE_ATTR_NR, struct c20_device_attr)
#define CAMB_GET_MLU_ID _IOWR(CAMBRICON_MAGIC_NUM, _CAMB_GET_MLU_ID_NR, int)
#define CAMB_GET_DEVICE_NAME _IOWR(CAMBRICON_MAGIC_NUM, _CAMB_GET_DEVICE_NAME_NR, unsigned char[BOARD_MODEL_NAME_LEN])
#define CAMB_GET_API_LIMIT_VER _IOWR(CAMBRICON_MAGIC_NUM, _CAMB_GET_API_LIMIT_VER_NR, struct camb_drv_support_api_ver)
#define CAMB_DRIVER_CAPABILITY	_IOWR(CAMBRICON_MAGIC_NUM, _CAMB_DRIVER_CAPABILITY_NR, struct drv_capability_ioctl_cmd)
#define CAMB_GET_DEVICE_WORK_MODE _IOWR(CAMBRICON_MAGIC_NUM, _CAMB_GET_DEVICE_WORK_MODE_NR, enum core_work_mode)
#define CAMB_GET_DEVICE_UNIQUE_ID _IOR(CAMBRICON_MAGIC_NUM, _CAMB_GET_DEVICE_UNIQUE_ID_NR, uint64_t)

#ifndef SBTS_VERSION
#define SBTS_VERSION                    (1U)
#endif
#define SBTS_VERSION_AF                 (2U)
#define SBTS_VERSION_FETCH              (3U)
#define SBTS_VERSION_C20_PARAM_SIZE     (4U)
/* c30 first kernel hdr version */
#define SBTS_VERSION_C30_1              (0x10U)
#define SBTS_VERSION_C30_PARAM_SIZE     (0x20U)
#define SBTS_VERSION_TCDP               (0x30U)
/* sbts func task version */
#define SBTS_VERSION_FUNC_TASK          (0xffU)

#define HOST_BASE_VERSION               (0U)
#define HOST_CURRENT_VERSION            (2U)    /* it will change with version */
#define HOST_VERSION(num)               ((__u64)(HOST_BASE_VERSION + num))
#define VERSION_MASK                    (0xffffffffULL)
#define SET_VERSION(host_ver, sbts_ver) (((__u64)(host_ver) << 32) | (sbts_ver))
#define GET_SBTS_VERSION(ver)		    ((__u64)(ver) & VERSION_MASK)
#define GET_HOST_VERSION(ver)           (((__u64)(ver) & ~VERSION_MASK) >> 32)

struct sbts_create_queue {
	__u64 version;
	__u64 hqueue;
	__u64 dump_uvaddr;              /* reuse by ack_uvaddr */
	__u32 flags;
	__u32 priority;
};

struct sbts_destroy_queue {
	__u64 version;
	__u64 hqueue;
};


/* core dump */
struct sbts_queue_dump {
	__u64 version;
	__u64 hqueue;
};

enum core_dump_ack_type {
	CORE_DUMP_DMA,
	CORE_DUMP_WAIT_FINISH,
	CORE_DUMP_ERROR,
	CORE_DUMP_ACK_NUM,
};

struct sbts_queue_dump_ack {
	__u64 version;
	__u64 type;
	__u64 hqueue;
	__u64 host_addr;
	__u64 device_addr;
	__u64 size;
	__u64 dump_id;
	__u64 seq_id;
};

/* notifier */
struct sbts_create_notifier {
	__u64 version;
	__u64 hnotifier;
	__u32 flags;
};

struct sbts_destroy_notifier {
	__u64 version;
	__u64 hnotifier;
};

struct sbts_wait_notifier {
	__u64 version;
	__u64 hnotifier;
};

struct sbts_query_notifier {
	__u64 version;
	__u64 hnotifier;
};

struct sbts_notifier_elapsed_time {
	__u64 version;
	__u64 tv_sec;    /* seconds */
	__u64 tv_usec;   /* microseconds */
	__u64 hstart;
	__u64 hend;
};

/* same as api use */
#define SBTS_NOTIFIER_IPC_HANDLE_NUM 4
struct sbts_ipc_notifier {
	__u64 version;
	__u64 hnotifier;
	__u64 ipchandle[SBTS_NOTIFIER_IPC_HANDLE_NUM];
};

struct sbts_task_topo_cmd {
	__u64 version;
	/* enum task_topo_cmd_type */
	__u64 cmd_type;
	/* reserved for context */
	__u64 ctx_id;
	/* drv create topo id */
	__u64 dev_topo_id;
	/* addr with inner queue struct */
	__u64 param_addr;
	/* inner queue nums */
	__u32 param_nums;
	__u32 reserved;
	/* topo total node numbers */
	__u64 node_nums;
	/* leader inner queue id */
	__u64 leader_hqueue;
};

struct sbts_query_queue {
	__u64 version;
	__u64 hqueue;
};

struct sbts_multi_queue_sync {
	__u64 version;
	__u64 except_queue;
};


enum debug_ctrl_cmd_type {
	DEBUG_CTRL_GET_MGR,
	DEBUG_CTRL_PUT_MGR,
	DEBUG_CTRL_REGISTER,
	DEBUG_CTRL_UNREGISTER,
	DEBUG_CTRL_UPDATE,
	DEBUG_CTRL_CMD_NUM,
};

struct debug_ctrl_get_mgr {
	/* output val */
	__u32 version;

	__u32 core_ver;
	__u32 core_num;
	__u32 each_size;
	__u64 core_map_addr;

	__u32 task_ver;
	__u32 task_size;
	__u64 task_map_addr;
};

struct debug_ctrl_update {
	__u32 head;
};

struct sbts_debug_ctrl {
	__u64 version;
	__u32 pid;
	__u32 type;
	union {
		struct debug_ctrl_get_mgr get;
		struct debug_ctrl_update update;
	};
};

/* should match with cndrv and device */
enum hw_cfg_hdl_type {
	ICACHE_MISS_FETCH_INSTNUM_GET = 0,
	ICACHE_MISS_FETCH_INSTNUM_SET,
	TNC_WATCHDOG_TIMER_GET,
	TNC_WATCHDOG_TIMER_SET,
	CACC_SET_ENABLE,
	CACC_SET_BYPASS,
	CACC_GET_ENABLE,
	CACC_GET_BYPASS,
	IPC_CFG_COMPRESS_ENABLE,
	IPC_CFG_COMPRESS_DISABLE,
	HW_CFG_HDL_TYPE_NUM,
};

struct sbts_hw_cfg_hdl {
	__u64 version;
	__u32 type;
	union {
		__u32 val;
	};
};

struct sbts_ctrl_task {
	__u64 version;
	__u64 type;
	__u64 rx_size;
	__u64 rx;
	__u64 priv_size;
	__u64 priv;
};

struct sbts_push_task {
	__u64 version;
	__u64 hqueue;
	__u64 hnotifier;
	__u64 priv_size;
	__u64 priv;
	__u64 param_size;
	__u64 params;
	__u64 extra_size;
	__u64 extra;
};

enum hostFn_ioctl_state {
	HOSTFN_LAUNCH = 1,
	HOSTFN_FINISH,
};

/* ********** ncs *********** */
struct ncs_comm_ctrl {
	__u32 version;
	__u32 ret_code;
	__u64 params;
	__u32 param_size;
	__u32 type;
	/* note : do not resize */
	__u64 data[11];
};

struct tcdp_comm_ctrl {
	__u32 version;
	__u32 ret_code;
	__u32 type;
	__u32 size;
	__u64 extern_data;
	/* note : do not resize */
	__u64 data[11];
};

struct sbts_place_idc {
	__u64 version;
	__u64 hqueue;
	__u64 host_addr;
	__u64 val;
	__u64 type;
	__u64 flag;
	/* out val */
	__u64 status;
	__u64 ticket;
};

struct sbts_get_hw_info {
	__u64 version;
	__u64 addr;
	__u64 size;
};

struct sbts_kernel {
	__u64 version;
	__u64 priv_size;
	__u64 priv;
	__u64 param_size;
	__u64 params;
};

struct sbts_notifier {
	__u64 version;
	__u64 hnotifier;
};

struct sbts_notifier_extra {
	__u64 version;
	__u64 hnotifier;
	__u64 fd;
};

struct sbts_idc {
	__u64 version;
	__u64 host_addr;
	__u64 val;
	__u64 type;
	__u64 flag;
	/* out val */
	__u64 status;
	__u64 ticket;
};

struct sbts_hostfn {
	__u64 version;
	__u64 hqueue;
	__u64 hf_status;
	__u64 seq;
	__u64 host_get_trigger_ns;
	__u64 hostfn_start_ns;
	__u64 hostfn_end_ns;
	__u64 extra_ptr;
	__u64 extra_size;
	__u64 reserve[7];
};

struct sbts_dma_async {
	__u64 version;
	__u64 dir;
	__u64 is_udvm_support;
	union {
		struct {
			__u64 src_addr;
			__u64 dst_addr;
			__u64 size;
			union {
				/* for udvm */
				__u64 udvm_fd;
				/* for mlu200 */
				struct {
					__u64 src_fd;
					__u64 dst_fd;
				} mem;
			};
		} memcpy;

		struct {
			__u64 fd;
			__u64 dev_addr;
			__u64 per_size;
			__u64 number;
			__u64 val;
		} memset;
	};
};

struct sbts_dma_priv {
	__u64 dir;
	union {
		struct {
			__u64 src_bus_set;
			__u64 src_pminfo;
			__u64 dst_bus_set;
			__u64 dst_pminfo;
		} memcpy;

		struct {
			__u64 bus_set;
			__u64 pminfo;
		} memset;
	};
};

struct sbts_dbg_kernel {
	__u64 version;
	__u64 priv_size;
	__u64 priv;
	__u64 param_size;
	__u64 params;
	__u64 ack_buffer;
	__u64 ack_buffer_size;
};

struct sbts_jpu_async {
	__u64 version;
	__u32 type;
	__u32 is_batch_head;
	__u64 dataq_addr;
	__u32 dataq_size;
	__u32 dataq_seg_size[4];
	__u64 cb_func;
	__u32 block_id;
	__u64 buf_hdl;
	__u64 efd_queue_sid;
	__u32 reserved[8];
};

struct sbts_topo_notifier {
	__u64 version;
	__u64 hnotifier;
	/* for extra */
	__u64 fd;
	/* usr / api */
	__u64 type;
	__u64 place_total;
	__u64 qtask_total;
};

/* param invoke_queue_type in sbts_topo_invoke */
enum sbts_topo_invoke_queue_type {
	SBTS_TOPO_INVOKE_IN_LEADER_QUEUE = 0,
	SBTS_TOPO_INVOKE_IN_USER_QUEUE = 1,
	SBTS_TOPO_INVOKE_IN_USER_QUEUE_NUM,
};

struct sbts_topo_invoke {
	__u64 invoke_queue_type;
};

enum sbts_task_type {
	SBTS_QUEUE_KERNEL = 0,
	SBTS_QUEUE_NOTIFIER_PLACE,
	SBTS_QUEUE_NOTIFIER_WAIT,
	SBTS_QUEUE_IDC_PLACE,
	SBTS_QUEUE_HOSTFN_INVOKE,
	SBTS_QUEUE_NCS_KERNEL,
	SBTS_QUEUE_DMA_ASYNC,
	SBTS_QUEUE_DBG_KERNEL,
	SBTS_QUEUE_DBG_TASK,
	SBTS_QUEUE_SYNC_TASK,
	SBTS_QUEUE_TCDP_TASK,
	SBTS_QUEUE_TCDP_DBG_TASK,
	SBTS_QUEUE_NOTIFIER_WAIT_EXTRA,
	SBTS_QUEUE_JPU_TASK,
	SBTS_QUEUE_TOPO_INVOKE,
	SBTS_QUEUE_TASK_TYPE_NUM,
};

#define MAX_PRIV_NUM (20)
union sbts_task_priv_data {
	struct sbts_kernel kernel;
	struct sbts_notifier notifier;
	struct sbts_idc idc;
	struct sbts_hostfn hostfn;
	struct sbts_dma_async dma_async;
	struct sbts_dbg_kernel dbg_kernel;
	struct sbts_notifier_extra notifier_extra;
	struct sbts_jpu_async jpu_async;
	struct sbts_topo_notifier topo_notifier;
	struct sbts_topo_invoke topo_invoke;
	__u64 sbts_task_max_priv[MAX_PRIV_NUM];
};

enum dev_topo_task_cmd {
	DEV_TOPO_TASK_TYPE_NORMAL = 0,
	DEV_TOPO_TASK_TYPE_CREATE = 1,
	DEV_TOPO_TASK_TYPE_PARAM = 2,
	DEV_TOPO_TASK_TYPE_INVOKE = 3,
	DEV_TOPO_TASK_TYPE_NUM,
};

#define SBTS_QUEUE_INVOKE_COMM_RES (5)
struct sbts_queue_invoke_task {
	__u64 version;
	__u64 hqueue;
	__u64 correlation_id;
	__u16 task_type;
	__u16 dev_topo_cmd;
	__u32 perf_disable;
	__u64 topo_info;
	__u64 dev_topo_id;
	__u32 dev_topo_node_index;
	__u32 reserve;
	__u64 res[SBTS_QUEUE_INVOKE_COMM_RES];
	union sbts_task_priv_data priv_data __attribute__((aligned(8)));
} __packed;

enum sbts_cmd_type {
	_SBTS_CREATE_QUEUE = 0,
	_SBTS_DESTROY_QUEUE,
	_SBTS_INVOKE_KERNEL, /* deprecated */
	_SBTS_QUEUE_SYNC, /* deprecated */
	_SBTS_CORE_DUMP,
	_SBTS_NOTIFIER_CREATE,
	_SBTS_NOTIFIER_DESTROY,
	_SBTS_NOTIFIER_PLACE, /* deprecated */
	_SBTS_NOTIFIER_WAIT,
	_SBTS_NOTIFIER_QUERY,
	_SBTS_NOTIFIER_ELAPSED_TIME,
	_SBTS_NOTIFIER_QUEUE_WAIT, /* deprecated */
	_SBTS_QUEUE_QUERY,
	_SBTS_SET_LOCAL_MEM, /* deprecated */
	_SBTS_GET_LOCAL_MEM, /* deprecated */
	_SBTS_INVOKE_KERNEL_DEBUG, /* deprecated */
	_SBTS_INVOKE_CNGDB_TASK,
	_SBTS_INVOKE_TOPO_ENTITY, /* deprecated */
	_SBTS_NCS_COMM_CMD,
	_SBTS_NCS_INVOKE_KERNEL, /* deprecated */
	_SBTS_TCDP_COMM_CMD,
	_SBTS_INVOKE_TCDP, /* deprecated */
	_SBTS_RESERVE2,
	_SBTS_RESERVE3,
	_SBTS_RESERVE4,
	_SBTS_RESERVE5,
	_SBTS_RESERVE6,
	_SBTS_RESERVE7,
	_SBTS_IDC_PLACE_TASK, /* deprecated */
	_SBTS_GET_HW_INFO,
	_SBTS_NOTIFIER_ELAPSED_SW_TIME,
	_SBTS_GET_UNOTIFY_INFO,
	_SBTS_SET_UNOTIFY_FD,
	_SBTS_DEBUG_TASK, /* deprecated */
	_SBTS_DEBUG_CTRL,
	_SBTS_HW_CFG_HDL,
	_SBTS_CORE_DUMP_ACK,
	_SBTS_INVOKE_HOST_FUNC, /* deprecated */
	_SBTS_QUEUE_INVOKE_TASK,
	_SBTS_NOTIFIER_IPC_GETHANDLE,
	_SBTS_NOTIFIER_IPC_OPENHANDLE,
	_SBTS_MULTI_QUEUE_SYNC,
	_SBTS_TASK_TOPO_CTRL,
	_SBTS_CMD_NUM,
};

/**
 * Declaration of sbts module
 */

#define SBTS_CREATE_QUEUE		\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_CREATE_QUEUE,	\
		struct sbts_create_queue)
#define SBTS_DESTROY_QUEUE		\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_DESTROY_QUEUE,	\
		struct sbts_destroy_queue)
#define SBTS_QUEUE_INVOKE_TASK	\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_QUEUE_INVOKE_TASK,	\
		struct sbts_queue_invoke_task)
#define SBTS_CORE_DUMP			\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_CORE_DUMP,	\
		struct sbts_queue_dump)

#define SBTS_NOTIFIER_CREATE		\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_NOTIFIER_CREATE,		\
		struct sbts_create_notifier)
#define SBTS_NOTIFIER_DESTROY		\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_NOTIFIER_DESTROY,	\
		struct sbts_destroy_notifier)
#define SBTS_NOTIFIER_WAIT			\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_NOTIFIER_WAIT,		\
		struct sbts_wait_notifier)
#define SBTS_NOTIFIER_QUERY		\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_NOTIFIER_QUERY,		\
		struct sbts_query_notifier)
#define SBTS_NOTIFIER_ELAPSED_TIME	\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_NOTIFIER_ELAPSED_TIME,\
		struct sbts_notifier_elapsed_time)

#define SBTS_INVOKE_CNGDB_TASK			\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_INVOKE_CNGDB_TASK,	\
		struct sbts_ctrl_task)

#define SBTS_NCS_COMM_CMD		\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_NCS_COMM_CMD,		\
		struct sbts_push_task)

#define SBTS_TCDP_COMM_CMD		\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_TCDP_COMM_CMD,		\
		struct tcdp_comm_ctrl)

#define SBTS_GET_HW_INFO			\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_GET_HW_INFO,			\
		struct sbts_get_hw_info)

#define SBTS_NOTIFIER_ELAPSED_SW_TIME	\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_NOTIFIER_ELAPSED_SW_TIME,\
		struct sbts_notifier_elapsed_time)

#define SBTS_GET_UNOTIFY_INFO			\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_GET_UNOTIFY_INFO,		\
		struct sbts_efd_head)

#define SBTS_SET_UNOTIFY_FD			\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_SET_UNOTIFY_FD,		\
		__u32)

#define SBTS_DEBUG_CTRL			\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_DEBUG_CTRL,		\
		struct sbts_debug_ctrl)

#define SBTS_HW_CFG_HDL			\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_HW_CFG_HDL,		\
		struct sbts_hw_cfg_hdl)

#define SBTS_CORE_DUMP_ACK			\
		_IOW(CAMBR_SBTS_MAGIC,	\
		_SBTS_CORE_DUMP_ACK,	\
		struct sbts_queue_dump_ack)

#define SBTS_NOTIFIER_IPC_GETHANDLE		\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_NOTIFIER_IPC_GETHANDLE,	\
		struct sbts_ipc_notifier)

#define SBTS_NOTIFIER_IPC_OPENHANDLE		\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_NOTIFIER_IPC_OPENHANDLE,	\
		struct sbts_ipc_notifier)

#define SBTS_MULTI_QUEUE_SYNC		\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_MULTI_QUEUE_SYNC,	\
		struct sbts_multi_queue_sync)

#define SBTS_TASK_TOPO_CTRL			\
		_IOW(CAMBR_SBTS_MAGIC,		\
		_SBTS_TASK_TOPO_CTRL,	\
		struct sbts_task_topo_cmd)

/**
 * Declaration of exception management module
 */

enum expmnt_nr_type {
	_HB_PICK_ALL = 1,
	_HB_GET_ONE,
	_EXPMNT_MAX_NR_COUNT,
};

#define EXPMNT_MAX_NR_COUNT	3

#define CMD_PICK_ALL _IOW(CAMBR_HB_MAGIC, _HB_PICK_ALL, struct DistributeMap)

#define CMD_GET_ONE  _IOW(CAMBR_HB_MAGIC, _HB_GET_ONE, struct ErrState)


/**
 * Declaration of I2C module
 */
#define CAMBR_I2C_MAGIC    'I'

enum i2c_nr_type {
	_I2C_CONFIG_SPEED = 1,
	_I2C_READ,
	_I2C_WRITE,
	_I2C_MAX_NR_COUNT,
};

#define I2C_MAX_NR_COUNT	4

#define I2C_CONFIG_SPEED	\
	_IOW(CAMBR_I2C_MAGIC, _I2C_CONFIG_SPEED, enum i2c_speed)
#define I2C_READ			\
	_IOW(CAMBR_I2C_MAGIC, _I2C_READ, struct cn_i2c_msg)
#define I2C_WRITE			\
	_IOW(CAMBR_I2C_MAGIC, _I2C_WRITE, struct cn_i2c_msg)


/* -------------- migrate ---------------- */
enum mig_op_sts_e {
	MIG_STS_PREPARE = 0,
	MIG_STS_START,
	MIG_STS_FAIL,
	MIG_STS_FINISH,
};

enum mig_op_dir_e {
	MIG_DIR_SRC = 0,
	MIG_DIR_DST,
};

enum mig_op_type_e {
	MIG_TYPE_STS = 0,
	MIG_TYPE_CFG,
	MIG_TYPE_DATA,
	MIG_TYPE_DEBUG_DMA,
	MIG_TYPE_DEBUG_DMA_CFG,
	MIG_TYPE_CNT
};

#define CN_MIG_DATA_EOF_BIT         (0x01)

#define PF_MIG_STAT_BUSY  0x1
#define PF_MIG_STAT_READY 0x2
#define PF_MIG_STAT_FAIL  0x3

#pragma pack(1)

struct mig_op_t {
	__s32  type;        /* MIG_TYPE_STS/MIG_TYPE_CFG/MIG_TYPE_DATA */
	__s32  vf;          /* 0/1/2/3 */
	__s32  dir;         /* MIG_DIR_SRC/MIG_DIR_DST */
};

struct mig_op_status_t {
	__s32  type;        /* MIG_TYPE_STS/MIG_TYPE_CFG/MIG_TYPE_DATA */
	__s32  vf;		    /* 0/1/2/3 */
	__s32  dir;         /* MIG_DIR_SRC/MIG_DIR_DST */
	__s32  sts;         /* mig_op_sts_e */
	__u32  cmd_data[4];
};

struct mig_op_cfg_t {
	__s32  type;        /* MIG_TYPE_STS/MIG_TYPE_CFG/MIG_TYPE_DATA */
	__s32  vf;		   /* 0/1/2/3 */
	__s32  dir;         /* MIG_DIR_SRC/MIG_DIR_DST */
	__u64  ca;      /* cpu address */
	__u64  len;
	__u64  ret_len; /* not used in restore data */
};

struct mig_op_data_t {
	__s32  type;        /* MIG_TYPE_STS/MIG_TYPE_CFG/MIG_TYPE_DATA */
	__s32  vf;		   /* 0/1/2/3 */
	__s32  dir;         /* MIG_DIR_SRC/MIG_DIR_DST */
	__u64  ca;         /* cpu address */
	__u64  len;
	__u64  ret_len;    /* not used in restore data */
	__u32  flag;
	__u32  data_category;  /* sbts/vpu/jpu/mem/... */
};

struct mig_op_debug_dma_t {
	__s32  type;        /* MIG_TYPE_STS/MIG_TYPE_CFG/MIG_TYPE_DATA */
	__s32  vf;          /* Not used */
	__s32  dir;         /* Not used */
	__u64  ca;          /* cpu address */
	__u64  ia;          /* ipu address */
	__u32  total_size;
	__u32  residual_size;
};

struct mig_op_debug_dma_cfg_t {
	__s32  type; /* MIG_TYPE_STS/MIG_TYPE_CFG/MIG_TYPE_DATA */
	__s32  vf;	/* Not used */
	__s32  dir; /* Not used */
	__u64  ca; /* cpu address */
	__u64  ia; /* ipu address */
	__u32  total_size;
	__u32  residual_size;
	__u32  dma_mask;  /* dma used mask */
	__u32  phy_mode;  /* 1 means phy mode */
};

struct mig_proto_cfg_pay_t {
	__u32 domain;
	__u32 chipset_model;
	__u32 board_ver;
	__u32 mcu_ver;
	__u32 firmware_ver;
	__u32 host_drv_ver;
	__u32 guest_drv_ver;
	__u32 cahce_size;
	__u32 reserved0;
	__u8  ipu_cfg[16];
	__u8  mem_cfg[16];
	__u8  vpu_cfg[16];
	__u8  jpu_cfg[16];
	__u8  pci_cfg[16];
	__u8  reserved1[16];
};


#define _MIG_OP_GET                  1
#define _MIG_OP_SET                  2

#define MIG_OP_GET                          \
		_IOWR(CAMBR_MIGRATION_MAGIC, _MIG_OP_GET, struct mig_op_t)

#define MIG_OP_SET                          \
		_IOWR(CAMBR_MIGRATION_MAGIC, _MIG_OP_SET, struct mig_op_t)

#pragma pack()

#if defined(__cplusplus)
}
#endif

#endif /*_sbts_IOCTL_H_*/


