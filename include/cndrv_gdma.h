#ifndef __CNDRV_GDMA_H__
#define __CNDRV_GDMA_H__
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/delay.h>

#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_core.h"
#include "cndrv_debug.h"

#define MEMCPY_D2D_NO_COMPRESS (0xf)

enum gdma_assist_id_t {
    GDMA_ASSIST_SET = 0x10000,
    GDMA_ASSIST_SET_DEBUG_PRINT = (GDMA_ASSIST_SET + 0x1),
    GDMA_ASSIST_SET_INJECT_ERROR_SRC = (GDMA_ASSIST_SET + 0x2),
    GDMA_ASSIST_SET_INJECT_ECC_ERROR = (GDMA_ASSIST_SET + 0x3),
    GDMA_ASSIST_SET_POLL_SIZE = (GDMA_ASSIST_SET + 0x4),

    GDMA_ASSIST_GET = 0x20000,
    GDMA_ASSIST_GET_DEBUG_PRINT = (GDMA_ASSIST_GET + 0x1),
    GDMA_ASSIST_GET_INJECT_ERROR_SRC = (GDMA_ASSIST_GET + 0x2),
    GDMA_ASSIST_GET_INJECT_ECC_ERROR = (GDMA_ASSIST_GET + 0x3),
    GDMA_ASSIST_GET_POLL_SIZE = (GDMA_ASSIST_GET + 0x4),
    GDMA_ASSIST_GET_INFO_CTRL_NUM = (GDMA_ASSIST_GET + 0x5),
    GDMA_ASSIST_GET_INFO_CTRL_CHAN_NUM = (GDMA_ASSIST_GET + 0x6),
    GDMA_ASSIST_GET_STAT_INFO = (GDMA_ASSIST_GET + 0x7),

    GDMA_ASSIST_ACT = 0x30000,
    GDMA_ASSIST_ACT_CHNL_ECC_INJECT = (GDMA_ASSIST_ACT + 0x3),
    GDMA_ASSIST_ACT_CTRL_REG_DUMP = (GDMA_ASSIST_ACT + 0x4),
    GDMA_ASSIST_ACT_CHNL_REG_DUMP = (GDMA_ASSIST_ACT + 0x5),
};

enum ce_memd2d_type_t {
	CE_MEMCPY_1D = 0,
	CE_MEMCPY_2D,
	CE_MEMCPY_3D,
	CE_MEMSET_D8,
	CE_MEMSET_D16,
	CE_MEMSET_D32,
	CE_MEMSET_D64,
};

struct memcpy_d2d_2d {
	u64 spitch;
	u64 dpitch;
	u64 width;
	u64 height;
};

struct memcpy_d2d_3d_pos {
	u64 x;
	/*!< The offset in the x direction.*/
	u64 y;
	/*!< The offset in the y direction.*/
	u64 z;
	/*!< The offset in the z direction.*/
};

struct memcpy_d2d_3d_pitch {
	u64 pitch;
	/*!< The pitch of the memory.*/
	void * ptr;
	/*!< The pointer of the memory.*/
	u64 xsize;
	/*!< The memory x size.*/
	u64 ysize;
	/*!< The memory y size.*/
};

struct memcpy_d2d_3d_extent {
	u64 depth;
	/*!< The depth of the memory.*/
	u64 height;
	/*!< The height of the memory.*/
	u64 width;
	/*!< The width of the memory.*/
};

struct memcpy_d2d_3d_compat {
	u64 dst;
	struct memcpy_d2d_3d_pos dst_pos;
	struct memcpy_d2d_3d_pitch dst_ptr;
	struct memcpy_d2d_3d_extent extent;
	u64 src;
	struct memcpy_d2d_3d_pos src_pos;
	struct memcpy_d2d_3d_pitch src_ptr;
};

struct memcpy_d2d_in {
	u64 src;
	u64 dst;
	ssize_t size;
	void *task_addr;
	u64 memset_val;
	enum ce_memd2d_type_t memd2d_type;
	struct memcpy_d2d_2d d2d_2d;
	struct memcpy_d2d_3d_compat d2d_3d;
	int compress_type;
};

struct memcpy_d2d_out {
	u64 addr;
	void *task_addr;
	int ret;
};

int cn_gdma_late_init(struct cn_core_set *core);
void cn_gdma_late_exit(struct cn_core_set *core);

int cn_gdma_able(struct cn_core_set *core);
int cn_gdma_memcpy_sync(struct cn_core_set *core,
					u64 src_vaddr,
					u64 dst_vaddr,
					ssize_t size,
					int compress_type);
int cn_gdma_memset_sync(struct cn_core_set *core,
					struct memset_s *t);
int cn_gdma_memcpy_2d_sync(struct cn_core_set *core,
						u64 src_vaddr,
						u64 dst_vaddr,
						ssize_t spitch,
						ssize_t dpitch,
						ssize_t width,
						ssize_t height);
int cn_gdma_memcpy_3d_sync(struct cn_core_set *core,
						struct memcpy_d2d_3d_compat *p);

int cn_mem_copy_d2d_2d(u64 tag,
					dev_addr_t dst_vaddr,
					ssize_t dpitch,
					dev_addr_t src_vaddr,
					ssize_t spitch,
					ssize_t width,
					ssize_t height,
					void *mem_set);
int cn_mem_copy_d2d_3d(u64 tag,
					struct memcpy_d2d_3d_compat *p,
					void *mem_set);

int cn_gdma_assist(struct cn_core_set *core, int assist_id, void *param_in, void *result_out);

#endif
