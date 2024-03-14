/************************************************************************
 *  @file cndrv_mig_internal.h
 *
 *  @brief For live migration support definitions.
 **************************************************************************/

/*************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
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
 ***************************************************************************/

#ifndef __CNDRV_MGR_INTERNAL_H
#define __CNDRV_MGR_INTERNAL_H

#include "cndrv_mig.h"

enum mig_mem_type_e {
	MIG_MEM_NORMAL = 0,
	MIG_MEM_SGL,
};

enum mig_state_e {
	MIG_STATE_IDLE = 0,
	MIG_STATE_PREPARE,
	MIG_STATE_READY,
	MIG_STATE_TRANSFER,
	MIG_STATE_TRANSFER_DONE,
	MIG_STATE_ERROR,
	MIG_STATE_CANCEL_INPROG,   /* Cancel inprogress */
	MIG_STATE_CANCEL_FAIL,     /* Cancel failure */
	MIG_STATE_CANCEL_DONE      /* Cancel done */
};

/**
 * ------------------------------------------------------------------------
 * Bit[31] | Bit[30:24]   | Bit[23:16] | Bit[15]        | Bit[14:10]
 * Status  | Global state | Module ID  | Device or Host | VF ID
 * | Bit[9:0]
 * | Error number/Execute status
 * ------------------------------------------------------------------------
 * Bit[31]    Status: if execute report an error
 *                1 execute report an error, Bit[9:0] contain Error Number
 *                0 execute report execute status, Bit[9:0] contain Execute status
 * Bit[30:24] Global state: current migrating status,
 *                likes save_prepare/resume_prepare/suspend/resume/
 *                save_complete/restore_complete
 * Bit[23:16] Module ID: indicate module id, likes sbts/mem/pci.
 *                but, for now, global module id is not definitely confirm.
 * Bit[15]    Device or Host: indicate this error code is from device or host
 *                1 host
 *                0 device
 * Bit[14:10] VF ID: indicat vf id
 * Bit[9:0]   Error number/Execute status:
 *                if Bit[31] is 0, this bit segment means execute staus,
 *                if Bit[31] is 1, this bit segment means error number.
 *                as for execute status, it may means job is done/working and so on,
 *                details defined by various modules.
 *                as for error number, the meanings of number is defined by various
 *                modules
 */
#define MIG_STATUS_ERROR (0x80000000)
#define mig_is_status_err(ret) (ret & MIG_STATUS_ERROR)
#define mig_set_status_err(ret) (ret | MIG_STATUS_ERROR)
#define mig_set_status_ok(ret) (ret & (~MIG_STATUS_ERROR))

#define MIG_GLOBAL_STATE_OFFSET 0x18
#define MIG_GLOBAL_STATE_HOLD_BITS 0x7
#define MIG_MODULEID_OFFSET 0x10
#define MIG_MODULEID_HOLD_BITS 0x8
#define MIG_DEVICE_OR_HOST_OFFSET 0xf
#define MIG_DEVICE_OR_HOST_HOLD_BITS 0x1
#define MIG_VFID_OFFSET 0xa
#define MIG_VFID_HOLD_BITS 0x5
#define MIG_STATUS_OR_ERRNO_OFFSET 0x0
#define MIG_STATUS_OR_ERRNO_HOLD_BITS 0xa

#define MIG_MASK(segment) \
	(((1 << MIG_##segment##_HOLD_BITS) - 1) << MIG_##segment##_OFFSET)
#define MIG_COPY_BITS(ret, val, segment) \
		(((val << MIG_##segment##_OFFSET) & MIG_MASK(segment)) | \
		(ret & (~MIG_MASK(segment))))
#define MIG_GET_BITS(ret, segment) \
	((ret & MIG_MASK(segment)) >> MIG_##segment##_OFFSET)

#define mig_get_global_state(ret) \
	MIG_GET_BITS(ret, GLOBAL_STATE)
#define mig_set_global_state(ret, val) \
	MIG_COPY_BITS(ret, val, GLOBAL_STATE)

#define mig_get_moduleid(ret) \
	MIG_GET_BITS(ret, MODULEID)
#define mig_set_moduleid(ret, val) \
	MIG_COPY_BITS(ret, val, MODULEID)

#define mig_is_host(ret) \
	(ret & MIG_MASK(DEVICE_OR_HOST))
#define mig_set_as_host(ret) \
	(ret | MIG_MASK(DEVICE_OR_HOST))
#define mig_set_as_device(ret) \
	(ret & (~MIG_MASK(DEVICE_OR_HOST)))

#define mig_get_vfid(ret) \
	MIG_GET_BITS(ret, VFID)
#define mig_set_vfid(ret, val) \
	MIG_COPY_BITS(ret, val, VFID)

#define mig_get_status_or_errno(ret) \
	MIG_GET_BITS(ret, STATUS_OR_ERRNO)
#define mig_set_status_or_errno(ret, val) \
	MIG_COPY_BITS(ret, val, STATUS_OR_ERRNO)

#ifdef CONFIG_CNDRV_MIG
/*
 * qemu call this function to get config information
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * ca: host buf address
 * size: host buf size
 * ret_size: the actual read data size
 * Notes: the user must malloc a enough size to store config onformation, suggest
 *        bigger than 4K.
 */
int mig_get_cfg(void *mig_priv, u32 vf, u64 ca, u64 size, u64 *ret_size);

/*
 * qemu call this function to restore data
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * ca: host buf address
 * size: host buf size
 * Notes: the user must malloc a enough size to store config onformation
 */
int mig_put_cfg(void *mig_priv, u32 vf, u64 ca, u64 size);

int mig_save_prepare(void *mig_priv, u32 vf);
int mig_restore_prepare(void *mig_priv, u32 vf);

int mig_save_start(void *mig_priv, u32 vf);
int mig_restore_start(void *mig_priv, u32 vf);

int mig_save_query_state(void *mig_priv, u32 vf, u32 *dev_state);
int mig_restore_query_state(void *mig_priv, u32 vf, u32 *dev_state);

int mig_save_complete(void *mig_priv, u32 vf);
int mig_restore_complete(void *mig_priv, u32 vf);

int mig_save_cancel(void *mig_priv, u32 vf);
int mig_restore_cancel(void *mig_priv, u32 vf);

/*
 * qemu call this function to restore data
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * ca: host buf address
 * size: host buf size
 * flag: 1 is the last data
 */
int mig_get_data(void *mig_priv, u32 vf, u64 ca, u64 size, u32 *flag,
	u64 *ret_size, u32 *data_category);

/*
 * qemu call this function to restore data
 * mig_set: the core->mig_set
 * vf: the vf index to migration
 * ca: host buf address
 * size: host buf size
 * flag: 1 is the last data
 */
int mig_put_data(void *mig_priv, u32 vf, u64 ca, u64 size, u32 flag);

#else
static inline int mig_get_cfg(void *mig_priv, u32 vf, u64 ca, u64 size, u64 *ret_size)
{
	return 0;
}
static inline int mig_save_query_state(void *mig_priv, u32 vf, u32 *dev_state)
{
	return 0;
}
static inline int mig_restore_prepare(void *mig_priv, u32 vf)
{
	return 0;
}
static inline int mig_save_prepare(void *mig_priv, u32 vf)
{
	return 0;
}
static inline int mig_restore_cancel(void *mig_priv, u32 vf)
{
	return 0;
}
static inline int mig_restore_complete(void *mig_priv, u32 vf)
{
	return 0;
}
static inline int mig_restore_start(void *mig_priv, u32 vf)
{
	return 0;
}
static inline int mig_save_start(void *mig_priv, u32 vf)
{
	return 0;
}
static inline int mig_save_cancel(void *mig_priv, u32 vf)
{
	return 0;
}
static inline int mig_get_data(void *mig_priv, u32 vf, u64 ca, u64 size, u32 *flag,
		u64 *ret_size, u32 *data_category)
{
	return 0;
}
static inline int mig_restore_query_state(void *mig_priv, u32 vf, u32 *dev_state)
{
	return 0;
}
static inline int mig_save_complete(void *mig_priv, u32 vf)
{
	return 0;
}
static inline int mig_put_data(void *mig_priv, u32 vf, u64 ca, u64 size, u32 flag)
{
	return 0;
}
static inline int mig_put_cfg(void *mig_priv, u32 vf, u64 ca, u64 size)
{
	return 0;
}
#endif

#endif
