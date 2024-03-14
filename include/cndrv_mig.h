/************************************************************************
 *  @file cndrv_mig.h
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

#ifndef __CNDRV_MGR_H
#define __CNDRV_MGR_H

enum mig_debug_type {
	MIG_DEBUG_CHECKSUM = 0,
	MIG_DEBUG_CHECKSUM_ERR,
	MIG_DEBUG_ERR_INJ,
	MIG_DEBUG_CNT,
};

#ifdef CONFIG_CNDRV_MIG

enum mig_host_drv {
	MIG_HOST_PCIE = 0,
	MIG_HOST_CNT
};

/*
 * Host pf driver may transfer some data in live migration, if a driver want
 * to transfer data, add a enum in mig_host_drv first, and next call this
 * function to set call back
 * mig_priv: the core->mig_set
 * mig_host_drv: the live migration driver index
 * get_host_data_size: the size of driver want to transfer data
 * get_host_data: callback for source get data
 * put_host_data: callback for dst put data
 */
int mig_reg_host_cb(struct cn_core_set *core, int mig_host_drv, void *priv,
	u64 (*get_host_data_size)(void *priv, int vf),
	u64 (*get_host_data)(void *priv, int vf, void *buf, u64 size),
	u64 (*put_host_data)(void *priv, int vf, void *buf, u64 size));

/*
 * Add debug information
 * mig_set: the core->mig_set
 * type: debug information type
 */
int mig_set_debug(struct cn_core_set *core, enum mig_debug_type type, int en);
/*
 * Get debug information
 * mig_set: the core->mig_set
 * type: debug information type
 */
int mig_get_debug_info(struct cn_core_set *core, enum mig_debug_type type, int *en);

int cn_mig_late_init(struct cn_core_set *core);
void cn_mig_late_exit(struct cn_core_set *core);


long cn_mig_ioctl(struct cn_core_set *core, unsigned int cmd, unsigned long arg);
#else
static inline int mig_get_debug_info(struct cn_core_set *core, enum mig_debug_type type, int *en)
{
	return 0;
}
static inline int mig_set_debug(struct cn_core_set *core, enum mig_debug_type type, int en)
{
	return 0;
}
static inline int cn_mig_late_init(struct cn_core_set *core)
{
	return 0;
}
static inline void cn_mig_late_exit(struct cn_core_set *core)
{
	return;
}
static inline long cn_mig_ioctl(struct cn_core_set *core, unsigned int cmd, unsigned long arg)
{
	return 0;
}
#endif

#endif
