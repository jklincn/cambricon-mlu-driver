/************************************************************************
 *  @file cndrv_proc.h
 *
 *  @brief For exception support definitions.
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
#ifndef __CNDRV_PROC_H__
#define __CNDRV_PROC_H__

typedef enum {
	PROC_HELP,
	PROC_READ,
	PROC_WRITE,
	PROC_SW_ALLOC,
	PROC_SRAM_BASE,
}SHOW_TYPE;

struct dob_set_t {
	u64 dev_va;
	size_t size;
	u8 data;
};

struct dob_rpc_alloc_t {
	u64 desc_buff;
	u64 desc_offset;
};

struct dob_rpc_free_t {
	u64 desc_offset;
};

struct sram_set_t {
	u64 dev_va;
	size_t size;
	u32 data;
};

enum PROCESS_STAGE {
	INIT_STAGE = 0,
	LATE_INIT_STAGE,
};

#ifdef CONFIG_CNDRV_PROC
extern int cn_proc_init(void);
extern void cn_proc_exit(void);

extern int cn_core_proc_init(struct cn_core_set *core);
extern void cn_core_proc_exit(struct cn_core_set *core);
extern int cn_proc_late_init(struct cn_core_set *core);
extern void cn_proc_late_exit(struct cn_core_set *core);
/* data outbound*/
extern int proc_open_channel(struct cn_core_set *core);
extern void proc_close_channel(struct cn_core_set *core);
extern int data_outbound_rpc_alloc(struct cn_core_set *core, struct dob_rpc_alloc_t *dob_alloc);
extern int data_outbound_rpc_free(struct cn_core_set *core, struct dob_rpc_free_t *dob_free);
extern int data_outbound_rpc_write(struct cn_core_set *core, struct dob_set_t *dob_set);
extern int data_outbound_rpc_read(struct cn_core_set *core, struct dob_set_t *dob_set);
extern int sram_rpc_write(struct cn_core_set *core, struct sram_set_t *sram_set);
extern int sram_rpc_read(struct cn_core_set *core, struct sram_set_t *sram_set);
extern void cn_core_show_mlumsg(struct cn_core_set *core);
#else
static inline int cn_proc_init(void)
{
	return 0;
}
static inline void cn_proc_exit(void)
{
	return;
}

static inline int cn_core_proc_init(struct cn_core_set *core)
{
	return 0;
}
static inline void cn_core_proc_exit(struct cn_core_set *core)
{
	return;
}
static inline int cn_proc_late_init(struct cn_core_set *core)
{
	return 0;
}
static inline void cn_proc_late_exit(struct cn_core_set *core)
{
	return;
}
static inline int proc_open_channel(struct cn_core_set *core)
{
	return 0;
}
static inline void proc_close_channel(struct cn_core_set *core)
{
}
static inline int data_outbound_rpc_alloc(struct cn_core_set *core, struct dob_rpc_alloc_t *dob_alloc)
{
	return 0;
}
static inline int data_outbound_rpc_free(struct cn_core_set *core, struct dob_rpc_free_t *dob_free)
{
	return 0;
}
static inline int data_outbound_rpc_write(struct cn_core_set *core, struct dob_set_t *dob_set)
{
	return 0;
}
static inline int data_outbound_rpc_read(struct cn_core_set *core, struct dob_set_t *dob_set)
{
	return 0;
}
static inline int sram_rpc_write(struct cn_core_set *core, struct sram_set_t *sram_set)
{
	return 0;
}
static inline int sram_rpc_read(struct cn_core_set *core, struct sram_set_t *sram_set)
{
	return 0;
}
static inline void cn_core_show_mlumsg(struct cn_core_set *core)
{
	return;
}
#endif

#endif /*__CNDRV_PROC_H__*/
