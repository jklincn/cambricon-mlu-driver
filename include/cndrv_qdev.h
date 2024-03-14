/*
 * include/cndrv_qdev.h
 *
 * NOTICE:
 * Copyright (C) 2020 Cambricon, Inc. All rights reserved.
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

#ifndef __CNDRV_QDEV_H__
#define __CNDRV_QDEV_H__

#ifdef CONFIG_CNDRV_MIG
/*
 * when core probe call this function, this function used for live migration
 * for virtual machine
 * return: -1:error     0:success
 */
int cn_qdev_late_init(struct cn_core_set *core);

/*
 * when core remove call this function, this function used for live migration
 * for virtual machine
 * return: 0
 */
void cn_qdev_late_exit(struct cn_core_set *core);

#else
static inline int cn_qdev_late_init(struct cn_core_set *core)
{
	return 0;
}

static inline void cn_qdev_late_exit(struct cn_core_set *core)
{
	return;
}

#endif

#endif
