/*
 * sbts/idc_internal.h
 *
 * NOTICE:
 * Copyright (C) 2022 Cambricon, Inc. All rights reserved.
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

#ifndef __SBTS_IDC_H
#define __SBTS_IDC_H

#include <linux/types.h>

struct cn_core_set;
struct idc_manager;



int sbts_idc_do_exit(u64 user, struct idc_manager *manager);

int sbts_idc_manager_init(
		struct idc_manager **ppidc_mgr,
		struct cn_core_set *core);

void sbts_idc_manager_exit(struct idc_manager *idc_manager);


int cn_sbts_idc_global_init(void);

void cn_sbts_idc_global_exit(void);


#endif /* __SBTS_IDC_H */
