/*
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


#ifndef __UTIL_DRV_H__
#define __UTIL_DRV_H__

#include "cndrv_core.h"

enum util_type {
	IPU_UTIL = 0,
	// VPU_UTIL,
	UTIL_TYPE_MAX,
};

struct smlu_util_adjust_module_s {
	void *smlu_util_adjust_module;
	void *smlu_util_adjust;
	void *smlu_util_adjust_output;
};

long smlu_util_adjust(int idx, int instance, enum util_type sub,
	unsigned long target, unsigned long usage);

typedef long (*ex_output_fn)(int idx, int instance, enum util_type sub);

struct pid_s {
	/* pid adjust middle data */
	long error;
	long last_error;
	long previous_error;

	long proportion, integral, derivative;
	long increase;
	long output;
	long time; /* just self add after util adjust */

	/* last_output and last_time is modified by ipu_util_output() */
	long last_output; /* protect by adjust_lock */
	__u64 last_time; /* protect by adjust_lock */
	struct mutex adjust_lock;
};

struct PID_parameter {
	/* format such as MLU370-X8 */
	char board_model_name[BOARD_MODEL_NAME_LEN];

	/* IPU */
	long IKP;
	long IKI;
	long IKD;
	/* VPU */
	long VKP;
	long VKI;
	long VKD;

	/* detail pid adjust data for each instance and util type */
	struct pid_s pid_info[MAX_SMLU_INSTANCE_COUNT + 1][UTIL_TYPE_MAX];
};

extern struct PID_parameter cn_pid_parameter[MAX_PHYS_CARD];
#endif // __UTIL_DRV_H__
