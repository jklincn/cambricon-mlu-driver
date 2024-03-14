/************************************************************************
 *  @file cndrv_vf_proc.h
 *
 *  @brief For vf/pf proc definitions.
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
#ifndef __CNDRV_VF_PROC_H__
#define __CNDRV_VF_PROC_H__

#define	VF_NODE_NAME_LENGTH	32

#define	MODE_READ	0444
#define	MODE_WRITE	0666

struct cn_vf_proc_set {
	char vf_proc_name[VF_NODE_NAME_LENGTH];	//vf proc directory name
	struct proc_dir_entry *cndrv_vf_dir;	//device node
};

extern int vf_proc_init(void *pcore, struct proc_dir_entry *parent_dir,
	struct proc_dir_entry *mlu_dir);
extern int vf_proc_exit(void *);
#endif /*__CNDRV_VF_PROC_H__*/
