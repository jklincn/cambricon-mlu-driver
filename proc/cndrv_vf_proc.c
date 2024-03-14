#include "cndrv_debug.h"
/************************************************************************
 *
 *  @file cndrv_vf_proc.c
 *
 *  @brief This file is designed to operate vf proc
 * ######################################################################
 *
 * Copyright (c) 2019 Cambricon, Inc. All rights reserved.
 *
 **************************************************************************/

/*************************************************************************
 * Software License Agreement:
 * -----------------------------------------------------------------------
 * Copyright (C) [2019] by Cambricon, Inc.
 * This code is licensed under MIT license (see below for details)
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *************************************************************************/
/************************************************************************
 *  Include files
 ************************************************************************/
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include "../core/version.h"
#include "../include/cndrv_bus.h"
#include "../include/cndrv_core.h"

#include "cndrv_proc.h"
#include "cndrv_vf_proc.h"
#include "cndrv_domain.h"
#include "cndrv_mm.h"
#include "../include/cndrv_sbts.h"
#include "cndrv_mig.h"

/* init vf device/ctrl node info */
static int vf_proc_set_init(struct cn_vf_proc_set **pvf_proc)
{
	struct cn_vf_proc_set *vf_proc = NULL;

	vf_proc = cn_kzalloc(sizeof(struct cn_vf_proc_set), GFP_KERNEL);
	if (!vf_proc)
		return -EINVAL;

	memset((void *)vf_proc, 0, sizeof(struct cn_vf_proc_set));

	*pvf_proc = vf_proc;
	return 0;
}

static int vf_proc_open(struct inode *inode, struct file *file)
{
	void *proc_data = PDE_DATA(inode);
	return single_open(file, NULL, proc_data);
}

const char *cndrv_vf_mig_debug[] = {
	"checksum", "checksum_error", "error_injection"};

static ssize_t vf_proc_mig_read(struct file *file, char __user *buf,
	size_t size, loff_t *ppos)
{
	char *msg_note =
		"echo checksum/checksum_error/error_injection enable/disable migration debug\n";
	char *msg_all;
	char temp_buf[64];
	int msg_len;
	int copy_len;
	int enable;
	enum mig_debug_type type;
	struct cn_core_set *core = NULL;

	if (*ppos < 0) {
		return -EINVAL;
	}

	core = PDE_DATA(file->f_inode);
	if (!core)
		return -EINVAL;

	msg_all = cn_kzalloc(4096, GFP_KERNEL);
	if (msg_all == NULL)
		return -ENOMEM;

	sprintf(msg_all, msg_note, strlen(msg_note));
	for (type = 0; type < MIG_DEBUG_CNT; type++) {
		enable = 0;
		mig_get_debug_info(core, type, &enable);
		if (enable) {
			sprintf(&temp_buf[0], "%s enable\n", cndrv_vf_mig_debug[type]);
		} else {
			sprintf(&temp_buf[0], "%s disable\n", cndrv_vf_mig_debug[type]);
		}
		strcat(msg_all, &temp_buf[0]);
	}

	msg_len = strlen(msg_all);
	copy_len = min((int)size, msg_len - (int)*ppos);
	if (copy_to_user(buf, &msg_all[*ppos], copy_len)) {
		cn_kfree(msg_all);
		return -EINVAL;
	}
	*ppos += copy_len;

	cn_kfree(msg_all);
	return copy_len;
}

static ssize_t vf_proc_mig_write(struct file *file, const char __user *buf,
	size_t count, loff_t *pos)
{
	char temp_buf[64];
	char debug_type[64];
	char debug_en[64];
	enum mig_debug_type type;
	struct cn_core_set *core = NULL;

	if (count <= 0 || count >= sizeof(temp_buf))
		return -EINVAL;

	core = PDE_DATA(file->f_inode);
	if (!core)
		return -EINVAL;

	memset(&temp_buf[0], 0, sizeof(temp_buf));
	memset(&debug_type[0], 0, sizeof(debug_type));
	memset(&debug_en[0], 0, sizeof(debug_en));

	if (copy_from_user((void *)temp_buf, (void *)buf, count)) {
		cn_dev_info("Copy data from user failed!\n");
		return -EINVAL;
	}

	sscanf(&temp_buf[0], "%s %s", &debug_type[0], &debug_en[0]);

	for (type = 0; type < MIG_DEBUG_CNT; type++) {
		if (strncmp(cndrv_vf_mig_debug[type], &debug_type[0],
			strlen(&debug_type[0])) == 0) {
			break;
		}
	}

	if (type >= MIG_DEBUG_CNT) {
		return -EINVAL;
	}

	if (strncmp("enable", &debug_en[0], strlen(&debug_en[0])) == 0) {
		mig_set_debug(core, type, 1);
	} else if (strncmp("disable", &debug_en[0], strlen(&debug_en[0])) == 0) {
		mig_set_debug(core, type, 0);
	} else {
		return -EINVAL;
	}

	return count;
}

#if KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE
static const struct file_operations cndrv_vf_mig_fops = {
	.owner		= THIS_MODULE,
	.open		= vf_proc_open,
	.read		= vf_proc_mig_read,
	.llseek		= seq_lseek,
	.write		= vf_proc_mig_write,
};
#else
static const struct proc_ops cndrv_vf_mig_fops = {
	.proc_open	= vf_proc_open,
	.proc_read	= vf_proc_mig_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= vf_proc_mig_write,
};
#endif

/* vf proc init */
int vf_proc_init(void *pcore, struct proc_dir_entry *parent_dir,
	struct proc_dir_entry *mlu_dir)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct proc_dir_entry *vf_proc_dir = NULL;
	struct proc_dir_entry *vf_proc_mig = NULL;
	struct cn_vf_proc_set *vf_proc = NULL;

	if ((!pcore) || (!parent_dir))
		return -EINVAL;

	/* make vf node in device */
	vf_proc_dir = proc_mkdir("vf", parent_dir);
	if (!vf_proc_dir) {
		printk(KERN_ERR"create proc vf fail!");
		return -EINVAL;
	}

	/* init vf device/ctrl data */
	if (vf_proc_set_init(&vf_proc)) {
		printk(KERN_ERR"init vf proc set fail!");
		goto err_proc_init;
	}

	vf_proc->cndrv_vf_dir = vf_proc_dir;

	/* live migration debug */
	vf_proc_mig = proc_create_data("migration", MODE_WRITE,
		vf_proc_dir, &cndrv_vf_mig_fops, pcore);
	if (!vf_proc_mig) {
		cn_dev_info("create live migration debug fail");
		goto err_create_data;
	}

	core->vf_proc_set = vf_proc;

	return 0;

err_create_data:
	cn_kfree(vf_proc);
err_proc_init:
	if (vf_proc_dir) {
		proc_remove(vf_proc_dir);
		vf_proc->cndrv_vf_dir = NULL;
	}
	return -EINVAL;
}

/* vf proc exit */
int vf_proc_exit(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_vf_proc_set *vf_proc = NULL;

	if (!pcore)
		return -EINVAL;

	vf_proc = core->vf_proc_set;

	if (!vf_proc) {
		printk(KERN_INFO"remove vf proc: No such directory");
		return -EINVAL;
	} else {
		if (vf_proc->cndrv_vf_dir) {
			proc_remove(vf_proc->cndrv_vf_dir);
			vf_proc->cndrv_vf_dir = NULL;
		}
		cn_kfree(vf_proc);
	}

	return 0;
}
