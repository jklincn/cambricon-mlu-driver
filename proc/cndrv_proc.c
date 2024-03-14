/************************************************************************
 *
 *  @file cndrv_proc.c
 *
 *  @brief This file is designed to progress exit notification functions
 * ######################################################################
 *
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 *
 **************************************************************************/

/*************************************************************************
 * Software License Agreement:
 * -----------------------------------------------------------------------
 * Copyright (C) [2018] by Cambricon, Inc.
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
#include <linux/utsname.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include "../core/version.h"
#include "../include/cndrv_bus.h"
#include "../include/cndrv_core.h"

#include "cndrv_fw.h"
#include "cndrv_proc_internal.h"
#include "cndrv_proc.h"
#include "cndrv_mm.h"
#include "cndrv_vf_proc.h"
#include "cndrv_debug.h"
#include "../include/cndrv_pinned_mm.h"
#include "cndrv_mcu.h"
#include "cndrv_monitor.h"
#include "cndrv_core.h"
#include "cndrv_domain.h"
#include "cndrv_trans.h"
#include "cndrv_mcc.h"
#include "cndrv_kthread.h"
#include "cndrv_kwork.h"
#include "cndrv_lpm.h"
#include "cndrv_sbts.h"
#include "cndrv_ipcm.h"
#ifdef CONFIG_CNDRV_EDGE
#include <linux/namei.h>
#else
#include "exp_mgnt.h"
#endif
#include "cndrv_commu.h"
#include "cndrv_ioctl.h"
#include "cndrv_xid.h"
#include "cndrv_gdma.h"
#include "cndrv_pmu_proc.h"
#include "cndrv_cndev.h"
#include "cndrv_smlu.h"
#include "cndrv_attr.h"
#include "cndrv_mem_perf.h"


#define M_SIZE		(1*1024*1024)
#define CN_PROC_DEBUG

#define PROC_PRIV_OP(__name) \
static const struct seq_operations __name##_op = { \
	.start		= __name##_start, \
	.next		= __name##_next, \
	.stop		= __name##_stop, \
	.show		= __name##_show, \
}

static inline bool cn_proc_need_lpm(struct cn_core_set *core)
{
	return ((MLUID_MAJOR_ID(core->device_id) < 5) || isCEPlatform(core));
}

static inline int cn_proc_get(struct cn_core_set *core)
{
	return cn_lpm_get_all_module_with_cond(core, cn_proc_need_lpm(core));
}

static inline void cn_proc_put(struct cn_core_set *core)
{
	(void)cn_lpm_put_all_module_with_cond(core, cn_proc_need_lpm(core));
}

#if KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE
#define PROC_SHOW_ATTRIBUTE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{				\
	if (cn_proc_get((struct cn_core_set *)PDE_DATA(inode))) \
		return -EINVAL; \
	return single_open(file, __name##_show, PDE_DATA(inode)); \
}				\
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file);\
	cn_proc_put((struct cn_core_set *)PDE_DATA(inode)); \
	return 0; \
} \
static const struct file_operations __name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= __name##_open, \
	.read		= seq_read, \
	.llseek		= seq_lseek, \
	.release	= __name##_release, \
}

#define PROC_SHOW_ATTRIBUTE_PRIV(__name) \
static const struct file_operations __name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= __name##_open, \
	.read		= seq_read, \
	.llseek		= seq_lseek, \
	.release	= seq_release_private, \
}

#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
#define PROC_SHOW_ATTRIBUTE_SIZE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{ \
	if (cn_proc_get((struct cn_core_set *)PDE_DATA(inode))) \
		return -EINVAL; \
	return single_open_size(file, __name##_show, PDE_DATA(inode), 2 * M_SIZE); \
} \
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file);\
	cn_proc_put((struct cn_core_set *)PDE_DATA(inode)); \
	return 0; \
} \
static const struct file_operations __name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= __name##_open, \
	.read		= seq_read, \
	.llseek		= seq_lseek, \
	.release	= __name##_release, \
}

#define PROC_WRITE_ATTRIBUTE_SIZE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{ \
	if (cn_proc_get((struct cn_core_set *)PDE_DATA(inode))) \
		return -EINVAL; \
	return single_open_size(file, __name##_show, PDE_DATA(inode), 2 * M_SIZE); \
} \
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file);\
	cn_proc_put((struct cn_core_set *)PDE_DATA(inode)); \
	return 0; \
} \
static const struct file_operations __name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= __name##_open, \
	.read		= seq_read, \
	.write		= __name##_write, \
	.llseek		= seq_lseek, \
	.release	= __name##_release, \
}
#else
#define PROC_SHOW_ATTRIBUTE_SIZE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{ \
	char *buf = NULL; \
	int ret = -1; \
	if (cn_proc_get((struct cn_core_set *)PDE_DATA(inode))) \
		return -EINVAL; \
	buf = kzalloc(2 * M_SIZE, GFP_KERNEL); \
	if (!buf) \
		return -ENOMEM; \
	ret = single_open(file, __name##_show, PDE_DATA(inode)); \
	if (ret) { \
		kfree(buf); \
		return ret; \
	} \
	((struct seq_file *)file->private_data)->buf = buf; \
	((struct seq_file *)file->private_data)->size = 2 * M_SIZE; \
	return 0; \
} \
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file);\
	cn_proc_put((struct cn_core_set *)PDE_DATA(inode)); \
	return 0; \
} \
static const struct file_operations __name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= __name##_open, \
	.read		= seq_read, \
	.llseek		= seq_lseek, \
	.release	= __name##_release, \
}

#define PROC_WRITE_ATTRIBUTE_SIZE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{ \
	char *buf = NULL; \
	int ret = -1; \
	if (cn_proc_get((struct cn_core_set *)PDE_DATA(inode))) \
		return -EINVAL; \
	buf = kzalloc(2 * M_SIZE, GFP_KERNEL); \
	if (!buf) \
		return -ENOMEM; \
	ret = single_open(file, __name##_show, PDE_DATA(inode)); \
	if (ret) { \
		kfree(buf); \
		return ret; \
	} \
	((struct seq_file *)file->private_data)->buf = buf; \
	((struct seq_file *)file->private_data)->size = 2 * M_SIZE; \
	return 0; \
} \
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file);\
	cn_proc_put((struct cn_core_set *)PDE_DATA(inode)); \
	return 0; \
} \
static const struct file_operations __name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= __name##_open, \
	.read		= seq_read, \
	.write		= __name##_write, \
	.llseek		= seq_lseek, \
	.release	= __name##_release, \
}
#endif

#define PROC_WRITE_ATTRIBUTE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{				\
	if (cn_proc_get((struct cn_core_set *)PDE_DATA(inode))) \
		return -EINVAL; \
	return single_open(file, __name##_show, PDE_DATA(inode)); \
}				\
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file);\
	cn_proc_put((struct cn_core_set *)PDE_DATA(inode)); \
	return 0; \
} \
static const struct file_operations __name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= __name##_open, \
	.read		= seq_read, \
	.write		= __name##_write, \
	.llseek		= seq_lseek, \
	.release	= __name##_release, \
}

#else
#define PROC_SHOW_ATTRIBUTE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{				\
	if (cn_proc_get((struct cn_core_set *)PDE_DATA(inode))) \
		return -EINVAL; \
	return single_open(file, __name##_show, PDE_DATA(inode)); \
}				\
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file);\
	cn_proc_put((struct cn_core_set *)PDE_DATA(inode)); \
	return 0; \
} \
static const struct proc_ops __name##_fops = { \
	.proc_open	= __name##_open, \
	.proc_read	= seq_read, \
	.proc_lseek	= seq_lseek, \
	.proc_release	= __name##_release, \
}

#define PROC_SHOW_ATTRIBUTE_PRIV(__name) \
static const struct proc_ops __name##_fops = { \
	.proc_open	= __name##_open, \
	.proc_read	= seq_read, \
	.proc_lseek	= seq_lseek, \
	.proc_release	= seq_release_private, \
}

#define PROC_SHOW_ATTRIBUTE_SIZE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{ \
	if (cn_proc_get((struct cn_core_set *)PDE_DATA(inode))) \
		return -EINVAL; \
	return single_open_size(file, __name##_show, PDE_DATA(inode), 2 * M_SIZE); \
} \
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file);\
	cn_proc_put((struct cn_core_set *)PDE_DATA(inode)); \
	return 0; \
} \
static const struct proc_ops __name##_fops = { \
	.proc_open	= __name##_open, \
	.proc_read	= seq_read, \
	.proc_lseek	= seq_lseek, \
	.proc_release	= __name##_release, \
}

#define PROC_WRITE_ATTRIBUTE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{				\
	if (cn_proc_get((struct cn_core_set *)PDE_DATA(inode))) \
		return -EINVAL; \
	return single_open(file, __name##_show, PDE_DATA(inode)); \
}				\
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file); \
	cn_proc_put((struct cn_core_set *)PDE_DATA(inode)); \
	return 0; \
} \
static const struct proc_ops __name##_fops = { \
	.proc_open	= __name##_open, \
	.proc_read	= seq_read, \
	.proc_write	= __name##_write, \
	.proc_lseek	= seq_lseek, \
	.proc_release	= __name##_release, \
}

#define PROC_WRITE_ATTRIBUTE_SIZE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{ \
	if (cn_proc_get((struct cn_core_set *)PDE_DATA(inode))) \
		return -EINVAL; \
	return single_open_size(file, __name##_show, PDE_DATA(inode), 2 * M_SIZE); \
} \
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file); \
	cn_proc_put((struct cn_core_set *)PDE_DATA(inode)); \
	return 0; \
} \
static const struct proc_ops __name##_fops = { \
	.proc_open	= __name##_open, \
	.proc_read	= seq_read, \
	.proc_write	= __name##_write, \
	.proc_lseek	= seq_lseek, \
	.proc_release	= __name##_release, \
}
#endif

#define DEBUGFS_SHOW_ATTRIBUTE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{				\
	if (cn_proc_get((struct cn_core_set *)inode->i_private)) \
		return -EINVAL; \
	return single_open(file, __name##_show, inode->i_private); \
}				\
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	single_release(inode, file); \
	cn_proc_put((struct cn_core_set *)inode->i_private); \
	return 0; \
} \
static const struct file_operations __name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= __name##_open, \
	.read		= seq_read, \
	.llseek		= seq_lseek, \
	.release	= __name##_release, \
}

#define DEBUGFS_WRITE_ATTRIBUTE(__name) \
static int __name##_open(struct inode *inode, struct file *file) \
{				\
	if (cn_proc_get((struct cn_core_set *)inode->i_private)) \
		return -EINVAL; \
	return single_open(file, __name##_show, inode->i_private); \
}				\
static int __name##_release(struct inode *inode, struct file *file) \
{ \
	if (file->private_data) \
		single_release(inode, file); \
	cn_proc_put((struct cn_core_set *)inode->i_private); \
	return 0; \
} \
static const struct file_operations __name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= __name##_open, \
	.read		= seq_read, \
	.write		= __name##_write, \
	.llseek		= seq_lseek, \
	.release	= __name##_release, \
}
static struct proc_dir_entry *cndrv_dir = NULL;
static struct proc_dir_entry *cndrv_mlu_dir = NULL;

static void cndrv_info_board_model(struct seq_file *m, const char *model_name)
{
	if (model_name) {
		seq_printf(m, "Device name: %s\n", model_name);
	} else {
		seq_puts(m, "Device name: mlu-cambricon\n");
	}
}

static void cndrv_info_device(struct seq_file *m, struct cn_core_set *core)
{
	char inode_path[64];

	snprintf(inode_path, sizeof(inode_path), (cn_core_is_vf(core) && cn_is_mim_en(core))
		? "/dev/cambricon-caps/%s" : "/dev/%s",
		dev_name(core->device->primary->kdev));
	seq_printf(m, "Device inode path: %s\n", inode_path);
	seq_printf(m, "Device Major: %d\n", core->device->primary->major);
	seq_printf(m, "Device Minor: %d\n", core->device->primary->index);
	seq_printf(m, "Driver Version: v%d.%d.%d\n",
		DRV_MAJOR,
		DRV_MINOR,
		DRV_BUILD);
#ifndef CONFIG_CNDRV_EDGE
	seq_printf(m, "MCU Version: v%u.%u.%u\n",
		core->board_info.mcu_info.mcu_major,
		core->board_info.mcu_info.mcu_minor,
		core->board_info.mcu_info.mcu_build);
#endif
	seq_printf(m, "Board Serial Number: SN/%llx\n", core->board_info.serial_num);
#ifndef CONFIG_CNDRV_EDGE
	seq_printf(m, "MLU Firmware Version: %s\n", core->firmware_version);
	seq_printf(m, "Board CV: %d\n", core->board_info.chip_version);
#endif
#if defined(CONFIG_CNDRV_CE3226_SOC)
	seq_printf(m, "Die Count: %d\n", core->die_cnt);
#endif
}

static void cndrv_info_ipu_freq(struct seq_file *m, struct cn_core_set *core)
{
	struct cn_proc_set *proc_set = (struct cn_proc_set *)core->proc_set;
	struct ipu_freq_info info = {0};
	int ret = 0;

	ret = cndrv_mcu_read_ipu_freq(core, &info);
	if (ret) {
		cn_dev_proc_err(proc_set, "get freq info err, ret:%d", ret);
		return;
	}

#if defined(CONFIG_CNDRV_CE3226_SOC)
	seq_printf(m, "CT Freq: %uMHz\n", info.die_ipu_freq.ipu_freq[0]);
	seq_printf(m, "LT Freq: %uMHz\n", info.die_ipu_freq.ipu_freq[1]);
#elif defined(CONFIG_CNDRV_PIGEON_SOC)

	switch (core->board_info.chip_type & 0x3) {
	case CN_CHIP_ID_LEOPARD:
		seq_printf(m, "IPU0 Freq: %uMHz\n", info.die_ipu_freq.ipu_freq[0]);
		seq_printf(m, "IPU1 Freq: %uMHz\n", info.die_ipu_freq.ipu_freq[1]);
		break;
	default:
		break;
	}

#else
	seq_printf(m, "IPU Freq: %uMHz\n", info.ipu_freq);
#endif
}

static struct pcie_speed PCIE_SPEED[] = {
	{0x0001, "2.5GT/s"},
	{0x0002, "5.0GT/s"},
	{0x0003, "8.0GT/s"},
	{0x0004, "16.0GT/s"},
	{0x0005, "32.0GT/s"}
};

static struct pcie_width PCIE_WIDTH[] = {
	{0x0001, "x1"},
	{0x0002, "x2"},
	{0x0004, "x4"},
	{0x0008, "x8"},
	{0x0010, "x16"}
};

static void cndrv_info_bus_pcie(struct seq_file *m, struct bus_info_s bus_info,
					struct bus_lnkcap_info lnk_info)
{
	char serial_num[64];
	int i = 0;

	snprintf(serial_num, 64, "%x_%x_%x", bus_info.info.pcie.bus_num,
			bus_info.info.pcie.device_id >> 3,
			bus_info.info.pcie.device_id & 0x7);
	seq_printf(m, "Bus Location: %s\n", serial_num);

	switch (bus_info.bus_type) {
	case BUS_TYPE_PCIE:
		seq_puts(m, "Bus Type: PCIE\n");
		break;
	default:
		seq_puts(m, "Bus Type: UNKNOWN TYPE\n");
		break;
	}
	seq_puts(m, "LnkSta: Speed ");
	for (i = 0; i < ARRAY_SIZE(PCIE_SPEED); i++) {
		if (lnk_info.speed == PCIE_SPEED[i].id) {
			seq_printf(m, "%s, ", PCIE_SPEED[i].str);
			break;
		}
	}
	if (i >= ARRAY_SIZE(PCIE_SPEED))
		seq_puts(m, "unknown, ");
	seq_puts(m, "Width ");
	for (i = 0; i < ARRAY_SIZE(PCIE_WIDTH); i++) {
		if (lnk_info.width == PCIE_WIDTH[i].id) {
			seq_printf(m, "%s\n", PCIE_WIDTH[i].str);
			break;
		}
	}
	if (i >= ARRAY_SIZE(PCIE_WIDTH))
		seq_puts(m, "unknown.\n");

	seq_puts(m, "Min_LnkSta: Speed ");
	for (i = 0; i < ARRAY_SIZE(PCIE_SPEED); i++) {
		if (lnk_info.min_speed == PCIE_SPEED[i].id) {
			seq_printf(m, "%s, ", PCIE_SPEED[i].str);
			break;
		}
	}
	if (i >= ARRAY_SIZE(PCIE_SPEED))
		seq_puts(m, "unknown, ");
	seq_puts(m, "Width ");
	for (i = 0; i < ARRAY_SIZE(PCIE_WIDTH); i++) {
		if (lnk_info.min_width == PCIE_WIDTH[i].id) {
			seq_printf(m, "%s\n", PCIE_WIDTH[i].str);
			break;
		}
	}
	if (i >= ARRAY_SIZE(PCIE_WIDTH))
		seq_puts(m, "unknown.\n");

}

static void cndrv_info_bar(struct seq_file *m, struct bar_info_s bar_info)
{
	seq_printf(m, "Region 0: Memory at %llx [size=%lldM]\n",
		bar_info.bar[0].bar_base,
		bar_info.bar[0].bar_sz / M_SIZE);
	seq_printf(m, "Region 2: Memory at %llx [size=%lldM]\n",
		bar_info.bar[2].bar_base,
		bar_info.bar[2].bar_sz / M_SIZE);
	seq_printf(m, "Region 4: Memory at %llx [size=%lldM]\n",
		bar_info.bar[4].bar_base,
		bar_info.bar[4].bar_sz / M_SIZE);
}

static void cndrv_info_interrupt(struct seq_file *m)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	static const char * const interrupt_mode[] = {"MSI", "MSIX", "INTX"};
	int index;

	index = cn_bus_get_isr_type(core->bus_set);
	if (index == MSI || index == MSIX || index == INTX) {
		seq_printf(m, "Interrupt Mode: %s\n", interrupt_mode[index]);
	}
}

static void cndrv_info_pcie_fw(struct seq_file *m, u64 pcie_fw_info)
{
	if (pcie_fw_info)
		seq_printf(m, "PCIE Firmware Version: FV/%llx\n", pcie_fw_info);
}

static int cndrv_info_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct bus_info_s bus_info;
	struct bar_info_s bar_info;
	struct bus_lnkcap_info lnk_info;
	char board_name[64];
	u64 pcie_fw_info = 0ULL;

	memset(&bus_info, 0, sizeof(struct bus_info_s));
	memset(&bar_info, 0, sizeof(struct bar_info_s));
	memset(&lnk_info, 0, sizeof(struct bus_lnkcap_info));

	cn_bus_get_bus_info(core->bus_set, &bus_info);

	if (bus_info.bus_type == BUS_TYPE_PCIE) {
		cn_bus_get_bar_info(core->bus_set, &bar_info);
		cn_bus_get_curlnk(core->bus_set, &lnk_info);
		cn_bus_get_pcie_fw_info(core->bus_set, &pcie_fw_info);
		if (cn_core_is_vf(core)) {
			sprintf(board_name, "%s-VF", core->board_info.board_model_name);
			cndrv_info_board_model(m, board_name);
		} else {
			cndrv_info_board_model(m, core->board_info.board_model_name);
		}

		cndrv_info_device(m, core);
		cndrv_info_pcie_fw(m, pcie_fw_info);
		if (!cn_core_is_vf(core))
			cndrv_info_ipu_freq(m, core);

		cndrv_info_interrupt(m);
		cndrv_info_bus_pcie(m, bus_info, lnk_info);
		cndrv_info_bar(m, bar_info);
	} else if (bus_info.bus_type == BUS_TYPE_EDGE) {
		cndrv_info_board_model(m, core->board_info.board_model_name);
		cndrv_info_device(m, core);
		cndrv_info_ipu_freq(m, core);
		cndrv_info_interrupt(m);
	} else {
		seq_puts(m, "Bus Type: UNKNOWN TYPE\n");
	}

	return 0;
}
PROC_SHOW_ATTRIBUTE(cndrv_info);

static int cndrv_kwork_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_kworkqueue_inner_t *wq_node;
	struct list_head *kworkqueue_list;

	seq_printf(m, "%s\n", "current mlu kworkqueue");
	kworkqueue_list = cn_get_core_workqueue_head(core);
	list_for_each_entry(wq_node, kworkqueue_list, list) {
		seq_printf(m, "\t%s\n", wq_node->name);
	}
	seq_printf(m, "\n");

	return 0;
}

static void cndrv_kthread_put(struct seq_file *m, struct cn_kthread_inner_t *node)
{
	seq_printf(m, "%-32s", node->t.name);
	seq_printf(m, "%-14ld", node->time);
	seq_printf(m, "%-35d", node->status.last_execution_duration);
	seq_printf(m, "%-22d", node->status.interval_time);
	seq_printf(m, "%-21ld", node->status.total_execution);
	seq_printf(m, "\n");
}

static int cndrv_kthread_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_kthread_inner_t *node;
	int i;

	struct kthread_show_s kthread_show_t[] = {
		{.head = &cn_global_list_head, .type_name = "global kthread"},
		{.head = &core->kthread_list, .type_name = "current mlu kthread"},
	};

	seq_printf(m, "\t\t\t\t%-14s%-35s%-22s%-21s\n", "period(s)",
		"last execution duration(ms)", "interval time(ms)", "total executions");

	for (i = 0; i < ARRAY_SIZE(kthread_show_t); i++) {
		seq_printf(m, "%s\n", kthread_show_t[i].type_name);
		list_for_each_entry(node, kthread_show_t[i].head, list) {
			cndrv_kthread_put(m, node);
		}

		seq_printf(m, "\n");
	}

	cndrv_kwork_show(m, v);

	return 0;
}
PROC_SHOW_ATTRIBUTE(cndrv_kthread);

static void cndrv_stat_int_occur_info(struct seq_file *m,
					struct int_occur_info_s *int_occur_info)
{
	int i = 0;

	for (i = 0; i < INTERRUPT_IRQ_NUM; i++) {
		if (int_occur_info->int_occur_count[i])
			seq_printf(m, "interrupt[%d] occurred count: %lld\n",
					i, int_occur_info->int_occur_count[i]);
	}
}

static void cndrv_stat_inbound_cnt(struct seq_file *m, int inbound_cnt)
{
	seq_printf(m, "inbound count: %d\n", inbound_cnt);
}

static void cndrv_stat_non_align_cnt(struct seq_file *m, u32 non_align_cnt)
{
	seq_printf(m, "non align count: %u\n", non_align_cnt);
}

static void cndrv_stat_heartbeat_cnt(struct seq_file *m, u32 heartbeat_cnt)
{
	seq_printf(m, "heartbeat count: %u\n", heartbeat_cnt);
}

static void cndrv_stat_soft_retry_cnt(struct seq_file *m, u32 soft_retry_cnt)
{
	seq_printf(m, "soft retry count: %u\n", soft_retry_cnt);
}

static void cndrv_stat_p2p_exchg_cnt(struct seq_file *m, u32 p2p_exchg_cnt)
{
	seq_printf(m, "p2p exchange count: %u\n", p2p_exchg_cnt);
}

static void cndrv_stat_temperature(struct seq_file *m, u32 *temperature)
{
	int i = 0;

	seq_puts(m, "temperature: ");
	for (i = 0; i < STAT_TEMPERATURE_NUM; i++)
		seq_printf(m, "%d ", temperature[i]);
	seq_puts(m, "\n");
}

static int cndrv_stat_p2p_able(struct seq_file *m)
{
	int i;
	int index = 0;
	struct p2p_stat *p2p_able;
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_proc_set *proc_set = (struct cn_proc_set *)core->proc_set;

	p2p_able = cn_kzalloc(sizeof(struct p2p_stat) * MAX_FUNCTION_NUM, GFP_KERNEL);
	if (!p2p_able) {
		cn_dev_proc_err(proc_set, "alloc p2p_able array error.");
		return -ENOMEM;
	}
	cn_bus_get_p2p_able_info(core->bus_set, p2p_able, &index);
	if (index) {
		seq_puts(m, "p2p able status table: ");
		seq_puts(m, "usage:{-1:disable 1:fast_able 2:slow_able 3:acs_open_able}\n");
	}
	for (i = 0; i < index; i++) {
		seq_printf(m, "\t\t\t\t[card%d to card%d]<->{%d}\n",
				p2p_able[i].x, p2p_able[i].y, p2p_able[i].able);
	}
	cn_kfree(p2p_able);

	return 0;
}

static void cndrv_stat_async_proc_info(struct seq_file *m, struct async_proc_info_s *async_proc_info)
{
	seq_printf(m, "async dma arm trigger count: %lld\n",
			async_proc_info->arm_trigger_dma_cnt);
	seq_printf(m, "async dma host trigger count: %lld\n",
			async_proc_info->host_trigger_dma_cnt);
	seq_printf(m, "async p2p arm trigger count: %lld\n",
			async_proc_info->arm_trigger_p2p_cnt);
	seq_printf(m, "async p2p host trigger count: %lld\n",
			async_proc_info->host_trigger_p2p_cnt);
}

static void cndrv_stat_dma_channel_info(struct seq_file *m, struct dma_channel_info_s *dma_channel_info)
{
	seq_printf(m, "dma physical channel status: %d occupied\n",
			dma_channel_info->phy_channel);
	seq_printf(m, "spkg dma physical channel status: %d occupied\n",
			dma_channel_info->spkg_phy_channel);
	seq_printf(m, "dma share virtual channel status: %d occupied\n",
			dma_channel_info->sh_virt_channel);
	seq_printf(m, "dma priv virtual channel status: %d occupied\n",
			dma_channel_info->priv_virt_channel);
	seq_printf(m, "async dma desc resource status: %d occupied\n",
			dma_channel_info->async_desc_resource);
	seq_printf(m, "async dma task resource status: %d occupied\n",
			dma_channel_info->async_task_resource);
	seq_printf(m, "normal dma task resource status: %d occupied\n",
			dma_channel_info->normal_task_resource);
}

static void cndrv_stat_sync_write_info(struct seq_file *m, struct sync_write_info *sw_info)
{
	int i;
	bool title = true;

	for (i = 0; i < 4; i++) {
		if (sw_info[i].status) {
			if (title) {
				seq_puts(m, "sync_write\tid\ttrigger_pa\t\ttrigger_kva\t\tflag_pa\t\ttrigger_count\n");
				title = false;
			}
			seq_printf(m, "\t\t%d", sw_info[i].sw_id);
			seq_printf(m, "\t%#llx", sw_info[i].sw_trigger_pa);
			seq_printf(m, "\t\t%#lx", sw_info[i].sw_trigger_kva);
			seq_printf(m, "\t%#llx", sw_info[i].sw_flag_pa);
			seq_printf(m, "\t%#x\n", sw_info[i].sw_trigger_count);
		}
	}
}

static void cndrv_stat_pcie_atomicop_info(struct seq_file *m,
						struct cn_core_set *core)
{
	struct pcie_atomicop_info_s info;

	if (cn_bus_get_pcie_atomicop_info(core->bus_set, &info))
		return;

	seq_printf(m, "pcie_atomicop_support:  %d\n", info.atomicop_support);
	seq_printf(m, "pcie_atomicop_host_va:  %#llx\n", info.atomicop_host_va);
	seq_printf(m, "pcie_atomicop_dev_va:   %#llx\n", info.atomicop_dev_va);
	seq_printf(m, "pcie_atomicop_desc_cnt: %u\n", info.atomicop_desc_cnt);
}

static int cndrv_stat_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_proc_set *proc_set = (struct cn_proc_set *)core->proc_set;
	struct int_occur_info_s *int_occur_info;
	struct dma_channel_info_s *dma_channel_info;
	struct async_proc_info_s async_proc_info;
	struct sync_write_info sw_info[4];
	int inbound_cnt;
	u32 non_align_cnt;
	u32 heartbeat_cnt;
	u32 soft_retry_cnt;
	u32 p2p_exchg_cnt;

	int_occur_info = cn_kzalloc(sizeof(struct int_occur_info_s), GFP_KERNEL);
	if (!int_occur_info) {
		cn_dev_proc_err(proc_set, "alloc interrupt occur info error.");
		return -ENOMEM;
	}

	dma_channel_info = cn_kzalloc(sizeof(struct dma_channel_info_s), GFP_KERNEL);
	if (!dma_channel_info) {
		cn_kfree(int_occur_info);
		cn_dev_proc_err(proc_set, "alloc dma channel info error.");
		return -ENOMEM;
	}

	cn_bus_get_int_occur_info(core->bus_set, int_occur_info);
	cndrv_stat_int_occur_info(m, int_occur_info);
	inbound_cnt = cn_bus_get_inbound_cnt(core->bus_set);
	cndrv_stat_inbound_cnt(m, inbound_cnt);
	non_align_cnt = cn_bus_get_non_align_cnt(core->bus_set);
	cndrv_stat_non_align_cnt(m, non_align_cnt);
	heartbeat_cnt = cn_bus_get_heartbeat_cnt(core->bus_set);
	cndrv_stat_heartbeat_cnt(m, heartbeat_cnt);
	soft_retry_cnt = cn_bus_get_soft_retry_cnt(core->bus_set);
	cndrv_stat_soft_retry_cnt(m, soft_retry_cnt);
	if (!cn_is_mim_en(core) && !cn_core_is_vf(core))
		cndrv_stat_temperature(m, core->temperature);
	cndrv_stat_p2p_able(m);
	p2p_exchg_cnt = cn_bus_get_p2p_exchg_cnt(core->bus_set);
	cndrv_stat_p2p_exchg_cnt(m, p2p_exchg_cnt);
	if (!cn_bus_get_async_proc_info(core->bus_set, &async_proc_info))
		cndrv_stat_async_proc_info(m, &async_proc_info);
	if (!cn_bus_get_dma_channel_info(core->bus_set, dma_channel_info))
		cndrv_stat_dma_channel_info(m, dma_channel_info);
	if (core->device_id == MLUID_590 || core->device_id == MLUID_580) {
		cn_bus_sync_write_info(core->bus_set, sw_info);
		cndrv_stat_sync_write_info(m, sw_info);
	}

	cndrv_stat_pcie_atomicop_info(m, core);

	cn_kfree(int_occur_info);
	cn_kfree(dma_channel_info);

	return 0;
}
PROC_SHOW_ATTRIBUTE(cndrv_stat);
static void *update_mlumsg_iter(struct seq_file *m, loff_t *pos)
{
	struct cn_mlumsg_iter *iter = m->private;
	u64 mlu_cur_first_seq = *(u64 *)(iter->mlumsg_base + sizeof(iter->log_first_idx) +
					sizeof(iter->log_next_idx));

	if (iter->log_first_seq < mlu_cur_first_seq) {
		iter->log_first_idx = *(u32 *)(iter->mlumsg_base);
		iter->log_first_seq = *(u64 *)(iter->mlumsg_base + sizeof(iter->log_first_idx) +
					sizeof(iter->log_next_idx));
	}

	iter->log_next_idx = *(u32 *)(iter->mlumsg_base + sizeof(iter->log_first_idx));
	iter->log_next_seq = *(u64 *)(iter->mlumsg_base + sizeof(iter->log_first_idx) +
				sizeof(iter->log_next_idx) + sizeof(iter->log_first_seq));
	return m->private;
}

static int mlumsg_append_char(char **pp, char *e, char c)
{
	if (*pp < e - 2) {
		*(*pp)++ = c;
	} else {
		*(*pp)++ = '\n';
		return -1;
	}

	return 0;
}

static ssize_t mlumsg_print_ext_body(char *buf, size_t size,
		char *dict, size_t dict_len,
		char *text, size_t text_len)
{
	char *p = buf, *e = buf + size;
	size_t i;

	for (i = 0; i < text_len; i++) {
		unsigned char c = text[i];

		if (c >= 127 || c == '\\')
			p += scnprintf(p, e - p, "\\x%02x", c);
		else
			if (mlumsg_append_char(&p, e, c))
				goto exit;
	}
	if (mlumsg_append_char(&p, e, '\n'))
		goto exit;

	if (dict_len) {
		bool line = true;

		for (i = 0; i < dict_len; i++) {
			unsigned char c = dict[i];

			if (line) {
				if (mlumsg_append_char(&p, e, ' '))
					goto exit;
				line = false;
			}
			if (c == '\0') {
				if (mlumsg_append_char(&p, e, '\n'))
					goto exit;
				line = true;
				continue;
			}
			if (c >= 127 || c == '\\') {
				p += scnprintf(p, e - p, "\\x%02x", c);
				continue;
			}
			if (mlumsg_append_char(&p, e, c))
				goto exit;
		}
		if (mlumsg_append_char(&p, e, '\n'))
			goto exit;
	}

exit:
	return p - buf;
}

static size_t mlumsg_print_time(u32 tsh, u32 tsl, char *buf)
{
	unsigned long rem_nsec;
	union time_nesc {
		u64 ts;
		struct {
			u32 t_nesch;
			u32 t_nescl;
		};
	};
	union time_nesc tnsec;

	tnsec.t_nesch = tsh;
	tnsec.t_nescl = tsl;

	rem_nsec = do_div(tnsec.ts, 1000000000);

	return sprintf(buf, "[%5lu.%06lu] ",
			(unsigned long)tnsec.ts, rem_nsec / 1000);
}

static u32 mlumsg_next(struct cn_mlumsg_iter *iter)
{
	struct mlumsg_log *msg = (struct mlumsg_log *)(iter->mlumsg_buf + iter->log_first_idx);

	if (!msg->len) {
		msg = (struct mlumsg_log *)iter->mlumsg_buf;
		return msg->len;
	}

	return iter->log_first_idx + msg->len;
}

static void *cndrv_mlumsg_start(struct seq_file *m, loff_t *pos)
{
	struct cn_mlumsg_iter *iter = m->private;

	update_mlumsg_iter(m, pos);

	if (iter->log_first_seq == iter->log_next_seq) {
		return NULL;
	}

	return m->private;
}

static void *cndrv_mlumsg_next(struct seq_file *m, void *p, loff_t *pos)
{
	struct cn_mlumsg_iter *iter = m->private;

	(*pos)++;
	if (iter->log_first_idx >= MLUMSG_SHM_SIZE) {
		cn_dev_err("log_first_idx out of bound, log_first_idx: %x", iter->log_first_idx);
		return 0;
	}
	update_mlumsg_iter(m, pos);

	if (iter->log_first_seq < iter->log_next_seq) {
		iter->log_first_idx = mlumsg_next(iter);
		iter->log_first_seq++;
	} else {
		return NULL;
	}

	return p;
}

static void cndrv_mlumsg_stop(struct seq_file *m, void *p)
{
}

static int cndrv_mlumsg_show(struct seq_file *m, void *p)
{
	struct mlumsg_log *msg = NULL;
	struct cn_mlumsg_iter *iter = m->private;
	void *text_buf;
	unsigned int buf_size = 512;
	size_t len = 0;
	u32 ts_nsech = 0;
	u32 ts_nsecl = 0;

	if (iter->log_first_idx >= MLUMSG_SHM_SIZE) {
		cn_dev_err("log_first_idx out of bound, log_first_idx = %x", iter->log_first_idx);
		return 0;
	}
	text_buf = cn_kzalloc(buf_size, GFP_KERNEL);
	if (!text_buf) {
		cn_dev_err("alloc text_buf error.");
		return -ENOMEM;
	}

	msg = (struct mlumsg_log *)(iter->mlumsg_buf + iter->log_first_idx);
	if ((msg->len != 0) && (iter->log_first_seq != iter->log_next_seq)) {
		ts_nsech = ioread32(&msg->ts_nsech);
		ts_nsecl = ioread32(&msg->ts_nsecl);
		len += mlumsg_print_time(ts_nsech, ts_nsecl, text_buf);
		len += mlumsg_print_ext_body(text_buf + len, buf_size - len,
				(char *)((char *)msg + sizeof(struct mlumsg_log) + msg->text_len),
				msg->dict_len,
				(char *)((char *)msg + sizeof(struct mlumsg_log)),
				msg->text_len);
		seq_printf(m, "%s", (char *)text_buf);
	}

	cn_kfree(text_buf);

	return 0;
}
PROC_PRIV_OP(cndrv_mlumsg);

static int cndrv_mlumsg_open(struct inode *inode, struct file *file)
{
	struct cn_mlumsg_iter *iter;
	struct cn_core_set *core = (struct cn_core_set *)PDE_DATA(inode);
	struct cn_proc_set *proc_set = (struct cn_proc_set *)core->proc_set;

	iter = __seq_open_private(file, &cndrv_mlumsg_op, sizeof(*iter));
	if (!iter)
		return -ENOMEM;

	iter->mlumsg_base = proc_set->msg_iter.mlumsg_base;
	iter->mlumsg_buf = proc_set->msg_iter.mlumsg_buf;
	iter->log_first_idx = *(u32 *)(iter->mlumsg_base);
	iter->log_next_idx = *(u32 *)(iter->mlumsg_base + sizeof(iter->log_first_idx));
	iter->log_first_seq = *(u64 *)(iter->mlumsg_base + sizeof(iter->log_first_idx) +
				sizeof(iter->log_next_idx));
	iter->log_next_seq = *(u64 *)(iter->mlumsg_base + sizeof(iter->log_first_idx) +
				sizeof(iter->log_next_idx) + sizeof(iter->log_first_seq));

	return 0;
}
PROC_SHOW_ATTRIBUTE_PRIV(cndrv_mlumsg);

void cn_core_show_mlumsg(struct cn_core_set *core)
{
	struct cn_proc_set *proc_set = core->proc_set;
	u32 first_idx, next_idx;
	u64 first_seq, next_seq;
	unsigned long mlumsg_base;
	unsigned long mlumsg_buf;
	u64 cur_first_seq;
	struct mlumsg_log *msg;
	char *text_buf;
	unsigned int buf_size = 512;

	mlumsg_base = proc_set->msg_iter.mlumsg_base;
	mlumsg_buf = proc_set->msg_iter.mlumsg_buf;
	first_idx = *(u32 *)(mlumsg_base);
	first_seq = *(u64 *)(mlumsg_base + sizeof(first_idx) + sizeof(next_idx));
	cur_first_seq = *(u64 *)(mlumsg_base + sizeof(first_idx) + sizeof(next_idx));

	next_idx = *(u32 *)(mlumsg_base + sizeof(first_idx));
	next_seq = *(u64 *)(mlumsg_base + sizeof(first_idx) +
			sizeof(next_idx) + sizeof(first_seq));
	if (first_seq == next_seq) {
		cn_dev_err("no log need output");
		return;
	}

	text_buf = cn_kzalloc(buf_size, GFP_KERNEL);
	if (!text_buf) {
		cn_dev_err("alloc text_buf error.");
		return;
	}

	while (first_seq < next_seq) {
		size_t len = 0;
		u32 ts_nsech, ts_nsecl;

		if (first_idx >= MLUMSG_SHM_SIZE) {
			cn_dev_err("log_first_idx out of bound, log_first_idx: %x", first_idx);
			goto exit;
		}

		msg = (struct mlumsg_log *)(mlumsg_buf + first_idx);
		if (msg->len != 0) {
			ts_nsech = ioread32(&msg->ts_nsech);
			ts_nsecl = ioread32(&msg->ts_nsecl);
			len += mlumsg_print_time(ts_nsech, ts_nsecl, text_buf);
			len += mlumsg_print_ext_body(text_buf + len, buf_size - len,
					(char *)((char *)msg + sizeof(struct mlumsg_log) + msg->text_len),
					msg->dict_len,
					(char *)((char *)msg + sizeof(struct mlumsg_log)),
					msg->text_len);
			text_buf[len] = 0;

			if (len > 0) {
				char *line = NULL;
				char *log_tmp = text_buf;

				/* printk.c LOG_LINE_MAX = 1024-32 */
				while ((line = strsep(&log_tmp, "\n")) != NULL) {
					if (line[0] == '\0' || !strlen(line))
						continue;
					cn_dev_core_err(core, "%s", line);
				}
			}
		}

		if (first_seq < cur_first_seq) {
			first_idx = *(u32 *)(mlumsg_base);
			first_seq = *(u64 *)(mlumsg_base + sizeof(first_idx) +
					sizeof(next_idx));
		}

		msg = (struct mlumsg_log *)(mlumsg_buf + first_idx);
		if (!msg->len) {
			msg = (struct mlumsg_log *)mlumsg_buf;
			first_idx = msg->len;
		} else {
			first_idx = first_idx + msg->len;
		}

		first_seq++;
	}
exit:
	cn_kfree(text_buf);
}

static int cn_mlumsg_set_init(struct cn_core_set *core)
{
#ifndef CONFIG_CNDRV_EDGE
	struct cn_proc_set *proc_set = core->proc_set;
	unsigned long mlumsg_base;
	int buf_offset;

	if (cn_core_is_vf(core))
		return 0;

	//if (cn_bus_data_outbound_able(core->bus_set)) {
	if (0) {
		mlumsg_base = cn_shm_get_host_addr_by_name(core,
			"kernel_debug_reserved_OB_DATA");
	} else {
		mlumsg_base = cn_shm_get_host_addr_by_name(core,
			"kernel_debug_reserved");
	}

	cn_dev_info("%s: mlumsg_base = %lx\n", __func__, mlumsg_base);

	if (mlumsg_base == (unsigned long)-1) {
		cn_dev_err("Failed to get host addr of kernel debug region\n");
		return -ENOMEM;
	}

	proc_set->msg_iter.mlumsg_base = mlumsg_base;
	buf_offset = sizeof(proc_set->msg_iter.log_first_idx)
			+ sizeof(proc_set->msg_iter.log_next_idx)
			+ sizeof(proc_set->msg_iter.log_first_seq)
			+ sizeof(proc_set->msg_iter.log_next_seq);
	proc_set->msg_iter.mlumsg_buf = proc_set->msg_iter.mlumsg_base + buf_offset;
#endif

	return 0;
}

static int cndrv_late_init_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	seq_printf(m, "late init flag: %d\n", core->late_init_flag);

	return 0;
}

static ssize_t cndrv_late_init_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *pos)
{
	char buf[4];
	ssize_t buf_size;
	struct cn_core_set *core = (struct cn_core_set *)PDE_DATA(file_inode(file));

	buf_size = min(count, (size_t)(sizeof(buf) - 1));

	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}

	buf[buf_size] = '\0';

	if (strcmp(buf, "1")) {
		set_serv_status(core);
	}

	return count;
}
PROC_WRITE_ATTRIBUTE(cndrv_late_init);

static int pinned_mem_info_show(struct seq_file *m, void *v)
{
	pinned_mem_info(m);
	return 0;
}
PROC_SHOW_ATTRIBUTE(pinned_mem_info);

static int cndrv_bang_printf_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	seq_printf(m, "kernel printf trigger timer is %dms\n", core->card_kprintf_timer);
	return 0;
}

static ssize_t cndrv_bang_printf_write(struct file *file,
		const char __user *user_buf, size_t count, loff_t *pos)
{
#define MAX_TRIGGER_TIMER_MS 2000
#define MIN_TRIGGER_TIMER_MS 1
	struct cn_core_set *core =
			(struct cn_core_set *)PDE_DATA(file_inode(file));
	int timer = 0;
	int ret = 0;

	ret = kstrtoint_from_user(user_buf, count, 0, &timer);
	if (ret) {
		cn_dev_core_err(core, "trigger get error.");
		return ret;
	}
	if (timer > MAX_TRIGGER_TIMER_MS) {
		core->card_kprintf_timer = MAX_TRIGGER_TIMER_MS;
	} else if (timer < MIN_TRIGGER_TIMER_MS) {
		core->card_kprintf_timer = MIN_TRIGGER_TIMER_MS;
	} else {
		core->card_kprintf_timer = timer;
	}
	ret = cn_kprintf_set(core);
	if (ret) {
		cn_dev_core_err(core, "kernel printf info set error.");
		return ret;
	}
	return count;
}

PROC_WRITE_ATTRIBUTE(cndrv_bang_printf);

static int cndrv_exclusive_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	int status = 0;

	if (cn_core_get_execute_mode(core) == COMPUTEMODE_EXCLUSIVE_PROCESS)
		status = 1;

	seq_printf(m, "%d\n", status);

	return 0;
}

static ssize_t cndrv_exclusive_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	int ret;
	unsigned long udata = 0;
	unsigned int mode = 0;
	struct cn_core_set *core =
			(struct cn_core_set *)PDE_DATA(file_inode(file));

	ret = kstrtoul_from_user(user_buf, count, 10, &udata);
	if (ret)
		return ret;

	if (udata) {
		mode = COMPUTEMODE_EXCLUSIVE_PROCESS;
	} else {
		mode = COMPUTEMODE_DEFAULT;
	}
	ret = cn_core_set_execute_mode(core, mode);
	if (ret)
		return ret;

	return count;
}
PROC_WRITE_ATTRIBUTE(cndrv_exclusive);

#ifdef CONFIG_CNDRV_EDGE
static int lowpower_task_mode_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	cn_lpm_info_show(m, core);
	return 0;
}

static ssize_t lowpower_task_mode_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core = (struct cn_core_set *)PDE_DATA(file_inode(file));
	struct cn_proc_set *proc_set = (struct cn_proc_set *)core->proc_set;
	int ret = 0;
	int cmd;

	ret = kstrtoint_from_user(user_buf, count, 10, &cmd);
	if (ret)
		return ret;

	ret = (cmd == 1) ? cn_sbts_lpm_mode_switch_to_task(core) :
		cn_sbts_lpm_mode_switch_to_user(core);
	if (ret) {
		cn_dev_proc_info(proc_set, "cmd %d set switch lowpower mode failed", cmd);
		return -EINVAL;
	}

	return count;
}

static int lowpower_task_mode_open(struct inode *inode, struct file *file)
{
	return single_open(file, lowpower_task_mode_show, PDE_DATA(inode));
}

static int lowpower_task_mode_release(struct inode *inode, struct file *file)
{
	return single_release(inode, file);
}

#if KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE
static const struct file_operations lowpower_task_mode_fops = {
	.owner		= THIS_MODULE,
	.open		= lowpower_task_mode_open,
	.read		= seq_read,
	.write		= lowpower_task_mode_write,
	.llseek		= seq_lseek,
	.release	= lowpower_task_mode_release,
};
#else
static const struct proc_ops lowpower_task_mode_fops = {
	.proc_open	= lowpower_task_mode_open,
	.proc_read	= seq_read,
	.proc_write	= lowpower_task_mode_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= lowpower_task_mode_release,
};
#endif
#endif

static int cndrv_idc_debug_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	return cn_sbts_idc_debug_show(core, m);
}

static ssize_t cndrv_idc_debug_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core =
			(struct cn_core_set *)PDE_DATA(file_inode(file));

	cn_sbts_idc_debug_write(core, user_buf, count);

	return count;
}
PROC_WRITE_ATTRIBUTE(cndrv_idc_debug);

static int cndrv_hostfn_info_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	return cn_hostfn_record_show(core, m);
}
PROC_SHOW_ATTRIBUTE(cndrv_hostfn_info);

static int cndrv_unotify_debug_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	return cn_sbts_unotify_debug_show(core, m);
}

static ssize_t cndrv_unotify_debug_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core =
			(struct cn_core_set *)PDE_DATA(file_inode(file));

	cn_sbts_unotify_debug_write(core, user_buf, count);

	return count;
}
PROC_WRITE_ATTRIBUTE(cndrv_unotify_debug);

static int cndrv_task_topo_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	return cn_sbts_topo_debug_show(core, m);
}

static ssize_t cndrv_task_topo_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core =
			(struct cn_core_set *)PDE_DATA(file_inode(file));

	cn_sbts_topo_debug_write(core, user_buf, count);

	return count;
}
PROC_WRITE_ATTRIBUTE(cndrv_task_topo);

static int cndrv_sbts_shm_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	return cn_sbts_shm_debug_show(core, m);
}

static ssize_t cndrv_sbts_shm_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core =
			(struct cn_core_set *)PDE_DATA(file_inode(file));

	cn_sbts_shm_debug_write(core, user_buf, count);

	return count;
}
PROC_WRITE_ATTRIBUTE(cndrv_sbts_shm);

static int cndrv_freq_cap_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	bool flag = core->drv_support_lt_freq_cap && core->fw_support_lt_freq_cap;

	seq_printf(m, "FW Support LT Freq Capping  : [%s]\n", core->fw_support_lt_freq_cap ? "Yes" : "No");
	seq_printf(m, "DRV Support LT Freq Capping : [%s]\n", core->drv_support_lt_freq_cap ? "Yes" : "No");
	seq_printf(m, "Current Freq Capping Mode   : [%s]\n", flag ? "LT" : "EDPP");
	return 0;
}
PROC_SHOW_ATTRIBUTE(cndrv_freq_cap);

static int cndrv_reg_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_proc_set *proc_set = (struct cn_proc_set *)core->proc_set;
	unsigned long reg_size;
	unsigned long offsize;
	unsigned long write_data;

	reg_size = cn_bus_get_reg_size(core->bus_set);
	if (core->device_id == MLUID_370) {
		reg_size *= 4; /* die to die 128*4=512MB*/
	}
	if (core->device_id == MLUID_590 || core->device_id == MLUID_580) {
		reg_size *= 8; /* 1024MB*/
	}
	if (proc_set->proc_reg.show == PROC_HELP) {
		seq_printf(m, "usage: read reg by \"echo \"read offsize(0~%ldM)\""
				" > reg | cat reg\"\n", reg_size/M_SIZE);
		seq_printf(m, "usage: write reg by \"echo \"write offsize(0~%ldM) "
				"data(4byte)\" > reg | cat reg\"\n", reg_size/M_SIZE);
	} else if (proc_set->proc_reg.show == PROC_READ) {
		seq_printf(m, "0x%08lx\n", proc_set->proc_reg.data);
	} else if (proc_set->proc_reg.show == PROC_WRITE) {
		offsize = proc_set->proc_reg.offsize;
		write_data = proc_set->proc_reg.data;
		seq_printf(m, "reg:%#lx,write data:%#lx,read data:%#x\n",
		offsize, write_data, reg_read32(core->bus_set, offsize));
	} else {
		seq_puts(m, "unknown mannal, for HELP by \" cat reg \"\n");
	}
	proc_set->proc_reg.data = 0;
	proc_set->proc_reg.offsize = 0;
	proc_set->proc_reg.show = PROC_HELP;

	return 0;
}

static ssize_t reg_read(struct cn_core_set *core, char *buf,
							unsigned long reg_size)
{
	char *temp;
	char *p = buf;
	unsigned long read_offsize = 0;
	struct cn_proc_set *proc_set = core->proc_set;

	/* jump 'read' key */
	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "reg offsize error");
		return -1;
	}
	if (kstrtoul(temp, 16, &read_offsize)) {
		cn_dev_proc_err(proc_set, "reg offsize error");
		return -1;
	} else if (read_offsize > reg_size - 4) {
		cn_dev_proc_err(proc_set, "reg offsize is too large");
		return -1;
	}
	proc_set->proc_reg.show = PROC_READ;
	proc_set->proc_reg.offsize = read_offsize;
	proc_set->proc_reg.data = reg_read32(core->bus_set, read_offsize);

	return 0;
}

static ssize_t reg_write(struct cn_core_set *core, char *buf,
							unsigned long reg_size)
{
	char *temp;
	char *p = buf;
	unsigned long write_offsize = 0;
	unsigned long write_data = 0;
	struct cn_proc_set *proc_set = core->proc_set;

	/* jump 'write' key */
	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "reg offsize error");
		return -1;
	}
	if (kstrtoul(temp, 16, &write_offsize)) {
		cn_dev_proc_err(proc_set, "reg offsize error");
		return -1;
	} else if (write_offsize > reg_size - 4) {
		cn_dev_proc_err(proc_set, "reg offsize is too large");
		return -1;
	}

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "reg data error");
		return -1;
	}
	if (kstrtoul(temp, 16, &write_data)) {
		cn_dev_proc_err(proc_set, "reg data error");
		return -1;
	}
	write_data = 0xffffffff & write_data;
	proc_set->proc_reg.show = PROC_WRITE;
	proc_set->proc_reg.offsize = write_offsize;
	proc_set->proc_reg.data = write_data;
	reg_write32(core->bus_set, write_offsize, write_data);

	return 0;
}

static ssize_t cndrv_reg_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *pos)
{
	char buf[128];
	ssize_t buf_size;
	struct cn_core_set *core =
			(struct cn_core_set *)(file_inode(file)->i_private);
	struct cn_proc_set *proc_set = core->proc_set;
	unsigned long reg_size;

	reg_size = cn_bus_get_reg_size(core->bus_set);
	if (core->device_id == MLUID_370) {
		reg_size *= 4; /* die to die 128*4=512MB*/
	}
	if (core->device_id == MLUID_590 || core->device_id == MLUID_580) {
		reg_size *= 8; /* 1024MB*/
	}
	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_proc_debug(proc_set, "user command:%s", buf);

	if (strstr(buf, "read")) {
		reg_read(core, buf, reg_size);
	} else if (strstr(buf, "write")) {
		reg_write(core, buf, reg_size);
	} else {
		cn_dev_info("usage:");
		cn_dev_info("echo \"read offsize(< reg_size:0x%lx - 4)\" > reg",
					reg_size);
		cn_dev_info("echo \"write offsize(< reg_size:0x%lx - 4)",
					reg_size);
		cn_dev_info("data(4byte)\" > reg");
	}
	return buf_size;
}
DEBUGFS_WRITE_ATTRIBUTE(cndrv_reg);

static int cndrv_mem_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_proc_set *proc_set = core->proc_set;
	unsigned long mem_size;
	unsigned long addr;
	unsigned long write_data;

	mem_size = cn_bus_get_mem_size(core->bus_set, 0);
	if (proc_set->proc_mem.show == PROC_HELP) {
		seq_printf(m, "usage: read mem by \"echo \"read addr(0~%ldM)\""
					" > mem ; cat mem\"\n", mem_size/M_SIZE);
		seq_printf(m, "usage: write mem by \"echo \"write addr(0~%ldM) "
				"data(4byte)\" > mem ; cat mem\"\n", mem_size/M_SIZE);
		seq_puts(m, "usage: alloc sw by \"echo \"swalloc addr\" > mem\"\n");
		seq_puts(m, "usage: free sw by \"echo \"swfree addr\" > mem\"\n");
		seq_puts(m, "usage: trigger sw by \"echo \"swtrigger addr val\" > mem\"\n");
		seq_puts(m, "usage: get sram base by echo srambase > mem ; cat mem\n");
	} else if (proc_set->proc_mem.show == PROC_READ) {
		seq_printf(m, "0x%08lx\n", proc_set->proc_mem.data);
	} else if (proc_set->proc_mem.show == PROC_WRITE) {
		addr = proc_set->proc_mem.addr;
		write_data = proc_set->proc_mem.data;
		seq_printf(m, "mem:%#lx,write data:%#lx,read data:%#x\n",
			addr, write_data, mem_read32(core->bus_set, addr));
	} else if (proc_set->proc_mem.show == PROC_SW_ALLOC) {
		seq_printf(m, "%#x\n", proc_set->proc_mem.sw_id);
	} else if (proc_set->proc_mem.show == PROC_SRAM_BASE) {
		seq_printf(m, "%#x\n", proc_set->proc_mem.sram_offset);
	} else {
		seq_puts(m, "unknown mannal, for HELP by \" cat mem \"\n");
	}
	proc_set->proc_mem.addr = 0;
	proc_set->proc_mem.data = 0;
	proc_set->proc_mem.show = PROC_HELP;

	return 0;
}

static ssize_t mem_read(struct cn_core_set *core, char *buf,
							unsigned long mem_size)
{
	char *temp;
	char *p = buf;
	unsigned long read_addr = 0;
	struct cn_proc_set *proc_set = core->proc_set;

	/* jump 'read' key */
	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "mem addr error");
		return -1;
	}
	if (kstrtoul(temp, 16, &read_addr)) {
		cn_dev_proc_err(proc_set, "mem addr error");
		return -1;
	} else if (read_addr > mem_size - 4) {
		cn_dev_proc_err(proc_set, "mem addr is too large");
		return -1;
	}
	proc_set->proc_mem.show = PROC_READ;
	proc_set->proc_mem.addr = read_addr;
	proc_set->proc_mem.data = mem_read32(core->bus_set, read_addr);

	return 0;
}

static ssize_t mem_write(struct cn_core_set *core, char *buf,
							unsigned long mem_size)
{
	char *temp;
	char *p = buf;
	unsigned long write_addr = 0;
	unsigned long write_data = 0;
	struct cn_proc_set *proc_set = core->proc_set;

	/* jump 'write' key */
	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "mem addr error");
		return -1;
	}
	if (kstrtoul(temp, 16, &write_addr)) {
		cn_dev_proc_err(proc_set, "mem addr error");
		return -1;
	} else if (write_addr > mem_size - 4) {
		cn_dev_proc_err(proc_set, "mem addr is too large");
		return -1;
	}

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "mem data error");
		return -1;
	}
	if (kstrtoul(temp, 16, &write_data)) {
		cn_dev_proc_err(proc_set, "mem data error");
		return -1;
	}
	write_data = 0xffffffff & write_data;
	proc_set->proc_mem.show = PROC_WRITE;
	proc_set->proc_mem.addr = write_addr;
	proc_set->proc_mem.data = write_data;
	mem_write32(core->bus_set, write_addr, write_data);

	return 0;
}

static ssize_t mem_sw_alloc(struct cn_core_set *core, char *buf)
{
	struct cn_proc_set *proc_set = core->proc_set;
	char *temp;
	char *p = buf;
	u64 flag_addr;
	int ret;

	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "flag addr error");
		return -1;
	}
	if (kstrtou64(temp, 16, &flag_addr)) {
		cn_dev_proc_err(proc_set, "flag addr error");
		return -1;
	}
	ret = cn_bus_sync_write_alloc(core->bus_set, flag_addr);
	if (ret)
		cn_dev_proc_err(proc_set, "swalloc error = %d", ret);

	proc_set->proc_mem.show = PROC_SW_ALLOC;

	return ret;
}

static ssize_t mem_sw_free(struct cn_core_set *core, char *buf)
{
	struct cn_proc_set *proc_set = core->proc_set;
	char *temp;
	char *p = buf;
	u64 flag_addr;

	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "flag addr error");
		return -1;
	}
	if (kstrtou64(temp, 16, &flag_addr)) {
		cn_dev_proc_err(proc_set, "flag addr error");
		return -1;
	}
	cn_bus_sync_write_free(core->bus_set, flag_addr);

	return 0;
}


static ssize_t mem_sw_trigger(struct cn_core_set *core, char *buf)
{
	struct cn_proc_set *proc_set = core->proc_set;
	char *temp;
	char *p = buf;
	u32 value;
	u64 dev_pa;

	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "flag addr error");
		return -1;
	}
	if (kstrtou64(temp, 16, &dev_pa)) {
		cn_dev_proc_err(proc_set, "flag addr error");
		return -1;
	}
	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "value error");
		return -1;
	}
	if (kstrtou32(temp, 16, &value)) {
		cn_dev_proc_err(proc_set, "value error");
		return -1;
	}
	cn_bus_sync_write_val(core->bus_set, dev_pa, value);

	return 0;
}

static ssize_t mem_sram_base(struct cn_core_set *core)
{
	struct cn_proc_set *proc_set = core->proc_set;
	unsigned long sram_host_kva;
	unsigned long sharemem_kva;

	sram_host_kva = cn_shm_get_host_addr_by_name(core, "sram_reserved");
	sharemem_kva = cn_bus_get_mem_virtaddr(core->bus_set, 0);

	proc_set->proc_mem.sram_offset = (u32)(sram_host_kva - sharemem_kva);
	proc_set->proc_mem.show = PROC_SRAM_BASE;

	return 0;
}

static ssize_t cndrv_mem_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *pos)
{
	char buf[128];
	ssize_t buf_size;
	struct cn_core_set *core =
			(struct cn_core_set *)(file_inode(file)->i_private);
	struct cn_proc_set *proc_set = core->proc_set;
	unsigned long mem_size;

	mem_size = cn_bus_get_mem_size(core->bus_set, 0);
	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_proc_debug(proc_set, "user command:%s", buf);

	if (strstr(buf, "read")) {
		mem_read(core, buf, mem_size);
	} else if (strstr(buf, "write")) {
		mem_write(core, buf, mem_size);
	} else if (strstr(buf, "swalloc")) {
		mem_sw_alloc(core, buf);
	} else if (strstr(buf, "swtrigger")) {
		mem_sw_trigger(core, buf);
	} else if (strstr(buf, "swfree")) {
		mem_sw_free(core, buf);
	} else if (strstr(buf, "srambase")) {
		mem_sram_base(core);
	} else {
		cn_dev_info("usage:");
		cn_dev_info("echo \"read addr(< mem_size:0x%lx - 4)\" > mem",
								mem_size);
		cn_dev_info("echo \"write addr(< mem_size:0x%lx - 4)", mem_size);
		cn_dev_info("data(4byte)\" > mem");
	}

	return buf_size;
}
DEBUGFS_WRITE_ATTRIBUTE(cndrv_mem);

static ssize_t cndrv_cn_mem_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *pos)
{
	char buf[128];
	ssize_t buf_size;
	struct cn_core_set *core =
				(struct cn_core_set *)PDE_DATA(file_inode(file));

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_core_debug(core, "user command:%s", buf);

	if (cn_mem_proc_mem_ctrl(core, buf))
		return -EINVAL;

	return buf_size;
}

static int cndrv_cn_mem_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	return cn_mem_proc_mem_show(core, m);
}
PROC_WRITE_ATTRIBUTE(cndrv_cn_mem);

static ssize_t cndrv_cn_mem_dump_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *pos)
{
	char buf[128];
	ssize_t buf_size;
	struct cn_core_set *core =
				(struct cn_core_set *)PDE_DATA(file_inode(file));

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_core_debug(core, "user command:%s", buf);

	if (cn_mem_proc_dump_ctrl(core, buf))
		return -EINVAL;

	return count;
}

static int cndrv_cn_mem_dump_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	return cn_mem_proc_dump_info(core, m);
}
PROC_WRITE_ATTRIBUTE_SIZE(cndrv_cn_mem_dump);

static int gdma_inject_error(struct cn_core_set *core, char *buf)
{
	char *temp;
	char *p = buf;
	int ret = 0;
	u64 inject_ecc_src;

	/* jump cmd key */
	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_core_err(core, "gdma cmd error, please cat gdma for help");
		return -1;
	}

	ret = kstrtou64(temp, 16, &inject_ecc_src);
	if (ret)
		return ret;

	ret = cn_gdma_assist(core, GDMA_ASSIST_SET_INJECT_ERROR_SRC, (void *)&inject_ecc_src, NULL);
	if (ret)
		return ret;

	cn_dev_info("gdma_inject_error:%#llx", inject_ecc_src);

	return 0;
}

static int gdma_inject_ecc(struct cn_core_set *core, char *buf)
{
	char *temp;
	char *p = buf;
	int ret = 0;
	u8 inject_ecc_error;

	/* jump cmd key */
	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_core_err(core, "gdma cmd error, please cat gdma for help");
		return -1;
	}

	ret = kstrtou8(temp, 16, &inject_ecc_error);
	if (ret)
		return ret;

	ret = cn_gdma_assist(core, GDMA_ASSIST_SET_INJECT_ECC_ERROR, (void *)&inject_ecc_error, NULL);
	if (ret)
		return ret;

	cn_dev_info("gdma_inject_ecc:%#x", inject_ecc_error);

	cn_gdma_assist(core, GDMA_ASSIST_ACT_CHNL_ECC_INJECT, NULL, NULL);

	return 0;
}

static int gdma_poll_size(struct cn_core_set *core, char *buf)
{
	char *temp;
	char *p = buf;
	int ret = 0;
	u32 poll_size;

	/* jump cmd key */
	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_core_err(core, "gdma cmd error, please cat gdma for help");
		return -1;
	}

	ret = kstrtou32(temp, 16, &poll_size);
	if (ret)
		return ret;

	ret = cn_gdma_assist(core, GDMA_ASSIST_SET_POLL_SIZE, (void *)&poll_size, NULL);
	if (ret)
		return ret;

	cn_dev_info("gdma_poll_size:0x%x", poll_size);

	return 0;
}

static int gdma_dbg_print(struct cn_core_set *core, char *buf)
{
	char *temp;
	char *p = buf;
	int ret = 0;
	u8 debug_print;

	/* jump cmd key */
	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_core_err(core, "gdma cmd error, please cat gdma for help");
		return -1;
	}

	ret = kstrtou8(temp, 16, &debug_print);
	if (ret)
		return ret;

	ret = cn_gdma_assist(core, GDMA_ASSIST_SET_DEBUG_PRINT, (void *)&debug_print, NULL);
	if (ret)
		return ret;

	cn_dev_info("gdma_dbg_print:%#x\n", debug_print);

	return 0;
}

static int gdma_reg_dump(struct cn_core_set *core, char *buf)
{
	char *temp;
	char *p = buf;
	int ret = 0;
	int ctrl_index = 0;
	int chan_index = 0;
	u32 info_ctrl_num;
	u32 info_ctrl_chan_num;
	int ctrl_chan_index = 0;

	cn_gdma_assist(core, GDMA_ASSIST_GET_INFO_CTRL_NUM, NULL, (void *)&info_ctrl_num);
	cn_gdma_assist(core, GDMA_ASSIST_GET_INFO_CTRL_CHAN_NUM, NULL, (void *)&info_ctrl_chan_num);

	/* jump cmd key */
	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_core_err(core, "gdma cmd error, please cat gdma for help");
		return -1;
	}

	ret = kstrtouint(temp, 16, &ctrl_index);
	if (ret)
		return ret;

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_core_err(core, "gdma cmd error, please cat gdma for help");
		return -1;
	}

	ret = kstrtouint(temp, 16, &chan_index);
	if (ret)
		return ret;

	if (ctrl_index >= info_ctrl_num ||
		chan_index >= info_ctrl_chan_num) {
		cn_dev_core_err(core, "gdma index %d or chan index %d invalid",
			ctrl_index, chan_index);
		cn_dev_core_err(core, "system has %d gdmac with per %d channel",
			info_ctrl_num, info_ctrl_chan_num);
		return -1;
	}

	cn_gdma_assist(core, GDMA_ASSIST_ACT_CTRL_REG_DUMP, (void *)&ctrl_index, NULL);
	ctrl_chan_index = (ctrl_index << 8) | (chan_index & 0xFF);
	cn_gdma_assist(core, GDMA_ASSIST_ACT_CHNL_REG_DUMP, (void *)&ctrl_chan_index, NULL);

	return 0;
}

static int cndrv_gdma_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	cn_gdma_assist(core, GDMA_ASSIST_GET_STAT_INFO, (void *)m, NULL);

	seq_puts(m, "\nusage: \"echo cmd > gdma\"\n");
	seq_puts(m, "cmd: inject_error [error_src_addr]\n");
	seq_puts(m, "     inject_ecc   [mask]\n");
	seq_puts(m, "     poll_size    [size]\n");
	seq_puts(m, "     dbg_print    [mask]\n");
	seq_puts(m, "     reg_dump     [gdmac index] [chan index]\n");

	return 0;
}

static ssize_t cndrv_gdma_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	char buf[128];
	ssize_t buf_size;
	struct cn_core_set *core =
		(struct cn_core_set *)(file_inode(file)->i_private);

	buf_size = min(count, (size_t)(sizeof(buf) - 1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_core_debug(core, "user command:%s", buf);

	if (strstr(buf, "inject_error")) {
		gdma_inject_error(core, buf);
	} else if (strstr(buf, "inject_ecc")) {
		gdma_inject_ecc(core, buf);
	} else if (strstr(buf, "poll_size")) {
		gdma_poll_size(core, buf);
	} else if (strstr(buf, "dbg_print")) {
		gdma_dbg_print(core, buf);
	} else if (strstr(buf, "reg_dump")) {
		gdma_reg_dump(core, buf);
	} else {
		cn_dev_core_info(core, "cmd is illegal, please cat gdma for help");
	}

	return buf_size;
}
DEBUGFS_WRITE_ATTRIBUTE(cndrv_gdma);

static int print_debug_show(struct seq_file *m, void *v)
{
	struct print_debug_info_s *debug_info = NULL;

	debug_info = &print_debug_info[0];
	seq_printf(m, "usage: \"echo mask > cndrv_debug\"\n");
	while (debug_info->name) {
		seq_printf(m, "mask: 0x%04x : %s\n", debug_info->bit_mask, debug_info->name);
		debug_info += 1;
	}

	return 0;
}

static ssize_t print_debug_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	int ret;
	unsigned long udata;
	struct cn_core_set *core =
			(struct cn_core_set *)(file_inode(file)->i_private);
	struct print_debug_info_s *debug_info = NULL;

	debug_info = &print_debug_info[0];

	ret = kstrtoul_from_user(user_buf, count, 16, &udata);
	if (ret)
		return ret;

	print_debug = udata;

	cn_dev_core_info(core, "print debug : 0x%04x", print_debug);
	while (debug_info->name) {
		if (debug_info->bit_mask & print_debug) {
			cn_dev_core_info(core, "%-16s: open", debug_info->name);
		} else {
			cn_dev_core_info(core, "%-16s: close", debug_info->name);
		}
		debug_info += 1;
	}

	return count;
}
DEBUGFS_WRITE_ATTRIBUTE(print_debug);

static int cndrv_debug_show(struct seq_file *m, void *v)
{
	seq_puts(m, "usage: \"echo cmd > cndrv_debug\"\n");
	seq_puts(m, "cmd: user_trace_enable             :  enable get user trace when ioctl failed\n");
	seq_puts(m, "     user_trace_disable            :  disable get user trace when ioctl failed\n");
	seq_puts(m, "     force_p2p_xchg_enable         :  enable to force p2p exchange\n");
	seq_puts(m, "     force_p2p_xchg_disable        :  disable to force p2p exchange\n");
	seq_puts(m, "     af_enable                     :  enable pcie dma async free\n");
	seq_puts(m, "     af_disable                    :  disable pcie dma async free\n");
	seq_puts(m, "     set_dma_err_inject_flag       :  let driver do retransfer by driping manual error\n");
	seq_puts(m, "     hostmemsize_check_enable      :  enable host mem size check\n");
	seq_puts(m, "     hostmemsize_check_disable     :  disable host mem size check\n");
	seq_puts(m, "     des_scatter_set               :  enable dma descripter scatter 0:disalbe 1-n: n*page_size\n");
	seq_puts(m, "     inject_heartbeat_error        :  inject heartbeat error\n");
	seq_puts(m, "     cancel_heartbeat_error        :  cancel heartbeat error\n");
	seq_puts(m, "     show_async_htable             :  show async dma hash table used cnt\n");
	seq_puts(m, "     dump_dma_info                 :  dump dma software info\n");

	return 0;
}

static ssize_t cndrv_debug_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	char buf[128];
	ssize_t buf_size;
	unsigned long set_value = 0;
	char *p = buf;
	struct cn_core_set *core =
		(struct cn_core_set *)(file_inode(file)->i_private);

	buf_size = min(count, (size_t)(sizeof(buf) - 1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_core_debug(core, "user command:%s", buf);

	if (strstr(buf, "user_trace_enable")) {
		core->user_trace_enable = 1;
		cn_dev_core_info(core, "user_trace_enable");
	} else if (strstr(buf, "user_trace_disable")) {
		core->user_trace_enable = 0;
		cn_dev_core_info(core, "user_trace_disable");
	} else if (strstr(buf, "force_p2p_xchg_enable")) {
		cn_bus_force_p2p_xchg(core->bus_set, 1);
		cn_dev_core_info(core, "force_p2p_xchg_enable");
	} else if (strstr(buf, "force_p2p_xchg_disable")) {
		cn_bus_force_p2p_xchg(core->bus_set, 0);
		cn_dev_core_info(core, "force_p2p_xchg_disable");
	} else if (strstr(buf, "af_enable")) {
		cn_bus_dma_af_ctrl(core->bus_set, 1);
	} else if (strstr(buf, "af_disable")) {
		cn_bus_dma_af_ctrl(core->bus_set, 0);
	} else if (strstr(buf, "set_dma_err_inject_flag")) {
		cn_bus_set_dma_err_inject_flag(core->bus_set, 1);
		cn_dev_core_info(core, "set_dma_err_inject_flag");
	} else if (strstr(buf, "hostmemsize_check_enable")) {
		dma_hmsc_enable = 1;
		cn_dev_core_info(core, "hostmemsize_check_enable");
	} else if (strstr(buf, "hostmemsize_check_disable")) {
		dma_hmsc_enable = 0;
		cn_dev_core_info(core, "hostmemsize_check_disable");
	} else if (strstr(buf, "des_scatter_set")) {
		strsep(&p, " ");
		if (kstrtoul(p, 10, &set_value)) {
			cn_dev_core_info(core, "change set value error");
		} else {
			if (set_value < 257) {
				cn_dev_core_info(core, "des_scatter_set value = %lu", set_value);
				cn_bus_dma_des_set(core->bus_set, set_value);
			} else {
				cn_dev_core_info(core, "des_scatter_set value = %lu invalid", set_value);
			}
		}
	} else if (strstr(buf, "inject_heartbeat_error")) {
		core->heartbeat_error = 1;
		cn_dev_core_info(core, "inject_heartbeat_error");
	} else if (strstr(buf, "cancel_heartbeat_error")) {
		core->heartbeat_error = 0;
		cn_dev_core_info(core, "cancel_heartbeat_error");
	} else if (strstr(buf, "show_async_htable")) {
		cn_bus_get_async_htable(core->bus_set);
	} else if (strstr(buf, "dump_dma_info")) {
		cn_bus_dump_dma_info(core->bus_set);
	} else {
		cn_dev_core_info(core, "cmd is illegal, please cat cndrv_debug for help");
	}

	return buf_size;
}
DEBUGFS_WRITE_ATTRIBUTE(cndrv_debug);

static int cndrv_debugfs_show(struct seq_file *m, void *v)
{
	seq_printf(m, "usage: \"echo debug > debugfs\"\n");

	return 0;
}

static ssize_t cndrv_debugfs_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *pos)
{
	char buf[128];
	ssize_t buf_size;
	struct cn_core_set *core =
			(struct cn_core_set *)(file_inode(file)->i_private);
	unsigned long mem_size;

	mem_size = cn_bus_get_mem_size(core->bus_set, 0);
	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_core_debug(core, "user command:%s", buf);

	if (strstr(buf, "debug")) {
		cn_mem_debugfs(core);
	} else {
		cn_dev_info("help:");
		cn_dev_info("use echo \"write cmd > debugfs. now only support debug");
	}
	return buf_size;
}
DEBUGFS_WRITE_ATTRIBUTE(cndrv_debugfs);

static ssize_t
cndrv_codec_turbo_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *pos)
{
	char buf[128];
	ssize_t buf_size;
	struct cn_core_set *core =
				(struct cn_core_set *)PDE_DATA(file_inode(file));

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}

	buf[buf_size] = '\0';
	cn_dev_core_debug(core, "user command:%s", buf);

	if (strstr(buf, "1")) {
		cn_mem_extension(core, 1);
	} else if (strstr(buf, "0")) {
		cn_mem_extension(core, 0);
	}

	return buf_size;
}

static int cndrv_codec_turbo_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	int status = 0;

	if (core->mem_extension & 0x01)
		status = 1;

	seq_printf(m, "CODEC Turbo : %s\n", status ? "ENABLE" : "DISABLE");
	seq_printf(m, "usage: echo %d > codec_turbo to %s mem extension\n",
				(!status), (!status) ? "ENABLE" : "DISABLE");

	return 0;
}
PROC_WRITE_ATTRIBUTE(cndrv_codec_turbo);

static int cndrv_pid_info_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_proc_set *proc_set = core->proc_set;
	struct pid_info_s *pid_info_node;
	struct proc_mem_info *process_info;
	struct pid_info_s tmp;
	u32 process_num;
	u16 smlu_instance_id = 0; /* 0 represents no specific instance */
	int i = 0;

	tmp.tgid = current->tgid;
	tmp.active_ns = task_active_pid_ns(current);
	tmp.active_pid = task_tgid_nr_ns(current, tmp.active_ns);

	process_num = core->open_count;
	if (process_num) {
		process_info = cn_kcalloc(process_num,
			sizeof(struct proc_mem_info), GFP_KERNEL);
		if (!process_info) {
			cn_dev_proc_err(proc_set, "malloc for buffer fail");
			return -ENOMEM;
		}
		/* try get from smlu first */
		if (cn_smlu_query_namespace_pid_infos(core, mem_cgrp_id, smlu_instance_id,
				&process_num, (struct smlu_proc_info *)process_info))
			goto mem_stat;
		else {
			for (i = 0; i < process_num; i++) {
				process_info[i].phy_memused = process_info[i].phy_memused >> 20;
			}
			goto done;
		}

mem_stat:
		i = 0;
		spin_lock(&core->pid_info_lock);
		list_for_each_entry(pid_info_node, &core->pid_head, pid_list) {
			if (cn_check_curproc_is_docker(&tmp) && tmp.active_ns != pid_info_node->active_ns)
				continue;
			if (tmp.tgid == tmp.active_pid) {
				process_info[i].pid = pid_info_node->tgid;
			} else {
				process_info[i].pid = pid_info_node->active_pid;
			}
			process_info[i].phy_memused =
				pid_info_node->phy_usedsize >> 20;
			cn_dev_proc_debug(proc_set, "%d:%d ", i, process_info[i].pid);
			i++;
			if (i >= process_num) {
				break;
			}
		}
		spin_unlock(&core->pid_info_lock);
		if (i < process_num) {
			process_num = i;
		}
done:
		seq_puts(m, "PID      phy_mem_used(MB)\n");
		for (i = 0; i < process_num; i++) {
			seq_printf(m, "%-8d %llu\n",
						process_info[i].pid, process_info[i].phy_memused);
		}

		cn_kfree(process_info);
	} else {
		seq_puts(m, "No process running now!\n");
	}

	return 0;
}
DEBUGFS_SHOW_ATTRIBUTE(cndrv_pid_info);

static int cndrv_cndev_show(struct seq_file *m, void *v)
{
	/* mcu debug */
	mcu_show_info(m, v);

	/* cndev debug */
	cndev_show_info(m, v);

	/* xid debug */
	xid_show_info(m, v);

	return 0;
}

static ssize_t cndrv_cndev_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	int ret;
	unsigned long udata;
	struct cn_core_set *core =
			(struct cn_core_set *)(file_inode(file)->i_private);
	struct cn_proc_set *proc_set = core->proc_set;

	ret = kstrtoul_from_user(user_buf, count, 10, &udata);
	if (ret)
		return ret;

	cndev_print_debug_set(core, udata);
	cn_dev_proc_info(proc_set, "cndev print debug: %s\n",
		udata != 0 ? "open" : "close");

	return count;
}
DEBUGFS_WRITE_ATTRIBUTE(cndrv_cndev);

static int cndrv_retire_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	cn_mem_proc_show_pgretire(core, m);

	return 0;
}

static int retire_irq_inject(struct cn_core_set *core, char *buf)
{
	char *temp;
	char *p = buf;
	unsigned int max_sys_mc_num = 0;
	u32 sys_mc_num = 0;
	u32 mc_state = 0;
	u32 ecc_addr = 0;
	struct cn_proc_set *proc_set = core->proc_set;
	int ret = 0;

	ret = cn_mcc_get_sys_mc_nums(core, &max_sys_mc_num);
	if (ret < 0) {
		cn_dev_proc_err(proc_set, "current platform not support retire irq inject");
		return -1;
	}

	/* jump 'irqinject' key */
	temp = strsep(&p, " ");

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "irqinject parameter error");
		return -1;
	}
	if (kstrtou32(temp, 10, &sys_mc_num)) {
		cn_dev_proc_err(proc_set, "sys_mc_num error");
		return -1;
	} else if (sys_mc_num > max_sys_mc_num) {
		cn_dev_proc_err(proc_set, "sys_mc_num(0~%d):%d is illegal",
				max_sys_mc_num - 1, sys_mc_num);
		return -1;
	}

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "irqinject parameter error");
		return -1;
	}
	if (kstrtou32(temp, 10, &mc_state)) {
		cn_dev_proc_err(proc_set, "mc_state error");
		return -1;
	} else if (mc_state != ECC_BIT_1 && mc_state != ECC_BIT_2 &&
						mc_state != ECC_BIT_1_2) {
		cn_dev_proc_err(proc_set, "mc_state(0/1):%d is illegal", mc_state);
		return -1;
	}

	temp = strsep(&p, " ");
	if (temp == NULL) {
		cn_dev_proc_err(proc_set, "irqinject parameter error");
		return -1;
	}
	if (kstrtou32(temp, 16, &ecc_addr)) {
		cn_dev_proc_err(proc_set, "ecc_addr error");
		return -1;
	}
	/* close eeprom*/
	cn_mcc_get_eeprom_switch((void *)core, 0);
	cn_mcc_ecc_irq_inject((void *)core, sys_mc_num, mc_state, ecc_addr);

	return 0;
}

static ssize_t cndrv_retire_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *pos)
{
	char buf[128];
	ssize_t buf_size;
	struct cn_core_set *core =
			(struct cn_core_set *)(file_inode(file)->i_private);
	struct cn_proc_set *proc_set = core->proc_set;

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_proc_debug(proc_set, "user command:%s", buf);

	switch (core->device_id) {
		case MLUID_290:
		case MLUID_370:
		case MLUID_590:
		case MLUID_580:
			break;
		default:
			return buf_size;
	}

	if (strstr(buf, "irqinject"))
		retire_irq_inject(core, buf);
	else if (strstr(buf, "retire open"))
		cn_mcc_retire_switch((void *)core, 1);
	else if (strstr(buf, "retire close"))
		cn_mcc_retire_switch((void *)core, 0);
	else if (strstr(buf, "eeprom open"))
		cn_mcc_get_eeprom_switch((void *)core, 1);
	else if (strstr(buf, "eeprom close"))
		cn_mcc_get_eeprom_switch((void *)core, 0);
	else if (strstr(buf, "init"))
		cn_dev_info("cmd3:init unsupport now");
	else if (strstr(buf, "pg retire"))
		cn_mem_proc_do_pgretire(core);
	else {
		cn_dev_info("usage:command error");
		cn_dev_info("cmd1:irqinject mc_num(0~31) state(0/1) ecc_addr(4Byte)");
		cn_dev_info("cmd2:retire open");
		cn_dev_info("cmd3:retire close");
		cn_dev_info("cmd4:pg retire");
	}

	return buf_size;
}
DEBUGFS_WRITE_ATTRIBUTE(cndrv_retire);

static int cndrv_qos_show(struct seq_file *m, void *v)
{
	return cndev_qos_show(m, v);
}

static ssize_t cndrv_qos_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	return cndev_qos_write(file, user_buf, count, pos);
}
PROC_WRITE_ATTRIBUTE(cndrv_qos);

static ssize_t cndrv_overtemp_warning_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	u32 cycle = 0;
	u32 mode = 0;
	char buf[128] = {0};
	char cmd[128] = {0};
	int ret = 0;
	ssize_t buf_size = 0;
	struct cndev_overtemp_param overtemp;
	struct cn_core_set *core = (struct cn_core_set *)PDE_DATA(file_inode(file));
	struct cn_proc_set *proc_set = core->proc_set;

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}

	buf[buf_size-1] = '\0';
	cn_dev_proc_info(proc_set, "user command:%s", buf);
	if (strlen(buf)) {
		ret = sscanf(buf, "%s %d %d", cmd, &mode, &cycle);
		if (!strcmp(cmd, "set_warning")) {
			memset(&overtemp, 0, sizeof(struct cndev_overtemp_param));
			overtemp.mode = mode;
			overtemp.cycle = cycle;
			if (cycle < 1) {
				overtemp.cycle = 30;
			}
			ret = cndrv_mcu_set_overtemp_param(core, &overtemp);
			if (ret) {
				if (ret == -EPERM) {
					cn_dev_proc_info(proc_set,
						"Set warning policy %s.\n", "not support");
					goto out;
				} else {
					cn_dev_proc_info(proc_set,
						"Set warning policy %s.\n", "failed");
				}
			} else {
					cn_dev_proc_info(proc_set,
						"Set warning policy %s.\n", "successfully");
			}
			if (!ret)
				goto out;
		}
	}

	cn_dev_proc_info(proc_set, "usage:");
	cn_dev_proc_info(proc_set, "mode:<auto/manual(0/1)> refresh cycle:<second)(1-65535)>");
	cn_dev_proc_info(proc_set, "echo \"set_warning <mode> <refresh cycle(second)>\" > overtemp_warning");

out:

	return buf_size;
}

static int cndrv_overtemp_warning_show(struct seq_file *m, void *v)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cndev_overtemp_param overtemp;

	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	memset(&overtemp, 0, sizeof(struct cndev_overtemp_param));
	ret = cndrv_mcu_get_overtemp_param(core, &overtemp);
	if (!ret) {
		seq_printf(m, "Overtemperaue Frequency Warning Mode: %u\n",
				overtemp.mode);
		seq_printf(m, "Overtemperaue Frequency Warning Refresh cycle: %u s\n",
				overtemp.cycle);
	}

	return 0;
}

PROC_WRITE_ATTRIBUTE(cndrv_overtemp_warning);

static ssize_t cndrv_llc_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	char buf[128] = {0};
	ssize_t buf_size;
	struct cn_core_set *core =
				(struct cn_core_set *)PDE_DATA(file_inode(file));

	buf_size = min(count, (size_t)(sizeof(buf) - 1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}

	buf[buf_size] = '\0';
	cn_dev_core_debug(core, "user command:%s", buf);

	if (!strlen(buf))
		return buf_size;

	if (cn_mem_proc_llc_ctrl(core, buf))
		return -EINVAL;

	return buf_size;
}

static int cndrv_llc_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	unsigned int compress_en = 0;
	unsigned int compress_mode = 0;
	unsigned int compress_high_mode = 0;

	cn_mcc_get_compress_info(core, &compress_en, &compress_mode,
							&compress_high_mode);

	seq_printf(m, "\n[COMP] Enable: [%s], Mode: [%s], Offset: [%s]\n",
					 comp_mode_en[compress_en], comp_mode_mode[compress_mode],
					 comp_high_mode[compress_high_mode]);
	return 0;
}
PROC_WRITE_ATTRIBUTE(cndrv_llc);

static int cndrv_core_state_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	seq_printf(m, "%s\n", cn_get_core_state_string(core->state));

	return 0;
}
PROC_SHOW_ATTRIBUTE(cndrv_core_state);

#ifdef CONFIG_CNDRV_EDGE
static int cndrv_cacc_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct sbts_hw_cfg_hdl param = {0};
	__u32 enable, bypass;
	int ret = 0;

	param.version = SBTS_VERSION;
	param.type = CACC_GET_ENABLE;
	param.val = 0xfffffff;
	ret = cn_hw_cfg_cacc_handle(core, &param, 0);
	if (ret) {
		seq_printf(m, "CACC_GET_ENABLE failed with %d\n", ret);
		return 0;
	}
	enable = param.val;

	param.version = SBTS_VERSION;
	param.type = CACC_GET_BYPASS;
	param.val = 0xfffffff;
	ret = cn_hw_cfg_cacc_handle(core, &param, 0);
	if (ret) {
		seq_printf(m, "CACC_GET_BYPASS failed with %d\n", ret);
		return 0;
	}
	bypass = param.val;

	seq_printf(m, "cacc enable:%d bypass:%d\n", enable, bypass);

	return 0;
}

static ssize_t cndrv_cacc_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core = (struct cn_core_set *)PDE_DATA(file_inode(file));
	struct sbts_hw_cfg_hdl param = {0};
	char buf[128];
	ssize_t buf_size;

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_core_debug(core, "user command:%s", buf);

	if (strstr(buf, "enable")) {
		param.version = SBTS_VERSION;
		param.type = CACC_SET_ENABLE;
		param.val = 1;
		cn_hw_cfg_cacc_handle(core, &param, 0);
	} else if (strstr(buf, "disable")) {
		param.version = SBTS_VERSION;
		param.type = CACC_SET_ENABLE;
		param.val = 0;
		cn_hw_cfg_cacc_handle(core, &param, 0);
	} else if (strstr(buf, "bypass")) {
		param.version = SBTS_VERSION;
		param.type = CACC_SET_BYPASS;
		param.val = 1;
		cn_hw_cfg_cacc_handle(core, &param, 0);
	} else if (strstr(buf, "unpass")) {
		param.version = SBTS_VERSION;
		param.type = CACC_SET_BYPASS;
		param.val = 0;
		cn_hw_cfg_cacc_handle(core, &param, 0);
	} else {
		cn_dev_core_err(core, "unknown command:%s", buf);
		return -EINVAL;
	}

	return count;
}
PROC_WRITE_ATTRIBUTE(cndrv_cacc);

#endif

static ssize_t queue_schedule_policy_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core = (struct cn_core_set *)PDE_DATA(file_inode(file));
	struct cn_proc_set *proc_set = core->proc_set;
	char buf[32];
	ssize_t buf_size;
	int ret = 0;

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size - 1] = '\0';

	ret = cn_sbts_set_queue_sch_policy(core, buf);
	if (ret) {
		cn_dev_proc_info(proc_set, "cmd %s set queue schedule policy failed", buf);
	}

	if (!cn_sbts_get_queue_sch_policy(core, buf)) {
		cn_dev_proc_info(proc_set, "current queue schedule policy %s", buf);
	}

	return count;
}

static int queue_schedule_policy_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	char buf[32];

	if (!cn_sbts_get_queue_sch_policy(core, buf)) {
		seq_printf(m, "current queue schedule policy %s\n", buf);
	}

	return 0;
}
PROC_WRITE_ATTRIBUTE(queue_schedule_policy);

static int policy_aux(__u32 *res, const char *buf, int size)
{
	int i = 0;
	__u32 policy = 0;
	for (i = 0; i < size; i++){
		if (buf[i] >= '0' && buf[i] <= '9') {
			policy = policy * 10 + (buf[i] - '0');
		} else if (buf[i] >= 'a' && buf[i] <= 'f') {
			policy = policy * 10 + (buf[i] - 'a');
		} else if (buf[i] >= 'A' && buf[i] <= 'F') {
			policy = policy * 10 + (buf[i] - 'A');
		} else {
			return -EFAULT;
		}
	}
	*res = policy;
	return 0;
}

static ssize_t aiisp_policy_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core = (struct cn_core_set *)PDE_DATA(file_inode(file));
	struct cn_proc_set *proc_set = (struct cn_proc_set *)core->proc_set;
	char buf[32];
	ssize_t buf_size;
	int ret = 0;
	__u32 policy = 0;
	__u32 old_policy = 0;

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size - 1] = '\0';

	if (switch_core_type_check(core)) {
		cn_dev_proc_err(proc_set, "cmd %s set aiisp policy is illegal in this chip", buf);
		return -EFAULT;
	}

	if (policy_aux(&policy, buf, buf_size-1)) {
		cn_dev_proc_err(proc_set, "set aiisp policy is illegal");
		return -EFAULT;
	}

	if ((policy != 0) && (policy != 1)) {
		cn_dev_proc_err(proc_set, "set aiisp policy is illegal");
		return -EFAULT;
	}

	if (cndev_open_count_lock()) {
		return -EBUSY;
	}
	if (get_cndev_open_count()) {
		cn_dev_proc_err(proc_set, "Please close cambrcion control device first, open count is %d", get_cndev_open_count());
		cndev_open_count_unlock();
		return -EBUSY;
	}

	if (cn_core_set_prohibit_mode(core, PROHIBITED_PROCESS)) {
		cn_dev_proc_err(proc_set, "Please close cambriocn device first");
		cndev_open_count_unlock();
		return -EBUSY;
	}
	cndev_open_count_unlock();

	if (cn_bus_core_type_switch(core->bus_set, policy)) {
		cn_dev_proc_err(proc_set, "Switch core type error");
		goto err;
	}

	ret = cn_sbts_set_aiisp_policy(core, policy);
	if (ret) {
		if (cn_sbts_get_old_aiisp_policy(core, &old_policy)) {
			cn_dev_proc_err(proc_set, "Switch core type restore old poilcy error");
			goto err;
		}
		if (cn_bus_core_type_switch(core->bus_set, old_policy)) {
			cn_dev_proc_err(proc_set, "Switch core type restore error");
			goto err;
		}
		cn_dev_proc_info(proc_set, "cmd %s set aiisp policy failed", buf);
		goto err;
	}

	if (!cn_sbts_get_aiisp_policy(core, buf, 32)) {
		cn_dev_proc_info(proc_set, "current aiisp policy %s", buf);
	}
	if (cn_core_set_prohibit_mode(core, COMPUTEMODE_DEFAULT)) {
		cn_dev_proc_err(proc_set, "Set prohibit mode to default mode failed");
		return -EBUSY;
	}
	return count;
err:
	if (cn_core_set_prohibit_mode(core, COMPUTEMODE_DEFAULT)) {
		cn_dev_proc_err(proc_set, "Set prohibit mode to default mode failed");
		return -EBUSY;
	}
	return -EFAULT;
}

static int aiisp_policy_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	char buf[32];

	if (!cn_sbts_get_aiisp_policy(core, buf, 32)) {
		seq_printf(m, "current aiisp policy %s\n", buf);
	}

	return 0;
}
PROC_WRITE_ATTRIBUTE(aiisp_policy);

static ssize_t schedule_policy_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core = (struct cn_core_set *)PDE_DATA(file_inode(file));
	struct cn_proc_set *proc_set = core->proc_set;
	char buf[32];
	ssize_t buf_size;
	int ret = 0;

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size - 1] = '\0';

	ret = cn_sbts_set_schedule_policy(core, buf);
	if (ret) {
		cn_dev_proc_info(proc_set, "cmd %s set schedule policy failed", buf);
	}

	if (!cn_sbts_get_schedule_policy(core, buf)) {
		cn_dev_proc_info(proc_set, "current schedule policy %s", buf);
	}

	return count;
}

static int schedule_policy_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	char buf[32];

	if (!cn_sbts_get_schedule_policy(core, buf)) {
		seq_printf(m, "current schedule policy %s\n", buf);
	}

	return 0;
}
PROC_WRITE_ATTRIBUTE(schedule_policy);

static int cndrv_lpm_info_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	cn_lpm_info_show(m, core);
	return 0;
}
PROC_SHOW_ATTRIBUTE(cndrv_lpm_info);

static ssize_t queue_record_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core =
			(struct cn_core_set *)PDE_DATA(file_inode(file));
	int ret = 0;

	ret = cn_queue_record_cmd(core, user_buf, count);
	if (ret) {
		return ret;
	}

	return count;
}

static int queue_record_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	cn_queue_record_show(m, core);
	return 0;
}
PROC_WRITE_ATTRIBUTE(queue_record);

static int p2pshm_debug_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	cn_p2pshm_proc_dump(m, core);
	return 0;
}
PROC_SHOW_ATTRIBUTE(p2pshm_debug);

static int cn_perf_debug_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	cn_perf_tgid_entry_show(m, core);
	return 0;
}
PROC_SHOW_ATTRIBUTE(cn_perf_debug);

static int cn_mem_perf_debug_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	cn_mem_perf_tgid_entry_show(m, core);
	return 0;
}
PROC_SHOW_ATTRIBUTE(cn_mem_perf_debug);

static void cndrv_bootinfo_put(struct seq_file *m, const char *name,
			enum PROCESS_STAGE stage, struct fn_state_s state)
{
	if (stage == INIT_STAGE) {
		seq_printf(m, "[%30s] -- [%20s] -- [time cost: %6d(ms)]\n", name, (state.status == INIT_OK) ? "INIT_OK"
				: (state.status == DEFAULT) ? "INIT_DEFAULT" : "EXIT_OK", state.init_cost);
	} else if (stage == LATE_INIT_STAGE) {
		seq_printf(m, "[%30s] -- [%20s] -- [time cost: %6d(ms)]\n", name, (state.status == INIT_OK) ? "LATE_INIT_OK"
				: (state.status == DEFAULT) ? "LATE_INIT_DEFAULT" : "LATE_EXIT_OK", state.init_cost);
	}
}

static void cndrv_bootinfo_pc(struct seq_file *m, struct cn_core_set *core)
{
	u32 old_pc = 0;
	u32 new_pc = 0;
	struct cn_proc_set *proc_set = core->proc_set;

	old_pc = core->arm_pc_init;
	switch (core->device_id) {
	case MLUID_290:
	case MLUID_270:
	case MLUID_220:
		new_pc = reg_read32(core->bus_set, 0x600200);
		break;
	case MLUID_CE3226:
		new_pc = reg_read32(core->bus_set, 0x600180);
		break;
	case MLUID_370:
		new_pc = reg_read32(core->bus_set, 0x8500180);
		break;
	case MLUID_580:
	case MLUID_590:
		new_pc = reg_read32(core->bus_set, 0x800180);
		break;
	default:
		seq_printf(m, "%#llx unknown\n", core->device_id);
		return;
	}


	if (old_pc != new_pc) {
		seq_printf(m, "old_pc=%#x != new_pc=%#x --> arm running\n",
						old_pc, new_pc);
		seq_puts(m, "please manual dump arm log\n");
		if (proc_set)
			seq_printf(m, "cat /proc/driver/cambricon/mlus/%s/mlumsg\n",
							proc_set->dev_name);
	} else
		seq_printf(m, "old_pc=%#x == new_pc=%#x --> arm no running\n",
						old_pc, new_pc);
}

static int cndrv_bootinfo_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_bus_set *bus_set;
	struct core_fn_s *core_fn_t;
	struct late_fn_s *late_fn_t;
	struct fn_state_s *core_fn_state, *late_fn_state;
	int i, idx, core_fn_num, late_fn_num;
	u32 device_ko_state;

	if (!core)
		return -EFAULT;

	bus_set = core->bus_set;
	if (!bus_set)
		return -EFAULT;

	idx = core->idx;
	core_fn_t = cn_core_get_core_fn_t();
	core_fn_num = cn_core_get_core_fn_num();
	core_fn_state = cn_core_get_core_fn_state(idx);
	late_fn_t = cn_dm_get_late_fn_t();
	late_fn_num = cn_dm_get_late_fn_num();
	late_fn_state = cn_dm_get_late_fn_state(idx);

	/* stage 1: for init, in cn_core_probe */
	for (i = 0; i < core_fn_num; i++) {
		cndrv_bootinfo_put(m, core_fn_t[i].name, INIT_STAGE,
						core_fn_state[i]);
	}

	/* stage 2: for device side bootinfo, through reg 0x3500 */
	device_ko_state = cn_bus_get_device_ko_bootinfo(bus_set);
	if (device_ko_state > 0) {
		if (core->state > CN_BOOTING && core->state <= CN_RUNNING) {
			seq_printf(m, "All modules in device side insert OK\n");
		} else {
			seq_printf(m, "The %d-th module inserts failed\n",
						*(int *)&device_ko_state + 1);
		}
	}

	/* stage 3: for late init, in cn_dm_init_domain */
	for (i = 0; i < late_fn_num; i++) {
		cndrv_bootinfo_put(m, late_fn_t[i].name, LATE_INIT_STAGE,
						late_fn_state[i]);
	}

	cndrv_bootinfo_pc(m, core);

	return 0;
}
PROC_SHOW_ATTRIBUTE(cndrv_bootinfo);

#ifndef CONFIG_CNDRV_EDGE
static ssize_t cn_report_proc_write(struct file *file, const char __user *user_buf,
						size_t count, loff_t *pos)
{
	int ret;
	struct cn_core_set *core =
				(struct cn_core_set *)PDE_DATA(file_inode(file));
	char *buf;
	char *cmd;
	char *para;
	int buf_size = 0;

	if (cn_is_mim_en(core) && cn_core_is_vf(core)) {
		cn_dev_core_info(core, "do not support in sriov and vf mode!");
		return 0;
	}

	buf = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		cn_dev_core_err(core, "no mem.");
		return -ENOMEM;
	}

	cmd = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (!cmd) {
		cn_dev_core_err(core, "no mem.");
		cn_kfree(buf);
		return -ENOMEM;
	}

	para = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (!para) {
		cn_dev_core_err(core, "no mem.");
		cn_kfree(buf);
		cn_kfree(cmd);
		return -ENOMEM;
	}

	buf_size = min(count, (size_t)(PATH_MAX-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		cn_kfree(para);
		cn_kfree(cmd);
		cn_kfree(buf);
		return -EFAULT;
	}

	if (strlen(buf)) {
		ret = sscanf(buf, "%s %s", cmd, para);
		cn_dev_core_info(core, "user command:%s %s", cmd, para);
		if (ret == 2) {
			if (!strcmp(cmd, "mode")) {
				if(!strcmp(para, "disable")) {
					cn_report_set_report_mode(core, 0);
				} else if(!strcmp(para, "enable")) {
					cn_report_set_report_mode(core, 1);
				} else if(!strcmp(para, "auto")) {
					cn_report_set_report_mode(core, 2);
				}
			} else if(!strcmp(cmd, "report")) {
				if(!strcmp(para, "on")) {
					cn_report_set_report_on(core, 1);
				}
			} else if(!strcmp(cmd, "path")) {
				cn_report_set_report_path(core, para);
			} else if(!strcmp(cmd, "flush")) {
				cn_report_armflush(core, 1);
			}
		}
	}

	cn_kfree(para);
	cn_kfree(cmd);
	cn_kfree(buf);

	return count;
}

static int cn_report_proc_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;

	seq_printf(m, "Available cmd:\n");
	seq_printf(m, "  report on --start gen report files\n");
	seq_printf(m, "  mode auto/enable/disable --set to enable auto report mode\n");
	seq_printf(m, "  path /xxx --set default path to store report files\n");
	seq_printf(m, "  flush xxx --flush device cache into mem\n");
	seq_printf(m, "Current state:\n");
	seq_printf(m, "report state=%d\n", cn_report_get_report_on(core));
	seq_printf(m, "report mode=%d [2=auto/1=enable/0=disable]\n", cn_report_get_report_mode(core));
	seq_printf(m, "report path=%s\n", cn_report_get_report_path(core));

	return 0;
}
PROC_WRITE_ATTRIBUTE(cn_report_proc);

static int cn_kdump_proc_open(struct inode *inode, struct file *file)
{
	struct cn_core_set *core =
				(struct cn_core_set *)PDE_DATA(file_inode(file));

	__sync_add_and_fetch(&core->open_count, 1);
	cn_kdump_exit(core);
	cn_kdump_init(core);

	return 0;
}

static int cn_kdump_proc_release(struct inode *inode, struct file *file)
{
	struct cn_core_set *core =
				(struct cn_core_set *)PDE_DATA(file_inode(file));
	if (!__sync_sub_and_fetch(&core->open_count, 1)) {
		cn_sbts_restore_resource(core);
		core->exclusive_pgid = -1;
	}
	return 0;
}

static ssize_t cn_kdump_proc_read(struct file *file, char __user *buffer,
										   size_t buflen, loff_t *fpos)
{
	struct cn_core_set *core =
				(struct cn_core_set *)PDE_DATA(file_inode(file));

	return cn_kdump_read(core, buffer, buflen, fpos);
}

#if KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE
static const struct file_operations cn_kdump_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= cn_kdump_proc_open,
	.read		= cn_kdump_proc_read,
	.llseek		= default_llseek,
	.release	= cn_kdump_proc_release,
};
#else
static const struct proc_ops cn_kdump_proc_fops = {
	.proc_open	= cn_kdump_proc_open,
	.proc_read	= cn_kdump_proc_read,
	.proc_lseek	= default_llseek,
	.proc_release	= cn_kdump_proc_release,
};
#endif

static int cndrv_xpulog_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct rpmsg_device *rpdev = NULL;
	int remote_fd = -1;
	int read_bytes = 0;
	/* Save the precious kernel stack */
	char *tmpbuf = NULL;
	char file_path[128];

	tmpbuf = cn_kzalloc(MAX_BUF_LEN, GFP_KERNEL);
	if (!tmpbuf) {
		return -ENOMEM;
	}

	if (cn_core_is_vf(core))
		sprintf(file_path, "/tmp/cncodec.log%d", core->vf_idx);
	else
		sprintf(file_path, "/cambr_syslog/cncodec.log");

	remote_fd = ipcm_remote_open(core, &rpdev, file_path, O_RDONLY, 0);
	if (remote_fd < 0) {
		seq_printf(m, "open /cambr_syslog/cncodec.log failed(%d)\n", remote_fd);
		cn_kfree(tmpbuf);

		return 0;
	}

	while ((read_bytes = ipcm_remote_read(rpdev, remote_fd, tmpbuf, MAX_BUF_LEN)) > 0) {
		tmpbuf[read_bytes] = '\0';
		seq_puts(m, tmpbuf);
	}

	ipcm_remote_close(rpdev, remote_fd);

	cn_kfree(tmpbuf);

	return 0;
}

PROC_SHOW_ATTRIBUTE_SIZE(cndrv_xpulog);

static ssize_t ipcm_perf_record_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core =
			(struct cn_core_set *)PDE_DATA(file_inode(file));
	char buf[32] = {0};
	int ret = 0;
	int test_cnt = 0;
	int record_en = 0;

	ret = simple_write_to_buffer(buf, sizeof(buf), pos, user_buf, count);
	if (!ret)
		return -EFAULT;
	ret = sscanf(buf, "%d %d", &test_cnt, &record_en);
	if (ret != 2)
		return -EINVAL;
	ret = ipcm_enable_perf_record(core, test_cnt, record_en);
	if (ret) {
		return ret;
	}

	return count;
}

static int ipcm_perf_record_show(struct seq_file *m, void *v)
{
	return ipcm_record_show(m, v);
}

PROC_WRITE_ATTRIBUTE_SIZE(ipcm_perf_record);

static int cndrv_remote_file_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct rpmsg_device *rpdev = NULL;
	int remote_fd = -1;
	int read_bytes = 0;
	char *tmpbuf = NULL;
	char *file_name = NULL;
	char *buf = NULL;
	struct cn_proc_set *proc_set = core->proc_set;

	file_name = proc_set->remote_file_name;
	if (strlen(file_name) == 0) {
		seq_printf(m, "Usage: remote file name unspecified, please specify file name "
			"u want to access by writing to me before reading, for example:\n"
			"echo /proc/cpuinfo > /proc/driver/cambricon/mlus/xxx/remote_file\n");
		return 0;
	}

	tmpbuf = cn_kzalloc(MAX_BUF_LEN, GFP_KERNEL);
	if (tmpbuf == NULL) {
		return -ENOMEM;
	}

	buf = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (buf == NULL) {
		cn_kfree(tmpbuf);
		return -ENOMEM;
	}

	down_read(&proc_set->remote_lock);

	/* Narrow down the locking scope */
	strncpy(buf, file_name, PATH_MAX);

	/* One-shot style */
	file_name[0] = '\0';

	up_read(&proc_set->remote_lock);

	remote_fd = ipcm_remote_open(core, &rpdev, buf, O_RDONLY, 0);
	if (remote_fd < 0) {
		seq_printf(m, "open %s failed(%d)\n", buf, remote_fd);
		cn_kfree(tmpbuf);
		cn_kfree(buf);

		return 0;
	}

	while ((read_bytes = ipcm_remote_read(rpdev, remote_fd, tmpbuf, MAX_BUF_LEN)) > 0) {
		tmpbuf[read_bytes] = '\0';
		seq_puts(m, tmpbuf);
	}

	ipcm_remote_close(rpdev, remote_fd);

	cn_kfree(tmpbuf);
	cn_kfree(buf);

	return 0;
}

static ssize_t cndrv_remote_file_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
	struct seq_file *seq = (struct seq_file *)file->private_data;
	struct cn_core_set *core = seq->private;
	struct cn_proc_set *proc_set = core->proc_set;

	/* It's assumed that the trailing character, '\0' or '\n'
	 * has been included in len */
	if (len <= 0 || len > sizeof(proc_set->remote_file_name)) {
		return -EINVAL;
	}

	down_write(&proc_set->remote_lock);

	proc_set->remote_file_name[sizeof(proc_set->remote_file_name) - 1] = 0;
	if (copy_from_user(proc_set->remote_file_name, buf, len)) {
		up_write(&proc_set->remote_lock);

		return -EFAULT;
	}

	/* Tricky part:
	 * Command "echo 123" actullay outputs 123\n in shell, so it's mandatory
	 * to eliminate this annoying '\n'
	 * */
	proc_set->remote_file_name[len - 1] = '\0';

	up_write(&proc_set->remote_lock);

	return len;
}

PROC_WRITE_ATTRIBUTE_SIZE(cndrv_remote_file);
#endif

static int cndrv_attr_show(struct seq_file *m, void *v)
{
	struct cn_core_set *(core) = (struct cn_core_set *)m->private;
	struct cn_device_attr attr;
	unsigned int *data = NULL;

	data = cn_kzalloc(CN_DEVICE_ATTRIBUTE_MAX *
			sizeof(unsigned int), GFP_KERNEL);
	if (unlikely(!data)) {
		cn_dev_core_err(core,
			"alloc attribute data failed!");
		return -ENOMEM;
	}

	attr.cnt = CN_DEVICE_ATTRIBUTE_MAX;
	attr.version = ATTR_VERSION_END;
	attr.data = NULL;

	cn_get_attribute_info(core, (void *)&attr, data);

	seq_printf(m, "[Cambricon ATTR Info]\n");
	/* Computing Capabilities */
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR                    : %u \n",
		data[CN_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR                    : %u \n",
		data[CN_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_SPARSE_COMPUTING_SUPPORTED                  : %u \n",
		data[CN_DEVICE_ATTRIBUTE_SPARSE_COMPUTING_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_FP16_COMPUTING_SUPPORTED                    : %u \n",
		data[CN_DEVICE_ATTRIBUTE_FP16_COMPUTING_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_INT4_COMPUTING_SUPPORTED                    : %u \n",
		data[CN_DEVICE_ATTRIBUTE_INT4_COMPUTING_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_INT8_COMPUTING_SUPPORTED                    : %u \n",
		data[CN_DEVICE_ATTRIBUTE_INT8_COMPUTING_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_BF16_COMPUTING_SUPPORTED                    : %u \n",
		data[CN_DEVICE_ATTRIBUTE_BF16_COMPUTING_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_TF32_COMPUTING_SUPPORTED                    : %u \n",
		data[CN_DEVICE_ATTRIBUTE_TF32_COMPUTING_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_COMPUTE_MODE                                : %u \n",
			data[CN_DEVICE_ATTRIBUTE_COMPUTE_MODE]);
	/* Heterogeneous Capabilities */
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_QUEUE_COUNT                             : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_QUEUE_COUNT]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_NOTIFIER_COUNT                          : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_NOTIFIER_COUNT]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_QUEUE_PRIORITIES_SUPPORTED                  : %u \n",
		data[CN_DEVICE_ATTRIBUTE_QUEUE_PRIORITIES_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_TINY_CORE_SUPPORTED                         : %u \n",
		data[CN_DEVICE_ATTRIBUTE_TINY_CORE_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_CODEC_JPEG_SUPPORTED                        : %u \n",
		data[CN_DEVICE_ATTRIBUTE_CODEC_JPEG_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_CODEC_H264_SUPPORTED                        : %u \n",
		data[CN_DEVICE_ATTRIBUTE_CODEC_H264_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_CODEC_H265_SUPPORTED                        : %u \n",
		data[CN_DEVICE_ATTRIBUTE_CODEC_H265_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_AIISP_CORE_SUPPORTED                        : %u \n",
		data[CN_DEVICE_ATTRIBUTE_AIISP_CORE_SUPPORTED]);
	/* new notifier use */
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MULTI_CTX_NOTIFIER_WAIT_SUPPORTED           : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MULTI_CTX_NOTIFIER_WAIT_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_IPCNOTIFIER_SUPPORTED                       : %u \n",
		data[CN_DEVICE_ATTRIBUTE_IPCNOTIFIER_SUPPORTED]);
	/* Elastic Capabilities */
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_X                        : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_X]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_Y                        : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_Y]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_Z                        : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_BLOCK_TASK_DIM_Z]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_CLUSTER_COUNT_PER_UNION_TASK            : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_CLUSTER_COUNT_PER_UNION_TASK]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_CLUSTER_COUNT                           : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_CLUSTER_COUNT]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_CORE_COUNT_PER_CLUSTER                  : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_CORE_COUNT_PER_CLUSTER]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_QUADRANT_COUNT                          : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_QUADRANT_COUNT]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_UNION_TYPE_PER_QUADRANT                 : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_UNION_TYPE_PER_QUADRANT]);
	/* Memory Capacities */
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_L2_CACHE_SIZE                           : 0x%x B \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_L2_CACHE_SIZE]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_N_RAM_SIZE_PER_CORE                         : 0x%x B \n",
		data[CN_DEVICE_ATTRIBUTE_N_RAM_SIZE_PER_CORE]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_WEIGHT_RAM_SIZE_PER_CORE                    : 0x%x B \n",
		data[CN_DEVICE_ATTRIBUTE_WEIGHT_RAM_SIZE_PER_CORE]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_TOTAL_CONST_MEMORY_SIZE                     : 0x%x MiB \n",
		data[CN_DEVICE_ATTRIBUTE_TOTAL_CONST_MEMORY_SIZE]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_LOCAL_MEMORY_SIZE_PER_CORE                  : %u \n",
		data[CN_DEVICE_ATTRIBUTE_LOCAL_MEMORY_SIZE_PER_CORE]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_SHARED_RAM_SIZE_PER_CLUSTER             : 0x%x B\n",
		data[CN_DEVICE_ATTRIBUTE_MAX_SHARED_RAM_SIZE_PER_CLUSTER]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_NODE_COUNT                    : %u \n",
		data[CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_NODE_COUNT]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_CLUSTER_L1_CACHE_SUPPORTED                  : 0x%x B \n",
		data[CN_DEVICE_ATTRIBUTE_CLUSTER_L1_CACHE_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_PERSISTING_L2_CACHE_SIZE                : 0x%x B \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_PERSISTING_L2_CACHE_SIZE]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_SIZE_PER_UNION_TASK       : %u \n",
		data[CN_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_SIZE_PER_UNION_TASK]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_VIRTUAL_ADDRESS_MANAGEMENT_SUPPORTED        : %u \n",
		data[CN_DEVICE_ATTRIBUTE_VIRTUAL_ADDRESS_MANAGEMENT_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR_SUPPORTED : %u \n",
		data[CN_DEVICE_ATTRIBUTE_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_GENERIC_COMPRESSION_SUPPORTED               : %u \n",
		data[CN_DEVICE_ATTRIBUTE_GENERIC_COMPRESSION_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_CAN_USE_HOST_POINTER_FOR_REGISTERED_MEM     : %u \n",
		data[CN_DEVICE_ATTRIBUTE_CAN_USE_HOST_POINTER_FOR_REGISTERED_MEM]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_CAN_MAP_HOST_MEMORY                         : %u \n",
		data[CN_DEVICE_ATTRIBUTE_CAN_MAP_HOST_MEMORY]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_LINEAR_MAPPING_SUPPORTED                    : %u \n",
		data[CN_DEVICE_ATTRIBUTE_LINEAR_MAPPING_SUPPORTED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_LINEAR_RECOMMEND_GRANULARITY                : 0x%x \n",
		data[CN_DEVICE_ATTRIBUTE_LINEAR_RECOMMEND_GRANULARITY]);
	/* Hardware Proterties */
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_ECC_ENABLED                                 : %u \n",
		data[CN_DEVICE_ATTRIBUTE_ECC_ENABLED]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_CLUSTER_CLOCK_RATE                          : %u MHz \n",
		data[CN_DEVICE_ATTRIBUTE_CLUSTER_CLOCK_RATE] / 1000);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MEMORY_CLOCK_RATE                           : %u MHz \n",
		data[CN_DEVICE_ATTRIBUTE_MEMORY_CLOCK_RATE] / 1000);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_BUS_WIDTH                     : %u bits \n",
		data[CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_BUS_WIDTH]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_TOTAL_SIZE                    : 0x%x MiB \n",
		data[CN_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_TOTAL_SIZE]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_PCI_BUS_ID                                  : 0x%x \n",
		data[CN_DEVICE_ATTRIBUTE_PCI_BUS_ID]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_PCI_DEVICE_ID                               : 0x%x \n",
		data[CN_DEVICE_ATTRIBUTE_PCI_DEVICE_ID]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID                               : 0x%x \n",
		data[CN_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_MDR_MEMORY_SIZE                             : 0x%x MiB\n",
		data[CN_DEVICE_ATTRIBUTE_MDR_MEMORY_SIZE]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_PCI_MPS                                     : %u B\n",
		data[CN_DEVICE_ATTRIBUTE_PCI_MPS]);
	seq_printf(m, "  CN_DEVICE_ATTRIBUTE_PCI_MRRS                                    : %u B\n",
		data[CN_DEVICE_ATTRIBUTE_PCI_MRRS]);

	cn_get_extra_attribute_info(core, data, CN_DEVICE_EXTRA_ATTRIBUTE_MAX);
	seq_printf(m, "  CN_DEVICE_EXTRA_ATTRIBUTE_MAX_CLUSTERS_PER_UNION_LIMIT_TASK[EXT]: %u \n",
		data[CN_DEVICE_EXTRA_ATTRIBUTE_MAX_CLUSTERS_PER_UNION_LIMIT_TASK]);
	seq_printf(m, "  CN_DEVICE_EXTRA_ATTRIBUTE_MAX_QUADRANT_COUNT[EXT]               : %u \n",
		data[CN_DEVICE_EXTRA_ATTRIBUTE_MAX_QUADRANT_COUNT]);
	seq_printf(m, "  CN_DEVICE_EXTRA_ATTRIBUTE_MAX_UNION_TYPE_PER_QUADRANT[EXT]      : %u \n",
		data[CN_DEVICE_EXTRA_ATTRIBUTE_MAX_UNION_TYPE_PER_QUADRANT]);
	seq_printf(m, "  CN_DEVICE_EXTRA_ATTRIBUTE_MLU_ISA_VERSION[EXT]                  : %u \n",
		data[CN_DEVICE_EXTRA_ATTRIBUTE_MLU_ISA_VERSION]);
	seq_printf(m, "  CN_DEVICE_EXTRA_ATTRIBUTE_IS_MULTIPLE_TENSOR_PROCESSOR[EXT]     : %u \n",
		data[CN_DEVICE_EXTRA_ATTRIBUTE_IS_MULTIPLE_TENSOR_PROCESSOR]);
	seq_printf(m, "  CN_DEVICE_EXTRA_ATTRIBUTE_AIISP_CORE_COUNT[EXT]                 : %u \n",
		data[CN_DEVICE_EXTRA_ATTRIBUTE_AIISP_CORE_COUNT]);

	cn_kfree(data);

	return 0;
}
PROC_SHOW_ATTRIBUTE(cndrv_attr);

#ifdef CONFIG_CNDRV_COMMU
PROC_WRITE_ATTRIBUTE(commu_endpoint);
#endif
static int cndrv_smlu_show(struct seq_file *m, void *v)
{
	return cn_smlu_cap_show(m, v);
}
PROC_SHOW_ATTRIBUTE(cndrv_smlu);

static struct cn_proc_file_info proc_file_info[] = {
	{.name = "information", .mode = 0444, .proc_fops = &cndrv_info_fops, .vf_en = 1},
	{.name = "core_state", .mode = 0666, .proc_fops = &cndrv_core_state_fops },
#ifndef CONFIG_CNDRV_EDGE
	{.name = "mlumsg", .mode = 0444, .proc_fops = &cndrv_mlumsg_fops },
	{.name = "bootinfo", .mode = 0444, .proc_fops = &cndrv_bootinfo_fops},
#endif
};

static struct cn_proc_file_info proc_late_file_info[] = {
#ifdef CONFIG_CNDRV_COMMU
	{.name = "commu_endpoint", .mode = 0666, .proc_fops = &commu_endpoint_fops},
#endif
	{.name = "kthread", .mode = 0444, .proc_fops = &cndrv_kthread_fops},
	{.name = "pinned_mem",
			.mode = 0444,
			.proc_fops = &pinned_mem_info_fops },
	{.name = "exclusive_mode",
			.mode = 0666,
			.proc_fops = &cndrv_exclusive_fops,
			.vf_en = 1 },
	{.name = "cn_mem", .mode = 0666, .proc_fops = &cndrv_cn_mem_fops,
			.vf_en = 1 },
	{.name = "bang_printf", .mode = 0666,
			.proc_fops = &cndrv_bang_printf_fops, .vf_en = 1},
	{.name = "idc_debug", .mode = 0666,
			.proc_fops = &cndrv_idc_debug_fops, .vf_en = 1},
	{.name = "unotify_debug", .mode = 0666,
			.proc_fops = &cndrv_unotify_debug_fops, .vf_en = 1},
	{.name = "hostfn_debug", .mode = 0444,
			.proc_fops = &cndrv_hostfn_info_fops, .vf_en = 1},
	{.name = "task_topo", .mode = 0666,
			.proc_fops = &cndrv_task_topo_fops, .vf_en = 1},
	{.name = "sbts_shm", .mode = 0666,
			.proc_fops = &cndrv_sbts_shm_fops, .vf_en = 1},
	{.name = "freq_cap", .mode = 0666,
			.proc_fops = &cndrv_freq_cap_fops, .vf_en = 1},
#ifndef CONFIG_CNDRV_EDGE
	{.name = "stat", .mode = 0444, .proc_fops = &cndrv_stat_fops },
	{.name = "overtemp_warning",
			.mode = 0666,
			.proc_fops = &cndrv_overtemp_warning_fops },
	{.name = "xpulog", .mode = 0444, .proc_fops = &cndrv_xpulog_fops, .vf_en = 1},
	{.name = "remote_file", .mode = 0666, .proc_fops = &cndrv_remote_file_fops },
	{.name = "ipcm_perf_record", .mode = 0666, .proc_fops = &ipcm_perf_record_fops },
	{.name = "report", .mode = 0666, .proc_fops = &cn_report_proc_fops},
	{.name = "llc_ctl", .mode = 0666, .proc_fops = &cndrv_llc_fops, .vf_en = 1},
	{.name = "kdump", .mode = 0666, .proc_fops = &cn_kdump_proc_fops},
#else
	{.name = "late_init", .mode = 0666, .proc_fops = &cndrv_late_init_fops },
#if defined(CONFIG_CNDRV_PIGEON_SOC)
	{.name = "llc_ctl", .mode = 0666, .proc_fops = &cndrv_llc_fops },
	{.name = "aiisp_policy", .mode = 0666, .proc_fops = &aiisp_policy_fops},
#endif
	{.name = "cacc", .mode = 0666, .proc_fops = &cndrv_cacc_fops},
	{.name = "ipu_pwr", .mode = 0666, .proc_fops = &lowpower_task_mode_fops},
#endif
	{.name = "queue_schedule_policy", .mode = 0666,
			.proc_fops = &queue_schedule_policy_fops, .vf_en = 1},
	{.name = "schedule_policy", .mode = 0666,
			.proc_fops = &schedule_policy_fops, .vf_en = 1},
	{.name = "low_power_info", .mode = 0666,
			.proc_fops = &cndrv_lpm_info_fops, .vf_en = 1},
	{.name = "queue_record", .mode = 0666,
			.proc_fops = &queue_record_fops, .vf_en = 1},
	{.name = "cn_mem_dump", .mode = 0666, .proc_fops = &cndrv_cn_mem_dump_fops,
			 .vf_en = 1},
	{.name = "p2pshm_debug", .mode = 0666,
			.proc_fops = &p2pshm_debug_fops, .vf_en = 1},
	{.name = "cn_perf_debug", .mode = 0666, .proc_fops = &cn_perf_debug_fops},
	{.name = "smlu", .mode = 0444, .proc_fops = &cndrv_smlu_fops},
	{.name = "attr", .mode = 0444, .proc_fops = &cndrv_attr_fops, .vf_en = 1},
	{.name = "cn_mem_perf_debug", .mode = 0666, .proc_fops = &cn_mem_perf_debug_fops},
};

static struct cn_proc_file_info proc_codec_turbo[] = {
	{ .name = "codec_turbo", .mode = 0666, .proc_fops = &cndrv_codec_turbo_fops},
};

#ifdef CN_PROC_DEBUG
static struct cn_proc_file_info debug_file_info[] = {
	{ .name = "reg", .mode = 0666, .debugfs_fops = &cndrv_reg_fops},
	{ .name = "mem", .mode = 0666, .debugfs_fops = &cndrv_mem_fops},
};

static struct cn_proc_file_info debug_late_file_info[] = {
	{ .name = "print_debug", .mode = 0666, .debugfs_fops = &print_debug_fops},
	{ .name = "debugfs", .mode = 0666, .debugfs_fops = &cndrv_debugfs_fops},
	{ .name = "pid_info", .mode = 0666, .debugfs_fops = &cndrv_pid_info_fops},
#ifndef CONFIG_CNDRV_EDGE
	{ .name = "cndrv_debug", .mode = 0666,
					.debugfs_fops = &cndrv_debug_fops},
	{ .name = "gdma", .mode = 0666, .debugfs_fops = &cndrv_gdma_fops},
	{ .name = "retire_debug", .mode = 0666, .debugfs_fops = &cndrv_retire_fops},
#endif
	{ .name = "QoS", .mode = 0666, .proc_fops = &cndrv_qos_fops },
	{ .name = "cndev_debug", .mode = 0666, .debugfs_fops = &cndrv_cndev_fops},
};
#endif

static int cn_proc_set_init(struct cn_core_set *core)
{
	struct cn_proc_set *proc_set = NULL;
	struct bus_info_s bus_info;
	char proc_name[64];
	int size = 0;
	int ret = 0;

	proc_set = cn_kzalloc(sizeof(struct cn_proc_set), GFP_KERNEL);
	if (!proc_set) {
		cn_dev_err("alloc proc set error.");
		return -ENOMEM;
	}
	core->proc_set = proc_set;
	if (!cndrv_mlu_dir) {
		cn_dev_proc_err(proc_set,
				"/proc/driver/cambricon/mlus:No such directory");
		ret = -EFAULT;
		goto err_free_proc_set;
	}
	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);
	switch (bus_info.bus_type) {
	case BUS_TYPE_EDGE: {
		size = snprintf(proc_name, 64, "%04x:%04x",
		bus_info.info.edge.vendor, bus_info.info.edge.device);
		proc_set->dev_name =
			cn_kzalloc(sizeof(char) * (size + 1), GFP_KERNEL);
		if (!proc_set->dev_name) {
			cn_dev_proc_err(proc_set, "alloc dev_name error.");
			ret = -ENOMEM;
			goto err_free_proc_set;
		}
		memcpy(proc_set->dev_name, proc_name, size);
		cn_dev_proc_debug(proc_set, "dev_name:%s", proc_set->dev_name);
		break;
	}
	case BUS_TYPE_PCIE: {
		size = snprintf(proc_name, 64, "%04x:%02x:%02x.%x",
				bus_info.info.pcie.domain_id,
				bus_info.info.pcie.bus_num,
				bus_info.info.pcie.device_id >> 3,
				bus_info.info.pcie.device_id & 0x7);
		proc_set->dev_name =
			cn_kzalloc(sizeof(char) * (size + 1), GFP_KERNEL);
		if (!proc_set->dev_name) {
			cn_dev_proc_err(proc_set, "alloc dev_name error.");
			ret = -ENOMEM;
			goto err_free_proc_set;
		}
		memcpy(proc_set->dev_name, proc_name, size);
		cn_dev_proc_debug(proc_set, "dev_name:%s", proc_set->dev_name);
		break;
	}
	default:
		cn_dev_proc_info(proc_set, "UNKNOWN BUS TYPE");
		break;
	}

	proc_set->dbgfs_name = cn_kzalloc(64, GFP_KERNEL);
	if (!proc_set->dbgfs_name) {
		cn_dev_proc_err(proc_set, "alloc dbgfs_name error");
		ret = -ENOMEM;
		goto err_free_dev_name;
	}

	if (cn_core_is_vf(core) && cn_is_mim_en(core))
		snprintf(proc_set->dbgfs_name, 64, "cambricon_dev%dmi%d",
						core->pf_idx, core->vf_idx);
	else
		snprintf(proc_set->dbgfs_name, 64, dev_name(core->device->primary->kdev));

	proc_set->cndrv_dev_dir = proc_mkdir(proc_set->dev_name, cndrv_mlu_dir);
	if (!proc_set->cndrv_dev_dir) {
		cn_dev_proc_err(proc_set,
				"create /proc/driver/cambricon/mlus/%s fail",
				proc_set->dev_name);
		ret = -EFAULT;
		goto err_free_dbgfs_name;
	}

#ifdef CN_PROC_DEBUG
	proc_set->cndrv_debug_dir = debugfs_create_dir(proc_set->dbgfs_name, NULL);
	if (!proc_set->cndrv_debug_dir) {
		cn_dev_proc_err(proc_set, "create /sys/kernel/debug/%s fail",
							proc_set->dev_name);
		ret = -EFAULT;
		goto err_free_dbgfs_name;
	}
#endif
	init_rwsem(&proc_set->remote_lock);

	return 0;

err_free_dbgfs_name:
	cn_kfree(proc_set->dbgfs_name);
err_free_dev_name:
	cn_kfree(proc_set->dev_name);
err_free_proc_set:
	cn_kfree(proc_set);

	return ret;
}

void cn_proc_set_exit(struct cn_core_set *core)
{
	struct cn_proc_set *proc_set;

	if (core == NULL)
		return;

	proc_set = core->proc_set;

#ifdef CN_PROC_DEBUG
	if (!proc_set->cndrv_debug_dir) {
		cn_dev_proc_info(proc_set,
		"/proc/driver/cambricon/mlus/%s/debug :No such directory",
							proc_set->dev_name);
	} else {
		debugfs_remove_recursive(proc_set->cndrv_debug_dir);
		proc_set->cndrv_debug_dir = NULL;
	}
#endif

	if (!proc_set->cndrv_dev_dir) {
		cn_dev_proc_info(proc_set,
			"/proc/driver/cambricon/mlus/%s :No such directory",
							proc_set->dev_name);
	} else {
		proc_remove(proc_set->cndrv_dev_dir);
		proc_set->cndrv_dev_dir = NULL;
	}

	cn_kfree(proc_set->dbgfs_name);
	cn_kfree(proc_set->dev_name);
	cn_kfree(proc_set);
}

static int cn_proc_file_create(struct cn_proc_file_info file_info,
				struct proc_dir_entry *parent, struct cn_core_set *core)
{
	if (cn_core_is_vf(core) && file_info.vf_en == 0) {
		return 0;
	}

	file_info.parent.proc = parent;
	file_info.core = core;
	if (proc_create_data(file_info.name, file_info.mode,
		parent, file_info.proc_fops, core) == NULL) {
		cn_dev_err("create %s fail", file_info.name);
		return -1;
	}

	return 0;
}

static void cn_proc_file_remove(struct cn_proc_file_info file_info,
				struct proc_dir_entry *parent, struct cn_core_set *core)
{
	if (cn_core_is_vf(core) && file_info.vf_en == 0) {
		return;
	}

	remove_proc_entry(file_info.name, parent);
}

static int cn_debugfs_file_create(struct cn_proc_file_info file_info,
				struct dentry *parent, struct cn_core_set *core)
{
	struct cn_proc_set *proc_set = core->proc_set;

	if (cn_core_is_vf(core) && file_info.vf_en == 0) {
		return 0;
	}

	file_info.parent.debugfs = parent;
	file_info.core = core;
	file_info.debug_entry = debugfs_create_file(file_info.name, file_info.mode,
		parent, core, file_info.debugfs_fops);
	if (file_info.debug_entry == NULL) {
		cn_dev_proc_err(proc_set,
			"create /proc/driver/cambricon/mlus/%s/debug/%s fail",
			proc_set->dev_name, file_info.name);
		return -1;
	}

	return 0;
}

static void cn_debugfs_file_remove(struct cn_proc_file_info file_info,
				struct cn_core_set *core)
{
	if (cn_core_is_vf(core) && file_info.vf_en == 0) {
		return;
	}

	debugfs_remove(file_info.debug_entry);
}

int sram_rpc_read(struct cn_core_set *core, struct sram_set_t *sram_set)
{
	int ret = 0;
	struct cn_proc_set *proc_set = core->proc_set;
	int remsg;
	int result_len;

	memset(&remsg, 0, sizeof(remsg));
	ret = commu_call_rpc(proc_set->proc_dob.dob_ep, "commu_sram_test_read",
				sram_set, sizeof(*sram_set), &remsg, &result_len);
	if (ret < 0)
		cn_dev_proc_err(proc_set, "commu_sram_test error ret=%d", ret);

	if (remsg)
		cn_dev_proc_err(proc_set, "commu_sram_test read error");

	return remsg;
}

int sram_rpc_write(struct cn_core_set *core, struct sram_set_t *sram_set)
{
	int ret = 0;
	struct cn_proc_set *proc_set = core->proc_set;
	int remsg;
	int result_len;

	memset(&remsg, 0, sizeof(remsg));
	ret = commu_call_rpc(proc_set->proc_dob.dob_ep, "commu_sram_test_write",
				sram_set, sizeof(*sram_set), &remsg, &result_len);
	if (ret < 0)
		cn_dev_proc_err(proc_set, "commu_sram_test error ret=%d", ret);

	if (remsg)
		cn_dev_proc_err(proc_set, "commu_sram_test write error");

	return remsg;
}

int data_outbound_rpc_alloc(struct cn_core_set *core, struct dob_rpc_alloc_t *dob_rpc_alloc)
{
	int ret = 0;
	struct cn_proc_set *proc_set = core->proc_set;
	int remsg;
	int result_len;

	memset(&remsg, 0, sizeof(remsg));
	ret = commu_call_rpc(proc_set->proc_dob.dob_ep, "commu_dob_alloc",
				dob_rpc_alloc, sizeof(*dob_rpc_alloc), &remsg, &result_len);
	if (ret < 0)
		cn_dev_proc_err(proc_set, "commu_dob_alloc error ret=%d", ret);

	if (remsg)
		cn_dev_proc_err(proc_set, "commu_dob_alloc error");

	return remsg;
}

int data_outbound_rpc_free(struct cn_core_set *core, struct dob_rpc_free_t *dob_rpc_free)
{
	int ret = 0;
	struct cn_proc_set *proc_set =core->proc_set;
	int remsg;
	int result_len;

	memset(&remsg, 0, sizeof(remsg));
	ret = commu_call_rpc(proc_set->proc_dob.dob_ep, "commu_dob_free",
				dob_rpc_free, sizeof(*dob_rpc_free), &remsg, &result_len);
	if (ret < 0)
		cn_dev_proc_err(proc_set, "commu_dob_free error ret=%d", ret);

	if (remsg)
		cn_dev_proc_err(proc_set, "commu_dob_free error");

	return remsg;
}

int data_outbound_rpc_read(struct cn_core_set *core, struct dob_set_t *dob_set)
{
	int ret = 0;
	struct cn_proc_set *proc_set = core->proc_set;
	int remsg;
	int result_len;

	memset(&remsg, 0, sizeof(remsg));
	ret = commu_call_rpc(proc_set->proc_dob.dob_ep, "commu_dob_test_read",
				dob_set, sizeof(*dob_set), &remsg, &result_len);
	if (ret < 0)
		cn_dev_proc_err(proc_set, "commu_dob_test error ret=%d", ret);

	if (remsg)
		cn_dev_proc_err(proc_set, "commu_dob_test read error");

	return remsg;
}

int data_outbound_rpc_write(struct cn_core_set *core, struct dob_set_t *dob_set)
{
	int ret = 0;
	struct cn_proc_set *proc_set = core->proc_set;
	int remsg;
	int result_len;

	memset(&remsg, 0, sizeof(remsg));
	ret = commu_call_rpc(proc_set->proc_dob.dob_ep, "commu_dob_test_write",
				dob_set, sizeof(*dob_set), &remsg, &result_len);
	if (ret < 0)
		cn_dev_proc_err(proc_set, "commu_dob_test error ret=%d", ret);

	if (remsg)
		cn_dev_proc_err(proc_set, "commu_dob_test write error");

	return remsg;
}

static int commu_proc_open_channel(
		struct cn_core_set *core, char *channel_name)
{
	struct cn_proc_set *proc_set = (struct cn_proc_set *)core->proc_set;
	struct commu_channel *channel;

	if (!channel_name || strlen(channel_name) == 0) {
		cn_dev_proc_err(proc_set, "channel name is illegal.");
		return -1;
	}

	channel = commu_search_channel_by_name(core, channel_name);
	if (!channel) {
		channel = commu_open_a_channel(channel_name, core, 0);
		cn_dev_proc_info(proc_set, "open channel %s done.", channel_name);
	}
	proc_set->proc_dob.dob_ep = search_endpoint_by_type(channel, COMMU_ENDPOINT_KERNEL_RPC);
	if (!proc_set->proc_dob.dob_ep) {
		proc_set->proc_dob.dob_ep = connect_rpc_endpoint(channel);
		cn_dev_proc_info(proc_set, "connect ep done.");
	}

	return 0;
}

static void commu_proc_close_channel(struct cn_core_set *core)
{
	struct cn_proc_set *proc_set = (struct cn_proc_set *)core->proc_set;

	if (proc_set->proc_dob.dob_ep) {
		proc_set->proc_dob.dob_ep = NULL;
	}
}

int proc_open_channel(struct cn_core_set *core)
{
	int ret = 0;
	char *channel_name = "test";

	ret = commu_proc_open_channel(core, channel_name);
	if (ret)
		cn_dev_core_err(core, "open channel error");

	return ret;
}

void proc_close_channel(struct cn_core_set *core)
{
	commu_proc_close_channel(core);
}

int cn_core_proc_init(struct cn_core_set *core)
{
	struct cn_proc_set *proc_set;
	int i = 0;
	int file_num;
	int ret = 0;

	ret = cn_proc_set_init(core);
	if (ret) {
		cn_dev_core_err(core, "proc set init error");
		return ret;
	}
	proc_set = core->proc_set;

	cn_mlumsg_set_init(core);

	file_num = ARRAY_SIZE(proc_file_info);
	if (file_num > 0) {
		for (i = 0; i < file_num; i++) {
			ret = cn_proc_file_create(proc_file_info[i],
					proc_set->cndrv_dev_dir, core);
			if (ret) {
				cn_dev_core_err(core, "proc file create error");
				return ret;
			}
		}
	}

#ifdef CN_PROC_DEBUG
	file_num = ARRAY_SIZE(debug_file_info);
	if (file_num > 0) {
		for (i = 0; i < file_num; i++) {
			ret = cn_debugfs_file_create(debug_file_info[i],
				proc_set->cndrv_debug_dir, core);
			if (ret) {
				cn_dev_core_err(core, "debugfs file create error");
				return ret;
			}
		}
	}
#endif

	return 0;
}

void cn_core_proc_exit(struct cn_core_set *core)
{
	cn_proc_set_exit(core);
}

int cn_proc_late_init(struct cn_core_set *core)
{
	struct cn_proc_set *proc_set = core->proc_set;
	int i = 0;
	int ret = 0;

	for (i = 0; i < ARRAY_SIZE(proc_late_file_info); i++) {
		ret = cn_proc_file_create(proc_late_file_info[i],
				proc_set->cndrv_dev_dir, core);
		if (ret)
			return ret;
	}

	/*Codec turbo will be valid only on MLU270_D4 board*/
	if (core->board_model == MLU270_D4) {
		for (i = 0; i < ARRAY_SIZE(proc_codec_turbo); i++) {
			ret = cn_proc_file_create(proc_codec_turbo[i],
					proc_set->cndrv_dev_dir, core);
			if (ret)
				return ret;
		}
	}

#ifdef CN_PROC_DEBUG
	for (i = 0; i < ARRAY_SIZE(debug_late_file_info); i++) {
		ret = cn_debugfs_file_create(debug_late_file_info[i],
				proc_set->cndrv_debug_dir, core);
		if (ret)
			return ret;
	}
#endif

	if (!cn_core_is_vf(core)) {
		/* TODO: init vf proc: create vf nodes. */
		if (cn_is_mim_en(core)) {
			ret = vf_proc_init(core, proc_set->cndrv_dev_dir, cndrv_mlu_dir);
			if (ret)
				return ret;
		}
	}

	return ret;
}

void cn_proc_late_exit(struct cn_core_set *core)
{
	struct cn_proc_set *proc_set;
	int i;

	if (!core) {
		cn_dev_err("core is NULL");
		return;
	}
	proc_set = core->proc_set;
	if (!proc_set)
		return;

	/* TODO: free vf proc, delete proc node */
	if (!cn_core_is_vf(core)) {
		if (cn_is_mim_en(core)) {
			vf_proc_exit((void *)core);
		}
	}

#ifdef CN_PROC_DEBUG
	for (i = 0; i < ARRAY_SIZE(debug_late_file_info); i++) {
		cn_debugfs_file_remove(debug_late_file_info[i], core);
	}
#endif

	if (core->board_model == MLU270_D4) {
		for (i = 0; i < ARRAY_SIZE(proc_codec_turbo); i++) {
			cn_proc_file_remove(proc_codec_turbo[i],
					proc_set->cndrv_dev_dir, core);
		}
	}

	for (i = 0; i < ARRAY_SIZE(proc_late_file_info); i++) {
		cn_proc_file_remove(proc_late_file_info[i],
				proc_set->cndrv_dev_dir, core);
	}
}

int cn_proc_init(void)
{
	cndrv_dir = proc_mkdir("driver/cambricon", NULL);
	if (!cndrv_dir) {
		cn_dev_err("create /proc/driver/cambricon fail");
		return -1;
	}

	cndrv_mlu_dir = proc_mkdir("mlus", cndrv_dir);
	if (!cndrv_mlu_dir) {
		cn_dev_err("create /proc/driver/cambricon/mlus fail");
		return -1;
	}

	cn_dev_info("init OK!");
	return 0;
}

void cn_proc_exit(void)
{
	if (!cndrv_mlu_dir) {
		cn_dev_info("/proc/driver/cambricon/mlus:No such directory");
	} else {
		proc_remove(cndrv_mlu_dir);
	}

	if (!cndrv_dir) {
		cn_dev_err("/proc/driver/cambricon/:No such directory");
		return;
	} else {
		proc_remove(cndrv_dir);
	}

	cn_dev_info("exit OK!");
	return;
}

