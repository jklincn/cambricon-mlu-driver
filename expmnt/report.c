/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/spinlock_types.h>
#include <linux/genalloc.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/random.h>
#include <linux/list.h>
#include <asm/io.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/namei.h>
#if (KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE)
#include <linux/time64.h>
#include <linux/timekeeping.h>
#else
#include <linux/timex.h>
#endif
#if (KERNEL_VERSION(5, 12, 0) > LINUX_VERSION_CODE)
#include <linux/user_namespace.h>
#endif
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
#include <linux/fsnotify.h>
#include <linux/sched/xacct.h>
#include <linux/uio.h>
#endif
#include <linux/rtc.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"
#include "cndrv_ioctl.h"
#include "exp_mgnt_private.h"
#include "cndrv_commu.h"
#include "cndrv_ipcm.h"

#define REPORT_OUBOUND_SIZE (0x100000)

extern char *mparam_report_path;
extern int mparam_report_mode;

static char *proc_files[] = {
	"cn_mem",
};
static char *proc_files_norpc[] = {
	"mlumsg",
};
/*file don't use seq file*/
static char *proc_rawfiles_norpc[] = {
	"kdump"
};
static char *debugfs_files[] = {
	"pid_info"
};

static int report_chain_register(struct cn_report_block **nl,
		struct cn_report_block *n)
{
	while ((*nl) != NULL) {
		if (n->priority > (*nl)->priority)
			break;
		nl = &((*nl)->next);
	}
	n->next = *nl;
	rcu_assign_pointer(*nl, n);
	return 0;
}

static int report_chain_unregister(struct cn_report_block **nl,
		struct cn_report_block *n)
{
	while ((*nl) != NULL) {
		if ((*nl) == n) {
			rcu_assign_pointer(*nl, n->next);
			return 0;
		}
		nl = &((*nl)->next);
	}
	return -ENOENT;
}

struct cn_report_block *cn_register_report(struct cn_core_set *core, char *name,
										   int prio, report_fn_t fn, void *data)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct cn_report_head *nh;
	struct cn_report_block *nb;

	if (cn_core_is_vf(core))
		return NULL;

	nh = &mnt_set->report_chain;
	nb = kmalloc(sizeof(struct cn_report_block), GFP_KERNEL);
	if (nb == NULL) {
		return NULL;
	}
	nb->name = name;
	nb->report_call = fn;
	nb->priority = prio;
	nb->data = data;

	down_write(&nh->rwsem);
	report_chain_register(&nh->head, nb);
	up_write(&nh->rwsem);
	return nb;
}
EXPORT_SYMBOL(cn_register_report);

int cn_unregister_report(struct cn_core_set *core, struct cn_report_block *nb)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct cn_report_head *nh = &mnt_set->report_chain;
	int ret;
	if(nb == NULL)
		return -EINVAL;

	down_write(&nh->rwsem);
	ret = report_chain_unregister(&nh->head, nb);
	up_write(&nh->rwsem);

	kfree(nb);
	return ret;
}
EXPORT_SYMBOL(cn_unregister_report);

static ssize_t cn_fs_read_seq(struct file *file, void *buf, size_t count, loff_t *pos)
{
#if (KERNEL_VERSION(5, 10, 0) < LINUX_VERSION_CODE)
/*
 * can't use ret = file->f_op->read(file, buf, count, pos)
 * for seq_file it will use seq_read() function
 * and iov_iter_init will be set for user space copy
 */
	struct kvec iov = { .iov_base = buf, .iov_len = count};
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, file);
	iov_iter_kvec(&iter, READ, &iov, 1, count);
	kiocb.ki_pos = *pos;
	ret = seq_read_iter(&kiocb, &iter);
	*pos = kiocb.ki_pos;

	if (ret > 0) {
		fsnotify_access(file);
		add_rchar(current, ret);
	}
	inc_syscr(current);
	return ret;
#else
	return cn_fs_read(file, buf, count, pos);
#endif
}

static ssize_t cn_fs_read_kernel(struct file *file, void *buf, size_t count, loff_t *pos)
{
#if (KERNEL_VERSION(5, 10, 0) < LINUX_VERSION_CODE)
	ssize_t ret = -EINVAL;
	if (file->f_op->read) {
		ret = file->f_op->read(file, buf, count, pos);

		if (ret > 0) {
			fsnotify_access(file);
			add_rchar(current, ret);
		}
		inc_syscr(current);
	}
	return ret;
#else
	return cn_fs_read(file, buf, count, pos);
#endif
}

static int report_call_chain(struct cn_core_set *core, char *file_path,
							 unsigned long val, void *v)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct cn_report_head *nh = &mnt_set->report_chain;
	struct cn_report_block *nb, *next_nb;
	int ret = 0;
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	mm_segment_t old_fs;
#endif
	struct file *fp;
	char *buf;

	buf = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		cn_dev_core_err(core, "no mem");
		return -ENOMEM;
	}

	if (rcu_access_pointer(nh->head)) {
		down_read(&nh->rwsem);
		nb = rcu_dereference_raw(nh->head);
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
		old_fs = get_fs();
		set_fs(KERNEL_DS);
#endif
		while (nb) {
			next_nb = rcu_dereference_raw(nb->next);
			if (nb->name == NULL) {
				nb = next_nb;
				continue;
			}

			memset(buf, 0, PATH_MAX);
			sprintf(buf, "%s/%s", file_path, nb->name);
			fp = filp_open(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
			if (IS_ERR(fp)) {
				cn_dev_core_err(core, "Open file:%s failed, %ld", buf,
								PTR_ERR(fp));
				ret = -EACCES;
				nb = next_nb;
				continue;
			}

			ret = nb->report_call(nb->data, val, (void *)fp);
			nb = next_nb;

			filp_close(fp, NULL);
		}
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
		set_fs(old_fs);
#endif
		up_read(&nh->rwsem);
	}
	cn_kfree(buf);
	return ret;
}

static int report_proc_files(struct cn_core_set *core, char *dest_path,
							 char *filelist[], int filenum, unsigned long val)
{
	struct bus_info_s bus_info;
	int ret = 0;
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	mm_segment_t old_fs;
#endif
	struct file *fp_src;
	struct file *fp_dest;
	char *buf;
	char src_path[256];
	int i = 0;
	int size, nread;
	char *tmp_buf;
	loff_t pos_src, pos_dest= 0;

	memset(src_path, 0, sizeof(src_path));
	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);
	switch (bus_info.bus_type) {
	case BUS_TYPE_EDGE: {
		size = sprintf(src_path, "%s/%04x:%04x/", "/proc/driver/cambircon/mlus",
		bus_info.info.edge.vendor, bus_info.info.edge.device);
		break;
	}
	case BUS_TYPE_PCIE: {
		size = sprintf(src_path, "%s/%04x:%02x:%02x.%x/", "/proc/driver/cambricon/mlus",
				bus_info.info.pcie.domain_id,
				bus_info.info.pcie.bus_num,
				bus_info.info.pcie.device_id >> 3,
				bus_info.info.pcie.device_id & 0x7);
		break;
	}
	default:
		cn_dev_core_err(core, "UNKNOWN BUS TYPE");
		return -1;
	}

	buf = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		cn_dev_core_err(core, "no mem");
		return -ENOMEM;
	}

	tmp_buf = cn_kzalloc(4096, GFP_KERNEL);
	if (!tmp_buf) {
		cn_dev_core_info(core, "no memory");
		cn_kfree(buf);
		return -ENOMEM;
	}

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	for(i = 0; i < filenum; i++) {
		if (filelist[i] == NULL)
			goto out;

		memset(buf, 0, PATH_MAX);
		sprintf(buf, "%s/%s", src_path, filelist[i]);
		fp_src = filp_open(buf, O_RDWR | O_CREAT, 0644);
		if (IS_ERR(fp_src)) {
			cn_dev_core_err(core, "Open file:%s failed, %ld", buf, PTR_ERR(fp_src));
			continue;
		}

		memset(buf, 0, PATH_MAX);
		sprintf(buf, "%s/%s", dest_path, filelist[i]);
		fp_dest = filp_open(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (IS_ERR(fp_dest)) {
			cn_dev_core_err(core, "Open file:%s failed, %ld", buf, PTR_ERR(fp_dest));
			filp_close(fp_src, NULL);
			continue;
		}

		pos_src = 0;
		pos_dest = 0;
		do {
			nread = cn_fs_read_seq(fp_src, tmp_buf, 4096, &pos_src);
			if (nread > 0)
				ret = cn_fs_write(fp_dest, tmp_buf, nread, &pos_dest);
		} while (nread > 0);

		filp_close(fp_src, NULL);
		filp_close(fp_dest, NULL);
	}

out:
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	set_fs(old_fs);
#endif
	cn_kfree(tmp_buf);
	cn_kfree(buf);

	return ret;
}

static int report_debugfs_files(struct cn_core_set *core, char *dest_path,
							char *filelist[], int filenum, unsigned long val)
{
	struct bus_info_s bus_info;
	int ret = 0;
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	mm_segment_t old_fs;
#endif
	struct file *fp_src;
	struct file *fp_dest;
	char *buf;
	char src_path[256];
	int i = 0;
	int size, nread;
	char *tmp_buf;
	loff_t pos_src, pos_dest= 0;

	memset(src_path, 0, sizeof(src_path));
	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);
	switch (bus_info.bus_type) {
	case BUS_TYPE_PCIE: {
		size = sprintf(src_path, "%s/cambricon_dev%d/", "/sys/kernel/debug",
				core->idx);
		break;
	}
	default:
		cn_dev_core_err(core, "UNKNOWN BUS TYPE");
		return -1;
	}

	buf = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		cn_dev_core_err(core, "no mem");
		return -ENOMEM;
	}

	tmp_buf = cn_kzalloc(4096, GFP_KERNEL);
	if (!tmp_buf) {
		cn_dev_core_info(core, "no memory");
		cn_kfree(buf);
		return -ENOMEM;
	}

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	for(i = 0; i < filenum; i++) {
		if (filelist[i] == NULL)
			goto out;

		memset(buf, 0, PATH_MAX);
		sprintf(buf, "%s/%s", src_path, filelist[i]);
		fp_src = filp_open(buf, O_RDWR | O_CREAT, 0644);
		if (IS_ERR(fp_src)) {
			cn_dev_core_err(core, "Open file:%s failed, %ld", buf, PTR_ERR(fp_src));
			continue;
		}

		memset(buf, 0, PATH_MAX);
		sprintf(buf, "%s/%s", dest_path, filelist[i]);
		fp_dest = filp_open(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (IS_ERR(fp_dest)) {
			cn_dev_core_err(core, "Open file:%s failed, %ld", buf, PTR_ERR(fp_dest));
			filp_close(fp_src, NULL);
			continue;
		}

		pos_src = 0;
		pos_dest = 0;
		do {
			nread = cn_fs_read_seq(fp_src, tmp_buf, 4096, &pos_src);
			if (nread > 0)
				ret = cn_fs_write(fp_dest, tmp_buf, nread, &pos_dest);
		} while (nread > 0);

		filp_close(fp_src, NULL);
		filp_close(fp_dest, NULL);
	}
out:
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	set_fs(old_fs);
#endif
	cn_kfree(tmp_buf);
	cn_kfree(buf);

	return ret;
}

static int report_proc_rawfiles(struct cn_core_set *core, char *dest_path,
							 char *filelist[], int filenum, unsigned long val)
{
	struct bus_info_s bus_info;
	int ret = 0;
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	mm_segment_t old_fs;
#endif
	struct file *fp_src;
	struct file *fp_dest;
	char *buf;
	char src_path[256];
	int i = 0;
	int size, nread;
	char *tmp_buf;
	loff_t pos_src, pos_dest= 0;

	memset(src_path, 0, sizeof(src_path));
	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);
	switch (bus_info.bus_type) {
	case BUS_TYPE_EDGE: {
		size = sprintf(src_path, "%s/%04x:%04x/", "/proc/driver/cambircon/mlus",
		bus_info.info.edge.vendor, bus_info.info.edge.device);
		break;
	}
	case BUS_TYPE_PCIE: {
		size = sprintf(src_path, "%s/%04x:%02x:%02x.%x/", "/proc/driver/cambricon/mlus",
				bus_info.info.pcie.domain_id,
				bus_info.info.pcie.bus_num,
				bus_info.info.pcie.device_id >> 3,
				bus_info.info.pcie.device_id & 0x7);
		break;
	}
	default:
		cn_dev_core_err(core, "UNKNOWN BUS TYPE");
		return -1;
	}

	buf = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		cn_dev_core_err(core, "no mem");
		return -ENOMEM;
	}

	tmp_buf = cn_kzalloc(4096, GFP_KERNEL);
	if (!tmp_buf) {
		cn_dev_core_info(core, "no memory");
		cn_kfree(buf);
		return -ENOMEM;
	}

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	for(i = 0; i < filenum; i++) {
		if (filelist[i] == NULL)
			goto out;

		memset(buf, 0, PATH_MAX);
		sprintf(buf, "%s/%s", src_path, filelist[i]);
		fp_src = filp_open(buf, O_RDWR | O_CREAT, 0644);
		if (IS_ERR(fp_src)) {
			cn_dev_core_err(core, "Open file:%s failed, %ld", buf, PTR_ERR(fp_src));
			continue;
		}

		memset(buf, 0, PATH_MAX);
		sprintf(buf, "%s/%s", dest_path, filelist[i]);
		fp_dest = filp_open(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (IS_ERR(fp_dest)) {
			cn_dev_core_err(core, "Open file:%s failed, %ld", buf, PTR_ERR(fp_dest));
			filp_close(fp_src, NULL);
			continue;
		}

		pos_src = 0;
		pos_dest = 0;
		do {
			nread = cn_fs_read_kernel(fp_src, tmp_buf, 4096, &pos_src);
			if (nread > 0)
				ret = cn_fs_write(fp_dest, tmp_buf, nread, &pos_dest);
		} while (nread > 0);

		filp_close(fp_src, NULL);
		filp_close(fp_dest, NULL);
	}

out:
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	set_fs(old_fs);
#endif
	cn_kfree(tmp_buf);
	cn_kfree(buf);

	return ret;
}

static int dev_mkdir(const char *name, umode_t mode)
{
	struct dentry *dentry;
	struct path path;
	int err;

	dentry = kern_path_create(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
#if (KERNEL_VERSION(5, 12, 0) > LINUX_VERSION_CODE)
	err = vfs_mkdir(path.dentry->d_inode, dentry, mode);
#else
	err = vfs_mkdir(&init_user_ns, path.dentry->d_inode, dentry, mode);
#endif

	done_path_create(&path, dentry);
	return err;
}

static int create_path(struct cn_core_set *core, const char *nodepath)
{
	char *path;
	char *s;
	int err = 0;

	/* parent directories do not exist, create them */
	path = kstrdup(nodepath, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	s = path;
	for (;;) {
		s = strchr(s, '/');
		if (!s)
			break;
		s[0] = '\0';
		err = dev_mkdir(path, 0755);
		if (err && err != -EEXIST) {
			cn_dev_core_err(core, "Error create path %d %s", err, s);
			break;
		}
		s[0] = '/';
		s++;
	}
	kfree(path);
	return err;
}

int __mnt_call_rpc_timeout(void *pcore, void *handle, char *func, void *msg,
		size_t msg_len, void *rsp, int *real_sz, size_t rsp_len, int time_out);

static int get_arm_report(struct cn_core_set *core, char *host_dir,
						  char *dev_dir, unsigned long val, void *v)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)(core->mnt_set);
	struct cn_bus_set *bus_set = (struct cn_bus_set *)(core->bus_set);
	void *endpoint = NULL;
	int ret = 0;
	struct rpc_report_param rpc_param = {0};
	struct rpc_arm_report_resp *rpc_resp;
	int out_size = 0;
	int i = 0;
	struct rpmsg_device *rpdev = NULL;
	int remote_fd = -1;
	int read_bytes = 0;
	char *tmpbuf = NULL;
	char *hostfile;
	char devfile[128];
	struct file *fp;
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	mm_segment_t old_fs;
#endif
	loff_t pos = 0;
	int index = 0;
	int oneloop;

	if (unlikely(!mnt_set)) {
		cn_dev_core_err(core, "mnt_set freed.");
		return -EINVAL;
	}

	if (unlikely(!bus_set)) {
		cn_dev_core_err(core, "bus_set freed.");
		return -EINVAL;
	}

	endpoint = mnt_set->endpoint;
	if (unlikely(!endpoint)) {
		cn_dev_core_err(core, "endpoint freed.");
		return -EINVAL;
	}

	if (strlen(dev_dir) >= 64) {
		cn_dev_core_err(core, "device file path %s big than 64", dev_dir);
		return -EINVAL;
	}

	if (strlen(host_dir) >= PATH_MAX - 64) {
		cn_dev_core_err(core, "host file path %s big than 4032", host_dir);
		return -EINVAL;
	}

	hostfile = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (!hostfile) {
		cn_dev_core_err(core, "no memory.");
		return -ENOMEM;
	}

	tmpbuf = cn_kzalloc(MAX_BUF_LEN, GFP_KERNEL);
	if (!tmpbuf) {
		cn_dev_core_err(core, "no memory.");
		ret = -ENOMEM;
		goto hostfile_failed;
	}

	rpc_resp = cn_kzalloc(sizeof(struct rpc_arm_report_resp) + sizeof(struct report_file_info)
						  * REPORT_MAX_FILE_CNT, GFP_KERNEL);
	if (!rpc_resp) {
		cn_dev_core_err(core, "no memory.");
		ret = -ENOMEM;
		goto tmpbuf_failed;
	}

	memcpy(rpc_param.file_path, dev_dir, strlen(dev_dir));
	rpc_param.cmd = val;
	ret = __mnt_call_rpc_timeout(core, endpoint, "rpc_arm_gen_report",
			&rpc_param,	sizeof(struct rpc_report_param), rpc_resp, &out_size,
			sizeof(struct heartbeat_pkg_s), 5000);
	if (ret < 0 || rpc_resp->ret < 0) {
		cn_dev_core_err(core, "cnrpc gen report failed (%d).", ret);
		goto fileinfo_failed;
	}

	/*only proc on or mode==auto will write file to host*/
	if ((mnt_set->report_mode != 2) && (mnt_set->report_on != 1)) {
		cn_kfree(tmpbuf);
		cn_kfree(rpc_resp);
		return 0;
	}

	/*get files with index*/
get_file_loops:
	rpc_param.cmd = index;
	ret = __mnt_call_rpc_timeout(core, endpoint, "rpc_arm_get_report_files",
			&rpc_param, sizeof(struct rpc_report_param), rpc_resp, &out_size,
			sizeof(struct heartbeat_pkg_s), 1000);
	if (ret < 0 || rpc_resp->ret < 0) {
		cn_dev_core_err(core, "cnrpc get report files failed (%d).", ret);
		goto fileinfo_failed;
	}
	cn_dev_core_info(core, "report file cnt(%d) index(%d) avaiable(%d).",
					 rpc_resp->file_cnt, index, rpc_resp->ret);

	oneloop = min(rpc_resp->file_cnt - index, REPORT_MAX_FILE_CNT);
	oneloop = min(oneloop, rpc_resp->ret);
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	for (i = 0; i < oneloop; i++) {
		cn_dev_core_info(core, "report file[%d]:%s, size:%d.", i,
			rpc_resp->files[i].file_name, rpc_resp->files[i].file_size);

		memset(hostfile, 0, PATH_MAX);
		memset(devfile, 0, sizeof(devfile));
		sprintf(hostfile, "%s/dev_%s", host_dir, rpc_resp->files[i].file_name);
		sprintf(devfile, "%s/%s", dev_dir, rpc_resp->files[i].file_name);

		remote_fd = ipcm_remote_open(core, &rpdev, devfile, O_RDONLY, 0);
		if (remote_fd < 0) {
			cn_dev_core_err(core, "Open devfile:%s failed(%d)", devfile, remote_fd);
			continue;
		}

		fp = filp_open(hostfile, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (IS_ERR(fp)) {
			cn_dev_core_err(core, "Open hostfile:%s failed, %ld", hostfile, PTR_ERR(fp));
			ipcm_remote_close(rpdev, remote_fd);
			continue;
		}

		pos = 0;
		while ((read_bytes = ipcm_remote_read(rpdev, remote_fd, tmpbuf, MAX_BUF_LEN)) > 0) {
			ret = cn_fs_write(fp, tmpbuf, read_bytes, &pos);
		}

		ipcm_remote_close(rpdev, remote_fd);
		filp_close(fp, NULL);
	}
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	set_fs(old_fs);
#endif

	index += i;
	if (index < rpc_resp->file_cnt)
		goto get_file_loops;

	ret = 0;

fileinfo_failed:
	cn_kfree(rpc_resp);
tmpbuf_failed:
	cn_kfree(tmpbuf);
hostfile_failed:
	cn_kfree(hostfile);
	return ret;
}

int cn_report_get_report_mode(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;

	return mnt_set->report_mode;
}

int cn_report_set_report_mode(struct cn_core_set *core, int value)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;

	mnt_set->report_mode = value;

	return 0;
}

int cn_report_get_report_on(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;

	return mnt_set->report_on;
}

void cn_report_set_report_on(struct cn_core_set *core, int value)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;

	mnt_set->report_on = value;
}

int cn_report_set_report_path(struct cn_core_set *core, char *path)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;

	if(strlen(path) < PATH_MAX) {
		memset(mnt_set->report_path, 0, PATH_MAX);
		memcpy(mnt_set->report_path, path, strlen(path));
	}

	return 0;
}

char *cn_report_get_report_path(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;

	return mnt_set->report_path;
}

static int report_outbound_set(struct cn_core_set *core,
							   unsigned long device_addr, unsigned long size)
{
	int ret = 0;
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct rpc_report_param rpc_param;
	struct rpc_arm_report_resp rpc_resp;
	int len;

	rpc_param.cmd = 1;
	rpc_param.outbound_iova = device_addr;
	rpc_param.outbound_size = size;

	ret = __mnt_call_rpc_timeout(core, mnt_set->endpoint, "rpc_arm_outbound_set",
			&rpc_param,	sizeof(struct rpc_report_param), &rpc_resp,
			&len, sizeof(struct heartbeat_pkg_s), 10000);
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client request failed (%d).\n", ret);
		return ret;
	}

	return rpc_resp.ret;
}

int cn_report_armflush(struct cn_core_set *core, int state)
{
	int ret = 0;
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct rpc_report_param rpc_param;
	struct rpc_arm_report_resp rpc_resp;
	int len;

	rpc_param.cmd = state;

	ret = __mnt_call_rpc_timeout(core, mnt_set->endpoint, "rpc_arm_flush",
			&rpc_param,	sizeof(struct rpc_report_param), &rpc_resp,
			&len, sizeof(struct heartbeat_pkg_s), 10000);
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client request failed (%d).\n", ret);
		return ret;
	}

	return ret;
}

int cn_report_query(struct cn_core_set *core, int *state)
{
	int ret = 0;
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct rpc_report_param rpc_param;
	struct rpc_arm_report_resp rpc_resp;
	int len;

	rpc_param.cmd = 1;

	ret = __mnt_call_rpc_timeout(core, mnt_set->endpoint, "rpc_arm_query_report",
			&rpc_param,	sizeof(struct rpc_report_param), &rpc_resp,
			&len, sizeof(struct heartbeat_pkg_s), 10000);
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client request failed (%d).\n", ret);
		return ret;
	}

	*state = rpc_resp.ret;
	return ret;
}

int cn_report_run(struct cn_core_set *core, unsigned long val, unsigned int host_only)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct bus_info_s bus_info;
	int size = 0;
	char *buf;

	buf = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		cn_dev_core_err(core, "no mem");
		return -ENOMEM;
	}

	memset(&bus_info, 0, sizeof(struct bus_info_s));

	cn_bus_get_bus_info(core->bus_set, &bus_info);
	switch (bus_info.bus_type) {
	case BUS_TYPE_EDGE: {
		size = sprintf(buf, "%s/%04x:%04x/", mnt_set->report_path,
		bus_info.info.edge.vendor, bus_info.info.edge.device);
		break;
	}
	case BUS_TYPE_PCIE: {
		size = sprintf(buf, "%s/%04x:%02x:%02x.%x/", mnt_set->report_path,
				bus_info.info.pcie.domain_id,
				bus_info.info.pcie.bus_num,
				bus_info.info.pcie.device_id >> 3,
				bus_info.info.pcie.device_id & 0x7);
		break;
	}
	default:
		size = sprintf(buf, "%s/", mnt_set->report_path);
		cn_dev_core_err(core, "UNKNOWN BUS TYPE");
		break;
	}

	cn_dev_core_info(core, "Report to %s", buf);
	/*only proc on or mode==auto will write file to host*/
	if ((mnt_set->report_mode == 2) || (mnt_set->report_on == 1)) {
		create_path(core, buf);
		if (host_only == 1) {
			report_proc_files(core, buf, proc_files_norpc, sizeof(proc_files_norpc)/sizeof(proc_files_norpc[0]), val);
			report_proc_rawfiles(core, buf, proc_rawfiles_norpc, sizeof(proc_rawfiles_norpc)/sizeof(proc_rawfiles_norpc[0]), val);
		} else {
			/*used rpc in lpm mode, maybe hung in heartbeat*/
			report_proc_files(core, buf, proc_files, sizeof(proc_files)/sizeof(proc_files[0]), val);
			report_debugfs_files(core, buf, debugfs_files, sizeof(debugfs_files)/sizeof(debugfs_files[0]), val);
		}
		report_call_chain(core, buf, val, NULL);
	}
	if ((host_only != 1) && (core->support_ipcm)) {
		get_arm_report(core, buf, "/var/log/cambricon/", val, NULL);
	}
	cn_dev_core_info(core, "Report to %s done", buf);
	cn_kfree(buf);
	return 0;
}

void cn_report_call(struct cn_core_set *core, unsigned long val)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	mnt_set->report_on = 2;
}

static int timestamp_notifier(void *data,
			     unsigned long action, void *fp)
{
	/*struct cn_core_set *core = (struct cn_core_set *)data;*/
	int ret = -1;
	loff_t pos = 0;
	struct file *fp1 = (struct file*)fp;
	char buf[128];
#if (KERNEL_VERSION(3, 17, 0) < LINUX_VERSION_CODE)
	struct timespec64 ts;
	ktime_get_ts64(&ts);
#else
	struct timespec ts;
	ktime_get_ts(&ts);
#endif
	memset(buf, 0, sizeof(buf));
	ret = sprintf(buf, "Time:%ld.%ld\n", (unsigned long)ts.tv_sec, ts.tv_nsec);
	if(ret > 0)
		ret = cn_fs_write(fp1, buf, ret, &pos);
	return ret;
}

static int outbound_notifier(void *data,
			     unsigned long action, void *fp)
{
	struct cn_core_set *core = (struct cn_core_set *)data;
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	int ret = -1;
	loff_t pos = 0;
	struct file *fp1 = (struct file*)fp;

	ret = cn_fs_write(fp1, (char *)mnt_set->outbound_host, REPORT_OUBOUND_SIZE, &pos);
	return ret;
}

void cn_report_init(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct cn_report_head *report_head = &mnt_set->report_chain;

	mnt_set->report_on = 0;
	mnt_set->report_mode = mparam_report_mode;
	mnt_set->report_path = cn_kzalloc(PATH_MAX, GFP_KERNEL);
	if (!mnt_set->report_path) {
		cn_dev_core_err(core, "no mem for report init");
		return;
	}
	memcpy(mnt_set->report_path, mparam_report_path,
		min(strlen(mparam_report_path), (size_t)(PATH_MAX - 64)));
	init_rwsem(&report_head->rwsem);
	report_head->head = NULL;

	mnt_set->nb_timestamp = cn_register_report(core, "timestamp", 0, timestamp_notifier, core);
	cn_dumpreg_init(core);
	if (cn_bus_outbound_able(core->bus_set))
		mnt_set->nb_dumpoutbound = cn_register_report(core, "fatal", 0, outbound_notifier, core);
}

void cn_report_free(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	if (cn_bus_outbound_able(core->bus_set))
		cn_unregister_report(core, mnt_set->nb_dumpoutbound);
	cn_unregister_report(core, mnt_set->nb_timestamp);
	cn_dumpreg_free(core);
	cn_kfree(mnt_set->report_path);
}

int cn_report_late_init(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;

	if (cn_bus_outbound_able(core->bus_set)) {
		cn_host_share_mem_alloc(0, &mnt_set->outbound_host,
							&mnt_set->outbound_device, REPORT_OUBOUND_SIZE, core);
		cn_dev_core_info(core, "Report outbound host:%lx iova:%llx",
						 mnt_set->outbound_host, mnt_set->outbound_device);
		report_outbound_set(core, mnt_set->outbound_device, REPORT_OUBOUND_SIZE);
	}
	return 0;
}

void cn_report_late_exit(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	if (cn_bus_outbound_able(core->bus_set))
		cn_host_share_mem_free(0, mnt_set->outbound_host,
							mnt_set->outbound_device, core);
}

