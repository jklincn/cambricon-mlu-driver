#ifndef __CAMBRICON_CNDRV_PMU_PROC_H__
#define __CAMBRICON_CNDRV_PMU_PROC_H__

int cndev_qos_show(struct seq_file *m, void *v);
ssize_t cndev_qos_write(struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos);
int cndev_show_info(struct seq_file *m, void *v);

#endif
