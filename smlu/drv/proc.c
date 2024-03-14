#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "proc.h"
#include "util.h"

struct proc_dir_entry *util_dir;

#define ECHO_USAGE_HELP \
"usae help: \n\
\t--<CardID> from 0 to 127 \n\
\t--IKP/IKI/IKD mean IPU PID parameter\n\
\techo \"<0>=IKP:1024;IKI:512;IKD:512,<1>=IKP:1024;IKI:512;IKD:512\" > /proc/cambricon-util_drv/pid"

static int util_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cn_pid_parameter); i++) {
		if (!strcmp(cn_pid_parameter[i].board_model_name, ""))
			continue;

		seq_printf(m, "<%d>=IKP:%ld;IKI:%ld;IKD:%ld\n",
			i, cn_pid_parameter[i].IKP,
			cn_pid_parameter[i].IKI, cn_pid_parameter[i].IKD);
	}

	seq_printf(m, "\r\n%s\r\n", ECHO_USAGE_HELP);

	return 0;
}

static int util_open(struct inode *inode, struct file *file)
{
	return single_open(file, util_show, NULL);
}

/*
 * <0>=IKP:1024;IKI:512;IKD:512,<1>=IKP:1024;IKI:512;IKD:512
 */
int parse(char *k)
{
	char *t;
	int ret, idx;

	t = strsep(&k, "=");
	if (t == NULL)
		return -1;

	/* t=<0> */
	ret = sscanf(t, "<%d>", &idx);
	if (ret != 1 || idx < 0 || idx >= MAX_PHYS_CARD
			|| !strcmp(cn_pid_parameter[idx].board_model_name, "")) {
		return -1;
	}

	/* IKP:1024;IKI:512;IKD:512 */
	while ((t = strsep(&k, ";")) != NULL) {
		char sub[16] = {0};
		long value;

		ret = sscanf(t, "%c%c%c:%ld", &sub[0], &sub[1], &sub[2], &value);
		if (ret != 4)
			return -1;

		if (strcmp("IKP", sub) == 0) {
			cn_pid_parameter[idx].IKP = value;
		} else if (strcmp("IKI", sub) == 0) {
			cn_pid_parameter[idx].IKI = value;
		} else if (strcmp("IKD", sub) == 0) {
			cn_pid_parameter[idx].IKD = value;
		} else {
			return -1;
		}
	}

	return 0;
}

static ssize_t util_write(struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	char *k, *t;
	int ret;

	k = kmalloc(count + 1, GFP_KERNEL);
	if (k == NULL)
		return -1;

	if (copy_from_user(k, user_buf, count)) {
		kfree(k);
		return -EFAULT;
	}

	k[count] = '\0';

	while ((t = strsep(&k, ",")) != NULL) {
		ret = parse(t);
		if (ret) {
			printk("%s\n", ECHO_USAGE_HELP);
			goto exit;
		}
	}

exit:
	kfree(k);
	return count;
}

#if KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE
static const struct file_operations fops = {
	.owner		= THIS_MODULE,
	.open		= util_open,
	.read		= seq_read,
	.write		= util_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#else
static const struct proc_ops fops = {
	.proc_open	= util_open,
	.proc_read	= seq_read,
	.proc_write	= util_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#endif

int util_proc_init(void)
{
	struct proc_dir_entry *e;

	util_dir = proc_mkdir("cambricon-util_drv", NULL);
	if (util_dir == NULL) {
		printk("proc mkdir fail\n");
		return -1;
	}

	e = proc_create("pid", 0666, util_dir, &fops);
	if (e == NULL) {
		printk("proc create fail\n");
		return -1;
	}

	return 0;
}

void util_proc_exit(void)
{
	if (util_dir)
		proc_remove(util_dir);
}
