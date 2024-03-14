#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/vmalloc.h>

#include "proc.h"
#include "cndrv_core.h"
#include "cndrv_pre_compile.h"
#include "trace.h"
#include "cndrv_smlu.h"
#include "smlu/smlu_internal.h"

#define TRACE_BUFFER_N (2)
#define TRACE_BUFFER_SIZE (1024 * 1024)

#define TRACE_DISABLE (0)
#define TRACE_ENABLE  (1)

#define TRACE_END   (0)
#define TRACE_START (1)

#define TRACE_FILE "./trace.json"

struct trace_buffer_s {
	char *b;
	long total;
};

struct strace_s {
	bool online;
	unsigned long time;
};

static struct trace_ctl_s {
	int enable;
	int start;
	struct strace_s instance[MAX_PHYS_CARD][MAX_SMLU_INSTANCE_COUNT + 1];

	int index;     /* current using buffer index */
	struct trace_buffer_s buffer[TRACE_BUFFER_N];

	unsigned long time;
	struct work_struct work;

	spinlock_t lock;
	struct mutex file_lock;
	struct file *fp;
	loff_t pos;
} ctl;

static void set_all_online(void)
{
	int i, k;

	for (i = 0; i < MAX_PHYS_CARD; i++) {
		for (k = 1; k <= MAX_SMLU_INSTANCE_COUNT; k++) {
			ctl.instance[i][k].online = true;
		}
	}
}

static void set_all_offline(void)
{
	int i, k;

	for (i = 0; i < MAX_PHYS_CARD; i++) {
		for (k = 1; k <= MAX_SMLU_INSTANCE_COUNT; k++) {
			ctl.instance[i][k].online = false;
			ctl.instance[i][k].time = 0;
		}
	}
}

static void set_mlu_all_online(int idx)
{
	int k;

	for (k = 1; k <= MAX_SMLU_INSTANCE_COUNT; k++) {
		ctl.instance[idx][k].online = true;
	}
}


static void set_online(int idx, int instance)
{
	ctl.instance[idx][instance].online = true;
}

static unsigned long real_time_us(void)
{
	unsigned long tv_usec = 0;
#if (KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE)
	struct timespec64 ts64;
	ktime_get_real_ts64(&ts64);
	tv_usec = timespec64_to_ns(&ts64) / 1000;
#else
	struct timeval tv;
	do_gettimeofday(&tv);
	tv_usec = tv.tv_usec + tv.tv_sec * 1000000;
#endif
	return tv_usec;
}

static int trace_json(int idx, int instance_id, enum util_type sub,
	unsigned long target, unsigned long usage, struct pid_s *t,
			unsigned long start, unsigned long dur)
{
	int index = ctl.index;
	long total = ctl.buffer[index].total;
	char *dst = ctl.buffer[index].b + total;
	int ret;

	ret = sprintf(dst,
		"{\"name\": \"target=%ld,usage=%ld,error=%ld,last=%ld,previous=%ld,"
		"proportion=%ld,integral=%ld,derivative=%ld,"
		"increase=%ld,output=%ld\","
		"\"ph\":\"X\",\"pid\":\"MLU-%d\","
		"\"tid\":\"instance-%d\",\"ts\":%ld,\"dur\":%ld},\n",
		target, usage,
		t->error, t->last_error, t->previous_error,
		t->proportion, t->integral, t->derivative,
		t->increase, t->output,
		idx, instance_id,
		start, dur);
	return ret;
}

static int trace_to_file(char *buf, long length)
{
	int ret;
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	mm_segment_t old_fs;
#endif

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif

	if (length > 0) {
		ret = cn_fs_write(ctl.fp, buf, length, &ctl.pos);
		if (ret != length) {
			pr_err("fs write fail ret=%d\n", ret);
			return -1;
		}
	}

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	set_fs(old_fs);
#endif
	return 0;
}

static int trace_to_file_end(void)
{
	int index = ctl.index;
	long length = ctl.buffer[index].total;
	char *buf = ctl.buffer[index].b;

	return trace_to_file(buf, length);
}

void trace_record(int idx, int instance_id, enum util_type sub,
	unsigned long target, unsigned long usage, struct pid_s *t)
{
	int ret;
	int index;
	unsigned long start, dur;
	unsigned long cur = real_time_us();

	if (ctl.enable != TRACE_ENABLE || ctl.start != TRACE_START ||
			idx < 0 || idx >= MAX_PHYS_CARD ||
			instance_id <= 0 || instance_id > MAX_SMLU_INSTANCE_COUNT ||
			ctl.instance[idx][instance_id].online != true) {
		return;
	}

	/* first point just init */
	if (ctl.instance[idx][instance_id].time == 0) {
		ctl.instance[idx][instance_id].time = cur;
		return;
	}

	start = ctl.instance[idx][instance_id].time - ctl.time;
	dur = cur - ctl.instance[idx][instance_id].time;
	ctl.instance[idx][instance_id].time = cur;

	spin_lock(&ctl.lock);
	ret = trace_json(idx, instance_id, sub, target, usage, t, start, dur);
	index = ctl.index;
	ctl.buffer[index].total += ret;

	/* 256 is reserve for last record and trace end flag */
	if (ctl.buffer[index].total + 256 >= TRACE_BUFFER_SIZE) {
		ctl.index = ctl.index == 0 ? 1: 0; /* pingpong */
		index = ctl.index;

		if (ctl.buffer[index].total != 0) {
			spin_unlock(&ctl.lock);
			pr_err("bug on: write file slow, maybe need a bigger buffer\n");
			return;
		}
		queue_work(system_unbound_wq, &ctl.work);
	}
	spin_unlock(&ctl.lock);
}

static int get_cur_write_back_index(void)
{
	return ctl.index == 1 ? 0 : 1;
}

static void write_back_work(struct work_struct *work)
{
	int ret;
	int i = get_cur_write_back_index(); /* pingpong */
	long length  = ctl.buffer[i].total;
	char *buf = ctl.buffer[i].b;

	pr_debug("schdule work, write back index=%d, total=%ld\n", i, length);
	if (length == 0) {
		pr_err("bug on: no data need write back\n");
		return;
	}

	ret = trace_to_file(buf, length);
	if (ret) {
		pr_err("bug on: write back to file failed\n");
	}

	ctl.buffer[i].total = 0;
}

static int trace_enable(void *arg)
{
	int i;

	if (ctl.enable == TRACE_ENABLE) {
		pr_info("already enable trace\n");
		return 0 ;
	}

	for (i = 0; i < TRACE_BUFFER_N; i++) {
		ctl.buffer[i].b = vmalloc(TRACE_BUFFER_SIZE);
		if (ctl.buffer[i].b == NULL)
			return -1;
	}

	ctl.enable = TRACE_ENABLE;
	ctl.start = TRACE_END;

	return 0;
}

static int trace_disable(void *arg)
{
	int i;

	if (ctl.enable != TRACE_ENABLE) {
		pr_info("disable trace need enable trace first\n");
		return 0;
	}

	if (ctl.start != TRACE_END) {
		pr_info("disable trace need end trace first\n");
		return 0;
	}

	ctl.enable = TRACE_DISABLE;
	set_all_offline();

	for (i = 0; i < TRACE_BUFFER_N; i++) {
		if (ctl.buffer[i].b)
			vfree(ctl.buffer[i].b);
	}
	return 0;
}

static void trace_json_start(void)
{
	int index = ctl.index;
	long total = ctl.buffer[index].total;
	char *dst = ctl.buffer[index].b + total;
	int ret;

	ret = sprintf(dst, "[\n");
	ctl.buffer[index].total += ret;
}

static int trace_add(void *arg)
{
	char *t, *k;
	char buf[64];
	int ret;
	int idx, instance_id;

	if (arg == NULL)
		return -1;

	if (ctl.enable != TRACE_ENABLE) {
		pr_info("add trace need enable trace first\n");
		return 0;
	}

	/* add all */
	if (strncmp(arg, "all", strlen("all")) == 0) {
		set_all_online();
		return 0;
	}

	/* add mlu<0>-instance<all> */
	ret = sscanf(arg, "mlu<%d>-instance<%s>", &idx, buf);
	if (ret != 2 || idx < 0 || idx >= MAX_PHYS_CARD)
		return -1;

	if (strncmp(buf, "all", strlen("all")) == 0) {
		set_mlu_all_online(idx);
		return 0;
	}

	/* add mlu<0>-instance<1,2,3> */
	k = buf;
	while ((t = strsep(&k, ",")) != NULL) {
		ret = sscanf(t, "%d", &instance_id);
		if (ret != 1 || instance_id <= 0 || instance_id > MAX_SMLU_INSTANCE_COUNT) {
			return -1;
		}
		set_online(idx, instance_id);
	}
	return 0;
}

static int trace_start(void *arg)
{
	int i, k;

	if (ctl.enable != TRACE_ENABLE) {
		pr_info("start trace need enable trace first\n");
		return 0;
	}

	ctl.fp = filp_open(TRACE_FILE, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(ctl.fp)) {
		pr_err("Open file:%s failed, %ld", TRACE_FILE, PTR_ERR(ctl.fp));
		return -1;
	}

	for (i = 0; i < MAX_PHYS_CARD; i++) {
		for (k = 1; k <= MAX_SMLU_INSTANCE_COUNT; k++) {
			ctl.instance[i][k].time = 0;
		}
	}

	ctl.index = 0;
	ctl.time = real_time_us();
	ctl.pos = 0;

	for (i = 0; i < TRACE_BUFFER_N; i++) {
		ctl.buffer[i].total = 0;
	}

	trace_json_start();
	ctl.start = TRACE_START;

	return 0;
}

static void trace_json_end(void)
{
	int index = ctl.index;
	long total = ctl.buffer[index].total;
	char *dst = ctl.buffer[index].b + total;
	int ret;

	/* last ',' is no need, so replace it with ']' */
	if (total > 3) {
		dst = dst - 2;
		*dst = ']';
	} else {
		ret = sprintf(dst, "]");
		ctl.buffer[index].total += ret;
	}
}

static int trace_end(void *arg)
{
	if (ctl.enable != TRACE_ENABLE) {
		printk("trace end need trace start first\n");
		return 0;
	}

	ctl.start = TRACE_END;

	/*
	 * wait a while for workqueue write back file finished,
	 * just for code simple, not add lock now
	 */
	msleep(100);

	trace_json_end();
	trace_to_file_end();

	if (ctl.fp) {
		filp_close(ctl.fp, NULL);
	}

	return 0;
}

#define ECHO_TRACE_USAGE_HELP \
"usage:\n" \
"--enable trace:" \
"\n\t echo \"enable\" > /proc/cambricon-util_drv/trace\n" \
"--add smlu instance:" \
"\n\t echo \"add [all][mlu<idx>-instance<all>][mlu<idx>-instance<id,id>]\" > /proc/cambricon-util_drv/trace\n" \
"--start trace:" \
"\n\t echo \"start\" > /proc/cambricon-util_drv/trace\n" \
"--end trace:" \
"\n\t echo \"end\" > /proc/cambricon-util_drv/trace\n" \
"--disable trace:" \
"\n\t echo \"disable\" > /proc/cambricon-util_drv/trace\n"

static int trace_show(struct seq_file *m, void *v)
{
	int i, k;
	int exist;

	seq_printf(m, "Trace state is [%s]\n",
			ctl.enable ? "enable" : "disable");

	for (i = 0; i < MAX_PHYS_CARD; i++) {
		exist  = 0;
		for (k = 1; k <= MAX_SMLU_INSTANCE_COUNT; k++) {
			if (ctl.instance[i][k].online != true ||
					!ex_util_data[i][k][IPU_UTIL].util_target)
				continue;
			if (exist == 0) {
				exist = 1;
				seq_printf(m, "MLU<%d>-instance<%d", i, k);
			} else {
				seq_printf(m, ",%d", k);
			}
		}
		if (exist == 1)
			seq_printf(m, "> trace start\n");
	}

	seq_printf(m, "\r\n%s\r\n", ECHO_TRACE_USAGE_HELP);
	return 0;
}

static int trace_open(struct inode *inode, struct file *file)
{
	return single_open(file, trace_show, NULL);
}

static struct trace_proc_ops {
	char *cmd;
	int (*fn)(void *);
} cmd_t[] = {
	{"enable", trace_enable},
	{"add", trace_add},
	{"start", trace_start},
	{"end", trace_end},
	{"disable", trace_disable},
};

static ssize_t trace_write(struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	char buf[128];
	int ret, i;
	char *t;
	char *k = buf;

	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;
	buf[count] = '\0';

	/* t=enable/disable/start/end/add */
	t = strsep(&k, " ");
	if (t == NULL)
		goto help;

	for (i = 0; i < ARRAY_SIZE(cmd_t); i++) {
		if (strncmp(t, cmd_t[i].cmd, strlen(cmd_t[i].cmd)) == 0) {
			ret = cmd_t[i].fn(k);
			if (ret)
				goto help;
			return count;
		}
	}
help:
	printk("%s\n", ECHO_TRACE_USAGE_HELP);
	return count;
}

#if KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE
static const struct file_operations fops = {
	.owner		= THIS_MODULE,
	.open		= trace_open,
	.read		= seq_read,
	.write		= trace_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#else
static const struct proc_ops fops = {
	.proc_open	= trace_open,
	.proc_read	= seq_read,
	.proc_write	= trace_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#endif

int util_trace_init(void)
{
	struct proc_dir_entry *e;

	INIT_WORK(&ctl.work, write_back_work);
	spin_lock_init(&ctl.lock);
	mutex_init(&ctl.file_lock);

	e = proc_create("trace", 0666, util_dir, &fops);
	if (e == NULL) {
		printk("proc create fail\n");
		return -1;
	}

	set_all_offline();
	return 0;
}


void util_trace_exit(void)
{

}
