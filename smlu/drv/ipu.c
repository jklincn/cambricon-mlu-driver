#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/jiffies.h>
#include <linux/ptrace.h>

#include "ipu.h"
#include "util.h"
#include "trace.h"
#include "cndrv_smlu.h"

long ipu_util_adjust(int idx, int instance, long target, long usage)
{
	long result;
	long ki, kp, kd;
	struct pid_s *t;

	if (idx < 0 || idx >= MAX_PHYS_CARD || instance <= 0 || instance > MAX_SMLU_INSTANCE_COUNT) {
		pr_err("input param error, idx=%d, instance=%d\n",
			idx, instance);
		return -1;
	}

	kp = cn_pid_parameter[idx].IKP;
	ki = cn_pid_parameter[idx].IKI;
	kd = cn_pid_parameter[idx].IKD;

	t = &cn_pid_parameter[idx].pid_info[instance][IPU_UTIL];

	t->error = target - usage;
	t->proportion = (t->error - t->last_error) * kp / 1024;
	t->integral = (t->error * ki) / 1024;
	/*
	 * kernel not support float type, if error*ki less than 1024 integral will be zero,
	 * by the time, error and last_error and previous_error all the same, output will be zero
	 * this case will block ipu ioctl
	 */
	if (t->integral == 0 && t->error != 0)
		t->integral = 1;

	t->derivative = (t->error - 2 * t->last_error + t->previous_error) * kd / 1024;
	t->increase = t->proportion + t->integral + t->derivative;

	result = t->output + t->increase;
	if (result < -200) /* no negative output */
		result = -200;
	if (result > 200)
		result = 200;

	t->output = result;

	/* trace point */
	trace_record(idx, instance, IPU_UTIL, target, usage, t);

	pr_debug("adjust idx=%d, instance=%d, target=%ld, usage=%ld "
		"error=%ld, last=%ld, previous=%ld "
		"proportion=%ld, integral=%ld, derivative=%ld, increase=%ld, result=%ld\n",
		idx, instance, target, usage,
		t->error, t->last_error, t->previous_error,
		t->proportion, t->integral, t->derivative, t->increase, result);

	t->previous_error = t->last_error;
	t->last_error = t->error;
	t->time++;

	if (result < 0)
		result = 0;

	return result;
}

#define IPU_BLOCK_TIMEOUT	5000 // (ms)
long ipu_util_output(int idx, int instance)
{
	long cnt;
	__u64 time;
	__u64 start, cur;
	int i = 1; /* record times of timeout print */
	struct pid_s *t;

	if (idx < 0 || idx >= MAX_PHYS_CARD || instance <= 0 || instance > MAX_SMLU_INSTANCE_COUNT) {
		pr_err("input param error, idx=%d, instance=%d\n",
			idx, instance);
		return -ENODEV; /* -ENODEV means no util adjust */
	}

	t = &cn_pid_parameter[idx].pid_info[instance][IPU_UTIL];
	start = get_jiffies_64();

	while (!fatal_signal_pending(current)) {
		cur = get_jiffies_64();
		if (jiffies_to_msecs(cur - start) > (i * IPU_BLOCK_TIMEOUT)) {
			pr_warn("ipu block over %u(ms)\n", i * IPU_BLOCK_TIMEOUT);
			i++;
		}

		mutex_lock(&t->adjust_lock);
		cnt = t->output;
		time = t->time;

		if (t->last_time != time) {
			t->last_time = time;
			t->last_output = cnt;
			pr_debug("update time:%llu, cnt:%ld\n", time, cnt);
		}
		if (t->last_output > 0) {
			t->last_output--;
			pr_debug("idx:%d, instance:%d, output time:%llu, output cnt:%ld\n", idx, instance,
				time, t->last_output);
			mutex_unlock(&t->adjust_lock);
			return 0;
		}
		mutex_unlock(&t->adjust_lock);
	}

	/* ctrl-c return will kill task invoke process */
	return -EINTR;
}

