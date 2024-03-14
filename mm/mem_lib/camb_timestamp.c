#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/module.h>
#include "cndrv_pre_compile.h"
#include "camb_timestamp.h"

u64 camb_get_real_time_us(void)
{
	u64 tv_usec = 0;
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
