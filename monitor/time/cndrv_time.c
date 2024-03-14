#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/platform_device.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/math64.h>
#include <linux/seq_file.h>
#include <asm/io.h>
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_commu.h"
#include "cndrv_debug.h"
#include "camb_pmu_rpc.h"

#include "cndrv_time.h"

#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_ipcm.h"
#include "cndrv_mcu.h"

int cn_perf_shm_alloc(struct monitor_perf_set *perf_set,
					 host_addr_t *host_va,
					 dev_addr_t *dev_iova,
					 u64 size)
{
	struct cn_core_set *core = perf_set->core;

	if (cn_bus_outbound_able(core->bus_set))
		return cn_host_share_mem_alloc(0, host_va, dev_iova, size, core);
	else
		return cn_device_share_mem_alloc(0, host_va, dev_iova, size, core);
}

void cn_perf_shm_free(struct monitor_perf_set *perf_set,
					  host_addr_t host_va,
					  dev_addr_t dev_iova)
{
	struct cn_core_set *core = perf_set->core;

	if (cn_bus_outbound_able(core->bus_set))
		cn_host_share_mem_free(0, host_va, dev_iova, core);
	else
		cn_device_share_mem_free(0, host_va, dev_iova, core);
}

#define TIME_SYNC_INTERVAL_US   (4000000)

static u64 get_host_monotonic_raw_time(void)
{
	u64 raw_time;
#if (KERNEL_VERSION(3, 17, 0) > LINUX_VERSION_CODE)
	struct timespec tp;

	getrawmonotonic(&tp);
	raw_time = timespec_to_ns(&tp);
#else
	raw_time = ktime_get_raw_ns();
#endif

	return raw_time;
}

static u64 get_host_monotonic_time(void)
{
	u64 time;
#if (KERNEL_VERSION(3, 17, 0) > LINUX_VERSION_CODE)
	struct timespec tp;

	ktime_get_ts(&tp);
	time = timespec_to_ns(&tp);
#else
	time = ktime_get_ns();
#endif

	return time;
}

u64 get_host_timestamp_by_clockid(int clockid)
{
	u64 timestamp;

	switch (clockid) {
	case CLOCK_MONOTONIC:
		timestamp = get_host_monotonic_time();
		break;
	case CLOCK_MONOTONIC_RAW:
		timestamp = get_host_monotonic_raw_time();
		break;
	default:
		timestamp = 0;
		cn_dev_warn("unsupport clock id[%d]", clockid);
		break;

	}

	return timestamp;
}

static int __ts_device_thread_set(struct monitor_perf_set *perf_set, u64 cmd)
{
	struct ts_offset_rpc_set_s rpc_set;
	struct cn_monitor_set *monitor_set = perf_set->monitor_set;
	int ret = 0, in_len = 0, result = 0;

	rpc_set.cmd = cmd;
	rpc_set.tx_vaddr = perf_set->tx_dev_vaddr;
	rpc_set.rx_vaddr = perf_set->rx_dev_vaddr;
	ret = __pmu_call_rpc_timeout(perf_set->core, perf_set->time_ep,
				"perf_rpc_get_device_time",
				&rpc_set, sizeof(rpc_set),
				&result, &in_len, sizeof(result),
				4 * HZ);
	cn_dev_monitor_debug(monitor_set, "result:%d, in_len:%d, ret:%d",
									result, in_len, ret);
	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "call rpc func error");
		return -EFAULT;
	}

	if (result) {
		return -EAGAIN;
	}

	return 0;
}


#define MAX_CACHELINE_SIZE (512)
static int __time_sync_shm_alloc(struct monitor_perf_set *perf_set)
{
	struct cn_monitor_set *monitor_set = perf_set->monitor_set;
	struct cn_core_set *core = perf_set->core;
	int tx_shm_size = ALIGN(sizeof(u64), MAX_CACHELINE_SIZE);
	int rx_shm_size = ALIGN(sizeof(*(perf_set->ack.d_as)), MAX_CACHELINE_SIZE);
	int ret;

	/* alloc inb shm for tx */
	ret = cn_device_share_mem_alloc(0,
			&perf_set->tx_host_vaddr, &perf_set->tx_dev_vaddr,
			tx_shm_size, core);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "alloc rx share mem failed");
		return ret;
	}

	/* alloc outb(if support) shm for rx */
	ret = cn_perf_shm_alloc(perf_set, &perf_set->rx_host_vaddr,
				&perf_set->rx_dev_vaddr, rx_shm_size);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "alloc rx share mem failed");
		cn_device_share_mem_free(0,
			perf_set->tx_host_vaddr, perf_set->tx_dev_vaddr, core);
		return ret;
	}

	/* use hpas for guaranteeing that 8 byte read is atomic */
	hpas_init(&perf_set->ack, (struct time_sync_ack_as *)perf_set->rx_host_vaddr);

	cn_dev_monitor_info(monitor_set,
			"alloc share mem for time sync: tx_host_addr[%#llx], tx_dev_addr[%#llx], rx_host_addr[%#llx], rx_dev_addr[%#llx]",
			(u64)perf_set->tx_host_vaddr, (u64)perf_set->tx_dev_vaddr,
			(u64)perf_set->rx_host_vaddr, (u64)perf_set->rx_dev_vaddr);

	return 0;

}

static void __time_sync_shm_free(struct monitor_perf_set *perf_set)
{
	struct cn_core_set *core = perf_set->core;

	/* free share mem of tx */
	cn_device_share_mem_free(0,
			perf_set->tx_host_vaddr, perf_set->tx_dev_vaddr, core);
	perf_set->tx_host_vaddr = 0;
	perf_set->tx_dev_vaddr = 0;

	/* free share mem of rx */
	cn_perf_shm_free(perf_set, perf_set->rx_host_vaddr, perf_set->rx_dev_vaddr);
	perf_set->rx_host_vaddr = 0;
	perf_set->rx_dev_vaddr = 0;
}

static inline void __time_sync_ep_init(host_addr_t tx_host_vaddr,
		host_addr_t rx_host_vaddr)
{
	memset_io((void *)tx_host_vaddr, 0, sizeof(u64));
	memset_io((void *)rx_host_vaddr, 0, ALIGN(sizeof(struct time_sync_ack_as), MAX_CACHELINE_SIZE));
	wmb(); /* flush */
}


/* host write to tx endpoint, which read by device */
static inline void __time_sync_tx_write_cmd(host_addr_t tx_host_vaddr, u64 data)
{
	memcpy_toio((void *)tx_host_vaddr, &data, sizeof(u64));
	wmb(); /* flush write buffer */
}

/* host read from tx endpoint, which write by device */
static inline u64 __time_sync_tx_read_cmd(host_addr_t tx_host_vaddr)
{
	u64 data;

	memcpy_fromio(&data, (void *)tx_host_vaddr, sizeof(u64));
	return data;
}

/* host read dev timestamp from rx endpoint */
static inline u64 __time_sync_rx_read(struct time_sync_ack *ack)
{
	struct time_sync_timestamp dev_ts = {0};
	int ret;

	ret = hpas_read(ack, &dev_ts);
	if (ret) {
		return dev_ts.dev_timestamp;
	} else {
		return 0;
	}
}

/* NOTICE: this macro also define in device */
#define DEVICE_THREAD_START  (0x1)
#define HOST_TRIGGER_CMD     (0x2)
__attribute__((unused)) static int
__get_single_time_sync_sample_pcie(struct monitor_perf_set *perf_set,
					u64 *host_timestamp, u64 *device_timestamp, u64 *max_err_ns,
					s32 clockid)
{
	struct cn_monitor_set *monitor_set = perf_set->monitor_set;
	struct cn_core_set *core = perf_set->core;
	u64 host_timestamp_before = 0, host_timestamp_after = 0;
	host_addr_t tx_vaddr = perf_set->tx_host_vaddr;
	host_addr_t rx_vaddr = perf_set->rx_host_vaddr;
	int64_t timeout;
	unsigned long flags;
	u64 temp;
	int ret = 0;

	if (!perf_set->time_ep) {
		return -EINVAL;
	}

	if (!tx_vaddr || !rx_vaddr) {
		cn_dev_monitor_err(monitor_set,
				"tx_vaddr[%#lx] or rx_vaddr[%#lx] is NULL!",
				tx_vaddr, rx_vaddr);
		return -EINVAL;
	}

	/* init tx and rx share mem */
	__time_sync_ep_init(tx_vaddr, rx_vaddr);

	/* 1. call rpc to create device polling thread */
	ret = __ts_device_thread_set(perf_set, DEVICE_THREAD_CREATE);
	if (ret) {
		cn_dev_monitor_debug(monitor_set,
				"device polling thread config error");
		return ret;
	}

	if (!spin_trylock_irqsave(&perf_set->ts_offset_lock, flags)) {
		cn_dev_monitor_debug(monitor_set, "get lock failed, try again");
		ret = -EAGAIN;
		goto err_trylock_failed;
	}

	/* 2. wait device thread run and inform host */
	timeout = TIME_SYNC_TIMEOUT;
	while (--timeout) {
		temp = __time_sync_tx_read_cmd(tx_vaddr);
		if (temp == DEVICE_THREAD_START) {
			break;
		}
		if (core->reset_flag != 0) {
			cn_dev_monitor_debug(monitor_set, "driver will reset, exit!");
			spin_unlock_irqrestore(&perf_set->ts_offset_lock, flags);
			return -EINTR;
		}
		udelay(1);
	}

	if (!timeout) {
		cn_dev_monitor_debug(monitor_set, "wait device poll thread run timeout");
		ret = -ETIMEDOUT;
		goto err_handle;
	}

	/* 3. trigger device to write device timestamp to share mem */
	host_timestamp_before =
		get_host_timestamp_by_clockid(clockid);
	temp = HOST_TRIGGER_CMD;
	__time_sync_tx_write_cmd(tx_vaddr, temp);

	/* 4. wait device thread write device timestamp to share mem */
	timeout = TIME_SYNC_TIMEOUT;
	while (--timeout) {
		temp = __time_sync_rx_read(&perf_set->ack);
		if (temp != 0) {
			host_timestamp_after = get_host_timestamp_by_clockid(clockid);
			*device_timestamp = temp;
			cn_dev_monitor_debug(monitor_set,
					"receive device timestamp[%llu] succ, timeout[%lld]",
					temp, timeout);
			cn_dev_monitor_debug(monitor_set,
					"host start ts[%llu], finish ts[%llu], cost: %lldns",
					host_timestamp_before, host_timestamp_after,
					host_timestamp_after - host_timestamp_before);
			break;
		}

		if (core->reset_flag != 0) {
			cn_dev_monitor_info(monitor_set, "driver will reset, exit!");
			spin_unlock_irqrestore(&perf_set->ts_offset_lock, flags);
			return -EINTR;
		}
		ndelay(100);
	}

	if (!timeout) {
		*device_timestamp = 0;
		cn_dev_monitor_debug(monitor_set, "receive device ts timestamp timeout");
		ret = -ETIMEDOUT;
		goto err_handle;
	}

	*host_timestamp = host_timestamp_before / 2 + host_timestamp_after / 2;
	*max_err_ns = host_timestamp_after - host_timestamp_before;

err_handle:
	spin_unlock_irqrestore(&perf_set->ts_offset_lock, flags);
err_trylock_failed:
	/* 5. call rpc to destroy device polling thread */
	__ts_device_thread_set(perf_set, DEVICE_THREAD_DESTROY);
	return ret;
}

static inline u64 __get_raw_tsg_ns(struct monitor_perf_set *perf_set)
{
	struct cn_monitor_set *monitor_set = perf_set->monitor_set;
	__le64 result;
	int in_len;
	int ret;

	/* in edge platform,
	 * we can call this api which defined in monitor_arm directly by rpc
	 */
	ret = __pmu_call_rpc(perf_set->core, perf_set->time_ep,
				"perf_rpc_get_raw_tsg_ns",
				NULL, 0,
				&result, &in_len, sizeof(result));
	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "call rpc func error");
		return 0;
	}

	return le64_to_cpu(result);
}

static int __get_single_time_sync_sample_edge(struct monitor_perf_set *perf_set,
					u64 *host_timestamp, u64 *device_timestamp, u64 *max_err_ns,
					s32 clockid)
{
	struct cn_monitor_set *monitor_set = perf_set->monitor_set;
	u64 host_timestamp_before = 0, host_timestamp_after = 0;
	unsigned long flags;

	if (!spin_trylock_irqsave(&perf_set->ts_offset_lock, flags)) {
		cn_dev_monitor_info(monitor_set, "get lock failed, try again");
		return -EAGAIN;
	}

	host_timestamp_before = get_host_timestamp_by_clockid(clockid);
	*device_timestamp = __get_raw_tsg_ns(perf_set);

	host_timestamp_after = get_host_timestamp_by_clockid(clockid);

	spin_unlock_irqrestore(&perf_set->ts_offset_lock, flags);

	if (!*device_timestamp) {
		return -EFAULT;
	}

	*host_timestamp = host_timestamp_before / 2 + host_timestamp_after / 2;
	*max_err_ns = host_timestamp_after - host_timestamp_before;

	return 0;
}

static int __get_single_time_sync_sample(struct monitor_perf_set *perf_set,
					u64 *host_timestamp, u64 *device_timestamp, u64 *max_err_ns,
					s32 clockid)
{
	int ret;

#ifdef CONFIG_CNDRV_EDGE
	ret = __get_single_time_sync_sample_edge(perf_set,
					host_timestamp, device_timestamp, max_err_ns,
					clockid);
#else
	struct cn_core_set *core = perf_set->core;
	if (!cn_core_is_vf(core) && cn_is_mim_en(core)) {
		ret = __get_single_time_sync_sample_edge(perf_set,
						host_timestamp, device_timestamp, max_err_ns,
						clockid);
	} else {
		ret = __get_single_time_sync_sample_pcie(perf_set,
						host_timestamp, device_timestamp, max_err_ns,
						clockid);
	}
#endif

	return ret;
}


/*
 * Background:
 *  1. there are offset between host clock and device, because of difference boot time.
 *  2. crystal(clock) is not ideal, so the offset is not invariable.
 *  3. the offset has linear increase or decline with time increase.
 */
static int __time_sync_algorithm(struct cn_monitor_set *monitor_set,
		u64 *host_timestamp, u64 *device_timestamp, u64 *max_err_ns, s32 clockid)
{
#define MAX_ERROR_TOLERANCE (5000)
	struct monitor_perf_set *perf_set = monitor_set->perf_set;
	u64 __host_timestamp = 0, __device_timestamp = 0, __max_err_ns = 0;
	int ret = 0;
	int retry = 5;

	if (mutex_lock_killable(&perf_set->ts_offset_mutex)) {
		return -EINTR;
	}

	/* max_err_ns is the error of single time synchronization
	 * to get better time sync result, may retry (max 5 times)
	 * 1. if max_err_ns > 10us, retry again
	 *    (after 5 times, if max_err_ns also greater than 10us, return failed)
	 * 2. if 5us <= max_err_ns < 10us, retry again
	 *    (after 5 times, if max_err_ns also greater than 5us, return success)
	 * 3. if max_err_ns < 5us, exit directly and return success
	 */
	do {
		ret = __get_single_time_sync_sample(perf_set, &__host_timestamp,
				&__device_timestamp, &__max_err_ns, clockid);
		if (ret) {
			cn_dev_monitor_debug(monitor_set, "get time offset failed");
			goto err_handle;
		}

		if (__max_err_ns <= MAX_ERROR_TOLERANCE)
			break;
	} while (--retry);

	if (!retry)
		ret = -EAGAIN;

	/* update by min tolerance */
	*host_timestamp   = __host_timestamp;
	*device_timestamp = __device_timestamp;
	*max_err_ns       = __max_err_ns;

	cn_dev_monitor_debug(monitor_set,
			"clk [%d] host_timestamp       : %llu", clockid, *host_timestamp);
	cn_dev_monitor_debug(monitor_set,
			"clk [%d] device_timestamp     : %llu", clockid, *device_timestamp);
	cn_dev_monitor_debug(monitor_set,
			"clk [%d] max error :          : %lld", clockid, *max_err_ns);

err_handle:
	mutex_unlock(&perf_set->ts_offset_mutex);
	return ret;
}

int cn_monitor_ts_offset_get(struct cn_monitor_set *monitor_set,
							struct monitor_ts_offset *ts_offset)
{
	return __time_sync_algorithm(monitor_set, &ts_offset->host_timestamp_ns,
			&ts_offset->device_timestamp_ns, &ts_offset->max_err_ns,
			CLOCK_MONOTONIC_RAW);
}

static inline enum slave_tkb_id __clk_id_to_tkb_id(s32 clk_id)
{
	if (clk_id == CLOCK_MONOTONIC)
		return SLAVE_TKB_MONO;
	else if (clk_id == CLOCK_MONOTONIC_RAW)
		return SLAVE_TKB_RAW;

	return SLAVE_TKB_NUM;
}

int __send_ts_offset_to_device(struct monitor_perf_set *perf_set, int clk_id)
{
	struct cn_monitor_set *monitor_set = perf_set->monitor_set;
	int ret;
	int result = 0;
	int in_len, out_len;
	enum slave_tkb_id tkb_id = __clk_id_to_tkb_id(clk_id);
	struct ts_sync_data *sync_data = &perf_set->ts_sync_data[tkb_id];

	if (unlikely(tkb_id >= SLAVE_TKB_NUM))
		return -EINVAL;

	if (!perf_set->time_ep)
		return -EINVAL;

	/* call rpc to send time offset result to device */
	out_len = sizeof(struct tk_base);
	ret = __pmu_call_rpc_timeout(perf_set->core, perf_set->time_ep,
				"perf_rpc_get_host_time",
				&sync_data->dev_tk_base, out_len,
				&result, &in_len, sizeof(result),
				4 * HZ);
	cn_dev_monitor_debug(monitor_set, "send host time, ret:%d  in_len:%d",
									ret, in_len);
	if (ret < 0) {
		cn_dev_monitor_err(monitor_set, "call rpc func error");
		return -EFAULT;
	}

	if (result) {
		cn_dev_monitor_err(monitor_set, "send time offset to device error");
		return -EFAULT;
	}

	/* used for debug */
	memcpy(&sync_data->tk_base_bak[sync_data->last % TK_BASE_BAK_NUM],
			&sync_data->dev_tk_base, sizeof(struct tk_base));

	return 0;
}

/* calculate the slope of linear fiting */
static int __slope_calculate(struct monitor_perf_set *perf_set,
		struct ts_offset_sample_data *prev_data,
		struct ts_offset_sample_data *last_data,
		int64_t *result)
{
	s64 dev_elapsed_ns, host_elapsed_ns;
	s32 elapsed_ms;

	if (unlikely(!prev_data->host_timestamp_ns)) {
		/* set the slope to 0 if only a group data */
		*result = 0;
		return 0;
	}

	/* x2 - x1 */
	dev_elapsed_ns = last_data->device_timestamp_ns
				- prev_data->device_timestamp_ns;
	/* y2 - y1 */
	host_elapsed_ns = last_data->host_timestamp_ns
				- prev_data->host_timestamp_ns;
	/*  (x2 - x1) >> 20 */
	elapsed_ms = dev_elapsed_ns >> 20;

	if (elapsed_ms == 0) {
		cn_dev_monitor_err(perf_set->monitor_set, "elapse_ms is 0!");
		return -EINVAL;
	}
	/* NOTICE:
	 * use shift to avoid floating-point calculation in kernel space,
	 * @result means nanoseconds of host faster/slower than device per second.
	 *
	 * current calculate mode without overflows:
	 *  ((y2 - y1) - (x2 - x1)) << 10
	 * --------------------------------
	 *	      (x2 - x1) >> 20
	 *
	 * same as:
	 *  ((y2 - y1) - (x2 - x1)) << 30
	 * --------------------------------
	 *           x2 - x1
	 */
	*result = div_s64((host_elapsed_ns - dev_elapsed_ns) << 10, elapsed_ms);

	return 0;
}

/*
 * host time calculate method:
 * Y = k * X + b
 *
 * k calculate method:
 *      y2 - y1
 * k = ---------
 *      x2 - x1
 *
 * b calculate method:
 *           y2 - y1
 * b = y2 - --------- * x2
 *           x2 - x1
 *
 * calculate method transfer:
 *		y2 - y1              y2 - y1
 * Y = --------- * X + y2 - --------- * x2
 *      x2 - x1              x2 - x1
 *
 * k is close to 1, like 1.00000001, transfer the method to remove float:
 *
 *		                        ((y2 - y1) - (x2 - x1)) << 30
 * Y = X +  ((X - x2) >> 30) * ------------------------------- + (y2 - x2)
 *                                       x2 - x1
 *
 * EXPLANATION:
 *  Y : host time transfer by slave time
 *  X : slave time
 *  x2: last_data.device_timestamp_ns
 *  x1: prev_data.device_timestamp_ns
 *  y2: last_data.host_timestamp_ns
 *  y1: prev_data.host_timestamp_ns
 * */
static int __linear_fit_param_cal(struct monitor_perf_set *perf_set,
		struct ts_offset_sample_data *prev_data,
		struct ts_offset_sample_data *last_data,
		struct tk_base *tk_base)
{
	struct cn_monitor_set *monitor_set = perf_set->monitor_set;
	int64_t slope = 0;
	int ret = 0;

	/* x2 */
	tk_base->last_tsg_ns = cpu_to_le64(last_data->device_timestamp_ns);
	/* y2 - x2 */
	tk_base->offset_ns = cpu_to_le64((int64_t)last_data->host_timestamp_ns
							 - (int64_t)last_data->device_timestamp_ns);

	if (__slope_calculate(perf_set, prev_data, last_data, &slope)) {
		cn_dev_monitor_err(monitor_set, "calculate slope error!");
		ret = -EINVAL;
	}
	tk_base->offset_ns_err_per_second = cpu_to_le64(slope);

	return ret;
}

static inline
bool easy_time_sync(struct cn_core_set *core)
{
	if (core->device_id == MLUID_PIGEON_EDGE)
		return true;
	else
		return false;
}

/* according to func __convert_tsg_to_host_time() in monitor_arm */
u64 __convert_dev_to_host_time(struct monitor_perf_set *perf_set,
		u64 arm_timestamp_ns, struct tk_base *tk_base)
{
	struct cn_core_set *core = perf_set->core;
	int64_t offset_ns_err;
	u64 host_timestamp_ns;
	s64 delta_time;
	s64 arm_elapse_time;

	/* slope */
	offset_ns_err = le64_to_cpu(tk_base->offset_ns_err_per_second);
	/* X - x2 */
	arm_elapse_time = (s64)arm_timestamp_ns - (s64)le64_to_cpu(tk_base->last_tsg_ns);
	/* delta_time: the error between host and arm time from latest time calibration
	 *
	 *                    ((y2 - y1) - (x2 - x1)) << 30
	 * offset_ns_err is: --------------------------------
	 *                           x2 - x1
	 *
	 * current calculate mode without overflows:
	 *                       ((y2 - y1) - (x2 - x1)) << 30
	 *  (((X - x2) >> 10) * --------------------------------) >> 20
	 *                              x2 - x1
	 *
	 * same as:
	 *                      ((y2 - y1) - (x2 - x1)) << 30
	 *  ((X - x2) >> 30) * -------------------------------
	 *                           x2 - x1
	 * */
	delta_time = (s64)(offset_ns_err * (arm_elapse_time >> 10)) >> 20;
	if (easy_time_sync(core)) {
		host_timestamp_ns = (u64)((s64)arm_timestamp_ns	+
				(s64)le64_to_cpu(tk_base->offset_ns));
	} else {
		host_timestamp_ns = (u64)((s64)arm_timestamp_ns + delta_time
				+ (s64)le64_to_cpu(tk_base->offset_ns));
	}

	return host_timestamp_ns;
}

static inline struct ts_offset_sample_data *
__get_last_sample_data(struct ts_sync_data *sync_data)
{
	return &sync_data->data[sync_data->last % MAX_SAMPLE_NUM];
}

static inline struct ts_offset_sample_data *
__get_prev_sample_data(struct ts_sync_data *sync_data)
{
	return &sync_data->data[sync_data->prev % MAX_SAMPLE_NUM];
}

static int
linear_fit_param_cal(struct monitor_perf_set *perf_set, int clk_id)
{
	int ret;
	u64 __last_dev;
	enum slave_tkb_id tkb_id = __clk_id_to_tkb_id(clk_id);
	struct ts_sync_data *sync_data;
	struct cn_monitor_set *monitor_set = perf_set->monitor_set;
	struct ts_offset_sample_data old_last_data;
	struct ts_offset_sample_data new_futr_data;
	struct tk_base new_tk_base;


	if (unlikely(tkb_id >= SLAVE_TKB_NUM))
		return -EINVAL;

	sync_data = &perf_set->ts_sync_data[tkb_id];
	/* 1. calculate slope and y-intercept of linear fit */
	ret = __linear_fit_param_cal(perf_set, __get_prev_sample_data(sync_data),
			__get_last_sample_data(sync_data), &new_tk_base);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "calculate linear fit params failed!");
		return -EINVAL;
	}
	/* if syts_data->prev == 0, still in lateinit, not correct */
	if (unlikely(sync_data->prev == 0))
		goto update_result;

	/* 2. correct the params to avoid time backward
	 *
	 * host time
	 *	  ^
	 *    |    o   n
	 *    |   o  n
	 *    |  o n
	 *    | ou
	 *    |o
	 *    |12345678---> slave time
	 *
	 *	o = old slope
	 *  u = update
	 *  n = new slope
	 *
	 * the slope and offset get in step 1 maybe make slave time backward:
	 * reader 4 will observe time going backwards versus reader 3;
	 *
	 *  host time
	 *     ^
	 *     |    o   n
	 *     |   o n
	 *     |  u
	 *     | on
	 *     |o
	 *     |12345678---> slave time
	 *
	 *   o = old slope
	 *   u = update
	 *   n = new slope
	 * use last host time to update avoid time backward:
	 * use 'u' instead of 'n' when update slope to avoid backward;
	 * */
	__last_dev = __get_last_sample_data(sync_data)->device_timestamp_ns;
	old_last_data.device_timestamp_ns = __last_dev;
	old_last_data.host_timestamp_ns   = __convert_dev_to_host_time(
			perf_set, old_last_data.device_timestamp_ns, &sync_data->dev_tk_base);

	new_futr_data.device_timestamp_ns = __last_dev + perf_set->delay_us * 1000;
	new_futr_data.host_timestamp_ns   = __convert_dev_to_host_time(
			perf_set, new_futr_data.device_timestamp_ns, &new_tk_base);

	ret = __linear_fit_param_cal(perf_set, &old_last_data, &new_futr_data,
			&new_tk_base);
	if (ret) {
		cn_dev_monitor_err(monitor_set,
				"correct step calculate linear fit params failed!");
		return -EINVAL;
	}

update_result:
	/* 3. update ts result */
	new_tk_base.clk_id = cpu_to_le32(clk_id);
	memcpy(&sync_data->dev_tk_base, &new_tk_base, sizeof(new_tk_base));

	return 0;
}

static int
__update_ts_sync_data(struct cn_monitor_set *monitor_set, int clk_id)
{
	int ret;
	u64 __max_err_ns;
	struct ts_offset_sample_data new;
	struct ts_sync_data *sync_data;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;
	enum slave_tkb_id tkb_id = __clk_id_to_tkb_id(clk_id);

	if (unlikely(tkb_id >= SLAVE_TKB_NUM))
		return -EINVAL;

	ret = __time_sync_algorithm(monitor_set, &new.host_timestamp_ns,
			&new.device_timestamp_ns, &__max_err_ns, clk_id);
	if (ret && (ret != -EAGAIN)) {
		cn_dev_monitor_debug(monitor_set, "get ts offset error!");
		return -EINVAL;
	}

	sync_data = &perf_set->ts_sync_data[tkb_id];

	(++sync_data->last < MAX_SAMPLE_NUM) ?
		(sync_data->prev = 0) : (++sync_data->prev);

	memcpy(__get_last_sample_data(sync_data), &new, sizeof(new));

	/* used for debug */
	sync_data->max_err_ns[sync_data->last % TK_BASE_BAK_NUM] = __max_err_ns;

	return 0;
}

static int
__time_sync_and_calculate(struct cn_core_set *core, int clk_id)
{
	int ret = 0;
	struct cn_monitor_set *monitor_set =
		(struct cn_monitor_set *)core->monitor_set;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	/* 1. call time sync to get new sample data */
	ret = __update_ts_sync_data(monitor_set, clk_id);
	if (ret) {
		cn_dev_monitor_debug(monitor_set, "clk_id[%d] update ts data failed!", clk_id);
		return -EINVAL;
	}

	/* 2. calculate new tk_base */
	ret = linear_fit_param_cal(perf_set, clk_id);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "clk_id[%d] update ts offset failed!", clk_id);
		return -EINVAL;
	}

	/* 3. send time offset result to device */
	ret = __send_ts_offset_to_device(perf_set, clk_id);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "send time offset result to device error!");
		return -EAGAIN;
	}

	return 0;
}

void __host_device_clock_sync_wq(struct work_struct *work)
{
	struct monitor_perf_set *perf_set =
				container_of(work, struct monitor_perf_set, time_sync_work.work);
	struct cn_monitor_set *monitor_set = perf_set->monitor_set;
	struct cn_core_set *core = perf_set->core;
	u64 delay_us;

	if (core->reset_flag != 0) {
		cn_dev_monitor_info(monitor_set,
				"driver will reset, exit time sync work!");
		return;
	}

	__time_sync_and_calculate(core, CLOCK_MONOTONIC_RAW);
	__time_sync_and_calculate(core, CLOCK_MONOTONIC);

	/* calculate the delay time for next time sync */
	if (perf_set->delay_us < TIME_SYNC_INTERVAL_US) {
		perf_set->delay_us *= 2;
		delay_us = (perf_set->delay_us < TIME_SYNC_INTERVAL_US) ?
				perf_set->delay_us : TIME_SYNC_INTERVAL_US;
	} else {
		delay_us = TIME_SYNC_INTERVAL_US;
	}

	schedule_delayed_work(&perf_set->time_sync_work,
			usecs_to_jiffies(delay_us));
}

static void __host_device_clock_sync_wq_set(struct monitor_perf_set *perf_set)
{

	INIT_DELAYED_WORK(&perf_set->time_sync_work, __host_device_clock_sync_wq);
	schedule_delayed_work(&perf_set->time_sync_work,
			usecs_to_jiffies(200000));
	perf_set->delay_us = 400000; /* 0.4s */
	perf_set->time_sync_work_active = true;
}

static void __host_device_clock_sync_wq_unset(struct monitor_perf_set *perf_set)
{
	if (perf_set->time_sync_work_active) {
		cancel_delayed_work_sync(&perf_set->time_sync_work);
		perf_set->time_sync_work_active = false;
	}
}

static int __perf_rpc_register(struct monitor_perf_set *perf_set)
{
	struct cn_monitor_set *monitor_set = perf_set->monitor_set;
	struct cn_core_set *core = perf_set->core;

	perf_set->perf_ep = __pmu_open_channel("perf-krpc", core);
	if (IS_ERR_OR_NULL(perf_set->perf_ep)) {
		cn_dev_monitor_err(monitor_set, "open perf-krpc channel failed");
		return -EFAULT;
	}

	perf_set->time_ep = __pmu_open_channel("time-krpc", core);
	if (IS_ERR_OR_NULL(perf_set->time_ep)) {
		cn_dev_monitor_err(monitor_set, "open time-krpc channel failed");
		__pmu_disconnect(perf_set->perf_ep, perf_set->core);
		return -EFAULT;
	}

	return 0;
}

static void __perf_rpc_unregister(struct monitor_perf_set *perf_set)
{
	if (perf_set->perf_ep) {
		__pmu_disconnect(perf_set->perf_ep, perf_set->core);
		perf_set->perf_ep = NULL;
	}

	if (perf_set->time_ep) {
		__pmu_disconnect(perf_set->time_ep, perf_set->core);
		perf_set->time_ep = NULL;
	}
}

static int
__perf_process_util_init(struct monitor_perf_set *perf_set)
{
	host_addr_t host_va;
	dev_addr_t dev_iova;
	int ret;

	ret = cn_perf_shm_alloc(perf_set, &host_va, &dev_iova,
				sizeof(struct perf_shm_data));
	if (unlikely(ret)) {
		return -ENOMEM;
	}

	perf_set->util.dev_iova = dev_iova;
	perf_set->util.host_va = host_va;
	perf_set->util.shm = (struct perf_shm_data *)host_va;

	return 0;
}

static void
__perf_process_util_exit(struct monitor_perf_set *perf_set)
{
	if (perf_set->util.host_va)
		cn_perf_shm_free(perf_set, perf_set->util.host_va, perf_set->util.dev_iova);
}

static int monitor_perf_lateinit(struct cn_monitor_set *monitor_set)
{
	struct monitor_perf_set *perf_set = monitor_set->perf_set;
	int ret;

	ret = __perf_rpc_register(perf_set);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "perf rpc register failed");
		return ret;
	}

	/* alloc time_sync_algorithm shared memory */
	ret = __time_sync_shm_alloc(perf_set);
	if (ret) {
		cn_dev_monitor_err(monitor_set,
			"alloc time sync algorithm share mem failed");
		goto free_rpc;
	}

	ret = __perf_process_util_init(perf_set);
	if (ret) {
		cn_dev_monitor_err(monitor_set,
			"alloc process util share mem failed");
		goto free_tsync_shm;
	}

	return 0;

free_tsync_shm:
	__time_sync_shm_free(perf_set);
free_rpc:
	__perf_rpc_unregister(perf_set);
	return ret;
}

int cn_monitor_ts_offset_calculate_in_late_init(struct cn_core_set *core)
{
	struct cn_monitor_set *monitor_set =
		(struct cn_monitor_set *)core->monitor_set;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;
	int ret;

	if (core->board_info.platform != MLU_PLAT_ASIC)
		return 0;

	ret = monitor_perf_lateinit(monitor_set);
	if (ret) {
		cn_dev_monitor_err(monitor_set, "perf module lateinit fail!");
		return ret;
	}

	__time_sync_and_calculate(core, CLOCK_MONOTONIC_RAW);
	__time_sync_and_calculate(core, CLOCK_MONOTONIC);
	if (!easy_time_sync(core)) {
		msleep(200);
		__time_sync_and_calculate(core, CLOCK_MONOTONIC_RAW);
		__time_sync_and_calculate(core, CLOCK_MONOTONIC);
	}
	__host_device_clock_sync_wq_set(perf_set);
	return 0;
}

void cn_monitor_ts_offset_calculate_in_late_exit(struct cn_core_set *core)
{
	struct cn_monitor_set *monitor_set = core->monitor_set;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	if (core->board_info.platform != MLU_PLAT_ASIC)
		return;

	__host_device_clock_sync_wq_unset(perf_set);
	__perf_process_util_exit(perf_set);
	__perf_rpc_unregister(perf_set);
	__time_sync_shm_free(perf_set);
}

int monitor_perf_init(struct cn_monitor_set *monitor_set)
{
	struct monitor_perf_set *perf_set = NULL;

	perf_set = cn_kzalloc(sizeof(struct monitor_perf_set), GFP_KERNEL);
	if (!perf_set) {
		cn_dev_err("alloc perf set error.");
		return -ENOMEM;
	}
	perf_set->monitor_set = monitor_set;
	perf_set->core = monitor_set->core;

	atomic64_set(&perf_set->seq_id, 0);
	init_rwsem(&perf_set->rwsem);
	INIT_LIST_HEAD(&perf_set->head);

	spin_lock_init(&perf_set->ts_offset_lock);
	mutex_init(&perf_set->ts_offset_mutex);

	monitor_set->perf_set = perf_set;
	return 0;
}

void monitor_perf_free(struct cn_monitor_set *monitor_set)
{
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	mutex_destroy(&perf_set->ts_offset_mutex);
	cn_kfree(perf_set);
}

/* define restart and stop func for heartbeat reset
 * restart: nothing should to do
 *          (because set workqueue and init rpc endpoint will be done in late init);
 * stop   : unset workqueue and disconnect rpc endpoint;
 */
int monitor_perf_restart(struct cn_monitor_set *monitor_set)
{
	return 0;
}

void monitor_perf_stop(struct cn_monitor_set *monitor_set)
{
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	__host_device_clock_sync_wq_unset(perf_set);
	__perf_process_util_exit(perf_set);
	__perf_rpc_unregister(perf_set);
	__time_sync_shm_free(perf_set);

	memset(perf_set->ts_sync_data, 0, sizeof(struct ts_sync_data) * SLAVE_TKB_NUM);
	atomic64_set(&perf_set->seq_id, 0);
}

void cn_perf_time_sync_show(struct seq_file *m, struct cn_core_set *core)
{
	int i;
	int tkb_id;
	struct ts_sync_data *sync_data;
	struct cn_monitor_set *monitor_set =
		(struct cn_monitor_set *)core->monitor_set;
	struct monitor_perf_set *perf_set = monitor_set->perf_set;

	for (tkb_id = 0; tkb_id < SLAVE_TKB_NUM; tkb_id++) {
		sync_data = &perf_set->ts_sync_data[tkb_id];
		seq_printf(m, "\ntkb id %d info start >>>>>>>>>\n", tkb_id);
		seq_printf(m, "last %lld\n", sync_data->last);
		seq_printf(m, "prev %lld\n", sync_data->prev);

		for (i = 0; i < MAX_SAMPLE_NUM; i++) {
			seq_printf(m, "sample data[%d] host ns %lld, device ns %lld\n", i,
					sync_data->data[i].host_timestamp_ns,
					sync_data->data[i].device_timestamp_ns);
		}

		for (i = 0; i < TK_BASE_BAK_NUM; i++) {
			seq_printf(m, "tk_bak [%d] clk_id %d, last_tsg_ns %lld, "
					"offset_ns %lld, offset_ns_err_per_second %lld, "
					"time sync max_err_ns %lld,\n",
					i,
					sync_data->tk_base_bak[i].clk_id,
					sync_data->tk_base_bak[i].last_tsg_ns,
					sync_data->tk_base_bak[i].offset_ns,
					sync_data->tk_base_bak[i].offset_ns_err_per_second,
					sync_data->max_err_ns[i]);

		}
		seq_printf(m, "tkb id %d info finish <<<<<<<<\n\n", tkb_id);
	}
}
