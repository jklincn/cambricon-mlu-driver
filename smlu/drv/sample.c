#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/hrtimer.h>

#include "util.h"
#include "smlu/smlu_internal.h" /* ex_util_data */

static struct hrtimer sample_timer;
static ktime_t sample_time;

static enum hrtimer_restart sample_hrtimer_work(struct hrtimer *timer)
{
	int card_id, instance_id;
	enum util_type type;

	for (card_id = 0; card_id < MAX_PHYS_CARD; card_id++) {
		for (instance_id = 1; instance_id <= MAX_SMLU_INSTANCE_COUNT; instance_id++) {
			for (type = 0; type < UTIL_TYPE_MAX; type++) {
				/* util_target is 0 represent this instance is not used */
				if (!ex_util_data[card_id][instance_id][type].util_target)
					continue;

				smlu_util_adjust(card_id, instance_id, type,
					ex_util_data[card_id][instance_id][type].util_target,
					ex_util_data[card_id][instance_id][type].util_usage);
			}
		}
	}

	hrtimer_forward_now(&sample_timer, sample_time);
	return HRTIMER_RESTART;
}

#define SAMPLE_TIME (1000 * 1000)
int util_sample_init(void)
{
	sample_time = ktime_set(0, SAMPLE_TIME); /*ns*/

	hrtimer_init(&sample_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	sample_timer.function = sample_hrtimer_work;
	hrtimer_start(&sample_timer, sample_time, HRTIMER_MODE_REL);

	return 0;
}

void util_sample_exit(void)
{
	hrtimer_cancel(&sample_timer);
}
