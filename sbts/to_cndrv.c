#include <linux/kthread.h>
#include "cndrv_core.h"
#include "cndrv_sbts.h"
#include "cndrv_mm.h"
#include "cndrv_hpq.h"
#include "sbts.h"
#include "queue.h"

static struct sbts_set *sbts_st;

int wake_up_sync_thread(void)
{
	struct sync_manager *sync_manager;

	if (!sbts_st || !sbts_st->sync_manager) {
		return -EINVAL;
	}

	sync_manager = sbts_st->sync_manager;
	sbts_wake_up_sync_manager(sync_manager);

	return 0;
}

int sbts_drv_to_cndrv_init(struct sbts_set *sbts)
{
	#ifdef CONFIG_CNDRV_EDGE
		sbts_st = sbts;
	#endif

	return 0;
}

int sbts_drv_to_cndrv_exit(struct sbts_set *sbts)
{
	return 0;
}

