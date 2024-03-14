#ifndef __GDMA_COMMON_API_H__
#define __GDMA_COMMON_API_H__

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"

#define CE_GDMA_CHAN_SEM_NUM (16)

struct ce_gdma_set {
	void *gdma_submit_endpoint;
	void *gdma_sync_endpoint;
	struct semaphore ce_gdma_sema;
};

struct cn_gdma_super_set {
	int mode;
	void *ce_gdma;
	void *host_gdma;
	struct cn_core_set *core;
};

#endif
