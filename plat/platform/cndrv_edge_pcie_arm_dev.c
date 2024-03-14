#include <linux/io.h>
#include "cndrv_bus.h"
#include "cndrv_edge.h"

int mlu_pcie_arm_dev_init(struct cn_edge_set *edge_set)
{
	edge_set->shm_cnt = 0;
	return 0;
}

void mlu_pcie_arm_dev_exit(struct cn_edge_set *edge_set)
{
}