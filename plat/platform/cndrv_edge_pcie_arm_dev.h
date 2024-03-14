#ifndef __MLU_PCIE_ARM_DEV_H__
#define __MLU_PCIE_ARM_DEV_H__

#if defined(CONFIG_CNDRV_PCIE_ARM_PLATFORM)
int mlu_pcie_arm_dev_init(struct cn_edge_set *edge_set);
void mlu_pcie_arm_dev_exit(struct cn_edge_set *edge_set);
#else
static inline int mlu_pcie_arm_dev_init(struct cn_edge_set *edge_set)
{
	return 0;
}
static inline void mlu_pcie_arm_dev_exit(struct cn_edge_set *edge_set)
{
}
#endif

#endif /* __MLU_PCIE_ARM_DEV_H__ */
