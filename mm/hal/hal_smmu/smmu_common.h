/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_CNDRV_SMMU_COMMON_H__
#define __CAMBRICON_CNDRV_SMMU_COMMON_H__

/*for pcie smmu config*/
#define VA_SIZE				(48)
#define PA_SIZE				(40)
#define GRANULE_SIZE		(1)


void smmu_dev_exit(void *pcore);
void smmu_dev_init(void *pcore);
void smmu_dev_reinit(void *pcore);

#ifndef CONFIG_CNDRV_EDGE
void pigeon_smmu_ops_register(void *);
void ce3226_smmu_ops_register(void *);
void mlu220_smmu_ops_register(void *);
void mlu270_smmu_ops_register(void *);
void mlu290_smmu_ops_register(void *);
void mlu370_smmu_ops_register(void *);
void mlu590_smmu_ops_register(void *);
#else
static inline void pigeon_smmu_ops_register(void *fops) {}
static inline void ce3226_smmu_ops_register(void *fops) {}
static inline void mlu220_smmu_ops_register(void *fops) {}
static inline void mlu270_smmu_ops_register(void *fops) {}
static inline void mlu290_smmu_ops_register(void *fops) {}
static inline void mlu370_smmu_ops_register(void *fops) {}
static inline void mlu590_smmu_ops_register(void *fops) {}
#endif

#endif /*__CAMBRICON_CNDRV_SMMU_H__*/
