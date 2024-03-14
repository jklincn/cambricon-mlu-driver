/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/

#ifndef __CAMBRICON_CNDRV_UDVM_H__
#define __CAMBRICON_CNDRV_UDVM_H__

int cn_udvm_open_entry(struct inode *inode, void **priv_data, u64 tag);
void cn_udvm_release_entry(struct inode *inode, void *priv_data);
int cn_udvm_init(void **pudvm);
void cn_udvm_exit(void *pudvm);
long cn_udvm_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);

/* other module need api */
int udvm_get_cardid_from_addr(dev_addr_t udvm_address);
dev_addr_t udvm_get_iova_from_addr(dev_addr_t udvm_address);
dev_addr_t udvm_get_head_from_addr(dev_addr_t udvm_address);
bool addr_is_udvm(dev_addr_t address);
#endif /*__CAMBRICON_CNDRV_UDVM_H__*/
