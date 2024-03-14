/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/file.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_mig_internal.h"

#include "cndrv_ioctl.h"

long cn_mig_check_par(struct cn_core_set *core, unsigned int cmd,
	struct mig_op_t *op_base)
{
	if (op_base->type >= MIG_TYPE_CNT) {
		cn_dev_core_err(core, "ioc:[%d] type:[%d] vf:[%d] dir:[%d]",
			_IOC_NR(cmd), op_base->type, op_base->vf, op_base->dir);
		return -EINVAL;
	}

	if (op_base->type == MIG_TYPE_STS || op_base->type == MIG_TYPE_DEBUG_DMA
		|| op_base->type == MIG_TYPE_DEBUG_DMA_CFG) {
		return 0;
	}

	if ((_IOC_NR(cmd) == _MIG_OP_GET && op_base->dir != MIG_DIR_SRC) ||
		(_IOC_NR(cmd) == _MIG_OP_SET && op_base->dir != MIG_DIR_DST)) {
		cn_dev_core_err(core, "ioc:[%d] type:[%d] vf:[%d] dir:[%d]",
			_IOC_NR(cmd), op_base->type, op_base->vf, op_base->dir);
		return -EINVAL;
	}

	return 0;
}

long cn_mig_status(struct cn_core_set *core, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	struct mig_op_status_t op_sts;

	if (copy_from_user((void *)&op_sts, (void *)arg, sizeof(op_sts))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		return -EFAULT;
	}

	if (op_sts.vf < 0 || op_sts.vf >= MIG_MAX_VF) {
		cn_dev_core_err(core, "vf=%d is illegal", op_sts.vf);
		return -EFAULT;
	}

	if (_IOC_NR(cmd) == _MIG_OP_GET) {
		if (op_sts.dir == MIG_DIR_SRC) {
			ret = mig_save_query_state(core->mig_set, op_sts.vf,
				&op_sts.cmd_data[0]);
		} else {
			ret = mig_restore_query_state(core->mig_set, op_sts.vf,
				&op_sts.cmd_data[0]);
		}

		if (copy_to_user((void *)arg, (void *)&op_sts, sizeof(op_sts))) {
			cn_dev_core_err(core, "copy_to_user failed.");
			return -EFAULT;
		}

		cn_dev_core_info(core, "status:%x", op_sts.cmd_data[0]);
		return ret;
	}

	cn_dev_core_info(core, "sts:%x", op_sts.sts);

	switch (op_sts.sts) {
	case MIG_STS_PREPARE: {
		if (op_sts.dir == MIG_DIR_SRC) {
			ret = mig_save_prepare(core->mig_set, op_sts.vf);
		} else {
			ret = mig_restore_prepare(core->mig_set, op_sts.vf);
		}
		break;
	}

	case MIG_STS_START: {
		if (op_sts.dir == MIG_DIR_SRC) {
			ret = mig_save_start(core->mig_set, op_sts.vf);
		} else {
			ret = mig_restore_start(core->mig_set, op_sts.vf);
		}
		break;
	}

	case MIG_STS_FAIL: {
		if (op_sts.dir == MIG_DIR_SRC) {
			ret = mig_save_cancel(core->mig_set, op_sts.vf);
		} else {
			ret = mig_restore_cancel(core->mig_set, op_sts.vf);
		}
		break;
	}

	case MIG_STS_FINISH: {
		if (op_sts.dir == MIG_DIR_SRC) {
			ret = mig_save_complete(core->mig_set, op_sts.vf);
		} else {
			ret = mig_restore_complete(core->mig_set, op_sts.vf);
		}
		break;
	}

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

long cn_mig_ioctl(struct cn_core_set *core, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	struct mig_op_t op_base;

	if (copy_from_user((void *)&op_base, (void *)arg, sizeof(op_base))) {
		cn_dev_core_err(core, "copy_from_user failed.");
		return -EFAULT;
	}

	if (!cn_core_is_vf(core)) {
		cn_dev_core_info(core, "migrattion type:[%d] vf:[%d] dir:[%d]",
			op_base.type, op_base.vf, op_base.dir);
	}

	ret = cn_mig_check_par(core, cmd, &op_base);
	if (ret) {
		return ret;
	}

	switch (op_base.type) {
	case MIG_TYPE_STS: {
		ret = cn_mig_status(core, cmd, arg);
		break;
	}

	case MIG_TYPE_CFG: {
		struct mig_op_cfg_t op_cfg;

		if (copy_from_user((void *)&op_cfg, (void *)arg, sizeof(op_cfg))) {
			cn_dev_core_err(core, "copy_from_user failed.");
			ret = -EFAULT;
			break;
		}

		if (op_cfg.vf < 0 || op_cfg.vf >= MIG_MAX_VF) {
			cn_dev_core_err(core, "vf=%d is illegal", op_cfg.vf);
			ret = -EFAULT;
			break;
		}

		if (op_cfg.dir == MIG_DIR_SRC) {
			ret = mig_get_cfg(core->mig_set, op_cfg.vf, op_cfg.ca,
				op_cfg.len, &op_cfg.ret_len);
		} else {
			ret = mig_put_cfg(core->mig_set, op_cfg.vf, op_cfg.ca,
				op_cfg.len);
		}

		if (copy_to_user((void *)arg, (void *)&op_cfg, sizeof(op_cfg))) {
			cn_dev_core_err(core, "copy_from_user failed.");
			ret = -EFAULT;
			break;
		}
		break;
	}

	case MIG_TYPE_DATA: {
		struct mig_op_data_t op_data;

		if (copy_from_user((void *)&op_data, (void *)arg, sizeof(op_data))) {
			cn_dev_core_err(core, "copy_from_user failed.");
			ret = -EFAULT;
			break;
		}

		if (op_data.vf < 0 || op_data.vf >= MIG_MAX_VF) {
			cn_dev_core_err(core, "vf=%d is illegal", op_data.vf);
			ret = -EFAULT;
			break;
		}

		if (op_data.dir == MIG_DIR_SRC) {
			ret = mig_get_data(core->mig_set, op_data.vf, op_data.ca, op_data.len,
				&op_data.flag, &op_data.ret_len, &op_data.data_category);
		} else {
			ret = mig_put_data(core->mig_set, op_data.vf, op_data.ca,
				op_data.len, op_data.flag);
		}

		if (copy_to_user((void *)arg, (void *)&op_data, sizeof(op_data))) {
			cn_dev_core_err(core, "copy_from_user failed.");
			ret = -EFAULT;
			break;
		}
		break;
	}

	case MIG_TYPE_DEBUG_DMA_CFG:
	case MIG_TYPE_DEBUG_DMA: {
		struct mig_op_debug_dma_cfg_t op_dma;
		struct transfer_s t;
		struct dma_config_t cfg;
		size_t len;

		memset(&cfg, 0, sizeof(cfg));
		if (op_base.type == MIG_TYPE_DEBUG_DMA) {
			len = sizeof(struct mig_op_debug_dma_t);
		} else {
			len = sizeof(struct mig_op_debug_dma_cfg_t);
		}

		if (copy_from_user((void *)&op_dma, (void *)arg, len)) {
			cn_dev_core_err(core, "copy_from_user failed.");
			ret = -EFAULT;
			break;
		}

		if (op_base.type == MIG_TYPE_DEBUG_DMA) {
			op_dma.dma_mask = 0;
			op_dma.phy_mode = 0;
		}

		cfg.phy_dma_mask = op_dma.dma_mask;
		cfg.phy_mode = op_dma.phy_mode;

		if (_IOC_NR(cmd) == _MIG_OP_SET) {
			TRANSFER_INIT(t, op_dma.ca, op_dma.ia,
					op_dma.total_size, DMA_H2D);
			op_dma.residual_size = cn_bus_dma_cfg(core->bus_set, &t, &cfg);
		} else {
			TRANSFER_INIT(t, op_dma.ca, op_dma.ia,
					op_dma.total_size, DMA_D2H);
			op_dma.residual_size = cn_bus_dma_cfg(core->bus_set, &t, &cfg);
		}

		if (copy_to_user((void *)arg, (void *)&op_dma, len)) {
			cn_dev_core_err(core, "copy_from_user failed.");
			ret = -EFAULT;
			break;
		}
		break;
	}

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}
