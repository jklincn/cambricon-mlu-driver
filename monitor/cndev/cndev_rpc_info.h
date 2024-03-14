#ifndef __CAMBRICON_CNDEV_RPC_INFO_H__
#define __CAMBRICON_CNDEV_RPC_INFO_H__

#include "cndrv_core.h"

enum cndev_rpc_cmd {
	CNDEV_RPC_CMD_GET_ERR_CNT = 0,
	CNDEV_RPC_CMD_GET_ECC = 1,
	CNDEV_RPC_CMD_MAX,
};

struct cndev_rpc_head {
	u32 version;
	u32 size;
	u32 cmd;
	s32 res;
};

struct cndev_cntr_rpc_info {
	struct cndev_rpc_head head;

	u64 parity_err_cntr;
};

struct cndev_ecc_cmd {
	struct cndev_rpc_head head;

	u32 host_vf_id;
	u32 module;
	u32 type;
};

struct cndev_ecc_data {
	struct cndev_rpc_head head;

	u32 ecc_num;
	u64 ecc_info[32];
};

#endif