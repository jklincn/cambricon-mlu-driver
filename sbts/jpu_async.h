#include <linux/types.h>

struct jpu_manager {
	struct cn_core_set *core;
	struct sbts_set *sbts;
	struct task_struct *worker;
};

struct eh_jpu_msg {
	__le64 queue_dsid;
	__le64 cb_func;
	__le64 strmbuf_hdl;
	__le32 block_id;
};

struct efd_jpu_msg {
	u64 version;
	u64 cb_func;
	u64 strmbuf_hdl;
	u32 block_id;
};

enum jpu_sta {
	JPU_COMM_INIT = 1,
	JPU_COMM_ERROR,
	JPU_COMM_FINISH,
	JPU_COMM_END,
};

int sbts_jpu_manager_init(
		struct jpu_manager **ppjpu_mgr, struct cn_core_set *core);
void sbts_jpu_manager_exit(struct jpu_manager *jpu_manager);