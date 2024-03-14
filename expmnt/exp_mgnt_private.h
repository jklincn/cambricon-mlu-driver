#ifndef __EXP_MGNT_PRIVATE_H__
#define __EXP_MGNT_PRIVATE_H__

#include "cndrv_mm.h"
#include "exp_mgnt.h"

#define DEL_PSTORE_FILE_IN_ACPU  (0x41)
#define FETCH_PSTORE_FILE        (0x31)
#define LS_PSTORE_NAME_SIZE	     (0x21)
#define D2H_BUF_SIZE                (64 * 1024)
#define GET_ALL_INFO             (0x11)
#define MAX_FILE_CNT                (8)
#define PSTORE_FILE_NAME_MAX_LEN    (100)
#define REPORT_MAX_FILE_CNT			(32)
#define REPORT_FILE_NAME_MAX_LEN    (20)

typedef u64 dev_addr_t;

struct file_info {
	char file_name[PSTORE_FILE_NAME_MAX_LEN];
	int file_size;
};

struct rpc_report_param {
	long cmd;
	char file_path[64];
	unsigned long outbound_iova;
	unsigned long outbound_size;
};

struct mlu_addr_info {
	dev_addr_t mlu_addr;
	size_t size;
};

struct rpc_arm_param {
	int cmd;
	struct mlu_addr_info mlu_addr_info;
	struct file_info file_info;
};

struct rpc_arm_resp {
	int ret;
	char file_path[64];
	int file_cnt;
	struct file_info files[0];
};

struct report_file_info {
	char file_name[REPORT_FILE_NAME_MAX_LEN];
	int file_size;
};

struct rpc_arm_report_resp {
	int ret;
	char file_path[64];
	int file_cnt;
	struct report_file_info files[0];
};

struct cndump_reg_map {
	const char * model;
	unsigned long addr_start;
	unsigned long addr_end;
	unsigned int index;
	int (*call_check)(struct cn_core_set *core, unsigned int index);
};

struct cn_report_block;
struct cn_report_head {
	struct rw_semaphore rwsem;
	struct cn_report_block __rcu *head;
};

struct cn_mnt_set {
	void *endpoint;
	void *core;
	void *heartbeat_pkg;
	struct cn_report_head report_chain;
	struct cn_report_block *nb_timestamp;
	struct cn_report_block *nb_dumpreg;
	struct cn_report_block *nb_dumpoutbound;
	struct cndump_reg_map *reg_map;
	host_addr_t outbound_host;
	dev_addr_t outbound_device;
	int reg_map_len;
	int report_on;    /*1:proc trigger; 2:api trigger*/
	int report_mode;  /*0:disable, 1:enable, 2:auto*/
	char *report_path;
	unsigned long kdumphdr_addr;
	size_t kdumphdr_size;
	char *elfcorebuf;
	size_t elfcorebuf_sz;
	size_t elfcorebuf_sz_orig;
	char *elfnotes_buf;
	size_t elfnotes_sz;
	u64 vmcore_size;
	struct list_head vmcore_list;
};

/* @brief : this structure data entry is descriptor for every module
 * @status: module owner customed exception attribute
 * @ts_cur: every exception data update to kernel generate it, (nanoseconds)
 */
struct data_entry_s {
	unsigned long status;
	ktime_t ts_cur;
} __attribute__((packed));

/* @brief           : this structure descriptor for every module data
 * @EXCP_NUM_PER_MOD: exception data fifo depth
 * @node            : list all module for management
 * @module_id       : module id
 * @lasted_ts       : updated ts when every data arrive it, and
 *                    can not modified after host get module data
 * @norm_cnt        :
 * @excp_cnt        :
 * @norm_heart_beat :
 * @excp_data       :
 */
struct module_data_s {
	unsigned int module_id;
	unsigned int norm_cnt;
	unsigned int excp_cnt;
	ktime_t lasted_ts;
	struct data_entry_s norm_heart_beat;
	struct data_entry_s excp_data[EXCP_NUM_PER_MOD];
	unsigned long timeout_threshold_ms;
	struct list_head node;
} __attribute__((packed));

/* @brief		: this data package is received from device
 * @module_num		: indicate the number of module this query
 * @ts_get_from_device	: timestamp generated when get data from device
 * @module_res		: all modules you want to get
 */
struct heartbeat_pkg_s {
	unsigned int module_num;
	ktime_t ts_get_from_device;
	struct module_data_s module_res[MAX_MODULES_NUM];
} __attribute__((packed));

typedef	int (*report_fn_t)(void *data,
			unsigned long action, void *fp);

struct cn_report_block {
	report_fn_t report_call;
	void *data;
	struct cn_report_block __rcu *next;
	int priority;
	char *name;
};

struct cn_report_block *cn_register_report(struct cn_core_set *core, char *name, int prio, report_fn_t fn, void *data);
int cn_unregister_report(struct cn_core_set *core, struct cn_report_block *nb);

#ifdef CONFIG_CNDRV_MNT
void collect_distribute_map(struct heartbeat_pkg_s *pkg, unsigned long bitmap, struct DistributeMap *res);
int get_one_msg(struct heartbeat_pkg_s *pkg, int module_id, struct ErrState *res);
extern void cn_report_init(struct cn_core_set *core);
extern void cn_report_free(struct cn_core_set *core);
extern void cn_dumpreg_init(struct cn_core_set *core);
extern void cn_dumpreg_free(struct cn_core_set *core);
#else
static inline void collect_distribute_map(struct heartbeat_pkg_s *pkg, unsigned long bitmap, struct DistributeMap *res){}
static inline int get_one_msg(struct heartbeat_pkg_s *pkg, int module_id, struct ErrState *res)
{
	return -1;
}
static inline void cn_report_init(struct cn_core_set *core){}
static inline void cn_report_free(struct cn_core_set *core){}
#endif

#endif // __EXP_MGNT_PRIVATE_H__
