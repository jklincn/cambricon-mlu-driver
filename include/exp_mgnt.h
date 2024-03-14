#ifndef __CN_EXP_MGNT_H__
#define __CN_EXP_MGNT_H__

#include <uapi/linux/time.h>

#define MAX_MODULES_NUM	(32)
#define EXCP_NUM_PER_MOD (6)

#define DEF_RPC_SERVICE(fn)	\
	{#fn, NULL}

#define DEF_RPC_SERVICE_END	\
	{NULL, NULL}

/*=============================*/
/* exception reset module test */
struct DistributeMap {
	unsigned int  ModuleNum;
	unsigned int  ModuleMap[MAX_MODULES_NUM];
	unsigned long ErrBitMap;
} __attribute__((packed));

struct ErrState {
	unsigned int ModuleID;
	unsigned int TimeoutFlag;
	unsigned int ExcpCnt;
	unsigned long ExcpState[EXCP_NUM_PER_MOD];
} __attribute__((packed));

#ifdef CONFIG_CNDRV_MNT

extern long cn_expmnt_ioctl(
		struct cn_core_set *core,
		unsigned int cmd,
		unsigned long arg);

extern int cn_mnt_rpc_late_init(struct cn_core_set *core);
extern void cn_mnt_rpc_late_exit(struct cn_core_set *core);

extern int cn_mnt_init(struct cn_core_set *core);
extern void cn_mnt_exit(struct cn_core_set *core);

extern int cn_device_status_query(struct cn_core_set *core, unsigned long *bitmap);

extern int cn_device_get_acpu_log(void *pcore);

void show_one_info(void* result, int len);
void show_all_info(struct cn_core_set *core);

int cn_report_late_init(struct cn_core_set *core);
void cn_report_late_exit(struct cn_core_set *core);
int cn_report_run(struct cn_core_set *core, unsigned long val, unsigned int host_only);
void cn_report_call(struct cn_core_set *core, unsigned long val);
int cn_report_query(struct cn_core_set *core, int *state);
int cn_report_armflush(struct cn_core_set *core, int state);
void cn_report_set_report_on(struct cn_core_set *core, int value);
int cn_report_get_report_on(struct cn_core_set *core);
int cn_report_set_report_mode(struct cn_core_set *core, int value);
int cn_report_get_report_mode(struct cn_core_set *core);
int cn_report_set_report_path(struct cn_core_set *core, char *path);
char *cn_report_get_report_path(struct cn_core_set *core);
int cn_kdump_init(struct cn_core_set *core);
void cn_kdump_exit(struct cn_core_set *core);
int cn_kdump_read(struct cn_core_set *core, char *buf, size_t len, loff_t *fops);
#else
static inline long cn_expmnt_ioctl(
		struct cn_core_set *core,
		unsigned int cmd,
		unsigned long arg){return 0;}

static inline int cn_mnt_rpc_late_init(struct cn_core_set *core){return 0;}
static inline void cn_mnt_rpc_late_exit(struct cn_core_set *core){return;}
static inline int cn_report_late_init(struct cn_core_set *core){return 0;}
static inline void cn_report_late_exit(struct cn_core_set *core){return;}

static inline int cn_mnt_init(struct cn_core_set *core){return 0;}
static inline void cn_mnt_exit(struct cn_core_set *core){}

static inline int cn_device_status_query(void *pcore, unsigned long *bitmap)
{
	return -1;
}

static inline int cn_device_get_acpu_log(void *pcore) { return 0; }

static inline int cn_report_run(struct cn_core_set *core, unsigned long val, unsigned int host_only){ return 0; }
static inline void cn_report_call(struct cn_core_set *core, unsigned long val){}
static inline int cn_report_query(struct cn_core_set *core, int *state){ return 0; }
static inline int cn_report_armflush(struct cn_core_set *core, int state){ return 0; }
static void cn_report_set_report_on(struct cn_core_set *core, int value){}
static int cn_report_get_report_on(struct cn_core_set *core){ return 0; }
static int cn_report_get_report_mode(struct cn_core_set *core){ return 0; }
static void show_all_info(struct cn_core_set *core){}
#endif

#endif // __CN_EXP_MGNT_H__
