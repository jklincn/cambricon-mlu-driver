/*
 * include/cndrv_core.h
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __CNDRV_CORE_H__
#define __CNDRV_CORE_H__
#include <linux/version.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/kref.h>

#include "cndrv_bus.h"
#include "cndrv_monitor_usr.h"
#include "cnhost_dev_common.h"

#define MLUID_100	(0x0100cabc)
#define MLUID_290	(0x0290cabc)
#define MLUID_290V1	(0x0291cabc)
#define MLUID_270	(0x0270cabc)
#define MLUID_220	(0x0220cabc)
#define MLUID_CE3226	(0x0320cabc)
#define MLUID_CE3226_EDGE	(0x0328cabc)
#define MLUID_220_EDGE	(0x0228cabc)
#define MLUID_270V	(0x0201cabc)
#define MLUID_270V1	(0x0271cabc)
#define MLUID_370	(0x0370cabc)
#define MLUID_370V	(0x0371cabc)
#define MLUID_370_DEV	(0x0379cabc)
#define MLUID_365	(0x0365cabc)
#define MLUID_365V	(0x0366cabc)
#define MLUID_585	(0x0585cabc)
#define MLUID_585V	(0x0586cabc)
#define MLUID_580	(0x0580cabc)
#define MLUID_580V	(0x0581cabc)
#define MLUID_580_DEV	(0x0589cabc)
#define MLUID_590	(0x0590cabc)
#define MLUID_590V	(0x0591cabc)
#define MLUID_590_DEV	(0x0599cabc)
#define MLUID_PIGEON	(0x5223cabc)
#define MLUID_PIGEON_EDGE	(0x0428cabc)
#define MLUID_570	(0x0570cabc)
#define MLUID_570V	(0x0571cabc)
#define MLUID_560	(0x0560cabc)
#define MLUID_560V	(0x0561cabc)

#define MLUID_MAJOR_ID(ID) ((ID >> 24U))

#define COMPUTEMODE_DEFAULT 0x0000
#define COMPUTEMODE_EXCLUSIVE_PROCESS 0x0001
#define PROHIBITED_PROCESS 0x0002

#define LOAD_FW

/*
 * IMPORTANT NOTICE
 *
 * Macro MAX_PHYS_CARD represents the max physical card number,
 * and macro MAX_FUNCTION_NUM represents the max function number,
 * including pf and vf.
 *
 * Mixing them may cause serious error.
 */
#define MAX_PHYS_CARD		(16)
#define MAX_OB_PHYS_CARD (MAX_PHYS_CARD)
#define MAX_MI_COUNT		(8)
#define MAX_FUNCTION_NUM	(MAX_PHYS_CARD * (MAX_MI_COUNT + 1))

#define MAX_SMLU_INSTANCE_COUNT (64)

#define MIG_MAX_VF      (8)

#define MLU290_HBM
#define HBM_SOFT_REPAIR

#define BOARD_MODEL_NAME_LEN 32
#define CNDRV_UUID_SIZE      (DRIVER_PMU_UUID_SIZE)
#define STAT_TEMPERATURE_NUM 5

#define CAMBR_CFGS_MAX_LEN	0X1000

#define SOC_ID_REG_CNT       8
#define CN_PALATFORM_TYPE_MAX_NUM  64
#define FIRMWARE_VERSION_SIZE	26

#define RESET_ACPU_ONLY   0x0001
/* not use for now*/
#define RESET_ACPU_AND_GETLOG   0x0002
#define RESET_ALL   0x0003

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define CN_KREF_READ(a) atomic_read(&((a)->refcount))
#else
#define CN_KREF_READ(a) kref_read(a)
#endif

typedef void * cn_user;

extern int print_debug;

extern char *isr_type;
extern int isr_default_type;
extern int g_platform_type;
extern int isr_type_index;
extern int link_check;
extern int cambr_virtcon_en;

enum cn_pcie_isr_type {
	MSI = 0,
	MSIX,
	INTX,
};

/**************************************************************************
* Data type declarations
***************************************************************************/
enum cn_boot_state {
	CN_EARLYINITED = 0,
	CN_BRINGUP,
	CN_BOOTING,
	CN_LATEINIT,
	CN_RUNNING,
	CN_BOOTERR,
	CN_RESET,
	CN_RESET_ERR,
	CN_UNKNOWN,
};

typedef enum cn_board_model {
	MLU270_EVB = 1,
	MLU270_D4 = 2,
	MLU270_S4 = 3,
	MLU270_S4a = 4,
	MLU270_V4 = 6,
	MLU270_X5K = 8,
	MLU270_F4 = 10,
	MLU270_FD4 = 12,
	MLU270_V4K = 14,
	MLU270_VF = 15,
	MLU220_M2 = 16,
	MLU220_EDGE = 17,
	MLU220_EVB = 18,
	MLU220_M2i = 19,
	MLU290 = 20,
	MLU290_VF = 21,
	MLU270_A4K = 22,
	MLU370 = 23,
	MLU370_VF = 24,
	CE3226_EDGE = 25,
	MLU590 = 26,
	MLU590_VF = 27,
	LEOPARD_EDGE = 28,
	PIGEON = 29,
	MLU580 = 30,
	MLU580_VF = 31,
	SOC_1V_2301 = 32,
	BOARD_MODEL_NUM,
} cn_board_model_t;

struct cn_mcu_info {
	/*mcu sw major version*/
	u8 mcu_major;
	/*mcu sw minor version*/
	u8 mcu_minor;
	/*mcu sw build version*/
	u8 mcu_build;
	/*skip check flag*/
	u8 skip_check;
	/*mcu sw rc version*/
	u8 mcu_rc;
};

struct cn_die_info {
	/*0x0:not exist, 0x1:bin1, 0x2:bin2, 0x3:bin3*/
	u8 die_0;
	/*0x0:not exist, 0x1:bin1, 0x2:bin2, 0x3:bin3*/
	u8 die_1;
};

union cndev_soc_id {
	u32 soc_id_reg[SOC_ID_REG_CNT];
	u8 soc_id_data[SOC_ID_SIZE];
};

struct cn_board_info {
	/* hw platform */
	u32 platform;
	/*Mother board sn*/
	u64 BA_serial_num;
	u16 BA_mcu_fw_ver;
	/*board sn*/
	u64 serial_num;
	/*chip hardware version base on RTL*/
	u8 chip_version;
	/*main chip type version: 'C10-01 C20L-02 C20-03...'*/
	u8 chip_type;
	/*subsystem_id as board type*/
	u32 board_type;
	/*ddr paricle type (0x01:X8 0x02:X16)*/
	/*spical info*/
	u8 special_info;
	u8 ddr_type;
	/*ddr paricle capacity (0x00:512M 0x01:1G)*/
	u32 ddr_cap;
	/* hbm count */
	u32 hbm_cnt;
	/* hbm bad mask, dec*/
	u32 bad_hbm_mask;
	/* hbm mask, dec */
	u32 hbm_mask;
	/* noc mode */
	u32 noc_mode;
	/* gdma mask*/
	u32 gdma_mask;
	/* ipu system mask */
	u32 ipusys_mask;
	/*ddr freq*/
	u32 ddr_freq;
	/*ddr freq*/
	u32 ddr_speed;
	/* ipu freq */
	u32 rated_ipu_freq;
	/* total phy memory on board 16 or 32 in MB */
	u64 total_memory;

	u8 cluster_num;
	u8 ipu_core_num;
	u8 mem_channel;

	u32 bus_width;
	u32 ecc_support;
	u64 stack_size;
	u64 sram_size;
	u64 cache_size;
	u32 bandwidth;
	u8 bandwidth_decimal;
	/* excution resource */
	u32 kc_limit;
	u32 o_kc_limit;
	u32 max_dimx;
	u32 max_dimy;
	u32 max_dimz;
	u32 max_queue;
	u32 max_notifier;
	u32 queue_prio_support;

	u32 peak_power;
	u32 min_power_cap_ctrl;

	u32 min_power_cap;
	u32 min_power_cap_dec;
	u32 max_power_cap_dec;

	u16 min_ipu_freq_cap;
	u16 max_ipu_freq_cap;

	struct cn_mcu_info mcu_info;
	u8 bsp_major;
	u8 bsp_minor;

	char board_model_name[BOARD_MODEL_NAME_LEN];

	int board_idx;

	u8 qdd_status;

	u8 uuid_ready;
	u8 uuid[CNDRV_UUID_SIZE];

	u16 slot_id;

	u8 chip_id;

	u8 secure_mode;
	union cndev_soc_id soc_id;

	u32 pci_device_id;
	u32 pci_bus_num;
	u32 pci_domain_id;
	u64 pcie_fw_info;
	u16 pci_mps;
	u16 pci_mrrs;

	struct cn_die_info chip_die_info[2];

	u8 marking_id;

	u32 platform_id;
	u32 platform_num;
	struct monitor_chip_info platform_info[CN_PALATFORM_TYPE_MAX_NUM];
};

struct pid_info_s {
	int tgid;
	int active_pid;
	int pgid;
	struct pid_namespace *active_ns;
	struct pid *taskpid;
	struct file *fp;

	struct list_head pid_list;
	u64 phy_usedsize;
	u64 vir_usedsize;

	__u64 ipu_util;
	//__u32 jpu_util;
	//__u32 vpu_dec_util;
	//__u32 vpu_enc_util;
};

enum overtemp_mode {
	OVERTEMP_WARNING_AUTO = 0,
	OVERTEMP_WARNING_MANUAL
};
struct mlu_overtemp_warning {
	u64 recall_count;
	u8 value;
	enum overtemp_mode mode;
	u32 cycle;
	u32 refresh_cycle;
};

struct mlu_overtemp_value {
	u8 freq_value;
	u8 poweroff_value;
};

struct cn_core_set {
	struct cn_bus_set *bus_set;
	void *mm_set;
	void *sbts_set;
	void *shm_set;
	void *gdma_set;

	void *monitor_set;
	void *cndev_set;
	void *mcu_set;
	void *mcc_set;
	struct rw_semaphore mcc_state_sem;
	void *proc_set;
	void *commu_set;
	void *ipcm_set;
	void *vf_proc_set;
	void *domain_set;
	void *lpm_set;
	void *i2c_set;

	void *mnt_set;
	void *vuart_set;
	void *mig_set;
	void *qdev_vf_set;
	void *trans_set;
	void *attr_set;
	void *nor_set;
	void *xid_set;
	void *ncs_set;

	void *state_monitor_kthread;

	/*
	 * the vendor id and device id
	 * C10  0100cabc
	 * c20  0200cabc
	 * c20l 0201cabc
	 * c20e 0220cabc
	 */
	u64 device_id;

	/*
	 * which plat identify
	 * fpga = 0xc0
	 * zebu = 0x00
	 */
	u8 type;

	/*card model type*/
	cn_board_model_t board_model;
	struct cn_board_info board_info;

	/*firmware version update when upload_fw*/
	unsigned char firmware_version[FIRMWARE_VERSION_SIZE+1];

	int open_count;
	struct list_head pid_head;
	spinlock_t pid_info_lock;

	int card_kprintf_timer; /* kernel printf trigger time unit:ms */

	int idx;
	int pf_idx;
	int vf_idx;
	char core_name[CNDEV_CORE_NAME_LEN];
	char node_name[32];
	struct platform_device *mbox;
	struct platform_device *ipc_device;

	struct cnhost_device *device;

	spinlock_t lock;

	unsigned int exclusive_mode;
	int exclusive_pgid;

	int mem_extension;
	int delay_free_enable;/*cut from mm_set to core_set*/
	/* delay work */
	int heartbeat_wait_cnt;

	/* workqueue */
	char work_name[32];
	struct work_struct	runqueue_work;
	struct mutex		runqueue_mutex;
	volatile enum cn_boot_state last_state;
	volatile enum cn_boot_state state;
	volatile int workq_state;
	int boot_count;
	int boot_max_time;
	ulong boot_ts;
	u32 reset_flag;
	unsigned long arm_pc_init;
	unsigned long certs_addr;
	u8 heartbeat_error;
	int late_init_flag;
	int user_trace_enable;
	struct mutex user_trace_lock;

	int mig_pending;
	wait_queue_head_t mig_wq;

	int cambr_mcu_version_check;
	u32 temperature[STAT_TEMPERATURE_NUM + 1];
	int die_cnt;
	struct mlu_overtemp_warning freq_warning;

	/* soft repair work(for reset mlu)*/
	struct work_struct repair_work;
	u32 repair_active;

	struct cn_die_info chip_die_info[2];
	bool support_ipcm;

	/* inline_ecc enabled ctrl */
	int ile_en;
	u32 fw_support_lt_freq_cap;
	u32 drv_support_lt_freq_cap;
	/* cambricon driver configs */
	char cambr_configs[CAMBR_CFGS_MAX_LEN];

	struct mlu_overtemp_warning poweroff_warning;

	struct list_head kthread_list;
	struct mutex kthread_lock;
	long slice;
	struct task_struct *kthread;

	void *kwork_set;

	/* add for mi_cap feature */
	struct list_head tid_cap_list_head;
	struct mutex tid_cap_lock;

	/*
	 * This is different the in domain_set->mim_enable, when call
	 * cn_core_set_mim_mode, this is set but domain_set->mim_enable not set,
	 * after call cn_dm_is_mim_mode_enable, domain_set->mim_enable will be set.
	 */
	int mim_enable;
	/* be care, edge and vf have no smlu_set */
	void *smlu_set;
	int smlu_enable;
	struct kref refcount;
	struct completion comp;
};

struct cn_core_index {
	struct cn_core_set *cn_core;
	/* on host mlu instance core set, vf_idx:[1,MAX_MI_COUNT] */
	struct cn_core_set *cn_mi_core[MAX_MI_COUNT + 1];
	u32 cn_bdf;
	u32 cn_mim_enable;
	u32 major;
	u32 minor;
};

/**
 * list for each potential vf_core under the given pf_idx
 *
 * NOTICE: need to check if vf_core is NULL in your loop
 *
 * @pf_idx:	input param to specific which pf card we will go to list
 * @vf_core:	the vf_core to use as a loop cursor
 * @i:		tmp variable as vf_idx
 */
#define list_sub_vf_core(pf_idx, vf_core, i)			\
	for (i = 1, vf_core = NULL; i <= MAX_MI_COUNT;		\
		vf_core = cn_core_get_mi_core(pf_idx, i), i++)

/* adapt for RHEL OS */
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a,b) (((a) << 8) + (b))
#endif

/**
 * define PDE_DATA function in some kernel versions
 *
 * resolve incompatibilities issues between different kernel version
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define PDE_DATA(i) (PDE(i)->data)
#elif ((LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)) || \
	(defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,1) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)))
#define PDE_DATA(i) pde_data(i)
#endif

/* defined for cn_core_probe and cn_core_remove */
struct core_fn_s {
	int (*init)(struct cn_core_set *);
	void (*exit)(struct cn_core_set *);
	char *name;
};

enum MODULE_PROCESS_STATE {
	DEFAULT = 0,
	INIT_OK,
	EXIT_OK,
};

/* used by both core_probe and late_init stages */
struct fn_state_s {
	int status;
	int init_cost;
};

struct core_fn_s *cn_core_get_core_fn_t(void);
int cn_core_get_core_fn_num(void);
struct fn_state_s *cn_core_get_core_fn_state(int idx);

int unset_fw_workq(struct cn_core_set *core);
int cn_host_vf_enable(void);
int cn_core_is_vf(struct cn_core_set *core);
bool isEdgePlatform(struct cn_core_set *core);
bool isCEPlatform(struct cn_core_set *core);
bool isPCIeArmPlatform(struct cn_core_set *core);
bool isMlu100SeriesProduct(struct cn_core_set *core);
int cn_core_vf_unload(struct cn_core_set *core);
int cn_core_get_numa_node(int id);
int cn_core_get_numa_node_by_core(struct cn_core_set *core);
struct device *cn_core_get_dev(int id);
struct cn_core_set *cn_core_get_with_idx(int idx);
struct cn_core_set *cn_core_get_with_unique_id(uint64_t unique_id);
void cn_core_put(struct cn_core_set *core);
struct cn_core_set *cn_core_get_ref(int idx);
void cn_core_put_deref(struct cn_core_set *core_set);
struct cn_core_set *cn_core_get_mi_core(int phy_idx, int mi_idx);
struct cn_core_set *cn_core_get_mi_core_ref(int phy_idx, int mi_idx);
uint32_t cn_core_get_proj_id(struct cn_core_set *core);
int cn_core_reset(struct cn_core_set *core, bool reset);
char *cn_get_core_state_string(enum cn_boot_state state);
u64 cn_core_get_fp_id(struct file *fp);
int heartbeat_thread_init(struct cn_core_set *core);
int heartbeat_thread_exit(struct cn_core_set *core);
int cn_core_lpm_enable(void);
int cn_core_lt_cap_enable(void);
int cn_cdev_late_init(struct cn_core_set *core);
void cn_cdev_late_exit(struct cn_core_set *core);
int cn_cdev_init(struct cn_core_set *core);
void cn_cdev_exit(struct cn_core_set *core);

struct fp_priv_data {
	struct cn_core_set *core;
	struct cnhost_minor *fp_minor;
	void *mm_priv_data;
	void *mm_perf_priv_data;
	void *monitor_priv_data;
	struct pid_info_s *pid_info_node;
	void *perf_priv_data;
	void *sbts_priv_data;
	void *smlu_priv_data;
	u64 fp_id;
	u32 state;
};

int cn_core_mig_suspend(struct cn_core_set *core);
int cn_core_mig_resume(struct cn_core_set *core, u32 new_bdf);


int cn_core_setup_dev_ctl(void);
void cn_core_remove_dev_ctl(void);
struct device *cndrv_core_get_dma_device(void);
void *cndrv_core_get_udvm(void);

int cn_check_curproc_is_docker(struct pid_info_s *cur_proc);
extern int cn_get_mlu_major_minor(int idx, unsigned int *major, unsigned int *minor);
extern int cn_get_mlu_idx(u32 bdf, bool is_pdev_virtfn);

int cn_is_host_ns(void);

static inline ssize_t cn_core_set_prohibit_mode(struct cn_core_set *core, unsigned int mode){
	spin_lock(&core->pid_info_lock);
	if (core->open_count) {
		spin_unlock(&core->pid_info_lock);
		return -EBUSY;
	}

	if (mode) {
		if (core->exclusive_mode == PROHIBITED_PROCESS) {
			spin_unlock(&core->pid_info_lock);
			return -EBUSY;
		}
		core->exclusive_mode = mode;
		core->exclusive_pgid = task_pgrp_nr_ns(current, task_active_pid_ns(current));
	} else {
		if (core->exclusive_pgid == task_pgrp_nr_ns(current, task_active_pid_ns(current))) {
			core->exclusive_mode = mode;
			core->exclusive_pgid = -1;
		} else {
			spin_unlock(&core->pid_info_lock);
			return -EBUSY;
		}
	}
	spin_unlock(&core->pid_info_lock);
	return 0;
}
static inline ssize_t cn_core_set_execute_mode(struct cn_core_set *core, unsigned int mode) {
	spin_lock(&core->pid_info_lock);
	if (core->open_count) {
		spin_unlock(&core->pid_info_lock);
		return -EBUSY;
	}

	if (core->exclusive_mode == PROHIBITED_PROCESS) {
		spin_unlock(&core->pid_info_lock);
		return -EBUSY;
	}

	if (mode) {
		core->exclusive_mode = COMPUTEMODE_EXCLUSIVE_PROCESS;
	} else {
		core->exclusive_mode = COMPUTEMODE_DEFAULT;
		core->exclusive_pgid = -1;
	}
	spin_unlock(&core->pid_info_lock);
	return 0;
}

static inline unsigned int cn_core_get_execute_mode(struct cn_core_set *core) {
	return core->exclusive_mode;
}

/*
 * In normal situation, the /dev/cambricon_NAME shall not be exist.
 */
int cn_pre_check_dev_node(const char *name);

/*
 * When call this function, the core will be delete and the new core will created,
 * so the core struct can't be accessed after called this function.
 */
int cn_core_set_mim_mode(struct cn_core_set *core, int enable);
int cn_is_mim_en(struct cn_core_set *core);
int cn_is_mim_en_bdf(u32 bdf, bool is_pdev_virtfn);
/* The vf nofify the pf's bdf, the vf's mim enable status must equal the attached pf */
int cn_mim_notify_vf_status(u32 vf_bdf, u32 pf_bdf);
/* MLU2xx/MLU3xx not support mim mode, must call this to notify the core */
int cn_mim_notify_mim_status(u32 pf_bdf, int enable);

/**
 * core_work_mode indicates that in which mode a core set is working
 *
 * FULL: Physical Function without MIM Mode enable
 * MIM_EN: Physical Function with MIM Mode enable
 * MI: Virtual Function, i.e. MLU Instance
 * SMLU: Split-MLU based on namespace, pure software virtualization
 */
enum core_work_mode {
	FULL = 0x1,
	MIM_EN = 0x2,
	MI = 0x4,
	SMLU = 0x8,
};

static inline enum core_work_mode cn_core_get_work_mode(struct cn_core_set *core)
{
	if (!core)
		return 0;

	if (cn_core_is_vf(core) && cn_is_mim_en(core))
		return MI;
	else if (cn_core_is_vf(core) && !cn_is_mim_en(core))
		return FULL;
	else if (cn_is_mim_en(core))
		return MIM_EN;
	else if (core->smlu_enable)
		return SMLU;
	else
		return FULL;
}

/* used for cndrv enum device, now unique_id is dev_t */
struct dev_info_s {
	unsigned int dev_num;
	uint64_t unique_id[MAX_PHYS_CARD];
};

void cn_core_get_phys_dev_info(struct dev_info_s *phys_dev_info);
void cn_core_get_sub_dev_info(struct cn_core_set *core,
		struct dev_info_s *sub_dev_info);
#endif /*__CNDRV_CORE_H*/
