#include <linux/seq_file.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/kfifo.h>
#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_mcc.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_udvm_usr.h"
#include "cndrv_fa.h"
#include "camb_mm.h"
#include "cndrv_ext.h"
#include "cndrv_pre_compile.h"
#include "../hal/cn_mem_hal.h"
#include "camb_udvm.h"
#include "camb_vmm.h"
#include "camb_mm_compat.h"
#include "camb_mm_tools.h"
#include "camb_timestamp.h"
#include "camb_linear_remap.h"

/******** memcheck interfaces START ********/
/* NOTE: if error happened, return zero as not redzone need set */
static unsigned long
__get_redzone_size(void *mem_set, struct mapinfo *pminfo, bool is_fa)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;
	unsigned long allocated_size = 0, aligned_size = 0;
	size_t page_size = 0;

	if (!pminfo)
		return 0;

	allocated_size = pminfo->mem_meta.size;
	if (is_fa) {
		aligned_size = camb_fixsize(mm_set->fa_array, allocated_size);
	} else {
		page_size = camb_get_page_size();
		/* if page_size == 0, aligned size is zero as well */
		aligned_size = ALIGN(allocated_size, page_size);
	}

	return aligned_size - allocated_size;
}

/* ret = 0, success; ret != 0, set_redzone failed */
static unsigned int
__get_memcheck_magic_with_fp(struct file *fp, struct cn_mm_set *mm_set)
{
	if (fp_is_udvm(fp)) {
		return (get_udvm_priv_data(fp)->memcheck_magic & 0xFF);
	} else {
		struct cn_mm_priv_data *mm_priv_data;

		mm_priv_data = __get_mm_priv(fp, mm_set);
		if (!mm_priv_data) {
			return 0;
		}

		return (mm_priv_data->memcheck_magic & 0xFF);
	}
}

int camb_config_redzone_size(struct file *fp, struct cn_mm_set *mm_set,
			struct mapinfo *pminfo, unsigned long *allocated_size, bool is_fa)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	unsigned int memcheck_magic = __get_memcheck_magic_with_fp(fp, mm_set);
	unsigned long redzone = 0;

	if (!pminfo->mem_meta.size) {
		cn_dev_core_err(core, "mem_meta.size is zero, maybe mapinfo isn't initialized");
		return -EINVAL;
	}

	*allocated_size = pminfo->mem_meta.size;
	/* memcheck_magic == 0, No Set Debug Mode */
	if (!memcheck_magic) {
		cn_dev_core_debug(core, "Do not Set MEMCHECK DEBUG MODE!");
		return 0;
	}

	redzone = __get_redzone_size(mm_set, pminfo, is_fa);
	if (redzone) {
		pminfo->redzone_size = redzone;
	} else {
		/* NOTE: normal alloc with aligned size, memory gap is enough to  protect
		 * device memory from the risk of OutOfBound Access.
		 *
		 * Only fa alloc with aligned size need memcheck to check is oob hanppened.
		 * Thus, the extra size allocated is decided by the fa alloc_order.
		 * */
		*allocated_size     += 1ULL << mm_set->fa_array->alloc_order;
		pminfo->redzone_size = 1ULL << mm_set->fa_array->alloc_order;
	}

	return 0;
}

int camb_set_redzone(struct file *fp, struct mapinfo *pminfo,
				struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	unsigned long redzone, size;
	unsigned char *buf = NULL;
	unsigned int memcheck_magic = __get_memcheck_magic_with_fp(fp, mm_set);

	/* memcheck_magic == 0, No Set Debug Mode */
	if (!memcheck_magic) {
		cn_dev_core_debug(core, "Do not Set MEMCHECK DEBUG MODE!");
		return 0;
	}

	size = pminfo->mem_meta.size;
	redzone = pminfo->redzone_size;
	if (!redzone) {
		cn_dev_core_debug(core, "RedZone is Zero! Don't Have PageNoUse Memory");
		return 0;
	}

	buf = cn_kzalloc(redzone, GFP_KERNEL);
	if (!buf) {
		cn_dev_core_err(core, "no mem error");
		return -ENOMEM;
	}

	cn_dev_core_debug(core, "Magic Number in RedZone:%#x\n", memcheck_magic);
	memset(buf, memcheck_magic, redzone);

	cn_bus_bar_copy_h2d(core->bus_set, pminfo->virt_addr + size,
						(unsigned long)buf, redzone);
	cn_kfree(buf);

	return 0;
}

/* ret = 0, success; ret < 0, check_redzone failed;
 * ret > 0, Out Of Bound Happened */
int camb_check_redzone(struct file *fp, struct mapinfo *pminfo,
			struct cn_mm_set *mm_set)
{
	int i, ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	unsigned int memcheck_magic = __get_memcheck_magic_with_fp(fp, mm_set);
	unsigned long redzone, size;
	unsigned char *buf = NULL;

	/* memcheck_magic == 0, No Set Debug Mode */
	if (!memcheck_magic)
		return 0;

	cn_dev_core_debug(core, "Magic Number in RedZone:%#x\n", memcheck_magic);

	size = pminfo->mem_meta.size;
	redzone = pminfo->redzone_size;
	if (!redzone) {
		cn_dev_core_debug(core, "RedZone is Zero! Don't Have PageNoUse Memory");
		return 0;
	}

	buf = cn_kzalloc(redzone, GFP_KERNEL);
	if (!buf) {
		cn_dev_core_err(core, "no mem error");
		return -ENOMEM;
	}

	cn_bus_bar_copy_d2h(core->bus_set, pminfo->virt_addr + size,
						(unsigned long)buf, redzone);

	for (i = 0; i < redzone; i++) {
		if (buf[i] != memcheck_magic) {
			cn_dev_core_err(core, "***** Memory Access OutBound ******");
			cn_dev_core_err(core, "Allocated memory start: %#llx, end: %#llx",
							pminfo->virt_addr, pminfo->virt_addr + size - 1);
			cn_dev_core_err(core, "Error: write data %#x in address %#llx",
							(unsigned int)buf[i], pminfo->virt_addr + size + i);
			ret = size + i;
			break;
		}
	}

	cn_kfree(buf);
	return ret;
}

#ifdef CONFIG_CNDRV_EDGE
int camb_mem_enable_memcheck(u64 tag, unsigned int magic, void *mem_set)
{
	cn_dev_warn("EDGE platform not support memcheck debug mode");
	return 0;
}
#else
int camb_mem_enable_memcheck(u64 tag, unsigned int magic, void *mem_set)
{
	struct file *fp = (struct file *)tag;

	if (fp_is_udvm(fp)) {
		get_udvm_priv_data(fp)->memcheck_magic = magic & 0xff;
	} else {
		struct cn_mm_priv_data *mm_priv_data;
		struct cn_mm_set *mm_set = mem_set;

		mm_priv_data = __get_mm_priv(fp, mm_set);
		if (!mm_priv_data) {
			return -EINVAL;
		}

		/* NOTE: if magic is zero means not enable memcheck */
		mm_priv_data->memcheck_magic = magic & 0xff;
	}

	cn_dev_info("Process %d enable MEMCHECK debug mode with %#x magic set",
			current->tgid, magic);
	return 0;
}
#endif
/******** memcheck interfaces END ********/

/******** INTERNAL DFX: dump memory info while alloc failed START ********/
static void
__parse_error_code(int errcode, struct cn_mm_set *mm_set)
{
	switch (errcode) {
	case -EINVAL:
		MEMTOOLS_LOG(" ErrCode <%d> : Invalid Parametrs Input", errcode);
		break;
	case -ENOMEM:
		MEMTOOLS_LOG(" ErrCode <%d> : Not Enough System Memory(OOM is possible)", errcode);
		break;
	case -ENOSPC:
		MEMTOOLS_LOG(" ErrCode <%d> : Not Enough Device Memory", errcode);
		break;
	case -EPERM:
		MEMTOOLS_LOG(" ErrCode <%d> : Not support config for current platform", errcode);
		break;
	default:
		MEMTOOLS_LOG(" ErrCode <%d> : Unknown Error Code", errcode);
		break;
	}
}

static char *__parse_sharemem_caller(struct mapinfo *pminfo)
{
	char *caller = NULL, *ret, *p;

	caller = kasprintf(GFP_KERNEL, "%pS", pminfo->shm_info.caller);
	p = caller;
	if (strstr(p, "shm_reserved")) {
		char *name = __shm_get_name_by_dev_vaddr(pminfo->mm_set, pminfo->virt_addr);
		ret = kasprintf(GFP_KERNEL, "%s", name ? name : strsep(&p, " "));
	} else {
		ret = kasprintf(GFP_KERNEL, "%s", strsep(&p, " "));
	}

	kfree(caller);
	return ret;
}

static inline void
___minfo_print_info(struct mapinfo *minfo, struct seq_file *s)
{
	char *name = minfo->mem_meta.name;

	/* output special info while name saved in minfo is NULL */
	if (strlen(name) == 0) {
		if (minfo->ipcm_info)
			name = minfo->ipcm_info->parent ? "IPC_CONSUMER" : "IPC_PRODUCER";
		else
			name = "NULL";
	}

	if (minfo->mem_meta.type == CN_SHARE_MEM) {
		char *name = __parse_sharemem_caller(minfo);
		MEMTOOLS_PROC(s, "\t |-PUB: iova: %#12llx, size: %#9lx, type: %15s, "
				"flag: %#x, shm_type: %s, name: %s", minfo->virt_addr,
				minfo->mem_meta.size, mem_type_str(minfo->mem_meta.type),
				minfo->mem_meta.flag, shm_type_str(minfo->shm_info.type), name);
		kfree(name);
	} else if (minfo->tag == 0) {
		if (minfo->mem_type == MEM_KEXT) {
			MEMTOOLS_PROC(s, "\t |-PUB-EXT: iova: %#12llx, kva: %#16llx size: %#9lx, type: %15s, "
					"flag: %#x, chl: %2d, node_type: %s, ext_name: %s",
					minfo->virt_addr, minfo->kva_info.kva, minfo->mem_meta.size,
					mem_type_str(minfo->mem_meta.type),
					minfo->mem_meta.flag, minfo->mem_meta.affinity,
					mapinfo_type_str(minfo->mem_type), name);
		} else {
			MEMTOOLS_PROC(s, "\t |-PUB: iova: %#12llx, size: %#9lx, type: %15s, "
					"flag: %#x, chl: %2d, node_type: %s, description: %s",
					minfo->virt_addr, minfo->mem_meta.size,
					mem_type_str(minfo->mem_meta.type),
					minfo->mem_meta.flag, minfo->mem_meta.affinity,
					mapinfo_type_str(minfo->mem_type), name);
		}
	} else {
		if (minfo->mem_type == MEM_KEXT) {
			MEMTOOLS_PROC(s, "\t |-<%d>: iova: %#12llx, kva:%#16llx size: %#9lx, type: %15s, "
					"flag: %#x, chl: %2d, node_type: %s, is_linear:%s, ext_name: %s",
					minfo->tgid, minfo->virt_addr, minfo->kva_info.kva,
					minfo->mem_meta.size, mem_type_str(minfo->mem_meta.type),
					minfo->mem_meta.flag, minfo->mem_meta.affinity,
					mapinfo_type_str(minfo->mem_type),
					minfo->is_linear ? "TRUE" : "FALSE", name);
		} else {
			MEMTOOLS_PROC(s, "\t |-<%d>: iova: %#12llx, size: %#9lx, type: %15s, "
					"flag: %#x, chl: %2d, node_type: %s, is_linear: %s, description: %s",
					minfo->tgid, minfo->virt_addr, minfo->mem_meta.size,
					mem_type_str(minfo->mem_meta.type),
					minfo->mem_meta.flag, minfo->mem_meta.affinity,
					mapinfo_type_str(minfo->mem_type),
					minfo->is_linear ? "TRUE" : "FALSE", name);
		}
	}
}

static void __dump_procs_minfo(struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = mm_set->core;
	struct pid_info_s *node;
	struct cn_mm_priv_data *mm_priv_data = NULL;
	unsigned long real_used_size = 0UL;
	unsigned long tot_used_size = 0UL, tot_real_used_size = 0UL;

	spin_lock(&core->pid_info_lock);
	if (list_empty(&core->pid_head)) {
		spin_unlock(&core->pid_info_lock);
		MEMTOOLS_LOG(" \t There is no process in running!");
		return;
	}

	list_for_each_entry(node, &core->pid_head, pid_list) {
		if (current->tgid == node->tgid)
			continue;

		mm_priv_data = __get_mm_priv(node->fp, NULL);
		if (!mm_priv_data) {
			MEMTOOLS_LOG(" \t PID: %d's mm_priv_data has been freed(fp:%px, pid_info:%px)!",
					node->tgid, node->fp, node);
			continue;
		}

		real_used_size = atomic_long_read(&mm_priv_data->used_size);
		MEMTOOLS_LOG(" \t PID: %d, Used: %5ldMB, RealUsed: %5ldMB", node->tgid,
				MMB(node->phy_usedsize), MMB(real_used_size));
		tot_used_size += node->phy_usedsize;
		tot_real_used_size += real_used_size;
	}
	spin_unlock(&core->pid_info_lock);
	MEMTOOLS_LOG(" \t Sum of Processes: Used: %5ldMB, RealUsed: %5ldMB",
			MMB(tot_used_size), MMB(tot_real_used_size));
}

void camb_dump_worker_stat(struct cn_mm_set *mm_set, struct seq_file *s)
{
	struct cn_core_set *core = mm_set->core;
	unsigned int work_status = 0;
	int df_state = 0;

	df_state = atomic_read(&mm_set->free_worker_state);
	work_status = work_busy(&mm_set->free_worker);
	if (work_status == WORK_BUSY_RUNNING)
		MEMTOOLS_PROC_LOG(s, "Delayfree[%s], worker_stat: RUNNING, free_worker_state: %s",
			(core->delay_free_enable == MEM_DELAYFREE_ENABLE) ? "ENABLE" : "DISABLE",
			(df_state == WORK_RUNNING) ? "RUNNING" : "IDLE");
	else if (work_status == WORK_BUSY_PENDING)
		MEMTOOLS_PROC_LOG(s, "Delayfree[%s], worker_stat: PENDING, free_worker_state: %s",
			(core->delay_free_enable == MEM_DELAYFREE_ENABLE) ? "ENABLE" : "DISABLE",
			(df_state == WORK_RUNNING) ? "RUNNING" : "IDLE");
	else
		MEMTOOLS_PROC_LOG(s, "Delayfree[%s], worker_stat: %d, free_worker_state: %s",
			(core->delay_free_enable == MEM_DELAYFREE_ENABLE) ? "ENABLE" : "DISABLE",
			work_status, (df_state == WORK_RUNNING) ? "RUNNING" : "IDLE");

	MEMTOOLS_PROC_LOG(s, " \t Freed Counts: %d, DF running times: %d ",
			atomic_read(&mm_set->free_mem_cnt),
			atomic_read(&mm_set->rpc_free_times));

	MEMTOOLS_PROC_LOG(s, " \t ReadytoFree << count: %ld, size: %ldMB >> ",
			mm_set->df_mem_cnt, MMB(mm_set->df_mem_size));

	if (df_state == WORK_RUNNING) {
		MEMTOOLS_LOG("COMMU status info:");
		MEMTOOLS_LOG("commu_cn_mm_krpc endpoint status:");
		__mem_endpoint_dump(core, mm_set->endpoint);
		MEMTOOLS_LOG(" ");

		__mem_endpoint_dump(core, mm_set->mem_async_endpoint);
		MEMTOOLS_LOG(" ");
	}
}

/*
 *FIXME: dump_error_minfo could not be called in MLUID_370_DEV,
 *because fa remote ops will calculate dev fa men twice.
 */
int camb_dump_error_minfo(u64 tag, struct mem_attr *pattr,
			struct cn_mm_set *mm_set, int errcode,
			struct dbg_base_meminfo_t *info)
{
	struct cn_core_set *core = mm_set->core;
	struct file *fp = (struct file *)tag;
	struct fp_priv_data *priv_data;
	struct cn_mm_priv_data *mm_priv_data = NULL;
	struct pid_info_s *node;

	struct fa_stat stat;
	struct cn_fa_array *arr = mm_set->fa_array;
	struct dbg_meminfo_t remsg;
	struct mem_dbg_t dbg;
	size_t result_len = sizeof(struct dbg_meminfo_t);

	int ret = 0, i;
	int skip_flag = 0;
	int min_channel_counts = 0;

	if (!mm_set->is_dump_meminfo) {
		__parse_error_code(errcode, mm_set);
		return 0;
	}

	if ((fp) && (fp->private_data)) {
		priv_data = fp->private_data;
		node = priv_data->pid_info_node;
		mm_priv_data = (struct cn_mm_priv_data *)priv_data->mm_priv_data;
	}

	dbg.pid = current->tgid;
	dbg.cmd = MEM_DBG_GETINFO;
	memset(&remsg, 0x0, result_len);
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_debug", &dbg,
						 sizeof(struct mem_dbg_t), &remsg, &result_len,
						 sizeof(struct dbg_meminfo_t));
	if (ret < 0 || remsg.ret) {
		cn_dev_core_err(core, "Failed, __mem_call_rpc(core, %d), rpc_mem_debug(%d)",
						ret, remsg.ret);
		skip_flag = 1;
	}

	MEMTOOLS_LOG("*************************************************");
	MEMTOOLS_LOG(" Name: <<%s>> MallocFailed MemoryInfo Dump ", current->comm);

	__parse_error_code(errcode, mm_set);

	if (pattr)
		MEMTOOLS_LOG(" Parameters: << type: %d, affinity: %d, size: %#lx, flag: %d >>",
				pattr->type, pattr->affinity, pattr->size, pattr->flag);

	MEMTOOLS_LOG(" >> Arm memory info list << ");
	if (info) {
		MEMTOOLS_LOG(" Board MemoryInfo:(from malloc failed return) ");
		MEMTOOLS_LOG(" Total Size: %ldMB, Used Size: %ldMB", MMB(info->total_mem),
				MMB(info->used_mem));

		if (info->chl_counts > MEM_DBG_MAX_CHANNELS)
			MEMTOOLS_LOG(" \t ChannelCounts: %d is invalid", info->chl_counts);

		min_channel_counts = min_t(unsigned int, info->chl_counts, MEM_DBG_MAX_CHANNELS);
		for (i = 0; i < min_channel_counts; i++) {
			MEMTOOLS_LOG(" \t Channel[%d]: %ldMB, UsedMem: %ldMB", i,
					MMB(info->per_chl_info[i].chl_total_mem),
					MMB(info->per_chl_info[i].chl_used_mem));
		}

	} else if (!skip_flag) {
		MEMTOOLS_LOG(" Board MemoryInfo:(call rpc again) ");
		MEMTOOLS_LOG(" Total Size: %ldMB, Used Size: %ldMB",
				MMB(remsg.base.total_mem), MMB(remsg.base.used_mem));

		if (remsg.base.chl_counts > MEM_DBG_MAX_CHANNELS)
			MEMTOOLS_LOG(" \t ChannelCounts: %d is invalid", remsg.base.chl_counts);

		min_channel_counts = min_t(unsigned int, remsg.base.chl_counts, MEM_DBG_MAX_CHANNELS);
		for (i = 0; i < min_channel_counts; i++) {
			MEMTOOLS_LOG(" \t Channel[%d]: %ldMB, UsedMem: %ldMB", i,
					MMB(remsg.base.per_chl_info[i].chl_total_mem),
					MMB(remsg.base.per_chl_info[i].chl_used_mem));
		}
	}

	if (!skip_flag) {
		MEMTOOLS_LOG(" Reserved Size: %ldMB, Allocated with ION: %ldMB",
				MMB(remsg.reserved_mem), MMB(remsg.allocated_with_ion));
	}

	MEMTOOLS_LOG(" >> Host memory info list << ");
	MEMTOOLS_LOG(" AllProcesses RealUsed: %ldMB, Public MemoryNode RealUsed: %ldMB",
			MMB(mm_set->vir_used_mem - DEFAULT_VIR_USED_MEM),
			MMB(atomic_long_read(&mm_set->mm_priv_data.used_size)));

	if (mm_priv_data) {
		MEMTOOLS_LOG(" CurrentProcess Used: %ldMB, RealUsed: %ldMB",
					 MMB(node->phy_usedsize),
					 MMB(atomic_long_read(&mm_priv_data->used_size)));

	}

	MEMTOOLS_LOG(" OtherProcesses Used Memory: ");
	__dump_procs_minfo(mm_set);

	ret = camb_fa_statistic(arr, &stat);
	if (!ret) {
		MEMTOOLS_LOG(" FastAlloc MemoryInfo:");
		MEMTOOLS_LOG(" \t Total: %ldMB, Used: %ldMB",
				MMB(stat.total_size), MMB(stat.used_size));
	}

	camb_dump_worker_stat(mm_set, NULL);

	MEMTOOLS_LOG("*************************************************");
	return 0;
}

int camb_proc_dump_error_ctrl(struct cn_mm_set *mm_set, bool isdump)
{
	cn_dev_core_info((struct cn_core_set *)mm_set->core,
					 "MallocFailed error log will be %s", isdump ? "detail" : "simple");
	mm_set->is_dump_meminfo = isdump;
	return 0;
}
/******** INTERNAL DFX: dump memory info while alloc failed END ********/

/******** PROC NODE: cn_mem_dump, dump allocated device memory address info START ********/
void camb_dump_public_rbtree(struct cn_mm_set *mm_set, struct seq_file *s)
{
	struct cn_mm_priv_data *mm_priv_data = NULL;
	struct mapinfo *post = NULL;
	struct rb_node *p = NULL;
	size_t tot_size[CN_SHM_MAX + 1] = {0};

	mm_priv_data = &mm_set->mm_priv_data;

	MEMTOOLS_PROC(s, "Address saved in public rbtree: ");
	read_lock(&mm_priv_data->node_lock);
	p = rb_first(&mm_priv_data->mmroot);
	while (p != NULL) {
		post = rb_entry(p, struct mapinfo, node);
		read_unlock(&mm_priv_data->node_lock);
		___minfo_print_info(post, s);

		if (post->mem_meta.type == CN_SHARE_MEM)
			tot_size[post->shm_info.type] += post->mem_meta.size;
		else
			tot_size[CN_SHM_MAX] += post->mem_meta.size;

		read_lock(&mm_priv_data->node_lock);
		p = rb_next(p);
	}
	read_unlock(&mm_priv_data->node_lock);

	MEMTOOLS_PROC(s, "\t |-TOTAL SIZE: inbound: %#lx B, outbound: %#lx B,"
			" outbound_data: %#lx B, others : %#lx B", tot_size[CN_DEV_SHM],
			tot_size[CN_HOST_SHM], tot_size[CN_HOST_DATA_SHM],
			tot_size[CN_SHM_MAX]);

	MEMTOOLS_PROC(s, "\t |-END"); /* add empty line for separate */
}

/* return non-zero means udvm is non-empty, else udvm is empty */
static int
camb_dump_process_list_from_udvm(struct cn_mm_set *mm_set, struct seq_file *s)
{
	struct cn_udvm_set *udvm_set = (struct cn_udvm_set *)cndrv_core_get_udvm();
	struct udvm_priv_data *udvm = NULL;
	struct mlu_priv_data *mlu = NULL;
	int index = get_index_with_mmset(mm_set);
	struct mapinfo *post = NULL;
	struct rb_node *p = NULL;
	int ret = 0;

	if (list_empty(&udvm_set->udvm_head))
		return 0;

	spin_lock(&udvm_set->udvm_lock);
	list_for_each_entry(udvm, &udvm_set->udvm_head, unode) {
		if (udvm_empty(udvm)) continue;

		mlu = udvm->mlu_priv[index];

		if (!mlu || RB_EMPTY_ROOT(&mlu->mmroot))
			continue;

		read_lock(&mlu->node_lock);
		p = rb_first(&mlu->mmroot);
		while (p != NULL) {
			post = rb_entry(p, struct mapinfo, node);
			read_unlock(&mlu->node_lock);
			___minfo_print_info(post, s);
			read_lock(&mlu->node_lock);
			p = rb_next(p);
		}
		read_unlock(&mlu->node_lock);

		ret = 1;
	}
	spin_unlock(&udvm_set->udvm_lock);
	if (ret) MEMTOOLS_PROC(s, "\t |-END UDVM"); /* add empty line for separate */

	return ret;
}

void camb_dump_process_list(struct cn_mm_set *mm_set, struct seq_file *s)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct cn_mm_priv_data *mm_priv_data = NULL;
	struct pid_info_s *node;
	struct mapinfo *post = NULL;
	struct rb_node *p = NULL;
	int ret = 0;

	MEMTOOLS_PROC(s, "Address saved in process list: ");
	ret = camb_dump_process_list_from_udvm(mm_set, s);
	if (ret)
		return;

	spin_lock(&core->pid_info_lock);
	if (list_empty(&core->pid_head)) {
		spin_unlock(&core->pid_info_lock);
		MEMTOOLS_PROC(s, " \t There is no process in running!");
		return;
	}

	list_for_each_entry(node, &core->pid_head, pid_list) {
		mm_priv_data = __get_mm_priv(node->fp, NULL);
		if (!mm_priv_data)
			continue;

		if (mm_priv_data->udvm_priv) {
			spin_lock(&mm_priv_data->mmlist_lock);
			list_for_each_entry(post, &mm_priv_data->minfo_list, priv_node)
				___minfo_print_info(post, s);

			spin_unlock(&mm_priv_data->mmlist_lock);
		} else {
			read_lock(&mm_priv_data->node_lock);
			p = rb_first(&mm_priv_data->mmroot);
			while (p != NULL) {
				post = rb_entry(p, struct mapinfo, node);
				read_unlock(&mm_priv_data->node_lock);
				___minfo_print_info(post, s);
				read_lock(&mm_priv_data->node_lock);
				p = rb_next(p);
			}
			read_unlock(&mm_priv_data->node_lock);
		}
	}
	spin_unlock(&core->pid_info_lock);
	MEMTOOLS_PROC(s, "\t |-END"); /* add empty line for separate */
}

int camb_align_granularity_ctrl(struct cn_mm_set *mm_set, unsigned int flag)
{
	struct cn_core_set *core = mm_set->core;

	if (flag == MEM_ALLOC_ALIGN_ENABLE) {
		mm_set->alloc_align.align_enable = MEM_ALLOC_ALIGN_ENABLE;
		cn_dev_core_info(core, "mem alloc align enabled.");
	} else if (flag == MEM_ALLOC_ALIGN_DISABLE) {
		mm_set->alloc_align.align_enable = MEM_ALLOC_ALIGN_DISABLE;
		/* reset align order to 14(16K) */
		mm_set->alloc_align.align_order = 14;
		cn_dev_core_info(core, "mem alloc align disabled.");
	}

	return 0;
}

int camb_align_granularity_set(struct cn_mm_set *mm_set, unsigned int order)
{
	struct cn_core_set *core = mm_set->core;

	cn_dev_core_debug(core, "alloc order: %u", order);

	if (order < 14) {
		cn_dev_core_err(core, "minimum order is 14.");
		return -EINVAL;
	}

	if (mm_set->alloc_align.align_enable != MEM_ALLOC_ALIGN_ENABLE) {
		mm_set->alloc_align.align_enable = MEM_ALLOC_ALIGN_ENABLE;
	}

	mm_set->alloc_align.align_order = order;

	return 0;
}

void camb_add_node_free_failure_list(struct cn_mm_set *mm_set,
								dev_addr_t dev_vaddr,
								struct mem_attr *mem_meta,
								size_t mem_size,
								int rpc_ret,
								bool mem_sync_commu_point)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct free_failure_node *mem_node= NULL;

	mem_node = cn_kzalloc(sizeof(struct free_failure_node), GFP_KERNEL);

	if (!mem_node) {
		cn_dev_core_err(core, "kzalloc free_failure_node space error!");
		return;
	}

	mem_node->dev_vaddr = dev_vaddr;
	if(mem_meta == NULL) {
		mem_node->mem_meta.size = mem_size;
	} else {
		memcpy(&mem_node->mem_meta, mem_meta, sizeof(struct mem_attr));
	}
	mem_node->rpc_ret = rpc_ret;
	mem_node->mem_sync_commu_point = mem_sync_commu_point;
	spin_lock(&mm_set->ffl_lock);
	list_add(&mem_node->list, &mm_set->free_failure_list);
	spin_unlock(&mm_set->ffl_lock);

	return;
}

void camb_dmup_free_failure_list(void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;

	struct free_failure_node *tmp = NULL;
	struct free_failure_node *pos = NULL;

	spin_lock(&mm_set->ffl_lock);
	list_for_each_entry_safe(pos, tmp, &mm_set->free_failure_list, list) {
		cn_dev_core_info(core, " >> Free Failure List << ");
		if (pos->mem_meta.tag) {
			cn_dev_core_info(core, "Mem Tag[%llx] : Va[%#llx] : Size[%lx] : Type[%x] "
							 ": affinity[%x] : flag[%x] : name[%s] RPC commu %d ret[%d]",
							 pos->mem_meta.tag, (u64)pos->dev_vaddr, pos->mem_meta.size,
							 pos->mem_meta.type, pos->mem_meta.affinity,
							 pos->mem_meta.flag, pos->mem_meta.name,
							 pos->mem_sync_commu_point, pos->rpc_ret);
		} else {
			cn_dev_core_info(core, "Mem Va[%#llx] : Size[%lx] : RPC commu %d ret[%d]",
							 (u64)pos->dev_vaddr, pos->mem_meta.size,
							 pos->mem_sync_commu_point, pos->rpc_ret);
		}
	}
	spin_unlock(&mm_set->ffl_lock);

	return;
}

void camb_clear_free_failure_list(void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct free_mem_list free_list;
	int  list_len = sizeof(struct free_mem_list);
	struct ret_msg remsg;
	size_t dev_ret_len = sizeof(struct ret_msg);
	struct free_failure_node *pos = NULL;
	int ret = 0;

	free_list.mem_cnt = 1;

	spin_lock(&mm_set->ffl_lock);
	while (!list_empty(&mm_set->free_failure_list)) {
		pos = list_first_entry(&mm_set->free_failure_list, struct free_failure_node, list);
		list_del(&pos->list);
		spin_unlock(&mm_set->ffl_lock);
		cn_dev_core_info(core, "Mem Va[%#llx] : Size[%lx] : RPC ret[%d]",
						 (u64)pos->dev_vaddr, pos->mem_meta.size, pos->rpc_ret);
		/*Temporarily Fa type just support NORMAL*/
		free_list.mem_list[0].tag = CN_IPU_MEM;
		free_list.mem_list[0].device_addr = pos->dev_vaddr;
		memset(&remsg, 0x00, sizeof(struct ret_msg));
		/*try free mem used the same endpoint*/
		if (pos->mem_sync_commu_point) {/*sync*/
			ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_free",
								 &free_list, list_len, &remsg, &dev_ret_len,
								 sizeof(struct ret_msg));
		} else {/*Temporarily not happen*/
			ret = __mem_call_rpc(core, mm_set->mem_async_endpoint, "rpc_mem_free",
								 &free_list, list_len, &remsg, &dev_ret_len,
								 sizeof(struct ret_msg));
		}
		if (ret < 0) {
			cn_dev_core_err(core, "addr %#llx call cnrpc client free mem failed.",
							(u64)pos->dev_vaddr);
		}

		if (!ret && remsg.ret) {
			cn_dev_core_err(core, "addr %#llx rpc_mem_free error status is %d",
							(u64)pos->dev_vaddr, remsg.ret);
		}
		cn_kfree(pos);
		spin_lock(&mm_set->ffl_lock);
	}
	spin_unlock(&mm_set->ffl_lock);

	return;
}

/* UDVM_IOCTL << UDVM_MEM_GET_ATTR >>: cn_mem_get_attributes */

static inline void __set_attribute_data_for_unknown(__u64 *data)
{
	data[UDVM_ATTRIBUTE_TYPE] = UDVM_MEMORY_TYPE_UNKNOWN;
	data[UDVM_ATTRIBUTE_DEVICE_POINTER] = 0;
	data[UDVM_ATTRIBUTE_HOST_POINTER] = 0;
	data[UDVM_ATTRIBUTE_SUPPORT_CACHE_OPS] = 0;
	data[UDVM_ATTRIBUTE_CONTEXT] = 0;
	data[UDVM_ATTRIBUTE_DEVICE_ORDINAL] = -2; /* zero is the valid value for device ordinal */
	data[UDVM_ATTRIBUTE_START_ADDR] = 0;
	data[UDVM_ATTRIBUTE_SIZE] = 0;
#if defined (CONFIG_CNDRV_EDGE)
	data[UDVM_ATTRIBUTE_HOST_CACHE_TYPE] = UDVM_HOST_CACHE_UNKNOWN;
#else
	data[UDVM_ATTRIBUTE_HOST_CACHE_TYPE] = UDVM_HOST_CACHE_NOT_SUPPORT;
#endif
	data[UDVM_ATTRIBUTE_ALLOWED_HANDLE_TYPES] = 0;
	data[UDVM_ATTRIBUTE_MAPPED] = 0;
	data[UDVM_ATTRIBUTE_ISLINEAR] = 0;
}

static int __get_attributes_with_host(u64 tag, host_addr_t addr, __u64 *data)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma = NULL;
	int memory_type = UDVM_MEMORY_TYPE_UNKNOWN;
	struct vma_priv_t *priv_data = NULL;
	struct mapinfo *pminfo = NULL;

	/**
	 * Maybe vma is error, find_vma only Look up the first VMA
	 * which satisfies addr < vm_end, NULL if none.
	 * So check uva and uva + len of vma.
	 **/
	cn_mmap_read_lock(mm);
	vma = find_vma(mm, addr);
	if (vma && addr >= vma->vm_start &&
		(camb_vma_is_dummy(vma) || camb_vma_is_uva(vma))) {
		memory_type = UDVM_MEMORY_TYPE_HOST;
		priv_data = vma->vm_private_data;
		if (priv_data)
			pminfo = priv_data->minfo;
	}
	cn_mmap_read_unlock(mm);

	__set_attribute_data_for_unknown(data);

	/* In this function, memory type only could be UNKNOWN or HOST */
	if (memory_type == UDVM_MEMORY_TYPE_HOST) {
		data[UDVM_ATTRIBUTE_TYPE] = UDVM_MEMORY_TYPE_HOST;
		if (pminfo) {
			data[UDVM_ATTRIBUTE_DEVICE_POINTER] =
				pminfo->virt_addr + priv_data->offset + (addr - vma->vm_start);
		} else {
			data[UDVM_ATTRIBUTE_DEVICE_POINTER] = 0;
		}

		data[UDVM_ATTRIBUTE_HOST_POINTER] = addr;
#if defined (CONFIG_CNDRV_EDGE)
		data[UDVM_ATTRIBUTE_SUPPORT_CACHE_OPS] = 1;
#else
		data[UDVM_ATTRIBUTE_SUPPORT_CACHE_OPS] = 0;
#endif
		data[UDVM_ATTRIBUTE_CONTEXT] = 0;

		data[UDVM_ATTRIBUTE_DEVICE_ORDINAL] = -2; /* zero is the valid value for device ordinal */
		data[UDVM_ATTRIBUTE_START_ADDR] = 0;
		data[UDVM_ATTRIBUTE_SIZE] = 0;

#if defined (CONFIG_CNDRV_EDGE)
		if (pgprot_val(pgprot_writecombine(vma->vm_page_prot)) ==
			pgprot_val(vma->vm_page_prot))

			data[UDVM_ATTRIBUTE_HOST_CACHE_TYPE] = UDVM_HOST_NONCACHE;
		else
			data[UDVM_ATTRIBUTE_HOST_CACHE_TYPE] = UDVM_HOST_CACHEABLE;
#else
		data[UDVM_ATTRIBUTE_HOST_CACHE_TYPE] = UDVM_HOST_CACHE_NOT_SUPPORT;
#endif
	}

	return 0;
}

static int
__get_attributes_with_device(u64 tag, dev_addr_t addr, __u64 *data,
						struct cn_mm_set *mm_set)
{
	int memory_type = UDVM_MEMORY_TYPE_UNKNOWN, ret = 0, do_release = 0;
	struct mapinfo *pminfo = NULL;

	/**
	 * NOTE: VMM address maybe not be valid for access(just only do cnMemMap),
	 * but it's valid for get_attribute. So it's inappropriat that calling camb_kref_get
	 * find pminfo for vmm address.
	 **/
	ret = camb_kref_get_without_vmm_check(tag, addr, &pminfo, mm_set);
	if (!ret) do_release = 1;

	if (pminfo) memory_type = UDVM_MEMORY_TYPE_DEVICE;

	__set_attribute_data_for_unknown(data);

	/* In this function, memory type only could be UNKNOWN or DEVICE */
	if (memory_type == UDVM_MEMORY_TYPE_DEVICE) {
		data[UDVM_ATTRIBUTE_TYPE] = UDVM_MEMORY_TYPE_DEVICE;
		data[UDVM_ATTRIBUTE_DEVICE_POINTER] = addr;
		/* TODO: unkown which uva, should we return */
		data[UDVM_ATTRIBUTE_HOST_POINTER] = 0;
#if defined (CONFIG_CNDRV_EDGE)
		data[UDVM_ATTRIBUTE_SUPPORT_CACHE_OPS] = 1;
		data[UDVM_ATTRIBUTE_HOST_CACHE_TYPE] = UDVM_HOST_CACHE_UNKNOWN;
#else
		data[UDVM_ATTRIBUTE_SUPPORT_CACHE_OPS] = 0;
		data[UDVM_ATTRIBUTE_HOST_CACHE_TYPE] = UDVM_HOST_CACHE_NOT_SUPPORT;
#endif
		/* TODO: add context value in pminfo */
		data[UDVM_ATTRIBUTE_CONTEXT] = 0;
		data[UDVM_ATTRIBUTE_DEVICE_ORDINAL] = get_index_with_mmset(pminfo->mm_set);
		if (pminfo->mem_type == MEM_VMM) {
			struct camb_vmm_handle *phandle = pminfo->vmm_info.phandle;
			camb_vmm_get_reserved_range(pminfo,
					(dev_addr_t *)&data[UDVM_ATTRIBUTE_START_ADDR],
					(unsigned long *)&data[UDVM_ATTRIBUTE_SIZE]);

			data[UDVM_ATTRIBUTE_ALLOWED_HANDLE_TYPES] = HANDLE_FLAG(phandle, shared);
		} else {
			data[UDVM_ATTRIBUTE_START_ADDR] = pminfo->virt_addr;
			data[UDVM_ATTRIBUTE_SIZE] = pminfo->mem_meta.size;
			data[UDVM_ATTRIBUTE_ALLOWED_HANDLE_TYPES] = 0;
		}

		data[UDVM_ATTRIBUTE_MAPPED] = 1;
		data[UDVM_ATTRIBUTE_ISLINEAR] = pminfo->is_linear;
		if (do_release) camb_kref_put(pminfo, camb_mem_release);
	}

	return 0;
}

int camb_mem_get_attributes(u64 tag, dev_addr_t addr, __u64 *data, void *mem_set)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)mem_set;

	if (!data)
		return 0;

	if (!mem_set) { /* input address is not udvm_address*/
		return __get_attributes_with_host(tag, addr, data);
	} else {
		return __get_attributes_with_device(tag, addr, data, mm_set);
	}
}

int camb_numa_ctrl(struct cn_mm_set *mm_set, bool flag)
{
	struct cn_core_set *core = mm_set->core;

	mm_set->numa_enable = flag;

	cn_dev_core_info(core, "numa %s.", (flag == true) ? "enabled" : "disabled");

	return 0;
}

int camb_compress_ctrl(struct cn_mm_set *mm_set, bool flag)
{
	struct cn_core_set *core = mm_set->core;

	if (!mm_set->compress_support)
		return 0;

	if (core->open_count) {
		cn_dev_core_info(core, "Can't enable compress alloc now! (Device not free)");
		return 0;
	}

	mm_set->enable_compress_alloc = flag;

	camb_mem_switch_linear_compress_rpc(mm_set, flag);

	if (mm_set->smmu_ops.smmu_reset_remap) {
		mm_set->smmu_ops.smmu_reset_remap(core, mm_set->linear.vaddr,
				mm_set->linear.paddr, mm_set->linear.size,
					SMMU_RMPTYPE_DRAM, flag ? 1UL << ATTR_compress : 0);
	}

	cn_dev_core_info(core, "%s compress alloc succeed!!", flag ? "ENABLE" : "DISABLE");
	return 0;
}

void camb_free_ts_node_init(struct mapinfo *pminfo)
{
	struct cn_mm_set *mm_set = pminfo->mm_set;
	struct free_ts_node *node = NULL;
	int ret = 0;

	if (!mm_set->free_ts.enable)
		return;

	node = cn_kzalloc(sizeof(struct free_ts_node), GFP_KERNEL);
	if (!node)
		return;

	memset(node->timestamps, 0x0, sizeof(u64) * FREE_TS_END);
	node->tgid = current->tgid;
	snprintf(node->comm, TASK_COMM_LEN, "%s", current->comm);

	node->info.address = pminfo->virt_addr;
	node->info.size    = pminfo->mem_meta.size;
	node->info.islinear = pminfo->is_linear;
	node->info.node    = pminfo->mem_type;
	node->info.type    = pminfo->mem_meta.type;
	node->info.prot    = pminfo->mem_meta.flag;
	if (!strlen(pminfo->mem_meta.name)) {
		if (pminfo->ipcm_info) {
			snprintf(node->info.name, EXT_NAME_SIZE, "%s", pminfo->ipcm_info->parent ? "<ipc_consumer>" : "<ipc_producer>");
		} else {
			snprintf(node->info.name, EXT_NAME_SIZE, "<anonymous>");
		}
	} else {
		snprintf(node->info.name, EXT_NAME_SIZE, "%s", pminfo->mem_meta.name);
	}

	spin_lock(&mm_set->free_ts.lock);
	ret = radix_tree_insert(&mm_set->free_ts.ra_root, (u64)pminfo, (void *)node);
	if (likely(!ret))
		list_add(&node->node, &mm_set->free_ts.list);
	spin_unlock(&mm_set->free_ts.lock);
}

void camb_free_ts_node_record(struct mapinfo *pminfo, enum free_timestamp_type type)
{
	struct cn_mm_set *mm_set = pminfo->mm_set;
	struct free_ts_node *node = NULL;

	if (!mm_set->free_ts.enable)
		return;

	if (type >= FREE_TS_END)
		return;

	rcu_read_lock();
	node = radix_tree_lookup(&mm_set->free_ts.ra_root, (u64)pminfo);
	if (!node) {
		rcu_read_unlock();
		return;
	}

	node->timestamps[type] = camb_get_real_time_us();
	rcu_read_unlock();
}

static int camb_free_ts_node_saved(struct cn_mm_set *mm_set, struct free_ts_node *node)
{
	struct cn_core_set *core = mm_set->core;
	struct free_ts_node *out = NULL;
	struct free_ts_root *free_ts = &mm_set->free_ts;
	int ret = 0;

	spin_lock(&free_ts->fifo_lock);
	if (!kfifo_initialized(&free_ts->backing_fifo))
		goto free_node;

	if (kfifo_is_full(&free_ts->backing_fifo)) {
		ret = kfifo_out(&free_ts->backing_fifo, (void *)&out, 1);
		if (ret != 1) {
			cn_dev_core_err(core, "bug on kfifo_out failed");
			goto free_node;
		}

		cn_dev_core_debug_limit(core, "Process:%s[%d]: (addrs:%#llx, sz:%#lx) is released due to fifo is fulled ",
					  node->comm, node->tgid, node->info.address, node->info.size);
		cn_kfree(out);
	}

	ret = kfifo_in(&free_ts->backing_fifo, (void *)&node, 1);
	if (ret != 1) {
		cn_dev_core_err(core, "bug on kfifo_in failed");
		goto free_node;
	}

	spin_unlock(&free_ts->fifo_lock);
	return 0;

free_node:
	spin_unlock(&free_ts->fifo_lock);
	cn_kfree(node);
	return 0;
}

void camb_free_ts_node_record_and_saved(struct mapinfo *pminfo, enum free_timestamp_type type)
{
	struct cn_mm_set *mm_set = pminfo->mm_set;
	struct free_ts_node *node = NULL;

	if (!mm_set->free_ts.enable)
		return;

	if (type != FREE_TS_END - 1)
		return;

	spin_lock(&mm_set->free_ts.lock);
	node = radix_tree_delete(&mm_set->free_ts.ra_root, (u64)pminfo);
	if (node) list_del_init(&node->node);
	spin_unlock(&mm_set->free_ts.lock);
	if (!node)
		return;

	node->timestamps[type] = camb_get_real_time_us();

	camb_free_ts_node_saved(mm_set, node);
}

static int camb_free_ts_printk(struct free_ts_node *node, struct seq_file *s)
{
	struct tm tm;
	int i = 0;

	MEMTOOLS_PROC(s, "Process:%s[%d]: (addrs:%#llx, sz:%#lx, linear:%s, node:%s, type:%s, prot:%#x, name:%s)\nTimestamp: ",
			node->comm, node->tgid, node->info.address, node->info.size,
			node->info.islinear ?  "TRUE" : "FALSE",
			mapinfo_type_str(node->info.node),
			mem_type_str(node->info.type), node->info.prot, node->info.name);
	for (i = 0; i < FREE_TS_END; i++) {
		if (node->timestamps[i]) {
			/* Add 8 hours for Asia/ShangHai timezone, we will only be used in China */
			cn_time64_to_tm(node->timestamps[i] / 1000000, 8 * 3600, &tm);
			MEMTOOLS_PROC(s, "\t [%-16s] --- "TIMESTAMP_FORMAT, timestamp_str(i),
					TIMESTAMP_PARAMS(tm, (int)(node->timestamps[i] % 1000000)));
		} else {
			MEMTOOLS_PROC(s, "\t [%-16s] --- [ NOT YET ]", timestamp_str(i));
		}
	}

	return 0;
}

void camb_free_ts_dump_nonfree(struct cn_mm_set *mm_set, struct seq_file *s)
{
	struct free_ts_node *node = NULL;

	MEMTOOLS_PROC(s, "Non free device memory time stamp list:");
	spin_lock(&mm_set->free_ts.lock);
	list_for_each_entry(node, &mm_set->free_ts.list, node) {
		camb_free_ts_printk(node, s);
	}
	spin_unlock(&mm_set->free_ts.lock);
}

void camb_free_ts_fifo_dump(struct cn_mm_set *mm_set, struct seq_file *s)
{
	struct free_ts_root *free_ts = &mm_set->free_ts;
	struct __kfifo *kfifo = &free_ts->backing_fifo.kfifo;
	struct free_ts_node **node = free_ts->backing_buf;
	int i = 0, len = 0, index = 0;

	MEMTOOLS_PROC(s, "Freed device memory time stamp list:");
	if (!kfifo_initialized(&free_ts->backing_fifo))
		return;

	spin_lock(&free_ts->fifo_lock);
	len = kfifo_len(&free_ts->backing_fifo);
	for (i = 0; i < len; i++) {
		index = kfifo->in - i - 1;
		camb_free_ts_printk(node[index & kfifo->mask], s);
	}
	spin_unlock(&free_ts->fifo_lock);
}

int camb_free_ts_nonfree_clear(struct cn_mm_set *mm_set)
{
	struct free_ts_root *free_ts = &mm_set->free_ts;
	struct free_ts_node *node = NULL, *next = NULL;

	spin_lock(&free_ts->lock);
	if (!list_empty(&free_ts->list)) {
		list_for_each_entry_safe(node, next, &free_ts->list, node) {
			list_del_init(&node->node);
			cn_kfree(node);
		}
	}
	spin_unlock(&free_ts->lock);

	return 0;
}

int camb_free_ts_fifo_clear(struct cn_mm_set *mm_set)
{
	struct free_ts_root *free_ts = &mm_set->free_ts;
	struct free_ts_node *node = NULL;
	struct cn_core_set *core = mm_set->core;
	int ret = 0;

	if (!kfifo_initialized(&free_ts->backing_fifo))
		return 0;

	spin_lock(&free_ts->fifo_lock);
	while (!kfifo_is_empty(&free_ts->backing_fifo)) {
		ret = kfifo_out(&free_ts->backing_fifo, (void *)&node, 1);
		if (ret != 1) {
			cn_dev_core_debug(core, "bug on kfifo_out failed");
			continue;
		}
		cn_kfree(node);
	}
	spin_unlock(&free_ts->fifo_lock);

	cn_dev_core_info(core, "clear free timestamp fifo finished");

	return 0;
}

int camb_free_ts_switch(struct cn_mm_set *mm_set, bool enabled)
{
	struct free_ts_root *free_ts = &mm_set->free_ts;
	struct cn_core_set *core = mm_set->core;

	if (!kfifo_initialized(&free_ts->backing_fifo))
		return -EPERM;

	free_ts->enable = enabled;
	cn_dev_core_info(core, "Current free_ts status is set as %s",
		free_ts->enable ? "ENABLE" : "DISABLE");

	return 0;
}

int camb_free_ts_init(struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = mm_set->core;
	struct free_ts_root *free_ts = &mm_set->free_ts;
	unsigned long fifo_size = 0;
	int ret = 0;

	/* 1. init called free but not call rpc mapinfo list */
	INIT_RADIX_TREE(&free_ts->ra_root, GFP_ATOMIC);
	INIT_LIST_HEAD(&free_ts->list);
	spin_lock_init(&free_ts->lock);

	spin_lock_init(&free_ts->fifo_lock);
	fifo_size = sizeof(struct free_ts_node *) * DEFAULT_KFIFO_LENGTH;
	free_ts->backing_buf = cn_kzalloc(fifo_size, GFP_KERNEL);
	if (!free_ts->backing_buf) {
		cn_dev_core_debug(core, "create backing buffer failed");
		return 0;
	}

	ret = __kfifo_init(&free_ts->backing_fifo.kfifo, free_ts->backing_buf,
			fifo_size, sizeof(struct free_ts_node *));
	if (ret) {
		cn_dev_core_debug(core, "create free timestamp backing fifo failed");
	}

	free_ts->enable = true;
	return 0;
}

void camb_free_ts_deinit(struct cn_mm_set *mm_set)
{
	camb_free_ts_nonfree_clear(mm_set);

	camb_free_ts_fifo_clear(mm_set);

	cn_kfree(mm_set->free_ts.backing_buf);
}
