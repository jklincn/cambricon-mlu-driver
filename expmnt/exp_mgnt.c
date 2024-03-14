/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/spinlock_types.h>
#include <linux/genalloc.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/random.h>
#include <linux/list.h>
#include <asm/io.h>
#include <linux/string.h>
#include <linux/time.h>
#if (KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE)
#include <linux/time64.h>
#include <linux/timekeeping.h>
#else
#include <linux/timex.h>
#endif
#include <linux/rtc.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"
#include "cndrv_ioctl.h"
#include "exp_mgnt_private.h"
#include "cndrv_commu.h"
#include "cndrv_ipcm.h"
#include "cndrv_xid.h"

static void *__mnt_open_channel(char *name, void *cn_mnt_set)
{
	void *handle = NULL;
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)cn_mnt_set;
	struct cn_core_set *core = (struct cn_core_set *)mnt_set->core;
	struct commu_channel *commu_chn = NULL;

	if (core->support_ipcm) {
		handle = (void *)ipcm_open_channel(core, name);
		if (handle == NULL) {
			cn_xid_err(core, XID_RPC_ERR, "ipcm_open_channel(%s) failed", name);
		}
	} else {
		commu_chn = commu_open_a_channel(name, core, 0);
		if (commu_chn == NULL) {
			cn_xid_err(core, XID_RPC_ERR, "commu_open_a_channel() failed");
			return NULL;
		}

		handle = (void *)connect_rpc_endpoint(commu_chn);
	}

	return handle;
}

static void __mnt_close_channel(void *cn_mnt_set)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)cn_mnt_set;
	struct cn_core_set *core = (struct cn_core_set *)mnt_set->core;

	if (core->support_ipcm) {
		if (likely(mnt_set->endpoint)) {
			ipcm_destroy_channel((struct rpmsg_device *)mnt_set->endpoint);
			mnt_set->endpoint = NULL;
		}
	} else {
		if (likely(mnt_set->endpoint)) {
			disconnect_endpoint((struct commu_endpoint *)mnt_set->endpoint);
			mnt_set->endpoint = NULL;
		}
	}
}

int __mnt_call_rpc_timeout(void *pcore, void *handle, char *func, void *msg, size_t msg_len,
			void *rsp, int *real_sz, size_t rsp_len, int time_out)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)pcore;

	if (handle == NULL) {
		pr_err("%s fails, handle == NULL\n", __func__);
		return -EINVAL;
	}

	if (core->support_ipcm) {
		ret = ipcm_rpc_call_timeout((struct rpmsg_device *)handle, func, msg,
				msg_len, rsp, (uint32_t *)real_sz, rsp_len, time_out);
	} else {
		ret = commu_call_rpc_timeout((struct commu_endpoint *)handle, func, msg,
				msg_len, rsp, (int *)real_sz, msecs_to_jiffies(time_out));
	}

	return ret;
}

void show_one_info(void* result, int len)
{
	struct heartbeat_pkg_s* heartbeat_pkg = (struct heartbeat_pkg_s*)result;

	pr_info("modules_num (%d)\n", heartbeat_pkg->module_num);
	pr_info("id(%d) norm_cnt(%d) excp_cnt(%d) lasted_ts(%lld)\n",
		heartbeat_pkg->module_res[0].module_id,
		heartbeat_pkg->module_res[0].norm_cnt,
		heartbeat_pkg->module_res[0].excp_cnt,
		ktime_to_ns(heartbeat_pkg->module_res[0].lasted_ts) / 1000000);
}

void show_all_info(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)(core->mnt_set);
	struct heartbeat_pkg_s *pkg = (struct heartbeat_pkg_s *)mnt_set->heartbeat_pkg;
	int i, j;

	cn_dev_core_info(core, "modules_num (%d)", pkg->module_num);
	for (i = 0; i < pkg->module_num; i++) {
		cn_dev_core_info(core,
				"id(%d) norm(%d) excp(%d) lasted_ts(%lld)",
				pkg->module_res[i].module_id,
				pkg->module_res[i].norm_cnt,
				pkg->module_res[i].excp_cnt,
				ktime_to_ns(pkg->module_res[i].lasted_ts) / 1000000);

		for (j = 0; j < pkg->module_res[i].excp_cnt &&
				j < EXCP_NUM_PER_MOD; j++)
			cn_dev_core_info(core,
					"id(%d) excp.status:0x%lx",
					pkg->module_res[i].module_id,
					pkg->module_res[i].excp_data[j].status);
	}
}

int check_timeout(ktime_t cur, ktime_t last, unsigned long threshold)
{
	if (((ktime_to_ns(cur) - ktime_to_ns(last)) / 1000000) > threshold)
		return 1;
	return 0;
}

int check_err(struct module_data_s *module)
{
	if (module->excp_cnt > 0)
		return 1;
	return 0;
}

int fast_checkout(struct heartbeat_pkg_s *pkg, int result_len, unsigned long *bitmap)
{
	int i = 0;

	if ((sizeof(struct heartbeat_pkg_s) - result_len) !=
			(MAX_MODULES_NUM - pkg->module_num) * sizeof(struct module_data_s)) {
		pr_err("[WARNING] heartbeat transport data Unmatch\n");
		return -1;
	}

	for (i = 0; i < pkg->module_num; i++) {
		bitmap[0] = bitmap[0] & (~(1<< (pkg->module_res[i].module_id)));
		if (check_timeout(pkg->ts_get_from_device,
				pkg->module_res[i].lasted_ts,
				pkg->module_res[i].timeout_threshold_ms))
			bitmap[0] = bitmap[0] | (1<< (pkg->module_res[i].module_id));
		if (check_err(&(pkg->module_res[i])))
			bitmap[0] = bitmap[0] | (1<< (pkg->module_res[i].module_id));
	}
	return 0;
}

static int32_t
rpc_get_info(void *pcore, void *endpoint, void *recv_buf, int *len, unsigned long *bitmap)
{
	int ret = 0;
	struct rpc_arm_param rpc_param;
	int result_from_server_len = *len;
	void *result_from_server = recv_buf;

	memset_io(result_from_server, 0, result_from_server_len);
	rpc_param.cmd = GET_ALL_INFO;

	/*
	 * Commu rpc may block when arm crash, use timeout rpc call
	 */
	ret = __mnt_call_rpc_timeout(pcore, endpoint, "rpc_arm_action", &rpc_param,
			sizeof(struct rpc_arm_param), result_from_server,
			&result_from_server_len, sizeof(struct heartbeat_pkg_s), 10000);

	if (ret < 0) {
		pr_err("cnrpc client request failed (%d).\n", ret);
		return ret;
	}

	*len = result_from_server_len;

	ret = fast_checkout(result_from_server, *len, bitmap);

#ifdef _DEBUG_HB_
	show_one_info(result_from_server, result_from_server_len);
#endif
	return ret;
}

int cn_device_status_query(struct cn_core_set *core, unsigned long *bitmap)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)(core->mnt_set);
	void *recv_buf = mnt_set->heartbeat_pkg;
	int len = sizeof(struct heartbeat_pkg_s);
	int ret = 0;

	ret = rpc_get_info(core, mnt_set->endpoint, recv_buf, &len, bitmap);

	return ret;
}

EXPORT_SYMBOL(cn_device_status_query);

int cn_device_get_acpu_log(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)(core->mnt_set);
	struct cn_bus_set *bus_set = (struct cn_bus_set *)(core->bus_set);
	void *endpoint = NULL;
	struct mem_attr mm_attr;
	dev_addr_t dev_vaddr;
	dev_addr_t ptr;
	int ret = 0;
	struct rpc_arm_param rpc_param = {0};
	struct rpc_arm_resp *rpc_resp;
	struct rpc_arm_resp rpc_resp_fetch = {0};
	int out_size = 0;
	int i = 0;
	char *tmp = NULL;
	char *log_tmp = NULL;
	char *line = NULL;
	struct file *fp;
	#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	mm_segment_t fs;
	#endif
	loff_t pos = 0;
	int ewrite, nwrite;
	int remain;
	char file_path[64] = {0};
	#if (KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE)
	struct timespec64 ts64;
	#else
	struct timex txc;
	#endif
	bool log_to_file = true;

	if (unlikely(!mnt_set)) {
		cn_dev_core_err(core, "mnt_set freed.");
		return -EINVAL;
	}

	if (unlikely(!bus_set)) {
		cn_dev_core_err(core, "bus_set freed.");
		return -EINVAL;
	}

	endpoint = mnt_set->endpoint;
	if (unlikely(!endpoint)) {
		cn_dev_core_err(core, "endpoint freed.");
		return -EINVAL;
	}

	rpc_resp = cn_kzalloc(sizeof(struct rpc_arm_resp) + sizeof(struct file_info) * MAX_FILE_CNT, GFP_KERNEL);
	if (!rpc_resp) {
		cn_dev_core_err(core, "no memory.");
		return -ENOMEM;
	}

	tmp = cn_kzalloc(D2H_BUF_SIZE, GFP_KERNEL);
	if (!tmp) {
		cn_dev_core_err(core, "no memory.");
		goto d2h_failed;
	}

	rpc_param.cmd = LS_PSTORE_NAME_SIZE;

	ret = __mnt_call_rpc_timeout(core, endpoint, "rpc_arm_ls_pstore_file_info", &rpc_param,
			sizeof(struct rpc_arm_param), rpc_resp, &out_size, sizeof(struct heartbeat_pkg_s), 1000);

	if (ret < 0 || rpc_resp->ret < 0) {
		cn_dev_core_err(core, "cnrpc client request failed (%d).", ret);
		goto cn_mem_failed;
	}
	cn_dev_core_debug(core, "pstore file cnt(%d).", rpc_resp->file_cnt);

	/* foreach pstore file
	 * vfs_read arm sysfs file---> mlu buffer --->d2h -->vfs_write host file
	 */
	for (i = 0; i < rpc_resp->file_cnt; i++) {
		cn_dev_core_debug(core, "pstore file:%s, size:%d",
			rpc_resp->files[i].file_name, rpc_resp->files[i].file_size);
		/*
		 * malloc cnrt buffer to copy data between x86 and arm
		 * buffer size is the values of file size
		 */
		INIT_MEM_ATTR(&mm_attr, rpc_resp->files[i].file_size, 1024, CN_IPU_MEM, -1, 0);
		ret = cn_mem_alloc(0, &dev_vaddr, &mm_attr, core);
		if (ret) {
			cn_dev_core_err(core, "ipu memory alloc failed(%d -- %#lx).",
				mm_attr.affinity, mm_attr.size);
			goto cn_mem_failed;
		}

		ret = cn_mem_dma_memsetD8(core, dev_vaddr, rpc_resp->files[i].file_size, 0, 0);
		if (ret)
			cn_dev_core_err(core, "dma memset error");

		rpc_param.cmd = FETCH_PSTORE_FILE;
		rpc_param.mlu_addr_info.mlu_addr = dev_vaddr;
		rpc_param.mlu_addr_info.size = rpc_resp->files[i].file_size;

		strcpy(rpc_param.file_info.file_name, rpc_resp->files[i].file_name);
		rpc_param.file_info.file_size = rpc_resp->files[i].file_size;

		ret = __mnt_call_rpc_timeout(core, endpoint, "rpc_arm_fetch_pstore_file",
				&rpc_param, sizeof(struct rpc_arm_param), &rpc_resp_fetch,
				&out_size, sizeof(struct heartbeat_pkg_s), 1000);

		if (ret < 0 || rpc_resp_fetch.ret < 0) {
			cn_dev_core_err(core, "cnrpc client request failed (%d).", ret);
			goto file_failed;
		}
		ptr = dev_vaddr;
		#if (KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE)
		ktime_get_real_ts64(&ts64);
		sprintf(file_path, "/pstore-%s-%lld", rpc_resp->files[i].file_name, ts64.tv_sec);
		#else
		do_gettimeofday(&(txc.time));
		sprintf(file_path, "/pstore-%s-%ld", rpc_resp->files[i].file_name, txc.time.tv_sec);
		#endif

		/*open file*/
		fp = filp_open(file_path, O_RDWR | O_CREAT, 0644);
		if (IS_ERR(fp)) {
			cn_dev_core_err(core, "open file:%s failed, %ld", file_path, PTR_ERR(fp));
			log_to_file = false;
		}

		if (log_to_file) {
			#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
			fs = get_fs();
			set_fs(KERNEL_DS);
			#endif
		}

		remain = rpc_resp->files[i].file_size;
		pos = 0;
		do {
			ewrite = min(remain, D2H_BUF_SIZE);
			/*
			 * get file data from cnrt memroy
			 * we need cn_bus_dma_kernel() but cn_mem_copy_d2h() called cn_bus_dma().
			 */
			cn_bus_dma_kernel(core->bus_set, (unsigned long)tmp,
					  (unsigned long)ptr, ewrite, DMA_D2H);
			ptr += ewrite;

			if (log_to_file) {
				/*
				 * write file data to file
				 * nwrite = fp->f_op->write(fp, tmp, ewrite, &fp->f_pos);
				 */
				#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
				nwrite = vfs_write(fp, tmp, ewrite, &pos);
				#else
				nwrite = kernel_write(fp, tmp, ewrite, &pos);//without dance with setfs()
				#endif
				if (nwrite <= 0) {
					cn_dev_core_err(core, "write %s fail (%d)", file_path, nwrite);
					ret = -EIO;
					goto out;
				}
			}
			remain -= ewrite;
			if (!strncmp(rpc_resp->files[i].file_name, "console-ramoops", strlen("console-ramoops"))) {
				cn_dev_core_err(core, "\n-------------acpu stack-----------\n");
				log_tmp = tmp;
				/* printk.c LOG_LINE_MAX = 1024-32 */
				while ((line = strsep(&log_tmp, "\n")) != NULL) {
					if (line[0] == '\0' || !strlen(line))
						continue;
					cn_dev_core_err(core, "%s", line);
				}
			}
		} while (remain > 0);

		if (log_to_file) {
			filp_close(fp, NULL);
			#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
			set_fs(fs);
			#endif
			cn_dev_core_info(core, "save file: %s.", file_path);
		}

		ret = cn_mem_free(0, dev_vaddr, core);
		if (ret < 0) {
			cn_dev_core_err(core, "mem_free failed.");
		}

		rpc_param.cmd = DEL_PSTORE_FILE_IN_ACPU;

		ret = __mnt_call_rpc_timeout(core, endpoint, "rpc_arm_del_pstore_file",
				&rpc_param, sizeof(struct rpc_arm_param), &rpc_resp_fetch,
				&out_size, sizeof(struct heartbeat_pkg_s), 1000);

		if (ret < 0 || rpc_resp_fetch.ret < 0) {
			cn_dev_core_err(core, "cnrpc client request failed (%d).", ret);
			goto cn_mem_failed;
		}
	}
	cn_kfree(tmp);
	cn_kfree(rpc_resp);

	return 0;

out:
	filp_close(fp, NULL);
	#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	set_fs(fs);
	#endif

file_failed:
	if (cn_mem_free(0, dev_vaddr, core) < 0)
		cn_dev_core_err(core, "mem_free failed.");

cn_mem_failed:
	cn_kfree(tmp);

d2h_failed:
	cn_kfree(rpc_resp);

	return ret;
}

int cn_mnt_init(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set;
	struct heartbeat_pkg_s *heartbeat_pkg;

	if (cn_core_is_vf(core))
		return 0;

	if ((core->device_id == MLUID_370_DEV) || (core->device_id == MLUID_590_DEV)) {
		cn_dev_core_info(core, "no support 370 or 590 dev.\n");
		return 0;
	}

	mnt_set = cn_kzalloc(sizeof(struct cn_mnt_set), GFP_KERNEL);
	if(mnt_set == NULL) {
		pr_err("mnt_set init fail\n");
		return -ENOMEM;
	}

	heartbeat_pkg = cn_kmalloc(sizeof(struct heartbeat_pkg_s), GFP_KERNEL);
	if (heartbeat_pkg == NULL) {
		cn_kfree(mnt_set);
		mnt_set = NULL;
		pr_err("exp tbl malloc faile\n");
		return -ENOMEM;
	}
	mnt_set->heartbeat_pkg = heartbeat_pkg;

	core->mnt_set = mnt_set;
	mnt_set->core = core;
	mnt_set->endpoint = NULL;

	cn_report_init(core);

	return 0;
}

void cn_mnt_rpc_late_exit(struct cn_core_set *core)
{
	struct cn_mnt_set* p_mnt_set;

	p_mnt_set = (struct cn_mnt_set *)(core->mnt_set);
	if (core->mnt_set) {
		__mnt_close_channel(p_mnt_set);
	}
	cn_report_late_exit(core);
	cn_kdump_exit(core);
}

void cn_mnt_exit(struct cn_core_set *core)
{
	struct cn_mnt_set* p_mnt_set;

	if (cn_core_is_vf(core))
		return;

	p_mnt_set = (struct cn_mnt_set *)(core->mnt_set);
	if (p_mnt_set == NULL)
		return;

	cn_report_free(core);

	if (p_mnt_set->heartbeat_pkg != NULL) {
		cn_kfree(p_mnt_set->heartbeat_pkg);
		p_mnt_set->heartbeat_pkg = NULL;
	}

	cn_kfree(core->mnt_set);
}

int cn_mnt_rpc_late_init(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = core->mnt_set;

	mnt_set->endpoint = __mnt_open_channel("mnt-commu", mnt_set);
	if (IS_ERR_OR_NULL(mnt_set->endpoint)) {
		pr_err("cn_mnt_krpc open rpc channel failed\n");
		return -EFAULT;
	}

	pr_info("cn_mnt_krpc register success\n");

	cn_kdump_init(core);
	cn_report_late_init(core);
	return 0;
}

/* Next function Just for test */
void collect_distribute_map(struct heartbeat_pkg_s *pkg, unsigned long bitmap, struct DistributeMap *res)
{
	int i;
	for (i = 0; i < pkg->module_num; i++) {
		res->ModuleMap[i] = pkg->module_res[i].module_id;
	}
	res->ErrBitMap = bitmap;
	res->ModuleNum = pkg->module_num;
}

int get_one_msg(struct heartbeat_pkg_s *pkg, int module_id, struct ErrState *res)
{
	int i, j;
	for (i = 0; i < pkg->module_num; i++) {
		if (pkg->module_res[i].module_id == module_id) {
			res->ModuleID = module_id;
			res->TimeoutFlag = 0;
			if (check_timeout(pkg->ts_get_from_device, pkg->module_res[i].lasted_ts, pkg->module_res[i].timeout_threshold_ms))
				res->TimeoutFlag = 1;
			res->ExcpCnt = pkg->module_res[i].excp_cnt;
			for (j = 0; j < res->ExcpCnt && j < EXCP_NUM_PER_MOD; j++) {
				res->ExcpState[j] = pkg->module_res[i].excp_data[j].status;
			}
			break;
		}
	}

	if (i == pkg->module_num) {
		return -1;
	}

	return 0;
}
