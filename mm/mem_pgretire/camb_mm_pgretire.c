#include <linux/io.h>
#include <linux/seq_file.h>
#include "cndrv_debug.h"
#include "cndrv_mcc.h"
#include "cndrv_mcu.h"
#include "camb_mm.h"
#include "camb_mm_compat.h"
#include "camb_mm_priv.h"
#include "camb_mm_pgretire.h"
#include "camb_mm_tools.h"

int camb_do_page_retirement(struct cn_mm_set *mm_set, int pgretire_mode)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct hbm_retire_info_t *retire_info = NULL;
	struct pgretire_info_t *pgr_info = NULL;
	unsigned int retire_nums = 0;
	int i = 0;

	if (!mm_set->pgretire_enable)
		return 0;

	pgr_info = (struct pgretire_info_t *)mm_set->pgretire_buf;
	cn_mcc_get_retire_info(core, &retire_info, &retire_nums, pgretire_mode);
	if (retire_nums > PGRETIRE_MAX_CNT) {
		cn_dev_core_err(core, "retire_nums:%d is bigger than MAX_CNT!", retire_nums);
		return -EPERM;
	}

	if (!retire_nums) {
		cn_dev_core_info(core, "don't have page need retired!");
		return 0;
	}

	/**
	 * NOTE: if PENDING is set, other process will not set share memory again,
	 * unless status is changed into IDLE/FAILURE
	 **/
	if (pgretire_mode == PGRETIRE_IRQ_MODE) {
		if (atomic_cmpxchg(&mm_set->pgretire_status, PGRETIRE_IDLE,
						   PGRETIRE_PENDING) != PGRETIRE_IDLE) {
			cn_dev_core_err(core, "pgretire is pending, wait next time retire");
			return -EBUSY;
		}

		mm_set->pgretire_counts++;
		atomic_set(&mm_set->pgretire_again, 0);
	}

	if (core->board_info.platform == MLU_PLAT_ASIC)
		memset_io((void *)mm_set->pgretire_buf, 0x0, PGRETIRE_BUF_LENS(retire_nums));

	pgr_info->magic = PGRETIRE_MAGIC;
	pgr_info->mode = pgretire_mode;
	pgr_info->length = PGRETIRE_BUF_LENS(retire_nums);
	pgr_info->counts = retire_nums;

	for (i = 0; i < pgr_info->counts; i++) {
		pgr_info->addrs[i].hbm_id   = retire_info[i].hbm_num;
		pgr_info->addrs[i].sys_id   = retire_info[i].sys_num;
		pgr_info->addrs[i].chl_id   = retire_info[i].pmc_num;
		pgr_info->addrs[i].ecc_type = retire_info[i].ecc_type;
		pgr_info->addrs[i].llc_addr = retire_info[i].ecc_addr;

		cn_dev_core_debug(core, "Read %d pgr_info: hbm_id:%d, sys_id:%d, chl_id:%d, type:%d, addr:%#x", i,
						  pgr_info->addrs[i].hbm_id,
						  pgr_info->addrs[i].sys_id,
						  pgr_info->addrs[i].chl_id,
						  pgr_info->addrs[i].ecc_type,
						  pgr_info->addrs[i].llc_addr);
	}

	return 0;
}

void camb_parse_pgretire_status(struct cn_mm_set *mm_set, void *seqfile)
{
	struct seq_file *m = (struct seq_file *)seqfile;
	int status = atomic_read(&mm_set->pgretire_status);

	if (!mm_set->pgretire_enable) {
		MEMTOOLS_PROC_LOG(m, "PageRetire is not support");
		return;
	}

	MEMTOOLS_PROC_LOG(m, " PageRetire Infomation:(After Driver Load)");
	MEMTOOLS_PROC_LOG(m, "\t IRQ Mode PageRetire Counts(function called times): %d",
				   mm_set->pgretire_counts);

	if (mm_set->pgretire_counts) {
		if (mm_set->pgretire_ret)
			MEMTOOLS_PROC_LOG(m, "\t Result: FAILURE(%d): ecc error is uncorrectable, "
						   "need driver reload", mm_set->pgretire_ret);
		else
			MEMTOOLS_PROC_LOG(m, "\t Result: SUCCEED: reload driver when you want");

	} else {
		if (mm_set->pgretire_ret)
			MEMTOOLS_PROC_LOG(m, "\t Result: FAILURE(%d): unretireable ecc error is hanppened in driver init, "
						   "current board is not reliable", mm_set->pgretire_ret);
		else
			MEMTOOLS_PROC_LOG(m, "\t Result: NULL: No pageretire happened!");
	}

	switch (status) {
	case PGRETIRE_IDLE:
		MEMTOOLS_PROC_LOG(m, "\t Status: IDLE");
		break;
	case PGRETIRE_PENDING:
		MEMTOOLS_PROC_LOG(m, "\t Status: PENDING");
		break;
	case PGRETIRE_RUNNING:
		MEMTOOLS_PROC_LOG(m, "\t Status: RUNNING");
		break;
	default:
		MEMTOOLS_PROC_LOG(m, "\t Status: invalid(%d)",
				   atomic_read(&mm_set->pgretire_status));
		break;
	}
}

int camb_init_page_retirement(struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = mm_set->core;

	if (!mm_set->pgretire_enable)
		return 0;

	atomic_set(&mm_set->pgretire_status, PGRETIRE_IDLE);
	atomic_set(&mm_set->pgretire_again, 0);
	mm_set->pgretire_counts = 0;
	mm_set->pgretire_ret = 0;

	mm_set->pgretire_buf =
		cn_shm_get_host_addr_by_name(core, "pgretire_reserved");

	if (mm_set->pgretire_buf == (host_addr_t)-1) {
		cn_dev_core_err(core, "don't found pgretire_reserved in shm reserved!");
		return -EINVAL;
	}

	/* NOTE: need init pgretire_buf reserved memory, avoid old data save in
	 * retire_buf */
	if (core->board_info.platform == MLU_PLAT_ASIC)
		memset_io((void *)mm_set->pgretire_buf, 0x0, PGRETIRE_SHM_REV_SZ);

	return camb_do_page_retirement(mm_set, PGRETIRE_INIT_MODE);
}

unsigned int camb_set_pgretire_status(struct cn_mm_set *mm_set)
{
	if (!mm_set->pgretire_enable)
		return PGRETIRE_DISABLE;

	/* only pgretire_status is pending, we can change it to RUNNING */
	if (atomic_cmpxchg(&mm_set->pgretire_status, PGRETIRE_PENDING,
					   PGRETIRE_RUNNING) == PGRETIRE_PENDING) {
		return PGRETIRE_ENABLE;
	}

	return PGRETIRE_DISABLE;
}

void camb_get_pgretire_result(struct cn_mm_set *mm_set, unsigned int flags,
					int retval)
{
	if (!mm_set->pgretire_enable || flags != PGRETIRE_ENABLE)
		return;

	atomic_cmpxchg(&mm_set->pgretire_status, PGRETIRE_RUNNING, PGRETIRE_IDLE);

	if (retval) {
		mm_set->pgretire_ret = retval;
		camb_parse_pgretire_status(mm_set, NULL);
	}

	if (atomic_read(&mm_set->pgretire_again) != 0)
		camb_do_page_retirement(mm_set, PGRETIRE_IRQ_MODE);
}

/* NOTE: only support called in irq bottom half */
int cn_mem_pageretire_handle(void *pcore)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;
	int ret = 0;

	if (!mm_set->pgretire_enable)
		return 0;

	camb_fa_mask_chunks(mm_set->fa_array);
	atomic_inc(&mm_set->pgretire_again);

	/* if PGRETIRE is PENDING or RUNNING, do not do pageretirement */
	if (atomic_read(&mm_set->pgretire_status) == PGRETIRE_IDLE) {
		ret = camb_do_page_retirement(mm_set, PGRETIRE_IRQ_MODE);
	} else {
		ret = -EBUSY;
	}

	if (!ret) camb_mem_trigger_pgretire_rpc(mm_set);

	return ret;
}

int cn_mem_pgr_get_pages(void *pcore, int ecc_type, uint32_t *counts,
				uint64_t *pages)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	struct ret_msg remsg;
	struct mem_dbg_t dbg;
	size_t result_len = sizeof(struct ret_msg);
	size_t input_len = sizeof(struct mem_dbg_t);
	int ret = 0;

	struct pgretire_dbg_t *pgr_dbg = NULL;

	if (!mm_set->pgretire_enable) {
		*counts = 0;
		return 0;
	}

	if (!cn_core_is_vf(core) && cn_is_mim_en(core)) {
		return -EACCES;
	}

	dbg.cmd = MEM_DBG_PGR_GETPAGES;
	dbg.ecc_type = ecc_type;
	memset(&remsg, 0x00, sizeof(struct ret_msg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_debug", &dbg, input_len,
						 &remsg, &result_len, sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client query mem failed.");
		return ret;
	}

	if (remsg.ret) {
		cn_dev_core_err(core, "rpc_mem_debugfs error status is %d", remsg.ret);
		return remsg.ret;
	}

	/* get data from share memory buffer */
	pgr_dbg = (struct pgretire_dbg_t *)(mm_set->pgretire_buf + PGRETIRE_DBG_OFS);
	if ((pgr_dbg->magic == PGRETIRE_MAGIC) && (pgr_dbg->ecc_type == ecc_type) &&
		(pgr_dbg->length == sizeof(struct pgretire_dbg_t))) {

		*counts = pgr_dbg->counts;
		memcpy(pages, pgr_dbg->pages, sizeof(uint64_t) * pgr_dbg->counts);
	}

	memset_io(pgr_dbg, 0x0, pgr_dbg->length);
	return 0;
}

int cn_mem_pgr_get_status(void *pcore, int *is_pending, int *error_status)
{
	struct cn_core_set *core = pcore;
	struct cn_mm_set *mm_set = core->mm_set;

	if (!mm_set)
		return -EINVAL;

	if (!mm_set->pgretire_enable) {
		*is_pending = 0;
		*error_status = 0;
		return 0;
	}

	if (atomic_read(&mm_set->pgretire_status) == PGRETIRE_IDLE)
		*is_pending = 0;
	else
		*is_pending = 1;

	*error_status = !!(mm_set->pgretire_ret);

	return 0;
}

int camb_get_pgretire_init_result(struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct ret_msg remsg;
	struct mem_dbg_t dbg;
	size_t result_len = sizeof(struct ret_msg);
	size_t input_len = sizeof(struct mem_dbg_t);
	int ret = 0;

	if (!mm_set->pgretire_enable)
		return 0;

	dbg.cmd = MEM_DBG_PGR_GETRET;
	memset(&remsg, 0x00, sizeof(struct ret_msg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_debug", &dbg, input_len,
						 &remsg, &result_len, sizeof(struct ret_msg));
	if (ret < 0) {
		cn_dev_core_err(core, "cnrpc client query mem failed.");
		return ret;
	}

	mm_set->pgretire_ret = remsg.ret;
	return 0;
}

