#include <linux/seq_file.h>
#include "cndrv_gdma.h"
#include "cndrv_commu.h"
#include "cndrv_ipcm.h"
#include "cndrv_core.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif
#include "gdma_rpc.h"
#include "gdma_api.h"
#include "gdma_common.h"
#include "ce_gdma_api.h"
#include "gdma_common_api.h"

static int cn_gdma_set_value(struct cn_core_set *core, int set_assist_id, void *value)
{
	int ret = 0;
	struct cn_gdma_super_set *gdma_su_set = core->gdma_set;
	struct cn_gdma_set *gdma_set = gdma_su_set->host_gdma;

	switch (set_assist_id) {
	case GDMA_ASSIST_SET_DEBUG_PRINT:
		gdma_set->debug_print = *(u8 *)value;
		break;
	case GDMA_ASSIST_SET_INJECT_ERROR_SRC:
		gdma_set->inject_error_src = *(u64 *)value;
		break;
	case GDMA_ASSIST_SET_INJECT_ECC_ERROR:
		gdma_set->inject_ecc_error = *(u8 *)value;
		break;
	case GDMA_ASSIST_SET_POLL_SIZE:
		gdma_set->poll_size = *(u32 *)value;
		break;
	default:
		ret = -1;
		break;
	}

	return ret;
}

static int cn_gdma_get_value(struct cn_core_set *core, int get_assist_id, void *value)
{
	int ret = 0;
	struct cn_gdma_super_set *gdma_su_set = core->gdma_set;
	struct cn_gdma_set *gdma_set = gdma_su_set->host_gdma;

	switch (get_assist_id) {
	case GDMA_ASSIST_GET_DEBUG_PRINT:
		*(u8 *)value = gdma_set->debug_print;
		break;
	case GDMA_ASSIST_GET_INJECT_ERROR_SRC:
		*(u64 *)value = gdma_set->inject_error_src;
		break;
	case GDMA_ASSIST_GET_INJECT_ECC_ERROR:
		*(u8 *)value = gdma_set->inject_ecc_error;
		break;
	case GDMA_ASSIST_GET_POLL_SIZE:
		*(u32 *)value = gdma_set->poll_size;
		break;
	case GDMA_ASSIST_GET_INFO_CTRL_NUM:
		*(u32 *)value = gdma_set->info->ctrl_num;
		break;
	case GDMA_ASSIST_GET_INFO_CTRL_CHAN_NUM:
		*(u32 *)value = gdma_set->info->ctrl_chan_num;
		break;
	default:
		ret = -1;
		break;
	}

	return ret;
}

static int cn_gdma_channel_ecc_inject(struct cn_core_set *core)
{
	int ret = 0;
	int i = 0;
	struct cn_gdma_super_set *gdma_su_set = core->gdma_set;
	struct cn_gdma_set *gdma_set = gdma_su_set->host_gdma;
	struct cn_gdma_phy_chan *pchan = NULL;

	for (i = 0; i < gdma_set->total_pchan_num; i++) {
		pchan = gdma_set->pchan_pool[i];
		pchan->ctrl->ops->channel_ecc_inject(pchan, gdma_set->inject_ecc_error);
	}

	return ret;
}

static int cn_gdma_ctrl_reg_dump(struct cn_core_set *core, int ctrl_index)
{
	int ret = 0;
	struct cn_gdma_controller *ctrl = NULL;
	struct cn_gdma_super_set *gdma_su_set = core->gdma_set;
	struct cn_gdma_set *gdma_set = gdma_su_set->host_gdma;

	ctrl = gdma_set->ctrl_pool[ctrl_index];
	ctrl->ops->ctrl_reg_dump(ctrl);

	return ret;
}

static int cn_gdma_channel_reg_dump(struct cn_core_set *core, int chnl_index)
{
	int ret = 0;
	struct cn_gdma_controller *ctrl = NULL;
	struct cn_gdma_phy_chan *chan = NULL;
	struct cn_gdma_super_set *gdma_su_set = core->gdma_set;
	struct cn_gdma_set *gdma_set = gdma_su_set->host_gdma;

	/***
	 * chnl_index
	 * Bit15~8   controller_id
	 * Bit7~0    channel_id in the controller
	 */
	ctrl = gdma_set->ctrl_pool[((chnl_index >> 8) & 0xFF)];
	chan = ctrl->pchans[(chnl_index & 0xFF)];
	ctrl->ops->channel_reg_dump(chan);

	return ret;
}

static int cn_gdma_get_stat_info(struct cn_core_set *core, struct seq_file *m)
{
	int i, j;
	struct cn_gdma_super_set *gdma_su_set = core->gdma_set;
	struct cn_gdma_set *gdma_set = gdma_su_set->host_gdma;
	struct cn_gdma_task *task;
	struct cn_gdma_virt_chan *vchan;
	struct cn_gdma_phy_chan *pchan;
	u32 task_num = 0;
	u32 priv_vchan_num = 0;
	u32 shared_vchan_num = 0;
	u32 pchan_num = 0;

	for (i = 0; i < gdma_set->task_num; i++) {
		task = gdma_set->task_pool[i];
		if (task->status != GDMA_TASK_IDLE)
			task_num++;
	}

	for (i = 0; i < gdma_set->task_num; i++) {
		task = gdma_set->task_pool[i];
		for (j = 0; j < task->priv_vchan_num; j++) {
			vchan = task->priv_vchan[j];
			if (vchan->status != GDMA_CHANNEL_IDLE)
				priv_vchan_num++;
		}
	}

	for (i = 0; i < gdma_set->vchan_num; i++) {
		vchan = gdma_set->vchan_pool[i];
		if (vchan->status != GDMA_CHANNEL_IDLE)
			shared_vchan_num++;
	}

	for (i = 0; i < gdma_set->total_pchan_num; i++) {
		pchan = gdma_set->pchan_pool[i];
		if (pchan->status != GDMA_CHANNEL_IDLE)
			pchan_num++;
	}

	seq_printf(m, "gdma task resource status: %d occupied\n",
			task_num);
	seq_printf(m, "gdma priv virtual channel status: %d occupied\n",
			priv_vchan_num);
	seq_printf(m, "gdma share virtual channel status: %d occupied\n",
			shared_vchan_num);
	seq_printf(m, "gdma physical channel status: %d occupied\n",
			pchan_num);

	return 0;
}

/*
 * Assist the caller to do some special handle via uniform API
 *
 * @core: the top core set's pointer
 * @assist_id: Assist ID what action will be called
 * @param_in: the param may be used by action(if not need can be NULL)
 * @result_out: the result that get after the action(if not need can be NULL)
 *
 * Return 0 if success, Others means fail.
 */
int cn_gdma_assist(struct cn_core_set *core, int assist_id, void *param_in, void *result_out)
{
	int ret = 0;

	if (core->gdma_set == NULL) {
		cn_dev_core_info(core, "not support gdma this core");
		return 0;
	}

	switch (assist_id) {
	/*Action*/
	case GDMA_ASSIST_ACT_CHNL_ECC_INJECT:
		ret = cn_gdma_channel_ecc_inject(core);
		break;
	case GDMA_ASSIST_ACT_CTRL_REG_DUMP:
		ret = cn_gdma_ctrl_reg_dump(core, *(int *)param_in);
		break;
	case GDMA_ASSIST_ACT_CHNL_REG_DUMP:
		ret = cn_gdma_channel_reg_dump(core, *(int *)param_in);
		break;
	/*Set*/
	case GDMA_ASSIST_SET_DEBUG_PRINT:
	case GDMA_ASSIST_SET_INJECT_ERROR_SRC:
	case GDMA_ASSIST_SET_INJECT_ECC_ERROR:
	case GDMA_ASSIST_SET_POLL_SIZE:
		ret = cn_gdma_set_value(core, assist_id, param_in);
		break;
	/*Get*/
	case GDMA_ASSIST_GET_DEBUG_PRINT:
	case GDMA_ASSIST_GET_INJECT_ERROR_SRC:
	case GDMA_ASSIST_GET_INJECT_ECC_ERROR:
	case GDMA_ASSIST_GET_POLL_SIZE:
	case GDMA_ASSIST_GET_INFO_CTRL_NUM:
	case GDMA_ASSIST_GET_INFO_CTRL_CHAN_NUM:
		ret = cn_gdma_get_value(core, assist_id, result_out);
		break;
	case GDMA_ASSIST_GET_STAT_INFO:
		ret = cn_gdma_get_stat_info(core, (struct seq_file *)param_in);
		break;
	default:
		cn_dev_core_info(core, "not support this 0x%x assist_id", assist_id);
		break;
	}

	return ret;
}
