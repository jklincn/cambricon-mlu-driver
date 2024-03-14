#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/platform_device.h>
#include <linux/timer.h>
#include <linux/pid_namespace.h>
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_smlu.h"
#include "cndrv_mcu.h"
#include "cndrv_mcc.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_debug.h"
#include "cndev_server.h"

static int cndev_device_info(struct cn_cndev_set *cndev_set,
	struct cndev_card_info *card_info, u16 vcard)
{
	/* fill basic info */
	memcpy(card_info, &cndev_set->card_static_info, sizeof(struct cndev_card_info));

	return 0;
}

static int cndev_vdevice_info(struct cn_cndev_set *cndev_set,
	struct cndev_card_info *card_info, u16 vcard)
{
	int ret = 0;
	struct board_info_s brdinfo_rmt;

	/* init buffer */
	memset(card_info, 0x00, sizeof(struct cndev_card_info));
	memset(&brdinfo_rmt, 0x00, sizeof(struct board_info_s));

	/* fill basic info */
	memcpy(card_info, &cndev_set->card_static_info, sizeof(struct cndev_card_info));

	/* get vcard info */
	ret = cndev_rpc_dev_info(cndev_set, &brdinfo_rmt, vcard);

	/* fill vcard info */
	card_info->ipu_cluster = brdinfo_rmt.ipu_cluster;
	card_info->ipu_core = brdinfo_rmt.ipu_core;
	card_info->bandwidth = brdinfo_rmt.ddr_bandwidth;
	card_info->bandwidth_decimal = brdinfo_rmt.ddr_bandwidth_decimal;
	card_info->data_width = brdinfo_rmt.ddr_bus_width;
	memcpy(card_info->uuid, brdinfo_rmt.uuid, CNDRV_UUID_SIZE);
	card_info->card_sn = brdinfo_rmt.sn;

	return ret;
}

int cndev_card_info(struct cn_cndev_set *cndev_set,
	unsigned long arg, struct cndev_head *arg_head)
{
	int ret = 0;
	u16 vcard = 0;
	u32 cpsize = sizeof(struct cndev_card_info);
	struct cndev_card_info card_info;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	cn_dev_cndev_debug(cndev_set, "read card info");

	cpsize = (cpsize > arg_head->buf_size) ? arg_head->buf_size : cpsize;

	vcard = (arg_head->card >> 8) & 0x0f;
	if (!vcard || (cndev_set->quirks & CNDEV_QUIRK_PF_ONLY))
		ret = cndev_device_info(cndev_set, &card_info, 0);
	else if (cn_is_smlu_en(cndev_set->core)) {
		ret = cndev_device_info(cndev_set, &card_info, 0);
		card_info.uuid[9] = vcard;
	}
	else
		ret = cndev_vdevice_info(cndev_set, &card_info, vcard);

	/* copy to user */
	ret |= cndev_cp_to_usr(arg, &card_info, cpsize);

	return ret;
}

void cndev_card_info_fill(struct cn_cndev_set *cndev_set)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_info_fill)) {
		return;
	}
	return cndev_set->ioctl->card_info_fill(cndev_set);
}

int cndev_card_power_info(struct cn_cndev_set *cndev_set,
				struct cndev_power_info *power_info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_power_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_power_info(cndev_set, power_info);
}

int cndev_card_memory_info(void *core_set,
				struct cndev_memory_info *mem_info)
{
	struct cn_core_set *core = (struct cn_core_set *)core_set;
	struct cn_cndev_set *cndev_set = NULL;

	if (IS_ERR_OR_NULL(core)) {
		cn_dev_err("core set is null");
		return -EINVAL;
	}
	cndev_set = (struct cn_cndev_set *)core->cndev_set;
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev_set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_memory_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_memory_info(cndev_set, mem_info);
}

int cndev_user_proc_info(struct cn_cndev_set *cndev_set,
				struct cndev_proc_info *proc_info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->user_proc_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->user_proc_info(cndev_set, proc_info);
}

//TODO
int cndev_card_health_state(struct cn_cndev_set *cndev_set,
				struct cndev_health_state *hstate)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_health_state)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_health_state(cndev_set, hstate);
}

int cndev_card_ecc_info(struct cn_cndev_set *cndev_set,
				struct cndev_ecc_info *einfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ecc_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ecc_info(cndev_set, einfo);

}

int cndev_card_vm_info(struct cn_cndev_set *cndev_set,
				struct cndev_vm_info *vinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_vm_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_vm_info(cndev_set, vinfo);
}

int cndev_card_ipuutil_info(struct cn_cndev_set *cndev_set,
				struct cndev_ipuutil_info *util_info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ipuutil_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ipuutil_info(cndev_set, util_info);

}

int cndev_card_acpuutil_info(struct cn_cndev_set *cndev_set,
				struct cndev_acpuutil_info *util_info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_acpuutil_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_acpuutil_info(cndev_set, util_info);

}

int cndev_card_acpuutil_timer(struct cn_cndev_set *cndev_set,
				struct cndev_acpuutil_timer *timer)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_acpuutil_timer)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_acpuutil_timer(cndev_set, timer);
}

int cndev_card_codecutil_info(struct cn_cndev_set *cndev_set,
				struct cndev_codecutil_info *uinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_codecutil_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_codecutil_info(cndev_set, uinfo);
}

int cndev_card_freq_info(struct cn_cndev_set *cndev_set,
				struct cndev_freq_info *freq_info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_freq_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_freq_info(cndev_set, freq_info);
}

int cndev_card_curbuslnk(struct cn_cndev_set *cndev_set,
				struct cndev_curbuslnk_info *linfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_curbuslnk)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_curbuslnk(cndev_set, linfo);
}

int cndev_card_pciethroughput(struct cn_cndev_set *cndev_set,
				struct cndev_pcie_throughput *tpinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_pciethroughput)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_pciethroughput(cndev_set, tpinfo);
}

int cndev_power_capping(struct cn_cndev_set *cndev_set,
				struct cndev_powercapping_s *pcinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_power_capping)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_power_capping(cndev_set, pcinfo);
}

int cndev_ipufreq_set(struct cn_cndev_set *cndev_set,
				struct cndev_ipufreq_set *setinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ipufreq_set)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ipufreq_set(cndev_set, setinfo);
}

int cndev_ioctl_attribute(struct cn_cndev_set *cndev_set,
				struct cndev_ioctl_attr *attrinfo)
{
	int i = 0;
	ioctls *pioctl = NULL;
	__u8 *ioctl_attr_buf = NULL;
	int real_count = 0;
	int pioctl_count = 0;
	int ret = 0;

	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}

	pioctl_count = sizeof(struct cn_cndev_ioctl) / sizeof(ioctls);

	pioctl = cn_kzalloc((pioctl_count * sizeof(ioctls)), GFP_KERNEL);
	if (!pioctl) {
		return -ENOMEM;
	}

	ioctl_attr_buf = cn_kzalloc(sizeof(__u8) * pioctl_count, GFP_KERNEL);
	if (!ioctl_attr_buf) {
		ret = -ENOMEM;
		goto err_1;
	}

	memcpy(pioctl, cndev_set->ioctl, sizeof(ioctls) * pioctl_count);

	for (i = 0; i < pioctl_count; i++) {
		ioctl_attr_buf[i] = IS_ERR_OR_NULL(pioctl[i]) ?
			ATTR_DISABLE : ATTR_ENABLE;
	}

	real_count = (pioctl_count < attrinfo->attr_num)
		? pioctl_count : attrinfo->attr_num;

	attrinfo->attr_num = pioctl_count;
	if (attrinfo->ioctl_attr) {
		ret = cndev_cp_to_usr(attrinfo->ioctl_attr, ioctl_attr_buf,
			real_count * sizeof(__u8));
	}

	cn_kfree(ioctl_attr_buf);

	cn_kfree(pioctl);

	return ret;

err_1:
	cn_kfree(pioctl);

	return ret;
}

int cndev_get_ncs_version(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_version *verinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ncs_version)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ncs_version(cndev_set, verinfo);
}

int cndev_get_ncs_state(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_state_info *stinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ncs_state)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ncs_state(cndev_set, stinfo);
}

int cndev_get_ncs_speed(struct cn_cndev_set *cndev_set,
							struct cndev_NCS_speed_info *stinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ncs_speed)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ncs_speed(cndev_set, stinfo);
}

int cndev_get_ncs_capability(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_capability *capinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ncs_capability)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ncs_capability(cndev_set, capinfo);
}

int cndev_get_ncs_counter(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_counter *cntrinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ncs_counter)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ncs_counter(cndev_set, cntrinfo);
}

int cndev_get_ncs_remote(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_remote_info *rmtinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ncs_remote)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ncs_remote(cndev_set, rmtinfo);
}

int cndev_reset_ncs_counter(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_reset_counter *rstinfo)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_reset_ncs_counter)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_reset_ncs_counter(cndev_set, rstinfo);
}

int cndev_chassis_info_fill(struct cn_cndev_set *cndev_set,
				struct cndev_chassis_info *chassis_info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_chassis_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_chassis_info(cndev_set, chassis_info);
}

int cndev_reset_qos(struct cn_cndev_set *cndev_set)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_qos_reset)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_qos_reset(cndev_set);
}

int cndev_qos_operation(struct cn_cndev_set *cndev_set, struct cndev_qos_info *qos_info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_qos_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_qos_info(cndev_set, qos_info);
}

int cndev_qos_desc(struct cn_cndev_set *cndev_set,
				struct cndev_qos_detail *qos_desc)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_qos_desc)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_qos_desc(cndev_set, qos_desc);
}

int cndev_set_qos_param(struct cn_cndev_set *cndev_set,
	struct cndev_qos_param *qos_info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_set_qos)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_set_qos(cndev_set, qos_info);
}

int cndev_set_qos_group_param(struct cn_cndev_set *cndev_set,
	struct cndev_qos_group_param *qos_info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_set_qos_group)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_set_qos_group(cndev_set, qos_info);
}


int cndev_get_retire_pages(struct cn_cndev_set *cndev_set,
	struct cndev_retire_page *retire_pages)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_retire_pages)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_retire_pages(cndev_set, retire_pages);
}

int cndev_get_retire_status(struct cn_cndev_set *cndev_set,
	struct cndev_retire_status *retire_status)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_retire_status)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_retire_status(cndev_set, retire_status);
}

int cndev_get_retire_remapped_rows(struct cn_cndev_set *cndev_set,
	struct cndev_retire_remapped_rows *retire_remapped_rows)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_retire_remapped_rows)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_retire_remapped_rows(cndev_set, retire_remapped_rows);
}

int cndev_retire_switch(struct cn_cndev_set *cndev_set,
	struct cndev_retire_op *retire_op)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_retire_switch)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_retire_switch(cndev_set, retire_op);
}

int cndev_ncs_port_config(struct cn_cndev_set *cndev_set,
				struct cndev_NCS_config *port_config)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ncs_port_config)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ncs_port_config(cndev_set, port_config);
}

int cndev_ncs_mlulink_switch_ctrl(struct cn_cndev_set *cndev_set,
				struct cndev_mlulink_switch_ctrl *mlulink_switch_ctrl)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_mlulink_switch_ctrl)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_mlulink_switch_ctrl(cndev_set, mlulink_switch_ctrl);
}

int cndev_ipu_freq_ctrl(struct cn_cndev_set *cndev_set,
	struct cndev_ipufreq_ctrl *ipufreq_ctrl)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_ipufreq_ctrl)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_ipufreq_ctrl(cndev_set, ipufreq_ctrl);
}

int cndev_get_ncs_info(struct cn_cndev_set *cndev_set,
	struct cndev_ncs_info *ncs_info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_ncs_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_ncs_info(cndev_set, ncs_info);
}

int cndev_get_card_info_ext(struct cn_cndev_set *cndev_set,
				struct cndev_card_info_ext *card_info_ext)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_card_info_ext)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_card_info_ext(cndev_set, card_info_ext);
}

int cndev_get_process_util(struct cn_cndev_set *cndev_set,
				struct cndev_process_ipuutil_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_process_iputil)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_process_iputil(cndev_set, info);
}

int cndev_get_process_codecutil(struct cn_cndev_set *cndev_set,
	struct cndev_process_codecutil_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_process_codecutil)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_process_codecutil(cndev_set, info);
}

int cndev_get_feature(struct cn_cndev_set *cndev_set,
	struct cndev_feature *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_feature)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_feature(cndev_set, info);
}

int cndev_set_feature(struct cn_cndev_set *cndev_set,
	struct cndev_feature *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_set_feature)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_set_feature(cndev_set, info);
}

int cndev_get_qos_conf(void *core_set, void **qos_conf)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)core_set;
	struct cn_cndev_set *cndev_set = NULL;

	if (IS_ERR_OR_NULL(core) || IS_ERR_OR_NULL(qos_conf))
		return -EINVAL;

	if (IS_ERR_OR_NULL(core->cndev_set))
		return -EINVAL;

 	cndev_set = (struct cn_cndev_set *)core->cndev_set;

	*qos_conf = &cndev_set->qos_conf;

	return ret;
}

int cndev_get_mim_profile_info(struct cn_cndev_set *cndev_set,
	struct cndev_mim_profile_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_mim_profile_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_mim_profile_info(cndev_set, info);
}

int cndev_get_mim_possible_place_info(struct cn_cndev_set *cndev_set,
	struct cndev_mim_possible_place_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_mim_possible_place_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_mim_possible_place_info(cndev_set, info);
}

int cndev_card_get_mim_vmlu_capacity_info(struct cn_cndev_set *cndev_set,
	struct cndev_mim_vmlu_capacity_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_mim_vmlu_capacity_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_mim_vmlu_capacity_info(cndev_set, info);
}

int cndev_card_get_mim_device_info(struct cn_cndev_set *cndev_set,
	struct cndev_mim_device_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_mim_device_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_mim_device_info(cndev_set, info);
}

int cndev_card_get_desc_info(struct cn_cndev_set *cndev_set,
	struct cndev_mi_card *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_desc_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_desc_info(cndev_set, info);
}

int cndev_card_get_cntr_info(struct cn_cndev_set *cndev_set,
	struct cndev_cntr_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_cntr_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_cntr_info(cndev_set, info);
}

int cndev_chassis_power_info_fill(struct cn_cndev_set *cndev_set,
		struct cndev_chassis_power_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->chassis_power_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->chassis_power_info(cndev_set, info);
}

/* smlu cap */
int cndev_get_smlu_profile_id(struct cn_cndev_set *cndev_set,
	struct cndev_smlu_profile_id *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_smlu_profile_id)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_smlu_profile_id(cndev_set, info);
}

int cndev_get_smlu_profile_info(struct cn_cndev_set *cndev_set,
	struct cndev_smlu_profile_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_get_smlu_profile_info)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_get_smlu_profile_info(cndev_set, info);
}

int cndev_new_smlu_profile(struct cn_cndev_set *cndev_set,
	struct cndev_smlu_profile_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_new_smlu_profile)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_new_smlu_profile(cndev_set, info);
}

int cndev_delete_smlu_profile(struct cn_cndev_set *cndev_set,
	struct cndev_smlu_profile_info *info)
{
	if (IS_ERR_OR_NULL(cndev_set)) {
		cn_dev_err("cndev set is null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl)) {
		cn_dev_err("cndev ioctl null");
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(cndev_set->ioctl->card_delete_smlu_profile)) {
		return -EINVAL;
	}
	return cndev_set->ioctl->card_delete_smlu_profile(cndev_set, info);
}
