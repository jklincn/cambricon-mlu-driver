#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/pid_namespace.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"

#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_qos.h"
#include "qos_inter.h"
#include "cndrv_cndev.h"

int set_qos_group_weight(void *core_set, u8 qos_weight, enum cndev_qos_group group)
{
	u32 reg32 = 0;
	int i = 0;
	struct cndev_qos_desc_info_s *qos = NULL;
	struct cndev_qos_conf_s *qos_conf = NULL;
	struct cn_core_set *core = (struct cn_core_set *)core_set;
	int ret = 0;

	ret = cndev_get_qos_conf(core, (void *)&qos_conf);
	if (ret) {
		return -1;
	}

	if (group >= CNDEV_QOS_MAX) {
		cn_dev_core_err(core, "Invalid QoS group index:%d\n", group);
		return -1;
	}

	qos = &qos_conf->qos[group];

	if (!qos) {
		cn_dev_core_err(core, "Invalid QoS group buffer:%d\n", group);
		return -1;
	}

	if (qos_weight < 3) {
		cn_dev_core_err(core, "Invalid QoS group weight:%d\n", qos_weight);
		return -1;
	}

	for (i = 0; i < qos->cnt; i++) {
		reg32 = reg_read32(core->bus_set, qos->desc[i].reg32);
		reg32 = reg32 & MLU2X0_QOS_WEIGHT_MASK;
		reg32 |= qos_weight;
		reg_write32(core->bus_set, qos->desc[i].reg32, reg32);
	}
	return 0;
}

int set_qos_weight(void *core_set, u8 qos_weight,
	enum cndev_qos_group group, int master)
{
	u32 reg32 = 0;
	struct cndev_qos_desc_info_s *qos = NULL;
	struct cndev_qos_conf_s *qos_conf = NULL;
	struct cn_core_set *core = (struct cn_core_set *)core_set;
	int ret = 0;

	ret = cndev_get_qos_conf(core, (void *)&qos_conf);
	if (ret) {
		return -1;
	}
	qos = &qos_conf->qos[group];

	if (!qos) {
		cn_dev_core_err(core, "Invalid QoS group buffer:%d\n", group);
		return -1;
	}

	if (master >= qos->cnt || master < 0 || qos_weight < 3) {
		cn_dev_core_err(core, "Invalid QoS group:%d, master:%d, qos_weight:%u\n",
			group, master, qos_weight);
		return -1;
	}

	reg32 = reg_read32(core->bus_set, qos->desc[master].reg32);
	reg32 = reg32 & MLU2X0_QOS_WEIGHT_MASK;
	reg32 |= qos_weight;
	reg_write32(core->bus_set, qos->desc[master].reg32, reg32);

	return 0;
}

static void reset_qos_group_weight(void *core_set, u32 group_id)
{
	u32 reg32 = 0;
	int i = 0;
	struct cndev_qos_desc_info_s *qos = NULL;
	u32 qos_group_num = 0;
	struct cndev_qos_conf_s *qos_conf = NULL;
	struct cn_core_set *core = (struct cn_core_set *)core_set;
	int ret = 0;

	ret = cndev_get_qos_conf(core, (void *)&qos_conf);
	if (ret) {
		return;
	}
	if (!qos_conf->qos_setting) {
		cn_dev_core_err(core, "Invalid QoS setting");
		return;
	}

	qos_group_num = qos_conf->qos_setting->qos_group_count;

	if (group_id >= qos_group_num) {
		cn_dev_core_err(core, "Invalid QoS group id.");
		return;
	}

	qos = &qos_conf->qos[group_id];

	if (!qos) {
		cn_dev_core_err(core, "Invalid QoS group.");
		return;
	}

	for (i = 0; i < qos->cnt; i++) {
		reg32 = reg_read32(core->bus_set, qos->desc[i].reg32);
		reg32 = reg32 & MLU2X0_QOS_WEIGHT_MASK;
		reg32 |= qos->desc[i].default_value;
		reg_write32(core->bus_set, qos->desc[i].reg32, reg32);
	}
}

static void reset_qos_weight(void *core_set)
{
	u32 reg32 = 0;
	int i = 0, j = 0;
	struct cndev_qos_desc_info_s *qos = NULL;
	u32 qos_group_num = 0;
	struct cndev_qos_conf_s *qos_conf = NULL;
	struct cn_core_set *core = (struct cn_core_set *)core_set;
	int ret = 0;

	ret = cndev_get_qos_conf(core, (void *)&qos_conf);
	if (ret) {
		return;
	}
	if (!qos_conf->qos_setting) {
		cn_dev_core_err(core, "Invalid QoS setting");
		return;
	}
	if (!qos_conf->qos_setting) {
		cn_dev_core_err(core, "Invalid QoS setting");
		return;
	}

	qos_group_num = qos_conf->qos_setting->qos_group_count;

	for (j = 0; j < qos_group_num; j++) {
		qos = &qos_conf->qos[j];

		if (!qos)
			continue;

		for (i = 0; i < qos->cnt; i++) {
			reg32 = reg_read32(core->bus_set, qos->desc[i].reg32);
			reg32 = reg32 & MLU2X0_QOS_WEIGHT_MASK;
			reg32 |= qos->desc[i].default_value;
			reg_write32(core->bus_set, qos->desc[i].reg32, reg32);
		}
	}
}

static int set_qos_policy(void *core_set, struct cndev_qos_policy *qos_info)
{
	u8 base = qos_info->qos_base;
	u8 up = qos_info->qos_up;
	u8 qos_weight = 0;
	u32 policy = qos_info->qos_policy;
	int ret = 0;
	struct cndev_qos_conf_s *qos_conf = NULL;
	struct cn_core_set *core = (struct cn_core_set *)core_set;

	ret = cndev_get_qos_conf(core, (void *)&qos_conf);
	if (ret) {
		return -EINVAL;
	}

	if (!qos_conf->qos_setting) {
		cn_dev_core_err(core, "Invalid QoS setting");
		return -EINVAL;
	}

	if (qos_info->group_id >= qos_conf->qos_setting->qos_group_count) {
		cn_dev_core_err(core, "Invalid group %u\n", qos_info->group_id);
		return -EINVAL;
	}

	if (!policy) {
		reset_qos_group_weight(core, qos_info->group_id);
		return 0;
	}

	if (policy >= 10) {
		cn_dev_core_err(core, "Invalid policy %u\n", policy);
		return -EINVAL;
	}

	if (base > qos_conf->qos_setting->max_qos_base ||
		base < qos_conf->qos_setting->min_qos_base) {
		cn_dev_core_err(core, "Invalid qos base\n");
		return -EINVAL;
	}

	if (up > qos_conf->qos_setting->max_qos_up ||
		up < qos_conf->qos_setting->min_qos_up) {
		cn_dev_core_err(core, "Invalid qos up\n");
		return -EINVAL;
	}

	qos_weight = (policy) * base * up;
	ret = set_qos_group_weight(core, qos_weight, qos_info->group_id);

	return ret;
}

int noc_qos_policy_common(void *core_set, struct cndev_qos_policy *qos_info)
{
	int ret = 0;

	if (IS_ERR_OR_NULL(core_set) || IS_ERR_OR_NULL(qos_info))
		return -EINVAL;

	ret = set_qos_policy(core_set, qos_info);

	return ret;
}

int noc_qos_desc_common(void *core_set, struct cndev_qos_detail_info *qos_detail)
{
	int ret = 0;
	int cnt = 0;
	u32 reg32 = 0;
	int i = 0, j = 0, k = 0;
	int copy_length = 0;
	struct cndev_qos_desc *temp_buf = NULL;
	struct cndev_qos_desc_info_s *qos = NULL;
	struct cndev_qos_conf_s *qos_conf = NULL;
	struct cn_core_set *core = (struct cn_core_set *)core_set;

	if (IS_ERR_OR_NULL(core) || IS_ERR_OR_NULL(qos_detail))
		return -EINVAL;
	ret = cndev_get_qos_conf(core, (void *)&qos_conf);
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

	if (!qos_conf->qos_setting) {
		cn_dev_core_err(core, "Invalid QoS setting");
		ret = -EINVAL;
		goto out;
	}
	for (i = 0; i < qos_conf->qos_setting->qos_group_count; i++) {
		cnt += qos_conf->qos[i].cnt;
	}

	temp_buf = cn_kzalloc((cnt) * sizeof(struct cndev_qos_desc), GFP_KERNEL);
	if (!temp_buf) {
		cn_dev_core_err(core, "alloc buf fail\n");
		ret = -ENOMEM;
		goto out;
	}

	for (j = 0; j < qos_conf->qos_setting->qos_group_count; j++) {
		qos = &qos_conf->qos[j];
		if (!qos) {
			continue;
		}

		for (i = 0; i < qos->cnt; i++) {
			reg32 = reg_read32(core->bus_set, qos->desc[i].reg32);
			temp_buf[k].qos_value.qos_weight = reg32 & (~MLU2X0_QOS_WEIGHT_MASK);
			temp_buf[k].qos_group = j;
			memcpy(temp_buf[k].qos_name, qos->desc[i].name, QOS_NAME_LEN);
			k++;
		}
	}

	copy_length =
		(qos_detail->qos_desc_num < cnt)
		? qos_detail->qos_desc_num : cnt;

	qos_detail->qos_desc_num = cnt;
	if (qos_detail->desc) {
		ret = cndev_cp_to_usr(qos_detail->desc, temp_buf,
			copy_length * sizeof(struct cndev_qos_desc));
	}

	cn_kfree(temp_buf);
	return 0;

out:
	return ret;
}

int set_qos_bandwidth(void *core_set, u16 bandwidth, enum cndev_qos_group group, u32 master)
{
	u32 reg32 = 0;
	int i = 0;
	struct cndev_qos_desc_info_s *qos = NULL;
	int ret = 0;
	struct cndev_qos_conf_s *qos_conf = NULL;
	struct cn_core_set *core = (struct cn_core_set *)core_set;

	ret = cndev_get_qos_conf(core, (void *)&qos_conf);
	if (ret) {
		return -EINVAL;
	}
	if (group >= CNDEV_QOS_MAX) {
		cn_dev_core_err(core, "Invalid QoS group index:%d\n", group);
		return EINVAL;
	}

	qos = &qos_conf->qos[group];

	if (!qos) {
		cn_dev_core_err(core, "Invalid QoS group buffer:%d\n", group);
		return -EINVAL;
	}

	if (bandwidth > qos->desc[i].max_value) {
		cn_dev_core_err(core, "Invalid QoS Bandwidth Setting:%hu\n", bandwidth);
		return -EINVAL;
	}


	if (master >= qos->cnt) {
		cn_dev_core_err(core, "Invalid QoS group:%d, master:%d\n",
			group, master);
		return -EINVAL;
	}

	reg32 = bandwidth & 0x1fff;
	reg_write32(core->bus_set, qos->desc[master].reg32, reg32);

	return 0;
}

int set_qos_group_bandwidth(void *core_set, u16 bandwidth, enum cndev_qos_group group)
{
	u32 reg32 = 0;
	int i = 0;
	struct cndev_qos_desc_info_s *qos = NULL;
	int ret = 0;
	struct cndev_qos_conf_s *qos_conf = NULL;
	struct cn_core_set *core = (struct cn_core_set *)core_set;

	ret = cndev_get_qos_conf(core, (void *)&qos_conf);
	if (ret) {
		return -EINVAL;
	}

	if (group >= CNDEV_QOS_MAX) {
		cn_dev_core_err(core, "Invalid QoS group index:%d\n", group);
		return EINVAL;
	}

	qos = &qos_conf->qos[group];

	if (!qos) {
		cn_dev_core_err(core, "Invalid QoS group buffer:%d\n", group);
		return -EINVAL;
	}


	if (bandwidth > qos->desc[i].max_value) {
		cn_dev_core_err(core, "Invalid QoS Bandwidth Setting:%hu\n", bandwidth);
		return -EINVAL;
	}

	for (i = 0; i < qos->cnt; i++) {
		reg32 = bandwidth & 0x1fff;
		reg_write32(core->bus_set, qos->desc[i].reg32, reg32);
	}
	return 0;
}

static void reset_qos_bandwidth(void *core_set)
{
	u32 reg32 = 0;
	int i = 0, j = 0;
	struct cndev_qos_desc_info_s *qos = NULL;
	u32 qos_group_num = 0;
	int ret = 0;
	struct cndev_qos_conf_s *qos_conf = NULL;
	struct cn_core_set *core = (struct cn_core_set *)core_set;

	ret = cndev_get_qos_conf(core, (void *)&qos_conf);
	if (ret) {
		return;
	}
	if (!qos_conf->qos_setting) {
		cn_dev_core_err(core, "Invalid QoS setting");
		return;
	}

	qos_group_num = qos_conf->qos_setting->qos_group_count;

	for (j = 0; j < qos_group_num; j++) {
		qos = &qos_conf->qos[j];

		if (!qos)
			continue;

		for (i = 0; i < qos->cnt; i++) {
			reg32 = qos->desc[i].default_value & 0x1fff;
			reg_write32(core->bus_set, qos->desc[i].reg32, reg32);
		}
	}
}

int noc_qos_reset_bandwidth(void *core_set)
{
	if (IS_ERR_OR_NULL(core_set))
		return -EINVAL;

	reset_qos_bandwidth(core_set);

	return 0;
}

int noc_qos_reset_common(void *core_set)
{

	if (IS_ERR_OR_NULL(core_set))
		return -EINVAL;

	reset_qos_weight(core_set);

	return 0;
}

int cndev_qos_info_init(void *core_set,
	struct cndev_qos_data_s *mlu_qos_infos,
	struct cndev_qos_setting_s *qos_setting)
{
	int i = 0;
	struct cndev_qos_data_s *itor = mlu_qos_infos;
	u32 die_cnt = 0;
	struct cndev_qos_conf_s *qos_conf = NULL;
	struct cn_core_set *core = (struct cn_core_set *)core_set;
	int ret = 0;

	ret = cndev_get_qos_conf(core, (void *)&qos_conf);
	if (ret) {
		return -EINVAL;
	}
	if (!mlu_qos_infos || !qos_setting) {
		cn_dev_core_err(core, "Invalid qos configuration.");
		return -EINVAL;
	}

	if (!core->die_cnt || core->die_cnt > 2)
		die_cnt = 1;
	else
		die_cnt = core->die_cnt;

	for (i = 0; i < qos_setting->qos_group_count; i++) {
		qos_conf->qos[i].desc = itor[i].qos_info;
		qos_conf->qos[i].cnt = itor[i].cnt * die_cnt;
	}
	qos_conf->qos_setting = qos_setting;

	return 0;
}

int cndev_qos_init(void *core_set)
{
	struct cn_core_set *core = (struct cn_core_set *)core_set;

	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	switch (core->device_id) {
	case MLUID_220_EDGE:
		cndev_qos_info_init(core, mlu220e_qos_infos, &mlu220e_qos_setting);
		break;
	case MLUID_220:
		cndev_qos_info_init(core, mlu220_qos_infos, &mlu2x0_qos_setting);
		break;
	case MLUID_270:
		cndev_qos_info_init(core, mlu270_qos_infos, &mlu2x0_qos_setting);
		break;
	case MLUID_290:
		cndev_qos_info_init(core, mlu290_qos_infos, &mlu2x0_qos_setting);
		break;
	case MLUID_370:
		cndev_qos_info_init(core, mlu370_qos_infos, &mlu370_qos_setting);
		break;
	case MLUID_CE3226:
		cndev_qos_info_init(core, ce3226_qos_infos, &ce3226_qos_setting);
		break;
	case MLUID_CE3226_EDGE:
		cndev_qos_info_init(core, ce3226_qos_infos, &ce3226_qos_setting);
		break;
	case MLUID_590:
	case MLUID_590V:
	case MLUID_270V:
	case MLUID_270V1:
	case MLUID_290V1:
	case MLUID_370V:
	case MLUID_370_DEV:
	case MLUID_590_DEV:
	case MLUID_PIGEON:
	case MLUID_PIGEON_EDGE:
	case MLUID_580:
	case MLUID_580V:
		break;
	default:
		cndev_qos_info_init(core, NULL, NULL);
		break;
	}

	return 0;
}
