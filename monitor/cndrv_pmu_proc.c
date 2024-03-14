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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#ifdef CONFIG_CNDRV_EDGE
#include <linux/namei.h>
#endif
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mcu.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_debug.h"
#include "./cndev/cndev_server.h"
#include "cndrv_proc.h"

#if defined(CONFIG_CNDRV_CE3226_SOC)
int cndev_qos_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)core->cndev_set;
	int i = 0, j = 0;
	struct cndev_qos_desc_info_s *qos = NULL;
	u32 reg32 = 0;

	seq_printf(m, "\nQoS Description:\n");
	seq_printf(m, "Group\tItems\tBandwidth\tDefault\tQoS-Name\n");
	for (j = 0; j < cndev_set->qos_conf.qos_setting->qos_group_count; j++) {
		qos = &cndev_set->qos_conf.qos[j];
		if (!qos)
			continue;
		for (i = 0; i < qos->cnt; i++) {
			reg32 = reg_read32(cndev_set->core->bus_set, qos->desc[i].reg32);
			seq_printf(m, "%d\t%d\t%-8u\t%hu\t%s\n",
				j,
				i,
				reg32 & 0x1fff,
				qos->desc[i].default_value,
				qos->desc[i].name);
		}
	}

	return 0;
}

ssize_t cndev_qos_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	u16 bandwidth = 0;
	u32 items = 0;
	u32 group = 0;
	char buf[128] = {0};
	char cmd[128] = {0};
	int ret = 0;
	ssize_t buf_size = 0;
	struct cn_core_set *core = (struct cn_core_set *)PDE_DATA(file_inode(file));
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)core->cndev_set;

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_core_info(core, "user command:%s", buf);
	if (strlen(buf)) {
		ret = sscanf(buf, "%s %hu %u %u", cmd, &bandwidth, &group, &items);
		if (!strcmp(cmd, "set_group_bandwidth") && ret == 3) {
			ret = set_qos_group_bandwidth(core, bandwidth, group);
			cn_dev_core_info(core,
				"Set Group Qos bandwidth %s.\n", ret == 0 ? "successfully" : "failed");
			if (!ret)
				goto out;
		} else if (!strcmp(cmd, "reset")) {
			/*reset qos bandwidth*/
			ret = cndev_reset_qos(cndev_set);
			cn_dev_core_info(core,
				"Reset Qos bandwidth %s.\n", ret == 0 ? "successfully" : "failed");
			if (!ret)
				goto out;
		} else if (!strcmp(cmd, "set_bandwidth") && ret == 4) {
			ret = set_qos_bandwidth(core, bandwidth, group, items);
			cn_dev_core_info(core,
				"Set Qos bandwidth %s.\n", ret == 0 ? "successfully" : "failed");
			if (!ret)
				goto out;
		}
	}
	cn_dev_core_err(core, "usage:");
	cn_dev_core_err(core, "echo \"reset\" > QoS");
	cn_dev_core_err(core, "echo \"set_group_bandwidth <bandwidth> <group id>\" > QoS");
	cn_dev_core_err(core, "echo \"set_bandwidth <bandwidth> <group id> <item id>\" > QoS");

out:

	return buf_size;
}
#else
int cndev_qos_show(struct seq_file *m, void *v)
{
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_cndev_set *cndev_set = core->cndev_set;
	int i = 0, j = 0;
	struct cndev_qos_desc_info_s *qos = NULL;
	u32 reg32 = 0;

	switch (core->device_id) {
	case MLUID_PIGEON:
	case MLUID_590:
	case MLUID_580:
		seq_printf(m, "Not support\n");
		goto out;
	}

	if (!cndev_set->qos_conf.qos_setting) {
		seq_puts(m, "Invalid qos configuration!\n");
		goto out;
	}

	seq_printf(m, "Qos group num: %u\n",
			cndev_set->qos_conf.qos_setting->qos_group_count);
	seq_printf(m, "max QoS base value: %u\n",
			cndev_set->qos_conf.qos_setting->max_qos_base);
	seq_printf(m, "max QoS up value: %u\n",
			cndev_set->qos_conf.qos_setting->max_qos_up);
	seq_printf(m, "min QoS base value: %u\n",
			cndev_set->qos_conf.qos_setting->min_qos_base);
	seq_printf(m, "min QoS up value: %u\n",
			cndev_set->qos_conf.qos_setting->min_qos_up);

	seq_puts(m, "\nQoS Description:\n");
	seq_puts(m, "Group\titems\tweight\tdefault\tQos-Name\n");
	for (j = 0; j < cndev_set->qos_conf.qos_setting->qos_group_count; j++) {
		qos = &cndev_set->qos_conf.qos[j];
		if (!qos)
			continue;
		for (i = 0; i < qos->cnt; i++) {
			reg32 = reg_read32(cndev_set->core->bus_set, qos->desc[i].reg32);
			reg32 &= (~MLU2X0_QOS_WEIGHT_MASK);

			seq_printf(m, "%3u\t%3u\t%3u\t%4u\t%s\n",
				j,
				i,
				reg32,
				qos->desc[i].default_value,
				qos->desc[i].name);
		}
	}

out:
	return 0;
}

ssize_t cndev_qos_write(
		struct file *file, const char __user *user_buf,
		size_t count, loff_t *pos)
{
	u32 base = 0;
	u32 up = 0;
	u32 policy = 0;
	u32 group = 0;
	char buf[128] = {0};
	char cmd[128] = {0};
	int ret = 0;
	ssize_t buf_size = 0;
	struct cndev_qos_info qos_info;
	struct cn_core_set *core = (struct cn_core_set *)PDE_DATA(file_inode(file));
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)core->cndev_set;
	struct cndev_qos_group_param qos_group_info;
	struct cndev_qos_param qos_weight_info;

	switch (core->device_id) {
	case MLUID_PIGEON:
	case MLUID_590:
	case MLUID_580:
		cn_dev_core_err(core, "Not support\n");
		buf_size = count;
		goto out;
	}

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size)) {
		return -EFAULT;
	}
	buf[buf_size] = '\0';
	cn_dev_core_info(core, "user command:%s", buf);

	if (strlen(buf)) {
		ret = sscanf(buf, "%s %u %u %u %u", cmd, &base, &up, &policy, &group);
		if (!strcmp(cmd, "set") && ret == 5) {
			qos_info.qos_base = base;
			qos_info.qos_up = up;
			qos_info.qos_policy = policy;
			qos_info.group_id = group;
			ret = cndev_qos_operation(cndev_set, &qos_info);
			cn_dev_core_info(core,
				"Set Qos policy %s.\n", ret == 0 ? "successfully" : "failed");
			if (!ret)
				goto out;
		} else if (!strcmp(cmd, "reset")) {
			ret = cndev_reset_qos(cndev_set);
			cn_dev_core_info(core,
				"Reset Qos policy %s.\n", ret == 0 ? "successfully" : "failed");
			if (!ret)
				goto out;
		} else if (!strcmp(cmd, "set_group_weight") && ret == 3) {
			qos_group_info.qos_value.qos_weight = up;
			qos_group_info.qos_group = base;
			ret = cndev_set_qos_group_policy(cndev_set, &qos_group_info);
			cn_dev_core_info(core,
				"Set qos group weight %s.\n", ret == 0 ? "successfully" : "failed");
			if (!ret)
				goto out;
		} else if (!strcmp(cmd, "set_weight") && ret == 4) {
			qos_weight_info.qos_group = base;
			qos_weight_info.master_index = up;
			qos_weight_info.qos_value.qos_weight = policy;
			ret = cndev_set_qos_policy(cndev_set, &qos_weight_info);
			cn_dev_core_info(core,
				"Set qos weight weight %s.\n", ret == 0 ? "successfully" : "failed");
			if (!ret)
				goto out;
		}
	}

	cn_dev_core_err(core, "usage:");
	cn_dev_core_err(core, "echo \"reset\" > QoS");
	cn_dev_core_err(core, "echo \"set <base> <up> <policy> <group id>\" > QoS");
	cn_dev_core_err(core, "echo \"set_group_weight <group id> <weight>\" > QoS");
	cn_dev_core_err(core, "echo \"set_weight <group id> <master id> <weight>\" > QoS");
out:

	return buf_size;
}
#endif

int cndev_show_info(struct seq_file *m, void *v)
{
	int ret = 0;
	struct cn_core_set *core = (struct cn_core_set *)m->private;
	struct cn_cndev_set *cndev_set = NULL;

	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	cndev_set = (struct cn_cndev_set *)core->cndev_set;
	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	seq_printf(m, "IPU Freq Setting Reference Count: %llu\n", (u64)atomic64_read(&cndev_set->ipu_freq_set_ref));
	seq_printf(m, "cndev print debug: %s\n",
		(cndev_set->print_debug == true) ? "open" : "close");

	return ret;
}
