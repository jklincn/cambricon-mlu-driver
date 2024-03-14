#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/timer.h>

#include "util.h"
#include "ipu.h"
#include "proc.h"
#include "sample.h"
#include "trace.h"

#define USAGE_HELP \
	"usage help: sudo insmod cambricon-util_drv.ko \
kpara=\"<0>=IKP:1024;IKI:512;IKD:512,<1>=IKP:1024;IKI:512;IKD:512\""

static char *kpara = NULL;
module_param(kpara, charp, 0444);

extern struct smlu_util_adjust_module_s ex_smlu_util_adjust_module;

typedef long (*adjust_fn)(int idx, int instance, long target, long usage);
typedef long (*output_fn)(int idx, int instance);

struct util_ctrl {
	adjust_fn adjust;
	output_fn output;
};
static struct util_ctrl ops[UTIL_TYPE_MAX];

long smlu_util_adjust(int idx, int instance, enum util_type sub,
	unsigned long target, unsigned long usage)
{
	long ret;
	adjust_fn fn = NULL;

	switch (sub) {
	case IPU_UTIL:
		fn = ops[sub].adjust;
	break;

	default:
	break;
	}

	if (fn == NULL)
		return -1;

	ret = fn(idx, instance, target, usage);
	return ret;
}

static long smlu_util_adjust_output(int idx, int instance, enum util_type sub)
{
	int ret;
	output_fn fn = NULL;

	switch (sub) {
	case IPU_UTIL:
		fn = ops[sub].output;
		break;
	default:
		pr_warn("no adjust_output_fn match for input type:%d\n", sub);
		break;
	}

	if (fn == NULL)
		return -ENODEV; /* -ENODEV means no util adjust */

	ret = fn(idx, instance);
	return ret;
}

static int util_fn_register(enum util_type sub, struct util_ctrl *c)
{
	if (c->adjust == NULL || c->output == NULL)
		return -1;

	ops[sub].adjust = c->adjust;
	ops[sub].output = c->output;
	return 0;
}

static void util_fn_unregister(enum util_type sub)
{
	ops[sub].adjust = NULL;
	ops[sub].output = NULL;
	return;
}

static void show_pid_parameter(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cn_pid_parameter); i++) {
		if (!strcmp(cn_pid_parameter[i].board_model_name, ""))
			continue;

		pr_info("<%d><%s>=IKP:%ld;IKI:%ld;IKD:%ld\n",
			i, cn_pid_parameter[i].board_model_name,
			cn_pid_parameter[i].IKP,
			cn_pid_parameter[i].IKI,
			cn_pid_parameter[i].IKD);
	}
}

static struct default_module_param {
	char board_model_name[BOARD_MODEL_NAME_LEN];
	long kp;
	long ki;
	long kd;
} pid_params[] = {
	{.board_model_name = "MLU370-D2", 256, 128, 128},
	{.board_model_name = "MLU370-X8", 256, 128, 128},
	{.board_model_name = "MLU370-S4", 256, 128, 128},
	{.board_model_name = "MLU370-M8", 256, 128, 128},
	{.board_model_name = "MLU5xx", 512, 240, 256},
	{.board_model_name = "DEFAULT", 256, 128, 128}, /* must be the last line */
};

static int default_module_parameter_init(void)
{
	int i, j;
	long kp, ki, kd;

	for (i = 0; i < ARRAY_SIZE(cn_pid_parameter); i++) {
		if (!strcmp(cn_pid_parameter[i].board_model_name, ""))
			continue;

		/* now MLU500 share the same params */
		if (!strncasecmp(cn_pid_parameter[i].board_model_name, "MLU5xx", 4))
			strcpy(cn_pid_parameter[i].board_model_name, "MLU5xx");

		for (j = 0; j < ARRAY_SIZE(pid_params) - 1; j++) {
			if (!strcmp(cn_pid_parameter[i].board_model_name,
					pid_params[j].board_model_name)) {
				kp = pid_params[j].kp;
				ki = pid_params[j].ki;
				kd = pid_params[j].kd;
				break;
			}
		}

		if (j == ARRAY_SIZE(pid_params) - 1) {
			pr_warn("the card type of %s is not default adapted\n",
				cn_pid_parameter[i].board_model_name);
			kp = pid_params[ARRAY_SIZE(pid_params) - 1].kp;
			ki = pid_params[ARRAY_SIZE(pid_params) - 1].ki;
			kd = pid_params[ARRAY_SIZE(pid_params) - 1].kd;
		}

		cn_pid_parameter[i].IKP = kp;
		cn_pid_parameter[i].IKI = ki;
		cn_pid_parameter[i].IKD = kd;
	}

	return 0;
}

static int parse_module_parameter(void)
{
	int ret;
	char *t, *k;

	if (kpara == NULL) {
		ret = default_module_parameter_init();
		return ret;
	}

	k = kmalloc(strlen(kpara) + 1, GFP_KERNEL);
	if (k == NULL)
		return -1;
	strcpy(k, kpara);

	while ((t = strsep(&k, ",")) != NULL) {
		ret = parse(t);
		if (ret) {
			printk("%s\n", USAGE_HELP);
			goto exit;
		}
	}
exit:
	kfree(k);
	return 0;
}

static void ex_module_init(void)
{
	ex_smlu_util_adjust_module.smlu_util_adjust_module = (void *)THIS_MODULE;
	ex_smlu_util_adjust_module.smlu_util_adjust_output = (void *)smlu_util_adjust_output;
}

static void ex_module_exit(void)
{
	ex_smlu_util_adjust_module.smlu_util_adjust_module = NULL;
	ex_smlu_util_adjust_module.smlu_util_adjust_output = NULL;
}

static void adjust_lock_init(void)
{
	int card_idx, instance_id, type;
	struct pid_s *pid_info;

	for (card_idx = 0; card_idx < MAX_PHYS_CARD; card_idx++) {
		for (instance_id = 1; instance_id <= MAX_SMLU_INSTANCE_COUNT; instance_id++) {
			for (type = 0; type < UTIL_TYPE_MAX; type++) {
				pid_info = &cn_pid_parameter[card_idx].pid_info[instance_id][type];
				mutex_init(&pid_info->adjust_lock);
			}
		}
	}
}

static int __init util_drv_init(void)
{
	int ret;
	struct util_ctrl c;

	/*
	 * we have three methods to change PID default parameter by your need
	 * 1. sudo insmod cambricon-util_drv.ko with kernel parameter
	 * 2. echo to proc device node
	 * 3. to change source code here
	 */
	ret = parse_module_parameter();
	if (ret) {
		return -1;
	}

	show_pid_parameter();

	adjust_lock_init();

	/*
	 * 3rd user can register util_ctrl struct for other util methods
	 * for example:
	 *    implement ipu_util_adjust_V2 and ipu_util_output_V2
	 *    use util_fn_register type=IPU_UTIL reister
	 */
	c.adjust = ipu_util_adjust;
	c.output = ipu_util_output;
	ret = util_fn_register(IPU_UTIL, &c);
	if (ret)
		return ret;

	ret = util_proc_init();
	if (ret)
		return -1;

	ret = util_trace_init();
	if (ret)
		return -1;

	ret = util_sample_init();
	if (ret)
		return -1;

	/* should insmod this module after cambricon-drv.ko */
	ex_module_init();

	return 0;
}

static void __exit util_drv_exit(void)
{
	ex_module_exit();
	util_sample_exit();
	util_trace_exit();
	util_proc_exit();

	util_fn_unregister(IPU_UTIL);
}

module_init(util_drv_init);
module_exit(util_drv_exit);
MODULE_DESCRIPTION("Cambricon MLU UTIL Module");
MODULE_LICENSE("GPL v2");
