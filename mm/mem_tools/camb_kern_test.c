#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/fs.h>
#include<linux/init.h>
#include<linux/device.h>
#include<linux/ioctl.h>
#include<linux/compat.h>
#include<linux/uaccess.h>
#include<linux/slab.h>
//#include<linux/kallsyms.h>
#include <linux/soc/cambricon/cnosal/cnosal_module.h>
#include<linux/string.h>
#include<linux/io.h>

#define NAME_MAX_SIZE (64)
#define ARGS_SIZE (64)
#define TEST_PRINT(fmt, args...)  \
({			\
	do {		\
	} while (0);	\
})

typedef struct {
	unsigned int num;
	char func_name[NAME_MAX_SIZE];
	char args[5][ARGS_SIZE];
	unsigned long ret;
} invoke_func;

#define ARG_TYPE_DEC 1
#define ARG_TYPE_HEX 2
#define ARG_TYPE_STR 3

void *(*pfunc_0)(void) = NULL;
void *(*pfunc_1)(unsigned long) = NULL;
void *(*pfunc_2)(unsigned long, unsigned long) = NULL;
void *(*pfunc_3)(unsigned long, unsigned long, unsigned long) = NULL;
void *(*pfunc_4)(unsigned long, unsigned long, unsigned long, unsigned long) = NULL;
void *(*pfunc_5)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long) = NULL;

bool in_number(char cin)
{
	if ((cin >= '0') && (cin <= '9')) {
		return true;
	} else if ((cin >= 'a') && (cin <= 'z')) {
		return true;
	} else if ((cin >= 'A') && (cin <= 'Z')) {
		return true;
	} else {
		return false;
	}

	return false;
}

int is_number(char *input)
{
	int i = 0;
	int len  = strlen(input);

	/*hex value*/
	if (input[0] == '0') {
		if ((input[1] == 'X') || (input[1] == 'x')) {
			/*only supoort (18 - 2) * 6 = 64bit*/
			if (len > 18) {
				return ARG_TYPE_STR;
			}

			for (i = 0; i < len; i++) {
				/*every char is valid*/
				if (!in_number(input[i])) {
					return ARG_TYPE_STR;
				}
			}

			return ARG_TYPE_HEX;
		}
	}

	/*dec val*/
	for (i = 0; i < len; i++) {
		if ((input[i] < '0') || (input[i] > '9')) {
			return ARG_TYPE_STR;
		}
	}

	return ARG_TYPE_DEC;
}

int deal_arg(invoke_func *cinfo, unsigned long *arg)
{
	int i = 0;
	int ret = 0;
	char str[ARGS_SIZE] = {0};
	char sarg[ARGS_SIZE * 6] = {0};
	int sum = 0;

	for (i = 0; i < cinfo->num; i++) {
		ret = is_number(cinfo->args[i]);
		switch (ret) {
		case ARG_TYPE_STR: {
				if (cinfo->args[i][0] == '#') {
					strcpy(str, &(cinfo->args[i][1]));
					strcpy(cinfo->args[i], str);
					arg[i] = (unsigned long)(&(cinfo->args[i]));
					sum += sprintf(sarg+sum, "%s ", (char *)arg[i]);
				} else {
					arg[i] = (unsigned long)(&(cinfo->args[i]));
					sum += sprintf(sarg + sum, "%s ", (char *)arg[i]);
				}

				break;
			}

		case ARG_TYPE_DEC: {
				sscanf(cinfo->args[i], "%ld", (long int *)(cinfo->args[i]));
				arg[i] = *(unsigned long *)(cinfo->args[i]);
				sum += sprintf(sarg+sum, "%ld ", *(long int *)(cinfo->args[i]));
				break;
			}

		case ARG_TYPE_HEX: {
				sscanf(cinfo->args[i], "%lx", (unsigned long int *)(cinfo->args[i]));
				arg[i] = *(unsigned long *)(cinfo->args[i]);
				sum += sprintf(sarg+sum, "0x%lx ", *(unsigned long int *)(cinfo->args[i]));
				break;
			}

		default:
				break;
		}
	}

	TEST_PRINT("call %s %s\n", cinfo->funcname, sarg);

	return 0;
}

unsigned long invoke_linux_kernel_func(const unsigned long funcaddr, invoke_func *func)
{
	unsigned long args[5] = {0};
	void *p = NULL;

	deal_arg(func, args);

	switch (func->num) {
		case 0: {
			pfunc_0 = (void *)funcaddr;
			p = pfunc_0();
			break;
		}

		case 1: {
			pfunc_1 = (void *)funcaddr;
			p = pfunc_1(args[0]);
			break;
		}

		case 2: {
			pfunc_2 = (void *)funcaddr;
			p = pfunc_2(args[0], args[1]);
			break;
		}

		case 3: {
			pfunc_3 = (void *)funcaddr;
			p = pfunc_3(args[0], args[1], args[2]);
			break;
		}

		case 4: {
			pfunc_4 = (void *)funcaddr;
			p = pfunc_4(args[0], args[1], args[2], args[3]);
			break;
		}

		case 5: {
			pfunc_5 = (void *)funcaddr;
			p = pfunc_5(args[0], args[1], args[2], args[3], args[4]);
			break;
		}

		default: {
			TEST_PRINT("install wrong argument num is %d\n", func->num);
			break;
		}
	}

	TEST_PRINT("%s run end, call return 0x%lx\n", func->funcname, (unsigned long)p);

	return (unsigned long)p;
}

int cn_copy_to_user(void *to, void *from, unsigned long n)
{
	int ret = copy_to_user(to, from, n);
	return ret;
}

int cn_copy_from_user(void *to, void *from, unsigned long n)
{
	int ret = copy_from_user(to, from, n);

	return ret;
}

long cn_mem_kernel_test(unsigned long arg)
{
	invoke_func cinfo;

	static unsigned long function_addr;
	unsigned long ret = 0;

	if (copy_from_user(&cinfo, (void *)arg, sizeof(invoke_func))) {
		TEST_PRINT("copy from user failed\n");
		return -1;
	}

	function_addr = cnosal_kallsyms_lookup_name(cinfo.func_name);
	if (function_addr == 0) {
		TEST_PRINT("cannot find function %s\n", cinfo.funcname);
		return -1;
	}

	ret = invoke_linux_kernel_func(function_addr, &cinfo);

	cinfo.ret = ret;

	if (copy_to_user((void *)arg, &cinfo, sizeof(invoke_func))) {
		TEST_PRINT("copy from user failed\n");
		return -1;
	}

	return ret;
}
