#ifndef __CAMBRICON_CNDRV_CNDEV_H__
#define __CAMBRICON_CNDRV_CNDEV_H__

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "cndrv_monitor_usr.h"

struct cndev_priv_data {
	void *udvm_priv_data;
	void *hostmem_priv_data;
	void *smlu_priv_data;
};

#define cndev_cp_from_usr(user, kernel, n)	\
({	\
	int __ret = 0;	\
	if (n <= 0) {	\
		pr_err("[%s] [%d] copy_from_user failed, invalid data size.\n", __func__, __LINE__);	\
		__ret = -EINVAL;	\
	} else {	\
		__ret = copy_from_user((void *)kernel, (void *)user, n);	\
		if (__ret) {	\
			pr_err("[%s] [%d] copy_from_user failed\n", __func__, __LINE__);	\
			__ret = -EFAULT;	\
		}	\
	}	\
	__ret;	\
})

#define cndev_cp_to_usr(user, kernel, n)	\
({	\
	int __ret = 0;	\
	__ret = copy_to_user((void*)user, (void*)kernel, n);	\
	if (__ret) {	\
		pr_err("[%s] [%d] copy_to_user failed\n", __func__, __LINE__);	\
		__ret = -EFAULT;	\
	}	\
	__ret;	\
})

#define cndev_cp_less_val(user_len, kern_len, user, kern, len)	\
({	\
	int __ret = 0;	\
	int n = *(user_len) < kern_len ? *(user_len) : kern_len;	\
	*(user_len) = kern_len;	\
	if (user)	\
		__ret = cndev_cp_to_usr(user, kern, n * len);	\
	__ret;	\
})

int cndev_card_memory_info(void *core_set,
				struct cndev_memory_info *mem_info);
int cndev_get_qos_conf(void *core_set, void **qos_conf);
int get_cndev_open_count(void);
int cndev_open_count_lock(void);
void cndev_open_count_unlock(void);

#endif
