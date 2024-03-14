#ifndef __XID_INTERNAL_H__
#define __XID_INTERNAL_H__

#include "cndrv_xid.h"

#define xid_cp_to_usr(user, kernel, n)	\
({	\
	int __ret = 0;	\
	__ret = copy_to_user((void*)user, (void*)kernel, n);	\
	if (__ret) {	\
		pr_err("[%s] [%d] copy_to_user failed\n", __func__, __LINE__);	\
		__ret = -EFAULT;	\
	}	\
	__ret;	\
})

#define xid_cp_less_val(user_len, kern_len, user, kern, len)	\
({	\
	int __ret = 0;	\
	int n = *(user_len) < kern_len ? *(user_len) : kern_len;	\
	*(user_len) = kern_len;	\
	if (user)	\
		__ret = xid_cp_to_usr(user, kern, n * len);	\
	__ret;	\
})

#endif /* __XID_INTERNAL_H__ */
