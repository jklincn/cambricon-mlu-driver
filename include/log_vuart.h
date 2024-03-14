#ifndef __LOG_VUART_H__
#define __LOG_VUART_H__

#include "cndrv_core.h"

#ifdef CONFIG_CNDRV_VUART
int cn_log_vuart_init(void);
void cn_log_vuart_exit(void);

int cn_log_vuart_late_init(struct cn_core_set *core);
void cn_log_vuart_late_exit(struct cn_core_set *core);
#else
static inline int cn_log_vuart_init(void)
{
	return 0;
}
static inline void cn_log_vuart_exit(void){}
static inline int cn_log_vuart_late_init(struct cn_core_set *core)
{
	return 0;
}
static inline void cn_log_vuart_late_exit(struct cn_core_set *core)
{
}

#endif

#endif
