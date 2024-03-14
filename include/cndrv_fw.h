#ifndef _CN_FW_H_
#define _CN_FW_H_

#include "cndrv_core.h"

int service_startup_status(struct cn_core_set *core);
void clear_serv_status(struct cn_core_set *core);
void set_serv_status(struct cn_core_set *core);

#ifdef CONFIG_CNDRV_FW
unsigned int crc32_o (unsigned int crc, unsigned char  *p, unsigned int len);
int bringup(struct cn_core_set *core, uint64_t boot_entry);
int boot_prepare(struct cn_core_set *core);
int cn_bringup(struct cn_core_set *core);
int shutdown(struct cn_core_set *core);
void setup_virtcon(struct cn_core_set *core, int en);
#else
static inline unsigned int crc32_o (unsigned int crc, unsigned char  *p, unsigned int len)
{
	return 0;
}
static inline int bringup(struct cn_core_set *core, uint64_t boot_entry)
{
	return -1;
}
static inline int cn_bringup(struct cn_core_set *core)
{
	return -1;
}

static inline void setup_virtcon(struct cn_core_set *core, int en){}

#endif

#endif
