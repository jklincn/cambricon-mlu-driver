#ifndef __CAMB_ASM_CACHE_H_
#define __CAMB_ASM_CACHE_H_
void camb_flush_dcache_range(void *addr, size_t len);
void camb_clean_dcache_range(void *addr, size_t len);
void camb_inv_dcache_range(void *addr, size_t len);
#endif
