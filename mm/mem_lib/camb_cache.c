#ifdef CONFIG_CNDRV_EDGE
#include <linux/cache.h>
#include <linux/printk.h>
#include <linux/version.h>

#include "camb_asm_cache.h"

#if defined(__KERNEL__)
#define __EDGE_CACHE_LINE_SIZE ((u64)(cache_line_size()))
#define __EDGE_CACHE_LINE_SIZE_MASK (__EDGE_CACHE_LINE_SIZE - 1)
#else
#error "unsupport user space"
#endif /* __KERNEL__ */
/*flush cache data to DDR*/
void cn_edge_cache_clean(void *start, u64 len)
{
	u64 i;
	u64 s = (u64)start & (~__EDGE_CACHE_LINE_SIZE_MASK);
	u64 e = ((u64)(start + len - 1) &
			(~__EDGE_CACHE_LINE_SIZE_MASK)) + __EDGE_CACHE_LINE_SIZE;
	u64 l = (e - s) & (~__EDGE_CACHE_LINE_SIZE_MASK);

	if (unlikely(!len)) {
		return;
	}

	for (i = 0; i < l;) {
		__asm__ __volatile__ (
		"dc cvac, %0\n\t"
		:
		: "r" (s + i)
		: "memory");
		i += __EDGE_CACHE_LINE_SIZE;
	}
	/*barrier*/
	smp_wmb();
}

#define read_tcr_el1()                          \
	({                                            \
		u64 reg;                                    \
		asm volatile("mrs %0, tcr_el1\n\t"          \
		: "=r" (reg));                              \
		reg;                                        \
	})

#define read_id_aa64mmfr1_el1()                 \
	({                                            \
		u64 reg;                                    \
		asm volatile("mrs %0, id_aa64mmfr1_el1\n\t" \
		: "=r" (reg));                              \
		reg;                                        \
	})

void cn_edge_cache_invalid(void *start, u64 len)
{
#if 0
	u64 tcr_el1 = read_tcr_el1();
	u64 tmp_tcr_el1 = tcr_el1 | ((u64)3 << 39);

	u64 id_aa64mmfr1_el1 = read_id_aa64mmfr1_el1();
	if ((id_aa64mmfr1_el1 & (0xF)) == 0x2) {
		asm volatile("msr tcr_el1, %0\n\t"	\
				:: "r" (tmp_tcr_el1));
	} else {
		pr_err("NOT SUPPORT HARDWARE UPDATE OF BOTH ACCESS FLAG AND DIRTY STATE\n");
		return;
	}
#endif

	camb_inv_dcache_range(start, len);
}

/*flush & invalid data */
void cn_edge_cache_flush(void *start, u64 len)
{
	camb_flush_dcache_range(start, len);
}

#undef __EDGE_CACHE_LINE_SIZE_MASK
#undef __EDGE_CACHE_LINE_SIZE
#endif
