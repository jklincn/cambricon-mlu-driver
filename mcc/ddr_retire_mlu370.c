#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/kthread.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/radix-tree.h>
#include <linux/bitops.h>

#include "cndrv_core.h"
#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_mcu.h"
#include "cndrv_mm.h"
#include "cndrv_mcc.h"
#include "mcc_main.h"
#include "ddr_retire_mlu370.h"

static unsigned long map0_base[] = {
	[0]  = 0x000000000, [1]  = 0x100000000,
	[2]  = 0x200000000, [3]  = 0x400000000,
	[4]  = 0x500000000, [5]  = 0x600000000,
	[6]  = 0x800000000, [7]  = 0x900000000,
	[8]  = 0xa00000000, [9]  = 0xc00000000,
	[10] = 0xd00000000, [11] = 0xe00000000,
	[12] = 0x1000000000, [13] = 0x1100000000,
	[14] = 0x1200000000, [15] = 0x1400000000,
	[16] = 0x1500000000, [17] = 0x1600000000,
	[18] = 0x1800000000, [19] = 0x1900000000,
	[20] = 0x1a00000000, [21] = 0x1c00000000,
	[22] = 0x1d00000000, [23] = 0x1e00000000,
};

/* NOTE: fix 3.10.693 compile error, not found radix_tree_empty function */
static inline bool cn_radix_tree_empty(struct radix_tree_root *root)
{
#if (KERNEL_VERSION(4, 7, 0) <= LINUX_VERSION_CODE)
	return radix_tree_empty(root);
#else
	return root->rnode == NULL;
#endif
}

/**** START: find error address code  ****/
static inline unsigned long
__bit2addr(unsigned long nr_bit, struct level_bits_t *level_bits)
{
	return level_bits->base + (nr_bit << level_bits->per_bit_shift);
}

static inline unsigned long
__addr2bit(unsigned long paddr, struct level_bits_t *level_bits)
{
	return (paddr - level_bits->base) >> level_bits->per_bit_shift;
}

static inline unsigned int
__addr2chlIdx(unsigned long paddr, struct retire_bits_t *bits)
{
	return ((paddr >> 34) & 0x7) * bits->chls_per_llc + ((paddr >> 32) & 0x3);
}

static int
__insert_l2(struct level_bits_t *l1_bits, struct level_bits_t *l2_bits,
			unsigned int nr_bit)
{
	int ret = 0;

	write_lock(&l1_bits->l2_root_lock);
	ret = radix_tree_insert(&l1_bits->l2_root, nr_bit, (void *)l2_bits);
	if (!ret) set_bit(nr_bit, l1_bits->bits);
	write_unlock(&l1_bits->l2_root_lock);

	return ret;
}

static struct level_bits_t *
__delete_l2(struct level_bits_t *l1_bits, unsigned int nr_bit)
{
	struct level_bits_t *l2_bits = NULL;

	write_lock(&l1_bits->l2_root_lock);
	clear_bit(nr_bit, l1_bits->bits);
	l2_bits = radix_tree_delete(&l1_bits->l2_root, nr_bit);
	write_unlock(&l1_bits->l2_root_lock);

	return l2_bits;
}

static struct level_bits_t *
__search_l2(struct level_bits_t *l1_bits, unsigned int nr_bit)
{
	struct level_bits_t *l2_bits = NULL;

	read_lock(&l1_bits->l2_root_lock);
	l2_bits = radix_tree_lookup(&l1_bits->l2_root, nr_bit);
	read_unlock(&l1_bits->l2_root_lock);

	return l2_bits;
}

static struct level_bits_t *
__create_level_bits(unsigned long base, unsigned long size, int level)
{
	struct level_bits_t *level_bits = NULL;
	unsigned long nr_bits = 0, nbytes = 0;
	unsigned int shift = 0;

	if (!level || level >= MAX_LEVEL)
		return ERR_PTR(-EINVAL);

	shift = level_bit_shift[level];
	if (!IS_ALIGNED(size, 1UL << shift) || !IS_ALIGNED(base, 1UL << shift))
		return ERR_PTR(-EINVAL);

	nr_bits = size >> shift;
	nbytes = sizeof(struct level_bits_t) + BITS_TO_LONGS(nr_bits) * sizeof(unsigned long);
	level_bits = cn_kzalloc(nbytes, GFP_KERNEL);
	if (unlikely(!level_bits))
		return ERR_PTR(-ENOMEM);

	level_bits->base = base;
	level_bits->size = size;
	level_bits->per_bit_shift = shift;
	level_bits->level = level;

	if (level == L1_BITS) {
		INIT_RADIX_TREE(&level_bits->l2_root, GFP_ATOMIC);
		rwlock_init(&level_bits->l2_root_lock);
	}

	return level_bits;
}

static void
__destroy_level_bits(struct level_bits_t *level_bits)
{
	struct level_bits_t *l2_bits;
	unsigned long len = 0;
	int nr_bit = 0;

	if (!level_bits)
		return ;

	if ((level_bits->level == L1_BITS) &&
		!cn_radix_tree_empty(&level_bits->l2_root)) {

		len = level_bits->size >> level_bits->per_bit_shift;
		for_each_set_bit(nr_bit, level_bits->bits, len) {
			l2_bits = __delete_l2(level_bits, nr_bit);
			/* NOTE: Each set_bit in l1_bits must have its l2_bits exist, so if
			 * __delete_l2 not find valid l2_bits. The situation is so dangerout that
			 * we need to check whether there are unconsidered concurrency scenaios!!! */
			BUG_ON(!l2_bits || (l2_bits->level != L2_BITS));
			cn_kfree(l2_bits);
		}
	}

	cn_kfree(level_bits);
}

static unsigned long
__find_addr_in_l2(void *retire_set, struct level_bits_t *l2_bits,
			unsigned int msys_idx, unsigned int chl_idx,
			bool (*addr_is_bad)(void *, unsigned long, unsigned long,
				unsigned int, unsigned int, bool))
{
	unsigned long base = 0, size = 0, bit = 0, len = 0;
	int ret = 0;

	len = l2_bits->size >> l2_bits->per_bit_shift;
	for_each_clear_bit(bit, l2_bits->bits, len) {
		base = __bit2addr(bit, l2_bits);
		size = 1UL << l2_bits->per_bit_shift;

		ret = addr_is_bad(retire_set, base, size, msys_idx, chl_idx, true);
		if (ret) {
			set_bit(bit, l2_bits->bits);
			return base;
		}
	}

	return 0;
}

/* NOTE: we will disable_irq before find_addr, so mlu370_retire_find_addr do not
 * need to worry about concurrent preemption at present. */
int mlu370_retire_find_addr(struct retire_bits_t *retire_bits,
			unsigned int msys_idx, unsigned int chl_idx, unsigned long *eaddr,
			bool (*addr_is_bad)(void *, unsigned long, unsigned long,
				unsigned int, unsigned int, bool))
{
	unsigned int start = (((msys_idx << 1) + chl_idx) / 3) * 3;
	unsigned long base = 0, size = 0, bit = 0, len = 0;
	unsigned long error_addr = 0;
	struct level_bits_t *l1_bits = NULL, *l2_bits = NULL;
	int i = 0, ret = -EINVAL;

	if (!retire_bits)
		return ret;

	for (i = start; i < start + retire_bits->chls_per_llc; i++) {
		l1_bits = retire_bits->l1_bits[i];
		len = l1_bits->size >> l1_bits->per_bit_shift;

		/* NOTE: ecc error is localized, check set_bit first may find error
		 * address easier. */
		for_each_set_bit(bit, l1_bits->bits, len) {
			l2_bits = __search_l2(l1_bits, bit);
			if (!l2_bits) {
				WARN(1, "not found nr_bit(%ld)'s l2_bits is impossible, maybe bug happened", bit);
				continue;
			}

			error_addr = __find_addr_in_l2(retire_bits->retire_set, l2_bits,
							msys_idx, chl_idx, addr_is_bad);
			if (error_addr) {
				ret = 0;
				goto finish_find;
			}
		}

		for_each_clear_bit(bit, l1_bits->bits, len) {
			base = __bit2addr(bit, l1_bits);
			size = 1UL << l1_bits->per_bit_shift;

			if (addr_is_bad(retire_bits->retire_set, base, size, msys_idx,
					chl_idx, true)) {
				l2_bits = __create_level_bits(base, size, L2_BITS);
				if (IS_ERR(l2_bits)) {
					ret = PTR_ERR(l2_bits);
					goto finish_find;
				}

				error_addr = __find_addr_in_l2(retire_bits->retire_set,
					l2_bits, msys_idx, chl_idx, addr_is_bad);

				if (error_addr)
					ret = __insert_l2(l1_bits, l2_bits, bit);

				if (ret) __destroy_level_bits(l2_bits);

				/* NOTE: no matter return value is failed or success, direct
				 * return. if failed, skip current irq bottom handle, wait next
				 * ecc irq happened */
				goto finish_find;
			}
		}
	}

finish_find:
	if (!ret)
		*eaddr = error_addr;

	return ret;
}

/* input phys address is 40bit map0 address */
int mlu370_retire_set_addr(struct retire_bits_t *retire_bits,
			unsigned long addr)
{
	struct level_bits_t *l1_bits = NULL;
	unsigned long nr_bit = 0;
	struct level_bits_t *l2_bits = NULL;
	int ret = 0;

	if (!retire_bits)
		return -EINVAL;

	/* 1. find l1_bits which cover input address */
	l1_bits = retire_bits->l1_bits[__addr2chlIdx(addr, retire_bits)];

	/* 2. test ecc_address bit in l1_bits is set */
	nr_bit = __addr2bit(addr, l1_bits);

	read_lock(&l1_bits->l2_root_lock);
	ret = test_bit(nr_bit, l1_bits->bits);
	read_unlock(&l1_bits->l2_root_lock);

	/* 3. find or create l2_bits with addr input */
	if (!ret) {
		l2_bits = __create_level_bits(__bit2addr(nr_bit, l1_bits),
						1UL << l1_bits->per_bit_shift, L2_BITS);
		if (IS_ERR(l2_bits))
			return PTR_ERR(l2_bits);

		ret = __insert_l2(l1_bits, l2_bits, nr_bit);
		if (ret)
			goto failed_insert;

	} else {
		l2_bits = __search_l2(l1_bits, nr_bit);
		if (!l2_bits) {
			WARN(1, "not found nr_bit(%ld)'s l2_bits is impossible, maybe bug happened", nr_bit);
			return -EINVAL;
		}
	}

	/* 4. set l2_bits error address bit */
	ret = test_and_set_bit(__addr2bit(addr, l2_bits), l2_bits->bits);
	WARN(ret, "same address(%#lx) input for set bitmaps", addr);
	return 0;

failed_insert:
	__destroy_level_bits(l2_bits);
	return ret;
}

struct retire_bits_t *
mlu370_retire_bitmap_init(struct cn_mcc_set *mcc_set, void *retire_set,
				unsigned int msys_cnt, unsigned long per_chl_sz,
				unsigned long div_base)
{
	struct cn_core_set *core = (struct cn_core_set *)mcc_set->core;
	struct retire_bits_t *retire_bits = NULL;
	unsigned int chls_cnts = msys_cnt << 1;
	int i = 0, ret = 0;

	retire_bits = cn_kzalloc(sizeof(struct retire_bits_t), GFP_KERNEL);
	if (!retire_bits) {
		cn_dev_core_err(core, "alloc and create retire_bits_t failed!");
		return ERR_PTR(-ENOMEM);
	}

	retire_bits->retire_set = retire_set;
	retire_bits->chls_per_llc = 3;
	retire_bits->llc_counts = chls_cnts / retire_bits->chls_per_llc;
	retire_bits->l1_bits =
		cn_kzalloc(sizeof(struct l1_bits_set *) * chls_cnts, GFP_KERNEL);
	if (!retire_bits->l1_bits) {
		cn_dev_core_err(core, "alloc and create l1_bits_set failed!");
		ret = -ENOMEM;
		goto failed_create_bits;
	}

	for (i = 0; i < chls_cnts; i++) {
		retire_bits->l1_bits[i] =
			__create_level_bits(map0_base[i] + div_base, per_chl_sz - div_base, L1_BITS);
		if (IS_ERR(retire_bits->l1_bits[i])) {
			cn_dev_core_err(core, "create %d physical l1_bitmap failed", i);
			ret = PTR_ERR(retire_bits->l1_bits[i]);
			retire_bits->l1_bits[i] = NULL;
			goto failed_init_global_bitmap;
		}
	}

	return retire_bits;

failed_init_global_bitmap:
	for (i = 0; i < chls_cnts; i++)
		__destroy_level_bits(retire_bits->l1_bits[i]);

	cn_kfree(retire_bits->l1_bits);
	retire_bits->l1_bits = NULL;
failed_create_bits:
	cn_kfree(retire_bits);
	return ERR_PTR(ret);
}

void mlu370_retire_bitmap_exit(void *retire_bitmap)
{
	struct retire_bits_t *retire_bits = (struct retire_bits_t *)retire_bitmap;
	unsigned int chls_cnts = 0;
	int i = 0;

	if (!retire_bits)
		return ;

	chls_cnts = retire_bits->llc_counts * retire_bits->chls_per_llc;
	for (i = 0; i < chls_cnts; i++)
		__destroy_level_bits(retire_bits->l1_bits[i]);

	cn_kfree(retire_bits->l1_bits);
	cn_kfree(retire_bits);
}

int mlu370_retire_create_host_buffer(void **host_buffer)
{
	if (!host_buffer)
		return -EINVAL;

	*host_buffer = cn_kzalloc((1UL << level_bit_shift[L1_BITS]), GFP_KERNEL);
	if (*host_buffer == NULL)
		return -ENOMEM;

	return 0;
}

void mlu370_retire_destroy_host_buffer(void *host_buffer)
{
	if (host_buffer)
		cn_kfree(host_buffer);
}

int mlu370_retire_create_shm_buffer(struct cn_core_set *core,
				unsigned long *dev_vaddr, unsigned long *host_vaddr)
{
	return cn_device_share_mem_alloc(0, (host_addr_t *)host_vaddr,
				(dev_addr_t *)dev_vaddr, 1UL << level_bit_shift[L1_BITS],
				core);
}

void mlu370_retire_destroy_shm_buffer(struct cn_core_set *core,
				unsigned long dev_vaddr, unsigned long host_vaddr)
{
	cn_device_share_mem_free(0, host_vaddr, dev_vaddr, core);
}

/**** END: find error address code  ****/

/* translate address input into address which saved in norflash */
static unsigned char remap_switch_table[][3] = {
	[0] = {0, 1, 2},
	[1] = {0, 2, 1},
	[2] = {1, 0, 2},
	[3] = {1, 2, 0},
	[4] = {2, 0, 1},
	[5] = {2, 1, 0},
};

static inline unsigned char
__remap_reverse(unsigned char real_chl, unsigned char remap_mode)
{
	int i = 0;
	for (i = 0; i < 3; i++) {
		if (remap_switch_table[remap_mode][i] == real_chl)
			return i;
	}

	return 0;
}

/* FIXME: remap_mode is static setting in llc registers, current just use hard code. */
static unsigned long
__addr2chl(unsigned long addr, unsigned long ch_cap_x512,
	unsigned char remap_mode)
{
	unsigned char input_chl_id = BITS(addr, 33, 32), chl_id = 0;
	unsigned char map_mode = BITS(addr, 38, 37);
	unsigned char chl_sel = ((BITS(addr, 33, 32) << 5) | BITS(addr, 13, 9)) % 3;
	unsigned long addr_13_9_div3 = BITS(addr, 13, 9) / 3;
	unsigned long out_3chl_mode2 = 0UL;
	unsigned long oaddr = 0;

	switch (input_chl_id) {
	case 0:
		if (chl_sel == 0)
			out_3chl_mode2 = BITS(addr, 31, 14) * 11;
		else if (chl_sel == 1)
			out_3chl_mode2 = BITS(addr, 31, 14) * 11;
		else if (chl_sel == 2)
			out_3chl_mode2 = BITS(addr, 31, 14) * 10;
		break;
	case 1:
		if (chl_sel == 0)
			out_3chl_mode2 = ch_cap_x512 / 32 * 11 + BITS(addr, 31, 14) * 11;
		else if (chl_sel == 1)
			out_3chl_mode2 = ch_cap_x512 / 32 * 11 + BITS(addr, 31, 14) * 10;
		else if (chl_sel == 2)
			out_3chl_mode2 = ch_cap_x512 / 32 * 10 + BITS(addr, 31, 14) * 11;
		break;
	case 2:
		if (chl_sel == 0)
			out_3chl_mode2 = ch_cap_x512 / 32 * 22 + BITS(addr, 31, 14) * 10;
		else if (chl_sel == 1)
			out_3chl_mode2 = ch_cap_x512 / 32 * 21 + BITS(addr, 31, 14) * 11;
		else if (chl_sel == 2)
			out_3chl_mode2 = ch_cap_x512 / 32 * 21 + BITS(addr, 31, 14) * 11;
		break;
	default:
		return 0;
	}

	out_3chl_mode2 = ((out_3chl_mode2 + addr_13_9_div3) << 9) | BITS(addr, 8, 0);
	chl_sel = remap_switch_table[remap_mode][chl_sel];
	chl_id  = (BITS(addr, 36, 34) << 2) + chl_sel;

	SET_BITS(oaddr, 39, 38, map_mode);
	SET_BITS(oaddr, 37, 33, chl_id);
	SET_BITS(oaddr, 32, 0, out_3chl_mode2);

	return oaddr;
}

static unsigned long
__chl2addr(unsigned long chl_addr, unsigned long ch_cap_x512,
	unsigned char remap_mode)
{
	unsigned long oaddr = 0, base = 0;
	unsigned char map_mode = BITS(chl_addr, 39, 38);
	unsigned char chl_id   = BITS(chl_addr, 37, 33);
	unsigned char module_id = BITS(chl_id, 4, 4);
	unsigned char llc_id = BITS(chl_id, 3, 2);
	unsigned char chl_sel = BITS(chl_id, 1, 0);
	unsigned char set_chl = 0;

	chl_sel = __remap_reverse(chl_sel, remap_mode);

	SET_BITS(oaddr, 39, 39, 0);
	SET_BITS(oaddr, 38, 37, map_mode);
	SET_BITS(oaddr, 36, 36, module_id);
	SET_BITS(oaddr, 35, 34, llc_id);

	if (chl_sel == 0) {
		if (BITS(chl_addr, 32, 9) < (ch_cap_x512 / 32 * 11)) {
			base = BITS(chl_addr, 32, 9);
			set_chl = 0;
		} else if (BITS(chl_addr, 32, 9) < (ch_cap_x512 / 32 * 22)) {
			base = BITS(chl_addr, 32, 9) - ch_cap_x512 / 32 * 11;
			set_chl = 1;
		} else {
			base = BITS(chl_addr, 32, 9) - ch_cap_x512 / 32 * 22;
			set_chl = 2;
		}
	} else if (chl_sel == 1) {
		if (BITS(chl_addr, 32, 9) < (ch_cap_x512 / 32 * 11)) {
			base = BITS(chl_addr, 32, 9);
			set_chl = 0;
		} else if (BITS(chl_addr, 32, 9) < (ch_cap_x512 / 32 * 21)) {
			base = BITS(chl_addr, 32, 9) - ch_cap_x512 / 32 * 11;
			set_chl = 1;
		} else {
			base = BITS(chl_addr, 32, 9) - ch_cap_x512 / 32 * 21;
			set_chl = 2;
		}

	} else if (chl_sel == 2) {
		if (BITS(chl_addr, 32, 9) < (ch_cap_x512 / 32 * 10)) {
			base = BITS(chl_addr, 32, 9);
			set_chl = 0;
		} else if (BITS(chl_addr, 32, 9) < (ch_cap_x512 / 32 * 21)) {
			base = BITS(chl_addr, 32, 9) - ch_cap_x512 / 32 * 10;
			set_chl = 1;
		} else {
			base = BITS(chl_addr, 32, 9) - ch_cap_x512 / 32 * 21;
			set_chl = 2;
		}
	}

	SET_BITS(oaddr, 33, 32, set_chl);
	if (set_chl == (2 - chl_sel)) {
		SET_BITS(oaddr, 31, 14, base / 10);
		SET_BITS(oaddr, 13, 9, base % 10 * 3 + (chl_sel + set_chl) % 3);
	} else {
		SET_BITS(oaddr, 31, 14, base / 11);
		SET_BITS(oaddr, 13, 9, base % 11 * 3 + (chl_sel + set_chl) % 3);
	}

	SET_BITS(oaddr, 8, 0, BITS(chl_addr, 8, 0));
	return oaddr;
}

static unsigned long __ile2real(unsigned long addr, unsigned long div_base)
{
	unsigned long real_paddr = 0, ile_paddr = BITS(addr, 32, 0);

	if (ile_paddr <= div_base) {
		real_paddr = ile_paddr;
	} else {
		real_paddr = div_base;
		real_paddr += ((ile_paddr - div_base) + ((ile_paddr - div_base) >> 3));
	}

	SET_BITS(real_paddr, 39, 33, BITS(addr, 39, 33));
	return real_paddr;
}

static unsigned long __real2ile(unsigned long addr, unsigned long div_base)
{
	unsigned long ile_paddr = 0, real_paddr = BITS(addr, 32, 0);

	if (real_paddr <= div_base) {
		ile_paddr = real_paddr;
	} else {
		ile_paddr = div_base + DIV_ROUND_UP((real_paddr - div_base) * 8, 9);
	}

	SET_BITS(ile_paddr, 39, 33, BITS(addr, 39, 33));
	return ile_paddr;
}

unsigned long
mlu370_address_encode(unsigned long input_addr, unsigned long ch_cap_x512,
	unsigned long div_base, unsigned int ch_remap_mode)
{
	unsigned long chl_addr = 0UL, oaddr = 0UL;

	/* 1. input_addr to chl_addr */
	chl_addr = __addr2chl(input_addr, ch_cap_x512, ch_remap_mode);

	/* 2. chl_addr to real dram addr */
	oaddr = __ile2real(chl_addr, div_base);

	return oaddr;
}

/* translate address read from norflash into address which is useable */
unsigned long
mlu370_address_decode(unsigned long encode_addr, unsigned long ch_cap_x512,
	unsigned long div_base, unsigned int ch_remap_mode, bool ile_en)
{
	unsigned long iaddr = 0UL, chl_addr = 0UL;

	/* 2. if inlineECC enable, chl_addr to user dram addr */
	chl_addr = ile_en ? __real2ile(encode_addr, div_base) : encode_addr;

	/* 3. user dram addr to user_chl_addr */
	iaddr = __chl2addr(chl_addr, ch_cap_x512, ch_remap_mode);

	return iaddr;
}

void mlu370_addr2info(unsigned long addr, unsigned char error_type,
				struct hbm_retire_info_t *info)
{
	if (!info)
		return ;

	info->hbm_num = BITS(addr, 36, 36);
	info->sys_num = BITS(addr, 35, 34);
	SET_BITS(info->pmc_num, 0, 0, 1);  /* default shuffle_en is enabled */
	SET_BITS(info->pmc_num, 2, 1, 0);  /* default interleaving_size is 512B */
	info->ecc_type = error_type;
	info->ecc_addr = BITS(addr, 33, 0) >> 9;
}

unsigned long mlu370_info2addr(struct hbm_retire_info_t info)
{
	unsigned long addr = 0;

	SET_BITS(addr, 36, 36, info.hbm_num);
	SET_BITS(addr, 35, 34, info.sys_num);
	SET_BITS(addr, 33, 0, (unsigned long)info.ecc_addr << 9);

	return addr;
}

int mlu370_size2level(unsigned long size)
{
	if (!is_power_of_2(size))
		return -EINVAL;

	if (order_base_2(size) == level_bit_shift[L1_BITS])
		return L1_BITS;

	if (order_base_2(size) == level_bit_shift[L2_BITS])
		return L2_BITS;

	return -EINVAL;
}
