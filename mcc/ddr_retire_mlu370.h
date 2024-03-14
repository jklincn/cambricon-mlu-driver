#ifndef __CAMBRICON_RETIRE_MLU370_H__
#define __CAMBRICON_RETIRE_MLU370_H__
#include <linux/radix-tree.h>

/* Current support mlu370 system memory mapping config and llc remap config*/
#define SHUFFLE_STATUS  (1) /* shuffle enable */
#define INTERLEAVE_SIZE (0) /* 512B interleave size */
#define LLC_INTERLEAVE_MODE (2) /* llc 3channel interleave mode */
#define LLC_3CHL_MODE   (1) /* llc 3channel no waste interleave */

enum {
	L1_BITS = 1,
	L2_BITS = 2,
	MAX_LEVEL,
};

/* NOTE: if want to change l1 per_bit_size, just modify level_bit_shift for L1_BITS,
 * and input base and size must be aligned with per_bit_size. L2_BITS's level_bit_shift
 * is fixed, can't be changed. */
static unsigned int level_bit_shift[MAX_LEVEL] = {
	[0] = -1, [1] = 20, [2] = 9,
};

struct level_bits_t {
	struct radix_tree_root l2_root; /* only validate, if level set as 1 */
	rwlock_t l2_root_lock; /* lock with bit_set and radix_tree insert */

	unsigned long base;
	unsigned long size;
	unsigned int per_bit_shift;
	unsigned int level;
	unsigned long bits[0];
};

struct retire_bits_t {
	unsigned int llc_counts;
	unsigned int chls_per_llc;
	struct level_bits_t **l1_bits;
	void *retire_set;
};

int mlu370_retire_set_addr(struct retire_bits_t *retire_bits,
			unsigned long addr);
struct retire_bits_t *mlu370_retire_bitmap_init(struct cn_mcc_set *mcc_set,
			void *retire_set, unsigned int msys_cnt, unsigned long per_chl_sz,
			unsigned long div_base);
void mlu370_retire_bitmap_exit(void *retire_bitmap);
void mlu370_addr2info(unsigned long addr, unsigned char error_type,
				struct hbm_retire_info_t *info);
unsigned long mlu370_info2addr(struct hbm_retire_info_t info);
unsigned long
mlu370_address_decode(unsigned long encode_addr, unsigned long ch_cap_x512,
	unsigned long div_base, unsigned int ch_remap_mode, bool ile_en);
unsigned long
mlu370_address_encode(unsigned long input_addr, unsigned long ch_cap_x512,
	unsigned long div_base, unsigned int ch_remap_mode);

int mlu370_size2level(unsigned long size);

int mlu370_retire_find_addr(struct retire_bits_t *retire_bits,
			unsigned int msys_idx, unsigned int chl_idx, unsigned long *eaddr,
			bool (*addr_is_bad)(void *, unsigned long, unsigned long,
				unsigned int, unsigned int, bool));

int mlu370_retire_create_host_buffer(void **host_buffer);
void mlu370_retire_destroy_host_buffer(void *host_buffer);

int mlu370_retire_create_shm_buffer(struct cn_core_set *core,
		unsigned long *dev_vaddr, unsigned long *host_vaddr);
void mlu370_retire_destroy_shm_buffer(struct cn_core_set *core,
		unsigned long dev_vaddr, unsigned long host_vaddr);

#endif /* __CAMBRICON_RETIRE_MLU370_H__ */
