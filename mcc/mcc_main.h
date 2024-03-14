#ifndef __CAMBRICON_MCCMAIN_H__
#define __CAMBRICON_MCCMAIN_H__
#include <linux/timer.h>

#define EEPROM_MAX_NUM                    (512)
#define MLU370_D2DC_RX_CRC_ERR_DURATION   (3)
#define BITS_MASK(addr, mask, lsb) (((addr) >> (lsb)) & (mask))
#define BITS(addr, msb, lsb) BITS_MASK(addr, ((1UL << ((msb) - (lsb) + 1)) - 1), lsb)

#define SET_BITS_MASK(addr, mask, lsb, val) \
	addr |= (unsigned long)((val) & (mask)) << (lsb)
#define SET_BITS(addr, msb, lsb, val) \
	SET_BITS_MASK(addr, ((1UL << ((msb) - (lsb) + 1)) - 1), lsb, val)

struct cn_mcc_ops {
	int (*get_channel_num)(void *mset);
	void *(*get_ecc_status)(void *mset);
	void (*mcc_exit)(void *mset);
	void (*repair_exit)(void *mset);
	void (*ile_exit)(void *mset);
	int (*get_d2dc_num)(void *mset);
	void *(*get_d2dc_status)(void *mset);
	void (*get_map_mode)(void *mset, unsigned int *map_mode,
						  unsigned int *hbm_idx);
	void (*get_compress_info)(void *mset, unsigned int *compress_en,
				unsigned int *compress_mode, unsigned int *compress_high_mode);
	void (*get_mem_limit_coef)(void *mset, unsigned int *limit_coef);
	void (*dump_llc_state)(void *mset);
};

struct cn_repair_ops {
	/* soft_repair & dynamic page retire ops */
	void (*get_retire_info)(void *mset, struct hbm_retire_info_t **retire_info,
			unsigned int *retire_num, int irq_flag);
	int (*get_retire_pages)(void *mset, int cause, unsigned int *pagecount,
			u64 **page_addr);
	int (*get_retire_pages_pending_status)(void *mset, int *ispending,
			int *isfailure);
	int (*get_remapped_rows)(void *mset, unsigned int *corr_rows,
			unsigned int *unc_rows, unsigned int *pending_rows,
			unsigned int *fail_rows);
	int (*retire_switch)(void *mset, int status);
	int (*ecc_irq_inject)(void *mset, u32 sys_mc_num,
			u32 mc_state, u32 ecc_addr);
	int (*get_eeprom_switch)(void *mset, int status);
	int (*get_eeprom_info)(void *mset, unsigned int **rom_info,
			unsigned int *eeprom_num);
	int (*get_sys_mc_nums)(void *mset, unsigned int *sys_mc_num);
};

struct memsys_config_st {
	union {
		struct { /* mlu370 config value */
			unsigned char shuffle_en;
			unsigned char interleave_size;
			unsigned char llc_interleave_mode;
			unsigned char llc_3chl_mode;
			unsigned char chl_remap_mode;
			unsigned int  ch_cap_x512;
		} mlu370;
		struct { /* mlu590 config value */
			unsigned char shuffle_dis;
			unsigned char interleave_size;
			unsigned char llc_interleave_mode;
			unsigned char llc_interleave_size;
			unsigned char llc_shuffle_dis;
			unsigned char llcg_interleave_mode;
			unsigned char sp_interleave_en;
			unsigned char hbm_capacity;
			unsigned char hbm_nums;
			unsigned int  hbm_bitmap;
			unsigned char llc_compress_dis;
			unsigned char llc_compress_mode;
			unsigned char llc_compress_high_mode;
			unsigned char hbm_mem_size_limit;
		} mlu590;
	};
};

struct cn_mcc_set {
	void *core;

	/*ecc status length depend on chip type*/
	void *ecc_status;

	/*d2dc status length depend on chip type*/
	void *d2dc_status;

	const struct cn_mcc_ops *mcc_ops;

	/* hbm soft_repair eeprom error information*/
	void *repair_set;
	const struct cn_repair_ops *repair_ops;

	struct timer_list mcc_timer;

	struct memsys_config_st msys_config;
};



extern int ddr_init_mlu270(struct cn_mcc_set *mcc_set);

extern int hbm_init_mlu290(struct cn_mcc_set *mcc_set);

extern int ddr_init_mlu370(struct cn_mcc_set *mcc_set);

extern int ddr_retire_init_mlu370(struct cn_mcc_set *mcc_set);

extern int hbm_repair_init_mlu290(struct cn_mcc_set *mcc_set);

extern int hbm_llc_noc_init_mlu590(struct cn_mcc_set *mcc_set);

extern int gddr_init_mlu580(struct cn_mcc_set *mcc_set);
#ifndef CONFIG_CNDRV_EDGE
int cn_bus_refresh_soft_repair_info(void *bus_set, unsigned int *info, unsigned int count);
int cn_bus_get_soft_repair_info(void *bus_set, unsigned int *info, unsigned int *count);
#else

static inline int cn_bus_refresh_soft_repair_info(void *bus_set, unsigned int *info, unsigned int count)
{
	return -1;
}
static inline int cn_bus_get_soft_repair_info(void *bus_set, unsigned int *info, unsigned int *count)
{
	return -1;
}
#endif


#endif
