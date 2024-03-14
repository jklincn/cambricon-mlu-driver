#ifndef __CNDRV_OB_REMAP_MM__
#define __CNDRV_OB_REMAP_MM__

#define OB_RPC_CONFIG (0x1)
#define OB_MAP_ERROR (0x2)
#define OB_MAP_COMPLETE (0x3)
#define OB_INIT (0x4)
struct ob_map_t {
	unsigned long iova_size;
	unsigned long device_pa;
	unsigned long iova;
	/**
	 * NOTE: For host vaddr input to do ob map, device_va is equal to iova,
	 * If device vaddr input to do ob map, device_va is input address.
	 **/
	unsigned long device_va;
	struct list_head list_node;
	/*iova is cn_get_page_size() align*/
	struct sg_table *table;
	void *priv;
	void (*sgt_release)(void *priv, struct sg_table *table);
	int status;
	int card_id;
	struct cn_mm_set *mm_set;
};

static inline size_t
camb_dob_size_align(size_t size, struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = mm_set->core;
	unsigned int lvl1_pg, lvl2_pg;
	unsigned int lvl1_pg_cnt, lvl2_pg_cnt;
	u64 lvl1_base, lvl2_base;

	size = PAGE_ALIGN(size);

	if (mm_set->lvl1_size && mm_set->lvl2_size) {
		goto align;
	}

	if (cn_bus_get_dob_win_info(core->bus_set, &lvl1_pg, &lvl1_pg_cnt, &lvl1_base,
					&lvl2_pg, &lvl2_pg_cnt, &lvl2_base)) {
		cn_dev_err("get lvl page error.");
		return 0;
	}

	mm_set->lvl1_size = 1 << lvl1_pg;
	mm_set->lvl2_size = 1 << lvl2_pg;

align:
	if (size > (mm_set->lvl2_size >> 1)) {
		/*lvl2_size need is 2 order*/
		return ALIGN(size, mm_set->lvl2_size);
	}

	/*lvl1_size need is 2 order*/
	return ALIGN(size, mm_set->lvl1_size);
}

int camb_search_ob_map(struct list_head *head, int card_id,
			struct ob_map_t **obmap);
struct ob_map_t *camb_init_ob_map(struct sg_table *table, void *priv,
	void (*sgt_release)(void *, struct sg_table *), unsigned long size, struct cn_mm_set *mm_set, dev_addr_t iova);
int camb_map_ob_win(struct ob_map_t *ob, int is_map_iova);
int camb_release_ob_map(struct ob_map_t *ob_map);
#endif
