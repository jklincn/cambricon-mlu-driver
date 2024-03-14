#ifndef __CAMBRICON_MM_EXT_H__
#define __CAMBRICON_MM_EXT_H__
int camb_split_sg_table(struct mapinfo *pminfo, dev_addr_t map_addr, __u64 map_size,
		struct sg_table *table, struct sg_table *out_table, void *mem_set);

void *camb_mem_map_kernel(struct sg_table *table, int cached);
#endif
