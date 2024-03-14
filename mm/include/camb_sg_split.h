#ifndef __CN_MEM_SG_SPLIT_H_
#define __CN_MEM_SG_SPLIT_H_
int cn_sg_split(struct scatterlist *in, const int in_mapped_nents,
	     const off_t skip, const int nb_splits,
	     const size_t *split_sizes,
	     struct scatterlist **out, int *out_mapped_nents,
	     gfp_t gfp_mask);

int cn_sg_alloc_table_from_pages(struct sg_table *sgt,
		struct page **pages, unsigned int n_pages,
		unsigned long offset, unsigned long size,
		gfp_t gfp_mask);

int cn_sg_clear_offset(struct scatterlist *sgl);
int cn_sg_get_sub(struct scatterlist *in, const int in_mapped_nents,
		const off_t skip, const size_t size,
		struct scatterlist **out, int *out_mapped_nents,
		gfp_t gfp_mask);
#endif
