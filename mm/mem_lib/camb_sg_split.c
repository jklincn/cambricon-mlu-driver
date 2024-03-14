#include <linux/scatterlist.h>
#include <linux/slab.h>
struct sg_splitter {
	struct scatterlist *in_sg0;
	int nents;
	off_t skip_sg0;
	unsigned int length_last_sg;

	struct scatterlist *out_sg;
};

static int sg_calculate_split(struct scatterlist *in, int nents, int nb_splits,
			      off_t skip, const size_t *sizes,
			      struct sg_splitter *splitters, bool mapped)
{
	int i;
	unsigned int sglen;
	size_t size = sizes[0], len;
	struct sg_splitter *curr = splitters;
	struct scatterlist *sg;

	for (i = 0; i < nb_splits; i++) {
		splitters[i].in_sg0 = NULL;
		splitters[i].nents = 0;
	}

	for_each_sg(in, sg, nents, i) {
		sglen = mapped ? sg_dma_len(sg) : sg->length;
		if (skip > sglen) {
			skip -= sglen;
			continue;
		}

		len = min_t(size_t, size, sglen - skip);
		if (!curr->in_sg0) {
			curr->in_sg0 = sg;
			curr->skip_sg0 = skip;
		}
		size -= len;
		curr->nents++;
		curr->length_last_sg = len;

		while (!size && (skip + len < sglen) && (--nb_splits > 0)) {
			curr++;
			size = *(++sizes);
			skip += len;
			len = min_t(size_t, size, sglen - skip);

			curr->in_sg0 = sg;
			curr->skip_sg0 = skip;
			curr->nents = 1;
			curr->length_last_sg = len;
			size -= len;
		}
		skip = 0;

		if (!size && --nb_splits > 0) {
			curr++;
			size = *(++sizes);
		}

		if (!nb_splits)
			break;
	}

	return (size || !splitters[0].in_sg0) ? -EINVAL : 0;
}

static void sg_split_phys(struct sg_splitter *splitters, const int nb_splits)
{
	int i, j;
	struct scatterlist *in_sg, *out_sg;
	struct sg_splitter *split;

	for (i = 0, split = splitters; i < nb_splits; i++, split++) {
		in_sg = split->in_sg0;
		out_sg = split->out_sg;
		for (j = 0; j < split->nents; j++, out_sg++) {
			*out_sg = *in_sg;
			if (!j) {
				out_sg->offset += split->skip_sg0;
				out_sg->length -= split->skip_sg0;
			} else {
				out_sg->offset = 0;
			}
			sg_dma_address(out_sg) = 0;
			sg_dma_len(out_sg) = 0;
			in_sg = sg_next(in_sg);
		}
		out_sg[-1].length = split->length_last_sg;
		sg_mark_end(out_sg - 1);
	}
}

static void sg_split_mapped(struct sg_splitter *splitters, const int nb_splits)
{
	int i, j;
	struct scatterlist *in_sg, *out_sg;
	struct sg_splitter *split;

	for (i = 0, split = splitters; i < nb_splits; i++, split++) {
		in_sg = split->in_sg0;
		out_sg = split->out_sg;
		for (j = 0; j < split->nents; j++, out_sg++) {
			sg_dma_address(out_sg) = sg_dma_address(in_sg);
			sg_dma_len(out_sg) = sg_dma_len(in_sg);
			if (!j) {
				sg_dma_address(out_sg) += split->skip_sg0;
				sg_dma_len(out_sg) -= split->skip_sg0;
			}
			in_sg = sg_next(in_sg);
		}
		sg_dma_len(--out_sg) = split->length_last_sg;
	}
}

/**
 * sg_split - split a scatterlist into several scatterlists
 * @in: the input sg list
 * @in_mapped_nents: the result of a dma_map_sg(in, ...), or 0 if not mapped.
 * @skip: the number of bytes to skip in the input sg list
 * @nb_splits: the number of desired sg outputs
 * @split_sizes: the respective size of each output sg list in bytes
 * @out: an array where to store the allocated output sg lists
 * @out_mapped_nents: the resulting sg lists mapped number of sg entries. Might
 *                    be NULL if sglist not already mapped (in_mapped_nents = 0)
 * @gfp_mask: the allocation flag
 *
 * This function splits the input sg list into nb_splits sg lists, which are
 * allocated and stored into out.
 * The @in is split into :
 *  - @out[0], which covers bytes [@skip .. @skip + @split_sizes[0] - 1] of @in
 *  - @out[1], which covers bytes [@skip + split_sizes[0] ..
 *                                 @skip + @split_sizes[0] + @split_sizes[1] -1]
 * etc ...
 * It will be the caller's duty to kfree() out array members.
 *
 * Returns 0 upon success, or error code
 */
int cn_sg_split(struct scatterlist *in, const int in_mapped_nents,
	     const off_t skip, const int nb_splits,
	     const size_t *split_sizes,
	     struct scatterlist **out, int *out_mapped_nents,
	     gfp_t gfp_mask)
{
	int i, ret;
	struct sg_splitter *splitters;

	splitters = kcalloc(nb_splits, sizeof(*splitters), gfp_mask);
	if (!splitters)
		return -ENOMEM;

	ret = sg_calculate_split(in, sg_nents(in), nb_splits, skip, split_sizes,
			   splitters, false);
	if (ret < 0)
		goto err;

	ret = -ENOMEM;
	for (i = 0; i < nb_splits; i++) {
		splitters[i].out_sg = kmalloc_array(splitters[i].nents,
						    sizeof(struct scatterlist),
						    gfp_mask);
		if (!splitters[i].out_sg)
			goto err;
	}

	/*
	 * The order of these 3 calls is important and should be kept.
	 */
	sg_split_phys(splitters, nb_splits);
	ret = sg_calculate_split(in, in_mapped_nents, nb_splits, skip,
				 split_sizes, splitters, true);
	if (ret < 0)
		goto err;

	sg_split_mapped(splitters, nb_splits);

	for (i = 0; i < nb_splits; i++) {
		out[i] = splitters[i].out_sg;
		if (out_mapped_nents)
			out_mapped_nents[i] = splitters[i].nents;
	}

	kfree(splitters);
	return 0;

err:
	for (i = 0; i < nb_splits; i++)
		kfree(splitters[i].out_sg);
	kfree(splitters);
	return ret;
}

/**
 * sg_alloc_table_from_pages - Allocate and initialize an sg table from
 *                             an array of pages
 * @sgt:        The sg table header to use
 * @pages:      Pointer to an array of page pointers
 * @n_pages:    Number of pages in the pages array
 * @offset:     Offset from start of the first page to the start of array of page pointers
 * @size:       Number of valid bytes in the buffer (after offset)
 * @gfp_mask:   GFP allocation mask
 *
 *  Description:
 *    Allocate and initialize an sg table from a list of pages. Contiguous
 *    ranges of the pages are squashed into a single scatterlist node. A user
 *    may provide an offset at a start and a size of valid data in a buffer
 *    specified by the page array. The returned sg table is released by
 *    sg_free_table.
 *
 * Returns:
 *   0 on success, negative error on failure
 *
 * NOTE:
 * strengthen offset than original interface
 */
int cn_sg_alloc_table_from_pages(struct sg_table *sgt,
		struct page **pages, unsigned int n_pages,
		unsigned long offset, unsigned long size,
		gfp_t gfp_mask)
{
	unsigned int chunks;
	unsigned int i;
	unsigned int cur_page;
	int ret;
	struct scatterlist *s;
	unsigned long page_index = 0;

	/* compute number of contiguous chunks */
	for (i = 1; i < n_pages; ++i) {
		if (page_to_pfn(pages[i]) != page_to_pfn(pages[i - 1]) + 1) {
			if (offset >= i * PAGE_SIZE) {
				page_index = i;
			} else {
				break;
			}
		}
	}

	pages += page_index;
	n_pages -= page_index;
	offset -= page_index * PAGE_SIZE;

	/* compute number of contiguous chunks */
	chunks = 1;
	for (i = 1; i < n_pages; ++i) {
		if (page_to_pfn(pages[i]) != page_to_pfn(pages[i - 1]) + 1)
			++chunks;
	}

	ret = sg_alloc_table(sgt, chunks, gfp_mask);
	if (unlikely(ret))
		return ret;

	/* merging chunks and putting them into the scatterlist */
	cur_page = 0;
	for_each_sg(sgt->sgl, s, sgt->orig_nents, i) {
		unsigned long chunk_size;
		unsigned int j;

		/* look for the end of the current chunk */
		for (j = cur_page + 1; j < n_pages; ++j)
			if (page_to_pfn(pages[j]) !=
					page_to_pfn(pages[j - 1]) + 1)
				break;

		chunk_size = ((j - cur_page) << PAGE_SHIFT) - offset;
		sg_set_page(s, pages[cur_page], min(size, chunk_size), offset);
		size -= chunk_size;
		offset = 0;
		cur_page = j;
		if (!size) {
			sg_mark_end(s);
			break;
		}
	}

	return 0;
}

int cn_sg_clear_offset(struct scatterlist *sgl)
{
	struct page *page = sg_page(sgl);

	if (unlikely(sgl->offset & (~PAGE_MASK))) {
		pr_err("sgl offset is not align PAGE_SIZE\n");
		return -1;
	}

	if (unlikely(!sgl->offset)) {
		return 0;
	}

	/*clear offset*/
	page = pfn_to_page(sg_phys(sgl) >> PAGE_SHIFT);

	sg_set_page(sgl, page, sgl->length, 0);

	return 0;
}

int cn_sg_get_sub(struct scatterlist *in, const int in_mapped_nents,
		const off_t skip, const size_t size,
		struct scatterlist **out, int *out_mapped_nents,
		gfp_t gfp_mask)
{
	unsigned long total_size = 0, osize[2] = {0};
	struct scatterlist *sg, *tmpsg[2];
	int ocounts[2] = {0};
	int ret = 0, nb_splits = 2, i = 0;

	for_each_sg(in, sg, in_mapped_nents, i)
		total_size += sg->length;

	osize[0] = size;
	osize[1] = total_size - skip - size;

	if (!osize[1])
		nb_splits = 1;

	ret = cn_sg_split(in, in_mapped_nents, skip, nb_splits, osize,
				tmpsg, ocounts, GFP_KERNEL);
	if (ret)
		return ret;

	if (nb_splits == 2)
		kfree(tmpsg[1]);

	*out = tmpsg[0];
	*out_mapped_nents = ocounts[0];
	return 0;
}
