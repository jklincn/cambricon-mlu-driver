//#define DEBUG
#define pr_fmt(fmt) "[mlu_peer_mem:%s:%d] " fmt, __func__, __LINE__
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/hugetlb.h>
#include <linux/pci.h>

#include "cndrv_pre_compile.h"
#include "peer_mem.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"

#define DRV_NAME "mlu_peer_mem"
#define DRV_VERSION "0.1.0"

//#define MLU_MLNX_IB_PEER_MEM_SYMBOLS_PRESENT

MODULE_AUTHOR("Cambricon System Software Group");
MODULE_LICENSE("Dual BSD/GPL");

#if defined(MLU_MLNX_IB_PEER_MEM_SYMBOLS_PRESENT)

static void *reg_handle = NULL;

struct mlu_mem_context {
	u64 core_context;
    u64 page_virt_start;
    u64 page_virt_end;
    size_t mapped_size;
	u32 mlu_id;
	u64 page_size;
	u64 npages;
	struct sg_table *pin_mem;
	int sg_allocated;
};

#define MLU_PAGE_SHIFT 14
#define MLU_PAGE_SIZE ((u64)1 << MLU_PAGE_SHIFT)
#define MLU_PAGE_OFFSET  (MLU_PAGE_SIZE-1)
#define MLU_PAGE_MASK    (~MLU_PAGE_OFFSET)

static int mlu_mem_acquire(unsigned long addr, size_t size, void *peer_mem_private_data,
		char *peer_mem_name, void **client_context)
{
	struct mlu_mem_context *mlu_mem_context;

	pr_debug("%s begin.\n", __func__);
	pr_debug("addr:0x%lx, size:0x%lx\n", addr, (unsigned long)size);

	if (!addr_is_udvm(addr)) {
		pr_debug("not mlu address\n");
		return 0;
	}

	pr_debug("mlu address\n");

	mlu_mem_context = kzalloc(sizeof(*mlu_mem_context), GFP_KERNEL);
	if (!mlu_mem_context) {
		pr_err("failed to allocate memory for context.\n");
		return 0;
	}

	mlu_mem_context->page_virt_start = addr & MLU_PAGE_MASK;
	mlu_mem_context->page_virt_end = (addr + size + MLU_PAGE_SIZE - 1) & MLU_PAGE_MASK;
    mlu_mem_context->mapped_size  = mlu_mem_context->page_virt_end - mlu_mem_context->page_virt_start;
	mlu_mem_context->mlu_id = udvm_get_cardid_from_addr(addr);

	pr_debug("mlu_id %d", mlu_mem_context->mlu_id);

	*client_context = mlu_mem_context;
	//__module_get(THIS_MODULE);
	return 1;
}

int __dump_table(struct sg_table *table)
{
	int i;
	size_t size = 0;
	int cnt;

	pr_info("table:%#llx", (u64)table);
	pr_info("table sgl:%#llx", (u64)table->sgl);
	pr_info("table nents:%#llx", (u64)table->nents);
	pr_info("table orig_nents:%#llx", (u64)table->orig_nents);

	cnt = sg_nents(table->sgl);
	/*This debug function maybe error,if sg is chain*/
	for (i = 0; i < cnt; i++) {
		pr_info("sgl[%d] page link:%#llx", i, (u64)table->sgl[i].page_link);
		pr_info("sgl[%d] offset:%#llx", i, (u64)table->sgl[i].offset);
		pr_info("sgl[%d] length:%#llx", i, (u64)table->sgl[i].length);
		pr_info("sgl[%d] dma_address:%#llx", i, (u64)table->sgl[i].dma_address);
		pr_info("sgl[%d] pfn:%lld", i, (u64)page_to_pfn(sg_page(&table->sgl[i])));
		size += table->sgl[i].length;
	}

	pr_info("table total size:%#llx", (u64)size);

	return 0;
}

static int mlu_mem_get_pages(unsigned long addr, size_t size, int write, int force,
		struct sg_table *sg_head, void *client_context, u64 core_context)
{
	int ret = 0;
	struct mlu_mem_context *mlu_mem_context;

	pr_debug("%s begin\n", __func__);
	pr_debug("addr:0x%lx,size:0x%lx\n", addr, (unsigned long)size);

	mlu_mem_context = (struct mlu_mem_context *)client_context;
	if (!mlu_mem_context) {
		pr_warn("Invalid client context\n");
		return -EINVAL;
	}

	mlu_mem_context->page_size = MLU_PAGE_SIZE;
	mlu_mem_context->core_context = core_context;

	ret = cn_mem_p2p_pin_mem(mlu_mem_context->page_virt_start,
			mlu_mem_context->mapped_size, &mlu_mem_context->pin_mem);
	if (ret < 0) {
		pr_err("cn_mem_p2p_pin_mem failed\n");
		return ret;
	}

	//__dump_table(mlu_mem_context->pin_mem);

	pr_debug("%s end\n", __func__);

	return 0;
}

static int mlu_mem_dma_map(struct sg_table *sg_head, void *client_context,
			   struct device *dma_device, int dmasync, int *nmap)
{
    int i, j, ret = 0;
	struct scatterlist *pin_sg, *sg, *tmp_sg;
	struct mlu_mem_context *mlu_mem_context =
		(struct mlu_mem_context *)client_context;
	u64 mapped_size, page_size, dma_addr = 0, tmp_size, tmp_npages;
	struct sg_table *pin_mem = mlu_mem_context->pin_mem;

	pr_debug("%s begin\n", __func__);

	page_size = mlu_mem_context->page_size;
	mapped_size  = mlu_mem_context->mapped_size;

	pr_debug("page start addr:0x%llx,mapped size:0x%lx\n",
			mlu_mem_context->page_virt_start, mlu_mem_context->mapped_size);

	//pr_debug("phy addr:0x%llx\n", phy_addr);
	pin_mem->nents = dma_map_sg(dma_device, pin_mem->sgl,
			pin_mem->orig_nents, DMA_BIDIRECTIONAL);
	if (!pin_mem->nents) {
		pr_err("failed to map scatterlist");
		return -1;
	}

	mlu_mem_context->npages = mapped_size / page_size;

	//__dump_table(pin_mem);

	ret = sg_alloc_table(sg_head, mlu_mem_context->npages, GFP_KERNEL);
	if (ret)
		return ret;

	mlu_mem_context->sg_allocated = 1;
	tmp_sg = sg_head->sgl;

	for_each_sg(pin_mem->sgl, pin_sg, pin_mem->nents, j) {

		dma_addr = sg_dma_address(pin_sg);
		tmp_size = sg_dma_len(pin_sg);
		tmp_npages = tmp_size / page_size;

		for_each_sg(tmp_sg, sg, tmp_npages, i) {
			sg_set_page(sg, NULL, page_size, 0);
			sg_dma_address(sg) = dma_addr + i * page_size;
			sg_dma_len(sg) = page_size;
		}
		tmp_sg = sg;
	}

	*nmap = mlu_mem_context->npages;

	pr_debug("sg_head %#llx, client_context %#llx.", (__u64)sg_head, (__u64)client_context);
	pr_debug("%s end\n", __func__);

	return ret;
}

static void mlu_mem_put_pages(struct sg_table *sg_head, void *client_context)
{
	struct mlu_mem_context *mlu_mem_context =
		(struct mlu_mem_context *)client_context;

	pr_debug("%s begin\n", __func__);
	pr_debug("put_pages: sg_head 0x%px, client_context 0x%px.\n", sg_head,
	      client_context);

    if (mlu_mem_context->pin_mem != NULL) {
		cn_mem_p2p_unpin_mem(mlu_mem_context->page_virt_start, mlu_mem_context->pin_mem);
    }

	pr_debug("%s end\n", __func__);
}

static int mlu_mem_dma_unmap(struct sg_table *sg_head, void *client_context,
			     struct device *dma_device)
{
	int ret = 0;
	struct mlu_mem_context *mlu_mem_context =
		(struct mlu_mem_context *)client_context;
	struct sg_table *pin_mem = mlu_mem_context->pin_mem;

    if (!mlu_mem_context) {
        pr_err("mlu_dma_unmap -- invalid mlu_mem_context\n");
        return -EINVAL;
    }

	if (mlu_mem_context->sg_allocated) {
		sg_free_table(sg_head);
		mlu_mem_context->sg_allocated = 0;
	}

	if (pin_mem) {
		dma_unmap_sg(dma_device, pin_mem->sgl, pin_mem->orig_nents, DMA_BIDIRECTIONAL);
		mlu_mem_context->npages = 0;
	}

	pr_debug("sg_head 0x%px, client_context 0x%px.", sg_head, client_context);

	return ret;
}

static unsigned long mlu_mem_get_page_size(void *client_context)
{
	struct mlu_mem_context *mlu_mem_context =
		(struct mlu_mem_context *)client_context;

	pr_debug("page size %llu\n", mlu_mem_context->page_size);

	return mlu_mem_context->page_size;
}

static void mlu_mem_release(void *client_context)
{
	struct mlu_mem_context *mlu_mem_context =
		(struct mlu_mem_context *) client_context;

	kfree(mlu_mem_context);
	// module_put(THIS_MODULE);
	pr_debug("%s end\n", __func__);
}

static struct peer_memory_client mlu_mem_client = {
	.acquire		= mlu_mem_acquire,
	.get_pages		= mlu_mem_get_pages,
	.dma_map		= mlu_mem_dma_map,
	.dma_unmap		= mlu_mem_dma_unmap,
	.put_pages		= mlu_mem_put_pages,
	.get_page_size	= mlu_mem_get_page_size,
	.release		= mlu_mem_release,
};
#endif

static int __init mlu_mem_client_init(void)
{
#if defined (MLU_MLNX_IB_PEER_MEM_SYMBOLS_PRESENT)
	int status = 0;

	strcpy(mlu_mem_client.name, DRV_NAME);
	strcpy(mlu_mem_client.version, DRV_VERSION);

	reg_handle = ib_register_peer_memory_client(&mlu_mem_client, NULL);
	if (!reg_handle) {
		pr_err("Cannot register peer memory client.\n");
		status = -EINVAL;
		goto exit;
	}

	pr_info("PeerDirect support was initialized successfully\n");

exit:
	if (status) {
		if (reg_handle) {
			ib_unregister_peer_memory_client(reg_handle);
			reg_handle = NULL;
		}
	}

	return status;
#else
	return -EINVAL;
#endif
}

static void __exit mlu_mem_client_exit(void)
{
#if defined (MLU_MLNX_IB_PEER_MEM_SYMBOLS_PRESENT)
	if (reg_handle)
		ib_unregister_peer_memory_client(reg_handle);
#endif
}

module_init(mlu_mem_client_init);
module_exit(mlu_mem_client_exit);
