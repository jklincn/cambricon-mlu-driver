#include <linux/module.h>
#include <linux/init.h>
#include <linux/scatterlist.h>
#include <linux/pci.h>
#include <linux/list.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "pcie_dma.h"
#include "cndrv_pci.h"
#include "cndrv_mm.h"
#include "cndrv_domain.h"
#include "cndrv_debug.h"

//#include <rdma/peer_mem.h>
#define IB_PEER_MEMORY_NAME_MAX 64
#define IB_PEER_MEMORY_VER_MAX 16

struct peer_memory_client {
	char	name[IB_PEER_MEMORY_NAME_MAX];
	char	version[IB_PEER_MEMORY_VER_MAX];
	/* acquire return code: 1-mine, 0-not mine */
	int (*acquire)(unsigned long addr, size_t size,
			void *peer_mem_private_data,
					char *peer_mem_name,
					void **client_context);
	int (*get_pages)(unsigned long addr,
			  size_t size, int write, int force,
			  struct sg_table *sg_head,
			  void *client_context, u64 core_context);
	int (*dma_map)(struct sg_table *sg_head, void *client_context,
			struct device *dma_device, int dmasync, int *nmap);
	int (*dma_unmap)(struct sg_table *sg_head, void *client_context,
			   struct device  *dma_device);
	void (*put_pages)(struct sg_table *sg_head, void *client_context);
	unsigned long (*get_page_size)(void *client_context);
	void (*release)(void *client_context);
	void* (*get_context_private_data)(u64 peer_id);
	void (*put_context_private_data)(void *context);
};

typedef int (*invalidate_peer_memory)(void *reg_handle,
					  void *core_context);

void *ib_register_peer_memory_client(struct peer_memory_client *peer_client,
				  invalidate_peer_memory *invalidate_callback);
void ib_unregister_peer_memory_client(void *reg_handle);


static void* (*pfn_ib_register_peer_memory_client)(struct peer_memory_client *peer_client,
					invalidate_peer_memory *invalidate_callback);

static void (*pfn_ib_unregister_peer_memory_client)(void *reg_handle);


//#define pr_fmt(fmt) "[%s:%d][CPU %d] " fmt, __func__, __LINE__,  raw_smp_processor_id()

#ifndef DRV_NAME
#define DRV_NAME "cambricon_peer_mem"
#endif
#define MDR_VERSION "0.1.0"

static void *reg_handle;
static DEFINE_MUTEX(ib_lock);

#define IB_INIT       0
#define IB_REGISTER   1
#define IB_EXIT       2
#define IB_REGISTER_FAIL   3
extern int ib_state;

struct mlu_mem_context {
	u64 va;
	size_t size;
	u32 mlu_id;
	u64 device_id;
	u64 page_size;
	u64 npages;
	u64 core_context;
	struct cn_pcie_set *pcie_set;
	int pcibar;
};

#define MEM_TYPE_MASK 0xffff000000000000
#define MEM_TYPE_SHIFT 48
#define MLU_ID_MASK 0x00ff000000000000
#define MLU_ID_SHIFT 48
#define MLU_PAGE_SHIFT 12
#define MLU_PAGE_SIZE ((u64)1 << MLU_PAGE_SHIFT)

static int is_mlu_address(unsigned long addr)
{
	addr = addr & MEM_TYPE_MASK;
	if (addr == 0xffff000000000000 || addr == 0x0000000000000000)
		return 0;
	return 1;
}

static struct cn_pcie_set *get_pcie_set(void *client_context)
{
	struct mlu_mem_context *mlu_mem_context =
		(struct mlu_mem_context *)client_context;
	struct cn_core_set *core_set;
	struct cn_bus_set *bus_set;
	struct cn_pcie_set *pcie_set;

	core_set = cn_core_get_with_idx(mlu_mem_context->mlu_id);
	mlu_mem_context->device_id = core_set->device_id;
	bus_set = (struct cn_bus_set *) core_set->bus_set;
	pcie_set = (struct cn_pcie_set *) bus_set->priv;
	return pcie_set;
}

static int mlu_mem_acquire(unsigned long addr, size_t size, void *peer_mem_private_data,
		char *peer_mem_name, void **client_context)
{
	int ret = 0;
	int bar_index;
	struct mlu_mem_context *mlu_mem_context;

	pr_debug("%s begin.\n", __func__);
	pr_debug("addr:0x%lx, size:0x%lx\n", addr, (unsigned long)size);

	ret = is_mlu_address(addr);
	if (!ret) {
		pr_debug("not mlu address\n");
		return 0;
	}

	pr_debug("mlu address\n");

	mlu_mem_context = cn_kzalloc(sizeof(*mlu_mem_context), GFP_KERNEL);
	if (!mlu_mem_context) {
		pr_err("failed to allocate memory for context.\n");
		return 0;
	}

	mlu_mem_context->va = addr & ~MEM_TYPE_MASK;
	mlu_mem_context->size = size;
	mlu_mem_context->mlu_id = (addr & MLU_ID_MASK) >> MLU_ID_SHIFT;
	mlu_mem_context->pcie_set = get_pcie_set(mlu_mem_context);

	if (mlu_mem_context->device_id != MLUID_370) {
		bar_index = 2;
		if (!mlu_mem_context->pcie_set->mdr_resource)
			mlu_mem_context->pcie_set->mdr_resource =
				pcie_get_specific_bar(bar_index, mlu_mem_context->pcie_set);
	} else
		bar_index = 0;

	mlu_mem_context->pcibar = bar_index;

	pr_debug("mlu_id %d", mlu_mem_context->mlu_id);

	*client_context = mlu_mem_context;
	//__module_get(THIS_MODULE);
	return 1;
}

static int mlu_mem_get_pages(unsigned long addr, size_t size, int write, int force,
		struct sg_table *sg_head, void *client_context, u64 core_context)
{
	struct mlu_mem_context *mlu_mem_context =
		(struct mlu_mem_context *)client_context;

	pr_debug("%s begin\n", __func__);
	pr_debug("addr:0x%lx,size:0x%lx\n", addr, (unsigned long)size);

	if (!mlu_mem_context) {
		pr_warn("Invalid client context\n");
		return -EINVAL;
	}

	mlu_mem_context->page_size = MLU_PAGE_SIZE;
	mlu_mem_context->core_context = core_context;

	pr_debug("%s end\n", __func__);

	return 0;
}

#define SHARE_MEM_OFFSET 0x8000000
#define MDR_OFFSET 0x4000000
#define MDR_SIZE 0x4000000
static int mlu_mem_dma_map(struct sg_table *sg_head, void *client_context,
			   struct device *dma_device, int dmasync, int *nmap)
{
	struct scatterlist *sg;
	struct mlu_mem_context *mlu_mem_context =
		(struct mlu_mem_context *)client_context;
	int ret, i;
	u64 offset_in_page, size, page_size;
	u32 chunks;
	u64 bus_addr;
	u64 axi_addr;
	u64 bar_base, offset_in_mdr;
	struct cn_pcie_set *pcie_set;
	int bar_index;
	struct bar_resource *mdr_resource;

	pr_debug("%s begin\n", __func__);

	page_size = mlu_mem_context->page_size;
	offset_in_page = mlu_mem_context->va & (page_size - 1);
	size = mlu_mem_context->size;
	chunks = (size  + offset_in_page + page_size - 1) / page_size;
	pcie_set = mlu_mem_context->pcie_set;
	mdr_resource = pcie_set->mdr_resource;
	bar_index = mlu_mem_context->pcibar;

	//if (cn_pci_lock_bar(pcie_set, &bar_index))
	//	return -1;

	if (!pcie_set->ops->set_bar_window) {
		cn_dev_pcie_err(pcie_set, "set_bar_window is NULL");
		return -EINVAL;
	}

	if (mlu_mem_context->device_id != MLUID_370) {
		axi_addr = pcie_set->ops->set_bar_window(mlu_mem_context->va, mdr_resource, pcie_set);
		bus_addr = mdr_resource->phy_base + mlu_mem_context->va - axi_addr;
		pr_debug("peer mem bar addr %#llx, axi addr %#llx, bus addr %#llx\n",
			pcie_set->pcibar[bar_index].base, axi_addr, bus_addr);
	} else {
		offset_in_mdr = mlu_mem_context->va % MDR_SIZE;
		bar_base = pci_resource_start(pcie_set->pdev, bar_index);
		bus_addr = bar_base + SHARE_MEM_OFFSET + MDR_OFFSET + offset_in_mdr;
		pr_debug("peer mem bar addr %#llx, offset_in_mdr %#llx, bus addr %#llx\n",
			bar_base, offset_in_mdr, bus_addr);
	}

	mlu_mem_context->npages = chunks;

	ret = sg_alloc_table(sg_head, chunks, GFP_KERNEL);
	if (ret)
		return ret;

	for_each_sg(sg_head->sgl, sg, sg_head->orig_nents, i) {
		uint64_t chunk_size, length;

		chunk_size = page_size - offset_in_page;
		length = min(size, chunk_size);

		sg_set_page(sg, NULL, length, offset_in_page);
		sg_dma_address(sg) = bus_addr;
		sg_dma_len(sg) = length;

		size -= length;
		offset_in_page = 0;
		bus_addr += length;
	}

	*nmap = mlu_mem_context->npages;

	pr_debug("sg_head %#llx, client_context %#llx.", (__u64)sg_head, (__u64)client_context);
	pr_debug("%s end\n", __func__);

	return 0;
}

static void mlu_mem_put_pages(struct sg_table *sg_head, void *client_context)
{
	pr_debug("%s begin\n", __func__);
	pr_debug("put_pages: sg_head 0x%px, client_context 0x%px.\n", sg_head,
	      client_context);

	sg_free_table(sg_head);

	pr_debug("%s end\n", __func__);
}

static int mlu_mem_dma_unmap(struct sg_table *sg_head, void *client_context,
			     struct device *dma_device)
{
	struct mlu_mem_context *mlu_mem_context =
		(struct mlu_mem_context *)client_context;
	struct cn_pcie_set *pcie_set;
	int bar_index;

	pcie_set = mlu_mem_context->pcie_set;

	bar_index = mlu_mem_context->pcibar;

	pr_debug("sg_head 0x%px, client_context 0x%px.", sg_head, client_context);

	return 0;
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

	cn_kfree(mlu_mem_context);
	// module_put(THIS_MODULE);
	pr_debug("%s end\n", __func__);
}

static struct peer_memory_client mlu_mem_client = {
	.acquire = mlu_mem_acquire,
	.get_pages = mlu_mem_get_pages,
	.dma_map = mlu_mem_dma_map,
	.dma_unmap = mlu_mem_dma_unmap,
	.put_pages = mlu_mem_put_pages,
	.get_page_size = mlu_mem_get_page_size,
	.release = mlu_mem_release,
};

static void mlu_mem_client_exit(void);

static int mlu_mem_client_init(void)
{
	mutex_lock(&ib_lock);

	if (ib_state == IB_REGISTER || ib_state == IB_EXIT || ib_state == IB_REGISTER_FAIL)
		goto exit;

	pfn_ib_register_peer_memory_client =
		(void *(*)(struct peer_memory_client *,
			  invalidate_peer_memory *))
		symbol_request(ib_register_peer_memory_client);
	if (!pfn_ib_register_peer_memory_client)
		goto exit;

	pfn_ib_unregister_peer_memory_client = (void (*)(void *))
		symbol_request(ib_unregister_peer_memory_client);
	if (!pfn_ib_unregister_peer_memory_client) {
		symbol_put(ib_register_peer_memory_client);
		pfn_ib_register_peer_memory_client = NULL;
		goto exit;
	}

	msleep(5000);

	strcpy(mlu_mem_client.name, DRV_NAME);
	strcpy(mlu_mem_client.version, MDR_VERSION);

	reg_handle = pfn_ib_register_peer_memory_client(&mlu_mem_client, NULL);
	if (!reg_handle) {
		pr_err("Cannot register peer memory client.\n");
		symbol_put(ib_register_peer_memory_client);
		symbol_put(ib_unregister_peer_memory_client);
		pfn_ib_unregister_peer_memory_client = NULL;
		pfn_ib_register_peer_memory_client = NULL;
		ib_state = IB_REGISTER_FAIL;
		goto exit;
	}

	ib_state = IB_REGISTER;
	pr_info("PeerDirect support was initialized successfully\n");
exit:
	mutex_unlock(&ib_lock);
	return 0;
}

static void mlu_mem_client_exit(void)
{
	mutex_lock(&ib_lock);

	ib_state = IB_EXIT;
	if (pfn_ib_unregister_peer_memory_client) {
		if (reg_handle)
			pfn_ib_unregister_peer_memory_client(reg_handle);

		symbol_put(ib_unregister_peer_memory_client);
	}

	if (pfn_ib_register_peer_memory_client)
		symbol_put(ib_register_peer_memory_client);

	/* Reset pointers to be safe */
	pfn_ib_unregister_peer_memory_client = NULL;
	pfn_ib_register_peer_memory_client = NULL;
	reg_handle = NULL;

	mutex_unlock(&ib_lock);
}
