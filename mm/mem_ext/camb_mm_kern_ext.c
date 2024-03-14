#include <linux/pci.h>
#include "camb_mm.h"
#include "cndrv_debug.h"
#include "cndrv_udvm.h"
#include "camb_udvm.h"
#include "cndrv_ext.h"
#include "camb_mm_compat.h"
#include "cndrv_core.h"
#include "camb_mm_ext.h"

int cn_mem_invalid_cache(void *kva, u64 len);

/*offset and size need PAGE_ALIGN*/
int __map_kernel(struct sg_table *table, int cached, kvirt_t *kva)
{
	void *vaddr;

	if (cached) {
		cached = 0x1;
	} else {
		cached = 0;
	}

	vaddr = camb_mem_map_kernel(table, cached);
	if (IS_ERR(vaddr)) {
		return PTR_ERR(vaddr);
	}

	*kva = (kvirt_t)vaddr;
	return 0;
}

static int __mem_map_kva(u64 tag, struct mapinfo *pminfo, dev_addr_t device_vaddr,
		u64 size, kvirt_t *kva, int cached, void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = mm_set->core;
	int ret = 0;
	struct sg_table table = {0};
	__u64 map_size = size;
	dev_addr_t map_dev_addr;

	if (__params_check_range(pminfo, device_vaddr, size)) {
		cn_dev_core_err(core, "iova %#llx or %#llx error.", device_vaddr, map_size);
		return -EINVAL;
	}

	/*head align*/
	map_size += offset_in_page(device_vaddr);
	/*tail align.*/
	map_size = PAGE_ALIGN(map_size);

	map_dev_addr = device_vaddr & PAGE_MASK;

	ret = camb_pminfo_sg_table_set(pminfo, mem_set);
	if (ret) {
		cn_dev_core_info(core, "sg table set fail.");
		goto fail_set_sg_table;
	}

	/*2. split sgl list of phy addrss*/
	ret = camb_split_sg_table(pminfo, map_dev_addr, map_size, pminfo->sg_table, &table, mem_set);
	if (ret) {
		cn_dev_core_info(core, "split sgl to get phy addrss sgl error");
		goto fail_split_sg_table;
	}

	/*3. map sg_table to kernel*/
	if (__map_kernel(&table, cached, kva)) {
		cn_dev_core_info(core, "split sgl to get phy addrss sgl error");
		goto fail_map_kva;
	}

	*kva += offset_in_page(device_vaddr);

	/**
	  * NOTICE:
	  * malloc by cn_sg_split need use kfree.
	  * malloc by sg_alloc_table need use sg_free_table.
	 */
	kfree(table.sgl);
	return ret;

fail_map_kva:
	/*malloc by cn_sg_split*/
	kfree(table.sgl);
fail_split_sg_table:
fail_set_sg_table:
	*kva = 0;
	return ret;
}

void __mem_unmap_kva(kvirt_t kva)
{
	vunmap((void *)(kva & PAGE_MASK));
}

void cn_mem_unmap(void* kva)
{
	__mem_unmap_kva((kvirt_t)kva);
}
EXPORT_SYMBOL(cn_mem_unmap);

static int __rpc_meminfo_get(struct mapinfo *pminfo, dev_addr_t iova, struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = mm_set->core;
	struct mem_attr_get attr = {0};
	dev_addr_t rpc_dev_addr;
	size_t result_len;
	int ret = 0;

	rpc_dev_addr = udvm_get_iova_from_addr(iova);
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_iova_get",
			(void *)&rpc_dev_addr, sizeof(rpc_dev_addr),
			(void *)&attr, (size_t *)&result_len, sizeof(struct mem_attr_get));

	if (ret < 0 || attr.ret) {
		cn_dev_core_err(core, "cnrpc request mem failed.");
		return attr.ret;
	}

	pminfo->mem_type = MEM_FAKE;
	pminfo->virt_addr = attr.iova | udvm_get_head_from_addr(iova);
	pminfo->mm_priv_data = __get_mm_priv(0, mm_set);
	pminfo->mm_set = mm_set;
	pminfo->udvm_priv = NULL;
	pminfo->tag = 0;

	/*init the memory attributes*/
	pminfo->mem_meta.size = (unsigned long)attr.size;
	pminfo->mem_meta.type = CN_IPU_MEM;

	return 0;
}

static int __rpc_meminfo_put(struct mapinfo *pminfo, dev_addr_t iova, struct cn_mm_set *mm_set)
{
	dev_addr_t device_vaddr = udvm_get_iova_from_addr(pminfo->virt_addr);
	struct ret_msg remsg = {0};
	size_t result_len;
	int ret;

	ret = __mem_call_rpc(mm_set->core, mm_set->endpoint, "rpc_iova_put",
			(void *)&device_vaddr, sizeof(device_vaddr),
			(void *)&remsg, (size_t *)&result_len, sizeof(struct ret_msg));

	if (ret < 0) {
		return (ret == ERROR_RPC_RESET) ? -EINVAL : -EAGAIN;
	}

	return 0;
}

static int rpc_mem_map(dev_addr_t iova, u64 size, int cached, kvirt_t *kva, struct cn_mm_set *mm_set)
{
	struct cn_core_set *core = mm_set->core;
	struct mapinfo rpc_minfo = {0};
	int ret = -EINVAL;

	ret = __rpc_meminfo_get(&rpc_minfo, iova, mm_set);
	if (ret) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal.", (u64)iova);
		return ret;
	}

	ret = __mem_map_kva(0, &rpc_minfo, iova, size, kva, cached, mm_set);
	if (ret) {
		cn_dev_core_err(core, "Addr(%#llx) map kva fail.", (u64)iova);
	}

	if (rpc_minfo.sg_table) {
		kfree(rpc_minfo.sg_table->sgl);
		cn_kfree(rpc_minfo.sg_table);
	}

	ret = __rpc_meminfo_put(&rpc_minfo, iova, mm_set);
	if (ret) {
		cn_dev_core_err(core, "Addr(%#llx) put fail.", (u64)iova);
	}

	return ret;
}

static int __cn_mem_kernel_map(u64 iova, u64 size, int cached, u64 *kva)
{
	struct cn_core_set *core;
	struct cn_mm_set *mm_set;

	core = (struct cn_core_set *)cn_core_get_with_idx(0);
	mm_set = core->mm_set;

	/**
	 * iova may be as follow:
	 * 1.usersapce cnMalloc
	 * 2.cn_mem_malloc_*  => no udvm address
	 * 3.public
	 * 4.pmu rpc get => no udvm address
	 **/
	return rpc_mem_map(iova, size, cached, kva, mm_set);
}

/*don't save kva*/
void *cn_mem_map_cached(u64 iova, u64 size)
{
	kvirt_t kva = 0;

	__cn_mem_kernel_map(iova, size, 1, &kva);

	return (void *)kva;
}
EXPORT_SYMBOL(cn_mem_map_cached);

void *cn_mem_map_nocached(u64 iova, u64 size)
{
	kvirt_t kva = 0;

	__cn_mem_kernel_map(iova, size, 0, &kva);

	return (void *)kva;
}
EXPORT_SYMBOL(cn_mem_map_nocached);

int __mem_malloc_ext(char *zone_name, u64 *iova, u64 *kva, char *buf_name,
		size_t size, int cached)
{
	struct cn_core_set *core;
	struct cn_mm_set *mm_set;
	struct mapinfo *pminfo = NULL;
	struct file *fp = NULL;
	struct mem_attr mm_attr = {0};
	int copy_size;
	int ret;

	core = (struct cn_core_set *)cn_core_get_with_idx(0);
	mm_set = core->mm_set;

	if (zone_name && !strncmp(zone_name, "reserved", 8))
		mm_attr.flag |= ATTR_FLAG_RESERVED_HEAP;

	mm_attr.tag      = (u64)fp;
	mm_attr.size     = size;
	mm_attr.align    = 1024;
	mm_attr.type     = CN_IPU_MEM;
	mm_attr.affinity = -1;
	mm_attr.vmid     = PF_ID;

	copy_size = strlen(buf_name);
	copy_size = copy_size < EXT_NAME_SIZE ? copy_size : EXT_NAME_SIZE;
	strncpy(mm_attr.name, buf_name, copy_size);

	/*TODO:return pminfo to optimize map.*/
	ret = camb_mem_alloc_internal((u64)fp, iova, &mm_attr, mm_set, &pminfo);
	if (ret) {
		cn_dev_core_err(core, "camb_mem_alloc_internal fail.");
		return ret;
	}

	/*don't map kva.*/
	if (kva == NULL)
		return ret;

	ret = __mem_map_kva(0, pminfo, pminfo->virt_addr, size, kva, cached, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) map kva fail.", *iova);
	}

	pminfo->kva_info.kva = (kvirt_t)*kva;
	pminfo->kva_info.kva_cached = cached;

	return ret;
}

u64 cn_mem_malloc_ext(char *zone_name, char *buf_name, u64 size)
{
	u64 iova;

	if (__mem_malloc_ext(zone_name, &iova, NULL, buf_name, size, 0)) {
		return 0;
	}

	return iova;
}
EXPORT_SYMBOL(cn_mem_malloc_ext);

int cn_mem_malloc_ext_cached(char *zone_name, char *buf_name, u64 *iova, void **kva, u64 size)
{
	return __mem_malloc_ext(zone_name, iova, (void *)kva, buf_name, size, 1);
}
EXPORT_SYMBOL(cn_mem_malloc_ext_cached);

int cn_mem_malloc_ext_nocached(char *zone_name, char *buf_name, u64 *iova, void **kva, u64 size)
{
	return __mem_malloc_ext(zone_name, iova, (void *)kva, buf_name, size, 0);
}
EXPORT_SYMBOL(cn_mem_malloc_ext_nocached);

void camb_unmap_kva(struct mapinfo *pminfo)
{
	if (unlikely(pminfo->kva_info.kva)) {
		if (pminfo->kva_info.kva_cached) {
			cn_mem_invalid_cache((void *)pminfo->kva_info.kva,
					pminfo->mem_meta.size);
		}

		__mem_unmap_kva(pminfo->kva_info.kva);
		pminfo->kva_info.kva = 0;
	}
}

int cn_mem_free_ext(u64 iova, void *kva)
{
	struct cn_core_set *core;

	core = (struct cn_core_set *)cn_core_get_with_idx(0);
	/*2. free iova*/
	return cn_mem_free(0, iova, core);
}
EXPORT_SYMBOL(cn_mem_free_ext);

int cn_mem_invalid_cache(void *kva, u64 len)
{
	if (kva == NULL)
		return -EINVAL;

	cn_edge_cache_invalid(kva, len);

	return 0;
}
EXPORT_SYMBOL(cn_mem_invalid_cache);

int cn_mem_flush_cache(void *kva, u64 len)
{
	if (kva == NULL)
		return -EINVAL;

	cn_edge_cache_flush(kva, len);

	return 0;
}
EXPORT_SYMBOL(cn_mem_flush_cache);

int cn_mem_get_phys(u64 iova, u64 size, void **sg_table)
{
	struct cn_core_set *core;
	struct cn_mm_set *mm_set;
	struct mapinfo *pminfo = NULL;
	int ret;

	core = (struct cn_core_set *)cn_core_get_with_idx(0);
	mm_set = core->mm_set;

	if (unlikely(!iova || !size || !sg_table)) {
		cn_dev_core_err(core, "iova %#llx or size %#llx"
				" or sg_table %#llx error",
				(u64)iova, (u64)size, (u64)sg_table);
		return -EINVAL;
	}

	ret = camb_kref_get((u64)0, iova, &pminfo, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal.", iova);
		return ret;
	}

	if (unlikely(pminfo->virt_addr != iova)
			|| (size != pminfo->mem_meta.size) ) {
		cn_dev_core_err(core, "iova (%#llx,%#llx) or size "
				"(%#llx %#llx) invalid.",
				(u64)pminfo->virt_addr, (u64)iova,
				(u64)pminfo->mem_meta.size, (u64)size);
		ret = -EINVAL;
		goto error_exit;
	}

	ret = camb_pminfo_sg_table_set(pminfo, mm_set);
	if (ret) {
		ret = -ENXIO;
		cn_dev_core_err(core, "sg table set error.");
		goto error_exit;
	}

	*sg_table = pminfo->sg_table;

	camb_kref_put(pminfo, camb_mem_release);

	return 0;

error_exit:
	camb_kref_put(pminfo, camb_mem_release);
	return ret;
}
EXPORT_SYMBOL(cn_mem_get_phys);

int __dump_table(struct cn_core_set *core, struct sg_table *table);

void __amand_sg_table(struct sg_table *sg_table, u64 iova, u64 size)
{
	int offset = offset_in_page(iova);
	struct scatterlist *sg;
	int cnt, j, tail;
	u64 total = 0;

	cnt = sg_nents(sg_table->sgl);

	for_each_sg(sg_table->sgl, sg, cnt, j) {
		total += sg->length;

		if (!j) {
			sg_dma_address(sg) += offset;
			sg_dma_len(sg) -= offset;
			sg->offset += offset;
			sg->length -= offset;
		}

		if (sg_is_last(sg)) {
			tail = total - size - offset;
			sg_dma_len(sg) -= tail;
			sg->length -= tail;
		}
	}
}

int cn_mem_get_phys_range(u64 iova, u64 size, void *sg_table)
{
	struct cn_core_set *core;
	struct cn_mm_set *mm_set;
	struct mapinfo *pminfo = NULL;
	int ret;
	u64 tag;
	u64 align_iova;
	u64 align_size;

	core = (struct cn_core_set *)cn_core_get_with_idx(0);
	mm_set = core->mm_set;

	/*Don't check iova and size align.*/
	if (unlikely(!iova || !size || !sg_table)) {
		cn_dev_core_err(core, "iova %#llx or size %#llx or sg_table %#llx invalid or need PAGE_ALIGN.",
				(u64)iova, (u64)size, (u64)sg_table);
		return -EINVAL;
	}

	/*iova from cnMalloc, kernel public, or kernel malloc*/
	ret = udvm_camb_kref_get(&pminfo, &tag, iova, mm_set, camb_kref_get);
	if (ret < 0) {
		cn_dev_core_err(core, "Addr(%#llx) is illegal.", iova);
		return ret;
	}

	if (__params_check_range(pminfo, iova, size)) {
		cn_dev_core_err(core, "iova %#llx or %#llx error.", iova, size);
		ret = -EINVAL;
		goto error_exit;
	}

	/*head align*/
	align_size = size;
	align_size += offset_in_page(iova);
	/*tail align.*/
	align_size = PAGE_ALIGN(align_size);

	align_iova = iova & PAGE_MASK;

	ret = camb_pminfo_sg_table_set(pminfo, mm_set);
	if (ret) {
		cn_dev_core_err(core, "sg table set error.");
		goto error_exit;
	}

	memset(sg_table, 0, sizeof(struct sg_table));
	ret = camb_split_sg_table(pminfo, align_iova, align_size, pminfo->sg_table, sg_table, mm_set);
	if (ret < 0) {
		cn_dev_core_err(core, "split sgl to get phy addrss sgl error");
		goto error_exit;
	}

	__amand_sg_table(sg_table, iova, size);

error_exit:
	camb_kref_put(pminfo, camb_mem_release);

	return ret;
}
EXPORT_SYMBOL(cn_mem_get_phys_range);

int cn_mem_free_sg_table(u64 iova, u64 size, void *sg_table)
{
	kfree(((struct sg_table *)sg_table)->sgl);
	return 0;
}
EXPORT_SYMBOL(cn_mem_free_sg_table);

