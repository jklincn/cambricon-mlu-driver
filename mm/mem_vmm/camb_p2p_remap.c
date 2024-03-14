#include "cndrv_debug.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_udvm.h"
#include "cndrv_genalloc.h"
#include "hal/cn_mem_hal.h"
#include "camb_mm.h"
#include "camb_p2p_remap.h"

#include "camb_trace.h"

#define PPOOL_ALIGN(ppool) (1UL << ((ppool)->shift))

static int
__mem_iova_remap_rpc(struct cn_mm_set *mm_set, dev_addr_t orig_iova,
					 dev_addr_t mapped_iova, unsigned long size,
					 unsigned int prot)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct remap_info_t params;
	int ret = 0, rpc_ret = 0;
	size_t result_len = sizeof(int), align = camb_get_page_size();

	if (!size)
		return -EINVAL;

	if (!mapped_iova) {
		cn_dev_core_debug(core, "input mapped_iova is invalid");
		return -EINVAL;
	}

	if (!IS_ALIGNED(size, align)) {
		cn_dev_core_debug(core, "input size(%#lx) is not aligned with %#lx",
						size, align);
		return -EINVAL;
	}

	if (!IS_ALIGNED(orig_iova, align) || !IS_ALIGNED(mapped_iova, align)) {
		cn_dev_core_debug(core, "input orig_iova(%#llx) or mapped_iova(%#llx) is "
						"not aligned with %#lx", orig_iova, mapped_iova, align);
		return -EINVAL;
	}

	params.handle = udvm_get_iova_from_addr(orig_iova);
	params.mapped_iova = udvm_get_iova_from_addr(mapped_iova);
	params.size = size;
	params.prot = prot;
	params.type = REMAP_IOVA;

	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_remap", &params,
						 sizeof(struct remap_info_t), &rpc_ret,
						 &result_len, sizeof(int));
	if (ret || rpc_ret) {
		cn_dev_core_debug(core, "rpc: iova_remap failed(%d, %d)", ret, rpc_ret);
		ret = ret ? ret : rpc_ret;
	}

	trace_iova_remap_rpc(orig_iova, mapped_iova, size, prot);
	return ret;
}

static int
__mem_iova_unmap_rpc(struct cn_mm_set *mm_set, dev_addr_t addr,
				unsigned long size)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct remap_info_t params;
	int ret = 0, rpc_ret = 0;
	size_t result_len = sizeof(int), align = camb_get_page_size();

	if (!IS_ALIGNED(size, align)) {
		cn_dev_core_debug(core, "input size(%#lx) is not aligned with %#lx",
						  size, align);
		return -EINVAL;
	}

	if (!IS_ALIGNED(addr, align)) {
		cn_dev_core_debug(core, "input addr(%#llx) is not aligned with %#lx",
						  addr, align);
		return -EINVAL;
	}

	memset(&params, 0, sizeof(struct remap_info_t));
	params.mapped_iova = udvm_get_iova_from_addr(addr);
	params.size = size;
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_unmap", &params,
						 sizeof(struct remap_info_t), &rpc_ret,
						 &result_len, sizeof(int));
	if (ret || rpc_ret) {
		cn_dev_core_debug(core, "rpc: iova_unmap failed(%d, %d)", ret, rpc_ret);
		ret = ret ? ret : rpc_ret;
	}

	trace_iova_unmap_rpc(addr, size);
	return ret;
}

static unsigned long __p2p_pool_getsize(struct peer_pool_t *ppool)
{
	unsigned long size = 0;

	read_lock(&ppool->size_lock);
	size = ppool->total_size - ppool->used_size;
	read_unlock(&ppool->size_lock);

	return size;
}

static void
__p2p_add_lru_locked(struct peer_pool_t *ppool, struct p2p_remap_node *node)
{
	WARN_ON(!spin_is_locked(&ppool->peer_lock));

	list_add(&node->lru_node, &ppool->lru_list);
	ppool->lru_size += node->size;
}

static void
__p2p_del_lru_locked(struct peer_pool_t *ppool, struct p2p_remap_node *node)
{
	WARN_ON(!spin_is_locked(&ppool->peer_lock));

	if (!list_empty(&node->lru_node)) {
		list_del_init(&node->lru_node);
		ppool->lru_size -= node->size;
	}
}

static dev_addr_t
__p2p_pool_alloc(struct peer_pool_t *ppool, unsigned long size)
{
	struct cn_core_set *core = NULL;
	dev_addr_t vaddr = 0UL;

	if (!ppool || !ppool->mm_set) {
		cn_dev_core_err(core, "input parameters is invalid!");
		return 0;
	}

	core = (struct cn_core_set *)ppool->mm_set->core;
	if (!IS_ALIGNED(size, PPOOL_ALIGN(ppool))) {
		cn_dev_core_err(core, "input address is not aligned!");
		return 0;
	}

	vaddr = cn_gen_pool_alloc(ppool->pool, size);

	if (vaddr) {
		write_lock(&ppool->size_lock);
		ppool->used_size += size;
		write_unlock(&ppool->size_lock);
	}

	return vaddr;
}

static void __p2p_pool_free(struct peer_pool_t *ppool, dev_addr_t addr,
				   unsigned long size)
{
	cn_gen_pool_free(ppool->pool, addr, size);

	write_lock(&ppool->size_lock);
	ppool->used_size -= size;
	write_unlock(&ppool->size_lock);
}

/**
 * TODO: if __p2p_pool_lru_shrink and camb_p2p_remap_release are called at the same
 * time, __p2p_pool_lru_shrink may be return failed. Even if remain size may be
 * enoughed to do remap because camb_p2p_remap_release has release enough memory.
 *
 * This problem only affect performance of single p2p async job, when lanuch
 * mutli p2p async job at the same time.
 **/
static unsigned long
__p2p_pool_lru_shrink(struct peer_pool_t *ppool, unsigned long shrink_size,
				bool value_check)
{
	struct cn_mm_set *mm_set = ppool->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct mapinfo *pminfo = NULL;
	struct list_head free_list;
	struct p2p_remap_node *pos, *tmp;
	unsigned long size = 0UL;
	int ret = 0, nums = 0;

	INIT_LIST_HEAD(&free_list);

	spin_lock(&ppool->peer_lock);
	list_for_each_entry_safe_reverse(pos, tmp, &ppool->lru_list, lru_node) {
		__p2p_del_lru_locked(ppool, pos);
		list_del_init(&pos->minfo_node);
		list_add(&pos->lru_node, &free_list);
		size += pos->size;

		if (size >= shrink_size)
			break;
	}
	spin_unlock(&ppool->peer_lock);

	list_for_each_entry_safe(pos, tmp, &free_list, lru_node) {
		list_del_init(&pos->lru_node);
		pminfo = pos->minfo;

		ret = __mem_iova_unmap_rpc(mm_set, pos->mapped_addr, pos->size);
		if (ret && value_check) {
			cn_dev_core_err(core, "unmap (addr:%#llx, size:%#lx) failed(%d)",
							pos->mapped_addr, pos->size, ret);

			spin_lock(&ppool->peer_lock);
			__p2p_add_lru_locked(ppool, pos);
			if (pminfo)
				list_add_tail(&pos->minfo_node, &pminfo->p2p_remap_list);
			size -= pos->size;
			spin_unlock(&ppool->peer_lock);

			continue;
		}

		__p2p_pool_free(ppool, pos->mapped_addr, pos->size);
		cn_kfree(pos);
		nums++;
	}

	if (value_check)
		trace_p2p_lru_shrink(ppool, shrink_size, nums, size);

	return size;
}


static int
__do_p2p_remap(struct cn_mm_set *mm_set, struct mapinfo *pminfo,
			   dev_addr_t start, unsigned long size,
			   dev_addr_t *mapped_addr)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct peer_pool_t *ppool = &mm_set->ppool;
	unsigned long align_size = 0, shrink_size = 0;
	dev_addr_t align_start = start & ~(PPOOL_ALIGN(ppool) - 1);
	struct p2p_remap_node *node = NULL;
	int ret = 0;

	size = (start + size) - align_start;
	align_size = ALIGN(size, PPOOL_ALIGN(ppool));

	if (!align_size) {
		cn_dev_core_debug(core, "input size(%#lx) is invalid after aligned", size);
		return -EINVAL;
	}

	if (align_size > ppool->total_size) {
		cn_dev_core_debug(core, "input size(%#lx) is out of limit(%#lx)",
						align_size, ppool->total_size);
		return -ENOMEM;
	}

	node = cn_kzalloc(sizeof(struct p2p_remap_node), GFP_KERNEL);
	if (!node) {
		cn_dev_core_debug(core, "alloc memory for p2p_remap_node failed!");
		return -ENOMEM;
	}

	spin_lock(&ppool->peer_lock);
	shrink_size = __p2p_pool_getsize(ppool);
	while ((shrink_size < align_size) && (shrink_size + ppool->lru_size >= align_size)) {
		spin_unlock(&ppool->peer_lock);

		shrink_size = align_size - shrink_size;
		shrink_size = ALIGN(shrink_size, PPOOL_ALIGN(ppool));

		__p2p_pool_lru_shrink(ppool, shrink_size, true);

		spin_lock(&ppool->peer_lock);
		/**
		 * NOTE: due to camb_p2p_remap_release, ppool remain_size may be enoughed
		 * even if lru_shrink return size is not enoughed. so we need check
		 * ppool remain_size again when lru_shrink return size is not enoughed.
		 **/
		shrink_size = __p2p_pool_getsize(ppool);
	}
	node->mapped_addr = __p2p_pool_alloc(ppool, align_size);
	spin_unlock(&ppool->peer_lock);

	if (!node->mapped_addr) {
		cn_dev_core_debug(core, "alloc mapped_addr from p2p_pool failed!");
		cn_kfree(node);
		return -ENXIO;
	}

	ret = __mem_iova_remap_rpc(mm_set, align_start, node->mapped_addr,
							   align_size, CN_C_nA);
	if (ret) {
		cn_dev_core_debug(core, "remap %#llx to %#llx, size:%#lx, failed(%d)",
						align_start, node->mapped_addr, align_size, ret);
		__p2p_pool_free(ppool, node->mapped_addr, align_size);
		cn_kfree(node);
		return ret;
	}

	node->orig_addr = align_start;
	node->size = align_size;
	node->minfo = pminfo;

	spin_lock(&ppool->peer_lock);
	list_add(&node->minfo_node, &pminfo->p2p_remap_list);
	atomic_set(&node->refcnt, 1);
	spin_unlock(&ppool->peer_lock);

	INIT_LIST_HEAD(&node->lru_node);

	*mapped_addr = node->mapped_addr + (start - align_start);

	trace_p2p_remap_slow(ppool, pminfo, start, size, *mapped_addr);

	return 0;
}

static int
__do_p2p_remap_fast(struct cn_mm_set *mm_set, struct mapinfo *pminfo,
					dev_addr_t start, unsigned long size,
					dev_addr_t *mapped_addr)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct peer_pool_t *ppool = &mm_set->ppool;
	struct p2p_remap_node *pos = NULL;
	int ret = -EINVAL;

	if (size > ppool->total_size) {
		cn_dev_core_debug(core, "input size(%#lx) is out of limit(%#lx)",
						size, ppool->total_size);
		return -ENOMEM;
	}

	spin_lock(&ppool->peer_lock);
	if (list_empty(&pminfo->p2p_remap_list)) {
		spin_unlock(&ppool->peer_lock);
		return ret;
	}

	list_for_each_entry(pos, &pminfo->p2p_remap_list, minfo_node) {
		if (start < pos->orig_addr ||
			(start + size) > (pos->orig_addr + pos->size))
			continue;

		if (atomic_inc_return(&pos->refcnt) == 1)
			__p2p_del_lru_locked(ppool, pos);

		*mapped_addr = pos->mapped_addr + (start - pos->orig_addr);
		ret = 0;
	}
	spin_unlock(&ppool->peer_lock);

	if (!ret) trace_p2p_remap_fast(ppool, pminfo, start, size, *mapped_addr);
	return ret;
}

int camb_mem_p2p_remap(struct mapinfo *pminfo, dev_addr_t start, unsigned long size,
						  dev_addr_t *mapped_addr)
{
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = NULL;
	int ret = 0;

	if (!pminfo || !mapped_addr) {
		return -EINVAL;
	}

	mm_set = (struct cn_mm_set *)pminfo->mm_set;
	core = (struct cn_core_set *)mm_set->core;
	start = udvm_get_iova_from_addr(start);

	if (mm_set->ppool.mode == PPOOL_MODE_DISABLE)
		return -EPERM;

	/**
	 * TODO: current p2p remap framework not support remap cross multi mapinfo.
	 * so couldn't support device memory created by VMM.
	 **/
	if (pminfo->mem_type == MEM_VMM)
		return -EPERM;

	/* NOTE: user can't guarantee cn_mem_p2p_unmap is called before
	 * cn_mem_dma_p2p_relealse is called. So we increase mapinfo->refcnt again
	 * to make sure free pminfo after p2p_unmap. */
	if (atomic_add_unless(&pminfo->refcnt, 1, 0) == 0)
		return -EINVAL;

	*mapped_addr = 0;

	ret = __do_p2p_remap_fast(mm_set, pminfo, start, size, mapped_addr);
	if (ret && (ret != -ENOMEM))
		ret = __do_p2p_remap(mm_set, pminfo, start, size, mapped_addr);

	cn_dev_core_debug(core, "orig_addr: %#llx, size: %#lx, mapinfo:%px, mapped_addr:%#llx",
			start, size, pminfo, *mapped_addr);

	if (ret)
		camb_kref_put(pminfo, camb_mem_release);

	if (!ret)
		trace_p2p_remap(&mm_set->ppool, pminfo, start, size, *mapped_addr);
	return ret;
}

int camb_mem_p2p_unmap(struct mapinfo *pminfo, dev_addr_t mapped_addr)
{
	struct cn_mm_set *mm_set = NULL;
	struct cn_core_set *core = NULL;
	struct peer_pool_t *ppool = NULL;
	struct p2p_remap_node *pos = NULL;
	int ret = -EINVAL, islru = 0;

	if (!pminfo)
		return -EINVAL;

	mm_set = (struct cn_mm_set *)pminfo->mm_set;
	core = (struct cn_core_set *)mm_set->core;
	ppool = &mm_set->ppool;
	mapped_addr = udvm_get_iova_from_addr(mapped_addr);

	if (mm_set->ppool.mode == PPOOL_MODE_DISABLE)
		return -EPERM;

	cn_dev_core_debug(core, "p2p unmapped addr:%#llx, input mapinfo:%px",
					  mapped_addr, pminfo);

	spin_lock(&ppool->peer_lock);
	list_for_each_entry(pos, &pminfo->p2p_remap_list, minfo_node) {
		if (mapped_addr >= pos->mapped_addr &&
			mapped_addr < (pos->mapped_addr + pos->size)) {

			ret = 0;
			if (atomic_sub_and_test(1, &pos->refcnt)) {
				__p2p_add_lru_locked(ppool, pos);
				islru = 1;
			}

			break;
		}
	}
	spin_unlock(&ppool->peer_lock);

	if (ret) {
		cn_dev_core_debug(core, "input mapped_addr(%#llx) is invalid!",
						mapped_addr);
	} else {
		trace_p2p_unmap(ppool, pminfo, mapped_addr, pos->mapped_addr,
				pos->size, islru);
	}

	camb_kref_put(pminfo, camb_mem_release);

	return ret;
}

int camb_p2p_pool_init(struct cn_mm_set *mm_set, dev_addr_t dev_vaddr, unsigned long size)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct peer_pool_t *ppool = &mm_set->ppool;
	int ret = 0;

	if (ppool->mode == PPOOL_MODE_DISABLE)
		return 0;

	if (!dev_vaddr || !size) {
		cn_dev_core_err(core, "invalid parameters input for create");
		return -EINVAL;
	}

	/* init peerpool saved in mm_set */
	ppool->total_size = size;
	ppool->shift      = __ffs(camb_get_page_size());
	ppool->start      = dev_vaddr;
	ppool->used_size  = 0;
	ppool->lru_size   = 0;
	ppool->mm_set     = mm_set;
	rwlock_init(&ppool->size_lock);

	INIT_LIST_HEAD(&ppool->lru_list);
	spin_lock_init(&ppool->peer_lock);

	ppool->pool = cn_gen_pool_create(ppool->shift, -1);
	if (!ppool->pool) {
		cn_dev_core_err(core, "create genpool for peer pool failed");
		return -ENOMEM;
	}

	ret = cn_gen_pool_add_virt(ppool->pool, ppool->start, 0,
					ppool->total_size, -1);
	if (ret) {
		cn_dev_core_err(core, "add genpool failed");
		cn_gen_pool_destroy(ppool->pool);
		return -ENOMEM;
	}

	cn_dev_core_info(core, "PPool Init:(%px) start:%#llx, size:%#lx, shift:%d",
					 ppool, ppool->start, ppool->total_size, ppool->shift);
	return 0;
}

void camb_p2p_pool_exit(struct cn_mm_set *mm_set)
{
	struct peer_pool_t *ppool = &mm_set->ppool;

	if (ppool->mode == PPOOL_MODE_DISABLE)
		return;

	if (ppool->used_size) {
		__p2p_pool_lru_shrink(ppool, ppool->used_size, false);
	}

	if (ppool->pool)
		cn_gen_pool_destroy(ppool->pool);
}

static int
__get_normal_mode_info(struct cn_mm_set *mm_set, dev_addr_t *dev_vaddr,
				unsigned long *size)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct ret_msg remsg;
	struct bar_info_s info;
	ssize_t result_len = sizeof(struct ret_msg);
	int ret = 0;

	memset(&info, 0x0, sizeof(struct bar_info_s));
	ret = cn_bus_get_bar_info(core->bus_set, &info);
	if (ret) {
		cn_dev_core_err(core, "error get bar_info!");
		return ret;
	}

	/* NOTE: p2p use bar2 do data transfer */
	*size = info.bar[2].bar_sz;

	memset(&remsg, 0x0, sizeof(struct ret_msg));
	ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_p2p_pool_init", size,
						 sizeof(uint64_t), &remsg, &result_len,
						 sizeof(struct ret_msg));
	if (ret || remsg.ret) {
		cn_dev_core_err(core, "p2p_pool_init failed! (%d,%d)", ret, remsg.ret);
		return -EINVAL;
	}

	*dev_vaddr = remsg.device_addr;
	return 0;
}

int camb_p2p_normal_remap_init(struct cn_mm_set *mm_set)
{
	dev_addr_t dev_vaddr = 0;
	ssize_t size = 0UL;
	int ret = 0;

	if (mm_set->ppool.mode != PPOOL_MODE_NORMAL)
		return 0;

	ret = __get_normal_mode_info(mm_set, &dev_vaddr, &size);
	if (ret) return ret;

	return camb_p2p_pool_init(mm_set, dev_vaddr, size);
}

void camb_p2p_normal_remap_exit(struct cn_mm_set *mm_set)
{
	struct peer_pool_t *ppool = &mm_set->ppool;

	if (ppool->mode != PPOOL_MODE_NORMAL)
		return ;

	camb_p2p_pool_exit(mm_set);
}

void camb_p2p_remap_release(struct mapinfo *pminfo)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)pminfo->mm_set;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct peer_pool_t *ppool = &mm_set->ppool;
	struct p2p_remap_node *pos, *tmp;
	struct list_head release_list;
	int ret = 0;

	if (ppool->mode == PPOOL_MODE_DISABLE)
		return ;

	INIT_LIST_HEAD(&release_list);

	spin_lock(&ppool->peer_lock);
	list_for_each_entry_safe(pos, tmp, &pminfo->p2p_remap_list, minfo_node) {
		__p2p_del_lru_locked(ppool, pos);
		list_del_init(&pos->minfo_node);
		list_add(&pos->minfo_node, &release_list);
	}
	spin_unlock(&ppool->peer_lock);

	list_for_each_entry_safe(pos, tmp, &release_list, minfo_node) {
		list_del_init(&pos->minfo_node);

		ret = __mem_iova_unmap_rpc(mm_set, pos->mapped_addr, pos->size);
		if (ret) {
			cn_dev_core_err(core, "unmap (addr:%#llx, size:%#lx) failed(%d)",
							pos->mapped_addr, pos->size, ret);

			spin_lock(&ppool->peer_lock);
			__p2p_add_lru_locked(ppool, pos);
			pos->minfo = NULL;
			spin_unlock(&ppool->peer_lock);
			continue;
		}

		__p2p_pool_free(ppool, pos->mapped_addr, pos->size);
		cn_kfree(pos);
	}
}

dev_addr_t camb_p2p_pool_get_base(struct cn_mm_set *mm_set)
{
	if (mm_set->ppool.mode == PPOOL_MODE_DISABLE)
		return 0;

	return mm_set->ppool.start;
}

bool camb_p2p_range_in_pool(struct cn_mm_set *mm_set, dev_addr_t base,
				unsigned long size)
{
	if (mm_set->ppool.mode == PPOOL_MODE_DISABLE)
		return false;

	return (base >= mm_set->ppool.start) && (base + size) <=
		(mm_set->ppool.total_size + mm_set->ppool.start);
}
