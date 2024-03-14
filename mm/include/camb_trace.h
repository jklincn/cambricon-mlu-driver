#undef TRACE_SYSTEM
#define TRACE_SYSTEM camb_mem

#if !defined(_TRACE_CAMB_MEM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_CAMB_MEM_H

#include <linux/tracepoint.h>
#include "camb_mm.h"

/* TRACE show mapinfo create and free */
DECLARE_EVENT_CLASS(camb_mapinfo,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo),

	TP_STRUCT__entry(
		__field(unsigned long, tgid)
		__field(unsigned long, dev_vaddr)
		__field(unsigned long, size)
		__field(int,  chl)
		__field(int,  flag)
		__string(type,  mem_type_str(pminfo->mem_meta.type))
		__string(mtype,  mapinfo_type_str(pminfo->mem_type))
	),

	TP_fast_assign(
		__entry->tgid = pminfo->tgid;
		__entry->dev_vaddr = pminfo->virt_addr;
		__entry->size = pminfo->mem_meta.size;
		__entry->chl = pminfo->mem_meta.affinity;
		__assign_str(type, mem_type_str(pminfo->mem_meta.type))
		__entry->flag = pminfo->mem_meta.flag;
		__assign_str(mtype, mapinfo_type_str(pminfo->mem_type))
	),

	TP_printk("TGID<%ld>, iova: %#lx, sz: %#lx, attr(%d, %s, %#x), type: %s",
			  __entry->tgid, __entry->dev_vaddr, __entry->size, __entry->chl,
			  __get_str(type), __entry->flag, __get_str(mtype))
);

DEFINE_EVENT(camb_mapinfo, mdr_alloc,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo)
);

DEFINE_EVENT(camb_mapinfo, alloc,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo)
);

DEFINE_EVENT(camb_mapinfo, free,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo)
);

DEFINE_EVENT(camb_mapinfo, ipc_close_handle,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo)
);

DEFINE_EVENT(camb_mapinfo, mem_priv_release,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo)
);

DEFINE_EVENT(camb_mapinfo, udvm_do_exit,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo)
);

DECLARE_EVENT_CLASS(camb_mapinfo_kref,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo),

	TP_STRUCT__entry(
		__field(unsigned long, tgid)
		__field(unsigned long, dev_vaddr)
		__field(unsigned long, size)
		__field(unsigned int , refcnt)
		__string(mtype,  mapinfo_type_str(pminfo->mem_type))
	),

	TP_fast_assign(
		__entry->tgid = pminfo->tgid;
		__entry->dev_vaddr = pminfo->virt_addr;
		__entry->size = pminfo->mem_meta.size;
		__entry->refcnt = atomic_read(&pminfo->refcnt);
		__assign_str(mtype, mapinfo_type_str(pminfo->mem_type))
	),

	TP_printk("TGID<%ld>, iova: %#lx, sz: %#lx, type: %s, refcnt:%d",
			  __entry->tgid, __entry->dev_vaddr, __entry->size,
			  __get_str(mtype), __entry->refcnt)
);

DEFINE_EVENT(camb_mapinfo_kref, mapinfo_kref_get,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo)
);

DEFINE_EVENT(camb_mapinfo_kref, mapinfo_kref_put,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo)
);

TRACE_EVENT(mapinfo_release,

	TP_PROTO(struct mapinfo *pminfo),

	TP_ARGS(pminfo),

	TP_STRUCT__entry(
		__field(unsigned long, tgid)
		__field(unsigned long, dev_vaddr)
		__field(unsigned long, size)
		__string(mtype,  mapinfo_type_str(pminfo->mem_type))
	),

	TP_fast_assign(
		__entry->tgid = pminfo->tgid;
		__entry->dev_vaddr = pminfo->virt_addr;
		__entry->size = pminfo->mem_meta.size;
		__assign_str(mtype, mapinfo_type_str(pminfo->mem_type))
	),

	TP_printk("TGID<%ld>, iova: %#lx, sz: %#lx, type: %s",
			  __entry->tgid, __entry->dev_vaddr, __entry->size,
			  __get_str(mtype))
);

TRACE_EVENT(mem_rpc,

	TP_PROTO(char *func),

	TP_ARGS(func),

	TP_STRUCT__entry(
		__field(unsigned long, tgid)
		__string(func, func)
	),

	TP_fast_assign(
		__entry->tgid = current->tgid;
		__assign_str(func, func);
	),

	TP_printk("TGID<%ld>, rpc callback: %s", __entry->tgid, __get_str(func))
);

DECLARE_EVENT_CLASS(camb_p2p_remap,

	TP_PROTO(struct peer_pool_t *ppool, struct mapinfo *pminfo,
			 unsigned long start, unsigned long size,
			 unsigned long mapped_addr),

	TP_ARGS(ppool, pminfo, start, size, mapped_addr),

	TP_STRUCT__entry(
		__field(unsigned long, ppool_tot)
		__field(unsigned long, ppool_used)
		__field(unsigned long, ppool_lru)
		__field(unsigned long, base)
		__field(unsigned long, tsize)
		__field(unsigned long, start)
		__field(unsigned long, size)
		__field(unsigned long, mapped_addr)
	),

	TP_fast_assign(
		__entry->ppool_tot = ppool->total_size;
		__entry->ppool_used = ppool->used_size;
		__entry->ppool_lru = ppool->lru_size;
		__entry->base = pminfo->virt_addr;
		__entry->tsize = pminfo->mem_meta.size;
		__entry->start = start;
		__entry->size = size;
		__entry->mapped_addr = mapped_addr;
	),

	TP_printk("PPOOL(tot:%#lx, used:%#lx, lru:%#lx), minfo(%#lx %#lx), input(%#lx %#lx), mapped:%#lx",
			  __entry->ppool_tot, __entry->ppool_used, __entry->ppool_lru,
			  __entry->base, __entry->tsize, __entry->start,
			  __entry->size, __entry->mapped_addr)
);

DEFINE_EVENT(camb_p2p_remap, p2p_remap,

	TP_PROTO(struct peer_pool_t *ppool, struct mapinfo *pminfo,
			 unsigned long start, unsigned long size,
			 unsigned long mapped_addr),

	TP_ARGS(ppool, pminfo, start, size, mapped_addr)
);

DEFINE_EVENT(camb_p2p_remap, p2p_remap_slow,

	TP_PROTO(struct peer_pool_t *ppool, struct mapinfo *pminfo,
			 unsigned long start, unsigned long size,
			 unsigned long mapped_addr),

	TP_ARGS(ppool, pminfo, start, size, mapped_addr)
);

DEFINE_EVENT(camb_p2p_remap, p2p_remap_fast,

	TP_PROTO(struct peer_pool_t *ppool, struct mapinfo *pminfo,
			 unsigned long start, unsigned long size,
			 unsigned long mapped_addr),

	TP_ARGS(ppool, pminfo, start, size, mapped_addr)
);

TRACE_EVENT(p2p_unmap,

	TP_PROTO(struct peer_pool_t *ppool, struct mapinfo *pminfo, unsigned long addr,
			 unsigned long base, unsigned long size, bool islru),

	TP_ARGS(ppool, pminfo, addr, base, size, islru),

	TP_STRUCT__entry(
		__field(unsigned long, ppool_tot)
		__field(unsigned long, ppool_used)
		__field(unsigned long, ppool_lru)
		__field(unsigned long, addr)
		__field(unsigned long, mapped_base)
		__field(unsigned long, mapped_size)
		__field(unsigned long, base)
		__field(unsigned long, size)
		__field(bool, islru)
	),

	TP_fast_assign(
		__entry->ppool_tot = ppool->total_size;
		__entry->ppool_used = ppool->used_size;
		__entry->ppool_lru = ppool->lru_size;
		__entry->addr = addr;
		__entry->mapped_base = base;
		__entry->mapped_size = size;
		__entry->base = pminfo->virt_addr;
		__entry->size = pminfo->mem_meta.size;
		__entry->islru = islru;
	),

	TP_printk("PPOOL(tot:%#lx, used:%#lx, lru:%#lx), unmap:%#lx, node(%#lx, %#lx), mapinfo(%#lx, %#lx). lruable:%s",
			  __entry->ppool_tot, __entry->ppool_used, __entry->ppool_lru,
			  __entry->addr, __entry->mapped_base, __entry->mapped_size,
			  __entry->base, __entry->size, __entry->islru ? "TRUE" : "FALSE")
);

TRACE_EVENT(p2p_lru_shrink,

	TP_PROTO(struct peer_pool_t *ppool, unsigned long isize, unsigned int counts, unsigned long size),

	TP_ARGS(ppool, isize, counts, size),

	TP_STRUCT__entry(
		__field(unsigned long, ppool_tot)
		__field(unsigned long, ppool_used)
		__field(unsigned long, ppool_lru)
		__field(unsigned long, isize)
		__field(unsigned int, counts)
		__field(unsigned long, size)
	),

	TP_fast_assign(
		__entry->ppool_tot = ppool->total_size;
		__entry->ppool_used = ppool->used_size;
		__entry->ppool_lru = ppool->lru_size;
		__entry->isize = isize;
		__entry->counts = counts;
		__entry->size = size;
	),

	TP_printk("PPOOL(tot:%#lx, used:%#lx, lru:%#lx), requested: %#lx, shrinked counts:%d, shrinked size:%#lx",
			  __entry->ppool_tot, __entry->ppool_used, __entry->ppool_lru,
			  __entry->isize, __entry->counts, __entry->size)
);

TRACE_EVENT(linear_remap,

	TP_PROTO(struct mapinfo *pminfo, unsigned long base, unsigned long size,
		unsigned int type),

	TP_ARGS(pminfo, base, size, type),

	TP_STRUCT__entry(
		__field(unsigned long, ibase)
		__field(unsigned long, isize)
		__field(unsigned long, base)
		__field(unsigned long, size)
		__field(unsigned int , type)
	),

	TP_fast_assign(
		__entry->ibase = base;
		__entry->isize = size;
		__entry->base = pminfo->virt_addr;
		__entry->size = pminfo->mem_meta.size;
		__entry->type = type;
	),

	TP_printk("input(%#lx, %#lx), mapinfo(%#lx, %#lx). linear_remap type:%d",
			  __entry->ibase, __entry->isize, __entry->base, __entry->size,
			  __entry->type)
)

TRACE_EVENT(linear_unmap,

	TP_PROTO(struct mapinfo *pminfo, unsigned int type),

	TP_ARGS(pminfo, type),

	TP_STRUCT__entry(
		__field(unsigned long, base)
		__field(unsigned long, size)
		__field(unsigned int , type)
	),

	TP_fast_assign(
		__entry->base = pminfo->virt_addr;
		__entry->size = pminfo->mem_meta.size;
		__entry->type = type;
	),

	TP_printk("mapinfo(%#lx, %#lx). linear_unmap type:%d", __entry->base,
		__entry->size, __entry->type)
)

TRACE_EVENT(iova_remap_rpc,

	TP_PROTO(unsigned long orig_iova, unsigned long mapped_iova,
			 unsigned long size, unsigned int prot),

	TP_ARGS(orig_iova, mapped_iova, size, prot),

	TP_STRUCT__entry(
		__field(unsigned long, orig_iova)
		__field(unsigned long, mapped_iova)
		__field(unsigned long, size)
		__field(unsigned int, prot)
	),

	TP_fast_assign(
		__entry->orig_iova = orig_iova;
		__entry->mapped_iova = mapped_iova;
		__entry->size = size;
		__entry->prot = prot;
	),

	TP_printk("iova_remap_rpc: orig:%#lx, size:%#lx, mapped:%#lx, prot:%#x",
			  __entry->orig_iova, __entry->size, __entry->mapped_iova,
			  __entry->prot)
);

TRACE_EVENT(iova_unmap_rpc,

	TP_PROTO(unsigned long iova, unsigned long size),

	TP_ARGS(iova, size),

	TP_STRUCT__entry(
		__field(unsigned long, iova)
		__field(unsigned long, size)
	),

	TP_fast_assign(
		__entry->iova = iova;
		__entry->size = size;
	),

	TP_printk("iova_unmap_rpc: iova:%#lx, size:%#lx", __entry->iova, __entry->size)
);

#endif

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE

#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE camb_trace

/* This part must be outside protection */
#include <trace/define_trace.h>
