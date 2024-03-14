#ifndef _PINNED_MM_H_
#define _PINNED_MM_H_

#include <linux/hash.h>
#include <linux/scatterlist.h>

//#define CN_PINNED_MM_DEBUG
#ifdef CN_PINNED_MM_DEBUG
#define debug(string,arg...) printk(string,##arg)
#else
#define debug(string,arg...)
#endif

typedef enum
{
	CN_HOSTALLOC_TYPE_DEFAULT = 0,   /* pinned memory */
	CN_HOSTALLOC_TYPE_WRITECOMBINED, /* pinned memory + wc */
	CN_HOSTALLOC_TYPE_NODE,		   /* pinned memory with numa node */
	CN_HOSTALLOC_TYPE_REGISTER,	   /* pinned memory with register */
} CN_HOSTALLOC_TYPE;

typedef enum {
	CN_MEMHOSTALLOC_MIN,
	CN_MEMHOSTALLOC_DEVICEMAP = 0x1,/*map dma , map ob*/
	CN_MEMHOSTALLOC_PORTABLE = 0x2,/*map dma ,no map ob*/
	CN_MEMHOSTALLOC_MAX,
	CN_MEMHOSTALLOC_ALLOC_HOST = 0xff,/*cnMallocHost*/
} CN_MEMHOSTALLOC_FLAG;

typedef enum {
	CN_MEMHOSTREGISTER_MIN,
	CN_MEMHOSTREGISTER_DEVICEMAP = 0x1,/*map dma ,map ob*/
	CN_MEMHOSTREGISTER_PORTABLE = 0x2,/*map dma, no map ob*/
	CN_MEMHOSTREGISTER_IOMEMORY = 0x4,/*iova*/
	CN_MEMHOSTREGISTER_MAX,
} CN_MEMHOSTREGISTER_FLAG;

#if defined(CONFIG_SMP)
struct pinned_mem_padding {
	char x[0];
} ____cacheline_internodealigned_in_smp;
#define PINNED_MEM_PADDING(name) struct pinned_mem_padding name
#else
#define PINNED_MEM_PADDING(name)
#endif

struct pinned_mem_rb_task {
	struct rb_root root;

	PINNED_MEM_PADDING(_pad3_);

	rwlock_t rb_lock;

	PINNED_MEM_PADDING(_pad4_);

};

struct pinned_mem_rb_blk {
	struct rb_root root;

	PINNED_MEM_PADDING(_pad1_);

	rwlock_t rb_lock;

	PINNED_MEM_PADDING(_pad2_);

};

/* physical page block */
struct pinned_mem {
	unsigned long kva_start;	/* kernel start virt addr :vmap*/
	unsigned long vm_size;		/* kernel start virt addr :vmap*/

	struct rb_node node;		/* RB Tree Node */
	atomic_t ref_cnt;

	struct udvm_ob_map_t *ob_map;

	/* set by other kernel driver mod */
	atomic_t k_rcnt;

	CN_HOSTALLOC_TYPE type;
	/*value is CN_MEMHOSTALLOC_FLAG*/
	unsigned int flags;

	struct page **pages;        /* phy page point */
	int    *pages_cnt;          /* number of consecutive physical pages per block*/
	int    chunks;              /* number of blocks */
};

struct pinned_mem_task {
	unsigned long task;
	int size;
	struct rb_root rb_uva;
	struct rb_node node;		/* RB Tree Node */
	struct list_head lnode;  /* list node saved in hostmem_priv*/
	atomic_t uva_cnt;
	atomic_t refcnt;
	void *hostmem_priv;   /* each pinned_mem_task only linked single priv */
};

struct pinned_mem_va {
	unsigned long task;
	struct rb_node node;
	unsigned long va_start;
	unsigned long vm_size;
	struct pinned_mem *pst_blk;/* pointer to physical page block */
	struct list_head cp_node;  /* list node saved in cp_dump_list */
	atomic_t refcnt;
};

extern int cn_pinned_mem_alloc(struct file *fp, unsigned long arg, unsigned int cond);
extern int cn_pinned_mem_free(struct file *fp, unsigned long arg, unsigned int cond);

int cn_pinned_mem_get_handle(struct file *fp, unsigned long arg, unsigned int cond);

int cn_pinned_mem_close_handle(struct file *fp, unsigned long arg, unsigned int cond);
int cn_pinned_mem_open_handle(struct file *fp, unsigned long arg, unsigned int cond);

int cn_pinned_mem_get_range(struct file *fp, unsigned long arg, unsigned int cond);

extern void cn_pinned_mem_do_exit(pid_t tgid);

extern struct pinned_mem_va *
cn_pinned_mem_check(struct task_struct *task, unsigned long va, unsigned long size);
extern struct pinned_mem *cn_async_pinned_mem_check(unsigned long kva);

extern unsigned long pinned_mem_info(struct seq_file *m);

extern int pinned_mem_open(void **hostmem_priv);
extern int pinned_mem_close(void *hostmem_priv);
extern void cn_pinned_mem_free_pstblk(struct pinned_mem *pst_blk);

extern struct pinned_mem *
cn_pinned_mem_get_kv_pst(pid_t tgid, unsigned long uva, u64 size, unsigned long *kva);
extern unsigned long cn_pinned_mem_get_kv(pid_t tgid, unsigned long uva, u64 size);
extern int cn_pinned_mem_put_kv(pid_t tgid, unsigned long kvaddr);

extern int cn_pinned_mem_pst_kref_get(struct pinned_mem *pst_blk);
extern int cn_pinned_mem_pst_kref_put_test(struct pinned_mem *pst_blk);

extern struct page *cn_pinned_mem_get_pages(struct pinned_mem *pst_blk, unsigned long uva_start,
	unsigned long cur_va, unsigned long *pcount);
extern int cn_pinned_mem_get_chunks(struct pinned_mem *pst_blk, unsigned long uva_start,
	unsigned long cur_va, size_t len, int *start, int *end);

extern int cn_pinned_mem_uva_locked(unsigned long va);
extern void cn_pinned_mem_uva_unlocked(unsigned long va);

/* adapt to alloc host pinned memory with numa node*/
extern int cn_pinned_mem_alloc_node(struct file *fp, unsigned long arg, unsigned int cond);
extern int cn_pinned_mem_flag_alloc(struct file *fp, unsigned long arg, unsigned int cond);
extern int cn_pinned_mem_get_device_pointer(struct file *fp, unsigned long arg, unsigned int cond);
extern int cn_pinned_mem_host_register(struct file *fp, unsigned long arg, unsigned int cond);
extern int cn_pinned_mem_host_unregister(struct file *fp, unsigned long arg, unsigned int cond);
extern int cn_pinned_mem_get_flags(struct file *fp, unsigned long arg, unsigned int cond);
#endif
