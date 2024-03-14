#ifndef __CNDRV_EDGE_H_
#define __CNDRV_EDGE_H_

#include <linux/interrupt.h>
#include <linux/hashtable.h>

#define LOWER32(ld) ((unsigned int)(ld & 0xFFFFFFFFu))
#define UPPER32(ld) ((unsigned int)(((unsigned long)ld >> 32) & 0xFFFFFFFFu))

typedef irqreturn_t (*interrupt_cb_t)(int irq, void *data);

struct edge_sharemem_s {
	void __iomem          *virt_addr;
	unsigned long         phy_addr;
	unsigned long         win_length;
	CN_MEM_TYPE           type;
	u64                   device_addr;
};

struct cn_edge_irq_desc {
	struct cn_edge_set          *priv; /* parent device */
	interrupt_cb_t                     handler;
	void                              *data;
};

struct cn_edge_set {
	struct cn_bus_set                 *bus_set;
	void __iomem                      *reg_virt_base;
	void *                      	compatible_pcie_set;
	unsigned long                      reg_phy_addr;
	unsigned long                      reg_size;
	spinlock_t                         interrupt_lock;
	struct cn_edge_irq_desc             irq_desc[256];/* user IRQ management */
	struct platform_device *pdev;
	unsigned int shm_cnt;
	struct edge_sharemem_s              share_mem[8];
	unsigned int device_id;
	/* async transfer management*/
	DECLARE_HASHTABLE(async_task_htable, 8);
	struct mutex async_task_hash_lock;
	struct kmem_cache                 *async_mem;
};

#ifdef CONFIG_CNDRV_EDGE
int cn_edge_drv_init(void);
void cn_edge_drv_exit(void);
#else
static inline int cn_edge_drv_init(void)
{
	return 0;
}
static inline void cn_edge_drv_exit(void){}
#endif

#endif
