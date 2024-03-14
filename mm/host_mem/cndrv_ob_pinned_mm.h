#ifndef __CNDRV_OB_PINNED_MM__
#define __CNDRV_OB_PINNED_MM__

struct udvm_dev_map_t {
	struct sg_table *table;
	void (*sgt_release)(void *priv, struct sg_table *table);
	/*refcnt for card dma map*/
	int dma_refcnt;
	/*refcnt for device ob map*/
	int dev_refcnt;
	unsigned int dev_status;
};

struct udvm_ob_map_t {
	unsigned long iova_size;
	unsigned long iova;
	unsigned long device_pa;
	int iova_ref;

	/**
	 * protect iova, dma_refcnt, dev_refcnt, iova_ref, and they
	 * correspond to operations, and dev_status.
	 **/
	struct mutex map_lock;
	/*set MAX_OB_PHY_CARDS for phys card max nums*/
	struct udvm_dev_map_t dev_map[MAX_OB_PHYS_CARD];
};
#endif
