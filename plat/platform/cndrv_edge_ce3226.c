#include <linux/io.h>
#include "cndrv_bus.h"
#include "cndrv_edge.h"
#include "cndrv_os_compat.h"

#define CE3226_SHM_PHY_ADDR	(0x410000000ULL)
#define CE3226_SHM_PHY_SIZE	(8UL << 20)
#define CE3226_REG_PHY_ADDR	(0x8000000000ULL)
#define CE3226_REG_PHY_SIZE	(256UL << 20)

extern int cn_of2shm(u64 *pa, u32 *sz);

int ce3226_edge_init(struct cn_edge_set *edge_set)
{
	u64 shm_pa = 0;
	u32 shm_sz = 0;
	int ret = 0;

	ret = cn_of2shm(&shm_pa, &shm_sz);
	if (ret < 0) {
		pr_warn("get share memory info from dts failed, use default value!\n");
		shm_pa = CE3226_SHM_PHY_ADDR;
		shm_sz = CE3226_SHM_PHY_SIZE;
	}

	shm_sz = (shm_sz > CE3226_SHM_PHY_SIZE) ? CE3226_SHM_PHY_SIZE : shm_sz;
	if (!IS_ALIGNED(shm_pa, shm_sz)) {
		pr_warn("shm_pa:%#llx, shm_sz:%#x set in device tree is illegal!\n",
				shm_pa, shm_sz);
		shm_pa = CE3226_SHM_PHY_ADDR;
		shm_sz = CE3226_SHM_PHY_SIZE;
	}

	edge_set->reg_virt_base =
		ioremap_nocache((phys_addr_t) (CE3226_REG_PHY_ADDR),
				CE3226_REG_PHY_SIZE);

	edge_set->shm_cnt = 1;
	edge_set->share_mem[0].phy_addr = shm_pa;
	edge_set->share_mem[0].virt_addr =
		ioremap_cache((phys_addr_t)shm_pa, shm_sz);
	edge_set->share_mem[0].win_length = shm_sz;
	edge_set->share_mem[0].type = CN_SHARE_MEM_DEV;
	edge_set->share_mem[0].device_addr = -1;
	edge_set->reg_phy_addr = CE3226_REG_PHY_ADDR;
	edge_set->reg_size = CE3226_REG_PHY_SIZE;
	return 0;
}

void ce3226_edge_exit(struct cn_edge_set *edge_set)
{
	iounmap(edge_set->share_mem[0].virt_addr);
	iounmap(edge_set->reg_virt_base);
}

