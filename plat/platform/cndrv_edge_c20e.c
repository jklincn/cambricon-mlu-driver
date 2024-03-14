#include <linux/io.h>
#include "cndrv_bus.h"
#include "cndrv_edge.h"
#include "cndrv_os_compat.h"

#define SHM_IOVA_ADDR	(0x8002000000ULL)
#define SHM_PHY_ADDR	(0x1002000000ULL)
#define SHM_PHY_SIZE	(32UL << 20)
#define REG_PHY_ADDR	(0x8000000000ULL)
#define REG_PHY_SIZE	(32UL << 20)

int c20e_edge_init(struct cn_edge_set *edge_set)
{
	edge_set->reg_virt_base =
		ioremap_nocache((phys_addr_t) (REG_PHY_ADDR),
				REG_PHY_SIZE);

	edge_set->shm_cnt = 1;
	edge_set->share_mem[0].phy_addr = SHM_PHY_ADDR;
	edge_set->share_mem[0].virt_addr =
		ioremap_cache((phys_addr_t)SHM_PHY_ADDR, SHM_PHY_SIZE);
	edge_set->share_mem[0].win_length = SHM_PHY_SIZE;
	edge_set->share_mem[0].type = CN_SHARE_MEM_DEV;
	edge_set->share_mem[0].device_addr = -1;
	edge_set->reg_phy_addr = REG_PHY_ADDR;
	edge_set->reg_size = REG_PHY_SIZE;
	return 0;
}

void c20e_edge_exit(struct cn_edge_set *edge_set)
{
	iounmap(edge_set->share_mem[0].virt_addr);
	iounmap(edge_set->reg_virt_base);
}
