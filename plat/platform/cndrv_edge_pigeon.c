#include <linux/io.h>
#include "cndrv_bus.h"
#include "cndrv_edge.h"
#include "cndrv_os_compat.h"
#include "cndrv_core.h"
#include "cndrv_attr.h"

#define PIGEON_SHM_PHY_ADDR	(0x410000000ULL)
#define PIGEON_SHM_PHY_SIZE	(8UL << 20)
#define PIGEON_REG_PHY_ADDR	(0x8000000000ULL)
#define PIGEON_REG_PHY_SIZE	(256UL << 20)
#define PIGEON_IPU_CFG		(0X020ULL)

extern int cn_of2shm(u64 *pa, u32 *sz);

int pigeon_edge_switch_core_type(void *priv, __u32 policy)
{
	__u32 isp_num = 0;
	__u32 nn_num = 0;
	struct cn_edge_set *edge_set = (struct cn_edge_set *)priv;
	struct cn_core_set *core = edge_set->bus_set->core;
	phys_addr_t top_sctrl = (phys_addr_t)(edge_set->reg_virt_base) + PIGEON_IPU_CFG;
	switch (policy) {
	case 0:
		iowrite32(0x80000000, (void *)top_sctrl);
		isp_num = 0;
		nn_num = 2;
		break;
	case 1:
		iowrite32(0x80008000, (void *)top_sctrl);
		isp_num = 1;
		nn_num = 1;
		break;
	default:
		break;
	}
	mb();
	cn_attr_update_aiisp(core, nn_num, isp_num);
	return 0;
}

int pigeon_edge_init(struct cn_edge_set *edge_set)
{
	u64 shm_pa = 0;
	u32 shm_sz = 0;
	int ret = 0;

	ret = cn_of2shm(&shm_pa, &shm_sz);
	if (ret < 0) {
		pr_warn("get share memory info from dts failed, use default value!\n");
		shm_pa = PIGEON_SHM_PHY_ADDR;
		shm_sz = PIGEON_SHM_PHY_SIZE;
	}

	shm_sz = (shm_sz > PIGEON_SHM_PHY_SIZE) ? PIGEON_SHM_PHY_SIZE : shm_sz;
	if (!IS_ALIGNED(shm_pa, shm_sz)) {
		pr_warn("shm_pa:%#llx, shm_sz:%#x set in device tree is illegal!\n",
				shm_pa, shm_sz);
		shm_pa = PIGEON_SHM_PHY_ADDR;
		shm_sz = PIGEON_SHM_PHY_SIZE;
	}

	edge_set->reg_virt_base =
		ioremap_nocache((phys_addr_t) (PIGEON_REG_PHY_ADDR),
				PIGEON_REG_PHY_SIZE);

	edge_set->shm_cnt = 1;
	edge_set->share_mem[0].phy_addr = shm_pa;
	edge_set->share_mem[0].virt_addr =
		ioremap_cache((phys_addr_t)shm_pa, shm_sz);
	edge_set->share_mem[0].win_length = shm_sz;
	edge_set->share_mem[0].type = CN_SHARE_MEM_DEV;
	edge_set->share_mem[0].device_addr = -1;
	edge_set->reg_phy_addr = PIGEON_REG_PHY_ADDR;
	edge_set->reg_size = PIGEON_REG_PHY_SIZE;
	return 0;
}

void pigeon_edge_exit(struct cn_edge_set *edge_set)
{
	iounmap(edge_set->share_mem[0].virt_addr);
	iounmap(edge_set->reg_virt_base);
}
