#include <linux/types.h>
#include "cndrv_core.h"
#include "cndrv_debug.h" /*cn_dev_core_err*/
#include "cndrv_mm.h"

#define SHM_SERV_STAT_OFFSET	(0x0)
int service_startup_status(struct cn_core_set *core)
{
	host_addr_t serv_stat_addr;
	int state = 0;

	if (isPCIeArmPlatform(core)) {
		return 1;
	}

	if (isEdgePlatform(core)) {
		return core->late_init_flag;
	}

	/***
	 * Check "RPC" shared memory which is in Device and Device-OS will init this address.
	 */
	serv_stat_addr = cn_shm_get_host_addr_by_name(core, "rpc_reserved");
	if (serv_stat_addr != (host_addr_t)(-1)) {
		serv_stat_addr = serv_stat_addr + SHM_SERV_STAT_OFFSET;
		state = (*(unsigned int*)serv_stat_addr);
	}
	return state;
}

void clear_serv_status(struct cn_core_set *core)
{
	host_addr_t serv_stat_addr;
	if (cn_core_is_vf(core))
		return;

	if (isPCIeArmPlatform(core)) {
		return;
	}

	if (isEdgePlatform(core)) {
		core->late_init_flag = 0;
		return;
	}

	serv_stat_addr = cn_shm_get_host_addr_by_name(core, "rpc_reserved");
	if (serv_stat_addr != (host_addr_t)(-1)) {
		serv_stat_addr = serv_stat_addr + SHM_SERV_STAT_OFFSET;
		(*(unsigned int*)serv_stat_addr) = 0;
	}
}

void set_serv_status(struct cn_core_set *core)
{
	if (isEdgePlatform(core)) {
		core->late_init_flag = 1;
	}
}
