#include <linux/types.h>
#include <linux/module.h>
#include <asm/io.h>

#include "cndrv_core.h"
#include "cndrv_mm.h"

#define CHANNEL_NAME_LENGTH	(20)

void setup_virtcon(struct cn_core_set *core, int en)
{
	char use_virtcon[CHANNEL_NAME_LENGTH] = "usevirtcon";
	char use_pl011[CHANNEL_NAME_LENGTH] = "usepl011";
	host_addr_t virt_addr;

	virt_addr = cn_shm_get_host_addr_by_name(core, "rpc_reserved");
	if (virt_addr != (host_addr_t)(-1)) {
		if (en) {
			memcpy_toio((void *)virt_addr, (unsigned char *)use_virtcon,
				CHANNEL_NAME_LENGTH);
		} else {
			memcpy_toio((void *)virt_addr,
				(unsigned char *)use_pl011, CHANNEL_NAME_LENGTH);
		}
	}
}

