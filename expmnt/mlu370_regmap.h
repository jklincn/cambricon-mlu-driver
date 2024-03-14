#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_debug.h"
#include "cndrv_ioctl.h"
#include "exp_mgnt_private.h"

static int check_370(struct cn_core_set *core, unsigned int index)
{
	return 1;
}


struct cndump_reg_map mlu370_regmap[] = {
	{"CPU:", 0x8500180, 0x850019c, 0, check_370}
};

