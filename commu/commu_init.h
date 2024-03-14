#ifndef COMMU_INIT
#define COMMU_INIT
#include <linux/kernel.h>
#include "cndrv_core.h"

struct commu_set;
struct ctrlq_desc;

int cn_commu_init(struct cn_core_set *core);
int commu_send_command_and_wait(struct commu_set *controller,
		struct ctrlq_desc *desc, struct ctrlq_desc *dest,
		u16 command, u64 name, u64 pci_addr, u64 shadow_addr);

#ifdef COMMU_HOST_POLL
int commu_mailbox_poll_worker(void *data);
#else
irqreturn_t commu_mailbox_interrupt_worker(int index, void *data);
#endif

#endif
