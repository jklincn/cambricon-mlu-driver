#include "cndrv_debug.h"
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "commu_internal.h"
#include "commu_init.h"
#include "cndrv_commu.h"
#include "../core/version.h"
#ifdef CONFIG_CNDRV_CNLOG
#include <linux/soc/cambricon/cndrv_cnlog.h>
#endif
#include "cndrv_kwork.h"

static void dump_mem(const char *tag, u8 *pdata, u32 nsize)
{
	int i = 0;
	printk("[COMMU]dumpmem: %s\n", tag);
	for(i = 0; i < nsize;) {
		printk(KERN_CONT "%02x ", pdata[i]);
		if (++i%16 == 0) printk(KERN_CONT "\n");
	}
	if (i % 16 != 0)
		printk(KERN_CONT "\n");
}

static inline uint64_t rte_rdtsc(void)
{
#if defined(__x86_64__)
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

	__asm volatile("rdtsc" :
		     "=a" (tsc.lo_32),
		     "=d" (tsc.hi_32));
	return tsc.tsc_64;
#elif defined(__aarch64__)
	uint64_t tsc;

	asm volatile("mrs %0, cntvct_el0" : "=r" (tsc));
	return tsc;
#else
	return 0;
#endif
}

int commu_send_command_and_wait(struct commu_set *controller,
		struct ctrlq_desc *desc, struct ctrlq_desc *dest,
		u16 command, u64 name, u64 pci_addr, u64 shadow_addr)
{
#define COMMU_COMMAND_WAIT_TIMEOUT (1999999UL)
	int time = COMMU_COMMAND_WAIT_TIMEOUT;
	int ret;

	/*FIXME
	 * too many reset_sign check in commu related apis
	 */
	if (unlikely(controller->reset_sign)) {
		COMMU_DBG("arm may hang, quit here.\n");
		return -2;
	}

	/*FIXME
	 * use a queue related mechanism to suspend ctrlq
	 */
	if (controller->suspend_tx)
		wait_event_killable(controller->migration_waitqueue,
			(!controller->suspend_tx));
	/*
	 * COMMU_PF_ID will be overwritten with real vf_id if we are vf,
	 * and if we are pf, this value will be send to arm directly.
	 */
	desc->vf_num = controller->pf_id;
	desc->command = command;
	desc->name = name;
	desc->pci_addr = pci_addr;
	desc->shadow_addr = shadow_addr;
	desc->seq = ctrlq_gen_seq(controller->ctrlq_send);
	ctrlq_put(controller->ctrlq_send, desc);
	controller->doorbell(controller->core_set);

	if (desc->command != COMMU_CMD_CPP)
		COMMU_DBG("command %x send. before wait %llx %x\n",
			(int)command, controller->on_polling, desc->seq);

	/*
	 * May here a concurrency issue?
	 * we seek, prepare for get, and e001 branch get before us
	 * something will wrong here
	 */
	/*
	 * Sync for the COMMU_CMD_CME_BOTTOM response, for arm side init process
	 * may have not finished, if return immediately here and
	 * afterwards the rpc be called, the calling may fail.
	 * */
	if (command == COMMU_CMD_HOSTP_HUP || command == COMMU_CMD_HOSTR_HUP) {
		ret = wait_event_killable(controller->commu_hup_waitqueue,
				(desc->seq == controller->hup_desc.seq
				 || controller->reset_sign));
	} else {
		ret = wait_event_killable(controller->commu_waitqueue,
				(!controller->suspend_rx &&
				(desc->seq == controller->desc.seq
				 || controller->reset_sign)));
	}

	if (controller->reset_sign) {
		COMMU_DBG("return timeout when in CN_RESET procedure.\n");
		return -2;
	}

	/* concurrency issue if not handle killable signal */
	if (ret == -ERESTARTSYS) {
		COMMU_INFO("fatal signal received. command will quit\n");

		while (--time) {
			if(desc->seq == controller->hup_desc.seq ||
					desc->seq == controller->desc.seq) {
				COMMU_INFO("user abort, command %x run success.\n",
						desc->seq);
				goto command_go;
			}

			/* sigkill & dev reset happen at the same time */
			if (controller->reset_sign) {
				COMMU_INFO("handle fatal signal when in CN_RESET happen.\n");
				return -2;
			}

			usleep_range(2, 5);
		}

		if (unlikely(!time)) {
			COMMU_INFO("[ERR] user abort, command %x run timeout.\n",
					desc->seq);
			goto command_quit;
		}
	}

command_go:
	if (dest)
		memcpy(dest, &controller->desc, sizeof(struct ctrlq_desc));
	controller->on_polling = 0;

	if (desc->command != COMMU_CMD_CPP)
		COMMU_DBG("after wait  %llx %x\n",
				controller->on_polling, desc->seq);
	return 0;

command_quit:
	return -ETIMEDOUT;
}

void commu_touch_doorbell(void *core_set) {
#define MBX_V2P_CTRL_C20l		(0x1000)
#define MBX_V2P_CTRL_C20		(0x0000)
#define MBX_V2P_CTRL_C30S		(0x1028)
#define MBX_V2P_CTRL_C50		(0x1048)
	struct cn_core_set *core = (struct cn_core_set *)core_set;
	struct cn_bus_set *bus = core->bus_set;

	if (core->device_id == MLUID_270V || core->device_id == MLUID_270V1)
		reg_write32(bus, MBX_V2P_CTRL_C20l, 1);
	else if (core->device_id == MLUID_290V1)
		reg_write32(bus, MBX_V2P_CTRL_C20, 1);
	else if (core->device_id == MLUID_370V)
		reg_write32(bus, MBX_V2P_CTRL_C30S, 1);
	else if (isCEPlatform(core)) {
		WARN_ON(1);
	} else if (core->device_id == MLUID_590V || core->device_id == MLUID_580V)
		reg_write32(bus, MBX_V2P_CTRL_C50, 1);
}

void commu_dummy_doorbell(void *core_set) {
	return;
}

/* only in 220 EDGE, host driver can see this MACRO defined in "dev" kernel */
#ifdef CONFIG_CNDRV_EDGE
extern void commu_dev_worker(u64 _ep);
extern void commu_dev_ctrlq_poll_work(void);
void commu_c20e_som_doorbell(void *core_set) {
	commu_dev_ctrlq_poll_work();
}

static void commu_mailbox_handler_timer_work(struct commu_set *controller)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint, *ep_next;
	struct hlist_node *tmp;
	int i;

	hash_for_each_safe(controller->commu_channel_head,
				i, tmp, channel, channel_node) {
		if (channel->kernel_channel) {
			llist_for_each_entry_safe(endpoint, ep_next,
				channel->channel_endpoints_head.first,
				channel_node) {
				if (!endpoint->rx.ops)
					continue;
				if (endpoint->rx.ops->query_new(endpoint->rx.real_queue))
					wake_up(&endpoint->waitqueue);
			}
		}
	}
}

static void commu_mailbox_handler_timer(struct work_struct *work)
{
	struct commu_set *controller = container_of(work, struct commu_set,
			poll_work.work);

	commu_mailbox_handler_timer_work(controller);
	schedule_delayed_work(&controller->poll_work, msecs_to_jiffies(2000));
}
#endif

void commu_touch_dev_doorbell(void *_ep)
{
	struct commu_endpoint *ep = (struct commu_endpoint *)_ep;
	struct cn_core_set *core = NULL;
	struct commu_set *controller = NULL;

	if (!ep || !ep->channel || !ep->tx.ops || !ep->channel->controller)
		return;

	controller = (struct commu_set *)ep->channel->controller;
	core = (struct cn_core_set *)controller->core_set;

	if (!core || !core->bus_set)
		return;

#ifdef COMMU_ENABLE_DATA_INTERRUPT
	struct cn_bus_set *bus = core->bus_set;
	/*
	 * 220M.2 low power mode
	 *
	 * 270
	 * reg_write32(bus, 0x1520a8, 1);
	 *
	 * 220_EDGE
	 * call dev func directly
	 */
	if (core->device_id == MLUID_220) {
		reg_write32(bus, 0xb1a0a8, 1);
	}
#endif

#ifdef CONFIG_CNDRV_EDGE
	commu_dev_worker(ep->id);
#endif
}

#ifndef llist_for_each_entry_safe
#define llist_for_each_entry_safe(pos, n, node, member)        \
	for (pos = llist_entry((node), typeof(*pos), member);   \
			member_address_is_nonnull(pos, member) &&       \
			(n = llist_entry(pos->member.next, typeof(*n), member), true);  \
			pos = n)
#endif

#ifndef member_address_is_nonnull
#define member_address_is_nonnull(ptr, member) \
	((uintptr_t)(ptr) + offsetof(typeof(*(ptr)), member) != 0)
#endif

/*TODO
 * define errno of commu api
 *
 * -1 suspend ECOMMUSUSPEND
 *
 * -2 reset ECOMMURESET
 *
 *  message queue depends on module owner handle suspend first(stop pick/recv queue msg)
 */
static void commu_live_migration_handler(struct work_struct *work)
{
	struct commu_set *controller = (struct commu_set *)container_of(work,
			struct commu_set, migration_work);
	struct commu_channel *channel;
	struct commu_endpoint *ep, *ep_next;
	struct hlist_node *tmp;
	int i, ret;
	int32_t mig_command = controller->migration_command;

	controller->migration_command = -1;

	switch (mig_command) {
	case COMMU_MIGRATION_SUSPEND_TX:
		COMMU_INFO("[migraion] suspend tx\n");
		controller->suspend_tx = 1;

		hash_for_each_safe(controller->commu_channel_head,
				i, tmp, channel, channel_node) {
			if (!channel->kernel_channel)
				continue;

			llist_for_each_entry_safe(ep, ep_next,
					channel->channel_endpoints_head.first,
					channel_node) {
				if (!ep->tx.ops)
					continue;

				ret = ep->tx.ops->suspend(ep->tx.real_queue);

				if (!ep->tx.ops->is_suspended(ep->tx.real_queue))
					COMMU_INFO("[ERR]set suspend flag failed\n");
			}
		}
		break;
	case COMMU_MIGRATION_RESUME_TX_RX:
		COMMU_INFO("[migraion] resume rx\n");
		/* resume rx first */
		controller->suspend_rx = 0;
		hash_for_each_safe(controller->commu_channel_head,
				i, tmp, channel, channel_node) {
			if (!channel->kernel_channel)
				continue;

			llist_for_each_entry_safe(ep, ep_next,
					channel->channel_endpoints_head.first,
					channel_node) {
				if (!ep->tx.ops)
					continue;

				wake_up(&ep->waitqueue);

				ret = ep->tx.ops->resume(ep->tx.real_queue);
			}
		}

		/* resume tx */
		COMMU_INFO("[migraion] resume tx\n");
		controller->suspend_tx = 0;
		wake_up(&controller->migration_waitqueue);
		break;
	default:
		COMMU_INFO("[migraion] command not support\n");
	}
}

#define PCIE_IRQ_GIC_ARM2PF         (25)
#define PCIE_IRQ_GIC_ARM2PF_C20     (34)
#define PCIE_IRQ_GIC_ARM2PF_C20e    (163)
#define PCIE_IRQ_GIC_ARM2PF_C30e    (210)
#define PCIE_IRQ_GIC_ARM2PF_C30S	(11)
#define PCIE_IRQ_GIC_ARM2PF_C50     (18)
#define PCIE_IRQ_GIC_ARM2PF_PIGEON  (328)
void cn_commu_pcie_sram_exit(struct cn_core_set *core)
{
	struct commu_set *controller = core->commu_set;
	struct commu_pcie_sram_set *sram = controller->sram;

	if (!controller->en_pcie_sram) {
		return;
	}

	if (!sram) {
		COMMU_INFO("commu pcie sram is NULL!\n");
		return;
	}

	cn_kfree(sram);

	controller->sram = NULL;
}

int cn_commu_pcie_sram_init(struct cn_core_set *core)
{
	struct commu_set *controller = core->commu_set;
	struct commu_pcie_sram_set *sram;
	host_addr_t host_base;
	dev_addr_t dev_base;
	phy_addr_t phy_base;
	size_t size;
	struct ctrlq_desc desc = {0};
	int ret = 0;

	if (!controller->en_pcie_sram) {
		return 0;
	}

	sram = cn_kzalloc(sizeof(struct commu_pcie_sram_set), GFP_KERNEL);
	if (!sram) {
		COMMU_INFO("kmalloc commu_pcie_sram_set failed!\n");
		return -1;
	}

	/* get pcie sram va/pa/size */
	ret = cn_sram_get_base_addr(0, &host_base, &dev_base,
			&phy_base, &size, core);
	if (ret) {
		COMMU_INFO("get pcie sram base addr and size failed!\n");
		goto out_free_set;
	}

	sram->sram_va = (u64)host_base;
	sram->sram_ba = (u64)dev_base;
	sram->sram_dev_pa = (u64)phy_base;
	COMMU_INFO("sram_va:%#llx sram_ba:%#llx sram_dev_pa:%#llx size:%#lx\n",
			sram->sram_va, sram->sram_ba, sram->sram_dev_pa, size);

	/* send cmd and wait device init pcie sram */
	ret = commu_send_command_and_wait(controller, &desc, NULL,
			COMMU_CMD_PCIE_SRAM_INIT, desc.name,
			(u64)phy_base, (u64)size);
	if (ret) {
		COMMU_INFO("commu cmd pcie sram init failed!\n");
		goto out_free_set;
	}

	controller->sram = sram;
	COMMU_INFO("commu pcie sram init succ!\n");
	return 0;

out_free_set:
	cn_kfree(sram);
	return -1;
}

int c20l_vf_commu_cdev_init(struct commu_set *controller);
int cn_commu_pre_init(struct cn_core_set *core)
{
	struct commu_set *controller;
	struct cn_bus_set *bus = core->bus_set;
	host_addr_t pshare_addr = 0;
	dev_addr_t pshare_dev_addr = 0;

	if (core->device_id == MLUID_370_DEV) {
		COMMU_DBG("no support 370 dev.\n");
		return 0;
	}

	if (core->device_id == MLUID_590_DEV) {
		COMMU_DBG("no support 590 dev.\n");
		return 0;
	}

	controller = cn_kzalloc(sizeof(*controller), GFP_KERNEL);
	if (!controller) {
		COMMU_DBG("kmalloc commu_set failed!\n");
		return -1;
	}

	core->commu_set = controller;
	controller->core_set = core;
	controller->on_polling = 0;
	controller->reset_sign = 0;
	controller->en_outbound = (int32_t)cn_bus_outbound_able(bus);
	controller->en_pcie_sram = (int32_t)cn_bus_pcie_sram_able(bus);
	controller->en_sync_write = (int32_t)cn_bus_sync_write_able(bus);
	init_waitqueue_head(&controller->commu_waitqueue);
	init_waitqueue_head(&controller->commu_hup_waitqueue);
	INIT_WORK(&controller->migration_work, commu_live_migration_handler);
	init_waitqueue_head(&controller->migration_waitqueue);
	hash_init(controller->commu_channel_head);
	mutex_init(&controller->mutex);
	mutex_init(&controller->user_mutex);

	/*
	 * MLU200's commu pf id is COMMU_VF_NUM, MLU300 is 0.
	 * Because MLU300 don't use commu in user app, so user don't modify
	 */
	switch (core->device_id) {
	case MLUID_100:
	case MLUID_270:
	case MLUID_270V:
	case MLUID_270V1:
	case MLUID_290:
	case MLUID_290V1:
	case MLUID_220:
	case MLUID_220_EDGE:
		controller->pf_id = 0x4;
		break;

	default:
		controller->pf_id = 0;
		break;
	}

	if (!isMlu100SeriesProduct(core) && !cn_core_is_vf(core)) {
		int i;
		pshare_addr = cn_shm_get_host_addr_by_name(core, "commu_reserved");
		pshare_dev_addr = cn_shm_get_dev_addr_by_name(core, "commu_reserved");
		COMMU_DBG("%s: local addr %px dev addr %px\n", __func__,
				(void *)pshare_addr, (void *)pshare_dev_addr);

		*(int32_t *)((void *)pshare_addr + COMMU_OUTBOUND_CFG_OFFSET) = controller->en_outbound;
		/* pf only: ctrlq from reserve memory */
		ctrlq_alloc(&controller->pf2arm, (void *)pshare_addr, 32);

		if (!controller->en_outbound) {
			ctrlq_alloc(&controller->arm2pf, (void *)pshare_addr + 0x1000, 32);
			ctrlq_alloc(&controller->arm2pf_user, (void *)pshare_addr + 0x2000, 32);
			controller->ctrlq_recv_user = &controller->arm2pf_user;
			controller->ctrlq_recv = &controller->arm2pf;
		} else {
			ctrlq_alloc(&controller->pf_user2arm, (void *)pshare_addr + 0x3000, 32);
			controller->ctrlq_send_user = &controller->pf_user2arm;
		}
		controller->ctrlq_send = &controller->pf2arm;
		controller->doorbell = commu_dummy_doorbell;
		controller->data_doorbell = commu_touch_dev_doorbell;

		controller->ib_va = (u64)cn_bus_get_mem_base(bus, 0);
		//#define COMMU_INBOUND_BASE (0x8008000000)
		controller->ib_ba = cn_shm_get_dev_va_base(core);
		if (controller->en_outbound) {
			controller->ob_ba = (u64)cn_bus_get_device_addr(bus, 1);
			controller->ob_va = (void *)cn_bus_get_mem_base(bus, 1);
		} else {
			controller->ob_ba = (dma_addr_t)controller->ib_ba;
			controller->ob_va = (void *)controller->ib_va;
		}
		for (i = 0; i < COMMU_VF_NUM; i++)
			controller->init_sign[i] = 0;

	} else if (cn_core_is_vf(core)) {
		controller->doorbell = commu_touch_doorbell;
		controller->data_doorbell = commu_touch_dev_doorbell;
		controller->ib_va = (u64)cn_bus_get_mem_base(bus, 0);
		controller->ib_ba = cn_shm_get_dev_va_base(core);
		if (controller->en_outbound) {
			controller->ob_va = (void *)cn_bus_get_mem_base(bus, 1);
			controller->ob_ba = (u64)cn_bus_get_device_addr(bus, 1);
		} else {
			controller->ob_ba = (dma_addr_t)controller->ib_ba;
			controller->ob_va = (void *)controller->ib_va;
		}
		cn_commu_init(core);
	}

#ifdef CONFIG_CNDRV_EDGE
	/*FIXME should be case of 220 som */
	controller->doorbell = commu_c20e_som_doorbell;
	controller->ib_va =  (u64)cn_bus_get_mem_base(core->bus_set, 0);
	controller->ib_ba = cn_shm_get_dev_va_base(core);
	controller->ob_ba = (dma_addr_t)controller->ib_ba;
	controller->ob_va = (void *)controller->ib_va;

	INIT_DELAYED_WORK(&controller->poll_work, commu_mailbox_handler_timer);
	schedule_delayed_work(&controller->poll_work, msecs_to_jiffies(500));

#endif
	if (MLUID_MAJOR_ID(core->device_id) == 2)
		c20l_vf_commu_cdev_init(controller);

	return 0;
}

static void pigeon_clear_history_mail(struct cn_core_set *core)
{
	/***
	 * For pigeon, read 18b058 will clean mailbox.
	 * NOTE:
	 *	when use MSI type, this unclear state will lead no new IRQ during
	 *	heartbeat process.
	 */
	int level = 0;
	int max_level = 0;
	int reg_val = 0;

	reg_val = reg_read32(core->bus_set, 0x18b050);
	max_level = (reg_val & 0x700) >> 8;
	for (level = 0; level < max_level; level++) {
		reg_read32(core->bus_set, 0x18b058);
	}
}

void commu_register_arm2pf_interrupt(struct cn_core_set *core);
int cn_commu_init(struct cn_core_set *core)
{
	/* c20l specific, should use ops */
#define MBX_V2P_ADDR_L_C20		(0x0004)
#define MBX_V2P_ADDR_L_C20l		(0x1004)
#define CMD_ALLOC_COMMU_CTRLQ		(0xcabc)
	host_addr_t ib_host_vaddr;
	dev_addr_t ib_device_vaddr;
	host_addr_t host_vaddr;
	dev_addr_t device_vaddr;
	int ret;
	u32 offset;
	struct cn_bus_set *bus = core->bus_set;
	struct commu_set *controller = core->commu_set;
	struct ctrlq_desc desc;
	unsigned long mailbox_base = 0;

	/* inbound ctrlq init*/
	{
	ret = cn_device_share_mem_alloc(0, &host_vaddr, &device_vaddr,
			0x1000, core);
	if (ret)
		return 1;
	COMMU_DBG("%s host%llx  device%llx\n", __func__, (u64)host_vaddr, (u64)device_vaddr);

	if (core->device_id == MLUID_270V || core->device_id == MLUID_270V1)
		mailbox_base = MBX_V2P_ADDR_L_C20l;
	else if (core->device_id == MLUID_290V1)
		mailbox_base = MBX_V2P_ADDR_L_C20;

	if (core->device_id == MLUID_370V) {
		offset = (u32)device_vaddr;
		/* wait for avail mbox, not full */
		while (reg_read32(bus, 0x1020) & 0x1u) {
			schedule();
			msleep(1);
		}

		reg_write32(bus, 0x1024, offset);
		wmb();/* make sure write order */
		reg_write32(bus, 0x1028, CMD_ALLOC_COMMU_CTRLQ << 16);
		offset = (u32)(device_vaddr >> 32);

		/* wait for avail mbox, not full */
		while (reg_read32(bus, 0x1020) & 0x1u) {
			schedule();
			msleep(1);
		}

		reg_write32(bus, 0x1024, offset);
		wmb();/* make sure write order */
		reg_write32(bus, 0x1028, (CMD_ALLOC_COMMU_CTRLQ << 16)
							| 0x1u << 1 | 0x1u);
		wait_event_interruptible_timeout(controller->commu_waitqueue,
			controller->ctrlq_alloc_wait_flag == 1,
			msecs_to_jiffies(10000));
	} else if (core->device_id == MLUID_590V || core->device_id == MLUID_580V) {
		offset = (u32)device_vaddr;
		reg_write32(bus, 0x1044, offset);
		wmb();
		reg_write32(bus, 0x1048, CMD_ALLOC_COMMU_CTRLQ << 16);
		offset = (u32)(device_vaddr >> 32);
		reg_write32(bus, 0x1044, offset);
		wmb();/* make sure write order */
		reg_write32(bus, 0x1048, (CMD_ALLOC_COMMU_CTRLQ << 16)
							| 0x1u << 1 | 0x1u);
		wait_event_interruptible_timeout(controller->commu_waitqueue,
			controller->ctrlq_alloc_wait_flag == 1,
			msecs_to_jiffies(10000));
	} else {
		reg_write32(bus, mailbox_base, CMD_ALLOC_COMMU_CTRLQ);
		controller->doorbell(controller->core_set);
		while (reg_read32(bus, mailbox_base) ==
			CMD_ALLOC_COMMU_CTRLQ) {
			msleep(1);
		}
		/* 0x8008000000 bar0 + 128M   base of pci share memory */
		offset = (device_vaddr - 0x8008000000) & 0x00000000ffffffff;
		reg_write32(bus, mailbox_base, offset);
		while (reg_read32(bus, mailbox_base) == offset)
			msleep(1);
	}

	ctrlq_alloc(&controller->vf2pf, (void *)host_vaddr, 32);
	controller->ctrlq_send = &controller->vf2pf;
	}

	/* outbound ctrlq init */
	{
	if (controller->en_outbound) {
		ret = cn_host_share_mem_alloc(0, &host_vaddr, &device_vaddr,
				0x2000, core);
		ret = cn_device_share_mem_alloc(0, &ib_host_vaddr, &ib_device_vaddr,
				0x2000, core);
		desc.name = 0x1;
	} else {
		ret = cn_device_share_mem_alloc(0, &host_vaddr, &device_vaddr,
				0x2000, core);
		ib_host_vaddr = (u64)controller->ib_va;
		desc.name = 0x0;
	}
	COMMU_DBG("outbound %s host%llx  device%llx\n", __func__, (u64)host_vaddr, (u64)device_vaddr);
	ctrlq_alloc(&controller->arm2vf, (void *)host_vaddr, 32);
	ctrlq_alloc(&controller->arm2vf_user, (void *)host_vaddr+0x1000, 32);
	if (controller->en_outbound) {
		ctrlq_alloc(&controller->vf2arm, (void *)ib_host_vaddr, 32);
		ctrlq_alloc(&controller->vf_user2arm, (void *)ib_host_vaddr + 0x1000, 32);
		(void)ctrlq_set_shadow(&controller->vf2arm, &controller->arm2vf);
		(void)ctrlq_set_shadow(&controller->vf_user2arm, &controller->arm2vf_user);
	}
	controller->ctrlq_recv = &controller->arm2vf;
	controller->ctrlq_recv_user = &controller->arm2vf_user;

#ifdef COMMU_HOST_POLL
	/*
	 * if HOST_POLL enabled, vf poll should init before the
	 * next send command func, or vf will sleep on wait_event
	 * there and has no one wake it up.
	 */
	commu_register_arm2pf_interrupt(core);
#endif
	commu_send_command_and_wait(controller, &desc, NULL,
			COMMU_CMD_SET_ARM2VF_ADDR, desc.name,
			(u64)ib_host_vaddr - (u64)controller->ib_va,
			(u64)host_vaddr - (u64)controller->ob_va);
	}

	ret = cn_commu_pcie_sram_init(core);
	if (unlikely(ret)) {
		COMMU_INFO("commu pcie sram init failed!\n");
		return ret;
	}

	return 0;
}

void commu_register_arm2pf_interrupt(struct cn_core_set *core)
{
#ifdef COMMU_HOST_POLL
	struct commu_set *controller = core->commu_set;

	controller->poll_worker = kthread_create(commu_mailbox_poll_worker,
			core, "commu_poll_idx%d", core->idx);
	COMMU_INFO("COMMU_POLL init %llx\n", core->device_id);

	wake_up_process(controller->poll_worker);
#else
	/* register interrupt for pf */
	if (core->device_id == MLUID_270) {
		cn_bus_register_interrupt(core->bus_set, PCIE_IRQ_GIC_ARM2PF,
				commu_mailbox_interrupt_worker, core);
		reg_write32(core->bus_set, 0x1520a4, 0);
		cn_bus_enable_irq(core->bus_set, PCIE_IRQ_GIC_ARM2PF);
	} else if (core->device_id == MLUID_290) {
		cn_bus_register_interrupt(core->bus_set, PCIE_IRQ_GIC_ARM2PF_C20,
				commu_mailbox_interrupt_worker, core);
		reg_write32(core->bus_set, 0x14406c, 0);
		cn_bus_enable_irq(core->bus_set, PCIE_IRQ_GIC_ARM2PF_C20);
	} else if (core->device_id == MLUID_220) {
		cn_bus_register_interrupt(core->bus_set, PCIE_IRQ_GIC_ARM2PF_C20e,
				commu_mailbox_interrupt_worker, core);
		reg_write32(core->bus_set, 0xb1a0a4, 0);
		cn_bus_enable_irq(core->bus_set, PCIE_IRQ_GIC_ARM2PF_C20e);
	} else if (core->device_id == MLUID_370) {
		#if defined(IPCM_COMMU_SHARED_IRQ) || defined(IPCM_POLLING_MODE)
		uint32_t reg_val;

		cn_bus_register_interrupt(core->bus_set, PCIE_IRQ_GIC_ARM2PF_C30S,
				commu_mailbox_interrupt_worker, core);
		reg_val = reg_read32(core->bus_set, 0x2232c);
		reg_write32(core->bus_set, 0x2232c, reg_val & 0x7FE);
		cn_bus_enable_irq(core->bus_set, PCIE_IRQ_GIC_ARM2PF_C30S);
		#endif
	} else if (core->device_id == MLUID_CE3226) {
		cn_bus_register_interrupt(core->bus_set, PCIE_IRQ_GIC_ARM2PF_C30e,
				commu_mailbox_interrupt_worker, core);
		cn_bus_enable_irq(core->bus_set, PCIE_IRQ_GIC_ARM2PF_C30e);
	} else if (core->device_id == MLUID_PIGEON) {
		cn_bus_register_interrupt(core->bus_set, PCIE_IRQ_GIC_ARM2PF_PIGEON,
				commu_mailbox_interrupt_worker, core);
		pigeon_clear_history_mail(core);
		cn_bus_enable_irq(core->bus_set, PCIE_IRQ_GIC_ARM2PF_PIGEON);
	} else if (core->device_id == MLUID_590 || core->device_id == MLUID_580) {
		#if defined(IPCM_COMMU_SHARED_IRQ) || defined(IPCM_POLLING_MODE)
		uint32_t reg_val;

		cn_bus_register_interrupt(core->bus_set, PCIE_IRQ_GIC_ARM2PF_C50,
		commu_mailbox_interrupt_worker, core);
		reg_val = reg_read32(core->bus_set, 0x4348);
		reg_write32(core->bus_set, 0x4348, reg_val & (~(0x1 << 0)));
		cn_bus_enable_irq(core->bus_set, PCIE_IRQ_GIC_ARM2PF_C50);
		#endif
	}

#endif
}

void commu_unregister_arm2pf_interrupt(struct cn_core_set *core)
{
#ifdef COMMU_HOST_POLL
	struct commu_set *controller = core->commu_set;

	kthread_stop(controller->poll_worker);
	/* commu_set should free and set null after kthread stop */
	if (core->commu_set) {
		cn_kfree(core->commu_set);
		core->commu_set = NULL;
	}
#else
	struct cn_bus_set *bus = core->bus_set;

	/* commu_set should free and set null before irq disable */
	if (core->commu_set) {
		cn_kfree(core->commu_set);
		core->commu_set = NULL;
	}

	if (core->device_id == MLUID_270) {
		cn_bus_unregister_interrupt(bus, PCIE_IRQ_GIC_ARM2PF);
		cn_bus_disable_irq(bus, PCIE_IRQ_GIC_ARM2PF);
	} else if (core->device_id == MLUID_290) {
		cn_bus_unregister_interrupt(bus, PCIE_IRQ_GIC_ARM2PF_C20);
		cn_bus_disable_irq(bus, PCIE_IRQ_GIC_ARM2PF_C20);
	} else if (core->device_id == MLUID_220) {
		cn_bus_unregister_interrupt(bus, PCIE_IRQ_GIC_ARM2PF_C20e);
		cn_bus_disable_irq(bus, PCIE_IRQ_GIC_ARM2PF_C20e);
	} else if (core->device_id == MLUID_370) {
		cn_bus_unregister_interrupt(bus, PCIE_IRQ_GIC_ARM2PF_C30S);
		cn_bus_disable_irq(bus, PCIE_IRQ_GIC_ARM2PF_C30S);
	} else if (core->device_id == MLUID_CE3226) {
		cn_bus_unregister_interrupt(bus, PCIE_IRQ_GIC_ARM2PF_C30e);
		cn_bus_disable_irq(bus, PCIE_IRQ_GIC_ARM2PF_C30e);
	} else if (core->device_id == MLUID_590 || core->device_id == MLUID_580) {
		cn_bus_unregister_interrupt(bus, PCIE_IRQ_GIC_ARM2PF_C50);
		cn_bus_disable_irq(bus, PCIE_IRQ_GIC_ARM2PF_C50);
	} else if (core->device_id == MLUID_PIGEON) {
		cn_bus_unregister_interrupt(bus, PCIE_IRQ_GIC_ARM2PF_PIGEON);
		cn_bus_disable_irq(bus, PCIE_IRQ_GIC_ARM2PF_PIGEON);
	}

#endif
}

int cn_commu_late_init(struct cn_core_set *core)
{
	int ret = 0;
	struct commu_set *controller = core->commu_set;

	if (controller->en_outbound) {
		host_addr_t host_vaddr;
		dev_addr_t device_vaddr;
		struct ctrlq_desc desc;

		/* only init outbount ctrlq for PF */
		if (core->device_id == MLUID_220)
			return 0;
		/* pf also need host memory to accelerate pcie */
		host_vaddr = cn_shm_get_host_addr_by_name(core, "commu_OB");
		device_vaddr = cn_shm_get_dev_addr_by_name(core, "commu_OB");
		COMMU_DBG("--- outbound %s host%px  device%px\n", __func__, (void *)host_vaddr, (void *)device_vaddr);
		ctrlq_alloc(&controller->arm2pf_host, (void *)host_vaddr, 32);
		ctrlq_alloc(&controller->arm2pf_user, (void *)host_vaddr+0x1000, 32);
		controller->ctrlq_recv = &controller->arm2pf_host;
		controller->ctrlq_recv_user = &controller->arm2pf_user;

		(void)ctrlq_set_shadow(controller->ctrlq_send, controller->ctrlq_recv);
		(void)ctrlq_set_shadow(controller->ctrlq_send_user, controller->ctrlq_recv_user);
		/* enable irq after ctrlq is ready */
		//cn_bus_enable_irq(core->bus_set, PCIE_IRQ_GIC_ARM2PF);
		commu_register_arm2pf_interrupt(core);
		desc.name = 0x1;
		commu_send_command_and_wait(controller, &desc, NULL,
				COMMU_CMD_SET_ARM2VF_ADDR, desc.name,
				desc.pci_addr,
				(u64)host_vaddr - (u64)controller->ob_va);
	} else {
		commu_register_arm2pf_interrupt(core);
	}

	ret = cn_commu_pcie_sram_init(core);
	if (unlikely(ret)) {
		COMMU_INFO("commu pcie sram init failed!\n");
		return ret;
	}

	return 0;
}

void cn_commu_late_exit(struct cn_core_set *core)
{
	struct commu_set *controller = core->commu_set;
	struct hlist_node *tmp;
	struct commu_channel *channel;
	int i;

	/* scan channel list, free all endpoints */
	hash_for_each_safe(controller->commu_channel_head,
			i, tmp, channel, channel_node) {
		COMMU_INFO("free channel %s\n", channel->name);
		close_a_channel(channel);
	}

	return;
}

static int c20l_vf_commu_cdev_exit(struct commu_set *controller);
void cn_commu_pre_exit(struct cn_core_set *core)
{
	struct commu_set *controller = core->commu_set;

#ifdef CONFIG_CNDRV_EDGE
	cancel_delayed_work_sync(&controller->poll_work);
	flush_work(&controller->poll_work.work);
#endif

	if (cn_core_is_vf(core)) {
		struct ctrlq_desc desc;

		/* vf leave */
		commu_send_command_and_wait(controller, &desc, NULL,
				COMMU_CMD_VF_EXIT, desc.name,
				desc.pci_addr, desc.shadow_addr);
	}

	if (core->device_id == MLUID_270 || core->device_id == MLUID_290
		|| core->device_id == MLUID_270V || core->device_id == MLUID_270V1
		|| core->device_id == MLUID_290V1)
		c20l_vf_commu_cdev_exit(core->commu_set);

	cn_commu_pcie_sram_exit(core);

	commu_unregister_arm2pf_interrupt(core);
}

int cn_commu_reset_callback(struct cn_core_set *core)
{
	struct commu_set *controller = core->commu_set;
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;
	int i;

	controller->reset_sign = 1;

	/*
	 * 1. wake_up all kernel endpoint blocked by wait_event
	 * 2. send server HUP event to userspace)
	 */
	hash_for_each(controller->commu_channel_head,
			i, channel, channel_node) {
		COMMU_INFO("channel %s\n", channel->name);
		if (!channel->kernel_channel) {
			/*
			 * TODO, should do
			 * schedule_work(&endpoint->channel->hup_work);
			 * sync here instead of continue;
			 */
			continue;
		}
		llist_for_each_entry(endpoint,
				channel->channel_endpoints_head.first,
				channel_node) {
			if (endpoint->channel && endpoint->channel->kernel_channel) {
				COMMU_INFO("-- endpoint %px type %d\n",
						endpoint,
						endpoint->type);
				wake_up(&endpoint->waitqueue);
			}
		}
	}

	return 0;
}

static inline void commu_ctrlq_all_dump(struct commu_set *controller)
{
	pr_info("===========ctrlq dump begin===============\n");
	pr_err("[COMMU ERR]current rx status:\n"
			"lh%u lt%u rh%u rt%u\n",
			controller->ctrlq_recv->head,
			controller->ctrlq_recv->tail,
			controller->ctrlq_recv->ring->head,
			controller->ctrlq_recv->ring->tail);
	/*
	 *dump_mem("ctrlq rx ring", (char *)controller->ctrlq_recv->ring,
	 *                sizeof(struct ctrlq_desc) * 32 + 8);
	 *dump_mem("ctrlq tx ring", (char *)controller->ctrlq_send->ring,
	 *                sizeof(struct ctrlq_desc) * 32 + 8);
	 */
	pr_info("===========ctrlq dump finished=============\n");

}

void commu_ctrlq_sync(struct commu_set *controller, struct ctrlq_desc *desc,
		int interruptible, int hup)
{
	u64 start, end;

	start = get_jiffies_64();
	while (test_and_set_bit(0, (long unsigned int *)&(controller->on_polling))) {
		end = get_jiffies_64();
		if (time_after64(end, start + HZ)) {
			wake_up(&controller->commu_hup_waitqueue);
			commu_ctrlq_all_dump(controller);
			break;
		}
	}

	if (desc->command != COMMU_RET_CPP)
		COMMU_DBG("set polling bit %x %x\n", desc->command, desc->seq);

	if (hup) {
		memcpy(&controller->hup_desc, desc, sizeof(struct ctrlq_desc));
		wake_up(&controller->commu_hup_waitqueue);
	} else {
		memcpy(&controller->desc, desc, sizeof(struct ctrlq_desc));
		wake_up(&controller->commu_waitqueue);
	}
}

static void commu_ctrlq_redirect_msg_to_user(struct ctrlq_desc *desc)
{
	struct commu_endpoint *endpoint;
	struct eventfd_ctx *listener;
	int seq;
	u16 port;

	endpoint = (struct commu_endpoint*)desc->shadow_addr;
	listener = (struct eventfd_ctx *)desc->pci_addr;
	port = desc->vf_num;
	seq = desc->seq;

	if (!endpoint || !endpoint->channel) {
		COMMU_INFO("[ERR]user msg recv null endpoint or channel\n");
		return;
	}

	COMMU_DBG("seq:%d port:%x ep%px  type%d ep->listener %px ctx %px\n",
			seq, port, endpoint, endpoint->type,
			endpoint->listener, listener);

	if (endpoint->channel->kernel_channel)
		return;

	switch(endpoint->type) {
		case COMMU_ENDPOINT_USER_PORT:
			if (!endpoint->ports[port].listener) {
				COMMU_INFO("[ERR]port have no listener\n");
				return;
			}
			eventfd_signal(endpoint->ports[port].listener, 1);
			break;
		case COMMU_ENDPOINT_USER_RPC:
			if (!listener) {
				COMMU_INFO("[ERR]rpc have no listener\n");
				return;
			}
			eventfd_signal(listener, 1);
			break;
		default:
			if (endpoint->listener)
				eventfd_signal(endpoint->listener, 1);
	}

	return;
}

#ifdef COMMU_HOST_POLL
int commu_mailbox_poll_worker(void *data)
{
	for (;;) {
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}
		cn_commu_mailbox_handler((struct cn_core_set *)data);
		usleep_range(20, 50);
	}
	return 0;
}
#else
irqreturn_t commu_mailbox_interrupt_worker(int index, void *data)
{
	struct cn_core_set *core = (struct cn_core_set *)data;

	if (core->device_id == MLUID_270)
		reg_write32(core->bus_set, 0x1520a4, 0);
	else if (core->device_id == MLUID_290) {
		uint32_t reg_val = 0;
		reg_write32(core->bus_set, 0x14406c, 0);
		/*
		 * JIRA[CTR-3711]: Add an read register operation
		 * to flush data on the path of PCIE bus,
		 * for avoid clear interruption by mistake.
		 */
		reg_val = reg_read32(core->bus_set, 0x14406c);
	}
	else if (core->device_id == MLUID_220)
		reg_write32(core->bus_set, 0xb1a0a4, 0);
	else if (core->device_id == MLUID_CE3226) {
		/*0x380000 is pcie base address*/
		/*0xb000 is mailbox base address*/
		/*0x58 is arm to host high address*/
		reg_read32(core->bus_set, 0x380000 + 0xb000 + 0x58);
	} else if (core->device_id == MLUID_PIGEON) {
		/*0x180000 is pcie base address*/
		/*0xb000 is mailbox base address*/
		/*0x58 is arm to host high address, read high entry try to pop/clear */
		reg_read32(core->bus_set, 0x180000 + 0xb000 + 0x58);
	} else if (core->device_id == MLUID_370) {

		uint32_t reg_val = 0, max_level = 0, irq_mask;
		uint32_t msg = 0;
		//uint32_t level = 0;

		msg = reg_read32(core->bus_set, 0x60914);
		reg_val = reg_read32(core->bus_set, 0x2222c);
		irq_mask = reg_read32(core->bus_set, 0x2232c);
		reg_val &= (~irq_mask);

		#if defined(IPCM_COMMU_SHARED_IRQ) && !defined(IPCM_POLLING_MODE)
		if (!(reg_val & 0x1) || (msg != 0x1))
			return IRQ_NONE;
		#endif

		reg_val = reg_read32(core->bus_set, 0x60910);
		max_level = (reg_val & 0x700) >> 8;
		//for (level = 0; level < max_level; level++)
		reg_val = reg_read32(core->bus_set, 0x60918);
	} else if (core->device_id == MLUID_590 || core->device_id == MLUID_580) {
		uint32_t reg_val, level, max_level;

		reg_val = reg_read32(core->bus_set, 0x4248);
		if (!(reg_val & 0x1))
			return IRQ_NONE;
		reg_val = reg_read32(core->bus_set, 0x28910);
		max_level = (reg_val & 0x700) >> 8;
		for (level = 0; level < max_level; level++)
			reg_val = reg_read32(core->bus_set, 0x28918);
	}

	cn_commu_mailbox_handler(core);

	return IRQ_HANDLED;
}
#endif

#ifdef CONFIG_CNDRV_EDGE
void cn_commu_host_intr_handler(void)
{
	struct cn_core_set *cn_core;

	cn_core = cn_core_get_with_idx(0);
	cn_commu_mailbox_handler(cn_core);
}
EXPORT_SYMBOL(cn_commu_host_intr_handler);
#endif

void cn_commu_mailbox_handler(struct cn_core_set *core)
{
#define COMMU_INTR_MAX_LOOP_TIME 100
	struct commu_set *controller = core->commu_set;
	struct commu_endpoint *endpoint;
	struct ctrlq_desc desc;
	int one_more_time;
	int loop_time = 0;

	if (!controller || !controller->ctrlq_recv || !controller->ctrlq_recv_user) {
		pr_debug("%s suspicious irq received.\n", __func__);
		return;
	}

temp:
	one_more_time = 0;

	if (ctrlq_get(controller->ctrlq_recv, &desc)) {
		COMMU_DBG("%s recv message from arm %x\n", __func__, desc.command);
		if (likely(desc.command == COMMU_DCMD_DATA_SENT)) {
			endpoint = (struct commu_endpoint*)desc.shadow_addr;
			if (!IS_ERR_OR_NULL(endpoint)) {
				wake_up(&endpoint->waitqueue);

				if (endpoint->type == COMMU_ENDPOINT_USER_RPC ||
					endpoint->type == COMMU_ENDPOINT_USER_MSG ||
					endpoint->type == COMMU_ENDPOINT_USER_PORT) {
					commu_ctrlq_redirect_msg_to_user(&desc);
				}
			}
			if (loop_time++ < COMMU_INTR_MAX_LOOP_TIME)
				one_more_time = 1;
		} else switch(desc.command) {
			case COMMU_RET_SET_ARM2VF_ADDR:
			case COMMU_RET_CRE_UPPER:
			case COMMU_RET_CRE_BOTTOM:
			case COMMU_RET_CRE_UPPER_PLUS:
			case COMMU_RET_CME_UPPER:
			case COMMU_RET_CME_UPPER_PLUS:
			case COMMU_RET_CME_BOTTOM:
			case COMMU_RET_DE_UPPER:
			case COMMU_RET_DE_BOTTOM:
			case COMMU_RET_CPE_UPPER:
			case COMMU_RET_CPE_UPPER_PLUS:
			case COMMU_RET_CPE_BOTTOM:
			case COMMU_RET_CPP:
			case COMMU_RET_VF_EXIT:
			case COMMU_RET_NO_CHANNEL:
			case COMMU_RET_NO_SERVER:
			case COMMU_RET_CE_CANCEL:
			case COMMU_RET_FAILED:
			case COMMU_RET_ALLOC_EP_FAILED:
			case COMMU_RET_COMMU_COMMAND_FAILED:
			case COMMU_RET_RESET_SERVER:
			case COMMU_RET_QUERY_STATUS:
			case COMMU_RET_PCIE_SRAM_INIT:
			case COMMU_RET_CME_UPPER_SRAM:
				commu_ctrlq_sync(controller, &desc, 1, 0);
				if (loop_time++ < COMMU_INTR_MAX_LOOP_TIME)
					one_more_time = 1;
				break;
			case COMMU_RET_HOSTP_HUP:
			case COMMU_RET_HOSTR_HUP:
				commu_ctrlq_sync(controller, &desc, 0, 1);
				if (loop_time++ < COMMU_INTR_MAX_LOOP_TIME)
					one_more_time = 1;
				break;
			case COMMU_DCMD_DEV_HUP:
				endpoint = (struct commu_endpoint*)desc.shadow_addr;
				if (endpoint && endpoint->channel)
					cn_schedule_work(core, &endpoint->channel->hup_work);
				break;
			case COMMU_DCMD_QUEUE_SUSPEND:

				COMMU_DBG("migration command %llx %d\n", desc.name, core->idx);
				if (desc.name == COMMU_MIGRATION_SUSPEND_RX)
					controller->suspend_rx = 1;
				else if (desc.name == COMMU_MIGRATION_UPDATE_EP_PAIR) {
					COMMU_DBG("[migraion] update ep pair\n");
					endpoint = (struct commu_endpoint *)desc.shadow_addr;
					if (endpoint)
						endpoint->id = desc.pci_addr;
				} else {
					controller->migration_command = desc.name;
					cn_schedule_work(core, &controller->migration_work);
				}
				commu_ctrlq_all_dump(controller);
				if (loop_time++ < COMMU_INTR_MAX_LOOP_TIME)
					one_more_time = 1;
				break;
			case COMMU_DCMD_EP_REBUILD:
				endpoint = (struct commu_endpoint *)desc.shadow_addr;
				if (endpoint->channel->kernel_channel
					&& endpoint->tx.ops) {
					endpoint->tx.ops->restart(endpoint->tx.real_queue);
					COMMU_DBG("Device server ep rebuild\n");
				}
				break;
			default:
				COMMU_DBG("suspicious irq received. h%u t%u\n",
						controller->ctrlq_recv->head,
						controller->ctrlq_recv->tail);
				dump_mem("kernel endpoint", (char *)&desc, 32);
		}
	}

	if (ctrlq_get(controller->ctrlq_recv_user, &desc)) {
		COMMU_DBG("doorbell from arm user %d %d  ring %d %d\n",
				controller->ctrlq_recv_user->head,
				controller->ctrlq_recv_user->tail,
				controller->ctrlq_recv_user->ring->head,
				controller->ctrlq_recv_user->ring->tail);

		if (likely(desc.command == COMMU_DCMD_DATA_SENT)) {
			endpoint = (struct commu_endpoint*)desc.shadow_addr;

			if (!endpoint) {
				COMMU_INFO("[ERR]NULL endpoint from arm.\n");
				return;
			}

			/* keep for future user->kernel tunnel */
			wake_up(&endpoint->waitqueue);

			commu_ctrlq_redirect_msg_to_user(&desc);

			if (loop_time++ < COMMU_INTR_MAX_LOOP_TIME)
				one_more_time = 1;
		}
		//dump_mem("userspace endpoint", (char*)&desc, 32);
	}

	if (one_more_time)
		goto temp;

	return;

}

static int commu_fops_open(struct inode *inode, struct file *filp)
{
	struct commu_set *c;
	c = container_of(inode->i_cdev, struct commu_set, commu_dev);
	filp->private_data = c;
	return 0;
}

/*
 * Called in the release function of the commu character device.
 *
 * If called, that means a process is finised, we use another process which
 * the same channel is also opened as a proxy to check deadlock.
 *
 * We can't do this in kernel cause we haven't have an easy way to change a
 * parameter simultaneously in kernel and user space.
 *
 * At the beginning, a userspace thread is used each process, running every 2
 * seconds to check deadlock, this is expansive so the thread will be
 * replaced by the mechanism below:
 * 1) if there are processes which also opened the channel, kernel signal one
 * of then, then the process signified will do the deadlock check;
 * 2) if none, deadlock can be checked when a new process inited, this step
 * will run only once.
 */
static void commu_hup_deadlock_checker(struct commu_channel *channel)
{
	struct commu_set *controller = (struct commu_set *)channel->controller;
	struct commu_fd_listener *listener;
	struct commu_user_mmap *desc_to_user;
	struct hlist_node *tmp;
	int i;

	desc_to_user = (struct commu_user_mmap *)channel->desc_to_user;

	/* used in cdev release, can not use killable func */
	mutex_lock(&controller->mutex);
	hash_for_each_safe(channel->process_listeners, i, tmp,
			listener, fd_listener_node) {
		if (commu_spin_lock(&desc_to_user->sign))
			goto release;
		channel->current_desc_user = listener->fd;
		desc_to_user->desc.command = COMMU_CMD_HOSTP_HUP;
		eventfd_signal(listener->listener, 1);
		if (commu_spin_unlock(&desc_to_user->sign))
			__sync_fetch_and_and(&desc_to_user->sign, 0);
		/* notify one of these processes is enough */
		break;
	}
release:
	mutex_unlock(&controller->mutex);

	return;
}

static int commu_fops_release(struct inode *inode, struct file *fp)
{
	struct commu_set *controller = (struct commu_set *)fp->private_data;
	struct commu_channel *channel;
	struct hlist_node *tmp;
	struct commu_fd_listener *listener;
	int i, j, port_num = 0;
	struct commu_endpoint *ep;
	struct commu_port_proxy *proxy;
	struct ctrlq_desc desc;
	int rpc_isfull = 0;
	int port_isfull = 0;

	if (unlikely(controller->reset_sign)) {
		COMMU_INFO("arm may hang, quit here.\n");
		return 0;
	}

	hash_for_each(controller->commu_channel_head, i, channel, channel_node) {
		if (channel->kernel_channel)
			continue;

		COMMU_DBG("commu userspace channel %s release triggered.\n",
				channel->name);
		port_num = 0;

		/* if current process hold the multi-process share sign, release it. */
		if (channel->current_desc_user == fp)
			((struct commu_user_mmap *)channel->desc_to_user)->sign = 0;

		mutex_lock(&controller->mutex);
		/* free listeners belong to the fp in each channel */
		hash_for_each_possible_safe(channel->process_listeners,
				listener, tmp, fd_listener_node, (u64)fp) {
			if (listener->fd == fp) {
				hash_del(&listener->fd_listener_node);
				cn_kfree(listener);
			}
		}
		mutex_unlock(&controller->mutex);

		/* release rpc related resources */
		if ((ep = search_endpoint_by_type(channel, COMMU_ENDPOINT_USER_RPC)) != NULL) {
			if ((listener = search_listener_in_ep_by_fp(ep, fp)) != NULL) {
				struct eventfd_ctx *ctx = listener->listener;

				/* set HUP flag for related desc in tx queue */
				ep->tx.ops->set_rpc_sigint(ep->tx.real_queue, ctx, "TX");
				COMMU_DBG("set rpc tx HUP flag finished.\n");
				ep->rx.ops->set_rpc_sigint(ep->rx.real_queue, ctx, "RX");

				/*TODO if no desc belong to eventfd, no need to command */

				mutex_lock(&controller->mutex);
				/* send HUP via ctrlq (use ctx as cancel token) */
				commu_send_command_and_wait(controller, &desc, NULL,
						COMMU_CMD_HOSTR_HUP, ep->id,
						desc.pci_addr, (u64)ctx);
				mutex_unlock(&controller->mutex);

				ep->rx.ops->set_rpc_sigint(ep->rx.real_queue, ctx, "RX");
			}
		}

		/*
		 * SIGINT handle for port proxy:
		 * 1) set tx/rx SIGINT flag
		 * 2) send sigint notify command
		 * 3) device set proxy SIGINT flag
		 * 4) wait response
		 * 5) set rx SIGINT again in case some packets recv by dev before 1)
		 * and send by dev before 3)
		 */
		if (channel->real_ep) {
			ep = channel->real_ep;
			for (j = 0; j < COMMU_ENDPOINT_MAX_PORT; j++) {
				proxy = &ep->ports[j];
				if (proxy->fp != fp)
					continue;
				COMMU_DBG("release port %d\n", j);

				/* set HUP flag for related desc in tx queue */
				ep->tx.ops->set_flag_sigint(ep->tx.real_queue, j, "TX");
				COMMU_DBG("set tx port HUP flag finished.\n");
				ep->rx.ops->set_flag_sigint(ep->rx.real_queue, j, "RX");

				port_num++;
			}


			if (port_num) {
				mutex_lock(&controller->mutex);
				/* send HUP via ctrlq */
				commu_send_command_and_wait(controller, &desc, NULL,
					COMMU_CMD_HOSTP_HUP, channel->real_ep->id,
					(u64)fp, 0);
				mutex_unlock(&controller->mutex);
				port_isfull = ep->rx.ops->is_full(ep->rx.real_queue);
			}


			for (j = 0; j < COMMU_ENDPOINT_MAX_PORT; j++) {
				proxy = &ep->ports[j];
				if (proxy->fp != fp)
					continue;

				/* set HUP flag for related desc in rx queue */
				COMMU_DBG("set port rx HUP flag ag.\n");
				ep->rx.ops->set_flag_sigint(ep->rx.real_queue, j, "RX");

				/* unset in_using for port proxy belong to the fp */
				//memset(proxy, 0x0, sizeof(*proxy));
				proxy->in_using = 0;
				proxy->port = j;
			}

			if (channel->real_ep) {
				ep = channel->real_ep;
				if (ep->lock_owner == (u64)fp) {
					ep->lock_owner = 0;
					up(&ep->ep_user_sema);
				}
			}
		}

		if ((ep = search_endpoint_by_type(channel, COMMU_ENDPOINT_USER_RPC)) != NULL) {
			if ((listener = search_listener_in_ep_by_fp(ep, fp)) != NULL) {
				struct eventfd_ctx *ctx = listener->listener;
				ep->rx.ops->set_rpc_sigint(ep->rx.real_queue, ctx, "RX");
				hash_del(&listener->fd_listener_node);
				cn_kfree(listener);
				port_num++;
				rpc_isfull = ep->rx.ops->is_full(ep->rx.real_queue);
			}

			if (ep->lock_owner == (u64)fp) {
				ep->lock_owner = 0;
				up(&ep->ep_user_sema);
			}
		}

		if (port_isfull || rpc_isfull) {
			commu_hup_deadlock_checker(channel);
		}
	}

	return 0;
}

static int commu_fops_mmap(struct file *fp, struct vm_area_struct *vma)
{
	int result = 0;
	unsigned long phys_addr = vma->vm_pgoff << PAGE_SHIFT;
	struct commu_set *ctrl = (struct commu_set *)fp->private_data;
	struct cn_core_set *core = (struct cn_core_set *)ctrl->core_set;
	struct cn_bus_set *bus = core->bus_set;
	u32 ob_size;
	struct page *ob_pages;

	if (ctrl->en_outbound) {
		unsigned char type = vma->vm_pgoff;
		unsigned long va = (unsigned long)vma->vm_start;

		ob_size = cn_bus_get_outbound_size(bus);
		/*FIXME replace this mmap type with IOCTL */
		if ((type == 1) && (vma->vm_end - vma->vm_start) == ob_size) {
			int i;
			int page_index = 0;

			COMMU_DBG("[ATTENTION] mmap type:%d. Only when mmap outbound type=1.\n", (int)type);
			vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

			for (i = 0; i < ob_size / PAGE_SIZE; i++) {
				ob_pages = cn_bus_get_outbound_pages(bus, page_index);
				remap_pfn_range(vma, va, page_to_pfn(ob_pages),
						PAGE_SIZE, PAGE_SHARED);
				page_index++;
				va += PAGE_SIZE;
			}

			return 0;
		} else if (type == 1) {
			COMMU_INFO("pid:%d, name:%s vm_pgoff:%lx vm_start - vm_end: 0x%lx - 0x%lx\n",
					current->pid, current->comm, vma->vm_pgoff, vma->vm_start, vma->vm_end);
		}
	}

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_flags |= VM_IO;

#if defined(__aarch64__)
	/* FT1500A not support io memory remap in cache mode */
	if (phys_addr >= cn_bus_get_mem_phyaddr(bus, 0) &&
		phys_addr < (cn_bus_get_mem_phyaddr(bus, 0) + cn_bus_get_mem_size(bus, 0)))
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#endif
	result = remap_pfn_range(vma, vma->vm_start, phys_addr>>PAGE_SHIFT,
				vma->vm_end-vma->vm_start, vma->vm_page_prot);
	if (result) {
		result = -EAGAIN;
	}

	return result;
}

#define  REGISTER_A_CHANNEL _IOWR('Y', 1, int)
#define  OPEN_AN_ENDPOINT _IOWR('Y', 2, int)
#define  OPEN_A_CHANNEL _IOWR('Y', 3, int)
#define  CONNECT_RPC_ENDPOINT _IOWR('Y', 4, int)
#define  GET_SHARE_MEM_BASE _IOWR('Y', 5, int)
#define  CONNECT_MSG_ENDPOINT _IOWR('Y', 6, int)
#define  CONNECT_PORT_ENDPOINT _IOWR('Y', 7, int)
#define  OPEN_PORT_ENDPOINT _IOWR('Y', 8, int)
#define  DISCONNECT_PORT_ENDPOINT _IOWR('Y', 9, int)
#define  DISCONNECT_RPC_ENDPOINT _IOWR('Y', 10, int)
#define  REBUILD_ALL_ENDPOINTS _IOWR('Y', 11, int)
#define  GET_DRIVER_VERSION _IOWR('Y', 12, int)
#define  GET_USER_LOCK _IOWR('Y', 16, int)
#define  RELEASE_USER_LOCK _IOWR('Y', 17, int)
#define  RESET_CHANNEL_OWNER _IOWR('Y', 18, int)
#define  GET_CONFIG_FLAG _IOWR('Y', 19, int)
#define  CONNECT_RPC_ENDPOINT_QUEUE_NUM_SIZE _IOWR('Y', 20, int)
#define  CONNECT_MSG_ENDPOINT_QUEUE_NUM_SIZE _IOWR('Y', 21, int)
#define  CONNECT_PORT_ENDPOINT_QUEUE_NUM_SIZE _IOWR('Y', 22, int)

enum commu_config_flag {
	COMMU_CONFIG_ENABLE_OUTBOUND = 0x1,
	COMMU_CONFIG_MMAP_KERNEL_RXTX = 0x2,
	COMMU_CONFIG_SHADOW_HEAD_TAIL = 0x4,
};

struct commu_args {
	char name[COMMU_CHANNEL_NAME_MAX_LEN];
	int channel_eventfd;
	uint64_t ctrlq_tx_base;
	uint64_t desc_to_user_base;
	void *ctrlq_tx;
	void *desc_to_user;
	int ep_eventfd;
	int commu_fd;
	void *ep;
	int ep_epollfd;
	void *ep_user;

	uint64_t in_base;
	uint64_t out_base;

	uint16_t port;
};

static
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36))
int
#else
long
#endif
commu_fops_ioctl(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36))
		struct inode *inode,
#endif
		struct file *fp,
		unsigned int cmd,
		unsigned long arg)
{
	int ret = 0;
	struct commu_set *c = fp->private_data;

	switch (cmd) {
	case GET_DRIVER_VERSION: {
		struct commu_args args;
		args.in_base = DRV_MAJOR;
		args.out_base = DRV_MINOR;
		COMMU_DBG("major %llx  minor %llx\n", args.in_base, args.out_base);
		ret = copy_to_user((void *)arg, (void *)&args, sizeof(struct commu_args));
		break;
	}
	case GET_SHARE_MEM_BASE: {
		struct commu_args args;
		struct cn_core_set *core = (struct cn_core_set *)c->core_set;
		struct cn_bus_set *bus = core->bus_set;
		args.in_base = (u64)cn_bus_get_mem_phyaddr(bus, 0);
		/*TODO
		 * if add new member in_size out_size in commu_args,
		 * how to keep compatibility to commu_lib.
		 *
		 * 1) ioctl has argv[] para
		 * 2) old struct some member has a flag to indicate new/old struct,
		 * new struct args add version
		 */
		args.ctrlq_tx_base = (u64)cn_bus_get_mem_size(bus, 0);
		args.desc_to_user_base = (u64)cn_bus_get_mem_size(bus, 1);
		COMMU_DBG("in_base %llx in_size %llx out_size %llx\n",
				args.in_base, args.ctrlq_tx_base, args.desc_to_user_base);
		ret = copy_to_user((void *)arg, (void *)&args, sizeof(struct commu_args));
		break;
	}
	case OPEN_A_CHANNEL: {
		struct commu_channel *channel;
		struct commu_user_mmap *desc_to_user;
		struct commu_args args;
		struct commu_fd_listener *listener;

		ret = copy_from_user((void *)&args, (void *)arg,
				sizeof(struct commu_args));

		if (ret) {
			COMMU_DBG("Copy parameters from user failed. ret %d\n", ret);
			break;
		}

		if (mutex_lock_killable(&c->user_mutex))
			return -EINTR;
		if (mutex_lock_killable(&c->mutex)) {
			mutex_unlock(&c->user_mutex);
			return -EINTR;
		}

		if ((channel = search_channel_by_name(c, args.name)) == NULL) {
			channel = open_a_channel(args.name, c, args.channel_eventfd);
			desc_to_user = page_address(alloc_page(GFP_KERNEL));//must 4k align for mmap
			memset(desc_to_user, 0x0, PAGE_SIZE);
			desc_to_user->sign = 0;
			channel->desc_to_user = desc_to_user;
		}

		if ((listener = search_listener_by_fp(channel, fp)) == NULL) {
			listener = cn_kzalloc(sizeof(*listener), GFP_KERNEL);
			listener->fd = fp;
			listener->listener = eventfd_ctx_fdget(args.channel_eventfd);
			hash_add(channel->process_listeners,
					&listener->fd_listener_node, (u64)listener->fd);
			COMMU_DBG("[commu] new process detected %px, new eventfd inited %px\n",
					fp, listener->listener);
		} else {
			listener->listener = eventfd_ctx_fdget(args.channel_eventfd);
		}

		mutex_unlock(&c->mutex);
		mutex_unlock(&c->user_mutex);
		channel->listener = eventfd_ctx_fdget(args.channel_eventfd);
		args.desc_to_user_base = (u64)__pa(channel->desc_to_user);
		COMMU_DBG("desc_to_user %llx\n", args.desc_to_user_base);
		ret = copy_to_user((void *)arg, (void *)&args, sizeof(struct commu_args));
		break;
	}
	case CONNECT_RPC_ENDPOINT:
	case CONNECT_RPC_ENDPOINT_QUEUE_NUM_SIZE: {
		struct commu_args args;
		struct commu_channel *channel;
		struct commu_endpoint *ep;
		uint64_t queue_num = 0;
		uint64_t data_size = 0;
		int32_t en_cross = 0;

		ret = copy_from_user((void *)&args, (void *)arg,
				sizeof(struct commu_args));

		if (ret) {
			COMMU_DBG("Copy parameters from user failed. ret %d\n", ret);
			break;
		}

		if ((channel = search_channel_by_name(c, args.name)) == NULL)
			return -1;

		if (cmd == CONNECT_RPC_ENDPOINT_QUEUE_NUM_SIZE) {
			queue_num = args.in_base;
			data_size = args.out_base;
			en_cross = args.ep_epollfd;
		} else {
			queue_num = COMMU_QUEUE_NUM;
			data_size = COMMU_USER_QUEUE_DATA_BUF_SIZE;
			en_cross = 0;
		}

		if (mutex_lock_killable(&c->user_mutex))
			return -EINTR;
		if (mutex_lock_killable(&c->mutex)) {
			mutex_unlock(&c->user_mutex);
			return -EINTR;
		}

		ep = connect_rpc_user_endpoint(channel, args.ep_eventfd,
						args.ep_user, queue_num,
						data_size, fp, en_cross);
		if (ep)
			args.ep = ep->listener;

		mutex_unlock(&c->mutex);
		mutex_unlock(&c->user_mutex);

		if (!ep)
			return -1;

		ret = copy_to_user((void *)arg, (void *)&args, sizeof(struct commu_args));

		break;
	}
	case CONNECT_MSG_ENDPOINT:
	case CONNECT_MSG_ENDPOINT_QUEUE_NUM_SIZE: {
		struct commu_args args;
		struct commu_channel *channel;
		uint64_t queue_num = 0;
		uint64_t data_size = 0;
		int32_t en_cross = 0;

		ret = copy_from_user((void *)&args, (void *)arg,
				sizeof(struct commu_args));

		if (ret) {
			COMMU_DBG("Copy parameters from user failed. ret %d\n", ret);
			break;
		}

		if ((channel = search_channel_by_name(c, args.name)) == NULL)
			return -1;

		if (cmd == CONNECT_MSG_ENDPOINT_QUEUE_NUM_SIZE) {
			queue_num = args.in_base;
			data_size = args.out_base;
			en_cross = args.ep_epollfd;
		} else {
			queue_num = COMMU_QUEUE_NUM;
			data_size = COMMU_USER_QUEUE_DATA_BUF_SIZE;
			en_cross = 0;
		}

		connect_msg_user_endpoint(channel, args.ep_eventfd, args.ep_user,
					queue_num, data_size, en_cross);

		break;
	}
	case CONNECT_PORT_ENDPOINT:
	case CONNECT_PORT_ENDPOINT_QUEUE_NUM_SIZE: {
		struct commu_args args;
		struct commu_channel *channel;
		uint64_t queue_num = 0;
		uint64_t data_size = 0;
		int32_t en_cross = 0;

		ret = copy_from_user((void *)&args, (void *)arg,
				sizeof(struct commu_args));

		if (ret) {
			pr_err("Copy parameters from user failed. ret %d\n", ret);
			break;
		}

		if ((channel = search_channel_by_name(c, args.name)) == NULL)
			return -1;

		if (cmd == CONNECT_PORT_ENDPOINT_QUEUE_NUM_SIZE) {
			queue_num = args.in_base;
			data_size = args.out_base;
			en_cross = args.ep_epollfd;
		} else {
			queue_num = COMMU_QUEUE_NUM;
			data_size = COMMU_USER_QUEUE_DATA_BUF_SIZE;
			en_cross = 0;
		}

		if (mutex_lock_killable(&c->user_mutex))
			return -EINTR;
		if (mutex_lock_killable(&c->mutex)) {
			mutex_unlock(&c->user_mutex);
			return -EINTR;
		}

		ret = connect_port_user_proxy(channel, args.port,
				args.ep_eventfd, args.ep_user,
				args.channel_eventfd, queue_num,
				data_size, fp, en_cross);

		mutex_unlock(&c->mutex);
		mutex_unlock(&c->user_mutex);

		break;
	}
	case DISCONNECT_PORT_ENDPOINT: {
		struct commu_args args;
		struct commu_endpoint *ep;

		ret = copy_from_user((void *)&args, (void *)arg,
				sizeof(struct commu_args));

		if (ret) {
			pr_err("Copy parameters from user failed. ret %d\n", ret);
			break;
		}

		ep = (struct commu_endpoint*)args.ep;

		/*TODO replace the controller lock with a channel lock */
		if (mutex_lock_killable(&c->user_mutex))
			return -EINTR;
		if (mutex_lock_killable(&c->mutex)) {
			mutex_unlock(&c->user_mutex);
			return -EINTR;
		}

		ret = disconnect_port_user_endpoint(ep, args.port, args.ep_user);
		mutex_unlock(&c->mutex);
		mutex_unlock(&c->user_mutex);

		break;
	}
	case DISCONNECT_RPC_ENDPOINT: {
		struct commu_args args;
		struct commu_endpoint *ep;

		ret = copy_from_user((void *)&args, (void *)arg,
				sizeof(struct commu_args));

		if (ret) {
			pr_err("Copy parameters from user failed. ret %d\n", ret);
			break;
		}

		ep = (struct commu_endpoint*)args.ep;

		/*TODO replace the controller lock with a channel lock */
		if (mutex_lock_killable(&c->user_mutex))
			return -EINTR;
		if (mutex_lock_killable(&c->mutex)) {
			mutex_unlock(&c->user_mutex);
			return -EINTR;
		}

		ret = disconnect_rpc_user_endpoint(ep, fp);
		mutex_unlock(&c->mutex);
		mutex_unlock(&c->user_mutex);

		break;
	}
	case GET_USER_LOCK: {
		struct commu_args args;
		struct commu_endpoint *ep;

		ret = copy_from_user((void *)&args, (void *)arg,
				sizeof(struct commu_args));

		if (ret) {
			pr_err("Copy parameters from user failed. ret %d\n", ret);
			break;
		}

		ep = (struct commu_endpoint *)args.ep;
		if (down_killable(&ep->ep_user_sema))
			return -EINTR;
		ep->lock_owner = (u64)fp;

		break;
	}
	case RELEASE_USER_LOCK: {
		struct commu_args args;
		struct commu_endpoint *ep;

		ret = copy_from_user((void *)&args, (void *)arg,
				sizeof(struct commu_args));

		if (ret) {
			pr_err("Copy parameters from user failed. ret %d\n", ret);
			break;
		}

		ep = (struct commu_endpoint *)args.ep;
		if (ep->lock_owner == (u64)fp) {
			ep->lock_owner = 0;
			up(&ep->ep_user_sema);
		} else {
			pr_err("repeated up user locker\n");
		}

		break;
	}
	case RESET_CHANNEL_OWNER: {
		struct commu_args args;
		struct commu_channel *channel;
		struct ctrlq_desc desc, seq;

		ret = copy_from_user((void *)&args, (void *)arg,
				sizeof(struct commu_args));

		if (ret) {
			pr_err("Copy parameters from user failed. ret %d\n", ret);
			break;
		}
		channel = search_channel_by_name(c, args.name);
		if (channel == NULL)
			return -1;

		if (mutex_lock_killable(&c->user_mutex))
			return -EINTR;
		if (mutex_lock_killable(&c->mutex)) {
			mutex_unlock(&c->user_mutex);
			return -EINTR;
		}

		if (args.in_base == 0x1) {
			ret = commu_send_command_and_wait(c, &desc, NULL,
				COMMU_CMD_RESET_SERVER, channel->hash_name,
				0, 0);
		} else if (args.in_base == 0x2) {
			ret = commu_send_command_and_wait(c, &desc, &seq,
				COMMU_CMD_QUERY_STATUS, channel->hash_name,
				0, 0);
			memset(&args, 0x0, sizeof(args));
			args.out_base = seq.pci_addr;
			ret = copy_to_user((void *)arg, (void *)&args, sizeof(struct commu_args));
		}
		mutex_unlock(&c->mutex);
		mutex_unlock(&c->user_mutex);

		break;
	}
	case GET_CONFIG_FLAG: {
		struct commu_args args;
		memset(&args, 0x0, sizeof(struct commu_args));
		if (c->en_outbound)
			args.commu_fd |= COMMU_CONFIG_ENABLE_OUTBOUND;
		args.commu_fd |= COMMU_CONFIG_MMAP_KERNEL_RXTX;
		#ifdef COMMU_SHADOW_HEAD_TAIL
		args.commu_fd |= COMMU_CONFIG_SHADOW_HEAD_TAIL;
		#endif
		ret = copy_to_user((void *)arg, (void *)&args, sizeof(struct commu_args));
		break;
	}
	default:
		ret = -1;
		COMMU_DBG("undefined IOCTL!\n");
	}
	return ret;
}

const struct file_operations commu_fops = {
	.owner   =  THIS_MODULE,
	.open    =  commu_fops_open,
	.mmap    =  commu_fops_mmap,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36))
	.ioctl   =  commu_fops_ioctl,
#else
	.unlocked_ioctl = commu_fops_ioctl,
#endif
	.read    = NULL,
	.write   =  NULL,
	.release =  commu_fops_release,
};

static DEFINE_MUTEX(commu_card_mutex);
static struct class *commu_class;
static int commu_cdev_count;
static char *commu_set_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode |= 0666;

	return NULL;
}

int c20l_vf_commu_cdev_init(struct commu_set *controller)
{
	int err = 0;
	char name[20];
	struct device *dev;
	struct cn_core_set *core = (struct cn_core_set *)controller->core_set;

	err = alloc_chrdev_region(&controller->dev_no, 0, 1, "commu");
	cdev_init(&controller->commu_dev, &commu_fops);
	controller->commu_dev.owner = THIS_MODULE;
	err = cdev_add(&controller->commu_dev, controller->dev_no, 1);
	if (err)
		COMMU_DBG(KERN_NOTICE "cdev add failed\n");

	mutex_lock(&commu_card_mutex);
	if (!commu_class) {
		commu_class = class_create(THIS_MODULE, "commu");
		commu_class->devnode = commu_set_devnode;
	}
	commu_cdev_count++;
	mutex_unlock(&commu_card_mutex);

	if (cn_host_vf_enable() && cn_core_is_vf(core))
		sprintf(name, "commu%dvf%d", core->pf_idx, core->vf_idx);
	else
		sprintf(name, "commu%d", core->idx);
	dev = device_create(commu_class, NULL, controller->dev_no, NULL, name);
	if (IS_ERR(dev)) {
		COMMU_INFO("device %s create failed\n", name);
	}
	return err;
}

static int c20l_vf_commu_cdev_exit(struct commu_set *controller)
{
	device_destroy(commu_class, controller->dev_no);

	mutex_lock(&commu_card_mutex);
	if (--commu_cdev_count == 0) {
		class_destroy(commu_class);
		commu_class = NULL;
	}
	mutex_unlock(&commu_card_mutex);

	cdev_del(&controller->commu_dev);
	unregister_chrdev_region(controller->dev_no, 1);

	return 0;
}
