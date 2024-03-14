#include "cndrv_debug.h"
/*dma command descriptor size*/
#define DESC_SIZE			(32)

#define DMA_CHANNEL_REG_SIZE	(0x40)

/*PCIe DMA Channel n source parameter Register*/
#define DSRC_PARAM(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x000)

/*PCIe DMA Channel n Dest Parameter Register*/
#define DDEST_PARAM(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x004)

/*PCIe DMA Channel n SrcAddr Lower Register*/
#define DSRCL(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x008)

/*PCIe DMA Channel n SrcAddr Upper Register*/
#define DSRCU(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x00c)

/*PCIe DMA Channel n DestAddr Lower Register*/
#define DDESTL(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x010)

/*PCIe DMA Channel n DestAddr Upper Register*/
#define DDESTU(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x014)

/*PCIe DMA Channel n Data Length Register(up to 4GB)*/
#define DLEN(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x018)

/*PCIe DMA Channel n Control Register(up to 4GB)*/
#define DCTRL(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x01c)

/*PCIe DMA Channel n Status Register(up to 4GB)*/
#define DSTATUS(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x020)

/*PCIe DMA Channel n Data PRC Length Register(more than 4GB)*/
#define DPRC_LEN(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x024)

/*PCIe DMA Channel n Data Length Register(up to 4GB)*/
#define DSHARE_ACCESS(channel_id)    \
	(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x028)

#define DID	(DBO + 0x0a8)/*PCIe DMA Interrupt Disable Register*/
#define DIBUcEE	(DBO + 0x0ac)/*PCIe DMA Inbound Buffer Uncorrected ECC Errors*/
#define DIBcEE	(DBO + 0x0b0)/*PCIe DMA Inbound Buffer corrected ECC Errors*/
#define DOBUcEE	(DBO + 0x0b4)/*PCIe DMA Outbound Buffer Uncorrected ECC Errors*/
#define DOBcEE	(DBO + 0x0b8)/*PCIe DMA Outbound Buffer corrected ECC Errors*/
#define DCV	(DBO + 0x0f8)/*PCIe DMA Capability and Version Register*/
#define DCFG	(DBO + 0x0fc)/*PCIe DMA Configuration Register*/
#define DEO	(0UL)	/*dma command descriptor offset*/

/*PCIE DMA Descriptor status*/
#define DE_STATUS                 (DEO+0)
/*PCIE DMA Descriptor control*/
#define DE_CTRL	                (DEO+4)
/*Next Descriptor Lower address*/
#define DE_NDL       (DEO + 0x8)
/*Next Descriptor Upper address*/
#define DE_NDU       (DEO + 0xc)
/*Src Address Lower  in descriptor*/
#define DE_SRC_LOWER (DEO + 0x10)
/*Src Address Upper  in descriptor*/
#define DE_SRC_UPPER (DEO + 0x14)
/*Dest Address Lower  in descriptor*/
#define DE_DEST_LOWER (DEO + 0x18)
/*Dest Address Upper  in descriptor*/
#define DE_DEST_UPPER (DEO + 0x1c)

#define DMA_PCIE_PARAM	(0x0)
#define DMA_AXI_PARAM	(0x4)
#define SG_ID_PCIE	(0x0)
#define SG_ID_AXI	(0x4)
#define DSE_COND	(0xa)
#define DIRQ		(0x3)
#define DIRQ_ID		(0x1)

/*FIXME replace this MACRO */
#define DIMASK_LOCAL	(DI_BASE + 0x0)/*PCIe DMA Interrupt Enable Register*/
#define DISTATUS_LOCAL	(DI_BASE + 0x4)/*PCIe DMA Interrupt Register*/
#define DIMSI_ADDR	(DI_BASE + 0X10)
#define DIMSI_STATUS	(DI_BASE + 0X14)
#define ISTATUS_DMA	(DI_BASE + 0x30)
#define MSI_MASK	(0x10)/* fix mlutithread bug*/
#define LENGTH_CTRL(len) \
	((len == 0x1000000) ? 0 : (unsigned int)(len & 0xFFFFFF))

#define NEXT_DESC_LOWER32(addr, current_index) \
	((unsigned int)((unsigned long)(addr + \
				(current_index + 1) * DESC_SIZE) & 0xFFFFFFFFU))
#define NEXT_DESC_UPPER32(addr, current_index) \
	((unsigned int)(((unsigned long)(addr + \
			(current_index + 1) * DESC_SIZE) >> 32) & 0xFFFFFFFFU))

#define FILL_DESC(addr, ctrl, ndl, ndu, src_addr, dest_addr, desc_offset) \
{ \
	*((u32 *)(addr + desc_offset + DE_CTRL)) = ctrl; \
	*((u32 *)(addr + desc_offset + DE_NDL)) = ndl; \
	*((u32 *)(addr + desc_offset + DE_NDU)) = ndu; \
	*((u32 *)(addr + desc_offset + DE_SRC_LOWER)) = src_addr; \
	*((u32 *)(addr + desc_offset + DE_SRC_UPPER)) = \
			(unsigned int)(src_addr >> 32); \
	*((u32 *)(addr + desc_offset + DE_DEST_LOWER)) = dest_addr; \
	*((u32 *)(addr + desc_offset + DE_DEST_UPPER)) = \
			(unsigned int)(dest_addr >> 32); \
}

struct outbound_mem {
	void *virt_addr;
	dma_addr_t pci_addr;
};

static void pcie_show_desc_list(struct dma_channel_info *channel);
static void pcie_dump_reg(struct cn_pcie_set *pcie_set);
static int pcie_dma_interrupt_init(struct cn_pcie_set *pcie_set);
static int pcie_pre_init_hw(struct cn_pcie_set *pcie_set);
#ifdef USE_DATA_OUTBOUND
static void pcie_priv_set_free(struct cn_pcie_set *pcie_set);
#endif
static int pci_hw_msi_enable(struct cn_pcie_set *pcie_set);
static int pci_hw_msix_enable(struct cn_pcie_set *pcie_set);
static int pci_hw_intx_enable(struct cn_pcie_set *pcie_set);
static int pci_hw_msi_disable(struct cn_pcie_set *pcie_set);
static int pci_hw_msix_disable(struct cn_pcie_set *pcie_set);
static int pci_hw_intx_disable(struct cn_pcie_set *pcie_set);

static int (*isr_hw_enable[3]) (struct cn_pcie_set *) = {
	pci_hw_msi_enable,
	pci_hw_msix_enable,
	pci_hw_intx_enable
};

static int (*isr_hw_disable[3])(struct cn_pcie_set *) = {
	pci_hw_msi_disable,
	pci_hw_msix_disable,
	pci_hw_intx_disable
};

#ifdef NEED_SUB_IRQ_MASK
struct pcie_sub_system_irq_mask_s {
	unsigned long reg;
	unsigned long unmask_val;
	unsigned long mask_val;
} pcie_sub_system_irq_mask[] = {
	{GBO + SUB_GBO_ASSIST + 0x100, 0x00, 0x03}, /*DMA0 finished and error 324*/
	{GBO + SUB_GBO_ASSIST + 0x104, 0x00, 0x03}, /*DMA1 finished and error 325*/
	{GBO + SUB_GBO_ASSIST + 0x108, 0x00, 0x01}, /*Mail box 0 to arm*/
	{GBO + SUB_GBO_ASSIST + 0x10C, 0x00, 0x01}, /*Mail box 1 to arm*/
	{GBO + SUB_GBO_ASSIST + 0x110, 0x00, 0x01}, /*Mail box 2 to host*/
	{GBO + SUB_GBO_ASSIST + 0x114, 0x00, 0x01}, /*Mail box 3 to host*/
	{GBO + SUB_GBO_ASSIST + 0x118, 0x00, 0x03}, /*Outbound rresp and bresp error*/
	{GBO + SUB_GBO_ASSIST + 0x11C, 0x00, 0x03}, /*Inbound rresp and bresp error*/
	{GBO + SUB_GBO_ASSIST + 0x120, 0x00, 0x01}, /*PCIe D State change*/
	{GBO + SUB_GBO_ASSIST + 0x124, 0x00, 0x01}, /*PCIe FLR (function level reset)*/
	{GBO + SUB_GBO_ASSIST + 0x128, 0x00, 0x01}, /*SMMU*/
	{GBO + SUB_GBO_ASSIST + 0x12C, 0x00, 0x01}, /*Ltssm linkdown*/
	{GBO + SUB_GBO_ASSIST + 0x130, 0x00, 0x01}, /*GIC resp error*/
	{GBO + SUB_GBO_ASSIST + 0x134, 0x00, 0x07}, /*GIC RAM error of MSIX  and APB And PCIe DPC*/
	{GBO + SUB_GBO_ASSIST + 0x138, 0x00, 0x01}, /*GIC RAM error of APB*/
	{GBO + SUB_GBO_ASSIST + 0x13C, 0x00, 0x01}, /*INTA*/
	{GBO + SUB_GBO_ASSIST + 0x140, 0x00, 0x01}, /*INTB*/
	{GBO + SUB_GBO_ASSIST + 0x144, 0x00, 0x01}, /*INTC*/
	{GBO + SUB_GBO_ASSIST + 0x148, 0x00, 0x01}, /*INTD*/
	{GBO + SUB_GBO_ASSIST + 0x14C, 0x00, 0x01}, /*PME*/
	{GBO + SUB_GBO_ASSIST + 0x150, 0x00, 0x01}, /*Link EQ request*/
	{GBO + SUB_GBO_ASSIST + 0x154, 0x00, 0x01}, /*Hot plug*/
	{GBO + SUB_GBO_ASSIST + 0x158, 0x00, 0x01}, /*AER*/
	{GBO + SUB_GBO_ASSIST + 0x15C, 0x00, 0x01}, /*Ltssm recovery*/
};
#endif

__attribute__((unused)) static int pcie_polling_dma_status(struct cn_pcie_set *pcie_set,
			struct dma_channel_info *channel)
{
	unsigned int interrupt_status;
	unsigned int err_mask = DMA_REG_CHANNEL_MASK << DMA_REG_CHANNEL_NUM;

	interrupt_status = cn_pci_reg_read32(pcie_set, DISTATUS_LOCAL);
	interrupt_status &= (1 << pcie_set->spkg_channel_id) |
		((1 << pcie_set->spkg_channel_id) << DMA_REG_CHANNEL_NUM);
	cn_pci_reg_write32(pcie_set, DISTATUS_LOCAL, interrupt_status);
	cn_pci_reg_read32(pcie_set, DISTATUS_LOCAL);

	if (!interrupt_status)
		return -EAGAIN;

	if (interrupt_status & err_mask) {
		cn_dev_pcie_err(pcie_set,
				"DMA interrupt error interrupt_status:%#x",
				interrupt_status);
		if (pcie_set->ops->dump_reg)
			pcie_set->ops->dump_reg(pcie_set);
		pcie_show_desc_list(channel);
		cn_pci_dma_spkg_complete(channel, CHANNEL_COMPLETED_ERR, pcie_set);
	} else {
		cn_pci_dma_spkg_complete(channel, CHANNEL_COMPLETED, pcie_set);
	}

	return 0;
}

static irqreturn_t msix_interrupt_handle(int phy_channel, struct cn_pcie_set *pcie_set)
{
	unsigned int interrupt_status;
	unsigned int err_mask, mask;
	struct dma_channel_info *channel;

	mask = (0x1 << phy_channel) | (0x1 << (phy_channel + DMA_REG_CHANNEL_NUM));
	err_mask = 0x1 << (phy_channel + DMA_REG_CHANNEL_NUM);

	/*
	 * read dma interrupt register to get which channel generate interrupt
	 * This interrupt may be done or error.not is done and error.
	 */
	interrupt_status = cn_pci_reg_read32(pcie_set, DISTATUS_LOCAL);
	interrupt_status &= mask;
	if (!interrupt_status)
		return IRQ_HANDLED;

	cn_pci_reg_write32(pcie_set, DISTATUS_LOCAL, interrupt_status);
	cn_pci_reg_read32(pcie_set, DISTATUS_LOCAL);

	/* fix change mlu from pf to vf, dma can not used error*/
	cn_pci_reg_write32(pcie_set, DSHARE_ACCESS(phy_channel), 0);
	if (!pcie_set->running_channels) {
		cn_dev_pcie_err(pcie_set,
			"running_channels is NULL");
		return IRQ_HANDLED;
	}

	channel = (struct dma_channel_info *)
		pcie_set->running_channels[phy_channel][0];
	if (!channel) {
		cn_dev_pcie_err(pcie_set,
			"phy_channel:%d is NULL", phy_channel);
		return IRQ_HANDLED;
	}

	if (interrupt_status & err_mask) {
		cn_dev_pcie_err(pcie_set,
			"DMA interrupt error interrupt_status:0x%x",
							interrupt_status);
		if (pcie_set->ops->dump_reg)
			pcie_set->ops->dump_reg(pcie_set);
		pcie_show_desc_list(channel);
		cn_pci_dma_complete(phy_channel, 0, CHANNEL_COMPLETED_ERR, pcie_set);
	} else {
		if (pcie_set->dma_err_inject_flag) {
			pcie_set->dma_err_inject_flag = 0;
			cn_dev_pcie_err(pcie_set, "DMA interrupt error status: Fake Manual Error.");
			cn_pci_dma_complete(phy_channel, 0, CHANNEL_COMPLETED_ERR, pcie_set);
		} else {
			cn_pci_dma_complete(phy_channel, 0, CHANNEL_COMPLETED, pcie_set);
		}
	}

	cn_pci_task_fair_schedule(pcie_set);
	return IRQ_HANDLED;
}

#ifdef NEED_SUB_IRQ_MASK
/* For C/S strcut machine system.
 * The irq product from server can not be Sync all the time, when meet advance situation, the
 * EP gic will hang for looooog time and don't ack new IRQ.
 */
#define STATUS_ADDR(irq)	(((irq / 32) << 2) + GIC_STATUS_CLR)
#define MSIX_PENDING_ADDR(irq)	(((irq / 32) << 2) + GIC_MSIX_PEND_CLR)
#define SHIFT_BIT_CNT(irq)      (irq % 32) /*MASK Group Sub Bit Location*/
static void preclear_pending(struct cn_pcie_set *pcie_set, int irq)
{
	unsigned int index;
	unsigned int max_cnt = sizeof(pcie_sub_system_irq_mask) / sizeof(struct pcie_sub_system_irq_mask_s);
	unsigned int val = 0;

	index = irq - PCIE_IRQ_DMA;
	if (index >= max_cnt) {
		cn_dev_pcie_info(pcie_set,
			"beyond pcie sub-system [%d] >= [%d].", index, max_cnt);
		return;
	}

	/***
	 * Without pre-check Exist or Not, just to do clear...
	 */
	/*clear status*/
	val = cn_pci_reg_read32(pcie_set, STATUS_ADDR(irq));
	cn_dev_debug("Current status 0x%x , to clear 0x%x for irq[%d] at 0x%x",
		val, (1 << SHIFT_BIT_CNT(irq)), irq, STATUS_ADDR(irq));
	val = (1 << SHIFT_BIT_CNT(irq));
	cn_pci_reg_write32(pcie_set, STATUS_ADDR(irq), val);
	cn_pci_reg_read32(pcie_set, STATUS_ADDR(irq));
	val ^= (1 << SHIFT_BIT_CNT(irq));
	cn_pci_reg_write32(pcie_set, STATUS_ADDR(irq), val);
	cn_pci_reg_read32(pcie_set, STATUS_ADDR(irq));

	/*clear pend*/
	if (pcie_set->irq_type == MSIX) {
		val = 1 << SHIFT_BIT_CNT(irq);
		cn_dev_debug("To clear msix pending 0x%x for irq[%d] at 0x%x",
			val, irq, MSIX_PENDING_ADDR(irq));
		cn_pci_reg_write32(pcie_set, MSIX_PENDING_ADDR(irq), val);
		cn_pci_reg_read32(pcie_set, MSIX_PENDING_ADDR(irq));
		val ^= (1 << SHIFT_BIT_CNT(irq));
		cn_pci_reg_write32(pcie_set, MSIX_PENDING_ADDR(irq), val);
		cn_pci_reg_read32(pcie_set, MSIX_PENDING_ADDR(irq));
	}
}
static void to_unmask_pcie_subsystem(struct cn_pcie_set *pcie_set, int irq)
{
	unsigned int index;
	unsigned int max_cnt = sizeof(pcie_sub_system_irq_mask) / sizeof(struct pcie_sub_system_irq_mask_s);

	index = irq - PCIE_IRQ_DMA;
	if (index >= max_cnt) {
		cn_dev_pcie_info(pcie_set,
			"beyond pcie sub-system [%d] >= [%d].", index, max_cnt);
		return;
	}
	preclear_pending(pcie_set, irq);
	cn_dev_debug("un-mask pcie sub-system %#lx = %#lx <%d/%d>",
		pcie_sub_system_irq_mask[index].reg,
		pcie_sub_system_irq_mask[index].unmask_val,
		index, max_cnt);
	cn_pci_reg_write32(pcie_set, pcie_sub_system_irq_mask[index].reg,
				pcie_sub_system_irq_mask[index].unmask_val);
	cn_pci_reg_read32(pcie_set, pcie_sub_system_irq_mask[index].reg);
}

static void to_mask_pcie_subsystem(struct cn_pcie_set *pcie_set, int irq)
{
	unsigned int index;
	unsigned int max_cnt = sizeof(pcie_sub_system_irq_mask) / sizeof(struct pcie_sub_system_irq_mask_s);

	index = irq - PCIE_IRQ_DMA;
	if (index >= max_cnt) {
		cn_dev_pcie_info(pcie_set,
			"beyond pcie sub-system [%d] >= [%d].", index, max_cnt);
		return;
	}

	cn_dev_debug("mask pcie sub-system %#lx = %#lx <%d/%d>",
		pcie_sub_system_irq_mask[index].reg,
		pcie_sub_system_irq_mask[index].mask_val,
		index, max_cnt);
	cn_pci_reg_write32(pcie_set, pcie_sub_system_irq_mask[index].reg,
				pcie_sub_system_irq_mask[index].mask_val);
	cn_pci_reg_read32(pcie_set, pcie_sub_system_irq_mask[index].reg);
	preclear_pending(pcie_set, irq);
}
#else
#define to_mask_pcie_subsystem(a, b)
#define to_unmask_pcie_subsystem(a, b)
#endif

static irqreturn_t pcie_dma_interrupt_handle(int index, void *data)
{
	unsigned int interrupt_status;
	unsigned int channel_bit;
	unsigned int err_mask;
	int phy_channel;
	int phy_channel_num;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct dma_channel_info *channel;

	/*
	 * each dma have single msix vetcor, just do oneself interrupt
	 * othersize, read DISTATUS_LOCAL maybe conflict
	 */
	if (pcie_set->irq_type == MSIX)
		return msix_interrupt_handle(index, pcie_set);

	if (pcie_set->do_dma_irq_status == 0)
		pcie_set->do_dma_irq_status = 1;
	else
		return IRQ_HANDLED;

	/*
	 * read dma interrupt register to get which channel generate interrupt
	 * This interrupt may be done or error.not is done and error.
	 */
	interrupt_status = cn_pci_reg_read32(pcie_set, DISTATUS_LOCAL);
	if (pcie_set->arm_trigger_enable) {
		interrupt_status &= HOST_PHY_CHANNEL_MASK |
			(HOST_PHY_CHANNEL_MASK << DMA_REG_CHANNEL_NUM);
	} else {
		interrupt_status &= INTR_DMA_CHANNEL_MASK |
			(INTR_DMA_CHANNEL_MASK << DMA_REG_CHANNEL_NUM);
	}
	cn_pci_reg_write32(pcie_set, DISTATUS_LOCAL, interrupt_status);
	cn_pci_reg_read32(pcie_set, DISTATUS_LOCAL);

	if (!interrupt_status)
		return 0;

	channel_bit = (1 | (1 << DMA_REG_CHANNEL_NUM));
	if (pcie_set->arm_trigger_enable) {
		err_mask = HOST_PHY_CHANNEL_MASK << DMA_REG_CHANNEL_NUM;
		phy_channel_num = HOST_PHY_CHANNEL_NUM;
	} else {
		err_mask = INTR_DMA_CHANNEL_MASK << DMA_REG_CHANNEL_NUM;
		phy_channel_num = INTR_DMA_CHANNEL_NUM;
	}
	for (phy_channel = 0; phy_channel < phy_channel_num;
			phy_channel++, (channel_bit <<= 1)) {
		if (!(interrupt_status & channel_bit))
			continue;
		/* fix change mlu from pf to vf, dma can not used error*/
		cn_pci_reg_write32(pcie_set, DSHARE_ACCESS(phy_channel), 0);

		channel = (struct dma_channel_info *)
			pcie_set->running_channels[phy_channel][0];
		if (!channel) {
			cn_dev_pcie_err(pcie_set,
				"phy_channel:%d is NULL", phy_channel);
			continue;
		}


		if ((interrupt_status & channel_bit) & err_mask) {
			cn_dev_pcie_err(pcie_set,
				"DMA interrupt error interrupt_status:0x%x",
								interrupt_status);
			if (pcie_set->ops->dump_reg)
				pcie_set->ops->dump_reg(pcie_set);
			pcie_show_desc_list(channel);
			cn_pci_dma_complete(phy_channel, 0, CHANNEL_COMPLETED_ERR, pcie_set);
		} else {
			if (pcie_set->dma_err_inject_flag) {
				pcie_set->dma_err_inject_flag = 0;
				cn_dev_pcie_err(pcie_set, "DMA interrupt error status: Fake Manual Error.");
				cn_pci_dma_complete(phy_channel, 0, CHANNEL_COMPLETED_ERR, pcie_set);
			} else {
				cn_pci_dma_complete(phy_channel, 0, CHANNEL_COMPLETED, pcie_set);
			}
		}

	}

	cn_pci_task_fair_schedule(pcie_set);
	return IRQ_HANDLED;
}

static int pci_hw_msix_enable(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, GIC_CTRL, GIC_ENABLE_MSIX_BIT | GIC_OPEN_GI_BIT);
	cn_pci_reg_read32(pcie_set, GIC_CTRL);

	return 0;
}

static int pci_hw_msix_disable(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, GIC_CTRL, 0);
	cn_pci_reg_read32(pcie_set, GIC_CTRL);

	return 0;
}

static int pci_hw_msi_enable(struct cn_pcie_set *pcie_set)
{
	/* enable msi */
	cn_pci_reg_write32(pcie_set, GIC_CTRL,
				GIC_ENABLE_MSI_BIT | GIC_OPEN_GI_BIT);
	cn_pci_reg_read32(pcie_set, GIC_CTRL);

	return 0;
}

static int pci_hw_msi_disable(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, GIC_CTRL, 0);
	cn_pci_reg_read32(pcie_set, GIC_CTRL);

	return 0;
}

static int pci_hw_intx_enable(struct cn_pcie_set *pcie_set)
{
	/* enable intx */
	cn_pci_reg_write32(pcie_set, GIC_CTRL,
				GIC_ENABLE_INTX_BIT | GIC_OPEN_GI_BIT);
	cn_pci_reg_read32(pcie_set, GIC_CTRL);

	return 0;
}

static int pci_hw_intx_disable(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, GIC_CTRL, 0);
	cn_pci_reg_read32(pcie_set, GIC_CTRL);

	return 0;
}

static void pci_isr_hw_enable(struct cn_pcie_set *pcie_set)
{
	isr_hw_enable[pcie_set->irq_type](pcie_set);
}

static void pci_isr_hw_disable(struct cn_pcie_set *pcie_set)
{
	isr_hw_disable[pcie_set->irq_type](pcie_set);
}

static int pcie_fill_desc_list(struct dma_channel_info *channel)
{
	cn_dev_info("no file_desc_list function, please add in private file");
	return 0;
}

static int pcie_async_dma_fill_desc_list(struct async_task *async_task)
{
	cn_dev_info("no async_dma_fill_desc_list function, please add in private file");
	return 0;
}

static void pcie_show_desc_list(struct dma_channel_info *channel)
{
	int desc_offset = 0;

	cn_dev_pcie_err(channel->pcie_set, "transfer_len:%ld desc_len:%d",
		channel->transfer_length, channel->desc_len);

	for (; desc_offset < channel->desc_len; desc_offset += DESC_SIZE) {
		cn_dev_pcie_err(channel->pcie_set,
			"%#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x",
			ioread32(channel->desc_virt_base + desc_offset + 0),
			ioread32(channel->desc_virt_base + desc_offset + 4),
			ioread32(channel->desc_virt_base + desc_offset + 8),
			ioread32(channel->desc_virt_base + desc_offset + 12),
			ioread32(channel->desc_virt_base + desc_offset + 16),
			ioread32(channel->desc_virt_base + desc_offset + 20),
			ioread32(channel->desc_virt_base + desc_offset + 24),
			ioread32(channel->desc_virt_base + desc_offset + 28));
	}
}

struct pcie_dump_reg_s {
	char *desc;
	unsigned long reg;
};

static void pcie_dump_reg(struct cn_pcie_set *pcie_set)
{
	cn_dev_pcie_info(pcie_set, "no dump function, please add in private file");
}

/*
 * no bug like c20l, we just do dummy_mb with a readback
 */
static void pci_mb(struct cn_pcie_set *pcie_set)
{
	/* barrier */
	smp_mb();
	cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);
}

static inline void do_one_irq(struct cn_pcie_set *pcie_set,
				int interrupt_index)
{
	u64 start, end;

	pcie_set->irq_desc[interrupt_index].occur_count++;

	if (pcie_set->irq_desc[interrupt_index].handler[0] == NULL) {
		cn_dev_pcie_err(pcie_set, "interrupt%d handle is NULL!",
				interrupt_index);
		return;
	}
	start = get_jiffies_64();
	if (pcie_set->irq_desc[interrupt_index].handler[0](interrupt_index,
		pcie_set->irq_desc[interrupt_index].data[0]) == IRQ_HANDLED) {
		end = get_jiffies_64();

		if (time_after64(end, start + HZ / 2))
			cn_dev_pcie_warn(pcie_set,
				"do interrupt%d spend too long time(%dms)!!!",
				interrupt_index, jiffies_to_msecs(end - start));
	}
}

static inline void do_irq(struct cn_pcie_set *pcie_set,
					u64 gic_status, u64 gic_mask, int i)
{
	int interrupt_index;
	int handler_num;
	u64 start, end;

	pcie_set->do_dma_irq_status = 0;
	gic_status &= (~gic_mask);
	while (gic_status) {
		interrupt_index = __ffs(gic_status);
		gic_status &= ~(1ULL << interrupt_index);
		interrupt_index += (i * 64);
		handler_num = 0;

		pcie_set->irq_desc[interrupt_index].occur_count++;

		do {
			if (pcie_set->irq_desc[interrupt_index].handler[handler_num] == NULL) {
				cn_dev_pcie_err(pcie_set, "no interrupt handle!:%llx %x",
						gic_status, interrupt_index);
				break;
			}
			start = get_jiffies_64();
			if (pcie_set->irq_desc[interrupt_index].handler[handler_num](interrupt_index,
				pcie_set->irq_desc[interrupt_index].data[handler_num]) == IRQ_HANDLED) {
				end = get_jiffies_64();

				if (time_after64(end, start + HZ / 2))
					cn_dev_pcie_warn(pcie_set,
						"do interrupt%d spend too long time(%dms)!!!",
						interrupt_index, jiffies_to_msecs(end - start));
				break;
			}
			handler_num++;
		} while (handler_num < IRQ_SHARED_NUM);

		if (handler_num == IRQ_SHARED_NUM)
			cn_dev_pcie_err(pcie_set, "no interrupt handle!:%llx %x",
						gic_status, interrupt_index);
	}
	pcie_set->do_dma_irq_status = 0;
}

static irqreturn_t msix_interrupt(int irq, void *data)
{
	u64 gic_status = 0;
	u64 gic_mask = 0;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct msix_entry *entry;
	int irq_start, irq_end;
	int vector_index;
	u32 value;
	u32 offsize;

	entry = (struct msix_entry *)pcie_set->msix_entry_buf;

	for (vector_index = 0; vector_index < MSIX_COUNT; vector_index++) {
		if (entry[vector_index].vector == irq)
			break;
	}

	if (vector_index >= MSIX_COUNT) {
		cn_dev_pcie_err(pcie_set, "Recv error interrupt:%d", irq);
		return IRQ_HANDLED;
	}

	/*
	 * dma0 to dma7 irq number is 0 ~ 7;
	 * one msix vector to a single dma, so no need to read gic status
	 */
	if (vector_index < 8) {
		do_one_irq(pcie_set, vector_index);
		goto done;
	}

#if (GIC_INTERRUPT_NUM != MSIX_COUNT)
	irq_start = irq_msix_gic_end[vector_index - 1] + 1;
	irq_end = irq_msix_gic_end[vector_index];
#else
	irq_start = irq_end = vector_index;
#endif

	for (i = (irq_start / 64); i <= (irq_end / 64); i++) {
		gic_mask = pcie_set->gic_mask[i];
		if (gic_mask == -1ULL)
			continue;

		if (i == irq_start / 64)
			gic_mask |= ((1UL << (irq_start % 64)) - 1);

		if (i == irq_end / 64 && (irq_end % 64) != 63)
			gic_mask |= (~((1UL << ((irq_end + 1) % 64)) - 1));

		gic_status = cn_pci_reg_read64(pcie_set, GIC_STATUS + i * 8);
		if (gic_status != -1ULL)
			do_irq(pcie_set, gic_status, gic_mask, i);
	}

done:
	offsize = (vector_index / 32) * 4;
	value = (1UL << (vector_index % 32));
	cn_pci_reg_write32(pcie_set, GIC_MSIX_PEND_CLR + offsize, value);
	cn_pci_reg_write32(pcie_set, GIC_MSIX_PEND_CLR + offsize, 0);

	return IRQ_HANDLED;
}

static irqreturn_t msi_interrupt(int irq, void *data)
{
	u64 gic_status = 0;
	u64 gic_mask = 0;
	u32 msi_mask = 0;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	int irq_start, irq_end;
	int vector_index;

	/* this lock is used to protect msi mask */
	spin_lock(&pcie_set->interrupt_lock);
	vector_index = irq - pcie_set->irq;

	if (vector_index >= MSI_COUNT) {
		cn_dev_pcie_err(pcie_set, "recv error interrupt:%d", irq);
		spin_unlock(&pcie_set->interrupt_lock);
		return IRQ_HANDLED;
	}

	/***
	 * PLDA IP. MSI mask  : write 1  --> handle --> write 0
	 */
	pci_read_config_dword(pcie_set->pdev, pcie_set->msi_pos + MSI_MASK,
								&msi_mask);
	msi_mask |= (0x1 << vector_index);
	pci_write_config_dword(pcie_set->pdev, pcie_set->msi_pos + MSI_MASK,
								msi_mask);

	irq_start = (vector_index == 0) ? 0 :
			(irq_msi_gic_end[vector_index - 1] + 1);
	irq_end = irq_msi_gic_end[vector_index];

	for (i = (irq_start / 64); i <= (irq_end / 64); i++) {
		gic_mask = pcie_set->gic_mask[i];
		if (gic_mask == -1ULL)
			continue;

		if (i == irq_start/64)
			gic_mask |= ((1UL << (irq_start % 64)) - 1);
		if (i == irq_end / 64 && (irq_end % 64) != 63)
			gic_mask |= (~((1UL << ((irq_end + 1) % 64)) - 1));

		gic_status = cn_pci_reg_read64(pcie_set, GIC_STATUS + i * 8);
		if (gic_status != -1ULL)
			do_irq(pcie_set, gic_status, gic_mask, i);
	}

	pci_read_config_dword(pcie_set->pdev, pcie_set->msi_pos + MSI_MASK,
								&msi_mask);
	msi_mask &= (~(0x1 << vector_index));
	pci_write_config_dword(pcie_set->pdev, pcie_set->msi_pos + MSI_MASK,
								msi_mask);
	spin_unlock(&pcie_set->interrupt_lock);

	return IRQ_HANDLED;
}

static irqreturn_t intx_interrupt(int irq, void *data)
{
	u64 gic_status = 0;
	u64 gic_mask = 0;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;


	for (i = 0; i < (GIC_INTERRUPT_NUM / 64); i++) {
		gic_mask = pcie_set->gic_mask[i];
		if (gic_mask == -1ULL)
			continue;

		gic_status = cn_pci_reg_read64(pcie_set, GIC_STATUS + i * 8);
		if (gic_status != -1ULL)
			do_irq(pcie_set, gic_status, gic_mask, i);
	}
	cn_pci_reg_write32(pcie_set, GLOBAL_INTX_CLR, 0x1);
	cn_pci_reg_write32(pcie_set, GLOBAL_INTX_CLR, 0x0);
	cn_pci_reg_read32(pcie_set, GLOBAL_INTX_CLR);

	return IRQ_HANDLED;
}

static int pcie_gic_mask(int irq, struct cn_pcie_set *pcie_set)
{
	u64 reg_val;
	int i = irq / 64;

	if (irq < 0) {
		cn_dev_pcie_err(pcie_set,
			"pcie_gic hw_irq %d can not less than zero", irq);
		return -1;
	}

	reg_val = cn_pci_reg_read64(pcie_set, GIC_MASK + i * 8);
	reg_val |= (1ULL << (irq % 64));
	pcie_set->gic_mask[i] = reg_val;

	cn_pci_reg_write64(pcie_set, GIC_MASK + i * 8, reg_val);
	cn_pci_reg_read64(pcie_set, GIC_MASK + i * 8);
	cn_dev_pcie_debug(pcie_set, "mask(ignore) irq-%d -> 0x%x = %#llx",
		irq, (GIC_MASK + i * 8), reg_val);

	/***
	 * The sub-system control bit shall be mask at the same time
	 */
	to_mask_pcie_subsystem(pcie_set, irq);

	return 0;
}

static int pcie_gic_unmask(int irq, struct cn_pcie_set *pcie_set)
{
	u64 reg_val;
	int i = irq / 64;

	if (irq < 0) {
		cn_dev_pcie_err(pcie_set,
			"pcie_gic hw_irq %d can not less than zero", irq);
		return -1;
	}

	reg_val = cn_pci_reg_read64(pcie_set, GIC_MASK + i * 8);
	reg_val &= (~(1ULL << (irq % 64)));
	pcie_set->gic_mask[i] = reg_val;

	cn_pci_reg_write64(pcie_set, GIC_MASK + i * 8, reg_val);
	cn_pci_reg_read64(pcie_set, GIC_MASK + i * 8);
	cn_dev_pcie_debug(pcie_set, "mask(accept) irq-%d -> 0x%x = %#llx",
		irq, (GIC_MASK + i * 8), reg_val);

	/***
	 * The sub-system control bit shall be unmask at the same time
	 */
	to_unmask_pcie_subsystem(pcie_set, irq);

	return 0;
}

static int pcie_gic_mask_all(struct cn_pcie_set *pcie_set)
{
	u64 reg_val = -1ULL;
	unsigned long i;

	for (i = 0; i < (GIC_INTERRUPT_NUM)/64; i++) {
		pcie_set->gic_mask[i] = reg_val;
		cn_pci_reg_write64(pcie_set, GIC_MASK + i * 8, reg_val);
		cn_pci_reg_read64(pcie_set, GIC_MASK + i * 8);
	}

	return 0;
}

static int pcie_get_irq(char *irq_desc, struct cn_pcie_set *pcie_set)
{
	int i = 0;

	for (; i < GIC_INTERRUPT_NUM; i++) {
		if (!strcmp(pcie_set->irq_str_index_ptr[i].str_index, irq_desc))
			return pcie_set->irq_str_index_ptr[i].hw_irq_num;
	}

	return -1;
}

static int pcie_dma_go(struct dma_channel_info *channel, int phy_channel)
{
	struct cn_pcie_set *pcie_set = channel->pcie_set;
	int channel_id = phy_channel;
	unsigned long src_desc_addr = 0;
	unsigned long dst_desc_addr = 0;
	int sgl_enable = 0;
	int sgl_mode = 0;
	int sg_id[2] = {0};

	if (channel->status != CHANNEL_RUNNING)
		cn_dev_pcie_err(pcie_set, "channel is not locked:%d", channel->status);

	switch (channel->direction) {
	case DMA_H2D:
		cn_pci_reg_write32(pcie_set,
			DSRC_PARAM(channel_id), DMA_PCIE_PARAM);
		cn_pci_reg_write32(pcie_set,
			DDEST_PARAM(channel_id), DMA_AXI_PARAM);
		break;
	case DMA_P2P:
	case DMA_D2H:
		cn_pci_reg_write32(pcie_set,
			DSRC_PARAM(channel_id), DMA_AXI_PARAM);
		cn_pci_reg_write32(pcie_set,
			DDEST_PARAM(channel_id), DMA_PCIE_PARAM);
		break;

	default:
		cn_dev_pcie_err(pcie_set, "unknown dma direction:%d", channel->direction);
		return -1;
	}
	src_desc_addr = channel->desc_device_va;
	dst_desc_addr = 0;
	sg_id[0] = SG_ID_AXI;//desc addr is pcie or axi
	sgl_mode = 3;
	sgl_enable = 1;

	cn_pci_reg_write32(pcie_set, DLEN(channel_id), channel->transfer_length);
	cn_pci_reg_write32(pcie_set, DSRCL(channel_id), LOWER32(src_desc_addr));
	cn_pci_reg_write32(pcie_set, DSRCU(channel_id), UPPER32(src_desc_addr));
	cn_pci_reg_write32(pcie_set, DDESTL(channel_id), LOWER32(dst_desc_addr));
	cn_pci_reg_write32(pcie_set, DDESTU(channel_id), UPPER32(dst_desc_addr));

	cn_pci_reg_read32(pcie_set, DDESTU(channel_id));
	cn_pci_reg_write32(pcie_set, DCTRL(channel_id), (sgl_enable << 3)
					| (DSE_COND << 4) | (DIRQ << 8)
					| (DIRQ_ID << 12) | (sgl_mode << 24)
					| (sg_id[0] << 26) | (sg_id[1] << 29)
					| 0x1);

	return 0;
}

static int pcie_init(struct cn_pcie_set *pcie_set)
{
	return 0;
}

static void pcie_unregister_bar(struct cn_pcie_set *pcie_set);

static void bar_deinit(struct cn_pcie_set *pcie_set)
{
	int i, seg;

	/*Free pcie_set->pcibar[N]*/
	for (i = 0; i < 6; i++) {
		if (pcie_set->pcibar[i].size <= 0)
			continue;

		for (seg = 0; seg < MAX_BAR_SEGMENTS; seg++) {
			if (pcie_set->pcibar[i].seg[seg].virt) {
				cn_iounmap(pcie_set->pcibar[i].seg[seg].virt);
				pcie_set->pcibar[i].seg[seg].virt = NULL;
			}
		}
	}

	/*Free pcie_set->bar_resource_head.*/
	pcie_unregister_bar(pcie_set);

	if (pcie_set->priv_set)
		cn_kfree(pcie_set->priv_set);
}

static int pcie_outbound_exit(struct cn_pcie_set *pcie_set)
{
	int i;
	int outbound_index;
	struct outbound_mem *outbound_mem;

	outbound_mem = pcie_set->share_priv;
	if ((!outbound_mem) || (!pcie_set->share_mem_pages))
		return 0;

	if (pcie_set->share_mem[1].virt_addr) {
		vm_unmap_ram(pcie_set->share_mem[1].virt_addr,
			(pcie_set->ob_cnt * pcie_set->ob_size) / PAGE_SIZE);
		pcie_set->share_mem[1].virt_addr = NULL;
	}

	for (i = 0; i < (pcie_set->ob_cnt * pcie_set->ob_size) / PAGE_SIZE; i++) {
		if (pcie_set->share_mem_pages[i]) {
			pcie_set->share_mem_pages[i] = NULL;
		}
	}

	for (i = 0; i < pcie_set->ob_cnt; i++) {
		if (outbound_mem[i].virt_addr)
			pci_free_consistent(pcie_set->pdev, pcie_set->ob_size,
				outbound_mem[i].virt_addr, outbound_mem[i].pci_addr);
	}

	for_each_set_bit(outbound_index, (unsigned long *)&pcie_set->ob_mask,
			sizeof(pcie_set->ob_mask) * 8) {
		cn_pci_reg_write64(pcie_set,
					SLV0_SRC_ADDRL(outbound_index), 0ULL);
		cn_pci_reg_write64(pcie_set,
					SLV0_TRSL_ADDRL(outbound_index), 0ULL);
		cn_pci_reg_write32(pcie_set,
					SLV0_TRSL_PARAM(outbound_index), 0);
		cn_pci_reg_write64(pcie_set,
					SLV0_TRSL_MASKL(outbound_index), 0ULL);
	}

	cn_kfree(pcie_set->share_mem_pages);
	pcie_set->share_mem_pages = NULL;
	cn_kfree(pcie_set->share_priv);
	pcie_set->share_priv = NULL;

	return 0;
}

static int pcie_exit(struct cn_pcie_set *pcie_set)
{
	return 0;
}

static void pcie_outbound_reg(struct cn_pcie_set *pcie_set)
{
	int i = 0;
	int outbound_index;
	struct outbound_mem *outbound_mem;
	u64 value;

	/***
	 * outbound_mem : data outbound
	 * share_mem_pages : normal outbound
	 */
	outbound_mem = pcie_set->share_priv;
	if ((!outbound_mem) || (!pcie_set->share_mem_pages))
		return;

	for_each_set_bit(outbound_index, (unsigned long *)&pcie_set->ob_mask,
		sizeof(pcie_set->ob_mask) * 8) {
		/* outbound pci address */
		cn_pci_reg_write64(pcie_set, SLV0_TRSL_ADDRL(outbound_index),
						(outbound_mem[i].pci_addr));
		/* axi address
		 * Attetion: OUTBOUND_AXI_BASE not needed for 370.
		 */
		value = (pcie_set->ob_size * outbound_index) |
			((OUTBOUND_POWER - 1) << 1) | (1 << 0);
#ifdef INIT_WITH_OB_AXI_BASE
		value |= OUTBOUND_AXI_BASE;
#endif
		cn_pci_reg_write64(pcie_set,
					SLV0_SRC_ADDRL(outbound_index), value);
		/* param*/
		value = 0;
		cn_pci_reg_write32(pcie_set,
				SLV0_TRSL_PARAM(outbound_index), (u32)value);
		/* mask*/
		value = ~(u64)((0x1ULL << OUTBOUND_POWER) - 1);
		cn_pci_reg_write64(pcie_set,
					SLV0_TRSL_MASKL(outbound_index), value);
		cn_pci_reg_read32(pcie_set, PCIE_DUMMY_WRITE);

		cn_dev_debug("outbound:%d virtual_addr:%llx pci_addr:%#llx i:%d",
				outbound_index, (u64)outbound_mem[i].virt_addr,
				outbound_mem[i].pci_addr, i);
		i++;
	}
}

static int pcie_outbound_init(struct cn_pcie_set *pcie_set)
{
	int i;
	int j;
	int page_index = 0;
	struct outbound_mem *outbound_mem;
	int index = pcie_set->share_mem_cnt;
	void *virt_addr;

	pcie_set->share_mem_pages =
		cn_kzalloc((pcie_set->ob_total_size / PAGE_SIZE) *
					sizeof(struct page *), GFP_KERNEL);
	if (!pcie_set->share_mem_pages) {
		cn_dev_pcie_err(pcie_set, "kzalloc share_mem_pages error");
		return -1;
	}

	outbound_mem = cn_kzalloc(pcie_set->ob_cnt *
				sizeof(struct outbound_mem), GFP_KERNEL);
	if (!outbound_mem) {
		cn_dev_pcie_err(pcie_set, "kzalloc outbound_mem error");
		goto ERROR_RET;
	}
	pcie_set->share_priv = (void *)outbound_mem;

	/*Alloc coherent HOST,VA and PCI.ADDR*/
	for (i = 0; i < pcie_set->ob_cnt; i++) {
		outbound_mem[i].virt_addr =
				dma_alloc_coherent(&pcie_set->pdev->dev,
				pcie_set->ob_size, &(outbound_mem[i].pci_addr),
				GFP_KERNEL | __GFP_NOWARN);
		if (!outbound_mem[i].virt_addr) {
			cn_dev_pcie_err(pcie_set, "dma_alloc_coherent error:%d", i);
			goto ERROR_RET;
		}

		if (outbound_mem[i].pci_addr&(pcie_set->ob_size - 1)) {
			cn_dev_pcie_err(pcie_set, "dma_alloc_coherent not align:%llx",
				outbound_mem[i].pci_addr);
			goto ERROR_RET;
		}
	}
	/*OB Host-Address Is dma-coherent. Here record its pages info*/
	page_index = 0;
	for (i = 0; i < pcie_set->ob_cnt; i++) {
		for (j = 0; j < pcie_set->ob_size / PAGE_SIZE; j++) {
			virt_addr = outbound_mem[i].virt_addr + j * PAGE_SIZE;
			if (is_vmalloc_addr(virt_addr))
				pcie_set->share_mem_pages[page_index] =
						vmalloc_to_page(virt_addr);
			else
				pcie_set->share_mem_pages[page_index] =
						virt_to_page(virt_addr);
			page_index++;
		}
	}
	/*re-map all pages to host.VA which is continous whole one.*/
#if  defined(__x86_64__)
	pcie_set->share_mem[index].virt_addr = cn_vm_map_ram(
		pcie_set->share_mem_pages, page_index, -1, PAGE_KERNEL_NOCACHE);
#else
	pcie_set->share_mem[index].virt_addr = cn_vm_map_ram(
		pcie_set->share_mem_pages, page_index, -1, PAGE_KERNEL);
#endif
	if (!pcie_set->share_mem[index].virt_addr) {
		cn_dev_pcie_err(pcie_set, "vm_map_ram error");
		goto ERROR_RET;
	}

	cn_dev_pcie_info(pcie_set, "host share mem virtual addr:%px",
		pcie_set->share_mem[index].virt_addr);
	pcie_set->share_mem[index].win_length = pcie_set->ob_total_size;
	pcie_set->share_mem[index].type = CN_SHARE_MEM_HOST;
	pcie_set->share_mem[index].device_addr = pcie_set->ob_axi_addr;

	pcie_set->share_mem_cnt++;
	return 0;

ERROR_RET:
	pcie_outbound_exit(pcie_set);
	return -1;
}

static int cn_pci_link_set(struct cn_pcie_set *pcie_set, bool enable)
{
	u16 lnk_ctrl;
	struct pci_dev *pdev;

	if (!(pcie_set->pdev->bus && pcie_set->pdev->bus->self)) {
		return 0;
	}

	pdev = pcie_set->pdev->bus->self;
	pcie_capability_read_word(pdev, PCI_EXP_LNKCTL, &lnk_ctrl);
	if (enable)
		lnk_ctrl &= ~PCI_EXP_LNKCTL_LD;
	else
		lnk_ctrl |= PCI_EXP_LNKCTL_LD;
	pcie_capability_write_word(pdev, PCI_EXP_LNKCTL, lnk_ctrl);

	cn_dev_pcie_info(pcie_set, "lnk_ctrl = 0x%x", lnk_ctrl);
	return 0;
}

static int pcie_soft_reset(struct cn_pcie_set *pcie_set)
{
	cn_pci_link_set(pcie_set, false);
	msleep(100);
	cn_pci_link_set(pcie_set, true);
	msleep(10);
	cn_pci_link_set(pcie_set, true);

	return 0;
}

static int pcie_dma_bypass_size(struct cn_pcie_set *pcie_set)
{
#if defined(__x86_64__)
	pcie_set->dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 512 * 1024;
	pcie_set->dma_bypass_pinned_size = dma_bypass_pinned_size ?
				dma_bypass_pinned_size : 256 * 1024;
	pcie_set->dma_memsetD8_custom_size = dma_memsetD8_custom_size ?
				dma_memsetD8_custom_size : 128 * 1024 * 1024;
	pcie_set->dma_memsetD16_custom_size = dma_memsetD16_custom_size ?
				dma_memsetD16_custom_size : 1024 * 1024;
	pcie_set->dma_memsetD32_custom_size = dma_memsetD32_custom_size ?
				dma_memsetD32_custom_size : 1024 * 1024;
#else
	pcie_set->dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 256;
	pcie_set->dma_bypass_pinned_size = dma_bypass_pinned_size ?
				dma_bypass_pinned_size : 256;
	pcie_set->dma_memsetD8_custom_size = dma_memsetD8_custom_size ?
				dma_memsetD8_custom_size : 256;
	pcie_set->dma_memsetD16_custom_size = dma_memsetD16_custom_size ?
				dma_memsetD16_custom_size : 256;
	pcie_set->dma_memsetD32_custom_size = dma_memsetD32_custom_size ?
				dma_memsetD32_custom_size : 256;
#endif
	pcie_set->d2h_bypass_custom_size = d2h_bypass_custom_size ?
				d2h_bypass_custom_size : 64;
	return 0;
}

static u64 pcie_set_bar_window(u64 axi_address, struct bar_resource *bar,
		struct cn_pcie_set *pcie_set)
{
	u64 addr = bar->window_addr;

	if (axi_address >= addr && axi_address < (addr + bar->size))
		return addr;

	axi_address &= (~((u64)(bar->size - 1)));
	cn_pci_reg_write64(pcie_set, bar->reg_index, axi_address);
	cn_pci_reg_read32(pcie_set, bar->reg_index);

	bar->window_addr = axi_address;
	return axi_address;
}

static struct cn_pci_ops public_ops = {
	.pcie_init = pcie_init,
	.pcie_exit = pcie_exit,
	.fill_desc_list = pcie_fill_desc_list,
	.show_desc_list = pcie_show_desc_list,
	.dump_reg = pcie_dump_reg,
	.pci_mb = pci_mb,
	.intx_isr = intx_interrupt,
	.msi_isr = msi_interrupt,
	.msix_isr = msix_interrupt,
	.isr_hw_enable = pci_isr_hw_enable,
	.isr_hw_disable = pci_isr_hw_disable,
	.gic_mask = pcie_gic_mask,
	.gic_unmask = pcie_gic_unmask,
	.gic_mask_all = pcie_gic_mask_all,
	.get_irq_by_desc = pcie_get_irq,
	.dma_bypass_size = pcie_dma_bypass_size,
	.dma_go_command = pcie_dma_go,
	.soft_reset = pcie_soft_reset,
	.bar_write = mlu370_pigeon_pcie_bar_write,
	.bar_read = mlu370_pigeon_pcie_bar_read,
	.async_dma_fill_desc_list = pcie_async_dma_fill_desc_list,
	.set_bar_window = pcie_set_bar_window,
};

static void outbound_pre_init(struct cn_pcie_set *pcie_set)
{
	const void *domain = NULL;

	if (cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		domain = cn_dm_get_domain_early(pcie_set->bus_set,
							DM_FUNC_OVERALL);
		if (!domain) {
			cn_dev_pcie_info(pcie_set,
					"get overall domain failed. exit");
			return;
		}
		pcie_set->ob_mask = cn_dm_pci_get_ob_mask(domain);
	} else {
		pcie_set->ob_mask = ((u64)((1ULL << PF_OUTBOUND_CNT) - 1))
							<< OUTBOUND_FIRST;
	}

	cn_dev_pcie_info(pcie_set, "ob_mask:%#llx", pcie_set->ob_mask);

	pcie_set->ob_size = OUTBOUND_SIZE;
	pcie_set->ob_axi_addr = OUTBOUND_AXI_BASE;
	pcie_set->ob_cnt = hweight64(pcie_set->ob_mask);
	pcie_set->ob_total_size = pcie_set->ob_size * pcie_set->ob_cnt;
	cn_dev_pcie_info(pcie_set,
			"ob_cnt:%d ob_size:0x%x ob_total_size:%x ob_axi_addr:%llx",
				pcie_set->ob_cnt, pcie_set->ob_size,
				pcie_set->ob_total_size, pcie_set->ob_axi_addr);
}

static void fill_msix_ram(struct cn_pcie_set *pcie_set)
{
	int i;

	/* NOTE: when heartbeat start pcie_set->heartbeat_cnt != 0,
	 * pcie_set->msix_ram use pcie_pre_exit() function keep value
	 */
	if (!pcie_set->heartbeat_cnt)
		memset((void *)(&pcie_set->msix_ram[0]),
				0xff, sizeof(pcie_set->msix_ram));

	for (i = 0; i < (GIC_INTERRUPT_NUM * 4); i++)
		cn_pci_reg_write32(pcie_set, (GBO + i * 4),
					pcie_set->msix_ram[i]);
}

#ifdef USE_DATA_OUTBOUND
static void c30s_pcie_data_outbound_pre_init(struct cn_pcie_set *pcie_set);
static int c30s_pcie_data_outbound_init(struct cn_pcie_set *pcie_set);
#endif
static int do_pcie_init(struct cn_pcie_set *pcie_set)
{
	int ret = 0;

	pcie_set->outbound_able = 1;
	/***
	 * Host Address Source prepared here : pcie_set->share_mem_pages.
	 */
	ret = pcie_outbound_init(pcie_set);
	if (ret) {
		pcie_set->outbound_able = 0;
	}

	/* It's ugly, but somewhere in code there is kinda dependency
	 * of layout of shm:
	 * [0] : device/inbound
	 * [1] : host/outbound config
	 * [2] : host/outbound data
	 * */

	/* data outbound disable by a deadlock
	 * pcie_set->dob_set->share_priv
	 */
	pcie_set->data_outbound_able = 0;
#ifdef USE_DATA_OUTBOUND
	if (!cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn) &&
			pcie_set->data_outbound_able) {
		c30s_pcie_data_outbound_pre_init(pcie_set);

		ret = c30s_pcie_data_outbound_init(pcie_set);
		if (ret) {
			pcie_set->data_outbound_able = 0;
			goto exit;
		}
	} else {
		pcie_set->data_outbound_able = 0;
	}
#endif
	ret = pcie_dma_interrupt_init(pcie_set);
	if (ret)
		goto exit;

	ret = pcie_pre_init_hw(pcie_set);
	if (ret)
		goto exit;

	return 0;
exit:
	pcie_outbound_exit(pcie_set);
	return -1;
}

/*
 * Public bug fix for PLDA IP
 */
__attribute__((unused)) static void bug_fix_list(struct cn_pcie_set *pcie_set)
{
	return;
}
