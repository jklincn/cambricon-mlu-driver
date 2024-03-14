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

static int workaround_for_d2h_with_poison_TLP(struct dma_channel_info *channel,
	struct cn_pcie_set *pcie_set, int phy)
{
	int i;
	struct pcie_dma_task *task = channel->task;

	if (channel->fix_count == 1) {
		cn_dev_pcie_info(channel->pcie_set, "try fix error");
		pcie_set->ops->dump_reg(pcie_set);
		return 1;
	}

	for (i = 0; i < channel->desc_len; i += DESC_SIZE) {
		unsigned long len, dst;
		unsigned int ctrl;

		dst = ioread32(channel->desc_virt_base + i + DE_DEST_LOWER);
		ctrl = ioread32(channel->desc_virt_base + i + DE_CTRL);
		len = (ctrl >> 8) & (0x1000000 - 1);

		/* head align-down to 64-Bytes, tail align-up to 64 Bytes */
		len = ((dst + len + 0x3f) & (~0x3f)) - (dst & (~0x3f));
		ctrl = (0x1 | (0x0 << 1) | (LENGTH_CTRL(len) << 8));
		iowrite32(ctrl, channel->desc_virt_base + i + DE_CTRL);

		dst &= (~0x3f);
		iowrite32(dst, channel->desc_virt_base + i + DE_DEST_LOWER);

#define KDBG_RESV_IOVA_START_L 0x08011000
#define KDBG_RESV_IOVA_START_H 0x80
		/* change dst as available mdr addr */
		iowrite32(KDBG_RESV_IOVA_START_L, channel->desc_virt_base + i + DE_SRC_LOWER);
		iowrite32(KDBG_RESV_IOVA_START_H, channel->desc_virt_base + i + DE_SRC_UPPER);
	}
	task->poison_flag = 1;
	channel->fix_count = 1;

	/* use same phy and command_id go dma again */
	channel->status = CHANNEL_RUNNING;
	pcie_set->ops->dma_go_command(channel, phy);

	return 0;
}

static irqreturn_t pcie_dma_interrupt_handle(int index, void *data)
{
	unsigned int interrupt_status, status;
	unsigned int channel_bit;
	unsigned int err_mask;
	int phy_channel;
	int phy_channel_num;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct dma_channel_info *channel;
	int ret;

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
		interrupt_status &= DMA_REG_CHANNEL_MASK |
			(DMA_REG_CHANNEL_MASK << DMA_REG_CHANNEL_NUM);
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
		err_mask = DMA_REG_CHANNEL_MASK << DMA_REG_CHANNEL_NUM;
		phy_channel_num = DMA_REG_CHANNEL_NUM;
	}
	for (phy_channel = 0; phy_channel < phy_channel_num;
			phy_channel++, (channel_bit <<= 1)) {
		if (!(interrupt_status & channel_bit))
			continue;
		/* fix change mlu from pf to vf, dma can not used error*/
		cn_pci_reg_write32(pcie_set, DSHARE_ACCESS(phy_channel), 0);

		__sync_fetch_and_and(&pcie_set->channel_run_flag,
					~(1 << phy_channel));

		if (!pcie_set->running_channels) {
			cn_dev_pcie_err(pcie_set,
				"running channels is NULL");
			return IRQ_HANDLED;
		}
		channel = (struct dma_channel_info *)
			pcie_set->running_channels[phy_channel];
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
			/*
			 * fix bug: d2h-dma error interrupt with poison TLP make MCE Error
			 * use MDR memory do D2H copy, to rewrite Host memory
			 *
			 * Bit [8]: Data reading failed due to Completion Timeout
			 * Bit [9]: Data reading failed due to UR received if on PCIe
			 * domain, or DECERR received if on AXI domain.
			 * Bit [10]: Data reading failed due to UR or EP received if on
			 * PCIe domain, or SLVERR response received if on AXI
			 * domain.
			 * Bit [11]: Data reading failed due to ECRC received if on PCIe
			 * domain, PCIe Controller or Bridge Memory Error; or Data
			 * error reported by the AXI Application if on AXI domain.
			 */
			status = cn_pci_reg_read32(pcie_set, DBO + 0x40 * phy_channel + 0x20);
			cn_dev_pcie_err(pcie_set, "DMA%d [0x20] status:0x%x",
							phy_channel, status);

			ret = 1;
			if ((channel->direction == DMA_D2H) && (status & 0xf00)) {
				ret = workaround_for_d2h_with_poison_TLP(channel, pcie_set, phy_channel);
			}

			if (ret) {
				cn_pci_dma_complete(phy_channel, CHANNEL_COMPLETED_ERR, pcie_set);
			}
		} else {
			if (pcie_set->dma_err_inject_flag) {
				pcie_set->dma_err_inject_flag = 0;
				cn_dev_pcie_err(pcie_set, "DMA interrupt error status: Fake Manual Error.");
				cn_pci_dma_complete(phy_channel, CHANNEL_COMPLETED_ERR, pcie_set);
			} else {
				cn_pci_dma_complete(phy_channel, CHANNEL_COMPLETED, pcie_set);
			}
		}

		if (channel->direction == DMA_H2D)
			atomic_dec(&pcie_set->inbound_count);
	}

	cn_pci_task_fair_schedule(pcie_set);
	return IRQ_HANDLED;
}

static int pci_hw_msix_enable(struct cn_pcie_set *pcie_set)
{
	unsigned int atr_size = 19;//1 MBytes(0x100000)
	unsigned int value = 0;

	/* PCIE send axi slave address for msix*/
	cn_pci_reg_write32(pcie_set, SLV0_SRC_ADDRU(0), value);
	value |= (atr_size << 1) | (1 << 0);
	cn_pci_reg_write32(pcie_set, SLV0_SRC_ADDRL(0), value);

	/* outbound address*/
	value = 0;
	cn_pci_reg_write32(pcie_set, SLV0_TRSL_ADDRU(0), value);
	value |= (0xFEE << 20);
	cn_pci_reg_write32(pcie_set, SLV0_TRSL_ADDRL(0), value);

	/* param*/
	value = 0;
	cn_pci_reg_write32(pcie_set, SLV0_TRSL_PARAM(0), value);

	/* mask*/
	cn_pci_reg_write32(pcie_set, SLV0_TRSL_MASKU(0), 0xFFFFFFFF);
	cn_pci_reg_write32(pcie_set, SLV0_TRSL_MASKL(0), 0xFFF00000);

	/* set msix vector count(16)*/
	value = cn_pci_reg_read32(pcie_set, GIC_MSIX_VECTOR_COUNT);
	value |= (~0x7U);
	cn_pci_reg_write32(pcie_set, GIC_MSIX_VECTOR_COUNT, value);

	/* enable msix*/
	cn_pci_reg_write32(pcie_set, GIC_CTRL, GIC_ENABLE_MSIX_BIT | GIC_OPEN_GI_BIT);
	value = cn_pci_reg_read32(pcie_set, GIC_CTRL);

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
	cn_dev_info("no dump function, please add in private file");
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
	spin_lock(&pcie_set->interrupt_lock);

	for (vector_index = 0; vector_index < MSIX_COUNT; vector_index++) {
		if (entry[vector_index].vector == irq)
			break;
	}

	if (vector_index >= MSIX_COUNT) {
		cn_dev_pcie_err(pcie_set, "Recv error interrupt:%d", irq);
		spin_unlock(&pcie_set->interrupt_lock);
		return IRQ_HANDLED;
	}

#if (GIC_INTERRUPT_NUM != MSIX_COUNT)
	irq_start = (vector_index == 0) ? 0 :
				(irq_msix_gic_end[vector_index - 1] + 1);
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

	offsize = (vector_index / 32) * 4;
	value = cn_pci_reg_read32(pcie_set, GIC_MSIX_PEND_CLR + offsize);
	value |= (1UL << (vector_index % 32));
	cn_pci_reg_write32(pcie_set, GIC_MSIX_PEND_CLR + offsize, value);
	value &= (~(1Ul << (vector_index % 32)));
	cn_pci_reg_write32(pcie_set, GIC_MSIX_PEND_CLR + offsize, value);
	cn_pci_reg_read32(pcie_set, GIC_MSIX_PEND_CLR + offsize);
	spin_unlock(&pcie_set->interrupt_lock);

	return IRQ_HANDLED;
}

static irqreturn_t msi_interrupt(int irq, void *data)
{
	u64 gic_status = 0;
	u64 gic_mask = 0;
	u32 msi_mask = 0;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct msix_entry *entry;
	int irq_start, irq_end;
	int vector_index;

	entry = (struct msix_entry *)pcie_set->msix_entry_buf;
	spin_lock(&pcie_set->interrupt_lock);

	vector_index = irq - pcie_set->irq;

	if (vector_index >= MSI_COUNT) {
		cn_dev_pcie_err(pcie_set, "recv error interrupt:%d", irq);
		spin_unlock(&pcie_set->interrupt_lock);
		return IRQ_HANDLED;
	}
	msi_mask = cn_pci_reg_read32(pcie_set, PCI_CONFIG_MSI_MASK);
	msi_mask |= (0x1 << vector_index);
	cn_pci_reg_write32(pcie_set, PCI_CONFIG_MSI_MASK, msi_mask);

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
	msi_mask = cn_pci_reg_read32(pcie_set, PCI_CONFIG_MSI_MASK);
	msi_mask &= (~(0x1 << vector_index));
	cn_pci_reg_write32(pcie_set, PCI_CONFIG_MSI_MASK, msi_mask);
	spin_unlock(&pcie_set->interrupt_lock);

	return IRQ_HANDLED;
}

static irqreturn_t intx_interrupt(int irq, void *data)
{
	u64 gic_status = 0;
	u64 gic_mask = 0;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;

	spin_lock(&pcie_set->interrupt_lock);

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

	spin_unlock(&pcie_set->interrupt_lock);

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

static int pcie_dma_align(struct transfer_s *t, size_t *head, size_t *tail)
{
	return 0;
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

	if (channel->direction == DMA_H2D) {
		if (!atomic_add_unless(&pcie_set->inbound_count, 1,
				pcie_set->max_inbound_cnt))
			return -1;
	}

	switch (channel->direction) {
	case DMA_P2P:
	case DMA_H2D:
		cn_pci_reg_write32(pcie_set,
			DSRC_PARAM(channel_id), DMA_PCIE_PARAM);
		cn_pci_reg_write32(pcie_set,
			DDEST_PARAM(channel_id), DMA_AXI_PARAM);
		break;
	case DMA_D2H:
		cn_pci_reg_write32(pcie_set,
			DSRC_PARAM(channel_id), DMA_AXI_PARAM);
		cn_pci_reg_write32(pcie_set,
			DDEST_PARAM(channel_id), DMA_PCIE_PARAM);
		break;

	default:
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

	outbound_mem = pcie_set->share_priv;
	if ((!outbound_mem) || (!pcie_set->share_mem_pages))
		return;

	for_each_set_bit(outbound_index, (unsigned long *)&pcie_set->ob_mask,
		sizeof(pcie_set->ob_mask) * 8) {
		/* outbound pci address */
		cn_pci_reg_write64(pcie_set, SLV0_TRSL_ADDRL(outbound_index),
						(outbound_mem[i].pci_addr));
		/* axi address */
		value = (pcie_set->ob_size * outbound_index) |
					((OUTBOUND_POWER - 1) << 1) | (1 << 0);
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
		cn_pci_reg_read64(pcie_set, SLV0_TRSL_MASKL(outbound_index));
		cn_dev_debug("outbound:%d virtual_addr:%px pci_addr:%#llx i:%d",
				outbound_index, outbound_mem[i].virt_addr,
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
		cn_dev_err("kzalloc share_mem_pages error");
		return -1;
	}

	outbound_mem = cn_kzalloc(pcie_set->ob_cnt *
				sizeof(struct outbound_mem), GFP_KERNEL);
	if (!outbound_mem) {
		cn_dev_err("kzalloc outbound_mem error");
		goto ERROR_RET;
	}
	pcie_set->share_priv = (void *)outbound_mem;

	for (i = 0; i < pcie_set->ob_cnt; i++) {
		outbound_mem[i].virt_addr =
				dma_alloc_coherent(&pcie_set->pdev->dev,
				pcie_set->ob_size, &(outbound_mem[i].pci_addr),
				GFP_KERNEL | __GFP_NOWARN);
		if (!outbound_mem[i].virt_addr) {
			cn_dev_err("dma_alloc_coherent error:%d", i);
			goto ERROR_RET;
		}

		if (outbound_mem[i].pci_addr&(pcie_set->ob_size - 1)) {
			cn_dev_err("dma_alloc_coherent not align:%llx",
				outbound_mem[i].pci_addr);
			goto ERROR_RET;
		}
	}

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

#if  defined(__x86_64__)
	pcie_set->share_mem[index].virt_addr = cn_vm_map_ram(
		pcie_set->share_mem_pages, page_index, -1, PAGE_KERNEL_NOCACHE);
#else
	pcie_set->share_mem[index].virt_addr = cn_vm_map_ram(
		pcie_set->share_mem_pages, page_index, -1, PAGE_KERNEL);
#endif
	if (!pcie_set->share_mem[index].virt_addr) {
		cn_dev_err("vm_map_ram error");
		goto ERROR_RET;
	}

	cn_dev_info("host share mem virtual addr:%px",
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

static int cn_pci_link_set(void *pcie_priv, bool enable)
{
	u16 lnk_ctrl;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)pcie_priv;
	struct pci_dev *pdev = pcie_set->pdev->bus->self;

	pcie_capability_read_word(pdev, PCI_EXP_LNKCTL, &lnk_ctrl);
	if (enable)
		lnk_ctrl &= ~PCI_EXP_LNKCTL_LD;
	else
		lnk_ctrl |= PCI_EXP_LNKCTL_LD;
	pcie_capability_write_word(pdev, PCI_EXP_LNKCTL, lnk_ctrl);

	cn_dev_info("lnk_ctrl = 0x%x", lnk_ctrl);
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

static int pcie_ddr_set_done(struct cn_pcie_set *pcie_set)
{
	return 0;
}

static int pcie_enable_pf_bar(struct cn_pcie_set *pcie_set)
{
	int index;
	u64 base, sz;
	struct bar_resource bar, *new;
	struct pci_dev *pdev = pcie_set->pdev;

	for (index = 2; index < 6; index++) {
		sz = pci_resource_len(pdev, index);
		if (!sz)
			continue;
		base = pci_resource_start(pdev, index);

		memset(&bar, 0, sizeof(bar));
		bar.type = PF_BAR;
		bar.index = index;
		bar.phy_base = base;
		bar.bus_base = cn_pci_bus_address(pdev, index);
		bar.size = sz;
		bar.reg_index = pf_table[index / 2 - 1].reg;
		bar.reg_mask = pf_table[index / 2 - 1].mask;
		bar.smmu_in = index / 2 * 2;
		bar.smmu_out = index / 2 * 2 - 1;

		new = pcie_bar_resource_struct_init(&bar);
		if (new)
			list_add_tail(&new->list, &pcie_set->bar_resource_head);
	}

	return 0;
}

static int pcie_dma_bypass_size(struct cn_pcie_set *pcie_set)
{
#if defined(__x86_64__)
	pcie_set->dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 256 * 1024;
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
	.set_bar_window = pcie_set_bar_window,
	.intx_isr = intx_interrupt,
	.msi_isr = msi_interrupt,
	.msix_isr = msix_interrupt,
	.isr_hw_enable = pci_isr_hw_enable,
	.isr_hw_disable = pci_isr_hw_disable,
	.gic_mask = pcie_gic_mask,
	.gic_unmask = pcie_gic_unmask,
	.gic_mask_all = pcie_gic_mask_all,
	.get_irq_by_desc = pcie_get_irq,
	.dma_align = pcie_dma_align,
	.dma_bypass_size = pcie_dma_bypass_size,
	.dma_go_command = pcie_dma_go,
	.soft_reset = pcie_soft_reset,
	.ddr_set_done = pcie_ddr_set_done,
	.bar_write = mlu290_ce3226_pcie_bar_write,
	.bar_read = mlu290_ce3226_pcie_bar_read,
	.enable_pf_bar = pcie_enable_pf_bar,
	.async_dma_fill_desc_list = pcie_async_dma_fill_desc_list,
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
	cn_dev_info("ob_cnt:%d ob_size:0x%x ob_total_size:%x ob_axi_addr:%llx",
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

static int pcie_bar_init(struct cn_pcie_set *pcie_set,
				u64 bar0_mem_offset, u64 bar0_mem_size)
{
	struct pcibar_seg_s *p_bar_seg;
	struct pcibar_s *p_bar;

	/* Init bar 0 */
	p_bar = &pcie_set->pcibar[0];

	/* the register area */
	p_bar_seg = &p_bar->seg[0];
	p_bar_seg->size = p_bar->size / 2;
	p_bar_seg->base = p_bar->base;
	p_bar_seg->virt = cn_ioremap(p_bar_seg->base, p_bar_seg->size);
	if (!p_bar_seg->virt)
		goto ERROR_RET;
	cn_dev_debug("bar0 register virt:%p", p_bar_seg->virt);

	pcie_set->reg_virt_base = p_bar_seg->virt;
	pcie_set->reg_phy_addr = p_bar_seg->base;
	pcie_set->reg_win_length = p_bar_seg->size;

	/* the bar share memory */
	p_bar_seg = &p_bar->seg[1];
	p_bar_seg->base = p_bar->base + pcie_set->reg_win_length;
	p_bar_seg->size = p_bar->size - pcie_set->reg_win_length;
	p_bar_seg->virt = cn_ioremap_wc(p_bar_seg->base, p_bar_seg->size);
	if (!p_bar_seg->virt)
		goto ERROR_RET;
	cn_dev_debug("bar0 memory virt:%p", p_bar_seg->virt);

	pcie_set->share_mem_cnt = 1;
	pcie_set->share_mem[0].virt_addr =
		pcie_set->pcibar[0].seg[1].virt + bar0_mem_offset;
	pcie_set->share_mem[0].phy_addr =
		pcie_set->pcibar[0].seg[1].base + bar0_mem_offset;
	pcie_set->share_mem[0].win_length = bar0_mem_size;
	pcie_set->share_mem[0].type = CN_SHARE_MEM_DEV;
	pcie_set->share_mem[0].device_addr = -1;

	return 0;

ERROR_RET:
	cn_dev_err("pcie bar init error");
	bar_deinit(pcie_set);

	return -1;
}

static void set_bar_default_window(struct cn_pcie_set *pcie_set)
{
	struct bar_resource *bar;

	list_for_each_entry(bar, &pcie_set->bar_resource_head, list) {
		bar->window_addr = 0;
		cn_pci_reg_write64(pcie_set, bar->reg_index, bar->reg_mask);
		cn_pci_reg_read32(pcie_set, bar->reg_index);
	}
}

static int do_pcie_init(struct cn_pcie_set *pcie_set)
{
	int ret;

	if (!cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		pcie_set->outbound_able = 1;
		ret = pcie_outbound_init(pcie_set);
		if (ret) {
			pcie_set->outbound_able = 0;
		}
	}

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
