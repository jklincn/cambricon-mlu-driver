#include "cndrv_debug.h"
/*dma command descriptor size*/
#define DESC_SIZE                            (64)

#define DMA_CHANNEL_REG_SIZE        (0x14)

	/*PCIe DMA Channel n Control Register*/
#define DCTRL(channel_id)    \
		(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x000)

	/*PCIe DMA Channel n Start Pointer Lower Register*/
#define DSPL(channel_id)    \
		(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x004)

	/*PCIe DMA Channel n Start Pointer Upper Register*/
#define DSPU(channel_id)    \
		(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x008)

	/*PCIe DMA Channel n Attribute Lower Register*/
#define DAL(channel_id)    \
		(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x00c)

	/*PCIe DMA Channel n Attribute Upper Register*/
#define DAU(channel_id)    \
		(DBO + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x010)

#define DI	(DBO+0x0a0)/*PCIe DMA Interrupt Register*/
#define DIE	(DBO+0x0a4)/*PCIe DMA Interrupt Enable Register*/
#define DID	(DBO+0x0a8)/*PCIe DMA Interrupt Disable Register*/
#define DIBUcEE	(DBO+0x0ac)/*PCIe DMA Inbound Buffer Uncorrected ECC Errors*/
#define DIBcEE	(DBO+0x0b0)/*PCIe DMA Inbound Buffer corrected ECC Errors*/
#define DOBUcEE	(DBO+0x0b4)/*PCIe DMA Outbound Buffer Uncorrected ECC Errors*/
#define DOBcEE	(DBO+0x0b8)/*PCIe DMA Outbound Buffer corrected ECC Errors*/
#define DCV	(DBO+0x0f8)/*PCIe DMA Capability and Version Register*/
#define DCFG	(DBO+0x0fc)/*PCIe DMA Configuration Register*/
#define DEO	(0UL)	/*dma command descriptor offset*/

	/*AXI Base Address offset Lower offset in descriptor.this is bar0/bar4 address*/
#define DE_ABAL                 (DEO+0)
	/*AXI Base Address offset Upper offset in descriptor.this is bar0/bar4 address*/
#define DE_ABAU	                (DEO+4)
	/*AXI Address Phase(AR or AW) control*/
#define DE_ADP                  (DEO+8)
	/*PCIe Base Address offset Lower offset in descriptor.
	 *this is cpu dma phy address
	 */
#define DE_PBAL	                (DEO+12)
	/*PCIe Base Address offset Upper offset
	 *in descriptor.this is cpu dma phy address
	 */
#define DE_PBAU	                (DEO+16)
	/*PCIe Lower offset in TLP header attributes */
#define DE_TLP_HEAD_ATTRL       (DEO+20)
	/*PCIe Upper offset in TLP header attributes */
#define DE_TLP_HEAD_ATTRU       (DEO+24)
	/* Length of transfer in bytes
	 * (0indicates maximum length transfer 2^24 bytes).
	 */
#define DE_LC        (DEO+28)
	/*bus status in descriptor.*/
#define DE_BS        (DEO+32)
	/*Next Descriptor Lower address*/
#define DE_NDL       (DEO+36)
	/*Next Descriptor Upper address*/
#define DE_NDU       (DEO+40)


#define LENGTH_CTRL(len, is_continue, is_interrupt) \
	((unsigned int)((len & 0xFFFFFF) | ((is_continue << 5 | is_interrupt) \
			<< 24)))

static void pcie_show_desc_list(struct dma_channel_info *channel);
static int adjust_dev_param(struct cn_pcie_set *pcie_set);
static int pci_hw_msi_enable(struct cn_pcie_set *pcie_set);
static int pci_hw_msix_enable(struct cn_pcie_set *pcie_set);
static int pci_hw_intx_enable(struct cn_pcie_set *pcie_set);
static int pci_hw_msi_disable(struct cn_pcie_set *pcie_set);
static int pci_hw_msix_disable(struct cn_pcie_set *pcie_set);
static int pci_hw_intx_disable(struct cn_pcie_set *pcie_set);

struct outbound_mem {
	void *virt_addr;
	dma_addr_t pci_addr;
};

static int (*isr_hw_enable[3])(struct cn_pcie_set *) = {
	pci_hw_msi_enable,
	pci_hw_msix_enable,
	pci_hw_intx_enable
};

static int (*isr_hw_disable[3])(struct cn_pcie_set *) = {
	pci_hw_msi_disable,
	pci_hw_msix_disable,
	pci_hw_intx_disable
};

static irqreturn_t pcie_dma_interrupt_handle(int index, void *data)
{
	unsigned int status;
	unsigned int channel_bit;
	unsigned int channel_mask;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct dma_channel_info *channel;

	/*
	 *  do all dma task in one interrupt, set do_dma_irq_status 1
	 *  other interrupt just return, no need to read/write DI
	 */
	if (pcie_set->do_dma_irq_status == 0)
		pcie_set->do_dma_irq_status = 1;
	else
		return IRQ_HANDLED;

	/*
	 * read dma interrupt register to get whitch channel generate interrupt.
	 * This interrupt may be done or error.not is done and error.
	 */
	status = cn_pci_reg_read32(pcie_set, DI);
	if (!status)
		return 0;

	if (cn_is_mim_en_bdf(pcie_set->bdf, pcie_set->pdev->is_virtfn)) {
		channel_mask = pcie_set->dma_phy_channel_mask;
		channel_mask |= (channel_mask << DMA_REG_CHANNEL_NUM);
		status &= channel_mask;
	}

	cn_pci_reg_write32(pcie_set, DI, status);

	channel_bit = (1 | (1 << DMA_REG_CHANNEL_NUM));
	for (i = 0; i < DMA_MAX_PHY_CHANNEL; i++, (channel_bit <<= 1)) {
		if (!(status & channel_bit))
			continue;

		__sync_fetch_and_and(&pcie_set->channel_run_flag, ~(1 << i));

		channel = (struct dma_channel_info *)
			pcie_set->running_channels[i];
		if (!channel) {
			cn_dev_pcie_err(pcie_set, "phy_channel:%d is NULL", i);
			continue;
		}

		if ((status & channel_bit) &
				(MAX_PHY_CHANNEL_MASK << DMA_REG_CHANNEL_NUM)) {
			cn_pci_dma_complete(i, CHANNEL_COMPLETED_ERR, pcie_set);
			cn_dev_pcie_err(pcie_set, "DMA interrupt error status:0x%x", status);
			if (pcie_set->ops->dump_reg)
				pcie_set->ops->dump_reg(pcie_set);
			pcie_show_desc_list(channel);
		} else {
			if (pcie_set->dma_err_inject_flag) {
				pcie_set->dma_err_inject_flag = 0;
				cn_dev_pcie_err(pcie_set, "DMA interrupt error status: Fake Manual Error.");
				cn_pci_dma_complete(i, CHANNEL_COMPLETED_ERR, pcie_set);
			} else {
				cn_pci_dma_complete(i, CHANNEL_COMPLETED, pcie_set);
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
	unsigned int pos, msi_addr_l, msi_addr_u, msi_ctrl;
	unsigned int value;
	/*set msi pending status in module select bit to update the msi pending status.*/
	value = cn_pci_reg_read32(pcie_set, DMCR);
	value |= (1 << MSI_PENDING_STATUS_SHIFT);
	cn_pci_reg_write32(pcie_set, DMCR, value);

	pos = pci_find_capability(pcie_set->pdev, PCI_CAP_ID_MSI);
	pci_read_config_dword(pcie_set->pdev, pos, &msi_ctrl);
	if (msi_ctrl & MSI_ADDR_IS_64) {
		/*
		 *config gic register.
		 *
		 * pcie send interrupt to gic ,then gic sendd addd to noc .
		 * noc only reserve low 20 bit ,other bit clear,then send to
		 * pcie region.according this address to match whitch region,
		 * then according to this region config to generate msi addr.
		 */
		/*PCIE send axi slave address for msi*/
		cn_pci_reg_write32(pcie_set, GIC_MSIX_ADDR_U, ALL_CFG_UPPER_ADDR);

		for (pos = 0; pos < 1; pos++) {
			/*msix address is 64 bit*/
			msi_addr_l = cn_pci_reg_read32(pcie_set, GBO + pos * 4);
			msi_addr_u = cn_pci_reg_read32(pcie_set, GBO + pos * 4 + 4);
			cn_dev_info("MSK_ADDR_L:%#x", msi_addr_l);
			cn_dev_info("MSK_ADDR_u:%#x", msi_addr_u);

			/*
			 * outbound address
			 */
			value = msi_addr_l;
			value &= (~0xff);
			value |= 0x17;
			cn_dev_info("%#x", value);
			cn_pci_reg_write32(pcie_set, A2P_ADDR_REG_0(0), value);
			cn_pci_reg_write32(pcie_set, A2P_ADDR_REG_1(0), msi_addr_u);
		}

		/*
		 *mem region
		 */
		cn_pci_reg_write32(pcie_set, OB_PCIE_DESC_REG_1(0), 0X2);

		/*
		 *enter address
		 *0~256
		 */
		value = (0x17);
		cn_pci_reg_write32(pcie_set, AXI_REGION_BASE_REG_0(0), value/*0X7*/);
		cn_pci_reg_write32(pcie_set, AXI_REGION_BASE_REG_1(0), ALL_CFG_UPPER_ADDR);

	} else {
		cn_dev_err("can not come true after to write.");
	}

	/*read a reg is important.*/
	/*why to read register , please see bugzilla id :167*/
	cn_pci_reg_read32(pcie_set, AXI_REGION_BASE_REG_1(0));
	cn_pci_reg_write32(pcie_set, GIC_CTRL, GIC_ENABLE_MSIX_BIT | GIC_OPEN_GI_BIT);

	cn_pci_reg_write32(pcie_set, GIC_MSIX_GROUP_MASK, 0);
	cn_pci_reg_write32(pcie_set, GIC_MSIX_ENABLE, 1);
	cn_pci_reg_write32(pcie_set, GIC_MSIX_VECTOR_COUNT, (MSIX_COUNT == GIC_INTERRUPT_NUM)?5:0);

	return 0;
}


static int pci_hw_msix_disable(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, GIC_CTRL, 0);
	return 0;
}

static int pci_hw_msi_enable(struct cn_pcie_set *pcie_set)
{
	unsigned int pos, msi_addr_l, msi_addr_u, msi_ctrl, msi_data;
	unsigned int value;
	/*set msi pending status in module select bit to update the msi pending status.*/
	value = cn_pci_reg_read32(pcie_set, DMCR);
	value |= (1 << MSI_PENDING_STATUS_SHIFT);
	cn_pci_reg_write32(pcie_set, DMCR, value);

	cn_pci_reg_read32(pcie_set, GIC_MSI_CLR);
	cn_pci_reg_write32(pcie_set, GIC_MSI_CLR, 0x1);
	cn_pci_reg_read32(pcie_set, GIC_MSI_CLR);

	pos = pci_find_capability(pcie_set->pdev, PCI_CAP_ID_MSI);
	pci_read_config_dword(pcie_set->pdev, pos, &msi_ctrl);
	if (msi_ctrl & MSI_ADDR_IS_64) {
		/*msi address is 64 bit*/
		pci_read_config_dword(pcie_set->pdev, pos + 0x4, &msi_addr_l);
		pci_read_config_dword(pcie_set->pdev, pos + 0x8, &msi_addr_u);
		pci_read_config_dword(pcie_set->pdev, pos + 0xc, &msi_data);
		cn_dev_debug("MSK_ADDR_L:%#x", msi_addr_l);
		cn_dev_debug("MSK_ADDR_u:%#x", msi_addr_u);
		cn_dev_debug("MSK_data:%#x", msi_data);

		/*
		 *config gic register.
		 *
		 * pcie send interrupt to gic ,then gic sendd addd to noc .
		 * noc only reserve low 20 bit ,other bit clear,then send to
		 * pcie region.according this address to match whitch region,
		 * then according to this region config to generate msi addr.
		 */
		/*PCIE send axi slave address for msi*/
		cn_pci_reg_write32(pcie_set, GIC_MSI_ADDR_U, 0x82);
		value = PCIE_MEM_BASE | (msi_addr_l & 0xFFFFF);
		cn_pci_reg_write32(pcie_set, GIC_MSI_ADDR_L, value);
		cn_pci_reg_write32(pcie_set, GIC_MSI_DATA, msi_data);
		/*
		 *config pci region 0
		 */

		/*
		 * outbound address
		 */
		value = msi_addr_l;
		value &= (~0xfffff);
		value |= 0x1f;
		cn_dev_info("%#x", value);
		cn_pci_reg_write32(pcie_set, A2P_ADDR_REG_0(0), value);
		cn_pci_reg_write32(pcie_set, A2P_ADDR_REG_1(0), msi_addr_u);

		/*
		 *mem region
		 */
		cn_pci_reg_write32(pcie_set, OB_PCIE_DESC_REG_1(0), 0X2);

		/*
		 *enter address
		 *0~256
		 */
		value = (PCIE_MEM_BASE | 0x1f);
		cn_pci_reg_write32(pcie_set, AXI_REGION_BASE_REG_0(0), value/*0X7*/);
		cn_pci_reg_write32(pcie_set, AXI_REGION_BASE_REG_1(0), 0x82);

	} else {
		cn_dev_err("can not come true after to write.");
	}

	/* read a reg is important. */
	/* why to read register , please see bugzilla id :167 */
	cn_pci_reg_read32(pcie_set, AXI_REGION_BASE_REG_1(0));
	cn_pci_reg_write32(pcie_set, GIC_CTRL, GIC_ENABLE_MSI_BIT|GIC_OPEN_GI_BIT);

	cn_pci_reg_write32(pcie_set, GIC_MSI_VECTOR_COUNT, MSI_COUNT_POWER);

	return 0;
}

static int pci_hw_msi_disable(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, GIC_CTRL, 0);
	return 0;
}

static int pci_hw_intx_enable(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, GIC_CTRL, GIC_ENABLE_INTX_BIT | GIC_OPEN_GI_BIT);
	return 0;
}

static int pci_hw_intx_disable(struct cn_pcie_set *pcie_set)
{
	cn_pci_reg_write32(pcie_set, GIC_CTRL, 0);
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



#if  defined(__x86_64__)
#define FILL_DESC(ram_addr, cpu_addr, len_ctrl, desc_offset,\
		channel) \
{ \
	*((u64 *)(channel->task->desc_buf + desc_offset + DE_ABAL)) = ram_addr; \
	*((u64 *)(channel->task->desc_buf + desc_offset + DE_PBAL)) = cpu_addr; \
	*((u32 *)(channel->task->desc_buf + desc_offset + DE_LC)) = len_ctrl; \
}
#else
#define FILL_DESC(ram_addr, cpu_addr, len_ctrl, desc_offset,\
		channel) \
{ \
	*((u64 *)(channel->task->desc_buf + desc_offset + DE_ABAL)) = ram_addr; \
	*((u32 *)(channel->task->desc_buf + desc_offset + DE_PBAL)) = cpu_addr; \
	*((u32 *)(channel->task->desc_buf + desc_offset + DE_PBAL + 4)) = \
		(unsigned int)(cpu_addr>>32); \
	*((u32 *)(channel->task->desc_buf + desc_offset + DE_LC)) = len_ctrl;\
}
#endif

static void pcie_show_desc_list(struct dma_channel_info *channel)
{
	int desc_offset = 0;

	cn_dev_err("transfer_len:%ld desc_len:%d",
			channel->transfer_length, channel->desc_len);

	for (; desc_offset < channel->desc_len; desc_offset += DESC_SIZE) {
		pr_err(
			"%#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x %#08x\n",
			ioread32(channel->desc_virt_base + desc_offset + 0),
			ioread32(channel->desc_virt_base + desc_offset + 4),
			ioread32(channel->desc_virt_base + desc_offset + 8),
			ioread32(channel->desc_virt_base + desc_offset + 12),
			ioread32(channel->desc_virt_base + desc_offset + 16),
			ioread32(channel->desc_virt_base + desc_offset + 20),
			ioread32(channel->desc_virt_base + desc_offset + 24),
			ioread32(channel->desc_virt_base + desc_offset + 28),
			ioread32(channel->desc_virt_base + desc_offset + 32),
			ioread32(channel->desc_virt_base + desc_offset + 36),
			ioread32(channel->desc_virt_base + desc_offset + 40));
	}
}

struct pcie_dump_reg_s {
	char *desc;
	unsigned long reg;
};

static inline void do_irq(struct cn_pcie_set *pcie_set,
						u64 status, u64 mask, int i)
{
	int index;
	int handler_num;
	u64 start, end;

	/*
	 *  do all dma task in one interrupt, set dma_ire_done 1
	 *  other interrupt just return, no need to read/write DI
	 */
	pcie_set->do_dma_irq_status = 0;

	status &= (~mask);
	while (status) {
		index = __ffs(status);
		status &= ~(1ULL << index);
		index += (i * 64);
		handler_num = 0;

		pcie_set->irq_desc[index].occur_count++;

		do {
			if (pcie_set->irq_desc[index].handler[handler_num] == NULL) {
				cn_dev_pcie_err(pcie_set, "no interrupt handle!:%llx %x",
						status, index);
				break;
			}
			start = get_jiffies_64();
			if (pcie_set->irq_desc[index].handler[handler_num](index,
				pcie_set->irq_desc[index].data[handler_num]) == IRQ_HANDLED) {
				end = get_jiffies_64();

				if (time_after64(end, start + HZ / 2))
					cn_dev_pcie_warn(pcie_set,
						"do interrupt%d spend too long time(%dms)!!!",
						index, jiffies_to_msecs(end - start));
				break;
			}
			handler_num++;
		} while (handler_num < IRQ_SHARED_NUM);

		if (handler_num == IRQ_SHARED_NUM)
			cn_dev_pcie_err(pcie_set, "no interrupt handle!:%llx %x",
						status, index);
	}
	pcie_set->do_dma_irq_status = 0;
}

static irqreturn_t msix_interrupt(int irq, void *data)
{
	u64 status;
	u64 mask;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct msix_entry* entry;
	int irq_start, irq_end;
	int vector_index;

	entry = (struct msix_entry*)pcie_set->msix_entry_buf;
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
	irq_start = (vector_index == 0) ? 0 : (irq_msix_gic_end[vector_index - 1] + 1);
	irq_end = irq_msix_gic_end[vector_index];
#else
	irq_start = irq_end = vector_index;
#endif

	for (i = (irq_start / 64); i <= (irq_end / 64); i++) {
		mask = pcie_set->gic_mask[i];
		if (mask == -1ULL)
			continue;

		if (i == irq_start / 64)
			mask |= ((1UL << (irq_start % 64)) - 1);

		if (i == irq_end / 64 && (irq_end % 64) != 63)
			mask |= (~((1UL << ((irq_end + 1) % 64)) - 1));

		status = cn_pci_reg_read64(pcie_set, GIC_STATUS + i * 8);
		if (status != -1ULL)
			do_irq(pcie_set, status, mask, i);
	}

	cn_pci_reg_read32(pcie_set, GIC_MSIX_CLR);
	cn_pci_reg_write32(pcie_set, GIC_MSIX_CLR + (vector_index / 32) * 4,
		(1UL << (vector_index % 32)));
	cn_pci_reg_read32(pcie_set, GIC_MSIX_CLR);
	spin_unlock(&pcie_set->interrupt_lock);

	return IRQ_HANDLED;
}

static irqreturn_t msi_interrupt(int irq, void *data)
{
	u64 status;
	u64 mask;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct msix_entry* entry;
	int irq_start, irq_end;
	int vector_index;

	entry = (struct msix_entry*)pcie_set->msix_entry_buf;
	spin_lock(&pcie_set->interrupt_lock);

	vector_index = irq - pcie_set->irq;

	if (vector_index >= MSI_COUNT) {
		cn_dev_pcie_err(pcie_set, "Recv error interrupt:%d", irq);
		spin_unlock(&pcie_set->interrupt_lock);
		return IRQ_HANDLED;
	}

	irq_start = (vector_index == 0) ? 0:(irq_msi_gic_end[vector_index - 1] + 1);
	irq_end = irq_msi_gic_end[vector_index];

	for (i = (irq_start / 64); i <= (irq_end / 64); i++) {
		mask = pcie_set->gic_mask[i];
		if (mask == -1ULL)
			continue;
		if (i == irq_start / 64)
			mask |= ((1UL << (irq_start % 64)) - 1);

		if (i == irq_end / 64 && (irq_end % 64) != 63)
			mask |= (~((1UL << ((irq_end + 1) % 64)) - 1));

		status = cn_pci_reg_read64(pcie_set, GIC_STATUS + i * 8);
		if (status != -1ULL)
			do_irq(pcie_set, status, mask, i);
	}

	/* why to read register?, please see bugzilla id :167 */
	cn_pci_reg_read32(pcie_set, GIC_MSI_CLR);
	cn_pci_reg_write32(pcie_set, GIC_MSI_CLR, 0x1 << vector_index);
	cn_pci_reg_read32(pcie_set, GIC_MSI_CLR);
	spin_unlock(&pcie_set->interrupt_lock);

	return IRQ_HANDLED;
}

static irqreturn_t intx_interrupt(int irq, void *data)
{
	u64 status;
	u64 mask;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;

	spin_lock(&pcie_set->interrupt_lock);

	for (i = 0; i < (GIC_INTERRUPT_NUM / 64); i++) {
		mask = pcie_set->gic_mask[i];
		if (mask == -1ULL)
			continue;

		status = cn_pci_reg_read64(pcie_set, GIC_STATUS + i * 8);
		if (status != -1ULL)
			do_irq(pcie_set, status, mask, i);
	}

	/* read data to make sure interrupt source had been clear. */
	/* why to read register , please see bugzilla id :167 */
	cn_pci_reg_read32(pcie_set, SIDEBAND(1));/*flush*/
	/*clear sideband*/
	cn_pci_reg_write32(pcie_set, SIDEBAND(25), 0xFFFF);
	cn_pci_reg_read32(pcie_set, SIDEBAND(1));/*flush*/
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
	int i;

	for (i = 0; i < GIC_INTERRUPT_NUM / 64; i++) {
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
	unsigned long start_desc_addr = channel->desc_device_va;

	if (channel->status != CHANNEL_RUNNING)
		cn_dev_pcie_err(pcie_set, "channel is not locked:%d", channel->status);

	if (channel->direction == DMA_H2D) {
		if (!atomic_add_unless(&pcie_set->inbound_count, 1,
				pcie_set->max_inbound_cnt))
			return -1;
	}

	cn_pci_reg_write32(pcie_set, DSPL(phy_channel), LOWER32(start_desc_addr));
	cn_pci_reg_write32(pcie_set, DSPU(phy_channel), UPPER32(start_desc_addr));

	/*
	 * make sure start point is written in.
	 */
	cn_pci_reg_read32(pcie_set, DSPL(phy_channel));

	/*
	 * start transfer
	 */
	switch (channel->direction) {
	case DMA_P2P:
	case DMA_H2D:
		cn_pci_reg_write32(pcie_set, DCTRL(phy_channel), 0x1);
		break;

	case DMA_D2H:
		cn_pci_reg_write32(pcie_set, DCTRL(phy_channel), 0x3);
		break;

	default:
		return -1;
	}

	return 0;
}

static int pcie_init(struct cn_pcie_set *pcie_set)
{
	return 0;
}

#if 0
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
			ClearPageReserved(pcie_set->share_mem_pages[i]);
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
		cn_pci_reg_write32(pcie_set, A2P_ADDR_REG_0(outbound_index), 0);
		cn_pci_reg_write32(pcie_set, A2P_ADDR_REG_1(outbound_index), 0);
		cn_pci_reg_write32(pcie_set, OB_PCIE_DESC_REG_1(outbound_index), 0);
		cn_pci_reg_write32(pcie_set, AXI_REGION_BASE_REG_0(outbound_index), 0);
		cn_pci_reg_write32(pcie_set, AXI_REGION_BASE_REG_1(outbound_index), 0);
	}

	cn_kfree(pcie_set->share_mem_pages);
	pcie_set->share_mem_pages = NULL;
	cn_kfree(pcie_set->share_priv);
	pcie_set->share_priv = NULL;

	return 0;
}
#endif

static int pcie_pre_exit(struct cn_pcie_set *pcie_set)
{
	int i;

	if (pcie_set->irq_type == MSIX) {
		for (i = 0; i < (GIC_INTERRUPT_NUM * 4); i++)
			pcie_set->msix_ram[i] =
				cn_pci_reg_read32(pcie_set, (GBO + i * 4));
	}

	cn_dev_pcie_info(pcie_set, "pcie_exit end");

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
}

static int pcie_exit(struct cn_pcie_set *pcie_set)
{
	if (isr_disable_func[pcie_set->irq_type](pcie_set)) {
		cn_dev_pcie_err(pcie_set, "isr destroyed failed!");
		return -1;
	}

	//pcie_outbound_exit(pcie_set);
	bar_deinit(pcie_set);

	return 0;
}

static int pcie_soft_reset(struct cn_pcie_set *pcie_set)
{
	u32 val;

	val = cn_pci_reg_read32(pcie_set, PMU_SYS_RST_CTRL);
	val |= 0x00010001;
	cn_pci_reg_write32(pcie_set, PMU_SYS_RST_CTRL, val);

	return 0;
}

static int pcie_ddr_set_done(struct cn_pcie_set *pcie_set)
{
	u32 val, cnt = 120;

	val = cn_pci_reg_read32(pcie_set, MCU_BASIC_INFO);

	while (!((val >> MCU_DDRTRAINED_FLAG_SHIFT)
				& MCU_DDRTRAINED_FLAG_MASK)) {
		cn_dev_info("DDR Training Params set ......");
		mdelay(500);
		val = cn_pci_reg_read32(pcie_set, MCU_BASIC_INFO);
		if (cnt-- == 0) {
			cn_dev_info("DDR Training Params set by MCU timeout");
			return -1;
		}
	}
	cn_dev_info("DDR Training Params set by MCU Finish");
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
	.pcie_pre_exit = pcie_pre_exit,
	.pcie_init = pcie_init,
	.pcie_exit = pcie_exit,
	.show_desc_list = pcie_show_desc_list,
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
	.ddr_set_done = pcie_ddr_set_done,
	.set_bar_window = pcie_set_bar_window,
	.bar_write = mlu290_ce3226_pcie_bar_write,
	.bar_read = mlu290_ce3226_pcie_bar_read,
};

#if 0
static void pcie_outbound_reg(struct cn_pcie_set *pcie_set)
{
	int i = 0;
	int outbound_index;
	struct outbound_mem *outbound_mem;
	u32 value;

	outbound_mem = pcie_set->share_priv;
	if ((!outbound_mem) || (!pcie_set->share_mem_pages))
		return;

	for_each_set_bit(outbound_index, (unsigned long *)&pcie_set->ob_mask,
		sizeof(pcie_set->ob_mask) * 8) {
		/* outbound pci address */
		cn_pci_reg_write64(pcie_set, A2P_ADDR_REG_0(outbound_index),
			(outbound_mem[i].pci_addr & (~0xffULL)) |
				(__fls(pcie_set->ob_size) - 1));

		/* pcie descriptor */
		cn_pci_reg_write32(pcie_set, OB_PCIE_DESC_REG_1(outbound_index), 0X2);

		/* axi address */
		value = ((u32)pcie_set->ob_axi_addr + pcie_set->ob_size*i) |
			(__fls(pcie_set->ob_size) - 1);
		cn_pci_reg_write32(pcie_set, AXI_REGION_BASE_REG_0(outbound_index), value);
		cn_pci_reg_write32(pcie_set, AXI_REGION_BASE_REG_1(outbound_index),
			(u32)(pcie_set->ob_axi_addr >> 32));

		cn_dev_debug("outbound:%d virtual_addr:%px pci_addr:%llx reg:%x %x %x %x %x %x %x",
			outbound_index, outbound_mem[i].virt_addr, outbound_mem[i].pci_addr,
			cn_pci_reg_read32(pcie_set, A2P_ADDR_REG_0(outbound_index)),
			cn_pci_reg_read32(pcie_set, A2P_ADDR_REG_1(outbound_index)),
			cn_pci_reg_read32(pcie_set, OB_PCIE_DESC_REG_1(outbound_index)),
			cn_pci_reg_read32(pcie_set, OB_PCIE_DESC_REG_2(outbound_index)),
			cn_pci_reg_read32(pcie_set, OB_PCIE_DESC_REG_3(outbound_index)),
			cn_pci_reg_read32(pcie_set, AXI_REGION_BASE_REG_0(outbound_index)),
			cn_pci_reg_read32(pcie_set, AXI_REGION_BASE_REG_1(outbound_index)));

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

	pcie_set->share_mem_pages = (struct page **)cn_kzalloc(
		sizeof(struct page *) * (pcie_set->ob_total_size / PAGE_SIZE),
		GFP_KERNEL);
	if (!pcie_set->share_mem_pages) {
		cn_dev_err("kzalloc share_mem_pages error");
		return -1;
	}

	outbound_mem = (struct outbound_mem *)cn_kzalloc(
		pcie_set->ob_cnt * sizeof(struct outbound_mem), GFP_KERNEL);
	if (!outbound_mem) {
		cn_dev_err("kzalloc outbound_mem error");
		goto ERROR_RET;
	}
	pcie_set->share_priv = (void *)outbound_mem;

	for (i = 0; i < pcie_set->ob_cnt; i++) {
		outbound_mem[i].virt_addr = dma_alloc_coherent(&pcie_set->pdev->dev,
			pcie_set->ob_size, &(outbound_mem[i].pci_addr), GFP_KERNEL);
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
			pcie_set->share_mem_pages[page_index] =
				virt_to_page(outbound_mem[i].virt_addr +
					j * PAGE_SIZE);
			SetPageReserved(pcie_set->share_mem_pages[page_index]);
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
	//pcie_outbound_exit(pcie_set);
	return -1;
}
#endif

static void fill_msix_ram(struct cn_pcie_set *pcie_set)
{
	int i;

	/* NOTE: when heartbeat start pcie_set->bus_set != NULL,
	 * pcie_set->msix_ram use pcie_pre_exit() function keep value
	 */
	if (!pcie_set->bus_set)
		memset((void *)(&pcie_set->msix_ram[0]),
				0xff, sizeof(pcie_set->msix_ram));

	for (i = 0; i < (GIC_INTERRUPT_NUM * 4); i++)
		cn_pci_reg_write32(pcie_set, (GBO + i * 4),
					pcie_set->msix_ram[i]);
}

static void bug_fix_list(struct cn_pcie_set *pcie_set)
{
	return;
}

static int pcie_dma_interrupt_init(struct cn_pcie_set *pcie_set)
{
	int i;
	char src[30];
	static const int interrupt_count[] = {MSI_COUNT, MSIX_COUNT, INTX_COUNT};

	pcie_set->irq_num = interrupt_count[pcie_set->irq_type];
	pcie_gic_mask_all(pcie_set);

	/* fix msix ram bug by writing msix ram */
	if (pcie_set->irq_type == MSIX)
		fill_msix_ram(pcie_set);

	do {
		if (isr_enable_func[pcie_set->irq_type](pcie_set) == 0)
			break;

		if (pcie_set->irq_type == MSIX) {
			pcie_set->irq_type = MSI;
			pcie_set->irq_num = interrupt_count[pcie_set->irq_type];
		} else if (pcie_set->irq_type == MSI) {
			pcie_set->irq_type = INTX;
			pcie_set->irq_num = interrupt_count[pcie_set->irq_type];
		} else if (pcie_set->irq_type == INTX) {
			cn_dev_pcie_err(pcie_set, "isr init failed!");
			return -1;
		}
	} while (1);

	pcie_set->irq_str_index_ptr = irq_str_index;
	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_phy_channel_mask & (1 << i)) {
			sprintf(src, "pcie_dma%d", i);
			cn_pci_register_interrupt(
					pcie_get_irq(src, pcie_set),
					pcie_dma_interrupt_handle, pcie_set, pcie_set);
		}
	}

	return 0;
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

static int pcie_pre_init_hw(struct cn_pcie_set *pcie_set)
{
	int i;
	unsigned long flags;
	unsigned int status;
#if 0
	pcie_outbound_reg(pcie_set);
#endif
	adjust_dev_param(pcie_set);

	set_bar_default_window(pcie_set);

	isr_hw_enable[pcie_set->irq_type](pcie_set);

	pcie_gic_mask_all(pcie_set);

	/* NOTE: clear dma interrupt before enable it*/
	status = cn_pci_reg_read32(pcie_set, DI);
	cn_pci_reg_write32(pcie_set, DI, status);

	for (i = 0; i < pcie_set->max_phy_channel; i++) {
		if (pcie_set->dma_phy_channel_mask & (1 << i)) {
			spin_lock_irqsave(&pcie_set->interrupt_lock, flags);
			pcie_gic_unmask(PCIE_IRQ_DMA + i, pcie_set);
			spin_unlock_irqrestore(&pcie_set->interrupt_lock, flags);
		}
	}
	cn_pci_reg_write32(pcie_set, DIE, 0xF0F);
	cn_pci_reg_write32(pcie_set, DID, 0x0F0);

	return 0;
}

static int do_pcie_init(struct cn_pcie_set *pcie_set)
{
	int ret;
#if 0
	ret = pcie_outbound_init(pcie_set);
	if (ret)
		return -1;
#endif

	ret = pcie_dma_interrupt_init(pcie_set);
	if (ret)
		goto exit;

	ret = pcie_pre_init_hw(pcie_set);
	if (ret)
		goto exit;

	return 0;
exit:
#if 0
	pcie_outbound_exit(pcie_set);
#endif
	return -1;
}
