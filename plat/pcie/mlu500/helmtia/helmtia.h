#include "cndrv_debug.h"
#include <linux/iommu.h>

/*dma command descriptor size*/
#define DESC_SIZE		(32)
#define DEO                     (0UL) /*dma command descriptor offset*/
/*PCIE DMA Descriptor status*/
#define DE_STATUS               (DEO + 0x0)
/*PCIE DMA Descriptor control*/
#define DE_CTRL                 (DEO + 0x4)
/*Next Descriptor Lower address*/
#define DE_NDL                  (DEO + 0x8)
/*Next Descriptor Upper address*/
#define DE_NDU                  (DEO + 0xc)
/*Src Address Lower  in descriptor*/
#define DE_SRC_LOWER            (DEO + 0x10)
/*Src Address Upper  in descriptor*/
#define DE_SRC_UPPER            (DEO + 0x14)
/*Dest Address Lower  in descriptor*/
#define DE_DEST_LOWER           (DEO + 0x18)
/*Dest Address Upper  in descriptor*/
#define DE_DEST_UPPER           (DEO + 0x1c)

#define MSI_MASK                (0x10)/* fix mlutithread bug*/
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

/* reserve 8MB data_outbound for commu and ipcm*/
static void pcie_show_desc_list(struct dma_channel_info *channel);

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
	isr_hw_enable[pcie_set->irq_set.irq_type](pcie_set);
}

static void pci_isr_hw_disable(struct cn_pcie_set *pcie_set)
{
	isr_hw_disable[pcie_set->irq_set.irq_type](pcie_set);
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
					u32 gic_status, u32 gic_mask, int i)
{
	int interrupt_index;
	int handler_num;
	u64 start, end;

	gic_status &= (~gic_mask);
	while (gic_status) {
		interrupt_index = __ffs(gic_status);
		gic_status &= ~(1ULL << interrupt_index);
		interrupt_index += (i * 32);
		handler_num = 0;

		pcie_set->irq_set.irq_desc[interrupt_index].occur_count++;

		do {
			if (pcie_set->irq_set.irq_desc[interrupt_index].handler[handler_num] == NULL) {
				cn_dev_pcie_err(pcie_set, "no interrupt handle!:%#x %d",
						gic_status, interrupt_index);
				break;
			}
			start = get_jiffies_64();
			if (pcie_set->irq_set.irq_desc[interrupt_index].handler[handler_num](interrupt_index,
				pcie_set->irq_set.irq_desc[interrupt_index].data[handler_num]) == IRQ_HANDLED) {
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
			cn_dev_pcie_err(pcie_set, "no interrupt handle!:%#x %d",
						gic_status, interrupt_index);
	}
}

static irqreturn_t msix_interrupt(int irq, void *data)
{
	u32 gic_status = 0;
	u32 gic_mask = 0;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	struct msix_entry *entry;
	int irq_start, irq_end;
	int vector_index;
	u32 value;
	u32 offsize;

	entry = (struct msix_entry *)pcie_set->irq_set.msix_entry_buf;

	for (vector_index = 0; vector_index < MSIX_COUNT; vector_index++) {
		if (entry[vector_index].vector == irq)
			break;
	}

	if (vector_index >= MSIX_COUNT) {
		cn_dev_pcie_err(pcie_set, "Recv error interrupt:%d", irq);
		return IRQ_HANDLED;
	}

#if (GIC_INTERRUPT_NUM != MSIX_COUNT)
	irq_start = (vector_index == 0) ? 0 :
				(irq_msix_gic_end[vector_index - 1] + 1);
	irq_end = irq_msix_gic_end[vector_index];
#else
	irq_start = irq_end = vector_index;
#endif

	for (i = (irq_start / 32); i <= (irq_end / 32); i++) {
		gic_mask = pcie_set->irq_set.gic_mask[i];
		if (gic_mask == ~0x0)
			continue;

		gic_status = cn_pci_reg_read32(pcie_set, GIC_STATUS + i * 4);
		if (gic_status == 0x0)
			continue;

		if (i == irq_start / 32)
			gic_mask |= ((1UL << (irq_start % 32)) - 1);

		if (i == irq_end / 32 && (irq_end % 32) != 31)
			gic_mask |= (~((1UL << ((irq_end + 1) % 32)) - 1));

		do_irq(pcie_set, gic_status, gic_mask, i);
	}

	offsize = (vector_index / 32) * 4;
	value = (1UL << (vector_index % 32));
	cn_pci_reg_write32(pcie_set, GIC_MSIX_PEND_CLR + offsize, value);
	cn_pci_reg_write32(pcie_set, GIC_MSIX_PEND_CLR + offsize, 0);

	return IRQ_HANDLED;
}

static irqreturn_t msi_interrupt(int irq, void *data)
{
	u32 gic_status = 0;
	u32 gic_mask = 0;
	u32 msi_mask = 0;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;
	int irq_start, irq_end;
	int vector_index;

	/* this lock is used to protect msi mask */
	spin_lock(&pcie_set->irq_set.interrupt_lock);
	vector_index = irq - pcie_set->irq_set.irq;

	if (vector_index >= MSI_COUNT) {
		cn_dev_pcie_err(pcie_set, "recv error interrupt:%d", irq);
		spin_unlock(&pcie_set->irq_set.interrupt_lock);
		return IRQ_HANDLED;
	}
	pci_read_config_dword(pcie_set->pdev, pcie_set->irq_set.msi_pos + MSI_MASK,
								&msi_mask);
	msi_mask |= (0x1 << vector_index);
	pci_write_config_dword(pcie_set->pdev, pcie_set->irq_set.msi_pos + MSI_MASK,
								msi_mask);

	irq_start = (vector_index == 0) ? 0 :
			(irq_msi_gic_end[vector_index - 1] + 1);
	irq_end = irq_msi_gic_end[vector_index];

	for (i = (irq_start / 32); i <= (irq_end / 32); i++) {
		gic_mask = pcie_set->irq_set.gic_mask[i];
		if (gic_mask == ~0x0)
			continue;

		gic_status = cn_pci_reg_read32(pcie_set, GIC_STATUS + i * 4);
		if (gic_status == 0x0)
			continue;

		if (i == irq_start / 32)
			gic_mask |= ((1UL << (irq_start % 32)) - 1);
		if (i == irq_end / 32 && (irq_end % 32) != 31)
			gic_mask |= (~((1UL << ((irq_end + 1) % 32)) - 1));

		do_irq(pcie_set, gic_status, gic_mask, i);
	}
	pci_read_config_dword(pcie_set->pdev, pcie_set->irq_set.msi_pos + MSI_MASK,
								&msi_mask);
	msi_mask &= (~(0x1 << vector_index));
	pci_write_config_dword(pcie_set->pdev, pcie_set->irq_set.msi_pos + MSI_MASK,
								msi_mask);
	spin_unlock(&pcie_set->irq_set.interrupt_lock);

	return IRQ_HANDLED;
}

static irqreturn_t intx_interrupt(int irq, void *data)
{
	u32 gic_status = 0;
	u32 gic_mask = 0;
	int i;
	struct cn_pcie_set *pcie_set = (struct cn_pcie_set *)data;

	for (i = 0; i < (GIC_INTERRUPT_NUM / 32); i++) {
		gic_mask = pcie_set->irq_set.gic_mask[i];
		if (gic_mask == ~0x0)
			continue;

		gic_status = cn_pci_reg_read32(pcie_set, GIC_STATUS + i * 4);
		if (gic_status == 0x0)
			continue;

		do_irq(pcie_set, gic_status, gic_mask, i);
	}
	cn_pci_reg_write32(pcie_set, GLOBAL_INTX_CLR, 0x1);
	cn_pci_reg_write32(pcie_set, GLOBAL_INTX_CLR, 0x0);
	cn_pci_reg_read32(pcie_set, GLOBAL_INTX_CLR);

	return IRQ_HANDLED;
}

static int pcie_gic_mask(int irq, struct cn_pcie_set *pcie_set)
{
	u32 reg_val;
	int i = irq / 32;

	if (irq < 0) {
		cn_dev_pcie_err(pcie_set,
			"pcie_gic hw_irq %d can not less than zero", irq);
		return -1;
	}

	reg_val = cn_pci_reg_read32(pcie_set, GIC_MASK + i * 4);
	reg_val |= (0x1 << (irq % 32));
	pcie_set->irq_set.gic_mask[i] = reg_val;

	cn_pci_reg_write32(pcie_set, GIC_MASK + i * 4, reg_val);
	cn_pci_reg_read32(pcie_set, GIC_MASK + i * 4);

	return 0;
}

static int pcie_gic_unmask(int irq, struct cn_pcie_set *pcie_set)
{
	u32 reg_val;
	int i = irq / 32;

	if (irq < 0) {
		cn_dev_pcie_err(pcie_set,
			"pcie_gic hw_irq %d can not less than zero", irq);
		return -1;
	}

	reg_val = cn_pci_reg_read32(pcie_set, GIC_MASK + i * 4);
	reg_val &= (~(0x1 << (irq % 32)));
	pcie_set->irq_set.gic_mask[i] = reg_val;

	cn_pci_reg_write32(pcie_set, GIC_MASK + i * 4, reg_val);
	cn_pci_reg_read32(pcie_set, GIC_MASK + i * 4);

	return 0;
}

static int pcie_gic_mask_all(struct cn_pcie_set *pcie_set)
{
	u32 reg_val = ~0x0;
	unsigned long i;

	for (i = 0; i < (GIC_INTERRUPT_NUM)/32; i++) {
		pcie_set->irq_set.gic_mask[i] = reg_val;
		cn_pci_reg_write32(pcie_set, GIC_MASK + i * 4, reg_val);
		cn_pci_reg_read32(pcie_set, GIC_MASK + i * 4);
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

static int pcie_soft_reset(struct cn_pcie_set *pcie_set)
{
	return 0;
}

static int pcie_chip_reset(struct cn_pcie_set *pcie_set)
{
	return 0;
}

static int pcie_ddr_set_done(struct cn_pcie_set *pcie_set)
{

#if 0  // need mcu set
	u32 reg32 = 0;
	int cnt, ret = 0;
	u8 sn_high_8bit;

	/*READ SN*/
	reg32 = cn_pci_reg_read32(pcie_set, IPC_5) & 0xFFFF;
	sn_high_8bit = (reg32 >> 8) & 0xFF;
	cn_dev_pcie_info(pcie_set, "board type: %X", sn_high_8bit);

	/*EVBS:0x51 PASS*/
	if (sn_high_8bit != 0x51) {
		cnt = 600;
		do {
			reg32 = cn_pci_reg_read32(pcie_set, IPC_1);
			if (((reg32 >> MLU370_MCU_DDRTRAINED_FLAG_SHIFT) & MLU370_MCU_DDRTRAINED_FLAG_MASK)
				< MLU370_MCU_DDRTRAINED_BOOT_DONE) {
				ret = -EINVAL;
			} else {
				cn_dev_pcie_info(pcie_set, "DDR Training Params set by MCU Finish");
				ret = 0;
				break;
			}

			if (cnt % 10 == 0)
				cn_dev_pcie_info(pcie_set, "Wait DDR Training status:%x!!", reg32);

			msleep(1000);
		} while (--cnt);
		if (!cnt) {
			cn_dev_pcie_err(pcie_set, "Wait DDR Training Finish Timeout!!");
			cn_recommend(pcie_set->bus_set->core, USER_RECOMMED);
			return ret;
		}
	}

	return ret;
#endif
	return 0;
}

static int pcie_dma_bypass_size(struct cn_pcie_set *pcie_set)
{
#if defined(__x86_64__)
	pcie_set->dma_set.dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 512 * 1024;
	pcie_set->dma_set.dma_bypass_pinned_size = dma_bypass_pinned_size ?
				dma_bypass_pinned_size : 256 * 1024;
	/* TODO: custom size depends on bandwidth test*/
	pcie_set->dma_set.dma_memsetD8_custom_size = dma_memsetD8_custom_size ?
		        dma_memsetD8_custom_size : 1024 * 1024;
	pcie_set->dma_set.dma_memsetD16_custom_size = dma_memsetD16_custom_size ?
		        dma_memsetD16_custom_size : 1024 * 1024;
	pcie_set->dma_set.dma_memsetD32_custom_size = dma_memsetD32_custom_size ?
				dma_memsetD32_custom_size : 1024 * 1024;
#else
	pcie_set->dma_set.dma_bypass_custom_size = dma_bypass_custom_size ?
				dma_bypass_custom_size : 256;
	pcie_set->dma_set.dma_bypass_pinned_size = dma_bypass_pinned_size ?
				dma_bypass_pinned_size : 256;
	pcie_set->dma_set.dma_memsetD8_custom_size = dma_memsetD8_custom_size ?
		        dma_memsetD8_custom_size : 256;
	pcie_set->dma_set.dma_memsetD16_custom_size = dma_memsetD16_custom_size ?
		        dma_memsetD16_custom_size : 256;
	pcie_set->dma_set.dma_memsetD32_custom_size = dma_memsetD32_custom_size ?
				dma_memsetD32_custom_size : 256;
#endif
	pcie_set->dma_set.d2h_bypass_custom_size = d2h_bypass_custom_size ?
				d2h_bypass_custom_size : 64;
	return 0;
}

static void pcie_save_msix_ram(struct cn_pcie_set *pcie_set)
{
	int i;

	if (pcie_set->irq_set.irq_type == MSIX) {
		for (i = 0; i < (GIC_INTERRUPT_NUM * 4); i++) {
			pcie_set->irq_set.msix_ram[i] =
				cn_pci_reg_read32(pcie_set, (GBO + i * 4));
		}
	}
}

static void fill_msix_ram(struct cn_pcie_set *pcie_set)
{
	int i;

	/* NOTE: when heartbeat start pcie_set->dfx.heartbeat_cnt != 0,
	 * pcie_set->irq_set.msix_ram use pcie_interrupt_exit() function keep value
	 */
	if (!pcie_set->dfx.heartbeat_cnt)
		memset((void *)(&pcie_set->irq_set.msix_ram[0]),
				0xff, sizeof(pcie_set->irq_set.msix_ram));

	for (i = 0; i < (GIC_INTERRUPT_NUM * 4); i++)
		cn_pci_reg_write32(pcie_set, (GBO + i * 4),
					pcie_set->irq_set.msix_ram[i]);
}

static struct cn_pci_ops public_ops = {
	/* register space */
	.pci_mb = pci_mb,
	/* memcpy */
	.dma_bypass_size = pcie_dma_bypass_size,
	.fill_desc_list = pcie_fill_desc_list,
	.show_desc_list = pcie_show_desc_list,
	.async_dma_fill_desc_list = pcie_async_dma_fill_desc_list,
	/* interrupt */
	.isr_hw_enable = pci_isr_hw_enable,
	.isr_hw_disable = pci_isr_hw_disable,
	.intx_isr = intx_interrupt,
	.msi_isr = msi_interrupt,
	.msix_isr = msix_interrupt,
	.gic_mask = pcie_gic_mask,
	.gic_unmask = pcie_gic_unmask,
	.gic_mask_all = pcie_gic_mask_all,
	.save_msix_ram = pcie_save_msix_ram,
	.get_irq_by_desc = pcie_get_irq,
	/* PCI Express basic */
	.soft_reset = pcie_soft_reset,
	.chip_reset = pcie_chip_reset,
	.ddr_set_done = pcie_ddr_set_done,
};

/*
 * Fix PLX bridge bug, if PLX bridge bar0 overlayed with iova, the bridge
 * will return UC error.
 * PLX 9797's upstrean port bar0 F60[26] = 1 and downstream 760[21] = 1,
 * otherwise upstrean port bar0 F60[26] = 1
 */
static int cn_pci_check_plx_bridge(struct cn_pcie_set *pcie_set)
{
	struct pci_dev *pdev = pcie_set->pdev;
	struct pci_bus *pbus;
	int type;
	int i;
	u32 offset;
	unsigned int value;

	if (!iommu_present(pdev->dev.bus)) {
		return 0;
	}

	while (pdev->bus && pdev->bus->self) {
		pbus = pdev->bus;
		pdev = pbus->self;
		type = pci_pcie_type(pdev);

		/* Not plx bridge or not support old version */
		if ((pdev->vendor != 0x10B5) || (type != PCI_EXP_TYPE_UPSTREAM) ||
			(pdev->device < 0x8700)) {
			continue;
		}

		pci_read_config_dword(pdev, 0xf60, &value);
		if (value & (1 << 26)) {
			continue;
		}

		if (pdev->device == 0x9797) {
			/* set 9797 all downstream 760[21] = 1 */
			u32 *pbar0 = (u32 *)pci_ioremap_bar(pdev, 0);

			if (pbar0) {
				for (i = 0; i < 6; i++) {
					offset = (0x760 + i*0x4000);
					pbar0[offset/4] |= (1 << 21);
					cn_dev_pcie_info(pcie_set, "PLX %x offset:%x value:%x",
						pdev->device, offset, pbar0[offset/4]);
				}

				cn_iounmap((void *)pbar0);
			}
		}

		/* Set upstearm F60[26] = 1 */
		value |= (1 << 26);
		pci_write_config_dword(pdev, 0xf60, value);
		cn_dev_pcie_info(pcie_set, "PLX %x value:%x", pdev->device, value);
	}

	return 0;
}
