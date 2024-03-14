#define C50_PCIE_VF
#define VF_MSI_COUNT		(1)
#define VF_MSIX_COUNT		(8)

#define VF_SHARED_DMA_DESC_TOTAL_SIZE   (0x200000)
#define VF_PRIV_DMA_DESC_TOTAL_SIZE     (0x200000)
#define VF_ASYNC_DMA_DESC_TOTAL_SIZE    (0x200000)

/* DMA control reg */
#define VF_CMD_BUF_CTRL_ENGINE		(0x0)
#define VF_CMD_BUF_ABORT_ENGINE		(0x4)
#define VF_CMD_BUF_STATUS_ENGINE	(0x8)
#define VF_CMD_STATUS_BUF_STATUS_ENGINE	(0xc)
#define VF_CMD_BUF_OVERFLOW_IRQ_ENGINE	(0x10)
#define VF_IDLE_SIGNAL_ENGINE		(0x1c)

#define VF_QUEUE(i)			(((i) + 1) * 0x100)
#define VF_CTRL_LOW_QUEUE(i)		(VF_QUEUE(i) + 0x0)
#define VF_CTRL_HIGH_QUEUE(i)		(VF_QUEUE(i) + 0x4)
#define VF_CTRL_DESC_NUM_QUEUE(i)	(VF_QUEUE(i) + 0x8)
#define VF_CTRL_CMD_CTRL1_QUEUE(i)	(VF_QUEUE(i) + 0xc)
#define VF_CTRL_CMD_CTRL2_QUEUE(i)	(VF_QUEUE(i) + 0x20)
#define VF_DMA_STATUS_QUEUE(i)		(VF_QUEUE(i) + 0x24)
#define VF_DMA_STATUS_UP_QUEUE(i)	(VF_QUEUE(i) + 0x28)
#define VF_DBG_SEL_QUEUE(i)		(VF_QUEUE(i) + 0x3c)
#define VF_DBG_DATA0_QUEUE(i)		(VF_QUEUE(i) + 0x40)
#define VF_DBG_DATA1_QUEUE(i)		(VF_QUEUE(i) + 0x44)
#define VF_DBG_DATA2_QUEUE(i)		(VF_QUEUE(i) + 0x48)
#define VF_DBG_DATA3_QUEUE(i)		(VF_QUEUE(i) + 0x4c)
#define VF_DBG_DATA4_QUEUE(i)		(VF_QUEUE(i) + 0x50)

/* GIC register */
#define VF_GIC_BASE		(0x2000)
#define VF_GIC_CTRL		(VF_GIC_BASE + 0x30C0)
#define VF_MBX_STATUS		(VF_GIC_BASE + 0x2200)
#define VF_INT_MASK		(VF_GIC_BASE + 0x3000)
#define VF_INT_STATUS		(VF_GIC_BASE + 0x3040)
#define VF_MSIX_PEND_CLR	(VF_GIC_BASE + 0x3080)

/* BAR 2/4 base and mask Register */
#define VF_BAR_BASE_SIZE  (0x100000UL)
#define VF_BAR_ADDR_MASK(index)	(0x10f8 + 0x4 * index)
#define VF_BAR_ADDR_BASE(index)	(0x10fc + 0x4 * index)

/* Mailbox Registers*/
#define VF2ARM_MBX_STATUS(i)	(0x1000 + 0x10 * i)
#define VF2ARM_MBX_ENTRYL(i)	(0x1004 + 0x10 * i)
#define VF2ARM_MBX_ENTRYH(i)	(0x1008 + 0x10 * i)

#define ARM2VF_MBX_STATUS(i)	(0x1020 + 0x10 * i)
#define ARM2VF_MBX_ENTRYL(i)	(0x1024 + 0x10 * i)
#define ARM2VF_MBX_ENTRYH(i)	(0x1028 + 0x10 * i)

#define VF2PF_MBX_STATUS(i)	(0x1040 + 0x10 * i)
#define VF2PF_MBX_ENTRYL(i)	(0x1044 + 0x10 * i)
#define VF2PF_MBX_ENTRYH(i)	(0x1048 + 0x10 * i)

#define PF2VF_MBX_STATUS(i)	(0x1060 + 0x10 * i)
#define PF2VF_MBX_ENTRYL(i)	(0x1064 + 0x10 * i)
#define PF2VF_MBX_ENTRYH(i)	(0x1068 + 0x10 * i)

#define VF2DIER_MBX_STATUS(i)	(0x1080 + 0x10 * i)
#define VF2DIER_MBX_ENTRYL(i)	(0x1084 + 0x10 * i)
#define VF2DIER_MBX_ENTRYH(i)	(0x1088 + 0x10 * i)

#define DIER2VF_MBX_STATUS(i)	(0x10a0 + 0x10 * i)
#define DIER2VF_MBX_ENTRYL(i)	(0x10a4 + 0x10 * i)
#define DIER2VF_MBX_ENTRYH(i)	(0x10a8 + 0x10 * i)

#define DESC_SIZE			(32)
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

struct pcie_rpc_sync_write_set
{
	u32 sw_index;
	u64 val;
};
