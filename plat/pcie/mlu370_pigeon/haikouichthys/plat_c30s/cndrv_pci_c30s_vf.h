#define GIC_MSI_COUNT       (1)

/* Interrupt Registers addr */
#define VF_MBX_STATUS		(0x0)
#define VF_PCIE_INT_MASK(i)	(0x100 + 0x4 * i)
#define VF_PCIE_INT_STATUS(i)	(0x120 + 0x4 * i)

/* BAR 2/4 base and mask Register */
#define VF_BAR_BASE_SIZE  (0x100000UL)
#define VF_BAR_ADDR_MASK(index)	(0x6f8 + 0x4 * index)
#define VF_BAR_ADDR_BASE(index)	(0x6fc + 0x4 * index)

/* Mailbox Registers*/
#define VF2ARM_MBX_STATUS(i)	(0x1000 + 0x10 * i)
#define VF2ARM_MBX_ENTRYL(i)	(0x1004 + 0x10 * i)
#define VF2ARM_MBX_ENTRYH(i)	(0x1008 + 0x10 * i)

#define VF2PF_MBX_STATUS(i)	(0x1020 + 0x10 * i)
#define VF2PF_MBX_ENTRYL(i)	(0x1024 + 0x10 * i)
#define VF2PF_MBX_ENTRYH(i)	(0x1028 + 0x10 * i)

#define VF2DIEL_MBX_STATUS(i)	(0x1040 + 0x10 * i)
#define VF2DIEL_MBX_ENTRYL(i)	(0x1044 + 0x10 * i)
#define VF2DIEL_MBX_ENTRYR(i)	(0x1048 + 0x10 * i)

#define VF2DIER_MBX_STATUS(i)	(0x1060 + 0x10 * i)
#define VF2DIER_MBX_ENTRYL(i)	(0x1064 + 0x10 * i)
#define VF2DIER_MBX_ENTRYH(i)	(0x1068 + 0x10 * i)

#define ARM2VF_MBX_STATUS(i)	(0x1080 + 0x10 * i)
#define ARM2VF_MBX_ENTRYL(i)	(0x1084 + 0x10 * i)
#define ARM2VF_MBX_ENTRYH(i)	(0x1088 + 0x10 * i)

#define PF2VF_MBX_STATUS(i)	(0x10a0 + 0x10 * i)
#define PF2VF_MBX_ENTRYL(i)	(0x10a4 + 0x10 * i)
#define PF2VF_MBX_ENTRYH(i)	(0x10a8 + 0x10 * i)

#define DIEL2VF_MBX_STATUS(i)	(0x10c0 + 0x10 * i)
#define DIEL2VF_MBX_ENTRYL(i)	(0x10c4 + 0x10 * i)
#define DIEL2VF_MBX_ENTRYH(i)	(0x10c8 + 0x10 * i)

#define DIER2VF_MBX_STATUS(i)	(0x10e0 + 0x10 * i)
#define DIER2VF_MBX_ENTRYL(i)	(0x10e4 + 0x10 * i)
#define DIER2VF_MBX_ENTRYH(i)	(0x10e8 + 0x10 * i)

/*DMA control regs offset*/
#define DMA_BASE_ADDR		(0x400)
#define VF_DMA_MASK_ADDR	(0x10)

#define DMA_INT_REG(channel_id)   (0x0600 + channel_id*4)

#define DESC_SIZE					(32)
#define DMA_CHANNEL_REG_SIZE		(0x40)
#define DMA_ISTATUS_BASE			(0x600)
#define DEO	(0UL)	/*dma command descriptor offset*/

#define DMA_PCIE_PARAM	(0x0)
#define DMA_AXI_PARAM	(0x4)
#define SG_ID_PCIE	(0x0)
#define SG_ID_AXI	(0x4)
#define DSE_COND	(0xa)
#define DIRQ		(0x3)
#define DIRQ_ID		(0x1)

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

/*PCIe DMA Channel n source parameter Register*/
#define DSRC_PARAM(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x000)

/*PCIe DMA Channel n Dest Parameter Register*/
#define DDEST_PARAM(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x004)

/*PCIe DMA Channel n SrcAddr Lower Register*/
#define DSRCL(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x008)

/*PCIe DMA Channel n SrcAddr Upper Register*/
#define DSRCU(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x00c)

/*PCIe DMA Channel n DestAddr Lower Register*/
#define DDESTL(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x010)

/*PCIe DMA Channel n DestAddr Upper Register*/
#define DDESTU(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x014)

/*PCIe DMA Channel n Data Length Register(up to 4GB)*/
#define DLEN(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x018)

/*PCIe DMA Channel n Control Register(up to 4GB)*/
#define DCTRL(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x01c)

/*PCIe DMA Channel n Status Register(up to 4GB)*/
#define DSTATUS(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x020)

/*PCIe DMA Channel n Data PRC Length Register(more than 4GB)*/
#define DPRC_LEN(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x024)

/*PCIe DMA Channel n Data Length Register(up to 4GB)*/
#define DSHARE_ACCESS(channel_id)    \
	(DMA_BASE_ADDR + DMA_CHANNEL_REG_SIZE * (channel_id) + 0x028)

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

#define VF_DESC_FETCH_BASE				(0x0800)
#define VF_DMA_DESC_ADDR_L_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x0)
#define VF_DMA_DESC_ADDR_H_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x4)
#define VF_DMA_DESC_NUM_FETCH(i)			(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x8)
#define VF_DMA_DESC_CTRL_FETCH(i)			(VF_DESC_FETCH_BASE + (i) * 0x100 + 0xC)
#define VF_DMA_DESC_CTRL2_FETCH(i)			(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x10)
#define VF_DMA_STATUS_FETCH(i)			(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x20)
#define VF_DMA_STATUS_UP_FETCH(i)			(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x24)
#define VF_DMA_CMD_BUFF_STATUS_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x30)
#define VF_DMA_CMD_STATUS_BUFF_STATUS_FETCH(i)	(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x34)
#define VF_DMA_DESC_DBG_SEL_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x3C)
#define VF_DMA_DESC_DBG_DATA0_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x40)
#define VF_DMA_DESC_DBG_DATA1_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x44)
#define VF_DMA_DESC_DBG_DATA2_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x48)
#define VF_DMA_DESC_DBG_DATA3_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x4C)
#define VF_DMA_DESC_DBG_DATA4_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x50)
#define VF_DMA_DESC_DBG_DATA5_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x54)
#define VF_DMA_DESC_DBG_DATA6_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x58)
#define VF_DMA_DESC_DBG_DATA7_FETCH(i)		(VF_DESC_FETCH_BASE + (i) * 0x100 + 0x5C)
#define VF_DMA_DESC_DBG_SM_FETCH(i)	        (VF_DESC_FETCH_BASE + (i) * 0x100 + 0x60)

#define VF_PCIE_IRQ_DMA			(0)

#define VF_OUTBOUND_AXI_BASE		(0x8000000000ULL)
