#ifndef __C50_HBM_INIT__
#define __C50_HBM_INIT__

//hbm core register offsets
#define HBM_SW_RST0                   (0x114)
#define HBM_SW_RST1                   (0x118)
#define CFG_DATA_SCRAMBLE             (0x200)

//umc register offsets
#define CFG_READ_DBI                  (0x1010 << 2)
#define CFG_WRITE_DBI                 (0x1011 << 2)
#define CFG_CCD_S                     (0x1019 << 2)
#define CFG_CCD_L                     (0x101a << 2)
#define CFG_RRD_S                     (0x101e << 2)
#define CFG_RRD_L                     (0x101f << 2)
#define CFG_WTR_S                     (0x1020 << 2)
#define CFG_WTR_L                     (0x1021 << 2)
#define CFG_RD_DQ_PARITY_EN           (0x1028 << 2)
#define CFG_WR_DQ_PARITY_EN           (0x1029 << 2)
#define CFG_CA_PARITY_EN              (0x102a << 2)
#define CFG_BANK_GROUP_EN             (0x102b << 2)
#define CFG_HBM_CB_EN                 (0x102c << 2)
#define CFG_HBM_PARITY_LATENCY        (0x102d << 2)
#define CFG_TCR_ENABLE                (0x102e << 2)
#define CFG_EN_RRDP                   (0x1030 << 2)
#define CFG_PS_ONE_FAW                (0x1031 << 2)
#define CFG_CCD_R                     (0x1032 << 2)
#define INIT_SBREF_EN                 (0x109c << 2)
#define CFG_RREFD                     (0x109d << 2)
#define CFG_RFCSB                     (0x109e << 2)
#define CFG_RCD_RD                    (0x10a1 << 2)
#define CFG_RCD_WR                    (0x10a2 << 2)
#define CFG_RAS                       (0x110d << 2)
#define CFG_RP                        (0x1110 << 2)
#define CFG_RC                        (0x1111 << 2)
#define CFG_FAW                       (0x1112 << 2)
#define CFG_RFC                       (0x1113 << 2)
#define CFG_RTP                       (0x1114 << 2)
#define CFG_WR                        (0x1115 << 2)
#define CFG_XP                        (0x1119 << 2)
#define CFG_READ_TO_WRITE             (0x111d << 2)
#define INIT_REF_PER                  (0x112e << 2)
#define CFG_MEM_ROWBITS               (0x1131 << 2)
#define CFG_MEM_BANKBITS              (0x1132 << 2)
#define CFG_XS                        (0x114d << 2)
#define CFG_WL                        (0x1172 << 2)
#define CFG_RL                        (0x1173 << 2)
#define CFG_CKSRE                     (0x11a4 << 2)
#define CFG_CKSRX                     (0x11a5 << 2)
#define CFG_DFI_T_PHY_RDLAT           (0x1401 << 2)
#define CFG_DFI_T_PHY_WRLAT           (0x1402 << 2)
#define CFG_DFI_T_RDDATA_EN           (0x1400 << 2)
#define CFG_SBREF_ISSUE_PER           (0x1704 << 2)
#define CFG_AXI_START_ADDRESS_AXI1    (0x1e02 << 2)
#define CFG_AXI_END_ADDRESS_AXI1      (0x1e07 << 2)
#define CTRLR_SOFT_RESET_N            (0x1100 << 2)
#define CFG_CTRLR_INIT_DISABLE        (0x117b << 2)
#define INIT_AUTOINIT_DISABLE         (0x1103 << 2)
#define INIT_AUTO_REF_EN              (0x110c << 2)
#define PHY_DFI_INIT_START            (0x1414 << 2)
#define CFG_STARTUP_DELAY             (0x112f << 2)
#define CFG_BL                        (0x110a << 2)
#define INIT_DFI_PHYUPD_EN            (0x1403 << 2)
#define CTRLR_INIT_DONE               (0x110b << 2)
#define STAT_DFI_INIT_COMPLETE        (0x140d << 2)
#define CFG_REORDER_EN                (0x1700 << 2)
#define CFG_DM_EN                     (0x1800 << 2)
#define CFG_ECC_CORRECTION_EN         (0x1900 << 2)

#define MLU590_A6_HBM_CHANNEL_COUNT					(6)
#define MLU590_A5_HBM_CHANNEL_COUNT					(5)
#define MLU590_A3_HBM_CHANNEL_COUNT					(3)
#define MLU590_VERIFICTION_PLAT_HBM_CHANNEL_COUNT	(1)
#define MLU590_HBM_BITMAP							(0x3f)
#define MLU590_HBM_NUM_MAX							(MLU590_A6_HBM_CHANNEL_COUNT)

/* shuffle register */
#define MLU590_SYSCTRL_BASE               (0x95e000)
#define MLU590_SYSCTRL_NOC_DATA_CTL       (MLU590_SYSCTRL_BASE + 0x08)
#define MLU590_SYSCTRL_ADDRESS_MAP        (MLU590_SYSCTRL_BASE + 0x0c)

#define MLU590_SYSCTRL_HBM_CAPACITY_OFF				(4)
#define MLU590_SYSCTRL_SHUFFLE_OFF					(8)
#define MLU590_SYSCTRL_INTERLEAVING_SIZE_OFF		(16)
#define MLU590_SYSCTRL_LLC_INTERLEAVING_MODE_OFF	(20)
#define MLU590_SYSCTRL_LLC_INTERLEAVING_SIZE_OFF	(24)
#define MLU590_SYSCTRL_LLC_SHUFFLE_OFF				(28)
#define MLU590_SYSCTRL_SP_INTERLEAVING_OFF			(28)

#define MLU590_SYSCTRL_SHUFFLE_MASK					(0x1)
#define MLU590_SYSCTRL_INTERLEAVING_SIZE_MASK		(0x3)
#define MLU590_SYSCTRL_LLC_INTERLEAVING_MODE_MASK	(0x3)
#define MLU590_SYSCTRL_LLC_INTERLEAVING_SIZE_MASK	(0x3)
#define MLU590_SYSCTRL_LLC_SHUFFLE_MASK				(0x1)
#define MLU590_SYSCTRL_SP_INTERLEAVING_MASK			(0x3)

#define	MLU590_HBM_RESETN_MASK						(0x10001)
/*
 *NOTE:
 *Top hbm id		0	1	2	3	4	5
 *Addrdec hbm id	0	2	1	4	3	5
 */
#define	MLU590_HBM0_TOP_RESETN_BASE					(0x915400 + 0x4)
#define	MLU590_HBM1_TOP_RESETN_BASE					(0x915400 + 0x8)
#define	MLU590_HBM2_TOP_RESETN_BASE					(0x915400 + 0xc)
#define	MLU590_HBM3_TOP_RESETN_BASE					(0x915400 + 0x10)
#define	MLU590_HBM4_TOP_RESETN_BASE					(0x915400 + 0x14)
#define	MLU590_HBM5_TOP_RESETN_BASE					(0x915400 + 0x18)

#define	MLU590_HBM0_DEC_RESETN_BASE					(MLU590_HBM0_TOP_RESETN_BASE)
#define	MLU590_HBM1_DEC_RESETN_BASE					(MLU590_HBM2_TOP_RESETN_BASE)
#define	MLU590_HBM2_DEC_RESETN_BASE					(MLU590_HBM1_TOP_RESETN_BASE)
#define	MLU590_HBM3_DEC_RESETN_BASE					(MLU590_HBM4_TOP_RESETN_BASE)
#define	MLU590_HBM4_DEC_RESETN_BASE					(MLU590_HBM3_TOP_RESETN_BASE)
#define	MLU590_HBM5_DEC_RESETN_BASE					(MLU590_HBM5_TOP_RESETN_BASE)

#define	MLU590_LLCG_CNT								(12)
#define	MLU590_LLC_SYS_RESETN_OFF					(0x4)
#define	MLU590_LLCG_RESETN_MASK						(0x10001)
#define	MLU590_LLCG0_RESETN_BASE					(0x915400 + 0xa8)
#define	MLU590_LLCG1_RESETN_BASE					(0x915400 + 0xb0)
#define	MLU590_LLCG2_RESETN_BASE					(0x915400 + 0xb8)
#define	MLU590_LLCG3_RESETN_BASE					(0x915400 + 0xc0)
#define	MLU590_LLCG4_RESETN_BASE					(0x915400 + 0xc8)
#define	MLU590_LLCG5_RESETN_BASE					(0x915400 + 0xd0)
#define	MLU590_LLCG6_RESETN_BASE					(0x915400 + 0xd8)
#define	MLU590_LLCG7_RESETN_BASE					(0x915400 + 0xe0)
#define	MLU590_LLCG8_RESETN_BASE					(0x915400 + 0xe8)
#define	MLU590_LLCG9_RESETN_BASE					(0x915400 + 0xf0)
#define	MLU590_LLCG10_RESETN_BASE					(0x915400 + 0xf8)
#define	MLU590_LLCG11_RESETN_BASE					(0x915400 + 0x100)

#define	MLU590_LLC_SYS_CONFIG_OFF					(0x4000)
#define	MLU590_LLC_GROUP0_BASE						(0x01900000)
#define	MLU590_LLC_GROUP1_BASE						(0x01908000)
#define	MLU590_LLC_GROUP2_BASE						(0x01910000)
#define	MLU590_LLC_GROUP3_BASE						(0x01918000)
#define	MLU590_LLC_GROUP4_BASE						(0x01920000)
#define	MLU590_LLC_GROUP5_BASE						(0x01928000)
#define	MLU590_LLC_GROUP6_BASE						(0x01930000)
#define	MLU590_LLC_GROUP7_BASE						(0x01938000)
#define	MLU590_LLC_GROUP8_BASE						(0x01940000)
#define	MLU590_LLC_GROUP9_BASE						(0x01948000)
#define	MLU590_LLC_GROUP10_BASE						(0x01950000)
#define	MLU590_LLC_GROUP11_BASE						(0x01958000)

/*-----------------------------------*/
/*UMC CONFIG*/
#define HBM_CORE_ADDR(i) ((i < 3) ? (0x200000 + (i * 0x200000)) : (0xA00000 + ((i - 3) * 0x200000)))
#define HBM_CORE_CSR(i)		((HBM_CORE_ADDR(i)) + 0x10000)
#define UMC_ADDR_BASE(i, j)	((HBM_CORE_ADDR(i)) + 0x30000 + (j * 0x10000))

/*NOC DATA MIDDLE*/
#define NOC_DATA_MIDDLE01_RD1 0x19a7000
#define NOC_DATA_MIDDLE01_RD2 0x19a9000
#define NOC_DATA_MIDDLE01_RD0 0x19aa000
#define NOC_DATA_MIDDLE01_RD3 0x19ad000
#define NOC_DATA_MIDDLE02_RD1 0x19b0000
#define NOC_DATA_MIDDLE02_RD2 0x19b1000
#define NOC_DATA_MIDDLE02_RD3 0x19b2000
#define NOC_DATA_MIDDLE02_RD4 0x19b3000
#define NOC_DATA_MIDDLE04_RD1 0x19bc000
#define NOC_DATA_MIDDLE04_RD2 0x19bd000
#define NOC_DATA_MIDDLE04_RD3 0x19be000
#define NOC_DATA_MIDDLE04_RD4 0x19bf000
#define NOC_DATA_MIDDLE11_RD1 0x19ce000
#define NOC_DATA_MIDDLE11_RD2 0x19cf000
#define NOC_DATA_MIDDLE11_RD3 0x19d0000
#define NOC_DATA_MIDDLE11_RD4 0x19d1000
#define NOC_DATA_MIDDLE13_RD1 0x19da000
#define NOC_DATA_MIDDLE13_RD2 0x19db000
#define NOC_DATA_MIDDLE13_RD3 0x19dc000
#define NOC_DATA_MIDDLE13_RD4 0x19dd000
#define NOC_DATA_MIDDLE14_RD1 0x19e0000
#define NOC_DATA_MIDDLE14_RD2 0x19e1000
#define NOC_DATA_MIDDLE14_RD3 0x19e2000
#define NOC_DATA_MIDDLE14_RD4 0x19e3000

#define NOC_VC_NUM_TABLE0_OFF	  0x34
#define NOC_VC_NUM_TABLE1_OFF	  0x38

enum HBM_CAPACITY_SIZE {
	HBM_CAPACITY_SIZE_8G = 0,
	HBM_CAPACITY_SIZE_16G,
};

/* NOC RD OUTSTANDING: each cluster has two read port */
#define NOC_DATA_NORTH_CLUSTER0_RD0 0x199608C
#define NOC_DATA_NORTH_CLUSTER0_RD1 0x199600C
#define NOC_DATA_NORTH_CLUSTER1_RD0 0x199420C
#define NOC_DATA_NORTH_CLUSTER1_RD1 0x199400C
#define NOC_DATA_SOUTH_CLUSTER2_RD0 0x199C00C
#define NOC_DATA_SOUTH_CLUSTER2_RD1 0x199C08C
#define NOC_DATA_SOUTH_CLUSTER3_RD0 0x199E00C
#define NOC_DATA_SOUTH_CLUSTER3_RD1 0x199E08C
#define NOC_DATA_NORTH_CLUSTER4_RD0 0x199610C
#define NOC_DATA_NORTH_CLUSTER4_RD1 0x199618C
#define NOC_DATA_NORTH_CLUSTER5_RD0 0x199428C
#define NOC_DATA_NORTH_CLUSTER5_RD1 0x199408C
#define NOC_DATA_SOUTH_CLUSTER6_RD0 0x19A008C
#define NOC_DATA_SOUTH_CLUSTER6_RD1 0x19A000C
#define NOC_DATA_SOUTH_CLUSTER7_RD0 0x19A200C
#define NOC_DATA_SOUTH_CLUSTER7_RD1 0x19A210C
#define NOC_DATA_NORTH_CLUSTER8_RD0 0x199A00C
#define NOC_DATA_NORTH_CLUSTER8_RD1 0x199A08C
#define NOC_DATA_NORTH_CLUSTER9_RD0 0x199808C
#define NOC_DATA_NORTH_CLUSTER9_RD1 0x199800C
#define NOC_DATA_SOUTH_CLUSTER10_RD0 0x19A010C
#define NOC_DATA_SOUTH_CLUSTER10_RD1 0x19A018C
#define NOC_DATA_SOUTH_CLUSTER11_RD0 0x19A208C
#define NOC_DATA_SOUTH_CLUSTER11_RD1 0x19A218C

#define NOC_DATA_CLUSTER_RD_OUTSTANDING_VALUE (192U)

#endif
