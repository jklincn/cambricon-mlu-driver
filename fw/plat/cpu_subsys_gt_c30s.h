#ifndef	__GENERIC_TIMER_REG_H__
#define	__GENERIC_TIMER_REG_H__

#define GENE_TIME_BASE_ADDR        	(0x02501000)

#define	GENERIC_TIMER_CTRL_CNTCR_RW_ADDR	0x00000000
#define	GENERIC_TIMER_CTRL_CNTCR__DEF_VAL	0x00000000
#define	GENERIC_TIMER_CTRL_CNTCR_CTRL_CNTCR_EN_OFFSET	0x00000000
#define	GENERIC_TIMER_CTRL_CNTCR_CTRL_CNTCR_EN_MASK	0x00000001
#define	GENERIC_TIMER_CTRL_CNTCR_CTRL_CNTCR_FCREQ_OFFSET	0x00000008
#define	GENERIC_TIMER_CTRL_CNTCR_CTRL_CNTCR_FCREQ_MASK	0x0003FF00
#define	GENERIC_TIMER_CTRL_CNTCR_CTRL_CNTCR_HDBG_OFFSET	0x00000001
#define	GENERIC_TIMER_CTRL_CNTCR_CTRL_CNTCR_HDBG_MASK	0x00000002

#define	GENERIC_TIMER_CTRL_CNTSR_RO_ADDR	0x00000004
#define	GENERIC_TIMER_CTRL_CNTSR__DEF_VAL	0x00000000
#define	GENERIC_TIMER_CTRL_CNTSR_CTRL_CNTSR_DBGH_OFFSET	0x00000001
#define	GENERIC_TIMER_CTRL_CNTSR_CTRL_CNTSR_DBGH_MASK	0x00000002
#define	GENERIC_TIMER_CTRL_CNTSR_CTRL_CNTSR_FCACK_OFFSET	0x00000008
#define	GENERIC_TIMER_CTRL_CNTSR_CTRL_CNTSR_FCACK_MASK	0xFFFFFF00

#define	GENERIC_TIMER_CTRL_CNTCV0_RW_ADDR	0x00000008
#define	GENERIC_TIMER_CTRL_CNTCV0__DEF_VAL	0x00000000
#define	GENERIC_TIMER_CTRL_CNTCV0_CTRL_CNTCV0_OFFSET	0x00000000
#define	GENERIC_TIMER_CTRL_CNTCV0_CTRL_CNTCV0_MASK	0xFFFFFFFF

#define	GENERIC_TIMER_CTRL_CNTCV1_RW_ADDR	0x0000000C
#define	GENERIC_TIMER_CTRL_CNTCV1__DEF_VAL	0x00000000
#define	GENERIC_TIMER_CTRL_CNTCV1_CTRL_CNTCV1_OFFSET	0x00000000
#define	GENERIC_TIMER_CTRL_CNTCV1_CTRL_CNTCV1_MASK	0xFFFFFFFF

#define	GENERIC_TIMER_CTRL_CNTFID0_RW_ADDR	0x00000020
#define	GENERIC_TIMER_CTRL_CNTFID0__DEF_VAL	0x017D7840
#define	GENERIC_TIMER_CTRL_CNTFID0_CTRL_CNTFID0_OFFSET	0x00000000
#define	GENERIC_TIMER_CTRL_CNTFID0_CTRL_CNTFID0_MASK	0xFFFFFFFF

#define	GENERIC_TIMER_CTRL_COUNTERID0_RO_ADDR	0x00000FD0
#define	GENERIC_TIMER_CTRL_COUNTERID0__DEF_VAL	0x00000000
#define	GENERIC_TIMER_CTRL_COUNTERID0_CTRL_COUNTERID0_OFFSET	0x00000000
#define	GENERIC_TIMER_CTRL_COUNTERID0_CTRL_COUNTERID0_MASK	0xFFFFFFFF

#define	GENERIC_TIMER_READ_CNTCV0_RO_ADDR	0x00001000
#define	GENERIC_TIMER_READ_CNTCV0__DEF_VAL	0x00000000
#define	GENERIC_TIMER_READ_CNTCV0_READ_CNTCV0_OFFSET	0x00000000
#define	GENERIC_TIMER_READ_CNTCV0_READ_CNTCV0_MASK	0xFFFFFFFF

#define	GENERIC_TIMER_READ_CNTCV1_RO_ADDR	0x00001004
#define	GENERIC_TIMER_READ_CNTCV1__DEF_VAL	0x00000000
#define	GENERIC_TIMER_READ_CNTCV1_READ_CNTCV1_OFFSET	0x00000000
#define	GENERIC_TIMER_READ_CNTCV1_READ_CNTCV1_MASK	0xFFFFFFFF

#define	GENERIC_TIMER_READ_COUNTERID0_RO_ADDR	0x00001FD0
#define	GENERIC_TIMER_READ_COUNTERID0__DEF_VAL	0x00000000
#define	GENERIC_TIMER_READ_COUNTERID0_READ_COUNTERID0_OFFSET	0x00000000
#define	GENERIC_TIMER_READ_COUNTERID0_READ_COUNTERID0_MASK	0xFFFFFFFF

/* export */
#define CNTCR_ADDR		(GENE_TIME_BASE_ADDR + GENERIC_TIMER_CTRL_CNTCR_RW_ADDR)
#define CNTSR_ADDR		(GENE_TIME_BASE_ADDR + GENERIC_TIMER_CTRL_CNTSR_RO_ADDR)
#define CNTCV_ADDR		(GENE_TIME_BASE_ADDR + GENERIC_TIMER_CTRL_CNTCV0_RW_ADDR)
#define CNTFID_ADDR		(GENE_TIME_BASE_ADDR + GENERIC_TIMER_CTRL_CNTFID0_RW_ADDR)  //only have table 0
#define COUNTERID0_ADDR		(GENE_TIME_BASE_ADDR + GENERIC_TIMER_CTRL_COUNTERID0_RO_ADDR)  //default as 0
#define CNTCV_F1_ADDR		(GENE_TIME_BASE_ADDR + GENERIC_TIMER_READ_CNTCV0_RO_ADDR)  //FRAME1 +4k

#endif
