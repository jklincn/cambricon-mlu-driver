#ifndef __CNDRV_NOR_INTERNAL_H__
#define __CNDRV_NOR_INTERNAL_H__

#include <linux/types.h>

#ifndef __ASSEMBLY__

#define NOR_READ 0x03
#define NOR_STATUS 0x05
#define NOR_FLAG_STATUS 0x70
#define NOR_RESET_E 0x66
#define NOR_RESET 0x99
#define NOR_ID_INS 0x9f
#define NOR_UNLOCK_INS 0x39
#define NOR_WRITE_E 0x06
#define NOR_WRITE_D 0x04
#define NOR_WRITE 0x02
#define NOR_ERASE_32K 0x52
#define NOR_ERASE_4K 0x20
#define NOR_ERASE_SEC 0xd8
#define NOR_ERASE_BULK 0x60

#define MICRON_W_REG 0x81
#define MICRON_DATA 0x6f
#define MX25_W_REG 0x01
#define MX25_R_REG 0x5
#define MX25_DATA_MASK 0x40
#define XTX_REG_W 0x35
#define XTX_REG_R 0x5
#define XTX_DATA_MASK 0x200
#define QUAD_PROGRAM_32 0x32

#define PROGRAM_SIZE 256
#define ERASE_SIZE 4096

#define ERESET 5 /* flash init reset error */
#define EID 6 /* get flash id error during */
#define ERDINS 7 /* sfc send read_ins to flash error*/
#define ERDADDR 8 /* sfc send address to flash  error*/
#define ESFCRDEND 10 /* sfc read data end error*/
#define ERESETINS 11 /* sfc send reset ins error*/
#define EWINS 12 /* sfc send write_en ins error*/
#define EWINSEND 13 /* sfc send write_en ins end error*/
#define ERESETEND 14 /* sfc send reset_ins end error*/
#define ERDINSEND 15 /* sfc send read_ins end error*/
#define ERDADDREND 16 /* sfc send read_address end error*/
#define ESFCRD_OF 17 /* sfc send read buffer addr  to flash error*/
#define SET_QUAD_ERR 18
#define SET_QUAD_ERR_D 19
#define SET_QUAD_ERR_END 20
#define SET_QUAD_ERR_END_D 21
#define SET_QUAD_ERR_R 22
#define SET_QUAD_ERR_END_R 23
#define SET_QUAD_ERR_END_R_D 24
#define SET_WEL_ERR 25
#define SET_WEL_ERR_D 26
#define ERDINSEND_DMA 28
#define ERDINSEND_DMA_D 29
#define ERDADDR_DMA 30
#define ERDADDREND_DMA 31
#define ERDIN_DMA 32
#define MODE_ERR 33
#define EID_WEL 39
#define ESET_NONREG 34
#define ESET_DATAREG 35
#define ER_REG 36
#define ERX_DATA_REG 37
#define EFLASH 38
#define EXTX_WRITE_DATA 39
#define EXTX_WRITE_REG 40
#define EXTX_WRITE_E 41
#define ECON_XTX_READ_REG_END 42
#define ECON_MX_DATA 43
#define ECON_MX_WRITE_REG 44
#define ECON_MX_WRITE_E 45
#define ECON_MX_WRITE_R 46
#define ECON_MICON_DATA 47
#define ECON_MICON_WRITE_REG 48
#define ECON_MICON_WRITE_E 49
#define ERD_ADDR 50
#define ERDADDR_DMA_ADDR 51
#define EDMA_TRANS_ERR 52
#define EDMA_SIZE_ERR 53
#define EDMA_ARG_ERR 54
#define EDATANOR 59
#define ECMDE 60
#define ECMDNOR 61
#define EADDRNOR 62
#define ESTATUS 63
#define EWRITENOR 64
#define EFLASHCMD 65
#define EWRITECMD 66
#define EFLASHADDR 67
#define EADDRCMD 68
#define EDATACMD 69

#define MODE4(length) (length & 0x03)
#define BYTE4_ALIGN(length) ((length >> 2) << 2)
#define DUAL_CMD_R 0xbb
#define QUAD_CMD_R 0xeb
#define QUAD_PROGRAM 0x38

#define W_FLASH_STAT2_CMD 0x31
#define FLASH_QUAD_EN 0x02
#define R_FLASH_STAT2_CMD 0x35

struct flash {
	uint32_t flashid;
	uint32_t op;
	uint32_t cfg_mode;
};

struct sfc_sig {
	int cs;
	int is_dma;
	int is_data;
	int trans_mode;
	int flag; //1: trans non cmd, 0:trans cmd
	int error_status;
	uint32_t op;
	size_t size;
};
struct sfc_signal {
	struct sfc_sig sfc_info;
	uint32_t standard_quad;
	uint32_t flash_status;
	uint32_t flash_id;
	uint64_t dma_addr;
	uint32_t addr;
	unsigned char *pdata;
	size_t data_len;
};

struct cn_nor_set {
	void *core;
	struct sfc_signal signal;
	uint32_t op;
	int32_t check_unit;
	unsigned long base;
};

int nor_init(struct cn_nor_set *nor_set, uint32_t mode);

#endif /*__ASSEMBLY__*/
#endif /*__NOR_H__*/
