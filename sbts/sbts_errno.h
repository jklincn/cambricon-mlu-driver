/*
 * sbts/sbts_errno.h
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef _SBTS_ERRNO_H
#define _SBTS_ERRNO_H

/*
 * these errno receive form device
 */
/* the lower 32 bits errno, these errno will return to driver-api after host map */
#define SBTST_ACK_OTHER_ERR 1
#define SBTST_ACK_INIT_FAILED 2
#define SBTST_ACK_PUSH_FAILED 3
#define SBTST_ACK_CFG_TASK_FAILED 4
#define SBTST_ACK_SWTASK_RUN_TIMEOUT 5
#define SBTST_ACK_LMEM_RESIZE_FAIL 53
#define SBTST_ACK_DMA_ASYNC_ERROR 54
#define SBTST_ACK_TASK_CORE_ERR 57
#define SBTST_ACK_IDC_ERROR 58
#define SBTST_ACK_NO_TINYCORE 59
#define SBTST_ACK_NOTIFIER_ERROR 60

#define SBTST_ACK_C2C_TASK_TIMEOUT 110
#define SBTST_ACK_C2C_QP_INVALID 111
#define SBTST_ACK_C2C_QP_BUSY 112
#define SBTST_ACK_C2C_QP_NOT_EXISTS 113
#define SBTST_ACK_C2C_TEMPLATE_INVALID 114
#define SBTST_ACK_C2C_TEMPLATE_NOT_EXISTS 115
#define SBTST_ACK_C2C_PARAM_INVALID 116
#define SBTST_ACK_C2C_DECS_CNT_ERR 117
#define SBTST_ACK_C2C_SRC_ADDR_ERR 118
#define SBTST_ACK_C2C_DST_ADDR_ERR 119
#define SBTST_ACK_C2C_KERNEL_ERR 120
#define SBTST_ACK_C2C_TRIGGER_CNT_ERR 121
#define SBTST_ACK_C2C_REMOTE_ERR 122
#define SBTST_ACK_C2C_LINK_UNCORR_ERR 123
#define SBTST_ACK_C2C_LINK_ERR 124
#define SBTST_ACK_C2C_TASK_EXIST 125
#define SBTST_ACK_C2C_TASK_TYPE_INVALID 126
#define SBTST_ACK_C2C_END 149

#define SBTST_ACK_TCDP_INTERNEL_ERR 150
#define SBTST_ACK_TCDP_HANDLE_INVALID 151
#define SBTST_ACK_TCDP_NO_RESOURCE 152
#define SBTST_ACK_TCDP_RESEND_EXCEED_MAX_NUM 153
#define SBTST_ACK_TCDP_END 200

/* the upper 32 bits errno, these errno just used for host driver */
#define SBTST_ACK_IFU_ERR 0x1 /* hardware code read from IRQ_STATUS_RO */
#define SBTST_ACK_IDU_ERR 0x2 /* hardware code read from IRQ_STATUS_RO */
#define SBTST_ACK_MAU_ERR 0x4 /* hardware code read from IRQ_STATUS_RO */
#define SBTST_ACK_SDU_ERR 0x8 /* hardware code read from IRQ_STATUS_RO */
#define SBTST_ACK_SMMU_ERR 0x10 /* hardware code read from IRQ_STATUS_RO */
#define SBTST_ACK_WATCH_DOG_ERR 0x40 /* hardware code read from IRQ_STATUS_RO */
#define SBTST_ACK_INIT_RAM_ERR 0x80 /* hardware code read from IRQ_STATUS_RO */
#define SBTST_ACK_DUMP_FINISH 0xff

/*
 * these errno return to driver-api after map
 */

#define SBTS_ERRNO_BASE           (530000)
#define SBTS_IPU_ERRNO_BASE       (530428)
#define SBTS_NCS_ACK_ERRNO_BASE   (530700)
#define SBTS_IPU_ERRNO_ACK_MASK   (0xff)
#define SBTS_IPU_ERRNO_ACK_OFFSET (8)
#define SBTS_IPU_ERRNO_RET_OFFSET (20)

enum cn_sbts_errno {
	/* share memory alloc error */
	CN_SBTS_ERROR_SHARE_MEM_ALLOC =          SBTS_ERRNO_BASE + 21,
	/* fill task descriptor error */
	CN_SBTS_ERROR_FILL_TASK_DESC =           SBTS_ERRNO_BASE + 22,
	/* ctrl task ioctl return error */
	CN_SBTS_ERROR_IOCTL_FAILED =             SBTS_ERRNO_BASE + 23,
	/* send dma async task to bus fail */
	CN_DMA_ASYNC_REG_TASK_FAILED =           SBTS_ERRNO_BASE + 24,
	/* process host function task fail*/
	CN_HOST_FUNC_TASK_FAILED =               SBTS_ERRNO_BASE + 25,
	/* notifier validation error */
	CN_NOTIFIER_ERROR_NOTIFIER_INVALID =     SBTS_ERRNO_BASE + 40,
	/* cngdb task receive data error */
	CN_KERNEL_DEBUG_ERROR_ACK =              SBTS_ERRNO_BASE + 50,
	/* cngdb polling ack data timeout */
	CN_KERNEL_DEBUG_ERROR_TIMEOUT =          SBTS_ERRNO_BASE + 51,
	CN_SBTS_TASK_DEVICE_INIT_FAILED =        SBTS_ERRNO_BASE + 301,
	CN_SBTS_TASK_DEVICE_PUSH_FAILED =        SBTS_ERRNO_BASE + 302,
	CN_SBTS_TASK_DEVICE_CFGTASK_FAILED =     SBTS_ERRNO_BASE + 303,
	CN_SBTS_TASK_SW_RUN_TIMEOUT =            SBTS_ERRNO_BASE + 304,
	CN_SBTS_TASK_OTHER_ERROR =               SBTS_ERRNO_BASE + 350,
	/* local memory resize fail */
	CN_SBTS_LMEM_RESIZE_FAIL =               SBTS_ERRNO_BASE + 410,
	/* queue number reach the limitation */
	CN_QUEUE_ERROR_NO_RESOURCE =             SBTS_ERRNO_BASE + 411,
	/* unknown ipu error */
	CN_IPU_UNKNOWN_ERR =                     SBTS_ERRNO_BASE + 422,
	/* queue validation error */
	CN_QUEUE_ERROR_QUEUE_INVALID =           SBTS_ERRNO_BASE + 423,
	/* ipu error from 430 to 479 */
	CN_IPU_INST_CFG_ERR =                    SBTS_ERRNO_BASE + 430,
	CN_IPU_SCALAR_CALC_ERR =                 SBTS_ERRNO_BASE + 431,
	CN_IPU_INST_INVALID =                    SBTS_ERRNO_BASE + 432,
	CN_IPU_INST_ISSUE_TIMEOUT =              SBTS_ERRNO_BASE + 433,
	CN_IPU_RD_SRAM_OVERFLOW =                SBTS_ERRNO_BASE + 434,
	CN_IPU_RD_DRAM_OVERFLOW =                SBTS_ERRNO_BASE + 435,
	CN_IPU_RD_NRAM_OVERFLOW =                SBTS_ERRNO_BASE + 436,
	CN_IPU_RD_WRAM_OVERFLOW =                SBTS_ERRNO_BASE + 437,
	CN_IPU_RD_ADDR_ERR =                     SBTS_ERRNO_BASE + 438,
	CN_IPU_WR_SRAM_OVERFLOW =                SBTS_ERRNO_BASE + 439,
	CN_IPU_WR_DRAM_OVERFLOW =                SBTS_ERRNO_BASE + 440,
	CN_IPU_WR_NRAM_OVERFLOW =                SBTS_ERRNO_BASE + 441,
	CN_IPU_WR_WRAM_OVERFLOW =                SBTS_ERRNO_BASE + 442,
	CN_IPU_WR_ADDR_ERR =                     SBTS_ERRNO_BASE + 443,
	CN_IPU_DECOMPRESS_ERR =                  SBTS_ERRNO_BASE + 444,
	CN_IPU_COMPRESS_ERR =                    SBTS_ERRNO_BASE + 445,
	CN_IPU_SRAM_ECC_ERR =                    SBTS_ERRNO_BASE + 446,
	CN_IPU_DRAM_ECC_ERR =                    SBTS_ERRNO_BASE + 447,
	CN_IPU_NRAM_ECC_ERR =                    SBTS_ERRNO_BASE + 448,
	CN_IPU_WRAM_ECC_ERR =                    SBTS_ERRNO_BASE + 449,
	CN_IPU_RD_SRAM_REQ_TIMEOUT =             SBTS_ERRNO_BASE + 450,
	CN_IPU_RD_DRAM_REQ_TIMEOUT =             SBTS_ERRNO_BASE + 451,
	CN_IPU_RD_NRAM_REQ_TIMEOUT =             SBTS_ERRNO_BASE + 452,
	CN_IPU_RD_WRAM_REQ_TIMEOUT =             SBTS_ERRNO_BASE + 453,
	CN_IPU_WR_SRAM_REQ_TIMEOUT =             SBTS_ERRNO_BASE + 454,
	CN_IPU_WR_DRAM_REQ_TIMEOUT =             SBTS_ERRNO_BASE + 455,
	CN_IPU_WR_NRAM_REQ_TIMEOUT =             SBTS_ERRNO_BASE + 456,
	CN_IPU_WR_WRAM_REQ_TIMEOUT =             SBTS_ERRNO_BASE + 457,
	CN_IPU_RD_SRAM_RESP_ERR =                SBTS_ERRNO_BASE + 458,
	CN_IPU_RD_DRAM_RESP_ERR =                SBTS_ERRNO_BASE + 459,
	CN_IPU_RD_NRAM_RESP_ERR =                SBTS_ERRNO_BASE + 460,
	CN_IPU_RD_WRAM_RESP_ERR =                SBTS_ERRNO_BASE + 461,
	CN_IPU_WR_SRAM_RESP_ERR =                SBTS_ERRNO_BASE + 462,
	CN_IPU_WR_DRAM_RESP_ERR =                SBTS_ERRNO_BASE + 463,
	CN_IPU_WR_NRAM_RESP_ERR =                SBTS_ERRNO_BASE + 464,
	CN_IPU_WR_WRAM_RESP_ERR =                SBTS_ERRNO_BASE + 465,
	CN_IPU_BUS_ERR =                         SBTS_ERRNO_BASE + 466,
	CN_IPU_RD_COM_OVERFLOW =                 SBTS_ERRNO_BASE + 467,
	CN_IPU_RD_COM_ERR =                      SBTS_ERRNO_BASE + 468,
	CN_IPU_SCALAR_NRAM_DATA_ERR =            SBTS_ERRNO_BASE + 469,
	CN_IPU_WR_NRAM_DATA_OVERFLOW =           SBTS_ERRNO_BASE + 470,
	CN_IPU_WR_NRAM_DATA_ERR =                SBTS_ERRNO_BASE + 471,
	CN_IPU_RD_WRAM_ERR =                     SBTS_ERRNO_BASE + 472,
	CN_IPU_WR_NRAM_DATA_TIMEOUT =            SBTS_ERRNO_BASE + 473,
	CN_IPU_RD_NRAM_DATA_TIMEOUT =            SBTS_ERRNO_BASE + 474,
	CN_IPU_NFU_ERR =                         SBTS_ERRNO_BASE + 475,
	CN_IPU_BARRIER_TIMEOUT =                 SBTS_ERRNO_BASE + 476,
	CN_IPU_PV_TIMEOUT =                      SBTS_ERRNO_BASE + 477,
	CN_IPU_ICACHE_ECC_ERR =                  SBTS_ERRNO_BASE + 478,
	CN_IPU_WATCH_DOG_TIMEOUT =               SBTS_ERRNO_BASE + 479,
	/* dma async task error */
	CN_DMA_ASYNC_ERR =                       SBTS_ERRNO_BASE + 480,
	CN_IDC_ERR =                             SBTS_ERRNO_BASE + 481,

	/* tinycore not exist */
	CN_TNC_NOT_EXIST =                       SBTS_ERRNO_BASE + 482,

	/* queue and d2d addr not same context */
	CN_DMA_D2D_INVALID_CONTEXT =             SBTS_ERRNO_BASE + 483,
	/* device notifier run error */
	CN_DEVICE_NOTIFIER_ERR =                 SBTS_ERRNO_BASE + 484,

	/* reserved for device task error code .. 600 */

	/* ncs from 600 to 799*/
	CN_NCS_RET_CODE_BASE =                   SBTS_ERRNO_BASE + 600,

	CN_NCS_PORT_NOT_IN_RANGE =               SBTS_ERRNO_BASE + 601,
	CN_NCS_PORT_LINK_ERR =                   SBTS_ERRNO_BASE + 602,
	CN_NCS_QP_CREATE_PARAM_INVALID =         SBTS_ERRNO_BASE + 603,
	CN_NCS_QP_CREATE_NO_RESOURCE =           SBTS_ERRNO_BASE + 604,
	CN_NCS_QP_MODIFY_PAIRING =               SBTS_ERRNO_BASE + 605,
	CN_NCS_QP_MODIFY_LQP_INVALID =           SBTS_ERRNO_BASE + 606,
	CN_NCS_QP_MODIFY_RQP_INVALID =           SBTS_ERRNO_BASE + 607,
	CN_NCS_QP_MODIFY_NO_RESOURCE =           SBTS_ERRNO_BASE + 608,
	CN_NCS_QP_DESTROY_PARAM_INVALID =        SBTS_ERRNO_BASE + 609,
	CN_NCS_QP_DESTROY_NOT_EXISTS =           SBTS_ERRNO_BASE + 610,
	CN_NCS_QP_DESTROY_BUSY =                 SBTS_ERRNO_BASE + 611,
	CN_NCS_QP_DESTROY_USER_INVALID =         SBTS_ERRNO_BASE + 612,
	CN_NCS_TEMPLATE_CREATE_PARAM_INVALID =   SBTS_ERRNO_BASE + 613,
	CN_NCS_TEMPLATE_CREATE_NO_RESOURCE =     SBTS_ERRNO_BASE + 614,
	CN_NCS_TEMPLATE_CREATE_LOAD_ERR =        SBTS_ERRNO_BASE + 615,
	CN_NCS_TEMPLATE_DESTROY_PARAM_INVALID =  SBTS_ERRNO_BASE + 616,
	CN_NCS_TEMPLATE_DESTROY_NOT_EXISTS =     SBTS_ERRNO_BASE + 617,
	CN_NCS_TEMPLATE_DESTROY_BUSY =           SBTS_ERRNO_BASE + 618,
	CN_NCS_TEMPLATE_DESTROY_USER_INVALID =   SBTS_ERRNO_BASE + 619,
	CN_NCS_PORT_OB_DISABLED	=                SBTS_ERRNO_BASE + 620,
	CN_NCS_PORT_IB_DISABLED =                SBTS_ERRNO_BASE + 621,
	CN_NCS_PORT_DISABLED =                   SBTS_ERRNO_BASE + 622,

	CN_NCS_UNSUPPORT =                       SBTS_ERRNO_BASE + 623,

	NCS_QP_GET_RES_LQP_INVALID =             SBTS_ERRNO_BASE + 624,
	NCS_QP_CREATE_DIRBUFF_INVALID =		 SBTS_ERRNO_BASE + 625,
	NCS_QP_IS_INJECTING_ERR =                SBTS_ERRNO_BASE + 626,

	CN_TCDP_OP_SUCCESS =                     SBTS_ERRNO_BASE + 700,

	CN_TCDP_NO_RESOURCE =                    SBTS_ERRNO_BASE + 701,
	CN_TCDP_INVALID_PARAM =                  SBTS_ERRNO_BASE + 702,
	CN_TCDP_SLOT_NOT_EXISTS =                SBTS_ERRNO_BASE + 703,
	CN_TCDP_USER_INVALID =                   SBTS_ERRNO_BASE + 704,
	CN_TCDP_QP_BUSY =                        SBTS_ERRNO_BASE + 705,

	CN_TCDP_UNSUPPORT =                      SBTS_ERRNO_BASE + 706,

	CN_TCDP_OUT_OF_MEM =                     SBTS_ERRNO_BASE + 750,
	CN_TCDP_HANDLE_BUSY =                    SBTS_ERRNO_BASE + 751,

	CN_TCDP_END =                            SBTS_ERRNO_BASE + 799,

	/* ncs stream sync err code, note: must not edit */
	CN_NCS_ACK_TASK_TIMEOUT =                SBTS_ERRNO_BASE + 810,
	CN_NCS_ACK_QP_INVALID =                  SBTS_ERRNO_BASE + 811,
	CN_NCS_ACK_QP_BUSY =                     SBTS_ERRNO_BASE + 812,
	CN_NCS_ACK_QP_NOT_EXISTS =               SBTS_ERRNO_BASE + 813,
	CN_NCS_ACK_TEMPLATE_INVALID =            SBTS_ERRNO_BASE + 814,
	CN_NCS_ACK_TEMPLATE_NOT_EXISTS =         SBTS_ERRNO_BASE + 815,
	CN_NCS_ACK_PARAM_INVALID =               SBTS_ERRNO_BASE + 816,
	CN_NCS_ACK_DECS_CNT_ERR =                SBTS_ERRNO_BASE + 817,
	CN_NCS_ACK_SRC_ADDR_ERR =                SBTS_ERRNO_BASE + 818,
	CN_NCS_ACK_DST_ADDR_ERR =                SBTS_ERRNO_BASE + 819,
	CN_NCS_ACK_KERNEL_ERR =                  SBTS_ERRNO_BASE + 820,
	CN_NCS_ACK_TRIGGER_CNT_ERR =             SBTS_ERRNO_BASE + 821,
	CN_NCS_ACK_REMOTE_ERR =                  SBTS_ERRNO_BASE + 822,
	CN_NCS_ACK_LINK_UNCORR_ERR =             SBTS_ERRNO_BASE + 823,
	CN_NCS_ACK_LINK_ERR =                    SBTS_ERRNO_BASE + 824,
	CN_NCS_ACK_TASK_EXIST =                  SBTS_ERRNO_BASE + 825,
	CN_NCS_ACK_TASK_TYPE_INVALID =           SBTS_ERRNO_BASE + 826,
	CN_NCS_ACK_DESC_NOT_MATCH =              SBTS_ERRNO_BASE + 827,

	CN_NCS_RET_CODE_END =                    SBTS_ERRNO_BASE + 849,

	/* tcdp stream sync err code, note: must not edit */
	CN_TCDP_ACK_TCDP_HANDLE_INVALID =        SBTS_ERRNO_BASE + 850,
	CN_TCDP_ACK_TCDP_NO_RESOURCE =		 SBTS_ERRNO_BASE + 851,
	CN_TCDP_ACK_TCDP_RESEND_EXCEED_MAX_NUM = SBTS_ERRNO_BASE + 852,

	CN_TCDP_RET_CODE_END =                   SBTS_ERRNO_BASE + 900,
};

#endif /* _SBTS_ERRNO_H */
