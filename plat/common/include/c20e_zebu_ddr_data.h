//*************************************************************************
//   File Name: regconfig_ddrc.h
//   Author: luoming
//   Description:
//   Created Time: Tue 26 Feb 2019 08:50:59 PM CST
// ************************************************************************/

#ifndef __C20E_ZEBU_DDR_INIT__
#define __C20E_ZEBU_DDR_INIT__

#define  FREQ0_MSTR           0x03080020
#define  FREQ0_MRCTRL0        0x00005030
#define  FREQ0_MRCTRL1        0x0001ab3d
#define  FREQ0_DERATEEN       0x00001303
#define  FREQ0_DERATEINT      0xa5265b31
#define  FREQ0_DERATECTL      0x00000001
#define  FREQ0_PWRCTL         0x08        //dingtian edit for zebu
#define  FREQ0_PWRTMG         0x00081603
#define  FREQ0_HWLPCTL        0x00950001
#define  FREQ0_RFSHCTL0       0x00002014 //luoming enable per bank ref
#define  FREQ0_RFSHCTL1       0x00060063
#define  FREQ0_RFSHTMG        0x01c48106 //luoming per bank ref 488/2/tCK(0.54) =452(1C4)
#define  FREQ0_RFSHCTL3       0x00000002 //luoming toggle refresh_updata_level
#define  FREQ0_RFSHTMG1       0x00540000
#define  FREQ0_CRCPARCTL0     0x00000000
#define  FREQ0_INIT0          0x00030002  //dingtian edit for zebu
#define  FREQ0_INIT1          0x0001000c
#define  FREQ0_INIT2          0x0000b605
#define  FREQ0_INIT3          0x00640036  //{MR1,MR2} for LPDDR4
#define  FREQ0_INIT4          0x00c00000  // DBI on MR3[7:6]=2'b11
#define  FREQ0_INIT5          0x0004000b
#define  FREQ0_INIT6          0x0002004d
#define  FREQ0_INIT7          0x0000004d
#define  FREQ0_DIMMCTL        0x00000000
#define  FREQ0_RANKCTL        0x0000e735
#define  FREQ0_DRAMTMG0       0x1e263f28
#define  FREQ0_DRAMTMG1       0x00070838 //WJN 190316 modify RD2PRE, 13.988
#define  FREQ0_DRAMTMG2       0x08121d1a // due to DBIon, RL update to 36
#define  FREQ0_DRAMTMG3       0x00d0e000
#define  FREQ0_DRAMTMG4       0x11040a11
#define  FREQ0_DRAMTMG5       0x080e0e0e
#define  FREQ0_DRAMTMG6       0x020f0009
#define  FREQ0_DRAMTMG7       0x00000d05
#define  FREQ0_DRAMTMG8       0x00000101
#define  FREQ0_DRAMTMG12      0x00020000
#define  FREQ0_DRAMTMG13      0x0d100002
#define  FREQ0_DRAMTMG14      0x0000010c
#define  FREQ0_DRAMTMG15      0x80000000
#define  FREQ0_ZQCTL0         0x03a5001c
#define  FREQ0_ZQCTL1         0x02f00070
#define  FREQ0_ZQCTL2         0x00000000
#define  FREQ0_DFITMG0        0x049b820c  //due to DBIon, RL update to 36, tphy_rddata_en update to 31=0x1f
#define  FREQ0_DFITMG1        0x00090303
#define  FREQ0_DFILPCFG0      0x03b12101
#define  FREQ0_DFIUPD0        0xe0400018
#define  FREQ0_DFIUPD1        0x00ae00b9
#define  FREQ0_DFIUPD2        0x80000000
#define  FREQ0_DFIMISC        0x00000011
#define  FREQ0_DFITMG2        0x00001f0c   //due to DBIon, RL update to 36, tphy_rdcslat update  to 31=0x1f
#define  FREQ0_DBICTL         0x00000007  //luoming close dm
#define  FREQ0_DFIPHYMSTR     0x00000000

#ifdef NO_FIX_ADDR_BUG
 // dch(axi_addr[32],cs_bit1xxx,cs_bit0(axi_addr[31])
#define  FREQ0_ADDRMAP0       0x1d0018
#else
#define  FREQ0_ADDRMAP0       0x1d0017
#endif
 // bank_b2,b1,b0(axi_addr[13:11])
#define  FREQ0_ADDRMAP1       0x080808
 // map axi_addr[10:3] to col[9:2]
 // col_b5,b4,b3,b2
#define  FREQ0_ADDRMAP2       0x00000000
 // col_b9,b8,b7,b6
#define  FREQ0_ADDRMAP3       0x00000000
 // col_b11,b10(not for LPDDR4)
#define  FREQ0_ADDRMAP4       0x1f1f
 // map axi_addr[30:14] to row[16:0]
 // row b11,b2_b10,b1,b0
#define  FREQ0_ADDRMAP5       0x07070707
 // lpddr4_3g6g12g,row_b15,b14,b2
 // not suport 3g 6g 12g
#define  FREQ0_ADDRMAP6       0x07070707
 //`define  FREQ0_ADDRMAP6       32'h2707_0707
#ifdef NO_FIX_ADDR_BUG
 // row_b17,b16
#define  FREQ0_ADDRMAP7       0x0707
#else
#define  FREQ0_ADDRMAP7       0x0f0f
#endif
 // not used since ADDRMAP5 bit2_b10 is not set to F
#define  FREQ0_ADDRMAP9       0x6040502
#define  FREQ0_ADDRMAP10      0x900000b
#define  FREQ0_ADDRMAP11      0xb

//`define  FREQ0_ADDRMAP0       32'h00000016
//`define  FREQ0_ADDRMAP1       32'h00061802
//`define  FREQ0_ADDRMAP2       32'h00050000
//`define  FREQ0_ADDRMAP3       32'h03030100
//`define  FREQ0_ADDRMAP4       32'h00001f1f
//`define  FREQ0_ADDRMAP5       32'h09060007
//`define  FREQ0_ADDRMAP6       32'h43090407
//`define  FREQ0_ADDRMAP7       32'h0000000f
//`define  FREQ0_ADDRMAP9       32'h090a0400
//`define  FREQ0_ADDRMAP10      32'h00030509
//`define  FREQ0_ADDRMAP11      32'h00000002
//
#define  FREQ0_ODTCFG         0x0d18022c
#define  FREQ0_ODTMAP         0x00000000
#define  FREQ0_SCHED          0x1bc4b5d8
#define  FREQ0_SCHED1         0x2300f015
#define  FREQ0_PERFHPR1       0x1c00dc81
#define  FREQ0_PERFLPR1       0xd20050ff
#define  FREQ0_PERFWR1        0x6200b02f
#define  FREQ0_SCHED3         0x3c3a2b38
#define  FREQ0_SCHED4         0x6f18bc00
#define  FREQ0_DBG0           0x00000007
#define  FREQ0_DBG1           0x00000000
#define  FREQ0_DBGCMD         0x00000000
#define  FREQ0_SWCTL          0x00000001
#define  FREQ0_SWCTLSTATIC    0x00000000
#define  FREQ0_POISONCFG      0x00010001
#define  FREQ0_PCCFG          0x00000110
#define  FREQ0_PCFGR_0        0x000062d3
#define  FREQ0_PCFGW_0        0x00001162
#define  FREQ0_PCTRL_0        0x00000001
#define  FREQ0_PCFGQOS0_0     0x00100007


#define  FREQ1_DERATEEN       0x00001303
#define  FREQ1_DERATEINT      0xa5265b31
#define  FREQ1_PWRTMG         0x00081603
#define  FREQ1_RFSHCTL0       0x00002010
#define  FREQ1_RFSHTMG        0x00718106
#define  FREQ1_RFSHTMG1       0x00540000
#define  FREQ1_INIT3          0x00640036
#define  FREQ1_INIT4          0x00f20000
#define  FREQ1_INIT6          0x0002004d
#define  FREQ1_INIT7          0x0000004d
#define  FREQ1_RANKCTL        0x0000a735
#define  FREQ1_DRAMTMG0       0x1e263f28
#define  FREQ1_DRAMTMG1       0x00070738
#define  FREQ1_DRAMTMG2       0x08121b1a
#define  FREQ1_DRAMTMG3       0x00d0e000
#define  FREQ1_DRAMTMG4       0x11040a11
#define  FREQ1_DRAMTMG5       0x080e0e0e
#define  FREQ1_DRAMTMG6       0x020f0009
#define  FREQ1_DRAMTMG7       0x00000d05
#define  FREQ1_DRAMTMG8       0x00000101
#define  FREQ1_DRAMTMG12      0x00020000
#define  FREQ1_DRAMTMG13      0x0d100002
#define  FREQ1_DRAMTMG14      0x0000010c
#define  FREQ1_DRAMTMG15      0x80000000
#define  FREQ1_ZQCTL0         0x03a5001c
#define  FREQ1_DFITMG0        0x049f820c
#define  FREQ1_DFITMG1        0x00090303
#define  FREQ1_DFITMG2        0x00001f0c
#define  FREQ1_ODTCFG         0x0d18022c

#endif // __C20E_ZEBU_DDR_INIT____
