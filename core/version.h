#ifndef __CNDRV_CORE_VERSION_H_
#define __CNDRV_CORE_VERSION_H_
/*
 * The encoding of driver version is illustrated below.
 * +--------------+---------------+-------+-------+------+-----+
 * |   Bits 63:52 | 51:40 | 39:32 | 31:25 | 24:16 |    15:0    |
 * +--------------+---------------+-------+-------+------+-----+
 *          |         |       |       |       |          |
 *          |         |       |       |       |          +--<DRV_VERSION>
 *          |         |       |       |       +--- <CHIP>
 *          |         |       |       +----- <RESERVED>
 *          |         |       +------- <PROJ>
 *          |         +--------- <RESERVED>
 *          +--------------- <VENDOR>
 */

#define DRV_MAJOR (5)
#define DRV_MINOR (10)
#define DRV_BUILD (22)

/*CAMBRICON*/
#define VENDOR_CAMBRICON	(0x00)
/*PROJECT*/
#define C00_PROJ		(0x00)
#define C10_PROJ		(0x01)
#define C20L_PROJ		(0x02)
#define C20E_PROJ		(0x03)
#define C20E_EDGE_PROJ		(0x04)
#define C20_PROJ		(0x05)
#define C30S_PROJ		(0x06)
#define CE3226_EDGE_PROJ		(0x07)
#define CE3226_PROJ		(0x08)
#define C30S_ARM_PROJ		(0x09)
#define C50_PROJ		(0x0a)
#define C50_ARM_PROJ		(0x0b)
#define PIGEON_EDGE_PROJ	(0x0c)
#define PIGEON_PROJ		(0x0d)
#define C50S_PROJ	(0x0e)
#define C50S_ARM_PROJ		(0x0f)
#define C60_PROJ		(0x11)
#define C60_ARM_PROJ		(0x12)

/*CHIP VERSION*/
#define CHIP_V1_0_ES		(0x0)
/*DRIVER VERSION*/
#define DRV_VERSION		(DRV_MAJOR * 100 + DRV_MINOR)

/*OLD DRIVER VERSION*/
#define DRV_V1_0		(0)

#define MLU_VENDOR_BIT				(52 - 32)
#define MLU_VENDOR_MASK				(0xFFF)

#define MLU_PROJECT_BIT				(32 - 32)
#define MLU_PROJECT_MASK			(0xFF)

#define MLU_CHIP_VERSION_BIT		(16)
#define MLU_CHIP_VERSION_MASK		(0xFF)

#define MLU_DRIVER_VERSION_BIT		(0)
#define MLU_DRIVER_VERSION_MASK		(0xFFFF)

#define VENDOR_TO_SERIAL(s)		((s & MLU_VENDOR_MASK) \
						<< MLU_VENDOR_BIT)
#define PROJ_TO_SERIAL(s)		((s & MLU_PROJECT_MASK) \
						<< MLU_PROJECT_BIT)
#define CHIPVERSION_TO_SERIAL(s)	((s & MLU_CHIP_VERSION_MASK) \
						<< MLU_CHIP_VERSION_BIT)
#define DRVVERSION_TO_SERIAL(s)		((s & MLU_DRIVER_VERSION_MASK) \
						<< MLU_DRIVER_VERSION_BIT)

#define SUPPORT_API_VER_LOW_MAJOR 2
#define SUPPORT_API_VER_LOW_MINOR 7
#define SUPPORT_API_VER_LOW_BUILD 0

#define SUPPORT_API_VER_HIGH_MAJOR  3
#define SUPPORT_API_VER_HIGH_MINOR  0
#define SUPPORT_API_VER_HIGH_BUILD  0

enum mluCoreVersion {
	_1A		= 0x00010009,
	_1H8MINI	= 0x00020004,
	_1H8		= 0x00020005,
	_1H16		= 0x00020009,
	_1M		= 0x00030009,
	_1V		= 0x00040001,
};

#endif /* __CNDRV_CORE_VERSION_H_ */
