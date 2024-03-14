#ifndef __GDR_DRV_H__
#define __GDR_DRV_H__

#define GDRDRV_STRINGIFY(s)           #s
#define GDRDRV_TOSTRING(s)            GDRDRV_STRINGIFY(s)

#define GDRDRV_MAJOR_VERSION    2
#define GDRDRV_MINOR_VERSION    3
#define GDRDRV_VERSION          ((GDRDRV_MAJOR_VERSION << 16) | GDRDRV_MINOR_VERSION)
#define GDRDRV_VERSION_STRING   GDRDRV_TOSTRING(GDRDRV_MAJOR_VERSION) "." GDRDRV_TOSTRING(GDRDRV_MINOR_VERSION)

#define MINIMUM_GDR_API_MAJOR_VERSION   2
#define MINIMUM_GDR_API_MINOR_VERSION   0
#define MINIMUM_GDR_API_VERSION         ((MINIMUM_GDR_API_MAJOR_VERSION << 16) | MINIMUM_GDR_API_MINOR_VERSION)

#define GDRDRV_IOCTL                 0xDA

typedef __u64 gdr_hnd_t;

//-----------

struct GDRDRV_IOC_PIN_BUFFER_PARAMS {
	// in
	__u64 addr;
	__u64 size;
	__u64 p2p_token;
	__u32 va_space;
	// out
	gdr_hnd_t handle;
};

#define GDRDRV_IOC_PIN_BUFFER _IOWR(GDRDRV_IOCTL, 1, struct GDRDRV_IOC_PIN_BUFFER_PARAMS)

//-----------

struct GDRDRV_IOC_UNPIN_BUFFER_PARAMS {
	// in
	gdr_hnd_t handle;
};

#define GDRDRV_IOC_UNPIN_BUFFER _IOWR(GDRDRV_IOCTL, 2, struct GDRDRV_IOC_UNPIN_BUFFER_PARAMS *)

//-----------

struct GDRDRV_IOC_GET_CB_FLAG_PARAMS {
	// in
	gdr_hnd_t handle;
	// out
	__u32 flag;
};

#define GDRDRV_IOC_GET_CB_FLAG _IOWR(GDRDRV_IOCTL, 3, struct GDRDRV_IOC_GET_CB_FLAG_PARAMS *)

//-----------

struct GDRDRV_IOC_GET_INFO_PARAMS {
	// in
	gdr_hnd_t handle;
	// out
	__u64 va;
	__u64 mapped_size;
	__u32 page_size;
	__u32 tsc_khz;
	__u64 tm_cycles;
	__u32 mapped;
	__u32 wc_mapping;
};

#define GDRDRV_IOC_GET_INFO _IOWR(GDRDRV_IOCTL, 4, struct GDRDRV_IOC_GET_INFO_PARAMS *)

//-----------

struct GDRDRV_IOC_GET_VERSION_PARAMS {
	// out
	__u32 gdrdrv_version;
	__u32 minimum_gdr_api_version;
};

#define GDRDRV_IOC_GET_VERSION _IOWR(GDRDRV_IOCTL, 255, struct GDRDRV_IOC_GET_VERSION_PARAMS *)

//-----------

#endif // __GDR_DRV_H__
