#ifndef __CAMBRICON_MM_EXT_REMAP_H__
#define __CAMBRICON_MM_EXT_REMAP_H__

#include"camb_vmm.h"


struct camb_handle_ref {
	struct list_head node;
	unsigned long handle;   /* handle id after udvm encode */
	unsigned long size;
	atomic_t     refcnt;    /* refcnt used to protect physical handle validate */
	struct cn_mm_set *mm_set; /*for camb_extn_mem_release*/
	struct extn_priv_data *extn_priv; /*for __handle_ref_kref_put*/
};

/* RPC command and its structure */
enum extn_ctl_cmd {
	EXTN_MEM_HANDLE_GET_BY_FD = 0x1,
	EXTN_MEM_HANDLE_PUT = 0x2,
	EXTN_MEM_MAP     = 0x3,
	EXTN_MEM_UNMAP   = 0x4,
};

struct extn_ctl_t {
	unsigned long handle;
	unsigned long iova;
	unsigned long size;
	unsigned int cmd;
	unsigned int fd;
	unsigned int  prot;
};

#endif
