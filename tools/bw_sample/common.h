#ifndef __COMMON_H
#define __COMMON_H

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <linux/types.h>
#include <asm/ioctl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <stdbool.h>

#include "cndrv_ioctl.h"
#include "cndrv_monitor_usr.h"

#define MAX_PHYS_CARD  128
#define ERR_PRT(string, arg...) printf("[%s][%d]" string "\n", \
		(char *)__func__, __LINE__, ##arg)

int open_mem_dev(void);
void close_mem_dev(int pin_fd);
int get_card_num(int pin_fd);
int open_cambricon_dev(int id);
void close_cambricon_dev(int fd);
int open_cambricon_cap(int id, int *cap_fd);
void close_cambricon_cap(int *cap_fd);
int get_card_bdf(int fd, char *bdf);
int alloc_dev_memory(int fd, uint64_t *addr,int size);

int mlu_memset_D8_async(int fd, __u64 addr, __u8 val, size_t size, void *hqueue);
int mlu_memset_D8(int fd, __u64 addr, __u8 val, size_t size);
int mlu_memset_D16_async(int fd, __u64 addr, __u16 val, size_t size, void *hqueue);
int mlu_memset_D16(int fd, __u64 addr, __u16 val, size_t size);
int mlu_memset_D32_async(int fd, __u64 addr, __u32 val, size_t size, void *hqueue);
int mlu_memset_D32(int fd, __u64 addr, __u32 val, size_t size);

void free_dev_memory(int fd, __u64 addr);
void *pinned_mem_alloc(int pin_fd, int size);
void pinned_mem_free(int pin_fd, char *va);

int p2p_able(int fd, int peer_fd);
int h2d(int fd, __u64 addr, char *buf, int size);
int d2h(int fd, __u64 addr, char *buf, int size);
int d2d(int fd, __u64 src_addr, __u64 dst_addr, __u64 size);
int p2p(int fd, int peer_fd, __u64 dst_addr, __u64 src_addr, __u64 size);
int async_h2d(int fd, __u64 addr, char *buf, int size, void *hstream);
int async_d2h(int fd, __u64 addr, char *buf, int size, void *hstream);
int async_d2d(int fd, __u64 src_addr, __u64 dst_addr, __u64 size, void *hstream);
int async_p2p(int fd, int peer_fd, __u64 dst_addr, __u64 src_addr, void *hstream, __u64 size);

int create_queue(int fd, void **hqueue, int flags);
int destroy_queue(int fd, void *hqueue);
int sync_queue(int fd, void *hqueue);
int create_notifier(int fd, void **hnotifier, int flags);
int destroy_notifier(int fd, void *hnotifier);
int place_notifier(int fd, void *hnotifier, void *hqueue);
int elapsed_swtime_notifier(int fd, struct timeval *ptv, void *hstart, void *hend);

/* new define */
typedef struct {
    uint64_t x;
    /*!< The offset in the x direction.*/
    uint64_t y;
    /*!< The offset in the y direction.*/
    uint64_t z;
    /*!< The offset in the z direction.*/
} pos;

typedef struct {
    uint64_t pitch;
    /*!< The pitch of the memory. It cannot be less than the p->extent.width,
            and must be smaller than 4MB. It can be 0.*/
    void *ptr;
    /*!< The pointer of the memory. The same as the p->dst.*/
    uint64_t xsize;
    /*!< The memory x size. It is not in use currently,
            which is set to p->extent.width.*/
    uint64_t ysize;
    /*!< The memory y size. It cannot be less than the p->extent.height.*/
} pitchedPtr;

typedef struct {
    uint64_t depth;
    /*!< The depth of the memory.*/
    uint64_t height;
    /*!< The height of the memory. It cannot be greater than 1MB.*/
    uint64_t width;
    /*!< The width of the memory. It cannot be greater than 1MB.*/
} type_extent;

typedef struct memcpy3dParam_st {
    void *dst;
    /*!< The destination address.*/
    pos dstPos;
    /*!< The destination address position.*/
    pitchedPtr dstPtr;
    /*!< The pitch of the destination address.*/
    type_extent extent;
    /*!< The extent of the memory.*/
    uint32_t dir;
    /*!< Data copy direction.*/
    void *src;
    /*!< The source address.*/
    pos srcPos;
    /*!< The source address position.*/
    pitchedPtr srcPtr;
    /*!< The pitch of the source address.*/
} memcpy3dParam;












#endif
