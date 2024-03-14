#include <stdio.h>
#include <sched.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "pthread.h"
#include "common.h"
#include "helper_string.h"
#ifndef NUMA_DISABLE
#include <numa.h>
#endif

#define DEFAULT_THREAD_REPEAT_NUM 100
#define DEFAULT_SIZE 0x2000000
#define ALIGNED_SIZE 0x40
#define MAX_THREAD_NUM 1024
#define MAX_REPEAT_NUM 1000

int pin_fd;
enum dma_dir_type {
	DMA_D2H = 0,
	DMA_H2D,
	DMA_D2D,
	DMA_MEMSET,
	DMA_BOTHWAY,
	DMA_D2D_2D,
	DMA_D2D_3D,
};

#define MEMSET_D8 (8)
#define MEMSET_D16 (16)
#define MEMSET_D32 (32)
#define DEFAULT_MEMSET_WIDTH MEMSET_D8

/**
 * D2D_2D
 *	#1 each thread has special dst/src dev_addr and will be recorded into thread_handle_2d
 *	#2 For 2D the param_width shall LE 1M
 *	#3 width  : dim1_len  dim2_stride(pitch)  <= MAX_2D_WIDTH (1M)
 *	#4 height : dim2_len
 *	#5 total  : dim1_len * dim2_len           <= MAX_2D_TOTAL (16M)
 *	#6 len(size) = width * height
 *
 *	Logic:  width default = 0x10
 *
 *		F_left_shift(width) ...  <= 1M || <= size/2  {The Half As Shift Edge}
 *		height = size/width
 * D2D_3D
 *	#1 SAME ABOVE
 *	#2 For 3D the param_width shall LE 1M
 *	#3 width  : dim1_len  dim2_stride(pitch)     <= MAX_3D_WIDTH (1M)
 *	#4 height : dim2_len  dim3_stride(pitch)     <= MAX_3D_HEIGHT (1M)
 *	#5 depth  : dim3_len
 *	#6 total  : dim1_len * dim2_len * dim3_len   <= MAX_3D_TOTAL (16M)
 *	#7 len(size) = width * height * depth
 *
 *	Logic:	depth default = 2
 *		width default = 0x10/depth
 *
 *		F_left_shift（width) ... <= 1M && <= size/depth/2  {The Half As Shift Edge: except depth}
 *		height = size/depth/width
 */
#define MAX_2D_WIDTH  (0x100000)
#define MAX_2D_TOTAL  (0x1000000)
#define MAX_3D_WIDTH  (0x100000)
#define MAX_3D_HEIGHT (0x100000)
#define MAX_3D_TOTAL  (0x1000000)
#define DEFAULT_3D_DEPTH (2)      /*Fixed Value, Tests result shows depth have no great effect on BW.*/
#define DEFAULT_MDIM_WIDTH (0x10)
#define MAX_WIDTH_LEFT_SHIFT (32)
struct thread_handle_multi_dim {
	pthread_t id;
	int num; /*The number to record the thread index used in table*/
	uint64_t dev;
	int fd;
	uint64_t dev_src;
	uint64_t dev_dst;
	char *host_src;
	char *host_dst;

	uint64_t len; /*The total real transfer bytes count*/

	/*param 2D specially*/
	uint64_t dpitch;
	uint64_t spitch;
	uint64_t width;
	uint64_t height;
	/*param 3D specially*/
	memcpy3dParam param_3d;
};
struct run_time_multi_dim {
	uint64_t dev;
	int fd;

	uint64_t dev_src;
	uint64_t dev_dst;
	char *host_src;
	char *host_dst;
	uint64_t total_size; /*The SUM of all thread's size*/

	int multi_dim_type;  /*User setting about D2D : 2D or 3D*/
	int thrd_num;	/*User setting about thread number*/
	unsigned long thrd_size;  /*User setting about copy sizei of each thread*/
	struct thread_handle_multi_dim thrds[MAX_THREAD_NUM];
	bool noaligned;
};


/***
 * Attention:
 *	The D2D_2D/3D not support Async Mode.
 */
#define D2D_2D_ASYNC_SPT  (0)
#define D2D_3D_ASYNC_SPT  (0)
#define IF_D2D_2D_TEST(mode)   (((mode) == ASYNC_MODE)?D2D_2D_ASYNC_SPT:1)
#define IF_D2D_3D_TEST(mode)   (((mode) == ASYNC_MODE)?D2D_3D_ASYNC_SPT:1)

enum dmaMode { SYNC_MODE, ASYNC_MODE, ASYNC_NO_BATCH_MODE };
enum testMode { QUICK_MODE, RANGE_MODE, SHMOO_MODE, SMALL_SHMOO_MODE };
enum memoryMode { PINNED, PAGEABLE };
enum varianceMode { NO_NEED_MODE, THREAD_MODE, REPEAT_MODE };
enum latencyMode { HW_LATENCY_MODE, SW_LATENCY_MODE, API_LATENCY_MODE };
int cpu_num;

#define MLU_CHECK(func) \
({ \
	int ret = func; \
	if (ret) { \
		printf("%s@%d %s return %d FAILED\n", __func__, __LINE__, #func, ret); \
		exit(-1); \
	} \
})

#define data_prt(string, arg...) do {  \
	FILE *fp; \
	char file_name[50]; \
	sprintf(file_name, "bandwidth_data");\
	fp = fopen(file_name, "aw+");\
	fseek(fp, 0, SEEK_END); \
	fprintf(fp, string, ##arg); \
	fclose(fp); \
	printf(string, ##arg); \
} while (0)

struct cmd_line_struct {
	enum memoryMode mem_mode;
	bool h2d;
	bool d2h;
	bool d2d;
	bool memset;
	bool bothway;
	bool d2d_2d;
	bool d2d_3d;
	unsigned int start;
	unsigned int end;
	unsigned int increment;
	enum testMode mode;
	unsigned int thread_num;
	enum dmaMode dma_mode;
	enum varianceMode variance;
	unsigned int repeat_num;
	unsigned int th_repeat_num;
	double sta_range;
	enum latencyMode latency_mode;
	bool cpu_numa;
	bool mem_numa;
	/*Multi Dim Setting*/
	int width_shift;
	unsigned long width;
	unsigned long depth;
	bool noaligned;
	/*Memset Width*/
	unsigned long memset_width;
};

struct dma_bw_struct {
	int fd;
	uint64_t dev_addr_0;
	uint64_t dev_addr_1;
	void *host_addr;
	unsigned long size;
	void *queue;
	struct timeval stime;
	struct timeval etime;
	int th_id;
	enum dma_dir_type dir;
	unsigned int th_repeat_num;
	double bw;
	void *info;
};

struct bw_result_struct {
	double h2d_bw;
	double d2h_bw;
	double h2d_th_variance;
	double d2h_th_variance;
	double latency;
};

struct dma_test_struct {
	int card_id;
	char bdf[64];
	int numa_node;
	uint64_t dev;
	int fd;
	uint64_t dev_addr_0;
	uint64_t dev_addr_1;
	void *host_addr;
	unsigned long size;
	enum dma_dir_type dir;
	struct cmd_line_struct cmd;
	int th_id;
	struct dma_bw_struct bw_set[MAX_THREAD_NUM];
	struct bw_result_struct result[MAX_REPEAT_NUM];
	int repeat_id;
	double h2d_bw;
	double d2h_bw;
	double h2d_bw_min;
	double d2h_bw_min;
	double h2d_bw_max;
	double d2h_bw_max;
	double h2d_variance;
	double d2h_variance;
	double h2d_sta_score;
	double d2h_sta_score;
	double latency;
	double latency_min;
	double latency_max;
	double latency_variance;
	double latency_sta_score;
	int multicard_test;

	int width_shift; /*0x10 SHIFT 0x100000*/
	unsigned long width;  /*width init value default 0x10*/
	unsigned long depth;  /*depth init value defualt 0x04*/
	unsigned long width_rcd; /*Record W/H/D change status*/
	unsigned long height_rcd;
	unsigned long depth_rcd;
	struct run_time_multi_dim multi_dim_set; /*The multi dim setting of one card*/
};

static void _fill_rtmd_baseon_info(struct dma_test_struct *info)
{
	info->multi_dim_set.dev = info->dev;
	info->multi_dim_set.fd = info->fd; /*keep same with top info*/
	info->multi_dim_set.thrd_size = info->size;
	info->multi_dim_set.multi_dim_type = info->dir;
	info->multi_dim_set.thrd_num = info->cmd.thread_num;
	info->width_shift = info->cmd.width_shift;
	info->width = info->cmd.width;
	info->depth = info->cmd.depth;
}
static int _alloc_resource(struct run_time_multi_dim *mdim, int fd)
{
	int result;
	int i = 0;
	struct thread_handle_multi_dim *thrd = NULL;

	/**
	 * prepare source for each job thread
	 *	memory buff : host_src  dev_src/dev_dst
	 *	context
	 */
	for (i = 0; i < mdim->thrd_num; i++) {
		thrd = mdim->thrds + i;
		thrd->dev = mdim->dev;
		thrd->len = mdim->thrd_size;
		if (mdim->noaligned) {
			thrd->host_src = (char *)malloc(mdim->thrd_size + ALIGNED_SIZE);
			if (!thrd->host_src) {
				printf("thrd %d alloc host_src FAILED\n", i);
				goto failed_exit;
			}

			thrd->host_dst = (char *)malloc(mdim->thrd_size + ALIGNED_SIZE);
			if (!thrd->host_dst) {
				printf("thrd %d alloc host dst FAILED\n", i);
				goto failed_exit;
			}

			result = alloc_dev_memory(fd, &thrd->dev_src, mdim->thrd_size + ALIGNED_SIZE);
			if (result != 0) {
				printf("thrd %d alloc dev_src with %d,FAILED\n", i, result);
				goto failed_exit;
			}

			result = alloc_dev_memory(fd, &thrd->dev_dst, mdim->thrd_size + ALIGNED_SIZE);
			if (result != 0) {
				printf("thrd %d alloc dev_dst with %d,FAILED\n", i, result);
				goto failed_exit;
			}
		} else {
			thrd->host_src = (char *)malloc(mdim->thrd_size);
			if (!thrd->host_src) {
				printf("thrd %d alloc host_src FAILED\n", i);
				goto failed_exit;
			}

			thrd->host_dst = (char *)malloc(mdim->thrd_size);
			if (!thrd->host_dst) {
				printf("thrd %d alloc host dst FAILED\n", i);
				goto failed_exit;
			}

			result = alloc_dev_memory(fd, &thrd->dev_src, mdim->thrd_size);
			if (result != 0) {
				printf("thrd %d alloc dev_src with %d,FAILED\n", i, result);
				goto failed_exit;
			}

			result = alloc_dev_memory(fd, &thrd->dev_dst, mdim->thrd_size);
			if (result != 0) {
				printf("thrd %d alloc dev_dst with %d,FAILED\n", i, result);
				goto failed_exit;
			}
		}
		/*Do Not Create new thread AND Note the Create will defaultly call SetCtx.*/
		thrd->fd = mdim->fd;
	}

	return 0;

failed_exit:

	for (i = 0; i < mdim->thrd_num; i++) {
		thrd = mdim->thrds + i;

		if (thrd->host_src) {
			free(thrd->host_src);
		}

		if (thrd->host_dst) {
			free(thrd->host_dst);
		}

		if (thrd->dev_src) {
			free_dev_memory(fd, thrd->dev_src);
		}

		if (thrd->dev_dst) {
			free_dev_memory(fd, thrd->dev_dst);
		}
	}

	return -1;
}

static int _release_resource(struct run_time_multi_dim *mdim, int fd)
{
	int i = 0;
	struct thread_handle_multi_dim *thrd = NULL;
	int result;

	for (i = 0; i < mdim->thrd_num; i++) {
		thrd = mdim->thrds + i;

		if (thrd->host_src) {
			free(thrd->host_src);
		}

		if (thrd->host_dst) {
			free(thrd->host_dst);
		}

		if (thrd->dev_src) {
			free_dev_memory(fd, thrd->dev_src);
		}

		if (thrd->dev_dst) {
			free_dev_memory(fd, thrd->dev_dst);
		}
	}

	return 0;
}

static void _prepare_2d_param(struct dma_test_struct *info)
{
	int i;
	struct thread_handle_multi_dim *thrd = NULL;
	struct run_time_multi_dim *rtmd = NULL;

	if (info->dir != DMA_D2D_2D) {
		return;
	}

	rtmd = &info->multi_dim_set;
	/**
	 * 2D:
	 *	width/pitch  height
	 *
	 * IF : ((!width) || (!height) || (width > dpitch) || (width > spitch) ||
	 *	 (width > (1 << 20))   ||
	 *	 (dpitch >= (1 << 22)) ||
	 *	 (spitch >= (1 << 22)) ||
	 *	 (width * height) > (1 << 24))
	 *
	 * THEN	: ret = CN_ERROR_INVALID_VALUE
	 *
	 */
	rtmd->noaligned = info->cmd.noaligned;
	for (i = 0; i < rtmd->thrd_num; i++) {
		thrd = rtmd->thrds + i;
		thrd->len = info->width_rcd * info->height_rcd;

		thrd->width = info->width_rcd;
		thrd->spitch = info->width_rcd;
		thrd->dpitch = info->width_rcd;
		thrd->height = info->height_rcd;
	}
}

static void _prepare_3d_param(struct dma_test_struct *info)
{
	int i;
	struct thread_handle_multi_dim *thrd = NULL;
	struct run_time_multi_dim *rtmd = NULL;

	if (info->dir != DMA_D2D_3D) {
		return;
	}

	rtmd = &info->multi_dim_set;
	/**
	 * width/pitch  height/pitch  depth
	 * IF : ((!pst->extent.width) || (!pst->extent.height) || (!pst->extent.depth) ||
	 *	 (!pst->dstPtr.ysize) || (!pst->srcPtr.ysize) || (pst->extent.width > pst->dstPtr.pitch) ||
	 *	 (pst->extent.width > pst->srcPtr.pitch) || (pst->extent.height > pst->dstPtr.ysize) ||
	 *	 (pst->extent.height > pst->srcPtr.ysize) ||
	 *	 (pst->extent.width > (1 << 20))  ||
	 *	 (pst->extent.height > (1 << 20)) ||
	 *	 (pst->dstPtr.pitch >= (1 << 22)) ||
	 *	 (pst->srcPtr.pitch >= (1 << 22)) ||
	 *
	 *	 ((pst->extent.width * pst->extent.height * pst->extent.depth) > (1 << 24)))
	 * THEN	: ret = CN_ERROR_INVALID_VALUE
	 */
	rtmd->noaligned = info->cmd.noaligned;
	for (i = 0; i < rtmd->thrd_num; i++) {
		thrd = rtmd->thrds + i;
		thrd->len = info->width_rcd * info->height_rcd * info->depth_rcd;
		if (info->cmd.noaligned) {
			thrd->dev_src = thrd->dev_src + rand() % ALIGNED_SIZE;
			thrd->dev_dst = thrd->dev_dst + rand() % ALIGNED_SIZE;
		}

		thrd->param_3d.extent.width = info->width_rcd;
		thrd->param_3d.extent.depth = info->depth_rcd;
		thrd->param_3d.extent.height = info->height_rcd;

		thrd->param_3d.dstPtr.ptr = (void *)thrd->dev_dst;
		thrd->param_3d.dstPtr.pitch = info->width_rcd;
		thrd->param_3d.dstPtr.xsize = info->height_rcd;
		thrd->param_3d.dstPtr.ysize = info->height_rcd;

		thrd->param_3d.srcPtr.ptr = (void *)thrd->dev_src;
		thrd->param_3d.srcPtr.pitch = info->width_rcd;
		thrd->param_3d.srcPtr.xsize = info->height_rcd;
		thrd->param_3d.srcPtr.ysize = info->height_rcd;
	}
}

static void* DtoD_mdim_entry(struct dma_test_struct *info)
{
	if (info->dir == DMA_D2D_2D || info->dir == DMA_D2D_3D) {
		_fill_rtmd_baseon_info(info);
		_alloc_resource(&info->multi_dim_set, info->fd);
	}
	return NULL;
}

static int _thread_2d(struct dma_test_struct *info, int thrd_id)
{
	struct thread_handle_multi_dim *thrd = NULL;
	int result = 0;
	uint64_t total_remain;

	thrd = &info->multi_dim_set.thrds[thrd_id];

	if (info->cmd.noaligned) {
		thrd->dev_src = thrd->dev_src + rand() % ALIGNED_SIZE;
		thrd->dev_dst = thrd->dev_dst + rand() % ALIGNED_SIZE;
	}

	total_remain = info->size;
LABEL_REMAIN_GO:
	if (total_remain > MAX_2D_TOTAL) {
		total_remain -= MAX_2D_TOTAL;
		thrd->height = MAX_2D_TOTAL / thrd->width;
	}
	/*
	result = cnMemcpy2D(thrd->dev_dst,
			thrd->dpitch,
			thrd->dev_src,
			thrd->spitch,
			thrd->width,
			thrd->height); */
	if (!result && total_remain) {
		if (total_remain <= MAX_2D_TOTAL) {
			thrd->height = total_remain / thrd->width;
			total_remain = 0;
		}
		goto LABEL_REMAIN_GO;
	}

	return result;
}

static int _thread_3d(struct dma_test_struct *info, int thrd_id)
{
	struct thread_handle_multi_dim *thrd = NULL;
	int result = 0;
	uint64_t total_remain;
	uint64_t tmp_3d_height;

	thrd = &info->multi_dim_set.thrds[thrd_id];
	total_remain = info->size;
LABEL_REMAIN_GO:
	if (total_remain > MAX_3D_TOTAL) {
		total_remain -= MAX_3D_TOTAL;
		tmp_3d_height = MAX_3D_TOTAL / info->depth_rcd / info->width_rcd;
		thrd->param_3d.extent.height = tmp_3d_height;
		thrd->param_3d.srcPtr.xsize = tmp_3d_height;
		thrd->param_3d.srcPtr.ysize = tmp_3d_height;
	}
	/*
	result = cnMemcpy3D(&thrd->param_3d);
	*/
	if (!result && total_remain) {
		if (total_remain <= MAX_3D_TOTAL) {
			tmp_3d_height = total_remain / info->depth_rcd / info->width_rcd;
			thrd->param_3d.extent.height = tmp_3d_height;
			thrd->param_3d.srcPtr.xsize = tmp_3d_height;
			thrd->param_3d.srcPtr.ysize = tmp_3d_height;
			total_remain = 0;
		}
		goto LABEL_REMAIN_GO;
	}

	return result;
}

static int DtoD_mdim_process(struct dma_bw_struct *bw_set)
{
	struct dma_test_struct *info = NULL;
	int thrd_id = bw_set->th_id; /*Use which thread_handle_multi_dim[x] based on this*/
	int result;

	info = bw_set->info;
	if (info->dir == DMA_D2D_2D) {
		result = _thread_2d(info, thrd_id);
	} else if (info->dir == DMA_D2D_3D) {
		result = _thread_3d(info, thrd_id);
	}

	return result;
}

static void* DtoD_mdim_leave(struct dma_test_struct *info)
{
	if (info->dir == DMA_D2D_2D || info->dir == DMA_D2D_3D) {
		_release_resource(&info->multi_dim_set, info->fd);
	}

	return NULL;
}

int get_numa_node(char *bdf)
{
	char cmd[300];
	char tmp[300];
	FILE *devices_stream;
	int value;

	sprintf(cmd, "cat /sys/bus/pci/devices/%s/numa_node", bdf);

	devices_stream = popen(cmd, "r");
	fgets(tmp, 300, devices_stream);
	value = (int)atoi(tmp);
	pclose(devices_stream);

	return value;
}

int set_numa_ctrl(char *bdf, bool flag)
{
	char proc_name[300];
	char cmd[300];
	char tmp[300];
	FILE *devices_stream;

	sprintf(proc_name, "/proc/driver/cambricon/mlus/%s/cn_mem", bdf);
	if (flag)
		sprintf(cmd, "echo numa enable > %s", proc_name);
	else
		sprintf(cmd, "echo numa disable > %s", proc_name);

	devices_stream = popen(cmd, "r");
	fgets(tmp, 300, devices_stream);
	pclose(devices_stream);

	return 0;
}

void *sync_dma_thread(void *arg)
{
	struct dma_bw_struct *bw_set = (struct dma_bw_struct *)arg;
	struct dma_test_struct *info = (struct dma_test_struct *)bw_set->info;
	int i;
	double time_ns;

#if 0
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(bw_set->th_id % cpu_num, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
		printf("warning: could not set cpu affinity, continuing...\n");
	}

	cpu_set_t get;

	CPU_ZERO(&get);
	if (sched_getaffinity(0, sizeof(get), &get) == -1) {
		printf("warning: could not set cpu affinity, continuing...\n");
	}
	for (i = 0; i < cpu_num; i++) {
		if (CPU_ISSET(i, &get)) {
			printf("thread:%d is running processor:%d\n", bw_set->th_id, i);
		}
	}
#endif
	/*
	cnCtxSetCurrent(bw_set->ctx);
	*/
	gettimeofday(&bw_set->stime, NULL);
	switch (bw_set->dir) {
	case DMA_H2D:
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(h2d(info->fd, bw_set->dev_addr_0, bw_set->host_addr, bw_set->size));
		}
		break;
	case DMA_D2H:
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(d2h(info->fd, bw_set->dev_addr_0, bw_set->host_addr, bw_set->size));
		}
		break;
	case DMA_D2D_2D:
	case DMA_D2D_3D:
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(DtoD_mdim_process(bw_set));
		}
		break;
	case DMA_D2D:
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(d2d(info->fd, bw_set->dev_addr_0, bw_set->dev_addr_1, bw_set->size));
		}
		break;
	case DMA_MEMSET:
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			/***
			 * Note:
			 *	the size is align to the value, so for D16/D32 It will
			 *	lead some allow-error.
			 */
			unsigned unit_num = bw_set->size;
			switch (info->cmd.memset_width) {
			case MEMSET_D8:
				MLU_CHECK(mlu_memset_D8(info->fd, bw_set->dev_addr_0, 0x5a, unit_num));
				break;
			case MEMSET_D16:
				MLU_CHECK(mlu_memset_D16(info->fd, bw_set->dev_addr_0, 0x5a5a, unit_num>>1));
				break;
			case MEMSET_D32:
				MLU_CHECK(mlu_memset_D32(info->fd, bw_set->dev_addr_0, 0x5a5a5a5a, unit_num>>2));
				break;
			}
		}
		break;
	default:
		printf("Unknown DMA Direction\n");
		break;
	}
	gettimeofday(&bw_set->etime, NULL);

	time_ns = (1000000 *  bw_set->etime.tv_sec + bw_set->etime.tv_usec -
		1000000 *  bw_set->stime.tv_sec - bw_set->stime.tv_usec) * 1000;
	bw_set->bw = bw_set->th_repeat_num * bw_set->size / time_ns;

	return NULL;
}

void *async_dma_thread(void *arg)
{
	struct dma_bw_struct *bw_set = (struct dma_bw_struct *)arg;
	struct dma_test_struct *info = (struct dma_test_struct *)bw_set->info;
	int i;
	double time_ns;

#if 0
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(bw_set->th_id % cpu_num, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
		printf("warning: could not set cpu affinity, continuing...\n");
	}

	cpu_set_t get;

	CPU_ZERO(&get);
	if (sched_getaffinity(0, sizeof(get), &get) == -1) {
		printf("warning: could not set cpu affinity, continuing...\n");
	}
	for (i = 0; i < cpu_num; i++) {
		if (CPU_ISSET(i, &get)) {
			printf("thread:%d is running processor:%d\n", bw_set->th_id, i);
		}
	}
#endif
	/*
	cnCtxSetCurrent(bw_set->ctx);
	*/
	gettimeofday(&bw_set->stime, NULL);
	switch (bw_set->dir) {
	case DMA_H2D:
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(async_h2d(info->fd, bw_set->dev_addr_0,
				bw_set->host_addr, bw_set->size, bw_set->queue));
			if (info->cmd.dma_mode == ASYNC_NO_BATCH_MODE)
				MLU_CHECK(sync_queue(info->fd, bw_set->queue));
		}
		break;
	case DMA_D2H:
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(async_d2h(info->fd, bw_set->dev_addr_0,
				bw_set->host_addr, bw_set->size, bw_set->queue));
			if (info->cmd.dma_mode == ASYNC_NO_BATCH_MODE)
				MLU_CHECK(sync_queue(info->fd, bw_set->queue));
		}
		break;
	case DMA_D2D:
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(async_d2d(info->fd, bw_set->dev_addr_0,
				bw_set->dev_addr_1, bw_set->size, bw_set->queue));
			if (info->cmd.dma_mode == ASYNC_NO_BATCH_MODE)
				MLU_CHECK(sync_queue(info->fd, bw_set->queue));
		}
		break;
	case DMA_MEMSET:
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			/***
			 * Note:
			 *	the size is align to the value, so for D16/D32 It will
			 *	lead some allow-error.
			 */
			unsigned unit_num = bw_set->size;
			switch (info->cmd.memset_width) {
			case MEMSET_D8:
				MLU_CHECK(mlu_memset_D8_async(info->fd, bw_set->dev_addr_0, 0x5a, unit_num, bw_set->queue));
				break;
			case MEMSET_D16:
				MLU_CHECK(mlu_memset_D16_async(info->fd, bw_set->dev_addr_0, 0x5a5a, unit_num>>1, bw_set->queue));
				break;
			case MEMSET_D32:
				MLU_CHECK(mlu_memset_D32_async(info->fd, bw_set->dev_addr_0, 0x5a5a5a5a, unit_num>>2, bw_set->queue));
				break;
			}
			if (info->cmd.dma_mode == ASYNC_NO_BATCH_MODE)
				MLU_CHECK(sync_queue(info->fd, bw_set->queue));
		}
		break;
	default:
		printf("Unknown DMA Direction\n");
		break;
	}
	MLU_CHECK(sync_queue(info->fd, bw_set->queue));

	gettimeofday(&bw_set->etime, NULL);
	time_ns = (1000000 *  bw_set->etime.tv_sec + bw_set->etime.tv_usec -
		1000000 *  bw_set->stime.tv_sec - bw_set->stime.tv_usec) * 1000;
	bw_set->bw = bw_set->th_repeat_num * bw_set->size / time_ns;
	return NULL;
}

void get_bandwidth_result(struct dma_test_struct *info)
{
	double stime;
	double etime;
	double h2d_ave = 0;
	double d2h_ave = 0;
	int i;

	switch (info->dir) {
	case DMA_H2D:
	case DMA_D2D:
	case DMA_MEMSET:
	case DMA_D2D_2D:
	case DMA_D2D_3D:
		stime = 1000000 * info->bw_set[0].stime.tv_sec + info->bw_set[0].stime.tv_usec;
		etime = 1000000 * info->bw_set[0].etime.tv_sec + info->bw_set[0].etime.tv_usec;
		for (i = 0; i < info->cmd.thread_num; i++) {
			if (stime > (1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec))
				stime = 1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec;
			if (etime < (1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec))
				etime = 1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec;
		}
		info->result[info->repeat_id].h2d_bw = info->cmd.th_repeat_num * info->size * info->cmd.thread_num / (etime - stime) / 1000;

		info->result[info->repeat_id].h2d_th_variance = 0;
		for (i = 0; i < info->cmd.thread_num; i++) {
			h2d_ave += info->bw_set[i].bw;
		}
		h2d_ave = h2d_ave / info->cmd.thread_num;
		for (i = 0; i < info->cmd.thread_num; i++) {
			info->result[info->repeat_id].h2d_th_variance += (info->bw_set[i].bw - h2d_ave) * (info->bw_set[i].bw - h2d_ave);
		}
		info->result[info->repeat_id].h2d_th_variance = info->result[info->repeat_id].h2d_th_variance / info->cmd.thread_num;

		break;
	case DMA_D2H:
		stime = 1000000 * info->bw_set[0].stime.tv_sec + info->bw_set[0].stime.tv_usec;
		etime = 1000000 * info->bw_set[0].etime.tv_sec + info->bw_set[0].etime.tv_usec;
		for (i = 0; i < info->cmd.thread_num; i++) {
			if (stime > (1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec))
				stime = 1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec;
			if (etime < (1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec))
				etime = 1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec;
		}
		info->result[info->repeat_id].d2h_bw = info->cmd.th_repeat_num * info->size * info->cmd.thread_num / (etime - stime) / 1000;

		info->result[info->repeat_id].d2h_th_variance = 0;
		for (i = 0; i < info->cmd.thread_num; i++) {
			d2h_ave += info->bw_set[i].bw;
		}
		d2h_ave = d2h_ave / info->cmd.thread_num;
		for (i = 0; i < info->cmd.thread_num; i++) {
			info->result[info->repeat_id].d2h_th_variance += (info->bw_set[i].bw - d2h_ave) * (info->bw_set[i].bw - d2h_ave);
		}
		info->result[info->repeat_id].d2h_th_variance = info->result[info->repeat_id].d2h_th_variance / info->cmd.thread_num;

		break;
	case DMA_BOTHWAY:
		stime = 1000000 * info->bw_set[0].stime.tv_sec + info->bw_set[0].stime.tv_usec;
		etime = 1000000 * info->bw_set[0].etime.tv_sec + info->bw_set[0].etime.tv_usec;
		for (i = 0; i < info->cmd.thread_num; i += 2) {
			if (stime > (1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec))
				stime = 1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec;
			if (etime < (1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec))
				etime = 1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec;
		}
		info->result[info->repeat_id].d2h_bw = info->cmd.th_repeat_num * info->size * info->cmd.thread_num / 2 / (etime - stime) / 1000;
		stime = 1000000 * info->bw_set[1].stime.tv_sec + info->bw_set[1].stime.tv_usec;
		etime = 1000000 * info->bw_set[1].etime.tv_sec + info->bw_set[1].etime.tv_usec;
		for (i = 1; i < info->cmd.thread_num; i += 2) {
			if (stime > (1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec))
				stime = 1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec;
			if (etime < (1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec))
				etime = 1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec;
		}
		info->result[info->repeat_id].h2d_bw = info->cmd.th_repeat_num * info->size * info->cmd.thread_num / 2 / (etime - stime) / 1000;

		info->result[info->repeat_id].h2d_th_variance = 0;
		for (i = 1; i < info->cmd.thread_num; i += 2) {
			h2d_ave += info->bw_set[i].bw;
		}
		h2d_ave = h2d_ave / info->cmd.thread_num / 2;
		for (i = 1; i < info->cmd.thread_num; i += 2) {
			info->result[info->repeat_id].h2d_th_variance += (info->bw_set[i].bw - h2d_ave) * (info->bw_set[i].bw - h2d_ave);
		}
		info->result[info->repeat_id].h2d_th_variance = info->result[info->repeat_id].h2d_th_variance / info->cmd.thread_num / 2;

		info->result[info->repeat_id].d2h_th_variance = 0;
		for (i = 0; i < info->cmd.thread_num; i += 2) {
			d2h_ave += info->bw_set[i].bw;
		}
		d2h_ave = d2h_ave / info->cmd.thread_num / 2;
		for (i = 0; i < info->cmd.thread_num; i += 2) {
			info->result[info->repeat_id].d2h_th_variance += (info->bw_set[i].bw - d2h_ave) * (info->bw_set[i].bw - d2h_ave);
		}
		info->result[info->repeat_id].d2h_th_variance = info->result[info->repeat_id].d2h_th_variance / info->cmd.thread_num / 2;

		break;
	default:
		printf("Unknown DMA Direction\n");
		break;
	}
}

void get_repeat_bandwidth_result(struct dma_test_struct *info)
{
	double h2d_bw_total = 0;
	double d2h_bw_total = 0;
	int i = 0;
	double range_min;
	double range_max;

	info->h2d_bw_max = 0;
	info->d2h_bw_max = 0;
	info->h2d_bw_min = 0xffff;
	info->d2h_bw_min = 0xffff;
	info->h2d_variance = 0;
	info->d2h_variance = 0;
	info->h2d_sta_score = 0;
	info->d2h_sta_score = 0;
	range_min = (100 - info->cmd.sta_range) / 100;
	range_max = (100 + info->cmd.sta_range) / 100;
	switch (info->dir) {
	case DMA_H2D:
	case DMA_D2D:
	case DMA_MEMSET:
	case DMA_D2D_2D:
	case DMA_D2D_3D:
		for (i = 0; i < info->cmd.repeat_num; i++) {
			h2d_bw_total += info->result[i].h2d_bw;
			info->h2d_bw_min = (info->result[i].h2d_bw > info->h2d_bw_min ? info->h2d_bw_min : info->result[i].h2d_bw);
			info->h2d_bw_max = (info->result[i].h2d_bw < info->h2d_bw_max ? info->h2d_bw_max : info->result[i].h2d_bw);
		}
		info->h2d_bw = h2d_bw_total / info->cmd.repeat_num;

		if (info->cmd.variance == THREAD_MODE) {
			info->h2d_variance += info->result[info->repeat_id].h2d_th_variance;
		} else if (info->cmd.variance == REPEAT_MODE) {
			for (i = 0; i < info->cmd.repeat_num; i++) {
				info->h2d_variance += (info->result[i].h2d_bw - info->h2d_bw) * (info->result[i].h2d_bw - info->h2d_bw);
			}
		}
		info->h2d_variance = info->h2d_variance / info->cmd.repeat_num;

		for (i = 0; i < info->cmd.repeat_num; i++) {
			if ((info->result[i].h2d_bw >= info->h2d_bw * range_min) &&
				(info->result[i].h2d_bw <= info->h2d_bw * range_max))
				info->h2d_sta_score++;
		}
		info->h2d_sta_score = info->h2d_sta_score / info->cmd.repeat_num * 100;
		break;
	case DMA_D2H:
		for (i = 0; i < info->cmd.repeat_num; i++) {
			d2h_bw_total += info->result[i].d2h_bw;
			info->d2h_bw_min = (info->result[i].d2h_bw > info->d2h_bw_min ? info->d2h_bw_min : info->result[i].d2h_bw);
			info->d2h_bw_max = (info->result[i].d2h_bw < info->d2h_bw_max ? info->d2h_bw_max : info->result[i].d2h_bw);
		}
		info->d2h_bw = d2h_bw_total / info->cmd.repeat_num;

		if (info->cmd.variance == THREAD_MODE) {
			info->d2h_variance += info->result[info->repeat_id].d2h_th_variance;
		} else if (info->cmd.variance == REPEAT_MODE) {
			for (i = 0; i < info->cmd.repeat_num; i++) {
				info->d2h_variance += (info->result[i].d2h_bw - info->d2h_bw) * (info->result[i].d2h_bw - info->d2h_bw);
			}
		}
		info->d2h_variance = info->d2h_variance / info->cmd.repeat_num;

		for (i = 0; i < info->cmd.repeat_num; i++) {
			if ((info->result[i].d2h_bw >= info->d2h_bw * range_min) &&
				(info->result[i].d2h_bw <= info->d2h_bw * range_max))
				info->d2h_sta_score++;
		}
		info->d2h_sta_score = info->d2h_sta_score / info->cmd.repeat_num * 100;
		break;
	case DMA_BOTHWAY:
		for (i = 0; i < info->cmd.repeat_num; i++) {
			h2d_bw_total += info->result[i].h2d_bw;
			info->h2d_bw_min = (info->result[i].h2d_bw > info->h2d_bw_min ? info->h2d_bw_min : info->result[i].h2d_bw);
			info->h2d_bw_max = (info->result[i].h2d_bw < info->h2d_bw_max ? info->h2d_bw_max : info->result[i].h2d_bw);
		}
		info->h2d_bw = h2d_bw_total / info->cmd.repeat_num;

		if (info->cmd.variance == THREAD_MODE) {
			info->h2d_variance += info->result[info->repeat_id].h2d_th_variance;
		} else if (info->cmd.variance == REPEAT_MODE) {
			for (i = 0; i < info->cmd.repeat_num; i++) {
				info->h2d_variance += (info->result[i].h2d_bw - info->h2d_bw) * (info->result[i].h2d_bw - info->h2d_bw);
			}
		}
		info->h2d_variance = info->h2d_variance / info->cmd.repeat_num;

		for (i = 0; i < info->cmd.repeat_num; i++) {
			if ((info->result[i].h2d_bw >= info->h2d_bw * range_min) &&
				(info->result[i].h2d_bw <= info->h2d_bw * range_max))
				info->h2d_sta_score++;
		}
		info->h2d_sta_score = info->h2d_sta_score / info->cmd.repeat_num * 100;

		for (i = 0; i < info->cmd.repeat_num; i++) {
			d2h_bw_total += info->result[i].d2h_bw;
			info->d2h_bw_min = (info->result[i].d2h_bw > info->d2h_bw_min ? info->d2h_bw_min : info->result[i].d2h_bw);
			info->d2h_bw_max = (info->result[i].d2h_bw < info->d2h_bw_max ? info->d2h_bw_max : info->result[i].d2h_bw);
		}
		info->d2h_bw = d2h_bw_total / info->cmd.repeat_num;

		if (info->cmd.variance == THREAD_MODE) {
			info->d2h_variance += info->result[info->repeat_id].d2h_th_variance;
		} else if (info->cmd.variance == REPEAT_MODE) {
			for (i = 0; i < info->cmd.repeat_num; i++) {
				info->d2h_variance += (info->result[i].d2h_bw - info->d2h_bw) * (info->result[i].d2h_bw - info->d2h_bw);
			}
		}
		info->d2h_variance = info->d2h_variance / info->cmd.repeat_num;

		break;
	default:
		printf("Unknown DMA Direction\n");
		break;
	}
}

void print_result_title(struct dma_test_struct *info)
{
	char title_buff[512];

	switch (info->dir) {
	case DMA_H2D:
	case DMA_D2H:
	case DMA_D2D:
	case DMA_MEMSET:
	case DMA_D2D_2D:
	case DMA_D2D_3D:
		if (info->cmd.repeat_num > 1) {
			if (info->cmd.variance == NO_NEED_MODE) {
				if (info->cmd.sta_range) {
					sprintf(title_buff, "%s", "Transfer Size\t\tAvg(GB/s)\t\tMin(GB/s)\t\tMax(GB/s)\t\tStability_Score");
				} else {
					sprintf(title_buff, "%s", "Transfer Size\t\tAvg(GB/s)\t\tMin(GB/s)\t\tMax(GB/s)");
				}
			} else {
				if (info->cmd.sta_range) {
					sprintf(title_buff, "%s", "Transfer Size\t\tAvg(GB/s)\t\tMin(GB/s)\t\tMax(GB/s)\t\tVariance\t\tStability_Score");
				} else {
					sprintf(title_buff, "%s", "Transfer Size\t\tAvg(GB/s)\t\tMin(GB/s)\t\tMax(GB/s)\t\tVariance");
				}
			}
		} else {
			if (info->cmd.variance == NO_NEED_MODE) {
				sprintf(title_buff, "%s", "Transfer Size\t\tBandwidth(GB/s)");
			} else {
				sprintf(title_buff, "%s", "Transfer Size\t\tBandwidth(GB/s)\t\tVariance");
			}
		}
		data_prt("%s", title_buff);

		if (info->dir == DMA_D2D_3D) {
			data_prt("\t\tWidth\tHeight\tDepth");
		} else if (info->dir == DMA_D2D_2D) {
			data_prt("\t\tWidth\tHeight");
		}
		data_prt("\n");



		break;
	case DMA_BOTHWAY:
		if (info->cmd.repeat_num > 1) {
			if (info->cmd.variance == NO_NEED_MODE) {
				if (info->cmd.sta_range) {
					data_prt("Transfer Size\t\tAvg(GB/s)\t\t\t\tMin(GB/s)\t\tMax(GB/s)\t\tStability_Score\n");
				} else {
					data_prt("Transfer Size\t\tAvg(GB/s)\t\t\t\tMin(GB/s)\t\tMax(GB/s)\n");
				}
			} else {
				if (info->cmd.sta_range) {
					data_prt("Transfer Size\t\tAvg(GB/s)\t\t\t\tMin(GB/s)\t\tMax(GB/s)\t\tVariance\t\tStability_Score\n");
				} else {
					data_prt("Transfer Size\t\tAvg(GB/s)\t\t\t\tMin(GB/s)\t\tMax(GB/s)\t\tVariance\n");
				}
			}
		} else {
			if (info->cmd.variance == NO_NEED_MODE) {
				data_prt("Transfer Size\t\tBandwidth(GB/s)\n");
			} else {
				data_prt("Transfer Size\t\tBandwidth(GB/s)\t\t\t\tVariance\n");
			}
		}
		break;
	default:
		printf("Unknown DMA Direction\n");
		break;
	}
}

void print_bw_result(struct dma_test_struct *info)
{
	char sizechar[100];
	char result_buff[512];

	if (info->cmd.noaligned)
		info->size -= ALIGNED_SIZE;
	if (info->size < 0x100000) {
		sprintf(sizechar, "%#lx\t\t", info->size);
	} else {
		sprintf(sizechar, "%#lx\t", info->size);
	}

	switch (info->dir) {
	case DMA_H2D:
	case DMA_D2D:
	case DMA_MEMSET:
	case DMA_D2D_2D:
	case DMA_D2D_3D:
		if (info->cmd.repeat_num > 1) {
			/*Amend add '\t' for the title 'Stability_Score' it cover two-tab*/
			if (info->cmd.variance == NO_NEED_MODE) {
				if (info->cmd.sta_range) {
					sprintf(result_buff, "%s\t%f\t\t%f\t\t%f\t\t%.2f\t", sizechar,
						info->h2d_bw, info->h2d_bw_min, info->h2d_bw_max, info->h2d_sta_score);
				} else {
					sprintf(result_buff, "%s\t%f\t\t%f\t\t%f", sizechar,
						info->h2d_bw, info->h2d_bw_min, info->h2d_bw_max);
				}
			} else {
				if (info->cmd.sta_range) {
					sprintf(result_buff, "%s\t%f\t\t%f\t\t%f\t\t%f\t\t%.2f\t", sizechar,
						info->h2d_bw, info->h2d_bw_min, info->h2d_bw_max,
						info->h2d_variance, info->h2d_sta_score);
				} else {
					sprintf(result_buff, "%s\t%f\t\t%f\t\t%f\t\t%f", sizechar,
						info->h2d_bw, info->h2d_bw_min, info->h2d_bw_max, info->h2d_variance);
				}
			}
		} else {
			if (info->cmd.variance == NO_NEED_MODE) {
				sprintf(result_buff, "%s\t%f", sizechar, info->h2d_bw);
			} else {
				sprintf(result_buff, "%s\t%f\t\t%f", sizechar, info->h2d_bw, info->h2d_variance);
			}
		}
		data_prt("%s", result_buff);

		if (info->dir == DMA_D2D_2D) {
			data_prt("\t\t%lx\t%lx", info->width_rcd, info->height_rcd);
		} else if (info->dir == DMA_D2D_3D) {
			data_prt("\t\t%lx\t%lx\t%lx", info->width_rcd, info->height_rcd, info->depth_rcd);
		}
		data_prt("\n");

		break;
	case DMA_D2H:
		if (info->cmd.repeat_num > 1) {
			if (info->cmd.variance == NO_NEED_MODE) {
				if (info->cmd.sta_range) {
					data_prt("%s\t%f\t\t%f\t\t%f\t\t%.2f\n", sizechar,
						info->d2h_bw, info->d2h_bw_min, info->d2h_bw_max, info->d2h_sta_score);
				} else {
					data_prt("%s\t%f\t\t%f\t\t%f\n", sizechar,
						info->d2h_bw, info->d2h_bw_min, info->d2h_bw_max);
				}
			} else {
				if (info->cmd.sta_range) {
					data_prt("%s\t%f\t\t%f\t\t%f\t\t%f\t\t%.2f\n", sizechar,
						info->d2h_bw, info->d2h_bw_min, info->d2h_bw_max,
						info->d2h_variance, info->d2h_sta_score);
				} else {
					data_prt("%s\t%f\t\t%f\t\t%f\t\t%f\n", sizechar,
						info->d2h_bw, info->d2h_bw_min, info->d2h_bw_max, info->d2h_variance);
				}
			}
		} else {
			if (info->cmd.variance == NO_NEED_MODE) {
				data_prt("%s\t%f\n", sizechar, info->d2h_bw);
			} else {
				data_prt("%s\t%f\t\t%f\n", sizechar, info->d2h_bw, info->d2h_variance);
			}
		}
		break;
	case DMA_BOTHWAY:
		if (info->cmd.repeat_num > 1) {
			if (info->cmd.variance == NO_NEED_MODE) {
				if (info->cmd.sta_range) {
					data_prt("%s\t%f(%f,%f)\t\t%f\t\t%f\t\t%.2f\n", sizechar,
						info->h2d_bw + info->d2h_bw, info->h2d_bw, info->d2h_bw,
						info->h2d_bw_min + info->d2h_bw_min,
						info->h2d_bw_max + info->d2h_bw_max,
						info->h2d_sta_score + info->d2h_sta_score);
				} else {
					data_prt("%s\t%f(%f,%f)\t\t%f\t\t%f\n", sizechar,
						info->h2d_bw + info->d2h_bw, info->h2d_bw, info->d2h_bw,
						info->h2d_bw_min + info->d2h_bw_min,
						info->h2d_bw_max + info->d2h_bw_max);
				}
			} else {
				if (info->cmd.sta_range) {
					data_prt("%s\t%f(%f,%f)\t\t%f\t\t%f\t\t%f\t\t%.2f\n", sizechar,
						info->h2d_bw + info->d2h_bw, info->h2d_bw, info->d2h_bw,
						info->h2d_bw_min + info->d2h_bw_min,
						info->h2d_bw_max + info->d2h_bw_max,
						info->h2d_variance + info->d2h_variance,
						info->h2d_sta_score + info->d2h_sta_score);
				} else {
					data_prt("%s\t%f(%f,%f)\t\t%f\t\t%f\t\t%.2f\n", sizechar,
						info->h2d_bw + info->d2h_bw, info->h2d_bw, info->d2h_bw,
						info->h2d_bw_min + info->d2h_bw_min,
						info->h2d_bw_max + info->d2h_bw_max,
						info->h2d_variance + info->d2h_variance);
				}
			}
		} else {
			if (info->cmd.variance == NO_NEED_MODE) {
				data_prt("%s\t%f(%f,%f)\n", sizechar,
					info->h2d_bw + info->d2h_bw, info->h2d_bw, info->d2h_bw);
			} else {
				data_prt("%s\t%f(%f,%f)\t\t(%f,%f)\n", sizechar,
					info->h2d_bw + info->d2h_bw, info->h2d_bw, info->d2h_bw,
					info->h2d_variance, info->d2h_variance);
			}
		}
		break;
	default:
		printf("Unknown DMA Direction\n");
		break;
	}
}

void print_latency_result(struct dma_test_struct *info)
{
	if (info->cmd.repeat_num > 1) {
		if (info->cmd.variance == NO_NEED_MODE) {
			if (info->cmd.sta_range) {
				printf("\t\t%f\t\t%f\t\t%f\t\t%.2f\n", info->latency,
					info->latency_min, info->latency_max, info->latency_sta_score);
			} else {
				printf("\t\t%f\t\t%f\t\t%f\n", info->latency,
					info->latency_min, info->latency_max);
			}
		} else {
			if (info->cmd.sta_range) {
				printf("\t\t%f\t\t%f\t\t%f\t\t%f\t\t%.2f\n", info->latency,
					info->latency_min, info->latency_max,
					info->latency_variance, info->latency_sta_score);
			} else {
				printf("\t\t%f\t\t%f\t\t%f\t\t%f\n", info->latency,
					info->latency_min, info->latency_max, info->latency_variance);
			}
		}
	} else {
		if (info->cmd.variance == NO_NEED_MODE) {
			printf("\t\t%f\n", info->latency);
		} else {
			printf("\t\t%f\t\t%f\n", info->latency,
				info->latency_variance);
		}
	}
}

int get_sync_bandwidth(struct dma_test_struct *info)
{
	int i;
	pthread_t th[info->cmd.thread_num];

	for (i = 0; i < info->cmd.thread_num; i++) {
		info->bw_set[i].fd = info->fd;
		if (info->cmd.noaligned) {
			info->bw_set[i].dev_addr_0 = info->dev_addr_0 +
							rand() % ALIGNED_SIZE;
			usleep(10);
			info->bw_set[i].dev_addr_1 = info->dev_addr_1 +
							rand() % ALIGNED_SIZE;
			usleep(10);
			info->bw_set[i].host_addr = info->host_addr +
							rand() % ALIGNED_SIZE;
		} else {
			info->bw_set[i].dev_addr_0 = info->dev_addr_0;
			info->bw_set[i].dev_addr_1 = info->dev_addr_1;
			info->bw_set[i].host_addr = info->host_addr;
		}
		info->bw_set[i].size = info->size;
		info->bw_set[i].th_repeat_num = info->cmd.th_repeat_num;
		info->bw_set[i].th_id = i;
		info->bw_set[i].info = info;
		if (info->dir == DMA_BOTHWAY) {
			if (i % 2)
				info->bw_set[i].dir = DMA_H2D;
			else
				info->bw_set[i].dir = DMA_D2H;
		} else {
			info->bw_set[i].dir = info->dir;
		}
	}
	for (i = 0; i < info->cmd.thread_num; i++) {
		pthread_create(&th[i], NULL, sync_dma_thread, &info->bw_set[i]);
	}
	for (i = 0; i < info->cmd.thread_num; i++) {
		pthread_join(th[i], NULL);
	}

	get_bandwidth_result(info);

	return 0;
}

double get_async_bandwidth(struct dma_test_struct *info)
{
	int i;
	pthread_t th[info->cmd.thread_num];

	for (i = 0; i < info->cmd.thread_num; i++) {
		info->bw_set[i].fd = info->fd;
		if (info->cmd.noaligned) {
			info->bw_set[i].dev_addr_0 = info->dev_addr_0 +
							rand() % ALIGNED_SIZE;
			usleep(10);
			info->bw_set[i].dev_addr_1 = info->dev_addr_1 +
							rand() % ALIGNED_SIZE;
			usleep(10);
			info->bw_set[i].host_addr = info->host_addr +
							rand() % ALIGNED_SIZE;
			info->bw_set[i].size = info->size - ALIGNED_SIZE;
		} else {
			info->bw_set[i].dev_addr_0 = info->dev_addr_0;
			info->bw_set[i].dev_addr_1 = info->dev_addr_1;
			info->bw_set[i].host_addr = info->host_addr;
			info->bw_set[i].size = info->size;
		}
		info->bw_set[i].th_repeat_num = info->cmd.th_repeat_num;
		info->bw_set[i].th_id = i;
		info->bw_set[i].info = info;
		switch (info->dir) {
		case DMA_H2D:
		case DMA_D2H:
		case DMA_D2D:
		case DMA_MEMSET:
			info->bw_set[i].dir = info->dir;
			break;
		case DMA_BOTHWAY:
			if (i % 2) {
				info->bw_set[i].dir = DMA_H2D;
			} else {
				info->bw_set[i].dir = DMA_D2H;
			}
			break;
		case DMA_D2D_2D:
		case DMA_D2D_3D:
			/*Not support 2D/3D for anync mode*/
			return 0;
		default:
			printf("Unknown DMA Direction\n");
			break;
		}
		/***
		 * Note: only vaild direction can do next job.
		 */
		MLU_CHECK(create_queue(info->fd, &info->bw_set[i].queue, 0));
	}

	for (i = 0; i < info->cmd.thread_num; i++) {
		info->th_id = i;
		pthread_create(&th[i], NULL, async_dma_thread, &info->bw_set[i]);
	}
	for (i = 0; i < info->cmd.thread_num; i++) {
		pthread_join(th[i], NULL);
	}

	get_bandwidth_result(info);

	for (i = 0; i < info->cmd.thread_num; i++) {
		MLU_CHECK(destroy_queue(info->fd, info->bw_set[i].queue));
	}

	return 0;
}

/**
 * 2D
 *	width : 0x10 -> size	MAXEDGE<=0x100000
 *	height: size / width
 *	Total : width * height  MAXEDGE<=0x1000000
 *
 * 3D
 *	width : 0x10 -> size / DEFAULT_3D_DEPTH(2)  MAXEDGE<=0x100000
 *	height: size / DEFAULT_3D_DEPTH / width     MAXEDGE<=0x100000
 *	Total : width * height * depth              MAXEDGE<=0x1000000
 */
static int _is_width_height_depth_valid(struct dma_test_struct *info)
{
	int valid = 1;

	if ((info->dir == DMA_D2D_2D && info->width_rcd > MAX_2D_WIDTH) ||
	    (info->dir == DMA_D2D_3D && info->width_rcd > MAX_3D_WIDTH)) {
		valid = 0;
		printf("width shall less-equal than Edge\n");
	}

	if (info->dir == DMA_D2D_2D) {
		if (info->width_rcd * info->height_rcd != info->size) {
			valid = 0;
			printf("width(0x%lx)*height(0x%lx) shall be equal to size(0x%lx)\n",
				info->width_rcd, info->height_rcd, info->size);
		}
	}

	if (info->dir == DMA_D2D_3D) {
		if (info->width_rcd * info->height_rcd * info->depth_rcd != info->size) {
			valid = 0;
			printf("width(0x%lx)*height(0x%lx)*depth(0x%lx) shall be equal to size(0x%lx)\n",
				info->width_rcd, info->height_rcd,
				info->depth_rcd,info->size);
		}
	}

LABEL_OUT:
	return valid;
}
static int _update_width_height_depth(struct dma_test_struct *info, int is_init)
{
	unsigned long width_edge = 0x10;
	int updated = 0;
	unsigned long width_tmp;
	unsigned long height_tmp;

	if (is_init) {
		info->depth_rcd = info->depth;

		if (info->dir == DMA_D2D_2D) {
			if (info->size > info->width) {
				info->width_rcd = info->width;
			} else {
				info->width_rcd = info->size;
			}
			info->height_rcd = info->size / info->width_rcd;
		} else if (info->dir == DMA_D2D_3D) {
			if (info->size / info->depth > info->width) {
				info->width_rcd = info->width;
			} else {
				info->width_rcd = info->size / info->depth;
			}
			info->height_rcd = info->size / info->depth / info->width_rcd;
		}
	} else if (info->width_shift) {
		/**
		 * check and get width_edge
		 *	2D : width<=1M && <= size
		 * 	3D : width<=1M && <= size/DEFAULT_3D_DEPTH
		 *	     height<=1M && <= size/DEFAULT_3D_DEPTH/width
		 */
		if (info->dir == DMA_D2D_2D) {
			width_edge = info->size;
			if (width_edge > MAX_2D_WIDTH) {
				width_edge = MAX_2D_WIDTH;
			}
		} else if (info->dir == DMA_D2D_3D) {
			width_edge = info->size / info->depth;
			if (width_edge > MAX_3D_WIDTH) {
				width_edge = MAX_3D_WIDTH;
			}
		}
		/*Try update ...*/
		width_tmp = info->width_rcd;
		width_tmp <<= info->width_shift;

		if (width_tmp <= width_edge) {
			updated = 1;
			if (info->dir == DMA_D2D_2D) {
				height_tmp = info->size / width_tmp;
			} else if (info->dir == DMA_D2D_3D) {
				height_tmp = info->size / info->depth / width_tmp;
			}
			info->width_rcd = width_tmp;
			info->height_rcd = height_tmp;
			info->depth_rcd = info->depth;
		}
	}

	if (_is_width_height_depth_valid(info)) {
		_prepare_2d_param(info);
		_prepare_3d_param(info);
	} else {
		updated = 0; /*Do Not Update for InValid W-H-D parameter*/
	}

	return updated;
}

/**
 * The entry for repeating test about bandwidth.
 *	The only variable is 'info->size'.
 */
void *get_copy_bandwidth(void *arg)
{
	struct dma_test_struct *info = (struct dma_test_struct *)arg;
	int i;

	/* cnCtxSetCurrent(info->ctx); */

	if (info->cmd.noaligned) {
		if (info->cmd.mem_mode == PINNED) {
			info->host_addr = pinned_mem_alloc(pin_fd, info->size + ALIGNED_SIZE);
		} else {
			if (info->cmd.mem_numa) {
#ifndef NUMA_DISABLE
				info->host_addr = numa_alloc_onnode(info->size + ALIGNED_SIZE,
						info->numa_node);
				if (!info->host_addr) {
					printf("malloc numa host_addr FAILED\n");
					return NULL;
				}
#endif
			} else {
				info->host_addr = malloc(info->size + ALIGNED_SIZE);
				if (!info->host_addr) {
					printf("malloc host_addr FAILED\n");
					return NULL;
				}
			}
		}
		memset(info->host_addr, 0, info->size + ALIGNED_SIZE);
		MLU_CHECK(alloc_dev_memory(info->fd, &info->dev_addr_0, info->size + ALIGNED_SIZE));
		MLU_CHECK(alloc_dev_memory(info->fd, &info->dev_addr_1, info->size + ALIGNED_SIZE));
	} else {
		if (info->cmd.mem_mode == PINNED) {
			info->host_addr = pinned_mem_alloc(pin_fd, info->size);
		} else {
			if (info->cmd.mem_numa) {
#ifndef NUMA_DISABLE
				info->host_addr = numa_alloc_onnode(info->size, info->numa_node);
				if (!info->host_addr) {
					printf("malloc numa host_addr FAILED\n");
					return NULL;
				}
#endif
			} else {
				info->host_addr = malloc(info->size);
				if (!info->host_addr) {
					printf("malloc host_addr FAILED\n");
					return NULL;
				}
			}
		}
		memset(info->host_addr, 0, info->size);
		MLU_CHECK(alloc_dev_memory(info->fd, &info->dev_addr_0, info->size));
		MLU_CHECK(alloc_dev_memory(info->fd, &info->dev_addr_1, info->size));
	}

	DtoD_mdim_entry(info); /*To prepare the source for D2D Multi Dim*/

	_update_width_height_depth(info, 1); /*For D2D Multi Dim: Init width height depth*/

LABEL_GET_BW:
	for (i = 0; i < info->cmd.repeat_num; i++) {
		info->repeat_id = i;
		if (info->cmd.dma_mode == SYNC_MODE) {
			if (get_sync_bandwidth(info)) {
				printf("get_sync_bandwidth FAILED\n");
				return NULL;
			}
		} else {
			if (get_async_bandwidth(info)) {
				printf("get_async_bandwidth FAILED\n");
				return NULL;
			}
		}
	}

	if (info->cmd.mem_mode == PINNED) {
		if (info->host_addr)
			pinned_mem_free(pin_fd, info->host_addr);
	} else {
		if (info->host_addr) {
			if (info->cmd.mem_numa) {
#ifndef NUMA_DISABLE
				if (info->cmd.noaligned) {
					numa_free(info->host_addr, info->size + ALIGNED_SIZE);
				} else {
					numa_free(info->host_addr, info->size);
				}
#endif
			} else {
				free(info->host_addr);
			}
		}
	}
	if (info->dev_addr_0) {
		free_dev_memory(info->fd, info->dev_addr_0);
	}
	if (info->dev_addr_1) {
		free_dev_memory(info->fd, info->dev_addr_1);
	}
	/***
	 * 1. Each repeat will calc all-threads' BW for one card.
	 * 2. After all repeat-num loop over, calc avg about these repeats for one card.
	 * 3. WHEN do multi-card-test, Do Not Show The Result That Got In Step-2.
	 */
	get_repeat_bandwidth_result(info);

	if (!info->multicard_test) {
		print_bw_result(info);
	}

	if (_update_width_height_depth(info, 0)) {
		/**
		 * Update width height depth. If valid then will do next loop.
		 */
		goto LABEL_GET_BW;
	}

	DtoD_mdim_leave(info); /*To free the source for D2D Multi Dim*/

	return NULL;
}

int run_copy_bandwidth_test(struct dma_test_struct *info)
{
	int size;

	switch (info->cmd.mode) {
	case QUICK_MODE:
		info->size = DEFAULT_SIZE;
		get_copy_bandwidth(info);
		break;
	case RANGE_MODE:
		for (size = info->cmd.start; size < info->cmd.end; size += info->cmd.increment) {
			info->size = size;
			get_copy_bandwidth(info);
		}
		break;
	case SHMOO_MODE:
		for (size = 0x10; size < 0x8000000; size *= 2) {
			if (info->cmd.noaligned)
				info->size = size + ALIGNED_SIZE;
			else
				info->size = size;
			get_copy_bandwidth(info);
		}
		break;
	case SMALL_SHMOO_MODE:
		for (size = 0x4; size < 0x800; size *= 2) {
			info->size = size;
			get_copy_bandwidth(info);
		}
		break;
	default:
		printf("Invalid mode - valid modes are quick, range, or shmoo\n");
		printf("See --help for more information\n");
		break;
	}
}

int get_multicard_bandwidth(struct dma_test_struct info[], int size, int device_count)
{
	pthread_t th[device_count];
	int i;
	double total_h2d_bw = 0;
	double total_d2h_bw = 0;
	char sizechar[100];

	for (i = 0; i < device_count; i++) {
		info[i].size = size;
		info[i].multicard_test = 1;
	}
	/***
	 * To get selected cards's BW via multi-thread.
	 */
	for (i = 0; i < device_count; i++) {
		pthread_create(&th[i], NULL, get_copy_bandwidth, &info[i]);
	}
	for (i = 0; i < device_count; i++) {
		pthread_join(th[i], NULL);
	}

	if (info->size < 0x100000) {
		sprintf(sizechar, "%#lx\t\t", info->size);
	} else {
		sprintf(sizechar, "%#lx\t", info->size);
	}
	/***
	 * To get total BW value for multi cards.
	 */
	switch (info[0].dir) {
	case DMA_H2D:
	case DMA_D2D:
	case DMA_D2D_2D:
	case DMA_D2D_3D:
	case DMA_MEMSET:
		for (i = 0; i < device_count; i++) {
			total_h2d_bw += info[i].h2d_bw;
		}
		data_prt("%s\t%f\n", sizechar, total_h2d_bw);
		break;
	case DMA_D2H:
		for (i = 0; i < device_count; i++) {
			total_d2h_bw += info[i].d2h_bw;
		}
		data_prt("%s\t%f\n", sizechar, total_d2h_bw);
		break;
	case DMA_BOTHWAY:
		for (i = 0; i < device_count; i++) {
			total_h2d_bw += info[i].h2d_bw;
			total_d2h_bw += info[i].d2h_bw;
		}
		data_prt("%s\t%f(%f,%f)\n", sizechar,
			total_h2d_bw + total_d2h_bw, total_h2d_bw, total_d2h_bw);
		break;
	default:
		printf("Unknown DMA Direction\n");
		break;
	}

	return 0;
}

int run_multicard_bandwidth_test(struct dma_test_struct info[], int device_count,
			const int argc, const char **argv)
{
	int size;

	switch (info[0].cmd.mode) {
	case QUICK_MODE:
		get_multicard_bandwidth(info, DEFAULT_SIZE, device_count);
		break;
	case RANGE_MODE:
		for (size = info->cmd.start; size < info->cmd.end; size += info->cmd.increment) {
			get_multicard_bandwidth(info, size, device_count);
		}
		break;
	case SHMOO_MODE:
		for (size = 0x400; size < 0x8000000; size *= 2) {
			get_multicard_bandwidth(info, size, device_count);
		}
		break;
	case SMALL_SHMOO_MODE:
		for (size = 0x4; size < 0x800; size *= 2) {
			get_multicard_bandwidth(info, size, device_count);
		}
		break;
	default:
		printf("Invalid mode - valid modes are quick, range, or shmoo\n");
		printf("See --help for more information\n");
		break;
	}

}

int get_copy_latency(struct dma_test_struct *info)
{
	int i;
	void *queue;
	void *notifier_start;
	void *notifier_end;
	struct timeval stime;
	struct timeval etime;
	float msec;
	double latency_total = 0;
	int repeat_id;
	double range_min;
	double range_max;

	info->size = 0x4;
	/* cnCtxSetCurrent(info->ctx); */
	MLU_CHECK(alloc_dev_memory(info->fd, &info->dev_addr_0, info->size));
	MLU_CHECK(alloc_dev_memory(info->fd, &info->dev_addr_1, info->size));
	info->host_addr = pinned_mem_alloc(pin_fd, info->size);
	memset(info->host_addr, 0, info->size);
	DtoD_mdim_entry(info); /*To prepare the source for D2D Multi Dim*/
	_update_width_height_depth(info, 1); /*For D2D Multi Dim: Init width height depth*/

	/***
	 * Note:
	 *	repeat_num & th_repeat_num(but with single thread).
	 */
	for (repeat_id = 0; repeat_id < info->cmd.repeat_num; repeat_id++) {
		if (info->cmd.dma_mode == SYNC_MODE) {
			gettimeofday(&stime, NULL);
			switch (info->dir) {
			case DMA_H2D:
				for (i = 0; i < info->cmd.th_repeat_num; i++) {
					MLU_CHECK(h2d(info->fd, info->dev_addr_0, info->host_addr, info->size));
				}
				break;
			case DMA_D2H:
				for (i = 0; i < info->cmd.th_repeat_num; i++) {
					MLU_CHECK(d2h(info->fd, info->dev_addr_0, info->host_addr,info->size));
				}
				break;
			case DMA_D2D:
				for (i = 0; i < info->cmd.th_repeat_num; i++) {
					MLU_CHECK(d2d(info->fd, info->dev_addr_0, info->dev_addr_1, info->size));
				}
				break;
			case DMA_D2D_2D:
			case DMA_D2D_3D:
				for (i = 0; i < info->cmd.th_repeat_num; i++) {
					MLU_CHECK(DtoD_mdim_process(&info->bw_set[0]));
				}
				break;
			case DMA_MEMSET:
				for (i = 0; i < info->cmd.th_repeat_num; i++) {
					MLU_CHECK(mlu_memset_D8(info->fd, info->dev_addr_0, 0x5a, info->size));
				}
				break;
			default:
				printf("Unknown DMA Direction\n");
				break;
			}
			gettimeofday(&etime, NULL);
			info->result[repeat_id].latency = (double)(etime.tv_sec * 1000000  + etime.tv_usec -
					stime.tv_sec * 1000000 - stime.tv_usec) / info->cmd.th_repeat_num;
		} else {
			if (info->cmd.latency_mode == HW_LATENCY_MODE) {
				MLU_CHECK(create_queue(info->fd, &queue, 0));
				MLU_CHECK(create_notifier(info->fd, &notifier_start, 0));
				MLU_CHECK(create_notifier(info->fd, &notifier_end, 0));
				MLU_CHECK(place_notifier(info->fd, notifier_start, queue));

				switch (info->dir) {
				case DMA_H2D:
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(async_h2d(info->fd, info->dev_addr_0,
							info->host_addr, info->size, queue));
					}
					break;
				case DMA_D2H:
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(async_d2h(info->fd, info->dev_addr_0,
							info->host_addr, info->size, queue));
					}
					break;
				case DMA_D2D:
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(async_d2d(info->fd, info->dev_addr_0,
							info->dev_addr_1, info->size, queue));
					}
					break;
				case DMA_MEMSET:
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(mlu_memset_D8_async(info->fd, info->dev_addr_0,
							0x5a, info->size, queue));
					}
					break;
				default:
					printf("Unknown DMA Direction\n");
					break;
				}

				MLU_CHECK(place_notifier(info->fd, notifier_end, queue));
				MLU_CHECK(sync_queue(info->fd, queue));
				MLU_CHECK(elapsed_swtime_notifier(info->fd, &stime, notifier_start, notifier_end));
				MLU_CHECK(destroy_notifier(info->fd, notifier_start));
				MLU_CHECK(destroy_notifier(info->fd, notifier_end));
				MLU_CHECK(destroy_queue(info->fd, queue));
				info->result[repeat_id].latency = (double)(stime.tv_sec * 1000000 + stime.tv_usec) / info->cmd.th_repeat_num;
			} else {
				MLU_CHECK(create_queue(info->fd, &queue, 0));
				gettimeofday(&stime, NULL);
				switch (info->dir) {
				case DMA_H2D:
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(async_h2d(info->fd, info->dev_addr_0,
							info->host_addr, info->size, queue));
					}
					break;
				case DMA_D2H:
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(async_d2h(info->fd, info->dev_addr_0,
							info->host_addr, info->size, queue));
					}
					break;
				case DMA_D2D:
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(async_d2d(info->fd, info->dev_addr_0,
							info->dev_addr_1, info->size, queue));
					}
					break;
				case DMA_MEMSET:
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(mlu_memset_D8_async(info->fd, info->dev_addr_0,
							0x5a, info->size, queue));
					}
					break;
				default:
					printf("Unknown DMA Direction\n");
					break;
				}
				if (info->cmd.latency_mode == SW_LATENCY_MODE)
					MLU_CHECK(sync_queue(info->fd, queue));
				gettimeofday(&etime, NULL);
				MLU_CHECK(destroy_queue(info->fd, queue));
				info->result[repeat_id].latency = (double)(etime.tv_sec * 1000000  + etime.tv_usec -
						stime.tv_sec * 1000000 - stime.tv_usec) / info->cmd.th_repeat_num;
			}
		}
	}

	info->latency_max = 0;
	info->latency_min = 0xffffffff;
	info->latency_variance = 0;
	info->latency_sta_score = 0;
	range_min = (100 - info->cmd.sta_range) / 100;
	range_max = (100 + info->cmd.sta_range) / 100;
	for (repeat_id = 0; repeat_id < info->cmd.repeat_num; repeat_id++) {
		latency_total += info->result[repeat_id].latency;
		info->latency_min = (info->result[repeat_id].latency > info->latency_min ? info->latency_min : info->result[repeat_id].latency);
		info->latency_max = (info->result[repeat_id].latency < info->latency_max ? info->latency_max : info->result[repeat_id].latency);
	}
	info->latency = latency_total / info->cmd.repeat_num;

	if (info->cmd.variance == REPEAT_MODE) {
		for (repeat_id = 0; repeat_id < info->cmd.repeat_num; repeat_id++) {
			info->latency_variance += (info->result[repeat_id].latency - info->latency) * (info->result[repeat_id].latency - info->latency);
		}
	}

	for (i = 0; i < info->cmd.repeat_num; i++) {
		if ((info->result[i].latency >= info->latency * range_min) &&
			(info->result[i].latency <= info->latency * range_max))
			info->latency_sta_score++;
	}
	info->latency_sta_score = info->latency_sta_score / info->cmd.repeat_num * 100;

	if (info->host_addr) {
		pinned_mem_free(pin_fd, info->host_addr);
		info->host_addr = NULL;
	}
	if (info->dev_addr_0) {
		free_dev_memory(info->fd, info->dev_addr_0);
	}
	if (info->dev_addr_1) {
		free_dev_memory(info->fd, info->dev_addr_1);
	}
	DtoD_mdim_leave(info); /*To free the source for D2D Multi Dim*/

	print_latency_result(info);

	return 0;
}


void print_help(void)
{
	printf("Usage:  bandwidthTest [OPTION]...\n");
	printf("\n");
	printf("Options:\n");
	printf("--help\t\t\tDisplay this help menu\n");
	printf("--device=[deviceno]\tdefault:0\n");
	printf("  0,1,2,...,n\t\tSpecify any particular device to be used\n");
	printf("--memory=[MEMMODE]\tdefault:pinned\n");
	printf("  pageable\t\tpageable memory\n");
	printf("  pinned\t\tnon-pageable system memory\n");
	printf("--mode=[MODE]\t\tdefault:quick\n");
	printf("  quick\t\t\tperforms a quick measurement\n");
	printf("  range\t\t\tmeasures a user-specified range of values\n");
	printf("  shmoo\t\t\tperforms an intense shmoo of a large range of values\n");
	printf("  small_shmoo\t\tperforms an intense shmoo of a small range of values\n");
	printf("--dir=[DIRECTION]\tdefault:all\n");
	printf("  h2d\t\t\tMeasure host to device transfers\n");
	printf("  d2h\t\t\tMeasure device to host transfers\n");
	printf("  d2d\t\t\tMeasure device to device transfers\n");
	printf("  memset\t\tMeasure device memset transfers\n");
	printf("  bothway\t\tMeasure host to device and device to host transfers\n");
	printf("  d2d_2d\t\tMeasure device to device 2D transfers\n");
	printf("  d2d_3d\t\tMeasure device to device 3D transfers\n");
	printf("  all\t\t\tMeasure host to device and device to host transfers\n");
	printf("--thread=[THREAD_NUM]\tdefault:1 max:1024\n");
	printf("--dma_mode=[DMAMODE]\tdefault:async\n");
	printf("  sync\t\t\tuse sync dma to get bandwidth\n");
	printf("  async\t\t\tuse async dma to get bandwidth\n");
	printf("  async_no_batch\tuse async dma no batch to get bandwidth\n");
	printf("--repeat_num=[NUM]\ttest repeat num default:1 max:1000\n");
	printf("--th_repeat_num=[NUM]\tthread repeat num default:100\n");
	printf("--variance=[MODE]\tdefault:no_need\n");
	printf("  no_need\t\tno need variance\n");
	printf("  thread_mode\t\tmultithread bandwidth variance\n");
	printf("  repeat_mode\t\tmultirepeat bandwidth variance\n");
	printf("--sta_range=[0-100]\tstability score limit percent range\n");
	printf("--latency_mode=[MODE]\tasync dma latency mode default:hw_latency\n");
	printf("  hw_latency\t\tget async copy 4B data latency hardware time\n");
	printf("  sw_latency\t\tget async copy 4B data latency software time\n");
	printf("  api_latency\t\tget async copy api latency software time\n");
	printf("--numa_mode=[MODE]\tnuma mode default:disable\n");
	printf("  disable\t\tdisable numa node bind\n");
	printf("  enable\t\tenable cpunodebind and membind\n");
	printf("  cpu\t\t\tenable cpunodebind\n");
	printf("  mem\t\t\tenable membind\n");
	printf("Range mode options\n");
	printf("--start=[SIZE]\t\tStarting transfer size in bytes\n");
	printf("--end=[SIZE]\t\tEnding transfer size in bytes\n");
	printf("--increment=[SIZE]\tIncrement size in bytes\n");
	printf("Multi Dim options\n");
	printf("--width_shift==[N]\twidth left shift setting\n");
	printf("  0        \t\tNo left shift. Default.\n");
	printf("  1/2/...32\t\tLet it left shift N each time\n");
	printf("--init_width==[N]\twidth init setting\n");
	printf("  1/2/..Edge\t\tThe width init value is N, default 0x10.2D_Edge(0x%x) 3D_Edge(0x%x)\n", MAX_2D_WIDTH, MAX_3D_WIDTH);
	printf("--init_depth==[N]\tdepth init setting\n");
	printf("  1/2/.....n\t\tThe depth init value is N and keep it during test. Default 4.\n");
	printf("--memset_width==[N]\tmemset handle width setting\n");
	printf("  8/16/32\t\tThe memset handle width init for MemsetD8/16/32 Default 8.\n");
	printf("--noaligned=[flag]\tflag=1 enable noaligned_test flag=0 disable noaligned\n");
	printf("\nExample:\n");
	printf("./bw_sample --device=0 --mode=range --start=1024 --end=10240 --increment=1024 --dir=all\n");
	printf("./bw_sample --device=0 --memory=pinned --mode=shmoo --dir=bothway --thread=64 --dma_mode=sync\n");
	printf("./bw_sample --device=0 --memory=pinned --mode=shmoo --dir=h2d --thread=4 --dma_mode=sync --repeat_num=10 --th_repeat_num=100 --variance=repeat_mode --sta_range=10\n");
}

int analysis_cmd_line(const int argc, const char **argv, struct dma_test_struct *info)
{
	char *mem_mode = NULL;
	char *dir = NULL;
	char *mode = NULL;
	char *thread_num = NULL;
	char *dma_mode = NULL;
	char *variance = NULL;
	char *repeat_num = NULL;
	char *th_repeat_num = NULL;
	char *sta_range = NULL;
	char *latency_mode = NULL;
	char *numa_mode = NULL;
	char *width_shift = NULL;
	char *width = NULL;
	char *depth = NULL;
	char *memset_width = NULL;
	char *noaligned = NULL;

	if (getCmdLineArgumentString(argc, argv, "memory", &mem_mode)) {
		if (strcmp(mem_mode, "pageable") == 0) {
			info->cmd.mem_mode = PAGEABLE;
		} else if (strcmp(mem_mode, "pinned") == 0) {
			info->cmd.mem_mode = PINNED;
		} else {
			printf("Invalid memory mode - valid modes are pageable or pinned\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.mem_mode = PINNED;
	}

	if (getCmdLineArgumentString(argc, argv, "dir", &dir)) {
		if (strcmp(dir, "h2d") == 0) {
			info->cmd.h2d = true;
		} else if (strcmp(dir, "d2h") == 0) {
			info->cmd.d2h = true;
		} else if (strcmp(dir, "d2d") == 0) {
			info->cmd.d2d = true;
		} else if (strcmp(dir, "memset") == 0) {
			info->cmd.memset = true;
		} else if (strcmp(dir, "bothway") == 0) {
			info->cmd.bothway = true;
		} else if (strcmp(dir, "d2d_2d") == 0) {
			info->cmd.d2d_2d = true;
		} else if (strcmp(dir, "d2d_3d") == 0) {
			info->cmd.d2d_3d = true;
		} else if (strcmp(dir, "all") == 0) {
			info->cmd.h2d = true;
			info->cmd.d2h = true;
			info->cmd.d2d = true;
			info->cmd.memset = true;
			info->cmd.bothway = true;
			info->cmd.d2d_2d = true;
			info->cmd.d2d_3d = true;
		} else {
			printf("Invalid dir mode\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.h2d = true;
		info->cmd.d2h = true;
		info->cmd.d2d = true;
		info->cmd.memset = true;
		info->cmd.d2d_2d = true;
		info->cmd.d2d_3d = true;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "thread", &thread_num)) {
		info->cmd.thread_num = atoi(thread_num);
		if ((info->cmd.thread_num <= 0) || (info->cmd.thread_num > MAX_THREAD_NUM)) {
			printf("Invalid thread\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.thread_num = 1;
	}
	if (info->cmd.bothway) {
		info->cmd.thread_num *= 2;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "dma_mode", &dma_mode)) {
		if (strcmp(dma_mode, "sync") == 0) {
			info->cmd.dma_mode = SYNC_MODE;
		} else if (strcmp(dma_mode, "async") == 0) {
			info->cmd.dma_mode = ASYNC_MODE;
		} else if (strcmp(dma_mode, "async_no_batch") == 0) {
			info->cmd.dma_mode = ASYNC_NO_BATCH_MODE;
		} else {
			printf("Invalid dma_mode\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.dma_mode = ASYNC_MODE;
	}

	if (getCmdLineArgumentString(argc, argv, "mode", &mode)) {
		if (strcmp(mode, "quick") == 0) {
			info->cmd.mode = QUICK_MODE;
		} else if (strcmp(mode, "range") == 0) {
			info->cmd.mode = RANGE_MODE;
		} else if (strcmp(mode, "shmoo") == 0) {
			info->cmd.mode = SHMOO_MODE;
		} else if (strcmp(mode, "small_shmoo") == 0) {
			info->cmd.mode = SMALL_SHMOO_MODE;
		} else {
			printf("Invalid mode - valid modes are quick, range, or shmoo\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.mode = QUICK_MODE;
	}

	if (info->cmd.mode == RANGE_MODE) {
		if (checkCmdLineFlag(argc, (const char **)argv, "start")) {
			info->cmd.start = getCmdLineArgumentInt(argc, argv, "start");

			if (info->cmd.start <= 0) {
				printf("Illegal argument - start must be greater than zero\n");
				return -1;
			}
		} else {
			printf("Must specify a starting size in range mode\n");
			printf("See --help for more information\n");
			return -1;
		}

		if (checkCmdLineFlag(argc, (const char **)argv, "end")) {
			info->cmd.end = getCmdLineArgumentInt(argc, argv, "end");

			if (info->cmd.end <= 0) {
				printf("Illegal argument - end must be greater than zero\n");
				return -1;
			}

			if (info->cmd.start > info->cmd.end) {
				printf("Illegal argument - start is greater than end\n");
				return -1;
			}
		} else {
			printf("Must specify an end size in range mode.\n");
			printf("See --help for more information\n");
			return -1;
		}


		if (checkCmdLineFlag(argc, argv, "increment")) {
			info->cmd.increment = getCmdLineArgumentInt(argc, argv, "increment");

			if (info->cmd.increment <= 0) {
				printf("Illegal argument - increment must be greater than zero\n");
				return -1;
			}
		} else {
			printf("Must specify an increment in user mode\n");
			printf("See --help for more information\n");
			return -1;
		}
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "variance", &variance)) {
		if (strcmp(variance, "no_need") == 0) {
			info->cmd.variance = NO_NEED_MODE;
		} else if (strcmp(variance, "thread_mode") == 0) {
			info->cmd.variance = THREAD_MODE;
		} else if (strcmp(variance, "repeat_mode") == 0) {
			info->cmd.variance = REPEAT_MODE;
		} else {
			printf("Invalid variance\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.variance = NO_NEED_MODE;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "repeat_num", &repeat_num)) {
		info->cmd.repeat_num = atoi(repeat_num);
		if ((info->cmd.repeat_num <= 0) || (info->cmd.repeat_num > MAX_REPEAT_NUM)) {
			printf("Invalid repeat_num\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.repeat_num = 1;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "th_repeat_num", &th_repeat_num)) {
		info->cmd.th_repeat_num = atoi(th_repeat_num);
		if (info->cmd.th_repeat_num <= 0) {
			printf("Invalid th_repeat_num\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.th_repeat_num = DEFAULT_THREAD_REPEAT_NUM;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "sta_range", &sta_range)) {
		info->cmd.sta_range = (double)atoi(sta_range);
		if (info->cmd.sta_range <= 0) {
			printf("Invalid sta_range\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.sta_range = 0;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "latency_mode", &latency_mode)) {
		if (strcmp(latency_mode, "hw_latency") == 0) {
			info->cmd.latency_mode = HW_LATENCY_MODE;
		} else if (strcmp(latency_mode, "sw_latency") == 0) {
			info->cmd.latency_mode = SW_LATENCY_MODE;
		} else if (strcmp(latency_mode, "api_latency") == 0) {
			info->cmd.latency_mode = API_LATENCY_MODE;
		} else {
			printf("Invalid latency_mode\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.latency_mode = HW_LATENCY_MODE;
	}

#ifndef NUMA_DISABLE
	if (getCmdLineArgumentString(argc, (const char **)argv, "numa_mode", &numa_mode)) {
		if (strcmp(numa_mode, "disable") == 0) {
			info->cmd.cpu_numa = false;
			info->cmd.mem_numa = false;
		} else if (strcmp(numa_mode, "enable") == 0) {
			info->cmd.cpu_numa = true;
			info->cmd.mem_numa = true;
		} else if (strcmp(numa_mode, "cpu") == 0) {
			info->cmd.cpu_numa = true;
			info->cmd.mem_numa = false;
		} else if (strcmp(numa_mode, "mem") == 0) {
			info->cmd.cpu_numa = false;
			info->cmd.mem_numa = true;
		} else {
			printf("Invalid numa_mode\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.cpu_numa = false;
		info->cmd.mem_numa = false;
	}
#else
	info->cmd.cpu_numa = false;
	info->cmd.mem_numa = false;
#endif

	if (getCmdLineArgumentString(argc, (const char **)argv, "width_shift", &width_shift)) {
		info->cmd.width_shift = getCmdLineArgumentInt(argc, argv, "width_shift");
		if (info->cmd.width_shift < 0 || info->cmd.width_shift >= MAX_WIDTH_LEFT_SHIFT) {
			printf("Invalid width_shift\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.width_shift = 0;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "init_width", &width)) {
		info->cmd.width = getCmdLineArgumentInt(argc, argv, "init_width");
		if (info->cmd.width <= 0 ||
		    (info->dir == DMA_D2D_2D && info->cmd.width > MAX_2D_WIDTH) ||
		    (info->dir == DMA_D2D_3D && info->cmd.width > MAX_3D_WIDTH)) {
			printf("Invalid width, shall BiggerEqual 1 [0x%lx].\n", info->cmd.width);
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.width = DEFAULT_MDIM_WIDTH;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "init_depth", &depth)) {
		info->cmd.depth = getCmdLineArgumentInt(argc, argv, "init_depth");
		if (info->cmd.depth <= 0) {
			printf("Invalid depth, shall BiggerEqual 1.\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.depth = DEFAULT_3D_DEPTH;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "memset_width", &memset_width)) {
		info->cmd.memset_width = getCmdLineArgumentInt(argc, argv, "memset_width");
		if (info->cmd.memset_width != 8 &&
		    info->cmd.memset_width != 16 &&
		    info->cmd.memset_width != 32) {
			printf("Invalid memset width, shall BiggerEqual 8/16/32 [0x%lx].\n", info->cmd.memset_width);
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.memset_width = DEFAULT_MEMSET_WIDTH;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "noaligned", &noaligned)) {
		info->cmd.noaligned = atoi(noaligned);
	} else {
		info->cmd.noaligned = false;
	}

	if (info->dir == DMA_D2D_2D) {
		if (info->size % info->width) {
			printf("Invalid 3D size-width, size must aliquot width.\n");
			printf("See --help for more information\n");
			return -1;
		}
	}
	if (info->dir == DMA_D2D_3D) {
		if (info->size % info->depth) {
			printf("Invalid 3D size-depth, size must aliquot depth.\n");
			printf("See --help for more information\n");
			return -1;
		}
		if ((info->size / info->depth) % info->width) {
			printf("Invalid 3D size-depth-width, size/depth must aliquot width.\n");
			printf("See --help for more information\n");
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int i = 0;
	int ret = 0;
	int device_count = 0;
	char *device = NULL;
	char device_prt[100];
	int run_device[128] = {0};
	int cap_fd[128][CN_DEV_MAX_INSTANCE_COUNT] = {0};
	int run_device_count;
	char seps[] = ",";
	char *token;

	srand(time(NULL));

	if (checkCmdLineFlag(argc, (const char **)argv, "help")) {
		print_help();
		return 0;
	}

	cpu_num = sysconf(_SC_NPROCESSORS_CONF);
	pin_fd = open_mem_dev();
	if (pin_fd < 0) {
		printf("mlu init FAILED\n");
		return -1;
	}
	device_count = get_card_num(pin_fd);
	if (device_count == 0) {
		printf("!!!!!No devices found!!!!!\n");
		return -1;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "device", &device)) {
		i = 0;
		token = strtok(device, seps);
		while (token) {
			run_device[i] = atoi(token);
			if (run_device[i] >= device_count) {
				printf("Invalid device param\n");
				return -1;
			}
			token = strtok(NULL, seps);
			i++;
		}
		run_device_count = i;
		for (i = 0; i < run_device_count; i++) {
			if (i)
				sprintf(device_prt, "%s,%d", device_prt, run_device[i]);
			else
				sprintf(device_prt, "%d", run_device[i]);
		}
	} else {
		run_device[i] = 0;
		run_device_count = 1;
	}

	struct dma_test_struct *info = (struct dma_test_struct *)malloc(run_device_count *
			sizeof(struct dma_test_struct));

	memset(info, 0, sizeof(struct dma_test_struct) * run_device_count);
	for (i = 0; i < run_device_count; i++) {
		if (open_cambricon_cap(i, cap_fd[i])) {
			printf("open cambricon-caps FAILED\n");
			return -1;
		}
		info[i].fd = open_cambricon_dev(run_device[i]);
		if (info[i].fd < 0) {
			printf("mlu init FAILED\n");
			return -1;
		}
		info[i].card_id = run_device[i];
		get_card_bdf(info[i].fd, info[i].bdf);
		info[i].numa_node = get_numa_node(info[i].bdf);
	}

	for (i = 0; i < run_device_count; i++) {
		if (analysis_cmd_line(argc, (const char **)argv, &info[i])) {
			printf("analysis_cmd_line FAILED\n");
			return -1;
		}
	}
	/***
	 * Tranverse selected cards one by one.
	 *	1. get and show BW of one card after 'multi-thread & repeat-num' process
	 *	2. get and show latency
	 */
	for (i = 0; i < run_device_count; i++) {
#ifndef NUMA_DISABLE
		if (info[i].cmd.cpu_numa) {
			numa_run_on_node(info[i].numa_node);
		}
		if (info[i].cmd.mem_numa) {
			set_numa_ctrl(info[i].bdf, true);
		}
#endif
		if (info[i].cmd.h2d) {
			data_prt("Host to Device Bandwidth, Device:%d\n", run_device[i]);
			info[i].dir = DMA_H2D;
			print_result_title(&info[i]);
			run_copy_bandwidth_test(&info[i]);
			printf("\n");

			printf("Host to Device Latency, Device:%d\n", run_device[i]);
			printf("Latency(us)");
			get_copy_latency(&info[i]);
			printf("\n");
		}
		if (info[i].cmd.d2h) {
			data_prt("Device to Host Bandwidth, Device:%d\n", run_device[i]);
			info[i].dir = DMA_D2H;
			print_result_title(&info[i]);
			run_copy_bandwidth_test(&info[i]);
			printf("\n");

			printf("Device to Host Latency, Device:%d\n", run_device[i]);
			printf("Latency(us)");
			get_copy_latency(&info[i]);
			printf("\n");
		}
		if (info[i].cmd.d2d) {
			data_prt("Device to Device Bandwidth, Device:%d\n", run_device[i]);
			info[i].dir = DMA_D2D;
			print_result_title(&info[i]);
			run_copy_bandwidth_test(&info[i]);
			printf("\n");

			printf("Device to Device Latency, Device:%d\n", run_device[i]);
			printf("Latency(us)");
			get_copy_latency(&info[i]);
			printf("\n");
		}
		if (info[i].cmd.memset) {
			data_prt("Device Memset Bandwidth, Device:%d\n", run_device[i]);
			info[i].dir = DMA_MEMSET;
			print_result_title(&info[i]);
			run_copy_bandwidth_test(&info[i]);
			printf("\n");

			printf("Device Memset Latency, Device:%d\n", run_device[i]);
			printf("Latency(us)");
			get_copy_latency(&info[i]);
			printf("\n");
		}
		if (info[i].cmd.bothway) {
			data_prt("Bothway Bandwidth, Device:%d\n", run_device[i]);
			info[i].dir = DMA_BOTHWAY;
			print_result_title(&info[i]);
			run_copy_bandwidth_test(&info[i]);
			printf("\n");
		}
		if (info[i].cmd.d2d_2d && IF_D2D_2D_TEST(info[i].cmd.dma_mode)) {
			//printf("Do not support Device to Device 2D Method!\n");
			//goto final;
			data_prt("Device to Device 2D Bandwidth, Device:%d\n", i);
			info[i].dir = DMA_D2D_2D;
			print_result_title(&info[i]);
			run_copy_bandwidth_test(&info[i]);
			printf("\n");

			printf("Device to Device 2D Latency, Device:%d\n", run_device[i]);
			printf("Latency(us)");
			get_copy_latency(&info[i]);
			printf("\n");
		}
		if (info[i].cmd.d2d_3d && IF_D2D_3D_TEST(info[i].cmd.dma_mode)) {
			//printf("Do not support Device to Device 3D Method!\n");
			//goto final;
			data_prt("Device to Device 3D Bandwidth, Device:%d\n", i);
			info[i].dir = DMA_D2D_3D;
			print_result_title(&info[i]);
			run_copy_bandwidth_test(&info[i]);
			printf("\n");

			printf("Device to Device 3D Latency, Device:%d\n", run_device[i]);
			printf("Latency(us)");
			get_copy_latency(&info[i]);
			printf("\n");
		}
#ifndef NUMA_DISABLE
		if (info[i].cmd.cpu_numa) {
			numa_run_on_node(-1);
		}
		if (info[i].cmd.mem_numa) {
			set_numa_ctrl(info[i].bdf, false);
		}
#endif
	}

	/***
	 * All selected cards multi test.
	 *	1, All selected cards start to get BW without shown at the same time,
	 *	2. Show the total BW of all selected cards.
	 */
	if (run_device_count > 1) {
		if (info[0].cmd.h2d) {
			data_prt("Host to Device Bandwidth, Device:%s\n", device_prt);
			data_prt("Transfer Size (Bytes)	Bandwidth(GB/s)\n");
			for (i = 0; i < run_device_count; i++) {
				info[i].dir = DMA_H2D;
			}
			run_multicard_bandwidth_test(info, run_device_count, argc, (const char **)argv);
			printf("\n");
		}
		if (info[0].cmd.d2h) {
			data_prt("Device to Host Bandwidth, Device:%s\n", device_prt);
			data_prt("Transfer Size (Bytes)	Bandwidth(GB/s)\n");
			for (i = 0; i < run_device_count; i++) {
				info[i].dir = DMA_D2H;
			}
			run_multicard_bandwidth_test(info, run_device_count, argc, (const char **)argv);
			printf("\n");
		}
		if (info[0].cmd.d2d) {
			data_prt("Device to Device Bandwidth, Device:%s\n", device_prt);
			data_prt("Transfer Size (Bytes)	Bandwidth(GB/s)\n");
			for (i = 0; i < run_device_count; i++) {
				info[i].dir = DMA_D2D;
			}
			run_multicard_bandwidth_test(info, run_device_count, argc, (const char **)argv);
			printf("\n");
		}
		if (info[0].cmd.memset) {
			data_prt("Device Memset Bandwidth, Device:%s\n", device_prt);
			data_prt("Transfer Size (Bytes)	Bandwidth(GB/s)\n");
			for (i = 0; i < run_device_count; i++) {
				info[i].dir = DMA_MEMSET;
			}
			run_multicard_bandwidth_test(info, run_device_count, argc, (const char **)argv);
			printf("\n");
		}
		if (info[0].cmd.bothway) {
			data_prt("Bothway Bandwidth, Device:%s\n", device_prt);
			data_prt("Transfer Size (Bytes)	Bandwidth(GB/s)\n");
			for (i = 0; i < run_device_count; i++) {
				info[i].dir = DMA_BOTHWAY;
			}
			run_multicard_bandwidth_test(info, run_device_count, argc, (const char **)argv);
			printf("\n");
		}
		if (info[0].cmd.d2d_2d && IF_D2D_2D_TEST(info[0].cmd.dma_mode)) {
			data_prt("Device to Device 2D Bandwidth, Device:%s\n", device_prt);
			data_prt("Transfer Size (Bytes)	Bandwidth(GB/s)\n");
			for (i = 0; i < run_device_count; i++) {
				info[i].dir = DMA_D2D_2D;
			}
			run_multicard_bandwidth_test(info, run_device_count, argc, (const char **)argv);
			printf("\n");
		}
		if (info[0].cmd.d2d_3d && IF_D2D_3D_TEST(info[0].cmd.dma_mode)) {
			data_prt("Device to Device 3D Bandwidth, Device:%s\n", device_prt);
			data_prt("Transfer Size (Bytes)	Bandwidth(GB/s)\n");
			for (i = 0; i < run_device_count; i++) {
				info[i].dir = DMA_D2D_3D;
			}
			run_multicard_bandwidth_test(info, run_device_count, argc, (const char **)argv);
			printf("\n");
		}
	}

final:
	for (i = 0; i < run_device_count; i++) {
		close_cambricon_dev(info[i].fd);
		close_cambricon_cap(cap_fd[i]);
	}
	close_mem_dev(pin_fd);
	return 0;
}
