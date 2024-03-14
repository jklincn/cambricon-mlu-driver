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

#define DEFAULT_THREAD_REPEAT_NUM 100
#define DEFAULT_SIZE 0x2000000
#define MAX_THREAD_NUM 1024
#define MAX_REPEAT_NUM 1000

int pin_fd;
enum dma_dir_type {
	DMA_P2P_L2H = 0,
	DMA_P2P_H2L,
	DMA_P2P_BOTHWAY,
};
enum dmaMode { SYNC_MODE, ASYNC_MODE, ASYNC_NO_BATCH_MODE };
enum testMode { QUICK_MODE, RANGE_MODE, SHMOO_MODE, SMALL_SHMOO_MODE };
enum varianceMode { NO_NEED_MODE, THREAD_MODE, REPEAT_MODE };
enum latencyMode { HW_LATENCY_MODE, SW_LATENCY_MODE, API_LATENCY_MODE };
uint64_t dev[128];
int fd[128];
int peer_able[128][128];
int cpu_num;

#define MLU_CHECK(func) \
({ \
	int ret = func; \
	if (ret) { \
		printf("%s@%d %s return %d FAILED\n", __func__, __LINE__, #func, ret); \
		exit(-1); \
	} \
})

struct cmd_line_struct {
	unsigned int start;
	unsigned int end;
	unsigned int increment;
	enum testMode mode;
	unsigned int thread_num;
	enum dmaMode dma_mode;
	enum dma_dir_type dir;
	enum varianceMode variance;
	unsigned int repeat_num;
	unsigned int th_repeat_num;
	double sta_range;
	enum latencyMode latency_mode;
};

struct dma_bw_struct {
	int src_fd;
	int dst_fd;
	uint64_t src_addr;
	uint64_t dst_addr;
	void *queue;
	struct timeval stime;
	struct timeval etime;
	unsigned long size;
	int th_id;
	int dir;
	unsigned int th_repeat_num;
	double bw;
	void *info;
};

struct bw_result_struct {
	double h2l_bw;
	double l2h_bw;
	double h2l_th_variance;
	double l2h_th_variance;
	double latency;
};

struct dma_test_struct {
	int fd0;
	int fd1;
	uint64_t dev0_addr;
	uint64_t dev1_addr;
	void *host_addr;
	unsigned long size;
	enum dma_dir_type dir;
	struct cmd_line_struct cmd;
	int th_id;
	struct dma_bw_struct bw_set[MAX_THREAD_NUM];
	struct bw_result_struct result[MAX_REPEAT_NUM];
	int repeat_id;
	double h2l_bw;
	double l2h_bw;
	double h2l_bw_min;
	double l2h_bw_min;
	double h2l_bw_max;
	double l2h_bw_max;
	double h2l_variance;
	double l2h_variance;
	double h2l_sta_score;
	double l2h_sta_score;
	double latency;
	double latency_min;
	double latency_max;
	double latency_variance;
	double latency_sta_score;
	int device_count;
};

void *sync_dma_thread(void *arg)
{
	struct dma_bw_struct *bw_set = (struct dma_bw_struct *)arg;
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
	cnCtxSetCurrent(bw_set->src_ctx);
	*/
	gettimeofday(&bw_set->stime, NULL);
	if (bw_set->src_fd != bw_set->dst_fd) {
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(p2p(bw_set->src_fd, bw_set->dst_fd,
				bw_set->dst_addr, bw_set->src_addr, bw_set->size));
		}
	} else {
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(d2d(bw_set->src_fd, bw_set->dst_addr,
				bw_set->src_addr, bw_set->size));
		}
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
	cnCtxSetCurrent(bw_set->src_ctx);
	*/
	gettimeofday(&bw_set->stime, NULL);
	if (bw_set->src_fd != bw_set->dst_fd) {
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(async_p2p(bw_set->src_fd, bw_set->dst_fd,
				bw_set->dst_addr, bw_set->src_addr, bw_set->queue, bw_set->size));
			if (info->cmd.dma_mode == ASYNC_NO_BATCH_MODE)
				MLU_CHECK(sync_queue(bw_set->src_fd, bw_set->queue));
		}
	} else {
		for (i = 0; i < bw_set->th_repeat_num; i++) {
			MLU_CHECK(async_d2d(bw_set->src_fd, bw_set->dst_addr,
				bw_set->src_addr, bw_set->size, bw_set->queue));
			if (info->cmd.dma_mode == ASYNC_NO_BATCH_MODE)
				MLU_CHECK(sync_queue(bw_set->src_fd, bw_set->queue));
		}
	}
	MLU_CHECK(sync_queue(bw_set->src_fd, bw_set->queue));
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
	double l2h_ave = 0;
	double h2l_ave = 0;
	int i;

	switch (info->dir) {
	case DMA_P2P_L2H:
		stime = 1000000 * info->bw_set[0].stime.tv_sec + info->bw_set[0].stime.tv_usec;
		etime = 1000000 * info->bw_set[0].etime.tv_sec + info->bw_set[0].etime.tv_usec;
		for (i = 0; i < info->cmd.thread_num; i++) {
			if (stime > (1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec))
				stime = 1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec;
			if (etime < (1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec))
				etime = 1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec;
		}
		info->result[info->repeat_id].l2h_bw = info->cmd.th_repeat_num * info->size * info->cmd.thread_num / (etime - stime) / 1000;

		info->result[info->repeat_id].l2h_th_variance = 0;
		for (i = 0; i < info->cmd.thread_num; i++) {
			l2h_ave += info->bw_set[i].bw;
		}
		l2h_ave = l2h_ave / info->cmd.thread_num;
		for (i = 0; i < info->cmd.thread_num; i++) {
			info->result[info->repeat_id].l2h_th_variance += (info->bw_set[i].bw - l2h_ave) * (info->bw_set[i].bw - l2h_ave);
		}
		info->result[info->repeat_id].l2h_th_variance = info->result[info->repeat_id].l2h_th_variance / info->cmd.thread_num;

		break;
	case DMA_P2P_BOTHWAY:
		stime = 1000000 * info->bw_set[0].stime.tv_sec + info->bw_set[0].stime.tv_usec;
		etime = 1000000 * info->bw_set[0].etime.tv_sec + info->bw_set[0].etime.tv_usec;
		for (i = 0; i < info->cmd.thread_num; i += 2) {
			if (stime > (1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec))
				stime = 1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec;
			if (etime < (1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec))
				etime = 1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec;
		}
		info->result[info->repeat_id].l2h_bw = info->cmd.th_repeat_num * info->size * info->cmd.thread_num / 2 / (etime - stime) / 1000;
		stime = 1000000 * info->bw_set[1].stime.tv_sec + info->bw_set[1].stime.tv_usec;
		etime = 1000000 * info->bw_set[1].etime.tv_sec + info->bw_set[1].etime.tv_usec;
		for (i = 1; i < info->cmd.thread_num; i += 2) {
			if (stime > (1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec))
				stime = 1000000 * info->bw_set[i].stime.tv_sec + info->bw_set[i].stime.tv_usec;
			if (etime < (1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec))
				etime = 1000000 * info->bw_set[i].etime.tv_sec + info->bw_set[i].etime.tv_usec;
		}
		info->result[info->repeat_id].h2l_bw = info->cmd.th_repeat_num * info->size * info->cmd.thread_num / 2 / (etime - stime) / 1000;

		info->result[info->repeat_id].l2h_th_variance = 0;
		for (i = 0; i < info->cmd.thread_num; i += 2) {
			l2h_ave += info->bw_set[i].bw;
		}
		l2h_ave = l2h_ave / info->cmd.thread_num / 2;
		for (i = 0; i < info->cmd.thread_num; i += 2) {
			info->result[info->repeat_id].l2h_th_variance += (info->bw_set[i].bw - l2h_ave) * (info->bw_set[i].bw - l2h_ave);
		}
		info->result[info->repeat_id].l2h_th_variance = info->result[info->repeat_id].l2h_th_variance / info->cmd.thread_num / 2;

		info->result[info->repeat_id].h2l_th_variance = 0;
		for (i = 1; i < info->cmd.thread_num; i += 2) {
			h2l_ave += info->bw_set[i].bw;
		}
		h2l_ave = h2l_ave / info->cmd.thread_num / 2;
		for (i = 1; i < info->cmd.thread_num; i += 2) {
			info->result[info->repeat_id].h2l_th_variance += (info->bw_set[i].bw - h2l_ave) * (info->bw_set[i].bw - h2l_ave);
		}
		info->result[info->repeat_id].h2l_th_variance = info->result[info->repeat_id].h2l_th_variance / info->cmd.thread_num / 2;
		break;
	default:
		printf("Unknown DMA Direction\n");
		break;
	}
}

void get_repeat_bandwidth_result(struct dma_test_struct *info)
{
	double h2l_bw_total = 0;
	double l2h_bw_total = 0;
	int i = 0;
	double range_min;
	double range_max;

	info->h2l_bw_max = 0;
	info->l2h_bw_max = 0;
	info->h2l_bw_min = 0xff;
	info->l2h_bw_min = 0xff;
	info->h2l_variance = 0;
	info->l2h_variance = 0;
	info->h2l_sta_score = 0;
	info->l2h_sta_score = 0;
	range_min = (100 - info->cmd.sta_range) / 100;
	range_max = (100 + info->cmd.sta_range) / 100;
	switch (info->dir) {
	case DMA_P2P_L2H:
		for (i = 0; i < info->cmd.repeat_num; i++) {
			l2h_bw_total += info->result[i].l2h_bw;
			info->l2h_bw_min = (info->result[i].l2h_bw > info->l2h_bw_min ? info->l2h_bw_min : info->result[i].l2h_bw);
			info->l2h_bw_max = (info->result[i].l2h_bw < info->l2h_bw_max ? info->l2h_bw_max : info->result[i].l2h_bw);
		}
		info->l2h_bw = l2h_bw_total / info->cmd.repeat_num;

		if (info->cmd.variance == THREAD_MODE) {
			info->l2h_variance += info->result[info->repeat_id].l2h_th_variance;
		} else if (info->cmd.variance == REPEAT_MODE) {
			for (i = 0; i < info->cmd.repeat_num; i++) {
				info->l2h_variance += (info->result[i].l2h_bw - info->l2h_bw) * (info->result[i].l2h_bw - info->l2h_bw);
			}
		}
		info->l2h_variance = info->l2h_variance / info->cmd.repeat_num;

		for (i = 0; i < info->cmd.repeat_num; i++) {
			if ((info->result[i].l2h_bw >= info->l2h_bw * range_min) &&
				(info->result[i].l2h_bw <= info->l2h_bw * range_max))
				info->l2h_sta_score++;
		}
		info->l2h_sta_score = info->l2h_sta_score / info->cmd.repeat_num * 100;
		break;
	case DMA_P2P_BOTHWAY:
		for (i = 0; i < info->cmd.repeat_num; i++) {
			l2h_bw_total += info->result[i].l2h_bw;
			info->l2h_bw_min = (info->result[i].l2h_bw > info->l2h_bw_min ? info->l2h_bw_min : info->result[i].l2h_bw);
			info->l2h_bw_max = (info->result[i].l2h_bw < info->l2h_bw_max ? info->l2h_bw_max : info->result[i].l2h_bw);
		}
		info->l2h_bw = l2h_bw_total / info->cmd.repeat_num;

		if (info->cmd.variance == THREAD_MODE) {
			info->l2h_variance += info->result[info->repeat_id].l2h_th_variance;
		} else if (info->cmd.variance == REPEAT_MODE) {
			for (i = 0; i < info->cmd.repeat_num; i++) {
				info->l2h_variance += (info->result[i].l2h_bw - info->l2h_bw) * (info->result[i].l2h_bw - info->l2h_bw);
			}
		}
		info->l2h_variance = info->l2h_variance / info->cmd.repeat_num;

		for (i = 0; i < info->cmd.repeat_num; i++) {
			if ((info->result[i].l2h_bw >= info->l2h_bw * range_min) &&
				(info->result[i].l2h_bw <= info->l2h_bw * range_max))
				info->l2h_sta_score++;
		}
		info->l2h_sta_score = info->l2h_sta_score / info->cmd.repeat_num * 100;

		for (i = 0; i < info->cmd.repeat_num; i++) {
			h2l_bw_total += info->result[i].h2l_bw;
			info->h2l_bw_min = (info->result[i].h2l_bw > info->h2l_bw_min ? info->h2l_bw_min : info->result[i].h2l_bw);
			info->h2l_bw_max = (info->result[i].h2l_bw < info->h2l_bw_max ? info->h2l_bw_max : info->result[i].h2l_bw);
		}
		info->h2l_bw = h2l_bw_total / info->cmd.repeat_num;

		if (info->cmd.variance == THREAD_MODE) {
			info->h2l_variance += info->result[info->repeat_id].h2l_th_variance;
		} else if (info->cmd.variance == REPEAT_MODE) {
			for (i = 0; i < info->cmd.repeat_num; i++) {
				info->h2l_variance += (info->result[i].h2l_bw - info->h2l_bw) * (info->result[i].h2l_bw - info->h2l_bw);
			}
		}
		info->h2l_variance = info->h2l_variance / info->cmd.repeat_num;

		break;
	default:
		printf("Unknown DMA Direction\n");
		break;
	}
}

void print_result_title(struct dma_test_struct *info)
{
	switch (info->dir) {
	case DMA_P2P_L2H:
		if (info->cmd.repeat_num > 1) {
			if (info->cmd.variance == NO_NEED_MODE) {
				if (info->cmd.sta_range) {
					printf("Transfer Size\t\tAvg(GB/s)\t\tMin(GB/s)\t\tMax(GB/s)\t\tStability_Score\n");
				} else {
					printf("Transfer Size\t\tAvg(GB/s)\t\tMin(GB/s)\t\tMax(GB/s)\n");
				}
			} else {
				if (info->cmd.sta_range) {
					printf("Transfer Size\t\tAvg(GB/s)\t\tMin(GB/s)\t\tMax(GB/s)\t\tVariance\t\tStability_Score\n");
				} else {
					printf("Transfer Size\t\tAvg(GB/s)\t\tMin(GB/s)\t\tMax(GB/s)\t\tVariance\n");
				}
			}
		} else {
			if (info->cmd.variance == NO_NEED_MODE) {
				printf("Transfer Size\t\tBandwidth(GB/s)\n");
			} else {
				printf("Transfer Size\t\tBandwidth(GB/s)\t\tVariance\n");
			}
		}
		break;
	case DMA_P2P_BOTHWAY:
		if (info->cmd.repeat_num > 1) {
			if (info->cmd.variance == NO_NEED_MODE) {
				if (info->cmd.sta_range) {
					printf("Transfer Size\t\tAvg(GB/s)\t\t\t\tMin(GB/s)\t\tMax(GB/s)\t\tStability_Score\n");
				} else {
					printf("Transfer Size\t\tAvg(GB/s)\t\t\t\tMin(GB/s)\t\tMax(GB/s)\n");
				}
			} else {
				if (info->cmd.sta_range) {
					printf("Transfer Size\t\tAvg(GB/s)\t\t\t\tMin(GB/s)\t\tMax(GB/s)\t\tVariance\t\tStability_Score\n");
				} else {
					printf("Transfer Size\t\tAvg(GB/s)\t\t\t\tMin(GB/s)\t\tMax(GB/s)\t\tVariance\n");
				}
			}
		} else {
			if (info->cmd.variance == NO_NEED_MODE) {
				printf("Transfer Size\t\tBandwidth(GB/s)\n");
			} else {
				printf("Transfer Size\t\tBandwidth(GB/s)\t\t\t\tVariance\n");
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
	if (info->size < 0x100000) {
		sprintf(sizechar, "%#lx\t\t", info->size);
	} else {
		sprintf(sizechar, "%#lx\t", info->size);
	}

	switch (info->dir) {
	case DMA_P2P_L2H:
		if (info->device_count) {
			printf("\t%f", info->l2h_bw);
		} else {
			if (info->cmd.repeat_num > 1) {
				if (info->cmd.variance == NO_NEED_MODE) {
					if (info->cmd.sta_range) {
						printf("%s\t%f\t\t%f\t\t%f\t\t%.2f\n", sizechar,
							info->l2h_bw, info->l2h_bw_min, info->l2h_bw_max, info->l2h_sta_score);
					} else {
						printf("%s\t%f\t\t%f\t\t%f\n", sizechar,
							info->l2h_bw, info->l2h_bw_min, info->l2h_bw_max);
					}
				} else {
					if (info->cmd.sta_range) {
						printf("%s\t%f\t\t%f\t\t%f\t\t%f\t\t%.2f\n", sizechar,
							info->l2h_bw, info->l2h_bw_min, info->l2h_bw_max,
							info->l2h_variance, info->l2h_sta_score);
					} else {
						printf("%s\t%f\t\t%f\t\t%f\t\t%f\n", sizechar,
							info->l2h_bw, info->l2h_bw_min, info->l2h_bw_max, info->l2h_variance);
					}
				}
			} else {
				if (info->cmd.variance == NO_NEED_MODE) {
					printf("%s\t%f\n", sizechar, info->l2h_bw);
				} else {
					printf("%s\t%f\t\t%f\n", sizechar, info->l2h_bw, info->l2h_variance);
				}
			}
		}
		break;
	case DMA_P2P_BOTHWAY:
		if (info->device_count) {
			printf("\t%f(%f,%f)", info->l2h_bw + info->h2l_bw, info->l2h_bw, info->h2l_bw);
		} else {
			if (info->cmd.repeat_num > 1) {
				if (info->cmd.variance == NO_NEED_MODE) {
					if (info->cmd.sta_range) {
						printf("%s\t%f(%f,%f)\t\t%f\t\t%f\t\t%.2f\n", sizechar,
							info->l2h_bw + info->h2l_bw, info->l2h_bw, info->h2l_bw,
							info->l2h_bw_min + info->h2l_bw_min,
							info->l2h_bw_max + info->h2l_bw_max,
							info->l2h_sta_score + info->h2l_sta_score);
					} else {
						printf("%s\t%f(%f,%f)\t\t%f\t\t%f\n", sizechar,
							info->l2h_bw + info->h2l_bw, info->l2h_bw, info->h2l_bw,
							info->l2h_bw_min + info->h2l_bw_min,
							info->l2h_bw_max + info->h2l_bw_max);
					}
				} else {
					if (info->cmd.sta_range) {
						printf("%s\t%f(%f,%f)\t\t%f\t\t%f\t\t%f\t\t%.2f\n", sizechar,
							info->l2h_bw + info->h2l_bw, info->l2h_bw, info->h2l_bw,
							info->l2h_bw_min + info->h2l_bw_min,
							info->l2h_bw_max + info->h2l_bw_max,
							info->l2h_variance + info->h2l_variance,
							info->l2h_sta_score + info->h2l_sta_score);
					} else {
						printf("%s\t%f(%f,%f)\t\t%f\t\t%f\t\t%.2f\n", sizechar,
							info->l2h_bw + info->h2l_bw, info->l2h_bw, info->h2l_bw,
							info->l2h_bw_min + info->h2l_bw_min,
							info->l2h_bw_max + info->h2l_bw_max,
							info->l2h_variance + info->h2l_variance);
					}
				}
			} else {
				if (info->cmd.variance == NO_NEED_MODE) {
					printf("%s\t%f(%f,%f)\n", sizechar,
						info->l2h_bw + info->h2l_bw, info->l2h_bw, info->h2l_bw);
				} else {
					printf("%s\t%f(%f,%f)\t\t(%f,%f)\n", sizechar,
						info->l2h_bw + info->h2l_bw, info->l2h_bw, info->h2l_bw,
						info->l2h_variance, info->h2l_variance);
				}
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
		info->bw_set[i].size = info->size;
		info->bw_set[i].th_repeat_num = info->cmd.th_repeat_num;
		info->bw_set[i].th_id = i;
		if (info->dir == DMA_P2P_BOTHWAY) {
			if (i % 2) {
				info->bw_set[i].dir = DMA_P2P_H2L;
				info->bw_set[i].src_fd = info->fd1;
				info->bw_set[i].dst_fd = info->fd0;
				info->bw_set[i].src_addr = info->dev1_addr;
				info->bw_set[i].dst_addr = info->dev0_addr;
				info->bw_set[i].info = info;
			} else {
				info->bw_set[i].dir = DMA_P2P_L2H;
				info->bw_set[i].src_fd = info->fd0;
				info->bw_set[i].dst_fd = info->fd1;
				info->bw_set[i].src_addr = info->dev0_addr;
				info->bw_set[i].dst_addr = info->dev1_addr;
				info->bw_set[i].info = info;
			}
		} else {
			info->bw_set[i].dir = DMA_P2P_L2H;
			info->bw_set[i].src_fd = info->fd0;
			info->bw_set[i].dst_fd = info->fd1;
			info->bw_set[i].src_addr = info->dev0_addr;
			info->bw_set[i].dst_addr = info->dev1_addr;
			info->bw_set[i].info = info;
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
		info->bw_set[i].size = info->size;
		info->bw_set[i].th_repeat_num = info->cmd.th_repeat_num;
		info->bw_set[i].th_id = i;
		if (info->dir == DMA_P2P_BOTHWAY) {
			if (i % 2) {
				info->bw_set[i].dir = DMA_P2P_H2L;
				info->bw_set[i].src_fd = info->fd1;
				info->bw_set[i].dst_fd = info->fd0;
				info->bw_set[i].src_addr = info->dev1_addr;
				info->bw_set[i].dst_addr = info->dev0_addr;
				info->bw_set[i].info = info;
				/*
				cnCtxSetCurrent(info->bw_set[i].src_ctx);
				*/
				MLU_CHECK(create_queue(info->bw_set[i].src_fd, &info->bw_set[i].queue, 0));
			} else {
				info->bw_set[i].dir = DMA_P2P_L2H;
				info->bw_set[i].src_fd = info->fd0;
				info->bw_set[i].dst_fd = info->fd1;
				info->bw_set[i].src_addr = info->dev0_addr;
				info->bw_set[i].dst_addr = info->dev1_addr;
				info->bw_set[i].info = info;
				/*
				cnCtxSetCurrent(info->bw_set[i].src_ctx);
				*/
				MLU_CHECK(create_queue(info->bw_set[i].src_fd,
						&info->bw_set[i].queue, 0));
			}
		} else {
			info->bw_set[i].dir = DMA_P2P_L2H;
			info->bw_set[i].src_fd = info->fd0;
			info->bw_set[i].dst_fd = info->fd1;
			info->bw_set[i].src_addr = info->dev0_addr;
			info->bw_set[i].dst_addr = info->dev1_addr;
			info->bw_set[i].info = info;
			/*
			cnCtxSetCurrent(info->bw_set[i].src_ctx);
			*/
			MLU_CHECK(create_queue(info->bw_set[i].src_fd,
					&info->bw_set[i].queue, 0));
		}
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
		/*
		cnCtxSetCurrent(info->bw_set[i].src_ctx);
		*/
		MLU_CHECK(destroy_queue(info->bw_set[i].src_fd, info->bw_set[i].queue));
	}

	return 0;
}

int get_copy_bandwidth(struct dma_test_struct *info)
{
	int i;
	/*
	cnCtxSetCurrent(info->ctx0);
	*/
	MLU_CHECK(alloc_dev_memory(info->fd0, &info->dev0_addr, info->size));
	/*
	cnCtxSetCurrent(info->ctx1);
	*/
	MLU_CHECK(alloc_dev_memory(info->fd1, &info->dev1_addr, info->size));

	for (i = 0; i < info->cmd.repeat_num; i++) {
		info->repeat_id = i;
		if (info->cmd.dma_mode == SYNC_MODE) {
			if (get_sync_bandwidth(info)) {
				printf("get_sync_bandwidth FAILED\n");
				return -1;
			}
		} else {
			if (get_async_bandwidth(info)) {
				printf("get_async_bandwidth FAILED\n");
				return -1;
			}
		}
	}

	if (info->dev0_addr) {
		free_dev_memory(info->fd0, info->dev0_addr);
	}
	if (info->dev1_addr) {
		free_dev_memory(info->fd1, info->dev1_addr);
	}
	get_repeat_bandwidth_result(info);

	print_bw_result(info);

	return 0;
}

int run_copy_bandwidth_test(struct dma_test_struct *info)
{
	int size;
	int i, j;

	if (info->device_count) {
		info->size = DEFAULT_SIZE;
		for (i = 0; i < info->device_count; i++) {
			printf("    %d", i);
			for (j = 0; j < info->device_count; j++) {
				info->fd0 = fd[i];
				info->fd1 = fd[j];
				get_copy_bandwidth(info);
			}
			printf("\n");
		}
	} else {
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

	return 0;
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
	/*
	cnCtxSetCurrent(info->ctx0);
	*/
	MLU_CHECK(alloc_dev_memory(info->fd0, &info->dev0_addr, info->size));
	/*
	cnCtxSetCurrent(info->ctx1);
	*/
	MLU_CHECK(alloc_dev_memory(info->fd1, &info->dev1_addr, info->size));

	for (repeat_id = 0; repeat_id < info->cmd.repeat_num; repeat_id++) {
		if (info->cmd.dma_mode == SYNC_MODE) {
			/*
			cnCtxSetCurrent(info->ctx0);
			*/
			gettimeofday(&stime, NULL);
			if (info->fd0 != info->fd1) {
				for (i = 0; i < info->cmd.th_repeat_num; i++) {
					MLU_CHECK(p2p(info->fd0, info->fd1, info->dev1_addr,
						info->dev0_addr, info->size));
				}
			} else {
				for (i = 0; i < info->cmd.th_repeat_num; i++) {
					MLU_CHECK(d2d(info->fd0, info->dev1_addr, info->dev0_addr, info->size));
				}
			}
			gettimeofday(&etime, NULL);
			info->result[repeat_id].latency = (double)(etime.tv_sec * 1000000  + etime.tv_usec -
					stime.tv_sec * 1000000 - stime.tv_usec) / info->cmd.th_repeat_num;
		} else {
			if (info->cmd.latency_mode == HW_LATENCY_MODE) {
				/*
				cnCtxSetCurrent(info->ctx0);
				*/
				MLU_CHECK(create_queue(info->fd0, &queue, 0));
				MLU_CHECK(create_notifier(info->fd0, &notifier_start, 0));
				MLU_CHECK(create_notifier(info->fd0, &notifier_end, 0));
				MLU_CHECK(place_notifier(info->fd0, notifier_start, queue));

				if (info->fd0 != info->fd1) {
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(async_p2p(info->fd0, info->fd1,
							info->dev1_addr, info->dev0_addr, queue, info->size));
					}
				} else {
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(async_d2d(info->fd0, info->dev1_addr,
							info->dev0_addr, info->size, queue));
					}
				}

				MLU_CHECK(place_notifier(info->fd0, notifier_end, queue));
				MLU_CHECK(sync_queue(info->fd0, queue));
				MLU_CHECK(elapsed_swtime_notifier(info->fd0, &stime, notifier_start, notifier_end));
				MLU_CHECK(destroy_notifier(info->fd0, notifier_start));
				MLU_CHECK(destroy_notifier(info->fd0, notifier_end));
				MLU_CHECK(destroy_queue(info->fd0, queue));
				info->result[repeat_id].latency = (double)(stime.tv_sec * 1000000 + stime.tv_usec) / info->cmd.th_repeat_num;
			} else {
				/*
				cnCtxSetCurrent(info->ctx0);
				*/
				MLU_CHECK(create_queue(info->fd0, &queue, 0));
				gettimeofday(&stime, NULL);

				if (info->fd0 != info->fd1) {
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(async_p2p(info->fd0, info->fd1,
							info->dev1_addr, info->dev0_addr, queue, info->size));
					}
				} else {
					for (i = 0; i < info->cmd.th_repeat_num; i++) {
						MLU_CHECK(async_d2d(info->fd0, info->dev1_addr,
							info->dev0_addr, info->size, queue));
					}
				}
				if (info->cmd.latency_mode == SW_LATENCY_MODE)
					MLU_CHECK(sync_queue(info->fd0, queue));

				gettimeofday(&etime, NULL);
				MLU_CHECK(destroy_queue(info->fd0, queue));
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

	if (info->dev0_addr) {
		free_dev_memory(info->fd0, info->dev0_addr);
	}
	if (info->dev1_addr) {
		free_dev_memory(info->fd1, info->dev1_addr);
	}
	return 0;
}

int run_copy_latency_test(struct dma_test_struct *info)
{
	int i, j;

	info->size = 0x4;
	if (info->device_count) {
		for (i = 0; i < info->device_count; i++) {
			printf("    %d", i);
			for (j = 0; j < info->device_count; j++) {
				info->fd0 = fd[i];
				info->fd1 = fd[j];
				get_copy_latency(info);
				printf("\t%f", info->latency);
			}
			printf("\n");
		}
	} else {
		get_copy_latency(info);
		print_latency_result(info);
	}

	return 0;
}

void print_help(void)
{
	printf("Usage:  bandwidthTest [OPTION]...\n");
	printf("\n");
	printf("Options:\n");
	printf("--help\t\t\tDisplay this help menu\n");
	printf("--src_dev=[deviceno]\tdefault:all\n");
	printf("--dst_dev=[deviceno]\tdefault:all\n");
	printf("  all\t\t\tcompute cumulative bandwidth on all the devices\n");
	printf("  0,1,2,...,n\t\tSpecify any particular device to be used\n");
	printf("--mode=[MODE]\t\tdefault:quick\n");
	printf("  quick\t\t\tperforms a quick measurement\n");
	printf("  range\t\t\tmeasures a user-specified range of values\n");
	printf("  shmoo\t\t\tperforms an intense shmoo of a large range of values\n");
	printf("  small_shmoo\t\tperforms an intense shmoo of a small range of values\n");
	printf("--dir=[DIRECTION]\tdefault:oneway\n");
	printf("  oneway\t\tMeasure unidirectional transfers\n");
	printf("  bothway\t\tMeasure directional transfers\n");
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
	printf("Range mode options\n");
	printf("--start=[SIZE]\t\tStarting transfer size in bytes\n");
	printf("--end=[SIZE]\t\tEnding transfer size in bytes\n");
	printf("--increment=[SIZE]\tIncrement size in bytes\n");
	printf("\nExample:\n");
	printf("./p2p_sample --src_dev=0 --dst_dev=1 --mode=range --start=1024 --end=10240 --increment=1024 --dir=oneway\n");
	printf("./p2p_sample --src_dev=0 --dst_dev=1 --mode=shmoo --dir=bothway --thread=64 --dma_mode=sync\n");
	printf("./p2pBandwidthLatencyTest --src_dev=0 --dst_dev=1 --mode=shmoo --dir=oneway --thread=4 --dma_mode=sync --repeat_num=10 --th_repeat_num=100 --variance=repeat_mode --sta_range=10\n");
}

int analysis_cmd_line(const int argc, const char **argv, struct dma_test_struct *info)
{
	char *dir = NULL;
	char *mode = NULL;
	char *thread_num = NULL;
	char *dma_mode = NULL;
	char *variance = NULL;
	char *repeat_num = NULL;
	char *th_repeat_num = NULL;
	char *sta_range = NULL;
	char *latency_mode = NULL;

	if (getCmdLineArgumentString(argc, argv, "dir", &dir)) {
		if (strcmp(dir, "oneway") == 0) {
			info->cmd.dir = DMA_P2P_L2H;
			info->dir = DMA_P2P_L2H;
		} else if (strcmp(dir, "bothway") == 0) {
			info->cmd.dir = DMA_P2P_BOTHWAY;
			info->dir = DMA_P2P_BOTHWAY;
		} else {
			printf("Invalid dir mode - valid modes are oneway or bothway or all\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.dir = DMA_P2P_L2H;
		info->dir = DMA_P2P_L2H;
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
	if (info->dir == DMA_P2P_BOTHWAY) {
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

	return 0;
}

int main(int argc, char **argv)
{
	int i = 0;
	int j = 0;
	int ret = 0;
	int device_count;
	int src_dev;
	int dst_dev;
	int can_peer;

	cpu_num = sysconf(_SC_NPROCESSORS_CONF);
	if (checkCmdLineFlag(argc, (const char **)argv, "help")) {
		print_help();
		return 0;
	}
	pin_fd = open_mem_dev();
	if (pin_fd < 0) {
		printf("mlu init FAILED\n");
		return -1;
	}
	device_count = get_card_num(pin_fd);
	if (device_count < 2) {
		printf("Please run this case in multicard environment\n");
		return -1;
	}

	for (i = 0; i < device_count; i++) {
		fd[i] = open_cambricon_dev(i);
	}

	for (i = 0; i < device_count; i++) {
		for (j = 0; j < device_count; j++) {
			if (p2p_able(fd[i], fd[j])) {
				peer_able[i][j] = 0;
			} else {
				peer_able[i][j] = 1;
			}
		}
	}

	struct dma_test_struct info;

	memset(&info, 0, sizeof(struct dma_test_struct));
	if (analysis_cmd_line(argc, (const char **)argv, &info)) {
		printf("analysis_cmd_line failed\n");
		return -1;
	}
	src_dev = getCmdLineArgumentInt(argc, (const char **)argv, "src_dev");
	dst_dev = getCmdLineArgumentInt(argc, (const char **)argv, "dst_dev");
	if (src_dev < 0 || src_dev >= device_count ||
		dst_dev < 0 || dst_dev >= device_count || src_dev == dst_dev) {
		printf("PEER ABLE TOPO:\n");
		for (j = 0; j < device_count; j++) {
			for (i = 0; i < device_count; i++) {
				if (peer_able[i][j] == 1) {
					printf("1 ");
				} else {
					printf("0 ");
				}
			}
			printf("\n");
		}
		info.device_count = device_count;
		printf("  Peer to Peer Bandwidth(GB/s)\n");
		printf("  D/D");
		if (info.dir == DMA_P2P_BOTHWAY) {
			printf("\t0");
			for (i = 1; i < device_count; i++)
				printf("\t\t\t\t%d", i);
		} else {
			printf("\t0");
			for (i = 1; i < device_count; i++)
				printf("\t\t%d", i);
		}
		printf("\n");
		run_copy_bandwidth_test(&info);
		printf("\n");

		printf("  Peer to Peer Latency(us)\n");
		printf("  D/D");
		printf("\t0");
		for (i = 1; i < device_count; i++)
			printf("\t\t%d", i);
		printf("\n");
		run_copy_latency_test(&info);
		printf("\n");
	} else {
		if (!peer_able[src_dev][dst_dev])
			printf("Device:%d<-->Device:%d Can't Peer to Peer\n", src_dev, dst_dev);

		info.fd0 = fd[src_dev];
		info.fd1 = fd[dst_dev];
		printf("Peer to Peer Bandwidth, Device:%d<-->Device:%d\n", src_dev, dst_dev);
		print_result_title(&info);
		run_copy_bandwidth_test(&info);
		printf("\n");

		if (info.dir != DMA_P2P_BOTHWAY) {
			printf("Peer to Peer Latency, Device:%d<-->Device:%d\n", src_dev, dst_dev);
			printf("Latency(us)");
			run_copy_latency_test(&info);
			printf("\n");
		}
	}

	for (i = 0; i < device_count; i++)
		close_cambricon_dev(fd[i]);
	close_mem_dev(pin_fd);
	return 0;
}
