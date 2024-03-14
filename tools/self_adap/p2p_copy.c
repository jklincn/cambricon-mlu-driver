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

#define DEFAULT_SIZE 0x2000000
#define ALIGNED_SIZE 0x200
#define DISABLE_DEFAULT_TOPO_P2P  (1) /*If enable it will test on dev0/1 when user param is beyond device_count*/
#define JUST_WARN_WHEN_NOT_MULTI_CARD  (1) /*It will just print log but not return error when device_count not support P2P*/

int pin_fd;
int result = 0;

enum testMode { CHECK_MODE, DETAIL_MODE, NO_CHECK_MODE, LAST_CHECK_MODE };
enum dmaMode { SYNC_MODE, ASYNC_MODE, ALL_MODE };
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
	enum testMode mode;
	enum dmaMode dma_mode;
	unsigned int thread_num;
	unsigned int repeat_num;
};

struct dma_bw_struct {
	int src_fd;
	int dst_fd;
	uint64_t dev_addr_0;
	uint64_t dev_addr_1;
	void *host_addr_0;
	void *host_addr_1;
	unsigned long size;
	void *queue;
	void *info;
	int result;
};

struct dma_test_struct {
	int dev0;
	int dev1;
	int fd0;
	int fd1;
	int pin_fd;
	uint64_t dev_addr_0;
	uint64_t dev_addr_1;
	void *host_addr_0;
	void *host_addr_1;
	unsigned long size;
	struct cmd_line_struct cmd;
	pthread_t th;
	int thread_id;
	int repeat_id;
};

static void print_help(void)
{
	printf("Usage:  p2p_copy Test [OPTION]...\n");
	printf("\n");
	printf("Options:\n");
	printf("--help\t\t\tDisplay this help menu\n");
	printf("--src_dev=[deviceno]\tdefault:all\n");
	printf("--dst_dev=[deviceno]\tdefault:all\n");
	printf("  all\t\t\tcompute cumulative bandwidth on all the devices\n");
	printf("  0,1,2,...,n\t\tSpecify any particular device to be used\n");
	printf("--thread=[THREAD_NUM]\tdefault:1\n");
	printf("--repeat=[REPEAT_NUM]\tdefault:1\n");
	printf("--dma_mode=[DMAMODE]\tdefault:all\n");
	printf("  sync\t\t\tuse sync dma to copy\n");
	printf("  async\t\t\tuse async dma to copy\n");
	printf("  all\t\t\tuse sync and async dma to copy\n");
	printf("--mode=[MODE]\t\tdefault:check\n");
	printf("  check\t\t\toutput result only\n");
	printf("  detail\t\toutput detail\n");
	printf("  checknon\t\tdo not check\n");
	printf("  checkatlast\t\tcheck at the last loop only\n");
	printf("\nExample:\n");
	printf("./p2p_copy --thread=10 --repeat=10 --mode=detail\n");
	printf("./p2p_copy --thread=10 --repeat=10 --dma_mode=sync\n");
	printf("./p2p_copy --src_dev=0 --dst_dev=1 --thread=10 --repeat=10\n");
}

void hexdump(uint8_t *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (i == len - 1){
			printf("%02x", buf[i]);
		} else if (!((i + 1) % 64)) {
			printf("%02x\n", buf[i]);
		} else {
			printf("%02x ", buf[i]);
		}
	}
}

int detail_output(struct dma_test_struct *info, struct dma_bw_struct *bw_set, char *out_str)
{
	printf("host_addr A:%#lx  host_addr B:%#lx  device_addr C:%#lx  device_addr D:%#lx\tsize:%#lx\n",
			(uint64_t)info->host_addr_0,
			(uint64_t)info->host_addr_1,
			info->dev_addr_0,
			info->dev_addr_1,
			info->size);
	printf("A1=A+offsetA:%#lx  B1=B+offsetB:%#lx  C1=C+offsetC:%#lx  D1=D+offsetD:%#lx\tlen:%#lx\n",
			(uint64_t)bw_set->host_addr_0,
			(uint64_t)bw_set->host_addr_1,
			bw_set->dev_addr_0,
			bw_set->dev_addr_1,
			bw_set->size);
	if (bw_set->result) {
		printf("[A1, A1+len):\n");
		hexdump((uint8_t *)bw_set->host_addr_0, bw_set->size);
		printf("\n");
		printf("[B1, B1+len):\n");
		hexdump((uint8_t *)bw_set->host_addr_1, bw_set->size);
		printf("\n");
		printf("%sFAILED\n", out_str);
		return -1;
	} else {
		printf("Memory: [A1, A1+len)=[B1, B1+len)\n");
		printf("%sPASS\n", out_str);
	}
	printf("--------------------\n");

	return 0;
}

int alloc_addr_memory(struct dma_test_struct *info) {
	info->size = DEFAULT_SIZE + rand() % DEFAULT_SIZE;
	info->host_addr_0 = pinned_mem_alloc(info->pin_fd, info->size);
	info->host_addr_1 = pinned_mem_alloc(info->pin_fd, info->size);
	if ((!info->host_addr_0) || (!info->host_addr_1)) {
		printf("malloc host_addr FAILED\n");
		return -1;
	}
	MLU_CHECK(alloc_dev_memory(info->fd0, &info->dev_addr_0, info->size));
	MLU_CHECK(alloc_dev_memory(info->fd1, &info->dev_addr_1, info->size));

	return 0;
}

void free_addr_memory(struct dma_test_struct *info) {
	if (info->host_addr_0) {
		pinned_mem_free(info->pin_fd, info->host_addr_0);
		info->host_addr_0 = NULL;
	}
	if (info->host_addr_1) {
		pinned_mem_free(info->pin_fd, info->host_addr_1);
		info->host_addr_1 = NULL;
	}
	if (info->dev_addr_0) {
		free_dev_memory(info->fd0, info->dev_addr_0);
		info->dev_addr_0 = 0;
	}
	if (info->dev_addr_1) {
		free_dev_memory(info->fd1, info->dev_addr_1);
		info->dev_addr_1 = 0;
	}
}

int prepare_p2p_copy(struct dma_test_struct *info, struct dma_bw_struct *bw_set)
{
	unsigned long i;
	unsigned long max_offset = 0;
	unsigned long offset[4];

	for (i = 0; i < 4; i++) {
		offset[i] = rand() % ALIGNED_SIZE;
		max_offset = max_offset < offset[i]? offset[i]: max_offset;
	}
	bw_set->size = rand() % (info->size - max_offset - 1) + 1;
	bw_set->dev_addr_0 = info->dev_addr_0 + offset[0];
	bw_set->dev_addr_1 = info->dev_addr_1 + offset[1];
	bw_set->host_addr_0 = info->host_addr_0 + offset[2];
	bw_set->host_addr_1 = info->host_addr_1 + offset[3];

	memset(bw_set->host_addr_0, rand(), bw_set->size);
	memset(bw_set->host_addr_1, 0, bw_set->size);
	for (i = 0; i < 3; i++) {
		memset((uint8_t *)bw_set->host_addr_0 + i * (bw_set->size - 1) / 2, rand(), 1);
	}

	return 0;
}

void *sync_dma_thread(void *arg)
{
	int i;
	struct dma_bw_struct *bw_set = (struct dma_bw_struct *)arg;
	struct dma_test_struct *info = (struct dma_test_struct *)bw_set->info;

	for (i = 0; i < info->cmd.repeat_num; i++) {
		info->repeat_id = i + 1;
		bw_set->result = 0;
		if (prepare_p2p_copy(info, bw_set)) {
			return NULL;
		}
		MLU_CHECK(h2d(info->fd0, bw_set->dev_addr_0, bw_set->host_addr_0, bw_set->size));
		MLU_CHECK(p2p(bw_set->src_fd, bw_set->dst_fd,
					bw_set->dev_addr_1, bw_set->dev_addr_0, bw_set->size));
		MLU_CHECK(d2h(info->fd1, bw_set->dev_addr_1, bw_set->host_addr_1, bw_set->size));
		if (info->cmd.mode != NO_CHECK_MODE &&
				(info->cmd.mode != LAST_CHECK_MODE ||
				 info->repeat_id == info->cmd.repeat_num) &&
				memcmp(bw_set->host_addr_0, bw_set->host_addr_1, bw_set->size)) {
			bw_set->result = 1;
			return NULL;
		}
	}
	return NULL;
}

void *async_dma_thread(void *arg)
{
	int i;
	struct dma_bw_struct *bw_set = (struct dma_bw_struct *)arg;
	struct dma_test_struct *info = (struct dma_test_struct *)bw_set->info;

	MLU_CHECK(create_queue(info->fd0, &(bw_set->queue), 0));
	for (i = 0; i < info->cmd.repeat_num; i++) {
		info->repeat_id = i + 1;
		bw_set->result = 0;
		if (prepare_p2p_copy(info, bw_set)) {
			MLU_CHECK(destroy_queue(info->fd0, bw_set->queue));
			return NULL;
		}
		MLU_CHECK(h2d(info->fd0, bw_set->dev_addr_0, bw_set->host_addr_0, bw_set->size));
		MLU_CHECK(async_p2p(bw_set->src_fd, bw_set->dst_fd,
					bw_set->dev_addr_1, bw_set->dev_addr_0, bw_set->queue, bw_set->size));
		MLU_CHECK(sync_queue(info->fd0, bw_set->queue));
		MLU_CHECK(d2h(info->fd1, bw_set->dev_addr_1, bw_set->host_addr_1, bw_set->size));
		if (info->cmd.mode != NO_CHECK_MODE &&
				(info->cmd.mode != LAST_CHECK_MODE ||
				 info->repeat_id == info->cmd.repeat_num) &&
				memcmp(bw_set->host_addr_0, bw_set->host_addr_1, bw_set->size)) {
			bw_set->result = 1;
			MLU_CHECK(destroy_queue(info->fd0, bw_set->queue));
			return NULL;
		}
	}

	MLU_CHECK(destroy_queue(info->fd0, bw_set->queue));
	return NULL;
}

int run_p2p_copy_test(struct dma_test_struct *info)
{
	int i;
	char out_str[128];
	struct dma_test_struct *th_info;
	struct dma_bw_struct *bw_set;

	th_info = (struct dma_test_struct *)malloc(info->cmd.thread_num * sizeof(struct dma_test_struct));
	bw_set = (struct dma_bw_struct *)malloc(info->cmd.thread_num * sizeof(struct dma_bw_struct));

	for (i = 0; i < info->cmd.thread_num; i++) {
		th_info[i] = *info;
		th_info[i].thread_id = i + 1;
		bw_set[i].info = &th_info[i];
		bw_set[i].src_fd = th_info[i].fd0;
		bw_set[i].dst_fd = th_info[i].fd1;
		if (alloc_addr_memory(&th_info[i])) {
			printf("malloc host and dev address FAILED\n");
			return -1;
		}
	}
	/* run async p2p copy */
	if (info->cmd.dma_mode == ALL_MODE || info->cmd.dma_mode == ASYNC_MODE) {
		for (i = 0; i < info->cmd.thread_num; i++) {
			pthread_create(&(th_info[i].th), NULL, async_dma_thread, &bw_set[i]);
		}
		if (info->cmd.mode == DETAIL_MODE) {
			printf("--------------------\n");
		}
		for (i = 0; i < info->cmd.thread_num; i++) {
			pthread_join(th_info[i].th, NULL);
			sprintf(out_str, "repeat:%d  thread:%d async p2p copy ", th_info[i].repeat_id, th_info[i].thread_id);
			if ((info->cmd.mode == DETAIL_MODE &&
						detail_output(&th_info[i], &bw_set[i], out_str)) ||
					bw_set[i].result) {
				result = 1;
			}
		}
	}
	/* run sync p2p copy */
	if (info->cmd.dma_mode == ALL_MODE || info->cmd.dma_mode == SYNC_MODE) {
		for (i = 0; i < info->cmd.thread_num; i++) {
			pthread_create(&(th_info[i].th), NULL, sync_dma_thread, &bw_set[i]);
		}
		if (info->cmd.mode == DETAIL_MODE) {
			printf("--------------------\n");
		}
		for (i = 0; i < info->cmd.thread_num; i++) {
			pthread_join(th_info[i].th, NULL);
			sprintf(out_str, "repeat:%d  thread:%d sync p2p copy ", th_info[i].repeat_id, th_info[i].thread_id);
			if ((info->cmd.mode == DETAIL_MODE &&
						detail_output(&th_info[i], &bw_set[i], out_str)) ||
					bw_set[i].result) {
				result = 1;
			}
		}
	}
	/*---------------------*/
	for (i = 0; i < info->cmd.thread_num; i++) {
		free_addr_memory(&th_info[i]);
	}
	free(th_info);
	free(bw_set);
	return result;
}
int analysis_cmd_line(const int argc, const char **argv, struct dma_test_struct *info)
{
	char *thread_num = NULL;
	char *repeat_num = NULL;
	char *mode = NULL;
	char *dma_mode = NULL;

	if (getCmdLineArgumentString(argc, (const char **)argv, "thread", &thread_num)) {
		info->cmd.thread_num = atoi(thread_num);
		if (info->cmd.thread_num <= 0) {
			printf("Invalid thread\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.thread_num = 1;
	}

	if (getCmdLineArgumentString(argc, (const char **)argv, "repeat", &repeat_num)) {
		info->cmd.repeat_num = atoi(repeat_num);
		if (info->cmd.repeat_num <= 0) {
			printf("Invalid repeat\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.repeat_num = 1;
	}

	if (getCmdLineArgumentString(argc, argv, "dma_mode", &dma_mode)) {
		if (strcmp(dma_mode, "all") == 0) {
			info->cmd.dma_mode = ALL_MODE;
		} else if (strcmp(dma_mode, "async") == 0) {
			info->cmd.dma_mode = ASYNC_MODE;
		} else if (strcmp(dma_mode, "sync") == 0) {
			info->cmd.dma_mode = SYNC_MODE;
		} else {
			printf("Invalid dma_mode - valid modes are all, sync, async\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.dma_mode = ALL_MODE;
	}

	if (getCmdLineArgumentString(argc, argv, "mode", &mode)) {
		if (strcmp(mode, "check") == 0) {
			info->cmd.mode = CHECK_MODE;
		} else if (strcmp(mode, "detail") == 0) {
			info->cmd.mode = DETAIL_MODE;
		} else if (strcmp(mode, "checknon") == 0) {
			info->cmd.mode = NO_CHECK_MODE;
		} else if (strcmp(mode, "checkatlast") == 0) {
			info->cmd.mode = LAST_CHECK_MODE;
		} else {
			printf("Invalid mode - valid modes are check, detail, checknon. checkatlast\n");
			printf("See --help for more information\n");
			return -1;
		}
	} else {
		info->cmd.mode = CHECK_MODE;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int i = 0;
	int j = 0;
	int ret = 0;
	int device_count = 0;
	int can_peer;

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
	if (device_count < 2) {
		printf("Please run this case in multicard environment\n");
#if JUST_WARN_WHEN_NOT_MULTI_CARD
		return 0;
#else
		return -1;
#endif
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
	info.pin_fd = pin_fd;
	if (analysis_cmd_line(argc, (const char **)argv, &info)) {
		printf("analysis_cmd_line failed\n");
		return -1;
	}

	info.dev0 = getCmdLineArgumentInt(argc, (const char **)argv, "src_dev");
	info.dev1 = getCmdLineArgumentInt(argc, (const char **)argv, "dst_dev");
	if (info.dev0 < 0 || info.dev0 >= device_count ||
		info.dev1 < 0 || info.dev1 >= device_count || info.dev0 == info.dev1) {
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
#if DISABLE_DEFAULT_TOPO_P2P
		printf("Please check param: device_count=%d src_dev=%d dst_dev=%d\n",
				device_count, info.dev0, info.dev1);
		return -1;
#endif
		for (i = 0; i < device_count; i++) {
			info.dev0 = i;
			info.fd0 = fd[info.dev0];
			for (j = 0; j < device_count; j++) {
				if (i == j) {
					continue;
				}
				info.dev1 = j;
				info.fd1 = fd[info.dev1];
				result = 0;
				if (!peer_able[i][j] || run_p2p_copy_test(&info)) {
					if (info.cmd.mode != NO_CHECK_MODE) {
						printf("================================\n");
						printf("device[%d->%d] p2p copy ERROR\n", info.dev0, info.dev1);
					}
				} else {
					if (info.cmd.mode != NO_CHECK_MODE) {
						printf("================================\n");
						printf("device[%d->%d] p2p copy SUCCESS\n", info.dev0, info.dev1);
					}
				}
			}
		}
	} else {
		info.fd0 = fd[info.dev0];
		info.fd1 = fd[info.dev1];
		if (!peer_able[info.dev0][info.dev1]) {
			result = 1;
		} else {
			result = run_p2p_copy_test(&info);
		}
		if (result) {
			if (info.cmd.mode != NO_CHECK_MODE) {
				printf("================================\n");
				printf("device[%d->%d] p2p copy ERROR\n", info.dev0, info.dev1);
			}
		} else {
			if (info.cmd.mode != NO_CHECK_MODE) {
				printf("================================\n");
				printf("device[%d->%d] p2p copy SUCCESS\n", info.dev0, info.dev1);
			}
		}
	}
	if (info.cmd.mode != NO_CHECK_MODE) {
		printf("================================\n");
	}

final:
	for (i = 0; i < device_count; i++)
		close_cambricon_dev(fd[i]);
	close_mem_dev(pin_fd);
	return 0;
}
