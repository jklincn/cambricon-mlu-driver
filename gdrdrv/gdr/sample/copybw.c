#include <stdlib.h>
#include <getopt.h>
#include <memory.h>
#include <stdio.h>
#include <math.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include "cn_api.h"
#include "gdrapi.h"


CNdev device;
CNcontext ctx;
CNqueue stream;
int num_write_iters = 1;
int num_read_iters  = 1;
size_t _size = 128 * 1024;
size_t copy_size = 10000;
size_t copy_offset;
int dev_id;

struct gdr *gdr_open_safe()
{
	struct gdr *g = gdr_open();

	if (!g) {
		fprintf(stderr, "gdr open error\n");
		exit(EXIT_FAILURE);
	}
	return g;
}

int compare_buf(uint32_t *ref_buf, uint32_t *buf, size_t size)
{
	int diff = 0;

	if (size % 4 != 0U) {
		printf("warning: buffer size %zu is not dword aligned, ignoring trailing bytes\n", size);
		size -= (size % 4);
	}
	unsigned int ndwords = size / sizeof(uint32_t);

	for (unsigned int w = 0; w < ndwords; ++w) {
		if (ref_buf[w] != buf[w]) {
			if (!diff) {
				printf("%10.10s %8.8s %8.8s\n", "word", "content", "expected");
			}
			if (diff < 10) {
				printf("%10d %08x %08x\n", w, buf[w], ref_buf[w]);
			}
			++diff;
		}
	}
	if (diff) {
		printf("check error: %d different dwords out of %d\n", diff, ndwords);
	}
	return diff;
}

int run_test(CNaddr dev_addr, size_t size)
{
	uint32_t *init_buf = NULL;
	void *map_d_ptr = NULL;
	int i = 0;
	int ret = 0;
	struct gdr_mh_s mh;
	struct gdr *g;
	double byte_count;
	double dt_ms;
	double bps;
	double write_bw;
	double read_bw;
	struct timespec beg, end;

	cnMallocHost((void **)&init_buf, size);
	memset(init_buf, 0xa5, size);
	cnMemcpyHtoD(dev_addr, init_buf, size);

	g = gdr_open_safe();
	// wave out the test if GPUDirectRDMA is not enabled
	ret = gdr_pin_buffer(g, dev_addr, size, 0, 0, &mh);
	if (ret) {
		printf("remap buffer failed\n");
		goto err;
	}
	ret = gdr_map(g, mh, &map_d_ptr, size);
	if (ret) {
		printf("mmap usr buffer failed\n");
		goto err;
	}
	ret = compare_buf(init_buf, map_d_ptr + copy_offset / 4, copy_size);
	if (ret) {
		goto err0;
	}
	memset(init_buf, 0xb7, size);

	// copy from GPU benchmark
	clock_gettime(CLOCK_MONOTONIC, &beg);

	for (int iter = 0; iter < num_write_iters; ++iter) {
		gdr_copy_to_mapping(mh, map_d_ptr + copy_offset / 4, init_buf, copy_size);
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	byte_count = (double) copy_size * num_write_iters;
	dt_ms = (end.tv_nsec-beg.tv_nsec)/1000000.0 + (end.tv_sec-beg.tv_sec)*1000.0;
	bps = byte_count / dt_ms * 1e3;
	write_bw = bps / 1024.0 / 1024.0;
	printf("write BW: %f MB/s\n", write_bw);

	cnMemcpyDtoH(init_buf, dev_addr, copy_size);

	ret = compare_buf(map_d_ptr + copy_offset / 4, init_buf + copy_offset / 4, copy_size);
	if (ret) {
		goto err0;
	}
	//compare_buf(init_buf, map_d_ptr + copy_offset / 4, size);
	// copy from GPU benchmark
	clock_gettime(CLOCK_MONOTONIC, &beg);
	for (int iter = 0; iter < num_read_iters; ++iter) {
		gdr_copy_from_mapping(mh, init_buf, map_d_ptr + copy_offset/4, size);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	byte_count = (double) size * num_read_iters;
	dt_ms = (end.tv_nsec-beg.tv_nsec)/1000000.0 + (end.tv_sec-beg.tv_sec)*1000.0;
	bps = byte_count / dt_ms * 1e3;
	read_bw = bps / 1024.0 / 1024.0;
	printf("read BW: %f MB/s\n", read_bw);

err0:
	gdr_unmap(g, mh, map_d_ptr, size);

	gdr_unpin_buffer(g, mh);
	gdr_close(g);
err:
	cnFreeHost(init_buf);
	return ret;
}

void print_usage(const char *path)
{
	printf("help: %s [-h][-s size][-c size][-o offset][-d dev_id][w write_num][r read_num]", path);
	printf("options\n");
	printf("-h          print this help test\n");
	printf("-s <size>   buffer allocation size (default _size %lu)\n", _size);
	printf("-c <size>   copy size (default copy_size %lu)\n", copy_size);
	printf("-o <offset> copy offset (default offset %lu)\n", copy_offset);
	printf("-d <dev_id> GPU ID (default id %d)\n", dev_id);
	printf("-w <witers> number of write iterations (default iters %d)\n", num_write_iters);
	printf("-r <riters> number of read iterations (default iters %d)\n", num_read_iters);
}

int main(int argc, char *argv[])
{
	CNaddr cn_addr;
	CNaddr cn_addr_temp;
	int ret = 0;

	while (1) {
		int c;

		c = getopt(argc, argv, "s:d:o:c:w:r:a:h");
		if (c == -1)
			break;

		switch (c) {
		case 's':
			_size = strtol(optarg, NULL, 0);
			break;
		case 'c':
			copy_size = strtol(optarg, NULL, 0);
			break;
		case 'o':
			copy_offset = strtol(optarg, NULL, 0);
			break;
		case 'd':
			dev_id = strtol(optarg, NULL, 0);
			break;
		case 'w':
			num_write_iters = strtol(optarg, NULL, 0);
			break;
		case 'r':
			num_read_iters = strtol(optarg, NULL, 0);
			break;
		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			fprintf(stderr, "ERROR: invalid option\n");
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (!copy_size)
		copy_size = _size;

	if (copy_offset % sizeof(uint32_t) != 0) {
		fprintf(stderr, "ERROR: offset must be multiple of 4 bytes\n");
		exit(EXIT_FAILURE);
	}

	if (copy_offset + copy_size > _size) {
		fprintf(stderr, "ERROR: offset + copy size run past the end of the buffer\n");
		exit(EXIT_FAILURE);
	}

	/* open device cn */
	if (cnInit(0)) {
		printf("cn Init FAILED(can not find the device)\n");
		return 0;
	}
	if (cnDeviceGet(&device, dev_id)) {
		printf("Device get FAILED\n");
		return 0;
	}

	if (cnCtxCreate(&ctx, 0, device)) {
		printf("Device open FAILED\n");
		return 0;
	}

	//device dest
	if (cnMalloc(&cn_addr, _size)) {
		printf("cnMalloc FAILED\n");
		goto failed;
	}

	ret = run_test(cn_addr, _size);
	if (!ret) {
		printf("copybw test ok\n");
	} else {
		printf("copybw test failed\n");
	}
	cnFree(cn_addr);
failed:
	if (cnCtxDestroy(ctx)) {
		printf("Exit FAILED\n");
		exit(0);
	}
	return 0;
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 *  indent-tabs-mode: nil
 * End:
 */
