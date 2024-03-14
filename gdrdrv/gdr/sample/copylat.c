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
int num_write_iters = 1;
int num_read_iters  = 1;
size_t _size = 128 * 1024;
int do_cncopy;
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

void init_host_buf(uint32_t *h_buf, size_t size)
{
	uint32_t base_value = 0x3f4c5e6a;
	uint32_t w;

	for (w = 0; w < size / sizeof(uint32_t); w++) {
		h_buf[w] = base_value ^ (1 << (w % 32));
	}
}

int run_test(CNaddr dev_addr, size_t size)
{
	uint32_t *init_buf = NULL;
	void *map_d_ptr = NULL;
	int ret = 0;
	struct gdr_mh_s mh;
	struct gdr *g;
	double lat_us = 0.0;
	struct timespec beg, end;
	size_t copy_size = 1;
	int iter;

	cnMallocHost((void **)&init_buf, size);
	init_host_buf(init_buf, size);

	if (do_cncopy) {
		printf("cnMemcpyHtoD iter for each size %d\n", num_write_iters);
		printf("Test \t\t\t Size(B) \t Avg.Time(us)\n");
		copy_size = 1;
		while (copy_size <= size) {
			clock_gettime(CLOCK_MONOTONIC, &beg);
			for (iter = 0; iter < num_write_iters; ++iter) {
				cnMemcpyHtoD(dev_addr, init_buf, copy_size);
			}
			clock_gettime(CLOCK_MONOTONIC, &end);
			lat_us = ((end.tv_nsec - beg.tv_nsec) / 1000.0 + (end.tv_sec - beg.tv_sec) * 1000000.0)
			/ (double)iter;
			printf("cnMemcpyHtoD H2D \t %8zu \t %11.4f\n", copy_size, lat_us);
			copy_size <<= 1;
		}

		printf("cnMemcpyDtoH iter for each size %d\n", num_read_iters);
		printf("Test \t\t\t Size(B) \t Avg.Time(us)\n");
		copy_size = 1;
		while (copy_size <= size) {
			clock_gettime(CLOCK_MONOTONIC, &beg);
			for (iter = 0; iter < num_read_iters; ++iter) {
				cnMemcpyDtoH(init_buf, dev_addr, copy_size);
			}
			clock_gettime(CLOCK_MONOTONIC, &end);
			lat_us = ((end.tv_nsec - beg.tv_nsec) / 1000.0 + (end.tv_sec - beg.tv_sec) * 1000000.0)
			/ (double)iter;
			printf("cnMemcpyDtoH D2H \t %8zu \t %11.4f\n", copy_size, lat_us);
			copy_size <<= 1;
		}
	}

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
	// copy from GPU benchmark
	printf("gdr_copy_to_mapping iter for each size %d\n", num_write_iters);
	printf("Test \t\t\t\t Size(B) \t Avg.Time(us)\n");
	copy_size = 1;
	while (copy_size <= size) {
		clock_gettime(CLOCK_MONOTONIC, &beg);

		for (iter = 0; iter < num_write_iters; ++iter) {
			gdr_copy_to_mapping(mh, map_d_ptr, init_buf, copy_size);
		}

		clock_gettime(CLOCK_MONOTONIC, &end);
		lat_us = ((end.tv_nsec - beg.tv_nsec) / 1000.0 + (end.tv_sec - beg.tv_sec) * 1000000.0)
		/ (double)iter;
		printf("gdr_copy_to_mapping H2D \t %8zu \t %11.4f\n", copy_size, lat_us);
		copy_size <<= 1;
	}
	//sync();

	//compare_buf(init_buf, map_d_ptr + copy_offset / 4, size);
	// copy from GPU benchmark
	printf("gdr_copy_from_mapping iter for each size %d\n", num_read_iters);
	printf("Test \t\t\t\t Size(B) \t Avg.Time(us)\n");
	copy_size = 1;
	while (copy_size <= size) {
		clock_gettime(CLOCK_MONOTONIC, &beg);

		for (iter = 0; iter < num_read_iters; ++iter) {
			gdr_copy_from_mapping(mh, init_buf, map_d_ptr, copy_size);
		}
		clock_gettime(CLOCK_MONOTONIC, &end);
		lat_us = ((end.tv_nsec - beg.tv_nsec) / 1000.0 + (end.tv_sec - beg.tv_sec) * 1000000.0)
		/ (double)iter;
		printf("gdr_copy_from_mapping D2H \t %8zu \t %11.4f\n", copy_size, lat_us);
		copy_size <<= 1;
	}
err:
	gdr_unmap(g, mh, map_d_ptr, size);

	gdr_unpin_buffer(g, mh);
	gdr_close(g);
	cnFreeHost(init_buf);
	return ret;
}

void print_usage(const char *path)
{
	printf("help: %s [-h][-s size][-c do_cncopy][-d dev_id][w write_num][r read_num]", path);
	printf("options\n");
	printf("-h          print this help test\n");
	printf("-s <size>   buffer allocation size (default _size %lu)\n", _size);
	printf("-c <size>   cnMemcpy (default do_cncopy %d)\n", do_cncopy);
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
			do_cncopy = strtol(optarg, NULL, 0);
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
		printf("copylat test PASSED\n");
	} else {
		printf("copylat test FAILED\n");
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
