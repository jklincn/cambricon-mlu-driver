#include "common.h"

int open_mem_dev(void)
{
	int pin_fd;
	char buf[100];

	sprintf(buf, "/dev/cambricon_ctl");
	pin_fd = open(buf, O_RDWR | O_TRUNC | O_SYNC, 0666);
	if (pin_fd < 0) {
		ERR_PRT("open %s error", buf);
		return 0;
	}

	return pin_fd;
}

void close_mem_dev(int pin_fd)
{
	if (pin_fd)
		close(pin_fd);
}

int get_card_num(int pin_fd)
{
	int ret;
	struct cndev_cardnum param;

	ret = ioctl(pin_fd, MONITOR_CNDEV_CARDNUM, &param);
	if (ret) {
		ERR_PRT("MONITOR CNDEV CARDNUM error");
		return 0;
	}

	return param.card_count;
}

int open_cambricon_cap(int id, int *cap_fd)
{
	int fd;
	int mim_id;
	char cap_name[255];
	struct stat st;

	for (mim_id = 0; mim_id < CN_DEV_MAX_INSTANCE_COUNT; mim_id++) {
		snprintf(cap_name, 255, "%s%d_mi%d",
				"/dev/cambricon-caps/cap_dev", id, mim_id);
		if (!stat(cap_name, &st)) {
			fd = open(cap_name, O_RDWR | O_CLOEXEC, 0666);
			if (fd < 0) {
				ERR_PRT("open %s error", cap_name);
				return -1;
			}
			cap_fd[mim_id] = fd;
		}
	}
	return 0;
}

void close_cambricon_cap(int *cap_fd)
{
	int mim_id;

	for (mim_id = 0; mim_id < CN_DEV_MAX_INSTANCE_COUNT; mim_id++) {
		if (cap_fd[mim_id])
			close(cap_fd[mim_id]);
	}
}

int open_cambricon_dev(int id)
{
	int fd;
	char buf[80];

	if (id < 0 || id >= MAX_PHYS_CARD) {
		ERR_PRT("input id:%d error", id);
		return -1;
	}

	sprintf(buf, "/dev/cambricon_dev%d", id);
	fd = open(buf, O_RDWR | O_CREAT
			| O_TRUNC | O_SYNC, 0666);
	if (fd < 0) {
		ERR_PRT("open %s error", buf);
		return -1;
	}

	return fd;
}

void close_cambricon_dev(int fd)
{
	close(fd);
}

int get_card_bdf(int fd, char *bdf)
{
	int ret;
	__u32 attr_v2[CN_DEVICE_ATTRIBUTE_MAX];
	struct cn_device_attr attr_c20;
	int domain_id, bus_id, device_id, slot_id, func_id;

	attr_c20.version = 1;
	attr_c20.cnt = CN_DEVICE_ATTRIBUTE_MAX;
	attr_c20.data = attr_v2;
	ret = ioctl(fd, CAMB_GET_DEVICE_ATTR, &attr_c20);
	if (ret) {
		ERR_PRT("CAMB_GET_DEVICE_PRIVATE_ATTR error");
		return -1;
	} else {
		domain_id = attr_v2[CN_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID];
		bus_id = attr_v2[CN_DEVICE_ATTRIBUTE_PCI_BUS_ID];
		device_id = attr_v2[CN_DEVICE_ATTRIBUTE_PCI_DEVICE_ID];
		slot_id = device_id >> 3;
		func_id = device_id & 0x7;
		sprintf(bdf, "%04x:%02x:%02x.%x",
				domain_id, bus_id, slot_id, func_id);
	}

	return 0;
}

int alloc_dev_memory(int fd,uint64_t *addr,int size)
{
	int ret;
	struct mem_alloc_compat_s mm_alloc;
	int count = 0;

	memset(&mm_alloc, 0, sizeof(mm_alloc));
	mm_alloc.size = size;
	mm_alloc.align = 0x10000;
	mm_alloc.type = 2;
	mm_alloc.affinity = -2;

retry:
	ret = ioctl(fd, M_MEM_ALLOC, &mm_alloc);
	if (ret != 0) {
		if (count++ < 10) {
			sleep(1);
			goto retry;
		}
		ERR_PRT("memory alloc error ret:%d", ret);
		return ret;
	}
	*addr = mm_alloc.ret_addr;
	return ret;
}

void free_dev_memory(int fd, __u64 addr)
{
	int ret;
	struct mem_free_param_s mm_free;

	memset(&mm_free, 0, sizeof(mm_free));
	mm_free.ret_addr = addr;

	ret = ioctl(fd, M_MEM_FREE, &mm_free);
	if (ret < 0) {
		ERR_PRT("memory free error ret:%d", ret);
		exit(0);
	}
}

void *pinned_mem_alloc(int pin_fd, int size)
{
	int ret;
	struct pinned_mem_param pm_param;

	pm_param.size = size;
	ret = ioctl(pin_fd, M_PINNED_MEM_ALLOC, &pm_param);
	if (ret && (pm_param.uaddr == 0)) {
		ERR_PRT("pinned memory alloc fail");
		return NULL;
	}

	return (void *)pm_param.uaddr;
}

void pinned_mem_free(int pin_fd, char *va)
{
	int ret;
	unsigned long uaddr = (unsigned long)va;

	ret = ioctl(pin_fd, M_PINNED_MEM_FREE, &uaddr);
	if (ret) {
		ERR_PRT("pinned memory free pages error %d\n", ret);
		exit(0);
	}
}

int p2p_able(int fd, int peer_fd)
{
	int ret = 0;
	struct p2p_able_s p2p_able;

	p2p_able.peer_fd = peer_fd;
	ret = ioctl(fd, M_PEER_ABLE, &p2p_able);
	if (ret) {
		ERR_PRT("fd%d and peer_fd%d p2p not able", fd, peer_fd);
		return ret;
	}

	return ret;
}


int mlu_memset_D8_async(int fd, __u64 addr, __u8 val, size_t size, void *hqueue)
{
	int ret;
	struct sbts_queue_invoke_task invoke_task = {0};
	invoke_task.version = 0;
	invoke_task.hqueue = (__u64)hqueue;
	invoke_task.correlation_id = 0;
	invoke_task.task_type = SBTS_QUEUE_DMA_ASYNC;
	invoke_task.priv_data.dma_async.version = SBTS_VERSION;
	invoke_task.priv_data.dma_async.dir = 3;
	invoke_task.priv_data.dma_async.is_udvm_support = false;
	invoke_task.priv_data.dma_async.memset.fd = fd;
	invoke_task.priv_data.dma_async.memset.dev_addr = addr;
	invoke_task.priv_data.dma_async.memset.per_size = sizeof(__u8);
	invoke_task.priv_data.dma_async.memset.number = size;
	invoke_task.priv_data.dma_async.memset.val = val;

	ret = ioctl(fd, SBTS_QUEUE_INVOKE_TASK, &invoke_task);
	if (ret) {
		ERR_PRT("ASYNC M_DMA_MEMSET_D8 error!");
		return -1;
	}
	return 0;
}

int mlu_memset_D16_async(int fd, __u64 addr, __u16 val, size_t size, void *hqueue)
{
	int ret;
	struct sbts_queue_invoke_task invoke_task = {0};
	invoke_task.version = 0;
	invoke_task.hqueue = (__u64)hqueue;
	invoke_task.correlation_id = 0;
	invoke_task.task_type = SBTS_QUEUE_DMA_ASYNC;
	invoke_task.priv_data.dma_async.version = SBTS_VERSION;
	invoke_task.priv_data.dma_async.dir = 4;
	invoke_task.priv_data.dma_async.is_udvm_support = false;
	invoke_task.priv_data.dma_async.memset.fd = fd;
	invoke_task.priv_data.dma_async.memset.dev_addr = addr;
	invoke_task.priv_data.dma_async.memset.per_size = sizeof(__u16);
	invoke_task.priv_data.dma_async.memset.number = size;
	invoke_task.priv_data.dma_async.memset.val = val;

	ret = ioctl(fd, SBTS_QUEUE_INVOKE_TASK, &invoke_task);
	if (ret) {
		ERR_PRT("ASYNC M_DMA_MEMSET_D16 error!");
		return -1;
	}
	return 0;
}

int mlu_memset_D32_async(int fd, __u64 addr, __u32 val, size_t size, void *hqueue)
{
	int ret;
	struct sbts_queue_invoke_task invoke_task = {0};
	invoke_task.version = 0;
	invoke_task.hqueue = (__u64)hqueue;
	invoke_task.correlation_id = 0;
	invoke_task.task_type = SBTS_QUEUE_DMA_ASYNC;
	invoke_task.priv_data.dma_async.version = SBTS_VERSION;
	invoke_task.priv_data.dma_async.dir = 5;
	invoke_task.priv_data.dma_async.is_udvm_support = false;
	invoke_task.priv_data.dma_async.memset.fd = fd;
	invoke_task.priv_data.dma_async.memset.dev_addr = addr;
	invoke_task.priv_data.dma_async.memset.per_size = sizeof(__u32);
	invoke_task.priv_data.dma_async.memset.number = size;
	invoke_task.priv_data.dma_async.memset.val = val;

	ret = ioctl(fd, SBTS_QUEUE_INVOKE_TASK, &invoke_task);
	if (ret) {
		ERR_PRT("ASYNC M_DMA_MEMSET_D32 error!");
		return -1;
	}
	return 0;
}

int mlu_memset_D8(int fd, __u64 addr, __u8 val, size_t size)
{
	int ret;
	struct mem_bar_memset_compat_s memset_D8;

	memset_D8.dev_addr = addr;
	memset_D8.val = val;
	memset_D8.number = size;

	ret = ioctl(fd, M_DMA_MEMSET, &memset_D8);
	if (ret != 0) {
		ERR_PRT("M_DMA_MEMSET_D8 error!");
		return -1;
	}
	return 0;
}

int mlu_memset_D16(int fd, __u64 addr, __u16 val, size_t size)
{
	int ret;
	struct mem_bar_memsetd16_compat_s memset_D16;

	memset_D16.dev_addr = addr;
	memset_D16.val = val;
	memset_D16.number = size;
	ret = ioctl(fd, M_DMA_MEMSETD16, &memset_D16);
	if (ret != 0) {
		ERR_PRT("M_DMA_MEMSET_D16 error!");
		return -1;
	}
	return 0;
}

int mlu_memset_D32(int fd, __u64 addr, __u32 val, size_t size)
{
	int ret;
	struct mem_bar_memsetd32_compat_s memset_D32;

	memset_D32.dev_addr = addr;
	memset_D32.val = val;
	memset_D32.number = size;
	ret = ioctl(fd, M_DMA_MEMSETD32, &memset_D32);
	if (ret != 0) {
		ERR_PRT("M_DMA_MEMSET_D32 error!");
		return -1;
	}
	return 0;
}
int h2d(int fd, __u64 addr, char *buf, int size)
{
	int ret;
	struct mem_copy_h2d_compat_s copy_h2d;

	copy_h2d.ca = (__u64)buf;
	copy_h2d.ia = addr;
	copy_h2d.total_size = size;
	copy_h2d.residual_size = 0;

	ret = ioctl(fd, M_MEM_COPY_H2D, (void *)&copy_h2d);
	if (ret != 0) {
		ERR_PRT("COPY H2D error");
		return -1;
	}

	return 0;
}

int d2h(int fd, __u64 addr, char *buf, int size)
{
	int ret;
	struct mem_copy_d2h_compat_s copy_d2h;

	copy_d2h.ca = (__u64)buf;
	copy_d2h.ia = addr;
	copy_d2h.total_size = size;
	copy_d2h.residual_size = 0;

	ret = ioctl(fd, M_MEM_COPY_D2H, (void *)&copy_d2h);
	if (ret) {
		ERR_PRT("COPY D2H error");
		return -1;
	}

	return 0;
}

int d2d(int fd, __u64 src_addr, __u64 dst_addr, __u64 size)
{
	int ret;
	struct mem_copy_d2d_compat_s copy_d2d;

	copy_d2d.src = src_addr;
	copy_d2d.dst = dst_addr;
	copy_d2d.size = size;

	ret = ioctl(fd, M_MEM_COPY_D2D, (void *)&copy_d2d);
	if (ret != 0) {
		ERR_PRT("COPY D2D error");
		return -1;
	}

	return 0;
}

int p2p(int fd, int peer_fd, __u64 dst_addr, __u64 src_addr, __u64 size)
{
	int ret = 0;
	struct mem_copy_p2p_compat_s p2p_set;

	p2p_set.peer_fd = peer_fd;
	p2p_set.src_addr = src_addr;
	p2p_set.dst_addr = dst_addr;
	p2p_set.count = size;

	ret = ioctl(fd, M_PEER_TO_PEER, &p2p_set);
	if (ret) {
		ERR_PRT("COPY P2P error");
		return ret;
	}

	return ret;
}

int async_h2d(int fd, __u64 addr, char *buf, int size, void *hqueue)
{
	int ret;
#ifdef M_MEM_COPY_ASYNC_D2H
	struct mem_copy_h2d_async_compat_s async_copy_h2d;

	async_copy_h2d.version = SBTS_VERSION;
	async_copy_h2d.hqueue = (__u64)hqueue;
	async_copy_h2d.ia = addr;
	async_copy_h2d.ca = (__u64)buf;
	async_copy_h2d.total_size = size;
	async_copy_h2d.residual_size = size;

	ioctl(fd, M_MEM_COPY_ASYNC_H2D, &async_copy_h2d);
	ret = async_copy_h2d.residual_size;
	if (ret != 0) {
		ERR_PRT("ASYNC COPY H2D error");
		return -1;
	}
#endif
#ifdef SBTS_QUEUE_INVOKE_TASK
	struct sbts_queue_invoke_task invoke_task = {0};

	invoke_task.version = 0;
	invoke_task.hqueue = (__u64)hqueue;
	invoke_task.correlation_id = 0;
	invoke_task.task_type = SBTS_QUEUE_DMA_ASYNC;
	invoke_task.priv_data.dma_async.version = SBTS_VERSION;
	invoke_task.priv_data.dma_async.dir = 0;
	invoke_task.priv_data.dma_async.is_udvm_support = false;
	invoke_task.priv_data.dma_async.memcpy.src_addr = (__u64)buf;
	invoke_task.priv_data.dma_async.memcpy.dst_addr = addr;
	invoke_task.priv_data.dma_async.memcpy.size = size;
	invoke_task.priv_data.dma_async.memcpy.mem.src_fd = -1;
	invoke_task.priv_data.dma_async.memcpy.mem.dst_fd = fd;

	ret = ioctl(fd, SBTS_QUEUE_INVOKE_TASK, &invoke_task, sizeof(invoke_task));
	if (ret) {
		ERR_PRT("ASYNC COPY TO DDR error!");
		return -1;
	}
#endif
	return 0;
}

int async_d2h(int fd, __u64 addr, char *buf, int size, void *hqueue)
{
	int ret;
#ifdef M_MEM_COPY_ASYNC_D2H
	struct mem_copy_d2h_async_compat_s async_copy_d2h;

	async_copy_d2h.version = SBTS_VERSION;
	async_copy_d2h.hqueue = (__u64)hqueue;
	async_copy_d2h.ia = addr;
	async_copy_d2h.ca = (__u64)buf;
	async_copy_d2h.total_size = size;
	async_copy_d2h.residual_size = size;

	ioctl(fd, M_MEM_COPY_ASYNC_D2H, &async_copy_d2h);
	ret = async_copy_d2h.residual_size;
	if (ret != 0) {
		ERR_PRT("ASYNC COPY D2H error");
		return -1;
	}
#endif
#ifdef SBTS_QUEUE_INVOKE_TASK
	struct sbts_queue_invoke_task invoke_task = {0};

	invoke_task.version = 0;
	invoke_task.hqueue = (__u64)hqueue;
	invoke_task.correlation_id = 0;
	invoke_task.task_type = SBTS_QUEUE_DMA_ASYNC;
	invoke_task.priv_data.dma_async.version = SBTS_VERSION;
	invoke_task.priv_data.dma_async.dir = 1;
	invoke_task.priv_data.dma_async.is_udvm_support = false;
	invoke_task.priv_data.dma_async.memcpy.src_addr = addr;
	invoke_task.priv_data.dma_async.memcpy.dst_addr = (__u64)buf;
	invoke_task.priv_data.dma_async.memcpy.size = size;
	invoke_task.priv_data.dma_async.memcpy.mem.src_fd = fd;
	invoke_task.priv_data.dma_async.memcpy.mem.dst_fd = -1;

	ret = ioctl(fd, SBTS_QUEUE_INVOKE_TASK, &invoke_task, sizeof(invoke_task));
	if (ret) {
		ERR_PRT("ASYNC COPY TO DDR error!");
		return -1;
	}
#endif
	return 0;
}

int async_d2d(int fd, __u64 src_addr, __u64 dst_addr, __u64 size, void *hqueue)
{
	int ret;
#ifdef M_MEM_COPY_ASYNC_D2D
	struct mem_copy_d2d_async_compat_s async_copy_d2d;

	async_copy_d2d.version = SBTS_VERSION;
	async_copy_d2d.hqueue = (__u64)hqueue;
	async_copy_d2d.src = src_addr;
	async_copy_d2d.dst = dst_addr;
	async_copy_d2d.size = size;
	async_copy_d2d.residual_size = size;

	ret = ioctl(fd, M_MEM_COPY_ASYNC_D2D, &async_copy_d2d);
	if (ret != 0) {
		ERR_PRT("ASYNC COPY D2D error");
		return -1;
	}
#endif
#ifdef SBTS_QUEUE_INVOKE_TASK
	struct sbts_queue_invoke_task invoke_task = {0};

	invoke_task.version = 0;
	invoke_task.hqueue = (__u64)hqueue;
	invoke_task.correlation_id = 0;
	invoke_task.task_type = SBTS_QUEUE_DMA_ASYNC;
	invoke_task.priv_data.dma_async.version = SBTS_VERSION;
	invoke_task.priv_data.dma_async.dir = 6;
	invoke_task.priv_data.dma_async.is_udvm_support = false;
	invoke_task.priv_data.dma_async.memcpy.src_addr = src_addr;
	invoke_task.priv_data.dma_async.memcpy.dst_addr = dst_addr;
	invoke_task.priv_data.dma_async.memcpy.size = size;
	invoke_task.priv_data.dma_async.memcpy.mem.src_fd = fd;
	invoke_task.priv_data.dma_async.memcpy.mem.dst_fd = fd;

	ret = ioctl(fd, SBTS_QUEUE_INVOKE_TASK, &invoke_task, sizeof(invoke_task));
	if (ret) {
		ERR_PRT("ASYNC COPY TO DDR error!");
		return -1;
	}
#endif
	return 0;
}

int async_p2p(int fd, int peer_fd, __u64 dst_addr, __u64 src_addr, void *hstream, __u64 size)
{
	int ret = 0;
#ifdef M_PEER_TO_PEER_ASYNC
	struct mem_copy_p2p_async_compat_s p2p_set;

	p2p_set.version = SBTS_VERSION;
	p2p_set.src_fd = fd;
	p2p_set.dst_fd = peer_fd;
	p2p_set.src_addr = src_addr;
	p2p_set.dst_addr = dst_addr;
	p2p_set.count = size;
	p2p_set.hqueue = (__u64)hstream;

	ret = ioctl(fd, M_PEER_TO_PEER_ASYNC, &p2p_set);
	if (ret) {
		ERR_PRT("ASYNC COPY P2P error");
		return ret;
	}
#endif
#ifdef SBTS_QUEUE_INVOKE_TASK
	struct sbts_queue_invoke_task invoke_task = {0};

	invoke_task.version = 0;
	invoke_task.hqueue = (__u64)hstream;
	invoke_task.correlation_id = 0;
	invoke_task.task_type = SBTS_QUEUE_DMA_ASYNC;
	invoke_task.priv_data.dma_async.version = SBTS_VERSION;
	invoke_task.priv_data.dma_async.dir = 2;
	invoke_task.priv_data.dma_async.is_udvm_support = false;
	invoke_task.priv_data.dma_async.memcpy.src_addr = src_addr;
	invoke_task.priv_data.dma_async.memcpy.dst_addr = dst_addr;
	invoke_task.priv_data.dma_async.memcpy.size = size;
	invoke_task.priv_data.dma_async.memcpy.mem.src_fd = fd;
	invoke_task.priv_data.dma_async.memcpy.mem.dst_fd = peer_fd;

	ret = ioctl(fd, SBTS_QUEUE_INVOKE_TASK, &invoke_task, sizeof(invoke_task));
	if (ret) {
		ERR_PRT("ASYNC COPY TO DDR error!");
		return -1;
	}
#endif
	return 0;
}

int create_queue(int fd, void **hqueue, int flags)
{
	int ret;
	struct sbts_create_queue param;

	param.version = SET_VERSION(6U, SBTS_VERSION);
	param.flags = flags;
	param.priority = 0;
	param.dump_uvaddr = 0;

	ret = ioctl(fd, SBTS_CREATE_QUEUE, &param);
	if (ret) {
		ERR_PRT("SBTS CREATE QUEUE error!");
		return ret;
	}
	*hqueue = (void *)param.hqueue;

	return 0;
}

int destroy_queue(int fd, void *hqueue)
{
	int ret;
	struct sbts_destroy_queue param;

	param.version = SBTS_VERSION;
	param.hqueue = (__u64)hqueue;

	ret = ioctl(fd, SBTS_DESTROY_QUEUE, &param);
	if (ret) {
		ERR_PRT("SBTS DESTROY QUEUE error!");
		return ret;
	}

	return 0;
}

int sync_queue(int fd, void *hqueue)
{
	int ret;
#ifdef SBTS_QUEUE_SYNC
	struct sbts_push_task param = {0};

	param.version = SBTS_VERSION;
	param.hqueue = (__u64)hqueue;

	ret = ioctl(fd, SBTS_QUEUE_SYNC, &param);
	if (ret) {
		ERR_PRT("SBTS QUEUE SYNC error!");
		return ret;
	}
#endif
#ifdef SBTS_QUEUE_INVOKE_TASK
	struct sbts_queue_invoke_task invoke_task = {0};

	invoke_task.version = 0;
	invoke_task.hqueue = (__u64)hqueue;
	invoke_task.correlation_id = 0;
	invoke_task.task_type = SBTS_QUEUE_SYNC_TASK;
	ret = ioctl(fd, SBTS_QUEUE_INVOKE_TASK, &invoke_task, sizeof(invoke_task));
	if (ret) {
		ERR_PRT("SBTS QUEUE SYNC error!");
		return -1;
	}
#endif
	return 0;
}

int create_notifier(int fd, void **hnotifier, int flags)
{
	int ret;
	struct sbts_create_notifier param;

	param.version = SBTS_VERSION;
	param.flags = flags;

	ret = ioctl(fd, SBTS_NOTIFIER_CREATE, &param);
	if (ret) {
		ERR_PRT("SBTS CREATE NOTIFIER error!");
		return ret;
	}
	*hnotifier = (void *)param.hnotifier;

	return 0;
}

int destroy_notifier(int fd, void *hnotifier)
{
	int ret;
	struct sbts_destroy_notifier param;

	param.version = SBTS_VERSION;
	param.hnotifier = (__u64)hnotifier;

	ret = ioctl(fd, SBTS_NOTIFIER_DESTROY, &param);
	if (ret) {
		ERR_PRT("SBTS DESTROY NOTIFIER error!");
		return ret;
	}

	return 0;
}

int place_notifier(int fd, void *hnotifier, void *hqueue)
{
	int ret;
#ifdef SBTS_NOTIFIER_PLACE
	struct sbts_push_task param;

	param.version = SBTS_VERSION;
	param.hqueue = (__u64)hqueue;
	param.hnotifier = (__u64)hnotifier;

	ret = ioctl(fd, SBTS_NOTIFIER_PLACE, &param);
	if (ret) {
		ERR_PRT("SBTS PLACE NOTIFIER error!");
		return ret;
	}
#endif
#ifdef SBTS_QUEUE_INVOKE_TASK
	struct sbts_queue_invoke_task invoke_task = {0};

	invoke_task.version = 0;
	invoke_task.hqueue = (__u64)hqueue;
	invoke_task.correlation_id = 0;
	invoke_task.task_type = SBTS_QUEUE_NOTIFIER_PLACE;
	invoke_task.priv_data.notifier.version = SBTS_VERSION;
	invoke_task.priv_data.notifier.hnotifier = (__u64)hnotifier;

	ret = ioctl(fd, SBTS_QUEUE_INVOKE_TASK, &invoke_task, sizeof(invoke_task));
	if (ret) {
		ERR_PRT("SBTS QUEUE SYNC error!");
		return -1;
	}
#endif
	return 0;
}

int elapsed_swtime_notifier(int fd, struct timeval *ptv, void *hstart, void *hend)
{
	int ret;
	struct sbts_notifier_elapsed_time param;

	param.version = SBTS_VERSION;
	param.tv_sec = 0;
	param.tv_usec = 0;
	param.hstart = (__u64)hstart;
	param.hend = (__u64)hend;

	ret = ioctl(fd, SBTS_NOTIFIER_ELAPSED_SW_TIME, &param);
	if (ret) {
		ERR_PRT("SBTS NOTIFIER ELAPSED SW TIME error!");
		return ret;
	}

	ptv->tv_sec = param.tv_sec;
	ptv->tv_usec = param.tv_usec;
	return 0;
}
