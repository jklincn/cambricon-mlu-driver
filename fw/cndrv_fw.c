#include "cndrv_debug.h"
#include <linux/printk.h>
#include <linux/firmware.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/crc32.h>
#include <asm/unaligned.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_fw.h"
#include "cndrv_mcu.h"
#include "../core/version.h"

#define FIRMWARE_IMG_MAX	10
#define FIRMWARE_MAGIC		"CAMBR-FW"
#define FIRMWARE_MAGIC_SIZE	8
#define FIRMWARE_NAME_LEN	64

struct cn_fw {
	/* firmware stuff */
	unsigned char *bin_fw;
	unsigned long size_fw;
	unsigned int retval;
};

struct fw_pkg_hdr {
	unsigned char magic[FIRMWARE_MAGIC_SIZE];
	unsigned char version[FIRMWARE_VERSION_SIZE];

	struct payload {
		unsigned long size;	/* payload size in bytes */
		unsigned long addr;	/* payload physical load addr */
		char name[FIRMWARE_NAME_LEN]; /* payload name */
	} data[FIRMWARE_IMG_MAX];

	unsigned long npayload;
	unsigned long page_size;
	unsigned long timestamp;	/* timestamp information */
	unsigned char target_ending;	/* target endness: 0-LE, 1-BE */

	unsigned char name[FIRMWARE_NAME_LEN]; /* asciiz product name */
	unsigned id[8];
};

typedef struct fw_image {
	char name[FIRMWARE_NAME_LEN];
	unsigned long load_addr;	/* load point of the image */
	unsigned long mem_limit; /* memory limit size of the image */

	void *data;
	unsigned int size;
} fw_image_t;

/*****************************************************************************************
 * INITIALIZATION
 ****************************************************************************************/

#define DMA_KERNEL_CP
#define CHECK_ALL_PARTS        0

extern char *mparam_fw_path;
static int set_fw_path(struct cn_core_set *core, char *path)
{
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	mm_segment_t old_fs;
#endif
	struct file *fp;
	loff_t pos = 0;
	int ret = 0;

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif

	fp = filp_open("/sys/module/firmware_class/parameters/path", O_RDWR | O_CREAT, 0644);
	if (IS_ERR(fp)) {
		cn_dev_core_err(core, "Open file:%s failed, %ld", "/sys/module/firmware_class/parameters/path/sys/module/firmware_class/parameters/path", PTR_ERR(fp));
		ret = -1;
		goto set_path_exit;
	}

	if (strlen(path) == 0)
		ret = cn_fs_write(fp, "\0", 1, &pos);
	else
		ret = cn_fs_write(fp, path, strlen(path), &pos);

	filp_close(fp, NULL);

set_path_exit:
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	set_fs(old_fs);
#endif
	return ret;
}


int check_firmware(struct cn_fw *cn_fw)
{
	u32 crc = 0;
	struct fw_pkg_hdr *fw_hdr;
	unsigned char *ptr;
	unsigned long pagesize = 0;

	ptr = cn_fw->bin_fw;
	/* check for firmware magic */
	fw_hdr = (struct fw_pkg_hdr *)ptr;
	if(strncmp(fw_hdr->magic, FIRMWARE_MAGIC, FIRMWARE_MAGIC_SIZE) != 0) {
		pr_err("firmware: this is not cambricon firmware\n");
		return -EINVAL;
	}

	crc = get_unaligned_be32(&fw_hdr->id[0]);

	pagesize = get_unaligned_be32(&fw_hdr->page_size);

	if (crc != crc32_o(0, ptr + pagesize, cn_fw->size_fw - pagesize)) {
		pr_err("firmware: crc32 of firmware does not match.\n");
		return -EINVAL;
	}

	return 0;
}

void put_firmware(struct cn_fw *cn_fw)
{
	cn_vfree(cn_fw->bin_fw);
}

int get_firmware(struct cn_fw *cn_fw, struct device *dev, u64 device_id)
{
	int ret;
	const struct firmware *fw;
	char fw_name[100];

	memset(fw_name, 0x00, sizeof(fw_name));

	switch(device_id) {
	case MLUID_580:
		sprintf(fw_name, "cambricon/%s/firmware_sys.img", "mlu580");
		break;
	case MLUID_590:
		sprintf(fw_name, "cambricon/%s/firmware_sys.img", "mlu590");
		break;
	case MLUID_370:
		sprintf(fw_name, "cambricon/%s/firmware_sys.img", "mlu370");
		break;
	case MLUID_CE3226:
		sprintf(fw_name, "cambricon/%s/firmware_sys.img", "ce3226");
		break;
	case MLUID_PIGEON:
		sprintf(fw_name, "cambricon/%s/firmware_sys.img", "pigeon");
		break;
	case MLUID_290:
		sprintf(fw_name, "cambricon/%s/firmware_sys.img", "mlu290");
		break;
	case MLUID_270:
		sprintf(fw_name, "cambricon/%s/firmware_sys.img", "mlu270");
		break;
	case MLUID_220:
		sprintf(fw_name, "cambricon/%s/firmware_sys.img", "mlu220");
		break;
	default:
		pr_err("Can not get MLUID: 0x%llx firmware\n", device_id);
		return -1;
	}

	/***
	 * request cambricon firmware, this will block util someone uploads it
	 * /lib/firmware/...
	 */
	ret = request_firmware(&fw, fw_name, dev);
	if (ret) {
		if (ret == -ENOENT) {
			pr_err(KERN_ERR "firmware: could not load firmware,"
				" file not found: arm_firmware.img\n");
			pr_err(KERN_ERR "firmware: usually this should be in "
				"/usr/lib/hotplug/firmware or /lib/firmware/cambricon\n");
		} else {
			pr_err(KERN_ERR "firmware: cannot request firmware"
				" (error %i)\n", ret);
		}
		return -EINVAL;
	}

	/* firmware can not exceed 128M */
	if (fw->size >= 0x08000000) {
		pr_err("firmware: this firmware is way too big.\n");
		release_firmware(fw);
		return -EINVAL;
	}

	/* check if the firmware is available */
	cn_fw->bin_fw = cn_vzalloc(fw->size);
	if (NULL == cn_fw->bin_fw) {
		pr_err("out of memory\n");
		release_firmware(fw);
		return -ENOMEM;
	}
	/* mid-copy to prepare firmware buffer */
	memcpy(cn_fw->bin_fw, fw->data, fw->size);
	cn_fw->size_fw = fw->size;
	if ((ret = check_firmware(cn_fw))) {
		cn_vfree(cn_fw->bin_fw);
	}

	release_firmware(fw);
	return ret;
}

int upload_buff(struct cn_core_set *core, unsigned char *image_name,
		unsigned char *buff, unsigned long load_addr,
		unsigned long size, unsigned long block_size)
{
	int i = 0, j = 0;
	int ret = 0;

	unsigned remain_size = size;
	unsigned long copy_size = 0;

	unsigned long block_mask = block_size - 1;
	int cnt = (size + block_mask) / block_size;

	for (i = 0; i < cnt; i++) {
		if (i == cnt - 1)
			remain_size = size - (cnt - 1) * block_size;
		for (j = 0; j < block_size && j < remain_size; j += 4) {
			mem_write32(core->bus_set,
				load_addr + i * block_size + j,
				*(unsigned int *)(buff + i * block_size + j));
		}

		schedule();

		copy_size = copy_size + j;
	}

	if (copy_size >= 0x100000) {
		cn_dev_core_info(core, "image: [%s] send_size = %ldM",
				image_name, copy_size / 1024 / 1024);
	} else {
		cn_dev_core_info(core, "image: [%s] send_size = 0x%lx",
				image_name, copy_size);
	}

	return ret;
}

int upload_dma_buff(
		struct cn_core_set *core,
		unsigned char *image_name,
		unsigned char *image,
		unsigned long load_addr,
		unsigned long size,
		unsigned long block_size)
{
	int i = 0;
	int ret = 0;
	unsigned remain_size = size;
	unsigned long copy_size = 0;
	unsigned long total_size = 0;
	unsigned long block_mask = block_size - 1;
	int cnt = (size + block_mask) / block_size;
	unsigned char *block_buf = NULL;

	block_buf = cn_vzalloc(block_size * sizeof(unsigned char));
	if (!block_buf)
		return -1;

	for (i = 0; i < cnt; i++) {
		if (i == cnt - 1)
			remain_size = size - (cnt - 1) * block_size;

		copy_size = (remain_size < block_size) ? remain_size : block_size;
		memcpy(block_buf, image + (i * block_size), copy_size);

		if (core->board_info.platform == MLU_PLAT_ASIC) {
			cn_bus_boot_image(core->bus_set, (unsigned long)block_buf,
					load_addr + i * block_size, copy_size);
		} else {
			cn_bus_dma_kernel(core->bus_set, (unsigned long)block_buf,
					load_addr + i * block_size, copy_size, DMA_H2D);
		}
		schedule();

#if CHECK_ALL_PARTS
		pr_debug("Check image[%s][%d] ...\n", image_name, i);
		ret = cn_bus_check_image(core->bus_set, block_buf,
			load_addr + i * block_size, copy_size);
		if (ret) {
			pr_err("image[%s][%d] check failed!\n", image_name, i);
			goto ERR_RET;
		}
#else
		if (!strcmp(image_name, "bl1.bin") ||
		    ((core->device_id == MLUID_PIGEON) && !strcmp(image_name, "bl31.bin"))) {
			pr_info("Check image[%s][%d] ...\n", image_name, i);
			ret = cn_bus_check_image(core->bus_set, block_buf,
				load_addr + i * block_size, copy_size);
			if (ret) {
				pr_err("bin image[%d] check failed!\n", i);
				goto ERR_RET;
			}
		}
#endif
		total_size = total_size + copy_size;
	}

	if (total_size >= 0x100000)
		cn_dev_core_debug(core, "image: [%s] send size = %ldM", image_name,
				total_size / (1024 * 1024));
	else
		cn_dev_core_debug(core, "image: [%s] send size = 0x%lx Bytes",
				image_name, total_size);

ERR_RET:
	if (block_buf)
		cn_vfree(block_buf);

	return ret;
}

/*The SMMU is not work before buring up*/
#define DDR_BASE	(0x0)

int upload_image(struct cn_core_set *core, unsigned char *image_name, unsigned char* image, unsigned long load_addr, unsigned long size)
{
	int ret = 0;
	int block_size = 0x100000; // every time transfer 1MB then schedule

#ifdef DMA_KERNEL_CP
	/***
	 * BAR2/4 used for bar_copy handle process (Bar4 only for pigeon)
	 * If HSP_BOOT then will use DMA engine.
	 */
	ret = upload_dma_buff(core, image_name, image, load_addr + DDR_BASE, size, block_size);
	if (ret) {
		printk(KERN_ERR "upload_dma_buff report failure\n");
	}
#else
	/***
	 * mem_write : Will use the "share_mem[0] + load_addr" to access OS ZONE.
	 */
	upload_buff(core, image_name, image, load_addr, size, block_size);
#endif
	return ret;
}

unsigned long aligned_pagesize(unsigned long size, unsigned long pagesize)
{
	unsigned long pagemask = pagesize - 1;
	unsigned long comp;
	comp = pagesize - (size & pagemask);
	if (comp == pagesize) comp = 0;
	return size + comp;
}

int upload_fw(struct cn_core_set *core, unsigned long *bl1_entry_point, unsigned long *img_certs_addr)
{
	struct cn_fw cn_fw;
	struct fw_pkg_hdr *fw_hdr;
	struct device *dev = cn_bus_get_dev(core->bus_set);
	unsigned char *ptr;
	unsigned long pagesize;
	int i;
	int ret = 0;
	char version[30];

	if (mparam_fw_path != NULL)
		set_fw_path(core, mparam_fw_path);
	/* locate at /lib/firmware/cambricon/pigeon/firmware_sys.img */
	ret = get_firmware(&cn_fw, dev, core->device_id);
	if (ret) {
		pr_err("get_firmware failure\n");
		ret = -1;
		goto exit_unset_path;
	}
	/* Get head information from image */
	ptr = cn_fw.bin_fw;
	fw_hdr = (struct fw_pkg_hdr *)ptr;

	pagesize = get_unaligned_be32(&fw_hdr->page_size);

	printk("firmware_sys.img Version:   %s\n", fw_hdr->version);
	strncpy(core->firmware_version, fw_hdr->version, FIRMWARE_VERSION_SIZE);

	sprintf(version, "%d.%d.%d", DRV_MAJOR, DRV_MINOR, DRV_BUILD);

	if (strncmp(version, core->firmware_version, strlen(core->firmware_version))) {
		pr_err("firmware_sys.img version differ from cndrv_host version,"
				"Drv Version: %s, firmware_sys.img Version: %s\n",
				version, fw_hdr->version);
		ret = -1;
		goto exit;
	}

	for (i = 0; i < fw_hdr->npayload; i++) {
		printk("    %-20s address 0x%llx(size 0x%08x)\n", fw_hdr->data[i].name,
				get_unaligned_be64(&fw_hdr->data[i].addr),
				get_unaligned_be32(&fw_hdr->data[i].size));
		/***
		 * For PIGEONM.2 will use bl31.bin
		 */
		if (core->device_id == MLUID_PIGEON) {
			if (!strcmp("bl31.bin", fw_hdr->data[i].name)) {
				pr_info("PIGEONM.2's entry is in bl31.bin.\n");
				*bl1_entry_point = get_unaligned_be64(&fw_hdr->data[i].addr); /*PC to bring*/
			}
		} else {
			if (!strcmp("bl1.bin", fw_hdr->data[i].name)) {
				*bl1_entry_point = get_unaligned_be64(&fw_hdr->data[i].addr); /*PC to bring*/
			} else if (!strcmp("fw-certs", fw_hdr->data[i].name)) {
				*img_certs_addr = get_unaligned_be64(&fw_hdr->data[i].addr);
			} else {
				continue;
			}
		}
	}

	ptr = ptr + aligned_pagesize(sizeof(struct fw_pkg_hdr), pagesize);

	/***
	 * The firmware image may have more than one parts.
	 */
	for (i = 0; i < fw_hdr->npayload; i++) {
		ret = upload_image(core, fw_hdr->data[i].name, ptr,
			get_unaligned_be64(&fw_hdr->data[i].addr),
			get_unaligned_be32(&fw_hdr->data[i].size));
		if (ret)
			goto exit;
		ptr = ptr + aligned_pagesize(get_unaligned_be32(&fw_hdr->data[i].size), pagesize);
	}

exit:
	put_firmware(&cn_fw);
exit_unset_path:
	if (mparam_fw_path != NULL)
		set_fw_path(core, "\0");
	return ret;
}

int cn_bringup(struct cn_core_set *core)
{
	int ret = 0;
	unsigned long bl1_entry_point = 0;
	unsigned long img_certs_addr = 0;

	mutex_lock(&core->runqueue_mutex);
	/* check device bus idle state and pre ready for bringup */
	ret = boot_prepare(core);
	if (ret) {
		pr_err("[%s] boot prepare failure\n", core->core_name);
		mutex_unlock(&core->runqueue_mutex);
		return -1;
	}

	/* copy device fw from host to device DDR */
	if (core->board_info.platform != MLU_PLAT_VDK) {
		ret = upload_fw(core, &bl1_entry_point, &img_certs_addr);
		if (ret) {
			pr_err("[%s] upload fw failure\n", core->core_name);
			mutex_unlock(&core->runqueue_mutex);
			return -1;
		}
	}

	core->arm_pc_init = bl1_entry_point;
	core->certs_addr = img_certs_addr;

	/* bringup device cpu system and device controller startup executing inst */
	ret = bringup(core, bl1_entry_point);
	if (ret) {
		pr_err("[%s] bringup failure\n", core->core_name);
		mutex_unlock(&core->runqueue_mutex);
		return -1;
	}
	mutex_unlock(&core->runqueue_mutex);
	return 0;
}

