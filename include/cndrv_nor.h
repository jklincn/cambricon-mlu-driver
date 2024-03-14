#ifndef __CAMBRICON_NOR_H__
#define __CAMBRICON_NOR_H__

#ifndef __ASSEMBLY__

/*
 * @brief: read date from ISSE nor flash in APB mode
 * @param: addr should be four bytes aligned
 *         length should be four bytes aligned
 * @return:readout length in bytes
 */
ssize_t nor_read(struct cn_core_set *core_set, uint32_t *buffer, uint32_t addr,
		size_t length);
/*
 * @brief: Nor flash consists of blocks with 4KB granule. An erasion is
 *         necessary before a block is written which is hidden in
 *         nor_write api. So, if only part of a block needs to be updated,
 *         follow the steps:
 *         1. preserve whole block by nor_read into a buffer
 *         2. update buffer
 *         3. write whole buffer by nor_write
 *
 * @param: addr should be four bytes aligned
 *         length should be four bytes aligned
 * @return:copy out length in bytes
 */
ssize_t nor_write(struct cn_core_set *core_set, uint32_t *src_buffer,
		uint32_t dst_addr, size_t length);
int cn_nor_init(struct cn_core_set *core);
void cn_nor_exit(struct cn_core_set *core);

#endif /*__ASSEMBLY__*/
#endif /*__NOR_H__*/
