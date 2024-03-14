
#include "../dmlib/include/domain.h"
#include "../dmlib/domain_resource_dictionary.h"
#include "../dmlib/domain_private.h"
#ifdef DM_UT_TEST_GLOBAL_ENABLE

static char ut_dm_ipu_resource[] = {
	a_ipu_cores,
	b_ipu_caps,
	c_ipu_mems,
	-1
};
static char ut_dm_vpu_resource[] = {
	a_vpu_cores,
	b_vpu_caps,
	c_vpu_mems,
	-1
};
static char ut_dm_jpu_resource[] = {
	a_jpu_cores,
	b_jpu_mems,
	-1
};
static char ut_dm_mem_resource[] = {
	a_mem_num_of_zones,
	b_mem_zone,
	b_mem_zone,
	-1
};
static char ut_dm_pci_resource[] = {
	a_pci_ob_num,
	b_pci_ob_host_addr,
	c_pci_ob_axi_addr,
#if 0
	d_pci_ob_sz,
	e_pci_bar_num,
	f_pci_bar_sz,
	g_pci_bar_reg_bs,
	h_pci_bar_reg_sz,
	i_pci_bar_shm_bs,
	j_pci_bar_shm_sz,
	k_pci_dma_ch,
#endif
	-1
};
static char ut_dm_board_resource[] = {
	a_chip_ver,
	b_board_id,
	-1
};
const struct dm_resource_discriptor dm_ut_res_set[] = {
	[0] = {.mod_idx = DM_IPU_IDX, .res = ut_dm_ipu_resource},
	[1] = {.mod_idx = DM_VPU_IDX, .res = ut_dm_vpu_resource},
	[2] = {.mod_idx = DM_JPU_IDX, .res = ut_dm_jpu_resource},
	[3] = {.mod_idx = DM_MEM_IDX, .res = ut_dm_mem_resource},
	[4] = {.mod_idx = DM_PCI_IDX, .res = ut_dm_pci_resource},
	[5] = {.mod_idx = DM_BOARD_IDX, .res = ut_dm_board_resource},
	[6] = {.mod_idx = -1, .res = NULL},
};
static char _res_offset0[ARRAY_SIZE(ut_dm_ipu_resource) + 1] = {0, 0, 0};
static char _res_offset1[ARRAY_SIZE(ut_dm_vpu_resource) + 1] = {0, 0, 0};
static char _res_offset2[ARRAY_SIZE(ut_dm_jpu_resource) + 1] = {0, 0, 0};
static char _res_offset3[ARRAY_SIZE(ut_dm_mem_resource) + 1] = {0, 0, 0};
static char _res_offset4[ARRAY_SIZE(ut_dm_pci_resource) + 1] = {0, 0, 0};//{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static char _res_offset5[ARRAY_SIZE(ut_dm_board_resource) + 1] = {0, 0, 0};
static char *res_offset[6] = {
	_res_offset0,
	_res_offset1,
	_res_offset2,
	_res_offset3,
	_res_offset4,
	_res_offset5,
};
u64 _res_val0[4];
u64 _res_val1[4];
u64 _res_val2[4];
u64 _res_val3[4];
u64 _res_val4[12];
u64 _res_val5[4];
u64 *res_val[6] = {
	_res_val0,
	_res_val1,
	_res_val2,
	_res_val3,
	_res_val4,
	_res_val5,
};
int dm_ut_case_rpc_get_resource(struct domain_set_type *set)
{
	static int counter = 0;
	struct domain_type *domain = NULL;
	int i = 0;
	static int ut_res_set_max_res_num = 0;
	static int mig_res_set_max_res_num = 0;
	counter++;
	if (counter == 200) {
		print_info("dm_ut_case_rpc_get_and_set_resource start %d\n",
								counter);
	} else {
		return 0;
	}
	ut_res_set_max_res_num == 0 ?
		ut_res_set_max_res_num = get_max_resource_number(dm_ut_res_set) :
		ut_res_set_max_res_num;
	mig_res_set_max_res_num  == 0 ?
		mig_res_set_max_res_num =
			get_max_resource_number(dm_ut_res_set) :
		mig_res_set_max_res_num;
	print_info("ut_res_max=%d mig_res_max=%d\n",
		    ut_res_set_max_res_num, mig_res_set_max_res_num);
	for_each_set_bit(i, &set->domains_mask,
			sizeof(set->domains_mask) * BITS_PER_BYTE) {
		if (i == 0)
			continue;

		domain = dm_get_domain(set, i);
		dm_rpc_get_resource_host(set->queue.host.rpc, res_val,
				dm_ut_res_set, res_offset,
				ut_res_set_max_res_num, domain);
		dm_rpc_get_resource_host(set->queue.host.rpc, res_val,
				dm_mig_res_set,
				res_offset, mig_res_set_max_res_num, domain);
	}
	return 0;
}
int dm_ut_case_rpc_set_resource(struct domain_set_type *set)
{
	static int counter = 0;
	struct domain_type *domain = NULL;
	int i = 0;

	counter++;
	if (counter == 200) {
		print_info("dm_ut_case_rpc_get_and_set_resource start %d\n", counter);
	} else {
		return 0;
	}
	for_each_set_bit(i, &set->domains_mask,
			sizeof(set->domains_mask) * BITS_PER_BYTE) {
		if (i == 0)
			continue;

		domain = dm_get_domain(set, i);
		dm_rpc_set_resource_host(set->queue.host.rpc, domain, domain,
				dm_outbound_distribute_resource_set,
				res_offset, 4);
	}
	return 0;
}

int dm_ut_test_start(struct domain_set_type *set)
{
	int ret;
	ret = dm_ut_case_rpc_get_resource(set);
	if (ret < 0) {
		return -1;
	}
	ret = dm_ut_case_rpc_set_resource(set);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

#endif
