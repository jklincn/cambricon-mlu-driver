#include <linux/bitmap.h>
#include <linux/delay.h>
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_ioctl.h"
#include "cndrv_domain.h"
#include "include/internal_interface.h"
#include "dmlib/include/domain.h"

struct mlu_instance_placement_info
{
	u32 placement_mask;
	u32 size;
};

int cn_dm_device_is_support_mim(struct cn_core_set *core, u32 *support)
{
	struct domain_set_type *domain_set = NULL;
	int ret = 0, is_support = 0, ret_len = 0;

	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	if (IS_ERR_OR_NULL(support))
		return -EINVAL;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (IS_ERR_OR_NULL(domain_set))
		return -EINVAL;

	if (domain_set->mim_dev_support == DM_MIM_DEV_NOT_INIT) {
		ret = dm_compat_rpc(domain_set,
			"dm_rpc_query_platform_is_mim_support",
			&is_support, sizeof(int), &is_support,
			&ret_len, sizeof(int));
		if (unlikely(ret < 0)) {
			cn_domain_err(domain_set,
				"dm_rpc_query_platform_is_mim_support failed");
			return -EINVAL;
		} else {
			*support = is_support ? DM_MIM_DEV_SUPPORT : DM_MIM_DEV_NOT_SUPPORT;
			domain_set->mim_dev_support = *support;
		}
	} else {
		*support = domain_set->mim_dev_support;
	}

	return 0;
}

bool cn_dm_is_mim_support(struct cn_core_set *core)
{
	struct domain_set_type *domain_set;
	int ret, is_support, ret_len;

	if (!core)
		return false;

	if (!cn_is_mim_en(core))
		return false;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return false;

	if (domain_set->is_mim_support == 0) {
		ret = dm_compat_rpc(domain_set,
			"dm_rpc_query_platform_is_mim_support",
			&is_support, sizeof(int), &is_support,
			&ret_len, sizeof(int));
		if (unlikely(ret < 0)) {
			cn_domain_err(domain_set,
				"dm_rpc_query_platform_is_mim_support failed");
			domain_set->is_mim_support = -1;
		}

		if (is_support && (!cn_core_is_vf(core)))
			domain_set->is_mim_support = 1;
		else
			domain_set->is_mim_support = -1;
	}

	if (domain_set->is_mim_support == 1)
		return true;
	else
		return false;
}

static int cn_dm_activate_mim_mode(struct cn_core_set *core)
{
	int nums_max_domain, nums_domain;
	struct domain_set_type *domain_set;
	int i, ret_val, ret_len, ret;
	u32 domain_id;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	if (!cn_dm_is_mim_support(core)) {
		cn_domain_err(domain_set, "mim mode is not support");
		return -1;
	}

	mutex_lock(&domain_set->mim_lock);
	if (domain_set->mim_enable) {
		cn_domain_err(domain_set, "MIM mode is already enabled");
		goto err;
	}

	nums_domain = bitmap_weight(&domain_set->domains_mask, 32) - 1;
	nums_max_domain = domain_set_attr_get_max_vf(domain_set);
	if (nums_domain != nums_max_domain) {
		cn_domain_err(domain_set, "nums_domain:%d,nums_max_domain:%d, enable MIM mode failed",
						nums_domain, nums_max_domain);
		goto err;
	}

	for (i = 1; i <= nums_domain; i++)
		cn_bus_remove_mi(core->bus_set, i);

	for (i = 0; i < nums_domain; i++) {
		domain_id = DM_FUNC_VF0 + i;
		ret = dm_compat_rpc(domain_set, "dm_rpc_destroy_mlu_instance",
					&domain_id, sizeof(u32), &ret_val,
					&ret_len, sizeof(int));
		if (ret_val) {
			cn_domain_err(domain_set, "MIM mode enable failed, destroy mlu instance err, domain_id:%u",
					domain_id);
			goto err;
		}

		if (unlikely(ret < 0)) {
			cn_domain_err(domain_set, "dm_rpc_destroy_mlu_instance err");
			goto err;
		}
	}

	domain_set->mim_enable = 1;
	mutex_unlock(&domain_set->mim_lock);
	return 0;

err:
	mutex_unlock(&domain_set->mim_lock);
	return -1;
}

static int cn_dm_disactivate_mim_mode(struct cn_core_set *core)
{
	struct domain_set_type *domain_set;

	if (!core)
		return -OTHER_ERR;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -OTHER_ERR;

	if (!cn_dm_is_mim_support(core)) {
		cn_domain_err(domain_set, "mim mode is not support");
		return -EACCES;
	}

	mutex_lock(&domain_set->mim_lock);
	if (!(domain_set->mim_enable)) {
		cn_domain_err(domain_set, "MIM mode not enabled, disable failed");
		mutex_unlock(&domain_set->mim_lock);
		return -EACCES;
	}

	if (domain_set->mlu_instance_mask != 0) {
		cn_domain_err(domain_set, "mlu instance mask:%u, MIM mode disable failed",
				domain_set->mlu_instance_mask);
		mutex_unlock(&domain_set->mim_lock);
		return -EBUSY;
	}

	domain_set->mim_enable = 0;
	mutex_unlock(&domain_set->mim_lock);
	return 0;
}

int cn_dm_is_sriov_enable(struct cn_core_set *core)
{
	struct cn_bus_set *bus_set;

	if (!core)
		return -1;

	bus_set = core->bus_set;
	if (!bus_set || !bus_set->ops || !bus_set->ops->is_sriov_enable)
		return -1;

	return bus_set->ops->is_sriov_enable(bus_set->priv);
}

int cn_dm_enable_sriov(struct cn_core_set *core)
{
	int max_vf, ret;
	struct cn_bus_set *bus_set;
	struct domain_set_type *domain_set;

	if (!core)
		return -OTHER_ERR;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -OTHER_ERR;

	if (!cn_dm_is_mim_support(core)) {
		cn_domain_err(domain_set, "mim mode is not support");
		return -EUNSUP;
	}

	mutex_lock(&domain_set->mim_lock);
	if (domain_set->mlu_instance_mask != 0) {
		cn_domain_err(domain_set, "destroy all created MIs before enable SR-IOV");
		ret = -EBUSY;
		goto err;
	}

	if (cn_dm_is_sriov_enable(core)) {
		cn_domain_err(domain_set, "sriov mode already enabled");
		ret = -ESAON;
		goto err;
	}

	max_vf = domain_set_attr_get_max_vf(domain_set);
	if (max_vf < 0) {
		cn_domain_err(domain_set, "invalid max_vf:%d", max_vf);
		ret = -OTHER_ERR;
		goto err;
	}

	bus_set = core->bus_set;
	if (!bus_set || !bus_set->ops || !bus_set->ops->enable_sriov) {
		ret = -OTHER_ERR;
		goto err;
	}

	ret = bus_set->ops->enable_sriov(bus_set->priv, max_vf);
	mutex_unlock(&domain_set->mim_lock);
	if (ret) {
		ret = -OTHER_ERR;
		return ret;
	}

	ret = cn_dm_activate_mim_mode(core);
	if (ret)
		ret = -OTHER_ERR;

	return ret;

err:
	mutex_unlock(&domain_set->mim_lock);
	return ret;
}

int cn_dm_disable_sriov(struct cn_core_set *core)
{
	struct cn_bus_set *bus_set;
	struct domain_set_type *domain_set;
	int ret;

	if (!core)
		return -OTHER_ERR;

	ret = cn_dm_disactivate_mim_mode(core);
	if (ret)
		return ret;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -OTHER_ERR;

	if (!cn_dm_is_mim_support(core)) {
		cn_domain_err(domain_set, "mim mode is not support");
		return -EACCES;
	}

	mutex_lock(&domain_set->mim_lock);
	if (domain_set->mim_enable) {
		ret = -EACCES;
		goto err;
	}

	if (!cn_dm_is_sriov_enable(core)) {
		cn_domain_err(domain_set, "sriov mode is not enabled");
		ret = -EACCES;
		goto err;
	}

	bus_set = core->bus_set;
	if (!bus_set || !bus_set->ops || !bus_set->ops->disable_sriov) {
		ret = -OTHER_ERR;
		goto err;
	}

	ret = bus_set->ops->disable_sriov(bus_set->priv);
	if (ret)
		ret = -OTHER_ERR;

	mutex_unlock(&domain_set->mim_lock);
	return ret;

err:
	mutex_unlock(&domain_set->mim_lock);
	return ret;
}

int cn_dm_query_mlu_instance_possible_placement(struct cn_core_set *core,
				unsigned int profile_id, int *count,
				struct mlu_instance_placement *placement)
{
	u32 size;
	unsigned long placement_mask;
	int ret, ret_len, i, instance_idx;
	struct domain_set_type *domain_set;
	struct mlu_instance_placement_info info;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	if (!cn_dm_is_mim_support(core)) {
		cn_domain_err(domain_set, "mim mode is not support");
		return -1;
	}

	ret = dm_compat_rpc(domain_set,
			"dm_rpc_query_instance_profiles_possible_placement",
			&profile_id, sizeof(profile_id), &info,
			&ret_len, sizeof(struct mlu_instance_placement_info));
	if (ret < 0) {
		cn_domain_err(domain_set,
			"dm_rpc_query_instance_profiles_possible_placement failed");
		return -1;
	}

	placement_mask = info.placement_mask;
	size = info.size;
	instance_idx = 0;
	for_each_set_bit(i, &placement_mask, sizeof(u32) * BITS_PER_U8)
	{
		placement[instance_idx].start = i;
		placement[instance_idx].size = size;
		instance_idx++;
	}

	*count = instance_idx;

	return 0;
}

int cn_dm_query_profile_total_mlu_instance_num(struct cn_core_set *core,
				unsigned int profile_id)
{
	int ret, ret_len, num;
	struct domain_set_type *domain_set;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	if (!cn_dm_is_mim_support(core)) {
		cn_domain_err(domain_set, "mim mode is not support");
		return -1;
	}

	ret = dm_compat_rpc(domain_set,
			"dm_rpc_query_profile_total_instance_num",
			&profile_id, sizeof(profile_id), &num,
			&ret_len, sizeof(num));
	if (ret < 0) {
		cn_domain_err(domain_set,
			"dm_rpc_query_profile_total_instance_num failed");
		return -1;
	}

	return num;
}

int cn_dm_query_profile_available_mlu_instance_num(struct cn_core_set *core,
				unsigned int profile_id)
{
	int ret, ret_len, num;
	struct domain_set_type *domain_set;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	if (!cn_dm_is_mim_support(core)) {
		cn_domain_err(domain_set, "mim mode is not support");
		return -1;
	}

	ret = dm_compat_rpc(domain_set,
			"dm_rpc_query_profile_available_instance_num",
			&profile_id, sizeof(profile_id), &num,
			&ret_len, sizeof(num));
	if (ret < 0) {
		cn_domain_err(domain_set,
			"dm_rpc_query_profile_available_instance_num failed");
		return -1;
	}

	return num;
}

int cn_dm_query_mlu_instance_info(struct cn_core_set *core,
				unsigned int mlu_instance_id,
				struct mlu_instance_info *instance_info)
{
	int ret, ret_len, domain_id;
	struct domain_set_type *domain_set;
	struct cn_bus_set *bus_set;
	struct pci_bdf_info_s bdf_info;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	if (!domain_set->mim_enable) {
		cn_domain_err(domain_set, "MIM mode is not enabled, can't query mlu instance info");
		return -1;
	}

	domain_id = mlu_instance_id;
	instance_info->domain_nr = 0;
	ret = dm_compat_rpc(domain_set,
			"dm_rpc_query_mlu_instance_info",
			&domain_id, sizeof(domain_id), instance_info,
			&ret_len, sizeof(*instance_info));
	if (ret < 0) {
		cn_domain_debug(domain_set,
			"dm_rpc_query_mlu_instance_info failed");
		return -1;
	}

	bus_set = core->bus_set;
	if (!bus_set || !bus_set->ops ||
				!bus_set->ops->get_pci_virtfn_bdf_info)
		return -1;

	bus_set->ops->get_pci_virtfn_bdf_info(bus_set->priv,
						domain_id, &bdf_info);
	instance_info->mlu_instance_id = mlu_instance_id;
	instance_info->domain_nr = bdf_info.domain_nr;
	instance_info->bus_num = bdf_info.bus_num;
	instance_info->devfn = bdf_info.devfn;
	sprintf(instance_info->device_name, "/dev/cambricon-caps/cap_dev%d_mi%d",
				core->pf_idx, mlu_instance_id);
	sprintf(instance_info->ipcm_device_name, "/dev/cambricon_ipcm%d",
				core->pf_idx);

	return 0;
}

int cn_dm_query_all_mlu_instance_info(struct cn_core_set *core, int *count,
				struct mlu_instance_info *instance_info)
{
	struct domain_set_type *domain_set;
	int max_mim_device_count, i, k, ret;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	if (!domain_set->mim_enable) {
		cn_domain_err(domain_set, "MIM mode is not enabled, can't query all mlu instance info");
		return -1;
	}

	max_mim_device_count = cn_dm_query_max_mim_device_count(core);
	k = 0;
	for (i = 1; i <= max_mim_device_count; i++) {
		ret = cn_dm_query_mlu_instance_info(core, i, instance_info + k);
		if (!ret)
			k++;
	}

	*count = k;

	return 0;
}

int cn_dm_query_mlu_instance_mask(struct cn_core_set *core, u32 *mlu_instance_mask)
{
	struct domain_set_type *domain_set;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	if (!domain_set->mim_enable)
		return -1;

	*mlu_instance_mask = domain_set->mlu_instance_mask;

	return 0;
}

int cn_dm_query_onhost_mlu_instance_mask(struct cn_core_set *core, u32 *mlu_instance_mask)
{
	struct domain_set_type *domain_set;
	int domain_id;
	u32 val = 0;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	if (!domain_set->mim_enable) {
		cn_domain_err(domain_set, "MIM mode is not enabled, can't query on host mlu_instance_mask");
		return -1;
	}

	for_each_set_bit(domain_id, (unsigned long *)&domain_set->mlu_instance_mask,
			sizeof(domain_set->mlu_instance_mask) * BITS_PER_U8) {
		if (cn_core_get_mi_core(core->pf_idx, domain_id))
			val |= (0x1u << domain_id);
	}

	*mlu_instance_mask = val;
	return 0;
}

int cn_dm_query_max_mim_device_count(struct cn_core_set *core)
{
	struct domain_set_type *domain_set;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	if (!cn_dm_is_mim_support(core)) {
		cn_domain_err(domain_set, "mim mode is not support");
		return -1;
	}

	return domain_set_attr_get_max_vf(domain_set);
}

int cn_dm_query_mlu_instance_profile_info(struct cn_core_set *core,
						enum mlu_instance_profile profile,
						struct mlu_instance_profile_info *info)
{
	struct domain_set_type *domain_set;
	int ret, ret_len;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	if (!cn_dm_is_mim_support(core)) {
		cn_domain_err(domain_set, "mim mode is not support");
		return -1;
	}

	ret = dm_compat_rpc(domain_set, "dm_rpc_query_mlu_instance_profile_info",
					&profile, sizeof(enum mlu_instance_profile), info,
					&ret_len, sizeof(struct mlu_instance_profile_info));
	if (ret < 0) {
		cn_domain_info(domain_set, "query mlu instance profile info rpc failed, profile:%d", profile);
		return -1;
	}

	if (info->ipu_num < 0)
		return 1;

	/* due to not support gdma, info write to 0 */
	if (core->device_id == MLUID_590 || core->device_id == MLUID_585)
		info->gdma_num = 0;

	return 0;
}

bool cn_dm_is_mim_mode_enable(struct cn_core_set *core)
{
	struct domain_set_type *domain_set;

	if (!core)
		return false;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return false;

	if (!cn_dm_is_mim_support(core))
		return false;

	return domain_set->mim_enable;
}

int cn_dm_create_mlu_instance(struct cn_core_set *core, unsigned int profile_id)
{
	struct domain_set_type *domain_set;
	int ret, domain_id, ret_len, i;
	struct cn_core_set *core_set;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	mutex_lock(&domain_set->mim_lock);
	if (!domain_set->mim_enable) {
		cn_domain_err(domain_set, "MIM mode is not enabled, can't create mlu instance");
		goto err;
	}

	ret = dm_compat_rpc(domain_set,
			"dm_rpc_create_mlu_instance",
			&profile_id, sizeof(unsigned int), &domain_id,
			&ret_len, sizeof(int));
	if (unlikely(ret < 0)) {
		cn_domain_err(domain_set, "dm_rpc_create_mlu_instance err");
		goto err;
	}

	if (domain_id < 0) {
		cn_domain_err(domain_set, "create mlu instance failed, profile_id:%u", profile_id);
		goto err;
	}

	ret = cn_bus_probe_mi(core->bus_set, domain_id);
	if (ret) {
		cn_domain_err(domain_set, "cn_bus_probe_mi%d failed\n", domain_id);
		goto err;
	}

	for (i = 0; i < 1000; i++) {
		core_set = cn_core_get_mi_core(core->pf_idx, domain_id);
		if (core_set && core_set->state == CN_RUNNING)
			break;

		msleep(1);
	}

	if (!core_set || core_set->state != CN_RUNNING) {
		cn_domain_err(domain_set, "mlu instance init time out");
		goto err;
	}

	domain_set->mlu_instance_mask |= (0x1u << domain_id);
	mutex_unlock(&domain_set->mim_lock);
	return domain_id;

err:
	mutex_unlock(&domain_set->mim_lock);
	return -1;
}

int cn_dm_create_mlu_instance_with_placement(struct cn_core_set *core,
					unsigned int profile_id, unsigned int start)
{
	struct domain_set_type *domain_set;
	struct cn_core_set *core_set;
	int ret, domain_id, ret_len, i;
	u64 val;

	if (!core)
		return -1;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -1;

	mutex_lock(&domain_set->mim_lock);
	if (!domain_set->mim_enable) {
		cn_domain_err(domain_set, "MIM mode is not enabled, can't create mlu instance");
		goto err;
	}

	val = start;
	val <<= 32;
	val |= profile_id;
	ret = dm_compat_rpc(domain_set,
			"dm_rpc_create_mlu_instance_with_placement",
			&val, sizeof(u64), &domain_id,
			&ret_len, sizeof(int));
	if (unlikely(ret < 0)) {
		cn_domain_err(domain_set, "dm_rpc_create_mlu_instance_with_placement err");
		goto err;
	}

	if (domain_id < 0) {
		cn_domain_err(domain_set, "create mlu instance with placement failed, profile_id:%u, start:%u", profile_id, start);
		goto err;
	}

	ret = cn_bus_probe_mi(core->bus_set, domain_id);
	if (ret) {
		cn_domain_err(domain_set, "cn_bus_probe_mi%d failed\n", domain_id);
		goto err;
	}

	for (i = 0; i < 1000; i++) {
		core_set = cn_core_get_mi_core(core->pf_idx, domain_id);
		if (core_set && core_set->state == CN_RUNNING)
			break;

		msleep(1);
	}

	if (!core_set || core_set->state != CN_RUNNING) {
		cn_domain_err(domain_set, "mlu instance init time out");
		goto err;
	}

	domain_set->mlu_instance_mask |= (0x1u << domain_id);
	mutex_unlock(&domain_set->mim_lock);
	return domain_id;

err:
	mutex_unlock(&domain_set->mim_lock);
	return -1;
}

int cn_dm_destroy_mlu_instance(struct cn_core_set *core, unsigned int mlu_instance_id)
{
	struct domain_set_type *domain_set;
	struct cn_core_set *mi_core;
	int ret, ret_len, ret_val;
	u32 domain_id;
	struct domain_type *domain;

	if (!core)
		return -OTHER_ERR;

	domain_set = (struct domain_set_type *)core->domain_set;
	if (!domain_set)
		return -OTHER_ERR;

	mutex_lock(&domain_set->mim_lock);
	if (!domain_set->mim_enable) {
		cn_domain_err(domain_set, "MIM mode is not enabled, can't destroy mlu instance");
		ret = -OTHER_ERR;
		goto err;
	}

	if (!(domain_set->mlu_instance_mask & (0x1u << mlu_instance_id))) {
		cn_domain_err(domain_set, "mlu_instance_id:%u err, destroy failed\n", mlu_instance_id);
		ret = -MI_ID_ERR;
		goto err;
	}

	domain_id = mlu_instance_id;
	domain = cn_dm_get_domain(core, domain_id);
	if (!domain) {
		cn_domain_err(domain_set, "domain %u not exist", domain_id);
		ret = -MI_ID_ERR;
		goto err;
	}

	mi_core = cn_core_get_mi_core(core->pf_idx, domain_id);
	if (!mi_core) {
		cn_domain_err(domain_set,
				"detach device frome other driver first, destroy mi%d failed",
				domain_id);
		ret = -MI_ON_USE;
		goto err;
	}

	if (mi_core->open_count) {
		cn_domain_err(domain_set, "mi %d is busy, destroy failed", domain_id);
		ret = -MI_ON_USE;
		goto err;
	}

	cn_bus_remove_mi(core->bus_set, domain_id);
	if (domain->state != DM_STATE_DEFINED) {
		cn_domain_err(domain_set, "domain %u state is %d, can not be destroy",
						domain_id, domain->state);
		ret = -OTHER_ERR;
		goto err;
	}

	ret = dm_compat_rpc(domain_set,
			"dm_rpc_destroy_mlu_instance",
			&domain_id, sizeof(u32), &ret_val,
			&ret_len, sizeof(int));
	if (unlikely(ret < 0)) {
		cn_domain_err(domain_set, "dm_rpc_destroy_mlu_instance err");
		ret = -OTHER_ERR;
		goto err;
	}

	if (ret_val < 0) {
		cn_domain_err(domain_set, "destroy mlu instance failed");
		ret = -OTHER_ERR;
		goto err;
	}

	domain_set->mlu_instance_mask &= ~(0x1u << domain_id);
	mutex_unlock(&domain_set->mim_lock);
	return 0;

err:
	mutex_unlock(&domain_set->mim_lock);
	return ret;
}

#if 0
/* test code */
int mim_test(struct cn_core_set *core)
{
	int profile_num, pi_num[10];
	int i, k, j, t;
	int ret_val;
	struct pi_info_s pi_info;
	enum pi_status_e pi_status;
	struct domain_set_type *domain_set;
	int domain_id;

	domain_set = (struct domain_set_type *)core->domain_set;
	profile_num = dm_query_profile_num(core);
	cn_domain_info(domain_set, "profile_num is %d", profile_num);
	for (i = 0; i < profile_num; i++)
		pi_num[i] = dm_query_pi_profile_num_by_id(core, i);

	for (i = 0; i < profile_num; i++) {
		for (k = 0; k < pi_num[i]; k++) {
			ret_val = dm_query_pi_info_by_id(core, i, k, &pi_info);
			cn_domain_info(domain_set, "profile:%d, index:%d, ipu_mask:%llx, mem_size:%llx, ret:%d, ret_val:%d",
					i, k, pi_info.ipu_mask, pi_info.mem_size, pi_info.ret, ret_val);
			ret_val = dm_query_profile_pi_status(core, i, k, &pi_status);
			cn_domain_info(domain_set, "pi_status:%d, ret_val:%d", pi_status, ret_val);
		}
	}

	for (i = 0; i < profile_num; i++) {
		for (k = 0; k < pi_num[i]; k++) {
			domain_id = dm_alloc_pi_by_profile_id(core, i, k);
			if (domain_id < 0)
				break;
			cn_domain_info(domain_set, "alloc pi domain id:%d", domain_id);
			for (j = 0; j < profile_num; j++) {
				for (t = 0; t < pi_num[j]; t++) {
					ret_val = dm_query_profile_pi_status(core, j, t, &pi_status);
					cn_domain_info(domain_set, "profile_id:%d, index:%d, pi_status:%d, ret_val:%d",
							j, t, pi_status, ret_val);
				}
			}
			dm_release_pi_by_domain_id(core, domain_id);
		}
	}

	return 0;
}
#endif
