#include "cndrv_bus.h"
#include "cndrv_commu.h"
#include "cndrv_domain.h"
#include "dmlib/domain_resource_dictionary.h"
#include "cndrv_ipcm.h"
#include "cndrv_xid.h"

static void *__dm_open_channel(struct cn_core_set *core, char *name)
{
	void *handle = NULL;

	if (core->support_ipcm) {
		handle = (void *)ipcm_open_channel(core, name);
		if (handle == NULL) {
			cn_xid_err(core, XID_RPC_ERR, "ipcm_open_channel(%s) failed", name);
		}
	} else {
		struct commu_channel *channel = commu_open_a_channel(name, core, 0);

		handle = (void *)connect_rpc_endpoint(channel);
		if (handle == NULL) {
			cn_xid_err(core, XID_RPC_ERR, "connect_rpc_endpoint(%s) failed", name);
		}
	}

	return handle;
}

static void __dm_destroy_channel(struct cn_core_set *core, void **ept)
{
	if (*ept == NULL) {
		return;
	}

	if (core->support_ipcm) {
		ipcm_destroy_channel((struct rpmsg_device *)*ept);
		*ept = NULL;
	} else {
		disconnect_endpoint((struct commu_endpoint *)*ept);
		*ept = NULL;
	}
}

s32 dm_build_rpc_connection(struct cn_core_set *core)
{
	struct domain_set_type *set = (struct domain_set_type *)core->domain_set;

	set->ep_rpc = __dm_open_channel(core, "domain");
	if (IS_ERR_OR_NULL(set->ep_rpc)) {
		pr_err("__dm_open_channel() for domain failed\n");

		return -EFAULT;
	}

	pr_info("cn_dm_rpc_init() success\n");

	return 0;
}

void dm_destroy_rpc_connection(struct cn_core_set *core)
{
	struct domain_set_type *set = (struct domain_set_type *)core->domain_set;

	__dm_destroy_channel(core, &set->ep_rpc);
}

s32 dm_compat_rpc(void *domain_set, char *name,
		void *in, int in_size, void *out, int *out_size, s32 buf_sz)
{
	struct domain_set_type *set = domain_set;
	struct cn_core_set *core = set->core;

	if (core->support_ipcm) {
		return ipcm_rpc_call((struct rpmsg_device *)set->ep_rpc, name,
			in, in_size, out, out_size, buf_sz);
	} else {
		return commu_call_rpc((struct commu_endpoint *)set->ep_rpc, name, in, in_size, out, out_size);
	}
}

int dm_queue_rpc(struct domain_set_type *set, char *cmd, char *msg)
{
	char tmp[COMMU_RPC_SIZE];
	int out = 0;

	cn_domain_debug(set, "rpc<%s:%s>", cmd, msg);
	memset(tmp, 0, sizeof(tmp));
	dm_compat_rpc((void *)set, cmd, msg, strlen(msg) + 1, tmp, &out, sizeof(tmp));
	cn_domain_debug(set, "return<%d: %s>", out, tmp);
	if (dm_is_rpc_ok(tmp))
		return 0;

	return -1;
}

int dm_rpc_set_domain_set_daemon_state(
			struct domain_set_type *set, unsigned long attr)
{
	char tmp[COMMU_RPC_SIZE];
	int ret = -1;
	int ret_size;

	memset(tmp, 0, COMMU_RPC_SIZE);
	ret = dm_compat_rpc((void *)set, "dm_rpc_set_domain_set_daemon_state", &attr,
			sizeof(unsigned long), tmp, &ret_size, sizeof(tmp));
	cn_domain_debug(set, "return<%d, %s>", ret_size, tmp);
	if (dm_is_rpc_ok(tmp)) {
		cn_domain_info(set, "rpc set domain and set daemon state ok");
		return 0;
	}

	return -1;
}

static inline s32 suture_one_module(s32 *len, s32 mod_idx,
			s32 start_res_offset, s8 res_offset[],
			s8 *res_table[], s8 a_module_res[], s8 *msg)
{
	s32 j, res_idx;
	s8 *mod_str;

	for (j = start_res_offset; a_module_res[j] != -1; j++) {
		res_idx = a_module_res[j];
		get_resource_string(mod_idx, res_idx,
				&res_table[j - start_res_offset]);
	}

	res_table[j - start_res_offset] = NULL;
	get_module_string(mod_idx, &mod_str);
	print_debug("mod_str %s len=%d\n", mod_str, *len);
	return _dm_resource_suture(mod_str, res_table, NULL, msg,
						len, res_offset);
}

#define supported_max_res_num 4
static s32 dm_rpc_get_one_module_resource(struct domain_set_type *set,
		s32 mod_idx, s8 a_module_res[], s8 res_offset[],
		s32 start_res_offset, s8 *buf, s32 *len)
{
	s8 *rpc_name = "dm_rpc_get_resource";
	s32 ret, len_tmp, sutured_res;
	s8 *res_table[supported_max_res_num + 1], *msg;

	msg = buf + sizeof(struct dm_rpc_res_head);
	len_tmp = *len - sizeof(struct dm_rpc_res_head);
	ret = suture_one_module(&len_tmp, mod_idx, start_res_offset,
			res_offset, res_table, a_module_res, msg);
	if (ret < 0) {
		sutured_res = (-ret + 1);
		print_debug("mod_idx=%d len_tmp=%d, start_res_id=%d\n",
			    mod_idx, len_tmp, start_res_offset);
	} else if (ret == 0 && len_tmp > 0) {
		sutured_res = 1;
		print_debug("sutured_res=%d len_tmp=%d 00start_res=%d\n",
			    sutured_res, len_tmp, start_res_offset);
	} else if (ret > 0) {
		sutured_res = (ret + 1);
	} else {
		print_warn("nothing sutured mod_idx=%d start_res=%d\n",
			    mod_idx, start_res_offset);
		return 0;
	}
	dm_rpc_res_head_set_size(buf, len_tmp);
	print_debug("rpc len_tmp=%d msg %s\n", len_tmp, msg);
	ret = dm_compat_rpc((void *)set, rpc_name, buf,
			len_tmp + sizeof(struct dm_rpc_res_head),
			buf, len, *len);
	if (!memcmp(buf, "no func found", sizeof("no func found"))) {
		print_warn("dm_rpc_get_resource does exist, skip it.\n");
		return -1;
	}
	ret = dm_rpc_res_head_get_ret(buf);
	if (ret < 0 || ret > sutured_res) {
		print_err("BUG ret=%d\n", ret);
		return -1;
	}
	*len -= sizeof(struct dm_rpc_res_head);
	print_debug("msg ret=%d sz=%d\n", ret, dm_rpc_res_head_get_size(buf));
	return ret;
}

static s32 dm_parse_one_module_all_resource_value(s8 *msg, s32 len,
			u64 res_val[], s32 start_res_offset, s8 res_offset[])
{
	s8 *head = NULL;
	s32 ret, j = 0, mod_idx, res_idx, len_left = len, len_tmp = len;

	do {
		ret = _dm_parse_resource_value(msg, &len_tmp,
				&res_val[start_res_offset + j],
				&mod_idx, &res_idx, &head);
		len_left -= len_tmp;
		print_debug
		    ("parse mod=%d res=%d start_res=%d val=0x%llx msg %s\n",
			mod_idx, res_idx, start_res_offset,
			res_val[start_res_offset + j], msg);
		print_debug
		    ("len=%d len_tmp=%d len_lft=%d\n", len, len_tmp, len_left);
		if (ret != res_offset[start_res_offset + j] || len_left < 0) {
			print_err("BUG j=%d mod_idx=%d res_idx=%d",
				   j, mod_idx, res_idx);
			if (ret != res_offset[start_res_offset + j])
				print_err
				  ("BUG res_offset not fit %d %d, msg %s\n",
				   ret, res_offset[start_res_offset + j], msg);

			return -1;
		}
		msg += len_tmp;
		j++;
	} while (len_left > 0);
	return j;
}

#define buf_sz COMMU_RPC_SIZE
s32 dm_rpc_get_resource_host(struct domain_set_type *set, u64 *res_val[],
			const struct dm_resource_discriptor *res_set,
			s8 *res_offset[], s32 max_res_num,
			struct domain_type *target_domain)
{
	s32 mod_idx, i, finished_res_num;
	s32 ret, len_tmp, start_res_offset = 0;
	s8 *msg, buf[buf_sz + 1];
	u32 target_funcid = target_domain->func_id;
	/* TODO: fix this hard code after comfirm if stack is overflow */
	if (max_res_num > supported_max_res_num + 1) {
		print_err("can not handle set max res %d > 3\n", max_res_num);
		return -1;
	}
	for (i = 0; res_set[i].mod_idx != -1; i++) {
		mod_idx = res_set[i].mod_idx;
		start_res_offset = 0;
current_module_need_more_rpc:
		dm_rpc_res_head_set_version(buf, DM_VERSION_CUR);
		dm_rpc_res_head_set_funcid(buf, target_funcid);
		finished_res_num = 0;
		len_tmp = buf_sz;
		ret = dm_rpc_get_one_module_resource(set, mod_idx,
			res_set[i].res, res_offset[i], start_res_offset,
			buf, &len_tmp);
		if (!(ret > 0)) {
			print_err("fail get res mod=%d start_res=%d ret=%d",
				  mod_idx, start_res_offset, ret);
			return -1;
		}
		finished_res_num = ret;
		/* some resource send back */
		msg = buf + sizeof(struct dm_rpc_res_head);
		ret = dm_parse_one_module_all_resource_value(msg, len_tmp,
				res_val[i], start_res_offset, res_offset[i]);
		if (ret != finished_res_num) {
			print_err("fail get res mod=%d start_res=%d ret=%d finished_res_num=%d",
				  mod_idx, start_res_offset, ret,
				  finished_res_num);
			return -1;
		}

		print_debug("res_set[%d].res[%d + %d]=%d\n", i,
			   res_set[i].res[finished_res_num + start_res_offset],
			   finished_res_num, start_res_offset);
		if (res_set[i].res[finished_res_num + start_res_offset] != -1) {
			print_debug("need_more rpc %d",
				     finished_res_num + start_res_offset);
			start_res_offset += finished_res_num;
			goto current_module_need_more_rpc;
		}
	}
	return 0;
}

s32 dm_rpc_set_resource_host(struct domain_set_type *set, struct domain_type *domain,
				struct domain_type *target_domain,
				const struct dm_resource_discriptor *res_set,
				s8 *res_offset[], s32 max_res_num)
{
	s8 *rpc_name = "dm_rpc_set_resource";
	s8 buf[buf_sz];
	s32 len_left = buf_sz, len_tmp, len_rpc, len_ret;
	u64 val_table[supported_max_res_num];
	s8 *res_table[supported_max_res_num + 1];
	s32 ret, mod_idx, res_idx = 0, seq, i, j, i_continue, j_continue;
	s8 *mod_str, *msg;
	s32 need_recall = 0, need_suture = 0;
	u32 target_funcid;

	i_continue = 0;
	j_continue = 0;
	seq = 0;
	/* TODO: fix this hard code after comfirm if stack is overflow */
	if (max_res_num > supported_max_res_num) {
		print_err("can not handle set max res %d > 3\n", max_res_num);
		return -1;
	}
	target_funcid = target_domain->func_id;
need_recall_rpc:
	dm_rpc_res_head_set_funcid(buf, target_funcid);
	len_rpc = 0;
	msg = buf + sizeof(struct dm_rpc_res_head);
	len_left = buf_sz - sizeof(struct dm_rpc_res_head);
	need_recall = 0;
	for (i = i_continue; res_set[i].mod_idx != -1; i++) {
		mod_idx = res_set[i].mod_idx;
		j = j_continue;
		need_suture = 0;
		for (j = j_continue; res_set[i].res[j] != -1; j++) {
			if (j > max_res_num) {
				print_err("res num overflow mod_idx=%d j=%d\n",
								 mod_idx, j);
				return 0;
			}
			need_suture = 1;
			res_idx = res_set[i].res[j];
			get_resource_value(domain, mod_idx, res_idx,
				&val_table[j - j_continue],
				res_offset[i][j - j_continue], target_domain);
			get_resource_string(mod_idx, res_idx,
				&res_table[j - j_continue]);
			print_debug("rpc<%s> mod_idx=%d res_idx =%d res_val<0x%llx> res_str<%s>\n",
				     rpc_name, mod_idx, res_idx,
				     val_table[j - j_continue],
				     res_table[j - j_continue]);
		}
		if (need_suture == 0)
			continue;

		res_table[j - j_continue] = NULL;
		get_module_string(mod_idx, &mod_str);
		len_tmp = len_left;
		ret = _dm_resource_suture(mod_str, res_table, val_table, msg,
						&len_tmp, res_offset[i]);
		print_debug("rpc<%s> mod_idx=%d res_idx =%d len_tmp=%d len_left=%d mod_str<%s> msg<%s>\n",
			     rpc_name, mod_idx, res_idx, len_tmp, len_left,
			     mod_str, msg);
		if (ret < 0) {
			i_continue = i;
			seq += (-ret + 1);
			j_continue += (-ret + 1);
			len_rpc += len_tmp;
			len_left -= len_tmp;
			need_recall = 1;
			print_debug("rpc<%s> i=%d j=%d i_c=%d j_c=%d seq=%d len_rpc=%d len_left=%d len_tmp=%d need_recall=%d\n",
				    rpc_name, i, j, i_continue, j_continue, seq,
				    len_rpc, len_left, len_tmp, need_recall);
			break;
		} else if (ret == 0) {
			if (len_tmp == 0) {
				print_err("nothing sutured togather mod_idx=%d res number %d seq %d\n",
					   mod_idx, j, seq);
				return seq;
			}
			i_continue = i;
			seq++;
			j_continue++;
			len_rpc += len_tmp;
			len_left -= len_tmp;
			need_recall = 1;
			print_debug("rpc<%s> i=%d j=%d i_c=%d j_c=%d seq=%d len_rpc=%d len_left=%d len_tmp=%d 00need_recall=%d\n",
				     rpc_name, i, j, i_continue,
				     j_continue, seq, len_rpc,
				     len_left, len_tmp, need_recall);
			break;
		}
		/* suture more */
		len_rpc += len_tmp;
		len_left -= len_tmp;
		msg += len_rpc;
		seq += (ret + 1);
		j_continue = 0;
		need_recall = 0;
		print_debug("rpc<%s> i=%d j=%d i_c=%d j_c=%d seq=%d len_rpc=%d len_left=%d len_tmp=%d noneed_recall=%d\n",
		      rpc_name, i, j, i_continue, j_continue, seq,
		      len_rpc, len_left, len_tmp, need_recall);
	}
	if (need_suture == 0)
		return seq;

	dm_rpc_res_head_set_size(buf, len_rpc);
	len_rpc += sizeof(struct dm_rpc_res_head);

	ret = dm_compat_rpc((void *)set, rpc_name, buf, len_rpc, buf, &len_ret,
								sizeof(buf));
	print_debug("rpc<%s: %d> ret %d return<%d: %s>\n", rpc_name, len_rpc,
							ret, len_ret, buf);
	if (!memcmp(buf, "no func found", sizeof("no func found"))
	    || !memcmp(buf, "fail", sizeof("fail"))) {
		print_warn("dm_rpc_set_resource does exist, skip it.\n");
		return -1;
	}

	ret = dm_rpc_res_head_get_ret(buf);
	if (ret != seq) {
		print_err("fail on dm_rpc_set_resource ret=%d seq=%d.\n",
								ret, seq);
		return -1;
	}
	if (need_recall)
		goto need_recall_rpc;

	return seq;
}
