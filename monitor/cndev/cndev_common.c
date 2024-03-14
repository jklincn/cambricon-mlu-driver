#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/ioctl.h>
#include <linux/pid_namespace.h>
#include "../camb_pmu_rpc.h"
#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"
#include "cndrv_mcu.h"
#include "cndrv_mcc.h"
#include "../../core/version.h"
#include "cndrv_commu.h"

#include "cndev_server.h"
#include "../monitor.h"
#include "cndrv_xid.h"
#include "cndrv_monitor.h"
#include "cndrv_monitor_usr.h"
#include "cndrv_ipcm.h"
#include "cndrv_smlu.h"
#include "cndrv_cap.h"
#include "cndrv_attr.h"
#include "cndrv_domain.h"
#include "cndev_rpc_info.h"

#define CNDEV_MAX_ECC_NUM ((IPU_LOCATION_NUM) + (TNC_LOCATION_NUM) + \
	(PCIE_LOCATION_NUM) + (SMMU_LOCATION_NUM) + (LLC_LOCATION_NUM) + (NCS_LOCATION_NUM))

#define IPU_LOC_OF (0)
#define TNC_LOC_OF ((IPU_LOC_OF) + (IPU_LOCATION_NUM))
#define PCIE_LOC_OF ((TNC_LOC_OF) + (TNC_LOCATION_NUM))
#define SMMU_LOC_OF ((PCIE_LOC_OF) + (PCIE_LOCATION_NUM))
#define LLC_LOC_OF ((SMMU_LOC_OF) + (SMMU_LOCATION_NUM))
#define NCS_LOC_OF ((LLC_LOC_OF) + (LLC_LOCATION_NUM))

extern const u64 device_computing_power[BOARD_MAX][CNDEV_MAX_COMPUTING_POWER_TYPE];

void cndev_check_bus_throughput(struct cn_cndev_set *cndev_set)
{
	struct cn_core_set *core = NULL;
	struct dma_info_s dma_info;

	if (IS_ERR_OR_NULL(cndev_set))
		return;
	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return;

	cn_bus_get_dma_info(core->bus_set, &dma_info);

	cndev_set->bus_throughput.read_data =
		dma_info.dma_data_total[DMA_D2H] -
		cndev_set->bus_throughput.read_last;
	cndev_set->bus_throughput.write_data =
		dma_info.dma_data_total[DMA_H2D] -
		cndev_set->bus_throughput.write_last;
	cndev_set->bus_throughput.read_last =
		dma_info.dma_data_total[DMA_D2H];
	cndev_set->bus_throughput.write_last =
		dma_info.dma_data_total[DMA_H2D];
}

static enum hrtimer_restart cndev_work_hrtimer_common(struct hrtimer *timer)
{
	struct cn_cndev_set *cndev_set;

	cndev_set = container_of(timer, struct cn_cndev_set, hrtimer);

	if (IS_ERR_OR_NULL(cndev_set))
		goto timer_err;

	/*check bus throughput each 20ms*/
	cndev_check_bus_throughput(cndev_set);

	hrtimer_forward_now(timer, cndev_set->time_delay);
	return HRTIMER_RESTART;
timer_err:
	return HRTIMER_NORESTART;
}

int cndev_common_init(struct cn_cndev_set *cndev_set)
{
	cndev_set->time_delay = ktime_set(0, 20 * 1000 * 1000);
	hrtimer_init(&cndev_set->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	cndev_set->hrtimer.function = cndev_work_hrtimer_common;

	cndev_qos_init(cndev_set->core);
	return 0;
}

int cndev_start_common(void *cset)
{
	int in_len = 0;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int ret = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	ret = __pmu_call_rpc(core, cndev_set->endpoint,
			"rpc_cndev_host_start",
			NULL, 0,
			NULL, &in_len, sizeof(int));

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
	}

	hrtimer_start(&cndev_set->hrtimer,
		cndev_set->time_delay,
		HRTIMER_MODE_REL);

	return ret;
}

int cndev_do_exit_common(void *cset)
{
	int in_len = sizeof(int);
	struct cn_cndev_set *cndev_set
			= (struct cn_cndev_set *)cset;
	struct cn_core_set *core
			= (struct cn_core_set *)cndev_set->core;
	int ret = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	hrtimer_cancel(&cndev_set->hrtimer);

	if (core->state == CN_RUNNING) {
		ret = __pmu_call_rpc(core, cndev_set->endpoint,
				"rpc_cndev_do_exit",
				NULL, 0,
				NULL, &in_len, sizeof(int));

		if (ret < 0) {
			cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
		}
	}

	return 0;
}

void card_info_fill_common(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;
	struct cn_board_info *pbrdinfo = &core->board_info;
	struct cndev_card_info *info = &cndev_set->card_static_info;
	struct bus_info_s bus_info;
	struct bus_lnkcap_info lnk_info;
	struct board_info_s brdinfo_rmt;

	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);

	memset(&lnk_info, 0, sizeof(struct bus_lnkcap_info));
	cn_bus_get_lnkcap(core->bus_set, &lnk_info);

	info->head.card = core->idx;
	info->head.version = CNDEV_CURRENT_VER;
	info->head.buf_size = sizeof(struct cndev_card_info);
	info->head.real_size = sizeof(struct cndev_card_info);

	info->mcu_major_ver = pbrdinfo->mcu_info.mcu_major;
	info->mcu_minor_ver = pbrdinfo->mcu_info.mcu_minor;
	info->mcu_build_ver = pbrdinfo->mcu_info.mcu_build;
	info->driver_major_ver = DRV_MAJOR;
	info->driver_minor_ver = DRV_MINOR;
	info->driver_build_ver = DRV_BUILD;

	info->subsystem_id = pbrdinfo->board_type;

	/*get from pci_dev*/
	info->bus_type = bus_info.bus_type;
	info->device_id = bus_info.info.pcie.device;
	info->vendor_id = bus_info.info.pcie.vendor;
	info->subsystem_vendor = bus_info.info.pcie.subsystem_vendor;
	info->domain = bus_info.info.pcie.domain_id;
	info->bus = bus_info.info.pcie.bus_num;
	info->device = (bus_info.info.pcie.device_id >> 3) & 0x1f;
	info->func = bus_info.info.pcie.device_id & 0x07;

	info->ipu_cluster = pbrdinfo->cluster_num;
	info->ipu_core = pbrdinfo->ipu_core_num;

	info->max_speed = lnk_info.speed;
	info->max_width = lnk_info.width;

	info->card_name = core->board_model;
	info->card_sn = pbrdinfo->serial_num;

	strcpy(info->board_model, pbrdinfo->board_model_name);

	info->mother_board_sn = pbrdinfo->BA_serial_num;
	info->mother_board_mcu_fw_ver = pbrdinfo->BA_mcu_fw_ver;
	info->slot_id = pbrdinfo->slot_id;
	info->chip_id = pbrdinfo->chip_id;

	info->qdd_status = pbrdinfo->qdd_status;

	cn_bus_get_pcie_fw_info(core->bus_set, &info->pcie_fw_info);
	/* SOC ID*/
	info->secure_mode = pbrdinfo->secure_mode;
	memcpy(info->soc_id, pbrdinfo->soc_id.soc_id_data, SOC_ID_SIZE);

	/* get info from dev */
	memset(&brdinfo_rmt, 0x0, sizeof(struct board_info_s));
	cndev_rpc_dev_info(cndev_set, &brdinfo_rmt, 0);
	/* mem data width */
	info->data_width = brdinfo_rmt.ddr_bus_width;
	info->bandwidth = brdinfo_rmt.ddr_bandwidth;
	info->bandwidth_decimal = brdinfo_rmt.ddr_bandwidth_decimal;
	memcpy(info->uuid, brdinfo_rmt.uuid, CNDRV_UUID_SIZE);
}

void card_info_fill_vf_common(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;
	struct board_info_s brdinfo_rmt;
	struct cn_board_info *pbrdinfo = &core->board_info;
	struct cndev_card_info *info = &cndev_set->card_static_info;
	struct bus_info_s bus_info;
	struct bus_lnkcap_info lnk_info;

	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);

	memset(&lnk_info, 0, sizeof(struct bus_lnkcap_info));
	cn_bus_get_lnkcap(core->bus_set, &lnk_info);

	info->head.card = core->idx;
	info->head.version = CNDEV_CURRENT_VER;
	info->head.buf_size = sizeof(struct cndev_card_info);
	info->head.real_size = sizeof(struct cndev_card_info);

	info->driver_major_ver = DRV_MAJOR;
	info->driver_minor_ver = DRV_MINOR;
	info->driver_build_ver = DRV_BUILD;

	info->device_id = (core->device_id >> 16) & 0xFFFF;
	/*get from pci_dev*/
	info->bus_type = bus_info.bus_type;
	info->vendor_id = bus_info.info.pcie.vendor;
	info->subsystem_vendor = bus_info.info.pcie.subsystem_vendor;
	info->domain = bus_info.info.pcie.domain_id;
	info->bus = bus_info.info.pcie.bus_num;
	info->device = (bus_info.info.pcie.device_id >> 3) & 0x1f;
	info->func = bus_info.info.pcie.device_id & 0x07;

	info->max_speed = lnk_info.speed;
	info->max_width = lnk_info.width;

	info->card_name = core->board_model;
	info->card_sn = 0;

	strcpy(info->board_model, pbrdinfo->board_model_name);

	cn_dev_core_info(core, "board_model_name %s, board_model %#x",
		info->board_model, core->board_model);

	/* get info from dev */
	memset(&brdinfo_rmt, 0x0, sizeof(struct board_info_s));
	cndev_rpc_dev_info(cndev_set, &brdinfo_rmt, 0);

	info->mcu_major_ver = brdinfo_rmt.mcu_info.mcu_major;
	info->mcu_minor_ver = brdinfo_rmt.mcu_info.mcu_minor;
	info->mcu_build_ver = brdinfo_rmt.mcu_info.mcu_build;

	/*reset core board info version*/
	pbrdinfo->mcu_info.mcu_major = brdinfo_rmt.mcu_info.mcu_major;
	pbrdinfo->mcu_info.mcu_minor = brdinfo_rmt.mcu_info.mcu_minor;
	pbrdinfo->mcu_info.mcu_build = brdinfo_rmt.mcu_info.mcu_build;
	pbrdinfo->chip_id = brdinfo_rmt.chip_id;
	pbrdinfo->serial_num = brdinfo_rmt.sn;
	pbrdinfo->board_type = brdinfo_rmt.board_type;

	pbrdinfo->pci_device_id = bus_info.info.pcie.device_id;
	pbrdinfo->pci_bus_num = bus_info.info.pcie.bus_num;
	pbrdinfo->pci_domain_id = bus_info.info.pcie.domain_id;
	pbrdinfo->pci_mps = bus_info.info.pcie.mps;
	pbrdinfo->pci_mrrs = bus_info.info.pcie.mrrs;

	memcpy(info->uuid, brdinfo_rmt.uuid, CNDRV_UUID_SIZE);

	info->ipu_cluster = brdinfo_rmt.ipu_cluster;
	info->ipu_core = brdinfo_rmt.ipu_core;

	info->card_sn = brdinfo_rmt.sn;

	info->secure_mode = brdinfo_rmt.secure_mode;
	memcpy(info->soc_id, brdinfo_rmt.soc_id, SOC_ID_SIZE);
	/* mem data width */
	info->data_width = brdinfo_rmt.ddr_bus_width;
	info->bandwidth = brdinfo_rmt.ddr_bandwidth;
	info->bandwidth_decimal = brdinfo_rmt.ddr_bandwidth_decimal;
}

int cndev_get_valid_vf_num(void *cset, u16 *num, u16 *mask)
{
	int ret = 0;
	struct cndev_vf_info_s vf_info;
	int result_len = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_get_vf_num",
			NULL, 0,
			(void *)&vf_info, &result_len, sizeof(struct cndev_vf_info_s));
	if (ret < 0) {
		return ret;
	}
	*num = vf_info.vm_num;
	*mask = vf_info.vm_mask;

	return 0;
}

/**
* @brief user want to know some info with card range or domain/vf range,
* 	so we need to inform card that what info we want.
* 	If vcard with (1 - 4) it means user want one domain/vf info.
* 	If vcard with 0 it means user want whole card info even in vf.
* 	sriov check is to inform card that some domain/vf isnt running.
* @param
* @param
* @return
*/
int cndev_vcard_trans(struct cn_cndev_set *cndev_set, u16 *vcard)
{
	u16 vf_num = 0, vf_mask = 0;
	struct cn_core_set *core = (struct cn_core_set *)cndev_set->core;

	if (cn_is_smlu_en(core)) {
		*vcard = 0;
		return 0;
	}

	if (cndev_set->device_id == MLUID_220) {
		*vcard = 0;
		return 0;
	}

	if ((cndev_set->device_id == MLUID_270 ||
				cndev_set->device_id == MLUID_290 ||
				cndev_set->device_id == MLUID_370 ||
				cndev_set->device_id == MLUID_590 ||
				cndev_set->device_id == MLUID_580) &&
				*vcard) {
		if (cndev_get_valid_vf_num(cndev_set, &vf_num, &vf_mask)) {
			vf_num = 0;
		}
		if (!vf_num) {
			cn_dev_cndev_err(cndev_set, "user input error");
			return -EINVAL;
		}
		if (!((0x01 << (*vcard-1)) & vf_mask)) {
			cn_dev_cndev_err(cndev_set, "vf %d not running", *vcard);
			return -EINVAL;
		}
	} else {
		if (cn_core_is_vf(core)) {
			*vcard = 0;
		} else {
			*vcard = 0xff;
		}
	}
	return 0;
}

int cndev_card_health_status_common(void *cset,
			struct cndev_health_state *hstate)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core;
	u8 card_status = CNDEV_CARD_ERROR;
	int result_len = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	hstate->head.version = CNDEV_CURRENT_VER;
	hstate->head.real_size = sizeof(struct cndev_health_state);

	hstate->host_state = core->state;

	if (IS_ERR_OR_NULL(cndev_set->endpoint)) {
		cn_dev_cndev_err(cndev_set, "cndev commu endpoint null");
		hstate->card_state = card_status;
		return 0;
	}

	if (hstate->host_state == CN_RUNNING) {
		ret = __pmu_call_rpc(core, cndev_set->endpoint,
				"rpc_cndev_health_check",
				NULL, 0,
				&card_status, &result_len, sizeof(u8));
		if (ret < 0) {
			cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
			return ret;
		}
	}

	hstate->card_state = card_status;

	return ret;
}

void cndev_proc_info_combine(struct proc_mem_info *mem_info, u32 *num)
{
	u32 proc_num;
	int i, j;

	proc_num = *num;
	for (i = 0; i < proc_num; i++) {
		while ((mem_info[i].pid == mem_info[proc_num-1].pid)
				&& (proc_num > (i + 1))) {
			cn_dev_debug("%d:%d = %d:%d", i, mem_info[i].pid,
					proc_num-1, mem_info[proc_num-1].pid);
			mem_info[i].phy_memused +=
				mem_info[proc_num-1].phy_memused;
			mem_info[i].virt_memused +=
				mem_info[proc_num-1].virt_memused;
			proc_num--;
		}
		if (proc_num == (i + 1)) {
			break;
		}
		for (j = proc_num - 2; j > i; j--) {
			if (mem_info[i].pid == mem_info[j].pid) {
				cn_dev_debug("%d:%d = %d:%d", i, mem_info[i].pid,
						j, mem_info[j].pid);
				mem_info[i].phy_memused +=
					mem_info[j].phy_memused;
				mem_info[i].virt_memused +=
					mem_info[j].virt_memused;
				memcpy(&mem_info[j],
					&mem_info[proc_num-1],
					sizeof(struct proc_mem_info));
				proc_num--;
			}
		}
	}
	*num = proc_num;
}

int cndev_user_proc_info_common(void *cset,
	struct cndev_proc_info *proc_info)
{
	int ret = 0, copy_length = 0, i = 0;
	u32 proc_num;
	struct pid_info_s *pid_info_node = NULL;
	struct pid_info_s tmp;
	struct proc_mem_info *mem_info = NULL;
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u16 smlu_instance_id = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	if (cn_is_smlu_en(core))
		smlu_instance_id = (proc_info->head.card >> 8) & 0xff;

	tmp.tgid = current->tgid;
	tmp.active_ns = task_active_pid_ns(current);
	tmp.active_pid = task_tgid_nr_ns(current, tmp.active_ns);

	proc_info->head.version = CNDEV_CURRENT_VER;
	proc_info->head.real_size = sizeof(struct cndev_proc_info);
	proc_num = core->open_count;
	if (proc_num) {
		mem_info =
			cn_kcalloc(proc_num,
				sizeof(struct proc_mem_info), GFP_KERNEL);
		if (!mem_info) {
			cn_dev_cndev_err(cndev_set, "malloc for buffer fail");
			proc_info->proc_num = 0;
			return -ENOMEM;
		}

		/* try get from smlu first */
		if (cn_is_smlu_en(core)) {
			ret = cn_smlu_query_namespace_pid_infos(core, mem_cgrp_id,
				smlu_instance_id, &proc_num, (struct smlu_proc_info *)mem_info);
			if (ret == -EINVAL || ret == -ESRCH) {
				ret = 0;
				proc_num = 0;
			} else if (ret == 0) {
				for (i = 0; i < proc_num; i++) {
					mem_info[i].phy_memused = mem_info[i].phy_memused >> 10;
					mem_info[i].virt_memused = mem_info[i].virt_memused >> 10;
					cn_dev_cndev_debug(cndev_set, "%d : pid[%d] %lld KB",
						i, mem_info[i].pid, mem_info[i].phy_memused);
				}
			}
			goto done;
		}

		/* FULL MLU MODE */
		i = 0;
		spin_lock(&core->pid_info_lock);
		list_for_each_entry(pid_info_node, &core->pid_head, pid_list) {
			if (!pid_info_node->fp || (cn_check_curproc_is_docker(&tmp) && tmp.active_ns != pid_info_node->active_ns))
				continue;
			if (tmp.tgid == tmp.active_pid) {
				mem_info[i].pid = pid_info_node->tgid;
			} else {
				mem_info[i].pid = pid_info_node->active_pid;
			}
			mem_info[i].phy_memused =
				pid_info_node->phy_usedsize >> 10;
			mem_info[i].virt_memused =
				pid_info_node->vir_usedsize >> 10;
			cn_dev_cndev_debug(cndev_set, "%d:%d ", i, mem_info[i].pid);
			i++;
			if (i >= proc_num) {
				break;
			}
		}
		spin_unlock(&core->pid_info_lock);
		if (i < proc_num) {
			proc_num = i;
		}
		cn_dev_cndev_debug(cndev_set, "total proc: %d", proc_num);
		cndev_proc_info_combine(mem_info, &proc_num);
		for (i = 0; i < proc_num; i++) {
			cn_mem_get_vmm_pid_info(core, mem_info[i].pid,
					&mem_info[i].virt_memused, &mem_info[i].phy_memused);
		}
done:
		cn_dev_cndev_debug(cndev_set, "final proc: %d", proc_num);
		copy_length = (proc_num < proc_info->proc_num)
			? proc_num : proc_info->proc_num;
		proc_info->proc_num = proc_num;
		if (proc_info->proc_info_node && proc_num) {
			ret = cndev_cp_to_usr(
				proc_info->proc_info_node,
				mem_info,
				copy_length * sizeof(struct proc_mem_info));
		}
		cn_kfree(mem_info);
	} else {
		proc_info->proc_num = 0;
	}
	return ret;
}

int cndev_user_proc_info_mlu500_vf(void *cset,
	struct cndev_proc_info *proc_info)
{
	int ret = 0, copy_length = 0, i = 0;
	u32 proc_num = 0;
	struct pid_info_s *pid_info_node = NULL;
	struct pid_info_s tmp;
	struct proc_mem_info *mem_info = NULL;
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	tmp.tgid = current->tgid;
	tmp.active_ns = task_active_pid_ns(current);
	tmp.active_pid = task_tgid_nr_ns(current, tmp.active_ns);

	proc_info->head.version = CNDEV_CURRENT_VER;
	proc_info->head.real_size = sizeof(struct cndev_proc_info);
	proc_num = core->open_count;
	if (proc_num) {
		mem_info =
			cn_kcalloc(proc_num,
				sizeof(struct proc_mem_info), GFP_KERNEL);
		if (!mem_info) {
			cn_dev_cndev_err(cndev_set, "malloc for buffer fail");
			proc_info->proc_num = 0;
			return -ENOMEM;
		}

		i = 0;
		spin_lock(&core->pid_info_lock);
		list_for_each_entry(pid_info_node, &core->pid_head, pid_list) {
			if (!pid_info_node->fp || (cn_check_curproc_is_docker(&tmp) && tmp.active_ns != pid_info_node->active_ns))
				continue;
			if (tmp.tgid == tmp.active_pid) {
				mem_info[i].pid = pid_info_node->tgid;
			} else {
				mem_info[i].pid = pid_info_node->active_pid;
			}
			mem_info[i].phy_memused =
				pid_info_node->phy_usedsize >> 10;
			mem_info[i].virt_memused =
				pid_info_node->vir_usedsize >> 10;
			cn_dev_cndev_debug(cndev_set, "%d:%d ", i, mem_info[i].pid);
			i++;
			if (i >= proc_num) {
				break;
			}
		}
		spin_unlock(&core->pid_info_lock);
		if (i < proc_num) {
			proc_num = i;
		}
		cn_dev_cndev_debug(cndev_set, "total proc: %d", proc_num);
		cndev_proc_info_combine(mem_info, &proc_num);
		for (i = 0; i < proc_num; i++) {
			cn_mem_get_vmm_pid_info(core, mem_info[i].pid,
					&mem_info[i].virt_memused, &mem_info[i].phy_memused);
		}

		/* copy to user */
		cn_dev_cndev_debug(cndev_set, "final proc: %d", proc_num);
		copy_length = (proc_num < proc_info->proc_num)
			? proc_num : proc_info->proc_num;
		proc_info->proc_num = proc_num;
		if (proc_info->proc_info_node && proc_num) {
			ret = cndev_cp_to_usr(
				proc_info->proc_info_node,
				mem_info,
				copy_length * sizeof(struct proc_mem_info));
		}
		cn_kfree(mem_info);
	} else {
		proc_info->proc_num = 0;
	}
	return ret;
}

int card_power_info_vf_common(void *cset,
			struct cndev_power_info *power_info)
{
	struct power_info_s *pinfo;
	int ret = 0;
	int result_len = 0;
	int vcard = 0;
	s8 *temp;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	/*TODO: max temperature_num ?*/
	pinfo = cn_kzalloc(sizeof(struct power_info_s), GFP_KERNEL);
	if (!pinfo)
		return -ENOMEM;

	temp = pinfo->temp;

	power_info->head.version = CNDEV_CURRENT_VER;
	power_info->head.real_size = sizeof(struct cndev_power_info);

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_power_info",
			(void *)&vcard, sizeof(u16),
			(void *)pinfo, &result_len, sizeof(struct power_info_s));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_power_info ret:%d result_len:%d"
			, ret, result_len);
	cn_dev_cndev_debug(cndev_set, "power_usage: %dw; max_power: %dw;"
			"fan_speed: %d; temperature: %d"
			, pinfo->power_usage
			, pinfo->max_power
			, pinfo->fan_speed
			, pinfo->temp[0]);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		cn_kfree(pinfo);
		return ret;
	}

	power_info->ignore_chassis_power_info = 1;

	power_info->tdp = pinfo->tdp;
	power_info->power_usage = pinfo->power_usage;
	power_info->power_usage_decimal = 0;

	power_info->max_power = pinfo->max_power;
	power_info->fan_speed = pinfo->fan_speed;

	power_info->min_power_cap = 0;
	power_info->min_power_cap_decimal = 0;
	power_info->max_power_cap_decimal = 0;

	power_info->instantaneous_power = 0;
	power_info->instantaneous_power_decimal = 0;
	power_info->ipu_cluster_mask = pinfo->logic_ic_bitmap;
	power_info->ipu_cluster_freq_num = pinfo->ic_num;
	power_info->edpp_count = pinfo->edpp_count;
	power_info->tdp_freq_capping_count = pinfo->tdp_freq_capping_count;

	ret = cndev_cp_less_val(
		&power_info->temperature_num, pinfo->temperature_num,
		power_info->temp, pinfo->temp, sizeof(s8));
	if (ret) {
		goto out;
	}

	ret = cndev_cp_less_val(
		&power_info->ipu_cluster_freq_num, pinfo->ic_num,
		power_info->ipu_cluster_freq, pinfo->ic_freq, sizeof(u16));

out:
	cn_kfree(pinfo);
	return ret;
}

static int get_card_ecc_desc(void *cset,
	struct cndev_ecc_cmd *ecc_cmd, struct cndev_ecc_data *ecc_info)
{
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret = 0;
	uint32_t result_len = 0;

	core = (struct cn_core_set *)cndev_set->core;

	/* rpc call */
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_common",
			(void *)ecc_cmd, sizeof(struct cndev_ecc_cmd),
			(void *)ecc_info, &result_len, sizeof(struct cndev_ecc_data));

	/* res check */
	if (ret) {
		cn_dev_cndev_err(cndev_set, "cndev rpc res %d %d", ecc_info->head.res , ret);
		return -EINVAL;
	}

	return ret;
}

static void __parser_ecc_info(struct cndev_ecc_desc_info *ecc_desc, u32 type,
	u64 *ecc_info, u32 module, u32 num)
{
	u32 i = 0;

	for (i = 0; i < num; i++) {
		ecc_desc[i].type = type;
		ecc_desc[i].ecc_counter = ecc_info[i];
		ecc_desc[i].module = module;
		ecc_desc[i].ecc_location = i;
	}
}

static int __unpack_ecc_info(struct cndev_ecc_desc_info *ecc_desc, u32 type,
	struct cndev_ecc_data *ecc_data)
{
	/* IPU */
	__parser_ecc_info(&ecc_desc[IPU_LOC_OF], type,
		&ecc_data->ecc_info[IPU_LOC_OF], CNDEV_IPU_ECC, IPU_LOCATION_NUM);

	/* TNC */
	__parser_ecc_info(&ecc_desc[TNC_LOC_OF], type,
		&ecc_data->ecc_info[TNC_LOC_OF], CNDEV_TNC_ECC, TNC_LOCATION_NUM);

	/* PCIe */
	__parser_ecc_info(&ecc_desc[PCIE_LOC_OF], type,
		&ecc_data->ecc_info[PCIE_LOC_OF], CNDEV_PCIE_ECC, PCIE_LOCATION_NUM);

	/* SMMU */
	__parser_ecc_info(&ecc_desc[SMMU_LOC_OF], type,
		&ecc_data->ecc_info[SMMU_LOC_OF], CNDEV_SMMU_ECC, SMMU_LOCATION_NUM);

	/* LLC */
	__parser_ecc_info(&ecc_desc[LLC_LOC_OF], type,
		&ecc_data->ecc_info[LLC_LOC_OF], CNDEV_LLC_ECC, LLC_LOCATION_NUM);

	/* NCS */
	__parser_ecc_info(&ecc_desc[NCS_LOC_OF], type,
		&ecc_data->ecc_info[NCS_LOC_OF], CNDEV_NCS_ECC, NCS_LOCATION_NUM);

	return 0;
}

int card_ecc_info_common(void *cset,
	struct cndev_ecc_info *einfo)
{
	struct ecc_info_t *card_ecc_info = NULL;
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u16 vcard = 0;
	int ret = 0;
	struct cndev_ecc_cmd ecc_cmd;
	struct cndev_ecc_data *ecc_data = NULL;
	struct cndev_ecc_desc_info *ecc_desc = NULL;
	int copy_size = 0;
	int num = 0;
	u32 i = 0;
	const int max_ecc_num = ECC_MAX_TYPE * CNDEV_MAX_ECC_NUM;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	vcard = (einfo->head.card >> 8) & 0x0f;
	ret = cndev_vcard_trans(cndev_set, &vcard);
	if (ret) {
		return -EINVAL;
	}

	einfo->head.version = CNDEV_CURRENT_VER;
	einfo->head.real_size = sizeof(struct cndev_ecc_info);
	einfo->single_biterr = 0;
	einfo->multi_biterr = 0;
	einfo->single_multierr = 0;
	einfo->multi_multierr = 0;
	einfo->corrected_err = 0;
	einfo->uncorrect_err = 0;
	einfo->total_err = 0;
	einfo->die2die_crc_err = 0;
	einfo->die2die_crc_err_overflow = 0;
	einfo->addr_forbidden_err = 0;
	einfo->inline_ecc_support = core->ile_en;

	down_read(&core->mcc_state_sem);

	card_ecc_info =
		(struct ecc_info_t *)cn_mcc_get_ecc_status(core);
	if (IS_ERR_OR_NULL(card_ecc_info)) {
		cn_dev_cndev_err(cndev_set, "get ecc ptr err");
		ret = -EINVAL;
		goto out;
	}
	up_read(&core->mcc_state_sem);

	/* corrected_err */
	einfo->single_biterr +=
		card_ecc_info[0].one_bit_ecc_error;

	/* uncorrect_err */
	einfo->single_multierr +=
		card_ecc_info[0].multiple_bit_ecc_error;

	einfo->corrected_err = einfo->single_biterr + einfo->multi_biterr;
	einfo->uncorrect_err = einfo->single_multierr + einfo->multi_multierr;
	einfo->total_err = einfo->corrected_err + einfo->uncorrect_err;

	if (einfo->ecc_desc_num) {
		ecc_data = cn_kzalloc(sizeof(struct cndev_ecc_data), GFP_KERNEL);
		if (!ecc_data) {
			cn_dev_cndev_err(cndev_set, "alloc memory fail");
			ret = -ENOMEM;
			goto free_ecc_data;
		}

		ecc_desc = cn_kzalloc(sizeof(struct cndev_ecc_desc_info) * max_ecc_num, GFP_KERNEL);
		if (!ecc_desc) {
			cn_dev_cndev_err(cndev_set, "alloc memory fail");
			ret = -ENOMEM;
			goto free_ecc_desc;
		}

		/* get ipu ecc desc */
		ecc_cmd.head.version = 0;
		ecc_cmd.head.cmd = CNDEV_RPC_CMD_GET_ECC;
		ecc_cmd.head.size = sizeof(struct cndev_ecc_cmd);
		ecc_cmd.host_vf_id = 0xff;

		for (i = 0; i < ECC_MAX_TYPE; i++) {
			ecc_cmd.type = i;
			memset(ecc_data, 0x0, sizeof(struct cndev_ecc_data));
			ret = get_card_ecc_desc(cndev_set, &ecc_cmd, ecc_data);
			if (ret)
				goto failed;

			if (num + ecc_data->ecc_num < max_ecc_num) {
				num += ecc_data->ecc_num;
			} else {
				copy_size = max_ecc_num - num;
				if (copy_size > 0) {
					num += copy_size;
				}
			}

			__unpack_ecc_info(&ecc_desc[CNDEV_MAX_ECC_NUM * i], i, ecc_data);
		}

		ret = cndev_cp_less_val(
			&einfo->ecc_desc_num, num,
			einfo->ecc_desc, ecc_desc, sizeof(struct cndev_ecc_desc_info));
	} else {
		einfo->ecc_desc_num = max_ecc_num;
	}

failed:
	if (ecc_desc)
		cn_kfree(ecc_desc);
free_ecc_desc:
	if (ecc_data)
		cn_kfree(ecc_data);
free_ecc_data:
	return ret;
out:
	up_read(&core->mcc_state_sem);
	return ret;
}

int card_ecc_info_vf_common(void *cset,
	struct cndev_ecc_info *einfo)
{
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u16 vcard = 0;
	int ret = 0;
	struct cndev_ecc_cmd ecc_cmd;
	struct cndev_ecc_data *ecc_data = NULL;
	struct cndev_ecc_desc_info *ecc_desc = NULL;
	int copy_size = 0;
	int num = 0;
	u32 i = 0;
	const int max_ecc_num = ECC_MAX_TYPE * CNDEV_MAX_ECC_NUM;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	vcard = (einfo->head.card >> 8) & 0x0f;
	ret = cndev_vcard_trans(cndev_set, &vcard);
	if (ret) {
		return -EINVAL;
	}

	einfo->head.version = CNDEV_CURRENT_VER;
	einfo->head.real_size = sizeof(struct cndev_ecc_info);
	einfo->single_biterr = 0;
	einfo->multi_biterr = 0;
	einfo->single_multierr = 0;
	einfo->multi_multierr = 0;
	einfo->corrected_err = 0;
	einfo->uncorrect_err = 0;
	einfo->total_err = 0;
	einfo->die2die_crc_err = 0;
	einfo->die2die_crc_err_overflow = 0;
	einfo->addr_forbidden_err = 0;
	einfo->inline_ecc_support = 0;
	einfo->single_biterr = 0;
	einfo->single_multierr = 0;
	einfo->corrected_err = einfo->single_biterr + einfo->multi_biterr;
	einfo->uncorrect_err = einfo->single_multierr + einfo->multi_multierr;
	einfo->total_err = einfo->corrected_err + einfo->uncorrect_err;

	if (einfo->ecc_desc_num) {
		ecc_data = cn_kzalloc(sizeof(struct cndev_ecc_data), GFP_KERNEL);
		if (!ecc_data) {
			cn_dev_cndev_err(cndev_set, "alloc memory fail");
			ret = -ENOMEM;
			goto free_ecc_data;
		}

		ecc_desc = cn_kzalloc(sizeof(struct cndev_ecc_desc_info) * max_ecc_num, GFP_KERNEL);
		if (!ecc_desc) {
			cn_dev_cndev_err(cndev_set, "alloc memory fail");
			ret = -ENOMEM;
			goto free_ecc_desc;
		}

		/* get ipu ecc desc */
		ecc_cmd.head.version = 0;
		ecc_cmd.head.cmd = CNDEV_RPC_CMD_GET_ECC;
		ecc_cmd.head.size = sizeof(struct cndev_ecc_cmd);
		ecc_cmd.host_vf_id = vcard;

		for (i = 0; i < ECC_MAX_TYPE; i++) {
			ecc_cmd.type = i;
			memset(ecc_data, 0x0, sizeof(struct cndev_ecc_data));
			ret = get_card_ecc_desc(cndev_set, &ecc_cmd, ecc_data);
			if (ret)
				goto failed;

			if (num + ecc_data->ecc_num < max_ecc_num) {
				num += ecc_data->ecc_num;
			} else {
				copy_size = max_ecc_num - num;
				if (copy_size > 0) {
					num += copy_size;
				}
			}

			__unpack_ecc_info(&ecc_desc[CNDEV_MAX_ECC_NUM * i], i, ecc_data);
		}

		ret = cndev_cp_less_val(
			&einfo->ecc_desc_num, num,
			einfo->ecc_desc, ecc_desc, sizeof(struct cndev_ecc_desc_info));
	} else {
		einfo->ecc_desc_num = max_ecc_num;
	}

failed:
	if (ecc_desc)
		cn_kfree(ecc_desc);

free_ecc_desc:
	if (ecc_data)
		cn_kfree(ecc_data);
free_ecc_data:
	return ret;
}

static u64 pow64(u64 base, unsigned int exp)
{
	u64 result = 1;

	while (exp) {
		if (exp & 1)
			result *= base;
		exp >>= 1;
		base *= base;
	}

	return result;
}

int cndev_card_memory_info_common(void *cset,
	struct cndev_memory_info *mem_info)
{
	struct mem_size_info size_info;
	struct memory_info_s *minfo;
	int result_len = 0;
	int copy_length = 0;
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret, i;
	u16 vcard;
	u32 unit = 0;
	u64 align_size = 0;
	u64 mem_cap_per_chnl = 0;
	u64 mem_channel_num = 0;
	struct smlu_cgroup_res *res;
	bool use_smlu_phy_used = false;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	mem_info->head.version = CNDEV_CURRENT_VER;
	mem_info->head.real_size = sizeof(struct cndev_memory_info);

	minfo = cn_kzalloc(sizeof(struct memory_info_s) + 32 * sizeof(u64),
			GFP_KERNEL);
	if (!minfo) {
		cn_dev_cndev_err(cndev_set, "malloc for buffer fail");
		mem_info->chl_num = 0;
		return -ENOMEM;
	}

	cn_mem_get_size_info(&size_info, core);

	vcard = (mem_info->head.card >> 8) & 0x0f;

	ret = cndev_vcard_trans(cndev_set, &vcard);
	if (ret) {
		goto free_minfo;
	}

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_memory_info",
			(void *)&vcard, sizeof(u16),
			(void *)minfo, &result_len, sizeof(struct memory_info_s) + 32 * sizeof(u64));

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		mem_info->chl_num = 0;
		goto free_minfo;
	}

	res = cn_kmalloc(sizeof(*res), GFP_KERNEL);
	if (res == NULL) {
		ret = -ENOMEM;
		goto free_minfo;
	}

	/* correct to split size */
	ret = cn_smlu_query_namespace_quota(core, mem_cgrp_id, NULL, res);
	if (ret == 0) {/* smlu enabled && name space in rbtree */
		cn_dev_cndev_debug(cndev_set, "correct phy_total 0x%llx B -> 0x%llx B", minfo->phy_total, res->max);
		cn_dev_cndev_debug(cndev_set, "correct phy_used 0x%llx B -> 0x%llx B", minfo->phy_used, res->usage);
		minfo->phy_total = (res->max);
		minfo->phy_used = (res->usage);
		use_smlu_phy_used = true;
	}

	cn_kfree(res);
	ret = 0;

	if (mem_info->mlu_memory_unit >= MLU_MEM_UNIT_UNKNOWN) {
		mem_info->mlu_memory_unit = MLU_MEM_UNIT_MB;
	}
	unit = MLU_MEM_UNIT_B - mem_info->mlu_memory_unit;

	align_size = pow64(1024, unit);
	mem_info->phy_total = minfo->phy_total / align_size;
	if (!use_smlu_phy_used)
		mem_info->phy_used = 0;
	else
		mem_info->phy_used = minfo->phy_used / align_size;
	mem_info->virt_total = size_info.vir_total_mem / align_size;
	mem_info->virt_used = size_info.vir_used_mem / align_size;
	mem_info->fa_total = size_info.fa_total_mem / align_size;
	mem_info->fa_used = size_info.fa_used_mem / align_size;
	cn_attr_get_resource(core, RES_MEM_CAP_PER_CHNL, &mem_cap_per_chnl);
	cn_attr_get_resource(core, RES_MEM_CHANNEL_NUM, &mem_channel_num);
	mem_info->global_mem = (mem_cap_per_chnl * mem_channel_num * 1024 * 1024) / align_size;

	for (i = 0; i < minfo->chl_num; i++) {
		minfo->each_chl[i] = DIV_ROUND_UP(minfo->each_chl[i], align_size);
		if (!use_smlu_phy_used)
			mem_info->phy_used += minfo->each_chl[i];
	}
	copy_length = (mem_info->chl_num < minfo->chl_num) ?
			mem_info->chl_num : minfo->chl_num;

	if (mem_info->each_chl) {
		ret = cndev_cp_to_usr(mem_info->each_chl, minfo->each_chl,
				copy_length * sizeof(u64));
	}
	mem_info->chl_num = minfo->chl_num;
	mem_info->sys_totalram = minfo->sys_totalram;
	mem_info->sys_freeram = minfo->sys_freeram;

free_minfo:
	cn_kfree(minfo);
	return ret;
}

int cndev_card_ipuutil_info_common(void *cset,
	struct cndev_ipuutil_info *util_info)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct ipuutil_info_s *uinfo;
	int ret = 0;
	int result_len = 0;
	u8 *core_util;
	u16 vcard;
	u32 total_core_cnt = 0;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	vcard = (util_info->head.card >> 8) & 0x0f;

	ret = cndev_vcard_trans(cndev_set, &vcard);
	if (ret)
		return ret;
	vcard = (vcard == 0xff) ? 0 : vcard;

	uinfo = cn_kzalloc(sizeof(struct ipuutil_info_s)
			+ 100 * sizeof(u8), GFP_KERNEL);
	if (!uinfo) {
		cn_dev_cndev_err(cndev_set, "no mem error");
		return -ENOMEM;
	}

	core_util = uinfo->core_util;

	util_info->head.version = CNDEV_CURRENT_VER;
	util_info->head.real_size = sizeof(struct cndev_ipuutil_info);

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_ipuutil_info",
			(void *)&vcard, sizeof(u16),
			(void *)uinfo, &result_len, sizeof(struct ipuutil_info_s) + 100 * sizeof(u8));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_ipuutil_info ret:%d  result_len:%d"
			, ret, result_len);
	cn_dev_cndev_debug(cndev_set, "chip util: %u%%", uinfo->chip_util);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		cn_kfree(uinfo);
		return ret;
	}

	total_core_cnt = uinfo->core_num + uinfo->tinycore_num;
	ret = cndev_cp_less_val(
			&util_info->core_num, total_core_cnt,
			util_info->core_util, core_util, sizeof(u8));

	util_info->tinycore_num = uinfo->tinycore_num;
	util_info->core_num = uinfo->core_num;
	util_info->chip_util = uinfo->chip_util;

	cn_kfree(uinfo);
	return 0;
}

int cndev_card_acpuutil_info_common(void *cset,
	struct cndev_acpuutil_info *util_info)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct acpuutil_info_s *uinfo = NULL;
	int ret = 0;
	int result_len = 0;
	u8 *core_util;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	uinfo = cn_kzalloc(sizeof(struct acpuutil_info_s)
			+ 64 * sizeof(u8), GFP_KERNEL);
	if (!uinfo) {
		cn_dev_cndev_err(cndev_set, "no mem error");
		return -ENOMEM;
	}

	core_util = uinfo->core_util;

	util_info->head.version = CNDEV_CURRENT_VER;
	util_info->head.real_size = sizeof(struct cndev_acpuutil_info);

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_acpuutil_info",
			NULL, 0,
			(void *)uinfo, &result_len, sizeof(struct acpuutil_info_s) + 64 * sizeof(u8));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_cpuutil_info ret:%d  result_len:%d"
			, ret, result_len);
	cn_dev_cndev_debug(cndev_set, "chip util: %u%%", uinfo->chip_util);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		cn_kfree(uinfo);
		return ret;
	}

	ret = cndev_cp_less_val(
			&util_info->core_num, uinfo->core_num,
			util_info->core_util, core_util, sizeof(u8));

	util_info->core_num = uinfo->core_num;
	util_info->chip_util = uinfo->chip_util;

	cn_kfree(uinfo);
	return 0;
}

int cndev_card_get_acpuutil_timer_common(void *cset,
	struct cndev_acpuutil_timer *timer)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret = 0;
	int result_len = 0;
	size_t result = sizeof(int);
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_get_acpuutil_timer",
			NULL, 0,
			&result, &result_len, sizeof(int));

	cn_dev_cndev_debug(cndev_set, "rpc cndev get cpuutil info ret:%d  result_len:%d"
			, ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}
	timer->timer = result;

	return 0;
}

int cndev_card_set_acpuutil_timer_common(void *cset,
	struct cndev_acpuutil_timer *timer)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	unsigned int val = 0;
	int ret = 0;
	int result_len = 0;
	int result = 0;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	val = timer->timer;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_set_acpuutil_timer",
			(void *)&val, sizeof(unsigned int),
			&result, &result_len, sizeof(int));

	cn_dev_cndev_debug(cndev_set, "rpc cndev set cpuutil info ret:%d  result_len:%d"
			, ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	return result;
}

int cndev_card_acpuutil_timer_common(void *cset,
	struct cndev_acpuutil_timer *timer)
{
	int result = 0;

	timer->head.version = CNDEV_CURRENT_VER;
	timer->head.real_size = sizeof(struct cndev_acpuutil_timer);

	if (timer->ops_type) {
		result = cndev_card_set_acpuutil_timer_common(cset, timer);
	} else {
		result = cndev_card_get_acpuutil_timer_common(cset, timer);
	}

	return result;
}

int cndev_card_codecutil_info_common(void *cset,
	struct cndev_codecutil_info *util_info)
{
	int ret = 0;
	struct codecutil_info_s *uinfo;
	int result_len = 0;
	u8 *codec_util;
	u16 vcard = 0;
	u16 user_num, real_num;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	uinfo = cn_kzalloc(sizeof(struct codecutil_info_s)
			+ 100 * sizeof(u8), GFP_KERNEL);
	if (!uinfo) {
		cn_dev_cndev_err(cndev_set, "no mem error");
		return -ENOMEM;
	}

	codec_util = uinfo->codec_util;

	util_info->head.version = CNDEV_CURRENT_VER;
	util_info->head.real_size = sizeof(struct cndev_codecutil_info);

	vcard = (util_info->head.card >> 8) & 0x0f;

	ret = cndev_vcard_trans(cndev_set, &vcard);
	if (ret) {
		cn_kfree(uinfo);
		return ret;
	}
	vcard = (vcard == 0xff) ? 0 : vcard;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_codecutil_info",
			(void *)&vcard, sizeof(u16),
			(void *)uinfo, &result_len, sizeof(struct codecutil_info_s) + 100 * sizeof(u8));

	cn_dev_cndev_debug(cndev_set,
			"rpc_cndev_codecutil_info ret:%d  result_len:%d", ret, result_len);
	cn_dev_cndev_debug(cndev_set, "vpu num: %u, jpu num: %u, scaler num: %u",
			uinfo->vpu_num, uinfo->jpu_num, uinfo->scaler_num);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		cn_kfree(uinfo);
		return ret;
	}

	if (!(cndev_set->quirks & CNDEV_QUIRK_SUPPORT_SCALER)
			&& uinfo->scaler_num) {
		cn_dev_cndev_err(cndev_set, "scaler num [%u] is err", uinfo->scaler_num);
		cn_kfree(uinfo);
		return -EFAULT;
	}

	user_num = util_info->vpu_num + util_info->jpu_num + util_info->scaler_num;
	real_num = uinfo->jpu_num + uinfo->vpu_num + uinfo->scaler_num;
	ret = cndev_cp_less_val(
			&user_num, real_num,
			util_info->codec_util, codec_util, sizeof(u8));

	util_info->vpu_num = uinfo->vpu_num;
	util_info->jpu_num = uinfo->jpu_num;
	util_info->scaler_num = uinfo->scaler_num;

	cn_kfree(uinfo);
	return 0;
}


int cndev_card_curbuslnk_common(void *cset,
	struct cndev_curbuslnk_info *linfo)
{
	struct bus_lnkcap_info lnk_info;
	struct cn_core_set *core;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u16 vcard;

	vcard = (linfo->head.card >> 8) & 0x0f;
	if (vcard)
		return -ENODEV;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;
	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	linfo->head.version = CNDEV_CURRENT_VER;
	linfo->head.real_size = sizeof(struct cndev_curbuslnk_info);

	memset(&lnk_info, 0, sizeof(struct bus_lnkcap_info));
	cn_bus_get_curlnk(core->bus_set, &lnk_info);

	linfo->cur_speed = lnk_info.speed;
	linfo->cur_width = lnk_info.width;

	return 0;
}

int cndev_card_pciethroughput_common(void *cset,
	struct cndev_pcie_throughput *tpinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	u16 vcard;

	vcard = (tpinfo->head.card >> 8) & 0x0f;
	if (vcard)
		return -ENODEV;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	tpinfo->head.version = CNDEV_CURRENT_VER;
	tpinfo->head.real_size = sizeof(struct cndev_pcie_throughput);

	tpinfo->pcie_read = cndev_set->bus_throughput.read_data;
	tpinfo->pcie_write = cndev_set->bus_throughput.write_data;

	tpinfo->soft_retry_cnt = (u64)cn_bus_get_soft_retry_cnt(core->bus_set);

	return 0;
}

int cndev_card_powercapping_common(void *cset,
	struct cndev_powercapping_s *pcinfo)
{
	struct power_capping_info *mcu_param;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	u16 vcard;

	vcard = (pcinfo->head.card >> 8) & 0x0f;
	if (vcard)
		return -ENODEV;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	pcinfo->head.version = CNDEV_CURRENT_VER;
	pcinfo->head.real_size = sizeof(struct cndev_powercapping_s);

	mcu_param = (struct power_capping_info *)&pcinfo->ops_type;

	return cndrv_mcu_power_capping(cndev_set->core, mcu_param);
}

int cndev_qos_policy_common(void *cset, struct cndev_qos_info *qos_info)
{
	int ret = 0;
	struct cndev_qos_policy qos_policy = {0};
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	if (IS_ERR_OR_NULL(cset) || IS_ERR_OR_NULL(qos_info))
		return -EINVAL;

	qos_info->head.version = CNDEV_CURRENT_VER;
	qos_info->head.real_size = sizeof(struct cndev_qos_info);

	qos_policy.qos_base = qos_info->qos_base;
	qos_policy.qos_policy = qos_info->qos_policy;
	qos_policy.qos_up = qos_info->qos_up;
	qos_policy.group_id = qos_info->group_id;

	ret = noc_qos_policy_common(cndev_set->core, &qos_policy);
	return ret;
}

int cndev_qos_desc_common(void *cset, struct cndev_qos_detail *qos_detail)
{
	int ret = 0;
	struct cndev_qos_detail_info qos_info = {0};
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	if (IS_ERR_OR_NULL(cset) || IS_ERR_OR_NULL(qos_detail))
		return -EINVAL;

	qos_detail->head.version = CNDEV_CURRENT_VER;
	qos_detail->head.real_size = sizeof(struct cndev_qos_detail);

	qos_info.qos_desc_num = qos_detail->qos_desc_num;
	qos_info.desc = qos_detail->desc;

	ret = noc_qos_desc_common(cndev_set->core, &qos_info);
	if (!ret) {
		qos_detail->qos_desc_num = qos_info.qos_desc_num;
	}

	return ret;
}

int cndev_qos_reset_common(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	if (IS_ERR_OR_NULL(cset))
		return -EINVAL;

	return noc_qos_reset_common(cndev_set->core);
}

int cndev_set_qos_policy(void *cset, struct cndev_qos_param *qos_info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	if (IS_ERR_OR_NULL(cset) || IS_ERR_OR_NULL(qos_info))
		return -EINVAL;

	qos_info->head.version = CNDEV_CURRENT_VER;
	qos_info->head.real_size = sizeof(struct cndev_qos_param);

	ret = set_qos_weight(cndev_set->core, qos_info->qos_value.qos_weight, qos_info->qos_group, qos_info->master_index);
	return ret;
}

int cndev_set_qos_group_policy(void *cset, struct cndev_qos_group_param *qos_info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	if (IS_ERR_OR_NULL(cset) || IS_ERR_OR_NULL(qos_info))
		return -EINVAL;

	qos_info->head.version = CNDEV_CURRENT_VER;
	qos_info->head.real_size = sizeof(struct cndev_qos_group_param);

	ret = set_qos_group_weight(cndev_set->core, qos_info->qos_value.qos_weight, qos_info->qos_group);
	return ret;
}

int cndev_card_get_retire_pages(void *cset,
	struct cndev_retire_page *retire_pages)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int result = 0;
	u64 *page_addr = NULL;
	u32 page_count = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	retire_pages->head.version = CNDEV_CURRENT_VER;
	retire_pages->head.real_size = sizeof(struct cndev_retire_page);

	result = cn_mcc_get_retire_pages(core, retire_pages->cause,
		&page_count, &page_addr);
	if (result == -EACCES) {
		retire_pages->page_count = 0;
		result = 0;
		goto out;
	}

	if (result) {
		cn_dev_cndev_err(cndev_set, "get retire pages info failed");
		goto out;
	}

	if (page_count)
		result = cndev_cp_less_val(
				&retire_pages->page_count, page_count,
				retire_pages->page_addr, page_addr, sizeof(u64));

	retire_pages->page_count = page_count;

out:
	return result;
}

int cndev_card_get_retire_status(void *cset,
	struct cndev_retire_status *retire_status)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int result = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	retire_status->head.version = CNDEV_CURRENT_VER;
	retire_status->head.real_size = sizeof(struct cndev_retire_status);

	result = cn_mcc_get_retire_pages_pending_status(core,
		&retire_status->is_pending, &retire_status->is_failure);

	return result;
}

int cndev_card_get_retire_remapped_rows(void *cset,
	struct cndev_retire_remapped_rows *retire_remapped_rows)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int result = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	retire_remapped_rows->head.version = CNDEV_CURRENT_VER;
	retire_remapped_rows->head.real_size = sizeof(struct cndev_retire_remapped_rows);

	result = cn_mcc_get_remapped_rows(core, &retire_remapped_rows->corr_rows,
		&retire_remapped_rows->unc_rows, &retire_remapped_rows->pending_rows,
		&retire_remapped_rows->fail_rows);

	return result;
}

int cndev_card_retire_switch(void *cset,
	struct cndev_retire_op *retire_op)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int result = 0;
	int ret = 0;
	u32 retire_switch = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	retire_op->head.version = CNDEV_CURRENT_VER;
	retire_op->head.real_size = sizeof(struct cndev_retire_op);

	if (retire_op->op) {
		if (retire_op->retire_switch)
			retire_switch = 1;
		else
			retire_switch = 0;

		result = cn_mcc_retire_switch(core, retire_switch);
		/*set switch(on-1), return 1*/
		/*set switch(off-0), return 0*/
		/*set switch(others), query*/
		if (retire_switch == result)
			return 0;
		else
			return -EINVAL;
	} else {
		/*set switch 0xff means query switch*/
		ret = cn_mcc_retire_switch(core, 0xff);
		if (ret < 0) {
			retire_op->retire_switch = 0;
			result = -EINVAL;
		} else {
			retire_op->retire_switch = ret;
			result = 0;
		}
	}
	return result;
}

int card_ncs_version_common(void *cset,
			struct cndev_NCS_version *verinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	u32 link = 0;
	struct NCS_basic_info_s rpc_info = {0};
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(verinfo))
		return -EINVAL;

	verinfo->head.version = CNDEV_CURRENT_VER;
	verinfo->head.real_size = sizeof(struct cndev_NCS_version);

	link = verinfo->link;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_get_cclink_basic_info",
			(void *)&link, sizeof(u32),
			(void *)&rpc_info, &result_len, sizeof(struct NCS_basic_info_s));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_get_cclink_basic_info rpc_info.ret:%d result_len:%d"
			, rpc_info.ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	verinfo->build_version = rpc_info.build_version;
	verinfo->minor_version = rpc_info.minor_version;
	verinfo->major_version = rpc_info.major_version;

	return rpc_info.ret;
}

int card_ncs_state_common(void *cset,
	struct cndev_NCS_state_info *stinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	u32 link = 0;
	struct ncs_state_data link_state;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(stinfo))
		return -EINVAL;

	stinfo->head.version = CNDEV_CURRENT_VER;
	stinfo->head.real_size = sizeof(struct cndev_NCS_state_info);

	link = stinfo->link;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_get_cclink_state_info",
					(void *)&link, sizeof(u32),
					(void *)&link_state, &result_len, sizeof(struct ncs_state_data));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_get_cclink_state_info link_state.ret:%d result_len:%d"
					, link_state.ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	stinfo->serdes_state = link_state.serdes_state;
	stinfo->state = link_state.is_active;
	stinfo->cable_state = link_state.cable_state;

	return link_state.ret;
}

int card_ncs_speed_common(void *cset,
	struct cndev_NCS_speed_info *stinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	u32 link = 0;
	struct NCS_speed_info_s rpc_info = {0};
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(stinfo))
		return -EINVAL;

	stinfo->head.version = CNDEV_CURRENT_VER;
	stinfo->head.real_size = sizeof(struct cndev_NCS_speed_info);

	link = stinfo->link;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_get_cclink_speed_info",
			(void *)&link, sizeof(u32),
			(void *)&rpc_info, &result_len, sizeof(struct NCS_speed_info_s));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_get_cclink_speed_info rpc_info.ret:%d result_len:%d"
			, rpc_info.ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	stinfo->speed = rpc_info.speed;
	stinfo->speed_fmt = rpc_info.speed_fmt;

	return rpc_info.ret;
}

int card_ncs_capability_common(void *cset,
	struct cndev_NCS_capability *capinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	u32 link = 0;
	struct NCS_capability_info_s rpc_info = {0};
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(capinfo))
		return -EINVAL;

	capinfo->head.version = CNDEV_CURRENT_VER;
	capinfo->head.real_size = sizeof(struct cndev_NCS_capability);

	link = capinfo->link;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_get_cclink_capability_info",
			(void *)&link, sizeof(u32),
			(void *)&rpc_info, &result_len, sizeof(struct NCS_capability_info_s));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_get_cclink_capability_info rpc_info.ret:%d result_len:%d"
			, rpc_info.ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	capinfo->cap_ilkn_fec = rpc_info.cap_ilkn_fec;
	capinfo->cap_p2p_tsf = rpc_info.cap_p2p_tsf;
	return rpc_info.ret;
}

int card_ncs_counter_common(void *cset,
	struct cndev_NCS_counter *cntrinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	u32 link = 0;
	struct ncs_cnt_info_s rpc_info = {0};
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(cntrinfo))
		return -EINVAL;

	cntrinfo->head.version = CNDEV_CURRENT_VER;
	cntrinfo->head.real_size = sizeof(struct cndev_NCS_counter);

	link = cntrinfo->link;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_get_cclink_counter_info",
			(void *)&link, sizeof(u32),
			(void *)&rpc_info, &result_len, sizeof(struct ncs_cnt_info_s));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_get_cclink_counter_info rpc_info.ret:%d result_len:%d"
			, rpc_info.ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	memcpy(&cntrinfo->info, &rpc_info.ncs_cnt, sizeof(u64) * CCLINK_ERR_NUM_V1);
	cntrinfo->info.err_rd_err_pkg = rpc_info.ncs_cnt[CCLINK_ERR_RD_ERR_PKG];
	cntrinfo->info.err_wr_err_pkg = rpc_info.ncs_cnt[CCLINK_ERR_WR_ERR_PKG];
	cntrinfo->info.err_smmu = rpc_info.ncs_cnt[CCLINK_ERR_SMMU];
	cntrinfo->info.cntr_cnp_pkg = rpc_info.ncs_cnt[CCLINK_CNTR_CNP_PKGS];
	cntrinfo->info.cntr_pfc_pkg = rpc_info.ncs_cnt[CCLINK_CNTR_PFC_PKGS];

	return rpc_info.ret;
}

int card_ncs_remote_common(void *cset,
	struct cndev_NCS_remote_info *rmtinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	u32 link = 0;
	struct NCS_basic_info_s rpc_info = {0};
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(rmtinfo))
		return -EINVAL;

	rmtinfo->head.version = CNDEV_CURRENT_VER;
	rmtinfo->head.real_size = sizeof(struct cndev_NCS_remote_info);

	link = rmtinfo->link;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_get_cclink_basic_info",
			(void *)&link, sizeof(u32),
			(void *)&rpc_info, &result_len, sizeof(struct NCS_basic_info_s));

	cn_dev_cndev_debug(cndev_set,
		"rpc_cndev_do_get_cclink_basic_info rpc_info.ret:%d result_len:%d",
		rpc_info.ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	rmtinfo->ba_sn = rpc_info.ba_sn;
	rmtinfo->mc_sn = rpc_info.mc_sn;
	rmtinfo->port_id = rpc_info.port_id;
	rmtinfo->slot_id = rpc_info.slot_id;

	rmtinfo->type = rpc_info.type;
	rmtinfo->dev_ip_version = rpc_info.dev_ip_version;
	rmtinfo->is_ip_valid = rpc_info.is_ip_valid;

	memcpy(rmtinfo->dev_ip, rpc_info.dev_ip, ADDRESS_LEN);
	memcpy(rmtinfo->uuid, rpc_info.uuid, CNDRV_UUID_SIZE);

	rmtinfo->ncs_uuid64 = rpc_info.ncs_uuid64;

	return rpc_info.ret;
}

int card_ncs_reset_cntr_common(void *cset,
	struct cndev_NCS_reset_counter *rstinfo)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;
	int ret = 0;
	int res = 0;
	struct NCS_reset_counter_s rpc_info = {0};
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(rstinfo))
		return -EINVAL;

	rstinfo->head.version = CNDEV_CURRENT_VER;
	rstinfo->head.real_size = sizeof(struct cndev_NCS_reset_counter);

	rpc_info.link = rstinfo->link;
	rpc_info.cntr = rstinfo->cntr;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_do_reset_cclink_counter",
			(void *)&rpc_info, sizeof(struct NCS_reset_counter_s),
			&res, &result_len, sizeof(int));

	cn_dev_cndev_debug(cndev_set, "rpc_cndev_do_reset_cclink_counter res:%d result_len:%d"
			, res, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	return res;
}

int card_get_ncs_info_common(void *cset,
			struct cndev_ncs_info *ncs_info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core;
	struct ncs_info_s info;
	int result_len = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	ncs_info->head.version = CNDEV_CURRENT_VER;
	ncs_info->head.real_size = sizeof(struct cndev_ncs_info);

	ret = __pmu_call_rpc(core, cndev_set->endpoint,
			"rpc_cndev_get_ncs_info",
			NULL, 0,
			&info, &result_len, sizeof(struct ncs_info_s));
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	if (info.ret) {
		cn_dev_cndev_err(cndev_set, "get ncs info failed %d", info.ret);
		return ret;
	}

	ncs_info->support_mlulink = info.is_support_mlulink;
	ret = cndev_cp_less_val(
			&ncs_info->ncs_num, info.mlulink_port,
			ncs_info->ncs_info, info.basic_info, sizeof(struct cndev_ncs_basic_info));
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "cndev cpy to usr failed");
		return ret;
	}

	ncs_info->ncs_num = info.mlulink_port;
	ncs_info->ncs_uuid64 = info.ncs_uuid64;

	return info.ret > 0 ? -info.ret : info.ret;
}

int card_ncs_port_config_common(void *cset, struct cndev_NCS_config *port_config)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	uint32_t result_len = sizeof(struct NCS_port_config_s);
	int ret = 0;
	struct NCS_port_config_s port_config_in;
	struct NCS_port_config_s port_config_out;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(port_config))
		return -EINVAL;

	port_config->head.version = CNDEV_CURRENT_VER;
	port_config->head.real_size = sizeof(struct cndev_NCS_config);

	/* set port mode */
	if (port_config->ops_type) {
		port_config_in.ops = 1;
		port_config_in.current_mode_flags = port_config->current_mode_flags;
		port_config_in.port_idx = port_config->port_idx;
	} else {
		/* get port mode */
		port_config_in.ops = 0;
		port_config_in.port_idx = port_config->port_idx;
	}

	core = cndev_set->core;
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_cclink_port_info",
			(void *)&port_config_in, sizeof(struct NCS_port_config_s),
			(void *)&port_config_out, &result_len, sizeof(struct NCS_port_config_s));

	cn_dev_cndev_debug(cndev_set,
		"rpc_cndev_cclink_port_info rpc_info.ret:%d result_len:%d",
		port_config_out.ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	/* get port mode */
	if (!port_config_out.ret && !port_config->ops_type) {
		port_config->support_mode_flags = port_config_out.support_mode_flags;
		port_config->current_mode_flags = port_config_out.current_mode_flags;
	}

	return port_config_out.ret > 0 ? -port_config_out.ret : port_config_out.ret;
}

int card_mlulink_switch_ctrl_common(void *cset, struct cndev_mlulink_switch_ctrl *mlulink_switch_ctrl)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	uint32_t result_len = sizeof(struct mlulink_switch_ctrl_s);
	int ret = 0;
	struct mlulink_switch_ctrl_s ctrl_in;
	struct mlulink_switch_ctrl_s ctrl_out;
	struct cn_core_set *core = NULL;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(mlulink_switch_ctrl))
		return -EINVAL;

	mlulink_switch_ctrl->head.version = CNDEV_CURRENT_VER;
	mlulink_switch_ctrl->head.real_size = sizeof(struct cndev_mlulink_switch_ctrl);

	if (mlulink_switch_ctrl->ops_type) {
		ctrl_in.ops = 1;
		ctrl_in.field = mlulink_switch_ctrl->field;
		ctrl_in.port_idx = mlulink_switch_ctrl->port_idx;
		ctrl_in.value = mlulink_switch_ctrl->value;
	} else {
		ctrl_in.ops = 0;
		ctrl_in.port_idx = mlulink_switch_ctrl->port_idx;
		ctrl_in.field = mlulink_switch_ctrl->field;
	}

	core = cndev_set->core;
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_cclink_switch_ctrl",
			(void *)&ctrl_in, sizeof(struct mlulink_switch_ctrl_s),
			(void *)&ctrl_out, &result_len, sizeof(struct mlulink_switch_ctrl_s));

	cn_dev_cndev_debug(cndev_set,
		"rpc_cndev_cclink_switch_ctrl rpc_info.ret:%d result_len:%d",
		ctrl_out.ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	/* get mlulink switch field value */
	if (!ctrl_out.ret && !mlulink_switch_ctrl->ops_type) {
		mlulink_switch_ctrl->value = ctrl_out.value;
	}

	return ctrl_out.ret;
}

int cndev_get_process_codec_info(struct cn_cndev_set *cndev_set)
{
	struct cn_core_set *core = NULL;
	struct pid_info_s *pid_info_node = NULL;
	struct cn_cndev_process_info *process_info = NULL;
	struct pid_info_s tmp;
	u32 process_num;
	int i = 0;
	u64 tgid = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	process_info = &cndev_set->process_info;
	if (IS_ERR_OR_NULL(process_info))
		return -EINVAL;

	tmp.tgid = current->tgid;
	tmp.active_ns = task_active_pid_ns(current);
	tmp.active_pid = task_tgid_nr_ns(current, tmp.active_ns);

	process_num = core->open_count;
	if (process_num) {
		spin_lock(&core->pid_info_lock);
		list_for_each_entry(pid_info_node, &core->pid_head, pid_list) {
			if (cn_check_curproc_is_docker(&tmp) && tmp.active_ns != pid_info_node->active_ns)
				continue;
			if (tmp.tgid == tmp.active_pid) {
				tgid = pid_info_node->tgid;
			} else {
				tgid = pid_info_node->active_pid;
			}
			process_info->codec[i].tgid = tgid;
			process_info->active_pid[i] = pid_info_node->active_pid;
			i++;
			if (i >= process_num || i >= CN_CNDEV_MAX_CODEC_PROCESS_NUM) {
				break;
			}
		}
		spin_unlock(&core->pid_info_lock);
	}
	process_info->process_num = i;
	return 0;
}

int cndev_get_process_codecutil_unit(struct cn_cndev_set *cndev_set, u32 buf_pos, u32 pid_unit)
{
	struct cn_core_set *core = NULL;
	struct cn_cndev_process_info *process_info = NULL;
	struct codec_pid_info pid_info;
	struct codec_process_util *util_info = NULL;
	u32 i = 0;
	int ret = 0;
	u32 result_len = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	process_info = &cndev_set->process_info;
	if (IS_ERR_OR_NULL(process_info))
		return -EINVAL;

	util_info = &process_info->util_info;
	memset(&pid_info, 0, sizeof(struct codec_pid_info));
	memset(util_info, 0, sizeof(struct codec_process_util));

	for (i = 0; i < pid_unit; i++) {
		pid_info.tgid[i] = process_info->active_pid[i + buf_pos];
	}
	pid_info.process_num = pid_unit;

	/* 4.call rpc to get util */
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_get_process_codecutil",
			(void *)&pid_info, sizeof(struct codec_pid_info),
			(void *)util_info, &result_len, sizeof(struct codec_process_util));
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}
	if (util_info->ret) {
		cn_dev_cndev_debug(cndev_set, "get process codec util info failed %d", util_info->ret);
	}
	for (i = 0; i < pid_unit; i++) {
		process_info->codec[i + buf_pos].vpu_enc_util = util_info->vpu_enc[i];
		process_info->codec[i + buf_pos].vpu_dec_util = util_info->vpu_dec[i];
		process_info->codec[i + buf_pos].jpu_util = util_info->jpu[i];
	}

	return ret;
}

int cndev_split_process_codecutil(struct cn_cndev_set *cndev_set)
{
	int ret = 0;
	struct cn_cndev_process_info *process_info = &cndev_set->process_info;
	u32 i = 0;
	u32 loop = 0;
	u32 remainder = 0;
	u32 buf_pos = 0;

	loop = process_info->process_num / MAX_PROCESS_CODEC_CNT;
	remainder = process_info->process_num % MAX_PROCESS_CODEC_CNT;

	for (i = 0; i < loop; i++) {
		buf_pos = i * MAX_PROCESS_CODEC_CNT;
		ret = cndev_get_process_codecutil_unit(cndev_set, buf_pos, MAX_PROCESS_CODEC_CNT);
		if (ret) {
			return ret;
		}
	}

	if (remainder) {
		buf_pos = loop * MAX_PROCESS_CODEC_CNT;
		ret = cndev_get_process_codecutil_unit(cndev_set, buf_pos, remainder);
		if (ret) {
			return ret;
		}
	}

	return ret;
}

int cndev_get_process_codecutil_common(void *cset, struct cndev_process_codecutil_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u16 vcard = 0;
	struct cn_cndev_process_info *process_info = &cndev_set->process_info;
	u32 copy_num = 0;

	if (IS_ERR_OR_NULL(process_info->codec) || IS_ERR_OR_NULL(process_info->active_pid))
		return -EINVAL;

	info->head.version = CNDEV_CURRENT_VER;
	info->head.real_size = sizeof(struct cndev_process_codecutil_info);

	/* 1.get vcard value */
	vcard = (info->head.card >> 8) & 0x0f;
	ret = cndev_vcard_trans(cndev_set, &vcard);
	if (ret) {
		return ret;
	}

	mutex_lock(&process_info->codec_mutex);

	/* 2.get process pid */
	cndev_get_process_codec_info(cndev_set);

	if (process_info->process_num && info->process_num) {
		/* 3.fill rpc msg */
		/* 4.call rpc to get util */
		ret = cndev_split_process_codecutil(cndev_set);
		if (!ret) {
			copy_num = (info->process_num < process_info->process_num) ?
				info->process_num : process_info->process_num;
			if (copy_to_user((void *)info->codec_util, process_info->codec,
				copy_num * sizeof(struct cndev_process_codecutil))) {
				cn_dev_cndev_err(cndev_set, "cndev copy_to_user failed");
				ret = -EFAULT;
			}
		}
	}

	info->process_num = process_info->process_num;

	mutex_unlock(&process_info->codec_mutex);

	return ret;
}

static int
__process_ipuutil_remove_duplicate(struct cndev_process_ipuutil *data, int size)
{
	int i = 0, j = 0;
	int index = 1;

	if (!size)
		return 0;

	for (i = 1; i < size; i++) {
		for (j = 0; j < index; j++) {
			if (data[i].tgid == data[j].tgid)
				break;
		}
		if (j == index) {
			data[index].tgid = data[j].tgid;
			data[index].util = data[j].util;
			index++;
		}
	}

	return index;
}

int cndev_get_process_ipuutil_common(void *cset, struct cndev_process_ipuutil_info *info)
{
	int ret = 0;
	struct cndev_process_ipuutil *util_data;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct cn_monitor_set *monitor_set = NULL;
	struct monitor_perf_set *perf_set = NULL;
	struct pid_info_s *pid_i = NULL;
	struct pid_namespace *active_ns;
	pid_t active_pid;
	bool in_docker = false;
	u32 proc_num;
	u16 smlu_instance_id = 0; /* 0 represents no specific instance */

	int retry = 10000;
	int index = 0;
	int process_num, copy;

	info->head.version = CNDEV_CURRENT_VER;
	info->head.real_size = sizeof(struct cndev_process_ipuutil_info);

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	monitor_set = core->monitor_set;
	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	perf_set = monitor_set->perf_set;
	if (IS_ERR_OR_NULL(perf_set))
		return -EINVAL;

	proc_num = core->open_count;
	if (!proc_num) {
		info->process_num = 0;
		info->total_util = 0;
		return 0;
	}

	/* for smlu, the total_util of ipu will store after the real_proc_num's util_data */
	util_data = cn_kzalloc(proc_num * sizeof(*util_data) + sizeof(u32), GFP_KERNEL);
	if (unlikely(!util_data)) {
		cn_dev_cndev_err(cndev_set, "malloc util_data buffer fail");
		return -ENOMEM;
	}

	/* try get from smlu first */
	if (cn_smlu_query_namespace_pid_infos(core, ipu_cgrp_id, smlu_instance_id,
			&proc_num, (struct smlu_proc_info *)util_data))
		goto ipu_stat;
	else {
		info->total_util = *((u32 *)(&util_data[proc_num]));
		index = proc_num;
		goto done;
	}
ipu_stat:
	/* check namespace */
	active_ns = task_active_pid_ns(current);
	active_pid = task_tgid_nr_ns(current, active_ns);
	if (active_pid != current->tgid) {
		in_docker = true;
	}

	ret = perf_process_util_update(monitor_set->perf_set, retry);
	if (unlikely(ret)) {
		cn_dev_cndev_info(cndev_set, "update process util return -EAGAIN retry");
		goto out;
	}

	info->total_util = perf_chip_util_get(perf_set);

	spin_lock(&core->pid_info_lock);
	list_for_each_entry(pid_i, &core->pid_head, pid_list) {
		if (in_docker && (active_ns != pid_i->active_ns)) {
			continue;
		}
		util_data[index].tgid = (in_docker) ? pid_i->active_pid : pid_i->tgid;
		util_data[index].util = perf_process_util_get(pid_info2tgid_entry(pid_i));
		index++;

		if (index >= proc_num)
			break;
	}
	spin_unlock(&core->pid_info_lock);

done:
	process_num = __process_ipuutil_remove_duplicate(util_data, index);
	copy = (process_num < info->process_num) ? process_num : info->process_num;
	info->process_num = process_num;

	if (copy_to_user((void *)info->ipu_util, (void *)util_data,
					sizeof(*util_data) * copy)) {
		cn_dev_cndev_err(cndev_set, "copy to user fail");
		ret = -EINVAL;
	}

out:
	cn_kfree(util_data);

	return ret;
}

int cndev_card_card_info_ext(void *cset,
	struct cndev_card_info_ext *ext_info)
{
	int result_len = 0;
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int ret;
	struct board_info_ext_s board_info_ext;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	ext_info->head.version = CNDEV_CURRENT_VER;
	ext_info->head.real_size = sizeof(struct cndev_card_info_ext);

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_get_card_info_ext",
			NULL, 0,
			(void *)&board_info_ext, &result_len, sizeof(struct board_info_ext_s));

	if (!board_info_ext.ret) {
		ext_info->pre_setting_info.pre_setting_ready =
			board_info_ext.pre_setting_info.pre_setting_ready;
		if (board_info_ext.pre_setting_info.pre_setting_ready) {
			ext_info->pre_setting_info.tdp =
				board_info_ext.pre_setting_info.tdp;
			ext_info->pre_setting_info.over_temp_duce_freq_temp =
				board_info_ext.pre_setting_info.over_temp_duce_freq_temp;
			ext_info->pre_setting_info.over_temp_poweroff_temp =
				board_info_ext.pre_setting_info.over_temp_poweroff_temp;
			ext_info->pre_setting_info.max_mem_temp =
				board_info_ext.pre_setting_info.max_mem_temp;
			ext_info->pre_setting_info.max_core_temp =
				board_info_ext.pre_setting_info.max_core_temp;
		}

		ext_info->mac_info.mac_addr_ready[0] =
			board_info_ext.mac_info.mac_addr_ready[0];
		if (board_info_ext.mac_info.mac_addr_ready[0]) {
			memcpy(ext_info->mac_info.card_mac_address[0],
				board_info_ext.mac_info.card_mac_address[0], 6);
		}

		ext_info->mac_info.mac_addr_ready[1] =
			board_info_ext.mac_info.mac_addr_ready[1];
		if (board_info_ext.mac_info.mac_addr_ready[1]) {
			memcpy(ext_info->mac_info.card_mac_address[1],
				board_info_ext.mac_info.card_mac_address[1], 6);
		}
	};

	return board_info_ext.ret;
}

int cndev_card_get_xid_common(void *cset, struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cndev_feature_get_xid xid_info;
	struct cn_core_set *core = NULL;
	struct cn_xid_set *xid_set = NULL;
	u32 cpsize = sizeof(struct cndev_feature_get_xid);

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	xid_set = (struct cn_xid_set *)core->xid_set;
	if (IS_ERR_OR_NULL(xid_set))
		return -EINVAL;

	cpsize = (cpsize < info->head.buf_size) ? cpsize : info->head.buf_size;
	if (IS_ERR_OR_NULL(info->DPTR))
		return -EINVAL;

	if (IS_ERR_OR_NULL(xid_set))
		return -EINVAL;

	if (cndev_cp_from_usr(info->DPTR, &xid_info, cpsize))
		return -EINVAL;

	switch (xid_info.select) {
	case XID_SELECT_XID:
		cn_get_xid_err(core, &xid_info.data.cn_xid.xid);
		break;
	case XID_SELECT_XIDS_STATUS:
	case XID_SELECT_XIDS_SWITCH:
		ret = cn_get_xid_status(core, &xid_info);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	ret |= cndev_cp_to_usr(info->DPTR, &xid_info, cpsize);
	return ret;
}

int cndev_card_set_xid_common(void *cset, struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cndev_feature_set_xid xid_info;
	struct cn_core_set *core = NULL;
	u32 cpsize = sizeof(struct cndev_feature_set_xid);

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	if (IS_ERR_OR_NULL(info->DPTR))
		return -EINVAL;

	if (cndev_cp_from_usr(info->DPTR, &xid_info, cpsize))
		return -EINVAL;

	switch (xid_info.ctrl) {
	case XID_CTRL_CLEAR:
		cn_clear_xid_common(core, &xid_info);
		break;
	case XID_CTRL_ENABLE:
		cn_enable_xid_common(core, &xid_info);
		break;
	case XID_CTRL_DISABLE:
		cn_disable_xid_common(core, &xid_info);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

int cndev_card_get_computing_power_common(void *cset, struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cndev_feature_get_computing_power computing_power;
	struct cn_core_set *core = NULL;
	struct cn_monitor_set *monitor_set = NULL;
	u32 cpsize = sizeof(struct cndev_feature_get_computing_power);
	u64 real_num = 0;

	cpsize = (cpsize < info->head.buf_size) ? cpsize : info->head.buf_size;
	if (IS_ERR_OR_NULL(info->DPTR))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	monitor_set = core->monitor_set;
	if (IS_ERR_OR_NULL(monitor_set))
		return -EINVAL;

	if (cndev_cp_from_usr(info->DPTR, &computing_power, cpsize))
		return -EINVAL;

	real_num = computing_power.num > CNDEV_MAX_COMPUTING_POWER_TYPE ? CNDEV_MAX_COMPUTING_POWER_TYPE : computing_power.num;
	if (real_num) {
		ret = cndev_cp_to_usr(computing_power.buffer, device_computing_power[monitor_set->board_type], real_num * sizeof(u64));
	}

	computing_power.num = real_num;

	ret |= cndev_cp_to_usr(info->DPTR, &computing_power, cpsize);

	return ret;
}

int cndev_card_exclusive_mode_common(void *cset, int ops, struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct cndev_feature_exclusive_mode ex_mode;
	u32 cpsize = sizeof(struct cndev_feature_exclusive_mode);

	cpsize = (cpsize < info->head.buf_size) ? cpsize : info->head.buf_size;
	if (IS_ERR_OR_NULL(info->DPTR))
		return -EINVAL;

	if (cndev_cp_from_usr(info->DPTR, &ex_mode, cpsize))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	if (ops == CNDEV_GET_EXCLUSIVE_MODE) {
		ex_mode.mode = cn_core_get_execute_mode(core);
		ret = cndev_cp_to_usr(info->DPTR, &ex_mode, cpsize);
	} else if (ops == CNDEV_SET_EXCLUSIVE_MODE) {
		ret = cn_core_set_execute_mode(core, ex_mode.mode);
	} else {
		return -EINVAL;
	}

	return ret;
}

int cndev_card_sriov_mode_common(void *cset, int ops, struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct cndev_feature_sriov_mode sriov_mode;
	u32 cpsize = sizeof(struct cndev_feature_sriov_mode);

	cpsize = (cpsize < info->head.buf_size) ? cpsize : info->head.buf_size;
	if (IS_ERR_OR_NULL(info->DPTR))
		return -EINVAL;

	if (cndev_cp_from_usr(info->DPTR, &sriov_mode, cpsize))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	sriov_mode.head.version = CNDEV_MIM_VERSION_1;
	sriov_mode.head.size = sizeof(struct cndev_feature_sriov_mode);

	if (ops == CNDEV_GET_SRIOV_MODE) {
		ret = cn_dm_is_sriov_enable(core);
		if (ret >= 0) {
			sriov_mode.mode = ret;
			ret = cndev_cp_to_usr(info->DPTR, &sriov_mode, cpsize);
		}
	} else if (ops == CNDEV_SET_SRIOV_MODE) {
		if (sriov_mode.mode) {
			ret = cn_dm_enable_sriov(core);
		} else {
			ret = cn_dm_disable_sriov(core);
		}
	} else {
		return -EINVAL;
	}

	return ret;
}

int cndev_card_set_mim_vmlu_common(void *cset,
	struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct cndev_feature_mim_vmlu vmlu;
	u32 cpsize = sizeof(struct cndev_feature_mim_vmlu);
	int instance_id = 0;

	cpsize = (cpsize < info->head.buf_size) ? cpsize : info->head.buf_size;
	if (IS_ERR_OR_NULL(info->DPTR))
		return -EINVAL;

	if (cndev_cp_from_usr(info->DPTR, &vmlu, cpsize))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	vmlu.head.version = CNDEV_MIM_VERSION_1;
	vmlu.head.size = sizeof(struct cndev_feature_mim_vmlu);

	if (vmlu.ops == CNDEV_CREATE_VMLU) {
		instance_id = cn_dm_create_mlu_instance(core, vmlu.create_mi.profile_id);
		if (instance_id >= 0) {
			vmlu.create_mi.instance_id = instance_id;
			ret = cndev_cp_to_usr(info->DPTR, &vmlu, cpsize);
		} else {
			ret = instance_id;
		}
	} else if (vmlu.ops == CNDEV_CREATE_VMLU_WITH_PLACE) {
		instance_id = cn_dm_create_mlu_instance_with_placement(core,
			vmlu.create_mi_with_place.profile_id,
			vmlu.create_mi_with_place.placement.start);
		if (instance_id >= 0) {
			vmlu.create_mi.instance_id = instance_id;
			ret = cndev_cp_to_usr(info->DPTR, &vmlu, cpsize);
		} else {
			ret = instance_id;
		}
	} else if (vmlu.ops == CNDEV_DESTROY_VMLU) {
		ret = cn_dm_destroy_mlu_instance(core, vmlu.destroy_mi.instance_id);
	} else {
		return -EINVAL;
	}

	return ret;
}

int cndev_card_get_mim_vmlu_info_common(void *cset,
	struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct cndev_feature_mim_vmlu_info vmlu_info = {};
	struct cndev_instance_info *ins_info = NULL;
	struct mlu_instance_info *mi_info = NULL;
	int i = 0;
	int total_mi = 0;
	u32 cpsize = sizeof(struct cndev_feature_mim_vmlu_info);
	u32 data_num = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	cpsize = (cpsize < info->head.buf_size) ? cpsize : info->head.buf_size;
	if (IS_ERR_OR_NULL(info->DPTR))
		return -EINVAL;

	if (cndev_cp_from_usr(info->DPTR, &vmlu_info, cpsize))
		return -EINVAL;

	if (!vmlu_info.select)
		data_num = CNDEV_MAX_INSTANCE_COUNT;
	else
		data_num = 1;

	mi_info = cn_kzalloc(sizeof(struct mlu_instance_info) * data_num, GFP_KERNEL);
	if (!mi_info) {
		ret = -ENOMEM;
		goto out;
	}

	ins_info = cn_kzalloc(sizeof(struct cndev_instance_info) * data_num, GFP_KERNEL);
	if (!ins_info) {
		ret = -ENOMEM;
		goto err_1;
	}

	vmlu_info.head.version = CNDEV_MIM_VERSION_1;
	vmlu_info.head.size = sizeof(struct cndev_feature_mim_vmlu_info);

	if (vmlu_info.select) {
		ret = cn_dm_query_mlu_instance_info(core, vmlu_info.instance_id, mi_info);
		if (!ret) {
			ins_info->instance_id = vmlu_info.instance_id;
			ins_info->profile_id = mi_info->profile_id;
			ins_info->bus = mi_info->bus_num;
			ins_info->device = (mi_info->devfn >> 3) & 0x1f;
			ins_info->function = mi_info->devfn & 0x7;
			ins_info->placement.size = mi_info->placement.size;
			ins_info->placement.start = mi_info->placement.start;
			ins_info->domain = mi_info->domain_nr;
			memcpy(ins_info->ipcm_device_name, mi_info->ipcm_device_name, DRIVER_IPCM_DEV_NAME_SIZE);
			memcpy(ins_info->device_name, mi_info->device_name, CNDEV_DEVICE_NAME_LEN);
			memcpy(ins_info->uuid, cndev_set->card_static_info.uuid, DRIVER_PMU_UUID_SIZE);

			ins_info->uuid[9] = vmlu_info.instance_id;
			if (vmlu_info.instance_num)
				ret = cndev_cp_to_usr(vmlu_info.instance_info, ins_info,
					sizeof(struct cndev_instance_info));

			vmlu_info.instance_num = 1;
			ret |= cndev_cp_to_usr(info->DPTR, &vmlu_info, cpsize);
		}
	} else {
		if (!capable(CAP_SYS_ADMIN)) {
			cn_dev_warn("Permission denied");
			ret = -EACCES;
			goto exit;
		}
		ret = cn_dm_query_all_mlu_instance_info(core, &total_mi, mi_info);
		if (!ret) {
			total_mi = total_mi > CNDEV_MAX_INSTANCE_COUNT ? CNDEV_MAX_INSTANCE_COUNT : total_mi;
			for (i = 0; i < total_mi; i++) {
				ins_info[i].profile_id = mi_info[i].profile_id;
				ins_info[i].instance_id = mi_info[i].mlu_instance_id;
				ins_info[i].bus = mi_info[i].bus_num;
				ins_info[i].device = (mi_info[i].devfn >> 3) & 0x1f;
				ins_info[i].function = mi_info[i].devfn & 0x7;
				ins_info[i].placement.size = mi_info[i].placement.size;
				ins_info[i].placement.start = mi_info[i].placement.start;
				memcpy(ins_info[i].uuid, cndev_set->card_static_info.uuid, DRIVER_PMU_UUID_SIZE);
				ins_info[i].uuid[9] = mi_info[i].mlu_instance_id;
				ins_info[i].domain = mi_info[i].domain_nr;
				memcpy(ins_info[i].ipcm_device_name, mi_info[i].ipcm_device_name, DRIVER_IPCM_DEV_NAME_SIZE);
				memcpy(ins_info[i].device_name, mi_info[i].device_name, CNDEV_DEVICE_NAME_LEN);
			}

			if (vmlu_info.instance_num)
				ret = cndev_cp_less_val(&vmlu_info.instance_num, total_mi,
					vmlu_info.instance_info, ins_info,
					sizeof(struct cndev_instance_info));

			vmlu_info.instance_num = total_mi;
			ret |= cndev_cp_to_usr(info->DPTR, &vmlu_info, cpsize);
		}
	}

exit:
	cn_kfree(ins_info);
err_1:
	cn_kfree(mi_info);
out:
	return ret;
}

int cndev_card_set_smlu_common(void *cset,
	struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct cndev_feature_smlu smlu;
	u32 cpsize = sizeof(struct cndev_feature_smlu);
	int cgrp_id = 0;

	cpsize = (cpsize < info->head.buf_size) ? cpsize : info->head.buf_size;
	if (IS_ERR_OR_NULL(info->DPTR))
		return -EINVAL;

	if (cndev_cp_from_usr(info->DPTR, &smlu, cpsize))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	smlu.head.version = CNDEV_SMLU_VERSION_2;
	smlu.head.size = sizeof(struct cndev_feature_smlu);

	if (smlu.ops == CNDEV_CREATE_SMLU_CGROUP) {
		u32 profile_id = smlu.create_cgrp.profile_id;
		struct smlu_profile_info profile_info = {0};
		struct cndev_smlu_cgroup_info res = {0};

		ret = cn_smlu_query_profile_info(core, profile_id, &profile_info);
		if (ret) {
			cn_dev_core_err(core, "query profile info failed");
			return -EINVAL;
		}

		if (profile_info.remain_capacity == 0) {
			cn_dev_core_err(core, "remain capacity insufficient");
			return -EFAULT; /* -EFAULT represents exceed, be consistent with cnmon */
		}

		memcpy(res.cgroup_item, profile_info.profile_res, sizeof(res.cgroup_item));
		res.profile_id = profile_id;
		cgrp_id = cn_smlu_cap_node_init(core, &res);
		if (cgrp_id >= 0) {
			smlu.create_cgrp.cgrp_id = cgrp_id;
			ret = cndev_cp_to_usr(info->DPTR, &smlu, cpsize);
		} else {
			ret = cgrp_id;
		}
	} else if (smlu.ops == CNDEV_DESTROY_SMLU_CGROUP) {
		ret = cn_smlu_cap_node_exit(core, smlu.destroy_cgrp.cgrp_id);
	} else {
		cn_dev_core_err(core, "invalid smlu.ops %d", smlu.ops);
		return -EINVAL;
	}

	return ret;
}

int cndev_card_get_smlu_info_common(void *cset, struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	/* compat for mim_vmlu */
	struct cndev_feature_smlu_info smlu_info = {};
	struct cndev_smlu_cgroup_info *cgroup_info = NULL;
	u32 cpsize = sizeof(struct cndev_feature_smlu_info);
	u32 data_num = 0;

	cpsize = (cpsize < info->head.buf_size) ? cpsize : info->head.buf_size;
	if (IS_ERR_OR_NULL(info->DPTR))
		return -EINVAL;

	if (cndev_cp_from_usr(info->DPTR, &smlu_info, cpsize))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	if (!smlu_info.select)
		data_num = CNDEV_MAX_INSTANCE_COUNT;
	else
		data_num = 1;

	cgroup_info = cn_kzalloc(sizeof(struct cndev_smlu_cgroup_info) * data_num, GFP_KERNEL);
	if (!cgroup_info)
		return -ENOMEM;

	smlu_info.head.version = CNDEV_SMLU_VERSION_2;
	smlu_info.head.size = sizeof(struct cndev_feature_smlu_info);

	if (smlu_info.select) {
		cgroup_info->cgrp_id = smlu_info.instance_id;
		ret = cn_smlu_query_instance(core, cgroup_info);
		if (!ret) {
			if (smlu_info.instance_num)
				ret = cndev_cp_to_usr(smlu_info.instance_info, cgroup_info, sizeof(struct cndev_smlu_cgroup_info));

			smlu_info.instance_num = 1;
			ret |= cndev_cp_to_usr(info->DPTR, &smlu_info, cpsize);
		}
	} else {
		if (!capable(CAP_SYS_ADMIN)) {
			cn_dev_warn("Permission denied");
			ret = -EACCES;
			goto exit;
		}
		/* data_num will be update to real number */
		ret = cn_smlu_query_all_instances(core, &data_num, cgroup_info);
		if (!ret) {
			if (smlu_info.instance_num)
				ret = cndev_cp_less_val(&smlu_info.instance_num, data_num,
					smlu_info.instance_info, cgroup_info,
					sizeof(struct cndev_smlu_cgroup_info));

			smlu_info.instance_num = data_num;
			ret |= cndev_cp_to_usr(info->DPTR, &smlu_info, cpsize);
		}
	}

exit:
	cn_kfree(cgroup_info);
	return ret;
}

int cndev_card_get_feature_common(void *cset, struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	info->head.version = CNDEV_CURRENT_VER;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	switch (info->FID)
	{
	case CN_FEAT_XID:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_get_xid);
		ret = cndev_card_get_xid_common(cset, info);
		break;
	case CN_FEAT_CMP_PW:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_get_computing_power);
		ret = cndev_card_get_computing_power_common(cset, info);
		break;
	case CN_FEAT_EXCLUSIVE_MOD:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_exclusive_mode);
		ret = cndev_card_exclusive_mode_common(cset, CNDEV_GET_EXCLUSIVE_MODE, info);
		break;
	case CN_FEAT_SRIOV_MOD:
		info->SUP = 0;
		info->head.real_size = sizeof(struct cndev_feature_sriov_mode);
		break;
	case CN_FEAT_MIM_VMLU:
		info->SUP = 0;
		info->head.real_size = sizeof(struct cndev_feature_mim_vmlu);
		break;
	case CN_FEAT_SMLU:
		info->SUP = cn_is_smlu_support(core);
		info->head.real_size = sizeof(struct cndev_feature_smlu_info);
		if (info->SUP) {
			ret = cndev_card_get_smlu_info_common(cset, info);
		} else {
			ret = 0;
		}
		break;
	default:
		ret = 0;
		info->SUP = 0;
		break;
	}

	return ret;
}

#define CNDEV_MAX_PLACE_COUNT 64

int cndev_card_get_mim_profile_info_common(void *cset,
	struct cndev_mim_profile_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct mlu_instance_profile_info mi_profile_info = {0};
	u32 copy_size = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	ret = cn_dm_query_mlu_instance_profile_info(core, info->profile, &mi_profile_info);

	switch (ret) {
		case 0:
			info->profile_id = mi_profile_info.profile_id;
			info->ipu_count = mi_profile_info.ipu_num;
			info->vpu_count = mi_profile_info.vpu_num;
			info->jpu_count = mi_profile_info.jpu_num;
			info->gdma_count = mi_profile_info.gdma_num;
			info->mem_size = mi_profile_info.mem_size;
			info->profile_name_size = CNDEV_MAX_PROFILE_NAME_SIZE;
			copy_size = info->profile_name_size > CNDEV_MAX_PROFILE_NAME_SIZE ?
				CNDEV_MAX_PROFILE_NAME_SIZE : info->profile_name_size;
			ret = cndev_cp_to_usr(info->name, &mi_profile_info.name, copy_size);
		break;
		case 1:
			ret = -EPERM;
		break;
		default:
			ret = -EINVAL;
		break;
	}

	return ret;
}

int cndev_card_get_mim_possible_place_info_common(void *cset,
	struct cndev_mim_possible_place_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct mlu_instance_placement *mi_placement = NULL;
	u32 copy_size = 0;
	int mi_place_count = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	mi_placement = (struct mlu_instance_placement *)cn_kzalloc(
		CNDEV_MAX_PLACE_COUNT * sizeof(struct mlu_instance_placement), GFP_KERNEL);
	if (!mi_placement) {
		cn_dev_cndev_err(cndev_set, "alloc memory fail");
		ret = -ENOMEM;
		goto PIERR;
	}

	ret = cn_dm_query_mlu_instance_possible_placement(core,
		info->profile_id, &mi_place_count, mi_placement);
	if (!ret) {
		copy_size = mi_place_count > CNDEV_MAX_PLACE_COUNT ?
		CNDEV_MAX_PLACE_COUNT : mi_place_count;
		ret = cndev_cp_less_val(
			&info->count, copy_size,
			info->place_info, mi_placement,
			sizeof(struct cndev_mim_vmlu_placement));
		info->count = copy_size;
	}

	cn_kfree(mi_placement);
PIERR:
	return ret;
}

int cndev_card_get_mim_vmlu_capacity_info_common(void *cset,
	struct cndev_mim_vmlu_capacity_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int count = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	count = cn_dm_query_profile_available_mlu_instance_num(core, info->profile_id);
	if (count >= 0) {
		info->count = (u32)count;
		ret = 0;
	} else {
		ret = -EINVAL;
	}

	return ret;
}

int cndev_card_get_mim_device_info_common(void *cset,
	struct cndev_mim_device_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	int count = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	count = cn_dm_query_profile_total_mlu_instance_num(core, info->profile_id);
	if (count >= 0) {
		info->max_dev_count = (u32)count;
		ret = 0;
	} else {
		ret = -EINVAL;
	}

	return ret;
}

int cndev_card_get_desc_common(void *cset, struct cndev_mi_card *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u32 mlu_instance_mask = 0;
	u32 mi_on_docker_mask = 0;

	ret = cn_dm_query_mlu_instance_mask(cndev_set->core, &mlu_instance_mask);
	if (!ret) {
		info->virt_card_mask = mlu_instance_mask;
		info->vf_count = bitmap_weight((unsigned long *)&info->virt_card_mask, 64);
	} else {
		return ret;
	}

	ret = cn_dm_query_onhost_mlu_instance_mask(cndev_set->core, &mi_on_docker_mask);
	if (!ret) {
		info->mi_on_docker_mask = mi_on_docker_mask;
	} else {
		return ret;
	}

	return 0;
}

int cndev_card_get_cntr_info_common(void *cset, struct cndev_cntr_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct cndev_cntr_rpc_info cache_info = {};
	struct cndev_rpc_head cmd;
	uint32_t result_len = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	/* fill head */
	info->head.version = CNDEV_CURRENT_VER;
	info->head.real_size = sizeof(struct cndev_cntr_info);

	/* pack rpc cmd */
	cmd.version = 0;
	cmd.cmd = CNDEV_RPC_CMD_GET_ERR_CNT;
	cmd.size = sizeof(struct cndev_rpc_head);

	/* rpc call */
	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_common",
			(void *)&cmd, sizeof(struct cndev_rpc_head),
			(void *)&cache_info, &result_len, sizeof(struct cndev_cntr_rpc_info));

	/* res check */
	if (cache_info.head.res || ret) {
		cn_dev_cndev_err(cndev_set, "cndev rpc res %d %d", cache_info.head.res , ret);
		return -EINVAL;
	} else {
		info->parity_err_cntr = cache_info.parity_err_cntr;
	}

	return 0;
}

int cndev_checkstate_common(void *core_set)
{
	struct cn_core_set *core = (struct cn_core_set *)core_set;

	if (IS_ERR_OR_NULL(core))
		return -EINVAL;

	spin_lock(&core->pid_info_lock);
	if (core->state != CN_RUNNING) {
		spin_unlock(&core->pid_info_lock);
		return -EINVAL;
	}
	spin_unlock(&core->pid_info_lock);

	return 0;
}

int cndev_card_set_feature_common(void *cset, struct cndev_feature *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	info->head.version = CNDEV_CURRENT_VER;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	switch (info->FID)
	{
	case CN_FEAT_XID:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_set_xid);
		ret = cndev_card_set_xid_common(cset, info);
		break;
	case CN_FEAT_CMP_PW:
		info->SUP = 0;
		break;
	case CN_FEAT_EXCLUSIVE_MOD:
		info->SUP = 1;
		info->head.real_size = sizeof(struct cndev_feature_exclusive_mode);
		ret = cndev_card_exclusive_mode_common(cset, CNDEV_SET_EXCLUSIVE_MODE, info);
		break;
	case CN_FEAT_SRIOV_MOD:
		info->SUP = 0;
		info->head.real_size = sizeof(struct cndev_feature_sriov_mode);
		break;
	case CN_FEAT_MIM_VMLU:
		info->SUP = 0;
		info->head.real_size = sizeof(struct cndev_feature_mim_vmlu);
		break;
	case CN_FEAT_SMLU:
		info->SUP = cn_is_smlu_support(core);
		info->head.real_size = sizeof(struct cndev_feature_smlu);
		if (info->SUP) {
			ret = cndev_card_set_smlu_common(cset, info);
		} else {
			ret = 0;
		}
		break;
	default:
		ret = 0;
		info->SUP = 0;
		break;
	}

	return ret;
}

/* smlu cap */
int cndev_card_get_smlu_profile_id_common(void *cset,
	struct cndev_smlu_profile_id *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	u32 *profile_id;
	u32 count = MAX_SMLU_PROFILE_COUNT;
	u32 copy_size = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	profile_id = (u32 *)cn_kzalloc(sizeof(u32) * count, GFP_KERNEL);
	if (!profile_id) {
		cn_dev_cndev_err(cndev_set, "alloc memory fail");
		return -ENOMEM;
	}

	ret = cn_smlu_query_available_profile_id(core, profile_id, &count);

	switch (ret) {
		case 0:
			info->profile_count = count;

			copy_size = min(count, info->profile_count) * sizeof(u32);
			ret = cndev_cp_to_usr(info->profile_id, profile_id, copy_size);
		break;
		case 1:
			ret = -EPERM;
		break;
		default:
			ret = -EINVAL;
		break;
	}

	cn_kfree(profile_id);
	return ret;
}

int cndev_card_get_smlu_profile_info_common(void *cset,
	struct cndev_smlu_profile_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct smlu_profile_info profile_info = {0};
	u32 copy_size = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	ret = cn_smlu_query_profile_info(core, info->profile, &profile_info);

	switch (ret) {
		case 0:
			info->profile_id = profile_info.profile_id;
			info->total_capacity = profile_info.total_capacity;
			info->remain_capacity = profile_info.remain_capacity;

			copy_size = min(sizeof(info->profile_res), sizeof(profile_info.profile_res));
			memcpy(info->profile_res, profile_info.profile_res, copy_size);

			copy_size = min((__u32)info->profile_name_size, (__u32)CNDEV_MAX_PROFILE_NAME_SIZE);
			info->profile_name_size = CNDEV_MAX_PROFILE_NAME_SIZE;
			ret = cndev_cp_to_usr(info->profile_name, profile_info.profile_name, copy_size);
		break;
		case 1:
			ret = -EPERM;
		break;
		default:
			ret = -EINVAL;
		break;
	}

	return ret;
}

int cndev_card_new_smlu_profile_common(void *cset,
	struct cndev_smlu_profile_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;
	struct smlu_profile_info profile_info = {0};
	struct cndev_smlu_cgroup_info res = {0};
	u32 copy_size = 0;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	memcpy(res.cgroup_item, info->profile_res, sizeof(res.cgroup_item));
	ret = cn_smlu_new_profile(core, &res, &profile_info);
	if (ret) {
		cn_dev_cndev_err(cndev_set, "cn_smlu_new_profile failed");
		return -EINVAL;
	}

	info->profile_id = profile_info.profile_id;
	info->total_capacity = profile_info.total_capacity;
	info->remain_capacity = profile_info.remain_capacity;

	copy_size = min((__u32)info->profile_name_size, (__u32)CNDEV_MAX_PROFILE_NAME_SIZE);
	info->profile_name_size = CNDEV_MAX_PROFILE_NAME_SIZE;
	ret = cndev_cp_to_usr(info->profile_name, profile_info.profile_name, copy_size);

	return ret;
}

int cndev_card_delete_smlu_profile_common(void *cset,
	struct cndev_smlu_profile_info *info)
{
	int ret = 0;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *core = NULL;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EINVAL;

	core = (struct cn_core_set *)cndev_set->core;
	if (IS_ERR_OR_NULL(core)) {
		cn_dev_cndev_err(cndev_set, "cndev core null");
		return -EINVAL;
	}

	ret = cn_smlu_delete_profile(core, info->profile_id);
	if (ret) {
		cn_dev_cndev_err(cndev_set, "cn_smlu_delete_profile failed");
		return -EINVAL;
	}

	return ret;
}

int cndev_rpc_lateinit(void *cset)
{
	uint32_t result_len = sizeof(int);
	int ret = 0;
	int res = 0;
	struct cn_cndev_lateset rpc_info;
	struct cn_core_set *core = NULL;
	struct bus_info_s bus_info;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	memset(&rpc_info, 0, sizeof(struct cn_cndev_lateset));
	memset(&bus_info, 0, sizeof(struct bus_info_s));
	cn_bus_get_bus_info(core->bus_set, &bus_info);

	rpc_info.bus = bus_info.info.pcie.bus_num;
	rpc_info.device = (bus_info.info.pcie.device_id >> 3) & 0x1f;
	rpc_info.func = bus_info.info.pcie.device_id & 0x07;
	rpc_info.domain = bus_info.info.pcie.domain_id << 16;
	rpc_info.driver_major_ver = DRV_MAJOR;
	rpc_info.driver_minor_ver = DRV_MINOR;
	rpc_info.driver_build_ver = DRV_BUILD;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_lateinit",
			(void *)&rpc_info, sizeof(struct cn_cndev_lateset),
			&res, &result_len, sizeof(int));

	cn_dev_cndev_debug(cndev_set, "cndev lateinit res:%d result_len:%d"
			, res, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		return ret;
	}

	return res;
}

int cndev_rpc_dev_info(void *cset, struct board_info_s *brdinfo_rmt, u16 vcard)
{
	int ret = 0;
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	int result_len = 0;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	if (IS_ERR_OR_NULL(brdinfo_rmt))
		return -EINVAL;

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_basic_info",
		(void *)&vcard, sizeof(u16),
		(void *)brdinfo_rmt, &result_len, sizeof(struct board_info_s));
	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call failed, ret = %d", ret);
	}

	return ret;
}

int cndev_rpc_resource(void *cset)
{
	uint32_t result_len = sizeof(int);
	int ret = 0;
	struct cn_cndev_resource *resource = NULL;
	struct cn_core_set *core = NULL;
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	u32 max_count = 0;
	const u32 request_size = RES_BASIC_INFO_END;

	CHECK_CNDEV_EP_NULL(cndev_set, core);

	result_len = sizeof(struct cn_cndev_resource)
			+ request_size * sizeof(u64);
	resource = (struct cn_cndev_resource *)cn_kzalloc(result_len, GFP_KERNEL);
	if (!resource) {
		cn_dev_cndev_err(cndev_set, "alloc memory fail");
		ret = -ENOMEM;
		goto out;
	}

	ret = __pmu_call_rpc(core, cndev_set->endpoint, "rpc_cndev_get_resource",
		(void *)&request_size, sizeof(u32),
		(void *)resource, &result_len,
		result_len);

	cn_dev_cndev_debug(cndev_set, "cndev resource ret:%d result_len:%d"
		, ret, result_len);

	if (ret < 0) {
		cn_dev_cndev_err(cndev_set, "call commu failed");
		goto free_out;
	} else {
		max_count = resource->count > request_size ? request_size : resource->count;
		cn_attr_fill_resource(core, resource->resource, max_count);
	}

	ret = resource->ret;
	cn_kfree(resource);

	return ret;

free_out:
	cn_kfree(resource);
out:
	return ret;
}

int cndev_rpc_client_register(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;

	if (IS_ERR_OR_NULL(cndev_set))
		return -EFAULT;

	cndev_set->endpoint = __pmu_open_channel("cndev-krpc", core);
	if (IS_ERR_OR_NULL(cndev_set->endpoint)) {
		cn_xid_err(core, XID_RPC_ERR, "open commu channel failed");
		return -EFAULT;
	}

	return 0;
}

int cndev_lateinit_common(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_cndev_set *cndev_set
		= (struct cn_cndev_set *)core->cndev_set;
	int ret = 0;

	ret = cndev_rpc_client_register(pcore);
	if (ret) {
		cn_dev_cndev_err(cndev_set, "cndev rpc call commu register failed");
		goto out;
	}

	ret = cndev_rpc_resource(cndev_set);
	if (ret) {
		cn_dev_cndev_err(cndev_set, "cndev get resource failed");
		goto out;
	}

out:
	return ret;
}

int cndev_restart_common(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;

	if (!cndev_set) {
		return 0;
	}

	hrtimer_start(&cndev_set->hrtimer,
		cndev_set->time_delay,
		HRTIMER_MODE_REL);
	return 0;
}

void cndev_stop_common(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *pcore = NULL;

	if (!cndev_set) {
		return;
	}

	pcore = cndev_set->core;

	if (cndev_set->endpoint) {
		__pmu_disconnect(cndev_set->endpoint, pcore);
		cndev_set->endpoint = NULL;
	}

	hrtimer_cancel(&cndev_set->hrtimer);
}

void cndev_exit_common(void *cset)
{
	struct cn_cndev_set *cndev_set = (struct cn_cndev_set *)cset;
	struct cn_core_set *pcore = NULL;

	if (!cndev_set) {
		return;
	}

	pcore = cndev_set->core;

	if (cndev_set) {
		hrtimer_cancel(&cndev_set->hrtimer);
	}

	cndev_set->ops = NULL;
	cndev_set->ioctl = NULL;
}
