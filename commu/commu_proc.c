#include "cndrv_debug.h"
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include "commu_internal.h"
#include "commu_init.h"
#include "cndrv_commu.h"

static void dump_mem(const char *tag, u8 *pdata, u32 nsize)
{
	int i = 0;
	printk("[COMMU]dumpmem: %s\n", tag);
	for (i = 0; i < nsize;) {
		printk(KERN_CONT "%02x ", pdata[i]);
		if (++i % 16 == 0)
			printk(KERN_CONT "\n");
	}
	if (i % 16 != 0)
		printk(KERN_CONT "\n");
}

static inline uint64_t rte_rdtsc(void)
{
#if defined(__x86_64__)
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

	__asm volatile("rdtsc" :
		     "=a" (tsc.lo_32),
		     "=d" (tsc.hi_32));
	return tsc.tsc_64;
#elif defined(__aarch64__)
	uint64_t tsc;

	asm volatile("mrs %0, cntvct_el0" : "=r" (tsc));
	return tsc;
#else
	return 0;
#endif
}

static inline void commu_ctrlq_all_dump(struct commu_set *controller)
{
	pr_info("===========ctrlq dump begin===============\n");
	pr_info("current tx status:\n"
			"lh%u lt%u rh%u rt%u\n",
			controller->ctrlq_send->head,
			controller->ctrlq_send->tail,
			*(controller->ctrlq_send->shadow_head),
			*(controller->ctrlq_send->shadow_tail));
	pr_info("current rx status:\n"
			"lh%u lt%u rh%u rt%u\n",
			controller->ctrlq_recv->head,
			controller->ctrlq_recv->tail,
			*(controller->ctrlq_recv->shadow_head),
			*(controller->ctrlq_recv->shadow_tail));
	/*
	 *dump_mem("ctrlq rx ring", (char *)controller->ctrlq_recv->ring,
	 *                sizeof(struct ctrlq_desc) * 32 + 8);
	 *dump_mem("ctrlq tx ring", (char *)controller->ctrlq_send->ring,
	 *                sizeof(struct ctrlq_desc) * 32 + 8);
	 */
	pr_info("===========ctrlq dump finished=============\n");

}

#define COMMU_CPU_FREQUENCY  3700
static struct commu_endpoint *ep;
int commu_proc_command_with_num(struct commu_set *controller, int data)
{
	struct commu_channel *channel;
	uint64_t counter_begin, counter_end;

	if (data == 1) {
		channel = open_a_channel("test", controller, 0);
		ep = connect_rpc_endpoint(channel);
	} else if (data == 2) {
		channel = open_a_channel("test", controller, 0);
		ep = connect_msg_endpoint(channel);
	} else if (data == 3) {
		channel = open_a_channel("cambricon", controller, 0);
		ep = connect_rpc_endpoint(channel);
	} else if (data == 4) {
		char tmp[100];
		int out;
		int i;
		u64 sum = 0;
		for (i = 0; i < 1024; i++) {
		counter_begin = rte_rdtsc();
		if (ep)
			commu_call_rpc(ep, "commu_test", tmp, 1, tmp, &out);
		counter_end = rte_rdtsc();
		pr_info("thread %d cycles: %llu time: %llu us\n", current->pid, counter_end - counter_begin,
				(counter_end - counter_begin) / (COMMU_CPU_FREQUENCY));
		sum += counter_end - counter_begin;
		}
		pr_info("thread %d all time: %llu average time: %llu us\n", current->pid, sum / COMMU_CPU_FREQUENCY,
				sum / (COMMU_CPU_FREQUENCY * 1024));
		//dump_mem("call rpc", tmp, 20);
	} else if (data == 5) {
		char tmp[100];
		int out;
		memset(tmp, 0x0, 100);
		memcpy(tmp, "message from vf", strlen("message from vf"));
		commu_send_message(ep, tmp, 20);
		commu_wait_for_message(ep, tmp, &out);

		dump_mem("recv message", tmp, 20);
	} else if (data == 6) {
		/* DEBUG only: print endpoint head/tails */
		struct llist_head *head;
		struct llist_node *first;
		u64 hash_name = commu_string_hash("test");

		//hash_for_each_possible(name, obj, member, key)
		//hash_for_each_possible(commu_channel_head, channel, channel_node, hash_name)

		hlist_for_each_entry(channel,
				&controller->commu_channel_head[hash_min(hash_name, 8)], channel_node) {
			if (channel->hash_name == hash_name) {
				break;
			}
		}

		COMMU_DBG("==%s --- %px --- %llx\n", __func__, channel, hash_name);

		head = &channel->channel_endpoints_head;
		first = head->first;
		ep = llist_entry((first), typeof(*ep), channel_node);
		pr_info("%s -- tx local head %u local tail%u\n"
			"remot head %u remot tail%u\n"
			"rx local head %u local tail%u\n"
			"remot head %u remot tail%u\n",
			__func__,
			*(u32 *)ep->tx.ops->head_addr(ep->tx.real_queue),
			*(u32 *)ep->tx.ops->tail_addr(ep->tx.real_queue),
			*(u32 *)ep->tx.ops->get_ring_head(ep->tx.real_queue),
			*(u32 *)ep->rx.ops->get_ring_tail(ep->rx.real_queue),
			*(u32 *)ep->rx.ops->head_addr(ep->rx.real_queue),
			*(u32 *)ep->rx.ops->tail_addr(ep->rx.real_queue),
			*(u32 *)ep->rx.ops->get_ring_head(ep->rx.real_queue),
			*(u32 *)ep->tx.ops->get_ring_tail(ep->tx.real_queue)
			);
		pr_info("%s -- ctrlq_recv local head %u local tail%u\n"
				   "remot head %u remot tail%u\n",
				   __func__,
				controller->ctrlq_recv->head,
				controller->ctrlq_recv->tail,
				controller->ctrlq_recv->ring->head,
				controller->ctrlq_recv->ring->tail
			);

	} else if (data == 7) {
		struct hlist_node *tmp;
		int i;

		hash_for_each_safe(controller->commu_channel_head, i, tmp, channel, channel_node) {
			printk("channel:%s\n", channel->name);
			close_a_channel(channel);
		}
	}

	return 0;
}

static void commu_proc_helper(void)
{
	COMMU_INFO("USAGE\nIndependent Commands:\n"
		"1. ls(list all channels)\n"
		"2. ll(list all channels and endpoints)\n"
		"3. dump_ctrlq(dump ctrlq memory)\n"
		"4. send_file/recv_file\n"
		"5. dmesg#bytes(only pf)\n"
		"6. migration#command#vf_id(only pf)\n"
		"7. cmd#command(exce command on device-side)\n"
		"Channel Commands:\n"
		"ops(open/close)#channel_name\n"
		"Endpoint Commands:\n"
		"ops(connect/disconnect/ls)#type(rpc/msg/port)#para\n"
		"('open#channel ls' get ep pointer, disconnect#pointer)\n"
		"Debug Commands:\n"
		"ops(dump/call/set)#para1#para2#para3\n"
		"details for set commands:\n"
		"tx_local_head/tx_ring_head/tx_desc_flag/tx_queue_flag\n"
		"set#tx_desc_flag#0#0x3(set flag of tx desc0 to x03)\n");
}

/** NOTE:
 * memory module will use this interface dump memory endpoint
 * while alloc failed. so delete static key word.
 **/
int commu_proc_list_endpoint(struct commu_endpoint *endpoint)
{
	u32 ltxh, ltxt, rtxh, rtxt, lrxh, lrxt, rrxh, rrxt;

	rtxh = *(u32 *)endpoint->tx.ops->get_ring_head(endpoint->tx.real_queue);
	rrxh = *(u32 *)endpoint->rx.ops->get_ring_head(endpoint->rx.real_queue);

	ltxh = *(u32 *)endpoint->tx.ops->head_addr(endpoint->tx.real_queue);
	ltxt = *(u32 *)endpoint->tx.ops->tail_addr(endpoint->tx.real_queue);
	rtxt = *(u32 *)endpoint->rx.ops->get_shadow_tail(endpoint->tx.real_queue);
	lrxh = *(u32 *)endpoint->rx.ops->head_addr(endpoint->rx.real_queue);
	lrxt = *(u32 *)endpoint->rx.ops->tail_addr(endpoint->rx.real_queue);
	rrxt = *(u32 *)endpoint->tx.ops->get_shadow_tail(endpoint->rx.real_queue);
	COMMU_INFO("---tx: lh %u lt %u rh %u rt %u\n", ltxh, ltxt, rtxh, rtxt);
	if (rtxh != rtxt) {
		COMMU_INFO("WARNING:tx remote tail NOT EQUAL to remote haid\n");
		if (endpoint->tx.ops->dump_queue)
			endpoint->tx.ops->dump_queue(endpoint->tx.real_queue);
	}
	COMMU_INFO("---rx: lh %u lt %u rh %u rt %u\n", lrxh, lrxt, rrxh, rrxt);
	if (rrxh != rrxt) {
		COMMU_INFO("WARNING:rx remote tail NOT EQUAL to remote haid\n");
		if (endpoint->rx.ops->dump_queue)
			endpoint->rx.ops->dump_queue(endpoint->rx.real_queue);
	}
	/* dump all entries */
	if (ltxh != rtxh) {
		COMMU_INFO("WARNING:tx local haid != tx remote haid\ndump endpoint tx desc begin\n");
		if (endpoint->tx.ops->dump_queue)
			endpoint->tx.ops->dump_queue(endpoint->tx.real_queue);
	}
	if (lrxt != rrxt) {
		COMMU_INFO("WARNING:rx local haid != rx remote haid\ndump endpoint rx desc begin\n");
		if (endpoint->rx.ops->dump_queue)
			endpoint->rx.ops->dump_queue(endpoint->rx.real_queue);
	}

	return 0;
}

static void commu_proc_ll_channel(struct commu_set *controller)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;
	int i;

	hash_for_each(controller->commu_channel_head,
			i, channel, channel_node) {
		COMMU_INFO("channel %s kernel_channel %x\n", channel->name, channel->kernel_channel);
		llist_for_each_entry(endpoint,
				channel->channel_endpoints_head.first,
				channel_node) {
			COMMU_INFO("-- endpoint %px type %d\n", endpoint,
					endpoint->type);
			commu_proc_list_endpoint(endpoint);
		}
	}
}
static int commu_proc_send_file(struct commu_set *controller, int count)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;
	struct file *fp;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
	mm_segment_t fs;
#endif
	loff_t pos = 0;
	struct kstat stat;
	char *sf = "/data/test";
	char dbuf[500];
	char *default_channel = "test";
	int file_size, copy_len, ret, out;
	u32 command;

	channel = search_channel_by_name(controller, default_channel);
	if (!channel)
		channel = open_a_channel(default_channel, controller, 0);
	endpoint = search_endpoint_by_type(channel, COMMU_ENDPOINT_KERNEL_MSG);
	if (!endpoint)
		endpoint = connect_msg_endpoint(channel);

	fp = filp_open(sf, O_RDWR, 0);
	if (IS_ERR(fp)) {
		COMMU_INFO("[ERR] open file failed.\n");
		return -EFAULT;
	}
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
	fs = get_fs();
	set_fs(KERNEL_DS);
	vfs_stat(sf, &stat);
#else
	vfs_getattr(&fp->f_path, &stat, STATX_SIZE, AT_STATX_SYNC_AS_STAT);
#endif
	file_size = (int)stat.size;

	/*
	 * single thread makes life easier
	 * we do not need even recv response
	 */
	command = 0xcabcbeef;
	memcpy(dbuf, (void *)&command, 4);
	memcpy(dbuf + 4, (void *)&file_size, 4);
	ret = commu_send_message(endpoint, dbuf, 8);
	commu_wait_for_message_seq(endpoint, dbuf, &out, ret);
	dump_mem("recv message", dbuf, 20);
	while (pos < file_size) {
		copy_len = (file_size - pos) > 496 ? 496 : (file_size - pos);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
		vfs_read(fp, dbuf, copy_len, &pos);
#else
		kernel_read(fp, dbuf, copy_len, &pos);
#endif
		ret = commu_send_message(endpoint, dbuf, copy_len);
		if (ret == 0) {
			pos -= copy_len;
			continue;
		}
	}

	COMMU_INFO("file size : %d %d\n", (int)stat.size, out);

	filp_close(fp, NULL);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
	set_fs(fs);
#endif

	return count;
}

static int commu_proc_recv_file(struct commu_set *controller, int count)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;
	struct file *fp;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
	mm_segment_t fs;
#endif
	loff_t pos = 0;
	char *sf = "./commu_recv_file";
	char dbuf[500];
	char *default_channel = "test";
	int file_size, ret, out;
	u32 command;

	channel = search_channel_by_name(controller, default_channel);
	if (!channel)
		channel = open_a_channel(default_channel, controller, 0);
	endpoint = search_endpoint_by_type(channel, COMMU_ENDPOINT_KERNEL_MSG);
	if (!endpoint)
		endpoint = connect_msg_endpoint(channel);

	fp = filp_open(sf, O_RDWR | O_CREAT, 0644);
	if (IS_ERR(fp)) {
		COMMU_INFO("[ERR] open file failed.\n");
		return -EFAULT;
	}
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
	fs = get_fs();
	set_fs(KERNEL_DS);
#endif

	command = 0xcabccafe;
	memcpy(dbuf, (void *)&command, 4);
	ret = commu_send_message(endpoint, dbuf, 4);
	commu_wait_for_message_seq(endpoint, dbuf, &out, ret);
	file_size = *(u32 *)dbuf;
	COMMU_INFO("file size : %d \n", file_size);

	while (pos < file_size) {
		commu_wait_for_message_seq(endpoint, dbuf, &out, ret);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
		vfs_write(fp, dbuf, out, &pos);
#else
		kernel_write(fp, dbuf, out, &pos);
#endif
	}

	filp_close(fp, NULL);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
	set_fs(fs);
#endif
	return count;
}

static int commu_proc_dmesg_dev(struct commu_set *controller,
		char *para, int count)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;
	char *default_channel = "test";
	char dbuf[512];
	char *tmp;
	int ret, out;
	u32 command;
	int size, pos = 0, i;

	channel = search_channel_by_name(controller, default_channel);
	if (!channel)
		channel = open_a_channel(default_channel, controller, 0);
	endpoint = search_endpoint_by_type(channel, COMMU_ENDPOINT_KERNEL_MSG);
	if (!endpoint)
		endpoint = connect_msg_endpoint(channel);

	if (!para || kstrtoint(para, 10, &size))
		size = 1024;

	command = 0xcabcfeed;
	memcpy(dbuf, (void *)&command, 4);
	size = size > 0x100000 ? 0x100000 : size;
	memcpy(dbuf + 4, (void *)&size, 4);
	ret = commu_send_message(endpoint, dbuf, 8);
	commu_wait_for_message_seq(endpoint, dbuf, &out, ret);
	size = *(u32 *)dbuf;
	COMMU_INFO("log size : %d \n[dev log]\n", size);
	tmp = cn_kzalloc(size+1, GFP_KERNEL);

	while (pos < size) {
		commu_wait_for_message_seq(endpoint, tmp + pos, &out, ret);
		pos += out;
	}
	/*
	 * in case there are special chars that %c can't print
	 * printk(KERN_CONT "%s", tmp); seems has a max size limit
	 */
	//dump_mem("arm log", tmp, size);
	for (i = 0; i < size; i++)
		printk(KERN_CONT "%c", tmp[i]);
	printk(KERN_CONT "\n");

	cn_kfree(tmp);
	return count;
}

static int commu_proc_ddump_dev(struct commu_set *controller, int count)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;
	char *default_channel = "test";
	char dbuf[512];
	char *tmp;
	int ret, out;
	u32 command;
	int size, pos = 0, i;

	channel = search_channel_by_name(controller, default_channel);
	if (!channel)
		channel = open_a_channel(default_channel, controller, 0);
	endpoint = search_endpoint_by_type(channel, COMMU_ENDPOINT_KERNEL_MSG);
	if (!endpoint)
		endpoint = connect_msg_endpoint(channel);

	command = 0xcabcfeef;
	memcpy(dbuf, (void *)&command, 4);
	ret = commu_send_message(endpoint, dbuf, 8);
	commu_wait_for_message_seq(endpoint, dbuf, &out, ret);
	size = *(u32 *)dbuf;

	COMMU_INFO("log size : %d\n[dev commu info]\n", size);

	if (!size)
		return -ENOMEM;

	tmp = cn_vzalloc(size+1);
	if (!tmp) {
		return -ENOMEM;
	}

	while (pos < size) {
		commu_wait_for_message_seq(endpoint, tmp + pos, &out, ret);
		pos += out;
		COMMU_DBG("recv %d, %d/%d\n", out, pos, size);
	}
	/*
	 *in case there are special chars that %c can't print
	 *printk(KERN_CONT "%s", tmp); seems has a max size limit
	 */
	/* dump_mem("arm commu endpoint", tmp, size); */

	for (i = 0; i < size; i++)
		printk(KERN_CONT "%c", tmp[i]);
	printk(KERN_CONT "\n");

	cn_vfree(tmp);
	return count;
}

static int commu_proc_migration_dev(struct commu_set *controller,
		char *para, int count)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;
	char *default_channel = "test";
	char dbuf[32];
	int ret, out;
	u32 command;
	int size, vf_id;
	char *para1 = strsep(&para, "#");

	COMMU_INFO("%s %s\n", para1, para);

	channel = search_channel_by_name(controller, default_channel);
	if (!channel)
		channel = open_a_channel(default_channel, controller, 0);
	endpoint = search_endpoint_by_type(channel, COMMU_ENDPOINT_KERNEL_MSG);
	if (!endpoint)
		endpoint = connect_msg_endpoint(channel);

	/* 1. prepare 2. query 3. resume */
	if (!para1 || kstrtoint(para1, 10, &size))
		size = 2;

	if (!para || kstrtoint(para, 10, &vf_id))
		vf_id = 0;

	command = 0xcabcfeee;
	memcpy(dbuf, (void *)&command, 4);
	size = (size > 3 || size < 1) ? 2 : size;
	memcpy(dbuf + 4, (void *)&size, 4);
	vf_id = vf_id > COMMU_VF_NUM ? 0 : vf_id;
	memcpy(dbuf + 8, (void *)&vf_id, 4);
	ret = commu_send_message(endpoint, dbuf, 12);
	commu_wait_for_message_seq(endpoint, dbuf, &out, ret);

	COMMU_INFO("query status: %d\n", *(int *)dbuf);

	return count;
}

int commu_proc_dev_cmd_exce(struct commu_set *controller, char *cmd,
			char *para, int count)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;
	char *default_channel = "test";
	char command[200] = {0};
	char tmp[512];
	int out, ret;

	channel = search_channel_by_name(controller, default_channel);
	if (!channel)
		channel = open_a_channel(default_channel, controller, 0);
	endpoint = search_endpoint_by_type(channel, COMMU_ENDPOINT_KERNEL_RPC);
	if (!endpoint)
		endpoint = connect_rpc_endpoint(channel);

	strcpy(command, cmd);
	if (para != NULL) {
		strcat(command, " ");
		strcat(command, para);
	}
	COMMU_INFO("%s\n", command);

	ret = commu_call_rpc(endpoint, "commu_call_user_bin", command, strlen(command) + 1, tmp, &out);
	if (ret < 0) {
		COMMU_INFO("Run cmd %s on board failed\n", cmd);
	}

	return count;
}
static void commu_proc_dump_errinfo(struct commu_set *controller,
		char *para)
{
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;

	if (!para || strlen(para) == 0) {
		COMMU_INFO("[ERR]channel name is illegal.\n");
		return;
	}

	channel = search_channel_by_name(controller, para);
	if (!channel) {
		COMMU_INFO("[ERR]cant find channel by name [%s].\n", para);
		return;

	}
	llist_for_each_entry(endpoint,
			channel->channel_endpoints_head.first,
			channel_node) {
		COMMU_INFO("-- endpoint %px type %d\n", endpoint,
				endpoint->type);
		commu_proc_list_endpoint(endpoint);
		if (endpoint->rx.ops->dump_errinfo)
			endpoint->rx.ops->dump_errinfo(endpoint->rx.real_queue);
		else
			COMMU_INFO("---- endpoint dump errinfo handle NULL\n");
	}
}
static int commu_proc_independent_commands(struct commu_set *controller,
		char *channel_ops, int count, char *para)
{
	struct commu_channel *channel;
	unsigned long data = 0;
	int i;

	/* if echo value is digital number, call old test case */
	if (!kstrtoul(channel_ops, 10, &data)) {
		commu_proc_command_with_num(controller, data);
	} else if (!strncmp(channel_ops, "ls", 2)) {
		hash_for_each(controller->commu_channel_head,
				i, channel, channel_node) {
			COMMU_INFO("channel %s\n", channel->name);
		}
	} else if (!strncmp(channel_ops, "ll", 2)) {
		commu_proc_ll_channel(controller);
	} else if (!strncmp(channel_ops, "dump_ctrlq", 10)) {
		commu_ctrlq_all_dump(controller);
	} else if (!strncmp(channel_ops, "send_file", 9)) {
		return commu_proc_send_file(controller, count);
	} else if (!strncmp(channel_ops, "recv_file", 9)) {
		return commu_proc_recv_file(controller, count);
	} else if (!strncmp(channel_ops, "dmesg", 5)) {
		return commu_proc_dmesg_dev(controller, para, count);
	} else if (!strncmp(channel_ops, "migration", 9)) {
		return commu_proc_migration_dev(controller, para, count);
	} else if (!strncmp(channel_ops, "ddump", 5)) {
		return commu_proc_ddump_dev(controller, count);
	} else if (!strncmp(channel_ops, "dump_errinfo", 12)) {
		commu_proc_dump_errinfo(controller, para);
	} else {
		COMMU_INFO("[ERR]command %s not support.\n", channel_ops);
		return -EINVAL;
	}

	return count;
}

static struct commu_channel *commu_proc_open_channel(
		struct commu_set *controller, char *channel_name)
{
	struct commu_channel *channel;

	if (!channel_name || strlen(channel_name) == 0) {
		COMMU_INFO("[ERR]channel name is illegal.\n");
		return NULL;
	}

	channel = search_channel_by_name(controller, channel_name);
	if (!channel) {
		channel = open_a_channel(channel_name, controller, 0);
		COMMU_INFO("open channel %s done.\n", channel_name);
	}

	return channel;
}

static int commu_proc_close_channel(struct commu_set *controller,
		char *channel_name, int count)
{
	struct commu_channel *channel;

	if (!channel_name || strlen(channel_name) == 0) {
		COMMU_INFO("[ERR]channel name is illegal.\n");
		return -EINVAL;
	}

	channel = search_channel_by_name(controller, channel_name);
	if (channel) {
		close_a_channel(channel);
		COMMU_INFO("close channel %s done.\n", channel_name);
	}

	return count;
}

static struct commu_endpoint *commu_proc_connect_endpoint(
		struct commu_channel *channel, char *ep_type)
{
	struct commu_endpoint *endpoint;
	int type;

	if (!ep_type)
		ep_type = "null";

	if (!strncmp(ep_type, "krpc", 4) || !strncmp(ep_type, "rpc", 3))
		type = COMMU_ENDPOINT_KERNEL_RPC;
	else if (!strncmp(ep_type, "urpc", 4))
		type = COMMU_ENDPOINT_USER_RPC;
	else if (!strncmp(ep_type, "kmsg", 4))
		type = COMMU_ENDPOINT_KERNEL_MSG;
	else if (!strncmp(ep_type, "umsg", 4))
		type = COMMU_ENDPOINT_USER_MSG;
	else if (!strncmp(ep_type, "kport", 5))
		type = COMMU_ENDPOINT_KERNEL_PORT;
	else if (!strncmp(ep_type, "uport", 5))
		type = COMMU_ENDPOINT_USER_PORT;
	else {
		COMMU_INFO("[ERR]endpoint type %s illegal.\n", ep_type);
		return NULL;
	}

	endpoint = search_endpoint_by_type(channel, type);

	if (!endpoint) {
		if (type == COMMU_ENDPOINT_KERNEL_RPC)
			endpoint = connect_rpc_endpoint(channel);
		else if (type == COMMU_ENDPOINT_KERNEL_RPC)
			endpoint = connect_msg_endpoint(channel);
		COMMU_INFO("connect ep_type %s ep done.\n", ep_type);
	} else
		COMMU_INFO("find ep_type %s ep in channel.\n", ep_type);

	return endpoint;
}

static int commu_proc_disconnect_endpoint(char *ep_type, int count)
{
	unsigned long data = 0;

	if (!ep_type) {
		COMMU_INFO("[ERR]endpoint pointer illegal.\n");
		return -EINVAL;
	}

	/* convert ep_type string 0x**** to pointer */
	if (!kstrtoul(ep_type, 16, &data)) {
		COMMU_INFO("endpoint pointer is %lx.\n", data);
		disconnect_endpoint((struct commu_endpoint *)data);
	} else {
		COMMU_INFO("[ERR]pointer illegal, disconnect failed.\n");
		return -EINVAL;
	}

	return count;
}

static int commu_proc_ls_endpoint(struct commu_channel *channel, int count)
{
	struct commu_endpoint *endpoint;

	llist_for_each_entry(endpoint,
			channel->channel_endpoints_head.first,
			channel_node) {
		COMMU_INFO("endpoint %px type %d\n", endpoint,
				endpoint->type);
	}
	return count;
}

static int commu_proc_call_rpc(struct commu_endpoint *endpoint,
		char *para1, char *para2)
{
	char tmp[100];
	int out;
	u64 sum = 0;
	uint64_t counter_begin, counter_end;
	unsigned long times = 1024;
	int i;

	if (!para1 || strlen(para1) == 0) {
		COMMU_INFO("func name illegal, use default commu_test\n");
		para1 = "commu_test";
	}

	if (!para2)
		para2 = "1";

	if (kstrtoul(para2, 10, &times))
		times = 1024;

	memset(tmp, 0x0, 100);
	for (i = 0; i < times; i++) {
		counter_begin = rte_rdtsc();
		commu_call_rpc(endpoint, para1, tmp, 1, tmp, &out);
		counter_end = rte_rdtsc();
		COMMU_INFO("ret %llx cycles: %llu time: %llu us\n",
				*(u64 *)tmp,
				counter_end - counter_begin,
				(counter_end - counter_begin) /
				(COMMU_CPU_FREQUENCY));
		sum += counter_end - counter_begin;
	}
	COMMU_INFO("all time: %llu average time: %llu us\n",
			sum / COMMU_CPU_FREQUENCY,
			sum / (COMMU_CPU_FREQUENCY * times));
	return 0;
}

static int commu_proc_set_queue(struct commu_endpoint *endpoint,
		char *para1, char *para2)
{
	unsigned long value = 0;
	if (!para1 || !para2) {
		COMMU_INFO("no target or value to set\n");
		return 0;
	}

	if (strncmp(para1, "tx_desc_flag", 12) &&
			strncmp(para1, "rx_desc_flag", 12)) {
		if (kstrtoul(para2, 10, &value))
			return 0;
	}

	if (!strncmp(para1, "tx_local_head", 13)) {
		*(u32 *)endpoint->tx.ops->
			head_addr(endpoint->tx.real_queue) = value;
	} else if (!strncmp(para1, "tx_local_tail", 13)) {
		*(u32 *)endpoint->tx.ops->
			tail_addr(endpoint->tx.real_queue) = value;
	} else if (!strncmp(para1, "tx_ring_head", 12)) {
		*(u32 *)endpoint->tx.ops->
			get_ring_head(endpoint->tx.real_queue) = value;
	} else if (!strncmp(para1, "tx_ring_tail", 12)) {
		*(u32 *)endpoint->tx.ops->
			get_ring_tail(endpoint->tx.real_queue) = value;
	} else if (!strncmp(para1, "tx_desc_flag", 12)) {
		unsigned long index;
		char *para3 = strsep(&para2, "#");

		if (!para2 || !para3)
			return 0;

		if (kstrtoul(para3, 10, &index) || kstrtoul(para2, 16, &value))
			return 0;

		endpoint->tx.ops->
			set_desc_flag(endpoint->tx.real_queue, index, value);
	} else if (!strncmp(para1, "rx_local_head", 13)) {
		*(u32 *)endpoint->rx.ops->
			head_addr(endpoint->rx.real_queue) = value;
	} else if (!strncmp(para1, "rx_local_tail", 13)) {
		*(u32 *)endpoint->rx.ops->
			tail_addr(endpoint->rx.real_queue) = value;
	} else if (!strncmp(para1, "rx_ring_head", 12)) {
		*(u32 *)endpoint->rx.ops->
			get_ring_head(endpoint->rx.real_queue) = value;
	} else if (!strncmp(para1, "rx_ring_tail", 12)) {
		*(u32 *)endpoint->rx.ops->
			get_ring_tail(endpoint->rx.real_queue) = value;
	} else if (!strncmp(para1, "rx_desc_flag", 12)) {
		unsigned long index;
		char *para3 = strsep(&para2, "#");

		if (!para2 || !para3)
			return 0;

		if (kstrtoul(para3, 10, &index) || kstrtoul(para2, 16, &value))
			return 0;

		endpoint->rx.ops->
			set_desc_flag(endpoint->rx.real_queue, index, value);
	} else
		COMMU_INFO("the set options not support.\n");

	return 0;

}

static int commu_proc_dump_endpoint(struct commu_endpoint *endpoint)
{
	COMMU_INFO("tx local head %u local tail%u\n"
		"remote head %u remot tail%u\n"
		"rx local head %u local tail%u\n"
		"remote head %u remot tail%u\n",
		*(u32 *)endpoint->tx.ops->head_addr(endpoint->tx.real_queue),
		*(u32 *)endpoint->tx.ops->tail_addr(endpoint->tx.real_queue),
		*(u32 *)endpoint->tx.ops->get_ring_head(endpoint->tx.real_queue),
		*(u32 *)endpoint->rx.ops->get_ring_tail(endpoint->rx.real_queue),
		*(u32 *)endpoint->rx.ops->head_addr(endpoint->rx.real_queue),
		*(u32 *)endpoint->rx.ops->tail_addr(endpoint->rx.real_queue),
		*(u32 *)endpoint->rx.ops->get_ring_head(endpoint->rx.real_queue),
		*(u32 *)endpoint->tx.ops->get_ring_tail(endpoint->tx.real_queue));

	/* dump all entries */
	COMMU_INFO("dump endpoint tx desc begin\n");
	if (endpoint->tx.ops->dump_queue)
		endpoint->tx.ops->dump_queue(endpoint->tx.real_queue);

	COMMU_INFO("dump endpoint rx desc begin\n");
	if (endpoint->rx.ops->dump_queue)
		endpoint->rx.ops->dump_queue(endpoint->rx.real_queue);

	return 0;
}

int commu_endpoint_show(struct seq_file *m, void *v)
{
	return 0;
}

ssize_t commu_endpoint_write(struct file *file, const char __user *buf,
		size_t count, loff_t *pos)
{
	struct cn_core_set *core = (struct cn_core_set *)
		PDE_DATA(file_inode(file));
	struct commu_set *controller = (struct commu_set *)core->commu_set;
	struct commu_channel *channel;
	struct commu_endpoint *endpoint;
	char command[200];
	char *sep = command;
	char *ops_name;
	char *channel_ops, *channel_name;
	char *ep_ops, *ep_type, *ep_para;
	char *ops, *para1, *para2;

	/****************************
	 * preprocess inputs section
	 ****************************/
	memset(command, 0x0, 200);
	/*
	 * count can not beyond 200.
	 */
	count = count > 200 ? 200 : count;
	if (copy_from_user(command, buf, count))
		return -EFAULT;

	/* clear the last newline character*/
	if (count > 1)
		command[count - 1] = 0x0;

	COMMU_INFO("%s %d %d\n", sep, (int)strlen(sep), (int)count);

	if (strchr(sep, ' ') == strrchr(sep, ' '))
		commu_proc_helper();

	/****************************
	 * channel operations section
	 ****************************/
	ops_name = strsep(&sep, " ");
	channel_ops = strsep(&ops_name, "#");
	channel_name = ops_name;
	channel_ops = channel_ops ? channel_ops : "other";
	COMMU_INFO("%s %s\n", channel_ops, channel_name);

	if (!strncmp(channel_ops, "open", 4)) {
		channel = commu_proc_open_channel(controller, channel_name);
		if (!channel) {
			COMMU_INFO("no channel opened.\n");
			return count;
		}
	} else if (!strncmp(channel_ops, "close", 5)) {
		return commu_proc_close_channel(controller, channel_name, count);
	} else if (!strncmp(channel_ops, "cmd", 3)) {
		return commu_proc_dev_cmd_exce(controller, channel_name, sep, count);
	} else
		return commu_proc_independent_commands(controller,
				channel_ops, count, channel_name);

	/*****************************
	 * endpoint operations section
	 *****************************/
	ops_name = strsep(&sep, " ");
	ep_ops = strsep(&ops_name, "#");
	ep_type = strsep(&ops_name, "#");
	ep_para = ops_name;
	ep_ops = ep_ops ? ep_ops : "other";
	COMMU_INFO("%s %s %s\n", ep_ops, ep_type, ep_para);

	if (!strncmp(ep_ops, "connect", 7)) {
		endpoint = commu_proc_connect_endpoint(channel, ep_type);
		if (!endpoint) {
			COMMU_INFO("no endpoint found or connected.\n");
			return count;
		}
	} else if (!strncmp(ep_ops, "disconnect", 10)) {
		return commu_proc_disconnect_endpoint(ep_type, count);
	} else if (!strncmp(ep_ops, "ls", 2)) {
		return commu_proc_ls_endpoint(channel, count);
	} else {
		COMMU_INFO("[ERR]endpoint ops %s not support.\n", ep_ops);
		return -EINVAL;
	}

	/*****************************
	 * DEBUG ep operations section
	 *****************************/
	ops_name = strsep(&sep, " ");
	ops = strsep(&ops_name, "#");
	para1 = strsep(&ops_name, "#");
	para2 = ops_name;
	ops = ops ? ops : "other";
	COMMU_INFO("%s %s %s\n", ops, para1, para2);

	if (!strncmp(ops, "dump", 4)) {
		commu_proc_dump_endpoint(endpoint);
	} else if (!strncmp(ops, "call", 4)) {
		commu_proc_call_rpc(endpoint, para1, para2);
	} else if (!strncmp(ops, "set", 4)) {
		commu_proc_set_queue(endpoint, para1, para2);

	} else
		COMMU_INFO("debug command %s not support\n", ops);

	return count;
}
