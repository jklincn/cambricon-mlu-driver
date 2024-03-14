/*
 * core/cndrv_affinity.c
 *
 * NOTICE:
 * Copyright (C) 2018 Cambricon, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/topology.h>
#include <linux/cpumask.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>

#include "cndrv_affinity_internal.h"
#include "cndrv_debug.h"
#include "cndrv_pre_compile.h"

struct cn_affinity_node_list node_affinity_list = {
	.list = LIST_HEAD_INIT(node_affinity_list.list),
	.lock = __MUTEX_INITIALIZER(node_affinity_list.lock)
};

static inline void init_cpu_mask_set(struct cpu_mask_set *set)
{
	cpumask_clear(&set->mask);
	cpumask_clear(&set->used);
	set->gen = 0;
}

/* Initialize non-HT cpu cores mask */
void init_real_cpu_mask(void)
{
	int possible, curr_cpu, i, ht;

	cpumask_clear(&node_affinity_list.real_cpu_mask);

	/* Start with cpu online mask as the real cpu mask */
	cpumask_copy(&node_affinity_list.real_cpu_mask, cpu_online_mask);

	/*
	 * Remove HT cores from the real cpu mask.  Do this in two steps below.
	 */
	possible = cpumask_weight(&node_affinity_list.real_cpu_mask);
	ht = cpumask_weight(cn_topology_sibling_cpumask(
				cpumask_first(&node_affinity_list.real_cpu_mask)));
	/*
	 * Step 1.  Skip over the first N HT siblings and use them as the
	 * "real" cores.  Assumes that HT cores are not enumerated in
	 * succession (except in the single core case).
	 */
	curr_cpu = cpumask_first(&node_affinity_list.real_cpu_mask);
	for (i = 0; i < possible / ht; i++)
		curr_cpu = cpumask_next(curr_cpu, &node_affinity_list.real_cpu_mask);
	/*
	 * Step 2.  Remove the remaining HT siblings.  Use cpumask_next() to
	 * skip any gaps.
	 */
	for (; i < possible; i++) {
		cpumask_clear_cpu(curr_cpu, &node_affinity_list.real_cpu_mask);
		curr_cpu = cpumask_next(curr_cpu, &node_affinity_list.real_cpu_mask);
	}
}

int cn_node_affinity_init(void)
{
	node_affinity_list.num_online_nodes = num_online_nodes();
	node_affinity_list.num_online_cpus = num_online_cpus();

	/*
	 * The real cpu mask is part of the affinity struct but it has to be
	 * initialized early.
	 */
	init_real_cpu_mask();

	return 0;
}

void cn_node_affinity_destroy(void)
{
	struct list_head *pos, *q;
	struct cn_affinity_node *entry;

	mutex_lock(&node_affinity_list.lock);
	list_for_each_safe(pos, q, &node_affinity_list.list) {
		entry = list_entry(pos, struct cn_affinity_node,
				   list);
		list_del(pos);
		cn_kfree(entry);
	}
	mutex_unlock(&node_affinity_list.lock);
}

static struct cn_affinity_node *node_affinity_allocate(int node)
{
	struct cn_affinity_node *entry;

	entry = cn_kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;
	entry->node = node;
	INIT_LIST_HEAD(&entry->list);

	return entry;
}

/*
 * It appends an entry to the list.
 * It *must* be called with node_affinity_list.lock held.
 */
static void node_affinity_add_tail(struct cn_affinity_node *entry)
{
	list_add_tail(&entry->list, &node_affinity_list.list);
}

/* It must be called with node_affinity_list.lock held */
static struct cn_affinity_node *node_affinity_lookup(int node)
{
	struct list_head *pos;
	struct cn_affinity_node *entry;

	list_for_each(pos, &node_affinity_list.list) {
		entry = list_entry(pos, struct cn_affinity_node, list);
		if (entry->node == node)
			return entry;
	}

	return NULL;
}

int cn_dev_affinity_init(int *node)
{
	struct cn_affinity_node *entry;
	const struct cpumask *local_mask;

	if (*node < 0) {
		pr_info("This is a uma system, force numa to 0\n");
		*node = numa_node_id();
	}

	local_mask = cpumask_of_node(*node);

	if (cpumask_first(local_mask) >= nr_cpu_ids)
		local_mask = topology_core_cpumask(0);

	mutex_lock(&node_affinity_list.lock);
	entry = node_affinity_lookup(*node);

	/*
	 * If this is the first time this NUMA node's affinity is used,
	 * create an entry in the global affinity structure and initialize it.
	 */
	if (!entry) {
		entry = node_affinity_allocate(*node);
		if (!entry) {
			pr_err("Unable to allocate global affinity node\n");
			mutex_unlock(&node_affinity_list.lock);
			return -ENOMEM;
		}
		init_cpu_mask_set(&entry->int_set);

		/* Use the "real" cpu mask of this node as the default */
		cpumask_and(&entry->int_set.mask, &node_affinity_list.real_cpu_mask,
			    local_mask);

		node_affinity_add_tail(entry);
	}
	mutex_unlock(&node_affinity_list.lock);

	return 0;
}

/*
 * Function sets the irq affinity for msi.
 * It *must* be called with node_affinity_list.lock held.
 */
static int get_cpu_affinity(int node, cpumask_t *cpu_mask)
{
	int ret;
	cpumask_var_t diff;
	struct cn_affinity_node *entry;
	struct cpu_mask_set *set = NULL;
	int cpu = 0;

	if (node < 0)
		return -1;

	cpumask_clear(cpu_mask);

	ret = zalloc_cpumask_var(&diff, GFP_KERNEL);
	if (!ret)
		return -ENOMEM;

	entry = node_affinity_lookup(node);
	if (entry == NULL)
		return -1;

	set = &entry->int_set;

	/*
	 * The general and control contexts are placed on a particular
	 * CPU, which is set above. Skip accounting for it. Everything else
	 * finds its CPU here.
	 */
	if (set) {
		if (cpumask_equal(&set->mask, &set->used)) {
			/*
			 * We've used up all the CPUs, bump up the generation
			 * and reset the 'used' map
			 */
			set->gen++;
			cpumask_clear(&set->used);
		}
		cpumask_andnot(diff, &set->mask, &set->used);
		cpu = cpumask_first(diff);
		cpumask_set_cpu(cpu, &set->used);
	}

	cpumask_set_cpu(cpu, cpu_mask);

	pr_debug("numa node : %d, assgin cpu: %d\n", node, cpu);

	free_cpumask_var(diff);

	return 0;
}

int cn_get_cpu_affinity(int node, cpumask_t *cpu_mask)
{
	int ret;

	mutex_lock(&node_affinity_list.lock);
	ret = get_cpu_affinity(node, cpu_mask);
	mutex_unlock(&node_affinity_list.lock);
	return ret;
}

void cn_put_cpu_affinity(int node, cpumask_t *cpu_mask)
{
	struct cpu_mask_set *set = NULL;
	struct cn_affinity_node *entry;

	mutex_lock(&node_affinity_list.lock);
	entry = node_affinity_lookup(node);

	set = &entry->int_set;

	if (set) {
		cpumask_andnot(&set->used, &set->used, cpu_mask);
		if (cpumask_empty(&set->used) && set->gen) {
			set->gen--;
			cpumask_copy(&set->used, &set->mask);
		}
	}

	cpumask_clear(cpu_mask);
	mutex_unlock(&node_affinity_list.lock);
}

#if (KERNEL_VERSION(3, 19, 8) >= LINUX_VERSION_CODE)
typedef int (*set_affinity)(unsigned int irq, const struct cpumask *cpumask, bool force);

static int __cn_irq_set_affinity(unsigned int irq, const struct cpumask *cpumask)
{
	static set_affinity __func_irq_set_affinity;

	if (!__func_irq_set_affinity) {
		__func_irq_set_affinity = (set_affinity)kallsyms_lookup_name("__irq_set_affinity");
		if (!__func_irq_set_affinity) {
			pr_err("get __func_set_affinity failed!");
			return -EINVAL;
		}
	}

	return __func_irq_set_affinity(irq, cpumask, false);
}
#endif

int cn_irq_set_affinity(unsigned int irq, const struct cpumask *cpumask)
{
	int ret;

	ret = irq_set_affinity_hint(irq, cpumask);
	if (ret) {
		pr_err("irq set affinity hint failed!");
		return ret;
	}

	if (cpumask == NULL)
		return ret;

#if (KERNEL_VERSION(3, 19, 8) >= LINUX_VERSION_CODE)
	ret = __cn_irq_set_affinity(irq, cpumask);
#endif
	return ret;
}
