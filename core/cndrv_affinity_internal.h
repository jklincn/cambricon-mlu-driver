/*
 * core/cndrv_affinity_internal.h
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
#ifndef __CNDRV_AFFINITY_INTERNAL_H__
#define __CNDRV_AFFINITY_INTERNAL_H__

struct cpu_mask_set {
	struct cpumask mask;
	struct cpumask used;
	uint gen;
};

/* Initialize non-HT cpu cores mask */
void init_real_cpu_mask(void);
/* Initialize driver affinity data */
int cn_dev_affinity_init(int *node);
int cn_get_cpu_affinity(int node, cpumask_t *cpu_mask);
void cn_put_cpu_affinity(int node, cpumask_t *cpu_mask);
int cn_irq_set_affinity(unsigned int irq, const struct cpumask *cpumask);

struct cn_affinity_node {
	int node;
	struct cpu_mask_set int_set;
	struct list_head list;
};

struct cn_affinity_node_list {
	struct list_head list;
	struct cpumask real_cpu_mask;
	int num_online_nodes;
	int num_online_cpus;
	struct mutex lock; /* protects affinity nodes */
};

int cn_node_affinity_init(void);
void cn_node_affinity_destroy(void);
extern struct cn_affinity_node_list node_affinity_list;

#endif /* __CNDRV_AFFINITY_INTERNAL_H__ */
