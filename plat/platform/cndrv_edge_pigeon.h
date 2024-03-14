#ifndef __CNDRV_EDGE_PIGEON_H_
#define __CNDRV_EDGE_PIGEON_H_

#if defined(CONFIG_CNDRV_PIGEON_SOC)
int pigeon_edge_init(struct cn_edge_set *soc_set);
void pigeon_edge_exit(struct cn_edge_set *soc_set);
int pigeon_edge_switch_core_type(void *priv, __u32 policy);
#else
static inline int pigeon_edge_init(struct cn_edge_set *edge_set)
{
	return 0;
}
static inline void pigeon_edge_exit(struct cn_edge_set *edge_set)
{
}
static inline int pigeon_edge_switch_core_type(void *priv, __u32 policy)
{
	return 0;
}
#endif

#endif
