#ifndef __CNDRV_EDGE_CE3226_H_
#define __CNDRV_EDGE_CE3226_H_

#if defined(CONFIG_CNDRV_CE3226_SOC)
int ce3226_edge_init(struct cn_edge_set *soc_set);
void ce3226_edge_exit(struct cn_edge_set *soc_set);
#else
static inline int ce3226_edge_init(struct cn_edge_set *edge_set)
{
	return 0;
}
static inline void ce3226_edge_exit(struct cn_edge_set *edge_set)
{
}
#endif

#endif
