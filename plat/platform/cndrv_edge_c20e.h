#ifndef __CNDRV_EDGE_C20E_H_
#define __CNDRV_EDGE_C20E_H_

#if defined(CONFIG_CNDRV_C20E_SOC)
int c20e_edge_init(struct cn_edge_set *edge_set);
void c20e_edge_exit(struct cn_edge_set *edge_set);
#else
static inline int c20e_edge_init(struct cn_edge_set *edge_set)
{
	return 0;
}
static inline void c20e_edge_exit(struct cn_edge_set *edge_set)
{
}
#endif

#endif
