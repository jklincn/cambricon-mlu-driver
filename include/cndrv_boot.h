#ifndef _CN_PLAT_BOOT_H_
#define _CN_PLAT_BOOT_H_

#ifdef CONFIG_CNDRV_FW
extern int c20l_asic_boot_pre(struct cn_core_set *core);
extern int c20l_asic_cpu_boot(struct cn_core_set *core, uint64_t boot_entry);

extern int c20_boot_pre(struct cn_core_set *core);
extern int c20_cpu_boot(struct cn_core_set *core, uint64_t boot_entry);

extern int c20e_boot_pre(struct cn_core_set *core);
extern int c20e_cpu_boot(struct cn_core_set *core, uint64_t boot_entry);

extern int c30s_boot_pre(struct cn_core_set *core);
extern int c30s_cpu_boot(struct cn_core_set *core, uint64_t boot_entry);

extern int ce3226_boot_pre(struct cn_core_set *core);
extern int ce3226_cpu_boot(struct cn_core_set *core, uint64_t boot_entry);

extern int pigeon_boot_pre(struct cn_core_set *core);
extern int pigeon_cpu_boot(struct cn_core_set *core, uint64_t boot_entry);

extern int c50_boot_pre(struct cn_core_set *core);
extern int c50_boot_pre_m2(struct cn_core_set *core);
extern int c50s_boot_pre(struct cn_core_set *core);
extern int c50_cpu_boot(struct cn_core_set *core, uint64_t boot_entry);

int shutdown(struct cn_core_set *core);

#else

int c20l_asic_boot_pre(struct cn_core_set *core)
{return -1;}
int c20l_asic_cpu_boot(struct cn_core_set *core, uint64_t boot_entry)
{return -1;}

int c20_boot_pre(struct cn_core_set *core)
{return -1;}
int c20_cpu_boot(struct cn_core_set *core, uint64_t boot_entry)
{return -1;}

int c20e_boot_pre(struct cn_core_set *core)
{return -1;}
int c20e_cpu_boot(struct cn_core_set *core, uint64_t boot_entry)
{return -1;}
int shutdown(struct cn_core_set *core)
{return -1;}

int c30s_boot_pre(struct cn_core_set *core)
{return -1;}
int c30s_cpu_boot(struct cn_core_set *core, uint64_t boot_entry)
{return -1;}

int pigeon_boot_pre(struct cn_core_set *core)
{return -1;}
int pigeon_cpu_boot(struct cn_core_set *core, uint64_t boot_entry)
{return -1;}

int c50_boot_pre(struct cn_core_set *core)
{return -1; }
int c50_boot_pre_m2(struct cn_core_set *core)
{return -1; }
int c50s_boot_pre(struct cn_core_set *core)
{return -1; }
int c50_cpu_boot(struct cn_core_set *core, uint64_t boot_entry)
{return -1; }

#endif

#endif // _CN_PLAT_BOOT_H_
