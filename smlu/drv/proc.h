#ifndef __UTIL_PROC_H__
#define __UTIL_PROC_H__

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

extern int util_proc_init(void);
extern void util_proc_exit(void);
extern int parse(char *k);

extern struct proc_dir_entry *util_dir;
#endif
