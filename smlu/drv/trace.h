#ifndef __UTIL_TRACE_H__
#define __UTIL_TRACE_H__

#include "util.h"
#include "ipu.h"

extern int util_trace_init(void);
extern void util_trace_exit(void);

extern void trace_record(int idx, int instance_id, enum util_type sub,
	unsigned long target, unsigned long usage, struct pid_s *t);
#endif
