#ifndef __UTIL_IPU_H__
#define __UTIL_IPU_H__

#include "util.h"

extern long ipu_util_adjust(int idx, int instance, long target, long usage);
extern long ipu_util_output(int idx, int instance);

#endif
