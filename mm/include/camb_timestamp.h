#ifndef __CAMBRICON_TIMESTAMP_H_
#define __CAMBRICON_TIMESTAMP_H_

#define TIME_STRING_LEN (64)

#define TIMESTAMP_FORMAT "[CST: %04ld-%02d-%02d %02d:%02d:%02d.%06d]"

#define TIMESTAMP_PARAMS(tm, usecs) \
	((tm).tm_year + 1900), ((tm).tm_mon + 1), ((tm).tm_mday), ((tm).tm_hour), \
	((tm).tm_min), ((tm).tm_sec), (usecs)

#define TIME_STRING_CREATE(name, flags) \
	char *name = cn_kzalloc(sizeof(char) * TIME_STRING_LEN, flags); \
	if (!name) { \
		cn_dev_err("create time stamp buffer %s failed", #name); \
		return -ENOMEM;  \
	}

#define TIME_STRING_DESTROY(name)  cn_kfree(name);

u64 camb_get_real_time_us(void);

#endif /* __CAMBRICON_TIMESTAMP_H_ */
