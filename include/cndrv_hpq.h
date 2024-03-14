/*
 * sbts/hpq.h
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
#ifndef __SBTS_HPQ_H
#define __SBTS_HPQ_H

#include <asm/io.h>
#include <linux/types.h>
#include <asm/barrier.h>

/* memory nocacheble */
struct __iohpq {
	__le32 io_in;
	__le32 io_out;
	__le32 io_order;
	__le32 io_esize;

	u8 data[0];
};

#define __STRUCT_HPQ(datatype)	\
	{			\
		u32 in;		\
		u32 *rd_out;	\
		u32 esize;	\
		u32 mask;	\
								\
		union {						\
			datatype *type;				\
			struct __iohpq __iomem *ptr;		\
		};						\
	}

#define STRUCT_HPQ(name, type)  struct name __STRUCT_HPQ(type)

#define hpq_init(hpq, order, buff, rd) \
({ \
	typeof((hpq) + 1) __tmp = (hpq); \
	__tmp->in =0; \
	__tmp->rd_out = (typeof(__tmp->rd_out))(rd); \
	__tmp->rd_out ? *__tmp->rd_out = 0 : 0; \
	__tmp->esize = sizeof(*__tmp->type); \
	__tmp->mask = (1<<order) - 1; \
	__hpq_init(&__tmp->ptr, order, __tmp->esize, buff); \
})

#define hpq_reload(hpq, io_buff, rd) \
({ \
	 typeof((hpq) + 1) __tmp = (hpq); \
	 __tmp->ptr = (struct __iohpq *) (io_buff); \
	 __tmp->in = __tmp->ptr->io_in; \
	 __tmp->rd_out =  (typeof(__tmp->rd_out))(rd); \
	 __tmp->esize = __tmp->ptr->io_esize; \
	 __tmp->mask = (1<< __tmp->ptr->io_order) - 1; \
})


#define hpq_len_wr(hpq) \
({ \
	typeof((hpq) + 1) __tmpl = (hpq); \
	__tmpl->rd_out ? __tmpl->in - (*__tmpl->rd_out) : \
	__tmpl->in - __tmpl->ptr->io_out; \
})

#define hpq_len_rd(hpq) \
({ \
	typeof((hpq) + 1) __tmpl = (hpq); \
	__tmpl->ptr->io_in - __tmpl->ptr->io_out; \
})

#define hpq_is_empty_wr(hpq) \
({ \
	typeof((hpq) + 1) __tmpq = (hpq); \
	__tmpq->rd_out ? __tmpq->in == (*__tmpq->rd_out) : \
	__tmpq->in == __tmpq->ptr->io_out; \
})

#define hpq_is_empty_rd(hpq) \
({ \
	typeof((hpq) + 1) __tmpq = (hpq); \
	smp_wmb(); \
	__tmpq->ptr->io_in == __tmpq->ptr->io_out; \
})

#define hpq_is_full_wr(hpq) \
({ \
	typeof((hpq) + 1) __tmpq = (hpq); \
	smp_wmb(); \
	hpq_len_wr(__tmpq) > __tmpq->mask; \
})

#define hpq_is_full_rd(hpq) \
({ \
	typeof((hpq) + 1) __tmpq = (hpq); \
	smp_wmb(); \
	hpq_len_rd(__tmpq) > __tmpq->mask; \
})

#define hpq_put(hpq, val, func_mb, dev) \
({ \
	 unsigned int __ret = 0; \
	 typeof((hpq) + 1) __tmp = hpq; \
	 __ret = !hpq_is_full_wr(__tmp); \
	 if (__ret) { \
		((typeof(__tmp->type))(__tmp->ptr->data)) \
				[__tmp->in & __tmp->mask] = *val; \
		if (dev) { \
			func_mb(dev); \
		}\
		__tmp->in++; \
		__tmp->ptr->io_in = __tmp->in; \
	 } \
	 __ret; \
 })

#define hpq_get(hpq, val) \
({ \
	unsigned int __ret = 0; \
	typeof((hpq) + 1) __tmp = hpq; \
	__ret = !hpq_is_empty_rd(__tmp); \
	if (__ret) { \
		*(typeof(__tmp->type))val = \
				((typeof(__tmp->type))(__tmp->ptr->data)) \
				[__tmp->ptr->io_out & __tmp->mask]; \
		*(typeof(__tmp->type))val = \
				((typeof(__tmp->type))(__tmp->ptr->data)) \
				[__tmp->ptr->io_out & __tmp->mask]; \
		smp_rmb(); \
		__tmp->ptr->io_out++; \
		__tmp->rd_out ? (*__tmp->rd_out) = __tmp->ptr->io_out : 0; \
	} \
	__ret; \
})


#define hpq_peek(hpq, val) \
({ \
	unsigned int __ret = 0; \
	typeof((hpq) + 1) __tmp = hpq; \
	__ret = !hpq_is_empty_rd(__tmp); \
	if (__ret) { \
		*(typeof(__tmp->type))val = \
		((typeof(__tmp->type))(__tmp->ptr->data)) \
		[__tmp->ptr->io_out & __tmp->mask]; \
		*(typeof(__tmp->type))val = \
		((typeof(__tmp->type))(__tmp->ptr->data)) \
		[__tmp->ptr->io_out & __tmp->mask]; \
		smp_rmb(); \
	} \
	__ret; \
})

#define hpq_skip(hpq) \
({ \
	unsigned int __ret = 0; \
	typeof((hpq) + 1) __tmp = hpq; \
	__ret = !hpq_is_empty_rd(__tmp); \
	if (__ret) { \
		__tmp->ptr->io_out++; \
		__tmp->rd_out ? (*__tmp->rd_out) = __tmp->ptr->io_out : 0; \
	} \
	__ret; \
})

#define HPAS_STRUCT_USE_SIZE (sizeof(__le64) * 2)
/* high performance atomic struct
 * producer only write without read
 * cosumer can read with high performance
 * user must INIT!!!!
 */
#define STRUCT_HPAS(name, type) \
struct name { \
	u8 seq; \
	struct name##_as { \
		__le64 rd_seq; \
		__le64 wr_seq; \
		type entry; \
	}*d_as; \
}

#define STRUCT_HPAS_32(name, type) \
struct name { \
	u8 seq; \
	struct name##_as { \
		__le32 rd_seq; \
		__le32 wr_seq; \
		type entry; \
	} *d_as; \
}

#define hpas_read(hpas, val) \
({ \
	unsigned int __ret; \
	unsigned int __time = 9999999; \
	typeof((hpas) + 1) __tmp = hpas; \
	do { \
		__ret = __tmp->d_as->rd_seq; \
		smp_rmb(); \
		memcpy_fromio(val, &__tmp->d_as->entry, sizeof(*val)); \
		__time--; \
		smp_rmb(); \
	} while((__ret != __tmp->d_as->wr_seq) && __time); \
	(__time ? 1 : 0); \
})

#define hpas_write(hpas, val) \
({ \
	typeof((hpas) + 1) __tmp = hpas; \
	typeof((val) + 1) __val = val; \
	__tmp->seq++; \
	__tmp->d_as->wr_seq = __tmp->seq; \
	smp_wmb(); \
	memcpy_tocfg(&__tmp->d_as->entry, __val, sizeof(__tmp->d_as->entry)); \
	smp_wmb(); \
	__tmp->d_as->rd_seq= __tmp->seq; \
	0; \
})

/* be carefull */
#define hpas_init(hpas, buff) \
({ \
	typeof((hpas) + 1) __tmp = hpas; \
	typeof((buff) + 1) __tmpb = buff; \
	memset_io(__tmpb, 0, sizeof(*__tmp->d_as)); \
	__tmp->seq = 0; \
	__tmp->d_as = (typeof(__tmp->d_as)) __tmpb; \
})

#define hpas_reload(hpas, buff) \
({ \
	typeof((hpas) + 1) __tmp = hpas; \
	typeof((buff) + 1) __tmpb = buff; \
	__tmp->d_as = (typeof(__tmp->d_as)) __tmpb; \
	__tmp->seq = 0; \
})

static inline void memcpy_tocfg(void *dst, void *src, int size)
{
	int i = 0;
	int *src_a = (int *)src;
	int *dst_a = (int *)dst;

	BUG_ON(((long)src & 3) || ((long)dst & 3) || (size & 3));

	for (i= 0; i < size/sizeof(*src_a); i++) {
		*(volatile int*)dst_a++ = *(volatile int *)src_a++;
	}
}

static inline
int __hpq_init(struct __iohpq **hpq, int order, int esize, unsigned long buff)
{
	struct __iohpq *_hpq = (struct __iohpq *) buff;

	*hpq = (struct __iohpq *) buff;
	_hpq->io_in = 0;
	_hpq->io_out = 0;
	_hpq->io_order = order;
	_hpq->io_esize = esize;

	return 0;
}

#endif /* __SBTS_HPQ_H */
