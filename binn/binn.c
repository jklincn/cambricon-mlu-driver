#include "cndrv_debug.h"

/************************************************************************
 *  @file binn.c
 *
 *  @brief Binn serializer/de-serializer for linux kernel
 **************************************************************************/

/*************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
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
 ***************************************************************************/

/**************************************************************************
 * Includes
 ***************************************************************************/

#if defined(__KERNEL__)
#if defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,1) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
#        include <linux/stdarg.h>
#else
#        include <stdarg.h>
#endif
#        if defined(MODVERSIONS)
#        include <linux/modversions.h>
#        endif /*MODVERSIONS*/
#        include <linux/kernel.h>
#        include <linux/string.h>
#        include <linux/errno.h>
#        include <linux/sched.h>
#        include <linux/slab.h>
#        include <linux/types.h>
#        include <linux/kernel.h>
#        include <linux/timer.h>
#        include <linux/major.h>
#        include <asm/io.h>
#        include <linux/completion.h>  /* For complete() and  wait_for_completion() */
#        include <asm/byteorder.h>
#else /*__KERNEL__*/
#        include <stdio.h>
#        include <stdlib.h>
#        include <stdint.h>
#        include <string.h>
#        include <memory.h>
#endif /*__KERNEL__*/
#include "binn_internal.h"


#if defined(__KERNEL__)
#define __BINN_EXPORT_SYMBOL(__func__)
#else /*!__KERNEL__*/
#define __BINN_EXPORT_SYMBOL(__func__)
#endif /*__KERNEL__*/

#define UNUSED(x) (void)(x)
#if !defined(__KERNEL__)
#define roundval(dbl) (dbl >= 0.0 ? \ (int)(dbl + 0.5) : \
	((dbl - (double)(int)dbl) <= -0.5 ? (int)dbl : (int)(dbl - 0.5)))
#endif /*__KERNEL__*/
// magic number:  0x1F 0xb1 0x22 0x1F  =>  0x1FB1221F or 0x1F22B11F
// because the BINN_STORAGE_NOBYTES (binary 000) may not have so many sub-types (BINN_STORAGE_HAS_MORE = 0x10)
#define BINN_MAGIC            0x1F22B11F

#define MAX_BINN_HEADER       9  // [1:type][4:size][4:count]
#define MIN_BINN_SIZE         3  // [1:type][1:size][1:count]
#define CHUNK_SIZE            256  // 1024

#define BINN_DISABLE_SMALL_HEADER

#define BINN_STRUCT        1
#define BINN_BUFFER        2

void* (*malloc_fn)(size_t len) = 0;
void* (*realloc_fn)(void *ptr, size_t len) = 0;
void  (*free_fn)(void *ptr) = 0;

/***************************************************************************/

#if defined(__alpha__) || defined(__hppa__) || defined(__mips__) || defined(__powerpc__) || defined(__sparc__)
#define BINN_ONLY_ALIGNED_ACCESS
#elif (defined(__arm__) || defined(__aarch64__)) && !defined(__ARM_FEATURE_UNALIGNED)
#define BINN_ONLY_ALIGNED_ACCESS
#endif

#if defined(_WIN32)
#define BIG_ENDIAN      0x1000
#define LITTLE_ENDIAN   0x0001
#define BYTE_ORDER      LITTLE_ENDIAN
#elif defined(__APPLE__)
/* macros already defined */
#elif defined(__OpenBSD__) || defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/endian.h>
#elif defined(_AIX)
#include <sys/machine.h>
#elif defined(__KERNEL__)
#   ifndef BYTE_ORDER
#      define BYTE_ORDER __BYTE_ORDER
#   endif /*BYTE_ORDER*/
#   ifndef BIG_ENDIAN
#      define BIG_ENDIAN   __BIG_ENDIAN
#   endif /*BIT_ENDIAN*/
#   ifndef LITTLE_ENDIAN
#      define LITTLE_ENDIAN  __LITTLE_ENDIAN
#   endif /*LITTLE_ENDIAN*/

#   ifdef __BIG_ENDIAN
#      define __BYTE_ORDER  __BIG_ENDIAN
#      define __LITTLE_ENDIAN  0
#   else /*!BIG_ENDIAN*/
#      define __BYTE_ORDER  __LITTLE_ENDIAN
#      define __BIG_ENDIAN  0
#   endif /*__BIG_ENDIAN*/

#ifndef UINT64_MAX
#define  UINT64_MAX  U64_MAX
#endif /*UINT64_MAX*/

#ifndef UINT32_MAX
#define  UINT32_MAX  U32_MAX
#endif /*UINT32_MAX*/

#ifndef UINT16_MAX
#define  UINT16_MAX  U16_MAX
#endif /*UINT16_MAX*/


#ifndef UINT8_MAX
#define  UINT8_MAX  U8_MAX
#endif /*UINT8_MAX*/


#ifndef UINT64_MIN
#define  UINT64_MIN  U64_MIN
#endif /*UINT64_MIN*/

#ifndef UINT32_MIN
#define  UINT32_MIN  U32_MIN
#endif /*UINT32_MIN*/

#ifndef UINT16_MIN
#define  UINT16_MIN  U16_MIN
#endif /*UINT16_MIN*/


#ifndef UINT8_MIN
#define  UINT8_MIN  U8_MIN
#endif /*UINT8_MIN*/


#ifndef INT64_MAX
#define  INT64_MAX  S64_MAX
#endif /*INT64_MAX*/

#ifndef INT32_MAX
#define  INT32_MAX  S32_MAX
#endif /*INT32_MAX*/

#ifndef INT16_MAX
#define  INT16_MAX  S16_MAX
#endif /*INT16_MAX*/


#ifndef INT8_MAX
#define  INT8_MAX  S8_MAX
#endif /*INT8_MAX*/


#ifndef INT64_MIN
#define  INT64_MIN  S64_MIN
#endif /*INT64_MIN*/

#ifndef INT32_MIN
#define  INT32_MIN  S32_MIN
#endif /*INT32_MIN*/

#ifndef INT16_MIN
#define  INT16_MIN  S16_MIN
#endif /*INT16_MIN*/


#ifndef INT8_MIN
#define  INT8_MIN  S8_MIN
#endif /*INT8_MIN*/

#else /*__KERNEL__*/
#include <endian.h>
#endif /*AIX*/



#ifndef BYTE_ORDER
#error "BYTE_ORDER not defined"
#endif
#ifndef BIG_ENDIAN
#error "BIG_ENDIAN not defined"
#endif
#ifndef LITTLE_ENDIAN
#error "LITTLE_ENDIAN not defined"
#endif
#if BIG_ENDIAN == LITTLE_ENDIAN
#error "BIG_ENDIAN == LITTLE_ENDIAN"
#endif
#if ((BYTE_ORDER != BIG_ENDIAN) && (BYTE_ORDER != LITTLE_ENDIAN))
#error "BYTE_ORDER not supported"
#endif

typedef unsigned short int     u16;
typedef unsigned int           u32;
typedef unsigned long long int u64;

BINN_PRIVATE void copy_be16(u16 *pdest, u16 *psource)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	unsigned char *source = (unsigned char *)psource;
	unsigned char *dest = (unsigned char *)pdest;

	dest[0] = source[1];
	dest[1] = source[0];
#else // if BYTE_ORDER == BIG_ENDIAN
#ifdef BINN_ONLY_ALIGNED_ACCESS
	if ((uintptr_t)psource % 2 == 0) {  // address aligned to 16 bit
		*pdest = *psource;
	} else {
		unsigned char *source = (unsigned char *) psource;
		unsigned char *dest = (unsigned char *) pdest;

		dest[0] = source[0];  // indexes are the same
		dest[1] = source[1];
	}
#else
	*pdest = *psource;
#endif
#endif
}

BINN_PRIVATE void copy_be32(u32 *pdest, u32 *psource)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	unsigned char *source = (unsigned char *)psource;
	unsigned char *dest = (unsigned char *)pdest;

	dest[0] = source[3];
	dest[1] = source[2];
	dest[2] = source[1];
	dest[3] = source[0];
#else // if BYTE_ORDER == BIG_ENDIAN
#ifdef BINN_ONLY_ALIGNED_ACCESS
	if ((uintptr_t)psource % 4 == 0) {  // address aligned to 32 bit
		*pdest = *psource;
	} else {
		unsigned char *source = (unsigned char *) psource;
		unsigned char *dest = (unsigned char *) pdest;

		dest[0] = source[0];  // indexes are the same
		dest[1] = source[1];
		dest[2] = source[2];
		dest[3] = source[3];
	}
#else
	*pdest = *psource;
#endif
#endif
}

BINN_PRIVATE void copy_be64(u64 *pdest, u64 *psource)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	unsigned char *source = (unsigned char *) psource;
	unsigned char *dest = (unsigned char *) pdest;
	int i;

	for (i = 0; i < 8; i++) {
		dest[i] = source[7 - i];
	}

#else // if BYTE_ORDER == BIG_ENDIAN
#ifdef BINN_ONLY_ALIGNED_ACCESS
	if ((uintptr_t)psource % 8 == 0) {  // address aligned to 64 bit
		*pdest = *psource;
	} else {
		unsigned char *source = (unsigned char *)psource;
		unsigned char *dest = (unsigned char *)pdest;
		int i;

		for (i = 0; i < 8; i++) {
			dest[i] = source[i];  // indexes are the same
		}
	}
#else
	*pdest = *psource;
#endif
#endif
}

/***************************************************************************/

#ifndef WIN32
#define stricmp strcasecmp
#define strnicmp strncasecmp
#endif

BINN_PRIVATE BOOL IsValidBinnHeader(void *pbuf, int *ptype, int *pcount, int *psize, int *pheadersize);

/***************************************************************************/

void APIENTRY binn_set_alloc_functions(void* (*new_malloc)(size_t),
	void *(*new_realloc)(void *, size_t), void (*new_free)(void *))
{
	malloc_fn = new_malloc;
	realloc_fn = new_realloc;
	free_fn = new_free;
}

#if defined(__KERNEL__)

static void *__kernel_malloc(size_t size)
{
	gfp_t flags = GFP_KERNEL;

	return cn_kzalloc(size, flags);
}

static void __kernel_free(void *ptr)
{
	cn_kfree(ptr);
}


static void *__kernel_realloc(void *ptr, size_t new_size)
{
	gfp_t flags = GFP_KERNEL;

	return krealloc(ptr, new_size, flags);
}


static int atoi(const char *p)
{
	int val = 0;

	if (kstrtoint(p, 10, &val) < 0) {
		return 0;
	}

	return val;
}

static char *strdup(const char *s)
{
	size_t n;
	char *ptr;

	if (!s) {
		return NULL;
	}
	n = strlen(s);

	ptr = (char *)__kernel_malloc(n + 1);

	if (!ptr)  {
		return NULL;
	}
	strcpy(ptr, s);
	return ptr;
}

#else /*__KERNEL__*/

#endif /*__KERNEL__*/

/***************************************************************************/

BINN_PRIVATE void check_alloc_functions(void)
{
#if defined(__KERNEL__)
	if (malloc_fn == 0)
		malloc_fn = &__kernel_malloc;
	if (realloc_fn == 0)
		realloc_fn = &__kernel_realloc;
	if (free_fn == 0)
		free_fn = &__kernel_free;
#else /*__KERNEL__*/
	if (malloc_fn == 0)
		malloc_fn = &malloc;
	if (realloc_fn == 0)
		realloc_fn = &realloc;
	if (free_fn == 0)
		free_fn = &free;
#endif /*__KERNEL__*/
}

/***************************************************************************/

BINN_PRIVATE void *binn_malloc(int size)
{
	check_alloc_functions();
	return malloc_fn(size);
}

/***************************************************************************/

BINN_PRIVATE void *binn_memdup(void *src, int size)
{
	void *dest;

	if (src == NULL || size <= 0)
		return NULL;

	dest = binn_malloc(size);
	if (dest == NULL)
		return NULL;
	memcpy(dest, src, size);

	return dest;
}

/***************************************************************************/

BINN_PRIVATE size_t strlen2(char *str)
{
	if (str == NULL)
		return 0;

	return strlen(str);
}

	/***************************************************************************/

int APIENTRY binn_create_type(int storage_type, int data_type_index)
{
	if (data_type_index < 0)
		return -1;

	if ((storage_type < BINN_STORAGE_MIN) || (storage_type > BINN_STORAGE_MAX))
		return -1;

	if (data_type_index < 16) {
		return storage_type | data_type_index;
	} else if (data_type_index < 4096) {
		storage_type |= BINN_STORAGE_HAS_MORE;
		storage_type <<= 8;
		data_type_index >>= 4;
		return storage_type | data_type_index;
	} else {
		return -1;
	}
}

/***************************************************************************/

BOOL APIENTRY binn_get_type_info(int long_type, int *pstorage_type, int *pextra_type)
{
	int storage_type, extra_type;
	BOOL retval = TRUE;

again:
	if (long_type < 0) {
		goto loc_invalid;
	} else if (long_type <= 0xff) {
		storage_type = long_type & BINN_STORAGE_MASK;
		extra_type = long_type & BINN_TYPE_MASK;
	} else if (long_type <= 0xffff) {
		storage_type = long_type & BINN_STORAGE_MASK16;
		storage_type >>= 8;
		extra_type = long_type & BINN_TYPE_MASK16;
		extra_type >>= 4;
	} else if (long_type & BINN_STORAGE_VIRTUAL) {
		//storage_type = BINN_STORAGE_VIRTUAL;
		//extra_type = xxx;
		long_type &= 0xffff;
		goto again;
	} else {
loc_invalid:
		storage_type = -1;
		extra_type = -1;
		retval = FALSE;
	}

	if (pstorage_type)
		*pstorage_type = storage_type;

	if (pextra_type)
		*pextra_type = extra_type;

	return retval;
}

/***************************************************************************/

BOOL APIENTRY binn_create(struct binn *item, int type, int size, void *pointer)
{
	BOOL retval = FALSE;

	switch (type) {
	case BINN_LIST:
	case BINN_MAP:
	case BINN_OBJECT:
		break;

	default:
		goto loc_exit;
	}

	if ((item == NULL) || (size < 0))
		goto loc_exit;

	if (size < MIN_BINN_SIZE) {
		if (pointer)
			goto loc_exit;
		else
			size = 0;
	}

	memset(item, 0, sizeof(struct binn));

	if (pointer) {
		item->pre_allocated = TRUE;
		item->pbuf = pointer;
		item->alloc_size = size;
	} else {
		item->pre_allocated = FALSE;
		if (size == 0)
			size = CHUNK_SIZE;

		pointer = binn_malloc(size);
		if (pointer == 0)
			return INVALID_BINN;

		item->pbuf = pointer;
		item->alloc_size = size;
	}

	item->header = BINN_MAGIC;
	//item->allocated = FALSE;   -- already zeroed
	item->writable = TRUE;
	item->used_size = MAX_BINN_HEADER;  /* save space for the header */
	item->type = type;
	//item->count = 0;           -- already zeroed
	item->dirty = TRUE;          /* the header is not written to the buffer */

	retval = TRUE;

loc_exit:
	return retval;
}

/***************************************************************************/

struct binn *APIENTRY binn_new(int type, int size, void *pointer)
{
	struct binn *item;

	item = (struct binn *)binn_malloc(sizeof(struct binn));

	if (binn_create(item, type, size, pointer) == FALSE) {
		free_fn(item);
		return NULL;
	}

	item->allocated = TRUE;
	return item;
}

/*************************************************************************************/

BOOL APIENTRY binn_create_list(struct binn *list)
{
	return binn_create(list, BINN_LIST, 0, NULL);
}

/*************************************************************************************/

BOOL APIENTRY binn_create_map(struct binn *map)
{
	return binn_create(map, BINN_MAP, 0, NULL);
}

/*************************************************************************************/

BOOL APIENTRY binn_create_object(struct binn *object)
{
	return binn_create(object, BINN_OBJECT, 0, NULL);
}

/***************************************************************************/

struct binn *APIENTRY binn_list(void)
{
	return binn_new(BINN_LIST, 0, 0);
}

/***************************************************************************/

struct binn *APIENTRY binn_map(void)
{
	return binn_new(BINN_MAP, 0, 0);
}

/***************************************************************************/

struct binn *APIENTRY binn_object(void)
{
	return binn_new(BINN_OBJECT, 0, 0);
}

/***************************************************************************/

struct binn *APIENTRY binn_copy(void *old)
{
	int type, count, size, header_size;
	unsigned char *old_ptr = binn_ptr(old);
	struct binn *item;

	size = 0;
	if (!IsValidBinnHeader(old_ptr, &type, &count, &size, &header_size))
		return NULL;

	item = binn_new(type, size - header_size + MAX_BINN_HEADER, NULL);
	if (item) {
		unsigned char *dest;

		dest = ((unsigned char *) item->pbuf) + MAX_BINN_HEADER;
		memcpy(dest, old_ptr + header_size, size - header_size);
		item->used_size = MAX_BINN_HEADER + size - header_size;
		item->count = count;
	}

	return item;
}

/*************************************************************************************/

BOOL APIENTRY binn_load(void *data, struct binn *value)
{
	if ((data == NULL) || (value == NULL))
		return FALSE;

	memset(value, 0, sizeof(struct binn));
	value->header = BINN_MAGIC;
	//value->allocated = FALSE;  --  already zeroed
	//value->writable = FALSE;

	if (binn_is_valid(data, &value->type, &value->count, &value->size) == FALSE)
		return FALSE;

	value->ptr = data;
	return TRUE;
}

/*************************************************************************************/

struct binn *APIENTRY binn_open(void *data)
{
	struct binn *item;

	item = (struct binn *)binn_malloc(sizeof(struct binn));

	if (binn_load(data, item) == FALSE) {
		free_fn(item);
		return NULL;
	}

	item->allocated = TRUE;
	return item;
}

/***************************************************************************/

BINN_PRIVATE int binn_get_ptr_type(void *ptr)
{
	if (ptr == NULL)
		return 0;

	switch (*(unsigned int *)ptr) {
	case BINN_MAGIC:
		return BINN_STRUCT;

	default:
		return BINN_BUFFER;
	}
}

/***************************************************************************/

BOOL APIENTRY binn_is_struct(void *ptr)
{
	if (ptr == NULL)
		return FALSE;

	if ((*(unsigned int *)ptr) == BINN_MAGIC) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/***************************************************************************/

BINN_PRIVATE int CalcAllocation(int needed_size, int alloc_size)
{
	int calc_size;

	calc_size = alloc_size;
	while (calc_size < needed_size) {
		calc_size <<= 1;  // same as *= 2
	}

	return calc_size;
}

/***************************************************************************/

BINN_PRIVATE BOOL CheckAllocation(struct binn *item, int add_size)
{
	int  alloc_size;
	void *ptr;

	if (item->used_size + add_size > item->alloc_size) {
		if (item->pre_allocated)
			return FALSE;

		alloc_size = CalcAllocation(item->used_size + add_size, item->alloc_size);
		ptr = realloc_fn(item->pbuf, alloc_size);
		if (ptr == NULL)
			return FALSE;

		item->pbuf = ptr;
		item->alloc_size = alloc_size;
	}

	return TRUE;
}

/***************************************************************************/

#if BYTE_ORDER == BIG_ENDIAN

BINN_PRIVATE int get_storage_size(int storage_type)
{
	switch (storage_type) {
	case BINN_STORAGE_NOBYTES:
		return 0;

	case BINN_STORAGE_BYTE:
		return 1;

	case BINN_STORAGE_WORD:
		return 2;

	case BINN_STORAGE_DWORD:
		return 4;

	case BINN_STORAGE_QWORD:
		return 8;

	default:
		return 0;
	}
}

#endif

/***************************************************************************/

BINN_PRIVATE unsigned char *AdvanceDataPos(unsigned char *p, unsigned char *plimit)
{
	unsigned char byte;
	int  storage_type, DataSize;

	if (p > plimit)
		return 0;

	byte = *p;
	p++;
	storage_type = byte & BINN_STORAGE_MASK;
	if (byte & BINN_STORAGE_HAS_MORE)
		p++;

	switch (storage_type) {
	case BINN_STORAGE_NOBYTES:
		//p += 0;
		break;

	case BINN_STORAGE_BYTE:
		p++;
		break;

	case BINN_STORAGE_WORD:
		p += 2;
		break;

	case BINN_STORAGE_DWORD:
		p += 4;
		break;

	case BINN_STORAGE_QWORD:
		p += 8;
		break;

	case BINN_STORAGE_BLOB:
	case BINN_STORAGE_STRING:
		if (p > plimit)
			return 0;
		DataSize = *((unsigned char *)p);
		if (DataSize & 0x80) {
			if (p + sizeof(int) - 1 > plimit)
				return 0;
			copy_be32((u32 *)&DataSize, (u32 *)p);
			DataSize &= 0x7FFFFFFF;
			p += 4;
		} else {
			p++;
		}

		p += DataSize;
		if (storage_type == BINN_STORAGE_STRING) {
			p++;  // null terminator.
		}
		break;

	case BINN_STORAGE_CONTAINER:
		if (p > plimit)
			return 0;
		DataSize = *((unsigned char *)p);
		if (DataSize & 0x80) {
			if (p + sizeof(int) - 1 > plimit)
				return 0;
			copy_be32((u32 *)&DataSize, (u32 *)p);
			DataSize &= 0x7FFFFFFF;
		}
		DataSize--;  // remove the type byte already added before
		p += DataSize;
		break;

	default:
		return 0;
	}

	if (p > plimit)
		return 0;

	return p;

}

/***************************************************************************/

BINN_PRIVATE unsigned char *SearchForID(unsigned char *p,
		int header_size, int size, int numitems, int id)
{
	unsigned char *plimit, *base;
	int  i, int32;

	base = p;
	plimit = p + size - 1;
	p += header_size;

	// search for the ID in all the arguments.
	for (i = 0; i < numitems; i++) {
		copy_be32((u32 *)&int32, (u32 *)p);
		p += 4;
		if (p > plimit)
			break;
		// Compare if the IDs are equal.
		if (int32 == id)
			return p;
		// xxx
		p = AdvanceDataPos(p, plimit);
		if ((p == 0) || (p < base))
			break;
	}

	return NULL;
}

/***************************************************************************/

BINN_PRIVATE unsigned char *SearchForKey(unsigned char *p, int header_size,
		int size, int numitems, char *key)
{
	unsigned char len, *plimit, *base;
	int  i, keylen;

	base = p;
	plimit = p + size - 1;
	p += header_size;

	keylen = strlen(key);

	// search for the key in all the arguments.
	for (i = 0; i < numitems; i++) {
		len = *((unsigned char *)p);
		p++;
		if (p > plimit)
			break;

		// Compare if the strings are equal.
		if (len > 0) {
		   /* note that there is no null terminator here */
			if (strnicmp((char *)p, key, len) == 0) {
				if (keylen == len) {
					p += len;
					return p;
				}
			}

			p += len;
			if (p > plimit)
				break;
		} else if (len == keylen) {   // in the case of empty string: ""
			return p;
		}

		// xxx
		p = AdvanceDataPos(p, plimit);
		if ((p == 0) || (p < base))
			break;
	}

	return NULL;

}

/***************************************************************************/

BINN_PRIVATE BOOL AddValue(struct binn *item, int type, void *pvalue, int size);

/***************************************************************************/

BINN_PRIVATE BOOL binn_list_add_raw(struct binn *item, int type, void *pvalue, int size)
{
	if ((item == NULL) || (item->type != BINN_LIST) || (item->writable == FALSE))
		return FALSE;

	if (AddValue(item, type, pvalue, size) == FALSE)
		return FALSE;

	item->count++;

	return TRUE;
}

/***************************************************************************/

BINN_PRIVATE BOOL binn_object_set_raw(struct binn *item, char *key, int type,
		void *pvalue, int size)
{
	unsigned char *p, len;
	int int32;

	if ((item == NULL) || (item->type != BINN_OBJECT) || (item->writable == FALSE))
		return FALSE;

	if (key == NULL)
		return FALSE;
	int32 = strlen(key);
	if (int32 > 255)
		return FALSE;

	// is the key already in it?
	p = SearchForKey(item->pbuf, MAX_BINN_HEADER, item->used_size, item->count, key);
	if (p)
		return FALSE;

	// start adding it

	if (CheckAllocation(item, 1 + int32) == FALSE)
		return FALSE;  // bytes used for the key size and the key itself.

	p = ((unsigned char *)item->pbuf) + item->used_size;
	len = int32;
	*p = len;
	p++;
	memcpy(p, key, int32);
	int32++;  // now contains the strlen + 1 byte for the len
	item->used_size += int32;

	if (AddValue(item, type, pvalue, size) == FALSE) {
		item->used_size -= int32;
		return FALSE;
	}

	item->count++;

	return TRUE;

}

/***************************************************************************/

BINN_PRIVATE BOOL binn_map_set_raw(struct binn *item, int id, int type,
		void *pvalue, int size)
{
	unsigned char *p;

	if ((item == NULL) || (item->type != BINN_MAP) || (item->writable == FALSE))
		return FALSE;

	// is the ID already in it?
	p = SearchForID(item->pbuf, MAX_BINN_HEADER, item->used_size, item->count, id);
	if (p)
		return FALSE;

	// start adding it

	if (CheckAllocation(item, 4) == FALSE)
		return FALSE;  // 4 bytes used for the id.

	p = ((unsigned char *)item->pbuf) + item->used_size;
	copy_be32((u32 *)p, (u32 *)&id);
	item->used_size += 4;

	if (AddValue(item, type, pvalue, size) == FALSE) {
		item->used_size -= 4;
		return FALSE;
	}

	item->count++;

	return TRUE;

}

/***************************************************************************/

BINN_PRIVATE void *compress_int(int *pstorage_type, int *ptype, void *psource)
{
	int storage_type, storage_type2, type, type2 = 0;
	int64  vint = 0;
	uint64 vuint;
	char *pvalue;
#if BYTE_ORDER == BIG_ENDIAN
	int size1, size2;
#endif

	storage_type = *pstorage_type;
	if (storage_type == BINN_STORAGE_BYTE)
		return psource;

	type = *ptype;

	switch (type) {
	case BINN_INT64:
		vint = *(int64 *)psource;
		goto loc_signed;
	case BINN_INT32:
		vint = *(int *)psource;
		goto loc_signed;
	case BINN_INT16:
		vint = *(short *)psource;
		goto loc_signed;
	case BINN_UINT64:
		vuint = *(uint64 *)psource;
		goto loc_positive;
	case BINN_UINT32:
		vuint = *(unsigned int *)psource;
		goto loc_positive;
	case BINN_UINT16:
		vuint = *(unsigned short *)psource;
		goto loc_positive;
	}

loc_signed:
	if (vint >= 0) {
		vuint = vint;
		goto loc_positive;
	}

	//loc_negative:

	if (vint >= INT8_MIN) {
		type2 = BINN_INT8;
	} else if (vint >= INT16_MIN) {
		type2 = BINN_INT16;
	} else if (vint >= INT32_MIN) {
		type2 = BINN_INT32;
	}
	goto loc_exit;

loc_positive:

	if (vuint <= UINT8_MAX) {
		type2 = BINN_UINT8;
	} else if (vuint <= UINT16_MAX) {
		type2 = BINN_UINT16;
	} else {
		if (vuint <= UINT32_MAX) {
			type2 = BINN_UINT32;
		}
	}

loc_exit:

	pvalue = (char *)psource;

	if ((type2) && (type2 != type)) {
		*ptype = type2;
		storage_type2 = binn_get_write_storage(type2);
		*pstorage_type = storage_type2;
#if BYTE_ORDER == BIG_ENDIAN
		size1 = get_storage_size(storage_type);
		size2 = get_storage_size(storage_type2);
		pvalue += (size1 - size2);
#endif
	}

	return pvalue;
}

/***************************************************************************/

BINN_PRIVATE int type_family(int type);

BINN_PRIVATE BOOL AddValue(struct binn *item, int type, void *pvalue, int size)
{
	int int32, ArgSize, storage_type, extra_type;
	unsigned char *p;

	binn_get_type_info(type, &storage_type, &extra_type);

	if (pvalue == NULL) {
		switch (storage_type) {
		case BINN_STORAGE_NOBYTES:
			break;

		case BINN_STORAGE_BLOB:
		case BINN_STORAGE_STRING:
			if (size == 0) {
				break; // the 2 above are allowed to have 0 length
			} else {
				return FALSE;
			}
		default:
			return FALSE;
		}
	}

	if ((type_family(type) == BINN_FAMILY_INT) && (item->disable_int_compression == FALSE))
		pvalue = compress_int(&storage_type, &type, pvalue);

	switch (storage_type) {
	case BINN_STORAGE_NOBYTES:
		size = 0;
		ArgSize = size;
		break;
	case BINN_STORAGE_BYTE:
		size = 1;
		ArgSize = size;
		break;
	case BINN_STORAGE_WORD:
		size = 2;
		ArgSize = size;
		break;
	case BINN_STORAGE_DWORD:
		size = 4;
		ArgSize = size;
		break;
	case BINN_STORAGE_QWORD:
		size = 8;
		ArgSize = size;
		break;
	case BINN_STORAGE_BLOB:
		if (size < 0)
			return FALSE;
		ArgSize = size + 4; // at least this size
		break;
	case BINN_STORAGE_STRING:
		if (size < 0)
			return FALSE;
		if (size == 0)
			size = strlen2((char *) pvalue);
		ArgSize = size + 5; // at least this size
		break;
	case BINN_STORAGE_CONTAINER:
		if (size <= 0)
			return FALSE;
		ArgSize = size;
		break;
	default:
		return FALSE;
	}

	ArgSize += 2;  // at least 2 bytes used for data_type.
	if (CheckAllocation(item, ArgSize) == FALSE)
		return FALSE;

	// Gets the pointer to the next place in buffer
	p = ((unsigned char *)item->pbuf) + item->used_size;

	// If the data is not a container, store the data type
	if (storage_type != BINN_STORAGE_CONTAINER) {
		if (type > 255) {
			u16 type16 = type;

			copy_be16((u16 *)p, (u16 *)&type16);
			p += 2;
			item->used_size += 2;
		} else {
			*p = type;
			p++;
			item->used_size++;
		}
	}

	switch (storage_type) {
	case BINN_STORAGE_NOBYTES:
		// Nothing to do.
		break;
	case BINN_STORAGE_BYTE:
		*((char *)p) = *((char *) pvalue);
		item->used_size += 1;
		break;
	case BINN_STORAGE_WORD:
		copy_be16((u16 *)p, (u16 *)pvalue);
		item->used_size += 2;
		break;
	case BINN_STORAGE_DWORD:
		copy_be32((u32 *)p, (u32 *)pvalue);
		item->used_size += 4;
		break;
	case BINN_STORAGE_QWORD:
		copy_be64((u64 *)p, (u64 *)pvalue);
		item->used_size += 8;
		break;
	case BINN_STORAGE_BLOB:
	case BINN_STORAGE_STRING:
		if (size > 127) {
			int32 = size | 0x80000000;
			copy_be32((u32 *)p, (u32 *)&int32);
			p += 4;
			item->used_size += 4;
		} else {
			*((unsigned char *)p) = size;
			p++;
			item->used_size++;
		}
		memcpy(p, pvalue, size);
		if (storage_type == BINN_STORAGE_STRING) {
			p += size;
			*((char *)p) = (char) 0;
			size++;  // null terminator
		}
		item->used_size += size;
		break;
	case BINN_STORAGE_CONTAINER:
		memcpy(p, pvalue, size);
		item->used_size += size;
		break;
	}

	item->dirty = TRUE;

	return TRUE;
}

/***************************************************************************/

BINN_PRIVATE BOOL binn_save_header(struct binn *item)
{
	unsigned char byte, *p;
	int int32;
#ifndef BINN_DISABLE_SMALL_HEADER
	int size;
#endif

	if (item == NULL)
		return FALSE;

#ifndef BINN_DISABLE_SMALL_HEADER

	p = ((unsigned char *)item->pbuf) + MAX_BINN_HEADER;
	size = item->used_size - MAX_BINN_HEADER + 3;  // at least 3 bytes for the header

	// write the count
	if (item->count > 127) {
		p -= 4;
		size += 3;
		int32 = item->count | 0x80000000;
		copy_be32((u32 *)p, (u32 *)&int32);
	} else {
		p--;
		*p = (unsigned char) item->count;
	}

	// write the size
	if (size > 127) {
		p -= 4;
		size += 3;
		int32 = size | 0x80000000;
		copy_be32((u32 *)p, (u32 *)&int32);
	} else {
		p--;
		*p = (unsigned char) size;
	}

	// write the type.
	p--;
	*p = (unsigned char)item->type;

	// set the values
	item->ptr = p;
	item->size = size;

	UNUSED(byte);

#else

	p = (unsigned char *)item->pbuf;

	// write the type.
	byte = item->type;
	*p = byte;
	p++;
	// write the size
	int32 = item->used_size | 0x80000000;
	copy_be32((u32 *)p, (u32 *)&int32);
	p += 4;
	// write the count
	int32 = item->count | 0x80000000;
	copy_be32((u32 *)p, (u32 *)&int32);

	item->ptr = item->pbuf;
	item->size = item->used_size;

#endif

	item->dirty = FALSE;

	return TRUE;
}

/***************************************************************************/

void APIENTRY binn_free(struct binn *item)
{
	if (item == NULL)
		return;

	if ((item->writable) && (item->pre_allocated == FALSE)) {
		free_fn(item->pbuf);
	}

	if (item->freefn)
		item->freefn(item->ptr);

	if (item->allocated) {
		free_fn(item);
	} else {
		memset(item, 0, sizeof(struct binn));
		item->header = BINN_MAGIC;
	}

}


/***************************************************************************/
/* free the struct binn structure but keeps the binn buffer allocated, returning a pointer to it. */
/* use the free function to release the buffer later */
void * APIENTRY binn_release(struct binn *item)
{
	void *data;

	if (item == NULL)
		return NULL;

	data = binn_ptr(item);

	if (data > item->pbuf) {
		memmove(item->pbuf, data, item->size);
		data = item->pbuf;
	}

	if (item->allocated) {
		free_fn(item);
	} else {
		memset(item, 0, sizeof(struct binn));
		item->header = BINN_MAGIC;
	}

	return data;

}


/***************************************************************************/

BINN_PRIVATE BOOL IsValidBinnHeader(void *pbuf, int *ptype, int *pcount,
		int *psize, int *pheadersize)
{
	unsigned char byte, *p, *plimit = 0;
	int int32, type, size, count;

	if (pbuf == NULL)
		return FALSE;

	p = (unsigned char *)pbuf;

	if (psize && *psize > 0) {
		plimit = p + *psize - 1;
	}

	// get the type
	byte = *p;
	p++;
	if ((byte & BINN_STORAGE_MASK) != BINN_STORAGE_CONTAINER)
		return FALSE;

	if (byte & BINN_STORAGE_HAS_MORE)
		return FALSE;

	type = byte;

	switch (type) {
	case BINN_LIST:
	case BINN_MAP:
	case BINN_OBJECT:
		break;

	default:
		return FALSE;
	}

	// get the size
	if (plimit && p > plimit)
		return FALSE;
	int32 = *((unsigned char *)p);
	if (int32 & 0x80) {
		if (plimit && p + sizeof(int) - 1 > plimit)
			return FALSE;
		copy_be32((u32 *)&int32, (u32 *)p);
		int32 &= 0x7FFFFFFF;
		p += 4;
	} else {
		p++;
	}
	size = int32;

	// get the count
	if (plimit && p > plimit)
		return FALSE;
	int32 = *((unsigned char *)p);
	if (int32 & 0x80) {
		if (plimit && p + sizeof(int) - 1 > plimit)
			return FALSE;
		copy_be32((u32 *)&int32, (u32 *)p);
		int32 &= 0x7FFFFFFF;
		p += 4;
	} else {
		p++;
	}
	count = int32;

	if ((size < MIN_BINN_SIZE) || (count < 0))
		return FALSE;

	// return the values
	if (ptype)
		*ptype  = type;
	if (pcount)
		*pcount = count;
	if (psize && *psize == 0)
		*psize = size;
	if (pheadersize)
		*pheadersize = (int)(p - (unsigned char *)pbuf);

	return TRUE;
}

/***************************************************************************/

BINN_PRIVATE int binn_buf_type(void *pbuf)
{
	int  type;

	if (!IsValidBinnHeader(pbuf, &type, NULL, NULL, NULL))
		return INVALID_BINN;

	return type;
}

/***************************************************************************/

BINN_PRIVATE int binn_buf_count(void *pbuf)
{
	int  nitems;

	if (!IsValidBinnHeader(pbuf, NULL, &nitems, NULL, NULL))
		return 0;

	return nitems;
}

/***************************************************************************/

BINN_PRIVATE int binn_buf_size(void *pbuf)
{
	int  size = 0;

	if (!IsValidBinnHeader(pbuf, NULL, NULL, &size, NULL))
		return 0;

	return size;
}

/***************************************************************************/

void * APIENTRY binn_ptr(void *ptr)
{
	struct binn *item;

	switch (binn_get_ptr_type(ptr)) {
	case BINN_STRUCT:
		item = (struct binn *)ptr;
		if (item->writable && item->dirty) {
			binn_save_header(item);
		}
		return item->ptr;
	case BINN_BUFFER:
		return ptr;
	default:
		return NULL;
	}
}

/***************************************************************************/

int APIENTRY binn_size(void *ptr)
{
	struct binn *item;

	switch (binn_get_ptr_type(ptr)) {
	case BINN_STRUCT:
		item = (struct binn *)ptr;
		if (item->writable && item->dirty) {
			binn_save_header(item);
		}
		return item->size;
	case BINN_BUFFER:
		return binn_buf_size(ptr);
	default:
		return 0;
	}

}

/***************************************************************************/

int APIENTRY binn_type(void *ptr)
{
	struct binn *item;

	switch (binn_get_ptr_type(ptr)) {
	case BINN_STRUCT:
		item = (struct binn *)ptr;
		return item->type;
	case BINN_BUFFER:
		return binn_buf_type(ptr);
	default:
		return -1;
	}

}

/***************************************************************************/

int APIENTRY binn_count(void *ptr)
{
	struct binn *item;

	switch (binn_get_ptr_type(ptr)) {
	case BINN_STRUCT:
		item = (struct binn *)ptr;
		return item->count;
	case BINN_BUFFER:
		return binn_buf_count(ptr);
	default:
		return -1;
	}

}

/***************************************************************************/

BOOL APIENTRY binn_is_valid_ex(void *ptr, int *ptype, int *pcount, int *psize)
{
	int  i, type, count, size, header_size;
	unsigned char *p, *plimit, *base, len;
	void *pbuf;

	pbuf = binn_ptr(ptr);
	if (pbuf == NULL)
		return FALSE;

	// is there an informed size?
	if (psize && *psize > 0) {
		size = *psize;
	} else {
		size = 0;
	}

	if (!IsValidBinnHeader(pbuf, &type, &count, &size, &header_size))
		return FALSE;

	// is there an informed size?
	if (psize && *psize > 0) {
		// is it the same as the one in the buffer?
		if (size != *psize)
			return FALSE;
	}
	// is there an informed count?
	if (pcount && *pcount > 0) {
		// is it the same as the one in the buffer?
		if (count != *pcount)
			return FALSE;
	}
	// is there an informed type?
	if (ptype && *ptype != 0) {
		// is it the same as the one in the buffer?
		if (type != *ptype)
			return FALSE;
	}

	// it could compare the content size with the size informed on the header

	p = (unsigned char *)pbuf;
	base = p;
	plimit = p + size;

	p += header_size;

	// process all the arguments.
	for (i = 0; i < count; i++) {
		switch (type) {
		case BINN_OBJECT:
			// gets the string size (argument name)
			len = *p;
			p++;
			//if (len == 0) goto Invalid;
			// increment the used space
			p += len;
			break;
		case BINN_MAP:
			// increment the used space
			p += 4;
			break;
		//case BINN_LIST:
		//  break;
		default:
			break;
		}

		p = AdvanceDataPos(p, plimit);
		if ((p == 0) || (p < base))
			goto Invalid;
	}

	if (ptype && *ptype == 0)
		*ptype = type;

	if (pcount && *pcount == 0)
		*pcount = count;

	if (psize && *psize == 0)
		*psize = size;

	return TRUE;

Invalid:
	return FALSE;
}

/***************************************************************************/

BOOL APIENTRY binn_is_valid(void *ptr, int *ptype, int *pcount, int *psize)
{
	if (ptype)
		*ptype = 0;
	if (pcount)
		*pcount = 0;
	if (psize)
		*psize = 0;

	return binn_is_valid_ex(ptr, ptype, pcount, psize);
}

/***************************************************************************/
/*** INTERNAL FUNCTIONS ****************************************************/
/***************************************************************************/

BINN_PRIVATE BOOL GetValue(unsigned char *p, struct binn *value)
{
	unsigned char byte;
	int   data_type, storage_type;  //, extra_type;
	int   DataSize;
	void *p2;

	if (value == NULL)
		return FALSE;

	memset(value, 0, sizeof(struct binn));
	value->header = BINN_MAGIC;
	//value->allocated = FALSE;  --  already zeroed
	//value->writable = FALSE;

	// saves for use with BINN_STORAGE_CONTAINER
	p2 = p;

	// read the data type
	byte = *p; p++;
	storage_type = byte & BINN_STORAGE_MASK;

	if (byte & BINN_STORAGE_HAS_MORE) {
		data_type = byte << 8;
		byte = *p; p++;
		data_type |= byte;
		//extra_type = data_type & BINN_TYPE_MASK16;
	} else {
		data_type = byte;
		//extra_type = byte & BINN_TYPE_MASK;
	}

	//value->storage_type = storage_type;
	value->type = data_type;

	switch (storage_type) {
	case BINN_STORAGE_NOBYTES:
		break;
	case BINN_STORAGE_BYTE:
		value->vuint8 = *((unsigned char *)p);
		value->ptr = p;   //value->ptr = &value->vuint8;
		break;
	case BINN_STORAGE_WORD:
		copy_be16((u16 *)&value->vint16, (u16 *)p);
		value->ptr = &value->vint16;
		break;
	case BINN_STORAGE_DWORD:
		copy_be32((u32 *)&value->vint32, (u32 *)p);
		value->ptr = &value->vint32;
		break;
	case BINN_STORAGE_QWORD:
		copy_be64((u64 *)&value->vint64, (u64 *)p);
		value->ptr = &value->vint64;
		break;
	case BINN_STORAGE_BLOB:
	case BINN_STORAGE_STRING:
		DataSize = *((unsigned char *)p);
		if (DataSize & 0x80) {
			copy_be32((u32 *)&DataSize, (u32 *)p);
			DataSize &= 0x7FFFFFFF;
			p += 4;
		} else {
			p++;
		}
		value->size = DataSize;
		value->ptr = p;
		break;
	case BINN_STORAGE_CONTAINER:
		value->ptr = p2;  // <-- it returns the pointer to the container, not the data
		if (IsValidBinnHeader(p2, NULL, &value->count, &value->size, NULL) == FALSE)
			return FALSE;
		break;
	default:
		return FALSE;
	}

	// convert the returned value, if needed

	switch (value->type) {
	case BINN_TRUE:
		value->type = BINN_BOOL;
		value->vbool = TRUE;
		value->ptr = &value->vbool;
		break;
	case BINN_FALSE:
		value->type = BINN_BOOL;
		value->vbool = FALSE;
		value->ptr = &value->vbool;
		break;
#ifdef BINN_EXTENDED
#if !defined(__KERNEL__)
	case BINN_SINGLE_STR:
		value->type = BINN_SINGLE;

		/* converts from string to double, and then to float */
		value->vfloat = (float)atof((const char *)value->ptr);

		value->ptr = &value->vfloat;
		break;
	case BINN_DOUBLE_STR:
		value->type = BINN_DOUBLE;

		value->vdouble = atof((const char *)value->ptr);  // converts from string to double
		value->ptr = &value->vdouble;
		break;
#endif /*__KERNEL__*/
#endif
	}

	return TRUE;
}

/***************************************************************************/

#if BYTE_ORDER == LITTLE_ENDIAN

/* on little-endian devices we store the value so we can return a pointer to integers. */
/* it's valid only for single-threaded apps. */
/*multi-threaded apps must use the _get_ functions instead. */

struct binn local_value;

BINN_PRIVATE void *store_value(struct binn *value)
{
	memcpy(&local_value, value, sizeof(struct binn));

	switch (binn_get_read_storage(value->type)) {
	case BINN_STORAGE_NOBYTES:
		// return a valid pointer
	case BINN_STORAGE_WORD:
	case BINN_STORAGE_DWORD:
	case BINN_STORAGE_QWORD:
		/* returns the pointer to the converted value, from big-endian to little-endian */
		return &local_value.vint32;
	}

	/* returns from the on stack value to be thread-safe (for list, map, object, string and blob) */
	return value->ptr;

}

#endif

/***************************************************************************/
/*** READ FUNCTIONS ********************************************************/
/***************************************************************************/

BOOL APIENTRY binn_object_get_value(void *ptr, char *key, struct binn *value)
{
	int type, count, size = 0, header_size;
	unsigned char *p;

	ptr = binn_ptr(ptr);
	if ((ptr == 0) || (key == 0) || (value == 0))
		return FALSE;

	// check the header
	if (IsValidBinnHeader(ptr, &type, &count, &size, &header_size) == FALSE)
		return FALSE;

	if (type != BINN_OBJECT)
		return FALSE;
	if (count == 0)
		return FALSE;

	p = (unsigned char *)ptr;
	p = SearchForKey(p, header_size, size, count, key);
	if (p == FALSE)
		return FALSE;

	return GetValue(p, value);

}


/***************************************************************************/

BOOL APIENTRY binn_map_get_value(void *ptr, int id, struct binn *value)
{
	int type, count, size = 0, header_size;
	unsigned char *p;

	ptr = binn_ptr(ptr);
	if ((ptr == 0) || (value == 0))
		return FALSE;

	// check the header
	if (IsValidBinnHeader(ptr, &type, &count, &size, &header_size) == FALSE)
		return FALSE;

	if (type != BINN_MAP)
		return FALSE;
	if (count == 0)
		return FALSE;

	p = (unsigned char *)ptr;
	p = SearchForID(p, header_size, size, count, id);
	if (p == FALSE)
		return FALSE;

	return GetValue(p, value);

}

/***************************************************************************/

BOOL APIENTRY binn_list_get_value(void *ptr, int pos, struct binn *value)
{
	int  i, type, count, size = 0, header_size;
	unsigned char *p, *plimit, *base;

	ptr = binn_ptr(ptr);
	if ((ptr == 0) || (value == 0))
		return FALSE;

	// check the header
	if (IsValidBinnHeader(ptr, &type, &count, &size, &header_size) == FALSE)
		return FALSE;

	if (type != BINN_LIST)
		return FALSE;
	if (count == 0)
		return FALSE;
	if ((pos <= 0) | (pos > count))
		return FALSE;
	pos--;  // convert from base 1 to base 0

	p = (unsigned char *) ptr;
	base = p;
	plimit = p + size;
	p += header_size;

	for (i = 0; i < pos; i++) {
		p = AdvanceDataPos(p, plimit);
		if ((p == 0) || (p < base))
			return FALSE;
	}

	return GetValue(p, value);

}

/***************************************************************************/
/*** READ PAIR BY POSITION *************************************************/
/***************************************************************************/

BINN_PRIVATE BOOL binn_read_pair(int expected_type, void *ptr, int pos,
		int *pid, char *pkey, struct binn *value)
{
	int  type, count, size = 0, header_size;
	int  i, int32, id = 0, counter = 0;
	unsigned char *p, *plimit, *base, *key = NULL, len = 0;

	ptr = binn_ptr(ptr);

	// check the header
	if (IsValidBinnHeader(ptr, &type, &count, &size, &header_size) == FALSE)
		return FALSE;

	if ((type != expected_type) || (count == 0) || (pos < 1) || (pos > count))
		return FALSE;

	p = (unsigned char *) ptr;
	base = p;
	plimit = p + size - 1;
	p += header_size;

	for (i = 0; i < count; i++) {
		switch (type) {
		case BINN_MAP:
			copy_be32((u32 *)&int32, (u32 *)p);
			p += 4;
			if (p > plimit)
				return FALSE;
			id = int32;
			break;
		case BINN_OBJECT:
			len = *((unsigned char *)p); p++;
			if (p > plimit)
				return FALSE;
			key = p;
			p += len;
			if (p > plimit)
				return FALSE;
			break;
		}

		counter++;
		if (counter == pos)
			goto found;
		//
		p = AdvanceDataPos(p, plimit);
		if ((p == 0) || (p < base))
			return FALSE;
	}

	return FALSE;

found:

	switch (type) {
	case BINN_MAP:
		if (pid)
			*pid = id;
		break;
	case BINN_OBJECT:
		if (pkey) {
			memcpy(pkey, key, len);
			pkey[len] = 0;
		}
		break;
	}

	return GetValue(p, value);

}

/***************************************************************************/

BOOL APIENTRY binn_map_get_pair(void *ptr, int pos, int *pid, struct binn *value)
{
	return binn_read_pair(BINN_MAP, ptr, pos, pid, NULL, value);
}

/***************************************************************************/

BOOL APIENTRY binn_object_get_pair(void *ptr, int pos, char *pkey, struct binn *value)
{
	return binn_read_pair(BINN_OBJECT, ptr, pos, NULL, pkey, value);
}

/***************************************************************************/

struct binn * APIENTRY binn_map_pair(void *map, int pos, int *pid)
{
	struct binn *value;

	value = (struct binn *)binn_malloc(sizeof(struct binn));

	if (binn_read_pair(BINN_MAP, map, pos, pid, NULL, value) == FALSE) {
		free_fn(value);
		return NULL;
	}

	value->allocated = TRUE;
	return value;

}

/***************************************************************************/

struct binn * APIENTRY binn_object_pair(void *obj, int pos, char *pkey)
{
	struct binn *value;

	value = (struct binn *) binn_malloc(sizeof(struct binn));

	if (binn_read_pair(BINN_OBJECT, obj, pos, NULL, pkey, value) == FALSE) {
		free_fn(value);
		return NULL;
	}

	value->allocated = TRUE;
	return value;

}

/***************************************************************************/
/***************************************************************************/

void * APIENTRY binn_map_read_pair(void *ptr, int pos, int *pid, int *ptype, int *psize)
{
	struct binn value;

	if (binn_map_get_pair(ptr, pos, pid, &value) == FALSE)
		return NULL;
	if (ptype)
		*ptype = value.type;
	if (psize)
		*psize = value.size;

#if BYTE_ORDER == LITTLE_ENDIAN
	return store_value(&value);
#else
	return value.ptr;
#endif
}


/***************************************************************************/

void * APIENTRY binn_object_read_pair(void *ptr, int pos, char *pkey, int *ptype, int *psize)
{
	struct binn value;

	if (binn_object_get_pair(ptr, pos, pkey, &value) == FALSE)
		return NULL;
	if (ptype)
		*ptype = value.type;
	if (psize)
		*psize = value.size;

#if BYTE_ORDER == LITTLE_ENDIAN
	return store_value(&value);
#else
	return value.ptr;
#endif

}

/***************************************************************************/
/*** SEQUENTIAL READ FUNCTIONS *********************************************/
/***************************************************************************/

BOOL APIENTRY binn_iter_init(struct binn_iter *iter, void *ptr,
	int expected_type)
{
	int  type, count, size = 0, header_size;

	ptr = binn_ptr(ptr);
	if ((ptr == 0) || (iter == 0))
		return FALSE;
	memset(iter, 0, sizeof(struct binn_iter));

	// check the header
	if (IsValidBinnHeader(ptr, &type, &count, &size, &header_size) == FALSE)
		return FALSE;

	if (type != expected_type)
		return FALSE;
	//if (count == 0) return FALSE;  -- should not be used

	iter->plimit = (unsigned char *)ptr + size - 1;
	iter->pnext = (unsigned char *)ptr + header_size;
	iter->count = count;
	iter->binn_current = 0;
	iter->type = type;

	return TRUE;
}

/***************************************************************************/

BOOL APIENTRY binn_list_next(struct binn_iter *iter, struct binn *value)
{
	unsigned char *pnow;

	if ((iter == 0) || (iter->pnext == 0) || (iter->pnext > iter->plimit) ||
			(iter->binn_current > iter->count) || (iter->type != BINN_LIST))
		return FALSE;

	iter->binn_current++;
	if (iter->binn_current > iter->count)
		return FALSE;

	pnow = iter->pnext;
	iter->pnext = AdvanceDataPos(pnow, iter->plimit);
	if (iter->pnext != 0 && iter->pnext < pnow)
		return FALSE;

	return GetValue(pnow, value);
}


/***************************************************************************/

BINN_PRIVATE BOOL binn_read_next_pair(int expected_type,
		struct binn_iter *iter, int *pid, char *pkey, struct binn *value)
{
	int  int32, id;
	unsigned char *p, *key;
	unsigned short len;

	if ((iter == 0) || (iter->pnext == 0) || (iter->pnext > iter->plimit) ||
		(iter->binn_current > iter->count) || (iter->type != expected_type))
		return FALSE;

	iter->binn_current++;
	if (iter->binn_current > iter->count)
		return FALSE;

	p = iter->pnext;

	switch (expected_type) {
	case BINN_MAP:
		copy_be32((u32 *)&int32, (u32 *)p);
		p += 4;
		if (p > iter->plimit)
			return FALSE;
		id = int32;
		if (pid)
			*pid = id;
		break;
	case BINN_OBJECT:
		len = *((unsigned char *)p);
		p++;
		key = p;
		p += len;
		if (p > iter->plimit)
			return FALSE;
		if (pkey) {
			memcpy(pkey, key, len);
			pkey[len] = 0;
		}
		break;
	}

	iter->pnext = AdvanceDataPos(p, iter->plimit);
	if (iter->pnext != 0 && iter->pnext < p)
		return FALSE;

	return GetValue(p, value);

}

/***************************************************************************/

BOOL APIENTRY binn_map_next(struct binn_iter *iter, int *pid, struct binn *value)
{
	return binn_read_next_pair(BINN_MAP, iter, pid, NULL, value);
}

/***************************************************************************/

BOOL APIENTRY binn_object_next(struct binn_iter *iter, char *pkey, struct binn *value)
{
	return binn_read_next_pair(BINN_OBJECT, iter, NULL, pkey, value);
}


/***************************************************************************/
/***************************************************************************/

struct binn * APIENTRY binn_list_next_value(struct binn_iter *iter)
{
	struct binn *value;

	value = (struct binn *) binn_malloc(sizeof(struct binn));

	if (binn_list_next(iter, value) == FALSE) {
		free_fn(value);
		return NULL;
	}

	value->allocated = TRUE;
	return value;
}

/***************************************************************************/

struct binn * APIENTRY binn_map_next_value(struct binn_iter *iter, int *pid)
{
	struct binn *value;

	value = (struct binn *) binn_malloc(sizeof(struct binn));

	if (binn_map_next(iter, pid, value) == FALSE) {
		free_fn(value);
		return NULL;
	}

	value->allocated = TRUE;
	return value;

}

/***************************************************************************/

struct binn * APIENTRY binn_object_next_value(struct binn_iter *iter, char *pkey)
{
	struct binn *value;

	value = (struct binn *) binn_malloc(sizeof(struct binn));

	if (binn_object_next(iter, pkey, value) == FALSE) {
		free_fn(value);
		return NULL;
	}

	value->allocated = TRUE;
	return value;

}

/***************************************************************************/
/***************************************************************************/

void * APIENTRY binn_list_read_next(struct binn_iter *iter, int *ptype, int *psize)
{
	struct binn value;

	if (binn_list_next(iter, &value) == FALSE)
		return NULL;
	if (ptype)
		*ptype = value.type;
	if (psize)
		*psize = value.size;

#if BYTE_ORDER == LITTLE_ENDIAN
	return store_value(&value);
#else
	return value.ptr;
#endif

}

/***************************************************************************/

void * APIENTRY binn_map_read_next(struct binn_iter *iter, int *pid, int *ptype, int *psize)
{
	struct binn value;

	if (binn_map_next(iter, pid, &value) == FALSE)
		return NULL;
	if (ptype)
		*ptype = value.type;
	if (psize)
		*psize = value.size;

#if BYTE_ORDER == LITTLE_ENDIAN
	return store_value(&value);
#else
	return value.ptr;
#endif

}

/***************************************************************************/

void * APIENTRY binn_object_read_next(struct binn_iter *iter, char *pkey, int *ptype, int *psize)
{
	struct binn value;

	if (binn_object_next(iter, pkey, &value) == FALSE)
		return NULL;
	if (ptype)
		*ptype = value.type;
	if (psize)
		*psize = value.size;
#if BYTE_ORDER == LITTLE_ENDIAN
	return store_value(&value);
#else
	return value.ptr;
#endif

}

/*************************************************************************************/
/****** EXTENDED INTERFACE ***********************************************************/
/****** none of the functions above call the functions below *************************/
/*************************************************************************************/

int APIENTRY binn_get_write_storage(int type)
{
	int storage_type;

	switch (type) {
	case BINN_SINGLE_STR:
	case BINN_DOUBLE_STR:
		return BINN_STORAGE_STRING;

	case BINN_BOOL:
		return BINN_STORAGE_NOBYTES;

	default:
		binn_get_type_info(type, &storage_type, NULL);
		return storage_type;
	}

}

/*************************************************************************************/

int APIENTRY binn_get_read_storage(int type)
{
	int storage_type;

	switch (type) {
#ifdef BINN_EXTENDED
	case BINN_SINGLE_STR:
		return BINN_STORAGE_DWORD;
	case BINN_DOUBLE_STR:
		return BINN_STORAGE_QWORD;
#endif
	case BINN_BOOL:
	case BINN_TRUE:
	case BINN_FALSE:
		return BINN_STORAGE_DWORD;
	default:
		binn_get_type_info(type, &storage_type, NULL);
		return storage_type;
	}

}

/*************************************************************************************/

BINN_PRIVATE BOOL GetWriteConvertedData(int *ptype, void **ppvalue, int *psize)
{
	int  type;
#ifdef BINN_EXTENDED
	float  f1;
	double d1;
	char pstr[128];

	UNUSED(pstr);
	UNUSED(d1);
	UNUSED(f1);
#endif /*BINN_EXTENDED*/
	type = *ptype;

	if (*ppvalue == NULL) {
		switch (type) {
		case BINN_NULL:
		case BINN_TRUE:
		case BINN_FALSE:
			break;
		case BINN_STRING:
		case BINN_BLOB:
			if (*psize == 0) {
				break;
			} else {
				return FALSE;
			}
		default:
			return FALSE;
		}
	}

	switch (type) {
#ifdef BINN_EXTENDED
	case BINN_SINGLE:
		f1 = **(float **)ppvalue;
		d1 = f1;  // convert from float (32bits) to double (64bits)
		type = BINN_SINGLE_STR;
		goto conv_double;
	case BINN_DOUBLE:
		d1 = **(double **)ppvalue;
		type = BINN_DOUBLE_STR;
conv_double:
		// the '%.17e' is more precise than the '%g'
		snprintf(pstr, 127, "%.17e", d1);
		*ppvalue = pstr;
		*ptype = type;
		break;
#endif
	case BINN_DECIMAL:
	case BINN_CURRENCYSTR:
		return TRUE;  //! temporary

	case BINN_DATE:
	case BINN_DATETIME:
	case BINN_TIME:
		return TRUE;  //! temporary

	case BINN_BOOL:
		if (**((BOOL **)ppvalue) == FALSE) {
			type = BINN_FALSE;
		} else {
			type = BINN_TRUE;
		}
		*ptype = type;
		break;

	}

	return TRUE;

}

/*************************************************************************************/

BINN_PRIVATE int type_family(int type)
{

	switch (type) {
	case BINN_LIST:
	case BINN_MAP:
	case BINN_OBJECT:
		return BINN_FAMILY_BINN;

	case BINN_INT8:
	case BINN_INT16:
	case BINN_INT32:
	case BINN_INT64:
	case BINN_UINT8:
	case BINN_UINT16:
	case BINN_UINT32:
	case BINN_UINT64:
		return BINN_FAMILY_INT;

	case BINN_FLOAT32:
	case BINN_FLOAT64:
	//case BINN_SINGLE:
	case BINN_SINGLE_STR:
	//case BINN_DOUBLE:
	case BINN_DOUBLE_STR:
		return BINN_FAMILY_FLOAT;

	case BINN_STRING:
	case BINN_HTML:
	case BINN_CSS:
	case BINN_XML:
	case BINN_JSON:
	case BINN_JAVASCRIPT:
		return BINN_FAMILY_STRING;

	case BINN_BLOB:
	case BINN_JPEG:
	case BINN_GIF:
	case BINN_PNG:
	case BINN_BMP:
		return BINN_FAMILY_BLOB;

	case BINN_DECIMAL:
	case BINN_CURRENCY:
	case BINN_DATE:
	case BINN_TIME:
	case BINN_DATETIME:
		return BINN_FAMILY_STRING;

	case BINN_BOOL:
		return BINN_FAMILY_BOOL;

	case BINN_NULL:
		return BINN_FAMILY_NULL;

	default:
		// if it wasn't found
		return BINN_FAMILY_NONE;
	}

}

/*************************************************************************************/

BINN_PRIVATE int int_type(int type)
{
	switch (type) {
	case BINN_INT8:
	case BINN_INT16:
	case BINN_INT32:
	case BINN_INT64:
		return BINN_SIGNED_INT;

	case BINN_UINT8:
	case BINN_UINT16:
	case BINN_UINT32:
	case BINN_UINT64:
		return BINN_UNSIGNED_INT;

	default:
		return 0;
	}

}

/*************************************************************************************/

BINN_PRIVATE BOOL copy_raw_value(void *psource, void *pdest, int data_store)
{
	switch (data_store) {
	case BINN_STORAGE_NOBYTES:
		break;
	case BINN_STORAGE_BYTE:
		*((char *) pdest) = *(char *)psource;
		break;
	case BINN_STORAGE_WORD:
		*((short *) pdest) = *(short *)psource;
		break;
	case BINN_STORAGE_DWORD:
		*((int *) pdest) = *(int *)psource;
		break;
	case BINN_STORAGE_QWORD:
		*((uint64 *) pdest) = *(uint64 *)psource;
		break;
	case BINN_STORAGE_BLOB:
	case BINN_STORAGE_STRING:
	case BINN_STORAGE_CONTAINER:
		*((char **) pdest) = (char *)psource;
		break;
	default:
		return FALSE;
	}

	return TRUE;

}

/*************************************************************************************/

BINN_PRIVATE BOOL copy_int_value(void *psource, void *pdest, int source_type, int dest_type)
{
	uint64 vuint64 = 0;
	int64 vint64 = 0;

	switch (source_type) {
	case BINN_INT8:
		vint64 = *(signed char *)psource;
		break;
	case BINN_INT16:
		vint64 = *(short *)psource;
		break;
	case BINN_INT32:
		vint64 = *(int *)psource;
		break;
	case BINN_INT64:
		vint64 = *(int64 *)psource;
		break;

	case BINN_UINT8:
		vuint64 = *(unsigned char *)psource;
		break;
	case BINN_UINT16:
		vuint64 = *(unsigned short *)psource;
		break;
	case BINN_UINT32:
		vuint64 = *(unsigned int *)psource;
		break;
	case BINN_UINT64:
		vuint64 = *(uint64 *)psource;
		break;

	default:
		return FALSE;
	}


	// copy from int64 to uint64, if possible

	if ((int_type(source_type) == BINN_UNSIGNED_INT) &&
		(int_type(dest_type) == BINN_SIGNED_INT)) {
		if (vuint64 > INT64_MAX)
			return FALSE;

		vint64 = vuint64;
	} else if ((int_type(source_type) == BINN_SIGNED_INT) &&
		(int_type(dest_type) == BINN_UNSIGNED_INT)) {
		if (vint64 < 0)
			return FALSE;

		vuint64 = vint64;
	}


	switch (dest_type) {
	case BINN_INT8:
		if ((vint64 < INT8_MIN) || (vint64 > INT8_MAX))
			return FALSE;
		*(signed char *)pdest = (signed char) vint64;
		break;
	case BINN_INT16:
		if ((vint64 < INT16_MIN) || (vint64 > INT16_MAX))
			return FALSE;
		*(short *)pdest = (short) vint64;
		break;
	case BINN_INT32:
		if ((vint64 < INT32_MIN) || (vint64 > INT32_MAX))
			return FALSE;
		*(int *)pdest = (int) vint64;
		break;
	case BINN_INT64:
		*(int64 *)pdest = vint64;
		break;

	case BINN_UINT8:
		if (vuint64 > UINT8_MAX)
			return FALSE;
		*(unsigned char *)pdest = (unsigned char) vuint64;
		break;
	case BINN_UINT16:
		if (vuint64 > UINT16_MAX)
			return FALSE;
		*(unsigned short *)pdest = (unsigned short) vuint64;
		break;
	case BINN_UINT32:
		if (vuint64 > UINT32_MAX)
			return FALSE;
		*(unsigned int *)pdest = (unsigned int) vuint64;
		break;
	case BINN_UINT64:
		*(uint64 *)pdest = vuint64;
		break;

	default:
		return FALSE;
	}

	return TRUE;

}

/*************************************************************************************/

#if !defined(__KERNEL__)
BINN_PRIVATE BOOL copy_float_value(void *psource, void *pdest, int source_type, int dest_type)
{
	switch (source_type) {
	case BINN_FLOAT32:
		*(double *)pdest = *(float *)psource;
		break;
	case BINN_FLOAT64:
		*(float *)pdest = (float) *(double *)psource;
		break;
	default:
		return FALSE;
	}

	return TRUE;
}
#endif /*__KERNEL__*/
/*************************************************************************************/

BINN_PRIVATE void zero_value(void *pvalue, int type)
{
	switch (binn_get_read_storage(type)) {
	case BINN_STORAGE_NOBYTES:
		break;
	case BINN_STORAGE_BYTE:
		*((char *) pvalue) = 0;
		//size=1;
		break;
	case BINN_STORAGE_WORD:
		*((short *) pvalue) = 0;
		//size=2;
		break;
	case BINN_STORAGE_DWORD:
		*((int *) pvalue) = 0;
		//size=4;
		break;
	case BINN_STORAGE_QWORD:
		*((uint64 *) pvalue) = 0;
		//size=8;
		break;
	case BINN_STORAGE_BLOB:
	case BINN_STORAGE_STRING:
	case BINN_STORAGE_CONTAINER:
		*(char **)pvalue = NULL;
		break;
	}

}

/*************************************************************************************/

BINN_PRIVATE BOOL copy_value(void *psource, void *pdest, int source_type,
	int dest_type, int data_store)
{
	if (type_family(source_type) != type_family(dest_type))
		return FALSE;

	if ((type_family(source_type) == BINN_FAMILY_INT) && (source_type != dest_type)) {
		return copy_int_value(psource, pdest, source_type, dest_type);
	}
#if !defined(__KERNEL__)
	else if ((type_family(source_type) == BINN_FAMILY_FLOAT) && (source_type != dest_type)) {
		return copy_float_value(psource, pdest, source_type, dest_type);
	}
#endif /*__KERNEL__*/
	else {
		return copy_raw_value(psource, pdest, data_store);
	}
}

/*************************************************************************************/
/*** WRITE FUNCTIONS *****************************************************************/
/*************************************************************************************/

BOOL APIENTRY binn_list_add(struct binn *list, int type, void *pvalue, int size)
{
	if (GetWriteConvertedData(&type, &pvalue, &size) == FALSE)
		return FALSE;

	return binn_list_add_raw(list, type, pvalue, size);
}

/*************************************************************************************/

BOOL APIENTRY binn_map_set(struct binn *map, int id, int type, void *pvalue, int size)
{
	if (GetWriteConvertedData(&type, &pvalue, &size) == FALSE)
		return FALSE;

	return binn_map_set_raw(map, id, type, pvalue, size);
}

/*************************************************************************************/

BOOL APIENTRY binn_object_set(struct binn *obj, char *key, int type, void *pvalue, int size)
{
	if (GetWriteConvertedData(&type, &pvalue, &size) == FALSE)
		return FALSE;

	return binn_object_set_raw(obj, key, type, pvalue, size);
}

/*************************************************************************************/

// this function is used by the wrappers
BOOL APIENTRY binn_add_value(struct binn *item, int binn_type, int id, char *name,
	int type, void *pvalue, int size)
{
	switch (binn_type) {
	case BINN_LIST:
		return binn_list_add(item, type, pvalue, size);
	case BINN_MAP:
		return binn_map_set(item, id, type, pvalue, size);
	case BINN_OBJECT:
		return binn_object_set(item, name, type, pvalue, size);
	default:
		return FALSE;
	}
}

/*************************************************************************************/
/*************************************************************************************/

BOOL APIENTRY binn_list_add_new(struct binn *list, struct binn *value)
{
	BOOL retval;

	if ((list == NULL) || (value == NULL))
		return FALSE;

	retval = binn_list_add_value(list, value);
	if (value)
		free_fn(value);
	return retval;
}

/*************************************************************************************/

BOOL APIENTRY binn_map_set_new(struct binn *map, int id, struct binn *value)
{
	BOOL retval;

	if ((map == NULL) || (value == NULL))
		return FALSE;

	retval = binn_map_set_value(map, id, value);
	if (value)
		free_fn(value);

	return retval;
}

/*************************************************************************************/

BOOL APIENTRY binn_object_set_new(struct binn *obj, char *key, struct binn *value)
{
	BOOL retval;

	if (value == NULL)
		return false;

	retval = binn_object_set_value(obj, key, value);
	if (value)
		free_fn(value);

	return retval;
}

/*************************************************************************************/
/*** READ FUNCTIONS ******************************************************************/
/*************************************************************************************/

struct binn * APIENTRY binn_list_value(void *ptr, int pos)
{
	struct binn *value;

	value = (struct binn *)binn_malloc(sizeof(struct binn));

	if (binn_list_get_value(ptr, pos, value) == FALSE) {
		free_fn(value);
		return NULL;
	}

	value->allocated = TRUE;
	return value;
}

/*************************************************************************************/

struct binn * APIENTRY binn_map_value(void *ptr, int id)
{
	struct binn *value;

	value = (struct binn *)binn_malloc(sizeof(struct binn));

	if (binn_map_get_value(ptr, id, value) == FALSE) {
		free_fn(value);
		return NULL;
	}

	value->allocated = TRUE;
	return value;
}

/*************************************************************************************/

struct binn * APIENTRY binn_object_value(void *ptr, char *key)
{
	struct binn *value;

	value = (struct binn *)binn_malloc(sizeof(struct binn));

	if (binn_object_get_value(ptr, key, value) == FALSE) {
		free_fn(value);
		return NULL;
	}

	value->allocated = TRUE;
	return value;

}

/***************************************************************************/
/***************************************************************************/

void * APIENTRY binn_list_read(void *list, int pos, int *ptype, int *psize)
{
	struct binn value;

	if (binn_list_get_value(list, pos, &value) == FALSE)
		return NULL;
	if (ptype)
		*ptype = value.type;
	if (psize)
		*psize = value.size;
#if BYTE_ORDER == LITTLE_ENDIAN
	return store_value(&value);
#else
	return value.ptr;
#endif

}

/***************************************************************************/

void * APIENTRY binn_map_read(void *map, int id, int *ptype, int *psize)
{
	struct binn value;

	if (binn_map_get_value(map, id, &value) == FALSE)
		return NULL;
	if (ptype)
		*ptype = value.type;
	if (psize)
		*psize = value.size;
#if BYTE_ORDER == LITTLE_ENDIAN
	return store_value(&value);
#else
	return value.ptr;
#endif

}

/***************************************************************************/

void * APIENTRY binn_object_read(void *obj, char *key, int *ptype, int *psize)
{
	struct binn value;

	if (binn_object_get_value(obj, key, &value) == FALSE)
		return NULL;
	if (ptype)
		*ptype = value.type;
	if (psize)
		*psize = value.size;
#if BYTE_ORDER == LITTLE_ENDIAN
	return store_value(&value);
#else
	return value.ptr;
#endif

}

/***************************************************************************/
/***************************************************************************/

BOOL APIENTRY binn_list_get(void *ptr, int pos, int type, void *pvalue, int *psize)
{
	struct binn value;
	int storage_type;

	storage_type = binn_get_read_storage(type);
	if ((storage_type != BINN_STORAGE_NOBYTES) && (pvalue == NULL))
		return FALSE;

	zero_value(pvalue, type);

	if (binn_list_get_value(ptr, pos, &value) == FALSE)
		return FALSE;

	if (copy_value(value.ptr, pvalue, value.type, type, storage_type) == FALSE)
		return FALSE;

	if (psize)
		*psize = value.size;

	return TRUE;

}

/***************************************************************************/

BOOL APIENTRY binn_map_get(void *ptr, int id, int type, void *pvalue, int *psize)
{
	struct binn value;
	int storage_type;

	storage_type = binn_get_read_storage(type);
	if ((storage_type != BINN_STORAGE_NOBYTES) && (pvalue == NULL))
		return FALSE;

	zero_value(pvalue, type);

	if (binn_map_get_value(ptr, id, &value) == FALSE)
		return FALSE;

	if (copy_value(value.ptr, pvalue, value.type, type, storage_type) == FALSE)
		return FALSE;

	if (psize)
		*psize = value.size;

	return TRUE;

}

/***************************************************************************/

//   if (binn_object_get(obj, "multiplier", BINN_INT32, &multiplier, NULL) == FALSE) xxx;

BOOL APIENTRY binn_object_get(void *ptr, char *key, int type, void *pvalue, int *psize)
{
	struct binn value;
	int storage_type;

	storage_type = binn_get_read_storage(type);
	if ((storage_type != BINN_STORAGE_NOBYTES) && (pvalue == NULL))
		return FALSE;

	zero_value(pvalue, type);

	if (binn_object_get_value(ptr, key, &value) == FALSE)
		return FALSE;

	if (copy_value(value.ptr, pvalue, value.type, type, storage_type) == FALSE)
		return FALSE;

	if (psize)
		*psize = value.size;

	return TRUE;

}

/***************************************************************************/
/***************************************************************************/

// these functions below may not be implemented as inline functions, because
// they use a lot of space, even for the variable. so they will be exported.

// but what about using as static?
//    is there any problem with wrappers? can these wrappers implement these functions using the header?
//    if as static, will they be present even on modules that don't use the functions?

signed char APIENTRY binn_list_int8(void *list, int pos)
{
	signed char value;

	binn_list_get(list, pos, BINN_INT8, &value, NULL);

	return value;
}

short APIENTRY binn_list_int16(void *list, int pos)
{
	short value;

	binn_list_get(list, pos, BINN_INT16, &value, NULL);

	return value;
}

int APIENTRY binn_list_int32(void *list, int pos)
{
	int value;

	binn_list_get(list, pos, BINN_INT32, &value, NULL);

	return value;
}

int64 APIENTRY binn_list_int64(void *list, int pos)
{
	int64 value;

	binn_list_get(list, pos, BINN_INT64, &value, NULL);

	return value;
}

unsigned char APIENTRY binn_list_uint8(void *list, int pos)
{
	unsigned char value;

	binn_list_get(list, pos, BINN_UINT8, &value, NULL);

	return value;
}

unsigned short APIENTRY binn_list_uint16(void *list, int pos)
{
	unsigned short value;

	binn_list_get(list, pos, BINN_UINT16, &value, NULL);

	return value;
}

unsigned int APIENTRY binn_list_uint32(void *list, int pos)
{
	unsigned int value;

	binn_list_get(list, pos, BINN_UINT32, &value, NULL);

	return value;
}

uint64 APIENTRY binn_list_uint64(void *list, int pos)
{
	uint64 value;

	binn_list_get(list, pos, BINN_UINT64, &value, NULL);

	return value;
}

#if !defined(__KERNEL__)

float APIENTRY binn_list_float(void *list, int pos)
{
	float value;

	binn_list_get(list, pos, BINN_FLOAT32, &value, NULL);

	return value;
}


double APIENTRY binn_list_double(void *list, int pos)
{
	double value;

	binn_list_get(list, pos, BINN_FLOAT64, &value, NULL);

	return value;
}

#endif /*__KERNEL__*/

BOOL APIENTRY binn_list_bool(void *list, int pos)
{
	BOOL value;

	binn_list_get(list, pos, BINN_BOOL, &value, NULL);

	return value;
}

BOOL APIENTRY binn_list_null(void *list, int pos)
{
	return binn_list_get(list, pos, BINN_NULL, NULL, NULL);
}

char * APIENTRY binn_list_str(void *list, int pos)
{
	char *value;

	binn_list_get(list, pos, BINN_STRING, &value, NULL);

	return value;
}

void * APIENTRY binn_list_blob(void *list, int pos, int *psize)
{
	void *value;

	binn_list_get(list, pos, BINN_BLOB, &value, psize);

	return value;
}

void * APIENTRY binn_list_list(void *list, int pos)
{
	void *value;

	binn_list_get(list, pos, BINN_LIST, &value, NULL);

	return value;
}

void * APIENTRY binn_list_map(void *list, int pos)
{
	void *value;

	binn_list_get(list, pos, BINN_MAP, &value, NULL);

	return value;
}

void * APIENTRY binn_list_object(void *list, int pos)
{
	void *value;

	binn_list_get(list, pos, BINN_OBJECT, &value, NULL);

	return value;
}

/***************************************************************************/

signed char APIENTRY binn_map_int8(void *map, int id)
{
	signed char value;

	binn_map_get(map, id, BINN_INT8, &value, NULL);

	return value;
}

short APIENTRY binn_map_int16(void *map, int id)
{
	short value;

	binn_map_get(map, id, BINN_INT16, &value, NULL);

	return value;
}

int APIENTRY binn_map_int32(void *map, int id)
{
	int value;

	binn_map_get(map, id, BINN_INT32, &value, NULL);

	return value;
}

int64 APIENTRY binn_map_int64(void *map, int id)
{
	int64 value;

	binn_map_get(map, id, BINN_INT64, &value, NULL);

	return value;
}

unsigned char APIENTRY binn_map_uint8(void *map, int id)
{
	unsigned char value;

	binn_map_get(map, id, BINN_UINT8, &value, NULL);

	return value;
}

unsigned short APIENTRY binn_map_uint16(void *map, int id)
{
	unsigned short value;

	binn_map_get(map, id, BINN_UINT16, &value, NULL);

	return value;
}

unsigned int APIENTRY binn_map_uint32(void *map, int id)
{
	unsigned int value;

	binn_map_get(map, id, BINN_UINT32, &value, NULL);

	return value;
}

uint64 APIENTRY binn_map_uint64(void *map, int id)
{
	uint64 value;

	binn_map_get(map, id, BINN_UINT64, &value, NULL);

	return value;
}


#if !defined(__KERNEL__)

float APIENTRY binn_map_float(void *map, int id)
{
	float value;

	binn_map_get(map, id, BINN_FLOAT32, &value, NULL);

	return value;
}

double APIENTRY binn_map_double(void *map, int id)
{
	double value;

	binn_map_get(map, id, BINN_FLOAT64, &value, NULL);

	return value;
}

#endif /*__KERNEL__*/


BOOL APIENTRY binn_map_bool(void *map, int id)
{
	BOOL value;

	binn_map_get(map, id, BINN_BOOL, &value, NULL);

	return value;
}

BOOL APIENTRY binn_map_null(void *map, int id)
{
	return binn_map_get(map, id, BINN_NULL, NULL, NULL);
}

char * APIENTRY binn_map_str(void *map, int id)
{
	char *value;

	binn_map_get(map, id, BINN_STRING, &value, NULL);

	return value;
}

void * APIENTRY binn_map_blob(void *map, int id, int *psize)
{
	void *value;

	binn_map_get(map, id, BINN_BLOB, &value, psize);

	return value;
}

void * APIENTRY binn_map_list(void *map, int id)
{
	void *value;

	binn_map_get(map, id, BINN_LIST, &value, NULL);

	return value;
}

void * APIENTRY binn_map_map(void *map, int id)
{
	void *value;

	binn_map_get(map, id, BINN_MAP, &value, NULL);

	return value;
}

void * APIENTRY binn_map_object(void *map, int id)
{
	void *value;

	binn_map_get(map, id, BINN_OBJECT, &value, NULL);

	return value;
}

/***************************************************************************/

signed char APIENTRY binn_object_int8(void *obj, char *key)
{
	signed char value;

	binn_object_get(obj, key, BINN_INT8, &value, NULL);

	return value;
}

short APIENTRY binn_object_int16(void *obj, char *key)
{
	short value;

	binn_object_get(obj, key, BINN_INT16, &value, NULL);

	return value;
}

int APIENTRY binn_object_int32(void *obj, char *key)
{
	int value;

	binn_object_get(obj, key, BINN_INT32, &value, NULL);

	return value;
}

int64 APIENTRY binn_object_int64(void *obj, char *key)
{
	int64 value;

	binn_object_get(obj, key, BINN_INT64, &value, NULL);

	return value;
}

unsigned char APIENTRY binn_object_uint8(void *obj, char *key)
{
	unsigned char value;

	binn_object_get(obj, key, BINN_UINT8, &value, NULL);

	return value;
}

unsigned short APIENTRY binn_object_uint16(void *obj, char *key)
{
	unsigned short value;

	binn_object_get(obj, key, BINN_UINT16, &value, NULL);

	return value;
}

unsigned int APIENTRY binn_object_uint32(void *obj, char *key)
{
	unsigned int value;

	binn_object_get(obj, key, BINN_UINT32, &value, NULL);

	return value;
}

uint64 APIENTRY binn_object_uint64(void *obj, char *key)
{
	uint64 value;

	binn_object_get(obj, key, BINN_UINT64, &value, NULL);

	return value;
}

#if !defined(__KERNEL__)

float APIENTRY binn_object_float(void *obj, char *key)
{
	float value;

	binn_object_get(obj, key, BINN_FLOAT32, &value, NULL);

	return value;
}

double APIENTRY binn_object_double(void *obj, char *key)
{
	double value;

	binn_object_get(obj, key, BINN_FLOAT64, &value, NULL);

	return value;
}

#endif /*__KERNEL__*/

BOOL APIENTRY binn_object_bool(void *obj, char *key)
{
	BOOL value;

	binn_object_get(obj, key, BINN_BOOL, &value, NULL);

	return value;
}

BOOL APIENTRY binn_object_null(void *obj, char *key)
{
	return binn_object_get(obj, key, BINN_NULL, NULL, NULL);
}

char * APIENTRY binn_object_str(void *obj, char *key)
{
	char *value;

	binn_object_get(obj, key, BINN_STRING, &value, NULL);

	return value;
}

void * APIENTRY binn_object_blob(void *obj, char *key, int *psize)
{
	void *value;

	binn_object_get(obj, key, BINN_BLOB, &value, psize);

	return value;
}

void * APIENTRY binn_object_list(void *obj, char *key)
{
	void *value;

	binn_object_get(obj, key, BINN_LIST, &value, NULL);

	return value;
}

void * APIENTRY binn_object_map(void *obj, char *key)
{
	void *value;

	binn_object_get(obj, key, BINN_MAP, &value, NULL);

	return value;
}

void * APIENTRY binn_object_object(void *obj, char *key)
{
	void *value;

	binn_object_get(obj, key, BINN_OBJECT, &value, NULL);

	return value;
}

/*************************************************************************************/
/*************************************************************************************/

BINN_PRIVATE struct binn *binn_alloc_item(void)
{
	struct binn *item;

	item = (struct binn *)binn_malloc(sizeof(struct binn));
	if (item) {
		memset(item, 0, sizeof(struct binn));
		item->header = BINN_MAGIC;
		item->allocated = TRUE;
		//item->writable = FALSE;  -- already zeroed
	}
	return item;
}


/*************************************************************************************/

struct binn * APIENTRY binn_value(int type, void *pvalue, int size, binn_mem_free freefn)
{
	int storage_type;
	struct binn *item = binn_alloc_item();

	if (item) {
		item->type = type;
		binn_get_type_info(type, &storage_type, NULL);

		if (storage_type == BINN_STORAGE_STRING) {
			if (size == 0) {
				size = strlen((char *)pvalue) + 1;
			}
		}

		switch (storage_type) {
		case BINN_STORAGE_NOBYTES:
			break;
		case BINN_STORAGE_STRING:
		case BINN_STORAGE_BLOB:
		case BINN_STORAGE_CONTAINER:
			if (freefn == BINN_TRANSIENT) {
				item->ptr = binn_memdup(pvalue, size);
				if (item->ptr == NULL) {
					free_fn(item);
					return NULL;
				}
				item->freefn = free_fn;
				if (storage_type == BINN_STORAGE_STRING)
					size--;
			} else {
				item->ptr = pvalue;
				item->freefn = freefn;
			}
			item->size = size;
			break;
		default:
			item->ptr = &item->vint32;
			copy_raw_value(pvalue, item->ptr, storage_type);
		}
	}
	return item;
}

/*************************************************************************************/

BOOL APIENTRY binn_set_string(struct binn *item, char *str, binn_mem_free pfree)
{
	if (item == NULL || str == NULL)
		return FALSE;

	if (pfree == BINN_TRANSIENT) {
		item->ptr = binn_memdup(str, strlen(str) + 1);
		if (item->ptr == NULL)
			return FALSE;
		item->freefn = free_fn;
	} else {
		item->ptr = str;
		item->freefn = pfree;
	}

	item->type = BINN_STRING;
	return TRUE;
}

/*************************************************************************************/

BOOL APIENTRY binn_set_blob(struct binn *item, void *ptr, int size, binn_mem_free pfree)
{
	if (item == NULL || ptr == NULL)
		return FALSE;

	if (pfree == BINN_TRANSIENT) {
		item->ptr = binn_memdup(ptr, size);
		if (item->ptr == NULL)
			return FALSE;
		item->freefn = free_fn;
	} else {
		item->ptr = ptr;
		item->freefn = pfree;
	}

	item->type = BINN_BLOB;
	item->size = size;

	return TRUE;
}

/*************************************************************************************/
/*** READ CONVERTED VALUE ************************************************************/
/*************************************************************************************/

#ifdef _MSC_VER
#define atoi64 _atoi64
#else
int64 atoi64(char *str)
{
	int64 retval;
	int is_negative = 0;

	if (*str == '-') {
		is_negative = 1;
		str++;
	}
	retval = 0;
	for (; *str; str++) {
		retval = 10 * retval + (*str - '0');
	}
	if (is_negative)
		retval *= -1;
	return retval;
}
#endif

/*****************************************************************************/

BINN_PRIVATE BOOL is_integer(char *p)
{
	BOOL retval;

	if (p == NULL)
		return FALSE;
	if (*p == '-')
		p++;
	if (*p == 0)
		return FALSE;

	retval = TRUE;

	for (; *p; p++) {
		if ((*p < '0') || (*p > '9')) {
			retval = FALSE;
		}
	}

	return retval;
}


/*****************************************************************************/

#if !defined(__KERNEL__)
BINN_PRIVATE BOOL is_float(char *p)
{
	BOOL retval, number_found = FALSE;

	if (p == NULL)
		return FALSE;

	if (*p == '-')
		p++;
	if (*p == 0)
		return FALSE;

	retval = TRUE;

	for (; *p; p++) {
		if ((*p == '.') || (*p == ',')) {
			if (!number_found)
				retval = FALSE;
		} else if ((*p >= '0') && (*p <= '9')) {
			number_found = TRUE;
		} else {
			return FALSE;
		}
	}

	return retval;
}
#endif /*__KERNEL__*/

/*************************************************************************************/

BINN_PRIVATE BOOL is_bool_str(char *str, BOOL *pbool)
{
	int64  vint;
#if !defined(__KERNEL__)
	double vdouble;
#endif /*__KERNEL__*/
	if (str == NULL || pbool == NULL)
		return FALSE;

	if (stricmp(str, "true") == 0)
		goto loc_true;
	if (stricmp(str, "yes") == 0)
		goto loc_true;
	if (stricmp(str, "on") == 0)
		goto loc_true;

	if (stricmp(str, "false") == 0)
		goto loc_false;
	if (stricmp(str, "no") == 0)
		goto loc_false;
	if (stricmp(str, "off") == 0)
		goto loc_false;

	if (is_integer(str)) {
		vint = atoi64(str);
		*pbool = (vint != 0) ? TRUE : FALSE;
		return TRUE;
	}
#if !defined(__KERNEL__)
	else if (is_float(str)) {
		vdouble = atof(str);
		*pbool = (vdouble != 0) ? TRUE : FALSE;
		return TRUE;
	}
#endif /*__KERNEL__*/
	return FALSE;

loc_true:
	*pbool = TRUE;
	return TRUE;

loc_false:
	*pbool = FALSE;
	return TRUE;

}


/*************************************************************************************/

BOOL APIENTRY binn_get_int32(struct binn *value, int *pint)
{
	if (value == NULL || pint == NULL)
		return FALSE;

	if (type_family(value->type) == BINN_FAMILY_INT) {
		return copy_int_value(value->ptr, pint, value->type, BINN_INT32);
	}

	switch (value->type) {
#if !defined(__KERNEL__)
	case BINN_FLOAT:
		if ((value->vfloat < INT32_MIN) || (value->vfloat > INT32_MAX))
			return FALSE;
		*pint = roundval(value->vfloat);
		break;
	case BINN_DOUBLE:
		if ((value->vdouble < INT32_MIN) || (value->vdouble > INT32_MAX))
			return FALSE;
		*pint = roundval(value->vdouble);
		break;
#endif /*__KERNEL__*/
	case BINN_STRING:
		if (is_integer((char *)value->ptr))
			*pint = atoi((char *)value->ptr);
#if !defined(__KERNEL__)
		else if (is_float((char *)value->ptr)) {
			*pint = roundval(atof((char *)value->ptr));
		}
#endif /*__KERNEL__*/
		else
			return FALSE;
		break;
	case BINN_BOOL:
		*pint = value->vbool;
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

/*************************************************************************************/

BOOL APIENTRY binn_get_int64(struct binn *value, int64 *pint)
{
	if (value == NULL || pint == NULL)
		return FALSE;

	if (type_family(value->type) == BINN_FAMILY_INT) {
		return copy_int_value(value->ptr, pint, value->type, BINN_INT64);
	}

	switch (value->type) {
#if !defined(__KERNEL__)
	case BINN_FLOAT:
		if ((value->vfloat < INT64_MIN) || (value->vfloat > INT64_MAX))
			return FALSE;
		*pint = roundval(value->vfloat);
		break;

	case BINN_DOUBLE:
		if ((value->vdouble < INT64_MIN) || (value->vdouble > INT64_MAX))
			return FALSE;
		*pint = roundval(value->vdouble);
		break;

#endif /*__KERNEL__*/
	case BINN_STRING:
		if (is_integer((char *)value->ptr))
			*pint = atoi64((char *)value->ptr);
#if !defined(__KERNEL__)
		else if (is_float((char *)value->ptr)) {
			*pint = roundval(atof((char *)value->ptr));
		}
#endif /*__KERNEL__*/
		else
			return FALSE;
		break;

	case BINN_BOOL:
		*pint = value->vbool;
		break;

	default:
		return FALSE;
	}

	return TRUE;
}


/*************************************************************************************/

#if !defined(__KERNEL__)
BOOL APIENTRY binn_get_double(struct binn *value, double *pfloat)
{
	int64 vint;

	if (value == NULL || pfloat == NULL)
		return FALSE;

	if (type_family(value->type) == BINN_FAMILY_INT) {
		if (copy_int_value(value->ptr, &vint, value->type, BINN_INT64) == FALSE)
			return FALSE;
		*pfloat = (double) vint;
		return TRUE;
	}

	switch (value->type) {
	case BINN_FLOAT:
		*pfloat = value->vfloat;
		break;
	case BINN_DOUBLE:
		*pfloat = value->vdouble;
		break;
	case BINN_STRING:
		if (is_integer((char *)value->ptr))
			*pfloat = (double) atoi64((char *)value->ptr);
		else if (is_float((char *)value->ptr)) {
#if !defined(__KERNEL__)
			*pfloat = atof((char *)value->ptr);
#endif /*__KERNEL__*/
		} else {
			return FALSE;
		}
		break;
	case BINN_BOOL:
		*pfloat = value->vbool;
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

#endif /*__KERNEL__*/

/*************************************************************************************/

BOOL APIENTRY binn_get_bool(struct binn *value, BOOL *pbool)
{
	int64 vint;

	if (value == NULL || pbool == NULL)
		return FALSE;

	if (type_family(value->type) == BINN_FAMILY_INT) {
		if (copy_int_value(value->ptr, &vint, value->type, BINN_INT64) == FALSE)
			return FALSE;
		*pbool = (vint != 0) ? TRUE : FALSE;
		return TRUE;
	}

	switch (value->type) {
	case BINN_BOOL:
		*pbool = value->vbool;
		break;
#if !defined(__KERNEL__)
	case BINN_FLOAT:
		*pbool = (value->vfloat != 0) ? TRUE : FALSE;
		break;
	case BINN_DOUBLE:
		*pbool = (value->vdouble != 0) ? TRUE : FALSE;
		break;
#endif /*__KERNEL__*/
	case BINN_STRING:
		return is_bool_str((char *)value->ptr, pbool);
	default:
		return FALSE;
	}

	return TRUE;
}

/*************************************************************************************/

char * APIENTRY binn_get_str(struct binn *value)
{
	int64 vint;
	char buf[128];

	if (value == NULL)
		return NULL;

	if (type_family(value->type) == BINN_FAMILY_INT) {
		if (copy_int_value(value->ptr, &vint, value->type, BINN_INT64) == FALSE)
			return NULL;

		sprintf(buf, "%" INT64_FORMAT, vint);
		goto loc_convert_value;
	}

	switch (value->type) {
#if defined(__KERNEL__)
	case BINN_FLOAT:
	case BINN_DOUBLE:
		pr_err("Error Binn don't support double and float now\n");
		return NULL;
#else
	case BINN_FLOAT:
		value->vdouble = value->vfloat;
	case BINN_DOUBLE:
		sprintf(buf, "%g", value->vdouble);
		goto loc_convert_value;
#endif /*__KERNEL__*/
	case BINN_STRING:
		return (char *)value->ptr;
	case BINN_BOOL:
		if (value->vbool)
			strcpy(buf, "true");
		else
			strcpy(buf, "false");
		goto loc_convert_value;
	}

	return NULL;

loc_convert_value:

	//value->vint64 = 0;
	value->ptr = strdup(buf);
	if (value->ptr == NULL)
		return NULL;
#if defined(__KERNEL__)
	value->freefn = __kernel_free;
#else /*__KERNEL__*/
	value->freefn = free;
#endif /*__KERNEL__*/
	value->type = BINN_STRING;

	return (char *)value->ptr;
}


/*************************************************************************************/
/*** GENERAL FUNCTIONS ***************************************************************/
/*************************************************************************************/

BOOL APIENTRY binn_is_container(struct binn *item)
{
	if (item == NULL)
		return FALSE;

	switch (item->type) {
	case BINN_LIST:
	case BINN_MAP:
	case BINN_OBJECT:
		return TRUE;

	default:
		return FALSE;
	}
}

#if !defined(__KERNEL__)
int main(int argc, char *argv[])
{
}
#endif
/*************************************************************************************/
