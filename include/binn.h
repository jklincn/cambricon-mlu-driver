
// TO ENABLE INLINE FUNCTIONS:
//   ON MSVC: enable the 'Inline Function Expansion' (/Ob2) compiler option, and maybe the
//            'Whole Program Optimitazion' (/GL), that requires the
//            'Link Time Code Generation' (/LTCG) linker option to be enabled too

#ifndef BINN_H
#define BINN_H

#ifdef __cplusplus
extern "C" {
#endif


#ifndef NULL
#ifdef __cplusplus
#define NULL    0
#else
#define NULL    ((void *)0)
#endif
#endif

#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef BOOL
#define BOOL int
#endif

#if defined(__KERNEL__)
#if !defined(__GNUC__)
	typedef u64  uint64_t;
	typedef s64  int64_t;
#endif /*__GNUC__*/
#endif /*__KERNEL__*/

#ifndef APIENTRY
 #ifdef _WIN32
  #define APIENTRY __stdcall
 #else
  #define APIENTRY
 #endif
#endif

#ifndef BINN_PRIVATE
 #ifdef DEBUG
  #define BINN_PRIVATE
 #else
  #define BINN_PRIVATE  static
 #endif
#endif

#ifndef int64
#define int64 s64
#define uint64 u64
#endif

#ifdef _WIN32
#define INT64_FORMAT  "I64i"
#define UINT64_FORMAT "I64u"
#define INT64_HEX_FORMAT  "I64x"
#else
#define INT64_FORMAT  "lli"
#define UINT64_FORMAT "llu"
#define INT64_HEX_FORMAT  "llx"
#endif


/* BINN CONSTANTS  ---------------------------------------- */

#define INVALID_BINN         0

/* Storage Data Types  ------------------------------------ */

#define BINN_STORAGE_NOBYTES   0x00
#define BINN_STORAGE_BYTE      0x20  /*  8 bits */
#define BINN_STORAGE_WORD      0x40  /* 16 bits -- the endianness (byte order) is automatically corrected */
#define BINN_STORAGE_DWORD     0x60  /* 32 bits -- the endianness (byte order) is automatically corrected */
#define BINN_STORAGE_QWORD     0x80  /* 64 bits -- the endianness (byte order) is automatically corrected */
#define BINN_STORAGE_STRING    0xA0  /* Are stored with null termination */
#define BINN_STORAGE_BLOB      0xC0
#define BINN_STORAGE_CONTAINER 0xE0
#define BINN_STORAGE_VIRTUAL   0x80000

#define BINN_STORAGE_MIN       BINN_STORAGE_NOBYTES
#define BINN_STORAGE_MAX       BINN_STORAGE_CONTAINER

#define BINN_STORAGE_MASK      0xE0
#define BINN_STORAGE_MASK16    0xE000
#define BINN_STORAGE_HAS_MORE  0x10
#define BINN_TYPE_MASK         0x0F
#define BINN_TYPE_MASK16       0x0FFF

#define BINN_MAX_VALUE_MASK    0xFFFFF


/* Data Formats  ------------------------------------------ */

#define BINN_LIST      0xE0
#define BINN_MAP       0xE1
#define BINN_OBJECT    0xE2

#define BINN_NULL      0x00
#define BINN_TRUE      0x01
#define BINN_FALSE     0x02

/* (BYTE) (unsigned byte) Is the default format for the BYTE type */
#define BINN_UINT8     0x20
/* (BYTE) (signed byte, from -128 to +127. The 0x80 is the sign bit */
/*  so the range in hex is from 0x80 [-128] to 0x7F [127], being 0x00 = 0 and 0xFF = -1) */
#define BINN_INT8      0x21
#define BINN_UINT16    0x40  /* (WORD) (unsigned integer) Is the default format for the WORD type */
#define BINN_INT16     0x41  /* (WORD) (signed integer) */
#define BINN_UINT32    0x60  /* (DWORD) (unsigned integer) Is the default format for the DWORD type */
#define BINN_INT32     0x61  /* (DWORD) (signed integer) */
#define BINN_UINT64    0x80  /* (QWORD) (unsigned integer) Is the default format for the QWORD type */
#define BINN_INT64     0x81  /* (QWORD) (signed integer) */

#define BINN_SCHAR     BINN_INT8
#define BINN_UCHAR     BINN_UINT8

#define BINN_STRING    0xA0  /* (STRING) Raw String */
#define BINN_DATETIME  0xA1  /* (STRING) iso8601 format -- YYYY-MM-DD HH:MM:SS */
#define BINN_DATE      0xA2  /* (STRING) iso8601 format -- YYYY-MM-DD */
#define BINN_TIME      0xA3  /* (STRING) iso8601 format -- HH:MM:SS */
/* (STRING) High precision number - used for generic decimal values and for those */
/* ones that cannot be represented in the float64 format. */
#define BINN_DECIMAL   0xA4
/* (STRING) With currency unit/symbol - check for some iso standard format */
#define BINN_CURRENCYSTR  0xA5
#define BINN_SINGLE_STR   0xA6  /* (STRING) Can be restored to float32 */
#define BINN_DOUBLE_STR   0xA7  /* (STRING) May be restored to float64 */

#define BINN_FLOAT32   0x62  /* (DWORD) */
#define BINN_FLOAT64   0x82  /* (QWORD) */
#define BINN_FLOAT     BINN_FLOAT32
#define BINN_SINGLE    BINN_FLOAT32
#define BINN_DOUBLE    BINN_FLOAT64

#define BINN_CURRENCY  0x83  /* (QWORD) */

#define BINN_BLOB      0xC0  /* (BLOB) Raw Blob */


/* virtual types: */

#define BINN_BOOL      0x80061  /* (DWORD) The value may be 0 or 1 */


/* extended content types: */

/* strings: */

#define BINN_HTML      0xB001
#define BINN_XML       0xB002
#define BINN_JSON      0xB003
#define BINN_JAVASCRIPT 0xB004
#define BINN_CSS       0xB005

/* blobs: */

#define BINN_JPEG      0xD001
#define BINN_GIF       0xD002
#define BINN_PNG       0xD003
#define BINN_BMP       0xD004


/* type families */
#define BINN_FAMILY_NONE   0x00
#define BINN_FAMILY_NULL   0xf1
#define BINN_FAMILY_INT    0xf2
#define BINN_FAMILY_FLOAT  0xf3
#define BINN_FAMILY_STRING 0xf4
#define BINN_FAMILY_BLOB   0xf5
#define BINN_FAMILY_BOOL   0xf6
#define BINN_FAMILY_BINN   0xf7

/* integer types related to signal */
#define BINN_SIGNED_INT     11
#define BINN_UNSIGNED_INT   22


typedef void (*binn_mem_free)(void *);
#define BINN_STATIC      ((binn_mem_free)0)
#define BINN_TRANSIENT   ((binn_mem_free)-1)



/* --- WRITE FUNCTIONS  ------------- */

/* create a new binn allocating memory for the structure */
struct binn *APIENTRY binn_object(void);

/* extended interface */
BOOL   APIENTRY binn_object_set(struct binn *obj, char *key, int type, void *pvalue, int size);

/* release memory */
void   APIENTRY binn_free(struct binn *item);

/* these functions accept pointer to the binn structure and pointer to the binn buffer */
void * APIENTRY binn_ptr(void *ptr);
int    APIENTRY binn_size(void *ptr);
struct binn *APIENTRY binn_new(int type, int size, void *buffer);
void   APIENTRY binn_free(struct binn *item);
void * APIENTRY binn_release(struct binn *item);

/* single interface - these functions check the data type */
BOOL APIENTRY binn_object_get(void *obj, char *key, int type, void *pvalue, int *psize);
uint64         APIENTRY binn_object_uint64(void *obj, char *key);
unsigned int   APIENTRY binn_object_uint32(void *obj, char *key);


static inline BOOL binn_object_set_uint32(struct binn *obj, char *key,
	unsigned int value) {
	return binn_object_set(obj, key, BINN_UINT32, &value, 0);
}

static inline BOOL binn_object_set_uint64(struct binn *obj, char *key, uint64 value) {
	return binn_object_set(obj, key, BINN_UINT64, &value, 0);
}

static inline BOOL binn_object_get_uint32(void *obj, char *key, unsigned int *pvalue) {
	return binn_object_get(obj, key, BINN_UINT32, pvalue, NULL);
}

static inline BOOL binn_object_get_uint64(void *obj, char *key, uint64 *pvalue) {
	return binn_object_get(obj, key, BINN_UINT64, pvalue, NULL);
}

static inline BOOL binn_object_set_int32(struct binn *obj, char *key, int value) {
	return binn_object_set(obj, key, BINN_INT32, &value, 0);
}

static inline BOOL binn_object_set_blob(struct binn *obj, char *key, void *ptr, int size) {
	return binn_object_set(obj, key, BINN_BLOB, ptr, size);
}

static inline BOOL binn_object_get_int32(void *obj, char *key, int *pvalue) {
	return binn_object_get(obj, key, BINN_INT32, pvalue, NULL);
}

static inline BOOL binn_object_get_blob(void *obj, char *key, void **pvalue, int *psize) {
	return binn_object_get(obj, key, BINN_BLOB, pvalue, psize);
}

static inline BOOL binn_object_get_uint8(void *obj, char *key, unsigned char *pvalue) {
	return binn_object_get(obj, key, BINN_UINT8, pvalue, NULL);
}

static inline BOOL binn_object_set_uint8(struct binn *obj, char *key,
	unsigned char value) {
	return binn_object_set(obj, key, BINN_UINT8, &value, 0);
}


#ifdef __cplusplus
}
#endif

#endif /* BINN_H */
