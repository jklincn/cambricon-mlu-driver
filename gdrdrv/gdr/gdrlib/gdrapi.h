#ifndef __GDRAPI_H__
#define __GDRAPI_H__

#include <stdint.h> // for standard [u]intX_t types
#include <stddef.h>
#include <sys/queue.h>

#define MAJOR_VERSION_SHIFT     16
#define MINOR_VERSION_MASK      (((uint32_t)1 << MAJOR_VERSION_SHIFT) - 1)

#define GDR_API_MAJOR_VERSION    2
#define GDR_API_MINOR_VERSION    3
#define GDR_API_VERSION          ((GDR_API_MAJOR_VERSION << MAJOR_VERSION_SHIFT) | GDR_API_MINOR_VERSION)

#define MINIMUM_GDRDRV_MAJOR_VERSION    2
#define MINIMUM_GDRDRV_MINOR_VERSION    0
#define MINIMUM_GDRDRV_VERSION          ((MINIMUM_GDRDRV_MAJOR_VERSION << MAJOR_VERSION_SHIFT) | \
					MINIMUM_GDRDRV_MINOR_VERSION)


#define GPU_PAGE_SHIFT   14
#define GPU_PAGE_SIZE    (1UL << GPU_PAGE_SHIFT)
#define GPU_PAGE_OFFSET  (GPU_PAGE_SIZE-1)
#define GPU_PAGE_MASK    (~GPU_PAGE_OFFSET)
#ifndef unlikely
#ifdef __GNUC__
#define unlikely(x)         __builtin_expect(!!(x), 0)
#else
#define unlikely(x)         (x)
#endif
#endif

#ifndef READ_ONCE
#define READ_ONCE(x)      (*(volatile typeof(x) *)&x)
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v)    (READ_ONCE(x) = (v))
#endif


struct gdr_memh_t {
	uint32_t handle;

	LIST_ENTRY(gdr_memh_t) entries;
	unsigned mapped:1;
	unsigned wc_mapping:1;
};

struct gdr {
	int fd;
	LIST_HEAD(memh_list, gdr_memh_t) memhs;
	size_t page_size;
	size_t page_mask;
	uint8_t page_shift;
};

// Initialize the library, e.g. by opening a connection to the kernel-mode
// driver. Returns an handle to the library state object.
struct gdr *gdr_open(void);

// Destroy library state object, e.g. it closes the connection to kernel-mode
// driver.
int gdr_close(struct gdr *g);

// The handle to a user-space GPU memory mapping
struct gdr_mh_s {
	unsigned long h;
};

// Create a peer-to-peer mapping of the device memory buffer, returning an opaque handle.
// Note that at this point the mapping is still not accessible to user-space.
int gdr_pin_buffer(struct gdr *g, unsigned long addr, size_t size, uint64_t p2p_token, uint32_t va_space,
		struct gdr_mh_s *handle);

// Destroys the peer-to-peer mapping and frees the handle.
//
// If there exists a corresponding user-space mapping, gdr_unmap should be
// called before this one.
int gdr_unpin_buffer(struct gdr *g, struct gdr_mh_s handle);

// flag is set when the kernel callback (relative to the
// gdr_unpin_buffer.
int gdr_get_callback_flag(struct gdr *g, struct gdr_mh_s handle, int *flag);

// After pinning, info struct contains details of the mapped area.
//
// Note that both info->va and info->mapped_size might be different from
// the original address passed to gdr_pin_buffer due to aligning happening
// in the kernel-mode driver
struct gdr_info {
	uint64_t va;
	uint64_t mapped_size;
	uint32_t page_size;
	// tm_cycles and cycles_per_ms are deprecated and will be removed in future.
	uint64_t tm_cycles;
	uint32_t cycles_per_ms;
	unsigned mapped:1;
	unsigned wc_mapping:1;
};
int gdr_get_info(struct gdr *g, struct gdr_mh_s handle, struct gdr_info *info);

// Create a user-space mapping of the memory handle.
//
// WARNING: the address could be potentially aligned to the boundary of the page size
// before being mapped in user-space, so the pointer returned might be
// affected by an offset. gdr_get_info can be used to calculate that
// offset.
int gdr_map(struct gdr *g, struct gdr_mh_s handle, void **va, size_t size);

// get rid of a user-space mapping.
// First invoke gdr_unmap() then gdr_unpin_buffer().
int gdr_unmap(struct gdr *g, struct gdr_mh_s handle, void *va, size_t size);

// map_d_ptr is the user-space virtual address belonging to a mapping of a device memory buffer,
// i.e. one returned by gdr_map()
//
// WARNING: Both integrity and ordering of data as observed by pre-launched GPU
// work is not guaranteed by this API. For more information, see
int gdr_copy_to_mapping(struct gdr_mh_s handle, void *map_d_ptr, const void *h_ptr, size_t size);

int gdr_copy_from_mapping(struct gdr_mh_s handle, void *h_ptr, const void *map_d_ptr, size_t size);

// Query the version of libgdrapi
void gdr_runtime_get_version(int *major, int *minor);

// Query the version of gdrdrv driver
int gdr_driver_get_version(struct gdr *g, int *major, int *minor);
#endif // __GDRAPI_H__
