/************************************************************************
 *  @file cndrv_pre_compile.h
 *
 *  @brief For cndrv_host pre_compile.
 **************************************************************************/

#ifndef __CNDRV_PRE_COMPILE_H
#define __CNDRV_PRE_COMPILE_H

#include <linux/version.h>
#include "functions.h"
#include "generic.h"
#include "macros.h"
#include "symbols.h"
#include "types.h"

#if defined(CN_PRECOMPILE_TIME_TO_TM)
	#define cn_time64_to_tm time_to_tm
#elif defined(CN_PRECOMPILE_TIME64_TO_TM)
	#define cn_time64_to_tm time64_to_tm
#else
	#define cn_time64_to_tm time64_to_tm
#endif

#if defined(CN_PRECOMPILE_GET_USER_PAGES_HAS_GUP_FLAGS_ARGS)
	#define cn_get_user_pages get_user_pages
#elif defined(CN_PRECOMPILE_GET_USER_PAGES_HAS_WRITE_AND_FORCE_ARGS)
	#define cn_get_user_pages(start, nr_pages, flags, pages, vmas)\
		get_user_pages(start, nr_pages, flags, 0, pages, vmas)
#elif defined(CN_PRECOMPILE_GET_USER_PAGES_HAS_TASK_STRUCT_AND_GUP_FLAGS_ARGS)
	#define cn_get_user_pages(start, nr_pages, flags, pages, vmas)\
		get_user_pages(current, current->mm, start, nr_pages, flags, pages, vmas)
#elif defined(CN_PRECOMPILE_GET_USER_PAGES_HAS_TASK_STRUCT_WRITE_AND_FORCE_ARGS)
	#define cn_get_user_pages(start, nr_pages, flags, pages, vmas)\
		get_user_pages(current, current->mm, start, nr_pages, flags, 0, pages, vmas)
#else
	#define cn_get_user_pages get_user_pages
#endif

#if defined(CN_PRECOMPILE_GET_USER_PAGES_REMOTE_PRESENT)
	#if defined(CN_PRECOMPILE_GET_USER_PAGES_REMOTE_HAS_LOCKED_AND_GUP_FLAGS_ARGS)
		#define cn_get_user_pages_remote get_user_pages_remote
	#elif defined(CN_PRECOMPILE_GET_USER_PAGES_REMOTE_HAS_GUP_FLAGS_ARGS)
		#define cn_get_user_pages_remote(tsk, mm, start, nr_pages, flags, pages, vmas, locked)\
			get_user_pages_remote(tsk, mm, start, nr_pages, flags, pages, vmas)
	#elif defined(CN_PRECOMPILE_GET_USER_PAGES_REMOTE_HAS_WRITE_AND_FORCE_ARGS)
		#define cn_get_user_pages_remote(tsk, mm, start, nr_pages, flags, pages, vmas, locked)\
			get_user_pages_remote(tsk, mm, start, nr_pages, flags, 0, pages, vmas)
	#elif defined(CN_PRECOMPILE_GET_USER_PAGES_REMOTE_NO_TASK_ARGS)
		#define cn_get_user_pages_remote(tsk, mm, start, nr_pages, flags, pages, vmas, locked)\
			get_user_pages_remote(mm, start, nr_pages, flags, pages, vmas, locked)
	#else
		#define cn_get_user_pages_remote get_user_pages_remote
	#endif
#else
	#if defined(CN_PRECOMPILE_GET_USER_PAGES_HAS_TASK_STRUCT_AND_GUP_FLAGS_ARGS)
		#define cn_get_user_pages_remote(tsk, mm, start, nr_pages, flags, pages, vmas, locked)\
			get_user_pages(tsk, mm, start, nr_pages, flags, pages, vmas)
	#elif defined(CN_PRECOMPILE_GET_USER_PAGES_HAS_TASK_STRUCT_WRITE_AND_FORCE_ARGS)
		#define cn_get_user_pages_remote(tsk, mm, start, nr_pages, flags, pages, vmas, locked)\
			get_user_pages(tsk, mm, start, nr_pages, flags, 0, pages, vmas)
	#endif
#endif

#if defined(CN_PRECOMPILE_ACCESS_OK_HAS_TYPE)
	#define cn_access_ok(type, addr, size) access_ok(type, addr, size)
#elif defined(CN_PRECOMPILE_ACCESS_OK_NO_TYPE)
	#define cn_access_ok(type, addr, size) access_ok(addr, size)
#endif

#if defined(CN_PRECOMPILE_VM_MAP_RAM_HAS_PROT)
	#define cn_vm_map_ram vm_map_ram
#elif defined(CN_PRECOMPILE_VM_MAP_RAM_NO_PROT)
	#define cn_vm_map_ram(pages, page_cnt, node, prot) \
		vm_map_ram(pages, page_cnt, node)
#endif

#if defined(CN_PRECOMPILE_MMAP_READ_LOCK_MMAP_LOCK)
	#define cn_mmap_read_lock mmap_read_lock
	#define cn_mmap_read_unlock mmap_read_unlock
#elif defined(CN_PRECOMPILE_MMAP_READ_LOCK_MMAP_SEM)
	#define cn_mmap_read_lock(mm) down_read(&mm->mmap_sem)
	#define cn_mmap_read_unlock(mm) up_read(&mm->mmap_sem)
#endif

#if defined(CN_PRECOMPILE_MMAP_WRITE_LOCK_MMAP_LOCK)
	#define cn_mmap_write_lock mmap_write_lock
	#define cn_mmap_write_unlock mmap_write_unlock
#elif defined(CN_PRECOMPILE_MMAP_WRITE_LOCK_MMAP_SEM)
	#define cn_mmap_write_lock(mm) down_write(&mm->mmap_sem)
	#define cn_mmap_write_unlock(mm) up_write(&mm->mmap_sem)
#endif

#if defined(CN_PRECOMPILE_MAP_VM_AREA_OLD)
	#define cn_map_vm_area(area, prot, pages) map_vm_area(area, prot, &pages)
#elif defined(CN_PRECOMPILE_MAP_VM_AREA_PAGES)
	#define cn_map_vm_area map_vm_area
#endif

#if defined(CN_PRECOMPILE_FCHECK)
	#define cn_fcheck fcheck
#elif defined(CN_PRECOMPILE_FCHECK_LOOKUP_FD_RCU)
	#define cn_fcheck lookup_fd_rcu
#endif

#if defined(CN_PRECOMPILE_PCI_CLEANUP_AER_UNCORRECT_ERROR_STATUS)
	#define cn_pci_cleanup_aer_uncorrect_error_status pci_cleanup_aer_uncorrect_error_status
#elif defined(CN_PRECOMPILE_PCI_AER_CLEAR_NONFATAL_STATUS)
	#define cn_pci_cleanup_aer_uncorrect_error_status pci_aer_clear_nonfatal_status
#endif

#if defined(CN_PRECOMPILE_CPUMASK_CLEAR_CPU_CPUS_MASK)
	#define CN_CLEAR_CPUMASK(a) cpumask_clear_cpu(a, &current->cpus_mask)
#elif defined(CN_PRECOMPILE_CPUMASK_CLEAR_CPU_CPUS_ALLOWED)
	#define CN_CLEAR_CPUMASK(a) cpumask_clear_cpu(a, &current->cpus_allowed)
#endif

#if defined(CN_PRECOMPILE_TOPOLOGY_SIBLING_CPUMASK)
	#define cn_topology_sibling_cpumask(cpu) topology_sibling_cpumask(cpu)
#elif defined(CN_PRECOMPILE_TOPOLOGY_THREAD_CPUMASK)
	#define cn_topology_sibling_cpumask(cpu) topology_thread_cpumask(cpu)
#endif

#if defined(CN_PRECOMPILE_KERNEL_READ)
	#define cn_fs_write(file, buf, count, pos) kernel_write(file, buf, count, pos)
	#define cn_fs_read(file, buf, count, pos) kernel_read(file, buf, count, pos)
#else
	#define cn_fs_write(file, buf, count, pos) vfs_write(file, buf, count, pos)
	#define cn_fs_read(file, buf, count, pos) vfs_read(file, buf, count, pos)
#endif

#endif
