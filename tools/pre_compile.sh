#!/bin/sh

SCRIPTDIR=`dirname $0`
mkdir -p $SCRIPTDIR/../pre_compile
cd $SCRIPTDIR/../pre_compile

build_cflags() {
	if [ "$CONFIG_CNDRV_PCIE_PLATFORM" = "y" ]; then
		BASE_CFLAGS="-O2 -D__KERNEL__ \
			-nostdinc -isystem $ISYSTEM"

		if [ "$OUTPUT" != "$SOURCES" ]; then
			OUTPUT_CFLAGS="-I$OUTPUT/include2 -I$OUTPUT/include"
			if [ -f "$OUTPUT/include/generated/autoconf.h" ]; then
				AUTOCONF_FILE="$OUTPUT/include/generated/autoconf.h"
			else
				AUTOCONF_FILE="$OUTPUT/include/linux/autoconf.h"
			fi
		else
			if [ -f "$HEADERS/generated/autoconf.h" ]; then
				AUTOCONF_FILE="$HEADERS/generated/autoconf.h"
			else
				AUTOCONF_FILE="$HEADERS/linux/autoconf.h"
			fi
		fi

		if [ -f "$HEADERS/generated/kconfig.h" ]; then
			KCONFIG_FILE="$HEADERS/generated/kconfig.h"
		else
			KCONFIG_FILE="$HEADERS/linux/kconfig.h"
		fi

		SOURCE_HEADERS="$HEADERS"
		SOURCE_ARCH_HEADERS="$SOURCES/arch/$KERNEL_ARCH/include"
		OUTPUT_HEADERS="$OUTPUT/include"
		OUTPUT_ARCH_HEADERS="$OUTPUT/arch/$KERNEL_ARCH/include"

		# Add the mach-default includes (only found on x86/older kernels)
		MACH_CFLAGS="$MACH_CFLAGS -I$SOURCE_HEADERS/asm-$KERNEL_ARCH/mach-default"
		MACH_CFLAGS="$MACH_CFLAGS -I$SOURCE_ARCH_HEADERS/asm/mach-default"

		CFLAGS="$BASE_CFLAGS $MACH_CFLAGS $OUTPUT_CFLAGS -include $AUTOCONF_FILE"
		CFLAGS="$CFLAGS -include $KCONFIG_FILE"
		CFLAGS="$CFLAGS -I$SOURCE_HEADERS"
		CFLAGS="$CFLAGS -I$SOURCE_HEADERS/uapi"
		CFLAGS="$CFLAGS -I$SOURCE_HEADERS/xen"
		CFLAGS="$CFLAGS -I$OUTPUT_HEADERS/generated/uapi"
		CFLAGS="$CFLAGS -I$SOURCE_ARCH_HEADERS"
		CFLAGS="$CFLAGS -I$SOURCE_ARCH_HEADERS/uapi"
		CFLAGS="$CFLAGS -I$OUTPUT_ARCH_HEADERS/generated"
		CFLAGS="$CFLAGS -I$OUTPUT_ARCH_HEADERS/generated/uapi"
		CFLAGS="$CFLAGS -Werror"
	else
		BASE_CFLAGS="-O2 -D__KERNEL__ \
			-nostdinc -isystem $ISYSTEM"
		CFLAGS="$BASE_CFLAGS"
		CFLAGS="$CFLAGS -include $OUTPUT/include/generated/autoconf.h"
		CFLAGS="$CFLAGS -include $SOURCES/include/linux/kconfig.h"
		CFLAGS="$CFLAGS -I $SOURCES/include"
		CFLAGS="$CFLAGS -I $SOURCES/include/uapi"
		CFLAGS="$CFLAGS -I $SOURCES/include/xen"
		CFLAGS="$CFLAGS -I $OUTPUT/include"
		CFLAGS="$CFLAGS -I $OUTPUT/include/generated/uapi"
		CFLAGS="$CFLAGS -I $SOURCES/arch/arm64/include"
		CFLAGS="$CFLAGS -I $SOURCES/arch/arm64/include/uapi"
		CFLAGS="$CFLAGS -I $OUTPUT/arch/arm64/include/generated"
		CFLAGS="$CFLAGS -I $OUTPUT/arch/arm64/include/generated/uapi"
		CFLAGS="$CFLAGS -Werror"
	fi
	#if [ -n "$BUILD_PARAMS" ]; then
	#    CFLAGS="$CFLAGS -D$BUILD_PARAMS"
	#fi
}

check_for_ib_peer_memory_symbols() {
    kernel_dir="$1"
    module_symvers="${kernel_dir}/Module.symvers"

    sym_ib_register="ib_register_peer_memory_client"
    sym_ib_unregister="ib_unregister_peer_memory_client"
    tab='	'

    # Return 0 for true(no errors), 1 for false
    if [ ! -f "${module_symvers}" ]; then
        return 1
    fi

    if grep -e "${tab}${sym_ib_register}${tab}.*${tab}EXPORT_SYMBOL.*\$"    \
               "${module_symvers}" > /dev/null 2>&1 &&
       grep -e "${tab}${sym_ib_unregister}${tab}.*${tab}EXPORT_SYMBOL.*\$"  \
               "${module_symvers}" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

append_comptest() {
	#
	# Echo data from stdin: this is a transitional function to make it easier
	# to port comptests from drivers with parallel comptest generation to
	# older driver versions
	#

	while read LINE; do
		echo ${LINE}
	done
}

COMPTEST_PREAMBLE="
#include <linux/kconfig.h>
#include <generated/autoconf.h>
#if defined(CONFIG_KASAN) && defined(CONFIG_ARM64)
#if defined(CONFIG_KASAN_SW_TAGS)
#define KASAN_SHADOW_SCALE_SHIFT 4
#else
#define KASAN_SHADOW_SCALE_SHIFT 3
#endif
#endif
"

check_comptest() {
	#
	# Compile the current comptest C file and check+output the result
	#
	CODE="$1"
	DEF="$2"
	CAT="$3"

	echo "$COMPTEST_PREAMBLE
	$CODE" > comptest$$.c

	$CC $CFLAGS -c comptest$$.c > /dev/null 2>&1
	rm -f comptest$$.c

	if [ -f comptest$$.o ]; then
		echo "#define ${DEF}" | append_comptest "${CAT}"
		rm -f comptest$$.o
		return
	fi
}

check_cpu_model() {
	MODEL="$1"
	DEF="$2"
	CAT="$3"

	num=$(lscpu | grep $MODEL | wc -l)
	if [ ${num} != 0 ]; then
		echo "#define ${DEF}" | append_comptest "${CAT}"
		return
	fi
}

generate_makefile() {
FILE_NAME="$1"
echo "
obj-m := $FILE_NAME.o
all:
	make -C ${OUTPUT} M=\`pwd\` src=\`pwd\` modules
clean:
	make -C ${OUTPUT} M=\`pwd\` src=\`pwd\` clean
" > Makefile
}

compile_test() {
    case "$1" in
	get_user_pages)
		#
		# Conftest for get_user_pages()
		#
		# Use long type for get_user_pages and unsigned long for nr_pages
		# 2013 Feb 22: 28a35716d317980ae9bc2ff2f84c33a3cda9e884
		#
		# Removed struct task_struct *tsk & struct mm_struct *mm from get_user_pages.
		# 2016 Feb 12: cde70140fed8429acf7a14e2e2cbd3e329036653
		#
		# Replaced get_user_pages6 with get_user_pages.
		# 2016 April 4: c12d2da56d0e07d230968ee2305aaa86b93a6832
		#
		# Replaced write and force parameters with gup_flags.
		# 2016 Oct 12: 768ae309a96103ed02eb1e111e838c87854d8b51
		#
		# Comptest #1: Check if get_user_pages has gup_flags instead of write and force parameters.
		# Return if true.

		CODE="
		#include <linux/mm.h>
		long get_user_pages(unsigned long start,
				unsigned long nr_pages,
				unsigned int gup_flags,
				struct page **pages,
				struct vm_area_struct **vmas) {
			return 0;
		}"

		check_comptest "$CODE" "CN_PRECOMPILE_GET_USER_PAGES_HAS_GUP_FLAGS_ARGS" "functions"

		# Comptest #2: Check if get_user_pages has write and force parameters.
		# Return if available.

		CODE="
		#include <linux/mm.h>
		long get_user_pages(unsigned long start,
				unsigned long nr_pages,
				int write,
				int force,
				struct page **pages,
				struct vm_area_struct **vmas) {
			return 0;
		}"

		check_comptest "$CODE" "CN_PRECOMPILE_GET_USER_PAGES_HAS_WRITE_AND_FORCE_ARGS" "functions"

		# Comptest #3: Check if get_user_pages has task_struct and mm_struck,
		# and has gup_flags instead of write and force parameters.
		# Return if available.

		CODE="
		#include <linux/mm.h>
		long get_user_pages(struct task_struct *tsk,
				struct mm_struct *mm,
				unsigned long start,
				unsigned long nr_pages,
				unsigned int gup_flags,
				struct page **pages,
				struct vm_area_struct **vmas) {
			return 0;
		}"

		check_comptest "$CODE" \
			"CN_PRECOMPILE_GET_USER_PAGES_HAS_TASK_STRUCT_AND_GUP_FLAGS_ARGS" "functions"

		# Comptest #4: Check if get_user_pages has task_struct and mm_struck,
		# and has write and force parameters.
		# Return if available.

		CODE="
		#include <linux/mm.h>
		long get_user_pages(struct task_struct *tsk,
				struct mm_struct *mm,
				unsigned long start,
				unsigned long nr_pages,
				int write,
				int force,
				struct page **pages,
				struct vm_area_struct **vmas) {
			return 0;
		}"

		check_comptest "$CODE" \
			"CN_PRECOMPILE_GET_USER_PAGES_HAS_TASK_STRUCT_WRITE_AND_FORCE_ARGS" "functions"

		return
	;;

	get_user_pages_remote)
		#
		# Determine if the function get_user_pages_remote() is
		# present and has write/force parameters.
		#
		# get_user_pages_remote() was added by:
		#   2016 Feb 12: 1e9877902dc7e11d2be038371c6fbf2dfcd469d7
		#
		# get_user_pages[_remote]() write/force parameters
		# replaced with gup_flags:
		#   2016 Oct 12: 768ae309a96103ed02eb1e111e838c87854d8b51
		#   2016 Oct 12: 9beae1ea89305a9667ceaab6d0bf46a045ad71e7
		#
		# get_user_pages_remote() added 'locked' parameter
		#   2016 Dec 14:5b56d49fc31dbb0487e14ead790fc81ca9fb2c99
		#
		# comptest #1: check if get_user_pages_remote() is available
		# return if not available.

		echo "$COMPTEST_PREAMBLE
		#include <linux/mm.h>
		extern long get_user_pages_remote();
		void comptest_get_user_pages_remote(void) {
			get_user_pages_remote();
		}" > comptest$$.c

		$CC $CFLAGS -c comptest$$.c > /dev/null 2>&1
		rm -f comptest$$.c

		if [ -f comptest$$.o ]; then
			echo "#undef CN_PRECOMPILE_GET_USER_PAGES_REMOTE_PRESENT" | append_comptest "functions"
			rm -f comptest$$.o
			return
		fi

		# comptest #2: check if get_user_pages_remote() has locked argument
		# Return if available.
		echo "$COMPTEST_PREAMBLE
		#include <linux/mm.h>
				long get_user_pages_remote(struct task_struct *tsk,
				struct mm_struct *mm,
				unsigned long start,
				unsigned long nr_pages,
				unsigned int gup_flags,
				struct page **pages,
				struct vm_area_struct **vmas,
				int *locked) {
			return 0;
		}" > comptest$$.c

		$CC $CFLAGS -c comptest$$.c > /dev/null 2>&1
		rm -f comptest$$.c

		if [ -f comptest$$.o ]; then
			echo "#define CN_PRECOMPILE_GET_USER_PAGES_REMOTE_PRESENT" | append_comptest "functions"
			echo "#define CN_PRECOMPILE_GET_USER_PAGES_REMOTE_HAS_LOCKED_AND_GUP_FLAGS_ARGS" \
				| append_comptest "functions"
			rm -f comptest$$.o
			return
		fi

		# comptest #3: check if get_user_pages_remote() has has gup_flags
		# instead of write and force parameters.
		# Return if available.
		echo "$COMPTEST_PREAMBLE
		#include <linux/mm.h>
		long get_user_pages_remote(struct task_struct *tsk,
				struct mm_struct *mm,
				unsigned long start,
				unsigned long nr_pages,
				unsigned int gup_flags,
				struct page **pages,
				struct vm_area_struct **vmas) {
			return 0;
		}" > comptest$$.c

		$CC $CFLAGS -c comptest$$.c > /dev/null 2>&1
		rm -f comptest$$.c

		if [ -f comptest$$.o ]; then
			echo "#define CN_PRECOMPILE_GET_USER_PAGES_REMOTE_PRESENT" | append_comptest "functions"
			echo "#define CN_PRECOMPILE_GET_USER_PAGES_REMOTE_HAS_GUP_FLAGS_ARGS" \
				| append_comptest "functions"
			rm -f comptest$$.o
			return
		fi

		# comptest #4: check if get_user_pages_remote() has write and
		# force arguments.
		# Return if available.
		echo "$COMPTEST_PREAMBLE
		#include <linux/mm.h>
		long get_user_pages_remote(struct task_struct *tsk,
				struct mm_struct *mm,
				unsigned long start,
				unsigned long nr_pages,
				int write,
				int force,
				struct page **pages,
				struct vm_area_struct **vmas) {
			return 0;
		}" > comptest$$.c

		$CC $CFLAGS -c comptest$$.c > /dev/null 2>&1
		rm -f comptest$$.c

		if [ -f comptest$$.o ]; then
			echo "#define CN_PRECOMPILE_GET_USER_PAGES_REMOTE_PRESENT" | append_comptest "functions"
			echo "#define CN_PRECOMPILE_GET_USER_PAGES_REMOTE_HAS_WRITE_AND_FORCE_ARGS" \
				| append_comptest "functions"
			rm -f comptest$$.o
			return
		fi

		# comptest #5: check if get_user_pages_remote() has task
		# Return if available.
		echo "$COMPTEST_PREAMBLE
		#include <linux/kconfig.h>
		#include <linux/mm.h>
		long get_user_pages_remote(struct mm_struct *mm,
				unsigned long start,
				unsigned long nr_pages,
				unsigned int gup_flags,
				struct page **pages,
				struct vm_area_struct **vmas,
				int *locked) {
			return 0;
		}" > comptest$$.c

		$CC $CFLAGS -c comptest$$.c > /dev/null 2>&1
		rm -f comptest$$.c

		if [ -f comptest$$.o ]; then
			echo "#define CN_PRECOMPILE_GET_USER_PAGES_REMOTE_PRESENT" | append_comptest "functions"
			echo "#define CN_PRECOMPILE_GET_USER_PAGES_REMOTE_NO_TASK_ARGS" \
				| append_comptest "functions"
			rm -f comptest$$.o
			return
		fi

		#default
		echo "#define CN_PRECOMPILE_GET_USER_PAGES_REMOTE_PRESENT" | append_comptest "functions"
		echo "#define CN_PRECOMPILE_GET_USER_PAGES_REMOTE_HAS_LOCKED_AND_GUP_FLAGS_ARGS" \
			| append_comptest "functions"

		return
	;;

	access_ok)
		# macros: access_ok
		# comptest #1: check if access_ok() has type
		# return if available.

		CODE="
		#include <linux/uaccess.h>
		void comptest_access_ok(void) {
			access_ok(VERIFY_WRITE, NULL, 0);
		}"

		check_comptest "$CODE" "CN_PRECOMPILE_ACCESS_OK_HAS_TYPE" "macros"

		# comptest #2: check if access_ok() does not have type
		# Return if available.
		CODE="
		#include <linux/uaccess.h>
		void comptest_access_ok(void) {
			access_ok(NULL, 0);
		}"

		check_comptest "$CODE" "CN_PRECOMPILE_ACCESS_OK_NO_TYPE" "macros"

		return
	;;

	vm_map_ram)
		# function: vm_map_ram
		# comptest #1: check if vm_map_ram() has prot
		# return if available.
		if [ "$ARCH" = "i386" -o "$ARCH" = "x86_64" ]; then
		CODE="
		#include <linux/vmalloc.h>
		#if defined(__x86_64__)
		#include <asm/pgtable_types.h>
		#endif
		void *comptest_vm_map_ram(struct page **pages,
				unsigned int count,
				int node,
				pgprot_t prot) {
			vm_map_ram(pages, count, node, prot);
			return NULL;
		}"
		else
		CODE="
		#include <linux/vmalloc.h>
		void *comptest_vm_map_ram(struct page **pages,
				unsigned int count,
				int node,
				pgprot_t prot) {
			vm_map_ram(pages, count, node, prot);
			return NULL;
		}"
		fi

		check_comptest "$CODE" "CN_PRECOMPILE_VM_MAP_RAM_HAS_PROT" "functions"

		# comptest #2: check if vm_map_ram() does not have prot
		# Return if available.
		if [ "$ARCH" = "i386" -o "$ARCH" = "x86_64" ]; then
		CODE="
		#include <linux/vmalloc.h>
		#if defined(__x86_64__)
		#include <asm/pgtable_types.h>
		#endif
		void *comptest_vm_map_ram(struct page **pages,
				unsigned int count,
				int node) {
			vm_map_ram(pages, count, node);
			return NULL;
		}"
		else
		CODE="
		#include <linux/vmalloc.h>
		void *comptest_vm_map_ram(struct page **pages,
				unsigned int count,
				int node) {
			vm_map_ram(pages, count, node);
			return NULL;
		}"
		fi

		check_comptest "$CODE" "CN_PRECOMPILE_VM_MAP_RAM_NO_PROT" "functions"

		return
	;;

	mmap_read_lock)
		# function: mmap_read_lock
		# comptest #1: check if mmap_read_lock() mmap_lock
		# return if available.
		echo "$COMPTEST_PREAMBLE
		#include <linux/mm_types.h>
		#include <linux/mmap_lock.h>
		void *comptest_mmap_read_lock(struct mm_struct *mm) {
			mmap_read_lock(mm);
		}" > comptest$$.c

		$CC $CFLAGS -c comptest$$.c > /dev/null 2>&1
		rm -f comptest$$.c
		if [ -f comptest$$.o ]; then
			echo "#define CN_PRECOMPILE_MMAP_READ_LOCK_MMAP_LOCK" | append_comptest "functions"
			rm -f comptest$$.o
			return
		fi

		# comptest #2 / default: check if mmap_read_lock() mmap_sem
		echo "#define CN_PRECOMPILE_MMAP_READ_LOCK_MMAP_SEM" | append_comptest "functions"

		return
	;;

	mmap_write_lock)
		# function: mmap_read_lock
		# comptest #1: check if mmap_read_lock() mmap_lock
		# return if available.
		echo "$COMPTEST_PREAMBLE
		#include <linux/mm_types.h>
		#include <linux/mmap_lock.h>
		void *comptest_mmap_write_lock(struct mm_struct *mm) {
			mmap_write_lock(mm);
		}" > comptest$$.c

		$CC $CFLAGS -c comptest$$.c > /dev/null 2>&1
		rm -f comptest$$.c
		if [ -f comptest$$.o ]; then
			echo "#define CN_PRECOMPILE_MMAP_WRITE_LOCK_MMAP_LOCK" | append_comptest "functions"
			rm -f comptest$$.o
			return
		fi

		# comptest #2 / default: check if mmap_read_lock() mmap_sem
		echo "#define CN_PRECOMPILE_MMAP_WRITE_LOCK_MMAP_SEM" | append_comptest "functions"

		return
	;;

	map_vm_area)
		# function: map_vm_area
		# comptest #1: check if map_vm_area() pages
		# return if available.
		if [ "$ARCH" = "i386" -o "$ARCH" = "x86_64" ]; then
		CODE="
		#if defined(__x86_64__)
		#include <asm/pgtable_types.h>
		#endif
		#include <linux/mm.h>
		void *comptest_map_vm_area(struct vm_struct *area,
				pgprot_t prot,
				struct page ***pages) {
			map_vm_area(area, prot, pages);
			return NULL;
		}"
		else
		CODE="
		#include <linux/mm.h>
		void *comptest_map_vm_area(struct vm_struct *area,
				pgprot_t prot,
				struct page ***pages) {
			map_vm_area(area, prot, pages);
			return NULL;
		}"
		fi

		check_comptest "$CODE" "CN_PRECOMPILE_MAP_VM_AREA_OLD" "functions"

		# comptest #2: check if map_vm_area() &pages
		# Return if available.
		if [ "$ARCH" = "i386" -o "$ARCH" = "x86_64" ]; then
		CODE="
		#if defined(__x86_64__)
		#include <asm/pgtable_types.h>
		#endif
		#include <linux/mm.h>
		#include <linux/vmalloc.h>
		void *comptest_map_vm_area(struct vm_struct *area,
				pgprot_t prot,
				struct page **pages) {
			map_vm_area(area, prot, pages);
			return NULL;
		}"
		else
		CODE="
		#include <linux/mm.h>
		#include <linux/vmalloc.h>
		void *comptest_map_vm_area(struct vm_struct *area,
				pgprot_t prot,
				struct page **pages) {
			map_vm_area(area, prot, pages);
			return NULL;
		}"
		fi

		check_comptest "$CODE" "CN_PRECOMPILE_MAP_VM_AREA_PAGES" "functions"

		return
	;;

	fcheck)
		# function: mmap_read_lock
		# comptest #1: check if mmap_read_lock() mmap_lock
		# return if available.
		echo "$COMPTEST_PREAMBLE
		#include <linux/sched.h>
		#include <linux/fdtable.h>
		void *comptest_fcheck(unsigned int fd) {
			return lookup_fd_rcu(fd);
		}" > comptest$$.c

		$CC $CFLAGS -c comptest$$.c > /dev/null 2>&1
		rm -f comptest$$.c
		if [ -f comptest$$.o ]; then
			echo "#define CN_PRECOMPILE_FCHECK_LOOKUP_FD_RCU" | append_comptest "functions"
			rm -f comptest$$.o
			return
		fi

		# comptest #2 default: fcheck
		echo "#define CN_PRECOMPILE_FCHECK" | append_comptest "functions"

		return
	;;

	llist_reverse_order)
		# function: llist_reverse_order
		# return if available.
		CODE="
		#include <linux/llist.h>
		void comptest_llist_reverse_order(struct llist_node *first) {
			first = llist_reverse_order(first);
		}"

		check_comptest "$CODE" "CN_PRECOMPILE_LLIST_REVERSE_ORDER" "functions"

		return
	;;

	pci_cleanup_aer_uncorrect_error_status)
		# function: pci_cleanup_aer_uncorrect_error_status
		# return if available.
		CODE="
		#include <linux/types.h>
		#include <linux/pci.h>
		#include <linux/aer.h>
		void comptest_pci_cleanup_aer_uncorrect_error_status(struct pci_dev *dev) {
			pci_cleanup_aer_uncorrect_error_status(dev);
		}"
		check_comptest "$CODE" "CN_PRECOMPILE_PCI_CLEANUP_AER_UNCORRECT_ERROR_STATUS" "functions"

		# function: pci_aer_clear_nonfatal_status
		# return if available.
		CODE="
		#include <linux/types.h>
		#include <linux/pci.h>
		#include <linux/aer.h>
		void comptest_pci_aer_clear_nonfatal_status(struct pci_dev *dev) {
			pci_aer_clear_nonfatal_status(dev);
		}"
		check_comptest "$CODE" "CN_PRECOMPILE_PCI_AER_CLEAR_NONFATAL_STATUS" "functions"

		return
	;;

	cpumask_clear_cpu)
		# function: cpumask_clear_cpu cpus_mask
		# return if available.
		CODE="
		#include <linux/sched.h>
		#include <linux/cpumask.h>
		void comptest_cpumask_clear_cpu(int cpu, struct task_struct *tsk) {
			cpumask_clear_cpu(cpu, &tsk->cpus_mask);
		}"
		check_comptest "$CODE" "CN_PRECOMPILE_CPUMASK_CLEAR_CPU_CPUS_MASK" "functions"

		# function: cpumask_clear_cpu cpus_allowed
		# return if available.
		CODE="
		#include <linux/sched.h>
		#include <linux/cpumask.h>
		void comptest_cpumask_clear_cpu(int cpu, struct task_struct *tsk) {
			cpumask_clear_cpu(cpu, &tsk->cpus_allowed);
		}"
		check_comptest "$CODE" "CN_PRECOMPILE_CPUMASK_CLEAR_CPU_CPUS_ALLOWED" "functions"

		return
	;;

	topology_sibling_cpumask)
		# function: topology_sibling_cpumask
		# return if available.
		CODE="
		#include <linux/topology.h>
		#include <linux/cpumask.h>
		void comptest_topology_sibling_cpumask(int cpu) {
			int ht;
			struct cpumask mask;

			ht = cpumask_weight(topology_sibling_cpumask(cpumask_first(&mask)));
		}"
		check_comptest "$CODE" "CN_PRECOMPILE_TOPOLOGY_SIBLING_CPUMASK" "macros"

		# function: topology_thread_cpumask
		# return if available.
		CODE="
		#include <linux/topology.h>
		#include <linux/cpumask.h>
		void comptest_topology_sibling_cpumask(int cpu) {
			int ht;
			struct cpumask mask;

			ht = cpumask_weight(topology_thread_cpumask(cpumask_first(&mask)));
		}"
		check_comptest "$CODE" "CN_PRECOMPILE_TOPOLOGY_THREAD_CPUMASK" "macros"

		return
	;;

	time64_to_tm)
		# function: time64_to_tm
		# return if available.
		CODE="
		#include <linux/time.h>
		void comptest_time64_to_tm(u64 secs, int offset, struct tm *result) {
			time_to_tm(secs, offset, result);
		}"
		check_comptest "$CODE" "CN_PRECOMPILE_TIME_TO_TM" "macros"

		# function: time64_to_tm
		# return if available.
		CODE="
		#include <linux/time.h>
		void comptest_time64_to_tm(u64 secs, int offset, struct tm *result) {
			time64_to_tm(secs, offset, result);
		}"
		check_comptest "$CODE" "CN_PRECOMPILE_TIME64_TO_TM" "macros"

		return
	;;

	kernel_read)
		# function: kernel_read
		# return if available.
		CODE="
		#include <linux/fs.h>
		void comptest_kernel_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
			kernel_read(file, buf, count, pos);
		}"
		check_comptest "$CODE" "CN_PRECOMPILE_KERNEL_READ" "macros"

		return
	;;

	ioremap_wc)
		check_cpu_model "Phytium" "CN_PRECOMPILE_IOREMAP_WC_DISABLE" "functions"

		return
	;;

	ib_peer_memory_symbols)
        #
        # Determine if the following symbols exist in Module.symvers:
        # 1. ib_register_peer_memory_client
        # 2. ib_unregister_peer_memory_client
        # The conftest first checks in the kernel's own Module.symvers in
        # the regular path. If the symbols are not found there, it's possible
        # that MOFED is installed and check for these symbols in MOFED's
        # Module.symvers whose path is different from the kernel's symvers.
        #
        # Note: KERNELRELEASE and ARCH are defined by Kbuild and automatically
        # passed down to conftest.sh as env vars.

		MLNX_OFED_KERNEL_DIR=/usr/src/ofa_kernel
		VAR_DKMS_SOURCES_DIR=$(test -d /var/lib/dkms/mlnx-ofed-kernel &&
                               ls -d /var/lib/dkms/mlnx-ofed-kernel/*/build 2>/dev/null)

		if check_for_ib_peer_memory_symbols "$OUTPUT" || \
		   check_for_ib_peer_memory_symbols "$MLNX_OFED_KERNEL_DIR/$ARCH/$KERNELRELEASE" || \
		   check_for_ib_peer_memory_symbols "$MLNX_OFED_KERNEL_DIR/$KERNELRELEASE" || \
		   check_for_ib_peer_memory_symbols "$MLNX_OFED_KERNEL_DIR/default" || \
		   check_for_ib_peer_memory_symbols "$VAR_DKMS_SOURCES_DIR"; then
		    echo "#define MLU_MLNX_IB_PEER_MEM_SYMBOLS_PRESENT" | append_comptest "symbols"
		else
		    echo "#undef MLU_MLNX_IB_PEER_MEM_SYMBOLS_PRESENT" | append_comptest "symbols"
		fi

		return
	;;

	uart_handle_sysrq_char)
		# function: uart_handle_sysrq_char
		# return if available.
		mkdir -p uart_handle_sysrq_char_dir
		cd uart_handle_sysrq_char_dir
		echo "$COMPTEST_PREAMBLE
		#include <linux/init.h>
		#include <linux/module.h>
		#include <linux/serial_core.h>

		static int __init comptest_init(void)
		{
			struct uart_port *port = NULL;
			unsigned int ch = 1;

			uart_handle_sysrq_char(port, ch);
			return 0;
		}

		static void __exit comptest_exit(void)
		{
		}

		module_init(comptest_init);
		module_exit(comptest_exit);

		MODULE_AUTHOR(\"Cambricon System Software Group\");
		MODULE_LICENSE(\"Dual BSD/GPL\");
		" > comptest_uart_handle_sysrq_char.c

		generate_makefile "comptest_uart_handle_sysrq_char"
		logsave comptest_uart_handle_sysrq_char_log bash -c "make" > /dev/null 2>&1
		warn_num=$(cat comptest_uart_handle_sysrq_char_log | grep WARNING | grep undefined | wc -l)
		if [ $warn_num -eq '0' ]; then
			echo "#define CN_PRECOMPILE_UART_HANDLE_SYSRQ_CHAR" | append_comptest "functions"
		fi
		#make clean > /dev/null 2>&1
		#rm -f comptest_uart_handle_sysrq_char.c
		#rm -f comptest_uart_handle_sysrq_char_log
		#rm -f Makefile
		cd ..
		rm -rf uart_handle_sysrq_char_dir

		return
	;;

    esac
}

case "$1" in
	compile_tests)
		#
		# Run a series of compile tests to determine the set of interfaces
		# and features available in the target kernel.
		#
		shift
		CC=$1
		CFLAGS=$2
		ARCH=$3
		OUTPUT=$4
		shift
		shift
		shift
		shift

		for i in $*; do compile_test $i; done

		exit 0
	;;

	build_cflags)
		#
		# Generate CFLAGS for use in the compile tests
		#
		shift
		CC=$1
		ARCH=$2
		ISYSTEM=`$CC -print-file-name=include 2> /dev/null`
		SOURCES=$3
		HEADERS=$SOURCES/include
		OUTPUT=$4
		CONFIG_CNDRV_PCIE_PLATFORM=$5
		KERNEL_ARCH="$ARCH"

		if [ "$ARCH" = "i386" -o "$ARCH" = "x86_64" ]; then
		    if [ -d "$SOURCES/arch/x86" ]; then
		        KERNEL_ARCH="x86"
		    fi
		fi

		HEADERS_ARCH="$SOURCES/arch/$KERNEL_ARCH/include"

		build_cflags
		echo $CFLAGS
		exit 0
	;;

esac
