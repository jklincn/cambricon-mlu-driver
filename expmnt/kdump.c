/*****************************************************************************
 * NOTICE:
 * Copyright (c) 2018 Cambricon, Inc. All rights reserved.
 * All Rights Reserved.
 * Property of Cambricon, Inc.
 * This software is made available solely pursuant to the
 * terms of a Cambricon license agreement which governs its use.
 ****************************************************************************/
#include <linux/mm.h>
#include <linux/kcore.h>
#include <linux/user.h>
#include <linux/elf.h>
#include <linux/elfcore.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <asm/uaccess.h>
#include <asm/io.h>

#include "cndrv_core.h"
#include "cndrv_bus.h"
#include "cndrv_mm.h"
#include "cndrv_debug.h"
#include "cndrv_ioctl.h"
#include "exp_mgnt_private.h"
#include "cndrv_commu.h"
#include "cndrv_ipcm.h"

/* Read from device use phy addrs*/
static size_t dma_d2h_phy(struct cn_core_set *core, u64 host_addr, u64 dev_addr,
						  size_t size, int userbuf)
{
	int ret;

	ret = cn_bus_dma_bypass_smmu_all(core->bus_set, 1);
	if (ret) {
		cn_dev_core_info(core, "dma bypass smmu all error");
		return ret;
	}
	if (userbuf) {
		struct transfer_s t;
		TRANSFER_INIT(t, host_addr, dev_addr, size, DMA_D2H);
		ret = cn_bus_dma(core->bus_set, &t);
		if (ret) {
			cn_dev_core_info(core,
				"dma error host_addr:%#llx dev_addr:%#llx size:%#lx userbuf:%d",
				host_addr, dev_addr, size, userbuf);
			cn_bus_dma_bypass_smmu_all(core->bus_set, 0);
			return ret;
		}
	} else {
		ret = cn_bus_dma_kernel(core->bus_set, host_addr, dev_addr,
				size, DMA_D2H);
		if (ret) {
			cn_dev_core_info(core,
				"dma error host_addr:%#llx dev_addr:%#llx size:%#lx userbuf:%d",
				host_addr, dev_addr, size, userbuf);
			cn_bus_dma_bypass_smmu_all(core->bus_set, 0);
			return ret;
		}
	}

	ret = cn_bus_dma_bypass_smmu_all(core->bus_set, 0);
	if (ret) {
		cn_dev_core_info(core, "dma unbypass smmu all error");
		return ret;
	}

	return ret;
}

static ssize_t read_from_oldmem(struct cn_core_set *core, char *buf, size_t count,
				u64 *ppos, int userbuf)
{
	ssize_t nr_bytes;

	if (!count)
		return 0;

	nr_bytes = dma_d2h_phy(core, (u64)buf, *ppos, count, userbuf);
	return nr_bytes;
}

/* notes data is in device mem, should read undirectly */
static ssize_t elfcorehdr_read_notes(struct cn_core_set *core, char *buf,
									 size_t count, u64 *ppos)
{
	return read_from_oldmem(core, buf, count, ppos, 0);
}

/* elfcorehdr is in sharemem, can read directly */
static ssize_t elfcorehdr_read(char *buf, size_t count, u64 *ppos)
{
	memcpy(buf, (char *)ppos, count);
	return count;
}

/*
 * Copy to either kernel or user space
 */
static int copy_to(void *target, void *src, size_t size, int userbuf)
{
	if (userbuf) {
		if (copy_to_user((char __user *) target, src, size))
			return -EFAULT;
	} else {
		memcpy(target, src, size);
	}
	return 0;
}

/* Read from the ELF header and then the crash dump. On error, negative value is
 * returned otherwise number of bytes read are returned.
 */
static ssize_t __read_vmcore(struct cn_core_set *core, char *buffer, size_t buflen, loff_t *fpos,
			     int userbuf)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	ssize_t acc = 0, tmp;
	size_t tsz;
	u64 start;
	struct vmcore *m = NULL;

	if (buflen == 0 || *fpos >= mnt_set->vmcore_size)
		return 0;

	/* trim buflen to not go beyond EOF */
	if (buflen > mnt_set->vmcore_size - *fpos)
		buflen = mnt_set->vmcore_size - *fpos;

	/* Read ELF core header */
	if (*fpos < mnt_set->elfcorebuf_sz) {
		tsz = min(mnt_set->elfcorebuf_sz - (size_t)*fpos, buflen);
		if (copy_to(buffer, mnt_set->elfcorebuf + *fpos, tsz, userbuf))
			return -EFAULT;
		buflen -= tsz;
		*fpos += tsz;
		buffer += tsz;
		acc += tsz;

		/* leave now if filled buffer already */
		if (buflen == 0)
			return acc;
	}

	/* Read Elf note segment */
	if (*fpos < mnt_set->elfcorebuf_sz + mnt_set->elfnotes_sz) {
		void *kaddr;

		tsz = min(mnt_set->elfcorebuf_sz + mnt_set->elfnotes_sz - (size_t)*fpos, buflen);
		kaddr = mnt_set->elfnotes_buf + *fpos - mnt_set->elfcorebuf_sz;
		if (copy_to(buffer, kaddr, tsz, userbuf))
			return -EFAULT;
		buflen -= tsz;
		*fpos += tsz;
		buffer += tsz;
		acc += tsz;

		/* leave now if filled buffer already */
		if (buflen == 0)
			return acc;
	}

	list_for_each_entry(m, &mnt_set->vmcore_list, list) {
		if (*fpos < m->offset + m->size) {
			tsz = (size_t)min_t(unsigned long long,
					    m->offset + m->size - *fpos,
					    buflen);
			start = m->paddr + *fpos - m->offset;
			tmp = read_from_oldmem(core, buffer, tsz, &start, userbuf);
			if (tmp < 0)
				return tmp;
			buflen -= tsz;
			*fpos += tsz;
			buffer += tsz;
			acc += tsz;

			/* leave now if filled buffer already */
			if (buflen == 0)
				return acc;
		}
	}

	return acc;
}

int cn_kdump_read(struct cn_core_set *core, char *buf, size_t len, loff_t *fpos)
{
	return __read_vmcore(core, buf, len, fpos, virt_addr_valid(buf)?0:1);
}

/**
 * alloc_elfnotes_buf - allocate buffer for ELF note segment in
 *                      vmalloc memory
 *
 * @notes_sz: size of buffer
 *
 * If CONFIG_MMU is defined, use vmalloc_user() to allow users to mmap
 * the buffer to user-space by means of remap_vmalloc_range().
 *
 * If CONFIG_MMU is not defined, use vzalloc() since mmap_vmcore() is
 * disabled and there's no need to allow users to mmap the buffer.
 */
static inline char *alloc_elfnotes_buf(size_t notes_sz)
{
	return vmalloc_user(notes_sz);
}

static u64 get_vmcore_size(size_t elfsz, size_t elfnotesegsz,
				  struct list_head *vc_list)
{
	u64 size;
	struct vmcore *m;

	size = elfsz + elfnotesegsz;
	list_for_each_entry(m, vc_list, list) {
		size += m->size;
	}
	return size;
}

/**
 * update_note_header_size_elf64 - update p_memsz member of each PT_NOTE entry
 *
 * @ehdr_ptr: ELF header
 *
 * This function updates p_memsz member of each PT_NOTE entry in the
 * program header table pointed to by @ehdr_ptr to real size of ELF
 * note segment.
 */
static int update_note_header_size_elf64(struct cn_core_set *core, const Elf64_Ehdr *ehdr_ptr)
{
	int i, rc=0;
	Elf64_Phdr *phdr_ptr;
	Elf64_Nhdr *nhdr_ptr;

	phdr_ptr = (Elf64_Phdr *)(ehdr_ptr + 1);
	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		void *notes_section;
		u64 offset, max_sz, sz, real_sz = 0;
		cn_dev_core_info(core, "%s poffset=%llx paddr=%llx vaddr=%llx filesz=%llx memsz=%llx",
			   (phdr_ptr->p_type == PT_NOTE)?"PT_NOTE":"PT_LOAD", phdr_ptr->p_offset,
			   phdr_ptr->p_paddr, phdr_ptr->p_vaddr, phdr_ptr->p_filesz, phdr_ptr->p_memsz);
		if (phdr_ptr->p_type != PT_NOTE)
			continue;
		max_sz = phdr_ptr->p_memsz;
		offset = phdr_ptr->p_offset;
		notes_section = kmalloc(max_sz, GFP_KERNEL);
		if (!notes_section)
			return -ENOMEM;
		rc = elfcorehdr_read_notes(core, notes_section, max_sz, &offset);
		if (rc < 0) {
			kfree(notes_section);
			return rc;
		}
		nhdr_ptr = notes_section;
		cn_dev_core_debug(core, "note type=%d namesz=%d descsz=%d",
			   nhdr_ptr->n_type, nhdr_ptr->n_namesz, nhdr_ptr->n_descsz);
		while (nhdr_ptr->n_namesz != 0) {
			sz = sizeof(Elf64_Nhdr) +
				(((u64)nhdr_ptr->n_namesz + 3) & ~3) +
				(((u64)nhdr_ptr->n_descsz + 3) & ~3);
			if ((real_sz + sz) > max_sz) {
				cn_dev_core_info(core, "Warning: Exceeded p_memsz, dropping PT_NOTE entry n_namesz=0x%x, n_descsz=0x%x",
					nhdr_ptr->n_namesz, nhdr_ptr->n_descsz);
				break;
			}
			real_sz += sz;
			nhdr_ptr = (Elf64_Nhdr*)((char*)nhdr_ptr + sz);
		}
		kfree(notes_section);
		phdr_ptr->p_memsz = real_sz;
		if (real_sz == 0) {
			cn_dev_core_debug(core, "kdump: Zero PT_NOTE entries found");
		}
	}

	return 0;
}

/**
 * get_note_number_and_size_elf64 - get the number of PT_NOTE program
 * headers and sum of real size of their ELF note segment headers and
 * data.
 *
 * @ehdr_ptr: ELF header
 * @nr_ptnote: buffer for the number of PT_NOTE program headers
 * @sz_ptnote: buffer for size of unique PT_NOTE program header
 *
 * This function is used to merge multiple PT_NOTE program headers
 * into a unique single one. The resulting unique entry will have
 * @sz_ptnote in its phdr->p_mem.
 *
 * It is assumed that program headers with PT_NOTE type pointed to by
 * @ehdr_ptr has already been updated by update_note_header_size_elf64
 * and each of PT_NOTE program headers has actual ELF note segment
 * size in its p_memsz member.
 */
static int get_note_number_and_size_elf64(const Elf64_Ehdr *ehdr_ptr,
						 int *nr_ptnote, u64 *sz_ptnote)
{
	int i;
	Elf64_Phdr *phdr_ptr;

	*nr_ptnote = *sz_ptnote = 0;

	phdr_ptr = (Elf64_Phdr *)(ehdr_ptr + 1);
	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		if (phdr_ptr->p_type != PT_NOTE)
			continue;
		*nr_ptnote += 1;
		*sz_ptnote += phdr_ptr->p_memsz;
	}

	return 0;
}

/**
 * copy_notes_elf64 - copy ELF note segments in a given buffer
 *
 * @ehdr_ptr: ELF header
 * @notes_buf: buffer into which ELF note segments are copied
 *
 * This function is used to copy ELF note segment in the 1st kernel
 * into the buffer @notes_buf in the 2nd kernel. It is assumed that
 * size of the buffer @notes_buf is equal to or larger than sum of the
 * real ELF note segment headers and data.
 *
 * It is assumed that program headers with PT_NOTE type pointed to by
 * @ehdr_ptr has already been updated by update_note_header_size_elf64
 * and each of PT_NOTE program headers has actual ELF note segment
 * size in its p_memsz member.
 */
static int copy_notes_elf64(struct cn_core_set *core, const Elf64_Ehdr *ehdr_ptr, char *notes_buf)
{
	int i, rc=0;
	Elf64_Phdr *phdr_ptr;

	phdr_ptr = (Elf64_Phdr*)(ehdr_ptr + 1);

	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		u64 offset;
		if (phdr_ptr->p_type != PT_NOTE)
			continue;
		offset = phdr_ptr->p_offset;
		rc = elfcorehdr_read_notes(core, notes_buf, phdr_ptr->p_memsz,
					   &offset);
		if (rc < 0)
			return rc;
		notes_buf += phdr_ptr->p_memsz;
	}

	return 0;
}

/* Merges all the PT_NOTE headers into one. */
static int merge_note_headers_elf64(struct cn_core_set *core, char *elfptr, size_t *elfsz,
					   char **notes_buf, size_t *notes_sz)
{
	int i, nr_ptnote=0, rc=0;
	char *tmp;
	Elf64_Ehdr *ehdr_ptr;
	Elf64_Phdr phdr;
	u64 phdr_sz = 0, note_off;

	ehdr_ptr = (Elf64_Ehdr *)elfptr;

	rc = update_note_header_size_elf64(core, ehdr_ptr);
	if (rc < 0)
		return rc;

	rc = get_note_number_and_size_elf64(ehdr_ptr, &nr_ptnote, &phdr_sz);
	if (rc < 0)
		return rc;

	*notes_sz = roundup(phdr_sz, PAGE_SIZE);
	*notes_buf = alloc_elfnotes_buf(*notes_sz);
	if (!*notes_buf)
		return -ENOMEM;

	rc = copy_notes_elf64(core, ehdr_ptr, *notes_buf);
	if (rc < 0)
		return rc;

	/* Prepare merged PT_NOTE program header. */
	phdr.p_type    = PT_NOTE;
	phdr.p_flags   = 0;
	note_off = sizeof(Elf64_Ehdr) +
			(ehdr_ptr->e_phnum - nr_ptnote +1) * sizeof(Elf64_Phdr);
	phdr.p_offset  = roundup(note_off, PAGE_SIZE);
	phdr.p_vaddr   = phdr.p_paddr = 0;
	phdr.p_filesz  = phdr.p_memsz = phdr_sz;
	phdr.p_align   = 0;

	/* Add merged PT_NOTE program header*/
	tmp = elfptr + sizeof(Elf64_Ehdr);
	memcpy(tmp, &phdr, sizeof(phdr));
	tmp += sizeof(phdr);

	/* Remove unwanted PT_NOTE program headers. */
	i = (nr_ptnote - 1) * sizeof(Elf64_Phdr);
	*elfsz = *elfsz - i;
	memmove(tmp, tmp+i, ((*elfsz)-sizeof(Elf64_Ehdr)-sizeof(Elf64_Phdr)));
	memset(elfptr + *elfsz, 0, i);
	*elfsz = roundup(*elfsz, PAGE_SIZE);

	/* Modify e_phnum to reflect merged headers. */
	ehdr_ptr->e_phnum = ehdr_ptr->e_phnum - nr_ptnote + 1;

	return 0;
}

/* Add memory chunks represented by program headers to vmcore list. Also update
 * the new offset fields of exported program headers. */
static int process_ptload_program_headers_elf64(char *elfptr,
						size_t elfsz,
						size_t elfnotes_sz,
						struct list_head *vc_list)
{
	int i;
	Elf64_Ehdr *ehdr_ptr;
	Elf64_Phdr *phdr_ptr;
	loff_t vmcore_off;
	struct vmcore *new;

	ehdr_ptr = (Elf64_Ehdr *)elfptr;
	phdr_ptr = (Elf64_Phdr*)(elfptr + sizeof(Elf64_Ehdr)); /* PT_NOTE hdr */

	/* Skip Elf header, program headers and Elf note segment. */
	vmcore_off = elfsz + elfnotes_sz;

	for (i = 0; i < ehdr_ptr->e_phnum; i++, phdr_ptr++) {
		u64 paddr, start, end, size;

		if (phdr_ptr->p_type != PT_LOAD)
			continue;

		paddr = phdr_ptr->p_offset;
		start = rounddown(paddr, PAGE_SIZE);
		end = roundup(paddr + phdr_ptr->p_memsz, PAGE_SIZE);
		size = end - start;

		/* Add this contiguous chunk of memory to vmcore list.*/
		new = kzalloc(sizeof(struct vmcore), GFP_KERNEL);
		if (!new)
			return -ENOMEM;
		new->paddr = start;
		new->size = size;
		list_add_tail(&new->list, vc_list);

		/* Update the program header offset. */
		phdr_ptr->p_offset = vmcore_off + (paddr - start);
		vmcore_off = vmcore_off + size;
	}
	return 0;
}

/* Sets offset fields of vmcore elements. */
static void set_vmcore_list_offsets(size_t elfsz, size_t elfnotes_sz,
					   struct list_head *vc_list)
{
	loff_t vmcore_off;
	struct vmcore *m;

	/* Skip Elf header, program headers and Elf note segment. */
	vmcore_off = elfsz + elfnotes_sz;

	list_for_each_entry(m, vc_list, list) {
		m->offset = vmcore_off;
		vmcore_off += m->size;
	}
}

static int parse_crash_elf64_headers(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	int rc=0;
	Elf64_Ehdr ehdr;
	u64 addr;

	addr = mnt_set->kdumphdr_addr;

	/* Read Elf header */
	rc = elfcorehdr_read((char *)&ehdr, sizeof(Elf64_Ehdr), (u64 *)addr);
	if (rc < 0)
		return rc;

	/* Do some basic Verification. */
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
		(ehdr.e_type != ET_CORE) ||
		ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
		ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
		ehdr.e_version != EV_CURRENT ||
		ehdr.e_ehsize != sizeof(Elf64_Ehdr) ||
		ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
		ehdr.e_phnum == 0) {
		cn_dev_core_err(core, "Warning: Core image elf header is not sane\n");
		return -EINVAL;
	}

	mnt_set->elfcorebuf_sz_orig = sizeof(Elf64_Ehdr) +
				ehdr.e_phnum * sizeof(Elf64_Phdr);
	mnt_set->elfcorebuf_sz = mnt_set->elfcorebuf_sz_orig;
	if (mnt_set->elfcorebuf == NULL) {
		mnt_set->elfcorebuf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
										get_order(mnt_set->elfcorebuf_sz_orig));
	}
	rc = elfcorehdr_read(mnt_set->elfcorebuf, mnt_set->elfcorebuf_sz_orig, (u64 *)addr);
	if (rc < 0)
		goto fail;

	cn_dev_core_debug(core, "elfbuffer size=%ld phnum=%d e_ehsize=%d e_phentsize=%d", mnt_set->elfcorebuf_sz,
					 ehdr.e_phnum, ehdr.e_ehsize, ehdr.e_phentsize);

	/* Merge all PT_NOTE headers into one. */
	rc = merge_note_headers_elf64(core, mnt_set->elfcorebuf, &mnt_set->elfcorebuf_sz,
				      &mnt_set->elfnotes_buf, &mnt_set->elfnotes_sz);
	if (rc)
		goto fail;
	rc = process_ptload_program_headers_elf64(mnt_set->elfcorebuf, mnt_set->elfcorebuf_sz,
						  mnt_set->elfnotes_sz, &mnt_set->vmcore_list);
	if (rc)
		goto fail;
	set_vmcore_list_offsets(mnt_set->elfcorebuf_sz, mnt_set->elfnotes_sz, &mnt_set->vmcore_list);
	return 0;
fail:
	vfree(mnt_set->elfnotes_buf);
	mnt_set->elfnotes_buf = NULL;
	free_pages((unsigned long)mnt_set->elfcorebuf, get_order(mnt_set->elfcorebuf_sz_orig));
	mnt_set->elfcorebuf = NULL;
	return rc;
}

static int parse_crash_elf_headers(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	unsigned char e_ident[EI_NIDENT];
	u64 addr;
	int rc=0;

	addr = mnt_set->kdumphdr_addr;;
	rc = elfcorehdr_read(e_ident, EI_NIDENT, (u64 *)addr);
	if (rc < 0)
		return rc;
	if (memcmp(e_ident, ELFMAG, SELFMAG) != 0) {
		cn_dev_core_err(core, "Warning: Core image elf header not found\n");
		return -EINVAL;
	}

	if (e_ident[EI_CLASS] == ELFCLASS64) {
		rc = parse_crash_elf64_headers(core);
		if (rc)
			return rc;
	} else {
		cn_dev_core_err(core, "Warning: Core image elf header is not sane\n");
		return -EINVAL;
	}

	/* Determine vmcore size. */
	mnt_set->vmcore_size = get_vmcore_size(mnt_set->elfcorebuf_sz, mnt_set->elfnotes_sz,
				      &mnt_set->vmcore_list);

	return 0;
}

int cn_kdump_init(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	int rc = 0;

	mnt_set->kdumphdr_addr = cn_shm_get_host_addr_by_name(core, "kdump_reserved");
	mnt_set->kdumphdr_size = cn_shm_get_size_by_name(core, "kdump_reserved");
	cn_dev_core_info(core, "kdump_header base = %lx size = %lx",
				mnt_set->kdumphdr_addr, mnt_set->kdumphdr_size);

	INIT_LIST_HEAD(&mnt_set->vmcore_list);

	rc = parse_crash_elf_headers(core);
	if (rc) {
		cn_dev_core_err(core, "Kdump: vmcore not initialized\n");
		return rc;
	}

	return 0;
}

void cn_kdump_exit(struct cn_core_set *core)
{
	struct cn_mnt_set *mnt_set = (struct cn_mnt_set *)core->mnt_set;
	struct list_head *pos, *next;

	/* clear the vmcore list. */
	list_for_each_safe(pos, next, &mnt_set->vmcore_list) {
		struct vmcore *m;

		m = list_entry(pos, struct vmcore, list);
		list_del(&m->list);
		kfree(m);
	}

	vfree(mnt_set->elfnotes_buf);
	mnt_set->elfnotes_buf = NULL;
	if (mnt_set->elfcorebuf != NULL) {
		free_pages((unsigned long)mnt_set->elfcorebuf, get_order(mnt_set->elfcorebuf_sz_orig));
		mnt_set->elfcorebuf = NULL;
	}
}
