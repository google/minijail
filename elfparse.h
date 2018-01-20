/* elfparse.h
 * Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Elf parsing.
 */

#ifndef _ELFPARSE_H_
#define _ELFPARSE_H_

#include <elf.h>

/*
 * These structs come from elf.h
 * The version in elf.h do not pack these structs so
 * portability could be an issue.
 * The compiler could mess with aligmment depending on arch
 * so I'm redefining them here and packing them to 1-byte alignment.
 */
#if !defined(EI_NIDENT)
#define EI_NIDENT (16)
#endif
#pragma pack(push)
#pragma pack(1)
typedef struct
{
	unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */
	Elf32_Half    e_type;             /* Object file type */
	Elf32_Half    e_machine;          /* Architecture */
	Elf32_Word    e_version;          /* Object file version */
	Elf32_Addr    e_entry;            /* Entry point virtual address */
	Elf32_Off     e_phoff;            /* Program header table file offset */
	Elf32_Off     e_shoff;            /* Section header table file offset */
	Elf32_Word    e_flags;            /* Processor-specific flags */
	Elf32_Half    e_ehsize;           /* ELF header size in bytes */
	Elf32_Half    e_phentsize;        /* Program header table entry size */
	Elf32_Half    e_phnum;            /* Program header table entry count */
	Elf32_Half    e_shentsize;        /* Section header table entry size */
	Elf32_Half    e_shnum;            /* Section header table entry count */
	Elf32_Half    e_shstrndx;         /* Section header string table index */
} Minijail_Elf32_Ehdr;

typedef struct
{
	unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */
	Elf64_Half    e_type;             /* Object file type */
	Elf64_Half    e_machine;          /* Architecture */
	Elf64_Word    e_version;          /* Object file version */
	Elf64_Addr    e_entry;            /* Entry point virtual address */
	Elf64_Off     e_phoff;            /* Program header table file offset */
	Elf64_Off     e_shoff;            /* Section header table file offset */
	Elf64_Word    e_flags;            /* Processor-specific flags */
	Elf64_Half    e_ehsize;           /* ELF header size in bytes */
	Elf64_Half    e_phentsize;        /* Program header table entry size */
	Elf64_Half    e_phnum;            /* Program header table entry count */
	Elf64_Half    e_shentsize;        /* Section header table entry size */
	Elf64_Half    e_shnum;            /* Section header table entry count */
	Elf64_Half    e_shstrndx;         /* Section header string table index */
} Minijail_Elf64_Ehdr;

typedef struct
{
	Elf32_Word      p_type;           /* Segment type */
	Elf32_Off       p_offset;         /* Segment file offset */
	Elf32_Addr      p_vaddr;          /* Segment virtual address */
	Elf32_Addr      p_paddr;          /* Segment physical address */
	Elf32_Word      p_filesz;         /* Segment size in file */
	Elf32_Word      p_memsz;          /* Segment size in memory */
	Elf32_Word      p_flags;          /* Segment flags */
	Elf32_Word      p_align;          /* Segment alignment */
} Minijail_Elf32_Phdr;

typedef struct
{
	Elf64_Word      p_type;           /* Segment type */
	Elf64_Word      p_flags;          /* Segment flags */
	Elf64_Off       p_offset;         /* Segment file offset */
	Elf64_Addr      p_vaddr;          /* Segment virtual address */
	Elf64_Addr      p_paddr;          /* Segment physical address */
	Elf64_Xword     p_filesz;         /* Segment size in file */
	Elf64_Xword     p_memsz;          /* Segment size in memory */
	Elf64_Xword     p_align;          /* Segment alignment */
} Minijail_Elf64_Phdr;
#pragma pack(pop)
/* End of definitions from elf.h */

enum ElfTypeEnum { ELFERROR=0, ELFSTATIC=1, ELFDYNAMIC=2 };
typedef enum ElfTypeEnum ElfType;

/*
 * This is the initial amount of the ELF file we try and read.
 * It is the same value that the kernel uses (BINPRM_BUF_SIZE).
 */
#define HEADERSIZE  128

ElfType get_elf_linkage(const char *path);

#endif /* _ELFPARSE_H_ */
