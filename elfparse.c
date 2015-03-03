/* Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "elfparse.h"

int is_elf_magic (const uint8_t *buf)
{
	return (buf[EI_MAG0] == ELFMAG0) &&
	       (buf[EI_MAG1] == ELFMAG1) &&
	       (buf[EI_MAG2] == ELFMAG2) &&
	       (buf[EI_MAG3] == ELFMAG3);
}

#define parseElftemplate(bit)                                                \
ElfType parseElf ## bit(FILE *elf_file, uint8_t *pHead, int little_endian)   \
{                                                                            \
	ElfType                      ret          = ELFSTATIC;               \
	Minijail_Elf ## bit ## _Ehdr *pHeader     = NULL;                    \
	Minijail_Elf ## bit ## _Phdr pheader      = { 0 };                   \
	uint32_t                     i            = 0;                       \
	                                                                     \
	if (!elf_file || !pHead)                                             \
		return ELFERROR;                                             \
	                                                                     \
	pHeader = (Minijail_Elf ## bit ## _Ehdr *)pHead;                     \
	if (little_endian) {                                                 \
		pHeader->e_phoff = le ## bit ## toh(pHeader->e_phoff);       \
		pHeader->e_phentsize = le16toh(pHeader->e_phentsize);        \
		pHeader->e_phnum = le16toh(pHeader->e_phnum);                \
	} else {                                                             \
		pHeader->e_phoff = be ## bit ## toh(pHeader->e_phoff);       \
		pHeader->e_phentsize = be16toh(pHeader->e_phentsize);        \
		pHeader->e_phnum = be16toh(pHeader->e_phnum);                \
	}                                                                    \
	if (pHeader->e_phentsize != sizeof(Minijail_Elf ## bit ## _Phdr))    \
		return ELFERROR;                                             \
	                                                                     \
	if (fseek(elf_file, pHeader->e_phoff, SEEK_SET) != 0)                \
		return ELFERROR;                                             \
	                                                                     \
	for (i = 0; i < pHeader->e_phnum; i++) {                             \
		if (fread(&pheader, sizeof(pheader), 1, elf_file) == 1) {    \
			if (pheader.p_type == PT_INTERP) {                   \
				ret = ELFDYNAMIC;                            \
				break;                                       \
			}                                                    \
		} else {                                                     \
			ret = ELFERROR;                                      \
			break;                                               \
		}                                                            \
	}                                                                    \
	return ret;                                                          \
}
parseElftemplate(64)
parseElftemplate(32)

/* Public function to determine the linkage of an ELF. */
ElfType get_elf_linkage(const char *path)
{
	ElfType ret = ELFERROR;
	FILE *elf_file = NULL;
	uint8_t pHeader[HEADERSIZE] = "";

	elf_file = fopen(path, "r");
	if (elf_file) {
		if (fread(pHeader, 1, HEADERSIZE, elf_file) == HEADERSIZE) {
			if (is_elf_magic(pHeader)) {
				if ((pHeader[EI_DATA] == ELFDATA2LSB) &&
				    (pHeader[EI_CLASS] == ELFCLASS64)) {
					/* 64 bit little endian */
					ret = parseElf64(elf_file, pHeader, 1);
				} else if ((pHeader[EI_DATA] == ELFDATA2MSB) &&
					  (pHeader[EI_CLASS] == ELFCLASS64)) {
					/* 64 bit big endian */
					ret = parseElf64(elf_file, pHeader, 0);
				} else if ((pHeader[EI_DATA] == ELFDATA2LSB) &&
					  (pHeader[EI_CLASS] == ELFCLASS32)) {
					/* 32 bit little endian */
					ret = parseElf32(elf_file, pHeader, 1);
				} else if ((pHeader[EI_DATA] == ELFDATA2MSB) &&
					  (pHeader[EI_CLASS] == ELFCLASS32)) {
					/* 32 bit big endian */
					ret = parseElf32(elf_file, pHeader, 0);
				}
			} else {
				/*
				 * The binary is not an ELF. We assume it's a
				 * script. We should parse the #! line and
				 * check the interpreter to guard against
				 * static interpreters escaping the sandbox.
				 * As minijail is only called from rootfs
				 * it was deemed not necessary to check this.
				 * So we will just let execve decided if this
				 * is valid.
				 */
				ret = ELFDYNAMIC;
			}
		} else {
			/*
			 * The file is smaller than |HEADERSIZE| bytes.
			 * We assume it's a short script. See above for
			 * reasoning on scripts.
			 */
			ret = ELFDYNAMIC;
		}
		fclose(elf_file);
	}
	return ret;
}
