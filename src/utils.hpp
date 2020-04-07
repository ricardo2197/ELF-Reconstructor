#ifndef UTILS_HPP
#define UTILS_HPP

#include <errno.h>
#include <stdlib.h>
#include "dbgtrace.hpp"

#define M_EXIT(assertion, call_description, code)				\
	do {								\
		if (assertion) {					\
			DBGE(call_description ": %s",  strerror(errno)) \
			exit(code);					\
		}							\
	} while (0)

#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))
#define ELF_CAST(type, base) (ELF_OFFSET_CAST(type, base, 0))
#define ELF_OFFSET_CAST(type, base, offset) (type*)((uint8_t*)base + offset)

#define ELF_FUNTION_DECL_T template <typename ElfHdr, \
    typename ElfPhdr = typename std::conditional< std::is_same<ElfHdr, Elf64_Ehdr>::value, Elf64_Phdr, Elf32_Phdr>::type, \
    typename ElfShdr = typename std::conditional< std::is_same<ElfHdr, Elf64_Ehdr>::value, Elf64_Shdr, Elf32_Shdr>::type,  \
	typename ElfAddr = typename std::conditional< std::is_same<ElfHdr, Elf64_Ehdr>::value, Elf64_Addr, Elf32_Addr>::type >

#define ERRNO_SUCCESS 		0
#define ERRNO_ARGUMENTS 	1
#define ERRNO_FILE_ERROR 	2
#define ERRNO_MMAP		 	3
#define ERRNO_NOMEM			4
#define ERRNO_INVALIDELF	5

#endif