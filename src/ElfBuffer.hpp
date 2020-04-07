#ifndef ELFBUFFER_H
#define ELFBUFFER_H

#include <sys/types.h>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <type_traits>
#include <vector>

#include "Core.hpp"

/*
    Using a std::vector<elfPhdr> to create a list of phdr with assosicated data.
    Storing the elf header separately in a std::vector in order to add/remove bytes from
    PHDR table.
    When dumping the data, elfhdr and elfchunks are chained together and offsets are updated.
    !!!! REMEMBER: first PHDR also contains the ELF Header, but in our program they are saved
    indipendently. Take care of this when updating offsets.
*/

/*
    Phdr from CORE file. (pointer)
    Phdr from ELF image. (copy)
    Data.
*/

template <typename ElfPhdr>
struct Elf_phdr_chunk {
    ElfPhdr *core_hdr;
    ElfPhdr original_hdr;
    void *data;
};

ELF_FUNTION_DECL_T
class ElfBuffer {
public:
    ElfBuffer() {};
    ElfBuffer(bool l, int c): list(l), index(c) {};
    void reconstruct_elf(Core &coredump);
    ElfHdr* get_elf_header();
    ElfPhdr* get_phdr_table();
    void add_phdr_segment(char *data, unsigned len, ElfPhdr *phdr);
    bool find_original_elf_header(Core &coredump);
    bool find_original_segments(Core &coredump);
    bool assemble_elf();
    bool add_padding(unsigned long long upper_bound);

    bool find_original_segments_pie(Core &coredump);
    
    template <typename ElfDynamic = typename std::conditional< std::is_same<ElfHdr, Elf64_Ehdr>::value, Elf64_Dyn, Elf32_Dyn>::type>
    bool patch_binary();

    template <typename Type>
    void modify_address(ElfAddr address, Type value);

private:
    std::vector<Elf_phdr_chunk<ElfPhdr> > elf_chunks;
    std::vector<uint8_t> elf_hdr_bytes;
    std::vector<uint8_t> elf_buffer;
    bool can_assemble = false;
    bool can_dump = false;
    bool is_pie = false;
    bool list;
    int index;
    uint64_t vmaddr_elf_header = 0x0;
};

#endif