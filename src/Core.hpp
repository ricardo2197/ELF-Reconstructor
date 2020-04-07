#ifndef CORE_HPP
#define CORE_HPP

#include <sys/types.h>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <type_traits>
#include <utility>
#include "utils.hpp"
#include "elfcomm.hpp"
#include "ElfInternals.hpp"

class Core {
public:
    Core();
    ~Core();
    bool load_core(const char *path);
    static bool check_eident(uint8_t *hdr, bool log = true);
    void *get_core() const {return core;};
    unsigned long get_size() const {return size;};
    
    /*  ELF specific functions arhitecture dependent    */
    ELF_FUNTION_DECL_T
    std::pair<void*, void*> get_phdr_at(int index);

    ELF_FUNTION_DECL_T
    unsigned get_phnum();

    ELF_FUNTION_DECL_T
    bool check_ELFHdr(ELF::ElfHdrClass<ElfHdr> &hdr);
        
    int elf_class;
private:
    ELF::ElfHdrClass<Elf32_Ehdr> elf_header_32;
    ELF::ElfHdrClass<Elf64_Ehdr> elf_header_64;

    uint8_t *core;
    int fd;
    unsigned long long size;
    bool is_valid_core = false;
};
#endif