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

class Core {
public:
    Core();
    ~Core();
    bool load_core(char *path);
    static bool check_eident(uint8_t *hdr);
    void *get_core() const {return core;};
    unsigned long get_size() const {return size;};
    
    /*  ELF specific functions arhitecture dependent    */
    ELF_FUNTION_DECL_T
    std::pair<ElfPhdr*, void*> get_phdr_at(int index);

    ELF_FUNTION_DECL_T
    unsigned get_phnum();

    ELF_FUNTION_DECL_T
    bool check_ELFHdr(ElfHdr *hdr);

private:
    uint8_t *core;
    int fd;
    unsigned long size;
    bool is_valid_core = false;
};
#endif