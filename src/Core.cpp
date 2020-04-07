#include "Core.hpp"
#include "dbgtrace.hpp"
#include "utils.hpp"

Core::Core() {
    fd = 0;
    core = NULL;
    size = 0;
}

Core::~Core() {
    if (fd)
        close(fd);
    
    if (core)
        munmap(core, size);
}

/*  Validate eident field from ELF header */
bool Core::check_eident(uint8_t *hdr) {
    bool check = false;

    do {
        if (memcmp(hdr, ELFMAG, 4)) {
            DBGW("Wrong ELFMAG. File is not ELF");
            break;
        }

        if (!(hdr[EI_CLASS] == ELFCLASS32 || hdr[EI_CLASS] == ELFCLASS64)) {
            DBGE("Invalid EI_CLASS");
            break;
        }

        if (!(hdr[EI_DATA] == ELFDATA2LSB || hdr[EI_DATA] == ELFDATA2MSB)) {
            DBGE("Wrong EI_DATA");
            break;
        }

        if (!(hdr[EI_VERSION] == EV_CURRENT)) {
            DBGE("Wrong EI_VERSION");
            break;
        }

        if (!(hdr[EI_OSABI] == ELFOSABI_NONE || hdr[EI_OSABI] == ELFOSABI_SYSV ||
              hdr[EI_OSABI] == ELFOSABI_HPUX || hdr[EI_OSABI] == ELFOSABI_NETBSD ||
              hdr[EI_OSABI] == ELFOSABI_LINUX || hdr[EI_OSABI] == ELFOSABI_SOLARIS ||
              hdr[EI_OSABI] == ELFOSABI_IRIX || hdr[EI_OSABI] == ELFOSABI_FREEBSD ||
              hdr[EI_OSABI] == ELFOSABI_TRU64 || hdr[EI_OSABI] == ELFOSABI_ARM ||
              hdr[EI_OSABI] == ELFOSABI_STANDALONE)) {
            DBGE("WRONG EI_OSABI");
            break;
        }

        check = true;
    } while(0);

    return check;
}

/*  This method loads the core into memory and checks if it is valid    */
bool Core::load_core(char *path)
{
    int ret = 0;
    struct stat st;
    bool check = false;
    ret = stat(path, &st);
    M_EXIT(ret != 0, "Could not get size of file", ERRNO_FILE_ERROR);
    size = st.st_size;

    fd = open(path, O_RDONLY);
    M_EXIT(fd < 0, "Could not open file", ERRNO_FILE_ERROR);

    core = (uint8_t*)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    M_EXIT(core == MAP_FAILED, "Could not mmap file", ERRNO_MMAP);
    DBGI("Core size %lu, fd %d, mmap %p", size, fd, core);
    
    M_EXIT(size < EI_NIDENT, "File too small", ERRNO_FILE_ERROR);
    check = check_eident(core);
    M_EXIT(!check, "Invalid E_IDENT", ERRNO_INVALIDELF);


    if (core[EI_CLASS] == ELFCLASS32) {
        DBGI("ELF is 32 bits");
        return check_ELFHdr<Elf32_Ehdr>((Elf32_Ehdr*)core);
    }

    DBGI("Elf is 64 bits");
    return check_ELFHdr<Elf64_Ehdr>((Elf64_Ehdr*)core);
}

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
bool Core::check_ELFHdr(ElfHdr *hdr)
{
    bool check = false;

    do {
        if (!(hdr->e_type == ET_CORE)) {
            DBGE("File not ET_CORE");
            break;
        }

        if (!(hdr->e_version == EV_CURRENT)) {
            DBGE("Invalid E_VERSION");
            break;
        }

        if (hdr->e_phoff > size) {
            DBGE("e_phoff past end of file");
            break;
        }

        if (hdr->e_shoff > size) {
            DBGE("e_shoff past end of file");
            break;
        }

        //  TODO add case for PN_XNUM
        if (hdr->e_phnum != PN_XNUM && hdr->e_phnum * hdr->e_phentsize > size) {
            DBGE("PH Table past end of file");
            break;
        }

        if (hdr->e_shnum * hdr->e_shentsize > size) {
            DBGE("SH Table past end of file");
            break;
        }

        bool is_valid = true;
        ElfPhdr *vphdr = ELF_OFFSET_CAST(ElfPhdr, hdr, hdr->e_phoff);
        for (int i = 0; i < hdr->e_phnum; i++) {
            if (vphdr[i].p_offset + vphdr[i].p_filesz > size) {
                DBGE("Phdr %d over past of file: %u", i, vphdr[i].p_filesz + vphdr[i].p_offset);
                is_valid = false;
                break;
            }
        }

        if (!is_valid)
            break;

        is_valid = true;
        ElfShdr *vshdr = ELF_OFFSET_CAST(ElfShdr, hdr, hdr->e_shoff);
        for (int i = 0; i < hdr->e_shnum; i++) {
            if (vshdr[i].sh_offset + vshdr[i].sh_size > size) {
                DBGE("Shdr %d over past of file: %u", i, vshdr[i].sh_offset + vshdr[i].sh_size);
                is_valid = false;
                break;
            }
        }

        if (!is_valid)
            break;

        check = true;
    } while(0);

    is_valid_core = true;
    return check;
}

/*  Get Program Header for the provided index   */
template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
 std::pair<ElfPhdr*, void*> Core::get_phdr_at(int index)
 {
     if (!is_valid_core) {
        DBGW("Core file is not valid");
        return std::pair<ElfPhdr*, void*>(nullptr, nullptr);
     }

     if (index >= ELF_CAST(ElfHdr, core)->e_phnum) {
        DBGW("Requested index greater than total E_PHNUM");
        return std::pair<ElfPhdr*, void*>(nullptr, nullptr);
     }

    ElfHdr *hdr = ELF_CAST(ElfHdr, core);
    ElfPhdr *phdr = ELF_OFFSET_CAST(ElfPhdr, hdr, hdr->e_phoff);
    void *ptr = ELF_OFFSET_CAST(void, hdr,  phdr[index].p_offset);
    return std::pair<ElfPhdr*, void*>(&phdr[index], ptr);
}

/*  Get total number of Program Headers */
template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
unsigned Core::get_phnum()
{
     if (!is_valid_core) {
         DBGW("Core file is not valid");
         return 0;
     }

     return ELF_CAST(ElfHdr, core)->e_phnum;
}

template unsigned Core::get_phnum<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr, Elf64_Addr>();
template unsigned Core::get_phnum<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr, Elf32_Addr>();

template std::pair<Elf64_Phdr*, void*> Core::get_phdr_at<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr, Elf64_Addr>(int index);
template std::pair<Elf32_Phdr*, void*> Core::get_phdr_at<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr, Elf32_Addr>(int index);