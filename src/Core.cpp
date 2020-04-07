#include "Core.hpp"
#include "dbgtrace.hpp"
#include "utils.hpp"

Core::Core()
{
    fd = 0;
    core = NULL;
    size = 0;
}

Core::~Core()
{
    if (fd)
        close(fd);

    if (core)
        munmap(core, size);
}

/*  Validate eident field from ELF header */
bool Core::check_eident(uint8_t *hdr, bool log)
{
    bool check = false;

    do
    {
        if (memcmp(hdr, ELFMAG, 4))
        {
            if (log)
                DBGE("Wrong ELFMAG. File is not ELF");
            break;
        }

        if (!(hdr[EI_CLASS] == ELFCLASS32 || hdr[EI_CLASS] == ELFCLASS64))
        {
            if (log)
                DBGE("Invalid EI_CLASS");
            break;
        }

        if (!(hdr[EI_DATA] == ELFDATA2LSB || hdr[EI_DATA] == ELFDATA2MSB))
        {
            if (log)
                DBGE("Wrong EI_DATA");
            break;
        }

        if (!(hdr[EI_VERSION] == EV_CURRENT))
        {
            if (log)
                DBGE("Wrong EI_VERSION");
            break;
        }

        if (!(hdr[EI_OSABI] == ELFOSABI_NONE || hdr[EI_OSABI] == ELFOSABI_SYSV ||
              hdr[EI_OSABI] == ELFOSABI_HPUX || hdr[EI_OSABI] == ELFOSABI_NETBSD ||
              hdr[EI_OSABI] == ELFOSABI_LINUX || hdr[EI_OSABI] == ELFOSABI_SOLARIS ||
              hdr[EI_OSABI] == ELFOSABI_IRIX || hdr[EI_OSABI] == ELFOSABI_FREEBSD ||
              hdr[EI_OSABI] == ELFOSABI_TRU64 || hdr[EI_OSABI] == ELFOSABI_ARM ||
              hdr[EI_OSABI] == ELFOSABI_STANDALONE))
        {
            if (log)
                DBGE("WRONG EI_OSABI");
            break;
        }

        check = true;
    } while (0);

    return check;
}

/*  This method loads the core into memory and checks if it is valid    */
bool Core::load_core(const char *path)
{
    int ret = 0;
    struct stat st;
    bool check = false;
    ret = stat(path, &st);
    M_EXIT(ret != 0, "Could not get size of file", ERRNO_FILE_ERROR);
    size = st.st_size;

    fd = open(path, O_RDONLY);
    M_EXIT(fd < 0, "Could not open file", ERRNO_FILE_ERROR);

    core = (uint8_t *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    M_EXIT(core == MAP_FAILED, "Could not mmap file", ERRNO_MMAP);
    DBGI("Core size %lu, fd %d, mmap %p", size, fd, core);

    M_EXIT(size < EI_NIDENT, "File too small", ERRNO_FILE_ERROR);
    check = check_eident(core);
    M_EXIT(!check, "Invalid E_IDENT", ERRNO_INVALIDELF);

    if (core[EI_CLASS] == ELFCLASS32)
    {
        DBGI("ELF is 32 bits");
        elf_class = ELFCLASS32;
        elf_header_32 = ELF::ElfHdrClass<Elf32_Ehdr>((Elf32_Ehdr *)core);
        return check_ELFHdr<Elf32_Ehdr>(elf_header_32);
    }

    DBGI("Elf is 64 bits");
    elf_class = ELFCLASS64;
    elf_header_64 = ELF::ElfHdrClass<Elf64_Ehdr>((Elf64_Ehdr *)core);
    return check_ELFHdr<Elf64_Ehdr>(elf_header_64);
}

template <typename ElfHdr,  typename ElfAddr>
bool Core::check_ELFHdr(ELF::ElfHdrClass<ElfHdr> &hdr)
{
    bool check = false;

    do
    {
        auto e_ident = hdr.get_e_ident();
        switch ((int)(e_ident[EI_DATA]))
        {
        default:
        case ELFDATANONE:
        case ELFDATA2LSB:
            DBGI("Little endian");
            byte_get = byte_get_little_endian;
            byte_put = byte_put_little_endian;
            break;
        case ELFDATA2MSB:
            DBGI("Big endian");
            byte_get = byte_get_big_endian;
            byte_put = byte_put_big_endian;
            break;
        }

        if (hdr.get_e_type() != ET_CORE)
        {
            DBGE("File not ET_CORE");
            break;
        }

        if (!(hdr.get_e_version() == EV_CURRENT))
        {
            DBGE("Invalid E_VERSION");
            break;
        }

        if (hdr.get_e_phoff() > size)
        {
            DBGE("e_phoff past end of file");
            break;
        }

        if (hdr.get_e_shoff() > size)
        {
            DBGE("e_shoff past end of file");
            break;
        }

        if (hdr.get_e_phnum() != PN_XNUM && (uint)(hdr.get_e_phnum() * hdr.get_e_phentsize()) > size)
        {
            DBGE("PH Table past end of file");
            break;
        }

        if ((uint)(hdr.get_e_shnum()) * hdr.get_e_shentsize() > size)
        {
            DBGE("SH Table past end of file");
            break;
        }

        bool is_valid = true;
        //ElfPhdr *vphdr = ELF_OFFSET_CAST(ElfPhdr, hdr, BYTE_GET(hdr->e_phoff));
        auto phnum = hdr.get_e_phnum();
        for (int i = 0; i < phnum; i++)
        {
            auto phdr = hdr.get_phdr_at_index(i);

            auto offset = phdr.get_p_offset();
            auto filesize = phdr.get_p_filesz();
            if (offset + filesize > size)
            {
                DBGE("Phdr %d over past of file: %u", i, offset + filesize);
                is_valid = false;
                break;
            }
        }

        if (!is_valid)
            break;

        is_valid = true;
        check = true;
    } while (0);

    is_valid_core = true;
    return check;
}

/*  Get Program Header for the provided index   */
template <typename ElfHdr,  typename ElfAddr>
std::pair<void *, void *> Core::get_phdr_at(int index)
{
    if (!is_valid_core)
    {
        DBGW("Core file is not valid");
        return std::pair<void *, void *>(nullptr, nullptr);
    }

    ELF::ElfHdrClass<ElfHdr> core_header((ElfHdr*)core);
    if (index >= core_header.get_e_phnum())
    {
        DBGW("Requested index greater than total E_PHNUM");
        return std::pair<void *, void *>(nullptr, nullptr);
    }

    auto phdr = core_header.get_phdr_at_index(index);
    void *ptr = (uint8_t*)core_header.get_raw_ptr() + phdr.get_p_offset();
    return std::pair<void *, void *>(phdr.get_raw_ptr(), ptr);
}

/*  Get total number of Program Headers */
template <typename ElfHdr, typename ElfAddr>
unsigned Core::get_phnum()
{
    if (!is_valid_core)
    {
        DBGW("Core file is not valid");
        return 0;
    }

     ELF::ElfHdrClass<ElfHdr> core_header((ElfHdr*)core);
    return core_header.get_e_phnum();
}

template unsigned Core::get_phnum<Elf64_Ehdr,  Elf64_Addr>();
template unsigned Core::get_phnum<Elf32_Ehdr, Elf32_Addr>();

template std::pair<void *, void *> Core::get_phdr_at<Elf64_Ehdr, Elf64_Addr>(int index);
template std::pair<void *, void *> Core::get_phdr_at<Elf32_Ehdr, Elf32_Addr>(int index);
