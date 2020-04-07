#ifndef ELF_INTERNALS_H
#define ELF_INTERNALS_H

#include "utils.hpp"
#include "elfcomm.hpp"

namespace ELF {

ELF_STRUCT_DECL_T
class ElfPHdrClass {
private:
    ElfPhdr *hdr;
public:
    ElfPHdrClass() {};
    ElfPHdrClass(void *p) : hdr((ElfPhdr*)p) {};
    decltype(hdr->p_type)       get_p_type()        { return BYTE_GET(hdr->p_type);         }
    decltype(hdr->p_flags)      get_p_flags()       { return BYTE_GET(hdr->p_flags);        }
    decltype(hdr->p_offset)     get_p_offset()      { return BYTE_GET(hdr->p_offset);       }
    decltype(hdr->p_vaddr)      get_p_vaddr()       { return BYTE_GET(hdr->p_vaddr);        }
    decltype(hdr->p_filesz)     get_p_filesz()      { return BYTE_GET(hdr->p_filesz);       }
    decltype(hdr->p_memsz)      get_p_memsz()       { return BYTE_GET(hdr->p_memsz);        }
    decltype(hdr)               get_raw_ptr()       { return hdr;                           }       
};

ELF_STRUCT_DECL_T
class ElfDynClass {
private:
    ElfDynamic *hdr;
public:
    ElfDynClass() {};
    ElfDynClass(void *p) : hdr((ElfDynamic*)p) {};
    decltype(hdr->d_tag)        get_d_tag()         { return BYTE_GET(hdr->d_tag);          }
    decltype(hdr->d_un.d_ptr)   get_d_un_d_ptr()    { return BYTE_GET(hdr->d_un.d_ptr);     }
    decltype(hdr)               get_raw_ptr()       { return hdr;                           }
    void                        set_d_un_d_ptr(uint64_t p) { return BYTE_PUT(hdr->d_un.d_ptr, p);} 
};

ELF_STRUCT_DECL_T
class ElfHdrClass {
private:
    ElfHdr *hdr;
    int dynamic_index = -1;

public:
    ElfHdrClass() {};
    ElfHdrClass(void *h) : hdr((ElfHdr*)h) {};

    decltype(&hdr->e_ident[0])  get_e_ident()       { return &hdr->e_ident[0];              }
    decltype(hdr->e_type)       get_e_type()        { return BYTE_GET(hdr->e_type);         }
    decltype(hdr->e_version)    get_e_version()     { return BYTE_GET(hdr->e_version);      }
    decltype(hdr->e_phoff)      get_e_phoff()       { return BYTE_GET(hdr->e_phoff);        }
    decltype(hdr->e_shoff)      get_e_shoff()       { return BYTE_GET(hdr->e_shoff);        }
    decltype(hdr->e_phnum)      get_e_phnum()       { return BYTE_GET(hdr->e_phnum);        }
    decltype(hdr->e_phentsize)  get_e_phentsize()   { return BYTE_GET(hdr->e_phentsize);    }
    decltype(hdr->e_shnum)      get_e_shnum()       { return BYTE_GET(hdr->e_shnum);        }
    decltype(hdr->e_shentsize)  get_e_shentsize()   { return BYTE_GET(hdr->e_shentsize);    }
    decltype(hdr)               get_raw_ptr()       { return hdr;                   }
    void                        set_shoff(uint32_t p)   { BYTE_PUT(hdr->e_shoff, p);}
    void                        set_shnum(uint32_t p)   { BYTE_PUT(hdr->e_shnum, p);  }
    void                        set_shentsize(uint32_t p)   { BYTE_PUT(hdr->e_shentsize, p); }
    void                        set_shstrndx(uint32_t p)    {BYTE_PUT(hdr->e_shstrndx, p); }

    ElfPHdrClass<ElfHdr> get_phdr_at_index(uint32_t index) {
        ElfPhdr *vphdr = ELF_OFFSET_CAST(ElfPhdr, hdr, BYTE_GET(hdr->e_phoff));
        return ELF::ElfPHdrClass<ElfHdr>(&vphdr[index]);
    }

    void* get_dynamic_section(uint32_t section, bool is_index = false) {

        int index = dynamic_index;
        for (int i = 0; i < get_e_phnum() && index == -1; i++) {
            auto phdr = get_phdr_at_index(i);
            if (phdr.get_p_type() == PT_DYNAMIC) {
                DBGI("Found dynamic section @ %x", phdr.get_p_offset());
                index = i;
                dynamic_index = index;
                break;
            }
        }

        if (index == -1) {
            dynamic_index = -1;
            DBGW("Could not find dynamic section. Executable might be statically linked.");
            return nullptr;
        }

        /*  Looking up for section   */
        auto phdr = get_phdr_at_index(index);
        ElfDynamic *vdyn = ELF_OFFSET_CAST(ElfDynamic, hdr, phdr.get_p_offset());
        index = -1;

        for (int j = 0;; j++) {
            if (BYTE_GET(vdyn[j].d_tag) == DT_NULL) {
                DBGW("Could not find SECTION");
                break;
            }

            if ((is_index && j == section) || (!is_index && BYTE_GET(vdyn[j].d_tag) == section)) {
                index = j;
                return ElfDynClass<ElfHdr>(&vdyn[index]).get_raw_ptr();
            }
        }
        return nullptr;
    }

        void* get_dynamic_section_at_index(uint32_t index) {
        return get_dynamic_section(index, true);
    }
};

};
#endif