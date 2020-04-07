#include "ElfBuffer.hpp"
#include "dbgtrace.hpp"
#include "utils.hpp"
#include "Core.hpp"

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
void ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::reconstruct_elf(Core &coredump)
{
    bool ret;
    uint8_t *core = (uint8_t*)(coredump.get_core());
    auto size = coredump.get_size();

    if (!core || !size) {
        DBGE("Empty core or invalid size");
        return;
    }

    /*  Recover ELF header of the original image    */
    ret = find_original_elf_header(coredump);
    if (!ret) {
        DBGE("Could not find ELF original header in CORE segments");
        return;
    }

    /*  Dump all segments into a list   */
    if ((get_elf_header()->e_type) == ET_DYN) {
        DBGI("Executable is PIE");
        ret = find_original_segments_pie(coredump);
    } else 
        ret = find_original_segments(coredump);

    if (!ret) {
        DBGE("Could not find original loadable segments");
        return;
    }

    /*  Assemble segments with headers  */
    ret = assemble_elf();
    if (!ret) {
        DBGE("Could not assemble ELF");
        return;
    }

    /*  
     *   Do not return if this function fails
     *   ELF might have no dynamic section.
     */
    ret = patch_binary();
    if (!ret) {
        DBGE("Could not patch ELF. It might be corrupted");
    }

    //TODO make proper dump
    FILE *f = fopen("test.out", "wb");
    if (!f)
    {   
        DBGE("Could not open file");
        return;
    }

    fwrite(elf_buffer.data(), elf_buffer.size(), 1, f);
    fclose(f);
}

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
template <typename Type>
void ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::modify_address(ElfAddr address, Type value)
{
    ElfHdr *hdr = ELF_CAST(ElfHdr, elf_buffer.data());
    ElfPhdr* vphdr = ELF_OFFSET_CAST(ElfPhdr, hdr, hdr->e_phoff);

    for (int k =0; k < hdr->e_phnum; k++)
    {
        if (vphdr[k].p_type != PT_LOAD)
            continue;

        if (vphdr[k].p_vaddr <= address && address < vphdr[k].p_vaddr + vphdr[k].p_filesz) 
        {
            auto dif = address - vphdr[k].p_vaddr;
            Type *address_in_elf = ELF_OFFSET_CAST(Type, hdr, vphdr[k].p_offset + dif);
            DBGI("Patching %p with 0x%x", address_in_elf, value);
            *address_in_elf = value;
            return;
        }
    }

    DBGE("Failed to find segment for %p", address);
}

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
template <typename ElfDynamic>
bool ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::patch_binary()
{
    ElfHdr *hdr = ELF_CAST(ElfHdr, elf_buffer.data());
    hdr->e_shnum = 0;
    hdr->e_shoff = 0;
    hdr->e_shstrndx = 0;

    /*  Searching PT_DYNAMIC Program Header */
    ElfPhdr* vphdr = ELF_OFFSET_CAST(ElfPhdr, hdr, hdr->e_phoff);
    int index = -1;
    for (int i = 0; i < hdr->e_phnum; i++) {
        if (vphdr[i].p_type == PT_DYNAMIC) {
            DBGI("Found dynamic section @ %x", vphdr[i].p_offset);
            index = i;
            break;
        }
    }

    if (index == -1) {
        DBGE("Could not find dynamic section");
        return false;
    }

    /*  Looking up for PLTGOT   */
    ElfDynamic *vdyn = ELF_OFFSET_CAST(ElfDynamic, hdr, vphdr[index].p_offset);
    index = -1;

    for (int j = 0;; j++) {
        if (vdyn[j].d_tag == DT_NULL) {
            DBGE("Could not find PLTGOT");
            break;
        }

        if (vdyn[j].d_tag == DT_PLTGOT) {
            DBGI("Found PLTGOT @ %p", vdyn[j].d_un.d_ptr);
            index = j;
            break;
        }
    }

    if (index == -1) {
        DBGW("Could not find PLTGOT in PT_DYNAMIC")
        return false;
    }
    
    return true;

}

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
ElfHdr* ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::get_elf_header()
{
    if (!elf_hdr_bytes.size()) {
        DBGW("No ELF header.");
        return nullptr;
    }

    return (ElfHdr*)elf_hdr_bytes.data();
}

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
ElfPhdr* ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::get_phdr_table()
{

}

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
void ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::add_phdr_segment(char *data, unsigned len, ElfPhdr *phdr)
{

}

/*  The original ELF header is usally located in the first PT_LOAD Segment  */
template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
bool ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::find_original_elf_header(Core &coredump)
{
    int current = 0;
    unsigned num = coredump.get_phnum<ElfHdr>();
    for (int i = 0 ; i < num; i++) {
        auto entry = coredump.get_phdr_at<ElfHdr>(i);
        if (!entry.first && !entry.second) {
            DBGW("Invalid entry in get_phdr_at");
            return false;
        }

        if (entry.first->p_type != PT_LOAD)
            continue;

        if (!Core::check_eident((uint8_t*)entry.second)) {
            if (!list)
                DBGW("Original ELF Header not present in PT_LOAD segment");
            continue;
        }

        DBGI("[%d] Found original ELF Header @ %p, vmaddress %p, offset in core %p", current, entry.second, entry.first->p_vaddr, entry.first->p_offset)
        if (list) {
            current++;
            continue;
        }
        if (current < this->index) {
            current++;
            continue;
        }
        ElfHdr *original_header = (ElfHdr*)entry.second;
        
        // Size of original elf header + Phdr table.
        unsigned total_size = original_header->e_phoff + original_header->e_phnum * original_header->e_phentsize;
        vmaddr_elf_header = entry.first->p_vaddr;

        elf_hdr_bytes.insert(elf_hdr_bytes.begin(), (uint8_t*)entry.second, (uint8_t*)entry.second + total_size);
        return true;
    }

    DBGW("Could not recover original ELF Header");
    return false;
}

/*  
    Recover PT_LOAD segments and save them into a list for further processing.
    Matching original segments with their dump pages in the CORE file.
    NOte: one original segment could result in more consecutive segments in the core file.
    |padding + text1|text2|text3 + padding| - core
    |text1+text2+text3| - original file.
    Always take into consideration the size from the original ELF;
*/

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
bool ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::find_original_segments(Core &coredump)
{
    auto elf_hdr = get_elf_header();
    if (!elf_hdr)
        return false;
    
    unsigned pnum = elf_hdr->e_phnum;
    unsigned num = coredump.get_phnum<ElfHdr>();

    /*  For each original segment we lookup for its dump in the CORE    */
    ElfPhdr *vphdr = ELF_OFFSET_CAST(ElfPhdr, elf_hdr, elf_hdr->e_phoff);
    for (int j = 0; j < pnum; j++) {
        
        if (vphdr[j].p_type != PT_LOAD)
            continue;
        
        int i = 0;
        for (i = 0; i < num; i++) {
            auto entry = coredump.get_phdr_at<ElfHdr>(i);

            if (!entry.first && !entry.second) {
                DBGW("Invalid entry in get_phdr_at");
                return false;
            }

            if (entry.first->p_type != PT_LOAD)
                continue;

            if (!(entry.first->p_vaddr <= vphdr[j].p_vaddr &&
                entry.first->p_memsz + entry.first->p_vaddr > vphdr[j].p_vaddr)) {
                    continue;
                }

            Elf_phdr_chunk<ElfPhdr> chunk;
            chunk.data = (void*)((uint8_t*)entry.second + ((ElfAddr)vphdr[j].p_vaddr - (ElfAddr)entry.first->p_vaddr ));
            chunk.core_hdr = entry.first;
            memcpy(&chunk.original_hdr, &vphdr[j], sizeof(chunk.original_hdr));

            elf_chunks.push_back(chunk);
            DBGI("Saved chunk[%d] vaddr %p, memsize %u, filesize %u, data @ %p", elf_chunks.size() - 1, chunk.original_hdr.p_vaddr,
                                chunk.original_hdr.p_memsz, chunk.original_hdr.p_filesz, chunk.data);
            break;
            
        }
        if (i == num) {
            DBGW("Segment not found in core image");
        }
    }

    if (!elf_chunks.size()) {
        DBGW("No PT_LOAD segments found");
        return false;
    }

    can_assemble = true;
    return true;
}

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
bool ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::add_padding(unsigned long long upper_bound)
{
    auto current_size = elf_buffer.size();
    if (upper_bound < current_size) {
        DBGE("Padding bound is lower than actual size.");
        return false;
    }

    auto n = upper_bound - current_size;
    if (n)
        DBGI("Padding from 0x%x to 0x%x", current_size, upper_bound)
    
    for (int i = 0; i < n; i++) {
        elf_buffer.push_back(0x42); //padding byte
    }

    return true;
}

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
bool ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::assemble_elf()
{
    bool ret;
    if (!can_assemble) {
        DBGW("Cannot assemble ELF");
        return false;
    }

    /*  Append to buffer the segment which starts with the original ELF header  */
    for (int i = 0; i < elf_chunks.size(); i++) {
        if (elf_chunks[i].core_hdr->p_vaddr == vmaddr_elf_header) {
            auto core_phdr = elf_chunks[i].core_hdr;
            auto elf_phdr = elf_chunks[i].original_hdr;
            elf_buffer.insert(elf_buffer.begin(), (uint8_t*)elf_chunks[i].data, (uint8_t*)elf_chunks[i].data + elf_phdr.p_filesz);
            elf_chunks.erase(elf_chunks.begin() + i);
            DBGI("Added segment vmaddr %p, memsz %u filesz %u", elf_phdr.p_vaddr,
                    elf_phdr.p_memsz, elf_phdr.p_filesz);
        }
    }

    if (!elf_buffer.size())
    {
        DBGW("Could not append ELF header to buffer");
        return false;
    }

    DBGI("Added ELF Header section: 0x%x bytes", elf_buffer.size());
    for (int i = 0; i < elf_chunks.size(); i++)
    {
        auto c_chunk = elf_chunks[i];
        ret = add_padding(c_chunk.original_hdr.p_offset);
        if (!ret)
            return false;

        elf_buffer.insert(elf_buffer.end(), (uint8_t*)c_chunk.data, (uint8_t*)c_chunk.data + c_chunk.original_hdr.p_filesz);
        DBGI("Added segment vmaddr %p, memsz %u filesz %u", c_chunk.original_hdr.p_vaddr,
                    c_chunk.original_hdr.p_memsz, c_chunk.original_hdr.p_filesz);
    }
    return true;
}

template <typename ElfHdr, typename ElfPhdr, typename ElfShdr, typename ElfAddr>
bool ElfBuffer<ElfHdr, ElfPhdr, ElfShdr, ElfAddr>::find_original_segments_pie(Core &coredump)
{
    auto elf_hdr = get_elf_header();
    if (!elf_hdr)
        return false;
    
    unsigned pnum = elf_hdr->e_phnum;
    unsigned num = coredump.get_phnum<ElfHdr>();

    /*  For each original segment we lookup for its dump in the CORE    */
    ElfPhdr *vphdr = ELF_OFFSET_CAST(ElfPhdr, elf_hdr, elf_hdr->e_phoff);
    for (int j = 0; j < pnum; j++) {
        
        if (vphdr[j].p_type != PT_LOAD)
            continue;
        
        int i = 0;
        for (i = 0; i < num; i++) {
            auto entry = coredump.get_phdr_at<ElfHdr>(i);

            if (!entry.first && !entry.second) {
                DBGW("Invalid entry in get_phdr_at");
                return false;
            }

            if (entry.first->p_type != PT_LOAD)
                continue;

            if (!(entry.first->p_vaddr <= vphdr[j].p_vaddr + vmaddr_elf_header &&
                entry.first->p_memsz + entry.first->p_vaddr > vphdr[j].p_vaddr + vmaddr_elf_header)) {
                    continue;
                }

            Elf_phdr_chunk<ElfPhdr> chunk;
            chunk.data = (void*)((uint8_t*)entry.second + ((ElfAddr)vphdr[j].p_vaddr - (ElfAddr)entry.first->p_vaddr + vmaddr_elf_header ));
            chunk.core_hdr = entry.first;
            memcpy(&chunk.original_hdr, &vphdr[j], sizeof(chunk.original_hdr));

            elf_chunks.push_back(chunk);
            DBGI("Saved chunk[%d] vaddr %p, memsize %u, filesize %u, data @ %p", elf_chunks.size() - 1, chunk.original_hdr.p_vaddr,
                                chunk.original_hdr.p_memsz, chunk.original_hdr.p_filesz, chunk.data);
            break;
            
        }
        if (i == num) {
            DBGW("Segment not found in core image");
        }
    }

    if (!elf_chunks.size()) {
        DBGW("No PT_LOAD segments found");
        return false;
    }

    can_assemble = true;
    return true;
}

template class ElfBuffer<Elf64_Ehdr>;
template class ElfBuffer<Elf32_Ehdr>;