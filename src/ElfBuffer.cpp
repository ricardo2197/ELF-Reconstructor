#include "ElfBuffer.hpp"
#include "dbgtrace.hpp"
#include "utils.hpp"
#include "Core.hpp"

//TODO rezolva ceva cu void* intors din core si cu pointerii pasati aiurea
//TODO ascunde byte_put la fel ca get
//TODO nu mai plimba mereu pointerii, stocheaza obiectele, ex elf header data

template <typename ElfHdr, typename ElfAddr>
void ElfBuffer<ElfHdr, ElfAddr>::reconstruct_elf(Core &coredump)
{
	bool ret;
	size_t wbytes;

	uint8_t *core = (uint8_t *)(coredump.get_core());
	auto size = coredump.get_size();

	if (!core || !size)
	{
		DBGE("Empty core or invalid size");
		return;
	}

	/*  Recover ELF header of the original image    */
	ret = find_original_elf_header(coredump);
	if (!ret)
	{
		DBGE("Could not find ELF original header in CORE segments");
		return;
	}

	/*  Dump all segments into a list   */
	auto hdr = get_elf_header();
	if (hdr.get_e_type() == ET_DYN)
	{
		DBGI("Executable is PIE");
		is_pie = true;
		ret = find_original_segments_pie(coredump);
	}
	else
		ret = find_original_segments(coredump);

	if (!ret)
	{
		DBGE("Could not find original loadable segments");
		return;
	}

	/*  Assemble segments with headers  */
	ret = assemble_elf();
	if (!ret)
	{
		DBGE("Could not assemble ELF");
		return;
	}

	/*  
     *   Do not return if this function fails
     *   ELF might have no dynamic section.
     */
	ret = patch_binary();
	if (!ret)
	{
		DBGW("Could not patch ELF. Executable might be static");
	}

	FILE *f = fopen(m_config.output.c_str(), "wb");
	if (!f)
	{
		DBGE("Could not open file");
		return;
	}

	wbytes = fwrite(elf_buffer.data(), 1, elf_buffer.size(), f);
	if (wbytes != elf_buffer.size())
	{
		DBGE("Could not write entire ELF to file");
	}

	DBGI("Successfully wrote output file");
	fclose(f);
}

template <typename ElfHdr, typename ElfAddr>
template <typename Type>
void ElfBuffer<ElfHdr, ElfAddr>::modify_address(ElfAddr address, Type value)
{
	ELF::ElfHdrClass<ElfHdr> hdr((ElfHdr *)elf_buffer.data());
	for (int k = 0; k < hdr.get_e_phnum(); k++)
	{
		auto phdr = hdr.get_phdr_at_index(k);

		if (phdr.get_p_type() != PT_LOAD)
			continue;

		if (phdr.get_p_vaddr() <= address && address < phdr.get_p_vaddr() + phdr.get_p_filesz())
		{
			auto dif = address - phdr.get_p_vaddr();
			Type *address_in_elf = ELF_OFFSET_CAST(Type, hdr.get_raw_ptr(), phdr.get_p_offset() + dif);
			DBGI("Patching %p with 0x%x", address, value);
			BYTE_PUT(*address_in_elf, value);
			return;
		}
	}

	DBGE("Failed to find segment for %p", address);
}

template <typename ElfHdr, typename ElfAddr>
template <typename ElfDynamic>
bool ElfBuffer<ElfHdr, ElfAddr>::patch_binary_pie()
{
	ElfDynamic *vdyn = nullptr;
	ELF::ElfHdrClass<ElfHdr> header(elf_buffer.data());

	for (int j = 0;; j++)
	{

		auto dphdr = ELF::ElfDynClass<ElfHdr>(header.get_dynamic_section_at_index(j));

		if (!dphdr.get_raw_ptr()) {
			break;
		}
		
		auto old_value = dphdr.get_d_un_d_ptr();
		if (old_value > base_address)
		{
			DBGI("Patching dynamic section %d, old: %p, new: %p", j, old_value, old_value - base_address);
			auto dyn_ptr = old_value;
			dyn_ptr -= base_address;
			dphdr.set_d_un_d_ptr(dyn_ptr);
			//BYTE_PUT(vdyn[j].d_un.d_ptr, dyn_ptr);
		}
	}
	return true;
}

template <typename ElfHdr, typename ElfAddr>
template <typename ElfDynamic>
bool ElfBuffer<ElfHdr, ElfAddr>::patch_binary()
{
	int index_got;
	int index_plt_relsz;
	int index_relaent;
	int got_entries_nr = 0;
	int debug_index;

	ElfDynamic *vdyn = nullptr;
	ElfHdr *hdr = ELF_CAST(ElfHdr, elf_buffer.data());
	ELF::ElfHdrClass<ElfHdr> header(hdr);

	//header.set_shentsize(0);
	header.set_shnum(0);
	header.set_shoff(0);
	header.set_shstrndx(0);

	// BYTE_PUT(hdr->e_shnum, 0);
	// BYTE_PUT(hdr->e_shoff, 0);
	// BYTE_PUT(hdr->e_shstrndx, 0);

	auto debug_ptr = header.get_dynamic_section(DT_DEBUG);
	ELF::ElfDynClass<ElfHdr> debug_ent(debug_ptr);
	if (debug_ptr)
		debug_ent.set_d_un_d_ptr(0);

	auto got_ptr = header.get_dynamic_section(DT_PLTGOT);
	if (!got_ptr)
	{
		DBGW("Could not find PLTGOT in PT_DYNAMIC")
		return false;
	}

	if (is_pie)
		patch_binary_pie();

	// patching GOT[1], GOT[2]
	ElfAddr got_address = BYTE_GET(((ElfDynamic*)got_ptr)->d_un.d_ptr);
	//modify_address<ElfAddr>(ADDR2ELF(got_address, 1), 0x0);
	//modify_address<ElfAddr>(ADDR2ELF(got_address, 2), 0x0);

	for (auto &p : m_config.patches)
	{
		modify_address<ElfAddr>(ADDR2ELF(p.first, 0), p.second);
	}

	auto plt_relsz_ptr = header.get_dynamic_section(DT_PLTRELSZ);
	if (!plt_relsz_ptr)
	{
		plt_relsz_ptr = header.get_dynamic_section(DT_RELASZ);
		if (!plt_relsz_ptr)
		{
			DBGW("Could not find DT_PLTRELSZ in PT_DYNAMIC");
			return false;
		}
	}

	auto relaent_ptr = header.get_dynamic_section(DT_RELAENT);
	if (!relaent_ptr)
	{
		relaent_ptr = header.get_dynamic_section(DT_RELENT);
		if (!relaent_ptr)
		{
			DBGW("Could not find DT_RELENT in PT_DYNAMIC")
			return false;
		}
	}

	ELF::ElfDynClass<ElfHdr> relsz(plt_relsz_ptr);
	ELF::ElfDynClass<ElfHdr> relaent(relaent_ptr);

	got_entries_nr = relsz.get_d_un_d_ptr() / relaent.get_d_un_d_ptr();
	DBGI("Found %d PLT/GOT entries, GOT %p", got_entries_nr, ADDR2ELF(got_address, 3));
	return true;
}

template <typename ElfHdr, typename ElfAddr>
ELF::ElfHdrClass<ElfHdr> ElfBuffer<ElfHdr, ElfAddr>::get_elf_header()
{
	if (!elf_hdr_bytes.size())
	{
		DBGW("No ELF header.");
		return nullptr;
	}

	return ELF::ElfHdrClass<ElfHdr>((ElfHdr *)elf_hdr_bytes.data());
}

/*  The original ELF header is usally located in the first PT_LOAD Segment  */
template <typename ElfHdr, typename ElfAddr>
bool ElfBuffer<ElfHdr, ElfAddr>::find_original_elf_header(Core &coredump)
{
	int current = 0;
	unsigned num = coredump.get_phnum<ElfHdr>();
	for (uint i = 0; i < num; i++)
	{
		auto entry = coredump.get_phdr_at<ElfHdr>(i);
		if (!entry.first && !entry.second)
		{
			DBGW("Invalid entry in get_phdr_at");
			return false;
		}

		ELF::ElfPHdrClass<ElfHdr> phdr(entry.first);

		if (phdr.get_p_type() != PT_LOAD)
			continue;

		if (!Core::check_eident((uint8_t *)entry.second, false))
		{
			if (!m_config.list)
				DBGW("Original ELF Header not present in PT_LOAD segment");
			continue;
		}

		DBGI("-[%d] Found original ELF Header @ %p, vmaddress %p, offset in core %p", current, entry.second,
			 phdr.get_p_vaddr(), phdr.get_p_offset());

		if (m_config.list)
		{
			current++;
			continue;
		}

		if (current < m_config.elf_index)
		{
			current++;
			continue;
		}

		base_address = phdr.get_p_vaddr();
		ELF::ElfHdrClass<ElfHdr> original_header((ElfHdr *)entry.second);

		// Size of original elf header + Phdr table.
		unsigned total_size = original_header.get_e_phoff() + original_header.get_e_phnum() * original_header.get_e_phentsize();
		vmaddr_elf_header = phdr.get_p_vaddr();

		elf_hdr_bytes.insert(elf_hdr_bytes.begin(), (uint8_t *)original_header.get_raw_ptr(), (uint8_t *)original_header.get_raw_ptr() + total_size);
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

template <typename ElfHdr, typename ElfAddr>
bool ElfBuffer<ElfHdr, ElfAddr>::find_original_segments(Core &coredump)
{
	auto elf_hdr = get_elf_header();
	if (!elf_hdr.get_raw_ptr())
		return false;

	unsigned pnum = elf_hdr.get_e_phnum();
	unsigned num = coredump.get_phnum<ElfHdr>();

	/*  For each original segment we lookup for its dump in the CORE    */
	for (uint j = 0; j < pnum; j++)
	{

		ELF::ElfPHdrClass<ElfHdr> phdr = elf_hdr.get_phdr_at_index(j);
		if (phdr.get_p_type() != PT_LOAD)
			continue;

		uint i = 0;
		for (i = 0; i < num; i++)
		{
			auto entry = coredump.get_phdr_at<ElfHdr>(i);
			if (!entry.first && !entry.second)
			{
				DBGW("Invalid entry in get_phdr_at");
				return false;
			}

			ELF::ElfPHdrClass<ElfHdr> phdr_core(entry.first);
			if (phdr_core.get_p_type() != PT_LOAD)
				continue;

			if (!(phdr_core.get_p_vaddr() <= phdr.get_p_vaddr() &&
				  phdr_core.get_p_memsz() + phdr_core.get_p_vaddr() > phdr.get_p_vaddr()))
			{
				continue;
			}

			Elf_phdr_chunk<ElfHdr> chunk;
			chunk.data = (void *)((uint8_t *)entry.second + (phdr.get_p_vaddr() - phdr_core.get_p_vaddr()));
			chunk.core_hdr = phdr_core;
			chunk.original_hdr = phdr;
			elf_chunks.push_back(chunk);
			DBGI("Saved chunk[%d] vaddr %p, memsize %u, filesize %u, data @ %p", elf_chunks.size() - 1, phdr.get_p_vaddr(),
				 phdr.get_p_memsz(), phdr.get_p_filesz(), chunk.data);
			break;
		}
		if (i == num)
		{
			DBGW("Segment not found in core image");
		}
	}

	if (!elf_chunks.size())
	{
		DBGW("No PT_LOAD segments found");
		return false;
	}

	can_assemble = true;
	return true;
}

template <typename ElfHdr, typename ElfAddr>
bool ElfBuffer<ElfHdr, ElfAddr>::add_padding(unsigned long long upper_bound)
{
	auto current_size = elf_buffer.size();
	if (upper_bound < current_size)
	{
		DBGE("Padding bound is lower than actual size.");
		return false;
	}

	auto n = upper_bound - current_size;
	if (n)
		DBGI("Padding from 0x%x to 0x%x", current_size, upper_bound)

	for (uint i = 0; i < n; i++)
	{
		elf_buffer.push_back(0x0); //padding byte
	}

	return true;
}

template <typename ElfHdr, typename ElfAddr>
bool ElfBuffer<ElfHdr, ElfAddr>::assemble_elf()
{
	bool ret;
	if (!can_assemble)
	{
		DBGW("Cannot assemble ELF");
		return false;
	}

	/*  Append to buffer the segment which starts with the original ELF header  */
	for (uint i = 0; i < elf_chunks.size(); i++)
	{
		if (elf_chunks[i].core_hdr.get_p_vaddr() == vmaddr_elf_header)
		{
			auto elf_phdr = elf_chunks[i].original_hdr;
			elf_buffer.insert(elf_buffer.begin(), (uint8_t *)elf_chunks[i].data, (uint8_t *)elf_chunks[i].data + elf_phdr.get_p_filesz());
			elf_chunks.erase(elf_chunks.begin() + i);
			DBGI("Added segment vmaddr %p, memsz %u filesz %u", elf_phdr.get_p_vaddr(),
				 elf_phdr.get_p_memsz(), elf_phdr.get_p_filesz());
		}
	}

	if (!elf_buffer.size())
	{
		DBGW("Could not append ELF header to buffer");
		return false;
	}

	DBGI("Added ELF Header section: 0x%x bytes", elf_buffer.size());
	for (uint i = 0; i < elf_chunks.size(); i++)
	{
		auto c_chunk = elf_chunks[i];
		ret = add_padding(c_chunk.original_hdr.get_p_offset());
		if (!ret)
			return false;

		elf_buffer.insert(elf_buffer.end(), (uint8_t *)c_chunk.data, (uint8_t *)c_chunk.data + c_chunk.original_hdr.get_p_filesz());
		DBGI("Added segment vmaddr %p, memsz %u filesz %u", c_chunk.original_hdr.get_p_vaddr(),
			 c_chunk.original_hdr.get_p_memsz(), c_chunk.original_hdr.get_p_filesz());
	}
	return true;
}

template <typename ElfHdr, typename ElfAddr>
bool ElfBuffer<ElfHdr, ElfAddr>::find_original_segments_pie(Core &coredump)
{
	auto elf_hdr = get_elf_header();
	if (!elf_hdr.get_raw_ptr())
		return false;

	unsigned pnum = elf_hdr.get_e_phnum();
	unsigned num = coredump.get_phnum<ElfHdr>();

	/*  For each original segment we lookup for its dump in the CORE    */
	//ElfPhdr *vphdr = ELF_OFFSET_CAST(ElfPhdr, elf_hdr, BYTE_GET(elf_hdr->e_phoff));
	for (uint j = 0; j < pnum; j++)
	{

		auto phdr = elf_hdr.get_phdr_at_index(j);
		if (phdr.get_p_type() != PT_LOAD)
			continue;

		uint i = 0;
		for (i = 0; i < num; i++)
		{
			auto entry = coredump.get_phdr_at<ElfHdr>(i);

			if (!entry.first && !entry.second)
			{
				DBGW("Invalid entry in get_phdr_at");
				return false;
			}

			ELF::ElfPHdrClass<ElfHdr> phdr_core(entry.first);

			if (phdr_core.get_p_type() != PT_LOAD)
				continue;

			if (!(phdr_core.get_p_vaddr() <= phdr.get_p_vaddr() + vmaddr_elf_header &&
				  phdr_core.get_p_memsz() + phdr_core.get_p_vaddr() > phdr.get_p_vaddr() + vmaddr_elf_header))
			{
				continue;
			}

			Elf_phdr_chunk<ElfHdr> chunk;
			chunk.data = (void *)((uint8_t *)entry.second + (phdr.get_p_vaddr() + vmaddr_elf_header - phdr_core.get_p_vaddr()));
			chunk.core_hdr = phdr_core;
			chunk.original_hdr = phdr;
			elf_chunks.push_back(chunk);
			DBGI("Saved chunk[%d] vaddr %p, memsize %u, filesize %u, data @ %p", elf_chunks.size() - 1, chunk.original_hdr.get_p_vaddr(),
				 chunk.original_hdr.get_p_memsz(), chunk.original_hdr.get_p_filesz(), chunk.data);

			break;
		}
		if (i == num)
		{
			DBGW("Segment not found in core image");
		}
	}

	if (!elf_chunks.size())
	{
		DBGW("No PT_LOAD segments found");
		return false;
	}

	can_assemble = true;
	return true;
}

template class ElfBuffer<Elf64_Ehdr>;
template class ElfBuffer<Elf32_Ehdr>;