#ifndef ELF_CONFIG_H
#define ELF_CONFIG_H

#include <vector>
#include <string>

using PatchVector = std::vector<std::pair<uint64_t, uint64_t> >;

class ElfConfig {
public:
    bool list = false;
    int elf_index = 0;
    PatchVector patches;
    std::string output;
    std::string patch_file;
};

#endif