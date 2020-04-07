#include <iostream>
#include "dbgtrace.hpp"
#include "utils.hpp"
#include "Core.hpp"
#include "ElfBuffer.hpp"
int main(int argc, char **argv) 
{
    bool retVal;
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " core_file" << std::endl;
        exit(ERRNO_ARGUMENTS);
    }

    bool list = argc > 2 ? std::string(argv[2]) == "list" : false;
    int number = argc > 2 ? atoi(argv[2]) : 0;
    
    DBGI("ELF path: %s", argv[1]);
    Core p;
    retVal = p.load_core(argv[1]);
    if (!retVal)
        return ERRNO_INVALIDELF;
    
    DBGI("ELF Core is valid");

    ElfBuffer<Elf64_Ehdr> original_elf(list, number);
    original_elf.reconstruct_elf(p);
    return 0;
}