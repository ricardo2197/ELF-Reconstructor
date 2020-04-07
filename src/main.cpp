#include <iostream>
#include <getopt.h>
#include "dbgtrace.hpp"
#include "utils.hpp"
#include "Core.hpp"
#include "ElfBuffer.hpp"
#include "ElfConfig.hpp"
        
void parse_arguments(ElfConfig &config, int argc, char **argv)
{
    int list = 0;
    int c;
    int option_index = 0;

    config.elf_index = 0;
    config.list = false;
    config.output = "elf.out";
    config.patch_file = "";

    static struct option long_options[] =
    {
        {"list",    no_argument,       &list, 'l'},
        {"number",  required_argument, 0, 'n'},
        {"patch",   required_argument, 0, 'p'},
        {"output",  required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };

    while (1)
    {
        option_index = 0;
        c = getopt_long (argc, argv, "ln:p:o:",
                       long_options, &option_index);

      if (c == -1)
        break;

      switch (c)
        {
        case 0:
            break;
        case 'n':
            config.elf_index = atoi(optarg);
            break;

        case 'p':
            config.patch_file = optarg;
            break;

        case 'o':
            config.output = optarg;
            break;

        case '?':
            break;

        case 'l':
            list = 1;
            break;
        default:
            ;
        }
    }

    config.list = list ? true : false;
}


void read_patch_file(std::vector<std::pair<uint64_t, uint64_t> > &vec, const ElfConfig &config)
{
    if (config.patch_file.empty())
        return;

    FILE *f = fopen(config.patch_file.c_str(), "r");
    char line[128] = {0};
    int size = 128;
    uint64_t address = 0;
    uint64_t value = 0;

    if (!f)
        return;
    
    while (fgets(line, size, f))
    {
        if (line[0] == '\n')
            break;
        sscanf(line, "%p %p", &address, &value);
        vec.push_back(std::make_pair(address, value));
    }
}

void print_usage(char **argv)
{
    std::cerr << "Usage: " << argv[0] << " core_file [OPTIONS]" << std::endl;
    std::cerr << "Available options:\n" 
    "   -l, --list              List ELF Headers found in dump\n"
    "   -n, --number=N          Reconstruct Nth ELF listed in with --list\n"
    "   -o, --output=FILE       Output file name. Default is elf.out\n";
}

int main(int argc, char **argv) 
{
    bool retVal;
    std::string input_file;

    if (argc < 2) {
        print_usage(argv);
        exit(ERRNO_ARGUMENTS);
    }

    input_file = argv[1];
    ElfConfig config;
    parse_arguments(config, argc, argv);

    PatchVector patches;
    read_patch_file(patches, config);
    config.patches = patches;

    DBGI("ELF path: %s", input_file.c_str());
    Core p;
    retVal = p.load_core(input_file.c_str());

    if (!retVal)
        return ERRNO_INVALIDELF;  
    
    DBGI("ELF Core is valid");
    
    if (p.elf_class == ELFCLASS32) {
        ElfBuffer<Elf32_Ehdr> original_elf(config);
        original_elf.reconstruct_elf(p);
    } else if (p.elf_class == ELFCLASS64) {
        ElfBuffer<Elf64_Ehdr> original_elf(config);
        original_elf.reconstruct_elf(p);
    } else {
        DBGW("Unsupported ELFCLASS");
    }
    
    return 0;
}
