/**==============================================
 *                 create_elf_header.c
 *  file where the function to write an elf header is
 *  Author: *
 *  Date: 2025-11-20
 *=============================================**/

#include "../includes/elf_header.h"

int create_elf_header(const char *filename)
{
    FILE *file = fopen(filename, "w+b");
    if (!file) {
        perror("Failed to open file for writing ELF header");
        return -1;
    }

    Elf64_Ehdr elf_header;
    memset(&elf_header, 0, sizeof(Elf64_Ehdr));
    elf_header.e_ident[EI_MAG0] = ELFMAG0;
    elf_header.e_ident[EI_MAG1] = ELFMAG1;
    elf_header.e_ident[EI_MAG2] = ELFMAG2;
    elf_header.e_ident[EI_MAG3] = ELFMAG3;
    elf_header.e_ident[EI_CLASS] = ELFCLASS64;
    elf_header.e_ident[EI_DATA] = ELFDATA2LSB;
    elf_header.e_ident[EI_VERSION] = EV_CURRENT;
    elf_header.e_type = ET_EXEC;
    elf_header.e_machine = EM_X86_64;
    elf_header.e_version = EV_CURRENT;
    elf_header.e_entry = 0x400000; // Entry point address
    elf_header.e_phoff = sizeof(Elf64_Ehdr); // Program header table offset
    elf_header.e_ehsize = sizeof(Elf64_Ehdr);
    elf_header.e_phentsize = sizeof(Elf64_Phdr);
    elf_header.e_phnum = 1; // Number of program headers
    fwrite(&elf_header, 1, sizeof(Elf64_Ehdr), file);

    fclose(file);
    return 0;
}
