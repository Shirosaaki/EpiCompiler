/**==============================================
 *                 elf_header.h
 *  elf header header
 *  Author: shirosaaki
 *  Date: 2025-11-20
 *=============================================**/

#ifndef ELF_HEADER_H_
    #define ELF_HEADER_H_
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <stdarg.h>
    #include <elf.h>

int create_elf_header(const char *filename);

#endif /* !ELF_HEADER_H_ */
