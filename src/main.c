/**==============================================
 *                 main.c
 *  main code of the epiCompiler
 *  Author: shirosaaki
 *  Date: 2025-11-20
 *=============================================**/

#include "../includes/epi_compiler.h"

int main(int ac, char **av)
{
    if (ac != 3) {
        fprintf(stderr, "Usage: %s <source_file> <output_file>\n", av[0]);
        return EXIT_FAILURE;
    }

    const char *source_file = av[1];
    printf("Compiling source file: %s\n", source_file);

    const char *output_file = av[2];
    printf("Output file: %s\n", output_file);

    // Compilation logic would go here
    create_elf_header(output_file);
    printf("Compilation finished successfully.\n");
    return EXIT_SUCCESS;
}
