#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <elf.h>

#define DEBUG 1

#define debug(...) \
            do { if (DEBUG) printf("<debug>:"__VA_ARGS__); } while (0)

void disassemble(int32_t fd, Elf32_Ehdr eh, Elf32_Shdr* sh_tbl);
void read_elf_header(int32_t fd, Elf32_Ehdr *elf_header);
void read_section_header_table(int32_t fd, Elf32_Ehdr eh, Elf32_Shdr sh_table[]);
char* read_section(int32_t fd, Elf32_Shdr sh);
void print_elf_header(Elf32_Ehdr elf_header);
