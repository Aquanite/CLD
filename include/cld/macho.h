#ifndef CLD_MACHO_H
#define CLD_MACHO_H

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cld/common.h"

typedef struct {
    char sectname[CLD_NAME_CAPACITY];
    char segname[CLD_NAME_CAPACITY];
    uint32_t input_index;
    uint64_t address;
    uint64_t size;
    uint32_t align;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
    const uint8_t *contents;
    const struct relocation_info *relocations;
    uint32_t relocation_count;
} CldInputSection;

typedef struct {
    struct nlist_64 raw;
    const char *name;
} CldInputSymbol;

typedef struct {
    char *path;
    uint8_t *data;
    size_t size;
    uint32_t header_flags;
    bool has_build_version;
    struct build_version_command build_version;
    size_t section_count;
    CldInputSection *sections;
    size_t symbol_count;
    CldInputSymbol *symbols;
} CldMachOObject;

bool cld_parse_macho_object(const char *path, CldMachOObject *object_file, CldError *error);
void cld_free_macho_object(CldMachOObject *object_file);

#endif
