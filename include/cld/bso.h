#ifndef CLD_BSO_H
#define CLD_BSO_H

#include <stddef.h>
#include <stdint.h>

#include "cld/common.h"

typedef enum {
    CLD_BSO_RELOC_ABS8 = 1,
    CLD_BSO_RELOC_ABS16 = 2,
    CLD_BSO_RELOC_ABS32 = 3,
    CLD_BSO_RELOC_ABS64 = 4,
    CLD_BSO_RELOC_REL8 = 5,
    CLD_BSO_RELOC_REL32 = 6,
} CldBsoRelocationKind;

typedef struct {
    uint32_t name_offset;
    uint32_t value;
    uint32_t flags;
    const char *name;
} CldBsoSymbol;

#define CLD_BSO_SYMBOL_DEFINED (1u << 0)
#define CLD_BSO_SYMBOL_GLOBAL  (1u << 1)

typedef struct {
    uint32_t offset;
    int32_t addend;
    uint32_t symbol_index;
    uint32_t kind;
} CldBsoRelocation;

typedef struct {
    char *path;
    uint8_t *data;
    size_t size;
    char *owned_string_table;
    const uint8_t *code;
    uint32_t code_size;
    const char *string_table;
    uint32_t string_table_size;
    size_t symbol_count;
    CldBsoSymbol *symbols;
    size_t relocation_count;
    CldBsoRelocation *relocations;
} CldBsoObject;

bool cld_parse_bso_object(const char *path, CldBsoObject *object_file, CldError *error);
bool cld_parse_bslash_object(const char *path, CldBsoObject *object_file, CldError *error);
void cld_free_bso_object(CldBsoObject *object_file);

#endif
