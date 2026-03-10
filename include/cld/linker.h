#ifndef CLD_LINKER_H
#define CLD_LINKER_H

#include <stddef.h>
#include <stdint.h>

#include "cld/common.h"
#include "cld/macho.h"
#include "cld/target.h"

typedef enum {
    CLD_OUTPUT_KIND_RELOCATABLE,
    CLD_OUTPUT_KIND_EXECUTABLE,
} CldOutputKind;

typedef struct {
    const CldTarget *target;
    const char *output_path;
    const char *entry_symbol;
    uint64_t stack_size;
    bool no_stdlib;
    CldOutputKind output_kind;
} CldLinkOptions;

bool cld_link_objects(const CldMachOObject *object_files, size_t object_count, const CldLinkOptions *options, CldError *error);

#endif
