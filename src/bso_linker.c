#include "cld/linker.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
    char magic[4];
    uint32_t version;
    uint32_t code_size;
    uint32_t symbol_count;
    uint32_t relocation_count;
    uint32_t string_table_size;
} CldBsoHeader;

typedef struct {
    uint32_t name_offset;
    uint32_t value;
    uint32_t flags;
} CldBsoSymbolRecord;

typedef struct {
    uint32_t offset;
    int32_t addend;
    uint32_t symbol_index;
    uint32_t kind;
} CldBsoRelocationRecord;

typedef struct {
    const CldBsoObject *input;
    uint32_t base_offset;
    size_t *symbol_map;
} CldBsoObjectState;

typedef struct {
    const char *name;
    const char *source_path;
    uint32_t value;
    uint32_t flags;
    bool is_defined;
} CldBsoResolvedSymbol;

const CldTarget cld_target_bslash = {
    .name = "bslash",
    .object_format = CLD_OBJECT_FORMAT_BSO,
    .host_native = false,
    .cpu_type = 0,
    .cpu_subtype = 0,
    .platform = 0,
    .minos = 0,
    .sdk = 0,
    .page_size = 1,
    .image_base = 0,
    .page_zero_size = 0,
    .default_stack_size = 0,
    .stack_top = 0,
};

static size_t cld_bso_find_symbol_index(const CldBsoResolvedSymbol *symbols,
                                        size_t symbol_count,
                                        const char *name) {
    size_t symbol_index;

    for (symbol_index = 0; symbol_index < symbol_count; ++symbol_index) {
        if (strcmp(symbols[symbol_index].name, name) == 0) {
            return symbol_index;
        }
    }

    return SIZE_MAX;
}

static bool cld_bso_range_is_valid(size_t size, uint32_t offset, uint32_t width) {
    return offset <= size && width <= size - offset;
}

static void cld_bso_write_u64(uint8_t *data, uint32_t width, uint64_t value) {
    uint32_t byte_index;

    for (byte_index = 0; byte_index < width; ++byte_index) {
        data[byte_index] = (uint8_t) ((value >> (byte_index * 8u)) & 0xffu);
    }
}

static bool cld_bso_relocation_width(uint32_t kind, uint32_t *width, bool *relative, CldError *error) {
    switch (kind) {
        case CLD_BSO_RELOC_ABS8:
            *width = 1;
            *relative = false;
            return true;
        case CLD_BSO_RELOC_ABS16:
            *width = 2;
            *relative = false;
            return true;
        case CLD_BSO_RELOC_ABS32:
            *width = 4;
            *relative = false;
            return true;
        case CLD_BSO_RELOC_ABS64:
            *width = 8;
            *relative = false;
            return true;
        case CLD_BSO_RELOC_REL8:
            *width = 1;
            *relative = true;
            return true;
        case CLD_BSO_RELOC_REL32:
            *width = 4;
            *relative = true;
            return true;
        default:
            cld_set_error(error, "unsupported BSO relocation kind %u", kind);
            return false;
    }
}

static bool cld_bso_add_resolved_symbol(CldBsoResolvedSymbol **symbols,
                                        size_t *symbol_count,
                                        size_t *symbol_capacity,
                                        const CldBsoSymbol *input_symbol,
                                        uint32_t adjusted_value,
                                        const char *source_path,
                                        size_t *output_index,
                                        CldError *error) {
    CldBsoResolvedSymbol *grown;
    size_t symbol_index;
    bool is_defined;

    symbol_index = cld_bso_find_symbol_index(*symbols, *symbol_count, input_symbol->name);
    is_defined = (input_symbol->flags & CLD_BSO_SYMBOL_DEFINED) != 0;
    if (symbol_index != SIZE_MAX) {
        if ((*symbols)[symbol_index].is_defined && is_defined) {
            cld_set_error(error,
                          "multiple definitions of symbol %s in %s and %s",
                          input_symbol->name,
                          (*symbols)[symbol_index].source_path,
                          source_path);
            return false;
        }
        (*symbols)[symbol_index].flags |= input_symbol->flags;
        if (is_defined) {
            (*symbols)[symbol_index].is_defined = true;
            (*symbols)[symbol_index].value = adjusted_value;
            (*symbols)[symbol_index].source_path = source_path;
        }
        *output_index = symbol_index;
        return true;
    }

    if (*symbol_count == *symbol_capacity) {
        size_t new_capacity;

        new_capacity = *symbol_capacity == 0 ? 16 : *symbol_capacity * 2;
        grown = realloc(*symbols, new_capacity * sizeof(**symbols));
        if (grown == NULL) {
            cld_set_error(error, "out of memory growing BSO symbol table");
            return false;
        }
        *symbols = grown;
        *symbol_capacity = new_capacity;
    }

    (*symbols)[*symbol_count].name = input_symbol->name;
    (*symbols)[*symbol_count].source_path = source_path;
    (*symbols)[*symbol_count].value = is_defined ? adjusted_value : 0;
    (*symbols)[*symbol_count].flags = input_symbol->flags;
    (*symbols)[*symbol_count].is_defined = is_defined;
    *output_index = *symbol_count;
    *symbol_count += 1;
    return true;
}

static bool cld_bso_collect_objects(const CldBsoObject *object_files,
                                    size_t object_count,
                                    CldBsoObjectState **object_states_out,
                                    CldBsoResolvedSymbol **symbols_out,
                                    size_t *symbol_count_out,
                                    uint8_t **contents_out,
                                    size_t *contents_size_out,
                                    CldError *error) {
    CldBsoObjectState *object_states;
    CldBsoResolvedSymbol *symbols;
    size_t symbol_count;
    size_t symbol_capacity;
    uint8_t *contents;
    size_t contents_size;
    size_t object_index;

    object_states = calloc(object_count, sizeof(*object_states));
    symbols = NULL;
    symbol_count = 0;
    symbol_capacity = 0;
    contents = NULL;
    contents_size = 0;

    if (object_states == NULL) {
        cld_set_error(error, "out of memory allocating BSO object state");
        return false;
    }

    for (object_index = 0; object_index < object_count; ++object_index) {
        const CldBsoObject *object_file;
        size_t input_symbol_index;

        object_file = &object_files[object_index];
        if (contents_size > SIZE_MAX - object_file->code_size) {
            cld_set_error(error, "BSO output exceeds addressable size");
            goto failure;
        }
        if ((uint64_t) contents_size + object_file->code_size > UINT32_MAX) {
            cld_set_error(error, "BSO output exceeds 32-bit address space");
            goto failure;
        }

        object_states[object_index].input = object_file;
        object_states[object_index].base_offset = (uint32_t) contents_size;
        object_states[object_index].symbol_map = calloc(object_file->symbol_count,
                                                        sizeof(*object_states[object_index].symbol_map));
        if (object_file->symbol_count != 0 && object_states[object_index].symbol_map == NULL) {
            cld_set_error(error, "out of memory allocating BSO symbol map");
            goto failure;
        }

        if (object_file->code_size != 0) {
            uint8_t *grown;

            grown = realloc(contents, contents_size + object_file->code_size);
            if (grown == NULL) {
                cld_set_error(error, "out of memory growing BSO output image");
                goto failure;
            }
            contents = grown;
            memcpy(contents + contents_size, object_file->code, object_file->code_size);
            contents_size += object_file->code_size;
        }

        for (input_symbol_index = 0; input_symbol_index < object_file->symbol_count; ++input_symbol_index) {
            size_t output_symbol_index;
            uint32_t adjusted_value;

            adjusted_value = object_states[object_index].base_offset + object_file->symbols[input_symbol_index].value;
            if (!cld_bso_add_resolved_symbol(&symbols,
                                             &symbol_count,
                                             &symbol_capacity,
                                             &object_file->symbols[input_symbol_index],
                                             adjusted_value,
                                             object_file->path,
                                             &output_symbol_index,
                                             error)) {
                goto failure;
            }
            object_states[object_index].symbol_map[input_symbol_index] = output_symbol_index;
        }
    }

    *object_states_out = object_states;
    *symbols_out = symbols;
    *symbol_count_out = symbol_count;
    *contents_out = contents;
    *contents_size_out = contents_size;
    return true;

failure:
    if (object_states != NULL) {
        for (object_index = 0; object_index < object_count; ++object_index) {
            free(object_states[object_index].symbol_map);
        }
    }
    free(contents);
    free(symbols);
    free(object_states);
    return false;
}

static bool cld_bso_emit_object(const char *output_path,
                                const uint8_t *contents,
                                size_t contents_size,
                                const CldBsoResolvedSymbol *symbols,
                                size_t symbol_count,
                                const CldBsoRelocationRecord *relocations,
                                size_t relocation_count,
                                CldError *error) {
    uint8_t *symbol_bytes;
    uint8_t *string_bytes;
    size_t symbol_bytes_size;
    size_t string_size;
    size_t string_capacity;
    uint8_t *output_bytes;
    size_t output_size;
    size_t symbol_index;
    size_t relocation_bytes_size;
    CldBsoHeader header;

    symbol_bytes = NULL;
    string_bytes = NULL;
    output_bytes = NULL;
    string_size = 0;
    string_capacity = 0;
    symbol_bytes_size = symbol_count * sizeof(CldBsoSymbolRecord);
    relocation_bytes_size = relocation_count * sizeof(CldBsoRelocationRecord);

    if (!cld_append_bytes(&string_bytes, &string_size, &string_capacity, "", 1, error)) {
        goto failure;
    }

    if (symbol_bytes_size != 0) {
        symbol_bytes = calloc(symbol_count, sizeof(CldBsoSymbolRecord));
        if (symbol_bytes == NULL) {
            cld_set_error(error, "out of memory allocating BSO symbol output");
            goto failure;
        }
    }

    for (symbol_index = 0; symbol_index < symbol_count; ++symbol_index) {
        CldBsoSymbolRecord record;

        memset(&record, 0, sizeof(record));
        record.name_offset = (uint32_t) string_size;
        record.value = symbols[symbol_index].is_defined ? symbols[symbol_index].value : 0;
        record.flags = symbols[symbol_index].flags | CLD_BSO_SYMBOL_GLOBAL;
        if (symbols[symbol_index].is_defined) {
            record.flags |= CLD_BSO_SYMBOL_DEFINED;
        } else {
            record.flags &= ~CLD_BSO_SYMBOL_DEFINED;
        }

        if (!cld_append_bytes(&string_bytes,
                              &string_size,
                              &string_capacity,
                              symbols[symbol_index].name,
                              strlen(symbols[symbol_index].name) + 1,
                              error)) {
            goto failure;
        }

        memcpy(symbol_bytes + symbol_index * sizeof(record), &record, sizeof(record));
    }

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, "BSO1", 4);
    header.version = 1;
    header.code_size = (uint32_t) contents_size;
    header.symbol_count = (uint32_t) symbol_count;
    header.relocation_count = (uint32_t) relocation_count;
    header.string_table_size = (uint32_t) string_size;

    output_size = sizeof(header) + contents_size + symbol_bytes_size + relocation_bytes_size + string_size;
    output_bytes = malloc(output_size);
    if (output_bytes == NULL) {
        cld_set_error(error, "out of memory allocating BSO output file");
        goto failure;
    }

    memcpy(output_bytes, &header, sizeof(header));
    if (contents_size != 0) {
        memcpy(output_bytes + sizeof(header), contents, contents_size);
    }
    if (symbol_bytes_size != 0) {
        memcpy(output_bytes + sizeof(header) + contents_size, symbol_bytes, symbol_bytes_size);
    }
    if (relocation_bytes_size != 0) {
        memcpy(output_bytes + sizeof(header) + contents_size + symbol_bytes_size,
               relocations,
               relocation_bytes_size);
    }
    memcpy(output_bytes + sizeof(header) + contents_size + symbol_bytes_size + relocation_bytes_size,
           string_bytes,
           string_size);

    if (!cld_write_entire_file(output_path, output_bytes, output_size, error)) {
        goto failure;
    }
    if (chmod(output_path, 0644) != 0) {
        cld_set_error(error, "wrote BSO output but chmod failed for %s", output_path);
        goto failure;
    }

    free(output_bytes);
    free(string_bytes);
    free(symbol_bytes);
    return true;

failure:
    free(output_bytes);
    free(string_bytes);
    free(symbol_bytes);
    return false;
}

static bool cld_bso_emit_relocatable(const CldBsoObject *object_files,
                                     size_t object_count,
                                     const CldLinkOptions *options,
                                     CldError *error) {
    CldBsoObjectState *object_states;
    CldBsoResolvedSymbol *symbols;
    size_t symbol_count;
    uint8_t *contents;
    size_t contents_size;
    CldBsoRelocationRecord *relocations;
    size_t relocation_count;
    size_t relocation_capacity;
    size_t object_index;
    bool success;

    object_states = NULL;
    symbols = NULL;
    symbol_count = 0;
    contents = NULL;
    contents_size = 0;
    relocations = NULL;
    relocation_count = 0;
    relocation_capacity = 0;
    success = false;

    if (!cld_bso_collect_objects(object_files,
                                 object_count,
                                 &object_states,
                                 &symbols,
                                 &symbol_count,
                                 &contents,
                                 &contents_size,
                                 error)) {
        goto cleanup;
    }

    for (object_index = 0; object_index < object_count; ++object_index) {
        const CldBsoObject *object_file;
        size_t input_relocation_index;

        object_file = &object_files[object_index];
        for (input_relocation_index = 0; input_relocation_index < object_file->relocation_count; ++input_relocation_index) {
            CldBsoRelocationRecord record;
            size_t output_symbol_index;
            uint32_t width;
            bool relative;

            if (!cld_bso_relocation_width(object_file->relocations[input_relocation_index].kind,
                                          &width,
                                          &relative,
                                          error)) {
                goto cleanup;
            }
            (void) relative;
            if (!cld_bso_range_is_valid(object_file->code_size,
                                        object_file->relocations[input_relocation_index].offset,
                                        width)) {
                cld_set_error(error,
                              "relocation offset %u is outside %s",
                              object_file->relocations[input_relocation_index].offset,
                              object_file->path);
                goto cleanup;
            }

            if (relocation_count == relocation_capacity) {
                size_t new_capacity;
                CldBsoRelocationRecord *grown;

                new_capacity = relocation_capacity == 0 ? 16 : relocation_capacity * 2;
                grown = realloc(relocations, new_capacity * sizeof(*relocations));
                if (grown == NULL) {
                    cld_set_error(error, "out of memory growing BSO relocation output");
                    goto cleanup;
                }
                relocations = grown;
                relocation_capacity = new_capacity;
            }

            output_symbol_index = object_states[object_index].symbol_map[object_file->relocations[input_relocation_index].symbol_index];
            record.offset = object_states[object_index].base_offset + object_file->relocations[input_relocation_index].offset;
            record.addend = object_file->relocations[input_relocation_index].addend;
            record.symbol_index = (uint32_t) output_symbol_index;
            record.kind = object_file->relocations[input_relocation_index].kind;
            relocations[relocation_count++] = record;
        }
    }

    if (!cld_bso_emit_object(options->output_path,
                             contents,
                             contents_size,
                             symbols,
                             symbol_count,
                             relocations,
                             relocation_count,
                             error)) {
        goto cleanup;
    }

    success = true;

cleanup:
    if (object_states != NULL) {
        for (object_index = 0; object_index < object_count; ++object_index) {
            free(object_states[object_index].symbol_map);
        }
    }
    free(relocations);
    free(contents);
    free(symbols);
    free(object_states);
    return success;
}

static bool cld_bso_apply_relocations(uint8_t *contents,
                                      size_t contents_size,
                                      const CldBsoObjectState *object_states,
                                      size_t object_count,
                                      const CldBsoResolvedSymbol *symbols,
                                      CldError *error) {
    size_t object_index;

    for (object_index = 0; object_index < object_count; ++object_index) {
        const CldBsoObject *object_file;
        size_t relocation_index;

        object_file = object_states[object_index].input;
        for (relocation_index = 0; relocation_index < object_file->relocation_count; ++relocation_index) {
            const CldBsoRelocation *relocation;
            const CldBsoResolvedSymbol *symbol;
            uint32_t width;
            bool relative;
            uint32_t output_offset;
            int64_t value;

            relocation = &object_file->relocations[relocation_index];
            if (!cld_bso_relocation_width(relocation->kind, &width, &relative, error)) {
                return false;
            }

            output_offset = object_states[object_index].base_offset + relocation->offset;
            if (!cld_bso_range_is_valid(contents_size, output_offset, width)) {
                cld_set_error(error,
                              "relocation offset %u is outside the linked BSO image",
                              output_offset);
                return false;
            }

            symbol = &symbols[object_states[object_index].symbol_map[relocation->symbol_index]];
            if (!symbol->is_defined) {
                cld_set_error(error, "undefined symbol %s", symbol->name);
                return false;
            }

            value = (int64_t) symbol->value + relocation->addend;
            if (relative) {
                if (width == 1) {
                    if (value < INT8_MIN || value > INT8_MAX) {
                        cld_set_error(error, "relative 8-bit relocation for %s is out of range", symbol->name);
                        return false;
                    }
                    contents[output_offset] = (uint8_t) (int8_t) value;
                } else if (width == 4) {
                    if (value < INT32_MIN || value > INT32_MAX) {
                        cld_set_error(error, "relative 32-bit relocation for %s is out of range", symbol->name);
                        return false;
                    }
                    cld_bso_write_u64(contents + output_offset, width, (uint32_t) (int32_t) value);
                } else {
                    cld_set_error(error, "unsupported relative relocation width %u", width);
                    return false;
                }
                continue;
            }

            if (value < 0) {
                cld_set_error(error, "absolute relocation for %s resolved to a negative value", symbol->name);
                return false;
            }

            switch (width) {
                case 1:
                    if ((uint64_t) value > UINT8_MAX) {
                        cld_set_error(error, "absolute 8-bit relocation for %s is out of range", symbol->name);
                        return false;
                    }
                    contents[output_offset] = (uint8_t) value;
                    break;
                case 2:
                    if ((uint64_t) value > UINT16_MAX) {
                        cld_set_error(error, "absolute 16-bit relocation for %s is out of range", symbol->name);
                        return false;
                    }
                    cld_bso_write_u64(contents + output_offset, width, (uint16_t) value);
                    break;
                case 4:
                    if ((uint64_t) value > UINT32_MAX) {
                        cld_set_error(error, "absolute 32-bit relocation for %s is out of range", symbol->name);
                        return false;
                    }
                    cld_bso_write_u64(contents + output_offset, width, (uint32_t) value);
                    break;
                case 8:
                    cld_bso_write_u64(contents + output_offset, width, (uint64_t) value);
                    break;
                default:
                    cld_set_error(error, "unsupported absolute relocation width %u", width);
                    return false;
            }
        }
    }

    return true;
}

static bool cld_bso_emit_executable(const CldBsoObject *object_files,
                                    size_t object_count,
                                    const CldLinkOptions *options,
                                    CldError *error) {
    CldBsoObjectState *object_states;
    CldBsoResolvedSymbol *symbols;
    size_t symbol_count;
    uint8_t *contents;
    size_t contents_size;
    size_t object_index;
    bool success;

    object_states = NULL;
    symbols = NULL;
    symbol_count = 0;
    contents = NULL;
    contents_size = 0;
    success = false;

    if (!cld_bso_collect_objects(object_files,
                                 object_count,
                                 &object_states,
                                 &symbols,
                                 &symbol_count,
                                 &contents,
                                 &contents_size,
                                 error)) {
        goto cleanup;
    }

    for (object_index = 0; object_index < symbol_count; ++object_index) {
        if ((symbols[object_index].flags & CLD_BSO_SYMBOL_GLOBAL) == 0) {
            continue;
        }
        if (!symbols[object_index].is_defined) {
            cld_set_error(error, "undefined symbol %s", symbols[object_index].name);
            goto cleanup;
        }
    }

    if (!cld_bso_apply_relocations(contents,
                                   contents_size,
                                   object_states,
                                   object_count,
                                   symbols,
                                   error)) {
        goto cleanup;
    }

    if (!cld_write_entire_file(options->output_path, contents, contents_size, error)) {
        goto cleanup;
    }
    if (chmod(options->output_path, 0644) != 0) {
        cld_set_error(error, "wrote raw BSlash binary but chmod failed for %s", options->output_path);
        goto cleanup;
    }

    success = true;

cleanup:
    if (object_states != NULL) {
        for (object_index = 0; object_index < object_count; ++object_index) {
            free(object_states[object_index].symbol_map);
        }
    }
    free(contents);
    free(symbols);
    free(object_states);
    return success;
}

bool cld_link_bso_objects(const CldBsoObject *object_files,
                          size_t object_count,
                          const CldLinkOptions *options,
                          CldError *error) {
    if (object_count == 0) {
        cld_set_error(error, "no input objects were provided");
        return false;
    }
    if (options->target == NULL) {
        cld_set_error(error, "no target was selected");
        return false;
    }
    if (options->target->object_format != CLD_OBJECT_FORMAT_BSO) {
        cld_set_error(error, "BSO inputs require the bslash target");
        return false;
    }

    if (options->output_kind == CLD_OUTPUT_KIND_RELOCATABLE) {
        return cld_bso_emit_relocatable(object_files, object_count, options, error);
    }
    if (options->output_kind == CLD_OUTPUT_KIND_EXECUTABLE) {
        return cld_bso_emit_executable(object_files, object_count, options, error);
    }

    cld_set_error(error, "unsupported output kind");
    return false;
}
