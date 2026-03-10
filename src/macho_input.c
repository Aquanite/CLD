#include "cld/macho.h"

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/machine.h>
#include <stdlib.h>
#include <string.h>

static bool cld_range_is_valid(size_t file_size, uint64_t offset, uint64_t length) {
    if (offset > file_size) {
        return false;
    }
    if (length > (uint64_t) file_size - offset) {
        return false;
    }
    return true;
}

static void cld_copy_fixed_name(char destination[CLD_NAME_CAPACITY], const char source[16]) {
    memcpy(destination, source, 16);
    destination[16] = '\0';
}

bool cld_parse_macho_object(const char *path, CldMachOObject *object_file, CldError *error) {
    const uint8_t *cursor;
    const struct mach_header_64 *header;
    const struct symtab_command *symtab_command;
    uint32_t command_index;
    size_t section_index;
    size_t symbol_index;

    memset(object_file, 0, sizeof(*object_file));

    if (!cld_read_entire_file(path, &object_file->data, &object_file->size, error)) {
        return false;
    }

    object_file->path = strdup(path);
    if (object_file->path == NULL) {
        cld_set_error(error, "out of memory duplicating path");
        cld_free_macho_object(object_file);
        return false;
    }

    if (object_file->size < sizeof(*header)) {
        cld_set_error(error, "%s is too small to be a Mach-O file", path);
        cld_free_macho_object(object_file);
        return false;
    }

    header = (const struct mach_header_64 *) object_file->data;
    if (header->magic != MH_MAGIC_64) {
        cld_set_error(error, "%s is not a 64-bit Mach-O file", path);
        cld_free_macho_object(object_file);
        return false;
    }

    if (header->filetype != MH_OBJECT) {
        cld_set_error(error, "%s is not a relocatable Mach-O object", path);
        cld_free_macho_object(object_file);
        return false;
    }

    if (header->cputype != CPU_TYPE_ARM64) {
        cld_set_error(error, "%s is not an arm64 object file", path);
        cld_free_macho_object(object_file);
        return false;
    }

    object_file->header_flags = header->flags;

    if (!cld_range_is_valid(object_file->size, sizeof(*header), header->sizeofcmds)) {
        cld_set_error(error, "%s has truncated load commands", path);
        cld_free_macho_object(object_file);
        return false;
    }

    cursor = object_file->data + sizeof(*header);
    symtab_command = NULL;
    object_file->section_count = 0;

    for (command_index = 0; command_index < header->ncmds; ++command_index) {
        const struct load_command *command;

        if (!cld_range_is_valid(object_file->size, (uint64_t) (cursor - object_file->data), sizeof(*command))) {
            cld_set_error(error, "%s has an incomplete load command", path);
            cld_free_macho_object(object_file);
            return false;
        }

        command = (const struct load_command *) cursor;
        if (command->cmdsize < sizeof(*command) || !cld_range_is_valid(object_file->size, (uint64_t) (cursor - object_file->data), command->cmdsize)) {
            cld_set_error(error, "%s has an invalid load command size", path);
            cld_free_macho_object(object_file);
            return false;
        }

        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment_command;

            segment_command = (const struct segment_command_64 *) cursor;
            if (command->cmdsize < sizeof(*segment_command) + segment_command->nsects * sizeof(struct section_64)) {
                cld_set_error(error, "%s has a truncated segment command", path);
                cld_free_macho_object(object_file);
                return false;
            }
            object_file->section_count += segment_command->nsects;
        } else if (command->cmd == LC_SYMTAB) {
            symtab_command = (const struct symtab_command *) cursor;
        } else if (command->cmd == LC_BUILD_VERSION) {
            object_file->build_version = *(const struct build_version_command *) cursor;
            object_file->has_build_version = true;
        }

        cursor += command->cmdsize;
    }

    if (symtab_command == NULL) {
        cld_set_error(error, "%s is missing LC_SYMTAB", path);
        cld_free_macho_object(object_file);
        return false;
    }

    object_file->sections = calloc(object_file->section_count, sizeof(*object_file->sections));
    if (object_file->sections == NULL && object_file->section_count != 0) {
        cld_set_error(error, "out of memory allocating sections");
        cld_free_macho_object(object_file);
        return false;
    }

    cursor = object_file->data + sizeof(*header);
    section_index = 0;
    for (command_index = 0; command_index < header->ncmds; ++command_index) {
        const struct load_command *command;

        command = (const struct load_command *) cursor;
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment_command;
            const struct section_64 *sections;
            uint32_t input_section_index;

            segment_command = (const struct segment_command_64 *) cursor;
            sections = (const struct section_64 *) (segment_command + 1);
            for (input_section_index = 0; input_section_index < segment_command->nsects; ++input_section_index) {
                const struct section_64 *source_section;
                CldInputSection *destination_section;

                source_section = &sections[input_section_index];
                destination_section = &object_file->sections[section_index++];

                if ((source_section->flags & SECTION_TYPE) != S_ZEROFILL && !cld_range_is_valid(object_file->size, source_section->offset, source_section->size)) {
                    cld_set_error(error, "%s has a truncated section payload", path);
                    cld_free_macho_object(object_file);
                    return false;
                }

                if (source_section->nreloc != 0 && !cld_range_is_valid(object_file->size, source_section->reloff, (uint64_t) source_section->nreloc * sizeof(struct relocation_info))) {
                    cld_set_error(error, "%s has a truncated relocation table", path);
                    cld_free_macho_object(object_file);
                    return false;
                }

                cld_copy_fixed_name(destination_section->sectname, source_section->sectname);
                cld_copy_fixed_name(destination_section->segname, source_section->segname);
                destination_section->input_index = (uint32_t) section_index;
                destination_section->address = source_section->addr;
                destination_section->size = source_section->size;
                destination_section->align = source_section->align;
                destination_section->flags = source_section->flags;
                destination_section->reserved1 = source_section->reserved1;
                destination_section->reserved2 = source_section->reserved2;
                destination_section->reserved3 = source_section->reserved3;
                destination_section->contents = ((source_section->flags & SECTION_TYPE) == S_ZEROFILL) ? NULL : object_file->data + source_section->offset;
                destination_section->relocations = source_section->nreloc == 0 ? NULL : (const struct relocation_info *) (object_file->data + source_section->reloff);
                destination_section->relocation_count = source_section->nreloc;
            }
        }

        cursor += command->cmdsize;
    }

    if (!cld_range_is_valid(object_file->size, symtab_command->symoff, (uint64_t) symtab_command->nsyms * sizeof(struct nlist_64)) ||
        !cld_range_is_valid(object_file->size, symtab_command->stroff, symtab_command->strsize)) {
        cld_set_error(error, "%s has a truncated symbol table", path);
        cld_free_macho_object(object_file);
        return false;
    }

    object_file->symbol_count = symtab_command->nsyms;
    object_file->symbols = calloc(object_file->symbol_count, sizeof(*object_file->symbols));
    if (object_file->symbols == NULL && object_file->symbol_count != 0) {
        cld_set_error(error, "out of memory allocating symbols");
        cld_free_macho_object(object_file);
        return false;
    }

    for (symbol_index = 0; symbol_index < object_file->symbol_count; ++symbol_index) {
        const struct nlist_64 *symbol_table;
        const char *string_table;
        const struct nlist_64 *source_symbol;

        symbol_table = (const struct nlist_64 *) (object_file->data + symtab_command->symoff);
        string_table = (const char *) (object_file->data + symtab_command->stroff);
        source_symbol = &symbol_table[symbol_index];

        object_file->symbols[symbol_index].raw = *source_symbol;
        if (source_symbol->n_un.n_strx >= symtab_command->strsize) {
            cld_set_error(error, "%s contains a symbol with an invalid string index", path);
            cld_free_macho_object(object_file);
            return false;
        }

        object_file->symbols[symbol_index].name = string_table + source_symbol->n_un.n_strx;
    }

    return true;
}

void cld_free_macho_object(CldMachOObject *object_file) {
    if (object_file == NULL) {
        return;
    }

    free(object_file->path);
    free(object_file->data);
    free(object_file->sections);
    free(object_file->symbols);
    memset(object_file, 0, sizeof(*object_file));
}
