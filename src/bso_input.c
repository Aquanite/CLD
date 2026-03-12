#include "cld/bso.h"

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define CLD_BSO_MAGIC "BSO1"
#define CLD_BSO_MAGIC_SIZE 4
#define CLD_BSO_VERSION 1u
#define CLD_CPU_TYPE_BSLASH 0x01004253u

#define CLD_ELF_MAGIC_0 0x7fu
#define CLD_ELF_MAGIC_1 'E'
#define CLD_ELF_MAGIC_2 'L'
#define CLD_ELF_MAGIC_3 'F'
#define CLD_ELFCLASS64 2u
#define CLD_ELFDATA2LSB 1u
#define CLD_ET_REL 1u
#define CLD_EM_BSLASH 0x4253u
#define CLD_SHT_PROGBITS 1u
#define CLD_SHT_SYMTAB 2u
#define CLD_SHT_STRTAB 3u
#define CLD_SHT_RELA 4u
#define CLD_SHN_UNDEF 0u
#define CLD_SHN_ABS 0xfff1u

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} CldElf64Ehdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} CldElf64Shdr;

typedef struct {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} CldElf64Sym;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t r_addend;
} CldElf64Rela;

typedef struct {
    char magic[CLD_BSO_MAGIC_SIZE];
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

static bool cld_bso_range_is_valid(size_t file_size, uint64_t offset, uint64_t length) {
    if (offset > file_size) {
        return false;
    }
    if (length > (uint64_t) file_size - offset) {
        return false;
    }
    return true;
}

static int64_t cld_bso_sign_extend_u64(uint64_t value, unsigned width_bits) {
    uint64_t sign_bit;

    if (width_bits == 0 || width_bits >= 64) {
        return (int64_t) value;
    }

    sign_bit = 1ull << (width_bits - 1u);
    return (int64_t) ((value ^ sign_bit) - sign_bit);
}

static bool cld_bso_read_embedded_addend(const uint8_t *code,
                                         size_t code_size,
                                         uint32_t offset,
                                         uint32_t kind,
                                         int32_t *addend,
                                         CldError *error) {
    uint32_t width;
    uint64_t raw_value;

    switch (kind) {
        case CLD_BSO_RELOC_ABS8:
        case CLD_BSO_RELOC_REL8:
            width = 1;
            break;
        case CLD_BSO_RELOC_ABS16:
            width = 2;
            break;
        case CLD_BSO_RELOC_ABS32:
        case CLD_BSO_RELOC_REL32:
            width = 4;
            break;
        case CLD_BSO_RELOC_ABS64:
            width = 8;
            break;
        default:
            cld_set_error(error, "unsupported BSlash relocation kind %u", kind);
            return false;
    }

    if (!cld_bso_range_is_valid(code_size, offset, width)) {
        cld_set_error(error, "BSlash relocation offset %u is outside the section contents", offset);
        return false;
    }

    raw_value = 0;
    for (uint32_t byte_index = 0; byte_index < width; ++byte_index) {
        raw_value |= (uint64_t) code[offset + byte_index] << (byte_index * 8u);
    }

    if (kind == CLD_BSO_RELOC_REL8 || kind == CLD_BSO_RELOC_REL32) {
        *addend = (int32_t) cld_bso_sign_extend_u64(raw_value, width * 8u);
        return true;
    }

    if (raw_value > INT32_MAX) {
        cld_set_error(error, "BSlash relocation addend at offset %u is too large", offset);
        return false;
    }
    *addend = (int32_t) raw_value;
    return true;
}

static bool cld_bso_init_normalized_object(CldBsoObject *object_file,
                                           const char *path,
                                           uint32_t code_size,
                                           size_t symbol_count,
                                           size_t relocation_count,
                                           CldError *error) {
    memset(object_file, 0, sizeof(*object_file));

    object_file->path = strdup(path);
    if (object_file->path == NULL) {
        cld_set_error(error, "out of memory duplicating path");
        return false;
    }

    object_file->data = calloc(code_size == 0 ? 1u : 1u, code_size == 0 ? 1u : code_size);
    if (object_file->data == NULL) {
        cld_set_error(error, "out of memory allocating normalized BSlash code");
        cld_free_bso_object(object_file);
        return false;
    }

    object_file->size = code_size;
    object_file->code = object_file->data;
    object_file->code_size = code_size;
    object_file->symbol_count = symbol_count;
    object_file->relocation_count = relocation_count;
    object_file->symbols = calloc(symbol_count == 0 ? 1u : symbol_count, sizeof(*object_file->symbols));
    object_file->relocations = calloc(relocation_count == 0 ? 1u : relocation_count, sizeof(*object_file->relocations));
    if ((symbol_count != 0 && object_file->symbols == NULL) ||
        (relocation_count != 0 && object_file->relocations == NULL)) {
        cld_set_error(error, "out of memory allocating normalized BSlash tables");
        cld_free_bso_object(object_file);
        return false;
    }

    return true;
}

static bool cld_bso_copy_string_table(CldBsoObject *object_file,
                                      const char *source,
                                      uint32_t source_size,
                                      CldError *error) {
    if (source_size == 0) {
        object_file->owned_string_table = NULL;
        object_file->string_table = NULL;
        object_file->string_table_size = 0;
        return true;
    }

    object_file->owned_string_table = malloc(source_size);
    if (object_file->owned_string_table == NULL) {
        cld_set_error(error, "out of memory allocating normalized BSlash string table");
        return false;
    }
    memcpy(object_file->owned_string_table, source, source_size);
    object_file->string_table = object_file->owned_string_table;
    object_file->string_table_size = source_size;
    return true;
}

static bool cld_parse_bslash_macho_object(const char *path,
                                          CldBsoObject *object_file,
                                          CldError *error) {
    uint8_t *file_data;
    size_t file_size;
    const struct mach_header_64 *header;
    const struct symtab_command *symtab_command;
    const struct section_64 *code_section;
    const struct relocation_info *relocations;
    const uint8_t *symbol_table_bytes;
    const char *string_table;
    const uint8_t *cursor;
    uint32_t command_index;
    size_t kept_section_count;
    size_t output_symbol_count;
    size_t output_relocation_count;
    size_t symbol_index;
    size_t relocation_index;
    size_t *symbol_index_map;
    uint32_t normalized_string_table_size;
    bool success;

    file_data = NULL;
    file_size = 0;
    symtab_command = NULL;
    code_section = NULL;
    symbol_index_map = NULL;
    success = false;

    if (!cld_read_entire_file(path, &file_data, &file_size, error)) {
        return false;
    }

    if (file_size < sizeof(*header)) {
        goto cleanup;
    }
    header = (const struct mach_header_64 *) file_data;
    if (header->magic != MH_MAGIC_64 || header->filetype != MH_OBJECT || header->cputype != CLD_CPU_TYPE_BSLASH) {
        goto cleanup;
    }
    if (!cld_bso_range_is_valid(file_size, sizeof(*header), header->sizeofcmds)) {
        cld_set_error(error, "%s has truncated Mach-O load commands", path);
        goto cleanup;
    }

    cursor = file_data + sizeof(*header);
    kept_section_count = 0;
    for (command_index = 0; command_index < header->ncmds; ++command_index) {
        const struct load_command *command;

        if (!cld_bso_range_is_valid(file_size, (uint64_t) (cursor - file_data), sizeof(*command))) {
            cld_set_error(error, "%s has an incomplete Mach-O load command", path);
            goto cleanup;
        }
        command = (const struct load_command *) cursor;
        if (command->cmdsize < sizeof(*command) ||
            !cld_bso_range_is_valid(file_size, (uint64_t) (cursor - file_data), command->cmdsize)) {
            cld_set_error(error, "%s has an invalid Mach-O load command size", path);
            goto cleanup;
        }

        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment_command;
            const struct section_64 *sections;

            segment_command = (const struct segment_command_64 *) cursor;
            if (command->cmdsize < sizeof(*segment_command) + segment_command->nsects * sizeof(struct section_64)) {
                cld_set_error(error, "%s has a truncated Mach-O segment command", path);
                goto cleanup;
            }
            sections = (const struct section_64 *) (segment_command + 1);
            for (uint32_t section_index = 0; section_index < segment_command->nsects; ++section_index) {
                if ((sections[section_index].flags & SECTION_TYPE) == S_ZEROFILL) {
                    continue;
                }
                if (!cld_bso_range_is_valid(file_size, sections[section_index].offset, sections[section_index].size)) {
                    cld_set_error(error, "%s has a truncated BSlash Mach-O section payload", path);
                    goto cleanup;
                }
                if (sections[section_index].nreloc != 0 &&
                    !cld_bso_range_is_valid(file_size,
                                            sections[section_index].reloff,
                                            (uint64_t) sections[section_index].nreloc * sizeof(struct relocation_info))) {
                    cld_set_error(error, "%s has a truncated BSlash Mach-O relocation table", path);
                    goto cleanup;
                }
                code_section = &sections[section_index];
                kept_section_count += 1;
            }
        } else if (command->cmd == LC_SYMTAB) {
            symtab_command = (const struct symtab_command *) cursor;
        }

        cursor += command->cmdsize;
    }

    if (symtab_command == NULL) {
        cld_set_error(error, "%s is missing LC_SYMTAB", path);
        goto cleanup;
    }
    if (kept_section_count != 1 || code_section == NULL) {
        cld_set_error(error, "%s must contain exactly one non-zerofill BSlash section", path);
        goto cleanup;
    }
    if (!cld_bso_range_is_valid(file_size,
                                symtab_command->symoff,
                                (uint64_t) symtab_command->nsyms * sizeof(struct nlist_64)) ||
        !cld_bso_range_is_valid(file_size, symtab_command->stroff, symtab_command->strsize)) {
        cld_set_error(error, "%s has a truncated Mach-O symbol table", path);
        goto cleanup;
    }

    symbol_table_bytes = file_data + symtab_command->symoff;
    string_table = (const char *) (file_data + symtab_command->stroff);
    symbol_index_map = malloc(symtab_command->nsyms * sizeof(*symbol_index_map));
    if (symtab_command->nsyms != 0 && symbol_index_map == NULL) {
        cld_set_error(error, "out of memory allocating Mach-O symbol map");
        goto cleanup;
    }

    output_symbol_count = 0;
    for (symbol_index = 0; symbol_index < symtab_command->nsyms; ++symbol_index) {
        struct nlist_64 symbol;

        memcpy(&symbol,
               symbol_table_bytes + symbol_index * sizeof(symbol),
               sizeof(symbol));
        symbol_index_map[symbol_index] = SIZE_MAX;
        if ((symbol.n_type & N_STAB) != 0) {
            continue;
        }
        if (symbol.n_un.n_strx >= symtab_command->strsize) {
            cld_set_error(error, "%s contains a Mach-O symbol with an invalid string index", path);
            goto cleanup;
        }
        symbol_index_map[symbol_index] = output_symbol_count++;
    }

    relocations = code_section->nreloc == 0 ? NULL : (const struct relocation_info *) (file_data + code_section->reloff);
    output_relocation_count = code_section->nreloc;
    if (!cld_bso_init_normalized_object(object_file,
                                        path,
                                        (uint32_t) code_section->size,
                                        output_symbol_count,
                                        output_relocation_count,
                                        error)) {
        goto cleanup;
    }
    memcpy(object_file->data, file_data + code_section->offset, (size_t) code_section->size);
    normalized_string_table_size = symtab_command->strsize;
    if (!cld_bso_copy_string_table(object_file,
                                   string_table,
                                   normalized_string_table_size,
                                   error)) {
        goto cleanup;
    }

    output_symbol_count = 0;
    for (symbol_index = 0; symbol_index < symtab_command->nsyms; ++symbol_index) {
        struct nlist_64 symbol;
        uint8_t symbol_type;

        if (symbol_index_map[symbol_index] == SIZE_MAX) {
            continue;
        }
        memcpy(&symbol,
               symbol_table_bytes + symbol_index * sizeof(symbol),
               sizeof(symbol));
        symbol_type = symbol.n_type & N_TYPE;
        object_file->symbols[output_symbol_count].name_offset = symbol.n_un.n_strx;
        object_file->symbols[output_symbol_count].name = object_file->string_table + symbol.n_un.n_strx;
        object_file->symbols[output_symbol_count].flags = (symbol.n_type & N_EXT) != 0 ? CLD_BSO_SYMBOL_GLOBAL : 0;

        if (symbol_type == N_UNDF) {
            object_file->symbols[output_symbol_count].value = 0;
        } else if (symbol_type == N_ABS) {
            object_file->symbols[output_symbol_count].flags |= CLD_BSO_SYMBOL_DEFINED;
            object_file->symbols[output_symbol_count].value = (uint32_t) symbol.n_value;
        } else if (symbol_type == N_SECT) {
            if (symbol.n_sect == 0) {
                cld_set_error(error, "%s contains a BSlash Mach-O symbol without a section", path);
                goto cleanup;
            }
            object_file->symbols[output_symbol_count].flags |= CLD_BSO_SYMBOL_DEFINED;
            if (symbol.n_value < code_section->addr || symbol.n_value > code_section->addr + code_section->size) {
                cld_set_error(error, "%s contains a BSlash Mach-O symbol outside the code section", path);
                goto cleanup;
            }
            object_file->symbols[output_symbol_count].value = (uint32_t) (symbol.n_value - code_section->addr);
        } else {
            cld_set_error(error, "%s contains unsupported BSlash Mach-O symbol type %u", path, symbol_type);
            goto cleanup;
        }
        ++output_symbol_count;
    }

    for (relocation_index = 0; relocation_index < output_relocation_count; ++relocation_index) {
        uint32_t kind;
        size_t normalized_symbol_index;

        if (!relocations[relocation_index].r_extern) {
            cld_set_error(error, "%s contains a non-external BSlash Mach-O relocation", path);
            goto cleanup;
        }
        if (relocations[relocation_index].r_symbolnum >= symtab_command->nsyms ||
            symbol_index_map[relocations[relocation_index].r_symbolnum] == SIZE_MAX) {
            cld_set_error(error, "%s contains a Mach-O relocation with an invalid symbol index", path);
            goto cleanup;
        }

        switch (relocations[relocation_index].r_type) {
            case 0:
                kind = CLD_BSO_RELOC_ABS8;
                break;
            case 1:
                kind = CLD_BSO_RELOC_ABS16;
                break;
            case 2:
                kind = CLD_BSO_RELOC_ABS32;
                break;
            case 3:
                kind = CLD_BSO_RELOC_ABS64;
                break;
            case 4:
                kind = CLD_BSO_RELOC_REL8;
                break;
            case 5:
                kind = CLD_BSO_RELOC_REL32;
                break;
            default:
                cld_set_error(error, "%s contains unsupported BSlash Mach-O relocation type %u", path, relocations[relocation_index].r_type);
                goto cleanup;
        }

        normalized_symbol_index = symbol_index_map[relocations[relocation_index].r_symbolnum];
        object_file->relocations[relocation_index].offset = (uint32_t) relocations[relocation_index].r_address;
        object_file->relocations[relocation_index].symbol_index = (uint32_t) normalized_symbol_index;
        object_file->relocations[relocation_index].kind = kind;
        if (!cld_bso_read_embedded_addend(object_file->data,
                                          object_file->code_size,
                                          object_file->relocations[relocation_index].offset,
                                          kind,
                                          &object_file->relocations[relocation_index].addend,
                                          error)) {
            goto cleanup;
        }
    }

    success = true;

cleanup:
    free(symbol_index_map);
    free(file_data);
    if (!success) {
        cld_free_bso_object(object_file);
    }
    return success;
}

static uint32_t cld_elf64_r_sym(uint64_t info) {
    return (uint32_t) (info >> 32);
}

static uint32_t cld_elf64_r_type(uint64_t info) {
    return (uint32_t) info;
}

static uint8_t cld_elf64_st_bind(unsigned char info) {
    return (uint8_t) (info >> 4);
}

static bool cld_parse_bslash_elf_object(const char *path,
                                        CldBsoObject *object_file,
                                        CldError *error) {
    uint8_t *file_data;
    size_t file_size;
    const CldElf64Ehdr *header;
    const CldElf64Shdr *section_headers;
    const char *section_names;
    const CldElf64Shdr *code_section;
    size_t code_section_index;
    const CldElf64Shdr *symtab_section;
    const CldElf64Shdr *strtab_section;
    const CldElf64Sym *symbols;
    size_t symbol_table_count;
    size_t *symbol_index_map;
    size_t output_symbol_count;
    size_t output_relocation_count;
    uint32_t normalized_string_table_size;
    size_t section_index;
    size_t symbol_index;
    size_t relocation_write_index;
    bool success;

    file_data = NULL;
    file_size = 0;
    code_section = NULL;
    code_section_index = 0;
    symtab_section = NULL;
    strtab_section = NULL;
    symbol_index_map = NULL;
    success = false;

    if (!cld_read_entire_file(path, &file_data, &file_size, error)) {
        return false;
    }
    if (file_size < sizeof(*header)) {
        goto cleanup;
    }

    header = (const CldElf64Ehdr *) file_data;
    if (header->e_ident[0] != CLD_ELF_MAGIC_0 ||
        header->e_ident[1] != CLD_ELF_MAGIC_1 ||
        header->e_ident[2] != CLD_ELF_MAGIC_2 ||
        header->e_ident[3] != CLD_ELF_MAGIC_3 ||
        header->e_ident[4] != CLD_ELFCLASS64 ||
        header->e_ident[5] != CLD_ELFDATA2LSB ||
        header->e_type != CLD_ET_REL ||
        header->e_machine != CLD_EM_BSLASH) {
        goto cleanup;
    }

    if (header->e_shentsize != sizeof(CldElf64Shdr) ||
        !cld_bso_range_is_valid(file_size,
                                header->e_shoff,
                                (uint64_t) header->e_shnum * sizeof(CldElf64Shdr))) {
        cld_set_error(error, "%s has a truncated ELF section header table", path);
        goto cleanup;
    }
    section_headers = (const CldElf64Shdr *) (file_data + header->e_shoff);
    if (header->e_shstrndx >= header->e_shnum) {
        cld_set_error(error, "%s has an invalid ELF section name table index", path);
        goto cleanup;
    }
    if (!cld_bso_range_is_valid(file_size,
                                section_headers[header->e_shstrndx].sh_offset,
                                section_headers[header->e_shstrndx].sh_size)) {
        cld_set_error(error, "%s has a truncated ELF section name table", path);
        goto cleanup;
    }
    section_names = (const char *) (file_data + section_headers[header->e_shstrndx].sh_offset);

    for (section_index = 0; section_index < header->e_shnum; ++section_index) {
        const CldElf64Shdr *section;
        const char *section_name;

        section = &section_headers[section_index];
        if (section->sh_name >= section_headers[header->e_shstrndx].sh_size) {
            cld_set_error(error, "%s contains an ELF section with an invalid name index", path);
            goto cleanup;
        }
        section_name = section_names + section->sh_name;

        if (section->sh_type == CLD_SHT_PROGBITS && strcmp(section_name, ".text") == 0) {
            code_section = section;
            code_section_index = section_index;
        } else if (section->sh_type == CLD_SHT_SYMTAB) {
            symtab_section = section;
        }
    }

    if (code_section == NULL) {
        cld_set_error(error, "%s does not contain a .text section for BSlash code", path);
        goto cleanup;
    }
    if (symtab_section == NULL) {
        cld_set_error(error, "%s does not contain an ELF symbol table", path);
        goto cleanup;
    }
    if (!cld_bso_range_is_valid(file_size, code_section->sh_offset, code_section->sh_size)) {
        cld_set_error(error, "%s has a truncated ELF .text section", path);
        goto cleanup;
    }
    if (symtab_section->sh_link >= header->e_shnum) {
        cld_set_error(error, "%s has an invalid ELF string table link", path);
        goto cleanup;
    }
    strtab_section = &section_headers[symtab_section->sh_link];
    if (strtab_section->sh_type != CLD_SHT_STRTAB ||
        !cld_bso_range_is_valid(file_size, strtab_section->sh_offset, strtab_section->sh_size)) {
        cld_set_error(error, "%s has a truncated ELF symbol string table", path);
        goto cleanup;
    }
    if (symtab_section->sh_entsize != sizeof(CldElf64Sym) ||
        !cld_bso_range_is_valid(file_size, symtab_section->sh_offset, symtab_section->sh_size)) {
        cld_set_error(error, "%s has a truncated ELF symbol table", path);
        goto cleanup;
    }

    symbols = (const CldElf64Sym *) (file_data + symtab_section->sh_offset);
    symbol_table_count = (size_t) (symtab_section->sh_size / sizeof(CldElf64Sym));
    symbol_index_map = malloc((symbol_table_count == 0 ? 1u : symbol_table_count) * sizeof(*symbol_index_map));
    if (symbol_index_map == NULL) {
        cld_set_error(error, "out of memory allocating ELF symbol map");
        goto cleanup;
    }

    output_symbol_count = 0;
    for (symbol_index = 0; symbol_index < symbol_table_count; ++symbol_index) {
        symbol_index_map[symbol_index] = SIZE_MAX;
        if (symbol_index == 0) {
            continue;
        }
        if (symbols[symbol_index].st_name >= strtab_section->sh_size) {
            cld_set_error(error, "%s contains an ELF symbol with an invalid name index", path);
            goto cleanup;
        }
        symbol_index_map[symbol_index] = output_symbol_count++;
    }

    output_relocation_count = 0;
    for (section_index = 0; section_index < header->e_shnum; ++section_index) {
        const CldElf64Shdr *section;

        section = &section_headers[section_index];
        if (section->sh_type != CLD_SHT_RELA || section->sh_info != code_section_index) {
            continue;
        }
        if (section->sh_entsize != sizeof(CldElf64Rela) ||
            !cld_bso_range_is_valid(file_size, section->sh_offset, section->sh_size)) {
            cld_set_error(error, "%s has a truncated ELF relocation section", path);
            goto cleanup;
        }
        output_relocation_count += (size_t) (section->sh_size / sizeof(CldElf64Rela));
    }

    if (!cld_bso_init_normalized_object(object_file,
                                        path,
                                        (uint32_t) code_section->sh_size,
                                        output_symbol_count,
                                        output_relocation_count,
                                        error)) {
        goto cleanup;
    }
    memcpy(object_file->data, file_data + code_section->sh_offset, (size_t) code_section->sh_size);
    normalized_string_table_size = (uint32_t) strtab_section->sh_size;
    if (!cld_bso_copy_string_table(object_file,
                                   (const char *) (file_data + strtab_section->sh_offset),
                                   normalized_string_table_size,
                                   error)) {
        goto cleanup;
    }

    output_symbol_count = 0;
    for (symbol_index = 1; symbol_index < symbol_table_count; ++symbol_index) {
        const CldElf64Sym *symbol;
        const char *name;

        symbol = &symbols[symbol_index];
        name = object_file->string_table + symbol->st_name;
        object_file->symbols[output_symbol_count].name = name;
        object_file->symbols[output_symbol_count].name_offset = symbol->st_name;
        object_file->symbols[output_symbol_count].flags = cld_elf64_st_bind(symbol->st_info) == 0 ? 0 : CLD_BSO_SYMBOL_GLOBAL;

        if (symbol->st_shndx == CLD_SHN_UNDEF) {
            object_file->symbols[output_symbol_count].value = 0;
        } else if (symbol->st_shndx == CLD_SHN_ABS) {
            object_file->symbols[output_symbol_count].flags |= CLD_BSO_SYMBOL_DEFINED;
            object_file->symbols[output_symbol_count].value = (uint32_t) symbol->st_value;
        } else if (symbol->st_shndx == code_section_index) {
            if (symbol->st_value > code_section->sh_size) {
                cld_set_error(error, "%s contains an ELF symbol outside the BSlash .text section", path);
                goto cleanup;
            }
            object_file->symbols[output_symbol_count].flags |= CLD_BSO_SYMBOL_DEFINED;
            object_file->symbols[output_symbol_count].value = (uint32_t) symbol->st_value;
        } else {
            cld_set_error(error, "%s contains a BSlash ELF symbol in an unsupported section", path);
            goto cleanup;
        }

        ++output_symbol_count;
    }

    relocation_write_index = 0;
    for (section_index = 0; section_index < header->e_shnum; ++section_index) {
        const CldElf64Shdr *section;
        const CldElf64Rela *relocations;
        size_t relocation_count;

        section = &section_headers[section_index];
        if (section->sh_type != CLD_SHT_RELA || section->sh_info != code_section_index) {
            continue;
        }

        relocations = (const CldElf64Rela *) (file_data + section->sh_offset);
        relocation_count = (size_t) (section->sh_size / sizeof(CldElf64Rela));
        for (size_t rela_index = 0; rela_index < relocation_count; ++rela_index) {
            uint32_t symbol_number;
            uint32_t relocation_type;

            symbol_number = cld_elf64_r_sym(relocations[rela_index].r_info);
            relocation_type = cld_elf64_r_type(relocations[rela_index].r_info);
            if (symbol_number >= symbol_table_count || symbol_index_map[symbol_number] == SIZE_MAX) {
                cld_set_error(error, "%s contains an ELF relocation with an invalid symbol index", path);
                goto cleanup;
            }
            if (relocations[rela_index].r_offset > code_section->sh_size) {
                cld_set_error(error, "%s contains an ELF relocation outside the .text section", path);
                goto cleanup;
            }

            object_file->relocations[relocation_write_index].offset = (uint32_t) relocations[rela_index].r_offset;
            object_file->relocations[relocation_write_index].addend = (int32_t) relocations[rela_index].r_addend;
            object_file->relocations[relocation_write_index].symbol_index = (uint32_t) symbol_index_map[symbol_number];

            switch (relocation_type) {
                case 1:
                    object_file->relocations[relocation_write_index].kind = CLD_BSO_RELOC_ABS8;
                    break;
                case 2:
                    object_file->relocations[relocation_write_index].kind = CLD_BSO_RELOC_ABS16;
                    break;
                case 3:
                    object_file->relocations[relocation_write_index].kind = CLD_BSO_RELOC_ABS32;
                    break;
                case 4:
                    object_file->relocations[relocation_write_index].kind = CLD_BSO_RELOC_ABS64;
                    break;
                case 5:
                    object_file->relocations[relocation_write_index].kind = CLD_BSO_RELOC_REL8;
                    break;
                case 6:
                    object_file->relocations[relocation_write_index].kind = CLD_BSO_RELOC_REL32;
                    break;
                default:
                    cld_set_error(error, "%s contains unsupported BSlash ELF relocation type %u", path, relocation_type);
                    goto cleanup;
            }

            relocation_write_index += 1;
        }
    }

    success = true;

cleanup:
    free(symbol_index_map);
    free(file_data);
    if (!success) {
        cld_free_bso_object(object_file);
    }
    return success;
}

bool cld_parse_bso_object(const char *path, CldBsoObject *object_file, CldError *error) {
    const CldBsoHeader *header;
    uint64_t offset;
    const CldBsoSymbolRecord *symbol_records;
    const CldBsoRelocationRecord *relocation_records;
    size_t symbol_index;

    memset(object_file, 0, sizeof(*object_file));

    if (!cld_read_entire_file(path, &object_file->data, &object_file->size, error)) {
        return false;
    }

    object_file->path = strdup(path);
    if (object_file->path == NULL) {
        cld_set_error(error, "out of memory duplicating path");
        cld_free_bso_object(object_file);
        return false;
    }

    if (object_file->size < sizeof(*header)) {
        cld_set_error(error, "%s is too small to be a BSO file", path);
        cld_free_bso_object(object_file);
        return false;
    }

    header = (const CldBsoHeader *) object_file->data;
    if (memcmp(header->magic, CLD_BSO_MAGIC, CLD_BSO_MAGIC_SIZE) != 0) {
        cld_set_error(error, "%s is not a BSO object file", path);
        cld_free_bso_object(object_file);
        return false;
    }
    if (header->version != CLD_BSO_VERSION) {
        cld_set_error(error, "%s uses unsupported BSO version %u", path, header->version);
        cld_free_bso_object(object_file);
        return false;
    }

    offset = sizeof(*header);
    if (!cld_bso_range_is_valid(object_file->size, offset, header->code_size)) {
        cld_set_error(error, "%s has truncated BSO code", path);
        cld_free_bso_object(object_file);
        return false;
    }
    object_file->code = object_file->data + offset;
    object_file->code_size = header->code_size;
    offset += header->code_size;

    if (!cld_bso_range_is_valid(object_file->size,
                                offset,
                                (uint64_t) header->symbol_count * sizeof(CldBsoSymbolRecord))) {
        cld_set_error(error, "%s has a truncated BSO symbol table", path);
        cld_free_bso_object(object_file);
        return false;
    }
    symbol_records = (const CldBsoSymbolRecord *) (object_file->data + offset);
    offset += (uint64_t) header->symbol_count * sizeof(CldBsoSymbolRecord);

    if (!cld_bso_range_is_valid(object_file->size,
                                offset,
                                (uint64_t) header->relocation_count * sizeof(CldBsoRelocationRecord))) {
        cld_set_error(error, "%s has a truncated BSO relocation table", path);
        cld_free_bso_object(object_file);
        return false;
    }
    relocation_records = (const CldBsoRelocationRecord *) (object_file->data + offset);
    offset += (uint64_t) header->relocation_count * sizeof(CldBsoRelocationRecord);

    if (!cld_bso_range_is_valid(object_file->size, offset, header->string_table_size)) {
        cld_set_error(error, "%s has a truncated BSO string table", path);
        cld_free_bso_object(object_file);
        return false;
    }
    object_file->string_table = (const char *) (object_file->data + offset);
    object_file->string_table_size = header->string_table_size;
    offset += header->string_table_size;

    if (offset != object_file->size) {
        cld_set_error(error, "%s has trailing bytes after the BSO payload", path);
        cld_free_bso_object(object_file);
        return false;
    }

    object_file->symbol_count = header->symbol_count;
    object_file->relocation_count = header->relocation_count;
    object_file->symbols = calloc(object_file->symbol_count, sizeof(*object_file->symbols));
    object_file->relocations = calloc(object_file->relocation_count, sizeof(*object_file->relocations));
    if ((object_file->symbol_count != 0 && object_file->symbols == NULL) ||
        (object_file->relocation_count != 0 && object_file->relocations == NULL)) {
        cld_set_error(error, "out of memory allocating BSO tables");
        cld_free_bso_object(object_file);
        return false;
    }

    for (symbol_index = 0; symbol_index < object_file->symbol_count; ++symbol_index) {
        const CldBsoSymbolRecord *record;

        record = &symbol_records[symbol_index];
        if (record->name_offset >= header->string_table_size) {
            cld_set_error(error, "%s contains a BSO symbol with an invalid string index", path);
            cld_free_bso_object(object_file);
            return false;
        }
        if (memchr(object_file->string_table + record->name_offset,
                   '\0',
                   (size_t) header->string_table_size - record->name_offset) == NULL) {
            cld_set_error(error, "%s contains a BSO symbol name without a terminator", path);
            cld_free_bso_object(object_file);
            return false;
        }

        object_file->symbols[symbol_index].name_offset = record->name_offset;
        object_file->symbols[symbol_index].value = record->value;
        object_file->symbols[symbol_index].flags = record->flags;
        object_file->symbols[symbol_index].name = object_file->string_table + record->name_offset;

        if ((record->flags & CLD_BSO_SYMBOL_DEFINED) != 0 && record->value > header->code_size) {
            cld_set_error(error,
                          "%s defines symbol %s outside its code range",
                          path,
                          object_file->symbols[symbol_index].name);
            cld_free_bso_object(object_file);
            return false;
        }
    }

    for (symbol_index = 0; symbol_index < object_file->relocation_count; ++symbol_index) {
        const CldBsoRelocationRecord *record;

        record = &relocation_records[symbol_index];
        if (record->symbol_index >= header->symbol_count) {
            cld_set_error(error, "%s contains a BSO relocation with an invalid symbol index", path);
            cld_free_bso_object(object_file);
            return false;
        }
        object_file->relocations[symbol_index].offset = record->offset;
        object_file->relocations[symbol_index].addend = record->addend;
        object_file->relocations[symbol_index].symbol_index = record->symbol_index;
        object_file->relocations[symbol_index].kind = record->kind;
    }

    return true;
}

bool cld_parse_bslash_object(const char *path, CldBsoObject *object_file, CldError *error) {
    uint8_t *file_data;
    size_t file_size;
    bool success;

    file_data = NULL;
    file_size = 0;
    success = false;

    if (!cld_read_entire_file(path, &file_data, &file_size, error)) {
        return false;
    }
    if (file_size >= CLD_BSO_MAGIC_SIZE && memcmp(file_data, CLD_BSO_MAGIC, CLD_BSO_MAGIC_SIZE) == 0) {
        free(file_data);
        return cld_parse_bso_object(path, object_file, error);
    }
    if (file_size >= sizeof(uint32_t) && *(const uint32_t *) file_data == MH_MAGIC_64) {
        free(file_data);
        return cld_parse_bslash_macho_object(path, object_file, error);
    }
    if (file_size >= 4 &&
        file_data[0] == CLD_ELF_MAGIC_0 &&
        file_data[1] == CLD_ELF_MAGIC_1 &&
        file_data[2] == CLD_ELF_MAGIC_2 &&
        file_data[3] == CLD_ELF_MAGIC_3) {
        free(file_data);
        return cld_parse_bslash_elf_object(path, object_file, error);
    }

    free(file_data);
    cld_set_error(error, "%s is not a supported BSlash object file", path);
    return success;
}

void cld_free_bso_object(CldBsoObject *object_file) {
    if (object_file == NULL) {
        return;
    }

    free(object_file->path);
    free(object_file->data);
    free(object_file->owned_string_table);
    free(object_file->symbols);
    free(object_file->relocations);
    memset(object_file, 0, sizeof(*object_file));
}
