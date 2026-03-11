#include "cld/linker.h"

#include <mach-o/arm64/reloc.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/machine.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dlfcn.h>

extern char **environ;

#define CLD_ARM64_RELOCATION_PAGE_SIZE 0x1000ull

typedef struct {
    char sectname[CLD_NAME_CAPACITY];
    char segname[CLD_NAME_CAPACITY];
    uint32_t flags;
    uint32_t align;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
    size_t input_object_index;
    uint32_t input_section_index;
    uint32_t output_section_index;
    bool zero_fill;
    uint64_t size;
    uint64_t address;
    uint32_t file_offset;
    uint32_t relocation_offset;
    uint8_t *contents;
    struct relocation_info *owned_relocations;
    uint32_t relocation_capacity;
    uint32_t relocation_count;
    const struct relocation_info *relocations;
} CldOutputSection;

typedef struct {
    char segname[CLD_NAME_CAPACITY];
    int32_t maxprot;
    int32_t initprot;
    uint32_t section_start;
    uint32_t section_count;
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
} CldOutputSegment;

typedef struct {
    const char *name;
    const char *source_path;
    uint8_t type;
    uint8_t section;
    uint16_t description;
    uint64_t value;
    uint32_t output_index;
    size_t source_object_index;
    bool is_defined;
    bool include_in_output;
    bool is_dynamic_import;
    char *dynamic_import_dylib;
} CldResolvedSymbol;

typedef struct {
    char **names;
    size_t count;
    size_t capacity;
} CldSymbolNameSet;

typedef struct {
    char *symbol;
    char *dylib;
} CldImportCacheEntry;

typedef struct {
    CldImportCacheEntry *entries;
    size_t count;
    size_t capacity;
} CldImportCache;

#define CLD_MACOS_SDK_USR_LIB_DIR "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/lib"
#define CLD_MACOS_SDK_TBD_CACHE_PATH "/tmp/cld_macos_sdk_tbd_cache_v1.txt"
#define CLD_MACOS_SDK_TBD_CACHE_HEADER "CLD_TBD_CACHE_V1"
#define CLD_STARTUP_PROLOGUE_SIZE 20u
#define CLD_IMPORT_STUB_SIZE 16u
#define CLD_IMPORT_STUB_CAPACITY 4096u
#define CLD_ARM64_LDR_LITERAL_X16_PLUS8 0x58000050u
#define CLD_ARM64_BR_X16 0xd61f0200u
#define CLD_ARM64_B_IMM26_ZERO 0x14000000u

typedef struct {
    uint32_t output_section_index;
    uint64_t offset_in_output;
} CldSectionMapEntry;

typedef struct {
    const CldMachOObject *input;
    CldSectionMapEntry *section_map;
    uint32_t *symbol_index_map;
    size_t symbol_start;
    size_t object_index;
} CldInputObjectState;

const CldTarget cld_target_macos_arm64 = {
    .name = "macos-arm64",
    .object_format = CLD_OBJECT_FORMAT_MACHO,
    .host_native = true,
    .cpu_type = CPU_TYPE_ARM64,
    .cpu_subtype = CPU_SUBTYPE_ARM64_ALL,
    .platform = PLATFORM_MACOS,
    .minos = 0x000f0000,
    .sdk = 0,
    .page_size = 0x4000,
    .image_base = 0x100000000ull,
    .page_zero_size = 0x100000000ull,
    .default_stack_size = 0,
    .stack_top = 0,
};

const CldTarget cld_target_x86_64_elf = {
    .name = "x86_64-elf",
    .object_format = CLD_OBJECT_FORMAT_ELF,
    .host_native = false,
    .cpu_type = CPU_TYPE_X86_64,
    .cpu_subtype = CPU_SUBTYPE_X86_64_ALL,
    .platform = 0,
    .minos = 0,
    .sdk = 0,
    .page_size = 0x1000,
    .image_base = 0x400000,
    .page_zero_size = 0,
    .default_stack_size = 0,
    .stack_top = 0,
};

static bool cld_is_section_kept(const CldInputSection *section) {
    if ((section->flags & SECTION_ATTRIBUTES) & S_ATTR_DEBUG) {
        return false;
    }
    return true;
}

static bool cld_copy_name(char destination[CLD_NAME_CAPACITY], const char *source) {
    size_t name_length;

    name_length = strnlen(source, 16);
    if (name_length > 16) {
        return false;
    }

    memset(destination, 0, CLD_NAME_CAPACITY);
    memcpy(destination, source, name_length);
    return true;
}

static bool cld_segment_name_exists(const char (*segment_names)[CLD_NAME_CAPACITY],
                                    size_t segment_name_count,
                                    const char *segment_name) {
    size_t segment_index;

    for (segment_index = 0; segment_index < segment_name_count; ++segment_index) {
        if (strncmp(segment_names[segment_index], segment_name, 16) == 0) {
            return true;
        }
    }

    return false;
}

static uint64_t cld_section_alignment(const CldOutputSection *section) {
    uint32_t shift;

    shift = cld_min_u64(section->align, 15);
    return 1ull << shift;
}

static int32_t cld_segment_maxprot_for_name(const char *segname) {
    if (strcmp(segname, SEG_TEXT) == 0) {
        return 5;
    }
    if (strcmp(segname, "__DATA_CONST") == 0 || strcmp(segname, "__AUTH_CONST") == 0) {
        return 1;
    }
    return 3;
}

static int32_t cld_segment_initprot_for_name(const char *segname) {
    return cld_segment_maxprot_for_name(segname);
}

static ssize_t cld_find_segment(const CldOutputSegment *segments, size_t segment_count, const char *segname) {
    size_t segment_index;

    for (segment_index = 0; segment_index < segment_count; ++segment_index) {
        if (strncmp(segments[segment_index].segname, segname, 16) == 0) {
            return (ssize_t) segment_index;
        }
    }

    return -1;
}

static ssize_t cld_find_output_section(const CldOutputSection *sections,
                                       size_t section_count,
                                       const char *segname,
                                       const char *sectname) {
    size_t section_index;

    for (section_index = 0; section_index < section_count; ++section_index) {
        if (strncmp(sections[section_index].segname, segname, 16) != 0) {
            continue;
        }
        if (strncmp(sections[section_index].sectname, sectname, 16) != 0) {
            continue;
        }
        return (ssize_t) section_index;
    }

    return -1;
}

static size_t cld_load_command_size_for_segments(const CldOutputSegment *segments, size_t segment_count) {
    size_t total_size;
    size_t segment_index;

    total_size = 0;
    for (segment_index = 0; segment_index < segment_count; ++segment_index) {
        total_size += sizeof(struct segment_command_64);
        total_size += segments[segment_index].section_count * sizeof(struct section_64);
    }
    return total_size;
}

static uint32_t cld_aligned_command_size(size_t raw_size) {
    return (uint32_t) cld_align_up_u64((uint64_t) raw_size, 8);
}

static void cld_write_padded_command(uint8_t **cursor, const void *command, size_t raw_size) {
    uint32_t padded_size;

    padded_size = cld_aligned_command_size(raw_size);
    memcpy(*cursor, command, raw_size);
    if (padded_size > raw_size) {
        memset(*cursor + raw_size, 0, padded_size - raw_size);
    }
    *cursor += padded_size;
}

static void cld_symbol_name_set_destroy(CldSymbolNameSet *set) {
    if (set == NULL) {
        return;
    }
    if (set->names != NULL) {
        for (size_t i = 0; i < set->count; ++i) {
            free(set->names[i]);
        }
    }
    free(set->names);
    set->names = NULL;
    set->count = 0;
    set->capacity = 0;
}

static void cld_import_cache_destroy(CldImportCache *cache) {
    if (cache == NULL) {
        return;
    }
    if (cache->entries != NULL) {
        for (size_t i = 0; i < cache->count; ++i) {
            free(cache->entries[i].symbol);
            free(cache->entries[i].dylib);
        }
    }
    free(cache->entries);
    cache->entries = NULL;
    cache->count = 0;
    cache->capacity = 0;
}

static const char *cld_import_cache_lookup(const CldImportCache *cache,
                                           const char *symbol) {
    if (cache == NULL || symbol == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < cache->count; ++i) {
        if (cache->entries[i].symbol != NULL &&
            strcmp(cache->entries[i].symbol, symbol) == 0) {
            return cache->entries[i].dylib;
        }
    }
    return NULL;
}

static bool cld_import_cache_upsert(CldImportCache *cache,
                                    const char *symbol,
                                    const char *dylib,
                                    CldError *error) {
    size_t new_capacity;
    CldImportCacheEntry *grown;

    if (cache == NULL || symbol == NULL || dylib == NULL ||
        symbol[0] == '\0' || dylib[0] == '\0') {
        return true;
    }

    for (size_t i = 0; i < cache->count; ++i) {
        if (cache->entries[i].symbol != NULL && strcmp(cache->entries[i].symbol, symbol) == 0) {
            if (cache->entries[i].dylib != NULL && strcmp(cache->entries[i].dylib, dylib) == 0) {
                return true;
            }
            free(cache->entries[i].dylib);
            cache->entries[i].dylib = strdup(dylib);
            if (cache->entries[i].dylib == NULL) {
                cld_set_error(error, "out of memory updating cache for %s", symbol);
                return false;
            }
            return true;
        }
    }

    if (cache->count == cache->capacity) {
        new_capacity = cache->capacity == 0 ? 128 : cache->capacity * 2;
        grown = (CldImportCacheEntry *)realloc(cache->entries,
                                               new_capacity * sizeof(CldImportCacheEntry));
        if (grown == NULL) {
            cld_set_error(error, "out of memory growing import cache");
            return false;
        }
        cache->entries = grown;
        cache->capacity = new_capacity;
    }

    cache->entries[cache->count].symbol = strdup(symbol);
    cache->entries[cache->count].dylib = strdup(dylib);
    if (cache->entries[cache->count].symbol == NULL ||
        cache->entries[cache->count].dylib == NULL) {
        free(cache->entries[cache->count].symbol);
        free(cache->entries[cache->count].dylib);
        cache->entries[cache->count].symbol = NULL;
        cache->entries[cache->count].dylib = NULL;
        cld_set_error(error, "out of memory appending import cache entry");
        return false;
    }
    cache->count++;
    return true;
}

static bool cld_symbol_name_set_contains(const CldSymbolNameSet *set, const char *name) {
    size_t name_length;

    if (set == NULL || name == NULL) {
        return false;
    }
    name_length = strlen(name);
    for (size_t i = 0; i < set->count; ++i) {
        const char *candidate;

        candidate = set->names[i];
        if (candidate == NULL) {
            continue;
        }
        if (strcmp(candidate, name) == 0) {
            return true;
        }
        if (strncmp(candidate, name, name_length) == 0 && candidate[name_length] == '$') {
            return true;
        }
    }
    return false;
}

static bool cld_symbol_name_set_add(CldSymbolNameSet *set, const char *name, CldError *error) {
    char *copy;
    size_t new_capacity;
    char **grown;

    if (set == NULL || name == NULL || name[0] == '\0') {
        return true;
    }
    if (cld_symbol_name_set_contains(set, name)) {
        return true;
    }
    if (set->count == set->capacity) {
        new_capacity = set->capacity == 0 ? 256 : set->capacity * 2;
        grown = (char **) realloc(set->names, new_capacity * sizeof(char *));
        if (grown == NULL) {
            cld_set_error(error, "out of memory growing symbol name set");
            return false;
        }
        set->names = grown;
        set->capacity = new_capacity;
    }
    copy = strdup(name);
    if (copy == NULL) {
        cld_set_error(error, "out of memory duplicating symbol name %s", name);
        return false;
    }
    set->names[set->count++] = copy;
    return true;
}


static bool cld_extract_tbd_install_name(const char *line, char *output, size_t output_size) {
    const char *install;
    const char *quote_start;
    const char *quote_end;
    size_t length;

    install = strstr(line, "install-name:");
    if (install == NULL) {
        return false;
    }
    quote_start = strchr(install, '\'');
    if (quote_start == NULL) {
        quote_start = strchr(install, '"');
        if (quote_start == NULL) {
            return false;
        }
    }
    ++quote_start;
    quote_end = strchr(quote_start, quote_start[-1]);
    if (quote_end == NULL) {
        return false;
    }
    length = (size_t) (quote_end - quote_start);
    if (length == 0 || length >= output_size) {
        return false;
    }
    memcpy(output, quote_start, length);
    output[length] = '\0';
    return true;
}

static void cld_normalize_tbd_symbol(const char *raw,
                                     char *normalized,
                                     size_t normalized_size) {
    const char *chosen;
    const char *last_dollar;

    if (normalized_size == 0) {
        return;
    }
    normalized[0] = '\0';
    if (raw == NULL || raw[0] == '\0') {
        return;
    }

    chosen = raw;
    last_dollar = strrchr(raw, '$');
    if (last_dollar != NULL && last_dollar[1] == '_') {
        chosen = last_dollar + 1;
    } else {
        const char *decorated = strstr(raw, "$_");
        if (decorated != NULL && decorated[1] == '_') {
            chosen = decorated + 1;
        }
    }

    snprintf(normalized, normalized_size, "%s", chosen);
}

static bool cld_tbd_symbol_matches(const char *requested,
                                   const char *normalized_candidate) {
    size_t requested_length;

    if (requested == NULL || normalized_candidate == NULL) {
        return false;
    }
    if (strcmp(requested, normalized_candidate) == 0) {
        return true;
    }
    requested_length = strlen(requested);
    return strncmp(normalized_candidate, requested, requested_length) == 0 &&
           normalized_candidate[requested_length] == '$';
}

static bool cld_find_symbol_dylib_in_sdk_tbd_dir(const char *sdk_lib_dir,
                                                 const char *requested_symbol,
                                                 char *out_dylib,
                                                 size_t out_dylib_size,
                                                 CldError *error) {
    DIR *directory;
    struct dirent *entry;

    directory = opendir(sdk_lib_dir);
    if (directory == NULL) {
        cld_set_error(error, "failed to open SDK lib dir %s", sdk_lib_dir);
        return false;
    }

    while ((entry = readdir(directory)) != NULL) {
        const char *name;
        size_t name_length;
        FILE *file;
        char path[4096];
        char line[32768];
        char current_install_name[1024];

        name = entry->d_name;
        if (name == NULL || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        name_length = strlen(name);
        if (name_length < 5 || strcmp(name + (name_length - 4), ".tbd") != 0) {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", sdk_lib_dir, name);
        file = fopen(path, "rb");
        if (file == NULL) {
            continue;
        }

        current_install_name[0] = '\0';
        while (fgets(line, sizeof(line), file) != NULL) {
            char parsed_install_name[1024];
            char *cursor;

            if (cld_extract_tbd_install_name(line, parsed_install_name, sizeof(parsed_install_name))) {
                snprintf(current_install_name, sizeof(current_install_name), "%s", parsed_install_name);
            }

            cursor = line;
            while (*cursor != '\0') {
                char quote = *cursor;
                char *end;
                size_t length;
                char symbol[512];
                char normalized_symbol[512];

                if (quote != '\'' && quote != '"') {
                    ++cursor;
                    continue;
                }

                ++cursor;
                end = strchr(cursor, quote);
                if (end == NULL) {
                    break;
                }
                length = (size_t) (end - cursor);
                if (length > 0 && length < sizeof(symbol)) {
                    memcpy(symbol, cursor, length);
                    symbol[length] = '\0';
                    cld_normalize_tbd_symbol(symbol,
                                             normalized_symbol,
                                             sizeof(normalized_symbol));
                    if (normalized_symbol[0] == '_' &&
                        cld_tbd_symbol_matches(requested_symbol, normalized_symbol) &&
                        current_install_name[0] != '\0') {
                        snprintf(out_dylib, out_dylib_size, "%s", current_install_name);
                        fclose(file);
                        closedir(directory);
                        return true;
                    }
                }
                cursor = end + 1;
            }

            cursor = line;
            while (*cursor != '\0') {
                const char *start;
                size_t length;
                char symbol[512];
                char normalized_symbol[512];

                if (*cursor != '_') {
                    ++cursor;
                    continue;
                }

                start = cursor;
                ++cursor;
                while (*cursor != '\0' &&
                       (isalnum((unsigned char) *cursor) || *cursor == '_' || *cursor == '$' || *cursor == '.')) {
                    ++cursor;
                }

                length = (size_t) (cursor - start);
                if (length == 0 || length >= sizeof(symbol)) {
                    continue;
                }

                memcpy(symbol, start, length);
                symbol[length] = '\0';
                cld_normalize_tbd_symbol(symbol,
                                         normalized_symbol,
                                         sizeof(normalized_symbol));
                if (normalized_symbol[0] == '_' &&
                    cld_tbd_symbol_matches(requested_symbol, normalized_symbol) &&
                    current_install_name[0] != '\0') {
                    snprintf(out_dylib, out_dylib_size, "%s", current_install_name);
                    fclose(file);
                    closedir(directory);
                    return true;
                }
            }
        }

        fclose(file);
    }

    closedir(directory);
    return false;
}

static bool cld_load_sdk_tbd_exports_and_dylibs(const char *sdk_lib_dir,
                                                CldSymbolNameSet *exports,
                                                CldSymbolNameSet *dylibs,
                                                CldError *error) {
    DIR *directory;
    struct dirent *entry;

    directory = opendir(sdk_lib_dir);
    if (directory == NULL) {
        cld_set_error(error, "failed to open SDK lib dir %s", sdk_lib_dir);
        return false;
    }

    while ((entry = readdir(directory)) != NULL) {
        const char *name;
        size_t name_length;
        FILE *file;
        char path[4096];
        char line[32768];
        char current_install_name[1024];

        name = entry->d_name;
        if (name == NULL) {
            continue;
        }
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        name_length = strlen(name);
        if (name_length < 5 || strcmp(name + (name_length - 4), ".tbd") != 0) {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", sdk_lib_dir, name);
        file = fopen(path, "rb");
        if (file == NULL) {
            continue;
        }

        current_install_name[0] = '\0';
        while (fgets(line, sizeof(line), file) != NULL) {
            char parsed_install_name[1024];
            char *cursor;

            if (cld_extract_tbd_install_name(line, parsed_install_name, sizeof(parsed_install_name))) {
                snprintf(current_install_name, sizeof(current_install_name), "%s", parsed_install_name);
                if (!cld_symbol_name_set_add(dylibs, current_install_name, error)) {
                    fclose(file);
                    closedir(directory);
                    return false;
                }
            }

            cursor = line;
            while (*cursor != '\0') {
                char quote = *cursor;
                char *end;
                size_t length;
                char symbol[512];
                const char *normalized;
                const char *last_dollar;

                if (quote != '\'' && quote != '"') {
                    ++cursor;
                    continue;
                }

                ++cursor;
                end = strchr(cursor, quote);
                if (end == NULL) {
                    break;
                }
                length = (size_t) (end - cursor);
                if (length > 0 && length < sizeof(symbol)) {
                    memcpy(symbol, cursor, length);
                    symbol[length] = '\0';
                    normalized = symbol;
                    last_dollar = strrchr(symbol, '$');
                    if (last_dollar != NULL && last_dollar[1] == '_') {
                        normalized = last_dollar + 1;
                    } else {
                        const char *decorated = strstr(symbol, "$_");
                        if (decorated != NULL && decorated[1] == '_') {
                            normalized = decorated + 1;
                        }
                    }
                    if (normalized[0] == '_') {
                        if (!cld_symbol_name_set_add(exports, normalized, error)) {
                            fclose(file);
                            closedir(directory);
                            return false;
                        }
                    }
                }
                cursor = end + 1;
            }

            cursor = line;
            while (*cursor != '\0') {
                const char *start;
                size_t length;
                char symbol[512];
                const char *normalized;
                const char *last_dollar;

                if (*cursor != '_') {
                    ++cursor;
                    continue;
                }

                start = cursor;
                ++cursor;
                while (*cursor != '\0' &&
                       (isalnum((unsigned char) *cursor) || *cursor == '_' || *cursor == '$' || *cursor == '.')) {
                    ++cursor;
                }

                length = (size_t) (cursor - start);
                if (length == 0 || length >= sizeof(symbol)) {
                    continue;
                }

                memcpy(symbol, start, length);
                symbol[length] = '\0';
                normalized = symbol;
                last_dollar = strrchr(symbol, '$');
                if (last_dollar != NULL && last_dollar[1] == '_') {
                    normalized = last_dollar + 1;
                } else {
                    const char *decorated = strstr(symbol, "$_");
                    if (decorated != NULL && decorated[1] == '_') {
                        normalized = decorated + 1;
                    }
                }

                if (normalized[0] == '_') {
                    if (!cld_symbol_name_set_add(exports, normalized, error)) {
                        fclose(file);
                        closedir(directory);
                        return false;
                    }
                }
            }
        }

        fclose(file);
    }

    closedir(directory);
    return true;
}

static bool cld_load_sdk_tbd_cache(const char *cache_path,
                                   CldImportCache *cache,
                                   bool *cache_hit,
                                   CldError *error) {
    FILE *file;
    char line[32768];

    if (cache_hit != NULL)
        *cache_hit = false;

    file = fopen(cache_path, "rb");
    if (file == NULL) {
        if (errno == ENOENT) {
            return true;
        }
        cld_set_error(error, "failed to open tbd cache %s", cache_path);
        return false;
    }

    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return true;
    }
    line[strcspn(line, "\r\n")] = '\0';
    if (strcmp(line, CLD_MACOS_SDK_TBD_CACHE_HEADER) != 0) {
        fclose(file);
        return true;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char kind;
        char *payload;

        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') {
            continue;
        }
        kind = line[0];
        payload = line + 1;
        if (payload[0] == '\0') {
            continue;
        }
        if (kind == 'M') {
            char *separator = strchr(payload, '\t');
            if (separator == NULL) {
                continue;
            }
            *separator = '\0';
            ++separator;
            if (!cld_import_cache_upsert(cache, payload, separator, error)) {
                fclose(file);
                return false;
            }
        }
    }

    fclose(file);
    if (cache_hit != NULL) {
        *cache_hit = (cache->count != 0);
    }
    return true;
}

static bool cld_write_sdk_tbd_cache(const char *cache_path,
                                    const CldImportCache *cache,
                                    CldError *error) {
    FILE *file;

    file = fopen(cache_path, "wb");
    if (file == NULL) {
        cld_set_error(error, "failed to create tbd cache %s", cache_path);
        return false;
    }

    fprintf(file, "%s\n", CLD_MACOS_SDK_TBD_CACHE_HEADER);
    if (cache != NULL) {
        for (size_t i = 0; i < cache->count; ++i) {
            const CldImportCacheEntry *entry = &cache->entries[i];
            if (entry->symbol != NULL && entry->dylib != NULL &&
                entry->symbol[0] != '\0' && entry->dylib[0] != '\0') {
                fprintf(file, "M%s\t%s\n", entry->symbol, entry->dylib);
            }
        }
    }

    if (fclose(file) != 0) {
        cld_set_error(error, "failed to finalize tbd cache %s", cache_path);
        return false;
    }

    return true;
}

bool cld_flush_sdk_cache(CldError *error) {
    if (unlink(CLD_MACOS_SDK_TBD_CACHE_PATH) == 0) {
        return true;
    }
    if (errno == ENOENT) {
        return true;
    }
    cld_set_error(error, "failed to remove cache %s", CLD_MACOS_SDK_TBD_CACHE_PATH);
    return false;
}



static bool cld_run_codesign(const char *output_path, CldError *error) {
    pid_t process_id;
    int spawn_status;
    int wait_status;
    char *const arguments[] = {
        "/usr/bin/codesign",
        "-s",
        "-",
        (char *) output_path,
        NULL,
    };

    spawn_status = posix_spawn(&process_id, arguments[0], NULL, NULL, arguments, environ);
    if (spawn_status != 0) {
        cld_set_error(error, "failed to launch codesign for %s", output_path);
        return false;
    }

    if (waitpid(process_id, &wait_status, 0) < 0) {
        cld_set_error(error, "failed to wait for codesign on %s", output_path);
        return false;
    }

    if (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0) {
        cld_set_error(error, "codesign failed for %s", output_path);
        return false;
    }

    return true;
}

static bool cld_fixup_codesign_load_commands(const char *output_path, CldError *error) {
    uint8_t *file_bytes;
    size_t file_size;
    struct mach_header_64 *header;
    size_t command_index;
    size_t command_offset;
    struct linkedit_data_command *code_signature_command;

    file_bytes = NULL;
    file_size = 0;
    if (!cld_read_entire_file(output_path, &file_bytes, &file_size, error)) {
        return false;
    }

    if (file_size < sizeof(*header)) {
        free(file_bytes);
        cld_set_error(error, "signed output %s is truncated", output_path);
        return false;
    }

    header = (struct mach_header_64 *) file_bytes;
    if (header->magic != MH_MAGIC_64) {
        free(file_bytes);
        cld_set_error(error, "signed output %s is not a 64-bit Mach-O file", output_path);
        return false;
    }

    if (file_size < sizeof(*header) + header->sizeofcmds) {
        free(file_bytes);
        cld_set_error(error, "signed output %s has truncated load commands", output_path);
        return false;
    }

    command_offset = sizeof(*header);
    for (command_index = 0; command_index < header->ncmds; ++command_index) {
        struct load_command *command;

        if (command_offset + sizeof(*command) > sizeof(*header) + header->sizeofcmds) {
            free(file_bytes);
            cld_set_error(error, "signed output %s has an invalid load command table", output_path);
            return false;
        }

        command = (struct load_command *) (file_bytes + command_offset);
        if (command->cmdsize < sizeof(*command) || command_offset + command->cmdsize > sizeof(*header) + header->sizeofcmds) {
            free(file_bytes);
            cld_set_error(error, "signed output %s has an invalid load command size", output_path);
            return false;
        }
        command_offset += command->cmdsize;
    }

    if (command_offset + sizeof(struct linkedit_data_command) != sizeof(*header) + header->sizeofcmds) {
        free(file_bytes);
        return true;
    }

    code_signature_command = (struct linkedit_data_command *) (file_bytes + command_offset);
    if (code_signature_command->cmd != LC_CODE_SIGNATURE || code_signature_command->cmdsize != sizeof(*code_signature_command)) {
        free(file_bytes);
        return true;
    }

    header->ncmds += 1;
    if (!cld_write_entire_file(output_path, file_bytes, file_size, error)) {
        free(file_bytes);
        return false;
    }

    free(file_bytes);
    return true;
}

static uint64_t cld_read_u64(const uint8_t *data, uint32_t width) {
    uint64_t value;
    uint32_t byte_index;

    value = 0;
    for (byte_index = 0; byte_index < width; ++byte_index) {
        value |= (uint64_t) data[byte_index] << (byte_index * 8u);
    }
    return value;
}

static void cld_write_u64(uint8_t *data, uint32_t width, uint64_t value) {
    uint32_t byte_index;

    for (byte_index = 0; byte_index < width; ++byte_index) {
        data[byte_index] = (uint8_t) ((value >> (byte_index * 8u)) & 0xffu);
    }
}

static bool cld_symbol_names_match(const char *left, const char *right) {
    const char *left_normalized;
    const char *right_normalized;
    size_t left_length;
    size_t right_length;

    if (left == NULL || right == NULL) {
        return false;
    }

    left_normalized = (left[0] == '_') ? (left + 1) : left;
    right_normalized = (right[0] == '_') ? (right + 1) : right;

    if (strcmp(left_normalized, right_normalized) == 0) {
        return true;
    }

    left_length = strlen(left_normalized);
    right_length = strlen(right_normalized);
    if (left_length > right_length &&
        strncmp(left_normalized, right_normalized, right_length) == 0 &&
        (left_normalized[right_length] == '$' || left_normalized[right_length] == '.')) {
        return true;
    }
    if (right_length > left_length &&
        strncmp(right_normalized, left_normalized, left_length) == 0 &&
        (right_normalized[left_length] == '$' || right_normalized[left_length] == '.')) {
        return true;
    }

    return false;
}

static bool cld_lookup_defined_symbol_by_name(const CldResolvedSymbol *symbols,
                                              size_t symbol_count,
                                              const char *name,
                                              bool external_only,
                                              uint64_t *value,
                                              CldError *error) {
    size_t symbol_index;
    bool found;
    (void) error;
    found = false;
    for (symbol_index = 0; symbol_index < symbol_count; ++symbol_index) {
        if (!symbols[symbol_index].is_defined) {
            continue;
        }
        if (external_only && (symbols[symbol_index].type & N_EXT) == 0) {
            continue;
        }
        if (!cld_symbol_names_match(symbols[symbol_index].name, name)) {
            continue;
        }
        if (found) {
            /* Keep the first matching definition. Some generated object sets
               can contain duplicate non-external entries for the same name. */
            continue;
        }

        *value = symbols[symbol_index].value;
        found = true;
    }

    return found;
}

static size_t cld_find_defined_symbol_index_by_name(const CldResolvedSymbol *symbols,
                                                    size_t symbol_count,
                                                    const char *name,
                                                    bool external_only) {
    size_t symbol_index;

    for (symbol_index = 0; symbol_index < symbol_count; ++symbol_index) {
        if (!symbols[symbol_index].is_defined) {
            continue;
        }
        if (external_only && (symbols[symbol_index].type & N_EXT) == 0) {
            continue;
        }
        if (cld_symbol_names_match(symbols[symbol_index].name, name)) {
            return symbol_index;
        }
    }

    return SIZE_MAX;
}

static bool cld_validate_unique_external_definitions(const CldResolvedSymbol *symbols,
                                                     size_t symbol_count,
                                                     CldError *error) {
    size_t left_index;
    size_t right_index;

    for (left_index = 0; left_index < symbol_count; ++left_index) {
        if (!symbols[left_index].is_defined || (symbols[left_index].type & N_EXT) == 0) {
            continue;
        }

        for (right_index = left_index + 1; right_index < symbol_count; ++right_index) {
            if (!symbols[right_index].is_defined || (symbols[right_index].type & N_EXT) == 0) {
                continue;
            }
            if (!cld_symbol_names_match(symbols[left_index].name, symbols[right_index].name)) {
                continue;
            }

            cld_set_error(error,
                          "multiple definitions of symbol %s in %s and %s",
                          symbols[left_index].name,
                          symbols[left_index].source_path,
                          symbols[right_index].source_path);
            return false;
        }
    }

    return true;
}

static void cld_log_nearby_defined_symbols(const CldResolvedSymbol *symbols,
                                           size_t symbol_count,
                                           const char *requested_name) {
    const char *requested_normalized;
    size_t requested_length;
    size_t shown;

    if (symbols == NULL || requested_name == NULL) {
        return;
    }

    requested_normalized = requested_name[0] == '_' ? (requested_name + 1) : requested_name;
    requested_length = strlen(requested_normalized);
    if (requested_length == 0) {
        return;
    }

    shown = 0;
    for (size_t i = 0; i < symbol_count; ++i) {
        const char *candidate;
        const char *candidate_normalized;

        if (!symbols[i].is_defined || symbols[i].name == NULL) {
            continue;
        }
        candidate = symbols[i].name;
        candidate_normalized = candidate[0] == '_' ? (candidate + 1) : candidate;

        if (strncmp(candidate_normalized, requested_normalized, requested_length) != 0) {
            continue;
        }

        if (shown == 0) {
            fprintf(stderr, "cld: note: nearby defined symbols for %s:\n", requested_name);
        }
        fprintf(stderr, "cld: note:   %s\n", candidate);
        ++shown;
        if (shown >= 16) {
            break;
        }
    }
}

static bool cld_resolve_relocation_target(const CldInputObjectState *object_state,
                                          const CldOutputSection *sections,
                                          const CldResolvedSymbol *symbols,
                                          const struct relocation_info *relocation,
                                          uint64_t *target_value,
                                          CldError *error) {
    if (relocation->r_extern) {
        size_t symbol_index;

        if (relocation->r_symbolnum >= object_state->input->symbol_count) {
            cld_set_error(error, "relocation references symbol index %u outside the symbol table", relocation->r_symbolnum);
            return false;
        }

        symbol_index = object_state->symbol_start + relocation->r_symbolnum;
        if (!symbols[symbol_index].is_defined) {
            cld_set_error(error, "undefined external symbol %s is not supported yet", symbols[symbol_index].name);
            return false;
        }
        *target_value = symbols[symbol_index].value;
        return true;
    }

    if (relocation->r_symbolnum == 0 || relocation->r_symbolnum > object_state->input->section_count) {
        cld_set_error(error, "local relocation references invalid section ordinal %u", relocation->r_symbolnum);
        return false;
    }

    if (object_state->section_map[relocation->r_symbolnum].output_section_index == 0) {
        cld_set_error(error, "local relocation references a section that was not emitted");
        return false;
    }

    *target_value = sections[object_state->section_map[relocation->r_symbolnum].output_section_index - 1].address;
    return true;
}

static bool cld_append_output_relocation(CldOutputSection *section,
                                         const struct relocation_info *relocation,
                                         CldError *error) {
    struct relocation_info *next_relocations;
    uint32_t next_capacity;

    if (section->relocation_count == section->relocation_capacity) {
        next_capacity = section->relocation_capacity == 0 ? 8 : section->relocation_capacity * 2;
        next_relocations = realloc(section->owned_relocations, (size_t) next_capacity * sizeof(*next_relocations));
        if (next_relocations == NULL) {
            cld_set_error(error, "out of memory growing relocation table");
            return false;
        }
        section->owned_relocations = next_relocations;
        section->relocation_capacity = next_capacity;
        section->relocations = section->owned_relocations;
    }

    section->owned_relocations[section->relocation_count++] = *relocation;
    return true;
}

static bool cld_patch_branch26(uint8_t *contents, uint64_t place, uint64_t target, CldError *error) {
    uint32_t instruction;
    int64_t delta;
    int64_t immediate;

    instruction = (uint32_t) cld_read_u64(contents, 4);
    delta = (int64_t) target - (int64_t) place;
    if ((delta & 0x3) != 0) {
        cld_set_error(error, "branch target is not 4-byte aligned");
        return false;
    }

    immediate = delta >> 2;
    if (immediate < -(1ll << 25) || immediate >= (1ll << 25)) {
        cld_set_error(error, "branch relocation target is out of range");
        return false;
    }

    instruction &= 0xfc000000u;
    instruction |= (uint32_t) (immediate & 0x03ffffffu);
    cld_write_u64(contents, 4, instruction);
    return true;
}

static bool cld_patch_page21(uint8_t *contents, uint64_t place, uint64_t target, uint64_t page_size, CldError *error) {
    uint32_t instruction;
    int64_t page_delta;
    int64_t immediate;
    uint32_t immlo;
    uint32_t immhi;

    instruction = (uint32_t) cld_read_u64(contents, 4);
    page_delta = (int64_t) (target & ~(page_size - 1u)) - (int64_t) (place & ~(page_size - 1u));
    immediate = page_delta >> 12;
    if (immediate < -(1ll << 20) || immediate >= (1ll << 20)) {
        cld_set_error(error, "page21 relocation target is out of range");
        return false;
    }

    immlo = (uint32_t) (immediate & 0x3);
    immhi = (uint32_t) ((immediate >> 2) & 0x7ffff);
    instruction &= ~((uint32_t) (0x3u << 29) | (uint32_t) (0x7ffffu << 5));
    instruction |= (immlo << 29) | (immhi << 5);
    cld_write_u64(contents, 4, instruction);
    return true;
}

static bool cld_patch_pageoff12(uint8_t *contents, uint64_t target, uint32_t length, uint64_t page_size, CldError *error) {
    uint32_t instruction;
    uint64_t offset_in_page;
    uint64_t scale;
    uint64_t immediate;

    instruction = (uint32_t) cld_read_u64(contents, 4);
    offset_in_page = target & (page_size - 1u);
    if ((instruction & 0x1f000000u) == 0x11000000u) {
        /* add/sub (immediate): imm12 is unscaled */
        scale = 1ull;
    } else {
        scale = 1ull << length;
    }
    if ((offset_in_page % scale) != 0) {
        cld_set_error(error, "pageoff12 relocation target is not aligned for the instruction scale");
        return false;
    }

    immediate = offset_in_page / scale;
    if (immediate > 0xfff) {
        cld_set_error(error, "pageoff12 relocation target is out of range");
        return false;
    }

    instruction &= ~(0xfffu << 10);
    instruction |= (uint32_t) (immediate << 10);
    cld_write_u64(contents, 4, instruction);
    return true;
}

static bool cld_relax_got_load_pageoff12(uint8_t *contents, uint64_t target, uint64_t page_size, CldError *error) {
    uint32_t original_instruction;
    uint32_t rewritten_instruction;
    uint32_t register_destination;
    uint32_t register_base;
    uint64_t offset_in_page;

    original_instruction = (uint32_t) cld_read_u64(contents, 4);
    register_destination = original_instruction & 0x1fu;
    register_base = (original_instruction >> 5) & 0x1fu;
    offset_in_page = target & (page_size - 1u);
    if (offset_in_page > 0xfffu) {
        cld_set_error(error, "got-load relaxation target is out of range for add-immediate");
        return false;
    }

    rewritten_instruction = 0x91000000u;
    rewritten_instruction |= (uint32_t) (offset_in_page << 10);
    rewritten_instruction |= register_base << 5;
    rewritten_instruction |= register_destination;
    cld_write_u64(contents, 4, rewritten_instruction);
    return true;
}

static bool cld_apply_relocations(const CldTarget *target,
                                  CldOutputSection *sections,
                                  size_t section_count,
                                  const CldInputObjectState *object_states,
                                  const CldResolvedSymbol *symbols,
                                  CldOutputSection *startup_section,
                                  uint32_t *import_stub_slots,
                                  size_t import_stub_slot_count,
                                  uint32_t *next_import_stub_slot,
                                  CldError *error) {
    size_t section_index;

    (void) target;

    for (section_index = 0; section_index < section_count; ++section_index) {
        CldOutputSection *section;
        uint32_t relocation_index;
        int64_t pending_addend;

        section = &sections[section_index];
        if (section->relocation_count == 0 || section->input_object_index == SIZE_MAX) {
            continue;
        }

        pending_addend = 0;
        for (relocation_index = 0; relocation_index < section->relocation_count; ++relocation_index) {
            const struct relocation_info *relocation;
            const CldInputObjectState *object_state;
            uint8_t *fixup;
            uint64_t place;
            uint64_t target_value;
            uint32_t width;
            uint64_t encoded_addend;

            relocation = &section->relocations[relocation_index];
            object_state = &object_states[section->input_object_index];
            if (relocation->r_address < 0 || (uint64_t) relocation->r_address >= section->size) {
                cld_set_error(error, "relocation address %d is outside section %s,%s", relocation->r_address, section->segname, section->sectname);
                return false;
            }

            if (relocation->r_type == ARM64_RELOC_ADDEND) {
                pending_addend = cld_sign_extend_u32(relocation->r_symbolnum, 24);
                continue;
            }

            width = 1u << relocation->r_length;
            if ((uint64_t) relocation->r_address + width > section->size) {
                cld_set_error(error, "relocation width overruns section %s,%s", section->segname, section->sectname);
                return false;
            }

            fixup = section->contents + relocation->r_address;
            place = section->address + (uint64_t) relocation->r_address;

            if (relocation->r_extern) {
                size_t input_symbol_index;
                size_t resolved_symbol_index;

                input_symbol_index = relocation->r_symbolnum;
                if (input_symbol_index >= object_state->input->symbol_count) {
                    cld_set_error(error, "relocation references symbol index %u outside the symbol table", relocation->r_symbolnum);
                    return false;
                }
                resolved_symbol_index = object_state->symbol_start + input_symbol_index;
                if (!symbols[resolved_symbol_index].is_defined && symbols[resolved_symbol_index].is_dynamic_import) {
                    uint32_t stub_slot;
                    uint64_t stub_address;
                    uint64_t host_symbol_address;
                    const char *host_symbol_name;
                    void *host_symbol_ptr;

                    if (relocation->r_type != ARM64_RELOC_BRANCH26) {
                        cld_set_error(error,
                                      "dynamic import relocation type %u for %s is not supported yet",
                                      relocation->r_type,
                                      symbols[resolved_symbol_index].name);
                        return false;
                    }

                    if (resolved_symbol_index >= import_stub_slot_count) {
                        cld_set_error(error, "internal error: dynamic import slot index is out of range");
                        return false;
                    }

                    stub_slot = import_stub_slots[resolved_symbol_index];
                    if (stub_slot == UINT32_MAX) {
                        if (*next_import_stub_slot >= CLD_IMPORT_STUB_CAPACITY) {
                            cld_set_error(error,
                                          "dynamic import count exceeded reserved capacity (%u)",
                                          (unsigned int) CLD_IMPORT_STUB_CAPACITY);
                            return false;
                        }

                        host_symbol_name = symbols[resolved_symbol_index].name;
                        if (host_symbol_name != NULL && host_symbol_name[0] == '_') {
                            host_symbol_name += 1;
                        }

                        host_symbol_ptr = NULL;
                        if (symbols[resolved_symbol_index].dynamic_import_dylib != NULL &&
                            symbols[resolved_symbol_index].dynamic_import_dylib[0] != '\0') {
                            void *import_handle;
                            import_handle = dlopen(symbols[resolved_symbol_index].dynamic_import_dylib,
                                                   RTLD_LAZY);
                            if (import_handle == NULL) {
                                cld_set_error(error,
                                              "unable to open import dylib %s for symbol %s",
                                              symbols[resolved_symbol_index].dynamic_import_dylib,
                                              symbols[resolved_symbol_index].name);
                                return false;
                            }
                            host_symbol_ptr = dlsym(import_handle, host_symbol_name);
                            if (host_symbol_ptr == NULL) {
                                host_symbol_ptr = dlsym(import_handle, symbols[resolved_symbol_index].name);
                            }
                        }
                        if (host_symbol_ptr == NULL) {
                            host_symbol_ptr = dlsym(RTLD_DEFAULT, host_symbol_name);
                        }
                        if (host_symbol_ptr == NULL) {
                            host_symbol_ptr = dlsym(RTLD_DEFAULT, symbols[resolved_symbol_index].name);
                        }
                        if (host_symbol_ptr == NULL) {
                            cld_set_error(error,
                                          "unable to resolve host symbol for dynamic import %s",
                                          symbols[resolved_symbol_index].name);
                            return false;
                        }

                        host_symbol_address = (uint64_t) (uintptr_t) host_symbol_ptr;
                        stub_slot = *next_import_stub_slot;
                        *next_import_stub_slot += 1;
                        import_stub_slots[resolved_symbol_index] = stub_slot;

                        if ((uint64_t) CLD_STARTUP_PROLOGUE_SIZE
                            + ((uint64_t) stub_slot + 1u) * CLD_IMPORT_STUB_SIZE
                            > startup_section->size) {
                            cld_set_error(error, "startup section import-stub area is too small");
                            return false;
                        }

                        cld_write_u64(startup_section->contents
                                      + CLD_STARTUP_PROLOGUE_SIZE
                                      + (size_t) stub_slot * CLD_IMPORT_STUB_SIZE,
                                      4,
                                      CLD_ARM64_LDR_LITERAL_X16_PLUS8);
                        cld_write_u64(startup_section->contents
                                      + CLD_STARTUP_PROLOGUE_SIZE
                                      + (size_t) stub_slot * CLD_IMPORT_STUB_SIZE
                                      + 4,
                                      4,
                                      CLD_ARM64_BR_X16);
                        cld_write_u64(startup_section->contents
                                      + CLD_STARTUP_PROLOGUE_SIZE
                                      + (size_t) stub_slot * CLD_IMPORT_STUB_SIZE
                                      + 8,
                                      8,
                                      host_symbol_address);
                    }

                    stub_address = startup_section->address
                                 + CLD_STARTUP_PROLOGUE_SIZE
                                 + (uint64_t) stub_slot * CLD_IMPORT_STUB_SIZE;

                    if (!cld_patch_branch26(fixup, place, stub_address, error)) {
                        return false;
                    }
                    pending_addend = 0;
                    continue;
                }
            }

            if (relocation->r_type == ARM64_RELOC_SUBTRACTOR) {
                const struct relocation_info *next_relocation;
                uint64_t subtrahend;
                uint64_t minuend;

                if (relocation_index + 1 >= section->relocation_count) {
                    cld_set_error(error, "subtractor relocation is missing its paired unsigned relocation");
                    return false;
                }

                next_relocation = &section->relocations[relocation_index + 1];
                if (next_relocation->r_type != ARM64_RELOC_UNSIGNED || next_relocation->r_address != relocation->r_address) {
                    cld_set_error(error, "subtractor relocation is not followed by a matching unsigned relocation");
                    return false;
                }

                if (!cld_resolve_relocation_target(object_state, sections, symbols, relocation, &subtrahend, error) ||
                    !cld_resolve_relocation_target(object_state, sections, symbols, next_relocation, &minuend, error)) {
                    return false;
                }

                encoded_addend = cld_read_u64(fixup, width);
                cld_write_u64(fixup, width, minuend - subtrahend + encoded_addend);
                ++relocation_index;
                pending_addend = 0;
                continue;
            }

            if (!cld_resolve_relocation_target(object_state, sections, symbols, relocation, &target_value, error)) {
                return false;
            }

            target_value += (uint64_t) pending_addend;
            pending_addend = 0;

            switch (relocation->r_type) {
                case ARM64_RELOC_UNSIGNED:
                    encoded_addend = cld_read_u64(fixup, width);
                    cld_write_u64(fixup, width, target_value + encoded_addend);
                    break;
                case ARM64_RELOC_BRANCH26:
                    if (!cld_patch_branch26(fixup, place, target_value, error)) {
                        return false;
                    }
                    break;
                case ARM64_RELOC_PAGE21:
                    if (!cld_patch_page21(fixup, place, target_value, CLD_ARM64_RELOCATION_PAGE_SIZE, error)) {
                        return false;
                    }
                    break;
                case ARM64_RELOC_PAGEOFF12:
                    if (!cld_patch_pageoff12(fixup, target_value, relocation->r_length, CLD_ARM64_RELOCATION_PAGE_SIZE, error)) {
                        return false;
                    }
                    break;
                case ARM64_RELOC_GOT_LOAD_PAGE21:
                    if (!cld_patch_page21(fixup, place, target_value, CLD_ARM64_RELOCATION_PAGE_SIZE, error)) {
                        return false;
                    }
                    break;
                case ARM64_RELOC_GOT_LOAD_PAGEOFF12:
                    if (!cld_relax_got_load_pageoff12(fixup, target_value, CLD_ARM64_RELOCATION_PAGE_SIZE, error)) {
                        return false;
                    }
                    break;
                default:
                    cld_set_error(error, "unsupported arm64 relocation type %u in %s,%s", relocation->r_type, section->segname, section->sectname);
                    return false;
            }
        }
    }

    return true;
}

static bool cld_append_string(uint8_t **strings, size_t *size, size_t *capacity, const char *value, uint32_t *offset, CldError *error) {
    *offset = (uint32_t) *size;
    return cld_append_bytes(strings, size, capacity, value, strlen(value) + 1, error);
}

static bool cld_validate_build_versions(const CldMachOObject *object_files,
                                        size_t object_count,
                                        bool *has_build_version,
                                        struct build_version_command *build_version,
                                        CldError *error) {
    size_t object_index;

    *has_build_version = false;
    memset(build_version, 0, sizeof(*build_version));
    for (object_index = 0; object_index < object_count; ++object_index) {
        if (!object_files[object_index].has_build_version) {
            continue;
        }

        if (!*has_build_version) {
            *build_version = object_files[object_index].build_version;
            *has_build_version = true;
            continue;
        }

        if (build_version->platform != object_files[object_index].build_version.platform ||
            build_version->minos != object_files[object_index].build_version.minos) {
            cld_set_error(error, "input objects use incompatible build versions");
            return false;
        }

        build_version->sdk = cld_max_u64(build_version->sdk, object_files[object_index].build_version.sdk);
    }

    return true;
}

static bool cld_emit_macho_relocatable(const CldMachOObject *object_files,
                                       size_t object_count,
                                       const CldLinkOptions *options,
                                       CldError *error) {
    CldInputObjectState *object_states;
    CldOutputSection *sections;
    CldResolvedSymbol *symbols;
    size_t total_symbol_count;
    size_t max_section_count;
    size_t output_section_count;
    size_t object_index;
    size_t section_index;
    size_t symbol_index;
    bool has_build_version;
    struct build_version_command build_version;
    uint32_t output_symbol_count;
    uint32_t header_flags;
    size_t load_commands_size;
    size_t header_size;
    uint64_t current_address;
    uint32_t current_file_offset;
    uint32_t first_section_offset;
    uint32_t relocation_file_offset;
    uint32_t symtab_file_offset;
    uint32_t string_file_offset;
    uint8_t *symtab_bytes;
    size_t symtab_size;
    uint8_t *string_bytes;
    size_t string_size;
    size_t next_string_offset;
    uint8_t *output_bytes;
    size_t file_size;
    bool success;

    object_states = calloc(object_count, sizeof(*object_states));
    sections = NULL;
    symbols = NULL;
    symtab_bytes = NULL;
    string_bytes = NULL;
    output_bytes = NULL;
    success = false;
    total_symbol_count = 0;
    max_section_count = 0;
    output_section_count = 0;
    output_symbol_count = 0;
    header_flags = 0;
    string_size = 0;
    next_string_offset = 0;

    if (object_states == NULL) {
        cld_set_error(error, "out of memory allocating relocatable linker state");
        goto cleanup;
    }

    if (!cld_validate_build_versions(object_files, object_count, &has_build_version, &build_version, error)) {
        goto cleanup;
    }

    for (object_index = 0; object_index < object_count; ++object_index) {
        object_states[object_index].input = &object_files[object_index];
        object_states[object_index].object_index = object_index;
        object_states[object_index].symbol_start = total_symbol_count;
        total_symbol_count += object_files[object_index].symbol_count;
        max_section_count += object_files[object_index].section_count;
        header_flags |= object_files[object_index].header_flags;

        object_states[object_index].section_map = calloc(object_files[object_index].section_count + 1, sizeof(*object_states[object_index].section_map));
        object_states[object_index].symbol_index_map = calloc(object_files[object_index].symbol_count, sizeof(*object_states[object_index].symbol_index_map));
        if (object_states[object_index].section_map == NULL ||
            (object_files[object_index].symbol_count != 0 && object_states[object_index].symbol_index_map == NULL)) {
            cld_set_error(error, "out of memory allocating relocatable object maps");
            goto cleanup;
        }
    }

    sections = calloc(max_section_count, sizeof(*sections));
    symbols = calloc(total_symbol_count, sizeof(*symbols));
    if ((max_section_count != 0 && sections == NULL) || (total_symbol_count != 0 && symbols == NULL)) {
        cld_set_error(error, "out of memory allocating relocatable output state");
        goto cleanup;
    }

    for (object_index = 0; object_index < object_count; ++object_index) {
        const CldMachOObject *object_file;

        object_file = &object_files[object_index];
        for (section_index = 0; section_index < object_file->section_count; ++section_index) {
            const CldInputSection *input_section;
            CldOutputSection *output_section;
            ssize_t existing_index;
            uint64_t offset_in_output;
            uint64_t new_size;

            input_section = &object_file->sections[section_index];
            if (!cld_is_section_kept(input_section)) {
                continue;
            }

            existing_index = cld_find_output_section(sections, output_section_count, input_section->segname, input_section->sectname);
            if (existing_index < 0) {
                output_section = &sections[output_section_count];
                memset(output_section, 0, sizeof(*output_section));
                memcpy(output_section->segname, input_section->segname, CLD_NAME_CAPACITY);
                memcpy(output_section->sectname, input_section->sectname, CLD_NAME_CAPACITY);
                output_section->flags = input_section->flags;
                output_section->align = input_section->align;
                output_section->reserved1 = input_section->reserved1;
                output_section->reserved2 = input_section->reserved2;
                output_section->reserved3 = input_section->reserved3;
                output_section->zero_fill = ((input_section->flags & SECTION_TYPE) == S_ZEROFILL);
                ++output_section_count;
            } else {
                output_section = &sections[existing_index];
                if (output_section->flags != input_section->flags ||
                    output_section->reserved1 != input_section->reserved1 ||
                    output_section->reserved2 != input_section->reserved2 ||
                    output_section->reserved3 != input_section->reserved3 ||
                    output_section->zero_fill != (((input_section->flags & SECTION_TYPE) == S_ZEROFILL))) {
                    cld_set_error(error,
                                  "cannot merge incompatible section %s,%s from %s",
                                  input_section->segname,
                                  input_section->sectname,
                                  object_file->path);
                    goto cleanup;
                }
                output_section->align = (uint32_t) cld_max_u64(output_section->align, input_section->align);
            }

            offset_in_output = cld_align_up_u64(output_section->size, 1ull << cld_min_u64(input_section->align, 15));
            new_size = offset_in_output + input_section->size;
            object_states[object_index].section_map[input_section->input_index].output_section_index = (uint32_t) (output_section - sections + 1);
            object_states[object_index].section_map[input_section->input_index].offset_in_output = offset_in_output;

            if (!output_section->zero_fill && new_size != 0) {
                uint8_t *next_contents;

                next_contents = realloc(output_section->contents, (size_t) new_size);
                if (next_contents == NULL) {
                    cld_set_error(error, "out of memory merging section contents");
                    goto cleanup;
                }
                if (new_size > output_section->size) {
                    memset(next_contents + output_section->size, 0, (size_t) (new_size - output_section->size));
                }
                output_section->contents = next_contents;
                if (input_section->size != 0) {
                    memcpy(output_section->contents + offset_in_output, input_section->contents, (size_t) input_section->size);
                }
            }

            output_section->size = new_size;
        }
    }

    for (section_index = 0; section_index < output_section_count; ++section_index) {
        sections[section_index].output_section_index = (uint32_t) (section_index + 1);
    }

    current_address = 0;
    load_commands_size = sizeof(struct segment_command_64)
        + output_section_count * sizeof(struct section_64)
        + sizeof(struct symtab_command)
        + (has_build_version ? sizeof(struct build_version_command) : 0);
    header_size = sizeof(struct mach_header_64) + load_commands_size;
    current_file_offset = (uint32_t) header_size;
    first_section_offset = 0;

    for (section_index = 0; section_index < output_section_count; ++section_index) {
        CldOutputSection *section;
        uint64_t alignment;

        section = &sections[section_index];
        alignment = cld_section_alignment(section);
        current_address = cld_align_up_u64(current_address, alignment);
        section->address = current_address;
        if (section->zero_fill || section->size == 0) {
            section->file_offset = 0;
        } else {
            current_file_offset = (uint32_t) cld_align_up_u64(current_file_offset, alignment);
            section->file_offset = current_file_offset;
            if (first_section_offset == 0) {
                first_section_offset = section->file_offset;
            }
            current_file_offset += (uint32_t) section->size;
        }
        current_address += section->size;
    }

    for (object_index = 0; object_index < object_count; ++object_index) {
        const CldMachOObject *object_file;

        object_file = &object_files[object_index];
        for (symbol_index = 0; symbol_index < object_file->symbol_count; ++symbol_index) {
            const CldInputSymbol *input_symbol;
            CldResolvedSymbol *resolved_symbol;
            uint8_t symbol_type;

            input_symbol = &object_file->symbols[symbol_index];
            resolved_symbol = &symbols[object_states[object_index].symbol_start + symbol_index];
            symbol_type = input_symbol->raw.n_type & N_TYPE;
            resolved_symbol->name = input_symbol->name;
            resolved_symbol->source_path = object_file->path;
            resolved_symbol->source_object_index = object_index;
            resolved_symbol->type = input_symbol->raw.n_type;
            resolved_symbol->section = input_symbol->raw.n_sect;
            resolved_symbol->description = input_symbol->raw.n_desc;
            resolved_symbol->output_index = UINT32_MAX;
            resolved_symbol->include_in_output = (input_symbol->raw.n_type & N_STAB) == 0;

            if (!resolved_symbol->include_in_output) {
                continue;
            }

            if (symbol_type == N_SECT) {
                const CldSectionMapEntry *mapped_section;
                const CldOutputSection *output_section;
                uint64_t offset_in_section;

                if (input_symbol->raw.n_sect == 0 || input_symbol->raw.n_sect > object_file->section_count) {
                    cld_set_error(error, "symbol %s references an invalid section ordinal", input_symbol->name);
                    goto cleanup;
                }

                mapped_section = &object_states[object_index].section_map[input_symbol->raw.n_sect];
                if (mapped_section->output_section_index == 0) {
                    resolved_symbol->include_in_output = false;
                    continue;
                }

                output_section = &sections[mapped_section->output_section_index - 1];
                if (input_symbol->raw.n_value < object_file->sections[input_symbol->raw.n_sect - 1].address ||
                    input_symbol->raw.n_value > object_file->sections[input_symbol->raw.n_sect - 1].address + object_file->sections[input_symbol->raw.n_sect - 1].size) {
                    cld_set_error(error, "symbol %s extends beyond its section in %s", input_symbol->name, object_file->path);
                    goto cleanup;
                }
                offset_in_section = input_symbol->raw.n_value - object_file->sections[input_symbol->raw.n_sect - 1].address;
                resolved_symbol->is_defined = true;
                resolved_symbol->section = (uint8_t) mapped_section->output_section_index;
                resolved_symbol->value = output_section->address + mapped_section->offset_in_output + offset_in_section;
            } else if (symbol_type == N_ABS) {
                resolved_symbol->is_defined = true;
                resolved_symbol->section = NO_SECT;
                resolved_symbol->value = input_symbol->raw.n_value;
            } else if (symbol_type == N_UNDF) {
                resolved_symbol->is_defined = false;
                resolved_symbol->section = NO_SECT;
                resolved_symbol->value = 0;
            } else {
                cld_set_error(error, "unsupported symbol type for %s", input_symbol->name);
                goto cleanup;
            }
        }
    }

    if (!cld_validate_unique_external_definitions(symbols, total_symbol_count, error)) {
        goto cleanup;
    }

    for (symbol_index = 0; symbol_index < total_symbol_count; ++symbol_index) {
        if (!symbols[symbol_index].include_in_output || symbols[symbol_index].is_defined) {
            continue;
        }
        if ((symbols[symbol_index].type & N_EXT) == 0) {
            continue;
        }
        if (cld_find_defined_symbol_index_by_name(symbols, total_symbol_count, symbols[symbol_index].name, true) != SIZE_MAX) {
            symbols[symbol_index].include_in_output = false;
        }
    }

    output_symbol_count = 0;
    for (int pass = 0; pass < 3; ++pass) {
        for (symbol_index = 0; symbol_index < total_symbol_count; ++symbol_index) {
            bool is_external;
            bool emit_now;

            if (!symbols[symbol_index].include_in_output) {
                continue;
            }

            is_external = (symbols[symbol_index].type & N_EXT) != 0;
            emit_now = false;
            if (pass == 0 && !is_external) {
                emit_now = true;
            } else if (pass == 1 && is_external && symbols[symbol_index].is_defined) {
                emit_now = true;
            } else if (pass == 2 && is_external && !symbols[symbol_index].is_defined) {
                emit_now = true;
            }
            if (!emit_now) {
                continue;
            }

            symbols[symbol_index].output_index = output_symbol_count++;
        }
    }

    symtab_size = (size_t) output_symbol_count * sizeof(struct nlist_64);
    if (symtab_size != 0) {
        symtab_bytes = calloc(output_symbol_count, sizeof(struct nlist_64));
        if (symtab_bytes == NULL) {
            cld_set_error(error, "out of memory allocating relocatable symbol table");
            goto cleanup;
        }
    }

    string_size = 1;
    for (symbol_index = 0; symbol_index < total_symbol_count; ++symbol_index) {
        size_t symbol_name_size;

        if (!symbols[symbol_index].include_in_output) {
            continue;
        }

        symbol_name_size = strlen(symbols[symbol_index].name) + 1;
        if (string_size > SIZE_MAX - symbol_name_size) {
            cld_set_error(error, "relocatable string table overflow");
            goto cleanup;
        }
        string_size += symbol_name_size;
    }

    string_bytes = calloc(1, string_size);
    if (string_bytes == NULL) {
        cld_set_error(error, "out of memory allocating relocatable string table");
        goto cleanup;
    }
    next_string_offset = 1;

    for (symbol_index = 0; symbol_index < total_symbol_count; ++symbol_index) {
        struct nlist_64 output_symbol;
        uint32_t string_offset;
        size_t symbol_name_size;

        if (!symbols[symbol_index].include_in_output) {
            continue;
        }

        memset(&output_symbol, 0, sizeof(output_symbol));
        symbol_name_size = strlen(symbols[symbol_index].name) + 1;
        string_offset = (uint32_t) next_string_offset;
        memcpy(string_bytes + next_string_offset, symbols[symbol_index].name, symbol_name_size);
        next_string_offset += symbol_name_size;

        output_symbol.n_un.n_strx = string_offset;
        output_symbol.n_type = symbols[symbol_index].type;
        output_symbol.n_sect = symbols[symbol_index].is_defined ? symbols[symbol_index].section : NO_SECT;
        output_symbol.n_desc = symbols[symbol_index].description;
        output_symbol.n_value = symbols[symbol_index].is_defined ? symbols[symbol_index].value : 0;
        memcpy(symtab_bytes + (size_t) symbols[symbol_index].output_index * sizeof(output_symbol),
               &output_symbol,
               sizeof(output_symbol));
    }

    for (object_index = 0; object_index < object_count; ++object_index) {
        const CldMachOObject *object_file;

        object_file = &object_files[object_index];
        for (symbol_index = 0; symbol_index < object_file->symbol_count; ++symbol_index) {
            const CldResolvedSymbol *symbol;

            symbol = &symbols[object_states[object_index].symbol_start + symbol_index];
            if (symbol->include_in_output) {
                object_states[object_index].symbol_index_map[symbol_index] = symbol->output_index;
                continue;
            }

            if (!symbol->is_defined && (symbol->type & N_EXT) != 0) {
                size_t definition_index;

                definition_index = cld_find_defined_symbol_index_by_name(symbols, total_symbol_count, symbol->name, true);
                if (definition_index != SIZE_MAX) {
                    object_states[object_index].symbol_index_map[symbol_index] = symbols[definition_index].output_index;
                    continue;
                }
            }

            object_states[object_index].symbol_index_map[symbol_index] = UINT32_MAX;
        }
    }

    for (object_index = 0; object_index < object_count; ++object_index) {
        const CldMachOObject *object_file;

        object_file = &object_files[object_index];
        for (section_index = 0; section_index < object_file->section_count; ++section_index) {
            const CldInputSection *input_section;
            const CldSectionMapEntry *mapped_section;
            CldOutputSection *output_section;
            uint32_t relocation_index;

            input_section = &object_file->sections[section_index];
            if (!cld_is_section_kept(input_section)) {
                continue;
            }

            mapped_section = &object_states[object_index].section_map[input_section->input_index];
            output_section = &sections[mapped_section->output_section_index - 1];
            for (relocation_index = 0; relocation_index < input_section->relocation_count; ++relocation_index) {
                struct relocation_info output_relocation;

                output_relocation = input_section->relocations[relocation_index];
                output_relocation.r_address += (int32_t) mapped_section->offset_in_output;
                if (output_relocation.r_extern) {
                    if (output_relocation.r_symbolnum >= object_file->symbol_count) {
                        cld_set_error(error,
                                      "relocation in %s references symbol index %u outside the symbol table",
                                      object_file->path,
                                      output_relocation.r_symbolnum);
                        goto cleanup;
                    }
                    if (object_states[object_index].symbol_index_map[output_relocation.r_symbolnum] == UINT32_MAX) {
                        cld_set_error(error,
                                      "relocation in %s references symbol %s that is not emitted",
                                      object_file->path,
                                      object_file->symbols[output_relocation.r_symbolnum].name);
                        goto cleanup;
                    }
                    output_relocation.r_symbolnum = object_states[object_index].symbol_index_map[output_relocation.r_symbolnum];
                } else {
                    if (output_relocation.r_symbolnum == 0 || output_relocation.r_symbolnum > object_file->section_count) {
                        cld_set_error(error, "local relocation references invalid section ordinal %u", output_relocation.r_symbolnum);
                        goto cleanup;
                    }
                    if (object_states[object_index].section_map[output_relocation.r_symbolnum].output_section_index == 0) {
                        cld_set_error(error, "local relocation references a section that was not emitted");
                        goto cleanup;
                    }
                    output_relocation.r_symbolnum = object_states[object_index].section_map[output_relocation.r_symbolnum].output_section_index;
                }

                if (!cld_append_output_relocation(output_section, &output_relocation, error)) {
                    goto cleanup;
                }
            }
        }
    }

    current_file_offset = (uint32_t) cld_align_up_u64(current_file_offset, 4);
    relocation_file_offset = current_file_offset;
    for (section_index = 0; section_index < output_section_count; ++section_index) {
        CldOutputSection *section;

        section = &sections[section_index];
        if (section->relocation_count == 0) {
            section->relocation_offset = 0;
            continue;
        }

        current_file_offset = (uint32_t) cld_align_up_u64(current_file_offset, 4);
        section->relocation_offset = current_file_offset;
        current_file_offset += section->relocation_count * (uint32_t) sizeof(struct relocation_info);
    }

    symtab_file_offset = (uint32_t) cld_align_up_u64(current_file_offset, 8);
    string_file_offset = symtab_file_offset + (uint32_t) symtab_size;
    file_size = (size_t) string_file_offset + string_size;
    output_bytes = calloc(1, file_size);
    if (output_bytes == NULL) {
        cld_set_error(error, "out of memory allocating relocatable output file");
        goto cleanup;
    }

    for (section_index = 0; section_index < output_section_count; ++section_index) {
        const CldOutputSection *section;

        section = &sections[section_index];
        if (!section->zero_fill && section->size != 0) {
            memcpy(output_bytes + section->file_offset, section->contents, (size_t) section->size);
        }
        if (section->relocation_count != 0) {
            memcpy(output_bytes + section->relocation_offset,
                   section->owned_relocations,
                   (size_t) section->relocation_count * sizeof(struct relocation_info));
        }
    }
    memcpy(output_bytes + symtab_file_offset, symtab_bytes, symtab_size);
    memcpy(output_bytes + string_file_offset, string_bytes, string_size);

    {
        struct mach_header_64 *header;
        uint8_t *command_cursor;
        struct segment_command_64 segment_command;
        struct symtab_command symtab_command;

        header = (struct mach_header_64 *) output_bytes;
        header->magic = MH_MAGIC_64;
        header->cputype = options->target->cpu_type;
        header->cpusubtype = options->target->cpu_subtype;
        header->filetype = MH_OBJECT;
        header->ncmds = (uint32_t) (2 + (has_build_version ? 1 : 0));
        header->sizeofcmds = (uint32_t) load_commands_size;
        header->flags = header_flags;
        header->reserved = 0;

        command_cursor = output_bytes + sizeof(*header);
        memset(&segment_command, 0, sizeof(segment_command));
        segment_command.cmd = LC_SEGMENT_64;
        segment_command.cmdsize = (uint32_t) (sizeof(segment_command) + output_section_count * sizeof(struct section_64));
        segment_command.vmaddr = 0;
        segment_command.vmsize = current_address;
        segment_command.fileoff = first_section_offset;
        segment_command.filesize = first_section_offset == 0 ? 0 : relocation_file_offset - first_section_offset;
        segment_command.maxprot = 7;
        segment_command.initprot = 7;
        segment_command.nsects = (uint32_t) output_section_count;
        memcpy(command_cursor, &segment_command, sizeof(segment_command));
        command_cursor += sizeof(segment_command);

        for (section_index = 0; section_index < output_section_count; ++section_index) {
            struct section_64 section_command;
            const CldOutputSection *section;

            section = &sections[section_index];
            memset(&section_command, 0, sizeof(section_command));
            memcpy(section_command.sectname, section->sectname, 16);
            memcpy(section_command.segname, section->segname, 16);
            section_command.addr = section->address;
            section_command.size = section->size;
            section_command.offset = section->file_offset;
            section_command.align = section->align;
            section_command.reloff = section->relocation_offset;
            section_command.nreloc = section->relocation_count;
            section_command.flags = section->flags;
            section_command.reserved1 = section->reserved1;
            section_command.reserved2 = section->reserved2;
            section_command.reserved3 = section->reserved3;
            memcpy(command_cursor, &section_command, sizeof(section_command));
            command_cursor += sizeof(section_command);
        }

        memset(&symtab_command, 0, sizeof(symtab_command));
        symtab_command.cmd = LC_SYMTAB;
        symtab_command.cmdsize = sizeof(symtab_command);
        symtab_command.symoff = symtab_file_offset;
        symtab_command.nsyms = output_symbol_count;
        symtab_command.stroff = string_file_offset;
        symtab_command.strsize = (uint32_t) string_size;
        memcpy(command_cursor, &symtab_command, sizeof(symtab_command));
        command_cursor += sizeof(symtab_command);

        if (has_build_version) {
            build_version.cmd = LC_BUILD_VERSION;
            build_version.cmdsize = sizeof(build_version);
            memcpy(command_cursor, &build_version, sizeof(build_version));
        }
    }

    if (!cld_write_entire_file(options->output_path, output_bytes, file_size, error)) {
        goto cleanup;
    }

    if (chmod(options->output_path, 0644) != 0) {
        cld_set_error(error, "wrote relocatable output but chmod failed for %s", options->output_path);
        goto cleanup;
    }

    success = true;

cleanup:
    if (object_states != NULL) {
        for (object_index = 0; object_index < object_count; ++object_index) {
            free(object_states[object_index].section_map);
            free(object_states[object_index].symbol_index_map);
        }
    }
    if (sections != NULL) {
        for (section_index = 0; section_index < output_section_count; ++section_index) {
            free(sections[section_index].owned_relocations);
            free(sections[section_index].contents);
        }
    }
    free(output_bytes);
    free(string_bytes);
    free(symtab_bytes);
    free(symbols);
    free(sections);
    free(object_states);
    return success;
}

static bool cld_link_macho_arm64_executable(const CldMachOObject *object_files,
                                            size_t object_count,
                                            const CldLinkOptions *options,
                                            CldError *error) {
    const CldTarget *target;
    const char *entry_symbol;
    uint64_t stack_size;
    CldInputObjectState *object_states;
    CldOutputSection *sections;
    CldResolvedSymbol *symbols;
    size_t total_symbol_count;
    size_t output_section_count;
    size_t section_index;
    size_t symbol_index;
    size_t object_index;
    char (*ordered_segment_names)[CLD_NAME_CAPACITY];
    size_t ordered_segment_count;
    size_t ordered_segment_index;
    size_t segment_count;
    CldOutputSegment *segments;
    size_t load_commands_size;
    size_t header_size;
    size_t file_size;
    uint64_t current_file_end;
    uint64_t current_vm_end;
    size_t linkedit_file_offset;
    size_t linkedit_size;
    uint64_t entry_file_offset;
    uint8_t *symtab_bytes;
    size_t symtab_size;
    size_t symtab_capacity;
    uint8_t *string_bytes;
    size_t string_size;
    size_t string_capacity;
    uint8_t *output_bytes;
    struct mach_header_64 *header;
    uint8_t *command_cursor;
    size_t command_count;
    size_t dylinker_command_size;
    size_t dylib_commands_size;
    uint64_t entry_value;
    size_t startup_section_index;
    uint32_t local_symbol_count;
    uint32_t external_symbol_count;
    uint32_t *import_stub_slots;
    uint32_t next_import_stub_slot;
    bool has_build_version;
    struct build_version_command build_version;
    CldImportCache import_cache;
    CldSymbolNameSet needed_dylibs;
    bool tbd_cache_hit;
    bool tbd_cache_dirty;
    bool success;

    target = options->target != NULL ? options->target : &cld_target_macos_arm64;
    entry_symbol = options->entry_symbol != NULL ? options->entry_symbol : "_main";
    stack_size = options->stack_size;
    object_states = calloc(object_count, sizeof(*object_states));
    sections = NULL;
    symbols = NULL;
    segments = NULL;
    ordered_segment_names = NULL;
    symtab_bytes = NULL;
    string_bytes = NULL;
    output_bytes = NULL;
    import_stub_slots = NULL;
    next_import_stub_slot = 0;
    dylib_commands_size = 0;
    memset(&import_cache, 0, sizeof(import_cache));
    memset(&needed_dylibs, 0, sizeof(needed_dylibs));
    tbd_cache_hit = false;
    tbd_cache_dirty = false;
    success = false;
    total_symbol_count = 0;
    output_section_count = 1;

    if (object_states == NULL) {
        cld_set_error(error, "out of memory allocating linker object state");
        goto cleanup;
    }

    if (!cld_validate_build_versions(object_files, object_count, &has_build_version, &build_version, error)) {
        goto cleanup;
    }

    if (!options->no_stdlib) {
        if (!cld_load_sdk_tbd_cache(CLD_MACOS_SDK_TBD_CACHE_PATH,
                                    &import_cache,
                                    &tbd_cache_hit,
                                    error)) {
            goto cleanup;
        }
    }

    for (object_index = 0; object_index < object_count; ++object_index) {
        object_states[object_index].input = &object_files[object_index];
        object_states[object_index].object_index = object_index;
        object_states[object_index].symbol_start = total_symbol_count;
        total_symbol_count += object_files[object_index].symbol_count;
        for (section_index = 0; section_index < object_files[object_index].section_count; ++section_index) {
            if (cld_is_section_kept(&object_files[object_index].sections[section_index])) {
                ++output_section_count;
            }
        }
        object_states[object_index].section_map = calloc(object_files[object_index].section_count + 1, sizeof(*object_states[object_index].section_map));
        object_states[object_index].symbol_index_map = NULL;
        if (object_states[object_index].section_map == NULL) {
            cld_set_error(error, "out of memory allocating section map");
            goto cleanup;
        }
    }

    sections = calloc(output_section_count, sizeof(*sections));
    symbols = calloc(total_symbol_count, sizeof(*symbols));
    segments = calloc(output_section_count, sizeof(*segments));
    ordered_segment_names = calloc(output_section_count, sizeof(*ordered_segment_names));
    if (sections == NULL || symbols == NULL || segments == NULL || ordered_segment_names == NULL) {
        cld_set_error(error, "out of memory allocating linker state");
        goto cleanup;
    }
    import_stub_slots = malloc(total_symbol_count * sizeof(*import_stub_slots));
    if (import_stub_slots == NULL) {
        cld_set_error(error, "out of memory allocating dynamic import stub map");
        goto cleanup;
    }
    for (symbol_index = 0; symbol_index < total_symbol_count; ++symbol_index) {
        import_stub_slots[symbol_index] = UINT32_MAX;
    }

    startup_section_index = 0;
    memset(&sections[startup_section_index], 0, sizeof(sections[startup_section_index]));
    if (!cld_copy_name(sections[startup_section_index].segname, SEG_TEXT) || !cld_copy_name(sections[startup_section_index].sectname, "__cld_start")) {
        cld_set_error(error, "failed to initialize startup section name");
        goto cleanup;
    }
    sections[startup_section_index].input_object_index = SIZE_MAX;
    sections[startup_section_index].flags = S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
    sections[startup_section_index].align = 2;
    sections[startup_section_index].size = CLD_STARTUP_PROLOGUE_SIZE + ((uint64_t) CLD_IMPORT_STUB_CAPACITY * CLD_IMPORT_STUB_SIZE);
    sections[startup_section_index].contents = calloc(1, (size_t) sections[startup_section_index].size);
    if (sections[startup_section_index].contents == NULL) {
        cld_set_error(error, "out of memory allocating startup section");
        goto cleanup;
    }
    cld_write_u64(sections[startup_section_index].contents + 0, 4, 0x94000000u);
    cld_write_u64(sections[startup_section_index].contents + 4, 4, 0xd2800030u);
    cld_write_u64(sections[startup_section_index].contents + 8, 4, 0xf2a40010u);
    cld_write_u64(sections[startup_section_index].contents + 12, 4, 0xd4001001u);
    cld_write_u64(sections[startup_section_index].contents + 16, 4, CLD_ARM64_B_IMM26_ZERO);

    ordered_segment_count = 0;
    if (!cld_copy_name(ordered_segment_names[ordered_segment_count++], SEG_TEXT)) {
        cld_set_error(error, "failed to record startup segment name");
        goto cleanup;
    }

    for (object_index = 0; object_index < object_count; ++object_index) {
        const CldMachOObject *object_file;

        object_file = &object_files[object_index];
        for (section_index = 0; section_index < object_file->section_count; ++section_index) {
            const CldInputSection *input_section;

            input_section = &object_file->sections[section_index];
            if (!cld_is_section_kept(input_section)) {
                continue;
            }
            if (cld_segment_name_exists(ordered_segment_names, ordered_segment_count, input_section->segname)) {
                continue;
            }
            if (!cld_copy_name(ordered_segment_names[ordered_segment_count++], input_section->segname)) {
                cld_set_error(error, "failed to record output segment name");
                goto cleanup;
            }
        }
    }

    output_section_count = 1;
    for (ordered_segment_index = 0; ordered_segment_index < ordered_segment_count; ++ordered_segment_index) {
        for (object_index = 0; object_index < object_count; ++object_index) {
            const CldMachOObject *object_file;

            object_file = &object_files[object_index];
            for (section_index = 0; section_index < object_file->section_count; ++section_index) {
                CldOutputSection *section;
                const CldInputSection *input_section;

                input_section = &object_file->sections[section_index];
                if (!cld_is_section_kept(input_section)) {
                    continue;
                }
                if (strncmp(input_section->segname, ordered_segment_names[ordered_segment_index], 16) != 0) {
                    continue;
                }

                section = &sections[output_section_count++];
                memset(section, 0, sizeof(*section));
                memcpy(section->segname, input_section->segname, CLD_NAME_CAPACITY);
                memcpy(section->sectname, input_section->sectname, CLD_NAME_CAPACITY);
                section->flags = input_section->flags;
                section->align = input_section->align;
                section->reserved1 = input_section->reserved1;
                section->reserved2 = input_section->reserved2;
                section->reserved3 = input_section->reserved3;
                section->input_object_index = object_index;
                section->input_section_index = input_section->input_index;
                section->size = input_section->size;
                section->zero_fill = ((input_section->flags & SECTION_TYPE) == S_ZEROFILL);
                section->relocations = input_section->relocations;
                section->relocation_count = input_section->relocation_count;
                if (!section->zero_fill && section->size != 0) {
                    section->contents = malloc((size_t) section->size);
                    if (section->contents == NULL) {
                        cld_set_error(error, "out of memory copying section contents");
                        goto cleanup;
                    }
                    memcpy(section->contents, input_section->contents, (size_t) section->size);
                }
                object_states[object_index].section_map[input_section->input_index].output_section_index = (uint32_t) output_section_count;
                object_states[object_index].section_map[input_section->input_index].offset_in_output = 0;
            }
        }
    }

    segment_count = 0;
    for (section_index = 0; section_index < output_section_count; ++section_index) {
        CldOutputSection *section;
        ssize_t existing_segment;

        section = &sections[section_index];
        existing_segment = cld_find_segment(segments, segment_count, section->segname);
        if (existing_segment < 0) {
            CldOutputSegment *segment;

            segment = &segments[segment_count++];
            memset(segment, 0, sizeof(*segment));
            memcpy(segment->segname, section->segname, CLD_NAME_CAPACITY);
            segment->maxprot = cld_segment_maxprot_for_name(section->segname);
            segment->initprot = cld_segment_initprot_for_name(section->segname);
            segment->section_start = (uint32_t) section_index;
            segment->section_count = 1;
        } else {
            ++segments[existing_segment].section_count;
        }
    }

    if (segment_count == 0 || strcmp(segments[0].segname, SEG_TEXT) != 0) {
        cld_set_error(error, "the first output segment must be __TEXT");
        goto cleanup;
    }

    if (!options->no_stdlib) {
        if (!cld_symbol_name_set_add(&needed_dylibs,
                                     "/usr/lib/libSystem.B.dylib",
                                     error)) {
            goto cleanup;
        }
    }

    dylinker_command_size = sizeof(struct dylinker_command) + sizeof("/usr/lib/dyld");
    if (!options->no_stdlib) {
        for (size_t dylib_index = 0; dylib_index < needed_dylibs.count; ++dylib_index) {
            size_t raw_size;
            const char *dylib_name = needed_dylibs.names[dylib_index];
            if (dylib_name == NULL || dylib_name[0] == '\0') {
                continue;
            }
            raw_size = sizeof(struct dylib_command) + strlen(dylib_name) + 1;
            dylib_commands_size += cld_aligned_command_size(raw_size);
        }
    }
    command_count = 1 + segment_count + 1 + 1 + 1 + 1 + (options->no_stdlib ? 0 : needed_dylibs.count) + (has_build_version ? 1 : 0);
    load_commands_size = sizeof(struct segment_command_64)
        + sizeof(struct segment_command_64)
        + cld_load_command_size_for_segments(segments, segment_count)
        + sizeof(struct symtab_command)
        + sizeof(struct dysymtab_command)
        + cld_aligned_command_size(dylinker_command_size)
        + sizeof(struct entry_point_command)
        + (options->no_stdlib ? 0 : dylib_commands_size)
        + (has_build_version ? sizeof(struct build_version_command) : 0);
    header_size = sizeof(struct mach_header_64) + load_commands_size + sizeof(struct linkedit_data_command);

    current_file_end = 0;
    current_vm_end = target->image_base;
    for (size_t segment_index = 0; segment_index < segment_count; ++segment_index) {
        CldOutputSegment *segment;
        uint64_t relative_file_size;
        uint64_t relative_vm_size;

        segment = &segments[segment_index];
        if (segment_index == 0) {
            segment->fileoff = 0;
            segment->vmaddr = target->image_base;
            relative_file_size = header_size;
            relative_vm_size = header_size;
        } else {
            segment->fileoff = cld_align_up_u64(current_file_end, target->page_size);
            segment->vmaddr = cld_align_up_u64(current_vm_end, target->page_size);
            relative_file_size = 0;
            relative_vm_size = 0;
        }

        for (section_index = segment->section_start; section_index < segment->section_start + segment->section_count; ++section_index) {
            CldOutputSection *section;
            uint64_t alignment;

            section = &sections[section_index];
            alignment = cld_section_alignment(section);
            if (section->zero_fill) {
                relative_vm_size = cld_align_up_u64(relative_vm_size, alignment);
                section->address = segment->vmaddr + relative_vm_size;
                section->file_offset = 0;
                relative_vm_size += section->size;
            } else {
                relative_file_size = cld_align_up_u64(relative_file_size, alignment);
                relative_vm_size = cld_align_up_u64(relative_vm_size, alignment);
                relative_vm_size = cld_max_u64(relative_vm_size, relative_file_size);
                section->address = segment->vmaddr + relative_file_size;
                section->file_offset = (uint32_t) (segment->fileoff + relative_file_size);
                relative_file_size += section->size;
                relative_vm_size = cld_max_u64(relative_vm_size, relative_file_size);
            }
            section->output_section_index = (uint32_t) (section_index + 1);
            if (section->input_object_index != SIZE_MAX) {
                object_states[section->input_object_index].section_map[section->input_section_index].output_section_index = (uint32_t) (section_index + 1);
            }
        }

        segment->filesize = relative_file_size == 0 ? 0 : cld_align_up_u64(relative_file_size, target->page_size);
        segment->vmsize = cld_align_up_u64(cld_max_u64(relative_vm_size, segment->filesize), target->page_size);
        current_file_end = segment->fileoff + segment->filesize;
        current_vm_end = segment->vmaddr + segment->vmsize;
    }

    for (object_index = 0; object_index < object_count; ++object_index) {
        const CldMachOObject *object_file;

        object_file = &object_files[object_index];
        for (symbol_index = 0; symbol_index < object_file->symbol_count; ++symbol_index) {
            const CldInputSymbol *input_symbol;
            CldResolvedSymbol *resolved_symbol;
            uint8_t symbol_type;

            input_symbol = &object_file->symbols[symbol_index];
            resolved_symbol = &symbols[object_states[object_index].symbol_start + symbol_index];
            symbol_type = input_symbol->raw.n_type & N_TYPE;
            resolved_symbol->name = input_symbol->name;
            resolved_symbol->source_path = object_file->path;
            resolved_symbol->type = input_symbol->raw.n_type;
            resolved_symbol->section = input_symbol->raw.n_sect;
            resolved_symbol->description = input_symbol->raw.n_desc;
            resolved_symbol->output_index = UINT32_MAX;
            resolved_symbol->source_object_index = object_index;
            resolved_symbol->include_in_output = ((input_symbol->raw.n_type & N_STAB) == 0) && (symbol_type == N_SECT || symbol_type == N_ABS);

            if (symbol_type == N_SECT) {
                const CldSectionMapEntry *mapped_section;
                const CldOutputSection *output_section;
                uint64_t offset_in_section;

                if (input_symbol->raw.n_sect == 0 || input_symbol->raw.n_sect > object_file->section_count) {
                    cld_set_error(error, "symbol %s references an invalid section ordinal", input_symbol->name);
                    goto cleanup;
                }

                mapped_section = &object_states[object_index].section_map[input_symbol->raw.n_sect];
                if (mapped_section->output_section_index == 0) {
                    if ((input_symbol->raw.n_type & N_EXT) != 0) {
                        cld_set_error(error, "exported symbol %s lives in a section that is not emitted", input_symbol->name);
                        goto cleanup;
                    }
                    resolved_symbol->is_defined = false;
                    continue;
                }

                output_section = &sections[mapped_section->output_section_index - 1];
                if (input_symbol->raw.n_value < object_file->sections[input_symbol->raw.n_sect - 1].address ||
                    input_symbol->raw.n_value > object_file->sections[input_symbol->raw.n_sect - 1].address + object_file->sections[input_symbol->raw.n_sect - 1].size) {
                    cld_set_error(error, "symbol %s extends beyond its section in %s", input_symbol->name, object_file->path);
                    goto cleanup;
                }
                offset_in_section = input_symbol->raw.n_value - object_file->sections[input_symbol->raw.n_sect - 1].address;
                resolved_symbol->is_defined = true;
                resolved_symbol->section = (uint8_t) mapped_section->output_section_index;
                resolved_symbol->value = output_section->address + offset_in_section;
            } else if (symbol_type == N_ABS) {
                resolved_symbol->is_defined = true;
                resolved_symbol->value = input_symbol->raw.n_value;
            } else if (symbol_type == N_UNDF) {
                resolved_symbol->is_defined = false;
            } else {
                cld_set_error(error, "unsupported symbol type for %s", input_symbol->name);
                goto cleanup;
            }
        }
    }

    if (!cld_validate_unique_external_definitions(symbols, total_symbol_count, error)) {
        goto cleanup;
    }

    for (symbol_index = 0; symbol_index < total_symbol_count; ++symbol_index) {
        if (symbols[symbol_index].is_defined) {
            continue;
        }
        if ((symbols[symbol_index].type & N_EXT) == 0) {
            continue;
        }
        if (!cld_lookup_defined_symbol_by_name(symbols, total_symbol_count, symbols[symbol_index].name, true, &symbols[symbol_index].value, error) &&
            !cld_lookup_defined_symbol_by_name(symbols, total_symbol_count, symbols[symbol_index].name, false, &symbols[symbol_index].value, error)) {
            const char *cached_dylib;
            char resolved_dylib[1024];

            if (options->no_stdlib) {
                cld_set_error(error, "undefined symbol %s is not supported yet", symbols[symbol_index].name);
                goto cleanup;
            }

            cached_dylib = cld_import_cache_lookup(&import_cache, symbols[symbol_index].name);
            if (cached_dylib == NULL) {
                if (!cld_find_symbol_dylib_in_sdk_tbd_dir(CLD_MACOS_SDK_USR_LIB_DIR,
                                                          symbols[symbol_index].name,
                                                          resolved_dylib,
                                                          sizeof(resolved_dylib),
                                                          error)) {
                    cld_log_nearby_defined_symbols(symbols,
                                                   total_symbol_count,
                                                   symbols[symbol_index].name);
                    cld_set_error(error,
                                  "undefined symbol %s (not found in linked objects or SDK dylib exports)",
                                  symbols[symbol_index].name);
                    goto cleanup;
                }
                if (!cld_import_cache_upsert(&import_cache,
                                             symbols[symbol_index].name,
                                             resolved_dylib,
                                             error)) {
                    goto cleanup;
                }
                cached_dylib = cld_import_cache_lookup(&import_cache, symbols[symbol_index].name);
                tbd_cache_dirty = true;
            }
            free(symbols[symbol_index].dynamic_import_dylib);
            symbols[symbol_index].dynamic_import_dylib = cached_dylib != NULL ? strdup(cached_dylib) : NULL;
            if (cached_dylib != NULL && symbols[symbol_index].dynamic_import_dylib == NULL) {
                cld_set_error(error,
                              "out of memory recording import dylib for %s",
                              symbols[symbol_index].name);
                goto cleanup;
            }
            symbols[symbol_index].is_dynamic_import = true;
            continue;
        }
        symbols[symbol_index].is_defined = true;
    }

    if (tbd_cache_dirty) {
        if (!cld_write_sdk_tbd_cache(CLD_MACOS_SDK_TBD_CACHE_PATH,
                                     &import_cache,
                                     error)) {
            goto cleanup;
        }
    }

    if (!cld_lookup_defined_symbol_by_name(symbols, total_symbol_count, entry_symbol, false, &entry_value, error)) {
        cld_set_error(error, "entry symbol %s was not found in the linked objects", entry_symbol);
        goto cleanup;
    }

    if (!cld_patch_branch26(sections[startup_section_index].contents, sections[startup_section_index].address, entry_value, error)) {
        goto cleanup;
    }

    entry_file_offset = sections[startup_section_index].file_offset;

    if (!cld_apply_relocations(target,
                               sections,
                               output_section_count,
                               object_states,
                               symbols,
                               &sections[startup_section_index],
                               import_stub_slots,
                               total_symbol_count,
                               &next_import_stub_slot,
                               error)) {
        goto cleanup;
    }

    symtab_size = 0;
    symtab_capacity = 0;
    string_size = 0;
    string_capacity = 0;
    local_symbol_count = 0;
    external_symbol_count = 0;
    if (!cld_append_bytes(&string_bytes, &string_size, &string_capacity, "", 1, error)) {
        goto cleanup;
    }

    for (int pass = 0; pass < 2; ++pass) {
        for (symbol_index = 0; symbol_index < total_symbol_count; ++symbol_index) {
            struct nlist_64 output_symbol;
            uint32_t string_offset;
            bool is_external;

            if (!symbols[symbol_index].include_in_output || !symbols[symbol_index].is_defined) {
                continue;
            }

            is_external = (symbols[symbol_index].type & N_EXT) != 0;
            if ((pass == 0 && is_external) || (pass == 1 && !is_external)) {
                continue;
            }

            memset(&output_symbol, 0, sizeof(output_symbol));
            if (!cld_append_string(&string_bytes, &string_size, &string_capacity, symbols[symbol_index].name, &string_offset, error)) {
                goto cleanup;
            }

            output_symbol.n_un.n_strx = string_offset;
            output_symbol.n_type = symbols[symbol_index].type;
            output_symbol.n_sect = symbols[symbol_index].section;
            output_symbol.n_desc = symbols[symbol_index].description;
            output_symbol.n_value = symbols[symbol_index].value;
            if (!cld_append_bytes(&symtab_bytes, &symtab_size, &symtab_capacity, &output_symbol, sizeof(output_symbol), error)) {
                goto cleanup;
            }

            if (is_external) {
                ++external_symbol_count;
            } else {
                ++local_symbol_count;
            }
        }
    }

    linkedit_file_offset = (size_t) cld_align_up_u64(current_file_end, target->page_size);
    linkedit_size = symtab_size + string_size;
    file_size = linkedit_file_offset + linkedit_size;
    output_bytes = calloc(1, file_size);
    if (output_bytes == NULL) {
        cld_set_error(error, "out of memory allocating output file");
        goto cleanup;
    }

    for (section_index = 0; section_index < output_section_count; ++section_index) {
        const CldOutputSection *section;

        section = &sections[section_index];
        if (section->zero_fill || section->size == 0) {
            continue;
        }
        memcpy(output_bytes + section->file_offset, section->contents, (size_t) section->size);
    }
    memcpy(output_bytes + linkedit_file_offset, symtab_bytes, symtab_size);
    memcpy(output_bytes + linkedit_file_offset + symtab_size, string_bytes, string_size);

    header = (struct mach_header_64 *) output_bytes;
    header->magic = MH_MAGIC_64;
    header->cputype = target->cpu_type;
    header->cpusubtype = target->cpu_subtype;
    header->filetype = MH_EXECUTE;
    header->ncmds = (uint32_t) command_count;
    header->sizeofcmds = (uint32_t) load_commands_size;
    header->flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE;
    header->reserved = 0;

    command_cursor = output_bytes + sizeof(*header);
    {
        struct segment_command_64 page_zero;

        memset(&page_zero, 0, sizeof(page_zero));
        page_zero.cmd = LC_SEGMENT_64;
        page_zero.cmdsize = sizeof(page_zero);
        memcpy(page_zero.segname, SEG_PAGEZERO, sizeof(SEG_PAGEZERO));
        page_zero.vmaddr = 0;
        page_zero.vmsize = target->page_zero_size;
        page_zero.fileoff = 0;
        page_zero.filesize = 0;
        page_zero.maxprot = 0;
        page_zero.initprot = 0;
        memcpy(command_cursor, &page_zero, sizeof(page_zero));
        command_cursor += sizeof(page_zero);
    }

    for (size_t segment_index = 0; segment_index < segment_count; ++segment_index) {
        struct segment_command_64 segment_command;
        const CldOutputSegment *segment;

        segment = &segments[segment_index];
        memset(&segment_command, 0, sizeof(segment_command));
        segment_command.cmd = LC_SEGMENT_64;
        segment_command.cmdsize = (uint32_t) (sizeof(segment_command) + segment->section_count * sizeof(struct section_64));
        memcpy(segment_command.segname, segment->segname, 16);
        segment_command.vmaddr = segment->vmaddr;
        segment_command.vmsize = segment->vmsize;
        segment_command.fileoff = segment->fileoff;
        segment_command.filesize = segment->filesize;
        segment_command.maxprot = segment->maxprot;
        segment_command.initprot = segment->initprot;
        segment_command.nsects = segment->section_count;
        memcpy(command_cursor, &segment_command, sizeof(segment_command));
        command_cursor += sizeof(segment_command);

        for (section_index = segment->section_start; section_index < segment->section_start + segment->section_count; ++section_index) {
            struct section_64 section_command;
            const CldOutputSection *section;

            section = &sections[section_index];
            memset(&section_command, 0, sizeof(section_command));
            memcpy(section_command.sectname, section->sectname, 16);
            memcpy(section_command.segname, section->segname, 16);
            section_command.addr = section->address;
            section_command.size = section->size;
            section_command.offset = section->file_offset;
            section_command.align = section->align;
            section_command.reloff = 0;
            section_command.nreloc = 0;
            section_command.flags = section->flags;
            section_command.reserved1 = section->reserved1;
            section_command.reserved2 = section->reserved2;
            section_command.reserved3 = section->reserved3;
            memcpy(command_cursor, &section_command, sizeof(section_command));
            command_cursor += sizeof(section_command);
        }
    }

    {
        struct segment_command_64 linkedit_segment;

        memset(&linkedit_segment, 0, sizeof(linkedit_segment));
        linkedit_segment.cmd = LC_SEGMENT_64;
        linkedit_segment.cmdsize = sizeof(linkedit_segment);
        memcpy(linkedit_segment.segname, SEG_LINKEDIT, sizeof(SEG_LINKEDIT));
        linkedit_segment.vmaddr = cld_align_up_u64(current_vm_end, target->page_size);
        linkedit_segment.vmsize = cld_align_up_u64(linkedit_size, target->page_size);
        linkedit_segment.fileoff = linkedit_file_offset;
        linkedit_segment.filesize = linkedit_size;
        linkedit_segment.maxprot = 1;
        linkedit_segment.initprot = 1;
        memcpy(command_cursor, &linkedit_segment, sizeof(linkedit_segment));
        command_cursor += sizeof(linkedit_segment);
    }

    {
        struct symtab_command symtab_command;

        memset(&symtab_command, 0, sizeof(symtab_command));
        symtab_command.cmd = LC_SYMTAB;
        symtab_command.cmdsize = sizeof(symtab_command);
        symtab_command.symoff = (uint32_t) linkedit_file_offset;
        symtab_command.nsyms = (uint32_t) (symtab_size / sizeof(struct nlist_64));
        symtab_command.stroff = (uint32_t) (linkedit_file_offset + symtab_size);
        symtab_command.strsize = (uint32_t) string_size;
        memcpy(command_cursor, &symtab_command, sizeof(symtab_command));
        command_cursor += sizeof(symtab_command);
    }

    {
        struct dysymtab_command dysymtab_command;

        memset(&dysymtab_command, 0, sizeof(dysymtab_command));
        dysymtab_command.cmd = LC_DYSYMTAB;
        dysymtab_command.cmdsize = sizeof(dysymtab_command);
        dysymtab_command.ilocalsym = 0;
        dysymtab_command.nlocalsym = local_symbol_count;
        dysymtab_command.iextdefsym = local_symbol_count;
        dysymtab_command.nextdefsym = external_symbol_count;
        dysymtab_command.iundefsym = local_symbol_count + external_symbol_count;
        dysymtab_command.nundefsym = 0;
        memcpy(command_cursor, &dysymtab_command, sizeof(dysymtab_command));
        command_cursor += sizeof(dysymtab_command);
    }

    if (has_build_version) {
        build_version.cmd = LC_BUILD_VERSION;
        build_version.cmdsize = sizeof(build_version);
        memcpy(command_cursor, &build_version, sizeof(build_version));
        command_cursor += sizeof(build_version);
    }

    {
        struct dylinker_command dylinker_command;
        uint8_t raw_command[sizeof(struct dylinker_command) + sizeof("/usr/lib/dyld")];

        memset(raw_command, 0, sizeof(raw_command));
        memset(&dylinker_command, 0, sizeof(dylinker_command));
        dylinker_command.cmd = LC_LOAD_DYLINKER;
        dylinker_command.cmdsize = cld_aligned_command_size(sizeof(raw_command));
        dylinker_command.name.offset = sizeof(dylinker_command);
        memcpy(raw_command, &dylinker_command, sizeof(dylinker_command));
        memcpy(raw_command + sizeof(dylinker_command), "/usr/lib/dyld", sizeof("/usr/lib/dyld"));
        cld_write_padded_command(&command_cursor, raw_command, sizeof(raw_command));
    }

    {
        struct entry_point_command entry_point_command;

        memset(&entry_point_command, 0, sizeof(entry_point_command));
        entry_point_command.cmd = LC_MAIN;
        entry_point_command.cmdsize = sizeof(entry_point_command);
        entry_point_command.entryoff = entry_file_offset;
        entry_point_command.stacksize = stack_size;
        memcpy(command_cursor, &entry_point_command, sizeof(entry_point_command));
        command_cursor += sizeof(entry_point_command);
    }

    if (!options->no_stdlib) {
        for (size_t dylib_index = 0; dylib_index < needed_dylibs.count; ++dylib_index) {
            struct dylib_command dylib_command;
            size_t dylib_name_length;
            size_t raw_size;
            size_t command_size;
            uint8_t *raw_command;
            const char *dylib_name = needed_dylibs.names[dylib_index];

            if (dylib_name == NULL || dylib_name[0] == '\0') {
                continue;
            }
            dylib_name_length = strlen(dylib_name) + 1;
            raw_size = sizeof(struct dylib_command) + dylib_name_length;
            command_size = cld_aligned_command_size(raw_size);
            raw_command = (uint8_t *) calloc(1, command_size);
            if (raw_command == NULL) {
                cld_set_error(error, "out of memory creating LC_LOAD_DYLIB for %s", dylib_name);
                goto cleanup;
            }

            memset(&dylib_command, 0, sizeof(dylib_command));
            dylib_command.cmd = LC_LOAD_DYLIB;
            dylib_command.cmdsize = (uint32_t) command_size;
            dylib_command.dylib.name.offset = sizeof(dylib_command);
            memcpy(raw_command, &dylib_command, sizeof(dylib_command));
            memcpy(raw_command + sizeof(dylib_command), dylib_name, dylib_name_length);
            memcpy(command_cursor, raw_command, command_size);
            command_cursor += command_size;
            free(raw_command);
        }
    }

    if (!cld_write_entire_file(options->output_path, output_bytes, file_size, error)) {
        goto cleanup;
    }

    if (chmod(options->output_path, 0755) != 0) {
        cld_set_error(error, "linked output was written but chmod failed for %s", options->output_path);
        goto cleanup;
    }

    if (!cld_run_codesign(options->output_path, error)) {
        goto cleanup;
    }

    if (!cld_fixup_codesign_load_commands(options->output_path, error)) {
        goto cleanup;
    }

    success = true;

cleanup:
    if (object_states != NULL) {
        for (object_index = 0; object_index < object_count; ++object_index) {
            free(object_states[object_index].section_map);
            free(object_states[object_index].symbol_index_map);
        }
    }
    if (sections != NULL) {
        for (section_index = 0; section_index < output_section_count; ++section_index) {
            free(sections[section_index].owned_relocations);
            free(sections[section_index].contents);
        }
    }
    for (symbol_index = 0; symbol_index < total_symbol_count; ++symbol_index) {
        free(symbols[symbol_index].dynamic_import_dylib);
        symbols[symbol_index].dynamic_import_dylib = NULL;
    }
    free(output_bytes);
    free(import_stub_slots);
    cld_symbol_name_set_destroy(&needed_dylibs);
    free(string_bytes);
    free(symtab_bytes);
    cld_import_cache_destroy(&import_cache);
    free(ordered_segment_names);
    free(segments);
    free(symbols);
    free(sections);
    free(object_states);
    return success;
}

bool cld_link_objects(const CldMachOObject *object_files, size_t object_count, const CldLinkOptions *options, CldError *error) {
    if (object_count == 0) {
        cld_set_error(error, "no input objects were provided");
        return false;
    }

    if (options->target == NULL) {
        cld_set_error(error, "no target was selected");
        return false;
    }

    if (options->target->object_format == CLD_OBJECT_FORMAT_ELF) {
        cld_set_error(error,
                      "self-hosted ELF linking is not implemented for target %s (external compiler/linker fallback is disabled)",
                      options->target->name);
        return false;
    }

    if (options->output_kind == CLD_OUTPUT_KIND_RELOCATABLE) {
        if (options->target->cpu_type != CPU_TYPE_ARM64 || options->target->platform != PLATFORM_MACOS) {
            cld_set_error(error, "relocatable emission is not implemented for target %s", options->target->name);
            return false;
        }
        return cld_emit_macho_relocatable(object_files, object_count, options, error);
    }

    if (options->output_kind == CLD_OUTPUT_KIND_EXECUTABLE) {
        if (options->target->cpu_type != CPU_TYPE_ARM64 || options->target->platform != PLATFORM_MACOS) {
            cld_set_error(error, "executable emission is not implemented for target %s", options->target->name);
            return false;
        }
        return cld_link_macho_arm64_executable(object_files, object_count, options, error);
    }

    cld_set_error(error, "unsupported output kind");
    return false;
}
