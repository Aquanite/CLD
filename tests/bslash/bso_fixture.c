#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char magic[4];
    uint32_t version;
    uint32_t code_size;
    uint32_t symbol_count;
    uint32_t relocation_count;
    uint32_t string_table_size;
} bso_header_t;

typedef struct {
    uint32_t name_offset;
    uint32_t value;
    uint32_t flags;
} bso_symbol_record_t;

typedef struct {
    uint32_t offset;
    int32_t addend;
    uint32_t symbol_index;
    uint32_t kind;
} bso_relocation_record_t;

#define BSO_VERSION 1u
#define BSO_SYMBOL_DEFINED (1u << 0)
#define BSO_SYMBOL_GLOBAL  (1u << 1)
#define BSO_RELOC_ABS32 3u

static void fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

static void write_file(const char *path,
                       const uint8_t *code,
                       size_t code_size,
                       const bso_symbol_record_t *symbols,
                       size_t symbol_count,
                       const bso_relocation_record_t *relocations,
                       size_t relocation_count,
                       const uint8_t *strings,
                       size_t string_size) {
    FILE *file;
    bso_header_t header;

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, "BSO1", 4);
    header.version = BSO_VERSION;
    header.code_size = (uint32_t) code_size;
    header.symbol_count = (uint32_t) symbol_count;
    header.relocation_count = (uint32_t) relocation_count;
    header.string_table_size = (uint32_t) string_size;

    file = fopen(path, "wb");
    if (file == NULL) {
        fail("failed to open output fixture");
    }

    if (fwrite(&header, sizeof(header), 1, file) != 1) {
        fail("failed to write fixture header");
    }
    if (code_size != 0 && fwrite(code, 1, code_size, file) != code_size) {
        fail("failed to write fixture code");
    }
    if (symbol_count != 0 && fwrite(symbols, sizeof(*symbols), symbol_count, file) != symbol_count) {
        fail("failed to write fixture symbols");
    }
    if (relocation_count != 0 && fwrite(relocations, sizeof(*relocations), relocation_count, file) != relocation_count) {
        fail("failed to write fixture relocations");
    }
    if (string_size != 0 && fwrite(strings, 1, string_size, file) != string_size) {
        fail("failed to write fixture strings");
    }
    fclose(file);
}

static void emit_abs_ref(const char *path) {
    static const uint8_t code[] = {0x00, 0x00, 0x00, 0x00};
    static const uint8_t strings[] = {0x00, 't', 'a', 'r', 'g', 'e', 't', 0x00};
    static const bso_symbol_record_t symbols[] = {
        {1, 0, BSO_SYMBOL_GLOBAL},
    };
    static const bso_relocation_record_t relocations[] = {
        {0, 0, 0, BSO_RELOC_ABS32},
    };

    write_file(path,
               code,
               sizeof(code),
               symbols,
               sizeof(symbols) / sizeof(symbols[0]),
               relocations,
               sizeof(relocations) / sizeof(relocations[0]),
               strings,
               sizeof(strings));
}

static void emit_target(const char *path) {
    static const uint8_t code[] = {0x11, 0x22, 0x33, 0x44};
    static const uint8_t strings[] = {0x00, 't', 'a', 'r', 'g', 'e', 't', 0x00};
    static const bso_symbol_record_t symbols[] = {
        {1, 0, BSO_SYMBOL_GLOBAL | BSO_SYMBOL_DEFINED},
    };

    write_file(path,
               code,
               sizeof(code),
               symbols,
               sizeof(symbols) / sizeof(symbols[0]),
               NULL,
               0,
               strings,
               sizeof(strings));
}

static void emit_dup_a(const char *path) {
    static const uint8_t code[] = {0xaa};
    static const uint8_t strings[] = {0x00, 'd', 'u', 'p', 0x00};
    static const bso_symbol_record_t symbols[] = {
        {1, 0, BSO_SYMBOL_GLOBAL | BSO_SYMBOL_DEFINED},
    };

    write_file(path,
               code,
               sizeof(code),
               symbols,
               sizeof(symbols) / sizeof(symbols[0]),
               NULL,
               0,
               strings,
               sizeof(strings));
}

static void emit_dup_b(const char *path) {
    static const uint8_t code[] = {0xbb};
    static const uint8_t strings[] = {0x00, 'd', 'u', 'p', 0x00};
    static const bso_symbol_record_t symbols[] = {
        {1, 0, BSO_SYMBOL_GLOBAL | BSO_SYMBOL_DEFINED},
    };

    write_file(path,
               code,
               sizeof(code),
               symbols,
               sizeof(symbols) / sizeof(symbols[0]),
               NULL,
               0,
               strings,
               sizeof(strings));
}

static const char *string_at(const uint8_t *strings, uint32_t string_size, uint32_t offset) {
    if (offset >= string_size) {
        fail("invalid string offset in BSO file");
    }
    return (const char *) (strings + offset);
}

static void check_merged(const char *path) {
    FILE *file;
    bso_header_t header;
    uint8_t code[8];
    bso_symbol_record_t symbol;
    bso_relocation_record_t relocation;
    uint8_t strings[8];

    file = fopen(path, "rb");
    if (file == NULL) {
        fail("failed to open merged BSO file");
    }
    if (fread(&header, sizeof(header), 1, file) != 1) {
        fail("failed to read merged BSO header");
    }
    if (memcmp(header.magic, "BSO1", 4) != 0 ||
        header.version != BSO_VERSION ||
        header.code_size != 8 ||
        header.symbol_count != 1 ||
        header.relocation_count != 1 ||
        header.string_table_size != 8) {
        fail("merged BSO header did not match expectations");
    }
    if (fread(code, 1, sizeof(code), file) != sizeof(code)) {
        fail("failed to read merged BSO code");
    }
    if (fread(&symbol, sizeof(symbol), 1, file) != 1) {
        fail("failed to read merged BSO symbol");
    }
    if (fread(&relocation, sizeof(relocation), 1, file) != 1) {
        fail("failed to read merged BSO relocation");
    }
    if (fread(strings, 1, sizeof(strings), file) != sizeof(strings)) {
        fail("failed to read merged BSO strings");
    }
    fclose(file);

    if (memcmp(code, "\0\0\0\0\x11\x22\x33\x44", sizeof(code)) != 0) {
        fail("merged BSO code bytes were not preserved");
    }
    if (strcmp(string_at(strings, sizeof(strings), symbol.name_offset), "target") != 0) {
        fail("merged BSO symbol name mismatch");
    }
    if (symbol.value != 4 || symbol.flags != (BSO_SYMBOL_GLOBAL | BSO_SYMBOL_DEFINED)) {
        fail("merged BSO symbol value mismatch");
    }
    if (relocation.offset != 0 || relocation.addend != 0 || relocation.symbol_index != 0 || relocation.kind != BSO_RELOC_ABS32) {
        fail("merged BSO relocation mismatch");
    }
}

static void check_bin(const char *path) {
    FILE *file;
    uint8_t bytes[8];

    file = fopen(path, "rb");
    if (file == NULL) {
        fail("failed to open raw BSO output");
    }
    if (fread(bytes, 1, sizeof(bytes), file) != sizeof(bytes)) {
        fail("failed to read raw BSO output");
    }
    fclose(file);

    if (memcmp(bytes, "\x04\x00\x00\x00\x11\x22\x33\x44", sizeof(bytes)) != 0) {
        fail("linked raw BSO output mismatch");
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fail("usage: bso_fixture <command> <path>");
    }

    if (strcmp(argv[1], "emit-abs-ref") == 0) {
        emit_abs_ref(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "emit-target") == 0) {
        emit_target(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "emit-dup-a") == 0) {
        emit_dup_a(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "emit-dup-b") == 0) {
        emit_dup_b(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "check-merged") == 0) {
        check_merged(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "check-bin") == 0) {
        check_bin(argv[2]);
        return 0;
    }

    fail("unknown fixture command");
    return 1;
}