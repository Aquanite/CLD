#ifndef CLD_TARGET_H
#define CLD_TARGET_H

#include <stdbool.h>
#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CLD_OBJECT_FORMAT_MACHO,
    CLD_OBJECT_FORMAT_ELF,
} CldObjectFormat;

typedef struct {
    const char *name;
    CldObjectFormat object_format;
    bool host_native;
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    uint64_t page_size;
    uint64_t image_base;
    uint64_t page_zero_size;
    uint64_t default_stack_size;
    uint64_t stack_top;
} CldTarget;

extern const CldTarget cld_target_macos_arm64;
extern const CldTarget cld_target_x86_64_elf;

const CldTarget *cld_default_target(void);
const CldTarget *cld_find_target(const char *name);
size_t cld_target_count(void);
const CldTarget *cld_target_at(size_t index);

#endif
