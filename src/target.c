#include "cld/target.h"

#include <stddef.h>
#include <string.h>

static const CldTarget *const cld_targets[] = {
    &cld_target_macos_arm64,
    &cld_target_x86_64_elf,
};

const CldTarget *cld_default_target(void) {
    return cld_targets[0];
}

const CldTarget *cld_find_target(const char *name) {
    size_t index;

    for (index = 0; index < sizeof(cld_targets) / sizeof(cld_targets[0]); ++index) {
        if (strcmp(cld_targets[index]->name, name) == 0) {
            return cld_targets[index];
        }
    }

    return NULL;
}

size_t cld_target_count(void) {
    return sizeof(cld_targets) / sizeof(cld_targets[0]);
}

const CldTarget *cld_target_at(size_t index) {
    if (index >= cld_target_count()) {
        return NULL;
    }

    return cld_targets[index];
}
