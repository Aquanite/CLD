#ifndef CLD_COMMON_H
#define CLD_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#include <stdlib.h>
#include <string.h>
#ifndef strdup
#define strdup _strdup
#endif
#ifndef HAVE_STRNLEN
static inline size_t cld_strnlen_fallback(const char *value, size_t max_len) {
    size_t len = 0;
    while (len < max_len && value[len] != '\0') {
        ++len;
    }
    return len;
}
#define strnlen cld_strnlen_fallback
#endif
#endif

#define CLD_NAME_CAPACITY 17

typedef struct {
    char message[512];
} CldError;

void cld_set_error(CldError *error, const char *format, ...);
bool cld_read_entire_file(const char *path, uint8_t **data, size_t *size, CldError *error);
bool cld_write_entire_file(const char *path, const uint8_t *data, size_t size, CldError *error);
uint64_t cld_align_up_u64(uint64_t value, uint64_t alignment);
uint64_t cld_max_u64(uint64_t left, uint64_t right);
uint64_t cld_min_u64(uint64_t left, uint64_t right);
int64_t cld_sign_extend_u32(uint32_t value, unsigned width);
bool cld_append_bytes(uint8_t **buffer, size_t *size, size_t *capacity, const void *data, size_t data_size, CldError *error);

#endif
