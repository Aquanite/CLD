#include "cld/common.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cld_set_error(CldError *error, const char *format, ...) {
    va_list arguments;

    if (error == NULL) {
        return;
    }

    va_start(arguments, format);
    vsnprintf(error->message, sizeof(error->message), format, arguments);
    va_end(arguments);
}

bool cld_read_entire_file(const char *path, uint8_t **data, size_t *size, CldError *error) {
    FILE *file_handle;
    long file_size;
    uint8_t *buffer;

    *data = NULL;
    *size = 0;

    file_handle = fopen(path, "rb");
    if (file_handle == NULL) {
        cld_set_error(error, "failed to open %s: %s", path, strerror(errno));
        return false;
    }

    if (fseek(file_handle, 0, SEEK_END) != 0) {
        cld_set_error(error, "failed to seek %s: %s", path, strerror(errno));
        fclose(file_handle);
        return false;
    }

    file_size = ftell(file_handle);
    if (file_size < 0) {
        cld_set_error(error, "failed to size %s: %s", path, strerror(errno));
        fclose(file_handle);
        return false;
    }

    if (fseek(file_handle, 0, SEEK_SET) != 0) {
        cld_set_error(error, "failed to rewind %s: %s", path, strerror(errno));
        fclose(file_handle);
        return false;
    }

    buffer = malloc((size_t) file_size);
    if (buffer == NULL && file_size != 0) {
        cld_set_error(error, "out of memory reading %s", path);
        fclose(file_handle);
        return false;
    }

    if ((size_t) file_size != 0 && fread(buffer, 1, (size_t) file_size, file_handle) != (size_t) file_size) {
        cld_set_error(error, "failed to read %s: %s", path, strerror(errno));
        free(buffer);
        fclose(file_handle);
        return false;
    }

    fclose(file_handle);
    *data = buffer;
    *size = (size_t) file_size;
    return true;
}

bool cld_write_entire_file(const char *path, const uint8_t *data, size_t size, CldError *error) {
    FILE *file_handle;

    file_handle = fopen(path, "wb");
    if (file_handle == NULL) {
        cld_set_error(error, "failed to open %s for writing: %s", path, strerror(errno));
        return false;
    }

    if (size != 0 && fwrite(data, 1, size, file_handle) != size) {
        cld_set_error(error, "failed to write %s: %s", path, strerror(errno));
        fclose(file_handle);
        return false;
    }

    if (fclose(file_handle) != 0) {
        cld_set_error(error, "failed to close %s: %s", path, strerror(errno));
        return false;
    }

    return true;
}

uint64_t cld_align_up_u64(uint64_t value, uint64_t alignment) {
    uint64_t mask;

    if (alignment <= 1) {
        return value;
    }

    mask = alignment - 1;
    return (value + mask) & ~mask;
}

uint64_t cld_max_u64(uint64_t left, uint64_t right) {
    return left > right ? left : right;
}

uint64_t cld_min_u64(uint64_t left, uint64_t right) {
    return left < right ? left : right;
}

int64_t cld_sign_extend_u32(uint32_t value, unsigned width) {
    uint32_t sign_bit;

    if (width == 0 || width >= 32) {
        return (int32_t) value;
    }

    sign_bit = 1u << (width - 1u);
    return (int64_t) ((value ^ sign_bit) - sign_bit);
}

bool cld_append_bytes(uint8_t **buffer, size_t *size, size_t *capacity, const void *data, size_t data_size, CldError *error) {
    size_t required_size;
    size_t next_capacity;
    uint8_t *next_buffer;

    if (data_size == 0) {
        return true;
    }

    required_size = *size + data_size;
    if (required_size > *capacity || *buffer == NULL) {
        next_capacity = *capacity == 0 ? 64 : *capacity;
        while (next_capacity < required_size) {
            next_capacity *= 2;
        }

        next_buffer = realloc(*buffer, next_capacity);
        if (next_buffer == NULL) {
            cld_set_error(error, "out of memory while growing output buffer");
            return false;
        }

        *buffer = next_buffer;
        *capacity = next_capacity;
    }

    memcpy(*buffer + *size, data, data_size);
    *size = required_size;
    return true;
}
