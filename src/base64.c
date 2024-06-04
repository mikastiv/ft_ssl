#include "cipher.h"
#include "utils.h"

#include <assert.h>
#include <stdlib.h>

static const char* base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char padding = '=';

static u32
alpha_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == padding) return 0;
    if (c == '/') return 63;
    return (u32)-1;
}

Buffer
base64_encode(Buffer input) {
    u64 chunks = input.len / 3;
    u64 extra = input.len % 3;

    u64 size = chunks * 4 + (extra > 0 ? 4 : 0);
    Buffer buffer = buffer_create(malloc(size), size);
    if (!buffer.ptr) return (Buffer){ 0 };
    ft_memset(buffer, 0);

    u64 i = 0;
    u64 j = 0;
    for (; i + 2 < input.len; i += 3, j += 4) {
        u32 bytes = read_u24_be(&input.ptr[i]);
        buffer.ptr[j + 0] = base64[(bytes >> 18) & 0x3F];
        buffer.ptr[j + 1] = base64[(bytes >> 12) & 0x3F];
        buffer.ptr[j + 2] = base64[(bytes >> 6) & 0x3F];
        buffer.ptr[j + 3] = base64[(bytes >> 0) & 0x3F];
    }

    switch (extra) {
        case 2: {
            u32 bytes = read_u16_be(&input.ptr[i]);
            buffer.ptr[j + 0] = base64[(bytes >> 10) & 0x3F];
            buffer.ptr[j + 1] = base64[(bytes >> 4) & 0x3F];
            buffer.ptr[j + 2] = base64[(bytes & 0xF) << 2];
            buffer.ptr[j + 3] = padding;
        } break;
        case 1: {
            u32 bytes = input.ptr[i];
            buffer.ptr[j + 0] = base64[(bytes >> 2) & 0x3F];
            buffer.ptr[j + 1] = base64[(bytes & 0x3) << 4];
            buffer.ptr[j + 2] = padding;
            buffer.ptr[j + 3] = padding;
        } break;
    }

    return buffer;
}

static u64
count_ignore_whitespace(Buffer buffer) {
    u64 len = 0;
    for (u64 i = 0; i < buffer.len; i++) {
        if (!is_space(buffer.ptr[i])) len++;
    }
    return len;
}

static void
memcpy_ignore_whitespace(Buffer dst, Buffer src) {
    u64 i = 0;
    for (u64 j = 0; j < src.len; j++) {
        if (!is_space(src.ptr[j])) dst.ptr[i++] = src.ptr[j];
    }
}

Buffer
base64_decode(Buffer input) {
    const u64 size = count_ignore_whitespace(input);
    u64 chunks = size / 4;
    if (size % 4 != 0) return (Buffer){ 0 };

    Buffer clean_input = buffer_create(malloc(size), size);
    if (!clean_input.ptr) return (Buffer){ 0 };
    memcpy_ignore_whitespace(clean_input, input);

    u64 output_size = chunks * 3;
    Buffer buffer = buffer_create(malloc(output_size), output_size);
    if (!buffer.ptr) return (Buffer){ 0 };
    ft_memset(buffer, 0);

    for (u64 i = 0, j = 0; i < clean_input.len; i += 4, j += 3) {
        u32 bytes = 0;
        for (u64 k = 0; k < 4; k++) {
            bytes <<= 6;
            u32 index = alpha_index(clean_input.ptr[i + k]);
            if (index > 63) goto error;
            bytes |= index;
        }

        if (clean_input.ptr[i] == padding || clean_input.ptr[i + 1] == padding) goto error;

        u32 padding_count =
            (clean_input.ptr[i + 2] == padding) + (clean_input.ptr[i + 3] == padding);
        if (padding_count) {
            if (clean_input.ptr[i + 2] == padding && clean_input.ptr[i + 3] != padding) goto error;
        }

        buffer.ptr[j] = (bytes >> 16) & 0xFF;
        buffer.ptr[j + 1] = (padding_count < 2) ? (bytes >> 8) & 0xFF : 0;
        buffer.ptr[j + 2] = (padding_count < 1) ? bytes & 0xFF : 0;
    }

    free(clean_input.ptr);
    return buffer;

error:
    free(buffer.ptr);
    free(clean_input.ptr);
    return (Buffer){ 0 };
}
