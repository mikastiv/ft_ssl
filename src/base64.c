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
    assert(c == '/');
    return 63;
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
    for (; i + 3 < input.len; i += 3, j += 4) {
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

Buffer
base64_decode(Buffer input) {
    u64 chunks = input.len / 4;

    u64 size = chunks * 3;
    Buffer buffer = buffer_create(malloc(size), size);
    if (!buffer.ptr) return (Buffer){ 0 };
    ft_memset(buffer, 0);

    u64 i = 0;
    u64 j = 0;
    for (; i + 3 < input.len; i += 4, j += 3) {
        u32 bytes = 0;
        for (u64 k = 0; k < 4; k++) {
            bytes <<= 6;
            bytes |= alpha_index(input.ptr[i + k]);
        }

        u32 padding_count = (input.ptr[i + 2] == padding) + (input.ptr[i + 3] == padding);

        buffer.ptr[j] = (bytes >> 16) & 0xFF;
        buffer.ptr[j + 1] = (padding_count < 2) ? (bytes >> 8) & 0xFF : 0;
        buffer.ptr[j + 2] = (padding_count < 1) ? bytes & 0xFF : 0;
    }

    return buffer;
}
