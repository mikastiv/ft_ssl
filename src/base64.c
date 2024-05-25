#include "cipher.h"
#include "utils.h"

#include <stdlib.h>

static const char* base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
const char padding = '=';

Buffer
base64_encode(Buffer input) {
    u64 chunks = input.len / 6;
    u64 extra = input.len % 6;

    u64 size = chunks * 8 + (extra > 0 ? 8 : 0);
    Buffer buffer = buffer_create(malloc(size), size);
    ft_memset(buffer, 0);
    if (!buffer.ptr) return (Buffer){ .ptr = 0, .len = 0 };

    u64 i = 0;
    u64 j = 0;
    for (; i < chunks; i += 6) {
        u64 bytes = read_u48_be(&input.ptr[i]);
        for (u64 k = 0; k < 8; j++, k++) {
            buffer.ptr[j] = base64[(bytes >> (6 * (7 - k))) & 0x3F];
        }
    }

    while (extra >= 3) {
        u32 bytes = read_u24_be(&input.ptr[i]);

        buffer.ptr[j + 0] = base64[(bytes >> 18) & 0x3F];
        buffer.ptr[j + 1] = base64[(bytes >> 12) & 0x3F];
        buffer.ptr[j + 2] = base64[(bytes >> 6) & 0x3F];
        buffer.ptr[j + 3] = base64[bytes & 0x3F];

        extra -= 3;
        i += 3;
        j += 4;
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
