#include "digest.h"
#include "types.h"
#include "utils.h"

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>

static const u32 k[MD5_ROUNDS] = {
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
};

static const u32 shift[MD5_ROUNDS] = {
    7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 5,  9,  14, 20, 5,  9,
    14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
    4,  11, 16, 23, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21,
};

static Buffer
md5_buffer(Md5* md5) {
    return (Buffer){ .ptr = md5->buffer, .len = MD5_CHUNK_SIZE };
}

static void
md5_round(Md5* md5) {
    u32 s[16];

    Buffer dst = buffer_create((u8*)s, MD5_CHUNK_SIZE);
    ft_memcpy(dst, md5_buffer(md5));

    u32 a = md5->state[0];
    u32 b = md5->state[1];
    u32 c = md5->state[2];
    u32 d = md5->state[3];

    for (u32 i = 0; i < MD5_ROUNDS; i++) {
        u32 f, g;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | (~d));
            g = (7 * i) % 16;
        }

        f = f + a + k[i] + s[g];
        a = d;
        d = c;
        c = b;
        b = b + rotate_left32(f, shift[i]);
    }

    md5->state[0] += a;
    md5->state[1] += b;
    md5->state[2] += c;
    md5->state[3] += d;
}

Md5
md5_init(void) {
    return (Md5){
        .state = {
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
        },
        .total_len = 0,
        .buffer_len = 0,
        .buffer = {0},
    };
}

void
md5_update(Md5* md5, Buffer buffer) {
    md5->total_len += buffer.len;

    u32 index = 0;
    if (md5->buffer_len != 0) {
        u32 remaining = MD5_CHUNK_SIZE - md5->buffer_len;
        u32 len = (buffer.len > remaining) ? remaining : buffer.len;

        Buffer dst = buffer_create(md5->buffer + md5->buffer_len, len);
        Buffer src = buffer_create(buffer.ptr, len);
        ft_memcpy(dst, src);

        md5->buffer_len += len;
        index = len;

        if (md5->buffer_len == MD5_CHUNK_SIZE) {
            md5_round(md5);
            md5->buffer_len = 0;
        }
    }

    while (buffer.len - index >= MD5_CHUNK_SIZE) {
        Buffer src = buffer_create(buffer.ptr + index, MD5_CHUNK_SIZE);
        ft_memcpy(md5_buffer(md5), src);
        md5_round(md5);
        index += 64;
    }

    if (index < buffer.len) {
        u32 len = buffer.len - index;
        Buffer dst = buffer_create(md5->buffer, len);
        Buffer src = buffer_create(buffer.ptr + index, len);
        ft_memcpy(dst, src);
        md5->buffer_len = len;
    }
}

void
md5_final(Md5* md5, Buffer out) {
    assert(out.len == MD5_DIGEST_SIZE);

    Buffer rest = buffer_create(md5->buffer + md5->buffer_len, MD5_CHUNK_SIZE - md5->buffer_len);
    ft_memset(rest, 0);

    md5->buffer[md5->buffer_len++] = 0x80;
    if (md5->buffer_len > MD5_CHUNK_SIZE - MD5_LENGTH_SIZE) {
        md5_round(md5);
        ft_memset(md5_buffer(md5), 0);
    }

    u32 i = 0;
    u64 len = md5->total_len * 8;
    while (i < MD5_LENGTH_SIZE) {
        md5->buffer[MD5_CHUNK_SIZE - 8 + i] = (u8)len;
        len >>= 8;
        i++;
    }

    md5_round(md5);

    ft_memcpy(out, buffer_create((u8*)md5->state, MD5_DIGEST_SIZE));
}

digest_implement_interface(Md5, md5)
