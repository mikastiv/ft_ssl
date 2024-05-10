#include "hash.h"
#include "types.h"
#include "utils.h"

#include <assert.h>

static const u32 k[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

static Buffer
sha256_buffer(Sha256* sha) {
    return (Buffer){ .ptr = sha->buffer, .len = SHA256_CHUNK_SIZE };
}

static void
sha256_round(Sha256* sha) {
    u32 w[64];
    for (u32 i = 0; i < SHA256_CHUNK_SIZE; i += 4) {
        u8* bytes = &sha->buffer[i];
        w[i / 4] = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    }

    for (u32 i = 16; i < 64; i++) {
        u32 s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    u32 a = sha->state[0];
    u32 b = sha->state[1];
    u32 c = sha->state[2];
    u32 d = sha->state[3];
    u32 e = sha->state[4];
    u32 f = sha->state[5];
    u32 g = sha->state[6];
    u32 h = sha->state[7];

    for (u32 i = 0; i < 64; i++) {
        u32 ep1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        u32 ch = (e & f) ^ ((~e) & g);
        u32 t1 = h + ep1 + ch + k[i] + w[i];
        u32 ep0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        u32 maj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = ep0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    sha->state[0] += a;
    sha->state[1] += b;
    sha->state[2] += c;
    sha->state[3] += d;
    sha->state[4] += e;
    sha->state[5] += f;
    sha->state[6] += g;
    sha->state[7] += h;
}

Sha256
sha256_init(void) {
    return (Sha256){
        .state = {
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19,
        },
        .total_len = 0,
        .buffer_len = 0,
        .buffer = {0},
    };
}

void
sha256_update(Sha256* sha, Buffer buffer) {
    u32 index = 0;
    if (sha->buffer_len != 0) {
        u32 remaining = SHA256_CHUNK_SIZE - sha->buffer_len;
        u32 len = (buffer.len > remaining) ? remaining : buffer.len;

        Buffer dst = buffer_create(sha->buffer + sha->buffer_len, len);
        Buffer src = buffer_create(buffer.ptr, len);
        ft_memcpy(dst, src);

        sha->buffer_len += len;
        sha->total_len += len;
        index = len;

        if (sha->buffer_len == SHA256_CHUNK_SIZE) {
            sha256_round(sha);
            sha->buffer_len = 0;
        }
    }

    while (buffer.len - index >= SHA256_CHUNK_SIZE) {
        Buffer src = buffer_create(buffer.ptr + index, SHA256_CHUNK_SIZE);
        ft_memcpy(sha256_buffer(sha), src);
        sha256_round(sha);
        index += 64;
        sha->total_len += 64;
    }

    if (index < buffer.len) {
        u32 len = buffer.len - index;
        Buffer dst = buffer_create(sha->buffer, len);
        Buffer src = buffer_create(buffer.ptr + index, len);
        ft_memcpy(dst, src);
        sha->buffer_len = len;
        sha->total_len += len;
    }
}

void
sha256_final(Sha256* sha, Buffer out) {
    assert(out.len == SHA256_DIGEST_SIZE);

    Buffer rest = buffer_create(sha->buffer + sha->buffer_len, SHA256_CHUNK_SIZE - sha->buffer_len);
    ft_memset(rest, 0);

    sha->buffer[sha->buffer_len++] = 0x80;
    if (sha->buffer_len > SHA256_CHUNK_SIZE - 8) {
        sha256_round(sha);
        ft_memset(sha256_buffer(sha), 0);
    }

    u64 i = 0;
    u64 len = sha->total_len * 8;
    while (i < 8) {
        sha->buffer[SHA256_CHUNK_SIZE - 1 - i] = (u8)len;
        len >>= 8;
        i++;
    }

    sha256_round(sha);

    for (i = 0; i < SHA256_DIGEST_SIZE; i += 4) {
        u8* bytes = (u8*)&sha->state[i / 4];
        out.ptr[i] = bytes[3];
        out.ptr[i + 1] = bytes[2];
        out.ptr[i + 2] = bytes[1];
        out.ptr[i + 3] = bytes[0];
    }
}
