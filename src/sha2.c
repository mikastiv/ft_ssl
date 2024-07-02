#include "digest.h"
#include "ssl.h"
#include "types.h"
#include "utils.h"

#include <assert.h>
#include <unistd.h>

extern Options options;

static const u32 k32[SHA2X32_ROUNDS] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

static Sha2x32
sha2x32_init(u32 iv[8]) {
    return (Sha2x32) {
        .state = {
            iv[0],
            iv[1],
            iv[2],
            iv[3],
            iv[4],
            iv[5],
            iv[6],
            iv[7],
        },
    };
}

static Buffer
sha2x32_buffer(Sha2x32* sha) {
    return (Buffer){ .ptr = sha->buffer, .len = sizeof(sha->buffer) };
}

static void
sha2x32_round(Sha2x32* sha) {
    u32 w[SHA2X32_ROUNDS];
    for (u32 i = 0; i < SHA2X32_BLOCK_SIZE; i += sizeof(u32)) {
        u32 bytes = read_u32(&sha->buffer[i]);
        w[i / sizeof(u32)] = byte_swap32(bytes);
    }

    for (u32 i = 16; i < SHA2X32_ROUNDS; i++) {
        u32 s0 = rotate_right32(w[i - 15], 7) ^ rotate_right32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = rotate_right32(w[i - 2], 17) ^ rotate_right32(w[i - 2], 19) ^ (w[i - 2] >> 10);
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

    for (u32 i = 0; i < SHA2X32_ROUNDS; i++) {
        u32 ep1 = rotate_right32(e, 6) ^ rotate_right32(e, 11) ^ rotate_right32(e, 25);
        u32 ch = (e & f) ^ ((~e) & g);
        u32 t1 = h + ep1 + ch + k32[i] + w[i];
        u32 ep0 = rotate_right32(a, 2) ^ rotate_right32(a, 13) ^ rotate_right32(a, 22);
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

static void
sha2x32_update(Sha2x32* sha, Buffer buffer) {
    sha->total_len += buffer.len;

    u32 index = 0;
    if (sha->buffer_len != 0) {
        u32 remaining = SHA2X32_BLOCK_SIZE - sha->buffer_len;
        u32 len = (buffer.len > remaining) ? remaining : buffer.len;

        Buffer dst = buffer_create(sha->buffer + sha->buffer_len, len);
        Buffer src = buffer_create(buffer.ptr, len);
        ft_memcpy(dst, src);

        sha->buffer_len += len;
        index = len;

        if (sha->buffer_len == SHA2X32_BLOCK_SIZE) {
            sha2x32_round(sha);
            sha->buffer_len = 0;
        }
    }

    while (buffer.len - index >= SHA2X32_BLOCK_SIZE) {
        Buffer src = buffer_create(buffer.ptr + index, SHA2X32_BLOCK_SIZE);
        ft_memcpy(sha2x32_buffer(sha), src);
        sha2x32_round(sha);
        index += SHA2X32_BLOCK_SIZE;
    }

    if (index < buffer.len) {
        u32 len = buffer.len - index;
        Buffer dst = buffer_create(sha->buffer, len);
        Buffer src = buffer_create(buffer.ptr + index, len);
        ft_memcpy(dst, src);
        sha->buffer_len = len;
    }
}

static void
sha2x32_final(Sha2x32* sha, Buffer out, u32 digest_size) {
    assert(out.len == digest_size);

    Buffer padding =
        buffer_create(sha->buffer + sha->buffer_len, SHA2X32_BLOCK_SIZE - sha->buffer_len);
    ft_memset(padding, 0);

    sha->buffer[sha->buffer_len++] = 0x80;
    if (sha->buffer_len > SHA2X32_BLOCK_SIZE - SHA2X32_LENGTH_SIZE) {
        sha2x32_round(sha);
        ft_memset(sha2x32_buffer(sha), 0);
    }

    u32 i = 0;
    u64 len = sha->total_len * 8;
    while (i < SHA2X32_LENGTH_SIZE) {
        sha->buffer[SHA2X32_BLOCK_SIZE - 1 - i] = (u8)len;
        len >>= 8;
        i++;
    }

    sha2x32_round(sha);

    for (i = 0; i < digest_size; i += sizeof(u32)) {
        u8* bytes = (u8*)&sha->state[i / sizeof(u32)];
        out.ptr[i] = bytes[3];
        out.ptr[i + 1] = bytes[2];
        out.ptr[i + 2] = bytes[1];
        out.ptr[i + 3] = bytes[0];
    }
}

typedef void (*HashUpdate)(void*, Buffer);
typedef void (*HashFinal)(void*, Buffer);

typedef struct {
    HashUpdate update;
    HashFinal final;
} Hasher;

Sha256
sha256_init(void) {
    u32 iv[] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };

    return sha2x32_init(iv);
}

void
sha256_update(Sha256* sha, Buffer buffer) {
    sha2x32_update(sha, buffer);
}

void
sha256_final(Sha256* sha, Buffer out) {
    sha2x32_final(sha, out, SHA256_DIGEST_SIZE);
}

Sha224
sha224_init(void) {
    u32 iv[] = {
        0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
        0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
    };

    return sha2x32_init(iv);
}

void
sha224_update(Sha224* sha, Buffer buffer) {
    sha2x32_update(sha, buffer);
}

void
sha224_final(Sha224* sha, Buffer out) {
    sha2x32_final(sha, out, SHA224_DIGEST_SIZE);
}

static const u64 k64[SHA2X64_ROUNDS] = {
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
};

static Sha2x64
sha2x64_init(u64 iv[8]) {
    return (Sha2x64){
        .state = {
            iv[0],
            iv[1],
            iv[2],
            iv[3],
            iv[4],
            iv[5],
            iv[6],
            iv[7],
        },
    };
}

static Buffer
sha2x64_buffer(Sha2x64* sha) {
    return (Buffer){ .ptr = sha->buffer, .len = sizeof(sha->buffer) };
}

static void
sha2x64_round(Sha512* sha) {
    u64 w[SHA2X64_ROUNDS];
    for (u32 i = 0; i < SHA2X64_BLOCK_SIZE; i += sizeof(u64)) {
        u64 bytes = read_u64(&sha->buffer[i]);
        w[i / sizeof(u64)] = byte_swap64(bytes);
    }

    for (u32 i = 16; i < SHA2X64_ROUNDS; i++) {
        u64 s0 = rotate_right64(w[i - 15], 1) ^ rotate_right64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        u64 s1 = rotate_right64(w[i - 2], 19) ^ rotate_right64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    u64 a = sha->state[0];
    u64 b = sha->state[1];
    u64 c = sha->state[2];
    u64 d = sha->state[3];
    u64 e = sha->state[4];
    u64 f = sha->state[5];
    u64 g = sha->state[6];
    u64 h = sha->state[7];

    for (u32 i = 0; i < SHA2X64_ROUNDS; i++) {
        u64 ep1 = rotate_right64(e, 14) ^ rotate_right64(e, 18) ^ rotate_right64(e, 41);
        u64 ch = (e & f) ^ ((~e) & g);
        u64 t1 = h + ep1 + ch + k64[i] + w[i];
        u64 ep0 = rotate_right64(a, 28) ^ rotate_right64(a, 34) ^ rotate_right64(a, 39);
        u64 maj = (a & b) ^ (a & c) ^ (b & c);
        u64 t2 = ep0 + maj;

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

static void
sha2x64_update(Sha2x64* sha, Buffer buffer) {
    sha->total_len += buffer.len;

    u32 index = 0;
    if (sha->buffer_len != 0) {
        u32 remaining = SHA2X64_BLOCK_SIZE - sha->buffer_len;
        u32 len = (buffer.len > remaining) ? remaining : buffer.len;

        Buffer dst = buffer_create(sha->buffer + sha->buffer_len, len);
        Buffer src = buffer_create(buffer.ptr, len);
        ft_memcpy(dst, src);

        sha->buffer_len += len;
        index = len;

        if (sha->buffer_len == SHA2X64_BLOCK_SIZE) {
            sha2x64_round(sha);
            sha->buffer_len = 0;
        }
    }

    while (buffer.len - index >= SHA2X64_BLOCK_SIZE) {
        Buffer src = buffer_create(buffer.ptr + index, SHA2X64_BLOCK_SIZE);
        ft_memcpy(sha2x64_buffer(sha), src);
        sha2x64_round(sha);
        index += SHA2X64_BLOCK_SIZE;
    }

    if (index < buffer.len) {
        u32 len = buffer.len - index;
        Buffer dst = buffer_create(sha->buffer, len);
        Buffer src = buffer_create(buffer.ptr + index, len);
        ft_memcpy(dst, src);
        sha->buffer_len = len;
    }
}

static void
sha2x64_final(Sha2x64* sha, Buffer out, u32 digest_size) {
    assert(out.len == digest_size);

    Buffer padding =
        buffer_create(sha->buffer + sha->buffer_len, SHA2X64_BLOCK_SIZE - sha->buffer_len);
    ft_memset(padding, 0);

    sha->buffer[sha->buffer_len++] = 0x80;
    if (sha->buffer_len > SHA2X64_BLOCK_SIZE - SHA2X64_LENGTH_SIZE) {
        sha2x64_round(sha);
        ft_memset(sha2x64_buffer(sha), 0);
    }

    u32 i = 0;
    u64 len = sha->total_len * 8;
    while (i < SHA2X64_LENGTH_SIZE) {
        sha->buffer[SHA2X64_BLOCK_SIZE - 1 - i] = (u8)len;
        len >>= 8;
        i++;
    }

    sha2x64_round(sha);

    for (i = 0; i < digest_size; i += sizeof(u64)) {
        u8* bytes = (u8*)&sha->state[i / sizeof(u64)];
        out.ptr[i] = bytes[7];
        out.ptr[i + 1] = bytes[6];
        out.ptr[i + 2] = bytes[5];
        out.ptr[i + 3] = bytes[4];
        out.ptr[i + 4] = bytes[3];
        out.ptr[i + 5] = bytes[2];
        out.ptr[i + 6] = bytes[1];
        out.ptr[i + 7] = bytes[0];
    }
}

Sha512
sha512_init(void) {
    u64 iv[] = {
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    };

    return sha2x64_init(iv);
}

void
sha512_update(Sha512* sha, Buffer buffer) {
    sha2x64_update(sha, buffer);
}

void
sha512_final(Sha512* sha, Buffer out) {
    sha2x64_final(sha, out, SHA512_DIGEST_SIZE);
}

Sha384
sha384_init(void) {
    u64 iv[] = {
        0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
        0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
    };

    return sha2x64_init(iv);
}

void
sha384_update(Sha384* sha, Buffer buffer) {
    sha2x64_update(sha, buffer);
}

void
sha384_final(Sha384* sha, Buffer out) {
    sha2x64_final(sha, out, SHA384_DIGEST_SIZE);
}

// clang-format off
digest_implement_interface(Sha256, sha256)
digest_implement_interface(Sha224, sha224)
digest_implement_interface(Sha512, sha512)
digest_implement_interface(Sha384, sha384)
    // clang-format on
