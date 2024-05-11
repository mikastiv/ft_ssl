#include "hash.h"
#include "types.h"
#include "utils.h"

#include <assert.h>
#include <unistd.h>

static const u32 k32[] = {
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
    u32 w[64];
    for (u32 i = 0; i < SHA2X32_CHUNK_SIZE; i += sizeof(w[0])) {
        u8* bytes = &sha->buffer[i];
        w[i / sizeof(w[0])] = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
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
        u32 t1 = h + ep1 + ch + k32[i] + w[i];
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

static void
sha2x32_update(Sha2x32* sha, Buffer buffer) {
    u32 index = 0;
    if (sha->buffer_len != 0) {
        u32 remaining = SHA2X32_CHUNK_SIZE - sha->buffer_len;
        u32 len = (buffer.len > remaining) ? remaining : buffer.len;

        Buffer dst = buffer_create(sha->buffer + sha->buffer_len, len);
        Buffer src = buffer_create(buffer.ptr, len);
        ft_memcpy(dst, src);

        sha->buffer_len += len;
        sha->total_len += len;
        index = len;

        if (sha->buffer_len == SHA2X32_CHUNK_SIZE) {
            sha2x32_round(sha);
            sha->buffer_len = 0;
        }
    }

    while (buffer.len - index >= SHA2X32_CHUNK_SIZE) {
        Buffer src = buffer_create(buffer.ptr + index, SHA2X32_CHUNK_SIZE);
        ft_memcpy(sha2x32_buffer(sha), src);
        sha2x32_round(sha);
        index += SHA2X32_CHUNK_SIZE;
        sha->total_len += SHA2X32_CHUNK_SIZE;
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

static void
sha2x32_final(Sha2x32* sha, Buffer out, u32 digest_size) {
    assert(out.len == digest_size);

    Buffer padding =
        buffer_create(sha->buffer + sha->buffer_len, SHA2X32_CHUNK_SIZE - sha->buffer_len);
    ft_memset(padding, 0);

    sha->buffer[sha->buffer_len++] = 0x80;
    if (sha->buffer_len > SHA2X32_CHUNK_SIZE - 8) {
        sha2x32_round(sha);
        ft_memset(sha2x32_buffer(sha), 0);
    }

    u64 i = 0;
    u64 len = sha->total_len * 8;
    while (i < 8) {
        sha->buffer[SHA2X32_CHUNK_SIZE - 1 - i] = (u8)len;
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

static bool
sha2_hash_fd(int fd, void* sha, Hasher hasher, Buffer out) {
    u8 buffer[2046];
    i64 bytes = sizeof(buffer);
    while (bytes == sizeof(buffer)) {
        bytes = read(fd, buffer, sizeof(buffer));
        if (bytes < 0) return false;
        hasher.update(sha, buffer_create(buffer, (u64)bytes));
    }

    hasher.final(sha, out);

    return true;
}

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

bool
sha256_hash_fd(int fd, Buffer out) {
    Sha256 sha = sha256_init();
    Hasher hasher = {
        .update = (HashUpdate)&sha256_update,
        .final = (HashFinal)&sha256_final,
    };

    return sha2_hash_fd(fd, &sha, hasher, out);
}

void
sha256_hash_str(Buffer in, Buffer out) {
    Sha256 sha = sha256_init();
    sha256_update(&sha, in);
    sha256_final(&sha, out);
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

bool
sha224_hash_fd(int fd, Buffer out) {
    Sha224 sha = sha224_init();
    Hasher hasher = {
        .update = (HashUpdate)&sha224_update,
        .final = (HashFinal)&sha224_final,
    };

    return sha2_hash_fd(fd, &sha, hasher, out);
}

void
sha224_hash_str(Buffer in, Buffer out) {
    Sha224 sha = sha224_init();
    sha224_update(&sha, in);
    sha224_final(&sha, out);
}

static const u64 k64[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
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
    u64 w[80];
    for (u32 i = 0; i < SHA2X64_CHUNK_SIZE; i += sizeof(w[0])) {
        u8* bytes = &sha->buffer[i];
        u64 hi = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
        u64 lo = (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
        w[i / sizeof(w[0])] = (hi << 32) | lo;
    }

    for (u32 i = 16; i < 80; i++) {
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

    for (u32 i = 0; i < 80; i++) {
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
    u32 index = 0;
    if (sha->buffer_len != 0) {
        u32 remaining = SHA2X64_CHUNK_SIZE - sha->buffer_len;
        u32 len = (buffer.len > remaining) ? remaining : buffer.len;

        Buffer dst = buffer_create(sha->buffer + sha->buffer_len, len);
        Buffer src = buffer_create(buffer.ptr, len);
        ft_memcpy(dst, src);

        sha->buffer_len += len;
        sha->total_len += len;
        index = len;

        if (sha->buffer_len == SHA2X64_CHUNK_SIZE) {
            sha2x64_round(sha);
            sha->buffer_len = 0;
        }
    }

    while (buffer.len - index >= SHA2X64_CHUNK_SIZE) {
        Buffer src = buffer_create(buffer.ptr + index, SHA2X64_CHUNK_SIZE);
        ft_memcpy(sha2x64_buffer(sha), src);
        sha2x64_round(sha);
        index += SHA2X64_CHUNK_SIZE;
        sha->total_len += SHA2X64_CHUNK_SIZE;
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

static void
sha2x64_final(Sha2x64* sha, Buffer out, u32 digest_size) {
    assert(out.len == digest_size);

    Buffer padding =
        buffer_create(sha->buffer + sha->buffer_len, SHA2X64_CHUNK_SIZE - sha->buffer_len);
    ft_memset(padding, 0);

    sha->buffer[sha->buffer_len++] = 0x80;
    if (sha->buffer_len > SHA2X64_CHUNK_SIZE - 16) {
        sha2x64_round(sha);
        ft_memset(sha2x64_buffer(sha), 0);
    }

    u64 i = 0;
    u64 len = sha->total_len * 8;
    while (i < 16) {
        sha->buffer[SHA2X64_CHUNK_SIZE - 1 - i] = (u8)len;
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

bool
sha512_hash_fd(int fd, Buffer out) {
    Sha512 sha = sha512_init();
    Hasher hasher = {
        .update = (HashUpdate)&sha512_update,
        .final = (HashFinal)&sha512_final,
    };

    return sha2_hash_fd(fd, &sha, hasher, out);
}

void
sha512_hash_str(Buffer in, Buffer out) {
    Sha512 sha = sha512_init();
    sha512_update(&sha, in);
    sha512_final(&sha, out);
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

bool
sha384_hash_fd(int fd, Buffer out) {
    Sha384 sha = sha384_init();
    Hasher hasher = {
        .update = (HashUpdate)&sha384_update,
        .final = (HashFinal)&sha384_final,
    };

    return sha2_hash_fd(fd, &sha, hasher, out);
}

void
sha384_hash_str(Buffer in, Buffer out) {
    Sha384 sha = sha384_init();
    sha384_update(&sha, in);
    sha384_final(&sha, out);
}
