#include "cipher.h"
#include "globals.h"
#include "types.h"
#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Permuted choice 1
const static u8 pc1[] = {
    57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43,
    35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54,
    46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4,
};

// Permuted choice 2
const static u8 pc2[] = {
    14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,  26, 8,  16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
};

// Initial permutation
const static u8 ip[] = {
    58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20, 12, 4,  62, 54, 46, 38, 30, 22,
    14, 6,  64, 56, 48, 40, 32, 24, 16, 8,  57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35,
    27, 19, 11, 3,  61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7,
};

// Final permutation
const static u8 ip2[] = {
    40, 8,  48, 16, 56, 24, 64, 32, 39, 7,  47, 15, 55, 23, 63, 31, 38, 6,  46, 14, 54, 22,
    62, 30, 37, 5,  45, 13, 53, 21, 61, 29, 36, 4,  44, 12, 52, 20, 60, 28, 35, 3,  43, 11,
    51, 19, 59, 27, 34, 2,  42, 10, 50, 18, 58, 26, 33, 1,  41, 9,  49, 17, 57, 25,
};

// Permutation
const static u8 p[] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
    2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25,
};

// Expansion function
const static u8 e[] = {
    32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
};

// Substitution boxes
const static u8 s[][64] = {
    // clang-format off
    {
        14, 4,  13, 1, 2,  15, 11, 8, 3, 10, 6, 12, 5,  9,  0,  7,  0,  15, 7,  4,  14, 2,
        13, 1,  10, 6, 12, 11, 9,  5, 3, 8,  4, 1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,
        3,  10, 5,  0, 15, 12, 8,  2, 4, 9,  1, 7,  5,  11, 3,  14, 10, 0,  6,  13,
    },
    {
        15, 1,  8,  14, 6,  11, 3,  4, 9,  7,  2, 13, 12, 0,  5,  10, 3,  13, 4,  7, 15, 2,
        8,  14, 12, 0,  1,  10, 6,  9, 11, 5,  0, 14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,
        9,  3,  2,  15, 13, 8,  10, 1, 3,  15, 4, 2,  11, 6,  7,  12, 0,  5,  14, 9,
    },
    {
        10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7, 11, 4,  2,  8,  13, 7, 0,  9,  3, 4,
        6,  10, 2,  8,  5, 14, 12, 11, 15, 1,  13, 6, 4,  9,  8,  15, 3,  0, 11, 1,  2, 12,
        5,  10, 14, 7,  1, 10, 13, 0,  6,  9,  8,  7, 4,  15, 14, 3,  11, 5, 2,  12,
    },
    {
        7, 13, 14, 3, 0, 6,  9, 10, 1,  2, 8,  5, 11, 12, 4,  15, 13, 8,  11, 5,  6, 15,
        0, 3,  4,  7, 2, 12, 1, 10, 14, 9, 10, 6, 9,  0,  12, 11, 7,  13, 15, 1,  3, 14,
        5, 2,  8,  4, 3, 15, 0, 6,  10, 1, 13, 8, 9,  4,  5,  11, 12, 7,  2,  14,
    },
    {
        2,  12, 4, 1,  7,  10, 11, 6, 8, 5,  3, 15, 13, 0,  14, 9,  14, 11, 2,  12, 4,  7,
        13, 1,  5, 0,  15, 10, 3,  9, 8, 6,  4, 2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,
        6,  3,  0, 14, 11, 8,  12, 7, 1, 14, 2, 13, 6,  15, 0,  9,  10, 4,  5,  3,
    },
    {
        12, 1,  10, 15, 9,  2,  6, 8,  0, 13, 3,  4,  14, 7,  5, 11, 10, 15, 4, 2,  7, 12,
        9,  5,  6,  1,  13, 14, 0, 11, 3, 8,  9,  14, 15, 5,  2, 8,  12, 3,  7, 0,  4, 10,
        1,  13, 11, 6,  4,  3,  2, 12, 9, 5,  15, 10, 11, 14, 1, 7,  6,  0,  8, 13,
    },
    {
        4, 11, 2,  14, 15, 0,  8,  13, 3, 12, 9,  7, 5,  10, 6,  1,  13, 0,  11, 7,  4, 9,
        1, 10, 14, 3,  5,  12, 2,  15, 8, 6,  1,  4, 11, 13, 12, 3,  7,  14, 10, 15, 6, 8,
        0, 5,  9,  2,  6,  11, 13, 8,  1, 4,  10, 7, 9,  5,  0,  15, 14, 2,  3,  12,
    },
    {
        13, 2, 8,  4, 6, 15, 11, 1,  10, 9,  3, 14, 5,  0,  12, 7,  1,  15, 13, 8, 10, 3,
        7,  4, 12, 5, 6, 11, 0,  14, 9,  2,  7, 11, 4,  1,  9,  12, 14, 2,  0,  6, 10, 13,
        15, 3, 5,  8, 2, 1,  14, 7,  4,  10, 8, 13, 15, 12, 9,  0,  3,  5,  6,  11,
    }
    // clang-format on
};

const static u8 shift[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

typedef Des64 Subkey;
typedef Subkey Subkeys[16];

static bool
get_bit(Des64 value, u64 bit) {
    u64 index = bit / 8;
    u64 offset = bit % 8;
    u64 mask = 1ull << (7ull - offset);
    return (value.block[index] & mask) != 0;
}

static Des64
set_bit(Des64 value, u64 bit, bool v) {
    u64 index = bit / 8;
    u64 offset = bit % 8;
    u64 mask = 1ull << (7ull - offset);

    if (v) {
        value.block[index] |= mask;
    } else {
        value.block[index] &= ~mask;
    }

    return value;
}

static Des64
permute(Des64 value, const u8* permutation_table, u64 table_len) {
    Des64 permuted_value = { .raw = 0 };
    for (u64 i = 0; i < table_len; i++) {
        u64 bit = get_bit(value, permutation_table[i] - 1);
        permuted_value = set_bit(permuted_value, i, bit);
    }

    return permuted_value;
}

static Des64
circular_shift_left28(Des64 value, u64 times) {
    for (u64 i = 0; i < times; i++) {
        bool carry = get_bit(value, 0);
        for (u64 j = 0; j < 27; j++) {
            value = set_bit(value, j, get_bit(value, j + 1));
        }
        value = set_bit(value, 27, carry);
    }

    return value;
}

static void
split_block(Des64 block, u64 size, Des64* left, Des64* right) {
    for (u64 i = 0; i < size; i++) {
        *left = set_bit(*left, i, get_bit(block, i));
        *right = set_bit(*right, i, get_bit(block, i + size));
    }
}

static Des64
merge_blocks(Des64 left, Des64 right, u64 size) {
    Des64 merged = { .raw = 0 };
    for (u64 j = 0; j < size; j++) {
        merged = set_bit(merged, j, get_bit(left, j));
        merged = set_bit(merged, j + size, get_bit(right, j));
    }

    return merged;
}

static void
generate_subkeys(Des64 key, Subkeys out) {
    Des64 permuted_key = permute(key, pc1, array_len(pc1));

    Des64 left = { .raw = 0 };
    Des64 right = { .raw = 0 };
    split_block(permuted_key, 28, &left, &right);

    for (u64 i = 0; i < 16; i++) {
        right = circular_shift_left28(right, shift[i]);
        left = circular_shift_left28(left, shift[i]);

        Des64 concat = merge_blocks(left, right, 28);
        out[i] = permute(concat, pc2, array_len(pc2));
    }
}

static Des64
feistel(Des64 halfblock, Subkey subkey) {
    Des64 expanded = permute(halfblock, e, array_len(e));
    expanded.raw ^= subkey.raw;

    Des64 substituted = { .raw = 0 };
    for (u64 i = 0; i < 8; i++) {
        u64 j = i * 6;
        u64 bits[6] = { 0 };
        for (u64 k = 0; k < 6; k++) {
            if (get_bit(expanded, j + k)) {
                bits[k] = 1;
            }
        }

        u64 row = 2 * bits[0] + bits[5];
        u64 col = 8 * bits[1] + 4 * bits[2] + 2 * bits[3] + bits[4];
        u64 m = s[i][row * 16 + col];
        u64 n = 1;

        while (m > 0) {
            u64 bit = (i + 1) * 4 - n;
            substituted = set_bit(substituted, bit, m & 1ul);

            m >>= 1;
            n++;
        }
    }

    return permute(substituted, p, array_len(p));
}

static Des64
process_block(Des64 block, Subkeys subkeys) {
    Des64 permuted = permute(block, ip, array_len(ip));

    Des64 left = { .raw = 0 };
    Des64 right = { .raw = 0 };
    split_block(permuted, 32, &left, &right);

    for (u64 i = 0; i < 16; i++) {
        Des64 tmp = right;
        right = feistel(right, subkeys[i]);
        right.raw ^= left.raw;
        left = tmp;
    }

    Des64 block_cipher = merge_blocks(right, left, 32);
    block_cipher = permute(block_cipher, ip2, array_len(ip2));

    return block_cipher;
}

typedef void (*BlockCipherModeFn)(void*, Des64, Subkeys, Buffer);

typedef struct {
    i32 unused;
} EcbCtx;

static void
des_ecb_process_block(void* ptr, Des64 block, Subkeys subkeys, Buffer out) {
    (void)ptr;

    Des64 pblock = process_block(block, subkeys);
    ft_memcpy(out, buf(pblock.block, 8));
}

typedef struct {
    Des64 iv;
} IvCtx;

static void
des_cbc_process_block_encrypt(void* ptr, Des64 block, Subkeys subkeys, Buffer out) {
    IvCtx* ctx = ptr;

    block.raw ^= ctx->iv.raw;
    Des64 ciphertext = process_block(block, subkeys);
    ctx->iv = ciphertext;
    ft_memcpy(out, buf(ciphertext.block, 8));
}

static void
des_cbc_process_block_decrypt(void* ptr, Des64 block, Subkeys subkeys, Buffer out) {
    IvCtx* ctx = ptr;

    Des64 decoded = process_block(block, subkeys);
    decoded.raw ^= ctx->iv.raw;
    ctx->iv = block;
    ft_memcpy(out, buf(decoded.block, 8));
}

static void
des_ofb_process_block(void* ptr, Des64 block, Subkeys subkeys, Buffer out) {
    IvCtx* ctx = ptr;

    Des64 pblock = process_block(ctx->iv, subkeys);
    ctx->iv = pblock;
    pblock.raw ^= block.raw;
    ft_memcpy(out, buf(pblock.block, 8));
}

static void
des_cfb_process_block_encrypt(void* ptr, Des64 block, Subkeys subkeys, Buffer out) {
    IvCtx* ctx = ptr;

    Des64 ciphertext = process_block(ctx->iv, subkeys);
    ciphertext.raw ^= block.raw;
    ctx->iv = ciphertext;
    ft_memcpy(out, buf(ciphertext.block, 8));
}

static void
des_cfb_process_block_decrypt(void* ptr, Des64 block, Subkeys subkeys, Buffer out) {
    IvCtx* ctx = ptr;

    Des64 message = process_block(ctx->iv, subkeys);
    message.raw ^= block.raw;
    ctx->iv = block;
    ft_memcpy(out, buf(message.block, 8));
}

static Buffer
des_encrypt(Buffer message, DesKey key, void* ctx, BlockCipherModeFn mode_fn, bool skip_padding) {
    Subkeys subkeys;
    generate_subkeys(key, subkeys);

    u8 padding = 8 - (message.len % 8);
    if (skip_padding) padding = 0;

    u64 len = message.len + padding;
    u8* buffer = malloc(len);
    if (!buffer) {
        dprintf(STDERR_FILENO, "%s: out of memory\n", progname);
        return (Buffer){ 0 };
    }

    u64 i;
    for (i = 0; i + 7 < message.len; i += 8) {
        Des64 block = { .raw = read_u64(&message.ptr[i]) };
        mode_fn(ctx, block, subkeys, buf(buffer + i, 8));
    }
    if (i < len) {
        Des64 block;
        ft_memset(buf(block.block, sizeof(block)), padding);

        for (u64 j = 0; i + j < message.len; j++) {
            block.block[j] = message.ptr[i + j];
        }

        mode_fn(ctx, block, subkeys, buf(buffer + i, 8));
    }

    return buf(buffer, len);
}

static Buffer
remove_padding(Buffer buffer) {
    u8 padding = buffer.ptr[buffer.len - 1];
    if (padding > buffer.len) {
        dprintf(STDERR_FILENO, "%s: invalid ciphertext or key\n", progname);
        return (Buffer){ 0 };
    }
    buffer.len -= padding;

    return buffer;
}

static Buffer
des_decrypt(Buffer message, DesKey key, void* ctx, BlockCipherModeFn mode_fn, bool skip_padding) {
    if (message.len % 8 != 0) return (Buffer){ 0 };

    Subkeys subkeys;
    generate_subkeys(key, subkeys);

    for (u64 i = 0; i < array_len(subkeys) / 2; i++) {
        Subkey tmp = subkeys[i];
        subkeys[i] = subkeys[array_len(subkeys) - i - 1];
        subkeys[array_len(subkeys) - i - 1] = tmp;
    }

    u64 len = message.len;
    u8* buffer = malloc(len);
    if (!buffer) {
        dprintf(STDERR_FILENO, "%s: out of memory\n", progname);
        return (Buffer){ 0 };
    }

    for (u64 i = 0; i + 7 < message.len; i += 8) {
        Des64 block = { .raw = read_u64(&message.ptr[i]) };
        mode_fn(ctx, block, subkeys, buf(buffer + i, 8));
    }

    Buffer result = buf(buffer, len);
    if (!skip_padding) {
        Buffer tmp = remove_padding(result);
        if (!tmp.ptr) free(result.ptr);
        result = tmp;
    }

    return result;
}

Buffer
des_cbc_encrypt(Buffer message, DesKey key, Des64 iv) {
    IvCtx ctx = { .iv = iv };
    return des_encrypt(message, key, &ctx, &des_cbc_process_block_encrypt, false);
}

Buffer
des_cbc_decrypt(Buffer ciphertext, DesKey key, Des64 iv) {
    IvCtx ctx = { .iv = iv };
    return des_decrypt(ciphertext, key, &ctx, &des_cbc_process_block_decrypt, false);
}

Buffer
des_ecb_encrypt(Buffer message, DesKey key) {
    EcbCtx ctx;
    return des_encrypt(message, key, &ctx, &des_ecb_process_block, false);
}

Buffer
des_ecb_decrypt(Buffer ciphertext, DesKey key) {
    EcbCtx ctx;
    return des_decrypt(ciphertext, key, &ctx, &des_ecb_process_block, false);
}

Buffer
des_ofb_encrypt(Buffer message, DesKey key, Des64 iv) {
    IvCtx ctx = { .iv = iv };
    return des_encrypt(message, key, &ctx, &des_ofb_process_block, false);
}

Buffer
des_ofb_decrypt(Buffer ciphertext, DesKey key, Des64 iv) {
    IvCtx ctx = { .iv = iv };
    Buffer message = des_encrypt(ciphertext, key, &ctx, &des_ofb_process_block, true);
    Buffer result = remove_padding(message);
    if (!result.ptr) {
        free(message.ptr);
        return (Buffer){ 0 };
    }

    return result;
}

Buffer
des_cfb_encrypt(Buffer message, DesKey key, Des64 iv) {
    IvCtx ctx = { .iv = iv };
    return des_encrypt(message, key, &ctx, &des_cfb_process_block_encrypt, false);
}

Buffer
des_cfb_decrypt(Buffer ciphertext, DesKey key, Des64 iv) {
    IvCtx ctx = { .iv = iv };
    Buffer message = des_encrypt(ciphertext, key, &ctx, &des_cfb_process_block_decrypt, true);
    Buffer result = remove_padding(message);
    if (!result.ptr) {
        free(message.ptr);
        return (Buffer){ 0 };
    }

    return result;
}

static void
des3_get_keys(Des3Key key, DesKey* key1, DesKey* key2, DesKey* key3) {
    for (u64 i = 0; i < 8; i++) {
        key1->block[i] = key[i];
        key2->block[i] = key[i + 8];
        key3->block[i] = key[i + 16];
    }
}

Buffer
des3_ecb_encrypt(Buffer message, Des3Key key) {
    DesKey key1, key2, key3;
    des3_get_keys(key, &key1, &key2, &key3);

    EcbCtx ctx;
    Buffer tmp1 = des_encrypt(message, key1, &ctx, &des_ecb_process_block, false);
    Buffer tmp2 = des_decrypt(tmp1, key2, &ctx, &des_ecb_process_block, true);
    Buffer cipher = des_encrypt(tmp2, key3, &ctx, &des_ecb_process_block, true);

    free(tmp1.ptr);
    free(tmp2.ptr);

    return cipher;
}

Buffer
des3_ecb_decrypt(Buffer cipher, Des3Key key) {
    DesKey key1, key2, key3;
    des3_get_keys(key, &key1, &key2, &key3);

    EcbCtx ctx;
    Buffer tmp1 = des_decrypt(cipher, key3, &ctx, &des_ecb_process_block, true);
    Buffer tmp2 = des_encrypt(tmp1, key2, &ctx, &des_ecb_process_block, true);
    Buffer message = des_decrypt(tmp2, key1, &ctx, &des_ecb_process_block, false);

    free(tmp1.ptr);
    free(tmp2.ptr);

    return message;
}
