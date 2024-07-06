#include "cipher.h"
#include "digest.h"
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

static Buffer
des_encrypt(Buffer message, DesKey key, const Des64* iv) {
    Subkeys subkeys;
    generate_subkeys(key, subkeys);

    u8 padding = 8 - (message.len % 8);
    u64 len = message.len + padding;
    u8* buffer = malloc(len);
    if (!buffer) {
        dprintf(STDERR_FILENO, "%s: out of memory\n", progname);
        return (Buffer){ 0 };
    }

    Des64 prev_block = { .raw = 0 };
    if (iv) prev_block.raw = iv->raw;

    u64 i;
    for (i = 0; i + 7 < message.len; i += 8) {
        Des64 block = { .raw = read_u64(&message.ptr[i]) };
        if (iv) block.raw ^= prev_block.raw;

        Des64 cipher = process_block(block, subkeys);
        prev_block.raw = cipher.raw;

        for (u64 j = 0; j < 8; j++) {
            buffer[i + j] = cipher.block[j];
        }
    }
    if (i < len) {
        Des64 block;
        ft_memset(buffer_create(block.block, sizeof(block)), padding);

        for (u64 j = 0; i + j < message.len; j++) {
            block.block[j] = message.ptr[i + j];
        }

        if (iv) block.raw ^= prev_block.raw;
        Des64 cipher = process_block(block, subkeys);

        for (u64 j = 0; j < 8; j++) {
            buffer[i + j] = cipher.block[j];
        }
    }

    return buffer_create(buffer, len);
}

static Buffer
des_decrypt(Buffer message, DesKey key, const Des64* iv) {
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

    Des64 prev_block = { .raw = 0 };
    if (iv) prev_block.raw = iv->raw;

    for (u64 i = 0; i + 7 < message.len; i += 8) {
        Des64 block = { .raw = read_u64(&message.ptr[i]) };

        Des64 decoded = process_block(block, subkeys);
        if (iv) decoded.raw ^= prev_block.raw;
        prev_block.raw = block.raw;

        for (u64 j = 0; j < 8; j++) {
            buffer[i + j] = decoded.block[j];
        }
    }

    u8 padding = buffer[len - 1];
    if (padding > len) {
        dprintf(STDERR_FILENO, "%s: invalid ciphertext or key\n", progname);
        free(buffer);
        return (Buffer){ 0 };
    }
    len -= padding;

    return buffer_create(buffer, len);
}

Buffer
des_cbc_encrypt(Buffer message, DesKey key, Des64 iv) {
    return des_encrypt(message, key, &iv);
}

Buffer
des_cbc_decrypt(Buffer cipher, DesKey key, Des64 iv) {
    return des_decrypt(cipher, key, &iv);
}

Buffer
des_ecb_encrypt(Buffer message, DesKey key) {
    return des_encrypt(message, key, 0);
}

Buffer
des_ecb_decrypt(Buffer cipher, DesKey key) {
    return des_decrypt(cipher, key, 0);
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

    Buffer tmp1 = des_encrypt(message, key1, 0);
    Buffer tmp2 = des_decrypt(tmp1, key2, 0);
    Buffer cipher = des_encrypt(tmp2, key3, 0);

    free(tmp1.ptr);
    free(tmp2.ptr);

    return cipher;
}

Buffer
des3_ecb_decrypt(Buffer cipher, Des3Key key) {
    DesKey key1, key2, key3;
    des3_get_keys(key, &key1, &key2, &key3);

    Buffer tmp1 = des_decrypt(cipher, key3, 0);
    Buffer tmp2 = des_encrypt(tmp1, key2, 0);
    Buffer message = des_decrypt(tmp2, key1, 0);

    free(tmp1.ptr);
    free(tmp2.ptr);

    return message;
}

static void
hmac_sha256(Buffer password, Buffer data, Buffer out) {
    u8 key_block[SHA2X32_BLOCK_SIZE] = { 0 };

    if (password.len > SHA2X32_BLOCK_SIZE) {
        sha256_hash_str(password, buffer_create(key_block, SHA256_DIGEST_SIZE));
    } else {
        ft_memcpy(buffer_create(key_block, password.len), password);
    }

    u8 ipad[SHA2X32_BLOCK_SIZE];
    u8 opad[SHA2X32_BLOCK_SIZE];
    for (u64 i = 0; i < SHA2X32_BLOCK_SIZE; i++) {
        ipad[i] = 0x36 ^ key_block[i];
        opad[i] = 0x5C ^ key_block[i];
    }

    u8 temp_hash[SHA256_DIGEST_SIZE];

    Sha256 sha = sha256_init();
    sha256_update(&sha, buffer_create(ipad, SHA2X32_BLOCK_SIZE));
    sha256_update(&sha, data);
    sha256_final(&sha, buffer_create(temp_hash, SHA256_DIGEST_SIZE));

    sha = sha256_init();
    sha256_update(&sha, buffer_create(opad, SHA2X32_BLOCK_SIZE));
    sha256_update(&sha, buffer_create(temp_hash, SHA256_DIGEST_SIZE));
    sha256_final(&sha, out);
}

static void
pbkdf2_hmac_sha256_f(Buffer password, Buffer salt, u64 iter, u32 block_num, Buffer out) {
    u8 salt_block[64];

    for (u64 i = 0; i < salt.len; i++) {
        salt_block[i] = salt.ptr[i];
    }

    salt_block[salt.len + 0] = (u8)(block_num >> 24);
    salt_block[salt.len + 1] = (u8)(block_num >> 16);
    salt_block[salt.len + 2] = (u8)(block_num >> 8);
    salt_block[salt.len + 3] = (u8)block_num;

    u8 buffer1[SHA256_DIGEST_SIZE];
    u8 buffer2[SHA256_DIGEST_SIZE];
    Buffer hmac_tmp1 = buffer_create(buffer1, SHA256_DIGEST_SIZE);
    Buffer hmac_tmp2 = buffer_create(buffer2, SHA256_DIGEST_SIZE);

    hmac_sha256(password, buffer_create(salt_block, salt.len + 4), hmac_tmp1);
    ft_memcpy(hmac_tmp2, hmac_tmp1);

    for (u64 i = 1; i < iter; i++) {
        hmac_sha256(password, hmac_tmp2, hmac_tmp2);
        for (u64 j = 0; j < hmac_tmp1.len; j++) {
            hmac_tmp1.ptr[j] ^= hmac_tmp2.ptr[j];
        }
    }

    ft_memcpy(out, hmac_tmp1);
}

void
pbkdf2_generate(Buffer password, Buffer salt, Buffer out) {
    // OpenSSL's default iterations is 10000 and SHA256 is the default hasher

    u64 block_count = (out.len + (SHA256_DIGEST_SIZE - 1)) / SHA256_DIGEST_SIZE;

    for (u64 i = 0; i < block_count; i++) {
        u8 buffer[SHA256_DIGEST_SIZE];
        pbkdf2_hmac_sha256_f(
            password,
            salt,
            10000,
            i + 1,
            buffer_create(buffer, SHA256_DIGEST_SIZE)
        );

        u64 offset = SHA256_DIGEST_SIZE * i;
        u64 len = out.len - offset;
        ft_memcpy(buffer_create(out.ptr + offset, len), buffer_create(buffer, len));
    }
}
