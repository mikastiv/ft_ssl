#include "cipher.h"
#include "digest.h"
#include "types.h"
#include "utils.h"

#include <assert.h>

static void
hmac_sha256(Buffer password, Buffer data, Buffer out) {
    u8 key_block[SHA2X32_BLOCK_SIZE] = { 0 };

    if (password.len > SHA2X32_BLOCK_SIZE) {
        sha256_hash_str(password, buf(key_block, SHA256_DIGEST_SIZE));
    } else {
        ft_memcpy(buf(key_block, password.len), password);
    }

    u8 ipad[SHA2X32_BLOCK_SIZE];
    u8 opad[SHA2X32_BLOCK_SIZE];
    for (u64 i = 0; i < SHA2X32_BLOCK_SIZE; i++) {
        ipad[i] = 0x36 ^ key_block[i];
        opad[i] = 0x5C ^ key_block[i];
    }

    u8 temp_hash[SHA256_DIGEST_SIZE];

    Sha256 sha = sha256_init();
    sha256_update(&sha, buf(ipad, SHA2X32_BLOCK_SIZE));
    sha256_update(&sha, data);
    sha256_final(&sha, buf(temp_hash, SHA256_DIGEST_SIZE));

    sha = sha256_init();
    sha256_update(&sha, buf(opad, SHA2X32_BLOCK_SIZE));
    sha256_update(&sha, buf(temp_hash, SHA256_DIGEST_SIZE));
    sha256_final(&sha, out);
}

static void
pbkdf2_hmac_sha256_f(Buffer password, Buffer salt, u64 iter, u32 block_num, Buffer out) {
    assert(salt.len == PBKDF2_SALT_SIZE);
    // salt is 8 bytes
    u8 salt_block[PBKDF2_SALT_SIZE + sizeof(block_num)];

    for (u64 i = 0; i < PBKDF2_SALT_SIZE; i++) {
        salt_block[i] = salt.ptr[i];
    }

    salt_block[PBKDF2_SALT_SIZE + 0] = (u8)(block_num >> 24);
    salt_block[PBKDF2_SALT_SIZE + 1] = (u8)(block_num >> 16);
    salt_block[PBKDF2_SALT_SIZE + 2] = (u8)(block_num >> 8);
    salt_block[PBKDF2_SALT_SIZE + 3] = (u8)block_num;

    u8 buffer1[SHA256_DIGEST_SIZE];
    u8 buffer2[SHA256_DIGEST_SIZE];
    Buffer hmac_tmp1 = buf(buffer1, SHA256_DIGEST_SIZE);
    Buffer hmac_tmp2 = buf(buffer2, SHA256_DIGEST_SIZE);

    hmac_sha256(password, buf(salt_block, PBKDF2_SALT_SIZE + sizeof(block_num)), hmac_tmp1);
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
    assert(salt.len == PBKDF2_SALT_SIZE);
    // OpenSSL's default iterations is 10000 and SHA256 is the default hasher

    u64 block_count = (out.len + (SHA256_DIGEST_SIZE - 1)) / SHA256_DIGEST_SIZE;

    for (u64 i = 0; i < block_count; i++) {
        u8 buffer[SHA256_DIGEST_SIZE];
        pbkdf2_hmac_sha256_f(password, salt, 10000, i + 1, buf(buffer, SHA256_DIGEST_SIZE));

        u64 offset = SHA256_DIGEST_SIZE * i;
        u64 len = out.len - offset;
        ft_memcpy(buf(out.ptr + offset, len), buf(buffer, len));
    }
}
