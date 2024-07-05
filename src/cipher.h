#pragma once

#include "types.h"

typedef union {
    u8 block[8];
    u64 raw;
} Des64;

typedef Des64 DesKey;
typedef u8 Des192[192];
typedef Des192 Des3Key;

Buffer
base64_encode(Buffer input);

Buffer
base64_decode(Buffer input);

Buffer
des_ecb_encrypt(Buffer message, DesKey key);

Buffer
des_ecb_decrypt(Buffer cipher, DesKey key);

Buffer
des_cbc_encrypt(Buffer message, DesKey key, Des64 iv);

Buffer
des_cbc_decrypt(Buffer cipher, DesKey key, Des64 iv);

Buffer
des3_ecb_encrypt(Buffer message, Des3Key key);

Buffer
des3_ecb_decrypt(Buffer cipher, Des3Key key);

DesKey
des_pbkdf2_generate(Buffer password, Des64 salt);
