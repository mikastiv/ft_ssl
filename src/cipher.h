#pragma once

#include "types.h"

typedef union {
    u8 block[8];
    u64 raw;
} Des64;

typedef Des64 DesKey;

Buffer
base64_encode(Buffer input);

Buffer
base64_decode(Buffer input);

Buffer
des_encrypt(Buffer message, DesKey key);

Buffer
des_decrypt(Buffer message, DesKey key);
