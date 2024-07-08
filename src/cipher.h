#pragma once

#include "types.h"
#include "ssl.h"

#include <stdbool.h>

typedef union {
    u8 block[8];
    u64 raw;
} Des64;

#define DES_BLOCK_SIZE 8

typedef Des64 DesKey;
typedef u8 Des192[192];

#define DES_KEY_SIZE 8
#define PBKDF2_SALT_SIZE 8
#define PBKDF2_MAX_KEY_SIZE 512

Buffer
base64_encode(Buffer input);

Buffer
base64_decode(Buffer input);


bool
base64(Base64Options* options);

typedef Buffer (*DesFunc)(Buffer, Buffer, Des64);

Buffer
des_ecb_encrypt(Buffer message, Buffer key, Des64 iv);

Buffer
des_ecb_decrypt(Buffer ciphertext, Buffer key, Des64 iv);

Buffer
des_cbc_encrypt(Buffer message, Buffer key, Des64 iv);

Buffer
des_cbc_decrypt(Buffer ciphertext, Buffer key, Des64 iv);

Buffer
des_ofb_encrypt(Buffer message, Buffer key, Des64 iv);

Buffer
des_ofb_decrypt(Buffer ciphertext, Buffer key, Des64 iv);

Buffer
des_cfb_encrypt(Buffer message, Buffer key, Des64 iv);

Buffer
des_cfb_decrypt(Buffer ciphertext, Buffer key, Des64 iv);

Buffer
des_pcbc_encrypt(Buffer message, Buffer key, Des64 iv);

Buffer
des_pcbc_decrypt(Buffer ciphertext, Buffer key, Des64 iv);

Buffer
des3_ecb_encrypt(Buffer message, Buffer key, Des64 iv);

Buffer
des3_ecb_decrypt(Buffer ciphertext, Buffer key, Des64 iv);

Buffer
des3_cbc_encrypt(Buffer message, Buffer key, Des64 iv);

Buffer
des3_cbc_decrypt(Buffer ciphertext, Buffer key, Des64 iv);

Buffer
des3_ofb_encrypt(Buffer message, Buffer key, Des64 iv);

Buffer
des3_ofb_decrypt(Buffer ciphertext, Buffer key, Des64 iv);

Buffer
des3_cfb_encrypt(Buffer message, Buffer key, Des64 iv);

Buffer
des3_cfb_decrypt(Buffer ciphertext, Buffer key, Des64 iv);

Buffer
des3_pcbc_encrypt(Buffer message, Buffer key, Des64 iv);

Buffer
des3_pcbc_decrypt(Buffer ciphertext, Buffer key, Des64 iv);

void
pbkdf2_generate(Buffer password, Buffer salt, Buffer out);

bool
cipher(Command cmd, DesOptions* options);
