#pragma once

#include "types.h"

#define MD5_CHUNK_SIZE 64
#define MD5_DIGEST_SIZE 16

typedef struct {
    u32 state[4];
    u64 total_len;
    u8 buffer[MD5_CHUNK_SIZE];
    u64 buffer_len;
} Md5;

Md5
md5_init(void);

void
md5_update(Md5* md5, Buffer buffer);

void
md5_final(Md5* md5, Buffer out);

#define SHA256_CHUNK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    u32 state[8];
    u64 total_len;
    u8 buffer[SHA256_CHUNK_SIZE];
    u64 buffer_len;
} Sha256;

Sha256
sha256_init(void);

void
sha256_update(Sha256* sha, Buffer buffer);

void
sha256_final(Sha256* sha, Buffer out);
