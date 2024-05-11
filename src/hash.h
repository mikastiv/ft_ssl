#pragma once

#include "types.h"

#include <stdbool.h>

typedef bool (*hash_fd_func)(int, Buffer);
typedef void (*hash_str_func)(Buffer, Buffer);

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

bool
md5_hash_fd(int fd, Buffer out);

void
md5_hash_str(Buffer in, Buffer out);

#define SHA2X32_CHUNK_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define SHA224_DIGEST_SIZE 28

typedef struct {
    u32 state[8];
    u64 total_len;
    u8 buffer[SHA2X32_CHUNK_SIZE];
    u64 buffer_len;
} Sha2x32;

typedef Sha2x32 Sha256;

Sha256
sha256_init(void);

void
sha256_update(Sha256* sha, Buffer buffer);

void
sha256_final(Sha256* sha, Buffer out);

bool
sha256_hash_fd(int fd, Buffer out);

void
sha256_hash_str(Buffer in, Buffer out);

typedef Sha2x32 Sha224;

Sha224
sha224_init(void);

void
sha224_update(Sha224* sha, Buffer buffer);

void
sha224_final(Sha224* sha, Buffer out);

bool
sha224_hash_fd(int fd, Buffer out);

void
sha224_hash_str(Buffer in, Buffer out);

#define SHA2X64_CHUNK_SIZE 128
#define SHA512_DIGEST_SIZE 64
#define SHA384_DIGEST_SIZE 48

typedef struct {
    u64 state[8];
    u64 total_len;
    u8 buffer[SHA2X64_CHUNK_SIZE];
    u64 buffer_len;
} Sha2x64;

typedef Sha2x64 Sha512;

Sha512
sha512_init(void);

void
sha512_update(Sha512* sha, Buffer buffer);

void
sha512_final(Sha512* sha, Buffer out);

bool
sha512_hash_fd(int fd, Buffer out);

void
sha512_hash_str(Buffer in, Buffer out);

typedef Sha2x64 Sha384;

Sha384
sha384_init(void);

void
sha384_update(Sha384* sha, Buffer buffer);

void
sha384_final(Sha384* sha, Buffer out);

bool
sha384_hash_fd(int fd, Buffer out);

void
sha384_hash_str(Buffer in, Buffer out);
