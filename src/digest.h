#pragma once

#include "types.h"

#include <stdbool.h>

#define digest_declare_interface(prefix)                                                           \
    bool prefix##_hash_fd(int fd, Buffer out);                                                     \
    void prefix##_hash_str(Buffer in, Buffer out)

#define digest_implement_interface(Type, prefix)                                                   \
    void prefix##_hash_str(Buffer in, Buffer out) {                                                \
        Type hasher = prefix##_init();                                                             \
        prefix##_update(&hasher, in);                                                              \
        prefix##_final(&hasher, out);                                                              \
    }                                                                                              \
                                                                                                   \
    bool prefix##_hash_fd(int fd, Buffer out) {                                                    \
        Type hasher = prefix##_init();                                                             \
        u8 buffer[4096];                                                                           \
        i64 bytes = sizeof(buffer);                                                                \
        while (true) {                                                                             \
            bytes = read(fd, buffer, sizeof(buffer));                                              \
            if (bytes < 0) return false;                                                           \
            if (bytes == 0) break;                                                                 \
            prefix##_update(&hasher, (Buffer){ .ptr = buffer, .len = (u64)bytes });                \
        }                                                                                          \
        prefix##_final(&hasher, out);                                                              \
        return true;                                                                               \
    }

typedef bool (*HasherFd)(int, Buffer);
typedef void (*HasherStr)(Buffer, Buffer);

#define MD5_BLOCK_SIZE 64
#define MD5_ROUNDS 64
#define MD5_LENGTH_SIZE 8
#define MD5_DIGEST_SIZE 16

typedef struct {
    u32 state[4];
    u64 total_len;
    _Alignas(4) u8 buffer[MD5_BLOCK_SIZE];
    u64 buffer_len;
} Md5;

Md5
md5_init(void);

void
md5_update(Md5* md5, Buffer buffer);

void
md5_final(Md5* md5, Buffer out);

#define SHA2X32_BLOCK_SIZE 64
#define SHA2X32_ROUNDS 64
#define SHA2X32_LENGTH_SIZE 8
#define SHA256_DIGEST_SIZE 32
#define SHA224_DIGEST_SIZE 28

typedef struct {
    u32 state[8];
    u64 total_len;
    _Alignas(4) u8 buffer[SHA2X32_BLOCK_SIZE];
    u64 buffer_len;
} Sha2x32;

typedef Sha2x32 Sha256;

Sha256
sha256_init(void);

void
sha256_update(Sha256* sha, Buffer buffer);

void
sha256_final(Sha256* sha, Buffer out);

typedef Sha2x32 Sha224;

Sha224
sha224_init(void);

void
sha224_update(Sha224* sha, Buffer buffer);

void
sha224_final(Sha224* sha, Buffer out);

#define SHA2X64_BLOCK_SIZE 128
#define SHA2X64_ROUNDS 80
#define SHA2X64_LENGTH_SIZE 16
#define SHA512_DIGEST_SIZE 64
#define SHA384_DIGEST_SIZE 48

typedef struct {
    u64 state[8];
    u64 total_len;
    _Alignas(8) u8 buffer[SHA2X64_BLOCK_SIZE];
    u64 buffer_len;
} Sha2x64;

typedef Sha2x64 Sha512;

Sha512
sha512_init(void);

void
sha512_update(Sha512* sha, Buffer buffer);

void
sha512_final(Sha512* sha, Buffer out);

typedef Sha2x64 Sha384;

Sha384
sha384_init(void);

void
sha384_update(Sha384* sha, Buffer buffer);

void
sha384_final(Sha384* sha, Buffer out);

#define WHIRLPOOL_BLOCK_SIZE 64
#define WHIRLPOOL_ROUNDS 10
#define WHIRLPOOL_DIGEST_SIZE 64
#define WHIRLPOOL_LENGTH_SIZE 32

typedef struct {
    u64 state[8];
    u8 total_bitlen[WHIRLPOOL_LENGTH_SIZE];
    _Alignas(8) u8 buffer[WHIRLPOOL_BLOCK_SIZE];
    u64 buffer_len;
} Whirlpool;

Whirlpool
whirlpool_init(void);

void
whirlpool_update(Whirlpool* whrl, Buffer buffer);

void
whirlpool_final(Whirlpool* whrl, Buffer out);

digest_declare_interface(md5);
digest_declare_interface(sha256);
digest_declare_interface(sha224);
digest_declare_interface(sha512);
digest_declare_interface(sha384);
digest_declare_interface(whirlpool);
